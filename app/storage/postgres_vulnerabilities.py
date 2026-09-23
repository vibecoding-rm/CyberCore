import hashlib
import json
from datetime import datetime
from decimal import Decimal
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from app.intelligence.models import NormalizedVulnerability

_RANGE_COLUMNS = (
    "vulnerability_id",
    "source",
    "match_kind",
    "vendor",
    "product",
    "ecosystem",
    "range_type",
    "exact_version",
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
    "requires_platform",
    "criteria",
)


class VulnerabilityStoreError(RuntimeError):
    """Raised when a vulnerability store operation fails."""


class PostgresVulnerabilityRepository:
    def __init__(self, database_url: str, connect_timeout_seconds: int = 3):
        if connect_timeout_seconds <= 0:
            raise ValueError("El timeout de conexión debe ser positivo")
        self.database_url = database_url
        self.connect_timeout_seconds = connect_timeout_seconds

    async def _connect(self) -> psycopg.AsyncConnection[Any]:
        return await psycopg.AsyncConnection.connect(
            self.database_url,
            connect_timeout=self.connect_timeout_seconds,
        )

    async def ping(self) -> None:
        try:
            async with await self._connect() as conn:
                await conn.execute("SELECT 1")
        except Exception as exc:
            raise VulnerabilityStoreError("PostgreSQL no está disponible para vulnerabilidades") from exc

    async def upsert_vulnerability(
        self,
        vulnerability_id: str,
        source: str,
        title: str | None = None,
        description: str | None = None,
        cvss: float | Decimal | None = None,
        epss: float | Decimal | None = None,
        kev: bool | None = None,
        cwe_ids: list[str] | None = None,
        source_updated_at: datetime | str | None = None,
    ) -> int:
        if not vulnerability_id or not vulnerability_id.strip():
            raise ValueError("vulnerability_id no puede estar vacío")
        cve_clean = vulnerability_id.strip().upper()
        cwe_list = cwe_ids if cwe_ids is not None else []

        try:
            async with await self._connect() as conn:
                async with conn.transaction():
                    cursor = await conn.execute(
                        """
                        INSERT INTO vulnerabilities (
                            vulnerability_id,
                            source,
                            title,
                            description,
                            cvss,
                            epss,
                            kev,
                            cwe_ids,
                            source_updated_at,
                            ingested_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, now())
                        ON CONFLICT (vulnerability_id) DO UPDATE SET
                            source = EXCLUDED.source,
                            title = COALESCE(EXCLUDED.title, vulnerabilities.title),
                            description = COALESCE(EXCLUDED.description, vulnerabilities.description),
                            cvss = COALESCE(EXCLUDED.cvss, vulnerabilities.cvss),
                            epss = COALESCE(EXCLUDED.epss, vulnerabilities.epss),
                            kev = COALESCE(EXCLUDED.kev, vulnerabilities.kev),
                            cwe_ids = CASE
                                WHEN cardinality(EXCLUDED.cwe_ids) > 0 THEN EXCLUDED.cwe_ids
                                ELSE vulnerabilities.cwe_ids
                            END,
                            source_updated_at = COALESCE(EXCLUDED.source_updated_at, vulnerabilities.source_updated_at),
                            ingested_at = now()
                        RETURNING id
                        """,
                        (
                            cve_clean,
                            source,
                            title,
                            description,
                            cvss,
                            epss,
                            kev,
                            cwe_list,
                            source_updated_at,
                        ),
                    )
                    row = await cursor.fetchone()
                    if row is None:
                        raise VulnerabilityStoreError("No se pudo insertar o actualizar la vulnerabilidad")
                    return int(row[0])
        except Exception as exc:
            if isinstance(exc, (ValueError, VulnerabilityStoreError)):
                raise
            raise VulnerabilityStoreError("Error al persistir la vulnerabilidad") from exc

    async def bulk_upsert_kev(self, records: list[dict[str, Any]]) -> int:
        """Inserta o actualiza un lote de vulnerabilidades provenientes de CISA KEV."""
        if not records:
            return 0

        count = 0
        try:
            async with await self._connect() as conn:
                async with conn.transaction():
                    for record in records:
                        cve = record.get("cveID") or record.get("vulnerability_id")
                        if not cve:
                            continue
                        cve_clean = cve.strip().upper()
                        title = record.get("vulnerabilityName") or record.get("title")
                        desc = record.get("shortDescription") or record.get("description")
                        cwes = record.get("cwes") or record.get("cwe_ids") or []
                        if isinstance(cwes, str):
                            cwes = [c.strip() for c in cwes.split(",") if c.strip()]
                        date_added = record.get("dateAdded") or record.get("source_updated_at")

                        await conn.execute(
                            """
                            INSERT INTO vulnerabilities (
                                vulnerability_id,
                                source,
                                title,
                                description,
                                kev,
                                cwe_ids,
                                source_updated_at,
                                ingested_at
                            ) VALUES (%s, 'cisa_kev', %s, %s, true, %s, %s, now())
                            ON CONFLICT (vulnerability_id) DO UPDATE SET
                                kev = true,
                                title = COALESCE(EXCLUDED.title, vulnerabilities.title),
                                description = COALESCE(EXCLUDED.description, vulnerabilities.description),
                                cwe_ids = CASE
                                    WHEN cardinality(EXCLUDED.cwe_ids) > 0 THEN EXCLUDED.cwe_ids
                                    ELSE vulnerabilities.cwe_ids
                                END,
                                source_updated_at = COALESCE(EXCLUDED.source_updated_at, vulnerabilities.source_updated_at),
                                ingested_at = now()
                            """,
                            (cve_clean, title, desc, cwes, date_added),
                        )
                        count += 1
            return count
        except Exception as exc:
            raise VulnerabilityStoreError("Error al procesar lote CISA KEV") from exc

    async def bulk_upsert_epss(self, records: list[dict[str, Any]]) -> int:
        """Actualiza puntajes EPSS para una lista de registros {'cve': ..., 'epss': ...}."""
        if not records:
            return 0

        count = 0
        try:
            async with await self._connect() as conn:
                async with conn.transaction():
                    for record in records:
                        cve = record.get("cve") or record.get("vulnerability_id")
                        if not cve:
                            continue
                        cve_clean = cve.strip().upper()
                        epss_val = record.get("epss")
                        if epss_val is None:
                            continue
                        epss_float = float(epss_val)

                        await conn.execute(
                            """
                            INSERT INTO vulnerabilities (
                                vulnerability_id,
                                source,
                                epss,
                                ingested_at
                            ) VALUES (%s, 'epss', %s, now())
                            ON CONFLICT (vulnerability_id) DO UPDATE SET
                                epss = EXCLUDED.epss,
                                ingested_at = now()
                            """,
                            (cve_clean, epss_float),
                        )
                        count += 1
            return count
        except Exception as exc:
            raise VulnerabilityStoreError("Error al procesar lote EPSS") from exc

    async def get_vulnerability(self, vulnerability_id: str) -> dict[str, Any] | None:
        if not vulnerability_id:
            return None
        cve_clean = vulnerability_id.strip().upper()

        try:
            async with await self._connect() as conn:
                cursor = await conn.execute(
                    """
                    SELECT
                        id,
                        vulnerability_id,
                        source,
                        title,
                        description,
                        cvss,
                        epss,
                        kev,
                        cwe_ids,
                        source_updated_at,
                        ingested_at,
                        cvss_vector,
                        cvss_version,
                        aliases,
                        published_at
                    FROM vulnerabilities
                    WHERE vulnerability_id = %s
                    """,
                    (cve_clean,),
                )
                row = await cursor.fetchone()
                if row is None:
                    return None
                return {
                    "id": row[0],
                    "vulnerability_id": row[1],
                    "source": row[2],
                    "title": row[3],
                    "description": row[4],
                    "cvss": float(row[5]) if row[5] is not None else None,
                    "epss": float(row[6]) if row[6] is not None else None,
                    "kev": bool(row[7]) if row[7] is not None else False,
                    "cwe_ids": list(row[8]) if row[8] is not None else [],
                    "source_updated_at": row[9],
                    "ingested_at": row[10],
                    "cvss_vector": row[11],
                    "cvss_version": row[12],
                    "aliases": list(row[13]) if row[13] is not None else [],
                    "published_at": row[14],
                }
        except Exception as exc:
            raise VulnerabilityStoreError("Error al consultar vulnerabilidad") from exc

    async def list_vulnerabilities(
        self,
        limit: int = 50,
        kev_only: bool = False,
        min_epss: float | None = None,
    ) -> list[dict[str, Any]]:
        try:
            conditions = []
            params: list[Any] = []

            if kev_only:
                conditions.append("kev = true")
            if min_epss is not None:
                conditions.append("epss >= %s")
                params.append(min_epss)

            where_clause = ""
            if conditions:
                where_clause = "WHERE " + " AND ".join(conditions)

            params.append(limit)

            async with await self._connect() as conn:
                cursor = await conn.execute(
                    f"""
                    SELECT
                        id,
                        vulnerability_id,
                        source,
                        title,
                        description,
                        cvss,
                        epss,
                        kev,
                        cwe_ids,
                        source_updated_at,
                        ingested_at,
                        cvss_vector,
                        cvss_version,
                        aliases,
                        published_at
                    FROM vulnerabilities
                    {where_clause}
                    ORDER BY COALESCE(epss, 0) DESC, ingested_at DESC
                    LIMIT %s
                    """,
                    params,
                )
                results = []
                for row in await cursor.fetchall():
                    results.append({
                        "id": row[0],
                        "vulnerability_id": row[1],
                        "source": row[2],
                        "title": row[3],
                        "description": row[4],
                        "cvss": float(row[5]) if row[5] is not None else None,
                        "epss": float(row[6]) if row[6] is not None else None,
                        "kev": bool(row[7]) if row[7] is not None else False,
                        "cwe_ids": list(row[8]) if row[8] is not None else [],
                        "source_updated_at": row[9],
                        "ingested_at": row[10],
                        "cvss_vector": row[11],
                        "cvss_version": row[12],
                        "aliases": list(row[13]) if row[13] is not None else [],
                        "published_at": row[14],
                    })
                return results
        except Exception as exc:
            raise VulnerabilityStoreError("Error al listar vulnerabilidades") from exc

    async def count_vulnerabilities(self) -> dict[str, int]:
        try:
            async with await self._connect() as conn:
                cursor = await conn.execute(
                    """
                    SELECT
                        count(*) as total,
                        count(*) FILTER (WHERE kev = true) as kev_count,
                        count(*) FILTER (WHERE epss IS NOT NULL) as epss_count
                    FROM vulnerabilities
                    """
                )
                row = await cursor.fetchone()
                if row is None:
                    return {"total": 0, "kev": 0, "with_epss": 0}
                return {
                    "total": int(row[0]),
                    "kev": int(row[1]),
                    "with_epss": int(row[2]),
                }
        except Exception as exc:
            raise VulnerabilityStoreError("Error al contar vulnerabilidades") from exc

    async def store_intel_record(
        self,
        record: NormalizedVulnerability,
        raw_data: dict[str, Any],
        vulnerability_id: str | None = None,
    ) -> dict[str, Any]:
        """Persist a source payload with its hash and replace the ranges it declared.

        ``vulnerability_id`` lets an OSV record (e.g. a GHSA) be attached to the
        CVE it aliases. Raw payload, hash, vulnerability fields and ranges are
        written in one transaction so ranges never lose their provenance.
        """
        target_id = (vulnerability_id or record.vulnerability_id).strip().upper()
        if not target_id:
            raise ValueError("vulnerability_id no puede estar vacío")
        canonical = json.dumps(raw_data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        try:
            async with await self._connect() as conn:
                async with conn.transaction():
                    cursor = await conn.execute(
                        """
                        INSERT INTO intel_source_records (
                            source, record_id, source_url, sha256, raw_data, source_modified_at
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (source, record_id, sha256)
                            DO UPDATE SET fetched_at = now()
                        RETURNING id
                        """,
                        (
                            record.source,
                            record.vulnerability_id,
                            record.source_url,
                            digest,
                            Jsonb(raw_data),
                            record.source_modified_at,
                        ),
                    )
                    row = await cursor.fetchone()
                    if row is None:
                        raise VulnerabilityStoreError("No se pudo registrar el registro de origen")
                    source_record_id = int(row[0])

                    await conn.execute(
                        """
                        INSERT INTO vulnerabilities (
                            vulnerability_id, source, description, cvss, cvss_vector,
                            cvss_version, cwe_ids, aliases, published_at,
                            source_updated_at, ingested_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
                        ON CONFLICT (vulnerability_id) DO UPDATE SET
                            description = COALESCE(vulnerabilities.description, EXCLUDED.description),
                            cvss = COALESCE(EXCLUDED.cvss, vulnerabilities.cvss),
                            cvss_vector = COALESCE(EXCLUDED.cvss_vector, vulnerabilities.cvss_vector),
                            cvss_version = COALESCE(EXCLUDED.cvss_version, vulnerabilities.cvss_version),
                            cwe_ids = CASE
                                WHEN cardinality(vulnerabilities.cwe_ids) > 0 THEN vulnerabilities.cwe_ids
                                ELSE EXCLUDED.cwe_ids
                            END,
                            aliases = ARRAY(
                                SELECT DISTINCT unnest(vulnerabilities.aliases || EXCLUDED.aliases)
                            ),
                            published_at = COALESCE(vulnerabilities.published_at, EXCLUDED.published_at),
                            ingested_at = now()
                        """,
                        (
                            target_id,
                            record.source,
                            record.description,
                            record.cvss,
                            record.cvss_vector,
                            record.cvss_version,
                            record.cwe_ids,
                            [a for a in record.aliases if a != target_id],
                            record.published_at,
                            record.source_modified_at,
                        ),
                    )

                    # Replace only the ranges previously taken from this same
                    # source record; other records aliasing the CVE keep theirs.
                    await conn.execute(
                        """
                        DELETE FROM vulnerability_affected_ranges r
                        USING intel_source_records s
                        WHERE r.source_record_id = s.id
                          AND r.vulnerability_id = %s
                          AND s.source = %s
                          AND s.record_id = %s
                        """,
                        (target_id, record.source, record.vulnerability_id),
                    )
                    placeholders = ", ".join(["%s"] * (len(_RANGE_COLUMNS) + 1))
                    for affected in record.ranges:
                        values = affected.model_dump()
                        await conn.execute(
                            f"""
                            INSERT INTO vulnerability_affected_ranges (
                                source_record_id, {", ".join(_RANGE_COLUMNS)}
                            ) VALUES ({placeholders})
                            """,
                            (
                                source_record_id,
                                target_id,
                                record.source,
                                *(values[column] for column in _RANGE_COLUMNS[2:]),
                            ),
                        )
            return {
                "vulnerability_id": target_id,
                "source": record.source,
                "source_record_id": source_record_id,
                "sha256": digest,
                "ranges": len(record.ranges),
            }
        except Exception as exc:
            if isinstance(exc, (ValueError, VulnerabilityStoreError)):
                raise
            raise VulnerabilityStoreError("Error al persistir inteligencia de origen") from exc

    async def get_affected_ranges(
        self,
        vulnerability_id: str,
        *,
        vendor: str | None = None,
        product: str | None = None,
    ) -> list[dict[str, Any]]:
        """Stored ranges for a vulnerability, optionally narrowed to one product."""
        conditions = ["r.vulnerability_id = %s"]
        params: list[Any] = [vulnerability_id.strip().upper()]
        if vendor is not None:
            conditions.append("r.vendor = %s")
            params.append(vendor)
        if product is not None:
            conditions.append("r.product = %s")
            params.append(product)
        try:
            async with await self._connect() as conn:
                cursor = await conn.execute(
                    f"""
                    SELECT {", ".join("r." + c for c in _RANGE_COLUMNS)},
                           s.sha256, s.source_url, s.fetched_at
                    FROM vulnerability_affected_ranges r
                    JOIN intel_source_records s ON s.id = r.source_record_id
                    WHERE {" AND ".join(conditions)}
                    ORDER BY r.source, r.id
                    """,
                    params,
                )
                rows = await cursor.fetchall()
        except Exception as exc:
            raise VulnerabilityStoreError("Error al consultar rangos afectados") from exc
        columns = (*_RANGE_COLUMNS, "source_sha256", "source_url", "fetched_at")
        return [dict(zip(columns, row)) for row in rows]
