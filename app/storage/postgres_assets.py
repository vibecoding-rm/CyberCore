from typing import Any
import ipaddress
import psycopg

from app.api.models import Evidence


class AssetStoreError(RuntimeError):
    """Raised when an asset store operation fails."""


class PostgresAssetRepository:
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
            raise AssetStoreError("PostgreSQL no está disponible para activos") from exc

    async def upsert_asset(
        self,
        asset_key: str,
        display_name: str | None = None,
        environment: str = "production",
        criticality: int = 3,
        owner: str | None = None,
    ) -> int:
        if not (1 <= criticality <= 5):
            raise ValueError("La criticidad debe estar entre 1 y 5")
        try:
            async with await self._connect() as conn:
                async with conn.transaction():
                    cursor = await conn.execute(
                        """
                        INSERT INTO assets (
                            asset_key,
                            display_name,
                            environment,
                            criticality,
                            owner,
                            created_at,
                            updated_at
                        ) VALUES (%s, %s, %s, %s, %s, now(), now())
                        ON CONFLICT (asset_key) DO UPDATE SET
                            display_name = COALESCE(EXCLUDED.display_name, assets.display_name),
                            environment = COALESCE(EXCLUDED.environment, assets.environment),
                            criticality = COALESCE(EXCLUDED.criticality, assets.criticality),
                            owner = COALESCE(EXCLUDED.owner, assets.owner),
                            updated_at = now()
                        RETURNING id
                        """,
                        (asset_key, display_name, environment, criticality, owner),
                    )
                    row = await cursor.fetchone()
                    if row is None:
                        raise AssetStoreError("No se pudo insertar o actualizar el activo")
                    return int(row[0])
        except Exception as exc:
            if isinstance(exc, (ValueError, AssetStoreError)):
                raise
            raise AssetStoreError("Error al persistir el activo") from exc

    async def upsert_address(self, asset_id: int, address: str) -> int:
        try:
            # Validate IP address format
            ip_obj = ipaddress.ip_address(address.strip())
            clean_ip = str(ip_obj)

            async with await self._connect() as conn:
                async with conn.transaction():
                    cursor = await conn.execute(
                        """
                        INSERT INTO asset_addresses (
                            asset_id,
                            address,
                            first_seen,
                            last_seen
                        ) VALUES (%s, %s, now(), now())
                        ON CONFLICT (asset_id, address) DO UPDATE SET
                            last_seen = now()
                        RETURNING id
                        """,
                        (asset_id, clean_ip),
                    )
                    row = await cursor.fetchone()
                    if row is None:
                        raise AssetStoreError("No se pudo asociar la dirección al activo")
                    return int(row[0])
        except Exception as exc:
            if isinstance(exc, (ValueError, AssetStoreError)):
                raise
            raise AssetStoreError("Error al registrar dirección de activo") from exc

    async def upsert_service(
        self,
        asset_id: int,
        port: int,
        protocol: str = "tcp",
        service_name: str | None = None,
        product: str | None = None,
        version: str | None = None,
    ) -> int:
        if not (1 <= port <= 65535):
            raise ValueError(f"Puerto fuera de rango válido (1-65535): {port}")
        protocol = protocol.lower()
        if protocol not in ("tcp", "udp"):
            raise ValueError(f"Protocolo inválido: {protocol}")

        try:
            async with await self._connect() as conn:
                async with conn.transaction():
                    cursor = await conn.execute(
                        """
                        INSERT INTO services (
                            asset_id,
                            port,
                            protocol,
                            service_name,
                            product,
                            version,
                            observed_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, now())
                        ON CONFLICT (asset_id, port, protocol) DO UPDATE SET
                            service_name = COALESCE(EXCLUDED.service_name, services.service_name),
                            product = COALESCE(EXCLUDED.product, services.product),
                            version = COALESCE(EXCLUDED.version, services.version),
                            observed_at = now()
                        RETURNING id
                        """,
                        (asset_id, port, protocol, service_name, product, version),
                    )
                    row = await cursor.fetchone()
                    if row is None:
                        raise AssetStoreError("No se pudo registrar el servicio")
                    return int(row[0])
        except Exception as exc:
            if isinstance(exc, (ValueError, AssetStoreError)):
                raise
            raise AssetStoreError("Error al persistir el servicio") from exc

    async def record_evidence(self, evidence: Evidence) -> list[int]:
        """Extrae y persiste automáticamente activos y servicios a partir de evidencia recolectada."""
        affected_asset_ids: list[int] = []

        if evidence.source == "discover_hosts":
            hosts = evidence.data.get("hosts", [])
            for host in hosts:
                if host.get("status") == "up":
                    ip = host.get("ip")
                    if not ip:
                        continue
                    hostname = host.get("hostname")
                    display_name = hostname if hostname else f"Host {ip}"
                    asset_id = await self.upsert_asset(
                        asset_key=f"host:{ip}",
                        display_name=display_name,
                    )
                    await self.upsert_address(asset_id, ip)
                    affected_asset_ids.append(asset_id)

        elif evidence.source in ("inspect_services", "get_mock_inventory"):
            target = evidence.target
            # Check if target is an IP address
            try:
                ipaddress.ip_address(target.strip())
                is_ip = True
            except ValueError:
                is_ip = False

            display_name = evidence.data.get("hostname") or f"Host {target}"
            asset_key = f"host:{target}" if is_ip else f"target:{target}"
            asset_id = await self.upsert_asset(
                asset_key=asset_key,
                display_name=display_name,
            )
            if is_ip:
                await self.upsert_address(asset_id, target)

            services = evidence.data.get("services", [])
            for svc in services:
                if svc.get("state") == "open":
                    port = int(svc["port"])
                    protocol = svc.get("protocol", "tcp")
                    svc_name = svc.get("service") or svc.get("service_name")
                    product = svc.get("product")
                    version = svc.get("version")
                    await self.upsert_service(
                        asset_id=asset_id,
                        port=port,
                        protocol=protocol,
                        service_name=svc_name,
                        product=product,
                        version=version,
                    )
            affected_asset_ids.append(asset_id)

        return affected_asset_ids

    async def get_asset(self, asset_id: int) -> dict[str, Any] | None:
        try:
            async with await self._connect() as conn:
                cursor = await conn.execute(
                    """
                    SELECT id, asset_key, display_name, criticality, owner, environment, created_at, updated_at
                    FROM assets WHERE id = %s
                    """,
                    (asset_id,),
                )
                row = await cursor.fetchone()
                if row is None:
                    return None
                
                asset = {
                    "id": row[0],
                    "asset_key": row[1],
                    "display_name": row[2],
                    "criticality": row[3],
                    "owner": row[4],
                    "environment": row[5],
                    "created_at": row[6],
                    "updated_at": row[7],
                    "addresses": [],
                    "services": [],
                }

                # Fetch addresses
                addr_cursor = await conn.execute(
                    "SELECT address, first_seen, last_seen FROM asset_addresses WHERE asset_id = %s",
                    (asset_id,),
                )
                for addr_row in await addr_cursor.fetchall():
                    asset["addresses"].append({
                        "address": str(addr_row[0]),
                        "first_seen": addr_row[1],
                        "last_seen": addr_row[2],
                    })

                # Fetch services
                svc_cursor = await conn.execute(
                    """
                    SELECT port, protocol, service_name, product, version, observed_at
                    FROM services WHERE asset_id = %s ORDER BY port ASC
                    """,
                    (asset_id,),
                )
                for svc_row in await svc_cursor.fetchall():
                    asset["services"].append({
                        "port": svc_row[0],
                        "protocol": svc_row[1],
                        "service_name": svc_row[2],
                        "product": svc_row[3],
                        "version": svc_row[4],
                        "observed_at": svc_row[5],
                    })

                return asset
        except Exception as exc:
            raise AssetStoreError("Error al consultar activo") from exc

    async def get_asset_by_address(self, address: str) -> dict[str, Any] | None:
        try:
            clean_ip = str(ipaddress.ip_address(address.strip()))
            async with await self._connect() as conn:
                cursor = await conn.execute(
                    "SELECT asset_id FROM asset_addresses WHERE address = %s ORDER BY last_seen DESC LIMIT 1",
                    (clean_ip,),
                )
                row = await cursor.fetchone()
                if row is None:
                    return None
                return await self.get_asset(row[0])
        except ValueError:
            return None
        except Exception as exc:
            raise AssetStoreError("Error al consultar activo por dirección") from exc

    async def list_assets(self) -> list[dict[str, Any]]:
        try:
            async with await self._connect() as conn:
                cursor = await conn.execute("SELECT id FROM assets ORDER BY id ASC")
                asset_ids = [row[0] for row in await cursor.fetchall()]
            
            assets = []
            for asset_id in asset_ids:
                item = await self.get_asset(asset_id)
                if item:
                    assets.append(item)
            return assets
        except Exception as exc:
            raise AssetStoreError("Error al listar activos") from exc
