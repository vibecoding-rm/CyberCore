import argparse
import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.event_loop import configure_windows_asyncio
from app.intelligence.ingestion import VulnerabilityIngestService
from app.intelligence.nvd import NvdClient, NvdError
from app.intelligence.osv import OsvClient, OsvError
from app.settings import get_settings
from app.storage.postgres_vulnerabilities import PostgresVulnerabilityRepository


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ingiere inteligencia de vulnerabilidades (CISA KEV, EPSS, NVD y OSV) en CyberCore PostgreSQL."
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Siembra registros de referencia (Log4Shell, MOVEit, CitrixBleed, Ivanti, etc.)",
    )
    parser.add_argument(
        "--kev",
        action="store_true",
        help="Descarga e ingiere el catálogo completo de CISA KEV",
    )
    parser.add_argument(
        "--epss",
        action="store_true",
        help="Consulta puntajes EPSS para las vulnerabilidades KEV almacenadas",
    )
    parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Ruta a un archivo JSON local de CISA KEV para ingesta sin conexión",
    )
    parser.add_argument(
        "--nvd",
        action="store_true",
        help="Enriquece con NVD (CVSS, CWE y rangos CPE) los CVE indicados o los KEV almacenados",
    )
    parser.add_argument(
        "--osv",
        action="store_true",
        help="Enriquece con OSV (rangos por paquete y alias) los CVE indicados o los KEV almacenados",
    )
    parser.add_argument(
        "--cve",
        action="append",
        default=[],
        metavar="CVE-AAAA-NNNN",
        help="CVE concreto a enriquecer (repetible). Sin él se usan los KEV almacenados",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Máximo de CVE KEV a enriquecer cuando no se indica --cve (NVD sin clave: ~6 s por CVE)",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Muestra resumen del número de vulnerabilidades en la base de datos",
    )

    args = parser.parse_args()

    # If no flags given, default to showing summary and offering baseline
    if not (args.baseline or args.kev or args.epss or args.file or args.summary or args.nvd or args.osv):
        parser.print_help()
        sys.exit(1)

    settings = get_settings()
    repo = PostgresVulnerabilityRepository(
        database_url=settings.database_url,
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
    )
    service = VulnerabilityIngestService(repo)

    if args.baseline:
        print("[+] Sembrando catálogo base de vulnerabilidades...")
        res = await service.seed_baseline_sample()
        print(f"    -> {res['seeded_kev']} registros KEV sembrados con EPSS.")

    if args.file:
        print(f"[+] Ingestionando CISA KEV desde archivo local: {args.file}")
        count = await service.ingest_cisa_kev(file_path=args.file)
        print(f"    -> {count} registros KEV procesados.")

    elif args.kev:
        print("[+] Descargando e ingiriendo catálogo completo CISA KEV...")
        try:
            count = await service.ingest_cisa_kev()
            print(f"    -> {count} registros KEV procesados con éxito.")
        except Exception as exc:
            print(f"[-] Error durante la ingesta CISA KEV: {exc}", file=sys.stderr)

    if args.epss:
        print("[+] Obteniendo lista de CVEs para consultar EPSS...")
        items = await repo.list_vulnerabilities(limit=100, kev_only=True)
        cves = [item["vulnerability_id"] for item in items]
        if cves:
            print(f"    -> Consultando EPSS para {len(cves)} CVEs...")
            epss_count = await service.ingest_epss_for_cves(cves)
            print(f"    -> {epss_count} puntajes EPSS actualizados.")
        else:
            print("    -> No hay CVEs en la base de datos para consultar EPSS.")

    if args.nvd or args.osv:
        cves = [c.strip().upper() for c in args.cve]
        if not cves:
            items = await repo.list_vulnerabilities(limit=args.limit, kev_only=True)
            cves = [item["vulnerability_id"] for item in items]
        if not cves:
            print("    -> No hay CVE para enriquecer. Usa --cve o ingiere KEV primero.")

    if args.nvd and cves:
        mode = "con clave" if settings.nvd_api_key else "sin clave (6 s entre solicitudes)"
        print(f"[+] Enriqueciendo {len(cves)} CVE desde NVD {mode}...")
        async with NvdClient(api_key=settings.nvd_api_key or None) as nvd:
            for cve in cves:
                try:
                    [result] = await service.enrich_from_nvd([cve], nvd)
                    print(f"    -> {cve}: {result['status']}, {result.get('ranges', 0)} rangos")
                except (NvdError, ValueError) as exc:
                    print(f"[-] {cve}: {exc}", file=sys.stderr)

    if args.osv and cves:
        print(f"[+] Enriqueciendo {len(cves)} CVE desde OSV...")
        async with OsvClient() as osv:
            for cve in cves:
                try:
                    results = await service.enrich_from_osv(cve, osv)
                    ranges = sum(r.get("ranges", 0) for r in results)
                    print(f"    -> {cve}: {len(results)} registro(s), {ranges} rangos")
                except (OsvError, ValueError) as exc:
                    print(f"[-] {cve}: {exc}", file=sys.stderr)

    if args.summary or args.baseline or args.kev or args.file or args.epss or args.nvd or args.osv:
        stats = await repo.count_vulnerabilities()
        print("\n=== Resumen de Base de Datos CyberCore ===")
        print(f" Total vulnerabilidades: {stats['total']}")
        print(f" Marcadas como CISA KEV: {stats['kev']}")
        print(f" Con puntaje EPSS:       {stats['with_epss']}")
        print("==========================================")


if __name__ == "__main__":
    configure_windows_asyncio()
    asyncio.run(main())
