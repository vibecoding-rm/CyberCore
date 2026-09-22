import argparse
import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.agent.orchestrator import CyberCoreOrchestrator
from app.core.evidence_analysis import EvidenceGapAnalyzer
from app.core.policy import PolicyEngine
from app.core.tool_broker import ToolBroker
from app.event_loop import configure_windows_asyncio
from app.llm.ollama import OllamaChatClient
from app.settings import get_settings
from app.storage.postgres_approvals import PostgresApprovalRepository
from app.storage.postgres_assets import PostgresAssetRepository
from app.storage.postgres_budgets import PostgresBudgetCoordinator
from app.storage.postgres_journal import PostgresExecutionJournal
from app.storage.postgres_vulnerabilities import PostgresVulnerabilityRepository
from app.tools.mock_inventory import MockInventoryTool
from app.tools.nmap import NmapDiscoverHostsTool, NmapInspectServicesTool


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Demostración interactiva del Agente Orquestador Autónomo CyberCore."
    )
    parser.add_argument(
        "intent",
        nargs="?",
        default="Descubre los hosts activos en la red local de laboratorio 192.168.10.0/24 y resume tus hallazgos.",
        help="Intención del operador en lenguaje natural",
    )
    parser.add_argument(
        "--steps",
        type=int,
        default=5,
        help="Número máximo de pasos del orquestador",
    )
    args = parser.parse_args()

    settings = get_settings()
    print("=" * 60)
    print("   CyberCore - Agente Orquestador Autónomo (LLM ReAct)")
    print("=" * 60)
    print(f"[*] Modelo Orquestador: {settings.orchestrator_model}")
    print(f"[*] Ollama Base URL:    {settings.ollama_base_url}")
    print(f"[*] Modo Herramientas:  {settings.tool_mode}")
    print(f"[*] Intención Operador: {args.intent}\n")

    llm_client = OllamaChatClient(
        base_url=settings.ollama_base_url,
        timeout_seconds=settings.ollama_request_timeout_seconds,
        context_tokens=settings.ollama_context_tokens,
    )

    budget_coordinator = PostgresBudgetCoordinator(
        database_url=settings.database_url,
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
        request_window_seconds=settings.budget_request_window_seconds,
        lease_grace_seconds=settings.budget_lease_grace_seconds,
        budget_key=settings.budget_key,
    )
    approval_repo = PostgresApprovalRepository(
        database_url=settings.database_url,
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
    )
    journal = PostgresExecutionJournal(
        database_url=settings.database_url,
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
    )
    asset_repo = PostgresAssetRepository(
        database_url=settings.database_url,
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
    )
    vuln_repo = PostgresVulnerabilityRepository(
        database_url=settings.database_url,
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
    )

    tools = [
        MockInventoryTool(),
        NmapDiscoverHostsTool(mode=settings.tool_mode),
        NmapInspectServicesTool(mode=settings.tool_mode),
    ]

    broker = ToolBroker(
        policy=PolicyEngine(settings.policy_file),
        tools=tools,
        tool_mode=settings.tool_mode,
        journal=journal,
        budget_coordinator=budget_coordinator,
    )

    orchestrator = CyberCoreOrchestrator(
        llm_client=llm_client,
        model_name=settings.orchestrator_model,
        broker=broker,
        asset_repo=asset_repo,
        vuln_repo=vuln_repo,
        analyzer=EvidenceGapAnalyzer(),
        max_steps=args.steps,
    )

    try:
        result = await orchestrator.run(
            operator_intent=args.intent,
            requested_by="operador-lab",
        )

        print(f"\n[+] Estado de la corrida: {result.status.upper()}")
        print("-" * 60)
        for step in result.steps:
            print(f"[Paso {step.step_number}] ({step.action_type})")
            print(f"  Pensamiento:  {step.thought}")
            if step.tool:
                print(f"  Herramienta:  {step.tool}({step.arguments})")
            print(f"  Observación:\n    {step.observation.strip()}")
            print("-" * 60)

        if result.pending_approval:
            print("\n[!] APROBACIÓN REQUERIDA:")
            print(f"    Herramienta: {result.pending_approval.get('tool')}")
            print(f"    Argumentos:  {result.pending_approval.get('arguments')}")
            print(f"    Riesgo:      {result.pending_approval.get('risk')}")

        print("\n=== REPORTE FINAL DEL ORQUESTADOR ===")
        print(result.final_report)
        print("=====================================\n")

    finally:
        await llm_client.aclose()


if __name__ == "__main__":
    configure_windows_asyncio()
    asyncio.run(main())
