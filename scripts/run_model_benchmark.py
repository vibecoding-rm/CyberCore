import argparse
import asyncio

from app.evaluation.benchmark import BenchmarkRunner, BenchmarkSuite
from app.llm.ollama import OllamaChatClient, OllamaClientError
from app.settings import get_settings


def parse_args() -> argparse.Namespace:
    settings = get_settings()
    parser = argparse.ArgumentParser(
        description="Evalúa un modelo local sin darle acceso a herramientas.",
    )
    parser.add_argument("--model", default=settings.orchestrator_model)
    parser.add_argument("--suite", default="config/benchmark_cases.yaml")
    parser.add_argument("--base-url", default=settings.ollama_base_url)
    parser.add_argument(
        "--timeout",
        type=float,
        default=settings.ollama_request_timeout_seconds,
    )
    parser.add_argument(
        "--context-tokens",
        type=int,
        default=settings.ollama_context_tokens,
    )
    return parser.parse_args()


async def run(args: argparse.Namespace) -> int:
    suite = BenchmarkSuite.from_yaml(args.suite)
    try:
        async with OllamaChatClient(
            args.base_url,
            args.timeout,
            context_tokens=args.context_tokens,
        ) as client:
            models = await client.available_models()
            if args.model not in models:
                available = ", ".join(models) if models else "ninguno"
                raise OllamaClientError(
                    f"El modelo {args.model!r} no está instalado. Disponibles: {available}"
                )
            report = await BenchmarkRunner(client).run(suite, args.model)
    except OllamaClientError as exc:
        print(f"Error: {exc}")
        return 1

    print(report.model_dump_json(indent=2))
    return 0 if report.passed_cases == report.total_cases else 2


def main() -> None:
    raise SystemExit(asyncio.run(run(parse_args())))


if __name__ == "__main__":
    main()
