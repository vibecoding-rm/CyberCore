import argparse
import asyncio
from pathlib import Path

from app.evaluation.benchmark import BenchmarkRunner, BenchmarkSuite
from app.llm.base import ChatClient, LLMClientError
from app.llm.llamacpp import LlamaCppChatClient
from app.llm.ollama import OllamaChatClient
from app.settings import get_settings


def parse_args() -> argparse.Namespace:
    settings = get_settings()
    parser = argparse.ArgumentParser(
        description="Evalúa un modelo local sin darle acceso a herramientas.",
    )
    parser.add_argument(
        "--provider",
        choices=["ollama", "llamacpp"],
        default=settings.llm_provider,
    )
    parser.add_argument("--model", default=settings.orchestrator_model)
    parser.add_argument("--suite", default="config/benchmark_cybercam.yaml")
    parser.add_argument(
        "--split",
        choices=["train", "development", "test", "holdout", "all"],
        default="development",
        help="'test' sólo para la medición final; nunca para ajustar el prompt",
    )
    parser.add_argument("--output", default=None, help="Guarda el informe JSON en este archivo")
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument(
        "--context-tokens",
        type=int,
        default=settings.ollama_context_tokens,
        help="Sólo Ollama; en llama.cpp el contexto se fija al iniciar llama-server (-c).",
    )
    return parser.parse_args()


def build_client(args: argparse.Namespace) -> ChatClient:
    settings = get_settings()
    if args.provider == "llamacpp":
        return LlamaCppChatClient(
            args.base_url or settings.llamacpp_base_url,
            args.timeout or settings.llamacpp_request_timeout_seconds,
            api_key=settings.llamacpp_api_key or None,
        )
    return OllamaChatClient(
        args.base_url or settings.ollama_base_url,
        args.timeout or settings.ollama_request_timeout_seconds,
        context_tokens=args.context_tokens,
    )


async def run(args: argparse.Namespace) -> int:
    suite = BenchmarkSuite.from_yaml(args.suite)
    client = build_client(args)
    try:
        models = await client.available_models()
        if args.model not in models:
            available = ", ".join(models) if models else "ninguno"
            raise LLMClientError(
                f"El modelo {args.model!r} no está disponible. Disponibles: {available}"
            )
        split = None if args.split == "all" else args.split
        report = await BenchmarkRunner(client).run(suite, args.model, split=split)
    except LLMClientError as exc:
        print(f"Error: {exc}")
        return 1
    finally:
        await client.aclose()

    output = report.model_dump_json(indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    print(output)
    return 0 if report.passed_cases == report.total_cases else 2


def main() -> None:
    raise SystemExit(asyncio.run(run(parse_args())))


if __name__ == "__main__":
    main()
