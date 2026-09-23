from app.llm.base import ChatClient
from app.llm.llamacpp import LlamaCppChatClient
from app.llm.ollama import OllamaChatClient
from app.settings import Settings


def create_chat_client(settings: Settings) -> ChatClient:
    if settings.llm_provider == "llamacpp":
        return LlamaCppChatClient(
            base_url=settings.llamacpp_base_url,
            timeout_seconds=settings.llamacpp_request_timeout_seconds,
            api_key=settings.llamacpp_api_key or None,
        )
    return OllamaChatClient(
        base_url=settings.ollama_base_url,
        timeout_seconds=settings.ollama_request_timeout_seconds,
        context_tokens=settings.ollama_context_tokens,
    )


def llm_base_url(settings: Settings) -> str:
    if settings.llm_provider == "llamacpp":
        return settings.llamacpp_base_url
    return settings.ollama_base_url
