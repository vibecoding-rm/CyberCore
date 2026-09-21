from typing import Any, Protocol


class ToolAdapter(Protocol):
    name: str
    mode: str
    timeout_seconds: float

    def validate_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]: ...

    async def execute(self, arguments: dict[str, Any]) -> dict[str, Any]: ...
