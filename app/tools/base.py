from typing import Any, Protocol


class ToolAdapter(Protocol):
    name: str

    async def execute(self, arguments: dict[str, Any]) -> dict[str, Any]: ...
