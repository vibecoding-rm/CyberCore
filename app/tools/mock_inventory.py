from typing import Any

from ipaddress import ip_address

from pydantic import BaseModel, ConfigDict, Field, field_validator


class MockInventoryArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    target: str = Field(min_length=1, max_length=45)

    @field_validator("target")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        return str(ip_address(value))


class MockInventoryTool:
    name = "get_mock_inventory"
    mode = "mock"
    timeout_seconds = 5.0

    def validate_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return MockInventoryArguments.model_validate(arguments).model_dump(mode="json")

    async def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        target = str(arguments["target"])
        return {
            "target": target,
            "source": "simulated",
            "operating_system": "Ubuntu 24.04 (simulado)",
            "services": [
                {"port": 22, "protocol": "tcp", "service": "ssh", "state": "open"},
                {"port": 443, "protocol": "tcp", "service": "https", "state": "open"},
            ],
            "notice": "No se ejecutó ningún escaneo real.",
        }
