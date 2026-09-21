from typing import Any


class MockInventoryTool:
    name = "get_mock_inventory"

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
