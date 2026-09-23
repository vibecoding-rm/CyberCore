import hashlib
from typing import Any

from app.core.tool_broker import ToolBroker


def evidence_sha256(data: dict[str, Any]) -> str:
    """Hash used to seal tool evidence; also used to re-verify it when loaded."""
    return hashlib.sha256(ToolBroker.canonical_json(data)).hexdigest()
