import pytest
from pydantic import ValidationError

from app.api.models import ToolRequest


def test_request_rejects_unknown_top_level_fields():
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ToolRequest.model_validate(
            {
                "tool": "get_mock_inventory",
                "arguments": {"target": "192.168.10.25"},
                "admin": True,
            }
        )


@pytest.mark.parametrize(
    "tool_name",
    ["", "Shell", "../shell", "tool-name", "tool name", "a" * 101],
)
def test_request_rejects_invalid_tool_names(tool_name):
    with pytest.raises(ValidationError):
        ToolRequest(tool=tool_name)


def test_request_limits_argument_count():
    with pytest.raises(ValidationError, match="too_long"):
        ToolRequest(
            tool="get_mock_inventory",
            arguments={f"key_{index}": index for index in range(33)},
        )
