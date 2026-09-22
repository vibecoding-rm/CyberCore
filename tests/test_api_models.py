from uuid import UUID

import pytest
from pydantic import ValidationError

from app.api.models import (
    InventoryAssessmentRequest,
    ToolRequest,
    ToolRequestInput,
)


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


def test_request_rejects_non_uuid_request_id():
    with pytest.raises(ValidationError, match="uuid"):
        ToolRequest(
            request_id="replayed-or-malformed-id",
            tool="get_mock_inventory",
        )


def test_public_request_rejects_unverified_identity():
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ToolRequestInput.model_validate(
            {
                "tool": "get_mock_inventory",
                "arguments": {"target": "192.168.10.25"},
                "requested_by": "spoofed-admin",
            }
        )


@pytest.mark.parametrize(
    "vulnerability_id",
    ["cve-2026-99999", "CVE-26-1", "CVE-2026-ABC", "not-a-cve"],
)
def test_inventory_assessment_rejects_malformed_cve(vulnerability_id):
    with pytest.raises(ValidationError):
        InventoryAssessmentRequest(
            target="192.168.10.25",
            vulnerability_id=vulnerability_id,
        )


def test_inventory_assessment_rejects_extra_fields():
    with pytest.raises(ValidationError, match="extra_forbidden"):
        InventoryAssessmentRequest.model_validate(
            {
                "target": "192.168.10.25",
                "conclusion": "confirmed",
            }
        )


def test_inventory_assessment_accepts_uuid_from_json():
    request = InventoryAssessmentRequest.model_validate_json(
        """
        {
          "request_id": "12345678-1234-5678-1234-567812345678",
          "target": "192.168.10.25"
        }
        """
    )

    assert request.request_id == UUID("12345678-1234-5678-1234-567812345678")
