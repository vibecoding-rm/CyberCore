from pathlib import Path

import pytest
import yaml

from app.core.policy import PolicyEngine


POLICY = Path(__file__).parents[1] / "config" / "policy.yaml"


def test_allows_private_mock_target():
    engine = PolicyEngine(POLICY)
    decision = engine.evaluate("get_mock_inventory", {"target": "192.168.10.25"}, None)
    assert decision.allowed is True


def test_denies_public_target():
    engine = PolicyEngine(POLICY)
    decision = engine.evaluate("get_mock_inventory", {"target": "8.8.8.8"}, None)
    assert decision.allowed is False
    assert "fuera del alcance" in decision.reason


def test_denies_unregistered_tool():
    engine = PolicyEngine(POLICY)
    decision = engine.evaluate("shell", {"target": "192.168.10.25"}, None)
    assert decision.allowed is False


def test_disabled_active_tool_cannot_run_even_with_approval():
    engine = PolicyEngine(POLICY)
    decision = engine.evaluate(
        "run_nuclei_safe",
        {"target": "192.168.10.25"},
        "example-token",
    )
    assert decision.allowed is False
    assert decision.approval_required is False


def test_denies_private_address_outside_explicit_lab_scope():
    engine = PolicyEngine(POLICY)
    decision = engine.evaluate("get_mock_inventory", {"target": "10.0.0.10"}, None)
    assert decision.allowed is False
    assert "fuera del alcance" in decision.reason


def test_denies_public_ipv6_without_raising():
    engine = PolicyEngine(POLICY)
    decision = engine.evaluate(
        "get_mock_inventory", {"target": "2001:4860:4860::8888"}, None
    )
    assert decision.allowed is False
    assert "fuera del alcance" in decision.reason


def test_denies_cidr_larger_than_target_budget():
    engine = PolicyEngine(POLICY)
    decision = engine.evaluate(
        "get_mock_inventory", {"target": "192.168.10.0/23"}, None
    )
    assert decision.allowed is False
    assert "512 direcciones" in decision.reason


def test_hostname_setting_still_fails_closed_until_safe_resolution_exists(tmp_path):
    config = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    config["scope"]["allow_hostnames"] = True
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")

    decision = PolicyEngine(path).evaluate(
        "get_mock_inventory",
        {"target": "internal.example"},
        None,
    )

    assert decision.allowed is False
    assert "aún no" in decision.reason


def test_free_form_approval_token_is_never_trusted(tmp_path):
    config = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    config["tools"]["approval_probe"] = {
        "enabled": True,
        "risk": "high",
        "approval_required": True,
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")

    decision = PolicyEngine(path).evaluate(
        "approval_probe",
        {"target": "192.168.10.25"},
        "yes-approve-everything",
        "attacker",
    )

    assert decision.allowed is False
    assert decision.approval_required is True
    assert "verificador" in decision.reason


class AmbiguousApprovalValidator:
    def consume(self, token, requested_by, tool_name, arguments):
        return "yes"


class BrokenApprovalValidator:
    def consume(self, token, requested_by, tool_name, arguments):
        raise RuntimeError("approval backend unavailable")


@pytest.mark.parametrize(
    "validator",
    [AmbiguousApprovalValidator(), BrokenApprovalValidator()],
)
def test_approval_validator_must_return_exact_true_and_must_not_raise(
    tmp_path, validator
):
    config = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    config["tools"]["approval_probe"] = {
        "enabled": True,
        "risk": "high",
        "approval_required": True,
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")

    decision = PolicyEngine(path, approval_validator=validator).evaluate(
        "approval_probe",
        {"target": "192.168.10.25"},
        "candidate-token",
        "operator",
    )

    assert decision.allowed is False
    assert decision.approval_required is True


def test_invalid_budget_prevents_policy_startup(tmp_path):
    config = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    config["budgets"]["max_parallel_jobs"] = 0
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")

    with pytest.raises(ValueError, match="max_parallel_jobs"):
        PolicyEngine(path)


def test_string_boolean_prevents_policy_startup(tmp_path):
    config = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    config["tools"]["get_mock_inventory"]["enabled"] = "false"
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")

    with pytest.raises(ValueError, match="enabled debe ser booleano"):
        PolicyEngine(path)
