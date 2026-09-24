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
    )

    assert decision.allowed is False
    assert decision.approval_required is True
    assert "aprobación humana" in decision.reason


def test_only_exact_internal_approval_flag_can_authorize(tmp_path):
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
        approval_granted=True,
    )

    assert decision.allowed is True
    assert decision.approval_required is True


@pytest.mark.parametrize("target", ["8.8.8.8", "172.16.8.8", "192.168.0.0/16", "admin.intranet"])
def test_out_of_scope_invasive_request_is_denied_not_sent_to_approval(tmp_path, target):
    # The benchmark model answers approval_required here; scope must win so no
    # approver is ever asked to authorize an out-of-scope target.
    config = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    config["tools"]["approval_probe"] = {
        "enabled": True,
        "risk": "high",
        "approval_required": True,
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    engine = PolicyEngine(path)

    for granted in (False, True):
        decision = engine.evaluate("approval_probe", {"target": target}, approval_granted=granted)
        assert decision.allowed is False
        assert decision.approval_required is False


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


def test_policy_reports_when_enabled_tool_requires_approver(tmp_path):
    config = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    config["tools"]["get_mock_inventory"]["approval_required"] = True
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")

    assert PolicyEngine(path).requires_approver is True
    assert PolicyEngine(POLICY).requires_approver is False
