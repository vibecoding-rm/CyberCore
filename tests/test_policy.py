from pathlib import Path

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
