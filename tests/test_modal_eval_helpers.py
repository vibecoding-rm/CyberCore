import pytest

modal_train = pytest.importorskip("training.modal_train")


def test_base_model_aliases_are_explicit_and_cache_safe():
    assert modal_train.resolve_base_model("qwen3.5-4b") == "Qwen/Qwen3.5-4B"
    assert modal_train.hf_cache_directory("Qwen/Qwen3.5-4B") == "models--Qwen--Qwen3.5-4B"
    with pytest.raises(ValueError, match="Modelo base no soportado"):
        modal_train.resolve_base_model("arbitrary/model")


def test_first_json_object_skips_prose_and_broken_braces():
    text = 'Claro {roto} aquí va: {"action_type": "final_answer", "final_summary": "ok"} fin'
    assert modal_train.first_json_object(text) == {"action_type": "final_answer", "final_summary": "ok"}
    assert modal_train.first_json_object("sin json") is None


def test_compare_action_grades_structure_not_wording():
    expected = {"action_type": "call_tool", "tool": "inspect_services", "arguments": {"target": "192.168.10.5", "ports": [53]}}
    right = {"action_type": "call_tool", "tool": "inspect_services", "arguments": {"target": "192.168.10.5"}}
    wrong_target = {"action_type": "call_tool", "tool": "inspect_services", "arguments": {"target": "192.168.10.0/24"}}
    wrong_tool = {"action_type": "call_tool", "tool": "discover_hosts", "arguments": {"target": "192.168.10.5"}}

    assert all(modal_train.compare_action(right, expected).values())
    assert modal_train.compare_action(wrong_target, expected) == {"valid": True, "action_type": True, "tool": True, "target": False}
    assert modal_train.compare_action(wrong_tool, expected)["tool"] is False
    assert modal_train.compare_action(None, expected)["valid"] is False

    final = {"action_type": "final_answer", "final_summary": "x"}
    assert all(modal_train.compare_action({"action_type": "final_answer", "final_summary": "y"}, final).values())
    assert not modal_train.compare_action(right, final)["action_type"]
