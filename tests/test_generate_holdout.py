import yaml

from scripts.generate_benchmark import build_suite
from scripts.generate_holdout import OUTPUT, build_holdout


def test_holdout_shares_no_prompt_with_the_main_benchmark():
    existing = {case["prompt"] for case in build_suite()["cases"]}
    holdout = build_holdout()["cases"]
    assert {case["split"] for case in holdout} == {"holdout"}
    assert not existing & {case["prompt"] for case in holdout}


def test_committed_holdout_matches_the_generator():
    committed = yaml.safe_load(OUTPUT.read_text(encoding="utf-8"))
    assert committed == build_holdout()
