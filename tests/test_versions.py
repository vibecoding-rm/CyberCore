import pytest

from app.intelligence.cpe import parse_cpe
from app.intelligence.versions import compare_versions, evaluate_range, tokenize


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("2.4.49", "2.4.50", -1),
        ("2.4.50", "2.4.49", 1),
        ("2.4.49", "2.4.49", 0),
        ("1.0", "1.0.0", 0),
        ("1.0", "1.0.1", -1),
        ("10.0", "9.9", 1),
        ("9.6p1", "9.8", -1),
        ("8.5p1", "8.5p1", 0),
        ("8.5p1", "8.5p2", -1),
        ("1.1.1k", "1.1.1m", -1),
    ],
)
def test_ordered_versions(left, right, expected):
    assert compare_versions(left, right) == expected


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("9.8p1", "9.8"),  # suffix after a shared prefix: fixed or not depends on vendor
        ("1.0.0rc1", "1.0.0"),  # pre-release ordering is scheme specific
        ("1:2.3-4", "2.3"),  # Debian epochs need a dedicated comparator
        ("2.0~beta", "2.0"),
        ("abc", "1.0"),
        ("", "1.0"),
        ("1.0beta", "1.0alpha"),  # multi-letter words are not ordered alphabetically
    ],
)
def test_ambiguous_versions_are_not_guessed(left, right):
    assert compare_versions(left, right) is None


def test_tokenize_rejects_garbage():
    assert tokenize("2.4.49 (Unix)") is None
    assert tokenize("9.6p1") == [9, 6, "p", 1]


def test_range_with_both_bounds():
    verdict, reason = evaluate_range("9.6p1", start_including="8.6", end_including="9.8")
    assert verdict == "affected"
    assert ">= 8.6" in reason and "<= 9.8" in reason


def test_value_outside_range_is_not_affected():
    assert evaluate_range("2.4.51", end_excluding="2.4.50")[0] == "not_affected"
    assert evaluate_range("8.5", start_including="8.6", end_including="9.8")[0] == "not_affected"


def test_violated_bound_is_decisive_even_if_other_is_ambiguous():
    # 7.0 < 8.6 settles it; the ambiguous upper bound is never needed.
    assert evaluate_range("7.0", start_including="8.6", end_including="9.8p1")[0] == "not_affected"


def test_ambiguous_bound_yields_indeterminate():
    verdict, _ = evaluate_range("9.8p1", start_including="8.6", end_including="9.8")
    assert verdict == "indeterminate"


def test_exact_version():
    assert evaluate_range("2.4.49", exact="2.4.49")[0] == "affected"
    assert evaluate_range("2.4.48", exact="2.4.49")[0] == "not_affected"


def test_range_without_bounds_is_indeterminate():
    assert evaluate_range("1.0")[0] == "indeterminate"


def test_parse_cpe_formats():
    uri = parse_cpe("cpe:/a:openbsd:openssh:9.6p1")
    assert uri is not None and uri.key == "openbsd:openssh" and uri.version == "9.6p1"

    formatted = parse_cpe("cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*")
    assert formatted is not None and formatted.version == "8.5p1"

    wildcard = parse_cpe("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")
    assert wildcard is not None and wildcard.version is None

    assert parse_cpe("cpe:2.3:a:*:openssh:1.0") is None
    assert parse_cpe("openssh 9.6") is None
