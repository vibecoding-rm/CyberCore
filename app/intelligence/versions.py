"""Conservative version comparison for affected-range checks.

The comparator only answers when the ordering is unambiguous. Any doubt
(pre-release suffixes, mixed numeric/alphabetic segments at the deciding
position, unparsable strings) yields ``None`` so callers report the range as
indeterminate instead of guessing.

A trailing letter is ambiguous in general ("1.0rc1" is older than "1.0",
"9.8p1" is newer than "9.8"), so products whose numbering is known get their
own scheme. OpenSSL before 3.0 appends letters for later patch releases:
1.0.1 < 1.0.1a < ... < 1.0.1z < 1.0.1za.
"""

import re
from typing import Literal

_TOKEN_RE = re.compile(r"\d+|[a-z]+")
_VALID_RE = re.compile(r"^[0-9a-z][0-9a-z.\-_+]*$")

Token = int | str
Verdict = Literal["affected", "not_affected", "indeterminate"]
Scheme = Literal["generic", "openssl"]

_OPENSSL_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)([a-z]{0,2})$")
# CPE vendor:product pairs whose versions follow a known scheme.
_SCHEMES: dict[tuple[str, str], Scheme] = {("openssl", "openssl"): "openssl"}


def scheme_for(vendor: str | None, product: str | None) -> Scheme:
    return _SCHEMES.get(((vendor or "").lower(), (product or "").lower()), "generic")


def _openssl_key(version: str) -> tuple[int, int, int, tuple[int, ...]] | None:
    """1.0.1e -> (1, 0, 1, (5,)); anything else (1.0.2k-fips, 3.0.0-beta1) -> None."""
    match = _OPENSSL_RE.match(version.strip().lower())
    if match is None:
        return None
    major, minor, patch, letters = match.groups()
    return int(major), int(minor), int(patch), tuple(ord(c) - ord("a") + 1 for c in letters)


def tokenize(version: str) -> list[Token] | None:
    """Split a version into numeric and alphabetic runs, e.g. 9.6p1 -> [9, 6, 'p', 1]."""
    cleaned = version.strip().lower()
    if not cleaned or not _VALID_RE.match(cleaned) or ":" in cleaned or "~" in cleaned:
        return None
    return [int(tok) if tok.isdigit() else tok for tok in _TOKEN_RE.findall(cleaned)]


def compare_versions(left: str, right: str, scheme: Scheme = "generic") -> int | None:
    """Return -1, 0 or 1 when the ordering is certain, otherwise None."""
    if scheme == "openssl":
        ka, kb = _openssl_key(left), _openssl_key(right)
        if ka is None or kb is None:
            return None
        return (ka > kb) - (ka < kb)
    a = tokenize(left)
    b = tokenize(right)
    if not a or not b:
        return None

    for x, y in zip(a, b):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        # Mixed or alphabetic segments (1.1.1k vs 1.1.1m is the only safe case).
        if isinstance(x, str) and isinstance(y, str) and len(x) == len(y) == 1:
            return -1 if x < y else 1
        return None

    tail = a[len(b):] if len(a) > len(b) else b[len(a):]
    if not tail:
        return 0
    # "1.0" vs "1.0.0" is equal; "1.0" vs "1.0.1" is ordered; a trailing
    # suffix such as "9.8" vs "9.8p1" or "1.0" vs "1.0rc1" is ambiguous.
    if all(isinstance(tok, int) for tok in tail):
        if all(tok == 0 for tok in tail):
            return 0
        return 1 if len(a) > len(b) else -1
    return None


def evaluate_range(
    installed: str,
    *,
    exact: str | None = None,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
    scheme: Scheme = "generic",
) -> tuple[Verdict, str]:
    """Decide whether ``installed`` falls inside the declared bounds."""
    if exact is not None:
        result = compare_versions(installed, exact, scheme)
        if result is None:
            return "indeterminate", f"No se puede comparar {installed!r} con {exact!r}"
        if result == 0:
            return "affected", f"Coincide con la versión afectada {exact}"
        return "not_affected", f"Distinta de la versión afectada {exact}"

    bounds = (
        (start_including, lambda r: r >= 0, ">="),
        (start_excluding, lambda r: r > 0, ">"),
        (end_including, lambda r: r <= 0, "<="),
        (end_excluding, lambda r: r < 0, "<"),
    )
    if all(bound is None for bound, _, _ in bounds):
        return "indeterminate", "El rango no declara límites de versión"

    satisfied: list[str] = []
    for bound, predicate, symbol in bounds:
        if bound is None:
            continue
        result = compare_versions(installed, bound, scheme)
        if result is None:
            return (
                "indeterminate",
                f"No se puede comparar {installed!r} con el límite {symbol} {bound}",
            )
        if not predicate(result):
            return "not_affected", f"{installed} no cumple {symbol} {bound}"
        satisfied.append(f"{symbol} {bound}")
    return "affected", f"{installed} cumple {' y '.join(satisfied)}"
