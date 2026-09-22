import json

import pytest

from app.core.auth import ApiCredential, ApiKeyAuthenticator


OPERATOR_KEY = "operator-key-with-at-least-32-characters"


def credential(subject="verified-operator", role="operator", api_key=OPERATOR_KEY):
    return ApiCredential(
        subject=subject,
        role=role,
        key_sha256=ApiKeyAuthenticator.hash_api_key(api_key),
    )


def test_authenticates_valid_key_without_storing_plaintext():
    authenticator = ApiKeyAuthenticator([credential()])

    principal = authenticator.authenticate(OPERATOR_KEY)

    assert principal is not None
    assert principal.subject == "verified-operator"
    assert principal.role == "operator"
    assert OPERATOR_KEY not in repr(authenticator.credentials)


@pytest.mark.parametrize(
    "candidate",
    ["", "too-short", "x" * 513, "different-key-with-at-least-32-characters"],
)
def test_rejects_missing_malformed_or_unknown_keys(candidate):
    authenticator = ApiKeyAuthenticator([credential()])
    assert authenticator.authenticate(candidate) is None


def test_loads_strict_credentials_from_json():
    raw = json.dumps([credential(role="viewer").model_dump()])
    authenticator = ApiKeyAuthenticator.from_json(raw)

    principal = authenticator.authenticate(OPERATOR_KEY)

    assert authenticator.configured is True
    assert principal is not None
    assert principal.role == "viewer"


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        "{}",
        '[{"subject":"operator","role":"admin","key_sha256":"bad"}]',
        '[{"subject":"operator","role":"operator","key_sha256":"' + "a" * 64 + '","key":"secret"}]',
    ],
)
def test_rejects_invalid_credential_configuration(raw):
    with pytest.raises(ValueError):
        ApiKeyAuthenticator.from_json(raw)


def test_rejects_duplicate_key_hashes():
    with pytest.raises(ValueError, match="duplicados"):
        ApiKeyAuthenticator([credential("first"), credential("second")])
