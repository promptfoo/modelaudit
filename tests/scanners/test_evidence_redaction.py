"""Tests for scanner evidence redaction helpers."""

import pytest

from modelaudit.scanners._evidence_redaction import REDACTED_EVIDENCE_VALUE, redact_evidence_string


def test_redacts_compound_credential_assignments() -> None:
    """Compound credential keys should not preserve raw values."""
    text = (
        "client_secret=CLIENTSECRET123 "
        "refresh_token='REFRESHTOKEN456' "
        'access-token="ACCESSTOKEN789" '
        "service-private-key=PRIVATEKEY000"
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "CLIENTSECRET123" not in redacted
    assert "REFRESHTOKEN456" not in redacted
    assert "ACCESSTOKEN789" not in redacted
    assert "PRIVATEKEY000" not in redacted
    assert f"client_secret={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"refresh_token='{REDACTED_EVIDENCE_VALUE}'" in redacted
    assert f'access-token="{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f"service-private-key={REDACTED_EVIDENCE_VALUE}" in redacted


def test_redacts_compound_sensitive_query_parameters() -> None:
    """Compound query credential keys should be redacted in URL evidence."""
    text = "url=https://example.com/callback?client_secret=CLIENTSECRET123&refresh_token=REFRESHTOKEN456&ok=1"

    redacted = redact_evidence_string(text, max_chars=500)

    assert "CLIENTSECRET123" not in redacted
    assert "REFRESHTOKEN456" not in redacted
    assert "client_secret=<redacted>" in redacted
    assert "refresh_token=<redacted>" in redacted
    assert "ok=1" in redacted


def test_redacts_malformed_userinfo_url() -> None:
    """Malformed userinfo URLs should fail closed instead of returning raw evidence."""
    text = "download=https://user:LEAKY-PASS@[::1/path?token=QUERYSECRET"

    redacted = redact_evidence_string(text, max_chars=500)

    assert "user:LEAKY-PASS" not in redacted
    assert "QUERYSECRET" not in redacted
    assert "https://<credentials-redacted>@[::1/path" in redacted


def test_existing_token_assignment_redaction_still_applies() -> None:
    """Canonical token assignments should keep their existing redaction behavior."""
    redacted = redact_evidence_string("token=CANONICALTOKEN123", max_chars=500)

    assert "CANONICALTOKEN123" not in redacted
    assert redacted == f"token={REDACTED_EVIDENCE_VALUE}"


def test_redacts_capability_tokens_in_url_paths() -> None:
    """Opaque URL path tokens should not survive evidence serialization."""
    token = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"

    redacted = redact_evidence_string(f"https://example.com/path/{token}/model.bin", max_chars=500)

    assert token not in redacted
    assert redacted == f"https://example.com/path/{REDACTED_EVIDENCE_VALUE}/model.bin"


@pytest.mark.parametrize("scheme", ["ftps", "ssh", "telnet", "ws", "wss", "az", "wasb", "wasbs", "abfs", "abfss"])
def test_redacts_capability_tokens_in_supported_network_url_schemes(scheme: str) -> None:
    """Every URL scheme recognized by the network detector should redact path tokens."""
    token = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"

    redacted = redact_evidence_string(f"{scheme}://example.com/path/{token}/model.bin", max_chars=500)

    assert token not in redacted
    assert redacted == f"{scheme}://example.com/path/{REDACTED_EVIDENCE_VALUE}/model.bin"


def test_preserves_azure_authority_container_while_redacting_object_path_token() -> None:
    """A valid Azure authority container is identity, not userinfo."""
    token = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"

    redacted = redact_evidence_string(
        f"wasbs://container@account.blob.core.windows.net/{token}/model.bin",
        max_chars=500,
    )

    assert redacted == f"wasbs://container@account.blob.core.windows.net/{REDACTED_EVIDENCE_VALUE}/model.bin"


def test_redacts_azure_authority_userinfo_that_is_not_a_valid_container() -> None:
    """Azure authority credentials must not be mistaken for a container name."""
    redacted = redact_evidence_string(
        "wasbs://container:secret@account.blob.core.windows.net/model.bin",
        max_chars=500,
    )

    assert redacted == "wasbs://<credentials-redacted>@account.blob.core.windows.net/model.bin"


@pytest.mark.parametrize(
    "token",
    [
        "ghp_" + "a" * 36,
        "gho_" + "a" * 36,
        "ghu_" + "a" * 36,
        "ghs_" + "a" * 36,
        "ghr_" + "a" * 36,
        "AIza" + "a" * 35,
        "glpat-" + "a" * 20,
        "npm_" + "a" * 36,
        "sq0atp-" + "a" * 22,
        "sq0csp-" + "a" * 43,
        "stripe_live_" + "a" * 24,
        "sk_live_" + "a" * 24,
        "rk_live_" + "a" * 24,
    ],
)
def test_redacts_standalone_secret_token_shapes(token: str) -> None:
    """Secret-shaped strings should be redacted even without assignment syntax."""
    redacted = redact_evidence_string(f"metadata key: {token}", max_chars=500)

    assert token not in redacted
    assert redacted == f"metadata key: {REDACTED_EVIDENCE_VALUE}"
