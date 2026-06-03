"""Tests for scanner evidence redaction helpers."""

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


def test_redacts_r_assignment_operators() -> None:
    """Native R assignment operators should not preserve raw credential values."""
    redacted = redact_evidence_string(
        "token <- 'R_TOKEN_SECRET' password <<- R_PASSWORD_SECRET",
        max_chars=500,
    )

    assert "R_TOKEN_SECRET" not in redacted
    assert "R_PASSWORD_SECRET" not in redacted
    assert f"token <- '{REDACTED_EVIDENCE_VALUE}'" in redacted
    assert f"password <<- {REDACTED_EVIDENCE_VALUE}" in redacted


def test_redacts_r_rightward_assignment_operators() -> None:
    """Native R rightward assignment operators should not preserve raw credential values."""
    redacted = redact_evidence_string(
        "'R_TOKEN_SECRET' -> token \"R_PASSWORD_SECRET\" ->> password R_BARE_SECRET -> service_token",
        max_chars=500,
    )

    assert "R_TOKEN_SECRET" not in redacted
    assert "R_PASSWORD_SECRET" not in redacted
    assert "R_BARE_SECRET" not in redacted
    assert f"'{REDACTED_EVIDENCE_VALUE}' -> token" in redacted
    assert f'"{REDACTED_EVIDENCE_VALUE}" ->> password' in redacted
    assert f"{REDACTED_EVIDENCE_VALUE} -> service_token" in redacted


def test_redacts_escaped_and_backticked_r_assignments() -> None:
    """Escaped quoted values and backticked R identifiers should not leak secrets."""
    redacted = redact_evidence_string(
        r"""token <- "ABC\"ESCAPED_SECRET" `access-token` <- 'BACKTICK_LEFT' """
        + '"BACKTICK_RIGHT" -> `client-secret`; `api key` <- "SPACED_BACKTICK"',
        max_chars=500,
    )

    assert "ESCAPED_SECRET" not in redacted
    assert "BACKTICK_LEFT" not in redacted
    assert "BACKTICK_RIGHT" not in redacted
    assert "SPACED_BACKTICK" not in redacted
    assert f'token <- "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f"`access-token` <- '{REDACTED_EVIDENCE_VALUE}'" in redacted
    assert f'"{REDACTED_EVIDENCE_VALUE}" -> `client-secret`' in redacted
    assert f'`api key` <- "{REDACTED_EVIDENCE_VALUE}"' in redacted
