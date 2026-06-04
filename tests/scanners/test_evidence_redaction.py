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


def test_redacts_dotted_r_assignments_and_raw_strings() -> None:
    """Dotted identifiers and native raw literals should not leak credential values."""
    redacted = redact_evidence_string(
        'api.key <- "DOT_LEFT_SECRET"; "DOT_RIGHT_SECRET" -> access.token; '
        'token <- r"(RAW_LEFT_SECRET)"; R"---{RAW_RIGHT_SECRET}---" -> client.secret; '
        'refresh.token <- r"[raw values may contain \\"quotes\\" and ; delimiters]"; '
        '"access token" <- "QUOTED_NAME_SECRET"; r"(QUOTED_RAW_SECRET)" -> \'client.secret\'',
        max_chars=700,
    )

    for secret in (
        "DOT_LEFT_SECRET",
        "DOT_RIGHT_SECRET",
        "RAW_LEFT_SECRET",
        "RAW_RIGHT_SECRET",
        "QUOTED_NAME_SECRET",
        "QUOTED_RAW_SECRET",
    ):
        assert secret not in redacted
    assert "raw values may contain" not in redacted
    assert f'api.key <- "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'"{REDACTED_EVIDENCE_VALUE}" -> access.token' in redacted
    assert f"token <- {REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"{REDACTED_EVIDENCE_VALUE} -> client.secret" in redacted
    assert f"refresh.token <- {REDACTED_EVIDENCE_VALUE}" in redacted
    assert f'"access token" <- "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f"{REDACTED_EVIDENCE_VALUE} -> 'client.secret'" in redacted


def test_unterminated_r_raw_assignment_fails_closed() -> None:
    """Malformed raw literals should not leak their remaining payload."""
    redacted = redact_evidence_string(
        'base::system("curl"); token <- r"(UNTERMINATED_RAW_SECRET',
        max_chars=500,
    )

    assert "UNTERMINATED_RAW_SECRET" not in redacted
    assert redacted.endswith(f"token <- {REDACTED_EVIDENCE_VALUE}")


def test_malformed_r_raw_prefix_does_not_hide_later_assignment() -> None:
    """A malformed raw candidate should not consume a later valid credential literal."""
    redacted = redact_evidence_string(
        'r"{BROKEN_PREFIX; token <- r"(LATER_RAW_SECRET)"',
        max_chars=500,
    )

    assert "LATER_RAW_SECRET" not in redacted
    assert redacted.endswith(f"token <- {REDACTED_EVIDENCE_VALUE}")


def test_unterminated_quoted_r_assignments_fail_closed() -> None:
    """Incomplete ordinary string literals should not leak their remaining payload."""
    double_quoted = redact_evidence_string('token <- "DOUBLE_QUOTED_SECRET', max_chars=500)
    single_quoted = redact_evidence_string("password <<- 'SINGLE_QUOTED_SECRET", max_chars=500)

    assert double_quoted == f"token <- {REDACTED_EVIDENCE_VALUE}"
    assert single_quoted == f"password <<- {REDACTED_EVIDENCE_VALUE}"


def test_redacts_full_rightward_assignment_expressions() -> None:
    """Rightward assignment evidence should redact calls and parenthesized values."""
    redacted = redact_evidence_string(
        'base::system("curl"); paste("PREFIX;RIGHTWARD_SECRET", collapse=";") -> token; '
        '("PARENTHESIZED_SECRET") -> password',
        max_chars=500,
    )

    assert 'base::system("curl")' in redacted
    assert "PREFIX" not in redacted
    assert "RIGHTWARD_SECRET" not in redacted
    assert "PARENTHESIZED_SECRET" not in redacted
    assert redacted.count(REDACTED_EVIDENCE_VALUE) == 2


def test_rightward_raw_assignment_does_not_bypass_redaction_with_long_identifier() -> None:
    """Rightward targets should be inspected beyond the stored evidence length."""
    long_identifier = f"service_{'a' * 300}_token"
    redacted = redact_evidence_string(
        f'r"(LONG_RIGHTWARD_RAW_SECRET)" -> {long_identifier}',
        max_chars=500,
    )

    assert "LONG_RIGHTWARD_RAW_SECRET" not in redacted
    assert redacted.startswith(f"{REDACTED_EVIDENCE_VALUE} -> service_")


def test_large_rightward_assignment_evidence_avoids_pathological_backtracking() -> None:
    """Large printable executable strings should remain practical to redact."""
    redacted = redact_evidence_string(
        f"LONG_RIGHTWARD_SECRET -> service_token {'A' * 500_000}",
        max_chars=200,
    )

    assert "LONG_RIGHTWARD_SECRET" not in redacted
    assert redacted.startswith(f"{REDACTED_EVIDENCE_VALUE} -> service_token ")


def test_many_raw_assignments_are_redacted_in_one_pass() -> None:
    """Repeated raw literals should not rebuild the full evidence string per match."""
    text = "; ".join(f'token <- r"(RAW_SECRET_{index:04d})"' for index in range(2_000))

    redacted = redact_evidence_string(text, max_chars=len(text) * 2)

    assert "RAW_SECRET_0000" not in redacted
    assert "RAW_SECRET_1999" not in redacted
    assert redacted.count(REDACTED_EVIDENCE_VALUE) == 2_000


def test_many_rightward_assignments_are_redacted_in_one_pass() -> None:
    """Repeated rightward targets should reuse lexical statement analysis."""
    text = "; ".join(f"RIGHTWARD_SECRET_{index:04d} -> token" for index in range(2_000))

    redacted = redact_evidence_string(text, max_chars=len(text) * 2)

    assert "RIGHTWARD_SECRET_0000" not in redacted
    assert "RIGHTWARD_SECRET_1999" not in redacted
    assert redacted.count(REDACTED_EVIDENCE_VALUE) == 2_000
