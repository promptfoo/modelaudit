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


def test_redacts_signed_url_queries_and_capability_path_tokens() -> None:
    """Stored evidence should use the bounded network URL path policy."""
    path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"
    text = f"https://storage.googleapis.com/model-bucket/{path_token}/weights.bin?X-Goog-Signature=QUERYSECRET"

    redacted = redact_evidence_string(text, max_chars=500)

    assert path_token not in redacted
    assert "QUERYSECRET" not in redacted
    assert "model-bucket/<redacted>/weights.bin" in redacted
    assert "X-Goog-Signature=<redacted>" in redacted


def test_redacts_token_only_userinfo_across_network_url_schemes() -> None:
    """Network URL previews should not preserve token-only userinfo."""
    text = (
        "wss://WEBSOCKETTOKEN@socket.example/stream "
        "ftp://user:FTPPASSWORD@files.example/model.bin "
        "tcp://TCPTOKEN@callback.example:4444"
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "WEBSOCKETTOKEN" not in redacted
    assert "user:FTPPASSWORD" not in redacted
    assert "TCPTOKEN" not in redacted
    assert redacted.count("<credentials-redacted>@") == 3


def test_redacts_python_container_secret_assignments() -> None:
    """Python dictionary and environment assignments should not bypass evidence redaction."""
    text = 'os.environ["AWS_SECRET_ACCESS_KEY"] = "ENVSECRET123" credentials = {"client_secret": "DICTSECRET456"}'

    redacted = redact_evidence_string(text, max_chars=500)

    assert "ENVSECRET123" not in redacted
    assert "DICTSECRET456" not in redacted
    assert 'os.environ["AWS_SECRET_ACCESS_KEY"] = "<redacted>"' in redacted
    assert '{"client_secret": "<redacted>"}' in redacted


def test_redacts_triple_quoted_and_escaped_quote_secret_assignments() -> None:
    """Quoted credential redaction must consume the complete Python literal."""
    text = r'''TOKEN = """TRIPLESECRET123""" os.environ["AWS_SECRET_ACCESS_KEY"] = "prefix\"TAILSECRET456"'''

    redacted = redact_evidence_string(text, max_chars=500)

    assert "TRIPLESECRET123" not in redacted
    assert "TAILSECRET456" not in redacted
    assert 'TOKEN = """<redacted>"""' in redacted
    assert 'os.environ["AWS_SECRET_ACCESS_KEY"] = "<redacted>"' in redacted


def test_unterminated_secret_assignment_drops_remaining_evidence() -> None:
    """Malformed quoted credentials should fail closed instead of leaking their tail."""
    text = 'prefix TOKEN = "UNTERMINATEDSECRET123\nreturn eval("1 + 1")'

    redacted = redact_evidence_string(text, max_chars=500)

    assert "UNTERMINATEDSECRET123" not in redacted
    assert redacted == 'prefix TOKEN = "<redacted>"'


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
