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


def test_redacts_structured_secret_suffixes_pwd_and_token_auth() -> None:
    """Structured secret labels and token auth schemes should be sanitized."""
    text = "token_value=TOKENVALUE123 pwd=PASSWORD123 Authorization: Token AUTHTOKEN123"

    redacted = redact_evidence_string(text, max_chars=None)

    assert "TOKENVALUE123" not in redacted
    assert "PASSWORD123" not in redacted
    assert "AUTHTOKEN123" not in redacted
    assert f"token_value={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"pwd={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"Authorization: Token {REDACTED_EVIDENCE_VALUE}" in redacted


def test_redacts_multiline_secret_assignments() -> None:
    """Multiline quoted values should not leak after the first newline."""
    text = 'private_key = """-----BEGIN KEY-----\nMULTILINESECRET123\n-----END KEY-----"""\nos.system("id")'

    redacted = redact_evidence_string(text, max_chars=None)

    assert "MULTILINESECRET123" not in redacted
    assert f'private_key = """{REDACTED_EVIDENCE_VALUE}"""' in redacted
    assert "os.system" in redacted


def test_redacts_escaped_quote_secret_assignments() -> None:
    """Escaped delimiters should not terminate quoted secret redaction early."""
    text = 'api_key = "prefix\\"ESCAPEDSECRET123" os.system("id")'

    redacted = redact_evidence_string(text, max_chars=None)

    assert "ESCAPEDSECRET123" not in redacted
    assert f'api_key = "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert "os.system" in redacted


def test_redacts_unterminated_quoted_secret_assignments() -> None:
    """Truncated preview windows should fail closed on unterminated secret strings."""
    text = 'api_key = "TRUNCATEDSECRET123'

    redacted = redact_evidence_string(text, max_chars=None)

    assert "TRUNCATEDSECRET123" not in redacted
    assert f'api_key = "{REDACTED_EVIDENCE_VALUE}' in redacted


def test_redacts_subscripted_and_mapping_secret_assignments() -> None:
    """Python and JSON-style containers should redact sensitive keyed values."""
    text = (
        'os.environ["API_KEY"] = "ENVSECRET123" '
        'headers["Authorization"] = "HEADERSECRET456" '
        '{"client_secret": "MAPSECRET789", "public_url": "https://example.com/model.bin"}'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "ENVSECRET123" not in redacted
    assert "HEADERSECRET456" not in redacted
    assert "MAPSECRET789" not in redacted
    assert 'os.environ["API_KEY"] = "<redacted>"' in redacted
    assert 'headers["Authorization"] = "<redacted>"' in redacted
    assert '"client_secret": "<redacted>"' in redacted
    assert '"public_url": "https://example.com/model.bin"' in redacted


def test_redacts_url_path_capability_tokens() -> None:
    """Credential-shaped URL path segments should not survive evidence redaction."""
    github_token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    jwt_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"
    text = f"https://callback.example/{github_token}/model https://callback.example/api/{jwt_token}/done"

    redacted = redact_evidence_string(text, max_chars=None)

    assert github_token not in redacted
    assert jwt_token not in redacted
    assert "https://callback.example/<redacted>/model" in redacted
    assert "https://callback.example/api/<redacted>/done" in redacted


def test_redacts_compound_sensitive_query_parameters() -> None:
    """Compound query credential keys should be redacted in URL evidence."""
    text = "url=https://example.com/callback?client_secret=CLIENTSECRET123&refresh_token=REFRESHTOKEN456&ok=1"

    redacted = redact_evidence_string(text, max_chars=500)

    assert "CLIENTSECRET123" not in redacted
    assert "REFRESHTOKEN456" not in redacted
    assert "client_secret=<redacted>" in redacted
    assert "refresh_token=<redacted>" in redacted
    assert "ok=1" in redacted


def test_redacts_semicolon_and_nested_sensitive_query_parameters() -> None:
    """Alternative separators and nested encodings must not preserve credential values."""
    text = (
        "first=https://example.com/callback?ok=1;to%6ben=SEMICOLONSECRET123 "
        "second=https://example.com/callback?ok=token%253DNESTEDSECRET456 "
        "third=https://example.com/callback?ok=1&amp;token=HTMLSECRET789"
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "SEMICOLONSECRET123" not in redacted
    assert "NESTEDSECRET456" not in redacted
    assert "HTMLSECRET789" not in redacted
    assert redacted.count(REDACTED_EVIDENCE_VALUE) == 3


def test_redacts_bracketed_sensitive_query_parameters() -> None:
    """Array-style query keys should still be treated as sensitive keys."""
    text = "https://example.com/hook?api_key[]=ARRAYSECRET123&token[0]=INDEXSECRET456&ok=1"

    redacted = redact_evidence_string(text, max_chars=None)

    assert "ARRAYSECRET123" not in redacted
    assert "INDEXSECRET456" not in redacted
    assert "api_key%5B%5D=<redacted>" in redacted
    assert "token%5B0%5D=<redacted>" in redacted
    assert "ok=1" in redacted


def test_redacts_malformed_userinfo_url() -> None:
    """Malformed userinfo URLs should fail closed instead of returning raw evidence."""
    text = "download=https://user:LEAKY-PASS@[::1/path?token=QUERYSECRET"

    redacted = redact_evidence_string(text, max_chars=500)

    assert "user:LEAKY-PASS" not in redacted
    assert "QUERYSECRET" not in redacted
    assert "https://<credentials-redacted>@[::1/path" in redacted


def test_redacts_token_only_userinfo_across_network_url_schemes() -> None:
    """Network URL previews should not preserve token-only userinfo."""
    text = (
        "wss://WEBSOCKETTOKEN@socket.example/stream "
        "ftp://user:FTPPASSWORD@files.example/model.bin "
        "tcp://TCPTOKEN@callback.example:4444"
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "WEBSOCKETTOKEN" not in redacted
    assert "user:FTPPASSWORD" not in redacted
    assert "TCPTOKEN" not in redacted
    assert redacted.count("<credentials-redacted>@") == 3


def test_existing_token_assignment_redaction_still_applies() -> None:
    """Canonical token assignments should keep their existing redaction behavior."""
    redacted = redact_evidence_string("token=CANONICALTOKEN123", max_chars=500)

    assert "CANONICALTOKEN123" not in redacted
    assert redacted == f"token={REDACTED_EVIDENCE_VALUE}"
