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


def test_redacts_entire_url_query_while_preserving_path_context() -> None:
    """Unknown query keys can carry secrets, so stored evidence should omit the whole query."""
    text = "url=https://example.com/callback?client_secret=CLIENTSECRET123&refresh_token=REFRESHTOKEN456&ok=1"

    redacted = redact_evidence_string(text, max_chars=500)

    assert "CLIENTSECRET123" not in redacted
    assert "REFRESHTOKEN456" not in redacted
    assert "ok=1" not in redacted
    assert redacted == "url=https://example.com/callback"


def test_redacts_signed_url_queries_and_capability_path_tokens() -> None:
    """Stored evidence should use the bounded network URL path policy."""
    path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"
    text = f"https://storage.googleapis.com/model-bucket/{path_token}/weights.bin?X-Goog-Signature=QUERYSECRET"

    redacted = redact_evidence_string(text, max_chars=500)

    assert path_token not in redacted
    assert "QUERYSECRET" not in redacted
    assert "model-bucket/<redacted>/weights.bin" in redacted
    assert "X-Goog-Signature" not in redacted


def test_redacts_token_only_userinfo_across_network_url_schemes() -> None:
    """Network URL previews should not preserve token-only userinfo."""
    text = (
        "wss://WEBSOCKETTOKEN@socket.example/stream "
        "ftps://user:FTPPASSWORD@files.example/model.bin "
        "ssh://SSHTOKEN@host.example/repository "
        "telnet://TELNETTOKEN@console.example/session "
        "tcp://TCPTOKEN@callback.example:4444"
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "WEBSOCKETTOKEN" not in redacted
    assert "user:FTPPASSWORD" not in redacted
    assert "SSHTOKEN" not in redacted
    assert "TELNETTOKEN" not in redacted
    assert "TCPTOKEN" not in redacted
    assert redacted == (
        "wss://socket.example/stream "
        "ftps://files.example/model.bin "
        "ssh://host.example/repository "
        "telnet://console.example/session "
        "tcp://callback.example:4444"
    )


def test_redacts_legacy_s3_signed_url_access_key_id() -> None:
    """Legacy S3 query authentication must not serialize access key IDs."""
    access_key_id = "AKIAIOSFODNN7EXAMPLE"
    signature = "LEGACYSIGNATURESECRET"
    text = (
        "https://bucket.s3.amazonaws.com/model.bin"
        f"?AWSAccessKeyId={access_key_id}&Signature={signature}&Expires=9999999999"
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert access_key_id not in redacted
    assert signature not in redacted
    assert redacted == "https://bucket.s3.amazonaws.com/model.bin"


def test_preserves_absolute_file_url_paths_without_credentials() -> None:
    """Absolute file URL evidence should retain paths but drop untrusted URL data."""
    text = (
        "local=file:///tmp/model/payload.py?token=LOCALSECRET#fragment "
        "remote=file://user:FILEPASSWORD@fileserver/share/model.bin?signature=REMOTESECRET"
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "LOCALSECRET" not in redacted
    assert "FILEPASSWORD" not in redacted
    assert "REMOTESECRET" not in redacted
    assert redacted == ("local=file:///tmp/model/payload.py remote=file://fileserver/share/model.bin")


def test_redacts_python_container_secret_assignments() -> None:
    """Python dictionary and environment assignments should not bypass evidence redaction."""
    text = 'os.environ["AWS_SECRET_ACCESS_KEY"] = "ENVSECRET123" credentials = {"client_secret": "DICTSECRET456"}'

    redacted = redact_evidence_string(text, max_chars=500)

    assert "ENVSECRET123" not in redacted
    assert "DICTSECRET456" not in redacted
    assert 'os.environ["AWS_SECRET_ACCESS_KEY"] = "<redacted>"' in redacted
    assert '{"client_secret": "<redacted>"}' in redacted


def test_redacts_expression_and_authorization_assignments_without_losing_code_context() -> None:
    """Sensitive expression values and authorization fields should fail closed."""
    text = (
        "def payload():\n"
        '    client_secret = os.getenv("CLIENT_SECRET", "FALLBACKSECRET123")\n'
        '    headers["Authorization"] = "AUTHORIZATIONSECRET456"\n'
        '    Authorization = f"Bearer {runtime_token}"\n'
        '    return eval("1 + 1")'
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "FALLBACKSECRET123" not in redacted
    assert "AUTHORIZATIONSECRET456" not in redacted
    assert "runtime_token" not in redacted
    assert "client_secret = <redacted>" in redacted
    assert 'headers["Authorization"] = "<redacted>"' in redacted
    assert "Authorization = <redacted>" in redacted
    assert 'return eval("1 + 1")' in redacted


def test_redacts_multiline_sensitive_expression_assignment() -> None:
    """Fallback literals in multiline calls must not survive evidence serialization."""
    text = (
        'client_secret = os.getenv(\n    "CLIENT_SECRET",\n    "MULTILINEFALLBACKSECRET123",\n)\nreturn eval("1 + 1")'
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "MULTILINEFALLBACKSECRET123" not in redacted
    assert redacted.startswith("client_secret = <redacted>\n")
    assert 'return eval("1 + 1")' in redacted


def test_unparseable_expression_assignment_redacts_complete_rhs() -> None:
    """Binary framing must not let concatenated secret literals survive fallback redaction."""
    secret = "SECRETTAIL1234567890"
    text = f'\x00 client_secret = "prefix" + "{secret}"; eval("1 + 1")'

    redacted = redact_evidence_string(text, max_chars=500)

    assert secret not in redacted
    assert "client_secret = <redacted>" in redacted
    assert 'eval("1 + 1")' in redacted


def test_expression_redaction_preserves_annotations_and_argument_boundaries() -> None:
    """Redaction should preserve enough syntax to explain the surrounding finding."""
    text = (
        "def payload():\n"
        '    client_secret: str = os.getenv("CLIENT_SECRET", "ANNOTATEDSECRET123")\n'
        '    api_key: str = "ANNOTATEDLITERALSECRET456"\n'
        '    send(token=build_token("KEYWORDSECRET456"), safe="visible")\n'
        "    authorization_level = compute_level()\n"
        '    return eval("1 + 1")'
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "ANNOTATEDSECRET123" not in redacted
    assert "ANNOTATEDLITERALSECRET456" not in redacted
    assert "KEYWORDSECRET456" not in redacted
    assert "client_secret: str = <redacted>" in redacted
    assert "api_key: str = <redacted>" in redacted
    assert 'send(token=<redacted>, safe="visible")' in redacted
    assert "authorization_level = compute_level()" in redacted
    assert 'return eval("1 + 1")' in redacted


def test_unparseable_continued_sensitive_assignment_redacts_complete_rhs() -> None:
    """Explicit continuations must keep the next-line secret inside the fallback span."""
    secret = "CONTINUEDSECRET1234567890"
    text = f'\x00 client_secret = \\\n    "{secret}"\neval("1 + 1")'

    redacted = redact_evidence_string(text, max_chars=500)

    assert secret not in redacted
    assert "client_secret = <redacted>" in redacted
    assert 'eval("1 + 1")' in redacted


def test_unparseable_annotated_sensitive_assignment_redacts_literal() -> None:
    """Binary framing must not bypass annotated literal assignment redaction."""
    secret = "FRAMEDANNOTATEDSECRET1234567890"
    text = f'\x00 api_key: str = "{secret}"'

    redacted = redact_evidence_string(text, max_chars=500)

    assert secret not in redacted
    assert "api_key: str = <redacted>" in redacted


def test_redacts_compound_sensitive_assignments() -> None:
    """Augmented assignments must not serialize literal credential fragments."""
    text = (
        "def payload():\n"
        '    token += "COMPOUNDTOKENSECRET123"\n'
        '    headers["Authorization"] += "Bearer COMPOUNDAUTHSECRET456"\n'
        "    authorization_level += 1\n"
        '    tokenizer += "visible"'
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "COMPOUNDTOKENSECRET123" not in redacted
    assert "COMPOUNDAUTHSECRET456" not in redacted
    assert "token += <redacted>" in redacted
    assert 'headers["Authorization"] += <redacted>' in redacted
    assert "authorization_level += 1" in redacted
    assert 'tokenizer += "visible"' in redacted


def test_unparseable_compound_sensitive_assignment_redacts_literal() -> None:
    """Malformed framing must not bypass augmented assignment redaction."""
    secret = "FRAMEDCOMPOUNDSECRET1234567890"
    text = f'\x00 token += "{secret}"; eval("1 + 1")'

    redacted = redact_evidence_string(text, max_chars=500)

    assert secret not in redacted
    assert "token += <redacted>" in redacted
    assert 'eval("1 + 1")' in redacted


def test_redaction_bounds_expression_analysis_to_output_lookahead() -> None:
    """Very large evidence strings should still redact secrets near the visible prefix."""
    secret = "BOUNDEDSECRET1234567890"
    text = f'client_secret = os.getenv("KEY", "{secret}")\n' + ("x" * 100_000)

    redacted = redact_evidence_string(text, max_chars=100)

    assert secret not in redacted
    assert redacted.startswith("client_secret = <redacted>\n")
    assert len(redacted) == 100


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
