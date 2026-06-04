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
    assert f"Authorization: {REDACTED_EVIDENCE_VALUE}" in redacted


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


def test_redacts_prefixed_string_literal_secret_assignments() -> None:
    """Python string prefixes should be treated as part of quoted secret values."""
    text = 'api_key = r"RAWSECRET123" headers["Authorization"] = b"BYTESECRET456" {"client_secret": f"MAPSECRET789"}'

    redacted = redact_evidence_string(text, max_chars=None)

    assert "RAWSECRET123" not in redacted
    assert "BYTESECRET456" not in redacted
    assert "MAPSECRET789" not in redacted
    assert f'api_key = r"{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'headers["Authorization"] = b"{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'"client_secret": f"{REDACTED_EVIDENCE_VALUE}"' in redacted


def test_redacts_bare_quoted_authorization_assignments() -> None:
    """Authorization assignments should redact arbitrary quoted auth schemes."""
    text = (
        'Authorization = "ApiKey AUTHSECRET123" '
        'authorization = r"Custom AUTHSECRET456" '
        "Authorization: ApiKey AUTHSECRET789"
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "AUTHSECRET123" not in redacted
    assert "AUTHSECRET456" not in redacted
    assert "AUTHSECRET789" not in redacted
    assert f'Authorization = "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'authorization = r"{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f"Authorization: {REDACTED_EVIDENCE_VALUE}" in redacted


def test_redacts_escaped_json_mapping_secret_values() -> None:
    """Escaped JSON/config mappings embedded in strings should be sanitized."""
    text = r'payload="{\"api_key\":\"ESCAPEDJSONSECRET123\", \"safe\":\"ok\"}"'

    redacted = redact_evidence_string(text, max_chars=None)

    assert "ESCAPEDJSONSECRET123" not in redacted
    assert r"\"api_key\":\"<redacted>\"" in redacted
    assert r"\"safe\":\"ok\"" in redacted


def test_redacts_camel_case_secret_assignments() -> None:
    """Common camelCase credential keys should not preserve raw values."""
    text = (
        'dbPassword = "DBSECRET123" '
        'sessionToken: "SESSIONSECRET456" '
        '{"clientSecret": "MAPSECRET789"} '
        'headers["githubToken"] = "GITHUBSECRET000"'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "DBSECRET123" not in redacted
    assert "SESSIONSECRET456" not in redacted
    assert "MAPSECRET789" not in redacted
    assert "GITHUBSECRET000" not in redacted
    assert f'dbPassword = "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'sessionToken: "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'"clientSecret": "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'headers["githubToken"] = "{REDACTED_EVIDENCE_VALUE}"' in redacted


def test_redacts_non_scalar_sensitive_mapping_values() -> None:
    """Array/object and block sensitive values should fail closed."""
    text = (
        '{"api_key": ["ARRAYSECRET123"], "clientSecret": {"nested": "OBJECTSECRET456"}, "safe": true}\n'
        "api_key: |\n"
        "  BLOCKSECRET789\n"
        "safe: ok"
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "ARRAYSECRET123" not in redacted
    assert "OBJECTSECRET456" not in redacted
    assert "BLOCKSECRET789" not in redacted
    assert f'"api_key": {REDACTED_EVIDENCE_VALUE}' in redacted
    assert f'"clientSecret": {REDACTED_EVIDENCE_VALUE}' in redacted
    assert f"api_key: |\n  {REDACTED_EVIDENCE_VALUE}" in redacted
    assert "safe: ok" in redacted


def test_redacts_parenthesized_quoted_secret_assignments() -> None:
    """Parenthesized quoted values should not bypass assignment redaction."""
    text = (
        'api_key = ("PARENSECRET123") '
        'headers["Authorization"] = (\n  "HEADERSECRET456"\n) '
        '{"clientSecret": ("MAPSECRET789")}'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "PARENSECRET123" not in redacted
    assert "HEADERSECRET456" not in redacted
    assert "MAPSECRET789" not in redacted
    assert f'api_key = ("{REDACTED_EVIDENCE_VALUE}")' in redacted
    assert f'headers["Authorization"] = (\n  "{REDACTED_EVIDENCE_VALUE}"\n)' in redacted
    assert f'"clientSecret": ("{REDACTED_EVIDENCE_VALUE}")' in redacted


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


def test_redacts_hostname_less_url_path_capability_tokens() -> None:
    """Path-token redaction should also apply when URL parsing finds no hostname."""
    github_token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    text = f"file:///tmp/{github_token}/model https:///api/{github_token}/done"

    redacted = redact_evidence_string(text, max_chars=None)

    assert github_token not in redacted
    assert "file:///tmp/<redacted>/model" in redacted
    assert "https:///api/<redacted>/done" in redacted


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
    assert redacted == (
        "https://bucket.s3.amazonaws.com/model.bin?AWSAccessKeyId=<redacted>&Signature=<redacted>&Expires=9999999999"
    )


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
    assert redacted == (
        "local=file:///tmp/model/payload.py?token=<redacted> "
        "remote=file://<credentials-redacted>@fileserver/share/model.bin?signature=<redacted>"
    )


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
    assert 'Authorization = f"<redacted>"' in redacted
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


def test_redacts_bytes_keyed_and_walrus_sensitive_assignments() -> None:
    """Bytes mapping keys and walrus values must not bypass token redaction."""
    text = (
        'os.environb[b"AWS_SECRET_ACCESS_KEY"] = b"BYTESECRET1234567890"\n'
        'headers[b"Authorization"] = "AUTHSECRET1234567890"\n'
        'if (token := "WALRUSSECRET1234567890"):\n'
        '    eval("1 + 1")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "BYTESECRET1234567890" not in redacted
    assert "AUTHSECRET1234567890" not in redacted
    assert "WALRUSSECRET1234567890" not in redacted
    assert 'os.environb[b"AWS_SECRET_ACCESS_KEY"] = <redacted>' in redacted
    assert 'headers[b"Authorization"] = <redacted>' in redacted
    assert "token := <redacted>" in redacted
    assert 'eval("1 + 1")' in redacted


def test_redacts_prefixed_camel_case_secret_assignments() -> None:
    """Provider-prefixed camelCase credential names should remain covered."""
    text = (
        'awsSecretAccessKey = "AWSSECRET1234567890"; '
        'azureClientSecret = "AZURESECRET1234567890"; '
        'awsSecretsManagerRegion = "us-east-1"'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "AWSSECRET1234567890" not in redacted
    assert "AZURESECRET1234567890" not in redacted
    assert 'awsSecretAccessKey = "<redacted>"' in redacted
    assert 'azureClientSecret = "<redacted>"' in redacted
    assert 'awsSecretsManagerRegion = "us-east-1"' in redacted


def test_redacts_unpacking_assignments_and_preserves_lambda_context() -> None:
    """Sensitive unpacking and lambda defaults should redact without hiding findings."""
    text = (
        'api_key, other = "UNPACKSECRET1234567890", "ok"\n'
        'safe, visible = "left", "right"\n'
        'payload = lambda api_key="LAMBDASECRET1234567890": eval("1 + 1")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "UNPACKSECRET1234567890" not in redacted
    assert "LAMBDASECRET1234567890" not in redacted
    assert "api_key, other = <redacted>" in redacted
    assert 'safe, visible = "left", "right"' in redacted
    assert 'lambda api_key="<redacted>": eval("1 + 1")' in redacted


def test_redacts_sensitive_setter_call_values() -> None:
    """Credential setter APIs should sanitize their value arguments."""
    text = (
        'os.putenv("AWS_SECRET_ACCESS_KEY", "PUTENVSECRET1234567890"); '
        'setattr(config, "api_key", build_secret("SETATTRSECRET1234567890")); '
        'headers.setdefault("Authorization", "DEFAULTSECRET1234567890"); '
        'logger.info("api_key", "VISIBLE"); '
        'setattr(config, "timeout", "30"); eval("1 + 1")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "PUTENVSECRET1234567890" not in redacted
    assert "SETATTRSECRET1234567890" not in redacted
    assert "DEFAULTSECRET1234567890" not in redacted
    assert 'os.putenv("AWS_SECRET_ACCESS_KEY", <redacted>)' in redacted
    assert 'setattr(config, "api_key", <redacted>)' in redacted
    assert 'headers.setdefault("Authorization", <redacted>)' in redacted
    assert 'logger.info("api_key", "VISIBLE")' in redacted
    assert 'setattr(config, "timeout", "30")' in redacted
    assert 'eval("1 + 1")' in redacted


def test_unparseable_sensitive_assignment_and_setter_variants_fail_closed() -> None:
    """Binary framing must not reopen token-only assignment and setter gaps."""
    text = (
        '\x00 os.putenv("AWS_SECRET_ACCESS_KEY", "FRAMEDSETTERSECRET1234567890"); '
        'os.environb[b"AWS_SECRET_ACCESS_KEY"] = b"FRAMEDBYTESECRET1234567890"; '
        'api_key, other = "FRAMEDUNPACKSECRET1234567890", "ok"; '
        'if (token := "FRAMEDWALRUSSECRET1234567890"): eval("1 + 1")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "FRAMEDSETTERSECRET1234567890" not in redacted
    assert "FRAMEDBYTESECRET1234567890" not in redacted
    assert "FRAMEDUNPACKSECRET1234567890" not in redacted
    assert "FRAMEDWALRUSSECRET1234567890" not in redacted
    assert 'os.putenv("AWS_SECRET_ACCESS_KEY", <redacted>)' in redacted
    assert 'os.environb[b"AWS_SECRET_ACCESS_KEY"] = <redacted>' in redacted
    assert "api_key, other = <redacted>" in redacted
    assert "token := <redacted>" in redacted
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


def test_redacts_nested_bracketed_and_json_sensitive_query_parameters() -> None:
    """Encoded nested query/config values should redact sensitive payloads."""
    text = (
        "first=https://example.com/hook?redirect=https%3A%2F%2Fcb%2F%3Fapi_key%5B%5D%3DNESTEDARRAYSECRET123 "
        "second=https://example.com/hook?payload=%7B%22api_key%22%3A%22JSONSECRET456%22%7D"
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "NESTEDARRAYSECRET123" not in redacted
    assert "JSONSECRET456" not in redacted
    assert "redirect=<redacted>" in redacted
    assert "payload=<redacted>" in redacted


def test_redacts_credentials_inside_nested_redirect_urls() -> None:
    """Encoded redirect/callback URLs should not preserve embedded credentials."""
    github_token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    text = (
        "first=https://example.com/hook?redirect=https%3A%2F%2Fuser%3Apass%40evil.example%2Fcb "
        f"second=https://example.com/hook?callback=https%3A%2F%2Fcb.example%2F{github_token}%2Fdone"
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "user%3Apass" not in redacted
    assert "user:pass" not in redacted
    assert github_token not in redacted
    assert "redirect=<redacted>" in redacted
    assert "callback=<redacted>" in redacted


def test_redacts_sensitive_query_values_with_raw_semicolons() -> None:
    """Semicolons inside sensitive values should not leak as synthetic query keys."""
    text = "https://example.com/hook?token=SEMICOLONSECRET123;STILLSECRET456&ok=1"

    redacted = redact_evidence_string(text, max_chars=None)

    assert "SEMICOLONSECRET123" not in redacted
    assert "STILLSECRET456" not in redacted
    assert "STILLSECRET456=" not in redacted
    assert "token=<redacted>" in redacted
    assert "ok=1" in redacted


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
        "tcp://TCPTOKEN@callback.example:4444 "
        "ftps://user:FTPSPASSWORD@files.example/model.bin "
        "ssh://SSHTOKEN@git.example/repo "
        "telnet://user:TELNETPASSWORD@legacy.example"
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "WEBSOCKETTOKEN" not in redacted
    assert "user:FTPPASSWORD" not in redacted
    assert "TCPTOKEN" not in redacted
    assert "user:FTPSPASSWORD" not in redacted
    assert "SSHTOKEN" not in redacted
    assert "user:TELNETPASSWORD" not in redacted
    assert redacted.count("<credentials-redacted>@") == 6


def test_existing_token_assignment_redaction_still_applies() -> None:
    """Canonical token assignments should keep their existing redaction behavior."""
    redacted = redact_evidence_string("token=CANONICALTOKEN123", max_chars=500)

    assert "CANONICALTOKEN123" not in redacted
    assert redacted == f"token={REDACTED_EVIDENCE_VALUE}"
