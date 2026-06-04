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


def test_redacts_prefixed_camel_case_r_assignments() -> None:
    """Camel-case R credential names should not preserve raw values."""
    redacted = redact_evidence_string(
        'dbPassword <- "DB_PASSWORD_SECRET"; sessionToken <<- "SESSION_TOKEN_SECRET"; '
        'githubToken <- "GITHUB_TOKEN_SECRET"; `dbPassword` <- "BACKTICK_CAMEL_SECRET"; '
        'pwd <- "PWD_SECRET"',
        max_chars=500,
    )

    for secret in (
        "DB_PASSWORD_SECRET",
        "SESSION_TOKEN_SECRET",
        "GITHUB_TOKEN_SECRET",
        "BACKTICK_CAMEL_SECRET",
        "PWD_SECRET",
    ):
        assert secret not in redacted
    assert f'dbPassword <- "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'sessionToken <<- "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'githubToken <- "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'`dbPassword` <- "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'pwd <- "{REDACTED_EVIDENCE_VALUE}"' in redacted


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
