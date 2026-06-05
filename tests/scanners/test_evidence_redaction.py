"""Tests for scanner evidence redaction helpers."""

import json
from urllib.parse import quote

import pytest

from modelaudit.scanners._evidence_redaction import (
    REDACTED_EVIDENCE_VALUE,
    REDACTED_URL_CREDENTIALS,
    redact_evidence_string,
    redact_evidence_value,
)


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
    semicolon_secret = "SEMICOLON_QUERY_SECRET"
    redirect_secret = "REDIRECT_QUERY_SECRET"
    text = (
        "url=https://example.com/callback?client_secret=CLIENTSECRET123&refresh_token=REFRESHTOKEN456"
        f"&aws_access_key_id=AWSACCESSKEY789&ok=1;token={semicolon_secret}"
        f"&redirect=https://user:{redirect_secret}@evil.test/model"
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "CLIENTSECRET123" not in redacted
    assert "REFRESHTOKEN456" not in redacted
    assert "AWSACCESSKEY789" not in redacted
    assert semicolon_secret not in redacted
    assert redirect_secret not in redacted
    assert "client_secret=<redacted>" in redacted
    assert "refresh_token=<redacted>" in redacted
    assert "aws_access_key_id=<redacted>" in redacted
    assert "token=<redacted>" in redacted
    assert REDACTED_URL_CREDENTIALS in redacted
    assert "ok=1" in redacted


def test_caps_recursive_url_query_redaction() -> None:
    """Nested URL query values should not recurse without bound."""
    recursive_secret = "RECURSIVE_QUERY_SECRET"
    nested_url = f"https://evil.test/?token={recursive_secret}"
    for _ in range(20):
        nested_url = f"https://example.test/?r={quote(nested_url, safe='')}"

    redacted = redact_evidence_string(nested_url, max_chars=2000)

    assert recursive_secret not in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted


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


def test_redacts_userinfo_for_generic_url_schemes() -> None:
    """Credential-bearing URLs should redact userinfo across schemes."""
    ssh_secret = "SSH_URL_SECRET"
    postgres_secret = "POSTGRES_URL_SECRET"

    redacted = redact_evidence_string(
        f"ssh://user:{ssh_secret}@example.test/path postgres://user:{postgres_secret}@example.test/db",
        max_chars=500,
    )

    assert ssh_secret not in redacted
    assert postgres_secret not in redacted
    assert "ssh://<credentials-redacted>@example.test/path" in redacted
    assert "postgres://<credentials-redacted>@example.test/db" in redacted


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


def test_redacts_r_equals_assignments_for_quoted_identifiers_and_raw_values() -> None:
    """R equals assignments should use the same fail-closed evidence handling."""
    redacted = redact_evidence_string(
        '`access token` = "BACKTICK_EQUALS_SECRET"; token = r"(RAW_EQUALS_SECRET)"',
        max_chars=500,
    )

    assert "BACKTICK_EQUALS_SECRET" not in redacted
    assert "RAW_EQUALS_SECRET" not in redacted
    assert f'`access token` = "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f"token = {REDACTED_EVIDENCE_VALUE}" in redacted


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


def test_redacts_r_indexed_member_and_slot_assignment_targets() -> None:
    """R selectors targeting credential fields should not leak assigned values."""
    redacted = redact_evidence_string(
        'token[1] <- "INDEXED_SECRET"; config$token <- "MEMBER_SECRET"; '
        'config@password <- "SLOT_SECRET"; config[["api_key"]] <- "SUBSCRIPT_SECRET"; '
        '"RIGHT_MEMBER_SECRET" -> config$token',
        max_chars=700,
    )

    for secret in (
        "INDEXED_SECRET",
        "MEMBER_SECRET",
        "SLOT_SECRET",
        "SUBSCRIPT_SECRET",
        "RIGHT_MEMBER_SECRET",
    ):
        assert secret not in redacted
    assert f'token[1] <- "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'config$token <- "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'config@password <- "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'config[["api_key"]] <- "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'"{REDACTED_EVIDENCE_VALUE}" -> config$token' in redacted


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


def test_redacts_full_leftward_assignment_expressions() -> None:
    """Leftward R assignments should redact complete call-valued expressions."""
    redacted = redact_evidence_string(
        'base::system("curl"); token <- paste0("LEFT_SECRET", "TAIL"); safe <- visible',
        max_chars=500,
    )

    assert 'base::system("curl")' in redacted
    assert "LEFT_SECRET" not in redacted
    assert "TAIL" not in redacted
    assert f"token <- {REDACTED_EVIDENCE_VALUE}" in redacted
    assert "safe <- visible" in redacted


def test_redacts_simple_call_valued_rightward_assignment() -> None:
    """Generic call-shaped values must be redacted before structured parsing."""
    redacted = redact_evidence_string(
        'paste0("RIGHT_SECRET", "TAIL") -> token',
        max_chars=500,
    )

    assert redacted == f"{REDACTED_EVIDENCE_VALUE} -> token"


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


def test_redacts_plural_and_value_suffixed_credential_keys() -> None:
    """Plural and value-suffixed credential keys should redact child values."""
    credential_secret = "PLURAL_CREDENTIAL_SECRET"
    value_secret = "API_KEY_VALUE_SECRET"

    redacted_text = redact_evidence_string(
        f"credentials={credential_secret} api_key_value={value_secret}",
        max_chars=500,
    )
    redacted_value = redact_evidence_value(
        {
            "credentials": credential_secret,
            "api_key_value": value_secret,
            "nested": {"accessTokenValue": value_secret},
        },
        max_string_chars=500,
    )

    serialized_value = json.dumps(redacted_value)
    assert credential_secret not in redacted_text
    assert value_secret not in redacted_text
    assert credential_secret not in serialized_value
    assert value_secret not in serialized_value
    assert redacted_value == {
        "credentials": REDACTED_EVIDENCE_VALUE,
        "api_key_value": REDACTED_EVIDENCE_VALUE,
        "nested": {"accessTokenValue": REDACTED_EVIDENCE_VALUE},
    }


def test_redacts_indexed_credential_keys() -> None:
    """Indexed credential names should preserve the sensitive base key context."""
    api_secret = "INDEXED_API_KEY_SECRET"
    token_secret = "INDEXED_TOKEN_SECRET"
    query_secret = "INDEXED_QUERY_SECRET"

    redacted_text = redact_evidence_string(
        f"api_key[0]={api_secret} https://example.test/model.keras?token[0]={query_secret}&ok=1",
        max_chars=500,
    )
    redacted_value = redact_evidence_value(
        {
            "api_key[0]": api_secret,
            "token[0]": token_secret,
        },
        max_string_chars=500,
    )

    serialized_value = json.dumps(redacted_value)
    assert api_secret not in redacted_text
    assert query_secret not in redacted_text
    assert api_secret not in serialized_value
    assert token_secret not in serialized_value
    assert f"api_key[0]={REDACTED_EVIDENCE_VALUE}" in redacted_text
    assert REDACTED_EVIDENCE_VALUE in redacted_text
    assert "ok=1" in redacted_text
    assert redacted_value == {
        "api_key[0]": REDACTED_EVIDENCE_VALUE,
        "token[0]": REDACTED_EVIDENCE_VALUE,
    }


def test_redacts_dotted_credential_keys() -> None:
    """Dotted credential names should be canonicalized before redaction."""
    secret_key_secret = "DOTTED_SECRET_KEY_SECRET"
    api_key_secret = "DOTTED_API_KEY_SECRET"
    quoted_secret = "DOTTED_QUOTED_SECRET"

    redacted = redact_evidence_string(
        f'secret.key={secret_key_secret} api.key={api_key_secret} "secret.key":"{quoted_secret}"',
        max_chars=500,
    )
    redacted_value = redact_evidence_value({"secret.key": secret_key_secret}, max_string_chars=500)

    serialized_value = json.dumps(redacted_value)
    assert secret_key_secret not in redacted
    assert api_key_secret not in redacted
    assert quoted_secret not in redacted
    assert secret_key_secret not in serialized_value
    assert f"secret.key={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"api.key={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f'"secret.key":"{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert redacted_value == {"secret.key": REDACTED_EVIDENCE_VALUE}


def test_redacts_whitespace_separated_credential_flags() -> None:
    """CLI-style credential flags should redact the following value token."""
    api_secret = "CLI_API_KEY_SECRET"
    token_secret = "CLI_TOKEN_SECRET"
    password_secret = "CLI_PASSWORD_SECRET"

    redacted = redact_evidence_string(
        f"--api-key {api_secret} --token '{token_secret}' --config --password {password_secret} --safe visible",
        max_chars=500,
    )

    assert api_secret not in redacted
    assert token_secret not in redacted
    assert password_secret not in redacted
    assert f"--api-key {REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"--token '{REDACTED_EVIDENCE_VALUE}'" in redacted
    assert f"--password {REDACTED_EVIDENCE_VALUE}" in redacted
    assert "--safe visible" in redacted


def test_redacts_leading_underscore_credential_assignments() -> None:
    """Assignment-style credential keys may start with underscores."""
    token_secret = "LEADING_UNDERSCORE_TOKEN_SECRET"
    api_secret = "LEADING_UNDERSCORE_API_SECRET"

    redacted = redact_evidence_string(
        f"_token={token_secret} _api_key='{api_secret}'",
        max_chars=500,
    )

    assert token_secret not in redacted
    assert api_secret not in redacted
    assert f"_token={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"_api_key='{REDACTED_EVIDENCE_VALUE}'" in redacted


def test_redacts_call_style_sensitive_assignment_values() -> None:
    """Sensitive assignment values should consume calls and prefixed literals."""
    call_secret = "CALL_STYLE_SECRET"
    f_string_secret = "PREFIXED_LITERAL_SECRET"
    unbalanced_secret = "UNBALANCED_CALL_SECRET"

    redacted = redact_evidence_string(
        (
            f'api_key=SecretStr("{call_secret}") '
            f'api_key=f"{f_string_secret}" '
            f'api_key=SecretStr("{unbalanced_secret}" safe=value'
        ),
        max_chars=500,
    )

    assert call_secret not in redacted
    assert f_string_secret not in redacted
    assert unbalanced_secret not in redacted
    assert f"api_key={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f'api_key=f"{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert "safe=value" not in redacted


def test_redacts_access_key_id_assignments_and_nested_values() -> None:
    """AWS-style access key IDs should not survive string or structured redaction."""
    secret = "AWSACCESSKEY123"
    text = f"aws_access_key_id='{secret}' access-key-id={secret}"

    redacted_text = redact_evidence_string(text, max_chars=500)
    redacted_value = redact_evidence_value({"aws_access_key_id": secret, "nested": {"access-key-id": secret}})

    assert secret not in redacted_text
    assert secret not in str(redacted_value)
    assert redacted_value == {
        "aws_access_key_id": REDACTED_EVIDENCE_VALUE,
        "nested": {"access-key-id": REDACTED_EVIDENCE_VALUE},
    }


def test_redacts_authorization_values_by_structured_key() -> None:
    """Header-like detail keys should redact opaque values without needing a prefix in the value."""
    secret = "ZIP_AUTHORIZATION_SECRET"

    redacted_value = redact_evidence_value(
        {
            "Authorization": f"Basic {secret}",
            "headers": {"proxy-authorization": f"Bearer {secret}"},
        }
    )

    serialized_value = json.dumps(redacted_value)
    assert secret not in serialized_value
    assert redacted_value == {
        "Authorization": REDACTED_EVIDENCE_VALUE,
        "headers": {"proxy-authorization": REDACTED_EVIDENCE_VALUE},
    }


def test_redacts_camel_case_authorization_key_aliases() -> None:
    """Authorization suffix aliases should redact string and structured values."""
    secret = "CAMEL_AUTHORIZATION_SECRET"

    redacted_text = redact_evidence_string(
        f"proxyAuthorization={secret} authorizationValue='{secret}' proxyAuthorizationHeader='{secret}'",
        max_chars=500,
    )
    redacted_value = redact_evidence_value(
        {
            "proxyAuthorization": secret,
            "authorizationValue": secret,
            "proxyAuthorizationHeader": secret,
        },
        max_string_chars=500,
    )

    assert secret not in redacted_text
    assert secret not in json.dumps(redacted_value)
    assert f"proxyAuthorization={REDACTED_EVIDENCE_VALUE}" in redacted_text
    assert f"authorizationValue='{REDACTED_EVIDENCE_VALUE}'" in redacted_text
    assert f"proxyAuthorizationHeader='{REDACTED_EVIDENCE_VALUE}'" in redacted_text
    assert redacted_value == {
        "proxyAuthorization": REDACTED_EVIDENCE_VALUE,
        "authorizationValue": REDACTED_EVIDENCE_VALUE,
        "proxyAuthorizationHeader": REDACTED_EVIDENCE_VALUE,
    }


def test_redacts_authorization_aliases_in_specialized_string_contexts() -> None:
    """Malformed, subscripted, and R assignments should share authorization alias coverage."""
    subscript_secret = "SUBSCRIPT_AUTHORIZATION_SECRET"
    r_left_secret = "R_LEFT_AUTHORIZATION_SECRET"
    r_right_secret = "R_RIGHT_AUTHORIZATION_SECRET"
    unterminated_secret = "UNTERMINATED_AUTHORIZATION_SECRET"
    text = (
        f'headers["proxyAuthorization"] = "{subscript_secret}" '
        f'headers$proxyAuthorization <- "{r_left_secret}" '
        f'"{r_right_secret}" -> headers$proxyAuthorization '
        f"proxyAuthorization='{unterminated_secret}"
    )

    redacted = redact_evidence_string(text, max_chars=None)

    for secret in (subscript_secret, r_left_secret, r_right_secret, unterminated_secret):
        assert secret not in redacted
    assert 'headers["proxyAuthorization"] = "<redacted>"' in redacted
    assert 'headers$proxyAuthorization <- "<redacted>"' in redacted
    assert '"<redacted>" -> headers$proxyAuthorization' in redacted
    assert "proxyAuthorization='<redacted>" in redacted


def test_preserves_non_secret_authorization_metadata_keys() -> None:
    """Authorization-related status and method metadata should not be over-redacted."""
    text = (
        "authorizationStatus='allowed' proxyAuthorizationEnabled=true "
        "authorizationMethod='oauth' authorizationHeaderName='Authorization'"
    )
    structured = {
        "authorizationStatus": "allowed",
        "proxyAuthorizationEnabled": True,
        "authorizationMethod": "oauth",
        "authorizationHeaderName": "Authorization",
    }

    assert redact_evidence_string(text, max_chars=None) == text
    assert redact_evidence_value(structured) == structured


def test_redacts_secret_bearing_structured_keys() -> None:
    """Secret-bearing dict keys should be redacted as evidence too."""
    token_key_secret = "ZIP_TOKEN_KEY_SECRET"
    url_key_secret = "ZIP_URL_KEY_SECRET"

    redacted_value = redact_evidence_value(
        {
            f"token={token_key_secret}": "kept",
            f"https://user:{url_key_secret}@example.test/model.keras?api_key={token_key_secret}": {
                "safe": "value",
            },
        },
        max_string_chars=500,
    )

    serialized_value = json.dumps(redacted_value)
    assert token_key_secret not in serialized_value
    assert url_key_secret not in serialized_value
    assert f"token={REDACTED_EVIDENCE_VALUE}" in redacted_value
    assert f"https://{REDACTED_URL_CREDENTIALS}@example.test/model.keras?api_key={REDACTED_EVIDENCE_VALUE}" in (
        redacted_value
    )


def test_redacts_camel_case_structured_credential_keys() -> None:
    """SDK-style camelCase credential keys should redact values by key context."""
    aws_secret = "AWS_SECRET_ACCESS_KEY_VALUE"
    session_secret = "AWS_SESSION_TOKEN_VALUE"
    amz_secret = "X_AMZ_SECURITY_TOKEN_VALUE"
    private_key_secret = "SERVICE_PRIVATE_KEY_VALUE"

    redacted_value = redact_evidence_value(
        {
            "awsSecretAccessKey": aws_secret,
            "awsSessionToken": session_secret,
            "xAmzSecurityToken": amz_secret,
            "servicePrivateKey": private_key_secret,
        }
    )

    serialized_value = json.dumps(redacted_value)
    assert aws_secret not in serialized_value
    assert session_secret not in serialized_value
    assert amz_secret not in serialized_value
    assert private_key_secret not in serialized_value
    assert redacted_value == {
        "awsSecretAccessKey": REDACTED_EVIDENCE_VALUE,
        "awsSessionToken": REDACTED_EVIDENCE_VALUE,
        "xAmzSecurityToken": REDACTED_EVIDENCE_VALUE,
        "servicePrivateKey": REDACTED_EVIDENCE_VALUE,
    }


def test_redacts_camel_case_assignments_and_url_query_keys() -> None:
    """CamelCase credential aliases should redact in assignment text and URL queries."""
    assignment_secret = "CAMEL_ASSIGNMENT_SECRET"
    quoted_secret = "CAMEL_QUOTED_SECRET"
    escaped_quoted_secret = "CAMEL_ESCAPED_QUOTED_SECRET"
    query_secret = "CAMEL_QUERY_SECRET"

    redacted_text = redact_evidence_string(
        (
            f"awsSecretAccessKey={assignment_secret} "
            f"clientSecret='{quoted_secret}' "
            f"awsSecretAccessKey='abc\\'{escaped_quoted_secret}' "
            f"https://example.test/model.keras?xAmzSecurityToken={query_secret}&ok=1"
        ),
        max_chars=500,
    )

    assert assignment_secret not in redacted_text
    assert quoted_secret not in redacted_text
    assert escaped_quoted_secret not in redacted_text
    assert query_secret not in redacted_text
    assert f"awsSecretAccessKey={REDACTED_EVIDENCE_VALUE}" in redacted_text
    assert f"clientSecret='{REDACTED_EVIDENCE_VALUE}'" in redacted_text
    assert f"awsSecretAccessKey='{REDACTED_EVIDENCE_VALUE}'" in redacted_text
    assert f"xAmzSecurityToken={REDACTED_EVIDENCE_VALUE}" in redacted_text
    assert "ok=1" in redacted_text


def test_redacts_quoted_json_style_credential_strings() -> None:
    """Serialized JSON/dict strings should redact quoted credential key values."""
    json_secret = "JSON_STYLE_SECRET"
    camel_json_secret = "JSON_STYLE_CAMEL_SECRET"
    escaped_json_secret = "JSON_STYLE_ESCAPED_SECRET"

    redacted_text = redact_evidence_string(
        (
            f'{{"api_key":"{json_secret}","clientSecret":"{camel_json_secret}",'
            f'"secret":"abc\\"{escaped_json_secret}","safe":"ok"}}'
        ),
        max_chars=500,
    )

    assert json_secret not in redacted_text
    assert camel_json_secret not in redacted_text
    assert escaped_json_secret not in redacted_text
    assert f'"api_key":"{REDACTED_EVIDENCE_VALUE}"' in redacted_text
    assert f'"clientSecret":"{REDACTED_EVIDENCE_VALUE}"' in redacted_text
    assert f'"secret":"{REDACTED_EVIDENCE_VALUE}"' in redacted_text
    assert '"safe":"ok"' in redacted_text


def test_redacts_json_string_container_credential_values() -> None:
    """Serialized JSON strings should redact sensitive container values."""
    array_secret = "JSON_ARRAY_SECRET"
    object_secret = "JSON_OBJECT_SECRET"

    redacted_text = redact_evidence_string(
        f'{{"api_key":["{array_secret}"],"token":{{"nested":"{object_secret}"}},"safe":["ok"]}}',
        max_chars=500,
    )

    assert array_secret not in redacted_text
    assert object_secret not in redacted_text
    assert f'"api_key":"{REDACTED_EVIDENCE_VALUE}"' in redacted_text
    assert f'"token":"{REDACTED_EVIDENCE_VALUE}"' in redacted_text
    assert '"safe":["ok"]' in redacted_text


def test_redacts_pair_shaped_credential_lists_and_bounds_value_recursion() -> None:
    """Parsed list/tuple evidence should redact key/value pairs and bound recursion."""
    pair_secret = "PAIR_LIST_SECRET"
    nested_pair_secret = "NESTED_PAIR_LIST_SECRET"
    name_value_secret = "NAME_VALUE_PAIR_SECRET"
    deep_secret = "DEEP_VALUE_SECRET"

    redacted_pairs = redact_evidence_value(
        [
            ["api_key", pair_secret],
            {"params": [("token", nested_pair_secret)]},
            {"name": "API_KEY", "value": name_value_secret},
            {"Name": "API_KEY", "Value": name_value_secret},
        ],
        max_string_chars=500,
    )
    deep_value: object = deep_secret
    for _ in range(150):
        deep_value = [deep_value]
    redacted_deep = redact_evidence_value(deep_value, max_string_chars=500)

    serialized_pairs = json.dumps(redacted_pairs, default=str)
    assert pair_secret not in serialized_pairs
    assert nested_pair_secret not in serialized_pairs
    assert name_value_secret not in serialized_pairs
    assert ["api_key", REDACTED_EVIDENCE_VALUE] in redacted_pairs
    assert {"name": "API_KEY", "value": REDACTED_EVIDENCE_VALUE} in redacted_pairs
    assert {"Name": "API_KEY", "Value": REDACTED_EVIDENCE_VALUE} in redacted_pairs
    assert deep_secret not in str(redacted_deep)
    assert REDACTED_EVIDENCE_VALUE in str(redacted_deep)


def test_redacts_sensitive_container_assignments() -> None:
    """Credential assignments should consume array and object values before redaction."""
    array_secret = "CONTAINER_ASSIGNMENT_ARRAY_SECRET"
    object_secret = "CONTAINER_ASSIGNMENT_OBJECT_SECRET"
    nested_secret = "CONTAINER_ASSIGNMENT_NESTED_SECRET"
    outer_secret = "CONTAINER_ASSIGNMENT_OUTER_SECRET"
    parenthesized_secret = "CONTAINER_ASSIGNMENT_PAREN_SECRET"

    redacted_text = redact_evidence_string(
        (
            f'awsSecretAccessKey=["{array_secret}"] '
            f'token={{"nested":"{object_secret}"}} '
            f'api_key=[[],"{nested_secret}"] '
            f'metadata={{"api_key":["{outer_secret}"]}} '
            f'awsSecretAccessKey=("{parenthesized_secret}") '
            'safe=["visible"]'
        ),
        max_chars=500,
    )

    assert array_secret not in redacted_text
    assert object_secret not in redacted_text
    assert nested_secret not in redacted_text
    assert outer_secret not in redacted_text
    assert parenthesized_secret not in redacted_text
    assert f"awsSecretAccessKey={REDACTED_EVIDENCE_VALUE}" in redacted_text
    assert f"token={REDACTED_EVIDENCE_VALUE}" in redacted_text
    assert f"api_key={REDACTED_EVIDENCE_VALUE}" in redacted_text
    assert f'"api_key":"{REDACTED_EVIDENCE_VALUE}"' in redacted_text
    assert 'safe=["visible"]' in redacted_text


def test_redacts_embedded_structured_credential_literals() -> None:
    """Structured credential containers should redact even when embedded in prose."""
    json_secret = "EMBEDDED_JSON_SECRET"
    repr_secret = "EMBEDDED_REPR_SECRET"
    escaped_secret = "ESCAPED_JSON_LITERAL_SECRET"
    tuple_secret = "EMBEDDED_TUPLE_SECRET"
    invalid_secret = "EMBEDDED_INVALID_CONTAINER_SECRET"

    redacted_text = redact_evidence_string(
        (
            f"note {{\"api_key\":[\"{json_secret}\"]}} and repr {{'token':['{repr_secret}']}} "
            f"tuple ('api_key','{tuple_secret}') invalid {{\"api_key\":[{invalid_secret}]}}"
        ),
        max_chars=500,
    )
    redacted_escaped = redact_evidence_string(json.dumps(f'{{"api_key":["{escaped_secret}"]}}'), max_chars=500)

    assert json_secret not in redacted_text
    assert repr_secret not in redacted_text
    assert tuple_secret not in redacted_text
    assert invalid_secret not in redacted_text
    assert escaped_secret not in redacted_escaped
    assert f'"api_key":"{REDACTED_EVIDENCE_VALUE}"' in redacted_text
    assert f'"token":"{REDACTED_EVIDENCE_VALUE}"' in redacted_text
    assert f'["api_key","{REDACTED_EVIDENCE_VALUE}"]' in redacted_text
    assert f'"api_key":"{REDACTED_EVIDENCE_VALUE}"' in redacted_escaped


def test_redacts_quoted_non_letter_sensitive_key_fragments() -> None:
    """Quoted credential fragments should allow digit or underscore key starts."""
    two_factor_secret = "TWO_FACTOR_TOKEN_SECRET"
    underscore_secret = "UNDERSCORE_TOKEN_SECRET"

    redacted = redact_evidence_string(
        f'fragments "2fa_token":"{two_factor_secret}" and "_token":"{underscore_secret}"',
        max_chars=500,
    )

    assert two_factor_secret not in redacted
    assert underscore_secret not in redacted
    assert f'"2fa_token":"{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'"_token":"{REDACTED_EVIDENCE_VALUE}"' in redacted


def test_fails_closed_for_container_heavy_malformed_evidence() -> None:
    """Malformed container-heavy strings should avoid quadratic redaction scans."""
    redacted = redact_evidence_string("note " + "(" * 20000, max_chars=500)

    assert redacted == REDACTED_EVIDENCE_VALUE


def test_redacts_repr_style_container_credential_values() -> None:
    """Python repr-style container strings should redact sensitive nested values."""
    array_secret = "REPR_ARRAY_SECRET"
    object_secret = "REPR_OBJECT_SECRET"
    tuple_key_secret = "REPR_TUPLE_KEY_SECRET"
    set_secret = "REPR_SET_SECRET"
    bytes_secret = "REPR_BYTES_SECRET"
    tuple_string_secret = "REPR_TUPLE_STRING_SECRET"

    redacted_text = redact_evidence_string(
        (
            f"{{'api_key':['{array_secret}'],'token':{{'nested':'{object_secret}'}},"
            f"('api_key','{tuple_key_secret}'):'x','metadata':{{'token={set_secret}'}},"
            f"'bytes':b'token={bytes_secret}','safe':['ok']}}"
        ),
        max_chars=500,
    )
    redacted_tuple_text = redact_evidence_string(f"('api_key','{tuple_string_secret}')", max_chars=500)

    assert array_secret not in redacted_text
    assert object_secret not in redacted_text
    assert tuple_key_secret not in redacted_text
    assert set_secret not in redacted_text
    assert bytes_secret not in redacted_text
    assert tuple_string_secret not in redacted_tuple_text
    assert f'"api_key":"{REDACTED_EVIDENCE_VALUE}"' in redacted_text
    assert f'"token":"{REDACTED_EVIDENCE_VALUE}"' in redacted_text
    assert '"<tuple-key>":"x"' in redacted_text
    assert f'"metadata":["token={REDACTED_EVIDENCE_VALUE}"]' in redacted_text
    assert f'"bytes":"b\'token={REDACTED_EVIDENCE_VALUE}\'"' in redacted_text
    assert '"safe":["ok"]' in redacted_text
    assert f'["api_key","{REDACTED_EVIDENCE_VALUE}"]' in redacted_tuple_text


def test_redacts_oversized_and_deep_structured_evidence() -> None:
    """Oversized or deeply nested structured evidence should fail closed."""
    large_secret = "LARGE_STRUCTURED_SECRET"
    large_text = f'{{"api_key":["{large_secret}"],"pad":"{"x" * 11000}"}}'

    large_redacted = redact_evidence_string(large_text, max_chars=500)
    deep_redacted = redact_evidence_string("[" * 1200 + "]" * 1200, max_chars=500)

    assert large_secret not in large_redacted
    assert large_redacted == REDACTED_EVIDENCE_VALUE
    assert REDACTED_EVIDENCE_VALUE in deep_redacted
    assert len(deep_redacted) <= 500


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

    assert redacted == f"wasbs://{REDACTED_URL_CREDENTIALS}@account.blob.core.windows.net/model.bin"


def test_redacts_azure_style_authority_on_non_azure_host() -> None:
    """Container syntax alone must not exempt userinfo on an unrelated host."""
    redacted = redact_evidence_string("wasbs://accesskey@example.com/model.bin", max_chars=500)

    assert redacted == f"wasbs://{REDACTED_URL_CREDENTIALS}@example.com/model.bin"


def test_preserves_valid_azure_container_url_nested_in_query() -> None:
    """A nested Azure container URL without secrets should remain actionable."""
    nested_url = "wasbs://container@account.blob.core.windows.net/model.bin"
    text = f"https://example.com/hook?next={quote(nested_url, safe='')}"

    redacted = redact_evidence_string(text, max_chars=500)

    assert REDACTED_EVIDENCE_VALUE not in redacted
    assert REDACTED_URL_CREDENTIALS not in redacted
    assert "next=wasbs%3A%2F%2Fcontainer%40account.blob.core.windows.net%2Fmodel.bin" in redacted


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
        "sk-proj-" + "abc_def-" * 4,
    ],
)
def test_redacts_standalone_secret_token_shapes(token: str) -> None:
    """Secret-shaped strings should be redacted even without assignment syntax."""
    redacted = redact_evidence_string(f"metadata key: {token}", max_chars=500)

    assert redacted == f"metadata key: {REDACTED_EVIDENCE_VALUE}"


@pytest.mark.parametrize(
    "encoded_token",
    [
        "ghp%5F" + "a" * 36,
        "ghp%255F" + "a" * 36,
        "%67%68%70%5F" + "%61" * 36,
    ],
)
def test_redacts_percent_encoded_standalone_secret_tokens(encoded_token: str) -> None:
    """Percent encoding must not make a standalone secret safe to serialize."""
    redacted = redact_evidence_string(f"metadata key: {encoded_token}", max_chars=500)

    assert redacted == f"metadata key: {REDACTED_EVIDENCE_VALUE}"


@pytest.mark.parametrize(
    "near_miss",
    [
        "ghp_" + "a" * 35,
        "sk_live_" + "a" * 23,
        "sk-proj-" + "abc_def-" * 2 + "abcdefg",
        "modelghp_" + "a" * 36,
    ],
)
def test_preserves_near_miss_standalone_secret_shapes(near_miss: str) -> None:
    """Nearby non-secret identifiers should remain useful evidence."""
    text = f"metadata key: {near_miss}"

    assert redact_evidence_string(text, max_chars=500) == text


def test_preserves_percent_encoded_standalone_secret_near_miss() -> None:
    """Encoded identifiers that do not meet a token shape should remain actionable."""
    text = "metadata key: ghp%5F" + "a" * 35

    assert redact_evidence_string(text, max_chars=500) == text
