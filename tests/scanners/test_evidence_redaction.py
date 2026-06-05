"""Tests for scanner evidence redaction helpers."""

import ast
import json
from urllib.parse import quote

import pytest

from modelaudit.scanners import _evidence_redaction as evidence_redaction
from modelaudit.scanners._evidence_redaction import (
    REDACTED_EVIDENCE_VALUE,
    REDACTED_URL_CREDENTIALS,
    REDACTION_LOOKAHEAD_CHARS,
    redact_evidence_string,
    redact_evidence_value,
    redact_untrusted_error_message,
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


def test_rightward_raw_assignment_crossing_preview_boundary_preserves_safe_context() -> None:
    """Lookahead-confirmed raw assignments should retain context from the original preview."""
    long_identifier = f"service_{'a' * 300}_token"
    redacted = redact_evidence_string(
        f'base::system("curl"); r"(BOUNDARY_RAW_SECRET)" -> {long_identifier}',
        max_chars=200,
    )

    assert "BOUNDARY_RAW_SECRET" not in redacted
    assert redacted.startswith(f'base::system("curl"); {REDACTED_EVIDENCE_VALUE} -> service_')
    assert redacted.endswith("...")


def test_long_benign_rightward_raw_assignment_near_match_remains_visible() -> None:
    """A sensitive-looking target prefix must not redact a benign long identifier."""
    long_identifier = f"service_{'a' * 300}_tokenizer"
    redacted = redact_evidence_string(
        f'r"(BENIGN_RAW_VALUE)" -> {long_identifier}',
        max_chars=200,
    )

    assert "BENIGN_RAW_VALUE" in redacted
    assert REDACTED_EVIDENCE_VALUE not in redacted


def test_rightward_assignment_targets_beyond_lookahead_fail_closed() -> None:
    """An unfinished rightward target must not expose values before its sensitive suffix."""
    long_identifier = f"service_{'a' * 5_000}_token"

    for value in ('r"(RAW_SECRET)"', '"QUOTED_SECRET"', 'paste0("CALL_SECRET")'):
        redacted = redact_evidence_string(f"{value} -> {long_identifier}", max_chars=180)

        assert "SECRET" not in redacted
        assert redacted == REDACTED_EVIDENCE_VALUE

    for target in (f"`{long_identifier}`", f'"{long_identifier}"'):
        redacted = redact_evidence_string(f'r"(QUOTED_TARGET_SECRET)" -> {target}', max_chars=180)

        assert "QUOTED_TARGET_SECRET" not in redacted
        assert redacted == REDACTED_EVIDENCE_VALUE

    prefix = 'r"(DELIMITER_BOUNDARY_SECRET)" -> "service_'
    target_length = 180 + REDACTION_LOOKAHEAD_CHARS - len(prefix)
    exact_boundary_target = f'{prefix}{"a" * (target_length - len("_token"))}_token"'
    exact_boundary = redact_evidence_string(exact_boundary_target, max_chars=180)
    assert "DELIMITER_BOUNDARY_SECRET" not in exact_boundary
    assert exact_boundary == REDACTED_EVIDENCE_VALUE

    r_call = redact_evidence_string(f'def.foo("R_CALL_SECRET") -> {long_identifier}', max_chars=180)
    assert "R_CALL_SECRET" not in r_call
    assert r_call == REDACTED_EVIDENCE_VALUE


def test_long_python_return_annotation_is_not_treated_as_r_assignment() -> None:
    """A truncated Python annotation should not trigger the R fail-closed guard."""
    long_annotation = f"service_{'a' * 5_000}_token"
    text = f'def handler() -> {long_annotation}:\n    return "VISIBLE"'

    redacted = redact_evidence_string(text, max_chars=180)

    assert redacted.startswith("def handler")
    assert REDACTED_EVIDENCE_VALUE not in redacted


def test_python_raw_default_is_not_treated_as_r_assignment() -> None:
    """Parseable Python containing a raw string should retain its return annotation."""
    text = 'def handler(value=r"(VISIBLE)") -> token:\n    return value'

    assert redact_evidence_string(text, max_chars=None) == text


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
        "hf_" + "a" * 34,
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
        "ghp%2525255F" + "a" * 36,
    ],
)
def test_redacts_percent_encoded_standalone_secret_tokens(encoded_token: str) -> None:
    """Percent encoding must not make a standalone secret safe to serialize."""
    redacted = redact_evidence_string(f"metadata key: {encoded_token}", max_chars=500)

    assert redacted == f"metadata key: {REDACTED_EVIDENCE_VALUE}"


@pytest.mark.parametrize(
    ("encoded_value", "expected"),
    [
        ("api_key%3Dhunter2", f"api_key={REDACTED_EVIDENCE_VALUE}"),
        ("api_key%3DENCODEDSECRET123456", f"api_key={REDACTED_EVIDENCE_VALUE}"),
        ("api_key%253DENCODEDSECRET123456", f"api_key={REDACTED_EVIDENCE_VALUE}"),
        (
            "https%3A%2F%2Fuser%3Apass%40evil.example%2Fcb",
            f"https://{REDACTED_URL_CREDENTIALS}@evil.example/cb",
        ),
    ],
)
def test_redacts_percent_encoded_credential_evidence(encoded_value: str, expected: str) -> None:
    redacted = redact_evidence_string(encoded_value, max_chars=500)

    assert redacted == expected


def test_preserves_benign_percent_encoded_evidence() -> None:
    for text in ("version%3D1", "metadata%20label%20value"):
        assert redact_evidence_string(text, max_chars=500) == text


def test_bounds_deep_benign_percent_decoding(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nested benign encoding must not recursively rescan every remaining layer."""
    decode_depth = 12
    encoded = "version=1"
    for _ in range(decode_depth):
        encoded = quote(encoded, safe="")

    real_unquote = evidence_redaction.unquote
    unquote_calls = 0

    def counting_unquote(value: str) -> str:
        nonlocal unquote_calls
        unquote_calls += 1
        return real_unquote(value)

    monkeypatch.setattr(evidence_redaction, "unquote", counting_unquote)

    assert redact_evidence_string(encoded, max_chars=500) == encoded
    assert unquote_calls <= decode_depth + 1


@pytest.mark.parametrize(
    "near_miss",
    [
        "ghp_" + "a" * 35,
        "hf_" + "a" * 29,
        "sk_live_" + "a" * 23,
        "sk-proj-" + "abc_def-" * 2 + "abcdefg",
        "modelghp_" + "a" * 36,
        "sk-this-is-a-benign-model-identifier-2026",
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


@pytest.mark.parametrize("separator", ["\x00", "\t", "\n", "\r", "\u2028", "\u2029", "\u202e"])
def test_removes_terminal_and_format_controls_before_redaction(separator: str) -> None:
    """Model-controlled controls must neither render nor split sensitive keys."""
    secret = "CONTROLSECRET123456789"
    text = f"api_{separator}key={secret}\x1b[2J\nFORGED\u202e"

    redacted = redact_evidence_string(text, max_chars=500)

    assert redacted == "api_key=<redacted>"
    assert secret not in redacted


@pytest.mark.parametrize("encoded_separator", ["%00", "%E2%80%A8", "%E2%80%A9", "%E2%80%AE"])
def test_redacts_percent_encoded_controls_inside_sensitive_keys(encoded_separator: str) -> None:
    secret = "ENCODEDCONTROLSECRET123456789"

    redacted = redact_evidence_string(f"api_{encoded_separator}key={secret}", max_chars=500)

    assert redacted == "api_key=<redacted>"
    assert secret not in redacted


def test_attacker_supplied_redaction_marker_does_not_hide_control_split_secret() -> None:
    secret = "MARKERCONFUSIONSECRET123456789"
    text = f"note={REDACTED_EVIDENCE_VALUE}\napi_\nkey={REDACTED_EVIDENCE_VALUE}{secret}"

    redacted = redact_evidence_string(text, max_chars=500)

    assert secret not in redacted
    assert "api_key=<redacted>" in redacted


@pytest.mark.parametrize(
    "value",
    [
        f'loader("{REDACTED_EVIDENCE_VALUE}", "MARKERCONTAINERSECRET123456789")',
        f'{{"note":"{REDACTED_EVIDENCE_VALUE}","value":"MARKERCONTAINERSECRET123456789"}}',
    ],
)
def test_attacker_supplied_redaction_marker_does_not_hide_control_split_container_secret(value: str) -> None:
    redacted = redact_evidence_string(f"api_\nkey={value}", max_chars=500)

    assert redacted == "api_key=<redacted>"
    assert "MARKERCONTAINERSECRET123456789" not in redacted


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


def test_preserves_python_return_annotation_named_token() -> None:
    """Python return annotations must not be mistaken for R rightward assignments."""
    text = "def build() -> token:\n    return visible"

    assert redact_evidence_string(text, max_chars=None) == text


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
    assert 'logger.info("api_key", "<redacted>")' in redacted
    assert 'setattr(config, "timeout", "30")' in redacted
    assert 'eval("1 + 1")' in redacted


def test_redacts_embedded_name_value_credentials_and_generic_calls() -> None:
    """Structured name/value pairs should follow the same credential-key policy."""
    text = (
        'meta = {"name": "api_key", "value": "DICTSECRET1234567890"}; '
        'other = {"key": "client_secret", "value": build("KEYDICTSECRET1234567890")}; '
        'Credential(name="api_key", value="CALLSECRET1234567890"); '
        'Field(key="client_secret", value=build("KEYCALLSECRET1234567890")); '
        'Field(name="api_key_count", value="visible-count"); '
        'meta = {"name": "tokenizer", "value": "visible-tokenizer"}; eval("1 + 1")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    for secret in (
        "DICTSECRET1234567890",
        "KEYDICTSECRET1234567890",
        "CALLSECRET1234567890",
        "KEYCALLSECRET1234567890",
    ):
        assert secret not in redacted
    assert '"name": "api_key", "value": <redacted>' in redacted
    assert '"key": "client_secret", "value": <redacted>' in redacted
    assert 'Credential(name="api_key", value=<redacted>)' in redacted
    assert 'Field(key="client_secret", value=<redacted>)' in redacted
    assert 'Field(name="api_key_count", value="visible-count")' in redacted
    assert '"name": "tokenizer", "value": "visible-tokenizer"' in redacted
    assert 'eval("1 + 1")' in redacted


def test_redacts_duplicate_name_value_fields() -> None:
    """Case-variant duplicate value fields must not leave an earlier secret visible."""
    text = 'meta = {"name": "api_key", "value": "FIRST_DICT_SECRET", "Value": "SECOND_DICT_SECRET"}'

    redacted = redact_evidence_string(text, max_chars=None)

    assert "FIRST_DICT_SECRET" not in redacted
    assert "SECOND_DICT_SECRET" not in redacted
    assert redacted.count(REDACTED_EVIDENCE_VALUE) == 2


def test_redacts_byte_string_name_value_fields() -> None:
    """Byte-string descriptor keys and values should use the same credential policy."""
    text = 'meta = {b"name": b"api_key", b"value": b"BYTES_DICT_SECRET"}'

    redacted = redact_evidence_string(text, max_chars=None)

    assert "BYTES_DICT_SECRET" not in redacted
    assert 'b"value": <redacted>' in redacted


def test_name_value_declarations_are_not_treated_as_calls() -> None:
    """Function and class parameter defaults are declarations, not credential stores."""
    text = (
        'def Credential(name="api_key", value="VISIBLE_DEF"): return value\n'
        'async def AsyncCredential(name="api_key", value="VISIBLE_ASYNC"): return value\n'
        'class CredentialBase(name="api_key", value="VISIBLE_CLASS"): pass'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "VISIBLE_DEF" in redacted
    assert "VISIBLE_ASYNC" in redacted
    assert "VISIBLE_CLASS" in redacted
    assert REDACTED_EVIDENCE_VALUE not in redacted


def test_name_value_call_beyond_lookahead_fails_closed() -> None:
    """An unfinished sensitive keyword call must not leak a value past the lookahead bound."""
    text = f'Credential(name="api_key", value="BOUNDARY_CALL_SECRET{"A" * 5_000}")'

    redacted = redact_evidence_string(text, max_chars=180)

    assert "BOUNDARY_CALL_SECRET" not in redacted
    assert redacted == REDACTED_EVIDENCE_VALUE

    reversed_arguments = (
        'Credential(value="REVERSED_CALL_SECRET", padding="' + ("A" * 5_000) + '", name=("api_" + "key"))'
    )
    reversed_redacted = redact_evidence_string(reversed_arguments, max_chars=180)
    assert "REVERSED_CALL_SECRET" not in reversed_redacted
    assert reversed_redacted == REDACTED_EVIDENCE_VALUE

    benign = f'render(value="VISIBLE_VALUE{"A" * 5_000}")'
    benign_redacted = redact_evidence_string(benign, max_chars=180)
    assert "VISIBLE_VALUE" in benign_redacted
    assert REDACTED_EVIDENCE_VALUE not in benign_redacted


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


def test_redacts_acronym_prefixed_sensitive_assignments() -> None:
    """All-caps provider prefixes should not bypass target classification."""
    text = (
        'AWSAccessKeyId = os.getenv("KEY", "AWSACRONYMSECRET1234567890"); '
        'DBPassword = build("DBACRONYMSECRET1234567890"); '
        'DBPasswordlessMode = "enabled"'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "AWSACRONYMSECRET1234567890" not in redacted
    assert "DBACRONYMSECRET1234567890" not in redacted
    assert "AWSAccessKeyId = <redacted>" in redacted
    assert "DBPassword = <redacted>" in redacted
    assert 'DBPasswordlessMode = "enabled"' in redacted


def test_redacts_sensitive_getter_defaults_and_keyword_setters() -> None:
    """Credential keyed calls should support defaults and keyword arguments."""
    text = (
        'value = os.getenv("CLIENT_SECRET", "GETTERSECRET1234567890"); '
        'other = os.environ.get(key="AWS_SECRET_ACCESS_KEY", default="ENVGETSECRET1234567890"); '
        'os.putenv(key="AWS_SECRET_ACCESS_KEY", value="KWSETSECRET1234567890"); '
        'setattr(obj=config, name="api_key", value=build("KWATTRSECRET1234567890")); '
        'value = getattr(config, name="client_secret", default="GETATTRSECRET1234567890"); '
        'other = settings.get("api_key", "MAPPINGGETSECRET1234567890"); '
        'removed = settings.pop("refresh_token", "POPSECRET1234567890"); '
        'value = os.getenv("REGION", "us-east-1"); '
        'region = settings.get("region", "VISIBLE")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "GETTERSECRET1234567890" not in redacted
    assert "ENVGETSECRET1234567890" not in redacted
    assert "KWSETSECRET1234567890" not in redacted
    assert "KWATTRSECRET1234567890" not in redacted
    assert "GETATTRSECRET1234567890" not in redacted
    assert "MAPPINGGETSECRET1234567890" not in redacted
    assert "POPSECRET1234567890" not in redacted
    assert 'os.getenv("CLIENT_SECRET", <redacted>)' in redacted
    assert 'os.environ.get(key="AWS_SECRET_ACCESS_KEY", default=<redacted>)' in redacted
    assert 'os.putenv(key="AWS_SECRET_ACCESS_KEY", value=<redacted>)' in redacted
    assert 'setattr(obj=config, name="api_key", value=<redacted>)' in redacted
    assert 'getattr(config, name="client_secret", default=<redacted>)' in redacted
    assert 'settings.get("api_key", <redacted>)' in redacted
    assert 'settings.pop("refresh_token", <redacted>)' in redacted
    assert 'os.getenv("REGION", "us-east-1")' in redacted
    assert 'settings.get("region", "VISIBLE")' in redacted


def test_sensitive_keyed_calls_preserve_dangerous_value_operations() -> None:
    """Executable credential values should retain call shape without literal data."""
    text = (
        'value = os.getenv("CLIENT_SECRET", eval("GETTERSECRET1234567890")); '
        'headers.setdefault("api_key", exec("SETTERSECRET1234567890")); '
        'Field(key="client_secret", value=compile("COMPILESECRET1234567890", "file", "exec")); '
        'parser.add_argument("--api-key", default=eval("OPTIONSECRET1234567890")); '
        'numeric = os.getenv("CLIENT_SECRET", eval(12345678901234567890)); '
        'settings.get("region", eval("VISIBLEDEFAULT1234567890"))'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    for secret in (
        "GETTERSECRET1234567890",
        "SETTERSECRET1234567890",
        "COMPILESECRET1234567890",
        "OPTIONSECRET1234567890",
    ):
        assert secret not in redacted
    assert 'os.getenv("CLIENT_SECRET", eval("<redacted>"))' in redacted
    assert 'headers.setdefault("api_key", exec("<redacted>"))' in redacted
    assert 'Field(key="client_secret", value=compile("<redacted>", "<redacted>", "<redacted>"))' in redacted
    assert 'parser.add_argument("--api-key", default=eval("<redacted>"))' in redacted
    assert "12345678901234567890" not in redacted
    assert "numeric = os.getenv(\"CLIENT_SECRET\", eval('<redacted>'))" in redacted
    assert 'settings.get("region", eval("VISIBLEDEFAULT1234567890"))' in redacted


def test_redacts_sensitive_comparison_literals_without_losing_context() -> None:
    """Sensitive comparisons should remove literals and preserve dangerous calls."""
    text = (
        'if api_key == "COMPARESECRET1234567890": eval("1 + 1")\n'
        'if client_secret != build("COMPARESECRET0987654321"): exec("pass")\n'
        'if safe == "visible" and "REVERSECOMPARESECRET1234567890" == api_key: eval("4 + 4")\n'
        'if tokenizer == "visible": eval("2 + 2")\n'
        'if api_key: eval("5 + 5")\n'
        "if api_key_count == 1: eval('3 + 3')"
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "COMPARESECRET1234567890" not in redacted
    assert "COMPARESECRET0987654321" not in redacted
    assert "REVERSECOMPARESECRET1234567890" not in redacted
    assert "api_key == <redacted>" in redacted
    assert "client_secret != <redacted>" in redacted
    assert 'eval("1 + 1")' in redacted
    assert 'exec("pass")' in redacted
    assert 'safe == "visible" and <redacted> == api_key' in redacted
    assert 'eval("4 + 4")' in redacted
    assert 'tokenizer == "visible"' in redacted
    assert 'if api_key: eval("5 + 5")' in redacted
    assert "api_key_count == 1" in redacted


def test_sensitive_comparisons_preserve_dangerous_operand_calls() -> None:
    """Executable comparison operands should stay visible after literal redaction."""
    text = (
        'if api_key == eval("COMPARESECRET1234567890"): pass\n'
        'if client_secret in exec("MEMBERSHIPSECRET1234567890"): pass\n'
        "if access_token == eval(98765432109876543210): pass\n"
        "if session_id == 11223344556677889900: pass\n"
        'if tokenizer == eval("VISIBLECOMPARE1234567890"): pass'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "COMPARESECRET1234567890" not in redacted
    assert "MEMBERSHIPSECRET1234567890" not in redacted
    assert 'api_key == eval("<redacted>")' in redacted
    assert 'client_secret in exec("<redacted>")' in redacted
    assert "98765432109876543210" not in redacted
    assert "11223344556677889900" not in redacted
    assert "access_token == eval('<redacted>')" in redacted
    assert 'tokenizer == eval("VISIBLECOMPARE1234567890")' in redacted


def test_redacts_non_operator_sensitive_comparisons_without_losing_context() -> None:
    """Comparison helpers and match patterns must not expose credential literals."""
    text = (
        'hmac.compare_digest(api_key, "DIGESTSECRET1234567890"); eval("1")\n'
        'hmac.compare_digest("REVERSEDIGESTSECRET1234567890", client_secret); exec("2")\n'
        'if api_key.startswith("PREFIXSECRET1234567890"): eval("3")\n'
        'match api_key:\n    case "MATCHSECRET1234567890": eval("4")\n'
        'hmac.compare_digest(tokenizer, "visible"); tokenizer.startswith("visible-prefix")\n'
        'match tokenizer:\n    case "visible-match": print("ok")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    for secret in (
        "DIGESTSECRET1234567890",
        "REVERSEDIGESTSECRET1234567890",
        "PREFIXSECRET1234567890",
        "MATCHSECRET1234567890",
    ):
        assert secret not in redacted
    assert 'hmac.compare_digest(api_key, "<redacted>")' in redacted
    assert 'hmac.compare_digest("<redacted>", client_secret)' in redacted
    assert 'api_key.startswith("<redacted>")' in redacted
    assert 'case "<redacted>":' in redacted
    assert 'hmac.compare_digest(tokenizer, "visible")' in redacted
    assert 'tokenizer.startswith("visible-prefix")' in redacted
    assert 'case "visible-match":' in redacted
    assert 'eval("4")' in redacted


def test_redacts_sensitive_fstring_interpolations_without_losing_calls() -> None:
    """Credential-shaped f-strings should not leak or hide executable expressions."""
    text = (
        'first = f\'api_key={"FSTRINGSECRET1234567890"}\'; eval("1")\n'
        "second = f'client_secret={exec(\"FSTRINGCALLSECRET1234567890\")} status={status}'\n"
        'third = f\'{"api_key"}={"DYNAMICKEYSECRET1234567890"}\'\n'
        'fourth = f\'{"client_secret"}: {eval("DYNAMICKEYCALLSECRET1234567890")}\'\n'
        "fifth = f'api_key=PREFIX-{value}-TRAILINGSECRET1234567890'\n"
        "sixth = f'{\"api_key\"}={value}-DYNAMICTRAILINGSECRET1234567890'\n"
        "seventh = f'client_secret={value} operation={exec(24681357902468135790)}'\n"
        "visible = f'tokenizer={value} api_key_count={count}'\n"
        "dynamic_visible = f'{\"tokenizer\"}={value}'"
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "FSTRINGSECRET1234567890" not in redacted
    assert "FSTRINGCALLSECRET1234567890" not in redacted
    assert "DYNAMICKEYSECRET1234567890" not in redacted
    assert "DYNAMICKEYCALLSECRET1234567890" not in redacted
    assert "TRAILINGSECRET1234567890" not in redacted
    assert "DYNAMICTRAILINGSECRET1234567890" not in redacted
    assert "24681357902468135790" not in redacted
    assert "exec('<redacted>')" in redacted
    assert "eval('<redacted>')" in redacted
    assert "exec('<redacted>')" in redacted
    assert "f'tokenizer={value} api_key_count={count}'" in redacted
    assert "f'{\"tokenizer\"}={value}'" in redacted
    assert 'eval("1")' in redacted
    ast.parse(redacted)


def test_python_annotations_and_block_headers_are_not_assignments() -> None:
    """Credential-shaped Python targets must not erase annotations or block bodies."""
    text = (
        'api_key: str\ncredentials: "CredentialStore"\n'
        'def handle(api_key: str, authorization: "Header"):\n    eval("1")\n'
        'with open("visible") as api_key:\n    exec("2")\n'
        'class credentials:\n    marker = "visible"\n'
        'for api_key in values:\n    compile("3", "visible", "exec")'
    )

    assert redact_evidence_string(text, max_chars=None) == text


def test_redacts_generic_python_credential_keys_and_framed_variants() -> None:
    """Exact generic credential keys should redact without broad near-match false positives."""
    secret = "GENERICSECRET1234567890"
    framed_secret = "FRAMEDGENERICSECRET1234567890"
    text = (
        f'credentials = "{secret}"; headers = {{"API Key": "{secret}"}}; '
        'credentials_manager = "visible"; headers["API Key Count"] = "visible"; eval("1")'
    )
    framed = f'\x00 credentials = "{framed_secret}"; headers = {{"API Key": "{framed_secret}"}}; exec("2")'

    redacted = redact_evidence_string(text, max_chars=None)
    framed_redacted = redact_evidence_string(framed, max_chars=None)

    assert secret not in redacted
    assert framed_secret not in framed_redacted
    assert "credentials = <redacted>" in redacted
    assert '"API Key": "<redacted>"' in redacted
    assert 'credentials_manager = "visible"' in redacted
    assert 'headers["API Key Count"] = "visible"' in redacted
    assert 'eval("1")' in redacted
    assert 'exec("2")' in framed_redacted


def test_unparseable_sensitive_comparison_and_keyed_calls_fail_closed() -> None:
    """NUL framing must not reopen comparison, getter, or keyword-call gaps."""
    text = (
        '\x00 value = os.getenv(key="CLIENT_SECRET", default="FRAMEDGETSECRET1234567890"); '
        'os.putenv(key="AWS_SECRET_ACCESS_KEY", value="FRAMEDSETSECRET1234567890"); '
        'if api_key == "FRAMEDCOMPARESECRET1234567890": eval("1 + 1")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "FRAMEDGETSECRET1234567890" not in redacted
    assert "FRAMEDSETSECRET1234567890" not in redacted
    assert "FRAMEDCOMPARESECRET1234567890" not in redacted
    assert 'os.getenv(key="CLIENT_SECRET", default=<redacted>)' in redacted
    assert 'os.putenv(key="AWS_SECRET_ACCESS_KEY", value=<redacted>)' in redacted
    assert "api_key == <redacted>" in redacted
    assert 'eval("1 + 1")' in redacted


def test_redacts_http_auth_and_sensitive_option_defaults() -> None:
    """Auth arguments and credential option defaults must not retain secrets."""
    text = (
        'requests.get(url, auth=("user", "BASICAUTHSECRET1234567890")); '
        'parser.add_argument("-k", "--api-key", default="ARGPARSESECRET1234567890"); '
        'click.option("--client-secret", default=build("CLICKSECRET1234567890")); '
        'requests.get(url, auth_timeout="visible"); '
        'parser.add_argument("--region", default="us-east-1"); '
        'parser.add_argument("--api-key-count", default=3); '
        'click.option("--token-cache", default="enabled"); eval("1 + 1")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "BASICAUTHSECRET1234567890" not in redacted
    assert "ARGPARSESECRET1234567890" not in redacted
    assert "CLICKSECRET1234567890" not in redacted
    assert "auth=<redacted>" in redacted
    assert 'parser.add_argument("-k", "--api-key", default=<redacted>)' in redacted
    assert 'click.option("--client-secret", default=<redacted>)' in redacted
    assert 'auth_timeout="visible"' in redacted
    assert 'parser.add_argument("--region", default="us-east-1")' in redacted
    assert 'parser.add_argument("--api-key-count", default=3)' in redacted
    assert 'click.option("--token-cache", default="enabled")' in redacted
    assert 'eval("1 + 1")' in redacted


def test_auth_and_cookie_expressions_preserve_executable_call_context() -> None:
    """Executable auth values should retain the operation while redacting literals."""
    text = (
        'requests.get(url, auth=eval("AUTHCALLSECRET1234567890")); '
        'requests.get(url, cookie=exec("COOKIECALLSECRET1234567890")); '
        'requests.get(url, cookies={"sessionid": compile("COOKIECOMPILESECRET1234567890", "x", "exec")}); '
        'requests.get(url, auth=("user", "BASICAUTHSECRET1234567890"))'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    for secret in (
        "AUTHCALLSECRET1234567890",
        "COOKIECALLSECRET1234567890",
        "COOKIECOMPILESECRET1234567890",
        "BASICAUTHSECRET1234567890",
    ):
        assert secret not in redacted
    assert 'auth=eval("<redacted>")' in redacted
    assert 'cookie=exec("<redacted>")' in redacted
    assert 'compile("<redacted>", "<redacted>", "<redacted>")' in redacted
    assert "auth=<redacted>" in redacted


def test_redacts_parsed_python_literal_sensitive_keys() -> None:
    """Escaped and triple-quoted keys should be classified by parsed value."""
    text = (
        'os.environ["""API_KEY"""] = "TRIPLEKEYSECRET1234567890"\n'
        'payload[("client_" "secret")] = "CONCATKEYSECRET1234567890"\n'
        'payload = {"api_\\x6bey": "ESCAPEDKEYSECRET1234567890", '
        '"regi\\x6fn": "visible"}\n'
        'safe: "api_key" = "visible"'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "TRIPLEKEYSECRET1234567890" not in redacted
    assert "CONCATKEYSECRET1234567890" not in redacted
    assert "ESCAPEDKEYSECRET1234567890" not in redacted
    assert 'os.environ["""API_KEY"""] = <redacted>' in redacted
    assert 'payload[("client_" "secret")] = <redacted>' in redacted
    assert '"api_\\x6bey": <redacted>' in redacted
    assert '"regi\\x6fn": "visible"' in redacted
    assert 'safe: "api_key" = "visible"' in redacted


def test_redacts_concatenated_keys_and_literal_credential_pairs() -> None:
    """Static key concatenation and neutral key/value containers must be covered."""
    text = (
        'value = os.getenv("CLIENT_" "SECRET", "CONCATGETSECRET1234567890"); '
        'fvalue = os.getenv(f"CLIENT_SECRET", "FSTRINGGETSECRET1234567890"); '
        'os.putenv("AWS_" "SECRET_ACCESS_KEY", build("CONCATSETSECRET1234567890")); '
        'headers = [("X-API-Key", "PAIRSECRET1234567890"), ("Region", "visible")]; '
        'credentials = "client_secret", "BAREPAIRSECRET1234567890"; '
        'f_pair = (f"api_key", "FSTRINGPAIRSECRET1234567890"); '
        'authorization_pair = ("Authorization", build("AUTHPAIRSECRET1234567890")); '
        'labels = ["tokenizer", "visible"]; emit("api_key", "visible"); eval("1 + 1")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "CONCATGETSECRET1234567890" not in redacted
    assert "FSTRINGGETSECRET1234567890" not in redacted
    assert "CONCATSETSECRET1234567890" not in redacted
    assert "PAIRSECRET1234567890" not in redacted
    assert "BAREPAIRSECRET1234567890" not in redacted
    assert "FSTRINGPAIRSECRET1234567890" not in redacted
    assert "AUTHPAIRSECRET1234567890" not in redacted
    assert 'os.getenv("CLIENT_" "SECRET", <redacted>)' in redacted
    assert 'os.getenv(f"CLIENT_SECRET", <redacted>)' in redacted
    assert 'os.putenv("AWS_" "SECRET_ACCESS_KEY", <redacted>)' in redacted
    assert '("X-API-Key", <redacted>)' in redacted
    assert 'credentials = "client_secret", <redacted>' in redacted
    assert 'f_pair = (f"api_key", <redacted>)' in redacted
    assert 'authorization_pair = ("Authorization", <redacted>)' in redacted
    assert '("Region", "visible")' in redacted
    assert 'labels = ["tokenizer", "visible"]' in redacted
    assert 'emit("api_key", "<redacted>")' in redacted
    assert 'eval("1 + 1")' in redacted


def test_unparseable_literal_credential_pairs_fail_closed() -> None:
    """Framed evidence should still redact literal credential pairs."""
    text = '\x00 pairs = [("api_key", "FRAMEDPAIRSECRET1234567890"), ("region", "visible")]'

    redacted = redact_evidence_string(text, max_chars=None)

    assert "FRAMEDPAIRSECRET1234567890" not in redacted
    assert '("api_key", <redacted>)' in redacted
    assert '("region", "visible")' in redacted


def test_redacts_sensitive_membership_comparisons() -> None:
    """Membership operands for sensitive targets should not retain literals."""
    text = (
        'if api_key in ["MEMBERSHIPSECRET1234567890"]: eval("1 + 1")\n'
        'if client_secret not in ("NOTINSECRET1234567890",): exec("pass")\n'
        'if "REVERSEMEMBERSHIPSECRET1234567890" in api_keys: eval("2 + 2")\n'
        'if tokenizer in ["visible"]: eval("3 + 3")\n'
        "if api_key_count in [1, 2]: eval('4 + 4')"
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "MEMBERSHIPSECRET1234567890" not in redacted
    assert "NOTINSECRET1234567890" not in redacted
    assert "REVERSEMEMBERSHIPSECRET1234567890" not in redacted
    assert "api_key in <redacted>" in redacted
    assert "client_secret not in <redacted>" in redacted
    assert "<redacted> in api_keys" in redacted
    assert 'tokenizer in ["visible"]' in redacted
    assert "api_key_count in [1, 2]" in redacted
    assert 'eval("1 + 1")' in redacted
    assert 'exec("pass")' in redacted


def test_redacts_affixed_sensitive_targets_without_control_false_positives() -> None:
    """Private, numeric, and plural credentials should not broaden control names."""
    text = (
        '_api_key = "PRIVATESECRET1234567890"; '
        'api_key2 = build("NUMBEREDSECRET1234567890"); '
        'api_keys = ["PLURALSECRET1234567890"]; '
        "api_key_count = 2; token_cache = True; passwordless = True; tokenizer = visible"
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "PRIVATESECRET1234567890" not in redacted
    assert "NUMBEREDSECRET1234567890" not in redacted
    assert "PLURALSECRET1234567890" not in redacted
    assert '_api_key = "<redacted>"' in redacted
    assert "api_key2 = <redacted>" in redacted
    assert "api_keys = <redacted>" in redacted
    assert "api_key_count = 2" in redacted
    assert "token_cache = True" in redacted
    assert "passwordless = True" in redacted
    assert "tokenizer = visible" in redacted


def test_redacts_cookie_call_arguments_and_header_mappings() -> None:
    """Cookie-bearing calls and exact cookie/session keys should be sensitive."""
    text = (
        'requests.get(url, cookies={"sessionid": "COOKIECALLSECRET1234567890"}); '
        'headers = {"Cookie": "session=COOKIEHEADERSECRET1234567890"}; '
        'response = {"Set-Cookie": "SESSIONCOOKIESECRET1234567890"}; '
        'state = {"session_id": "SESSIONIDSECRET1234567890"}; '
        'requests.get(url, cookie_timeout="visible"); cookie_count = 1; eval("1 + 1")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "COOKIECALLSECRET1234567890" not in redacted
    assert "COOKIEHEADERSECRET1234567890" not in redacted
    assert "SESSIONCOOKIESECRET1234567890" not in redacted
    assert "SESSIONIDSECRET1234567890" not in redacted
    assert "cookies=<redacted>" in redacted
    assert '"Cookie": "<redacted>"' in redacted
    assert '"Set-Cookie": "<redacted>"' in redacted
    assert '"session_id": "<redacted>"' in redacted
    assert 'cookie_timeout="visible"' in redacted
    assert "cookie_count = 1" in redacted
    assert 'eval("1 + 1")' in redacted


def test_redacts_computed_and_constant_sensitive_subscript_targets() -> None:
    """Computed bases and constant key expressions must not expose assigned values."""
    text = (
        'globals()["api_key"] = "COMPUTEDSECRET1234567890"; '
        'factory()["Authorization"] = "FACTORYSECRET1234567890"; '
        '(config)["client_secret"] = "PARENSECRET1234567890"; '
        'os.environ["AWS_" + "SECRET_ACCESS_KEY"] = "CONCATSECRET1234567890"; '
        'payload[b"client_" + b"secret"] = b"BYTESECRET1234567890"; '
        'factory()["api_key_count"] = "visible"; '
        'payload["api_" + "key_count"] = "visible"; eval("1 + 1")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "COMPUTEDSECRET1234567890" not in redacted
    assert "FACTORYSECRET1234567890" not in redacted
    assert "PARENSECRET1234567890" not in redacted
    assert "CONCATSECRET1234567890" not in redacted
    assert "BYTESECRET1234567890" not in redacted
    assert 'globals()["api_key"] = <redacted>' in redacted
    assert 'factory()["Authorization"] = <redacted>' in redacted
    assert '(config)["client_secret"] = <redacted>' in redacted
    assert 'os.environ["AWS_" + "SECRET_ACCESS_KEY"] = <redacted>' in redacted
    assert 'payload[b"client_" + b"secret"] = <redacted>' in redacted
    assert 'factory()["api_key_count"] = "visible"' in redacted
    assert 'payload["api_" + "key_count"] = "visible"' in redacted
    assert 'eval("1 + 1")' in redacted


def test_redacts_sensitive_identifier_subscript_targets() -> None:
    """Named credential keys in subscript targets should redact their assigned values."""
    text = (
        'os.environ[API_KEY] = "ENVSECRET1234567890"; '
        'config[api_key] = "CONFIGSECRET1234567890"; config[auth] = "AUTHSECRET1234567890"; '
        'config[api_key_count] = "visible-count"; config[auth_timeout] = "visible-timeout"; '
        'config[tokenizer] = "visible-tokenizer"; eval("1 + 1")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "ENVSECRET1234567890" not in redacted
    assert "CONFIGSECRET1234567890" not in redacted
    assert "AUTHSECRET1234567890" not in redacted
    assert "visible-count" in redacted
    assert "visible-timeout" in redacted
    assert "visible-tokenizer" in redacted
    assert 'eval("1 + 1")' in redacted


def test_dynamic_sensitive_named_subscript_preserves_dangerous_context() -> None:
    """A dynamic index named token is not a literal credential key on arbitrary containers."""
    text = 'handlers[token] = eval("MALICIOUS_CONTEXT")'

    assert redact_evidence_string(text, max_chars=None) == text


def test_redacts_exact_auth_targets_without_auth_control_false_positives() -> None:
    """Credential-bearing auth variables should redact without matching controls."""
    text = (
        'auth = ("user", "AUTHSECRET1234567890"); '
        'basic_auth = build("BASICAUTHSECRET1234567890"); '
        'config["auth"] = "MAPPINGAUTHSECRET1234567890"; '
        'auth_timeout = 30; oauth_enabled = True; author = "visible"; eval("1 + 1")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "AUTHSECRET1234567890" not in redacted
    assert "BASICAUTHSECRET1234567890" not in redacted
    assert "MAPPINGAUTHSECRET1234567890" not in redacted
    assert "auth = <redacted>" in redacted
    assert "basic_auth = <redacted>" in redacted
    assert 'config["auth"] = "<redacted>"' in redacted
    assert "auth_timeout = 30" in redacted
    assert "oauth_enabled = True" in redacted
    assert 'author = "visible"' in redacted
    assert 'eval("1 + 1")' in redacted


def test_redaction_preserves_original_preview_boundary() -> None:
    """Shrinking a redacted value must not pull later source text into evidence."""
    hidden_secret = "HIDDENSECRET1234567890"
    long_secret = "A" * 4000
    text = f'api_key = "{long_secret}"\nneutral = "{hidden_secret}"'

    redacted = redact_evidence_string(text, max_chars=180)

    assert "A" * 100 not in redacted
    assert hidden_secret not in redacted
    assert redacted.startswith('api_key = "<redacted>')
    assert redacted.endswith("...")
    assert len(redacted) < 180


def test_redaction_fails_closed_for_tokens_crossing_preview_boundary() -> None:
    """Lookahead may identify a split token but must not expose later source bytes."""
    token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    text = f"prefix https://example.com/{token}/done hidden"

    redacted = redact_evidence_string(text, max_chars=45)

    assert token[:10] not in redacted
    assert "hidden" not in redacted
    assert redacted == "prefix https://example.com/..."


def test_redaction_bounds_expression_analysis_to_original_preview() -> None:
    """Very large evidence strings should redact secrets within the visible prefix."""
    secret = "BOUNDEDSECRET1234567890"
    text = f'client_secret = os.getenv("KEY", "{secret}")\n' + ("x" * 100_000)

    redacted = redact_evidence_string(text, max_chars=100)

    assert secret not in redacted
    assert redacted.startswith("client_secret = <redacted>\n")
    assert redacted.endswith("...")
    assert len(redacted) < 100


def test_indented_python_snippets_use_code_aware_comparison_redaction() -> None:
    """Function-body snippets should retain dangerous context without leaking comparisons."""
    text = (
        '    if api_key == "COMPARESECRET1234567890": eval("1")\n'
        '    if client_secret in ["MEMBERSHIPSECRET1234567890"]: exec("2")\n'
        '    if api_key_count == "visible": print("ok")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "COMPARESECRET1234567890" not in redacted
    assert "MEMBERSHIPSECRET1234567890" not in redacted
    assert "visible" in redacted
    assert 'eval("1")' in redacted
    assert 'exec("2")' in redacted


def test_indented_embedded_name_value_dict_is_redacted() -> None:
    """Dedented Python analysis should cover embedded credential descriptors."""
    text = '    meta = {"name": "api_key", "value": "INDENTED_DICT_SECRET"}; eval("1")'

    redacted = redact_evidence_string(text, max_chars=None)

    assert "INDENTED_DICT_SECRET" not in redacted
    assert '"value": <redacted>' in redacted
    assert 'eval("1")' in redacted


def test_single_line_indented_comparison_preserves_dangerous_call_context() -> None:
    """Colon-shaped control flow must not be mistaken for a mapping assignment."""
    text = '    if api_key == "SECRETKEY1234567890": eval("1")'

    redacted = redact_evidence_string(text, max_chars=None)

    assert "SECRETKEY1234567890" not in redacted
    assert redacted.strip() == 'if api_key == <redacted>: eval("1")'


def test_indented_python_return_annotation_is_not_treated_as_r_assignment() -> None:
    """Dedented routing should preserve Python annotations named like credentials."""
    text = "    def build() -> token:\n        return visible"

    assert redact_evidence_string(text, max_chars=None) == text


def test_redacts_triple_quoted_and_escaped_quote_secret_assignments() -> None:
    """Quoted credential redaction must consume the complete Python literal."""
    text = r'''TOKEN = """TRIPLESECRET123""" os.environ["AWS_SECRET_ACCESS_KEY"] = "prefix\"TAILSECRET456"'''

    redacted = redact_evidence_string(text, max_chars=500)

    assert "TRIPLESECRET123" not in redacted
    assert "TAILSECRET456" not in redacted
    assert 'TOKEN = """<redacted>"""' in redacted
    assert 'os.environ["AWS_SECRET_ACCESS_KEY"] = "<redacted>"' in redacted


def test_redacts_detail_sensitive_container_assignments() -> None:
    text = 'credentials = ["CONTAINERSECRET1234567890"]; credentials_map = {"value": "visible"}; eval("1")'

    redacted = redact_evidence_string(text, max_chars=None)

    assert "CONTAINERSECRET1234567890" not in redacted
    assert "credentials = <redacted>" in redacted
    assert 'credentials_map = {"value": "visible"}' in redacted
    assert 'eval("1")' in redacted


def test_redacts_sensitive_string_annotations() -> None:
    text = 'api_key: "ANNOTATIONSECRET1234567890"\napi_key_count: "visible"\neval("1")'

    redacted = redact_evidence_string(text, max_chars=None)

    assert "ANNOTATIONSECRET1234567890" not in redacted
    assert 'api_key: "<redacted>"' in redacted
    assert 'api_key_count: "visible"' in redacted
    assert 'eval("1")' in redacted


def test_sensitive_assignments_preserve_dangerous_rhs_calls() -> None:
    text = 'client_secret = eval("RHSSECRET1234567890")'

    redacted = redact_evidence_string(text, max_chars=None)

    assert "RHSSECRET1234567890" not in redacted
    assert redacted == 'client_secret = eval("<redacted>")'


def test_redacts_simple_cookie_and_session_assignments() -> None:
    text = (
        'cookie = "COOKIESECRET1234567890"; cookies = "COOKIESSECRET1234567890"; '
        'session_id = "SESSIONSECRET1234567890"; cookie_count = 1; session_timeout = 30; eval("1")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "COOKIESECRET1234567890" not in redacted
    assert "COOKIESSECRET1234567890" not in redacted
    assert "SESSIONSECRET1234567890" not in redacted
    assert "cookie = <redacted>" in redacted
    assert "cookies = <redacted>" in redacted
    assert "session_id = <redacted>" in redacted
    assert "cookie_count = 1" in redacted
    assert "session_timeout = 30" in redacted
    assert 'eval("1")' in redacted


def test_redaction_expansion_honors_max_chars() -> None:
    """Replacement markers must not make bounded evidence exceed its contract."""
    assignment = redact_evidence_string("api_key=x", max_chars=9)
    credential_url = "ssh://u:p@h/x"
    url = redact_evidence_string(credential_url, max_chars=len(credential_url))
    fail_closed = redact_evidence_string("(" * 20, max_chars=4)

    assert len(assignment) <= 9
    assert len(url) <= len(credential_url)
    assert len(fail_closed) <= 4
    assert "x" not in assignment
    assert "u:p" not in url


def test_redacts_positional_sensitive_label_value_calls() -> None:
    """Sensitive labels must sanitize adjacent positional and format values."""
    secrets = [
        "LOGGERSECRET1234567890",
        "LOGGERPASSWORD1234567890",
        "FORMATSECRET1234567890",
        "EXCEPTIONSECRET1234567890",
        "CALLSECRET1234567890",
    ]
    text = (
        f'logger.info("api_key=%s password=%s", "{secrets[0]}", "{secrets[1]}"); '
        f'"api_key={{}}".format("{secrets[2]}"); '
        f'Exception("Authorization", "{secrets[3]}"); '
        f'logger.info("client_secret=%s", eval("{secrets[4]}")); '
        'logger.info("api_key_count=%s", "VISIBLE"); '
        '"tokenizer={}".format("bert"); eval("1")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert all(secret not in redacted for secret in secrets)
    assert 'logger.info("api_key_count=%s", "VISIBLE")' in redacted
    assert '"tokenizer={}".format("bert")' in redacted
    assert 'eval("<redacted>")' in redacted
    assert 'eval("1")' in redacted


def test_redacts_percent_formatted_sensitive_values() -> None:
    """Alternative positional formatting must not bypass sensitive-label redaction."""
    percent_secret = "PERCENTSECRET1234567890"
    call_secret = "PERCENTCALLSECRET1234567890"
    text = (
        f'logger.info("api_key=%s" % "{percent_secret}"); '
        f'logger.info("client_secret=%s" % eval("{call_secret}")); '
        'logger.info("api_key_count=%s" % "VISIBLE"); '
        'logger.info("tokenizer=%s" % "bert"); eval("1")'
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert percent_secret not in redacted
    assert call_secret not in redacted
    assert 'eval("<redacted>")' in redacted
    assert 'logger.info("api_key_count=%s" % "VISIBLE")' in redacted
    assert 'logger.info("tokenizer=%s" % "bert")' in redacted
    assert 'eval("1")' in redacted


def test_preserves_parenthesized_parseable_python_evidence() -> None:
    """Parenthesized expressions should retain the dangerous call that explains a finding."""
    direct = redact_evidence_string('(eval("1"))', max_chars=None)
    lambda_hook = redact_evidence_string("(lambda x: eval(x))", max_chars=None)
    sensitive_tuple = redact_evidence_string('("Authorization", eval("SECRET1234567890"))', max_chars=None)

    assert 'eval("1")' in direct
    assert "lambda x: eval(x)" in lambda_hook
    assert 'eval("<redacted>")' in sensitive_tuple


def test_untrusted_error_message_discards_mixed_secret_shapes() -> None:
    leaked_secret = "UNSTRUCTURED-CREDENTIAL-MATERIAL-123456"

    redacted = redact_untrusted_error_message(RuntimeError(f"token=KNOWN_TOKEN_123 rejected {leaked_secret}"))

    assert redacted == REDACTED_EVIDENCE_VALUE
    assert leaked_secret not in redacted
