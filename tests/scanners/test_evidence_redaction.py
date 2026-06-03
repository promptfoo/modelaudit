"""Tests for scanner evidence redaction helpers."""

import json

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


def test_redacts_sensitive_container_assignments() -> None:
    """Credential assignments should consume array and object values before redaction."""
    array_secret = "CONTAINER_ASSIGNMENT_ARRAY_SECRET"
    object_secret = "CONTAINER_ASSIGNMENT_OBJECT_SECRET"
    nested_secret = "CONTAINER_ASSIGNMENT_NESTED_SECRET"
    outer_secret = "CONTAINER_ASSIGNMENT_OUTER_SECRET"

    redacted_text = redact_evidence_string(
        (
            f'awsSecretAccessKey=["{array_secret}"] '
            f'token={{"nested":"{object_secret}"}} '
            f'api_key=[[],"{nested_secret}"] '
            f'metadata={{"api_key":["{outer_secret}"]}} '
            'safe=["visible"]'
        ),
        max_chars=500,
    )

    assert array_secret not in redacted_text
    assert object_secret not in redacted_text
    assert nested_secret not in redacted_text
    assert outer_secret not in redacted_text
    assert f"awsSecretAccessKey={REDACTED_EVIDENCE_VALUE}" in redacted_text
    assert f"token={REDACTED_EVIDENCE_VALUE}" in redacted_text
    assert f"api_key={REDACTED_EVIDENCE_VALUE}" in redacted_text
    assert f'"api_key":"{REDACTED_EVIDENCE_VALUE}"' in redacted_text
    assert 'safe=["visible"]' in redacted_text


def test_redacts_embedded_structured_credential_literals() -> None:
    """Structured credential containers should redact even when embedded in prose."""
    json_secret = "EMBEDDED_JSON_SECRET"
    repr_secret = "EMBEDDED_REPR_SECRET"

    redacted_text = redact_evidence_string(
        f"note {{\"api_key\":[\"{json_secret}\"]}} and repr {{'token':['{repr_secret}']}}",
        max_chars=500,
    )

    assert json_secret not in redacted_text
    assert repr_secret not in redacted_text
    assert f'"api_key":"{REDACTED_EVIDENCE_VALUE}"' in redacted_text
    assert f'"token":"{REDACTED_EVIDENCE_VALUE}"' in redacted_text


def test_redacts_repr_style_container_credential_values() -> None:
    """Python repr-style container strings should redact sensitive nested values."""
    array_secret = "REPR_ARRAY_SECRET"
    object_secret = "REPR_OBJECT_SECRET"
    tuple_key_secret = "REPR_TUPLE_KEY_SECRET"
    set_secret = "REPR_SET_SECRET"

    redacted_text = redact_evidence_string(
        (
            f"{{'api_key':['{array_secret}'],'token':{{'nested':'{object_secret}'}},"
            f"('api_key','{tuple_key_secret}'):'x','metadata':{{'token={set_secret}'}},'safe':['ok']}}"
        ),
        max_chars=500,
    )

    assert array_secret not in redacted_text
    assert object_secret not in redacted_text
    assert tuple_key_secret not in redacted_text
    assert set_secret not in redacted_text
    assert f'"api_key":"{REDACTED_EVIDENCE_VALUE}"' in redacted_text
    assert f'"token":"{REDACTED_EVIDENCE_VALUE}"' in redacted_text
    assert '"<tuple-key>":"x"' in redacted_text
    assert f'"metadata":["token={REDACTED_EVIDENCE_VALUE}"]' in redacted_text
    assert '"safe":["ok"]' in redacted_text


def test_redacts_oversized_and_deep_structured_evidence() -> None:
    """Oversized or deeply nested structured evidence should fail closed."""
    large_secret = "LARGE_STRUCTURED_SECRET"
    large_text = f'{{"api_key":["{large_secret}"],"pad":"{"x" * 11000}"}}'

    large_redacted = redact_evidence_string(large_text, max_chars=500)
    deep_redacted = redact_evidence_string("[" * 1200 + "]" * 1200, max_chars=500)

    assert large_secret not in large_redacted
    assert large_redacted == REDACTED_EVIDENCE_VALUE
    assert deep_redacted == REDACTED_EVIDENCE_VALUE
