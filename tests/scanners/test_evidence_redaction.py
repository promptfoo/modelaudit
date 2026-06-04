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


def test_redacts_signed_url_queries_and_capability_path_tokens() -> None:
    """Stored evidence should use the bounded network URL path policy."""
    path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"
    text = f"https://storage.googleapis.com/model-bucket/{path_token}/weights.bin?X-Goog-Signature=QUERYSECRET"

    redacted = redact_evidence_string(text, max_chars=None)

    assert path_token not in redacted
    assert "QUERYSECRET" not in redacted
    assert "model-bucket/<redacted>/weights.bin" in redacted
    assert "X-Goog-Signature=<redacted>" in redacted


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


def test_redacts_credentials_across_extended_network_url_schemes() -> None:
    """All URL schemes recognized by network scanners should sanitize evidence."""
    path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"
    text = (
        f"ftps://user:FTPSPASSWORD@files.example/{path_token}/model.so "
        f"ssh://SSHTOKEN@host.example/{path_token}/model.so "
        f"telnet://TELNETTOKEN@host.example/{path_token}/model.so "
        f"az://AZTOKEN@account.example/{path_token}/model.so "
        f"wasbs://container@account.blob.core.windows.net/{path_token}/model.so "
        f"abfss://container@account.dfs.core.windows.net/{path_token}/model.so "
        f"gcs://model-bucket/{path_token}/model.so "
        f"r2://model-bucket/{path_token}/model.so "
        f"custom+transport://host.example/{path_token}/model.so"
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "FTPSPASSWORD" not in redacted
    assert "SSHTOKEN" not in redacted
    assert "TELNETTOKEN" not in redacted
    assert "AZTOKEN" not in redacted
    assert path_token not in redacted
    assert redacted.count("<credentials-redacted>@") == 6


def test_redacts_legacy_signed_url_access_identifiers() -> None:
    """Legacy AWS and Google signed URL identifiers should not persist."""
    text = (
        "https://storage.example/model.so?"
        "AWSAccessKeyId=AKIAEXAMPLEACCESSKEY&Signature=AWSSECRET&"
        "GoogleAccessId=service-account%40example.iam.gserviceaccount.com"
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "AKIAEXAMPLEACCESSKEY" not in redacted
    assert "AWSSECRET" not in redacted
    assert "service-account" not in redacted
    assert "AWSAccessKeyId=<redacted>" in redacted
    assert "Signature=<redacted>" in redacted
    assert "GoogleAccessId=<redacted>" in redacted


def test_redacts_legacy_access_identifier_assignments() -> None:
    """Legacy access identifiers should also be sanitized outside URLs."""
    text = "AWSAccessKeyId=AKIAEXAMPLEACCESSKEY google_access_id=service-account@example.iam.gserviceaccount.com"

    redacted = redact_evidence_string(text, max_chars=None)

    assert "AKIAEXAMPLEACCESSKEY" not in redacted
    assert "service-account" not in redacted
    assert "AWSAccessKeyId=<redacted>" in redacted
    assert "google_access_id=<redacted>" in redacted


def test_existing_token_assignment_redaction_still_applies() -> None:
    """Canonical token assignments should keep their existing redaction behavior."""
    redacted = redact_evidence_string("token=CANONICALTOKEN123", max_chars=500)

    assert "CANONICALTOKEN123" not in redacted
    assert redacted == f"token={REDACTED_EVIDENCE_VALUE}"
