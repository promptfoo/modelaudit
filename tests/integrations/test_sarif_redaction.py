import json
import os
import time
from pathlib import Path

import pytest

from modelaudit.integrations.sarif_formatter import format_sarif_output
from modelaudit.integrations.source_redaction import (
    redact_source_identifier,
    redact_source_text,
    redact_source_value,
)
from modelaudit.models import AssetModel, create_initial_audit_result
from modelaudit.scanners.base import Issue, IssueSeverity


def test_signed_asset_url_paths_are_redacted() -> None:
    raw_path = (
        "https://bucket.s3.amazonaws.com/model.pkl?"
        "X-Amz-Credential=AKIASECRET&X-Amz-Signature=deadbeef&token=secret-token"
    )
    safe_path = "https://bucket.s3.amazonaws.com/model.pkl"
    result = create_initial_audit_result()
    result.assets = [AssetModel(path=raw_path, type="pickle")]
    result.issues = [
        Issue(
            message=f"Unsafe model from {raw_path}",
            severity=IssueSeverity.WARNING,
            location=raw_path,
            details={"source_url": raw_path},
            timestamp=time.time(),
        )
    ]
    result.finalize_statistics()

    output = format_sarif_output(result, [raw_path])
    parsed = json.loads(output)
    run = parsed["runs"][0]

    assert raw_path not in output
    assert safe_path in output
    for leaked in ("AKIASECRET", "deadbeef", "secret-token", "X-Amz-Signature"):
        assert leaked not in output
    assert run["invocations"][0]["arguments"] == [safe_path]


@pytest.mark.parametrize(
    ("raw_path", "safe_path"),
    [
        ("//user:password@bucket.example/model.pkl?token=secret", "//bucket.example/model.pkl"),
        ("https:/user:password@bucket.example/model.pkl?token=secret", "https://bucket.example/model.pkl"),
        ("user%3Apassword%40bucket.example/model.pkl?token=secret", "bucket.example/model.pkl"),
        ("bucket.example/model.pkl?OPAQUE-SECRET", "bucket.example/model.pkl"),
        ("bucket.example/model.pkl%3FOPAQUE-SECRET", "bucket.example/model.pkl"),
        ("bucket.example/model.pkl%253FOPAQUE-SECRET", "bucket.example/model.pkl"),
        ("bucket.example/model.pkl%23OPAQUE-SECRET", "bucket.example/model.pkl"),
        ("bucket.example/token=PATH-SECRET?visible=yes", "<source redacted>"),
        ("bucket.example/token%3DPATH-SECRET?visible=yes", "<source redacted>"),
        (
            "https://bucket.example/token=PATH-SECRET/model.pkl?token=query-secret",
            "https://bucket.example/token=<redacted>/model.pkl",
        ),
        (
            "https://bucket.example/token%253DPATH-SECRET/model.pkl?token=query-secret",
            "https://bucket.example/token=<redacted>/model.pkl",
        ),
    ],
)
def test_noncanonical_source_credentials_are_redacted(raw_path: str, safe_path: str) -> None:
    result = create_initial_audit_result()
    result.assets = [AssetModel(path=raw_path, type="pickle")]
    result.issues = [
        Issue(
            message=f"Unsafe model from {raw_path}",
            severity=IssueSeverity.WARNING,
            location=raw_path,
            details={"source_url": raw_path},
            timestamp=time.time(),
        )
    ]
    result.finalize_statistics()

    output = format_sarif_output(result, [raw_path])
    invocation = json.loads(output)["runs"][0]["invocations"][0]

    assert invocation["arguments"] == [safe_path]
    for leaked in (
        "user:password",
        "user%3Apassword",
        "token=secret",
        "query-secret",
        "PATH-SECRET",
        "OPAQUE-SECRET",
    ):
        assert leaked not in output


def test_noncanonical_userinfo_rotation_preserves_fingerprint() -> None:
    def fingerprint(password: str) -> str:
        raw_path = f"//user:{password}@bucket.example/model.pkl?token=secret"
        result = create_initial_audit_result()
        result.issues = [
            Issue(
                message=f"Unsafe model from {raw_path}",
                severity=IssueSeverity.WARNING,
                location=raw_path,
                timestamp=time.time(),
            )
        ]
        result.finalize_statistics()
        output = json.loads(format_sarif_output(result, [raw_path]))
        return str(output["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"])

    assert fingerprint("first-password") == fingerprint("rotated-password")


def test_existing_local_assignment_paths_are_preserved(tmp_path: Path) -> None:
    first_path = tmp_path / "session=training" / "model.pkl"
    second_path = tmp_path / "session=evaluation" / "model.pkl"
    first_path.parent.mkdir()
    second_path.parent.mkdir()
    first_path.write_bytes(b"first")
    second_path.write_bytes(b"second")
    encoded_name_path = tmp_path / "model%3Fv1.pkl"
    encoded_name_path.write_bytes(b"encoded name")
    query_name_path = tmp_path / "model?version=1.pkl"
    query_name_path.write_bytes(b"query name")
    parameter_name_path = tmp_path / "model;version=1.pkl"
    parameter_name_path.write_bytes(b"parameter name")

    assert redact_source_identifier(str(first_path)) == str(first_path)
    assert redact_source_identifier(str(second_path)) == str(second_path)
    assert redact_source_identifier(str(encoded_name_path)) == str(encoded_name_path)
    assert redact_source_identifier(str(query_name_path)) == str(query_name_path)
    assert redact_source_identifier(str(parameter_name_path)) == str(parameter_name_path)
    if os.name != "nt":
        double_slash_path = f"/{query_name_path}"
        assert os.path.lexists(double_slash_path)
        assert redact_source_identifier(double_slash_path) == double_slash_path

    def fingerprint(path: Path) -> str:
        result = create_initial_audit_result()
        result.issues = [
            Issue(
                message="Unsafe local model",
                severity=IssueSeverity.WARNING,
                location=str(path),
                timestamp=time.time(),
            )
        ]
        result.finalize_statistics()
        output = json.loads(format_sarif_output(result, [str(path)]))
        assert output["runs"][0]["invocations"][0]["arguments"] == [str(path)]
        return str(output["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"])

    assert fingerprint(first_path) != fingerprint(second_path)


@pytest.mark.parametrize(
    "local_path",
    [
        r"C:\users\user:password@folder\model.pkl",
        r"\\server\share\user:password@folder\model.pkl",
    ],
)
def test_windows_and_unc_local_paths_are_preserved(local_path: str) -> None:
    assert redact_source_identifier(local_path) == local_path


@pytest.mark.parametrize(
    ("local_path", "safe_path"),
    [
        (r"C:\models\model.pkl?token=windows-secret", r"C:\models\model.pkl"),
        (r"\\server\share\model.pkl?token=unc-secret", r"\\server\share\model.pkl"),
    ],
)
def test_nonexistent_windows_and_unc_credential_suffixes_are_redacted(local_path: str, safe_path: str) -> None:
    assert redact_source_identifier(local_path) == safe_path


def test_unclassifiable_mapping_keys_fail_closed() -> None:
    result = create_initial_audit_result()
    result.issues = [
        Issue(
            message="Unsafe metadata",
            severity=IssueSeverity.WARNING,
            details={"nested": {b"token\xff": "RAW-SECRET", ("token",): "TUPLE-SECRET"}},
            timestamp=time.time(),
        )
    ]
    result.finalize_statistics()

    output = format_sarif_output(result, ["/test/model.pkl"])

    assert "RAW-SECRET" not in output
    assert "TUPLE-SECRET" not in output


def test_recursive_export_values_fail_closed() -> None:
    recursive: dict[str, object] = {}
    recursive["nested"] = recursive

    assert redact_source_value(recursive) == {"nested": "<redacted recursive value>"}


@pytest.mark.parametrize(
    "raw_path",
    [
        "token=scheme-less-secret?revision=v1",
        "sessionToken=scheme-less-secret?revision=v1",
        "session%54oken=scheme-less-secret?revision=v1",
        "bucket/token=path-secret/model.pkl?revision=v1",
        "bucket/token%3Dpath-secret/model.pkl?revision=v1",
        "Authorization: Bearer source-secret?revision=v1",
        "dbPassword: source-secret#tag=v1",
    ],
)
def test_safe_provenance_does_not_restore_sensitive_prefixes(raw_path: str) -> None:
    assert redact_source_identifier(raw_path) == "<source redacted>"


def test_export_alias_assignments_and_mapping_keys_are_redacted() -> None:
    result = create_initial_audit_result()
    result.issues = [
        Issue(
            message=(
                "sessionToken=Bearer message-secret; dbPassword: password-secret; "
                'refreshToken="abc,quoted-secret"; proxyAuthorization: "Bearer proxy-secret"; '
                "refreshToken=<redacted>marker-bypass-secret; Cookie: session=abc; csrf=cookie-secret\n"
                "sessionTokenCache=public-cache"
            ),
            severity=IssueSeverity.WARNING,
            details={
                "githubToken": "github-secret",
                b"token": "bytes-key-secret",
                "headers": {"Proxy-Authorization": "Bearer header-secret"},
            },
            timestamp=time.time(),
        )
    ]
    result.finalize_statistics()

    output = format_sarif_output(result, ["/test/model.pkl"])

    for secret in (
        "message-secret",
        "password-secret",
        "quoted-secret",
        "proxy-secret",
        "marker-bypass-secret",
        "cookie-secret",
        "github-secret",
        "bytes-key-secret",
        "header-secret",
    ):
        assert secret not in output
    assert "public-cache" in output


def test_escaped_quote_does_not_end_credential_redaction_early() -> None:
    redacted = redact_source_text('refreshToken="abc\\"quoted-secret"; visible=yes')

    assert "quoted-secret" not in redacted
    assert "visible=yes" in redacted


def test_redacted_url_path_assignment_preserves_safe_path_and_query() -> None:
    raw_url = "https://example.com/token%253Dpath-secret/model.pkl?visible=yes"

    assert redact_source_text(raw_url) == "https://example.com/token=<redacted>/model.pkl?visible=yes"


def test_nonexistent_local_suffix_is_redacted_but_literal_filename_is_preserved(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.pkl?token=source-secret"
    literal_path = tmp_path / "literal.pkl?token=filename-text"
    literal_path.write_bytes(b"model")

    assert redact_source_identifier(str(missing_path)) == str(tmp_path / "missing.pkl")
    assert redact_source_identifier(str(literal_path)) == str(literal_path)
    assert redact_source_identifier("./missing.pkl%3Ftoken%3Dsource-secret") == "./missing.pkl"
