import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest

from modelaudit.cli import _format_scan_output
from modelaudit.integrations.sarif_formatter import format_sarif_output
from modelaudit.integrations.source_redaction import (
    redact_prevalidated_source_value,
    redact_source_identifier,
    redact_source_reference,
    redact_source_text,
    redact_source_value,
)
from modelaudit.models import AssetModel, FileMetadataModel, LicenseInfoModel, create_initial_audit_result
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


@pytest.mark.parametrize(
    ("raw_path", "safe_path", "secret"),
    [
        (r"C:\models\token=windows-secret\model.pkl", "<source redacted>", "windows-secret"),
        (r"\\host\share\password=unc-secret\model.pkl", "<source redacted>", "unc-secret"),
        ("file:///tmp/model.pkl%3Ftoken%3Dfile-secret", "file:///tmp/model.pkl", "file-secret"),
        ("file:///tmp/model.pkl%253Ftoken%253Ddouble-secret", "file:///tmp/model.pkl", "double-secret"),
        ("file://api-key%40host/tmp/model.pkl", "file://host/tmp/model.pkl", "api-key"),
        (
            "api-key@bucket.example/model.pkl?token=query-secret",
            "bucket.example/model.pkl",
            "api-key",
        ),
        ("https:/single-key@bucket.example/model.pkl", "https://bucket.example/model.pkl", "single-key"),
        ("model.pkl;OPAQUE-SECRET", "model.pkl", "OPAQUE-SECRET"),
        ("https://host/model.pkl%3BOPAQUE-SECRET", "https://host/model.pkl", "OPAQUE-SECRET"),
        ("bucket/model.pkl%253BOPAQUE-SECRET", "bucket/model.pkl", "OPAQUE-SECRET"),
        (r"bucket/model.pkl\u003btoken\u003descaped-secret", "bucket/model.pkl", "escaped-secret"),
    ],
)
def test_edge_credentials_are_redacted_across_export_sinks(
    raw_path: str,
    safe_path: str,
    secret: str,
) -> None:
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

    sarif_output = format_sarif_output(result, [raw_path])
    json_output = _format_scan_output(result, [raw_path], output_format="json", verbose=True)
    text_output = _format_scan_output(result, [raw_path], output_format="text", verbose=True)

    assert json.loads(sarif_output)["runs"][0]["invocations"][0]["arguments"] == [safe_path]
    for output in (sarif_output, json_output, text_output):
        assert secret not in output


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
    "local_path",
    [
        r"C:\models\sessionTokenCache=public\model.pkl",
        r"\\host\share\password_policy=public\model.pkl",
    ],
)
def test_nonexistent_windows_and_unc_near_matches_are_preserved(local_path: str) -> None:
    assert redact_source_identifier(local_path) == local_path


def test_existing_windows_assignment_filename_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    local_path = r"C:\models\token=literal-filename\model.pkl"
    monkeypatch.setattr(
        "modelaudit.integrations.source_redaction._local_path_exists",
        lambda source: source == local_path,
    )

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


@pytest.mark.parametrize(
    "local_path",
    [
        "./api-key@bucket.example/model.pkl?token=secret",
        r"C:\models\user:password@bucket.example\model.pkl?token=secret",
    ],
)
def test_nonexistent_local_userinfo_with_credential_suffix_fails_closed(local_path: str) -> None:
    assert redact_source_identifier(local_path) == "<source redacted>"
    redacted_text = redact_source_text(local_path)
    assert "<source redacted>" in redacted_text
    assert "api-key" not in redacted_text
    assert "password" not in redacted_text
    assert "secret" not in redacted_text


@pytest.mark.parametrize(
    "source",
    [
        "file:///tmp/model%3Fv1.pkl",
        "file:///tmp/model.pkl%3Fversion%3D1",
        "user@example.com",
    ],
)
def test_encoded_file_names_and_email_near_matches_are_preserved(source: str) -> None:
    assert redact_source_identifier(source) == source


@pytest.mark.parametrize(
    "source",
    [
        "file://host/tmp/model.pkl",
        "model.pkl;version=v1",
        "bucket/model.pkl;version=v1",
    ],
)
def test_authority_and_semicolon_near_matches_are_preserved(source: str) -> None:
    assert redact_source_identifier(source) == source
    assert redact_source_text(f"source {source}") == f"source {source}"


def test_percent_encoded_at_in_file_path_is_not_treated_as_authority() -> None:
    source = "file:///tmp/api-key%40host/model.pkl"

    assert redact_source_identifier(source) == source


def test_unclassifiable_mapping_keys_fail_closed() -> None:
    result = create_initial_audit_result()
    result.issues = [
        Issue(
            message="Unsafe metadata",
            severity=IssueSeverity.WARNING,
            details={
                "nested": {
                    b"token\xff": "RAW-SECRET",
                    ("token",): "TUPLE-SECRET",
                    Path("bucket/model.pkl?token=PATH-KEY-SECRET"): "PATH-VALUE-SECRET",
                }
            },
            timestamp=time.time(),
        )
    ]
    result.finalize_statistics()

    output = format_sarif_output(result, ["/test/model.pkl"])

    assert "RAW-SECRET" not in output
    assert "TUPLE-SECRET" not in output
    assert "PATH-KEY-SECRET" not in output
    assert "PATH-VALUE-SECRET" not in output
    assert "bucket/model.pkl" in output


def test_recursive_export_values_fail_closed() -> None:
    recursive: dict[str, object] = {}
    recursive["nested"] = recursive

    assert redact_source_value(recursive) == {"nested": "<redacted recursive value>"}


def test_redact_source_value_preserves_colliding_mapping_entries() -> None:
    first_url = "https://example.com/model.pkl?token=first-secret"
    second_url = "https://example.com/model.pkl?token=second-secret"

    redacted = redact_source_value(
        {
            first_url: {"finding": "first"},
            second_url: {"finding": "second"},
        }
    )

    assert isinstance(redacted, dict)
    assert list(redacted.values()) == [{"finding": "first"}, {"finding": "second"}]
    assert list(redacted) == [
        "https://example.com/model.pkl",
        "https://example.com/model.pkl#modelaudit-redacted-key-2",
    ]
    assert "first-secret" not in repr(redacted)
    assert "second-secret" not in repr(redacted)


def test_redact_source_value_scales_for_many_colliding_mapping_keys() -> None:
    values = {f"https://example.com/model.pkl?token=secret-{index}": index for index in range(1000)}

    redacted = redact_source_value(values)

    assert isinstance(redacted, dict)
    assert len(redacted) == 1000
    assert redacted["https://example.com/model.pkl"] == 0
    assert redacted["https://example.com/model.pkl#modelaudit-redacted-key-1000"] == 999


def test_direct_sensitive_assignment_mapping_keys_redact_associated_values() -> None:
    source_key = "https://example.com/model.pkl?token=source-secret"

    redacted = redact_source_value(
        {
            "token=attacker-label": "RAW-SECRET",
            "Authorization%253A%2520Bearer%2520label": "HEADER-SECRET",
            source_key: {"finding": "preserved"},
        }
    )

    assert isinstance(redacted, dict)
    assert list(redacted.values()) == ["<redacted>", "<redacted>", {"finding": "preserved"}]
    assert source_key not in redacted
    assert "RAW-SECRET" not in repr(redacted)
    assert "HEADER-SECRET" not in repr(redacted)


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


@pytest.mark.parametrize("key", ["GoogleAccessId", "google_access_id", "pwd", "jwt", "passphrase"])
def test_common_export_credential_aliases_are_redacted(key: str) -> None:
    secret = "EXPORT-SECRET-123"

    assert secret not in redact_source_text(f"{key}={secret}; visible=yes")
    assert redact_source_value({key: secret}) == {key: "<redacted>"}
    assert secret not in redact_source_identifier(f"https://example.com/{key}={secret}/model.pkl")


@pytest.mark.parametrize(
    "text",
    [
        'payload={"token":"EXPORT-SECRET-123"}',
        "token[]=EXPORT-SECRET-123",
        "headers[token]=EXPORT-SECRET-123",
        'headers["token"]=EXPORT-SECRET-123',
        'headers[ "token" ]=EXPORT-SECRET-123',
        "headers[ token]=EXPORT-SECRET-123",
        "headers[token ]=EXPORT-SECRET-123",
        r'payload={"\u0074oken":"EXPORT-SECRET-123"}',
        r'payload={"to\u006ben":"EXPORT-SECRET-123"}',
        '"token"=EXPORT-SECRET-123',
        r"payload={\"token\":\"EXPORT-SECRET-123\"}",
        "Authorization Bearer EXPORT-SECRET-123",
        "Authorization Digest EXPORT-SECRET-123",
        "Authorization ApiKey EXPORT-SECRET-123",
        "Authorization DPoP EXPORT-SECRET-123",
        "Authorization Hawk EXPORT-SECRET-123",
        "Proxy-Authorization NTLM EXPORT-SECRET-123",
        "Proxy-Authorization ApiKey EXPORT-SECRET-123",
        "--token EXPORT-SECRET-123 --verbose",
        "token <- EXPORT-SECRET-123; visible=yes",
    ],
)
def test_serialized_and_argument_credentials_are_redacted(text: str) -> None:
    redacted = redact_source_text(text)

    assert "EXPORT-SECRET-123" not in redacted


def test_redact_source_text_handles_dense_credential_assignments() -> None:
    text = "token=EXPORT-SECRET-123;" * 5_000

    redacted = redact_source_text(text)

    assert "EXPORT-SECRET-123" not in redacted
    assert redacted.count("<redacted>") == 5_000


@pytest.mark.parametrize("operator", ["!=", ">=", "<="])
def test_sensitive_key_ordering_comparisons_are_not_treated_as_assignments(operator: str) -> None:
    text = f'config={{"client_secret" {operator} "public": "os.system(15)"}}'

    assert redact_source_text(text) == text


def test_sensitive_key_equality_comparisons_redact_value_and_preserve_context() -> None:
    text = 'config={"client_secret" == "public": "os.system(15)"}'

    redacted = redact_source_text(text)

    assert redacted == 'config={"client_secret" == <redacted>: "os.system(15)"}'


@pytest.mark.parametrize(
    "text",
    [
        'client_secret == "RAW-COMPARISON-SECRET-123456"',
        "token==RAW-COMPARISON-SECRET-123456; visible=yes",
    ],
)
def test_sensitive_key_comparison_values_are_redacted_in_generic_exports(text: str) -> None:
    for redacted in (redact_source_text(text), redact_source_value(text)):
        assert "RAW-COMPARISON-SECRET-123456" not in redacted
        assert "<redacted>" in redacted


def test_benign_comparisons_are_preserved_in_generic_exports() -> None:
    text = "status == 200 and count == 5"

    assert redact_source_text(text) == text


def test_comparison_marker_tail_is_redacted_in_generic_exports() -> None:
    text = 'client_secret == <redacted> + "RAW-MARKER-TAIL-SECRET-123456"'

    redacted = redact_source_text(text)

    assert "RAW-MARKER-TAIL-SECRET-123456" not in redacted
    assert redacted == "client_secret == <redacted>"


def test_exactly_redacted_comparison_value_is_preserved() -> None:
    text = "client_secret == <redacted>"

    assert redact_source_text(text) == text


def test_reversed_literal_key_comparison_redacts_value_in_generic_exports() -> None:
    text = '"OPAQUE-VALUE-CRED-123456" == "client_secret"; os.system("id")'

    redacted = redact_source_text(text)

    assert "OPAQUE-VALUE-CRED-123456" not in redacted
    assert '<redacted> == "client_secret"' in redacted
    assert 'os.system("id")' in redacted


@pytest.mark.parametrize(
    "text",
    [
        'label == "client_secret"; os.system("id")',
        '"OPAQUE-VALUE" == "tokenizer"',
    ],
)
def test_reversed_comparison_near_matches_are_preserved_in_generic_exports(text: str) -> None:
    assert redact_source_text(text) == text


def test_prevalidated_comparison_command_operands_are_preserved() -> None:
    text = 'client_secret == os.system("id")'

    assert redact_prevalidated_source_value(text) == text


def test_preserved_redacted_assignment_does_not_exempt_neighboring_secret() -> None:
    text = 'client_secret=os.system("curl -u alice:<redacted>"); token=RAW-NEIGHBOR-SECRET'

    redacted = redact_prevalidated_source_value(text)

    assert 'client_secret=os.system("curl -u alice:<redacted>")' in redacted
    assert "RAW-NEIGHBOR-SECRET" not in redacted


def test_preserved_marker_for_later_assignment_does_not_exempt_earlier_secret() -> None:
    text = "log session=RAW-SESSION-SECRET-123456 password=<redacted> done"

    redacted = redact_prevalidated_source_value(text)

    assert "RAW-SESSION-SECRET-123456" not in redacted
    assert "password=<redacted>" in redacted


def test_catboost_sarif_revalidates_attacker_supplied_redaction_marker() -> None:
    attacker_tail = "ATTACKER-MARKER-RAW-SECRET-123456"
    result = create_initial_audit_result()
    result.issues = [
        Issue(
            message="Suspicious command execution primitives detected",
            severity=IssueSeverity.CRITICAL,
            details={
                "matches": [
                    {
                        "excerpt": (
                            f'client_secret=os.system("<redacted> {attacker_tail}"); token=NEIGHBOR-RAW-SECRET-123456'
                        ),
                    }
                ],
                "set_evidence": {f'client_secret=os.system("<redacted> {attacker_tail}-SET")'},
                "binary_evidence": f"token={attacker_tail}-BYTES".encode(),
            },
            type="catboost_check",
            timestamp=time.time(),
        )
    ]
    result.finalize_statistics()

    output = format_sarif_output(result, ["/test/model.cbm"])

    assert attacker_tail not in output
    assert "NEIGHBOR-RAW-SECRET-123456" not in output
    assert "client_secret=os.system(<redacted>)" in output


@pytest.mark.parametrize(
    ("excerpt", "secrets"),
    [
        (
            'client_secret == "DIRECT-COMPARISON-SECRET-123456"; os.system("id")',
            ("DIRECT-COMPARISON-SECRET-123456",),
        ),
        (
            'client_secret === "STRICT-COMPARISON-SECRET-123456"; os.system("id")',
            ("STRICT-COMPARISON-SECRET-123456",),
        ),
        (
            '"REVERSED-COMPARISON-SECRET-123456" == client_secret; os.system("id")',
            ("REVERSED-COMPARISON-SECRET-123456",),
        ),
        (
            '"LOW-COMPARISON-SECRET-123456" < client_secret < "HIGH-COMPARISON-SECRET-123456"; os.system("id")',
            ("LOW-COMPARISON-SECRET-123456", "HIGH-COMPARISON-SECRET-123456"),
        ),
        (
            'client_secret == ("PART-A-SECRET" + "CONCAT-COMPARISON-SECRET-123456"); os.system("id")',
            ("PART-A-SECRET", "CONCAT-COMPARISON-SECRET-123456"),
        ),
        (
            'client_secret == lookup("CALL-COMPARISON-SECRET-123456") if enabled '
            'else "FALLBACK-COMPARISON-SECRET-123456"; os.system("id")',
            ("CALL-COMPARISON-SECRET-123456", "FALLBACK-COMPARISON-SECRET-123456"),
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
    ],
)
def test_catboost_sarif_redacts_sensitive_comparison_statements(
    excerpt: str,
    secrets: tuple[str, ...],
) -> None:
    result = create_initial_audit_result()
    result.issues = [
        Issue(
            message="Suspicious command execution primitives detected",
            severity=IssueSeverity.CRITICAL,
            details={"matches": [{"excerpt": excerpt}]},
            type="catboost_check",
            timestamp=time.time(),
        )
    ]
    result.finalize_statistics()

    output = format_sarif_output(result, ["/test/model.cbm"])
    properties = json.loads(output)["runs"][0]["results"][0]["properties"]
    redacted_excerpt = properties["matches"][0]["excerpt"]

    assert all(secret not in output for secret in secrets)
    assert 'os.system("id")' in redacted_excerpt


def test_catboost_sarif_preserves_sensitive_comparison_command_operand() -> None:
    result = create_initial_audit_result()
    result.issues = [
        Issue(
            message="Suspicious command execution primitives detected",
            severity=IssueSeverity.CRITICAL,
            details={"matches": [{"excerpt": 'client_secret == os.system("id")'}]},
            type="catboost_check",
            timestamp=time.time(),
        )
    ]
    result.finalize_statistics()

    output = format_sarif_output(result, ["/test/model.cbm"])
    properties = json.loads(output)["runs"][0]["results"][0]["properties"]

    assert 'os.system("id")' in properties["matches"][0]["excerpt"]


@pytest.mark.parametrize(
    "text",
    [
        "https://host/model,Authorization: Bearer URL-ADJACENT-SECRET",
        "https://host/model;password: URL-ADJACENT-SECRET",
        "metadata token%3DENCODED-SECRET visible=yes",
        "metadata token%253DDOUBLE-ENCODED-SECRET",
        "Authorization%3A%20Bearer%20ENCODED-HEADER-SECRET",
        r"password\u003aESCAPED-SECRET",
        '{"token":"QUOTED-SECRET"}',
        '{"Authorization":"Bearer QUOTED-HEADER-SECRET"}',
        "token%3DCHAINED-SECRET%26visible%3Dyes",
        "token%253DDOUBLE-CHAINED-SECRET%2526visible%253Dyes",
        "Authorization%3A%20Bearer%20HEADER-SECRET%3Btoken%3DSECOND-SECRET",
    ],
)
def test_encoded_quoted_and_url_adjacent_assignments_are_redacted(text: str) -> None:
    redacted = redact_source_text(text)

    assert "SECRET" not in redacted
    assert "<redacted>" in redacted


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('--token "EXPORT SECRET 123" --verbose', "--token <redacted> --verbose"),
        ('Authorization Bearer "EXPORT SECRET 123" tail', "Authorization Bearer <redacted> tail"),
        ("payload=[token=EXPORT-SECRET-123] tail", "payload=[token=<redacted>] tail"),
        ("--token=EXPORT-SECRET-123 --verbose", "--token=<redacted> --verbose"),
        ("token: |\n  EXPORT-SECRET-123\nnext=safe", "token: <redacted>\nnext=safe"),
        ("token: >\n  EXPORT SECRET 123\nnext=safe", "token: <redacted>\nnext=safe"),
    ],
)
def test_credential_redaction_preserves_surrounding_context(text: str, expected: str) -> None:
    assert redact_source_text(text) == expected


def test_oversized_export_text_fails_closed() -> None:
    assert redact_source_text("a" * (256 * 1024 + 1)) == "<redacted oversized value>"


@pytest.mark.parametrize(
    "text",
    [
        "request_signature_algorithm=rsa",
        "authorization_method=oauth2",
        "Authorization method oauth2",
        "Authorization status disabled",
        "password_policy=strong",
        "my_secret_ingredient=salt",
        "token_count=42",
        "token_type_ids=[1, 2]",
        "signature_algorithm=rsa",
    ],
)
def test_export_credential_near_matches_are_preserved(text: str) -> None:
    assert redact_source_text(text) == text


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("bucket/user:EXPORT-SECRET-123@host/model.pkl", "bucket/host/model.pkl"),
        ("bucket/user%3AEXPORT-SECRET-123%40host/model.pkl", "bucket/host/model.pkl"),
        ("bucket/user%253AEXPORT-SECRET-123%2540host/model.pkl", "bucket/host/model.pkl"),
        ("///user:EXPORT-SECRET-123@host/model.pkl", "<source redacted>"),
        ("stream://jdbc:postgresql://user:EXPORT-SECRET-123@host/db", "stream://jdbc:postgresql://host/db"),
    ],
)
def test_nested_userinfo_is_redacted_from_direct_identifiers(source: str, expected: str) -> None:
    assert redact_source_identifier(source) == expected


def test_malformed_url_authority_fails_closed() -> None:
    source = "https://user:EXPORT-SECRET-123@[broken/model.pkl"

    assert redact_source_identifier(source) == "<cloud URL redacted>"
    assert redact_source_reference(source) == "<cloud URL redacted>"


@pytest.mark.parametrize(
    "source",
    [
        "model.pkl?branch=main",
        "file:///tmp/model.pkl?tag=v1",
        "model.pkl#tag=v1",
    ],
)
def test_safe_source_reference_provenance_is_not_duplicated(source: str) -> None:
    assert redact_source_reference(source) == source


@pytest.mark.parametrize(
    "text",
    [
        "token_count=128",
        "signature_algorithm=RSA",
        "auth_method=oauth",
        "session_duration=10",
        "password_length=12",
        "version%3D1",
        "tokenizer%3Dpublic",
    ],
)
def test_benign_metric_and_encoded_near_matches_are_preserved(text: str) -> None:
    assert redact_source_text(text) == text


def test_escaped_quote_does_not_end_credential_redaction_early() -> None:
    redacted = redact_source_text('refreshToken="abc\\"quoted-secret"; visible=yes')

    assert "quoted-secret" not in redacted
    assert "visible=yes" in redacted


def test_redacted_url_path_assignment_preserves_safe_path_and_query() -> None:
    raw_url = "https://example.com/token%253Dpath-secret/model.pkl?visible=yes"

    assert redact_source_text(raw_url) == "https://example.com/token=<redacted>/model.pkl?visible=yes"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "https://example.com/token:URL-SECRET/model.pkl",
            "https://example.com/token=<redacted>/model.pkl",
        ),
        (
            "https://example.com/sessionToken%253AURL-SECRET/model.pkl",
            "https://example.com/sessionToken=<redacted>/model.pkl",
        ),
        ("bucket/token:PATH-SECRET/model.pkl", "<source redacted>"),
        ("/tmp/token:PATH-SECRET/model.pkl", "<source redacted>"),
        (r"C:\models\token:PATH-SECRET\model.pkl", "<source redacted>"),
    ],
)
def test_colon_path_credentials_are_redacted(source: str, expected: str) -> None:
    assert redact_source_identifier(source) == expected


@pytest.mark.parametrize(
    "source",
    [
        "https://example.com/version:1/model.pkl",
        "bucket/version:1/model.pkl",
        "/tmp/version:1/model.pkl",
        r"C:\models\version:1\model.pkl",
    ],
)
def test_benign_colon_path_segments_are_preserved(source: str) -> None:
    assert redact_source_identifier(source) == source


def test_nonexistent_local_suffix_is_redacted_but_literal_filename_is_preserved(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.pkl?token=source-secret"
    literal_path = tmp_path / "literal.pkl?token=filename-text"
    literal_path.write_bytes(b"model")

    assert redact_source_identifier(str(missing_path)) == str(tmp_path / "missing.pkl")
    assert redact_source_identifier(str(literal_path)) == str(literal_path)
    assert redact_source_identifier("./missing.pkl%3Ftoken%3Dsource-secret") == "./missing.pkl"


@pytest.mark.parametrize(
    "raw_path",
    [
        "./user:password@bucket.example/model.pkl",
        "./bucket/token=path-secret/model.pkl?revision=v1",
        "./bucket/token%3Dpath-secret/model.pkl?revision=v1",
    ],
)
def test_nonexistent_posix_local_credential_prefixes_fail_closed(raw_path: str) -> None:
    assert redact_source_identifier(raw_path) == "<source redacted>"


@pytest.mark.parametrize(
    "local_path",
    [
        "/tmp/build@2026/model.pkl",
        "./artifacts/user@example.com/model.pkl",
        "./artifacts/user@example.com/model.pkl?version=1",
    ],
)
def test_nonexistent_posix_at_paths_are_preserved(local_path: str) -> None:
    assert redact_source_identifier(local_path) == local_path
    assert redact_source_text(f"source {local_path}") == f"source {local_path}"


@pytest.mark.parametrize(
    ("raw_path", "safe_path"),
    [
        ("/bucket/model.pkl;token=source-secret", "/bucket/model.pkl"),
        ("./bucket/model.pkl%3Btoken%3Dsource-secret", "./bucket/model.pkl"),
    ],
)
def test_nonexistent_local_semicolon_credentials_are_redacted(raw_path: str, safe_path: str) -> None:
    assert redact_source_identifier(raw_path) == safe_path


def test_existing_local_credential_shaped_filename_is_preserved(tmp_path: Path) -> None:
    literal_path = tmp_path / "model.pkl;token=filename-text"
    literal_path.write_bytes(b"model")

    assert redact_source_identifier(str(literal_path)) == str(literal_path)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("model.pkl?OPAQUE-SECRET", "model.pkl"),
        ("model.pkl%3FOPAQUE-SECRET", "model.pkl"),
        ("model.pkl;OPAQUE-SECRET", "model.pkl"),
        ("bucket/model.pkl;OPAQUE-SECRET", "bucket/model.pkl"),
        (r"bucket/model.pkl\u003btoken\u003descaped-secret", "bucket/model.pkl"),
        ("source //bucket.example/model.pkl?OPAQUE-SECRET", "source //bucket.example/model.pkl"),
        ("model.pkl?version=1", "model.pkl?version=1"),
        ("model.pkl%3Fversion%3D1", "model.pkl%3Fversion%3D1"),
        ("./bucket/model.pkl;version=1", "./bucket/model.pkl;version=1"),
        ("release 1.2.3? maybe", "release 1.2.3? maybe"),
        ("email user@example.com?subject=safe", "email user@example.com?subject=safe"),
        ("email user@example.com?token=secret", "email user@example.com"),
    ],
)
def test_bare_and_protocol_relative_opaque_source_text_redaction(text: str, expected: str) -> None:
    assert redact_source_text(text) == expected


def test_format_scan_output_serializes_pydantic_urls_and_preserves_text_findings() -> None:
    generated_at = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    scan_id = UUID("12345678-1234-5678-1234-567812345678")
    result = create_initial_audit_result()
    result.issues = [
        Issue(
            message="Critical finding",
            severity=IssueSeverity.CRITICAL,
            timestamp=time.time(),
            details={
                "binary": b"\xff",
                "generated_at": generated_at,
                "local_path": Path("models/model.pkl"),
                "scan_id": scan_id,
            },
        )
    ]
    result.file_metadata = {
        "model.pkl": FileMetadataModel(
            license_info=[
                LicenseInfoModel(
                    spdx_id="MIT",
                    name="MIT",
                    url="https://example.com/license",
                )
            ]
        )
    }
    result.finalize_statistics()

    json_output = _format_scan_output(result, ["model.pkl"], output_format="json", verbose=True)
    payload = json.loads(json_output)
    assert payload["file_metadata"]["model.pkl"]["license_info"][0]["url"] == "https://example.com/license"
    assert payload["issues"][0]["details"] == {
        "binary": "<binary data>",
        "generated_at": "2026-01-02T03:04:05Z",
        "local_path": "models/model.pkl",
        "scan_id": "12345678-1234-5678-1234-567812345678",
    }

    text_output = _format_scan_output(result, ["model.pkl"], output_format="text", verbose=True)
    assert "Critical Issues" in text_output
    assert "Critical finding" in text_output
