from __future__ import annotations

import base64
import json
import struct
from pathlib import Path

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file, scan_model_streaming
from modelaudit.models import ModelAuditResultModel
from modelaudit.scanners import get_scanner_for_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, IssueSeverity, ScanResult
from modelaudit.scanners.mxnet_scanner import MXNetScanner


def _write_symbol_file(path: Path, custom_node: dict | None = None, metadata: str = "benign metadata") -> None:
    nodes = [
        {"op": "null", "name": "data", "inputs": []},
        {
            "op": "Convolution",
            "name": "conv1",
            "attrs": {"kernel": "(3,3)", "num_filter": "8"},
            "inputs": [[0, 0, 0]],
        },
    ]
    heads = [[1, 0, 0]]

    if custom_node:
        nodes.append(custom_node)
        heads = [[2, 0, 0]]

    symbol_graph = {
        "nodes": nodes,
        "arg_nodes": [0],
        "heads": heads,
        "attrs": {"metadata": metadata},
    }
    path.write_text(json.dumps(symbol_graph), encoding="utf-8")


def _write_params_file(path: Path, values: tuple[float, ...] | None = None) -> None:
    tensor_values = values or (0.0, 1.0, -2.5, 3.14, 8.0, -0.125)
    path.write_bytes(struct.pack(f"<{len(tensor_values)}f", *tensor_values))


def _assert_inconclusive_result(result: ScanResult, reason: str) -> None:
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert reason in result.metadata["scan_outcome_reasons"]
    assert result.metadata["analysis_incomplete"] is True


def _assert_aggregate_inconclusive(result: ModelAuditResultModel, path: Path, reason: str) -> None:
    metadata = result.file_metadata[str(path)]
    assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert reason in metadata["scan_outcome_reasons"]
    assert metadata["analysis_incomplete"] is True
    assert result.success is False
    assert determine_exit_code(result) == 2


def _assert_aggregate_inconclusive_not_cached(path: Path, reason: str, cache_dir: Path) -> None:
    reset_cache_manager()
    try:
        first_result = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second_result = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for result in (first_result, second_result):
            _assert_aggregate_inconclusive(result, path, reason)
            assert not [
                issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            ]

        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_mxnet_scanner_can_handle_symbol_and_params(tmp_path: Path) -> None:
    symbol_path = tmp_path / "model-symbol.json"
    params_path = tmp_path / "model-0000.params"
    _write_symbol_file(symbol_path)
    _write_params_file(params_path)

    assert MXNetScanner.can_handle(str(symbol_path))
    assert MXNetScanner.can_handle(str(params_path))


def test_mxnet_scanner_handles_renamed_structural_symbol_graph(tmp_path: Path) -> None:
    symbol_path = tmp_path / "unsafe.jpg"
    _write_symbol_file(
        symbol_path,
        custom_node={
            "op": "Custom",
            "name": "custom_loader",
            "attrs": {"library": "../../tmp/libevil.so", "op_type": "unsafe_loader"},
            "inputs": [[1, 0, 0]],
        },
    )

    assert not MXNetScanner.can_handle(str(symbol_path))
    result = scan_file(str(symbol_path))

    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_mxnet_scanner_rejects_non_mxnet_files(tmp_path: Path) -> None:
    fake_symbol = tmp_path / "fake.json"
    fake_symbol.write_text('{"not": "mxnet"}', encoding="utf-8")
    bad_params_name = tmp_path / "weights.params"
    bad_params_name.write_bytes(b"raw bytes")

    assert not MXNetScanner.can_handle(str(fake_symbol))
    assert not MXNetScanner.can_handle(str(bad_params_name))


def test_mxnet_scanner_routes_malformed_symbol_for_fail_closed_scan(tmp_path: Path) -> None:
    symbol_path = tmp_path / "malformed-symbol.json"
    symbol_path.write_text('{"nodes": [', encoding="utf-8")

    assert MXNetScanner.can_handle(str(symbol_path))


def test_mxnet_symbol_scan_with_valid_pair_has_no_security_findings(tmp_path: Path) -> None:
    symbol_path = tmp_path / "resnet-symbol.json"
    params_path = tmp_path / "resnet-0000.params"
    _write_symbol_file(symbol_path)
    _write_params_file(params_path)

    result = MXNetScanner().scan(str(symbol_path))

    assert result.success
    assert result.metadata.get("has_params_companion") is True
    high_severity = [
        issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert high_severity == []


def test_mxnet_scanner_reports_missing_companion_files(tmp_path: Path) -> None:
    symbol_path = tmp_path / "bert-symbol.json"
    params_path = tmp_path / "bert-0000.params"
    _write_symbol_file(symbol_path)

    symbol_result = MXNetScanner().scan(str(symbol_path))
    assert symbol_result.metadata.get("has_params_companion") is False
    assert any("No matching MXNet params companion file found" in issue.message for issue in symbol_result.issues)

    symbol_path.unlink()
    _write_params_file(params_path)
    params_result = MXNetScanner().scan(str(params_path))
    assert params_result.metadata.get("has_symbol_companion") is False
    assert any("No matching MXNet symbol companion file found" in issue.message for issue in params_result.issues)


def test_mxnet_direct_params_fails_closed_for_inconclusive_symbol_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.utils.file.detection.MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    monkeypatch.setattr("modelaudit.scanners.mxnet_scanner.MAX_SYMBOL_READ_BYTES", 128)
    params_path = tmp_path / "payload-0000.params"
    params_path.write_text(
        '{"padding":"'
        + ("x" * 256)
        + '","nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = MXNetScanner().scan(str(params_path))

    _assert_inconclusive_result(result, "mxnet_symbol_truncated")
    assert "mxnet_params_truncated" not in result.metadata["scan_outcome_reasons"]


def test_mxnet_direct_params_routes_bom_prefixed_symbol_content(tmp_path: Path) -> None:
    params_path = tmp_path / "payload-0000.params"
    params_path.write_text(
        '\ufeff{"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = MXNetScanner().scan(str(params_path))

    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_mxnet_direct_symbol_routed_params_preserves_raw_text_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.utils.file.detection.MXNET_SYMBOL_SIGNATURE_READ_BYTES", 512)
    monkeypatch.setattr("modelaudit.scanners.mxnet_scanner.MAX_SYMBOL_READ_BYTES", 512)
    params_path = tmp_path / "payload-0000.params"
    params_path.write_text(
        '{"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        '"version":[1,7,4],"learner":{"malicious_code":"os.system()"},"padding":"' + ("x" * 1024) + '"}',
        encoding="utf-8",
    )

    result = MXNetScanner().scan(str(params_path))

    assert any("Suspicious executable token" in issue.message for issue in result.issues)
    assert "mxnet_symbol_truncated" in result.metadata["scan_outcome_reasons"]


@pytest.mark.parametrize("stream", [False, True], ids=["standard", "streaming"])
def test_directory_scan_preserves_path_sensitive_companion_metadata(tmp_path: Path, stream: bool) -> None:
    with_params_dir = tmp_path / "with_params"
    without_params_dir = tmp_path / "without_params"
    with_params_dir.mkdir()
    without_params_dir.mkdir()

    with_params_symbol = with_params_dir / "net-symbol.json"
    without_params_symbol = without_params_dir / "net-symbol.json"
    _write_symbol_file(with_params_symbol)
    _write_symbol_file(without_params_symbol)
    _write_params_file(with_params_dir / "net-0000.params")

    if stream:
        files = sorted(path for path in tmp_path.rglob("*") if path.is_file())
        result = scan_model_streaming(
            ((path, index == len(files) - 1) for index, path in enumerate(files)),
            scan_root=str(tmp_path),
            delete_after_scan=False,
            cache_enabled=False,
            skip_file_types=False,
        )
    else:
        result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False, skip_file_types=False)

    assert result.file_metadata[str(with_params_symbol)]["has_params_companion"] is True
    assert result.file_metadata[str(without_params_symbol)]["has_params_companion"] is False
    missing_companion_checks = [
        check
        for check in result.checks
        if check.name == "MXNet Companion Artifact Check" and check.status.value == "failed"
    ]
    assert {check.location for check in missing_companion_checks} == {str(without_params_symbol)}


def test_mxnet_scanner_detects_suspicious_custom_operator_reference(tmp_path: Path) -> None:
    symbol_path = tmp_path / "unsafe-symbol.json"
    params_path = tmp_path / "unsafe-0000.params"
    _write_symbol_file(
        symbol_path,
        custom_node={
            "op": "Custom",
            "name": "custom_loader",
            "attrs": {
                "library": "../../tmp/libevil.so",
                "op_type": "unsafe_loader",
            },
            "inputs": [[1, 0, 0]],
        },
    )
    _write_params_file(params_path)

    result = MXNetScanner().scan(str(symbol_path))

    custom_issues = [issue for issue in result.issues if issue.details.get("attribute") == "library"]
    assert len(custom_issues) == 1
    assert custom_issues[0].severity == IssueSeverity.WARNING
    assert "node: custom_loader" in (custom_issues[0].location or "")


def test_mxnet_scanner_detects_cve_2022_24294_pathological_operator_name(tmp_path: Path) -> None:
    symbol_path = tmp_path / "redos-symbol.json"
    params_path = tmp_path / "redos-0000.params"
    pathological_operator = "<A" * 600
    _write_symbol_file(
        symbol_path,
        custom_node={
            "op": pathological_operator,
            "name": "redos_operator",
            "attrs": {"kernel": "(1,1)"},
            "inputs": [[1, 0, 0]],
        },
    )
    _write_params_file(params_path)

    result = MXNetScanner().scan(str(symbol_path))

    cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2022-24294"]
    assert len(cve_checks) == 1
    assert cve_checks[0].severity == IssueSeverity.WARNING
    details = cve_checks[0].details
    assert details["cvss"] == 7.5
    assert details["cwe"] == "CWE-400"
    assert "remediation" in details
    assert details["finding_count"] == 1
    assert details["findings"][0]["op_name_length"] == len(pathological_operator)


def test_mxnet_scanner_long_simple_operator_name_no_cve(tmp_path: Path) -> None:
    symbol_path = tmp_path / "long-safe-symbol.json"
    params_path = tmp_path / "long-safe-0000.params"
    _write_symbol_file(
        symbol_path,
        custom_node={
            "op": f"Custom{'A' * 2000}",
            "name": "long_custom_operator",
            "attrs": {"kernel": "(1,1)"},
            "inputs": [[1, 0, 0]],
        },
    )
    _write_params_file(params_path)

    result = MXNetScanner().scan(str(symbol_path))

    assert not [check for check in result.checks if check.details.get("cve_id") == "CVE-2022-24294"]


def test_mxnet_scanner_long_node_name_no_cve(tmp_path: Path) -> None:
    symbol_path = tmp_path / "long-node-symbol.json"
    params_path = tmp_path / "long-node-0000.params"
    _write_symbol_file(
        symbol_path,
        custom_node={
            "op": "Convolution",
            "name": f"node_{'<' * 1500}",
            "attrs": {"kernel": "(1,1)", "num_filter": "8"},
            "inputs": [[1, 0, 0]],
        },
    )
    _write_params_file(params_path)

    result = MXNetScanner().scan(str(symbol_path))

    assert not [check for check in result.checks if check.details.get("cve_id") == "CVE-2022-24294"]


def test_mxnet_scanner_detects_encoded_metadata_payload(tmp_path: Path) -> None:
    symbol_path = tmp_path / "payload-symbol.json"
    params_path = tmp_path / "payload-0000.params"

    encoded_payload = base64.b64encode(b"__import__('os').system('id')").decode("ascii")
    _write_symbol_file(symbol_path, metadata=encoded_payload)
    _write_params_file(params_path)

    result = MXNetScanner().scan(str(symbol_path))

    assert any("Encoded Metadata Payload" in check.name for check in result.checks)


def test_mxnet_scanner_comment_token_does_not_suppress_encoded_payload_detection(tmp_path: Path) -> None:
    symbol_path = tmp_path / "payload-comment-symbol.json"
    params_path = tmp_path / "payload-comment-0000.params"

    encoded_payload = base64.b64encode(b"# __import__('os').system('id')").decode("ascii")
    _write_symbol_file(symbol_path, metadata=encoded_payload)
    _write_params_file(params_path)

    result = MXNetScanner().scan(str(symbol_path))

    assert any("Encoded Metadata Payload" in check.name for check in result.checks)


def test_mxnet_scanner_handles_corrupt_params_file(tmp_path: Path) -> None:
    params_path = tmp_path / "corrupt-0000.params"
    params_path.write_bytes(b"")

    result = MXNetScanner().scan(str(params_path))

    _assert_inconclusive_result(result, "mxnet_params_empty")
    assert any("MXNet params blob is empty" in issue.message for issue in result.issues)


def test_mxnet_corrupt_params_aggregate_exit_code_is_inconclusive(tmp_path: Path) -> None:
    params_path = tmp_path / "corrupt-0000.params"
    params_path.write_bytes(b"")

    result = scan_model_directory_or_file(str(params_path), cache_scan_results=False)

    _assert_aggregate_inconclusive(result, params_path, "mxnet_params_empty")


def test_mxnet_truncated_params_aggregate_exit_code_is_inconclusive(tmp_path: Path) -> None:
    params_path = tmp_path / "truncated-0000.params"
    params_path.write_bytes(b"short")

    direct_result = MXNetScanner().scan(str(params_path))
    aggregate_result = scan_model_directory_or_file(str(params_path), cache_scan_results=False)

    _assert_inconclusive_result(direct_result, "mxnet_params_truncated")
    _assert_aggregate_inconclusive(aggregate_result, params_path, "mxnet_params_truncated")


def test_mxnet_malformed_symbol_scan_is_inconclusive(tmp_path: Path) -> None:
    symbol_path = tmp_path / "broken-symbol.json"
    symbol_path.write_text('{"nodes": [', encoding="utf-8")

    result = MXNetScanner().scan(str(symbol_path))
    aggregate_result = scan_model_directory_or_file(str(symbol_path), cache_scan_results=False)

    _assert_inconclusive_result(result, "mxnet_symbol_parse_failed")
    _assert_aggregate_inconclusive(aggregate_result, symbol_path, "mxnet_symbol_parse_failed")
    assert any(check.name == "MXNet Symbol Parse" for check in result.checks)


def test_mxnet_symbol_decoder_recursion_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    symbol_path = tmp_path / "recursive-symbol.json"
    _write_symbol_file(symbol_path)

    def raise_recursion(_payload: object) -> object:
        raise RecursionError("decoder nesting limit")

    monkeypatch.setattr("modelaudit.scanners.mxnet_scanner.json.loads", raise_recursion)

    result = MXNetScanner().scan(str(symbol_path))

    _assert_inconclusive_result(result, "mxnet_symbol_parse_failed")
    assert any(check.name == "MXNet Symbol Parse" for check in result.checks)


def test_direct_mxnet_scan_of_invalid_renamed_symbol_is_inconclusive(tmp_path: Path) -> None:
    artifact_path = tmp_path / "model.mxnet"
    artifact_path.write_bytes(b"mxnet-ish content")

    result = MXNetScanner().scan(str(artifact_path))

    _assert_inconclusive_result(result, "mxnet_symbol_parse_failed")


def test_mxnet_symbol_read_failure_scan_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    symbol_path = tmp_path / "unreadable-symbol.json"
    symbol_path.write_text("{}", encoding="utf-8")

    def raise_os_error(path: Path, max_bytes: int) -> tuple[bytes, bool]:
        raise OSError("symbol read failed")

    monkeypatch.setattr(MXNetScanner, "_read_bounded_bytes", staticmethod(raise_os_error))

    result = MXNetScanner().scan(str(symbol_path))

    _assert_inconclusive_result(result, "mxnet_symbol_read_failed")
    read_checks = [check for check in result.checks if check.name == "MXNet Symbol Read"]
    assert len(read_checks) == 1
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == "mxnet_symbol_read_failed"


def test_mxnet_symbol_read_failure_aggregate_exit_code_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    symbol_path = tmp_path / "unreadable-symbol.json"
    _write_symbol_file(symbol_path)
    symbol_path.write_text(symbol_path.read_text(encoding="utf-8") + (" " * (10 * 1024)), encoding="utf-8")

    def raise_os_error(path: Path, max_bytes: int) -> tuple[bytes, bool]:
        raise OSError("symbol read failed")

    monkeypatch.setattr(MXNetScanner, "_read_bounded_bytes", staticmethod(raise_os_error))

    _assert_aggregate_inconclusive_not_cached(
        symbol_path,
        "mxnet_symbol_read_failed",
        tmp_path / "symbol-read-cache",
    )


def test_mxnet_params_read_failure_scan_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    params_path = tmp_path / "unreadable-0000.params"
    params_path.write_bytes(b"placeholder params")

    def raise_os_error(path: Path, max_bytes: int) -> tuple[bytes, bool]:
        raise OSError("params read failed")

    monkeypatch.setattr(MXNetScanner, "_read_bounded_bytes", staticmethod(raise_os_error))

    result = MXNetScanner().scan(str(params_path))

    _assert_inconclusive_result(result, "mxnet_params_read_failed")
    read_checks = [check for check in result.checks if check.name == "MXNet Params Read"]
    assert len(read_checks) == 1
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == "mxnet_params_read_failed"


def test_mxnet_params_read_failure_aggregate_exit_code_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    params_path = tmp_path / "unreadable-0000.params"
    _write_params_file(params_path)

    def raise_os_error(path: Path, max_bytes: int) -> tuple[bytes, bool]:
        raise OSError("params read failed")

    monkeypatch.setattr(MXNetScanner, "_read_bounded_bytes", staticmethod(raise_os_error))

    _assert_aggregate_inconclusive_not_cached(
        params_path,
        "mxnet_params_read_failed",
        tmp_path / "params-read-cache",
    )


def test_mxnet_truncated_symbol_scan_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    symbol_path = tmp_path / "truncated-symbol.json"
    _write_symbol_file(symbol_path)
    monkeypatch.setattr("modelaudit.scanners.mxnet_scanner.MAX_SYMBOL_READ_BYTES", 8)

    result = MXNetScanner().scan(str(symbol_path))

    _assert_inconclusive_result(result, "mxnet_symbol_truncated")


def test_mxnet_empty_symbol_scan_is_inconclusive(tmp_path: Path) -> None:
    symbol_path = tmp_path / "empty-symbol.json"
    symbol_path.write_text("", encoding="utf-8")

    result = MXNetScanner().scan(str(symbol_path))

    _assert_inconclusive_result(result, "mxnet_symbol_empty")


def test_mxnet_invalid_symbol_structure_scan_is_inconclusive(tmp_path: Path) -> None:
    symbol_path = tmp_path / "invalid-symbol.json"
    symbol_path.write_text(json.dumps({"nodes": [], "arg_nodes": [], "heads": []}), encoding="utf-8")

    result = MXNetScanner().scan(str(symbol_path))
    aggregate_result = scan_model_directory_or_file(str(symbol_path), cache_scan_results=False)

    _assert_inconclusive_result(result, "mxnet_symbol_invalid_structure")
    _assert_aggregate_inconclusive(aggregate_result, symbol_path, "mxnet_symbol_invalid_structure")


def test_mxnet_params_numeric_blob_does_not_trigger_false_positives(tmp_path: Path) -> None:
    symbol_path = tmp_path / "clean-symbol.json"
    params_path = tmp_path / "clean-0000.params"
    _write_symbol_file(symbol_path)
    _write_params_file(params_path, values=tuple(float(i) for i in range(256)))

    result = MXNetScanner().scan(str(params_path))

    high_severity = [
        issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert high_severity == []


def test_mxnet_scanner_routing_uses_mxnet_scanner_for_pair_files(tmp_path: Path) -> None:
    symbol_path = tmp_path / "paired-symbol.json"
    params_path = tmp_path / "paired-0000.params"
    _write_symbol_file(symbol_path)
    _write_params_file(params_path)

    symbol_scanner = get_scanner_for_file(str(symbol_path))
    params_scanner = get_scanner_for_file(str(params_path))

    assert symbol_scanner is not None
    assert params_scanner is not None
    assert symbol_scanner.name == "mxnet"
    assert params_scanner.name == "mxnet"
