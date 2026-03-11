import pickle
from pathlib import Path
from typing import Any, Protocol, TypedDict

import pytest

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.tf_savedmodel_scanner import TensorFlowSavedModelScanner


class _NodeCollection(Protocol):
    def add(self) -> Any:
        """Append a protobuf node and return the mutable node object."""


class _RequiredNodeSpec(TypedDict):
    op: str


class _NodeSpec(_RequiredNodeSpec, total=False):
    name: str
    string_attrs: dict[str, str]
    function_ref: str


# Defer TensorFlow check to avoid module-level imports
def has_tensorflow():
    try:
        import tensorflow as tf

        # Avoid treating vendored protobuf-only stubs as full TensorFlow runtime.
        return bool(getattr(tf, "__version__", None)) and hasattr(tf, "constant")
    except Exception:
        return False


def has_tf_protos() -> bool:
    """Check if TensorFlow protobuf stubs are available (vendored or from TensorFlow)."""
    import modelaudit.protos

    return modelaudit.protos._check_vendored_protos()


def test_tf_savedmodel_scanner_can_handle(tmp_path: Path) -> None:
    """Test the can_handle method of TensorFlowSavedModelScanner."""
    # Create a directory with saved_model.pb
    tf_dir = tmp_path / "tf_model"
    tf_dir.mkdir()
    (tf_dir / "saved_model.pb").write_bytes(b"dummy content")

    # Create a regular directory
    regular_dir = tmp_path / "regular_dir"
    regular_dir.mkdir()

    # Create a file
    test_file = tmp_path / "test.pb"
    test_file.write_bytes(b"dummy content")

    if has_tf_protos():
        # With vendored protos or TensorFlow, can_handle works for valid paths
        assert TensorFlowSavedModelScanner.can_handle(str(tf_dir)) is True
        assert TensorFlowSavedModelScanner.can_handle(str(regular_dir)) is False
        assert TensorFlowSavedModelScanner.can_handle(str(test_file)) is True  # Now accepts any .pb file
    else:
        # Without protos, can_handle returns False
        assert TensorFlowSavedModelScanner.can_handle(str(tf_dir)) is False
        assert TensorFlowSavedModelScanner.can_handle(str(regular_dir)) is False
        assert TensorFlowSavedModelScanner.can_handle(str(test_file)) is False


def create_tf_savedmodel(tmp_path: Path, *, malicious: bool = False) -> Path:
    """Create a mock TensorFlow SavedModel directory for testing."""
    import importlib

    importlib.import_module("modelaudit.protos")
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

    # Create a directory that mimics a TensorFlow SavedModel
    model_dir = tmp_path / "tf_model"
    model_dir.mkdir()

    # Create a minimal valid SavedModel protobuf
    saved_model = SavedModel()

    # Add a meta graph
    meta_graph = saved_model.meta_graphs.add()

    # Add a simple graph
    graph_def = meta_graph.graph_def

    # Add a simple constant node
    node = graph_def.node.add()
    node.name = "Const"
    node.op = "Const"

    if malicious:
        # Add a suspicious operation
        suspicious_node = graph_def.node.add()
        suspicious_node.name = "suspicious_op"
        suspicious_node.op = "PyFunc"  # This is in our suspicious ops list

    # Write the protobuf to file
    with (model_dir / "saved_model.pb").open("wb") as f:
        f.write(saved_model.SerializeToString())

    # Create variables directory
    variables_dir = model_dir / "variables"
    variables_dir.mkdir()

    # Create variables.index
    (variables_dir / "variables.index").write_bytes(b"dummy index content")

    # Create variables.data
    (variables_dir / "variables.data-00000-of-00001").write_bytes(b"dummy data content")

    # Create assets directory
    assets_dir = model_dir / "assets"
    assets_dir.mkdir()

    # If malicious, add a malicious pickle file
    if malicious:

        class MaliciousClass:
            def __reduce__(self):
                return (eval, ("print('malicious code')",))

        malicious_data = {"malicious": MaliciousClass()}
        malicious_pickle = pickle.dumps(malicious_data)
        (model_dir / "malicious.pkl").write_bytes(malicious_pickle)

    return model_dir


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_scanner_safe_model(tmp_path: Path) -> None:
    """Test scanning a safe TensorFlow SavedModel."""
    model_dir = create_tf_savedmodel(tmp_path)

    scanner = TensorFlowSavedModelScanner()
    result = scanner.scan(str(model_dir))

    assert result.success is True
    assert result.bytes_scanned > 0

    # Check for issues - a safe model might still have some informational issues
    error_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert len(error_issues) == 0


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_scanner_malicious_model(tmp_path: Path) -> None:
    """Test scanning a malicious TensorFlow SavedModel."""
    model_dir = create_tf_savedmodel(tmp_path, malicious=True)

    scanner = TensorFlowSavedModelScanner()
    result = scanner.scan(str(model_dir))

    # The scanner should detect errors from:
    # 1. Malicious pickle files in the directory, OR
    # 2. Suspicious TensorFlow operations (e.g. PyFunc), OR
    # 3. Both malicious files and suspicious operations
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        "malicious.pkl" in issue.message.lower()
        or "eval" in issue.message.lower()
        or "pyfunc" in issue.message.lower()
        or "suspicious" in issue.message.lower()
        for issue in result.issues
    )

    # Issues about PyFunc operations should include a 'why' explanation
    pyfunc_issues = [issue for issue in result.issues if issue.message and "PyFunc" in issue.message]
    assert any(issue.why is not None for issue in pyfunc_issues)


def test_tf_savedmodel_scanner_invalid_model(tmp_path):
    """Test scanning an invalid TensorFlow SavedModel."""
    # Create an invalid model directory (missing required files)
    invalid_dir = tmp_path / "invalid_model"
    invalid_dir.mkdir()
    (invalid_dir / "saved_model.pb").write_bytes(b"dummy content")
    # Missing variables directory

    scanner = TensorFlowSavedModelScanner()
    result = scanner.scan(str(invalid_dir))

    # Should have issues about invalid protobuf format or TensorFlow not installed
    # Note: Missing dependencies are WARNING (not security issue), errors in parsing are CRITICAL
    assert len(result.issues) > 0
    assert any(
        "error" in issue.message.lower()
        or "parsing" in issue.message.lower()
        or "invalid" in issue.message.lower()
        or "tensorflow not installed" in issue.message.lower()
        for issue in result.issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_detect_readfile_operation(tmp_path: Path) -> None:
    # Synthesize a SavedModel containing a ReadFile node
    model_path = _create_test_savedmodel_with_op(tmp_path, "ReadFile", "readfile_test")
    scanner = TensorFlowSavedModelScanner()
    result = scanner.scan(model_path)

    readfile_issues = [i for i in result.issues if i.message and "ReadFile" in i.message]
    assert readfile_issues, "Expected detection for ReadFile operation"
    assert any(i.severity == IssueSeverity.CRITICAL for i in readfile_issues)
    # Ensure an explanation is provided for developer guidance
    assert any(i.why for i in readfile_issues), "Missing explanation for ReadFile detection"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_detect_pyfunc_operation(tmp_path: Path) -> None:
    model_path = _create_test_savedmodel_with_op(tmp_path, "PyFunc", "pyfunc_test")
    scanner = TensorFlowSavedModelScanner()
    result = scanner.scan(model_path)

    pyfunc_issues = [i for i in result.issues if i.message and "PyFunc" in i.message]
    assert pyfunc_issues, "Expected detection for PyFunc operation"
    assert any(i.severity == IssueSeverity.CRITICAL for i in pyfunc_issues)
    assert any(i.why for i in pyfunc_issues), "Missing explanation for PyFunc detection"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_detect_writefile_operation(tmp_path: Path) -> None:
    # Synthesize a SavedModel containing a WriteFile node
    model_path = _create_test_savedmodel_with_op(tmp_path, "WriteFile", "writefile_test")
    scanner = TensorFlowSavedModelScanner()
    result = scanner.scan(model_path)

    writefile_issues = [i for i in result.issues if i.message and "WriteFile" in i.message]
    assert writefile_issues, "Expected detection for WriteFile operation"
    assert any(i.severity == IssueSeverity.CRITICAL for i in writefile_issues)
    # Ensure an explanation is provided for developer guidance
    assert any(i.why for i in writefile_issues), "Missing explanation for WriteFile detection"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
@pytest.mark.parametrize(
    ("op_name", "function_name"),
    [
        ("WriteFile", "__inference_writefile_attack_1"),
        ("PyFunc", "__inference_pyfunc_attack_1"),
        ("ParseTensor", "__inference_parse_tensor_attack_1"),
    ],
)
def test_detect_suspicious_ops_in_function_definitions(
    tmp_path: Path,
    op_name: str,
    function_name: str,
) -> None:
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        function_nodes={
            function_name: [
                {
                    "op": op_name,
                    "name": f"function_{op_name.lower()}_node",
                }
            ]
        },
        model_name=f"function_def_{op_name.lower()}",
    )

    result = TensorFlowSavedModelScanner().scan(model_path)
    matching_issues = [issue for issue in result.issues if issue.message and op_name in issue.message]

    assert matching_issues, f"Expected detection for {op_name} inside a function definition"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in matching_issues)
    assert any(issue.details.get("node_scope") == "function_def" for issue in matching_issues)
    assert any(issue.details.get("function_name") == function_name for issue in matching_issues)
    assert any(function_name in (issue.location or "") for issue in matching_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_stateful_partitioned_call_detected_in_function_definition(tmp_path: Path) -> None:
    function_name = "__inference_stateful_partitioned_call_1"
    target_name = "__inference_eval_fn_123"
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        function_nodes={
            function_name: [
                {
                    "op": "StatefulPartitionedCall",
                    "name": "partitioned_call",
                    "function_ref": target_name,
                }
            ]
        },
        model_name="function_def_stateful_partitioned_call",
    )

    result = TensorFlowSavedModelScanner().scan(model_path)
    matching_issues = [
        issue
        for issue in result.issues
        if issue.message and "StatefulPartitionedCall with suspicious function" in issue.message
    ]

    assert matching_issues, "Expected StatefulPartitionedCall warning inside a function definition"
    assert all(issue.severity == IssueSeverity.WARNING for issue in matching_issues)
    assert any(issue.details.get("stateful_call_target") == target_name for issue in matching_issues)
    assert any(issue.details.get("node_scope") == "function_def" for issue in matching_issues)
    assert any(issue.details.get("function_name") == function_name for issue in matching_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_stateful_partitioned_call_ignores_evaluate_like_function_names(tmp_path: Path) -> None:
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        function_nodes={
            "__inference_stateful_partitioned_call_1": [
                {
                    "op": "StatefulPartitionedCall",
                    "name": "partitioned_call",
                    "function_ref": "__inference_evaluate_123",
                }
            ]
        },
        model_name="function_def_stateful_partitioned_call_evaluate",
    )

    result = TensorFlowSavedModelScanner().scan(model_path)

    assert not any(
        issue.message and "StatefulPartitionedCall with suspicious function" in issue.message for issue in result.issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_lambda_named_function_definition_nodes_do_not_trigger_lambda_layer_warning(tmp_path: Path) -> None:
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        function_nodes={
            "__inference_safe_lambdaish_1": [
                {
                    "op": "Identity",
                    "name": "lambda/Identity",
                }
            ]
        },
        model_name="function_def_lambda_named_node",
    )

    result = TensorFlowSavedModelScanner().scan(model_path)

    assert not any(issue.message == "Lambda layer detected in graph" for issue in result.issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_graph_lambda_named_nodes_still_trigger_lambda_layer_warning(tmp_path: Path) -> None:
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "Identity",
                "name": "lambda/Identity",
            }
        ],
        model_name="graph_lambda_named_node",
    )

    result = TensorFlowSavedModelScanner().scan(model_path)
    lambda_issues = [issue for issue in result.issues if issue.message == "Lambda layer detected in graph"]

    assert lambda_issues, "Expected Lambda layer warning for top-level graph nodes"
    assert any(issue.details.get("node_scope") == "graph_def" for issue in lambda_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_protobuf_string_injection_detected_in_function_definition(tmp_path: Path) -> None:
    function_name = "__inference_payload_attack_1"
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        function_nodes={
            function_name: [
                {
                    "op": "Const",
                    "name": "payload_node",
                    "string_attrs": {
                        "payload": "os.system('/bin/echo exploit')",
                    },
                }
            ]
        },
        model_name="function_def_string_injection",
    )

    result = TensorFlowSavedModelScanner().scan(model_path)
    injection_issues = [
        issue
        for issue in result.issues
        if "protobuf string" in issue.message.lower() and issue.details.get("attack_type") == "system_command"
    ]

    assert injection_issues, "Expected protobuf string injection detection inside a function definition"
    assert any(issue.details.get("node_scope") == "function_def" for issue in injection_issues)
    assert any(issue.details.get("function_name") == function_name for issue in injection_issues)
    assert any(issue.details.get("attribute_name") == "payload" for issue in injection_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_function_definition_ops_are_counted_in_metadata(tmp_path: Path) -> None:
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[{"op": "WriteFile", "name": "top_level_write"}],
        function_nodes={
            "__inference_writefile_attack_1": [
                {"op": "WriteFile", "name": "function_write"},
            ]
        },
        model_name="count_function_ops",
    )

    result = TensorFlowSavedModelScanner().scan(model_path)

    assert result.metadata["op_counts"]["WriteFile"] == 2
    assert result.metadata["suspicious_op_found"] is True


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_safe_function_definition_ops_do_not_trigger_findings(tmp_path: Path) -> None:
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[{"op": "Placeholder", "name": "input_node"}],
        function_nodes={
            "__inference_safe_signature_wrapper_1": [
                {"op": "Const", "name": "const_value"},
                {"op": "AddV2", "name": "add_value"},
                {"op": "Identity", "name": "identity_value"},
            ]
        },
        model_name="safe_function_def",
    )

    result = TensorFlowSavedModelScanner().scan(model_path)

    assert result.issues == []
    assert result.metadata["op_counts"]["Const"] == 1
    assert result.metadata["op_counts"]["AddV2"] == 1
    assert result.metadata["op_counts"]["Identity"] == 1
    assert result.metadata["suspicious_op_found"] is False


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_scanner_with_blacklist(tmp_path: Path) -> None:
    """Test TensorFlow SavedModel scanner with custom blacklist patterns."""
    model_dir = create_tf_savedmodel(tmp_path)

    # Create a file with content that matches our blacklist
    (model_dir / "custom_file.txt").write_bytes(
        b"This file contains suspicious_function",
    )

    # Create scanner with custom blacklist
    scanner = TensorFlowSavedModelScanner(
        config={"blacklist_patterns": ["suspicious_function"]},
    )
    result = scanner.scan(str(model_dir))

    # Should detect our blacklisted pattern
    blacklist_issues = [issue for issue in result.issues if "suspicious_function" in issue.message.lower()]
    assert len(blacklist_issues) > 0


def test_tf_savedmodel_scanner_not_a_directory(tmp_path):
    """Test scanning a file instead of a directory."""
    # Create a file
    test_file = tmp_path / "model.pb"
    test_file.write_bytes(b"dummy content")

    scanner = TensorFlowSavedModelScanner()
    result = scanner.scan(str(test_file))

    # Should have an issue about invalid protobuf format or TensorFlow not installed
    # Note: Missing dependencies are WARNING (not security issue), errors in parsing are CRITICAL
    assert len(result.issues) > 0
    assert any(
        "error" in issue.message.lower()
        or "parsing" in issue.message.lower()
        or "tensorflow not installed" in issue.message.lower()
        for issue in result.issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_scanner_unreadable_file(tmp_path: Path, requires_symlinks: None) -> None:
    """Scanner should report unreadable files instead of silently skipping."""
    model_dir = create_tf_savedmodel(tmp_path)

    missing = model_dir / "missing.txt"
    missing.write_text("secret")
    # Replace file with dangling symlink to trigger read error
    missing.unlink()
    missing.symlink_to("/nonexistent/path")

    scanner = TensorFlowSavedModelScanner(config={"blacklist_patterns": ["secret"]})
    result = scanner.scan(str(model_dir))

    assert any("error reading file" in issue.message.lower() for issue in result.issues)


def _create_test_savedmodel_with_op(tmp_path: Path, op_name: str, model_name: str | None = None) -> str:
    """Helper function to create a test SavedModel with a specific TensorFlow operation."""
    return _create_test_savedmodel_with_ops(tmp_path, [op_name], model_name)


def _create_test_savedmodel_with_scoped_nodes(
    tmp_path: Path,
    *,
    graph_nodes: list[_NodeSpec] | None = None,
    function_nodes: dict[str, list[_NodeSpec]] | None = None,
    model_name: str | None = None,
) -> str:
    """Create a SavedModel with top-level and function-definition graph nodes."""
    import importlib

    importlib.import_module("modelaudit.protos")
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

    if model_name is None:
        model_name = "test_model_scoped_nodes"

    model_dir = tmp_path / model_name
    model_dir.mkdir()

    # Create SavedModel with the specified operations
    saved_model = SavedModel()
    meta_graph = saved_model.meta_graphs.add()
    meta_graph.meta_info_def.tags.append("serve")

    graph_def = meta_graph.graph_def

    def add_node(node_collection: _NodeCollection, spec: _NodeSpec, default_name: str) -> None:
        node = node_collection.add()
        node.name = spec.get("name", default_name)
        node.op = spec["op"]

        for attr_name, attr_value in spec.get("string_attrs", {}).items():
            node.attr[attr_name].s = attr_value.encode("utf-8")

        function_ref = spec.get("function_ref")
        if function_ref is not None:
            node.attr["f"].func.name = function_ref

    for index, spec in enumerate(graph_nodes or []):
        add_node(graph_def.node, spec, f"graph_node_{index}_{str(spec['op']).lower()}")

    for function_name, node_specs in (function_nodes or {}).items():
        function_def = graph_def.library.function.add()
        function_def.signature.name = function_name
        for index, spec in enumerate(node_specs):
            add_node(function_def.node_def, spec, f"function_node_{index}_{str(spec['op']).lower()}")

    # Save the model
    saved_model_path = model_dir / "saved_model.pb"
    saved_model_path.write_bytes(saved_model.SerializeToString())

    # Create variables directory (required for valid SavedModel)
    variables_dir = model_dir / "variables"
    variables_dir.mkdir()

    return str(model_dir)


def _create_test_savedmodel_with_ops(
    tmp_path: Path,
    op_names: list[str],
    model_name: str | None = None,
) -> str:
    """Helper function to create a test SavedModel with multiple TensorFlow operations."""
    if model_name is None:
        model_name = f"test_model_{'_'.join(op.lower() for op in op_names[:2])}"

    graph_nodes: list[_NodeSpec] = [{"op": op_name} for op_name in op_names]
    return _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=graph_nodes,
        model_name=model_name,
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_scanner_explanations_for_all_suspicious_ops(tmp_path: Path) -> None:
    """Test that all suspicious TensorFlow operations generate explanations."""
    from modelaudit.config.explanations import get_tf_op_explanation
    from modelaudit.detectors.suspicious_symbols import SUSPICIOUS_OPS

    # Test each suspicious operation individually
    for op_name in SUSPICIOUS_OPS:
        # Create a SavedModel with the specific suspicious operation
        model_path = _create_test_savedmodel_with_op(tmp_path, op_name)

        # Scan the model
        scanner = TensorFlowSavedModelScanner()
        result = scanner.scan(model_path)

        # Should detect the suspicious operation
        suspicious_issues = [
            issue
            for issue in result.issues
            if issue.message and op_name in issue.message and issue.severity == IssueSeverity.CRITICAL
        ]

        assert len(suspicious_issues) > 0, f"Failed to detect suspicious TensorFlow operation: {op_name}"

        # Check that explanation is provided
        for issue in suspicious_issues:
            assert issue.why is not None, f"Missing explanation for suspicious TF operation: {op_name}"

            # Verify the explanation matches what we expect
            expected_explanation = get_tf_op_explanation(op_name)
            assert issue.why == expected_explanation, (
                f"Explanation mismatch for {op_name}. Expected: {expected_explanation}, Got: {issue.why}"
            )

            # Verify explanation quality
            assert len(issue.why) > 20, f"Explanation too short for {op_name}: {issue.why}"
            assert any(
                keyword in issue.why.lower()
                for keyword in ["attack", "malicious", "abuse", "exploit", "dangerous", "risk", "exfiltration"]
            ), f"Explanation for {op_name} should mention security risks: {issue.why}"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_scanner_explanation_categories(tmp_path: Path) -> None:
    """Test that TensorFlow scanner provides appropriate explanations by operation category."""
    # Test critical risk operations (code execution)
    critical_ops = ["PyFunc", "PyCall", "ExecuteOp", "ShellExecute"]
    for op_name in critical_ops:
        model_path = _create_test_savedmodel_with_op(tmp_path, op_name, f"critical_test_{op_name.lower()}")

        scanner = TensorFlowSavedModelScanner()
        result = scanner.scan(model_path)

        # Find issues related to this operation
        op_issues = [issue for issue in result.issues if issue.message and op_name in issue.message]
        assert len(op_issues) > 0, f"No issues found for critical operation {op_name}"

        for issue in op_issues:
            if issue.why:  # Check explanations when provided
                # Critical operations should mention code execution or system risks
                critical_keywords = ["execute", "code", "system", "shell", "commands", "arbitrary"]
                assert any(keyword in issue.why.lower() for keyword in critical_keywords), (
                    f"Critical operation {op_name} explanation should mention execution risks: {issue.why}"
                )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_scanner_no_explanation_for_safe_ops(tmp_path: Path) -> None:
    """Test that safe TensorFlow operations don't generate unnecessary explanations."""
    # Create a model with only safe operations
    safe_ops = ["MatMul", "Add", "Relu", "Conv2D", "MaxPool"]
    model_path = _create_test_savedmodel_with_ops(tmp_path, safe_ops, "safe_model")

    scanner = TensorFlowSavedModelScanner()
    result = scanner.scan(model_path)

    # Should not have any critical issues about suspicious operations
    suspicious_issues = [
        issue
        for issue in result.issues
        if issue.severity == IssueSeverity.CRITICAL and "suspicious" in issue.message.lower()
    ]
    assert len(suspicious_issues) == 0, "Safe operations should not trigger suspicious operation warnings"

    # Should not have explanations about TF operations (only other potential issues)
    tf_op_issues_with_explanations = [
        issue
        for issue in result.issues
        if issue.why and any(op in issue.why for op in ["TensorFlow", "operation", "graph"])
    ]
    assert len(tf_op_issues_with_explanations) == 0, "Safe operations should not have TF operation explanations"
