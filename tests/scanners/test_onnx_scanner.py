import struct
import sys
from pathlib import Path
from typing import Any

import pytest

# Skip if onnx is not available before importing it
pytest.importorskip("onnx")

import onnx
from onnx import TensorProto, helper
from onnx.onnx_ml_pb2 import StringStringEntryProto

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.detectors.jit_script import JITScriptDetector
from modelaudit.detectors.network_comm import NetworkCommDetector
from modelaudit.scanners.base import FORMAT_VALIDATION_CONFIG_KEY, INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.onnx_scanner import (
    ONNX_STRUCTURE_INCONCLUSIVE_REASON,
    OnnxScanner,
    _confirmed_onnx_operator_findings,
    _confirmed_python_operator_findings,
)
from modelaudit.utils.file.detection import PROTOBUF_MODEL_CANDIDATE_FORMAT


def _make_external_tensor(name: str, data_type: int, dims: list[int], external_path: str) -> Any:
    tensor = onnx.TensorProto()
    tensor.name = name
    tensor.data_type = data_type
    tensor.dims.extend(dims)
    tensor.data_location = onnx.TensorProto.EXTERNAL
    entry = StringStringEntryProto()
    entry.key = "location"
    entry.value = external_path
    tensor.external_data.append(entry)
    return tensor


def create_onnx_model(
    tmp_path: Path,
    *,
    custom: bool = False,
    custom_domain: str = "com.test",
    custom_op_type: str = "CustomOp",
    external: bool = False,
    external_path: str = "weights.bin",
    external_metadata: dict[str, str] | None = None,
    external_file_bytes: bytes | None = None,
    missing_external: bool = False,
    tensor_shape: tuple[int, ...] = (1,),
    include_initializer: bool = True,
    custom_opset_version: int | None = None,
) -> Path:
    X = helper.make_tensor_value_info("input", TensorProto.FLOAT, list(tensor_shape) or [1])
    Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, list(tensor_shape) or [1])
    node = (
        helper.make_node(
            custom_op_type,
            ["input"],
            ["output"],
            domain=custom_domain,
            name="custom",
        )
        if custom
        else helper.make_node("Relu", ["input"], ["output"], name="relu")
    )

    initializers: list[Any] = []
    if include_initializer and external:
        value_count = 1
        for dim in tensor_shape:
            value_count *= dim
        tensor = helper.make_tensor("W", TensorProto.FLOAT, list(tensor_shape), vals=[1.0] * max(1, value_count))
        tensor.data_location = onnx.TensorProto.EXTERNAL
        entry = StringStringEntryProto()
        entry.key = "location"
        entry.value = external_path
        tensor.external_data.append(entry)
        for key, value in (external_metadata or {}).items():
            extra_entry = StringStringEntryProto()
            extra_entry.key = key
            extra_entry.value = value
            tensor.external_data.append(extra_entry)
        initializers.append(tensor)
        if not missing_external:
            external_file = tmp_path / external_path
            external_file.parent.mkdir(parents=True, exist_ok=True)
            with open(external_file, "wb") as f:
                f.write(external_file_bytes or struct.pack("f", 1.0))
    elif include_initializer:
        value_count = 1
        for dim in tensor_shape:
            value_count *= dim
        tensor = helper.make_tensor("W", TensorProto.FLOAT, list(tensor_shape), vals=[1.0] * max(1, value_count))
        initializers.append(tensor)

    graph = helper.make_graph([node], "graph", [X], [Y], initializer=initializers)
    if custom and custom_opset_version is not None:
        model = helper.make_model(
            graph,
            opset_imports=[
                helper.make_opsetid("", 13),
                helper.make_opsetid(custom_domain, custom_opset_version),
            ],
        )
    else:
        model = helper.make_model(graph)
    path = tmp_path / "model.onnx"
    onnx.save(model, str(path))
    return path


def create_python_onnx_model(tmp_path: Path) -> Path:
    X = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1])
    Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1])
    node = helper.make_node("PythonOp", ["input"], ["output"], name="python")
    graph = helper.make_graph([node], "graph", [X], [Y])
    model = helper.make_model(graph)
    path = tmp_path / "model.onnx"
    onnx.save(model, str(path))
    return path


def create_onnx_model_with_nested_external_initializer(
    tmp_path: Path,
    *,
    external_path: str,
    missing_external: bool = False,
) -> Path:
    tensor = helper.make_tensor("nested_W", TensorProto.FLOAT, [1], vals=[1.0])
    tensor.data_location = onnx.TensorProto.EXTERNAL
    entry = StringStringEntryProto()
    entry.key = "location"
    entry.value = external_path
    tensor.external_data.append(entry)

    then_branch = helper.make_graph(
        [helper.make_node("Identity", ["nested_W"], ["Z"])],
        "then_branch",
        [],
        [helper.make_tensor_value_info("Z", TensorProto.FLOAT, [1])],
        initializer=[tensor],
    )
    else_tensor = helper.make_tensor("else_W", TensorProto.FLOAT, [1], vals=[0.0])
    else_branch = helper.make_graph(
        [helper.make_node("Identity", ["else_W"], ["Z"])],
        "else_branch",
        [],
        [helper.make_tensor_value_info("Z", TensorProto.FLOAT, [1])],
        initializer=[else_tensor],
    )
    condition = helper.make_tensor("cond", TensorProto.BOOL, [], vals=[True])
    graph = helper.make_graph(
        [helper.make_node("If", ["cond"], ["Y"], then_branch=then_branch, else_branch=else_branch)],
        "graph",
        [],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])],
        initializer=[condition],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    path = tmp_path / "nested_external.onnx"
    onnx.save(model, str(path))

    if not missing_external:
        external_file = tmp_path / external_path
        external_file.parent.mkdir(parents=True, exist_ok=True)
        external_file.write_bytes(struct.pack("f", 1.0))

    return path


def create_onnx_model_with_nested_external_sparse_initializer(
    tmp_path: Path,
    *,
    external_path: str,
    external_tensor: str = "values",
    missing_external: bool = False,
) -> Path:
    assert external_tensor in {"values", "indices"}
    values = (
        _make_external_tensor("nested_sparse_W", TensorProto.FLOAT, [1], external_path)
        if external_tensor == "values"
        else helper.make_tensor("nested_sparse_W", TensorProto.FLOAT, [1], vals=[1.0])
    )
    indices = (
        _make_external_tensor("nested_sparse_indices", TensorProto.INT64, [1], external_path)
        if external_tensor == "indices"
        else helper.make_tensor("nested_sparse_indices", TensorProto.INT64, [1], vals=[0])
    )
    sparse_tensor = helper.make_sparse_tensor(values, indices, [1])

    then_branch = helper.make_graph(
        [helper.make_node("Identity", ["nested_sparse_W"], ["Z"])],
        "then_branch",
        [],
        [helper.make_tensor_value_info("Z", TensorProto.FLOAT, [1])],
        sparse_initializer=[sparse_tensor],
    )
    else_branch = helper.make_graph(
        [helper.make_node("Identity", ["X"], ["Z"])],
        "else_branch",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1])],
        [helper.make_tensor_value_info("Z", TensorProto.FLOAT, [1])],
    )
    condition = helper.make_tensor("cond", TensorProto.BOOL, [], vals=[True])
    input_value = helper.make_tensor("X", TensorProto.FLOAT, [1], vals=[0.0])
    graph = helper.make_graph(
        [helper.make_node("If", ["cond"], ["Y"], then_branch=then_branch, else_branch=else_branch)],
        "graph",
        [],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])],
        initializer=[condition, input_value],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    path = tmp_path / "nested_sparse_external.onnx"
    onnx.save(model, str(path))

    if not missing_external:
        external_file = tmp_path / external_path
        external_file.parent.mkdir(parents=True, exist_ok=True)
        external_file.write_bytes(
            struct.pack("f" if external_tensor == "values" else "q", 1 if external_tensor == "values" else 0)
        )

    return path


def create_onnx_model_with_nested_external_tensor_attribute(
    tmp_path: Path,
    *,
    external_path: str,
    attribute_kind: str,
    external_tensor: str = "values",
    missing_external: bool = False,
) -> Path:
    assert attribute_kind in {"dense", "sparse"}
    assert external_tensor in {"values", "indices"}
    values = (
        _make_external_tensor("nested_attr_W", TensorProto.FLOAT, [1], external_path)
        if external_tensor == "values"
        else helper.make_tensor("nested_attr_W", TensorProto.FLOAT, [1], vals=[1.0])
    )
    indices = (
        _make_external_tensor("nested_attr_indices", TensorProto.INT64, [1], external_path)
        if external_tensor == "indices"
        else helper.make_tensor("nested_attr_indices", TensorProto.INT64, [1], vals=[0])
    )
    attribute = (
        {"value": values}
        if attribute_kind == "dense"
        else {"sparse_value": helper.make_sparse_tensor(values, indices, [1])}
    )

    then_branch = helper.make_graph(
        [helper.make_node("Constant", [], ["Z"], **attribute)],
        "then_branch",
        [],
        [helper.make_tensor_value_info("Z", TensorProto.FLOAT, [1])],
    )
    else_branch = helper.make_graph(
        [helper.make_node("Identity", ["X"], ["Z"])],
        "else_branch",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1])],
        [helper.make_tensor_value_info("Z", TensorProto.FLOAT, [1])],
    )
    condition = helper.make_tensor("cond", TensorProto.BOOL, [], vals=[True])
    input_value = helper.make_tensor("X", TensorProto.FLOAT, [1], vals=[0.0])
    graph = helper.make_graph(
        [helper.make_node("If", ["cond"], ["Y"], then_branch=then_branch, else_branch=else_branch)],
        "graph",
        [],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])],
        initializer=[condition, input_value],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    path = tmp_path / f"nested_{attribute_kind}_attribute_external.onnx"
    onnx.save(model, str(path))

    if not missing_external:
        external_file = tmp_path / external_path
        external_file.parent.mkdir(parents=True, exist_ok=True)
        external_file.write_bytes(
            struct.pack("f" if external_tensor == "values" else "q", 1 if external_tensor == "values" else 0)
        )

    return path


def create_onnx_model_with_function_default_external_tensor_attribute(
    tmp_path: Path,
    *,
    external_path: str,
    attribute_kind: str,
    external_tensor: str = "values",
    missing_external: bool = False,
    function_domain: str = "local",
    function_name: str = "ExternalDefault",
) -> Path:
    assert attribute_kind in {"dense", "sparse"}
    assert external_tensor in {"values", "indices"}
    values = (
        _make_external_tensor("default_W", TensorProto.FLOAT, [1], external_path)
        if external_tensor == "values"
        else helper.make_tensor("default_W", TensorProto.FLOAT, [1], vals=[1.0])
    )
    indices = (
        _make_external_tensor("default_indices", TensorProto.INT64, [1], external_path)
        if external_tensor == "indices"
        else helper.make_tensor("default_indices", TensorProto.INT64, [1], vals=[0])
    )
    attr_name = "default_value"
    attr_type = onnx.AttributeProto.TENSOR
    attr_value: Any = values
    node_attribute_name = "value"
    if attribute_kind == "sparse":
        attr_type = onnx.AttributeProto.SPARSE_TENSOR
        attr_value = helper.make_sparse_tensor(values, indices, [1])
        node_attribute_name = "sparse_value"
    node = helper.make_node("Constant", [], ["Y"])
    node.attribute.extend(
        [
            onnx.AttributeProto(
                name=node_attribute_name,
                ref_attr_name=attr_name,
                type=attr_type,
            )
        ]
    )
    function = helper.make_function(
        function_domain,
        function_name,
        [],
        ["Y"],
        [node],
        [helper.make_opsetid("", 13)],
        attribute_protos=[helper.make_attribute(attr_name, attr_value)],
    )
    graph = helper.make_graph(
        [helper.make_node(function_name, [], ["Y"], domain=function_domain)],
        "graph",
        [],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])],
    )
    model = helper.make_model(
        graph,
        functions=[function],
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid(function_domain, 1)],
    )
    model.ir_version = 9
    path = tmp_path / f"function_default_{attribute_kind}_external.onnx"
    onnx.save(model, str(path))

    if not missing_external:
        external_file = tmp_path / external_path
        external_file.parent.mkdir(parents=True, exist_ok=True)
        external_file.write_bytes(
            struct.pack("f" if external_tensor == "values" else "q", 1 if external_tensor == "values" else 0)
        )

    return path


def create_onnx_model_with_function_overload(
    tmp_path: Path,
    *,
    function_overload: str,
    call_overload: str,
) -> Path:
    function = helper.make_function(
        "local",
        "Transform",
        ["X"],
        ["Y"],
        [helper.make_node("Identity", ["X"], ["Y"])],
        [helper.make_opsetid("", 13)],
        overload=function_overload,
    )
    graph = helper.make_graph(
        [helper.make_node("Transform", ["X"], ["Y"], domain="local", overload=call_overload)],
        "graph",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])],
    )
    model = helper.make_model(
        graph,
        functions=[function],
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("local", 1)],
    )
    model.ir_version = 10
    path = tmp_path / f"function_overload_{function_overload}_{call_overload}.onnx"
    onnx.save(model, str(path))
    return path


def create_onnx_model_with_function_preview_operator(
    tmp_path: Path,
    *,
    include_unimported_model_preview: bool = False,
) -> Path:
    function = helper.make_function(
        "local",
        "PreviewWrapper",
        ["X"],
        ["Y"],
        [helper.make_node("FlexAttention", ["X"], ["Y"], domain="ai.onnx.preview")],
        [helper.make_opsetid("", 13), helper.make_opsetid("ai.onnx.preview", 1)],
    )
    graph_nodes = [helper.make_node("PreviewWrapper", ["X"], ["Y"], domain="local")]
    output_name = "Y"
    if include_unimported_model_preview:
        graph_nodes.append(helper.make_node("FlexAttention", ["Y"], ["Z"], domain="ai.onnx.preview"))
        output_name = "Z"
    graph = helper.make_graph(
        graph_nodes,
        "graph",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1])],
        [helper.make_tensor_value_info(output_name, TensorProto.FLOAT, [1])],
    )
    model = helper.make_model(
        graph,
        functions=[function],
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("local", 1)],
    )
    model.ir_version = 10
    path = tmp_path / "function_preview_operator.onnx"
    onnx.save(model, str(path))
    return path


def create_onnx_model_with_function_body_external_initializer(
    tmp_path: Path,
    *,
    external_path: str,
    missing_external: bool = False,
) -> Path:
    tensor = onnx.TensorProto()
    tensor.name = "function_W"
    tensor.data_type = TensorProto.FLOAT
    tensor.dims.append(1)
    tensor.data_location = onnx.TensorProto.EXTERNAL
    entry = StringStringEntryProto()
    entry.key = "location"
    entry.value = external_path
    tensor.external_data.append(entry)

    then_branch = helper.make_graph(
        [helper.make_node("Identity", ["function_W"], ["Z"])],
        "function_then_branch",
        [],
        [helper.make_tensor_value_info("Z", TensorProto.FLOAT, [1])],
        initializer=[tensor],
    )
    else_branch = helper.make_graph(
        [helper.make_node("Identity", ["X"], ["Z"])],
        "function_else_branch",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1])],
        [helper.make_tensor_value_info("Z", TensorProto.FLOAT, [1])],
    )
    if_node = helper.make_node(
        "If",
        ["cond"],
        ["Y"],
        then_branch=then_branch,
        else_branch=else_branch,
    )
    function = helper.make_function(
        "local",
        "SelectExternal",
        ["cond", "X"],
        ["Y"],
        [if_node],
        [helper.make_opsetid("", 13)],
    )
    condition = helper.make_tensor("cond", TensorProto.BOOL, [], vals=[True])
    input_value = helper.make_tensor("X", TensorProto.FLOAT, [1], vals=[0.0])
    graph = helper.make_graph(
        [helper.make_node("SelectExternal", ["cond", "X"], ["Y"], domain="local")],
        "graph",
        [],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])],
        initializer=[condition, input_value],
    )
    model = helper.make_model(
        graph,
        functions=[function],
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("local", 1)],
    )
    model.ir_version = 9
    path = tmp_path / "function_body_external.onnx"
    onnx.save(model, str(path))

    if not missing_external:
        external_file = tmp_path / external_path
        external_file.parent.mkdir(parents=True, exist_ok=True)
        external_file.write_bytes(struct.pack("f", 1.0))

    return path


def _failed_custom_domain_checks(result: Any) -> list[Any]:
    return [c for c in result.checks if c.name == "Custom Operator Domain Check" and c.status == CheckStatus.FAILED]


def _scan_and_extract_custom_domains(model_path: Path) -> tuple[Any, list[Any], list[str]]:
    scanner = OnnxScanner()
    result = scanner.scan(str(model_path))
    metadata = scanner.extract_metadata(str(model_path))
    custom_domains = metadata.get("custom_domains", [])
    return result, _failed_custom_domain_checks(result), custom_domains


def test_onnx_scanner_can_handle(tmp_path):
    model_path = create_onnx_model(tmp_path)
    assert OnnxScanner.can_handle(str(model_path))


def test_onnx_scanner_basic_model(tmp_path):
    model_path = create_onnx_model(tmp_path)
    scanner = OnnxScanner()
    result = scanner.scan(str(model_path))
    assert result.success
    assert result.bytes_scanned > 0
    assert not any(i.severity in (IssueSeverity.INFO, IssueSeverity.WARNING) for i in result.issues)


def test_onnx_scanner_unknown_only_payload_is_inconclusive(tmp_path: Path) -> None:
    model_path = tmp_path / "unknown-only.onnx"
    model_path.write_bytes(b"\x4a\x00" * 4097)

    result = OnnxScanner({"check_jit_script": False, "check_network_comm": False}).scan(str(model_path))

    assert result.success is False
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert ONNX_STRUCTURE_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    check = next(check for check in result.checks if check.name == "ONNX Structure Validation")
    assert check.status == CheckStatus.FAILED
    assert check.severity == IssueSeverity.INFO
    assert check.details["has_graph"] is False
    assert check.details["ir_version"] == 0


def test_onnx_scanner_tentative_protobuf_parse_failure_is_inconclusive(tmp_path: Path) -> None:
    model_path = tmp_path / "ambiguous.jpg"
    model_path.write_bytes(b"\x12\x05oops")
    scanner = OnnxScanner(
        {
            FORMAT_VALIDATION_CONFIG_KEY: {"routed_format": PROTOBUF_MODEL_CANDIDATE_FORMAT},
            "check_jit_script": False,
            "check_network_comm": False,
        }
    )

    result = scanner.scan(str(model_path))

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.bytes_scanned == model_path.stat().st_size
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["tentative_protobuf_candidate_unanalyzed"] == "onnx_parse_failed"
    assert "onnx_tentative_candidate_parse_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(issue.severity == IssueSeverity.INFO for issue in result.issues)


def test_onnx_scanner_tentative_invalid_version_still_detects_python_operator(tmp_path: Path) -> None:
    model_path = create_python_onnx_model(tmp_path)
    model = onnx.load(str(model_path))
    model.ir_version = 0
    onnx.save(model, str(model_path))
    scanner = OnnxScanner({FORMAT_VALIDATION_CONFIG_KEY: {"routed_format": PROTOBUF_MODEL_CANDIDATE_FORMAT}})

    result = scanner.scan(str(model_path))

    assert result.scanner_name == "onnx"
    assert result.success is False
    assert ONNX_STRUCTURE_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    assert any(issue.details.get("op_type") == "PythonOp" for issue in result.issues)


def test_onnx_scanner_reuses_raw_bytes_for_model_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful scans should parse from the raw detector buffer."""
    model_path = create_onnx_model(tmp_path)
    parsed_payloads: list[bytes] = []
    real_load_model_from_string = onnx.load_model_from_string

    def fail_path_loader(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("path-based ONNX parsing should not run after the raw read succeeds")

    def tracking_load_model_from_string(payload: bytes) -> Any:
        parsed_payloads.append(payload)
        return real_load_model_from_string(payload)

    monkeypatch.setattr(onnx, "load", fail_path_loader)
    monkeypatch.setattr(onnx, "load_model_from_string", tracking_load_model_from_string)

    result = OnnxScanner({"check_jit_script": False, "check_network_comm": False}).scan(str(model_path))

    assert result.success
    assert parsed_payloads == [model_path.read_bytes()]


def test_onnx_scanner_raw_read_failure_falls_back_to_path_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Raw-detector read failures should keep structural parsing but fail closed."""
    model_path = create_onnx_model(tmp_path)
    real_load = onnx.load
    raw_read_attempts = 0
    path_loads: list[str] = []

    def fail_first_raw_read(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        nonlocal raw_read_attempts
        if mode == "rb" and raw_read_attempts == 0:
            raw_read_attempts += 1
            raise OSError("simulated raw read failure")
        return open(file, mode, *args, **kwargs)

    def tracking_path_loader(path: str, *, load_external_data: bool) -> Any:
        path_loads.append(path)
        return real_load(path, load_external_data=load_external_data)

    monkeypatch.setattr("modelaudit.scanners.onnx_scanner.open", fail_first_raw_read, raising=False)
    monkeypatch.setattr(onnx, "load", tracking_path_loader)

    result = OnnxScanner({"check_jit_script": False, "check_network_comm": False}).scan(str(model_path))
    coverage_checks = [check for check in result.checks if check.name == "Raw Detector Analysis Coverage"]

    assert path_loads == [str(model_path)]
    assert result.success is False
    assert result.bytes_scanned > 0
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["detector"] == "raw_file_read"
    assert coverage_checks[0].details["coverage_gap"] == "file_read_failed"


def test_onnx_scanner_custom_op(tmp_path: Path) -> None:
    model_path = create_onnx_model(tmp_path, custom=True)
    result = OnnxScanner().scan(str(model_path))
    assert any("custom operator" in i.message.lower() for i in result.issues)


def test_onnx_scanner_standard_ai_onnx_ml_domain_not_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="ai.onnx.ml",
        custom_op_type="LinearRegressor",
    )
    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)
    assert len(custom_domain_checks) == 0, (
        f"Expected no custom-domain finding for ai.onnx.ml. Checks: {[c.message for c in result.checks]}"
    )
    assert "ai.onnx.ml" not in metadata_custom_domains


def test_onnx_scanner_standard_preview_training_domain_not_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="ai.onnx.preview.training",
        custom_op_type="Adam",
    )
    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)
    assert len(custom_domain_checks) == 0, (
        f"Expected no custom-domain finding for ai.onnx.preview.training. Checks: {[c.message for c in result.checks]}"
    )
    assert "ai.onnx.preview.training" not in metadata_custom_domains


def test_onnx_scanner_registered_ai_onnx_preview_operator_not_flagged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def registered_schema(op_type: str, version: int, domain: str) -> bool:
        return (domain, op_type, version) == ("ai.onnx.preview", "FlexAttention", 1)

    monkeypatch.setattr("modelaudit.scanners.onnx_scanner._has_operator_schema", registered_schema)
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="ai.onnx.preview",
        custom_op_type="FlexAttention",
        custom_opset_version=1,
    )
    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)
    assert len(custom_domain_checks) == 0, (
        f"Expected no custom-domain finding for ai.onnx.preview. Checks: {[c.message for c in result.checks]}"
    )
    assert "ai.onnx.preview" not in metadata_custom_domains


def test_onnx_scanner_unknown_ai_onnx_preview_operator_still_flagged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.scanners.onnx_scanner._has_operator_schema", lambda *_args: False)
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="ai.onnx.preview",
        custom_op_type="UnknownKernel",
        custom_opset_version=1,
    )

    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert len(custom_domain_checks) == 1
    assert custom_domain_checks[0].rule_code == "S1111"
    assert custom_domain_checks[0].details["op_type"] == "UnknownKernel"
    assert "ai.onnx.preview" in metadata_custom_domains


def test_onnx_scanner_preview_schema_rejects_nonempty_overload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def registered_schema(op_type: str, version: int, domain: str) -> bool:
        return (domain, op_type, version) == ("ai.onnx.preview", "FlexAttention", 1)

    monkeypatch.setattr("modelaudit.scanners.onnx_scanner._has_operator_schema", registered_schema)
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="ai.onnx.preview",
        custom_op_type="FlexAttention",
        custom_opset_version=1,
    )
    model = onnx.load(str(model_path))
    model.graph.node[0].overload = "unregistered"
    onnx.save(model, str(model_path))

    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert len(custom_domain_checks) == 1
    assert custom_domain_checks[0].rule_code == "S1111"
    assert "ai.onnx.preview" in metadata_custom_domains


def test_onnx_scanner_function_body_uses_function_opset_imports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def registered_schema(op_type: str, version: int, domain: str) -> bool:
        return (domain, op_type, version) == ("ai.onnx.preview", "FlexAttention", 1)

    monkeypatch.setattr("modelaudit.scanners.onnx_scanner._has_operator_schema", registered_schema)
    model_path = create_onnx_model_with_function_preview_operator(tmp_path)

    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert custom_domain_checks == []
    assert "ai.onnx.preview" not in metadata_custom_domains


def test_onnx_scanner_function_opset_does_not_authorize_model_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def registered_schema(op_type: str, version: int, domain: str) -> bool:
        return (domain, op_type, version) == ("ai.onnx.preview", "FlexAttention", 1)

    monkeypatch.setattr("modelaudit.scanners.onnx_scanner._has_operator_schema", registered_schema)
    model_path = create_onnx_model_with_function_preview_operator(
        tmp_path,
        include_unimported_model_preview=True,
    )

    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert len(custom_domain_checks) == 1
    assert custom_domain_checks[0].rule_code == "S1111"
    assert custom_domain_checks[0].details["op_type"] == "FlexAttention"
    assert "ai.onnx.preview" in metadata_custom_domains


def test_onnx_scanner_model_local_function_not_flagged_as_external(tmp_path: Path) -> None:
    model_path = create_onnx_model_with_function_default_external_tensor_attribute(
        tmp_path,
        external_path="weights.bin",
        attribute_kind="dense",
        function_domain="ai.onnx.contrib",
        function_name="custom_op",
    )

    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert custom_domain_checks == []
    assert result.metadata.get("custom_domains", []) == []
    assert "ai.onnx.contrib" not in metadata_custom_domains
    assert not [issue for issue in result.issues if issue.details.get("type") == "custom_operator"]


def test_onnx_scanner_matching_model_local_function_overload_not_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model_with_function_overload(
        tmp_path,
        function_overload="float",
        call_overload="float",
    )

    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert result.success is True
    assert custom_domain_checks == []
    assert "local" not in metadata_custom_domains


def test_onnx_scanner_mismatched_model_local_function_overload_still_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model_with_function_overload(
        tmp_path,
        function_overload="float",
        call_overload="integer",
    )

    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert len(custom_domain_checks) == 1
    assert custom_domain_checks[0].rule_code == "S1111"
    assert custom_domain_checks[0].details["op_type"] == "Transform"
    assert custom_domain_checks[0].details["domain"] == "local"
    assert "local" in metadata_custom_domains


def test_onnx_scanner_custom_domain_still_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="com.evil.ops",
        custom_op_type="BackdoorOp",
    )
    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)
    assert len(custom_domain_checks) > 0, "Expected custom domain finding for com.evil.ops"
    assert any(c.details.get("domain") == "com.evil.ops" for c in custom_domain_checks)
    assert all(c.rule_code == "S1111" for c in custom_domain_checks)
    assert all(c.severity == IssueSeverity.INFO for c in custom_domain_checks)
    assert "com.evil.ops" in result.metadata["custom_domains"]
    assert "com.evil.ops" in metadata_custom_domains


def test_onnx_scanner_custom_operator_emits_one_domain_rule(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="ai.onnx.contrib",
        custom_op_type="custom_op",
    )

    result = OnnxScanner().scan(str(model_path))
    custom_operator_issues = [issue for issue in result.issues if issue.rule_code == "S1111"]

    assert len(custom_operator_issues) == 1
    assert custom_operator_issues[0].severity == IssueSeverity.INFO
    assert custom_operator_issues[0].details["domain"] == "ai.onnx.contrib"
    assert not [issue for issue in result.issues if issue.details.get("type") == "custom_operator"]
    assert not any(issue.rule_code == "S510" for issue in result.issues)


def test_onnx_scanner_ai_onnx_ml_subdomain_still_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="ai.onnx.ml.malicious",
        custom_op_type="BackdoorOp",
    )
    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)
    assert len(custom_domain_checks) > 0, "Expected non-standard ai.onnx.ml subdomain to be flagged"
    assert any(c.details.get("domain") == "ai.onnx.ml.malicious" for c in custom_domain_checks)
    assert "ai.onnx.ml.malicious" in metadata_custom_domains


def test_onnx_scanner_ai_onnx_training_domain_still_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="ai.onnx.training",
        custom_op_type="BackdoorOp",
    )
    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)
    assert len(custom_domain_checks) > 0, "Expected non-standard ai.onnx.training domain to be flagged"
    assert any(c.details.get("domain") == "ai.onnx.training" for c in custom_domain_checks)
    assert "ai.onnx.training" in metadata_custom_domains


def test_onnx_scanner_external_data_missing(tmp_path: Path) -> None:
    """Missing external data file should produce a WARNING-level issue."""
    model_path = create_onnx_model(tmp_path, external=True, missing_external=True)
    result = OnnxScanner().scan(str(model_path))
    missing_checks = [
        c for c in result.checks if c.name == "External Data Reference Check" and "file may not be present" in c.message
    ]
    assert len(missing_checks) > 0, f"Should flag missing external data. Checks: {[c.message for c in result.checks]}"
    assert missing_checks[0].severity == IssueSeverity.WARNING


def test_onnx_scanner_external_data_exists(tmp_path: Path) -> None:
    """Existing external data file within model dir should produce INFO-level issue."""
    model_path = create_onnx_model(tmp_path, external=True, external_path="weights.bin")
    result = OnnxScanner().scan(str(model_path))
    resolved_checks = [
        c for c in result.checks if c.name == "External Data Reference Check" and "resolved successfully" in c.message
    ]
    assert len(resolved_checks) > 0, (
        f"Should report resolved external data. Checks: {[c.message for c in result.checks]}"
    )
    assert resolved_checks[0].severity == IssueSeverity.INFO
    assert resolved_checks[0].status.value == "passed"


def test_onnx_scanner_corrupted(tmp_path: Path) -> None:
    model_path = create_onnx_model(tmp_path)
    data = model_path.read_bytes()
    # truncate file to corrupt it
    model_path.write_bytes(data[:10])
    result = OnnxScanner().scan(str(model_path))
    assert not result.success or any(i.severity == IssueSeverity.INFO for i in result.issues)


def test_onnx_scanner_python_op(tmp_path: Path) -> None:
    model_path = create_python_onnx_model(tmp_path)
    result = OnnxScanner().scan(str(model_path))
    assert result.success is False
    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)
    assert any(i.details.get("op_type") == "PythonOp" for i in result.issues)


def test_onnx_scanner_pyfunc_operator_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(tmp_path, custom=True, custom_domain="", custom_op_type="PyFunc")

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    python_op_checks = [
        c for c in result.checks if c.name == "Python Operator Detection" and c.status == CheckStatus.FAILED
    ]
    assert len(python_op_checks) > 0
    assert python_op_checks[0].severity == IssueSeverity.CRITICAL
    assert python_op_checks[0].details.get("op_type") == "PyFunc"


def test_onnx_scanner_camel_case_python_op_wrapper_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="com.example",
        custom_op_type="MyPythonOp",
    )

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        c.name == "Python Operator Detection"
        and c.status == CheckStatus.FAILED
        and c.details.get("op_type") == "MyPythonOp"
        for c in result.checks
    )


@pytest.mark.parametrize("custom_op_type", ["MY_PYTHON_OP", "MY_PY_FUNC"])
def test_onnx_scanner_uppercase_snake_python_op_wrapper_flagged(tmp_path: Path, custom_op_type: str) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="com.example",
        custom_op_type=custom_op_type,
    )

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        c.name == "Python Operator Detection"
        and c.status == CheckStatus.FAILED
        and c.details.get("op_type") == custom_op_type
        for c in result.checks
    )


def test_onnx_scanner_python_substring_near_match_not_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="",
        custom_op_type="MyPythonOptimizer",
    )

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not [c for c in result.checks if c.name == "Python Operator Detection" and c.status == CheckStatus.FAILED]


def test_onnx_scanner_python_doc_string_metadata_not_flagged_as_python_operator(tmp_path: Path) -> None:
    model_path = create_onnx_model(tmp_path)
    model = onnx.load(str(model_path), load_external_data=False)
    model.doc_string = "Generated by Python training utilities"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not [
        issue
        for issue in result.issues
        if issue.details.get("type") == "python_operator" or "Python operator" in issue.message
    ]
    assert not [c for c in result.checks if c.name == "JIT Script Detection" and c.status == CheckStatus.FAILED]


def test_onnx_scanner_uppercase_snake_python_near_match_not_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="",
        custom_op_type="MY_PYTHON_OPTIMIZER",
    )

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not [c for c in result.checks if c.name == "Python Operator Detection" and c.status == CheckStatus.FAILED]


def _save_model_with_int8_weight(tmp_path: Path, weight_bytes: bytes, *, extra_node: Any = None) -> Path:
    """Build a clean ai.onnx-only model whose int8 initializer holds ``weight_bytes``."""
    weight = helper.make_tensor("W", TensorProto.INT8, [len(weight_bytes)], weight_bytes, raw=True)
    scale = helper.make_tensor("scale", TensorProto.FLOAT, [], [1.0])
    zero_point = helper.make_tensor("zp", TensorProto.INT8, [], [0])
    nodes = [helper.make_node("DequantizeLinear", ["W", "scale", "zp"], ["Y"], name="dq")]
    if extra_node is not None:
        nodes.append(extra_node)
    graph = helper.make_graph(
        nodes,
        "quant_graph",
        [],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [len(weight_bytes)])],
        initializer=[weight, scale, zero_point],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    path = tmp_path / "model.onnx"
    onnx.save(model, str(path))
    return path


def _python_operator_issues(result: Any) -> list[Any]:
    return [
        issue
        for issue in result.issues
        if issue.details.get("type") == "python_operator" or "Python operator" in issue.message
    ]


# Bytes "PyOp" (0x50 0x79 0x4F 0x70) bracketed by non-alphanumeric bytes: a
# realistic byte run inside quantized int8 weight data that the raw-byte JIT
# regex matches case-insensitively. See GitHub issue #1254.
_PYOP_WEIGHT_BYTES = bytes([0x00, 0x50, 0x79, 0x4F, 0x70, 0x00, 0x01, 0x02])


def test_onnx_scanner_skips_graph_confirmation_without_python_operator_candidate() -> None:
    accessed: list[bool] = []

    class UnreadableModel:
        @property
        def graph(self) -> Any:
            accessed.append(True)
            raise RuntimeError("graph should not be inspected")

    findings = [{"type": "embedded_script", "content": "harmless"}]

    assert _confirmed_python_operator_findings(findings, UnreadableModel()) == findings
    assert accessed == []


def test_onnx_scanner_custom_operator_confirmation_fails_closed() -> None:
    class UnreadableModel:
        @property
        def graph(self) -> Any:
            raise RuntimeError("operator inventory unavailable")

    findings = [{"type": "custom_operator", "message": "Custom ONNX operator detected"}]

    assert _confirmed_onnx_operator_findings(findings, UnreadableModel()) == findings


def test_onnx_scanner_custom_operator_confirmation_keeps_finding_without_graph() -> None:
    findings = [{"type": "custom_operator", "message": "Custom ONNX operator detected"}]

    assert _confirmed_onnx_operator_findings(findings, onnx.ModelProto()) == findings


def test_onnx_scanner_pyop_bytes_in_weight_data_not_flagged(tmp_path: Path) -> None:
    """A clean ai.onnx-only model is not flagged when weight bytes spell 'PyOp'."""
    model_path = _save_model_with_int8_weight(tmp_path, _PYOP_WEIGHT_BYTES)

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert _python_operator_issues(result) == []


@pytest.mark.parametrize(
    "weight_bytes",
    [b"\x00custom_op\x00", b"\x00ai.onnx.contrib\x00"],
    ids=["custom-op-marker", "contrib-domain-marker"],
)
def test_onnx_scanner_custom_op_marker_in_weight_data_not_flagged(tmp_path: Path, weight_bytes: bytes) -> None:
    """Raw custom-op marker bytes in weights do not imply a graph operator."""
    model_path = _save_model_with_int8_weight(tmp_path, weight_bytes)

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not [issue for issue in result.issues if issue.details.get("type") == "custom_operator"]
    assert not [check for check in result.checks if check.rule_code == "S1111" and check.status == CheckStatus.FAILED]


def test_onnx_scanner_explicit_custom_op_in_standard_domain_still_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="",
        custom_op_type="custom_op",
    )

    result = OnnxScanner().scan(str(model_path))
    custom_operator_issues = [issue for issue in result.issues if issue.rule_code == "S1111"]

    assert len(custom_operator_issues) == 1
    assert custom_operator_issues[0].severity == IssueSeverity.INFO
    assert custom_operator_issues[0].details["op_type"] == "custom_op"


def test_onnx_scanner_real_pyop_node_still_flagged_despite_weight_bytes(tmp_path: Path) -> None:
    """A genuine PyOp node stays CRITICAL even when weight bytes also spell 'PyOp'."""
    pyop_node = helper.make_node("PyOp", ["Y"], ["Z"], name="evil", domain="com.attacker")
    model_path = _save_model_with_int8_weight(tmp_path, _PYOP_WEIGHT_BYTES, extra_node=pyop_node)

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    python_operator_issues = _python_operator_issues(result)
    assert python_operator_issues
    assert all(issue.severity == IssueSeverity.CRITICAL for issue in python_operator_issues)


def test_onnx_scanner_subgraph_pyop_still_flagged(tmp_path: Path) -> None:
    """A PyOp hidden inside an If-branch subgraph is still detected."""
    then_branch = helper.make_graph(
        [helper.make_node("PyOp", ["X"], ["Z"], domain="com.attacker")],
        "then",
        [],
        [helper.make_tensor_value_info("Z", TensorProto.FLOAT, [1])],
    )
    else_branch = helper.make_graph(
        [helper.make_node("Identity", ["X"], ["Z"])],
        "else",
        [],
        [helper.make_tensor_value_info("Z", TensorProto.FLOAT, [1])],
    )
    if_node = helper.make_node("If", ["cond"], ["Y"], then_branch=then_branch, else_branch=else_branch)
    graph = helper.make_graph(
        [if_node],
        "graph",
        [
            helper.make_tensor_value_info("cond", TensorProto.BOOL, []),
            helper.make_tensor_value_info("X", TensorProto.FLOAT, [1]),
        ],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])],
    )
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("com.attacker", 1)],
    )
    model.ir_version = 8
    model_path = tmp_path / "subgraph.onnx"
    onnx.save(model, str(model_path))

    scanner = OnnxScanner()
    result = scanner.scan(str(model_path))
    metadata = scanner.extract_metadata(str(model_path))

    assert result.success is False
    python_operator_issues = _python_operator_issues(result)
    assert python_operator_issues
    assert all(issue.severity == IssueSeverity.CRITICAL for issue in python_operator_issues)
    assert result.metadata["custom_domains"] == ["com.attacker"]
    assert metadata["custom_domains"] == ["com.attacker"]
    assert all(check.rule_code == "S1111" for check in _failed_custom_domain_checks(result))


def test_onnx_scanner_subgraph_snake_python_op_still_flagged(tmp_path: Path) -> None:
    """A nested structural Python op must not depend on the raw-byte detector."""
    then_branch = helper.make_graph(
        [helper.make_node("Python_Op", ["X"], ["Z"])],
        "then",
        [],
        [helper.make_tensor_value_info("Z", TensorProto.FLOAT, [1])],
    )
    else_branch = helper.make_graph(
        [helper.make_node("Identity", ["X"], ["Z"])],
        "else",
        [],
        [helper.make_tensor_value_info("Z", TensorProto.FLOAT, [1])],
    )
    graph = helper.make_graph(
        [helper.make_node("If", ["cond"], ["Y"], then_branch=then_branch, else_branch=else_branch)],
        "graph",
        [
            helper.make_tensor_value_info("cond", TensorProto.BOOL, []),
            helper.make_tensor_value_info("X", TensorProto.FLOAT, [1]),
        ],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    model_path = tmp_path / "subgraph_snake_python_op.onnx"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        check.name == "Python Operator Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("op_type") == "Python_Op"
        for check in result.checks
    )


def test_onnx_scanner_function_default_graph_python_op_still_flagged(tmp_path: Path) -> None:
    """A Python op in a graph-valued function default must be inspected."""
    then_branch = helper.make_graph(
        [helper.make_node("Python_Op", ["X"], ["Y"])],
        "then",
        [],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])],
    )
    else_branch = helper.make_graph(
        [helper.make_node("Identity", ["X"], ["Y"])],
        "else",
        [],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])],
    )
    if_node = helper.make_node("If", ["cond"], ["Y"])
    if_node.attribute.extend(
        [
            onnx.AttributeProto(
                name="then_branch",
                ref_attr_name="then_graph",
                type=onnx.AttributeProto.GRAPH,
            ),
            onnx.AttributeProto(
                name="else_branch",
                ref_attr_name="else_graph",
                type=onnx.AttributeProto.GRAPH,
            ),
        ]
    )
    function = helper.make_function(
        "local",
        "Select",
        ["cond", "X"],
        ["Y"],
        [if_node],
        [helper.make_opsetid("", 13)],
        attribute_protos=[
            helper.make_attribute("then_graph", then_branch),
            helper.make_attribute("else_graph", else_branch),
        ],
    )
    graph = helper.make_graph(
        [helper.make_node("Select", ["cond", "X"], ["Y"], domain="local")],
        "graph",
        [
            helper.make_tensor_value_info("cond", TensorProto.BOOL, []),
            helper.make_tensor_value_info("X", TensorProto.FLOAT, [1]),
        ],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])],
    )
    model = helper.make_model(
        graph,
        functions=[function],
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("local", 1)],
    )
    model.ir_version = 9
    onnx.checker.check_model(model)
    model_path = tmp_path / "function_default_graph_python_op.onnx"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        check.name == "Python Operator Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("op_type") == "Python_Op"
        for check in result.checks
    )


@pytest.mark.parametrize("training_graph_field", ["initialization", "algorithm"])
def test_onnx_scanner_training_graph_pyop_still_flagged(tmp_path: Path, training_graph_field: str) -> None:
    """A PyOp in either training graph must not be discarded as weight-data noise."""
    model_path = _save_model_with_int8_weight(tmp_path, _PYOP_WEIGHT_BYTES)
    model = onnx.load(str(model_path))
    training_info = onnx.TrainingInfoProto()
    getattr(training_info, training_graph_field).CopyFrom(
        helper.make_graph(
            [helper.make_node("PyOp", ["X"], ["Y"], domain="com.attacker")],
            f"training_{training_graph_field}",
            [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1])],
            [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])],
        )
    )
    model.training_info.append(training_info)
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    python_operator_issues = _python_operator_issues(result)
    assert python_operator_issues
    assert all(issue.severity == IssueSeverity.CRITICAL for issue in python_operator_issues)


class TestCVE202551480SavePathTraversal:
    """Tests for CVE-2025-51480: ONNX save_external_data arbitrary file overwrite."""

    def test_traversal_detected_as_write_vuln(self, tmp_path: Path) -> None:
        """Path traversal in external_data should trigger CVE-2025-51480 (write direction)."""
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="../../../tmp/overwrite_target",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if "CVE-2025-51480" in c.name or "CVE-2025-51480" in c.message]
        assert len(cve_checks) > 0, (
            f"Should detect CVE-2025-51480 write traversal. Checks: {[c.message for c in result.checks]}"
        )
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details.get("cve_id") == "CVE-2025-51480"
        # Traversal should be classified as CVE traversal, not a simple reference.
        assert all(c.name != "External Data Reference Check" for c in result.checks)
        assert all("External Data Reference Check" not in c.message for c in result.checks)

    def test_nested_traversal_triggers_write_vuln(self, tmp_path: Path) -> None:
        """Nested traversal (lstrip bypass) should also be detected for write direction."""
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="subdir/../../overwrite_target",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2025-51480"]
        assert len(cve_checks) > 0, "Nested traversal should trigger write CVE too"

    def test_safe_path_no_write_vuln(self, tmp_path: Path) -> None:
        """Safe external data should not trigger CVE-2025-51480."""
        model_path = create_onnx_model(tmp_path, external=True, external_path="weights.bin")

        result = OnnxScanner().scan(str(model_path))

        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2025-51480"]
        assert len(cve_checks) == 0, "Safe paths should not trigger write CVE"

    def test_normalized_in_dir_path_with_dotdot_no_write_vuln(self, tmp_path: Path) -> None:
        """Paths containing '..' but resolving in-dir should not be tagged as CVE-2025-51480."""
        # We create the real target file in-dir, but build the ONNX with an external_data
        # reference of "subdir/../weights.bin" and `missing_external=True` so the model keeps
        # the external reference metadata while the resolved path still lands inside model_dir.
        (tmp_path / "weights.bin").write_bytes(struct.pack("f", 1.0))
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="subdir/../weights.bin",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2025-51480"]
        assert len(cve_checks) == 0, "Normalized in-dir path should not trigger write CVE"

    def test_absolute_sibling_path_triggers_write_vuln(self, tmp_path: Path) -> None:
        """Absolute sibling path should still be flagged as out-of-dir traversal."""
        sibling_dir = tmp_path.parent / f"{tmp_path.name}_evil"
        sibling_dir.mkdir(parents=True, exist_ok=True)
        sibling_file = sibling_dir / "weights.bin"
        sibling_file.write_bytes(struct.pack("f", 1.0))

        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path=str(sibling_file),
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))
        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2025-51480"]
        assert len(cve_checks) > 0, "Absolute sibling path must be detected as traversal"

    def test_write_vuln_details_fields(self, tmp_path: Path) -> None:
        """CVE-2025-51480 details should include cve_id, cvss, cwe, remediation."""
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="../overwrite_me",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2025-51480"]
        assert len(cve_checks) > 0
        details = cve_checks[0].details
        assert details["cvss"] == 8.8
        assert details["cwe"] == "CWE-22"
        assert "remediation" in details


class TestCVE202634447SymlinkTraversal:
    """Tests for CVE-2026-34447: ONNX external_data symlink traversal."""

    def test_symlink_escape_detected(self, tmp_path: Path, requires_symlinks: None) -> None:
        outside_dir = tmp_path.parent / f"{tmp_path.name}_outside"
        outside_dir.mkdir(parents=True, exist_ok=True)
        outside_weights = outside_dir / "weights.bin"
        outside_weights.write_bytes(struct.pack("f", 1.0))
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights.bin",
            missing_external=True,
        )
        (tmp_path / "weights.bin").symlink_to(outside_weights)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2026-34447"]
        assert len(cve_checks) == 1
        details = cve_checks[0].details
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert details["cvss"] == 5.5
        assert details["cwe"] == "CWE-22"
        assert "remediation" in details
        assert details["resolved_path"] == str(outside_weights.resolve())
        assert not [c for c in result.checks if c.details.get("cve_id") == "CVE-2025-51480"]
        assert not [c for c in result.checks if c.details.get("cve_id") == "CVE-2024-27318"]
        assert not [c for c in result.checks if c.details.get("cve_id") == "CVE-2022-25882"]

    def test_symlink_inside_model_dir_not_flagged(self, tmp_path: Path, requires_symlinks: None) -> None:
        safe_weights = tmp_path / "safe_payload.bin"
        safe_weights.write_bytes(struct.pack("f", 1.0))
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights.bin",
            missing_external=True,
        )
        (tmp_path / "weights.bin").symlink_to(safe_weights)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert not [c for c in result.checks if c.details.get("cve_id") == "CVE-2026-34447"]
        traversal_checks = [
            c for c in result.checks if c.status == CheckStatus.FAILED and "traversal" in c.message.lower()
        ]
        assert traversal_checks == []

    def test_broken_symlink_inside_model_dir_is_missing_external_data_not_cve(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights.bin",
            missing_external=True,
        )
        (tmp_path / "weights.bin").symlink_to(tmp_path / "missing_weights.bin")

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert not [c for c in result.checks if c.details.get("cve_id") == "CVE-2026-34447"]
        assert not [c for c in result.checks if c.details.get("cve_id") == "CVE-2025-51480"]
        missing_checks = [
            c for c in result.checks if c.name == "External Data Reference Check" and c.status == CheckStatus.FAILED
        ]
        assert len(missing_checks) == 1
        assert missing_checks[0].severity == IssueSeverity.WARNING

    def test_broken_symlink_escape_detected_without_target_file(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights.bin",
            missing_external=True,
        )
        missing_outside_weights = tmp_path.parent / f"{tmp_path.name}_missing_weights.bin"
        (tmp_path / "weights.bin").symlink_to(missing_outside_weights)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2026-34447"]
        assert len(cve_checks) == 1
        details = cve_checks[0].details
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert details["resolved_path"] == str(missing_outside_weights.resolve())
        assert not [c for c in result.checks if c.details.get("cve_id") == "CVE-2025-51480"]


class TestCVE202427318NestedPathTraversal:
    """Tests for CVE-2024-27318: ONNX nested path traversal bypass."""

    def test_nested_traversal_detected(self, tmp_path: Path) -> None:
        """Nested traversal like 'subdir/../../etc/passwd' should trigger CVE-2024-27318."""
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="subdir/../../etc/passwd",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if "CVE-2024-27318" in c.name or "CVE-2024-27318" in c.message]
        assert len(cve_checks) > 0, (
            f"Should detect CVE-2024-27318 nested traversal. Checks: {[c.message for c in result.checks]}"
        )
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details.get("cve_id") == "CVE-2024-27318"

    def test_direct_traversal_attributed_to_cve_2022(self, tmp_path: Path) -> None:
        """Direct traversal like '../../etc/passwd' should be CVE-2022-25882."""
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="../../etc/passwd",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2022-25882"]
        assert len(cve_checks) > 0, (
            f"Direct traversal should be CVE-2022-25882. Checks: {[(c.name, c.details) for c in result.checks]}"
        )

    def test_nested_traversal_nonexistent_target_still_detected(self, tmp_path: Path) -> None:
        """Traversal to non-existent paths should still be flagged (not just 'file not found')."""
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="data/../../../nonexistent/secret",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        # Should NOT be just a "file not found" - should be path traversal
        traversal_checks = [c for c in result.checks if "traversal" in c.message.lower() or "CVE-" in c.name]
        assert len(traversal_checks) > 0, (
            f"Nested traversal should be detected even for non-existent targets. "
            f"Checks: {[c.message for c in result.checks]}"
        )

    def test_safe_external_data_no_traversal_flag(self, tmp_path: Path) -> None:
        """Legitimate external data should not be flagged as traversal."""
        model_path = create_onnx_model(tmp_path, external=True, external_path="weights.bin")

        result = OnnxScanner().scan(str(model_path))

        traversal_checks = [
            c for c in result.checks if "traversal" in c.message.lower() and c.status == CheckStatus.FAILED
        ]
        assert len(traversal_checks) == 0, "Safe paths should not trigger traversal alerts"

    def test_normalized_in_dir_path_with_dotdot_no_traversal_flag(self, tmp_path: Path) -> None:
        """A path containing '..' that resolves in-dir should not be flagged as traversal."""
        (tmp_path / "weights.bin").write_bytes(struct.pack("f", 1.0))
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="subdir/../weights.bin",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        traversal_checks = [
            c for c in result.checks if "traversal" in c.message.lower() and c.status == CheckStatus.FAILED
        ]
        assert len(traversal_checks) == 0, "Normalized in-dir paths should not trigger traversal alerts"

    def test_nested_traversal_details_contain_cwe(self, tmp_path: Path) -> None:
        """CVE-2024-27318 details should include CWE-22."""
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights/../../../tmp/exfil",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2024-27318"]
        assert len(cve_checks) > 0
        assert cve_checks[0].details["cwe"] == "CWE-22"
        assert cve_checks[0].details["cvss"] == 7.5

    def test_nested_graph_initializer_traversal_detected(self, tmp_path: Path) -> None:
        model_path = create_onnx_model_with_nested_external_initializer(
            tmp_path,
            external_path="weights/../../../tmp/exfil",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2024-27318"]
        assert len(cve_checks) > 0
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details["tensor"] == "nested_W"

    @pytest.mark.parametrize(
        ("external_tensor", "tensor_name"),
        [("values", "nested_sparse_W"), ("indices", "nested_sparse_indices")],
    )
    def test_nested_graph_sparse_initializer_traversal_detected(
        self,
        tmp_path: Path,
        external_tensor: str,
        tensor_name: str,
    ) -> None:
        model_path = create_onnx_model_with_nested_external_sparse_initializer(
            tmp_path,
            external_path="weights/../../../tmp/exfil",
            external_tensor=external_tensor,
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2024-27318"]
        assert len(cve_checks) > 0
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details["tensor"] == tensor_name

    @pytest.mark.parametrize(
        ("attribute_kind", "external_tensor", "tensor_name"),
        [
            ("dense", "values", "nested_attr_W"),
            ("sparse", "values", "nested_attr_W"),
            ("sparse", "indices", "nested_attr_indices"),
        ],
    )
    def test_nested_graph_tensor_attribute_traversal_detected(
        self,
        tmp_path: Path,
        attribute_kind: str,
        external_tensor: str,
        tensor_name: str,
    ) -> None:
        model_path = create_onnx_model_with_nested_external_tensor_attribute(
            tmp_path,
            external_path="weights/../../../tmp/exfil",
            attribute_kind=attribute_kind,
            external_tensor=external_tensor,
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2024-27318"]
        assert len(cve_checks) > 0
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details["tensor"] == tensor_name

    @pytest.mark.parametrize(
        ("attribute_kind", "external_tensor", "tensor_name"),
        [
            ("dense", "values", "default_W"),
            ("sparse", "values", "default_W"),
            ("sparse", "indices", "default_indices"),
        ],
    )
    def test_function_default_tensor_attribute_traversal_detected(
        self,
        tmp_path: Path,
        attribute_kind: str,
        external_tensor: str,
        tensor_name: str,
    ) -> None:
        model_path = create_onnx_model_with_function_default_external_tensor_attribute(
            tmp_path,
            external_path="weights/../../../tmp/exfil",
            attribute_kind=attribute_kind,
            external_tensor=external_tensor,
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2024-27318"]
        assert len(cve_checks) > 0
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details["tensor"] == tensor_name

    def test_nested_graph_initializer_in_dir_dotdot_not_flagged(self, tmp_path: Path) -> None:
        (tmp_path / "nested_weights.bin").write_bytes(struct.pack("f", 1.0))
        model_path = create_onnx_model_with_nested_external_initializer(
            tmp_path,
            external_path="weights/../nested_weights.bin",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        traversal_checks = [
            c for c in result.checks if c.status == CheckStatus.FAILED and "traversal" in c.message.lower()
        ]
        assert traversal_checks == []
        size_checks = [
            c for c in result.checks if c.name == "External Data Size Validation" and c.status == CheckStatus.PASSED
        ]
        assert len(size_checks) > 0
        assert size_checks[0].details["tensor"] == "nested_W"

    def test_nested_graph_sparse_initializer_in_dir_dotdot_not_flagged(self, tmp_path: Path) -> None:
        model_path = create_onnx_model_with_nested_external_sparse_initializer(
            tmp_path,
            external_path="weights/../nested_weights.bin",
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        traversal_checks = [
            c for c in result.checks if c.status == CheckStatus.FAILED and "traversal" in c.message.lower()
        ]
        assert traversal_checks == []
        size_checks = [
            c for c in result.checks if c.name == "External Data Size Validation" and c.status == CheckStatus.PASSED
        ]
        assert len(size_checks) > 0
        assert size_checks[0].details["tensor"] == "nested_sparse_W"

    def test_nested_graph_sparse_attribute_in_dir_dotdot_not_flagged(self, tmp_path: Path) -> None:
        model_path = create_onnx_model_with_nested_external_tensor_attribute(
            tmp_path,
            external_path="weights/../nested_weights.bin",
            attribute_kind="sparse",
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        traversal_checks = [
            c for c in result.checks if c.status == CheckStatus.FAILED and "traversal" in c.message.lower()
        ]
        assert traversal_checks == []
        size_checks = [
            c for c in result.checks if c.name == "External Data Size Validation" and c.status == CheckStatus.PASSED
        ]
        assert len(size_checks) > 0
        assert size_checks[0].details["tensor"] == "nested_attr_W"

    def test_function_default_sparse_attribute_in_dir_dotdot_not_flagged(self, tmp_path: Path) -> None:
        model_path = create_onnx_model_with_function_default_external_tensor_attribute(
            tmp_path,
            external_path="weights/../nested_weights.bin",
            attribute_kind="sparse",
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        traversal_checks = [
            c for c in result.checks if c.status == CheckStatus.FAILED and "traversal" in c.message.lower()
        ]
        assert traversal_checks == []
        size_checks = [
            c for c in result.checks if c.name == "External Data Size Validation" and c.status == CheckStatus.PASSED
        ]
        assert len(size_checks) > 0
        assert size_checks[0].details["tensor"] == "default_W"

    def test_nested_graph_initializer_missing_external_data_reported(self, tmp_path: Path) -> None:
        model_path = create_onnx_model_with_nested_external_initializer(
            tmp_path,
            external_path="missing_nested_weights.bin",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        missing_checks = [
            c for c in result.checks if c.name == "External Data Reference Check" and c.status == CheckStatus.FAILED
        ]
        assert len(missing_checks) == 1
        assert missing_checks[0].severity == IssueSeverity.WARNING
        assert missing_checks[0].details["sample_tensors"] == ["nested_W"]

    def test_function_body_initializer_traversal_detected(self, tmp_path: Path) -> None:
        model_path = create_onnx_model_with_function_body_external_initializer(
            tmp_path,
            external_path="weights/../../../tmp/exfil",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2024-27318"]
        assert len(cve_checks) > 0
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details["tensor"] == "function_W"

    def test_function_body_initializer_in_dir_dotdot_not_flagged(self, tmp_path: Path) -> None:
        model_path = create_onnx_model_with_function_body_external_initializer(
            tmp_path,
            external_path="weights/../function_weights.bin",
        )

        result = OnnxScanner().scan(str(model_path))

        traversal_checks = [
            c for c in result.checks if c.status == CheckStatus.FAILED and "traversal" in c.message.lower()
        ]
        assert traversal_checks == []
        size_checks = [
            c for c in result.checks if c.name == "External Data Size Validation" and c.status == CheckStatus.PASSED
        ]
        assert len(size_checks) > 0
        assert size_checks[0].details["tensor"] == "function_W"

    def test_windows_absolute_path_is_flagged_on_posix_hosts(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path=r"C:\\Windows\\System32\\drivers\\etc\\hosts",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2022-25882"]
        assert len(cve_checks) > 0
        assert all(c.name != "External Data Reference Check" for c in result.checks)


class TestExternalDataSizeValidation:
    """Tests for external_data offset/length and dtype validation."""

    @staticmethod
    def _set_initializer_data_type(model_path: Path, data_type: int) -> None:
        model = onnx.load(str(model_path), load_external_data=False)
        model.graph.initializer[0].data_type = data_type
        onnx.save(model, str(model_path))

    def test_offset_past_remaining_data_fails_size_validation(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights.bin",
            external_metadata={"offset": "4"},
            external_file_bytes=struct.pack("ff", 1.0, 2.0),
            tensor_shape=(2,),
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        size_checks = [
            c for c in result.checks if c.name == "External Data Size Validation" and c.status == CheckStatus.FAILED
        ]
        assert len(size_checks) > 0
        assert size_checks[0].severity == IssueSeverity.CRITICAL
        assert size_checks[0].details["offset"] == 4
        assert size_checks[0].details["expected_size"] == 8

    def test_offset_and_length_covering_tensor_passes_size_validation(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights.bin",
            external_metadata={"offset": "4", "length": "8"},
            external_file_bytes=struct.pack("fff", 0.0, 1.0, 2.0),
            tensor_shape=(2,),
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        size_checks = [
            c for c in result.checks if c.name == "External Data Size Validation" and c.status == CheckStatus.PASSED
        ]
        assert len(size_checks) > 0
        assert size_checks[0].details["offset"] == 4
        assert size_checks[0].details["length"] == 8

    def test_external_data_size_validation_uses_current_onnx_dtype_api(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(tmp_path, external=True, external_path="weights.bin")

        result = OnnxScanner().scan(str(model_path))

        size_checks = [c for c in result.checks if c.name == "External Data Size Validation"]
        assert len(size_checks) > 0
        assert size_checks[0].status == CheckStatus.PASSED

    def test_unknown_external_data_dtype_is_inconclusive(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(tmp_path, external=True, external_path="weights.bin")
        self._set_initializer_data_type(model_path, 9999)

        direct = OnnxScanner().scan(str(model_path))
        aggregate = scan_model_directory_or_file(str(model_path), recursive=False)
        metadata = next(iter(aggregate.file_metadata.values()))

        assert direct.success is False
        assert direct.has_errors is False
        assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "onnx_structure_validation_failed" in direct.metadata["scan_outcome_reasons"]
        size_checks = [
            c for c in direct.checks if c.name == "External Data Size Validation" and c.status == CheckStatus.FAILED
        ]
        assert len(size_checks) > 0
        assert size_checks[0].severity == IssueSeverity.INFO
        assert size_checks[0].details["data_type"] == 9999
        assert aggregate.success is False
        assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert determine_exit_code(aggregate) == 2
        assert not any(issue.severity == IssueSeverity.CRITICAL for issue in aggregate.issues)

    def test_unknown_external_data_dtype_preserves_security_exit1(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(
            tmp_path,
            custom=True,
            custom_domain="",
            custom_op_type="PyFunc",
            external=True,
            external_path="weights.bin",
        )
        self._set_initializer_data_type(model_path, 9999)

        direct = OnnxScanner().scan(str(model_path))
        aggregate = scan_model_directory_or_file(str(model_path), recursive=False)

        assert direct.success is False
        assert direct.has_errors is True
        assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in aggregate.issues)
        assert determine_exit_code(aggregate) == 1

    def test_invalid_offset_metadata_fails_size_validation(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights.bin",
            external_metadata={"offset": "NaN"},
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        size_checks = [
            c for c in result.checks if c.name == "External Data Size Validation" and c.status == CheckStatus.FAILED
        ]
        assert len(size_checks) > 0
        assert size_checks[0].severity == IssueSeverity.CRITICAL
        assert "invalid" in size_checks[0].message.lower()

    def test_negative_offset_metadata_fails_size_validation(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights.bin",
            external_metadata={"offset": "-1"},
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        size_checks = [
            c for c in result.checks if c.name == "External Data Size Validation" and c.status == CheckStatus.FAILED
        ]
        assert len(size_checks) > 0
        assert size_checks[0].severity == IssueSeverity.CRITICAL
        assert "non-negative" in size_checks[0].message.lower()


class TestWeightDistributionCoverage:
    """Tests for ONNX weight-distribution analysis coverage gaps."""

    _INCONCLUSIVE_REASON = "onnx_weight_distribution_analysis_incomplete"

    @staticmethod
    def _coverage_checks(result: Any) -> list[Any]:
        return [c for c in result.checks if c.name == "Weight Distribution Analysis Coverage"]

    def _assert_uncached_inconclusive_exit2(self, model_path: Path, cache_dir: Path, **scan_kwargs: Any) -> None:
        reset_cache_manager()
        try:
            first_result = scan_model_directory_or_file(
                str(model_path),
                recursive=False,
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
                **scan_kwargs,
            )
            second_result = scan_model_directory_or_file(
                str(model_path),
                recursive=False,
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
                **scan_kwargs,
            )
            metadata = second_result.file_metadata[str(model_path)]

            assert first_result.success is False
            assert second_result.success is False
            assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
            assert self._INCONCLUSIVE_REASON in metadata.get("scan_outcome_reasons", [])
            assert determine_exit_code(first_result) == 2
            assert determine_exit_code(second_result) == 2
            assert not any(issue.severity == IssueSeverity.CRITICAL for issue in second_result.issues)
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_missing_weight_distribution_dependency_ignores_model_without_initializers(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        model_path = create_onnx_model(tmp_path, include_initializer=False)
        monkeypatch.setitem(sys.modules, "scipy", None)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert self._coverage_checks(result) == []

    def test_missing_weight_distribution_dependency_ignores_1d_only_initializers(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        model_path = create_onnx_model(tmp_path, tensor_shape=(4,))
        monkeypatch.setitem(sys.modules, "scipy", None)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert self._coverage_checks(result) == []

    def test_missing_weight_distribution_dependency_is_inconclusive(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        model_path = create_onnx_model(tmp_path, tensor_shape=(2, 2))
        monkeypatch.setitem(sys.modules, "scipy", None)

        result = OnnxScanner().scan(str(model_path))

        coverage_checks = self._coverage_checks(result)
        assert result.success is False
        assert result.has_errors is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert self._INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
        assert len(coverage_checks) == 1
        assert coverage_checks[0].status == CheckStatus.FAILED
        assert coverage_checks[0].severity == IssueSeverity.INFO
        assert "Weight distribution analysis dependency unavailable:" in coverage_checks[0].message
        assert coverage_checks[0].details["coverage_gap"] == "missing_dependency"
        self._assert_uncached_inconclusive_exit2(model_path, tmp_path / "cache")

    def test_external_weight_distribution_tensors_are_inconclusive(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights.bin",
            external_file_bytes=struct.pack("ffff", 1.0, 2.0, 3.0, 4.0),
            tensor_shape=(2, 2),
        )

        result = OnnxScanner().scan(str(model_path))

        coverage_checks = self._coverage_checks(result)
        assert result.success is False
        assert result.has_errors is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert self._INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
        assert len(coverage_checks) == 1
        assert (
            coverage_checks[0].message == "Weight distribution analysis skipped one or more eligible ONNX initializers"
        )
        assert coverage_checks[0].details["coverage_gap"] == "partial_initializer_coverage"
        assert coverage_checks[0].details["eligible_initializers"] == 1
        assert coverage_checks[0].details["external_initializers_skipped"] == 1
        assert coverage_checks[0].details["analyzed_initializers"] == 0
        self._assert_uncached_inconclusive_exit2(model_path, tmp_path / "cache")

    def test_oversized_weight_distribution_tensors_are_inconclusive(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(tmp_path, tensor_shape=(2, 2))

        result = OnnxScanner({"max_array_size": 1}).scan(str(model_path))

        coverage_checks = self._coverage_checks(result)
        assert result.success is False
        assert result.has_errors is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert self._INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
        assert len(coverage_checks) == 1
        assert (
            coverage_checks[0].message == "Weight distribution analysis skipped one or more eligible ONNX initializers"
        )
        assert coverage_checks[0].details["coverage_gap"] == "partial_initializer_coverage"
        assert coverage_checks[0].details["eligible_initializers"] == 1
        assert coverage_checks[0].details["oversized_initializers_skipped"] == 1
        assert coverage_checks[0].details["analyzed_initializers"] == 0
        self._assert_uncached_inconclusive_exit2(model_path, tmp_path / "cache", max_array_size=1)


class TestRawDetectorCoverage:
    """Tests for ONNX raw JIT/network detector coverage gaps."""

    _INCONCLUSIVE_REASON = "onnx_raw_detection_analysis_incomplete"

    @staticmethod
    def _coverage_checks(result: Any) -> list[Any]:
        return [c for c in result.checks if c.name == "Raw Detector Analysis Coverage"]

    def _assert_inconclusive_exit2(self, model_path: Path, direct: Any, *, detector: str) -> None:
        aggregate = scan_model_directory_or_file(str(model_path), recursive=False)
        metadata = next(iter(aggregate.file_metadata.values()))
        coverage_checks = self._coverage_checks(direct)

        assert direct.success is False
        assert direct.has_errors is False
        assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert self._INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
        assert len(coverage_checks) == 1
        assert coverage_checks[0].status == CheckStatus.FAILED
        assert coverage_checks[0].severity == IssueSeverity.INFO
        assert coverage_checks[0].details["coverage_gap"] == "analysis_failed"
        assert coverage_checks[0].details["detector"] == detector
        assert aggregate.success is False
        assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert self._INCONCLUSIVE_REASON in metadata.get("scan_outcome_reasons", [])
        assert determine_exit_code(aggregate) == 2
        assert not any(issue.severity == IssueSeverity.CRITICAL for issue in aggregate.issues)

    def test_jit_detector_failure_is_inconclusive(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        model_path = create_onnx_model(tmp_path)
        leaked_secret = "UNSTRUCTURED-ONNX-JIT-SECRET-123456"

        def _raise_analysis_failure(self: JITScriptDetector, *_args: Any, **_kwargs: Any) -> list[Any]:
            raise RuntimeError(f"jit detector rejected {leaked_secret}")

        monkeypatch.setattr(JITScriptDetector, "scan_model", _raise_analysis_failure)

        direct = OnnxScanner().scan(str(model_path))
        self._assert_inconclusive_exit2(model_path, direct, detector="jit_script")
        coverage_check = self._coverage_checks(direct)[0]
        assert leaked_secret not in str(direct.metadata)
        assert leaked_secret not in coverage_check.message
        assert leaked_secret not in str(coverage_check.details)
        assert leaked_secret not in caplog.text
        assert "<redacted>" in coverage_check.message

    def test_network_detector_failure_is_inconclusive(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        model_path = create_onnx_model(tmp_path)
        leaked_secret = "UNSTRUCTURED-ONNX-NETWORK-SECRET-123456"

        def _raise_analysis_failure(self: NetworkCommDetector, *_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
            raise RuntimeError(f"network detector rejected {leaked_secret}")

        monkeypatch.setattr(NetworkCommDetector, "scan", _raise_analysis_failure)

        direct = OnnxScanner().scan(str(model_path))
        self._assert_inconclusive_exit2(model_path, direct, detector="network_communication")
        coverage_check = self._coverage_checks(direct)[0]
        assert leaked_secret not in str(direct.metadata)
        assert leaked_secret not in coverage_check.message
        assert leaked_secret not in str(coverage_check.details)
        assert leaked_secret not in caplog.text
        assert "<redacted>" in coverage_check.message
