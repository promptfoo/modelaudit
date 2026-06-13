import json
import os
import struct
import sys
from pathlib import Path
from typing import Any

import pytest

# Skip if onnx is not available before importing it
pytest.importorskip("onnx")

import numpy as np
import onnx
from onnx import TensorProto, helper
from onnx.onnx_ml_pb2 import StringStringEntryProto

import modelaudit.core as modelaudit_core
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file, scan_model_streaming
from modelaudit.detectors.jit_script import JITScriptDetector
from modelaudit.detectors.network_comm import NetworkCommDetector
from modelaudit.integrations.sarif_formatter import format_sarif_output
from modelaudit.scanners.base import FORMAT_VALIDATION_CONFIG_KEY, INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.onnx_scanner import (
    ONNX_SCHEMA_INCONCLUSIVE_REASON,
    ONNX_STRUCTURE_INCONCLUSIVE_REASON,
    ONNX_WEIGHT_DISTRIBUTION_INCONCLUSIVE_REASON,
    OnnxScanner,
    _configured_onnx_weight_array_limit,
    _confirmed_onnx_operator_findings,
    _confirmed_python_operator_findings,
)
from modelaudit.scanners.weight_distribution_scanner import WeightDistributionScanner
from modelaudit.utils.file.detection import PROTOBUF_MODEL_CANDIDATE_FORMAT
from modelaudit.utils.helpers.file_hash import compute_sha256_hash
from modelaudit.utils.helpers.secure_hasher import compute_aggregate_hash


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


def assert_only_onnx_external_schema_validation_skipped(result: Any) -> None:
    schema_issues = [
        issue
        for issue in result.issues
        if issue.details.get("schema_validation_reason") == ONNX_SCHEMA_INCONCLUSIVE_REASON
        and issue.details.get("checker_available") is True
        and issue.details.get("external_data_present") is True
    ]
    assert len(schema_issues) == 1
    assert result.issues == schema_issues
    assert result.success is False


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
    initializer_consumer: str | None = None,
    custom_opset_version: int | None = None,
    custom_uses_initializer: bool = False,
) -> Path:
    X = helper.make_tensor_value_info("input", TensorProto.FLOAT, list(tensor_shape) or [1])
    Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, list(tensor_shape) or [1])
    if initializer_consumer is not None:
        node = helper.make_node(initializer_consumer, ["input", "W"], ["output"], name="weighted")
    elif custom:
        node = helper.make_node(
            custom_op_type,
            ["input", "W"] if custom_uses_initializer else ["input"],
            ["output"],
            domain=custom_domain,
            name="custom",
        )
    else:
        node = helper.make_node("Relu", ["input"], ["output"], name="relu")

    initializers: list[Any] = []
    if include_initializer and external:
        tensor = _make_external_tensor("W", TensorProto.FLOAT, list(tensor_shape), external_path)
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


def create_onnx_weight_model(
    tmp_path: Path,
    weights: np.ndarray,
    *,
    op_type: str,
    trans_b: bool = False,
    filename: str = "weighted.onnx",
) -> Path:
    """Create a small valid ONNX graph with the supplied initializer consumer."""
    weight_tensor = onnx.numpy_helper.from_array(weights, name="W")
    if op_type == "Gemm":
        input_features = weights.shape[1] if trans_b else weights.shape[0]
        output_features = weights.shape[0] if trans_b else weights.shape[1]
        X = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, input_features])
        Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, output_features])
        node = helper.make_node("Gemm", ["input", "W"], ["output"], name="linear", transB=int(trans_b))
    elif op_type == "MatMul":
        X = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, weights.shape[0]])
        Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, weights.shape[1]])
        node = helper.make_node("MatMul", ["input", "W"], ["output"], name="linear")
    elif op_type == "Gather":
        X = helper.make_tensor_value_info("input", TensorProto.INT64, [1])
        Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, weights.shape[1]])
        node = helper.make_node("Gather", ["W", "input"], ["output"], name="embedding")
    elif op_type == "MatMulInteger":
        X = helper.make_tensor_value_info("input", TensorProto.INT8, [1, weights.shape[0]])
        Y = helper.make_tensor_value_info("output", TensorProto.INT32, [1, weights.shape[1]])
        node = helper.make_node("MatMulInteger", ["input", "W"], ["output"], name="quantized_linear")
    elif op_type in {"Add", "Mul"}:
        X = helper.make_tensor_value_info("input", TensorProto.FLOAT, list(weights.shape))
        Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, list(weights.shape))
        node = helper.make_node(op_type, ["input", "W"], ["output"], name="bookkeeping")
    else:  # pragma: no cover - test helper guard
        raise AssertionError(f"unsupported test operator: {op_type}")

    graph = helper.make_graph([node], "weighted_graph", [X], [Y], initializer=[weight_tensor])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    path = tmp_path / filename
    onnx.save(model, str(path))
    return path


def create_transformed_onnx_weight_model(
    tmp_path: Path,
    analysis_weights: np.ndarray,
    *,
    transform: str,
) -> Path:
    """Create a MatMul whose weight reaches it through one intermediate operator."""
    assert transform in {
        "Identity",
        "Transpose",
        "Reshape",
        "ReshapeDynamic",
        "AddDynamic",
        "Cast",
        "CastFloat16",
    }
    initializers: list[Any] = []
    if transform == "Transpose":
        stored_weights = analysis_weights.T.copy()
    elif transform == "Reshape":
        stored_weights = analysis_weights.reshape(10, 10, analysis_weights.shape[1]).copy()
    else:
        stored_weights = analysis_weights.copy()
    initializers.append(onnx.numpy_helper.from_array(stored_weights, name="W"))

    if transform == "Identity":
        transform_node = helper.make_node("Identity", ["W"], ["W_view"], name="weight_identity")
    elif transform == "Transpose":
        transform_node = helper.make_node(
            "Transpose",
            ["W"],
            ["W_view"],
            name="weight_transpose",
            perm=[1, 0],
        )
    elif transform == "Reshape":
        shape = np.asarray(analysis_weights.shape, dtype=np.int64)
        initializers.append(onnx.numpy_helper.from_array(shape, name="weight_shape"))
        transform_node = helper.make_node(
            "Reshape",
            ["W", "weight_shape"],
            ["W_view"],
            name="weight_reshape",
        )
    elif transform == "ReshapeDynamic":
        transform_node = helper.make_node(
            "Reshape",
            ["W", "dynamic_shape"],
            ["W_view"],
            name="dynamic_weight_reshape",
        )
    elif transform == "AddDynamic":
        transform_node = helper.make_node(
            "Add",
            ["W", "dynamic_delta"],
            ["W_view"],
            name="dynamic_weight_add",
        )
    else:
        transform_node = helper.make_node(
            "Cast",
            ["W"],
            ["W_view"],
            name="weight_cast",
            to=TensorProto.FLOAT16 if transform == "CastFloat16" else TensorProto.FLOAT,
        )

    value_type = TensorProto.FLOAT16 if transform == "CastFloat16" else TensorProto.FLOAT
    X = helper.make_tensor_value_info("input", value_type, [1, analysis_weights.shape[0]])
    Y = helper.make_tensor_value_info("output", value_type, [1, analysis_weights.shape[1]])
    graph_inputs = [X]
    if transform == "ReshapeDynamic":
        graph_inputs.append(helper.make_tensor_value_info("dynamic_shape", TensorProto.INT64, [2]))
    elif transform == "AddDynamic":
        graph_inputs.append(
            helper.make_tensor_value_info("dynamic_delta", TensorProto.FLOAT, list(analysis_weights.shape))
        )
    matmul = helper.make_node("MatMul", ["input", "W_view"], ["output"], name="linear")
    graph = helper.make_graph(
        [transform_node, matmul],
        "transformed_weight_graph",
        graph_inputs,
        [Y],
        initializer=initializers,
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / f"{transform.lower()}-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_training_transformed_weight_model(tmp_path: Path, *, transform: str) -> Path:
    analysis_weights = np.zeros((100, 10), dtype=np.float32)
    analysis_weights[50:55, 3] = 10.0
    if transform == "Reshape":
        initializers = [
            onnx.numpy_helper.from_array(analysis_weights.reshape(-1), name="W"),
            onnx.numpy_helper.from_array(np.asarray(analysis_weights.shape, dtype=np.int64), name="shape"),
        ]
        transform_nodes = [helper.make_node("Reshape", ["W", "shape"], ["X"])]
    elif transform == "Cast":
        initializers = [onnx.numpy_helper.from_array(analysis_weights.astype(np.int64), name="W")]
        transform_nodes = [helper.make_node("Cast", ["W"], ["X"], to=TensorProto.FLOAT)]
    elif transform == "CastReshape":
        initializers = [
            onnx.numpy_helper.from_array(analysis_weights.astype(np.int64).reshape(-1), name="W"),
            onnx.numpy_helper.from_array(np.asarray(analysis_weights.shape, dtype=np.int64), name="shape"),
        ]
        transform_nodes = [
            helper.make_node("Cast", ["W"], ["W_float"], to=TensorProto.FLOAT),
            helper.make_node("Reshape", ["W_float", "shape"], ["X"]),
        ]
    else:
        raise ValueError(f"Unsupported transform: {transform}")

    main_input = helper.make_tensor_value_info("main_input", TensorProto.FLOAT, [1])
    main_output = helper.make_tensor_value_info("main_output", TensorProto.FLOAT, [1])
    main_graph = helper.make_graph(
        [helper.make_node("Identity", ["main_input"], ["main_output"])],
        "main_graph",
        [main_input],
        [main_output],
    )
    adam = helper.make_node(
        "Adam",
        ["R", "T", "X", "G", "V", "H"],
        ["X_new", "V_new", "H_new"],
        domain="ai.onnx.preview.training",
    )
    algorithm = helper.make_graph(
        [*transform_nodes, adam],
        "transformed_training_weight",
        [
            helper.make_tensor_value_info("R", TensorProto.FLOAT, []),
            helper.make_tensor_value_info("T", TensorProto.INT64, []),
            helper.make_tensor_value_info("G", TensorProto.FLOAT, [100, 10]),
            helper.make_tensor_value_info("V", TensorProto.FLOAT, [100, 10]),
            helper.make_tensor_value_info("H", TensorProto.FLOAT, [100, 10]),
        ],
        [
            helper.make_tensor_value_info("X_new", TensorProto.FLOAT, [100, 10]),
            helper.make_tensor_value_info("V_new", TensorProto.FLOAT, [100, 10]),
            helper.make_tensor_value_info("H_new", TensorProto.FLOAT, [100, 10]),
        ],
        initializer=initializers,
    )
    training_info = onnx.TrainingInfoProto()
    training_info.algorithm.CopyFrom(algorithm)
    model = helper.make_model(
        main_graph,
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("ai.onnx.preview.training", 1)],
    )
    model.ir_version = 8
    model.training_info.append(training_info)
    onnx.checker.check_model(model)
    path = tmp_path / f"training-{transform.lower()}-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_nonweight_transformed_matmul_model(tmp_path: Path, *, transform: str) -> Path:
    weights = np.zeros((10, 10), dtype=np.float32)
    weights[3:8, 4] = 10.0
    if transform == "Reshape":
        initializers = [
            onnx.numpy_helper.from_array(weights, name="W"),
            onnx.numpy_helper.from_array(np.asarray([100], dtype=np.int64), name="shape"),
        ]
        nodes = [
            helper.make_node("Reshape", ["W", "shape"], ["W_view"]),
            helper.make_node("MatMul", ["X", "W_view"], ["Y"]),
        ]
        graph_inputs = [helper.make_tensor_value_info("X", TensorProto.FLOAT, [100])]
        graph_outputs = [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [])]
    elif transform == "Cast":
        initializers = [onnx.numpy_helper.from_array(weights, name="W")]
        nodes = [
            helper.make_node("Cast", ["W"], ["W_view"], to=TensorProto.INT64),
            helper.make_node("MatMul", ["X", "W_view"], ["Y"]),
        ]
        graph_inputs = [helper.make_tensor_value_info("X", TensorProto.INT64, [1, 10])]
        graph_outputs = [helper.make_tensor_value_info("Y", TensorProto.INT64, [1, 10])]
    else:
        raise ValueError(f"Unsupported transform: {transform}")

    graph = helper.make_graph(nodes, "nonweight_transform", graph_inputs, graph_outputs, initializer=initializers)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / f"nonweight-{transform.lower()}.onnx"
    onnx.save(model, str(path))
    return path


def create_zipmap_classifier_model(tmp_path: Path) -> Path:
    weights = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="W")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
    map_type = helper.make_map_type_proto(
        TensorProto.INT64,
        helper.make_tensor_type_proto(TensorProto.FLOAT, []),
    )
    probabilities = helper.make_value_info("probabilities", helper.make_sequence_type_proto(map_type))
    nodes = [
        helper.make_node("MatMul", ["X", "W"], ["logits"]),
        helper.make_node(
            "ZipMap",
            ["logits"],
            ["probabilities"],
            domain="ai.onnx.ml",
            classlabels_int64s=list(range(10)),
        ),
    ]
    graph = helper.make_graph(nodes, "zipmap_classifier", [X], [probabilities], initializer=[weights])
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("ai.onnx.ml", 3)],
    )
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "zipmap-classifier.onnx"
    onnx.save(model, str(path))
    return path


def create_training_info_weight_model(tmp_path: Path) -> Path:
    main_input = helper.make_tensor_value_info("main_input", TensorProto.FLOAT, [1])
    main_output = helper.make_tensor_value_info("main_output", TensorProto.FLOAT, [1])
    main_graph = helper.make_graph(
        [helper.make_node("Identity", ["main_input"], ["main_output"])],
        "main_graph",
        [main_input],
        [main_output],
    )

    weights = np.zeros((100, 10), dtype=np.float32)
    weights[50:55, 3] = 10.0
    algorithm_inputs = [
        helper.make_tensor_value_info("R", TensorProto.FLOAT, []),
        helper.make_tensor_value_info("T", TensorProto.INT64, []),
        helper.make_tensor_value_info("G", TensorProto.FLOAT, [100, 10]),
        helper.make_tensor_value_info("V", TensorProto.FLOAT, [100, 10]),
        helper.make_tensor_value_info("H", TensorProto.FLOAT, [100, 10]),
    ]
    algorithm_outputs = [
        helper.make_tensor_value_info("X_new", TensorProto.FLOAT, [100, 10]),
        helper.make_tensor_value_info("V_new", TensorProto.FLOAT, [100, 10]),
        helper.make_tensor_value_info("H_new", TensorProto.FLOAT, [100, 10]),
    ]
    algorithm = helper.make_graph(
        [
            helper.make_node(
                "Adam",
                ["R", "T", "X", "G", "V", "H"],
                ["X_new", "V_new", "H_new"],
                domain="ai.onnx.preview.training",
            )
        ],
        "training_algorithm",
        algorithm_inputs,
        algorithm_outputs,
        initializer=[onnx.numpy_helper.from_array(weights, name="X")],
    )
    training_info = onnx.TrainingInfoProto()
    training_info.algorithm.CopyFrom(algorithm)
    model = helper.make_model(
        main_graph,
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("ai.onnx.preview.training", 1)],
    )
    model.ir_version = 8
    model.training_info.append(training_info)
    onnx.checker.check_model(model)
    path = tmp_path / "training-info-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_cross_training_info_weight_model(tmp_path: Path) -> Path:
    main_input = helper.make_tensor_value_info("main_input", TensorProto.FLOAT, [1])
    main_output = helper.make_tensor_value_info("main_output", TensorProto.FLOAT, [1])
    main_graph = helper.make_graph(
        [helper.make_node("Identity", ["main_input"], ["main_output"])],
        "main_graph",
        [main_input],
        [main_output],
    )

    weights = np.zeros((100, 10), dtype=np.float32)
    weights[50:55, 3] = 10.0
    first_algorithm = helper.make_graph(
        [helper.make_node("Identity", ["W"], ["W_seeded"])],
        "first_training_algorithm",
        [],
        [helper.make_tensor_value_info("W_seeded", TensorProto.FLOAT, [100, 10])],
        initializer=[onnx.numpy_helper.from_array(weights, name="W")],
    )
    first_training_info = onnx.TrainingInfoProto()
    first_training_info.algorithm.CopyFrom(first_algorithm)
    first_binding = first_training_info.update_binding.add()
    first_binding.key = "W"
    first_binding.value = "W_seeded"

    second_algorithm = helper.make_graph(
        [
            helper.make_node(
                "Adam",
                ["R", "T", "W", "G", "V", "H"],
                ["W_updated", "V_updated", "H_updated"],
                domain="ai.onnx.preview.training",
            )
        ],
        "second_training_algorithm",
        [
            helper.make_tensor_value_info("R", TensorProto.FLOAT, []),
            helper.make_tensor_value_info("T", TensorProto.INT64, []),
            helper.make_tensor_value_info("G", TensorProto.FLOAT, [100, 10]),
            helper.make_tensor_value_info("V", TensorProto.FLOAT, [100, 10]),
            helper.make_tensor_value_info("H", TensorProto.FLOAT, [100, 10]),
        ],
        [
            helper.make_tensor_value_info("W_updated", TensorProto.FLOAT, [100, 10]),
            helper.make_tensor_value_info("V_updated", TensorProto.FLOAT, [100, 10]),
            helper.make_tensor_value_info("H_updated", TensorProto.FLOAT, [100, 10]),
        ],
    )
    second_training_info = onnx.TrainingInfoProto()
    second_training_info.algorithm.CopyFrom(second_algorithm)
    second_binding = second_training_info.update_binding.add()
    second_binding.key = "W"
    second_binding.value = "W_updated"

    model = helper.make_model(
        main_graph,
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("ai.onnx.preview.training", 1)],
    )
    model.ir_version = 8
    model.training_info.extend([first_training_info, second_training_info])
    onnx.checker.check_model(model)
    path = tmp_path / "cross-training-info-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_training_initialization_reset_model(tmp_path: Path) -> Path:
    main_input = helper.make_tensor_value_info("main_input", TensorProto.FLOAT, [1])
    main_output = helper.make_tensor_value_info("main_output", TensorProto.FLOAT, [1])
    main_weights = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="W")
    main_graph = helper.make_graph(
        [helper.make_node("Identity", ["main_input"], ["main_output"])],
        "main_graph",
        [main_input],
        [main_output],
        initializer=[main_weights],
    )

    reset_weights = np.zeros((100, 10), dtype=np.float32)
    reset_weights[50:55, 3] = 10.0
    reset_tensor = onnx.numpy_helper.from_array(reset_weights, name="reset_value")
    initialization = helper.make_graph(
        [helper.make_node("Constant", [], ["W_reset"], value=reset_tensor)],
        "training_initialization",
        [],
        [helper.make_tensor_value_info("W_reset", TensorProto.FLOAT, [100, 10])],
    )
    training_info = onnx.TrainingInfoProto()
    training_info.initialization.CopyFrom(initialization)
    binding = training_info.initialization_binding.add()
    binding.key = "W"
    binding.value = "W_reset"

    model = helper.make_model(main_graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    model.training_info.append(training_info)
    onnx.checker.check_model(model)
    path = tmp_path / "training-initialization-reset.onnx"
    onnx.save(model, str(path))
    return path


def create_read_only_main_initializer_training_model(tmp_path: Path) -> Path:
    main_input = helper.make_tensor_value_info("main_input", TensorProto.FLOAT, [1])
    main_output = helper.make_tensor_value_info("main_output", TensorProto.FLOAT, [1])
    weights = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="W")
    main_graph = helper.make_graph(
        [helper.make_node("Identity", ["main_input"], ["main_output"])],
        "main_graph",
        [main_input],
        [main_output],
        initializer=[weights],
    )
    algorithm = helper.make_graph(
        [helper.make_node("Identity", ["W"], ["snapshot"])],
        "read_only_training_algorithm",
        [],
        [helper.make_tensor_value_info("snapshot", TensorProto.FLOAT, [100, 10])],
    )
    training_info = onnx.TrainingInfoProto()
    training_info.algorithm.CopyFrom(algorithm)
    model = helper.make_model(main_graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    model.training_info.append(training_info)
    onnx.checker.check_model(model)
    path = tmp_path / "read-only-main-initializer-training.onnx"
    onnx.save(model, str(path))
    return path


def create_non_weight_training_update_model(
    tmp_path: Path,
    *,
    data_type: int,
    op_type: str,
    shape: tuple[int, ...] = (),
    opset_version: int = 13,
) -> Path:
    numpy_dtype = (
        np.bool_ if data_type == TensorProto.BOOL else np.float32 if data_type == TensorProto.FLOAT else np.int64
    )
    state = onnx.numpy_helper.from_array(np.ones(shape, dtype=numpy_dtype), name="state")
    algorithm_initializers = []
    if op_type in {
        "BitwiseNot",
        "Celu",
        "Gelu",
        "Hardmax",
        "LogSoftmax",
        "LpNormalization",
        "Neg",
        "Not",
        "Round",
        "Shrink",
        "Softmax",
        "Swish",
    }:
        node_inputs = ["state"]
    elif op_type == "Where":
        condition = onnx.numpy_helper.from_array(np.ones(shape, dtype=np.bool_), name="condition")
        alternative = onnx.numpy_helper.from_array(np.ones(shape, dtype=numpy_dtype), name="alternative")
        algorithm_initializers.extend([condition, alternative])
        node_inputs = ["condition", "state", "alternative"]
    else:
        delta = onnx.numpy_helper.from_array(np.ones(shape, dtype=numpy_dtype), name="delta")
        algorithm_initializers.append(delta)
        node_inputs = ["state", "delta"]
    main_input = helper.make_tensor_value_info("main_input", TensorProto.FLOAT, [1])
    main_output = helper.make_tensor_value_info("main_output", TensorProto.FLOAT, [1])
    main_graph = helper.make_graph(
        [helper.make_node("Identity", ["main_input"], ["main_output"])],
        "main_graph",
        [main_input],
        [main_output],
        initializer=[state],
    )
    algorithm = helper.make_graph(
        [helper.make_node(op_type, node_inputs, ["state_new"])],
        "non_weight_training_update",
        [],
        [helper.make_tensor_value_info("state_new", data_type, list(shape))],
        initializer=algorithm_initializers,
    )
    training_info = onnx.TrainingInfoProto()
    training_info.algorithm.CopyFrom(algorithm)
    binding = training_info.update_binding.add()
    binding.key = "state"
    binding.value = "state_new"
    model = helper.make_model(main_graph, opset_imports=[helper.make_opsetid("", opset_version)])
    model.ir_version = 8
    model.training_info.append(training_info)
    onnx.checker.check_model(model)
    path = tmp_path / f"non-weight-{op_type.lower()}-training-update.onnx"
    onnx.save(model, str(path))
    return path


def create_flat_training_initialization_reset_model(tmp_path: Path) -> Path:
    stored_weights = np.zeros(1000, dtype=np.float32)
    shape = onnx.numpy_helper.from_array(np.asarray([100, 10], dtype=np.int64), name="shape")
    weights = onnx.numpy_helper.from_array(stored_weights, name="W")
    main_input = helper.make_tensor_value_info("main_input", TensorProto.FLOAT, [1, 100])
    main_output = helper.make_tensor_value_info("main_output", TensorProto.FLOAT, [1, 10])
    main_graph = helper.make_graph(
        [
            helper.make_node("Reshape", ["W", "shape"], ["W_matrix"]),
            helper.make_node("MatMul", ["main_input", "W_matrix"], ["main_output"]),
        ],
        "main_graph",
        [main_input],
        [main_output],
        initializer=[weights, shape],
    )

    reset_weights = np.zeros(1000, dtype=np.float32)
    reset_weights.reshape(100, 10)[50:55, 3] = 10.0
    reset_tensor = onnx.numpy_helper.from_array(reset_weights, name="reset_value")
    initialization = helper.make_graph(
        [helper.make_node("Constant", [], ["reset"], value=reset_tensor)],
        "flat_training_initialization",
        [],
        [helper.make_tensor_value_info("reset", TensorProto.FLOAT, [1000])],
    )
    training_info = onnx.TrainingInfoProto()
    training_info.initialization.CopyFrom(initialization)
    binding = training_info.initialization_binding.add()
    binding.key = "W"
    binding.value = "reset"
    model = helper.make_model(main_graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    model.training_info.append(training_info)
    onnx.checker.check_model(model)
    path = tmp_path / "flat-training-initialization-reset.onnx"
    onnx.save(model, str(path))
    return path


def create_recurrent_weight_model(
    tmp_path: Path,
    *,
    op_type: str,
    target_input_index: int,
    distributed_near_match: bool,
) -> Path:
    """Create a bidirectional recurrent operator with a targeted W or R pattern."""
    gate_multiplier = {"RNN": 1, "GRU": 3, "LSTM": 4}[op_type]
    directions = 2
    hidden_size = 100
    input_size = 100
    gate_hidden_size = gate_multiplier * hidden_size
    input_weights = np.zeros((directions, gate_hidden_size, input_size), dtype=np.float32)
    recurrent_weights = np.zeros((directions, gate_hidden_size, hidden_size), dtype=np.float32)
    target = input_weights if target_input_index == 1 else recurrent_weights
    if distributed_near_match:
        target[1, 3:8, 50] = 10.0
    else:
        target[1, 3, 50:55] = 10.0

    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 1, input_size])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, directions, 1, hidden_size])
    initializers = [
        onnx.numpy_helper.from_array(input_weights, name="W"),
        onnx.numpy_helper.from_array(recurrent_weights, name="R"),
    ]
    node = helper.make_node(
        op_type,
        ["X", "W", "R"],
        ["Y"],
        name=f"bidirectional_{op_type.lower()}",
        direction="bidirectional",
        hidden_size=hidden_size,
    )
    graph = helper.make_graph([node], f"{op_type.lower()}_weight_graph", [X], [Y], initializer=initializers)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 14)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / f"{op_type.lower()}-{target_input_index}-{distributed_near_match}.onnx"
    onnx.save(model, str(path))
    return path


def create_broadcast_dynamic_weight_model(tmp_path: Path) -> Path:
    """Create a runtime-derived matrix weight from a broadcast vector initializer."""
    vector = onnx.numpy_helper.from_array(np.zeros(10, dtype=np.float32), name="W")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
    delta = helper.make_tensor_value_info("dynamic_delta", TensorProto.FLOAT, [100, 10])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])
    nodes = [
        helper.make_node("Add", ["W", "dynamic_delta"], ["W_view"], name="broadcast_weight_add"),
        helper.make_node("MatMul", ["X", "W_view"], ["Y"], name="linear"),
    ]
    graph = helper.make_graph(nodes, "broadcast_dynamic_weight_graph", [X, delta], [Y], initializer=[vector])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "broadcast-dynamic-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_computed_weight_model(tmp_path: Path) -> Path:
    """Create a matrix weight computed from two static initializers."""
    left = onnx.numpy_helper.from_array(np.zeros((100, 100), dtype=np.float32), name="A")
    right = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="B")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])
    nodes = [
        helper.make_node("MatMul", ["A", "B"], ["W_view"], name="compute_weight"),
        helper.make_node("MatMul", ["X", "W_view"], ["Y"], name="linear"),
    ]
    graph = helper.make_graph(nodes, "computed_weight_graph", [X], [Y], initializer=[left, right])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "computed-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_dynamic_left_weight_model(tmp_path: Path) -> Path:
    """Create a runtime-derived left MatMul weight with a resolved right weight."""
    left = onnx.numpy_helper.from_array(np.zeros((100, 100), dtype=np.float32), name="W")
    right = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="R")
    delta = helper.make_tensor_value_info("dynamic_delta", TensorProto.FLOAT, [100, 100])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [100, 10])
    nodes = [
        helper.make_node("Add", ["W", "dynamic_delta"], ["W_view"], name="dynamic_left_weight_add"),
        helper.make_node("MatMul", ["W_view", "R"], ["Y"], name="linear"),
    ]
    graph = helper.make_graph(nodes, "dynamic_left_weight_graph", [delta], [Y], initializer=[left, right])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "dynamic-left-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_left_weight_stack_model(tmp_path: Path) -> Path:
    """Create two clean MatMuls with weights on the left and activations on the right."""
    first = onnx.numpy_helper.from_array(np.zeros((100, 100), dtype=np.float32), name="W1")
    second = onnx.numpy_helper.from_array(np.zeros((10, 100), dtype=np.float32), name="W2")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [100, 1])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [10, 1])
    nodes = [
        helper.make_node("MatMul", ["W1", "X"], ["hidden"], name="left_linear_1"),
        helper.make_node("MatMul", ["W2", "hidden"], ["Y"], name="left_linear_2"),
    ]
    graph = helper.make_graph(nodes, "left_weight_stack", [X], [Y], initializer=[first, second])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "left-weight-stack.onnx"
    onnx.save(model, str(path))
    return path


def create_left_weight_gemm_stack_model(tmp_path: Path) -> Path:
    """Create two clean Gemms with weights on the left and activations on the right."""
    first = onnx.numpy_helper.from_array(np.zeros((100, 100), dtype=np.float32), name="W1")
    second = onnx.numpy_helper.from_array(np.zeros((10, 100), dtype=np.float32), name="W2")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [100, 1])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [10, 1])
    nodes = [
        helper.make_node("Gemm", ["W1", "X"], ["hidden"], name="left_gemm_1"),
        helper.make_node("Gemm", ["W2", "hidden"], ["Y"], name="left_gemm_2"),
    ]
    graph = helper.make_graph(nodes, "left_weight_gemm_stack", [X], [Y], initializer=[first, second])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "left-weight-gemm-stack.onnx"
    onnx.save(model, str(path))
    return path


def create_attention_score_model(tmp_path: Path) -> Path:
    """Create a clean Q/K/V attention block with activation-only MatMuls."""
    query_weight = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="Wq")
    key_weight = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="Wk")
    value_weight = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="Wv")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])
    nodes = [
        helper.make_node("MatMul", ["X", "Wq"], ["Q"], name="query_projection"),
        helper.make_node("MatMul", ["X", "Wk"], ["K"], name="key_projection"),
        helper.make_node("MatMul", ["X", "Wv"], ["V"], name="value_projection"),
        helper.make_node("Transpose", ["K"], ["Kt"], name="transpose_key", perm=[1, 0]),
        helper.make_node("MatMul", ["Q", "Kt"], ["scores"], name="attention_scores"),
        helper.make_node("Softmax", ["scores"], ["probabilities"], name="attention_probabilities", axis=-1),
        helper.make_node("MatMul", ["probabilities", "V"], ["Y"], name="attention_context"),
    ]
    graph = helper.make_graph(
        nodes,
        "attention_score_graph",
        [X],
        [Y],
        initializer=[query_weight, key_weight, value_weight],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "attention-score.onnx"
    onnx.save(model, str(path))
    return path


def create_einsum_attention_score_model(tmp_path: Path) -> Path:
    """Create clean query/key projections contracted by Einsum."""
    query_weight = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="Wq")
    key_weight = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="Wk")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 2, 100])
    scores = helper.make_tensor_value_info("scores", TensorProto.FLOAT, [1, 2, 2])
    nodes = [
        helper.make_node("MatMul", ["X", "Wq"], ["Q"], name="query_projection"),
        helper.make_node("MatMul", ["X", "Wk"], ["K"], name="key_projection"),
        helper.make_node("Einsum", ["Q", "K"], ["scores"], name="attention_scores", equation="bid,bjd->bij"),
    ]
    graph = helper.make_graph(
        nodes,
        "einsum_attention_score_graph",
        [X],
        [scores],
        initializer=[query_weight, key_weight],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "einsum-attention-score.onnx"
    onnx.save(model, str(path))
    return path


def create_recurrent_dynamic_weight_model(tmp_path: Path) -> Path:
    """Create a GRU whose W input is generated at runtime."""
    hidden_size = 100
    projection = onnx.numpy_helper.from_array(np.zeros((1, 100, 100), dtype=np.float32), name="P")
    recurrent = onnx.numpy_helper.from_array(np.zeros((1, 300, 100), dtype=np.float32), name="R")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 1, 100])
    seed = helper.make_tensor_value_info("weight_seed", TensorProto.FLOAT, [1, 300, 100])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 1, 1, hidden_size])
    nodes = [
        helper.make_node("MatMul", ["weight_seed", "P"], ["W_dynamic"], name="generate_weight"),
        helper.make_node(
            "GRU",
            ["X", "W_dynamic", "R"],
            ["Y"],
            name="gru",
            hidden_size=hidden_size,
        ),
    ]
    graph = helper.make_graph(
        nodes, "recurrent_dynamic_weight_graph", [X, seed], [Y], initializer=[projection, recurrent]
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 14)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "recurrent-dynamic-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_projected_dynamic_matmul_weight_model(tmp_path: Path, *, left: bool) -> Path:
    """Use a projected runtime value as a later left- or right-hand MatMul weight."""
    projection = onnx.numpy_helper.from_array(np.zeros((100, 100), dtype=np.float32), name="P")
    if left:
        seed = helper.make_tensor_value_info("weight_seed", TensorProto.FLOAT, [10, 100])
        X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [100, 1])
        Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [10, 1])
        generator_inputs = ["weight_seed", "P"]
        linear_inputs = ["W_dynamic", "X"]
    else:
        seed = helper.make_tensor_value_info("weight_seed", TensorProto.FLOAT, [100, 10])
        X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
        Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])
        generator_inputs = ["P", "weight_seed"]
        linear_inputs = ["X", "W_dynamic"]
    nodes = [
        helper.make_node("MatMul", generator_inputs, ["W_dynamic"], name="generate_weight"),
        helper.make_node("MatMul", linear_inputs, ["Y"], name="linear"),
    ]
    graph = helper.make_graph(nodes, "projected_dynamic_weight_graph", [seed, X], [Y], initializer=[projection])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / f"projected-dynamic-matmul-weight-{left}.onnx"
    onnx.save(model, str(path))
    return path


def create_mixed_activation_and_raw_lineage_model(tmp_path: Path) -> Path:
    """Mix a prior activation with a raw dynamic initializer dependency."""
    shared_weight = onnx.numpy_helper.from_array(np.zeros((100, 100), dtype=np.float32), name="W")
    output_weight = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="R")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [100, 100])
    delta = helper.make_tensor_value_info("dynamic_delta", TensorProto.FLOAT, [100, 100])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [100, 10])
    nodes = [
        helper.make_node("MatMul", ["X", "W"], ["activation"], name="activation_projection"),
        helper.make_node("Add", ["W", "dynamic_delta"], ["raw_dynamic"], name="raw_dynamic_weight"),
        helper.make_node("Add", ["activation", "raw_dynamic"], ["mixed"], name="mix_lineages"),
        helper.make_node("MatMul", ["mixed", "R"], ["Y"], name="linear"),
    ]
    graph = helper.make_graph(
        nodes,
        "mixed_activation_raw_lineage_graph",
        [X, delta],
        [Y],
        initializer=[shared_weight, output_weight],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "mixed-activation-raw-lineage.onnx"
    onnx.save(model, str(path))
    return path


def create_batched_matmul_weight_model(tmp_path: Path, weights: np.ndarray, *, left: bool) -> Path:
    """Create a batched MatMul initializer on either operand."""
    weight_tensor = onnx.numpy_helper.from_array(weights, name="W")
    if left:
        X = helper.make_tensor_value_info("input", TensorProto.FLOAT, [weights.shape[0], weights.shape[2], 1])
        Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, [weights.shape[0], weights.shape[1], 1])
        node_inputs = ["W", "input"]
    else:
        X = helper.make_tensor_value_info("input", TensorProto.FLOAT, [weights.shape[0], 1, weights.shape[1]])
        Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, [weights.shape[0], 1, weights.shape[2]])
        node_inputs = ["input", "W"]
    node = helper.make_node("MatMul", node_inputs, ["output"], name="batched_linear")
    graph = helper.make_graph([node], "batched_matmul_graph", [X], [Y], initializer=[weight_tensor])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / ("batched-left-matmul.onnx" if left else "batched-right-matmul.onnx")
    onnx.save(model, str(path))
    return path


def create_collision_named_weight_model(tmp_path: Path) -> Path:
    """Create initializer names that collide with the former synthesized keys."""
    base_name = "W"
    intermediate_name = "W@output_axis=1"
    crafted_name = "W@output_axis=1,kind=matrix,group=1"
    initializers = [
        onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name=base_name),
        onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name=crafted_name),
        onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name=intermediate_name),
    ]
    right_input = helper.make_tensor_value_info("right_input", TensorProto.FLOAT, [1, 100])
    left_input = helper.make_tensor_value_info("left_input", TensorProto.FLOAT, [10, 1])
    outputs = [
        helper.make_tensor_value_info("base_right", TensorProto.FLOAT, [1, 10]),
        helper.make_tensor_value_info("base_left", TensorProto.FLOAT, [100, 1]),
        helper.make_tensor_value_info("crafted_output", TensorProto.FLOAT, [1, 10]),
        helper.make_tensor_value_info("intermediate_output", TensorProto.FLOAT, [1, 10]),
    ]
    nodes = [
        helper.make_node("MatMul", ["right_input", base_name], ["base_right"], name="base_right_node"),
        helper.make_node("MatMul", [base_name, "left_input"], ["base_left"], name="base_left_node"),
        helper.make_node(
            "MatMul",
            ["right_input", crafted_name],
            ["crafted_output"],
            name="crafted_node",
        ),
        helper.make_node(
            "MatMul",
            ["right_input", intermediate_name],
            ["intermediate_output"],
            name="intermediate_node",
        ),
    ]
    graph = helper.make_graph(nodes, "collision_graph", [right_input, left_input], outputs, initializer=initializers)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "collision-named-weights.onnx"
    onnx.save(model, str(path))
    return path


def create_many_consumer_weight_model(tmp_path: Path, *, consumer_count: int) -> Path:
    """Create bounded-metadata pressure with long attacker-controlled names."""
    initializer_name = "initializer-" + "x" * 1000
    weights = np.zeros((100, 10), dtype=np.float32)
    weights[50:55, 3] = 10.0
    initializer = onnx.numpy_helper.from_array(weights, name=initializer_name)
    X = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, 100])
    output_names = [f"output_{index}" for index in range(consumer_count)]
    Y = helper.make_tensor_value_info(output_names[-1], TensorProto.FLOAT, [1, 10])
    nodes = [
        helper.make_node(
            "MatMul",
            ["input", initializer_name],
            [output_name],
            name=f"consumer-{index}-" + "y" * 1000,
        )
        for index, output_name in enumerate(output_names)
    ]
    graph = helper.make_graph(nodes, "many_consumer_graph", [X], [Y], initializer=[initializer])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "many-consumer-weights.onnx"
    onnx.save(model, str(path))
    return path


def create_invalid_initializer_name_model(tmp_path: Path, *, duplicate: bool) -> Path:
    """Serialize an invalid graph so the scanner must reject ambiguous names itself."""
    X = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, 2])
    Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, 2])
    node = helper.make_node("Identity", ["input"], ["output"], name="identity")
    initializer_name = "W" if duplicate else ""
    initializers = [
        onnx.numpy_helper.from_array(np.zeros((2, 2), dtype=np.float32), name=initializer_name),
    ]
    if duplicate:
        initializers.append(onnx.numpy_helper.from_array(np.ones((2, 2), dtype=np.float32), name="W"))
    graph = helper.make_graph([node], "invalid_initializer_names", [X], [Y], initializer=initializers)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    path = tmp_path / ("duplicate-initializers.onnx" if duplicate else "empty-initializer.onnx")
    onnx.save(model, str(path))
    return path


def create_left_equivalent_linear_model(
    tmp_path: Path,
    analysis_weights: np.ndarray,
    *,
    op_type: str,
) -> Path:
    """Encode X @ W as transpose(W.T @ transpose(X))."""
    assert op_type in {"Gemm", "MatMul"}
    stored_weights = analysis_weights.T.copy()
    weight_tensor = onnx.numpy_helper.from_array(stored_weights, name="W")
    X = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, analysis_weights.shape[0]])
    Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, analysis_weights.shape[1]])
    nodes = [
        helper.make_node("Transpose", ["input"], ["input_t"], name="transpose_input", perm=[1, 0]),
        helper.make_node(op_type, ["W", "input_t"], ["output_t"], name="left_linear"),
        helper.make_node("Transpose", ["output_t"], ["output"], name="transpose_output", perm=[1, 0]),
    ]
    graph = helper.make_graph(nodes, "left_equivalent_graph", [X], [Y], initializer=[weight_tensor])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / f"left-equivalent-{op_type.lower()}.onnx"
    onnx.save(model, str(path))
    return path


def create_onnx_conv_weight_model(
    tmp_path: Path,
    weights: np.ndarray,
    *,
    transpose: bool,
    group: int = 1,
    filename: str = "conv-weighted.onnx",
) -> Path:
    """Create a valid Conv or ConvTranspose graph with inline weights."""
    op_type = "ConvTranspose" if transpose else "Conv"
    weight_tensor = onnx.numpy_helper.from_array(weights, name="W")
    input_channels = weights.shape[0] if transpose else weights.shape[1] * group
    output_channels = weights.shape[1] * group if transpose else weights.shape[0]
    X = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, input_channels, 8, 8])
    spatial_size = 8 + weights.shape[2] - 1 if transpose else 8 - weights.shape[2] + 1
    Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, output_channels, spatial_size, spatial_size])
    node = helper.make_node(op_type, ["input", "W"], ["output"], name="convolution", group=group)
    graph = helper.make_graph([node], "conv_weight_graph", [X], [Y], initializer=[weight_tensor])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / filename
    onnx.save(model, str(path))
    return path


def create_control_flow_captured_weight_model(
    tmp_path: Path,
    weights: np.ndarray,
    *,
    control_flow_op: str,
) -> Path:
    """Create a checker-valid control-flow graph whose body captures W."""
    weight_tensor = onnx.numpy_helper.from_array(weights, name="W")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, weights.shape[0]])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, weights.shape[1]])

    if control_flow_op == "If":
        condition = helper.make_tensor_value_info("condition", TensorProto.BOOL, [])

        def make_branch(name: str) -> Any:
            branch_output = helper.make_tensor_value_info(f"{name}_output", TensorProto.FLOAT, [1, weights.shape[1]])
            node = helper.make_node("MatMul", ["X", "W"], [f"{name}_output"], name=f"{name}_linear")
            return helper.make_graph([node], name, [], [branch_output])

        control_node = helper.make_node(
            "If",
            ["condition"],
            ["Y"],
            name="control",
            then_branch=make_branch("then"),
            else_branch=make_branch("else"),
        )
        graph_inputs = [condition, X]
        graph_outputs = [Y]
    elif control_flow_op == "Loop":
        trip_count = helper.make_tensor_value_info("trip_count", TensorProto.INT64, [])
        condition = helper.make_tensor_value_info("condition", TensorProto.BOOL, [])
        iteration = helper.make_tensor_value_info("iteration", TensorProto.INT64, [])
        body_condition = helper.make_tensor_value_info("body_condition", TensorProto.BOOL, [])
        state_input = helper.make_tensor_value_info("state_input", TensorProto.FLOAT, [1, weights.shape[0]])
        condition_output = helper.make_tensor_value_info("condition_output", TensorProto.BOOL, [])
        state_output = helper.make_tensor_value_info("state_output", TensorProto.FLOAT, [1, weights.shape[1]])
        body = helper.make_graph(
            [
                helper.make_node("Identity", ["body_condition"], ["condition_output"]),
                helper.make_node("MatMul", ["state_input", "W"], ["state_output"], name="loop_linear"),
            ],
            "loop_body",
            [iteration, body_condition, state_input],
            [condition_output, state_output],
        )
        control_node = helper.make_node(
            "Loop",
            ["trip_count", "condition", "X"],
            ["Y"],
            name="control",
            body=body,
        )
        graph_inputs = [trip_count, condition, X]
        graph_outputs = [Y]
    elif control_flow_op == "Scan":
        scan_values = helper.make_tensor_value_info("scan_values", TensorProto.FLOAT, [2, 1, weights.shape[0]])
        scan_outputs = helper.make_tensor_value_info("scan_outputs", TensorProto.FLOAT, [2, 1, weights.shape[0]])
        state_input = helper.make_tensor_value_info("state_input", TensorProto.FLOAT, [1, weights.shape[0]])
        scan_input = helper.make_tensor_value_info("scan_input", TensorProto.FLOAT, [1, weights.shape[0]])
        state_output = helper.make_tensor_value_info("state_output", TensorProto.FLOAT, [1, weights.shape[1]])
        scan_output = helper.make_tensor_value_info("scan_output", TensorProto.FLOAT, [1, weights.shape[0]])
        body = helper.make_graph(
            [
                helper.make_node("MatMul", ["state_input", "W"], ["state_output"], name="scan_linear"),
                helper.make_node("Identity", ["scan_input"], ["scan_output"]),
            ],
            "scan_body",
            [state_input, scan_input],
            [state_output, scan_output],
        )
        control_node = helper.make_node(
            "Scan",
            ["X", "scan_values"],
            ["Y", "scan_outputs"],
            name="control",
            body=body,
            num_scan_inputs=1,
        )
        graph_inputs = [X, scan_values]
        graph_outputs = [Y, scan_outputs]
    else:  # pragma: no cover - test helper guard
        raise AssertionError(f"Unsupported control-flow operator: {control_flow_op}")

    graph = helper.make_graph([control_node], "control_graph", graph_inputs, graph_outputs, initializer=[weight_tensor])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / f"captured-{control_flow_op.lower()}.onnx"
    onnx.save(model, str(path))
    return path


def create_control_flow_shadowed_weight_model(
    tmp_path: Path,
    outer_weights: np.ndarray,
    *,
    local_weights: np.ndarray | None = None,
) -> Path:
    """Create an If graph where a local W shadows an unused outer W."""
    outer_weight_tensor = onnx.numpy_helper.from_array(outer_weights, name="W")
    branch_weights = np.zeros_like(outer_weights) if local_weights is None else local_weights
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, outer_weights.shape[0]])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, outer_weights.shape[1]])
    condition = helper.make_tensor_value_info("condition", TensorProto.BOOL, [])

    def make_branch(name: str) -> Any:
        local_weight_tensor = onnx.numpy_helper.from_array(branch_weights, name="W")
        branch_output = helper.make_tensor_value_info(f"{name}_output", TensorProto.FLOAT, [1, outer_weights.shape[1]])
        node = helper.make_node("MatMul", ["X", "W"], [f"{name}_output"], name=f"{name}_linear")
        return helper.make_graph([node], name, [], [branch_output], initializer=[local_weight_tensor])

    control_node = helper.make_node(
        "If",
        ["condition"],
        ["Y"],
        name="control",
        then_branch=make_branch("then"),
        else_branch=make_branch("else"),
    )
    graph = helper.make_graph(
        [control_node],
        "control_graph",
        [condition, X],
        [Y],
        initializer=[outer_weight_tensor],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "shadowed-captured-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_control_flow_returned_weight_model(tmp_path: Path, weights: np.ndarray) -> Path:
    """Create an If that returns a captured weight to an outer MatMul."""
    initializer = onnx.numpy_helper.from_array(weights, name="W")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, weights.shape[0]])
    condition = helper.make_tensor_value_info("condition", TensorProto.BOOL, [])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, weights.shape[1]])

    def make_branch(name: str) -> Any:
        output_name = f"{name}_weight"
        output = helper.make_tensor_value_info(output_name, TensorProto.FLOAT, list(weights.shape))
        return helper.make_graph(
            [helper.make_node("Identity", ["W"], [output_name], name=f"{name}_identity")],
            name,
            [],
            [output],
        )

    nodes = [
        helper.make_node(
            "If",
            ["condition"],
            ["selected_weight"],
            name="select_weight",
            then_branch=make_branch("then"),
            else_branch=make_branch("else"),
        ),
        helper.make_node("MatMul", ["X", "selected_weight"], ["Y"], name="linear"),
    ]
    graph = helper.make_graph(nodes, "returned_weight_graph", [condition, X], [Y], initializer=[initializer])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "returned-control-flow-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_loop_carried_weight_model(tmp_path: Path, weights: np.ndarray) -> Path:
    """Create a Loop whose body consumes a weight through a formal input."""
    initializer = onnx.numpy_helper.from_array(weights, name="W")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, weights.shape[0]])
    trip_count = helper.make_tensor_value_info("trip_count", TensorProto.INT64, [])
    condition = helper.make_tensor_value_info("condition", TensorProto.BOOL, [])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, weights.shape[1]])
    iteration = helper.make_tensor_value_info("iteration", TensorProto.INT64, [])
    body_condition = helper.make_tensor_value_info("body_condition", TensorProto.BOOL, [])
    state_weight = helper.make_tensor_value_info("state_weight", TensorProto.FLOAT, list(weights.shape))
    condition_output = helper.make_tensor_value_info("condition_output", TensorProto.BOOL, [])
    weight_output = helper.make_tensor_value_info("weight_output", TensorProto.FLOAT, list(weights.shape))
    body = helper.make_graph(
        [
            helper.make_node("Identity", ["body_condition"], ["condition_output"]),
            helper.make_node("MatMul", ["X", "state_weight"], ["body_projection"], name="body_linear"),
            helper.make_node("Identity", ["state_weight"], ["weight_output"]),
        ],
        "loop_body",
        [iteration, body_condition, state_weight],
        [condition_output, weight_output],
    )
    nodes = [
        helper.make_node(
            "Loop",
            ["trip_count", "condition", "W"],
            ["final_weight"],
            name="carry_weight",
            body=body,
        ),
        helper.make_node("MatMul", ["X", "final_weight"], ["Y"], name="outer_linear"),
    ]
    graph = helper.make_graph(
        nodes,
        "loop_carried_weight_graph",
        [trip_count, condition, X],
        [Y],
        initializer=[initializer],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "loop-carried-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_activation_bookkeeping_model(tmp_path: Path, *, malicious: bool, rank_two_bias: bool = False) -> Path:
    """Create a linear stack whose activation path also consumes a bias."""
    first_weight = np.zeros((100, 100), dtype=np.float32)
    second_weight = np.zeros((100, 10), dtype=np.float32)
    if malicious:
        second_weight[50:55, 3] = 10.0
    initializers = [
        onnx.numpy_helper.from_array(first_weight, name="W1"),
        onnx.numpy_helper.from_array(
            np.zeros((1, 100) if rank_two_bias else 100, dtype=np.float32),
            name="bias",
        ),
        onnx.numpy_helper.from_array(second_weight, name="W2"),
    ]
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])
    nodes = [
        helper.make_node("MatMul", ["X", "W1"], ["hidden"], name="first_linear"),
        helper.make_node("Add", ["hidden", "bias"], ["biased"], name="bias_add"),
        helper.make_node("Relu", ["biased"], ["activated"], name="activation"),
        helper.make_node("MatMul", ["activated", "W2"], ["Y"], name="second_linear"),
    ]
    graph = helper.make_graph(nodes, "activation_bookkeeping_graph", [X], [Y], initializer=initializers)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / (
        f"{'malicious' if malicious else 'benign'}-activation-bookkeeping-{'2d' if rank_two_bias else '1d'}.onnx"
    )
    onnx.save(model, str(path))
    return path


def create_einsum_weight_model(tmp_path: Path, weights: np.ndarray) -> Path:
    initializer = onnx.numpy_helper.from_array(weights, name="W")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, weights.shape[0]])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, weights.shape[1]])
    node = helper.make_node("Einsum", ["X", "W"], ["Y"], name="linear", equation="bi,io->bo")
    graph = helper.make_graph([node], "einsum_weight_graph", [X], [Y], initializer=[initializer])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "einsum-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_qdq_weight_model(
    tmp_path: Path,
    *,
    malicious: bool = False,
    malformed_scale: bool = False,
    full_shape_parameters: bool = False,
    reshape_after_dequantization: bool = False,
) -> Path:
    weights = np.zeros((100, 10), dtype=np.int8)
    if malicious:
        weights[50:55, 3] = 100
    serialized_weights = weights.reshape((-1,)) if reshape_after_dequantization else weights
    quantized_weight = onnx.numpy_helper.from_array(serialized_weights, name="W")
    if full_shape_parameters:
        scale_value = np.ones(weights.shape, dtype=np.float32)
        zero_point_value = weights.copy()
    else:
        scale_value = np.asarray([0.1, 0.2], dtype=np.float32) if malformed_scale else np.asarray(0.1, dtype=np.float32)
        zero_point_value = np.asarray(0, dtype=np.int8)
    scale = onnx.numpy_helper.from_array(scale_value, name="scale")
    zero_point = onnx.numpy_helper.from_array(zero_point_value, name="zero_point")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])
    dequantized_output = "dequantized_flat" if reshape_after_dequantization else "dequantized_weight"
    nodes = [helper.make_node("DequantizeLinear", ["W", "scale", "zero_point"], [dequantized_output])]
    initializers = [quantized_weight, scale, zero_point]
    if reshape_after_dequantization:
        initializers.append(onnx.numpy_helper.from_array(np.asarray(weights.shape, dtype=np.int64), name="shape"))
        nodes.append(helper.make_node("Reshape", [dequantized_output, "shape"], ["dequantized_weight"]))
    nodes.append(helper.make_node("MatMul", ["X", "dequantized_weight"], ["Y"]))
    graph = helper.make_graph(nodes, "qdq_weight_graph", [X], [Y], initializer=initializers)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    if not (malformed_scale or full_shape_parameters):
        onnx.checker.check_model(model)
    suffix = (
        "full-shape"
        if full_shape_parameters
        else "malformed"
        if malformed_scale
        else "malicious"
        if malicious
        else "clean"
    )
    path = tmp_path / f"qdq-weight-{suffix}{'-reshape' if reshape_after_dequantization else ''}.onnx"
    onnx.save(model, str(path))
    return path


def create_qdq_float16_overflow_model(tmp_path: Path, *, output_dtype: int | None) -> Path:
    weights = np.full((100, 10), 2, dtype=np.int8)
    scale_dtype = np.float32 if output_dtype == TensorProto.FLOAT16 else np.float16
    initializers = [
        onnx.numpy_helper.from_array(weights, name="W"),
        onnx.numpy_helper.from_array(np.asarray(40_000, dtype=scale_dtype), name="scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.int8), name="zero_point"),
    ]
    dequantize_node = (
        helper.make_node(
            "DequantizeLinear",
            ["W", "scale", "zero_point"],
            ["dequantized_weight"],
        )
        if output_dtype is None
        else helper.make_node(
            "DequantizeLinear",
            ["W", "scale", "zero_point"],
            ["dequantized_weight"],
            output_dtype=output_dtype,
        )
    )
    nodes = [
        dequantize_node,
        helper.make_node("MatMul", ["X", "dequantized_weight"], ["Y"]),
    ]
    graph = helper.make_graph(
        nodes,
        "qdq_float16_overflow",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT16, [1, 100])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT16, [1, 10])],
        initializer=initializers,
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 23)])
    model.ir_version = 10
    onnx.checker.check_model(model, full_check=True)
    path = tmp_path / f"qdq-float16-{output_dtype if output_dtype is not None else 'inferred'}.onnx"
    onnx.save(model, str(path))
    return path


def create_matmul_integer_weight_model(
    tmp_path: Path,
    *,
    malicious: bool = False,
    omit_scale: bool = False,
    bind_scale: bool = True,
    zero_scale: bool = False,
    weight_on_left: bool = False,
    dead_scale_branch: bool = False,
    terminal_bias_add: bool = False,
    self_multiply_output: bool = False,
    filename: str = "matmul-integer-weight.onnx",
) -> Path:
    if dead_scale_branch:
        bind_scale = False
    if self_multiply_output:
        bind_scale = True
    weights = np.zeros((10, 100) if weight_on_left else (100, 10), dtype=np.int8)
    if malicious:
        if weight_on_left:
            weights[3, 50:55] = 100
        else:
            weights[50:55, 3] = 100
    initializers = [
        onnx.numpy_helper.from_array(weights, name="W_quantized"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.int8), name="X_zero_point"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.int8), name="W_zero_point"),
    ]
    if not omit_scale:
        scale_value = 0.0 if zero_scale else 0.1
        initializers.append(onnx.numpy_helper.from_array(np.asarray(scale_value, dtype=np.float32), name="W_scale"))
    X = helper.make_tensor_value_info("X", TensorProto.INT8, [100, 1] if weight_on_left else [1, 100])
    output_type = TensorProto.FLOAT if bind_scale else TensorProto.INT32
    Y = helper.make_tensor_value_info("Y", output_type, [10, 1] if weight_on_left else [1, 10])
    matmul_output = "Y_int" if bind_scale or terminal_bias_add else "Y"
    matmul_inputs = (
        ["W_quantized", "X", "W_zero_point", "X_zero_point"]
        if weight_on_left
        else ["X", "W_quantized", "X_zero_point", "W_zero_point"]
    )
    nodes = [
        helper.make_node(
            "MatMulInteger",
            matmul_inputs,
            [matmul_output],
            name="quantized_linear",
        ),
    ]
    if bind_scale:
        nodes.extend(
            [
                helper.make_node(
                    "Cast", [matmul_output], ["Y_cast"], name="quantized_linear_cast", to=TensorProto.FLOAT
                ),
                helper.make_node(
                    "Mul",
                    ["Y_cast", "Y_cast" if self_multiply_output else "W_scale"],
                    ["Y"],
                    name="quantized_linear_scale",
                ),
            ],
        )
    elif dead_scale_branch:
        nodes.extend(
            [
                helper.make_node("Cast", ["Y"], ["dead_cast"], to=TensorProto.FLOAT),
                helper.make_node("Mul", ["dead_cast", "W_scale"], ["dead_scaled"]),
            ]
        )
    elif terminal_bias_add:
        initializers.append(onnx.numpy_helper.from_array(np.asarray(0, dtype=np.int32), name="bias"))
        nodes.append(helper.make_node("Add", [matmul_output, "bias"], ["Y"]))
    graph = helper.make_graph(nodes, "matmul_integer_weight_graph", [X], [Y], initializer=initializers)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    if not (bind_scale and omit_scale):
        onnx.checker.check_model(model)
    path = tmp_path / filename
    onnx.save(model, str(path))
    return path


def create_matmul_integer_scale_chain_model(
    tmp_path: Path,
    *,
    vector_scale_count: int = 1,
    dynamic_scale_expression: bool = False,
    bias_add: bool = False,
    duplicate_add_input: bool = False,
    unsupported_live_op: str | None = None,
    anomalous_vector_scale: bool = True,
    weight_on_left: bool = False,
    expose_raw_output: bool = False,
    cast_data_type: int = TensorProto.FLOAT,
    overflow_scale: bool = False,
    scalar_overflow: bool = False,
    scalar_only_scale: bool = False,
    repeat_weight_scale: bool = False,
    nested_static_scale_expression: bool = False,
    cast_scale_expression: bool = False,
    widen_after_scale: bool = False,
    post_scale_bias_add: bool = False,
    narrow_after_scale: bool = False,
    integer_op_boundary: str = "direct",
) -> Path:
    assert integer_op_boundary in {"direct", "function", "if_subgraph"}
    weight_shape = (10, 100) if weight_on_left else (100, 10)
    weights = np.full(
        weight_shape,
        2 if overflow_scale or scalar_overflow or repeat_weight_scale else 1,
        dtype=np.int8,
    )
    scale_dtype = np.float16 if cast_data_type == TensorProto.FLOAT16 else np.float32
    vector_scale = np.full(
        (10, 1) if weight_on_left else 10,
        200 if repeat_weight_scale else 40_000 if overflow_scale else 1,
        dtype=scale_dtype,
    )
    if anomalous_vector_scale and not overflow_scale and not scalar_overflow and not repeat_weight_scale:
        vector_scale[3] = 100
    initializers = [
        onnx.numpy_helper.from_array(weights, name="W_quantized"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.int8), name="X_zero_point"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.int8), name="W_zero_point"),
        onnx.numpy_helper.from_array(
            np.asarray(
                40_000 if scalar_overflow else 1 if overflow_scale or repeat_weight_scale else 0.1,
                dtype=scale_dtype,
            ),
            name="X_scale",
        ),
    ]
    if not scalar_only_scale:
        for index in range(vector_scale_count):
            initializers.append(
                onnx.numpy_helper.from_array(vector_scale, name=f"W_scale_{index}"),
            )
    if nested_static_scale_expression:
        initializers.append(
            onnx.numpy_helper.from_array(np.asarray(0.5, dtype=scale_dtype), name="nested_scale"),
        )
    inputs = [helper.make_tensor_value_info("X", TensorProto.INT8, [100, 1] if weight_on_left else [1, 100])]
    matmul_inputs = (
        ["W_quantized", "X", "W_zero_point", "X_zero_point"]
        if weight_on_left
        else ["X", "W_quantized", "X_zero_point", "W_zero_point"]
    )
    functions: list[Any] = []
    if integer_op_boundary == "function":
        domain = "modelaudit.test"
        function_inputs = [f"function_input_{index}" for index in range(len(matmul_inputs))]
        functions.append(
            helper.make_function(
                domain,
                "IntegerMatMul",
                function_inputs,
                ["function_output"],
                [helper.make_node("MatMulInteger", function_inputs, ["function_output"])],
                [helper.make_opsetid("", 13)],
            )
        )
        nodes = [helper.make_node("IntegerMatMul", matmul_inputs, ["Y_int"], domain=domain)]
    elif integer_op_boundary == "if_subgraph":
        inputs.append(helper.make_tensor_value_info("condition", TensorProto.BOOL, []))

        def make_integer_branch(name: str) -> Any:
            output_name = f"{name}_output"
            output = helper.make_tensor_value_info(output_name, TensorProto.INT32, None)
            return helper.make_graph(
                [helper.make_node("MatMulInteger", matmul_inputs, [output_name])],
                name,
                [],
                [output],
            )

        nodes = [
            helper.make_node(
                "If",
                ["condition"],
                ["Y_int"],
                then_branch=make_integer_branch("then"),
                else_branch=make_integer_branch("else"),
            )
        ]
    else:
        nodes = [helper.make_node("MatMulInteger", matmul_inputs, ["Y_int"])]
    cast_input = "Y_int"
    if bias_add:
        initializers.append(onnx.numpy_helper.from_array(np.asarray(0, dtype=np.int32), name="bias"))
        nodes.append(helper.make_node("Add", ["Y_int", "bias"], ["Y_biased"]))
        cast_input = "Y_biased"
    elif duplicate_add_input:
        nodes.append(helper.make_node("Add", ["Y_int", "Y_int"], ["Y_biased"]))
        cast_input = "Y_biased"
    if unsupported_live_op == "Reshape":
        output_shape = [10, 1] if weight_on_left else [1, 10]
        initializers.append(
            onnx.numpy_helper.from_array(np.asarray(output_shape, dtype=np.int64), name="live_shape"),
        )
        nodes.append(helper.make_node("Reshape", [cast_input, "live_shape"], ["Y_reshaped"]))
        cast_input = "Y_reshaped"
    nodes.extend(
        [helper.make_node("Cast", [cast_input], ["Y_cast"], to=cast_data_type)],
    )
    activation_scale_input = "Y_cast"
    if unsupported_live_op == "Relu":
        nodes.append(helper.make_node("Relu", ["Y_cast"], ["Y_relu"]))
        activation_scale_input = "Y_relu"
    nodes.append(helper.make_node("Mul", [activation_scale_input, "X_scale"], ["Y_activation_scaled"]))
    scale_chain_input = "Y_activation_scaled"
    if post_scale_bias_add:
        initializers.append(onnx.numpy_helper.from_array(np.asarray(0, dtype=scale_dtype), name="float_bias"))
        nodes.append(helper.make_node("Add", [scale_chain_input, "float_bias"], ["Y_post_scale_bias"]))
        scale_chain_input = "Y_post_scale_bias"
    scale_name = "W_scale_0"
    if dynamic_scale_expression:
        inputs.append(helper.make_tensor_value_info("scale_gate", cast_data_type, list(vector_scale.shape)))
        nodes.append(helper.make_node("Mul", [scale_name, "scale_gate"], ["dynamic_weight_scale"]))
        scale_name = "dynamic_weight_scale"
    elif nested_static_scale_expression:
        nodes.append(helper.make_node("Mul", [scale_name, "nested_scale"], ["nested_weight_scale"]))
        scale_name = "nested_weight_scale"
    elif cast_scale_expression:
        nodes.extend(
            [
                helper.make_node("Cast", [scale_name], ["narrow_weight_scale"], to=TensorProto.FLOAT16),
                helper.make_node("Cast", ["narrow_weight_scale"], ["wide_weight_scale"], to=TensorProto.FLOAT),
            ]
        )
        scale_name = "wide_weight_scale"
    for index in range(1, vector_scale_count if not scalar_only_scale else 1):
        output_name = f"Y_weight_scaled_{index}"
        nodes.append(helper.make_node("Mul", ["Y_activation_scaled", scale_name], [output_name]))
        scale_name = f"W_scale_{index}"
        nodes.append(helper.make_node("Mul", [output_name, scale_name], [f"Y_stage_{index}"]))
        scale_name = f"Y_stage_{index}"
    if repeat_weight_scale:
        nodes.append(helper.make_node("Mul", [scale_chain_input, "W_scale_0"], ["Y_repeated_scale"]))
        scale_chain_input = "Y_repeated_scale"
    scale_chain_output = "Y_before_output_cast" if widen_after_scale or narrow_after_scale else "Y"
    if scalar_only_scale:
        nodes.append(helper.make_node("Identity", [scale_chain_input], [scale_chain_output]))
    elif vector_scale_count == 1:
        nodes.append(helper.make_node("Mul", [scale_chain_input, scale_name], [scale_chain_output]))
    else:
        nodes.append(helper.make_node("Identity", [scale_name], [scale_chain_output]))
    if widen_after_scale:
        nodes.append(helper.make_node("Cast", [scale_chain_output], ["Y"], to=TensorProto.FLOAT))
    elif narrow_after_scale:
        nodes.append(helper.make_node("Cast", [scale_chain_output], ["Y"], to=TensorProto.FLOAT16))
    output_shape = [10, 1] if weight_on_left else [1, 10]
    output_data_type = (
        TensorProto.FLOAT if widen_after_scale else TensorProto.FLOAT16 if narrow_after_scale else cast_data_type
    )
    outputs = [helper.make_tensor_value_info("Y", output_data_type, output_shape)]
    if expose_raw_output:
        outputs.append(helper.make_tensor_value_info("Y_int", TensorProto.INT32, output_shape))
    graph = helper.make_graph(
        nodes,
        "matmul_integer_scale_chain",
        inputs,
        outputs,
        initializer=initializers,
    )
    opset_imports = [helper.make_opsetid("", 13)]
    if integer_op_boundary == "function":
        opset_imports.append(helper.make_opsetid("modelaudit.test", 1))
    model = helper.make_model(graph, functions=functions, opset_imports=opset_imports)
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / f"matmul-integer-scale-chain-{integer_op_boundary}-{'left' if weight_on_left else 'right'}.onnx"
    onnx.save(model, str(path))
    return path


def create_dynamic_matmul_integer_bias_model(tmp_path: Path, *, malicious: bool) -> Path:
    weights = np.ones((100, 10), dtype=np.int8)
    weight_scale = np.ones(10, dtype=np.float32)
    if malicious:
        weight_scale[3] = 100.0
    graph = helper.make_graph(
        [
            helper.make_node(
                "DynamicQuantizeLinear",
                ["X"],
                ["X_quantized", "X_scale", "X_zero_point"],
            ),
            helper.make_node(
                "MatMulInteger",
                ["X_quantized", "W_quantized", "X_zero_point", "W_zero_point"],
                ["Y_integer"],
            ),
            helper.make_node("Cast", ["Y_integer"], ["Y_cast"], to=TensorProto.FLOAT),
            helper.make_node("Mul", ["X_scale", "W_scale"], ["combined_scale"]),
            helper.make_node("Mul", ["Y_cast", "combined_scale"], ["Y_scaled"]),
            helper.make_node("Add", ["Y_scaled", "bias"], ["Y"]),
            helper.make_node("Shape", ["Y"], ["Y_shape"]),
        ],
        "dynamic_matmul_integer_bias",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])],
        [
            helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10]),
            helper.make_tensor_value_info("Y_shape", TensorProto.INT64, [2]),
        ],
        initializer=[
            onnx.numpy_helper.from_array(weights, name="W_quantized"),
            onnx.numpy_helper.from_array(np.asarray(0, dtype=np.int8), name="W_zero_point"),
            onnx.numpy_helper.from_array(weight_scale, name="W_scale"),
            onnx.numpy_helper.from_array(np.zeros(10, dtype=np.float32), name="bias"),
        ],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / f"dynamic-matmul-integer-bias-{'malicious' if malicious else 'benign'}.onnx"
    onnx.save(model, str(path))
    return path


def create_declared_shape_metadata_model(tmp_path: Path) -> Path:
    graph = helper.make_graph(
        [
            helper.make_node("Shape", ["W"], ["weight_shape"]),
            helper.make_node("Gather", ["weight_shape", "index"], ["Y"]),
        ],
        "declared_shape_metadata",
        [],
        [helper.make_tensor_value_info("Y", TensorProto.INT64, [])],
        initializer=[
            onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="W"),
            onnx.numpy_helper.from_array(np.asarray(0, dtype=np.int64), name="index"),
        ],
        value_info=[helper.make_tensor_value_info("weight_shape", TensorProto.INT64, [2])],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "declared-shape-metadata.onnx"
    onnx.save(model, str(path))
    return path


def create_batched_matmul_integer_weight_model(tmp_path: Path) -> Path:
    initializers = [
        onnx.numpy_helper.from_array(np.zeros((2, 100, 10), dtype=np.int8), name="W_quantized"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.int8), name="X_zero_point"),
        onnx.numpy_helper.from_array(np.zeros((2, 1, 10), dtype=np.int8), name="W_zero_point"),
    ]
    graph = helper.make_graph(
        [
            helper.make_node(
                "MatMulInteger",
                ["X", "W_quantized", "X_zero_point", "W_zero_point"],
                ["Y"],
            ),
        ],
        "batched_matmul_integer_weight",
        [helper.make_tensor_value_info("X", TensorProto.INT8, [2, 1, 100])],
        [helper.make_tensor_value_info("Y", TensorProto.INT32, [2, 1, 10])],
        initializer=initializers,
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "batched-matmul-integer-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_quantized_conv_weight_model(
    tmp_path: Path,
    *,
    op_type: str,
    malicious: bool,
    per_channel: bool,
    full_rank_scale: bool = False,
) -> Path:
    weights = np.zeros((10, 4, 3, 3), dtype=np.int8)
    if malicious:
        weights[3, 0, :2, :3] = 100
    if per_channel and op_type == "ConvInteger":
        weight_scale = np.full((1, 10, 1, 1) if full_rank_scale else (10, 1, 1), 0.1, dtype=np.float32)
    else:
        weight_scale = np.full(10, 0.1, dtype=np.float32) if per_channel else np.asarray(0.1, dtype=np.float32)
    weight_zero_point = np.zeros(10, dtype=np.int8) if per_channel else np.asarray(0, dtype=np.int8)
    initializers = [
        onnx.numpy_helper.from_array(weights, name="W_quantized"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.int8), name="X_zero_point"),
        onnx.numpy_helper.from_array(weight_zero_point, name="W_zero_point"),
        onnx.numpy_helper.from_array(weight_scale, name="W_scale"),
    ]
    if op_type == "ConvInteger":
        nodes = [
            helper.make_node(
                "ConvInteger",
                ["X", "W_quantized", "X_zero_point", "W_zero_point"],
                ["Y_int"],
            ),
            helper.make_node("Cast", ["Y_int"], ["Y_cast"], to=TensorProto.FLOAT),
            helper.make_node("Mul", ["Y_cast", "W_scale"], ["Y"]),
        ]
        output_data_type = TensorProto.FLOAT
    else:
        initializers.extend(
            [
                onnx.numpy_helper.from_array(np.asarray(0.1, dtype=np.float32), name="X_scale"),
                onnx.numpy_helper.from_array(np.asarray(1.0, dtype=np.float32), name="Y_scale"),
                onnx.numpy_helper.from_array(np.asarray(0, dtype=np.int8), name="Y_zero_point"),
            ]
        )
        nodes = [
            helper.make_node(
                "QLinearConv",
                [
                    "X",
                    "X_scale",
                    "X_zero_point",
                    "W_quantized",
                    "W_scale",
                    "W_zero_point",
                    "Y_scale",
                    "Y_zero_point",
                ],
                ["Y"],
            ),
        ]
        output_data_type = TensorProto.INT8
    graph = helper.make_graph(
        nodes,
        f"{op_type.lower()}_weight",
        [helper.make_tensor_value_info("X", TensorProto.INT8, [1, 4, 8, 8])],
        [helper.make_tensor_value_info("Y", output_data_type, [1, 10, 6, 6])],
        initializer=initializers,
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model, full_check=True)
    path = tmp_path / f"{op_type.lower()}-{'channel' if per_channel else 'scalar'}-{malicious}.onnx"
    onnx.save(model, str(path))
    return path


def create_quantize_linear_qlinear_weight_model(
    tmp_path: Path,
    *,
    op_type: str,
    malicious: bool,
    dynamic_quantization: bool = False,
) -> Path:
    if op_type == "QLinearMatMul":
        weights = np.zeros((100, 10), dtype=np.float32)
        if malicious:
            weights[50:55, 3] = 25.5
        input_shape = [1, 100]
        output_shape = [1, 10]
    else:
        weights = np.zeros((10, 4, 3, 3), dtype=np.float32)
        if malicious:
            weights[3, 0, :2, :3] = 25.5
        input_shape = [1, 4, 8, 8]
        output_shape = [1, 10, 6, 6]

    initializers = [
        onnx.numpy_helper.from_array(weights, name="W_float"),
        onnx.numpy_helper.from_array(np.asarray(0.1, dtype=np.float32), name="X_scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name="X_zero_point"),
        onnx.numpy_helper.from_array(np.asarray(1.0, dtype=np.float32), name="Y_scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name="Y_zero_point"),
    ]
    if dynamic_quantization:
        weight_scale_name = "W_dynamic_scale"
        weight_zero_point_name = "W_dynamic_zero_point"
        nodes = [
            helper.make_node(
                "DynamicQuantizeLinear",
                ["W_float"],
                ["W_quantized", weight_scale_name, weight_zero_point_name],
            ),
        ]
    else:
        weight_scale_name = "W_scale"
        weight_zero_point_name = "W_zero_point"
        initializers.extend(
            [
                onnx.numpy_helper.from_array(np.asarray(0.1, dtype=np.float32), name=weight_scale_name),
                onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name=weight_zero_point_name),
            ],
        )
        nodes = [
            helper.make_node(
                "QuantizeLinear",
                ["W_float", weight_scale_name, weight_zero_point_name],
                ["W_quantized"],
            ),
        ]
    if op_type == "QLinearMatMul":
        nodes.append(
            helper.make_node(
                "QLinearMatMul",
                [
                    "X",
                    "X_scale",
                    "X_zero_point",
                    "W_quantized",
                    weight_scale_name,
                    weight_zero_point_name,
                    "Y_scale",
                    "Y_zero_point",
                ],
                ["Y"],
            ),
        )
    else:
        nodes.append(
            helper.make_node(
                "QLinearConv",
                [
                    "X",
                    "X_scale",
                    "X_zero_point",
                    "W_quantized",
                    weight_scale_name,
                    weight_zero_point_name,
                    "Y_scale",
                    "Y_zero_point",
                ],
                ["Y"],
            ),
        )
    graph = helper.make_graph(
        nodes,
        "quantize_linear_qlinear_weight",
        [helper.make_tensor_value_info("X", TensorProto.UINT8, input_shape)],
        [helper.make_tensor_value_info("Y", TensorProto.UINT8, output_shape)],
        initializer=initializers,
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model, full_check=True)
    quantizer_name = "dynamic-quantize-linear" if dynamic_quantization else "quantize-linear"
    path = tmp_path / f"{quantizer_name}-{op_type.lower()}-{'malicious' if malicious else 'benign'}.onnx"
    onnx.save(model, str(path))
    return path


def create_dynamic_quantize_gather_weight_model(tmp_path: Path) -> Path:
    weights = np.zeros((100, 10), dtype=np.float32)
    weights[50:55, 3] = 25.5
    initializers = [
        onnx.numpy_helper.from_array(weights, name="W_float"),
        onnx.numpy_helper.from_array(np.asarray([0], dtype=np.int64), name="indices"),
    ]
    nodes = [
        helper.make_node(
            "DynamicQuantizeLinear",
            ["W_float"],
            ["W_quantized", "W_scale", "W_zero_point"],
        ),
        helper.make_node("Gather", ["W_quantized", "indices"], ["Y"], axis=0),
    ]
    graph = helper.make_graph(
        nodes,
        "dynamic_quantize_gather_weight",
        [],
        [helper.make_tensor_value_info("Y", TensorProto.UINT8, [1, 10])],
        initializer=initializers,
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model, full_check=True)
    path = tmp_path / "dynamic-quantize-gather-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_custom_dynamic_quantize_name_collision_model(tmp_path: Path) -> Path:
    weights = np.zeros((100, 10), dtype=np.float32)
    weights[50:55, 3] = 10.0
    nodes = [
        helper.make_node(
            "DynamicQuantizeLinear",
            ["W"],
            ["unused_0", "custom_weight", "unused_2"],
            domain="com.test",
        ),
        helper.make_node("MatMul", ["X", "custom_weight"], ["Y"]),
    ]
    graph = helper.make_graph(
        nodes,
        "custom_dynamic_quantize_name_collision",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])],
        initializer=[onnx.numpy_helper.from_array(weights, name="W")],
        value_info=[helper.make_tensor_value_info("custom_weight", TensorProto.FLOAT, [100, 10])],
    )
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("com.test", 1)],
    )
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "custom-dynamic-quantize-name-collision.onnx"
    onnx.save(model, str(path))
    return path


def create_qlinear_matmul_left_weight_model(tmp_path: Path, *, malicious: bool) -> Path:
    weights = np.zeros((10, 100), dtype=np.uint8)
    if malicious:
        weights[3, 50:55] = 255
    initializers = [
        onnx.numpy_helper.from_array(weights, name="W"),
        onnx.numpy_helper.from_array(np.asarray(0.1, dtype=np.float32), name="W_scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name="W_zero_point"),
        onnx.numpy_helper.from_array(np.asarray(0.1, dtype=np.float32), name="X_scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name="X_zero_point"),
        onnx.numpy_helper.from_array(np.asarray(1.0, dtype=np.float32), name="Y_scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name="Y_zero_point"),
    ]
    node = helper.make_node(
        "QLinearMatMul",
        ["W", "W_scale", "W_zero_point", "X", "X_scale", "X_zero_point", "Y_scale", "Y_zero_point"],
        ["Y"],
    )
    graph = helper.make_graph(
        [node],
        "qlinear_matmul_left_weight",
        [helper.make_tensor_value_info("X", TensorProto.UINT8, [100, 1])],
        [helper.make_tensor_value_info("Y", TensorProto.UINT8, [10, 1])],
        initializer=initializers,
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 21)])
    model.ir_version = 10
    onnx.checker.check_model(model)
    path = tmp_path / f"qlinear-matmul-left-{'malicious' if malicious else 'benign'}.onnx"
    onnx.save(model, str(path))
    return path


def create_qdq_4bit_weight_model(tmp_path: Path, data_type: int, *, malicious: bool = False) -> Path:
    high_values: dict[int, int] = {
        int(TensorProto.INT2): 1,
        int(TensorProto.UINT2): 3,
        int(TensorProto.INT4): 7,
        int(TensorProto.UINT4): 15,
    }
    high_value = high_values[data_type]
    values = [0] * (100 * 10)
    if malicious:
        for row in range(50, 55):
            values[row * 10 + 3] = high_value
    quantized_weight = helper.make_tensor("W", data_type, [100, 10], values)
    scale = onnx.numpy_helper.from_array(np.asarray(10.0, dtype=np.float32), name="scale")
    zero_point = helper.make_tensor("zero_point", data_type, [], [0])
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])
    nodes = [
        helper.make_node("DequantizeLinear", ["W", "scale", "zero_point"], ["dequantized_weight"]),
        helper.make_node("MatMul", ["X", "dequantized_weight"], ["Y"]),
    ]
    graph = helper.make_graph(
        nodes, "qdq_4bit_weight_graph", [X], [Y], initializer=[quantized_weight, scale, zero_point]
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 21)])
    model.ir_version = 10
    path = tmp_path / f"qdq-weight-{TensorProto.DataType.Name(data_type).lower()}.onnx"
    onnx.save(model, str(path))
    return path


def create_packed_low_bit_initializer_model(
    tmp_path: Path,
    data_type: int,
    *,
    truncate: bool = False,
) -> Path:
    bits_per_element = 2 if data_type in {TensorProto.INT2, TensorProto.UINT2} else 4
    num_elements = 1001
    storage_size = (num_elements * bits_per_element + 7) // 8
    tensor = helper.make_tensor(
        "packed",
        data_type,
        [num_elements],
        bytes(storage_size),
        raw=True,
    )
    if truncate:
        tensor.raw_data = tensor.raw_data[:-1]
    graph = helper.make_graph(
        [],
        "packed_low_bit_initializer",
        [],
        [helper.make_tensor_value_info("packed", data_type, [num_elements])],
        initializer=[tensor],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 21)])
    model.ir_version = 10
    if not truncate:
        onnx.checker.check_model(model, full_check=True)
    path = tmp_path / f"packed-{TensorProto.DataType.Name(data_type).lower()}-{truncate}.onnx"
    onnx.save(model, str(path))
    return path


def create_oversized_packed_zero_point_model(tmp_path: Path) -> Path:
    weights = helper.make_tensor(
        "W",
        TensorProto.INT4,
        [100, 10],
        bytes(500),
        raw=True,
    )
    scale = onnx.numpy_helper.from_array(np.asarray(1.0, dtype=np.float32), name="scale")
    zero_point_elements = 4_002
    zero_point = helper.make_tensor(
        "zero_point",
        TensorProto.INT4,
        [zero_point_elements],
        bytes((zero_point_elements + 1) // 2),
        raw=True,
    )
    graph = helper.make_graph(
        [
            helper.make_node("DequantizeLinear", ["W", "scale", "zero_point"], ["dequantized_weight"]),
            helper.make_node("MatMul", ["X", "dequantized_weight"], ["Y"]),
        ],
        "oversized_packed_zero_point",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])],
        initializer=[weights, scale, zero_point],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 21)])
    model.ir_version = 10
    path = tmp_path / "oversized-packed-zero-point.onnx"
    onnx.save(model, str(path))
    return path


def create_concat_weight_lineage_model(tmp_path: Path, *, dynamic_right: bool = False) -> Path:
    left = np.zeros((50, 10), dtype=np.float32)
    right = np.zeros((50, 10), dtype=np.float32)
    right[:5, 3] = 100
    graph_inputs = [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])]
    initializers = [onnx.numpy_helper.from_array(left, name="W_left")]
    if dynamic_right:
        graph_inputs.append(helper.make_tensor_value_info("W_right", TensorProto.FLOAT, [50, 10]))
    else:
        initializers.append(onnx.numpy_helper.from_array(right, name="W_right"))
    graph = helper.make_graph(
        [
            helper.make_node("Concat", ["W_left", "W_right"], ["W"], axis=0),
            helper.make_node("MatMul", ["X", "W"], ["Y"]),
        ],
        "concat_weight_lineage",
        graph_inputs,
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])],
        initializer=initializers,
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "concat-weight-lineage.onnx"
    onnx.save(model, str(path))
    return path


def create_qdq_transposed_weight_model(tmp_path: Path, *, malicious: bool = False) -> Path:
    weights = np.zeros((10, 100), dtype=np.int8)
    if malicious:
        weights[3, 50:55] = 100
    quantized_weight = onnx.numpy_helper.from_array(weights, name="W")
    scale = onnx.numpy_helper.from_array(np.linspace(0.1, 1.0, 10, dtype=np.float32), name="scale")
    zero_point = onnx.numpy_helper.from_array(np.zeros(10, dtype=np.int8), name="zero_point")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])
    nodes = [
        helper.make_node("DequantizeLinear", ["W", "scale", "zero_point"], ["dequantized_weight"], axis=0),
        helper.make_node("Transpose", ["dequantized_weight"], ["transposed_weight"], perm=[1, 0]),
        helper.make_node("MatMul", ["X", "transposed_weight"], ["Y"]),
    ]
    graph = helper.make_graph(
        nodes, "qdq_transposed_weight_graph", [X], [Y], initializer=[quantized_weight, scale, zero_point]
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "qdq-transposed-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_qdq_transpose_reshape_weight_model(tmp_path: Path) -> Path:
    weights = np.zeros((10, 100), dtype=np.int8)
    initializers = [
        onnx.numpy_helper.from_array(weights, name="W"),
        onnx.numpy_helper.from_array(np.asarray(0.1, dtype=np.float32), name="scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.int8), name="zero_point"),
        onnx.numpy_helper.from_array(np.asarray([20, 50], dtype=np.int64), name="shape"),
    ]
    nodes = [
        helper.make_node("DequantizeLinear", ["W", "scale", "zero_point"], ["dequantized_weight"]),
        helper.make_node("Transpose", ["dequantized_weight"], ["transposed_weight"], perm=[1, 0]),
        helper.make_node("Reshape", ["transposed_weight", "shape"], ["reshaped_weight"]),
        helper.make_node("MatMul", ["X", "reshaped_weight"], ["Y"]),
    ]
    graph = helper.make_graph(
        nodes,
        "qdq_transpose_reshape_weight",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 20])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 50])],
        initializer=initializers,
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model, full_check=True)
    path = tmp_path / "qdq-transpose-reshape-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_qlinear_matmul_nd_scale_model(tmp_path: Path, *, malicious: bool = False) -> Path:
    weights = np.zeros((100, 10), dtype=np.uint8)
    if malicious:
        weights[50:55, 3] = 255
    initializers = [
        onnx.numpy_helper.from_array(weights, name="W"),
        onnx.numpy_helper.from_array(np.asarray(0.1, dtype=np.float32), name="X_scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name="X_zero_point"),
        onnx.numpy_helper.from_array(np.ones(10, dtype=np.float32), name="W_scale"),
        onnx.numpy_helper.from_array(np.zeros(10, dtype=np.uint8), name="W_zero_point"),
        onnx.numpy_helper.from_array(np.asarray(1.0, dtype=np.float32), name="Y_scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name="Y_zero_point"),
    ]
    X = helper.make_tensor_value_info("X", TensorProto.UINT8, [1, 100])
    Y = helper.make_tensor_value_info("Y", TensorProto.UINT8, [1, 10])
    node = helper.make_node(
        "QLinearMatMul",
        ["X", "X_scale", "X_zero_point", "W", "W_scale", "W_zero_point", "Y_scale", "Y_zero_point"],
        ["Y"],
        name="qlinear_matmul",
    )
    graph = helper.make_graph([node], "qlinear_matmul_nd_scale_graph", [X], [Y], initializer=initializers)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 21)])
    model.ir_version = 10
    onnx.checker.check_model(model)
    path = tmp_path / "qlinear-matmul-nd-scale.onnx"
    onnx.save(model, str(path))
    return path


def create_qlinear_matmul_invalid_parameter_model(tmp_path: Path, invalid_kind: str) -> Path:
    weights = np.zeros((100, 10), dtype=np.uint8)
    weights[50:55, 3] = 255
    scale_value = (
        np.ones(weights.shape, dtype=np.float32) if invalid_kind == "full_shape" else np.asarray(0.1, dtype=np.float32)
    )
    zero_point_value = (
        weights
        if invalid_kind == "full_shape"
        else np.asarray(0, dtype=np.float32 if invalid_kind == "zero_point_dtype" else np.uint8)
    )
    if invalid_kind == "scale_dtype":
        scale_value = np.asarray(1, dtype=np.uint8)
    initializers = [
        onnx.numpy_helper.from_array(weights, name="W"),
        onnx.numpy_helper.from_array(np.asarray(0.1, dtype=np.float32), name="X_scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name="X_zero_point"),
        onnx.numpy_helper.from_array(scale_value, name="W_scale"),
        onnx.numpy_helper.from_array(zero_point_value, name="W_zero_point"),
        onnx.numpy_helper.from_array(np.asarray(1.0, dtype=np.float32), name="Y_scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name="Y_zero_point"),
    ]
    node = helper.make_node(
        "QLinearMatMul",
        ["X", "X_scale", "X_zero_point", "W", "W_scale", "W_zero_point", "Y_scale", "Y_zero_point"],
        ["Y"],
    )
    graph = helper.make_graph(
        [node],
        "qlinear_matmul_invalid_parameter",
        [helper.make_tensor_value_info("X", TensorProto.UINT8, [1, 100])],
        [helper.make_tensor_value_info("Y", TensorProto.UINT8, [1, 10])],
        initializer=initializers,
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 21)])
    model.ir_version = 10
    path = tmp_path / f"qlinear-matmul-invalid-{invalid_kind}.onnx"
    onnx.save(model, str(path))
    return path


def create_qlinear_matmul_float16_scale_model(tmp_path: Path) -> Path:
    weights = np.full((100, 10), 2, dtype=np.uint8)
    initializers = [
        onnx.numpy_helper.from_array(weights, name="W"),
        onnx.numpy_helper.from_array(np.asarray(0.1, dtype=np.float16), name="X_scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name="X_zero_point"),
        onnx.numpy_helper.from_array(np.asarray(40_000, dtype=np.float16), name="W_scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name="W_zero_point"),
        onnx.numpy_helper.from_array(np.asarray(1.0, dtype=np.float16), name="Y_scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name="Y_zero_point"),
    ]
    node = helper.make_node(
        "QLinearMatMul",
        ["X", "X_scale", "X_zero_point", "W", "W_scale", "W_zero_point", "Y_scale", "Y_zero_point"],
        ["Y"],
    )
    graph = helper.make_graph(
        [node],
        "qlinear_matmul_float16_scale",
        [helper.make_tensor_value_info("X", TensorProto.UINT8, [1, 100])],
        [helper.make_tensor_value_info("Y", TensorProto.UINT8, [1, 10])],
        initializer=initializers,
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 21)])
    model.ir_version = 10
    onnx.checker.check_model(model, full_check=True)
    path = tmp_path / "qlinear-matmul-float16-scale.onnx"
    onnx.save(model, str(path))
    return path


def create_qlinear_matmul_group_fanout_model(tmp_path: Path, *, consumer_count: int = 100) -> Path:
    weights = np.zeros((64, 64), dtype=np.uint8)
    weights[50:55, 3] = 255
    initializers = [
        onnx.numpy_helper.from_array(weights, name="W"),
        onnx.numpy_helper.from_array(np.asarray(0.1, dtype=np.float32), name="X_scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name="X_zero_point"),
        onnx.numpy_helper.from_array(np.asarray(1.0, dtype=np.float32), name="Y_scale"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name="Y_zero_point"),
        onnx.numpy_helper.from_array(np.asarray(0, dtype=np.uint8), name="W_zero_point"),
    ]
    nodes = []
    for index in range(consumer_count):
        scale_name = f"W_scale_{index}"
        initializers.append(
            onnx.numpy_helper.from_array(np.asarray(0.1 + index / 1000, dtype=np.float32), name=scale_name)
        )
        nodes.append(
            helper.make_node(
                "QLinearMatMul",
                ["X", "X_scale", "X_zero_point", "W", scale_name, "W_zero_point", "Y_scale", "Y_zero_point"],
                [f"Y_{index}"],
                name=f"qlinear_matmul_{index}",
            ),
        )
    X = helper.make_tensor_value_info("X", TensorProto.UINT8, [1, 64])
    Y = helper.make_tensor_value_info(f"Y_{consumer_count - 1}", TensorProto.UINT8, [1, 64])
    graph = helper.make_graph(nodes, "qlinear_group_fanout", [X], [Y], initializer=initializers)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 21)])
    model.ir_version = 10
    onnx.checker.check_model(model)
    path = tmp_path / "qlinear-group-fanout.onnx"
    onnx.save(model, str(path))
    return path


def create_conv_group_fanout_model(tmp_path: Path, *, consumer_count: int = 101) -> Path:
    weights = np.zeros((100, 1, 1), dtype=np.float32)
    weights[3, 0, 0] = 10.0
    initializer = onnx.numpy_helper.from_array(weights, name="W")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100, 1])
    outputs = [f"Y_{index}" for index in range(consumer_count)]
    Y = helper.make_tensor_value_info(outputs[-1], TensorProto.FLOAT, [1, 100, 1])
    nodes = [
        helper.make_node("Conv", ["X", "W"], [output], name=f"conv_{index}", group=index + 1)
        for index, output in enumerate(outputs)
    ]
    graph = helper.make_graph(nodes, "conv_group_fanout", [X], [Y], initializer=[initializer])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    path = tmp_path / "conv-group-fanout.onnx"
    onnx.save(model, str(path))
    return path


def create_sparse_weight_model(tmp_path: Path) -> Path:
    values = helper.make_tensor("W", TensorProto.FLOAT, [5], vals=[10.0] * 5)
    indices = helper.make_tensor(
        "W_indices",
        TensorProto.INT64,
        [5],
        vals=[row * 10 + 3 for row in range(50, 55)],
    )
    sparse_weight = helper.make_sparse_tensor(values, indices, [100, 10])
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])
    node = helper.make_node("MatMul", ["X", "W"], ["Y"], name="linear")
    graph = helper.make_graph([node], "sparse_weight_graph", [X], [Y], sparse_initializer=[sparse_weight])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "sparse-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_constant_weight_model(tmp_path: Path, weights: np.ndarray) -> Path:
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, weights.shape[0]])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, weights.shape[1]])
    weight_tensor = onnx.numpy_helper.from_array(weights)
    nodes = [
        helper.make_node("Constant", [], ["W"], name="weight_constant", value=weight_tensor),
        helper.make_node("MatMul", ["X", "W"], ["Y"], name="linear"),
    ]
    graph = helper.make_graph(nodes, "constant_weight_graph", [X], [Y])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "constant-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_local_function_weight_model(tmp_path: Path, weights: np.ndarray) -> Path:
    domain = "modelaudit.test"
    initializer = onnx.numpy_helper.from_array(weights, name="W")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, weights.shape[0]])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, weights.shape[1]])
    function = helper.make_function(
        domain,
        "Linear",
        ["function_input", "function_weight"],
        ["function_output"],
        [helper.make_node("MatMul", ["function_input", "function_weight"], ["function_output"])],
        [helper.make_opsetid("", 13)],
    )
    call = helper.make_node("Linear", ["X", "W"], ["Y"], domain=domain, name="local_linear")
    graph = helper.make_graph([call], "local_function_graph", [X], [Y], initializer=[initializer])
    model = helper.make_model(
        graph,
        functions=[function],
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid(domain, 1)],
    )
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "local-function-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_local_function_default_weight_model(tmp_path: Path, weights: np.ndarray) -> Path:
    domain = "modelaudit.test"
    attribute_name = "default_weight"
    constant = helper.make_node("Constant", [], ["function_weight"])
    constant.attribute.extend(
        [
            onnx.AttributeProto(
                name="value",
                ref_attr_name=attribute_name,
                type=onnx.AttributeProto.TENSOR,
            ),
        ],
    )
    function = helper.make_function(
        domain,
        "DefaultWeight",
        [],
        ["function_weight"],
        [constant],
        [helper.make_opsetid("", 13)],
        attribute_protos=[helper.make_attribute(attribute_name, onnx.numpy_helper.from_array(weights))],
    )
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, weights.shape[0]])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, weights.shape[1]])
    nodes = [
        helper.make_node("DefaultWeight", [], ["W"], domain=domain),
        helper.make_node("MatMul", ["X", "W"], ["Y"]),
    ]
    graph = helper.make_graph(nodes, "local_function_default_weight_graph", [X], [Y])
    model = helper.make_model(
        graph,
        functions=[function],
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid(domain, 1)],
    )
    model.ir_version = 9
    onnx.checker.check_model(model)
    path = tmp_path / "local-function-default-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_repeated_local_function_default_weight_model(tmp_path: Path, weights: np.ndarray) -> Path:
    """Create two calls to one function-local default Constant weight."""
    domain = "modelaudit.test"
    attribute_name = "default_weight"
    constant = helper.make_node("Constant", [], ["function_weight"])
    constant.attribute.extend(
        [
            onnx.AttributeProto(
                name="value",
                ref_attr_name=attribute_name,
                type=onnx.AttributeProto.TENSOR,
            ),
        ],
    )
    function = helper.make_function(
        domain,
        "DefaultWeight",
        [],
        ["function_weight"],
        [constant],
        [helper.make_opsetid("", 13)],
        attribute_protos=[helper.make_attribute(attribute_name, onnx.numpy_helper.from_array(weights))],
    )
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, weights.shape[0]])
    Y1 = helper.make_tensor_value_info("Y1", TensorProto.FLOAT, [1, weights.shape[1]])
    Y2 = helper.make_tensor_value_info("Y2", TensorProto.FLOAT, [1, weights.shape[1]])
    nodes = [
        helper.make_node("DefaultWeight", [], ["W1"], domain=domain, name="default_weight_1"),
        helper.make_node("DefaultWeight", [], ["W2"], domain=domain, name="default_weight_2"),
        helper.make_node("MatMul", ["X", "W1"], ["Y1"], name="linear_1"),
        helper.make_node("MatMul", ["X", "W2"], ["Y2"], name="linear_2"),
    ]
    graph = helper.make_graph(nodes, "repeated_local_function_default_graph", [X], [Y1, Y2])
    model = helper.make_model(
        graph,
        functions=[function],
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid(domain, 1)],
    )
    model.ir_version = 9
    onnx.checker.check_model(model)
    path = tmp_path / "repeated-local-function-default-weight.onnx"
    onnx.save(model, str(path))
    return path


def create_many_local_function_weight_overrides_model(tmp_path: Path, *, call_count: int = 100) -> Path:
    """Create many distinct function attribute weights with a malicious final binding."""
    domain = "modelaudit.test"
    attribute_name = "weight_values"
    flat_constant = helper.make_node("Constant", [], ["flat_weight"])
    flat_constant.attribute.extend(
        [
            onnx.AttributeProto(
                name="value_floats",
                ref_attr_name=attribute_name,
                type=onnx.AttributeProto.FLOATS,
            ),
        ],
    )
    shape_constant = helper.make_node("Constant", [], ["weight_shape"], value_ints=[100, 10])
    reshape = helper.make_node("Reshape", ["flat_weight", "weight_shape"], ["function_weight"])
    function = helper.make_function(
        domain,
        "OverrideWeight",
        [],
        ["function_weight"],
        [flat_constant, shape_constant, reshape],
        [helper.make_opsetid("", 13)],
        attributes=[attribute_name],
    )
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])
    nodes: list[Any] = []
    for call_index in range(call_count):
        values = np.zeros((100, 10), dtype=np.float32)
        if call_index == call_count - 1:
            values[50:55, 3] = 10.0
        call = helper.make_node(
            "OverrideWeight",
            [],
            [f"W{call_index}"],
            domain=domain,
            name=f"override_weight_{call_index}",
        )
        call.attribute.extend([helper.make_attribute(attribute_name, values.reshape(-1).tolist())])
        nodes.extend(
            [
                call,
                helper.make_node(
                    "MatMul",
                    ["X", f"W{call_index}"],
                    ["Y" if call_index == call_count - 1 else f"unused_Y{call_index}"],
                    name=f"linear_{call_index}",
                ),
            ],
        )
    graph = helper.make_graph(nodes, "many_function_overrides_graph", [X], [Y])
    model = helper.make_model(
        graph,
        functions=[function],
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid(domain, 1)],
    )
    model.ir_version = 9
    onnx.checker.check_model(model)
    path = tmp_path / "many-local-function-weight-overrides.onnx"
    onnx.save(model, str(path))
    return path


def create_many_if_branch_weight_model(tmp_path: Path, *, branch_count: int = 20) -> Path:
    """Create many branch-local weights with a malicious final then-branch."""
    condition = helper.make_tensor_value_info("condition", TensorProto.BOOL, [])
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])
    nodes: list[Any] = []

    def branch_graph(name: str, weights: np.ndarray) -> Any:
        branch_output = helper.make_tensor_value_info("branch_output", TensorProto.FLOAT, [1, 10])
        constant = helper.make_node(
            "Constant",
            [],
            ["W"],
            value=onnx.numpy_helper.from_array(weights),
        )
        matmul = helper.make_node("MatMul", ["X", "W"], ["branch_output"])
        return helper.make_graph([constant, matmul], name, [], [branch_output])

    for branch_index in range(branch_count):
        then_weights = np.zeros((100, 10), dtype=np.float32)
        if branch_index == branch_count - 1:
            then_weights[50:55, 3] = 10.0
        else_weights = np.zeros((100, 10), dtype=np.float32)
        output_name = "Y" if branch_index == branch_count - 1 else f"unused_Y{branch_index}"
        nodes.append(
            helper.make_node(
                "If",
                ["condition"],
                [output_name],
                name=f"conditional_{branch_index}",
                then_branch=branch_graph(f"then_{branch_index}", then_weights),
                else_branch=branch_graph(f"else_{branch_index}", else_weights),
            ),
        )

    graph = helper.make_graph(nodes, "many_if_branch_weights", [condition, X], [Y])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "many-if-branch-weights.onnx"
    onnx.save(model, str(path))
    return path


def create_static_shape_transform_weight_model(
    tmp_path: Path,
    analysis_weights: np.ndarray,
    *,
    transform: str,
) -> Path:
    assert transform in {"Flatten", "ReshapeValueInts", "Squeeze", "Unsqueeze"}
    nodes: list[Any] = []
    initializers: list[Any] = []
    if transform in {"Flatten", "ReshapeValueInts"}:
        stored_weights = analysis_weights.reshape(10, 10, analysis_weights.shape[1]).copy()
    elif transform == "Squeeze":
        stored_weights = analysis_weights.reshape(1, *analysis_weights.shape).copy()
    else:
        stored_weights = analysis_weights.copy()
    initializers.append(onnx.numpy_helper.from_array(stored_weights, name="W"))

    if transform == "Flatten":
        nodes.append(helper.make_node("Flatten", ["W"], ["W_view"], axis=2))
        input_shape = [1, analysis_weights.shape[0]]
    elif transform == "ReshapeValueInts":
        nodes.extend(
            [
                helper.make_node("Constant", [], ["shape"], value_ints=list(analysis_weights.shape)),
                helper.make_node("Reshape", ["W", "shape"], ["W_view"]),
            ],
        )
        input_shape = [1, analysis_weights.shape[0]]
    elif transform == "Squeeze":
        axes = onnx.numpy_helper.from_array(np.asarray([0], dtype=np.int64), name="axes")
        initializers.append(axes)
        nodes.append(helper.make_node("Squeeze", ["W", "axes"], ["W_view"]))
        input_shape = [1, analysis_weights.shape[0]]
    else:
        axes = onnx.numpy_helper.from_array(np.asarray([0], dtype=np.int64), name="axes")
        initializers.append(axes)
        nodes.append(helper.make_node("Unsqueeze", ["W", "axes"], ["W_view"]))
        input_shape = [1, 1, analysis_weights.shape[0]]

    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, input_shape)
    output_shape = [1, analysis_weights.shape[1]] if transform != "Unsqueeze" else [1, 1, analysis_weights.shape[1]]
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, output_shape)
    nodes.append(helper.make_node("MatMul", ["X", "W_view"], ["Y"], name="linear"))
    graph = helper.make_graph(nodes, "static_shape_transform_graph", [X], [Y], initializer=initializers)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / f"{transform.lower()}-weight.onnx"
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
    tensor = _make_external_tensor("nested_W", TensorProto.FLOAT, [1], external_path)

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


_PINNED_HF_ONNX_O4_CASES = (
    (
        "rank2_all_minilm_l6_v2",
        "sentence-transformers/all-MiniLM-L6-v2",
        "1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
    ),
    (
        "rank5_ms_marco_minilm_l6_v2",
        "cross-encoder/ms-marco-MiniLM-L6-v2",
        "c5ee24cb16019beea0893ab7796b1df96625c6b8",
    ),
    (
        "rank20_all_mpnet_base_v2",
        "sentence-transformers/all-mpnet-base-v2",
        "e8c3b32edf5434bc2275fc9bab85f82640a19130",
    ),
)
_PINNED_HF_ONNX_O4_FILENAME = "onnx/model_O4.onnx"
_PINNED_HF_ONNX_MAX_BYTES = 250 * 1024 * 1024


def create_onnx_model_with_custom_nodes(
    tmp_path: Path,
    custom_nodes: list[tuple[str, str, str]],
    *,
    filename: str = "custom_nodes.onnx",
    include_custom_opsets: bool = True,
) -> Path:
    input_value = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1])
    output_value = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1])
    previous_output = "input"
    nodes = []
    for index, (domain, op_type, node_name) in enumerate(custom_nodes):
        next_output = "output" if index == len(custom_nodes) - 1 else f"value_{index}"
        nodes.append(helper.make_node(op_type, [previous_output], [next_output], domain=domain, name=node_name))
        previous_output = next_output

    opset_imports = [helper.make_opsetid("", 13)]
    if include_custom_opsets:
        opset_imports.extend(
            helper.make_opsetid(domain, 1)
            for domain in sorted({domain for domain, _op, _name in custom_nodes if domain})
        )
    graph = helper.make_graph(nodes, "custom_nodes", [input_value], [output_value])
    model = helper.make_model(graph, opset_imports=opset_imports)
    model.ir_version = 8
    model_path = tmp_path / filename
    onnx.save(model, str(model_path))
    return model_path


def create_onnx_model_with_explicit_custom_operator_identities(
    tmp_path: Path,
    custom_nodes: list[tuple[str, str, str, str]],
    *,
    filename: str = "explicit_custom_operator_identities.onnx",
) -> Path:
    input_value = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1])
    output_value = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1])
    previous_output = "input"
    nodes = []
    for index, (domain, op_type, overload, node_name) in enumerate(custom_nodes):
        next_output = "output" if index == len(custom_nodes) - 1 else f"value_{index}"
        node = helper.make_node(op_type, [previous_output], [next_output], domain=domain, name=node_name)
        node.overload = overload
        nodes.append(node)
        previous_output = next_output

    opset_imports = [helper.make_opsetid("", 13)]
    opset_imports.extend(
        helper.make_opsetid(domain, 13)
        for domain in sorted({domain for domain, _op_type, _overload, _node_name in custom_nodes if domain})
    )
    graph = helper.make_graph(nodes, "explicit_custom_operator_identities", [input_value], [output_value])
    model = helper.make_model(graph, opset_imports=opset_imports)
    model.ir_version = 8
    model_path = tmp_path / filename
    onnx.save(model, str(model_path))
    return model_path


def create_onnx_model_with_repeated_custom_domain_and_missing_external_data(tmp_path: Path) -> Path:
    input_value = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1])
    output_value = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1])
    weight = _make_external_tensor("W", TensorProto.FLOAT, [1], "missing-weights.bin")
    nodes = [
        helper.make_node("BackdoorOp", ["input", "W"], ["hidden"], domain="com.external", name="backdoor_0"),
        helper.make_node("BackdoorOp", ["hidden", "W"], ["output"], domain="com.external", name="backdoor_1"),
    ]
    graph = helper.make_graph(nodes, "custom_external_data", [input_value], [output_value], initializer=[weight])
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("com.external", 1)],
    )
    model.ir_version = 8
    model_path = tmp_path / "custom_external_data.onnx"
    onnx.save(model, str(model_path))
    return model_path


def create_onnx_model_with_mixed_custom_domains(tmp_path: Path) -> Path:
    X = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1])
    Z = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1])
    nodes = [
        helper.make_node("FastGelu", ["input"], ["hidden"], domain="com.microsoft", name="ort_fast_gelu"),
        helper.make_node("BackdoorOp", ["hidden"], ["output"], domain="com.acme.ops", name="backdoor"),
    ]
    graph = helper.make_graph(nodes, "mixed_custom_domains", [X], [Z])
    model = helper.make_model(
        graph,
        opset_imports=[
            helper.make_opsetid("", 13),
            helper.make_opsetid("com.microsoft", 1),
            helper.make_opsetid("com.acme.ops", 1),
        ],
    )
    path = tmp_path / "mixed_custom_domains.onnx"
    onnx.save(model, str(path))
    return path


def create_onnx_model_with_function_microsoft_operator(tmp_path: Path, *, op_type: str) -> Path:
    function = helper.make_function(
        "local",
        "MicrosoftWrapper",
        ["X"],
        ["Y"],
        [helper.make_node(op_type, ["X"], ["Y"], domain="com.microsoft")],
        [helper.make_opsetid("", 13), helper.make_opsetid("com.microsoft", 1)],
    )
    graph = helper.make_graph(
        [helper.make_node("MicrosoftWrapper", ["X"], ["Y"], domain="local")],
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
    path = tmp_path / f"function_microsoft_{op_type}.onnx"
    onnx.save(model, str(path))
    return path


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


def test_directory_scan_hashes_external_data_for_content_routed_onnx_bin(tmp_path: Path) -> None:
    model_path = create_onnx_model(tmp_path, external=True, external_path="model.onnx_data")
    routed_model_path = tmp_path / "model.bin"
    model_path.rename(routed_model_path)
    sidecar_path = tmp_path / "model.onnx_data"

    result = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    assert_only_onnx_external_schema_validation_skipped(result)
    assert result.bytes_scanned == routed_model_path.stat().st_size + sidecar_path.stat().st_size
    assert result.content_hash == compute_aggregate_hash(
        [
            compute_sha256_hash(routed_model_path),
            compute_sha256_hash(sidecar_path),
        ]
    )
    assert not any(check.name == "Format Validation" for check in result.checks)


def test_directory_scan_accepts_content_routed_onnx_bin_without_format_validation(tmp_path: Path) -> None:
    model_path = create_onnx_model(tmp_path)
    routed_model_path = tmp_path / "model.bin"
    model_path.rename(routed_model_path)

    result = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    assert result.success is True
    assert "onnx" in result.scanner_names
    assert not any(check.name == "Format Validation" for check in result.checks)


def test_directory_scan_does_not_parse_oversized_streamed_onnx_for_sidecar_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_onnx_model(tmp_path, external=True, external_path="model.onnx_data")
    parsed_paths: list[str] = []

    def tracking_path_loader(path: str, *_args: Any, **_kwargs: Any) -> Any:
        parsed_paths.append(path)
        raise AssertionError("oversized ONNX must not be parsed before max_file_size rejection")

    monkeypatch.setattr(onnx, "load", tracking_path_loader)

    result = scan_model_directory_or_file(
        str(tmp_path),
        max_file_size=model_path.stat().st_size - 1,
        cache_scan_results=False,
    )

    assert parsed_paths == []
    assert result.success is False
    assert any(
        metadata.get("operational_error_reason") == "max_file_size_exceeded"
        for metadata in result.file_metadata.values()
    )


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
        custom_opset_version=1,
    )
    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)
    assert len(custom_domain_checks) == 0, (
        f"Expected no custom-domain finding for ai.onnx.ml. Checks: {[c.message for c in result.checks]}"
    )
    assert "ai.onnx.ml" not in metadata_custom_domains
    assert result.success is True
    assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)


def test_onnx_scanner_standard_preview_training_domain_not_flagged(tmp_path: Path) -> None:
    r_value = helper.make_tensor_value_info("R", TensorProto.FLOAT, [])
    t_value = helper.make_tensor_value_info("T", TensorProto.INT64, [])
    x_value = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1])
    y_value = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])
    node = helper.make_node(
        "Adam",
        ["R", "T", "X"],
        ["Y"],
        domain="ai.onnx.preview.training",
        name="adam",
    )
    graph = helper.make_graph([node], "graph", [r_value, t_value, x_value], [y_value])
    model = helper.make_model(
        graph,
        opset_imports=[
            helper.make_opsetid("", 13),
            helper.make_opsetid("ai.onnx.preview.training", 1),
        ],
    )
    model.ir_version = 8
    model_path = tmp_path / "model.onnx"
    onnx.save(model, str(model_path))

    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)
    assert len(custom_domain_checks) == 0, (
        f"Expected no custom-domain finding for ai.onnx.preview.training. Checks: {[c.message for c in result.checks]}"
    )
    assert "ai.onnx.preview.training" not in metadata_custom_domains
    assert result.success is True
    assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)


def test_onnx_scanner_repeated_custom_domain_nodes_emit_one_domain_check(tmp_path: Path) -> None:
    domain = "com.vendor.runtime"
    custom_nodes = [
        *[(domain, "Attention", f"attention_{index}") for index in range(4)],
        (domain, "BiasAttention", "bias_attention"),
        (domain, "PackedAttention", "packed_attention"),
    ]
    model_path = create_onnx_model_with_custom_nodes(tmp_path, custom_nodes)

    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert len(custom_domain_checks) == 1
    check = custom_domain_checks[0]
    assert check.rule_code == "S1111"
    assert check.severity == IssueSeverity.INFO
    assert check.location == str(model_path)
    assert check.details["domain"] == domain
    assert check.details["occurrence_count"] == len(custom_nodes)
    assert check.details["operator_samples"] == ["Attention", "BiasAttention", "PackedAttention"]
    assert len(check.details["representative_nodes"]) == 5
    assert check.details["representative_nodes_truncated"] is True
    assert result.metadata["custom_domains"] == [domain]
    assert metadata_custom_domains == [domain]
    assert len([issue for issue in result.issues if issue.rule_code == "S1111"]) == 1


def test_onnx_scanner_custom_domain_aggregate_reports_distinct_operator_identities(tmp_path: Path) -> None:
    custom_nodes = [
        ("com.vendor", "KernelA", "fast", "kernel_a_fast"),
        ("com.vendor", "KernelA", "safe", "kernel_a_safe"),
        ("com.vendor", "KernelB", "fast", "kernel_b_fast"),
    ]
    model_path = create_onnx_model_with_explicit_custom_operator_identities(tmp_path, custom_nodes)

    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert len(custom_domain_checks) == 1
    details = custom_domain_checks[0].details
    assert details["domain"] == "com.vendor"
    assert details["occurrence_count"] == len(custom_nodes)
    assert details["distinct_operator_identity_count"] == len(custom_nodes)
    assert [
        {key: identity[key] for key in ("domain", "op_type", "overload")} for identity in details["operator_identities"]
    ] == [
        {"domain": "com.vendor", "op_type": "KernelA", "overload": "fast"},
        {"domain": "com.vendor", "op_type": "KernelA", "overload": "safe"},
        {"domain": "com.vendor", "op_type": "KernelB", "overload": "fast"},
    ]
    assert len({identity["operator_identity_hash"] for identity in details["operator_identities"]}) == len(custom_nodes)
    assert details["operator_identities_truncated"] is False
    assert details["check_consolidation_key"] == f"onnx_custom_operator_domain:{details['domain_hash']}"
    assert metadata_custom_domains == ["com.vendor"]


def test_onnx_scanner_custom_domain_custom_op_overloads_survive_json_and_sarif_serialization(
    tmp_path: Path,
) -> None:
    custom_nodes = [
        ("com.acme", "custom_op", "float", "acme_float"),
        ("com.acme", "custom_op", "int", "acme_int"),
    ]
    model_path = create_onnx_model_with_explicit_custom_operator_identities(tmp_path, custom_nodes)

    result = scan_model_directory_or_file(
        str(model_path),
        cache_scan_results=False,
        check_jit_script=False,
        check_network_comm=False,
        max_array_size=1,
    )

    expected_identities = [
        {"domain": "com.acme", "op_type": "custom_op", "overload": "float"},
        {"domain": "com.acme", "op_type": "custom_op", "overload": "int"},
    ]
    json_payload = result.model_dump(mode="json")
    json_custom_issues = [
        issue
        for issue in json_payload["issues"]
        if issue.get("rule_code") == "S1111" and issue.get("details", {}).get("domain") == "com.acme"
    ]

    assert len(json_custom_issues) == 1
    assert [
        {key: identity[key] for key in ("domain", "op_type", "overload")}
        for identity in json_custom_issues[0]["details"]["operator_identities"]
    ] == expected_identities
    assert len(
        {identity["operator_identity_hash"] for identity in json_custom_issues[0]["details"]["operator_identities"]}
    ) == len(expected_identities)
    assert json_custom_issues[0]["details"]["distinct_operator_identity_count"] == len(expected_identities)
    assert json_custom_issues[0]["details"]["operator_identities_truncated"] is False

    sarif_payload = json.loads(format_sarif_output(result, [str(model_path)]))
    sarif_results = [
        item
        for item in sarif_payload["runs"][0]["results"]
        if item["ruleId"] == "S1111" and item.get("properties", {}).get("domain") == "com.acme"
    ]

    assert len(sarif_results) == 1
    assert [
        {key: identity[key] for key in ("domain", "op_type", "overload")}
        for identity in sarif_results[0]["properties"]["operator_identities"]
    ] == expected_identities
    assert sarif_results[0]["properties"]["distinct_operator_identity_count"] == len(expected_identities)


def test_onnx_scanner_repeated_custom_domains_emit_one_check_per_domain(tmp_path: Path) -> None:
    custom_nodes = [
        ("com.vendor.alpha", "Attention", "attention_0"),
        ("com.vendor.alpha", "Attention", "attention_1"),
        ("com.attacker", "BackdoorOp", "backdoor_0"),
        ("com.attacker", "BackdoorOp", "backdoor_1"),
        ("ai.onnx.ml.malicious", "BackdoorOp", "lookalike"),
    ]
    model_path = create_onnx_model_with_custom_nodes(tmp_path, custom_nodes)

    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    checks_by_domain = {check.details["domain"]: check for check in custom_domain_checks}
    assert sorted(checks_by_domain) == ["ai.onnx.ml.malicious", "com.attacker", "com.vendor.alpha"]
    assert checks_by_domain["com.vendor.alpha"].details["occurrence_count"] == 2
    assert checks_by_domain["com.attacker"].details["occurrence_count"] == 2
    assert checks_by_domain["ai.onnx.ml.malicious"].details["occurrence_count"] == 1
    assert metadata_custom_domains == ["ai.onnx.ml.malicious", "com.attacker", "com.vendor.alpha"]


def test_onnx_scanner_custom_domains_survive_core_check_consolidation(tmp_path: Path) -> None:
    custom_nodes = [
        ("com.vendor.alpha", "Attention", "attention_0"),
        ("com.attacker", "BackdoorOp", "backdoor_0"),
        ("ai.onnx.ml.malicious", "BackdoorOp", "lookalike"),
    ]
    model_path = create_onnx_model_with_custom_nodes(tmp_path, custom_nodes)

    result = scan_model_directory_or_file(
        str(model_path),
        cache_scan_results=False,
        check_jit_script=False,
        check_network_comm=False,
        max_array_size=1,
    )

    custom_checks = [
        check
        for check in result.checks
        if check.name == "Custom Operator Domain Check" and check.status == CheckStatus.FAILED
    ]
    checks_by_domain = {check.details["domain"]: check for check in custom_checks}

    assert sorted(checks_by_domain) == ["ai.onnx.ml.malicious", "com.attacker", "com.vendor.alpha"]
    assert len({check.details["check_consolidation_key"] for check in custom_checks}) == len(custom_nodes)
    assert all(
        check.details["check_consolidation_key"] == f"onnx_custom_operator_domain:{check.details['domain_hash']}"
        for check in custom_checks
    )
    assert {
        issue.details["domain"]
        for issue in result.issues
        if issue.rule_code == "S1111" and issue.details.get("type") != "python_operator"
    } == set(checks_by_domain)


def test_onnx_scanner_long_custom_domain_operator_identities_use_raw_hashes(
    tmp_path: Path,
) -> None:
    shared_display_prefix = "Kernel" + ("A" * 280)
    custom_nodes = [
        ("com.vendor", f"{shared_display_prefix}_one", "", "long_one"),
        ("com.vendor", f"{shared_display_prefix}_two", "", "long_two"),
    ]
    model_path = create_onnx_model_with_explicit_custom_operator_identities(tmp_path, custom_nodes)

    result = scan_model_directory_or_file(
        str(model_path),
        cache_scan_results=False,
        check_jit_script=False,
        check_network_comm=False,
        max_array_size=1,
    )

    json_payload = result.model_dump(mode="json")
    json_custom_issues = [
        issue
        for issue in json_payload["issues"]
        if issue.get("rule_code") == "S1111" and issue.get("details", {}).get("domain") == "com.vendor"
    ]

    assert len(json_custom_issues) == 1
    identities = json_custom_issues[0]["details"]["operator_identities"]
    assert json_custom_issues[0]["details"]["distinct_operator_identity_count"] == len(custom_nodes)
    assert json_custom_issues[0]["details"]["operator_identities_truncated"] is False
    assert len(identities) == len(custom_nodes)
    assert len({identity["op_type"] for identity in identities}) == 1
    assert len({identity["operator_identity_hash"] for identity in identities}) == len(custom_nodes)

    sarif_payload = json.loads(format_sarif_output(result, [str(model_path)]))
    sarif_results = [
        item
        for item in sarif_payload["runs"][0]["results"]
        if item["ruleId"] == "S1111" and item.get("properties", {}).get("domain") == "com.vendor"
    ]

    assert len(sarif_results) == 1
    assert sarif_results[0]["properties"]["distinct_operator_identity_count"] == len(custom_nodes)
    assert len(
        {identity["operator_identity_hash"] for identity in sarif_results[0]["properties"]["operator_identities"]}
    ) == len(custom_nodes)


def test_onnx_scanner_long_custom_domains_survive_core_check_and_issue_dedup(
    tmp_path: Path,
) -> None:
    shared_domain_prefix = "com." + ("a" * 280)
    custom_nodes = [
        (f"{shared_domain_prefix}.one", "KernelA", "long_domain_one"),
        (f"{shared_domain_prefix}.two", "KernelB", "long_domain_two"),
    ]
    model_path = create_onnx_model_with_custom_nodes(tmp_path, custom_nodes)

    result = scan_model_directory_or_file(
        str(model_path),
        cache_scan_results=False,
        check_jit_script=False,
        check_network_comm=False,
        max_array_size=1,
    )

    expected_domains = {domain for domain, _op_type, _node_name in custom_nodes}
    json_payload = result.model_dump(mode="json")
    json_custom_issues = [
        issue
        for issue in json_payload["issues"]
        if issue.get("rule_code") == "S1111"
        and issue.get("details", {}).get("domain", "").startswith(shared_domain_prefix)
    ]
    json_custom_checks = [
        check
        for check in json_payload["checks"]
        if check.get("rule_code") == "S1111"
        and check.get("details", {}).get("domain", "").startswith(shared_domain_prefix)
    ]

    assert {issue["details"]["domain"] for issue in json_custom_issues} == expected_domains
    assert {check["details"]["domain"] for check in json_custom_checks} == expected_domains
    assert len({issue["message"] for issue in json_custom_issues}) == len(expected_domains)
    assert len({check["details"]["domain_hash"] for check in json_custom_checks}) == len(expected_domains)
    assert len({check["details"]["check_consolidation_key"] for check in json_custom_checks}) == len(expected_domains)
    assert all(
        check["details"]["check_consolidation_key"] == f"onnx_custom_operator_domain:{check['details']['domain_hash']}"
        for check in json_custom_checks
    )

    sarif_payload = json.loads(format_sarif_output(result, [str(model_path)]))
    sarif_results = [
        item
        for item in sarif_payload["runs"][0]["results"]
        if item["ruleId"] == "S1111" and item.get("properties", {}).get("domain", "").startswith(shared_domain_prefix)
    ]

    assert {item["properties"]["domain"] for item in sarif_results} == expected_domains
    assert len({item["properties"]["domain_hash"] for item in sarif_results}) == len(expected_domains)
    assert len({item["partialFingerprints"]["primaryLocationLineHash"] for item in sarif_results}) == len(
        expected_domains
    )


def test_onnx_scanner_repeated_custom_domain_without_opset_import_still_flagged(tmp_path: Path) -> None:
    custom_nodes = [
        ("com.malformed", "BackdoorOp", "backdoor_0"),
        ("com.malformed", "BackdoorOp", "backdoor_1"),
    ]
    model_path = create_onnx_model_with_custom_nodes(
        tmp_path,
        custom_nodes,
        include_custom_opsets=False,
    )

    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert len(custom_domain_checks) == 1
    assert custom_domain_checks[0].details["domain"] == "com.malformed"
    assert custom_domain_checks[0].details["occurrence_count"] == 2
    assert metadata_custom_domains == ["com.malformed"]


def test_onnx_scanner_custom_domain_dedup_preserves_external_data_findings(tmp_path: Path) -> None:
    model_path = create_onnx_model_with_repeated_custom_domain_and_missing_external_data(tmp_path)

    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert len(custom_domain_checks) == 1
    assert custom_domain_checks[0].details["domain"] == "com.external"
    assert custom_domain_checks[0].details["occurrence_count"] == 2
    assert metadata_custom_domains == ["com.external"]
    missing_external_checks = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check" and check.status == CheckStatus.FAILED
    ]
    assert missing_external_checks


def test_onnx_scanner_custom_domain_dedup_preserves_python_operator_detection(tmp_path: Path) -> None:
    custom_nodes = [
        ("com.attacker", "BackdoorOp", "backdoor_0"),
        ("com.attacker", "BackdoorOp", "backdoor_1"),
        ("com.attacker", "PyOp", "evil_pyop"),
    ]
    model_path = create_onnx_model_with_custom_nodes(tmp_path, custom_nodes)

    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert result.success is False
    assert len(custom_domain_checks) == 1
    assert custom_domain_checks[0].details["domain"] == "com.attacker"
    assert custom_domain_checks[0].details["occurrence_count"] == 3
    assert metadata_custom_domains == ["com.attacker"]
    python_operator_checks = [
        check
        for check in result.checks
        if check.name == "Python Operator Detection" and check.status == CheckStatus.FAILED
    ]
    assert len(python_operator_checks) == 1
    assert python_operator_checks[0].severity == IssueSeverity.CRITICAL
    assert python_operator_checks[0].details["op_type"] == "PyOp"


def test_onnx_scanner_custom_domain_dedup_preserves_multi_file_evidence(tmp_path: Path) -> None:
    create_onnx_model_with_custom_nodes(
        tmp_path,
        [("com.shared", "BackdoorOp", "first_0"), ("com.shared", "BackdoorOp", "first_1")],
        filename="first.onnx",
    )
    create_onnx_model_with_custom_nodes(
        tmp_path,
        [("com.shared", "BackdoorOp", "second_0"), ("com.shared", "BackdoorOp", "second_1")],
        filename="second.onnx",
    )

    result = scan_model_directory_or_file(
        str(tmp_path),
        recursive=False,
        cache_scan_results=False,
        check_jit_script=False,
        check_network_comm=False,
        max_array_size=1,
    )

    custom_checks = [
        check
        for check in result.checks
        if check.name == "Custom Operator Domain Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("domain") == "com.shared"
    ]
    assert len(custom_checks) == 2
    assert {Path(str(check.location)).name for check in custom_checks} == {"first.onnx", "second.onnx"}
    assert all(check.details["occurrence_count"] == 2 for check in custom_checks)


def test_onnx_scanner_explicit_custom_op_identity_survives_json_and_sarif_serialization(
    tmp_path: Path,
) -> None:
    custom_nodes = [
        ("", "custom_op", "float", "default_float"),
        ("", "custom_op", "int", "default_int"),
        ("ai.onnx", "custom_op", "float", "ai_onnx_float"),
    ]
    model_path = create_onnx_model_with_explicit_custom_operator_identities(tmp_path, custom_nodes)

    result = scan_model_directory_or_file(
        str(model_path),
        cache_scan_results=False,
        check_jit_script=False,
        check_network_comm=False,
        max_array_size=1,
    )

    expected_identities = {
        ("", "custom_op", "float"),
        ("", "custom_op", "int"),
        ("ai.onnx", "custom_op", "float"),
    }
    json_payload = result.model_dump(mode="json")
    json_custom_issues = [
        issue
        for issue in json_payload["issues"]
        if issue.get("rule_code") == "S1111"
        and issue.get("details", {}).get("operator_identity", {}).get("op_type") == "custom_op"
    ]

    assert len(json_custom_issues) == len(expected_identities)
    assert {
        (
            issue["details"]["operator_identity"]["domain"],
            issue["details"]["operator_identity"]["op_type"],
            issue["details"]["operator_identity"]["overload"],
        )
        for issue in json_custom_issues
    } == expected_identities
    assert len({issue["message"] for issue in json_custom_issues}) == len(expected_identities)
    assert all(issue["location"] == str(model_path) for issue in json_custom_issues)

    sarif_payload = json.loads(format_sarif_output(result, [str(model_path)]))
    sarif_results = [item for item in sarif_payload["runs"][0]["results"] if item["ruleId"] == "S1111"]

    assert len(sarif_results) == len(expected_identities)
    assert {item["message"]["text"] for item in sarif_results} == {issue["message"] for issue in json_custom_issues}
    assert len({item["partialFingerprints"]["primaryLocationLineHash"] for item in sarif_results}) == len(
        expected_identities
    )
    assert {
        (
            item["properties"]["operator_identity"]["domain"],
            item["properties"]["operator_identity"]["op_type"],
            item["properties"]["operator_identity"]["overload"],
        )
        for item in sarif_results
    } == expected_identities


def test_onnx_scanner_long_explicit_custom_op_names_survive_json_and_sarif_dedup(
    tmp_path: Path,
) -> None:
    shared_display_prefix = "custom_op_" + ("a" * 280)
    custom_nodes = [
        ("", f"{shared_display_prefix}_float", "", "long_float"),
        ("", f"{shared_display_prefix}_int", "", "long_int"),
    ]
    model_path = create_onnx_model_with_explicit_custom_operator_identities(tmp_path, custom_nodes)

    result = scan_model_directory_or_file(
        str(model_path),
        cache_scan_results=False,
        check_jit_script=False,
        check_network_comm=False,
        max_array_size=1,
    )

    json_payload = result.model_dump(mode="json")
    json_custom_issues = [
        issue
        for issue in json_payload["issues"]
        if issue.get("rule_code") == "S1111"
        and issue.get("details", {}).get("operator_identity", {}).get("op_type", "").startswith(shared_display_prefix)
    ]

    assert len(json_custom_issues) == len(custom_nodes)
    assert {issue["details"]["operator_identity"]["op_type"] for issue in json_custom_issues} == {
        op_type for _domain, op_type, _overload, _node_name in custom_nodes
    }
    assert len({issue["details"]["operator_identity_hash"] for issue in json_custom_issues}) == len(custom_nodes)
    assert len({issue["message"] for issue in json_custom_issues}) == len(custom_nodes)

    sarif_payload = json.loads(format_sarif_output(result, [str(model_path)]))
    sarif_results = [
        item
        for item in sarif_payload["runs"][0]["results"]
        if item["ruleId"] == "S1111"
        and item.get("properties", {}).get("operator_identity", {}).get("op_type", "").startswith(shared_display_prefix)
    ]

    assert len(sarif_results) == len(custom_nodes)
    assert len({item["properties"]["operator_identity_hash"] for item in sarif_results}) == len(custom_nodes)
    assert len({item["partialFingerprints"]["primaryLocationLineHash"] for item in sarif_results}) == len(custom_nodes)


def test_onnx_scanner_custom_operator_identity_hash_length_frames_nul_values(
    tmp_path: Path,
) -> None:
    custom_nodes = [
        ("", "custom_op\0x", "", "nul_in_op_type"),
        ("", "custom_op", "x\0", "nul_in_overload"),
    ]
    model_path = create_onnx_model_with_explicit_custom_operator_identities(tmp_path, custom_nodes)

    result = scan_model_directory_or_file(
        str(model_path),
        cache_scan_results=False,
        check_jit_script=False,
        check_network_comm=False,
        max_array_size=1,
    )

    expected_identities = {
        ("", "custom_op\0x", ""),
        ("", "custom_op", "x\0"),
    }
    json_payload = result.model_dump(mode="json")
    json_custom_issues = [
        issue
        for issue in json_payload["issues"]
        if issue.get("rule_code") == "S1111" and "operator_identity_hash" in issue.get("details", {})
    ]

    assert len(json_custom_issues) == len(expected_identities)
    assert {
        (
            issue["details"]["operator_identity"]["domain"],
            issue["details"]["operator_identity"]["op_type"],
            issue["details"]["operator_identity"]["overload"],
        )
        for issue in json_custom_issues
    } == expected_identities
    assert len({issue["details"]["operator_identity_hash"] for issue in json_custom_issues}) == len(expected_identities)

    sarif_payload = json.loads(format_sarif_output(result, [str(model_path)]))
    sarif_results = [
        item
        for item in sarif_payload["runs"][0]["results"]
        if item["ruleId"] == "S1111" and "operator_identity_hash" in item.get("properties", {})
    ]

    assert len(sarif_results) == len(expected_identities)
    assert len({item["properties"]["operator_identity_hash"] for item in sarif_results}) == len(expected_identities)
    assert len({item["partialFingerprints"]["primaryLocationLineHash"] for item in sarif_results}) == len(
        expected_identities
    )


@pytest.mark.parametrize("op_type", ["FastGelu", "SkipLayerNormalization"])
def test_onnx_scanner_known_microsoft_runtime_ops_not_flagged(tmp_path: Path, op_type: str) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="com.microsoft",
        custom_op_type=op_type,
        custom_opset_version=1,
    )

    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert custom_domain_checks == []
    assert "com.microsoft" not in result.metadata.get("custom_domains", [])
    assert "com.microsoft" not in metadata_custom_domains
    assert not [issue for issue in result.issues if issue.rule_code == "S1111"]


def test_onnx_scanner_mixed_microsoft_and_unknown_domains_flags_only_unknown(tmp_path: Path) -> None:
    model_path = create_onnx_model_with_mixed_custom_domains(tmp_path)

    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert len(custom_domain_checks) == 1
    assert custom_domain_checks[0].rule_code == "S1111"
    assert custom_domain_checks[0].details["domain"] == "com.acme.ops"
    assert custom_domain_checks[0].details["op_type"] == "BackdoorOp"
    assert result.metadata["custom_domains"] == ["com.acme.ops"]
    assert metadata_custom_domains == ["com.acme.ops"]


def test_onnx_scanner_unknown_microsoft_runtime_op_still_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="com.microsoft",
        custom_op_type="BackdoorOp",
        custom_opset_version=1,
    )

    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert len(custom_domain_checks) == 1
    assert custom_domain_checks[0].rule_code == "S1111"
    assert custom_domain_checks[0].details["domain"] == "com.microsoft"
    assert custom_domain_checks[0].details["op_type"] == "BackdoorOp"
    assert metadata_custom_domains == ["com.microsoft"]


@pytest.mark.parametrize(
    "domain",
    ["com.microsoft.evil", "com.microsoftx", "microsoft.com", "COM.MICROSOFT", "com.microsoft "],
)
def test_onnx_scanner_microsoft_domain_lookalikes_still_flagged(tmp_path: Path, domain: str) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain=domain,
        custom_op_type="FastGelu",
        custom_opset_version=1,
    )

    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert len(custom_domain_checks) == 1
    assert custom_domain_checks[0].rule_code == "S1111"
    assert custom_domain_checks[0].details["domain"] == domain
    assert metadata_custom_domains == [domain]


@pytest.mark.parametrize(
    ("custom_opset_version", "overload"),
    [(None, ""), (999, ""), (1, "evil")],
    ids=["missing-opset", "unsupported-opset", "nonempty-overload"],
)
def test_onnx_scanner_microsoft_runtime_policy_fails_closed_when_ambiguous(
    tmp_path: Path,
    custom_opset_version: int | None,
    overload: str,
) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="com.microsoft",
        custom_op_type="FastGelu",
        custom_opset_version=custom_opset_version,
    )
    if overload:
        model = onnx.load(str(model_path))
        model.graph.node[0].overload = overload
        onnx.save(model, str(model_path))

    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert len(custom_domain_checks) == 1
    assert custom_domain_checks[0].rule_code == "S1111"
    assert custom_domain_checks[0].details["domain"] == "com.microsoft"
    assert custom_domain_checks[0].details["op_type"] == "FastGelu"
    assert metadata_custom_domains == ["com.microsoft"]


def test_onnx_scanner_microsoft_runtime_policy_fails_closed_on_conflicting_opsets(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="com.microsoft",
        custom_op_type="FastGelu",
        custom_opset_version=1,
    )
    model = onnx.load(str(model_path))
    model = helper.make_model(
        model.graph,
        opset_imports=[
            helper.make_opsetid("", 13),
            helper.make_opsetid("com.microsoft", 999),
            helper.make_opsetid("com.microsoft", 1),
        ],
    )
    onnx.save(model, str(model_path))

    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert len(custom_domain_checks) == 1
    assert custom_domain_checks[0].rule_code == "S1111"
    assert custom_domain_checks[0].details["domain"] == "com.microsoft"
    assert metadata_custom_domains == ["com.microsoft"]


def test_onnx_scanner_microsoft_python_operator_still_critical(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="com.microsoft",
        custom_op_type="PythonOp",
        custom_opset_version=1,
    )

    result = OnnxScanner().scan(str(model_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Operator Detection" and check.status == CheckStatus.FAILED
    ]
    assert result.success is False
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S902"
    assert python_checks[0].severity == IssueSeverity.CRITICAL
    assert python_checks[0].details["domain"] == "com.microsoft"
    assert python_checks[0].details["op_type"] == "PythonOp"


def test_onnx_scanner_function_body_microsoft_runtime_op_uses_function_opset(tmp_path: Path) -> None:
    model_path = create_onnx_model_with_function_microsoft_operator(tmp_path, op_type="FastGelu")

    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert custom_domain_checks == []
    assert "com.microsoft" not in result.metadata.get("custom_domains", [])
    assert "com.microsoft" not in metadata_custom_domains


def test_onnx_scanner_function_body_unknown_microsoft_op_still_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model_with_function_microsoft_operator(tmp_path, op_type="BackdoorOp")

    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert len(custom_domain_checks) == 1
    assert custom_domain_checks[0].rule_code == "S1111"
    assert custom_domain_checks[0].details["domain"] == "com.microsoft"
    assert custom_domain_checks[0].details["op_type"] == "BackdoorOp"
    assert metadata_custom_domains == ["com.microsoft"]


@pytest.mark.slow
@pytest.mark.integration
@pytest.mark.parametrize(
    ("case_id", "repo_id", "revision"),
    _PINNED_HF_ONNX_O4_CASES,
    ids=[case[0] for case in _PINNED_HF_ONNX_O4_CASES],
)
def test_onnx_scanner_pinned_hf_microsoft_runtime_domains_are_low_noise(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case_id: str,
    repo_id: str,
    revision: str,
) -> None:
    if os.environ.get("MODELAUDIT_RUN_HF_REAL_MODEL_TESTS") != "1":
        pytest.skip("set MODELAUDIT_RUN_HF_REAL_MODEL_TESTS=1 to download pinned Hugging Face ONNX models")

    monkeypatch.setenv("PROMPTFOO_DISABLE_TELEMETRY", "1")
    monkeypatch.setenv("HF_HUB_DISABLE_TELEMETRY", "1")
    huggingface_hub = pytest.importorskip("huggingface_hub")
    cache_dir = tmp_path / "hf-cache"

    model_path = Path(
        huggingface_hub.hf_hub_download(
            repo_id=repo_id,
            revision=revision,
            filename=_PINNED_HF_ONNX_O4_FILENAME,
            cache_dir=str(cache_dir),
        )
    )
    assert model_path.stat().st_size <= _PINNED_HF_ONNX_MAX_BYTES

    model = onnx.load(str(model_path), load_external_data=False)
    microsoft_ops = {node.op_type for node in model.graph.node if node.domain == "com.microsoft"}
    assert {"FastGelu", "SkipLayerNormalization"}.issubset(microsoft_ops), case_id

    scanner = OnnxScanner({"check_jit_script": False, "check_network_comm": False, "max_array_size": 1})
    result = scanner.scan(str(model_path))
    metadata = scanner.extract_metadata(str(model_path))

    microsoft_domain_checks = [
        check for check in _failed_custom_domain_checks(result) if check.details.get("domain") == "com.microsoft"
    ]
    assert microsoft_domain_checks == []
    assert "com.microsoft" not in result.metadata.get("custom_domains", [])
    assert "com.microsoft" not in metadata.get("custom_domains", [])


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
    assert result.success is True
    assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)


def test_onnx_scanner_registered_onnx_ml_static_data_stays_clean(tmp_path: Path) -> None:
    data = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="data")
    output = helper.make_tensor_value_info("output", TensorProto.FLOAT, [100, 10])
    normalizer = helper.make_node("Normalizer", ["data"], ["output"], domain="ai.onnx.ml")
    graph = helper.make_graph([normalizer], "onnx_ml_static_data", [], [output], initializer=[data])
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("ai.onnx.ml", 3)],
    )
    model.ir_version = 8
    onnx.checker.check_model(model)
    model_path = tmp_path / "onnx-ml-static-data.onnx"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    assert semantics["eligible_initializer_count"] == 0
    assert semantics["coverage_gaps"] == {}


def test_onnx_scanner_static_onnx_ml_output_used_as_weight_fails_closed(tmp_path: Path) -> None:
    left_data = np.zeros((100, 100), dtype=np.float32)
    left_data[0, 0] = 1e20
    initializers = [
        onnx.numpy_helper.from_array(left_data, name="left_data"),
        onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="right_weight"),
    ]
    output = helper.make_tensor_value_info("output", TensorProto.FLOAT, [100, 10])
    nodes = [
        helper.make_node("Normalizer", ["left_data"], ["left_normalized"], domain="ai.onnx.ml"),
        helper.make_node("MatMul", ["left_normalized", "right_weight"], ["output"]),
    ]
    graph = helper.make_graph(nodes, "onnx_ml_static_weight_path", [], [output], initializer=initializers)
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("ai.onnx.ml", 3)],
    )
    model.ir_version = 8
    onnx.checker.check_model(model)
    model_path = tmp_path / "onnx-ml-static-weight-path.onnx"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    coverage_checks = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    assert semantics["eligible_initializer_count"] == 2
    assert semantics["analyzed_layer_count"] == 1


def test_onnx_scanner_onnx_ml_bookkeeping_initializer_stays_clean(tmp_path: Path) -> None:
    features = helper.make_tensor_value_info("features", TensorProto.FLOAT, [1, 2])
    output = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, 1])
    indices = helper.make_tensor("indices", TensorProto.INT64, [1], [0])
    node = helper.make_node(
        "ArrayFeatureExtractor",
        ["features", "indices"],
        ["output"],
        domain="ai.onnx.ml",
    )
    graph = helper.make_graph([node], "feature_extractor", [features], [output], initializer=[indices])
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("ai.onnx.ml", 3)],
    )
    model.ir_version = 8
    onnx.checker.check_model(model)
    model_path = tmp_path / "array-feature-extractor.onnx"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    assert semantics["eligible_initializer_count"] == 0
    assert semantics["coverage_gaps"] == {}


@pytest.mark.parametrize("transform", ["Add", "Sub", "Abs"])
def test_onnx_scanner_transformed_onnx_ml_bookkeeping_initializer_stays_clean(
    tmp_path: Path,
    transform: str,
) -> None:
    features = helper.make_tensor_value_info("features", TensorProto.FLOAT, [1, 2])
    output = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, 1])
    indices = helper.make_tensor("indices", TensorProto.INT64, [1], [0])
    graph_inputs = [features]
    if transform == "Abs":
        transform_node = helper.make_node(transform, ["indices"], ["dynamic_indices"])
    else:
        graph_inputs.append(helper.make_tensor_value_info("offset", TensorProto.INT64, [1]))
        transform_node = helper.make_node(transform, ["indices", "offset"], ["dynamic_indices"])
    nodes = [
        transform_node,
        helper.make_node(
            "ArrayFeatureExtractor",
            ["features", "dynamic_indices"],
            ["output"],
            domain="ai.onnx.ml",
        ),
    ]
    graph = helper.make_graph(nodes, "transformed_feature_extractor", graph_inputs, [output], [indices])
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("ai.onnx.ml", 3)],
    )
    model.ir_version = 8
    onnx.checker.check_model(model)
    model_path = tmp_path / "transformed-array-feature-extractor.onnx"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    assert semantics["eligible_initializer_count"] == 0
    assert semantics["coverage_gaps"] == {}


def test_onnx_scanner_onnx_ml_selector_does_not_taint_downstream_weights(tmp_path: Path) -> None:
    features = helper.make_tensor_value_info("features", TensorProto.FLOAT, [1, 4])
    output = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, 3])
    indices = helper.make_tensor("indices", TensorProto.INT64, [2], [0, 1])
    weights = onnx.numpy_helper.from_array(np.zeros((2, 3), dtype=np.float32), name="W")
    nodes = [
        helper.make_node(
            "ArrayFeatureExtractor",
            ["features", "indices"],
            ["selected"],
            domain="ai.onnx.ml",
        ),
        helper.make_node("MatMul", ["selected", "W"], ["output"]),
    ]
    graph = helper.make_graph(nodes, "feature_selection_matmul", [features], [output], [indices, weights])
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 13), helper.make_opsetid("ai.onnx.ml", 3)],
    )
    model.ir_version = 8
    onnx.checker.check_model(model)
    model_path = tmp_path / "feature-selection-matmul.onnx"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    assert semantics["eligible_initializer_count"] == 1
    assert semantics["analyzed_layer_count"] == 1
    assert semantics["coverage_gaps"] == {}


@pytest.mark.parametrize("transform", ["Reshape", "Cast", "CastReshape"])
def test_onnx_scanner_training_consumer_uses_effective_lineage_shape_and_dtype(
    tmp_path: Path,
    transform: str,
) -> None:
    model_path = create_training_transformed_weight_model(tmp_path, transform=transform)

    result = OnnxScanner().scan(str(model_path))

    coverage_checks = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
    assert result.success is False
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}


@pytest.mark.parametrize("transform", ["Reshape", "Cast"])
def test_onnx_scanner_nonweight_effective_transform_stays_clean(tmp_path: Path, transform: str) -> None:
    model_path = create_nonweight_transformed_matmul_model(tmp_path, transform=transform)

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    assert semantics["eligible_initializer_count"] == 0
    assert semantics["coverage_gaps"] == {}


def test_onnx_scanner_zipmap_activation_lineage_stays_clean(tmp_path: Path) -> None:
    model_path = create_zipmap_classifier_model(tmp_path)

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    assert semantics["eligible_initializer_count"] == 1
    assert semantics["analyzed_layer_count"] == 1
    assert semantics["coverage_gaps"] == {}


def test_onnx_scanner_training_graph_opaque_weight_consumer_fails_closed(tmp_path: Path) -> None:
    model_path = create_training_info_weight_model(tmp_path)

    result = OnnxScanner().scan(str(model_path))

    coverage_checks = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
    assert result.success is False
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    assert semantics["eligible_initializer_count"] == 1
    assert semantics["unresolved_lineage_samples"][0]["consumer_op"] == "Adam"


def test_onnx_scanner_read_only_main_initializer_is_visible_to_training_graph(tmp_path: Path) -> None:
    model_path = create_read_only_main_initializer_training_model(tmp_path)

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    assert semantics["eligible_initializer_count"] == 0
    assert semantics["coverage_gaps"] == {}


@pytest.mark.parametrize(
    ("data_type", "op_type", "shape", "opset_version"),
    [
        pytest.param(TensorProto.INT64, "Sub", (), 13, id="integer-counter"),
        pytest.param(TensorProto.FLOAT, "Add", (), 13, id="floating-learning-rate"),
        pytest.param(TensorProto.FLOAT, "Neg", (), 13, id="unary-negation"),
        pytest.param(TensorProto.FLOAT, "Round", (), 13, id="unary-rounding"),
        pytest.param(TensorProto.FLOAT, "Clip", (), 13, id="clipped-scalar"),
        pytest.param(TensorProto.FLOAT, "Celu", (), 13, id="celu-scalar"),
        pytest.param(TensorProto.FLOAT, "Shrink", (), 13, id="shrunk-scalar"),
        pytest.param(TensorProto.FLOAT, "PRelu", (), 13, id="prelu-scalar"),
        pytest.param(TensorProto.FLOAT, "Sum", (), 13, id="summed-scalar"),
        pytest.param(TensorProto.FLOAT, "Pow", (), 13, id="powered-scalar"),
        pytest.param(TensorProto.FLOAT, "Where", (), 13, id="selected-scalar"),
        pytest.param(TensorProto.FLOAT, "Softmax", (3,), 13, id="softmax-vector"),
        pytest.param(TensorProto.FLOAT, "LogSoftmax", (3,), 13, id="log-softmax-vector"),
        pytest.param(TensorProto.FLOAT, "Hardmax", (3,), 13, id="hardmax-vector"),
        pytest.param(TensorProto.FLOAT, "LpNormalization", (3,), 13, id="normalized-vector"),
        pytest.param(TensorProto.FLOAT, "Gelu", (), 20, id="gelu-scalar"),
        pytest.param(TensorProto.FLOAT, "Swish", (), 24, id="swish-scalar"),
        pytest.param(TensorProto.INT64, "BitwiseNot", (), 18, id="bitwise-not-scalar"),
        pytest.param(TensorProto.BOOL, "Not", (), 13, id="not-scalar"),
    ],
)
def test_onnx_scanner_non_weight_training_update_stays_clean(
    tmp_path: Path,
    data_type: int,
    op_type: str,
    shape: tuple[int, ...],
    opset_version: int,
) -> None:
    model_path = create_non_weight_training_update_model(
        tmp_path,
        data_type=data_type,
        op_type=op_type,
        shape=shape,
        opset_version=opset_version,
    )

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    assert semantics["eligible_initializer_count"] == 0
    assert semantics["coverage_gaps"] == {}


@pytest.mark.parametrize(
    "parameter_shape",
    [
        pytest.param((), id="scalar"),
        pytest.param((100,), id="vector"),
        pytest.param((1, 100), id="matrix"),
    ],
)
def test_onnx_scanner_dynamic_prelu_slope_stays_clean(
    tmp_path: Path,
    parameter_shape: tuple[int, ...],
) -> None:
    activation = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
    output = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])
    parameter = onnx.numpy_helper.from_array(np.ones(parameter_shape, dtype=np.float32), name="parameter")
    weights = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="W")
    graph = helper.make_graph(
        [
            helper.make_node("PRelu", ["X", "parameter"], ["activation"]),
            helper.make_node("MatMul", ["activation", "W"], ["Y"]),
        ],
        "dynamic_prelu_slope",
        [activation],
        [output],
        [parameter, weights],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    model_path = tmp_path / "dynamic-prelu-slope.onnx"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    expected_eligible = 2 if len(parameter_shape) >= 2 else 1
    expected_analyzed = 3 if len(parameter_shape) >= 2 else 1
    assert semantics["eligible_initializer_count"] == expected_eligible
    assert semantics["analyzed_layer_count"] == expected_analyzed
    assert semantics["coverage_gaps"] == {}


@pytest.mark.parametrize("transposed", [False, True])
def test_onnx_scanner_malicious_matrix_prelu_slope_remains_detected(
    tmp_path: Path,
    transposed: bool,
) -> None:
    slope_values = np.zeros((100, 10), dtype=np.float32)
    slope_values[50:55, 3] = 10.0
    if transposed:
        slope_values = slope_values.T
    rows, columns = slope_values.shape
    activation = helper.make_tensor_value_info("X", TensorProto.FLOAT, [rows, columns])
    output = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [rows, 3])
    slope = onnx.numpy_helper.from_array(slope_values, name="slope")
    weights = onnx.numpy_helper.from_array(np.zeros((columns, 3), dtype=np.float32), name="W")
    graph = helper.make_graph(
        [
            helper.make_node("PRelu", ["X", "slope"], ["activation"]),
            helper.make_node("MatMul", ["activation", "W"], ["Y"]),
        ],
        "malicious_matrix_prelu_slope",
        [activation],
        [output],
        [slope, weights],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    model_path = tmp_path / "malicious-matrix-prelu-slope.onnx"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    extreme_checks = [
        check
        for check in result.checks
        if check.name == "Weight Distribution Anomaly Detection" and "extremely large weight values" in check.message
    ]
    assert len(extreme_checks) == 1
    assert extreme_checks[0].details["initializer"] == "slope"
    assert extreme_checks[0].details["consumer_op"] == "PRelu"
    assert extreme_checks[0].details["consumer_input_index"] == 1
    assert extreme_checks[0].details["affected_neurons"] == [3]
    assert extreme_checks[0].details["output_axis"] == (0 if transposed else 1)
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    assert semantics["coverage_gaps"] == {}


@pytest.mark.parametrize("slope_shape", [(100, 1, 1), (1, 100, 1, 1)])
def test_onnx_scanner_prelu_singleton_axes_do_not_duplicate_findings(
    tmp_path: Path,
    slope_shape: tuple[int, ...],
) -> None:
    slope_values = np.zeros(slope_shape, dtype=np.float32)
    non_singleton_axis = slope_shape.index(100)
    outlier_slice: list[int | slice] = [0] * len(slope_shape)
    outlier_slice[non_singleton_axis] = slice(50, 55)
    slope_values[tuple(outlier_slice)] = 10.0
    activation = helper.make_tensor_value_info("X", TensorProto.FLOAT, list(slope_shape))
    output = helper.make_tensor_value_info("Y", TensorProto.FLOAT, list(slope_shape))
    slope = onnx.numpy_helper.from_array(slope_values, name="slope")
    graph = helper.make_graph(
        [helper.make_node("PRelu", ["X", "slope"], ["Y"])],
        "prelu_singleton_axes",
        [activation],
        [output],
        [slope],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    model_path = tmp_path / "prelu-singleton-axes.onnx"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    extreme_checks = [
        check
        for check in result.checks
        if check.name == "Weight Distribution Anomaly Detection" and "extremely large weight values" in check.message
    ]
    assert len(extreme_checks) == 1
    assert extreme_checks[0].details["initializer"] == "slope"
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    assert semantics["eligible_initializer_count"] == 1
    assert semantics["analyzed_layer_count"] == 2
    assert semantics["coverage_gaps"] == {}


def test_onnx_scanner_matrix_clip_bound_fails_closed(tmp_path: Path) -> None:
    scalar = helper.make_tensor_value_info("X", TensorProto.FLOAT, [])
    output = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [])
    matrix_bound = onnx.numpy_helper.from_array(np.zeros((2, 2), dtype=np.float32), name="minimum")
    graph = helper.make_graph(
        [helper.make_node("Clip", ["X", "minimum"], ["Y"])],
        "invalid_matrix_clip_bound",
        [scalar],
        [output],
        [matrix_bound],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    model_path = tmp_path / "matrix-clip-bound.onnx"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    coverage_checks = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}
    samples = result.metadata["onnx_weight_distribution_semantics"]["unresolved_lineage_samples"]
    assert {sample["reason"] for sample in samples} == {"invalid_clip_bound_shape"}


def test_onnx_scanner_transformed_non_scalar_clip_bound_fails_closed(tmp_path: Path) -> None:
    scalar = helper.make_tensor_value_info("X", TensorProto.FLOAT, [])
    output = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [])
    matrix_bound = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="minimum_matrix")
    vector_shape = onnx.numpy_helper.from_array(np.asarray([1000], dtype=np.int64), name="vector_shape")
    graph = helper.make_graph(
        [
            helper.make_node("Reshape", ["minimum_matrix", "vector_shape"], ["minimum"]),
            helper.make_node("Clip", ["X", "minimum"], ["Y"]),
        ],
        "transformed_invalid_clip_bound",
        [scalar],
        [output],
        [matrix_bound, vector_shape],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    model_path = tmp_path / "transformed-non-scalar-clip-bound.onnx"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    coverage_checks = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}
    samples = result.metadata["onnx_weight_distribution_semantics"]["unresolved_lineage_samples"]
    assert {sample["reason"] for sample in samples} == {"invalid_clip_bound_shape"}


@pytest.mark.parametrize(
    ("op_type", "opset_version"),
    [
        pytest.param("Gelu", 20, id="gelu"),
        pytest.param("Swish", 24, id="swish"),
    ],
)
def test_onnx_scanner_static_matrix_unary_output_used_as_weight_fails_closed(
    tmp_path: Path,
    op_type: str,
    opset_version: int,
) -> None:
    data = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.float32), name="data")
    weights = onnx.numpy_helper.from_array(np.zeros((10, 3), dtype=np.float32), name="W")
    output = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [100, 3])
    graph = helper.make_graph(
        [
            helper.make_node(op_type, ["data"], ["transformed"]),
            helper.make_node("MatMul", ["transformed", "W"], ["Y"]),
        ],
        f"static_{op_type.lower()}_weight_path",
        [],
        [output],
        [data, weights],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", opset_version)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    model_path = tmp_path / f"static-{op_type.lower()}-weight-path.onnx"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    coverage_checks = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}


@pytest.mark.parametrize("op_type", ["RandomNormalLike", "RandomUniformLike"])
def test_onnx_scanner_random_like_dtype_override_used_as_weight_fails_closed(
    tmp_path: Path,
    op_type: str,
) -> None:
    shape_seed = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.int64), name="shape_seed")
    activation = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
    output = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])
    graph = helper.make_graph(
        [
            helper.make_node(op_type, ["shape_seed"], ["generated_weight"], dtype=TensorProto.FLOAT),
            helper.make_node("MatMul", ["X", "generated_weight"], ["Y"]),
        ],
        f"{op_type.lower()}_weight_path",
        [activation],
        [output],
        [shape_seed],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 22)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    model_path = tmp_path / f"{op_type.lower()}-weight-path.onnx"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    coverage_checks = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}


def test_onnx_scanner_pow_exponent_dtype_override_used_as_weight_fails_closed(tmp_path: Path) -> None:
    exponent = onnx.numpy_helper.from_array(np.ones((100, 10), dtype=np.int64), name="exponent")
    base = helper.make_tensor_value_info("base", TensorProto.FLOAT, [100, 10])
    activation = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
    output = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])
    graph = helper.make_graph(
        [
            helper.make_node("Pow", ["base", "exponent"], ["generated_weight"]),
            helper.make_node("MatMul", ["X", "generated_weight"], ["Y"]),
        ],
        "pow_exponent_weight_path",
        [base, activation],
        [output],
        [exponent],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    model_path = tmp_path / "pow-exponent-weight-path.onnx"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    coverage_checks = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}


def test_onnx_scanner_cross_training_info_weight_state_fails_closed(tmp_path: Path) -> None:
    model_path = create_cross_training_info_weight_model(tmp_path)

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    coverage_checks = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
    assert len(coverage_checks) == 1
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    assert semantics["eligible_initializer_count"] == 1
    assert semantics["coverage_gaps"]["unresolved_training_graph_input"] == 1
    assert semantics["coverage_gaps"]["unresolved_training_binding"] == 1


def test_onnx_scanner_training_initialization_binding_fails_closed(tmp_path: Path) -> None:
    model_path = create_training_initialization_reset_model(tmp_path)

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    coverage_checks = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
    assert len(coverage_checks) == 1
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    assert semantics["eligible_initializer_count"] == 1
    assert any(
        sample["reason"] == "unresolved_initialization_binding" for sample in semantics["unresolved_lineage_samples"]
    )


def test_onnx_scanner_flat_weight_initialization_binding_fails_closed(tmp_path: Path) -> None:
    model_path = create_flat_training_initialization_reset_model(tmp_path)

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    coverage_checks = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
    assert len(coverage_checks) == 1
    semantics = result.metadata["onnx_weight_distribution_semantics"]
    assert semantics["eligible_initializer_count"] == 2
    assert any(
        sample["initializer"] == "reset" and sample["reason"] == "unresolved_initialization_binding"
        for sample in semantics["unresolved_lineage_samples"]
    )


def test_onnx_scanner_combined_training_initializer_collision_fails_closed(tmp_path: Path) -> None:
    model_path = create_flat_training_initialization_reset_model(tmp_path)
    model = onnx.load(str(model_path))
    colliding_algorithm = helper.make_graph(
        [],
        "colliding_training_algorithm",
        [],
        [],
        initializer=[onnx.numpy_helper.from_array(np.asarray(1.0, dtype=np.float32), name="W")],
    )
    model.training_info[0].algorithm.CopyFrom(colliding_algorithm)
    onnx.checker.check_model(model)
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    coverage_checks = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["coverage_gaps"] == {"invalid_initializer_names": 1}
    validation = result.metadata["onnx_weight_distribution_semantics"]["initializer_name_validation"]
    assert validation["duplicate_name_count"] == 1
    assert validation["samples"][0]["reason"] == "duplicate_combined_training_initializer_name"


def test_onnx_scanner_unknown_default_domain_matrix_consumer_fails_closed(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="",
        custom_op_type="OpaqueKernel",
        custom_uses_initializer=True,
        tensor_shape=(100, 10),
    )
    model = onnx.load(str(model_path))
    weights = np.zeros((100, 10), dtype=np.float32)
    weights[50:55, 3] = 10.0
    model.graph.initializer[0].CopyFrom(onnx.numpy_helper.from_array(weights, name="W"))
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    coverage_checks = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
    assert result.success is False
    assert not [check for check in result.checks if check.rule_code == "S1111" and check.status == CheckStatus.FAILED]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}
    sample = result.metadata["onnx_weight_distribution_semantics"]["unresolved_lineage_samples"][0]
    assert sample["consumer_op"] == "OpaqueKernel"
    assert sample["reason"] == "unsupported_weight_consumer"


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


def test_onnx_scanner_skips_path_schema_validation_for_external_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_onnx_model(tmp_path, external=True, external_path="weights.bin")

    def fail_if_called(_model_or_path: Any, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("external_data schema validation must not resolve through check_model")

    monkeypatch.setattr(onnx.checker, "check_model", fail_if_called)

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert ONNX_SCHEMA_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    schema_checks = [c for c in result.checks if c.name == "ONNX Schema Validation"]
    assert len(schema_checks) == 1
    assert schema_checks[0].details["external_data_present"] is True
    assert any(
        c.name == "External Data Reference Check"
        and c.status == CheckStatus.PASSED
        and c.details.get("file") == "weights.bin"
        for c in result.checks
    )


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

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert ONNX_SCHEMA_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
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

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert ONNX_SCHEMA_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
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

    def _create_hf_cache_snapshot_model(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        model_name: str = "model.onnx",
        sidecar_target: Path | None = None,
    ) -> Path:
        cache_hub = tmp_path / "hf-hub"
        monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
        cache_root = cache_hub / "models--FacebookAI--xlm-roberta-large"
        blobs_dir = cache_root / "blobs"
        snapshot_dir = cache_root / "snapshots" / ("a" * 40) / "onnx"
        blobs_dir.mkdir(parents=True)
        snapshot_dir.mkdir(parents=True)

        source_dir = tmp_path / "source"
        source_dir.mkdir()
        source_model = create_onnx_model(source_dir, external=True, external_path="model.onnx_data")
        model_blob = blobs_dir / "model-blob"
        sidecar_blob = blobs_dir / "sidecar-blob"
        model_blob.write_bytes(source_model.read_bytes())
        sidecar_blob.write_bytes((source_dir / "model.onnx_data").read_bytes())

        model_path = snapshot_dir / model_name
        sidecar_path = snapshot_dir / "model.onnx_data"
        model_path.symlink_to(os.path.relpath(model_blob, snapshot_dir))
        sidecar_path.symlink_to(os.path.relpath(sidecar_target or sidecar_blob, snapshot_dir))
        return model_path

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

    def test_huggingface_cache_snapshot_sidecar_symlink_to_blob_not_flagged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        model_path = self._create_hf_cache_snapshot_model(tmp_path, monkeypatch)

        result = OnnxScanner().scan(str(model_path))

        missing_checks = [
            c for c in result.checks if c.name == "External Data Reference Check" and c.status == CheckStatus.FAILED
        ]
        resolved_checks = [
            c
            for c in result.checks
            if c.name == "External Data Reference Check"
            and c.status == CheckStatus.PASSED
            and c.details.get("file") == "model.onnx_data"
        ]
        assert_only_onnx_external_schema_validation_skipped(result)
        assert missing_checks == []
        assert len(resolved_checks) == 1
        assert not [c for c in result.checks if c.details.get("cve_id") == "CVE-2026-34447"]

    def test_huggingface_cache_snapshot_content_routed_onnx_bin_uses_alias_sidecar_context(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        model_path = self._create_hf_cache_snapshot_model(tmp_path, monkeypatch, model_name="model.bin")
        sidecar_path = model_path.parent / "model.onnx_data"

        result = scan_model_directory_or_file(str(model_path.parent), cache_scan_results=False)

        resolved_checks = [
            c
            for c in result.checks
            if c.name == "External Data Reference Check"
            and c.status == CheckStatus.PASSED
            and c.details.get("file") == "model.onnx_data"
        ]
        assert len(resolved_checks) == 1
        assert_only_onnx_external_schema_validation_skipped(result)
        assert result.bytes_scanned == model_path.stat().st_size + sidecar_path.stat().st_size
        assert result.content_hash == compute_aggregate_hash(
            [
                compute_sha256_hash(model_path),
                compute_sha256_hash(sidecar_path),
            ]
        )
        assert not any(check.name == "Format Validation" for check in result.checks)
        assert not [c for c in result.checks if c.details.get("cve_id") == "CVE-2026-34447"]

    def test_huggingface_cache_snapshot_regular_model_with_sidecar_symlink_to_blob_still_flagged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        cache_hub = tmp_path / "hf-hub"
        monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
        cache_root = cache_hub / "models--FacebookAI--xlm-roberta-large"
        blobs_dir = cache_root / "blobs"
        snapshot_dir = cache_root / "snapshots" / ("a" * 40) / "onnx"
        blobs_dir.mkdir(parents=True)
        snapshot_dir.mkdir(parents=True)

        source_dir = tmp_path / "source-regular-model"
        source_dir.mkdir()
        source_model = create_onnx_model(source_dir, external=True, external_path="model.onnx_data")
        sidecar_blob = blobs_dir / "sidecar-blob"
        sidecar_blob.write_bytes((source_dir / "model.onnx_data").read_bytes())
        model_path = snapshot_dir / "model.onnx"
        model_path.write_bytes(source_model.read_bytes())
        (snapshot_dir / "model.onnx_data").symlink_to(os.path.relpath(sidecar_blob, snapshot_dir))

        result = OnnxScanner().scan(str(model_path))

        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2026-34447"]
        assert result.success is False
        assert len(cve_checks) == 1
        assert cve_checks[0].details["resolved_path"] == str(sidecar_blob.resolve())

    def test_huggingface_cache_snapshot_sidecar_symlink_outside_blob_still_flagged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        outside_dir = tmp_path.parent / f"{tmp_path.name}_outside_hf"
        outside_dir.mkdir(parents=True, exist_ok=True)
        outside_weights = outside_dir / "weights.bin"
        outside_weights.write_bytes(struct.pack("f", 1.0))
        model_path = self._create_hf_cache_snapshot_model(
            tmp_path,
            monkeypatch,
            sidecar_target=outside_weights,
        )

        result = OnnxScanner().scan(str(model_path))

        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2026-34447"]
        assert result.success is False
        assert len(cve_checks) == 1
        assert cve_checks[0].details["resolved_path"] == str(outside_weights.resolve())
        assert not [
            c for c in result.checks if c.name == "External Data Reference Check" and c.status == CheckStatus.FAILED
        ]

    def test_huggingface_cache_snapshot_directory_symlink_to_blob_still_flagged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        cache_hub = tmp_path / "hf-hub"
        monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
        cache_root = cache_hub / "models--FacebookAI--xlm-roberta-large"
        blobs_dir = cache_root / "blobs"
        snapshot_dir = cache_root / "snapshots" / ("a" * 40) / "onnx"
        blobs_dir.mkdir(parents=True)
        snapshot_dir.mkdir(parents=True)

        source_dir = tmp_path / "source-dir-symlink"
        source_dir.mkdir()
        source_model = create_onnx_model(source_dir, external=True, external_path="nested/model.onnx_data")
        model_blob = blobs_dir / "model-dir-symlink-blob"
        sidecar_blob = blobs_dir / "model.onnx_data"
        model_blob.write_bytes(source_model.read_bytes())
        sidecar_blob.write_bytes((source_dir / "nested" / "model.onnx_data").read_bytes())

        model_path = snapshot_dir / "model.onnx"
        model_path.symlink_to(os.path.relpath(model_blob, snapshot_dir))
        (snapshot_dir / "nested").symlink_to(os.path.relpath(blobs_dir, snapshot_dir))

        result = OnnxScanner().scan(str(model_path))

        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2026-34447"]
        assert result.success is False
        assert len(cve_checks) == 1
        assert cve_checks[0].details["file"] == "nested/model.onnx_data"
        assert cve_checks[0].details["resolved_path"] == str(sidecar_blob.resolve())

    def test_huggingface_cache_snapshot_malicious_external_data_traversal_still_flagged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        cache_hub = tmp_path / "hf-hub"
        monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
        cache_root = cache_hub / "models--FacebookAI--xlm-roberta-large"
        blobs_dir = cache_root / "blobs"
        snapshot_dir = cache_root / "snapshots" / ("a" * 40) / "onnx"
        blobs_dir.mkdir(parents=True)
        snapshot_dir.mkdir(parents=True)

        source_dir = tmp_path / "source-malicious"
        source_dir.mkdir()
        source_model = create_onnx_model(
            source_dir,
            external=True,
            external_path="../secret.bin",
            missing_external=True,
        )
        model_blob = blobs_dir / "model-traversal-blob"
        model_blob.write_bytes(source_model.read_bytes())
        model_path = snapshot_dir / "model.onnx"
        model_path.symlink_to(os.path.relpath(model_blob, snapshot_dir))

        result = OnnxScanner().scan(str(model_path))

        traversal_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2022-25882"]
        assert result.success is False
        assert len(traversal_checks) == 1
        assert traversal_checks[0].details["file"] == "../secret.bin"

    def test_huggingface_cache_non_snapshot_sidecar_symlink_to_blob_still_flagged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        cache_hub = tmp_path / "hf-hub"
        monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
        cache_root = cache_hub / "models--FacebookAI--xlm-roberta-large"
        blobs_dir = cache_root / "blobs"
        work_dir = cache_root / "scratch" / "onnx"
        blobs_dir.mkdir(parents=True)
        work_dir.mkdir(parents=True)

        source_model = create_onnx_model(work_dir, external=True, external_path="model.onnx_data")
        sidecar_blob = blobs_dir / "sidecar-blob"
        sidecar_blob.write_bytes((work_dir / "model.onnx_data").read_bytes())
        (work_dir / "model.onnx_data").unlink()
        (work_dir / "model.onnx_data").symlink_to(os.path.relpath(sidecar_blob, work_dir))

        result = OnnxScanner().scan(str(source_model))

        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2026-34447"]
        assert result.success is False
        assert len(cve_checks) == 1
        assert cve_checks[0].details["resolved_path"] == str(sidecar_blob.resolve())

    def test_huggingface_cache_nested_fake_snapshot_sidecar_symlink_to_blob_still_flagged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        cache_hub = tmp_path / "hf-hub"
        monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
        cache_root = cache_hub / "models--FacebookAI--xlm-roberta-large"
        blobs_dir = cache_root / "blobs"
        fake_snapshot_dir = cache_root / "scratch" / cache_root.name / "snapshots" / ("a" * 40) / "onnx"
        blobs_dir.mkdir(parents=True)
        fake_snapshot_dir.mkdir(parents=True)

        source_model = create_onnx_model(fake_snapshot_dir, external=True, external_path="model.onnx_data")
        sidecar_blob = blobs_dir / "sidecar-blob"
        sidecar_blob.write_bytes((fake_snapshot_dir / "model.onnx_data").read_bytes())
        (fake_snapshot_dir / "model.onnx_data").unlink()
        (fake_snapshot_dir / "model.onnx_data").symlink_to(os.path.relpath(sidecar_blob, fake_snapshot_dir))

        result = OnnxScanner().scan(str(source_model))

        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2026-34447"]
        assert result.success is False
        assert len(cve_checks) == 1
        assert cve_checks[0].details["symlink_path"] == str(fake_snapshot_dir / "model.onnx_data")
        assert cve_checks[0].details["resolved_path"] == str(sidecar_blob.resolve())

    def test_huggingface_cache_non_snapshot_sidecar_hardlink_to_blob_is_not_symlink_traversal(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cache_hub = tmp_path / "hf-hub"
        monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
        cache_root = cache_hub / "models--FacebookAI--xlm-roberta-large"
        blobs_dir = cache_root / "blobs"
        work_dir = cache_root / "scratch-hardlink" / "onnx"
        blobs_dir.mkdir(parents=True)
        work_dir.mkdir(parents=True)

        source_model = create_onnx_model(work_dir, external=True, external_path="model.onnx_data")
        sidecar_blob = blobs_dir / "sidecar-blob"
        sidecar_blob.write_bytes((work_dir / "model.onnx_data").read_bytes())
        (work_dir / "model.onnx_data").unlink()
        try:
            os.link(sidecar_blob, work_dir / "model.onnx_data")
        except OSError as exc:
            pytest.skip(f"hardlink creation unavailable: {exc}")

        result = OnnxScanner().scan(str(source_model))

        resolved_checks = [
            c
            for c in result.checks
            if c.name == "External Data Reference Check"
            and c.status == CheckStatus.PASSED
            and c.details.get("file") == "model.onnx_data"
        ]
        assert_only_onnx_external_schema_validation_skipped(result)
        assert len(resolved_checks) == 1
        assert not [c for c in result.checks if c.details.get("cve_id") == "CVE-2026-34447"]

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

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert ONNX_SCHEMA_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
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

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert ONNX_SCHEMA_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
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

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert ONNX_SCHEMA_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
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

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert ONNX_SCHEMA_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
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

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert ONNX_SCHEMA_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
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

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert ONNX_SCHEMA_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
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

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert ONNX_SCHEMA_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
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

    @pytest.mark.parametrize(
        "data_type",
        [TensorProto.INT2, TensorProto.UINT2, TensorProto.INT4, TensorProto.UINT4],
    )
    def test_external_packed_low_bit_size_validation(self, tmp_path: Path, data_type: int) -> None:
        bits_per_element = 2 if data_type in {TensorProto.INT2, TensorProto.UINT2} else 4
        num_elements = 1001
        storage_size = (num_elements * bits_per_element + 7) // 8
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights.bin",
            external_file_bytes=bytes(storage_size),
            tensor_shape=(num_elements,),
        )
        self._set_initializer_data_type(model_path, data_type)

        result = OnnxScanner().scan(str(model_path))

        size_checks = [check for check in result.checks if check.name == "External Data Size Validation"]
        assert len(size_checks) == 1
        assert size_checks[0].status == CheckStatus.PASSED
        assert size_checks[0].details["size"] == storage_size

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

    def test_training_weight_coverage_gap_is_uncached_inconclusive(self, tmp_path: Path) -> None:
        model_path = create_training_info_weight_model(tmp_path)

        direct = OnnxScanner().scan(str(model_path))

        coverage_checks = self._coverage_checks(direct)
        assert len(coverage_checks) == 1
        assert (
            coverage_checks[0].message == "Weight distribution analysis skipped one or more eligible ONNX initializers"
        )
        assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert ONNX_WEIGHT_DISTRIBUTION_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
        self._assert_uncached_inconclusive_exit2(model_path, tmp_path / "cache")

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

    def test_missing_weight_distribution_dependency_ignores_unused_2d_initializers(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        model_path = create_onnx_model(tmp_path, tensor_shape=(2, 2))
        monkeypatch.setitem(sys.modules, "scipy", None)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert result.metadata["onnx_weight_distribution_semantics"]["exclusion_counts"] == {
            "unused_initializer": 1,
        }
        assert self._coverage_checks(result) == []

    def test_missing_weight_distribution_dependency_is_inconclusive(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        model_path = create_onnx_model(tmp_path, tensor_shape=(2, 2), initializer_consumer="MatMul")
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

    def test_standalone_missing_scipy_is_uncached_inconclusive(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        model_path = create_onnx_model(tmp_path, tensor_shape=(2, 2), initializer_consumer="MatMul")
        monkeypatch.setitem(sys.modules, "scipy", None)

        direct = WeightDistributionScanner().scan(str(model_path))

        assert direct.success is False
        assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "weight_distribution_analysis_incomplete" in direct.metadata["scan_outcome_reasons"]
        reset_cache_manager()
        cache_dir = tmp_path / "standalone-cache"
        try:
            first = scan_model_directory_or_file(
                str(model_path),
                recursive=False,
                scanners=["weight_distribution"],
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            second = scan_model_directory_or_file(
                str(model_path),
                recursive=False,
                scanners=["weight_distribution"],
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

            metadata = second.file_metadata[str(model_path)]
            assert first.success is False
            assert second.success is False
            assert determine_exit_code(first) == 2
            assert determine_exit_code(second) == 2
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_external_weight_distribution_tensors_are_inconclusive(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights.bin",
            external_file_bytes=struct.pack("ffff", 1.0, 2.0, 3.0, 4.0),
            tensor_shape=(2, 2),
            initializer_consumer="MatMul",
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
        model_path = create_onnx_model(tmp_path, tensor_shape=(2, 2), initializer_consumer="MatMul")

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

    def test_standalone_invalid_initializer_size_is_uncached_inconclusive(self, tmp_path: Path) -> None:
        invalid_weight = onnx.TensorProto()
        invalid_weight.name = "W"
        invalid_weight.data_type = TensorProto.FLOAT
        invalid_weight.dims.extend([-1, 4])
        graph = helper.make_graph(
            [helper.make_node("MatMul", ["X", "W"], ["Y"])],
            "negative_initializer_dimension",
            [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 1])],
            [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 4])],
            initializer=[invalid_weight],
        )
        model_path = tmp_path / "negative-initializer-dimension.onnx"
        onnx.save(helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)]), str(model_path))

        direct = WeightDistributionScanner({"max_array_size": 1}).scan(str(model_path))

        assert direct.success is False
        assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "weight_distribution_analysis_incomplete" in direct.metadata["scan_outcome_reasons"]
        analysis_check = next(check for check in direct.checks if check.name == "Weight Distribution Analysis")
        assert analysis_check.details["oversized_initializers_skipped"] == 1

        cache_dir = tmp_path / "standalone-cache"
        reset_cache_manager()
        try:
            results = [
                scan_model_directory_or_file(
                    str(model_path),
                    recursive=False,
                    scanners=["weight_distribution"],
                    max_array_size=1,
                    cache_enabled=True,
                    cache_dir=str(cache_dir),
                    min_cache_file_size=0,
                )
                for _ in range(2)
            ]
            for result in results:
                assert result.success is False
                assert determine_exit_code(result) == 2
                assert result.file_metadata[str(model_path)]["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_inline_storage_is_bounded_before_materialization(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        tensor = onnx.TensorProto()
        tensor.name = "W"
        tensor.data_type = TensorProto.FLOAT
        tensor.dims.extend([1, 1])
        tensor.float_data.extend([1.0] * 100)
        X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 1])
        Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 1])
        node = helper.make_node("MatMul", ["X", "W"], ["Y"])
        model = helper.make_model(helper.make_graph([node], "oversized_inline", [X], [Y], initializer=[tensor]))
        model_path = tmp_path / "oversized-inline.onnx"
        onnx.save(model, str(model_path))
        original_to_array = onnx.numpy_helper.to_array

        def guarded_to_array(initializer: Any, *args: Any, **kwargs: Any) -> Any:
            if initializer.name == "W":
                raise AssertionError("oversized inline tensor must not be materialized")
            return original_to_array(initializer, *args, **kwargs)

        monkeypatch.setattr(onnx.numpy_helper, "to_array", guarded_to_array)
        result = OnnxScanner({"max_array_size": 8}).scan(str(model_path))

        coverage = self._coverage_checks(result)
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["oversized_initializers_skipped"] == 1
        assert coverage[0].details["extraction_failures"] == 0

    @pytest.mark.parametrize(
        "invalid_limit",
        ["unbounded", pytest.param(10**1000, id="oversized-integer")],
    )
    def test_invalid_array_limit_uses_default_before_materialization(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        invalid_limit: Any,
    ) -> None:
        tensor = onnx.TensorProto()
        tensor.name = "W"
        tensor.data_type = TensorProto.FLOAT
        tensor.dims.extend([32768, 1024])
        tensor.raw_data = b"\0\0\0\0"
        X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 32768])
        Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 1024])
        node = helper.make_node("MatMul", ["X", "W"], ["Y"])
        model = helper.make_model(
            helper.make_graph([node], "invalid_array_limit", [X], [Y], initializer=[tensor]),
            opset_imports=[helper.make_opsetid("", 13)],
        )
        model.ir_version = 8
        model_path = tmp_path / "invalid-array-limit.onnx"
        onnx.save(model, str(model_path))
        original_to_array = onnx.numpy_helper.to_array

        def guarded_to_array(initializer: Any, *args: Any, **kwargs: Any) -> Any:
            if initializer.name == "W":
                raise AssertionError("default-bounded tensor must not be materialized")
            return original_to_array(initializer, *args, **kwargs)

        monkeypatch.setattr(onnx.numpy_helper, "to_array", guarded_to_array)
        result = OnnxScanner({"max_array_size": invalid_limit}).scan(str(model_path))

        coverage = self._coverage_checks(result)
        assert len(coverage) == 1
        assert coverage[0].details["max_array_size"] == 100 * 1024 * 1024
        assert coverage[0].details["oversized_initializers_skipped"] == 1
        assert coverage[0].details["extraction_failures"] == 0

    def test_zero_array_limit_remains_explicitly_unlimited(self) -> None:
        assert _configured_onnx_weight_array_limit(0) is None


class TestWeightDistributionSemantics:
    """Regression tests for ONNX initializer semantics and output axes."""

    @staticmethod
    def _extreme_checks(result: Any) -> list[Any]:
        return [
            check
            for check in result.checks
            if check.name == "Weight Distribution Anomaly Detection"
            and "extremely large weight values" in check.message
        ]

    def test_gemm_transposed_weight_uses_the_real_output_axis(self, tmp_path: Path) -> None:
        weights = np.linspace(-0.1, 0.1, 384, dtype=np.float32).reshape(1, 384)
        model_path = create_onnx_weight_model(tmp_path, weights, op_type="Gemm", trans_b=True)

        result = OnnxScanner().scan(str(model_path))

        assert self._extreme_checks(result) == []
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_layer_count"] == 1
        assert semantics["eligible"][0]["consumer_op"] == "Gemm"
        assert semantics["eligible"][0]["output_axis"] == 0
        assert semantics["eligible"][0]["stored_shape"] == [1, 384]
        assert semantics["eligible"][0]["analysis_shape"] == [384, 1]

    @pytest.mark.parametrize(
        ("op_type", "weights", "expected_reason"),
        [
            ("Mul", np.zeros((288, 1), dtype=np.float32), "bookkeeping_constant"),
            ("Add", np.zeros((288, 1), dtype=np.float32), "bookkeeping_constant"),
        ],
    )
    def test_non_neuron_initializers_are_semantically_excluded(
        self,
        tmp_path: Path,
        op_type: str,
        weights: np.ndarray,
        expected_reason: str,
    ) -> None:
        model_path = create_onnx_weight_model(tmp_path, weights, op_type=op_type)

        result = OnnxScanner().scan(str(model_path))

        assert self._extreme_checks(result) == []
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 0
        assert semantics["analyzed_layer_count"] == 0
        assert semantics["exclusion_counts"][expected_reason] == 1
        assert semantics["exclusion_samples"][0]["initializer"] == "W"

    def test_gather_embedding_uses_non_indexed_feature_axes(self, tmp_path: Path) -> None:
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50:55, 3] = 10.0
        model_path = create_onnx_weight_model(tmp_path, weights, op_type="Gather")

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        assert checks[0].details["output_axis"] == 1
        assert checks[0].details["analysis_shape"] == [100, 10]
        assert checks[0].details["affected_neurons"] == [3]

    def test_gather_rare_entry_poison_remains_detected(self, tmp_path: Path) -> None:
        weights = np.zeros((100, 100), dtype=np.float32)
        weights[3, 30:35] = 10.0
        model_path = create_onnx_weight_model(tmp_path, weights, op_type="Gather")

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        assert checks[0].details["output_axis"] == 0
        assert checks[0].details["affected_neurons"] == [3]

    def test_gather_subthreshold_entry_near_match_stays_clean(self, tmp_path: Path) -> None:
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[3, 3:7] = 10.0
        model_path = create_onnx_weight_model(tmp_path, weights, op_type="Gather")

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert self._extreme_checks(result) == []
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert {tuple(context["output_axes"]) for context in semantics["eligible"]} == {(0,), (1,)}

    def test_clean_gather_embedding_table_stays_clean(self, tmp_path: Path) -> None:
        weights = np.random.default_rng(20260610).normal(0.0, 0.02, size=(100, 100)).astype(np.float32)
        model_path = create_onnx_weight_model(tmp_path, weights, op_type="Gather")

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert self._extreme_checks(result) == []
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_layer_count"] == 2

    @pytest.mark.parametrize(("op_type", "gate_multiplier"), [("RNN", 1), ("GRU", 3), ("LSTM", 4)])
    @pytest.mark.parametrize("target_input_index", [1, 2])
    def test_recurrent_weight_vectors_are_analyzed(
        self,
        tmp_path: Path,
        op_type: str,
        gate_multiplier: int,
        target_input_index: int,
    ) -> None:
        model_path = create_recurrent_weight_model(
            tmp_path,
            op_type=op_type,
            target_input_index=target_input_index,
            distributed_near_match=False,
        )

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        details = checks[0].details
        assert details["initializer"] == ("W" if target_input_index == 1 else "R")
        assert details["consumer_op"] == op_type
        assert details["consumer_input_index"] == target_input_index
        assert details["output_axes"] == [0, 1]
        assert details["analysis_shape"] == [100, 2 * gate_multiplier * 100]
        assert details["affected_neurons"] == [gate_multiplier * 100 + 3]
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 2
        assert semantics["analyzed_layer_count"] == 2

    @pytest.mark.parametrize("op_type", ["RNN", "GRU", "LSTM"])
    @pytest.mark.parametrize("target_input_index", [1, 2])
    def test_recurrent_extremes_distributed_across_outputs_stay_clean(
        self,
        tmp_path: Path,
        op_type: str,
        target_input_index: int,
    ) -> None:
        model_path = create_recurrent_weight_model(
            tmp_path,
            op_type=op_type,
            target_input_index=target_input_index,
            distributed_near_match=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert self._extreme_checks(result) == []
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 2
        assert semantics["analyzed_layer_count"] == 2

    @pytest.mark.parametrize(("op_type", "trans_b"), [("MatMul", False), ("Gemm", False), ("Gemm", True)])
    def test_malicious_repeated_extreme_weights_remain_detected(
        self,
        tmp_path: Path,
        op_type: str,
        trans_b: bool,
    ) -> None:
        analysis_weights = np.zeros((100, 10), dtype=np.float32)
        analysis_weights[50:55, 3] = 10.0
        stored_weights = analysis_weights.T if trans_b else analysis_weights
        model_path = create_onnx_weight_model(
            tmp_path,
            stored_weights,
            op_type=op_type,
            trans_b=trans_b,
        )

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        details = checks[0].details
        assert details["initializer"] == "W"
        assert details["consumer_op"] == op_type
        assert details["consumer_input_index"] == 1
        assert details["output_axis"] == (0 if trans_b else 1)
        assert details["analysis_shape"] == [100, 10]
        assert details["affected_neurons"] == [3]
        assert details["num_extreme_weights"] == 5
        assert details["max_extreme_weights_per_output"] == 5
        assert details["max_to_threshold_ratio"] > 1.0

    @pytest.mark.parametrize("malicious", [False, True])
    def test_stale_external_metadata_does_not_hide_inline_weights(
        self,
        tmp_path: Path,
        malicious: bool,
    ) -> None:
        weights = np.random.default_rng(20260610).normal(0.0, 0.02, size=(100, 10)).astype(np.float32)
        if malicious:
            weights.fill(0.0)
            weights[50:55, 3] = 10.0
        model_path = create_onnx_weight_model(tmp_path, weights, op_type="MatMul")
        model = onnx.load(str(model_path), load_external_data=False)
        initializer = model.graph.initializer[0]
        initializer.external_data.append(StringStringEntryProto(key="location", value="stale.bin"))
        initializer.data_location = TensorProto.DEFAULT
        onnx.save(model, str(model_path))
        (tmp_path / "stale.bin").write_bytes(weights.tobytes())

        result = OnnxScanner().scan(str(model_path))

        if not malicious:
            assert result.success is True
        assert len(self._extreme_checks(result)) == int(malicious)
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_layer_count"] == 1

    @pytest.mark.parametrize("op_type", ["Gemm", "MatMul"])
    def test_left_input_equivalent_graph_is_analyzed(self, tmp_path: Path, op_type: str) -> None:
        analysis_weights = np.zeros((100, 10), dtype=np.float32)
        analysis_weights[50:55, 3] = 10.0
        model_path = create_left_equivalent_linear_model(tmp_path, analysis_weights, op_type=op_type)

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        details = checks[0].details
        assert details["consumer_op"] == op_type
        assert details["consumer_input_index"] == 0
        assert details["output_axis"] == 0
        assert details["stored_shape"] == [10, 100]
        assert details["analysis_shape"] == [100, 10]
        assert details["affected_neurons"] == [3]
        assert details["analysis_storage_shares_memory"] is True

    def test_small_binary_head_uses_robust_fallback(self, tmp_path: Path) -> None:
        weights = np.zeros((50, 2), dtype=np.float32)
        weights[:5, 0] = 1_000_000.0
        model_path = create_onnx_weight_model(tmp_path, weights, op_type="MatMul")

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        assert checks[0].details["affected_neurons"] == [0]
        assert checks[0].details["max_to_threshold_ratio"] < 2.0

    def test_nonqualifying_decoy_does_not_suppress_malicious_output(self, tmp_path: Path) -> None:
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50:55, 3] = 10.0
        weights[0, 4] = 3.0
        model_path = create_onnx_weight_model(tmp_path, weights, op_type="MatMul")

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        assert checks[0].details["affected_neurons"] == [3]
        assert checks[0].details["num_extreme_weights"] == 5

    def test_grouped_conv_transpose_uses_all_conceptual_outputs_without_clean_fp(self, tmp_path: Path) -> None:
        weights = np.random.default_rng(42).normal(size=(4, 3, 3, 3)).astype(np.float32)
        model_path = create_onnx_conv_weight_model(tmp_path, weights, transpose=True, group=2)

        result = OnnxScanner().scan(str(model_path))

        assert [check for check in result.checks if check.name == "Weight Distribution Anomaly Detection"] == []
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["analyzed_layer_count"] == 1
        context = semantics["eligible"][0]
        assert context["stored_shape"] == [4, 3, 3, 3]
        assert context["analysis_shape"] == [18, 6]
        assert context["conceptual_output_axes"] == [0, 2]
        assert context["group"] == 2
        assert context["analysis_storage_shares_memory"] is True
        assert context["analysis_materialization"] == "zero_copy_view_chunked_reduction"

    def test_grouped_conv_transpose_retains_malicious_output_detection(self, tmp_path: Path) -> None:
        weights = np.zeros((4, 3, 3, 3), dtype=np.float32)
        weights[2:4, 1, 0:3, 0] = 10.0
        model_path = create_onnx_conv_weight_model(tmp_path, weights, transpose=True, group=2)

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        details = checks[0].details
        assert details["analysis_shape"] == [18, 6]
        assert details["affected_neurons"] == [4]
        assert details["num_extreme_weights"] == 6
        assert details["group"] == 2
        assert details["analysis_storage_shares_memory"] is True

    def test_grouped_conv_transpose_analysis_only_uses_zero_copy_moveaxis(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        weights = np.random.default_rng(7).normal(size=(4, 3, 3, 3)).astype(np.float32)
        model_path = create_onnx_conv_weight_model(tmp_path, weights, transpose=True, group=2)

        original_moveaxis = np.moveaxis
        moveaxis_calls = 0

        def checked_moveaxis(*args: Any, **kwargs: Any) -> Any:
            nonlocal moveaxis_calls
            moveaxis_calls += 1
            moved = original_moveaxis(*args, **kwargs)
            assert np.shares_memory(args[0], moved)
            return moved

        monkeypatch.setattr(np, "moveaxis", checked_moveaxis)
        result = OnnxScanner().scan(str(model_path))

        assert moveaxis_calls == 1
        assert (
            result.metadata["onnx_weight_distribution_semantics"]["eligible"][0]["analysis_storage_shares_memory"]
            is True
        )
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)

    @pytest.mark.parametrize("control_flow_op", ["If", "Loop", "Scan"])
    def test_control_flow_subgraph_captures_outer_weight_initializer(
        self,
        tmp_path: Path,
        control_flow_op: str,
    ) -> None:
        weights = np.zeros((100, 100), dtype=np.float32)
        weights[50:55, 3] = 10.0
        model_path = create_control_flow_captured_weight_model(
            tmp_path,
            weights,
            control_flow_op=control_flow_op,
        )

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        details = checks[0].details
        assert details["initializer"] == "W"
        assert details["consumer_op"] == "MatMul"
        assert details["consumer_input_index"] == 1
        assert details["analysis_shape"] == [100, 100]
        assert details["affected_neurons"] == [3]
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_layer_count"] == 1

    def test_subgraph_local_initializer_shadows_outer_weight(self, tmp_path: Path) -> None:
        outer_weights = np.zeros((100, 100), dtype=np.float32)
        outer_weights[50:55, 3] = 10.0
        model_path = create_control_flow_shadowed_weight_model(tmp_path, outer_weights)

        result = OnnxScanner().scan(str(model_path))

        assert self._extreme_checks(result) == []
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 2
        assert semantics["analyzed_layer_count"] == 2
        assert {context["initializer_graph_index"] for context in semantics["eligible"]} == {1, 2}
        assert semantics["exclusion_counts"]["unused_initializer"] == 1

    def test_subgraph_local_malicious_weights_are_analyzed(self, tmp_path: Path) -> None:
        outer_weights = np.zeros((100, 100), dtype=np.float32)
        local_weights = np.zeros_like(outer_weights)
        local_weights[50:55, 3] = 10.0
        model_path = create_control_flow_shadowed_weight_model(
            tmp_path,
            outer_weights,
            local_weights=local_weights,
        )

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 2
        assert {check.details["initializer_graph_index"] for check in checks} == {1, 2}
        assert all(check.details["affected_neurons"] == [3] for check in checks)

    @pytest.mark.parametrize(
        "model_factory",
        [create_control_flow_returned_weight_model, create_loop_carried_weight_model],
    )
    def test_weight_lineage_crosses_control_flow_boundaries(
        self,
        tmp_path: Path,
        model_factory: Any,
    ) -> None:
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50:55, 3] = 10.0
        model_path = model_factory(tmp_path, weights)

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        assert checks[0].details["affected_neurons"] == [3]
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)

    @pytest.mark.parametrize("rank_two_bias", [False, True])
    @pytest.mark.parametrize("malicious", [False, True])
    def test_dynamic_activation_paths_do_not_propagate_bookkeeping_lineage(
        self,
        tmp_path: Path,
        malicious: bool,
        rank_two_bias: bool,
    ) -> None:
        model_path = create_activation_bookkeeping_model(
            tmp_path,
            malicious=malicious,
            rank_two_bias=rank_two_bias,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert len(self._extreme_checks(result)) == int(malicious)
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["exclusion_counts"]["bookkeeping_constant"] == 1

    @pytest.mark.parametrize("malicious", [False, True])
    def test_standard_einsum_weights_are_oriented_and_analyzed(self, tmp_path: Path, malicious: bool) -> None:
        weights = np.zeros((100, 10), dtype=np.float32)
        if malicious:
            weights[50:55, 3] = 10.0
        model_path = create_einsum_weight_model(tmp_path, weights)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        checks = self._extreme_checks(result)
        assert len(checks) == int(malicious)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible"][0]["consumer_op"] == "Einsum"
        assert semantics["eligible"][0]["output_axes"] == [1]

    @pytest.mark.parametrize("malicious", [False, True])
    def test_qdq_weight_path_is_analyzed_under_bounded_dequantization(
        self,
        tmp_path: Path,
        malicious: bool,
    ) -> None:
        model_path = create_qdq_weight_model(tmp_path, malicious=malicious)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        checks = self._extreme_checks(result)
        assert len(checks) == int(malicious)
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 1
        assert semantics["analyzed_layer_count"] == 1
        context = semantics["eligible"][0]
        assert context["quantized_weight"] is True
        assert context["quantization_kind"] == "DequantizeLinear"
        assert context["analysis_materialization"] == "bounded_quantized_dequantize_copy"
        assert context["analysis_storage_shares_memory"] is False
        if malicious:
            assert checks[0].details["affected_neurons"] == [3]
            assert checks[0].details["lineage"] == ["DequantizeLinear"]

    @pytest.mark.parametrize("malicious", [False, True])
    def test_scalar_qdq_flat_weight_is_analyzed_before_reshape(self, tmp_path: Path, malicious: bool) -> None:
        model_path = create_qdq_weight_model(
            tmp_path,
            malicious=malicious,
            reshape_after_dequantization=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        checks = self._extreme_checks(result)
        assert len(checks) == int(malicious)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 1
        assert semantics["eligible"][0]["lineage"] == ["DequantizeLinear", "Reshape"]
        assert semantics["eligible"][0]["quantization_axis"] is None

    @pytest.mark.parametrize("weight_on_left", [False, True])
    @pytest.mark.parametrize("malicious", [False, True])
    def test_matmul_integer_weight_path_uses_centered_integer_weights(
        self,
        tmp_path: Path,
        malicious: bool,
        weight_on_left: bool,
    ) -> None:
        model_path = create_matmul_integer_weight_model(
            tmp_path,
            malicious=malicious,
            bind_scale=False,
            weight_on_left=weight_on_left,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        checks = self._extreme_checks(result)
        assert len(checks) == int(malicious)
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 1
        context = semantics["eligible"][0]
        assert context["consumer_op"] == "MatMulInteger"
        assert context["quantization_kind"] == "MatMulInteger"
        assert context["quantization_scale"] is None
        assert context["quantization_zero_point"] == "W_zero_point"
        assert context["output_axis"] == int(not weight_on_left)
        assert context["analysis_materialization"] == "bounded_quantized_dequantize_copy"
        if malicious:
            assert checks[0].details["affected_neurons"] == [3]

    def test_batched_matmul_integer_per_column_zero_point_is_analyzed(self, tmp_path: Path) -> None:
        model_path = create_batched_matmul_integer_weight_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 1

    @pytest.mark.parametrize(
        ("op_type", "per_channel", "full_rank_scale"),
        [
            ("ConvInteger", False, False),
            ("ConvInteger", True, False),
            ("ConvInteger", True, True),
            ("QLinearConv", False, False),
            ("QLinearConv", True, False),
        ],
    )
    @pytest.mark.parametrize("malicious", [False, True])
    def test_quantized_conv_weight_path_is_analyzed(
        self,
        tmp_path: Path,
        op_type: str,
        per_channel: bool,
        full_rank_scale: bool,
        malicious: bool,
    ) -> None:
        model_path = create_quantized_conv_weight_model(
            tmp_path,
            op_type=op_type,
            malicious=malicious,
            per_channel=per_channel,
            full_rank_scale=full_rank_scale,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        checks = self._extreme_checks(result)
        assert len(checks) == int(malicious)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 1
        context = semantics["eligible"][0]
        assert context["consumer_op"] == op_type
        assert context["quantization_kind"] == op_type
        if op_type == "ConvInteger" and per_channel:
            assert context["analysis_shape"] == [36, 10]
            assert context["output_axes"] == [0]
            assert context["quantization_scale"] == "W_scale"
        if malicious:
            assert checks[0].details["affected_neurons"] == [3]

    @pytest.mark.parametrize("op_type", ["QLinearMatMul", "QLinearConv"])
    @pytest.mark.parametrize("malicious", [False, True])
    def test_quantize_linear_weight_lineage_fails_closed(
        self,
        tmp_path: Path,
        op_type: str,
        malicious: bool,
    ) -> None:
        model_path = create_quantize_linear_qlinear_weight_model(
            tmp_path,
            op_type=op_type,
            malicious=malicious,
        )

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 0
        assert semantics["unresolved_lineage_samples"][0]["reason"] == "quantize_linear_lineage_unsupported"

    @pytest.mark.parametrize("op_type", ["QLinearMatMul", "QLinearConv"])
    @pytest.mark.parametrize("malicious", [False, True])
    def test_dynamic_quantize_linear_weight_lineage_fails_closed(
        self,
        tmp_path: Path,
        op_type: str,
        malicious: bool,
    ) -> None:
        model_path = create_quantize_linear_qlinear_weight_model(
            tmp_path,
            op_type=op_type,
            malicious=malicious,
            dynamic_quantization=True,
        )

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 0
        assert len(semantics["unresolved_lineage_samples"]) == 1
        unresolved = semantics["unresolved_lineage_samples"][0]
        assert unresolved["reason"] == "dynamic_quantize_linear_lineage_unsupported"
        assert unresolved["consumer_input_index"] == 3
        assert "unresolved_lineage_consumer" not in semantics["exclusion_counts"]

    def test_dynamic_quantize_linear_gather_weight_fails_closed(self, tmp_path: Path) -> None:
        model_path = create_dynamic_quantize_gather_weight_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 0
        unresolved = semantics["unresolved_lineage_samples"][0]
        assert unresolved["reason"] == "dynamic_quantize_linear_lineage_unsupported"
        assert unresolved["consumer_op"] == "Gather"

    def test_custom_dynamic_quantize_name_does_not_drop_weight_lineage(self, tmp_path: Path) -> None:
        model_path = create_custom_dynamic_quantize_name_collision_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 0
        assert semantics["unresolved_lineage_samples"][0]["reason"] == "unsupported_lineage_operator"

    def test_registered_standard_transform_preserves_unresolved_weight_lineage(self, tmp_path: Path) -> None:
        model_path = create_concat_weight_lineage_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 2
        assert semantics["analyzed_initializer_count"] == 0
        assert {sample["reason"] for sample in semantics["unresolved_lineage_samples"]} == {
            "unsupported_lineage_operator"
        }
        assert {sample["consumer_op"] for sample in semantics["unresolved_lineage_samples"]} == {"MatMul"}

    def test_dynamic_concat_weight_lineage_fails_closed(self, tmp_path: Path) -> None:
        result = OnnxScanner().scan(str(create_concat_weight_lineage_model(tmp_path, dynamic_right=True)))

        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert result.success is False
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 0
        assert {sample["reason"] for sample in semantics["unresolved_lineage_samples"]} == {"dynamic_input_lineage"}

    def test_matmul_integer_dead_scale_branch_cannot_suppress_anomaly(self, tmp_path: Path) -> None:
        model_path = create_matmul_integer_weight_model(
            tmp_path,
            malicious=True,
            dead_scale_branch=True,
            zero_scale=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        checks = self._extreme_checks(result)
        assert len(checks) == 1
        assert checks[0].details["affected_neurons"] == [3]
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 1
        assert semantics["eligible"][0]["quantization_scale"] is None

    def test_matmul_integer_terminal_integer_bias_uses_centered_weights(self, tmp_path: Path) -> None:
        model_path = create_matmul_integer_weight_model(
            tmp_path,
            bind_scale=False,
            terminal_bias_add=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 1
        assert semantics["eligible"][0]["quantization_scale"] is None

    @pytest.mark.parametrize(
        ("weight_on_left", "expose_raw_output"),
        [(False, False), (True, False)],
    )
    def test_matmul_integer_resolves_complete_live_scale_chain(
        self,
        tmp_path: Path,
        weight_on_left: bool,
        expose_raw_output: bool,
    ) -> None:
        model_path = create_matmul_integer_scale_chain_model(
            tmp_path,
            weight_on_left=weight_on_left,
            expose_raw_output=expose_raw_output,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        checks = [
            check
            for check in result.checks
            if check.name == "Weight Distribution Anomaly Detection" and "abnormal weight magnitudes" in check.message
        ]
        assert len(checks) == 1
        assert checks[0].details["outlier_neurons"] == [3]
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["analyzed_initializer_count"] == 1
        assert semantics["eligible"][0]["quantization_scale"] == "W_scale_0"

    @pytest.mark.parametrize("integer_op_boundary", ["direct", "function", "if_subgraph"])
    @pytest.mark.parametrize("anomalous_vector_scale", [False, True])
    def test_matmul_integer_scale_chain_fails_closed_at_non_root_graph_boundary(
        self,
        tmp_path: Path,
        integer_op_boundary: str,
        anomalous_vector_scale: bool,
    ) -> None:
        model_path = create_matmul_integer_scale_chain_model(
            tmp_path,
            anomalous_vector_scale=anomalous_vector_scale,
            integer_op_boundary=integer_op_boundary,
        )

        result = OnnxScanner().scan(str(model_path))
        semantics = result.metadata["onnx_weight_distribution_semantics"]

        if integer_op_boundary != "direct":
            assert result.success is False
            coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
            assert len(coverage) == 1
            assert semantics["eligible_initializer_count"] == 1
            assert semantics["analyzed_initializer_count"] == 0
            assert semantics["unresolved_lineage_samples"][0]["reason"] == "unresolved_quantized_weight_scale"
        else:
            assert result.success is True
            checks = [
                check
                for check in result.checks
                if check.name == "Weight Distribution Anomaly Detection"
                and "abnormal weight magnitudes" in check.message
            ]
            assert len(checks) == int(anomalous_vector_scale)
            assert semantics["analyzed_initializer_count"] == 1
            assert semantics["eligible"][0]["quantization_scale_factor_names"] == ["X_scale", "W_scale_0"]

    def test_matmul_integer_resolves_scale_chain_past_integer_bias(self, tmp_path: Path) -> None:
        model_path = create_matmul_integer_scale_chain_model(tmp_path, bias_add=True)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        checks = [
            check
            for check in result.checks
            if check.name == "Weight Distribution Anomaly Detection" and "abnormal weight magnitudes" in check.message
        ]
        assert len(checks) == 1
        assert checks[0].details["outlier_neurons"] == [3]
        context = result.metadata["onnx_weight_distribution_semantics"]["eligible"][0]
        assert context["quantization_scale"] == "W_scale_0"

    def test_matmul_integer_resolves_scale_chain_past_float_bias(self, tmp_path: Path) -> None:
        model_path = create_matmul_integer_scale_chain_model(tmp_path, post_scale_bias_add=True)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        checks = [
            check
            for check in result.checks
            if check.name == "Weight Distribution Anomaly Detection" and "abnormal weight magnitudes" in check.message
        ]
        assert len(checks) == 1
        assert checks[0].details["outlier_neurons"] == [3]
        context = result.metadata["onnx_weight_distribution_semantics"]["eligible"][0]
        assert context["quantization_scale_factor_names"] == ["X_scale", "W_scale_0"]

    @pytest.mark.parametrize("malicious", [False, True])
    def test_dynamic_matmul_integer_scale_chain_stops_after_complete_bias_path(
        self,
        tmp_path: Path,
        malicious: bool,
    ) -> None:
        result = OnnxScanner().scan(str(create_dynamic_matmul_integer_bias_model(tmp_path, malicious=malicious)))

        semantics = result.metadata["onnx_weight_distribution_semantics"]
        checks = [
            check
            for check in result.checks
            if check.name == "Weight Distribution Anomaly Detection" and "abnormal weight magnitudes" in check.message
        ]
        assert result.success is True
        assert len(checks) == int(malicious)
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 1
        assert semantics["coverage_gaps"] == {}
        assert semantics["eligible"][0]["quantization_scale_factor_names"] == ["W_scale"]

    def test_declared_low_rank_standard_output_does_not_become_weight_lineage(self, tmp_path: Path) -> None:
        result = OnnxScanner().scan(str(create_declared_shape_metadata_model(tmp_path)))

        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert result.success is True
        assert semantics["eligible_initializer_count"] == 0
        assert semantics["analyzed_initializer_count"] == 0
        assert semantics["coverage_gaps"] == {}

    def test_matmul_integer_non_unit_add_scale_chain_fails_closed(self, tmp_path: Path) -> None:
        model_path = create_matmul_integer_scale_chain_model(tmp_path, duplicate_add_input=True)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["analyzed_initializer_count"] == 0
        assert semantics["unresolved_lineage_samples"][0]["reason"] == "unresolved_quantized_weight_scale"

    @pytest.mark.parametrize("unsupported_live_op", ["Reshape", "Relu"])
    @pytest.mark.parametrize("anomalous_vector_scale", [False, True])
    def test_matmul_integer_unsupported_live_scale_path_fails_closed(
        self,
        tmp_path: Path,
        unsupported_live_op: str,
        anomalous_vector_scale: bool,
    ) -> None:
        model_path = create_matmul_integer_scale_chain_model(
            tmp_path,
            unsupported_live_op=unsupported_live_op,
            anomalous_vector_scale=anomalous_vector_scale,
        )

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["analyzed_initializer_count"] == 0
        assert semantics["unresolved_lineage_samples"][0]["reason"] == "unresolved_quantized_weight_scale"

    def test_matmul_integer_self_multiply_scale_path_fails_closed(self, tmp_path: Path) -> None:
        model_path = create_matmul_integer_weight_model(tmp_path, self_multiply_output=True)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["analyzed_initializer_count"] == 0
        assert semantics["unresolved_lineage_samples"][0]["reason"] == "unresolved_quantized_weight_scale"

    @pytest.mark.parametrize(
        ("overflow_scale", "scalar_overflow", "scalar_only_scale", "widen_after_scale"),
        [
            (True, False, False, False),
            (True, False, False, True),
            (False, True, False, False),
            (False, True, False, True),
            (False, True, True, False),
            (False, True, True, True),
        ],
    )
    def test_matmul_integer_scale_chain_preserves_cast_precision(
        self,
        tmp_path: Path,
        overflow_scale: bool,
        scalar_overflow: bool,
        scalar_only_scale: bool,
        widen_after_scale: bool,
    ) -> None:
        model_path = create_matmul_integer_scale_chain_model(
            tmp_path,
            cast_data_type=TensorProto.FLOAT16,
            overflow_scale=overflow_scale,
            scalar_overflow=scalar_overflow,
            scalar_only_scale=scalar_only_scale,
            widen_after_scale=widen_after_scale,
        )

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        assert checks[0].details["num_nonfinite_weights"] == 1000
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["analyzed_initializer_count"] == 1
        assert semantics["eligible"][0]["quantization_output_data_type"] == TensorProto.FLOAT16
        expected_scale_names = ["X_scale"] if scalar_only_scale else ["X_scale", "W_scale_0"]
        assert semantics["eligible"][0]["quantization_scale_factor_names"] == expected_scale_names

    def test_matmul_integer_scale_chain_preserves_repeated_factors(self, tmp_path: Path) -> None:
        model_path = create_matmul_integer_scale_chain_model(
            tmp_path,
            cast_data_type=TensorProto.FLOAT16,
            repeat_weight_scale=True,
        )

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        assert checks[0].details["num_nonfinite_weights"] == 1000
        context = result.metadata["onnx_weight_distribution_semantics"]["eligible"][0]
        assert context["quantization_scale_factor_names"] == ["X_scale", "W_scale_0", "W_scale_0"]

    def test_matmul_integer_scale_chain_preserves_narrowing_output_cast(self, tmp_path: Path) -> None:
        model_path = create_matmul_integer_scale_chain_model(
            tmp_path,
            scalar_overflow=True,
            scalar_only_scale=True,
            narrow_after_scale=True,
        )

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        assert checks[0].details["num_nonfinite_weights"] == 1000
        context = result.metadata["onnx_weight_distribution_semantics"]["eligible"][0]
        assert context["quantization_output_data_type"] == TensorProto.FLOAT16

    @pytest.mark.parametrize(
        (
            "vector_scale_count",
            "dynamic_scale_expression",
            "nested_static_scale_expression",
            "cast_scale_expression",
            "expose_raw_output",
        ),
        [
            (2, False, False, False, False),
            (1, True, False, False, False),
            (1, False, True, False, False),
            (1, False, False, True, False),
            (1, False, False, False, True),
        ],
    )
    def test_matmul_integer_unresolved_live_scale_chain_fails_closed(
        self,
        tmp_path: Path,
        vector_scale_count: int,
        dynamic_scale_expression: bool,
        nested_static_scale_expression: bool,
        cast_scale_expression: bool,
        expose_raw_output: bool,
    ) -> None:
        model_path = create_matmul_integer_scale_chain_model(
            tmp_path,
            vector_scale_count=vector_scale_count,
            dynamic_scale_expression=dynamic_scale_expression,
            nested_static_scale_expression=nested_static_scale_expression,
            cast_scale_expression=cast_scale_expression,
            expose_raw_output=expose_raw_output,
        )

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["analyzed_initializer_count"] == 0
        assert semantics["unresolved_lineage_samples"][0]["reason"] == "unresolved_quantized_weight_scale"

    @pytest.mark.parametrize("malicious", [False, True])
    def test_qlinear_matmul_left_weight_is_analyzed(self, tmp_path: Path, malicious: bool) -> None:
        model_path = create_qlinear_matmul_left_weight_model(tmp_path, malicious=malicious)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        checks = self._extreme_checks(result)
        assert len(checks) == int(malicious)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 1
        context = semantics["eligible"][0]
        assert context["consumer_op"] == "QLinearMatMul"
        assert context["consumer_input_index"] == 0
        assert context["output_axis"] == 0
        assert context["quantization_scale"] == "W_scale"
        if malicious:
            assert checks[0].details["affected_neurons"] == [3]

    def test_qdq_malformed_scale_shape_fails_closed(self, tmp_path: Path) -> None:
        model_path = create_qdq_weight_model(tmp_path, malformed_scale=True)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["extraction_failures"] == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 0

    def test_qdq_full_shape_parameters_fail_closed(self, tmp_path: Path) -> None:
        model_path = create_qdq_weight_model(tmp_path, malicious=True, full_shape_parameters=True)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["extraction_failures"] == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 0

    @pytest.mark.parametrize("output_dtype", [None, TensorProto.FLOAT16, 0])
    def test_qdq_float16_precision_preserves_nonfinite_weights(
        self,
        tmp_path: Path,
        output_dtype: int | None,
    ) -> None:
        model_path = create_qdq_float16_overflow_model(
            tmp_path,
            output_dtype=output_dtype,
        )

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        assert checks[0].details["num_nonfinite_weights"] == 1000
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 1
        assert semantics["eligible"][0]["quantization_output_data_type"] == TensorProto.FLOAT16

    @pytest.mark.parametrize("data_type", [TensorProto.INT4, TensorProto.UINT4])
    @pytest.mark.parametrize("malicious", [False, True])
    def test_qdq_low_bit_weight_path_is_analyzed(
        self,
        tmp_path: Path,
        data_type: int,
        malicious: bool,
    ) -> None:
        model_path = create_qdq_4bit_weight_model(tmp_path, data_type, malicious=malicious)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        checks = self._extreme_checks(result)
        assert len(checks) == int(malicious)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 1
        assert semantics["eligible"][0]["quantization_kind"] == "DequantizeLinear"

    @pytest.mark.parametrize(
        "data_type",
        [TensorProto.INT2, TensorProto.UINT2, TensorProto.INT4, TensorProto.UINT4],
    )
    def test_packed_low_bit_initializer_storage_size_is_valid(self, tmp_path: Path, data_type: int) -> None:
        model_path = create_packed_low_bit_initializer_model(tmp_path, data_type)

        result = OnnxScanner().scan(str(model_path))

        size_checks = [check for check in result.checks if check.name == "Tensor Size Validation"]
        assert len(size_checks) == 1
        assert size_checks[0].status == CheckStatus.PASSED
        assert result.metadata["validated_format"] == "onnx"

    @pytest.mark.parametrize("data_type", [TensorProto.INT2, TensorProto.INT4])
    def test_truncated_packed_low_bit_initializer_fails_size_validation(
        self,
        tmp_path: Path,
        data_type: int,
    ) -> None:
        model_path = create_packed_low_bit_initializer_model(tmp_path, data_type, truncate=True)

        result = OnnxScanner().scan(str(model_path))

        size_checks = [check for check in result.checks if check.name == "Tensor Size Validation"]
        assert len(size_checks) == 1
        assert size_checks[0].status == CheckStatus.FAILED
        assert size_checks[0].rule_code == "S703"
        assert "validated_format" not in result.metadata

    @pytest.mark.parametrize("data_type", [TensorProto.INT2, TensorProto.UINT2])
    def test_qdq_2bit_weight_path_fails_closed_when_decoder_cannot_materialize(
        self,
        tmp_path: Path,
        data_type: int,
    ) -> None:
        model_path = create_qdq_4bit_weight_model(tmp_path, data_type, malicious=True)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["extraction_failures"] == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 0

    def test_packed_quantization_parameter_is_bounded_by_decoded_size(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        model_path = create_oversized_packed_zero_point_model(tmp_path)
        decoded_names: list[str] = []
        original_to_array = onnx.numpy_helper.to_array

        def recording_to_array(tensor: Any, *args: Any, **kwargs: Any) -> Any:
            decoded_names.append(str(tensor.name))
            return original_to_array(tensor, *args, **kwargs)

        monkeypatch.setattr(onnx.numpy_helper, "to_array", recording_to_array)

        result = OnnxScanner({"max_array_size": 4_001}).scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["extraction_failures"] == 1
        assert "zero_point" not in decoded_names

    def test_qdq_transpose_materializes_before_axis_changes(self, tmp_path: Path) -> None:
        model_path = create_qdq_transposed_weight_model(tmp_path, malicious=True)

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        assert checks[0].details["affected_neurons"] == [3]
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 1
        context = semantics["eligible"][0]
        assert context["lineage"] == ["DequantizeLinear", "Transpose"]
        assert context["quantization_axis"] == 0

    def test_qdq_post_dequantization_copy_respects_retained_budget(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "modelaudit.scanners.onnx_scanner._ONNX_WEIGHT_RETAINED_ARRAY_BUDGET_MULTIPLIER",
            2,
        )
        model_path = create_qdq_transpose_reshape_weight_model(tmp_path)

        result = OnnxScanner({"max_array_size": 4_001}).scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["extraction_failures"] == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 0

    @pytest.mark.parametrize("malicious", [False, True])
    def test_qlinear_matmul_nd_scale_broadcast_is_analyzed(
        self,
        tmp_path: Path,
        malicious: bool,
    ) -> None:
        model_path = create_qlinear_matmul_nd_scale_model(tmp_path, malicious=malicious)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        checks = self._extreme_checks(result)
        assert len(checks) == int(malicious)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 1
        context = semantics["eligible"][0]
        assert context["consumer_op"] == "QLinearMatMul"
        assert context["quantization_scale"] == "W_scale"

    @pytest.mark.parametrize("invalid_kind", ["full_shape", "zero_point_dtype", "scale_dtype"])
    def test_qlinear_matmul_invalid_parameters_fail_closed(self, tmp_path: Path, invalid_kind: str) -> None:
        model_path = create_qlinear_matmul_invalid_parameter_model(tmp_path, invalid_kind)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["extraction_failures"] == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["analyzed_initializer_count"] == 0

    def test_qlinear_matmul_float16_scale_uses_float32_analysis(self, tmp_path: Path) -> None:
        model_path = create_qlinear_matmul_float16_scale_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert self._extreme_checks(result) == []
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["analyzed_initializer_count"] == 1
        assert semantics["eligible"][0]["quantization_output_data_type"] == TensorProto.FLOAT

    def test_quantized_lineage_self_overwrite_cycle_is_bounded(self, tmp_path: Path) -> None:
        weights = np.zeros((100, 10), dtype=np.int8)
        weights[50:55, 3] = 100
        initializers = [
            onnx.numpy_helper.from_array(weights, name="W"),
            onnx.numpy_helper.from_array(np.asarray(0.1, dtype=np.float32), name="scale"),
            onnx.numpy_helper.from_array(np.asarray(0, dtype=np.int8), name="zero_point"),
        ]
        graph = helper.make_graph(
            [
                helper.make_node("DequantizeLinear", ["W", "scale", "zero_point"], ["W"]),
                helper.make_node("MatMul", ["X", "W"], ["Y"]),
            ],
            "self_overwrite_qdq_cycle",
            [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])],
            [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])],
            initializer=initializers,
        )
        model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
        model.ir_version = 8
        model_path = tmp_path / "self-overwrite-qcycle.onnx"
        onnx.save(model, str(model_path))

        result = OnnxScanner().scan(str(model_path))

        assert len(self._extreme_checks(result)) == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 1
        assert semantics["node_visit_count"] == 2

    def test_quantized_dequantized_size_budget_fails_closed(self, tmp_path: Path) -> None:
        model_path = create_matmul_integer_weight_model(tmp_path)

        result = OnnxScanner({"max_array_size": 2000}).scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["oversized_initializers_skipped"] == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_initializer_count"] == 0

    def test_weight_lineage_edge_budget_exhaustion_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("modelaudit.scanners.onnx_scanner._ONNX_WEIGHT_EDGE_VISIT_LIMIT", 1)
        model_path = create_onnx_weight_model(
            tmp_path,
            np.zeros((100, 10), dtype=np.float32),
            op_type="MatMul",
        )

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["coverage_gaps"] == {"edge_visit_limit": 1}
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["edge_visit_limit"] == 1

    def test_initializer_group_fanout_limit_fails_closed_without_dropping_detected_groups(
        self,
        tmp_path: Path,
    ) -> None:
        model_path = create_conv_group_fanout_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["coverage_gaps"] == {"initializer_analysis_group_limit": 1}
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_layer_count"] == 100

    def test_quantized_copy_retained_budget_fails_closed(self, tmp_path: Path) -> None:
        model_path = create_qlinear_matmul_group_fanout_model(tmp_path)

        result = OnnxScanner({"max_array_size": 64 * 64 * 4 + 1}).scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["extraction_failures"] == 1
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_layer_count"] < 100

    def test_sparse_weight_lineage_fails_closed(self, tmp_path: Path) -> None:
        model_path = create_sparse_weight_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["coverage_gap"] == "unresolved_initializer_lineage"
        assert coverage[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["unresolved_lineage_samples"][0]["reason"] == "sparse_initializer_unsupported"

    @pytest.mark.parametrize(
        "model_factory",
        [
            create_constant_weight_model,
            create_local_function_weight_model,
            create_local_function_default_weight_model,
        ],
    )
    @pytest.mark.parametrize("malicious", [False, True])
    def test_static_and_function_weight_roots_are_analyzed(
        self,
        tmp_path: Path,
        model_factory: Any,
        malicious: bool,
    ) -> None:
        weights = np.zeros((100, 10), dtype=np.float32)
        if malicious:
            weights[50:55, 3] = 10.0
        model_path = model_factory(tmp_path, weights)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        checks = self._extreme_checks(result)
        assert len(checks) == int(malicious)
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
        assert result.metadata["onnx_weight_distribution_semantics"]["analyzed_layer_count"] == 1

    def test_repeated_function_constant_is_one_physical_initializer(self, tmp_path: Path) -> None:
        weights = np.zeros((100, 10), dtype=np.float32)
        model_path = create_repeated_local_function_default_weight_model(tmp_path, weights)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert self._extreme_checks(result) == []
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_layer_count"] == 1
        assert semantics["eligible"][0]["consumer_count"] == 2

    def test_distinct_function_attribute_bindings_do_not_alias(self, tmp_path: Path) -> None:
        model_path = create_many_local_function_weight_overrides_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        assert checks[0].details["affected_neurons"] == [3]
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 100
        assert semantics["analyzed_layer_count"] == 100

    def test_distinct_branch_local_constants_do_not_alias(self, tmp_path: Path) -> None:
        model_path = create_many_if_branch_weight_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        assert checks[0].details["affected_neurons"] == [3]
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 40
        assert semantics["analyzed_layer_count"] == 40

    @pytest.mark.parametrize("transform", ["Flatten", "ReshapeValueInts", "Squeeze", "Unsqueeze"])
    @pytest.mark.parametrize("malicious", [False, True])
    def test_static_shape_weight_transforms_preserve_detection_without_clean_noise(
        self,
        tmp_path: Path,
        transform: str,
        malicious: bool,
    ) -> None:
        weights = np.zeros((100, 10), dtype=np.float32)
        if malicious:
            weights[50:55, 3] = 10.0
        model_path = create_static_shape_transform_weight_model(tmp_path, weights, transform=transform)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert len(self._extreme_checks(result)) == int(malicious)
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)

    @pytest.mark.parametrize(
        ("transform", "expected_lineage"),
        [
            ("Identity", []),
            ("Cast", []),
            ("Transpose", ["Transpose"]),
            ("Reshape", ["Reshape"]),
        ],
    )
    def test_supported_initializer_lineage_reaches_matmul(
        self,
        tmp_path: Path,
        transform: str,
        expected_lineage: list[str],
    ) -> None:
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50:55, 3] = 10.0
        model_path = create_transformed_onnx_weight_model(tmp_path, weights, transform=transform)

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        assert checks[0].details["affected_neurons"] == [3]
        assert checks[0].details["lineage"] == expected_lineage
        assert checks[0].details["lineage_transform_count"] == len(expected_lineage)
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)

    @pytest.mark.parametrize("transform", ["ReshapeDynamic", "CastFloat16"])
    def test_unsupported_initializer_lineage_fails_closed(self, tmp_path: Path, transform: str) -> None:
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50:55, 3] = 10.0
        model_path = create_transformed_onnx_weight_model(tmp_path, weights, transform=transform)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert self._extreme_checks(result) == []
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["coverage_gap"] == "unresolved_initializer_lineage"
        assert coverage[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["coverage_gaps"] == {"unresolved_initializer_lineage": 1}

    def test_dynamic_mixed_weight_lineage_fails_closed(self, tmp_path: Path) -> None:
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50:55, 3] = 10.0
        model_path = create_transformed_onnx_weight_model(tmp_path, weights, transform="AddDynamic")

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert self._extreme_checks(result) == []
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["coverage_gap"] == "unresolved_initializer_lineage"
        assert coverage[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        sample = semantics["unresolved_lineage_samples"][0]
        assert sample["reason"] == "dynamic_input_lineage"
        assert sample["consumer_op"] == "MatMul"
        assert sample["consumer_input_index"] == 1

    def test_dynamic_left_weight_lineage_fails_closed(self, tmp_path: Path) -> None:
        model_path = create_dynamic_left_weight_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert self._extreme_checks(result) == []
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}
        sample = result.metadata["onnx_weight_distribution_semantics"]["unresolved_lineage_samples"][0]
        assert sample["initializer"] == "W"
        assert sample["reason"] == "dynamic_input_lineage"
        assert sample["consumer_op"] == "MatMul"
        assert sample["consumer_input_index"] == 0

    def test_recurrent_dynamic_weight_slot_fails_closed(self, tmp_path: Path) -> None:
        model_path = create_recurrent_dynamic_weight_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert self._extreme_checks(result) == []
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}
        sample = result.metadata["onnx_weight_distribution_semantics"]["unresolved_lineage_samples"][0]
        assert sample["initializer"] == "P"
        assert sample["reason"] == "dynamic_activation_lineage"
        assert sample["consumer_op"] == "GRU"
        assert sample["consumer_input_index"] == 1

    @pytest.mark.parametrize("left", [False, True])
    def test_projected_dynamic_matmul_weight_fails_closed(self, tmp_path: Path, left: bool) -> None:
        model_path = create_projected_dynamic_matmul_weight_model(tmp_path, left=left)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert self._extreme_checks(result) == []
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}
        samples = result.metadata["onnx_weight_distribution_semantics"]["unresolved_lineage_samples"]
        assert len(samples) == 1
        assert samples[0]["initializer"] == "P"
        assert samples[0]["reason"] == "dynamic_activation_lineage"
        assert samples[0]["consumer_op"] == "MatMul"
        assert samples[0]["consumer_input_index"] == (0 if left else 1)

    def test_broadcast_dynamic_weight_lineage_fails_closed(self, tmp_path: Path) -> None:
        model_path = create_broadcast_dynamic_weight_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert self._extreme_checks(result) == []
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}
        sample = result.metadata["onnx_weight_distribution_semantics"]["unresolved_lineage_samples"][0]
        assert sample["reason"] == "dynamic_input_lineage"
        assert sample["consumer_op"] == "MatMul"
        assert sample["consumer_input_index"] == 1

    def test_computed_weight_lineage_fails_closed(self, tmp_path: Path) -> None:
        model_path = create_computed_weight_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert self._extreme_checks(result) == []
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 2}
        samples = result.metadata["onnx_weight_distribution_semantics"]["unresolved_lineage_samples"]
        assert {sample["initializer"] for sample in samples} == {"A", "B"}
        assert {sample["reason"] for sample in samples} == {"unsupported_lineage_operator"}
        assert {sample["consumer_input_index"] for sample in samples} == {1}

    def test_raw_dynamic_taint_is_not_laundered_by_activation_lineage(self, tmp_path: Path) -> None:
        model_path = create_mixed_activation_and_raw_lineage_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        assert self._extreme_checks(result) == []
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["coverage_gaps"] == {"unresolved_initializer_lineage": 1}
        samples = result.metadata["onnx_weight_distribution_semantics"]["unresolved_lineage_samples"]
        assert len(samples) == 1
        assert samples[0]["initializer"] == "W"
        assert samples[0]["reason"] == "dynamic_input_lineage"
        assert samples[0]["consumer_input_index"] == 0

    @pytest.mark.parametrize(
        ("model_factory", "expected_layers"),
        [
            (create_left_weight_stack_model, 2),
            (create_left_weight_gemm_stack_model, 2),
            (create_attention_score_model, 3),
            (create_einsum_attention_score_model, 2),
        ],
    )
    def test_prior_layer_activations_are_not_reclassified_as_weights(
        self,
        tmp_path: Path,
        model_factory: Any,
        expected_layers: int,
    ) -> None:
        model_path = model_factory(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert self._extreme_checks(result) == []
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == expected_layers
        assert semantics["analyzed_layer_count"] == expected_layers

    def test_internal_analysis_ids_cannot_collide_with_initializer_names(self, tmp_path: Path) -> None:
        model_path = create_collision_named_weight_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        semantics = result.metadata["onnx_weight_distribution_semantics"]
        contexts = semantics["eligible"]
        assert semantics["eligible_initializer_count"] == 3
        assert semantics["analyzed_layer_count"] == 4
        assert [context["analysis_id"] for context in contexts] == [0, 1, 2, 3]
        assert len({context["analysis_id"] for context in contexts}) == 4
        assert {context["initializer"] for context in contexts} == {
            "W",
            "W@output_axis=1",
            "W@output_axis=1,kind=matrix,group=1",
        }

    @pytest.mark.parametrize("left", [False, True])
    def test_batched_matmul_preserves_batch_outputs(self, tmp_path: Path, left: bool) -> None:
        weights = np.zeros((2, 10, 100), dtype=np.float32) if left else np.zeros((2, 100, 10), dtype=np.float32)
        if left:
            weights[1, 3, 50:55] = 10.0
        else:
            weights[1, 50:55, 3] = 10.0
        model_path = create_batched_matmul_weight_model(tmp_path, weights, left=left)

        result = OnnxScanner().scan(str(model_path))

        checks = self._extreme_checks(result)
        assert len(checks) == 1
        details = checks[0].details
        expected_output_axes = [0, 1] if left else [0, 2]
        assert details["output_axes"] == expected_output_axes
        assert details["conceptual_output_axes"] == expected_output_axes
        assert details["analysis_shape"] == [100, 20]
        assert details["total_outputs"] == 20
        assert details["affected_neurons"] == [13]

    def test_consumer_and_string_metadata_are_bounded_with_counts(self, tmp_path: Path) -> None:
        model_path = create_many_consumer_weight_model(tmp_path, consumer_count=30)

        result = OnnxScanner().scan(str(model_path))

        semantics = result.metadata["onnx_weight_distribution_semantics"]
        context = semantics["eligible"][0]
        assert semantics["consumer_count"] == 30
        assert semantics["consumer_metadata_sample_count"] == 20
        assert semantics["consumer_metadata_truncated"] is True
        assert semantics["metadata_strings_truncated"] is True
        assert context["consumer_count"] == 30
        assert len(context["consumers"]) == 20
        assert context["consumers_truncated"] is True
        assert context["initializer_truncated"] is True
        assert context["initializer_length"] > len(context["initializer"])
        assert len(context["initializer"]) <= 256
        assert all(len(consumer["node"]) <= 256 for consumer in context["consumers"])
        checks = self._extreme_checks(result)
        assert len(checks) == 1
        assert len(checks[0].message) < 400

    @pytest.mark.parametrize("duplicate", [False, True])
    def test_invalid_initializer_names_fail_closed(self, tmp_path: Path, duplicate: bool) -> None:
        model_path = create_invalid_initializer_name_model(tmp_path, duplicate=duplicate)

        result = OnnxScanner().scan(str(model_path))

        coverage = [check for check in result.checks if check.name == "Weight Distribution Analysis Coverage"]
        validation = result.metadata["onnx_weight_distribution_semantics"]["initializer_name_validation"]
        assert result.success is False
        assert len(coverage) == 1
        assert coverage[0].details["coverage_gap"] == "invalid_initializer_names"
        assert validation["duplicate_name_count"] == int(duplicate)
        assert validation["empty_name_count"] == int(not duplicate)

    def test_standalone_onnx_scanner_matches_semantic_orientation(self, tmp_path: Path) -> None:
        weights = np.zeros((10, 100), dtype=np.float32)
        weights[3, 50:55] = 10.0
        model_path = create_onnx_weight_model(tmp_path, weights, op_type="Gemm", trans_b=True)

        integrated = OnnxScanner().scan(str(model_path))
        standalone = WeightDistributionScanner().scan(str(model_path))

        integrated_check = self._extreme_checks(integrated)[0]
        standalone_checks = [
            check
            for check in standalone.checks
            if check.name == "Weight Distribution Anomaly Detection"
            and "extremely large weight values" in check.message
        ]
        assert len(standalone_checks) == 1
        assert standalone_checks[0].details["output_axis"] == integrated_check.details["output_axis"] == 0
        assert standalone_checks[0].details["analysis_shape"] == integrated_check.details["analysis_shape"] == [100, 10]
        assert standalone_checks[0].details["affected_neurons"] == integrated_check.details["affected_neurons"] == [3]

    def test_standalone_onnx_scanner_matches_gather_orientation(self, tmp_path: Path) -> None:
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50:55, 3] = 10.0
        model_path = create_onnx_weight_model(tmp_path, weights, op_type="Gather")

        standalone = WeightDistributionScanner().scan(str(model_path))

        checks = [
            check
            for check in standalone.checks
            if check.name == "Weight Distribution Anomaly Detection"
            and "extremely large weight values" in check.message
        ]
        assert len(checks) == 1
        assert checks[0].details["output_axis"] == 1
        assert checks[0].details["affected_neurons"] == [3]
        semantics = standalone.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 1
        assert semantics["analyzed_layer_count"] == 2

    def test_aggregate_clusters_duplicate_exports_without_merging_distinct_anomalies(self, tmp_path: Path) -> None:
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50:55, 3] = 10.0
        first = create_onnx_weight_model(tmp_path, weights, op_type="MatMul", filename="duplicate-a.onnx")
        second = tmp_path / "duplicate-b.onnx"
        second.write_bytes(first.read_bytes())
        create_onnx_weight_model(tmp_path, weights, op_type="Gather", filename="distinct-gather.onnx")

        aggregate = scan_model_directory_or_file(
            str(tmp_path),
            recursive=False,
            scanners=["onnx"],
            cache_enabled=False,
        )

        clustered = [issue for issue in aggregate.issues if issue.details.get("clustered_onnx_weight_anomaly") is True]
        assert len(clustered) == 2
        assert {issue.details["cluster_size"] for issue in clustered} == {2}
        for issue in clustered:
            assert {item["file"] for item in issue.details["export_provenance"]} == {str(first), str(second)}
            assert issue.details["byte_identical_export_groups"][0]["export_count"] == 2
        onnx_weight_issues = [
            issue
            for issue in aggregate.issues
            if issue.type == "onnx_check"
            and ("affected_neurons" in issue.details or "outlier_neurons" in issue.details)
        ]
        assert len(onnx_weight_issues) == 4
        assert {issue.details["consumer_op"] for issue in onnx_weight_issues} == {"MatMul", "Gather"}
        assert sum(1 for issue in onnx_weight_issues if issue.details["consumer_op"] == "Gather") == 2

    def test_aggregate_bounds_duplicate_export_provenance_before_building_it(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50:55, 3] = 10.0
        first = create_onnx_weight_model(tmp_path, weights, op_type="MatMul", filename="duplicate-00.onnx")
        payload = first.read_bytes()
        for index in range(1, 21):
            (tmp_path / f"duplicate-{index:02d}.onnx").write_bytes(payload)

        provenance_call_count = 0
        original_provenance = modelaudit_core._onnx_weight_anomaly_provenance

        def recording_provenance(results: Any, issue: Any) -> dict[str, Any]:
            nonlocal provenance_call_count
            provenance_call_count += 1
            return original_provenance(results, issue)

        monkeypatch.setattr(modelaudit_core, "_onnx_weight_anomaly_provenance", recording_provenance)

        aggregate = scan_model_directory_or_file(
            str(tmp_path),
            recursive=False,
            scanners=["onnx"],
            cache_enabled=False,
        )

        clustered = [issue for issue in aggregate.issues if issue.details.get("clustered_onnx_weight_anomaly") is True]
        assert len(clustered) == 2
        assert provenance_call_count == 2 * 20
        for issue in clustered:
            assert issue.details["cluster_size"] == 21
            assert len(issue.details["export_provenance"]) == 20
            assert issue.details["export_provenance_truncated"] is True
            group = issue.details["byte_identical_export_groups"][0]
            assert group["export_count"] == 21
            assert len(group["files"]) == 20
            assert group["files_truncated"] is True

    def test_aggregate_does_not_cluster_distinct_file_hashes_with_same_signature(self, tmp_path: Path) -> None:
        positive_weights = np.zeros((100, 10), dtype=np.float32)
        positive_weights[50:55, 3] = 10.0
        negative_weights = np.zeros((100, 10), dtype=np.float32)
        negative_weights[10:15, 3] = -10.0
        create_onnx_weight_model(tmp_path, positive_weights, op_type="MatMul", filename="positive.onnx")
        create_onnx_weight_model(tmp_path, negative_weights, op_type="MatMul", filename="negative.onnx")

        aggregate = scan_model_directory_or_file(
            str(tmp_path),
            recursive=False,
            scanners=["onnx"],
            cache_enabled=False,
        )

        clustered = [issue for issue in aggregate.issues if issue.details.get("clustered_onnx_weight_anomaly") is True]
        assert clustered == []

    def test_streaming_does_not_cluster_distinct_file_hashes_with_same_signature(self, tmp_path: Path) -> None:
        positive_weights = np.zeros((100, 10), dtype=np.float32)
        positive_weights[50:55, 3] = 10.0
        negative_weights = np.zeros((100, 10), dtype=np.float32)
        negative_weights[10:15, 3] = -10.0
        positive = create_onnx_weight_model(
            tmp_path,
            positive_weights,
            op_type="MatMul",
            filename="stream-positive.onnx",
        )
        negative = create_onnx_weight_model(
            tmp_path,
            negative_weights,
            op_type="MatMul",
            filename="stream-negative.onnx",
        )

        aggregate = scan_model_streaming(
            iter([(positive, False), (negative, True)]),
            delete_after_scan=False,
            scanners=["onnx"],
            cache_enabled=False,
        )

        clustered = [issue for issue in aggregate.issues if issue.details.get("clustered_onnx_weight_anomaly") is True]
        assert clustered == []
        assert {
            metadata.file_hashes.sha256
            for metadata in aggregate.file_metadata.values()
            if metadata.file_hashes is not None
        } == {compute_sha256_hash(positive), compute_sha256_hash(negative)}

    def test_aggregate_preserves_distinct_analysis_groups_within_one_file(self, tmp_path: Path) -> None:
        model_path = create_qlinear_matmul_group_fanout_model(tmp_path, consumer_count=2)

        aggregate = scan_model_directory_or_file(
            str(model_path),
            scanners=["onnx"],
            cache_enabled=False,
        )

        clustered = [issue for issue in aggregate.issues if issue.details.get("clustered_onnx_weight_anomaly") is True]
        assert clustered == []
        weight_issues = [
            issue
            for issue in aggregate.issues
            if issue.type == "onnx_check"
            and ("affected_neurons" in issue.details or "outlier_neurons" in issue.details)
        ]
        assert len(weight_issues) == 4
        assert {issue.details["quantization_scale"] for issue in weight_issues} == {"W_scale_0", "W_scale_1"}

    @pytest.mark.integration
    def test_hf_minilm_pinned_quantized_export_has_bounded_lineage_coverage(self, tmp_path: Path) -> None:
        huggingface_hub = pytest.importorskip("huggingface_hub")
        model_path = huggingface_hub.hf_hub_download(
            "sentence-transformers/all-MiniLM-L12-v2",
            "onnx/model_qint8_avx512.onnx",
            revision="a50ef00143b4d5391434df20ae11632588ac25be",
            cache_dir=tmp_path / "hf-cache",
        )

        result = OnnxScanner({"cache_scan_results": False}).scan(model_path)

        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 72
        assert semantics["analyzed_initializer_count"] == 72
        assert semantics["analyzed_layer_count"] == 72
        assert semantics["coverage_gaps"] == {"lineages_per_value_limit": 109}
        anomaly_checks = [
            check
            for check in result.checks
            if check.name == "Weight Distribution Anomaly Detection" and check.status == CheckStatus.FAILED
        ]
        assert len(anomaly_checks) == 31
        assert {check.severity for check in anomaly_checks} == {IssueSeverity.INFO}
        assert all(
            check.details["analyzed_initializers"] == 72
            for check in result.checks
            if check.name == "Weight Distribution Analysis Coverage"
        )


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
