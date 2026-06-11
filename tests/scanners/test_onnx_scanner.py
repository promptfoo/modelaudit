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

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.detectors.jit_script import JITScriptDetector
from modelaudit.detectors.network_comm import NetworkCommDetector
from modelaudit.integrations.sarif_formatter import format_sarif_output
from modelaudit.scanners.base import FORMAT_VALIDATION_CONFIG_KEY, INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.onnx_scanner import (
    ONNX_STRUCTURE_INCONCLUSIVE_REASON,
    ONNX_WEIGHT_DISTRIBUTION_INCONCLUSIVE_REASON,
    OnnxScanner,
    _configured_onnx_weight_array_limit,
    _confirmed_onnx_operator_findings,
    _confirmed_python_operator_findings,
)
from modelaudit.scanners.weight_distribution_scanner import WeightDistributionScanner
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


def create_qdq_weight_model(tmp_path: Path) -> Path:
    quantized_weight = onnx.numpy_helper.from_array(np.zeros((100, 10), dtype=np.int8), name="W")
    scale = onnx.numpy_helper.from_array(np.asarray(0.1, dtype=np.float32), name="scale")
    zero_point = onnx.numpy_helper.from_array(np.asarray(0, dtype=np.int8), name="zero_point")
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])
    nodes = [
        helper.make_node("DequantizeLinear", ["W", "scale", "zero_point"], ["dequantized_weight"]),
        helper.make_node("MatMul", ["X", "dequantized_weight"], ["Y"]),
    ]
    graph = helper.make_graph(nodes, "qdq_weight_graph", [X], [Y], initializer=[quantized_weight, scale, zero_point])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    path = tmp_path / "qdq-weight.onnx"
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


_PINNED_HF_MULTILINGUAL_E5_LARGE = "intfloat/multilingual-e5-large"
_PINNED_HF_MULTILINGUAL_E5_LARGE_REVISION = "3d7cfbdacd47fdda877c5cd8a79fbcc4f2a574f3"
_PINNED_HF_MULTILINGUAL_E5_LARGE_ONNX = "onnx/model_O4.onnx"
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
    assert result.success is True
    assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)


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
    assert result.success is True
    assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)


def test_onnx_scanner_repeated_custom_domain_nodes_emit_one_domain_check(tmp_path: Path) -> None:
    custom_nodes = [
        *[("com.microsoft", "Attention", f"attention_{index}") for index in range(4)],
        ("com.microsoft", "BiasAttention", "bias_attention"),
        ("com.microsoft", "PackedAttention", "packed_attention"),
    ]
    model_path = create_onnx_model_with_custom_nodes(tmp_path, custom_nodes)

    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    assert len(custom_domain_checks) == 1
    check = custom_domain_checks[0]
    assert check.rule_code == "S1111"
    assert check.severity == IssueSeverity.INFO
    assert check.location == str(model_path)
    assert check.details["domain"] == "com.microsoft"
    assert check.details["occurrence_count"] == len(custom_nodes)
    assert check.details["operator_samples"] == ["Attention", "BiasAttention", "PackedAttention"]
    assert len(check.details["representative_nodes"]) == 5
    assert check.details["representative_nodes_truncated"] is True
    assert result.metadata["custom_domains"] == ["com.microsoft"]
    assert metadata_custom_domains == ["com.microsoft"]
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
    assert details["operator_identities"] == [
        {"domain": "com.vendor", "op_type": "KernelA", "overload": "fast"},
        {"domain": "com.vendor", "op_type": "KernelA", "overload": "safe"},
        {"domain": "com.vendor", "op_type": "KernelB", "overload": "fast"},
    ]
    assert details["operator_identities_truncated"] is False
    assert details["check_consolidation_key"] == "onnx_custom_operator_domain:com.vendor"
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
    assert json_custom_issues[0]["details"]["operator_identities"] == expected_identities
    assert json_custom_issues[0]["details"]["distinct_operator_identity_count"] == len(expected_identities)
    assert json_custom_issues[0]["details"]["operator_identities_truncated"] is False

    sarif_payload = json.loads(format_sarif_output(result, [str(model_path)]))
    sarif_results = [
        item
        for item in sarif_payload["runs"][0]["results"]
        if item["ruleId"] == "S1111" and item.get("properties", {}).get("domain") == "com.acme"
    ]

    assert len(sarif_results) == 1
    assert sarif_results[0]["properties"]["operator_identities"] == expected_identities
    assert sarif_results[0]["properties"]["distinct_operator_identity_count"] == len(expected_identities)


def test_onnx_scanner_repeated_custom_domains_emit_one_check_per_domain(tmp_path: Path) -> None:
    custom_nodes = [
        ("com.microsoft", "Attention", "attention_0"),
        ("com.microsoft", "Attention", "attention_1"),
        ("com.attacker", "BackdoorOp", "backdoor_0"),
        ("com.attacker", "BackdoorOp", "backdoor_1"),
        ("ai.onnx.ml.malicious", "BackdoorOp", "lookalike"),
    ]
    model_path = create_onnx_model_with_custom_nodes(tmp_path, custom_nodes)

    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)

    checks_by_domain = {check.details["domain"]: check for check in custom_domain_checks}
    assert sorted(checks_by_domain) == ["ai.onnx.ml.malicious", "com.attacker", "com.microsoft"]
    assert checks_by_domain["com.microsoft"].details["occurrence_count"] == 2
    assert checks_by_domain["com.attacker"].details["occurrence_count"] == 2
    assert checks_by_domain["ai.onnx.ml.malicious"].details["occurrence_count"] == 1
    assert metadata_custom_domains == ["ai.onnx.ml.malicious", "com.attacker", "com.microsoft"]


def test_onnx_scanner_custom_domains_survive_core_check_consolidation(tmp_path: Path) -> None:
    custom_nodes = [
        ("com.microsoft", "Attention", "attention_0"),
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

    assert sorted(checks_by_domain) == ["ai.onnx.ml.malicious", "com.attacker", "com.microsoft"]
    assert {check.details["check_consolidation_key"] for check in custom_checks} == {
        "onnx_custom_operator_domain:ai.onnx.ml.malicious",
        "onnx_custom_operator_domain:com.attacker",
        "onnx_custom_operator_domain:com.microsoft",
    }
    assert {
        issue.details["domain"]
        for issue in result.issues
        if issue.rule_code == "S1111" and issue.details.get("type") != "python_operator"
    } == set(checks_by_domain)


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


@pytest.mark.onnx
@pytest.mark.slow
@pytest.mark.integration
def test_onnx_scanner_pinned_hf_multilingual_e5_large_custom_domains_deduped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.environ.get("MODELAUDIT_RUN_HF_REAL_MODEL_TESTS") != "1":
        pytest.skip("set MODELAUDIT_RUN_HF_REAL_MODEL_TESTS=1 to download pinned Hugging Face ONNX models")

    monkeypatch.setenv("PROMPTFOO_DISABLE_TELEMETRY", "1")
    monkeypatch.setenv("HF_HUB_DISABLE_TELEMETRY", "1")
    huggingface_hub = pytest.importorskip("huggingface_hub")
    cache_dir = tmp_path / "hf-cache"
    model_path = Path(
        huggingface_hub.hf_hub_download(
            repo_id=_PINNED_HF_MULTILINGUAL_E5_LARGE,
            revision=_PINNED_HF_MULTILINGUAL_E5_LARGE_REVISION,
            filename=_PINNED_HF_MULTILINGUAL_E5_LARGE_ONNX,
            cache_dir=str(cache_dir),
        )
    )
    assert model_path.stat().st_size <= _PINNED_HF_ONNX_MAX_BYTES

    model = onnx.load(str(model_path), load_external_data=False)
    microsoft_node_count = sum(1 for node in model.graph.node if node.domain == "com.microsoft")
    assert microsoft_node_count == 96

    scanner = OnnxScanner({"check_jit_script": False, "check_network_comm": False, "max_array_size": 1})
    result = scanner.scan(str(model_path))
    metadata = scanner.extract_metadata(str(model_path))

    custom_domain_checks = _failed_custom_domain_checks(result)
    microsoft_domain_checks = [
        check for check in custom_domain_checks if check.details.get("domain") == "com.microsoft"
    ]
    assert len(microsoft_domain_checks) == 1
    assert microsoft_domain_checks[0].details["occurrence_count"] == microsoft_node_count
    assert microsoft_domain_checks[0].details["representative_nodes_truncated"] is True
    assert [check.details["domain"] for check in custom_domain_checks].count("com.microsoft") == 1
    assert result.metadata["custom_domains"] == ["com.microsoft"]
    assert metadata["custom_domains"] == ["com.microsoft"]


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
    assert custom_operator_issues[0].details["overload"] == ""
    assert custom_operator_issues[0].details["operator_identity"] == {
        "domain": "",
        "op_type": "custom_op",
        "overload": "",
    }
    assert "ONNX domain '<default>'" in custom_operator_issues[0].message
    assert "overload '<default>'" in custom_operator_issues[0].message


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
            ("MatMulInteger", np.full((128, 1), 127, dtype=np.int8), "quantized_operator"),
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

    def test_qdq_weight_path_remains_a_clean_quantized_exclusion(self, tmp_path: Path) -> None:
        model_path = create_qdq_weight_model(tmp_path)

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        assert not any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
        semantics = result.metadata["onnx_weight_distribution_semantics"]
        assert semantics["eligible_initializer_count"] == 0
        assert semantics["exclusion_counts"]["quantized_operator"] == 3

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
