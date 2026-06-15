from pathlib import Path
from typing import Any, cast

import pytest

pytest.importorskip("onnx")

import numpy as np
import onnx
from onnx import TensorProto, helper

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.scanners import onnx_scanner as scanner
from modelaudit.scanners.onnx_scanner import OnnxScanner


def _save(model: Any, path: Path, *, checked: bool = True) -> Path:
    if checked:
        onnx.checker.check_model(model)
    onnx.save(model, str(path))
    return path


def _tensor(name: str, values: np.ndarray) -> Any:
    return onnx.numpy_helper.from_array(values, name=name)


def _extreme_int8(malicious: bool) -> np.ndarray:
    weights = np.ones((100, 10), dtype=np.int8)
    if malicious:
        weights[:, 3] = 127
    return weights


def _coverage(result: Any) -> dict[str, Any]:
    return cast(dict[str, Any], result.metadata["onnx_weight_distribution_semantics"])


def _failed_coverage(result: Any) -> None:
    assert result.success is False
    assert any(check.name == "Weight Distribution Analysis Coverage" for check in result.checks)
    assert _coverage(result)["analyzed_initializer_count"] == 0


def _qlinear_matmul(tmp_path: Path, *, malicious: bool, scale_type: int = TensorProto.FLOAT) -> Path:
    weights = _extreme_int8(malicious)
    scale = helper.make_tensor("W_scale", scale_type, [], [1])
    initializers = [
        _tensor("W", weights),
        scale,
        _tensor("W_zero", np.asarray(0, dtype=np.int8)),
        _tensor("X_scale", np.asarray(1, dtype=np.float32)),
        _tensor("X_zero", np.asarray(0, dtype=np.int8)),
        _tensor("Y_scale", np.asarray(1, dtype=np.float32)),
        _tensor("Y_zero", np.asarray(0, dtype=np.int8)),
    ]
    node = helper.make_node(
        "QLinearMatMul",
        ["X", "X_scale", "X_zero", "W", "W_scale", "W_zero", "Y_scale", "Y_zero"],
        ["Y"],
    )
    graph = helper.make_graph(
        [node],
        "qlinear",
        [helper.make_tensor_value_info("X", TensorProto.INT8, [1, 100])],
        [helper.make_tensor_value_info("Y", TensorProto.INT8, [1, 10])],
        initializer=initializers,
    )
    return _save(helper.make_model(graph, opset_imports=[helper.make_opsetid("", 24)]), tmp_path / "q.onnx")


def _matmul_integer_scale_path(tmp_path: Path, *, suffix: str) -> Path:
    initializers = [
        _tensor("W", _extreme_int8(True)),
        _tensor("X_scale", np.asarray(1, dtype=np.float32)),
        _tensor("W_scale", np.asarray([1, 1, 1, 100, 1, 1, 1, 1, 1, 1], dtype=np.float32)),
        _tensor("sqrt2", np.asarray(np.sqrt(2), dtype=np.float32)),
        _tensor("one", np.asarray(1, dtype=np.float32)),
        _tensor("half", np.asarray(0.5, dtype=np.float32)),
    ]
    nodes = [
        helper.make_node("MatMulInteger", ["X", "W"], ["I"]),
        helper.make_node("Cast", ["I"], ["F"], to=TensorProto.FLOAT),
        helper.make_node("Mul", ["F", "X_scale"], ["S"]),
    ]
    inputs = [helper.make_tensor_value_info("X", TensorProto.INT8, [1, 100])]
    current = "S"
    if suffix == "dynamic_add":
        inputs.append(helper.make_tensor_value_info("bias", TensorProto.FLOAT, [1, 10]))
        nodes.append(helper.make_node("Add", [current, "bias"], ["B"]))
        current = "B"
    elif suffix == "dynamic_quantize":
        nodes.append(helper.make_node("DynamicQuantizeLinear", [current], ["Q", "Q_scale", "Q_zero"]))
        nodes.append(helper.make_node("Cast", ["Q"], ["B"], to=TensorProto.FLOAT))
        current = "B"
    elif suffix == "gelu":
        inputs.append(helper.make_tensor_value_info("bias", TensorProto.FLOAT, [1, 10]))
        nodes.extend(
            [
                helper.make_node("Add", [current, "bias"], ["B"]),
                helper.make_node("Div", ["B", "sqrt2"], ["D"]),
                helper.make_node("Erf", ["D"], ["E"]),
                helper.make_node("Add", ["E", "one"], ["E1"]),
                helper.make_node("Mul", ["B", "E1"], ["P"]),
                helper.make_node("Mul", ["P", "half"], ["G"]),
            ]
        )
        current = "G"
    elif suffix == "shape":
        inputs.append(helper.make_tensor_value_info("bias", TensorProto.FLOAT, [1, 10]))
        nodes.extend(
            [
                helper.make_node("Add", [current, "bias"], ["B"]),
                helper.make_node("Shape", ["B"], ["shape"]),
                helper.make_node("Cast", ["shape"], ["shape_f"], to=TensorProto.FLOAT),
                helper.make_node("Mul", ["B", "shape_f"], ["T"]),
            ]
        )
        current = "T"
    nodes.append(helper.make_node("Mul", [current, "W_scale"], ["Y"]))
    graph = helper.make_graph(
        nodes,
        "integer",
        inputs,
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])],
        initializer=initializers,
    )
    return _save(helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)]), tmp_path / f"{suffix}.onnx")


def _blocked_dq(tmp_path: Path) -> Path:
    nodes = [
        helper.make_node("DequantizeLinear", ["W", "scale", "zero"], ["Wf"], axis=1, block_size=2),
        helper.make_node("MatMul", ["X", "Wf"], ["Y"]),
    ]
    graph = helper.make_graph(
        nodes,
        "blocked",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 4])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 4])],
        initializer=[
            _tensor("W", np.ones((4, 4), dtype=np.int8)),
            _tensor("scale", np.ones((4, 2), dtype=np.float32)),
            _tensor("zero", np.zeros((4, 2), dtype=np.int8)),
        ],
    )
    return _save(helper.make_model(graph, opset_imports=[helper.make_opsetid("", 21)]), tmp_path / "blocked.onnx")


@pytest.mark.parametrize("malicious", [False, True], ids=["benign", "malicious"])
def test_qlinear_matmul_quantized_weights_are_analyzed(tmp_path: Path, malicious: bool) -> None:
    result = OnnxScanner().scan(str(_qlinear_matmul(tmp_path, malicious=malicious)))
    assert result.success is True
    assert _coverage(result)["analyzed_initializer_count"] == 1
    assert sum(check.name == "Weight Distribution Anomaly Detection" for check in result.checks) == int(malicious)


def test_float8e8m0_quantized_scale_is_accepted_when_available(tmp_path: Path) -> None:
    data_type = getattr(TensorProto, "FLOAT8E8M0", None)
    if data_type is None:
        pytest.skip("installed ONNX lacks FLOAT8E8M0")
    result = OnnxScanner().scan(str(_qlinear_matmul(tmp_path, malicious=False, scale_type=int(data_type))))
    assert result.success is True
    assert _coverage(result)["analyzed_initializer_count"] == 1


def test_blocked_dequantize_lineage_fails_closed(tmp_path: Path) -> None:
    result = OnnxScanner().scan(str(_blocked_dq(tmp_path)))
    _failed_coverage(result)
    assert _coverage(result)["unresolved_lineage_samples"][0]["reason"] == "blocked_dequantize_lineage_unsupported"


@pytest.mark.parametrize("suffix", ["dynamic_add", "dynamic_quantize", "gelu", "shape"])
def test_live_terminal_descendants_fail_closed(tmp_path: Path, suffix: str) -> None:
    result = OnnxScanner().scan(str(_matmul_integer_scale_path(tmp_path, suffix=suffix)))
    _failed_coverage(result)


def test_scale_expression_repeated_identity_inputs_fail_closed(tmp_path: Path) -> None:
    model = onnx.load(str(_matmul_integer_scale_path(tmp_path, suffix="dynamic_add")))
    model.graph.node[-1].input[1] = "expanded"
    model.graph.node.insert(len(model.graph.node) - 1, helper.make_node("Identity", ["W_scale"] * 32, ["expanded"]))
    result = OnnxScanner().scan(str(_save(model, tmp_path / "repeated.onnx", checked=False)))
    _failed_coverage(result)


def test_typed_field_decoder_reserves_before_decode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    weight = helper.make_tensor("W", TensorProto.FLOAT, [1_000, 1_000], [1.0] * 1_000_000)
    graph = helper.make_graph(
        [helper.make_node("MatMul", ["X", "W"], ["Y"])],
        "typed",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 1_000])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 1_000])],
        initializer=[weight],
    )
    model = helper.make_model(graph)
    decoded = False
    original = onnx.numpy_helper.to_array

    def record(tensor: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal decoded
        decoded = True
        return original(tensor, *args, **kwargs)

    monkeypatch.setattr(onnx.numpy_helper, "to_array", record)
    plan = scanner._build_onnx_weight_analysis_plan(model, onnx=onnx, np=np, max_array_size=8_000_000)
    assert decoded is False
    assert plan.oversized_initializers_skipped == 1


def test_quantized_identifiers_are_bounded(tmp_path: Path) -> None:
    path = _qlinear_matmul(tmp_path, malicious=False)
    model = onnx.load(str(path))
    long_name = "scale_" + "x" * 4096
    for initializer in model.graph.initializer:
        if initializer.name == "W_scale":
            initializer.name = long_name
    model.graph.node[0].input[4] = long_name
    result = OnnxScanner().scan(str(_save(model, tmp_path / "long.onnx")))
    context = _coverage(result)["eligible"][0]
    assert len(context["quantization_scale"]) <= 256
    assert context["quantization_scale_truncated"] is True


def _external_package(tmp_path: Path) -> tuple[Path, Path]:
    sidecar = tmp_path / "weights.bin"
    sidecar.write_bytes(np.ones((100, 10), dtype=np.float32).tobytes())
    weight = onnx.TensorProto()
    weight.name = "W"
    weight.data_type = TensorProto.FLOAT
    weight.dims.extend([100, 10])
    weight.data_location = TensorProto.EXTERNAL
    entry = weight.external_data.add()
    entry.key = "location"
    entry.value = sidecar.name
    graph = helper.make_graph(
        [helper.make_node("MatMul", ["X", "W"], ["Y"])],
        "external",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 100])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 10])],
        initializer=[weight],
    )
    return _save(helper.make_model(graph), tmp_path / "external.onnx", checked=False), sidecar


def test_external_data_race_is_uncached_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path, sidecar = _external_package(tmp_path)
    original = scan_file

    def mutate_before_scan(path: str, config: dict[str, Any]) -> Any:
        sidecar.write_bytes(b"changed")
        return original(path, config)

    monkeypatch.setattr("modelaudit.core.scan_file", mutate_before_scan)
    cache_dir = tmp_path / "cache"
    reset_cache_manager()
    try:
        result = scan_model_directory_or_file(
            str(model_path),
            scanners=["onnx"],
            cache_enabled=True,
            cache_dir=str(cache_dir),
        )
        assert result.success is False
        assert determine_exit_code(result) == 2
        checks = [check for check in result.checks if check.name == "ONNX External Data Stability"]
        assert len(checks) == 1
        assert checks[0].message == "ONNX external-data sources changed during the model scan"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_external_data_scan_does_not_reuse_primary_only_cache(tmp_path: Path) -> None:
    model_path, sidecar = _external_package(tmp_path)
    cache_dir = tmp_path / "cache"
    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(model_path),
            scanners=["onnx"],
            cache_enabled=True,
            cache_dir=str(cache_dir),
        )
        sidecar.write_bytes(np.zeros((100, 10), dtype=np.float32).tobytes())
        second = scan_model_directory_or_file(
            str(model_path),
            scanners=["onnx"],
            cache_enabled=True,
            cache_dir=str(cache_dir),
        )
        assert first.content_hash != second.content_hash
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_external_data_package_hash_matches_file_and_directory_routes(tmp_path: Path) -> None:
    model_path, _sidecar = _external_package(tmp_path)
    direct = scan_model_directory_or_file(str(model_path), scanners=["onnx"])
    directory = scan_model_directory_or_file(str(tmp_path), scanners=["onnx"])
    assert direct.content_hash == directory.content_hash


def test_standalone_weight_distribution_clusters_identical_onnx_exports(tmp_path: Path) -> None:
    first = _qlinear_matmul(tmp_path, malicious=True)
    second = tmp_path / "copy.onnx"
    second.write_bytes(first.read_bytes())
    result = scan_model_directory_or_file(str(tmp_path), scanners=["weight_distribution"])
    anomalies = [issue for issue in result.issues if issue.type == "weight_distribution_check"]
    assert len(anomalies) == 1
    assert anomalies[0].details["cluster_size"] == 2
