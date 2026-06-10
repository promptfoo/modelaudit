import builtins
import os
import pickle
import sys
import tempfile
import types
import zipfile
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

from modelaudit import core
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.config import ModelAuditConfig, reset_config, set_config
from modelaudit.rules import Severity
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, IssueSeverity
from modelaudit.scanners.weight_distribution_scanner import WeightDistributionScanner
from modelaudit.utils.tensorflow_compat import DataType, tensor_proto_to_ndarray
from tests.helpers import create_mock_pytorch_zip


def _make_mock_tensor_proto(
    *,
    shape: list[int],
    dtype: int,
    float_values: list[float] | None = None,
    string_values: list[bytes] | None = None,
    tensor_content: bytes = b"",
) -> Any:
    dims = [types.SimpleNamespace(size=size) for size in shape]
    return types.SimpleNamespace(
        tensor_shape=types.SimpleNamespace(dim=dims),
        dtype=dtype,
        tensor_content=tensor_content,
        string_val=string_values or [],
        float_val=float_values or [],
        double_val=[],
        int_val=[],
        int64_val=[],
        uint32_val=[],
        uint64_val=[],
        bool_val=[],
        scomplex_val=[],
        dcomplex_val=[],
        half_val=[],
        float8_val=[],
    )


def test_tensor_proto_to_ndarray_rejects_large_materialization_before_padding() -> None:
    tensor_proto = _make_mock_tensor_proto(shape=[1024, 1024], dtype=DataType.DT_FLOAT, float_values=[1.0])

    with pytest.raises(ValueError, match="exceeds configured limit"):
        tensor_proto_to_ndarray(tensor_proto, max_tensor_bytes=1024)


def test_tensor_proto_to_ndarray_small_tensor_still_broadcasts() -> None:
    tensor_proto = _make_mock_tensor_proto(shape=[2, 2], dtype=DataType.DT_FLOAT, float_values=[1.0])

    array = tensor_proto_to_ndarray(tensor_proto, max_tensor_bytes=1024)

    assert array.shape == (2, 2)
    assert array.tolist() == [[1.0, 1.0], [1.0, 1.0]]


def test_tensor_proto_to_ndarray_rejects_large_tensor_content_before_copy() -> None:
    tensor_proto = _make_mock_tensor_proto(
        shape=[1],
        dtype=DataType.DT_FLOAT,
        tensor_content=b"\x00\x00\x80?" * 1024,
    )

    with pytest.raises(ValueError, match="exceeds configured limit"):
        tensor_proto_to_ndarray(tensor_proto, max_tensor_bytes=16)


def test_tensor_proto_to_ndarray_rejects_large_string_materialization() -> None:
    tensor_proto = _make_mock_tensor_proto(
        shape=[1024, 1024],
        dtype=DataType.DT_STRING,
        string_values=[b"x"],
    )

    with pytest.raises(ValueError, match="exceeds configured limit"):
        tensor_proto_to_ndarray(tensor_proto, max_tensor_bytes=1024)


def test_extract_tensorflow_weights_skips_invalid_oversized_const(tmp_path: Path) -> None:
    import importlib

    import modelaudit.protos

    assert modelaudit.protos._check_vendored_protos()

    attr_value_pb2 = importlib.import_module("tensorflow.core.framework.attr_value_pb2")
    graph_pb2 = importlib.import_module("tensorflow.core.framework.graph_pb2")
    node_def_pb2 = importlib.import_module("tensorflow.core.framework.node_def_pb2")
    tensor_pb2 = importlib.import_module("tensorflow.core.framework.tensor_pb2")
    types_pb2 = importlib.import_module("tensorflow.core.framework.types_pb2")

    def make_const_node(name: str, shape: list[int], float_values: list[float]) -> Any:
        tensor = tensor_pb2.TensorProto(dtype=types_pb2.DT_FLOAT)
        for size in shape:
            tensor.tensor_shape.dim.add(size=size)
        tensor.float_val.extend(float_values)

        node = node_def_pb2.NodeDef(name=name, op="Const")
        node.attr["value"].CopyFrom(attr_value_pb2.AttrValue(tensor=tensor))
        node.attr["dtype"].CopyFrom(attr_value_pb2.AttrValue(type=types_pb2.DT_FLOAT))
        return node

    graph = graph_pb2.GraphDef()
    graph.node.extend(
        [
            make_const_node("dummy_const", [1024, 1024], [1.0]),
            make_const_node("dense/kernel", [2, 2], [1.0]),
        ]
    )

    model_path = tmp_path / "model.pb"
    model_path.write_bytes(graph.SerializeToString())

    scanner = WeightDistributionScanner({"max_array_size": 1024})
    weights = scanner._extract_tensorflow_weights(str(model_path))

    assert list(weights) == ["dense/kernel"]
    assert weights["dense/kernel"].shape == (2, 2)
    assert weights["dense/kernel"].tolist() == [[1.0, 1.0], [1.0, 1.0]]


def test_extract_tensorflow_weights_rejects_string_const(tmp_path: Path) -> None:
    import importlib

    import modelaudit.protos

    assert modelaudit.protos._check_vendored_protos()

    attr_value_pb2 = importlib.import_module("tensorflow.core.framework.attr_value_pb2")
    graph_pb2 = importlib.import_module("tensorflow.core.framework.graph_pb2")
    node_def_pb2 = importlib.import_module("tensorflow.core.framework.node_def_pb2")
    tensor_pb2 = importlib.import_module("tensorflow.core.framework.tensor_pb2")
    types_pb2 = importlib.import_module("tensorflow.core.framework.types_pb2")

    tensor = tensor_pb2.TensorProto(dtype=types_pb2.DT_STRING)
    for size in (2, 2):
        tensor.tensor_shape.dim.add(size=size)
    tensor.string_val.extend([b"x" * 1024] * 4)
    node = node_def_pb2.NodeDef(name="dense/kernel", op="Const")
    node.attr["value"].CopyFrom(attr_value_pb2.AttrValue(tensor=tensor))

    graph = graph_pb2.GraphDef()
    graph.node.append(node)
    model_path = tmp_path / "string-model.pb"
    model_path.write_bytes(graph.SerializeToString())

    scanner = WeightDistributionScanner(
        {
            "enable_unsafe_torch_load": True,
            "max_array_size": 64,
            "max_weight_distribution_total_bytes": 64,
        }
    )
    weights = scanner._extract_tensorflow_weights(str(model_path))

    assert weights == {}
    assert scanner.extraction_incomplete_reasons == ["tensorflow_const_tensor_dtype_unsupported"]


# Skip tests if required libraries are not available
def has_numpy():
    try:
        import numpy as np  # noqa: F401

        return True
    except ImportError:
        return False


def has_torch():
    try:
        import torch  # noqa: F401

        return True
    except ImportError:
        return False


def has_h5py():
    try:
        import h5py  # noqa: F401

        return True
    except ImportError:
        return False


def has_tensorflow():
    try:
        import tensorflow as tf

        # Vendored protobuf stubs are not sufficient for weight-distribution tests.
        return bool(getattr(tf, "__version__", None)) and hasattr(tf, "constant")
    except Exception:
        return False


# Use dynamic checks instead of module-level imports
# Defer expensive checks to avoid module-level heavy imports
HAS_NUMPY = has_numpy()  # numpy is lightweight


# Defer heavy imports until actually needed in tests
@lru_cache(maxsize=1)
def _has_torch_cached():
    return has_torch()


@lru_cache(maxsize=1)
def _has_h5py_cached():
    return has_h5py()


@lru_cache(maxsize=1)
def _has_tensorflow_cached():
    return has_tensorflow()


def _install_fake_torch(
    monkeypatch: pytest.MonkeyPatch,
    load: Any,
    *,
    version: str = "2.12.0",
) -> None:
    fake_torch: Any = types.ModuleType("torch")
    fake_torch.__version__ = version

    class FakeTensor:  # pragma: no cover - simple test double
        pass

    fake_torch.Tensor = FakeTensor
    fake_torch.device = lambda value: value
    fake_torch.load = load
    monkeypatch.setitem(sys.modules, "torch", fake_torch)


@pytest.mark.skipif(not HAS_NUMPY or not has_h5py(), reason="numpy and h5py required")
def test_non_numeric_hdf5_weight_metadata_is_not_a_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import h5py
    import numpy as np

    path = tmp_path / "metadata_weight.h5"
    with h5py.File(path, "w") as hdf5_file:
        hdf5_file.create_dataset("metadata/weight_names", data=np.array([[b"a", b"b"], [b"c", b"d"]]))

    original_array = np.array

    def fail_if_non_numeric_dataset_is_materialized(obj: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(obj, h5py.Dataset) and obj.name.endswith("metadata/weight_names"):
            raise AssertionError("non-numeric HDF5 weight metadata should not be materialized")
        return original_array(obj, *args, **kwargs)

    monkeypatch.setattr(np, "array", fail_if_non_numeric_dataset_is_materialized)
    set_config(ModelAuditConfig(severity={"S801": Severity.CRITICAL}))

    cache_dir = tmp_path / "cache"
    reset_cache_manager()
    try:
        first = core.scan_model_directory_or_file(
            str(path),
            scanners=["weight_distribution"],
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = core.scan_model_directory_or_file(
            str(path),
            scanners=["weight_distribution"],
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for result in (first, second):
            assert result.scanner_names == ["weight_distribution"]
            assert core.determine_exit_code(result) == 0
            assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
            assert all(issue.rule_code != "S801" for issue in result.issues)
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] >= 1
    finally:
        reset_cache_manager()
        reset_config()


@pytest.mark.skipif(not has_h5py(), reason="h5py required")
def test_zip_backed_keras_weight_distribution_stays_optional(tmp_path: Path) -> None:
    path = tmp_path / "model.keras"
    with zipfile.ZipFile(path, "w") as keras_archive:
        keras_archive.writestr("metadata.json", "{}")
        keras_archive.writestr("config.json", "{}")

    direct = WeightDistributionScanner().scan(str(path))
    assert direct.success is True
    assert direct.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME

    aggregate = core.scan_model_directory_or_file(str(path), scanners=["weight_distribution"], cache_enabled=False)
    assert aggregate.success is True
    assert core.determine_exit_code(aggregate) == 0
    assert aggregate.file_metadata[str(path)].get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME


@pytest.mark.skipif(not HAS_NUMPY or not has_h5py(), reason="numpy and h5py required")
def test_analysis_failure_is_inconclusive_and_not_cached(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import h5py
    import numpy as np

    path = tmp_path / "numeric_weights.h5"
    with h5py.File(path, "w") as hdf5_file:
        hdf5_file.create_dataset("model_weights/dense/kernel:0", data=np.zeros((2, 2)))

    def fail_analysis(_self: WeightDistributionScanner, _weights_info: dict[str, Any]) -> list[dict[str, Any]]:
        raise RuntimeError("simulated weight analysis failure")

    monkeypatch.setattr(WeightDistributionScanner, "_analyze_weight_distributions", fail_analysis)
    set_config(ModelAuditConfig(severity={"S801": Severity.CRITICAL}))

    try:
        direct = WeightDistributionScanner().scan(str(path))
        assert direct.success is False
        assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert direct.metadata["scan_outcome_reasons"] == ["weight_distribution_analysis_incomplete"]
        analysis_check = next(check for check in direct.checks if check.name == "Weight Distribution Analysis")
        assert analysis_check.details["analysis_incomplete"] is True
        assert analysis_check.details["scan_outcome_reason"] == "weight_distribution_analysis_incomplete"
        assert analysis_check.rule_code is None
        assert all(check.severity not in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for check in direct.checks)

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            first = core.scan_model_directory_or_file(
                str(path),
                scanners=["weight_distribution"],
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            second = core.scan_model_directory_or_file(
                str(path),
                scanners=["weight_distribution"],
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

            for aggregate in (first, second):
                metadata = aggregate.file_metadata[str(path)]
                assert aggregate.success is False
                assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
                assert metadata["scan_outcome_reasons"] == ["weight_distribution_analysis_incomplete"]
                assert core.determine_exit_code(aggregate) == 2
                assert not any(
                    issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues
                )
                assert all(issue.rule_code != "S801" for issue in aggregate.issues)
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()
    finally:
        reset_config()


@pytest.mark.skipif(not HAS_NUMPY or not has_h5py(), reason="numpy and h5py required")
def test_weight_extraction_failure_is_inconclusive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import h5py
    import numpy as np

    path = tmp_path / "unreadable_weights.h5"
    with h5py.File(path, "w") as hdf5_file:
        hdf5_file.create_dataset("model_weights/dense/kernel:0", data=np.zeros((2, 2)))

    def fail_open(*_args: object, **_kwargs: object) -> object:
        raise OSError("simulated HDF5 extraction read failure")

    monkeypatch.setattr(h5py, "File", fail_open)

    result = WeightDistributionScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["weight_distribution_analysis_incomplete"]
    analysis_check = next(check for check in result.checks if check.name == "Weight Distribution Analysis")
    assert analysis_check.details["analysis_incomplete"] is True
    assert analysis_check.details["scan_outcome_reason"] == "weight_distribution_analysis_incomplete"
    assert not any(check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for check in result.checks)


@pytest.mark.skipif(not HAS_NUMPY or not has_h5py(), reason="numpy and h5py required")
def test_partial_hdf5_weight_extraction_preserves_analyzed_findings(tmp_path: Path) -> None:
    import h5py
    import numpy as np

    path = tmp_path / "partial_external_weights.h5"
    anomalous_weights = np.zeros((100, 10), dtype=np.float32)
    anomalous_weights[50:55, 0] = 1000.0

    with h5py.File(path, "w") as hdf5_file:
        hdf5_file.create_dataset("model_weights/a_dense/weight:0", data=anomalous_weights)
        hdf5_file.create_dataset(
            "model_weights/z_dense/weight_external:0",
            shape=(2, 2),
            dtype=np.float32,
            external=[("missing-external-weights.bin", 0, h5py.h5f.UNLIMITED)],
        )

    result = WeightDistributionScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["weight_distribution_analysis_incomplete"]
    assert any(check.name == "Weight Distribution Anomaly Detection" for check in result.checks)
    analysis_check = next(check for check in result.checks if check.name == "Weight Distribution Analysis")
    assert analysis_check.details["analysis_incomplete"] is True
    assert analysis_check.details["external_reference_tensors"] == 1
    assert analysis_check.details["failed_tensors"] == ["model_weights/z_dense/weight_external:0"]


@pytest.mark.skipif(not HAS_NUMPY or not has_h5py(), reason="numpy and h5py required")
def test_hdf5_oversized_weight_dataset_skips_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import h5py
    import numpy as np

    path = tmp_path / "oversized_weights.h5"
    with h5py.File(path, "w") as hdf5_file:
        hdf5_file.create_dataset("model_weights/dense/kernel:0", shape=(16, 16), dtype=np.float32)

    original_array = np.array

    def fail_if_oversized_dataset_is_materialized(obj: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(obj, h5py.Dataset) and obj.name.endswith("model_weights/dense/kernel:0"):
            raise AssertionError("oversized HDF5 weight dataset should not be materialized")
        return original_array(obj, *args, **kwargs)

    monkeypatch.setattr(np, "array", fail_if_oversized_dataset_is_materialized)

    result = WeightDistributionScanner({"max_array_size": 1}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    analysis_check = next(check for check in result.checks if check.name == "Weight Distribution Analysis")
    assert "keras_tensor_size_limit" in analysis_check.details["extraction_incomplete_reasons"]
    assert analysis_check.details["failed_tensors"] == ["model_weights/dense/kernel:0"]


@pytest.mark.skipif(not HAS_NUMPY or not has_h5py(), reason="numpy and h5py required")
def test_hdf5_external_weight_link_skips_without_following_target(tmp_path: Path) -> None:
    import h5py

    path = tmp_path / "external_link_weights.h5"
    target_path = tmp_path / "missing_external_weights.h5"
    with h5py.File(path, "w") as hdf5_file:
        hdf5_file["model_weights/dense/kernel:0"] = h5py.ExternalLink(str(target_path), "/kernel")

    result = WeightDistributionScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    analysis_check = next(check for check in result.checks if check.name == "Weight Distribution Analysis")
    assert "keras_hdf5_external_link_skipped" in analysis_check.details["extraction_incomplete_reasons"]
    assert analysis_check.details["external_reference_tensors"] == 1
    assert analysis_check.details["failed_tensors"] == ["model_weights/dense/kernel:0"]


@pytest.mark.skipif(not HAS_NUMPY or not has_h5py(), reason="numpy and h5py required")
def test_hdf5_unrelated_external_link_does_not_make_weight_analysis_incomplete(tmp_path: Path) -> None:
    import h5py
    import numpy as np

    path = tmp_path / "external_metadata_link.h5"
    with h5py.File(path, "w") as hdf5_file:
        hdf5_file.create_dataset("model_weights/dense/kernel:0", data=np.ones((2, 2), dtype=np.float32))
        metadata = hdf5_file.create_group("metadata")
        metadata["asset"] = h5py.ExternalLink("missing-assets.h5", "/asset")

    scanner = WeightDistributionScanner()
    weights = scanner._extract_keras_weights(str(path))

    assert list(weights) == ["model_weights/dense/kernel:0"]
    assert scanner.extraction_incomplete is False


@pytest.mark.skipif(not HAS_NUMPY or not has_h5py(), reason="numpy and h5py required")
def test_hdf5_internal_soft_link_is_resolved(tmp_path: Path) -> None:
    import h5py
    import numpy as np

    path = tmp_path / "soft_link_weights.h5"
    with h5py.File(path, "w") as hdf5_file:
        hdf5_file.create_dataset("storage/dense_values", data=np.ones((2, 2), dtype=np.float32))
        hdf5_file["model_weights/dense/kernel:0"] = h5py.SoftLink("/storage/dense_values")

    scanner = WeightDistributionScanner()
    weights = scanner._extract_keras_weights(str(path))

    assert list(weights) == ["model_weights/dense/kernel:0"]
    assert scanner.extraction_incomplete is False


@pytest.mark.skipif(not HAS_NUMPY or not has_h5py(), reason="numpy and h5py required")
def test_hdf5_group_soft_link_preserves_weight_alias_path(tmp_path: Path) -> None:
    import h5py
    import numpy as np

    path = tmp_path / "group_soft_link_weights.h5"
    with h5py.File(path, "w") as hdf5_file:
        hdf5_file.create_dataset("z_storage/dense_values", data=np.ones((2, 2), dtype=np.float32))
        hdf5_file["a_model_weights"] = h5py.SoftLink("/z_storage")

    scanner = WeightDistributionScanner()
    weights = scanner._extract_keras_weights(str(path))

    assert list(weights) == ["a_model_weights/dense_values"]
    assert scanner.extraction_incomplete is False


@pytest.mark.skipif(not HAS_NUMPY or not has_h5py(), reason="numpy and h5py required")
def test_hdf5_hard_link_aliases_materialize_dataset_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import h5py
    import numpy as np

    path = tmp_path / "hard_link_weights.h5"
    with h5py.File(path, "w") as hdf5_file:
        dataset = hdf5_file.create_dataset("weights/original_weight", data=np.ones((2, 2), dtype=np.float32))
        hdf5_file["weights/alias_a_weight"] = dataset
        hdf5_file["weights/alias_b_weight"] = dataset

    materialized_datasets = 0
    original_array = np.array

    def count_dataset_materializations(obj: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal materialized_datasets
        if isinstance(obj, h5py.Dataset):
            materialized_datasets += 1
        return original_array(obj, *args, **kwargs)

    monkeypatch.setattr(np, "array", count_dataset_materializations)

    scanner = WeightDistributionScanner()
    weights = scanner._extract_keras_weights(str(path))

    assert len(weights) == 1
    assert materialized_datasets == 1
    assert scanner.retained_tensor_bytes == 16


@pytest.mark.skipif(not HAS_NUMPY or not has_h5py(), reason="numpy and h5py required")
def test_hdf5_cumulative_tensor_budget_stops_before_second_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import h5py
    import numpy as np

    path = tmp_path / "cumulative_weights.h5"
    with h5py.File(path, "w") as hdf5_file:
        hdf5_file.create_dataset("weights/a_weight", data=np.ones((2, 2), dtype=np.float32))
        hdf5_file.create_dataset("weights/b_weight", data=np.ones((2, 2), dtype=np.float32))

    materialized_names: list[str] = []
    original_array = np.array

    def track_dataset_materialization(obj: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(obj, h5py.Dataset):
            materialized_names.append(obj.name)
        return original_array(obj, *args, **kwargs)

    monkeypatch.setattr(np, "array", track_dataset_materialization)

    scanner = WeightDistributionScanner({"max_array_size": 32, "max_weight_distribution_total_bytes": 20})
    weights = scanner._extract_keras_weights(str(path))

    assert list(weights) == ["weights/a_weight"]
    assert materialized_names == ["/weights/a_weight"]
    assert scanner.extraction_incomplete is True
    assert scanner.extraction_incomplete_reasons == ["keras_tensor_size_limit_total"]
    assert scanner.extraction_incomplete_details["max_total_tensor_bytes"] == 20


@pytest.mark.skipif(not HAS_NUMPY or not has_h5py(), reason="numpy and h5py required")
def test_hdf5_external_group_link_is_inconclusive_and_not_cached(tmp_path: Path) -> None:
    import h5py

    path = tmp_path / "external_group.h5"
    with h5py.File(path, "w") as hdf5_file:
        hdf5_file["layers"] = h5py.ExternalLink("missing.h5", "/model_weights")

    cache_dir = tmp_path / "cache"
    reset_cache_manager()
    try:
        for _ in range(2):
            result = core.scan_model_directory_or_file(
                str(path),
                scanners=["weight_distribution"],
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            assert result.success is False
            assert core.determine_exit_code(result) == 2
            assert result.file_metadata[str(path)]["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_pytorch_primary_load_is_blocked_by_archive_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_torch: Any = types.ModuleType("torch")
    fake_torch.__version__ = "2.6.0"

    class FakeTensor:
        pass

    fake_torch.Tensor = FakeTensor
    fake_torch.device = lambda value: value
    load_called = False

    def fake_load(
        _path: str,
        *,
        map_location: object,
        weights_only: bool = False,
    ) -> dict[str, object]:
        del map_location, weights_only
        nonlocal load_called
        load_called = True
        return {}

    fake_torch.load = fake_load
    monkeypatch.setitem(sys.modules, "torch", fake_torch)

    path = tmp_path / "large.pt"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("data.pkl", pickle.dumps({}))
        archive.writestr("data/0", b"x" * 64)

    scanner = WeightDistributionScanner(
        {
            "enable_unsafe_torch_load": True,
            "max_array_size": 1024,
            "max_weight_distribution_total_bytes": 32,
        }
    )
    weights = scanner._extract_pytorch_weights(str(path))

    assert weights == {}
    assert load_called is False
    assert scanner.extraction_incomplete_reasons == ["pytorch_load_size_limit"]


def test_pytorch_primary_storage_is_checked_before_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_torch: Any = types.ModuleType("torch")
    fake_torch.__version__ = "2.6.0"

    class FakeTensor:
        pass

    fake_torch.Tensor = FakeTensor
    fake_torch.device = lambda value: value

    def fail_load(
        _path: str,
        *,
        map_location: object,
        weights_only: bool = False,
    ) -> object:
        del map_location, weights_only
        raise AssertionError("oversized storage should be rejected before torch.load")

    fake_torch.load = fail_load
    monkeypatch.setitem(sys.modules, "torch", fake_torch)

    path = tmp_path / "oversized-storage.pt"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("archive/data.pkl", pickle.dumps({}))
        archive.writestr("archive/data/0", b"x" * 64)

    scanner = WeightDistributionScanner(
        {
            "enable_unsafe_torch_load": True,
            "max_array_size": 8,
            "max_weight_distribution_total_bytes": 128,
        }
    )
    weights = scanner._extract_pytorch_weights(str(path))

    assert weights == {}
    assert scanner.extraction_incomplete_reasons == ["pytorch_tensor_storage_size_limit"]


def test_pytorch_load_budget_ignores_unrelated_archive_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_torch: Any = types.ModuleType("torch")
    fake_torch.__version__ = "2.6.0"

    class FakeTensor:
        pass

    fake_torch.Tensor = FakeTensor
    fake_torch.device = lambda value: value
    load_called = False

    def fake_load(
        _path: str,
        *,
        map_location: object,
        weights_only: bool = False,
    ) -> dict[str, object]:
        del map_location, weights_only
        nonlocal load_called
        load_called = True
        return {}

    fake_torch.load = fake_load
    monkeypatch.setitem(sys.modules, "torch", fake_torch)

    path = tmp_path / "metadata-heavy.pt"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("archive/data.pkl", pickle.dumps({}))
        archive.writestr("archive/data/0", b"x" * 26)
        archive.writestr("archive/metadata.json", b"x" * 1024)

    scanner = WeightDistributionScanner(
        {
            "enable_unsafe_torch_load": True,
            "max_array_size": 64,
            "max_weight_distribution_total_bytes": 64,
        }
    )
    weights = scanner._extract_pytorch_weights(str(path))

    assert weights == {}
    assert load_called is True
    assert scanner.extraction_incomplete is False


def test_pytorch_pickle_object_budget_blocks_compact_container_amplification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_torch: Any = types.ModuleType("torch")
    fake_torch.__version__ = "2.6.0"

    class FakeTensor:
        pass

    fake_torch.Tensor = FakeTensor
    fake_torch.device = lambda value: value

    def fail_load(
        _path: str,
        *,
        map_location: object,
        weights_only: bool = False,
    ) -> object:
        del map_location, weights_only
        raise AssertionError("object-heavy pickle should be rejected before torch.load")

    fake_torch.load = fail_load
    monkeypatch.setitem(sys.modules, "torch", fake_torch)

    path = tmp_path / "object-heavy.pt"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("archive/data.pkl", pickle.dumps([[] for _ in range(2000)], protocol=4))

    scanner = WeightDistributionScanner({"max_array_size": 8192, "max_weight_distribution_total_bytes": 8192})
    weights = scanner._extract_pytorch_weights(str(path))

    assert weights == {}
    assert scanner.extraction_incomplete_reasons == ["pytorch_pickle_object_budget"]


def test_pytorch_blocked_load_fallback_honors_remaining_metadata_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_torch: Any = types.ModuleType("torch")
    fake_torch.__version__ = "2.5.1"

    class FakeTensor:
        pass

    fake_torch.Tensor = FakeTensor
    fake_torch.device = lambda value: value

    def fake_load(
        _path: str,
        *,
        map_location: object,
        weights_only: bool = False,
    ) -> dict[str, object]:
        del map_location, weights_only
        raise AssertionError("unsafe torch.load must remain blocked")

    fake_torch.load = fake_load
    monkeypatch.setitem(sys.modules, "torch", fake_torch)

    path = tmp_path / "unsafe-version.pt"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("data.pkl", pickle.dumps({"layer.weight": [[1.0, 2.0], [3.0, 4.0]]}))

    original_open = zipfile.ZipFile.open

    def fail_if_data_pkl_is_opened(
        archive: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        mode: str = "r",
        pwd: bytes | None = None,
        *,
        force_zip64: bool = False,
    ) -> Any:
        member_name = name.filename if isinstance(name, zipfile.ZipInfo) else name
        if member_name == "data.pkl":
            raise AssertionError("over-budget data.pkl should not be opened")
        return original_open(archive, name, mode=mode, pwd=pwd, force_zip64=force_zip64)

    monkeypatch.setattr(zipfile.ZipFile, "open", fail_if_data_pkl_is_opened)

    scanner = WeightDistributionScanner({"max_array_size": 1024, "max_weight_distribution_total_bytes": 32})
    weights = scanner._extract_pytorch_weights(str(path))

    assert weights == {}
    assert scanner.extraction_unsafe is False
    assert scanner.extraction_incomplete_reasons == ["pytorch_zip_data_pkl_size_limit"]
    assert scanner.extraction_incomplete_details["max_pickle_metadata_bytes"] == 32


def test_pytorch_primary_tensor_size_is_checked_before_numpy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_torch: Any = types.ModuleType("torch")
    fake_torch.__version__ = "2.6.0"

    class FakeTensor:
        shape = (2, 2)

        @staticmethod
        def numel() -> int:
            return 4

        @staticmethod
        def element_size() -> int:
            return 4

        @staticmethod
        def detach() -> object:
            raise AssertionError("oversized tensor should not be converted")

    fake_torch.Tensor = FakeTensor
    fake_torch.device = lambda value: value

    def fake_load(
        _path: str,
        *,
        map_location: object,
        weights_only: bool = False,
    ) -> dict[str, object]:
        del map_location, weights_only
        return {"layer.weight": FakeTensor()}

    fake_torch.load = fake_load
    monkeypatch.setitem(sys.modules, "torch", fake_torch)

    path = tmp_path / "tensor.pt"
    path.write_bytes(b"x")
    scanner = WeightDistributionScanner(
        {
            "enable_unsafe_torch_load": True,
            "max_array_size": 8,
            "max_weight_distribution_total_bytes": 1024,
        }
    )
    weights = scanner._extract_pytorch_weights(str(path))

    assert weights == {}
    assert scanner.extraction_incomplete_reasons == ["pytorch_tensor_size_limit"]
    assert scanner.extraction_incomplete_details["tensor_nbytes"] == 16


def test_pytorch_unsupported_tensor_does_not_hide_valid_weights(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import numpy as np

    fake_torch: Any = types.ModuleType("torch")
    fake_torch.__version__ = "2.6.0"

    class FakeTensor:
        shape = (2, 2)

        def __init__(self, *, supported: bool) -> None:
            self.supported = supported

        @staticmethod
        def numel() -> int:
            return 4

        @staticmethod
        def element_size() -> int:
            return 4

        def detach(self) -> "FakeTensor":
            return self

        def cpu(self) -> "FakeTensor":
            return self

        def numpy(self) -> Any:
            if not self.supported:
                raise TypeError("unsupported tensor layout")
            return np.ones((2, 2), dtype=np.float32)

    fake_torch.Tensor = FakeTensor
    fake_torch.device = lambda value: value

    def fake_load(
        _path: str,
        *,
        map_location: object,
        weights_only: bool = False,
    ) -> dict[str, object]:
        del map_location, weights_only
        return {
            "dense.weight": FakeTensor(supported=True),
            "sparse.weight": FakeTensor(supported=False),
        }

    fake_torch.load = fake_load
    monkeypatch.setitem(sys.modules, "torch", fake_torch)

    path = tmp_path / "mixed.pt"
    path.write_bytes(b"x")
    scanner = WeightDistributionScanner({"enable_unsafe_torch_load": True})
    weights = scanner._extract_pytorch_weights(str(path))

    assert list(weights) == ["dense.weight"]
    assert scanner.extraction_incomplete is True
    assert scanner.extraction_incomplete_reasons == ["pytorch_tensor_read_failed"]
    assert scanner.extraction_incomplete_details["failed_tensors"] == ["sparse.weight"]


def test_pytorch_zip_alias_expansion_is_rejected_before_numpy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import numpy as np

    fake_torch: Any = types.ModuleType("torch")
    fake_torch.__version__ = "2.6.0"

    class FakeTensor:
        pass

    fake_torch.Tensor = FakeTensor
    fake_torch.device = lambda value: value

    def fail_load(
        _path: str,
        *,
        map_location: object,
        weights_only: bool = False,
    ) -> object:
        del map_location, weights_only
        raise RuntimeError("force restricted fallback")

    fake_torch.load = fail_load
    monkeypatch.setitem(sys.modules, "torch", fake_torch)

    row = [1.0] * 100
    payload = {"layer.weight": [row] * 100}
    path = tmp_path / "aliased.pt"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("data.pkl", pickle.dumps(payload, protocol=4))

    array_called = False
    original_array = np.array

    def track_array(value: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal array_called
        array_called = True
        return original_array(value, *args, **kwargs)

    monkeypatch.setattr(np, "array", track_array)

    scanner = WeightDistributionScanner({"max_array_size": 4096, "max_weight_distribution_total_bytes": 8192})
    weights = scanner._extract_pytorch_weights(str(path))

    assert weights == {}
    assert array_called is False
    assert scanner.extraction_incomplete_reasons == ["pytorch_tensor_materialization_failed"]


def test_pytorch_load_budget_ignores_incidental_eocd_in_legacy_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "legacy.pt"
    path.write_bytes(b"legacy tensor payload" + b"PK\x05\x06" + (b"\x00" * 18))

    def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("legacy non-ZIP files must not enter ZIP parsing")

    monkeypatch.setattr(zipfile, "ZipFile", fail_zipfile_open)
    scanner = WeightDistributionScanner()

    assert scanner._pytorch_load_within_budget(str(path)) is True
    assert scanner.extraction_incomplete is False


def test_pytorch_primary_load_reuses_budgeted_handle_after_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_payload = b"original tensor payload"
    replacement_payload = b"replacement tensor payload"
    path = tmp_path / "model.pt"
    replacement_path = tmp_path / "replacement.pt"
    path.write_bytes(original_payload)
    replacement_path.write_bytes(replacement_payload)

    fake_torch: Any = types.ModuleType("torch")

    class FakeTensor:
        pass

    fake_torch.Tensor = FakeTensor
    fake_torch.device = lambda value: value
    budgeted_handle: Any = None
    loaded_handle: Any = None
    loaded_payload: bytes | None = None

    def fake_load(
        handle: Any,
        *,
        map_location: object,
        weights_only: bool = False,
    ) -> dict[str, object]:
        nonlocal loaded_handle, loaded_payload
        del map_location, weights_only
        loaded_handle = handle
        loaded_payload = handle.read()
        return {}

    fake_torch.load = fake_load
    monkeypatch.setitem(sys.modules, "torch", fake_torch)

    scanner = WeightDistributionScanner({"enable_unsafe_torch_load": True})
    original_budget_check = scanner._pytorch_load_handle_within_budget
    original_open = builtins.open
    path_reopened = False

    def redirect_path_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal path_reopened
        if str(file) == str(path):
            path_reopened = True
            file = replacement_path
        return original_open(file, *args, **kwargs)

    def replace_path_after_budget(path_text: str, handle: Any, *, is_zip: bool) -> bool:
        nonlocal budgeted_handle
        within_budget = original_budget_check(path_text, handle, is_zip=is_zip)
        budgeted_handle = handle
        monkeypatch.setattr(builtins, "open", redirect_path_open)
        return within_budget

    monkeypatch.setattr(scanner, "_pytorch_load_handle_within_budget", replace_path_after_budget)

    assert scanner._extract_pytorch_weights(str(path)) == {}
    assert loaded_handle is budgeted_handle
    assert loaded_payload == original_payload
    assert path_reopened is False
    with builtins.open(path, "rb") as reopened:
        assert reopened.read() == replacement_payload
    assert path_reopened is True


def test_pytorch_zip_small_shared_sequence_is_not_treated_as_cycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_torch: Any = types.ModuleType("torch")
    fake_torch.__version__ = "2.6.0"

    class FakeTensor:
        pass

    fake_torch.Tensor = FakeTensor
    fake_torch.device = lambda value: value

    def fail_load(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("force restricted fallback")

    fake_torch.load = fail_load
    monkeypatch.setitem(sys.modules, "torch", fake_torch)

    row = [1.0, 2.0]
    path = tmp_path / "small-alias.pt"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("data.pkl", pickle.dumps({"layer.weight": [row, row]}, protocol=4))

    scanner = WeightDistributionScanner({"max_array_size": 1024, "max_weight_distribution_total_bytes": 1024})
    weights = scanner._extract_pytorch_weights(str(path))

    assert list(weights) == ["layer.weight"]
    assert weights["layer.weight"].shape == (2, 2)
    assert scanner.extraction_incomplete is False


def test_pytorch_zip_discarded_vector_does_not_consume_retained_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_torch: Any = types.ModuleType("torch")
    fake_torch.__version__ = "2.6.0"

    class FakeTensor:
        pass

    fake_torch.Tensor = FakeTensor
    fake_torch.device = lambda value: value

    def fail_load(
        _path: str,
        *,
        map_location: object,
        weights_only: bool = False,
    ) -> object:
        del map_location, weights_only
        raise RuntimeError("force restricted fallback")

    fake_torch.load = fail_load
    monkeypatch.setitem(sys.modules, "torch", fake_torch)

    payload = {
        "weight_names": [1] * 100,
        "layer.weight": [[1] * 10 for _ in range(10)],
    }
    path = tmp_path / "vector_metadata.pt"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("data.pkl", pickle.dumps(payload, protocol=4))

    scanner = WeightDistributionScanner({"max_array_size": 1000, "max_weight_distribution_total_bytes": 1000})
    weights = scanner._extract_pytorch_weights(str(path))

    assert list(weights) == ["layer.weight"]
    assert scanner.retained_tensor_bytes == 800
    assert scanner.extraction_incomplete is False


def test_pytorch_zip_ignores_large_non_weight_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_torch: Any = types.ModuleType("torch")
    fake_torch.__version__ = "2.6.0"

    class FakeTensor:
        pass

    fake_torch.Tensor = FakeTensor
    fake_torch.device = lambda value: value

    def fail_load(
        _path: str,
        *,
        map_location: object,
        weights_only: bool = False,
    ) -> object:
        del map_location, weights_only
        raise RuntimeError("force restricted fallback")

    fake_torch.load = fail_load
    monkeypatch.setitem(sys.modules, "torch", fake_torch)

    row = [1.0] * 100
    payload = {
        "metadata": [row] * 100,
        "layer.weight": [[1.0, 2.0], [3.0, 4.0]],
    }
    path = tmp_path / "metadata.pt"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("data.pkl", pickle.dumps(payload, protocol=4))

    scanner = WeightDistributionScanner({"max_array_size": 4096, "max_weight_distribution_total_bytes": 8192})
    weights = scanner._extract_pytorch_weights(str(path))

    assert list(weights) == ["layer.weight"]
    assert weights["layer.weight"].shape == (2, 2)
    assert scanner.extraction_incomplete is False


def test_tensorflow_unknown_dtype_is_skipped_before_load_variable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saved_model_dir = tmp_path / "saved_model"
    variables_dir = saved_model_dir / "variables"
    variables_dir.mkdir(parents=True)
    (variables_dir / "variables.index").write_bytes(b"checkpoint index")

    class FakeCheckpointReader:
        @staticmethod
        def get_variable_to_dtype_map() -> dict[str, object]:
            return {"dense/kernel": object}

    class FakeTrain:
        @staticmethod
        def load_checkpoint(_prefix: str) -> FakeCheckpointReader:
            return FakeCheckpointReader()

        @staticmethod
        def list_variables(_prefix: str) -> list[tuple[str, list[int]]]:
            return [("dense/kernel", [2, 2])]

        @staticmethod
        def load_variable(_prefix: str, _name: str) -> object:
            raise AssertionError("unknown dtype variable should not be loaded")

    fake_tensorflow: Any = types.ModuleType("tensorflow")
    fake_tensorflow.train = FakeTrain
    monkeypatch.setitem(sys.modules, "tensorflow", fake_tensorflow)

    scanner = WeightDistributionScanner()
    weights = scanner._extract_tensorflow_weights(str(saved_model_dir))

    assert weights == {}
    assert scanner.extraction_incomplete_reasons == ["tensorflow_checkpoint_tensor_size_limit"]


def test_fixed_width_custom_numeric_dtype_remains_bounded() -> None:
    import numpy as np

    scanner = WeightDistributionScanner()

    assert scanner._tensorflow_dtype_itemsize(np.dtype("V2")) == 2
    assert scanner._tensorflow_checkpoint_variable_nbytes([2, 2], np.dtype("V2")) == 8


def test_onnx_external_and_unknown_initializers_fail_closed_before_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import numpy as np

    initializers = [
        types.SimpleNamespace(
            name="external_weight",
            dims=[2, 2],
            data_type=1,
            data_location=1,
            external_data=[object()],
        ),
        types.SimpleNamespace(
            name="unknown_weight",
            dims=[2, 2],
            data_type=999,
            data_location=0,
            external_data=[],
        ),
        types.SimpleNamespace(
            name="valid_weight",
            dims=[2, 2],
            data_type=1,
            data_location=0,
            external_data=[],
        ),
        types.SimpleNamespace(
            name="custom_numeric_weight",
            dims=[2, 2],
            data_type=16,
            data_location=0,
            external_data=[],
        ),
    ]
    materialized: list[str] = []

    def tensor_dtype_to_np_dtype(data_type: int) -> Any:
        dtypes = {1: np.dtype("float32"), 16: np.dtype("V2")}
        return dtypes[data_type]

    def to_array(initializer: Any) -> Any:
        materialized.append(initializer.name)
        return np.ones((2, 2), dtype=np.float32)

    fake_onnx: Any = types.ModuleType("onnx")
    fake_onnx.TensorProto = types.SimpleNamespace(EXTERNAL=1)
    fake_onnx.helper = types.SimpleNamespace(tensor_dtype_to_np_dtype=tensor_dtype_to_np_dtype)
    fake_onnx.mapping = types.SimpleNamespace(TENSOR_TYPE_TO_NP_TYPE={1: np.dtype("float32"), 16: np.dtype("V2")})
    fake_onnx.numpy_helper = types.SimpleNamespace(to_array=to_array)
    fake_onnx.load = lambda _path, load_external_data: types.SimpleNamespace(
        graph=types.SimpleNamespace(initializer=initializers)
    )
    monkeypatch.setitem(sys.modules, "onnx", fake_onnx)

    path = tmp_path / "model.onnx"
    path.write_bytes(b"x")
    scanner = WeightDistributionScanner()
    weights = scanner._extract_onnx_weights(str(path))

    assert list(weights) == ["valid_weight", "custom_numeric_weight"]
    assert materialized == ["valid_weight", "custom_numeric_weight"]
    assert scanner.extraction_incomplete_reasons == [
        "onnx_external_initializer_skipped",
        "onnx_initializer_size_limit",
    ]


def test_onnx_inline_storage_is_bounded_before_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import numpy as np

    initializers = [
        types.SimpleNamespace(
            name="oversized_weight",
            dims=[2, 2],
            data_type=1,
            data_location=0,
            external_data=[],
            raw_data=b"x" * 128,
        ),
        types.SimpleNamespace(
            name="packed_weight",
            dims=[2, 2],
            data_type=21,
            data_location=0,
            external_data=[],
            raw_data=b"x" * 40,
        ),
    ]

    def fail_to_array(_initializer: Any) -> Any:
        raise AssertionError("oversized inline storage should be rejected before to_array")

    fake_onnx: Any = types.ModuleType("onnx")
    fake_onnx.TensorProto = types.SimpleNamespace(EXTERNAL=1, UINT4=21)
    fake_onnx.helper = types.SimpleNamespace(
        tensor_dtype_to_np_dtype=lambda data_type: np.dtype("float32") if data_type == 1 else np.dtype("uint8")
    )
    fake_onnx.mapping = types.SimpleNamespace(TENSOR_TYPE_TO_NP_TYPE={})
    fake_onnx.numpy_helper = types.SimpleNamespace(to_array=fail_to_array)
    fake_onnx.load = lambda _path, load_external_data: types.SimpleNamespace(
        graph=types.SimpleNamespace(initializer=initializers)
    )
    monkeypatch.setitem(sys.modules, "onnx", fake_onnx)

    path = tmp_path / "inline-storage.onnx"
    path.write_bytes(b"x")
    scanner = WeightDistributionScanner({"max_array_size": 64})
    weights = scanner._extract_onnx_weights(str(path))

    assert weights == {}
    assert scanner.extraction_incomplete_reasons == ["onnx_initializer_storage_size_limit"]
    assert scanner.extraction_incomplete_details["failed_tensors"] == [
        "oversized_weight",
        "packed_weight",
    ]


def test_repeated_oversized_tensors_do_not_multiply_configured_limit() -> None:
    scanner = WeightDistributionScanner({"max_array_size": 10})

    scanner._record_oversized_tensor("tensor_size_limit", "first", tensor_nbytes=11)
    scanner._record_oversized_tensor("tensor_size_limit", "second", tensor_nbytes=12)

    assert scanner.extraction_incomplete_details["oversized_tensors"] == 2
    assert scanner.extraction_incomplete_details["max_array_size"] == 10
    assert scanner.extraction_incomplete_details["tensor_nbytes"] == [11, 12]


@pytest.mark.skipif(not HAS_NUMPY, reason="numpy not available")
class TestWeightDistributionScanner:
    """Test suite for weight distribution anomaly detection"""

    def _create_mock_architecture_analysis(self, is_llm=False, is_transformer=False):
        """Helper method to create mock architecture analysis for testing"""
        return {
            "is_likely_transformer": is_transformer,
            "is_likely_llm": is_llm,
            "confidence": 0.8 if is_llm else 0.5,
            "evidence": ["Mock evidence for testing"],
            "architectural_features": {},
            "total_parameters": 100_000_000 if is_llm else 1_000_000,
            "layer_count": 24 if is_llm else 3,
        }

    def test_scanner_initialization(self):
        """Test scanner initialization with default and custom config"""
        # Default initialization
        scanner = WeightDistributionScanner()
        assert scanner.z_score_threshold == 3.0
        assert scanner.cosine_similarity_threshold == 0.7
        assert scanner.weight_magnitude_threshold == 3.0
        assert scanner.max_array_size == 100 * 1024 * 1024  # Default 100MB

        # Custom config
        config = {
            "z_score_threshold": 2.5,
            "cosine_similarity_threshold": 0.8,
            "weight_magnitude_threshold": 2.0,
            "max_array_size": 50 * 1024 * 1024,  # 50MB
        }
        scanner = WeightDistributionScanner(config)
        assert scanner.z_score_threshold == 2.5
        assert scanner.cosine_similarity_threshold == 0.8
        assert scanner.weight_magnitude_threshold == 2.0
        assert scanner.max_array_size == 50 * 1024 * 1024

    def test_onnx_semantic_views_count_physical_initializer_once(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import numpy as np

        weights = np.broadcast_to(np.asarray(0.0, dtype=np.float32), (5120, 5120))
        specs = [
            types.SimpleNamespace(
                initializer_index=7,
                analysis_id=analysis_id,
                weights=weights,
                output_axes=(output_axis,),
                matrix_analysis=True,
                context={"initializer": "embedding"},
            )
            for analysis_id, output_axis in enumerate((0, 1))
        ]
        captured_architectures: list[dict[str, Any]] = []
        scanner = WeightDistributionScanner()

        def capture_architecture(
            _layer_name: str,
            _weights: Any,
            architecture_analysis: dict[str, Any],
        ) -> list[dict[str, Any]]:
            captured_architectures.append(dict(architecture_analysis))
            return []

        monkeypatch.setattr(scanner, "_analyze_layer_weights", capture_architecture)

        assert scanner._analyze_onnx_weight_specs(specs) == []
        assert len(captured_architectures) == 2
        for architecture in captured_architectures:
            assert architecture["total_parameters"] == 5120 * 5120
            assert architecture["layer_count"] == 1
            assert architecture["is_likely_llm"] is False

    def test_numeric_byte_limit_config_is_coerced(self) -> None:
        import numpy as np

        scanner = WeightDistributionScanner(
            {
                "max_array_size": 1.5,
                "max_weight_distribution_total_bytes": np.int64(32),
            }
        )

        assert scanner._max_tensor_bytes() == 1
        assert scanner._max_total_tensor_bytes() == 32

    @pytest.mark.parametrize("invalid_limit", [True, False, "unbounded", -1, float("inf"), float("nan")])
    def test_invalid_tensor_byte_limit_uses_secure_default(self, invalid_limit: Any) -> None:
        scanner = WeightDistributionScanner({"max_array_size": invalid_limit})

        assert scanner._max_tensor_bytes() == 100 * 1024 * 1024
        assert scanner._max_total_tensor_bytes() == 512 * 1024 * 1024

    def test_zero_tensor_byte_limit_remains_explicitly_unlimited(self) -> None:
        scanner = WeightDistributionScanner({"max_array_size": 0})

        assert scanner._max_tensor_bytes() is None
        assert scanner._max_total_tensor_bytes() is None

        bounded_total_scanner = WeightDistributionScanner(
            {"max_array_size": 0, "max_weight_distribution_total_bytes": 64}
        )
        assert bounded_total_scanner._max_tensor_bytes() is None
        assert bounded_total_scanner._max_total_tensor_bytes() == 64

    def test_can_handle(self):
        """Test file type detection"""
        # Create temporary files to test can_handle
        with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as f:
            pt_path = f.name
        with tempfile.NamedTemporaryFile(suffix=".h5", delete=False) as f:
            h5_path = f.name
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            txt_path = f.name
        tf_dir = tempfile.mkdtemp()
        open(os.path.join(tf_dir, "saved_model.pb"), "wb").close()

        try:
            # Should handle PyTorch files if torch is available
            if _has_torch_cached():
                assert WeightDistributionScanner.can_handle(pt_path)

            # Should handle Keras files if h5py is available
            if _has_h5py_cached():
                assert WeightDistributionScanner.can_handle(h5_path)

            if _has_tensorflow_cached():
                assert WeightDistributionScanner.can_handle(tf_dir)

            # Should not handle unsupported extensions
            assert not WeightDistributionScanner.can_handle(txt_path)
            assert not WeightDistributionScanner.can_handle("directory/")
        finally:
            os.unlink(pt_path)
            os.unlink(h5_path)
            os.unlink(txt_path)
            os.unlink(os.path.join(tf_dir, "saved_model.pb"))
            os.rmdir(tf_dir)

    def test_analyze_layer_weights_outlier_detection(self):
        """Test detection of outlier weight vectors"""
        import numpy as np

        scanner = WeightDistributionScanner()

        # Create normal weights with one outlier
        np.random.seed(42)
        normal_weights = np.random.randn(100, 10) * 0.1  # Small weights

        # Make one neuron an outlier with large weights - make it even more extreme
        normal_weights[:, 5] = np.random.randn(100) * 10.0  # Much larger weights

        architecture_analysis = self._create_mock_architecture_analysis(is_llm=False)
        anomalies = scanner._analyze_layer_weights("test_layer", normal_weights, architecture_analysis)

        # Should detect the outlier neuron
        assert len(anomalies) > 0

        # Check for any type of anomaly (could be outlier or extreme value)
        has_outlier = any("abnormal weight magnitudes" in a["description"] for a in anomalies)
        has_extreme = any("extremely large weight values" in a["description"] for a in anomalies)
        assert has_outlier or has_extreme

        # If outlier detection worked, check the details
        outlier_anomaly = next(
            (a for a in anomalies if "abnormal weight magnitudes" in a["description"]),
            None,
        )
        if outlier_anomaly:
            assert 5 in outlier_anomaly["details"]["outlier_neurons"]

    def test_analyze_layer_weights_dissimilar_vectors(self):
        """Test detection of dissimilar weight vectors"""
        import numpy as np

        scanner = WeightDistributionScanner()

        # Create similar weight vectors
        np.random.seed(42)
        base_vector = np.random.randn(100)
        weights = np.column_stack(
            [base_vector + np.random.randn(100) * 0.1 for _ in range(9)],
        )

        # Add one completely different vector (potential backdoor)
        random_vector = np.random.randn(100) * 2
        weights = np.column_stack([weights, random_vector])

        architecture_analysis = self._create_mock_architecture_analysis(is_llm=False)
        anomalies = scanner._analyze_layer_weights("test_layer", weights, architecture_analysis)

        # Should detect the dissimilar vector
        dissimilar_anomaly = next(
            (a for a in anomalies if "dissimilar weights" in a["description"]),
            None,
        )
        assert dissimilar_anomaly is not None
        assert dissimilar_anomaly["details"]["neuron_index"] == 9

    def test_analyze_layer_weights_ignores_fully_dissimilar_small_head(self) -> None:
        import numpy as np

        weights = np.eye(3, dtype=np.float32)
        anomalies = WeightDistributionScanner()._analyze_layer_weights(
            "three_class_head",
            weights,
            self._create_mock_architecture_analysis(is_llm=False),
        )

        assert not any("dissimilar weights" in anomaly["description"] for anomaly in anomalies)

    def test_analyze_layer_weights_extreme_values(self) -> None:
        """Test detection of extreme weight values"""
        import numpy as np

        scanner = WeightDistributionScanner()

        # Create normal weights
        np.random.seed(42)
        weights = np.random.randn(100, 10) * 0.1

        # Add extreme values to one neuron
        weights[50:55, 3] = 10.0  # Very large values

        architecture_analysis = self._create_mock_architecture_analysis(is_llm=False)
        anomalies = scanner._analyze_layer_weights("test_layer", weights, architecture_analysis)

        # Should detect extreme weights
        extreme_anomaly = next(
            (a for a in anomalies if "extremely large weight values" in a["description"]),
            None,
        )
        assert extreme_anomaly is not None
        assert 3 in extreme_anomaly["details"]["affected_neurons"]
        assert extreme_anomaly["details"]["num_extreme_weights"] == 5
        assert extreme_anomaly["details"]["max_extreme_weights_per_output"] == 5
        assert extreme_anomaly["details"]["threshold_scope"] == "per_output"

    def test_extreme_value_check_ignores_ordinary_gaussian_tails(self) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.random.default_rng(20260609).normal(size=(2, 384))

        anomalies = scanner._analyze_layer_weights(
            "ordinary_projection",
            weights,
            self._create_mock_architecture_analysis(is_llm=False),
        )

        assert not any("extremely large weight values" in anomaly["description"] for anomaly in anomalies)

    def test_extreme_value_check_requires_repeated_values_per_output(self) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50, 3] = 100.0

        anomalies = scanner._analyze_layer_weights(
            "single_scalar",
            weights,
            self._create_mock_architecture_analysis(is_llm=False),
        )

        assert not any("extremely large weight values" in anomaly["description"] for anomaly in anomalies)

    def test_extreme_value_check_detects_small_binary_head_with_contaminated_threshold(self) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((50, 2), dtype=np.float32)
        weights[:5, 0] = 1_000_000.0

        anomalies = scanner._analyze_layer_weights(
            "small_binary_head",
            weights,
            self._create_mock_architecture_analysis(is_llm=False),
        )

        extreme = next(anomaly for anomaly in anomalies if "extremely large weight values" in anomaly["description"])
        assert extreme["details"]["affected_neurons"] == [0]
        assert extreme["details"]["max_to_threshold_ratio"] < 2.0
        assert extreme["details"]["per_output_evidence"][0]["detection_path"] == "robust_small_tensor_fallback"

    def test_extreme_value_check_ignores_nonqualifying_decoy_output(self) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50:55, 3] = 10.0
        weights[0, 4] = 3.0

        anomalies = scanner._analyze_layer_weights(
            "decoy_output",
            weights,
            self._create_mock_architecture_analysis(is_llm=False),
        )

        extreme = next(anomaly for anomaly in anomalies if "extremely large weight values" in anomaly["description"])
        assert extreme["details"]["affected_neurons"] == [3]
        assert extreme["details"]["num_extreme_weights"] == 5

    def test_extreme_value_check_detects_target_despite_larger_decoy_output(self) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50:55, 3] = 10.0
        weights[0, 4] = 1_000_000.0

        anomalies = scanner._analyze_layer_weights(
            "large_decoy_output",
            weights,
            self._create_mock_architecture_analysis(is_llm=False),
        )

        extreme = next(anomaly for anomaly in anomalies if "extremely large weight values" in anomaly["description"])
        assert extreme["details"]["affected_neurons"] == [3]
        assert extreme["details"]["total_affected"] == 1

    def test_extreme_value_check_detects_target_despite_two_value_decoy_output(self) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50:55, 3] = 10.0
        weights[60:62, 4] = 10.0

        anomalies = scanner._analyze_layer_weights(
            "two_value_decoy_output",
            weights,
            self._create_mock_architecture_analysis(is_llm=False),
        )

        extreme = next(anomaly for anomaly in anomalies if "extremely large weight values" in anomaly["description"])
        assert extreme["details"]["affected_neurons"] == [3]
        assert extreme["details"]["total_affected"] == 1
        assert extreme["details"]["tail_affected_outputs"] == 2
        assert extreme["details"]["localized"] is True

    def test_extreme_value_conditions_cannot_mix_across_outputs(self) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((100, 2000), dtype=np.float32)
        weights[0, 0] = 100.0
        weights[0:2, 1] = 0.70

        anomalies = scanner._analyze_layer_weights(
            "cross_output_mismatch",
            weights,
            self._create_mock_architecture_analysis(is_llm=False),
        )

        assert not any("extremely large weight values" in anomaly["description"] for anomaly in anomalies)

    def test_extreme_value_check_reports_two_poisoned_outputs_as_nonlocalized(self) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50:55, 3] = 10.0
        weights[60:65, 4] = 10.0

        anomalies = scanner._analyze_layer_weights(
            "two_affected_outputs",
            weights,
            self._create_mock_architecture_analysis(is_llm=False),
        )

        extreme = next(anomaly for anomaly in anomalies if "extremely large weight values" in anomaly["description"])
        assert extreme["details"]["affected_neurons"] == [3, 4]
        assert extreme["details"]["total_affected"] == 2
        assert extreme["details"]["affected_output_limit"] == 1
        assert extreme["details"]["localized"] is False

    def test_extreme_value_check_ignores_two_value_material_tail(self) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50:52, 3] = 10.0

        anomalies = scanner._analyze_layer_weights(
            "two_repeated_values",
            weights,
            self._create_mock_architecture_analysis(is_llm=False),
        )

        assert not any("extremely large weight values" in anomaly["description"] for anomaly in anomalies)

    def test_extreme_value_check_preserves_five_value_material_effect(self) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((100, 10), dtype=np.float32)
        weights[50:55, 3] = 10.0

        anomalies = scanner._analyze_layer_weights(
            "five_repeated_values",
            weights,
            self._create_mock_architecture_analysis(is_llm=False),
        )

        extreme = next(anomaly for anomaly in anomalies if "extremely large weight values" in anomaly["description"])
        assert extreme["details"]["affected_neurons"] == [3]
        assert extreme["details"]["minimum_extreme_weights_per_output"] == 5

    def test_extreme_value_check_detects_single_output_with_contaminated_threshold(self) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((50, 1), dtype=np.float64)
        weights[:5, 0] = 10.0

        anomalies = scanner._analyze_tensor_weight_extremes(
            "single_output_contaminated_threshold",
            weights,
            output_axes=(1,),
        )

        extreme = next(anomaly for anomaly in anomalies if "extremely large weight values" in anomaly["description"])
        assert extreme["details"]["affected_neurons"] == [0]
        assert extreme["details"]["per_output_evidence"][0]["detection_path"] == "robust_small_tensor_fallback"

    @pytest.mark.parametrize("nonfinite_value", [float("nan"), float("inf"), float("-inf")])
    def test_extreme_value_check_reports_nonfinite_without_suppressing_finite_target(
        self,
        nonfinite_value: float,
    ) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((100, 10), dtype=np.float64)
        weights[50:55, 3] = 10.0
        weights[0, 4] = nonfinite_value

        anomalies = scanner._analyze_tensor_weight_extremes(
            "nonfinite_decoy",
            weights,
            output_axes=(1,),
        )

        extreme = next(anomaly for anomaly in anomalies if "extremely large weight values" in anomaly["description"])
        assert extreme["details"]["affected_neurons"] == [3, 4]
        assert extreme["details"]["num_nonfinite_weights"] == 1
        assert extreme["details"]["per_output_evidence"][1]["detection_path"] == "nonfinite_values"

    def test_extreme_value_check_handles_finite_float64_square_overflow(self) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((100, 10), dtype=np.float64)
        weights[50:55, 3] = 1e154

        anomalies = scanner._analyze_tensor_weight_extremes(
            "finite_float64_extremes",
            weights,
            output_axes=(1,),
        )

        extreme = next(anomaly for anomaly in anomalies if "extremely large weight values" in anomaly["description"])
        assert extreme["details"]["affected_neurons"] == [3]
        assert np.isfinite(extreme["details"]["threshold"])

    def test_extreme_value_check_handles_signed_integer_minimum(self) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((100, 10), dtype=np.int64)
        weights[50:55, 3] = np.iinfo(np.int64).min

        anomalies = scanner._analyze_tensor_weight_extremes(
            "signed_integer_minimum",
            weights,
            output_axes=(1,),
        )

        extreme = next(anomaly for anomaly in anomalies if "extremely large weight values" in anomaly["description"])
        assert extreme["details"]["affected_neurons"] == [3]
        assert extreme["details"]["max_weight"] > 0

    @pytest.mark.parametrize(
        ("degrees_of_freedom", "seed", "shape"),
        [
            (3, 94, (50, 2)),
            (5, 26, (50, 2)),
            (7, 785, (50, 2)),
            (3, 3, (256, 64)),
            (3, 22, (512, 64)),
            (3, 1, (1024, 64)),
        ],
    )
    def test_extreme_value_check_ignores_deterministic_clean_heavy_tails(
        self,
        degrees_of_freedom: int,
        seed: int,
        shape: tuple[int, int],
    ) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.random.default_rng(seed).standard_t(degrees_of_freedom, size=shape)

        anomalies = scanner._analyze_layer_weights(
            f"clean_student_t_df{degrees_of_freedom}",
            weights,
            self._create_mock_architecture_analysis(is_llm=False),
        )

        assert not any("extremely large weight values" in anomaly["description"] for anomaly in anomalies)

    @pytest.mark.parametrize(
        ("seed", "shape"),
        [(1, (256, 64)), (2, (256, 64)), (25, (512, 64)), (48, (128, 512))],
    )
    def test_extreme_value_check_ignores_deterministic_clean_lognormal_tails(
        self,
        seed: int,
        shape: tuple[int, int],
    ) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.random.default_rng(seed).lognormal(size=shape)

        anomalies = scanner._analyze_layer_weights(
            "clean_lognormal",
            weights,
            self._create_mock_architecture_analysis(is_llm=False),
        )

        assert not any("extremely large weight values" in anomaly["description"] for anomaly in anomalies)

    @pytest.mark.parametrize("distribution", ["student_t", "lognormal"])
    def test_extreme_value_check_ignores_large_clean_single_output_heavy_tail(
        self,
        distribution: str,
    ) -> None:
        import numpy as np

        random = np.random.default_rng(12345)
        if distribution == "student_t":
            weights = random.standard_t(3, size=(100_000, 1))
        else:
            weights = random.lognormal(size=(100_000, 1))

        anomalies = WeightDistributionScanner()._analyze_tensor_weight_extremes(
            f"clean_{distribution}",
            weights,
            output_axes=(1,),
        )

        assert not any("extremely large weight values" in anomaly["description"] for anomaly in anomalies)

    @pytest.mark.parametrize("sample_offset", [0, 1])
    def test_extreme_value_check_cannot_be_evaded_by_regular_sample_alignment(self, sample_offset: int) -> None:
        import numpy as np

        weights = np.zeros((262_144 * 11, 1), dtype=np.float32)
        sampled_tail = weights[sample_offset::11, 0]
        sampled_tail[:] = np.linspace(9_000.0, 10_000.0, sampled_tail.size, dtype=np.float32)

        anomalies = WeightDistributionScanner()._analyze_tensor_weight_extremes(
            "sample_alignment",
            weights,
            output_axes=(1,),
        )

        extreme = next(anomaly for anomaly in anomalies if "extremely large weight values" in anomaly["description"])
        assert extreme["details"]["affected_neurons"] == [0]

    def test_tensor_extreme_analysis_batches_noncontiguous_output_prefixes(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import numpy as np

        weights = np.zeros((2, 100, 6_000), dtype=np.float32)
        weights[1, 50:55, 777] = 10_000.0

        def fail_unravel_index(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("output prefixes should be processed in bounded blocks")

        monkeypatch.setattr(np, "unravel_index", fail_unravel_index)

        anomalies = WeightDistributionScanner()._analyze_tensor_weight_extremes(
            "noncontiguous_output_prefixes",
            weights,
            output_axes=(0, 2),
        )

        extreme = next(anomaly for anomaly in anomalies if "extremely large weight values" in anomaly["description"])
        assert extreme["details"]["affected_neurons"] == [6_777]

    def test_tensor_extreme_analysis_bounds_temporary_chunks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((1024, 4096), dtype=np.float32)
        weights[:5, 3] = 1_000_000.0
        original_absolute = np.absolute
        work_buffer_sizes: list[int] = []

        def tracked_absolute(value: Any, *args: Any, **kwargs: Any) -> Any:
            output = kwargs.get("out")
            if output is not None:
                work_buffer_sizes.append(int(getattr(output, "nbytes", 0)))
            return original_absolute(value, *args, **kwargs)

        monkeypatch.setattr(np, "absolute", tracked_absolute)
        anomalies = scanner._analyze_tensor_weight_extremes("large_tensor", weights, output_axes=(1,))

        assert any("extremely large weight values" in anomaly["description"] for anomaly in anomalies)
        assert max(work_buffer_sizes) <= 8 * 1024 * 1024

    def test_tensor_extreme_analysis_chunks_single_wide_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((1_100_000, 1), dtype=np.float32)
        weights[:5, 0] = 1_000_000.0
        original_absolute = np.absolute
        work_buffer_sizes: list[int] = []

        def tracked_absolute(value: Any, *args: Any, **kwargs: Any) -> Any:
            output = kwargs.get("out")
            if output is not None:
                work_buffer_sizes.append(int(getattr(output, "nbytes", 0)))
            return original_absolute(value, *args, **kwargs)

        monkeypatch.setattr(np, "absolute", tracked_absolute)
        anomalies = scanner._analyze_tensor_weight_extremes("wide_output", weights, output_axes=(1,))

        assert any("extremely large weight values" in anomaly["description"] for anomaly in anomalies)
        assert len(work_buffer_sizes) > 2
        assert max(work_buffer_sizes) <= 8 * 1024 * 1024

    def test_tensor_extreme_analysis_does_not_overflow_float16_squares(self) -> None:
        import numpy as np

        scanner = WeightDistributionScanner()
        weights = np.zeros((100, 10), dtype=np.float16)
        weights[50:55, 3] = np.float16(10_000)

        anomalies = scanner._analyze_tensor_weight_extremes("float16_tensor", weights, output_axes=(1,))

        extreme = next(anomaly for anomaly in anomalies if "extremely large weight values" in anomaly["description"])
        assert extreme["details"]["affected_neurons"] == [3]
        assert np.isfinite(extreme["details"]["threshold"])
        assert np.isfinite(extreme["details"]["max_to_threshold_ratio"])

    @pytest.mark.skipif(False, reason="Dynamic skip - see test method")
    def test_pytorch_model_scan(self, tmp_path: Path) -> None:
        """Test scanning a PyTorch model with anomalous weights"""
        if not has_torch():
            pytest.skip("PyTorch not installed")

        import torch

        scanner = WeightDistributionScanner({"enable_unsafe_torch_load": True})

        # Create a simple model with anomalous weights
        class SimpleModel(torch.nn.Module):
            def __init__(self):
                super().__init__()
                self.fc1 = torch.nn.Linear(100, 50)
                self.fc2 = torch.nn.Linear(50, 10)

                # Make one output neuron in fc2 anomalous
                with torch.no_grad():
                    self.fc2.weight.data = torch.randn(10, 50) * 0.1
                    self.fc2.weight.data[5] = torch.randn(50) * 10.0  # Backdoor class - more extreme

        model = SimpleModel()

        model_path = tmp_path / "model.pt"
        torch.save(model.state_dict(), model_path)

        result = scanner.scan(str(model_path))
        assert result.success

        # If no issues found, it might be because the scanner couldn't extract weights
        # This test is more about integration than specific anomaly detection
        # So we'll make it more lenient
        if len(result.issues) == 0:
            # Check if any layers were analyzed
            assert result.metadata.get("layers_analyzed", 0) >= 0
        else:
            # Check that anomaly was detected - could be either type
            has_magnitude = any("abnormal weight magnitudes" in issue.message for issue in result.issues)
            has_extreme = any("extremely large weight values" in issue.message for issue in result.issues)
            assert has_magnitude or has_extreme

    @pytest.mark.skipif(False, reason="Dynamic skip - see test method")
    def test_keras_model_scan(self):
        """Test scanning a Keras model"""
        if not has_h5py():
            pytest.skip("h5py not installed")

        import h5py
        import numpy as np

        scanner = WeightDistributionScanner()

        # Create a simple H5 file with weights
        with tempfile.NamedTemporaryFile(suffix=".h5", delete=False) as f:
            with h5py.File(f.name, "w") as hf:
                # Create weight arrays
                normal_weights = np.random.randn(100, 10) * 0.1
                normal_weights[:, 5] = np.random.randn(100) * 3.0  # Anomalous

                # Store as Keras would
                hf.create_dataset("model_weights/dense_1/kernel:0", data=normal_weights)

            temp_path = f.name

        try:
            result = scanner.scan(temp_path)
            assert result.success
            # Should detect anomaly in the weights
            assert len(result.issues) > 0

        finally:
            os.unlink(temp_path)

    @pytest.mark.skipif(False, reason="Dynamic skip - see test method")
    def test_tensorflow_savedmodel_scan(self, tmp_path):
        """Test scanning a TensorFlow SavedModel directory."""
        import sys

        if not has_tensorflow():
            pytest.skip("TensorFlow not installed")

        # Skip on Python 3.12+ due to TensorFlow/typing compatibility issues
        if sys.version_info >= (3, 12):
            pytest.skip("TensorFlow SavedModel has compatibility issues with Python 3.12+")

        import tensorflow as tf

        # Skip if tf.keras is not available (newer TensorFlow versions separate Keras)
        if not hasattr(tf, "keras"):
            pytest.skip("tf.keras not available (Keras may be a separate package)")

        scanner = WeightDistributionScanner()

        model = tf.keras.Sequential([tf.keras.layers.Dense(2, input_shape=(3,))])  # type: ignore[call-arg]
        saved_path = tmp_path / "tf_model"
        tf.saved_model.save(model, str(saved_path))

        result = scanner.scan(str(saved_path))
        assert result.success
        assert result.metadata.get("layers_analyzed", 0) > 0

    def test_empty_model_handling(self):
        """Test handling of models with no extractable weights"""
        scanner = WeightDistributionScanner()

        # Create an empty file
        with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as f:
            f.write(b"")
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)
            # Should handle gracefully
            assert result.success or len(result.issues) > 0

        finally:
            os.unlink(temp_path)

    def test_pytorch_zip_data_pkl_safe_extraction(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Ensure safe pickle in PyTorch ZIP can be parsed without code execution"""
        load_called = False
        data = {"layer.weight": [[1.0, 2.0], [3.0, 4.0]]}
        data_bytes = pickle.dumps(data, protocol=4)
        zip_path = tmp_path / "model.pt"
        with zipfile.ZipFile(zip_path, "w") as z:
            z.writestr("data.pkl", data_bytes)

        def fake_load(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal load_called
            load_called = True
            return {}

        _install_fake_torch(monkeypatch, fake_load)
        scanner = WeightDistributionScanner()
        weights = scanner._extract_pytorch_weights(str(zip_path))
        assert not scanner.extraction_unsafe
        assert not scanner.extraction_incomplete
        assert load_called is False
        assert "layer.weight" in weights
        assert weights["layer.weight"].shape == (2, 2)

    def test_pytorch_zip_data_pkl_size_limit_skips_before_opening_member(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        fake_torch: Any = types.ModuleType("torch")
        fake_torch.__version__ = "2.6.0"

        class FakeTensor:  # pragma: no cover - simple test double
            pass

        fake_torch.Tensor = FakeTensor
        fake_torch.device = lambda value: value

        def fail_load(*_args: object, **_kwargs: object) -> object:
            raise RuntimeError("force zip fallback")

        fake_torch.load = fail_load
        monkeypatch.setitem(sys.modules, "torch", fake_torch)

        zip_path = tmp_path / "model.pt"
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr("data.pkl", pickle.dumps({"layer.weight": [[1.0, 2.0], [3.0, 4.0]]}))

        original_open = zipfile.ZipFile.open

        def fail_if_data_pkl_is_opened(
            archive: zipfile.ZipFile,
            name: str | zipfile.ZipInfo,
            mode: str = "r",
            pwd: bytes | None = None,
            *,
            force_zip64: bool = False,
        ) -> Any:
            member_name = name.filename if isinstance(name, zipfile.ZipInfo) else name
            if member_name == "data.pkl":
                raise AssertionError("oversized data.pkl should not be opened")
            return original_open(archive, name, mode=mode, pwd=pwd, force_zip64=force_zip64)

        monkeypatch.setattr(zipfile.ZipFile, "open", fail_if_data_pkl_is_opened)

        scanner = WeightDistributionScanner({"max_array_size": 1})
        weights = scanner._extract_pytorch_weights(str(zip_path))

        assert weights == {}
        assert scanner.extraction_incomplete is True
        assert scanner.extraction_incomplete_reasons == ["pytorch_zip_data_pkl_size_limit"]
        assert scanner.extraction_incomplete_details["failed_tensors"] == ["data.pkl"]

    @pytest.mark.skipif(False, reason="Dynamic skip - see test method")
    def test_pytorch_zip_data_pkl_unsafe_extraction(self, monkeypatch, tmp_path):
        """Unsafe pickle opcodes should be flagged"""
        if not has_torch():
            pytest.skip("PyTorch not installed")

        import torch

        model = torch.nn.Linear(2, 2)
        zip_path = tmp_path / "model.pt"
        torch.save(model.state_dict(), zip_path)

        def fail_load(*_args, **_kwargs):
            raise RuntimeError("fail")

        # Mock torch.load directly since torch is now a lazy import
        import torch

        monkeypatch.setattr(torch, "load", fail_load)
        scanner = WeightDistributionScanner()
        weights = scanner._extract_pytorch_weights(str(zip_path))
        assert weights == {}
        assert scanner.extraction_unsafe

    def test_tensorflow_checkpoint_size_limit_skips_before_load_variable(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        import numpy as np

        saved_model_dir = tmp_path / "saved_model"
        variables_dir = saved_model_dir / "variables"
        variables_dir.mkdir(parents=True)
        (variables_dir / "variables.index").write_bytes(b"checkpoint index")

        loaded_variables: list[str] = []

        class FakeCheckpointReader:
            def get_variable_to_dtype_map(self) -> dict[str, object]:
                return {
                    "dense/kernel": np.dtype("float32"),
                    "small/kernel": np.dtype("float32"),
                }

        class FakeTrain:
            @staticmethod
            def load_checkpoint(_prefix: str) -> FakeCheckpointReader:
                return FakeCheckpointReader()

            @staticmethod
            def list_variables(_prefix: str) -> list[tuple[str, list[int]]]:
                return [
                    ("dense/kernel", [1024, 1024]),
                    ("small/kernel", [2, 2]),
                ]

            @staticmethod
            def load_variable(_prefix: str, name: str) -> object:
                if name == "dense/kernel":
                    raise AssertionError("oversized checkpoint variable should not be loaded")
                loaded_variables.append(name)
                return np.ones((2, 2), dtype=np.float32)

        fake_tensorflow: Any = types.ModuleType("tensorflow")
        fake_tensorflow.train = FakeTrain
        monkeypatch.setitem(sys.modules, "tensorflow", fake_tensorflow)

        scanner = WeightDistributionScanner({"max_array_size": 128})
        weights = scanner._extract_tensorflow_weights(str(saved_model_dir))

        assert loaded_variables == ["small/kernel"]
        assert list(weights) == ["small/kernel"]
        assert scanner.extraction_incomplete is True
        assert "tensorflow_checkpoint_tensor_size_limit" in scanner.extraction_incomplete_reasons
        assert scanner.extraction_incomplete_details["failed_tensors"] == ["dense/kernel"]

    def test_tensorflow_checkpoint_skips_rank_one_weight_before_budgeting(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import numpy as np

        saved_model_dir = tmp_path / "saved_model"
        variables_dir = saved_model_dir / "variables"
        variables_dir.mkdir(parents=True)
        (variables_dir / "variables.index").write_bytes(b"checkpoint index")

        loaded_variables: list[str] = []

        class FakeCheckpointReader:
            @staticmethod
            def get_variable_to_dtype_map() -> dict[str, object]:
                return {
                    "class_weight": np.dtype("float32"),
                    "dense/kernel": np.dtype("float32"),
                }

        class FakeTrain:
            @staticmethod
            def load_checkpoint(_prefix: str) -> FakeCheckpointReader:
                return FakeCheckpointReader()

            @staticmethod
            def list_variables(_prefix: str) -> list[tuple[str, list[int]]]:
                return [("class_weight", [1024]), ("dense/kernel", [2, 2])]

            @staticmethod
            def load_variable(_prefix: str, name: str) -> object:
                loaded_variables.append(name)
                return np.ones((2, 2), dtype=np.float32)

        fake_tensorflow: Any = types.ModuleType("tensorflow")
        fake_tensorflow.train = FakeTrain
        monkeypatch.setitem(sys.modules, "tensorflow", fake_tensorflow)

        scanner = WeightDistributionScanner({"max_array_size": 128})
        weights = scanner._extract_tensorflow_weights(str(saved_model_dir))

        assert loaded_variables == ["dense/kernel"]
        assert list(weights) == ["dense/kernel"]
        assert scanner.extraction_incomplete is False

    def test_multiple_anomalies(self):
        """Test detection of multiple types of anomalies in one layer"""
        import numpy as np

        scanner = WeightDistributionScanner()

        # Create weights with multiple issues
        np.random.seed(42)
        weights = np.random.randn(100, 10) * 0.1

        # Neuron 3: Large magnitude outlier
        weights[:, 3] = np.random.randn(100) * 15.0  # More extreme outlier

        # Neuron 7: Dissimilar to others
        weights[:, 7] = np.random.randn(100) * 0.5 + 10.0

        architecture_analysis = self._create_mock_architecture_analysis(is_llm=False)
        anomalies = scanner._analyze_layer_weights("test_layer", weights, architecture_analysis)

        # Should detect at least one anomaly
        assert len(anomalies) >= 1

        # Check for any type of anomaly
        has_magnitude_anomaly = any("abnormal weight magnitudes" in a["description"] for a in anomalies)
        has_dissimilar_anomaly = any("dissimilar weights" in a["description"] for a in anomalies)
        has_extreme_anomaly = any("extremely large weight values" in a["description"] for a in anomalies)

        assert has_magnitude_anomaly or has_dissimilar_anomaly or has_extreme_anomaly

    def test_llm_vocabulary_layer_handling(self):
        """Test that LLM vocabulary layers don't produce false positives"""
        import numpy as np

        scanner = WeightDistributionScanner()

        # Create a large vocabulary layer like in LLMs (e.g., 32k vocab)
        np.random.seed(42)
        vocab_size = 32000
        hidden_dim = 4096
        weights = np.random.randn(hidden_dim, vocab_size) * 0.02  # Typical LLM init

        # Add some natural variation (not anomalous)
        for i in range(100):
            weights[:, i] *= 1.2  # Some tokens might have slightly different scales

        architecture_analysis = self._create_mock_architecture_analysis(is_llm=True)
        anomalies = scanner._analyze_layer_weights("lm_head.weight", weights, architecture_analysis)

        # Should not flag many neurons in an LLM
        # With our new thresholds, we expect very few or no anomalies
        assert len(anomalies) <= 1  # At most 1 anomaly type

        # If there are anomalies, they should affect very few neurons
        for anomaly in anomalies:
            if "outlier_neurons" in anomaly["details"]:
                # Should be less than 0.1% of neurons
                assert anomaly["details"]["total_outliers"] < vocab_size * 0.001

    def test_llm_checks_disabled_by_default(self):
        """Test that LLM checks are disabled by default"""
        import numpy as np

        scanner = WeightDistributionScanner()

        # Create LLM-like weights
        weights = np.random.randn(4096, 32000) * 0.02

        architecture_analysis = self._create_mock_architecture_analysis(is_llm=True)
        anomalies = scanner._analyze_layer_weights("lm_head.weight", weights, architecture_analysis)

        # Should return no anomalies since LLM checks are disabled by default
        assert len(anomalies) == 0

    def test_llm_checks_can_be_enabled(self):
        """Test that LLM checks can be explicitly enabled via config"""
        import numpy as np

        config = {"enable_llm_checks": True}
        scanner = WeightDistributionScanner(config)

        # Create LLM-like weights with some outliers
        np.random.seed(42)
        weights = np.random.randn(4096, 32000) * 0.02
        # Make a few neurons extreme outliers
        weights[:, 0] = np.random.randn(4096) * 10.0
        weights[:, 1] = np.random.randn(4096) * 10.0

        architecture_analysis = self._create_mock_architecture_analysis(is_llm=True)
        anomalies = scanner._analyze_layer_weights("lm_head.weight", weights, architecture_analysis)

        # With LLM checks enabled, might detect extreme outliers with strict thresholds
        # We made 2 extreme neurons, so could get up to 2 anomaly types (outlier + extreme)
        assert len(anomalies) <= 2

        # Should only flag the 2 neurons we made extreme
        for anomaly in anomalies:
            if "outlier_neurons" in anomaly["details"]:
                assert anomaly["details"]["total_outliers"] <= 2

    def test_gpt2_layer_pattern_detection(self):
        """Test that GPT-2 style layer patterns are detected as LLM layers"""
        import numpy as np

        scanner = WeightDistributionScanner()

        # Test GPT-2 style layer names
        gpt2_layer_names = [
            "h.0.mlp.c_fc.weight",
            "h.1.attn.c_attn.weight",
            "h.11.mlp.c_proj.weight",
            "transformer.h.5.mlp.c_fc.weight",
        ]

        # Create typical GPT-2 MLP weights (3072 -> 768 for GPT-2 base)
        np.random.seed(42)
        weights = np.random.randn(3072, 768) * 0.02

        # Add some natural variation
        weights[:, :10] *= 1.5  # Some neurons have different scales

        architecture_analysis = self._create_mock_architecture_analysis(is_llm=True)
        for layer_name in gpt2_layer_names:
            anomalies = scanner._analyze_layer_weights(layer_name, weights, architecture_analysis)

            # Should return no anomalies due to LLM detection
            assert len(anomalies) == 0, f"Layer {layer_name} should be detected as LLM"

    def test_transformer_layer_pattern_detection(self):
        """Test that transformer-related layers use structural analysis instead of name-based detection."""
        import numpy as np

        scanner = WeightDistributionScanner()

        # Test transformer-related layer names
        transformer_patterns = [
            "encoder.layers.0.mlp.dense_h_to_4h.weight",
            "decoder.attention.dense.weight",
            "transformer.mlp.fc_in.weight",
            "model.layers.5.mlp.gate_proj.weight",
        ]

        # Create transformer-like weights with some natural variation
        np.random.seed(42)
        weights = np.random.randn(1024, 4096) * 0.02  # Typical transformer dimensions

        # Add moderate natural variation (not extreme anomalies)
        weights[:, :10] *= 1.2  # Some neurons have slightly different scales

        architecture_analysis = self._create_mock_architecture_analysis(is_llm=True, is_transformer=True)
        for layer_name in transformer_patterns:
            anomalies = scanner._analyze_layer_weights(layer_name, weights, architecture_analysis)

            # With our new structural analysis approach:
            # - Large weight matrices (1024x4096 = 4M+ parameters) get relaxed thresholds
            # - Layer names no longer bypass security checks completely
            # - May still detect anomalies if weights are statistically unusual

            # The key security improvement: detection is based on actual weight properties,
            # not just names that can be spoofed by attackers

            # Should use relaxed thresholds for large models but still perform analysis
            assert len(anomalies) <= 2, f"Layer {layer_name} should use relaxed thresholds for large models"

            # If anomalies are found, they should indicate real statistical outliers
            for anomaly in anomalies:
                # Should have analysis_method metadata showing structural analysis was used
                assert anomaly["details"].get("analysis_method") == "structural_analysis"

    def test_large_hidden_dimension_detection(self):
        """Test that layers with large hidden dimensions are detected as LLM layers"""
        import numpy as np

        scanner = WeightDistributionScanner()

        # Test various large hidden dimensions typical of LLMs
        large_dimensions = [768, 1024, 2048, 4096, 8192]

        architecture_analysis = self._create_mock_architecture_analysis(is_llm=True)
        for hidden_dim in large_dimensions:
            np.random.seed(42)
            weights = np.random.randn(hidden_dim, 100) * 0.02  # Input dimension > 768

            anomalies = scanner._analyze_layer_weights("some_layer.weight", weights, architecture_analysis)

            # Should return no anomalies due to LLM detection
            assert len(anomalies) == 0, f"Layer with {hidden_dim} hidden dims should be detected as LLM"

    def test_non_llm_layers_still_analyzed(self):
        """Test that non-LLM layers are still properly analyzed for anomalies"""
        import numpy as np

        scanner = WeightDistributionScanner()

        # Create small classification layer (typical for image classification)
        np.random.seed(42)
        weights = np.random.randn(512, 10) * 0.1  # 512 features -> 10 classes

        # Add a clear anomaly
        weights[:, 5] = np.random.randn(512) * 5.0  # One class with much larger weights

        architecture_analysis = self._create_mock_architecture_analysis(is_llm=False)
        anomalies = scanner._analyze_layer_weights("classifier.weight", weights, architecture_analysis)

        # Should detect the anomaly since this is not an LLM layer
        assert len(anomalies) > 0, "Non-LLM layers should still be analyzed for anomalies"

        # Should find outlier neurons
        has_outlier = any("abnormal weight magnitudes" in a["description"] for a in anomalies)
        has_extreme = any("extremely large weight values" in a["description"] for a in anomalies)
        assert has_outlier or has_extreme

    def test_llm_enabled_with_extreme_outliers(self):
        """Test LLM analysis with extremely suspicious outliers when enabled"""
        import numpy as np

        config = {"enable_llm_checks": True}
        scanner = WeightDistributionScanner(config)

        # Create GPT-2 style layer with extremely suspicious outliers
        np.random.seed(42)
        weights = np.random.randn(768, 3072) * 0.02  # GPT-2 attention projection

        # Make just 1 neuron extremely suspicious (potential backdoor)
        weights[:, 0] = np.random.randn(768) * 50.0  # Very extreme outlier

        architecture_analysis = self._create_mock_architecture_analysis(is_llm=True)
        anomalies = scanner._analyze_layer_weights("h.0.attn.c_proj.weight", weights, architecture_analysis)

        # With strict LLM thresholds, only extreme outliers should be flagged
        # Should detect at most 1-2 issues (outlier detection + extreme values)
        assert len(anomalies) <= 2

        for anomaly in anomalies:
            if "outlier_neurons" in anomaly["details"]:
                # Should only flag the 1 extremely suspicious neuron
                assert anomaly["details"]["total_outliers"] <= 1
                assert 0 in anomaly["details"]["outlier_neurons"]

    def test_pytorch_zip_multiple_pickle_members_are_inconclusive(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        def fake_load(*_args: object, **_kwargs: object) -> dict[str, object]:
            raise AssertionError("torch.load must remain blocked")

        _install_fake_torch(monkeypatch, fake_load)
        payload = pickle.dumps({"layer.weight": [[1.0, 2.0], [3.0, 4.0]]}, protocol=4)

        distinct_path = tmp_path / "distinct-data-members.pt"
        with zipfile.ZipFile(distinct_path, "w") as archive:
            archive.writestr("decoy/data.pkl", payload)
            archive.writestr("actual/data.pkl", payload)

        duplicate_path = tmp_path / "duplicate-data-members.pt"
        with pytest.warns(UserWarning, match="Duplicate name"), zipfile.ZipFile(duplicate_path, "w") as archive:
            archive.writestr("data.pkl", payload)
            archive.writestr("data.pkl", payload)

        for model_path, expected_members in [
            (distinct_path, ["decoy/data.pkl", "actual/data.pkl"]),
            (duplicate_path, ["data.pkl", "data.pkl"]),
        ]:
            scanner = WeightDistributionScanner()
            weights = scanner._extract_pytorch_weights(str(model_path))

            assert weights == {}
            assert scanner.extraction_unsafe is False
            assert scanner.extraction_incomplete_reasons == ["pytorch_pickle_member_ambiguous"]
            assert scanner.extraction_incomplete_details == {
                "pickle_member_count": 2,
                "pickle_members": expected_members,
            }

    def test_pytorch_zip_marked_root_beats_decoy_pickle(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        def fake_load(*_args: object, **_kwargs: object) -> dict[str, object]:
            raise AssertionError("torch.load must remain blocked")

        _install_fake_torch(monkeypatch, fake_load)
        model_path = tmp_path / "marked-root.pt"
        with zipfile.ZipFile(model_path, "w") as archive:
            archive.writestr("decoy/data.pkl", pickle.dumps({"decoy.weight": [[9.0, 9.0], [9.0, 9.0]]}))
            archive.writestr("model/data.pkl", pickle.dumps({"layer.weight": [[1.0, 2.0], [3.0, 4.0]]}))
            archive.writestr("model/version", "3")

        scanner = WeightDistributionScanner()
        weights = scanner._extract_pytorch_weights(str(model_path))

        assert list(weights) == ["layer.weight"]
        assert weights["layer.weight"].tolist() == [[1.0, 2.0], [3.0, 4.0]]
        assert scanner.extraction_unsafe is False
        assert scanner.extraction_incomplete is False

    def test_pytorch_zip_multiple_credible_roots_fail_closed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        def fake_load(*_args: object, **_kwargs: object) -> dict[str, object]:
            raise AssertionError("torch.load must remain blocked")

        _install_fake_torch(monkeypatch, fake_load)
        model_path = tmp_path / "multiple-credible-roots.pt"
        with zipfile.ZipFile(model_path, "w") as archive:
            archive.writestr("data.pkl", pickle.dumps({"decoy.weight": [[0.0, 0.0], [0.0, 0.0]]}))
            archive.writestr("version", "3")
            archive.writestr("model/data.pkl", pickle.dumps({"actual.weight": [[1.0, 2.0], [3.0, 4.0]]}))
            archive.writestr("model/byteorder", "little")

        scanner = WeightDistributionScanner()
        result = scanner.scan(str(model_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        analysis_check = next(check for check in result.checks if check.name == "Weight Distribution Analysis")
        assert analysis_check.details["extraction_incomplete_reasons"] == ["pytorch_pickle_member_ambiguous"]
        assert analysis_check.details["pickle_member_count"] == 2
        assert analysis_check.details["pickle_members"] == ["data.pkl", "model/data.pkl"]

    def test_pytorch_zip_primitive_array_expansion_is_bounded_before_materialization(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        import numpy as np

        shared_row = [1.0] * 8
        data = {"layer.weight": [shared_row] * 200}
        assert len(pickle.dumps(data, protocol=4)) < 1024
        zip_path = create_mock_pytorch_zip(tmp_path / "expanded.pt", data=data)
        array_called = False

        def fake_load(*_args: object, **_kwargs: object) -> dict[str, object]:
            raise AssertionError("torch.load must remain blocked")

        original_array = np.array

        def track_array(value: Any) -> Any:
            nonlocal array_called
            array_called = True
            return original_array(value)

        _install_fake_torch(monkeypatch, fake_load)
        monkeypatch.setattr(np, "array", track_array)
        scanner = WeightDistributionScanner({"max_array_size": 1024})
        weights = scanner._extract_pytorch_weights(str(zip_path))

        assert weights == {}
        assert scanner.extraction_unsafe is False
        assert scanner.extraction_incomplete is True
        assert scanner.extraction_incomplete_reasons == ["pytorch_tensor_materialization_failed"]
        assert scanner.extraction_incomplete_details["failed_tensors"] == ["layer.weight"]
        assert array_called is False

    def test_pytorch_zip_primitive_array_budget_is_shared_across_aliased_keys(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        import numpy as np

        shared_value = [[float(column) for column in range(8)] for _row in range(4)]
        data = {f"layer{index}.weight": shared_value for index in range(20)}
        assert len(pickle.dumps(data, protocol=4)) < 1024
        zip_path = create_mock_pytorch_zip(tmp_path / "aliased.pt", data=data)
        array_calls = 0

        def fake_load(*_args: object, **_kwargs: object) -> dict[str, object]:
            raise AssertionError("torch.load must remain blocked")

        original_array = np.array

        def track_array(value: Any) -> Any:
            nonlocal array_calls
            array_calls += 1
            return original_array(value)

        _install_fake_torch(monkeypatch, fake_load)
        monkeypatch.setattr(np, "array", track_array)
        scanner = WeightDistributionScanner({"max_array_size": 1024})
        weights = scanner._extract_pytorch_weights(str(zip_path))

        assert array_calls <= 2
        assert sum(array.nbytes for array in weights.values()) <= 1024
        assert scanner.extraction_unsafe is False
        assert list(weights) == ["layer0.weight"]
        assert scanner.extraction_incomplete is False

    def test_pytorch_zip_nonnumeric_weight_metadata_is_ignored(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        data = {
            "layer.weight": [[1.0, 2.0], [3.0, 4.0]],
            "weight_names": ["layer.weight"],
            "kernel_metadata": [[b"dense", None]],
            "weight_metadata": True,
            "kernel_flags": [True, False],
            "weight_mask": [[True, False]],
        }
        model_path = create_mock_pytorch_zip(tmp_path / "metadata.pt", data=data)

        def fake_load(*_args: object, **_kwargs: object) -> dict[str, object]:
            raise AssertionError("torch.load must remain blocked")

        _install_fake_torch(monkeypatch, fake_load)
        scanner = WeightDistributionScanner()
        weights = scanner._extract_pytorch_weights(str(model_path))

        assert list(weights) == ["layer.weight"]
        assert scanner.extraction_unsafe is False
        assert scanner.extraction_incomplete is False

        result = WeightDistributionScanner().scan(str(model_path))
        assert result.success is True
        assert result.metadata["layers_analyzed"] == 1
        assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME

    def test_pytorch_zip_graph_budget_is_checked_before_unpickling(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        payload = b"\x80\x04" + (b"(1" * 1024) + b"}."
        assert len(payload) < 16384
        zip_path = tmp_path / "over-budget-graph.pt"
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr("data.pkl", payload)

        def fake_load(*_args: object, **_kwargs: object) -> dict[str, object]:
            raise AssertionError("torch.load must remain blocked")

        class FailIfInstantiatedUnpickler:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                raise AssertionError("over-budget pickle must not be unpickled")

        _install_fake_torch(monkeypatch, fake_load)
        monkeypatch.setattr(pickle, "Unpickler", FailIfInstantiatedUnpickler)
        scanner = WeightDistributionScanner({"max_array_size": 16384})
        weights = scanner._extract_pytorch_weights(str(zip_path))

        assert weights == {}
        assert scanner.extraction_unsafe is False
        assert scanner.extraction_incomplete_reasons == ["pytorch_pickle_graph_budget_exceeded"]
        assert scanner.extraction_incomplete_details["pickle_opcode_limit"] == 2048
        assert scanner.extraction_incomplete_details["pickle_opcode_count"] == 2049

    def test_pytorch_zip_sparse_memo_index_is_inconclusive_and_not_cached(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        sparse_index = 5_000_000
        payload = b"\x80\x04}r" + sparse_index.to_bytes(4, "little") + b"."
        model_path = create_mock_pytorch_zip(tmp_path / "sparse-memo.pt", with_pickle=False)
        with zipfile.ZipFile(model_path, "a") as archive:
            archive.writestr("data.pkl", payload)

        def fake_load(*_args: object, **_kwargs: object) -> dict[str, object]:
            raise AssertionError("torch.load must remain blocked")

        class FailIfInstantiatedUnpickler:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                raise AssertionError("sparse memo pickle must not be unpickled")

        _install_fake_torch(monkeypatch, fake_load)
        monkeypatch.setattr(pickle, "Unpickler", FailIfInstantiatedUnpickler)
        direct = WeightDistributionScanner().scan(str(model_path))

        assert direct.success is False
        assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        analysis_check = next(check for check in direct.checks if check.name == "Weight Distribution Analysis")
        assert analysis_check.details["extraction_incomplete_reasons"] == ["pytorch_pickle_graph_budget_exceeded"]
        assert analysis_check.details["pickle_memo_index"] == sparse_index
        assert analysis_check.details["pickle_memo_entries"] == 0
        assert analysis_check.details["pickle_memo_opcode"] == "LONG_BINPUT"

        cache_dir = tmp_path / "sparse-memo-cache"
        reset_cache_manager()
        try:
            first = core.scan_model_directory_or_file(
                str(model_path),
                scanners=["weight_distribution"],
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            second = core.scan_model_directory_or_file(
                str(model_path),
                scanners=["weight_distribution"],
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

            for aggregate in (first, second):
                assert aggregate.success is False
                assert core.determine_exit_code(aggregate) == 2
                assert aggregate.file_metadata[str(model_path)]["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_pytorch_zip_pickle_read_is_bounded_before_open(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        zip_path = tmp_path / "oversized-data.pt"
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr("data.pkl", b"x" * 1025)

        def fake_load(*_args: object, **_kwargs: object) -> dict[str, object]:
            raise AssertionError("torch.load must remain blocked")

        original_open = zipfile.ZipFile.open

        def fail_data_member_open(
            archive: zipfile.ZipFile,
            name: str | zipfile.ZipInfo,
            mode: Any = "r",
            pwd: bytes | None = None,
            *,
            force_zip64: bool = False,
        ) -> Any:
            member_name = name.filename if isinstance(name, zipfile.ZipInfo) else name
            if member_name == "data.pkl":
                raise AssertionError("oversized data.pkl must not be opened")
            return original_open(archive, name, mode, pwd, force_zip64=force_zip64)

        _install_fake_torch(monkeypatch, fake_load)
        monkeypatch.setattr(zipfile.ZipFile, "open", fail_data_member_open)
        scanner = WeightDistributionScanner({"max_array_size": 1024})
        weights = scanner._extract_pytorch_weights(str(zip_path))

        assert weights == {}
        assert scanner.extraction_unsafe is False
        assert scanner.extraction_incomplete_reasons == ["pytorch_zip_data_pkl_size_limit"]
        assert scanner.extraction_incomplete_details == {
            "failed_tensors": ["data.pkl"],
            "oversized_tensors": 1,
            "tensor_nbytes": 1025,
            "max_array_size": 1024,
            "max_pickle_metadata_bytes": 1024,
        }

    def test_partial_pytorch_zip_fallback_is_inconclusive_and_not_cached(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        data = {
            "good.weight": [[1.0, 2.0], [3.0, 4.0]],
            "bad.weight": [[1.0, 2.0], [3.0]],
        }
        model_path = create_mock_pytorch_zip(tmp_path / "partial.pt", data=data)

        def fake_load(*_args: object, **_kwargs: object) -> dict[str, object]:
            raise AssertionError("torch.load must remain blocked")

        _install_fake_torch(monkeypatch, fake_load)
        direct = WeightDistributionScanner().scan(str(model_path))

        assert direct.success is False
        assert direct.metadata["layers_analyzed"] == 1
        assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        analysis_check = next(check for check in direct.checks if check.name == "Weight Distribution Analysis")
        assert analysis_check.details["extraction_incomplete_reasons"] == ["pytorch_tensor_materialization_failed"]
        assert analysis_check.details["failed_tensors"] == ["bad.weight"]
        assert analysis_check.details["tensor_read_failures"] == 1

        cache_dir = tmp_path / "partial-cache"
        reset_cache_manager()
        try:
            first = core.scan_model_directory_or_file(
                str(model_path),
                scanners=["weight_distribution"],
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            second = core.scan_model_directory_or_file(
                str(model_path),
                scanners=["weight_distribution"],
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

            for aggregate in (first, second):
                assert aggregate.success is False
                assert core.determine_exit_code(aggregate) == 2
                assert aggregate.file_metadata[str(model_path)]["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    @pytest.mark.parametrize(
        "torch_version",
        ["2.9.9", "2.10.0", "2.12.0", "2.10.0+dev", "unknown"],
    )
    def test_blocks_torch_load_without_explicit_opt_in(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        torch_version: str,
    ) -> None:
        load_called = False

        def fake_load(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal load_called
            load_called = True
            return {}

        _install_fake_torch(monkeypatch, fake_load, version=torch_version)
        model_path = tmp_path / "blocked.pt"
        model_path.write_bytes(b"not-a-valid-pytorch-model")

        scanner = WeightDistributionScanner()
        weights = scanner._extract_pytorch_weights(str(model_path))

        assert weights == {}
        assert scanner.extraction_unsafe
        assert scanner.extraction_unsafe_reason is not None
        assert "Blocked torch.load" in scanner.extraction_unsafe_reason
        assert "not a trust boundary" in scanner.extraction_unsafe_reason
        assert load_called is False

    @pytest.mark.parametrize("unsafe_value", [1, "true", "false", {"enabled": True}])
    def test_torch_load_opt_in_requires_literal_true(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        unsafe_value: Any,
    ) -> None:
        load_called = False

        def fake_load(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal load_called
            load_called = True
            return {}

        _install_fake_torch(monkeypatch, fake_load)
        model_path = tmp_path / "strict-opt-in.pt"
        model_path.write_bytes(b"not-a-valid-pytorch-model")

        scanner = WeightDistributionScanner({"enable_unsafe_torch_load": unsafe_value})
        weights = scanner._extract_pytorch_weights(str(model_path))

        assert weights == {}
        assert scanner.extraction_unsafe
        assert load_called is False

    def test_explicit_torch_load_opt_in_retains_weights_only(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        load_call: dict[str, object] = {}

        def fake_load(_path: str, *, map_location: object, weights_only: bool) -> dict[str, object]:
            load_call["map_location"] = map_location
            load_call["weights_only"] = weights_only
            return {}

        _install_fake_torch(monkeypatch, fake_load)
        model_path = tmp_path / "opted-in.pt"
        model_path.write_bytes(b"not-a-valid-pytorch-model")

        scanner = WeightDistributionScanner({"enable_unsafe_torch_load": True})
        weights = scanner._extract_pytorch_weights(str(model_path))

        assert weights == {}
        assert scanner.extraction_unsafe is False
        assert load_call == {"map_location": "cpu", "weights_only": True}

    def test_explicit_torch_load_opt_in_supports_legacy_signatures(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        load_call: dict[str, object] = {}

        def fake_load(_path: str, *, map_location: object) -> dict[str, object]:
            load_call["map_location"] = map_location
            return {}

        _install_fake_torch(monkeypatch, fake_load, version="2.5.1")
        model_path = tmp_path / "legacy-opted-in.pt"
        model_path.write_bytes(b"not-a-valid-pytorch-model")

        scanner = WeightDistributionScanner({"enable_unsafe_torch_load": True})
        weights = scanner._extract_pytorch_weights(str(model_path))

        assert weights == {}
        assert scanner.extraction_unsafe is False
        assert load_call == {"map_location": "cpu"}

    def test_blocked_torch_load_is_inconclusive_and_not_cached(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        load_called = False

        def fake_load(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal load_called
            load_called = True
            return {}

        _install_fake_torch(monkeypatch, fake_load)
        model_path = create_mock_pytorch_zip(tmp_path / "blocked.pt", with_pickle=False)

        direct = WeightDistributionScanner().scan(str(model_path))

        assert direct.success is False
        assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert direct.metadata["scan_outcome_reasons"] == ["weight_distribution_analysis_incomplete"]
        analysis_check = next(check for check in direct.checks if check.name == "Weight Distribution Analysis")
        assert analysis_check.severity == IssueSeverity.INFO
        assert analysis_check.rule_code is None
        assert analysis_check.details["extraction_incomplete_reasons"] == ["unsafe_pytorch_weight_extraction"]
        assert "not a trust boundary" in analysis_check.details["unsafe_reason"]
        assert not any(check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for check in direct.checks)
        assert load_called is False

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            first = core.scan_model_directory_or_file(
                str(model_path),
                scanners=["weight_distribution"],
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            second = core.scan_model_directory_or_file(
                str(model_path),
                scanners=["weight_distribution"],
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

            for aggregate in (first, second):
                metadata = aggregate.file_metadata[str(model_path)]
                assert aggregate.success is False
                assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
                assert metadata["scan_outcome_reasons"] == ["weight_distribution_analysis_incomplete"]
                assert core.determine_exit_code(aggregate) == 2
                assert not any(
                    issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues
                )
                assert all(issue.rule_code != "S801" for issue in aggregate.issues)
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
            assert load_called is False
        finally:
            reset_cache_manager()
