"""Core dispatch regressions for content-routed model formats."""

from __future__ import annotations

import base64
import gzip
import json
import pickle
import zipfile
from pathlib import Path
from typing import Any

import pytest

from modelaudit import core as core_module
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import scan_file
from modelaudit.scanners.base import CheckStatus, IssueSeverity, ScanResult
from tests.helpers import create_mock_gguf, create_mock_onnx, create_mock_pytorch_zip

_SYSTEM_GLOBAL_NAMES = ("os.system", "posix.system", "nt.system")


def _build_malicious_pickle() -> bytes:
    """Build a tiny pickle payload that exercises nested dangerous-opcode scanning."""
    import os as os_module

    class DangerousPayload:
        """Serializable payload that reduces to a shell command invocation."""

        def __reduce__(self) -> tuple[Any, tuple[str]]:
            """Return a dangerous reducer target for scanner regression coverage."""
            return (os_module.system, ("echo core-dispatch-test",))

    return pickle.dumps(DangerousPayload())


def _create_misnamed_zip(path: Path, entries: dict[str, bytes]) -> None:
    """Write a ZIP archive at an intentionally misleading file path."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)


def _create_zip_with_ordered_entries(path: Path, entries: list[tuple[str, bytes]]) -> None:
    """Write a ZIP archive with duplicate entries in caller-defined order."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)


def _mark_zip_entries_encrypted(path: Path) -> None:
    """Set the ZIP encryption flag on all entries without changing payload bytes."""
    archive_bytes = bytearray(path.read_bytes())
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        offset = 0
        while True:
            offset = archive_bytes.find(signature, offset)
            if offset < 0:
                break
            flags = int.from_bytes(archive_bytes[offset + flag_offset : offset + flag_offset + 2], "little")
            archive_bytes[offset + flag_offset : offset + flag_offset + 2] = (flags | 0x1).to_bytes(2, "little")
            offset += len(signature)
    path.write_bytes(archive_bytes)


def _assert_system_pickle_detected(result: ScanResult, entry_name: str) -> None:
    """Assert a nested pickle finding points at the expected ZIP entry."""
    assert any(
        issue.rule_code == "S201"
        and issue.details.get("zip_entry") == entry_name
        and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    ), f"Expected S201 finding for {entry_name}, got: {[(i.location, i.message, i.details) for i in result.issues]}"


def test_scan_file_detects_malicious_zip_with_misleading_extension(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "payload.jpg"
    _create_misnamed_zip(disguised_zip, {"payload.pkl": _build_malicious_pickle()})

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    _assert_system_pickle_detected(result, "payload.pkl")


def test_scan_file_detects_misnamed_gzip_wrapped_pickle_by_header(tmp_path: Path) -> None:
    disguised_gzip = tmp_path / "payload.jpg"
    disguised_gzip.write_bytes(gzip.compress(_build_malicious_pickle()))

    result = scan_file(str(disguised_gzip))

    assert result.scanner_name == "compressed"
    routing_checks = [check for check in result.checks if check.name == "Compressed Wrapper Inner Scanner Routing"]
    assert routing_checks
    assert routing_checks[0].details.get("inner_scanner") == "pickle"
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("compressed_wrapper") == f"{disguised_gzip} -> payload.jpg.inner"
        and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    ), f"Expected compressed inner pickle finding, got: {[(i.location, i.message, i.details) for i in result.issues]}"


def test_scan_file_does_not_route_compression_magic_near_match_to_compressed(tmp_path: Path) -> None:
    near_match = tmp_path / "payload.jpg"
    near_match.write_bytes(b"\x1f\x00not-a-gzip-stream")

    result = scan_file(str(near_match))

    assert result.scanner_name == "unknown"
    assert not [check for check in result.checks if check.name.startswith("Compressed Wrapper")]
    assert result.issues == []


def test_scan_file_does_not_route_pk_prefix_near_match_to_zip(tmp_path: Path) -> None:
    near_match = tmp_path / "payload.jpg"
    near_match.write_bytes(b"PKNO harmless text")

    result = scan_file(str(near_match))

    assert result.scanner_name == "unknown"
    assert not [check for check in result.checks if "ZIP" in check.name]
    assert result.issues == []


def test_scan_file_detects_shadowed_duplicate_pickle_in_misleading_zip(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "payload.jpg"
    _create_zip_with_ordered_entries(
        disguised_zip,
        [
            ("payload.pkl", _build_malicious_pickle()),
            ("payload.pkl", pickle.dumps({"safe": True})),
        ],
    )

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    _assert_system_pickle_detected(result, "payload.pkl")


def test_scan_file_detects_malicious_payload_in_skops_via_zip_pipeline(tmp_path: Path) -> None:
    skops_archive = tmp_path / "payload.skops"
    _create_misnamed_zip(skops_archive, {"payload.pkl": _build_malicious_pickle()})

    result = scan_file(str(skops_archive))

    assert result.scanner_name == "skops"
    assert any("payload.pkl" in (issue.location or "") for issue in result.issues)


def test_scan_file_routes_misnamed_skops_archive_by_schema_content(tmp_path: Path) -> None:
    disguised_skops = tmp_path / "payload.jpg"
    _create_misnamed_zip(
        disguised_skops,
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
            "payload.pkl": _build_malicious_pickle(),
        },
    )

    result = scan_file(str(disguised_skops))

    assert result.scanner_name == "skops"
    assert any("payload.pkl" in (issue.location or "") for issue in result.issues)


def test_scan_file_routes_misnamed_skops_archive_by_bare_schema_content(tmp_path: Path) -> None:
    disguised_skops = tmp_path / "payload-no-ext-schema.jpg"
    _create_misnamed_zip(
        disguised_skops,
        {
            "nested/schema": json.dumps(
                {
                    "__class__": "Pipeline",
                    "__module__": "sklearn.pipeline",
                    "__loader__": "ObjectNode",
                    "_skops_version": "0.11.0",
                    "content": {},
                }
            ).encode("utf-8"),
            "payload.pkl": _build_malicious_pickle(),
        },
    )

    result = scan_file(str(disguised_skops))

    assert result.scanner_name == "skops"
    _assert_system_pickle_detected(result, "payload.pkl")


def test_scan_file_does_not_route_nested_bare_schema_near_match_to_skops(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "nested-schema-near-match.jpg"
    _create_misnamed_zip(
        disguised_zip,
        {
            "nested/schema": json.dumps(
                {
                    "__class__": "Pipeline",
                    "__module__": "sklearn.pipeline",
                    "__loader__": "ObjectNode",
                    "content": {},
                }
            ).encode("utf-8"),
        },
    )

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    assert not any("CVE-2025-" in check.name for check in result.checks)


def test_scan_file_does_not_route_near_match_schema_zip_to_skops(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "schema.jpg"
    _create_misnamed_zip(
        disguised_zip,
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

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    assert not any("CVE-2025-" in check.name for check in result.checks)


def test_scan_file_routes_oversized_misnamed_skops_schema_to_skops(tmp_path: Path) -> None:
    disguised_skops = tmp_path / "oversized-schema.jpg"
    schema = {
        "__class__": "Pipeline",
        "__module__": "sklearn.pipeline",
        "__loader__": "ObjectNode",
        "_skops_version": "0.11.0",
        "content": {},
        "padding": "x" * (4 * 1024 * 1024),
    }
    _create_misnamed_zip(
        disguised_skops,
        {
            "schema.json": json.dumps(schema).encode("utf-8"),
            "payload.pkl": _build_malicious_pickle(),
        },
    )

    result = scan_file(str(disguised_skops))

    assert result.scanner_name == "skops"
    assert any("payload.pkl" in (issue.location or "") for issue in result.issues)


def test_scan_file_handles_encrypted_skops_schema_without_routing_crash(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "encrypted-schema.jpg"
    _create_misnamed_zip(
        disguised_zip,
        {
            "schema.json": json.dumps(
                {
                    "__class__": "Pipeline",
                    "__module__": "sklearn.pipeline",
                    "__loader__": "ObjectNode",
                    "_skops_version": "0.12.0",
                    "content": {},
                }
            ).encode("utf-8"),
        },
    )
    _mark_zip_entries_encrypted(disguised_zip)

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    assert any("encrypted" in check.message.lower() for check in result.checks)


def test_scan_file_scans_clean_skops_without_nested_false_positives(tmp_path: Path) -> None:
    skops_archive = tmp_path / "clean.skops"
    _create_misnamed_zip(
        skops_archive,
        {
            "schema.json": json.dumps(
                {
                    "__class__": "Pipeline",
                    "__module__": "sklearn.pipeline",
                    "__loader__": "ObjectNode",
                    "_skops_version": "0.12.0",
                    "content": {},
                }
            ).encode("utf-8"),
            "metadata.json": b'{"name": "clean_model"}',
            "weights.bin": b"model weights",
        },
    )

    result = scan_file(str(skops_archive))

    assert result.scanner_name == "skops"
    assert result.success
    assert not result.issues


def test_scan_file_does_not_route_generic_zip_config_to_keras(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "repo.jpg"
    _create_misnamed_zip(disguised_zip, {"config.json": json.dumps({"model_type": "bert"}).encode("utf-8")})

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    assert not any(check.name.startswith("Keras ZIP") for check in result.checks)


def test_scan_file_routes_misnamed_keras_zip_by_content(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    malicious_code = "exec(\"print('Malicious!')\")"
    encoded_code = base64.b64encode(malicious_code.encode()).decode()
    config = {
        "class_name": "Functional",
        "config": {
            "layers": [
                {"class_name": "InputLayer", "name": "input_1", "config": {}},
                {
                    "class_name": "Lambda",
                    "name": "lambda_1",
                    "config": {"function": [encoded_code, None, None], "function_type": "lambda"},
                },
            ]
        },
    }
    _create_misnamed_zip(
        disguised_keras,
        {
            "config.json": json.dumps(config).encode("utf-8"),
            "metadata.json": json.dumps({"keras_version": "3.0.0"}).encode("utf-8"),
        },
    )

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert any("lambda" in issue.message.lower() for issue in result.issues)


def test_scan_file_routes_misnamed_config_only_keras_zip_by_content(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    malicious_code = "exec(\"print('Malicious!')\")"
    encoded_code = base64.b64encode(malicious_code.encode()).decode()
    config = {
        "class_name": "Functional",
        "config": {
            "layers": [
                {"class_name": "InputLayer", "name": "input_1", "config": {}},
                {
                    "class_name": "Lambda",
                    "name": "lambda_1",
                    "config": {"function": [encoded_code, None, None], "function_type": "lambda"},
                },
            ]
        },
    }
    _create_misnamed_zip(disguised_keras, {"config.json": json.dumps(config).encode("utf-8")})

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert any("lambda" in issue.message.lower() for issue in result.issues)


def test_scan_file_routes_misnamed_oversized_config_only_keras_zip_by_content(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    malicious_code = "exec(\"print('Malicious!')\")"
    encoded_code = base64.b64encode(malicious_code.encode()).decode()
    config = {
        "class_name": "Functional",
        "config": {
            "layers": [
                {"class_name": "InputLayer", "name": "input_1", "config": {}},
                {
                    "class_name": "Lambda",
                    "name": "lambda_1",
                    "config": {"function": [encoded_code, None, None], "function_type": "lambda"},
                },
            ]
        },
        "padding": "A" * (5 * 1024 * 1024),
    }
    with zipfile.ZipFile(disguised_keras, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("config.json", json.dumps(config))

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert any("lambda" in issue.message.lower() for issue in result.issues)


def test_scan_file_does_not_route_misnamed_oversized_generic_config_to_keras(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "repo.jpg"
    generic_config = {
        "model_type": "bert",
        "architectures": ["BertModel"],
        "padding": "A" * (5 * 1024 * 1024),
    }
    with zipfile.ZipFile(disguised_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("config.json", json.dumps(generic_config))

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    assert not any(check.name.startswith("Keras ZIP") for check in result.checks)


def test_scan_file_recursively_scans_embedded_pickle_in_content_routed_keras_zip(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    _create_misnamed_zip(
        disguised_keras,
        {
            "config.json": json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8"),
            "payload.pkl": _build_malicious_pickle(),
        },
    )

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert result.success is False
    _assert_system_pickle_detected(result, "payload.pkl")
    assert result.metadata.get("model_class") == "Sequential"


def test_scan_file_scans_shadowed_duplicate_pickle_members_in_content_routed_keras_zip(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    _create_zip_with_ordered_entries(
        disguised_keras,
        [
            ("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8")),
            ("payload.pkl", _build_malicious_pickle()),
            ("payload.pkl", pickle.dumps({"safe": True})),
        ],
    )

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert result.success is False
    _assert_system_pickle_detected(result, "payload.pkl")


def test_scan_file_content_routed_keras_zip_with_benign_extra_member_stays_clean(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    _create_misnamed_zip(
        disguised_keras,
        {
            "config.json": json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8"),
            "notes.txt": b"safe archive member",
        },
    )

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert result.success is True
    assert result.issues == []


def test_scan_file_content_routed_keras_zip_with_benign_pickle_member_stays_clean(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    _create_misnamed_zip(
        disguised_keras,
        {
            "config.json": json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8"),
            "weights.pkl": pickle.dumps({"weights": [1, 2, 3], "bias": [0.1, 0.2]}),
        },
    )

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert result.success is True
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_scan_file_content_routed_keras_zip_with_duplicate_benign_pickle_members_stays_clean(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    safe_payload = pickle.dumps({"weights": [1, 2, 3], "bias": [0.1, 0.2]})
    _create_zip_with_ordered_entries(
        disguised_keras,
        [
            ("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8")),
            ("weights.pkl", safe_payload),
            ("weights.pkl", safe_payload),
        ],
    )

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert result.success is True
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_scan_file_routes_config_only_keras_by_suffix(tmp_path: Path) -> None:
    keras_model = tmp_path / "model.keras"
    _create_misnamed_zip(
        keras_model,
        {
            "config.json": json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8"),
        },
    )

    result = scan_file(str(keras_model))

    assert result.scanner_name == "keras_zip"
    assert result.success


def test_scan_file_routes_misnamed_pytorch_zip_by_content(tmp_path: Path) -> None:
    disguised_torch = tmp_path / "model.jpg"
    _create_misnamed_zip(
        disguised_torch,
        {
            "data.pkl": _build_malicious_pickle(),
            "version": b"1.6",
        },
    )

    result = scan_file(str(disguised_torch))

    assert result.scanner_name == "pytorch_zip"
    assert any("data.pkl" in (issue.location or "") for issue in result.issues)


@pytest.mark.parametrize(
    ("pickle_member", "storage_member"),
    [("data.pkl", "data/0"), ("archive/data.pkl", "archive/data/0")],
)
def test_scan_file_routes_misnamed_pytorch_zip_with_storage_but_no_metadata(
    tmp_path: Path,
    pickle_member: str,
    storage_member: str,
) -> None:
    disguised_torch = tmp_path / f"metadata-stripped-{pickle_member.replace('/', '-')}.jpg"
    _create_misnamed_zip(
        disguised_torch,
        {
            pickle_member: _build_malicious_pickle(),
            storage_member: b"tensor-storage",
        },
    )

    result = scan_file(str(disguised_torch))

    assert result.scanner_name == "pytorch_zip"
    assert any(pickle_member in (issue.location or "") for issue in result.issues)


@pytest.mark.parametrize(
    ("pickle_member", "near_storage_member"),
    [
        ("data.pkl", "data/readme.txt"),
        ("data.pkl", "data/0abc"),
        ("data.pkl", "data/weights.v2"),
        ("data.pkl", "data/0/readme.txt"),
        ("archive/data.pkl", "archive/data/readme.txt"),
        ("archive/data.pkl", "archive/data/0abc"),
        ("archive/data.pkl", "archive/data/weights.v2"),
        ("archive/data.pkl", "archive/data/0/readme.txt"),
    ],
)
def test_scan_file_does_not_route_generic_data_directory_to_pytorch_zip(
    tmp_path: Path,
    pickle_member: str,
    near_storage_member: str,
) -> None:
    disguised_zip = tmp_path / f"generic-data-dir-{pickle_member.replace('/', '-')}.jpg"
    _create_misnamed_zip(
        disguised_zip,
        {
            pickle_member: _build_malicious_pickle(),
            near_storage_member: b"not tensor storage",
        },
    )

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    _assert_system_pickle_detected(result, pickle_member)


@pytest.mark.parametrize("suffix", [".pt", ".pth", ".ckpt", ".bin", ".pkl"])
def test_scan_file_routes_zip_backed_torch_suffix_collisions_to_pytorch_zip(
    tmp_path: Path,
    suffix: str,
) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / f"weights{suffix}")

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "pytorch_zip"
    assert result.success is True
    assert result.metadata.get("pickle_files")


@pytest.mark.parametrize("suffix", [".pt", ".pth", ".ckpt", ".pkl"])
def test_scan_file_routes_raw_pickle_torch_suffix_collisions_to_pickle(
    tmp_path: Path,
    suffix: str,
) -> None:
    model_path = tmp_path / f"weights{suffix}"
    model_path.write_bytes(pickle.dumps({"weights": [1, 2, 3]}, protocol=4))

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "pickle"
    assert result.success is True


def test_scan_file_routes_jax_pickles_through_jax_specific_analysis(tmp_path: Path) -> None:
    model_path = tmp_path / "state.pickle"
    model_path.write_bytes(
        pickle.dumps(
            {
                "framework": "jax",
                "payload": "jax.experimental.io_callback",
            }
        )
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "pickle"
    assert any(
        check.name == "JAX Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["pattern"] == r"jax\.experimental\.io_callback"
        for check in result.checks
    )


def test_scan_file_routes_raw_bin_without_zip_structure_to_pytorch_binary(tmp_path: Path) -> None:
    model_path = tmp_path / "weights.bin"
    model_path.write_bytes(b"\x00" * 128)

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "pytorch_binary"
    assert result.success is True


def test_preferred_scanner_does_not_route_generic_zip_bin_to_pickle(tmp_path: Path) -> None:
    model_path = tmp_path / "weights.bin"
    _create_misnamed_zip(model_path, {"metadata.txt": b"not a pickle"})

    assert core_module._select_preferred_scanner_id(str(model_path), "zip", ".bin") == "zip"


def test_scan_file_routes_misnamed_executorch_archive_by_content(tmp_path: Path) -> None:
    disguised_exec = tmp_path / "model.jpg"
    _create_misnamed_zip(
        disguised_exec,
        {
            "bytecode.pkl": pickle.dumps({"weights": [1, 2, 3]}),
            "version": b"1",
            "evil.py": b"print('evil')\n",
        },
    )

    result = scan_file(str(disguised_exec))

    assert result.scanner_name == "executorch"
    assert any(issue.rule_code == "S507" and "evil.py" in (issue.location or "") for issue in result.issues)
    assert any(issue.rule_code == "S104" and "evil.py" in (issue.location or "") for issue in result.issues)


def test_scan_file_does_not_route_non_pytorch_zip_with_generic_pickle(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "weights.jpg"
    _create_misnamed_zip(
        disguised_zip,
        {
            "weights.pkl": pickle.dumps({"weights": [1, 2, 3]}),
            "version": b"1.0",
        },
    )

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"


def test_scan_file_does_not_route_near_match_executorch_zip_without_numeric_version(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "bytecode.jpg"
    _create_misnamed_zip(
        disguised_zip,
        {
            "bytecode.pkl": pickle.dumps({"weights": [1, 2, 3]}),
            "version": b"dev",
        },
    )

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"


def test_scan_file_does_not_route_generic_data_pickle_without_pytorch_metadata(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "data.jpg"
    _create_misnamed_zip(disguised_zip, {"data.pkl": pickle.dumps({"weights": [1, 2, 3]})})

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"


def test_scan_file_routes_misnamed_torchserve_mar_by_content(tmp_path: Path) -> None:
    disguised_mar = tmp_path / "model.jpg"
    manifest = {
        "model": {
            "handler": "handler.py",
            "serializedFile": "model.pkl",
        }
    }
    _create_misnamed_zip(
        disguised_mar,
        {
            "MAR-INF/MANIFEST.json": json.dumps(manifest).encode("utf-8"),
            "handler.py": b"def handle(data, context):\n    return data\n",
            "model.pkl": _build_malicious_pickle(),
        },
    )

    result = scan_file(str(disguised_mar))

    assert result.scanner_name == "torchserve_mar"
    assert any("model.pkl" in (issue.location or "") for issue in result.issues)


def test_scan_file_routes_misnamed_keras_hdf5_by_header(tmp_path: Path) -> None:
    h5py = pytest.importorskip("h5py")

    disguised_h5 = tmp_path / "model.jpg"
    with h5py.File(disguised_h5, "w") as handle:
        handle.attrs["model_config"] = json.dumps(
            {
                "class_name": "Sequential",
                "config": {
                    "name": "test",
                    "layers": [{"class_name": "Lambda", "config": {"function": "lambda x: x * 2"}}],
                },
            }
        )
        handle.attrs["keras_version"] = "3.11.2"

    result = scan_file(str(disguised_h5))

    assert result.scanner_name == "keras_h5"
    assert any("CVE-2025-9905" in issue.message for issue in result.issues)


def test_scan_file_routes_misnamed_gguf_by_header(tmp_path: Path) -> None:
    disguised_gguf = create_mock_gguf(tmp_path / "model.payload")

    result = scan_file(str(disguised_gguf))

    assert result.scanner_name == "gguf"
    assert result.metadata["format"] == "gguf"


def test_scan_file_routes_gguf_chat_templates_through_jinja_analysis(tmp_path: Path) -> None:
    gguf_path = create_mock_gguf(
        tmp_path / "model.gguf",
        metadata={"tokenizer.chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}"},
    )

    result = scan_file(str(gguf_path), config={"cache_scan_results": False})

    assert result.scanner_name == "gguf"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_does_not_route_gguf_magic_near_match_to_gguf(tmp_path: Path) -> None:
    near_match = tmp_path / "model.payload"
    near_match.write_bytes(b"GGU?" + b"\x00" * 32)

    result = scan_file(str(near_match))

    assert result.scanner_name == "unknown"
    assert result.issues == []


def test_scan_file_routes_misnamed_onnx_by_header(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    disguised_onnx = tmp_path / "model.payload"
    create_mock_onnx(disguised_onnx)

    result = scan_file(str(disguised_onnx))

    assert result.scanner_name == "onnx"


def test_scan_file_routes_onnx_pb_by_content(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    onnx_pb = tmp_path / "model.pb"
    create_mock_onnx(onnx_pb)

    result = scan_file(str(onnx_pb))

    assert result.scanner_name == "onnx"
    assert not any(check.name == "Format Validation" for check in result.checks)


def test_scan_file_detects_malicious_onnx_pb_by_content(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    onnx_pb = tmp_path / "malicious.pb"
    create_mock_onnx(onnx_pb, op_type="PythonOp")

    result = scan_file(str(onnx_pb))

    assert result.scanner_name == "onnx"
    assert not any(check.name == "Format Validation" for check in result.checks)
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("op_type") == "PythonOp"
        for issue in result.issues
    )


def test_scan_file_does_not_route_incidental_onnx_pb_string(tmp_path: Path) -> None:
    near_match = tmp_path / "metadata.pb"
    near_match.write_bytes(bytes([0x0A, 0x04]) + b"onnx" + b"\x00" * 16)

    result = scan_file(str(near_match))

    assert result.scanner_name != "onnx"
    assert not any(check.name == "Python Operator Detection" for check in result.checks)


def test_scan_file_fails_closed_when_recognized_format_scanner_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unavailable_onnx = tmp_path / "model.onnx"
    unavailable_onnx.write_bytes(b"recognized-format")

    monkeypatch.setattr(core_module, "detect_file_format", lambda _path: "onnx")
    monkeypatch.setattr(core_module, "detect_file_format_from_magic", lambda _path: "onnx")
    monkeypatch.setattr(core_module, "detect_format_from_extension", lambda _path: "onnx")
    monkeypatch.setattr(core_module._registry, "load_scanner_by_id", lambda _scanner_id: None)
    monkeypatch.setattr(core_module._registry, "get_scanner_for_path", lambda *_args, **_kwargs: None)

    result = scan_file(str(unavailable_onnx))

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"
    assert "recognized_format_scanner_unavailable" in result.metadata["scan_outcome_reasons"]

    check = next(check for check in result.checks if check.name == "Format Detection")
    assert check.severity == IssueSeverity.INFO
    assert "Recognized format could not be scanned" in check.message
    assert check.details["format"] == "onnx"
    assert check.details["preferred_scanner_id"] == "onnx"

    aggregate = core_module.scan_model_directory_or_file(str(unavailable_onnx))
    assert aggregate.success is False
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_does_not_fail_closed_for_extension_only_recognized_format(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generic_pb = tmp_path / "metadata.pb"
    generic_pb.write_bytes(b"plain protobuf-ish bytes")

    monkeypatch.setattr(core_module._registry, "load_scanner_by_id", lambda _scanner_id: None)
    monkeypatch.setattr(core_module._registry, "get_scanner_for_path", lambda *_args, **_kwargs: None)

    result = scan_file(str(generic_pb))

    assert result.scanner_name == "unknown"
    assert result.success is True
    assert result.metadata.get("scan_outcome") != "inconclusive"
    assert not any(check.name == "Format Detection" for check in result.checks)


def test_scan_file_unavailable_recognized_format_result_is_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unavailable_onnx = tmp_path / "model.onnx"
    unavailable_onnx.write_bytes(b"recognized-format")
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    monkeypatch.setattr(core_module, "detect_file_format", lambda _path: "onnx")
    monkeypatch.setattr(core_module, "detect_file_format_from_magic", lambda _path: "onnx")
    monkeypatch.setattr(core_module, "detect_format_from_extension", lambda _path: "onnx")
    monkeypatch.setattr(core_module._registry, "load_scanner_by_id", lambda _scanner_id: None)
    monkeypatch.setattr(core_module._registry, "get_scanner_for_path", lambda *_args, **_kwargs: None)

    reset_cache_manager()
    try:
        first = scan_file(str(unavailable_onnx), config=config)
        second = scan_file(str(unavailable_onnx), config=config)

        assert first.success is False
        assert second.success is False
        assert first.metadata["scan_outcome"] == "inconclusive"
        assert second.metadata["scan_outcome"] == "inconclusive"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_fails_closed_when_xml_root_is_beyond_bounded_probe(tmp_path: Path) -> None:
    ambiguous_xml = tmp_path / "payload.txt"
    ambiguous_xml.write_text(
        "<?xml version='1.0'?><!--" + ("x" * ((1024 * 1024) + 64)) + "--><PMML version='4.4'></PMML>",
        encoding="utf-8",
    )

    result = scan_file(str(ambiguous_xml), config={"cache_scan_results": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["operational_error_reason"] == "xml_model_routing_incomplete"
    check = next(check for check in result.checks if check.name == "XML Model Routing")
    assert "bounded probe ended before the first structural root element" in check.message


def test_scan_file_incomplete_xml_routing_result_is_not_cached(tmp_path: Path) -> None:
    ambiguous_xml = tmp_path / "payload.txt"
    ambiguous_xml.write_text(
        "<?xml version='1.0'?><!--" + ("x" * ((1024 * 1024) + 64)) + "--><PMML version='4.4'></PMML>",
        encoding="utf-8",
    )
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        first = scan_file(str(ambiguous_xml), config=config)
        second = scan_file(str(ambiguous_xml), config=config)

        assert first.success is False
        assert second.success is False
        assert first.metadata["scan_outcome"] == "inconclusive"
        assert second.metadata["scan_outcome"] == "inconclusive"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_ignores_benign_onnx_token_near_match(tmp_path: Path) -> None:
    near_match = tmp_path / "note.payload"
    near_match.write_bytes(b"this documentation mentions onnx but is not a model")

    result = scan_file(str(near_match))

    assert result.scanner_name == "unknown"
    assert result.issues == []


def test_scan_file_routes_misnamed_numpy_by_header(tmp_path: Path) -> None:
    np = pytest.importorskip("numpy")

    disguised_numpy = tmp_path / "weights.payload"
    with disguised_numpy.open("wb") as handle:
        np.save(handle, np.array([1, 2, 3], dtype=np.float32), allow_pickle=False)

    result = scan_file(str(disguised_numpy))

    assert result.scanner_name == "numpy"


def test_scan_file_routes_misnamed_sevenzip_by_header(tmp_path: Path) -> None:
    py7zr = pytest.importorskip("py7zr")

    disguised_7z = tmp_path / "archive.jpg"
    payload = tmp_path / "payload.pkl"
    payload.write_bytes(_build_malicious_pickle())

    with py7zr.SevenZipFile(disguised_7z, "w") as archive:
        archive.write(payload, arcname="payload.pkl")

    result = scan_file(str(disguised_7z))

    assert result.scanner_name == "sevenzip"
    assert any("payload.pkl" in (issue.location or "") for issue in result.issues)


def test_scan_file_fails_closed_on_rar_archive(tmp_path: Path) -> None:
    rar_path = tmp_path / "archive.rar"
    rar_path.write_bytes(b"Rar!\x1a\x07\x01\x00" + b"\x00" * 32)

    result = scan_file(str(rar_path), config={"cache_scan_results": False})

    assert result.scanner_name == "rar"
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "rar_archive_unsupported" in result.metadata["scan_outcome_reasons"]
    rar_check = next(check for check in result.checks if check.name == "RAR Archive Support")
    assert rar_check.severity == IssueSeverity.INFO
    assert "RAR archive contents were not scanned" in rar_check.message


def test_scan_file_does_not_fail_closed_on_rar_suffix_near_match(tmp_path: Path) -> None:
    rar_path = tmp_path / "not_really.rar"
    rar_path.write_text("plain text, not a RAR archive\n", encoding="utf-8")

    result = scan_file(str(rar_path), config={"cache_scan_results": False})

    assert result.scanner_name != "rar"
    assert result.metadata.get("scan_outcome") != "inconclusive"
    assert not any(check.name == "RAR Archive Support" for check in result.checks)


def test_scan_file_rar_inconclusive_result_is_not_cached(tmp_path: Path) -> None:
    rar_path = tmp_path / "archive.rar"
    rar_path.write_bytes(b"Rar!\x1a\x07\x01\x00" + b"\x00" * 32)
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        first = scan_file(str(rar_path), config=config)
        second = scan_file(str(rar_path), config=config)

        assert first.success is False
        assert second.success is False
        assert first.metadata["scan_outcome"] == "inconclusive"
        assert second.metadata["scan_outcome"] == "inconclusive"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_routes_readme_documentation_to_metadata_scanner(tmp_path: Path) -> None:
    readme_path = tmp_path / "README.md"
    readme_path.write_text("# Model Card\n\nThis README is benign.\n")

    result = scan_file(str(readme_path), config={"cache_scan_results": False})

    assert result.scanner_name == "metadata"
    assert result.success is True


def test_scan_file_routes_model_config_json_to_manifest_scanner(tmp_path: Path) -> None:
    manifest_path = tmp_path / "config.json"
    manifest_path.write_text(
        json.dumps(
            {
                "model_type": "bert",
                "architectures": ["BertModel"],
                "hidden_size": 768,
            }
        )
    )

    result = scan_file(str(manifest_path), config={"cache_scan_results": False})

    assert result.scanner_name == "manifest"
    assert result.success is True


def test_scan_file_routes_manifest_owned_chat_templates_through_jinja_analysis(tmp_path: Path) -> None:
    manifest_path = tmp_path / "config.json"
    manifest_path.write_text(
        json.dumps(
            {
                "model_type": "llama",
                "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            }
        )
    )

    result = scan_file(str(manifest_path), config={"cache_scan_results": False})

    assert result.scanner_name == "manifest"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
