"""Core dispatch regressions for content-routed model formats."""

from __future__ import annotations

import base64
import json
import pickle
import zipfile
from pathlib import Path
from typing import Any

import pytest

from modelaudit.core import scan_file
from modelaudit.scanners.base import IssueSeverity, ScanResult

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
