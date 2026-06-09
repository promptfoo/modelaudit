import pickle
import struct
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any, BinaryIO

import pytest

from modelaudit import core
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.scanners.archive_dispatch import scan_nested_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.executorch_scanner import ExecuTorchScanner
from modelaudit.scanners.pytorch_binary_scanner import PyTorchBinaryScanner
from modelaudit.utils.file.detection import detect_file_format

_ASSETS_DIR = Path(__file__).resolve().parents[1] / "assets"


def create_executorch_binary(
    tmp_path: Path,
    *,
    identifier: bytes = b"ET12",
    filename: str = "program.pte",
    payload: bytes = b"",
) -> Path:
    binary_path = tmp_path / filename
    # Minimal valid FlatBuffer with the ExecuTorch file identifier.
    binary_path.write_bytes(b"\x0c\x00\x00\x00" + identifier + b"\x04\x00\x04\x00\x04\x00\x00\x00" + payload)
    return binary_path


def _valid_elf64_header() -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = (62).to_bytes(2, "little")
    header[20:24] = (1).to_bytes(4, "little")
    return bytes(header)


def create_executorch_archive(tmp_path: Path, *, malicious: bool = False) -> Path:
    zip_path = tmp_path / "model.ptl"
    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("version", "1")
        data: dict[str, object] = {"weights": [1, 2, 3]}
        if malicious:

            class Evil:
                def __reduce__(self):
                    return (eval, ("print('evil')",))

            data["malicious"] = Evil()
        z.writestr("bytecode.pkl", pickle.dumps(data))
    return zip_path


def _pickle_payload_with_eval(source: str) -> bytes:
    class EvalPayload:
        def __reduce__(self):
            return (eval, (source,))

    return pickle.dumps(EvalPayload())


def _corrupt_zip_member_crc(zip_path: Path, member_index: int) -> None:
    """Patch one ZIP member's local and central-directory CRC fields."""
    with zipfile.ZipFile(zip_path, "r") as zip_file:
        member_info = zip_file.infolist()[member_index]
        central_directory_offset = zip_file.start_dir

    archive_bytes = bytearray(zip_path.read_bytes())
    local_crc_offset = member_info.header_offset + 14
    original_crc = struct.unpack_from("<I", archive_bytes, local_crc_offset)[0]
    corrupt_crc = (original_crc ^ 0xFFFFFFFF) & 0xFFFFFFFF
    struct.pack_into("<I", archive_bytes, local_crc_offset, corrupt_crc)

    cursor = central_directory_offset
    while cursor < len(archive_bytes) and archive_bytes[cursor : cursor + 4] == b"PK\x01\x02":
        local_header_offset = struct.unpack_from("<I", archive_bytes, cursor + 42)[0]
        filename_len, extra_len, comment_len = struct.unpack_from("<HHH", archive_bytes, cursor + 28)
        if local_header_offset == member_info.header_offset:
            struct.pack_into("<I", archive_bytes, cursor + 16, corrupt_crc)
            zip_path.write_bytes(archive_bytes)
            return
        cursor += 46 + filename_len + extra_len + comment_len

    raise AssertionError(f"Unable to locate central directory entry at offset {member_info.header_offset}")


def _patch_zip_eocd_metadata(zip_path: Path, *, entry_count: int, directory_size: int | None = None) -> None:
    archive_bytes = bytearray(zip_path.read_bytes())
    eocd_offset = archive_bytes.rfind(b"PK\x05\x06")
    if eocd_offset < 0:
        raise AssertionError("Unable to locate ZIP end-of-central-directory record")
    struct.pack_into("<HH", archive_bytes, eocd_offset + 8, entry_count, entry_count)
    if directory_size is not None:
        struct.pack_into("<I", archive_bytes, eocd_offset + 12, directory_size)
    zip_path.write_bytes(archive_bytes)


def _zip_central_directory_size(zip_path: Path) -> int:
    archive_bytes = zip_path.read_bytes()
    eocd_offset = archive_bytes.rfind(b"PK\x05\x06")
    if eocd_offset < 0:
        raise AssertionError("Unable to locate ZIP end-of-central-directory record")
    return int(struct.unpack_from("<I", archive_bytes, eocd_offset + 12)[0])


def _insert_zip64_directory_metadata(zip_path: Path, *, entry_count: int, legacy_entry_count: int) -> None:
    archive_bytes = bytearray(zip_path.read_bytes())
    eocd_offset = archive_bytes.rfind(b"PK\x05\x06")
    if eocd_offset < 0:
        raise AssertionError("Unable to locate ZIP end-of-central-directory record")

    directory_size = struct.unpack_from("<I", archive_bytes, eocd_offset + 12)[0]
    directory_offset = struct.unpack_from("<I", archive_bytes, eocd_offset + 16)[0]
    zip64_eocd = struct.pack(
        "<4sQ2H2L4Q",
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        entry_count,
        entry_count,
        directory_size,
        directory_offset,
    )
    zip64_locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, eocd_offset, 1)
    legacy_eocd = bytearray(archive_bytes[eocd_offset:])
    struct.pack_into("<HH", legacy_eocd, 8, legacy_entry_count, legacy_entry_count)
    zip_path.write_bytes(archive_bytes[:eocd_offset] + zip64_eocd + zip64_locator + legacy_eocd)


def test_executorch_scanner_can_handle(tmp_path: Path) -> None:
    path = create_executorch_archive(tmp_path)
    assert ExecuTorchScanner.can_handle(str(path))
    other = tmp_path / "model.h5"
    other.write_bytes(b"data")
    assert not ExecuTorchScanner.can_handle(str(other))


def test_executorch_scanner_safe_model(tmp_path: Path) -> None:
    path = create_executorch_archive(tmp_path)
    scanner = ExecuTorchScanner()
    result = scanner.scan(str(path))
    assert result.success is True
    assert result.bytes_scanned > 0
    critical = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
    assert not critical


def test_executorch_scanner_malicious(tmp_path: Path) -> None:
    path = create_executorch_archive(tmp_path, malicious=True)
    scanner = ExecuTorchScanner()
    result = scanner.scan(str(path))
    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)
    assert any("eval" in i.message.lower() for i in result.issues)


def test_executorch_scanner_invalid_zip(tmp_path: Path) -> None:
    file_path = tmp_path / "bad.ptl"
    file_path.write_bytes(b"not zip")
    scanner = ExecuTorchScanner()
    result = scanner.scan(str(file_path))
    assert not result.success
    assert any("executorch" in i.message.lower() for i in result.issues)


def test_executorch_scanner_accepts_binary_program_header(tmp_path: Path) -> None:
    file_path = create_executorch_binary(tmp_path)
    scanner = ExecuTorchScanner()
    result = scanner.scan(str(file_path))
    assert result.success is True
    assert result.bytes_scanned == file_path.stat().st_size
    assert not any("not a valid executorch archive" in issue.message.lower() for issue in result.issues)
    assert not any("file type validation failed" in issue.message.lower() for issue in result.issues)


def test_executorch_scanner_accepts_versioned_binary_program_header(tmp_path: Path) -> None:
    file_path = create_executorch_binary(tmp_path, identifier=b"ET13")
    scanner = ExecuTorchScanner()
    result = scanner.scan(str(file_path))

    assert result.success is True
    assert result.bytes_scanned == file_path.stat().st_size
    assert not result.issues


def test_executorch_scanner_analyzes_raw_payload_in_valid_binary_program(tmp_path: Path) -> None:
    file_path = create_executorch_binary(
        tmp_path,
        identifier=b"ET13",
        payload=b"\x00" * 128 + b"os.system('id')" + b"\x00" * 64 + _valid_elf64_header() + b"\x00" * 64,
    )

    result = ExecuTorchScanner().scan(str(file_path))

    assert result.scanner_name == "executorch"
    assert result.metadata["supplemental_scanners"] == ["pytorch_binary"]
    assert result.bytes_scanned == file_path.stat().st_size
    assert any(
        check.name == "Embedded Code Pattern Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("pattern") == "os.system"
        for check in result.checks
    )
    assert any(
        issue.rule_code == "S501" and "Linux executable" in issue.message and issue.severity == IssueSeverity.CRITICAL
        for issue in result.issues
    )
    assert result.success is False

    aggregate = core.scan_model_directory_or_file(str(file_path), cache_scan_results=False)

    assert aggregate.files_scanned == 1
    assert core.determine_exit_code(aggregate) == 1
    assert any("Linux executable" in issue.message for issue in aggregate.issues)


def test_executorch_scanner_analyzes_raw_payload_in_direct_bin_scan(tmp_path: Path) -> None:
    file_path = create_executorch_binary(
        tmp_path,
        identifier=b"ET13",
        filename="program.bin",
        payload=b"\x00" * 128 + b"os.system('id')" + b"\x00" * 128,
    )

    result = ExecuTorchScanner().scan(str(file_path))

    assert result.scanner_name == "executorch"
    assert result.metadata["supplemental_scanners"] == ["pytorch_binary"]
    assert any(
        check.name == "Embedded Code Pattern Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("pattern") == "os.system"
        for check in result.checks
    )


@pytest.mark.parametrize("dispatch", ["core", "nested"])
def test_executorch_bin_overlap_runs_raw_analysis_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dispatch: str,
) -> None:
    file_path = create_executorch_binary(
        tmp_path,
        identifier=b"ET13",
        filename="program.bin",
        payload=b"\x00" * 128 + b"os.system('id')" + b"\x00" * 128,
    )
    original_scan = PyTorchBinaryScanner.scan
    scan_calls = 0

    def counted_scan(self: PyTorchBinaryScanner, path: str) -> ScanResult:
        nonlocal scan_calls
        scan_calls += 1
        return original_scan(self, path)

    monkeypatch.setattr(PyTorchBinaryScanner, "scan", counted_scan)

    if dispatch == "core":
        result = core.scan_file(str(file_path), config={"cache_scan_results": False})
    else:
        result = scan_nested_file(str(file_path), {"cache_enabled": False})

    assert result.scanner_name == "pytorch_binary"
    assert result.metadata["supplemental_scanners"] == ["executorch"]
    assert scan_calls == 1
    assert (
        sum(
            check.name == "Embedded Code Pattern Detection"
            and check.status == CheckStatus.FAILED
            and check.details.get("pattern") == "os.system"
            for check in result.checks
        )
        == 1
    )


@pytest.mark.parametrize("filename", ["program.pte", "program.bin"])
def test_executorch_scanner_raw_payload_analysis_ignores_benign_near_match(
    tmp_path: Path,
    filename: str,
) -> None:
    file_path = create_executorch_binary(
        tmp_path,
        identifier=b"ET13",
        filename=filename,
        payload=b"\x00" * 128 + b"operator=acos.systematic_normalization" + b"\x00" * 128,
    )

    result = ExecuTorchScanner().scan(str(file_path))

    assert result.success is True
    assert result.metadata["supplemental_scanners"] == ["pytorch_binary"]
    assert result.bytes_scanned == file_path.stat().st_size
    assert not result.issues
    assert any(
        check.name == "Embedded Code Pattern Detection" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


def test_executorch_header_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = create_executorch_binary(tmp_path)

    def raise_os_error(_path: str, length: int = 4) -> bytes:
        raise OSError(f"simulated ExecuTorch header read failure at {length} bytes")

    monkeypatch.setattr(ExecuTorchScanner, "_read_header", staticmethod(raise_os_error))

    direct = ExecuTorchScanner().scan(str(file_path))
    monkeypatch.setattr(ExecuTorchScanner, "can_handle", classmethod(lambda _cls, _path: True))
    aggregate = core.scan_model_directory_or_file(str(file_path), cache_scan_results=False)

    assert direct.success is False
    assert direct.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_read_failed" in direct.metadata.get("scan_outcome_reasons", [])
    assert any(
        check.name == "ExecuTorch File Read"
        and "Unable to read ExecuTorch content" in check.message
        and check.severity == IssueSeverity.INFO
        and check.details.get("scan_outcome_reason") == "executorch_read_failed"
        for check in direct.checks
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
    assert aggregate.file_metadata[str(file_path)].get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert core.determine_exit_code(aggregate) == 2


def test_executorch_read_failure_result_is_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = create_executorch_binary(tmp_path)
    cache_dir = tmp_path / "cache"

    def raise_os_error(_path: str, length: int = 4) -> bytes:
        raise OSError(f"simulated ExecuTorch header read failure at {length} bytes")

    monkeypatch.setattr(ExecuTorchScanner, "_read_header", staticmethod(raise_os_error))
    monkeypatch.setattr(ExecuTorchScanner, "can_handle", classmethod(lambda _cls, _path: True))

    reset_cache_manager()
    try:
        first = core.scan_model_directory_or_file(
            str(file_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = core.scan_model_directory_or_file(
            str(file_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(file_path)]
            assert aggregate.success is False
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert "executorch_read_failed" in metadata["scan_outcome_reasons"]
            assert any("Unable to read ExecuTorch content" in issue.message for issue in aggregate.issues)
            assert core.determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_executorch_structure_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = create_executorch_binary(tmp_path)

    def raise_os_error(_path: str, *, propagate_io_errors: bool = False) -> bool:
        assert propagate_io_errors is True
        raise OSError("simulated ExecuTorch structure read failure")

    monkeypatch.setattr("modelaudit.scanners.executorch_scanner._is_valid_executorch_binary", raise_os_error)

    result = ExecuTorchScanner().scan(str(file_path))

    assert result.success is False
    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_read_failed" in result.metadata.get("scan_outcome_reasons", [])
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_renamed_executorch_binary_routes_through_directory_scan(tmp_path: Path) -> None:
    file_path = create_executorch_binary(tmp_path, filename="program.jpg")

    assert ExecuTorchScanner.can_handle(str(file_path))
    assert detect_file_format(str(file_path)) == "executorch"
    assert core.scan_file(str(file_path)).scanner_name == "executorch"

    directory = core.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)
    assert directory.files_scanned == 1
    assert "executorch" in directory.scanner_names


def test_renamed_executorch_structure_read_failure_routes_to_inconclusive_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = create_executorch_binary(tmp_path, filename="program.jpg")

    def fail_structural_probe(_path: str | Path, *, propagate_io_errors: bool = False) -> bool:
        if propagate_io_errors:
            raise OSError("simulated renamed ExecuTorch structure read failure")
        return False

    monkeypatch.setattr("modelaudit.utils.file.detection._is_valid_executorch_binary", fail_structural_probe)
    monkeypatch.setattr("modelaudit.scanners.executorch_scanner._is_valid_executorch_binary", fail_structural_probe)

    assert detect_file_format(str(file_path)) == "executorch"

    directory = core.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)
    metadata = directory.file_metadata[str(file_path)]

    assert directory.files_scanned == 1
    assert "executorch" in directory.scanner_names
    assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_read_failed" in metadata["scan_outcome_reasons"]
    assert core.determine_exit_code(directory) == 2


def test_renamed_executorch_near_match_remains_skipped(tmp_path: Path) -> None:
    file_path = create_executorch_binary(tmp_path, identifier=b"ETXX", filename="program.jpg")

    assert not ExecuTorchScanner.can_handle(str(file_path))
    assert detect_file_format(str(file_path)) == "unknown"

    directory = core.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)
    assert directory.files_scanned == 0


def test_executorch_scanner_rejects_invalid_binary_signature_match(tmp_path: Path) -> None:
    file_path = tmp_path / "fake-program.pte"
    file_path.write_bytes(b"JUNKET12notflatbufferatall")

    scanner = ExecuTorchScanner()
    result = scanner.scan(str(file_path))

    assert result.success is False
    assert any(issue.rule_code == "S104" for issue in result.issues)


def test_executorch_scanner_scans_polyglot_binary_zip_payload(tmp_path: Path) -> None:
    file_path = create_executorch_binary(tmp_path)
    with zipfile.ZipFile(file_path, "a") as archive:
        archive.writestr("evil.py", "print('evil')")

    scanner = ExecuTorchScanner()
    result = scanner.scan(str(file_path))

    assert any(check.name == "ExecuTorch Binary Format Validation" for check in result.checks)
    assert any(issue.rule_code == "S507" for issue in result.issues)
    assert any(issue.rule_code == "S104" for issue in result.issues)


@pytest.mark.parametrize(
    ("payload", "expected_failed_pattern"),
    [
        (b"\x00" * 128 + b"os.system('id')" + b"\x00" * 128, "os.system"),
        (b"\x00" * 128 + b"operator=acos.systematic_normalization" + b"\x00" * 128, None),
    ],
    ids=["malicious-raw-prefix", "benign-raw-near-match"],
)
def test_executorch_scanner_analyzes_raw_payload_in_binary_zip_polyglot(
    tmp_path: Path,
    payload: bytes,
    expected_failed_pattern: str | None,
) -> None:
    file_path = create_executorch_binary(tmp_path, identifier=b"ET13", payload=payload)
    with zipfile.ZipFile(file_path, "a") as archive:
        archive.writestr("version", "1")

    result = ExecuTorchScanner().scan(str(file_path))

    assert result.metadata["supplemental_scanners"] == ["pytorch_binary"]
    failed_patterns = {
        str(check.details.get("pattern"))
        for check in result.checks
        if check.name == "Embedded Code Pattern Detection" and check.status == CheckStatus.FAILED
    }
    if expected_failed_pattern is None:
        assert result.success is True
        assert not failed_patterns
    else:
        assert result.has_warnings is True
        assert expected_failed_pattern in failed_patterns


def test_executorch_scanner_scans_stubbed_zip_payload(tmp_path: Path) -> None:
    file_path = create_executorch_archive(tmp_path, malicious=True)
    file_path.write_bytes(b"launcher-stub" + file_path.read_bytes())

    assert zipfile.is_zipfile(file_path)

    result = ExecuTorchScanner().scan(str(file_path))

    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)


@pytest.mark.parametrize("dispatch", ["direct", "core"])
def test_executorch_scanner_analyzes_raw_payload_in_executable_prefixed_zip(
    tmp_path: Path,
    dispatch: str,
) -> None:
    file_path = create_executorch_archive(tmp_path)
    file_path.write_bytes(
        _valid_elf64_header() + b"\x00" * 64 + b"os.system('id')" + b"\x00" * 64 + file_path.read_bytes()
    )

    if dispatch == "direct":
        result = ExecuTorchScanner().scan(str(file_path))
    else:
        result = core.scan_file(str(file_path), config={"cache_scan_results": False})

    assert "pytorch_binary" in result.metadata["supplemental_scanners"]
    assert any(
        check.name == "Embedded Code Pattern Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("pattern") == "os.system"
        for check in result.checks
    )
    assert any(
        issue.rule_code == "S501" and "Linux executable" in issue.message and issue.severity == IssueSeverity.CRITICAL
        for issue in result.issues
    )
    assert result.success is False


@pytest.mark.parametrize("dispatch", ["direct", "core"])
def test_executorch_scanner_raw_payload_ignores_benign_prefixed_zip_near_match(
    tmp_path: Path,
    dispatch: str,
) -> None:
    file_path = create_executorch_archive(tmp_path)
    file_path.write_bytes(b"launcher=acos.systematic_normalization\x00" + b"\x00" * 128 + file_path.read_bytes())

    if dispatch == "direct":
        result = ExecuTorchScanner().scan(str(file_path))
    else:
        result = core.scan_file(str(file_path), config={"cache_scan_results": False})

    assert "pytorch_binary" in result.metadata["supplemental_scanners"]
    assert result.success is True
    assert not any(
        check.name == "Embedded Code Pattern Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert not any(issue.rule_code == "S501" for issue in result.issues)


def test_executorch_scanner_preserves_legacy_pickle_rule_codes_for_embedded_members(tmp_path: Path) -> None:
    fixture_path = _ASSETS_DIR / "samples" / "pickles" / "decode_exec_chain.pkl"
    model_path = tmp_path / "decode_exec_chain.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("bytecode.pkl", fixture_path.read_bytes())

    result = ExecuTorchScanner().scan(str(model_path))

    assert any(
        issue.rule_code == "S604" and "S104" in issue.details.get("legacy_rule_aliases", []) for issue in result.issues
    )


def test_executorch_scanner_streams_pickle_members_without_zip_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_executorch_archive(tmp_path, malicious=True)
    original_read = zipfile.ZipFile.read

    def reject_zip_read(self: zipfile.ZipFile, name: str, pwd: bytes | None = None) -> bytes:
        if name.endswith(".pkl"):
            raise AssertionError("ExecuTorch pickle members should be scanned from z.open(), not z.read()")
        return original_read(self, name, pwd)

    monkeypatch.setattr(zipfile.ZipFile, "read", reject_zip_read)

    result = ExecuTorchScanner().scan(str(model_path))

    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_executorch_zip_entry_preflight_fails_before_archive_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "entry-bomb.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("first.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("second.pkl", _pickle_payload_with_eval("print('evil')"))

    def reject_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("entry-count preflight should reject before ZipFile opens")

    monkeypatch.setattr(zipfile, "ZipFile", reject_zipfile_open)

    result = ExecuTorchScanner(config={"max_executorch_zip_entries": 2}).scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_zip_entry_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "ExecuTorch ZIP Entry Count Preflight"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S410"
        and check.details["entry_count"] == 3
        and check.details["phase"] == "pre_open"
        for check in result.checks
    )


def test_executorch_zip_entry_limit_allows_exact_limit(tmp_path: Path) -> None:
    model_path = create_executorch_archive(tmp_path)

    result = ExecuTorchScanner(config={"max_executorch_zip_entries": 2}).scan(str(model_path))

    assert result.success is True
    assert result.metadata["executorch_zip_entry_count"] == 2
    assert result.metadata["max_executorch_zip_entries"] == 2


def test_executorch_zip_entry_preflight_counts_central_directory_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "forged-entry-count.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("first.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("second.pkl", _pickle_payload_with_eval("print('evil')"))
    _patch_zip_eocd_metadata(model_path, entry_count=1)

    def reject_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("central-directory preflight should reject before ZipFile opens")

    monkeypatch.setattr(zipfile, "ZipFile", reject_zipfile_open)

    result = ExecuTorchScanner(config={"max_executorch_zip_entries": 2}).scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_zip_entry_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "ExecuTorch ZIP Entry Count Preflight"
        and check.details["entry_count"] == 3
        and check.details["phase"] == "pre_open"
        for check in result.checks
    )


def test_executorch_zip_entry_preflight_rejects_truncated_central_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "forged-directory-size.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("benign.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("hidden.pkl", _pickle_payload_with_eval("print('evil')"))
    _patch_zip_eocd_metadata(model_path, entry_count=1, directory_size=0)

    def reject_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("invalid central-directory metadata should fail before ZipFile opens")

    monkeypatch.setattr(zipfile, "ZipFile", reject_zipfile_open)

    result = ExecuTorchScanner(config={"max_executorch_zip_entries": 2}).scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_zip_central_directory_invalid" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "ExecuTorch ZIP Central Directory Preflight"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S902"
        and check.details["entry_count"] == 1
        and check.details["phase"] == "pre_open"
        for check in result.checks
    )


def test_executorch_zip_entry_preflight_allows_trailing_bytes_without_opening_large_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "trailing-bytes.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("first.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("second.pkl", _pickle_payload_with_eval("print('evil')"))
    model_path.write_bytes(model_path.read_bytes() + b"\x00")
    assert zipfile.is_zipfile(model_path)

    def reject_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("trailing bytes must not bypass the entry-count preflight")

    monkeypatch.setattr(zipfile, "ZipFile", reject_zipfile_open)

    result = ExecuTorchScanner(config={"max_executorch_zip_entries": 2}).scan(str(model_path))

    assert result.success is False
    assert "executorch_zip_entry_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "ExecuTorch ZIP Entry Count Preflight" and check.details["entry_count"] == 3
        for check in result.checks
    )


def test_executorch_zip_entry_preflight_uses_zip64_count_with_legacy_near_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "zip64-count.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("first.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("second.pkl", _pickle_payload_with_eval("print('evil')"))
    _insert_zip64_directory_metadata(model_path, entry_count=3, legacy_entry_count=1)
    with zipfile.ZipFile(model_path, "r") as zipf:
        assert len(zipf.infolist()) == 3

    def reject_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("ZIP64 entry count must be checked before ZipFile opens")

    monkeypatch.setattr(zipfile, "ZipFile", reject_zipfile_open)

    result = ExecuTorchScanner(config={"max_executorch_zip_entries": 2}).scan(str(model_path))

    assert result.success is False
    assert "executorch_zip_entry_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "ExecuTorch ZIP Entry Count Preflight" and check.details["entry_count"] == 3
        for check in result.checks
    )


def test_executorch_zip_entry_preflight_rejects_eocd_shaped_comment_suffix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "ambiguous-eocd.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("hidden.pkl", _pickle_payload_with_eval("print('evil')"))
        zipf.comment = b"prefixPK\x05\x06" + b"\x00" * 18
    with zipfile.ZipFile(model_path, "r") as zipf:
        assert zipf.namelist() == []

    def reject_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("ambiguous EOCD metadata should fail before ZipFile opens")

    monkeypatch.setattr(zipfile, "ZipFile", reject_zipfile_open)

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.success is False
    assert "executorch_zip_central_directory_invalid" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "ExecuTorch ZIP Central Directory Preflight"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S902"
        for check in result.checks
    )


def test_executorch_zip_entry_preflight_rejects_trailing_eocd_overlay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "trailing-eocd-overlay.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("hidden.pkl", _pickle_payload_with_eval("print('evil')"))
    model_path.write_bytes(model_path.read_bytes() + b"PK\x05\x06" + b"\x00" * 18)
    with zipfile.ZipFile(model_path, "r") as zipf:
        assert zipf.namelist() == []

    def reject_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("ambiguous trailing EOCD overlay should fail before ZipFile opens")

    monkeypatch.setattr(zipfile, "ZipFile", reject_zipfile_open)

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_zip_central_directory_invalid" in result.metadata["scan_outcome_reasons"]


def test_executorch_zip_entry_preflight_ignores_unstructured_member_eocd_near_match(tmp_path: Path) -> None:
    model_path = tmp_path / "member-eocd-near-match.ptl"
    eocd_near_match = struct.pack(
        "<4s4H2LH",
        b"PK\x05\x06",
        0,
        0,
        0xFFFE,
        0xFFFE,
        0xFFFFFF00,
        0,
        0,
    )
    with zipfile.ZipFile(model_path, "w", compression=zipfile.ZIP_STORED) as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("bytecode.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("metadata.bin", eocd_near_match)

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.success is True
    assert "executorch_zip_central_directory_invalid" not in result.metadata.get("scan_outcome_reasons", [])


def test_executorch_zip_entry_preflight_rejects_repeated_digital_signatures() -> None:
    repeated_signatures = BytesIO((b"PK\x05\x05\x00\x00") * 2)

    entry_count, parsed_completely = ExecuTorchScanner._count_central_directory_entries(
        repeated_signatures,
        directory_start=0,
        directory_size=12,
        entry_limit=10,
    )

    assert entry_count == 0
    assert parsed_completely is False
    assert repeated_signatures.tell() == 6


def test_executorch_zip_central_directory_size_fails_before_archive_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "large-central-directory.ptl"
    member = zipfile.ZipInfo("version")
    member.comment = b"A" * 256
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr(member, "1")

    def reject_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("central-directory size preflight should reject before ZipFile opens")

    def reject_directory_parse(*_args: Any, **_kwargs: Any) -> tuple[int, bool]:
        raise AssertionError("central-directory size preflight should reject before parsing directory entries")

    monkeypatch.setattr(zipfile, "ZipFile", reject_zipfile_open)
    monkeypatch.setattr(ExecuTorchScanner, "_count_central_directory_entries", staticmethod(reject_directory_parse))

    result = ExecuTorchScanner(config={"max_executorch_zip_central_directory_size": 128}).scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_zip_central_directory_size_limit" in result.metadata["scan_outcome_reasons"]
    assert result.metadata["executorch_zip_central_directory_size"] > 128
    assert any(
        check.name == "ExecuTorch ZIP Central Directory Size Preflight"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S410"
        and check.details["central_directory_size"] > 128
        and check.details["max_central_directory_size"] == 128
        and check.details["phase"] == "pre_open"
        for check in result.checks
    )


def test_executorch_zip_central_directory_size_allows_exact_limit(tmp_path: Path) -> None:
    model_path = create_executorch_archive(tmp_path)
    central_directory_size = _zip_central_directory_size(model_path)

    result = ExecuTorchScanner(config={"max_executorch_zip_central_directory_size": central_directory_size}).scan(
        str(model_path)
    )

    assert result.success is True
    assert result.metadata["executorch_zip_central_directory_size"] == central_directory_size
    assert result.metadata["max_executorch_zip_central_directory_size"] == central_directory_size
    assert result.bytes_scanned > 0


def test_executorch_zip_preflight_and_zipfile_share_one_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_executorch_archive(tmp_path)
    original_read_entry_count = ExecuTorchScanner._read_zip_entry_count
    original_zipfile = zipfile.ZipFile
    preflight_handle: BinaryIO | None = None

    def record_preflight_handle(
        _cls: type[ExecuTorchScanner],
        handle: BinaryIO,
        file_size: int,
        entry_limit: int,
        directory_limit: int,
    ) -> tuple[int, int, bool] | None:
        nonlocal preflight_handle
        preflight_handle = handle
        return original_read_entry_count(handle, file_size, entry_limit, directory_limit)

    def verify_zipfile_handle(file: Any, *args: Any, **kwargs: Any) -> zipfile.ZipFile:
        assert preflight_handle is not None
        assert file is preflight_handle
        return original_zipfile(preflight_handle, *args, **kwargs)

    monkeypatch.setattr(ExecuTorchScanner, "_read_zip_entry_count", classmethod(record_preflight_handle))
    monkeypatch.setattr(zipfile, "ZipFile", verify_zipfile_handle)

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.success is True
    assert preflight_handle is not None
    assert preflight_handle.closed is True


def test_executorch_zip_preflight_read_failure_stops_before_zipfile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_executorch_archive(tmp_path)

    def fail_preflight_read(*_args: Any, **_kwargs: Any) -> tuple[int, int, bool] | None:
        raise OSError("simulated central-directory read failure")

    def reject_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("ZipFile must not open after a preflight read failure")

    monkeypatch.setattr(ExecuTorchScanner, "_read_zip_entry_count", classmethod(fail_preflight_read))
    monkeypatch.setattr(zipfile, "ZipFile", reject_zipfile_open)

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.success is False
    assert "executorch_read_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "ExecuTorch File Read"
        and check.details["exception_type"] == "OSError"
        and check.details["scan_outcome_reason"] == "executorch_read_failed"
        for check in result.checks
    )


def test_executorch_zip_entry_limit_fails_after_open_when_preflight_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "entry-bomb-post-open.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("first.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("second.pkl", _pickle_payload_with_eval("print('evil')"))

    monkeypatch.setattr(
        ExecuTorchScanner,
        "_read_zip_entry_count",
        classmethod(lambda _cls, _path, _size, _entry_limit, _directory_limit: None),
    )

    result = ExecuTorchScanner(config={"max_executorch_zip_entries": 2}).scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_zip_entry_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "ExecuTorch ZIP Entry Count Limit"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S410"
        and check.details["entry_count"] == 3
        and check.details["phase"] == "post_open"
        for check in result.checks
    )


def test_executorch_zip_aggregate_limit_fails_before_member_content_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "split-size-bomb.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("bytecode.pkl", _pickle_payload_with_eval("print('evil')"))
        zipf.writestr("weights.bin", b"A" * 32)

    scanner = ExecuTorchScanner(config={"max_executorch_zip_total_uncompressed_size": 16})
    assert scanner.pickle_scanner is not None

    def reject_pickle_scan(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("aggregate-size preflight should stop before scanning pickle members")

    monkeypatch.setattr(scanner.pickle_scanner, "scan_stream", reject_pickle_scan)

    result = scanner.scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_zip_total_uncompressed_size_limit" in result.metadata["scan_outcome_reasons"]
    assert result.metadata["executorch_zip_uncompressed_size"] > 16
    assert any(
        check.name == "ExecuTorch ZIP Aggregate Size Limit"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S410"
        and check.details["archive_uncompressed_size"] > 16
        and check.details["max_total_uncompressed_size"] == 16
        for check in result.checks
    )


@pytest.mark.parametrize("malicious_first", [True, False])
def test_executorch_zip_aggregate_limit_preserves_scannable_member_detection(
    tmp_path: Path,
    malicious_first: bool,
) -> None:
    model_path = tmp_path / "mixed-aggregate.ptl"
    malicious_payload = _pickle_payload_with_eval("print('evil')")
    benign_payload = pickle.dumps({"weights": b"A" * 4096})
    members = [
        ("malicious.pkl", malicious_payload),
        ("benign.pkl", benign_payload),
    ]
    if not malicious_first:
        members.reverse()

    with zipfile.ZipFile(model_path, "w", compression=zipfile.ZIP_STORED) as zipf:
        zipf.writestr("version", "1")
        for name, payload in members:
            zipf.writestr(name, payload)

    result = ExecuTorchScanner(config={"max_executorch_zip_total_uncompressed_size": len(malicious_payload)}).scan(
        str(model_path)
    )

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_zip_total_uncompressed_size_limit" in result.metadata["scan_outcome_reasons"]
    assert result.bytes_scanned == len(malicious_payload)
    assert result.metadata["executorch_zip_skipped_pickle_files"] == ["benign.pkl"]
    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)


def test_executorch_zip_aggregate_limit_allows_benign_near_match(tmp_path: Path) -> None:
    model_path = tmp_path / "aggregate-near-match.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("bytecode.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("weights.bin", b"A" * 8)

    with zipfile.ZipFile(model_path, "r") as zipf:
        aggregate_limit = sum(entry.file_size for entry in zipf.infolist() if not entry.is_dir())

    result = ExecuTorchScanner(config={"max_executorch_zip_total_uncompressed_size": aggregate_limit}).scan(
        str(model_path)
    )

    assert result.success is True
    assert result.metadata["executorch_zip_uncompressed_size"] == aggregate_limit
    assert result.bytes_scanned > 0
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        check.name == "ExecuTorch ZIP Aggregate Size Limit"
        and check.status == CheckStatus.PASSED
        and check.details["archive_uncompressed_size"] == aggregate_limit
        for check in result.checks
    )


@pytest.mark.parametrize(
    "config",
    [
        {"max_executorch_zip_total_uncompressed_size": False},
        {"max_executorch_zip_total_uncompressed_size": 0.0},
        {"max_zip_total_uncompressed_size": False},
        {"max_executorch_zip_total_uncompressed_size": 0, "max_total_size": False},
    ],
)
def test_executorch_zip_invalid_zero_like_aggregate_limits_use_safe_default(config: dict[str, Any]) -> None:
    assert (
        ExecuTorchScanner._get_max_total_uncompressed_size_from_config(config)
        == ExecuTorchScanner.DEFAULT_MAX_TOTAL_UNCOMPRESSED_SIZE
    )


def test_executorch_zip_integer_zero_aggregate_limit_remains_unlimited() -> None:
    assert (
        ExecuTorchScanner._get_max_total_uncompressed_size_from_config(
            {"max_executorch_zip_total_uncompressed_size": 0}
        )
        == ExecuTorchScanner.UNLIMITED_ARCHIVE_SIZE
    )


def test_executorch_zip_pickle_compression_ratio_fails_before_member_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "compression-bomb.ptl"
    payload = pickle.dumps({"weights": b"A" * (2 * 1024 * 1024)})
    with zipfile.ZipFile(model_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("bytecode.pkl", payload)

    scanner = ExecuTorchScanner()
    assert scanner.pickle_scanner is not None

    def reject_pickle_scan(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("compression-ratio preflight should stop before scanning pickle members")

    monkeypatch.setattr(scanner.pickle_scanner, "scan_stream", reject_pickle_scan)

    result = scanner.scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_zip_compression_ratio_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "ExecuTorch ZIP Pickle Compression Ratio Limit"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S410"
        and check.details["compression_ratio"] > check.details["max_compression_ratio"]
        for check in result.checks
    )


def test_executorch_zip_pickle_compression_ratio_allows_small_benign_member(tmp_path: Path) -> None:
    model_path = tmp_path / "small-compressible.ptl"
    payload = pickle.dumps({"weights": b"A" * (512 * 1024)})
    with zipfile.ZipFile(model_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("bytecode.pkl", payload)

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.success is True
    assert result.bytes_scanned == len(payload)
    assert "executorch_zip_compression_ratio_limit" not in result.metadata.get("scan_outcome_reasons", [])


def test_executorch_zip_pickle_compression_ratio_rejects_split_small_members() -> None:
    scanner = ExecuTorchScanner()
    result = scanner._create_result()
    pickle_entries = []
    for index in range(2):
        entry = zipfile.ZipInfo(f"split-{index}.pkl")
        entry.file_size = 600 * 1024
        entry.compress_size = 1024
        pickle_entries.append(entry)

    scannable_entries, analysis_incomplete = scanner._check_pickle_member_budgets(
        result,
        "split-bomb.ptl",
        pickle_entries,
    )

    assert scannable_entries == []
    assert analysis_incomplete is True
    assert "executorch_zip_compression_ratio_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "ExecuTorch ZIP Pickle Compression Ratio Limit"
        and check.details["aggregate_small_member_check"] is True
        and check.details["member_count"] == 2
        for check in result.checks
    )


def test_executorch_zip_pickle_compression_ratio_allows_exact_ratio_limit() -> None:
    scanner = ExecuTorchScanner()
    result = scanner._create_result()
    entry = zipfile.ZipInfo("exact-ratio.pkl")
    entry.file_size = 1_048_600
    entry.compress_size = 10_486

    scannable_entries, analysis_incomplete = scanner._check_pickle_member_budgets(
        result,
        "exact-ratio.ptl",
        [entry],
    )

    assert scannable_entries == [entry]
    assert analysis_incomplete is False


def test_executorch_zip_pickle_member_size_fails_before_member_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_executorch_archive(tmp_path)
    scanner = ExecuTorchScanner()
    assert scanner.pickle_scanner is not None
    monkeypatch.setattr(scanner.pickle_scanner, "max_file_read_size", 16)

    def reject_pickle_scan(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("pickle member size preflight should stop before scanning")

    monkeypatch.setattr(scanner.pickle_scanner, "scan_stream", reject_pickle_scan)

    result = scanner.scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_zip_pickle_member_size_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "ExecuTorch ZIP Pickle Member Size Limit"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S410"
        and check.details["uncompressed_size"] > check.details["max_pickle_member_size"]
        for check in result.checks
    )


def test_executorch_zip_pickle_member_size_preserves_safe_member_detection(tmp_path: Path) -> None:
    model_path = tmp_path / "mixed-size.ptl"
    malicious_payload = _pickle_payload_with_eval("print('evil')")
    oversized_payload = pickle.dumps({"weights": b"A" * 4096})
    with zipfile.ZipFile(model_path, "w", compression=zipfile.ZIP_STORED) as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("malicious.pkl", malicious_payload)
        zipf.writestr("oversized.pkl", oversized_payload)

    scanner = ExecuTorchScanner()
    assert scanner.pickle_scanner is not None
    scanner.pickle_scanner.max_file_read_size = len(malicious_payload)

    result = scanner.scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_zip_pickle_member_size_limit" in result.metadata["scan_outcome_reasons"]
    assert result.bytes_scanned == len(malicious_payload)
    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)


def test_executorch_zip_pickle_compression_ratio_preserves_safe_member_detection(tmp_path: Path) -> None:
    model_path = tmp_path / "mixed-ratio.ptl"
    malicious_payload = _pickle_payload_with_eval("print('evil')")
    compressed_payload = pickle.dumps({"weights": b"A" * (2 * 1024 * 1024)})
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("malicious.pkl", malicious_payload, compress_type=zipfile.ZIP_STORED)
        zipf.writestr("compressed.pkl", compressed_payload, compress_type=zipfile.ZIP_DEFLATED)

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_zip_compression_ratio_limit" in result.metadata["scan_outcome_reasons"]
    assert result.bytes_scanned == len(malicious_payload)
    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)


def test_executorch_zip_pickle_member_size_allows_exact_limit() -> None:
    scanner = ExecuTorchScanner()
    assert scanner.pickle_scanner is not None
    scanner.pickle_scanner.max_file_read_size = 16
    result = scanner._create_result()
    entry = zipfile.ZipInfo("exact-size.pkl")
    entry.file_size = 16
    entry.compress_size = 16

    scannable_entries, analysis_incomplete = scanner._check_pickle_member_budgets(
        result,
        "exact-size.ptl",
        [entry],
    )

    assert scannable_entries == [entry]
    assert analysis_incomplete is False


@pytest.mark.parametrize(
    ("config", "reason"),
    [
        ({"max_executorch_zip_entries": 2}, "executorch_zip_entry_limit"),
        (
            {"max_executorch_zip_total_uncompressed_size": 16},
            "executorch_zip_total_uncompressed_size_limit",
        ),
    ],
)
def test_executorch_zip_budget_failure_propagates_exit_code_and_is_not_cached(
    tmp_path: Path,
    config: dict[str, int],
    reason: str,
) -> None:
    model_path = tmp_path / f"{reason}.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("bytecode.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("weights.bin", b"A" * 32)
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        for _ in range(2):
            scan_kwargs: dict[str, Any] = {
                "cache_enabled": True,
                "cache_dir": str(cache_dir),
                "min_cache_file_size": 0,
                **config,
            }
            aggregate = core.scan_model_directory_or_file(str(model_path), **scan_kwargs)
            metadata = aggregate.file_metadata[str(model_path)]
            assert aggregate.success is True
            assert metadata["analysis_incomplete"] is True
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert reason in metadata["scan_outcome_reasons"]
            assert core.determine_exit_code(aggregate) == 1
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_executorch_duplicate_pickle_members_scan_malicious_first_entry(tmp_path: Path) -> None:
    model_path = tmp_path / "duplicate-model.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("model.pkl", _pickle_payload_with_eval("print('evil')"))
        zipf.writestr("model.pkl", pickle.dumps({"weights": [1, 2, 3]}))

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["model.pkl", "model.pkl"]
    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)


def test_renamed_executorch_archive_duplicate_members_route_and_detect_shadowed_payload(tmp_path: Path) -> None:
    model_path = tmp_path / "duplicate-model.jpg"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("bytecode.pkl", _pickle_payload_with_eval("print('evil')"))
        zipf.writestr("bytecode.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("version", "not-a-version")

    file_result = core.scan_file(str(model_path), config={"cache_scan_results": False})
    result = core.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    assert file_result.scanner_name == "executorch"
    assert any(
        issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in file_result.issues
    )
    assert result.files_scanned == 1
    assert "executorch" in result.scanner_names
    assert core.determine_exit_code(result) == 1
    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)


def test_renamed_executorch_archive_unreadable_duplicate_version_does_not_hide_valid_marker(tmp_path: Path) -> None:
    model_path = tmp_path / "duplicate-version-model.jpg"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "corrupt")
        zipf.writestr("bytecode.pkl", _pickle_payload_with_eval("print('evil')"))
        zipf.writestr("version", "1")
    _corrupt_zip_member_crc(model_path, 0)

    assert ExecuTorchScanner.can_handle(str(model_path))

    result = core.scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "executorch"
    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)


def test_renamed_executorch_archive_case_insensitive_members_route_and_detect_payload(tmp_path: Path) -> None:
    model_path = tmp_path / "uppercase-members.jpg"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("VERSION", "1")
        zipf.writestr("BYTECODE.PKL", _pickle_payload_with_eval("print('evil')"))

    assert ExecuTorchScanner.can_handle(str(model_path))

    result = core.scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "executorch"
    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)


def test_renamed_executorch_archive_case_insensitive_near_match_does_not_route(tmp_path: Path) -> None:
    model_path = tmp_path / "uppercase-near-match.jpg"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("VERSION", "not-a-version")
        zipf.writestr("BYTECODE.PKL", pickle.dumps({"weights": [1, 2, 3]}))

    assert not ExecuTorchScanner.can_handle(str(model_path))


def test_executorch_duplicate_pickle_members_scan_malicious_last_entry(tmp_path: Path) -> None:
    model_path = tmp_path / "duplicate-model-reversed.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("model.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("model.pkl", _pickle_payload_with_eval("print('evil')"))

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["model.pkl", "model.pkl"]
    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)


def test_executorch_unreadable_duplicate_pickle_is_inconclusive_and_scans_later_member(tmp_path: Path) -> None:
    model_path = tmp_path / "duplicate-corrupt-model.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("model.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("model.pkl", _pickle_payload_with_eval("print('evil')"))
    _corrupt_zip_member_crc(model_path, 1)

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)


def test_executorch_benign_duplicate_pickle_members_stay_clean(tmp_path: Path) -> None:
    model_path = tmp_path / "duplicate-benign-model.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("model.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("model.pkl", pickle.dumps({"weights": [4, 5, 6]}))

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.success is True
    assert result.metadata["pickle_files"] == ["model.pkl", "model.pkl"]
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_executorch_case_insensitive_python_suffix_is_flagged(tmp_path: Path) -> None:
    model_path = tmp_path / "uppercase-python.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("bytecode.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("hooks.PY", "print('evil')")

    result = ExecuTorchScanner().scan(str(model_path))

    assert any(issue.rule_code == "S104" and issue.details.get("file") == "hooks.PY" for issue in result.issues)
