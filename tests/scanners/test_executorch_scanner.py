import pickle
import struct
import zipfile
from pathlib import Path

import pytest

from modelaudit import core
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, IssueSeverity
from modelaudit.scanners.executorch_scanner import ExecuTorchScanner
from modelaudit.utils.file.detection import detect_file_format

_ASSETS_DIR = Path(__file__).resolve().parents[1] / "assets"


def create_executorch_binary(tmp_path: Path, *, identifier: bytes = b"ET12", filename: str = "program.pte") -> Path:
    binary_path = tmp_path / filename
    # Minimal valid FlatBuffer with the ExecuTorch file identifier.
    binary_path.write_bytes(b"\x0c\x00\x00\x00" + identifier + b"\x04\x00\x04\x00\x04\x00\x00\x00")
    return binary_path


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


def _large_first_operand_pickle_with_eval(operand_size: int = 70 * 1024) -> bytes:
    padding = b"A" * operand_size
    source = b"print('evil')"
    return (
        b"\x80\x03X"
        + len(padding).to_bytes(4, "little")
        + padding
        + b"0cbuiltins\neval\nX"
        + len(source).to_bytes(4, "little")
        + source
        + b"\x85R."
    )


def _large_protocol0_first_operand_pickle_with_eval(operand_size: int = 70 * 1024) -> bytes:
    source = b"print('evil')"
    return b"V" + (b"A" * operand_size) + b"\n0cbuiltins\neval\nV" + source + b"\n\x85R."


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


def _mark_zip_member_encrypted(zip_path: Path, member_index: int) -> None:
    """Set the encrypted flag on one member so ZipFile.open requires a password."""
    with zipfile.ZipFile(zip_path, "r") as zip_file:
        member_info = zip_file.infolist()[member_index]
        central_directory_offset = zip_file.start_dir

    archive_bytes = bytearray(zip_path.read_bytes())
    local_flags_offset = member_info.header_offset + 6
    local_flags = struct.unpack_from("<H", archive_bytes, local_flags_offset)[0]
    struct.pack_into("<H", archive_bytes, local_flags_offset, local_flags | 0x1)

    cursor = central_directory_offset
    while cursor < len(archive_bytes) and archive_bytes[cursor : cursor + 4] == b"PK\x01\x02":
        local_header_offset = struct.unpack_from("<I", archive_bytes, cursor + 42)[0]
        filename_len, extra_len, comment_len = struct.unpack_from("<HHH", archive_bytes, cursor + 28)
        if local_header_offset == member_info.header_offset:
            central_flags = struct.unpack_from("<H", archive_bytes, cursor + 8)[0]
            struct.pack_into("<H", archive_bytes, cursor + 8, central_flags | 0x1)
            zip_path.write_bytes(archive_bytes)
            return
        cursor += 46 + filename_len + extra_len + comment_len

    raise AssertionError(f"Unable to locate central directory entry at offset {member_info.header_offset}")


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


def test_executorch_scanner_scans_stubbed_zip_payload(tmp_path: Path) -> None:
    file_path = create_executorch_archive(tmp_path, malicious=True)
    file_path.write_bytes(b"launcher-stub" + file_path.read_bytes())

    assert zipfile.is_zipfile(file_path)

    result = ExecuTorchScanner().scan(str(file_path))

    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)


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


def test_executorch_duplicate_pickle_members_scan_malicious_first_entry(tmp_path: Path) -> None:
    model_path = tmp_path / "duplicate-model.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("model.pkl", _pickle_payload_with_eval("print('evil')"))
        zipf.writestr("model.pkl", pickle.dumps({"weights": [1, 2, 3]}))

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["model.pkl", "model.pkl"]
    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)


def test_executorch_scans_hidden_extensionless_pickle_member(tmp_path: Path) -> None:
    model_path = tmp_path / "hidden-extensionless-pickle.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("bytecode", _pickle_payload_with_eval("print('evil')"))

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["bytecode"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("pickle_filename") == "bytecode"
        for issue in result.issues
    )


def test_executorch_scans_hidden_pickle_with_boundary_spanning_first_operand(tmp_path: Path) -> None:
    model_path = tmp_path / "hidden-large-first-operand.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("payload", _large_first_operand_pickle_with_eval())

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["payload"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("pickle_filename") == "payload"
        for issue in result.issues
    )


def test_executorch_scans_hidden_protocol0_pickle_with_boundary_spanning_first_operand(tmp_path: Path) -> None:
    model_path = tmp_path / "hidden-protocol0-large-first-operand.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("payload", _large_protocol0_first_operand_pickle_with_eval())

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["payload"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("pickle_filename") == "payload"
        for issue in result.issues
    )


def test_executorch_scans_hidden_protocolless_binary_pickle(tmp_path: Path) -> None:
    model_path = tmp_path / "hidden-protocolless-binary.ptl"
    payload = _pickle_payload_with_eval("print('evil')")
    assert payload.startswith(b"\x80\x04")
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("payload", payload[2:])

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["payload"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("pickle_filename") == "payload"
        for issue in result.issues
    )


def test_executorch_scans_hidden_protocolless_binary_pickle_without_frame(tmp_path: Path) -> None:
    model_path = tmp_path / "hidden-protocolless-binary-without-frame.ptl"
    payload = b"\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94\x8c\rprint('evil')\x94\x85R."
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("payload", payload)

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["payload"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("pickle_filename") == "payload"
        for issue in result.issues
    )


def test_executorch_scans_hidden_protocol0_persid_member(tmp_path: Path) -> None:
    model_path = tmp_path / "hidden-persid.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("payload", b"Pexternal-resource\n.")

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["payload"]


def test_executorch_binary_pickle_near_match_remains_unselected(tmp_path: Path) -> None:
    model_path = tmp_path / "binary-pickle-near-match.ptl"
    near_match = b"\x80\x03X" + (100_000).to_bytes(4, "little") + b"not enough payload"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("payload", near_match)

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.success is True
    assert result.metadata["pickle_files"] == []


def test_executorch_complete_binary_opcode_near_match_remains_unselected(tmp_path: Path) -> None:
    model_path = tmp_path / "complete-binary-opcode-near-match.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("payload", b"\x80\x04NNNnot-a-pickle")

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.success is True
    assert result.metadata["pickle_files"] == []


def test_executorch_hidden_pickle_discovery_does_not_short_circuit_on_data_pkl(tmp_path: Path) -> None:
    model_path = tmp_path / "hidden-extensionless-with-data-pkl.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("payload", _pickle_payload_with_eval("print('evil')"))

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["data.pkl", "payload"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("pickle_filename") == "payload"
        for issue in result.issues
    )


def test_executorch_pickle_discovery_ignores_plain_text_opcode_near_match(tmp_path: Path) -> None:
    model_path = tmp_path / "benign-pickleish-text.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("bytecode", b"cat is a category label, not a GLOBAL opcode stream")
        zipf.writestr("constants", b"I keep integer-looking notes in this checkpoint manifest")

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.success is True
    assert result.metadata["pickle_files"] == []
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_executorch_pickle_discovery_failures_are_inconclusive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    model_path = tmp_path / "unreadable-hidden-pickle-probe.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("payload", _pickle_payload_with_eval("print('evil')"))

    original = ExecuTorchScanner._entry_looks_like_pickle

    def fail_payload_probe(
        scanner: ExecuTorchScanner,
        zip_file: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        probe_bytes_remaining: list[int],
    ) -> bool:
        if entry.filename == "payload":
            raise OSError("simulated hidden pickle probe failure")
        return original(scanner, zip_file, entry, probe_bytes_remaining)

    monkeypatch.setattr(ExecuTorchScanner, "_entry_looks_like_pickle", fail_payload_probe)

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_pickle_discovery_incomplete" in result.metadata["scan_outcome_reasons"]
    assert result.metadata["pickle_files"] == ["data.pkl"]
    discovery_checks = [check for check in result.checks if check.name == "Pickle Discovery"]
    assert len(discovery_checks) == 1
    assert discovery_checks[0].details["zip_entries"] == ["payload"]
    assert discovery_checks[0].details["scan_outcome_reason"] == "executorch_pickle_discovery_incomplete"


def test_executorch_pickle_discovery_entry_limit_fails_closed(tmp_path: Path) -> None:
    model_path = tmp_path / "hidden-pickle-after-entry-limit.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("payload", _pickle_payload_with_eval("print('evil')"))

    result = ExecuTorchScanner(config={"max_executorch_pickle_discovery_entries": 1}).scan(str(model_path))

    assert result.success is False
    assert result.metadata["pickle_files"] == []
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_pickle_discovery_incomplete" in result.metadata["scan_outcome_reasons"]
    discovery_check = next(check for check in result.checks if check.name == "Pickle Discovery")
    assert discovery_check.details["failed_count"] == 1


def test_executorch_pickle_discovery_entry_limit_preserves_early_malicious_finding(tmp_path: Path) -> None:
    model_path = tmp_path / "hidden-pickle-before-entry-limit.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("payload", _pickle_payload_with_eval("print('evil')"))
        zipf.writestr("version", "1")

    result = ExecuTorchScanner(config={"max_executorch_pickle_discovery_entries": 1}).scan(str(model_path))

    assert result.metadata["pickle_files"] == ["payload"]
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_executorch_pickle_discovery_probe_budget_fails_closed(tmp_path: Path) -> None:
    model_path = tmp_path / "hidden-pickle-over-probe-budget.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("payload", _large_protocol0_first_operand_pickle_with_eval())

    result = ExecuTorchScanner(config={"max_executorch_pickle_discovery_probe_bytes": 16}).scan(str(model_path))

    assert result.success is False
    assert result.metadata["pickle_files"] == []
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    discovery_check = next(check for check in result.checks if check.name == "Pickle Discovery")
    assert discovery_check.details["failed_count"] == 1
    assert discovery_check.details["entries"][0]["exception_type"] == "_PickleDiscoveryBudgetExceeded"


def test_executorch_pickle_discovery_one_byte_budget_fails_closed(tmp_path: Path) -> None:
    model_path = tmp_path / "hidden-pickle-over-one-byte-probe-budget.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("payload", _pickle_payload_with_eval("print('evil')"))

    result = ExecuTorchScanner(config={"max_executorch_pickle_discovery_probe_bytes": 1}).scan(str(model_path))

    assert result.success is False
    assert result.metadata["pickle_files"] == []
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    discovery_check = next(check for check in result.checks if check.name == "Pickle Discovery")
    assert discovery_check.details["failed_count"] == 1


def test_executorch_empty_member_does_not_exceed_exhausted_probe_budget(tmp_path: Path) -> None:
    model_path = tmp_path / "empty-after-probe-budget.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("empty", b"")

    result = ExecuTorchScanner(config={"max_executorch_pickle_discovery_probe_bytes": 1}).scan(str(model_path))

    assert result.success is True
    assert result.metadata["pickle_files"] == []


def test_executorch_unreadable_known_pickle_does_not_hide_later_malicious_member(tmp_path: Path) -> None:
    model_path = tmp_path / "encrypted-known-before-hidden.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        zipf.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("payload", _pickle_payload_with_eval("print('evil')"))
    _mark_zip_member_encrypted(model_path, 1)

    result = ExecuTorchScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["data.pkl", "payload"]
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_pickle_member_scan_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("pickle_filename") == "payload"
        for issue in result.issues
    )


def test_executorch_embedded_pickle_failures_have_bounded_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "many-unreadable-pickles.ptl"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "1")
        for index in range(25):
            zipf.writestr(f"payload-{index}.pkl", pickle.dumps({"index": index}))

    scanner = ExecuTorchScanner()
    assert scanner.pickle_scanner is not None

    def fail_embedded_scan(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated embedded pickle read failure")

    monkeypatch.setattr(scanner.pickle_scanner, "scan_stream", fail_embedded_scan)

    result = scanner.scan(str(model_path))

    assert result.success is False
    failure_checks = [check for check in result.checks if check.name == "Embedded Pickle Scan"]
    assert len(failure_checks) == 1
    assert failure_checks[0].details["failed_count"] == 25
    assert failure_checks[0].details["reported_failure_count"] == 20
    assert len(failure_checks[0].details["entries"]) == 20


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
