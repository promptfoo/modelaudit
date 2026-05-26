import pickle
import zipfile
from pathlib import Path

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME
from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.executorch_scanner import ExecuTorchScanner

_ASSETS_DIR = Path(__file__).resolve().parents[1] / "assets"


def create_executorch_binary(tmp_path: Path, *, identifier: bytes = b"ET12") -> Path:
    binary_path = tmp_path / "program.pte"
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
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_format_unrecognized" in result.metadata["scan_outcome_reasons"]
    assert any("executorch" in i.message.lower() for i in result.issues)
    assert not any(i.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for i in result.issues)
    assert not any(i.rule_code == "S104" for i in result.issues)


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


def test_executorch_scanner_rejects_invalid_binary_signature_match(tmp_path: Path) -> None:
    file_path = tmp_path / "fake-program.pte"
    file_path.write_bytes(b"JUNKET12notflatbufferatall")

    scanner = ExecuTorchScanner()
    result = scanner.scan(str(file_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_format_unrecognized" in result.metadata["scan_outcome_reasons"]
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)
    assert not any(issue.rule_code == "S104" for issue in result.issues)


def test_executorch_scanner_marks_corrupt_zip_inconclusive(tmp_path: Path) -> None:
    file_path = tmp_path / "corrupt.ptl"
    file_path.write_bytes(b"PKnot a zip")

    result = ExecuTorchScanner().scan(str(file_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_zip_parse_failed" in result.metadata["scan_outcome_reasons"]
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_executorch_scanner_marks_unexpected_zip_error_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = create_executorch_archive(tmp_path)

    def fail_zip_open(*args: object, **kwargs: object) -> None:
        raise RuntimeError("archive unavailable")

    monkeypatch.setattr(zipfile, "ZipFile", fail_zip_open)

    result = ExecuTorchScanner().scan(str(file_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "executorch_scan_failed" in result.metadata["scan_outcome_reasons"]
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_invalid_executorch_candidate_is_inconclusive_and_uncached(tmp_path: Path) -> None:
    file_path = tmp_path / "invalid.ptl"
    file_path.write_bytes(b"not zip")
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        first_result = scan_model_directory_or_file(
            str(file_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second_result = scan_model_directory_or_file(
            str(file_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for audit_result in (first_result, second_result):
            metadata = audit_result.file_metadata[str(file_path)]
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert "executorch_format_unrecognized" in metadata["scan_outcome_reasons"]
            assert determine_exit_code(audit_result) == 1
            assert any(
                "file type validation failed" in issue.message.lower() and issue.severity == IssueSeverity.WARNING
                for issue in audit_result.issues
            )
            assert not any(issue.rule_code == "S104" for issue in audit_result.issues)

        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_executorch_scanner_scans_polyglot_binary_zip_payload(tmp_path: Path) -> None:
    file_path = create_executorch_binary(tmp_path)
    with zipfile.ZipFile(file_path, "a") as archive:
        archive.writestr("evil.py", "print('evil')")

    scanner = ExecuTorchScanner()
    result = scanner.scan(str(file_path))

    assert any(check.name == "ExecuTorch Binary Format Validation" for check in result.checks)
    python_issues = [issue for issue in result.issues if issue.rule_code == "S507"]
    assert len(python_issues) == 1
    assert python_issues[0].severity == IssueSeverity.CRITICAL
    assert not any(issue.rule_code == "S104" for issue in result.issues)


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
