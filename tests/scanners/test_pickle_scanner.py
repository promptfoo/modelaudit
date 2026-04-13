from __future__ import annotations

import io
import os
import pickle
from pathlib import Path
from typing import Any

from modelaudit.scanners.base import IssueSeverity, ScanResult
from modelaudit.scanners.pickle_scanner import (
    ALWAYS_DANGEROUS_FUNCTIONS,
    ALWAYS_DANGEROUS_MODULES,
    PickleScanner,
    _is_legitimate_serialization_file,
    _looks_like_pickle,
    is_suspicious_global,
)
from tests.helpers import create_mock_pytorch_zip


class MaliciousPayload:
    def __reduce__(self) -> tuple[Any, tuple[str]]:
        return (os.system, ("id",))


class NonSeekableBytesIO(io.BytesIO):
    def seekable(self) -> bool:
        return False


def test_pickle_scanner_star_import_exports_scanner_class() -> None:
    namespace: dict[str, object] = {}

    exec("from modelaudit.scanners.pickle_scanner import *", namespace)

    assert namespace["PickleScanner"] is PickleScanner


def test_looks_like_pickle_sniffs_binary_and_protocol_zero_payloads() -> None:
    assert _looks_like_pickle(pickle.dumps({"safe": True}, protocol=4)) is True
    assert _looks_like_pickle(b"cos\nsystem\n.") is True
    assert _looks_like_pickle(b"not a pickle") is False


def test_can_handle_accepts_raw_pickle_and_rejects_zip_container(tmp_path: Path) -> None:
    raw_pickle = tmp_path / "model.pkl"
    raw_pickle.write_bytes(pickle.dumps({"weights": [1, 2, 3]}, protocol=4))

    zip_pickle = create_mock_pytorch_zip(tmp_path / "model.pt", malicious=False)

    assert PickleScanner.can_handle(str(raw_pickle)) is True
    assert PickleScanner.can_handle(str(zip_pickle)) is False


def test_scan_safe_pickle_uses_rust_engine_and_preserves_integrity_metadata(tmp_path: Path) -> None:
    path = tmp_path / "safe.pkl"
    path.write_bytes(pickle.dumps({"weights": [1, 2, 3]}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["pickle_primary_engine"] == "rust"
    assert result.metadata["file_size"] == path.stat().st_size
    assert result.metadata["file_hashes"]["sha256"]
    assert not [issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}]


def test_scan_large_low_information_pickle_skips_expensive_raw_detectors(tmp_path: Path) -> None:
    path = tmp_path / "large-safe.pkl"
    path.write_bytes(pickle.dumps({"blob": "A" * (2 * 1024 * 1024)}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_primary_engine"] == "rust"
    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True
    assert result.metadata["pickle_expensive_raw_detector_skip_reason"] == "rust_complete_clean_no_expensive_raw_seeds"


def test_expensive_raw_prefilters_preserve_secret_and_network_findings(tmp_path: Path) -> None:
    path = tmp_path / "seeded.pkl"
    payload = {
        "token": "sk-" + ("A" * 48),
        "endpoint": "https://attacker.example/cmd",
    }
    path.write_bytes(pickle.dumps(payload, protocol=4))

    result = PickleScanner().scan(str(path))

    assert any(check.name == "Embedded Secrets Detection" for check in result.checks)
    assert any(check.name == "Network Communication Detection" for check in result.checks)
    assert not result.metadata.get("pickle_secrets_raw_detector_skipped")
    assert not result.metadata.get("pickle_network_raw_detector_skipped")


def test_scan_malicious_pickle_reports_rust_finding(tmp_path: Path) -> None:
    path = tmp_path / "evil.pkl"
    path.write_bytes(pickle.dumps(MaliciousPayload(), protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["pickle_primary_engine"] == "rust"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        issue.details.get("import_reference") in {"posix.system", "os.system", "nt.system"} for issue in result.issues
    )


def test_scan_stream_treats_negative_size_as_unknown_size() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), -1, source="unknown-size.pkl")

    assert result.success is True
    assert result.metadata["pickle_primary_engine"] == "rust"
    assert not result.metadata.get("operational_error")


def test_scan_stream_runs_root_raw_detectors_for_seekable_stream() -> None:
    payload = pickle.dumps({"script": "os.system('id')"}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="stream-raw.pkl")

    assert any(issue.details.get("source") == "bounded_raw_pickle_window" for issue in result.issues)


def test_scan_stream_detects_base64_encoded_execution_text() -> None:
    payload = pickle.dumps({"encoded": "b3Muc3lzdGVtKCdpZCcp"}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="encoded-raw.pkl")

    assert any(issue.rule_code == "S604" for issue in result.issues)


def test_scan_stream_preserves_legacy_raw_eval_exec_importlib_detection() -> None:
    payload = pickle.dumps({"script": "eval # inline\n(1); exec\t(x); import importlib"}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="raw-code.pkl")

    critical_messages = [issue.message for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert any("eval" in message for message in critical_messages)
    assert any("exec" in message for message in critical_messages)
    assert any("importlib" in message for message in critical_messages)
    assert any(issue.rule_code == "S104" for issue in result.issues)


def test_scan_stream_does_not_flag_importlib_comment_as_critical() -> None:
    payload = pickle.dumps(
        {"documentation": "This model does not use importlib# Safe comment", "config": {"safe": True}},
        protocol=4,
    )

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="comment.pkl")

    assert not any(
        issue.severity == IssueSeverity.CRITICAL and "importlib" in issue.message.lower() for issue in result.issues
    )


def test_scan_stream_does_not_flag_primarily_documentation_raw_text() -> None:
    payload = (
        b"V# eval(1)\n"
        b"# exec(2)\n"
        b"# os.system('id')\n"
        b"# importlib.import_module('os')\n"
        b"# subprocess.run('id')\n"
        b"plain note\n."
    )

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="comment-doc.pkl")

    assert not any(issue.details.get("source") == "bounded_raw_pickle_window" for issue in result.issues)


def test_scan_stream_documentation_padding_does_not_suppress_raw_structural_evidence() -> None:
    payload = (b"# documentation line\n" * 32) + b"cposix\nsystem\n."

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="doc-padded-evil.pkl")

    assert any(
        issue.details.get("source") == "bounded_raw_pickle_window"
        and issue.details.get("associated_global") in {"os.system", "posix.system", "nt.system"}
        for issue in result.issues
    )


def test_root_legacy_metadata_detectors_preserve_import_only_and_main_build_rules() -> None:
    scanner = PickleScanner()
    result = ScanResult(scanner_name="pickle", scanner=scanner)
    result.metadata["import_references"] = [
        {
            "import_reference": "tests.test_pickle_scanner.__dict__",
            "module": "tests.test_pickle_scanner",
            "name": "__dict__",
            "opcode": "GLOBAL",
            "position": 257,
            "is_dangerous": False,
        },
        {
            "import_reference": "__main__.CustomModel",
            "module": "__main__",
            "name": "CustomModel",
            "opcode": "STACK_GLOBAL",
            "position": 42,
            "is_dangerous": False,
        },
    ]

    scanner._add_root_legacy_metadata_detectors(result, "payload.pkl")

    assert {issue.rule_code for issue in result.issues} >= {"S206", "S207"}
    assert any("tests.test_pickle_scanner.__dict__" in issue.message for issue in result.issues)
    assert any("__main__.CustomModel" in issue.message for issue in result.issues)


def test_scan_stream_preserves_copyreg_extension_reduce_detection() -> None:
    payload = b"\x80\x04\x82\x01)R."

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="extension-reduce.pkl")

    assert any(
        issue.rule_code == "S201" and issue.details.get("associated_global") == "__copyreg_extension__.code_1"
        for issue in result.issues
    )


def test_scan_stream_does_not_treat_system_name_as_setitem_cve() -> None:
    payload = b"cos\nsystem\n."

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="global-only.pkl")

    assert any(
        issue.details.get("associated_global") in {"os.system", "posix.system", "nt.system"} for issue in result.issues
    )
    assert all(issue.rule_code != "S310" for issue in result.issues)
    assert all(issue.rule_code != "S209" for issue in result.issues)


def test_scan_stream_accepts_unknown_size_stream() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), None, source="unknown-size.pkl")

    assert result.success is True
    assert result.metadata["pickle_primary_engine"] == "rust"


def test_scan_stream_non_seekable_payload_above_root_cap_returns_truncated_result() -> None:
    payload = pickle.dumps({"pad": b"A" * 4096}, protocol=4)

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": 64}).scan_stream(
        NonSeekableBytesIO(payload),
        len(payload),
        source="large-nonseek.pkl",
    )

    assert result.metadata["pickle_stream_truncated_for_root_scan"] is True
    assert result.metadata["pickle_stream_bytes_buffered"] == 64
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata.get("operational_error_reason") != "short_read"
    assert result.success is False
    assert not any(issue.details.get("category") == "short_read" for issue in result.issues)
    assert any(check.name == "Pickle Stream Read Limit" for check in result.checks)


def test_extract_metadata_uses_pickle_opcodes_not_raw_bytes(tmp_path: Path) -> None:
    path = tmp_path / "safe.pkl"
    path.write_bytes(pickle.dumps({"letter": "R", "word": "build"}, protocol=4))

    metadata = PickleScanner().extract_metadata(str(path))

    assert metadata["has_dangerous_opcodes"] is False
    assert metadata["dangerous_opcodes"] == []
    assert metadata["total_opcodes"] > 0


def test_scan_bin_file_detects_executable_tail_after_pickle_stream(tmp_path: Path) -> None:
    path = tmp_path / "model.bin"
    path.write_bytes(pickle.dumps({"safe": True}, protocol=4) + b"\x7fELF/bin/sh\x00")

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert any(issue.rule_code == "S502" for issue in result.issues)


def test_scan_bin_file_pe_tail_requires_pe_evidence(tmp_path: Path) -> None:
    path = tmp_path / "model.bin"
    path.write_bytes(pickle.dumps({"safe": True}, protocol=4) + b"MZ benign initials")

    result = PickleScanner().scan(str(path))

    assert not any(issue.rule_code == "S501" for issue in result.issues)


def test_scan_bin_file_detects_pe_tail_with_dos_stub(tmp_path: Path) -> None:
    path = tmp_path / "model.bin"
    path.write_bytes(
        pickle.dumps({"safe": True}, protocol=4) + b"MZ" + (b"\x00" * 30) + b"This program cannot be run in DOS mode"
    )

    result = PickleScanner().scan(str(path))

    assert any(issue.rule_code == "S501" for issue in result.issues)


def test_raw_cve_setitem_detection_ignores_unparsed_tail_strings(tmp_path: Path) -> None:
    path = tmp_path / "tail.pkl"
    path.write_bytes(pickle.dumps({"safe": True}, protocol=4) + b"os.system")

    result = PickleScanner().scan(str(path))

    assert all(
        not (issue.details.get("cve_id") == "CVE-2026-24747" and issue.rule_code in {"S209", "S310"})
        for issue in result.issues
    )


def test_raw_cve_setitem_detection_is_not_suppressed_by_comment_token(tmp_path: Path) -> None:
    path = tmp_path / "comment-token-setitem.pkl"
    path.write_bytes(b"(dS'_rebuild_tensor # comment token is not a bypass'\nS'value'\ns.")

    result = PickleScanner().scan(str(path))

    assert any(issue.details.get("cve_id") == "CVE-2026-24747" for issue in result.issues)
    assert any(issue.rule_code == "S209" for issue in result.issues)


def test_raw_cve_comment_only_text_does_not_trigger_setitem(tmp_path: Path) -> None:
    path = tmp_path / "comment-only.pkl"
    path.write_bytes(
        pickle.dumps({"doc": "# _rebuild_tensor SETITEM storage_offset nbytes\n# documentation only"}, protocol=4)
    )

    result = PickleScanner().scan(str(path))

    assert not any(issue.details.get("cve_id") == "CVE-2026-24747" for issue in result.issues)


def test_raw_cve_rebuild_tensor_global_is_not_suppressed_by_documentation_literal(tmp_path: Path) -> None:
    path = tmp_path / "doc-literal-real-global.pkl"
    path.write_bytes(
        b"(dS'doc'\nS'# _rebuild_tensor\\n# documentation only'\nsctorch\n_rebuild_tensor_v2\nS'value'\ns."
    )

    result = PickleScanner().scan(str(path))

    assert any(issue.details.get("cve_id") == "CVE-2026-24747" for issue in result.issues)
    assert result.metadata["primary_cve"] == "CVE-2026-24747"


def test_scan_stream_enforces_size_limit() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    result = PickleScanner(config={"max_file_read_size": 4}).scan_stream(
        io.BytesIO(payload),
        len(payload),
        source="too-large.pkl",
    )

    assert result.success is False
    assert any(check.name == "File Size Limit" for check in result.checks)


def test_direct_scan_delegates_zip_backed_pytorch_container(tmp_path: Path) -> None:
    path = create_mock_pytorch_zip(tmp_path / "model.pt", malicious=True)

    result = PickleScanner().scan(str(path))

    assert result.scanner_name == "pytorch_zip"
    assert any(issue.details.get("pickle_filename") == "data.pkl" for issue in result.issues)


def test_policy_compatibility_exports_cover_required_dangerous_symbols() -> None:
    assert {"os.system", "subprocess.Popen", "eval", "exec", "__import__"} <= ALWAYS_DANGEROUS_FUNCTIONS
    assert {"os", "subprocess", "posix", "nt"} <= ALWAYS_DANGEROUS_MODULES
    assert is_suspicious_global("builtins", "eval") is True
    assert is_suspicious_global("builtins", "len") is False
    assert is_suspicious_global("os", "system") is True
    assert is_suspicious_global("json", "loads") is False


def test_legitimate_serialization_file_uses_rust_scan(tmp_path: Path) -> None:
    safe_path = tmp_path / "safe.joblib"
    safe_path.write_bytes(b"\x80\x04cjoblib.numpy_pickle\nNumpyArrayWrapper\nq\x00.")
    malicious_path = tmp_path / "evil.joblib"
    malicious_path.write_bytes(pickle.dumps(MaliciousPayload(), protocol=4))
    text_path = tmp_path / "not-pickle.joblib"
    text_path.write_text("not a pickle", encoding="utf-8")

    assert _is_legitimate_serialization_file(str(safe_path)) is True
    assert _is_legitimate_serialization_file(str(malicious_path)) is False
    assert _is_legitimate_serialization_file(str(text_path)) is False


def test_scan_missing_path_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "missing.pkl"

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert any(check.name == "Path Exists" for check in result.checks)
