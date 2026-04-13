from __future__ import annotations

import base64
import binascii
import pickle
import pickletools
import re
import zipfile
from pathlib import Path

import pytest

from modelaudit_picklescan import SafetyVerdict, ScanOptions, ScanStatus, scan_bytes, scan_file
from modelaudit_picklescan._parity_corpus import (
    generated_parity_payloads,
    malicious_reduce_payload,
    prefix_truncation_payloads,
)
from modelaudit_picklescan.engine.rust import _report_from_native_dict
from modelaudit_picklescan.engine.selection import rust_engine_available

pytestmark = pytest.mark.skipif(not rust_engine_available(), reason="Rust picklescan extension is not built")


def _rust_source_text() -> str:
    rust_src = Path(__file__).resolve().parents[1] / "rust" / "src"
    return "\n".join(path.read_text() for path in sorted(rust_src.glob("*.rs")))


def _rust_string_array(source: str, name: str) -> set[str]:
    match = re.search(rf"const {name}: &\[&str\] = &\[(.*?)\];", source, flags=re.DOTALL)
    assert match is not None
    return set(re.findall(r'"([^"]*)"', match.group(1)))


def _rust_tuple_array(source: str, name: str) -> set[tuple[str, str]]:
    match = re.search(rf"const {name}: &\[\(&str, &str\)\] = &\[(.*?)\];", source, flags=re.DOTALL)
    assert match is not None
    return set(re.findall(r'\("([^"]*)",\s*"([^"]*)"\)', match.group(1)))


@pytest.fixture
def parity_payloads() -> dict[str, tuple[bytes, ScanOptions | None]]:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    return {
        "safe": (pickle.dumps({"weights": [1, 2, 3]}, protocol=4), None),
        "malicious_reduce": (malicious_reduce_payload(), None),
        "stack_global": (b"\x80\x04\x8c\x05posix\x94\x8c\x06system\x94\x93.", None),
        "suspicious_string": (pickle.dumps({"code": "exec('import os; os.system(\"id\")')"}, protocol=4), None),
        "non_magic_numeric_dunder_string": (pickle.dumps({"code": "__1__"}, protocol=4), None),
        "non_magic_embedded_dunder_string": (pickle.dumps({"code": "a__b__c"}, protocol=4), None),
        "protocol0_unicode_word_boundary_string": (pickle.dumps({"code": "é__a__"}, protocol=0), None),
        "protocol0_unicode_hex_escape_string": (pickle.dumps({"code": "\\x41"}, protocol=0), None),
        "protocol0_string_hex_escape": (b"S'\\x5cx41'\n.", None),
        "getattr_whitespace_suspicious_string": (pickle.dumps({"code": 'getattr (x, "system")'}, protocol=4), None),
        "nested_raw": (pickle.dumps({"outer": nested_payload}, protocol=4), None),
        "nested_base64": (
            pickle.dumps({"outer": base64.b64encode(nested_payload).decode("ascii")}, protocol=4),
            None,
        ),
        "nested_hex": (
            pickle.dumps({"outer": binascii.hexlify(nested_payload).decode("ascii")}, protocol=4),
            None,
        ),
        "missing_stop_mark": (b"(", None),
        "missing_stop_proto_none": (b"\x80\x04N", None),
        "truncated_put_line": (b"(dp", None),
        "truncated_unicode_line": (b"Vabc", None),
        "opcode_budget_tail": (b"\x80\x04cos\nsystem\n.", ScanOptions(max_opcodes=1)),
        "literal_budget": (
            pickle.dumps({"code": "A" * 64 + "os.system('id')" + "B" * 64}, protocol=4),
            ScanOptions(max_string_literal_scan_chars=8),
        ),
    }


def test_rust_parser_declares_all_pickletools_opcodes() -> None:
    source = _rust_source_text()
    rust_opcodes = set(re.findall(r'name: "([A-Z0-9_]+)"', source))
    rust_opcodes.update(re.findall(r'simple_opcode\("([A-Z0-9_]+)"', source))

    assert rust_opcodes == {opcode.name for opcode in pickletools.opcodes}


def test_rust_policy_tables_keep_required_security_coverage() -> None:
    source = _rust_source_text()
    builtin_names = _rust_string_array(source, "BUILTIN_DANGEROUS_NAMES")
    wildcard_modules = _rust_string_array(source, "DANGEROUS_WILDCARD_MODULES")
    dangerous_globals = _rust_tuple_array(source, "DANGEROUS_GLOBALS")

    assert builtin_names, "Failed to extract BUILTIN_DANGEROUS_NAMES from Rust source"
    assert wildcard_modules, "Failed to extract DANGEROUS_WILDCARD_MODULES from Rust source"
    assert dangerous_globals, "Failed to extract DANGEROUS_GLOBALS from Rust source"

    assert {"eval", "exec", "getattr", "open", "__import__"} <= builtin_names
    assert {"os", "posix", "subprocess", "socket", "ctypes", "pickle"} <= wildcard_modules
    assert {
        ("numpy", "load"),
        ("torch", "load"),
        ("uuid", "_ip_getnode"),
    } <= dangerous_globals


def test_rust_engine_scans_parity_payloads(parity_payloads: dict[str, tuple[bytes, ScanOptions | None]]) -> None:
    for name, (payload, options) in parity_payloads.items():
        rust_report = scan_bytes(payload, source=f"{name}.pkl", options=options)

        assert rust_report.status in {ScanStatus.COMPLETE, ScanStatus.INCONCLUSIVE, ScanStatus.ERROR}
        assert all(notice.code != "engine_fallback" for notice in rust_report.notices)


def test_generated_payloads_scan_without_runtime_errors() -> None:
    failures: list[str] = []
    for name, payload, options in generated_parity_payloads():
        rust_report = scan_bytes(payload, source=f"{name}.pkl", options=options)

        if rust_report.status == ScanStatus.ERROR and any(
            error.category == "rust_engine_error" for error in rust_report.errors
        ):
            failures.append(name)

    assert failures == []


def test_rust_report_conversion_rejects_non_bool_coverage_flags() -> None:
    raw_report = {
        "source": "native.pkl",
        "status": "complete",
        "verdict": "clean",
        "findings": [],
        "notices": [],
        "errors": [],
        "coverage": {
            "bytes_scanned": 0,
            "raw_scan_complete": "false",
            "opcode_scan_complete": True,
        },
        "metadata": {},
        "duration_s": 0.0,
    }

    with pytest.raises(TypeError, match="expected bool or None"):
        _report_from_native_dict(raw_report)


def test_prefix_truncations_scan_without_runtime_errors() -> None:
    failures: list[str] = []
    for name, payload, options in prefix_truncation_payloads():
        for prefix_len in range(len(payload) + 1):
            prefix = payload[:prefix_len]
            rust_report = scan_bytes(prefix, source=f"{name}-prefix-{prefix_len}.pkl", options=options)

            if rust_report.status == ScanStatus.ERROR and any(
                error.category == "rust_engine_error" for error in rust_report.errors
            ):
                failures.append(f"{name}:{prefix_len}")

    assert failures == []


def test_rust_engine_detects_malicious_payload_without_python_fallback() -> None:
    report = scan_bytes(malicious_reduce_payload(), source="native-malicious.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)
    assert all(notice.code != "engine_fallback" for notice in report.notices)


def test_rust_engine_scans_pytorch_zip_data_pickle_without_python_fallback(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "model.pt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("archive/data.pkl", malicious_reduce_payload())
        archive.writestr("archive/version", "3\n")
        archive.writestr("archive/byteorder", "little")

    report = scan_file(archive_path)

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert report.metadata["container_type"] == "pytorch_zip"
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)
    assert all(finding.location is not None and "archive/data.pkl" in finding.location for finding in report.findings)
    assert all(notice.code != "engine_fallback" for notice in report.notices)
