from __future__ import annotations

import base64
import binascii
import pickle
import pickletools
import re
import zipfile
from importlib.util import find_spec
from pathlib import Path

import pytest
from parity_corpus import (
    generated_parity_payloads,
    malicious_reduce_payload,
    prefix_truncation_payloads,
)

from modelaudit_picklescan import SafetyVerdict, ScanOptions, ScanStatus, scan_bytes, scan_file
from modelaudit_picklescan.api import _RUST_EXTENSION_MODULE

_SUSPICIOUS_STRING_LITERAL_INDICES = {*range(8, 20), *range(22, 31)}
_GENERATED_EXPECTED_VERDICTS: dict[str, SafetyVerdict] = {
    **{
        f"string-{index}-protocol-{protocol}": SafetyVerdict.SUSPICIOUS
        for index in _SUSPICIOUS_STRING_LITERAL_INDICES
        for protocol in range(6)
    },
    "bytes-small-limit-2": SafetyVerdict.MALICIOUS,
    "bytes-3": SafetyVerdict.MALICIOUS,
    "bytes-small-limit-3": SafetyVerdict.MALICIOUS,
    "base64-3": SafetyVerdict.MALICIOUS,
    "hex-3": SafetyVerdict.MALICIOUS,
    "bytes-small-limit-4": SafetyVerdict.MALICIOUS,
    "raw-0": SafetyVerdict.SUSPICIOUS,
    "raw-1": SafetyVerdict.SUSPICIOUS,
    "raw-4": SafetyVerdict.MALICIOUS,
    "raw-5": SafetyVerdict.MALICIOUS,
    "raw-6": SafetyVerdict.MALICIOUS,
    "raw-7": SafetyVerdict.MALICIOUS,
    "raw-8": SafetyVerdict.MALICIOUS,
    "raw-9": SafetyVerdict.MALICIOUS,
    "raw-10": SafetyVerdict.MALICIOUS,
    "raw-11": SafetyVerdict.MALICIOUS,
    "raw-12": SafetyVerdict.MALICIOUS,
    "raw-15": SafetyVerdict.MALICIOUS,
    "raw-16": SafetyVerdict.MALICIOUS,
    "raw-17": SafetyVerdict.SUSPICIOUS,
    "raw-18": SafetyVerdict.SUSPICIOUS,
    "raw-19": SafetyVerdict.SUSPICIOUS,
    "raw-20": SafetyVerdict.MALICIOUS,
    "raw-21": SafetyVerdict.MALICIOUS,
    "budget-1": SafetyVerdict.MALICIOUS,
    "budget-2": SafetyVerdict.MALICIOUS,
    "budget-3": SafetyVerdict.MALICIOUS,
    "budget-5": SafetyVerdict.MALICIOUS,
    "budget-10": SafetyVerdict.MALICIOUS,
    "budget-ext-boundary": SafetyVerdict.SUSPICIOUS,
}
_PREFIX_FULL_PAYLOAD_EXPECTED_VERDICTS: dict[str, SafetyVerdict] = {
    "malicious": SafetyVerdict.MALICIOUS,
    "proto0-string": SafetyVerdict.SUSPICIOUS,
    "proto4-string": SafetyVerdict.SUSPICIOUS,
    "nested-malicious": SafetyVerdict.MALICIOUS,
    "global-call": SafetyVerdict.MALICIOUS,
    "stack-global-call": SafetyVerdict.MALICIOUS,
}

pytestmark = pytest.mark.skipif(
    find_spec(_RUST_EXTENSION_MODULE) is None, reason="Rust picklescan extension is not built"
)


def _rust_source_text() -> str:
    rust_src = Path(__file__).resolve().parents[1] / "rust" / "src"
    return "\n".join(path.read_text() for path in sorted(rust_src.glob("*.rs")))


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


@pytest.mark.parametrize(
    "module,name",
    [
        ("builtins", "eval"),
        ("builtins", "exec"),
        ("builtins", "getattr"),
        ("builtins", "open"),
        ("builtins", "__import__"),
        ("os", "system"),
        ("posix", "system"),
        ("subprocess", "Popen"),
        ("socket", "socket"),
        ("ctypes", "CDLL"),
        ("pickle", "loads"),
        ("numpy", "load"),
        ("torch", "load"),
        ("uuid", "_ip_getnode"),
    ],
)
def test_rust_policy_detects_required_security_coverage(module: str, name: str) -> None:
    payload = f"c{module}\n{name}\n)R.".encode()

    report = scan_bytes(payload, source=f"{module}-{name}.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL" and finding.details.get("import_reference") == f"{module}.{name}"
        for finding in report.findings
    )


def test_rust_engine_scans_parity_payloads(parity_payloads: dict[str, tuple[bytes, ScanOptions | None]]) -> None:
    expected_verdicts = {
        "safe": SafetyVerdict.CLEAN,
        "malicious_reduce": SafetyVerdict.MALICIOUS,
        "stack_global": SafetyVerdict.MALICIOUS,
        "suspicious_string": SafetyVerdict.SUSPICIOUS,
        "non_magic_numeric_dunder_string": SafetyVerdict.CLEAN,
        "non_magic_embedded_dunder_string": SafetyVerdict.CLEAN,
        "getattr_whitespace_suspicious_string": SafetyVerdict.SUSPICIOUS,
        "nested_raw": SafetyVerdict.CLEAN,
        "nested_base64": SafetyVerdict.CLEAN,
        "nested_hex": SafetyVerdict.CLEAN,
    }
    for name, (payload, options) in parity_payloads.items():
        rust_report = scan_bytes(payload, source=f"{name}.pkl", options=options)

        assert rust_report.status in {ScanStatus.COMPLETE, ScanStatus.INCONCLUSIVE, ScanStatus.ERROR}
        assert all(notice.code != "engine_fallback" for notice in rust_report.notices)
        if name in expected_verdicts:
            assert rust_report.verdict == expected_verdicts[name], name


def test_generated_payloads_scan_without_runtime_errors() -> None:
    failures: list[str] = []
    for name, payload, options in generated_parity_payloads():
        rust_report = scan_bytes(payload, source=f"{name}.pkl", options=options)

        if rust_report.status == ScanStatus.ERROR and any(
            error.category == "rust_engine_error" for error in rust_report.errors
        ):
            failures.append(name)
        expected_verdict = _GENERATED_EXPECTED_VERDICTS.get(name)
        if expected_verdict is not None:
            assert rust_report.verdict == expected_verdict, name
            assert rust_report.findings, name

    assert failures == []


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
            if prefix_len == len(payload) and name in _PREFIX_FULL_PAYLOAD_EXPECTED_VERDICTS:
                assert rust_report.verdict == _PREFIX_FULL_PAYLOAD_EXPECTED_VERDICTS[name], name
                assert rust_report.findings, name

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
