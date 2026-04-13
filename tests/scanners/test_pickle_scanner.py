from __future__ import annotations

import hashlib
import io
import os
import pickle
from pathlib import Path
from typing import Any

import pytest

from modelaudit.scanners.base import IssueSeverity, ScanResult
from modelaudit.scanners.pickle_scanner import (
    ALWAYS_DANGEROUS_FUNCTIONS,
    ALWAYS_DANGEROUS_MODULES,
    PickleScanner,
    _is_dangerous_module,
    _is_legitimate_serialization_file,
    _looks_like_pickle,
    _pickle_opcode_summary,
    is_suspicious_global,
)
from tests.helpers import create_mock_pytorch_zip

EXPECTED_SYSTEM_GLOBAL = "nt.system" if os.name == "nt" else "posix.system"


class MaliciousPayload:
    def __reduce__(self) -> tuple[Any, tuple[str]]:
        return (os.system, ("id",))


class NonSeekableBytesIO(io.BytesIO):
    def seekable(self) -> bool:
        return False


def _short_binunicode(data: bytes) -> bytes:
    if len(data) > 0xFF:
        raise ValueError("SHORT_BINUNICODE helper accepts at most 255 bytes")
    return b"\x8c" + bytes([len(data)]) + data


def _make_opcode_padding_stream(opcode_pairs: int) -> bytes:
    return b"\x80\x02" + (b"K\x010" * opcode_pairs) + b"."


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


def test_expensive_raw_prefilters_preserve_structured_secret_assignments(tmp_path: Path) -> None:
    path = tmp_path / "structured-secret.pkl"
    path.write_bytes(pickle.dumps({"env": "password=CorrectHorseBattery42"}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert any(check.name == "Embedded Secrets Detection" for check in result.checks)
    assert not result.metadata.get("pickle_secrets_raw_detector_skipped")


def test_scan_malicious_pickle_reports_rust_finding(tmp_path: Path) -> None:
    path = tmp_path / "evil.pkl"
    path.write_bytes(pickle.dumps(MaliciousPayload(), protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["pickle_primary_engine"] == "rust"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(issue.details.get("import_reference") == EXPECTED_SYSTEM_GLOBAL for issue in result.issues)


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
    assert {issue.rule_code for issue in raw_builtin_issues} == {"S104"}


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


def test_scan_stream_non_seekable_known_size_buffers_full_payload_past_raw_cap() -> None:
    payload = pickle.dumps({"pad": b"A" * 4096}, protocol=4)

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": 64}).scan_stream(
        NonSeekableBytesIO(payload),
        len(payload),
        source="known-large-nonseek.pkl",
    )

    assert result.success is True
    assert result.metadata["pickle_stream_bytes_buffered"] == len(payload)
    assert "pickle_stream_truncated_for_root_scan" not in result.metadata


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


def test_scan_missing_path_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "missing.pkl"

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert any(check.name == "Path Exists" for check in result.checks)
