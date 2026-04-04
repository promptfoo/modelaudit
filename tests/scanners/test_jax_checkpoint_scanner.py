import json
import os
import pickle
from pathlib import Path

import pytest

from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.jax_checkpoint_scanner import JaxCheckpointScanner


def _write_orbax_metadata(checkpoint_dir: Path, metadata: dict[str, object]) -> None:
    checkpoint_dir.mkdir()
    (checkpoint_dir / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")


def _proto4_short_unicode(value: str) -> bytes:
    encoded = value.encode("utf-8")
    assert len(encoded) <= 255
    return b"\x8c" + bytes([len(encoded)]) + encoded


def _proto4_binunicode(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return b"X" + len(encoded).to_bytes(4, "little") + encoded


def test_orbax_metadata_regex_patterns_are_detected(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_checkpoint"
    _write_orbax_metadata(
        checkpoint_dir,
        {
            "version": "0.1.0",
            "type": "orbax_checkpoint",
            "jax_config": {
                "runtime_hook": "jax.experimental.host_callback.call(os.system, 'id')",
            },
        },
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    failed_checks = [check for check in result.checks if check.status == CheckStatus.FAILED]
    assert any(
        check.name == "Orbax Pattern Security Check"
        and check.severity == IssueSeverity.CRITICAL
        and check.details["pattern"] == r"jax\.experimental\.host_callback\.call"
        for check in failed_checks
    )


def test_orbax_dangerous_restore_fn_is_flagged_as_critical(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_checkpoint"
    _write_orbax_metadata(
        checkpoint_dir,
        {
            "version": "0.1.0",
            "type": "orbax_checkpoint",
            "restore_fn": "lambda x: eval(x.decode())",
        },
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert any(
        check.name == "Orbax Restore Function Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["restore_fn"] == "lambda x: eval(x.decode())"
        for check in result.checks
    )


def test_orbax_benign_restore_fn_is_flagged_as_warning(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_checkpoint"
    _write_orbax_metadata(
        checkpoint_dir,
        {
            "version": "0.1.0",
            "type": "orbax_checkpoint",
            "restore_fn": "custom_deserialize",
        },
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert any(
        check.name == "Orbax Restore Function Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        and check.details["restore_fn"] == "custom_deserialize"
        for check in result.checks
    )


def test_orbax_documentation_only_mentions_do_not_trigger_pattern_check(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_checkpoint"
    _write_orbax_metadata(
        checkpoint_dir,
        {
            "version": "0.1.0",
            "type": "orbax_checkpoint",
            "description": "Documentation mentions jax.experimental.host_callback.call as unsupported.",
        },
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert all(check.name != "Orbax Pattern Security Check" for check in result.checks)
    assert all(issue.severity != IssueSeverity.CRITICAL for issue in result.issues)


def test_orbax_metadata_doc_substrings_do_not_bypass_pattern_checks(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_checkpoint"
    _write_orbax_metadata(
        checkpoint_dir,
        {
            "version": "0.1.0",
            "type": "orbax_checkpoint",
            "production": {
                "runtime_hook": "jax.experimental.host_callback.call(os.system, 'id')",
            },
            "notebook": {
                "restore_hook": "orbax.checkpoint.restore(... eval(payload))",
            },
        },
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    failed_contexts = {
        check.details["context"]
        for check in result.checks
        if check.name == "Orbax Pattern Security Check" and check.status == CheckStatus.FAILED
    }
    assert "orbax_metadata.production.runtime_hook" in failed_contexts
    assert "orbax_metadata.notebook.restore_hook" in failed_contexts


def test_orbax_metadata_doc_like_keys_with_executable_content_do_not_bypass_pattern_checks(
    tmp_path: Path,
) -> None:
    checkpoint_dir = tmp_path / "orbax_checkpoint"
    _write_orbax_metadata(
        checkpoint_dir,
        {
            "version": "0.1.0",
            "type": "orbax_checkpoint",
            "notes": "jax.experimental.host_callback.call(os.system, 'id')",
        },
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert any(
        check.name == "Orbax Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["context"] == "orbax_metadata.notes"
        and check.details["pattern"] == r"jax\.experimental\.host_callback\.call"
        for check in result.checks
    )


def test_orbax_metadata_pattern_findings_are_capped_for_repeated_strings(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_checkpoint"
    _write_orbax_metadata(
        checkpoint_dir,
        {
            "version": "0.1.0",
            "type": "orbax_checkpoint",
            "jax_config": {
                "runtime_hooks": ["jax.experimental.host_callback.call(os.system, 'id')" for _ in range(12)],
            },
        },
    )

    scanner = JaxCheckpointScanner(config={"jax_metadata_max_pattern_findings": 3})
    result = scanner.scan(str(checkpoint_dir))

    pattern_findings = [
        check
        for check in result.checks
        if check.name == "Orbax Pattern Security Check" and check.status == CheckStatus.FAILED
    ]
    limit_checks = [
        check
        for check in result.checks
        if check.name == "Orbax Pattern Finding Limit" and check.status == CheckStatus.FAILED
    ]

    assert result.success
    assert len(pattern_findings) == 3
    assert len(limit_checks) == 1
    assert limit_checks[0].severity == IssueSeverity.WARNING
    assert limit_checks[0].details["max_metadata_pattern_findings"] == 3


class _SafeJaxState:
    def __init__(self) -> None:
        self.framework = "jax"
        self.label = "boring"


class _MaliciousJaxState:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return os.system, ("echo jax-owned",)


def test_benign_jax_pickle_does_not_false_positive_on_opcode_letters(tmp_path: Path) -> None:
    pickle_path = tmp_path / "safe_state.pickle"
    pickle_path.write_bytes(
        pickle.dumps(
            {
                "framework": "jax",
                "payload": _SafeJaxState(),
                "note": "contains ordinary letters like i, o, b, c",
            },
        ),
    )

    assert JaxCheckpointScanner.can_handle(str(pickle_path))

    result = JaxCheckpointScanner().scan(str(pickle_path))

    assert result.success
    assert all(check.name != "Pickle Opcode Security Check" for check in result.checks)
    assert all(issue.severity != IssueSeverity.CRITICAL for issue in result.issues)


def test_malicious_pickle_global_opcode_is_detected(tmp_path: Path) -> None:
    pickle_path = tmp_path / "malicious_state.pickle"
    pickle_path.write_bytes(pickle.dumps({"framework": "jax", "payload": _MaliciousJaxState()}))

    assert JaxCheckpointScanner.can_handle(str(pickle_path))

    result = JaxCheckpointScanner().scan(str(pickle_path))

    assert result.success
    failed_checks = [check for check in result.checks if check.status == CheckStatus.FAILED]
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.severity == IssueSeverity.CRITICAL
        and check.details["global"] in {"os.system", "posix.system", "nt.system"}
        for check in failed_checks
    )


def test_stack_global_opcode_is_detected_after_interleaved_unhandled_stack_push(tmp_path: Path) -> None:
    pickle_path = tmp_path / "interleaved_empty_list_stack_global_state.pickle"
    payload = (
        b"\x80\x04"
        + _proto4_short_unicode("jax")
        + b"0"
        + _proto4_short_unicode("os")
        + _proto4_short_unicode("system")
        + b"]"
        + b"0"
        + b"\x93."
    )
    pickle_path.write_bytes(payload)

    assert JaxCheckpointScanner.can_handle(str(pickle_path))

    result = JaxCheckpointScanner().scan(str(pickle_path))

    assert result.success
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["opcode"] == "STACK_GLOBAL"
        and check.details["global"] == "os.system"
        for check in result.checks
    )


def test_memoized_stack_global_opcode_is_detected(tmp_path: Path) -> None:
    pickle_path = tmp_path / "memoized_stack_global_state.pickle"
    payload = (
        b"\x80\x04"
        + _proto4_short_unicode("jax")
        + b"\x94"
        + b"0"
        + _proto4_short_unicode("os")
        + b"\x94"
        + _proto4_short_unicode("system")
        + b"\x94"
        + _proto4_short_unicode("benign")
        + b"0"
        + _proto4_short_unicode("value")
        + b"0"
        + b"h\x01"
        + b"h\x02"
        + b"\x93."
    )
    pickle_path.write_bytes(payload)

    assert JaxCheckpointScanner.can_handle(str(pickle_path))

    result = JaxCheckpointScanner().scan(str(pickle_path))

    assert result.success
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["opcode"] == "STACK_GLOBAL"
        and check.details["global"] == "os.system"
        for check in result.checks
    )


def test_high_index_memoized_stack_global_opcode_is_detected_after_memo_eviction(tmp_path: Path) -> None:
    pickle_path = tmp_path / "high_index_memoized_stack_global_state.pickle"
    filler_count = JaxCheckpointScanner._PICKLE_MEMO_STATE_LIMIT + 16
    module_memo_index = filler_count + 1
    class_memo_index = filler_count + 2
    payload = bytearray(b"\x80\x04")
    payload.extend(_proto4_short_unicode("jax"))
    payload.extend(b"\x94")
    payload.extend(b"0")
    for filler_index in range(filler_count):
        payload.extend(_proto4_short_unicode(f"safe-{filler_index % 32}"))
        payload.extend(b"\x94")
        payload.extend(b"0")
    payload.extend(_proto4_short_unicode("os"))
    payload.extend(b"\x94")
    payload.extend(b"0")
    payload.extend(_proto4_short_unicode("system"))
    payload.extend(b"\x94")
    payload.extend(b"0")
    payload.extend(b"j")
    payload.extend(module_memo_index.to_bytes(4, "little"))
    payload.extend(b"j")
    payload.extend(class_memo_index.to_bytes(4, "little"))
    payload.extend(b"\x93.")
    pickle_path.write_bytes(bytes(payload))

    assert JaxCheckpointScanner.can_handle(str(pickle_path))

    result = JaxCheckpointScanner().scan(str(pickle_path))

    assert result.success
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["opcode"] == "STACK_GLOBAL"
        and check.details["global"] == "os.system"
        for check in result.checks
    )


def test_old_memoized_stack_global_opcode_is_detected_after_filler_memo_eviction(tmp_path: Path) -> None:
    pickle_path = tmp_path / "old_memoized_stack_global_state.pickle"
    payload = bytearray(b"\x80\x04")
    payload.extend(_proto4_short_unicode("jax"))
    payload.extend(b"\x94")
    payload.extend(b"0")
    payload.extend(_proto4_short_unicode("os"))
    payload.extend(b"\x94")
    payload.extend(b"0")
    payload.extend(_proto4_short_unicode("system"))
    payload.extend(b"\x94")
    payload.extend(b"0")
    for filler_index in range(JaxCheckpointScanner._PICKLE_MEMO_STATE_LIMIT + 16):
        payload.extend(_proto4_short_unicode(f"safe-{filler_index % 32}"))
        payload.extend(b"\x94")
        payload.extend(b"0")
    payload.extend(b"h\x01")
    payload.extend(b"h\x02")
    payload.extend(b"\x93.")
    pickle_path.write_bytes(bytes(payload))

    assert JaxCheckpointScanner.can_handle(str(pickle_path))

    result = JaxCheckpointScanner().scan(str(pickle_path))

    assert result.success
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["opcode"] == "STACK_GLOBAL"
        and check.details["global"] == "os.system"
        for check in result.checks
    )


def test_old_memoized_stack_global_opcode_is_detected_after_dangerous_token_flood(tmp_path: Path) -> None:
    pickle_path = tmp_path / "dangerous_token_flood_memoized_stack_global_state.pickle"
    payload = bytearray(b"\x80\x04")
    payload.extend(_proto4_short_unicode("jax"))
    payload.extend(b"\x94")
    payload.extend(b"0")
    payload.extend(_proto4_short_unicode("os"))
    payload.extend(b"\x94")
    payload.extend(b"0")
    payload.extend(_proto4_short_unicode("system"))
    payload.extend(b"\x94")
    payload.extend(b"0")
    for _ in range(JaxCheckpointScanner._PICKLE_MEMO_STATE_LIMIT + 16):
        payload.extend(_proto4_short_unicode("run"))
        payload.extend(b"\x94")
        payload.extend(b"0")
    payload.extend(b"h\x01")
    payload.extend(b"h\x02")
    payload.extend(b"\x93.")
    pickle_path.write_bytes(bytes(payload))

    assert JaxCheckpointScanner.can_handle(str(pickle_path))

    result = JaxCheckpointScanner().scan(str(pickle_path))

    assert result.success
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["opcode"] == "STACK_GLOBAL"
        and check.details["global"] == "os.system"
        for check in result.checks
    )


def test_memoize_index_stays_aligned_after_rewriting_evicted_explicit_memo_slot(tmp_path: Path) -> None:
    pickle_path = tmp_path / "rewritten_evicted_memo_slot_state.pickle"
    filler_count = JaxCheckpointScanner._PICKLE_MEMO_STATE_LIMIT + 16
    expected_system_memo_index = filler_count + 1
    payload = bytearray(b"\x80\x04")
    payload.extend(_proto4_short_unicode("jax"))
    payload.extend(b"\x94")
    payload.extend(b"0")
    for filler_index in range(filler_count):
        payload.extend(_proto4_short_unicode(f"safe-{filler_index % 32}"))
        payload.extend(b"\x94")
        payload.extend(b"0")
    payload.extend(_proto4_short_unicode("os"))
    payload.extend(b"r")
    payload.extend((0).to_bytes(4, "little"))
    payload.extend(b"0")
    payload.extend(_proto4_short_unicode("system"))
    payload.extend(b"\x94")
    payload.extend(b"0")
    payload.extend(b"h\x00")
    payload.extend(b"j")
    payload.extend(expected_system_memo_index.to_bytes(4, "little"))
    payload.extend(b"\x93.")
    pickle_path.write_bytes(bytes(payload))

    assert JaxCheckpointScanner.can_handle(str(pickle_path))

    result = JaxCheckpointScanner().scan(str(pickle_path))

    assert result.success
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["opcode"] == "STACK_GLOBAL"
        and check.details["global"] == "os.system"
        for check in result.checks
    )


def test_many_memoize_events_keep_high_memo_index_resolution_bounded(tmp_path: Path) -> None:
    pickle_path = tmp_path / "many_memoize_events_state.pickle"
    filler_count = (JaxCheckpointScanner._PICKLE_MEMO_STATE_LIMIT * 8) + 32
    module_memo_index = filler_count + 1
    class_memo_index = filler_count + 2
    payload = bytearray(b"\x80\x04")
    payload.extend(_proto4_short_unicode("jax"))
    payload.extend(b"\x94")
    payload.extend(b"0")
    for filler_index in range(filler_count):
        payload.extend(_proto4_short_unicode(f"safe-{filler_index % 32}"))
        payload.extend(b"\x94")
        payload.extend(b"0")
    payload.extend(_proto4_short_unicode("os"))
    payload.extend(b"\x94")
    payload.extend(b"0")
    payload.extend(_proto4_short_unicode("system"))
    payload.extend(b"\x94")
    payload.extend(b"0")
    payload.extend(b"j")
    payload.extend(module_memo_index.to_bytes(4, "little"))
    payload.extend(b"j")
    payload.extend(class_memo_index.to_bytes(4, "little"))
    payload.extend(b"\x93.")
    pickle_path.write_bytes(bytes(payload))

    assert JaxCheckpointScanner.can_handle(str(pickle_path))

    result = JaxCheckpointScanner().scan(str(pickle_path))

    assert result.success
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["opcode"] == "STACK_GLOBAL"
        and check.details["global"] == "os.system"
        for check in result.checks
    )


def test_pickle_opcode_findings_are_capped_for_repeated_dangerous_globals(tmp_path: Path) -> None:
    pickle_path = tmp_path / "repeated_dangerous_globals.pickle"
    payload = bytearray(b"\x80\x04")
    payload.extend(_proto4_short_unicode("jax"))
    payload.extend(b"0")
    for _ in range(12):
        payload.extend(_proto4_short_unicode("os"))
        payload.extend(_proto4_short_unicode("system"))
        payload.extend(b"\x93")
        payload.extend(b"0")
    payload.extend(b".")
    pickle_path.write_bytes(bytes(payload))

    scanner = JaxCheckpointScanner(config={"jax_pickle_max_opcode_findings": 3})
    assert scanner.can_handle(str(pickle_path))

    result = scanner.scan(str(pickle_path))

    opcode_findings = [
        check
        for check in result.checks
        if check.name == "Pickle Opcode Security Check" and check.status == CheckStatus.FAILED
    ]
    finding_limit_checks = [
        check
        for check in result.checks
        if check.name == "Pickle Opcode Finding Limit" and check.status == CheckStatus.FAILED
    ]

    assert result.success
    assert len(opcode_findings) == 3
    assert all(check.details["global"] == "os.system" for check in opcode_findings)
    assert len(finding_limit_checks) == 1
    assert finding_limit_checks[0].severity == IssueSeverity.WARNING


def test_truncated_large_pickle_prefix_keeps_dangerous_global_without_scan_error(tmp_path: Path) -> None:
    pickle_path = tmp_path / "truncated_dangerous_prefix.pickle"
    payload = (
        b"\x80\x04"
        + _proto4_short_unicode("jax")
        + b"0"
        + _proto4_short_unicode("os")
        + _proto4_short_unicode("system")
        + b"\x93"
        + b"0"
        + _proto4_binunicode("a" * 4096)
    )
    pickle_path.write_bytes(payload)

    scanner = JaxCheckpointScanner(config={"jax_pickle_max_scan_bytes": 1024})
    assert scanner.can_handle(str(pickle_path))

    result = scanner.scan(str(pickle_path))

    assert result.success
    assert any(
        check.name == "Pickle Checkpoint Prefix Scan Limit"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["global"] == "os.system"
        for check in result.checks
    )
    assert all(check.name != "Pickle Checkpoint Scan" for check in result.checks)


def test_truncated_benign_large_pickle_prefix_does_not_emit_scan_error(tmp_path: Path) -> None:
    pickle_path = tmp_path / "truncated_benign_prefix.pickle"
    payload = b"\x80\x04" + _proto4_short_unicode("jax") + b"0" + _proto4_binunicode("safe" * 1024)
    pickle_path.write_bytes(payload)

    scanner = JaxCheckpointScanner(config={"jax_pickle_max_scan_bytes": 1024})
    assert scanner.can_handle(str(pickle_path))

    result = scanner.scan(str(pickle_path))

    assert result.success
    assert all(check.name != "Pickle Checkpoint Scan" for check in result.checks)
    assert all(
        check.name != "Pickle Opcode Security Check" or check.status != CheckStatus.FAILED for check in result.checks
    )


@pytest.mark.parametrize(
    ("module_name", "global_name"),
    [
        ("_io", "FileIO"),
        ("builtins", "getattr"),
        ("dill", "load"),
        ("dill", "loads"),
        ("joblib", "load"),
        ("joblib", "_pickle_load"),
        ("marshal", "loads"),
        ("operator", "attrgetter"),
        ("subprocess", "getoutput"),
        ("types", "CodeType"),
    ],
)
def test_dangerous_loader_globals_are_detected(tmp_path: Path, module_name: str, global_name: str) -> None:
    pickle_path = tmp_path / "second_stage_loader_state.pickle"
    payload = (
        b"\x80\x04"
        + _proto4_short_unicode("jax")
        + b"\x94"
        + b"0"
        + _proto4_short_unicode(module_name)
        + b"\x94"
        + _proto4_short_unicode(global_name)
        + b"\x94"
        + b"\x93."
    )
    pickle_path.write_bytes(payload)

    assert JaxCheckpointScanner.can_handle(str(pickle_path))

    result = JaxCheckpointScanner().scan(str(pickle_path))

    assert result.success
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["global"] == f"{module_name}.{global_name}"
        for check in result.checks
    )


def test_can_handle_json_checkpoint_with_jax_metadata(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "model.checkpoint"
    checkpoint_path.write_text(
        json.dumps({"framework": "jax", "orbax_version": "0.1.0"}),
        encoding="utf-8",
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path))

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success
    assert result.metadata["checkpoint_type"] == "file"


def test_zero_max_file_size_config_does_not_flag_small_json_checkpoint_as_too_large(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "small_model.checkpoint"
    checkpoint_path.write_text(
        json.dumps({"framework": "jax", "orbax_version": "0.1.0"}),
        encoding="utf-8",
    )

    scanner = JaxCheckpointScanner(config={"max_file_size": 0})
    assert scanner.can_handle(str(checkpoint_path))

    result = scanner.scan(str(checkpoint_path))

    assert result.success
    assert all(
        check.name != "Checkpoint File Size Check" or check.status != CheckStatus.FAILED for check in result.checks
    )


def test_can_handle_json_checkpoint_with_jax_marker_after_initial_header(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "late_marker_model.checkpoint"
    checkpoint_path.write_text(
        json.dumps(
            {
                "padding": "x" * 1024,
                "framework": "jax",
                "payload": "jax.experimental.host_callback.call(os.system, 'id')",
            }
        ),
        encoding="utf-8",
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path))

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success
    assert any(
        check.name == "JSON Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["context"] == "json_checkpoint.payload"
        for check in result.checks
    )


def test_can_handle_json_checkpoint_with_utf8_bom_prefix_and_jax_payload(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "bom_model.checkpoint"
    checkpoint_path.write_bytes(
        b"\xef\xbb\xbf"
        + json.dumps(
            {
                "framework": "jax",
                "payload": "jax.experimental.host_callback.call(os.system, 'id')",
            }
        ).encode("utf-8")
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path))

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success
    assert any(
        check.name == "JSON Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["context"] == "json_checkpoint.payload"
        for check in result.checks
    )


def test_scan_json_checkpoint_with_leading_whitespace_array_metadata(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "array_metadata.checkpoint"
    checkpoint_path.write_text(
        "\n  "
        + json.dumps(
            [
                "jax.experimental.host_callback.call(os.system, 'id')",
                "orbax checkpoint metadata",
            ]
        ),
        encoding="utf-8",
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path))

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success
    assert any(
        check.name == "JSON Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_can_handle_json_checkpoint_rejects_non_jax_near_match(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "generic_model.checkpoint"
    checkpoint_path.write_text(
        json.dumps({"framework": "pytorch", "format": "checkpoint"}),
        encoding="utf-8",
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is False


def test_can_handle_bom_json_checkpoint_rejects_non_jax_near_match(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "bom_generic_model.checkpoint"
    checkpoint_path.write_bytes(
        b"\xef\xbb\xbf" + json.dumps({"framework": "pytorch", "format": "checkpoint"}).encode("utf-8")
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is False


def test_metadata_traversal_stops_at_depth_limit_without_recursing_unbounded() -> None:
    nested_metadata: object = "jax.experimental.host_callback.call(os.system, 'id')"
    for _ in range(2 * JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH):
        nested_metadata = {"nested": nested_metadata}

    depth_cap_contexts: set[str] = set()
    assert (
        list(
            JaxCheckpointScanner._iter_string_metadata(
                nested_metadata,
                depth_cap_contexts=depth_cap_contexts,
            )
        )
        == []
    )
    assert depth_cap_contexts == {
        "root" + (".nested" * JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH),
    }


def test_deep_orbax_metadata_reports_depth_limit_without_silent_truncation(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "deep_orbax_checkpoint"
    nested_metadata: object = "jax.experimental.host_callback.call(os.system, 'id')"
    for _ in range(2 * JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH):
        nested_metadata = {"nested": nested_metadata}
    _write_orbax_metadata(
        checkpoint_dir,
        {
            "version": "0.1.0",
            "type": "orbax_checkpoint",
            "payload": nested_metadata,
        },
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert any(
        check.name == "Orbax Metadata Traversal Depth Limit"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        and check.details["traversal_depth_cap_reached"] is True
        and check.details["max_metadata_traversal_depth"] == JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH
        and check.details["context"].startswith("orbax_metadata.payload")
        for check in result.checks
    )


def test_deep_json_checkpoint_reports_depth_limit_without_silent_truncation(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "deep_model.checkpoint"
    nested_metadata: object = "jax.experimental.host_callback.call(os.system, 'id')"
    for _ in range(2 * JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH):
        nested_metadata = {"nested": nested_metadata}
    checkpoint_path.write_text(
        json.dumps({"framework": "jax", "payload": nested_metadata}),
        encoding="utf-8",
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path))

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success
    assert any(
        check.name == "JSON Metadata Traversal Depth Limit"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        and check.details["traversal_depth_cap_reached"] is True
        and check.details["max_metadata_traversal_depth"] == JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH
        and check.details["context"].startswith("json_checkpoint.payload")
        for check in result.checks
    )
