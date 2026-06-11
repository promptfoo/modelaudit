import builtins
import json
import os
import pickle
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.jax_checkpoint_scanner import JaxCheckpointScanner
from modelaudit.utils.file import detection as detection_module
from modelaudit.utils.file.detection import (
    JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES,
    JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES,
    is_confirmed_jax_json_checkpoint_file,
    is_jax_json_checkpoint_file,
)


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


def _assert_file_inconclusive_not_cached(
    path: Path,
    expected_reason: str,
    cache_dir: Path,
    **scan_kwargs: Any,
) -> None:
    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )
        second = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert expected_reason in metadata["scan_outcome_reasons"]
            assert not [
                issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            ]
            assert determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


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


def test_orbax_restore_fn_redacts_secret_assignments_in_details(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_checkpoint"
    secret = "SECRETKEY1234567890"
    fallback_secret = "FALLBACKSECRET1234567890"
    _write_orbax_metadata(
        checkpoint_dir,
        {
            "version": "0.1.0",
            "type": "orbax_checkpoint",
            "restore_fn": (
                f"lambda x: eval(x.decode()); credentials={{'client_secret': '{secret}'}}; "
                f'client_secret = os.getenv("CLIENT_SECRET", "{fallback_secret}")'
            ),
        },
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    check = next(
        check
        for check in result.checks
        if check.name == "Orbax Restore Function Check" and check.status == CheckStatus.FAILED
    )
    serialized = result.to_json()
    assert check.severity == IssueSeverity.CRITICAL
    assert secret not in serialized
    assert fallback_secret not in serialized
    assert "eval(x.decode())" in check.details["restore_fn"]
    assert "'client_secret': '<redacted>'" in check.details["restore_fn"]
    assert "client_secret = <redacted>" in check.details["restore_fn"]


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


@pytest.mark.parametrize("metadata_filename", ["metadata.json", "orbax_checkpoint_metadata.json", "_CHECKPOINT"])
def test_oversized_orbax_metadata_fails_closed_without_full_json_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    metadata_filename: str,
) -> None:
    checkpoint_dir = tmp_path / f"oversized_{metadata_filename.replace('.', '_')}"
    checkpoint_dir.mkdir()
    metadata_path = checkpoint_dir / metadata_filename
    metadata_path.write_text(
        json.dumps(
            {
                "framework": "jax",
                "type": "orbax_checkpoint",
                "padding": "x" * JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES,
            }
        ),
        encoding="utf-8",
    )
    assert metadata_path.stat().st_size > JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES

    def fail_json_load(_stream: Any) -> Any:
        raise AssertionError("oversized Orbax metadata should not be fully parsed")

    monkeypatch.setattr("modelaudit.scanners.jax_checkpoint_scanner.json.load", fail_json_load)

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_metadata_analysis_size_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Orbax Metadata Analysis Limit"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.INFO
        and check.details["file"] == metadata_filename
        and check.details["file_size"] == metadata_path.stat().st_size
        and check.details["max_json_analysis_bytes"] == JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )
    assert not [check for check in result.checks if check.severity == IssueSeverity.CRITICAL]


def test_oversized_orbax_metadata_reports_visible_bounded_pattern_before_failing_closed(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "oversized_orbax_prefix_signal"
    checkpoint_dir.mkdir()
    (checkpoint_dir / "metadata.json").write_text(
        json.dumps(
            {
                "framework": "jax",
                "type": "orbax_checkpoint",
                "payload": "jax.experimental.host_callback.call(os.system, 'id')",
                "padding": "x" * JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES,
            }
        ),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_metadata_analysis_size_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Orbax Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["context"] == "orbax_metadata_bounded_prefix.payload"
        for check in result.checks
    )


def test_oversized_orbax_metadata_preserves_visible_restore_fn_detection(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "oversized_orbax_restore_fn"
    checkpoint_dir.mkdir()
    secret = "OVERSIZEDFALLBACKSECRET123"
    (checkpoint_dir / "metadata.json").write_text(
        json.dumps(
            {
                "framework": "jax",
                "type": "orbax_checkpoint",
                "restore_fn": f'lambda x: eval(x); client_secret = os.getenv("KEY", "{secret}")',
                "padding": "x" * JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES,
            }
        ),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_metadata_analysis_size_limit" in result.metadata["scan_outcome_reasons"]
    restore_check = next(
        check
        for check in result.checks
        if check.name == "Orbax Restore Function Check" and check.status == CheckStatus.FAILED
    )
    assert secret not in result.to_json()
    assert restore_check.severity == IssueSeverity.CRITICAL
    assert restore_check.details["restore_fn"] == "lambda x: eval(x); client_secret = <redacted>"


def test_oversized_orbax_metadata_preserves_visible_nested_restore_fn_detection(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "oversized_orbax_nested_restore_fn"
    checkpoint_dir.mkdir()
    (checkpoint_dir / "metadata.json").write_text(
        json.dumps(
            {
                "framework": "jax",
                "type": "orbax_checkpoint",
                "restore_fn": ["eval"],
                "padding": "x" * JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES,
            }
        ),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_metadata_analysis_size_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Orbax Restore Function Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["restore_fn"] == "eval"
        for check in result.checks
    )


def test_oversized_orbax_metadata_reports_strongest_visible_nested_restore_fn(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "oversized_orbax_strongest_restore_fn"
    checkpoint_dir.mkdir()
    (checkpoint_dir / "metadata.json").write_text(
        json.dumps(
            {
                "framework": "jax",
                "type": "orbax_checkpoint",
                "restore_fn": ["custom_deserialize", "eval"],
                "padding": "x" * JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES,
            }
        ),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    restore_checks = [
        check
        for check in result.checks
        if check.name == "Orbax Restore Function Check" and check.status == CheckStatus.FAILED
    ]
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_metadata_analysis_size_limit" in result.metadata["scan_outcome_reasons"]
    assert len(restore_checks) == 1
    assert restore_checks[0].severity == IssueSeverity.CRITICAL
    assert restore_checks[0].details["restore_fn"] == "eval"


def test_oversized_orbax_metadata_duplicate_restore_fn_reports_once(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "oversized_orbax_duplicate_restore_fn"
    checkpoint_dir.mkdir()
    duplicate_restore_fields = ",".join('"restore_fn":"eval"' for _ in range(20))
    (checkpoint_dir / "metadata.json").write_text(
        (
            '{"framework":"jax","type":"orbax_checkpoint",'
            f'{duplicate_restore_fields},"padding":"{"x" * JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES}"'
            "}"
        ),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    restore_checks = [
        check
        for check in result.checks
        if check.name == "Orbax Restore Function Check" and check.status == CheckStatus.FAILED
    ]
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_metadata_analysis_size_limit" in result.metadata["scan_outcome_reasons"]
    assert len(restore_checks) == 1
    assert restore_checks[0].severity == IssueSeverity.CRITICAL
    assert restore_checks[0].details["restore_fn"] == "eval"


def test_oversized_orbax_doc_like_metadata_prefix_remains_benign(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "oversized_orbax_docs"
    checkpoint_dir.mkdir()
    (checkpoint_dir / "metadata.json").write_text(
        json.dumps(
            {
                "framework": "jax",
                "type": "orbax_checkpoint",
                "docs": "The jax.experimental.io_callback API is described in Orbax user documentation",
                "padding": "x" * JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES,
            }
        ),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_metadata_analysis_size_limit" in result.metadata["scan_outcome_reasons"]
    assert not [
        check
        for check in result.checks
        if check.name == "Orbax Pattern Security Check" and check.severity == IssueSeverity.CRITICAL
    ]


def test_orbax_directory_accounting_uses_inspected_files_only(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_with_unrelated_descendant"
    _write_orbax_metadata(checkpoint_dir, {"type": "orbax_checkpoint", "framework": "jax"})
    nested_dir = checkpoint_dir / "nested"
    nested_dir.mkdir()
    unrelated_payload = nested_dir / "unrelated.bin"
    unrelated_payload.write_bytes(b"x" * 4096)

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))
    metadata_size = (checkpoint_dir / "metadata.json").stat().st_size

    assert result.success is True
    assert result.bytes_scanned == metadata_size
    assert result.metadata["total_size"] == metadata_size
    assert result.metadata["orbax_files_inspected"] == 1
    assert result.metadata["directory_accounting_scope"] == "orbax_selected_files"
    assert result.bytes_scanned < unrelated_payload.stat().st_size


def test_orbax_directory_entry_count_limit_fails_closed(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_many_directory_entries"
    _write_orbax_metadata(checkpoint_dir, {"type": "orbax_checkpoint", "framework": "jax"})
    (checkpoint_dir / "unrelated.txt").write_text("not a checkpoint", encoding="utf-8")

    result = JaxCheckpointScanner(config={"jax_orbax_max_directory_entries": 1}).scan(str(checkpoint_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_directory_entry_count_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Orbax Directory Entry Count Limit"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.INFO
        and check.details["max_orbax_directory_entries"] == 1
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )


def test_orbax_directory_probe_does_not_route_on_entry_count_alone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint_dir = tmp_path / "orbax_probe_limit"
    checkpoint_dir.mkdir()
    entries_yielded = 0

    def synthetic_entries(path: Path) -> Iterator[Path]:
        nonlocal entries_yielded
        assert path == checkpoint_dir
        for index in range(JaxCheckpointScanner.DEFAULT_MAX_ORBAX_DIRECTORY_ENTRIES + 1):
            entries_yielded += 1
            yield checkpoint_dir / f"unrelated_{index}.txt"

    monkeypatch.setattr(Path, "iterdir", synthetic_entries)

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir)) is False
    assert entries_yielded == JaxCheckpointScanner.DEFAULT_MAX_ORBAX_DIRECTORY_ENTRIES + 1


def test_orbax_checkpoint_file_count_limit_fails_closed(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_many_checkpoints"
    _write_orbax_metadata(checkpoint_dir, {"type": "orbax_checkpoint", "framework": "jax"})
    (checkpoint_dir / "checkpoint_0").write_bytes(b"unknown checkpoint bytes")
    (checkpoint_dir / "checkpoint_1").write_bytes(b"unknown checkpoint bytes")

    result = JaxCheckpointScanner(config={"jax_orbax_max_checkpoint_files": 1}).scan(str(checkpoint_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_checkpoint_file_count_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Orbax Checkpoint File Count Limit"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.INFO
        and check.details["max_orbax_checkpoint_files"] == 1
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )


@pytest.mark.parametrize("checkpoint_filename", ["checkpoint_42", "params_0"])
def test_orbax_prefixed_checkpoint_file_is_scanned(tmp_path: Path, checkpoint_filename: str) -> None:
    checkpoint_dir = tmp_path / "orbax_prefixed_file"
    checkpoint_dir.mkdir()
    (checkpoint_dir / checkpoint_filename).write_bytes(b"cposix\nsystem\np0\n(Vid\np1\ntp2\nRp3\n.")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["global"] == "posix.system"
        for check in result.checks
    )


@pytest.mark.parametrize("checkpoint_entry", ["model_1", "step_0"])
@pytest.mark.parametrize("entry_kind", ["directory", "file"])
def test_bare_numbered_checkpoint_entry_does_not_route_directory(
    tmp_path: Path,
    checkpoint_entry: str,
    entry_kind: str,
) -> None:
    checkpoint_dir = tmp_path / "ordinary-model-directory"
    checkpoint_dir.mkdir()
    entry_path = checkpoint_dir / checkpoint_entry
    if entry_kind == "directory":
        entry_path.mkdir()
    else:
        entry_path.write_text("ordinary model notes", encoding="utf-8")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir)) is False


def test_numbered_checkpoint_probe_handles_short_regular_file_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint_dir = tmp_path / "short-read-checkpoint"
    checkpoint_dir.mkdir()
    (checkpoint_dir / "model_1").write_text('{"framework":"jax"}', encoding="utf-8")
    real_read = os.read

    def short_read(descriptor: int, size: int) -> bytes:
        return real_read(descriptor, min(size, 1))

    monkeypatch.setattr("modelaudit.scanners.jax_checkpoint_scanner.os.read", short_read)

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir)) is True


@pytest.mark.usefixtures("requires_symlinks")
@pytest.mark.parametrize("checkpoint_entry", ["model_1", "step_0"])
def test_linked_numbered_checkpoint_entry_selects_owner_without_content_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    checkpoint_entry: str,
) -> None:
    checkpoint_dir = tmp_path / "linked-numbered-checkpoint"
    checkpoint_dir.mkdir()
    outside_checkpoint = tmp_path / "outside-checkpoint"
    outside_checkpoint.write_bytes(b"cposix\nsystem\np0\n(Vid\np1\ntp2\nRp3\n.")
    (checkpoint_dir / checkpoint_entry).symlink_to(outside_checkpoint)

    def fail_content_probe(
        _cls: type[JaxCheckpointScanner],
        _path: Path,
        _expected_stat: os.stat_result,
    ) -> bool | None:
        raise AssertionError("directory routing must not read linked checkpoint entries")

    monkeypatch.setattr(JaxCheckpointScanner, "_probe_numbered_checkpoint_file", classmethod(fail_content_probe))

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir)) is True


def test_orbax_nested_checkpoint_directory_fails_closed(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_nested_checkpoint"
    nested_checkpoint_dir = checkpoint_dir / "step_0"
    nested_checkpoint_dir.mkdir(parents=True)
    (nested_checkpoint_dir / "checkpoint").write_bytes(b"cposix\nsystem\np0\n(Vid\np1\ntp2\nRp3\n.")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_checkpoint_entry_uninspected" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Orbax Checkpoint Entry Coverage"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.INFO
        and check.details["entry"] == "step_0"
        and check.details["entry_type"] == "directory"
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )


def test_orbax_checkpoint_entry_near_match_does_not_route_directory(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "not_orbax"
    checkpoint_dir.mkdir()
    (checkpoint_dir / "checkpointing_notes.txt").write_text("plain documentation", encoding="utf-8")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir)) is False


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


def test_pickle_candidate_probe_reuses_open_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    checkpoint_path = tmp_path / "candidate.pickle"
    checkpoint_path.write_bytes(pickle.dumps({"framework": "jax"}))

    original_open = builtins.open
    open_count = 0

    def counting_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal open_count
        if file == str(checkpoint_path):
            open_count += 1
        return original_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", counting_open)

    assert JaxCheckpointScanner._is_likely_jax_file(str(checkpoint_path)) is True
    assert open_count == 1


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


def test_protocol_zero_jax_checkpoint_pickle_global_opcode_is_detected(tmp_path: Path) -> None:
    pickle_path = tmp_path / "malicious_protocol0_state.checkpoint"
    pickle_path.write_bytes(pickle.dumps({"framework": "jax", "payload": _MaliciousJaxState()}, protocol=0))

    assert JaxCheckpointScanner.can_handle(str(pickle_path))

    result = JaxCheckpointScanner().scan(str(pickle_path))

    assert result.success
    assert not any(
        check.name == "Checkpoint Format Detection" and check.details.get("format") == "unknown"
        for check in result.checks
    )
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["global"] in {"os.system", "posix.system", "nt.system"}
        for check in result.checks
    )


def test_orbax_protocol_zero_checkpoint_without_jax_marker_scans_pickle(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_protocol0"
    checkpoint_dir.mkdir()
    checkpoint_file = checkpoint_dir / "checkpoint"
    checkpoint_file.write_bytes(b"cposix\nsystem\np0\n(Vid\np1\ntp2\nRp3\n.")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert not any(
        check.name == "Checkpoint Format Detection" and check.details.get("format") == "unknown"
        for check in result.checks
    )
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["global"] == "posix.system"
        for check in result.checks
    )


def test_orbax_protocol_one_checkpoint_without_jax_marker_scans_pickle(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_protocol1"
    checkpoint_dir.mkdir()
    checkpoint_file = checkpoint_dir / "checkpoint"
    checkpoint_file.write_bytes(pickle.dumps({"payload": _MaliciousJaxState()}, protocol=1))

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert not any(
        check.name == "Checkpoint Format Detection" and check.details.get("format") == "unknown"
        for check in result.checks
    )
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["global"] in {"os.system", "posix.system", "nt.system"}
        for check in result.checks
    )


@pytest.mark.parametrize(
    "text",
    [
        "configuration for jax checkpoint in a plain text sidecar",
        "JAX checkpoint metadata in a plain text sidecar",
    ],
)
def test_jax_text_checkpoint_with_legacy_opcode_prefix_does_not_scan_as_pickle(tmp_path: Path, text: str) -> None:
    checkpoint_path = tmp_path / "plain_text.checkpoint"
    checkpoint_path.write_text(text, encoding="utf-8")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path))

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success
    assert not any(check.name == "Pickle Checkpoint Scan" for check in result.checks)
    assert "jax_pickle_scan_failed" not in result.metadata.get("scan_outcome_reasons", [])


def test_orbax_text_checkpoint_sidecar_with_global_shape_does_not_scan_as_pickle(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_plain_text"
    checkpoint_dir.mkdir()
    (checkpoint_dir / "metadata.json").write_text("{}", encoding="utf-8")
    (checkpoint_dir / "checkpoint").write_text("configuration\nmetadata\n", encoding="utf-8")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert not any(check.name == "Pickle Checkpoint Scan" for check in result.checks)
    assert "jax_pickle_scan_failed" not in result.metadata.get("scan_outcome_reasons", [])


def test_empty_orbax_checkpoint_file_does_not_scan_as_pickle(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "empty_orbax"
    checkpoint_dir.mkdir()
    (checkpoint_dir / "checkpoint").write_bytes(b"")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert not any(check.name == "Pickle Checkpoint Scan" for check in result.checks)
    assert "jax_pickle_scan_failed" not in result.metadata.get("scan_outcome_reasons", [])


def test_orbax_plaintext_checkpoint_with_global_shaped_prefix_does_not_scan_as_pickle(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "plaintext_orbax"
    checkpoint_dir.mkdir()
    (checkpoint_dir / "checkpoint").write_text("configuration\nmetadata\n", encoding="utf-8")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert not any(check.name == "Pickle Checkpoint Scan" for check in result.checks)
    assert "jax_pickle_scan_failed" not in result.metadata.get("scan_outcome_reasons", [])


def test_orbax_legacy_probe_read_failure_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint_dir = tmp_path / "unreadable_legacy_orbax"
    checkpoint_dir.mkdir()
    checkpoint_file = checkpoint_dir / "checkpoint"
    checkpoint_file.write_bytes(b"cposix\nsystem\np0\n(Vid\np1\ntp2\nRp3\n.")
    original_open = builtins.open
    checkpoint_open_count = 0

    def fail_second_checkpoint_read(file: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal checkpoint_open_count
        if file == str(checkpoint_file) and args and args[0] == "rb":
            checkpoint_open_count += 1
            if checkpoint_open_count == 2:
                raise OSError("simulated legacy pickle probe read failure")
        return original_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fail_second_checkpoint_read)

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success is False
    assert "jax_checkpoint_file_scan_failed" in result.metadata.get("scan_outcome_reasons", [])
    assert any(
        check.name == "Checkpoint File Scan"
        and check.details.get("scan_outcome_reason") == "jax_checkpoint_file_scan_failed"
        for check in result.checks
    )


def test_single_file_legacy_indicator_read_failure_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint_file = tmp_path / "legacy_jax.checkpoint"
    checkpoint_file.write_bytes(b"Vjax\n.")
    scanner = JaxCheckpointScanner()

    monkeypatch.setattr(scanner, "_has_structural_legacy_pickle_prefix", lambda _path, _header: True)

    def fail_indicator_read(_path: str, _header: bytes) -> bool:
        raise OSError("simulated JAX indicator read failure")

    monkeypatch.setattr(scanner, "_legacy_pickle_header_has_jax_indicator", fail_indicator_read)

    result = scanner.scan(str(checkpoint_file))

    assert result.success is False
    assert "jax_checkpoint_file_scan_failed" in result.metadata.get("scan_outcome_reasons", [])
    assert any(
        check.name == "Checkpoint File Scan"
        and check.details.get("scan_outcome_reason") == "jax_checkpoint_file_scan_failed"
        for check in result.checks
    )


def test_orbax_legacy_pickle_dangerous_global_after_probe_boundary_is_detected(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_probe_boundary"
    checkpoint_dir.mkdir()
    checkpoint_file = checkpoint_dir / "checkpoint"
    harmless_prefix = b"N0" * (JaxCheckpointScanner._LEGACY_PICKLE_PREFIX_PROBE_BYTES // 2)
    checkpoint_file.write_bytes(harmless_prefix + b"cposix\nsystem\n(Vid\ntR.")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert not any(
        check.name == "Checkpoint Format Detection" and check.details.get("format") == "unknown"
        for check in result.checks
    )
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["global"] == "posix.system"
        for check in result.checks
    )


def test_orbax_protocol_zero_persid_checkpoint_scans_pickle(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_persid"
    checkpoint_dir.mkdir()
    checkpoint_file = checkpoint_dir / "checkpoint"
    checkpoint_file.write_bytes(b"Popaque_id\ncposix\nsystem\np0\n(Vid\np1\ntp2\nRp3\n.")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert not any(
        check.name == "Checkpoint Format Detection" and check.details.get("format") == "unknown"
        for check in result.checks
    )
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["global"] == "posix.system"
        for check in result.checks
    )


def test_orbax_protocol_zero_long_unicode_prefix_scans_pickle(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_long_unicode"
    checkpoint_dir.mkdir()
    checkpoint_file = checkpoint_dir / "checkpoint"
    checkpoint_file.write_bytes(
        b"V" + (b"A" * (JaxCheckpointScanner._LEGACY_PICKLE_PREFIX_PROBE_BYTES + 1)) + b"\n"
        b"cposix\nsystem\np0\n(Vid\np1\ntp2\nRp3\n."
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert not any(
        check.name == "Checkpoint Format Detection" and check.details.get("format") == "unknown"
        for check in result.checks
    )
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["global"] == "posix.system"
        for check in result.checks
    )


def test_eof_truncated_orbax_legacy_pickle_is_scanned_inconclusive(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_eof_truncated"
    checkpoint_dir.mkdir()
    checkpoint_file = checkpoint_dir / "checkpoint"
    checkpoint_file.write_bytes(b"cposix\nsystem\n")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert not any(
        check.name == "Checkpoint Format Detection" and check.details.get("format") == "unknown"
        for check in result.checks
    )
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["global"] == "posix.system"
        for check in result.checks
    )
    assert "jax_pickle_scan_failed" in result.metadata.get("scan_outcome_reasons", [])


@pytest.mark.parametrize("bytes_prefix", [b"B\x03\x00\x00\x00abc", b"C\x03abc"])
def test_orbax_binbytes_prefix_scans_pickle(tmp_path: Path, bytes_prefix: bytes) -> None:
    checkpoint_dir = tmp_path / "orbax_binbytes"
    checkpoint_dir.mkdir()
    checkpoint_file = checkpoint_dir / "checkpoint"
    checkpoint_file.write_bytes(bytes_prefix + b"cposix\nsystem\np0\n(Vid\np1\ntp2\nRp3\n.")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert not any(
        check.name == "Checkpoint Format Detection" and check.details.get("format") == "unknown"
        for check in result.checks
    )
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["global"] == "posix.system"
        for check in result.checks
    )


def test_orbax_frame_prefix_scans_pickle(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_frame"
    checkpoint_dir.mkdir()
    checkpoint_file = checkpoint_dir / "checkpoint"
    frame_payload = b"cposix\nsystem\np0\n(Vid\np1\ntp2\nRp3\n."
    checkpoint_file.write_bytes(b"\x95" + len(frame_payload).to_bytes(8, "little") + frame_payload)

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert not any(
        check.name == "Checkpoint Format Detection" and check.details.get("format") == "unknown"
        for check in result.checks
    )
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["global"] == "posix.system"
        for check in result.checks
    )


def test_orbax_truncated_binstring_prefix_scans_pickle(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_long_binstring"
    checkpoint_dir.mkdir()
    checkpoint_file = checkpoint_dir / "checkpoint"
    binary_string = b"A" * (JaxCheckpointScanner._LEGACY_PICKLE_PREFIX_PROBE_BYTES + 1)
    checkpoint_file.write_bytes(
        b"T" + len(binary_string).to_bytes(4, "little") + binary_string + b"cposix\nsystem\np0\n(Vid\np1\ntp2\nRp3\n."
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success
    assert not any(
        check.name == "Checkpoint Format Detection" and check.details.get("format") == "unknown"
        for check in result.checks
    )
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["global"] == "posix.system"
        for check in result.checks
    )


def test_orbax_truncated_numeric_prefix_is_scanned_inconclusive(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "orbax_long_numeric"
    checkpoint_dir.mkdir()
    checkpoint_file = checkpoint_dir / "checkpoint"
    checkpoint_file.write_bytes(
        b"I" + (b"9" * (JaxCheckpointScanner._LEGACY_PICKLE_PREFIX_PROBE_BYTES + 1)) + b"\n"
        b"cposix\nsystem\np0\n(Vid\np1\ntp2\nRp3\n."
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert not any(
        check.name == "Checkpoint Format Detection" and check.details.get("format") == "unknown"
        for check in result.checks
    )
    assert "jax_pickle_scan_failed" in result.metadata.get("scan_outcome_reasons", [])


def test_benign_protocol_zero_jax_checkpoint_is_scanned_as_pickle(tmp_path: Path) -> None:
    pickle_path = tmp_path / "benign_protocol0_state.checkpoint"
    pickle_path.write_bytes(pickle.dumps({"framework": "jax", "params": {"dense": [1, 2, 3]}}, protocol=0))

    assert JaxCheckpointScanner.can_handle(str(pickle_path))

    result = JaxCheckpointScanner().scan(str(pickle_path))

    assert result.success
    assert not any(
        check.name == "Checkpoint Format Detection" and check.details.get("format") == "unknown"
        for check in result.checks
    )
    assert not any(
        check.name == "Pickle Opcode Security Check" and check.status == CheckStatus.FAILED for check in result.checks
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
        + b"."
    )
    pickle_path.write_bytes(payload)

    scanner = JaxCheckpointScanner(config={"jax_pickle_max_scan_bytes": 1024})
    assert scanner.can_handle(str(pickle_path))

    result = scanner.scan(str(pickle_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "jax_pickle_scan_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Pickle Checkpoint Prefix Scan Limit"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.INFO
        for check in result.checks
    )
    assert any(
        check.name == "Pickle Opcode Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["global"] == "os.system"
        for check in result.checks
    )
    assert all(check.name != "Pickle Checkpoint Scan" for check in result.checks)

    aggregate = scan_model_directory_or_file(
        str(pickle_path),
        cache_scan_results=False,
        jax_pickle_max_scan_bytes=1024,
    )
    assert determine_exit_code(aggregate) == 1
    assert aggregate.file_metadata[str(pickle_path)]["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_pickle_scan_limit_exceeded" in aggregate.file_metadata[str(pickle_path)]["scan_outcome_reasons"]


def test_truncated_benign_large_pickle_prefix_does_not_emit_scan_error(tmp_path: Path) -> None:
    pickle_path = tmp_path / "truncated_benign_prefix.pickle"
    payload = b"\x80\x04" + _proto4_short_unicode("jax") + b"0" + _proto4_binunicode("safe" * 1024) + b"."
    pickle_path.write_bytes(payload)

    scanner = JaxCheckpointScanner(config={"jax_pickle_max_scan_bytes": 1024})
    assert scanner.can_handle(str(pickle_path))

    result = scanner.scan(str(pickle_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "jax_pickle_scan_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    assert all(check.name != "Pickle Checkpoint Scan" for check in result.checks)
    assert any(
        check.name == "Pickle Checkpoint Prefix Scan Limit"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.INFO
        for check in result.checks
    )
    assert all(
        check.name != "Pickle Opcode Security Check" or check.status != CheckStatus.FAILED for check in result.checks
    )
    _assert_file_inconclusive_not_cached(
        pickle_path,
        "jax_pickle_scan_limit_exceeded",
        tmp_path / "pickle-prefix-cache",
        jax_pickle_max_scan_bytes=1024,
    )


def test_late_dangerous_pickle_opcode_beyond_prefix_is_inconclusive(tmp_path: Path) -> None:
    pickle_path = tmp_path / "late_dangerous_prefix.pickle"
    payload = (
        b"\x80\x04"
        + _proto4_short_unicode("jax")
        + b"0"
        + _proto4_binunicode("safe" * 1024)
        + b"0"
        + _proto4_short_unicode("os")
        + _proto4_short_unicode("system")
        + b"\x93."
    )
    pickle_path.write_bytes(payload)

    scanner = JaxCheckpointScanner(config={"jax_pickle_max_scan_bytes": 1024})
    assert scanner.can_handle(str(pickle_path))

    result = scanner.scan(str(pickle_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "jax_pickle_scan_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Pickle Checkpoint Prefix Scan Limit"
        and "inspected for opcode patterns" in check.message
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )
    assert not any(
        check.name == "Pickle Opcode Security Check" and check.status == CheckStatus.FAILED for check in result.checks
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


def test_can_handle_renamed_jax_json_checkpoint_without_routing_ajax_near_match(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "model.jpg"
    native_checkpoint_path = tmp_path / "model.checkpoint"
    near_match_path = tmp_path / "ajax.jpg"
    payload = (" " * 1024) + json.dumps({"framework": "jax", "orbax_version": "0.1.0"})
    checkpoint_path.write_text(payload, encoding="utf-8")
    native_checkpoint_path.write_text(payload, encoding="utf-8")
    near_match_path.write_text(json.dumps({"framework": "ajax", "format": "checkpoint"}), encoding="utf-8")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is True
    assert JaxCheckpointScanner.can_handle(str(native_checkpoint_path)) is True
    assert JaxCheckpointScanner.can_handle(str(near_match_path)) is False


@pytest.mark.usefixtures("requires_symlinks")
def test_can_handle_refused_renamed_jax_json_symlink_as_unknown(tmp_path: Path) -> None:
    target_path = tmp_path / "payload.txt"
    symlink_path = tmp_path / "payload.jpg"
    target_path.write_text("ordinary payload", encoding="utf-8")
    symlink_path.symlink_to(target_path)

    assert is_jax_json_checkpoint_file(symlink_path) is False
    assert JaxCheckpointScanner.can_handle(str(symlink_path)) is False


def test_can_handle_unavailable_renamed_jax_json_file_as_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload_path = tmp_path / "payload.jpg"
    payload_path.write_text("ordinary payload", encoding="utf-8")

    def fail_open(_path: str | bytes | os.PathLike[str] | os.PathLike[bytes], _flags: int) -> int:
        raise PermissionError("forced JAX routing open failure")

    monkeypatch.setattr(detection_module.os, "open", fail_open)

    assert is_jax_json_checkpoint_file(payload_path) is False
    assert JaxCheckpointScanner.can_handle(str(payload_path)) is False


def test_oversized_renamed_jax_json_checkpoint_fails_closed_without_routing_ajax_near_match(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "large-model.jpg"
    near_match_path = tmp_path / "large-ajax.jpg"
    padding = "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16)
    checkpoint_path.write_text(json.dumps({"padding": padding, "framework": "jax"}), encoding="utf-8")
    near_match_path.write_text(json.dumps({"padding": padding, "framework": "ajax"}), encoding="utf-8")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is True
    assert JaxCheckpointScanner.can_handle(str(near_match_path)) is False

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "jax_json_checkpoint_analysis_size_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "JSON Checkpoint Analysis Limit"
        and check.status == CheckStatus.FAILED
        and check.message == "JSON checkpoint analysis incomplete because the file exceeds the bounded parsing limit"
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )
    _assert_file_inconclusive_not_cached(
        checkpoint_path,
        "jax_json_checkpoint_analysis_size_limit",
        tmp_path / "json-size-cache",
    )


def test_oversized_jax_json_checkpoint_reports_visible_bounded_pattern_before_failing_closed(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "malicious-large.checkpoint"
    checkpoint_path.write_text(
        json.dumps(
            {
                "framework": "jax",
                "payload": "jax.experimental.host_callback.call(os.system, 'id')",
                "padding": "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16),
            }
        ),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert any(
        check.name == "JSON Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["context"] == "json_checkpoint_bounded_prefix.payload"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "description",
    [
        "Documentation mentions jax.experimental.host_callback.call as unsupported.",
        {"detail": "Documentation mentions jax.experimental.host_callback.call as unsupported."},
        ["Documentation mentions jax.experimental.host_callback.call as unsupported."],
    ],
)
def test_oversized_jax_json_checkpoint_does_not_promote_documentation_pattern_to_critical(
    tmp_path: Path,
    description: object,
) -> None:
    checkpoint_path = tmp_path / "documentation-large.checkpoint"
    checkpoint_path.write_text(
        json.dumps(
            {
                "framework": "jax",
                "description": description,
                "padding": "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16),
            }
        ),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert all(check.name != "JSON Pattern Security Check" for check in result.checks)


def test_oversized_jax_json_checkpoint_reports_visible_nested_payload_pattern(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "nested-malicious-large.checkpoint"
    checkpoint_path.write_text(
        json.dumps(
            {
                "framework": "jax",
                "runtime": {"payload": "jax.experimental.host_callback.call(os.system, 'id')"},
                "padding": "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16),
            }
        ),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert any(
        check.name == "JSON Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["context"] == "json_checkpoint_bounded_prefix.runtime.payload"
        for check in result.checks
    )


def test_oversized_jax_json_checkpoint_reports_visible_payload_after_depth_capped_value(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "depth-capped-prefix-large.checkpoint"
    deep_value: object = "benign"
    for _ in range(JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH + 1):
        deep_value = [deep_value]
    checkpoint_path.write_text(
        json.dumps(
            {
                "framework": "jax",
                "deep": deep_value,
                "payload": "jax.experimental.io_callback",
                "padding": "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16),
            }
        ),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert any(
        check.name == "JSON Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["context"] == "json_checkpoint_bounded_prefix.payload"
        for check in result.checks
    )
    assert any(check.name == "JSON Metadata Traversal Depth Limit" for check in result.checks)


def test_oversized_jax_json_checkpoint_reports_visible_payload_after_json_parser_recursion_limit(
    tmp_path: Path,
) -> None:
    checkpoint_path = tmp_path / "recursive-prefix-large.checkpoint"
    depth = 2048
    checkpoint_path.write_text(
        '{"framework":"jax","deep":'
        + ("[" * depth)
        + "0"
        + ("]" * depth)
        + ',"payload":"jax.experimental.io_callback","padding":"'
        + ("x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16))
        + '"}',
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert any(
        check.name == "JSON Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["context"] == "json_checkpoint_bounded_prefix.payload"
        for check in result.checks
    )
    assert all(check.name != "Checkpoint File Scan" for check in result.checks)


def test_oversized_jax_json_checkpoint_reports_pattern_in_truncated_visible_string_value(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "long-payload-malicious.checkpoint"
    checkpoint_path.write_text(
        json.dumps(
            {
                "framework": "jax",
                "payload": "jax.experimental.io_callback" + ("x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16)),
            }
        ),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert any(
        check.name == "JSON Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["pattern"] == r"jax\.experimental\.io_callback"
        and check.details["context"] == "json_checkpoint_bounded_prefix.payload"
        for check in result.checks
    )


def test_oversized_jax_json_checkpoint_decodes_pattern_in_truncated_string_value(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "escaped-long-payload-malicious.checkpoint"
    checkpoint_path.write_text(
        '{"framework":"jax","payload":"jax\\u002eexperimental\\u002eio_callback'
        + ("x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16))
        + '"}',
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert any(
        check.name == "JSON Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["pattern"] == r"jax\.experimental\.io_callback"
        and check.details["context"] == "json_checkpoint_bounded_prefix.payload"
        for check in result.checks
    )


def test_oversized_jax_json_checkpoint_decodes_truncated_documentation_before_suppression(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "escaped-long-documentation.checkpoint"
    checkpoint_path.write_text(
        '{"framework":"jax","description":"caf\\u00e9 Documentation mentions '
        "jax.experimental.io_callback as unsupported. "
        + ("x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16))
        + '"}',
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert all(check.name != "JSON Pattern Security Check" for check in result.checks)


def test_oversized_jax_json_checkpoint_does_not_scan_trailing_second_root(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "trailing-document-large.checkpoint"
    checkpoint_path.write_text(
        '{"framework":"jax"}{"payload":"jax.experimental.io_callback","padding":"'
        + ("x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16))
        + '"}',
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert all(check.name != "JSON Pattern Security Check" for check in result.checks)


def test_oversized_jax_json_checkpoint_scans_visible_first_root_before_trailing_bytes(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "visible-malicious-root-with-trailing-bytes.checkpoint"
    checkpoint_path.write_text(
        '{"framework":"jax","payload":"jax.experimental.io_callback"}'
        + ("x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16)),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert any(
        check.name == "JSON Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["context"] == "json_checkpoint_bounded_prefix.payload"
        for check in result.checks
    )


def test_oversized_jax_json_checkpoint_uses_final_duplicate_value_when_root_is_visible(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "visible-root-duplicate-value.checkpoint"
    checkpoint_path.write_text(
        '{"framework":"jax","payload":"jax.experimental.io_callback","payload":"benign"}'
        + (" " * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16)),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert all(check.name != "JSON Pattern Security Check" for check in result.checks)


def test_oversized_jax_json_checkpoint_reports_visible_duplicate_value_when_root_is_truncated(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "truncated-root-duplicate-value.checkpoint"
    checkpoint_path.write_text(
        '{"framework":"jax","payload":"jax.experimental.io_callback","padding":"'
        + ("x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16))
        + '","payload":"benign"}',
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert any(
        check.name == "JSON Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["context"] == "json_checkpoint_bounded_prefix.payload"
        for check in result.checks
    )


def test_oversized_jax_json_array_reports_visible_nested_pattern(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "array-malicious.checkpoint"
    checkpoint_path.write_text(
        json.dumps(
            [
                "jax.experimental.host_callback.call(os.system, 'id')",
                "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16),
            ]
        ),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert any(
        check.name == "JSON Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["context"] == "json_checkpoint_bounded_prefix[0]"
        for check in result.checks
    )


def test_renamed_jax_json_with_root_after_routing_budget_fails_closed(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "late-root.jpg"
    checkpoint_path.write_text(
        (" " * (JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 1)) + json.dumps({"framework": "jax"}),
        encoding="utf-8",
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is True

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "jax_json_checkpoint_analysis_size_limit" in result.metadata["scan_outcome_reasons"]


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


def test_can_handle_json_checkpoint_rejects_ajax_near_match(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "ajax_model.checkpoint"
    checkpoint_path.write_text(
        json.dumps({"framework": "ajax", "format": "checkpoint"}),
        encoding="utf-8",
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is False


def test_can_handle_json_checkpoint_rejects_late_ajax_near_match(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "late_ajax_model.checkpoint"
    checkpoint_path.write_text(
        json.dumps({"padding": "x" * 1024, "framework": "ajax", "format": "checkpoint"}),
        encoding="utf-8",
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is False


def test_can_handle_pickle_checkpoint_rejects_ajax_near_match(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "ajax_state.pickle"
    checkpoint_path.write_bytes(pickle.dumps({"framework": "ajax"}))

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is False


def test_can_handle_pickle_checkpoint_accepts_protocol_zero_jax_indicator(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "state.pickle"
    checkpoint_path.write_bytes(b"Vjax\np0\n.")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is True


def test_can_handle_json_checkpoint_accepts_letter_prefixed_jax_indicator(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "prefixed_model.checkpoint"
    checkpoint_path.write_text(
        json.dumps({"framework": "myflax", "format": "checkpoint"}),
        encoding="utf-8",
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is True


def test_can_handle_bom_json_checkpoint_rejects_non_jax_near_match(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "bom_generic_model.checkpoint"
    checkpoint_path.write_bytes(
        b"\xef\xbb\xbf" + json.dumps({"framework": "pytorch", "format": "checkpoint"}).encode("utf-8")
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is False


def test_can_handle_numpy_checkpoint_rejects_ajax_filename_near_match(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "ajax_weights.checkpoint"
    checkpoint_path.write_bytes(b"\x93NUMPY" + (b"\x00" * 64))

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is False


def test_can_handle_numpy_checkpoint_accepts_underscored_jax_filename(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "model_jax_weights.checkpoint"
    checkpoint_path.write_bytes(b"\x93NUMPY")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is True


def test_can_handle_numpy_checkpoint_accepts_digit_prefixed_jax_filename(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "model1jax_weights.checkpoint"
    checkpoint_path.write_bytes(b"\x93NUMPY")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is True


def test_can_handle_numpy_checkpoint_accepts_letter_prefixed_jax_filename(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "myjax_weights.checkpoint"
    checkpoint_path.write_bytes(b"\x93NUMPY")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is True


def test_can_handle_letter_prefixed_jax_payload_still_routes_malicious_json(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "prefixed_payload.checkpoint"
    checkpoint_path.write_text(
        json.dumps(
            {
                "framework": "myjax",
                "payload": "jax.experimental.host_callback.call(os.system, 'id')",
            }
        ),
        encoding="utf-8",
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path)) is True

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success
    assert any(
        check.name == "JSON Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


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

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "jax_metadata_traversal_depth_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Orbax Metadata Traversal Depth Limit"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.INFO
        and check.details["traversal_depth_cap_reached"] is True
        and check.details["max_metadata_traversal_depth"] == JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH
        and check.details["context"].startswith("orbax_metadata.payload")
        for check in result.checks
    )


def test_deep_json_checkpoint_reports_depth_limit_without_silent_truncation(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "deep_model.jpg"
    nested_metadata: object = "jax.experimental.host_callback.call(os.system, 'id')"
    for _ in range(2 * JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH):
        nested_metadata = {"nested": nested_metadata}
    checkpoint_path.write_text(
        json.dumps({"framework": "jax", "payload": nested_metadata}),
        encoding="utf-8",
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path))

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "jax_metadata_traversal_depth_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "JSON Metadata Traversal Depth Limit"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.INFO
        and check.details["traversal_depth_cap_reached"] is True
        and check.details["max_metadata_traversal_depth"] == JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH
        and check.details["context"].startswith("json_checkpoint.payload")
        for check in result.checks
    )

    _assert_file_inconclusive_not_cached(
        checkpoint_path,
        "jax_metadata_traversal_depth_limit",
        tmp_path / "json-depth-cache",
    )


def test_malformed_jax_json_checkpoint_is_inconclusive(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "malformed.checkpoint"
    checkpoint_path.write_text('{"framework": "jax", "payload": ', encoding="utf-8")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path))

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "jax_json_parse_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "JSON Checkpoint Validation"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.INFO
        for check in result.checks
    )

    _assert_file_inconclusive_not_cached(
        checkpoint_path,
        "jax_json_parse_failed",
        tmp_path / "json-parse-cache",
    )


def test_checkpoint_file_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint_path = tmp_path / "read-failure.checkpoint"
    checkpoint_path.write_text(json.dumps({"framework": "jax", "type": "checkpoint"}), encoding="utf-8")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path))

    def fail_open(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("simulated JAX file read failure")

    def always_handles(_cls: type[JaxCheckpointScanner], _path: str) -> bool:
        return True

    monkeypatch.setattr(JaxCheckpointScanner, "can_handle", classmethod(always_handles))
    monkeypatch.setattr("modelaudit.scanners.jax_checkpoint_scanner.open", fail_open, raising=False)

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_checkpoint_file_scan_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Checkpoint File Scan"
        and check.severity == IssueSeverity.INFO
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )
    _assert_file_inconclusive_not_cached(
        checkpoint_path,
        "jax_checkpoint_file_scan_failed",
        tmp_path / "file-read-cache",
    )


def test_json_loader_failure_is_inconclusive_and_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint_path = tmp_path / "json-loader-failure.checkpoint"
    checkpoint_path.write_text(json.dumps({"framework": "jax", "type": "checkpoint"}), encoding="utf-8")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path))

    def fail_json_load(_stream: Any) -> Any:
        raise OSError("simulated JSON load failure")

    monkeypatch.setattr("modelaudit.scanners.jax_checkpoint_scanner.json.load", fail_json_load)

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_json_scan_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "JSON Checkpoint Scan"
        and check.severity == IssueSeverity.INFO
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )
    _assert_file_inconclusive_not_cached(
        checkpoint_path,
        "jax_json_scan_failed",
        tmp_path / "json-load-cache",
    )


def test_unexpected_checkpoint_dispatch_failure_is_inconclusive_and_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint_path = tmp_path / "unexpected-failure.checkpoint"
    checkpoint_path.write_text(json.dumps({"framework": "jax", "type": "checkpoint"}), encoding="utf-8")

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path))

    def fail_dispatch(_self: JaxCheckpointScanner, _path: str, _result: Any) -> None:
        raise RuntimeError("simulated JAX dispatcher failure")

    monkeypatch.setattr(JaxCheckpointScanner, "_scan_checkpoint_file", fail_dispatch)

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_checkpoint_scan_failed" in result.metadata["scan_outcome_reasons"]
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "jax_checkpoint_scan_failed"
    assert any(
        check.name == "JAX Checkpoint Scan"
        and check.severity == IssueSeverity.INFO
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )
    _assert_file_inconclusive_not_cached(
        checkpoint_path,
        "jax_checkpoint_scan_failed",
        tmp_path / "dispatcher-cache",
    )


def test_pickle_opcode_parse_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pickle_path = tmp_path / "jax_parse_failure.pickle"
    pickle_path.write_bytes(b"\x80\x04" + _proto4_short_unicode("jax") + b".")

    assert JaxCheckpointScanner.can_handle(str(pickle_path))

    def fail_genops(_data: bytes) -> Any:
        raise ValueError("simulated pickle parse failure")

    monkeypatch.setattr("modelaudit.scanners.jax_checkpoint_scanner.pickletools.genops", fail_genops)

    result = JaxCheckpointScanner().scan(str(pickle_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_pickle_scan_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Pickle Checkpoint Scan"
        and check.severity == IssueSeverity.INFO
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )


def test_object_numpy_file_is_inconclusive(tmp_path: Path) -> None:
    np = pytest.importorskip("numpy")
    checkpoint_path = tmp_path / "jax_object.ckpt"
    with checkpoint_path.open("wb") as checkpoint_file:
        np.save(checkpoint_file, np.array([{"payload": "unsafe"}], dtype=object), allow_pickle=True)

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path))

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_numpy_load_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "NumPy Checkpoint Load"
        and check.severity == IssueSeverity.INFO
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )


def test_numpy_dependency_unavailable_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    np = pytest.importorskip("numpy")
    checkpoint_path = tmp_path / "jax_numeric.ckpt"
    with checkpoint_path.open("wb") as checkpoint_file:
        np.save(checkpoint_file, np.array([1.0, 2.0, 3.0]))

    assert JaxCheckpointScanner.can_handle(str(checkpoint_path))
    monkeypatch.setattr("modelaudit.scanners.jax_checkpoint_scanner.HAS_NUMPY", False)

    result = JaxCheckpointScanner().scan(str(checkpoint_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_numpy_analysis_unavailable" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "NumPy Library Check"
        and check.severity == IssueSeverity.INFO
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )


def test_malformed_orbax_metadata_is_inconclusive(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "malformed_orbax"
    checkpoint_dir.mkdir()
    (checkpoint_dir / "metadata.json").write_text(
        '{"version": 1, "type": "orbax_checkpoint"',
        encoding="utf-8",
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))
    aggregate = scan_model_directory_or_file(str(checkpoint_dir), cache_scan_results=False)

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "jax_orbax_metadata_parse_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Orbax Metadata JSON Validation"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.INFO
        for check in result.checks
    )
    assert aggregate.file_metadata[str(checkpoint_dir)]["directory_owner_scan"] is True
    assert aggregate.file_metadata[str(checkpoint_dir)]["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert determine_exit_code(aggregate) == 2


@pytest.mark.usefixtures("requires_symlinks")
def test_metadata_symlink_selects_owner_without_content_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint_dir = tmp_path / "linked-orbax-metadata"
    checkpoint_dir.mkdir()
    outside_metadata = tmp_path / "outside-metadata.json"
    outside_metadata.write_text('{"format":"orbax","restore_fn":"os.system"}', encoding="utf-8")
    (checkpoint_dir / "metadata.json").symlink_to(outside_metadata)

    def fail_content_probe(_path: str | Path) -> bool:
        raise AssertionError("directory routing must not read linked metadata")

    monkeypatch.setattr(
        "modelaudit.scanners.jax_checkpoint_scanner.is_jax_json_checkpoint_file",
        fail_content_probe,
    )

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir)) is True


@pytest.mark.parametrize(
    "metadata",
    [
        '{"package":"backup-tool"',
        '{"description":"format orbax"',
        '{"nested":{"format":"orbax"}',
        '{"format":"jaxonomy"',
        '{"format":"borbax"',
    ],
)
def test_malformed_generic_metadata_json_is_not_routed_as_jax(tmp_path: Path, metadata: str) -> None:
    ordinary_directory = tmp_path / "malformed-backup-package"
    ordinary_directory.mkdir()
    (ordinary_directory / "metadata.json").write_text(metadata, encoding="utf-8")

    assert JaxCheckpointScanner.can_handle(str(ordinary_directory)) is False


def test_generic_metadata_json_is_not_routed_as_jax(tmp_path: Path) -> None:
    ordinary_directory = tmp_path / "backup-package"
    ordinary_directory.mkdir()
    (ordinary_directory / "metadata.json").write_text(
        '{"package":"backup-tool","restore_fn":"os.system"}',
        encoding="utf-8",
    )

    assert JaxCheckpointScanner.can_handle(str(ordinary_directory)) is False

    result = scan_model_directory_or_file(str(ordinary_directory), cache_scan_results=False)

    assert "jax_checkpoint" not in result.scanner_names
    assert not any(issue.rule_code == "S302" for issue in result.issues)
    assert determine_exit_code(result) == 0


def test_large_ambiguous_generic_metadata_json_routes_fail_closed(tmp_path: Path) -> None:
    ordinary_directory = tmp_path / "large-backup-package"
    ordinary_directory.mkdir()
    (ordinary_directory / "metadata.json").write_text(
        '{"package":"backup-tool","notes":"' + "A" * (JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 1),
        encoding="utf-8",
    )

    assert JaxCheckpointScanner.can_handle(str(ordinary_directory)) is True

    result = JaxCheckpointScanner().scan(str(ordinary_directory))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_metadata_analysis_size_limit" in result.metadata["scan_outcome_reasons"]
    assert not any(check.rule_code == "S302" for check in result.checks)


def test_late_jax_identity_routes_visible_dangerous_restore_fn(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "late-jax-identity-visible-restore"
    checkpoint_dir.mkdir()
    metadata_path = checkpoint_dir / "metadata.json"
    metadata_path.write_text(
        '{"restore_fn":"os.system","padding":"'
        + "A" * (JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 1)
        + '","framework":"jax"}',
        encoding="utf-8",
    )
    assert metadata_path.stat().st_size > JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir)) is True

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success is False
    assert "jax_orbax_metadata_analysis_size_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Orbax Restore Function Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.rule_code == "S302"
        for check in result.checks
    )


def test_late_jax_identity_and_restore_fn_route_inconclusively_without_unbounded_read(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "late-jax-identity-and-restore"
    checkpoint_dir.mkdir()
    metadata_path = checkpoint_dir / "metadata.json"
    metadata_path.write_text(
        '{"padding":"'
        + "A" * (JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 1)
        + '","framework":"jax","restore_fn":"os.system"}',
        encoding="utf-8",
    )
    assert metadata_path.stat().st_size > JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir)) is True

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_metadata_analysis_size_limit" in result.metadata["scan_outcome_reasons"]
    assert not any(check.rule_code == "S302" for check in result.checks)


def test_jax_identity_before_split_utf8_boundary_remains_confirmed(tmp_path: Path) -> None:
    metadata_path = tmp_path / "metadata.json"
    prefix = b'{"framework":"jax","padding":"'
    padding_size = JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES - len(prefix)
    metadata_path.write_bytes(prefix + b"A" * padding_size + "é".encode() + b'"}')

    assert metadata_path.stat().st_size > JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES
    assert is_confirmed_jax_json_checkpoint_file(metadata_path) is True


def test_json_parser_limit_remains_ambiguous_instead_of_raising(tmp_path: Path) -> None:
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text(
        '{"padding":' + "9" * 5000 + ',"framework":"jax"}',
        encoding="utf-8",
    )

    assert is_jax_json_checkpoint_file(metadata_path) is True


@pytest.mark.usefixtures("requires_symlinks")
def test_jax_json_routing_does_not_read_retargeted_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text('{"framework":"jax"}', encoding="utf-8")
    outside_path = tmp_path / "outside.json"
    outside_path.write_text('{"framework":"jax","restore_fn":"os.system"}', encoding="utf-8")
    original_open = detection_module.os.open

    def retarget_before_open(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], flags: int) -> int:
        metadata_path.unlink()
        metadata_path.symlink_to(outside_path)
        return original_open(path, flags)

    def fail_read(_descriptor: int, _size: int) -> bytes:
        raise AssertionError("routing must validate the opened identity before reading")

    monkeypatch.setattr(detection_module.os, "open", retarget_before_open)
    monkeypatch.setattr(detection_module.os, "read", fail_read)

    assert is_jax_json_checkpoint_file(metadata_path) is True


def test_huggingface_model_index_filename_is_not_an_orbax_directory_marker(tmp_path: Path) -> None:
    ordinary_directory = tmp_path / "diffusers-model"
    ordinary_directory.mkdir()
    (ordinary_directory / "model_index.json").write_text(
        '{"_class_name":"StableDiffusionPipeline"}',
        encoding="utf-8",
    )

    assert JaxCheckpointScanner.can_handle(str(ordinary_directory)) is False


def test_oversized_orbax_metadata_fails_closed_without_json_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint_dir = tmp_path / "oversized_orbax"
    checkpoint_dir.mkdir()
    padding = "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16)
    (checkpoint_dir / "metadata.json").write_text(
        json.dumps(
            {
                "type": "orbax_checkpoint",
                "padding": padding,
                "payload": "jax.experimental.host_callback.call(os.system, 'id')",
            }
        ),
        encoding="utf-8",
    )

    def fail_json_load(_stream: Any) -> Any:
        raise AssertionError("oversized Orbax metadata must not be fully loaded")

    monkeypatch.setattr("modelaudit.scanners.jax_checkpoint_scanner.json.load", fail_json_load)

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_metadata_analysis_size_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Orbax Metadata Analysis Limit"
        and check.status == CheckStatus.FAILED
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )
    assert all(check.name != "Orbax Pattern Security Check" for check in result.checks)


def test_oversized_orbax_metadata_reports_visible_bounded_pattern(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "oversized_orbax_visible"
    checkpoint_dir.mkdir()
    (checkpoint_dir / "metadata.json").write_text(
        json.dumps(
            {
                "type": "orbax_checkpoint",
                "payload": "jax.experimental.host_callback.call(os.system, 'id')",
                "padding": "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16),
            }
        ),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_metadata_analysis_size_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Orbax Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["context"] == "orbax_metadata_bounded_prefix.payload"
        for check in result.checks
    )


def test_oversized_orbax_metadata_reports_visible_dangerous_restore_fn(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "oversized_orbax_restore_fn"
    checkpoint_dir.mkdir()
    (checkpoint_dir / "metadata.json").write_text(
        json.dumps(
            {
                "type": "orbax_checkpoint",
                "restore_fn": "os.system",
                "padding": "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16),
            }
        ),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_metadata_analysis_size_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Orbax Restore Function Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["restore_fn"] == "os.system"
        for check in result.checks
    )


def test_oversized_orbax_metadata_keeps_visible_benign_restore_fn_warning_only(tmp_path: Path) -> None:
    checkpoint_dir = tmp_path / "oversized_orbax_benign_restore_fn"
    checkpoint_dir.mkdir()
    (checkpoint_dir / "metadata.json").write_text(
        json.dumps(
            {
                "type": "orbax_checkpoint",
                "restore_fn": "custom_deserialize",
                "padding": "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16),
            }
        ),
        encoding="utf-8",
    )

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    restore_checks = [check for check in result.checks if check.name == "Orbax Restore Function Check"]
    assert len(restore_checks) == 1
    assert restore_checks[0].status == CheckStatus.FAILED
    assert restore_checks[0].severity == IssueSeverity.WARNING
    assert restore_checks[0].details["restore_fn"] == "custom_deserialize"


def test_orbax_metadata_read_failure_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint_dir = tmp_path / "unreadable_orbax"
    _write_orbax_metadata(checkpoint_dir, {"type": "orbax_checkpoint"})

    def fail_json_load(_stream: Any) -> Any:
        raise OSError("simulated Orbax metadata read failure")

    monkeypatch.setattr("modelaudit.scanners.jax_checkpoint_scanner.json.load", fail_json_load)

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jax_orbax_metadata_read_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Orbax Metadata Read Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.INFO
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )


def test_unreadable_orbax_metadata_keeps_directory_owner_routing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint_dir = tmp_path / "unreadable_orbax"
    _write_orbax_metadata(checkpoint_dir, {"type": "orbax_checkpoint"})

    def fail_read(_descriptor: int, _size: int) -> bytes:
        raise OSError("simulated Orbax metadata routing read failure")

    monkeypatch.setattr(detection_module.os, "read", fail_read)

    assert JaxCheckpointScanner.can_handle(str(checkpoint_dir)) is True


def test_orbax_object_numpy_checkpoint_is_inconclusive(tmp_path: Path) -> None:
    np = pytest.importorskip("numpy")
    checkpoint_dir = tmp_path / "orbax_object_numpy"
    _write_orbax_metadata(checkpoint_dir, {"type": "orbax_checkpoint"})
    with (checkpoint_dir / "checkpoint_0").open("wb") as checkpoint_file:
        np.save(checkpoint_file, np.array([{"payload": "unsafe"}], dtype=object), allow_pickle=True)

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "jax_numpy_load_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "NumPy Checkpoint Load"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.INFO
        for check in result.checks
    )


def test_orbax_numeric_numpy_checkpoint_remains_clean(tmp_path: Path) -> None:
    np = pytest.importorskip("numpy")
    checkpoint_dir = tmp_path / "orbax_numeric_numpy"
    _write_orbax_metadata(checkpoint_dir, {"type": "orbax_checkpoint"})
    with (checkpoint_dir / "checkpoint_0").open("wb") as checkpoint_file:
        np.save(checkpoint_file, np.array([1.0, 2.0, 3.0]))

    result = JaxCheckpointScanner().scan(str(checkpoint_dir))

    assert result.success is True
    assert result.metadata.get("scan_outcome") != "inconclusive"
