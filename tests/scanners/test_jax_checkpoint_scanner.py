import json
import os
import pickle
from pathlib import Path

from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.jax_checkpoint_scanner import JaxCheckpointScanner


def _write_orbax_metadata(checkpoint_dir: Path, metadata: dict[str, object]) -> None:
    checkpoint_dir.mkdir()
    (checkpoint_dir / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")


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
