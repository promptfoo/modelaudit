import struct
from pathlib import Path
from typing import Any

import pytest

# Skip if onnx is not available before importing it
pytest.importorskip("onnx")

import onnx
from onnx import TensorProto, helper
from onnx.onnx_ml_pb2 import StringStringEntryProto

from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.onnx_scanner import OnnxScanner


def create_onnx_model(
    tmp_path: Path,
    *,
    custom: bool = False,
    custom_domain: str = "com.test",
    custom_op_type: str = "CustomOp",
    external: bool = False,
    external_path: str = "weights.bin",
    external_metadata: dict[str, str] | None = None,
    external_file_bytes: bytes | None = None,
    missing_external: bool = False,
    tensor_shape: tuple[int, ...] = (1,),
) -> Path:
    X = helper.make_tensor_value_info("input", TensorProto.FLOAT, list(tensor_shape) or [1])
    Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, list(tensor_shape) or [1])
    node = (
        helper.make_node(
            custom_op_type,
            ["input"],
            ["output"],
            domain=custom_domain,
            name="custom",
        )
        if custom
        else helper.make_node("Relu", ["input"], ["output"], name="relu")
    )

    initializers = []
    if external:
        value_count = 1
        for dim in tensor_shape:
            value_count *= dim
        tensor = helper.make_tensor("W", TensorProto.FLOAT, list(tensor_shape), vals=[1.0] * max(1, value_count))
        tensor.data_location = onnx.TensorProto.EXTERNAL
        entry = StringStringEntryProto()
        entry.key = "location"
        entry.value = external_path
        tensor.external_data.append(entry)
        for key, value in (external_metadata or {}).items():
            extra_entry = StringStringEntryProto()
            extra_entry.key = key
            extra_entry.value = value
            tensor.external_data.append(extra_entry)
        initializers.append(tensor)
        if not missing_external:
            external_file = tmp_path / external_path
            external_file.parent.mkdir(parents=True, exist_ok=True)
            with open(external_file, "wb") as f:
                f.write(external_file_bytes or struct.pack("f", 1.0))
    else:
        value_count = 1
        for dim in tensor_shape:
            value_count *= dim
        tensor = helper.make_tensor("W", TensorProto.FLOAT, list(tensor_shape), vals=[1.0] * max(1, value_count))
        initializers.append(tensor)

    graph = helper.make_graph([node], "graph", [X], [Y], initializer=initializers)
    model = helper.make_model(graph)
    path = tmp_path / "model.onnx"
    onnx.save(model, str(path))
    return path


def create_python_onnx_model(tmp_path: Path) -> Path:
    X = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1])
    Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1])
    node = helper.make_node("PythonOp", ["input"], ["output"], name="python")
    graph = helper.make_graph([node], "graph", [X], [Y])
    model = helper.make_model(graph)
    path = tmp_path / "model.onnx"
    onnx.save(model, str(path))
    return path


def _failed_custom_domain_checks(result: Any) -> list[Any]:
    return [c for c in result.checks if c.name == "Custom Operator Domain Check" and c.status == CheckStatus.FAILED]


def _scan_and_extract_custom_domains(model_path: Path) -> tuple[Any, list[Any], list[str]]:
    scanner = OnnxScanner()
    result = scanner.scan(str(model_path))
    metadata = scanner.extract_metadata(str(model_path))
    custom_domains = metadata.get("custom_domains", [])
    return result, _failed_custom_domain_checks(result), custom_domains


def test_onnx_scanner_can_handle(tmp_path):
    model_path = create_onnx_model(tmp_path)
    assert OnnxScanner.can_handle(str(model_path))


def test_onnx_scanner_basic_model(tmp_path):
    model_path = create_onnx_model(tmp_path)
    scanner = OnnxScanner()
    result = scanner.scan(str(model_path))
    assert result.success
    assert result.bytes_scanned > 0
    assert not any(i.severity in (IssueSeverity.INFO, IssueSeverity.WARNING) for i in result.issues)


def test_onnx_scanner_custom_op(tmp_path: Path) -> None:
    model_path = create_onnx_model(tmp_path, custom=True)
    result = OnnxScanner().scan(str(model_path))
    assert any("custom operator" in i.message.lower() for i in result.issues)


def test_onnx_scanner_standard_ai_onnx_ml_domain_not_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="ai.onnx.ml",
        custom_op_type="LinearRegressor",
    )
    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)
    assert len(custom_domain_checks) == 0, (
        f"Expected no custom-domain finding for ai.onnx.ml. Checks: {[c.message for c in result.checks]}"
    )
    assert "ai.onnx.ml" not in metadata_custom_domains


def test_onnx_scanner_standard_preview_training_domain_not_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="ai.onnx.preview.training",
        custom_op_type="Adam",
    )
    result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)
    assert len(custom_domain_checks) == 0, (
        f"Expected no custom-domain finding for ai.onnx.preview.training. Checks: {[c.message for c in result.checks]}"
    )
    assert "ai.onnx.preview.training" not in metadata_custom_domains


def test_onnx_scanner_custom_domain_still_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="com.evil.ops",
        custom_op_type="BackdoorOp",
    )
    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)
    assert len(custom_domain_checks) > 0, "Expected custom domain finding for com.evil.ops"
    assert any(c.details.get("domain") == "com.evil.ops" for c in custom_domain_checks)
    assert "com.evil.ops" in metadata_custom_domains


def test_onnx_scanner_ai_onnx_ml_subdomain_still_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="ai.onnx.ml.malicious",
        custom_op_type="BackdoorOp",
    )
    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)
    assert len(custom_domain_checks) > 0, "Expected non-standard ai.onnx.ml subdomain to be flagged"
    assert any(c.details.get("domain") == "ai.onnx.ml.malicious" for c in custom_domain_checks)
    assert "ai.onnx.ml.malicious" in metadata_custom_domains


def test_onnx_scanner_ai_onnx_training_domain_still_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="ai.onnx.training",
        custom_op_type="BackdoorOp",
    )
    _result, custom_domain_checks, metadata_custom_domains = _scan_and_extract_custom_domains(model_path)
    assert len(custom_domain_checks) > 0, "Expected non-standard ai.onnx.training domain to be flagged"
    assert any(c.details.get("domain") == "ai.onnx.training" for c in custom_domain_checks)
    assert "ai.onnx.training" in metadata_custom_domains


def test_onnx_scanner_external_data_missing(tmp_path: Path) -> None:
    """Missing external data file should produce a WARNING-level issue."""
    model_path = create_onnx_model(tmp_path, external=True, missing_external=True)
    result = OnnxScanner().scan(str(model_path))
    missing_checks = [
        c for c in result.checks if c.name == "External Data Reference Check" and "file may not be present" in c.message
    ]
    assert len(missing_checks) > 0, f"Should flag missing external data. Checks: {[c.message for c in result.checks]}"
    assert missing_checks[0].severity == IssueSeverity.WARNING


def test_onnx_scanner_external_data_exists(tmp_path: Path) -> None:
    """Existing external data file within model dir should produce INFO-level issue."""
    model_path = create_onnx_model(tmp_path, external=True, external_path="weights.bin")
    result = OnnxScanner().scan(str(model_path))
    resolved_checks = [
        c for c in result.checks if c.name == "External Data Reference Check" and "resolved successfully" in c.message
    ]
    assert len(resolved_checks) > 0, (
        f"Should report resolved external data. Checks: {[c.message for c in result.checks]}"
    )
    assert resolved_checks[0].severity == IssueSeverity.INFO
    assert resolved_checks[0].status.value == "passed"


def test_onnx_scanner_corrupted(tmp_path: Path) -> None:
    model_path = create_onnx_model(tmp_path)
    data = model_path.read_bytes()
    # truncate file to corrupt it
    model_path.write_bytes(data[:10])
    result = OnnxScanner().scan(str(model_path))
    assert not result.success or any(i.severity == IssueSeverity.INFO for i in result.issues)


def test_onnx_scanner_python_op(tmp_path: Path) -> None:
    model_path = create_python_onnx_model(tmp_path)
    result = OnnxScanner().scan(str(model_path))
    assert result.success is False
    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)
    assert any(i.details.get("op_type") == "PythonOp" for i in result.issues)


def test_onnx_scanner_pyfunc_operator_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(tmp_path, custom=True, custom_domain="", custom_op_type="PyFunc")

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    python_op_checks = [
        c for c in result.checks if c.name == "Python Operator Detection" and c.status == CheckStatus.FAILED
    ]
    assert len(python_op_checks) > 0
    assert python_op_checks[0].severity == IssueSeverity.CRITICAL
    assert python_op_checks[0].details.get("op_type") == "PyFunc"


def test_onnx_scanner_camel_case_python_op_wrapper_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="com.example",
        custom_op_type="MyPythonOp",
    )

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        c.name == "Python Operator Detection"
        and c.status == CheckStatus.FAILED
        and c.details.get("op_type") == "MyPythonOp"
        for c in result.checks
    )


@pytest.mark.parametrize("custom_op_type", ["MY_PYTHON_OP", "MY_PY_FUNC"])
def test_onnx_scanner_uppercase_snake_python_op_wrapper_flagged(tmp_path: Path, custom_op_type: str) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="com.example",
        custom_op_type=custom_op_type,
    )

    result = OnnxScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        c.name == "Python Operator Detection"
        and c.status == CheckStatus.FAILED
        and c.details.get("op_type") == custom_op_type
        for c in result.checks
    )


def test_onnx_scanner_python_substring_near_match_not_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="",
        custom_op_type="MyPythonOptimizer",
    )

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not [c for c in result.checks if c.name == "Python Operator Detection" and c.status == CheckStatus.FAILED]


def test_onnx_scanner_python_doc_string_metadata_not_flagged_as_python_operator(tmp_path: Path) -> None:
    model_path = create_onnx_model(tmp_path)
    model = onnx.load(str(model_path), load_external_data=False)
    model.doc_string = "Generated by Python training utilities"
    onnx.save(model, str(model_path))

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not [
        issue
        for issue in result.issues
        if issue.details.get("type") == "python_operator" or "Python operator" in issue.message
    ]
    assert not [c for c in result.checks if c.name == "JIT Script Detection" and c.status == CheckStatus.FAILED]


def test_onnx_scanner_uppercase_snake_python_near_match_not_flagged(tmp_path: Path) -> None:
    model_path = create_onnx_model(
        tmp_path,
        custom=True,
        custom_domain="",
        custom_op_type="MY_PYTHON_OPTIMIZER",
    )

    result = OnnxScanner().scan(str(model_path))

    assert result.success is True
    assert not [c for c in result.checks if c.name == "Python Operator Detection" and c.status == CheckStatus.FAILED]


class TestCVE202551480SavePathTraversal:
    """Tests for CVE-2025-51480: ONNX save_external_data arbitrary file overwrite."""

    def test_traversal_detected_as_write_vuln(self, tmp_path: Path) -> None:
        """Path traversal in external_data should trigger CVE-2025-51480 (write direction)."""
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="../../../tmp/overwrite_target",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if "CVE-2025-51480" in c.name or "CVE-2025-51480" in c.message]
        assert len(cve_checks) > 0, (
            f"Should detect CVE-2025-51480 write traversal. Checks: {[c.message for c in result.checks]}"
        )
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details.get("cve_id") == "CVE-2025-51480"
        # Traversal should be classified as CVE traversal, not a simple reference.
        assert all(c.name != "External Data Reference Check" for c in result.checks)
        assert all("External Data Reference Check" not in c.message for c in result.checks)

    def test_nested_traversal_triggers_write_vuln(self, tmp_path: Path) -> None:
        """Nested traversal (lstrip bypass) should also be detected for write direction."""
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="subdir/../../overwrite_target",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2025-51480"]
        assert len(cve_checks) > 0, "Nested traversal should trigger write CVE too"

    def test_safe_path_no_write_vuln(self, tmp_path: Path) -> None:
        """Safe external data should not trigger CVE-2025-51480."""
        model_path = create_onnx_model(tmp_path, external=True, external_path="weights.bin")

        result = OnnxScanner().scan(str(model_path))

        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2025-51480"]
        assert len(cve_checks) == 0, "Safe paths should not trigger write CVE"

    def test_normalized_in_dir_path_with_dotdot_no_write_vuln(self, tmp_path: Path) -> None:
        """Paths containing '..' but resolving in-dir should not be tagged as CVE-2025-51480."""
        # We create the real target file in-dir, but build the ONNX with an external_data
        # reference of "subdir/../weights.bin" and `missing_external=True` so the model keeps
        # the external reference metadata while the resolved path still lands inside model_dir.
        (tmp_path / "weights.bin").write_bytes(struct.pack("f", 1.0))
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="subdir/../weights.bin",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2025-51480"]
        assert len(cve_checks) == 0, "Normalized in-dir path should not trigger write CVE"

    def test_absolute_sibling_path_triggers_write_vuln(self, tmp_path: Path) -> None:
        """Absolute sibling path should still be flagged as out-of-dir traversal."""
        sibling_dir = tmp_path.parent / f"{tmp_path.name}_evil"
        sibling_dir.mkdir(parents=True, exist_ok=True)
        sibling_file = sibling_dir / "weights.bin"
        sibling_file.write_bytes(struct.pack("f", 1.0))

        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path=str(sibling_file),
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))
        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2025-51480"]
        assert len(cve_checks) > 0, "Absolute sibling path must be detected as traversal"

    def test_write_vuln_details_fields(self, tmp_path: Path) -> None:
        """CVE-2025-51480 details should include cve_id, cvss, cwe, remediation."""
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="../overwrite_me",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2025-51480"]
        assert len(cve_checks) > 0
        details = cve_checks[0].details
        assert details["cvss"] == 8.8
        assert details["cwe"] == "CWE-22"
        assert "remediation" in details


class TestCVE202427318NestedPathTraversal:
    """Tests for CVE-2024-27318: ONNX nested path traversal bypass."""

    def test_nested_traversal_detected(self, tmp_path: Path) -> None:
        """Nested traversal like 'subdir/../../etc/passwd' should trigger CVE-2024-27318."""
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="subdir/../../etc/passwd",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if "CVE-2024-27318" in c.name or "CVE-2024-27318" in c.message]
        assert len(cve_checks) > 0, (
            f"Should detect CVE-2024-27318 nested traversal. Checks: {[c.message for c in result.checks]}"
        )
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details.get("cve_id") == "CVE-2024-27318"

    def test_direct_traversal_attributed_to_cve_2022(self, tmp_path: Path) -> None:
        """Direct traversal like '../../etc/passwd' should be CVE-2022-25882."""
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="../../etc/passwd",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2022-25882"]
        assert len(cve_checks) > 0, (
            f"Direct traversal should be CVE-2022-25882. Checks: {[(c.name, c.details) for c in result.checks]}"
        )

    def test_nested_traversal_nonexistent_target_still_detected(self, tmp_path: Path) -> None:
        """Traversal to non-existent paths should still be flagged (not just 'file not found')."""
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="data/../../../nonexistent/secret",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        # Should NOT be just a "file not found" - should be path traversal
        traversal_checks = [c for c in result.checks if "traversal" in c.message.lower() or "CVE-" in c.name]
        assert len(traversal_checks) > 0, (
            f"Nested traversal should be detected even for non-existent targets. "
            f"Checks: {[c.message for c in result.checks]}"
        )

    def test_safe_external_data_no_traversal_flag(self, tmp_path: Path) -> None:
        """Legitimate external data should not be flagged as traversal."""
        model_path = create_onnx_model(tmp_path, external=True, external_path="weights.bin")

        result = OnnxScanner().scan(str(model_path))

        traversal_checks = [
            c for c in result.checks if "traversal" in c.message.lower() and c.status == CheckStatus.FAILED
        ]
        assert len(traversal_checks) == 0, "Safe paths should not trigger traversal alerts"

    def test_normalized_in_dir_path_with_dotdot_no_traversal_flag(self, tmp_path: Path) -> None:
        """A path containing '..' that resolves in-dir should not be flagged as traversal."""
        (tmp_path / "weights.bin").write_bytes(struct.pack("f", 1.0))
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="subdir/../weights.bin",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        traversal_checks = [
            c for c in result.checks if "traversal" in c.message.lower() and c.status == CheckStatus.FAILED
        ]
        assert len(traversal_checks) == 0, "Normalized in-dir paths should not trigger traversal alerts"

    def test_nested_traversal_details_contain_cwe(self, tmp_path: Path) -> None:
        """CVE-2024-27318 details should include CWE-22."""
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights/../../../tmp/exfil",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2024-27318"]
        assert len(cve_checks) > 0
        assert cve_checks[0].details["cwe"] == "CWE-22"
        assert cve_checks[0].details["cvss"] == 7.5

    def test_windows_absolute_path_is_flagged_on_posix_hosts(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path=r"C:\\Windows\\System32\\drivers\\etc\\hosts",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2022-25882"]
        assert len(cve_checks) > 0
        assert all(c.name != "External Data Reference Check" for c in result.checks)


class TestExternalDataSizeValidation:
    """Tests for external_data offset/length and dtype validation."""

    def test_offset_past_remaining_data_fails_size_validation(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights.bin",
            external_metadata={"offset": "4"},
            external_file_bytes=struct.pack("ff", 1.0, 2.0),
            tensor_shape=(2,),
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        size_checks = [
            c for c in result.checks if c.name == "External Data Size Validation" and c.status == CheckStatus.FAILED
        ]
        assert len(size_checks) > 0
        assert size_checks[0].severity == IssueSeverity.CRITICAL
        assert size_checks[0].details["offset"] == 4
        assert size_checks[0].details["expected_size"] == 8

    def test_offset_and_length_covering_tensor_passes_size_validation(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights.bin",
            external_metadata={"offset": "4", "length": "8"},
            external_file_bytes=struct.pack("fff", 0.0, 1.0, 2.0),
            tensor_shape=(2,),
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is True
        size_checks = [
            c for c in result.checks if c.name == "External Data Size Validation" and c.status == CheckStatus.PASSED
        ]
        assert len(size_checks) > 0
        assert size_checks[0].details["offset"] == 4
        assert size_checks[0].details["length"] == 8

    def test_external_data_size_validation_uses_current_onnx_dtype_api(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(tmp_path, external=True, external_path="weights.bin")

        result = OnnxScanner().scan(str(model_path))

        size_checks = [c for c in result.checks if c.name == "External Data Size Validation"]
        assert len(size_checks) > 0
        assert size_checks[0].status == CheckStatus.PASSED

    def test_invalid_offset_metadata_fails_size_validation(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights.bin",
            external_metadata={"offset": "NaN"},
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        size_checks = [
            c for c in result.checks if c.name == "External Data Size Validation" and c.status == CheckStatus.FAILED
        ]
        assert len(size_checks) > 0
        assert size_checks[0].severity == IssueSeverity.CRITICAL
        assert "invalid" in size_checks[0].message.lower()

    def test_negative_offset_metadata_fails_size_validation(self, tmp_path: Path) -> None:
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="weights.bin",
            external_metadata={"offset": "-1"},
        )

        result = OnnxScanner().scan(str(model_path))

        assert result.success is False
        size_checks = [
            c for c in result.checks if c.name == "External Data Size Validation" and c.status == CheckStatus.FAILED
        ]
        assert len(size_checks) > 0
        assert size_checks[0].severity == IssueSeverity.CRITICAL
        assert "non-negative" in size_checks[0].message.lower()
