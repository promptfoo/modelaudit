import struct
from pathlib import Path

import pytest

# Skip if onnx is not available before importing it
pytest.importorskip("onnx")

import onnx
from onnx import TensorProto, helper
from onnx.onnx_ml_pb2 import StringStringEntryProto

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.onnx_scanner import OnnxScanner


def create_onnx_model(
    tmp_path: Path,
    *,
    custom: bool = False,
    external: bool = False,
    external_path: str = "weights.bin",
    missing_external: bool = False,
) -> Path:
    X = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1])
    Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1])
    node = (
        helper.make_node(
            "CustomOp",
            ["input"],
            ["output"],
            domain="com.test",
            name="custom",
        )
        if custom
        else helper.make_node("Relu", ["input"], ["output"], name="relu")
    )

    initializers = []
    if external:
        tensor = helper.make_tensor("W", TensorProto.FLOAT, [1], vals=[1.0])
        tensor.data_location = onnx.TensorProto.EXTERNAL
        entry = StringStringEntryProto()
        entry.key = "location"
        entry.value = external_path
        tensor.external_data.append(entry)
        initializers.append(tensor)
        if not missing_external:
            with open(tmp_path / external_path, "wb") as f:
                f.write(struct.pack("f", 1.0))
    else:
        tensor = helper.make_tensor("W", TensorProto.FLOAT, [1], vals=[1.0])
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


def test_onnx_scanner_custom_op(tmp_path):
    model_path = create_onnx_model(tmp_path, custom=True)
    result = OnnxScanner().scan(str(model_path))
    assert any("custom operator" in i.message.lower() for i in result.issues)


def test_onnx_scanner_external_data_missing(tmp_path):
    model_path = create_onnx_model(tmp_path, external=True, missing_external=True)
    result = OnnxScanner().scan(str(model_path))
    assert any("external data file" in i.message.lower() for i in result.issues)


def test_onnx_scanner_corrupted(tmp_path):
    model_path = create_onnx_model(tmp_path)
    data = model_path.read_bytes()
    # truncate file to corrupt it
    model_path.write_bytes(data[:10])
    result = OnnxScanner().scan(str(model_path))
    assert not result.success or any(i.severity == IssueSeverity.INFO for i in result.issues)


def test_onnx_scanner_python_op(tmp_path):
    model_path = create_python_onnx_model(tmp_path)
    result = OnnxScanner().scan(str(model_path))
    # Python operators are flagged at CRITICAL or INFO level depending on scanner version
    assert any(i.severity in (IssueSeverity.CRITICAL, IssueSeverity.INFO) for i in result.issues)
    assert any(i.details.get("op_type") == "PythonOp" for i in result.issues)


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

        cve_checks = [c for c in result.checks if "CVE-2025-51480" in c.name or "CVE-2025-51480" in c.message]
        assert len(cve_checks) > 0, (
            f"Should detect CVE-2025-51480 write traversal. Checks: {[c.message for c in result.checks]}"
        )
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details.get("cve_id") == "CVE-2025-51480"
        # Traversal should be classified as CVE traversal, not missing file.
        assert all(c.name != "External Data File Existence" for c in result.checks)
        assert all("External Data File Existence" not in c.message for c in result.checks)

    def test_nested_traversal_triggers_write_vuln(self, tmp_path: Path) -> None:
        """Nested traversal (lstrip bypass) should also be detected for write direction."""
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="subdir/../../overwrite_target",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

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

        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2025-51480"]
        assert len(cve_checks) > 0
        details = cve_checks[0].details
        assert details["cvss"] == 8.8
        assert details["cwe"] == "CWE-22"
        assert "remediation" in details


class TestCVE202225882PathTraversal:
    """Tests for CVE-2022-25882: ONNX external_data path traversal."""

    @staticmethod
    def _create_escaped_target(tmp_path: Path) -> tuple[Path, str]:
        """Create a target file at the correct path-traversal resolution location.

        The model is saved at ``tmp_path / "model.onnx"``, so the model directory
        is ``tmp_path``.  A relative path of ``../outside/secret.txt`` therefore
        resolves to ``tmp_path.parent / "outside" / "secret.txt"`` — one level
        *above* ``tmp_path``, not inside it.

        Returns:
            (target_file, traversal_string) where ``traversal_string`` is the
            relative path to embed in the ONNX model's external_data location.
        """
        outside_dir = tmp_path.parent / "outside"
        outside_dir.mkdir(exist_ok=True)
        target = outside_dir / "secret.txt"
        target.write_bytes(b"\x00" * 4)
        return target, "../outside/secret.txt"

    def test_path_traversal_detected(self, tmp_path):
        """external_data pointing outside model dir should trigger CVE-2022-25882."""
        _target, traversal_path = self._create_escaped_target(tmp_path)

        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path=traversal_path,
            missing_external=True,  # Don't create in model dir
        )

        result = OnnxScanner().scan(str(model_path))

        cve_checks = [c for c in result.checks if "CVE-2022-25882" in c.name or "CVE-2022-25882" in c.message]
        assert len(cve_checks) > 0, (
            f"Should detect CVE-2022-25882 path traversal. Checks: {[c.message for c in result.checks]}"
        )
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details.get("cve_id") == "CVE-2022-25882"

    def test_safe_external_data_no_cve(self, tmp_path):
        """External data within model directory should not trigger CVE-2022-25882."""
        model_path = create_onnx_model(tmp_path, external=True, external_path="weights.bin")

        result = OnnxScanner().scan(str(model_path))

        cve_issues = [c for c in result.checks if "CVE-2022-25882" in (c.name + c.message)]
        assert len(cve_issues) == 0, "Safe external data should not trigger CVE-2022-25882"

    def test_normalized_in_dir_path_with_dotdot_no_cve(self, tmp_path):
        """Paths containing '..' but normalizing inside model dir should not be CVE-tagged."""
        (tmp_path / "weights.bin").write_bytes(struct.pack("f", 1.0))
        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path="subdir/../weights.bin",
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))
        cve_issues = [c for c in result.checks if "CVE-2022-25882" in (c.name + c.message)]
        assert len(cve_issues) == 0, "Normalized in-dir path should not trigger CVE-2022-25882"

    def test_path_traversal_message_includes_path(self, tmp_path):
        """CVE-2022-25882 check message should include the offending path."""
        _target, traversal_path = self._create_escaped_target(tmp_path)

        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path=traversal_path,
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        # The traversal path should appear in a check message
        all_messages = " ".join(c.message for c in result.checks)
        assert traversal_path in all_messages, (
            f"Expected traversal path '{traversal_path}' in check messages. Got: {all_messages}"
        )

    def test_cve_details_contain_required_fields(self, tmp_path):
        """CVE-2022-25882 details should include cve_id, cvss, cwe, remediation."""
        _target, traversal_path = self._create_escaped_target(tmp_path)

        model_path = create_onnx_model(
            tmp_path,
            external=True,
            external_path=traversal_path,
            missing_external=True,
        )

        result = OnnxScanner().scan(str(model_path))

        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2022-25882"]
        assert len(cve_checks) > 0, "Should find CVE-2022-25882 check"
        details = cve_checks[0].details
        assert details["cvss"] == 7.5
        assert details["cwe"] == "CWE-22"
        assert "description" in details
        assert "remediation" in details
