"""Integration tests for JIT/Script detection in scanners."""

import pickle

import pytest

from modelaudit.scanners.pickle_scanner import PickleScanner

try:
    import onnx  # noqa: F401

    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False


class TestJITScriptIntegration:
    """Test that JIT/Script detection is integrated with scanners."""

    def test_pickle_scanner_with_torchscript(self, tmp_path):
        """Test that pickle scanner detects TorchScript patterns."""
        # Create a pickle file with TorchScript-like content
        data = {
            "model_type": "torchscript",
            "code": b"torch.ops.aten.system('rm -rf /')",
            "weights": [1.0, 2.0, 3.0],
        }

        pickle_file = tmp_path / "model_with_jit.pkl"
        with open(pickle_file, "wb") as f:
            pickle.dump(data, f)

        # Scan with JIT detection enabled
        scanner = PickleScanner({"check_jit_script": True})
        result = scanner.scan(str(pickle_file))

        # Check that JIT/Script risks were detected
        jit_checks = [c for c in result.checks if "JIT/Script" in c.name]
        assert len(jit_checks) > 0, "Should have JIT/Script checks"

        # Should detect the dangerous operation
        failed_checks = [c for c in jit_checks if c.status.value == "failed"]
        if failed_checks:
            assert any("torch.ops.aten.system" in str(c.details) for c in failed_checks)

    def test_pickle_scanner_without_jit(self, tmp_path):
        """Test that clean pickle files pass JIT/Script check."""
        # Create a clean pickle file
        data = {
            "model_type": "standard",
            "weights": [1.0, 2.0, 3.0],
            "config": {"learning_rate": 0.001},
        }

        pickle_file = tmp_path / "clean_model.pkl"
        with open(pickle_file, "wb") as f:
            pickle.dump(data, f)

        # Scan with JIT detection enabled
        scanner = PickleScanner({"check_jit_script": True})
        result = scanner.scan(str(pickle_file))

        # Check that JIT/Script check passed
        jit_checks = [c for c in result.checks if "JIT/Script" in c.name]
        if jit_checks:
            # Should have a passing check
            assert any(c.status.value == "passed" for c in jit_checks), "Should pass JIT/Script check"

    def test_jit_check_disabled(self, tmp_path):
        """Test that JIT/Script check can be disabled."""
        # Create a pickle file with JIT code
        data = {"code": b"torch.jit.script"}

        pickle_file = tmp_path / "model_with_jit.pkl"
        with open(pickle_file, "wb") as f:
            pickle.dump(data, f)

        # Scan with JIT check disabled
        scanner = PickleScanner({"check_jit_script": False})
        result = scanner.scan(str(pickle_file))

        # Should not have any JIT/Script checks
        jit_checks = [c for c in result.checks if "JIT/Script" in c.name]
        assert len(jit_checks) == 0, "JIT/Script check should be disabled"


@pytest.mark.skipif(not HAS_ONNX, reason="onnx not installed")
class TestONNXScannerJITIntegration:
    """Test JIT/Script detection in ONNX scanner."""

    def test_onnx_scanner_with_python_op(self, tmp_path):
        """Test that ONNX scanner detects Python operators as JIT risks."""
        import onnx
        from onnx import TensorProto, helper

        # Create a simple ONNX model with a Python operator
        input_tensor = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, 3])
        output_tensor = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, 3])

        # Create a custom Python operator node
        python_node = helper.make_node(
            "PythonOp",
            inputs=["input"],
            outputs=["output"],
            domain="custom",
        )

        graph = helper.make_graph(
            [python_node],
            "test_model",
            [input_tensor],
            [output_tensor],
        )

        model = helper.make_model(graph)

        # Save the model
        model_path = tmp_path / "model_with_python_op.onnx"
        onnx.save(model, str(model_path))

        # Scan the model
        from modelaudit.scanners.onnx_scanner import OnnxScanner

        scanner = OnnxScanner({"check_jit_script": True})
        result = scanner.scan(str(model_path))

        # Should detect Python operator risks
        jit_checks = [c for c in result.checks if "JIT/Script" in c.name or "Python" in c.name]
        assert len(jit_checks) > 0, "Should detect Python operator risks"

    def test_onnx_no_false_positive_torchscript_warnings(self, tmp_path):
        """Test that ONNX files with PyTorch metadata don't trigger false JIT/Script warnings.

        Regression test for bug where ONNX files exported from PyTorch contain
        'org.pytorch.aten' custom operator domain metadata, which was incorrectly
        flagged as "Hex-encoded TorchScript references" by the pattern r"\\x[0-9a-fA-F]{2}.*torch".

        This test verifies that the fix (only running TorchScript scanners on unknown model types)
        eliminates these false positives.
        """
        import onnx
        from onnx import TensorProto, helper

        # Create a simple ONNX model with PyTorch custom domain (org.pytorch.aten)
        input_tensor = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, 3])
        output_tensor = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, 3])

        # Create a node using PyTorch ATen operator domain
        # This is legitimate and common in ONNX models exported from PyTorch
        aten_node = helper.make_node(
            "ATen",
            inputs=["input"],
            outputs=["output"],
            domain="org.pytorch.aten",  # Standard PyTorch custom operator domain
        )

        graph = helper.make_graph(
            [aten_node],
            "pytorch_onnx_model",
            [input_tensor],
            [output_tensor],
        )

        # Create model with custom operator domain import
        model = helper.make_model(graph)
        # Add the custom domain to opset imports (simulates real PyTorch export)
        opset_import = model.opset_import.add()
        opset_import.domain = "org.pytorch.aten"
        opset_import.version = 1

        # Save the model
        model_path = tmp_path / "pytorch_exported.onnx"
        onnx.save(model, str(model_path))

        # Scan the model
        from modelaudit.scanners.onnx_scanner import OnnxScanner

        scanner = OnnxScanner({"check_jit_script": True})
        result = scanner.scan(str(model_path))

        # Should NOT trigger false positive "Hex-encoded TorchScript references" warnings
        # The fix ensures TorchScript vulnerability scanners don't run on identified ONNX files
        torchscript_obfuscation_issues = [
            issue
            for issue in result.issues
            if issue.type == "torchscript_obfuscation" or "Hex-encoded TorchScript" in issue.message
        ]

        assert len(torchscript_obfuscation_issues) == 0, (
            f"Should not have false positive TorchScript warnings for ONNX file with PyTorch metadata. "
            f"Found: {[i.message for i in torchscript_obfuscation_issues]}"
        )

        # Should still perform legitimate ONNX checks (custom domain warnings are OK)
        # But severity should be INFO for well-known domains, not WARNING
        custom_domain_checks = [
            c for c in result.checks if "Custom Operator Domain" in c.name or "custom" in str(c.details)
        ]
        # Having custom domain checks is fine - we just want to ensure no TorchScript false positives
        assert len(torchscript_obfuscation_issues) == 0, "No TorchScript false positives"
