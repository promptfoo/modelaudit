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
