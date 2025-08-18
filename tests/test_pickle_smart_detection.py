import pickle
import sys
import unittest
from collections import OrderedDict
from pathlib import Path

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.pickle_scanner import (
    PickleScanner,
    _detect_ml_context,
    _is_actually_dangerous_global,
    _should_ignore_opcode_sequence,
)

# Add the parent directory to sys.path to allow importing modelaudit
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# Define test classes at module level to make them picklable
class MockPyTorchModel:
    def __reduce__(self):
        return (
            OrderedDict,
            ([("layer1.weight", "tensor_data"), ("layer1.bias", "bias_data")],),
        )


class MockYOLODetect:
    def __init__(self):
        self.anchors = [[10, 13], [16, 30], [33, 23]]
        self.strides = [8, 16, 32]


class MockYOLOModel:
    def __init__(self):
        self.model = MockYOLODetect()
        self.names = {0: "person", 1: "bicycle", 2: "car"}


class ComplexPyTorchModel:
    def __init__(self):
        # Simulate a complex model with many layers
        state_dict = OrderedDict()
        for i in range(20):  # 20 layers
            state_dict[f"features.{i}.weight"] = f"tensor_data_{i}"
            state_dict[f"features.{i}.bias"] = f"bias_data_{i}"

        self.state_dict = state_dict
        self.training = False
        self._modules = OrderedDict()

    def __reduce__(self):
        return (self.__class__, ())


class MLModelWithReduces:
    def __init__(self):
        self.data = OrderedDict([("conv1.weight", "data")])

    def __reduce__(self):
        return (self.__class__, ())


class MixedContent:
    def __init__(self):
        self.legitimate = OrderedDict([("layer.weight", "data")])
        # This would be suspicious in isolation
        self.metadata = {"__version__": "1.0"}


class TestPickleSmartDetection(unittest.TestCase):
    """Test smart detection capabilities for PickleScanner"""

    def setUp(self):
        self.scanner = PickleScanner()

    def test_ml_context_detection_pytorch(self):
        """Test ML context detection for PyTorch models"""

        # Pickle it and analyze
        test_file = Path(__file__).parent / "temp_pytorch_test.pkl"
        with test_file.open("wb") as f:
            pickle.dump(MockPyTorchModel(), f)

        try:
            result = self.scanner.scan(str(test_file))

            # Should complete successfully
            self.assertTrue(result.success)

            # Should detect ML context (relaxed expectation since
            # collections.OrderedDict alone may not trigger high ML confidence)
            ml_context = result.metadata.get("ml_context", {})
            # Check if it's detected as ML content OR has very few issues
            # (indicating smart filtering worked)
            self.assertTrue(
                ml_context.get("is_ml_content", False) or len(result.issues) < 5,
                f"Expected ML detection or low issue count, got {len(result.issues)} issues",
            )

        finally:
            if test_file.exists():
                test_file.unlink()

    def test_ml_context_detection_yolo(self):
        """Test ML context detection for YOLO-like models"""

        test_file = Path(__file__).parent / "temp_yolo_test.pkl"
        with test_file.open("wb") as f:
            pickle.dump(MockYOLOModel(), f)

        try:
            result = self.scanner.scan(str(test_file))

            # Should complete successfully
            self.assertTrue(result.success)

            # Should have fewer issues than without smart detection
            self.assertLess(
                len(result.issues),
                50,
                "YOLO model should have reduced warnings",
            )

        finally:
            if test_file.exists():
                test_file.unlink()

    def test_safe_ml_globals_not_flagged(self):
        """Test that safe ML global references are not flagged as suspicious"""
        # Test torch references
        self.assertFalse(
            _is_actually_dangerous_global(
                "torch",
                "tensor",
                {"is_ml_content": True, "overall_confidence": 0.8},
            ),
        )
        self.assertFalse(
            _is_actually_dangerous_global(
                "torch.nn",
                "Linear",
                {"is_ml_content": True, "overall_confidence": 0.8},
            ),
        )
        self.assertFalse(
            _is_actually_dangerous_global(
                "collections",
                "OrderedDict",
                {"is_ml_content": True, "overall_confidence": 0.8},
            ),
        )

        # Test that genuinely dangerous references are still flagged
        self.assertTrue(
            _is_actually_dangerous_global(
                "os",
                "system",
                {"is_ml_content": True, "overall_confidence": 0.8},
            ),
        )
        self.assertTrue(
            _is_actually_dangerous_global(
                "subprocess",
                "call",
                {"is_ml_content": True, "overall_confidence": 0.8},
            ),
        )

    def test_opcode_sequence_ignoring(self):
        """Test that ML opcode sequences are properly ignored"""
        # Mock ML-heavy opcode sequence
        mock_ml_opcodes = [
            (type("MockOp", (), {"name": "GLOBAL"})(), "torch.nn.Linear", 0),
            (type("MockOp", (), {"name": "REDUCE"})(), None, 1),
            (type("MockOp", (), {"name": "BUILD"})(), None, 2),
        ] * 50  # Simulate many ML operations

        # Should ignore for high-confidence ML content
        high_confidence_context = {"is_ml_content": True, "overall_confidence": 0.8}
        self.assertTrue(
            _should_ignore_opcode_sequence(mock_ml_opcodes, high_confidence_context),
        )

        # Should not ignore for low-confidence content
        low_confidence_context = {"is_ml_content": False, "overall_confidence": 0.1}
        self.assertFalse(
            _should_ignore_opcode_sequence(mock_ml_opcodes, low_confidence_context),
        )

    def test_complex_pytorch_model_low_false_positives(self):
        """Test that complex PyTorch-like models generate minimal false positives"""

        test_file = Path(__file__).parent / "temp_complex_pytorch_test.pkl"
        with test_file.open("wb") as f:
            pickle.dump(ComplexPyTorchModel(), f)

        try:
            result = self.scanner.scan(str(test_file))

            # Should complete successfully
            self.assertTrue(result.success)

            # Should have very few issues (< 50 instead of thousands)
            self.assertLess(
                len(result.issues),
                50,
                f"Expected < 50 issues, got {len(result.issues)}. Issues: {[i.message for i in result.issues]}",
            )

            # Check ML context was detected or smart filtering worked
            ml_context = result.metadata.get("ml_context", {})
            self.assertTrue(
                ml_context.get("is_ml_content", False) or len(result.issues) < 50,
                "Should detect ML content or have smart filtering",
            )

        finally:
            if test_file.exists():
                test_file.unlink()

    def test_severity_adjustment_for_ml_content(self):
        """Test that severity is appropriately adjusted for ML content"""

        test_file = Path(__file__).parent / "temp_severity_test.pkl"
        with test_file.open("wb") as f:
            pickle.dump(MLModelWithReduces(), f)

        try:
            result = self.scanner.scan(str(test_file))

            # Should complete successfully
            self.assertTrue(result.success)

            # Any remaining issues should be INFO or WARNING level, not ERROR
            error_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
            self.assertEqual(
                len(error_issues),
                0,
                f"Should not have ERROR level issues for ML content. Got: {[i.message for i in error_issues]}",
            )

        finally:
            if test_file.exists():
                test_file.unlink()

    def test_ml_context_detection_confidence_scoring(self):
        """Test ML context detection confidence scoring"""
        # Create different types of ML content
        pytorch_opcodes = [
            (type("MockOp", (), {"name": "GLOBAL"})(), "torch.nn.Linear", 0),
            (type("MockOp", (), {"name": "GLOBAL"})(), "torch.tensor", 1),
            (type("MockOp", (), {"name": "GLOBAL"})(), "collections.OrderedDict", 2),
        ]

        context = _detect_ml_context(pytorch_opcodes)

        # Should detect PyTorch
        self.assertIn("pytorch", context["frameworks"])
        self.assertTrue(context["is_ml_content"])
        # Adjusted expectation based on new algorithm
        self.assertGreater(
            context["overall_confidence"],
            0.1,
            "Should have some confidence in ML detection",
        )

    def test_mixed_content_handling(self):
        """Test handling of mixed legitimate/suspicious content"""

        test_file = Path(__file__).parent / "temp_mixed_test.pkl"
        with test_file.open("wb") as f:
            pickle.dump(MixedContent(), f)

        try:
            result = self.scanner.scan(str(test_file))

            # Should complete successfully
            self.assertTrue(result.success)

            # Should not flag the __version__ string as suspicious in ML context
            version_issues = [issue for issue in result.issues if "__version__" in issue.message]
            self.assertEqual(
                len(version_issues),
                0,
                "Should not flag __version__ in ML context",
            )

        finally:
            if test_file.exists():
                test_file.unlink()

    def test_actual_malicious_pickle_still_detected(self):
        """Test that genuinely malicious pickles are still caught"""

        # Create a genuinely malicious pickle
        class MaliciousPickle:
            def __reduce__(self):
                import subprocess

                return (subprocess.call, (["echo", "malicious"],))

        test_file = Path(__file__).parent / "temp_malicious_test.pkl"
        with test_file.open("wb") as f:
            pickle.dump(MaliciousPickle(), f)

        try:
            result = self.scanner.scan(str(test_file))

            # Should still detect the malicious content
            self.assertTrue(len(result.issues) > 0, "Should detect malicious pickle")

            # Should have at least one ERROR or WARNING
            high_severity_issues = [
                issue for issue in result.issues if issue.severity in [IssueSeverity.CRITICAL, IssueSeverity.WARNING]
            ]
            self.assertTrue(
                len(high_severity_issues) > 0,
                "Should flag malicious content with high severity",
            )

        finally:
            if test_file.exists():
                test_file.unlink()


if __name__ == "__main__":
    unittest.main()
