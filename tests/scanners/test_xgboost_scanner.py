"""
Tests for XGBoost model scanner

Tests cover various XGBoost model formats and security vulnerabilities:
- JSON models with valid/invalid schemas
- UBJ (Universal Binary JSON) models
- Binary .bst models with integrity checks
- Malicious content detection in all formats
- Integration with pickle scanner for .pkl/.joblib files
"""

import json
import pickle
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.xgboost_scanner import XGBoostScanner


class FakeBooster:
    """A simple class that can be pickled for testing."""

    def __init__(self):
        self.__class__.__name__ = "Booster"


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def xgboost_scanner():
    """Create an XGBoost scanner instance."""
    return XGBoostScanner()


@pytest.fixture
def valid_xgboost_json():
    """Valid XGBoost JSON model structure."""
    return {
        "version": [1, 7, 4],
        "learner": {
            "feature_names": ["feature_0", "feature_1", "feature_2"],
            "feature_types": ["float", "float", "float"],
            "learner_model_param": {
                "base_score": "0.5",
                "boost_from_average": "1",
                "num_class": "0",
                "num_features": "3",
                "num_parallel_tree": "1",
                "num_target": "1",
                "objective": "reg:squarederror",
                "predictor": "auto",
                "random_state": "0",
                "seed": "0",
                "seed_per_iteration": "0",
                "validate_parameters": "1",
            },
            "gradient_booster": {
                "name": "gbtree",
                "model": {
                    "gbtree_model_param": {"num_trees": "2", "num_parallel_tree": "1"},
                    "trees": [
                        {
                            "tree_param": {
                                "num_roots": "1",
                                "num_nodes": "3",
                                "num_deleted": "0",
                                "max_depth": "1",
                                "num_feature": "3",
                                "size_leaf_vector": "1",
                            },
                            "loss_changes": [0.5, 0.0, 0.0],
                            "sum_hessian": [2.0, 1.0, 1.0],
                            "base_weights": [0.25, -0.5, 0.5],
                            "left_children": [1, -1, -1],
                            "right_children": [2, -1, -1],
                            "parents": [2147483647, 0, 0],
                            "split_indices": [0, 0, 0],
                            "split_conditions": [0.5, 0.0, 0.0],
                            "split_type": [0, 0, 0],
                            "default_left": [0, 0, 0],
                            "categories": [],
                            "categories_nodes": [],
                            "categories_segments": [],
                            "categories_sizes": [],
                        },
                        {
                            "tree_param": {
                                "num_roots": "1",
                                "num_nodes": "1",
                                "num_deleted": "0",
                                "max_depth": "0",
                                "num_feature": "3",
                                "size_leaf_vector": "1",
                            },
                            "loss_changes": [0.0],
                            "sum_hessian": [2.0],
                            "base_weights": [0.125],
                            "left_children": [-1],
                            "right_children": [-1],
                            "parents": [2147483647],
                            "split_indices": [0],
                            "split_conditions": [0.0],
                            "split_type": [0],
                            "default_left": [0],
                            "categories": [],
                            "categories_nodes": [],
                            "categories_segments": [],
                            "categories_sizes": [],
                        },
                    ],
                    "tree_info": [0, 0],
                },
            },
        },
    }


class TestXGBoostScannerBasic:
    """Test basic XGBoost scanner functionality."""

    def test_can_handle_supported_extensions(self, temp_dir):
        """Test that scanner handles supported XGBoost file extensions."""
        # .bst, .model, .ubj are accepted based on extension
        for ext in [".bst", ".model", ".ubj"]:
            test_file = temp_dir / f"test{ext}"
            test_file.write_text("dummy content")
            assert XGBoostScanner.can_handle(str(test_file))

        # .json requires valid XGBoost structure
        json_file = temp_dir / "test.json"
        json_file.write_text(json.dumps({"version": [1, 5, 2], "learner": {"gradient_booster": {}}}))
        assert XGBoostScanner.can_handle(str(json_file))

    def test_cannot_handle_unsupported_extensions(self, temp_dir):
        """Test that scanner rejects unsupported file extensions."""
        unsupported_extensions = [".txt", ".pkl", ".h5", ".onnx"]

        for ext in unsupported_extensions:
            test_file = temp_dir / f"test{ext}"
            test_file.write_text("dummy content")

            assert not XGBoostScanner.can_handle(str(test_file))

    def test_scanner_name_and_description(self):
        """Test scanner metadata."""
        assert XGBoostScanner.name == "xgboost"
        assert "XGBoost" in XGBoostScanner.description
        assert "vulnerabilities" in XGBoostScanner.description

    def test_nonexistent_file_handling(self, xgboost_scanner):
        """Test handling of non-existent files."""
        result = xgboost_scanner.scan("/nonexistent/path/model.bst")
        assert not result.success
        assert any("does not exist" in str(issue.message) for issue in result.issues)


class TestXGBoostJSONScanning:
    """Test XGBoost JSON model scanning."""

    def test_valid_json_model_passes(self, temp_dir, xgboost_scanner, valid_xgboost_json):
        """Test that valid XGBoost JSON model passes all checks."""
        json_file = temp_dir / "valid_model.json"
        json_file.write_text(json.dumps(valid_xgboost_json, indent=2))

        result = xgboost_scanner.scan(str(json_file))

        assert result.success
        # Should have passing checks for JSON parsing and schema validation
        passing_checks = [c for c in result.checks if c.status.value == "passed"]
        assert len(passing_checks) > 0

        # Should not have critical issues
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 0

    def test_invalid_json_fails(self, temp_dir, xgboost_scanner):
        """Test that invalid JSON content is detected."""
        json_file = temp_dir / "invalid.json"
        json_file.write_text('{"invalid": json content}')  # Invalid JSON

        result = xgboost_scanner.scan(str(json_file))

        # Should detect JSON parsing error
        assert any("Invalid JSON format" in str(issue.message) for issue in result.issues)

    def test_missing_required_keys_detected(self, temp_dir):
        """Test that scanner rejects JSON files missing required XGBoost keys in can_handle()."""
        incomplete_json = {"version": [1, 0, 0]}  # Missing learner

        json_file = temp_dir / "incomplete.json"
        json_file.write_text(json.dumps(incomplete_json))

        # Should be rejected by can_handle() - scanner won't even try to scan it
        assert not XGBoostScanner.can_handle(str(json_file))

    def test_malicious_json_content_detected(self, temp_dir, xgboost_scanner):
        """Test detection of malicious patterns in JSON."""
        malicious_json = {
            "version": [1, 0, 0],
            "learner": {
                "malicious_code": "os.system('rm -rf /')",
                "eval_call": "eval('__import__(\\'os\\').system(\\'ls\\')')",
                "subprocess_usage": "subprocess.run(['cat', '/etc/passwd'])",
            },
        }

        json_file = temp_dir / "malicious.json"
        json_file.write_text(json.dumps(malicious_json))

        result = xgboost_scanner.scan(str(json_file))

        # Should detect multiple suspicious patterns
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0
        assert any("Suspicious pattern detected" in str(issue.message) for issue in critical_issues)


@pytest.mark.skipif(not hasattr(pytest, "importorskip"), reason="pytest.importorskip not available")
class TestXGBoostUBJScanning:
    """Test XGBoost UBJ model scanning."""

    def test_ubj_without_ubjson_library(self, temp_dir, xgboost_scanner):
        """Test UBJ scanning without ubjson library (INFO level)."""
        ubj_file = temp_dir / "model.ubj"
        ubj_file.write_bytes(b"\x7b\x55")  # UBJ object start

        with patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=False):
            result = xgboost_scanner.scan(str(ubj_file))

        # Message changed to "Cannot scan UBJ file"
        assert any("cannot scan ubj file" in str(issue.message).lower() for issue in result.issues)

    def test_invalid_ubj_detected(self, temp_dir, xgboost_scanner):
        """Test detection of invalid UBJ content."""
        ubj_file = temp_dir / "invalid.ubj"
        ubj_file.write_bytes(b"\xff\xff\xff\xff")  # Invalid UBJ data

        # Mock ubjson to be available but raise exception on decode
        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch("ubjson.loadb") as mock_loadb,
        ):
            mock_loadb.side_effect = Exception("Invalid UBJ format")

            result = xgboost_scanner.scan(str(ubj_file))

        assert any("Error analyzing XGBoost UBJ model" in str(issue.message) for issue in result.issues)


class TestXGBoostBinaryScanning:
    """Test XGBoost binary model scanning."""

    def test_empty_binary_file_detected(self, temp_dir, xgboost_scanner):
        """Test detection of empty binary files."""
        binary_file = temp_dir / "empty.bst"
        binary_file.write_bytes(b"")

        result = xgboost_scanner.scan(str(binary_file))

        assert any("empty" in str(issue.message).lower() for issue in result.issues)

    def test_pickle_masquerading_as_bst_detected(self, temp_dir, xgboost_scanner):
        """Test detection of pickle files with .bst extension."""
        # Create a pickle file
        pickle_data = pickle.dumps({"fake": "model"})

        fake_bst = temp_dir / "fake.bst"
        fake_bst.write_bytes(pickle_data)

        result = xgboost_scanner.scan(str(fake_bst))

        assert any("pickle file" in str(issue.message) for issue in result.issues)

    def test_binary_structure_validation(self, temp_dir, xgboost_scanner):
        """Test binary structure validation."""
        # Create a file with some XGBoost-like content
        binary_content = b"gbtree\x00\x00\x01\x02reg:squarederror\x00\x00"

        binary_file = temp_dir / "valid.bst"
        binary_file.write_bytes(binary_content)

        result = xgboost_scanner.scan(str(binary_file))

        # Should find expected XGBoost patterns
        pattern_checks = [c for c in result.checks if "Pattern Check" in c.name and c.status.value == "passed"]
        assert len(pattern_checks) > 0

    def test_suspicious_binary_patterns_detected(self, temp_dir, xgboost_scanner):
        """Test detection of suspicious binary patterns."""
        # Create binary data with no recognizable XGBoost patterns
        suspicious_binary = bytes(range(256))  # All byte values 0-255

        binary_file = temp_dir / "suspicious.bst"
        binary_file.write_bytes(suspicious_binary)

        result = xgboost_scanner.scan(str(binary_file))

        # Should detect unusual binary patterns
        assert any("unusual binary patterns" in str(issue.message) for issue in result.issues)

    @patch("modelaudit.scanners.xgboost_scanner._check_xgboost_available")
    def test_xgboost_loading_disabled_by_default(self, mock_check_xgb, temp_dir, xgboost_scanner):
        """Test that XGBoost loading is disabled by default."""
        mock_check_xgb.return_value = True

        binary_file = temp_dir / "test.bst"
        binary_file.write_bytes(b"some_binary_data")

        result = xgboost_scanner.scan(str(binary_file))

        # Should indicate safe mode (loading disabled)
        assert any("safe mode" in str(check.message) for check in result.checks)

    @patch("modelaudit.scanners.xgboost_scanner._check_xgboost_available")
    @patch("modelaudit.scanners.xgboost_scanner.subprocess")
    def test_xgboost_loading_success(self, mock_subprocess, mock_check_xgb, temp_dir):
        """Test successful XGBoost model loading."""
        mock_check_xgb.return_value = True
        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.stdout = "SUCCESS: Model loaded successfully"
        mock_proc.stderr = ""
        mock_subprocess.run.return_value = mock_proc

        # Create scanner with loading enabled
        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})

        binary_file = temp_dir / "valid.bst"
        binary_file.write_bytes(b"dummy_xgboost_data")

        result = loading_scanner.scan(str(binary_file))

        assert any("loaded successfully" in str(check.message) for check in result.checks)

    @patch("modelaudit.scanners.xgboost_scanner._check_xgboost_available")
    @patch("modelaudit.scanners.xgboost_scanner.subprocess")
    def test_xgboost_loading_failure(self, mock_subprocess, mock_check_xgb, temp_dir):
        """Test XGBoost model loading failure detection."""
        mock_check_xgb.return_value = True
        mock_proc = Mock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "ERROR: Invalid model format"
        mock_subprocess.run.return_value = mock_proc

        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})

        binary_file = temp_dir / "invalid.bst"
        binary_file.write_bytes(b"invalid_data")

        result = loading_scanner.scan(str(binary_file))

        assert any("Failed to load XGBoost model" in str(issue.message) for issue in result.issues)

    @patch("modelaudit.scanners.xgboost_scanner._check_xgboost_available")
    @patch("modelaudit.scanners.xgboost_scanner.subprocess")
    def test_xgboost_loading_timeout(self, mock_subprocess, mock_check_xgb, temp_dir):
        """Test XGBoost model loading timeout handling."""
        mock_check_xgb.return_value = True
        mock_subprocess.run.side_effect = mock_subprocess.TimeoutExpired(["python"], 30)

        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})

        binary_file = temp_dir / "timeout.bst"
        binary_file.write_bytes(b"data_that_causes_timeout")

        result = loading_scanner.scan(str(binary_file))

        assert any("timeout" in str(issue.message).lower() for issue in result.issues)


class TestXGBoostScannerConfiguration:
    """Test XGBoost scanner configuration options."""

    def test_xgboost_loading_enabled(self, temp_dir):
        """Test enabling XGBoost loading."""
        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})
        assert loading_scanner.enable_xgb_loading is True


class TestXGBoostSecurityPatterns:
    """Test specific security vulnerability patterns."""

    def test_hex_encoded_data_detection(self, temp_dir, xgboost_scanner):
        """Test detection of hex-encoded data that could be shellcode."""
        malicious_json = {
            "version": [1, 0, 0],
            "learner": {
                "suspicious_field": "\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48",  # Hex pattern
                "another_field": "\\x90\\x90\\x90\\x90",  # NOP sled pattern
            },
        }

        json_file = temp_dir / "hex_encoded.json"
        json_file.write_text(json.dumps(malicious_json))

        result = xgboost_scanner.scan(str(json_file))

        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0
        assert any("Hex-encoded data" in str(issue.message) for issue in critical_issues)


class TestXGBoostPickleIntegration:
    """Test integration with pickle scanner for XGBoost pickle files."""

    def test_pickle_file_with_xgboost_extension_detected(self, temp_dir, xgboost_scanner):
        """Test that pickle files masquerading as XGBoost files are detected."""
        # Create a pickle file with XGBoost-related content
        xgb_mock = FakeBooster()
        pickle_data = pickle.dumps(xgb_mock)

        fake_bst = temp_dir / "xgb_model.bst"
        fake_bst.write_bytes(pickle_data)

        result = xgboost_scanner.scan(str(fake_bst))

        # Should detect file format spoofing
        assert any("pickle file" in str(issue.message) for issue in result.issues)


# Integration tests (require actual dependencies)
@pytest.mark.integration
class TestXGBoostScannerIntegration:
    """Integration tests requiring actual XGBoost/ubjson libraries."""

    def test_real_xgboost_model_creation_and_scan(self, temp_dir):
        """Test scanning of a real XGBoost model."""
        xgboost = pytest.importorskip("xgboost", minversion="1.0")
        import numpy as np
        import xgboost as xgb

        # Create a simple dataset and train a model
        X = np.random.randn(100, 3)
        y = np.random.randn(100)

        dtrain = xgb.DMatrix(X, label=y)
        params = {"objective": "reg:squarederror", "max_depth": 3, "eta": 0.1}
        model = xgb.train(params, dtrain, num_boost_round=5)

        # Save in different formats
        json_path = temp_dir / "real_model.json"
        bst_path = temp_dir / "real_model.bst"

        model.save_model(str(json_path))
        model.save_model(str(bst_path))

        # Scan both files
        scanner = XGBoostScanner()

        json_result = scanner.scan(str(json_path))
        bst_result = scanner.scan(str(bst_path))

        # Both should scan successfully without critical issues
        assert json_result.success
        assert bst_result.success

        json_critical = [i for i in json_result.issues if i.severity == IssueSeverity.CRITICAL]
        bst_critical = [i for i in bst_result.issues if i.severity == IssueSeverity.CRITICAL]

        assert len(json_critical) == 0, f"JSON model had critical issues: {json_critical}"
        assert len(bst_critical) == 0, f"BST model had critical issues: {bst_critical}"

    def test_real_ubj_format_scan(self, temp_dir, valid_xgboost_json):
        """Test scanning of real UBJ format."""
        ubjson = pytest.importorskip("ubjson")

        # Create UBJ file
        ubj_path = temp_dir / "model.ubj"
        ubj_data = ubjson.dumpb(valid_xgboost_json)
        ubj_path.write_bytes(ubj_data)

        scanner = XGBoostScanner()
        result = scanner.scan(str(ubj_path))

        assert result.success

        # Should successfully decode UBJ
        assert any("decoded successfully" in str(check.message) for check in result.checks)

        # Should not have critical issues for valid content (except analysis errors which are acceptable)
        critical_issues = [
            i for i in result.issues if i.severity == IssueSeverity.CRITICAL and "Error analyzing" not in str(i.message)
        ]
        assert len(critical_issues) == 0
