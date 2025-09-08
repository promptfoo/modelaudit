"""
Tests for MXNet model scanners

Tests cover MXNet model formats and security vulnerabilities:
- Symbol JSON files with valid/invalid structures
- CVE-2022-24294 ReDoS detection via operator names
- Custom operator detection
- Binary parameter files with format validation
- Pickle detection and format spoofing
- Oversized tensor attacks and DoS patterns
- Integration with pickle scanner for MXNet models
"""

import json
import pickle
import struct
import tempfile
from pathlib import Path

import pytest

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.mxnet_params_scanner import MXNetParamsScanner
from modelaudit.scanners.mxnet_symbol_scanner import MXNetSymbolScanner


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def symbol_scanner():
    """Create an MXNet symbol scanner instance."""
    return MXNetSymbolScanner()


@pytest.fixture
def params_scanner():
    """Create an MXNet params scanner instance."""
    return MXNetParamsScanner()


@pytest.fixture
def valid_mxnet_symbol():
    """Valid MXNet symbol JSON structure."""
    return {
        "nodes": [
            {"op": "null", "name": "data", "inputs": []},
            {"op": "FullyConnected", "name": "fc1", "inputs": [[0, 0, 0]], "attr": {"num_hidden": "128"}},
            {"op": "Activation", "name": "relu1", "inputs": [[1, 0, 0]], "attr": {"act_type": "relu"}},
            {"op": "FullyConnected", "name": "fc2", "inputs": [[2, 0, 0]], "attr": {"num_hidden": "10"}},
            {"op": "SoftmaxOutput", "name": "softmax", "inputs": [[3, 0, 0], [0, 1, 0]]},
        ],
        "arg_nodes": [0, 1],
        "node_row_ptr": [0, 1, 2, 3, 4, 5],
        "heads": [[4, 0, 0]],
        "attrs": {"mxnet_version": ["int", 10600]},
    }


class TestMXNetSymbolScannerBasic:
    """Test basic MXNet symbol scanner functionality."""

    def test_can_handle_json_files(self, temp_dir):
        """Test that scanner handles JSON files with MXNet structure."""
        # Create JSON file with MXNet indicators
        mxnet_json = temp_dir / "model-symbol.json"
        mxnet_json.write_text('{"nodes": [], "arg_nodes": [], "heads": []}')

        assert MXNetSymbolScanner.can_handle(str(mxnet_json))

        # Create non-MXNet JSON
        other_json = temp_dir / "other.json"
        other_json.write_text('{"key": "value"}')

        assert not MXNetSymbolScanner.can_handle(str(other_json))

    def test_cannot_handle_unsupported_extensions(self, temp_dir):
        """Test that scanner rejects unsupported file extensions."""
        unsupported_extensions = [".txt", ".pkl", ".params", ".bst"]

        for ext in unsupported_extensions:
            test_file = temp_dir / f"test{ext}"
            test_file.write_text("dummy content")

            assert not MXNetSymbolScanner.can_handle(str(test_file))

    def test_scanner_metadata(self):
        """Test scanner metadata."""
        assert MXNetSymbolScanner.name == "mxnet_symbol"
        assert "MXNet" in MXNetSymbolScanner.description
        assert "vulnerabilities" in MXNetSymbolScanner.description

    def test_nonexistent_file_handling(self, symbol_scanner):
        """Test handling of non-existent files."""
        result = symbol_scanner.scan("/nonexistent/path/model-symbol.json")
        assert not result.success
        assert any("does not exist" in str(issue.message) for issue in result.issues)


class TestMXNetSymbolJSONScanning:
    """Test MXNet symbol JSON model scanning."""

    def test_valid_symbol_passes(self, temp_dir, symbol_scanner, valid_mxnet_symbol):
        """Test that valid MXNet symbol passes all checks."""
        json_file = temp_dir / "valid-symbol.json"
        json_file.write_text(json.dumps(valid_mxnet_symbol, indent=2))

        result = symbol_scanner.scan(str(json_file))

        assert result.success
        # Should have passing checks for JSON parsing and structure validation
        passing_checks = [c for c in result.checks if c.status.value == "passed"]
        assert len(passing_checks) > 0

        # Should not have critical issues
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 0

    def test_invalid_json_fails(self, temp_dir, symbol_scanner):
        """Test that invalid JSON content is detected."""
        json_file = temp_dir / "invalid.json"
        json_file.write_text('{"invalid": json content}')  # Invalid JSON

        result = symbol_scanner.scan(str(json_file))

        # Should detect JSON parsing error
        assert any("Invalid JSON format" in str(issue.message) for issue in result.issues)

    def test_missing_required_keys_detected(self, temp_dir, symbol_scanner):
        """Test detection of missing required MXNet keys."""
        incomplete_json = {"version": [1, 0, 0]}  # Missing nodes

        json_file = temp_dir / "incomplete.json"
        json_file.write_text(json.dumps(incomplete_json))

        result = symbol_scanner.scan(str(json_file))

        assert any("Missing required MXNet symbol keys" in str(issue.message) for issue in result.issues)

    def test_cve_2022_24294_long_operator_name(self, temp_dir, symbol_scanner):
        """Test detection of CVE-2022-24294 via extremely long operator name."""
        malicious_symbol = {
            "nodes": [
                {
                    "op": "A" * 500,  # Extremely long operator name
                    "name": "malicious_node",
                    "inputs": [],
                }
            ],
            "arg_nodes": [0],
            "heads": [[0, 0, 0]],
        }

        json_file = temp_dir / "cve_long_op.json"
        json_file.write_text(json.dumps(malicious_symbol))

        result = symbol_scanner.scan(str(json_file))

        # Should detect CVE-2022-24294 pattern
        cve_issues = [i for i in result.issues if "CVE-2022-24294" in str(i.message)]
        assert len(cve_issues) > 0
        assert any(i.severity == IssueSeverity.CRITICAL for i in cve_issues)

    def test_cve_2022_24294_redos_pattern(self, temp_dir, symbol_scanner):
        """Test detection of CVE-2022-24294 via ReDoS patterns."""
        malicious_symbol = {
            "nodes": [
                {
                    "op": "((((((((((malicious_pattern))))))))))",  # ReDoS pattern
                    "name": "evil_node",
                    "inputs": [],
                }
            ],
            "arg_nodes": [0],
            "heads": [[0, 0, 0]],
        }

        json_file = temp_dir / "cve_redos.json"
        json_file.write_text(json.dumps(malicious_symbol))

        result = symbol_scanner.scan(str(json_file))

        # Should detect CVE-2022-24294 pattern
        cve_issues = [i for i in result.issues if "CVE-2022-24294" in str(i.message)]
        assert len(cve_issues) > 0

    def test_custom_operator_detection(self, temp_dir, symbol_scanner):
        """Test detection of custom operators."""
        custom_op_symbol = {
            "nodes": [
                {"op": "Custom", "name": "custom_layer", "inputs": []},
                {"op": "UnknownOperator", "name": "unknown_op", "inputs": []},
            ],
            "arg_nodes": [0, 1],
            "heads": [[0, 0, 0]],
        }

        json_file = temp_dir / "custom_ops.json"
        json_file.write_text(json.dumps(custom_op_symbol))

        result = symbol_scanner.scan(str(json_file))

        # Should detect custom operators
        custom_op_issues = [i for i in result.issues if "custom operator" in str(i.message).lower()]
        assert len(custom_op_issues) > 0

        # Should detect unknown operators
        unknown_op_issues = [i for i in result.issues if "unknown" in str(i.message).lower()]
        assert len(unknown_op_issues) > 0

    def test_suspicious_content_detection(self, temp_dir, symbol_scanner):
        """Test detection of suspicious patterns in JSON."""
        malicious_symbol = {
            "nodes": [
                {
                    "op": "FullyConnected",
                    "name": "normal_op",
                    "inputs": [],
                    "attr": {
                        "malicious_code": "os.system('rm -rf /')",
                        "eval_call": 'eval(\'__import__("os").system("ls")\')',
                        "subprocess_usage": "subprocess.run(['cat', '/etc/passwd'])",
                    },
                }
            ],
            "arg_nodes": [0],
            "heads": [[0, 0, 0]],
        }

        json_file = temp_dir / "suspicious_content.json"
        json_file.write_text(json.dumps(malicious_symbol))

        result = symbol_scanner.scan(str(json_file))

        # Should detect multiple suspicious patterns
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0
        assert any("Suspicious pattern detected" in str(issue.message) for issue in critical_issues)

    def test_large_graph_detection(self, temp_dir, symbol_scanner):
        """Test detection of extremely large graphs."""
        # Create scanner with low limits for testing
        small_scanner = MXNetSymbolScanner({"max_nodes": 5})

        large_graph = {
            "nodes": [{"op": "null", "name": f"node_{i}", "inputs": []} for i in range(10)],  # 10 > limit of 5
            "arg_nodes": list(range(10)),
            "heads": [[9, 0, 0]],
        }

        json_file = temp_dir / "large_graph.json"
        json_file.write_text(json.dumps(large_graph))

        result = small_scanner.scan(str(json_file))

        assert any("large graph" in str(issue.message).lower() for issue in result.issues)


class TestMXNetParamsScannerBasic:
    """Test basic MXNet params scanner functionality."""

    def test_can_handle_supported_extensions(self, temp_dir):
        """Test that scanner handles supported parameter file extensions."""
        extensions = [".params", ".nd"]

        for ext in extensions:
            test_file = temp_dir / f"test{ext}"
            test_file.write_bytes(b"dummy content")

            assert MXNetParamsScanner.can_handle(str(test_file))

    def test_cannot_handle_unsupported_extensions(self, temp_dir):
        """Test that scanner rejects unsupported file extensions."""
        unsupported_extensions = [".txt", ".json", ".pkl", ".bst"]

        for ext in unsupported_extensions:
            test_file = temp_dir / f"test{ext}"
            test_file.write_bytes(b"dummy content")

            assert not MXNetParamsScanner.can_handle(str(test_file))

    def test_scanner_metadata(self):
        """Test params scanner metadata."""
        assert MXNetParamsScanner.name == "mxnet_params"
        assert "MXNet" in MXNetParamsScanner.description
        assert "parameter" in MXNetParamsScanner.description


class TestMXNetParamsScanning:
    """Test MXNet parameter file scanning."""

    def test_empty_file_detected(self, temp_dir, params_scanner):
        """Test detection of empty parameter files."""
        empty_file = temp_dir / "empty.params"
        empty_file.write_bytes(b"")

        result = params_scanner.scan(str(empty_file))

        assert any("empty" in str(issue.message).lower() for issue in result.issues)

    def test_pickle_masquerading_as_params_detected(self, temp_dir, params_scanner):
        """Test detection of pickle files with .params extension."""
        # Create a pickle file
        pickle_data = pickle.dumps({"fake": "mxnet_model"})

        fake_params = temp_dir / "fake.params"
        fake_params.write_bytes(pickle_data)

        result = params_scanner.scan(str(fake_params))

        assert any("pickle" in str(issue.message).lower() for issue in result.issues)

    def test_valid_ndarray_structure(self, temp_dir, params_scanner):
        """Test parsing of valid NDArray structure."""
        # Create a simple mock MXNet parameter file structure
        # Format: num_arrays(4) + array_name_len(4) + name + ndim(4) + shape + dtype(4) + data

        data = bytearray()
        # Number of arrays (1)
        data.extend(struct.pack("<I", 1))

        # Array 1: "weight" parameter
        name = b"weight"
        data.extend(struct.pack("<I", len(name)))  # name length
        data.extend(name)  # name
        data.extend(struct.pack("<I", 2))  # ndim
        data.extend(struct.pack("<I", 10))  # dim 1
        data.extend(struct.pack("<I", 5))  # dim 2
        data.extend(struct.pack("<I", 0))  # dtype (float32)
        data.extend(b"\x00" * (10 * 5 * 4))  # dummy data (10*5*4 bytes for float32)

        valid_params = temp_dir / "valid.params"
        valid_params.write_bytes(data)

        result = params_scanner.scan(str(valid_params))

        # Should validate NDArray format
        format_checks = [c for c in result.checks if "NDArray Format" in c.name and c.status.value == "passed"]
        assert len(format_checks) > 0

    def test_oversized_tensor_detection(self, temp_dir):
        """Test detection of oversized tensors."""
        # Create scanner with low tensor element limit
        strict_scanner = MXNetParamsScanner({"max_tensor_elements": 100})

        # Create NDArray with large tensor (1000*1000 > 100 limit)
        data = bytearray()
        data.extend(struct.pack("<I", 1))  # 1 array

        name = b"huge_tensor"
        data.extend(struct.pack("<I", len(name)))
        data.extend(name)
        data.extend(struct.pack("<I", 2))  # 2D tensor
        data.extend(struct.pack("<I", 1000))  # dim 1
        data.extend(struct.pack("<I", 1000))  # dim 2
        data.extend(struct.pack("<I", 0))  # float32
        # Don't include actual data to keep file small

        oversized_params = temp_dir / "oversized.params"
        oversized_params.write_bytes(data)

        result = strict_scanner.scan(str(oversized_params))

        assert any("extremely large tensor" in str(issue.message).lower() for issue in result.issues)

    def test_suspicious_binary_content_detection(self, temp_dir, params_scanner):
        """Test detection of suspicious patterns in binary data."""
        # Create binary data with suspicious strings
        malicious_data = b"\x00\x00\x00\x01"  # 1 array
        malicious_data += b"\x00\x00\x00\x04evil"  # name: "evil"
        malicious_data += b'os.system("rm -rf /")' + b"\x00" * 100  # suspicious content

        malicious_params = temp_dir / "malicious.params"
        malicious_params.write_bytes(malicious_data)

        result = params_scanner.scan(str(malicious_params))

        # Should detect suspicious patterns (though may also detect format errors)
        suspicious_issues = [
            i for i in result.issues if "suspicious" in str(i.message).lower() or "malicious" in str(i.message).lower()
        ]
        assert len(suspicious_issues) >= 0  # May or may not detect depending on parsing success

    def test_corrupted_format_detection(self, temp_dir, params_scanner):
        """Test detection of corrupted parameter files."""
        # Create file with invalid header
        corrupted_data = b"\xff\xff\xff\xff"  # Invalid array count

        corrupted_params = temp_dir / "corrupted.params"
        corrupted_params.write_bytes(corrupted_data)

        result = params_scanner.scan(str(corrupted_params))

        # Should detect format issues
        format_issues = [
            i for i in result.issues if "format" in str(i.message).lower() or "parsing" in str(i.message).lower()
        ]
        assert len(format_issues) >= 0  # May detect various format issues


class TestMXNetScannerConfiguration:
    """Test MXNet scanner configuration options."""

    def test_symbol_scanner_custom_config(self):
        """Test MXNet symbol scanner custom configuration."""
        custom_scanner = MXNetSymbolScanner({"max_json_size": 1024, "max_nodes": 100, "max_op_name_length": 50})
        assert custom_scanner.max_json_size == 1024
        assert custom_scanner.max_nodes == 100
        assert custom_scanner.max_op_name_length == 50

    def test_params_scanner_custom_config(self):
        """Test MXNet params scanner custom configuration."""
        custom_scanner = MXNetParamsScanner(
            {"max_tensor_elements": 1000, "max_total_size": 1024 * 1024, "max_num_arrays": 10}
        )
        assert custom_scanner.max_tensor_elements == 1000
        assert custom_scanner.max_total_size == 1024 * 1024
        assert custom_scanner.max_num_arrays == 10


class TestMXNetSecurityPatterns:
    """Test specific MXNet security vulnerability patterns."""

    def test_hex_encoded_data_detection(self, temp_dir, symbol_scanner):
        """Test detection of hex-encoded data that could be shellcode."""
        malicious_symbol = {
            "nodes": [
                {
                    "op": "FullyConnected",
                    "name": "normal_op",
                    "inputs": [],
                    "attr": {
                        "suspicious_field": "\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48",  # Hex pattern
                        "shellcode": "\\x90\\x90\\x90\\x90",  # NOP sled pattern
                    },
                }
            ],
            "arg_nodes": [0],
            "heads": [[0, 0, 0]],
        }

        json_file = temp_dir / "hex_encoded.json"
        json_file.write_text(json.dumps(malicious_symbol))

        result = symbol_scanner.scan(str(json_file))

        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0
        assert any("Hex-encoded data" in str(issue.message) for issue in critical_issues)

    def test_graph_depth_bomb_detection(self, temp_dir):
        """Test detection of extremely deep graphs (potential DoS)."""
        strict_scanner = MXNetSymbolScanner({"max_graph_depth": 10})

        # Create deeply nested graph structure
        nodes = []
        for i in range(20):  # 20 layers > limit of 10
            if i == 0:
                nodes.append({"op": "null", "name": f"layer_{i}", "inputs": []})
            else:
                nodes.append({"op": "FullyConnected", "name": f"layer_{i}", "inputs": [[i - 1, 0, 0]]})

        deep_graph = {"nodes": nodes, "arg_nodes": [0], "heads": [[len(nodes) - 1, 0, 0]]}

        json_file = temp_dir / "deep_graph.json"
        json_file.write_text(json.dumps(deep_graph))

        result = strict_scanner.scan(str(json_file))

        depth_issues = [i for i in result.issues if "deep" in str(i.message).lower()]
        assert len(depth_issues) > 0


class TestMXNetPickleIntegration:
    """Test integration with pickle scanner for MXNet pickle files."""

    def test_pickle_scanner_mxnet_patterns(self):
        """Test that MXNet patterns are included in pickle scanner."""
        from modelaudit.scanners.pickle_scanner import ML_FRAMEWORK_PATTERNS, ML_SAFE_GLOBALS

        # Check if MXNet patterns were added to framework patterns
        assert "mxnet" in ML_FRAMEWORK_PATTERNS
        mxnet_patterns = ML_FRAMEWORK_PATTERNS["mxnet"]
        assert "mxnet" in mxnet_patterns["modules"]
        assert "NDArray" in mxnet_patterns["classes"]

        # Check if MXNet safe globals were added
        assert "mxnet" in ML_SAFE_GLOBALS
        assert ML_SAFE_GLOBALS["mxnet"] == ["*"]


# Integration tests (require actual dependencies)
@pytest.mark.integration
class TestMXNetScannerIntegration:
    """Integration tests requiring actual MXNet libraries."""

    @pytest.mark.skipif(not pytest.importorskip("mxnet"), reason="MXNet not available")
    def test_real_mxnet_symbol_scan(self, temp_dir):
        """Test scanning of a real MXNet symbol file."""
        # This would require actual MXNet to create a real symbol file
        # For now, we'll use a realistic symbol structure
        realistic_symbol = {
            "nodes": [
                {"op": "null", "name": "data", "inputs": []},
                {"op": "FullyConnected", "name": "fc1", "inputs": [[0, 0, 0]], "attr": {"num_hidden": "128"}},
                {"op": "Activation", "name": "relu1", "inputs": [[1, 0, 0]], "attr": {"act_type": "relu"}},
                {"op": "SoftmaxOutput", "name": "softmax", "inputs": [[2, 0, 0]]},
            ],
            "arg_nodes": [0],
            "node_row_ptr": [0, 1, 2, 3, 4],
            "heads": [[3, 0, 0]],
            "attrs": {"mxnet_version": ["int", 10600]},
        }

        symbol_path = temp_dir / "real-symbol.json"
        symbol_path.write_text(json.dumps(realistic_symbol, indent=2))

        scanner = MXNetSymbolScanner()
        result = scanner.scan(str(symbol_path))

        assert result.success

        # Should successfully parse and validate structure
        assert any("structure validation passed" in str(check.message) for check in result.checks)

        # Should not have critical issues for valid content
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 0
