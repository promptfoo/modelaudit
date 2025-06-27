"""Tests for JAX checkpoint scanner."""

import json
import pickle

import numpy as np

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.jax_checkpoint_scanner import JaxCheckpointScanner


class TestJaxCheckpointScanner:
    """Test JAX checkpoint scanner functionality."""

    def test_can_handle_orbax_directory(self, tmp_path):
        """Test detection of Orbax checkpoint directories."""
        # Create Orbax checkpoint directory structure
        checkpoint_dir = tmp_path / "orbax_checkpoint"
        checkpoint_dir.mkdir()

        # Create metadata file
        metadata = {"version": "0.1.0", "type": "orbax_checkpoint", "format": "flax"}
        (checkpoint_dir / "orbax_checkpoint_metadata.json").write_text(json.dumps(metadata))

        assert JaxCheckpointScanner.can_handle(str(checkpoint_dir))

    def test_can_handle_jax_checkpoint_files(self, tmp_path):
        """Test detection of JAX checkpoint files."""
        # Create JAX checkpoint file with JAX indicators
        checkpoint_file = tmp_path / "model.ckpt"
        jax_data = {
            "params": {"layer1": {"weight": [1, 2, 3]}, "layer2": {"bias": [0.1]}},
            "jax_version": "0.4.0",
            "flax_module": "test_module",
        }

        with open(checkpoint_file, "wb") as f:
            pickle.dump(jax_data, f)

        assert JaxCheckpointScanner.can_handle(str(checkpoint_file))

    def test_can_handle_non_jax_files(self, tmp_path):
        """Test that non-JAX files are not handled."""
        # Create regular pickle file without JAX indicators
        regular_file = tmp_path / "regular.ckpt"
        regular_data = {"simple": "data", "no_jax": True}

        with open(regular_file, "wb") as f:
            pickle.dump(regular_data, f)

        assert not JaxCheckpointScanner.can_handle(str(regular_file))

    def test_scan_orbax_checkpoint_directory(self, tmp_path):
        """Test scanning Orbax checkpoint directory."""
        checkpoint_dir = tmp_path / "orbax_test"
        checkpoint_dir.mkdir()

        # Create metadata
        metadata = {"version": "0.1.0", "type": "orbax_checkpoint", "restore_fn": "custom_restore_function"}
        (checkpoint_dir / "metadata.json").write_text(json.dumps(metadata))

        # Create checkpoint file
        checkpoint_data = {"params": {"weight": np.random.rand(10, 10).tolist()}}
        with open(checkpoint_dir / "checkpoint", "wb") as f:
            pickle.dump(checkpoint_data, f)

        scanner = JaxCheckpointScanner()
        result = scanner.scan(str(checkpoint_dir))

        assert result.success
        assert result.metadata["checkpoint_type"] == "directory"

        # Should detect custom restore function
        warnings = [issue for issue in result.issues if issue.severity == IssueSeverity.WARNING]
        assert any("Custom restore function" in issue.message for issue in warnings)

    def test_scan_suspicious_orbax_metadata(self, tmp_path):
        """Test detection of suspicious patterns in Orbax metadata."""
        checkpoint_dir = tmp_path / "suspicious_orbax"
        checkpoint_dir.mkdir()

        # Create metadata with suspicious patterns
        metadata = {
            "version": "0.1.0",
            "custom_code": "jax.experimental.host_callback.call(malicious_fn)",
            "restore_config": "subprocess.run(['rm', '-rf', '/'])",
        }
        (checkpoint_dir / "metadata.json").write_text(json.dumps(metadata))

        scanner = JaxCheckpointScanner()
        result = scanner.scan(str(checkpoint_dir))

        # Should detect suspicious patterns
        critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0
        assert any("host_callback" in issue.message.lower() for issue in critical_issues)

    def test_scan_pickle_checkpoint_with_dangerous_opcodes(self, tmp_path):
        """Test detection of dangerous pickle opcodes in checkpoint."""
        checkpoint_file = tmp_path / "dangerous.ckpt"

        # Create pickle with dangerous opcodes (simplified simulation)
        # In real scenario, this would be a more complex malicious pickle
        with open(checkpoint_file, "wb") as f:
            f.write(b"\x80\x03")  # Pickle protocol
            f.write(b"c")  # GLOBAL opcode
            f.write(b"os\nsystem\n")  # os.system reference
            f.write(b"R")  # REDUCE opcode
            f.write(b"jax.numpy.array")  # JAX content to pass can_handle

        scanner = JaxCheckpointScanner()
        result = scanner.scan(str(checkpoint_file))

        # Should detect dangerous opcodes
        critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0

    def test_scan_numpy_checkpoint(self, tmp_path):
        """Test scanning NumPy-based checkpoints."""
        checkpoint_file = tmp_path / "jax_weights.npy"

        # Create NumPy array
        weights = np.random.rand(100, 50).astype(np.float32)
        np.save(checkpoint_file, weights)

        scanner = JaxCheckpointScanner()
        result = scanner.scan(str(checkpoint_file))

        assert result.success
        assert result.bytes_scanned > 0

    def test_scan_large_numpy_checkpoint(self, tmp_path):
        """Test detection of extremely large NumPy arrays."""
        checkpoint_file = tmp_path / "huge_array.npy"

        # Create very large array (but save as small file to avoid actual memory usage)
        # We'll mock the array loading to simulate a huge array
        small_array = np.zeros((10, 10), dtype=np.float32)
        np.save(checkpoint_file, small_array)

        # Patch the array to appear larger
        original_load = np.load

        def mock_load(*args, **kwargs):
            array = original_load(*args, **kwargs)
            # Simulate huge size
            array.size = 200_000_000  # 200M elements
            array.shape = (200_000_000,)
            return array

        import numpy

        numpy.load = mock_load

        try:
            scanner = JaxCheckpointScanner()
            result = scanner.scan(str(checkpoint_file))

            # Should detect large array
            warnings = [issue for issue in result.issues if issue.severity == IssueSeverity.WARNING]
            assert any("Extremely large NumPy array" in issue.message for issue in warnings)
        finally:
            numpy.load = original_load

    def test_scan_json_checkpoint_metadata(self, tmp_path):
        """Test scanning JSON checkpoint metadata."""
        json_file = tmp_path / "config.json"

        config = {"model_type": "transformer", "jax_version": "0.4.0", "custom_transform": "jax.jit(eval_function)"}
        json_file.write_text(json.dumps(config))

        scanner = JaxCheckpointScanner()
        result = scanner.scan(str(json_file))

        # Should detect suspicious JAX pattern
        critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
        assert any("eval_function" in issue.message.lower() for issue in critical_issues)

    def test_scan_invalid_json_checkpoint(self, tmp_path):
        """Test handling of invalid JSON in checkpoint."""
        json_file = tmp_path / "invalid.json"
        json_file.write_text('{"invalid": json content}')

        scanner = JaxCheckpointScanner()
        result = scanner.scan(str(json_file))

        warnings = [issue for issue in result.issues if issue.severity == IssueSeverity.WARNING]
        assert any("Invalid JSON" in issue.message for issue in warnings)

    def test_scan_file_too_large(self, tmp_path):
        """Test handling of files that exceed size limit."""
        large_file = tmp_path / "large.ckpt"

        # Create file that simulates being too large
        large_file.write_bytes(b"dummy content")

        # Configure scanner with small size limit
        config = {"max_file_size": 5}  # 5 bytes limit
        scanner = JaxCheckpointScanner(config)
        result = scanner.scan(str(large_file))

        warnings = [issue for issue in result.issues if issue.severity == IssueSeverity.WARNING]
        assert any("too large" in issue.message for issue in warnings)

    def test_scan_unknown_format_checkpoint(self, tmp_path):
        """Test handling of unknown checkpoint formats."""
        unknown_file = tmp_path / "unknown.ckpt"

        # Create file with unknown format
        unknown_file.write_bytes(b"UNKNOWN_FORMAT_DATA")

        scanner = JaxCheckpointScanner()
        result = scanner.scan(str(unknown_file))

        info_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.INFO]
        assert any("Unknown checkpoint file format" in issue.message for issue in info_issues)

    def test_directory_based_checkpoint_size_calculation(self, tmp_path):
        """Test total size calculation for directory-based checkpoints."""
        checkpoint_dir = tmp_path / "size_test"
        checkpoint_dir.mkdir()

        # Create multiple files
        (checkpoint_dir / "metadata.json").write_text('{"type": "test"}')
        (checkpoint_dir / "file1.bin").write_bytes(b"x" * 100)
        (checkpoint_dir / "file2.bin").write_bytes(b"y" * 200)

        # Create subdirectory with file
        subdir = checkpoint_dir / "subdir"
        subdir.mkdir()
        (subdir / "file3.bin").write_bytes(b"z" * 50)

        scanner = JaxCheckpointScanner()
        result = scanner.scan(str(checkpoint_dir))

        assert result.success
        # Total should be sum of all files
        expected_size = len('{"type": "test"}') + 100 + 200 + 50
        assert result.bytes_scanned == expected_size
        assert result.metadata["total_size"] == expected_size

    def test_scan_nonexistent_path(self):
        """Test handling of nonexistent paths."""
        scanner = JaxCheckpointScanner()
        result = scanner.scan("/nonexistent/path")

        assert not result.success
        # Should have path validation error

    def test_jax_specific_patterns_detection(self, tmp_path):
        """Test detection of JAX-specific suspicious patterns."""
        patterns_to_test = [
            "jax.experimental.host_callback.call",
            "jax.debug.callback",
            "orbax.checkpoint.restore.eval",
            "jax.jit.subprocess",
        ]

        for i, pattern in enumerate(patterns_to_test):
            checkpoint_file = tmp_path / f"pattern_test_{i}.ckpt"

            # Create JAX checkpoint with suspicious pattern
            data = {"jax_model": True, "suspicious_code": pattern, "params": {"layer": [1, 2, 3]}}

            with open(checkpoint_file, "wb") as f:
                pickle.dump(data, f)

            scanner = JaxCheckpointScanner()
            result = scanner.scan(str(checkpoint_file))

            # Should detect the suspicious pattern
            critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) > 0, f"Failed to detect pattern: {pattern}"
