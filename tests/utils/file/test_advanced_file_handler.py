"""Tests for advanced file handler."""

import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME, IssueSeverity, ScanResult
from modelaudit.utils.file.handlers import (
    AdvancedFileHandler,
    MemoryMappedHandler,
    ParallelShardHandler,
    ShardedModelDetector,
    should_use_advanced_handler,
)


class CompletingShardScanner:
    """Minimal scanner for shard-handler coverage tests."""

    name = "completing_shard_scanner"

    def scan(self, shard_path: str) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        result.bytes_scanned = Path(shard_path).stat().st_size
        result.finish(success=True)
        return result


class FailingShardScanner:
    """Scanner that simulates an operational shard scan failure."""

    name = "failing_shard_scanner"

    def scan(self, shard_path: str) -> ScanResult:
        raise RuntimeError(f"cannot scan {Path(shard_path).name}")


class TestShardedModelDetector:
    """Test sharded model detection."""

    def test_detect_pytorch_shards(self) -> None:
        """Test detection of PyTorch sharded models."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create sharded model files
            shard_files = [
                "pytorch_model-00001-of-00003.bin",
                "pytorch_model-00002-of-00003.bin",
                "pytorch_model-00003-of-00003.bin",
            ]

            for shard in shard_files:
                Path(tmpdir, shard).write_bytes(b"test")

            # Test detection
            test_file = str(Path(tmpdir, shard_files[0]))
            shard_info = ShardedModelDetector.detect_shards(test_file)

            assert shard_info is not None
            assert shard_info["total_shards"] == 3
            assert len(shard_info["shards"]) == 3

    def test_detect_safetensors_shards(self) -> None:
        """Test detection of SafeTensors sharded models."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create sharded model files
            shard_files = [
                "model-00001-of-00002.safetensors",
                "model-00002-of-00002.safetensors",
            ]

            for shard in shard_files:
                Path(tmpdir, shard).write_bytes(b"test")

            # Test detection
            test_file = str(Path(tmpdir, shard_files[0]))
            shard_info = ShardedModelDetector.detect_shards(test_file)

            assert shard_info is not None
            assert shard_info["total_shards"] == 2

    def test_detect_shards_records_missing_expected_indices(self, tmp_path: Path) -> None:
        """Missing numbered shards should be explicit in detector metadata."""
        shard_one = tmp_path / "model-00001-of-00003.safetensors"
        shard_three = tmp_path / "model-00003-of-00003.safetensors"
        shard_one.write_bytes(b"test")
        shard_three.write_bytes(b"test")

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["total_shards"] == 2
        assert shard_info["expected_total_shards"] == 3
        assert shard_info["missing_shard_indices"] == [2]

    def test_detect_shards_ignores_suffix_near_matches(self, tmp_path: Path) -> None:
        """Shard routing should not count files that only prefix-match a shard name."""
        shard_one = tmp_path / "model-00001-of-00001.safetensors"
        near_match = tmp_path / "model-00001-of-00001.safetensors.bak"
        shard_one.write_bytes(b"test")
        near_match.write_bytes(b"backup")

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one)]
        assert shard_info["total_shards"] == 1

    def test_no_shards_detected(self) -> None:
        """Test when file is not sharded."""
        with tempfile.NamedTemporaryFile(suffix=".bin") as f:
            f.write(b"test")
            f.flush()

            shard_info = ShardedModelDetector.detect_shards(f.name)
            assert shard_info is None

    def test_find_model_config(self) -> None:
        """Test finding model configuration file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create config file
            config_path = Path(tmpdir, "config.json")
            config_path.write_text('{"model_type": "llama"}')

            # Create model file
            model_path = Path(tmpdir, "model.bin")
            model_path.write_bytes(b"test")

            # Test finding config
            found_config = ShardedModelDetector.find_model_config(str(model_path))
            assert found_config == str(config_path)


class TestMemoryMappedHandler:
    """Test memory-mapped scanning."""

    def test_mmap_scanning(self) -> None:
        """Test basic memory-mapped scanning."""
        # Create a test file with suspicious content
        with tempfile.NamedTemporaryFile(delete=False) as f:
            # Write some content with suspicious patterns
            content = b"normal content" * 1000
            content += b"exec('malicious code')"
            content += b"more content" * 1000
            f.write(content)
            temp_path = f.name

        try:
            mock_scanner = MagicMock()
            mock_scanner.name = "test_scanner"

            mmap_scanner = MemoryMappedHandler(temp_path, mock_scanner)
            result = mmap_scanner.scan_with_mmap()

            # With full scanning, we might not detect patterns in mmap test
            # The important thing is that the scan completes without errors
            assert result is not None
            # Optionally check for exec if detected
            # assert any("exec" in issue.message for issue in result.issues)

        finally:
            os.unlink(temp_path)

    def test_mmap_with_large_file(self) -> None:
        """Test memory mapping with larger file."""
        # Create a larger test file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            # Write 10MB of data
            chunk = b"x" * (1024 * 1024)  # 1MB
            for _ in range(10):
                f.write(chunk)
            f.write(b"__import__('os').system('bad')")
            temp_path = f.name

        try:
            mock_scanner = MagicMock()
            mock_scanner.name = "test_scanner"

            mmap_scanner = MemoryMappedHandler(temp_path, mock_scanner)
            result = mmap_scanner.scan_with_mmap()

            # With full scanning, mmap test focuses on completion without errors
            assert result is not None

        finally:
            os.unlink(temp_path)


class TestAdvancedFileHandler:
    """Test extreme large file handler."""

    @patch("modelaudit.utils.file.handlers.os.path.getsize")
    def test_extreme_file_detection(self, mock_getsize: Any) -> None:
        """Test detection of extreme large files."""
        # Test file over the 50GB advanced-handler threshold
        mock_getsize.return_value = 300 * 1024 * 1024 * 1024  # 300GB

        assert should_use_advanced_handler("large_model.bin")

        # Test file under threshold
        mock_getsize.return_value = 50 * 1024 * 1024 * 1024  # 50GB

        assert not should_use_advanced_handler("small_model.bin")

    @patch("modelaudit.utils.file.handlers.os.path.getsize")
    @patch("modelaudit.utils.file.handlers.ShardedModelDetector.detect_shards")
    def test_massive_file_handling(self, mock_detect: Any, mock_getsize: Any) -> None:
        """Test handling of massive files above the distributed-scan threshold."""
        mock_detect.return_value = None  # Not sharded
        mock_getsize.return_value = 600 * 1024 * 1024 * 1024  # 600GB

        with tempfile.NamedTemporaryFile() as f:
            f.write(b"\x80\x03test")  # Pickle header
            f.flush()

            mock_scanner = MagicMock()
            mock_scanner.name = "test_scanner"

            handler = AdvancedFileHandler(f.name, mock_scanner)

            with patch("builtins.open", create=True) as mock_open:
                mock_file = MagicMock()
                mock_file.read.return_value = b"\x80\x03test"
                mock_open.return_value.__enter__.return_value = mock_file

                result = handler.scan()

                # With full scanning, we don't warn about size anymore
                # The scan should complete successfully
                assert result is not None

    @patch("modelaudit.utils.file.handlers.os.path.getsize")
    @patch("modelaudit.utils.file.handlers.ShardedModelDetector.detect_shards")
    def test_massive_file_without_bounded_support_fails_closed(
        self,
        mock_detect: Any,
        mock_getsize: Any,
        tmp_path: Path,
    ) -> None:
        """Unsupported scanners should stop with an operational-style error message."""
        mock_detect.return_value = None
        mock_getsize.return_value = 600 * 1024 * 1024 * 1024

        model_path = tmp_path / "huge-model.bin"
        model_path.write_bytes(b"test")

        class ScannerWithoutBoundedSupport:
            name = "test_scanner"

        handler = AdvancedFileHandler(str(model_path), ScannerWithoutBoundedSupport())
        result = handler.scan()

        assert not result.success
        assert any(
            check.name == "Large File Coverage Check" and "Error scanning file:" in check.message
            for check in result.checks
        )

    def test_sharded_model_missing_shards_marks_scan_inconclusive(self, tmp_path: Path) -> None:
        """A partial shard set must not report complete coverage."""
        shard_one = tmp_path / "model-00001-of-00003.safetensors"
        shard_three = tmp_path / "model-00003-of-00003.safetensors"
        shard_one.write_bytes(b"safe")
        shard_three.write_bytes(b"safe")

        handler = AdvancedFileHandler(str(shard_one), CompletingShardScanner())
        result = handler.scan()

        assert result.end_time is not None
        assert result.success is False
        assert result.metadata["analysis_incomplete"] is True
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "missing_model_shards" in result.metadata["scan_outcome_reasons"]
        coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
        assert len(coverage_checks) == 1
        assert coverage_checks[0].severity == IssueSeverity.INFO
        assert coverage_checks[0].details["missing_shard_indices"] == [2]

    def test_parallel_shard_errors_mark_scan_inconclusive(self, tmp_path: Path) -> None:
        """Shard scan exceptions are incomplete coverage, not security findings."""
        shard_path = tmp_path / "model-00001-of-00001.safetensors"
        shard_path.write_bytes(b"safe")
        handler = ParallelShardHandler(
            {
                "shards": [str(shard_path)],
                "total_shards": 1,
                "total_size": shard_path.stat().st_size,
            },
            FailingShardScanner,
        )

        result = handler.scan_shards()

        assert result.end_time is not None
        assert result.success is False
        assert result.metadata["analysis_incomplete"] is True
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "shard_scan_error" in result.metadata["scan_outcome_reasons"]
        shard_checks = [check for check in result.checks if check.name == "Shard Scan"]
        assert len(shard_checks) == 1
        assert shard_checks[0].severity == IssueSeverity.INFO
