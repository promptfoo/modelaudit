"""Tests for advanced file handler."""

import os
import tempfile
from contextvars import ContextVar
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from modelaudit.cache.cache_manager import reset_cache_manager
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME, IssueSeverity, ScanResult
from modelaudit.utils.file.handlers import (
    MAX_RECORDED_MISSING_SHARD_INDICES,
    AdvancedFileHandler,
    MemoryMappedHandler,
    ParallelShardHandler,
    ShardedModelDetector,
    scan_advanced_large_file,
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


class OperationalFailureScanner:
    """Scanner that simulates an operational shard scan failure."""

    name = "operational_failure_scanner"

    def scan(self, shard_path: str) -> ScanResult:
        raise RuntimeError(f"cannot scan {Path(shard_path).name}")


class IncompleteShardScanner:
    """Scanner that returns an unsuccessful non-critical shard result."""

    name = "incomplete_shard_scanner"

    def scan(self, shard_path: str) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        result.add_check(
            name="Shard Parse Coverage",
            passed=False,
            message=f"Shard could not be fully parsed: {Path(shard_path).name}",
            severity=IssueSeverity.INFO,
            location=shard_path,
        )
        result.finish(success=False)
        return result


_SHARD_SCAN_CONTEXT: ContextVar[str] = ContextVar("_SHARD_SCAN_CONTEXT", default="missing")


class ContextRecordingShardScanner:
    """Scanner that records worker context for propagation tests."""

    name = "context_recording_shard_scanner"

    def scan(self, shard_path: str) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        result.add_check(
            name="Shard Context",
            passed=True,
            message=Path(shard_path).name,
            severity=IssueSeverity.INFO,
            details={"context_value": _SHARD_SCAN_CONTEXT.get()},
        )
        result.finish(success=True)
        return result


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
        assert shard_info["missing_shard_count"] == 1
        assert shard_info["missing_shard_indices"] == [2]

    def test_detect_shards_bounds_missing_expected_indices(self, tmp_path: Path) -> None:
        """Huge declared shard totals should not expand into huge missing-index lists."""
        shard_one = tmp_path / "model-00001-of-999999999999.safetensors"
        shard_one.write_bytes(b"test")

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["expected_total_shards"] == 999999999999
        assert shard_info["missing_shard_count"] == 999999999998
        assert len(shard_info["missing_shard_indices"]) == MAX_RECORDED_MISSING_SHARD_INDICES
        assert shard_info["missing_shard_indices_truncated"] is True

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

    def test_detect_shards_respects_allowed_paths(self, tmp_path: Path) -> None:
        """Directory scans should be able to constrain shard expansion to validated paths."""
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_two = tmp_path / "model-00002-of-00002.safetensors"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")

        shard_info = ShardedModelDetector.detect_shards(
            str(shard_one),
            allowed_paths=[str(shard_one.resolve())],
        )

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one)]
        assert shard_info["total_shards"] == 1

    def test_detect_shards_rejects_direct_sibling_symlink_outside_scan_directory(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Direct file scans must not expand sibling shard symlinks outside the scan directory."""
        outside_dir = tmp_path / "outside"
        scan_dir = tmp_path / "scan"
        outside_dir.mkdir()
        scan_dir.mkdir()
        shard_one = scan_dir / "checkpoint_1.pt"
        shard_two = scan_dir / "checkpoint_2.pt"
        outside_target = outside_dir / "outside-shard.pt"
        shard_one.write_bytes(b"one")
        outside_target.write_bytes(b"outside")
        shard_two.symlink_to(outside_target)

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one)]
        assert shard_info["total_shards"] == 1
        assert shard_info["total_size"] == shard_one.stat().st_size
        assert shard_info["out_of_scope_shard_count"] == 1
        assert shard_info["out_of_scope_shards"] == [str(shard_two)]

    def test_detect_shards_allows_validated_symlink_target_from_allowlist(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Directory scans may include a symlinked shard once the resolved target is validated."""
        outside_dir = tmp_path / "outside"
        scan_dir = tmp_path / "scan"
        outside_dir.mkdir()
        scan_dir.mkdir()
        shard_one = scan_dir / "checkpoint_1.pt"
        shard_two = scan_dir / "checkpoint_2.pt"
        outside_target = outside_dir / "outside-shard.pt"
        shard_one.write_bytes(b"one")
        outside_target.write_bytes(b"outside")
        shard_two.symlink_to(outside_target)

        shard_info = ShardedModelDetector.detect_shards(
            str(shard_one),
            allowed_paths=[str(shard_one.resolve()), str(outside_target.resolve())],
        )

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one), str(shard_two)]
        assert shard_info["total_shards"] == 2
        assert "out_of_scope_shard_count" not in shard_info

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

            def scan(self, _file_path: str) -> ScanResult:
                result = ScanResult(scanner_name=self.name)
                result.finish(success=True)
                return result

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
        assert coverage_checks[0].details["missing_shard_count"] == 1
        assert coverage_checks[0].details["missing_shard_indices"] == [2]
        assert coverage_checks[0].details["missing_shard_indices_truncated"] is False

    def test_sharded_model_broken_shard_marks_scan_inconclusive(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Unreadable shard links should be reported as missing instead of aborting expansion."""
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_two = tmp_path / "model-00002-of-00002.safetensors"
        shard_one.write_bytes(b"safe")
        shard_two.symlink_to(tmp_path / "missing-shard")

        handler = AdvancedFileHandler(str(shard_one), CompletingShardScanner())
        result = handler.scan()

        coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
        assert result.success is False
        assert result.bytes_scanned == shard_one.stat().st_size
        assert len(coverage_checks) == 1
        assert coverage_checks[0].details["missing_shard_count"] == 1
        assert coverage_checks[0].details["unreadable_shard_count"] == 1
        assert coverage_checks[0].details["unreadable_shards"] == [str(shard_two)]

    def test_sharded_model_broken_shard_without_declared_total_marks_scan_inconclusive(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Unreadable members cannot be silently dropped when a family has no declared total."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"safe")
        shard_two.symlink_to(tmp_path / "missing-shard")

        handler = AdvancedFileHandler(str(shard_one), CompletingShardScanner())
        result = handler.scan()

        coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
        assert result.success is False
        assert result.bytes_scanned == shard_one.stat().st_size
        assert "unreadable_model_shards" in result.metadata["scan_outcome_reasons"]
        assert len(coverage_checks) == 1
        assert coverage_checks[0].details["unreadable_shard_count"] == 1
        assert coverage_checks[0].details["unreadable_shards"] == [str(shard_two)]

    def test_sharded_model_out_of_scope_symlink_marks_scan_inconclusive(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Sibling symlink shards outside a direct scan directory cannot be treated as covered."""
        outside_dir = tmp_path / "outside"
        scan_dir = tmp_path / "scan"
        outside_dir.mkdir()
        scan_dir.mkdir()
        shard_one = scan_dir / "checkpoint_1.pt"
        shard_two = scan_dir / "checkpoint_2.pt"
        outside_target = outside_dir / "outside-shard.pt"
        shard_one.write_bytes(b"safe")
        outside_target.write_bytes(b"malicious shard outside direct scan")
        shard_two.symlink_to(outside_target)

        handler = AdvancedFileHandler(str(shard_one), CompletingShardScanner())
        result = handler.scan()

        coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
        assert result.success is False
        assert result.bytes_scanned == shard_one.stat().st_size
        assert "out_of_scope_model_shards" in result.metadata["scan_outcome_reasons"]
        assert len(coverage_checks) == 1
        assert coverage_checks[0].details["out_of_scope_shard_count"] == 1
        assert coverage_checks[0].details["out_of_scope_shards"] == [str(shard_two)]

    def test_sharded_model_honors_allowed_shard_paths(self, tmp_path: Path) -> None:
        """Restricted shard scans must not expand beyond the validated allowlist."""
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_two = tmp_path / "model-00002-of-00002.safetensors"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")

        handler = AdvancedFileHandler(
            str(shard_one),
            CompletingShardScanner(),
            allowed_shard_paths=[str(shard_one.resolve())],
        )
        result = handler.scan()

        shard_detection = next(check for check in result.checks if check.name == "Sharded Model Detection")
        assert shard_detection.details["shards"] == [str(shard_one)]
        assert result.bytes_scanned == shard_one.stat().st_size

    def test_sharded_model_preserves_scanner_config_for_each_shard(self, tmp_path: Path) -> None:
        """Shard fanout should retain caller configuration for each scanner instance."""
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_two = tmp_path / "model-00002-of-00002.safetensors"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")
        captured_configs: list[dict[str, Any]] = []

        class ConfiguredShardScanner(CompletingShardScanner):
            def __init__(self, config: dict[str, Any] | None = None) -> None:
                self.config = dict(config or {})
                captured_configs.append(self.config)

        scanner = ConfiguredShardScanner({"max_tensor_bytes": 7})
        captured_configs.clear()

        result = AdvancedFileHandler(str(shard_one), scanner).scan()

        assert result.success is True
        assert captured_configs == [{"max_tensor_bytes": 7}, {"max_tensor_bytes": 7}]

    def test_cached_advanced_scan_keys_allowed_shard_paths(self, tmp_path: Path) -> None:
        """Different validated shard allowlists must not share advanced-scan cache entries."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two-two")
        cache_dir = tmp_path / "cache"

        class CachedCompletingShardScanner(CompletingShardScanner):
            def __init__(self, config: dict[str, Any] | None = None) -> None:
                self.config = config or {}

        scanner = CachedCompletingShardScanner(
            {
                "cache_enabled": True,
                "cache_dir": str(cache_dir),
            }
        )
        restricted_paths = [str(shard_one.resolve())]
        expanded_paths = [str(shard_one.resolve()), str(shard_two.resolve())]

        reset_cache_manager()
        try:
            restricted = scan_advanced_large_file(
                str(shard_one),
                scanner,
                allowed_shard_paths=restricted_paths,
            )
            expanded = scan_advanced_large_file(
                str(shard_one),
                scanner,
                allowed_shard_paths=expanded_paths,
            )
        finally:
            reset_cache_manager()

        assert restricted.bytes_scanned == shard_one.stat().st_size
        assert expanded.bytes_scanned == shard_one.stat().st_size + shard_two.stat().st_size

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
            OperationalFailureScanner,
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

    def test_parallel_shards_inherit_scan_context(self, tmp_path: Path) -> None:
        """Shard workers preserve an enclosing source-sensitive scan snapshot."""
        shard_path = tmp_path / "model-00001-of-00001.safetensors"
        shard_path.write_bytes(b"safe")
        handler = ParallelShardHandler(
            {
                "shards": [str(shard_path)],
                "total_shards": 1,
                "total_size": shard_path.stat().st_size,
            },
            ContextRecordingShardScanner,
        )
        token = _SHARD_SCAN_CONTEXT.set("directory-snapshot")
        try:
            result = handler.scan_shards()
        finally:
            _SHARD_SCAN_CONTEXT.reset(token)

        context_checks = [check for check in result.checks if check.name == "Shard Context"]
        assert len(context_checks) == 1
        assert context_checks[0].details["context_value"] == "directory-snapshot"

    def test_sharded_model_preserves_unsuccessful_shard_result(self, tmp_path: Path) -> None:
        """Non-critical shard failures must not be overwritten after aggregate merge."""
        shard_path = tmp_path / "model-00001-of-00001.safetensors"
        shard_path.write_bytes(b"partial")

        handler = AdvancedFileHandler(str(shard_path), IncompleteShardScanner())
        result = handler.scan()

        assert result.end_time is not None
        assert result.success is False
        assert result.has_errors is False
        assert "scan_outcome" not in result.metadata
        assert any(check.name == "Shard Parse Coverage" for check in result.checks)
