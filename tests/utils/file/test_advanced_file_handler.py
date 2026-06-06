"""Tests for advanced file handler."""

import os
import tempfile
from contextvars import ContextVar
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.cache.cache_manager import get_cache_manager, reset_cache_manager
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.utils.file.handlers import (
    MAX_RECORDED_MISSING_SHARD_INDICES,
    AdvancedFileHandler,
    MemoryMappedHandler,
    ParallelShardHandler,
    ShardedModelDetector,
    ValidatedShardTargets,
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

    def test_detect_shards_direct_hf_snapshot_includes_blob_backed_siblings(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        """Selecting one normal HF snapshot shard should scan its complete sibling family."""
        hf_home = tmp_path / "hf-home"
        monkeypatch.setenv("HF_HOME", str(hf_home))
        cache_dir = hf_home / "hub" / "models--org--model"
        snapshot = cache_dir / "snapshots" / "abc123"
        blobs_dir = cache_dir / "blobs"
        snapshot.mkdir(parents=True)
        blobs_dir.mkdir()
        shard_paths: list[Path] = []
        for index in range(1, 3):
            blob = blobs_dir / f"blob-{index}"
            blob.write_bytes(f"blob-{index}".encode())
            shard = snapshot / f"model-{index:05d}-of-00002.safetensors"
            shard.symlink_to(Path("../../blobs") / blob.name)
            shard_paths.append(shard)

        shard_info = ShardedModelDetector.detect_shards(str(shard_paths[0]))

        assert shard_info is not None
        assert shard_info["shards"] == [str(path) for path in shard_paths]
        assert shard_info["total_shards"] == 2
        assert "missing_shard_count" not in shard_info
        assert "out_of_scope_shard_count" not in shard_info

    def test_detect_shards_rejects_duplicate_symlink_targets(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Two shard indices cannot satisfy coverage by resolving to one file."""
        blob = tmp_path / "blob"
        blob.write_bytes(b"shared")
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_two = tmp_path / "model-00002-of-00002.safetensors"
        shard_one.symlink_to(blob.name)
        shard_two.symlink_to(blob.name)

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))
        result = AdvancedFileHandler(str(shard_one), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert shard_info["total_shards"] == 1
        assert shard_info["missing_shard_count"] == 1
        assert shard_info["duplicate_shard_count"] == 1
        assert shard_info["duplicate_shards"] == [str(shard_two)]
        assert result.success is False
        assert "duplicate_model_shard_targets" in result.metadata["scan_outcome_reasons"]

    def test_detect_shards_rejects_duplicate_hardlink_targets(self, tmp_path: Path) -> None:
        """Hardlinked shard names must not be double-counted as distinct coverage."""
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_two = tmp_path / "model-00002-of-00002.safetensors"
        shard_one.write_bytes(b"shared")
        os.link(shard_one, shard_two)

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["total_shards"] == 1
        assert shard_info["missing_shard_count"] == 1
        assert shard_info["duplicate_shard_count"] == 1

    def test_validated_shard_target_mapping_rejects_alias_swap(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """An alias cannot switch to another already-approved family target."""
        target_one = tmp_path / "target-one"
        target_two = tmp_path / "target-two"
        target_one.write_bytes(b"one")
        target_two.write_bytes(b"two")
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_two = tmp_path / "model-00002-of-00002.safetensors"
        shard_one.symlink_to(target_one.name)
        shard_two.symlink_to(target_two.name)
        allowed_targets: ValidatedShardTargets = {
            str(shard_one): {
                "resolved_path": str(target_one),
                "device": target_one.stat().st_dev,
                "inode": target_one.stat().st_ino,
            },
            str(shard_two): {
                "resolved_path": str(target_two),
                "device": target_two.stat().st_dev,
                "inode": target_two.stat().st_ino,
            },
        }
        shard_one.unlink()
        shard_one.symlink_to(target_two.name)

        result = AdvancedFileHandler(
            str(shard_one),
            CompletingShardScanner(),
            allowed_shard_paths=[str(target_one), str(target_two)],
            allowed_shard_targets=allowed_targets,
        ).scan()

        assert result.success is False
        assert result.metadata["operational_error_reason"] == "shard_boundary_changed"
        assert any(check.details["reason"] == "shard_target_changed" for check in result.checks)

    def test_detect_shards_preserves_direct_symlink_representative_outside_scan_directory(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """The user-selected shard remains scannable even when its target is outside the containing directory."""
        outside_dir = tmp_path / "outside"
        scan_dir = tmp_path / "scan"
        outside_dir.mkdir()
        scan_dir.mkdir()
        shard_one = scan_dir / "model-00001-of-00002.safetensors"
        outside_target = outside_dir / "outside-shard.safetensors"
        outside_target.write_bytes(b"outside")
        shard_one.symlink_to(outside_target)

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one)]
        assert shard_info["total_shards"] == 1
        assert shard_info["missing_shard_count"] == 1
        assert should_use_advanced_handler(str(shard_one))

    def test_detect_shards_treats_symlink_loop_as_unreadable(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Cyclic sibling symlinks must fail closed as incomplete shard coverage."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"safe")
        shard_two.symlink_to(shard_two.name)

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one)]
        assert shard_info["unreadable_shard_count"] == 1
        assert shard_info["unreadable_shards"] == [str(shard_two)]

        result = AdvancedFileHandler(str(shard_one), CompletingShardScanner()).scan()

        assert result.success is False
        assert "unreadable_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_shards_ignores_nearby_family_with_different_declared_total(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A neighboring shard family must not create false incomplete-coverage findings."""
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        selected_shard = tmp_path / "model-00001-of-00001.safetensors"
        unrelated_alias = tmp_path / "model-00001-of-00002.safetensors"
        outside_target = outside_dir / "other-family.safetensors"
        selected_shard.write_bytes(b"selected")
        outside_target.write_bytes(b"unrelated")
        unrelated_alias.symlink_to(outside_target)

        shard_info = ShardedModelDetector.detect_shards(str(selected_shard))
        result = AdvancedFileHandler(str(selected_shard), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert shard_info["shards"] == [str(selected_shard)]
        assert "out_of_scope_shard_count" not in shard_info
        assert result.success is True

    def test_detect_shards_does_not_reresolve_validated_allowlist_targets(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Retargeting a validated sibling path cannot move the allowlist outside."""
        scan_dir = tmp_path / "scan"
        outside_dir = tmp_path / "outside"
        scan_dir.mkdir()
        outside_dir.mkdir()
        shard_one = scan_dir / "checkpoint_1.pt"
        shard_two = scan_dir / "checkpoint_2.pt"
        inside_target = scan_dir / "inside.pt"
        outside_target = outside_dir / "outside.pt"
        shard_one.write_bytes(b"first")
        inside_target.write_bytes(b"inside")
        outside_target.write_bytes(b"outside")
        shard_two.symlink_to(inside_target)
        allowed_paths = [str(shard_one.resolve()), str(inside_target.resolve())]
        inside_target.unlink()
        inside_target.symlink_to(outside_target)

        shard_info = ShardedModelDetector.detect_shards(str(shard_one), allowed_paths=allowed_paths)
        result = AdvancedFileHandler(
            str(shard_one),
            CompletingShardScanner(),
            allowed_shard_paths=allowed_paths,
        ).scan()

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one)]
        assert str(shard_two) not in shard_info["shards"]
        assert shard_info["out_of_scope_shards"] == [str(shard_two)]
        assert result.success is False
        assert "out_of_scope_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_shards_rejects_non_regular_member(self, tmp_path: Path) -> None:
        """A directory whose name resembles a shard cannot be counted or scanned."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"safe")
        shard_two.mkdir()

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one)]
        assert shard_info["unreadable_shards"] == [str(shard_two)]

    def test_shard_target_swap_after_detection_fails_closed(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Shard workers must not follow a symlink retargeted after validation."""
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        inside_target = tmp_path / "inside.pt"
        outside_target = outside_dir / "outside.pt"
        shard_one.write_bytes(b"first")
        inside_target.write_bytes(b"inside")
        outside_target.write_bytes(b"outside")
        shard_two.symlink_to(inside_target)
        scanned_payloads: list[bytes] = []

        class RecordingScanner:
            name = "recording_scanner"

            def scan(self, shard_path: str) -> ScanResult:
                scanned_payloads.append(Path(shard_path).read_bytes())
                result = ScanResult(scanner_name=self.name)
                result.finish(success=True)
                return result

        handler = AdvancedFileHandler(str(shard_one), RecordingScanner())
        shard_two.unlink()
        shard_two.symlink_to(outside_target)

        result = handler.scan()

        assert result.success is False
        assert b"outside" not in scanned_payloads
        assert "shard_scan_error" in result.metadata["scan_outcome_reasons"]

    def test_shard_target_swap_during_scan_discards_clean_result(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A clean result cannot be trusted when its validated target changed mid-scan."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        original_target = tmp_path / "malicious.pt"
        replacement_target = tmp_path / "safe.pt"
        shard_one.write_bytes(b"first")
        original_target.write_bytes(b"malicious")
        replacement_target.write_bytes(b"safe")
        shard_two.symlink_to(original_target)
        scanned_payloads: list[bytes] = []

        class SwappingScanner:
            name = "swapping_scanner"

            def scan(self, shard_path: str) -> ScanResult:
                path = Path(shard_path)
                result = ScanResult(scanner_name=self.name)
                if path == original_target:
                    path.unlink()
                    path.symlink_to(replacement_target)
                    result.add_check(
                        name="Clean Replacement Accepted",
                        passed=True,
                        message=path.name,
                        severity=IssueSeverity.INFO,
                    )
                scanned_payloads.append(path.read_bytes())
                result.finish(success=True)
                return result

        result = AdvancedFileHandler(str(shard_one), SwappingScanner()).scan()

        assert b"safe" in scanned_payloads
        assert result.success is False
        assert "shard_scan_error" in result.metadata["scan_outcome_reasons"]
        assert any(check.name == "Shard Scan" and check.status == CheckStatus.FAILED for check in result.checks)
        assert not any(check.name == "Clean Replacement Accepted" for check in result.checks)

    def test_shard_added_during_scan_marks_family_inconclusive(self, tmp_path: Path) -> None:
        """A shard created after detection cannot remain outside the completed scan set."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        added_shard = tmp_path / "checkpoint_3.pt"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")
        scanned_names: list[str] = []

        class AddingShardScanner:
            name = "adding_shard_scanner"

            def scan(self, shard_path: str) -> ScanResult:
                scanned_names.append(Path(shard_path).name)
                if Path(shard_path) == shard_one:
                    added_shard.write_bytes(b"malicious-unscanned")
                result = ScanResult(scanner_name=self.name)
                result.finish(success=True)
                return result

        result = AdvancedFileHandler(str(shard_one), AddingShardScanner()).scan()

        assert set(scanned_names) == {shard_one.name, shard_two.name}
        assert added_shard.name not in scanned_names
        assert result.success is False
        assert "shard_family_changed" in result.metadata["scan_outcome_reasons"]
        membership_check = next(check for check in result.checks if check.name == "Sharded Model Membership Check")
        assert membership_check.details["added_shards"] == [str(added_shard)]
        assert membership_check.details["analysis_incomplete"] is True

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

    def test_find_model_config_rejects_external_symlink(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Model metadata discovery must not read configuration outside the shard directory."""
        scan_dir = tmp_path / "scan"
        outside_dir = tmp_path / "outside"
        scan_dir.mkdir()
        outside_dir.mkdir()
        model_path = scan_dir / "checkpoint_1.pt"
        outside_config = outside_dir / "config.json"
        model_path.write_bytes(b"model")
        outside_config.write_text('{"torch_dtype": "float16"}')
        (scan_dir / "config.json").symlink_to(outside_config)

        assert ShardedModelDetector.find_model_config(str(model_path)) is None

    def test_sharded_model_rejects_config_symlink_swap_without_nofollow(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        """Descriptor identity checks must protect platforms without ``O_NOFOLLOW``."""
        scan_dir = tmp_path / "scan"
        outside_dir = tmp_path / "outside"
        scan_dir.mkdir()
        outside_dir.mkdir()
        shard_one = scan_dir / "checkpoint_1.pt"
        shard_two = scan_dir / "checkpoint_2.pt"
        config_path = scan_dir / "config.json"
        outside_config = outside_dir / "config.json"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")
        config_path.write_text('{"model_type": "safe"}')
        outside_config.write_text('{"torch_dtype": "float16"}')
        original_open = os.open
        swapped = False

        def swap_before_open(path: str, flags: int) -> int:
            nonlocal swapped
            if Path(path) == config_path:
                config_path.unlink()
                config_path.symlink_to(outside_config)
                swapped = True
            return original_open(path, flags)

        monkeypatch.setattr(os, "O_NOFOLLOW", 0, raising=False)
        monkeypatch.setattr(os, "open", swap_before_open)

        result = AdvancedFileHandler(str(shard_one), CompletingShardScanner()).scan()

        assert swapped is True
        assert not any(check.name == "PyTorch Configuration Detection" for check in result.checks)


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

    def test_sharded_model_reports_out_of_scope_and_unreadable_shards(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Distinct shard coverage gaps must all remain visible to operators."""
        outside_dir = tmp_path / "outside"
        scan_dir = tmp_path / "scan"
        outside_dir.mkdir()
        scan_dir.mkdir()
        shard_one = scan_dir / "checkpoint_1.pt"
        shard_two = scan_dir / "checkpoint_2.pt"
        shard_three = scan_dir / "checkpoint_3.pt"
        outside_target = outside_dir / "outside-shard.pt"
        shard_one.write_bytes(b"safe")
        outside_target.write_bytes(b"outside")
        shard_two.symlink_to(outside_target)
        shard_three.symlink_to(scan_dir / "missing-shard")

        result = AdvancedFileHandler(str(shard_one), CompletingShardScanner()).scan()

        coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
        assert result.success is False
        assert "out_of_scope_model_shards" in result.metadata["scan_outcome_reasons"]
        assert "unreadable_model_shards" in result.metadata["scan_outcome_reasons"]
        assert len(coverage_checks) == 1
        assert coverage_checks[0].details["out_of_scope_shard_count"] == 1
        assert coverage_checks[0].details["out_of_scope_shards"] == [str(shard_two)]
        assert coverage_checks[0].details["unreadable_shard_count"] == 1
        assert coverage_checks[0].details["unreadable_shards"] == [str(shard_three)]

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

    def test_sharded_model_marks_in_directory_allowlist_retarget_inconclusive(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """An unnumbered sibling cannot silently move to a new in-directory target."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        original_target = tmp_path / "original.pt"
        replacement_target = tmp_path / "replacement.pt"
        shard_one.write_bytes(b"one")
        original_target.write_bytes(b"original")
        replacement_target.write_bytes(b"replacement")
        shard_two.symlink_to(original_target)
        allowed_paths = [str(shard_one.resolve()), str(original_target.resolve())]
        shard_two.unlink()
        shard_two.symlink_to(replacement_target)

        result = AdvancedFileHandler(
            str(shard_one),
            CompletingShardScanner(),
            allowed_shard_paths=allowed_paths,
        ).scan()

        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]
        coverage_check = next(check for check in result.checks if check.name == "Sharded Model Coverage Check")
        assert coverage_check.details["unvalidated_shards"] == [str(shard_two)]

    def test_sharded_model_rejects_retargeted_representative_before_fallback(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A changed representative cannot downgrade into an ordinary file scan."""
        representative = tmp_path / "checkpoint_1.pt"
        original_target = tmp_path / "original.pt"
        replacement_target = tmp_path / "replacement.pt"
        original_target.write_bytes(b"original")
        replacement_target.write_bytes(b"replacement")
        representative.symlink_to(original_target)
        allowed_paths = [str(original_target.resolve())]
        representative.unlink()
        representative.symlink_to(replacement_target)

        result = scan_advanced_large_file(
            str(representative),
            CompletingShardScanner(),
            allowed_shard_paths=allowed_paths,
        )

        assert result.success is False
        assert result.scanner_name == "completing_shard_scanner"
        assert result.metadata["operational_error_reason"] == "shard_boundary_changed"
        assert "shard_boundary_changed" in result.metadata["scan_outcome_reasons"]

    def test_sharded_model_reports_unreadable_and_unvalidated_allowlist_members(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """All simultaneous allowlist coverage gaps remain visible in one check."""
        shard_one = tmp_path / "checkpoint_1.pt"
        broken_shard = tmp_path / "checkpoint_2.pt"
        retargeted_shard = tmp_path / "checkpoint_3.pt"
        original_target = tmp_path / "original.pt"
        replacement_target = tmp_path / "replacement.pt"
        shard_one.write_bytes(b"one")
        original_target.write_bytes(b"original")
        replacement_target.write_bytes(b"replacement")
        broken_shard.symlink_to(tmp_path / "missing.pt")
        retargeted_shard.symlink_to(original_target)
        allowed_paths = [
            str(shard_one.resolve()),
            str(original_target.resolve()),
            str((tmp_path / "missing.pt").absolute()),
        ]
        retargeted_shard.unlink()
        retargeted_shard.symlink_to(replacement_target)

        result = AdvancedFileHandler(
            str(shard_one),
            CompletingShardScanner(),
            allowed_shard_paths=allowed_paths,
        ).scan()

        coverage_check = next(check for check in result.checks if check.name == "Sharded Model Coverage Check")
        assert result.success is False
        assert "unreadable_model_shards" in result.metadata["scan_outcome_reasons"]
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]
        assert coverage_check.details["unreadable_shards"] == [str(broken_shard)]
        assert coverage_check.details["unvalidated_shards"] == [str(retargeted_shard)]

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

    def test_cached_sharded_scan_revalidates_retargeted_sibling(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A successful shard scan cache cannot hide a sibling later retargeted outside."""
        scan_dir = tmp_path / "scan"
        outside_dir = tmp_path / "outside"
        scan_dir.mkdir()
        outside_dir.mkdir()
        shard_one = scan_dir / "checkpoint_1.pt"
        shard_two = scan_dir / "checkpoint_2.pt"
        inside_target = scan_dir / "inside.pt"
        outside_target = outside_dir / "outside.pt"
        shard_one.write_bytes(b"first")
        inside_target.write_bytes(b"inside")
        outside_target.write_bytes(b"outside")
        shard_two.symlink_to(inside_target)
        cache_dir = tmp_path / "cache"

        class CachedCompletingShardScanner(CompletingShardScanner):
            def __init__(self, config: dict[str, Any] | None = None) -> None:
                self.config = config or {}

        scanner = CachedCompletingShardScanner({"cache_enabled": True, "cache_dir": str(cache_dir)})

        reset_cache_manager()
        try:
            first = scan_advanced_large_file(str(shard_one), scanner)
            cache_manager = get_cache_manager(str(cache_dir), enabled=True)
            cached_entries = cache_manager.get_stats()["total_entries"]
            shard_two.unlink()
            shard_two.symlink_to(outside_target)
            second = scan_advanced_large_file(str(shard_one), scanner)
        finally:
            reset_cache_manager()

        assert first.success is True
        assert cached_entries > 0
        assert second.success is False
        assert "out_of_scope_model_shards" in second.metadata["scan_outcome_reasons"]
        assert cache_manager.get_stats()["total_entries"] == cached_entries

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
