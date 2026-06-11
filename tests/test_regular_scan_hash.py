"""Tests for content hash generation in regular scan mode."""

import hashlib
import os
import pickle
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.utils.helpers.secure_hasher import compute_aggregate_hash
from tests.helpers import create_mock_pytorch_zip


class TestRegularScanContentHash:
    """Test content hash generation for regular (non-streaming) scans."""

    def test_single_file_generates_hash(self, tmp_path):
        """Test that scanning a single file generates a content hash."""
        # Create a simple pickle file
        test_file = tmp_path / "model.pkl"
        data = {"key": "value", "number": 42}
        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        # Scan the file
        result = scan_model_directory_or_file(str(test_file))

        # Verify content_hash is present and valid
        assert hasattr(result, "content_hash")
        assert result.content_hash is not None
        assert isinstance(result.content_hash, str)
        assert len(result.content_hash) == 64  # SHA-256 hex digest length

    def test_single_archive_hash_uses_outer_file_bytes(self, tmp_path: Path) -> None:
        """Archive scans must hash the scanned archive, not merged nested metadata."""
        archive_path = tmp_path / "model.zip"
        nested_payload = pickle.dumps({"nested": "payload"})
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("model.pkl", nested_payload)

        result = scan_model_directory_or_file(str(archive_path))

        outer_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        nested_hash = hashlib.sha256(nested_payload).hexdigest()
        assert result.content_hash == compute_aggregate_hash([outer_hash])
        assert result.content_hash != compute_aggregate_hash([nested_hash])

    def test_directory_generates_hash(self, tmp_path):
        """Test that scanning a directory generates an aggregate content hash."""
        # Create multiple pickle files
        for i in range(3):
            test_file = tmp_path / f"model_{i}.pkl"
            data = {"id": i, "value": f"test_{i}"}
            with open(test_file, "wb") as f:
                pickle.dump(data, f)

        # Scan the directory
        result = scan_model_directory_or_file(str(tmp_path))

        # Verify content_hash is present and valid
        assert hasattr(result, "content_hash")
        assert result.content_hash is not None
        assert isinstance(result.content_hash, str)
        assert len(result.content_hash) == 64

    def test_hash_is_deterministic(self, tmp_path):
        """Test that scanning the same content produces the same hash."""
        # Create a test file
        test_file = tmp_path / "model.pkl"
        data = {"deterministic": "test"}
        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        # Scan twice
        result1 = scan_model_directory_or_file(str(test_file))
        result2 = scan_model_directory_or_file(str(test_file))

        # Hashes should be identical
        assert result1.content_hash == result2.content_hash

    def test_directory_hash_is_deterministic(self, tmp_path):
        """Test that scanning the same directory produces the same hash."""
        # Create multiple files
        for i in range(3):
            test_file = tmp_path / f"model_{i}.pkl"
            data = {"id": i}
            with open(test_file, "wb") as f:
                pickle.dump(data, f)

        # Scan twice
        result1 = scan_model_directory_or_file(str(tmp_path))
        result2 = scan_model_directory_or_file(str(tmp_path))

        # Hashes should be identical
        assert result1.content_hash == result2.content_hash

    def test_different_content_different_hash(self, tmp_path):
        """Test that different content produces different hashes."""
        # Create first file
        file1 = tmp_path / "model1.pkl"
        with open(file1, "wb") as f:
            pickle.dump({"data": "first"}, f)

        # Create second file with different content
        file2 = tmp_path / "model2.pkl"
        with open(file2, "wb") as f:
            pickle.dump({"data": "second"}, f)

        # Scan both files
        result1 = scan_model_directory_or_file(str(file1))
        result2 = scan_model_directory_or_file(str(file2))

        # Hashes should be different
        assert result1.content_hash != result2.content_hash

    def test_hash_order_independence(self, tmp_path):
        """Test that file processing order doesn't affect the aggregate hash."""
        # Create files with different names to ensure different traversal order
        files = []
        for name in ["aaa.pkl", "zzz.pkl", "mmm.pkl"]:
            file_path = tmp_path / name
            with open(file_path, "wb") as f:
                pickle.dump({"name": name}, f)
            files.append(file_path)

        # Scan the directory multiple times to verify consistent hash
        # (os.walk might process in different order)
        result1 = scan_model_directory_or_file(str(tmp_path))
        result2 = scan_model_directory_or_file(str(tmp_path))

        # Hashes should be identical across scans (order-independent)
        # This is guaranteed by compute_aggregate_hash sorting the hashes
        assert result1.content_hash is not None
        assert result1.content_hash == result2.content_hash

    def test_duplicate_files_single_hash(self, tmp_path):
        """Test that duplicate files are deduplicated and contribute once to hash."""
        # Create identical files
        data = {"duplicate": "content"}
        for i in range(3):
            test_file = tmp_path / f"dup_{i}.pkl"
            with open(test_file, "wb") as f:
                pickle.dump(data, f)

        # Scan directory with duplicates
        result = scan_model_directory_or_file(str(tmp_path))

        # Should have a hash (deduplication means only one hash contributed)
        assert result.content_hash is not None

    def test_empty_directory_no_hash(self, tmp_path):
        """Test that an empty directory doesn't generate a content hash."""
        # Scan empty directory
        result = scan_model_directory_or_file(str(tmp_path))

        # content_hash should not be set (remains None) when no files are hashed
        assert result.content_hash is None

    def test_hash_consistency_with_streaming(self, tmp_path):
        """Test that regular and streaming modes produce compatible hashes."""
        # Create test files
        file_hashes = []
        for i in range(2):
            test_file = tmp_path / f"model_{i}.pkl"
            data = {"id": i}
            with open(test_file, "wb") as f:
                pickle.dump(data, f)

            # Compute individual file hash
            import hashlib

            hash_sha256 = hashlib.sha256()
            with open(test_file, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_sha256.update(chunk)
            file_hashes.append(hash_sha256.hexdigest())

        # Compute expected aggregate hash
        expected_hash = compute_aggregate_hash(file_hashes)

        # Scan directory with regular mode
        result = scan_model_directory_or_file(str(tmp_path))

        # Should match the expected aggregate
        assert result.content_hash == expected_hash

    def test_mixed_files_generates_hash(self, tmp_path):
        """Test that scanning a directory with mixed file types generates a hash."""
        # Create a model file
        model_file = tmp_path / "model.pkl"
        with open(model_file, "wb") as f:
            pickle.dump({"data": "model"}, f)

        # Create a text file (scanned for metadata but not with model scanners)
        text_file = tmp_path / "readme.txt"
        text_file.write_text("This is a readme")

        # Scan directory
        result = scan_model_directory_or_file(str(tmp_path))

        # Should have a content hash
        assert result.content_hash is not None
        # Both files are processed (readme.txt for metadata)
        assert result.files_scanned == 2


@pytest.mark.unit
class TestHashGenerationEdgeCases:
    """Test edge cases in hash generation."""

    def test_hash_with_nested_directories(self, tmp_path):
        """Test hash generation with nested directory structure."""
        # Create nested structure
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        file1 = tmp_path / "model.pkl"
        with open(file1, "wb") as f:
            pickle.dump({"level": 1}, f)

        file2 = subdir / "nested.pkl"
        with open(file2, "wb") as f:
            pickle.dump({"level": 2}, f)

        # Scan root directory
        result = scan_model_directory_or_file(str(tmp_path))

        # Should generate hash for all files
        assert result.content_hash is not None
        assert result.files_scanned == 2

    def test_hash_with_regular_files(self, tmp_path):
        """Test that regular files generate hash correctly."""
        # Create a regular file
        regular_file = tmp_path / "model.pkl"
        with open(regular_file, "wb") as f:
            pickle.dump({"type": "regular"}, f)

        # Scan directory
        result = scan_model_directory_or_file(str(tmp_path))

        assert result.content_hash is not None
        assert result.files_scanned == 1

    def test_hash_files_by_path_reuses_hash_for_hardlinks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Hardlinked paths should reuse the same read during the hash prepass."""
        from modelaudit import core

        source = tmp_path / "source.pkl"
        source.write_bytes(pickle.dumps({"hardlink": True}))
        linked_path = tmp_path / "linked.pkl"
        os.link(source, linked_path)

        hashed_paths: list[str] = []
        original_hash = core._calculate_file_hash

        def spy_hash(path: str) -> str:
            hashed_paths.append(path)
            return original_hash(path)

        monkeypatch.setattr(core, "_calculate_file_hash", spy_hash)

        content_hashes = core._hash_files_by_path([str(source), str(linked_path)])

        assert content_hashes[str(source)] == content_hashes[str(linked_path)]
        assert hashed_paths == [str(source)]

    def test_directory_scan_does_not_hash_files_over_max_file_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Directory hash prepass should not read files regular scanning will reject."""
        from modelaudit import core

        oversized = tmp_path / "oversized.pkl"
        oversized.write_bytes(b"X" * 128)
        small = tmp_path / "small.pkl"
        small.write_bytes(pickle.dumps({"safe": True}))

        original_hash = core._calculate_file_hash
        hashed_paths: list[str] = []

        def fail_if_oversized_hashed(path: str) -> str:
            hashed_paths.append(path)
            if path == str(oversized):
                raise AssertionError("oversized file was hashed before max_file_size rejection")
            return original_hash(path)

        monkeypatch.setattr(core, "_calculate_file_hash", fail_if_oversized_hashed)

        result = scan_model_directory_or_file(
            str(tmp_path),
            max_file_size=64,
            cache_enabled=False,
        )

        assert str(oversized) not in hashed_paths
        assert str(small) in hashed_paths
        assert determine_exit_code(result) == 2
        assert any(issue.message.startswith("File too large to scan") for issue in result.issues)
        assert result.has_errors is True

    def test_single_file_scan_does_not_hash_files_over_max_file_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Single-file hashing should honor the same regular scan size budget."""
        from modelaudit import core

        oversized = tmp_path / "oversized.pkl"
        oversized.write_bytes(b"X" * 128)

        monkeypatch.setattr(
            core,
            "_calculate_file_hash",
            lambda _path: pytest.fail("oversized file was hashed before max_file_size rejection"),
        )

        result = scan_model_directory_or_file(
            str(oversized),
            max_file_size=64,
            cache_enabled=False,
        )

        assert determine_exit_code(result) == 2
        assert any(issue.message.startswith("File too large to scan") for issue in result.issues)
        assert result.has_errors is True

    def test_single_file_scan_bypasses_cache_hash_for_max_file_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Cache lookup should not content-hash files regular scanning will reject."""
        from modelaudit.utils.helpers.secure_hasher import SecureFileHasher

        oversized = tmp_path / "oversized.pkl"
        oversized.write_bytes(b"X" * 128)

        def fail_if_cache_hashes_oversized(self: SecureFileHasher, path: str) -> str:
            if path == str(oversized):
                pytest.fail("oversized file was content-hashed for cache lookup before max_file_size rejection")
            return "a" * 64

        monkeypatch.setattr(SecureFileHasher, "hash_file", fail_if_cache_hashes_oversized)
        monkeypatch.setattr(
            SecureFileHasher,
            "hash_file_with_stat",
            lambda self, path, _stat: fail_if_cache_hashes_oversized(self, path),
        )

        result = scan_model_directory_or_file(
            str(oversized),
            max_file_size=64,
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            content_hash_threshold=1,
            max_cache_file_size=1024,
        )

        assert determine_exit_code(result) == 2
        assert any(issue.message.startswith("File too large to scan") for issue in result.issues)
        assert result.has_errors is True

    def test_hash_files_by_path_stops_hashing_at_max_total_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Directory hash prepasses should stop after crossing the aggregate scan budget."""
        from modelaudit import core

        first = tmp_path / "first.pkl"
        first.write_bytes(b"A" * 32)
        second = tmp_path / "second.pkl"
        second.write_bytes(b"B" * 33)
        third = tmp_path / "third.pkl"
        third.write_bytes(b"C")

        original_hash = core._calculate_file_hash
        hashed_paths: list[str] = []

        def track_hash(path: str) -> str:
            hashed_paths.append(path)
            return original_hash(path)

        monkeypatch.setattr(core, "_calculate_file_hash", track_hash)

        content_hashes = core._hash_files_by_path(
            [str(first), str(second), str(third)],
            config={"max_total_size": 64},
        )

        assert hashed_paths == [str(first), str(second)]
        assert content_hashes[str(third)].startswith("unhashable_max_total_size_")

    def test_hash_files_by_path_defers_oversized_pytorch_zip_read_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Aggregate hashing must not full-read oversized ZIP-backed PyTorch containers."""
        from modelaudit import core

        zip_path = create_mock_pytorch_zip(tmp_path / "large.pt")
        with zip_path.open("ab") as handle:
            handle.write(b"A" * 2048)

        def fail_hash(path: str) -> str:
            if path == str(zip_path):
                pytest.fail("oversized PyTorch ZIP was content-hashed before bounded scan dispatch")
            return "a" * 64

        monkeypatch.setattr(core, "_calculate_file_hash", fail_hash)

        content_hashes = core._hash_files_by_path(
            [str(zip_path)],
            config={"max_file_read_size": 64},
        )

        assert content_hashes[str(zip_path)].startswith("unhashable_pytorch_zip_read_limit_")

    def test_single_file_scan_defers_oversized_pytorch_zip_content_hash(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Single-file scans must not publish aggregate hashes for prefix-hashed PyTorch ZIPs."""
        from modelaudit import core

        zip_path = create_mock_pytorch_zip(tmp_path / "large.pt")
        with zip_path.open("ab") as handle:
            handle.write(b"A" * 2048)

        def fail_hash(path: str) -> str:
            if path == str(zip_path):
                pytest.fail("oversized PyTorch ZIP was content-hashed before bounded scan dispatch")
            return "a" * 64

        monkeypatch.setattr(core.BaseScanner, "default_max_file_read_size", 256)
        monkeypatch.setattr(core, "_calculate_file_hash", fail_hash)

        result = scan_model_directory_or_file(
            str(zip_path),
            max_file_size=10_000,
            cache_enabled=False,
        )

        assert result.success is True
        assert result.content_hash is None
        file_hashes = result.file_metadata[str(zip_path)].file_hashes
        assert file_hashes is not None
        assert file_hashes.sha256_prefix
        assert file_hashes.sha256 is None

    def test_directory_scan_omits_content_hash_when_max_total_hashing_incomplete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Successful scans must not publish aggregate hashes for only a prefix of files."""
        from modelaudit import core
        from modelaudit.scanner_results import ScanResult

        first = tmp_path / "first.pkl"
        first.write_bytes(b"A" * 32)
        second = tmp_path / "second.pkl"
        second.write_bytes(b"B" * 33)
        third = tmp_path / "third.pkl"
        third.write_bytes(b"C")
        original_walk = core.os.walk

        original_hash = core._calculate_file_hash
        hashed_paths: list[str] = []

        def unsorted_walk(
            top: str,
            topdown: bool = True,
            onerror: Callable[[OSError], None] | None = None,
            followlinks: bool = False,
        ) -> Iterator[tuple[str, list[str], list[str]]]:
            if Path(top) == tmp_path:
                yield str(tmp_path), [], ["third.pkl", "first.pkl", "second.pkl"]
                return
            yield from original_walk(top, topdown=topdown, onerror=onerror, followlinks=followlinks)

        def track_hash(path: str) -> str:
            hashed_paths.append(path)
            return original_hash(path)

        def successful_scan(_path: str, _config: dict[str, object]) -> ScanResult:
            scan_result = ScanResult(scanner_name="bounded_test")
            scan_result.bytes_scanned = 1
            scan_result.finish(success=True)
            return scan_result

        monkeypatch.setattr(core.os, "walk", unsorted_walk)
        monkeypatch.setattr(core, "_calculate_file_hash", track_hash)
        monkeypatch.setattr(core, "scan_file", successful_scan)

        result = scan_model_directory_or_file(
            str(tmp_path),
            max_total_size=64,
            cache_enabled=False,
        )

        assert len(hashed_paths) == 2
        assert result.content_hash is None
        assert result.success is True

    def test_directory_scan_omits_content_hash_when_max_file_size_hashing_incomplete(
        self,
        tmp_path: Path,
    ) -> None:
        """Directory scans must not publish hashes that omit oversized rejected files."""
        small = tmp_path / "small.pkl"
        small.write_bytes(pickle.dumps(1))
        oversized = tmp_path / "oversized.pkl"
        oversized.write_bytes(pickle.dumps({"safe": True}) + b"X" * 128)

        result = scan_model_directory_or_file(
            str(tmp_path),
            max_file_size=64,
            cache_enabled=False,
        )

        assert result.content_hash is None
        assert determine_exit_code(result) == 2
        assert any(issue.message.startswith("File too large to scan") for issue in result.issues)

    def test_directory_scan_omits_content_hash_when_expanded_scan_bytes_exceed_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A scan stopped by expanded bytes must not publish its precomputed aggregate hash."""
        from modelaudit import core
        from modelaudit.scanner_results import ScanResult

        first = tmp_path / "first.pkl"
        first.write_bytes(b"A")
        second = tmp_path / "second.pkl"
        second.write_bytes(b"B")
        scanned_paths: list[str] = []

        def expanded_scan(path: str, _config: dict[str, object]) -> ScanResult:
            scanned_paths.append(path)
            scan_result = ScanResult(scanner_name="bounded_test")
            scan_result.bytes_scanned = 128
            scan_result.finish(success=True)
            return scan_result

        monkeypatch.setattr(core, "scan_file", expanded_scan)

        result = scan_model_directory_or_file(
            str(tmp_path),
            max_total_size=64,
            cache_enabled=False,
        )

        assert scanned_paths == [str(first)]
        assert result.content_hash is None
        assert determine_exit_code(result) == 2
        assert any(issue.message.startswith("Total scan size limit exceeded") for issue in result.issues)

    def test_single_file_scan_fails_closed_after_max_total_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Single-file scans should fail closed after measured budget overflow."""
        from modelaudit import core
        from modelaudit.scanner_results import ScanResult

        oversized = tmp_path / "oversized.pkl"
        oversized.write_bytes(pickle.dumps({"safe": True}) + b"X" * 128)
        scan_result = ScanResult(scanner_name="bounded_test")
        scan_result.bytes_scanned = 128
        scan_result.finish(success=True)

        hashed_paths: list[str] = []
        original_hash = core._calculate_file_hash

        def track_hash(path: str) -> str:
            hashed_paths.append(path)
            return original_hash(path)

        monkeypatch.setattr(core, "_calculate_file_hash", track_hash)
        monkeypatch.setattr(core, "scan_file", lambda _path, _config: scan_result)

        result = scan_model_directory_or_file(
            str(oversized),
            max_total_size=64,
            cache_enabled=False,
        )

        assert hashed_paths == [str(oversized)]
        assert determine_exit_code(result) == 2
        assert any(issue.message.startswith("Total scan size limit exceeded") for issue in result.issues)
        assert result.has_errors is True
        assert result.content_hash is None

    def test_unhashable_files_excluded_from_hash(self, tmp_path, monkeypatch):
        """Test that files failing to hash are excluded from aggregate hash."""
        # Create a valid file
        valid_file = tmp_path / "valid.pkl"
        with open(valid_file, "wb") as f:
            pickle.dump({"data": "valid"}, f)

        # Create a file that will fail to hash
        bad_file = tmp_path / "bad.pkl"
        with open(bad_file, "wb") as f:
            pickle.dump({"data": "bad"}, f)

        # Mock _calculate_file_hash to fail for bad.pkl
        from modelaudit import core

        original_hash = core._calculate_file_hash

        def mock_hash(path):
            if "bad.pkl" in str(path):
                raise OSError("Simulated hash failure")
            return original_hash(path)

        monkeypatch.setattr(core, "_calculate_file_hash", mock_hash)

        # Scan directory
        result = scan_model_directory_or_file(str(tmp_path))

        # Should have a hash based only on the valid file
        assert result.content_hash is not None
        # files_scanned should include both files
        assert result.files_scanned == 2

    def test_hash_generation_performance(self, tmp_path):
        """Test that hash generation doesn't significantly impact performance."""
        import time

        # Create multiple files
        for i in range(10):
            test_file = tmp_path / f"model_{i}.pkl"
            with open(test_file, "wb") as f:
                pickle.dump({"id": i}, f)

        # Measure scan time
        start = time.time()
        result = scan_model_directory_or_file(str(tmp_path))
        duration = time.time() - start

        # Should complete quickly (under 2 seconds for 10 small files)
        assert duration < 2.0
        assert result.content_hash is not None
        assert result.files_scanned == 10
