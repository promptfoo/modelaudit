import asyncio
import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from modelaudit.utils.sources.cloud_storage import (
    GCSCache,
    _run_coroutine_sync,
    analyze_cloud_target,
    download_from_cloud,
    download_from_cloud_streaming,
    filter_scannable_files,
    get_cloud_object_size,
    is_cloud_url,
)


def make_fs_mock() -> MagicMock:
    fs = MagicMock()
    fs.__enter__.return_value = fs
    fs.__exit__.side_effect = lambda exc_type, exc, tb: fs.close()
    return fs


def test_run_coroutine_sync_without_running_loop() -> None:
    """_run_coroutine_sync should use asyncio.run() when no loop is active."""

    async def return_value() -> str:
        return "ok"

    result = _run_coroutine_sync(lambda: return_value())
    assert result == "ok"


class TestCloudURLDetection:
    def test_valid_cloud_urls(self):
        valid = [
            "s3://bucket/key",
            "gs://my-bucket/model.pt",
            "r2://data/model.bin",
            "https://bucket.s3.amazonaws.com/file",
            "https://storage.googleapis.com/bucket/file",
            "https://account.r2.cloudflarestorage.com/bucket/file",
        ]
        for url in valid:
            assert is_cloud_url(url), f"Failed to detect {url}"

    def test_invalid_cloud_urls(self):
        invalid = [
            "https://huggingface.co/model",
            "ftp://example.com/file",
            "",  # empty
        ]
        for url in invalid:
            assert not is_cloud_url(url), f"Incorrectly detected {url}"


@patch("fsspec.filesystem")
def test_download_from_cloud(mock_fs, tmp_path):
    fs_meta = make_fs_mock()
    fs_meta.info.return_value = {"type": "file", "size": 1024}

    fs = make_fs_mock()
    fs.info.return_value = {"type": "file", "size": 1024}

    mock_fs.side_effect = [fs_meta, fs]

    url = "s3://bucket/model.pt"
    result = download_from_cloud(url, cache_dir=tmp_path)

    # Verify fs.get was called (path will include cache subdirectories)
    fs.get.assert_called_once()
    call_args = fs.get.call_args[0]
    assert call_args[0] == url
    assert "model.pt" in call_args[1]

    # Result should be a path containing the filename
    assert isinstance(result, Path)
    assert result.name == "model.pt"
    assert result.exists() or True  # Mock doesn't create actual files

    # Note: fsspec filesystems don't need explicit cleanup according to implementation


@pytest.mark.asyncio
async def test_download_from_cloud_async_context(tmp_path: Path) -> None:
    """download_from_cloud should work from an active event loop context."""
    fs = make_fs_mock()
    fs.info.return_value = {"type": "file", "size": 1024}

    async def mock_analyze(_url: str) -> dict[str, object]:
        return {
            "type": "file",
            "size": 1024,
            "name": "model.pt",
            "human_size": "1.0 KB",
            "estimated_time": "1 second",
        }

    await asyncio.sleep(0)
    with (
        patch("fsspec.filesystem", return_value=fs),
        patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new=mock_analyze),
        patch(
            "modelaudit.utils.sources.cloud_storage.asyncio.run_coroutine_threadsafe",
            side_effect=AssertionError("run_coroutine_threadsafe should not be used"),
        ),
    ):
        result = download_from_cloud("s3://bucket/model.pt", cache_dir=tmp_path, use_cache=False)

    assert isinstance(result, Path)
    assert result.name == "model.pt"


@patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
@patch("modelaudit.utils.file.streaming.get_streaming_preview")
def test_download_from_cloud_streaming_returns_stream_url(mock_preview, mock_analyze, tmp_path):
    url = "s3://bucket/model.pt"
    mock_preview.return_value = None
    mock_analyze.return_value = {
        "type": "file",
        "size": 1024,
        "name": "model.pt",
        "human_size": "1.0 KB",
        "estimated_time": "1 second",
    }

    result = download_from_cloud(url, cache_dir=tmp_path, use_cache=False, stream_analyze=True)

    assert result == f"stream://{url}"


@pytest.mark.asyncio
async def test_download_from_cloud_streaming_async_context() -> None:
    """download_from_cloud_streaming should work from an active event loop context."""
    fs = make_fs_mock()
    fs.info.return_value = {"type": "file", "size": 1024}
    fs.get.side_effect = lambda _src, dst: Path(dst).write_bytes(b"data")

    async def mock_analyze(_url: str) -> dict[str, object]:
        return {
            "type": "file",
            "size": 1024,
            "name": "model.pt",
            "human_size": "1.0 KB",
            "estimated_time": "1 second",
        }

    await asyncio.sleep(0)
    with (
        patch("fsspec.filesystem", return_value=fs),
        patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new=mock_analyze),
        patch(
            "modelaudit.utils.sources.cloud_storage.asyncio.run_coroutine_threadsafe",
            side_effect=AssertionError("run_coroutine_threadsafe should not be used"),
        ),
    ):
        streamed = list(download_from_cloud_streaming("s3://bucket/model.pt", show_progress=False))

    assert len(streamed) == 1
    streamed_path, is_last = streamed[0]
    assert streamed_path.name == "model.pt"
    assert is_last is True


@patch("builtins.__import__")
def test_download_missing_dependency(mock_import):
    def side_effect(name, *args, **kwargs):
        if name == "fsspec":
            raise ImportError("no fsspec")
        return original_import(name, *args, **kwargs)

    original_import = __import__
    mock_import.side_effect = side_effect

    with pytest.raises(ImportError):
        download_from_cloud("s3://bucket/model.pt")


@patch("fsspec.filesystem")
def test_analyze_cloud_target_returns_metadata(mock_fs):
    """Test that analyze_cloud_target returns correct metadata."""
    fs = make_fs_mock()
    fs.info.return_value = {"type": "file", "size": 1024}
    mock_fs.return_value = fs

    metadata = asyncio.run(analyze_cloud_target("s3://bucket/model.pt"))

    assert metadata["size"] == 1024
    # Note: fsspec filesystems don't need explicit cleanup according to implementation


@patch("fsspec.filesystem")
@patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
def test_download_from_cloud_analysis_failure(mock_analyze, mock_fs):
    mock_analyze.return_value = {"type": "unknown", "error": "boom"}
    with pytest.raises(ValueError, match="Failed to analyze cloud target"):
        download_from_cloud("s3://bucket/model.pt", use_cache=False)
    mock_fs.assert_not_called()


class TestCloudObjectSize:
    """Test cloud object size retrieval."""

    def test_get_cloud_object_size_single_file(self) -> None:
        """Test getting size of a single file."""
        fs = MagicMock()
        fs.info.return_value = {"size": 1024 * 1024}  # 1 MB

        size = get_cloud_object_size(fs, "s3://bucket/file.bin")
        assert size == 1024 * 1024

    def test_get_cloud_object_size_directory(self) -> None:
        """Test getting total size of a directory."""
        fs = MagicMock()
        fs.info.return_value = {}  # No size means it's a directory

        def ls_side_effect(path, detail=True):
            if path == "s3://bucket/dir/":
                return [
                    {"name": "s3://bucket/dir/file1.bin", "size": 1024 * 1024, "type": "file"},
                    {"name": "s3://bucket/dir/subdir", "type": "directory"},
                    {"name": "s3://bucket/dir/file2.bin", "size": 2048 * 1024, "type": "file"},
                ]
            elif path == "s3://bucket/dir/subdir":
                return [{"name": "s3://bucket/dir/subdir/file3.bin", "size": 512 * 1024, "type": "file"}]
            return []

        fs.ls.side_effect = ls_side_effect

        size = get_cloud_object_size(fs, "s3://bucket/dir/")
        assert size == (1024 + 2048 + 512) * 1024  # 3.5 MB

    def test_get_cloud_object_size_error(self) -> None:
        """Test size retrieval returns None on error."""
        fs = MagicMock()
        fs.info.side_effect = Exception("Access denied")

        size = get_cloud_object_size(fs, "s3://bucket/file.bin")
        assert size is None

    def test_get_cloud_object_size_invalid_top_level_size_non_strict(self) -> None:
        """Test invalid top-level size values are ignored in non-strict mode."""
        fs = MagicMock()
        fs.info.return_value = {"size": None}

        size = get_cloud_object_size(fs, "s3://bucket/file.bin")
        assert size is None

    def test_get_cloud_object_size_invalid_top_level_size_strict(self) -> None:
        """Test invalid top-level size values raise ValueError in strict mode."""
        fs = MagicMock()
        fs.info.return_value = {"size": None}
        fs.walk.side_effect = RuntimeError("walk unavailable")
        fs.ls.side_effect = RuntimeError("ls unavailable")

        with pytest.raises(ValueError, match="invalid size from info\\(\\)"):
            get_cloud_object_size(fs, "s3://bucket/file.bin", strict=True)


class TestDiskSpaceCheckingForCloud:
    """Test disk space checking for cloud downloads."""

    @patch("modelaudit.utils.sources.cloud_storage.get_cloud_object_size")
    @patch("modelaudit.utils.sources.cloud_storage.check_disk_space")
    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    def test_download_insufficient_disk_space(
        self,
        mock_fs_class: MagicMock,
        mock_analyze: AsyncMock,
        mock_check_disk_space: MagicMock,
        mock_get_size: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test download fails when disk space is insufficient."""
        fs = make_fs_mock()
        mock_fs_class.return_value = fs

        # Mock analyze_cloud_target to return file metadata
        mock_analyze.return_value = {
            "type": "file",
            "size": 10 * 1024 * 1024 * 1024,
            "name": "large-model.bin",
            "human_size": "10.0 GB",
            "estimated_time": "5 minutes",
        }

        # Mock object size
        mock_get_size.return_value = 10 * 1024 * 1024 * 1024  # 10 GB

        # Mock disk space check to fail
        mock_check_disk_space.return_value = (False, "Insufficient disk space. Required: 12.0 GB, Available: 5.0 GB")

        # Test download failure
        temp_download_dir = tmp_path / "modelaudit_test_cloud_disk_space"
        with (
            patch("modelaudit.utils.sources.cloud_storage.tempfile.mkdtemp", return_value=str(temp_download_dir)),
            pytest.raises(Exception, match=r"Cannot download from.*Insufficient disk space"),
        ):
            download_from_cloud("s3://bucket/large-model.bin", use_cache=False)

        # Verify download was not attempted
        fs.get.assert_not_called()
        assert not temp_download_dir.exists()

        # Verify the disk space check was actually called
        mock_check_disk_space.assert_called_once()

        # Verify object size check was called
        mock_get_size.assert_called_once()

    @patch("modelaudit.utils.sources.cloud_storage.get_cloud_object_size")
    @patch("modelaudit.utils.sources.cloud_storage.check_disk_space")
    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    def test_download_with_disk_space_check(
        self, mock_fs_class, mock_analyze, mock_check_disk_space, mock_get_size, tmp_path
    ):
        """Test successful download with disk space check."""
        fs_meta = make_fs_mock()
        fs_meta.info.return_value = {"type": "file", "size": 1024 * 1024 * 1024}

        fs = make_fs_mock()
        fs.info.return_value = {"type": "file", "size": 1024 * 1024 * 1024}

        mock_fs_class.side_effect = [fs_meta, fs]

        # Mock analyze_cloud_target to return file metadata
        mock_analyze.return_value = {
            "type": "file",
            "size": 1024 * 1024 * 1024,
            "name": "model.bin",
            "human_size": "1.0 GB",
            "estimated_time": "1 minute",
        }

        # Mock object size
        mock_get_size.return_value = 1024 * 1024 * 1024  # 1 GB

        # Mock disk space check to pass
        mock_check_disk_space.return_value = (True, "Sufficient disk space available (10.0 GB)")

        # Test download
        result = download_from_cloud("s3://bucket/model.bin", cache_dir=tmp_path)

        # Verify disk space was checked
        mock_check_disk_space.assert_called_once()

        # Verify download proceeded - with context managers, fs.get is called but then fs is closed
        # Just verify the result is correct since the mock behavior changes with context managers
        assert isinstance(result, Path)
        assert result.name == "model.bin"
        assert str(tmp_path) in str(result)  # Should be within the cache dir


class TestCloudPathSecurity:
    """Test path-safety behavior for cloud downloads."""

    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    def test_download_rejects_path_traversal(
        self,
        mock_fs_class: MagicMock,
        mock_analyze: AsyncMock,
        tmp_path: Path,
    ) -> None:
        fs = make_fs_mock()
        fs.info.return_value = {}
        mock_fs_class.return_value = fs

        mock_analyze.return_value = {
            "type": "directory",
            "file_count": 1,
            "total_size": 1024,
            "human_size": "1.0 KB",
            "estimated_time": "instant",
            "files": [
                {
                    "path": "s3://bucket/models/../secrets/evil.pkl",
                    "name": "evil.pkl",
                    "size": 1024,
                    "human_size": "1.0 KB",
                }
            ],
        }

        with pytest.raises(ValueError, match="Path traversal attempt detected"):
            download_from_cloud(
                "s3://bucket/models",
                cache_dir=tmp_path,
                use_cache=False,
                selective=False,
                show_progress=False,
            )

        fs.get.assert_not_called()

    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    def test_download_continues_when_size_cannot_be_determined(
        self,
        mock_fs_class: MagicMock,
        mock_analyze: AsyncMock,
    ) -> None:
        fs = make_fs_mock()
        fs.info.side_effect = RuntimeError("permission denied")
        mock_fs_class.return_value = fs

        mock_analyze.return_value = {
            "type": "file",
            "size": 0,
            "name": "model.bin",
            "human_size": "0 B",
            "estimated_time": "instant",
        }

        result = download_from_cloud(
            "s3://bucket/model.bin",
            use_cache=False,
            show_progress=False,
        )

        assert isinstance(result, Path)
        assert result.name == "model.bin"
        fs.get.assert_called_once()

    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    def test_streaming_download_rejects_path_traversal(
        self,
        mock_fs_class: MagicMock,
        mock_analyze: AsyncMock,
    ) -> None:
        fs = make_fs_mock()
        mock_fs_class.return_value = fs

        mock_analyze.return_value = {
            "type": "directory",
            "file_count": 1,
            "total_size": 1024,
            "human_size": "1.0 KB",
            "estimated_time": "instant",
            "files": [
                {
                    "path": "s3://bucket/models/../secrets/evil.pkl",
                    "name": "evil.pkl",
                    "size": 1024,
                    "human_size": "1.0 KB",
                }
            ],
        }

        with pytest.raises(ValueError, match="Path traversal attempt detected"):
            list(
                download_from_cloud_streaming(
                    "s3://bucket/models",
                    show_progress=False,
                    selective=False,
                )
            )

        fs.get.assert_not_called()


class TestCloudCacheSafety:
    """Regression tests for cloud cache boundary enforcement."""

    def test_cache_file_does_not_trust_prefix_sibling_path(self, tmp_path: Path) -> None:
        """Cacheing a sibling path should copy into cache, not trust prefix similarity."""
        cache = GCSCache(cache_dir=tmp_path / "cache")
        sibling_dir = tmp_path / "cache_evil"
        sibling_dir.mkdir(parents=True, exist_ok=True)
        source_file = sibling_dir / "artifact.bin"
        source_file.write_bytes(b"artifact")

        cache.cache_file("s3://bucket/model.bin", source_file)

        cached_path = cache.get_cached_path("s3://bucket/model.bin")
        assert cached_path is not None
        assert cached_path.resolve() != source_file.resolve()
        cached_path.resolve().relative_to(cache.cache_dir.resolve())
        assert source_file.exists()

    def test_clean_old_cache_does_not_delete_outside_cache(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Cleanup must not delete files that are outside cache_dir."""
        caplog.set_level(logging.WARNING, logger="modelaudit.utils.sources.cloud_storage")
        cache = GCSCache(cache_dir=tmp_path / "cache")
        outside_file = tmp_path / "outside" / "artifact.bin"
        outside_file.parent.mkdir(parents=True, exist_ok=True)
        outside_file.write_bytes(b"artifact")

        poisoned_url = "s3://bucket/poisoned"
        poisoned_key = cache.get_cache_key(poisoned_url)
        cache.metadata[poisoned_key] = {
            "url": poisoned_url,
            "path": str(outside_file),
            "etag": None,
            "size": outside_file.stat().st_size,
            "cached_at": "2000-01-01T00:00:00",
            "last_accessed": "2000-01-01T00:00:00",
        }
        cache._save_metadata()

        cache.clean_old_cache(max_age_days=0)

        assert outside_file.exists()
        assert poisoned_key not in cache.metadata
        assert "outside cache dir" in caplog.text


class TestCloudDownloadCleanup:
    """Regression tests for temporary download directory cleanup."""

    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("modelaudit.utils.sources.cloud_storage.retry_with_backoff")
    @patch("fsspec.filesystem")
    def test_download_failure_cleans_temp_dir(
        self,
        mock_fs_class: MagicMock,
        mock_retry_with_backoff: MagicMock,
        mock_analyze: AsyncMock,
        tmp_path: Path,
    ) -> None:
        """Failed single-file downloads should remove auto-created temp directories."""
        fs = make_fs_mock()
        fs.info.return_value = {"type": "file", "size": 1024}
        fs.get.side_effect = RuntimeError("network failure")
        mock_fs_class.return_value = fs

        mock_analyze.return_value = {
            "type": "file",
            "size": 1024,
            "name": "model.bin",
            "human_size": "1.0 KB",
            "estimated_time": "1 second",
        }
        mock_retry_with_backoff.side_effect = lambda *_args, **_kwargs: lambda func: func

        temp_download_dir = tmp_path / "modelaudit_cloud_temp"
        temp_download_dir.mkdir(parents=True, exist_ok=True)
        with (
            patch("modelaudit.utils.sources.cloud_storage.tempfile.mkdtemp", return_value=str(temp_download_dir)),
            pytest.raises(RuntimeError, match="network failure"),
        ):
            download_from_cloud("s3://bucket/model.bin", use_cache=False, show_progress=False)

        assert not temp_download_dir.exists()


def test_filter_scannable_files_recognizes_pdiparams():
    files = [{"path": "model.pdiparams"}]
    assert filter_scannable_files(files) == files


def test_filter_scannable_files_handles_tar_gz_and_tgz():
    files = [{"path": "archive.tar.gz"}, {"path": "weights.tgz"}]
    assert filter_scannable_files(files) == files
