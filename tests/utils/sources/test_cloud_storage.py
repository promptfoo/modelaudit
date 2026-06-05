import asyncio
import json
import logging
import os
import stat
from io import BytesIO
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from modelaudit.utils.helpers.retry import RetryError
from modelaudit.utils.sources.cloud_storage import (
    GCSCache,
    _build_safe_local_path,
    _run_coroutine_sync,
    analyze_cloud_target,
    download_from_cloud,
    download_from_cloud_streaming,
    filter_scannable_files,
    get_cloud_object_size,
    is_cloud_url,
    redact_cloud_error_for_display,
    redact_url_for_display,
)


def make_fs_mock() -> MagicMock:
    fs = MagicMock()
    fs.__enter__.return_value = fs

    def close_context(_exc_type: object, _exc: object, _tb: object) -> None:
        fs.close()

    fs.__exit__.side_effect = close_context
    return fs


class _FailAfterPayload(BytesIO):
    """Return the payload once, then simulate a transient transport failure."""

    def read(self, size: int | None = -1) -> bytes:
        if self.tell() == len(self.getvalue()):
            raise OSError("connection reset")
        return super().read(size)


def configure_partial_metadata_failure(fs: MagicMock, url: str) -> tuple[str, str]:
    model_url = f"{url.rstrip('/')}/model.bin"
    hidden_url = f"{url.rstrip('/')}/evil.pkl?X-Amz-Signature=secret"

    def info_side_effect(path: str) -> dict[str, object]:
        if path == url:
            return {"type": "directory", "name": "bucket/path/"}
        if path == model_url:
            return {"type": "file", "size": 2048}
        if path == hidden_url:
            raise PermissionError(f"metadata denied for {hidden_url}")
        raise FileNotFoundError(path)

    fs.info.side_effect = info_side_effect
    fs.glob.return_value = [model_url, hidden_url]
    return model_url, hidden_url


def test_run_coroutine_sync_without_running_loop() -> None:
    """_run_coroutine_sync should use asyncio.run() when no loop is active."""

    async def return_value() -> str:
        return "ok"

    result = _run_coroutine_sync(lambda: return_value())
    assert result == "ok"


class TestCloudURLDetection:
    def test_detects_valid_cloud_url_patterns(self):
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

    def test_rejects_invalid_cloud_url_patterns(self):
        invalid = [
            "https://huggingface.co/model",
            "ftp://example.com/file",
            "",  # empty
        ]
        for url in invalid:
            assert not is_cloud_url(url), f"Incorrectly detected {url}"


class TestCloudURLRedaction:
    def test_redact_url_for_display_strips_credentials_and_query(self) -> None:
        url = "https://user:pass@example.com:8443/path/to/model.bin?X-Amz-Signature=secret#fragment"
        assert redact_url_for_display(url) == "https://example.com:8443/path/to/model.bin"

    def test_redact_url_for_display_strips_cloud_query_params(self) -> None:
        url = "s3://bucket/model.bin?X-Amz-Credential=secret&X-Amz-Signature=secret"
        assert redact_url_for_display(url) == "s3://bucket/model.bin"

    def test_redact_url_for_display_handles_invalid_port(self) -> None:
        """Malformed ports must not disable signed-query and userinfo redaction."""
        url = "https://user:password@example.com:notaport/model.bin?token=secret"

        redacted = redact_url_for_display(url)

        assert redacted == "https://example.com:notaport/model.bin"
        assert "password" not in redacted
        assert "secret" not in redacted

    def test_redact_cloud_error_for_display_redacts_embedded_signed_urls(self) -> None:
        url = "s3://bucket/model.bin?X-Amz-Credential=cred&X-Amz-Signature=secret"
        message = f"Forbidden while opening {url}"

        redacted = redact_cloud_error_for_display(message, url)

        assert "s3://bucket/model.bin" in redacted
        assert "X-Amz-Credential" not in redacted
        assert "X-Amz-Signature" not in redacted
        assert "secret" not in redacted

    def test_redact_cloud_error_for_display_redacts_query_credentials_without_exact_url(self) -> None:
        message = (
            "provider failed: https://storage.googleapis.com/bucket/model.bin?X-Goog-Signature=secret&token=abc123"
        )

        redacted = redact_cloud_error_for_display(message)

        assert "X-Goog-Signature=<redacted>" in redacted
        assert "token=<redacted>" in redacted
        assert "secret" not in redacted
        assert "abc123" not in redacted

    def test_redact_cloud_error_for_display_redacts_legacy_aws_access_key_id(self) -> None:
        message = (
            "provider failed: https://bucket.s3.amazonaws.com/model.bin?"
            "AWSAccessKeyId=AKIASECRET&Expires=123456&Signature=deadbeef"
        )

        redacted = redact_cloud_error_for_display(message)

        assert "AWSAccessKeyId=<redacted>" in redacted
        assert "Signature=<redacted>" in redacted
        assert "AKIASECRET" not in redacted
        assert "deadbeef" not in redacted

    def test_redact_cloud_error_for_display_handles_encoded_and_fragment_credentials(self) -> None:
        message = (
            "provider failed: https://example.com/model?tokenizer=bert&X-Amz-Sign%61ture=secret"
            "#access_token=fragment-secret"
        )

        redacted = redact_cloud_error_for_display(message)

        assert "tokenizer=bert" in redacted
        assert "X-Amz-Sign%61ture=<redacted>" in redacted
        assert "access_token=<redacted>" in redacted
        assert "fragment-secret" not in redacted


@patch("modelaudit.utils.helpers.retry.time.sleep")
@patch("fsspec.filesystem")
def test_analyze_cloud_target_redacts_signed_url_retry_logs(
    mock_fs: MagicMock, mock_sleep: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    url = "s3://bucket/model.bin?X-Amz-Signature=secret"
    fs = make_fs_mock()
    fs.info.side_effect = OSError(f"Forbidden while opening {url}")
    mock_fs.return_value = fs
    caplog.set_level(logging.DEBUG, logger="modelaudit.utils.helpers.retry")

    result = asyncio.run(analyze_cloud_target(url))

    assert "X-Amz-Signature" not in result["error"]
    assert "secret" not in result["error"]
    assert "s3://bucket/model.bin" in caplog.text
    assert "X-Amz-Signature" not in caplog.text
    assert "secret" not in caplog.text
    mock_sleep.assert_called()


@patch("fsspec.filesystem")
def test_analyze_cloud_target_directory_success(mock_fs: MagicMock) -> None:
    url = "s3://bucket/path/"
    model_url = "s3://bucket/path/model.bin"
    fs = make_fs_mock()

    def info_side_effect(path: str) -> dict[str, object]:
        if path == url:
            return {"type": "directory", "name": "bucket/path/"}
        if path == model_url:
            return {"type": "file", "size": 2048}
        raise FileNotFoundError(path)

    fs.info.side_effect = info_side_effect
    fs.glob.return_value = [model_url]
    mock_fs.return_value = fs

    result = asyncio.run(analyze_cloud_target(url))

    assert result["type"] == "directory"
    assert result["file_count"] == 1
    assert result["total_size"] == 2048
    assert result["human_size"] == "2.0 KB"
    assert result["files"] == [{"path": model_url, "name": "model.bin", "size": 2048, "human_size": "2.0 KB"}]
    fs.glob.assert_called_once_with("s3://bucket/path/**")


@patch("fsspec.filesystem")
def test_analyze_cloud_target_directory_ignores_explicit_directory_metadata(
    mock_fs: MagicMock,
) -> None:
    url = "s3://bucket/path/"
    directory_url = "s3://bucket/path/nested/"
    model_url = "s3://bucket/path/nested/model.bin"
    fs = make_fs_mock()

    def info_side_effect(path: str) -> dict[str, object]:
        if path == url:
            return {"type": "directory", "name": "bucket/path/"}
        if path == directory_url:
            return {"type": "directory", "size": 0}
        if path == model_url:
            return {"type": "file", "size": 2048}
        raise FileNotFoundError(path)

    fs.info.side_effect = info_side_effect
    fs.glob.return_value = [directory_url, model_url]
    mock_fs.return_value = fs

    result = asyncio.run(analyze_cloud_target(url))

    assert result["type"] == "directory"
    assert result["file_count"] == 1
    assert result["files"][0]["path"] == model_url


@patch("fsspec.filesystem")
def test_analyze_cloud_target_directory_fails_on_partial_metadata_error(
    mock_fs: MagicMock,
) -> None:
    url = "s3://bucket/path/"
    fs = make_fs_mock()
    _model_url, hidden_url = configure_partial_metadata_failure(fs, url)
    mock_fs.return_value = fs

    result = asyncio.run(analyze_cloud_target(url))
    serialized = json.dumps(result)

    assert result["type"] == "unknown"
    assert result["analysis_incomplete"] is True
    assert result["metadata_error_count"] == 1
    assert "metadata lookup failed for 1 object" in result["error"]
    assert "evil.pkl" in result["error"]
    assert "X-Amz-Signature" not in serialized
    assert "secret" not in serialized
    assert hidden_url not in serialized


@patch("fsspec.filesystem")
def test_analyze_cloud_target_directory_fails_on_incomplete_listed_object_metadata(
    mock_fs: MagicMock,
) -> None:
    url = "s3://bucket/path/"
    hidden_path = "bucket/path/hidden.pkl"
    fs = make_fs_mock()
    fs.info.side_effect = lambda path: {"type": "directory"} if path == url else {}
    fs.glob.return_value = [hidden_path]
    mock_fs.return_value = fs

    result = asyncio.run(analyze_cloud_target(url))

    assert result["type"] == "unknown"
    assert result["analysis_incomplete"] is True
    assert result["metadata_error_count"] == 1
    assert result["metadata_errors"][0]["path"] == hidden_path
    assert "incomplete metadata" in result["metadata_errors"][0]["error"]


@patch("fsspec.filesystem")
def test_analyze_cloud_target_redacts_protocol_stripped_metadata_error_path(
    mock_fs: MagicMock,
) -> None:
    url = "s3://bucket/path/"
    hidden_path = "bucket/path/hidden.pkl?X-Amz-Signature=secret"
    fs = make_fs_mock()

    def info_side_effect(path: str) -> dict[str, object]:
        if path == url:
            return {"type": "directory"}
        raise PermissionError(f"metadata denied for {path}")

    fs.info.side_effect = info_side_effect
    fs.glob.return_value = [hidden_path]
    mock_fs.return_value = fs

    result = asyncio.run(analyze_cloud_target(url))
    serialized = json.dumps(result)

    assert result["type"] == "unknown"
    assert result["analysis_incomplete"] is True
    assert result["metadata_errors"][0]["path"].endswith("X-Amz-Signature=<redacted>")
    assert "secret" not in serialized


@patch("fsspec.filesystem")
def test_analyze_cloud_target_bounds_partial_metadata_error_details(
    mock_fs: MagicMock,
) -> None:
    url = "s3://bucket/path/"
    failed_urls = [f"s3://bucket/path/evil-{index}.pkl?X-Amz-Signature=secret-{index}" for index in range(5)]
    fs = make_fs_mock()

    def info_side_effect(path: str) -> dict[str, object]:
        if path == url:
            return {"type": "directory", "name": "bucket/path/"}
        raise PermissionError(f"metadata denied for {path}: {'x' * 1024}")

    fs.info.side_effect = info_side_effect
    fs.glob.return_value = failed_urls
    mock_fs.return_value = fs

    result = asyncio.run(analyze_cloud_target(url))
    serialized = json.dumps(result)

    assert result["type"] == "unknown"
    assert result["analysis_incomplete"] is True
    assert result["metadata_error_count"] == 5
    assert len(result["metadata_errors"]) == 3
    assert all(len(entry["error"]) <= 512 for entry in result["metadata_errors"])
    assert result["error"].endswith("; ...")
    assert "evil-4.pkl" not in serialized
    assert "X-Amz-Signature" not in serialized
    assert "secret-" not in serialized


def test_filter_scannable_files_handles_signed_cloud_urls() -> None:
    files = [{"path": "s3://bucket/model.pkl?X-Amz-Signature=secret"}]

    assert filter_scannable_files(files) == files


@patch("fsspec.filesystem")
def test_download_from_cloud_fails_closed_on_partial_directory_metadata_error(
    mock_fs_class: MagicMock,
    tmp_path: Path,
) -> None:
    url = "s3://bucket/path/"
    fs = make_fs_mock()
    configure_partial_metadata_failure(fs, url)
    mock_fs_class.return_value = fs

    with pytest.raises(ValueError, match="Cloud directory analysis incomplete"):
        download_from_cloud(
            url,
            cache_dir=tmp_path,
            use_cache=False,
            selective=False,
            show_progress=False,
        )

    fs.get.assert_not_called()


@patch("fsspec.filesystem")
def test_download_from_cloud_streaming_fails_closed_on_partial_directory_metadata_error(
    mock_fs_class: MagicMock,
) -> None:
    url = "s3://bucket/path/"
    fs = make_fs_mock()
    configure_partial_metadata_failure(fs, url)
    mock_fs_class.return_value = fs

    with pytest.raises(ValueError, match="Cloud directory analysis incomplete"):
        list(download_from_cloud_streaming(url, selective=False, show_progress=False))

    fs.get.assert_not_called()


@patch("fsspec.filesystem")
def test_download_from_cloud(mock_fs: MagicMock, tmp_path: Path) -> None:
    fs_meta = make_fs_mock()
    fs_meta.info.return_value = {"type": "file", "size": 1024}

    fs = make_fs_mock()
    fs.info.return_value = {"type": "file", "size": 1024}
    fs.get.side_effect = lambda _src, dst: Path(dst).write_bytes(b"data")

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

    # Note: fsspec filesystems don't need explicit cleanup according to implementation


@patch("fsspec.filesystem")
def test_download_from_cloud_reuses_cache_with_matching_etag(mock_fs: MagicMock, tmp_path: Path) -> None:
    url = "s3://bucket/model.pt"

    first_meta = make_fs_mock()
    first_meta.info.return_value = {"type": "file", "size": 4, "ETag": "etag-v1"}

    downloader = make_fs_mock()
    downloader.info.return_value = {"type": "file", "size": 4, "ETag": "etag-v1"}
    downloader.get.side_effect = lambda _src, dst: Path(dst).write_bytes(b"data")

    second_meta = make_fs_mock()
    second_meta.info.return_value = {"type": "file", "size": 4, "ETag": "etag-v1"}

    mock_fs.side_effect = [first_meta, downloader, second_meta]

    first = download_from_cloud(url, cache_dir=tmp_path, show_progress=False)
    second = download_from_cloud(url, cache_dir=tmp_path, max_size=4, show_progress=False)

    assert isinstance(first, Path)
    assert second == first
    assert first.read_bytes() == b"data"
    downloader.get.assert_called_once()
    assert mock_fs.call_count == 3


@patch("fsspec.filesystem")
def test_download_from_cloud_does_not_reuse_cached_file_over_max_size(mock_fs: MagicMock, tmp_path: Path) -> None:
    url = "s3://bucket/model.pt"

    first_meta = make_fs_mock()
    first_meta.info.return_value = {"type": "file", "size": 4, "ETag": "etag-v1"}

    first_downloader = make_fs_mock()
    first_downloader.info.return_value = {"type": "file", "size": 4, "ETag": "etag-v1"}
    first_downloader.get.side_effect = lambda _src, dst: Path(dst).write_bytes(b"data")

    second_meta = make_fs_mock()
    second_meta.info.return_value = {"type": "file", "size": 4, "ETag": "etag-v1"}

    second_downloader = make_fs_mock()
    second_downloader.info.return_value = {"type": "file", "size": 4, "ETag": "etag-v1"}
    second_downloader.open.return_value = BytesIO(b"data")

    mock_fs.side_effect = [first_meta, first_downloader, second_meta, second_downloader]

    first = download_from_cloud(url, cache_dir=tmp_path, show_progress=False)
    assert isinstance(first, Path)
    first.write_bytes(b"oversized")

    second = download_from_cloud(url, cache_dir=tmp_path, max_size=4, show_progress=False)

    assert second == first
    assert second.read_bytes() == b"data"
    second_downloader.open.assert_called_once_with(url, "rb")
    assert mock_fs.call_count == 4


@patch("fsspec.filesystem")
def test_download_from_cloud_replaces_symlinked_cached_file_with_max_size(mock_fs: MagicMock, tmp_path: Path) -> None:
    url = "s3://bucket/model.pt"

    first_meta = make_fs_mock()
    first_meta.info.return_value = {"type": "file", "size": 4, "ETag": "etag-v1"}

    first_downloader = make_fs_mock()
    first_downloader.info.return_value = {"type": "file", "size": 4, "ETag": "etag-v1"}
    first_downloader.get.side_effect = lambda _src, dst: Path(dst).write_bytes(b"data")

    second_meta = make_fs_mock()
    second_meta.info.return_value = {"type": "file", "size": 4, "ETag": "etag-v1"}

    second_downloader = make_fs_mock()
    second_downloader.info.return_value = {"type": "file", "size": 4, "ETag": "etag-v1"}
    second_downloader.open.return_value = BytesIO(b"safe")

    mock_fs.side_effect = [first_meta, first_downloader, second_meta, second_downloader]

    first = download_from_cloud(url, cache_dir=tmp_path, show_progress=False)
    assert isinstance(first, Path)
    decoy = first.parent / "decoy.bin"
    decoy.write_bytes(b"keep")
    first.unlink()
    first.symlink_to(decoy.name)

    second = download_from_cloud(url, cache_dir=tmp_path, max_size=4, show_progress=False)

    assert second == first
    assert not second.is_symlink()
    assert second.read_bytes() == b"safe"
    assert decoy.read_bytes() == b"keep"
    second_downloader.open.assert_called_once_with(url, "rb")
    assert mock_fs.call_count == 4


@patch("fsspec.filesystem")
def test_download_from_cloud_clears_stale_directory_cache(mock_fs: MagicMock, tmp_path: Path) -> None:
    url = "s3://bucket/models"
    cache = GCSCache(cache_dir=tmp_path / "cache")
    stale_dir = tmp_path / "stale"
    stale_dir.mkdir()
    (stale_dir / "old-model.bin").write_bytes(b"old")
    cache.cache_file(url, stale_dir, etag="etag-v1")

    fs_meta = make_fs_mock()
    fs_meta.info.return_value = {"type": "directory", "ETag": "etag-v2"}
    fs_meta.glob.return_value = ["s3://bucket/models/new-model.bin"]
    fs_meta.info.side_effect = [
        {"type": "directory", "ETag": "etag-v2"},
        {"type": "file", "size": 3, "ETag": "file-etag-v2"},
    ]

    fs = make_fs_mock()
    fs.info.return_value = {"type": "file", "size": 3}
    fs.get.side_effect = lambda _src, dst: Path(dst).write_bytes(b"new")

    mock_fs.side_effect = [fs_meta, fs]

    result = download_from_cloud(url, cache_dir=tmp_path / "cache", show_progress=False, selective=False)

    assert isinstance(result, Path)
    assert not (result / "old-model.bin").exists()
    assert (result / "new-model.bin").read_bytes() == b"new"


@patch("fsspec.filesystem")
def test_download_from_cloud_replaces_symlinked_directory_cache_without_touching_target(
    mock_fs: MagicMock, tmp_path: Path
) -> None:
    url = "s3://bucket/models"
    cache = GCSCache(cache_dir=tmp_path / "cache")
    stale_dir = tmp_path / "stale"
    stale_dir.mkdir()
    (stale_dir / "old-model.bin").write_bytes(b"old")
    cache.cache_file(url, stale_dir, etag="etag-v1")
    cached_path = cache.get_cached_path(url, etag="etag-v1")
    assert cached_path is not None

    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_marker = outside_dir / "keep.txt"
    outside_marker.write_text("keep", encoding="utf-8")
    (cached_path / "old-model.bin").unlink()
    cached_path.rmdir()
    cached_path.symlink_to(outside_dir, target_is_directory=True)

    fs_meta = make_fs_mock()
    fs_meta.info.return_value = {"type": "directory", "ETag": "etag-v2"}
    fs_meta.glob.return_value = ["s3://bucket/models/new-model.bin"]
    fs_meta.info.side_effect = [
        {"type": "directory", "ETag": "etag-v2"},
        {"type": "file", "size": 3, "ETag": "file-etag-v2"},
    ]

    fs = make_fs_mock()
    fs.info.return_value = {"type": "file", "size": 3}
    fs.get.side_effect = lambda _src, dst: Path(dst).write_bytes(b"new")

    mock_fs.side_effect = [fs_meta, fs]

    result = download_from_cloud(url, cache_dir=tmp_path / "cache", show_progress=False, selective=False)

    assert isinstance(result, Path)
    assert not result.is_symlink()
    assert (result / "new-model.bin").read_bytes() == b"new"
    assert outside_marker.read_text(encoding="utf-8") == "keep"


@patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
@patch("modelaudit.utils.sources.cloud_storage.check_disk_space")
@patch("fsspec.filesystem")
def test_download_from_cloud_strips_query_params_from_local_path(
    mock_fs: MagicMock, mock_disk_space: MagicMock, mock_analyze: AsyncMock, tmp_path: Path
) -> None:
    url = "s3://bucket/model.bin?X-Amz-Signature=secret"
    fs = make_fs_mock()
    fs.info.return_value = {"type": "file", "size": 1024}
    fs.get.side_effect = lambda _src, dst: Path(dst).write_bytes(b"data")
    mock_fs.return_value = fs
    mock_analyze.return_value = {
        "type": "file",
        "size": 1024,
        "name": "model.bin",
        "human_size": "1.0 KB",
        "estimated_time": "1 second",
    }
    mock_disk_space.return_value = (True, "")

    result = download_from_cloud(url, cache_dir=tmp_path, use_cache=False, show_progress=False)

    assert isinstance(result, Path)
    assert result.name == "model.bin"
    assert "X-Amz-Signature" not in str(result)
    assert "secret" not in str(result)
    assert "X-Amz-Signature" not in fs.get.call_args.args[1]
    assert "secret" not in fs.get.call_args.args[1]


def test_build_safe_local_path_preserves_signed_directory_relative_paths(tmp_path: Path) -> None:
    """Signed directory URLs should keep object-relative paths without query secrets."""
    base_url = "s3://bucket/models?X-Amz-Signature=base-secret"
    first = "s3://bucket/models/a/model.pkl?X-Amz-Signature=first-secret"
    second = "s3://bucket/models/b/model.pkl?X-Amz-Signature=second-secret"

    first_path = _build_safe_local_path(base_url, first, tmp_path)
    second_path = _build_safe_local_path(base_url, second, tmp_path)

    assert first_path == tmp_path / "a" / "model.pkl"
    assert second_path == tmp_path / "b" / "model.pkl"
    assert "X-Amz-Signature" not in str(first_path)
    assert "X-Amz-Signature" not in str(second_path)


@patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
@patch("modelaudit.utils.sources.cloud_storage.check_disk_space")
@patch("fsspec.filesystem")
def test_download_from_cloud_redacts_sensitive_url_in_errors(
    mock_fs: MagicMock, mock_disk_space: MagicMock, mock_analyze: AsyncMock, tmp_path: Path
) -> None:
    fs = make_fs_mock()
    fs.info.return_value = {"type": "file", "size": 1024}
    mock_fs.return_value = fs
    mock_analyze.return_value = {
        "type": "file",
        "size": 1024,
        "name": "model.bin",
        "human_size": "1.0 KB",
        "estimated_time": "1 second",
    }
    mock_disk_space.return_value = (False, "not enough space")

    url = "s3://bucket/model.bin?X-Amz-Signature=secret"

    with pytest.raises(Exception) as excinfo:
        download_from_cloud(url, cache_dir=tmp_path, use_cache=False, show_progress=False)

    assert "s3://bucket/model.bin" in str(excinfo.value)
    assert "X-Amz-Signature" not in str(excinfo.value)


@patch("modelaudit.utils.helpers.retry.time.sleep")
@patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
@patch("modelaudit.utils.sources.cloud_storage.check_disk_space")
@patch("fsspec.filesystem")
def test_download_from_cloud_redacts_signed_url_retry_logs(
    mock_fs: MagicMock,
    mock_disk_space: MagicMock,
    mock_analyze: MagicMock,
    mock_sleep: MagicMock,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    url = "s3://bucket/model.bin?X-Amz-Signature=secret"
    fs = make_fs_mock()
    fs.info.return_value = {"type": "file", "size": 1024}
    fs.get.side_effect = OSError(f"Forbidden while opening {url}")
    mock_fs.return_value = fs
    mock_analyze.return_value = {
        "type": "file",
        "size": 1024,
        "name": "model.bin",
        "human_size": "1.0 KB",
        "estimated_time": "1 second",
    }
    mock_disk_space.return_value = (True, "")
    caplog.set_level(logging.DEBUG, logger="modelaudit.utils.helpers.retry")

    with pytest.raises(RetryError):
        download_from_cloud(url, cache_dir=tmp_path, use_cache=False, show_progress=False)

    assert "s3://bucket/model.bin" in caplog.text
    assert "X-Amz-Signature" not in caplog.text
    assert "secret" not in caplog.text
    mock_sleep.assert_called()


@patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
def test_download_from_cloud_redacts_raw_analyzer_error_url(mock_analyze):
    url = "s3://bucket/model.bin?X-Amz-Signature=secret"
    mock_analyze.return_value = {
        "type": "unknown",
        "error": f"Forbidden while opening {url}",
    }

    with pytest.raises(ValueError) as excinfo:
        download_from_cloud(url, use_cache=False, show_progress=False)

    message = str(excinfo.value)
    assert "s3://bucket/model.bin" in message
    assert "X-Amz-Signature" not in message
    assert "secret" not in message


@pytest.mark.asyncio
async def test_download_from_cloud_async_context(tmp_path: Path) -> None:
    """download_from_cloud should work from an active event loop context."""
    fs = make_fs_mock()
    fs.info.return_value = {"type": "file", "size": 1024}
    downloaded_content = b"async test payload"

    def mock_get(remote_path: str, local_path: str, **_kwargs: object) -> None:
        Path(local_path).write_bytes(downloaded_content)

    fs.get.side_effect = mock_get

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
    fs.get.assert_called_once()
    get_args = fs.get.call_args.args
    assert get_args[0] == "s3://bucket/model.pt"
    assert Path(get_args[1]) == result
    assert result.exists()
    assert result.read_bytes() == downloaded_content


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
async def test_download_from_cloud_streaming_async_context(tmp_path: Path) -> None:
    """download_from_cloud_streaming should work from an active event loop context."""
    fs = make_fs_mock()
    fs.info.return_value = {"type": "file", "size": 1024}
    fs.get.side_effect = lambda _src, dst: Path(dst).write_bytes(b"data")
    temp_dir = tmp_path / "streaming-tempdir"

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
        patch("modelaudit.utils.sources.cloud_storage.tempfile.mkdtemp", return_value=str(temp_dir)) as mock_mkdtemp,
    ):
        streamed = list(download_from_cloud_streaming("s3://bucket/model.pt", show_progress=False))

    assert len(streamed) == 1
    streamed_path, is_last = streamed[0]
    assert streamed_path.name == "model.pt"
    assert is_last is True
    fs.get.assert_called_once()
    mock_mkdtemp.assert_called_once_with(prefix="modelaudit_stream_")
    assert not temp_dir.exists()


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

    def test_get_cloud_object_size_directory_with_size_uses_walk(self) -> None:
        """Test directory objects with a size still recurse into children."""
        fs = MagicMock()

        def info_side_effect(path: str) -> dict[str, object]:
            if path == "s3://bucket/dir/":
                return {"type": "directory", "size": 0}
            if path == "s3://bucket/dir/file1.bin":
                return {"type": "file", "size": 1024}
            if path == "s3://bucket/dir/subdir/file2.bin":
                return {"type": "file", "size": 2048}
            return {}

        fs.info.side_effect = info_side_effect
        fs.walk.return_value = [
            ("s3://bucket/dir/", ["s3://bucket/dir/subdir"], ["s3://bucket/dir/file1.bin"]),
            ("s3://bucket/dir/subdir", [], ["s3://bucket/dir/subdir/file2.bin"]),
        ]
        fs.ls.side_effect = AssertionError("ls should not be called when walk succeeds")

        size = get_cloud_object_size(fs, "s3://bucket/dir/")

        assert size == 3072
        fs.walk.assert_called_once_with("s3://bucket/dir/")
        fs.ls.assert_not_called()

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
    def test_download_with_zero_max_size_remains_uncapped(
        self,
        mock_fs_class: MagicMock,
        mock_analyze: AsyncMock,
        tmp_path: Path,
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
            cache_dir=tmp_path,
            max_size=0,
            use_cache=False,
            show_progress=False,
        )

        assert result == tmp_path / "model.bin"
        fs.get.assert_called_once_with("s3://bucket/model.bin", str(result))
        fs.open.assert_not_called()

    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    @pytest.mark.parametrize("metadata_size", [0, 1])
    def test_download_with_max_size_fails_when_size_cannot_be_determined(
        self,
        mock_fs_class: MagicMock,
        mock_analyze: AsyncMock,
        metadata_size: int,
    ) -> None:
        fs = make_fs_mock()
        fs.info.side_effect = RuntimeError("permission denied")
        mock_fs_class.return_value = fs

        mock_analyze.return_value = {
            "type": "file",
            "size": metadata_size,
            "name": "model.bin",
            "human_size": f"{metadata_size} B",
            "estimated_time": "instant",
        }

        with pytest.raises(ValueError, match="Unable to enforce maximum cloud download size"):
            download_from_cloud(
                "s3://bucket/model.bin",
                max_size=1024,
                use_cache=False,
                show_progress=False,
            )

        fs.get.assert_not_called()

    @pytest.mark.parametrize("prefix_size", [2048, "unknown"])
    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    def test_download_with_max_size_applies_to_selected_directory_files(
        self,
        mock_fs_class: MagicMock,
        mock_analyze: AsyncMock,
        tmp_path: Path,
        prefix_size: int | str,
    ) -> None:
        fs = make_fs_mock()
        fs.info.return_value = {"type": "file", "size": 512}
        fs.open.return_value = BytesIO(b"model")
        mock_fs_class.return_value = fs

        model_url = "s3://bucket/models/model.pkl"
        mock_analyze.return_value = {
            "type": "directory",
            "file_count": 2,
            "total_size": prefix_size,
            "human_size": "2.0 KB",
            "estimated_time": "instant",
            "files": [
                {"path": model_url, "name": "model.pkl", "size": 512, "human_size": "512 B"},
                {"path": "s3://bucket/models/preview.png", "name": "preview.png", "size": 1536, "human_size": "1.5 KB"},
            ],
        }

        result = download_from_cloud(
            "s3://bucket/models",
            cache_dir=tmp_path,
            max_size=1024,
            use_cache=False,
            show_progress=False,
        )

        assert result == tmp_path
        fs.info.assert_called_once_with(model_url)
        fs.open.assert_called_once_with(model_url, "rb")
        fs.get.assert_not_called()

    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    def test_download_with_max_size_rejects_selected_directory_total_over_limit(
        self,
        mock_fs_class: MagicMock,
        mock_analyze: AsyncMock,
        tmp_path: Path,
    ) -> None:
        fs = make_fs_mock()
        fs.info.return_value = {"type": "file", "size": 600}
        mock_fs_class.return_value = fs
        mock_analyze.return_value = {
            "type": "directory",
            "file_count": 2,
            "total_size": 1200,
            "human_size": "1.2 KB",
            "estimated_time": "instant",
            "files": [
                {"path": "s3://bucket/models/model-1.pkl", "name": "model-1.pkl", "size": 600, "human_size": "600 B"},
                {"path": "s3://bucket/models/model-2.pkl", "name": "model-2.pkl", "size": 600, "human_size": "600 B"},
            ],
        }

        with pytest.raises(ValueError, match="exceeds maximum allowed size"):
            download_from_cloud(
                "s3://bucket/models",
                cache_dir=tmp_path,
                max_size=1024,
                use_cache=False,
                show_progress=False,
            )

        fs.get.assert_not_called()

    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    def test_download_with_max_size_rejects_underreported_transfer_without_retry(
        self,
        mock_fs_class: MagicMock,
        mock_analyze: AsyncMock,
        tmp_path: Path,
    ) -> None:
        fs = make_fs_mock()
        fs.info.return_value = {"type": "file", "size": 4}
        fs.open.return_value = BytesIO(b"oversized")
        mock_fs_class.return_value = fs
        mock_analyze.return_value = {
            "type": "file",
            "size": 4,
            "name": "model.bin",
            "human_size": "4 B",
            "estimated_time": "instant",
        }

        with pytest.raises(ValueError, match="Cloud download exceeds maximum allowed size"):
            download_from_cloud(
                "s3://bucket/model.bin",
                cache_dir=tmp_path,
                max_size=4,
                use_cache=False,
                show_progress=False,
            )

        fs.open.assert_called_once_with("s3://bucket/model.bin", "rb")
        fs.get.assert_not_called()
        assert not (tmp_path / "model.bin").exists()

    @patch("modelaudit.utils.helpers.retry.time.sleep")
    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    def test_download_with_max_size_counts_failed_attempts_against_budget(
        self,
        mock_fs_class: MagicMock,
        mock_analyze: AsyncMock,
        mock_sleep: MagicMock,
        tmp_path: Path,
    ) -> None:
        fs = make_fs_mock()
        fs.info.return_value = {"type": "file", "size": 3}
        fs.open.side_effect = lambda *_args: _FailAfterPayload(b"abc")
        mock_fs_class.return_value = fs
        mock_analyze.return_value = {
            "type": "file",
            "size": 3,
            "name": "model.bin",
            "human_size": "3 B",
            "estimated_time": "instant",
        }

        with pytest.raises(ValueError, match="Cloud download exceeds maximum allowed size"):
            download_from_cloud(
                "s3://bucket/model.bin",
                cache_dir=tmp_path,
                max_size=4,
                use_cache=False,
                show_progress=False,
            )

        assert fs.open.call_count == 2
        mock_sleep.assert_called_once()
        assert not (tmp_path / "model.bin").exists()

    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    def test_download_with_max_size_rejects_late_object_size_over_limit(
        self,
        mock_fs_class: MagicMock,
        mock_analyze: AsyncMock,
    ) -> None:
        fs = make_fs_mock()
        fs.info.return_value = {"type": "file", "size": 2048}
        mock_fs_class.return_value = fs

        mock_analyze.return_value = {
            "type": "file",
            "size": 0,
            "name": "model.bin",
            "human_size": "0 B",
            "estimated_time": "instant",
        }

        with pytest.raises(ValueError, match="exceeds maximum allowed size"):
            download_from_cloud(
                "s3://bucket/model.bin",
                max_size=1024,
                use_cache=False,
                show_progress=False,
            )

        fs.get.assert_not_called()

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

    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    def test_streaming_download_with_max_size_fails_when_size_cannot_be_determined(
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

        with pytest.raises(ValueError, match="Unable to enforce maximum cloud download size"):
            list(download_from_cloud_streaming("s3://bucket/model.bin", max_size=1024, show_progress=False))

        fs.get.assert_not_called()

    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    def test_streaming_download_with_zero_max_size_remains_uncapped(
        self,
        mock_fs_class: MagicMock,
        mock_analyze: AsyncMock,
    ) -> None:
        fs = make_fs_mock()
        mock_fs_class.return_value = fs
        mock_analyze.return_value = {
            "type": "file",
            "size": 0,
            "name": "model.bin",
            "human_size": "0 B",
            "estimated_time": "instant",
        }

        streamed = list(download_from_cloud_streaming("s3://bucket/model.bin", max_size=0, show_progress=False))

        assert len(streamed) == 1
        fs.get.assert_called_once()
        fs.open.assert_not_called()

    @pytest.mark.parametrize("prefix_size", [2048, "unknown"])
    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    def test_streaming_download_with_max_size_applies_to_selected_directory_files(
        self,
        mock_fs_class: MagicMock,
        mock_analyze: AsyncMock,
        prefix_size: int | str,
    ) -> None:
        fs = make_fs_mock()
        fs.info.return_value = {"type": "file", "size": 512}
        fs.open.return_value = BytesIO(b"model")
        mock_fs_class.return_value = fs

        model_url = "s3://bucket/models/model.pkl"
        mock_analyze.return_value = {
            "type": "directory",
            "file_count": 2,
            "total_size": prefix_size,
            "human_size": "2.0 KB",
            "estimated_time": "instant",
            "files": [
                {"path": model_url, "name": "model.pkl", "size": 512, "human_size": "512 B"},
                {"path": "s3://bucket/models/preview.png", "name": "preview.png", "size": 1536, "human_size": "1.5 KB"},
            ],
        }

        streamed = list(
            download_from_cloud_streaming(
                "s3://bucket/models",
                max_size=1024,
                show_progress=False,
            )
        )

        assert len(streamed) == 1
        fs.info.assert_called_once_with(model_url)
        fs.open.assert_called_once_with(model_url, "rb")
        fs.get.assert_not_called()

    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    def test_streaming_download_with_max_size_rejects_underreported_transfer_without_retry(
        self,
        mock_fs_class: MagicMock,
        mock_analyze: AsyncMock,
    ) -> None:
        fs = make_fs_mock()
        fs.info.return_value = {"type": "file", "size": 4}
        fs.open.return_value = BytesIO(b"oversized")
        mock_fs_class.return_value = fs
        mock_analyze.return_value = {
            "type": "file",
            "size": 4,
            "name": "model.bin",
            "human_size": "4 B",
            "estimated_time": "instant",
        }

        with pytest.raises(ValueError, match="Cloud download exceeds maximum allowed size"):
            list(download_from_cloud_streaming("s3://bucket/model.bin", max_size=4, show_progress=False))

        fs.open.assert_called_once_with("s3://bucket/model.bin", "rb")
        fs.get.assert_not_called()

    @patch("modelaudit.utils.helpers.retry.time.sleep")
    @patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
    @patch("fsspec.filesystem")
    def test_streaming_download_with_max_size_counts_failed_attempts_against_budget(
        self,
        mock_fs_class: MagicMock,
        mock_analyze: AsyncMock,
        mock_sleep: MagicMock,
    ) -> None:
        fs = make_fs_mock()
        fs.info.return_value = {"type": "file", "size": 3}
        fs.open.side_effect = lambda *_args: _FailAfterPayload(b"abc")
        mock_fs_class.return_value = fs
        mock_analyze.return_value = {
            "type": "file",
            "size": 3,
            "name": "model.bin",
            "human_size": "3 B",
            "estimated_time": "instant",
        }

        with pytest.raises(ValueError, match="Cloud download exceeds maximum allowed size"):
            list(download_from_cloud_streaming("s3://bucket/model.bin", max_size=4, show_progress=False))

        assert fs.open.call_count == 2
        mock_sleep.assert_called_once()


class TestCloudCacheSafety:
    """Regression tests for cloud cache boundary enforcement."""

    def test_cache_file_does_not_trust_prefix_sibling_path(self, tmp_path: Path) -> None:
        """Cacheing a sibling path should copy into cache, not trust prefix similarity."""
        cache = GCSCache(cache_dir=tmp_path / "cache")
        sibling_dir = tmp_path / "cache_evil"
        sibling_dir.mkdir(parents=True, exist_ok=True)
        source_file = sibling_dir / "artifact.bin"
        source_file.write_bytes(b"artifact")

        url = "s3://bucket/model.bin"
        cache.cache_file(url, source_file, etag="etag-v1")

        cached_path = cache.get_cached_path(url, etag="etag-v1")
        assert cached_path is not None
        assert cached_path.resolve() != source_file.resolve()
        assert cached_path.resolve().is_relative_to(cache.cache_dir.resolve())
        assert source_file.exists()

    def test_cache_without_etag_is_stale_miss(self, tmp_path: Path) -> None:
        """Cache entries without validators must not be reused as fresh remote objects."""
        cache = GCSCache(cache_dir=tmp_path / "cache")
        source_file = tmp_path / "artifact.bin"
        source_file.write_bytes(b"artifact")
        url = "s3://bucket/model.bin"

        cache.cache_file(url, source_file)

        assert cache.get_cached_path(url) is None
        assert cache.get_cached_path(url, etag="etag-v1") is None

    def test_cache_with_matching_etag_hits(self, tmp_path: Path) -> None:
        cache = GCSCache(cache_dir=tmp_path / "cache")
        source_file = tmp_path / "artifact.bin"
        source_file.write_bytes(b"artifact")
        url = "s3://bucket/model.bin"

        cache.cache_file(url, source_file, etag="etag-v1")

        cached_path = cache.get_cached_path(url, etag="etag-v1")

        assert cached_path is not None
        assert cached_path.read_bytes() == b"artifact"

    def test_cache_with_mismatched_etag_misses(self, tmp_path: Path) -> None:
        cache = GCSCache(cache_dir=tmp_path / "cache")
        source_file = tmp_path / "artifact.bin"
        source_file.write_bytes(b"artifact")
        url = "s3://bucket/model.bin"

        cache.cache_file(url, source_file, etag="etag-v1")

        assert cache.get_cached_path(url, etag="etag-v2") is None

    def test_legacy_cache_without_etag_is_stale_miss_and_migrates_metadata(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        cached_file = cache_dir / "aa" / "bb" / "model.bin"
        cached_file.parent.mkdir(parents=True)
        cached_file.write_bytes(b"artifact")
        signed_url = (
            "https://user:pass@bucket.s3.amazonaws.com/path/model.bin"
            "?X-Amz-Credential=secret&X-Amz-Signature=sig#fragment"
        )

        cache = GCSCache(cache_dir=cache_dir)
        cache_key = cache.get_cache_key(signed_url)
        cache.metadata_file.write_text(
            json.dumps(
                {
                    cache_key: {
                        "url": signed_url,
                        "path": str(cached_file),
                        "size": cached_file.stat().st_size,
                        "cached_at": "2026-01-01T00:00:00",
                        "last_accessed": "2026-01-01T00:00:00",
                    }
                }
            ),
            encoding="utf-8",
        )

        cache = GCSCache(cache_dir=cache_dir)

        assert cache.get_cached_path(signed_url) is None
        raw_metadata = cache.metadata_file.read_text(encoding="utf-8")
        metadata = json.loads(raw_metadata)
        entry = metadata[cache_key]
        assert "url" not in entry
        assert entry["url_sha256"] == cache_key
        assert entry["url_display"] == "https://bucket.s3.amazonaws.com/path/model.bin"
        assert "X-Amz-Credential" not in raw_metadata
        assert "X-Amz-Signature" not in raw_metadata
        assert "user:pass" not in raw_metadata

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

    def test_cache_metadata_redacts_signed_urls_and_uses_private_permissions(self, tmp_path: Path) -> None:
        """Cache metadata should not persist raw signed URL credentials."""
        cache = GCSCache(cache_dir=tmp_path / "cache")
        source_file = tmp_path / "artifact.bin"
        source_file.write_bytes(b"artifact")
        signed_url = (
            "https://user:pass@bucket.s3.amazonaws.com/path/model.bin"
            "?X-Amz-Credential=secret&X-Amz-Signature=sig#fragment"
        )

        cache.cache_file(signed_url, source_file, etag="etag-value")

        raw_metadata = cache.metadata_file.read_text(encoding="utf-8")
        metadata = json.loads(raw_metadata)
        entry = metadata[cache.get_cache_key(signed_url)]
        assert "url" not in entry
        assert entry["url_sha256"] == cache.get_cache_key(signed_url)
        assert entry["url_display"] == "https://bucket.s3.amazonaws.com/path/model.bin"
        assert "X-Amz-Credential" not in raw_metadata
        assert "X-Amz-Signature" not in raw_metadata
        assert "user:pass" not in raw_metadata
        assert "fragment" not in raw_metadata
        if os.name != "nt":
            assert stat.S_IMODE(cache.metadata_file.stat().st_mode) == 0o600


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


def test_filter_scannable_files_recognizes_pdiparams() -> None:
    files = [{"path": "model.pdiparams"}, {"path": "notes.csv"}, {"path": "preview.png"}]

    assert filter_scannable_files(files) == [{"path": "model.pdiparams"}]


def test_filter_scannable_files_uses_registry_extensions():
    files = [{"path": "model.nemo"}, {"path": "model.rds"}, {"path": "README.md"}, {"path": "notes.csv"}]
    assert filter_scannable_files(files) == files[:3]


def test_filter_scannable_files_handles_tar_gz_and_tgz():
    files = [{"path": "archive.tar.gz"}, {"path": "weights.tgz"}]
    assert filter_scannable_files(files) == files
