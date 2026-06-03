import importlib
import io
import logging
import os
import struct
import subprocess
import sys
import tarfile
from collections.abc import Iterator
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

import pytest
import requests

from modelaudit.scanner_selection import scanner_selection_config_from_inputs
from modelaudit.utils.file.detection import PROTOBUF_MODEL_CANDIDATE_FORMAT
from modelaudit.utils.sources.jfrog import (
    _scanner_ids_for_detected_jfrog_format,
    detect_jfrog_target_type,
    download_artifact,
    download_jfrog_folder,
    filter_scannable_files,
    format_size,
    get_storage_api_url,
    is_jfrog_url,
    list_jfrog_folder_contents,
    redact_jfrog_url_for_display,
)
from tests.helpers import create_mock_coreml, create_mock_mxnet_symbol, create_mock_onnx


class _FakeStreamingResponse:
    def __init__(self, payload: bytes, *, status_code: int = 200, headers: dict[str, str] | None = None) -> None:
        self.payload = payload
        self.status_code = status_code
        self.headers = headers or {}
        self.closed = False

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            error_response = MagicMock(spec=requests.Response)
            error_response.status_code = self.status_code
            raise requests.exceptions.HTTPError(response=error_response)
        return None

    def iter_content(self, chunk_size: int = 1) -> Iterator[bytes]:
        for offset in range(0, len(self.payload), chunk_size):
            yield self.payload[offset : offset + chunk_size]

    def close(self) -> None:
        self.closed = True


def _encode_proto_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("protobuf varints cannot encode negative values")

    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _build_tensorflow_remote_route_payloads() -> dict[str, bytes]:
    """Build minimal vendored-proto TensorFlow fixtures without importing TensorFlow itself."""
    import modelaudit.protos  # noqa: F401

    meta_graph_pb2 = importlib.import_module("tensorflow.core.protobuf.meta_graph_pb2")
    saved_model_pb2 = importlib.import_module("tensorflow.core.protobuf.saved_model_pb2")

    metagraph = meta_graph_pb2.MetaGraphDef()
    metagraph_node = metagraph.graph_def.node.add()
    metagraph_node.name = "pyfunc_node"
    metagraph_node.op = "PyFunc"

    saved_model = saved_model_pb2.SavedModel()
    saved_model.saved_model_schema_version = 1
    saved_node = saved_model.meta_graphs.add().graph_def.node.add()
    saved_node.name = "pyfunc_node"
    saved_node.op = "PyFunc"

    return {
        "metagraph.payload": cast(bytes, metagraph.SerializeToString()),
        "savedmodel.payload": cast(bytes, saved_model.SerializeToString()),
    }


class TestJFrogURLDetection:
    def test_valid_jfrog_urls(self):
        valid_urls = [
            "https://company.jfrog.io/artifactory/repo/model.bin",
            "http://localhost/artifactory/libs-release/model.pt",
            "http://127.0.0.1/artifactory/libs-release/model.pt",
        ]
        for url in valid_urls:
            assert is_jfrog_url(url)

    def test_invalid_jfrog_urls(self):
        invalid_urls = [
            "https://example.com/model",
            "https://evil.example/artifactory/repo/model.bin",
            "https://my-jfrog.com/artifactory/libs-release/model.pt",
            "http://attacker.jfrog.io/artifactory/repo/model.bin",
            "hf://model",
            "",
        ]
        for url in invalid_urls:
            assert not is_jfrog_url(url)

    def test_allowlisted_self_hosted_jfrog_urls(self, monkeypatch):
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "my-jfrog.com,artifacts.internal")

        assert is_jfrog_url("https://my-jfrog.com/artifactory/libs-release/model.pt")
        assert is_jfrog_url("https://artifacts.internal/artifactory/ml/model.pkl")


class TestJFrogDownload:
    def test_redact_jfrog_url_for_display(self) -> None:
        raw_url = "https://user:leaky-pass@company.jfrog.io/artifactory/repo/model.bin?token=leaky-token#fragment"

        redacted = redact_jfrog_url_for_display(raw_url)

        assert redacted == "https://<credentials-redacted>@company.jfrog.io/artifactory/repo/model.bin"
        assert "leaky-pass" not in redacted
        assert "leaky-token" not in redacted
        assert "fragment" not in redacted

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_success(self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Mock successful response
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.iter_content.return_value = [b"data"]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        result = download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path, api_token="test-token"
        )
        assert result.exists()
        assert result.read_bytes() == b"data"

        # Verify the request was made with proper headers
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert "X-JFrog-Art-Api" in call_args[1]["headers"]
        assert call_args[1]["headers"]["X-JFrog-Art-Api"] == "test-token"

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_rejects_cross_origin_redirect(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Full artifact downloads must not follow an off-origin redirect."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        redirect_response = _FakeStreamingResponse(
            b"",
            status_code=302,
            headers={"Location": "https://evil.example/artifacts/model.bin"},
        )
        mock_get.return_value = redirect_response

        with pytest.raises(Exception, match="Refusing cross-origin JFrog redirect"):
            download_artifact(
                "https://company.jfrog.io/artifactory/repo/model.bin",
                cache_dir=tmp_path,
                api_token="test-token",
            )

        assert mock_get.call_count == 1
        assert redirect_response.closed is True
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_follows_same_origin_redirect(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Full artifact downloads may follow a bounded same-origin redirect."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        redirect_response = _FakeStreamingResponse(b"", status_code=307, headers={"Location": "model.bin?download=1"})
        final_response = _FakeStreamingResponse(b"data")
        mock_get.side_effect = [redirect_response, final_response]

        result = download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            cache_dir=tmp_path,
            api_token="test-token",
        )

        assert result.read_bytes() == b"data"
        assert mock_get.call_args_list[1].args[0] == ("https://company.jfrog.io/artifactory/repo/model.bin?download=1")
        assert mock_get.call_args_list[1].kwargs["headers"]["X-JFrog-Art-Api"] == "test-token"
        assert redirect_response.closed is True
        assert final_response.closed is True

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_follows_default_port_same_origin_redirect(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Default-port redirects should be treated as the same effective origin."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        redirected_url = "https://company.jfrog.io:443/artifactory/repo/model.bin?download=1"
        redirect_response = _FakeStreamingResponse(b"", status_code=302, headers={"Location": redirected_url})
        final_response = _FakeStreamingResponse(b"data")
        mock_get.side_effect = [redirect_response, final_response]

        result = download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            cache_dir=tmp_path,
            api_token="test-token",
        )

        assert result.read_bytes() == b"data"
        assert mock_get.call_args_list[1].args[0] == redirected_url
        assert redirect_response.closed is True
        assert final_response.closed is True

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_closes_response_before_parsing_malformed_redirect(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Malformed redirect targets must not leak streamed responses."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        redirect_response = _FakeStreamingResponse(b"", status_code=302, headers={"Location": "https://[::1"})
        mock_get.return_value = redirect_response

        with pytest.raises(Exception, match="Failed to download artifact"):
            download_artifact(
                "https://company.jfrog.io/artifactory/repo/model.bin",
                cache_dir=tmp_path,
                api_token="test-token",
            )

        assert redirect_response.closed is True
        assert not any(tmp_path.iterdir())

    def test_invalid_url(self):
        with pytest.raises(ValueError):
            download_artifact("https://example.com/model")

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.shutil.rmtree")
    def test_download_cleanup_on_failure(self, mock_rmtree, mock_get):
        # Mock request failure
        mock_get.side_effect = Exception("fail")

        with pytest.raises(Exception):  # noqa: B017 - generic exception from helper
            download_artifact("https://company.jfrog.io/artifactory/repo/model.bin")
        mock_rmtree.assert_called()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_authentication_methods(self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test different authentication methods."""
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.iter_content.return_value = [b"data"]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        # Test API token
        download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path, api_token="test-api-token"
        )
        call_args = mock_get.call_args
        assert call_args[1]["headers"]["X-JFrog-Art-Api"] == "test-api-token"

        # Test access token
        download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path, access_token="test-access-token"
        )
        call_args = mock_get.call_args
        assert call_args[1]["headers"]["Authorization"] == "Bearer test-access-token"

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_explicit_access_token_precedes_environment_api_token(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Explicit caller credentials should not be shadowed by ambient env tokens."""
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.iter_content.return_value = [b"data"]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        monkeypatch.setenv("JFROG_API_TOKEN", "env-api-token")

        download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            cache_dir=tmp_path,
            access_token="explicit-access-token",
        )

        call_args = mock_get.call_args
        assert call_args[1]["headers"] == {"Authorization": "Bearer explicit-access-token"}

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_environment_variables(self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test authentication via environment variables."""
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.iter_content.return_value = [b"data"]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        # Test JFROG_API_TOKEN
        monkeypatch.setenv("JFROG_API_TOKEN", "env-api-token")
        download_artifact("https://company.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path)
        call_args = mock_get.call_args
        assert call_args[1]["headers"]["X-JFrog-Art-Api"] == "env-api-token"

        # Test JFROG_ACCESS_TOKEN (clear API token first)
        monkeypatch.delenv("JFROG_API_TOKEN", raising=False)
        monkeypatch.setenv("JFROG_ACCESS_TOKEN", "env-access-token")
        download_artifact("https://company.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path)
        call_args = mock_get.call_args
        assert call_args[1]["headers"]["Authorization"] == "Bearer env-access-token"

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_unconfigured_jfrog_host_receives_no_credentials(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Credentials should not be sent to arbitrary JFrog SaaS tenants."""
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.iter_content.return_value = [b"data"]
        monkeypatch.setenv("JFROG_API_TOKEN", "env-api-token")
        monkeypatch.setenv("JFROG_ACCESS_TOKEN", "env-access-token")

        with caplog.at_level(logging.WARNING, logger="modelaudit.utils.sources.jfrog"):
            download_artifact(
                "https://attacker.jfrog.io/artifactory/repo/model.bin",
                cache_dir=tmp_path,
                api_token="explicit-api-token",
                access_token="explicit-access-token",
            )

        call_args = mock_get.call_args
        assert call_args[1]["headers"] == {}
        assert "Skipping JFrog credentials" in caplog.text
        assert "explicit-api-token" not in caplog.text
        assert "env-api-token" not in caplog.text

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_http_jfrog_saas_url_is_rejected_before_credentials(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Non-local HTTP JFrog URLs must not receive credentials."""
        monkeypatch.setenv("JFROG_API_TOKEN", "env-api-token")

        with pytest.raises(ValueError, match="Not a JFrog URL"):
            download_artifact("http://attacker.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path)

        mock_get.assert_not_called()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_storage_api_skips_credentials_for_unconfigured_host(
        self, mock_get: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Storage API probing should share the same credential forwarding policy."""
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"repo": "public-repo", "path": "/model.bin", "size": 12}
        monkeypatch.setenv("JFROG_API_TOKEN", "env-api-token")

        result = detect_jfrog_target_type(
            "https://attacker.jfrog.io/artifactory/repo/model.bin",
            api_token="explicit-api-token",
        )

        assert result["type"] == "file"
        assert mock_get.call_args[1]["headers"] == {}

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_storage_api_explicit_access_token_precedes_environment_api_token(
        self, mock_get: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Explicit Storage API access tokens should not be shadowed by env API tokens."""
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"repo": "repo", "path": "/model.bin", "size": 12}
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        monkeypatch.setenv("JFROG_API_TOKEN", "env-api-token")

        result = detect_jfrog_target_type(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            access_token="explicit-access-token",
        )

        assert result["type"] == "file"
        assert mock_get.call_args[1]["headers"] == {"Authorization": "Bearer explicit-access-token"}

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_no_authentication(self, mock_get, tmp_path, caplog):
        """Test anonymous access when no authentication is provided."""
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.iter_content.return_value = [b"data"]

        with caplog.at_level(logging.WARNING, logger="modelaudit.utils.sources.jfrog"):
            download_artifact("https://company.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path)

        assert "No JFrog authentication provided. Attempting anonymous access." in caplog.text

        # Verify request was made without auth headers
        call_args = mock_get.call_args
        assert not call_args[1]["headers"]  # Empty headers dict

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_error_redacts_sensitive_url(self, mock_get, tmp_path):
        """Download errors should not expose URL credentials or query tokens."""
        mock_response = mock_get.return_value
        mock_error_response = MagicMock(spec=requests.Response)
        mock_error_response.status_code = 401
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_error_response)
        raw_url = "https://user:leaky-pass@company.jfrog.io/artifactory/repo/model.bin?token=leaky-token"

        with pytest.raises(Exception) as excinfo:
            download_artifact(raw_url, cache_dir=tmp_path)

        message = str(excinfo.value)
        assert "https://<credentials-redacted>@company.jfrog.io/artifactory/repo/model.bin" in message
        assert "user:leaky-pass" not in message
        assert "leaky-token" not in message
        assert "?token=" not in message
        assert mock_get.call_args[0][0] == raw_url

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_import_does_not_load_dotenv_from_cwd(self, mock_get, tmp_path):
        """Importing the JFrog helper must not mutate env from an untrusted cwd."""
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.iter_content.return_value = [b"data"]

        repo_root = Path(__file__).resolve().parents[2]
        dotenv_dir = tmp_path / "dotenv-cwd"
        dotenv_dir.mkdir()
        (dotenv_dir / ".env").write_text("HTTP_PROXY=http://attacker.invalid:8080\n", encoding="utf-8")

        env = os.environ.copy()
        env.pop("HTTP_PROXY", None)
        env.pop("HTTPS_PROXY", None)
        pythonpath = env.get("PYTHONPATH")
        env["PYTHONPATH"] = str(repo_root) if not pythonpath else f"{repo_root}{os.pathsep}{pythonpath}"

        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                ("import os; import modelaudit.utils.sources.jfrog; print(os.environ.get('HTTP_PROXY'))"),
            ],
            cwd=dotenv_dir,
            capture_output=True,
            check=True,
            env=env,
            text=True,
        )

        assert completed.stdout.strip() == "None"


class TestJFrogStorageAPI:
    """Test Storage API URL conversion and folder operations."""

    def test_get_storage_api_url(self):
        """Test conversion of artifact URLs to Storage API URLs."""
        test_cases = [
            (
                "https://company.jfrog.io/artifactory/repo/model.pkl",
                "https://company.jfrog.io/artifactory/api/storage/repo/model.pkl",
            ),
            (
                "https://my-jfrog.com/artifactory/libs-release/models/",
                "https://my-jfrog.com/artifactory/api/storage/libs-release/models/",
            ),
            (
                "http://localhost:8081/artifactory/local-repo/path/to/file.bin",
                "http://localhost:8081/artifactory/api/storage/local-repo/path/to/file.bin",
            ),
        ]

        for artifact_url, expected_storage_url in test_cases:
            result = get_storage_api_url(artifact_url)
            assert result == expected_storage_url

    def test_get_storage_api_url_invalid(self):
        """Test error handling for invalid URLs."""
        invalid_urls = [
            "https://example.com/file.pkl",  # No artifactory in path
            "not-a-url",  # Invalid URL format
        ]

        for url in invalid_urls:
            with pytest.raises(ValueError):
                get_storage_api_url(url)

    def test_format_size(self):
        """Test human-readable size formatting."""
        test_cases = [
            (0, "0.0 B"),
            (512, "512.0 B"),
            (1024, "1.0 KB"),
            (1536, "1.5 KB"),
            (1048576, "1.0 MB"),
            (1073741824, "1.0 GB"),
        ]

        for size_bytes, expected in test_cases:
            result = format_size(size_bytes)
            assert result == expected

    def test_filter_scannable_files(self):
        """Test filtering of files to registry-backed scanner extensions."""
        files = [
            {"name": "model.pkl", "path": "/repo/model.pkl", "size": 1024},
            {"name": "data.txt", "path": "/repo/data.txt", "size": 512},
            {"name": "model.pt", "path": "/repo/model.pt", "size": 2048},
            {"name": "config.json", "path": "/repo/config.json", "size": 256},
            {"name": "weights.safetensors", "path": "/repo/weights.safetensors", "size": 4096},
        ]

        scannable = filter_scannable_files(files)

        assert len(scannable) == 5
        scannable_names = {f["name"] for f in scannable}
        assert scannable_names == {"model.pkl", "data.txt", "model.pt", "config.json", "weights.safetensors"}


class TestJFrogFolderDetection:
    """Test JFrog folder detection and listing."""

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_detect_jfrog_target_type_file(self, mock_get, tmp_path):
        """Test detection of JFrog file targets."""
        # Mock response for a file
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "repo": "my-repo",
            "path": "/model.pkl",
            "size": 1024,
            "lastModified": "2024-01-01T00:00:00.000Z",
        }

        result = detect_jfrog_target_type("https://company.jfrog.io/artifactory/repo/model.pkl", api_token="test-token")

        assert result["type"] == "file"
        assert result["size"] == 1024
        assert result["repo"] == "my-repo"

        # Verify Storage API URL was called
        mock_get.assert_called_once()
        called_url = mock_get.call_args[0][0]
        assert "api/storage" in called_url

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_detect_jfrog_target_type_folder(self, mock_get):
        """Test detection of JFrog folder targets."""
        # Mock response for a folder with children
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "repo": "my-repo",
            "path": "/models",
            "children": [
                {"uri": "/model1.pkl", "folder": False, "size": 1024},
                {"uri": "/subfolder", "folder": True},
                {"uri": "/model2.pt", "folder": False, "size": 2048},
            ],
        }

        result = detect_jfrog_target_type("https://company.jfrog.io/artifactory/repo/models/", api_token="test-token")

        assert result["type"] == "folder"
        assert len(result["children"]) == 3
        assert result["repo"] == "my-repo"

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_detect_jfrog_target_type_auth_error(self, mock_get):
        """Test handling of authentication errors."""
        mock_response = mock_get.return_value
        from unittest.mock import Mock

        mock_error_response = Mock(spec=requests.Response)
        mock_error_response.status_code = 401
        http_error = requests.exceptions.HTTPError(response=mock_error_response)
        mock_response.raise_for_status.side_effect = http_error

        with pytest.raises(Exception, match="Authentication failed"):
            detect_jfrog_target_type("https://company.jfrog.io/artifactory/repo/model.pkl")

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_detect_jfrog_target_type_not_found(self, mock_get):
        """Test handling of 404 errors."""
        mock_response = mock_get.return_value
        from unittest.mock import Mock

        mock_error_response = Mock(spec=requests.Response)
        mock_error_response.status_code = 404
        http_error = requests.exceptions.HTTPError(response=mock_error_response)
        mock_response.raise_for_status.side_effect = http_error

        with pytest.raises(Exception, match="not found"):
            detect_jfrog_target_type("https://company.jfrog.io/artifactory/repo/nonexistent.pkl")


class TestJFrogFolderListing:
    """Test JFrog folder content listing."""

    @patch("modelaudit.utils.sources.jfrog.detect_jfrog_target_type")
    def test_list_jfrog_folder_contents_simple(self, mock_detect):
        """Test listing contents of a simple folder."""
        # Mock folder with files
        mock_detect.return_value = {
            "type": "folder",
            "children": [
                {"uri": "/model1.pkl", "folder": False, "size": 1024},
                {"uri": "/model2.pt", "folder": False, "size": 2048},
                {"uri": "/readme.txt", "folder": False, "size": 256},
            ],
        }

        files = list_jfrog_folder_contents(
            "https://company.jfrog.io/artifactory/repo/models/",
            api_token="test-token",
            recursive=False,
            selective=True,  # Filter to only scannable files
        )

        # Text files have a registry-backed scanner and remain in selective downloads.
        assert len(files) == 3
        file_names = {f["name"] for f in files}
        assert file_names == {"model1.pkl", "model2.pt", "readme.txt"}

        # Check file details
        pkl_file = next(f for f in files if f["name"] == "model1.pkl")
        assert pkl_file["size"] == 1024
        assert pkl_file["human_size"] == "1.0 KB"

    @patch("modelaudit.utils.sources.jfrog.detect_jfrog_target_type")
    def test_list_jfrog_folder_contents_recursive(self, mock_detect):
        """Test recursive listing of nested folders."""

        def mock_detect_side_effect(url, *args, **kwargs):
            if url.endswith("models/") or url.endswith("models"):
                return {
                    "type": "folder",
                    "children": [
                        {"uri": "/model1.pkl", "folder": False, "size": 1024},
                        {"uri": "/pytorch", "folder": True},
                    ],
                }
            elif url.endswith("/pytorch") or url.endswith("pytorch"):
                return {"type": "folder", "children": [{"uri": "/model2.pt", "folder": False, "size": 2048}]}
            else:
                return {"type": "file"}

        mock_detect.side_effect = mock_detect_side_effect

        files = list_jfrog_folder_contents(
            "https://company.jfrog.io/artifactory/repo/models/", api_token="test-token", recursive=True, selective=False
        )

        # Should find files in both root and subfolder (before filtering)
        assert len(files) == 2
        file_names = {f["name"] for f in files}
        assert file_names == {"model1.pkl", "model2.pt"}

        # Test with filtering enabled
        filtered_files = list_jfrog_folder_contents(
            "https://company.jfrog.io/artifactory/repo/models/", api_token="test-token", recursive=True, selective=True
        )
        # Should still find the same files since they are scannable model files
        assert len(filtered_files) == 2

    @patch("modelaudit.utils.sources.jfrog.detect_jfrog_target_type")
    def test_list_jfrog_folder_contents_not_folder(self, mock_detect):
        """Test error when trying to list contents of a file."""
        mock_detect.return_value = {"type": "file", "size": 1024}

        with pytest.raises(ValueError, match="not a JFrog folder"):
            list_jfrog_folder_contents("https://company.jfrog.io/artifactory/repo/model.pkl")

    @patch("modelaudit.utils.sources.jfrog.detect_jfrog_target_type")
    def test_list_jfrog_folder_contents_propagates_subfolder_error(self, mock_detect: MagicMock) -> None:
        """Listing must fail closed when a subfolder API call errors."""

        def mock_detect_side_effect(url: str, *args: object, **kwargs: object) -> dict:
            if url.endswith("models/") or url.endswith("models"):
                return {
                    "type": "folder",
                    "children": [
                        {"uri": "/model1.pkl", "folder": False, "size": 1024},
                        {"uri": "/subdir", "folder": True},
                    ],
                }
            if "subdir" in url:
                raise Exception("network timeout")
            return {"type": "file", "size": 0, "path": "", "repo": ""}

        mock_detect.side_effect = mock_detect_side_effect

        with pytest.raises(Exception, match="network timeout"):
            list_jfrog_folder_contents(
                "https://company.jfrog.io/artifactory/repo/models/",
                api_token="test-token",
                recursive=True,
                selective=False,
            )

    @patch("modelaudit.utils.sources.jfrog.detect_jfrog_target_type")
    def test_list_jfrog_folder_contents_raises_on_max_depth(self, mock_detect: MagicMock) -> None:
        """Listing must fail closed when recursion depth is exceeded."""

        def mock_detect_side_effect(url: str, *args: object, **kwargs: object) -> dict:
            # Every URL returns a folder with one subfolder to force deep recursion
            return {
                "type": "folder",
                "children": [{"uri": "/deeper", "folder": True}],
            }

        mock_detect.side_effect = mock_detect_side_effect

        with pytest.raises(Exception, match="Maximum recursion depth"):
            list_jfrog_folder_contents(
                "https://company.jfrog.io/artifactory/repo/models/",
                api_token="test-token",
                recursive=True,
                selective=False,
            )

    @patch("modelaudit.utils.sources.jfrog.detect_jfrog_target_type")
    def test_list_jfrog_folder_contents_raises_on_non_folder_subpath(self, mock_detect: MagicMock) -> None:
        """Listing must fail closed when a supposed subfolder resolves to a non-folder."""

        def mock_detect_side_effect(url: str, *args: object, **kwargs: object) -> dict:
            if url.endswith("models/") or url.endswith("models"):
                return {
                    "type": "folder",
                    "children": [{"uri": "/subdir", "folder": True}],
                }
            if "subdir" in url:
                return {"type": "file", "size": 0, "path": "subdir", "repo": "repo"}
            return {"type": "file", "size": 0, "path": "", "repo": ""}

        mock_detect.side_effect = mock_detect_side_effect

        with pytest.raises(Exception, match="Expected JFrog folder while listing"):
            list_jfrog_folder_contents(
                "https://company.jfrog.io/artifactory/repo/models/",
                api_token="test-token",
                recursive=True,
                selective=False,
            )


class TestJFrogFolderDownload:
    """Test JFrog folder download functionality."""

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_success(self, mock_list, mock_download, tmp_path):
        """Test successful folder download."""
        # Mock folder contents
        mock_list.return_value = [
            {
                "name": "model1.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/model1.pkl",
                "size": 1024,
                "human_size": "1.0 KB",
            },
            {
                "name": "model2.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model2.pt",
                "size": 2048,
                "human_size": "2.0 KB",
            },
        ]

        # Mock individual file downloads
        def mock_download_side_effect(url, cache_dir, **kwargs):
            filename = Path(url).name
            downloaded_file = cache_dir / filename
            downloaded_file.write_bytes(b"mock file content")
            return downloaded_file

        mock_download.side_effect = mock_download_side_effect

        result_dir = download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/", cache_dir=tmp_path, api_token="test-token"
        )

        assert result_dir == tmp_path
        assert len(list(tmp_path.glob("**/*"))) >= 2  # At least 2 files downloaded

    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_no_files(self, mock_list):
        """Test error when no scannable files found."""
        mock_list.return_value = []  # No files after filtering

        with pytest.raises(ValueError, match="No scannable model files found"):
            download_jfrog_folder("https://company.jfrog.io/artifactory/repo/empty-folder/")

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_selective_includes_content_routed_skipped_file(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Selective downloads should include renamed model artifacts found by bounded content sniffing."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        tflite_url = "https://company.jfrog.io/artifactory/repo/models/evil.payload"
        proto0_pickle_url = "https://company.jfrog.io/artifactory/repo/models/pickle.payload"
        safetensors_url = "https://company.jfrog.io/artifactory/repo/models/weights.jpg"
        unknown_size_safetensors_url = "https://company.jfrog.io/artifactory/repo/models/large-weights.jpg"
        preview_url = "https://company.jfrog.io/artifactory/repo/models/preview.png"
        tflite_payload = b"\x08\x00\x00\x00TFL3" + b"\x00" * 16
        proto0_pickle_payload = b"cposix\nsystem\n(S'echo pwned'\ntR."
        safetensors_header = b'{"tensor":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
        safetensors_payload = struct.pack("<Q", len(safetensors_header)) + safetensors_header + b"\x00\x00\x00\x00"
        large_safetensors_probe = struct.pack("<Q", 70_000) + b"{" + (b" " * (64 * 1024 - 9))
        preview_payload = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
        mock_list.return_value = [
            {
                "name": "model.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/model.pkl",
                "size": 1024,
                "human_size": "1.0 KB",
            },
            {"name": "evil.payload", "path": tflite_url, "size": len(tflite_payload), "human_size": "24 B"},
            {
                "name": "pickle.payload",
                "path": proto0_pickle_url,
                "size": len(proto0_pickle_payload),
                "human_size": "32 B",
            },
            {
                "name": "weights.jpg",
                "path": safetensors_url,
                "size": len(safetensors_payload),
                "human_size": "72 B",
            },
            {
                "name": "large-weights.jpg",
                "path": unknown_size_safetensors_url,
                "size": 0,
                "human_size": "Unknown",
            },
            {"name": "preview.png", "path": preview_url, "size": len(preview_payload), "human_size": "24 B"},
        ]

        def get_side_effect(url: str, **_kwargs: object) -> _FakeStreamingResponse:
            if url == tflite_url:
                return _FakeStreamingResponse(tflite_payload)
            if url == proto0_pickle_url:
                return _FakeStreamingResponse(proto0_pickle_payload)
            if url == safetensors_url:
                return _FakeStreamingResponse(safetensors_payload)
            if url == unknown_size_safetensors_url:
                return _FakeStreamingResponse(large_safetensors_probe)
            if url == preview_url:
                return _FakeStreamingResponse(preview_payload)
            raise AssertionError(f"unexpected content probe: {url}")

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            filename = Path(url).name
            downloaded_file = cache_dir / filename
            downloaded_file.write_bytes(b"mock file content")
            return downloaded_file

        mock_get.side_effect = get_side_effect
        mock_download.side_effect = download_side_effect

        result_dir = download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            api_token="test-token",
            show_progress=False,
        )

        assert result_dir == tmp_path
        assert mock_list.call_args.kwargs["selective"] is False
        assert {call.args[0] for call in mock_get.call_args_list} == {
            tflite_url,
            proto0_pickle_url,
            safetensors_url,
            unknown_size_safetensors_url,
            preview_url,
        }
        assert all(call.kwargs["headers"]["Range"] == "bytes=0-65535" for call in mock_get.call_args_list)
        assert all(call.kwargs["headers"]["X-JFrog-Art-Api"] == "test-token" for call in mock_get.call_args_list)
        assert [call.args[0].rsplit("/", 1)[-1] for call in mock_download.call_args_list] == [
            "model.pkl",
            "evil.payload",
            "pickle.payload",
            "weights.jpg",
            "large-weights.jpg",
        ]
        assert (tmp_path / "evil.payload").exists()
        assert (tmp_path / "pickle.payload").exists()
        assert (tmp_path / "weights.jpg").exists()
        assert (tmp_path / "large-weights.jpg").exists()
        assert not (tmp_path / "preview.png").exists()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_selective_skips_benign_unsupported_content(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Benign unsupported content should not become a full artifact download."""
        preview_url = "https://company.jfrog.io/artifactory/repo/models/preview.png"
        malformed_safetensors_url = "https://company.jfrog.io/artifactory/repo/models/framing.jpg"
        preview_payload = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
        malformed_safetensors_payload = struct.pack("<Q", 12) + b"{not-json!!!"
        mock_list.return_value = [
            {"name": "preview.png", "path": preview_url, "size": len(preview_payload), "human_size": "24 B"},
            {
                "name": "framing.jpg",
                "path": malformed_safetensors_url,
                "size": len(malformed_safetensors_payload),
                "human_size": "20 B",
            },
        ]

        def get_side_effect(url: str, **_kwargs: object) -> _FakeStreamingResponse:
            if url == preview_url:
                return _FakeStreamingResponse(preview_payload)
            if url == malformed_safetensors_url:
                return _FakeStreamingResponse(malformed_safetensors_payload)
            raise AssertionError(f"unexpected content probe: {url}")

        mock_get.side_effect = get_side_effect

        with pytest.raises(ValueError, match="No scannable model files found"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                show_progress=False,
            )

        assert {call.args[0] for call in mock_get.call_args_list} == {preview_url, malformed_safetensors_url}
        mock_download.assert_not_called()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_selective_includes_local_bounded_content_routes(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Remote probes should preserve renamed formats recognized by bounded local predicates."""
        cntk_payload = (
            b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02"
            b"\x12\x09\x0a\x03uid\x12\x02ab CompositeFunction primitive_functions "
        )
        lightgbm_payload = (
            b"tree=0\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\nmax_feature_idx=2\n"
            b"tree_sizes=12\nnum_leaves=2\nsplit_feature=0\nleaf_value=0.1 0.2\n"
        )
        torch7_payload = b"T7\x00\x00torch.FloatTensor nn.Sequential "
        executorch_payload = b"\x04\x00\x00\x00ET12payload"
        mxnet_payload = create_mock_mxnet_symbol(tmp_path / "fixture-symbol.json").read_bytes()
        payloads = {
            "https://company.jfrog.io/artifactory/repo/models/cntk.payload": cntk_payload,
            "https://company.jfrog.io/artifactory/repo/models/lightgbm.payload": lightgbm_payload,
            "https://company.jfrog.io/artifactory/repo/models/torch7.payload": torch7_payload,
            "https://company.jfrog.io/artifactory/repo/models/executorch.payload": executorch_payload,
            "https://company.jfrog.io/artifactory/repo/models/mxnet.payload": mxnet_payload,
        }
        mock_list.return_value = [
            {"name": Path(url).name, "path": url, "size": len(payload), "human_size": "Unknown"}
            for url, payload in payloads.items()
        ]
        mock_get.side_effect = lambda url, **_kwargs: _FakeStreamingResponse(payloads[url])

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            downloaded_file = cache_dir / Path(urlparse(url).path).name
            downloaded_file.write_bytes(b"mock file content")
            return downloaded_file

        mock_download.side_effect = download_side_effect

        download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path / "downloads",
            show_progress=False,
        )

        assert {call.args[0] for call in mock_download.call_args_list} == set(payloads)
        probed_urls = [call.args[0] for call in mock_get.call_args_list]
        assert all(probed_urls.count(url) == 1 for url in set(payloads))

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_selective_includes_jax_json_checkpoint(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Remote JSON probes should preserve renamed JAX/Orbax checkpoint metadata."""
        payload_url = "https://company.jfrog.io/artifactory/repo/models/checkpoint.payload"
        payload = b'{"framework":"jax","checkpoint_type":"orbax"}'
        mock_list.return_value = [
            {"name": "checkpoint.payload", "path": payload_url, "size": len(payload), "human_size": "Unknown"}
        ]
        mock_get.return_value = _FakeStreamingResponse(payload)

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            downloaded_file = cache_dir / Path(urlparse(url).path).name
            downloaded_file.write_bytes(b"mock file content")
            return downloaded_file

        mock_download.side_effect = download_side_effect

        download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            show_progress=False,
            scanner_selection=scanner_selection_config_from_inputs(scanners=["jax_checkpoint"]),
        )

        mock_download.assert_called_once_with(
            payload_url,
            cache_dir=tmp_path,
            api_token=None,
            access_token=None,
            timeout=30,
        )

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_json_probe_stays_within_sniff_cap(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """JSON-looking remote probes should not expand beyond the 64 KiB sniff bound."""
        payload_url = "https://company.jfrog.io/artifactory/repo/models/large-json.payload"
        payload = b"{" + (b" " * (64 * 1024 - 1)) + b'"framework":"jax"}'
        mock_list.return_value = [
            {"name": "large-json.payload", "path": payload_url, "size": 0, "human_size": "Unknown"}
        ]
        mock_get.return_value = _FakeStreamingResponse(payload)

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            downloaded_file = cache_dir / Path(urlparse(url).path).name
            downloaded_file.write_bytes(b"mock file content")
            return downloaded_file

        mock_download.side_effect = download_side_effect

        download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            show_progress=False,
            scanner_selection=scanner_selection_config_from_inputs(scanners=["mxnet"]),
        )

        assert mock_get.call_count == 1
        assert mock_get.call_args.kwargs["headers"]["Range"] == "bytes=0-65535"
        mock_download.assert_called_once()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_selective_skips_local_route_near_matches(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Remote probes should not pull benign near matches for longer local signatures."""
        payloads = {
            "https://company.jfrog.io/artifactory/repo/models/cntk.payload": b"\x0a\x07version \x0a\x03uid",
            "https://company.jfrog.io/artifactory/repo/models/lightgbm.payload": b"tree=0\nversion=v4\n",
            "https://company.jfrog.io/artifactory/repo/models/torch7.payload": b"torch nn.Sequential source text",
            "https://company.jfrog.io/artifactory/repo/models/executorch.payload": b"\x04\x00\x00\x00ETxxpayload",
            "https://company.jfrog.io/artifactory/repo/models/mxnet.payload": b'{"nodes":[],"arg_nodes":[],"heads":[]}',
        }
        mock_list.return_value = [
            {"name": Path(url).name, "path": url, "size": len(payload), "human_size": "Unknown"}
            for url, payload in payloads.items()
        ]
        mock_get.side_effect = lambda url, **_kwargs: _FakeStreamingResponse(payloads[url])

        with pytest.raises(ValueError, match="No scannable model files found"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path / "downloads",
                show_progress=False,
            )

        mock_download.assert_not_called()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_selective_includes_tensorflow_protobuf_routes(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Selective remote probes should preserve renamed TensorFlow protobuf models."""
        payloads = {
            f"https://company.jfrog.io/artifactory/repo/models/{name}": payload
            for name, payload in _build_tensorflow_remote_route_payloads().items()
        }
        mock_list.return_value = [
            {"name": Path(url).name, "path": url, "size": len(payload), "human_size": "Unknown"}
            for url, payload in payloads.items()
        ]
        mock_get.side_effect = lambda url, **_kwargs: _FakeStreamingResponse(payloads[url])

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            downloaded_file = cache_dir / Path(urlparse(url).path).name
            downloaded_file.write_bytes(b"mock file content")
            return downloaded_file

        mock_download.side_effect = download_side_effect

        download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            show_progress=False,
        )

        assert {call.args[0] for call in mock_download.call_args_list} == set(payloads)

    def test_jfrog_protobuf_candidate_scanner_selection_preserves_tensorflow_routes(self) -> None:
        """Ambiguous remote protobufs should remain eligible for TensorFlow scanner selection."""
        scanner_ids = _scanner_ids_for_detected_jfrog_format(PROTOBUF_MODEL_CANDIDATE_FORMAT)

        assert {"coreml", "onnx", "protobuf_model_candidate", "tf_metagraph", "tf_savedmodel"} <= scanner_ids

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_probe_fails_closed_on_untrusted_redirect(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Content probes must not route artifacts using an untrusted redirect body."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        hidden_url = "https://company.jfrog.io/artifactory/repo/models/evil.payload"
        redirected_url = "https://evil.example/artifacts/evil.payload"
        payload = b"\x08\x00\x00\x00TFL3" + b"\x00" * 16
        redirect_response = _FakeStreamingResponse(b"", status_code=302, headers={"Location": redirected_url})
        mock_get.return_value = redirect_response
        mock_list.return_value = [
            {"name": "evil.payload", "path": hidden_url, "size": len(payload), "human_size": "24 B"}
        ]

        with pytest.raises(ValueError, match="selective filtering incomplete"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                api_token="test-token",
                show_progress=False,
            )

        assert mock_get.call_args_list[0].args[0] == hidden_url
        assert mock_get.call_args_list[0].kwargs["headers"]["X-JFrog-Art-Api"] == "test-token"
        assert mock_get.call_count == 1
        assert redirect_response.closed is True
        mock_download.assert_not_called()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_probe_fails_closed_on_parser_confused_redirect(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Redirect routing trust must use the host Requests will actually contact."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        hidden_url = "https://company.jfrog.io/artifactory/repo/models/evil.payload"
        redirected_url = "https://evil.example\\@company.jfrog.io/artifacts/evil.payload"
        payload = b"\x08\x00\x00\x00TFL3" + b"\x00" * 16
        redirect_response = _FakeStreamingResponse(b"", status_code=302, headers={"Location": redirected_url})
        mock_get.return_value = redirect_response
        mock_list.return_value = [
            {"name": "evil.payload", "path": hidden_url, "size": len(payload), "human_size": "24 B"}
        ]

        with pytest.raises(ValueError, match="selective filtering incomplete"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                api_token="test-token",
                show_progress=False,
            )

        assert mock_get.call_args_list[0].kwargs["headers"]["X-JFrog-Art-Api"] == "test-token"
        assert mock_get.call_count == 1
        assert redirect_response.closed is True
        mock_download.assert_not_called()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_probe_preserves_credentials_on_trusted_redirect(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Relative redirects on a trusted JFrog host can keep auth while still bounding the probe."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        hidden_url = "https://company.jfrog.io/artifactory/repo/models/evil.payload"
        payload = b"\x08\x00\x00\x00TFL3" + b"\x00" * 16
        redirect_response = _FakeStreamingResponse(
            b"", status_code=307, headers={"Location": "evil.payload?download=1"}
        )
        final_response = _FakeStreamingResponse(payload)
        mock_get.side_effect = [redirect_response, final_response]
        mock_list.return_value = [
            {"name": "evil.payload", "path": hidden_url, "size": len(payload), "human_size": "24 B"}
        ]

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            downloaded_file = cache_dir / Path(urlparse(url).path).name
            downloaded_file.write_bytes(b"mock file content")
            return downloaded_file

        mock_download.side_effect = download_side_effect

        download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            api_token="test-token",
            show_progress=False,
        )

        assert mock_get.call_args_list[1].args[0] == (
            "https://company.jfrog.io/artifactory/repo/models/evil.payload?download=1"
        )
        assert mock_get.call_args_list[1].kwargs["headers"]["X-JFrog-Art-Api"] == "test-token"
        assert mock_get.call_args_list[1].kwargs["headers"]["Range"] == "bytes=0-65535"
        assert redirect_response.closed is True
        mock_download.assert_called_once_with(
            "https://company.jfrog.io/artifactory/repo/models/evil.payload?download=1",
            cache_dir=tmp_path,
            api_token="test-token",
            access_token=None,
            timeout=30,
        )
        assert (tmp_path / "evil.payload").exists()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_probe_allows_default_port_redirect(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Content probes should not reject redirects that only spell out the default port."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        hidden_url = "https://company.jfrog.io/artifactory/repo/models/model.payload"
        redirected_url = "https://company.jfrog.io:443/artifactory/repo/models/model.payload?download=1"
        payload = b"\x08\x00\x00\x00TFL3" + b"\x00" * 16
        redirect_response = _FakeStreamingResponse(b"", status_code=302, headers={"Location": redirected_url})
        final_response = _FakeStreamingResponse(payload)
        mock_get.side_effect = [redirect_response, final_response]
        mock_list.return_value = [
            {"name": "model.payload", "path": hidden_url, "size": len(payload), "human_size": "24 B"}
        ]

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            downloaded_file = cache_dir / Path(urlparse(url).path).name
            downloaded_file.write_bytes(b"mock file content")
            return downloaded_file

        mock_download.side_effect = download_side_effect

        download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            api_token="test-token",
            show_progress=False,
        )

        assert mock_get.call_args_list[1].args[0] == redirected_url
        assert mock_get.call_args_list[1].kwargs["headers"]["X-JFrog-Art-Api"] == "test-token"
        mock_download.assert_called_once_with(
            redirected_url,
            cache_dir=tmp_path,
            api_token="test-token",
            access_token=None,
            timeout=30,
        )

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_selective_includes_structured_remote_routes(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Selective remote probes should preserve ONNX, CoreML, and TAR payloads with renamed suffixes."""
        pytest.importorskip("onnx")
        onnx_payload = create_mock_onnx(tmp_path / "fixture.onnx").read_bytes()
        coreml_payload = create_mock_coreml(tmp_path / "fixture.mlmodel").read_bytes()
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
            member_payload = b"payload"
            member = tarfile.TarInfo("model.pkl")
            member.size = len(member_payload)
            archive.addfile(member, io.BytesIO(member_payload))
        tar_payload = tar_buffer.getvalue()
        payloads = {
            "https://company.jfrog.io/artifactory/repo/models/model.payload": onnx_payload,
            "https://company.jfrog.io/artifactory/repo/models/network.payload": coreml_payload,
            "https://company.jfrog.io/artifactory/repo/models/archive.payload": tar_payload,
        }
        mock_list.return_value = [
            {"name": Path(url).name, "path": url, "size": len(payload), "human_size": "Unknown"}
            for url, payload in payloads.items()
        ]
        mock_get.side_effect = lambda url, **_kwargs: _FakeStreamingResponse(payloads[url])

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            downloaded_file = cache_dir / Path(urlparse(url).path).name
            downloaded_file.write_bytes(b"mock file content")
            return downloaded_file

        mock_download.side_effect = download_side_effect

        result_dir = download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path / "downloads",
            show_progress=False,
        )

        assert result_dir == tmp_path / "downloads"
        assert {call.args[0] for call in mock_download.call_args_list} == set(payloads)

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_preserves_truncated_onnx_probe_candidate(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Truncated ONNX graph evidence should remain eligible for protobuf-model routing."""
        payload_url = "https://company.jfrog.io/artifactory/repo/models/model.payload"
        graph_field_prefix = _encode_proto_varint((7 << 3) | 2) + _encode_proto_varint(128 * 1024)
        payload = b"\x08\x08" + graph_field_prefix + (b"\x0a" * (64 * 1024))
        mock_list.return_value = [
            {"name": "model.payload", "path": payload_url, "size": 128 * 1024, "human_size": "128 KiB"}
        ]
        mock_get.return_value = _FakeStreamingResponse(payload)

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            downloaded_file = cache_dir / Path(urlparse(url).path).name
            downloaded_file.write_bytes(b"mock file content")
            return downloaded_file

        mock_download.side_effect = download_side_effect

        download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            show_progress=False,
            scanner_selection=scanner_selection_config_from_inputs(scanners=["onnx"]),
        )

        mock_download.assert_called_once_with(
            payload_url,
            cache_dir=tmp_path,
            api_token=None,
            access_token=None,
            timeout=30,
        )

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_scanner_selection_preserves_structure_routed_zip(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """ZIP-backed scanner selection should retain renamed archives for local structure routing."""
        zip_url = "https://company.jfrog.io/artifactory/repo/models/model.payload"
        mock_list.return_value = [{"name": "model.payload", "path": zip_url, "size": 8, "human_size": "8 B"}]
        mock_get.return_value = _FakeStreamingResponse(b"PK\x03\x04data")

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            downloaded_file = cache_dir / Path(urlparse(url).path).name
            downloaded_file.write_bytes(b"mock file content")
            return downloaded_file

        mock_download.side_effect = download_side_effect

        download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            show_progress=False,
            scanner_selection=scanner_selection_config_from_inputs(scanners=["pytorch_zip"]),
        )

        mock_download.assert_called_once()
        assert (tmp_path / "model.payload").exists()

    @patch("modelaudit.utils.sources.jfrog._detect_jfrog_content_route_format")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_selective_caps_skipped_content_probes(
        self,
        mock_list: MagicMock,
        mock_detect: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Selective routing should abort instead of probing an unbounded skipped-file listing."""
        mock_list.return_value = [
            {
                "name": f"artifact-{index}.payload",
                "path": f"https://company.jfrog.io/artifactory/repo/models/artifact-{index}.payload",
                "size": 8,
                "human_size": "8 B",
            }
            for index in range(257)
        ]
        mock_detect.return_value = (None, "")

        with pytest.raises(ValueError, match="content probe limit"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                show_progress=False,
            )

        assert mock_detect.call_count == 256

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_selective_fails_closed_when_skipped_content_cannot_be_inspected(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Skipped remote files must be inspectable before selective filtering excludes them."""
        hidden_url = "https://user:leaky-pass@company.jfrog.io/artifactory/repo/models/evil.payload?token=leaky-token"
        mock_list.return_value = [
            {
                "name": "model.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/model.pkl",
                "size": 1024,
                "human_size": "1.0 KB",
            },
            {"name": "evil.payload", "path": hidden_url, "size": 24, "human_size": "24 B"},
        ]
        mock_get.side_effect = PermissionError(f"denied {hidden_url}")

        with pytest.raises(ValueError) as excinfo:
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                show_progress=False,
            )

        error = str(excinfo.value)
        assert "selective filtering incomplete" in error
        assert "evil.payload" in error
        assert "leaky-pass" not in error
        assert "leaky-token" not in error
        assert "?token=" not in error
        mock_download.assert_not_called()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_scanner_selection_includes_matching_content_route_only(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Scanner allowlists should admit matching renamed content without pulling unrelated formats."""
        safetensors_url = "https://company.jfrog.io/artifactory/repo/models/weights.jpg"
        pickle_url = "https://company.jfrog.io/artifactory/repo/models/pickle.payload"
        safetensors_header = b'{"tensor":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
        safetensors_payload = struct.pack("<Q", len(safetensors_header)) + safetensors_header + b"\x00\x00\x00\x00"
        pickle_payload = b"\x80\x04cos\nsystem\n."
        mock_list.return_value = [
            {
                "name": "weights.jpg",
                "path": safetensors_url,
                "size": len(safetensors_payload),
                "human_size": "72 B",
            },
            {"name": "pickle.payload", "path": pickle_url, "size": len(pickle_payload), "human_size": "16 B"},
        ]

        def get_side_effect(url: str, **_kwargs: object) -> _FakeStreamingResponse:
            if url == safetensors_url:
                return _FakeStreamingResponse(safetensors_payload)
            if url == pickle_url:
                return _FakeStreamingResponse(pickle_payload)
            raise AssertionError(f"unexpected content probe: {url}")

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            downloaded_file = cache_dir / Path(url).name
            downloaded_file.write_bytes(b"mock file content")
            return downloaded_file

        mock_get.side_effect = get_side_effect
        mock_download.side_effect = download_side_effect

        download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            show_progress=False,
            scannable_extensions={".safetensors"},
            scanner_selection=scanner_selection_config_from_inputs(scanners=["safetensors"]),
        )

        assert {call.args[0] for call in mock_get.call_args_list} == {safetensors_url, pickle_url}
        assert [call.args[0].rsplit("/", 1)[-1] for call in mock_download.call_args_list] == ["weights.jpg"]
        assert (tmp_path / "weights.jpg").exists()
        assert not (tmp_path / "pickle.payload").exists()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_selected_extensions_do_not_probe_skipped_content(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Explicit scanner-extension filtering should not pull in content for excluded scanners."""
        mock_list.return_value = [
            {
                "name": "weights.safetensors",
                "path": "https://company.jfrog.io/artifactory/repo/models/weights.safetensors",
                "size": 1024,
                "human_size": "1.0 KB",
            },
            {
                "name": "evil.payload",
                "path": "https://company.jfrog.io/artifactory/repo/models/evil.payload",
                "size": 24,
                "human_size": "24 B",
            },
        ]

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            filename = Path(url).name
            downloaded_file = cache_dir / filename
            downloaded_file.write_bytes(b"mock file content")
            return downloaded_file

        mock_download.side_effect = download_side_effect

        download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            show_progress=False,
            scannable_extensions={".safetensors"},
        )

        mock_get.assert_not_called()
        assert [call.args[0].rsplit("/", 1)[-1] for call in mock_download.call_args_list] == ["weights.safetensors"]
        assert (tmp_path / "weights.safetensors").exists()
        assert not (tmp_path / "evil.payload").exists()

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_rejects_traversal_paths(self, mock_list, mock_download, tmp_path):
        """Test that traversal paths from JFrog metadata are rejected."""
        mock_list.return_value = [
            {
                "name": "../../escape.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/../../escape.pkl",
                "size": 1024,
                "human_size": "1.0 KB",
            }
        ]

        with pytest.raises(Exception, match="JFrog folder download failed"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                api_token="test-token",
                show_progress=False,
            )

        assert not any(tmp_path.iterdir())
        mock_download.assert_not_called()

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_aborts_on_partial_failure(self, mock_list, mock_download, tmp_path):
        """Test that a single file download error aborts the folder download."""
        mock_list.return_value = [
            {
                "name": "model1.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/model1.pkl",
                "size": 1024,
                "human_size": "1.0 KB",
            },
            {
                "name": "model2.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model2.pt",
                "size": 2048,
                "human_size": "2.0 KB",
            },
            {
                "name": "model3.safetensors",
                "path": "https://company.jfrog.io/artifactory/repo/models/model3.safetensors",
                "size": 4096,
                "human_size": "4.0 KB",
            },
        ]

        attempted_downloads: list[str] = []

        def mock_download_side_effect(url, cache_dir, **kwargs):
            filename = Path(url).name
            attempted_downloads.append(filename)
            downloaded_file = cache_dir / filename
            downloaded_file.write_bytes(b"mock file content")
            if filename == "model2.pt":
                raise Exception("boom")
            return downloaded_file

        mock_download.side_effect = mock_download_side_effect

        with pytest.raises(Exception, match=r"failed after 1 of 3 file\(s\) completed"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                api_token="test-token",
                show_progress=False,
            )

        assert attempted_downloads == ["model1.pkl", "model2.pt"]
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.tempfile.mkdtemp")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_cleans_owned_temp_dir_on_failure(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_mkdtemp: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Owned temp directories must be removed when a download aborts."""
        owned_download_dir = tmp_path / "owned-jfrog-downloads"
        owned_download_dir.mkdir()
        mock_mkdtemp.return_value = str(owned_download_dir)
        mock_list.return_value = [
            {
                "name": "model1.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/model1.pkl",
                "size": 1024,
                "human_size": "1.0 KB",
            }
        ]
        mock_download.side_effect = Exception("boom")

        with pytest.raises(Exception, match=r"failed after 0 of 1 file\(s\) completed"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=None,
                api_token="test-token",
                show_progress=False,
            )

        assert not owned_download_dir.exists()
