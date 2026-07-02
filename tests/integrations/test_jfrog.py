import importlib
import io
import json
import logging
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

import pytest
import requests

from modelaudit.scanner_selection import (
    resolve_scanner_selection_policy,
    scanner_selection_config_from_inputs,
    selected_scanner_extensions,
    selected_scanner_filenames,
)
from modelaudit.utils.file.detection import (
    EXECUTABLE_ZIP_POLYGLOT_FORMAT,
    LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT,
    MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT,
    PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
    PROTOBUF_MODEL_CANDIDATE_FORMAT,
    XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT,
)
from modelaudit.utils.sources.jfrog import (
    JFROG_DOWNLOAD_CHUNK_SIZE,
    _filter_scannable_jfrog_files,
    _local_download_path_collision_key,
    _scanner_ids_for_detected_jfrog_format,
    detect_jfrog_target_type,
    download_artifact,
    download_jfrog_folder,
    filter_scannable_files,
    format_size,
    get_storage_api_url,
    is_jfrog_url,
    is_jfrog_url_like,
    list_jfrog_folder_contents,
    redact_jfrog_url_for_display,
)
from tests.helpers import create_mock_coreml, create_mock_mxnet_symbol, create_mock_onnx


class _FakeStreamingResponse:
    def __init__(self, payload: bytes, *, status_code: int = 200, headers: dict[str, str] | None = None) -> None:
        self.payload = payload
        self.status_code = status_code
        self.headers = headers or {}
        self.cookies = requests.cookies.RequestsCookieJar()
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


@pytest.mark.parametrize(
    ("selected_scanner", "detected_format", "expected"),
    [
        pytest.param("pickle", "zip", [], id="reject-unselected-pytorch-zip"),
        pytest.param("pytorch_zip", "zip", "routed", id="retain-selected-pytorch-zip"),
        pytest.param(
            "pickle",
            PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
            "routed",
            id="retain-inconclusive-pickle-route",
        ),
        pytest.param("pickle", None, "original", id="retain-inconclusive-shared-suffix"),
    ],
)
@patch("modelaudit.utils.sources.jfrog._detect_jfrog_content_route_format")
def test_filter_scannable_jfrog_files_validates_shared_suffix_ownership(
    mock_detect: MagicMock,
    selected_scanner: str,
    detected_format: str | None,
    expected: list[dict[str, object]] | str,
) -> None:
    url = "https://company.jfrog.io/artifactory/repo/models/model.pt"
    files = [{"path": url, "name": "model.pt", "size": 8, "human_size": "8 B"}]
    mock_detect.return_value = (detected_format, url)
    policy = resolve_scanner_selection_policy(scanners=[selected_scanner])

    actual = _filter_scannable_jfrog_files(
        files,
        scannable_extensions=selected_scanner_extensions(policy, conservative=True),
        scanner_selection=policy.to_config(),
    )

    if expected == "routed":
        assert actual == [
            {
                **files[0],
                "content_detected_format": detected_format,
                "content_probe_download_url": url,
            }
        ]
    elif expected == "original":
        assert actual == files
    else:
        assert actual == expected
    mock_detect.assert_called_once()


@patch("modelaudit.utils.sources.jfrog._detect_jfrog_content_route_format")
def test_filter_scannable_jfrog_files_keeps_selected_joblib_without_content_probe(
    mock_detect: MagicMock,
) -> None:
    url = "https://company.jfrog.io/artifactory/repo/models/model.joblib"
    files = [{"path": url, "name": "model.joblib", "size": 8, "human_size": "8 B"}]
    policy = resolve_scanner_selection_policy(scanners=["joblib"])

    actual = _filter_scannable_jfrog_files(
        files,
        scannable_extensions=selected_scanner_extensions(policy, conservative=True),
        scanner_selection=policy.to_config(),
    )

    assert actual == files
    mock_detect.assert_not_called()


def _fake_json_response(payload: object, *, headers: dict[str, str] | None = None) -> _FakeStreamingResponse:
    return _FakeStreamingResponse(json.dumps(payload).encode(), headers=headers)


def _encode_proto_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("protobuf varints cannot encode negative values")

    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _ubjson_key(key: bytes) -> bytes:
    return b"U" + bytes([len(key)]) + key


def _ubjson_string(value: bytes) -> bytes:
    return b"SL" + len(value).to_bytes(8, byteorder="big", signed=True) + value


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
        ]
        for url in valid_urls:
            assert is_jfrog_url(url)

    def test_invalid_jfrog_urls(self):
        invalid_urls = [
            "https://example.com/model",
            "https://evil.example/artifactory/repo/model.bin",
            "https://my-jfrog.com/artifactory/libs-release/model.pt",
            "http://attacker.jfrog.io/artifactory/repo/model.bin",
            "http://localhost/artifactory/libs-release/model.pt",
            "https://localhost/artifactory/libs-release/model.pt",
            "https://127.0.0.1/artifactory/libs-release/model.pt",
            "https://[::1]/artifactory/libs-release/model.pt",
            "hf://model",
            "",
        ]
        for url in invalid_urls:
            assert not is_jfrog_url(url)

    def test_allowlisted_self_hosted_jfrog_urls(self, monkeypatch):
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "my-jfrog.com,artifacts.internal")

        assert is_jfrog_url("https://my-jfrog.com/artifactory/libs-release/model.pt")
        assert is_jfrog_url("https://artifacts.internal/artifactory/ml/model.pkl")
        assert not is_jfrog_url("http://my-jfrog.com/artifactory/libs-release/model.pt")

    def test_loopback_hosts_are_not_trusted_even_when_allowlisted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "localhost,127.0.0.1,https://[::1]")

        assert not is_jfrog_url("https://localhost/artifactory/libs-release/model.pt")
        assert not is_jfrog_url("https://127.0.0.1/artifactory/libs-release/model.pt")
        assert not is_jfrog_url("https://[::1]/artifactory/libs-release/model.pt")

    @pytest.mark.parametrize(
        "hostname",
        [
            "127.1",
            "127.0.1",
            "0177.0.0.1",
            "2130706433",
            "0x7f000001",
            "127.0.0.01",
            "service.localhost",
            "0.0.0.0",
            "[::]",
            "[::ffff:127.0.0.1]",
        ],
    )
    def test_local_aliases_are_not_trusted_even_when_allowlisted(
        self, monkeypatch: pytest.MonkeyPatch, hostname: str
    ) -> None:
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", hostname)

        assert not is_jfrog_url(f"https://{hostname}/artifactory/libs-release/model.pt")

    def test_rejected_local_jfrog_url_is_still_recognized_for_redaction(self) -> None:
        assert is_jfrog_url_like("http://user:secret@localhost/artifactory/libs-release/model.pt?token=secret")

    @pytest.mark.parametrize(
        "url",
        [
            "https://localhost/models/model.pt?token=benign",
            "https://example.com/artifactory/repo/model.pt?token=benign",
            "https://company.jfrog.io/not-artifactory/repo/model.pt?token=benign",
        ],
    )
    def test_non_jfrog_near_matches_are_not_classified_for_redaction(self, url: str) -> None:
        assert not is_jfrog_url_like(url)


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
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {"Content-Length": "4"}
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
        assert call_args[1]["allow_redirects"] is False

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_rejects_content_length_over_max_size(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Declared oversized artifacts should fail before writing a body."""
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {"Content-Length": "6"}
        mock_response.iter_content.return_value = [b"oversized"]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        with pytest.raises(Exception, match="exceeds maximum allowed size"):
            download_artifact(
                "https://company.jfrog.io/artifactory/repo/model.bin",
                cache_dir=tmp_path,
                api_token="test-token",
                max_size=5,
            )

        assert not (tmp_path / "model.bin").exists()
        assert not any(tmp_path.iterdir())
        mock_response.close.assert_called_once_with()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_rejects_content_length_over_max_size_preserves_existing_file(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Failed bounded downloads must not delete caller-owned cache files."""
        existing_file = tmp_path / "model.bin"
        existing_file.write_bytes(b"keep me")
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {"Content-Length": "6"}
        mock_response.iter_content.return_value = [b"oversized"]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        with pytest.raises(Exception, match="exceeds maximum allowed size"):
            download_artifact(
                "https://company.jfrog.io/artifactory/repo/model.bin",
                cache_dir=tmp_path,
                api_token="test-token",
                max_size=5,
            )

        assert existing_file.read_bytes() == b"keep me"
        assert list(tmp_path.iterdir()) == [existing_file]

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_stream_enforces_max_size_and_cleans_partial_file(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Streaming responses without Content-Length must still be byte-capped."""
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {}
        mock_response.iter_content.return_value = [b"1", b"2", b"3", b"4", b"5", b"6"]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        with pytest.raises(Exception, match="exceeds maximum allowed size"):
            download_artifact(
                "https://company.jfrog.io/artifactory/repo/model.bin",
                cache_dir=tmp_path,
                api_token="test-token",
                max_size=5,
            )

        assert not (tmp_path / "model.bin").exists()
        assert not any(tmp_path.iterdir())
        mock_response.iter_content.assert_called_once_with(chunk_size=JFROG_DOWNLOAD_CHUNK_SIZE)
        mock_response.close.assert_called_once_with()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_allows_unknown_content_length_under_max_size(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Absent Content-Length is allowed when the streamed body stays within budget."""
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {}
        mock_response.iter_content.return_value = [b"123", b"45"]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        result = download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            cache_dir=tmp_path,
            api_token="test-token",
            max_size=5,
        )

        assert result.read_bytes() == b"12345"

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_interrupt_removes_partial_file_and_preserves_cache(
        self,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Interrupts must not leak partial files or replace existing cache entries."""
        existing_file = tmp_path / "model.bin"
        existing_file.write_bytes(b"old")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.iter_content.side_effect = KeyboardInterrupt
        mock_get.return_value = mock_response

        with pytest.raises(KeyboardInterrupt):
            download_artifact(
                "https://company.jfrog.io/artifactory/repo/model.bin",
                cache_dir=tmp_path,
                max_size=5,
            )

        assert existing_file.read_bytes() == b"old"
        assert not list(tmp_path.glob(".model.bin.*.tmp"))
        mock_response.iter_content.assert_called_once_with(chunk_size=JFROG_DOWNLOAD_CHUNK_SIZE)

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_allows_content_length_equal_to_max_size(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An artifact exactly at the configured boundary should remain downloadable."""
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {"Content-Length": "5"}
        mock_response.iter_content.return_value = [b"123", b"45"]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        result = download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            cache_dir=tmp_path,
            api_token="test-token",
            max_size=5,
        )

        assert result.read_bytes() == b"12345"
        mock_response.iter_content.assert_called_once_with(chunk_size=JFROG_DOWNLOAD_CHUNK_SIZE)

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_treats_zero_max_size_as_unlimited(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """User-facing zero download budgets should preserve the unlimited convention."""
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {}
        mock_response.iter_content.return_value = [b"data"]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        result = download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            cache_dir=tmp_path,
            api_token="test-token",
            max_size=0,
        )

        assert result.read_bytes() == b"data"

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_enforces_internal_zero_remaining_budget(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An exhausted folder budget must not turn into an unlimited artifact download."""
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {}
        mock_response.iter_content.return_value = [b"x"]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        with pytest.raises(Exception, match="exceeds maximum allowed size"):
            download_artifact(
                "https://company.jfrog.io/artifactory/repo/model.bin",
                cache_dir=tmp_path,
                api_token="test-token",
                max_size=0,
                _enforce_zero_max_size=True,
            )

        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_cross_origin_redirect_strips_credentials(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Full artifact downloads may follow an off-origin redirect without credentials."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_REDIRECT_HOSTS", "evil.example")
        redirect_response = _FakeStreamingResponse(
            b"",
            status_code=302,
            headers={"Location": "https://evil.example/artifacts/model.bin"},
        )
        final_response = _FakeStreamingResponse(b"data")
        mock_get.side_effect = [redirect_response, final_response]

        result = download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            cache_dir=tmp_path,
            api_token="test-token",
        )

        assert result.read_bytes() == b"data"
        assert mock_get.call_args_list[0].kwargs["headers"] == {"X-JFrog-Art-Api": "test-token"}
        assert mock_get.call_args_list[1].kwargs["headers"] == {}
        assert redirect_response.closed is True
        assert final_response.closed is True

    @pytest.mark.parametrize(
        "location",
        [
            "http://cdn.example/artifacts/model.bin",
            "https://localhost/artifacts/model.bin",
            "https://127.1/artifacts/model.bin",
            "https://[::ffff:127.0.0.1]/artifacts/model.bin",
            "https://evil.example\\@company.jfrog.io/artifacts/model.bin",
        ],
    )
    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_rejects_unsafe_redirect_targets(
        self,
        mock_get: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        location: str,
    ) -> None:
        """Downloads must not follow local, plaintext, or parser-confused redirects."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        redirect_response = _FakeStreamingResponse(b"", status_code=302, headers={"Location": location})
        mock_get.return_value = redirect_response

        with pytest.raises(Exception, match="Refusing unsafe JFrog download target"):
            download_artifact(
                "https://company.jfrog.io/artifactory/repo/model.bin",
                cache_dir=tmp_path,
                api_token="test-token",
            )

        mock_get.assert_called_once()
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
        assert mock_get.call_args_list[1].kwargs["headers"] == {"X-JFrog-Art-Api": "test-token"}
        assert redirect_response.closed is True
        assert final_response.closed is True

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_strips_credentials_on_alternate_port_redirect(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Credentials must not cross an effective-origin port boundary."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        redirected_url = "https://company.jfrog.io:8443/artifactory/repo/model.bin"
        redirect_response = _FakeStreamingResponse(b"", status_code=302, headers={"Location": redirected_url})
        final_response = _FakeStreamingResponse(b"data")
        mock_get.side_effect = [redirect_response, final_response]

        result = download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            cache_dir=tmp_path,
            api_token="test-token",
        )

        assert result.read_bytes() == b"data"
        assert mock_get.call_args_list[0].kwargs["headers"] == {"X-JFrog-Art-Api": "test-token"}
        assert mock_get.call_args_list[1].args[0] == redirected_url
        assert mock_get.call_args_list[1].kwargs["headers"] == {}
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
        mock_response.status_code = 200
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
        mock_response.status_code = 200
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
        mock_response.status_code = 200
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
        mock_response.status_code = 200
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
    def test_parser_confused_initial_jfrog_url_receives_no_credentials(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Parser-confused initial URLs must be rejected before any request is sent."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        with pytest.raises(ValueError, match="Not a JFrog URL"):
            download_artifact(
                "https://evil.example\\@company.jfrog.io/artifactory/repo/model.bin",
                cache_dir=tmp_path,
                api_token="test-token",
            )

        mock_get.assert_not_called()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_untrusted_download_redirect_strips_credentials(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API tokens must not be forwarded to an untrusted redirect target."""
        redirect_response = MagicMock(spec=requests.Response)
        redirect_response.status_code = 302
        redirect_response.headers = {"Location": "https://evil.example/artifacts/model.bin"}
        final_response = MagicMock(spec=requests.Response)
        final_response.status_code = 200
        final_response.headers = {}
        final_response.raise_for_status.return_value = None
        final_response.iter_content.return_value = [b"data"]
        mock_get.side_effect = [redirect_response, final_response]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_REDIRECT_HOSTS", "evil.example")

        result = download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            cache_dir=tmp_path,
            api_token="test-token",
        )

        assert result.read_bytes() == b"data"
        assert mock_get.call_args_list[0].kwargs["headers"] == {"X-JFrog-Art-Api": "test-token"}
        assert mock_get.call_args_list[1].args[0] == "https://evil.example/artifacts/model.bin"
        assert mock_get.call_args_list[1].kwargs["headers"] == {}
        assert all(call.kwargs["allow_redirects"] is False for call in mock_get.call_args_list)

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_artifact_uses_explicit_safe_destination_filename(
        self,
        mock_get: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Folder downloads must avoid staging under a raw filesystem-ambiguous URL basename."""
        response = MagicMock(spec=requests.Response)
        response.status_code = 200
        response.headers = {}
        response.raise_for_status.return_value = None
        response.iter_content.return_value = [b"data"]
        mock_get.return_value = response
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        result = download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.pkl ",
            cache_dir=tmp_path,
            _destination_filename="model.pkl%20",
        )

        assert result == tmp_path / "model.pkl%20"
        assert result.read_bytes() == b"data"
        assert not (tmp_path / "model.pkl ").exists()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_untrusted_download_redirect_enforces_streaming_budget(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Redirected bodies must remain capped after credentials are stripped."""
        redirect_response = MagicMock(spec=requests.Response)
        redirect_response.status_code = 302
        redirect_response.headers = {"Location": "https://evil.example/artifacts/model.bin"}
        final_response = MagicMock(spec=requests.Response)
        final_response.status_code = 200
        final_response.headers = {}
        final_response.raise_for_status.return_value = None
        final_response.iter_content.return_value = [b"123", b"456"]
        mock_get.side_effect = [redirect_response, final_response]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_REDIRECT_HOSTS", "evil.example")

        with pytest.raises(Exception, match="exceeds maximum allowed size"):
            download_artifact(
                "https://company.jfrog.io/artifactory/repo/model.bin",
                cache_dir=tmp_path,
                api_token="test-token",
                max_size=5,
            )

        assert mock_get.call_args_list[0].kwargs["headers"] == {"X-JFrog-Art-Api": "test-token"}
        assert mock_get.call_args_list[1].kwargs["headers"] == {}
        assert not any(tmp_path.iterdir())
        redirect_response.close.assert_called_once_with()
        final_response.close.assert_called_once_with()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_can_require_same_origin_redirects(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Content-routed downloads must retain the probe's same-origin redirect policy."""
        redirect_response = MagicMock(spec=requests.Response)
        redirect_response.status_code = 302
        redirect_response.headers = {"Location": "https://evil.example/artifacts/model.bin"}
        mock_get.return_value = redirect_response
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        with pytest.raises(Exception, match="Refusing cross-origin JFrog redirect"):
            download_artifact(
                "https://company.jfrog.io/artifactory/repo/model.bin",
                cache_dir=tmp_path,
                api_token="test-token",
                require_same_origin_redirects=True,
            )

        mock_get.assert_called_once()
        redirect_response.close.assert_called_once_with()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_parser_confused_redirect_is_rejected(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Redirect validation must reject conflicting parser destinations."""
        redirect_response = MagicMock(spec=requests.Response)
        redirect_response.status_code = 302
        redirect_response.headers = {"Location": "https://evil.example\\@company.jfrog.io/artifacts/model.bin"}
        mock_get.return_value = redirect_response
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        with pytest.raises(Exception, match="Refusing unsafe JFrog download target"):
            download_artifact(
                "https://company.jfrog.io/artifactory/repo/model.bin",
                cache_dir=tmp_path,
                api_token="test-token",
            )

        mock_get.assert_called_once()
        assert mock_get.call_args.kwargs["headers"] == {"X-JFrog-Art-Api": "test-token"}
        redirect_response.close.assert_called_once_with()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_trusted_download_redirect_preserves_credentials(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Credentials can be reused when a redirect target is explicitly trusted."""
        redirect_response = MagicMock(spec=requests.Response)
        redirect_response.status_code = 307
        redirect_response.headers = {"Location": "/artifactory/repo/model.bin?download=1"}
        final_response = MagicMock(spec=requests.Response)
        final_response.status_code = 200
        final_response.headers = {}
        final_response.raise_for_status.return_value = None
        final_response.iter_content.return_value = [b"data"]
        mock_get.side_effect = [redirect_response, final_response]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        result = download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            cache_dir=tmp_path,
            api_token="test-token",
        )

        assert result.read_bytes() == b"data"
        assert mock_get.call_args_list[1].args[0] == ("https://company.jfrog.io/artifactory/repo/model.bin?download=1")
        assert mock_get.call_args_list[1].kwargs["headers"] == {"X-JFrog-Art-Api": "test-token"}

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_redirect_preserves_response_cookies(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Manual redirects should preserve stickiness/session cookies through the cookie jar."""
        redirect_response = MagicMock(spec=requests.Response)
        redirect_response.status_code = 302
        redirect_response.headers = {"Location": "/artifactory/repo/model.bin?node=1"}
        redirect_response.cookies = requests.cookies.cookiejar_from_dict({"ROUTEID": "backend-a"})
        final_response = MagicMock(spec=requests.Response)
        final_response.status_code = 200
        final_response.headers = {}
        final_response.raise_for_status.return_value = None
        final_response.iter_content.return_value = [b"data"]
        mock_get.side_effect = [redirect_response, final_response]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        result = download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            cache_dir=tmp_path,
            api_token="test-token",
        )

        assert result.read_bytes() == b"data"
        first_cookie_jar = mock_get.call_args_list[0].kwargs["cookies"]
        second_cookie_jar = mock_get.call_args_list[1].kwargs["cookies"]
        assert first_cookie_jar is second_cookie_jar
        assert second_cookie_jar.get("ROUTEID") == "backend-a"

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_redirect_does_not_restore_credentials_across_trust_boundaries(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An untrusted hop must permanently drop trusted credentials and session state."""
        trusted_redirect = MagicMock(spec=requests.Response)
        trusted_redirect.status_code = 302
        trusted_redirect.headers = {"Location": "https://evil.example/artifacts/model.bin"}
        trusted_redirect.cookies = requests.cookies.cookiejar_from_dict({"JFROG_SESSION": "trusted-session"})
        untrusted_redirect = MagicMock(spec=requests.Response)
        untrusted_redirect.status_code = 302
        untrusted_redirect.headers = {"Location": "https://company.jfrog.io/artifactory/repo/model.bin?node=1"}
        untrusted_redirect.cookies = requests.cookies.cookiejar_from_dict({"EVIL_SESSION": "untrusted-session"})
        final_response = MagicMock(spec=requests.Response)
        final_response.status_code = 200
        final_response.headers = {}
        final_response.raise_for_status.return_value = None
        final_response.iter_content.return_value = [b"data"]
        mock_get.side_effect = [trusted_redirect, untrusted_redirect, final_response]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_REDIRECT_HOSTS", "evil.example")

        result = download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            cache_dir=tmp_path,
            api_token="test-token",
        )

        assert result.read_bytes() == b"data"
        trusted_cookie_jar = mock_get.call_args_list[0].kwargs["cookies"]
        untrusted_cookie_jar = mock_get.call_args_list[1].kwargs["cookies"]
        returning_cookie_jar = mock_get.call_args_list[2].kwargs["cookies"]
        assert returning_cookie_jar is not trusted_cookie_jar
        assert returning_cookie_jar is not untrusted_cookie_jar
        assert trusted_cookie_jar is not untrusted_cookie_jar
        assert trusted_cookie_jar.get("JFROG_SESSION") == "trusted-session"
        assert trusted_cookie_jar.get("EVIL_SESSION") is None
        assert untrusted_cookie_jar.get("JFROG_SESSION") is None
        assert untrusted_cookie_jar.get("EVIL_SESSION") == "untrusted-session"
        assert returning_cookie_jar.get("JFROG_SESSION") is None
        assert returning_cookie_jar.get("EVIL_SESSION") is None
        assert mock_get.call_args_list[1].kwargs["headers"] == {}
        assert mock_get.call_args_list[2].kwargs["headers"] == {}

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_redirect_without_location_fails_closed(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Redirect responses without a target must not be scanned as artifact bodies."""
        redirect_response = MagicMock(spec=requests.Response)
        redirect_response.status_code = 302
        redirect_response.headers = {}
        mock_get.return_value = redirect_response
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        with pytest.raises(Exception, match="JFrog redirect response missing Location header"):
            download_artifact(
                "https://company.jfrog.io/artifactory/repo/model.bin",
                cache_dir=tmp_path,
                api_token="test-token",
            )

        redirect_response.close.assert_called_once_with()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_download_malformed_redirect_location_closes_response(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Malformed redirect targets must not leave streamed responses open."""
        redirect_response = MagicMock(spec=requests.Response)
        redirect_response.status_code = 302
        redirect_response.headers = {"Location": "https://[::1"}
        mock_get.return_value = redirect_response
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        with pytest.raises(Exception, match="Invalid IPv6 URL"):
            download_artifact(
                "https://company.jfrog.io/artifactory/repo/model.bin",
                cache_dir=tmp_path,
                api_token="test-token",
            )

        redirect_response.close.assert_called_once_with()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_http_jfrog_saas_url_is_rejected_before_credentials(
        self, mock_get: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Non-local HTTP JFrog URLs must not receive credentials."""
        monkeypatch.setenv("JFROG_API_TOKEN", "env-api-token")

        with pytest.raises(ValueError, match="Not a JFrog URL"):
            download_artifact("http://attacker.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path)

        mock_get.assert_not_called()

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost/artifactory/repo/model.bin",
            "https://localhost/artifactory/repo/model.bin",
            "https://127.0.0.1/artifactory/repo/model.bin",
            "https://127.1/artifactory/repo/model.bin",
            "https://0177.0.0.1/artifactory/repo/model.bin",
            "https://2130706433/artifactory/repo/model.bin",
            "https://service.localhost/artifactory/repo/model.bin",
            "https://0.0.0.0/artifactory/repo/model.bin",
            "https://[::1]/artifactory/repo/model.bin",
            "https://[::]/artifactory/repo/model.bin",
            "https://[::ffff:127.0.0.1]/artifactory/repo/model.bin",
        ],
    )
    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_loopback_jfrog_url_is_rejected_before_credentials(
        self,
        mock_get: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        url: str,
    ) -> None:
        """Loopback URLs must not receive operator JFrog credentials."""
        monkeypatch.setenv(
            "MODELAUDIT_JFROG_ALLOWED_HOSTS",
            "localhost,127.0.0.1,127.1,0177.0.0.1,2130706433,service.localhost,0.0.0.0,https://[::1],https://[::],"
            "https://[::ffff:127.0.0.1]",
        )
        monkeypatch.setenv("JFROG_API_TOKEN", "env-api-token")

        with pytest.raises(ValueError, match="Not a JFrog URL"):
            download_artifact(url, cache_dir=tmp_path, api_token="explicit-api-token")

        mock_get.assert_not_called()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_storage_api_skips_credentials_for_unconfigured_host(
        self, mock_get: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Storage API probing should share the same credential forwarding policy."""
        mock_get.return_value = _fake_json_response({"repo": "public-repo", "path": "/model.bin", "size": 12})
        monkeypatch.setenv("JFROG_API_TOKEN", "env-api-token")

        result = detect_jfrog_target_type(
            "https://attacker.jfrog.io/artifactory/repo/model.bin",
            api_token="explicit-api-token",
        )

        assert result["type"] == "file"
        assert mock_get.call_args[1]["headers"] == {}

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_storage_api_rejects_loopback_before_credentials(
        self, mock_get: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Storage API probing must not send credentials to loopback hosts."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "localhost")
        monkeypatch.setenv("JFROG_ACCESS_TOKEN", "env-access-token")

        with pytest.raises(ValueError, match="Not a JFrog URL"):
            detect_jfrog_target_type(
                "https://localhost/artifactory/repo/model.bin",
                access_token="explicit-access-token",
            )

        mock_get.assert_not_called()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_storage_api_untrusted_redirect_strips_credentials(
        self, mock_get: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Storage API redirects must not forward credentials to untrusted hosts."""
        redirect_response = MagicMock(spec=requests.Response)
        redirect_response.status_code = 302
        redirect_response.headers = {"Location": "https://evil.example/storage/model.bin"}
        final_response = _fake_json_response({"repo": "repo", "path": "/model.bin", "size": 12})
        mock_get.side_effect = [redirect_response, final_response]
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_REDIRECT_HOSTS", "evil.example")

        result = detect_jfrog_target_type(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            api_token="test-token",
        )

        assert result["type"] == "file"
        assert mock_get.call_args_list[0].kwargs["headers"] == {"X-JFrog-Art-Api": "test-token"}
        assert mock_get.call_args_list[1].args[0] == "https://evil.example/storage/model.bin"
        assert mock_get.call_args_list[1].kwargs["headers"] == {}
        assert all(call.kwargs["allow_redirects"] is False for call in mock_get.call_args_list)

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_storage_api_rejects_parser_confused_redirect(
        self, mock_get: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Storage API redirects must reject ambiguous effective destinations."""
        redirect_response = MagicMock(spec=requests.Response)
        redirect_response.status_code = 302
        redirect_response.headers = {"Location": "https://evil.example\\@company.jfrog.io/storage/model.bin"}
        mock_get.return_value = redirect_response
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")

        with pytest.raises(Exception, match="Refusing unsafe JFrog download target"):
            detect_jfrog_target_type(
                "https://company.jfrog.io/artifactory/repo/model.bin",
                api_token="test-token",
            )

        mock_get.assert_called_once()
        assert mock_get.call_args.kwargs["headers"] == {"X-JFrog-Art-Api": "test-token"}

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_storage_api_explicit_access_token_precedes_environment_api_token(
        self, mock_get: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Explicit Storage API access tokens should not be shadowed by env API tokens."""
        mock_get.return_value = _fake_json_response({"repo": "repo", "path": "/model.bin", "size": 12})
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        monkeypatch.setenv("JFROG_API_TOKEN", "env-api-token")

        result = detect_jfrog_target_type(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            access_token="explicit-access-token",
        )

        assert result["type"] == "file"
        assert mock_get.call_args[1]["headers"] == {"Authorization": "Bearer explicit-access-token"}

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_no_authentication(
        self,
        mock_get: MagicMock,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test anonymous access when no authentication is provided."""
        mock_response = mock_get.return_value
        mock_response.status_code = 200
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
    def test_detect_jfrog_target_type_file(self, mock_get: MagicMock) -> None:
        """Test detection of JFrog file targets."""
        # Mock response for a file
        mock_get.return_value = _fake_json_response(
            {
                "repo": "my-repo",
                "path": "/model.pkl",
                "size": 1024,
                "lastModified": "2024-01-01T00:00:00.000Z",
            }
        )

        result = detect_jfrog_target_type("https://company.jfrog.io/artifactory/repo/model.pkl", api_token="test-token")

        assert result["type"] == "file"
        assert result["size"] == 1024
        assert result["repo"] == "my-repo"

        # Verify Storage API URL was called
        mock_get.assert_called_once()
        called_url = mock_get.call_args[0][0]
        assert "api/storage" in called_url

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_detect_jfrog_target_type_folder(self, mock_get: MagicMock) -> None:
        """Test detection of JFrog folder targets."""
        # Mock response for a folder with children
        mock_get.return_value = _fake_json_response(
            {
                "repo": "my-repo",
                "path": "/models",
                "children": [
                    {"uri": "/model1.pkl", "folder": False, "size": 1024},
                    {"uri": "/subfolder", "folder": True},
                    {"uri": "/model2.pt", "folder": False, "size": 2048},
                ],
            }
        )

        result = detect_jfrog_target_type("https://company.jfrog.io/artifactory/repo/models/", api_token="test-token")

        assert result["type"] == "folder"
        assert len(result["children"]) == 3
        assert result["repo"] == "my-repo"

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_detect_jfrog_target_type_rejects_declared_oversized_storage_response(
        self, mock_get: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("modelaudit.utils.sources.jfrog._MAX_JFROG_STORAGE_RESPONSE_BYTES", 64)
        response = _fake_json_response(
            {"repo": "my-repo", "path": "/model.pkl", "size": 12},
            headers={"Content-Length": "65"},
        )
        mock_get.return_value = response

        with pytest.raises(ValueError, match="Storage API response size"):
            detect_jfrog_target_type("https://company.jfrog.io/artifactory/repo/model.pkl")

        assert response.closed
        assert mock_get.call_args.kwargs["stream"] is True

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_detect_jfrog_target_type_rejects_streamed_oversized_storage_response(
        self, mock_get: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("modelaudit.utils.sources.jfrog._MAX_JFROG_STORAGE_RESPONSE_BYTES", 64)
        response = _FakeStreamingResponse(b"{" + b" " * 64 + b"}")
        mock_get.return_value = response

        with pytest.raises(ValueError, match="Storage API response size"):
            detect_jfrog_target_type("https://company.jfrog.io/artifactory/repo/model.pkl")

        assert response.closed

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_detect_jfrog_target_type_allows_storage_response_at_exact_limit(
        self, mock_get: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        payload = json.dumps({"repo": "repo", "path": "/model.pkl", "size": 12}).encode()
        monkeypatch.setattr("modelaudit.utils.sources.jfrog._MAX_JFROG_STORAGE_RESPONSE_BYTES", len(payload))
        response = _FakeStreamingResponse(payload, headers={"Content-Length": str(len(payload))})
        mock_get.return_value = response

        result = detect_jfrog_target_type("https://company.jfrog.io/artifactory/repo/model.pkl")

        assert result["type"] == "file"
        assert result["size"] == 12
        assert response.closed

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    def test_detect_jfrog_target_type_rejects_non_list_children(self, mock_get: MagicMock) -> None:
        response = _fake_json_response({"repo": "repo", "path": "/models", "children": {}})
        mock_get.return_value = response

        with pytest.raises(ValueError, match="expected children to be a list"):
            detect_jfrog_target_type("https://company.jfrog.io/artifactory/repo/models/")

        assert response.closed

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

    @patch("modelaudit.utils.sources.jfrog.detect_jfrog_target_type")
    def test_list_jfrog_folder_contents_rejects_encoded_traversal(self, mock_detect: MagicMock) -> None:
        """Prepared URL normalization must not escape the requested folder."""
        mock_detect.return_value = {
            "type": "folder",
            "children": [{"uri": "/%2e%2e/secret.pt", "folder": False, "size": 4}],
        }

        with pytest.raises(ValueError, match="Unsafe JFrog child path"):
            list_jfrog_folder_contents(
                "https://company.jfrog.io/artifactory/repo/models/",
                recursive=False,
                selective=False,
            )

    @patch("modelaudit.utils.sources.jfrog.detect_jfrog_target_type")
    def test_list_jfrog_folder_contents_allows_encoded_filename(self, mock_detect: MagicMock) -> None:
        """Benign percent-encoded filename characters should remain supported."""
        mock_detect.return_value = {
            "type": "folder",
            "children": [{"uri": "/model%20v1.pt", "folder": False, "size": 4}],
        }

        files = list_jfrog_folder_contents(
            "https://company.jfrog.io/artifactory/repo/models/",
            recursive=False,
            selective=False,
        )

        assert files[0]["path"].endswith("/model%20v1.pt")

    @patch("modelaudit.utils.sources.jfrog.detect_jfrog_target_type")
    def test_list_jfrog_folder_contents_rejects_invalid_encoded_utf8(self, mock_detect: MagicMock) -> None:
        """Invalid encoded bytes must not collapse into a shared canonical path."""
        mock_detect.return_value = {
            "type": "folder",
            "children": [{"uri": "/%FF/model.pt", "folder": False, "size": 4}],
        }

        with pytest.raises(ValueError, match="Unsafe JFrog child path"):
            list_jfrog_folder_contents(
                "https://company.jfrog.io/artifactory/repo/models/",
                recursive=False,
                selective=False,
            )

    @patch("modelaudit.utils.sources.jfrog._MAX_JFROG_LISTING_ENTRIES", 1)
    @patch("modelaudit.utils.sources.jfrog.detect_jfrog_target_type")
    def test_list_jfrog_folder_contents_caps_entries(self, mock_detect: MagicMock) -> None:
        """Wide listings must fail closed before accumulating unbounded metadata."""
        mock_detect.return_value = {
            "type": "folder",
            "children": [
                {"uri": "/first.pt", "folder": False, "size": 4},
                {"uri": "/second.pt", "folder": False, "size": 4},
            ],
        }

        with pytest.raises(Exception, match="maximum of 1 entries"):
            list_jfrog_folder_contents(
                "https://company.jfrog.io/artifactory/repo/models/",
                recursive=False,
                selective=False,
            )

    @patch("modelaudit.utils.sources.jfrog.detect_jfrog_target_type")
    def test_list_jfrog_folder_contents_skips_repeated_folder(self, mock_detect: MagicMock) -> None:
        """Canonical duplicate folder references should be traversed only once."""

        def mock_detect_side_effect(url: str, *args: object, **kwargs: object) -> dict[str, object]:
            if url.rstrip("/").endswith("models"):
                return {
                    "type": "folder",
                    "children": [
                        {"uri": "/subdir", "folder": True},
                        {"uri": "/%73ubdir", "folder": True},
                    ],
                }
            return {
                "type": "folder",
                "children": [{"uri": "/model.pt", "folder": False, "size": 4}],
            }

        mock_detect.side_effect = mock_detect_side_effect

        files = list_jfrog_folder_contents(
            "https://company.jfrog.io/artifactory/repo/models/",
            recursive=True,
            selective=False,
        )

        assert [file_info["name"] for file_info in files] == ["model.pt"]
        assert mock_detect.call_count == 3

    @patch("modelaudit.utils.sources.jfrog._MAX_JFROG_LISTED_FOLDERS", 1)
    @patch("modelaudit.utils.sources.jfrog.detect_jfrog_target_type")
    def test_list_jfrog_folder_contents_caps_folders(self, mock_detect: MagicMock) -> None:
        """Folder traversal should stop before fetching beyond the configured cap."""
        mock_detect.return_value = {
            "type": "folder",
            "children": [{"uri": "/subdir", "folder": True}],
        }

        with pytest.raises(Exception, match="maximum of 1 folders"):
            list_jfrog_folder_contents(
                "https://company.jfrog.io/artifactory/repo/models/",
                recursive=True,
                selective=False,
            )

        assert mock_detect.call_count == 2


class TestJFrogFolderDownload:
    """Test JFrog folder download functionality."""

    def test_local_download_path_collision_key_normalizes_unicode_and_case(self, tmp_path: Path) -> None:
        """Canonical Unicode and case aliases must compare equally on every host."""
        composed = tmp_path / "caf\N{LATIN SMALL LETTER E WITH ACUTE}" / "Model.pkl"
        decomposed = tmp_path / "cafe\N{COMBINING ACUTE ACCENT}" / "model.pkl"

        assert _local_download_path_collision_key(composed) == _local_download_path_collision_key(decomposed)

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

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_rejects_oversized_selected_file_before_download(
        self, mock_list: MagicMock, mock_download: MagicMock, tmp_path: Path
    ) -> None:
        """Selected files that exceed the configured file budget should not be fetched."""
        mock_list.return_value = [
            {
                "name": "large-model.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/large-model.pt",
                "size": 6,
                "size_known": True,
                "human_size": "6.0 B",
            }
        ]

        with pytest.raises(ValueError, match="exceeds maximum allowed size"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                api_token="test-token",
                show_progress=False,
                max_file_size=5,
            )

        mock_download.assert_not_called()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.detect_jfrog_target_type")
    def test_download_jfrog_folder_resolves_unknown_selected_file_size_when_capped(
        self, mock_detect: MagicMock, mock_download: MagicMock, tmp_path: Path
    ) -> None:
        """Bounded folder downloads should use Storage API file metadata before failing closed."""

        def mock_detect_side_effect(url: str, *args: object, **kwargs: object) -> dict[str, object]:
            if url.endswith("model.pt"):
                return {"type": "file", "repo": "repo", "path": "/models/model.pt", "size": 4, "size_known": True}
            return {
                "type": "folder",
                "repo": "repo",
                "path": "/models",
                "children": [{"uri": "/model.pt", "folder": False}],
            }

        def mock_download_side_effect(url: str, cache_dir: Path, **kwargs: object) -> Path:
            assert kwargs["max_size"] == 5
            path = cache_dir / Path(url).name
            path.write_bytes(b"data")
            return path

        mock_detect.side_effect = mock_detect_side_effect
        mock_download.side_effect = mock_download_side_effect

        result = download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            api_token="test-token",
            show_progress=False,
            max_size=5,
        )

        assert result == tmp_path
        assert (tmp_path / "model.pt").read_bytes() == b"data"
        assert mock_detect.call_count == 3

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_rejects_unknown_selected_file_size_when_capped(
        self, mock_list: MagicMock, mock_download: MagicMock, tmp_path: Path
    ) -> None:
        """Unknown selected-file sizes should fail closed when a total download cap is active."""
        mock_list.return_value = [
            {
                "name": "model.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model.pt",
                "size": 0,
                "size_known": False,
                "human_size": "Unknown",
            }
        ]

        with pytest.raises(ValueError, match="Cannot verify JFrog selected artifact size"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                api_token="test-token",
                show_progress=False,
                max_size=5,
            )

        mock_download.assert_not_called()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_passes_remaining_total_budget_to_artifacts(
        self, mock_list: MagicMock, mock_download: MagicMock, tmp_path: Path
    ) -> None:
        """Folder downloads should enforce one cumulative budget across selected files."""
        mock_list.return_value = [
            {
                "name": "model1.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model1.pt",
                "size": 4,
                "size_known": True,
                "human_size": "4.0 B",
            },
            {
                "name": "model2.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model2.pt",
                "size": 5,
                "size_known": True,
                "human_size": "5.0 B",
            },
        ]
        seen_limits: list[int | None] = []

        def mock_download_side_effect(url: str, cache_dir: Path, **kwargs: object) -> Path:
            max_size = kwargs.get("max_size")
            assert max_size is None or isinstance(max_size, int)
            seen_limits.append(max_size)
            path = cache_dir / Path(url).name
            path.write_bytes(b"x" * (4 if path.name == "model1.pt" else 5))
            return path

        mock_download.side_effect = mock_download_side_effect

        result = download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            api_token="test-token",
            show_progress=False,
            max_size=9,
        )

        assert result == tmp_path
        assert seen_limits == [9, 5]
        assert (tmp_path / "model1.pt").stat().st_size == 4
        assert (tmp_path / "model2.pt").stat().st_size == 5

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_counts_content_probes_toward_total_budget(
        self,
        mock_list: MagicMock,
        mock_get: MagicMock,
        mock_download: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Selective-routing probes should consume the same acquisition budget as downloads."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        payload_url = "https://company.jfrog.io/artifactory/repo/models/model.payload"
        payload = b"cposix\nsystem\n(S'echo pwned'\ntR."
        mock_list.return_value = [
            {
                "name": "model.payload",
                "path": payload_url,
                "size": len(payload),
                "size_known": True,
                "human_size": f"{len(payload)} B",
            }
        ]
        mock_get.return_value = _FakeStreamingResponse(payload)

        def download_side_effect(url: str, cache_dir: Path, **kwargs: object) -> Path:
            assert url == payload_url
            assert kwargs["max_size"] == len(payload)
            path = cache_dir / "model.payload"
            path.write_bytes(payload)
            return path

        mock_download.side_effect = download_side_effect

        result = download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            api_token="test-token",
            show_progress=False,
            max_size=len(payload) * 2,
        )

        assert result == tmp_path
        assert (tmp_path / "model.payload").read_bytes() == payload
        mock_get.assert_called_once()
        mock_download.assert_called_once()

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_stops_when_content_probes_exhaust_total_budget(
        self,
        mock_list: MagicMock,
        mock_get: MagicMock,
        mock_download: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An exhausted probe budget must abort instead of silently skipping later artifacts."""
        monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
        mock_list.return_value = [
            {
                "name": f"model-{index}.payload",
                "path": f"https://company.jfrog.io/artifactory/repo/models/model-{index}.payload",
                "size": 20,
                "size_known": True,
                "human_size": "20 B",
            }
            for index in range(2)
        ]
        mock_get.return_value = _FakeStreamingResponse(b"not-a-model")

        with pytest.raises(ValueError, match=r"content probe .*download budget"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                api_token="test-token",
                show_progress=False,
                max_size=len(b"not-a-model"),
            )

        mock_get.assert_called_once()
        mock_download.assert_not_called()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog._detect_jfrog_content_route_format")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_caps_each_content_probe_with_file_limit(
        self,
        mock_list: MagicMock,
        mock_detect_format: MagicMock,
        mock_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A per-file limit must also bound selective content-sniff downloads."""
        payload_url = "https://company.jfrog.io/artifactory/repo/models/model.payload"
        mock_list.return_value = [
            {
                "name": "model.payload",
                "path": payload_url,
                "size": 10,
                "size_known": True,
                "human_size": "10.0 B",
            }
        ]

        def detect_side_effect(*_args: object, **kwargs: object) -> tuple[None, str]:
            probe_bytes_counter = kwargs["probe_bytes_counter"]
            assert isinstance(probe_bytes_counter, list)
            probe_bytes_counter[0] += 5
            return None, payload_url

        mock_detect_format.side_effect = detect_side_effect

        with pytest.raises(ValueError, match="content probe was truncated by the download budget"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                show_progress=False,
                max_file_size=5,
            )

        assert mock_detect_format.call_args.kwargs["max_probe_bytes"] == 5
        mock_download.assert_not_called()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_preserves_exhausted_total_budget(
        self, mock_list: MagicMock, mock_download: MagicMock, tmp_path: Path
    ) -> None:
        """A zero remaining total must stay enforceable for a declared empty artifact."""
        mock_list.return_value = [
            {
                "name": "model1.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model1.pt",
                "size": 4,
                "size_known": True,
                "human_size": "4.0 B",
            },
            {
                "name": "model2.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model2.pt",
                "size": 0,
                "size_known": True,
                "human_size": "Unknown",
            },
        ]
        seen_limits: list[tuple[int | None, bool]] = []

        def mock_download_side_effect(url: str, cache_dir: Path, **kwargs: object) -> Path:
            max_size = kwargs.get("max_size")
            enforce_zero = kwargs.get("_enforce_zero_max_size")
            assert max_size is None or isinstance(max_size, int)
            assert isinstance(enforce_zero, bool)
            seen_limits.append((max_size, enforce_zero))
            path = cache_dir / Path(url).name
            path.write_bytes(b"x" * (4 if path.name == "model1.pt" else 0))
            return path

        mock_download.side_effect = mock_download_side_effect

        result = download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            api_token="test-token",
            show_progress=False,
            max_size=4,
        )

        assert result == tmp_path
        assert seen_limits == [(4, False), (0, True)]

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_rejects_total_over_budget_before_download(
        self, mock_list: MagicMock, mock_download: MagicMock, tmp_path: Path
    ) -> None:
        """Declared selected-file totals should be capped before any artifact body is fetched."""
        mock_list.return_value = [
            {
                "name": "model1.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model1.pt",
                "size": 6,
                "size_known": True,
                "human_size": "6.0 B",
            },
            {
                "name": "model2.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model2.pt",
                "size": 5,
                "size_known": True,
                "human_size": "5.0 B",
            },
        ]

        with pytest.raises(ValueError, match="folder selected-file total"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                api_token="test-token",
                show_progress=False,
                max_size=10,
            )

        mock_download.assert_not_called()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_failed_child_preserves_existing_file(
        self, mock_list: MagicMock, mock_download: MagicMock, tmp_path: Path
    ) -> None:
        """Folder abort cleanup must not delete caller-owned cache files."""
        existing_file = tmp_path / "model.pt"
        existing_file.write_bytes(b"keep me")
        mock_list.return_value = [
            {
                "name": "model.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model.pt",
                "size": 4,
                "size_known": True,
                "human_size": "4.0 B",
            }
        ]
        mock_download.side_effect = Exception("exceeds maximum allowed size")

        with pytest.raises(Exception, match="JFrog folder download failed"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                api_token="test-token",
                show_progress=False,
                max_size=5,
            )

        assert existing_file.read_bytes() == b"keep me"
        assert list(tmp_path.iterdir()) == [existing_file]

    @patch("modelaudit.utils.sources.jfrog.shutil.copy2")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_backup_failure_preserves_existing_file(
        self, mock_list: MagicMock, mock_download: MagicMock, mock_copy: MagicMock, tmp_path: Path
    ) -> None:
        """Backup failures should not make caller-owned files eligible for abort cleanup."""
        existing_file = tmp_path / "model.pt"
        existing_file.write_bytes(b"keep me")
        mock_list.return_value = [
            {
                "name": "model.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model.pt",
                "size": 4,
                "size_known": True,
                "human_size": "4.0 B",
            }
        ]
        mock_copy.side_effect = OSError("backup volume full")

        with pytest.raises(Exception, match="JFrog folder download failed"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                api_token="test-token",
                show_progress=False,
                max_size=5,
            )

        mock_download.assert_not_called()
        assert existing_file.read_bytes() == b"keep me"
        assert list(tmp_path.iterdir()) == [existing_file]

    @patch("modelaudit.utils.sources.jfrog.tempfile.mkdtemp")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_restore_failure_keeps_backup(
        self, mock_list: MagicMock, mock_download: MagicMock, mock_mkdtemp: MagicMock, tmp_path: Path
    ) -> None:
        """Restore failures should retain the backup so original bytes are recoverable."""
        existing_file = tmp_path / "model1.pt"
        existing_file.write_bytes(b"original")
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        mock_mkdtemp.return_value = str(backup_dir)
        mock_list.return_value = [
            {
                "name": "model1.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model1.pt",
                "size": 4,
                "size_known": True,
                "human_size": "4.0 B",
            },
            {
                "name": "model2.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model2.pt",
                "size": 4,
                "size_known": True,
                "human_size": "4.0 B",
            },
        ]

        def mock_download_side_effect(url: str, cache_dir: Path, **kwargs: object) -> Path:
            path = cache_dir / Path(url).name
            if path.name == "model2.pt":
                raise Exception("boom")
            path.write_bytes(b"new")
            return path

        original_copy2 = shutil.copy2

        def fail_restore_copy(
            src: str | Path,
            dst: str | Path,
            *,
            follow_symlinks: bool = True,
        ) -> Path:
            if Path(dst) == existing_file:
                raise OSError("restore failed")
            return Path(original_copy2(src, dst, follow_symlinks=follow_symlinks))

        mock_download.side_effect = mock_download_side_effect
        with (
            patch("modelaudit.utils.sources.jfrog.shutil.copy2", side_effect=fail_restore_copy),
            pytest.raises(Exception, match="Failed to restore original JFrog cache file"),
        ):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                api_token="test-token",
                show_progress=False,
                max_size=8,
            )

        assert existing_file.read_bytes() == b"new"
        backup_files = list(backup_dir.glob("*.bak"))
        assert len(backup_files) == 1
        assert backup_files[0].read_bytes() == b"original"

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_interrupt_restores_existing_file(
        self, mock_list: MagicMock, mock_download: MagicMock, tmp_path: Path
    ) -> None:
        """Interrupts must restore caller-owned files before propagating."""
        existing_file = tmp_path / "model1.pt"
        existing_file.write_bytes(b"original")
        mock_list.return_value = [
            {
                "name": "model1.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model1.pt",
                "size": 3,
                "size_known": True,
                "human_size": "3.0 B",
            },
            {
                "name": "model2.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model2.pt",
                "size": 3,
                "size_known": True,
                "human_size": "3.0 B",
            },
        ]

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            path = cache_dir / Path(url).name
            if path.name == "model2.pt":
                raise KeyboardInterrupt
            path.write_bytes(b"new")
            return path

        mock_download.side_effect = download_side_effect
        with pytest.raises(KeyboardInterrupt):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                show_progress=False,
                max_size=6,
            )

        assert existing_file.read_bytes() == b"original"
        assert not (tmp_path / "model2.pt").exists()

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_failure_restores_existing_symlink(
        self, mock_list: MagicMock, mock_download: MagicMock, tmp_path: Path
    ) -> None:
        """Rollback must preserve an existing cache symlink as a symlink."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        target = cache_dir / "target.pt"
        target.write_bytes(b"target")
        existing_link = cache_dir / "model1.pt"
        existing_link.symlink_to(target)
        mock_list.return_value = [
            {
                "name": "model1.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model1.pt",
                "size": 3,
                "size_known": True,
                "human_size": "3.0 B",
            },
            {
                "name": "model2.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model2.pt",
                "size": 3,
                "size_known": True,
                "human_size": "3.0 B",
            },
        ]

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            path = cache_dir / Path(url).name
            if path.name == "model2.pt":
                raise OSError("second download failed")
            path.unlink()
            path.write_bytes(b"new")
            return path

        mock_download.side_effect = download_side_effect
        with pytest.raises(Exception, match="JFrog folder download failed"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=cache_dir,
                show_progress=False,
                max_size=6,
            )

        assert existing_link.is_symlink()
        assert os.path.samefile(existing_link, target)
        assert target.read_bytes() == b"target"
        assert mock_download.call_count == 2

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
        openvino_payload = b'<?xml version="1.0"?><net name="model" version="10"></net>'
        pmml_payload = b'<?xml version="1.0"?><PMML version="4.4"></PMML>'
        flax_payload = b"\x81\xa6params\x81\xa1x\x01"
        llamafile_payload = b"\x7fELF" + (b"\x00" * 16) + b"llamafile runtime"
        pickle_payload = (b"\x8c\x01x0" * 8) + b"\x8c\x02os\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94."
        bounded_pickle_payload = (
            b"\x8c\x01x0" * ((64 * 1024) // 4)
        ) + b"\x8c\x02os\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94."
        payloads = {
            "https://company.jfrog.io/artifactory/repo/models/cntk.payload": cntk_payload,
            "https://company.jfrog.io/artifactory/repo/models/lightgbm.payload": lightgbm_payload,
            "https://company.jfrog.io/artifactory/repo/models/torch7.payload": torch7_payload,
            "https://company.jfrog.io/artifactory/repo/models/executorch.payload": executorch_payload,
            "https://company.jfrog.io/artifactory/repo/models/mxnet.payload": mxnet_payload,
            "https://company.jfrog.io/artifactory/repo/models/openvino.payload": openvino_payload,
            "https://company.jfrog.io/artifactory/repo/models/pmml.payload": pmml_payload,
            "https://company.jfrog.io/artifactory/repo/models/flax.payload": flax_payload,
            "https://company.jfrog.io/artifactory/repo/models/llamafile.payload": llamafile_payload,
            "https://company.jfrog.io/artifactory/repo/models/pickle.payload": pickle_payload,
            "https://company.jfrog.io/artifactory/repo/models/bounded-pickle.payload": bounded_pickle_payload,
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
            require_same_origin_redirects=True,
        )

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_scanner_selection_preserves_bounded_jax_json_candidates(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """JAX-only scans must preserve identities or objects beyond the remote probe window."""
        late_identity_url = "https://company.jfrog.io/artifactory/repo/models/late-identity.payload"
        late_object_url = "https://company.jfrog.io/artifactory/repo/models/late-object.payload"
        near_match_url = "https://company.jfrog.io/artifactory/repo/models/ajax.payload"
        payloads = {
            late_identity_url: (b'{"padding":"' + (b"x" * 70_000) + b'","framework":"jax","checkpoint_type":"orbax"}'),
            late_object_url: (b" " * 70_000) + b'{"framework":"jax"}',
            near_match_url: b'{"framework":"ajax","format":"checkpoint"}',
        }
        mock_list.return_value = [
            {"name": Path(urlparse(url).path).name, "path": url, "size": len(payload), "human_size": "Unknown"}
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
            scanner_selection=scanner_selection_config_from_inputs(scanners=["jax_checkpoint"]),
        )

        assert {call.args[0] for call in mock_download.call_args_list} == {late_identity_url, late_object_url}
        assert not (tmp_path / "ajax.payload").exists()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_selective_includes_truncated_flax_prefix(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Recognized Flax roots must survive values extending past the remote probe window."""
        payload_url = "https://company.jfrog.io/artifactory/repo/models/checkpoint.payload"
        payload = b"\x81\xa6params\xc6" + (100_000).to_bytes(4, "big") + (b"x" * 100_000)
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
            scanner_selection=scanner_selection_config_from_inputs(scanners=["flax_msgpack"]),
        )

        assert mock_get.call_args.kwargs["headers"]["Range"] == "bytes=0-65535"
        mock_download.assert_called_once_with(
            payload_url,
            cache_dir=tmp_path,
            api_token=None,
            access_token=None,
            timeout=30,
            require_same_origin_redirects=True,
        )

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_selective_includes_inconclusive_flax_prefix(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Flax probes that exhaust their bounded prefix must fail closed."""
        payload_url = "https://company.jfrog.io/artifactory/repo/models/checkpoint.payload"
        payload = b"\xa0" * 100_000
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
            scanner_selection=scanner_selection_config_from_inputs(scanners=["flax_msgpack"]),
        )

        assert mock_get.call_args.kwargs["headers"]["Range"] == "bytes=0-65535"
        mock_download.assert_called_once_with(
            payload_url,
            cache_dir=tmp_path,
            api_token=None,
            access_token=None,
            timeout=30,
            require_same_origin_redirects=True,
        )

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_scanner_selection_preserves_xgboost_content_routes(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """XGBoost-only scans should preserve bounded UBJSON and MXNet-overlap routes."""
        extensionless_url = "https://company.jfrog.io/artifactory/repo/models/booster"
        inconclusive_url = "https://company.jfrog.io/artifactory/repo/models/large-booster"
        overlap_url = "https://company.jfrog.io/artifactory/repo/models/polyglot.payload"
        benign_url = "https://company.jfrog.io/artifactory/repo/models/manifest"
        extensionless_payload = (
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
        inconclusive_payload = (
            b"{"
            + _ubjson_key(b"learner")
            + b"{"
            + _ubjson_key(b"metadata")
            + _ubjson_string(b"x" * 100_000)
            + _ubjson_key(b"learner_model_param")
            + b"{}"
            + b"}"
            + b"}"
        )
        overlap_payload = (
            b'{"version":[1,7,4],"learner":{"gradient_booster":{}},'
            b'"nodes":[{"op":"Custom","name":"load"}],"arg_nodes":[0],"heads":[[0,0,0]]}'
        )
        benign_payload = b'{"kind":"manifest","safe":true}'
        payloads = {
            extensionless_url: extensionless_payload,
            inconclusive_url: inconclusive_payload,
            overlap_url: overlap_payload,
            benign_url: benign_payload,
        }
        mock_list.return_value = [
            {"name": Path(urlparse(url).path).name, "path": url, "size": len(payload), "human_size": "Unknown"}
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
            scanner_selection=scanner_selection_config_from_inputs(scanners=["xgboost"]),
        )

        assert {call.args[0] for call in mock_download.call_args_list} == {
            extensionless_url,
            inconclusive_url,
            overlap_url,
        }
        assert not (tmp_path / "manifest").exists()

    def test_jfrog_inconclusive_xgboost_ubjson_candidates_include_xgboost_owner(self) -> None:
        scanner_ids = _scanner_ids_for_detected_jfrog_format(XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT)

        assert scanner_ids == {"xgboost"}

    def test_jfrog_inconclusive_json_candidates_include_jax_and_mxnet_owners(self) -> None:
        scanner_ids = _scanner_ids_for_detected_jfrog_format(MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT)

        assert scanner_ids == {"jax_checkpoint", "mxnet"}

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

        with pytest.raises(ValueError, match="No scannable model files found"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                show_progress=False,
                scanner_selection=scanner_selection_config_from_inputs(scanners=["mxnet"]),
            )

        assert mock_get.call_count == 1
        assert mock_get.call_args.kwargs["headers"]["Range"] == "bytes=0-65535"
        mock_download.assert_not_called()

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
            "https://company.jfrog.io/artifactory/repo/models/xml.payload": (
                b'<?xml version="1.0"?><project><model name="not-a-model-format"/></project>'
            ),
            "https://company.jfrog.io/artifactory/repo/models/flax.payload": b"\x81\xa4name\xa5value",
            "https://company.jfrog.io/artifactory/repo/models/llamafile.payload": (
                b"\x7fELF" + (b"\x00" * 16) + b"generic runtime"
            ),
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

    @pytest.mark.parametrize("detected_format", ["tar", "gzip", "bzip2", "xz"])
    def test_jfrog_tar_candidates_include_nemo_scanner_owner(self, detected_format: str) -> None:
        """Selected NeMo scans should preserve renamed TAR-backed candidates."""
        assert "nemo" in _scanner_ids_for_detected_jfrog_format(detected_format)

    @pytest.mark.parametrize("detected_format", ["gzip", "bzip2", "xz"])
    def test_jfrog_compressed_candidates_include_tar_scanner_owner(self, detected_format: str) -> None:
        """Selected TAR scans should preserve renamed compressed TAR candidates."""
        assert "tar" in _scanner_ids_for_detected_jfrog_format(detected_format)

    @pytest.mark.parametrize("detected_format", [EXECUTABLE_ZIP_POLYGLOT_FORMAT, LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT])
    def test_jfrog_executable_candidates_include_zip_scanner_owners(self, detected_format: str) -> None:
        """Executable ZIP candidates should remain eligible for local archive routing."""
        scanner_ids = _scanner_ids_for_detected_jfrog_format(detected_format)

        assert "zip" in scanner_ids
        if detected_format == LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT:
            assert "llamafile" in scanner_ids

    def test_jfrog_inconclusive_xml_candidates_include_model_scanner_owners(self) -> None:
        """Truncated renamed XML probes should remain eligible for both XML model scanners."""
        scanner_ids = _scanner_ids_for_detected_jfrog_format("xml_model_inconclusive")

        assert {"openvino", "pmml"} <= scanner_ids

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
        redirected_url = "https://company.jfrog.io/downloads/evil.payload?download=1"
        redirect_response = _FakeStreamingResponse(b"", status_code=307, headers={"Location": redirected_url})
        redirect_response.cookies = requests.cookies.cookiejar_from_dict({"ROUTEID": "backend-a"})
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

        assert mock_get.call_args_list[1].args[0] == redirected_url
        assert mock_get.call_args_list[1].kwargs["headers"]["X-JFrog-Art-Api"] == "test-token"
        assert mock_get.call_args_list[1].kwargs["headers"]["Range"] == "bytes=0-65535"
        assert mock_get.call_args_list[0].kwargs["cookies"] is mock_get.call_args_list[1].kwargs["cookies"]
        assert mock_get.call_args_list[1].kwargs["cookies"].get("ROUTEID") == "backend-a"
        assert redirect_response.closed is True
        mock_download.assert_called_once_with(
            hidden_url,
            cache_dir=tmp_path,
            api_token="test-token",
            access_token=None,
            timeout=30,
            require_same_origin_redirects=True,
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
            hidden_url,
            cache_dir=tmp_path,
            api_token="test-token",
            access_token=None,
            timeout=30,
            require_same_origin_redirects=True,
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
            require_same_origin_redirects=True,
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
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zip_archive:
            zip_archive.writestr("archive/data.pkl", b"N.")
            zip_archive.writestr("archive/version", b"3")
        payload = archive.getvalue()
        mock_list.return_value = [
            {"name": "model.payload", "path": zip_url, "size": len(payload), "human_size": f"{len(payload)} B"}
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
            scanner_selection=scanner_selection_config_from_inputs(scanners=["pytorch_zip"]),
        )

        mock_download.assert_called_once()
        assert (tmp_path / "model.payload").exists()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_skips_benign_zip_content(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Renamed document archives should not be downloaded as model ZIPs."""
        zip_url = "https://company.jfrog.io/artifactory/repo/models/document.payload"
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zip_archive:
            zip_archive.writestr("[Content_Types].xml", b"<Types />")
            zip_archive.writestr("word/document.xml", b"<document />")
        payload = archive.getvalue()
        mock_list.return_value = [
            {"name": "document.payload", "path": zip_url, "size": len(payload), "human_size": f"{len(payload)} B"}
        ]
        mock_get.return_value = _FakeStreamingResponse(payload)

        with pytest.raises(ValueError, match="No scannable model files found"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                show_progress=False,
            )

        mock_download.assert_not_called()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_fails_closed_on_incomplete_zip_probe(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A ZIP larger than the bounded prefix must not be skipped or downloaded blindly."""
        zip_url = "https://company.jfrog.io/artifactory/repo/models/archive.payload"
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zip_archive:
            zip_archive.writestr("padding.bin", b"x" * (64 * 1024))
            zip_archive.writestr("model.pkl", b"cos\nsystem\n(S'echo pwned'\ntR.")
        payload = archive.getvalue()
        mock_list.return_value = [
            {"name": "archive.payload", "path": zip_url, "size": len(payload), "human_size": f"{len(payload)} B"}
        ]
        mock_get.return_value = _FakeStreamingResponse(payload)

        with pytest.raises(ValueError, match="selective filtering incomplete"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                show_progress=False,
            )

        mock_download.assert_not_called()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_scanner_selection_preserves_executable_zip_polyglot(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """ZIP-only scans should retain self-extracting archives while rejecting benign executables."""
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zip_archive:
            zip_archive.writestr("model.pkl", b"payload")
        polyglot_url = "https://company.jfrog.io/artifactory/repo/models/polyglot.payload"
        benign_url = "https://company.jfrog.io/artifactory/repo/models/tool.payload"
        payloads = {
            polyglot_url: b"\x7fELF" + (b"\x00" * 16) + archive.getvalue(),
            benign_url: b"\x7fELF" + (b"\x00" * 64) + b"ordinary executable",
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
            scanner_selection=scanner_selection_config_from_inputs(scanners=["zip"]),
        )

        assert [call.args[0] for call in mock_download.call_args_list] == [polyglot_url]
        assert not (tmp_path / "tool.payload").exists()

    @patch("modelaudit.utils.sources.jfrog.requests.get")
    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_scanner_selection_preserves_compressed_tar_candidate(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        mock_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """TAR-only scans should retain renamed compressed TAR candidates."""
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as archive:
            member = tarfile.TarInfo("model.pkl")
            member.size = len(b"payload")
            archive.addfile(member, io.BytesIO(b"payload"))
        payload_url = "https://company.jfrog.io/artifactory/repo/models/archive.payload"
        payload = tar_buffer.getvalue()
        mock_list.return_value = [
            {"name": "archive.payload", "path": payload_url, "size": len(payload), "human_size": "Unknown"}
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
            scanner_selection=scanner_selection_config_from_inputs(scanners=["tar"]),
        )

        mock_download.assert_called_once()

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

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_scanner_selection_includes_exact_filename(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        readme_url = "https://company.jfrog.io/artifactory/repo/models/README"
        mock_list.return_value = [
            {"name": "README", "path": readme_url, "size": 8, "size_known": True, "human_size": "8 B"}
        ]

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            downloaded_file = cache_dir / Path(urlparse(url).path).name
            downloaded_file.write_text("model docs", encoding="utf-8")
            return downloaded_file

        mock_download.side_effect = download_side_effect
        policy = resolve_scanner_selection_policy(scanners=["metadata"])

        download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            show_progress=False,
            scannable_extensions=selected_scanner_extensions(policy, conservative=True),
            scannable_filenames=selected_scanner_filenames(policy, conservative=True),
            scanner_selection=policy.to_config(),
        )

        mock_download.assert_called_once()
        assert (tmp_path / "README").read_text(encoding="utf-8") == "model docs"

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
    def test_download_jfrog_folder_rejects_traversal_paths(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that traversal paths from JFrog metadata are rejected."""
        mock_list.return_value = [
            {
                "name": "../../escape.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/../../escape.pkl",
                "size": 1024,
                "human_size": "1.0 KB",
            }
        ]

        with pytest.raises(ValueError, match="Unsafe JFrog artifact path"):
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
    def test_download_jfrog_folder_rejects_case_insensitive_local_collisions(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Folder downloads must fail closed before local case aliases overwrite each other."""
        mock_list.return_value = [
            {
                "name": "Model.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/Model.pkl",
                "size": 8,
                "human_size": "8 B",
            },
            {
                "name": "model.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/model.pkl",
                "size": 8,
                "human_size": "8 B",
            },
        ]

        with pytest.raises(ValueError, match="Colliding local JFrog artifact paths"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                show_progress=False,
            )

        mock_download.assert_not_called()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_rejects_trailing_dot_local_collisions(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Windows trailing-dot aliases must fail before either artifact is downloaded."""
        mock_list.return_value = [
            {
                "name": "team/model.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/team/model.pkl",
                "size": 8,
                "human_size": "8 B",
            },
            {
                "name": "team./model.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/team./model.pkl",
                "size": 8,
                "human_size": "8 B",
            },
        ]

        with pytest.raises(ValueError, match="Colliding local JFrog artifact paths"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                show_progress=False,
            )

        mock_download.assert_not_called()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_rejects_file_directory_local_collisions(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A selected file must not alias another selected artifact's parent directory."""
        mock_list.return_value = [
            {
                "name": "model.pkl/child.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model.pkl/child.pt",
                "size": 8,
                "human_size": "8 B",
            },
            {
                "name": "Model.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/Model.pkl",
                "size": 8,
                "human_size": "8 B",
            },
        ]

        with pytest.raises(ValueError, match="Colliding local JFrog artifact paths"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                show_progress=False,
            )

        mock_download.assert_not_called()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_rejects_ntfs_alternate_data_stream_paths(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """NTFS alternate data streams must not hide selected artifacts from directory scans."""
        mock_list.return_value = [
            {
                "name": "model.pkl:payload",
                "path": "https://company.jfrog.io/artifactory/repo/models/model.pkl:payload",
                "size": 8,
                "human_size": "8 B",
            }
        ]

        with pytest.raises(ValueError, match="Unsafe JFrog artifact path"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                selective=False,
                show_progress=False,
            )

        mock_download.assert_not_called()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_rejects_windows_reserved_device_names(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """DOS device basenames remain reserved even when an extension is present."""
        mock_list.return_value = [
            {
                "name": "NUL.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/NUL.pkl",
                "size": 8,
                "human_size": "8 B",
            }
        ]

        with pytest.raises(ValueError, match="Unsafe JFrog artifact path"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                show_progress=False,
            )

        mock_download.assert_not_called()
        assert not any(tmp_path.iterdir())

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_allows_reserved_name_near_match(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Ordinary names that merely contain a reserved token must remain downloadable."""
        artifact_url = "https://company.jfrog.io/artifactory/repo/models/null.pkl"
        mock_list.return_value = [{"name": "null.pkl", "path": artifact_url, "size": 8, "human_size": "8 B"}]

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            downloaded_file = cache_dir / Path(urlparse(url).path).name
            downloaded_file.write_bytes(b"payload")
            return downloaded_file

        mock_download.side_effect = download_side_effect

        download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            show_progress=False,
        )

        assert (tmp_path / "null.pkl").read_bytes() == b"payload"

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_uses_prepared_destination_filenames(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Raw URL basenames must not create transient aliases before the final rename."""
        plain_url = "https://company.jfrog.io/artifactory/repo/models/model.pkl"
        spaced_url = "https://company.jfrog.io/artifactory/repo/models/model.pkl "
        mock_list.return_value = [
            {"name": "model.pkl", "path": plain_url, "size": 8, "human_size": "8 B"},
            {"name": "model.pkl ", "path": spaced_url, "size": 8, "human_size": "8 B"},
        ]

        def download_side_effect(url: str, cache_dir: Path, **kwargs: object) -> Path:
            destination_filename = cast(str, kwargs.get("_destination_filename", Path(urlparse(url).path).name))
            downloaded_file = cache_dir / destination_filename
            downloaded_file.write_text(url, encoding="utf-8")
            return downloaded_file

        mock_download.side_effect = download_side_effect

        download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            selective=False,
            show_progress=False,
        )

        assert (tmp_path / "model.pkl").read_text(encoding="utf-8") == plain_url
        assert (tmp_path / "model.pkl%20").read_text(encoding="utf-8") == spaced_url
        assert "_destination_filename" not in mock_download.call_args_list[0].kwargs
        assert mock_download.call_args_list[1].kwargs["_destination_filename"] == "model.pkl%20"

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_rejects_canonical_local_path_collisions(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Folder downloads must reject distinct remote names resolving to one local path."""
        real_dir = tmp_path / "real"
        alias_dir = tmp_path / "alias"
        real_dir.mkdir()
        try:
            alias_dir.symlink_to(real_dir, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"directory symlinks unavailable: {exc}")

        mock_list.return_value = [
            {
                "name": "alias/model.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/alias/model.pkl",
                "size": 8,
                "human_size": "8 B",
            },
            {
                "name": "real/model.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/real/model.pkl",
                "size": 8,
                "human_size": "8 B",
            },
        ]

        with pytest.raises(ValueError, match="Colliding local JFrog artifact paths"):
            download_jfrog_folder(
                "https://company.jfrog.io/artifactory/repo/models/",
                cache_dir=tmp_path,
                show_progress=False,
            )

        mock_download.assert_not_called()
        assert not (real_dir / "model.pkl").exists()

    @patch("modelaudit.utils.sources.jfrog.download_artifact")
    @patch("modelaudit.utils.sources.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_allows_benign_distinct_local_names(
        self,
        mock_list: MagicMock,
        mock_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Distinct local paths should still download normally."""
        first_url = "https://company.jfrog.io/artifactory/repo/models/team-a/model.pkl"
        second_url = "https://company.jfrog.io/artifactory/repo/models/team-b/model.pkl"
        mock_list.return_value = [
            {"name": "team-a/model.pkl", "path": first_url, "size": 8, "human_size": "8 B"},
            {"name": "team-b/model.pkl", "path": second_url, "size": 8, "human_size": "8 B"},
        ]

        def download_side_effect(url: str, cache_dir: Path, **_kwargs: object) -> Path:
            downloaded_file = cache_dir / Path(urlparse(url).path).name
            downloaded_file.write_bytes(b"payload")
            return downloaded_file

        mock_download.side_effect = download_side_effect

        download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/",
            cache_dir=tmp_path,
            show_progress=False,
        )

        assert [call.args[0] for call in mock_download.call_args_list] == [first_url, second_url]
        assert (tmp_path / "team-a" / "model.pkl").read_bytes() == b"payload"
        assert (tmp_path / "team-b" / "model.pkl").read_bytes() == b"payload"

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
