import bz2
import gzip
import io
import json
import lzma
import pickle
import tarfile
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners import get_scanner_for_file
from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.compressed_scanner import CompressedScanner, _MissingOptionalDependencyError

TarWriteMode = Literal["w:gz", "w:bz2", "w:xz"]


class _MaliciousPayload:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (eval, ("print('owned')",))


_LZ4_FRAME_MAGIC = b"\x04\x22\x4d\x18"


class _FakeLz4FrameDecompressor:
    def __init__(self, frames: dict[bytes, bytes], error_type: type[RuntimeError]) -> None:
        self.frames = frames
        self.error_type = error_type
        self.max_lengths: list[int] = []
        self.eof = False
        self.needs_input = True
        self.unused_data = b""

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        self.max_lengths.append(max_length)
        if not data.startswith(_LZ4_FRAME_MAGIC):
            raise self.error_type("Invalid lz4 frame")

        marker_start = len(_LZ4_FRAME_MAGIC)
        marker = data[marker_start : marker_start + 1]
        if marker not in self.frames:
            raise self.error_type("Invalid lz4 frame")

        output = self.frames[marker]
        if max_length >= 0 and len(output) > max_length:
            raise AssertionError("Fake lz4 frame output exceeded max_length")

        self.eof = True
        self.needs_input = True
        self.unused_data = data[marker_start + 1 :]
        return output


class _FakeLz4FrameModule:
    class LZ4FrameError(RuntimeError):
        pass

    def __init__(self, frames: dict[bytes, bytes]) -> None:
        self.frames = frames
        self.decompressors: list[_FakeLz4FrameDecompressor] = []
        self.LZ4FrameDecompressor: Callable[[], _FakeLz4FrameDecompressor] = self._create_decompressor

    def _create_decompressor(self) -> _FakeLz4FrameDecompressor:
        decompressor = _FakeLz4FrameDecompressor(self.frames, self.LZ4FrameError)
        self.decompressors.append(decompressor)
        return decompressor


class _FakeLz4ChunkContext:
    def __init__(self, frames: dict[bytes, bytes], error_type: type[RuntimeError]) -> None:
        self.frames = frames
        self.error_type = error_type
        self.max_lengths: list[int] = []

    def decompress_chunk(self, data: bytes, max_length: int = -1) -> tuple[bytes, int, bool]:
        self.max_lengths.append(max_length)
        if not data.startswith(_LZ4_FRAME_MAGIC):
            raise self.error_type("Invalid lz4 frame")

        marker_start = len(_LZ4_FRAME_MAGIC)
        marker = data[marker_start : marker_start + 1]
        if marker not in self.frames:
            raise self.error_type("Invalid lz4 frame")

        output = self.frames[marker]
        if max_length >= 0 and len(output) > max_length:
            raise AssertionError("Fake lz4 frame output exceeded max_length")

        return output, marker_start + 1, True


class _FakeLz4ChunkModule:
    class LZ4FrameError(RuntimeError):
        pass

    def __init__(self, frames: dict[bytes, bytes]) -> None:
        self.frames = frames
        self.contexts: list[_FakeLz4ChunkContext] = []

    def create_decompression_context(self) -> _FakeLz4ChunkContext:
        context = _FakeLz4ChunkContext(self.frames, self.LZ4FrameError)
        self.contexts.append(context)
        return context

    def decompress_chunk(
        self,
        context: _FakeLz4ChunkContext,
        data: bytes,
        max_length: int = -1,
    ) -> tuple[bytes, int, bool]:
        return context.decompress_chunk(data, max_length=max_length)


def test_compressed_scanner_can_handle_requires_matching_signature(tmp_path: Path) -> None:
    valid_gzip_path = tmp_path / "model.pkl.gz"
    valid_gzip_path.write_bytes(gzip.compress(pickle.dumps({"weights": [1, 2, 3]})))

    invalid_gzip_path = tmp_path / "model.txt.gz"
    invalid_gzip_path.write_bytes(b"not-gzip")

    assert CompressedScanner.can_handle(str(valid_gzip_path)) is True
    assert CompressedScanner.can_handle(str(invalid_gzip_path)) is False


@pytest.mark.parametrize(
    ("filename", "expected_suffix"),
    [
        ("model.gz", ".bin"),
        ("weights.xz", ".bin"),
        ("tokenizer.gz", ""),
        ("spiece.gz", ""),
        ("tokenizer.model.gz", ".model"),
    ],
)
def test_declared_compressed_inner_suffix_preserves_routing_intent(
    filename: str,
    expected_suffix: str,
) -> None:
    assert CompressedScanner._derive_inner_suffix(filename) == expected_suffix


def test_bare_compressed_raw_binary_routes_inner_as_pytorch_binary(tmp_path: Path) -> None:
    wrapper = tmp_path / "model.gz"
    wrapper.write_bytes(gzip.compress(b"raw binary weights" + b"\0" * 128))

    result = scan_model_directory_or_file(str(wrapper), cache_enabled=False)
    metadata = result.file_metadata[str(wrapper)]
    metadata_extra = metadata.model_extra or {}

    assert result.success is True
    assert metadata_extra["scanner_dependency_ids"] == ["compressed", "pytorch_binary"]
    assert metadata_extra["decompressed_bytes"] == 146


def test_tokenizer_gzip_raw_binary_routes_inner_as_pytorch_binary_security_scan(tmp_path: Path) -> None:
    wrapper = tmp_path / "tokenizer.gz"
    wrapper.write_bytes(gzip.compress(b"\0" * 50 + b"CONFIDENTIAL_DATA" + b"\0" * 50))

    result = scan_model_directory_or_file(
        str(wrapper),
        blacklist_patterns=["CONFIDENTIAL"],
        cache_enabled=False,
    )
    metadata = result.file_metadata[str(wrapper)]
    metadata_extra = metadata.model_extra or {}

    assert determine_exit_code(result) == 1
    assert metadata_extra["scanner_dependency_ids"] == ["compressed", "pytorch_binary"]
    assert any(issue.rule_code == "S1001" and "CONFIDENTIAL" in issue.message for issue in result.issues)


def test_compressed_scanner_can_handle_header_routed_misnamed_wrapper(tmp_path: Path) -> None:
    disguised_gzip_path = tmp_path / "model.jpg"
    disguised_gzip_path.write_bytes(gzip.compress(pickle.dumps({"weights": [1, 2, 3]})))

    near_match_path = tmp_path / "near-match.jpg"
    near_match_path.write_bytes(b"\x1f\x00not-a-gzip-stream")

    assert CompressedScanner.can_handle(str(disguised_gzip_path)) is True
    assert CompressedScanner.can_handle(str(near_match_path)) is False


def test_registry_routes_misnamed_compressed_malicious_payload_and_rejects_near_match(tmp_path: Path) -> None:
    payload_path = tmp_path / "payload.jpg"
    payload_path.write_bytes(gzip.compress(pickle.dumps({"payload": _MaliciousPayload()})))
    near_match_path = tmp_path / "near-match.jpg"
    near_match_path.write_bytes(b"\x1f\x00not-a-gzip-stream")

    scanner = get_scanner_for_file(str(payload_path))

    assert scanner is not None
    assert scanner.name == "compressed"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in scanner.scan(str(payload_path)).issues)
    assert get_scanner_for_file(str(near_match_path)) is None


def test_compressed_scanner_can_handle_rejects_invalid_zlib_header_near_match(tmp_path: Path) -> None:
    zlib_path = tmp_path / "payload.bin.zlib"
    zlib_path.write_bytes(b"\x78\x00" + b"not-a-valid-zlib-stream")

    assert CompressedScanner.can_handle(str(zlib_path)) is False


@pytest.mark.parametrize(
    ("filename", "mode"),
    [
        ("model.tar.gz", "w:gz"),
        ("model.tar.bz2", "w:bz2"),
        ("model.tar.xz", "w:xz"),
    ],
)
def test_compound_tar_wrappers_route_to_tar_scanner(
    tmp_path: Path,
    filename: str,
    mode: TarWriteMode,
) -> None:
    archive_path = tmp_path / filename
    payload = b"weights"

    with tarfile.open(archive_path, mode) as tar:
        info = tarfile.TarInfo("weights.bin")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

    scanner = get_scanner_for_file(str(archive_path))

    assert scanner is not None
    assert scanner.name == "tar"


def test_truncated_compound_tar_wrapper_routes_to_compressed_scanner(tmp_path: Path) -> None:
    archive_path = tmp_path / "truncated.tar.gz"
    archive_path.write_bytes(b"\x1f\x8b\x08\x00\x00\x00\x00\x00")

    scanner = get_scanner_for_file(str(archive_path))

    assert scanner is not None
    assert scanner.name == "compressed"


@pytest.mark.parametrize(
    ("filename", "mode"),
    [
        ("safe.tar.gz", "w:gz"),
        ("safe.tar.bz2", "w:bz2"),
        ("safe.tar.xz", "w:xz"),
    ],
)
def test_compound_tar_wrappers_scan_benign_payloads_without_critical_findings(
    tmp_path: Path,
    filename: str,
    mode: TarWriteMode,
) -> None:
    archive_path = tmp_path / filename
    payload = pickle.dumps({"weights": [1, 2, 3]})

    with tarfile.open(archive_path, mode) as tar:
        info = tarfile.TarInfo("safe.pkl")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

    scanner = get_scanner_for_file(str(archive_path))

    assert scanner is not None
    assert scanner.name == "tar"

    result = scanner.scan(str(archive_path))
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]

    assert critical_issues == []


@pytest.mark.parametrize(
    ("filename", "mode"),
    [
        ("malicious.tar.gz", "w:gz"),
        ("malicious.tar.bz2", "w:bz2"),
        ("malicious.tar.xz", "w:xz"),
    ],
)
def test_compound_tar_wrappers_surface_malicious_inner_findings(
    tmp_path: Path,
    filename: str,
    mode: TarWriteMode,
) -> None:
    archive_path = tmp_path / filename
    payload = pickle.dumps({"payload": _MaliciousPayload()})

    with tarfile.open(archive_path, mode) as tar:
        info = tarfile.TarInfo("evil.pkl")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

    scanner = get_scanner_for_file(str(archive_path))

    assert scanner is not None
    assert scanner.name == "tar"

    result = scanner.scan(str(archive_path))
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]

    assert critical_issues
    assert any("eval" in issue.message.lower() for issue in critical_issues)
    assert any(issue.location == f"{archive_path}:evil.pkl" for issue in critical_issues)


def test_compressed_scanner_routes_benign_inner_payload(tmp_path: Path) -> None:
    safe_pickle = pickle.dumps({"layer": [1, 2, 3]})
    path = tmp_path / "safe_model.pkl.gz"
    path.write_bytes(gzip.compress(safe_pickle))

    scanner = CompressedScanner()
    result = scanner.scan(str(path))

    assert result.success is True

    routing_checks = [c for c in result.checks if c.name == "Compressed Wrapper Inner Scanner Routing"]
    assert routing_checks and routing_checks[0].status == CheckStatus.PASSED

    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert len(critical_issues) == 0


def test_compressed_scanner_surfaces_malicious_inner_findings(tmp_path: Path) -> None:
    malicious_pickle = pickle.dumps({"payload": _MaliciousPayload()})
    path = tmp_path / "malicious.pkl.gz"
    path.write_bytes(gzip.compress(malicious_pickle))

    scanner = CompressedScanner()
    result = scanner.scan(str(path))

    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]

    assert critical_issues
    assert any("eval" in issue.message.lower() for issue in critical_issues)
    assert any(issue.location == f"{path} -> malicious.pkl" for issue in critical_issues)


def test_compressed_scanner_surfaces_malicious_inner_findings_from_zlib_wrapper(tmp_path: Path) -> None:
    malicious_pickle = pickle.dumps({"payload": _MaliciousPayload()})
    path = tmp_path / "malicious.pkl.zlib"
    path.write_bytes(zlib.compress(malicious_pickle))

    scanner = CompressedScanner()
    result = scanner.scan(str(path))

    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]

    assert critical_issues
    assert any("eval" in issue.message.lower() for issue in critical_issues)
    assert any(issue.location == f"{path} -> malicious.pkl" for issue in critical_issues)


def test_compressed_scanner_surfaces_high_risk_python_payload(tmp_path: Path) -> None:
    path = tmp_path / "evil.py.gz"
    path.write_bytes(gzip.compress(b'import os\nos.system("echo hidden")\n'))

    result = CompressedScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
    assert any(check.rule_code == "S101" for check in python_checks)
    assert any(check.location == f"{path} -> evil.py" for check in python_checks)
    assert determine_exit_code(aggregate) == 1


def test_compressed_scanner_header_routed_python_payload_preserves_security_name(tmp_path: Path) -> None:
    path = tmp_path / "evil.py"
    path.write_bytes(gzip.compress(b'import os\nos.system("echo hidden")\n'))

    result = CompressedScanner().scan(str(path))

    python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
    assert any(check.rule_code == "S101" for check in python_checks)
    assert any(check.location == f"{path} -> evil.py.inner" for check in python_checks)


def test_compressed_scanner_nested_python_payload_preserves_security_name(tmp_path: Path) -> None:
    path = tmp_path / "evil.py.gz.gz"
    path.write_bytes(gzip.compress(gzip.compress(b'import os\nos.system("echo hidden")\n')))

    result = CompressedScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
    assert any(check.rule_code == "S101" for check in python_checks)
    assert determine_exit_code(aggregate) == 1


def test_compressed_scanner_python_named_executable_bytes_still_report_executable(tmp_path: Path) -> None:
    path = tmp_path / "native.py.gz"
    path.write_bytes(gzip.compress(b"\x7fELF" + b"\x00" * 48))

    result = CompressedScanner().scan(str(path))

    executable_checks = [check for check in result.checks if check.name == "Executable Archive Member Detection"]
    assert executable_checks
    assert executable_checks[0].location == f"{path} -> native.py"


def test_compressed_scanner_python_named_non_python_shebang_reports_executable(tmp_path: Path) -> None:
    path = tmp_path / "script.py.gz"
    path.write_bytes(gzip.compress(b"#!/bin/sh\nrm -rf /tmp/pwned\n"))

    result = CompressedScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    executable_checks = [check for check in result.checks if check.name == "Executable Archive Member Detection"]
    assert executable_checks
    assert executable_checks[0].location == f"{path} -> script.py"
    assert determine_exit_code(aggregate) == 1


def test_compressed_scanner_oversized_python_named_shebang_still_reports_executable(tmp_path: Path) -> None:
    path = tmp_path / "script.py.gz"
    payload = b"#!/bin/sh\n" + (b"# filler\n" * ((CompressedScanner.MAX_PYTHON_PAYLOAD_ANALYSIS_BYTES // 9) + 1))
    path.write_bytes(gzip.compress(payload))

    result = CompressedScanner(config={"compressed_max_decompression_ratio": 10000.0}).scan(str(path))
    aggregate = scan_model_directory_or_file(
        str(path),
        cache_enabled=False,
        compressed_max_decompression_ratio=10000.0,
    )

    assert result.metadata["scan_outcome_reasons"] == ["compressed_python_payload_analysis_incomplete"]
    executable_checks = [check for check in result.checks if check.name == "Executable Archive Member Detection"]
    assert executable_checks
    assert executable_checks[0].location == f"{path} -> script.py"
    assert determine_exit_code(aggregate) == 1


def test_compressed_scanner_surfaces_content_disguised_executable_payload(tmp_path: Path) -> None:
    path = tmp_path / "payload.dat.gz"
    path.write_bytes(gzip.compress(b"\x7fELF" + b"\x00" * 48))

    result = CompressedScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    executable_checks = [check for check in result.checks if check.name == "Executable Archive Member Detection"]
    assert len(executable_checks) == 1
    assert executable_checks[0].location == f"{path} -> payload.dat"
    assert determine_exit_code(aggregate) == 1


def test_compressed_scanner_benign_llamafile_uses_owned_executable_analysis(tmp_path: Path) -> None:
    path = tmp_path / "safe.llamafile.gz"
    payload = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llamafile runtime\n--threads 4\n"
    path.write_bytes(gzip.compress(payload))

    result = CompressedScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    routing_checks = [check for check in result.checks if check.name == "Compressed Wrapper Inner Scanner Routing"]
    assert routing_checks[0].details["inner_scanner"] == "llamafile"
    assert not any(check.name == "Executable Archive Member Detection" for check in result.checks)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    ("filename", "payload"),
    [
        ("safe.py.gz", b"import math\nanswer = math.sqrt(4)\n"),
        ("safe_shebang.py.gz", b"#!/usr/bin/env python3\nprint('ok')\n"),
        ("safe_env_split.py.gz", b"#!/usr/bin/env -S 'python3 -I'\nprint('ok')\n"),
        ("safe_env_split_long.py.gz", b"#!/usr/bin/env --split-string='python3 -I'\nprint('ok')\n"),
        ("safe.dat.gz", b"weights: [1, 2, 3]\n"),
    ],
)
def test_compressed_scanner_generic_payload_security_benign_controls(
    tmp_path: Path,
    filename: str,
    payload: bytes,
) -> None:
    path = tmp_path / filename
    path.write_bytes(gzip.compress(payload))

    result = CompressedScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert not any(
        check.name in {"Python Archive Member Security", "Executable Archive Member Detection"}
        and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 0


def test_compressed_scanner_unparseable_python_payload_is_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "broken.py.gz"
    path.write_bytes(gzip.compress(b"def incomplete(\n"))

    result = CompressedScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["scan_outcome_reasons"] == ["compressed_python_payload_analysis_incomplete"]

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            min_cache_file_size=0,
        )
        second = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert aggregate.success is False
            assert determine_exit_code(aggregate) == 2
            assert metadata["scan_outcome"] == "inconclusive"
            assert metadata["scan_outcome_reasons"] == ["compressed_python_payload_analysis_incomplete"]
            assert any("could not be parsed" in issue.message.lower() for issue in aggregate.issues)
        assert get_cache_manager(str(tmp_path / "cache"), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_compressed_scanner_corrupt_stream_is_warning_not_critical(tmp_path: Path) -> None:
    path = tmp_path / "broken_payload.gz"
    path.write_bytes(b"\x1f\x8b\x08\x00\x00\x00\x00\x00")

    scanner = CompressedScanner()
    result = scanner.scan(str(path))

    decode_checks = [c for c in result.checks if c.name == "Compressed Wrapper Stream Decode"]
    assert decode_checks and decode_checks[0].status == CheckStatus.FAILED
    assert decode_checks[0].severity == IssueSeverity.WARNING
    assert decode_checks[0].details["scan_outcome_reason"] == "compressed_stream_decode_failed"
    assert result.metadata["scan_outcome_reasons"] == ["compressed_stream_decode_failed"]
    assert result.success is False


@pytest.mark.parametrize(
    ("extension", "compressor"),
    [
        (".bz2", bz2.compress),
        (".xz", lzma.compress),
        (".zlib", zlib.compress),
    ],
)
def test_compressed_scanner_enforces_decompression_size_limit(
    tmp_path: Path,
    extension: str,
    compressor: Callable[[bytes], bytes],
) -> None:
    data = b"A" * 4096
    path = tmp_path / f"oversize_payload.bin{extension}"
    path.write_bytes(compressor(data))

    scanner = CompressedScanner(config={"compressed_max_decompressed_bytes": 512})
    result = scanner.scan(str(path))

    limit_checks = [c for c in result.checks if c.name == "Compressed Wrapper Decompression Limits"]
    assert limit_checks and limit_checks[0].status == CheckStatus.FAILED
    assert "analysis incomplete" in limit_checks[0].message.lower()
    assert limit_checks[0].severity == IssueSeverity.WARNING
    assert limit_checks[0].details["scan_outcome_reason"] == "compressed_decompression_limit_exceeded"
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["scan_outcome_reasons"] == ["compressed_decompression_limit_exceeded"]
    assert result.success is False


def test_compressed_scanner_enforces_decompression_ratio_limit(tmp_path: Path) -> None:
    highly_compressible = b"0" * 20_000
    path = tmp_path / "ratio_payload.bin.gz"
    path.write_bytes(gzip.compress(highly_compressible))

    scanner = CompressedScanner(config={"compressed_max_decompression_ratio": 5.0})
    result = scanner.scan(str(path))

    ratio_checks = [c for c in result.checks if c.name == "Compressed Wrapper Decompression Limits"]
    assert ratio_checks and ratio_checks[0].status == CheckStatus.FAILED
    assert "analysis incomplete" in ratio_checks[0].message.lower()
    assert ratio_checks[0].severity == IssueSeverity.WARNING
    assert ratio_checks[0].details["scan_outcome_reason"] == "compressed_decompression_limit_exceeded"
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["scan_outcome_reasons"] == ["compressed_decompression_limit_exceeded"]
    assert result.success is False


def test_compressed_scanner_false_positive_control_high_ratio_within_policy(tmp_path: Path) -> None:
    highly_compressible = b"0" * 20_000
    path = tmp_path / "policy_ok_payload.txt.gz"
    path.write_bytes(gzip.compress(highly_compressible))

    scanner = CompressedScanner(
        config={
            "compressed_max_decompressed_bytes": 64 * 1024,
            "compressed_max_decompression_ratio": 5000.0,
        },
    )
    result = scanner.scan(str(path))

    ratio_failures = [
        c
        for c in result.checks
        if c.name == "Compressed Wrapper Decompression Limits" and c.status == CheckStatus.FAILED
    ]
    assert len(ratio_failures) == 0


def test_compressed_scanner_depth_limit_marks_analysis_incomplete(tmp_path: Path) -> None:
    path = tmp_path / "nested_payload.pkl.gz"
    path.write_bytes(gzip.compress(pickle.dumps({"safe": True})))

    result = CompressedScanner(config={"_compressed_depth": 1, "compressed_max_depth": 1}).scan(str(path))

    depth_checks = [c for c in result.checks if c.name == "Compressed Wrapper Depth Limit"]
    assert depth_checks and depth_checks[0].status == CheckStatus.FAILED
    assert depth_checks[0].details["scan_outcome_reason"] == "compressed_depth_limit_exceeded"
    assert result.metadata["scan_outcome_reasons"] == ["compressed_depth_limit_exceeded"]
    assert result.success is False


def test_read_zlib_stream_uses_bounded_decompression(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeDecompressor:
        def __init__(self) -> None:
            self.max_lengths: list[int] = []
            self.flush_lengths: list[int] = []
            self.eof = True
            self.unconsumed_tail = b""
            self.unused_data = b""

        def decompress(self, _chunk: bytes, max_length: int = 0) -> bytes:
            self.max_lengths.append(max_length)
            return b"x" * min(256, max_length)

        def flush(self, length: int = 0) -> bytes:
            self.flush_lengths.append(length)
            return b""

    fake_decompressor = _FakeDecompressor()

    monkeypatch.setattr(
        "modelaudit.scanners.compressed_scanner.zlib.decompressobj",
        lambda: fake_decompressor,
    )

    CompressedScanner._read_zlib_stream_with_limits(
        source=io.BytesIO(b"compressed"),
        destination=io.BytesIO(),
        max_decompressed_bytes=1024,
        max_ratio=100.0,
        compressed_size=10,
        chunk_size=4,
    )

    assert fake_decompressor.max_lengths
    assert fake_decompressor.max_lengths == [4, 4, 4]
    assert fake_decompressor.flush_lengths == [4]


def test_read_concatenated_stream_uses_chunk_bounded_decompression() -> None:
    class _FakeDecompressor:
        def __init__(self) -> None:
            self.max_lengths: list[int] = []
            self.eof = False
            self.needs_input = True
            self.unused_data = b""

        def decompress(self, _chunk: bytes, max_length: int = 0) -> bytes:
            self.max_lengths.append(max_length)
            self.eof = True
            return b"x" * max_length

    fake_decompressors: list[_FakeDecompressor] = []

    def _factory() -> _FakeDecompressor:
        fake_decompressor = _FakeDecompressor()
        fake_decompressors.append(fake_decompressor)
        return fake_decompressor

    total_out = CompressedScanner._read_concatenated_stream_with_limits(
        source=io.BytesIO(b"x"),
        destination=io.BytesIO(),
        decompressor_factory=_factory,
        error_types=(ValueError,),
        codec="fake",
        max_decompressed_bytes=512 * 1024 * 1024,
        max_ratio=1000.0,
        compressed_size=1,
        chunk_size=8,
    )

    assert total_out == 8
    assert [length for fake in fake_decompressors for length in fake.max_lengths] == [8]


def test_read_concatenated_stream_splits_member_after_chunk_boundary() -> None:
    class _FakeDecompressor:
        def __init__(self) -> None:
            self.eof = False
            self.needs_input = True
            self.unused_data = b""

        def decompress(self, _chunk: bytes, max_length: int = 0) -> bytes:
            self.eof = True
            return b"x"

    new_member_calls: list[None] = []

    CompressedScanner._read_concatenated_stream_with_limits(
        source=io.BytesIO(b"ab"),
        destination=io.BytesIO(),
        decompressor_factory=_FakeDecompressor,
        error_types=(ValueError,),
        codec="fake",
        max_decompressed_bytes=1024,
        max_ratio=1000.0,
        compressed_size=2,
        chunk_size=1,
        on_new_member=lambda: new_member_calls.append(None),
    )

    assert len(new_member_calls) == 1


def test_read_gzip_stream_preserves_buffered_input_when_probe_cap_is_hit() -> None:
    payload = b"x" * 64
    destination = io.BytesIO()

    total_out = CompressedScanner._read_gzip_stream_with_limits(
        source=io.BytesIO(gzip.compress(payload)),
        destination=destination,
        max_decompressed_bytes=1024,
        max_ratio=1000.0,
        compressed_size=1,
        chunk_size=8,
    )

    assert total_out == len(payload)
    assert destination.getvalue() == payload


def test_read_lz4_stream_uses_chunk_bounded_decompression() -> None:
    fake_lz4_frame = _FakeLz4FrameModule({b"S": b"12345678"})
    destination = io.BytesIO()

    total_out = CompressedScanner._read_lz4_stream_with_limits(
        source=io.BytesIO(_LZ4_FRAME_MAGIC + b"S"),
        destination=destination,
        lz4_frame=fake_lz4_frame,
        max_decompressed_bytes=512 * 1024 * 1024,
        max_ratio=1000.0,
        compressed_size=1,
        chunk_size=8,
    )

    assert total_out == 8
    assert destination.getvalue() == b"12345678"
    assert [length for fake in fake_lz4_frame.decompressors for length in fake.max_lengths] == [8]


def test_read_lz4_stream_falls_back_to_chunk_api_when_decompressor_class_missing() -> None:
    fake_lz4_frame = _FakeLz4ChunkModule({b"S": b"12345678"})
    destination = io.BytesIO()

    total_out = CompressedScanner._read_lz4_stream_with_limits(
        source=io.BytesIO(_LZ4_FRAME_MAGIC + b"S"),
        destination=destination,
        lz4_frame=fake_lz4_frame,
        max_decompressed_bytes=512 * 1024 * 1024,
        max_ratio=1000.0,
        compressed_size=1,
        chunk_size=8,
    )

    assert total_out == 8
    assert destination.getvalue() == b"12345678"
    assert [length for context in fake_lz4_frame.contexts for length in context.max_lengths] == [8]


def test_read_zlib_stream_allows_exact_limit_real_stream() -> None:
    payload = b"A" * 1024
    compressed = zlib.compress(payload)
    destination = io.BytesIO()

    total_out = CompressedScanner._read_zlib_stream_with_limits(
        source=io.BytesIO(compressed),
        destination=destination,
        max_decompressed_bytes=len(payload),
        max_ratio=1000.0,
        compressed_size=len(compressed),
        chunk_size=1,
    )

    assert total_out == len(payload)
    assert destination.getvalue() == payload


def test_compressed_scanner_rejects_raw_trailer_after_zlib_member(tmp_path: Path) -> None:
    """A raw trailer after a valid zlib stream must not hide an unscanned pickle payload."""
    safe_pickle = pickle.dumps({"safe": [1, 2, 3]})
    malicious_pickle_trailer = b'cos\nsystem\n(S"echo owned"\ntR.'

    path = tmp_path / "payload.pkl.zlib"
    path.write_bytes(zlib.compress(safe_pickle) + malicious_pickle_trailer)

    result = CompressedScanner().scan(str(path))

    decode_checks = [check for check in result.checks if check.name == "Compressed Wrapper Stream Decode"]
    assert decode_checks and decode_checks[0].status == CheckStatus.FAILED
    assert "invalid zlib stream" in decode_checks[0].message.lower()
    assert result.success is False
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


@pytest.mark.parametrize(
    ("filename", "compressor"),
    [
        ("payload.pkl.bz2", bz2.compress),
        ("payload.pkl.xz", lzma.compress),
    ],
)
def test_compressed_scanner_rejects_raw_trailer_after_bzip2_or_xz_member(
    tmp_path: Path,
    filename: str,
    compressor: Callable[[bytes], bytes],
) -> None:
    """A raw trailer after a valid stream must not hide an unscanned pickle payload."""
    safe_pickle = pickle.dumps({"safe": [1, 2, 3]})
    malicious_pickle_trailer = b'cos\nsystem\n(S"echo owned"\ntR.'

    path = tmp_path / filename
    path.write_bytes(compressor(safe_pickle) + malicious_pickle_trailer)

    result = CompressedScanner().scan(str(path))

    decode_checks = [check for check in result.checks if check.name == "Compressed Wrapper Stream Decode"]
    assert decode_checks and decode_checks[0].status == CheckStatus.FAILED
    assert "invalid" in decode_checks[0].message.lower()
    assert result.success is False
    assert result.has_warnings is True
    assert result.has_errors is False
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_compressed_scanner_allows_concatenated_zlib_members(tmp_path: Path) -> None:
    """Concatenated zlib members should remain a supported benign encoding shape."""
    payload_a = pickle.dumps({"weights": [1, 2, 3]}, protocol=4)
    payload_b = pickle.dumps({"bias": [4, 5, 6]}, protocol=4)

    path = tmp_path / "safe_multi_stream.pkl.zlib"
    path.write_bytes(zlib.compress(payload_a) + zlib.compress(payload_b))

    result = CompressedScanner().scan(str(path))

    assert result.success is True
    assert not any(
        check.name == "Compressed Wrapper Stream Decode" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


@pytest.mark.parametrize(
    ("filename", "compressor"),
    [
        ("safe_multi_stream.pkl.gz", gzip.compress),
        ("safe_multi_stream.pkl.bz2", bz2.compress),
        ("safe_multi_stream.pkl.xz", lzma.compress),
    ],
)
def test_compressed_scanner_allows_concatenated_gzip_bzip2_and_xz_members(
    tmp_path: Path,
    filename: str,
    compressor: Callable[[bytes], bytes],
) -> None:
    """Concatenated valid members should remain supported for bzip2 and xz."""
    payload_a = pickle.dumps({"weights": [1, 2, 3]}, protocol=4)
    payload_b = pickle.dumps({"bias": [4, 5, 6]}, protocol=4)

    path = tmp_path / filename
    path.write_bytes(compressor(payload_a) + compressor(payload_b))

    result = CompressedScanner().scan(str(path))

    assert result.success is True
    assert not any(
        check.name == "Compressed Wrapper Stream Decode" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


@pytest.mark.parametrize(
    ("filename", "compressor"),
    [
        ("payload.txt.gz", gzip.compress),
        ("payload.txt.bz2", bz2.compress),
        ("payload.txt.xz", lzma.compress),
        ("payload.txt.zlib", zlib.compress),
    ],
)
def test_compressed_scanner_scans_each_concatenated_member(
    tmp_path: Path,
    filename: str,
    compressor: Callable[[bytes], bytes],
) -> None:
    """A benign first member must not hide a later malicious member."""
    path = tmp_path / filename
    path.write_bytes(compressor(b"harmless prelude\n") + compressor(pickle.dumps(_MaliciousPayload())))

    result = CompressedScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["compressed_member_count"] == 2
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert critical_issues
    assert any(issue.location == f"{path} -> payload.txt#member-2" for issue in critical_issues)
    member_routing_checks = [
        check for check in result.checks if check.name == "Compressed Wrapper Member Scanner Routing"
    ]
    assert len(member_routing_checks) == 2
    assert member_routing_checks[1].details["inner_scanner"] == "pickle"


def test_compressed_scanner_rejects_excess_concatenated_members(tmp_path: Path) -> None:
    path = tmp_path / "too_many_members.pkl.zlib"
    path.write_bytes(zlib.compress(b"a") + zlib.compress(b"b") + zlib.compress(b"c"))

    result = CompressedScanner(config={"compressed_max_members": 2}).scan(str(path))

    limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
    assert limit_checks and limit_checks[0].status == CheckStatus.FAILED
    assert "member count exceeded limit (3 > 2)" in limit_checks[0].message.lower()
    assert "analysis incomplete" in limit_checks[0].message.lower()
    assert limit_checks[0].severity == IssueSeverity.INFO
    assert limit_checks[0].details["max_compressed_members"] == 2
    assert limit_checks[0].details["scan_outcome_reason"] == "compressed_member_limit_exceeded"
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["scan_outcome_reasons"] == ["compressed_member_limit_exceeded"]
    assert result.success is False


def test_compressed_scanner_excess_members_are_exit2_and_not_cached(tmp_path: Path) -> None:
    path = tmp_path / "too_many_members.pkl.zlib"
    path.write_bytes(zlib.compress(b"a") + zlib.compress(b"b") + zlib.compress(b"c"))

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            min_cache_file_size=0,
            compressed_max_members=2,
        )
        second = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            min_cache_file_size=0,
            compressed_max_members=2,
        )

        for aggregate in (first, second):
            assert aggregate.success is False
            assert determine_exit_code(aggregate) == 2
            assert any("member count exceeded limit (3 > 2)" in issue.message.lower() for issue in aggregate.issues)
        assert get_cache_manager(str(tmp_path / "cache"), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_compressed_scanner_complete_wrapper_caches_without_ephemeral_inner_entries(tmp_path: Path) -> None:
    path = tmp_path / "safe_payload.pkl.gz"
    path.write_bytes(gzip.compress(pickle.dumps({"weights": [1, 2, 3]}, protocol=4)))

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            min_cache_file_size=0,
        )
        first_stats = get_cache_manager(str(tmp_path / "cache"), enabled=True).get_stats()
        second = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            min_cache_file_size=0,
        )
        second_stats = get_cache_manager(str(tmp_path / "cache"), enabled=True).get_stats()
        cache_files = [
            cache_file
            for cache_file in (tmp_path / "cache").rglob("*.json")
            if cache_file.name != "cache_metadata.json"
        ]
        cached_names = {
            json.loads(cache_file.read_text(encoding="utf-8"))["file_info"]["original_name"]
            for cache_file in cache_files
        }

        assert first.success is True
        assert second.success is True
        assert first_stats["total_entries"] == 2
        assert second_stats["total_entries"] == first_stats["total_entries"]
        assert second_stats["cache_hits"] > first_stats["cache_hits"]
        assert cached_names == {path.name}
    finally:
        reset_cache_manager()


def test_compressed_scanner_depth_limit_preserves_exit1_and_is_not_cached(tmp_path: Path) -> None:
    path = tmp_path / "depth_limited_payload.pkl.gz"
    path.write_bytes(gzip.compress(pickle.dumps({"weights": [1, 2, 3]})))

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            min_cache_file_size=0,
            compressed_max_depth=0,
        )
        second = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            min_cache_file_size=0,
            compressed_max_depth=0,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert aggregate.success is False
            assert determine_exit_code(aggregate) == 1
            assert metadata["scan_outcome"] == "inconclusive"
            assert metadata["scan_outcome_reasons"] == ["compressed_depth_limit_exceeded"]
            assert any("nesting depth (0) exceeded" in issue.message.lower() for issue in aggregate.issues)
        assert get_cache_manager(str(tmp_path / "cache"), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_compressed_scanner_decompression_limit_preserves_exit1_and_is_not_cached(tmp_path: Path) -> None:
    path = tmp_path / "size_limited_payload.pkl.gz"
    path.write_bytes(gzip.compress(b"A" * 4096))

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            min_cache_file_size=0,
            compressed_max_decompressed_bytes=512,
        )
        second = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            min_cache_file_size=0,
            compressed_max_decompressed_bytes=512,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert aggregate.success is False
            assert determine_exit_code(aggregate) == 1
            assert metadata["scan_outcome"] == "inconclusive"
            assert metadata["scan_outcome_reasons"] == ["compressed_decompression_limit_exceeded"]
            assert any("decompressed size exceeded limit" in issue.message.lower() for issue in aggregate.issues)
        assert get_cache_manager(str(tmp_path / "cache"), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_compressed_scanner_corrupt_stream_preserves_exit1_and_is_not_cached(tmp_path: Path) -> None:
    path = tmp_path / "corrupt_payload.pkl.gz"
    path.write_bytes(b"\x1f\x8b\x08\x00\x00\x00\x00\x00")

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            min_cache_file_size=0,
        )
        second = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert aggregate.success is False
            assert determine_exit_code(aggregate) == 1
            assert metadata["scan_outcome"] == "inconclusive"
            assert metadata["scan_outcome_reasons"] == ["compressed_stream_decode_failed"]
            assert any("invalid gzip stream" in issue.message.lower() for issue in aggregate.issues)
        assert get_cache_manager(str(tmp_path / "cache"), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_compressed_scanner_keeps_split_pickle_members_clean(tmp_path: Path) -> None:
    payload = pickle.dumps({"weights": [1, 2, 3]}, protocol=4)
    split_at = len(payload) // 2
    path = tmp_path / "split.pkl.gz"
    path.write_bytes(gzip.compress(payload[:split_at]) + gzip.compress(payload[split_at:]))

    result = CompressedScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["compressed_member_count"] == 2
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert not any(check.name == "Compressed Wrapper Member Scanner Routing" for check in result.checks)


def test_compressed_scanner_still_scans_later_pickle_member_after_fragment_filter(tmp_path: Path) -> None:
    safe_pickle = pickle.dumps({"weights": [1, 2, 3]}, protocol=4)
    malicious_pickle = pickle.dumps(_MaliciousPayload(), protocol=4)
    path = tmp_path / "safe_then_malicious.pkl.gz"
    path.write_bytes(gzip.compress(safe_pickle) + gzip.compress(malicious_pickle))

    result = CompressedScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["compressed_member_count"] == 2
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert critical_issues
    assert any(issue.location == f"{path} -> safe_then_malicious.pkl#member-2" for issue in critical_issues)


def test_compressed_scanner_scans_later_content_disguised_executable_member(tmp_path: Path) -> None:
    path = tmp_path / "payload.dat.gz"
    path.write_bytes(gzip.compress(b"harmless prelude\n") + gzip.compress(b"\x7fELF" + b"\x00" * 48))

    result = CompressedScanner().scan(str(path))

    executable_checks = [check for check in result.checks if check.name == "Executable Archive Member Detection"]
    assert executable_checks
    assert executable_checks[0].location == f"{path} -> payload.dat#member-2"


def test_compressed_scanner_analyzes_split_python_as_one_payload(tmp_path: Path) -> None:
    payload = b'import os\nos.system("echo hidden")\n'
    path = tmp_path / "split.py.gz"
    path.write_bytes(gzip.compress(payload[:10]) + gzip.compress(payload[10:]))

    result = CompressedScanner().scan(str(path))

    python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
    assert any(check.rule_code == "S101" for check in python_checks)
    assert "scan_outcome" not in result.metadata


def test_compressed_scanner_scans_later_python_member_when_aggregate_cannot_parse(tmp_path: Path) -> None:
    path = tmp_path / "members.py.gz"
    path.write_bytes(gzip.compress(b"def incomplete(\n") + gzip.compress(b'import os\nos.system("echo hidden")\n'))

    result = CompressedScanner().scan(str(path))

    python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
    assert any(
        check.rule_code == "S101" and check.location == f"{path} -> members.py#member-2" for check in python_checks
    )
    assert result.metadata["scan_outcome_reasons"] == ["compressed_python_payload_analysis_incomplete"]


def test_read_lz4_chunk_stream_splits_members_across_chunk_boundary() -> None:
    fake_lz4_frame = _FakeLz4ChunkModule({b"A": b"a", b"B": b"b"})
    destination = io.BytesIO()
    member_boundaries: list[None] = []

    total_out = CompressedScanner._read_lz4_chunk_stream_with_limits(
        source=io.BytesIO(_LZ4_FRAME_MAGIC + b"A" + _LZ4_FRAME_MAGIC + b"B"),
        destination=destination,
        lz4_frame=fake_lz4_frame,
        max_decompressed_bytes=1024,
        max_ratio=1000.0,
        compressed_size=10,
        chunk_size=len(_LZ4_FRAME_MAGIC) + 1,
        on_new_member=lambda: member_boundaries.append(None),
    )

    assert total_out == 2
    assert destination.getvalue() == b"ab"
    assert len(member_boundaries) == 1


def test_compressed_scanner_rejects_raw_trailer_after_lz4_frame(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A raw trailer after a valid lz4 frame must not hide an unscanned pickle payload."""
    safe_pickle = pickle.dumps({"safe": [1, 2, 3]})
    malicious_pickle_trailer = b'cos\nsystem\n(S"echo owned"\ntR.'
    fake_lz4_frame = _FakeLz4FrameModule({b"S": safe_pickle})

    monkeypatch.setattr(CompressedScanner, "_get_lz4_frame_module", staticmethod(lambda: fake_lz4_frame))

    path = tmp_path / "payload.pkl.lz4"
    path.write_bytes(_LZ4_FRAME_MAGIC + b"S" + malicious_pickle_trailer)

    result = CompressedScanner().scan(str(path))

    decode_checks = [check for check in result.checks if check.name == "Compressed Wrapper Stream Decode"]
    assert decode_checks and decode_checks[0].status == CheckStatus.FAILED
    assert "invalid lz4 stream" in decode_checks[0].message.lower()
    assert result.success is False
    assert result.has_warnings is True
    assert result.has_errors is False
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_compressed_scanner_rejects_raw_trailer_after_lz4_chunk_api_frame(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The legacy chunk API fallback must also fail closed on raw trailer bytes."""
    safe_pickle = pickle.dumps({"safe": [1, 2, 3]})
    malicious_pickle_trailer = b'cos\nsystem\n(S"echo owned"\ntR.'
    fake_lz4_frame = _FakeLz4ChunkModule({b"S": safe_pickle})

    monkeypatch.setattr(CompressedScanner, "_get_lz4_frame_module", staticmethod(lambda: fake_lz4_frame))

    path = tmp_path / "payload.pkl.lz4"
    path.write_bytes(_LZ4_FRAME_MAGIC + b"S" + malicious_pickle_trailer)

    result = CompressedScanner().scan(str(path))

    decode_checks = [check for check in result.checks if check.name == "Compressed Wrapper Stream Decode"]
    assert decode_checks and decode_checks[0].status == CheckStatus.FAILED
    assert "invalid lz4 stream" in decode_checks[0].message.lower()
    assert result.success is False
    assert result.has_warnings is True
    assert result.has_errors is False
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_compressed_scanner_allows_concatenated_lz4_frames(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Concatenated valid lz4 frames should remain supported when lz4 is installed."""
    payload_a = pickle.dumps({"weights": [1, 2, 3]}, protocol=4)
    payload_b = pickle.dumps({"bias": [4, 5, 6]}, protocol=4)
    fake_lz4_frame = _FakeLz4FrameModule({b"A": payload_a, b"B": payload_b})

    monkeypatch.setattr(CompressedScanner, "_get_lz4_frame_module", staticmethod(lambda: fake_lz4_frame))

    path = tmp_path / "safe_multi_frame.pkl.lz4"
    path.write_bytes(_LZ4_FRAME_MAGIC + b"A" + _LZ4_FRAME_MAGIC + b"B")

    result = CompressedScanner().scan(str(path))

    assert result.success is True
    assert not any(
        check.name == "Compressed Wrapper Stream Decode" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_compressed_scanner_allows_concatenated_lz4_chunk_api_frames(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The legacy chunk API fallback should preserve valid concatenated lz4 frames."""
    payload_a = pickle.dumps({"weights": [1, 2, 3]}, protocol=4)
    payload_b = pickle.dumps({"bias": [4, 5, 6]}, protocol=4)
    fake_lz4_frame = _FakeLz4ChunkModule({b"A": payload_a, b"B": payload_b})

    monkeypatch.setattr(CompressedScanner, "_get_lz4_frame_module", staticmethod(lambda: fake_lz4_frame))

    path = tmp_path / "safe_multi_frame.pkl.lz4"
    path.write_bytes(_LZ4_FRAME_MAGIC + b"A" + _LZ4_FRAME_MAGIC + b"B")

    result = CompressedScanner().scan(str(path))

    assert result.success is True
    assert not any(
        check.name == "Compressed Wrapper Stream Decode" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_compressed_scanner_missing_lz4_dependency_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lz4_path = tmp_path / "payload.bin.lz4"
    lz4_path.write_bytes(b"\x04\x22\x4d\x18" + b"\x00" * 16)

    def _raise_missing_dependency() -> None:
        raise _MissingOptionalDependencyError("Optional dependency 'lz4' is not installed")

    monkeypatch.setattr(CompressedScanner, "_get_lz4_frame_module", staticmethod(_raise_missing_dependency))

    scanner = CompressedScanner()
    result = scanner.scan(str(lz4_path))

    dependency_checks = [c for c in result.checks if c.name == "Compressed Wrapper Optional Dependency"]
    assert dependency_checks and dependency_checks[0].status == CheckStatus.FAILED
    assert dependency_checks[0].severity == IssueSeverity.INFO
    assert dependency_checks[0].details["scan_outcome_reason"] == "compressed_optional_dependency_unavailable"
    assert result.metadata["scan_outcome_reasons"] == ["compressed_optional_dependency_unavailable"]
    assert result.success is False


def test_compressed_scanner_missing_lz4_is_exit2_and_not_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lz4_path = tmp_path / "payload.bin.lz4"
    lz4_path.write_bytes(b"\x04\x22\x4d\x18" + b"\x00" * 16)

    def _raise_missing_dependency() -> object:
        raise _MissingOptionalDependencyError("Optional dependency 'lz4' is not installed")

    monkeypatch.setattr(CompressedScanner, "_get_lz4_frame_module", staticmethod(_raise_missing_dependency))

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(lz4_path),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            min_cache_file_size=0,
        )
        second = scan_model_directory_or_file(
            str(lz4_path),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(lz4_path)]
            assert aggregate.success is False
            assert determine_exit_code(aggregate) == 2
            assert metadata["scan_outcome"] == "inconclusive"
            assert metadata["scan_outcome_reasons"] == ["compressed_optional_dependency_unavailable"]
            assert any("optional dependency" in issue.message.lower() for issue in aggregate.issues)
        assert get_cache_manager(str(tmp_path / "cache"), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()
