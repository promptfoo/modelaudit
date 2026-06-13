"""Streaming analysis support for cloud-hosted model files."""

import inspect
import io
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeGuard
from urllib.parse import unquote, urlparse

import click

if TYPE_CHECKING:
    from modelaudit.scanner_results import ScanResult
    from modelaudit.scanners.base import BaseScanner
from modelaudit.utils.sources.cloud_storage import (
    get_cloud_filesystem_config,
    get_fs_protocol,
    redact_cloud_error_for_display,
)

from .detection import _has_zip_magic

_MAX_STREAM_SOURCE_PATH_DECODE_PASSES = 4
STREAMING_ANALYSIS_DEFAULT_MAX_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class StreamedSourceByteAccounting:
    """Internal exact-once byte accounting for trusted streamed scan items."""

    pretransferred_bytes: int = 0
    source_bytes_preaccounted: int = 0

    def __post_init__(self) -> None:
        for name, value in (
            ("pretransferred_bytes", self.pretransferred_bytes),
            ("source_bytes_preaccounted", self.source_bytes_preaccounted),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


def resolve_streaming_max_bytes(max_bytes: object = None) -> int:
    """Return a bounded positive streaming-analysis read limit."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        return STREAMING_ANALYSIS_DEFAULT_MAX_BYTES
    return max_bytes


def _is_positive_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _streaming_max_bytes_from_scanner_config(scanner: "BaseScanner", max_bytes: object = None) -> int:
    if _is_positive_int(max_bytes):
        resolved_max = max_bytes
    else:
        configured_stream_max = scanner.config.get("streaming_max_bytes")
        resolved_max = (
            configured_stream_max if _is_positive_int(configured_stream_max) else STREAMING_ANALYSIS_DEFAULT_MAX_BYTES
        )

    for config_key in ("max_file_size", "max_file_read_size"):
        configured_max = scanner.config.get(config_key)
        if _is_positive_int(configured_max):
            resolved_max = min(resolved_max, configured_max)
    return resolved_max


def _is_unproven_partial_scan_issue(issue: Any, *, known_file_size: int | None) -> bool:
    """Return whether an issue can be explained solely by a bounded prefix ending."""
    details = getattr(issue, "details", None)
    if not isinstance(details, dict):
        return False
    if details.get("tamper_type") == "oversized_frame":
        if details.get("overrun_boundary") in {"stop", "next_frame"}:
            return False
        position = details.get("position")
        frame_length = details.get("frame_length")
        if known_file_size is None:
            return True
        if (
            isinstance(position, bool)
            or not isinstance(position, int)
            or isinstance(frame_length, bool)
            or not isinstance(frame_length, int)
        ):
            return False
        frame_payload_offset = position + 9
        return frame_length <= max(known_file_size - frame_payload_offset, 0)
    if details.get("analysis_incomplete") is not True:
        return False
    return details.get("notice_code") == "parse_incomplete" or details.get("category") in {
        "parse_error",
        "short_read",
    }


def _get_streaming_filesystem_config(url: str) -> tuple[str, str, dict[str, Any]]:
    """Resolve provider URLs while retaining support for non-cloud test filesystems."""
    protocol = get_fs_protocol(url)
    if protocol not in {"s3", "gcs"}:
        return protocol, url, {}
    return get_cloud_filesystem_config(url)


def can_stream_analyze(url: str, scanner: "BaseScanner") -> bool:
    """Check if a file can be analyzed via streaming."""
    # Currently support streaming for pickle files
    # Can be extended to other formats that support partial reads
    path = Path(stream_source_path(url))
    suffix = path.suffix.lower()
    return suffix in {".pkl", ".pickle", ".joblib"}


def stream_source_path(url: str) -> str:
    """Return the decoded URL path used for scanner routing and file naming."""
    parsed = urlparse(url)
    if parsed.scheme.casefold() in {"s3", "gs", "gcs", "r2"}:
        parsed_path = parsed.path
        if parsed.query:
            parsed_path = f"{parsed_path}?{parsed.query}"
        if parsed.fragment:
            parsed_path = f"{parsed_path}#{parsed.fragment}"
        return parsed_path or url

    parsed_path = parsed.path
    for _ in range(_MAX_STREAM_SOURCE_PATH_DECODE_PASSES):
        decoded_path = unquote(parsed_path)
        if decoded_path == parsed_path:
            break
        parsed_path = decoded_path

    fallback_prefix: str | None = None
    for index, character in enumerate(parsed_path):
        if character not in "?#":
            continue
        prefix = parsed_path[:index]
        encoded_suffix = parsed_path[index + 1 :]
        if Path(prefix).suffix:
            return prefix or url
        if fallback_prefix is None and any(delimiter in encoded_suffix for delimiter in "=&;"):
            fallback_prefix = prefix
    if fallback_prefix is not None:
        return fallback_prefix or url
    return parsed_path or url


def _scan_stream_accepts_source_keyword(method: Any) -> bool:
    """Return True when a scan_stream-like method accepts `source=` explicitly or via `**kwargs`."""
    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        return False

    source_parameter = signature.parameters.get("source")
    if source_parameter is not None:
        return source_parameter.kind in {
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        }

    return any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in signature.parameters.values())


def _mark_streaming_analysis_incomplete(result: "ScanResult", *, header_only_fallback: bool = False) -> None:
    from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME

    result.metadata["analysis_incomplete"] = True
    result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
    result.metadata.setdefault(
        "scan_outcome_message",
        "Streaming analysis incomplete; failed closed because full scanner coverage was not available.",
    )

    existing_reasons = result.metadata.get("scan_outcome_reasons")
    reasons = existing_reasons if isinstance(existing_reasons, list) else []
    if "streaming_analysis_incomplete" not in reasons:
        reasons.append("streaming_analysis_incomplete")
    if header_only_fallback and "streaming_header_only_fallback" not in reasons:
        reasons.append("streaming_header_only_fallback")
    result.metadata["scan_outcome_reasons"] = reasons


def stream_analyze_file(
    url: str,
    scanner: "BaseScanner",
    max_bytes: int | None = None,
) -> tuple["ScanResult | None", bool]:
    from modelaudit.scanner_results import Issue, IssueSeverity, ScanResult

    """Stream analyze a file from cloud storage.

    After downloading a configurable chunk of bytes, this function attempts to
    run the provided ``scanner`` directly on the in-memory data. If the scanner
    exposes a partial-scan capability, the resulting issues and metadata are
    merged into the streaming result. When the scanner cannot operate on partial
    content, limited header checks are performed instead.

    Returns:
        Tuple of (ScanResult or None, analysis_complete)
        analysis_complete indicates if scanner-backed analysis covered the entire file
    """
    try:
        import fsspec
    except ImportError as e:
        raise ImportError(
            "fsspec package is required for streaming analysis. "
            "Try reinstalling modelaudit: 'pip install --force-reinstall modelaudit'"
        ) from e

    fs_protocol, fs_url, fs_args = _get_streaming_filesystem_config(url)
    fs = fsspec.filesystem(fs_protocol, **fs_args)

    try:
        # Get file info first
        info = fs.info(fs_url)
        reported_file_size = info.get("size")
        known_file_size = (
            reported_file_size
            if isinstance(reported_file_size, int)
            and not isinstance(reported_file_size, bool)
            and reported_file_size >= 0
            else None
        )

        resolved_max_bytes = _streaming_max_bytes_from_scanner_config(scanner, max_bytes)

        # Use one spare byte of the budget to detect an object that grew after
        # the metadata lookup without exceeding the configured read cap.
        if known_file_size is None:
            bytes_to_read = resolved_max_bytes
        elif known_file_size < resolved_max_bytes:
            bytes_to_read = known_file_size + 1
        else:
            bytes_to_read = resolved_max_bytes

        # Read partial content
        extra_byte_observed = False
        with fs.open(fs_url, "rb") as f:
            content = f.read(bytes_to_read)
            if not isinstance(content, bytes):
                raise TypeError("cloud filesystem returned non-bytes content")
            if known_file_size is not None and known_file_size < resolved_max_bytes and len(content) == known_file_size:
                # A legal short read can stop at the stale reported size even
                # when the object grew. Probe EOF separately before treating
                # exact-size coverage as complete.
                extra = f.read(1)
                if not isinstance(extra, bytes):
                    raise TypeError("cloud filesystem returned non-bytes content")
                extra_byte_observed = bool(extra)
        bytes_read = len(content)
        reported_size_disproven = known_file_size is not None and (bytes_read > known_file_size or extra_byte_observed)
        bytes_complete = (
            known_file_size is not None
            and known_file_size < resolved_max_bytes
            and bytes_read == known_file_size
            and not extra_byte_observed
        )

        # Create a temporary in-memory file for scanning
        temp_file = io.BytesIO(content)
        source_path = stream_source_path(url)
        temp_file.name = Path(source_path).name

        issues: list[Issue] = []
        metadata: dict[str, Any] = {}

        # Try to use scanner's partial capabilities if available
        scan_result: ScanResult | None = None
        try:
            temp_file.seek(0)
            scan_result = scanner.scan(temp_file)  # type: ignore[arg-type]
        except Exception:
            scan_result = None

        if scan_result is None:
            partial_methods = [
                ("scan_stream", True),
                ("scan_bytes", False),
                ("scan_fileobj", False),
            ]
            for method_name, needs_size in partial_methods:
                if hasattr(scanner, method_name):
                    method = getattr(scanner, method_name)
                    try:
                        temp_file.seek(0)
                        if method_name == "scan_stream" and needs_size:
                            if _scan_stream_accepts_source_keyword(method):
                                scan_result = method(temp_file, bytes_read, source=url)
                            else:
                                scan_result = method(temp_file, bytes_read)
                        else:
                            scan_result = method(temp_file, bytes_to_read) if needs_size else method(temp_file)
                        break
                    except Exception:
                        scan_result = None

        if scan_result is not None:
            scanner_issues = list(scan_result.issues)
            if not bytes_complete:
                proof_file_size = (
                    known_file_size
                    if known_file_size is not None and bytes_read <= known_file_size and not extra_byte_observed
                    else None
                )
                scanner_issues = [
                    issue
                    for issue in scanner_issues
                    if not _is_unproven_partial_scan_issue(issue, known_file_size=proof_file_size)
                ]
            issues.extend(scanner_issues)
            metadata.update(scan_result.metadata)
            if not scanner_issues and metadata.get("pickle_verdict") == "suspicious":
                metadata["pickle_verdict"] = "unknown"

        # Fallback manual checks for pickle headers when scanner doesn't support partial scans
        if scan_result is None and Path(source_path).suffix.lower() in {".pkl", ".pickle", ".joblib"}:
            dangerous_patterns = [
                b"os\nsystem",
                b"subprocess",
                b"eval",
                b"exec",
                b"__import__",
                b"compile",
                b"globals",
                b"locals",
                b"builtins",
                b"getattr",
                b"setattr",
                b"delattr",
                b"open",
                b"file",
                b"input",
                b"raw_input",
                b"execfile",
                b"reload",
                b"__builtin__",
                b"__builtins__",
            ]

            for pattern in dangerous_patterns:
                if pattern in content:
                    issues.append(
                        Issue(
                            message=(
                                f"Dangerous pattern '{pattern.decode('utf-8', errors='ignore')}' found in file header"
                            ),
                            severity=IssueSeverity.CRITICAL,
                            location=url,
                            details={
                                "pattern": pattern.decode("utf-8", errors="ignore"),
                                "detection_method": "streaming_header_scan",
                                "bytes_analyzed": bytes_read,
                                "file_size": reported_file_size,
                                "analysis_complete": False,
                            },
                            type="streaming_security_check",
                            why=(
                                f"The file header contains the dangerous pattern "
                                f"'{pattern.decode('utf-8', errors='ignore')}' which could "
                                "indicate malicious code execution."
                            ),
                        )
                    )

            if content.startswith(b"\x80"):  # Pickle protocol marker
                protocol_version = content[1] if len(content) > 1 else 0
                protocol_marker_only = bytes_complete and len(content) == 2 and protocol_version in {2, 3, 4, 5}
                if protocol_version >= 3 and not protocol_marker_only:
                    issues.append(
                        Issue(
                            message=f"Pickle protocol {protocol_version} detected",
                            severity=IssueSeverity.WARNING,
                            location=url,
                            details={
                                "protocol_version": protocol_version,
                                "detection_method": "streaming_protocol_check",
                            },
                            type="streaming_pickle_protocol_check",
                            why=(
                                f"This pickle file uses protocol {protocol_version} which "
                                "supports more complex operations that could be exploited."
                            ),
                        )
                    )

        # Create a result for any successful streamed read; reserve None for
        # transport/setup failures so callers can distinguish fallback from an
        # inconclusive partial analysis.
        scan_result_incomplete = bool(scan_result and scan_result.metadata.get("analysis_incomplete"))
        analysis_complete = bytes_complete and scan_result is not None and not scan_result_incomplete

        result = ScanResult(scanner_name="streaming")
        scanned = getattr(scan_result, "bytes_scanned", 0) if scan_result is not None else 0
        result.bytes_scanned = scanned or bytes_read
        result.issues = issues
        result.metadata = dict(metadata)
        result.metadata.update(
            {
                "streaming_analysis": True,
                "bytes_analyzed": bytes_read,
                "bytes_complete": bytes_complete,
                "analysis_complete": analysis_complete,
                "file_size": None if reported_size_disproven else reported_file_size,
                "file_size_known": known_file_size is not None and not reported_size_disproven,
                "reported_file_size": reported_file_size,
                "max_bytes": resolved_max_bytes,
            }
        )
        if not analysis_complete:
            _mark_streaming_analysis_incomplete(result, header_only_fallback=scan_result is None)
        scanner_success = bool(getattr(scan_result, "success", True)) if scan_result is not None else True
        result.finish(success=analysis_complete and scanner_success)
        return result, analysis_complete

    except Exception as e:
        # If streaming fails, return None to fall back to regular download
        try:
            ctx = click.get_current_context(silent=True)
            if ctx and ctx.params.get("verbose"):
                click.echo(f"Streaming analysis failed: {redact_cloud_error_for_display(e, url)}")
        except Exception:
            # Not in a Click context, just log silently
            pass
        return None, False


def get_streaming_preview(url: str, max_bytes: int = 1024) -> dict[str, Any] | None:
    """Get a preview of file contents for analysis."""
    try:
        import fsspec
    except ImportError:
        return None

    try:
        fs_protocol, fs_url, fs_args = _get_streaming_filesystem_config(url)
        fs = fsspec.filesystem(fs_protocol, **fs_args)

        # Read first few bytes
        with fs.open(fs_url, "rb") as f:
            header = f.read(max_bytes)

        # Analyze header
        preview = {
            "header_bytes": header[:64].hex(),
            "header_ascii": header[:64].decode("utf-8", errors="replace"),
            "detected_format": None,
        }

        # Detect file format from header
        if header.startswith(b"\x80"):
            preview["detected_format"] = "pickle"
            preview["pickle_protocol"] = header[1] if len(header) > 1 else "unknown"
        elif _has_zip_magic(header):
            preview["detected_format"] = "zip (possibly pytorch/tensorflow)"
        elif b"HDF" in header[:10]:
            preview["detected_format"] = "HDF5 (keras/tensorflow)"
        elif header.startswith(b"\x08\x01\x12\x00") or b"onnx" in header[:32].lower():
            preview["detected_format"] = "ONNX"

        return preview

    except Exception:
        return None
