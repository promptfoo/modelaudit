"""Streaming analysis support for cloud-hosted model files."""

import inspect
import io
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlparse

import click

if TYPE_CHECKING:
    from modelaudit.scanner_results import ScanResult
    from modelaudit.scanners.base import BaseScanner
from modelaudit.utils.sources.cloud_storage import get_fs_protocol, redact_cloud_error_for_display

from .detection import _has_zip_magic


def can_stream_analyze(url: str, scanner: "BaseScanner") -> bool:
    """Check if a file can be analyzed via streaming."""
    # Currently support streaming for pickle files
    # Can be extended to other formats that support partial reads
    path = Path(stream_source_path(url))
    suffix = path.suffix.lower()
    return suffix in {".pkl", ".pickle", ".joblib"}


def stream_source_path(url: str) -> str:
    """Return the decoded URL path used for scanner routing and file naming."""
    parsed_path = unquote(urlparse(url).path)
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
    max_bytes: int = 1024 * 1024 * 1024 * 1024,  # 1TB default
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

    fs_protocol = get_fs_protocol(url)
    # Use anonymous access for public buckets
    fs = fsspec.filesystem(fs_protocol, token="anon") if fs_protocol == "gcs" else fsspec.filesystem(fs_protocol)

    try:
        # Get file info first
        info = fs.info(url)
        file_size = info.get("size", 0)

        if file_size == 0:
            return None, True

        # Determine how much to read
        bytes_to_read = min(file_size, max_bytes)
        bytes_complete = bytes_to_read >= file_size

        # Read partial content
        with fs.open(url, "rb") as f:
            content = f.read(bytes_to_read)

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
                                scan_result = method(temp_file, bytes_to_read, source=url)
                            else:
                                scan_result = method(temp_file, bytes_to_read)
                        else:
                            scan_result = method(temp_file, bytes_to_read) if needs_size else method(temp_file)
                        break
                    except Exception:
                        scan_result = None

        if scan_result is not None:
            issues.extend(scan_result.issues)
            metadata.update(scan_result.metadata)

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
                                "bytes_analyzed": bytes_to_read,
                                "file_size": file_size,
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
        result.bytes_scanned = scanned or bytes_to_read
        result.issues = issues
        result.metadata = {
            "streaming_analysis": True,
            "bytes_analyzed": bytes_to_read,
            "bytes_complete": bytes_complete,
            "analysis_complete": analysis_complete,
            "file_size": file_size,
        }
        result.metadata.update(metadata)
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
        fs_protocol = get_fs_protocol(url)
        fs = fsspec.filesystem(fs_protocol, token="anon") if fs_protocol == "gcs" else fsspec.filesystem(fs_protocol)

        # Read first few bytes
        with fs.open(url, "rb") as f:
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
