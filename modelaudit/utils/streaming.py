"""Streaming analysis support for cloud-hosted model files."""

import io
from pathlib import Path
from typing import Any, Optional

import click

from modelaudit.scanners.base import BaseScanner, Issue, IssueSeverity, ScanResult
from modelaudit.utils.cloud_storage import get_fs_protocol


def can_stream_analyze(url: str, scanner: BaseScanner) -> bool:
    """Check if a file can be analyzed via streaming."""
    # Currently support streaming for pickle files
    # Can be extended to other formats that support partial reads
    path = Path(url)
    return path.suffix.lower() in {".pkl", ".pickle", ".joblib"}


def stream_analyze_file(
    url: str,
    scanner: BaseScanner,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB default
) -> tuple[Optional[ScanResult], bool]:
    """
    Stream analyze a file from cloud storage.

    Returns:
        Tuple of (ScanResult or None, was_complete)
        was_complete indicates if the entire file was analyzed
    """
    try:
        import fsspec
    except ImportError as e:
        raise ImportError(
            "fsspec package is required for streaming analysis. Install with 'pip install modelaudit[cloud]'"
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
        was_complete = bytes_to_read >= file_size

        # Read partial content
        with fs.open(url, "rb") as f:
            content = f.read(bytes_to_read)

        # Create a temporary in-memory file for scanning
        temp_file = io.BytesIO(content)
        temp_file.name = Path(url).name

        # Attempt to scan the partial content
        # Note: This may not work for all file formats
        issues = []

        # For pickle files, we can detect many security issues from the header
        if Path(url).suffix.lower() in {".pkl", ".pickle", ".joblib"}:
            # Check for dangerous patterns in raw content
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
                                "analysis_complete": was_complete,
                            },
                            why=(
                                f"The file header contains the dangerous pattern "
                                f"'{pattern.decode('utf-8', errors='ignore')}' which could "
                                "indicate malicious code execution."
                            ),
                        )
                    )

            # Also check for pickle protocol version and opcodes
            if content.startswith(b"\x80"):  # Pickle protocol marker
                protocol_version = content[1] if len(content) > 1 else 0
                if protocol_version >= 3:
                    # Protocol 3+ allows more dangerous operations
                    issues.append(
                        Issue(
                            message=f"Pickle protocol {protocol_version} detected",
                            severity=IssueSeverity.WARNING,
                            location=url,
                            details={
                                "protocol_version": protocol_version,
                                "detection_method": "streaming_protocol_check",
                            },
                            why=(
                                f"This pickle file uses protocol {protocol_version} which "
                                "supports more complex operations that could be exploited."
                            ),
                        )
                    )

        # Create scan result
        if issues or was_complete:
            result = ScanResult(scanner_name="streaming")
            result.bytes_scanned = bytes_to_read
            result.issues = issues
            result.metadata = {
                "streaming_analysis": True,
                "bytes_analyzed": bytes_to_read,
                "analysis_complete": was_complete,
                "file_size": file_size,
            }
            result.finish(success=True)
            return result, was_complete
        else:
            # Partial analysis with no findings
            return None, was_complete

    except Exception as e:
        # If streaming fails, return None to fall back to regular download
        try:
            ctx = click.get_current_context(silent=True)
            if ctx and ctx.params.get("verbose"):
                click.echo(f"Streaming analysis failed: {e}")
        except Exception:
            # Not in a Click context, just log silently
            pass
        return None, False


def get_streaming_preview(url: str, max_bytes: int = 1024) -> Optional[dict[str, Any]]:
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
        elif header.startswith(b"PK"):
            preview["detected_format"] = "zip (possibly pytorch/tensorflow)"
        elif b"HDF" in header[:10]:
            preview["detected_format"] = "HDF5 (keras/tensorflow)"
        elif header.startswith(b"\x08\x08"):
            preview["detected_format"] = "ONNX"

        return preview

    except Exception:
        return None
