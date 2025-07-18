import builtins
import logging
import os
import time
from pathlib import Path
from threading import Lock
from typing import IO, Any, Callable, Optional, cast
from unittest.mock import patch

from modelaudit.license_checker import (
    check_commercial_use_warnings,
    collect_license_metadata,
)
from modelaudit.scanners import _registry
from modelaudit.scanners.base import BaseScanner, IssueSeverity, ScanResult
from modelaudit.utils import is_within_directory, resolve_dvc_file
from modelaudit.utils.assets import asset_from_scan_result
from modelaudit.utils.filetype import (
    detect_file_format,
    detect_file_format_from_magic,
    detect_format_from_extension,
    validate_file_type,
)

logger = logging.getLogger("modelaudit.core")

# Lock to ensure thread-safe monkey patching of builtins.open
_OPEN_PATCH_LOCK = Lock()


def _add_asset_to_results(
    results: dict[str, Any],
    file_path: str,
    file_result: ScanResult,
) -> None:
    """Helper function to add an asset entry to the results."""
    assets_list = cast(list[dict[str, Any]], results["assets"])
    assets_list.append(asset_from_scan_result(file_path, file_result))


def _add_error_asset_to_results(results: dict[str, Any], file_path: str) -> None:
    """Helper function to add an error asset entry to the results."""
    assets_list = cast(list[dict[str, Any]], results["assets"])
    assets_list.append({"path": file_path, "type": "error"})


def validate_scan_config(config: dict[str, Any]) -> None:
    """Validate configuration parameters for scanning."""
    timeout = config.get("timeout")
    if timeout is not None and (not isinstance(timeout, int) or timeout <= 0):
        raise ValueError("timeout must be a positive integer")

    max_file_size = config.get("max_file_size")
    if max_file_size is not None and (not isinstance(max_file_size, int) or max_file_size < 0):
        raise ValueError("max_file_size must be a non-negative integer")

    max_total_size = config.get("max_total_size")
    if max_total_size is not None and (not isinstance(max_total_size, int) or max_total_size < 0):
        raise ValueError("max_total_size must be a non-negative integer")

    chunk_size = config.get("chunk_size")
    if chunk_size is not None and (not isinstance(chunk_size, int) or chunk_size <= 0):
        raise ValueError("chunk_size must be a positive integer")


def scan_model_directory_or_file(
    path: str,
    blacklist_patterns: Optional[list[str]] = None,
    timeout: int = 300,
    max_file_size: int = 0,
    max_total_size: int = 0,
    progress_callback: Optional[Callable[[str, float], None]] = None,
    **kwargs,
) -> dict[str, Any]:
    """
    Scan a model file or directory for malicious content.

    Args:
        path: Path to the model file or directory
        blacklist_patterns: Additional blacklist patterns to check against model names
        timeout: Scan timeout in seconds
        max_file_size: Maximum file size to scan in bytes
        max_total_size: Maximum total bytes to scan across all files
        progress_callback: Optional callback function to report progress
                          (message, percentage)
        **kwargs: Additional arguments to pass to scanners

    Returns:
        Dictionary with scan results
    """
    # Start timer for timeout
    start_time = time.time()

    # Initialize results with proper type hints
    results: dict[str, Any] = {
        "start_time": start_time,
        "path": path,
        "bytes_scanned": 0,
        "issues": [],
        "success": True,
        "files_scanned": 0,
        "scanners": [],  # Track the scanners used
        "assets": [],
        "file_metadata": {},  # Per-file metadata
    }

    # Configure scan options
    config = {
        "blacklist_patterns": blacklist_patterns,
        "max_file_size": max_file_size,
        "max_total_size": max_total_size,
        "timeout": timeout,
        **kwargs,
    }

    validate_scan_config(config)

    try:
        # Check if path exists
        if not os.path.exists(path):
            raise FileNotFoundError(f"Path does not exist: {path}")

        # Check if path is readable
        if not os.access(path, os.R_OK):
            raise PermissionError(f"Path is not readable: {path}")

        # Check if path is a directory
        if os.path.isdir(path):
            if progress_callback:
                progress_callback(f"Scanning directory: {path}", 0.0)

            # Scan all files in the directory
            # Use lazy file counting for better performance on large directories
            total_files = None  # Will be set to actual count if directory is small
            processed_files = 0
            limit_reached = False

            # Quick check: count files only if directory seems reasonable in size
            # This avoids the expensive rglob() on very large directories
            try:
                # Do a quick count of immediate children first
                immediate_children = len(list(Path(path).iterdir()))
                if immediate_children < 1000:  # Only count if not too many immediate children
                    total_files = sum(1 for _ in Path(path).rglob("*") if _.is_file())
            except (OSError, PermissionError):
                # If we can't count, just proceed without progress percentage
                total_files = None

            base_dir = Path(path).resolve()
            for root, _, files in os.walk(path, followlinks=False):
                for file in files:
                    file_path = os.path.join(root, file)
                    resolved_file = Path(file_path).resolve()

                    # Check if this is a HuggingFace cache symlink scenario
                    is_hf_cache_symlink = False
                    if (
                        os.path.islink(file_path)
                        and ".cache/huggingface/hub" in str(base_dir)
                        and "/snapshots/" in str(file_path)
                    ):
                        link_target = os.readlink(file_path)
                        # Resolve the relative link target
                        resolved_target = (Path(file_path).parent / link_target).resolve()
                        # Check if target is in the blobs directory of the same model cache
                        if "/blobs/" in str(resolved_target):
                            # Extract the model cache root (e.g., models--distilbert-base-uncased)
                            cache_parts = str(base_dir).split("/")
                            for i, part in enumerate(cache_parts):
                                if part.startswith("models--") and i > 0:
                                    cache_root = "/".join(cache_parts[: i + 1])
                                    # Check if the target is within the same model's cache structure
                                    if str(resolved_target).startswith(cache_root):
                                        is_hf_cache_symlink = True
                                        # Update the resolved_file to the actual target for scanning
                                        resolved_file = resolved_target
                                    break

                    if not is_hf_cache_symlink and not is_within_directory(str(base_dir), str(resolved_file)):
                        issues_list = cast(list[dict[str, Any]], results["issues"])
                        issues_list.append(
                            {
                                "message": "Path traversal outside scanned directory",
                                "severity": IssueSeverity.CRITICAL.value,
                                "location": file_path,
                                "details": {"resolved_path": str(resolved_file)},
                            },
                        )
                        continue

                    # Skip non-model files early
                    if _should_skip_file(file_path):
                        logger.debug(f"Skipping non-model file: {file_path}")
                        continue

                    # Check timeout
                    if time.time() - start_time > timeout:
                        raise TimeoutError(f"Scan timeout after {timeout} seconds")

                    # Update progress before scanning
                    if progress_callback:
                        if total_files is not None and total_files > 0:
                            progress_callback(
                                f"Scanning file {processed_files + 1}/{total_files}: {file}",
                                processed_files / total_files * 100,
                            )
                        else:
                            # No total count available, just show file count
                            progress_callback(
                                f"Scanning file {processed_files + 1}: {file}",
                                0.0,  # Can't calculate percentage without total
                            )

                    # Scan the file
                    try:
                        # Use resolved_file path for actual scanning (handles symlinks)
                        file_result = scan_file(str(resolved_file), config)
                        # Use cast to help mypy understand the types
                        results["bytes_scanned"] = cast(int, results["bytes_scanned"]) + file_result.bytes_scanned
                        results["files_scanned"] = cast(int, results["files_scanned"]) + 1  # Increment file count
                        processed_files += 1  # Increment after successful scan

                        # Track scanner name
                        scanner_name = file_result.scanner_name
                        scanners_list = cast(list[str], results["scanners"])
                        if scanner_name and scanner_name not in scanners_list:
                            scanners_list.append(scanner_name)

                        # Add issues from file scan
                        issues_list = cast(list[dict[str, Any]], results["issues"])
                        for issue in file_result.issues:
                            issues_list.append(issue.to_dict())

                        # Add to assets list for inventory
                        _add_asset_to_results(results, file_path, file_result)

                        # Save metadata for SBOM generation
                        file_meta = cast(dict[str, Any], results["file_metadata"])
                        # Merge scanner metadata with license metadata
                        license_metadata = collect_license_metadata(file_path)
                        combined_metadata = {**file_result.metadata, **license_metadata}
                        file_meta[file_path] = combined_metadata

                        if max_total_size > 0 and cast(int, results["bytes_scanned"]) > max_total_size:
                            issues_list.append(
                                {
                                    "message": f"Total scan size limit exceeded: {results['bytes_scanned']} bytes "
                                    f"(max: {max_total_size})",
                                    "severity": IssueSeverity.WARNING.value,
                                    "location": file_path,
                                    "details": {"max_total_size": max_total_size},
                                },
                            )
                            limit_reached = True
                            break
                    except Exception as e:
                        logger.warning(f"Error scanning file {file_path}: {e!s}")
                        # Add as an issue
                        issues_list = cast(list[dict[str, Any]], results["issues"])
                        issues_list.append(
                            {
                                "message": f"Error scanning file: {e!s}",
                                "severity": IssueSeverity.WARNING.value,
                                "location": file_path,
                                "details": {"exception_type": type(e).__name__},
                            },
                        )
                        # Add error entry to assets
                        _add_error_asset_to_results(results, file_path)
                if limit_reached:
                    break
            # Stop scanning if size limit reached
            if limit_reached:
                logger.info("Scan terminated early due to total size limit")
                issues_list = cast(list[dict[str, Any]], results["issues"])
                issues_list.append(
                    {
                        "message": "Scan terminated early due to total size limit",
                        "severity": IssueSeverity.INFO.value,
                        "location": path,
                        "details": {"max_total_size": max_total_size},
                    }
                )
        else:
            # Scan a single file or DVC pointer
            target_files = [path]
            if path.endswith(".dvc"):
                dvc_targets = resolve_dvc_file(path)
                if dvc_targets:
                    target_files = dvc_targets

            for _idx, target in enumerate(target_files):
                if progress_callback:
                    progress_callback(f"Scanning file: {target}", 0.0)

                file_size = os.path.getsize(target)
                results["files_scanned"] = cast(int, results.get("files_scanned", 0)) + 1

                if progress_callback is not None and file_size > 0:

                    def create_progress_open(callback: Callable[[str, float], None], current_file_size: int):
                        """Create a progress-aware file opener with properly bound variables."""

                        def progress_open(file_path: str, mode: str = "r", *args: Any, **kwargs: Any) -> IO[Any]:
                            # Note: We intentionally don't use a context manager here because we need to
                            # return the file object for further processing. The SIM115 warning is
                            # suppressed because this is a legitimate use case.
                            file = builtins.open(file_path, mode, *args, **kwargs)  # noqa: SIM115
                            file_pos = 0

                            original_read = file.read

                            def progress_read(size: int = -1) -> Any:
                                nonlocal file_pos
                                data = original_read(size)
                                if isinstance(data, (str, bytes)):
                                    file_pos += len(data)
                                callback(
                                    f"Reading file: {os.path.basename(file_path)}",
                                    min(file_pos / current_file_size * 100, 100),
                                )
                                return data

                            file.read = progress_read  # type: ignore[method-assign]
                            return file

                        return progress_open

                    progress_opener = create_progress_open(progress_callback, file_size)
                    with _OPEN_PATCH_LOCK, patch("builtins.open", progress_opener):
                        file_result = scan_file(target, config)
                else:
                    file_result = scan_file(target, config)

                results["bytes_scanned"] = cast(int, results["bytes_scanned"]) + file_result.bytes_scanned

                scanner_name = file_result.scanner_name
                scanners_list = cast(list[str], results["scanners"])
                if scanner_name and scanner_name not in scanners_list:
                    scanners_list.append(scanner_name)

                issues_list = cast(list[dict[str, Any]], results["issues"])
                for issue in file_result.issues:
                    issues_list.append(issue.to_dict())

                _add_asset_to_results(results, target, file_result)

                file_meta = cast(dict[str, Any], results["file_metadata"])
                license_metadata = collect_license_metadata(target)
                combined_metadata = {**file_result.metadata, **license_metadata}
                file_meta[target] = combined_metadata

                if max_total_size > 0 and cast(int, results["bytes_scanned"]) > max_total_size:
                    issues_list.append(
                        {
                            "message": (
                                f"Total scan size limit exceeded: {results['bytes_scanned']} bytes "
                                f"(max: {max_total_size})"
                            ),
                            "severity": IssueSeverity.WARNING.value,
                            "location": target,
                            "details": {"max_total_size": max_total_size},
                        }
                    )

                if progress_callback:
                    progress_callback(f"Completed scanning: {target}", 100.0)

    except Exception as e:
        logger.exception(f"Error during scan: {e!s}")
        results["success"] = False
        issue_dict = {
            "message": f"Error during scan: {e!s}",
            "severity": IssueSeverity.WARNING.value,
            "details": {"exception_type": type(e).__name__},
        }
        issues_list = cast(list[dict[str, Any]], results["issues"])
        issues_list.append(issue_dict)
        _add_error_asset_to_results(results, path)

    # Add final timing information
    results["finish_time"] = time.time()
    results["duration"] = cast(float, results["finish_time"]) - cast(
        float,
        results["start_time"],
    )

    # Add license warnings if any
    try:
        license_warnings = check_commercial_use_warnings(results)
        issues_list = cast(list[dict[str, Any]], results["issues"])
        for warning in license_warnings:
            # Convert license warnings to issues
            issue_dict = {
                "message": warning["message"],
                "severity": warning["severity"],
                "location": "",  # License warnings are generally project-wide
                "details": warning.get("details", {}),
                "type": warning["type"],
            }
            issues_list.append(issue_dict)
    except Exception as e:
        logger.warning(f"Error checking license warnings: {e!s}")

    # Determine if there were operational scan errors vs security findings
    # has_errors should only be True for operational errors (scanner crashes,
    # file not found, etc.) not for security findings detected in models
    operational_error_indicators = [
        # Scanner execution errors
        "Error during scan",
        "Error checking file size",
        "Error scanning file",
        "Scanner crashed",
        "Scan timeout",
        # File system errors
        "Path does not exist",
        "Path is not readable",
        "Permission denied",
        "File not found",
        # Dependency/environment errors
        "not installed, cannot scan",
        "Missing dependency",
        "Import error",
        "Module not found",
        # File format/corruption errors
        "not a valid",
        "Invalid file format",
        "Corrupted file",
        "Bad file signature",
        "Unable to parse",
        # Resource/system errors
        "Out of memory",
        "Disk space",
        "Too many open files",
    ]

    issues_list = cast(list[dict[str, Any]], results["issues"])
    results["has_errors"] = (
        any(
            any(indicator in issue.get("message", "") for indicator in operational_error_indicators)
            for issue in issues_list
            if isinstance(issue, dict) and issue.get("severity") == IssueSeverity.CRITICAL.value
        )
        or not results["success"]
    )

    return results


def determine_exit_code(results: dict[str, Any]) -> int:
    """
    Determine the appropriate exit code based on scan results.

    Exit codes:
    - 0: Success, no security issues found
    - 1: Security issues found (scan completed successfully)
    - 2: Operational errors occurred during scanning

    Args:
        results: Dictionary with scan results

    Returns:
        Exit code (0, 1, or 2)
    """
    # Check for operational errors first (highest priority)
    if results.get("has_errors", False):
        return 2

    # Check for any security findings (warnings, errors, or info issues)
    issues = results.get("issues", [])
    if issues:
        # Filter out DEBUG level issues for exit code determination
        non_debug_issues = [issue for issue in issues if isinstance(issue, dict) and issue.get("severity") != "debug"]
        if non_debug_issues:
            return 1

    # No issues found
    return 0


def _should_skip_file(path: str) -> bool:
    """
    Check if a file should be skipped based on its extension or name.

    Args:
        path: File path to check

    Returns:
        True if the file should be skipped
    """
    import os

    filename = os.path.basename(path)
    _, ext = os.path.splitext(filename)
    ext = ext.lower()

    # Skip common non-model file extensions
    skip_extensions = {
        # Documentation and text files
        ".md",
        ".txt",
        ".rst",
        ".doc",
        ".docx",
        ".pdf",
        # Source code files
        ".py",
        ".js",
        ".ts",
        ".java",
        ".cpp",
        ".c",
        ".h",
        ".go",
        ".rs",
        # Web files
        ".html",
        ".css",
        ".scss",
        ".sass",
        ".less",
        # Configuration files (but keep .json, .yaml, .yml as they can be model configs)
        ".ini",
        ".cfg",
        ".conf",
        ".toml",
        # Build and package files
        ".lock",
        ".log",
        ".pid",
        # Version control
        ".gitignore",
        ".gitattributes",
        ".gitkeep",
        # IDE files
        ".pyc",
        ".pyo",
        ".pyd",
        ".so",
        ".dylib",
        ".dll",
        # Archives (but keep .zip as it can contain models)
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        # Media files
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".bmp",
        ".svg",
        ".ico",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".wmv",
        ".flv",
        # Temporary files
        ".tmp",
        ".temp",
        ".swp",
        ".bak",
        "~",
    }

    if ext in skip_extensions:
        return True

    # Skip hidden files (starting with .) except for specific model extensions
    if filename.startswith(".") and ext not in {".pkl", ".pt", ".pth", ".h5", ".ckpt"}:
        return True

    # Skip specific filenames
    skip_filenames = {
        "LICENSE",
        "README",
        "CHANGELOG",
        "AUTHORS",
        "CONTRIBUTORS",
        "Makefile",
        "requirements.txt",
        "setup.py",
        "setup.cfg",
        "package.json",
        "package-lock.json",
        "yarn.lock",
    }

    return filename in skip_filenames


def _is_huggingface_cache_file(path: str) -> bool:
    """
    Check if a file is a HuggingFace cache/metadata file that should be skipped.

    Args:
        path: File path to check

    Returns:
        True if the file is a HuggingFace cache file that should be skipped
    """
    import os

    filename = os.path.basename(path)

    # HuggingFace cache file patterns - be more specific
    hf_cache_patterns = [
        ".lock",  # Download lock files
        ".metadata",  # HuggingFace metadata files
    ]

    # Check if file ends with cache patterns
    for pattern in hf_cache_patterns:
        if filename.endswith(pattern):
            return True

    # Check for specific HuggingFace cache metadata files
    # We no longer skip all HuggingFace cache files since we handle symlinks properly now

    # Check for Git-related files that are commonly cached
    if filename in [".gitignore", ".gitattributes", "main", "HEAD"]:
        return True

    # Check if file is in refs directory (Git references, not actual model files)
    return bool("/refs/" in path and filename in ["main", "HEAD"])


def scan_file(path: str, config: Optional[dict[str, Any]] = None) -> ScanResult:
    """
    Scan a single file with the appropriate scanner.

    Args:
        path: Path to the file to scan
        config: Optional scanner configuration

    Returns:
        ScanResult object with the scan results
    """
    if config is None:
        config = {}
    validate_scan_config(config)

    # Skip HuggingFace cache files to reduce noise
    if _is_huggingface_cache_file(path):
        sr = ScanResult(scanner_name="skipped")
        sr.add_issue(
            "Skipped HuggingFace cache file",
            severity=IssueSeverity.DEBUG,
            details={"path": path, "reason": "huggingface_cache_file"},
        )
        sr.finish(success=True)
        return sr

    # Check file size first
    max_file_size = config.get("max_file_size", 0)  # Default unlimited
    try:
        file_size = os.path.getsize(path)
        if max_file_size > 0 and file_size > max_file_size:
            sr = ScanResult(scanner_name="size_check")
            sr.add_issue(
                f"File too large to scan: {file_size} bytes (max: {max_file_size})",
                severity=IssueSeverity.WARNING,
                details={
                    "file_size": file_size,
                    "max_file_size": max_file_size,
                    "path": path,
                },
            )
            return sr
    except OSError as e:
        sr = ScanResult(scanner_name="error")
        sr.add_issue(
            f"Error checking file size: {e}",
            severity=IssueSeverity.WARNING,
            details={"error": str(e), "path": path},
        )
        return sr

    logger.info(f"Scanning file: {path}")

    header_format = detect_file_format(path)
    ext_format = detect_format_from_extension(path)
    ext = os.path.splitext(path)[1].lower()

    # Validate file type consistency as a security check
    file_type_valid = validate_file_type(path)
    discrepancy_msg = None
    magic_format = None

    if not file_type_valid:
        # File type validation failed - this is a security concern
        # Get the actual magic bytes format for accurate error message
        magic_format = detect_file_format_from_magic(path)
        discrepancy_msg = (
            f"File type validation failed: extension indicates {ext_format} but magic bytes "
            f"indicate {magic_format}. This could indicate file spoofing or corruption."
        )
        logger.warning(discrepancy_msg)
    elif header_format != ext_format and header_format != "unknown" and ext_format != "unknown":
        # Don't warn about common PyTorch .bin files that are ZIP format internally
        # This is expected behavior for torch.save()
        if not (ext_format == "pytorch_binary" and header_format == "zip" and ext == ".bin"):
            discrepancy_msg = f"File extension indicates {ext_format} but header indicates {header_format}."
            logger.warning(discrepancy_msg)

    # Prefer scanner based on header format using lazy loading
    preferred_scanner: Optional[type[BaseScanner]] = None

    # Special handling for PyTorch files that are ZIP-based
    if header_format == "zip" and ext in [".pt", ".pth"]:
        preferred_scanner = _registry.load_scanner_by_id("pytorch_zip")
    elif header_format == "zip" and ext == ".bin":
        # PyTorch .bin files saved with torch.save() are ZIP format internally
        # Use PickleScanner which can handle both pickle and ZIP-based PyTorch files
        preferred_scanner = _registry.load_scanner_by_id("pickle")
    else:
        format_to_scanner = {
            "pickle": "pickle",
            "pytorch_binary": "pytorch_binary",
            "hdf5": "keras_h5",
            "safetensors": "safetensors",
            "tensorflow_directory": "tf_savedmodel",
            "protobuf": "tf_savedmodel",
            "zip": "zip",
            "onnx": "onnx",
            "gguf": "gguf",
            "ggml": "gguf",
            "numpy": "numpy",
        }
        scanner_id = format_to_scanner.get(header_format)
        if scanner_id:
            preferred_scanner = _registry.load_scanner_by_id(scanner_id)

    result: Optional[ScanResult]
    if preferred_scanner and preferred_scanner.can_handle(path):
        logger.debug(
            f"Using {preferred_scanner.name} scanner for {path} based on header",
        )
        scanner = preferred_scanner(config=config)  # type: ignore[abstract]
        result = scanner.scan(path)
    else:
        # Use registry's lazy loading method to avoid loading all scanners
        scanner_class = _registry.get_scanner_for_path(path)
        if scanner_class:
            logger.debug(f"Using {scanner_class.name} scanner for {path}")
            scanner = scanner_class(config=config)  # type: ignore[abstract]
            result = scanner.scan(path)
        else:
            format_ = header_format
            sr = ScanResult(scanner_name="unknown")
            sr.add_issue(
                f"Unknown or unhandled format: {format_}",
                severity=IssueSeverity.DEBUG,
                details={"format": format_, "path": path},
            )
            result = sr

    if discrepancy_msg:
        # Determine severity based on whether it's a validation failure or just a discrepancy
        severity = IssueSeverity.WARNING if not file_type_valid else IssueSeverity.DEBUG
        # For validation failures, use the actual magic format
        detail_header_format = magic_format if not file_type_valid else header_format
        result.add_issue(
            discrepancy_msg + " Using header-based detection.",
            severity=severity,
            location=path,
            details={
                "extension_format": ext_format,
                "header_format": detail_header_format,
                "file_type_validation_failed": not file_type_valid,
            },
        )

    return result


def merge_scan_result(
    results: dict[str, Any],
    scan_result: ScanResult,
) -> dict[str, Any]:
    """
    Merge a ScanResult object into the results dictionary.

    Args:
        results: The existing results dictionary
        scan_result: The ScanResult object to merge

    Returns:
        The updated results dictionary
    """
    # Convert scan_result to dict if it's a ScanResult object
    scan_dict = scan_result.to_dict() if isinstance(scan_result, ScanResult) else scan_result

    # Merge issues
    issues_list = cast(list[dict[str, Any]], results["issues"])
    for issue in scan_dict.get("issues", []):
        issues_list.append(issue)

    # Update bytes scanned
    results["bytes_scanned"] = cast(int, results["bytes_scanned"]) + scan_dict.get(
        "bytes_scanned",
        0,
    )

    # Update scanner info if not already set
    if "scanner_name" not in results and "scanner" in scan_dict:
        results["scanner_name"] = scan_dict["scanner"]

    # Set success to False if any scan failed
    if not scan_dict.get("success", True):
        results["success"] = False

    return results
