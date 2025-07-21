"""
Simple wrapper to add parallel directory scanning to ModelAudit.
"""

import logging
import os
from pathlib import Path
from typing import Any, Callable, Optional

from modelaudit.core import _is_huggingface_cache_file
from modelaudit.parallel_scanner import ParallelScanner
from modelaudit.scanners.base import IssueSeverity
from modelaudit.utils import is_within_directory

logger = logging.getLogger("modelaudit.parallel_directory")


from modelaudit.utils.file_filter import should_skip_file


def _should_skip_file(file_path: str, skip_file_types: bool = True) -> bool:
    """Check if a file should be skipped based on common non-model file patterns."""
    if not skip_file_types:
        return False
    return should_skip_file(file_path)


def scan_directory_parallel(
    path: str,
    config: dict[str, Any],
    progress_callback: Optional[Callable[[str, float], None]] = None,
    max_workers: Optional[int] = None,
) -> dict[str, Any]:
    """
    Scan a directory using parallel processing.

    Args:
        path: Directory path to scan
        config: Scanner configuration
        progress_callback: Progress callback function
        max_workers: Number of worker processes

    Returns:
        Scan results dictionary
    """
    base_dir = Path(path).resolve()
    files_to_scan = []

    # Track path traversal issues
    path_traversal_issues = []

    # Collect all files to scan
    for root, _, files in os.walk(path, followlinks=False):
        for file in files:
            file_path = os.path.join(root, file)

            # Skip non-model files based on config
            skip_file_types = config.get("skip_file_types", True)
            if _should_skip_file(file_path, skip_file_types):
                continue

            # Skip HuggingFace cache files
            if _is_huggingface_cache_file(file_path):
                continue

            resolved_file = Path(file_path).resolve()

            # Check if this is a HuggingFace cache symlink scenario
            is_hf_cache_symlink = False
            if (
                os.path.islink(file_path)
                and ".cache/huggingface/hub" in str(base_dir)
                and "/snapshots/" in str(file_path)
            ):
                try:
                    link_target = os.readlink(file_path)
                except OSError as e:
                    path_traversal_issues.append(
                        {
                            "message": "Broken symlink encountered",
                            "severity": "warning",
                            "location": file_path,
                            "details": {"error": str(e)},
                        }
                    )
                    continue
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

            # Check file is within base directory
            if not is_hf_cache_symlink and not is_within_directory(str(base_dir), str(resolved_file)):
                path_traversal_issues.append(
                    {
                        "message": "Path traversal outside scanned directory",
                        "severity": "critical",
                        "location": file_path,
                        "details": {"resolved_path": str(resolved_file)},
                    }
                )
                continue

            files_to_scan.append(str(resolved_file))

    if not files_to_scan and not path_traversal_issues:
        # Return empty results
        return {
            "bytes_scanned": 0,
            "issues": [],
            "files_scanned": 0,
            "scanners": [],
            "assets": [],
            "file_metadata": {},
            "has_errors": False,
            "success": True,
        }

    # Use parallel scanner
    scanner = ParallelScanner(
        max_workers=max_workers,
        timeout_per_file=config.get("timeout", 300),
        progress_callback=progress_callback,
    )

    # Run parallel scan
    results = (
        scanner.scan_files(files_to_scan, config)
        if files_to_scan
        else {
            "bytes_scanned": 0,
            "issues": [],
            "files_scanned": 0,
            "scanners": [],
            "assets": [],
            "file_metadata": {},
            "has_errors": False,
            "success": True,
        }
    )

    # Add path traversal issues to results
    if path_traversal_issues:
        for issue in path_traversal_issues:
            # Map string severity to IssueSeverity enum
            severity_str = issue.get("severity", "critical")
            severity_value = IssueSeverity.WARNING.value if severity_str == "warning" else IssueSeverity.CRITICAL.value

            issue_dict = {
                "message": issue["message"],
                "severity": severity_value,
                "location": issue["location"],
                "details": issue["details"],
            }
            results["issues"].append(issue_dict)

    # Add parallel scan markers
    results["parallel_scan"] = True
    results["worker_count"] = scanner.max_workers if files_to_scan else 0

    logger.debug(f"Parallel scan returning results with keys: {list(results.keys())}")
    logger.debug(f"parallel_scan={results.get('parallel_scan')}, worker_count={results.get('worker_count')}")

    return results
