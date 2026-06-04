"""Model Metadata Extractor - Extract metadata from ML model files."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from .scanners import get_scanner_for_file
from .utils import is_within_directory

logger = logging.getLogger("modelaudit.metadata_extractor")

MAX_METADATA_DIRECTORY_FILES = 10_000
MAX_METADATA_DIRECTORY_BYTES = 1024 * 1024 * 1024
MAX_METADATA_DIRECTORY_DEPTH = 64
MAX_METADATA_DIRECTORY_ENTRIES = 20_000
METADATA_DIRECTORY_BUDGET_REASON = "metadata_directory_extraction_budget_exceeded"
NON_REGULAR_METADATA_ENTRY_ERROR = "Unsupported non-regular filesystem entry"


class ModelMetadataExtractor:
    """Extract metadata from ML model files using existing scanner infrastructure."""

    def extract(self, path: str, security_only: bool = False, allow_deserialization: bool = False) -> dict[str, Any]:
        """Extract metadata from a model file or directory."""
        path_obj = Path(path)

        if path_obj.is_dir():
            return self._extract_directory_metadata(path, security_only, allow_deserialization)
        else:
            return self._extract_file_metadata(path, security_only, allow_deserialization)

    def _extract_file_metadata(
        self, file_path: str, security_only: bool = False, allow_deserialization: bool = False
    ) -> dict[str, Any]:
        """Extract metadata from a single model file."""
        scanner = get_scanner_for_file(file_path, {"allow_metadata_deserialization": allow_deserialization})
        if scanner is None:
            return {
                "file": os.path.basename(file_path),
                "path": file_path,
                "format": "unknown",
                "error": "No scanner available for this file type",
            }

        scanner_class = type(scanner)

        # Start with file-level fields, then layer scanner metadata on top.
        # Scanner extract_metadata() provides format, description, file_size
        # which we augment with file/path identifiers.
        try:
            metadata = scanner.extract_metadata(file_path)
        except Exception as e:
            logger.debug("extract_metadata failed for %s: %s", file_path, e, exc_info=True)
            metadata = {"extraction_error": str(e)}

        # Always ensure file identifiers are present
        metadata.setdefault("file", os.path.basename(file_path))
        metadata.setdefault("path", file_path)
        metadata.setdefault("format", getattr(scanner, "name", getattr(scanner_class, "name", "unknown")))

        # Filter for security-only if requested
        if security_only:
            metadata = self._filter_security_metadata(metadata)

        return metadata

    def _extract_directory_metadata(
        self, directory: str, security_only: bool = False, allow_deserialization: bool = False
    ) -> dict[str, Any]:
        """Extract metadata from all model files in a directory."""
        results: dict[str, Any] = {"directory": directory, "files": [], "summary": {"total_files": 0, "formats": {}}}
        base_path = Path(directory).resolve()
        base_dir = str(base_path)
        files_considered = 0
        bytes_considered = 0
        entries_considered = 1
        stop_traversal = False
        pending_directories = [(base_path, 0)]

        if entries_considered > MAX_METADATA_DIRECTORY_ENTRIES:
            self._mark_directory_budget_exceeded(
                results,
                limit="max_entries",
                max_entries=MAX_METADATA_DIRECTORY_ENTRIES,
                entries_considered=entries_considered,
                path=base_dir,
            )
            return results

        while pending_directories and not stop_traversal:
            root_path, current_depth = pending_directories.pop()
            root = str(root_path)
            child_directories: list[Path] = []
            files: list[str] = []
            try:
                with os.scandir(root_path) as entries:
                    for entry in entries:
                        if entries_considered >= MAX_METADATA_DIRECTORY_ENTRIES:
                            self._mark_directory_budget_exceeded(
                                results,
                                limit="max_entries",
                                max_entries=MAX_METADATA_DIRECTORY_ENTRIES,
                                entries_considered=entries_considered,
                                path=entry.path,
                            )
                            stop_traversal = True
                            break

                        entries_considered += 1
                        try:
                            is_directory = entry.is_dir(follow_symlinks=False)
                        except OSError as e:
                            logger.debug("Failed to classify metadata directory entry %s: %s", entry.path, e)
                            is_directory = False

                        if is_directory:
                            child_depth = current_depth + 1
                            if child_depth > MAX_METADATA_DIRECTORY_DEPTH:
                                self._mark_directory_budget_exceeded(
                                    results,
                                    limit="max_depth",
                                    max_depth=MAX_METADATA_DIRECTORY_DEPTH,
                                    observed_depth=child_depth,
                                    path=entry.path,
                                )
                                continue
                            child_directories.append(Path(entry.path))
                            continue

                        try:
                            is_symlink = entry.is_symlink()
                        except OSError as e:
                            logger.debug("Failed to classify metadata symlink entry %s: %s", entry.path, e)
                            is_symlink = False

                        try:
                            if is_symlink and entry.is_dir():
                                continue
                        except OSError as e:
                            logger.debug("Failed to inspect metadata directory symlink %s: %s", entry.path, e)

                        if files_considered >= MAX_METADATA_DIRECTORY_FILES:
                            self._mark_directory_budget_exceeded(
                                results,
                                limit="max_files",
                                max_files=MAX_METADATA_DIRECTORY_FILES,
                                files_considered=files_considered,
                                path=entry.path,
                            )
                            stop_traversal = True
                            break

                        files_considered += 1

                        try:
                            is_regular_file = entry.is_file(follow_symlinks=is_symlink)
                        except OSError as e:
                            results["files"].append({"file": entry.name, "path": entry.path, "error": str(e)})
                            continue

                        if not is_regular_file:
                            results["files"].append(
                                {
                                    "file": entry.name,
                                    "path": entry.path,
                                    "error": NON_REGULAR_METADATA_ENTRY_ERROR,
                                }
                            )
                            continue

                        files.append(entry.name)
            except OSError as e:
                results["files"].append({"file": root_path.name, "path": root, "error": str(e)})
                continue

            files.sort()
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    if not is_within_directory(base_dir, file_path):
                        results["files"].append(
                            {
                                "file": file,
                                "path": file_path,
                                "error": "Path traversal outside metadata directory",
                            }
                        )
                        continue

                    try:
                        file_size = Path(file_path).stat().st_size
                    except OSError as e:
                        results["files"].append({"file": file, "path": file_path, "error": str(e)})
                        continue

                    if bytes_considered + file_size > MAX_METADATA_DIRECTORY_BYTES:
                        self._mark_directory_budget_exceeded(
                            results,
                            limit="max_bytes",
                            max_bytes=MAX_METADATA_DIRECTORY_BYTES,
                            bytes_considered=bytes_considered,
                            next_file_size=file_size,
                            path=file_path,
                        )
                        stop_traversal = True
                        break

                    bytes_considered += file_size
                    file_metadata = self._extract_file_metadata(file_path, security_only, allow_deserialization)
                    if file_metadata.get("format") != "unknown":
                        results["files"].append(file_metadata)

                        # Update summary
                        results["summary"]["total_files"] += 1
                        format_name = file_metadata.get("format", "unknown")
                        results["summary"]["formats"][format_name] = (
                            results["summary"]["formats"].get(format_name, 0) + 1
                        )

                except Exception as e:
                    logger.debug("Metadata extraction failed for %s: %s", file_path, e, exc_info=True)
                    results["files"].append({"file": file, "path": file_path, "error": str(e)})

            child_directories.sort(key=lambda child_path: child_path.name)
            pending_directories.extend((child_path, current_depth + 1) for child_path in reversed(child_directories))

        return results

    @staticmethod
    def _mark_directory_budget_exceeded(results: dict[str, Any], *, limit: str, **details: Any) -> None:
        """Record incomplete directory metadata extraction once an aggregate budget is exhausted."""
        results["analysis_incomplete"] = True
        results["scan_outcome"] = "inconclusive"
        reasons = results.setdefault("scan_outcome_reasons", [])
        if METADATA_DIRECTORY_BUDGET_REASON not in reasons:
            reasons.append(METADATA_DIRECTORY_BUDGET_REASON)

        budget_event = {
            "reason": METADATA_DIRECTORY_BUDGET_REASON,
            "limit": limit,
            "analysis_incomplete": True,
            **details,
        }
        results.setdefault("budget_events", []).append(budget_event)
        results["summary"]["analysis_incomplete"] = True
        results["summary"]["scan_outcome"] = "inconclusive"
        results["summary"]["scan_outcome_reasons"] = list(reasons)

    def _filter_security_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        """Filter metadata to show only security-relevant information."""
        security_keys = [
            "file",
            "path",
            "format",
            "file_size",
            "suspicious_patterns",
            "security_flags",
            "custom_operators",
            "dangerous_ops",
            "external_data",
            "urls",
            "imports",
            "producer",
            "framework_version",
            # ONNX security fields
            "external_data_paths",
            "model_producer",
            "domain",
            # SafeTensors security fields
            "custom_metadata",
            "tensor_count",
            # Common security indicators
            "has_custom_operators",
            "has_external_data",
            # Deserialization status
            "deserialization_skipped",
            "reason",
            "dangerous_opcodes",
            "has_dangerous_opcodes",
        ]

        filtered = {}
        for key in security_keys:
            if key in metadata:
                filtered[key] = metadata[key]

        # Add any keys containing 'security', 'suspicious', 'dangerous', etc.
        for key, value in metadata.items():
            key_lower = key.lower()
            if any(term in key_lower for term in ["security", "suspicious", "dangerous", "malicious", "risk"]):
                filtered[key] = value

        return filtered
