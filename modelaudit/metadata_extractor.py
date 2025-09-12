"""Model Metadata Extractor - Extract metadata from ML model files."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .scanners import SCANNER_REGISTRY


class ModelMetadataExtractor:
    """Extract metadata from ML model files using existing scanner infrastructure."""

    def extract(self, path: str, security_only: bool = False) -> dict[str, Any]:
        """Extract metadata from a model file or directory."""
        path_obj = Path(path)

        if path_obj.is_dir():
            return self._extract_directory_metadata(path, security_only)
        else:
            return self._extract_file_metadata(path, security_only)

    def _extract_file_metadata(self, file_path: str, security_only: bool = False) -> dict[str, Any]:
        """Extract metadata from a single model file."""
        # Find appropriate scanner for this file
        scanner_class = None
        for scanner_cls in SCANNER_REGISTRY:
            if scanner_cls.can_handle(file_path):
                scanner_class = scanner_cls
                break

        if not scanner_class:
            return {
                "file": os.path.basename(file_path),
                "format": "unknown",
                "error": "No scanner available for this file type",
            }

        # Create scanner instance and extract metadata
        scanner = scanner_class()

        # Get basic metadata
        metadata = {
            "file": os.path.basename(file_path),
            "path": file_path,
            "format": getattr(scanner_class, "name", "unknown"),
            "file_size": scanner.get_file_size(file_path)
            if hasattr(scanner, "get_file_size")
            else os.path.getsize(file_path),
        }

        # Try to extract format-specific metadata if scanner supports it
        if hasattr(scanner, "extract_metadata"):
            try:
                format_metadata = scanner.extract_metadata(file_path)
                metadata.update(format_metadata)
            except Exception as e:
                metadata["extraction_error"] = str(e)

        # Filter for security-only if requested
        if security_only:
            metadata = self._filter_security_metadata(metadata)

        return metadata

    def _extract_directory_metadata(self, directory: str, security_only: bool = False) -> dict[str, Any]:
        """Extract metadata from all model files in a directory."""
        results: dict[str, Any] = {"directory": directory, "files": [], "summary": {"total_files": 0, "formats": {}}}

        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    file_metadata = self._extract_file_metadata(file_path, security_only)
                    if file_metadata.get("format") != "unknown":
                        results["files"].append(file_metadata)

                        # Update summary
                        results["summary"]["total_files"] += 1
                        format_name = file_metadata.get("format", "unknown")
                        results["summary"]["formats"][format_name] = (
                            results["summary"]["formats"].get(format_name, 0) + 1
                        )

                except Exception as e:
                    results["files"].append({"file": file, "path": file_path, "error": str(e)})

        return results

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
        ]

        filtered = {}
        for key in security_keys:
            if key in metadata:
                filtered[key] = metadata[key]

        # Add any keys containing 'security', 'suspicious', 'dangerous', etc.
        for key, value in metadata.items():
            if any(term in key.lower() for term in ["security", "suspicious", "dangerous", "malicious", "risk"]):
                filtered[key] = value

        return filtered
