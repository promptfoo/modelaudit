"""Scanner for raw PyTorch binary model files (.bin, .pt)."""

import os
import struct
from typing import Any, ClassVar

from modelaudit.detectors.suspicious_symbols import (
    BINARY_CODE_PATTERNS,
    EXECUTABLE_SIGNATURES,
)

from .base import BaseScanner, IssueSeverity, ScanResult, logger


class PyTorchBinaryScanner(BaseScanner):
    """Scanner for raw PyTorch binary tensor files (.bin)"""

    name = "pytorch_binary"
    description = "Scans PyTorch binary tensor files for suspicious patterns"
    supported_extensions: ClassVar[list[str]] = [".bin"]
    SHEBANG_CONTEXT_BYTES: ClassVar[int] = 50

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        # Get blacklist patterns from config
        self.blacklist_patterns = self.config.get("blacklist_patterns") or []

    def _is_nested_archive_member(self) -> bool:
        """Return True when this scan is running on an extracted archive member."""
        try:
            return int(self.config.get("_archive_depth", 0)) > 0
        except (TypeError, ValueError):
            return False

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        # Check file extension
        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False

        # Check if it's actually a pytorch binary file
        try:
            from modelaudit.utils.file.detection import detect_file_format, validate_file_type

            file_format = detect_file_format(path)

            # Validate file type for security, but be permissive for .bin files
            # since they can contain various formats of legitimate binary data
            if not validate_file_type(path):
                # File type validation failed - log but don't reject immediately
                # for .bin files since they can contain arbitrary binary data
                logger.warning(f"File type validation failed for .bin file: {path}")
                # Continue to check if it's still a valid pytorch_binary format

            return file_format == "pytorch_binary"
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        """Scan a PyTorch binary file for suspicious patterns"""
        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        try:
            self.current_file_path = path

            # Check for suspiciously small files
            if file_size < 100 and not self._is_nested_archive_member():
                result.add_check(
                    name="File Size Validation",
                    passed=False,
                    message=f"Suspiciously small binary file: {file_size} bytes",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={"file_size": file_size},
                    rule_code="S902",
                )
            else:
                result.add_check(
                    name="File Size Validation",
                    passed=True,
                    message=("Nested binary member size is accepted" if file_size < 100 else "File size is reasonable"),
                    location=path,
                    details={
                        "file_size": file_size,
                        "archive_depth": self.config.get("_archive_depth", 0),
                    },
                    rule_code=None,  # Passing check
                )
            # Read file in chunks to look for suspicious patterns
            bytes_scanned = 0
            chunk_size = 1024 * 1024  # 1MB chunks
            previous_chunk_tail = b""
            chunk_overlap = self._get_chunk_overlap_size(chunk_size)

            with open(path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    bytes_scanned += len(chunk)
                    chunk_offset = bytes_scanned - len(chunk)
                    scan_window = previous_chunk_tail + chunk
                    window_offset = chunk_offset - len(previous_chunk_tail)
                    overlap_prefix_len = len(previous_chunk_tail)

                    # Check for embedded Python code patterns
                    self._check_for_code_patterns(
                        scan_window,
                        result,
                        window_offset,
                        overlap_prefix_len=overlap_prefix_len,
                    )

                    # Check for blacklisted patterns
                    if self.blacklist_patterns:
                        self._check_for_blacklist_patterns(
                            scan_window,
                            result,
                            window_offset,
                            overlap_prefix_len=overlap_prefix_len,
                        )

                    # Check for executable file signatures
                    self._check_for_executable_signatures(
                        chunk,
                        result,
                        chunk_offset,
                    )
                    previous_chunk_tail = chunk[-chunk_overlap:] if chunk_overlap else b""

            result.bytes_scanned = bytes_scanned

            # Check if file appears to be a valid tensor file
            self._validate_tensor_structure(path, result)

        except Exception as e:
            result.add_check(
                name="Binary File Scan",
                passed=False,
                message=f"Error scanning binary file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=not result.has_errors)
        return result

    def _get_chunk_overlap_size(self, chunk_size: int) -> int:
        """Return the number of trailing bytes to carry into the next chunk scan."""
        longest_pattern = max(
            [
                self.SHEBANG_CONTEXT_BYTES,
                *(len(pattern) for pattern in BINARY_CODE_PATTERNS),
                *(len(pattern.encode("utf-8")) for pattern in (self.blacklist_patterns or []) if pattern),
                *(len(signature) for signature in EXECUTABLE_SIGNATURES),
            ]
        )
        return max(0, min(chunk_size - 1, longest_pattern - 1))

    def _check_for_code_patterns(
        self,
        chunk: bytes,
        result: ScanResult,
        offset: int,
        *,
        overlap_prefix_len: int = 0,
    ) -> None:
        """Check for patterns that might indicate embedded code"""
        # Common patterns that might indicate embedded Python code
        found_suspicious = False
        for pattern in BINARY_CODE_PATTERNS:
            search_start = 0
            while True:
                pos = chunk.find(pattern, search_start)
                if pos == -1:
                    break
                search_start = pos + 1
                if pos + len(pattern) <= overlap_prefix_len:
                    continue
                result.add_check(
                    name="Embedded Code Pattern Detection",
                    passed=False,
                    message=f"Suspicious code pattern found: {pattern.decode('ascii', errors='ignore')}",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=f"{self.current_file_path} (offset: {offset + pos})",
                    details={
                        "pattern": pattern.decode("ascii", errors="ignore"),
                        "offset": offset + pos,
                    },
                )
                found_suspicious = True
                break

        if not found_suspicious and offset == 0:  # Only record success on first chunk
            result.add_check(
                name="Embedded Code Pattern Detection",
                passed=True,
                message="No suspicious code patterns detected",
                location=self.current_file_path,
                rule_code=None,  # Passing check
            )

    def _check_for_blacklist_patterns(
        self,
        chunk: bytes,
        result: ScanResult,
        offset: int,
        *,
        overlap_prefix_len: int = 0,
    ) -> None:
        """Check for blacklisted patterns in the binary data"""
        found_blacklisted = False
        for pattern in self.blacklist_patterns or []:
            pattern_bytes = pattern.encode("utf-8")
            if not pattern_bytes:
                continue

            search_start = 0
            while True:
                pos = chunk.find(pattern_bytes, search_start)
                if pos == -1:
                    break
                search_start = pos + 1
                if pos + len(pattern_bytes) <= overlap_prefix_len:
                    continue
                result.add_check(
                    name="Blacklist Pattern Check",
                    passed=False,
                    message=f"Blacklisted pattern found: {pattern}",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{self.current_file_path} (offset: {offset + pos})",
                    rule_code="S1001",
                    details={
                        "pattern": pattern,
                        "offset": offset + pos,
                    },
                )
                found_blacklisted = True
                break

        if not found_blacklisted and offset == 0:  # Only record success on first chunk
            result.add_check(
                name="Blacklist Pattern Check",
                passed=True,
                message="No blacklisted patterns found",
                location=self.current_file_path,
                rule_code=None,  # Passing check
            )

    def _verify_shebang_context(self, data: bytes, offset_in_chunk: int) -> bool:
        """
        Verify that a shebang pattern has the context of a real executable script.

        Real shebangs must have:
        1. Valid interpreter path after #!/
        2. Proper line ending after interpreter path
        """
        # Extract enough bytes to check full shebang line
        max_shebang_len = self.SHEBANG_CONTEXT_BYTES
        snippet = data[offset_in_chunk : offset_in_chunk + max_shebang_len]

        if len(snippet) < 10:  # Need at least #!/bin/sh
            return False

        # Valid interpreter paths
        valid_interpreters = [
            b"#!/bin/bash",
            b"#!/bin/sh",
            b"#!/usr/bin/python",
            b"#!/usr/bin/python3",
            b"#!/usr/bin/env",
            b"#!/bin/zsh",
            b"#!/bin/dash",
            b"#!/usr/bin/perl",
            b"#!/usr/bin/ruby",
        ]

        # Check if snippet matches a valid interpreter
        for interpreter in valid_interpreters:
            if snippet.startswith(interpreter):
                # Found valid interpreter - check what follows
                interp_len = len(interpreter)

                if len(snippet) <= interp_len:
                    return False

                # Get character right after interpreter
                next_char = snippet[interp_len : interp_len + 1]

                # Valid next characters: newline, space, tab, or / (for /usr/bin/env python)
                if next_char in (b"\n", b"\r", b" ", b"\t", b"/"):
                    return True

        return False

    def _check_for_executable_signatures(
        self,
        chunk: bytes,
        result: ScanResult,
        offset: int,
    ) -> None:
        """Check for executable file signatures with context-aware detection"""
        from modelaudit.utils.helpers.ml_context import analyze_binary_for_ml_context

        # RULE 1: Only scan first 64KB - real executables have signatures at start
        if offset > 65536:
            return

        # Analyze ML context for this chunk
        ml_context = analyze_binary_for_ml_context(chunk, self.get_file_size(self.current_file_path))

        # Count patterns for density analysis
        pattern_counts = {}

        # Common executable signatures
        for sig, description in EXECUTABLE_SIGNATURES.items():
            if sig in chunk:
                # Count all occurrences
                positions = []
                pos = 0
                while True:
                    pos = chunk.find(sig, pos)
                    if pos == -1:
                        break
                    positions.append(offset + pos)
                    pos += len(sig)

                if positions:
                    pattern_counts[sig] = (positions, description)

        # Process findings with context-aware filtering
        for sig, (positions, description) in pattern_counts.items():
            # Calculate pattern density more reasonably for small files
            file_size_mb = self.get_file_size(self.current_file_path) / (1024 * 1024)
            # Use at least 1MB for density calculation to avoid inflated densities in small files
            effective_size_mb = max(file_size_mb, 1.0)
            pattern_density = len(positions) / effective_size_mb

            # Apply context-aware filtering
            filtered_positions = []
            ignored_count = 0

            for pos in positions:
                # For shell shebangs, verify they have valid interpreter context
                if sig == b"#!/":
                    # Calculate position within chunk
                    pos_in_chunk = pos - offset
                    if not self._verify_shebang_context(chunk, pos_in_chunk):
                        ignored_count += 1
                        continue  # Skip - not a real shebang

                # For other signatures, check if it's in weight data
                # High ML weight confidence means it's likely coincidental
                if ml_context.get("weight_confidence", 0) > 0.7:
                    ignored_count += 1
                    continue

                filtered_positions.append(pos)

            # Report significant patterns that weren't filtered out
            for pos in filtered_positions[:10]:  # Limit to first 10
                result.add_check(
                    name="Executable Signature Detection",
                    passed=False,
                    message=f"Executable signature found: {description}",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{self.current_file_path} (offset: {pos})",
                    rule_code="S501",
                    details={
                        "signature": sig.hex(),
                        "description": description,
                        "offset": pos,
                        "total_found": len(positions),
                        "pattern_density_per_mb": round(pattern_density, 1),
                        "ml_context_confidence": ml_context.get("weight_confidence", 0),
                    },
                )

            # Add debug note about ignored patterns (only shown in verbose mode)
            if ignored_count > 0 and len(positions) > 5:
                from modelaudit.utils.helpers.ml_context import get_ml_context_explanation

                explanation = get_ml_context_explanation(ml_context, len(positions))
                result.add_check(
                    name="False Positive Filter",
                    passed=True,
                    message=f"Ignored {ignored_count} likely false positive {description} patterns",
                    severity=IssueSeverity.DEBUG,
                    location=f"{self.current_file_path}",
                    details={
                        "signature": sig.hex(),
                        "ignored_count": ignored_count,
                        "total_found": len(positions),
                        "pattern_density_per_mb": round(pattern_density, 1),
                        "ml_context_explanation": explanation,
                    },
                    why=f"These patterns were likely false positives in ML weight data. {explanation}",
                    rule_code=None,  # Passing check
                )

    def _validate_tensor_structure(self, path: str, result: ScanResult) -> None:
        """Validate that the file appears to have valid tensor structure"""
        try:
            with open(path, "rb") as f:
                # Read first few bytes to check for common tensor patterns
                header = f.read(32)

                # Validate tensor file header patterns
                if len(header) < 8:
                    result.add_check(
                        name="Tensor File Size Validation",
                        passed=False,
                        message="File too small to be a valid tensor file",
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={"header_size": len(header)},
                        rule_code="S703",
                    )
                    return

                # Check for IEEE 754 float patterns

                # Try to interpret first 8 bytes as double
                try:
                    value = struct.unpack("d", header[:8])[0]
                    # Validate float value is within reasonable bounds
                    if not (-1e100 < value < 1e100) or value != value:  # NaN check
                        result.metadata["tensor_validation"] = "unusual_float_values"
                except struct.error as e:
                    result.add_check(
                        name="Tensor Header Interpretation",
                        passed=False,
                        message="Error interpreting tensor header",
                        severity=IssueSeverity.DEBUG,
                        location=self.current_file_path,
                        details={
                            "exception": str(e),
                            "exception_type": type(e).__name__,
                        },
                        rule_code="S703",
                    )

        except Exception as e:
            result.add_check(
                name="Tensor Structure Validation",
                passed=False,
                message=f"Error validating tensor structure: {e!s}",
                severity=IssueSeverity.DEBUG,
                location=self.current_file_path,
                details={"exception": str(e)},
                rule_code="S703",
            )

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract PyTorch binary metadata."""
        metadata = super().extract_metadata(file_path)

        try:
            file_size = self.get_file_size(file_path)

            # Basic binary analysis
            with open(file_path, "rb") as f:
                # Read first few KB to analyze structure
                header_data = f.read(min(8192, file_size))

                # Look for PyTorch signatures
                pytorch_signatures = [b"PK\x03\x04", b"\x93NUMPY", b"pytorch", b"torch"]
                detected_format = "pytorch_binary"

                for sig in pytorch_signatures:
                    if sig in header_data:
                        if sig == b"PK\x03\x04":
                            detected_format = "pytorch_zip"
                        elif sig == b"\x93NUMPY":
                            detected_format = "numpy_compatible"
                        break

                metadata.update(
                    {
                        "detected_format": detected_format,
                        "header_size": len(header_data),
                        "has_pytorch_signature": any(sig in header_data for sig in pytorch_signatures),
                    }
                )

                # Try to estimate tensor count from binary patterns
                tensor_markers = header_data.count(b"tensor") + header_data.count(b"Tensor")
                if tensor_markers > 0:
                    metadata["estimated_tensors"] = tensor_markers

        except Exception as e:
            metadata["extraction_error"] = str(e)

        return metadata
