import os
import struct
from typing import Any, ClassVar, Optional

from modelaudit.suspicious_symbols import (
    BINARY_CODE_PATTERNS,
    EXECUTABLE_SIGNATURES,
)

from .base import BaseScanner, IssueSeverity, ScanResult, logger


class PyTorchBinaryScanner(BaseScanner):
    """Scanner for raw PyTorch binary tensor files (.bin)"""

    name = "pytorch_binary"
    description = "Scans PyTorch binary tensor files for suspicious patterns"
    supported_extensions: ClassVar[list[str]] = [".bin"]

    def __init__(self, config: Optional[dict[str, Any]] = None):
        super().__init__(config)
        # Get blacklist patterns from config
        self.blacklist_patterns = self.config.get("blacklist_patterns", [])

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
            from modelaudit.utils.filetype import detect_file_format, validate_file_type

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
            if file_size < 100:
                result.add_check(
                    name="File Size Validation",
                    passed=False,
                    message=f"Suspiciously small binary file: {file_size} bytes",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={"file_size": file_size},
                )
            else:
                result.add_check(
                    name="File Size Validation",
                    passed=True,
                    message="File size is reasonable",
                    location=path,
                    details={"file_size": file_size},
                )

            # Read file in chunks to look for suspicious patterns
            bytes_scanned = 0
            chunk_size = 1024 * 1024  # 1MB chunks

            with open(path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    bytes_scanned += len(chunk)

                    # Check for embedded Python code patterns
                    self._check_for_code_patterns(
                        chunk,
                        result,
                        bytes_scanned - len(chunk),
                    )

                    # Check for blacklisted patterns
                    if self.blacklist_patterns:
                        self._check_for_blacklist_patterns(
                            chunk,
                            result,
                            bytes_scanned - len(chunk),
                        )

                    # Check for executable file signatures
                    self._check_for_executable_signatures(
                        chunk,
                        result,
                        bytes_scanned - len(chunk),
                    )

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

        result.finish(success=True)
        return result

    def _check_for_code_patterns(
        self,
        chunk: bytes,
        result: ScanResult,
        offset: int,
    ) -> None:
        """Check for patterns that might indicate embedded code"""
        # Common patterns that might indicate embedded Python code
        found_suspicious = False
        for pattern in BINARY_CODE_PATTERNS:
            if pattern in chunk:
                # Find the position within the chunk
                pos = chunk.find(pattern)
                result.add_check(
                    name="Embedded Code Pattern Detection",
                    passed=False,
                    message=f"Suspicious code pattern found: {pattern.decode('ascii', errors='ignore')}",
                    severity=IssueSeverity.INFO,
                    location=f"{self.current_file_path} (offset: {offset + pos})",
                    details={
                        "pattern": pattern.decode("ascii", errors="ignore"),
                        "offset": offset + pos,
                    },
                )
                found_suspicious = True

        if not found_suspicious and offset == 0:  # Only record success on first chunk
            result.add_check(
                name="Embedded Code Pattern Detection",
                passed=True,
                message="No suspicious code patterns detected",
                location=self.current_file_path,
            )

    def _check_for_blacklist_patterns(
        self,
        chunk: bytes,
        result: ScanResult,
        offset: int,
    ) -> None:
        """Check for blacklisted patterns in the binary data"""
        found_blacklisted = False
        for pattern in self.blacklist_patterns:
            pattern_bytes = pattern.encode("utf-8")
            if pattern_bytes in chunk:
                pos = chunk.find(pattern_bytes)
                result.add_check(
                    name="Blacklist Pattern Check",
                    passed=False,
                    message=f"Blacklisted pattern found: {pattern}",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{self.current_file_path} (offset: {offset + pos})",
                    details={
                        "pattern": pattern,
                        "offset": offset + pos,
                    },
                )
                found_blacklisted = True

        if not found_blacklisted and offset == 0:  # Only record success on first chunk
            result.add_check(
                name="Blacklist Pattern Check",
                passed=True,
                message="No blacklisted patterns found",
                location=self.current_file_path,
            )

    def _check_for_executable_signatures(
        self,
        chunk: bytes,
        result: ScanResult,
        offset: int,
    ) -> None:
        """Check for executable file signatures with ML context awareness"""
        from modelaudit.utils.ml_context import (
            analyze_binary_for_ml_context,
            should_ignore_executable_signature,
        )

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

        # Process findings with ML context filtering
        for sig, (positions, description) in pattern_counts.items():
            # Calculate pattern density more reasonably for small files
            file_size_mb = self.get_file_size(self.current_file_path) / (1024 * 1024)
            # Use at least 1MB for density calculation to avoid inflated densities in small files
            effective_size_mb = max(file_size_mb, 1.0)
            pattern_density = len(positions) / effective_size_mb

            # Apply ML context filtering
            filtered_positions = []
            ignored_count = 0

            for pos in positions:
                if should_ignore_executable_signature(sig, pos, ml_context, int(pattern_density), len(positions)):
                    ignored_count += 1
                else:
                    filtered_positions.append(pos)

            # Report significant patterns that weren't filtered out
            for pos in filtered_positions[:10]:  # Limit to first 10
                result.add_check(
                    name="Executable Signature Detection",
                    passed=False,
                    message=f"Executable signature found: {description}",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{self.current_file_path} (offset: {pos})",
                    details={
                        "signature": sig.hex(),
                        "description": description,
                        "offset": pos,
                        "total_found": len(positions),
                        "pattern_density_per_mb": round(pattern_density, 1),
                        "ml_context_confidence": ml_context.get("weight_confidence", 0),
                    },
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
                    )

        except Exception as e:
            result.add_check(
                name="Tensor Structure Validation",
                passed=False,
                message=f"Error validating tensor structure: {e!s}",
                severity=IssueSeverity.DEBUG,
                location=self.current_file_path,
                details={"exception": str(e)},
            )
