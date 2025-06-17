import os
import struct
from typing import Any, Optional

from .base import BaseScanner, IssueSeverity, ScanResult


class PyTorchBinaryScanner(BaseScanner):
    """Scanner for raw PyTorch binary tensor files (.bin)"""

    name = "pytorch_binary"
    description = "Scans PyTorch binary tensor files for suspicious patterns"
    supported_extensions = [".bin"]

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
            from modelaudit.utils.filetype import detect_file_format

            file_format = detect_file_format(path)
            return file_format == "pytorch_binary"
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        """Scan a PyTorch binary file for suspicious patterns"""
        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            self.current_file_path = path

            # Check for suspiciously small files
            if file_size < 100:
                result.add_issue(
                    f"Suspiciously small binary file: {file_size} bytes",
                    severity=IssueSeverity.WARNING,
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
                        chunk, result, bytes_scanned - len(chunk)
                    )

                    # Check for blacklisted patterns
                    if self.blacklist_patterns:
                        self._check_for_blacklist_patterns(
                            chunk, result, bytes_scanned - len(chunk)
                        )

                    # Check for executable file signatures
                    self._check_for_executable_signatures(
                        chunk, result, bytes_scanned - len(chunk)
                    )

            result.bytes_scanned = bytes_scanned

            # Check if file appears to be a valid tensor file
            self._validate_tensor_structure(path, result)

        except Exception as e:
            result.add_issue(
                f"Error scanning binary file: {str(e)}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result

    def _check_for_code_patterns(
        self, chunk: bytes, result: ScanResult, offset: int
    ) -> None:
        """Check for patterns that might indicate embedded code"""
        # Common patterns that might indicate embedded Python code
        code_patterns = [
            b"import os",
            b"import sys",
            b"import subprocess",
            b"eval(",
            b"exec(",
            b"__import__",
            b"compile(",
            b"globals()",
            b"locals()",
            b"open(",
            b"file(",
            b"input(",
            b"raw_input(",
            b"execfile(",
            b"os.system",
            b"subprocess.call",
            b"subprocess.Popen",
            b"socket.socket",
        ]

        for pattern in code_patterns:
            if pattern in chunk:
                # Find the position within the chunk
                pos = chunk.find(pattern)
                result.add_issue(
                    f"Suspicious code pattern found: {pattern.decode('ascii', errors='ignore')}",
                    severity=IssueSeverity.WARNING,
                    location=f"{self.current_file_path} (offset: {offset + pos})",
                    details={
                        "pattern": pattern.decode("ascii", errors="ignore"),
                        "offset": offset + pos,
                    },
                )

    def _check_for_blacklist_patterns(
        self, chunk: bytes, result: ScanResult, offset: int
    ) -> None:
        """Check for blacklisted patterns in the binary data"""
        for pattern in self.blacklist_patterns:
            pattern_bytes = pattern.encode("utf-8")
            if pattern_bytes in chunk:
                pos = chunk.find(pattern_bytes)
                result.add_issue(
                    f"Blacklisted pattern found: {pattern}",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{self.current_file_path} (offset: {offset + pos})",
                    details={
                        "pattern": pattern,
                        "offset": offset + pos,
                    },
                )

    def _check_for_executable_signatures(
        self, chunk: bytes, result: ScanResult, offset: int
    ) -> None:
        """Check for executable file signatures"""
        # Common executable signatures
        executable_sigs = {
            b"MZ": "Windows executable (PE)",
            b"\x7fELF": "Linux executable (ELF)",
            b"\xfe\xed\xfa\xce": "macOS executable (Mach-O 32-bit)",
            b"\xfe\xed\xfa\xcf": "macOS executable (Mach-O 64-bit)",
            b"\xcf\xfa\xed\xfe": "macOS executable (Mach-O)",
            b"#!/": "Shell script shebang",
        }

        for sig, description in executable_sigs.items():
            if sig in chunk:
                pos = chunk.find(sig)
                result.add_issue(
                    f"Executable signature found: {description}",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{self.current_file_path} (offset: {offset + pos})",
                    details={
                        "signature": sig.hex(),
                        "description": description,
                        "offset": offset + pos,
                    },
                )

    def _validate_tensor_structure(self, path: str, result: ScanResult) -> None:
        """Validate that the file appears to have valid tensor structure"""
        try:
            with open(path, "rb") as f:
                # Read first few bytes to check for common tensor patterns
                header = f.read(32)

                # PyTorch tensors often start with specific patterns
                # This is a basic check - real validation would require parsing the format
                if len(header) < 8:
                    result.add_issue(
                        "File too small to be a valid tensor file",
                        severity=IssueSeverity.WARNING,
                        location=self.current_file_path,
                        details={"header_size": len(header)},
                    )
                    return

                # Check if it looks like it might contain float32/float64 data
                # by looking for patterns of IEEE 754 floats
                # This is a heuristic - not definitive

                # Try to interpret first 8 bytes as double
                try:
                    value = struct.unpack("d", header[:8])[0]
                    # Check if it's a reasonable float value (not NaN, not huge)
                    if not (-1e100 < value < 1e100) or value != value:  # NaN check
                        result.metadata["tensor_validation"] = "unusual_float_values"
                except struct.error:
                    pass

        except Exception as e:
            result.add_issue(
                f"Error validating tensor structure: {str(e)}",
                severity=IssueSeverity.DEBUG,
                location=self.current_file_path,
                details={"exception": str(e)},
            )
