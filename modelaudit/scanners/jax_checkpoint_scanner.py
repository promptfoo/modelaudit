"""JAX Checkpoint Scanner - Handles non-msgpack JAX/Flax model formats."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult

np: Any

try:
    import numpy as np

    HAS_NUMPY = True
except ImportError:  # pragma: no cover
    HAS_NUMPY = False
    np = None


class JaxCheckpointScanner(BaseScanner):
    """Scanner for JAX checkpoint files in various formats (Orbax, pickle-based, etc.)."""

    name = "jax_checkpoint"
    description = "Scans JAX checkpoint files in various serialization formats"
    supported_extensions: ClassVar[list[str]] = [
        ".ckpt",  # JAX checkpoint files (when not PyTorch)
        ".checkpoint",  # Explicit checkpoint files
        ".orbax-checkpoint",  # Orbax checkpoint directories
        ".pickle",  # JAX models saved as pickle (when context suggests JAX)
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.max_file_size = self.config.get(
            "max_file_size", 100 * 1024 * 1024 * 1024
        )  # 100GB limit for large JAX models

        # JAX-specific suspicious patterns
        self.jax_suspicious_patterns = [
            # JAX transform misuse
            r"jax\.experimental\.host_callback\.call",
            r"jax\.experimental\.io_callback",
            r"jax\.debug\.callback",
            # Dangerous JAX operations
            r"jax\.lax\.stop_gradient.*eval",
            r"jax\.lax\.cond.*exec",
            # Orbax-specific threats
            r"orbax\.checkpoint\.restore.*eval",
            r"orbax\.checkpoint\.save.*exec",
            # JAX compilation threats
            r"jax\.jit.*subprocess",
            r"jax\.pmap.*os\.system",
        ]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.exists(path):
            return False

        # Handle directory-based checkpoints (like Orbax)
        if os.path.isdir(path):
            return cls._is_jax_checkpoint_directory(path)

        # Handle file-based checkpoints
        if os.path.isfile(path):
            ext = os.path.splitext(path)[1].lower()
            if ext in cls.supported_extensions:
                return cls._is_likely_jax_file(path)

        return False

    @classmethod
    def _is_jax_checkpoint_directory(cls, path: str) -> bool:
        """Check if directory looks like a JAX/Orbax checkpoint."""
        path_obj = Path(path)

        # Orbax checkpoint indicators
        orbax_files = ["checkpoint", "checkpoint_0", "metadata.json", "_CHECKPOINT", "orbax_checkpoint_metadata.json"]

        # Check for Orbax files
        for orbax_file in orbax_files:
            if (path_obj / orbax_file).exists():
                return True

        # Check for JAX checkpoint patterns
        jax_patterns = ["step_*", "params_*", "state_*", "model_*"]
        return any(list(path_obj.glob(pattern)) for pattern in jax_patterns)

    @classmethod
    def _is_likely_jax_file(cls, path: str) -> bool:
        """Determine if a file is likely a JAX checkpoint."""
        try:
            with open(path, "rb") as f:
                header = f.read(512)

            # Check for pickle format with JAX indicators
            if header.startswith(b"\x80"):  # Pickle protocol
                # Read more to check for JAX-specific content
                try:
                    with open(path, "rb") as f:
                        data = f.read(8192)  # Read first 8KB
                        data_str = data.decode("utf-8", errors="ignore").lower()

                    jax_indicators = ["jax", "flax", "haiku", "orbax", "arrayimpl", "jaxlib", "device_array"]

                    return any(indicator in data_str for indicator in jax_indicators)
                except Exception:
                    pass

            # Check for JSON metadata files
            if path.endswith(".json") and b"jax" in header.lower():
                return True

            # Check for NumPy files in JAX context
            if header.startswith(b"\x93NUMPY") and "jax" in path.lower():
                return True

        except Exception:
            pass

        return False

    def _scan_orbax_checkpoint(self, path: str, result: ScanResult) -> None:
        """Scan Orbax checkpoint directory."""
        path_obj = Path(path)

        # Check metadata files
        metadata_files = ["metadata.json", "orbax_checkpoint_metadata.json", "_CHECKPOINT"]

        for metadata_file in metadata_files:
            metadata_path = path_obj / metadata_file
            if metadata_path.exists():
                try:
                    with open(metadata_path, encoding="utf-8") as f:
                        metadata = json.load(f)

                    # Analyze metadata for suspicious content
                    self._analyze_orbax_metadata(metadata, str(metadata_path), result)

                except json.JSONDecodeError as e:
                    result.add_check(
                        name="Orbax Metadata JSON Validation",
                        passed=False,
                        message=f"Invalid JSON in Orbax metadata: {e}",
                        severity=IssueSeverity.WARNING,
                        location=str(metadata_path),
                        details={"error": str(e), "file": metadata_file},
                    )
                except Exception as e:
                    result.add_check(
                        name="Orbax Metadata Read Check",
                        passed=False,
                        message=f"Error reading Orbax metadata: {e}",
                        severity=IssueSeverity.WARNING,
                        location=str(metadata_path),
                    )

        # Scan checkpoint files
        checkpoint_files = list(path_obj.glob("checkpoint*"))
        for checkpoint_file in checkpoint_files:
            if checkpoint_file.is_file():
                self._scan_checkpoint_file(str(checkpoint_file), result)

    def _analyze_orbax_metadata(self, metadata: dict[str, Any], path: str, result: ScanResult) -> None:
        """Analyze Orbax metadata for security issues."""

        # Check for suspicious restore functions
        if "restore_fn" in metadata:
            result.add_check(
                name="Orbax Restore Function Check",
                passed=False,
                message="Custom restore function detected in Orbax metadata",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"restore_fn": str(metadata["restore_fn"])[:200]},
            )

        # Check for code injection in metadata
        metadata_str = str(metadata).lower()
        for pattern in self.jax_suspicious_patterns:
            if pattern in metadata_str:
                result.add_check(
                    name="Orbax Pattern Security Check",
                    passed=False,
                    message=f"Suspicious pattern in Orbax metadata: {pattern}",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"pattern": pattern},
                )

        # Extract useful metadata
        if isinstance(metadata, dict):
            result.metadata.update(
                {
                    "orbax_version": metadata.get("version"),
                    "checkpoint_type": metadata.get("type", "unknown"),
                    "save_format": metadata.get("format", "unknown"),
                }
            )

    def _scan_checkpoint_file(self, path: str, result: ScanResult) -> None:
        """Scan individual checkpoint file."""
        try:
            file_size = os.path.getsize(path)

            if file_size > self.max_file_size:
                result.add_check(
                    name="Checkpoint File Size Check",
                    passed=False,
                    message=f"Checkpoint file too large: {file_size:,} bytes",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"file_size": file_size, "max_size": self.max_file_size},
                )
                return

            with open(path, "rb") as f:
                header = f.read(1024)

            # Check file format
            if header.startswith(b"\x80"):  # Pickle format
                self._scan_pickle_checkpoint(path, result)
            elif header.startswith(b"\x93NUMPY"):  # NumPy format
                self._scan_numpy_checkpoint(path, result)
            elif header.startswith(b"{"):  # JSON format
                self._scan_json_checkpoint(path, result)
            else:
                result.add_check(
                    name="Checkpoint Format Detection",
                    passed=True,
                    message=f"Unknown checkpoint file format: {path}",
                    location=path,
                    details={"format": "unknown"},
                )

        except Exception as e:
            result.add_check(
                name="Checkpoint File Scan",
                passed=False,
                message=f"Error scanning checkpoint file: {e}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"error": str(e), "error_type": type(e).__name__},
            )

    def _scan_pickle_checkpoint(self, path: str, result: ScanResult) -> None:
        """Scan pickle-based JAX checkpoint."""
        try:
            # Use safe pickle loading practices
            with open(path, "rb") as f:
                # Read pickle opcodes to check for dangerous operations
                # Don't actually unpickle for security
                data = f.read(8192)  # Read first 8KB

            # Check for dangerous pickle opcodes
            dangerous_opcodes = [
                b"R",  # REDUCE
                b"i",  # INST
                b"o",  # OBJ
                b"b",  # BUILD
                b"c",  # GLOBAL
            ]

            for opcode in dangerous_opcodes:
                if opcode in data:
                    result.add_check(
                        name="Pickle Opcode Security Check",
                        passed=False,
                        message=f"Dangerous pickle opcode detected: {opcode.decode('ascii', errors='ignore')}",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"opcode": opcode.hex()},
                    )

            # Check for JAX-specific suspicious content
            try:
                data_str = data.decode("utf-8", errors="ignore")
                for pattern in self.jax_suspicious_patterns:
                    if pattern in data_str:
                        result.add_check(
                            name="JAX Pattern Security Check",
                            passed=False,
                            message=f"Suspicious JAX pattern in pickle: {pattern}",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={"pattern": pattern},
                        )
            except Exception:
                pass

        except Exception as e:
            result.add_check(
                name="Pickle Checkpoint Scan",
                passed=False,
                message=f"Error scanning pickle checkpoint: {e}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"error": str(e), "error_type": type(e).__name__},
            )

    def _scan_numpy_checkpoint(self, path: str, result: ScanResult) -> None:
        """Scan NumPy-based JAX checkpoint."""
        if not HAS_NUMPY:
            result.add_check(
                name="NumPy Library Check",
                passed=False,
                message="NumPy not available for checkpoint analysis",
                severity=IssueSeverity.INFO,
                location=path,
                details={"required_library": "numpy"},
            )
            return

        try:
            # Load and validate NumPy array
            array = np.load(path, allow_pickle=False)  # Disable pickle for security

            # Check array properties
            if array.size > 100_000_000:  # 100M elements
                result.add_check(
                    name="NumPy Array Size Check",
                    passed=False,
                    message=f"Extremely large NumPy array: {array.size:,} elements",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"size": array.size, "shape": array.shape, "threshold": 100_000_000},
                )

            # Validate array shape
            if any(dim <= 0 for dim in array.shape):
                result.add_check(
                    name="NumPy Array Shape Validation",
                    passed=False,
                    message="Invalid array shape with non-positive dimensions",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"shape": array.shape},
                )

        except Exception as e:
            result.add_check(
                name="NumPy Checkpoint Load",
                passed=False,
                message=f"Error loading NumPy checkpoint: {e}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"error": str(e), "error_type": type(e).__name__},
            )

    def _scan_json_checkpoint(self, path: str, result: ScanResult) -> None:
        """Scan JSON-based checkpoint metadata."""
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)

            # Analyze JSON content for suspicious patterns
            data_str = json.dumps(data).lower()
            for pattern in self.jax_suspicious_patterns:
                if pattern in data_str:
                    result.add_check(
                        name="JSON Pattern Security Check",
                        passed=False,
                        message=f"Suspicious pattern in JSON checkpoint: {pattern}",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"pattern": pattern},
                    )

        except json.JSONDecodeError as e:
            result.add_check(
                name="JSON Checkpoint Validation",
                passed=False,
                message=f"Invalid JSON in checkpoint: {e}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"error": str(e)},
            )
        except Exception as e:
            result.add_check(
                name="JSON Checkpoint Scan",
                passed=False,
                message=f"Error scanning JSON checkpoint: {e}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"error": str(e), "error_type": type(e).__name__},
            )

    def scan(self, path: str) -> ScanResult:
        """Scan JAX checkpoint file or directory."""
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        try:
            self.current_file_path = path

            if os.path.isdir(path):
                # Scan directory-based checkpoint (like Orbax)
                result.metadata["checkpoint_type"] = "directory"
                result.metadata["path_type"] = "directory"

                self._scan_orbax_checkpoint(path, result)

                # Calculate total size
                total_size = sum(f.stat().st_size for f in Path(path).rglob("*") if f.is_file())
                result.bytes_scanned = total_size
                result.metadata["total_size"] = total_size

            else:
                # Scan single file checkpoint
                result.metadata["checkpoint_type"] = "file"
                result.metadata["path_type"] = "file"

                file_size = os.path.getsize(path)
                result.bytes_scanned = file_size
                result.metadata["file_size"] = file_size

                self._scan_checkpoint_file(path, result)

        except Exception as e:
            result.add_check(
                name="JAX Checkpoint Scan",
                passed=False,
                message=f"Unexpected error scanning JAX checkpoint: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"error": str(e), "error_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result
