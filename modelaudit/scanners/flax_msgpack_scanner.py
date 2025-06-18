from __future__ import annotations

import os
from typing import Any, Dict, Optional

try:
    import msgpack  # type: ignore

    HAS_MSGPACK = True
except Exception:  # pragma: no cover - optional dependency missing
    HAS_MSGPACK = False

from .base import BaseScanner, IssueSeverity, ScanResult


class FlaxMsgpackScanner(BaseScanner):
    """Scanner for Flax msgpack checkpoint files."""

    name = "flax_msgpack"
    description = "Scans Flax/JAX msgpack checkpoints for integrity issues"
    supported_extensions = [".msgpack"]

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self.max_blob_bytes = self.config.get(
            "max_blob_bytes", 10 * 1024 * 1024
        )  # 10MB

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext in cls.supported_extensions and HAS_MSGPACK:
            return True
        return False

    def _check_blob(self, value: Any, location: str, result: ScanResult) -> None:
        if isinstance(value, (bytes, bytearray)):
            size = len(value)
            if size > self.max_blob_bytes:
                result.add_issue(
                    f"Byte blob too large: {size} bytes",
                    severity=IssueSeverity.WARNING,
                    location=location,
                    details={"size": size},
                )
        elif isinstance(value, dict):
            for k, v in value.items():
                self._check_blob(v, f"{location}/{k}", result)
        elif isinstance(value, list):
            for i, v in enumerate(value):
                self._check_blob(v, f"{location}[{i}]", result)

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        if not HAS_MSGPACK:
            result.add_issue(
                "msgpack library not installed",
                severity=IssueSeverity.CRITICAL,
                location=path,
            )
            result.finish(success=False)
            return result

        try:
            self.current_file_path = path
            with open(path, "rb") as f:
                unpacker = msgpack.Unpacker(f, raw=False)
                obj = unpacker.unpack()
                leftover = f.read(1)
                if leftover:
                    result.add_issue(
                        "Extra trailing bytes after msgpack data",
                        severity=IssueSeverity.WARNING,
                        location=path,
                    )

            result.metadata["top_level_type"] = type(obj).__name__
            if isinstance(obj, dict):
                result.metadata["top_level_keys"] = list(obj.keys())
            self._check_blob(obj, "", result)
            result.bytes_scanned = file_size
        except Exception as e:  # pragma: no cover - unexpected errors
            result.add_issue(
                f"Invalid Flax .msgpack file: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result
