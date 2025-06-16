from __future__ import annotations

import io
import os
import zlib
import lzma
from typing import Optional, Any

from .base import BaseScanner, IssueSeverity, ScanResult
from .pickle_scanner import PickleScanner
from ..utils.filetype import read_magic_bytes


class JoblibScanner(BaseScanner):
    """Scanner for joblib serialized files."""

    name = "joblib"
    description = "Scans joblib files by decompressing and analyzing embedded pickle"
    supported_extensions = [".joblib"]

    def __init__(self, config: Optional[dict[str, Any]] = None):
        super().__init__(config)
        self.pickle_scanner = PickleScanner(config)

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext != ".joblib":
            return False
        return True

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            self.current_file_path = path
            magic = read_magic_bytes(path, 4)
            with open(path, "rb") as f:
                data = f.read()

            if magic.startswith(b"PK"):
                # Treat as zip archive
                from .zip_scanner import ZipScanner

                zip_scanner = ZipScanner(self.config)
                sub_result = zip_scanner.scan(path)
                result.merge(sub_result)
                result.bytes_scanned = sub_result.bytes_scanned
                result.metadata.update(sub_result.metadata)
                result.finish(success=sub_result.success)
                return result

            if magic.startswith(b"\x80"):
                file_like = io.BytesIO(data)
                sub_result = self.pickle_scanner._scan_pickle_bytes(file_like, len(data))
                result.merge(sub_result)
                result.bytes_scanned = len(data)
            else:
                # Try zlib then lzma
                decompressed = None
                try:
                    decompressed = zlib.decompress(data)
                except Exception:
                    try:
                        decompressed = lzma.decompress(data)
                    except Exception as e:
                        result.add_issue(
                            f"Unable to decompress joblib file: {e}",
                            severity=IssueSeverity.ERROR,
                            location=path,
                        )
                        result.finish(success=False)
                        return result
                file_like = io.BytesIO(decompressed)
                sub_result = self.pickle_scanner._scan_pickle_bytes(
                    file_like, len(decompressed)
                )
                result.merge(sub_result)
                result.bytes_scanned = len(decompressed)
        except Exception as e:  # pragma: no cover
            result.add_issue(
                f"Error scanning joblib file: {e}",
                severity=IssueSeverity.ERROR,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result
