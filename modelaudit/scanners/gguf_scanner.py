import os
import struct

from .base import BaseScanner, IssueSeverity, ScanResult


class GgufScanner(BaseScanner):
    """Scanner for GGUF/GGML model files"""

    name = "gguf"
    description = "Validates GGUF/GGML model file headers and metadata"
    supported_extensions = [".gguf", ".ggml"]

    TYPE_SIZES = {
        0: 1,  # UINT8
        1: 1,  # INT8
        2: 2,  # UINT16
        3: 2,  # INT16
        4: 4,  # UINT32
        5: 4,  # INT32
        6: 4,  # FLOAT32
        7: 1,  # BOOL
        10: 8,  # UINT64
        11: 8,  # INT64
        12: 8,  # FLOAT64
    }

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False

        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False

        try:
            with open(path, "rb") as f:
                magic = f.read(4)
            return magic in (b"GGUF", b"GGML")
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        result.bytes_scanned = file_size

        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic == b"GGUF":
                    self._scan_gguf(f, file_size, result)
                else:
                    self._scan_ggml(f, file_size, magic, result)
        except Exception as e:
            result.add_issue(
                f"Error scanning GGUF file: {str(e)}",
                severity=IssueSeverity.ERROR,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(
            success=not any(i.severity == IssueSeverity.ERROR for i in result.issues)
        )
        return result

    def _read_string(self, f, file_size: int, offset: int) -> tuple[str, int]:
        if offset + 8 > file_size:
            raise ValueError("Unexpected end of file while reading string length")
        length = struct.unpack("<Q", f.read(8))[0]
        offset += 8
        if length > file_size - offset:
            raise ValueError("String length exceeds file size")
        data = f.read(length)
        offset += length
        return data.decode("utf-8", "ignore"), offset

    def _scan_gguf(self, f, file_size: int, result: ScanResult) -> None:
        version = struct.unpack("<I", f.read(4))[0]
        n_tensors = struct.unpack("<q", f.read(8))[0]
        n_kv = struct.unpack("<q", f.read(8))[0]

        result.metadata.update(
            {
                "format": "gguf",
                "version": version,
                "n_tensors": n_tensors,
                "n_kv": n_kv,
            }
        )

        if n_kv < 0 or n_kv > 1_000_000:
            result.add_issue(
                f"GGUF header appears invalid (declared {n_kv} entries)",
                severity=IssueSeverity.ERROR,
            )
            return

        offset = 24
        if offset >= file_size:
            result.add_issue(
                "File too small to contain GGUF metadata", severity=IssueSeverity.ERROR
            )
            return

        try:
            for _ in range(min(n_kv, 20)):
                key, offset = self._read_string(f, file_size, offset)
                if any(x in key for x in ("../", "..\\", "/", "\\")):
                    result.add_issue(
                        f"Suspicious metadata key: {key}", severity=IssueSeverity.INFO
                    )
                if offset + 4 > file_size:
                    raise ValueError("Unexpected end of file reading value type")
                val_type = struct.unpack("<i", f.read(4))[0]
                offset += 4
                if val_type == 8:  # string
                    value, offset = self._read_string(f, file_size, offset)
                    if any(p in value for p in ("/", "\\", ";", "&&")):
                        result.add_issue(
                            f"Suspicious metadata value: {value}",
                            severity=IssueSeverity.INFO,
                        )
                elif val_type == 9:  # array
                    if offset + 12 > file_size:
                        raise ValueError("Unexpected end of file reading array header")
                    arr_type = struct.unpack("<i", f.read(4))[0]
                    arr_len = struct.unpack("<Q", f.read(8))[0]
                    offset += 12
                    item_size = self.TYPE_SIZES.get(arr_type, 0)
                    total = item_size * arr_len
                    if total > file_size - offset:
                        raise ValueError("Array size exceeds file size")
                    f.seek(total, os.SEEK_CUR)
                    offset += total
                else:
                    size = self.TYPE_SIZES.get(val_type)
                    if size is None or offset + size > file_size:
                        raise ValueError("Invalid value type or size")
                    f.seek(size, os.SEEK_CUR)
                    offset += size
        except Exception as e:
            result.add_issue(
                f"GGUF metadata parse error: {e}", severity=IssueSeverity.ERROR
            )

    def _scan_ggml(self, f, file_size: int, magic: bytes, result: ScanResult) -> None:
        result.metadata["format"] = "ggml"
        result.metadata["magic"] = magic.decode("ascii", "ignore")
        if file_size < 32:
            result.add_issue(
                "File too small to be valid GGML", severity=IssueSeverity.ERROR
            )
            return
        # Basic heuristic: read an int32 version and a count
        version_bytes = f.read(4)
        if len(version_bytes) < 4:
            result.add_issue("Truncated GGML header", severity=IssueSeverity.ERROR)
            return
        version = struct.unpack("<I", version_bytes)[0]
        result.metadata["version"] = version
        if version > 1000:
            result.add_issue(
                f"Suspicious GGML version: {version}", severity=IssueSeverity.WARNING
            )
