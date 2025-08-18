from __future__ import annotations

from typing import Any

from modelaudit.scanners.base import ScanResult


def asset_from_scan_result(path: str, scan_result: ScanResult) -> dict[str, Any]:
    """Build an asset entry from a ScanResult."""
    entry: dict[str, Any] = {
        "path": path,
        "type": scan_result.scanner_name,
    }

    meta = scan_result.metadata
    if "file_size" in meta:
        entry["size"] = meta["file_size"]
    if "tensors" in meta:
        entry["tensors"] = meta["tensors"]
    if "keys" in meta:
        entry["keys"] = meta["keys"]
    if "contents" in meta:
        entry["contents"] = meta["contents"]
    return entry
