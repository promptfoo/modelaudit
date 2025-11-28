from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
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
        # Handle tensor data - convert dictionaries to string names for AssetModel compatibility
        tensors = meta["tensors"]
        if tensors and isinstance(tensors, list):
            # Check if this is a list of dictionaries (e.g., from GGUF scanner)
            if all(isinstance(t, dict) and "name" in t for t in tensors):
                entry["tensors"] = [t["name"] for t in tensors]
            else:
                # Assume it's already a list of strings or other compatible format
                entry["tensors"] = tensors
        else:
            entry["tensors"] = tensors
    if "keys" in meta:
        entry["keys"] = meta["keys"]
    if "contents" in meta:
        entry["contents"] = meta["contents"]
    return entry
