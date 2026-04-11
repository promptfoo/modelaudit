"""Nested archive dispatch helpers used by recursive scanners."""

import os
from collections.abc import Callable
from typing import Any

from ..scanner_registry_metadata import get_scanner_registry_metadata
from ..scanner_results import ScanResult
from ..utils.file.detection import (
    detect_file_format,
    is_executorch_archive,
    is_keras_zip_archive,
    is_pytorch_zip_archive,
    is_skops_archive,
    is_torchserve_mar_archive,
)

NESTED_SCAN_CALLBACK_CONFIG_KEY = "_archive_nested_scan_callback"
NestedScanCallback = Callable[[str, dict[str, Any] | None], ScanResult]


def _build_header_format_to_scanner_id() -> dict[str, str]:
    metadata = get_scanner_registry_metadata()
    header_format_to_scanner_id = {scanner_id: scanner_id for scanner_id in metadata}
    for scanner_id, scanner_info in metadata.items():
        for header_format in scanner_info.get("header_formats", ()):
            header_format_to_scanner_id[str(header_format)] = scanner_id
    return header_format_to_scanner_id


_HEADER_FORMAT_TO_SCANNER_ID: dict[str, str] = _build_header_format_to_scanner_id()
_COMPRESSED_HEADER_FORMATS: frozenset[str] = frozenset(
    header_format for header_format, scanner_id in _HEADER_FORMAT_TO_SCANNER_ID.items() if scanner_id == "compressed"
)
_R_SERIALIZED_EXTENSIONS: frozenset[str] = frozenset({".rds", ".rda", ".rdata"})


def _select_nested_scanner_id(path: str) -> str | None:
    """Select a scanner for extracted archive members using trusted file structure first."""
    header_format = detect_file_format(path)
    ext = os.path.splitext(path)[1].lower()

    if header_format == "zip":
        if is_torchserve_mar_archive(path):
            return "torchserve_mar"
        if is_keras_zip_archive(path, allow_config_only=ext == ".keras"):
            return "keras_zip"
        if is_pytorch_zip_archive(path):
            return "pytorch_zip"
        if is_executorch_archive(path):
            return "executorch"
        if is_skops_archive(path):
            return "skops"
        if ext == ".skops":
            return "skops"
        if ext == ".joblib":
            return "joblib"
        if ext == ".bin":
            return "pickle"
        return "zip"

    if ext == ".joblib" and header_format in _COMPRESSED_HEADER_FORMATS | {"pickle"}:
        return "joblib"

    if ext in _R_SERIALIZED_EXTENSIONS and header_format in _COMPRESSED_HEADER_FORMATS | {"r_serialized"}:
        return "r_serialized"

    if header_format == "tar" and ext == ".nemo":
        return "nemo"

    return _HEADER_FORMAT_TO_SCANNER_ID.get(header_format)


def scan_nested_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
    """Scan an extracted archive member without importing `modelaudit.core`."""
    from . import _registry

    scanner_class = None
    scanner_id = _select_nested_scanner_id(path)
    if scanner_id:
        scanner_class = _registry.load_scanner_by_id(scanner_id)
        if scanner_class and not scanner_class.can_handle(path):
            scanner_class = None

    if scanner_class is None:
        scanner_class = _registry.get_scanner_for_path(path)

    if scanner_class is None:
        result = ScanResult(scanner_name="unknown")
        result.finish(success=True)
        return result

    scanner = scanner_class(config=config)
    return scanner.scan_with_cache(path)
