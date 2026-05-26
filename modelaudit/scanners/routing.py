"""Shared trusted-content routing policy for scanner selection."""

from __future__ import annotations

import os
from typing import Any

from ..scanner_registry_metadata import get_scanner_registry_metadata
from ..utils.file.detection import (
    PROTOBUF_MODEL_CANDIDATE_FORMAT,
    is_executorch_archive,
    is_keras_zip_archive,
    is_pytorch_zip_archive,
    is_skops_archive,
    is_torchserve_mar_archive,
)


def _build_header_format_to_scanner_id() -> dict[str, str]:
    metadata = get_scanner_registry_metadata()
    header_format_to_scanner_id = {scanner_id: scanner_id for scanner_id in metadata}
    for scanner_id, scanner_info in metadata.items():
        for header_format in scanner_info.get("header_formats", ()):
            header_format_to_scanner_id[str(header_format)] = scanner_id
    return header_format_to_scanner_id


HEADER_FORMAT_TO_SCANNER_ID: dict[str, str] = _build_header_format_to_scanner_id()
COMPRESSED_HEADER_FORMATS: frozenset[str] = frozenset(
    header_format for header_format, scanner_id in HEADER_FORMAT_TO_SCANNER_ID.items() if scanner_id == "compressed"
)
R_SERIALIZED_EXTENSIONS: frozenset[str] = frozenset({".rds", ".rda", ".rdata"})


def select_routed_scanner_id(path: str, header_format: str, *, extension: str | None = None) -> str | None:
    """Select the scanner owned by a trusted bounded content route."""
    ext = extension if extension is not None else os.path.splitext(path)[1].lower()

    if header_format == PROTOBUF_MODEL_CANDIDATE_FORMAT:
        return "protobuf_model_candidate"

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
        return "zip"

    if ext == ".joblib" and header_format in COMPRESSED_HEADER_FORMATS | {"pickle"}:
        return "joblib"

    if ext in R_SERIALIZED_EXTENSIONS and header_format in COMPRESSED_HEADER_FORMATS | {"r_serialized"}:
        return "r_serialized"

    if header_format == "tar" and ext == ".nemo":
        return "nemo"

    return HEADER_FORMAT_TO_SCANNER_ID.get(header_format)


def is_direct_header_route(scanner_id: str, header_format: str) -> bool:
    """Return whether a strict detected format directly identifies a scanner."""
    if header_format == PROTOBUF_MODEL_CANDIDATE_FORMAT:
        return scanner_id == "protobuf_model_candidate"
    return header_format != "unknown" and HEADER_FORMAT_TO_SCANNER_ID.get(header_format) == scanner_id


def routed_scanner_can_handle(scanner_class: type[Any], scanner_id: str, header_format: str, path: str) -> bool:
    """Accept content-routed scanners after their own gate or direct strict detection."""
    if scanner_class.can_handle(path):
        return True

    return os.path.exists(path) and is_direct_header_route(scanner_id, header_format)
