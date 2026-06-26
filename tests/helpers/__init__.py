"""
Test helpers and utilities for ModelAudit tests.

This module provides common fixtures and utilities to reduce test duplication
and improve test maintainability.
"""

from tests.helpers.file_creators import (
    create_malicious_pickle,
    create_mock_coreml,
    create_mock_gguf,
    create_mock_h5,
    create_mock_manifest,
    create_mock_mxnet_symbol,
    create_mock_onnx,
    create_mock_pytorch_zip,
    create_mock_safetensors,
    create_safe_pickle,
    prefix_mock_onnx_with_branching_unknown_groups,
    prefix_mock_onnx_with_unknown_field,
    prefix_mock_onnx_with_unknown_group,
    write_mock_pytorch_zip_metadata,
)
from tests.helpers.frameworks import (
    requires_dill,
    requires_h5py,
    requires_joblib,
    requires_msgpack,
    requires_onnx,
    requires_pytorch,
    requires_safetensors,
    requires_tensorflow,
    requires_xgboost,
)


def is_huggingface_rate_limit_error(error: BaseException) -> bool:
    """Return whether an exception chain records an explicit Hugging Face HTTP 429."""
    pending: list[BaseException] = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        status_code = getattr(getattr(current, "response", None), "status_code", None)
        if status_code == 429 or "429 Too Many Requests" in str(current):
            return True
        for nested in (current.__cause__, current.__context__):
            if nested is not None:
                pending.append(nested)
    return False


__all__ = [
    "create_malicious_pickle",
    "create_mock_coreml",
    "create_mock_gguf",
    "create_mock_h5",
    "create_mock_manifest",
    "create_mock_mxnet_symbol",
    "create_mock_onnx",
    "create_mock_pytorch_zip",
    "create_mock_safetensors",
    "create_safe_pickle",
    "is_huggingface_rate_limit_error",
    "prefix_mock_onnx_with_branching_unknown_groups",
    "prefix_mock_onnx_with_unknown_field",
    "prefix_mock_onnx_with_unknown_group",
    "requires_dill",
    "requires_h5py",
    "requires_joblib",
    "requires_msgpack",
    "requires_onnx",
    "requires_pytorch",
    "requires_safetensors",
    "requires_tensorflow",
    "requires_xgboost",
    "write_mock_pytorch_zip_metadata",
]
