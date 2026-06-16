"""
Test helpers and utilities for ModelAudit tests.

This module provides common fixtures and utilities to reduce test duplication
and improve test maintainability.
"""

from tests.helpers.file_creators import (
    create_equal_length_onnx_payloads,
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

__all__ = [
    "create_equal_length_onnx_payloads",
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
