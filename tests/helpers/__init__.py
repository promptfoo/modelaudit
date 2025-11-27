"""
Test helpers and utilities for ModelAudit tests.

This module provides common fixtures and utilities to reduce test duplication
and improve test maintainability.
"""

from tests.helpers.file_creators import (
    create_malicious_pickle,
    create_mock_gguf,
    create_mock_h5,
    create_mock_manifest,
    create_mock_pytorch_zip,
    create_mock_safetensors,
    create_safe_pickle,
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
    "create_malicious_pickle",
    "create_mock_gguf",
    "create_mock_h5",
    "create_mock_manifest",
    "create_mock_pytorch_zip",
    "create_mock_safetensors",
    "create_safe_pickle",
    "requires_dill",
    "requires_h5py",
    "requires_joblib",
    "requires_msgpack",
    "requires_onnx",
    "requires_pytorch",
    "requires_safetensors",
    "requires_tensorflow",
    "requires_xgboost",
]
