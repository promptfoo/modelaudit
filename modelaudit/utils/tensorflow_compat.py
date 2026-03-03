"""
TensorFlow compatibility utilities for parsing TensorFlow models without the full TensorFlow package.

This module provides:
1. Protobuf parsing for SavedModel and GraphDef without TensorFlow
2. tensor_proto_to_ndarray() - replacement for tf.make_ndarray()
3. Checkpoint reading utilities (requires full TensorFlow)

The goal is to eliminate the TensorFlow/Keras dependency for basic model scanning,
avoiding exposure to Keras CVEs while maintaining full scanning functionality.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


# TensorFlow DataType enum values (from types.proto)
# These match tensorflow.core.framework.types_pb2.DataType
class DataType:
    """TensorFlow DataType enum constants."""

    DT_INVALID = 0
    DT_FLOAT = 1
    DT_DOUBLE = 2
    DT_INT32 = 3
    DT_UINT8 = 4
    DT_INT16 = 5
    DT_INT8 = 6
    DT_STRING = 7
    DT_COMPLEX64 = 8
    DT_INT64 = 9
    DT_BOOL = 10
    DT_QINT8 = 11
    DT_QUINT8 = 12
    DT_QINT32 = 13
    DT_BFLOAT16 = 14
    DT_QINT16 = 15
    DT_QUINT16 = 16
    DT_UINT16 = 17
    DT_COMPLEX128 = 18
    DT_HALF = 19
    DT_RESOURCE = 20
    DT_VARIANT = 21
    DT_UINT32 = 22
    DT_UINT64 = 23
    DT_FLOAT8_E5M2 = 24
    DT_FLOAT8_E4M3FN = 25


# Mapping from TensorFlow DataType to numpy dtype
DTYPE_MAP: dict[int, np.dtype[Any]] = {
    DataType.DT_FLOAT: np.dtype(np.float32),
    DataType.DT_DOUBLE: np.dtype(np.float64),
    DataType.DT_INT32: np.dtype(np.int32),
    DataType.DT_UINT8: np.dtype(np.uint8),
    DataType.DT_INT16: np.dtype(np.int16),
    DataType.DT_INT8: np.dtype(np.int8),
    DataType.DT_STRING: np.dtype(object),
    DataType.DT_COMPLEX64: np.dtype(np.complex64),
    DataType.DT_INT64: np.dtype(np.int64),
    DataType.DT_BOOL: np.dtype(np.bool_),
    DataType.DT_QINT8: np.dtype(np.int8),
    DataType.DT_QUINT8: np.dtype(np.uint8),
    DataType.DT_QINT32: np.dtype(np.int32),
    DataType.DT_BFLOAT16: np.dtype(np.uint16),  # bfloat16 stored as uint16
    DataType.DT_QINT16: np.dtype(np.int16),
    DataType.DT_QUINT16: np.dtype(np.uint16),
    DataType.DT_UINT16: np.dtype(np.uint16),
    DataType.DT_COMPLEX128: np.dtype(np.complex128),
    DataType.DT_HALF: np.dtype(np.float16),
    DataType.DT_UINT32: np.dtype(np.uint32),
    DataType.DT_UINT64: np.dtype(np.uint64),
    DataType.DT_FLOAT8_E5M2: np.dtype(np.uint8),  # float8 stored as uint8
    DataType.DT_FLOAT8_E4M3FN: np.dtype(np.uint8),  # float8 stored as uint8
}


def tensor_proto_to_ndarray(tensor_proto: Any) -> np.ndarray[Any, Any]:
    """
    Convert a TensorProto to a numpy ndarray.

    This is a drop-in replacement for tf.make_ndarray() that doesn't require TensorFlow.

    The algorithm follows TensorFlow's implementation:
    1. Extract shape and dtype from the proto
    2. Fast path: if tensor_content exists, use frombuffer
    3. Slow path: extract from typed fields (float_val, int_val, etc.)
    4. Handle padding for scalar broadcasting
    5. Reshape to final shape

    Args:
        tensor_proto: A TensorProto message (from tensorflow.core.framework.tensor_pb2)

    Returns:
        numpy ndarray containing the tensor data

    Raises:
        ValueError: If dtype is unsupported or data is malformed
    """
    # Extract shape
    if hasattr(tensor_proto, "tensor_shape") and tensor_proto.tensor_shape.dim:
        shape = tuple(d.size for d in tensor_proto.tensor_shape.dim)
    else:
        shape = ()

    num_elements = int(np.prod(shape)) if shape else 1

    # Get dtype
    dtype_enum = tensor_proto.dtype
    if dtype_enum not in DTYPE_MAP:
        raise ValueError(f"Unsupported TensorFlow dtype: {dtype_enum}")

    dtype = DTYPE_MAP[dtype_enum]

    # Fast path: binary content (most common for large tensors)
    if tensor_proto.tensor_content:
        # Handle special dtypes that need reinterpretation
        if dtype_enum == DataType.DT_BFLOAT16:
            # bfloat16 is stored as bytes, interpret as uint16 then view as bfloat16
            arr = np.frombuffer(tensor_proto.tensor_content, dtype=np.uint16).copy()
            # Note: numpy doesn't natively support bfloat16, keep as uint16
            # Users can convert with ml_dtypes if needed
        elif dtype_enum in (DataType.DT_FLOAT8_E5M2, DataType.DT_FLOAT8_E4M3FN):
            # float8 types stored as bytes
            arr = np.frombuffer(tensor_proto.tensor_content, dtype=np.uint8).copy()
        else:
            arr = np.frombuffer(tensor_proto.tensor_content, dtype=dtype).copy()

        result: np.ndarray[Any, Any] = arr.reshape(shape) if shape else arr
        return result

    # Slow path: extract from typed fields
    values: np.ndarray[Any, Any]

    if dtype_enum == DataType.DT_STRING:
        # String tensors use string_val field
        values = np.array(list(tensor_proto.string_val), dtype=object)

    elif dtype_enum == DataType.DT_FLOAT:
        values = np.array(tensor_proto.float_val, dtype=np.float32)

    elif dtype_enum == DataType.DT_DOUBLE:
        values = np.array(tensor_proto.double_val, dtype=np.float64)

    elif dtype_enum in (DataType.DT_INT32, DataType.DT_INT16, DataType.DT_INT8):
        values = np.array(tensor_proto.int_val, dtype=dtype)

    elif dtype_enum == DataType.DT_INT64:
        values = np.array(tensor_proto.int64_val, dtype=np.int64)

    elif dtype_enum in (DataType.DT_UINT8, DataType.DT_QUINT8):
        values = np.array(tensor_proto.int_val, dtype=np.uint8)

    elif dtype_enum in (DataType.DT_UINT16, DataType.DT_QUINT16):
        values = np.array(tensor_proto.int_val, dtype=np.uint16)

    elif dtype_enum == DataType.DT_UINT32:
        values = np.array(tensor_proto.uint32_val, dtype=np.uint32)

    elif dtype_enum == DataType.DT_UINT64:
        values = np.array(tensor_proto.uint64_val, dtype=np.uint64)

    elif dtype_enum == DataType.DT_BOOL:
        values = np.array(tensor_proto.bool_val, dtype=np.bool_)

    elif dtype_enum == DataType.DT_COMPLEX64:
        # Complex stored as pairs of floats
        float_vals = np.array(tensor_proto.scomplex_val, dtype=np.float32)
        values = float_vals[0::2] + 1j * float_vals[1::2]
        values = values.astype(np.complex64)

    elif dtype_enum == DataType.DT_COMPLEX128:
        # Complex stored as pairs of doubles
        double_vals = np.array(tensor_proto.dcomplex_val, dtype=np.float64)
        values = double_vals[0::2] + 1j * double_vals[1::2]
        values = values.astype(np.complex128)

    elif dtype_enum == DataType.DT_HALF:
        # Half precision stored in half_val as uint16
        half_vals = np.array(tensor_proto.half_val, dtype=np.uint16)
        values = half_vals.view(np.float16)

    elif dtype_enum == DataType.DT_BFLOAT16:
        # bfloat16 stored in half_val as uint16
        values = np.array(tensor_proto.half_val, dtype=np.uint16)

    elif dtype_enum in (DataType.DT_FLOAT8_E5M2, DataType.DT_FLOAT8_E4M3FN):
        # float8 stored in float8_val as uint8
        values = np.array(tensor_proto.float8_val, dtype=np.uint8)

    else:
        raise ValueError(f"Unsupported TensorFlow dtype for typed field extraction: {dtype_enum}")

    # Handle scalar broadcasting (TensorFlow pads with last value)
    if values.size > 0 and values.size < num_elements:
        values = np.pad(values, (0, num_elements - values.size), mode="edge")

    return values.reshape(shape) if shape else values


def get_protobuf_classes() -> tuple[Any, Any]:
    """
    Get SavedModel and GraphDef protobuf classes.

    Uses modelaudit.protos to initialize proto loading (TF-native first, vendored fallback),
    then imports via tensorflow.core.* which resolves to whichever source is available.

    Returns:
        Tuple of (SavedModel, GraphDef) classes

    Raises:
        ImportError: If neither vendored protos nor TensorFlow are available
    """
    import modelaudit.protos

    if not modelaudit.protos._check_vendored_protos():
        raise ImportError(
            "TensorFlow protobuf stubs not available. "
            "Vendored protos may be missing or corrupted. "
            "Reinstall modelaudit or install TensorFlow with: pip install modelaudit[tensorflow]"
        )

    from tensorflow.core.framework.graph_pb2 import GraphDef
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

    return SavedModel, GraphDef


# Checkpoint reading requires full TensorFlow (no lightweight alternative)
def list_checkpoint_variables(checkpoint_path: str) -> list[tuple[str, list[int]]]:
    """
    List variables in a TensorFlow checkpoint.

    This requires full TensorFlow - there's no lightweight alternative for checkpoint reading.

    Args:
        checkpoint_path: Path to checkpoint prefix (without .index/.data-* suffix)

    Returns:
        List of (variable_name, shape) tuples

    Raises:
        ImportError: If TensorFlow is not installed
    """
    try:
        import tensorflow as tf
    except ImportError as e:
        raise ImportError(
            "Checkpoint reading requires TensorFlow. Install with: pip install modelaudit[tensorflow]"
        ) from e

    return [(name, list(shape)) for name, shape in tf.train.list_variables(checkpoint_path)]


def load_checkpoint_variable(checkpoint_path: str, variable_name: str) -> np.ndarray[Any, Any]:
    """
    Load a variable from a TensorFlow checkpoint.

    This requires full TensorFlow - there's no lightweight alternative for checkpoint reading.

    Args:
        checkpoint_path: Path to checkpoint prefix (without .index/.data-* suffix)
        variable_name: Name of variable to load

    Returns:
        numpy array containing the variable data

    Raises:
        ImportError: If TensorFlow is not installed
    """
    try:
        import tensorflow as tf
    except ImportError as e:
        raise ImportError(
            "Checkpoint reading requires TensorFlow. Install with: pip install modelaudit[tensorflow]"
        ) from e

    return np.array(tf.train.load_variable(checkpoint_path, variable_name))
