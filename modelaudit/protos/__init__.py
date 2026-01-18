"""
Vendored TensorFlow protobuf stubs.

These are generated from TensorFlow's .proto files to enable SavedModel parsing
without requiring the full TensorFlow package (and avoiding Keras CVE exposure).

Strategy:
1. If TensorFlow is installed, use its protos (no sys.path manipulation needed)
2. If TensorFlow is NOT installed, fall back to vendored protos via sys.path

This avoids conflicts when TensorFlow is present.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

_PROTOS_DIR = str(Path(__file__).parent)
_PROTOS_AVAILABLE: bool | None = None
_USING_VENDORED = False


def _check_tensorflow_protos() -> bool:
    """Check if TensorFlow's protos are available (TensorFlow is installed)."""
    try:
        # Try importing from TensorFlow directly (without sys.path manipulation)
        from tensorflow.core.framework.graph_pb2 import GraphDef
        from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

        return True
    except ImportError:
        return False


def _setup_vendored_protos() -> bool:
    """Set up vendored protos by adding to sys.path. Only call if TensorFlow not installed."""
    global _USING_VENDORED

    if _PROTOS_DIR not in sys.path:
        # Add vendored protos to sys.path (only when TensorFlow isn't installed)
        sys.path.insert(0, _PROTOS_DIR)
        _USING_VENDORED = True
        logger.debug("Using vendored TensorFlow protos (TensorFlow not installed)")

    try:
        from tensorflow.core.framework.graph_pb2 import GraphDef
        from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

        return True
    except ImportError as e:
        logger.debug(f"Vendored TensorFlow protos failed to load: {e}")
        return False


def _check_vendored_protos() -> bool:
    """Check if protos are available (either from TensorFlow or vendored)."""
    global _PROTOS_AVAILABLE

    if _PROTOS_AVAILABLE is not None:
        return _PROTOS_AVAILABLE

    # Strategy: prefer TensorFlow's protos, fall back to vendored
    if _check_tensorflow_protos():
        _PROTOS_AVAILABLE = True
        logger.debug("Using TensorFlow's native protos")
    else:
        _PROTOS_AVAILABLE = _setup_vendored_protos()

    return _PROTOS_AVAILABLE


def get_saved_model_class() -> type:
    """Get the SavedModel protobuf class (from TensorFlow or vendored protos)."""
    if not _check_vendored_protos():
        raise ImportError("TensorFlow protos not available (neither TensorFlow nor vendored)")

    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

    return SavedModel


def get_graph_def_class() -> type:
    """Get the GraphDef protobuf class (from TensorFlow or vendored protos)."""
    if not _check_vendored_protos():
        raise ImportError("TensorFlow protos not available (neither TensorFlow nor vendored)")

    from tensorflow.core.framework.graph_pb2 import GraphDef

    return GraphDef


def get_saved_model_pb2() -> object:
    """Get the saved_model_pb2 module (from TensorFlow or vendored protos)."""
    if not _check_vendored_protos():
        raise ImportError("TensorFlow protos not available (neither TensorFlow nor vendored)")

    from tensorflow.core.protobuf import saved_model_pb2

    return saved_model_pb2


def get_graph_pb2() -> object:
    """Get the graph_pb2 module (from TensorFlow or vendored protos)."""
    if not _check_vendored_protos():
        raise ImportError("TensorFlow protos not available (neither TensorFlow nor vendored)")

    from tensorflow.core.framework import graph_pb2

    return graph_pb2


def is_using_vendored_protos() -> bool:
    """Return True if using vendored protos, False if using TensorFlow's native protos."""
    _check_vendored_protos()  # Ensure initialization
    return _USING_VENDORED


# Initialize on import - sets up sys.path if TensorFlow not installed
# This ensures that subsequent `from tensorflow.core...` imports work
_check_vendored_protos()
