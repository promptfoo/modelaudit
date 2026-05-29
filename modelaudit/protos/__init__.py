"""
Vendored TensorFlow protobuf stubs.

These are generated from TensorFlow's .proto files to enable SavedModel parsing
without requiring the full TensorFlow package (and avoiding Keras CVE exposure).

Strategy:
1. Use native TensorFlow protos only from trusted installation roots.
2. Otherwise, prefer vendored protobuf stubs for scanner-owned parsing.
3. Never probe ambient `tensorflow` from CWD/PYTHONPATH shadow roots.

This avoids executing attacker-shadowed TensorFlow packages from CWD/PYTHONPATH
during static model scanning.
"""

from __future__ import annotations

import importlib.machinery
import logging
import site
import sys
import sysconfig
import types
from contextlib import suppress
from pathlib import Path

logger = logging.getLogger(__name__)

_PROTOS_DIR = str(Path(__file__).parent)
_PROTOS_PATH = Path(_PROTOS_DIR).resolve()
_PROTOS_AVAILABLE: bool | None = None
_USING_VENDORED = False


def _path_is_relative_to(path: Path, root: Path) -> bool:
    with suppress(ValueError):
        path.relative_to(root)
        return True
    return False


def _trusted_tensorflow_roots() -> list[Path]:
    roots: list[Path] = []
    seen: set[Path] = set()

    for key in ("purelib", "platlib"):
        path_value = sysconfig.get_paths().get(key)
        if path_value:
            root = Path(path_value).resolve()
            if root not in seen:
                roots.append(root)
                seen.add(root)

    with suppress(Exception):
        for site_path in site.getsitepackages():
            root = Path(site_path).resolve()
            if root not in seen:
                roots.append(root)
                seen.add(root)
    with suppress(Exception):
        user_site = site.getusersitepackages()
        root = Path(user_site).resolve()
        if root not in seen:
            roots.append(root)
            seen.add(root)

    return roots


def _module_is_under_root(module: types.ModuleType, root: Path) -> bool:
    module_file = getattr(module, "__file__", None)
    if module_file and _path_is_relative_to(Path(module_file).resolve(), root):
        return True

    module_paths = getattr(module, "__path__", ())
    return any(_path_is_relative_to(Path(module_path).resolve(), root) for module_path in module_paths)


def _remove_tensorflow_modules_outside(root: Path) -> None:
    for module_name, module in list(sys.modules.items()):
        if module_name != "tensorflow" and not module_name.startswith("tensorflow."):
            continue
        if not isinstance(module, types.ModuleType) or not _module_is_under_root(module, root):
            sys.modules.pop(module_name, None)


def _trusted_tensorflow_root() -> Path | None:
    for root in _trusted_tensorflow_roots():
        spec = importlib.machinery.PathFinder.find_spec("tensorflow", [str(root)])
        if spec is None or spec.origin is None:
            continue
        if _path_is_relative_to(Path(spec.origin).resolve(), root):
            return root
    return None


def _ensure_vendored_protos_first() -> None:
    """Place vendored TensorFlow protobuf stubs before ambient import roots."""
    with suppress(ValueError):
        sys.path.remove(_PROTOS_DIR)
    sys.path.insert(0, _PROTOS_DIR)


def _setup_vendored_protos() -> bool:
    """Set up vendored protos by adding them ahead of ambient sys.path roots."""
    global _USING_VENDORED

    _remove_tensorflow_modules_outside(_PROTOS_PATH)
    _ensure_vendored_protos_first()
    _USING_VENDORED = True
    logger.debug("Using vendored TensorFlow protos")

    try:
        from tensorflow.core.framework.graph_pb2 import GraphDef
        from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

        return True
    except ImportError as e:
        logger.debug("Vendored TensorFlow protos failed to load: %s", e)
        return False


def _setup_trusted_tensorflow_protos() -> bool:
    """Import TensorFlow protobuf stubs only from trusted installation roots."""
    global _USING_VENDORED

    trusted_root = _trusted_tensorflow_root()
    if trusted_root is None:
        return False

    original_sys_path = list(sys.path)
    _remove_tensorflow_modules_outside(trusted_root)
    try:
        sys.path[:] = [str(trusted_root), *[entry for entry in sys.path if entry != str(trusted_root)]]
        from tensorflow.core.framework.graph_pb2 import GraphDef
        from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

        _USING_VENDORED = False
        logger.debug("Using TensorFlow protos from trusted installation root %s", trusted_root)
        return True
    except ImportError as e:
        logger.debug("Trusted TensorFlow protobuf import failed: %s", e)
        return False
    finally:
        sys.path[:] = original_sys_path


def _check_vendored_protos() -> bool:
    """Check if safe TensorFlow protobuf stubs are available."""
    global _PROTOS_AVAILABLE

    if _PROTOS_AVAILABLE is not None:
        return _PROTOS_AVAILABLE

    _PROTOS_AVAILABLE = _setup_trusted_tensorflow_protos() or _setup_vendored_protos()
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


def get_saved_model_pb2() -> types.ModuleType:
    """Get the saved_model_pb2 module (from TensorFlow or vendored protos)."""
    if not _check_vendored_protos():
        raise ImportError("TensorFlow protos not available (neither TensorFlow nor vendored)")

    from tensorflow.core.protobuf import saved_model_pb2

    return saved_model_pb2


def get_graph_pb2() -> types.ModuleType:
    """Get the graph_pb2 module (from TensorFlow or vendored protos)."""
    if not _check_vendored_protos():
        raise ImportError("TensorFlow protos not available (neither TensorFlow nor vendored)")

    from tensorflow.core.framework import graph_pb2

    return graph_pb2


def is_using_vendored_protos() -> bool:
    """Return True when vendored protos are active."""
    _check_vendored_protos()  # Ensure initialization
    return _USING_VENDORED


# Initialize on import so subsequent `from tensorflow.core...` imports resolve
# to scanner-owned vendored stubs before ambient packages.
_check_vendored_protos()
