"""Rust extension availability helpers for the standalone pickle scanner."""

from __future__ import annotations

import importlib.util

RUST_EXTENSION_MODULE = "modelaudit_picklescan._rust"


def rust_engine_available() -> bool:
    """Return whether the native Rust extension is importable."""
    return importlib.util.find_spec(RUST_EXTENSION_MODULE) is not None
