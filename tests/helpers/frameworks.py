"""
Framework-aware decorators for tests.

These decorators provide a cleaner way to skip tests when optional
frameworks are not installed.

Usage:
    from tests.helpers import requires_pytorch

    @requires_pytorch
    def test_pytorch_feature():
        import torch
        ...
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

import pytest


def _make_requires_decorator(
    module_name: str, package_name: str | None = None
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Create a decorator that skips if a module is not installed."""
    display_name = package_name or module_name

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            pytest.importorskip(module_name)
            return func(*args, **kwargs)

        return wrapper

    decorator.__doc__ = f"Skip test if {display_name} is not installed."
    return decorator


# Framework decorators
requires_tensorflow = _make_requires_decorator("tensorflow", "TensorFlow")
requires_pytorch = _make_requires_decorator("torch", "PyTorch")
requires_onnx = _make_requires_decorator("onnx", "ONNX")
requires_h5py = _make_requires_decorator("h5py")
requires_msgpack = _make_requires_decorator("msgpack")
requires_xgboost = _make_requires_decorator("xgboost", "XGBoost")
requires_safetensors = _make_requires_decorator("safetensors")
requires_joblib = _make_requires_decorator("joblib")
requires_dill = _make_requires_decorator("dill")


def skip_if_slow(reason: str = "Test is slow") -> pytest.MarkDecorator:
    """Skip test in fast mode (when running with -m 'not slow')."""
    return pytest.mark.slow


def skip_in_ci(
    reason: str = "Test not suitable for CI",
) -> Callable[[Callable[..., Any]], Callable[..., Any]] | pytest.MarkDecorator:
    """Skip test in CI environment."""
    import os

    if os.environ.get("CI"):
        return pytest.mark.skip(reason=reason)
    return lambda f: f
