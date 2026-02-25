"""Automatic default configuration utilities.

This module re-exports helpers from ``modelaudit.utils.helpers.auto_defaults``
for compatibility with existing imports.
"""

from .helpers.auto_defaults import (
    apply_auto_overrides,
    detect_ci_environment,
    detect_file_size,
    detect_input_type,
    detect_tty_capabilities,
    generate_auto_defaults,
    parse_size_string,
)

__all__ = [
    "apply_auto_overrides",
    "detect_ci_environment",
    "detect_file_size",
    "detect_input_type",
    "detect_tty_capabilities",
    "generate_auto_defaults",
    "parse_size_string",
]
