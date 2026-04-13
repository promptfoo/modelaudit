from __future__ import annotations

from typing import Any

import pytest

from modelaudit_picklescan import ScanOptions
from modelaudit_picklescan.options import MAX_TIMEOUT_S


def test_scan_options_defaults_are_safe_and_finite() -> None:
    options = ScanOptions()

    assert options.timeout_s > 0
    assert options.max_opcodes > 0
    assert options.post_budget_scan_bytes >= 0
    assert options.max_known_stream_read_bytes > 0


def test_scan_options_clamps_excessive_timeout() -> None:
    options = ScanOptions(timeout_s=1.0e18)

    assert options.timeout_s == MAX_TIMEOUT_S


@pytest.mark.parametrize(
    ("kwargs", "expected_error"),
    [
        ({"timeout_s": 0}, "timeout_s must be greater than 0"),
        ({"timeout_s": True}, "timeout_s must be greater than 0"),
        ({"timeout_s": float("inf")}, "timeout_s must be greater than 0"),
        ({"timeout_s": float("-inf")}, "timeout_s must be greater than 0"),
        ({"timeout_s": float("nan")}, "timeout_s must be greater than 0"),
        ({"max_opcodes": 0}, "max_opcodes must be greater than 0"),
        ({"max_opcodes": False}, "max_opcodes must be greater than 0"),
        ({"post_budget_scan_bytes": -1}, "post_budget_scan_bytes must be greater than or equal to 0"),
        ({"post_budget_scan_bytes": True}, "post_budget_scan_bytes must be greater than or equal to 0"),
        ({"post_budget_scan_bytes": 1.5}, "post_budget_scan_bytes must be greater than or equal to 0"),
        ({"post_budget_scan_bytes": "1024"}, "post_budget_scan_bytes must be greater than or equal to 0"),
        ({"max_known_stream_read_bytes": 0}, "max_known_stream_read_bytes must be greater than 0"),
        ({"max_known_stream_read_bytes": True}, "max_known_stream_read_bytes must be greater than 0"),
        ({"max_string_literal_scan_chars": -1}, "max_string_literal_scan_chars must be greater than or equal to 0"),
        ({"max_string_literal_scan_chars": True}, "max_string_literal_scan_chars must be greater than or equal to 0"),
        ({"max_nested_pickle_bytes": -1}, "max_nested_pickle_bytes must be greater than or equal to 0"),
        ({"max_nested_pickle_bytes": False}, "max_nested_pickle_bytes must be greater than or equal to 0"),
        ({"max_nested_depth": -1}, "max_nested_depth must be greater than or equal to 0"),
        ({"max_nested_depth": 1.5}, "max_nested_depth must be greater than or equal to 0"),
    ],
)
def test_scan_options_reject_invalid_resource_limits(
    kwargs: dict[str, Any],
    expected_error: str,
) -> None:
    with pytest.raises(ValueError, match=expected_error):
        ScanOptions(**kwargs)
