"""Retry call compatibility after retiring diagnostic masking."""

from collections.abc import Callable

import pytest

from modelaudit.utils.helpers.retry import exponential_backoff, retry_cloud_operation, retry_with_backoff


@pytest.mark.parametrize(
    "operation",
    [
        lambda: exponential_backoff(lambda: 17, max_retries=0, sanitize_error=str)(),
        lambda: retry_with_backoff(max_retries=0, sanitize_error=str)(lambda: 17)(),
        lambda: retry_cloud_operation(lambda: 17, max_retries=0, sanitize_error=str),
    ],
)
def test_retry_accepts_retired_sanitizer_keyword(operation: Callable[[], int]) -> None:
    assert operation() == 17
