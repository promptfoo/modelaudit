"""Retry call compatibility after retiring diagnostic masking."""

from collections.abc import Callable
from unittest.mock import Mock

import pytest

from modelaudit.utils.helpers.retry import RetryError, exponential_backoff, retry_cloud_operation, retry_with_backoff


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


@pytest.mark.parametrize("control", ["\r", "\n", "\t", "\r\n"])
def test_retry_logs_one_line_and_retains_raw_exception(control: str, caplog: pytest.LogCaptureFixture) -> None:
    error = OSError(f"token=synthetic-secret{control}FORGED")
    operation = Mock(side_effect=error)
    with caplog.at_level("DEBUG", logger="modelaudit.utils.helpers.retry"), pytest.raises(RetryError) as raised:
        exponential_backoff(operation, max_retries=1, base_delay=0, jitter=False)()
    assert operation.call_count == 2
    assert raised.value.last_error is error
    messages = [record.message for record in caplog.records if record.name == "modelaudit.utils.helpers.retry"]
    assert len(messages) == 1
    assert messages[0].startswith("Attempt 1 failed for ") and len(messages[0].splitlines()) == 1
    assert control + "FORGED" not in messages[0]
    assert "synthetic-secret" in messages[0]
