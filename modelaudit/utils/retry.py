"""Retry logic utilities for robust cloud operations."""

import functools
import logging
import random
import time
from typing import Any, Callable, Optional, TypeVar

import click

logger = logging.getLogger(__name__)

T = TypeVar("T")


class RetryError(Exception):
    """Raised when all retry attempts fail."""

    def __init__(self, message: str, last_error: Optional[Exception] = None):
        super().__init__(message)
        self.last_error = last_error


def exponential_backoff(
    func: Callable[..., T],
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retry_on: Optional[tuple[type[Exception], ...]] = None,
    verbose: bool = False,
) -> Callable[..., T]:
    """
    Decorator for exponential backoff retry logic.

    Args:
        func: Function to retry
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay between retries in seconds
        max_delay: Maximum delay between retries in seconds
        exponential_base: Base for exponential backoff calculation
        jitter: Add random jitter to delays to prevent thundering herd
        retry_on: Tuple of exception types to retry on (None = all exceptions)
        verbose: Show retry messages to user

    Returns:
        Wrapped function with retry logic
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> T:
        last_exception = None

        for attempt in range(max_retries + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Check if we should retry this exception
                if retry_on and not isinstance(e, retry_on):
                    raise

                last_exception = e

                # Don't retry after last attempt
                if attempt == max_retries:
                    break

                # Calculate delay with exponential backoff
                delay = min(base_delay * (exponential_base**attempt), max_delay)

                # Add jitter if requested
                if jitter:
                    delay *= 0.5 + random.random()

                # Log retry attempt
                logger.warning(
                    f"Attempt {attempt + 1} failed for {func.__name__}: {e}. Retrying in {delay:.1f} seconds..."
                )

                if verbose:
                    click.echo(
                        f"⚠️  Connection failed (attempt {attempt + 1}/{max_retries + 1}). "
                        f"Retrying in {delay:.1f} seconds..."
                    )

                time.sleep(delay)

        # All retries exhausted
        raise RetryError(f"Failed after {max_retries + 1} attempts: {func.__name__}", last_error=last_exception)

    return wrapper


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retry_on: Optional[tuple[type[Exception], ...]] = None,
    verbose: bool = False,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator factory for retry with exponential backoff.

    Usage:
        @retry_with_backoff(max_retries=5, retry_on=(ConnectionError, TimeoutError))
        def download_file(url):
            # Download logic here
            pass
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        return exponential_backoff(
            func,
            max_retries=max_retries,
            base_delay=base_delay,
            max_delay=max_delay,
            exponential_base=exponential_base,
            jitter=jitter,
            retry_on=retry_on,
            verbose=verbose,
        )

    return decorator


def retry_cloud_operation(
    func: Callable[..., T],
    *args: Any,
    max_retries: int = 3,
    verbose: bool = False,
    **kwargs: Any,
) -> T:
    """
    Convenience function to retry cloud operations with sensible defaults.

    Retries on common cloud/network errors:
    - ConnectionError
    - TimeoutError
    - OSError (network-related)
    - Various HTTP errors

    Args:
        func: Function to execute
        *args: Arguments for the function
        max_retries: Maximum retry attempts
        verbose: Show retry messages
        **kwargs: Keyword arguments for the function

    Returns:
        Result of the function call

    Raises:
        RetryError: When all retries are exhausted
    """
    # Common network/cloud errors to retry
    retry_exceptions: tuple[type[Exception], ...] = (
        ConnectionError,
        TimeoutError,
        OSError,  # Includes network-related OS errors
    )

    # Try to include HTTP errors if available
    try:
        import requests

        retry_exceptions = (
            *retry_exceptions,
            requests.ConnectionError,
            requests.Timeout,
            requests.HTTPError,
        )
    except ImportError:
        pass

    # Try to include fsspec errors if available
    try:
        import fsspec

        retry_exceptions = (*retry_exceptions, fsspec.exceptions.FSTimeoutError)
    except (ImportError, AttributeError):
        pass

    wrapped_func = retry_with_backoff(
        max_retries=max_retries,
        retry_on=retry_exceptions,
        verbose=verbose,
    )(func)

    return wrapped_func(*args, **kwargs)
