"""Shared substring assertions for scanner evidence."""


def _assert_absent(value: str, *substrings: str) -> None:
    for substring in substrings:
        assert substring not in value


def _assert_present(value: str, *substrings: str) -> None:
    for substring in substrings:
        assert substring in value
