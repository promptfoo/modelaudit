"""Deterministic response doubles for source download tests."""

from collections.abc import Iterator

import requests


class FakeStreamingResponse:
    def __init__(self, payload: bytes, *, status_code: int = 200, headers: dict[str, str] | None = None) -> None:
        self.payload = payload
        self.status_code = status_code
        self.headers = headers or {}
        self.cookies = requests.cookies.RequestsCookieJar()
        self.closed = False

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, chunk_size: int = 1) -> Iterator[bytes]:
        for offset in range(0, len(self.payload), chunk_size):
            yield self.payload[offset : offset + chunk_size]

    def close(self) -> None:
        self.closed = True
