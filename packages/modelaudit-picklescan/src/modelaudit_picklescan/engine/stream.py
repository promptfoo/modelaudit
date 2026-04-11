"""Bounded stream wrapper used by pickle opcode analysis."""

from __future__ import annotations

from typing import BinaryIO


class _StreamReadError(Exception):
    """Raised when the source stream fails during incremental parsing."""

    def __init__(self, source_error: Exception) -> None:
        super().__init__(str(source_error))
        self.source_error = source_error


class _BoundedPickleStream:
    """Incrementally read pickle bytes while enforcing an optional byte limit."""

    def __init__(self, stream: BinaryIO, byte_limit: int | None) -> None:
        self._stream = stream
        self._byte_limit = byte_limit
        self._prefetched = bytearray()
        self._position = 0
        self.short_read = False

    def tell(self) -> int:
        return self._position

    def has_remaining_bytes(self) -> bool:
        if self._byte_limit is not None and self._position >= self._byte_limit:
            return False
        if self._prefetched:
            return True

        chunk = self._read_once(1)
        if not chunk:
            if self._byte_limit is not None and self._position < self._byte_limit:
                self.short_read = True
            return False
        self._prefetched.extend(chunk)
        return True

    def read(self, size: int | None = -1) -> bytes:
        read_size = self._bounded_size(size)
        if read_size == 0:
            return b""

        if read_size is None:
            prefetched = self._consume_prefetched()
            chunk = self._read_once(None)
            payload = prefetched + chunk
            self._position += len(payload)
            return payload

        chunks: list[bytes] = []
        prefetched = self._consume_prefetched(read_size)
        if prefetched:
            chunks.append(prefetched)
        bytes_read = len(prefetched)
        while bytes_read < read_size:
            chunk = self._read_once(read_size - bytes_read)
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)

        self._position += bytes_read
        self._mark_short_read_if_needed(bytes_read, expected_bytes=read_size)
        return b"".join(chunks)

    def readline(self, size: int | None = -1) -> bytes:
        read_size = self._bounded_size(size)
        if read_size == 0:
            return b""

        prefix = self._consume_prefetched_line(read_size)
        if prefix.endswith(b"\n") or (read_size is not None and len(prefix) >= read_size):
            self._position += len(prefix)
            return prefix

        suffix_size = None if read_size is None else read_size - len(prefix)
        suffix = self._readline_once(suffix_size)
        chunk = prefix + suffix
        chunk_len = len(chunk)
        if self._byte_limit is not None and self._position + chunk_len < self._byte_limit and not chunk.endswith(b"\n"):
            self.short_read = True
        self._position += chunk_len
        return chunk

    def _bounded_size(self, requested_size: int | None) -> int | None:
        if requested_size is not None and requested_size < 0:
            requested_size = None
        if self._byte_limit is None:
            return requested_size

        remaining = max(self._byte_limit - self._position, 0)
        if requested_size is None:
            return remaining
        return min(requested_size, remaining)

    def _read_once(self, size: int | None) -> bytes:
        try:
            return self._stream.read() if size is None else self._stream.read(size)
        except (OSError, ValueError) as error:
            raise _StreamReadError(error) from error

    def _readline_once(self, size: int | None) -> bytes:
        try:
            return self._stream.readline() if size is None else self._stream.readline(size)
        except (OSError, ValueError) as error:
            raise _StreamReadError(error) from error

    def _mark_short_read_if_needed(self, bytes_read: int, *, expected_bytes: int) -> None:
        if self._byte_limit is None:
            return
        if bytes_read < expected_bytes and self._position < self._byte_limit:
            self.short_read = True

    def _consume_prefetched(self, size: int | None = None) -> bytes:
        if not self._prefetched:
            return b""

        if size is None or size >= len(self._prefetched):
            chunk = bytes(self._prefetched)
            self._prefetched.clear()
            return chunk

        chunk = bytes(self._prefetched[:size])
        del self._prefetched[:size]
        return chunk

    def _consume_prefetched_line(self, size: int | None = None) -> bytes:
        if not self._prefetched:
            return b""

        limit = len(self._prefetched) if size is None else min(size, len(self._prefetched))
        newline_index = self._prefetched.find(b"\n", 0, limit)
        end = newline_index + 1 if newline_index >= 0 else limit
        chunk = bytes(self._prefetched[:end])
        del self._prefetched[:end]
        return chunk
