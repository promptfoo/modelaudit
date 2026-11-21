"""Text signals used to select PyTorch storage literals for pickle analysis."""

import base64
import binascii
import re
from collections.abc import Callable, Iterable, Iterator

_MAGIC_METHOD_PATTERN = (
    r"(?<!\w)__(?:reduce|reduce_ex|setstate|getstate|getnewargs|getnewargs_ex|subclasses|globals|code|"
    r"builtins|import|mro|base|bases|abs|add|aiter|and|anext|bool|bytes|call|ceil|contains|del|"
    r"delitem|enter|eq|exit|floor|format|fspath|ge|getattribute|getattr|getitem|gt|hash|iadd|iand|"
    r"ilshift|imatmul|imod|imul|index|invert|ior|ipow|irshift|iter|isub|itruediv|ixor|le|len|"
    r"length_hint|lshift|lt|matmul|mod|mul|ne|neg|next|or|pos|pow|radd|rand|rlshift|rmatmul|"
    r"rmod|rmul|ror|rpow|repr|reversed|round|rshift|rrshift|rsub|rtruediv|rxor|setitem|setattr|"
    r"set_name|str|sub|trunc|truediv|xor|delattr)__(?!\w)"
)

_STANDALONE_PATTERNS = (
    r"base64\.b64decode",
    r"importlib",
    r"os\.(?:system|popen|spawn[a-z]*)",
    r"subprocess\.(?:Popen|call|check_output|run|check_call)",
    r"commands\.(?:getoutput|getstatusoutput)",
    r"__import__",
    r"\\x[0-9a-fA-F]{2}",
    r"getattr\s*\(\s*getattr\s*\(",
)
_ROUTE_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE | re.DOTALL)
    for pattern in (
        r"(?:compile|eval|exec)\(",
        r"__import__\(",
        r"import\s+[\w.]+",
        r"from\s+[\w.]+\s+import\s*(?:\(|\*|[\w.,\s]+)",
        r"importlib\.(?:import_module|__import__)\(",
        r"os\.(?:system|popen|spawn[a-z]*)(?:\.__call__)?\(",
        r"subprocess\.(?:Popen|call|check_output|run|check_call)\(",
        r"base64\.(?:b64decode|decode)\(",
        r"(?:pickle|cloudpickle|joblib)\.(?:_pickle_load|load|loads)\(",
        r"copyreg\.(?:add_extension|remove_extension)\(",
        r"getattr\s*\(\s*\w+\s*,\s*['\"](?:system|popen|spawn|exec|eval|call|run|Popen)['\"]",
    )
)

_LINE_CONTINUATION = re.compile(r"\\(?:\r\n?|\n)[ \t\f]*")
_WHITESPACE = re.compile(r"\s+")
_TEXT_BATCH_SIZE = 1024
_BASE64_TOKEN = re.compile(rb"[A-Za-z0-9+/_-][A-Za-z0-9+/_=\-\s\r\n\t]{7,}")
_BASE64_ALPHABET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-")
_STANDARD_BASE64 = bytes.maketrans(b"-_", b"+/")
_HEX_TOKEN = re.compile(rb"(?:[0-9A-Fa-f]{2}[\s\r\n\t]*){4,}")
_MAX_TOKENS = 64
_MAX_BASE64_SEGMENTS = 64
_MAX_WINDOWS = 16
_DECODED_WINDOW_BYTES = 64 * 1024
_DECODED_OVERLAP_BYTES = 1024
_BASE64_WINDOW_BYTES = ((_DECODED_WINDOW_BYTES + 2) // 3) * 4
_BASE64_OVERLAP_BYTES = ((_DECODED_OVERLAP_BYTES + 2) // 3) * 4


def _replace_in_batches(text: str, pattern: re.Pattern[str], replacement: str) -> str:
    """Match only the original text and bound the number of unjoined fragments."""
    chunks: list[str] = []
    fragments: list[str] = []
    last_end = 0
    for match in pattern.finditer(text):
        fragments.append(text[last_end : match.start()])
        last_end = match.end()
        if len(fragments) >= _TEXT_BATCH_SIZE:
            chunks.append(replacement.join(fragments))
            fragments.clear()
    if not last_end:
        return text
    fragments.append(text[last_end:])
    chunks.append(replacement.join(fragments))
    return replacement.join(chunks)


def normalize_continuations(text: str) -> str:
    return _replace_in_batches(text, _LINE_CONTINUATION, "")


def _compact_member_access_and_calls(text: str) -> str:
    spaced = _replace_in_batches(text, _WHITESPACE, " ")
    return spaced.replace(" .", ".").replace(". ", ".").replace(" (", "(")


def base64_token_segments(token: bytes) -> tuple[tuple[int, int], ...] | None:
    """Include the whole token and candidates separated by interior base64 padding."""
    n = len(token)
    segments = [(0, n)] if n >= 8 else []
    starts = [0]
    for match in re.finditer(rb"=+", token):
        end = match.end()
        if end == n or token[end] not in _BASE64_ALPHABET:
            continue
        if len(starts) >= _MAX_BASE64_SEGMENTS:
            return None
        segments.extend((start, end) for start in starts if end - start >= 8)
        if len(segments) > _MAX_BASE64_SEGMENTS:
            return None
        starts.append(end)
    segments.extend((start, n) for start in starts[1:] if n - start >= 8)
    return tuple(segments) if len(segments) <= _MAX_BASE64_SEGMENTS else None


def _matches_tokens(value: bytes, pattern: re.Pattern[bytes], check: Callable[[bytes], bool]) -> bool:
    count = 0
    for match in pattern.finditer(value):
        token = re.sub(rb"\s+", b"", match.group())
        if len(token) < 8:
            continue
        count += 1
        if count > _MAX_TOKENS or check(token):
            return True
    return False


def _windows(value: bytes, start: int, end: int, size: int, overlap: int) -> Iterator[bytes | None]:
    """Yield None if the window budget ends before covering the whole range."""
    for index, offset in enumerate(range(start, end, size - overlap)):
        if index >= _MAX_WINDOWS:
            yield None
            return
        yield value[offset : min(end, offset + size)]
        if offset + size >= end:
            return


class StorageLiteralMatcher:
    """Apply the caller's text policy to raw, normalized and decoded storage literals."""

    def __init__(self, patterns: Iterable[str] = _STANDALONE_PATTERNS) -> None:
        raw = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (*patterns, _MAGIC_METHOD_PATTERN))
        self._patterns = raw + _ROUTE_PATTERNS
        # Route aliases and wrapped calls, but leave the verdict to the native
        # classifier. Lossy decoding can erase a separator next to the dunder.
        self._discovery_patterns = (*self._patterns, re.compile(r"__lazy_import__|\b(?:eval|exec)\b", re.IGNORECASE))

    def matches_text(self, text: str, *, discovery: bool = False) -> bool:
        patterns = self._discovery_patterns if discovery else self._patterns
        if any(pattern.search(text) for pattern in patterns):
            return True
        normalized = normalize_continuations(text)
        if normalized != text and any(pattern.search(normalized) for pattern in patterns):
            return True
        compacted = _compact_member_access_and_calls(normalized)
        return compacted != normalized and any(pattern.search(compacted) for pattern in _ROUTE_PATTERNS)

    def matches(self, value: bytes) -> bool:
        text = value.decode("utf-8", errors="ignore") or value.decode("latin-1")
        return (
            self.matches_text(text, discovery=True)
            or _matches_tokens(value, _BASE64_TOKEN, self._matches_base64)
            or _matches_tokens(value, _HEX_TOKEN, self._matches_hex)
        )

    def _matches_decoded(self, decoded: bytes) -> bool:
        for window in _windows(decoded, 0, len(decoded), _DECODED_WINDOW_BYTES, _DECODED_OVERLAP_BYTES):
            if window is None:
                return True
            for encoding in ("utf-8", "latin-1"):
                text = window.decode(encoding, errors="ignore")
                if text and self.matches_text(text, discovery=True):
                    return True
        return False

    def _matches_base64(self, token: bytes) -> bool:
        token = token.translate(_STANDARD_BASE64)
        segments = base64_token_segments(token)
        if segments is None:
            return True
        for start, end in segments:
            for shift in range(16):
                if end - start - shift < 8:
                    break
                if self._matches_base64_windows(token, start + shift, end):
                    return True
        return False

    def _matches_base64_windows(self, token: bytes, start: int, end: int) -> bool:
        for window in _windows(token, start, end, _BASE64_WINDOW_BYTES, _BASE64_OVERLAP_BYTES):
            if window is None:
                return True
            # A separator or surplus padding can end a native candidate inside
            # this wider discovery token. Keep all decodable prefix bytes.
            window = window.rstrip(b"=")
            if len(window) % 4 == 1:
                window = window[:-1]
            try:
                decoded = base64.b64decode(window + b"=" * (-len(window) % 4), validate=True)
            except (binascii.Error, ValueError):
                return False
            if decoded and self._matches_decoded(decoded):
                return True
        return False

    def _matches_hex(self, token: bytes) -> bool:
        try:
            decoded = binascii.unhexlify(token)
        except (binascii.Error, ValueError):
            return False
        return self._matches_decoded(decoded)
