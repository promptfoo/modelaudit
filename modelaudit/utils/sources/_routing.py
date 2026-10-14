import json
import struct
from collections.abc import Callable


def _is_remote_safetensors_candidate(
    prefix: bytes,
    file_size: int | None,
    read_prefix: Callable[[int], bytes],
    *,
    unknown_oversized_minimum: int = 0,
) -> bool:
    """Share bounded framing while retaining caller read and completeness policies."""
    if len(prefix) < 9:
        return False
    header_len = struct.unpack("<Q", prefix[:8])[0]
    if header_len <= 0 or (file_size is not None and header_len > file_size - 8):
        return False

    from modelaudit.utils.file.detection import SAFETENSORS_ROUTING_HEADER_PARSE_BYTES

    if header_len > SAFETENSORS_ROUTING_HEADER_PARSE_BYTES:
        return prefix[8:9] == b"{" and (file_size is not None or len(prefix) >= unknown_oversized_minimum)

    header_probe = read_prefix(8 + header_len)
    if len(header_probe) != 8 + header_len or header_probe[8:9] != b"{":
        return False
    try:
        parsed_header = json.loads(header_probe[8:].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(parsed_header, dict)
