"""Bound JSON allocation independently of the interpreter's decoder limits."""

MAX_JSON_NESTING_DEPTH = 256


def validate_json_structural_limits(raw: bytes, max_tokens: int | None, label: str) -> None:
    """Reject excessive nesting or containers before materializing the JSON graph."""
    token_count = 0
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
            continue
        if byte == ord('"'):
            in_string = True
        elif byte in {ord("{"), ord("[")}:
            depth += 1
            if depth > MAX_JSON_NESTING_DEPTH:
                raise ValueError(f"{label} exceeds JSON nesting depth limit ({MAX_JSON_NESTING_DEPTH})")
            token_count += 1
        elif byte == ord(","):
            token_count += 1
        elif byte in {ord("}"), ord("]")}:
            depth -= 1
        if max_tokens is not None and token_count > max_tokens:
            raise ValueError(f"{label} exceeds JSON object/value limit")
