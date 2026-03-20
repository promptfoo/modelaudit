"""Helpers for asserting JSON output from Click CLI tests."""

from __future__ import annotations

import json
from typing import Any


def parse_click_json_output(output: str) -> dict[str, Any]:
    """Parse JSON from `CliRunner` output, tolerating prefixed stderr log lines.

    Click's test runner can merge stderr into `result.output`, so scans that emit
    findings may prepend log lines before the JSON payload even though a real
    subprocess keeps stdout and stderr separate.
    """
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        for index, char in enumerate(output):
            if char != "{":
                continue

            try:
                parsed, end = decoder.raw_decode(output, index)
            except json.JSONDecodeError:
                continue

            if output[end:].strip():
                continue
            break
        else:
            raise

    if not isinstance(parsed, dict):
        raise TypeError(f"Expected a JSON object, got {type(parsed).__name__}")
    return parsed
