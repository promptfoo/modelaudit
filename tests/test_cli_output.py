from __future__ import annotations

import json

import pytest

from tests.cli_output import parse_click_json_output


def test_parse_click_json_output_handles_prefixed_log_lines() -> None:
    """Click tests may prefix stderr logs before the JSON body."""
    payload = {"files_scanned": 1, "issues": [{"rule_code": "S405"}]}
    output = (
        "2026-03-20 16:16:35,821 - modelaudit.scanners - CRITICAL - "
        "[S405] [CRITICAL] (evil.tar:../evil.txt): Archive entry ../evil.txt attempted path traversal\n"
        f"{json.dumps(payload, indent=2)}\n"
    )

    assert parse_click_json_output(output) == payload


def test_parse_click_json_output_rejects_non_object_json() -> None:
    """CLI scan JSON should be an object payload, not a scalar or array."""
    with pytest.raises(TypeError, match="Expected a JSON object"):
        parse_click_json_output("[]")
