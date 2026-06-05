"""Subprocess entry point for deadline-bounded Hugging Face downloads."""

from __future__ import annotations

import json
import os
import sys
from typing import Any

_RESULT_PREFIX = "MODELAUDIT_HF_DOWNLOAD_RESULT="


def _run_operation(operation: str, download_kwargs: dict[str, Any]) -> str:
    if operation == "snapshot_download":
        from huggingface_hub import snapshot_download

        downloaded_path: object = snapshot_download(**download_kwargs)
    elif operation == "hf_hub_download":
        from huggingface_hub import hf_hub_download

        downloaded_path = hf_hub_download(**download_kwargs)
    else:
        raise ValueError(f"Unsupported Hugging Face download operation: {operation}")

    if not isinstance(downloaded_path, (str, bytes, os.PathLike)):
        raise TypeError("Hugging Face download returned a non-path result")
    return os.fsdecode(downloaded_path)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        operation = payload["operation"]
        download_kwargs = payload["download_kwargs"]
        if not isinstance(operation, str) or not isinstance(download_kwargs, dict):
            raise ValueError("Invalid Hugging Face download worker payload")
        result = {"ok": True, "path": _run_operation(operation, download_kwargs)}
    except BaseException as exc:
        result = {"ok": False, "error_type": type(exc).__name__, "error": str(exc)}

    print(f"{_RESULT_PREFIX}{json.dumps(result)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
