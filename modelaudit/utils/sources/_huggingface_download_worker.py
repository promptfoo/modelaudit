"""Subprocess entry point for deadline-bounded Hugging Face downloads."""

from __future__ import annotations

import json
import os
import sys
from typing import Any

_RESULT_PREFIX = "MODELAUDIT_HF_DOWNLOAD_RESULT="


def _run_operation(operation: str, operation_kwargs: dict[str, Any]) -> dict[str, Any]:
    if operation == "list_repo_files":
        from huggingface_hub import HfApi

        repo_info = HfApi().repo_info(
            operation_kwargs["repo_id"],
            timeout=operation_kwargs.get("request_timeout"),
            files_metadata=False,
        )
        siblings = getattr(repo_info, "siblings", None)
        files: list[str] | None = None
        if siblings is not None:
            files = []
            for sibling in siblings:
                if isinstance(sibling, dict):
                    file_name = sibling.get("rfilename") or sibling.get("path")
                else:
                    file_name = getattr(sibling, "rfilename", None) or getattr(sibling, "path", None)
                if isinstance(file_name, str) and file_name:
                    files.append(file_name)
        return {"value": {"files": files, "revision": getattr(repo_info, "sha", None)}}
    if operation == "list_repo_tree":
        from huggingface_hub import HfApi

        repo_files = HfApi().list_repo_tree(
            operation_kwargs["repo_id"],
            recursive=True,
            revision=operation_kwargs.get("revision"),
        )
        tree_files: list[dict[str, Any]] = []
        for item in repo_files:
            path = getattr(item, "path", None)
            if not isinstance(path, str) or not hasattr(item, "size"):
                continue
            tree_files.append({"path": path, "size": getattr(item, "size", None)})
        return {"value": {"files": tree_files}}
    if operation == "snapshot_download":
        from huggingface_hub import snapshot_download

        downloaded_path: object = snapshot_download(**operation_kwargs)
    elif operation == "hf_hub_download":
        from huggingface_hub import hf_hub_download

        downloaded_path = hf_hub_download(**operation_kwargs)
    elif operation == "get_model_size":
        from huggingface_hub import HfApi

        model_info = HfApi().model_info(
            operation_kwargs["repo_id"],
            timeout=operation_kwargs.get("request_timeout"),
        )
        total_size = sum(
            file_info.size
            for file_info in (getattr(model_info, "siblings", None) or ())
            if isinstance(getattr(file_info, "size", None), int)
            and not isinstance(file_info.size, bool)
            and file_info.size > 0
        )
        return {"value": total_size or None}
    elif operation == "get_path_sizes":
        from huggingface_hub import HfApi

        api = HfApi()
        resolved_revision = operation_kwargs.get("resolved_revision")
        if resolved_revision is None:
            repo_info_kwargs: dict[str, Any] = {"files_metadata": False}
            requested_revision = operation_kwargs.get("requested_revision")
            if requested_revision is not None:
                repo_info_kwargs["revision"] = requested_revision
            repo_info = api.repo_info(operation_kwargs["repo_id"], **repo_info_kwargs)
            resolved_revision = getattr(repo_info, "sha", None)
        path_info = api.get_paths_info(
            operation_kwargs["repo_id"],
            operation_kwargs["filenames"],
            revision=resolved_revision,
        )
        return {
            "value": {
                "revision": resolved_revision,
                "sizes": [
                    {"path": getattr(item, "path", None), "size": getattr(item, "size", None)} for item in path_info
                ],
            }
        }
    else:
        raise ValueError(f"Unsupported Hugging Face download operation: {operation}")

    if not isinstance(downloaded_path, (str, bytes, os.PathLike)):
        raise TypeError("Hugging Face download returned a non-path result")
    return {"path": os.fsdecode(downloaded_path)}


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        operation = payload["operation"]
        operation_kwargs = payload["operation_kwargs"]
        if not isinstance(operation, str) or not isinstance(operation_kwargs, dict):
            raise ValueError("Invalid Hugging Face download worker payload")
        result = {"ok": True, **_run_operation(operation, operation_kwargs)}
    except Exception as exc:
        result = {"ok": False, "error_type": type(exc).__name__, "error": str(exc)}

    print(f"{_RESULT_PREFIX}{json.dumps(result)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
