"""Large-corpus QA harness for the Rust-backed pickle scanner.

The harness is intentionally conservative: it never deserializes model files,
stores all large artifacts outside the repository, and treats the Rust
standalone picklescanner as the primary ModelAudit baseline while adding
third-party scanner differentials for Fickling, ModelScan, and upstream
PickleScan.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import os
import pickle
import platform
import re
import shutil
import subprocess
import sys
import time
import zipfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from modelaudit_picklescan import PickleReport, ScanOptions, ScanStatus, Severity
from modelaudit_picklescan import PickleScanner as StandalonePickleScanner
from modelaudit_picklescan import scan_file as package_scan_file

from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, IssueSeverity, ScanResult
from modelaudit.scanners.pickle_scanner import PickleScanner
from modelaudit.scanners.picklescan_adapter import pickle_report_to_scan_result

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS_ROOT = Path("/tmp/modelaudit-large-pickle-corpus")
DEFAULT_TOOLS_ROOT = Path("~/code").expanduser()
TELEMETRY_ENV = {
    "PROMPTFOO_DISABLE_TELEMETRY": "1",
    "NO_ANALYTICS": "1",
    "POSTHOG_DISABLED": "1",
}
TIER_ORDER = {"smoke": 0, "medium": 1, "full": 2}
MODELAUDIT_THIRD_PARTY_BASELINE_PRIORITY = (
    ("modelaudit-picklescan", "rust"),
    ("modelaudit-root", "adapter-only:rust"),
    ("modelaudit-root", "default:rust"),
)


@dataclass(frozen=True, slots=True)
class CorpusEntry:
    id: str
    bucket: str
    repo_id: str
    path: str
    initial_size: str
    discovery_label: str
    qa_purpose: str
    min_tier: str = "full"


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    repo_url: str
    default_path: str
    invocation: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NormalizedResult:
    engine: str
    status: str
    verdict: str
    success: bool
    warning_count: int
    critical_count: int
    info_count: int
    rule_codes: tuple[str, ...]
    messages: tuple[str, ...]
    metadata: dict[str, Any]


CORPUS_ENTRIES: tuple[CorpusEntry, ...] = (
    CorpusEntry(
        "B01",
        "benign-small",
        "fullstuck/transformers_resnet18_cifar100",
        "pytorch_model.bin",
        "44.8 MB",
        "Safe",
        "Lower-bound large pickle, common Torch globals.",
        "smoke",
    ),
    CorpusEntry(
        "B02",
        "benign-small",
        "fullstuck/transformers_resnet18_cifar100",
        "resnet18_cifar100_classifier.pth",
        "46.8 MB",
        "Safe",
        ".pth extension routing and standalone direct scan.",
        "medium",
    ),
    CorpusEntry(
        "B03",
        "benign-small",
        "glazzova/body_type_resnet_v1",
        "pytorch_model.bin",
        "94.4 MB",
        "Pickle imports",
        "ResNet-style state dict.",
        "medium",
    ),
    CorpusEntry(
        "B04",
        "benign-medium",
        "glazzova/body_type_resnet_v1",
        "optimizer.pt",
        "188 MB",
        "Safe",
        "Optimizer checkpoint with PyTorch storage metadata.",
        "medium",
    ),
    CorpusEntry(
        "B05",
        "benign-medium",
        "joaogante/test_text_generation_pipeline_a",
        "pytorch_model.bin",
        "268 MB",
        "Pickle imports",
        "Transformers state dict.",
        "smoke",
    ),
    CorpusEntry(
        "B06",
        "benign-medium",
        "dima806/closed_eyes_image_detection",
        "checkpoint-2148/pytorch_model.bin",
        "343 MB",
        "Safe",
        "Checkpoint subdirectory path handling.",
        "medium",
    ),
    CorpusEntry(
        "B07",
        "benign-medium",
        "dima806/closed_eyes_image_detection",
        "checkpoint-2148/optimizer.pt",
        "687 MB",
        "Safe",
        "Large optimizer object with expected-safe imports.",
        "medium",
    ),
    CorpusEntry(
        "B08",
        "benign-medium",
        "intfloat/multilingual-e5-small",
        "pytorch_model.bin",
        "471 MB",
        "Safe",
        "LongStorage plus FloatStorage import references.",
        "medium",
    ),
    CorpusEntry(
        "B09",
        "benign-medium",
        "nealcly/detection-longformer",
        "pytorch_model.bin",
        "595 MB",
        "Safe",
        "Longformer checkpoint, medium file baseline.",
        "medium",
    ),
    CorpusEntry(
        "B10",
        "benign-large",
        "nealcly/detection-longformer",
        "optimizer.pt",
        "1.19 GB",
        "Safe",
        "Large optimizer stress, root memory behavior.",
    ),
    CorpusEntry(
        "B11",
        "benign-medium",
        "sagawa/CompoundT5",
        "pytorch_model.bin",
        "794 MB",
        "Pickle imports",
        "T5 state dict and JAX-adjacent repo mix.",
        "medium",
    ),
    CorpusEntry(
        "B12",
        "benign-large",
        "csebuetnlp/mT5_multilingual_XLSum",
        "pytorch_model.bin",
        "2.33 GB",
        "Safe",
        "Multi-GB model scan throughput.",
    ),
    CorpusEntry(
        "B13",
        "benign-large",
        "emre/whisper-medium-turkish-2",
        "pytorch_model.bin",
        "3.06 GB",
        "Safe",
        "Whisper checkpoint, large file routing.",
    ),
    CorpusEntry(
        "B14",
        "benign-large",
        "ash56/ssl-aasist",
        "xlsr2_300m.pt",
        "3.81 GB",
        "Safe",
        ".pt file, multi-GB direct candidate.",
    ),
    CorpusEntry(
        "B15",
        "benign-large",
        "timm/vit_large_patch14_clip_224.openai",
        "pytorch_model.bin",
        "1.71 GB",
        "Safe",
        "ViT state dict with common Torch globals.",
    ),
    CorpusEntry(
        "B16",
        "benign-large",
        "timm/vit_large_patch14_clip_224.openai",
        "open_clip_pytorch_model.bin",
        "1.71 GB",
        "Pickle imports",
        "Same model family, alternate filename.",
    ),
    CorpusEntry(
        "B17",
        "benign-xl",
        "InternScience/ChartVLM-large",
        "base_decoder/pytorch_model.bin",
        "5.34 GB",
        "Safe",
        "Very large PyTorch binary.",
    ),
    CorpusEntry(
        "B18",
        "benign-xl",
        "tencent/Hunyuan3D-Omni",
        "model/pytorch_model.bin",
        "12.2 GB",
        "Pickle imports",
        "Upper-bound stress file.",
    ),
    CorpusEntry(
        "P01",
        "positive-real",
        "ykilcher/totally-harmless-model",
        "pytorch_model.bin",
        "265 MB",
        "Unsafe",
        "Known public malicious/PoC model payload.",
        "smoke",
    ),
    CorpusEntry(
        "P02",
        "positive-real",
        "sheigel/best-llm",
        "pytorch_model.bin",
        "265 MB",
        "Unsafe",
        "Public unsafe model with distilbert-sized payload.",
        "medium",
    ),
    CorpusEntry(
        "P03",
        "positive-real",
        "dbmdz/flair-historic-ner-lft",
        "pytorch_model.bin",
        "444 MB",
        "Unsafe",
        "Large unsafe file with builtins.getattr and ML imports.",
        "medium",
    ),
    CorpusEntry(
        "P04",
        "positive-real",
        "dbmdz/flair-historic-ner-onb",
        "pytorch_model.bin",
        "444 MB",
        "Unsafe",
        "Independent Flair unsafe model, same size class.",
        "medium",
    ),
    CorpusEntry(
        "P05",
        "positive-real",
        "ecmwf/aifs-single-1.0",
        "aifs-single-mse-1.0.ckpt",
        "994 MB",
        "Unsafe",
        "Near-1GB checkpoint unsafe by public scanner metadata.",
        "medium",
    ),
    CorpusEntry(
        "P06",
        "positive-real",
        "alphacep/vosk-tts-ru-stabletts",
        "vosk_tts_ru_0.10.ckpt",
        "561 MB",
        "Unsafe",
        "TTS checkpoint unsafe by public scanner metadata.",
        "medium",
    ),
    CorpusEntry(
        "P07",
        "positive-real",
        "projecte-aina/matxa-tts-cat-multispeaker",
        "checkpoint_epoch=2399.ckpt",
        "251 MB",
        "Unsafe",
        "Checkpoint with functools.partial, OmegaConf, optimizer globals.",
        "medium",
    ),
)

REPLACEMENT_ENTRIES: tuple[CorpusEntry, ...] = (
    CorpusEntry(
        "R01",
        "replacement-benign-xl",
        "InternScience/ChartVLM-large",
        "base_decoder/state_dict.pth",
        "10.7 GB",
        "Safe",
        "Replacement queue very-large PyTorch state dict.",
    ),
    CorpusEntry(
        "R02",
        "replacement-benign-xl",
        "tencent/Hunyuan3D-Omni",
        "model/pytorch_model_ema.bin",
        "12.2 GB",
        "Safe",
        "Replacement queue EMA model binary.",
    ),
    CorpusEntry(
        "R03",
        "replacement-benign-xl",
        "emre/whisper-medium-turkish-2",
        "optimizer.pt",
        "6.11 GB",
        "Safe",
        "Replacement queue large optimizer checkpoint.",
    ),
    CorpusEntry(
        "R04",
        "replacement-positive",
        "projecte-aina/matxa-tts-cat-multiaccent",
        "checkpoint_epoch=2399.ckpt",
        "251 MB",
        "Unsafe",
        "Replacement queue unsafe TTS checkpoint.",
        "medium",
    ),
    CorpusEntry(
        "R05",
        "replacement-positive",
        "dbmdz/flair-historic-ner-onb",
        "pytorch_model.bin",
        "444 MB",
        "Unsafe",
        "Replacement queue duplicate of a known unsafe Flair checkpoint.",
        "medium",
    ),
)

TOOL_SPECS: dict[str, ToolSpec] = {
    "fickling": ToolSpec(
        "fickling",
        "https://github.com/trailofbits/fickling.git",
        "fickling",
        (
            "uv",
            "run",
            "--isolated",
            "--with-editable",
            "{path}",
            "fickling",
            "--check-safety",
            "-p",
            "{artifact}",
        ),
    ),
    "modelscan": ToolSpec(
        "modelscan",
        "https://github.com/protectai/modelscan.git",
        "modelscan",
        (
            "uv",
            "run",
            "--isolated",
            "--with-editable",
            "{path}",
            "modelscan",
            "-p",
            "{artifact}",
            "-r",
            "json",
            "-o",
            "{output}",
        ),
    ),
    "picklescan": ToolSpec(
        "picklescan",
        "https://github.com/mmaitre314/picklescan.git",
        "picklescan",
        (
            "uv",
            "run",
            "--isolated",
            "--with-editable",
            "{path}",
            "picklescan",
            "--path",
            "{artifact}",
        ),
    ),
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, tuple):
        return list(value)
    if hasattr(value, "value"):
        return value.value
    return repr(value)


def _json_clean(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_clean(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_json_clean(item) for item in value]
    if isinstance(value, bytes | bytearray):
        return {"hex": bytes(value).hex(), "length": len(value)}
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "value"):
        return value.value
    if value is None or isinstance(value, str | int | float | bool):
        return value
    return repr(value)


def _write_json(path: Path, payload: Mapping[str, Any] | Sequence[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=_json_default) + "\n", encoding="utf-8")


def _append_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, default=_json_default) + "\n")


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object in {path}")
    return payload


def _sha256_file(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _repo_git(args: Sequence[str], *, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=False,
        text=True,
        capture_output=True,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            "git command failed: "
            f"git {' '.join(args)}\n"
            f"cwd: {cwd}\n"
            f"exit: {completed.returncode}\n"
            f"stdout: {completed.stdout.strip()}\n"
            f"stderr: {completed.stderr.strip()}"
        )
    return completed


def _run_command(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout_s: float | None = None,
    env: Mapping[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], float]:
    started_at = time.monotonic()
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env={**os.environ, **TELEMETRY_ENV, **dict(env or {})},
        text=True,
        capture_output=True,
        timeout=timeout_s,
        check=False,
    )
    return completed, time.monotonic() - started_at


def _tool_path(spec: ToolSpec, tools_root: Path) -> Path:
    default_path = Path(spec.default_path).expanduser()
    if default_path.is_absolute():
        return default_path
    return tools_root / default_path


def _tool_dirty_status(path: Path) -> str:
    return _repo_git(["status", "--short"], cwd=path).stdout.strip()


def _git_describe(path: Path) -> str:
    return _repo_git(["describe", "--tags", "--always", "--dirty"], cwd=path).stdout.strip()


def _git_branch(path: Path) -> str:
    return _repo_git(["branch", "--show-current"], cwd=path).stdout.strip()


def _git_remote(path: Path) -> str:
    return _repo_git(["remote", "get-url", "origin"], cwd=path).stdout.strip()


def _git_head(path: Path) -> str:
    return _repo_git(["rev-parse", "HEAD"], cwd=path).stdout.strip()


def _git_default_branch(path: Path) -> str:
    result = _repo_git(["symbolic-ref", "refs/remotes/origin/HEAD"], cwd=path, check=False)
    ref = result.stdout.strip()
    if ref.startswith("refs/remotes/origin/"):
        return ref.removeprefix("refs/remotes/origin/")
    return _git_branch(path) or "main"


def _sync_tool(spec: ToolSpec, *, tools_root: Path, allow_dirty: bool, skip_pull: bool) -> dict[str, Any]:
    path = _tool_path(spec, tools_root)
    tools_root.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        subprocess.run(["git", "clone", spec.repo_url, str(path)], check=True)
    if not (path / ".git").exists():
        raise ValueError(f"{path} exists but is not a Git repository")

    remote = _git_remote(path)
    if remote != spec.repo_url:
        raise ValueError(f"{spec.name} remote mismatch: expected {spec.repo_url}, got {remote}")

    dirty = _tool_dirty_status(path)
    if dirty and not allow_dirty:
        raise ValueError(f"{spec.name} worktree is dirty:\n{dirty}")

    if not skip_pull:
        _repo_git(["fetch", "--tags", "origin"], cwd=path)
        default_branch = _git_default_branch(path)
        current_branch = _git_branch(path)
        if not dirty and current_branch and current_branch != default_branch:
            _repo_git(["checkout", default_branch], cwd=path)
        _repo_git(["pull", "--ff-only"], cwd=path)

    return {
        "name": spec.name,
        "path": str(path),
        "repo_url": spec.repo_url,
        "remote": _git_remote(path),
        "branch": _git_branch(path),
        "commit": _git_head(path),
        "describe": _git_describe(path),
        "dirty": _tool_dirty_status(path),
        "synced_at": _now_iso(),
    }


def _select_entries(
    *,
    ids: set[str] | None,
    tier: str,
    include_replacements: bool = False,
) -> list[CorpusEntry]:
    if tier not in TIER_ORDER:
        raise ValueError(f"unknown tier: {tier}")
    replacement_ids_requested = ids is not None and bool(ids & {entry.id for entry in REPLACEMENT_ENTRIES})
    source_entries = [*CORPUS_ENTRIES]
    if include_replacements or replacement_ids_requested:
        source_entries.extend(REPLACEMENT_ENTRIES)
    entries = []
    for entry in source_entries:
        if ids is not None and entry.id not in ids:
            continue
        if ids is None and TIER_ORDER[entry.min_tier] > TIER_ORDER[tier]:
            continue
        entries.append(entry)
    return entries


def _entry_local_path(corpus_root: Path, entry: CorpusEntry) -> Path:
    return corpus_root / "raw" / entry.id / entry.path


def _validated_artifact_id(value: object) -> str:
    artifact_id = str(value)
    if (
        not artifact_id
        or artifact_id in {".", ".."}
        or "/" in artifact_id
        or "\\" in artifact_id
        or PureWindowsPath(artifact_id).drive
        or Path(artifact_id).is_absolute()
    ):
        raise ValueError(f"unsafe corpus artifact id: {artifact_id!r}")
    return artifact_id


def _validated_remote_path(value: object) -> Path:
    raw_path = str(value)
    raw_parts = raw_path.split("/")
    remote_path = PurePosixPath(raw_path)
    if (
        not raw_path
        or "\\" in raw_path
        or remote_path.is_absolute()
        or PureWindowsPath(raw_path).drive
        or any(part in {"", ".", ".."} for part in raw_parts)
    ):
        raise ValueError(f"unsafe corpus artifact path: {raw_path!r}")
    return Path(*raw_parts)


def _contained_output_path(root: Path, *parts: str | Path) -> Path:
    resolved_root = root.resolve()
    candidate = resolved_root.joinpath(*parts).resolve()
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise ValueError(f"corpus path escapes output root: {candidate}")
    return candidate


def _validated_lock_entry_path(entry: Mapping[str, Any]) -> tuple[str, Path]:
    return _validated_artifact_id(entry["id"]), _validated_remote_path(entry["path"])


def _entry_to_lock(entry: CorpusEntry, *, corpus_root: Path) -> dict[str, Any]:
    return {
        **asdict(entry),
        "revision": "main",
        "remote_size_bytes": None,
        "sha256": None,
        "etag": None,
        "license": None,
        "source_url": f"https://huggingface.co/{entry.repo_id}/tree/main",
        "downloaded_at": None,
        "local_path": str(_entry_local_path(corpus_root, entry)),
        "preflight_status": "pending",
        "preflight_error": None,
    }


def _hf_file_metadata(repo_id: str, filename: str, *, revision: str) -> dict[str, Any]:
    try:
        from huggingface_hub import HfApi
    except Exception as error:  # pragma: no cover - depends on optional import state
        raise RuntimeError("huggingface_hub is required for online preflight") from error

    api = HfApi()
    info = api.model_info(repo_id, revision=revision, files_metadata=True)
    siblings = getattr(info, "siblings", []) or []
    for sibling in siblings:
        sibling_name = getattr(sibling, "rfilename", None)
        if sibling_name != filename:
            continue
        lfs = getattr(sibling, "lfs", None) or {}
        size = getattr(sibling, "size", None)
        if size is None and isinstance(lfs, Mapping):
            size = lfs.get("size")
        sha = None
        if isinstance(lfs, Mapping):
            sha = lfs.get("sha256")
        return {
            "revision": getattr(info, "sha", revision),
            "remote_size_bytes": size,
            "etag": getattr(sibling, "blob_id", None) or sha,
            "license": (getattr(info, "card_data", None) or {}).get("license")
            if isinstance(getattr(info, "card_data", None), Mapping)
            else None,
            "preflight_status": "ok",
            "preflight_error": None,
        }
    raise FileNotFoundError(f"{filename} not found in {repo_id}@{revision}")


def _load_lock_entries(lock_path: Path) -> list[dict[str, Any]]:
    payload = _read_json(lock_path)
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise ValueError(f"lockfile missing entries list: {lock_path}")
    return [entry for entry in entries if isinstance(entry, dict)]


LOCK_CORE_KEYS = {"schema_version", "created_at", "tier", "entry_count", "entries"}


def _lock_extra_metadata(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in payload.items() if key not in LOCK_CORE_KEYS}


def _write_lock(
    lock_path: Path,
    entries: list[dict[str, Any]],
    *,
    tier: str,
    extra: Mapping[str, Any] | None = None,
) -> None:
    payload = {
        "schema_version": 1,
        "created_at": _now_iso(),
        "tier": tier,
        "entry_count": len(entries),
        "entries": entries,
    }
    if extra:
        payload.update(extra)
    _write_json(lock_path, payload)


def _finalize_downloaded_entry(entry: dict[str, Any], local_path: Path) -> dict[str, Any]:
    entry["local_path"] = str(local_path)
    entry["sha256"] = _sha256_file(local_path)
    entry["downloaded_at"] = _now_iso()
    entry["downloaded_size_bytes"] = local_path.stat().st_size
    return entry


def _direct_download_entry(entry: Mapping[str, Any], local_path: Path) -> Path:
    revision = str(entry.get("revision") or "main")
    repo_id = str(entry["repo_id"])
    filename = str(entry["path"])
    url = f"https://huggingface.co/{repo_id}/resolve/{revision}/{quote(filename, safe='/')}"
    part_path = _contained_output_path(local_path.parent, f"{local_path.name}.part")
    local_path.parent.mkdir(parents=True, exist_ok=True)

    expected_size = entry.get("remote_size_bytes")
    if local_path.exists() and isinstance(expected_size, int) and local_path.stat().st_size == expected_size:
        return local_path

    resume_at = part_path.stat().st_size if part_path.exists() else 0
    headers = {"User-Agent": "modelaudit-large-pickle-corpus-qa/1.0"}
    if resume_at:
        headers["Range"] = f"bytes={resume_at}-"
    request = Request(url, headers=headers)

    try:
        with urlopen(request, timeout=300) as response:
            status = getattr(response, "status", None)
            mode = "ab" if resume_at and status == 206 else "wb"
            with part_path.open(mode) as handle:
                while chunk := response.read(8 * 1024 * 1024):
                    handle.write(chunk)
    except HTTPError as error:
        if error.code != 416:
            raise

    part_path.replace(local_path)
    if isinstance(expected_size, int) and local_path.stat().st_size != expected_size:
        raise RuntimeError(
            f"direct download size mismatch for {local_path}: expected {expected_size}, got {local_path.stat().st_size}"
        )
    return local_path


def _download_entry(
    entry: dict[str, Any],
    *,
    corpus_root: Path,
    etag_timeout_s: float,
    direct_fallback: bool,
    direct_only: bool,
) -> dict[str, Any]:
    artifact_id, relative_path = _validated_lock_entry_path(entry)

    try:
        from huggingface_hub import hf_hub_download
    except Exception as error:  # pragma: no cover - depends on optional import state
        raise RuntimeError("huggingface_hub is required for downloads") from error

    raw_root = _contained_output_path(corpus_root, "raw")
    local_dir = _contained_output_path(raw_root, artifact_id)
    local_dir.mkdir(parents=True, exist_ok=True)
    expected_path = _contained_output_path(local_dir, relative_path)
    expected_size = entry.get("remote_size_bytes")
    if expected_path.exists() and isinstance(expected_size, int) and expected_path.stat().st_size == expected_size:
        return _finalize_downloaded_entry(entry, expected_path)

    if direct_only:
        local_path = _direct_download_entry(entry, expected_path)
        entry["download_fallback"] = "direct-only"
        return _finalize_downloaded_entry(entry, local_path)

    try:
        downloaded = hf_hub_download(
            repo_id=str(entry["repo_id"]),
            filename=relative_path.as_posix(),
            revision=str(entry.get("revision") or "main"),
            local_dir=local_dir,
            etag_timeout=etag_timeout_s,
        )
        local_path = _contained_output_path(local_dir, Path(downloaded).resolve().relative_to(local_dir.resolve()))
    except Exception:
        if not direct_fallback:
            raise
        local_path = _direct_download_entry(entry, expected_path)
        entry["download_fallback"] = "direct"
    return _finalize_downloaded_entry(entry, local_path)


def _classify_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"exists": False, "kind": "missing", "size_bytes": None}
    with path.open("rb") as handle:
        header = handle.read(16)
    kind = "unknown"
    is_zip = zipfile.is_zipfile(path)
    if is_zip:
        kind = "zip"
    elif header.startswith(b"\x80") or header[:1] in {b"(", b"c", b"d", b"l", b"i", b"I", b"S", b"V"}:
        kind = "pickle-like"
    elif header.startswith(b"7z\xbc\xaf\x27\x1c"):
        kind = "7z"
    elif path.suffix.lower() in {".pt", ".pth", ".ckpt", ".bin"}:
        kind = "model-binary"
    return {
        "exists": True,
        "kind": kind,
        "size_bytes": path.stat().st_size,
        "header_hex": header.hex(),
        "is_zip": is_zip,
    }


def _legacy_status(result: ScanResult) -> str:
    if result.metadata.get("operational_error"):
        return "error"
    if result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME:
        return "inconclusive"
    return "complete"


def _legacy_verdict(result: ScanResult) -> str:
    severities = [issue.severity for issue in result.issues]
    if IssueSeverity.CRITICAL in severities:
        return "malicious"
    if IssueSeverity.WARNING in severities:
        return "suspicious"
    if _legacy_status(result) == "complete":
        return "clean"
    return "unknown"


def _normalize_scan_result(result: ScanResult, *, engine: str) -> NormalizedResult:
    return NormalizedResult(
        engine=engine,
        status=_legacy_status(result),
        verdict=_legacy_verdict(result),
        success=bool(result.success),
        warning_count=sum(1 for issue in result.issues if issue.severity == IssueSeverity.WARNING),
        critical_count=sum(1 for issue in result.issues if issue.severity == IssueSeverity.CRITICAL),
        info_count=sum(1 for issue in result.issues if issue.severity == IssueSeverity.INFO),
        rule_codes=tuple(sorted(issue.rule_code for issue in result.issues if issue.rule_code)),
        messages=tuple(sorted(issue.message for issue in result.issues)),
        metadata=_json_clean(dict(result.metadata)),
    )


def _normalize_package_report(report: PickleReport, *, engine: str) -> NormalizedResult:
    return NormalizedResult(
        engine=engine,
        status=report.status.value,
        verdict=report.verdict.value,
        success=report.status == ScanStatus.COMPLETE
        or (report.status == ScanStatus.INCONCLUSIVE and report.has_security_findings),
        warning_count=sum(1 for finding in report.findings if finding.severity == Severity.WARNING),
        critical_count=sum(1 for finding in report.findings if finding.severity == Severity.CRITICAL),
        info_count=len(report.notices),
        rule_codes=tuple(sorted(finding.rule_code for finding in report.findings if finding.rule_code)),
        messages=tuple(sorted(finding.message for finding in report.findings)),
        metadata=_json_clean(dict(report.metadata)),
    )


def _scan_package(path: Path, *, engine: str, artifact_id: str) -> dict[str, Any]:
    if engine != "rust":
        raise ValueError(f"unsupported picklescan engine after Rust migration: {engine}")
    started = time.monotonic()
    if artifact_id == "V10":
        report = StandalonePickleScanner(options=ScanOptions(max_opcodes=1)).scan_file(path)
    else:
        report = package_scan_file(path)
    duration = time.monotonic() - started
    normalized = _normalize_package_report(report, engine=f"package:{engine}")
    return {
        "artifact_id": artifact_id,
        "scanner": "modelaudit-picklescan",
        "mode": engine,
        "duration_s": duration,
        "result": asdict(normalized),
        "raw": _stable_report_dict(report),
    }


def _scan_root(path: Path, *, engine: str, root_mode: str, artifact_id: str) -> dict[str, Any]:
    if engine != "rust":
        raise ValueError(f"unsupported root picklescan engine after Rust migration: {engine}")
    started = time.monotonic()
    scanner = PickleScanner()
    if root_mode == "default":
        result = scanner.scan(str(path))
    elif root_mode == "adapter-only":
        report = package_scan_file(path)
        result = pickle_report_to_scan_result(report, scanner_name=scanner.name, scanner=scanner)
        result.metadata["pickle_primary_engine"] = "rust"
    else:
        raise ValueError(f"unsupported root mode: {root_mode}")
    duration = time.monotonic() - started
    normalized = _normalize_scan_result(result, engine=f"root:{root_mode}:{engine}")
    return {
        "artifact_id": artifact_id,
        "scanner": "modelaudit-root",
        "mode": f"{root_mode}:{engine}",
        "duration_s": duration,
        "result": asdict(normalized),
    }


def _stable_report_dict(report: PickleReport) -> dict[str, Any]:
    payload = report.to_dict()
    payload.pop("duration_s", None)
    cleaned = _json_clean(payload)
    if not isinstance(cleaned, dict):
        raise TypeError(f"expected report dict, got {type(cleaned).__name__}")
    return cleaned


def _tool_command(spec: ToolSpec, *, tool_path: Path, artifact_path: Path, output_path: Path) -> list[str]:
    return [
        part.format(path=str(tool_path), artifact=str(artifact_path), output=str(output_path))
        for part in spec.invocation
    ]


def _third_party_verdict(tool: str, exit_code: int, stdout: str, stderr: str, output_json: Path) -> str:
    combined = f"{stdout}\n{stderr}".lower()
    if "traceback (most recent call last)" in combined or "unhandled exception" in combined:
        return "error"
    if tool == "modelscan" and output_json.exists():
        try:
            payload = json.loads(output_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}
        summary = payload.get("summary") if isinstance(payload, Mapping) else None
        total_issues = summary.get("total_issues") if isinstance(summary, Mapping) else None
        issues = payload.get("issues") if isinstance(payload, Mapping) else None
        if isinstance(total_issues, int) and total_issues > 0:
            return "malicious"
        if isinstance(issues, list) and issues:
            return "malicious"
        if exit_code in {2, 3, 4}:
            return "error"
        return "clean" if exit_code == 0 else "unknown"
    if tool == "picklescan":
        infected_match = re.search(r"infected files:\s*(\d+)", combined)
        dangerous_match = re.search(r"dangerous globals:\s*(\d+)", combined)
        infected_count = int(infected_match.group(1)) if infected_match else None
        dangerous_count = int(dangerous_match.group(1)) if dangerous_match else None
        if (infected_count is not None and infected_count > 0) or (dangerous_count is not None and dangerous_count > 0):
            return "malicious"
        if exit_code in {2, 3, 4}:
            return "error"
        if exit_code == 0 and infected_count == 0 and dangerous_count == 0:
            return "clean"
        if exit_code == 1:
            return "malicious"
    if exit_code == 1:
        return "malicious"
    if exit_code in {2, 3, 4}:
        return "error"
    if "unsafe" in combined or "malicious" in combined or "infected" in combined:
        return "malicious"
    if "safe" in combined or exit_code == 0:
        return "clean"
    return "unknown"


def _scan_third_party(
    path: Path,
    *,
    artifact_id: str,
    spec: ToolSpec,
    tools_root: Path,
    run_dir: Path,
    timeout_s: float,
) -> dict[str, Any]:
    artifact_id = _validated_artifact_id(artifact_id)
    tool_path = _tool_path(spec, tools_root)
    output_path = _contained_output_path(run_dir, "third-party-raw", artifact_id, f"{spec.name}.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    command = _tool_command(spec, tool_path=tool_path, artifact_path=path, output_path=output_path)
    try:
        completed, duration = _run_command(command, timeout_s=timeout_s)
        status = "complete"
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as error:
        duration = timeout_s
        status = "timeout"
        exit_code = 124
        stdout = (error.stdout or "") if isinstance(error.stdout, str) else ""
        stderr = (error.stderr or "") if isinstance(error.stderr, str) else ""
    except FileNotFoundError as error:
        duration = 0.0
        status = "error"
        exit_code = 127
        stdout = ""
        stderr = str(error)

    return {
        "artifact_id": artifact_id,
        "tool": spec.name,
        "tool_path": str(tool_path),
        "tool_commit": _git_head(tool_path) if (tool_path / ".git").exists() else None,
        "command": command,
        "status": status,
        "verdict": _third_party_verdict(spec.name, exit_code, stdout, stderr, output_path),
        "exit_code": exit_code,
        "stdout_tail": stdout[-4000:],
        "stderr_tail": stderr[-4000:],
        "duration_s": duration,
        "raw_output": str(output_path) if output_path.exists() else None,
    }


def _is_package_scannable_path(path: Path, classification: Mapping[str, Any]) -> bool:
    if classification.get("kind") == "zip":
        return path.suffix.lower() in {".pt", ".pth", ".ckpt", ".pkl", ".bin"}
    return path.suffix.lower() in {".pkl", ".pickle", ".dill", ".joblib", ".pt", ".pth", ".ckpt", ".bin"}


def _iter_pickle_zip_members(path: Path, *, run_dir: Path, artifact_id: str) -> Iterator[tuple[str, Path]]:
    try:
        with zipfile.ZipFile(path) as archive:
            for member_index, member in enumerate(archive.infolist()):
                if member.is_dir():
                    continue
                member_name = member.filename
                lowered = member_name.lower()
                if not (
                    lowered.endswith((".pkl", ".pickle")) or lowered.endswith("/data.pkl") or lowered == "data.pkl"
                ):
                    continue
                member_path = _member_file_path(run_dir, artifact_id, member_name, member_index=member_index)
                member_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with archive.open(member) as source, member_path.open("wb") as target:
                        shutil.copyfileobj(source, target, length=1024 * 1024)
                except Exception as error:
                    logging.warning("failed to extract %s from %s: %s", member_name, path, error)
                    continue
                yield member_name, member_path
    except zipfile.BadZipFile:
        return


def _member_file_path(run_dir: Path, artifact_id: str, member_name: str, *, member_index: int) -> Path:
    artifact_id = _validated_artifact_id(artifact_id)
    member_digest = hashlib.sha256(member_name.encode("utf-8")).hexdigest()
    safe_member_name = f"{member_index:08d}-{member_digest}.pkl"
    return _contained_output_path(run_dir, "members", artifact_id, safe_member_name)


def _malicious_reduce_payload() -> bytes:
    return raw_os_system_reduce_payload()


def _stack_global_payload() -> bytes:
    return raw_stack_global_eval_reduce_payload()


def raw_os_system_reduce_payload() -> bytes:
    return b"\x80\x04cos\nsystem\n\x8c\x0cecho qa-noop\x85R."


def raw_stack_global_eval_reduce_payload() -> bytes:
    return b"\x80\x04\x8c\x08builtins\x8c\x04eval\x93\x8c\x031+1\x85R."


def _write_synthetic_variants(output_dir: Path) -> list[dict[str, Any]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    malicious = _malicious_reduce_payload()
    stack_global = _stack_global_payload()
    nested = pickle.dumps({"outer": malicious}, protocol=4)
    base64_payload = __import__("base64").b64encode(malicious).decode("ascii")
    hex_payload = malicious.hex()
    escaped_hex_payload = "".join(f"\\x{byte:02x}" for byte in malicious)
    variants: dict[str, bytes] = {
        "V01_append_reduce.pkl": pickle.dumps({"safe": True}, protocol=4) + malicious,
        "V02_stack_global_reduce.pkl": stack_global,
        "V03_memoized_stack_global.pkl": b"\x80\x04\x8c\x02osq\x00\x8c\x06systemq\x01h\x00h\x01\x93\x85R.",
        "V04_malformed_stack_global.pkl": b"\x80\x04K\x01K\x02\x93.",
        "V05_ext_ref.pkl": b"\x80\x04\x82\x01.",
        "V06_nested_raw.pkl": nested,
        "V07_nested_base64.pkl": pickle.dumps({"outer": base64_payload}, protocol=4),
        "V08_nested_hex.pkl": pickle.dumps({"outer": hex_payload, "escaped": escaped_hex_payload}, protocol=4),
        "V09_suspicious_late_literal.pkl": pickle.dumps({"code": ("A" * 4096) + "os.system('id')"}, protocol=4),
        "V10_post_budget_tail.pkl": b"\x80\x04}" + malicious,
        "V11_large_benign_decoy.pkl": pickle.dumps({"blob": b"\x80\x04not-a-pickle" * 4096}, protocol=4),
        "V14_policy_callables.pkl": b"".join(
            [
                b"\x80\x04cpip\nmain\n.",
                b"\x80\x04ctorch\nload\n.",
                b"\x80\x04cnumpy\nload\n.",
                b"\x80\x04cjoblib\nload\n.",
                b"\x80\x04cdill\nloads\n.",
                b"\x80\x04ctarfile\nopen\n.",
                b"\x80\x04czipfile\nZipFile\n.",
                b"\x80\x04clogging.config\ndictConfig\n.",
                b"\x80\x04cuuid\n_popen\n.",
            ]
        ),
        "V15_benign_state_dict.pkl": pickle.dumps({"weights": [1, 2, 3]}, protocol=4),
    }

    records: list[dict[str, Any]] = []
    for filename, payload in variants.items():
        path = output_dir / filename
        path.write_bytes(payload)
        records.append(
            {
                "id": filename.split("_", 1)[0],
                "kind": "synthetic",
                "path": str(path),
                "size_bytes": path.stat().st_size,
                "sha256": _sha256_file(path),
                "created_at": _now_iso(),
            }
        )

    zip_variant = output_dir / "V12_pytorch_zip_data_pkl.pt"
    with zipfile.ZipFile(zip_variant, "w") as archive:
        archive.writestr("archive/data.pkl", malicious)
        archive.writestr("archive/version", "3\n")
        archive.writestr("archive/byteorder", "little")
    records.append(
        {
            "id": "V12",
            "kind": "synthetic",
            "path": str(zip_variant),
            "size_bytes": zip_variant.stat().st_size,
            "sha256": _sha256_file(zip_variant),
            "created_at": _now_iso(),
        }
    )

    malformed = output_dir / "V13_malformed_7z_like.pt"
    malformed.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 128 + malicious)
    records.append(
        {
            "id": "V13",
            "kind": "synthetic",
            "path": str(malformed),
            "size_bytes": malformed.stat().st_size,
            "sha256": _sha256_file(malformed),
            "created_at": _now_iso(),
        }
    )
    _write_json(output_dir / "synthetic-manifest.json", {"entries": records})
    return records


def _environment_payload(*, tools: Sequence[dict[str, Any]] | None = None) -> dict[str, Any]:
    git_status = _repo_git(["status", "--short"], cwd=REPO_ROOT, check=False).stdout.strip()
    return {
        "created_at": _now_iso(),
        "repo_root": str(REPO_ROOT),
        "git_commit": _repo_git(["rev-parse", "HEAD"], cwd=REPO_ROOT, check=False).stdout.strip(),
        "git_branch": _repo_git(["branch", "--show-current"], cwd=REPO_ROOT, check=False).stdout.strip(),
        "dirty_worktree": bool(git_status),
        "git_status_short": git_status,
        "python": sys.version,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "tools": list(tools or []),
        "engine": "rust",
    }


def cmd_list_corpus(args: argparse.Namespace) -> int:
    entries = _select_entries(
        ids=set(args.ids) if args.ids else None,
        tier=args.tier,
        include_replacements=args.include_replacements,
    )
    payload = {
        "tier": args.tier,
        "include_replacements": args.include_replacements,
        "entry_count": len(entries),
        "entries": [asdict(entry) for entry in entries],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_sync_tools(args: argparse.Namespace) -> int:
    tools_root = Path(args.tools_root).expanduser()
    selected_tools = args.tools or sorted(TOOL_SPECS)
    results = [
        _sync_tool(
            TOOL_SPECS[name],
            tools_root=tools_root,
            allow_dirty=args.allow_dirty,
            skip_pull=args.skip_pull,
        )
        for name in selected_tools
    ]
    output = Path(args.out) if args.out else None
    if output:
        _write_json(output, {"tools": results})
    print(json.dumps({"tools": results}, indent=2, sort_keys=True))
    return 0


def cmd_preflight(args: argparse.Namespace) -> int:
    corpus_root = Path(args.corpus_root)
    entries = []
    for entry in _select_entries(
        ids=set(args.ids) if args.ids else None,
        tier=args.tier,
        include_replacements=args.include_replacements,
    ):
        record = _entry_to_lock(entry, corpus_root=corpus_root)
        if not args.offline:
            try:
                record.update(_hf_file_metadata(entry.repo_id, entry.path, revision=args.revision))
            except Exception as error:
                record["preflight_status"] = "error"
                record["preflight_error"] = f"{type(error).__name__}: {error}"
        entries.append(record)
    _write_lock(Path(args.out), entries, tier=args.tier)
    print(f"Wrote {len(entries)} corpus entries to {args.out}")
    return 1 if any(entry.get("preflight_status") == "error" for entry in entries) else 0


def _is_replacement_lock_entry(entry: Mapping[str, Any]) -> bool:
    return str(entry.get("id", "")).startswith("R")


def cmd_finalize_lock(args: argparse.Namespace) -> int:
    source_lock = Path(args.lock)
    payload = _read_json(source_lock)
    entries = _load_lock_entries(source_lock)
    ok_primary = [
        entry for entry in entries if not _is_replacement_lock_entry(entry) and entry.get("preflight_status") == "ok"
    ]
    failed_primary = [
        entry for entry in entries if not _is_replacement_lock_entry(entry) and entry.get("preflight_status") != "ok"
    ]
    ok_replacements = [
        entry for entry in entries if _is_replacement_lock_entry(entry) and entry.get("preflight_status") == "ok"
    ]

    selected = [dict(entry) for entry in ok_primary]
    needed = max(int(args.target_count) - len(selected), 0)
    selected_replacements = [dict(entry) for entry in ok_replacements[:needed]]
    failed_primary_ids = [str(entry.get("id")) for entry in failed_primary]
    for replacement in selected_replacements:
        replacement["selected_as_replacement"] = True
        replacement["replacement_note"] = f"fills one of unavailable primary slots: {', '.join(failed_primary_ids)}"
    selected.extend(selected_replacements)

    _write_lock(
        Path(args.out),
        selected,
        tier=str(payload.get("tier", "custom")),
        extra={
            "source_lock": str(source_lock),
            "target_count": int(args.target_count),
            "unavailable_primary_ids": failed_primary_ids,
            "selected_replacement_ids": [str(entry.get("id")) for entry in selected_replacements],
            "selection_status": "ok" if len(selected) == int(args.target_count) else "incomplete",
        },
    )
    print(f"Wrote {len(selected)} selected corpus entries to {args.out}")
    return 0 if len(selected) == int(args.target_count) else 1


def cmd_download(args: argparse.Namespace) -> int:
    corpus_root = Path(args.corpus_root)
    lock_path = Path(args.lock)
    lock_payload = _read_json(lock_path)
    entries = _load_lock_entries(lock_path)
    selected_ids = set(args.ids) if args.ids else None
    downloaded_bytes = 0
    budget_bytes = int(float(args.budget_gb) * 1024 * 1024 * 1024) if args.budget_gb is not None else None
    updated = []
    download_failed = False
    for entry in entries:
        if selected_ids is not None and str(entry.get("id")) not in selected_ids:
            updated.append(entry)
            continue
        try:
            _validated_lock_entry_path(entry)
            remote_size = entry.get("remote_size_bytes")
            if (
                budget_bytes is not None
                and isinstance(remote_size, int)
                and downloaded_bytes + remote_size > budget_bytes
            ):
                entry["download_status"] = "skipped_budget"
                entry.pop("download_error", None)
                updated.append(entry)
                continue
            entry = _download_entry(
                entry,
                corpus_root=corpus_root,
                etag_timeout_s=float(args.etag_timeout_s),
                direct_fallback=not args.no_direct_fallback,
                direct_only=args.direct_only,
            )
            downloaded_bytes += int(entry.get("downloaded_size_bytes") or 0)
            entry["download_status"] = "ok"
            entry.pop("download_error", None)
        except Exception as error:
            download_failed = True
            entry["download_status"] = "error"
            entry["download_error"] = f"{type(error).__name__}: {error}"
        updated.append(entry)
    _write_lock(
        lock_path,
        updated,
        tier=str(lock_payload.get("tier", "custom")),
        extra=_lock_extra_metadata(lock_payload),
    )
    print(f"Updated {lock_path}; downloaded {downloaded_bytes} bytes")
    return 1 if download_failed else 0


def cmd_classify(args: argparse.Namespace) -> int:
    lock_path = Path(args.lock)
    lock_payload = _read_json(lock_path)
    entries = _load_lock_entries(lock_path)
    for entry in entries:
        entry["classification"] = _classify_file(Path(str(entry["local_path"])))
    _write_lock(
        lock_path,
        entries,
        tier=str(lock_payload.get("tier", "custom")),
        extra=_lock_extra_metadata(lock_payload),
    )
    print(f"Classified {len(entries)} entries in {lock_path}")
    return 0


def _scan_records_for_entry(
    entry: Mapping[str, Any],
    *,
    run_dir: Path,
    package_engines: Sequence[str],
    root_modes: Sequence[str],
    third_party_tools: Sequence[str],
    tools_root: Path,
    third_party_timeout_s: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    path = Path(str(entry["local_path"]))
    try:
        artifact_id = _validated_artifact_id(entry["id"])
    except ValueError as error:
        return (
            [
                {
                    "artifact_id": str(entry.get("id")),
                    "scanner": "harness",
                    "mode": "invalid-lock-entry",
                    "status": "error",
                    "error": f"{type(error).__name__}: {error}",
                }
            ],
            [],
        )
    scan_rows: list[dict[str, Any]] = []
    third_party_rows: list[dict[str, Any]] = []
    if not path.exists():
        missing = {
            "artifact_id": artifact_id,
            "scanner": "harness",
            "mode": "missing",
            "status": "error",
            "error": f"local path does not exist: {path}",
        }
        return [missing], third_party_rows

    classification = entry.get("classification")
    classification_map = classification if isinstance(classification, Mapping) else _classify_file(path)
    package_targets: list[tuple[str, Path]] = []
    if _is_package_scannable_path(path, classification_map):
        package_targets.append((artifact_id, path))
    elif classification_map.get("kind") == "zip":
        for member_name, member_path in _iter_pickle_zip_members(path, run_dir=run_dir, artifact_id=artifact_id):
            package_targets.append((f"{artifact_id}:{member_name}", member_path))

    for target_artifact_id, target_path in package_targets:
        for engine in package_engines:
            try:
                scan_rows.append(_scan_package(target_path, engine=engine, artifact_id=target_artifact_id))
            except Exception as error:
                scan_rows.append(
                    {
                        "artifact_id": target_artifact_id,
                        "scanner": "modelaudit-picklescan",
                        "mode": engine,
                        "status": "error",
                        "error": f"{type(error).__name__}: {error}",
                    }
                )

    for root_mode in root_modes:
        for engine in package_engines:
            try:
                scan_rows.append(_scan_root(path, engine=engine, root_mode=root_mode, artifact_id=artifact_id))
            except Exception as error:
                scan_rows.append(
                    {
                        "artifact_id": artifact_id,
                        "scanner": "modelaudit-root",
                        "mode": f"{root_mode}:{engine}",
                        "status": "error",
                        "error": f"{type(error).__name__}: {error}",
                    }
                )

    for tool in third_party_tools:
        third_party_rows.append(
            _scan_third_party(
                path,
                artifact_id=artifact_id,
                spec=TOOL_SPECS[tool],
                tools_root=tools_root,
                run_dir=run_dir,
                timeout_s=third_party_timeout_s,
            )
        )
    return scan_rows, third_party_rows


def cmd_generate_synthetic(args: argparse.Namespace) -> int:
    records = _write_synthetic_variants(Path(args.out))
    print(f"Wrote {len(records)} synthetic variants to {args.out}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    run_dir = Path(args.out)
    run_dir.mkdir(parents=True, exist_ok=True)
    lock_path = Path(args.lock)
    lock_payload = _read_json(lock_path)
    entries = _load_lock_entries(lock_path)
    selected_ids = set(args.ids) if args.ids else None
    if selected_ids:
        entries = [entry for entry in entries if entry.get("id") in selected_ids]
    if not args.no_synthetic:
        synthetic_dir = run_dir / "synthetic"
        synthetic_entries = _write_synthetic_variants(synthetic_dir)
        entries.extend(
            {
                "id": entry["id"],
                "bucket": "synthetic",
                "repo_id": "local-synthetic",
                "path": Path(str(entry["path"])).name,
                "local_path": entry["path"],
                "sha256": entry["sha256"],
                "classification": _classify_file(Path(str(entry["path"]))),
            }
            for entry in synthetic_entries
        )

    tools = []
    if args.third_party_tools:
        tool_names = [name for name in args.third_party_tools.split(",") if name]
        tools = [
            _sync_tool(
                TOOL_SPECS[name],
                tools_root=Path(args.tools_root).expanduser(),
                allow_dirty=args.allow_dirty_tools,
                skip_pull=args.skip_tool_pull,
            )
            for name in tool_names
        ]
    else:
        tool_names = []

    _write_json(run_dir / "environment.json", _environment_payload(tools=tools))
    _write_json(run_dir / "large-corpus.lock.json", lock_payload)
    scan_results_path = run_dir / "scan-results.jsonl"
    third_party_results_path = run_dir / "third-party-results.jsonl"
    scan_results_path.unlink(missing_ok=True)
    third_party_results_path.unlink(missing_ok=True)

    package_engines = tuple(engine for engine in args.engines.split(",") if engine)
    unsupported_engines = sorted(set(package_engines) - {"rust"})
    if unsupported_engines:
        print(
            "Unsupported picklescan engine(s) after Rust migration: " + ", ".join(unsupported_engines),
            file=sys.stderr,
        )
        return 2
    root_modes = tuple(mode for mode in args.root_modes.split(",") if mode)
    all_scan_rows: list[dict[str, Any]] = []
    all_third_party_rows: list[dict[str, Any]] = []
    previous_logging_disable_level = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        for entry in entries:
            scan_rows, third_party_rows = _scan_records_for_entry(
                entry,
                run_dir=run_dir,
                package_engines=package_engines,
                root_modes=root_modes,
                third_party_tools=tool_names,
                tools_root=Path(args.tools_root).expanduser(),
                third_party_timeout_s=args.third_party_timeout_s,
            )
            _append_jsonl(scan_results_path, scan_rows)
            _append_jsonl(third_party_results_path, third_party_rows)
            all_scan_rows.extend(scan_rows)
            all_third_party_rows.extend(third_party_rows)
    finally:
        logging.disable(previous_logging_disable_level)

    _write_json(run_dir / "parity-drift.json", _build_parity_drift(all_scan_rows))
    _write_json(
        run_dir / "third-party-differential.json",
        _build_third_party_differential(all_third_party_rows, scan_rows=all_scan_rows),
    )
    _write_json(run_dir / "coverage-matrix.json", _build_coverage_matrix(all_scan_rows))
    _write_json(run_dir / "benchmark-results.json", _build_benchmark_results(all_scan_rows, all_third_party_rows))
    _write_benchmark_csv(run_dir / "benchmark-summary.csv", all_scan_rows, all_third_party_rows)
    _write_report(run_dir, all_scan_rows, all_third_party_rows)
    print(f"Wrote QA run to {run_dir}")
    scan_error_count = sum(1 for row in all_scan_rows if _scan_row_has_error(row))
    if scan_error_count:
        print(
            f"QA scan failed with {scan_error_count} scan error(s); see {scan_results_path}",
            file=sys.stderr,
        )
        return 2
    return 1 if _has_blocking_drift(all_scan_rows) and args.fail_on_drift else 0


def _scan_row_has_error(row: Mapping[str, Any]) -> bool:
    if row.get("status") == "error":
        return True
    result = row.get("result")
    return isinstance(result, Mapping) and result.get("status") == "error"


def _rows_by_artifact_and_scanner(rows: Iterable[Mapping[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        result = row.get("result")
        if not isinstance(result, Mapping):
            continue
        key = (str(row.get("artifact_id")), f"{row.get('scanner')}:{row.get('mode')}")
        indexed[key] = dict(row)
    return indexed


def _result_rank(result: Mapping[str, Any]) -> int:
    verdict = result.get("verdict")
    return {"clean": 0, "suspicious": 1, "malicious": 2, "unknown": -1}.get(str(verdict), -1)


def _build_parity_drift(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    by_artifact: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        by_artifact[str(row.get("artifact_id"))].append(row)

    drifts = []
    for artifact_id, artifact_rows in sorted(by_artifact.items()):
        package_rust = _find_result(artifact_rows, "modelaudit-picklescan", "rust")
        for root_mode in ("default", "adapter-only"):
            root_rust = _find_result(artifact_rows, "modelaudit-root", f"{root_mode}:rust")
            if package_rust and root_rust:
                drift = _compare_results(package_rust, root_rust)
                if drift["delta"] != "match":
                    drifts.append({"artifact_id": artifact_id, "scope": f"package_vs_root:{root_mode}", **drift})

    return {
        "drift_count": len(drifts),
        "summary": dict(Counter(str(drift["delta"]) for drift in drifts)),
        "drifts": drifts,
    }


def _find_result(rows: Sequence[Mapping[str, Any]], scanner: str, mode: str) -> Mapping[str, Any] | None:
    for row in rows:
        result = row.get("result")
        if row.get("scanner") == scanner and row.get("mode") == mode and isinstance(result, Mapping):
            return result
    return None


def _compare_results(a: Mapping[str, Any], b: Mapping[str, Any]) -> dict[str, Any]:
    keys = ("status", "verdict", "success", "rule_codes")
    differences = {key: {"a": a.get(key), "b": b.get(key)} for key in keys if a.get(key) != b.get(key)}
    if not differences:
        return {"delta": "match", "differences": {}}
    if _result_rank(b) < _result_rank(a):
        delta = "potential_fn"
    elif a.get("status") != b.get("status"):
        delta = "status_drift"
    elif a.get("verdict") != b.get("verdict"):
        delta = "verdict_drift"
    else:
        delta = "rule_drift"
    return {"delta": delta, "differences": differences}


def _build_third_party_differential(
    rows: Sequence[Mapping[str, Any]],
    *,
    scan_rows: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    by_tool = Counter(str(row.get("tool")) for row in rows)
    by_verdict = Counter(str(row.get("verdict")) for row in rows)
    failures = [
        row
        for row in rows
        if row.get("status") in {"error", "timeout"}
        or row.get("verdict") == "error"
        or row.get("exit_code") not in {0, 1, None}
    ]
    comparison = _build_modelaudit_third_party_comparison(scan_rows, rows)
    return {
        "result_count": len(rows),
        "summary_by_tool": dict(sorted(by_tool.items())),
        "summary_by_verdict": dict(sorted(by_verdict.items())),
        "failure_count": len(failures),
        "failures": failures,
        **comparison,
    }


def _build_modelaudit_third_party_comparison(
    scan_rows: Sequence[Mapping[str, Any]],
    third_party_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    baselines = _modelaudit_baseline_rows(scan_rows)
    comparison_rows: list[dict[str, Any]] = []
    summary: Counter[str] = Counter()

    for row in third_party_rows:
        artifact_id = str(row.get("artifact_id"))
        baseline = baselines.get(artifact_id)
        if baseline is None:
            continue
        result = baseline.get("result")
        if not isinstance(result, Mapping):
            continue

        modelaudit_verdict = str(result.get("verdict"))
        third_party_verdict = str(row.get("verdict"))
        delta = _third_party_delta(modelaudit_verdict, third_party_verdict)
        if delta is None:
            continue
        summary[delta] += 1
        if delta == "match":
            continue

        rule_codes = result.get("rule_codes")
        messages = result.get("messages")
        comparison_rows.append(
            {
                "artifact_id": artifact_id,
                "tool": row.get("tool"),
                "delta": delta,
                "modelaudit_scanner": baseline.get("scanner"),
                "modelaudit_mode": baseline.get("mode"),
                "modelaudit_verdict": modelaudit_verdict,
                "modelaudit_rule_codes": list(rule_codes)
                if isinstance(rule_codes, Sequence) and not isinstance(rule_codes, str)
                else [],
                "modelaudit_messages": list(messages)
                if isinstance(messages, Sequence) and not isinstance(messages, str)
                else [],
                "third_party_verdict": third_party_verdict,
                "third_party_status": row.get("status"),
                "third_party_exit_code": row.get("exit_code"),
            }
        )

    return {
        "comparison_count": sum(summary.values()),
        "agreement_count": summary.get("match", 0),
        "disagreement_count": len(comparison_rows),
        "summary_by_delta": dict(sorted(summary.items())),
        "disagreements": comparison_rows,
    }


def _modelaudit_baseline_rows(rows: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    rows_by_key: dict[tuple[str, str, str], Mapping[str, Any]] = {}
    for row in rows:
        result = row.get("result")
        if not isinstance(result, Mapping):
            continue
        rows_by_key[(str(row.get("artifact_id")), str(row.get("scanner")), str(row.get("mode")))] = row

    artifact_ids = sorted({key[0] for key in rows_by_key})
    baselines: dict[str, Mapping[str, Any]] = {}
    for artifact_id in artifact_ids:
        for scanner, mode in MODELAUDIT_THIRD_PARTY_BASELINE_PRIORITY:
            candidate = rows_by_key.get((artifact_id, scanner, mode))
            if candidate is not None:
                baselines[artifact_id] = candidate
                break
    return baselines


def _third_party_delta(modelaudit_verdict: str, third_party_verdict: str) -> str | None:
    if third_party_verdict in {"error", "unknown"} or modelaudit_verdict in {"error", "unknown"}:
        return None

    modelaudit_positive = modelaudit_verdict in {"malicious", "suspicious"}
    third_party_positive = third_party_verdict in {"malicious", "suspicious"}
    if modelaudit_positive and third_party_verdict == "clean":
        return "modelaudit_only_positive"
    if modelaudit_verdict == "clean" and third_party_positive:
        return "third_party_only_positive"
    if modelaudit_positive and third_party_positive and modelaudit_verdict != third_party_verdict:
        return "severity_drift"
    return "match"


def _build_coverage_matrix(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    required = {
        "DANGEROUS_GLOBAL",
        "DANGEROUS_CALL",
        "MALFORMED_STACK_GLOBAL",
        "EXTENSION_REF",
        "SUSPICIOUS_STRING",
        "S213",
        "S601",
        "S602",
        "POST_BUDGET_GLOBAL",
    }
    coverage: dict[str, set[str]] = {rule: set() for rule in required}
    observed: set[str] = set()
    for row in rows:
        result = row.get("result")
        if not isinstance(result, Mapping):
            continue
        rule_codes = result.get("rule_codes")
        if not isinstance(rule_codes, Sequence) or isinstance(rule_codes, str):
            continue
        for rule in rule_codes:
            rule_text = str(rule)
            observed.add(rule_text)
            if rule_text in coverage:
                coverage[rule_text].add(str(row.get("artifact_id")))
    return {
        "required": sorted(required),
        "observed": sorted(observed),
        "coverage": {rule: sorted(artifact_ids) for rule, artifact_ids in coverage.items()},
        "missing": sorted(rule for rule, artifact_ids in coverage.items() if not artifact_ids),
    }


def _build_benchmark_results(
    scan_rows: Sequence[Mapping[str, Any]],
    third_party_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    durations: dict[str, list[float]] = defaultdict(list)
    for row in [*scan_rows, *third_party_rows]:
        duration = row.get("duration_s")
        if isinstance(duration, int | float):
            key = f"{row.get('scanner') or row.get('tool')}:{row.get('mode') or 'default'}"
            durations[key].append(float(duration))
    return {
        key: {
            "count": len(values),
            "total_s": sum(values),
            "mean_s": sum(values) / len(values) if values else 0.0,
            "max_s": max(values) if values else 0.0,
        }
        for key, values in sorted(durations.items())
    }


def _write_benchmark_csv(
    path: Path,
    scan_rows: Sequence[Mapping[str, Any]],
    third_party_rows: Sequence[Mapping[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["artifact_id", "scanner", "mode", "duration_s", "verdict"])
        writer.writeheader()
        for row in scan_rows:
            result = row.get("result") if isinstance(row.get("result"), Mapping) else {}
            writer.writerow(
                {
                    "artifact_id": row.get("artifact_id"),
                    "scanner": row.get("scanner"),
                    "mode": row.get("mode"),
                    "duration_s": row.get("duration_s"),
                    "verdict": result.get("verdict") if isinstance(result, Mapping) else None,
                }
            )
        for row in third_party_rows:
            writer.writerow(
                {
                    "artifact_id": row.get("artifact_id"),
                    "scanner": row.get("tool"),
                    "mode": "third-party",
                    "duration_s": row.get("duration_s"),
                    "verdict": row.get("verdict"),
                }
            )


def _has_blocking_drift(rows: Sequence[Mapping[str, Any]]) -> bool:
    drift = _build_parity_drift(rows)
    return any(item["delta"] in {"potential_fn", "status_drift", "verdict_drift"} for item in drift["drifts"])


def _write_report(
    run_dir: Path,
    scan_rows: Sequence[Mapping[str, Any]],
    third_party_rows: Sequence[Mapping[str, Any]],
) -> None:
    drift = _build_parity_drift(scan_rows)
    third_party = _build_third_party_differential(third_party_rows, scan_rows=scan_rows)
    coverage = _build_coverage_matrix(scan_rows)
    benchmark = _build_benchmark_results(scan_rows, third_party_rows)
    lines = [
        "# PickleScan Rust Large-Corpus QA Report",
        "",
        f"Generated: {_now_iso()}",
        "",
        "## Summary",
        "",
        f"- ModelAudit scan rows: {len(scan_rows)}",
        f"- Third-party scan rows: {len(third_party_rows)}",
        f"- Parity drift count: {drift['drift_count']}",
        f"- Third-party failure count: {third_party['failure_count']}",
        f"- Coverage missing: {', '.join(coverage['missing']) if coverage['missing'] else 'none'}",
        "",
        "## Parity Drift",
        "",
        "```json",
        json.dumps(drift, indent=2, sort_keys=True, default=_json_default),
        "```",
        "",
        "## Third-Party Differential",
        "",
        "```json",
        json.dumps(third_party, indent=2, sort_keys=True, default=_json_default),
        "```",
        "",
        "## Coverage Matrix",
        "",
        "```json",
        json.dumps(coverage, indent=2, sort_keys=True, default=_json_default),
        "```",
        "",
        "## Benchmark Summary",
        "",
        "```json",
        json.dumps(benchmark, indent=2, sort_keys=True, default=_json_default),
        "```",
        "",
    ]
    (run_dir / "qa-report.md").write_text("\n".join(lines), encoding="utf-8")


def cmd_report(args: argparse.Namespace) -> int:
    run_dir = Path(args.run)
    scan_rows = _read_jsonl(run_dir / "scan-results.jsonl")
    third_party_rows = _read_jsonl(run_dir / "third-party-results.jsonl")
    _write_json(run_dir / "parity-drift.json", _build_parity_drift(scan_rows))
    _write_json(
        run_dir / "third-party-differential.json",
        _build_third_party_differential(third_party_rows, scan_rows=scan_rows),
    )
    _write_json(run_dir / "coverage-matrix.json", _build_coverage_matrix(scan_rows))
    _write_json(run_dir / "benchmark-results.json", _build_benchmark_results(scan_rows, third_party_rows))
    _write_benchmark_csv(run_dir / "benchmark-summary.csv", scan_rows, third_party_rows)
    _write_report(run_dir, scan_rows, third_party_rows)
    print(f"Wrote report files in {run_dir}")
    return 0


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                payload = json.loads(line)
                if isinstance(payload, dict):
                    rows.append(payload)
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run large-corpus QA for the Rust pickle scanner.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list-corpus", help="Print the built-in corpus manifest.")
    list_parser.add_argument("--tier", choices=sorted(TIER_ORDER), default="full")
    list_parser.add_argument("--ids", nargs="*")
    list_parser.add_argument("--include-replacements", action="store_true")
    list_parser.set_defaults(func=cmd_list_corpus)

    sync_parser = subparsers.add_parser("sync-tools", help="Clone or fast-forward third-party scanner tools.")
    sync_parser.add_argument("--tools-root", default=str(DEFAULT_TOOLS_ROOT))
    sync_parser.add_argument("--tools", nargs="*", choices=sorted(TOOL_SPECS))
    sync_parser.add_argument("--out")
    sync_parser.add_argument("--allow-dirty", action="store_true")
    sync_parser.add_argument("--skip-pull", action="store_true")
    sync_parser.set_defaults(func=cmd_sync_tools)

    preflight_parser = subparsers.add_parser("preflight", help="Resolve corpus metadata and write a lockfile.")
    preflight_parser.add_argument("--out", required=True)
    preflight_parser.add_argument("--corpus-root", default=str(DEFAULT_CORPUS_ROOT))
    preflight_parser.add_argument("--tier", choices=sorted(TIER_ORDER), default="full")
    preflight_parser.add_argument("--ids", nargs="*")
    preflight_parser.add_argument("--revision", default="main")
    preflight_parser.add_argument("--offline", action="store_true")
    preflight_parser.add_argument("--include-replacements", action="store_true")
    preflight_parser.set_defaults(func=cmd_preflight)

    finalize_parser = subparsers.add_parser(
        "finalize-lock",
        help="Select preflight-ok primary entries and replacement queue entries for a run lock.",
    )
    finalize_parser.add_argument("--lock", required=True)
    finalize_parser.add_argument("--out", required=True)
    finalize_parser.add_argument("--target-count", type=int, default=25)
    finalize_parser.set_defaults(func=cmd_finalize_lock)

    download_parser = subparsers.add_parser("download", help="Download locked corpus entries.")
    download_parser.add_argument("--lock", required=True)
    download_parser.add_argument("--corpus-root", default=str(DEFAULT_CORPUS_ROOT))
    download_parser.add_argument("--ids", nargs="*")
    download_parser.add_argument("--budget-gb", type=float)
    download_parser.add_argument("--etag-timeout-s", type=float, default=60.0)
    download_parser.add_argument("--no-direct-fallback", action="store_true")
    download_parser.add_argument("--direct-only", action="store_true")
    download_parser.set_defaults(func=cmd_download)

    classify_parser = subparsers.add_parser("classify", help="Classify downloaded corpus files.")
    classify_parser.add_argument("--lock", required=True)
    classify_parser.set_defaults(func=cmd_classify)

    synthetic_parser = subparsers.add_parser("generate-synthetic", help="Generate deterministic synthetic variants.")
    synthetic_parser.add_argument("--out", required=True)
    synthetic_parser.set_defaults(func=cmd_generate_synthetic)

    scan_parser = subparsers.add_parser("scan", help="Run ModelAudit and optional third-party scans.")
    scan_parser.add_argument("--lock", required=True)
    scan_parser.add_argument("--out", required=True)
    scan_parser.add_argument("--ids", nargs="*")
    scan_parser.add_argument("--engines", default="rust", help="Comma-separated engine list; only 'rust' is supported.")
    scan_parser.add_argument("--root-modes", default="default,adapter-only")
    scan_parser.add_argument("--third-party-tools", default="")
    scan_parser.add_argument("--tools-root", default=str(DEFAULT_TOOLS_ROOT))
    scan_parser.add_argument("--third-party-timeout-s", type=float, default=300.0)
    scan_parser.add_argument("--allow-dirty-tools", action="store_true")
    scan_parser.add_argument("--skip-tool-pull", action="store_true")
    scan_parser.add_argument("--no-synthetic", action="store_true")
    scan_parser.add_argument("--fail-on-drift", action="store_true")
    scan_parser.set_defaults(func=cmd_scan)

    report_parser = subparsers.add_parser("report", help="Rebuild report files for an existing run directory.")
    report_parser.add_argument("--run", required=True)
    report_parser.set_defaults(func=cmd_report)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
