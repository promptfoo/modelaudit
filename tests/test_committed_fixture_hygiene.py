"""Guardrails for committed test fixture artifacts.

These checks keep generated or one-off scanner assets from quietly becoming
unmaintained repository payloads. They inspect tracked files only, so local
scratch files do not affect the test result.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ASSETS_DIR = REPO_ROOT / "tests" / "assets"
SAFETENSORS_DIR = ASSETS_DIR / "samples" / "safetensors"
KERAS_DIR = ASSETS_DIR / "samples" / "keras"
JINJA2_DIR = ASSETS_DIR / "samples" / "jinja2"
BYPASS_POC_DIR = ASSETS_DIR / "pickles" / "bypass_pocs"

EXPECTED_SAFETENSORS_FIXTURES = {
    "malicious_import.safetensors",
    "safe_model.safetensors",
}
MAX_COMMITTED_SAFETENSORS_BYTES = 4 * 1024

EXPECTED_KERAS_BINARY_FIXTURES = {
    "custom_layer_attack.h5",
    "loss_injection.h5",
    "malicious_lambda.h5",
    "metric_injection.h5",
    "safe_model.h5",
}

LARGE_ASSET_BYTES = 100 * 1024
LARGE_ASSET_ALLOWLIST = {
    "tests/assets/samples/pickles/safe_large_model.pkl": "safe pickle regression corpus large-file fixture",
    "tests/assets/scenarios/license_scenarios/agpl_component/agpl_model.pkl": "license scenario model fixture",
    "tests/assets/scenarios/license_scenarios/unlicensed_dataset/embeddings.npy": "license scenario dataset fixture",
}


def _tracked_asset_paths() -> tuple[Path, ...]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "tests/assets"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        pytest.skip(f"git tracked-file inventory unavailable: {exc}")

    return tuple(REPO_ROOT / line for line in result.stdout.splitlines() if line)


def _tracked_under(directory: Path) -> tuple[Path, ...]:
    return tuple(path for path in _tracked_asset_paths() if path.is_relative_to(directory))


def test_committed_safetensors_corpus_stays_small_and_intentional() -> None:
    safetensors_files = tuple(path for path in _tracked_under(SAFETENSORS_DIR) if path.suffix == ".safetensors")

    assert {path.name for path in safetensors_files} == EXPECTED_SAFETENSORS_FIXTURES
    oversized = {
        path.relative_to(REPO_ROOT).as_posix(): path.stat().st_size
        for path in safetensors_files
        if path.stat().st_size > MAX_COMMITTED_SAFETENSORS_BYTES
    }
    assert oversized == {}


def test_committed_keras_binary_fixtures_match_exercised_corpus() -> None:
    keras_files = {path.name for path in _tracked_under(KERAS_DIR) if path.suffix.lower() in {".h5", ".hdf5", ".keras"}}

    assert keras_files == EXPECTED_KERAS_BINARY_FIXTURES


def test_jinja2_corpus_uses_routed_subdirectories() -> None:
    root_level_files = sorted(
        path.relative_to(REPO_ROOT).as_posix() for path in _tracked_under(JINJA2_DIR) if path.parent == JINJA2_DIR
    )

    assert root_level_files == []


def test_pickle_bypass_poc_generators_are_not_committed() -> None:
    bypass_poc_files = sorted(path.relative_to(REPO_ROOT).as_posix() for path in _tracked_under(BYPASS_POC_DIR))

    assert bypass_poc_files == []


def test_large_committed_assets_are_allowlisted() -> None:
    large_assets = {
        path.relative_to(REPO_ROOT).as_posix(): path.stat().st_size
        for path in _tracked_asset_paths()
        if path.stat().st_size > LARGE_ASSET_BYTES
    }

    assert large_assets.keys() == LARGE_ASSET_ALLOWLIST.keys()
