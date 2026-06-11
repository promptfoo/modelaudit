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
SENTENCEPIECE_DIR = ASSETS_DIR / "samples" / "sentencepiece"

EXPECTED_SAFETENSORS_FIXTURES = {
    "tests/assets/samples/safetensors/malicious_import.safetensors",
    "tests/assets/samples/safetensors/safe_model.safetensors",
}
MAX_COMMITTED_SAFETENSORS_BYTES = 4 * 1024

EXPECTED_KERAS_BINARY_FIXTURES = {
    "tests/assets/samples/keras/custom_layer_attack.h5",
    "tests/assets/samples/keras/loss_injection.h5",
    "tests/assets/samples/keras/malicious_lambda.h5",
    "tests/assets/samples/keras/metric_injection.h5",
    "tests/assets/samples/keras/safe_model.h5",
}

EXPECTED_JINJA2_FIXTURES = {
    "tests/assets/samples/jinja2/benign/chatml_format.json",
    "tests/assets/samples/jinja2/benign/complex_legitimate.json",
    "tests/assets/samples/jinja2/benign/conditional_system.json",
    "tests/assets/samples/jinja2/benign/huggingface_llama.json",
    "tests/assets/samples/jinja2/benign/simple_roles.json",
    "tests/assets/samples/jinja2/benign/special_tokens.json",
    "tests/assets/samples/jinja2/edge_cases/empty_template.json",
    "tests/assets/samples/jinja2/edge_cases/malformed_template.json",
    "tests/assets/samples/jinja2/edge_cases/multiple_templates.json",
    "tests/assets/samples/jinja2/edge_cases/no_template.json",
    "tests/assets/samples/jinja2/edge_cases/oversized_template.json",
    "tests/assets/samples/jinja2/malicious/attr_bypass.json",
    "tests/assets/samples/jinja2/malicious/combined_attack.json",
    "tests/assets/samples/jinja2/malicious/config_exploit.json",
    "tests/assets/samples/jinja2/malicious/cve_2024_34359_original.json",
    "tests/assets/samples/jinja2/malicious/direct_eval.json",
    "tests/assets/samples/jinja2/malicious/env_extraction.json",
    "tests/assets/samples/jinja2/malicious/file_access.json",
    "tests/assets/samples/jinja2/malicious/hex_bypass.json",
    "tests/assets/samples/jinja2/malicious/loop_discovery.json",
    "tests/assets/samples/jinja2/malicious/network_exfil.json",
    "tests/assets/samples/jinja2/malicious/request_exploit.json",
    "tests/assets/samples/jinja2/malicious/subprocess_injection.json",
    "tests/assets/samples/jinja2/obfuscated/base64_payload.json",
    "tests/assets/samples/jinja2/obfuscated/char_construction.json",
    "tests/assets/samples/jinja2/obfuscated/format_bypass.json",
    "tests/assets/samples/jinja2/obfuscated/getattr_bypass.json",
    "tests/assets/samples/jinja2/standalone/benign_chat.j2",
    "tests/assets/samples/jinja2/standalone/malicious_subprocess.template",
    "tests/assets/samples/jinja2/standalone/malicious_standalone.jinja",
    "tests/assets/samples/jinja2/standalone/suspicious_benign.template",
    "tests/assets/samples/jinja2/yaml/malicious_config.yaml",
    "tests/assets/samples/jinja2/yaml/model_config.yaml",
}

EXPECTED_SENTENCEPIECE_FIXTURES = {
    "tests/assets/samples/sentencepiece/custom_unknown_disabled_specials.model",
    "tests/assets/samples/sentencepiece/custom_unknown_disabled_specials_byte_fallback.model",
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


def _repo_relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def _is_bypass_poc_generator(path: Path) -> bool:
    relative_path = path.relative_to(REPO_ROOT)
    parts = relative_path.parts
    if "bypass_pocs" in parts:
        return True
    return path.suffix == ".py" and path.name.startswith("gen_bypass")


def test_committed_safetensors_corpus_stays_small_and_intentional() -> None:
    safetensors_files = {
        _repo_relative(path) for path in _tracked_under(SAFETENSORS_DIR) if path.suffix == ".safetensors"
    }

    assert safetensors_files == EXPECTED_SAFETENSORS_FIXTURES
    oversized = {
        _repo_relative(path): path.stat().st_size
        for path in _tracked_under(SAFETENSORS_DIR)
        if path.suffix == ".safetensors"
        if path.stat().st_size > MAX_COMMITTED_SAFETENSORS_BYTES
    }
    assert oversized == {}


def test_committed_keras_binary_fixtures_match_exercised_corpus() -> None:
    keras_files = {
        _repo_relative(path) for path in _tracked_under(KERAS_DIR) if path.suffix.lower() in {".h5", ".hdf5", ".keras"}
    }

    assert keras_files == EXPECTED_KERAS_BINARY_FIXTURES


def test_jinja2_corpus_matches_routed_inventory() -> None:
    jinja2_files = {_repo_relative(path) for path in _tracked_under(JINJA2_DIR)}

    assert jinja2_files == EXPECTED_JINJA2_FIXTURES


def test_sentencepiece_corpus_matches_routed_inventory() -> None:
    sentencepiece_files = {_repo_relative(path) for path in _tracked_under(SENTENCEPIECE_DIR)}

    assert sentencepiece_files == EXPECTED_SENTENCEPIECE_FIXTURES


def test_pickle_bypass_poc_generators_are_not_committed() -> None:
    bypass_poc_files = sorted(_repo_relative(path) for path in _tracked_asset_paths() if _is_bypass_poc_generator(path))

    assert bypass_poc_files == []


def test_pickle_bypass_poc_guard_matches_removed_artifact_patterns() -> None:
    assert _is_bypass_poc_generator(REPO_ROOT / "tests/assets/pickles/bypass_pocs/gen_bypass_v4.py")
    assert _is_bypass_poc_generator(REPO_ROOT / "tests/assets/exploits/gen_bypass_v5.py")
    assert not _is_bypass_poc_generator(REPO_ROOT / "tests/assets/generators/generate_evil_pickle.py")


def test_large_committed_assets_are_allowlisted() -> None:
    large_assets = {
        _repo_relative(path): path.stat().st_size
        for path in _tracked_asset_paths()
        if path.stat().st_size > LARGE_ASSET_BYTES
    }

    assert large_assets.keys() == LARGE_ASSET_ALLOWLIST.keys()
