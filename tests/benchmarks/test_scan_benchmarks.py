from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache.cache_manager import reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.detectors.secrets import SecretsDetector
from tests.helpers.file_creators import (
    create_malicious_pickle,
    create_mock_manifest,
    create_mock_pytorch_zip,
    create_safe_pickle,
)

pytest.importorskip("pytest_benchmark")

pytestmark = pytest.mark.performance

SCAN_ROUNDS = 3
WARMUP_ROUNDS = 1


def _build_large_pickle_payload(seed: int) -> dict[str, Any]:
    layers = []
    for layer_index in range(64):
        weights = [((seed + layer_index + offset) % 997) / 997.0 for offset in range(256)]
        layers.append(
            {
                "name": f"layer_{seed}_{layer_index}",
                "weights": weights,
                "bias": weights[:32],
                "shape": [64, 4],
                "activation": "relu" if layer_index % 2 == 0 else "gelu",
                "trainable": layer_index % 3 != 0,
            }
        )

    return {
        "model": {
            "name": f"benchmark-model-{seed}",
            "layers": layers,
            "tokenizer": {f"token_{seed}_{index}": index for index in range(1024)},
            "metadata": {
                "framework": "pytorch",
                "version": "2.6.0",
                "tags": ["benchmark", "security", "release"],
            },
        }
    }


def _create_release_candidate_repository(root: Path) -> Path:
    root.mkdir()
    create_safe_pickle(root / "model.pkl", data=_build_large_pickle_payload(0))
    create_mock_pytorch_zip(root / "weights.pt", data=_build_large_pickle_payload(1))
    create_mock_manifest(
        root / "manifest.json",
        content={
            "model_name": "release-candidate",
            "version": "2026.05.03",
            "files": ["model.pkl", "weights.pt", "tokenizer.json"],
        },
    )
    (root / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    (root / "README.md").write_text("# Release candidate\n", encoding="utf-8")
    (root / "tokenizer.json").write_text('{"vocab_size": 1024}\n', encoding="utf-8")

    adapters = root / "adapters"
    adapters.mkdir()
    create_safe_pickle(adapters / "adapter.pkl", data=_build_large_pickle_payload(2))
    create_mock_manifest(adapters / "adapter_manifest.json")

    metadata = root / "metadata"
    metadata.mkdir()
    for index in range(24):
        (metadata / f"run_{index}.json").write_text(
            f'{{"step": {index}, "notes": "release metadata"}}\n',
            encoding="utf-8",
        )

    return root


def _create_duplicate_registry_snapshot(root: Path) -> Path:
    root.mkdir()
    canonical = create_safe_pickle(root / "canonical.pkl", data=_build_large_pickle_payload(10))

    for version_index in range(4):
        version_dir = root / f"v{version_index}"
        version_dir.mkdir()
        shutil.copy2(canonical, version_dir / "model.pkl")
        create_mock_manifest(
            version_dir / "manifest.json",
            content={
                "model_name": "registry-model",
                "version": f"1.0.{version_index}",
                "files": ["model.pkl"],
            },
        )
        (version_dir / "README.md").write_text(
            f"# Registry model v{version_index}\n",
            encoding="utf-8",
        )

    return root


def _create_suspicious_pickle_intake(root: Path) -> Path:
    root.mkdir()
    create_safe_pickle(root / "known_good.pkl", data=_build_large_pickle_payload(20))
    create_malicious_pickle(root / "direct_payload.pkl")

    asset_root = Path(__file__).resolve().parents[1] / "assets" / "samples" / "pickles"
    shutil.copy2(asset_root / "malicious_model_realistic.pkl", root / "uploaded_model.pkl")
    shutil.copy2(asset_root / "nested_pickle_base64.pkl", root / "encoded_payload.pkl")

    return root


def _path_total_bytes(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def _benchmark_context(
    path: Path,
    *,
    workload: str,
    cache_state: str,
) -> dict[str, int | str]:
    return {
        "workload": workload,
        "path": path.name,
        "bytes": _path_total_bytes(path),
        "files": sum(1 for item in path.rglob("*") if item.is_file()) if path.is_dir() else 1,
        "cache_state": cache_state,
    }


@pytest.fixture(scope="session")
def benchmark_inputs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    root = tmp_path_factory.mktemp("scan-benchmarks")

    single_checkpoint = create_safe_pickle(
        root / "single_checkpoint.pkl",
        data=_build_large_pickle_payload(99),
    )
    release_candidate = _create_release_candidate_repository(root / "release-candidate")
    registry_snapshot = _create_duplicate_registry_snapshot(root / "registry-snapshot")
    suspicious_intake = _create_suspicious_pickle_intake(root / "suspicious-intake")

    return {
        "single_checkpoint": single_checkpoint,
        "release_candidate": release_candidate,
        "registry_snapshot": registry_snapshot,
        "suspicious_intake": suspicious_intake,
    }


def _benchmark_scan(
    benchmark: Any,
    path: Path,
    *,
    workload: str,
    cache_enabled: bool = False,
    cache_dir: Path | None = None,
) -> Any:
    cache_state = "warm" if cache_enabled else "disabled"
    benchmark.extra_info.update(
        _benchmark_context(
            path,
            workload=workload,
            cache_state=cache_state,
        )
    )
    scan_kwargs: dict[str, Any] = {"cache_enabled": cache_enabled}
    if cache_dir is not None:
        scan_kwargs["cache_dir"] = str(cache_dir)
        scan_kwargs["min_cache_file_size"] = 0

    return benchmark.pedantic(
        lambda: scan_model_directory_or_file(str(path), **scan_kwargs),
        iterations=1,
        rounds=SCAN_ROUNDS,
        warmup_rounds=WARMUP_ROUNDS,
    )


def test_scan_single_checkpoint_before_load(benchmark: Any, benchmark_inputs: dict[str, Path]) -> None:
    result = _benchmark_scan(
        benchmark,
        benchmark_inputs["single_checkpoint"],
        workload="single-checkpoint-preflight",
    )

    assert result.success is True
    assert result.files_scanned == 1


def test_scan_release_candidate_repository(benchmark: Any, benchmark_inputs: dict[str, Path]) -> None:
    result = _benchmark_scan(
        benchmark,
        benchmark_inputs["release_candidate"],
        workload="mixed-model-repository",
    )

    assert result.success is True
    assert result.files_scanned >= 3


def test_scan_duplicate_registry_snapshot(benchmark: Any, benchmark_inputs: dict[str, Path]) -> None:
    result = _benchmark_scan(
        benchmark,
        benchmark_inputs["registry_snapshot"],
        workload="duplicate-heavy-registry",
    )

    assert result.success is True
    assert result.files_scanned >= 4


def test_scan_suspicious_pickle_intake(benchmark: Any, benchmark_inputs: dict[str, Path]) -> None:
    result = _benchmark_scan(
        benchmark,
        benchmark_inputs["suspicious_intake"],
        workload="suspicious-pickle-intake",
    )

    assert result.files_scanned >= 4
    assert result.issues
    assert determine_exit_code(result) == 1


def test_scan_warm_cached_repository_rescan(
    benchmark: Any,
    benchmark_inputs: dict[str, Path],
    tmp_path: Path,
) -> None:
    path = benchmark_inputs["release_candidate"]
    cache_dir = tmp_path / "cache"
    reset_cache_manager()
    try:
        primed = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        assert primed.success is True

        result = _benchmark_scan(
            benchmark,
            path,
            workload="warm-cache-rescan",
            cache_enabled=True,
            cache_dir=cache_dir,
        )
    finally:
        reset_cache_manager()

    assert result.success is True
    assert result.files_scanned >= 3


def test_rejected_basic_auth_candidates_scan_linearly(benchmark: Any) -> None:
    detector = SecretsDetector()
    text = " ".join(["Basic dXNlcjpwYXNz"] * 20_000)
    benchmark.extra_info.update(
        {
            "workload": "rejected-basic-auth-candidates",
            "bytes": len(text),
            "files": 1,
            "cache_state": "disabled",
        }
    )

    findings = benchmark.pedantic(
        lambda: detector.scan_text(text, context="README.md"),
        iterations=1,
        rounds=SCAN_ROUNDS,
        warmup_rounds=WARMUP_ROUNDS,
    )

    assert not [finding for finding in findings if finding.get("secret_type") == "Basic Auth Credentials"]
