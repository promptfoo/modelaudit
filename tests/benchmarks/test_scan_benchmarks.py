from __future__ import annotations

import pickle
import shutil
import zipfile
from pathlib import Path
from typing import Any

import pytest

from modelaudit.core import scan_model_directory_or_file
from modelaudit.utils.file.detection import detect_file_format, validate_file_type
from tests.helpers.file_creators import create_mock_manifest, create_safe_pickle

pytest.importorskip("pytest_benchmark")

pytestmark = pytest.mark.performance

DETECTION_ROUNDS = 25
SCAN_ROUNDS = 5
WARMUP_ROUNDS = 1


def _build_large_pickle_payload(seed: int) -> dict[str, Any]:
    layers = []
    for layer_index in range(24):
        weights = [((seed + layer_index + offset) % 251) / 251.0 for offset in range(192)]
        layers.append(
            {
                "name": f"layer_{seed}_{layer_index}",
                "weights": weights,
                "bias": weights[:16],
                "shape": [48, 4],
                "activation": "relu" if layer_index % 2 == 0 else "gelu",
                "trainable": True,
            },
        )

    tokenizer = {f"token_{seed}_{index}": index for index in range(256)}
    return {
        "model": {
            "name": f"benchmark-model-{seed}",
            "layers": layers,
            "tokenizer": tokenizer,
            "metadata": {
                "framework": "pytorch",
                "version": "2.6.0",
                "tags": ["benchmark", "security", "scan"],
            },
        },
    }


def _create_pytorch_benchmark_zip(path: Path) -> Path:
    state_dict = {
        "state_dict": {
            f"encoder.layer.{index}.weight": [float((index + offset) % 17) for offset in range(128)]
            for index in range(16)
        },
        "metadata": {"version": "2.6.0", "producer": "benchmark"},
    }

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("version", "3")
        archive.writestr("byteorder", "little")
        archive.writestr("data.pkl", pickle.dumps(state_dict, protocol=4))
        archive.writestr("constants.pkl", pickle.dumps({"constants": [1, 2, 3]}, protocol=4))

        for index in range(24):
            archive.writestr(f"data/{index}", bytes([index % 251]) * (64 * 1024))

    return path


def _create_mixed_corpus(root: Path) -> Path:
    root.mkdir()
    create_safe_pickle(root / "safe_root.pkl", data=_build_large_pickle_payload(0))
    create_safe_pickle(root / "safe_extra.pkl", data=_build_large_pickle_payload(1))
    _create_pytorch_benchmark_zip(root / "weights.pt")
    create_mock_manifest(root / "manifest.json")

    nested = root / "nested"
    nested.mkdir()
    create_safe_pickle(nested / "nested_safe.pkl", data=_build_large_pickle_payload(2))
    create_mock_manifest(nested / "nested_manifest.json")

    notes_dir = root / "notes"
    notes_dir.mkdir()
    for index in range(48):
        (notes_dir / f"note_{index}.txt").write_text(f"benchmark note {index}\n", encoding="utf-8")

    return root


def _create_duplicate_corpus(root: Path) -> Path:
    root.mkdir()
    canonical = create_safe_pickle(root / "canonical.pkl", data=_build_large_pickle_payload(10))

    for group_index in range(4):
        shard_dir = root / f"group_{group_index}"
        shard_dir.mkdir()
        for duplicate_index in range(4):
            shutil.copy2(canonical, shard_dir / f"duplicate_{group_index}_{duplicate_index}.pkl")
        for note_index in range(16):
            (shard_dir / f"ignore_{note_index}.txt").write_text("skip me\n", encoding="utf-8")

    return root


@pytest.fixture(scope="session")
def benchmark_inputs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    root = tmp_path_factory.mktemp("scan-benchmarks")

    safe_pickle = create_safe_pickle(root / "safe_model.pkl", data=_build_large_pickle_payload(99))
    pytorch_zip = _create_pytorch_benchmark_zip(root / "state_dict.pt")
    mixed_directory = _create_mixed_corpus(root / "mixed-corpus")
    duplicate_directory = _create_duplicate_corpus(root / "duplicate-corpus")

    return {
        "safe_pickle": safe_pickle,
        "pytorch_zip": pytorch_zip,
        "mixed_directory": mixed_directory,
        "duplicate_directory": duplicate_directory,
    }


def _benchmark_scan(benchmark: Any, path: Path, *, rounds: int = SCAN_ROUNDS) -> Any:
    benchmark.extra_info.update(
        {
            "path": path.name,
            "bytes": path.stat().st_size if path.is_file() else 0,
            "files": sum(1 for item in path.rglob("*") if item.is_file()) if path.is_dir() else 1,
        },
    )
    return benchmark.pedantic(
        lambda: scan_model_directory_or_file(str(path)),
        iterations=1,
        rounds=rounds,
        warmup_rounds=WARMUP_ROUNDS,
    )


def test_detect_file_format_safe_pickle(benchmark: Any, benchmark_inputs: dict[str, Path]) -> None:
    path = benchmark_inputs["safe_pickle"]
    benchmark.extra_info.update({"path": path.name, "bytes": path.stat().st_size})

    detected_format = benchmark.pedantic(
        lambda: detect_file_format(str(path)),
        iterations=1,
        rounds=DETECTION_ROUNDS,
        warmup_rounds=WARMUP_ROUNDS,
    )

    assert detected_format == "pickle"


def test_validate_file_type_pytorch_zip(benchmark: Any, benchmark_inputs: dict[str, Path]) -> None:
    path = benchmark_inputs["pytorch_zip"]
    benchmark.extra_info.update({"path": path.name, "bytes": path.stat().st_size})

    is_valid = benchmark.pedantic(
        lambda: validate_file_type(str(path)),
        iterations=1,
        rounds=DETECTION_ROUNDS,
        warmup_rounds=WARMUP_ROUNDS,
    )

    assert is_valid is True


def test_scan_safe_pickle(benchmark: Any, benchmark_inputs: dict[str, Path]) -> None:
    result = _benchmark_scan(benchmark, benchmark_inputs["safe_pickle"])

    assert result.success is True
    assert result.files_scanned >= 1


def test_scan_pytorch_zip(benchmark: Any, benchmark_inputs: dict[str, Path]) -> None:
    result = _benchmark_scan(benchmark, benchmark_inputs["pytorch_zip"], rounds=3)

    assert result.success is True
    assert result.files_scanned >= 1


def test_scan_mixed_directory(benchmark: Any, benchmark_inputs: dict[str, Path]) -> None:
    result = _benchmark_scan(benchmark, benchmark_inputs["mixed_directory"], rounds=3)

    assert result.success is True
    assert result.files_scanned >= 1


def test_scan_duplicate_directory(benchmark: Any, benchmark_inputs: dict[str, Path]) -> None:
    result = _benchmark_scan(benchmark, benchmark_inputs["duplicate_directory"], rounds=3)

    assert result.success is True
    assert result.files_scanned >= 1
