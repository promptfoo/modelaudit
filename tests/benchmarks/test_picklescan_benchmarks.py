from __future__ import annotations

import base64
import binascii
import io
import os
import pickle
from typing import Any

import pytest
from modelaudit_picklescan import PickleScanner, SafetyVerdict, ScanStatus, scan_bytes

pytest.importorskip("pytest_benchmark")

pytestmark = pytest.mark.performance

SCAN_ROUNDS = 6
WARMUP_ROUNDS = 2


class MaliciousReduce:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (os.system, ("echo benchmark",))


class ChunkedReadStream(io.BytesIO):
    def __init__(self, payload: bytes, *, max_read_size: int) -> None:
        super().__init__(payload)
        self.max_read_size = max_read_size

    def read(self, size: int | None = -1) -> bytes:
        if size is None or size < 0:
            size = self.max_read_size
        return super().read(min(size, self.max_read_size))


def _build_large_safe_model() -> dict[str, Any]:
    layers = []
    for layer_index in range(96):
        weights = [((layer_index + offset) % 997) / 997.0 for offset in range(256)]
        layers.append(
            {
                "name": f"layer_{layer_index}",
                "weights": weights,
                "bias": weights[:32],
                "shape": [64, 4],
                "activation": "relu" if layer_index % 2 == 0 else "gelu",
                "trainable": layer_index % 3 != 0,
            }
        )
    return {
        "model": {
            "name": "standalone-picklescan-benchmark",
            "layers": layers,
            "tokenizer": {f"token_{index}": index for index in range(2048)},
        }
    }


@pytest.fixture(scope="session")
def standalone_pickle_payloads() -> dict[str, bytes]:
    safe_small = pickle.dumps({"weights": [1, 2, 3], "metadata": {"format": "pickle"}}, protocol=4)
    safe_large = pickle.dumps(_build_large_safe_model(), protocol=4)
    malicious_reduce = pickle.dumps(MaliciousReduce(), protocol=4)
    nested_payload = malicious_reduce
    multi_stream_padded = safe_small + (b"\x00" * 4096) + malicious_reduce

    return {
        "safe_large": safe_large,
        "malicious_reduce": malicious_reduce,
        "nested_raw": pickle.dumps({"outer": nested_payload}, protocol=4),
        "nested_base64": pickle.dumps(
            {"outer": base64.b64encode(nested_payload).decode("ascii")},
            protocol=4,
        ),
        "nested_hex": pickle.dumps(
            {"outer": binascii.hexlify(nested_payload).decode("ascii")},
            protocol=4,
        ),
        "multi_stream_padded": multi_stream_padded,
    }


def _benchmark_scan_bytes(
    benchmark: Any,
    *,
    workload: str,
    name: str,
    payload: bytes,
) -> Any:
    benchmark.extra_info.update(
        {
            "workload": workload,
            "path": name,
            "bytes": len(payload),
            "files": 1,
            "engine": "rust",
        }
    )
    return benchmark.pedantic(
        lambda: scan_bytes(payload, source=f"{name}.pkl"),
        iterations=1,
        rounds=SCAN_ROUNDS,
        warmup_rounds=WARMUP_ROUNDS,
    )


def test_picklescan_clean_training_checkpoint(
    benchmark: Any,
    standalone_pickle_payloads: dict[str, bytes],
) -> None:
    report = _benchmark_scan_bytes(
        benchmark,
        workload="clean-training-checkpoint",
        name="safe_large",
        payload=standalone_pickle_payloads["safe_large"],
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


def test_picklescan_direct_malicious_upload(
    benchmark: Any,
    standalone_pickle_payloads: dict[str, bytes],
) -> None:
    report = _benchmark_scan_bytes(
        benchmark,
        workload="direct-malicious-upload",
        name="malicious_reduce",
        payload=standalone_pickle_payloads["malicious_reduce"],
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert report.findings


@pytest.mark.parametrize("payload_name", ["nested_raw", "nested_base64", "nested_hex"])
def test_picklescan_nested_payload_review(
    benchmark: Any,
    standalone_pickle_payloads: dict[str, bytes],
    payload_name: str,
) -> None:
    report = _benchmark_scan_bytes(
        benchmark,
        workload="nested-payload-review",
        name=payload_name,
        payload=standalone_pickle_payloads[payload_name],
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert report.findings


def test_picklescan_padded_multi_stream_upload(
    benchmark: Any,
    standalone_pickle_payloads: dict[str, bytes],
) -> None:
    report = _benchmark_scan_bytes(
        benchmark,
        workload="padded-multi-stream-upload",
        name="multi_stream_padded",
        payload=standalone_pickle_payloads["multi_stream_padded"],
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert report.findings
    assert any(notice.code == "follow_on_stream_detected" for notice in report.notices)


def test_picklescan_chunked_upload_stream(
    benchmark: Any,
    standalone_pickle_payloads: dict[str, bytes],
) -> None:
    payload = standalone_pickle_payloads["safe_large"]
    scanner = PickleScanner()
    benchmark.extra_info.update(
        {
            "workload": "chunked-upload-stream",
            "path": "chunked_stream",
            "bytes": len(payload),
            "files": 1,
            "engine": "rust",
        }
    )

    report = benchmark.pedantic(
        lambda: scanner.scan_stream(
            ChunkedReadStream(payload, max_read_size=64),
            source="chunked-stream.pkl",
            size=len(payload),
        ),
        iterations=1,
        rounds=SCAN_ROUNDS,
        warmup_rounds=WARMUP_ROUNDS,
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.coverage.bytes_scanned == len(payload)
