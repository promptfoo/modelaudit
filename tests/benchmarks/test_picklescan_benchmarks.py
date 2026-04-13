from __future__ import annotations

import base64
import binascii
import io
import os
import pickle
from typing import Any

import pytest
from modelaudit_picklescan import PickleScanner, SafetyVerdict, ScanOptions, ScanStatus, scan_bytes

pytest.importorskip("pytest_benchmark")

pytestmark = pytest.mark.performance

SCAN_ROUNDS = 8
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
    stack_global = b"\x80\x04\x8c\x05posix\x94\x8c\x06system\x94\x93."
    multi_stream_padded = safe_small + (b"\x00" * 4096) + malicious_reduce
    opcode_budget_tail = b"\x80\x04cos\nsystem\n."
    long_benign_string = pickle.dumps({"text": "A" * (1024 * 1024)}, protocol=4)
    hidden_suspicious_string = pickle.dumps(
        {"text": ("A" * 4096) + "os.system('id')" + ("B" * 4096)},
        protocol=4,
    )

    return {
        "safe_small": safe_small,
        "safe_large": safe_large,
        "malicious_reduce": malicious_reduce,
        "stack_global": stack_global,
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
        "opcode_budget_tail": opcode_budget_tail,
        "long_benign_string": long_benign_string,
        "hidden_suspicious_string": hidden_suspicious_string,
    }


def _benchmark_scan_bytes(
    benchmark: Any,
    *,
    name: str,
    payload: bytes,
    options: ScanOptions | None = None,
) -> Any:
    benchmark.extra_info.update(
        {
            "path": name,
            "bytes": len(payload),
            "files": 1,
            "engine": "rust",
        }
    )
    return benchmark.pedantic(
        lambda: scan_bytes(payload, source=f"{name}.pkl", options=options),
        iterations=1,
        rounds=SCAN_ROUNDS,
        warmup_rounds=WARMUP_ROUNDS,
    )


@pytest.mark.parametrize("payload_name", ["safe_small", "safe_large", "long_benign_string"])
def test_picklescan_safe_payloads(
    benchmark: Any,
    standalone_pickle_payloads: dict[str, bytes],
    payload_name: str,
) -> None:
    report = _benchmark_scan_bytes(
        benchmark,
        name=payload_name,
        payload=standalone_pickle_payloads[payload_name],
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


@pytest.mark.parametrize("payload_name", ["malicious_reduce", "stack_global"])
def test_picklescan_dangerous_global_payloads(
    benchmark: Any,
    standalone_pickle_payloads: dict[str, bytes],
    payload_name: str,
) -> None:
    report = _benchmark_scan_bytes(
        benchmark,
        name=payload_name,
        payload=standalone_pickle_payloads[payload_name],
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert report.findings


@pytest.mark.parametrize("payload_name", ["nested_raw", "nested_base64", "nested_hex"])
def test_picklescan_nested_payloads(
    benchmark: Any,
    standalone_pickle_payloads: dict[str, bytes],
    payload_name: str,
) -> None:
    report = _benchmark_scan_bytes(
        benchmark,
        name=payload_name,
        payload=standalone_pickle_payloads[payload_name],
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert report.findings


def test_picklescan_multi_stream_padded_payload(
    benchmark: Any,
    standalone_pickle_payloads: dict[str, bytes],
) -> None:
    report = _benchmark_scan_bytes(
        benchmark,
        name="multi_stream_padded",
        payload=standalone_pickle_payloads["multi_stream_padded"],
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert report.findings
    assert any(notice.code == "follow_on_stream_detected" for notice in report.notices)


def test_picklescan_opcode_budget_tail_payload(
    benchmark: Any,
    standalone_pickle_payloads: dict[str, bytes],
) -> None:
    report = _benchmark_scan_bytes(
        benchmark,
        name="opcode_budget_tail",
        payload=standalone_pickle_payloads["opcode_budget_tail"],
        options=ScanOptions(max_opcodes=1),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert report.findings


def test_picklescan_hidden_suspicious_string_budget(
    benchmark: Any,
    standalone_pickle_payloads: dict[str, bytes],
) -> None:
    report = _benchmark_scan_bytes(
        benchmark,
        name="hidden_suspicious_string",
        payload=standalone_pickle_payloads["hidden_suspicious_string"],
        options=ScanOptions(max_string_literal_scan_chars=8),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(finding.rule_code == "SUSPICIOUS_STRING" for finding in report.findings)
    assert any(notice.code == "literal_scan_truncated" for notice in report.notices)


def test_picklescan_chunked_stream(
    benchmark: Any,
    standalone_pickle_payloads: dict[str, bytes],
) -> None:
    payload = standalone_pickle_payloads["safe_large"]
    scanner = PickleScanner()
    benchmark.extra_info.update(
        {
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
