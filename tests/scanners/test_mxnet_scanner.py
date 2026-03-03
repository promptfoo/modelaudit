import base64
import json
import struct
from pathlib import Path

from modelaudit.scanners import get_scanner_for_file
from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.mxnet_scanner import MXNetScanner


def _write_symbol_file(path: Path, custom_node: dict | None = None, metadata: str = "benign metadata") -> None:
    nodes = [
        {"op": "null", "name": "data", "inputs": []},
        {
            "op": "Convolution",
            "name": "conv1",
            "attrs": {"kernel": "(3,3)", "num_filter": "8"},
            "inputs": [[0, 0, 0]],
        },
    ]
    heads = [[1, 0, 0]]

    if custom_node:
        nodes.append(custom_node)
        heads = [[2, 0, 0]]

    symbol_graph = {
        "nodes": nodes,
        "arg_nodes": [0],
        "heads": heads,
        "attrs": {"metadata": metadata},
    }
    path.write_text(json.dumps(symbol_graph), encoding="utf-8")


def _write_params_file(path: Path, values: tuple[float, ...] | None = None) -> None:
    tensor_values = values or (0.0, 1.0, -2.5, 3.14, 8.0, -0.125)
    path.write_bytes(struct.pack(f"<{len(tensor_values)}f", *tensor_values))


def test_mxnet_scanner_can_handle_symbol_and_params(tmp_path: Path) -> None:
    symbol_path = tmp_path / "model-symbol.json"
    params_path = tmp_path / "model-0000.params"
    _write_symbol_file(symbol_path)
    _write_params_file(params_path)

    assert MXNetScanner.can_handle(str(symbol_path))
    assert MXNetScanner.can_handle(str(params_path))


def test_mxnet_scanner_rejects_non_mxnet_files(tmp_path: Path) -> None:
    fake_symbol = tmp_path / "fake-symbol.json"
    fake_symbol.write_text('{"not": "mxnet"}', encoding="utf-8")
    bad_params_name = tmp_path / "weights.params"
    bad_params_name.write_bytes(b"raw bytes")

    assert not MXNetScanner.can_handle(str(fake_symbol))
    assert not MXNetScanner.can_handle(str(bad_params_name))


def test_mxnet_symbol_scan_with_valid_pair_has_no_security_findings(tmp_path: Path) -> None:
    symbol_path = tmp_path / "resnet-symbol.json"
    params_path = tmp_path / "resnet-0000.params"
    _write_symbol_file(symbol_path)
    _write_params_file(params_path)

    result = MXNetScanner().scan(str(symbol_path))

    assert result.success
    assert result.metadata.get("has_params_companion") is True
    high_severity = [
        issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert high_severity == []


def test_mxnet_scanner_reports_missing_companion_files(tmp_path: Path) -> None:
    symbol_path = tmp_path / "bert-symbol.json"
    params_path = tmp_path / "bert-0000.params"
    _write_symbol_file(symbol_path)

    symbol_result = MXNetScanner().scan(str(symbol_path))
    assert symbol_result.metadata.get("has_params_companion") is False
    assert any("No matching MXNet params companion file found" in issue.message for issue in symbol_result.issues)

    symbol_path.unlink()
    _write_params_file(params_path)
    params_result = MXNetScanner().scan(str(params_path))
    assert params_result.metadata.get("has_symbol_companion") is False
    assert any("No matching MXNet symbol companion file found" in issue.message for issue in params_result.issues)


def test_mxnet_scanner_detects_suspicious_custom_operator_reference(tmp_path: Path) -> None:
    symbol_path = tmp_path / "unsafe-symbol.json"
    params_path = tmp_path / "unsafe-0000.params"
    _write_symbol_file(
        symbol_path,
        custom_node={
            "op": "Custom",
            "name": "custom_loader",
            "attrs": {
                "library": "../../tmp/libevil.so",
                "op_type": "unsafe_loader",
            },
            "inputs": [[1, 0, 0]],
        },
    )
    _write_params_file(params_path)

    result = MXNetScanner().scan(str(symbol_path))

    custom_issues = [issue for issue in result.issues if issue.details.get("attribute") == "library"]
    assert len(custom_issues) == 1
    assert custom_issues[0].severity == IssueSeverity.WARNING
    assert "node: custom_loader" in (custom_issues[0].location or "")


def test_mxnet_scanner_detects_encoded_metadata_payload(tmp_path: Path) -> None:
    symbol_path = tmp_path / "payload-symbol.json"
    params_path = tmp_path / "payload-0000.params"

    encoded_payload = base64.b64encode(b"__import__('os').system('id')").decode("ascii")
    _write_symbol_file(symbol_path, metadata=encoded_payload)
    _write_params_file(params_path)

    result = MXNetScanner().scan(str(symbol_path))

    assert any("Encoded Metadata Payload" in check.name for check in result.checks)


def test_mxnet_scanner_handles_corrupt_params_file(tmp_path: Path) -> None:
    params_path = tmp_path / "corrupt-0000.params"
    params_path.write_bytes(b"")

    result = MXNetScanner().scan(str(params_path))

    assert not result.success
    assert any("MXNet params blob is empty" in issue.message for issue in result.issues)


def test_mxnet_params_numeric_blob_does_not_trigger_false_positives(tmp_path: Path) -> None:
    symbol_path = tmp_path / "clean-symbol.json"
    params_path = tmp_path / "clean-0000.params"
    _write_symbol_file(symbol_path)
    _write_params_file(params_path, values=tuple(float(i) for i in range(256)))

    result = MXNetScanner().scan(str(params_path))

    high_severity = [
        issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert high_severity == []


def test_mxnet_scanner_routing_uses_mxnet_scanner_for_pair_files(tmp_path: Path) -> None:
    symbol_path = tmp_path / "paired-symbol.json"
    params_path = tmp_path / "paired-0000.params"
    _write_symbol_file(symbol_path)
    _write_params_file(params_path)

    symbol_scanner = get_scanner_for_file(str(symbol_path))
    params_scanner = get_scanner_for_file(str(params_path))

    assert symbol_scanner is not None
    assert params_scanner is not None
    assert symbol_scanner.name == "mxnet"
    assert params_scanner.name == "mxnet"
