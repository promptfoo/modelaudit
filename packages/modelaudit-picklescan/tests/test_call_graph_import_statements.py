"""Focused call-graph regressions for function-body import statements."""

from __future__ import annotations

import os
import subprocess
import sys
from importlib.util import find_spec
from pathlib import Path

import pytest

from modelaudit_picklescan import PickleReport, SafetyVerdict, Severity, scan_bytes
from modelaudit_picklescan.api import _RUST_EXTENSION_MODULE
from modelaudit_picklescan.call_graph import _calls_for_function, _find_sink_path

pytestmark = pytest.mark.skipif(
    find_spec(_RUST_EXTENSION_MODULE) is None,
    reason="Rust picklescan extension is not built",
)


def _short_binunicode(data: bytes) -> bytes:
    if len(data) > 0xFF:
        raise ValueError("SHORT_BINUNICODE helper accepts at most 255 bytes")
    return b"\x8c" + bytes([len(data)]) + data


def _global_operand(module: str, name: str) -> bytes:
    return _short_binunicode(module.encode()) + _short_binunicode(name.encode()) + b"\x93"


def _global_call_payload(module: str, name: str) -> bytes:
    return b"".join([b"\x80\x04", _global_operand(module, name), b")R."])


def _has_critical_call_graph_finding(report: PickleReport, module: str, name: str, sink: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.rule_code == "DANGEROUS_CALL_GRAPH"
        and finding.details.get("module") == module
        and finding.details.get("name") == name
        and finding.details.get("sink") == sink
        for finding in report.findings
    )


@pytest.mark.parametrize("helper_name", ["execsitecustomize", "execusercustomize"])
def test_call_graph_models_site_customization_import_statements(helper_name: str) -> None:
    function_name = f"site.{helper_name}"

    assert "builtins.__import__" in (_calls_for_function(function_name) or ())
    assert _find_sink_path(function_name) == (function_name, "builtins.__import__")


def test_call_graph_models_direct_shadowable_function_body_imports() -> None:
    calls = _calls_for_function("base64.main") or ()

    assert "builtins.__import__" in calls
    assert _find_sink_path("base64.main") == ("base64.main", "builtins.__import__")


def test_call_graph_ignores_imports_inside_nested_functions_until_called() -> None:
    calls = _calls_for_function("site.enablerlcompleter") or ()

    assert "builtins.__import__" not in calls
    assert _find_sink_path("site.enablerlcompleter") is None


@pytest.mark.parametrize(
    ("helper_name", "module_name", "marker_content"),
    [
        ("execsitecustomize", "sitecustomize", "sitecustomize-owned"),
        ("execusercustomize", "usercustomize", "usercustomize-owned"),
    ],
)
def test_scan_bytes_blocks_site_customization_import_execution_rce(
    tmp_path: Path,
    helper_name: str,
    module_name: str,
    marker_content: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / f"{module_name}_marker"
    (module_dir / f"{module_name}.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text({marker_content!r})\n",
        encoding="utf-8",
    )
    payload = _global_call_payload("site", helper_name)

    report = scan_bytes(payload, source=f"site-{helper_name}-import-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, "site", helper_name, "builtins.__import__")

    assert not marker.exists()
    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])
module_name = sys.argv[4]
marker_content = sys.argv[5]

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop(module_name, None)
result = pickle.loads(payload)
if result is not None:
    raise SystemExit(f"expected None result, got {result!r}")
if not marker.exists():
    raise SystemExit("marker was not written")
if marker.read_text() != marker_content:
    raise SystemExit("marker content mismatch")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex(), module_name, marker_content],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == marker_content


def test_scan_bytes_blocks_base64_main_import_side_effect_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "base64_getopt_marker"
    marker_content = "getopt-owned"
    (module_dir / "getopt.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "class error(Exception):\n"
        "    pass\n"
        "def getopt(args, shortopts):\n"
        "    return [('-h', '')], []\n",
        encoding="utf-8",
    )
    payload = _global_call_payload("base64", "main")

    report = scan_bytes(payload, source="base64-main-import-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, "base64", "main", "builtins.__import__")

    assert not marker.exists()
    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])
marker_content = sys.argv[4]

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("getopt", None)
result = pickle.loads(payload)
if result is not None:
    raise SystemExit(f"expected None result, got {result!r}")
if not marker.exists():
    raise SystemExit("marker was not written")
if marker.read_text() != marker_content:
    raise SystemExit("marker content mismatch")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex(), marker_content],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == marker_content
