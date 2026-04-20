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
from modelaudit_picklescan.call_graph import (
    _call_graph_entrypoints,
    _calls_for_function,
    _find_sink_path,
    find_dangerous_call_graphs,
)

pytestmark = pytest.mark.skipif(
    find_spec(_RUST_EXTENSION_MODULE) is None,
    reason="Rust picklescan extension is not built",
)


def _short_binunicode(data: bytes) -> bytes:
    if len(data) > 0xFF:
        raise ValueError("SHORT_BINUNICODE helper accepts at most 255 bytes")
    return b"\x8c" + bytes([len(data)]) + data


def _unicode_operand(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return _short_binunicode(data)
    return b"X" + len(data).to_bytes(4, "little") + data


def _global_operand(module: str, name: str) -> bytes:
    return _unicode_operand(module) + _unicode_operand(name) + b"\x93"


def _args_tuple(*arg_operands: bytes) -> bytes:
    if not arg_operands:
        return b")"
    if len(arg_operands) == 1:
        return arg_operands[0] + b"\x85"
    return b"(" + b"".join(arg_operands) + b"t"


def _global_call_payload(module: str, name: str, *arg_operands: bytes) -> bytes:
    return b"".join([b"\x80\x04", _global_operand(module, name), _args_tuple(*arg_operands), b"R."])


def _sitebuiltins_helper_instance_call_payload() -> bytes:
    return b"".join([b"\x80\x04", _global_operand("_sitebuiltins", "_Helper"), b")R)R."])


def _sitebuiltins_helper_call_iterator_payload(*, consume: bool) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("_sitebuiltins", "_Helper"),
        b")R",
        b"\x94",
        b"0",
        _global_operand("builtins", "iter"),
        b"h\x00",
        _unicode_operand("stop"),
        b"\x86R",
    ]
    if consume:
        parts.extend(
            [
                b"\x94",
                b"0",
                _global_operand("builtins", "list"),
                b"h\x01",
                b"\x85R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_payload() -> bytes:
    return _global_call_payload("builtins", "help")


def _ipaddress_format_payload() -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("ipaddress", "IPv4Address"),
            _args_tuple(_unicode_operand("1.2.3.4")),
            b"R",
            b"\x94",
            _global_operand("builtins", "format"),
            _args_tuple(b"h\x00", _unicode_operand("b")),
            b"R.",
        ]
    )


def _typing_extensions_get_type_hints_payload(marker: Path) -> bytes:
    marker_content = "typing-ext-owned"
    annotation_expr = f"open({str(marker)!r},'w').write({marker_content!r})"
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("types", "ModuleType"),
            _args_tuple(_unicode_operand("modelaudit_te_probe")),
            b"R",
            b"\x94",
            b"}",
            _unicode_operand("__annotations__"),
            b"}",
            _unicode_operand("x"),
            _unicode_operand(annotation_expr),
            b"s",
            b"s",
            b"b",
            b"0",
            _global_operand("typing_extensions", "get_type_hints"),
            b"h\x00",
            b"\x85",
            b"R.",
        ]
    )


def _has_critical_call_graph_finding(report: PickleReport, module: str, name: str, sink: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.rule_code == "DANGEROUS_CALL_GRAPH"
        and finding.details.get("module") == module
        and finding.details.get("name") == name
        and finding.details.get("sink") == sink
        for finding in report.findings
    )


def _has_critical_call_graph_finding_with_sink_prefix(
    report: PickleReport,
    module: str,
    name: str,
    sink_prefix: str,
) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.rule_code == "DANGEROUS_CALL_GRAPH"
        and finding.details.get("module") == module
        and finding.details.get("name") == name
        and str(finding.details.get("sink", "")).startswith(sink_prefix)
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


def test_call_graph_propagates_wrapper_import_execution_fallbacks() -> None:
    calls = _calls_for_function("platform.mac_ver") or ()

    assert "platform._mac_ver_xml" in calls
    assert _find_sink_path("platform.mac_ver") == (
        "platform.mac_ver",
        "platform._mac_ver_xml",
        "builtins.__import__",
    )


def test_call_graph_ignores_imports_inside_nested_functions_until_called() -> None:
    calls = _calls_for_function("site.enablerlcompleter") or ()

    assert "builtins.__import__" not in calls
    assert _find_sink_path("site.enablerlcompleter") is None


def test_call_graph_models_getattr_default_callable_fallbacks() -> None:
    calls = _calls_for_function("platform._Processor.get") or ()

    assert "platform._Processor.from_subprocess" in calls
    assert _find_sink_path("platform._Processor.get") == (
        "platform._Processor.get",
        "platform._Processor.from_subprocess",
        "subprocess.check_output",
    )


def test_call_graph_models_version_gated_typing_extensions_definitions() -> None:
    function_name = "typing_extensions.get_type_hints"
    calls = _calls_for_function(function_name) or ()
    path = _find_sink_path(function_name)

    assert _call_graph_entrypoints(function_name) == (function_name,)
    assert "typing.get_type_hints" in calls
    assert path is not None
    assert path[0] == function_name
    assert path[-1] in {"builtins.compile", "builtins.eval"}


def test_call_graph_models_required_arg_imports_when_pickle_supplies_args() -> None:
    import_references = [
        {
            "module": "_pyio",
            "name": "_open_code_with_warning",
            "import_reference": "_pyio._open_code_with_warning",
        }
    ]

    assert _find_sink_path("_pyio._open_code_with_warning") is None
    assert find_dangerous_call_graphs(import_references) == ()
    assert (
        find_dangerous_call_graphs(
            import_references,
            [
                {
                    "module": "_pyio",
                    "name": "_open_code_with_warning",
                    "positional_arg_count": 0,
                }
            ],
        )
        == ()
    )

    findings = find_dangerous_call_graphs(
        import_references,
        [
            {
                "module": "_pyio",
                "name": "_open_code_with_warning",
                "positional_arg_count": 1,
            }
        ],
    )

    assert len(findings) == 1
    assert findings[0].sink == "builtins.__import__"
    assert findings[0].call_path == ("_pyio._open_code_with_warning", "builtins.__import__")


def test_call_graph_models_constructed_callable_instance_invocations() -> None:
    import_references = [
        {
            "module": "_sitebuiltins",
            "name": "_Helper",
            "import_reference": "_sitebuiltins._Helper",
        }
    ]
    constructor_only_invocations = [
        {
            "module": "_sitebuiltins",
            "name": "_Helper",
            "positional_arg_count": 0,
        }
    ]
    callable_instance_invocations = [
        *constructor_only_invocations,
        {
            "module": "_sitebuiltins",
            "name": "_Helper.__call__",
            "positional_arg_count": 0,
        },
    ]

    assert find_dangerous_call_graphs(import_references, constructor_only_invocations) == ()

    findings = find_dangerous_call_graphs(import_references, callable_instance_invocations)

    assert len(findings) == 1
    assert findings[0].module == "_sitebuiltins"
    assert findings[0].name == "_Helper.__call__"
    assert findings[0].sink == "builtins.__import__"
    assert findings[0].call_path == ("_sitebuiltins._Helper.__call__", "builtins.__import__")


def test_call_graph_models_builtins_help_singleton_invocations() -> None:
    import_references = [
        {
            "module": "builtins",
            "name": "help",
            "import_reference": "builtins.help",
        }
    ]
    help_invocations = [
        {
            "module": "builtins",
            "name": "help",
            "positional_arg_count": 0,
        }
    ]

    assert find_dangerous_call_graphs(import_references) == ()

    findings = find_dangerous_call_graphs(import_references, help_invocations)

    assert len(findings) == 1
    assert findings[0].module == "_sitebuiltins"
    assert findings[0].name == "_Helper.__call__"
    assert findings[0].sink == "builtins.__import__"
    assert findings[0].call_path == ("_sitebuiltins._Helper.__call__", "builtins.__import__")


def test_call_graph_models_builtin_format_protocol_dispatch_invocations() -> None:
    import_references = [
        {
            "module": "ipaddress",
            "name": "IPv4Address",
            "import_reference": "ipaddress.IPv4Address",
        },
        {
            "module": "builtins",
            "name": "format",
            "import_reference": "builtins.format",
        },
    ]
    direct_invocations = [
        {
            "module": "ipaddress",
            "name": "IPv4Address",
            "positional_arg_count": 1,
        },
        {
            "module": "builtins",
            "name": "format",
            "positional_arg_count": 2,
        },
    ]
    protocol_invocations = [
        *direct_invocations,
        {
            "module": "ipaddress",
            "name": "IPv4Address.__format__",
            "positional_arg_count": 1,
        },
    ]

    assert find_dangerous_call_graphs(import_references, direct_invocations) == ()

    findings = find_dangerous_call_graphs(import_references, protocol_invocations)

    assert len(findings) == 1
    assert findings[0].module == "ipaddress"
    assert findings[0].name == "IPv4Address.__format__"
    assert findings[0].sink == "builtins.__import__"
    assert findings[0].call_path == ("ipaddress.IPv4Address.__format__", "builtins.__import__")


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


def test_scan_bytes_blocks_sitebuiltins_helper_callable_instance_import_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "sitebuiltins_helper_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'shadow-help'\n",
        encoding="utf-8",
    )
    payload = _sitebuiltins_helper_instance_call_payload()

    report = scan_bytes(payload, source="sitebuiltins-helper-callable-instance-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "_sitebuiltins",
        "_Helper.__call__",
        "builtins.__import__",
    )
    assert any(
        invocation.get("module") == "_sitebuiltins"
        and invocation.get("name") == "_Helper.__call__"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )

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
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if result != "shadow-help":
    raise SystemExit(f"expected shadow help result, got {result!r}")
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


def test_scan_bytes_blocks_builtins_help_singleton_import_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "builtins_help_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'shadow-help'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_payload()

    report = scan_bytes(payload, source="builtins-help-singleton-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "_sitebuiltins",
        "_Helper.__call__",
        "builtins.__import__",
    )
    assert any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )

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
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if result != "shadow-help":
    raise SystemExit(f"expected shadow help result, got {result!r}")
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


def test_scan_bytes_blocks_iter_callable_sentinel_consumption_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "iter_callable_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'stop'\n",
        encoding="utf-8",
    )

    lazy_payload = _sitebuiltins_helper_call_iterator_payload(consume=False)
    report = scan_bytes(lazy_payload, source="iter-callable-lazy.pkl")

    assert report.verdict == SafetyVerdict.CLEAN

    payload = _sitebuiltins_helper_call_iterator_payload(consume=True)
    report = scan_bytes(payload, source="iter-callable-list-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "_sitebuiltins",
        "_Helper.__call__",
        "builtins.__import__",
    )
    assert any(
        invocation.get("module") == "_sitebuiltins"
        and invocation.get("name") == "_Helper.__call__"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )

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
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if result != []:
    raise SystemExit(f"expected empty list result, got {result!r}")
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


def test_scan_bytes_blocks_ipaddress_format_protocol_dispatch_import_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "ipaddress_format_marker"
    marker_content = "re-owned"
    (module_dir / "re.py").write_text(
        "from pathlib import Path\n"
        "import sys\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "class Match:\n"
        "    def groups(self):\n"
        "        return ('', '', 'b')\n"
        "class Pattern:\n"
        "    def fullmatch(self, text):\n"
        "        return Match() if text == 'b' else None\n"
        "def compile(pattern):\n"
        "    return Pattern()\n",
        encoding="utf-8",
    )
    payload = _ipaddress_format_payload()

    report = scan_bytes(payload, source="ipaddress-format-protocol-dispatch-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "ipaddress",
        "IPv4Address.__format__",
        "builtins.__import__",
    )
    assert any(
        invocation.get("module") == "ipaddress"
        and invocation.get("name") == "IPv4Address.__format__"
        and invocation.get("positional_arg_count") == 1
        for invocation in report.metadata.get("callable_invocations", [])
    )

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
sys.modules.pop("ipaddress", None)
sys.modules.pop("re", None)
result = pickle.loads(payload)
if result != "00000001000000100000001100000100":
    raise SystemExit(f"expected binary IPv4 result, got {result!r}")
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


def test_scan_bytes_blocks_platform_processor_get_dynamic_fallback_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "processor_marker"
    marker_content = "processor-owned"
    (module_dir / "subprocess.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "DEVNULL = None\n"
        "class CalledProcessError(Exception):\n"
        "    pass\n"
        "def check_output(*args, **kwargs):\n"
        "    return 'shadow-processor'\n",
        encoding="utf-8",
    )
    payload = _global_call_payload("platform", "_Processor.get")

    report = scan_bytes(payload, source="platform-processor-get-import-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "platform",
        "_Processor.get",
        "subprocess.check_output",
    )

    import platform

    if hasattr(platform._Processor, f"get_{sys.platform}"):  # type: ignore[attr-defined]
        pytest.skip("platform._Processor.get does not use from_subprocess on this platform")

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
sys.modules.pop("platform", None)
sys.modules.pop("subprocess", None)
result = pickle.loads(payload)
if result != "shadow-processor":
    raise SystemExit(f"expected shadow processor result, got {result!r}")
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


def test_scan_bytes_blocks_platform_mac_ver_wrapper_import_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "mac_ver_marker"
    marker_content = "plistlib-owned"
    (module_dir / "plistlib.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def load(file_obj):\n"
        "    return {'ProductVersion': '13.37'}\n",
        encoding="utf-8",
    )
    payload = _global_call_payload("platform", "mac_ver")

    report = scan_bytes(payload, source="platform-mac-ver-plistlib-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, "platform", "mac_ver", "builtins.__import__")

    assert not marker.exists()
    child_code = """
import builtins
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])
marker_content = sys.argv[4]
system_version_plist = "/System/Library/CoreServices/SystemVersion.plist"

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")

original_exists = __import__("os").path.exists
original_open = builtins.open

def fake_exists(path):
    return str(path) == system_version_plist or original_exists(path)

class FakePlistFile:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, *args):
        return b""

def fake_open(path, *args, **kwargs):
    if str(path) == system_version_plist:
        return FakePlistFile()
    return original_open(path, *args, **kwargs)

sys.path.insert(0, str(module_dir))
sys.modules.pop("platform", None)
sys.modules.pop("plistlib", None)
__import__("os").path.exists = fake_exists
builtins.open = fake_open
try:
    result = pickle.loads(payload)
finally:
    __import__("os").path.exists = original_exists
    builtins.open = original_open

if result[0] != "13.37":
    raise SystemExit(f"expected shadow plist result, got {result!r}")
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


def test_scan_bytes_blocks_typing_extensions_get_type_hints_annotation_rce(tmp_path: Path) -> None:
    marker = tmp_path / "typing_extensions_marker"
    marker_content = "typing-ext-owned"
    payload = _typing_extensions_get_type_hints_payload(marker)

    report = scan_bytes(payload, source="typing-extensions-get-type-hints-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding_with_sink_prefix(
        report,
        "typing_extensions",
        "get_type_hints",
        "builtins.",
    )

    assert not marker.exists()
    child_code = """
import pickle
import sys
from pathlib import Path

marker = Path(sys.argv[1])
payload = bytes.fromhex(sys.argv[2])
marker_content = sys.argv[3]

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
result = pickle.loads(payload)
if result != {"x": len(marker_content)}:
    raise SystemExit(f"unexpected get_type_hints result: {result!r}")
if not marker.exists():
    raise SystemExit("marker was not written")
if marker.read_text() != marker_content:
    raise SystemExit("marker content mismatch")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(marker), payload.hex(), marker_content],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == marker_content


def test_scan_bytes_blocks_pyio_open_code_warning_import_side_effect_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "warnings_marker"
    marker_content = "warnings-owned"
    target = tmp_path / "target.py"
    target.write_text("print('opened')\n", encoding="utf-8")
    (module_dir / "warnings.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def warn(*args, **kwargs):\n"
        "    pass\n",
        encoding="utf-8",
    )
    payload = _global_call_payload("_pyio", "_open_code_with_warning", _unicode_operand(str(target)))

    report = scan_bytes(payload, source="pyio-open-code-warning-import-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "_pyio",
        "_open_code_with_warning",
        "builtins.__import__",
    )
    assert any(
        invocation.get("module") == "_pyio"
        and invocation.get("name") == "_open_code_with_warning"
        and invocation.get("positional_arg_count") == 1
        for invocation in report.metadata.get("callable_invocations", [])
    )

    no_arg_report = scan_bytes(
        _global_call_payload("_pyio", "_open_code_with_warning"),
        source="pyio-open-code-warning-no-arg.pkl",
    )
    assert not _has_critical_call_graph_finding(
        no_arg_report,
        "_pyio",
        "_open_code_with_warning",
        "builtins.__import__",
    )

    assert not marker.exists()
    child_code = """
import _pyio
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
sys.modules.pop("warnings", None)
result = pickle.loads(payload)
try:
    if result.__class__.__name__ != "BufferedReader":
        raise SystemExit(f"expected BufferedReader result, got {type(result).__name__}")
finally:
    result.close()
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
