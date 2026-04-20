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


def _builtins_help_call_iterator_next_payload(*, consume: bool, with_default: bool = False) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("builtins", "iter"),
        _global_operand("builtins", "help"),
        _unicode_operand("stop"),
        b"\x86R",
    ]
    if consume:
        parts.extend(
            [
                b"\x94",
                b"0",
                _global_operand("builtins", "next"),
                _args_tuple(b"h\x00", _unicode_operand("fallback")) if with_default else _args_tuple(b"h\x00"),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_call_iterator_deque_payload(*, consume: bool, with_maxlen: bool = False) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("builtins", "iter"),
        _global_operand("builtins", "help"),
        _unicode_operand("stop"),
        b"\x86R",
    ]
    if consume:
        parts.extend(
            [
                b"\x94",
                b"0",
                _global_operand("collections", "deque"),
                _args_tuple(b"h\x00", b"K\x00") if with_maxlen else _args_tuple(b"h\x00"),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_call_iterator_builtin_consumer_payload(
    consumer: str,
    *,
    consume: bool,
    extra_arg_operands: tuple[bytes, ...] = (),
) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("builtins", "iter"),
        _global_operand("builtins", "help"),
        _unicode_operand("stop"),
        b"\x86R",
    ]
    if consume:
        parts.extend(
            [
                b"\x94",
                b"0",
                _global_operand("builtins", consumer),
                _args_tuple(b"h\x00", *extra_arg_operands),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_call_iterator_join_payload(
    join_name: str,
    separator_operand: bytes,
    *,
    consume: bool,
) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("builtins", "iter"),
        _global_operand("builtins", "help"),
        _unicode_operand("stop"),
        b"\x86R",
    ]
    if consume:
        parts.extend(
            [
                b"\x94",
                b"0",
                _global_operand("builtins", join_name),
                _args_tuple(separator_operand, b"h\x00"),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_call_iterator_bytearray_join_payload(*, consume: bool) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("builtins", "bytearray"),
        b"C\x00",
        b"\x85R",
        b"\x94",
        b"0",
        _global_operand("builtins", "iter"),
        _global_operand("builtins", "help"),
        _unicode_operand("stop"),
        b"\x86R",
    ]
    if consume:
        parts.extend(
            [
                b"\x94",
                b"0",
                _global_operand("builtins", "bytearray.join"),
                _args_tuple(b"h\x00", b"h\x01"),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_call_iterator_lazy_wrapper_payload(
    wrapper: str,
    *,
    consume: bool,
    extra_wrapper_arg_operands: tuple[bytes, ...] = (),
) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("builtins", "iter"),
        _global_operand("builtins", "help"),
        _unicode_operand("stop"),
        b"\x86R",
        b"\x94",
        b"0",
        _global_operand("builtins", wrapper),
        _args_tuple(b"h\x00", *extra_wrapper_arg_operands),
        b"R",
    ]
    if consume:
        parts.extend(
            [
                b"\x94",
                b"0",
                _global_operand("builtins", "list"),
                _args_tuple(b"h\x01"),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_call_iterator_itertools_wrapper_payload(
    wrapper: str,
    *,
    consume: bool,
    first_arg_operand: bytes = b"h\x00",
    extra_wrapper_arg_operands: tuple[bytes, ...] = (),
) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("builtins", "iter"),
        _global_operand("builtins", "help"),
        _unicode_operand("stop"),
        b"\x86R",
        b"\x94",
        b"0",
        _global_operand("itertools", wrapper),
        _args_tuple(first_arg_operand, *extra_wrapper_arg_operands),
        b"R",
    ]
    if consume:
        parts.extend(
            [
                b"\x94",
                b"0",
                _global_operand("builtins", "list"),
                _args_tuple(b"h\x01"),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_call_iterator_itertools_product_payload() -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("builtins", "iter"),
            _global_operand("builtins", "help"),
            _unicode_operand("stop"),
            b"\x86R",
            b"\x94",
            b"0",
            _global_operand("itertools", "product"),
            _args_tuple(b"h\x00"),
            b"R.",
        ]
    )


def _builtins_help_call_iterator_itertools_next_wrapper_payload(
    wrapper: str,
    *,
    first_arg_operand: bytes = b"h\x00",
    extra_wrapper_arg_operands: tuple[bytes, ...] = (),
) -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("builtins", "iter"),
            _global_operand("builtins", "help"),
            _unicode_operand("stop"),
            b"\x86R",
            b"\x94",
            b"0",
            _global_operand("itertools", wrapper),
            _args_tuple(first_arg_operand, *extra_wrapper_arg_operands),
            b"R",
            b"\x94",
            b"0",
            _global_operand("builtins", "next"),
            _args_tuple(b"h\x01"),
            b"R.",
        ]
    )


def _builtins_help_call_iterator_itertools_tee_getitem_next_payload() -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("builtins", "iter"),
            _global_operand("builtins", "help"),
            _unicode_operand("stop"),
            b"\x86R",
            b"\x94",
            b"0",
            _global_operand("itertools", "tee"),
            _args_tuple(b"h\x00"),
            b"R",
            b"\x94",
            b"0",
            _global_operand("operator", "getitem"),
            _args_tuple(b"h\x01", b"K\x00"),
            b"R",
            b"\x94",
            b"0",
            _global_operand("builtins", "next"),
            _args_tuple(b"h\x02"),
            b"R.",
        ]
    )


def _builtins_help_call_iterator_stdlib_materializer_payload(
    module: str,
    name: str,
    *materializer_arg_operands: bytes,
) -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("builtins", "iter"),
            _global_operand("builtins", "help"),
            _unicode_operand("stop"),
            b"\x86R",
            b"\x94",
            b"0",
            _global_operand(module, name),
            _args_tuple(*materializer_arg_operands),
            b"R.",
        ]
    )


def _builtins_help_call_iterator_heapq_merge_next_payload() -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("builtins", "iter"),
            _global_operand("builtins", "help"),
            _unicode_operand("stop"),
            b"\x86R",
            b"\x94",
            b"0",
            _global_operand("heapq", "merge"),
            _args_tuple(b"h\x00"),
            b"R",
            b"\x94",
            b"0",
            _global_operand("builtins", "next"),
            _args_tuple(b"h\x01"),
            b"R.",
        ]
    )


def _sitebuiltins_helper_defaultdict_payload(*, lookup: bool) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("_sitebuiltins", "_Helper"),
        b")R",
        b"\x94",
        b"0",
        _global_operand("collections", "defaultdict"),
        b"h\x00",
        b"\x85R",
    ]
    if lookup:
        parts.extend(
            [
                b"\x94",
                b"0",
                _global_operand("operator", "getitem"),
                b"h\x01",
                _unicode_operand("missing"),
                b"\x86R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_defaultdict_method_payload(
    module: str,
    method_name: str,
    *,
    lookup: bool,
) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("collections", "defaultdict"),
        _global_operand("builtins", "help"),
        b"\x85R",
        b"\x94",
        b"0",
    ]
    if lookup:
        parts.extend(
            [
                _global_operand(module, method_name),
                _args_tuple(b"h\x00", _unicode_operand("missing")),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_payload() -> bytes:
    return _global_call_payload("builtins", "help")


def _builtins_help_defaultdict_format_map_payload(*, lookup: bool) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("collections", "defaultdict"),
        _global_operand("builtins", "help"),
        b"\x85R",
    ]
    if lookup:
        parts.extend(
            [
                b"\x94",
                b"0",
                _global_operand("builtins", "str.format_map"),
                _args_tuple(_unicode_operand("{x}"), b"h\x00"),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_defaultdict_operator_mod_payload(*, lookup: bool) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("collections", "defaultdict"),
        _global_operand("builtins", "help"),
        b"\x85R",
    ]
    if lookup:
        parts.extend(
            [
                b"\x94",
                b"0",
                _global_operand("operator", "mod"),
                _args_tuple(_unicode_operand("%(x)s"), b"h\x00"),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_defaultdict_formatter_vformat_payload(*, lookup: bool) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("string", "Formatter"),
        b")R",
        b"\x94",
        b"0",
        _global_operand("collections", "defaultdict"),
        _global_operand("builtins", "help"),
        b"\x85R",
    ]
    if lookup:
        parts.extend(
            [
                b"\x94",
                b"0",
                _global_operand("string", "Formatter.vformat"),
                _args_tuple(b"h\x00", _unicode_operand("{x}"), b"N", b"h\x01"),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_defaultdict_formatter_private_vformat_payload(*, lookup: bool) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("string", "Formatter"),
        b")R",
        b"\x94",
        b"0",
        _global_operand("collections", "defaultdict"),
        _global_operand("builtins", "help"),
        b"\x85R",
    ]
    if lookup:
        parts.extend(
            [
                b"\x94",
                b"0",
                _global_operand("string", "Formatter._vformat"),
                _args_tuple(b"h\x00", _unicode_operand("{x}"), b"N", b"h\x01", b"\x8f", b"K\x02"),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


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


def _ipaddress_str_format_payload() -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("ipaddress", "IPv4Address"),
            _args_tuple(_unicode_operand("1.2.3.4")),
            b"R",
            b"\x94",
            b"0",
            _global_operand("builtins", "str.format"),
            _args_tuple(_unicode_operand("{:b}"), b"h\x00"),
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


def test_call_graph_models_str_format_protocol_dispatch_invocations() -> None:
    import_references = [
        {
            "module": "ipaddress",
            "name": "IPv4Address",
            "import_reference": "ipaddress.IPv4Address",
        },
        {
            "module": "builtins",
            "name": "str.format",
            "import_reference": "builtins.str.format",
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
            "name": "str.format",
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


@pytest.mark.parametrize("with_default", [False, True])
def test_scan_bytes_blocks_next_call_iterator_consumption_rce(
    tmp_path: Path,
    with_default: bool,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "next_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )

    lazy_payload = _builtins_help_call_iterator_next_payload(consume=False)
    report = scan_bytes(lazy_payload, source="next-call-iterator-lazy.pkl")

    assert report.verdict == SafetyVerdict.CLEAN

    payload = _builtins_help_call_iterator_next_payload(consume=True, with_default=with_default)
    suffix = "default" if with_default else "single"
    report = scan_bytes(payload, source=f"next-call-iterator-{suffix}-rce.pkl")

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
if result != "factory-value":
    raise SystemExit(f"expected factory value result, got {result!r}")
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


@pytest.mark.parametrize("with_maxlen", [False, True])
def test_scan_bytes_blocks_deque_call_iterator_consumption_rce(
    tmp_path: Path,
    with_maxlen: bool,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "deque_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'stop'\n",
        encoding="utf-8",
    )

    lazy_payload = _builtins_help_call_iterator_deque_payload(consume=False)
    report = scan_bytes(lazy_payload, source="deque-call-iterator-lazy.pkl")

    assert report.verdict == SafetyVerdict.CLEAN

    payload = _builtins_help_call_iterator_deque_payload(consume=True, with_maxlen=with_maxlen)
    suffix = "maxlen" if with_maxlen else "single"
    report = scan_bytes(payload, source=f"deque-call-iterator-{suffix}-rce.pkl")

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
expected_maxlen = None if sys.argv[5] == "None" else int(sys.argv[5])

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if type(result).__name__ != "deque":
    raise SystemExit(f"expected deque result, got {type(result).__name__}")
if len(result) != 0:
    raise SystemExit(f"expected empty deque result, got {result!r}")
if result.maxlen != expected_maxlen:
    raise SystemExit(f"expected maxlen {expected_maxlen!r}, got {result.maxlen!r}")
if not marker.exists():
    raise SystemExit("marker was not written")
if marker.read_text() != marker_content:
    raise SystemExit("marker content mismatch")
"""
    expected_maxlen = "0" if with_maxlen else "None"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            child_code,
            str(module_dir),
            str(marker),
            payload.hex(),
            marker_content,
            expected_maxlen,
        ],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == marker_content


@pytest.mark.parametrize(
    ("consumer", "extra_arg_operands", "expected_repr"),
    [
        ("all", (), "True"),
        ("any", (), "False"),
        ("bytearray", (), "bytearray(b'')"),
        ("bytes", (), "b''"),
        ("sorted", (), "[]"),
        ("sum", (), "0"),
        ("sum", (b"K\x0a",), "10"),
    ],
)
def test_scan_bytes_blocks_builtin_iterable_call_iterator_consumption_rce(
    tmp_path: Path,
    consumer: str,
    extra_arg_operands: tuple[bytes, ...],
    expected_repr: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "builtin_iterable_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'stop'\n",
        encoding="utf-8",
    )

    lazy_payload = _builtins_help_call_iterator_builtin_consumer_payload(consumer, consume=False)
    report = scan_bytes(lazy_payload, source="builtin-iterable-call-iterator-lazy.pkl")

    assert report.verdict == SafetyVerdict.CLEAN

    payload = _builtins_help_call_iterator_builtin_consumer_payload(
        consumer,
        consume=True,
        extra_arg_operands=extra_arg_operands,
    )
    report = scan_bytes(payload, source=f"builtin-{consumer}-call-iterator-rce.pkl")

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
expected_repr = sys.argv[5]

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if repr(result) != expected_repr:
    raise SystemExit(f"expected result repr {expected_repr!r}, got {result!r}")
if not marker.exists():
    raise SystemExit("marker was not written")
if marker.read_text() != marker_content:
    raise SystemExit("marker content mismatch")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex(), marker_content, expected_repr],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == marker_content


@pytest.mark.parametrize(
    ("join_name", "separator_operand", "expected_repr"),
    [
        ("str.join", _unicode_operand(""), "''"),
        ("bytes.join", b"C\x00", "b''"),
    ],
)
def test_scan_bytes_blocks_join_call_iterator_consumption_rce(
    tmp_path: Path,
    join_name: str,
    separator_operand: bytes,
    expected_repr: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "join_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'stop'\n",
        encoding="utf-8",
    )

    lazy_payload = _builtins_help_call_iterator_join_payload(
        join_name,
        separator_operand,
        consume=False,
    )
    report = scan_bytes(lazy_payload, source=f"builtin-{join_name}-call-iterator-lazy.pkl")

    assert report.verdict == SafetyVerdict.CLEAN

    payload = _builtins_help_call_iterator_join_payload(
        join_name,
        separator_operand,
        consume=True,
    )
    report = scan_bytes(payload, source=f"builtin-{join_name}-call-iterator-rce.pkl")

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
expected_repr = sys.argv[5]

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if repr(result) != expected_repr:
    raise SystemExit(f"expected result repr {expected_repr!r}, got {result!r}")
if not marker.exists():
    raise SystemExit("marker was not written")
if marker.read_text() != marker_content:
    raise SystemExit("marker content mismatch")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex(), marker_content, expected_repr],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == marker_content


def test_scan_bytes_blocks_bytearray_join_call_iterator_consumption_rce(
    tmp_path: Path,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "bytearray_join_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'stop'\n",
        encoding="utf-8",
    )

    lazy_payload = _builtins_help_call_iterator_bytearray_join_payload(consume=False)
    report = scan_bytes(lazy_payload, source="builtin-bytearray-join-call-iterator-lazy.pkl")

    assert report.verdict == SafetyVerdict.CLEAN

    payload = _builtins_help_call_iterator_bytearray_join_payload(consume=True)
    report = scan_bytes(payload, source="builtin-bytearray-join-call-iterator-rce.pkl")

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
if repr(result) != "bytearray(b'')":
    raise SystemExit(f"expected empty bytearray result, got {result!r}")
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


@pytest.mark.parametrize("consumer", ["max", "min"])
def test_scan_bytes_blocks_min_max_call_iterator_consumption_rce(
    tmp_path: Path,
    consumer: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "min_max_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'stop'\n",
        encoding="utf-8",
    )

    payload = _builtins_help_call_iterator_builtin_consumer_payload(consumer, consume=True)
    report = scan_bytes(payload, source=f"builtin-{consumer}-call-iterator-rce.pkl")

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
consumer = sys.argv[5]

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
try:
    pickle.loads(payload)
except ValueError as exc:
    if "iterable argument is empty" not in str(exc):
        raise
else:
    raise SystemExit(f"expected {consumer} to reject empty iterator")
if not marker.exists():
    raise SystemExit("marker was not written")
if marker.read_text() != marker_content:
    raise SystemExit("marker content mismatch")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex(), marker_content, consumer],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == marker_content


@pytest.mark.parametrize(
    ("wrapper", "extra_wrapper_arg_operands"),
    [
        ("iter", ()),
        ("enumerate", ()),
        ("enumerate", (b"K\x0a",)),
        ("zip", ()),
    ],
)
def test_scan_bytes_blocks_lazy_wrapper_call_iterator_consumption_rce(
    tmp_path: Path,
    wrapper: str,
    extra_wrapper_arg_operands: tuple[bytes, ...],
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "lazy_wrapper_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'stop'\n",
        encoding="utf-8",
    )

    lazy_payload = _builtins_help_call_iterator_lazy_wrapper_payload(
        wrapper,
        consume=False,
        extra_wrapper_arg_operands=extra_wrapper_arg_operands,
    )
    report = scan_bytes(lazy_payload, source=f"builtin-{wrapper}-call-iterator-wrapper-lazy.pkl")

    assert report.verdict == SafetyVerdict.CLEAN

    payload = _builtins_help_call_iterator_lazy_wrapper_payload(
        wrapper,
        consume=True,
        extra_wrapper_arg_operands=extra_wrapper_arg_operands,
    )
    report = scan_bytes(payload, source=f"builtin-{wrapper}-call-iterator-wrapper-rce.pkl")

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


@pytest.mark.parametrize(
    ("wrapper", "first_arg_operand", "extra_wrapper_arg_operands"),
    [
        ("chain", b"h\x00", ()),
        ("islice", b"h\x00", (b"K\x01",)),
        ("chain.from_iterable", b"h\x00", ()),
        ("chain.from_iterable", b"(h\x00t", ()),
    ],
)
def test_scan_bytes_blocks_itertools_lazy_wrapper_call_iterator_consumption_rce(
    tmp_path: Path,
    wrapper: str,
    first_arg_operand: bytes,
    extra_wrapper_arg_operands: tuple[bytes, ...],
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "itertools_wrapper_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'stop'\n",
        encoding="utf-8",
    )

    lazy_payload = _builtins_help_call_iterator_itertools_wrapper_payload(
        wrapper,
        consume=False,
        first_arg_operand=first_arg_operand,
        extra_wrapper_arg_operands=extra_wrapper_arg_operands,
    )
    report = scan_bytes(lazy_payload, source=f"itertools-{wrapper}-call-iterator-wrapper-lazy.pkl")

    assert report.verdict == SafetyVerdict.CLEAN

    payload = _builtins_help_call_iterator_itertools_wrapper_payload(
        wrapper,
        consume=True,
        first_arg_operand=first_arg_operand,
        extra_wrapper_arg_operands=extra_wrapper_arg_operands,
    )
    report = scan_bytes(payload, source=f"itertools-{wrapper}-call-iterator-wrapper-rce.pkl")

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


def test_scan_bytes_blocks_itertools_product_call_iterator_materialization_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "itertools_product_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "_values = ['owned-value', 'stop']\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )

    payload = _builtins_help_call_iterator_itertools_product_payload()
    report = scan_bytes(payload, source="itertools-product-call-iterator-rce.pkl")

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
if list(result) != [("owned-value",)]:
    raise SystemExit("unexpected product contents")
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


@pytest.mark.parametrize(
    ("payload", "expected_repr"),
    [
        (_builtins_help_call_iterator_itertools_next_wrapper_payload("cycle"), "'owned-value'"),
        (
            _builtins_help_call_iterator_itertools_next_wrapper_payload(
                "zip_longest",
                extra_wrapper_arg_operands=(b")",),
            ),
            "('owned-value', None)",
        ),
        (
            _builtins_help_call_iterator_itertools_next_wrapper_payload(
                "compress",
                extra_wrapper_arg_operands=(b"(K\x01t",),
            ),
            "'owned-value'",
        ),
        (_builtins_help_call_iterator_itertools_next_wrapper_payload("pairwise"), "('owned-value', 'b')"),
        (_builtins_help_call_iterator_itertools_tee_getitem_next_payload(), "'owned-value'"),
    ],
)
def test_scan_bytes_blocks_itertools_adapter_next_call_iterator_consumption_rce(
    tmp_path: Path,
    payload: bytes,
    expected_repr: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "itertools_adapter_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "_values = ['owned-value', 'b', 'stop']\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )

    report = scan_bytes(payload, source="itertools-adapter-next-call-iterator-rce.pkl")

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
expected_repr = sys.argv[5]

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if repr(result) != expected_repr:
    raise SystemExit(f"expected {expected_repr}, got {result!r}")
if not marker.exists():
    raise SystemExit("marker was not written")
if marker.read_text() != marker_content:
    raise SystemExit("marker content mismatch")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex(), marker_content, expected_repr],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == marker_content


@pytest.mark.parametrize(
    ("payload", "values_literal", "expected_repr"),
    [
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("array", "array", _unicode_operand("i"), b"h\x00"),
            "[7, 'stop']",
            "array('i', [7])",
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("collections", "Counter", b"h\x00"),
            "['owned-value', 'stop']",
            "Counter({'owned-value': 1})",
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("collections", "OrderedDict", b"h\x00"),
            "[(('owned-key', 'owned-value')), 'stop']",
            "OrderedDict({'owned-key': 'owned-value'})",
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("collections", "UserDict", b"h\x00"),
            "[('owned-key', 'owned-value'), 'stop']",
            "{'owned-key': 'owned-value'}",
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("collections", "UserList", b"h\x00"),
            "['owned-value', 'stop']",
            "['owned-value']",
        ),
    ],
)
def test_scan_bytes_blocks_stdlib_materializer_call_iterator_consumption_rce(
    tmp_path: Path,
    payload: bytes,
    values_literal: str,
    expected_repr: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "stdlib_materializer_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        f"_values = {values_literal}\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )

    report = scan_bytes(payload, source="stdlib-materializer-call-iterator-rce.pkl")

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
expected_repr = sys.argv[5]

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if repr(result) != expected_repr:
    raise SystemExit(f"expected {expected_repr}, got {result!r}")
if not marker.exists():
    raise SystemExit("marker was not written")
if marker.read_text() != marker_content:
    raise SystemExit("marker content mismatch")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex(), marker_content, expected_repr],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == marker_content


@pytest.mark.parametrize(
    ("payload", "setup_code", "expected_type", "expected_len"),
    [
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("weakref", "WeakSet", b"h\x00"),
            "class Box:\n    pass\n_box = Box()\n_values = [_box, 'stop']\n",
            "WeakSet",
            1,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("weakref", "WeakKeyDictionary", b"h\x00"),
            "class Box:\n    pass\n_key = Box()\n_values = [(_key, 'owned-value'), 'stop']\n",
            "WeakKeyDictionary",
            1,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("weakref", "WeakValueDictionary", b"h\x00"),
            "class Box:\n    pass\n_value = Box()\n_values = [('owned-key', _value), 'stop']\n",
            "WeakValueDictionary",
            1,
        ),
    ],
)
def test_scan_bytes_blocks_weakref_materializer_call_iterator_consumption_rce(
    tmp_path: Path,
    payload: bytes,
    setup_code: str,
    expected_type: str,
    expected_len: int,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "weakref_materializer_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        f"{setup_code}"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )

    report = scan_bytes(payload, source="weakref-materializer-call-iterator-rce.pkl")

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
expected_type = sys.argv[5]
expected_len = int(sys.argv[6])

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if type(result).__name__ != expected_type:
    raise SystemExit(f"expected {expected_type}, got {type(result).__name__}")
if len(result) != expected_len:
    raise SystemExit(f"expected len {expected_len}, got {len(result)}")
if not marker.exists():
    raise SystemExit("marker was not written")
if marker.read_text() != marker_content:
    raise SystemExit("marker content mismatch")
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            child_code,
            str(module_dir),
            str(marker),
            payload.hex(),
            marker_content,
            expected_type,
            str(expected_len),
        ],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == marker_content


def test_scan_bytes_blocks_heapq_merge_call_iterator_consumption_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "heapq_merge_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "_values = ['owned-value', 'stop']\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )

    payload = _builtins_help_call_iterator_heapq_merge_next_payload()
    report = scan_bytes(payload, source="heapq-merge-call-iterator-rce.pkl")

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
if result != "owned-value":
    raise SystemExit(f"unexpected result {result!r}")
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


def test_scan_bytes_blocks_defaultdict_factory_getitem_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "defaultdict_factory_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )

    factory_only_payload = _sitebuiltins_helper_defaultdict_payload(lookup=False)
    report = scan_bytes(factory_only_payload, source="defaultdict-factory-only.pkl")

    assert report.verdict == SafetyVerdict.CLEAN

    payload = _sitebuiltins_helper_defaultdict_payload(lookup=True)
    report = scan_bytes(payload, source="defaultdict-factory-getitem-rce.pkl")

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
if result != "factory-value":
    raise SystemExit(f"expected factory value result, got {result!r}")
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


@pytest.mark.parametrize(
    ("module", "method_name"),
    [
        ("collections", "defaultdict.__missing__"),
        ("collections", "defaultdict.__getitem__"),
        ("builtins", "dict.__getitem__"),
    ],
)
def test_scan_bytes_blocks_defaultdict_method_factory_rce(
    tmp_path: Path,
    module: str,
    method_name: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "defaultdict_method_factory_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )

    factory_only_payload = _builtins_help_defaultdict_method_payload(module, method_name, lookup=False)
    report = scan_bytes(factory_only_payload, source="defaultdict-method-factory-only.pkl")

    assert report.verdict == SafetyVerdict.CLEAN

    payload = _builtins_help_defaultdict_method_payload(module, method_name, lookup=True)
    report = scan_bytes(payload, source=f"{module}-{method_name}-defaultdict-factory-rce.pkl")

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
if result != "factory-value":
    raise SystemExit(f"expected factory value result, got {result!r}")
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


def test_scan_bytes_blocks_format_map_defaultdict_factory_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "format_map_defaultdict_factory_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )

    factory_only_payload = _builtins_help_defaultdict_format_map_payload(lookup=False)
    report = scan_bytes(factory_only_payload, source="format-map-defaultdict-factory-only.pkl")

    assert report.verdict == SafetyVerdict.CLEAN

    payload = _builtins_help_defaultdict_format_map_payload(lookup=True)
    report = scan_bytes(payload, source="format-map-defaultdict-factory-rce.pkl")

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
if result != "factory-value":
    raise SystemExit(f"expected factory value result, got {result!r}")
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


def test_scan_bytes_blocks_operator_mod_defaultdict_factory_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "operator_mod_defaultdict_factory_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )

    factory_only_payload = _builtins_help_defaultdict_operator_mod_payload(lookup=False)
    report = scan_bytes(factory_only_payload, source="operator-mod-defaultdict-factory-only.pkl")

    assert report.verdict == SafetyVerdict.CLEAN

    payload = _builtins_help_defaultdict_operator_mod_payload(lookup=True)
    report = scan_bytes(payload, source="operator-mod-defaultdict-factory-rce.pkl")

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
if result != "factory-value":
    raise SystemExit(f"expected factory value result, got {result!r}")
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


def test_scan_bytes_blocks_formatter_vformat_defaultdict_factory_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "formatter_vformat_defaultdict_factory_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )

    factory_only_payload = _builtins_help_defaultdict_formatter_vformat_payload(lookup=False)
    report = scan_bytes(factory_only_payload, source="formatter-vformat-defaultdict-factory-only.pkl")

    assert report.verdict == SafetyVerdict.CLEAN

    payload = _builtins_help_defaultdict_formatter_vformat_payload(lookup=True)
    report = scan_bytes(payload, source="formatter-vformat-defaultdict-factory-rce.pkl")

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
if result != "factory-value":
    raise SystemExit(f"expected factory value result, got {result!r}")
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


def test_scan_bytes_blocks_formatter_private_vformat_defaultdict_factory_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "formatter_private_vformat_defaultdict_factory_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )

    factory_only_payload = _builtins_help_defaultdict_formatter_private_vformat_payload(lookup=False)
    report = scan_bytes(factory_only_payload, source="formatter-private-vformat-defaultdict-factory-only.pkl")

    assert report.verdict == SafetyVerdict.CLEAN

    payload = _builtins_help_defaultdict_formatter_private_vformat_payload(lookup=True)
    report = scan_bytes(payload, source="formatter-private-vformat-defaultdict-factory-rce.pkl")

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
if result != ("factory-value", 0):
    raise SystemExit(f"expected private vformat result tuple, got {result!r}")
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


def test_scan_bytes_blocks_ipaddress_str_format_protocol_dispatch_import_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "ipaddress_str_format_marker"
    marker_content = "re-owned"
    (module_dir / "re.py").write_text(
        "from pathlib import Path\n"
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
    payload = _ipaddress_str_format_payload()

    report = scan_bytes(payload, source="ipaddress-str-format-protocol-dispatch-rce.pkl")

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
