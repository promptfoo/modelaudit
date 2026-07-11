"""Focused call-graph regressions for function-body import statements."""

from __future__ import annotations

import ast
import builtins
import importlib
import io
import os
import pickle
import py_compile
import subprocess
import sys
import threading
import typing
import zipfile
from contextvars import copy_context
from importlib.machinery import (
    EXTENSION_SUFFIXES,
    SOURCE_SUFFIXES,
    FileFinder,
    FrozenImporter,
    ModuleSpec,
    SourceFileLoader,
)
from importlib.util import find_spec
from pathlib import Path
from types import FunctionType
from typing import Any
from zipimport import zipimporter

import pytest

import modelaudit_picklescan.api as api_module
import modelaudit_picklescan.call_graph as call_graph
from modelaudit_picklescan import PickleReport, SafetyVerdict, ScanOptions, ScanStatus, Severity, scan_bytes

pytestmark = pytest.mark.skipif(
    find_spec(api_module._RUST_EXTENSION_MODULE) is None,
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


def _bytes_operand(value: bytes) -> bytes:
    if len(value) <= 0xFF:
        return b"C" + bytes([len(value)]) + value
    return b"B" + len(value).to_bytes(4, "little") + value


def _global_operand(module: str, name: str) -> bytes:
    return _unicode_operand(module) + _unicode_operand(name) + b"\x93"


def _args_tuple(*arg_operands: bytes) -> bytes:
    if not arg_operands:
        return b")"
    if len(arg_operands) == 1:
        return arg_operands[0] + b"\x85"
    return b"(" + b"".join(arg_operands) + b"t"


def _singleton_small_int_tuple_operand(value: int) -> bytes:
    if not 0 <= value <= 0xFF:
        raise ValueError("singleton int tuple helper accepts one-byte positive ints")
    return bytes([ord("K"), value, 0x85])


def _global_call_payload(module: str, name: str, *arg_operands: bytes) -> bytes:
    return b"".join([b"\x80\x04", _global_operand(module, name), _args_tuple(*arg_operands), b"R."])


def _clear_call_graph_caches() -> None:
    for function in call_graph._SOURCE_SENSITIVE_CACHED_FUNCTIONS:
        function.cache_clear()


def test_wildcard_summary_and_analysis_share_module_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_path = tmp_path / "module.py"
    module_path.write_text("from dependency import *\n\ndef run():\n    return 1\n", encoding="utf-8")
    parse_calls = 0
    real_parse = call_graph.ast.parse

    def tracking_parse(source_code: str, filename: str = "<unknown>") -> ast.Module:
        nonlocal parse_calls
        parse_calls += 1
        return real_parse(source_code, filename=filename)

    monkeypatch.setattr(
        call_graph, "_resolve_module_source", lambda module_name: module_path if module_name == "module" else None
    )
    monkeypatch.setattr(call_graph.ast, "parse", tracking_parse)
    _clear_call_graph_caches()

    assert call_graph._wildcard_export_summary("module") is not None
    assert call_graph._analyze_module("module") is not None
    assert parse_calls == 1


def test_shared_source_sensitive_caches_clears_once_per_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    clear_count = 0

    def fake_clear() -> None:
        nonlocal clear_count
        clear_count += 1

    monkeypatch.setattr(call_graph, "_clear_source_sensitive_caches_now", fake_clear)

    with call_graph.shared_source_sensitive_caches():
        call_graph._clear_source_sensitive_caches()
        call_graph._clear_source_sensitive_caches()
        call_graph._clear_source_sensitive_caches()

    assert clear_count == 1

    call_graph._clear_source_sensitive_caches()
    assert clear_count == 2


def test_shared_source_snapshot_tracks_large_extension_candidates_by_presence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_tp_large_extension_candidate"
    extension_path = tmp_path / f"{module_name}{EXTENSION_SUFFIXES[0]}"
    extension_path.write_bytes(b"x" * (call_graph._MAX_SOURCE_BYTES + 1))
    monkeypatch.syspath_prepend(str(tmp_path))

    with call_graph.shared_source_sensitive_caches():
        report_generation = call_graph._begin_shared_source_report()
        call_graph._track_shared_source_candidates((module_name,))
        call_graph._ensure_shared_source_snapshot_stable(report_generation)

        extension_path.unlink()
        with pytest.raises(call_graph._CallGraphAnalysisLimitError, match="source changed"):
            call_graph._ensure_shared_source_snapshot_stable(report_generation)


def test_module_initialization_inert_proof_rejects_unbounded_module_depth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_source_lookup(_module_name: str) -> object:
        raise AssertionError("unbounded module names must be rejected before source lookup")

    monkeypatch.setattr(call_graph, "_module_source_context", fail_source_lookup)

    assert call_graph.module_initialization_is_proven_inert(".".join(["package"] * 33)) is False


def test_import_only_reference_trust_rejects_reviewed_unavailable_optional_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delitem(sys.modules, "dill", raising=False)
    monkeypatch.setattr(call_graph, "_find_standard_filesystem_spec", lambda _module_name: None)
    call_graph._trusted_module_origin_kind.cache_clear()
    try:
        assert call_graph.import_only_reference_is_proven_trusted("dill", "dump") is False
        assert call_graph.import_only_reference_is_proven_trusted("dill", "loads") is False
        assert call_graph.import_only_reference_is_proven_trusted("private_payload", "Gadget") is False
    finally:
        call_graph._trusted_module_origin_kind.cache_clear()


def test_trusted_origin_rejects_local_distribution_metadata_outside_trusted_install_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay = tmp_path / "overlay"
    package_dir = overlay / "_pytest" / "_py"
    package_dir.mkdir(parents=True)
    (overlay / "_pytest" / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "path.py").write_text("class LocalPath:\n    pass\n", encoding="utf-8")
    dist_info = overlay / "pytest-1.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text("Name: pytest\nVersion: 1.0\n", encoding="utf-8")
    (dist_info / "top_level.txt").write_text("_pytest\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(overlay))
    for module_name in ("_pytest._py.path", "_pytest._py", "_pytest"):
        monkeypatch.delitem(sys.modules, module_name, raising=False)
    call_graph._clear_source_sensitive_caches()

    assert call_graph._trusted_module_origin_kind("_pytest._py.path") is None

    monkeypatch.setattr(
        call_graph,
        "_TRUSTED_SITE_PACKAGE_PATHS",
        (*call_graph._TRUSTED_SITE_PACKAGE_PATHS, overlay.resolve()),
    )
    call_graph._clear_source_sensitive_caches()

    assert call_graph._trusted_module_origin_kind("_pytest._py.path") == "site_packages"

    shadow_root = tmp_path / "shadow"
    shadow_package_dir = shadow_root / "_pytest" / "_py"
    shadow_package_dir.mkdir(parents=True)
    (shadow_root / "_pytest" / "__init__.py").write_text("", encoding="utf-8")
    (shadow_package_dir / "__init__.py").write_text("", encoding="utf-8")
    (shadow_package_dir / "path.py").write_text("class LocalPath:\n    pass\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(shadow_root))
    call_graph._clear_source_sensitive_caches()

    assert call_graph._trusted_module_origin_kind("_pytest._py.path") is None


def test_trusted_origin_rejects_inactive_lookalike_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment_root = tmp_path / "environment"
    site_packages = (
        environment_root / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    )
    package_dir = site_packages / "_pytest" / "_py"
    package_dir.mkdir(parents=True)
    (environment_root / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (site_packages / "_pytest" / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "path.py").write_text("class LocalPath:\n    pass\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(site_packages))
    for module_name in ("_pytest._py.path", "_pytest._py", "_pytest"):
        monkeypatch.delitem(sys.modules, module_name, raising=False)
    call_graph._clear_source_sensitive_caches()

    assert call_graph._trusted_module_origin_kind("_pytest._py.path") is None


def test_trusted_origin_recognizes_active_environment_delegated_overlay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_site_packages = tmp_path / "active" / "lib" / "python" / "site-packages"
    active_site_packages.mkdir(parents=True)
    overlay_site_packages = tmp_path / "overlay" / "lib" / "python" / "site-packages"
    package_dir = overlay_site_packages / "_pytest" / "_py"
    package_dir.mkdir(parents=True)
    (overlay_site_packages / "_pytest" / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "path.py").write_text("class LocalPath:\n    pass\n", encoding="utf-8")
    (active_site_packages / "_uv_ephemeral_overlay.pth").write_text(
        f"import site; site.addsitedir({str(overlay_site_packages)!r})\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(call_graph, "_TRUSTED_SITE_PACKAGE_PATHS", (active_site_packages.resolve(),))
    monkeypatch.setattr(
        call_graph,
        "_TRUSTED_DELEGATED_SITE_PACKAGE_PATHS",
        call_graph._trusted_delegated_site_package_paths(),
    )
    monkeypatch.syspath_prepend(str(overlay_site_packages))
    for module_name in ("_pytest._py.path", "_pytest._py", "_pytest"):
        monkeypatch.delitem(sys.modules, module_name, raising=False)
    call_graph._clear_source_sensitive_caches()

    assert call_graph._trusted_module_origin_kind("_pytest._py.path") == "site_packages"


def test_trusted_origin_ignores_nonexecuted_pth_addsitedir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_site_packages = tmp_path / "active" / "lib" / "python" / "site-packages"
    active_site_packages.mkdir(parents=True)
    overlay_site_packages = tmp_path / "overlay" / "lib" / "python" / "site-packages"
    package_dir = overlay_site_packages / "_pytest" / "_py"
    package_dir.mkdir(parents=True)
    (overlay_site_packages / "_pytest" / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "path.py").write_text("class LocalPath:\n    pass\n", encoding="utf-8")
    (active_site_packages / "deferred-overlay.pth").write_text(
        f"import site; deferred = lambda: site.addsitedir({str(overlay_site_packages)!r})\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(call_graph, "_TRUSTED_SITE_PACKAGE_PATHS", (active_site_packages.resolve(),))
    monkeypatch.setattr(
        call_graph,
        "_TRUSTED_DELEGATED_SITE_PACKAGE_PATHS",
        call_graph._trusted_delegated_site_package_paths(),
    )
    monkeypatch.syspath_prepend(str(overlay_site_packages))
    for module_name in ("_pytest._py.path", "_pytest._py", "_pytest"):
        monkeypatch.delitem(sys.modules, module_name, raising=False)
    call_graph._clear_source_sensitive_caches()

    assert call_graph._trusted_module_origin_kind("_pytest._py.path") is None


def test_legacy_builtin_module_alias_does_not_require_origin_review() -> None:
    assert call_graph.import_only_module_requires_origin_review("__builtin__", "set") is False


def test_unresolved_framework_reconstruction_reference_requires_origin_review(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(call_graph, "_trusted_module_origin_kind", lambda _module_name: "unresolved")

    assert call_graph.import_only_module_requires_origin_review("torch._utils", "_rebuild_tensor_v2") is True
    assert call_graph.import_only_reference_is_proven_trusted("torch._utils", "_rebuild_tensor_v2") is False
    assert call_graph.import_only_module_requires_origin_review("torch._utils", "Gadget") is True
    assert call_graph.import_only_reference_is_proven_trusted("torch._utils", "Gadget") is False


def test_shared_source_sensitive_caches_allows_inherited_worker_scopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_count = 0
    worker_entered = threading.Event()

    def fake_clear() -> None:
        nonlocal clear_count
        clear_count += 1

    def enter_worker_scope() -> None:
        with call_graph.shared_source_sensitive_caches():
            call_graph._clear_source_sensitive_caches()
            worker_entered.set()

    monkeypatch.setattr(call_graph, "_clear_source_sensitive_caches_now", fake_clear)

    with call_graph.shared_source_sensitive_caches():
        worker_context = copy_context()
        worker = threading.Thread(target=worker_context.run, args=(enter_worker_scope,))
        worker.start()
        assert worker_entered.wait(timeout=1)
        worker.join(timeout=1)
        assert not worker.is_alive()
        assert clear_count == 1

    with call_graph.shared_source_sensitive_caches():
        pass

    assert clear_count == 2


def test_shared_source_sensitive_caches_serializes_inherited_worker_work() -> None:
    first_entered = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()

    def hold_first_scope() -> None:
        with call_graph.shared_source_sensitive_caches():
            first_entered.set()
            release_first.wait(timeout=1)

    def enter_second_scope() -> None:
        with call_graph.shared_source_sensitive_caches():
            second_entered.set()

    with call_graph.shared_source_sensitive_caches():
        first_context = copy_context()
        second_context = copy_context()
        first_worker = threading.Thread(target=first_context.run, args=(hold_first_scope,))
        second_worker = threading.Thread(target=second_context.run, args=(enter_second_scope,))
        first_worker.start()
        assert first_entered.wait(timeout=1)
        second_worker.start()
        second_was_blocked = not second_entered.wait(timeout=0.05)
        release_first.set()
        assert second_entered.wait(timeout=1)
        first_worker.join(timeout=1)
        second_worker.join(timeout=1)

    assert second_was_blocked
    assert not first_worker.is_alive()
    assert not second_worker.is_alive()


def test_shared_source_sensitive_caches_serializes_independent_scopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_count = 0
    worker_started = threading.Event()
    worker_entered = threading.Event()

    def fake_clear() -> None:
        nonlocal clear_count
        clear_count += 1

    def enter_worker_scope() -> None:
        worker_started.set()
        with call_graph.shared_source_sensitive_caches():
            worker_entered.set()

    monkeypatch.setattr(call_graph, "_clear_source_sensitive_caches_now", fake_clear)

    with call_graph.shared_source_sensitive_caches():
        worker = threading.Thread(target=enter_worker_scope)
        worker.start()
        assert worker_started.wait(timeout=1)
        assert not worker_entered.wait(timeout=0.05)

    assert worker_entered.wait(timeout=1)
    worker.join(timeout=1)
    assert not worker.is_alive()
    assert clear_count == 2


def test_shared_source_sensitive_caches_refreshes_between_outer_scopes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_scoped_rewritten_call_graph_source"
    module_path = module_dir / f"{module_name}.py"
    module_path.write_text("def invoke(command):\n    return command\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    _clear_call_graph_caches()
    payload = _global_call_payload(module_name, "invoke", _unicode_operand("echo rewritten"))

    try:
        with call_graph.shared_source_sensitive_caches():
            safe_report = scan_bytes(payload, source="scoped-source-safe.pkl")

        module_path.write_text(
            "import os\n\ndef invoke(command):\n    return os.system(command)\n",
            encoding="utf-8",
        )
        importlib.invalidate_caches()

        with call_graph.shared_source_sensitive_caches():
            dangerous_report = scan_bytes(payload, source="scoped-source-dangerous.pkl")
    finally:
        _clear_call_graph_caches()

    assert safe_report.verdict == SafetyVerdict.SUSPICIOUS
    assert not _has_critical_call_graph_finding(safe_report, module_name, "invoke", "os.system")
    assert dangerous_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(dangerous_report, module_name, "invoke", "os.system")


def test_shared_source_sensitive_caches_refreshes_changed_source_within_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_scoped_changed_call_graph_source"
    module_path = module_dir / f"{module_name}.py"
    module_path.write_text("def invoke(command):\n    return command\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    _clear_call_graph_caches()
    payload = _global_call_payload(module_name, "invoke", _unicode_operand("echo changed"))

    try:
        with call_graph.shared_source_sensitive_caches():
            safe_report = scan_bytes(payload, source="scoped-changed-safe.pkl")
            module_path.write_text(
                "import os\n\ndef invoke(command):\n    return os.system(command)\n",
                encoding="utf-8",
            )
            importlib.invalidate_caches()
            dangerous_report = scan_bytes(payload, source="scoped-changed-dangerous.pkl")
    finally:
        _clear_call_graph_caches()

    assert safe_report.verdict == SafetyVerdict.SUSPICIOUS
    assert not _has_critical_call_graph_finding(safe_report, module_name, "invoke", "os.system")
    assert dangerous_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(dangerous_report, module_name, "invoke", "os.system")


def test_shared_source_sensitive_caches_fails_closed_when_final_validation_observes_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_scoped_inflight_call_graph_source"
    module_path = module_dir / f"{module_name}.py"
    module_path.write_text("def invoke(command):\n    return command\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    _clear_call_graph_caches()
    payload = _global_call_payload(module_name, "invoke", _unicode_operand("echo inflight"))

    try:
        with call_graph.shared_source_sensitive_caches():
            safe_report = scan_bytes(payload, source="scoped-inflight-safe.pkl")
            real_ensure_stable = api_module._ensure_shared_source_snapshot_stable
            source_rewritten = False

            def rewrite_before_completion_check(report_generation: int | None) -> None:
                nonlocal source_rewritten
                if not source_rewritten:
                    module_path.write_text(
                        "import os\n\ndef invoke(command):\n    return os.system(command)\n",
                        encoding="utf-8",
                    )
                    importlib.invalidate_caches()
                    source_rewritten = True
                real_ensure_stable(report_generation)

            monkeypatch.setattr(api_module, "_ensure_shared_source_snapshot_stable", rewrite_before_completion_check)
            changed_report = scan_bytes(payload, source="scoped-inflight-changed.pkl")
    finally:
        _clear_call_graph_caches()

    assert safe_report.verdict == SafetyVerdict.SUSPICIOUS
    assert not _has_critical_call_graph_finding(safe_report, module_name, "invoke", "os.system")
    assert source_rewritten is True
    assert changed_report.status == ScanStatus.INCONCLUSIVE
    assert changed_report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(error.details.get("analysis") == "python_call_graph_source_stability" for error in changed_report.errors)


def test_shared_source_sensitive_caches_fails_closed_after_mid_report_refresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_scoped_mid_report_call_graph_source"
    module_path = module_dir / f"{module_name}.py"
    module_path.write_text("def invoke(command):\n    return command\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    _clear_call_graph_caches()
    payload = _global_call_payload(module_name, "invoke", _unicode_operand("echo mid-report"))

    try:
        with call_graph.shared_source_sensitive_caches():
            safe_report = scan_bytes(payload, source="scoped-mid-report-safe.pkl")
            real_startup_findings = api_module.find_startup_hook_write_call_graphs
            source_rewritten = False

            def rewrite_before_later_subpass(
                import_references: object,
                callable_invocations: object | None = None,
                *,
                callable_invocations_complete: bool = True,
            ) -> tuple[call_graph.StartupHookWriteFinding, ...]:
                nonlocal source_rewritten
                if not source_rewritten:
                    module_path.write_text(
                        "import os\n\ndef invoke(command):\n    return os.system(command)\n",
                        encoding="utf-8",
                    )
                    importlib.invalidate_caches()
                    source_rewritten = True
                return real_startup_findings(
                    import_references,
                    callable_invocations,
                    callable_invocations_complete=callable_invocations_complete,
                )

            monkeypatch.setattr(api_module, "find_startup_hook_write_call_graphs", rewrite_before_later_subpass)
            changed_report = scan_bytes(payload, source="scoped-mid-report-changed.pkl")
    finally:
        _clear_call_graph_caches()

    assert safe_report.verdict == SafetyVerdict.SUSPICIOUS
    assert not _has_critical_call_graph_finding(safe_report, module_name, "invoke", "os.system")
    assert source_rewritten is True
    assert changed_report.status == ScanStatus.INCONCLUSIVE
    assert changed_report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(error.details.get("analysis") == "python_call_graph_source_stability" for error in changed_report.errors)


def test_call_graph_report_avoids_runtime_distribution_discovery_during_benign_cache_population(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path_entry = str(tmp_path)
    monkeypatch.syspath_prepend(path_entry)
    monkeypatch.delitem(sys.path_importer_cache, path_entry, raising=False)
    importlib.invalidate_caches()
    payload = _global_call_payload("builtins", "print", _unicode_operand("echo benign"))
    real_startup_findings = api_module.find_startup_hook_write_call_graphs
    cache_populated = False
    runtime_distribution_discovery_calls = 0
    trusted_root = call_graph._TRUSTED_SITE_PACKAGE_PATHS[0]

    def runtime_packages_distributions() -> dict[str, list[str]]:
        nonlocal runtime_distribution_discovery_calls
        runtime_distribution_discovery_calls += 1
        return {}

    def runtime_distribution(_name: str) -> object:
        nonlocal runtime_distribution_discovery_calls
        runtime_distribution_discovery_calls += 1
        return object()

    # Distribution discovery can lazily import helper modules. It must remain
    # outside the report snapshot so benign initialization cannot churn it.
    monkeypatch.setattr(call_graph, "packages_distributions", runtime_packages_distributions)
    monkeypatch.setattr(call_graph, "distribution", runtime_distribution)
    monkeypatch.setattr(
        call_graph,
        "_STARTUP_DISTRIBUTION_ROOTS",
        {"probe": ((trusted_root / "probe.dist-info", tmp_path.resolve()),)},
    )
    _clear_call_graph_caches()

    def populate_before_later_subpass(
        import_references: object,
        callable_invocations: object | None = None,
        *,
        callable_invocations_complete: bool = True,
    ) -> tuple[call_graph.StartupHookWriteFinding, ...]:
        nonlocal cache_populated
        if not cache_populated:
            monkeypatch.setitem(
                sys.path_importer_cache,
                path_entry,
                FileFinder(path_entry, *call_graph._STANDARD_FILE_FINDER_LOADER_DETAILS),
            )
            cache_populated = True
        assert call_graph._installed_distribution_roots("probe") == (tmp_path.resolve(),)
        return real_startup_findings(
            import_references,
            callable_invocations,
            callable_invocations_complete=callable_invocations_complete,
        )

    monkeypatch.setattr(api_module, "find_startup_hook_write_call_graphs", populate_before_later_subpass)
    try:
        report = scan_bytes(payload, source="benign-mid-report-importer-population.pkl")
    finally:
        _clear_call_graph_caches()

    assert cache_populated is True
    assert runtime_distribution_discovery_calls == 0
    assert report.status == ScanStatus.COMPLETE
    assert not any(error.details.get("analysis") == "python_call_graph_source_stability" for error in report.errors)


def _env_without_pythonpath() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}


def _pickle_exec_child_code(body: str) -> str:
    return f"""
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])

sys.path.insert(0, str(module_dir))
{body}
"""


def test_iter_call_nodes_reuses_cached_walk(monkeypatch: pytest.MonkeyPatch) -> None:
    module = ast.parse(
        """
def bridge(target, command):
    callback = getattr(target, command)
    callback(command)
"""
    )
    bridge = module.body[0]
    assert isinstance(bridge, ast.FunctionDef)

    visits = 0
    original_visit = ast.NodeVisitor.visit

    def counting_visit(self: ast.NodeVisitor, node: ast.AST) -> Any:
        nonlocal visits
        visits += 1
        return original_visit(self, node)

    monkeypatch.setattr(ast.NodeVisitor, "visit", counting_visit)
    call_graph._iter_call_nodes.cache_clear()

    first = call_graph._iter_call_nodes(bridge)
    first_visit_count = visits
    second = call_graph._iter_call_nodes(bridge)

    assert first == second
    assert first_visit_count > 0
    assert visits == first_visit_count


def test_collect_function_import_aliases_reuses_cached_walk(monkeypatch: pytest.MonkeyPatch) -> None:
    module = ast.parse(
        """
def bridge():
    import os
    from subprocess import run
    return run
"""
    )
    bridge = module.body[0]
    assert isinstance(bridge, ast.FunctionDef)

    calls = 0
    original_collect_import_aliases = call_graph._collect_import_aliases

    def counting_collect_import_aliases(
        statements: tuple[ast.stmt, ...],
        module_name: str,
        is_package: bool,
    ) -> dict[str, str]:
        nonlocal calls
        calls += 1
        return original_collect_import_aliases(statements, module_name, is_package)

    monkeypatch.setattr(call_graph, "_collect_import_aliases", counting_collect_import_aliases)
    call_graph._collect_function_import_aliases.cache_clear()

    expected = {"os": "os", "run": "subprocess.run"}
    assert call_graph._collect_function_import_aliases(bridge, "benchmod", False) == expected
    assert call_graph._collect_function_import_aliases(bridge, "benchmod", False) == expected
    assert calls == 2


def test_parameter_controlled_names_reuses_cached_analysis(monkeypatch: pytest.MonkeyPatch) -> None:
    module = ast.parse(
        """
def bridge(command):
    alias = command
    return alias
"""
    )
    bridge = module.body[0]
    assert isinstance(bridge, ast.FunctionDef)

    calls = 0
    original_initial_parameter_controlled_names = call_graph._initial_parameter_controlled_names

    def counting_initial_parameter_controlled_names(
        function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> set[str]:
        nonlocal calls
        calls += 1
        return original_initial_parameter_controlled_names(function_node)

    monkeypatch.setattr(
        call_graph,
        "_initial_parameter_controlled_names",
        counting_initial_parameter_controlled_names,
    )
    call_graph._parameter_controlled_names.cache_clear()

    assert call_graph._parameter_controlled_names(bridge) == {"command", "alias"}
    assert call_graph._parameter_controlled_names(bridge) == {"command", "alias"}
    assert calls == 1


def test_split_function_name_reuses_cached_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    analyze_calls: list[str] = []

    class _AnalyzedModule:
        pass

    def fake_analyze_module(module_name: str) -> _AnalyzedModule | None:
        analyze_calls.append(module_name)
        return _AnalyzedModule() if module_name == "pkg.mod" else None

    monkeypatch.setattr(call_graph, "_analyze_module", fake_analyze_module)
    call_graph._split_function_name.cache_clear()

    assert call_graph._split_function_name("pkg.mod.func") == ("pkg.mod", "func")
    assert call_graph._split_function_name("pkg.mod.func") == ("pkg.mod", "func")
    assert analyze_calls == ["pkg.mod"]


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


def _constructed_call_operand(module: str, name: str, *arg_operands: bytes) -> bytes:
    return b"".join([_global_operand(module, name), _args_tuple(*arg_operands), b"R"])


def _builtins_help_call_iterator_method_descriptor_payload(
    module: str,
    name: str,
    *method_arg_operands: bytes,
) -> bytes:
    return _builtins_help_call_iterator_stdlib_materializer_payload(module, name, *method_arg_operands)


def _builtins_help_call_iterator_operator_payload(
    name: str,
    *arg_operands: bytes,
) -> bytes:
    return _builtins_help_call_iterator_stdlib_materializer_payload("operator", name, *arg_operands)


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


def _builtins_help_heapq_key_callback_payload(name: str, iterable_operand: bytes) -> bytes:
    return _global_call_payload("heapq", name, b"K\x01", iterable_operand, _global_operand("builtins", "help"))


def _builtins_help_re_sub_payload(
    name: str,
    pattern: str,
    value: str,
    *extra_arg_operands: bytes,
) -> bytes:
    return _global_call_payload(
        "re",
        name,
        _unicode_operand(pattern),
        _global_operand("builtins", "help"),
        _unicode_operand(value),
        *extra_arg_operands,
    )


def _builtins_help_re_pattern_sub_payload(
    name: str,
    pattern: str,
    value: str,
    compile_flags_operand: bytes | None = None,
) -> bytes:
    compile_arguments: tuple[bytes, ...] = (_unicode_operand(pattern),)
    if compile_flags_operand is not None:
        compile_arguments = (_unicode_operand(pattern), compile_flags_operand)
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("re", "compile"),
            _args_tuple(*compile_arguments),
            b"R",
            b"\x94",
            b"0",
            _global_operand("re", f"Pattern.{name}"),
            _args_tuple(b"h\x00", _global_operand("builtins", "help"), _unicode_operand(value)),
            b"R.",
        ]
    )


def _builtins_help_re_scanner_payload(
    pattern: str,
    value: str,
    flags_operand: bytes | None = None,
) -> bytes:
    rule = _args_tuple(_unicode_operand(pattern), _global_operand("builtins", "help"))
    lexicon = _args_tuple(rule)
    scanner_arguments: tuple[bytes, ...] = (lexicon,)
    if flags_operand is not None:
        scanner_arguments = (lexicon, flags_operand)
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("re", "Scanner"),
            _args_tuple(*scanner_arguments),
            b"R",
            b"\x94",
            b"0",
            _global_operand("re", "Scanner.scan"),
            _args_tuple(b"h\x00", _unicode_operand(value)),
            b"R.",
        ]
    )


def _builtins_help_future_callback_payload(*, complete: bool = True) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("concurrent.futures", "Future"),
        _args_tuple(),
        b"R",
        b"\x94",
        b"0",
        _global_operand("concurrent.futures", "Future.add_done_callback"),
        _args_tuple(b"h\x00", _global_operand("builtins", "help")),
        b"R",
    ]
    if complete:
        parts.extend(
            [
                b"0",
                _global_operand("concurrent.futures", "Future.set_result"),
                _args_tuple(b"h\x00", _unicode_operand("owned-token")),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_done_future_add_callback_payload() -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("concurrent.futures", "Future"),
            _args_tuple(),
            b"R",
            b"\x94",
            b"0",
            _global_operand("concurrent.futures", "Future.set_result"),
            _args_tuple(b"h\x00", _unicode_operand("owned-token")),
            b"R",
            b"0",
            _global_operand("concurrent.futures", "Future.add_done_callback"),
            _args_tuple(b"h\x00", _global_operand("builtins", "help")),
            b"R.",
        ]
    )


def _builtins_help_weakref_callback_payload(name: str, *, with_callback: bool = True) -> bytes:
    referent = _global_operand("collections", "UserList") + _args_tuple() + b"R"
    arguments = (referent, _global_operand("builtins", "help")) if with_callback else (referent,)
    return _global_call_payload("weakref", name, *arguments)


def _builtins_help_weakmethod_callback_payload(*, with_callback: bool = True) -> bytes:
    instance = _global_operand("collections", "UserList") + _args_tuple() + b"R"
    bound_method = (
        _global_operand("collections", "UserList.append.__get__")
        + _args_tuple(instance, _global_operand("collections", "UserList"))
        + b"R"
    )
    arguments = (bound_method, _global_operand("builtins", "help")) if with_callback else (bound_method,)
    return _global_call_payload("weakref", "WeakMethod", *arguments)


def _builtins_help_tokenize_readline_payload(name: str, *, consume: bool) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("tokenize", name),
        _global_operand("builtins", "help"),
        b"\x85R",
    ]
    if consume:
        parts.extend(
            [
                b"\x94",
                b"0",
                _global_operand("builtins", "list"),
                b"h\x00",
                b"\x85R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


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


def _builtins_help_payload_after_import_prefix(import_names: list[str]) -> bytes:
    parts = [b"\x80\x04"]
    for name in import_names:
        parts.extend([_global_operand("builtins", name), b"0"])
    parts.extend(
        [
            _global_operand("builtins", "help"),
            _args_tuple(_unicode_operand("os")),
            b"R.",
        ]
    )
    return b"".join(parts)


def _duplicate_callable_invocation_budget_payload(repetitions: int) -> bytes:
    parts = [b"\x80\x04"]
    bool_invocation = b"".join(
        [
            _global_operand("builtins", "bool"),
            _args_tuple(_unicode_operand("safe")),
            b"R0",
        ]
    )
    for _ in range(repetitions):
        parts.append(bool_invocation)
    parts.extend(
        [
            _global_operand("builtins", "help"),
            _args_tuple(_unicode_operand("os")),
            b"R.",
        ]
    )
    return b"".join(parts)


def _builtins_help_defaultdict_format_map_payload(
    *,
    lookup: bool,
    format_string: str = "{x}",
    format_operand: bytes | None = None,
) -> bytes:
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
                _args_tuple(format_operand or _unicode_operand(format_string), b"h\x00"),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_defaultdict_str_format_payload(format_string: str, *format_arguments: bytes) -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("collections", "defaultdict"),
            _global_operand("builtins", "help"),
            b"\x85R",
            b"\x94",
            b"0",
            _global_operand("builtins", "str.format"),
            _args_tuple(_unicode_operand(format_string), *format_arguments),
            b"R.",
        ]
    )


def _builtins_help_defaultdict_operator_mod_payload(
    *,
    lookup: bool,
    operator_name: str = "mod",
    format_string: str = "%(x)s",
) -> bytes:
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
                _global_operand("operator", operator_name),
                _args_tuple(_unicode_operand(format_string), b"h\x00"),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_defaultdict_formatter_vformat_payload(*, lookup: bool, format_string: str = "{x}") -> bytes:
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
                _args_tuple(b"h\x00", _unicode_operand(format_string), b"N", b"h\x01"),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_defaultdict_formatter_private_vformat_payload(
    *,
    lookup: bool,
    format_string: str = "{x}",
) -> bytes:
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
                _args_tuple(b"h\x00", _unicode_operand(format_string), b"N", b"h\x01", b"\x8f", b"K\x02"),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _builtins_help_defaultdict_template_payload(method_name: str, template: str) -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("collections", "defaultdict"),
            _global_operand("builtins", "help"),
            b"\x85R",
            b"\x94",
            b"0",
            _global_operand("string", "Template"),
            _args_tuple(_unicode_operand(template)),
            b"R",
            b"\x94",
            b"0",
            _global_operand("string", method_name),
            _args_tuple(b"h\x01", b"h\x00"),
            b"R.",
        ]
    )


def _mapping_wrapper_getitem_payload(
    wrapper_module: str,
    wrapper_name: str,
    *,
    lookup: bool,
    default_factory: bool,
) -> bytes:
    parts = [b"\x80\x04"]
    if default_factory:
        parts.extend(
            [
                _global_operand("collections", "defaultdict"),
                _global_operand("builtins", "help"),
                b"\x85R",
            ]
        )
    else:
        parts.append(b"}")
    parts.extend(
        [
            b"\x94",
            b"0",
            _global_operand(wrapper_module, wrapper_name),
            _args_tuple(b"h\x00"),
            b"R",
        ]
    )
    if lookup:
        parts.extend(
            [
                b"\x94",
                b"0",
                _global_operand("operator", "getitem"),
                _args_tuple(b"h\x01", _unicode_operand("missing")),
                b"R",
            ]
        )
    parts.append(b".")
    return b"".join(parts)


def _chainmap_shadowed_defaultdict_getitem_payload() -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            b"}",
            b"\x94",
            _unicode_operand("present"),
            _unicode_operand("safe"),
            b"s",
            b"0",
            _global_operand("collections", "defaultdict"),
            _global_operand("builtins", "help"),
            b"\x85R",
            b"\x94",
            b"0",
            _global_operand("collections", "ChainMap"),
            b"h\x00",
            b"h\x01",
            b"\x86R",
            b"\x94",
            b"0",
            _global_operand("operator", "getitem"),
            b"h\x02",
            _unicode_operand("present"),
            b"\x86R.",
        ]
    )


def _chainmap_defaultdict_str_format_payload(*, key: str, format_string: str) -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            b"}",
            b"\x94",
            _unicode_operand(key),
            _unicode_operand("safe"),
            b"s",
            b"0",
            _global_operand("collections", "defaultdict"),
            _global_operand("builtins", "help"),
            b"\x85R",
            b"\x94",
            b"0",
            _global_operand("collections", "ChainMap"),
            b"h\x00",
            b"h\x01",
            b"\x86R",
            b"\x94",
            b"0",
            _global_operand("builtins", "str.format"),
            _args_tuple(_unicode_operand(format_string), b"h\x02"),
            b"R.",
        ]
    )


def _nested_defaultdict_str_format_payload() -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("collections", "defaultdict"),
            _global_operand("builtins", "help"),
            b"\x85R",
            b"\x94",
            b"0",
            b"}",
            b"\x94",
            _unicode_operand("present"),
            b"h\x00",
            b"s",
            b"0",
            _global_operand("builtins", "str.format"),
            _args_tuple(_unicode_operand("{0[present][missing]}"), b"h\x01"),
            b"R.",
        ]
    )


def _nested_setitems_defaultdict_str_format_payload() -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("collections", "defaultdict"),
            _global_operand("builtins", "help"),
            b"\x85R",
            b"\x94",
            b"0",
            b"}",
            b"\x94",
            b"(",
            _unicode_operand("present"),
            b"h\x00",
            b"u",
            b"0",
            _global_operand("builtins", "str.format"),
            _args_tuple(_unicode_operand("{0[present][missing]}"), b"h\x01"),
            b"R.",
        ]
    )


def _nested_defaultdict_format_map_payload() -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("collections", "defaultdict"),
            _global_operand("builtins", "help"),
            b"\x85R",
            b"\x94",
            b"0",
            b"}",
            b"\x94",
            _unicode_operand("present"),
            b"h\x00",
            b"s",
            b"0",
            _global_operand("builtins", "str.format_map"),
            _args_tuple(_unicode_operand("{present[missing]}"), b"h\x01"),
            b"R.",
        ]
    )


def _nested_defaultdict_formatter_payload(method_name: str) -> bytes:
    parts = [
        b"\x80\x04",
        _global_operand("string", "Formatter"),
        b")R",
        b"\x94",
        b"0",
        _global_operand("collections", "defaultdict"),
        _global_operand("builtins", "help"),
        b"\x85R",
        b"\x94",
        b"0",
        b"}",
        b"\x94",
        _unicode_operand("present"),
        b"h\x01",
        b"s",
        b"0",
        _global_operand("string", f"Formatter.{method_name}"),
    ]
    arguments = [b"h\x00", _unicode_operand("{present[missing]}"), b"N", b"h\x02"]
    if method_name == "_vformat":
        arguments.extend([b"\x8f", b"K\x02"])
    parts.extend([_args_tuple(*arguments), b"R."])
    return b"".join(parts)


def _nested_wrapped_defaultdict_str_format_payload(wrapper_module: str, wrapper_name: str) -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("collections", "defaultdict"),
            _global_operand("builtins", "help"),
            b"\x85R",
            b"\x94",
            b"0",
            b"}",
            b"\x94",
            _unicode_operand("present"),
            b"h\x00",
            b"s",
            b"0",
            _global_operand(wrapper_module, wrapper_name),
            _args_tuple(b"h\x01"),
            b"R",
            b"\x94",
            b"0",
            _global_operand("builtins", "str.format"),
            _args_tuple(_unicode_operand("{0[present][missing]}"), b"h\x02"),
            b"R.",
        ]
    )


def _memoized_nested_defaultdict_str_format_payload() -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            b"}",
            b"\x94",
            b"0",
            b"}",
            b"\x94",
            _unicode_operand("present"),
            b"h\x00",
            b"s",
            b"0",
            b"h\x00",
            _unicode_operand("nested"),
            _global_operand("collections", "defaultdict"),
            _global_operand("builtins", "help"),
            b"\x85R",
            b"s",
            b"0",
            _global_operand("builtins", "str.format"),
            _args_tuple(_unicode_operand("{0[present][nested][missing]}"), b"h\x01"),
            b"R.",
        ]
    )


def _deep_mapping_proxy_defaultdict_getitem_payload(depth: int) -> bytes:
    if not 1 <= depth <= 255:
        raise ValueError("depth must fit one-byte memo references")

    parts = [
        b"\x80\x04",
        _global_operand("collections", "defaultdict"),
        _global_operand("builtins", "help"),
        b"\x85R",
        b"\x94",
    ]
    for memo_index in range(depth):
        parts.extend(
            [
                b"0",
                _global_operand("types", "MappingProxyType"),
                b"h" + bytes([memo_index]),
                b"\x85R",
                b"\x94",
            ]
        )
    parts.extend(
        [
            b"0",
            _global_operand("operator", "getitem"),
            b"h" + bytes([depth]),
            _unicode_operand("missing"),
            b"\x86R.",
        ]
    )
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


def _ipaddress_str_format_payload(format_string: str = "{:b}", *, format_operand: bytes | None = None) -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("ipaddress", "IPv4Address"),
            _args_tuple(_unicode_operand("1.2.3.4")),
            b"R",
            b"\x94",
            b"0",
            _global_operand("builtins", "str.format"),
            _args_tuple(format_operand or _unicode_operand(format_string), b"h\x00"),
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


def _has_call_graph_source_unavailable_notice(
    report: PickleReport,
    module: str,
    name: str,
    reason: str,
) -> bool:
    return any(
        notice.code == "call_graph_source_unavailable"
        and notice.details.get("module") == module
        and notice.details.get("name") == name
        and notice.details.get("reason") == reason
        for notice in report.notices
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


def _run_python_subprocess(args: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd),
        env=_env_without_pythonpath(),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_scan_bytes_retains_late_invocation_after_duplicate_metadata_budget() -> None:
    parts = [b"\x80\x04"]
    for _ in range(10_000):
        parts.extend([_global_operand("builtins", "bool"), b")R0"])
    parts.extend([_global_operand("builtins", "help"), _args_tuple(_unicode_operand("os")), b"R."])

    report = scan_bytes(b"".join(parts), source="duplicate-invocation-budget-help-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "_sitebuiltins",
        "_Helper.__call__",
        "builtins.__import__",
    )
    callable_invocations = report.metadata.get("callable_invocations", [])
    assert (
        sum(
            invocation.get("module") == "builtins" and invocation.get("name") == "bool"
            for invocation in callable_invocations
        )
        == 1
    )
    assert any(
        invocation.get("module") == "builtins" and invocation.get("name") == "help"
        for invocation in callable_invocations
    )


def test_scan_bytes_retains_callable_aliases_at_import_reference_limit() -> None:
    benign_builtins = [
        "abs",
        "all",
        "any",
        "ascii",
        "bin",
        "callable",
        "chr",
        "divmod",
        "enumerate",
        "filter",
        "float",
        "format",
        "frozenset",
        "hash",
        "hex",
        "id",
        "int",
        "isinstance",
        "issubclass",
        "iter",
        "len",
        "list",
        "map",
        "max",
        "min",
        "next",
        "oct",
        "ord",
        "pow",
        "repr",
        "round",
    ]
    parts = [b"\x80\x04"]
    for name in benign_builtins:
        parts.extend([_global_operand("builtins", name), b"0"])
    parts.extend([_global_operand("builtins", "help"), _args_tuple(_unicode_operand("os")), b"R."])

    report = scan_bytes(b"".join(parts), source="import-reference-limit-help-alias-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "_sitebuiltins",
        "_Helper.__call__",
        "builtins.__import__",
    )


@pytest.mark.parametrize("function_name", ["harmless_nested_def", "harmless_lambda"])
def test_scan_bytes_ignores_uninvoked_nested_function_body_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    function_name: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "nested_body_marker"
    command_args = (sys.executable, str(marker))
    module_name = "modelaudit_fp_probe_nested_body"
    (module_dir / f"{module_name}.py").write_text(
        "import subprocess\n\n"
        "_WRITE_CMD = \"from pathlib import Path; Path(__import__('sys').argv[1]).write_text('owned')\"\n\n"
        "def harmless_nested_def(value):\n"
        "    def inner():\n"
        "        subprocess.run([value[0], '-c', _WRITE_CMD, value[1]], check=True)\n"
        "    return value\n\n"
        "def harmless_lambda(value):\n"
        "    inner = lambda: subprocess.run([value[0], '-c', _WRITE_CMD, value[1]], check=True)\n"
        "    return value\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(module_dir))
    payload = _global_call_payload(
        module_name,
        function_name,
        _unicode_operand(command_args[0]) + _unicode_operand(command_args[1]) + b"\x86",
    )

    report = scan_bytes(payload, source=f"{function_name}-nested-body-clean.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert not _has_critical_call_graph_finding(report, module_name, function_name, "subprocess.run")
    child_code = _pickle_exec_child_code(
        """
pickle.loads(payload)
if marker.exists():
    raise SystemExit("nested body unexpectedly executed")
"""
    )
    result = _run_python_subprocess(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=tmp_path.parent,
    )
    assert result.returncode == 0, result.stderr


def test_scan_bytes_does_not_treat_newobj_as_init_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "newobj_init_marker"
    command = f"{sys.executable} -c \"from pathlib import Path; Path({str(marker)!r}).write_text('owned')\""
    module_name = "modelaudit_fp_probe_newobj_init"
    (module_dir / f"{module_name}.py").write_text(
        "import os\n\n"
        "class InitImports:\n"
        "    def __init__(self):\n"
        f"        os.system({command!r})\n"
        "    def __setstate__(self, state):\n"
        "        self.__dict__.update(state)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(module_dir))
    module = importlib.import_module(module_name)
    target_type = module.InitImports
    instance = target_type.__new__(target_type)
    instance.value = "safe"
    payload = pickle.dumps(instance, protocol=4)

    report = scan_bytes(payload, source="newobj-init-import-clean.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert not _has_critical_call_graph_finding(report, module_name, "InitImports", "os.system")
    child_code = _pickle_exec_child_code(
        """
result = pickle.loads(payload)
if getattr(result, "value", None) != "safe":
    raise SystemExit(f"unexpected state: {result.__dict__!r}")
if marker.exists():
    raise SystemExit("NEWOBJ unexpectedly executed __init__")
"""
    )
    result = _run_python_subprocess(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=tmp_path.parent,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("function_name", ["nested_default_executes", "lambda_default_executes"])
def test_scan_bytes_preserves_nested_signature_execution_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    function_name: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_probe_nested_signature"
    (module_dir / f"{module_name}.py").write_text(
        "import os\n\n"
        "def nested_default_executes(value):\n"
        "    def inner(result=os.system(value)):\n"
        "        return result\n"
        "    return value\n\n"
        "def lambda_default_executes(value):\n"
        "    inner = lambda result=os.system(value): result\n"
        "    return value\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(module_dir))

    report = scan_bytes(
        _global_call_payload(module_name, function_name, _unicode_operand("echo nested-signature")),
        source=f"{function_name}-nested-signature-rce.pkl",
    )

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, module_name, function_name, "os.system")


@pytest.mark.parametrize("helper_name", ["execsitecustomize", "execusercustomize"])
def test_call_graph_models_site_customization_import_statements(helper_name: str) -> None:
    function_name = f"site.{helper_name}"

    assert "builtins.__import__" in (call_graph._calls_for_function(function_name) or ())
    assert call_graph._find_sink_path(function_name) == (function_name, "builtins.__import__")


def test_call_graph_models_direct_shadowable_function_body_imports() -> None:
    calls = call_graph._calls_for_function("base64.main") or ()

    assert "builtins.__import__" in calls
    assert call_graph._find_sink_path("base64.main") == ("base64.main", "builtins.__import__")


def test_call_graph_treats_proven_frozen_function_body_import_as_safe() -> None:
    if FrozenImporter.find_spec("ntpath") is None:
        pytest.skip("ntpath is not frozen on this interpreter")

    assert call_graph._import_module_can_execute_user_code("ntpath") is False


def test_call_graph_does_not_trust_dotted_name_under_frozen_module() -> None:
    if FrozenImporter.find_spec("ntpath") is None:
        pytest.skip("ntpath is not frozen on this interpreter")

    assert call_graph._import_module_can_execute_user_code("ntpath.attacker") is True


def test_call_graph_fails_closed_when_custom_finder_can_shadow_frozen_function_body_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if FrozenImporter.find_spec("ntpath") is None:
        pytest.skip("ntpath is not frozen on this interpreter")
    marker = tmp_path / "meta_path_called"

    class CustomMetaPathFinder:
        @staticmethod
        def find_spec(
            fullname: str,
            path: object | None = None,
            target: object | None = None,
        ) -> ModuleSpec | None:
            del path, target
            if fullname == "ntpath":
                marker.write_text(fullname, encoding="utf-8")
                return ModuleSpec(fullname, loader=None, origin="custom://module")
            return None

    with monkeypatch.context() as context:
        context.delitem(sys.modules, "ntpath", raising=False)
        context.setattr(sys, "meta_path", [CustomMetaPathFinder(), *sys.meta_path])
        _clear_call_graph_caches()

        try:
            assert call_graph._import_module_can_execute_user_code("ntpath") is True
        finally:
            _clear_call_graph_caches()

    assert not marker.exists()


def test_call_graph_keeps_module_dict_dotted_lookup_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_probe_dict_dunder_getattr"
    (module_dir / f"{module_name}.py").write_text(
        "import os\n\ndef __getattr__(name):\n    os.system(name)\n    raise AttributeError(name)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    _clear_call_graph_caches()

    try:
        findings = call_graph.find_dangerous_call_graphs(
            [{"module": module_name, "name": "__dict__.values", "import_reference": f"{module_name}.__dict__.values"}]
        )
    finally:
        _clear_call_graph_caches()

    assert findings == ()


def test_call_graph_models_missing_dotted_dunder_module_getattr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_probe_missing_dunder_getattr"
    (module_dir / f"{module_name}.py").write_text(
        "import os\n\ndef __getattr__(name):\n    os.system(name)\n    raise AttributeError(name)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    _clear_call_graph_caches()

    try:
        findings = call_graph.find_dangerous_call_graphs(
            [
                {
                    "module": module_name,
                    "name": "__missing__.x",
                    "import_reference": f"{module_name}.__missing__.x",
                }
            ]
        )
    finally:
        _clear_call_graph_caches()

    assert any(
        finding.module == module_name and finding.name == "__missing__.x" and finding.sink == "os.system"
        for finding in findings
    )


def test_scan_bytes_marks_zipimported_invoked_call_graph_source_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_tp_zip_call_graph_source"
    module_zip = tmp_path / "modules.zip"
    with zipfile.ZipFile(module_zip, "w") as archive:
        archive.writestr(
            f"{module_name}.py",
            "import os\n\ndef invoke(command):\n    return os.system(command)\n",
        )
    monkeypatch.syspath_prepend(str(module_zip))
    importlib.invalidate_caches()
    _clear_call_graph_caches()

    try:
        report = scan_bytes(
            _global_call_payload(module_name, "invoke", _unicode_operand("echo hidden")),
            source="zipimport-call-graph-source.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_call_graph_source_unavailable_notice(report, module_name, "invoke", "source_unavailable")


def test_scan_bytes_marks_zipimported_dotted_source_unavailable_without_parent_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_name = "modelaudit_tp_zip_parent_probe"
    module_name = f"{package_name}.child"
    marker = tmp_path / "parent_imported"
    module_zip = tmp_path / "modules.zip"
    with zipfile.ZipFile(module_zip, "w") as archive:
        archive.writestr(
            f"{package_name}/__init__.py",
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('imported')\n",
        )
        archive.writestr(
            f"{package_name}/child.py",
            "def invoke(command):\n    return command\n",
        )
    monkeypatch.syspath_prepend(str(module_zip))
    importlib.invalidate_caches()
    _clear_call_graph_caches()

    try:
        report = scan_bytes(
            _global_call_payload(module_name, "invoke", _unicode_operand("echo hidden")),
            source="zipimport-dotted-call-graph-source.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_call_graph_source_unavailable_notice(report, module_name, "invoke", "source_unavailable")
    assert not marker.exists()


def test_scan_bytes_marks_lookup_failures_as_unanalyzable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_tp_lookup_failure_probe"

    def raise_lookup_failure(_: str) -> None:
        raise RuntimeError("lookup failed")

    monkeypatch.setattr(call_graph, "_find_module_spec_without_imports", raise_lookup_failure)
    _clear_call_graph_caches()

    try:
        report = scan_bytes(
            _global_call_payload(module_name, "invoke", _unicode_operand("echo hidden")),
            source="lookup-failure-call-graph-source.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_call_graph_source_unavailable_notice(report, module_name, "invoke", "source_unavailable")


def test_scan_bytes_fails_closed_when_custom_meta_path_finder_can_shadow_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_source_available_meta_path_probe"
    (module_dir / f"{module_name}.py").write_text("def invoke(command):\n    return command\n", encoding="utf-8")
    marker = tmp_path / "meta_path_called"

    class CustomMetaPathFinder:
        @staticmethod
        def find_spec(
            fullname: str,
            path: object | None = None,
            target: object | None = None,
        ) -> ModuleSpec | None:
            del path, target
            if fullname == module_name:
                marker.write_text(fullname, encoding="utf-8")
                return ModuleSpec(fullname, loader=None, origin="custom://module")
            return None

    monkeypatch.syspath_prepend(str(module_dir))
    monkeypatch.setattr(sys, "meta_path", [CustomMetaPathFinder(), *sys.meta_path])
    importlib.invalidate_caches()
    _clear_call_graph_caches()

    try:
        report = scan_bytes(
            _global_call_payload(module_name, "invoke", _unicode_operand("echo benign")),
            source="source-available-call-graph-source.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)
    assert _has_call_graph_source_unavailable_notice(report, module_name, "invoke", "source_unavailable")
    assert not marker.exists()


def test_call_graph_fails_closed_for_meta_path_finder_installed_before_import(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_preimport_meta_path_probe"
    (module_dir / f"{module_name}.py").write_text(
        "def invoke(command):\n    return command\n",
        encoding="utf-8",
    )
    marker = tmp_path / "preimport_meta_path_called"
    child_code = """
import sys
from importlib.machinery import ModuleSpec
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
module_name = sys.argv[3]

class PreexistingMetaPathFinder:
    @staticmethod
    def find_spec(fullname, path=None, target=None):
        del path, target
        if fullname == module_name:
            marker.write_text(fullname, encoding="utf-8")
            return ModuleSpec(fullname, loader=None, origin="custom://module")
        return None

sys.path.insert(0, str(module_dir))
sys.meta_path.insert(0, PreexistingMetaPathFinder())
from modelaudit_picklescan.call_graph import _call_graph_source_unavailable_reason

reason = _call_graph_source_unavailable_reason(module_name)
if reason != "source_unavailable":
    raise SystemExit(f"unexpected source reason: {reason!r}")
if marker.exists():
    raise SystemExit("pre-existing finder was invoked")
"""

    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), module_name],
        cwd=str(tmp_path),
        env=dict(os.environ),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert not marker.exists()


def test_scan_bytes_fails_closed_for_late_loaded_stdlib_source_modules_without_invoking_custom_meta_path_finders(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "meta_path_called"
    child_code = """
import sys
from importlib.machinery import ModuleSpec
from pathlib import Path

import modelaudit_picklescan.call_graph as call_graph
from modelaudit_picklescan import SafetyVerdict, ScanStatus, scan_bytes

module_name = "statistics"
marker = Path(sys.argv[1])
if module_name in sys.modules:
    raise SystemExit("statistics was loaded before the call-graph trust snapshot")

import statistics

class CustomMetaPathFinder:
    @staticmethod
    def find_spec(fullname, path=None, target=None):
        del path, target
        if fullname == module_name:
            marker.write_text(fullname, encoding="utf-8")
            return ModuleSpec(fullname, loader=None, origin="custom://module")
        return None

sys.meta_path.insert(0, CustomMetaPathFinder())
for function in call_graph._SOURCE_SENSITIVE_CACHED_FUNCTIONS:
    function.cache_clear()
payload = b"\\x80\\x04\\x8c\\x0astatistics\\x8c\\x04mean\\x93]\\x85R."
report = scan_bytes(payload, source="stdlib-source-call-graph-source.pkl")
if report.status != ScanStatus.COMPLETE or report.verdict != SafetyVerdict.SUSPICIOUS:
    raise SystemExit(f"unexpected report: {report.to_dict()!r}")
if not any(
    finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
    and finding.details.get("import_reference") == "statistics.mean"
    for finding in report.findings
):
    raise SystemExit(f"unexpected findings: {report.to_dict()!r}")
if marker.exists():
    raise SystemExit("custom meta-path finder was invoked")
if statistics.mean([1, 2, 3]) != 2:
    raise SystemExit("statistics.mean changed")
"""

    result = subprocess.run(
        [sys.executable, "-c", child_code, str(marker)],
        cwd=str(tmp_path),
        env=dict(os.environ),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert not marker.exists()


def test_scan_bytes_keeps_frozen_stdlib_globals_clean_without_custom_meta_path_finders(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "_frozen_importlib"
    marker = tmp_path / "meta_path_called"

    class CustomMetaPathFinder:
        @staticmethod
        def find_spec(
            fullname: str,
            path: object | None = None,
            target: object | None = None,
        ) -> ModuleSpec | None:
            del path, target
            if fullname == module_name:
                marker.write_text(fullname, encoding="utf-8")
                return ModuleSpec(fullname, loader=None, origin="custom://module")
            return None

    monkeypatch.setattr(sys, "meta_path", [CustomMetaPathFinder(), *sys.meta_path])
    _clear_call_graph_caches()

    try:
        report = scan_bytes(
            pickle.dumps(importlib.machinery.ModuleSpec("x", None), protocol=4),
            source="frozen-stdlib-call-graph-source.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not _has_call_graph_source_unavailable_notice(report, module_name, "ModuleSpec", "source_unavailable")
    assert not marker.exists()


def test_call_graph_trusts_only_exact_builtin_module_names() -> None:
    assert call_graph._call_graph_source_unavailable_reason("_io") is None
    assert call_graph._call_graph_source_unavailable_reason("_io.nonexistent") == "source_unavailable"


def test_call_graph_fails_closed_when_custom_meta_path_finder_can_shadow_frozen_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "__hello__"
    marker = tmp_path / "meta_path_called"

    class CustomMetaPathFinder:
        @staticmethod
        def find_spec(
            fullname: str,
            path: object | None = None,
            target: object | None = None,
        ) -> ModuleSpec | None:
            del path, target
            if fullname == module_name:
                marker.write_text(fullname, encoding="utf-8")
                return ModuleSpec(fullname, loader=None, origin="custom://module")
            return None

    monkeypatch.delitem(sys.modules, module_name, raising=False)
    monkeypatch.setattr(sys, "meta_path", [CustomMetaPathFinder(), *sys.meta_path])
    _clear_call_graph_caches()

    try:
        assert call_graph._call_graph_source_unavailable_reason(module_name) == "source_unavailable"
    finally:
        _clear_call_graph_caches()

    assert not marker.exists()


def test_call_graph_keeps_path_extension_modules_analyzable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_tp_extension_module_probe"
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    (module_dir / f"{module_name}{EXTENSION_SUFFIXES[0]}").write_bytes(b"not imported")
    monkeypatch.syspath_prepend(str(module_dir))
    _clear_call_graph_caches()

    try:
        assert call_graph._call_graph_source_unavailable_reason(module_name) is None
    finally:
        _clear_call_graph_caches()


def test_scan_bytes_marks_custom_meta_path_specs_as_unanalyzable_without_invoking_finder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_tp_meta_path_spec_probe"
    marker = tmp_path / "meta_path_called"

    class CustomMetaPathFinder:
        @staticmethod
        def find_spec(
            fullname: str,
            path: object | None = None,
            target: object | None = None,
        ) -> ModuleSpec | None:
            del path, target
            if fullname == module_name:
                marker.write_text(fullname, encoding="utf-8")
                return ModuleSpec(fullname, loader=None, origin="custom://module")
            return None

    monkeypatch.setattr(sys, "meta_path", [CustomMetaPathFinder(), *sys.meta_path])
    _clear_call_graph_caches()

    try:
        report = scan_bytes(
            _global_call_payload(module_name, "invoke", _unicode_operand("echo hidden")),
            source="meta-path-spec-call-graph-source.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_call_graph_source_unavailable_notice(report, module_name, "invoke", "source_unavailable")
    assert not marker.exists()


def test_scan_bytes_marks_custom_path_entry_specs_as_unanalyzable_without_invoking_finder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_tp_path_entry_spec_probe"
    marker = tmp_path / "path_entry_finder_called"
    path_entry = str(tmp_path / "custom-path-entry")
    extension_dir = tmp_path / "extensions"
    extension_dir.mkdir()
    (extension_dir / f"{module_name}{EXTENSION_SUFFIXES[0]}").write_bytes(b"not imported")

    class CustomPathEntryFinder:
        @staticmethod
        def find_spec(fullname: str, target: object | None = None) -> ModuleSpec | None:
            del target
            if fullname == module_name:
                marker.write_text(fullname, encoding="utf-8")
                return ModuleSpec(fullname, loader=None, origin="custom://module")
            return None

    monkeypatch.setattr(sys, "path", [path_entry, str(extension_dir), *sys.path])
    monkeypatch.setitem(sys.path_importer_cache, path_entry, CustomPathEntryFinder())
    _clear_call_graph_caches()

    try:
        report = scan_bytes(
            _global_call_payload(module_name, "invoke", _unicode_operand("echo hidden")),
            source="path-entry-spec-call-graph-source.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)
    assert _has_call_graph_source_unavailable_notice(report, module_name, "invoke", "source_unavailable")
    assert not marker.exists()


def test_scan_bytes_treats_file_finder_subclass_as_untrusted_without_invoking_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_tp_file_finder_subclass"
    module_path = tmp_path / f"{module_name}.py"
    module_path.write_text("def invoke(value):\n    return value\n", encoding="utf-8")
    marker = tmp_path / "file_finder_subclass_called"

    class CustomFileFinder(FileFinder):
        def find_spec(self, fullname: str, target: object | None = None) -> ModuleSpec | None:
            del target
            marker.write_text(fullname, encoding="utf-8")
            return super().find_spec(fullname)

    path_entry = str(tmp_path)
    finder = CustomFileFinder(path_entry, (SourceFileLoader, SOURCE_SUFFIXES))
    monkeypatch.setattr(sys, "path", [path_entry, *sys.path])
    monkeypatch.setitem(sys.path_importer_cache, path_entry, finder)
    _clear_call_graph_caches()

    try:
        report = scan_bytes(
            _global_call_payload(module_name, "invoke", _unicode_operand("echo hidden")),
            source="file-finder-subclass-call-graph-source.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)
    assert _has_call_graph_source_unavailable_notice(report, module_name, "invoke", "source_unavailable")
    assert not marker.exists()


def test_scan_bytes_treats_custom_file_finder_loader_as_untrusted_without_invoking_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_tp_custom_file_finder_loader"
    module_path = tmp_path / f"{module_name}.py"
    module_path.write_text("def invoke(value):\n    return value\n", encoding="utf-8")
    marker = tmp_path / "custom_file_finder_loader_called"

    class CustomLoader(SourceFileLoader):
        def __init__(self, fullname: str, path: str) -> None:
            marker.write_text(f"{fullname}:{path}", encoding="utf-8")
            super().__init__(fullname, path)

    path_entry = str(tmp_path)
    finder = FileFinder(path_entry, (CustomLoader, SOURCE_SUFFIXES))
    monkeypatch.setattr(sys, "path", [path_entry, *sys.path])
    monkeypatch.setitem(sys.path_importer_cache, path_entry, finder)
    _clear_call_graph_caches()

    try:
        report = scan_bytes(
            _global_call_payload(module_name, "invoke", _unicode_operand("echo hidden")),
            source="custom-file-finder-loader-call-graph-source.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)
    assert _has_call_graph_source_unavailable_notice(report, module_name, "invoke", "source_unavailable")
    assert not marker.exists()


def test_scan_bytes_treats_shadowed_zipimporter_as_untrusted_without_invoking_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_tp_shadowed_zipimporter"
    archive_path = tmp_path / "modules.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(f"{module_name}.py", "def invoke(value):\n    return value\n")
    marker = tmp_path / "shadowed_zipimporter_called"

    finder = zipimporter(str(archive_path))
    original_find_spec = finder.find_spec

    def shadowed_find_spec(fullname: str, target: Any = None) -> ModuleSpec | None:
        marker.write_text(fullname, encoding="utf-8")
        return original_find_spec(fullname, target)

    object.__getattribute__(finder, "__dict__")["find_spec"] = shadowed_find_spec
    path_entry = str(archive_path)
    monkeypatch.setattr(sys, "path", [path_entry, *sys.path])
    monkeypatch.setitem(sys.path_importer_cache, path_entry, finder)
    _clear_call_graph_caches()

    try:
        report = scan_bytes(
            _global_call_payload(module_name, "invoke", _unicode_operand("echo hidden")),
            source="shadowed-zipimporter-call-graph-source.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)
    assert _has_call_graph_source_unavailable_notice(report, module_name, "invoke", "source_unavailable")
    assert not marker.exists()


def test_call_graph_honors_bytecode_precedence_over_later_extension(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_tp_bytecode_shadowing_extension"
    bytecode_dir = tmp_path / "bytecode"
    extension_dir = tmp_path / "extension"
    bytecode_dir.mkdir()
    extension_dir.mkdir()
    source_path = bytecode_dir / f"{module_name}.py"
    source_path.write_text("def invoke(command):\n    return command\n", encoding="utf-8")
    py_compile.compile(str(source_path), cfile=str(bytecode_dir / f"{module_name}.pyc"), doraise=True)
    source_path.unlink()
    (extension_dir / f"{module_name}{EXTENSION_SUFFIXES[0]}").write_bytes(b"not imported")
    monkeypatch.setattr(sys, "path", [str(bytecode_dir), str(extension_dir), *sys.path])
    importlib.invalidate_caches()
    _clear_call_graph_caches()

    try:
        assert call_graph._call_graph_source_unavailable_reason(module_name) == "source_unavailable"
    finally:
        _clear_call_graph_caches()


def test_call_graph_does_not_invoke_custom_path_hook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_tp_uncached_path_hook_probe"
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    (module_dir / f"{module_name}.py").write_text("def invoke(command):\n    return command\n", encoding="utf-8")
    marker = tmp_path / "path_hook_called"

    def custom_path_hook(path: str) -> object:
        marker.write_text(path, encoding="utf-8")
        raise ImportError

    monkeypatch.syspath_prepend(str(module_dir))
    monkeypatch.setattr(sys, "path_hooks", [custom_path_hook, *sys.path_hooks])
    sys.path_importer_cache.pop(str(module_dir), None)
    _clear_call_graph_caches()

    try:
        assert call_graph._call_graph_source_unavailable_reason(module_name) == "source_unavailable"
    finally:
        _clear_call_graph_caches()

    assert not marker.exists()


def test_call_graph_rejects_path_hook_with_spoofed_standard_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_tp_spoofed_path_hook_probe"
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    (module_dir / f"{module_name}.py").write_text("def invoke():\n    return None\n", encoding="utf-8")
    marker = tmp_path / "spoofed_path_hook_called"

    def spoofed_path_hook(path: str) -> object:
        marker.write_text(path, encoding="utf-8")
        raise ImportError

    spoofed_path_hook.__module__ = "_frozen_importlib_external"
    spoofed_path_hook.__qualname__ = "FileFinder.path_hook.<locals>.path_hook_for_FileFinder"
    monkeypatch.syspath_prepend(str(module_dir))
    monkeypatch.setattr(sys, "path_hooks", [spoofed_path_hook, *sys.path_hooks])
    sys.path_importer_cache.pop(str(module_dir), None)
    _clear_call_graph_caches()

    try:
        assert call_graph._call_graph_source_unavailable_reason(module_name) == "source_unavailable"
    finally:
        _clear_call_graph_caches()

    assert not marker.exists()


def test_call_graph_honors_zipimport_precedence_over_later_extension(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_tp_zip_shadowing_extension"
    zip_path = tmp_path / "modules.zip"
    extension_dir = tmp_path / "extension"
    extension_dir.mkdir()
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(f"{module_name}.py", "def invoke(command):\n    return command\n")
    (extension_dir / f"{module_name}{EXTENSION_SUFFIXES[0]}").write_bytes(b"not imported")
    monkeypatch.setattr(sys, "path", [str(zip_path), str(extension_dir), *sys.path])
    importlib.invalidate_caches()
    _clear_call_graph_caches()

    try:
        report = scan_bytes(
            _global_call_payload(module_name, "invoke", _unicode_operand("echo hidden")),
            source="zip-shadowing-extension.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)
    assert _has_call_graph_source_unavailable_notice(report, module_name, "invoke", "source_unavailable")


def test_call_graph_keeps_extension_precedence_over_later_zipimport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_tp_extension_shadowing_zip"
    extension_dir = tmp_path / "extension"
    extension_dir.mkdir()
    zip_path = tmp_path / "modules.zip"
    (extension_dir / f"{module_name}{EXTENSION_SUFFIXES[0]}").write_bytes(b"not imported")
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(f"{module_name}.py", "def invoke(command):\n    return command\n")
    monkeypatch.setattr(sys, "path", [str(extension_dir), str(zip_path), *sys.path])
    importlib.invalidate_caches()
    _clear_call_graph_caches()

    try:
        assert call_graph._call_graph_source_unavailable_reason(module_name) is None
    finally:
        _clear_call_graph_caches()


def test_scan_bytes_marks_bytecode_only_invoked_call_graph_source_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_bytecode_only_call_graph_source"
    source_path = module_dir / f"{module_name}.py"
    source_path.write_text("def invoke(command):\n    return command\n", encoding="utf-8")
    py_compile.compile(str(source_path), cfile=str(module_dir / f"{module_name}.pyc"), doraise=True)
    source_path.unlink()
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    _clear_call_graph_caches()

    try:
        report = scan_bytes(
            _global_call_payload(module_name, "invoke", _unicode_operand("echo hidden")),
            source="bytecode-only-call-graph-source.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_call_graph_source_unavailable_notice(report, module_name, "invoke", "source_unavailable")


def test_scan_bytes_refreshes_call_graph_after_source_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_rewritten_call_graph_source"
    module_path = module_dir / f"{module_name}.py"
    module_path.write_text("def invoke(command):\n    return command\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    _clear_call_graph_caches()
    payload = _global_call_payload(module_name, "invoke", _unicode_operand("echo rewritten"))

    try:
        safe_report = scan_bytes(payload, source="rewritten-call-graph-safe.pkl")

        module_path.write_text(
            "import os\n\ndef invoke(command):\n    return os.system(command)\n",
            encoding="utf-8",
        )
        importlib.invalidate_caches()
        dangerous_report = scan_bytes(payload, source="rewritten-call-graph-dangerous.pkl")
    finally:
        _clear_call_graph_caches()

    assert safe_report.verdict == SafetyVerdict.SUSPICIOUS
    assert not _has_critical_call_graph_finding(safe_report, module_name, "invoke", "os.system")
    assert dangerous_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(dangerous_report, module_name, "invoke", "os.system")


def test_scan_bytes_refreshes_invoked_import_fallback_after_source_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_rewritten_invoked_import_source"
    module_path = module_dir / f"{module_name}.py"
    module_path.write_text("def invoke(command):\n    return command\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    _clear_call_graph_caches()
    payload = _global_call_payload(module_name, "invoke", _unicode_operand("echo rewritten"))

    try:
        safe_report = scan_bytes(payload, source="rewritten-invoked-import-safe.pkl")

        module_path.write_text(
            "def invoke(command):\n    import modelaudit_tp_invoked_import_dependency\n    return command\n",
            encoding="utf-8",
        )
        importlib.invalidate_caches()
        dangerous_report = scan_bytes(payload, source="rewritten-invoked-import-dangerous.pkl")
    finally:
        _clear_call_graph_caches()

    assert safe_report.verdict == SafetyVerdict.SUSPICIOUS
    assert not _has_critical_call_graph_finding(safe_report, module_name, "invoke", "builtins.__import__")
    assert dangerous_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(dangerous_report, module_name, "invoke", "builtins.__import__")


def test_startup_hook_write_call_graph_refreshes_after_source_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_rewritten_startup_hook_source"
    module_path = module_dir / f"{module_name}.py"
    module_path.write_text(
        "def open_payload(path):\n    return path\n\ndef write_payload(handle, value):\n    return value\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    _clear_call_graph_caches()
    import_references = (
        {"module": module_name, "name": "open_payload"},
        {"module": module_name, "name": "write_payload"},
    )
    callable_invocations = import_references

    try:
        safe_findings = call_graph.find_startup_hook_write_call_graphs(import_references, callable_invocations)

        module_path.write_text(
            "def open_payload(path):\n    return open(path, 'w', encoding='utf-8')\n\n"
            "def write_payload(handle, value):\n    return handle.write(value)\n",
            encoding="utf-8",
        )
        importlib.invalidate_caches()
        dangerous_findings = call_graph.find_startup_hook_write_call_graphs(
            import_references,
            callable_invocations,
        )
    finally:
        _clear_call_graph_caches()

    assert safe_findings == ()
    assert len(dangerous_findings) == 1
    finding = dangerous_findings[0]
    assert finding.opener_import_reference == f"{module_name}.open_payload"
    assert finding.writer_import_reference == f"{module_name}.write_payload"
    assert finding.open_sink == "builtins.open"
    assert finding.write_sink == "handle.write"


def test_call_graph_propagates_wrapper_import_execution_fallbacks() -> None:
    calls = call_graph._calls_for_function("platform.mac_ver") or ()

    assert "platform._mac_ver_xml" in calls
    assert call_graph._find_sink_path("platform.mac_ver") == (
        "platform.mac_ver",
        "platform._mac_ver_xml",
        "builtins.__import__",
    )


def test_call_graph_ignores_imports_inside_nested_functions_until_called() -> None:
    calls = call_graph._calls_for_function("site.enablerlcompleter") or ()

    assert "builtins.__import__" not in calls
    assert call_graph._find_sink_path("site.enablerlcompleter") is None


def test_call_graph_models_getattr_default_callable_fallbacks() -> None:
    calls = call_graph._calls_for_function("platform._Processor.get") or ()

    assert "platform._Processor.from_subprocess" in calls
    assert call_graph._find_sink_path("platform._Processor.get") == (
        "platform._Processor.get",
        "platform._Processor.from_subprocess",
        "subprocess.check_output",
    )


def _is_typing_readonly_guard(statement: ast.stmt) -> bool:
    if not isinstance(statement, ast.If) or not isinstance(statement.test, ast.Call):
        return False
    test = statement.test
    return (
        isinstance(test.func, ast.Name)
        and test.func.id == "hasattr"
        and len(test.args) == 2
        and isinstance(test.args[0], ast.Name)
        and test.args[0].id == "typing"
        and isinstance(test.args[1], ast.Constant)
        and test.args[1].value == "ReadOnly"
    )


def _is_typing_get_type_hints_guard(statement: ast.stmt) -> bool:
    return (
        _is_typing_readonly_guard(statement)
        and isinstance(statement, ast.If)
        and any(
            isinstance(branch_statement, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "get_type_hints" for target in branch_statement.targets
            )
            for branch_statement in statement.body
        )
        and any(
            isinstance(branch_statement, ast.FunctionDef) and branch_statement.name == "get_type_hints"
            for branch_statement in statement.orelse
        )
    )


def _is_builtin_sentinel_guard(statement: ast.stmt) -> bool:
    if not isinstance(statement, ast.If) or not isinstance(statement.test, ast.Call):
        return False
    test = statement.test
    return (
        isinstance(test.func, ast.Name)
        and test.func.id == "hasattr"
        and len(test.args) == 2
        and isinstance(test.args[0], ast.Name)
        and test.args[0].id == "builtins"
        and isinstance(test.args[1], ast.Constant)
        and test.args[1].value == "sentinel"
    )


def test_runtime_guard_selects_live_typing_extensions_export() -> None:
    typing_extensions = pytest.importorskip("typing_extensions")
    source_path = Path(typing_extensions.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    guard = next(statement for statement in tree.body if _is_typing_get_type_hints_guard(statement))

    statements = call_graph._runtime_selected_module_statements(tree.body, "typing_extensions")

    assert guard not in statements
    if typing_extensions.get_type_hints is typing.get_type_hints:
        assert any(
            isinstance(statement, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "get_type_hints" for target in statement.targets)
            for statement in statements
        )
    else:
        assert any(
            isinstance(statement, ast.FunctionDef) and statement.name == "get_type_hints" for statement in statements
        )


def test_runtime_guard_selects_live_builtin_sentinel_branch() -> None:
    typing_extensions = pytest.importorskip("typing_extensions")
    source_path = Path(typing_extensions.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    guard = next((statement for statement in tree.body if _is_builtin_sentinel_guard(statement)), None)
    if guard is None:
        pytest.skip("installed typing_extensions has no builtins.sentinel runtime guard")

    statements = call_graph._runtime_selected_module_statements(tree.body, "typing_extensions")

    assert guard not in statements
    if hasattr(builtins, "sentinel"):
        assert any(
            isinstance(statement, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "sentinel" for target in statement.targets)
            for statement in statements
        )
    else:
        assert any(
            isinstance(statement, ast.ClassDef) and statement.name == "sentinel" for statement in statements
        )


def test_runtime_guard_keeps_dynamic_builtin_sentinel_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    typing_extensions = pytest.importorskip("typing_extensions")
    builtins_namespace = call_graph._IMPORT_RUNTIME_BUILTINS
    assert isinstance(builtins_namespace, dict)
    if "sentinel" in builtins_namespace:
        pytest.skip("builtins.sentinel is directly available")
    source_path = Path(typing_extensions.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    guard = next((statement for statement in tree.body if _is_builtin_sentinel_guard(statement)), None)
    if guard is None:
        pytest.skip("installed typing_extensions has no builtins.sentinel runtime guard")
    monkeypatch.setitem(builtins_namespace, "__getattr__", lambda _name: object())

    assert hasattr(builtins, "sentinel")
    statements = call_graph._runtime_selected_module_statements(tree.body, "typing_extensions")

    assert guard in statements


def test_runtime_guard_marks_unloaded_module_snapshot_unreusable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    typing_extensions = pytest.importorskip("typing_extensions")
    source_path = Path(typing_extensions.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    guard = next(statement for statement in tree.body if _is_typing_get_type_hints_guard(statement))
    assert isinstance(guard, ast.If)
    monkeypatch.delitem(sys.modules, "typing_extensions")

    with call_graph.shared_source_sensitive_caches():
        snapshot = call_graph._SHARED_SOURCE_SENSITIVE_SNAPSHOT.get()
        assert snapshot is not None
        snapshot.reusable = True

        assert call_graph._typing_extensions_runtime_guard_value(guard, "typing_extensions") is None
        assert snapshot.reusable is False


def test_runtime_guard_keeps_mutated_typing_extensions_export_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    typing_extensions = pytest.importorskip("typing_extensions")
    source_path = Path(typing_extensions.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    monkeypatch.setattr(typing_extensions, "get_type_hints", object())

    statements = call_graph._runtime_selected_module_statements(tree.body, "typing_extensions")

    assert any(_is_typing_get_type_hints_guard(statement) for statement in statements)


def test_runtime_guard_keeps_shared_replacement_alias_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    typing_extensions = pytest.importorskip("typing_extensions")
    source_path = Path(typing_extensions.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))

    def replacement(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {}

    monkeypatch.setattr(typing, "get_type_hints", replacement)
    monkeypatch.setattr(typing_extensions, "get_type_hints", replacement)

    statements = call_graph._runtime_selected_module_statements(tree.body, "typing_extensions")

    assert any(_is_typing_get_type_hints_guard(statement) for statement in statements)


def test_runtime_guard_keeps_source_location_forgery_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    typing_extensions = pytest.importorskip("typing_extensions")
    source_path = Path(typing_extensions.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    guard = next(statement for statement in tree.body if _is_typing_get_type_hints_guard(statement))
    assert isinstance(guard, ast.If)
    wrapper = next(
        statement
        for statement in guard.orelse
        if isinstance(statement, ast.FunctionDef) and statement.name == "get_type_hints"
    )

    def replacement(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {}

    forged_code = replacement.__code__.replace(
        co_filename=str(source_path),
        co_firstlineno=wrapper.lineno,
    )
    forged = FunctionType(forged_code, vars(typing_extensions), "get_type_hints")
    monkeypatch.setattr(typing_extensions, "get_type_hints", forged)

    statements = call_graph._runtime_selected_module_statements(tree.body, "typing_extensions")

    assert any(_is_typing_get_type_hints_guard(statement) for statement in statements)


def test_call_graph_models_version_gated_typing_extensions_definitions() -> None:
    pytest.importorskip("typing_extensions")

    function_name = "typing_extensions.get_type_hints"
    calls = call_graph._calls_for_function(function_name) or ()
    path = call_graph._find_sink_path(function_name)

    if hasattr(typing, "ReadOnly"):
        assert call_graph._resolve_function_target(function_name) == "typing.get_type_hints"
    else:
        assert call_graph._call_graph_entrypoints(function_name) == (function_name,)
        assert "typing.get_type_hints" in calls
    assert path is not None
    assert path[0] in {function_name, "typing.get_type_hints"}
    assert path[-1] in {"builtins.compile", "builtins.eval"}


def test_call_graph_models_required_arg_imports_when_pickle_supplies_args() -> None:
    import_references = [
        {
            "module": "_pyio",
            "name": "_open_code_with_warning",
            "import_reference": "_pyio._open_code_with_warning",
        }
    ]

    assert call_graph._find_sink_path("_pyio._open_code_with_warning") is None
    assert call_graph.find_dangerous_call_graphs(import_references) == ()
    assert (
        call_graph.find_dangerous_call_graphs(
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

    findings = call_graph.find_dangerous_call_graphs(
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

    assert call_graph.find_dangerous_call_graphs(import_references, constructor_only_invocations) == ()

    findings = call_graph.find_dangerous_call_graphs(import_references, callable_instance_invocations)

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
            "opcode": "REDUCE",
            "positional_arg_count": 0,
        }
    ]

    assert call_graph.find_dangerous_call_graphs(import_references) == ()

    findings = call_graph.find_dangerous_call_graphs(import_references, help_invocations)

    assert len(findings) == 1
    assert findings[0].module == "_sitebuiltins"
    assert findings[0].name == "_Helper.__call__"
    assert findings[0].sink == "builtins.__import__"
    assert findings[0].call_path == ("_sitebuiltins._Helper.__call__", "builtins.__import__")
    assert findings[0].invocation_import_reference == "builtins.help"
    assert findings[0].invocation_opcode == "REDUCE"


def test_scan_bytes_ignores_benign_torch_extension_metadata_globals() -> None:
    torch = pytest.importorskip("torch")
    if not all(hasattr(torch, name) for name in ("device", "float32", "Size")):
        pytest.skip("usable PyTorch API is unavailable")
    payload = pickle.dumps(
        {
            "device": torch.device("cpu"),
            "dtype": torch.float32,
            "shape": torch.Size([2, 3]),
        },
        protocol=4,
    )

    report = scan_bytes(payload, source="torch-extension-metadata-clean.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.rule_code == "DANGEROUS_CALL_GRAPH" for finding in report.findings)


def test_scan_bytes_detects_newobj_ex_required_keyword_only_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "newobj-ex-keyword-marker"
    (tmp_path / "modelaudit_tp_newobj_ex_helper.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('owned', encoding='utf-8')\n",
        encoding="utf-8",
    )
    (tmp_path / "modelaudit_tp_newobj_ex_target.py").write_text(
        "class Gadget:\n"
        "    def __new__(cls, *, token):\n"
        "        import modelaudit_tp_newobj_ex_helper\n"
        "        return super().__new__(cls)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()
    _clear_call_graph_caches()
    payload = b"\x80\x04cmodelaudit_tp_newobj_ex_target\nGadget\n)}\x8c\x05token\x8c\x01xs\x92."

    try:
        report = scan_bytes(payload, source="newobj-ex-required-keyword.pkl")
    finally:
        _clear_call_graph_caches()

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL_GRAPH"
        and finding.details.get("import_reference") == "modelaudit_tp_newobj_ex_target.Gadget"
        and finding.details.get("sink") == "builtins.__import__"
        for finding in report.findings
    )
    assert not marker.exists()

    subprocess.run(
        [
            sys.executable,
            "-c",
            f"import pickle, sys; sys.path.insert(0, {str(tmp_path)!r}); pickle.loads({payload!r})",
        ],
        check=True,
    )
    assert marker.read_text(encoding="utf-8") == "owned"


def test_scan_bytes_does_not_enter_newobj_ex_body_when_required_keyword_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "modelaudit_tp_newobj_ex_missing_keyword.py").write_text(
        "class Gadget:\n"
        "    def __new__(cls, *, token):\n"
        "        import modelaudit_tp_newobj_ex_missing_helper\n"
        "        return super().__new__(cls)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()
    _clear_call_graph_caches()
    payload = b"\x80\x04cmodelaudit_tp_newobj_ex_missing_keyword\nGadget\n)}\x92."

    try:
        report = scan_bytes(payload, source="newobj-ex-missing-keyword.pkl")
    finally:
        _clear_call_graph_caches()

    assert report.verdict != SafetyVerdict.MALICIOUS
    assert not any(
        finding.rule_code == "DANGEROUS_CALL_GRAPH" and finding.details.get("sink") == "builtins.__import__"
        for finding in report.findings
    )


def test_scan_bytes_fails_closed_on_opaque_newobj_ex_keyword_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "opaque-newobj-ex-keyword-marker"
    (tmp_path / "modelaudit_tp_opaque_newobj_ex_helper.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('owned', encoding='utf-8')\n",
        encoding="utf-8",
    )
    (tmp_path / "modelaudit_tp_opaque_newobj_ex_target.py").write_text(
        "class Gadget:\n"
        "    def __new__(cls, **kwargs):\n"
        "        import modelaudit_tp_opaque_newobj_ex_helper\n"
        "        return super().__new__(cls)\n",
        encoding="utf-8",
    )
    (tmp_path / "modelaudit_tp_opaque_newobj_ex_factory.py").write_text(
        "def make_kwargs():\n    return {}\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()
    _clear_call_graph_caches()
    payload = (
        b"\x80\x04cmodelaudit_tp_opaque_newobj_ex_target\nGadget\n)"
        b"cmodelaudit_tp_opaque_newobj_ex_factory\nmake_kwargs\n)R\x92."
    )

    try:
        report = scan_bytes(payload, source="opaque-newobj-ex-keywords.pkl")
    finally:
        _clear_call_graph_caches()

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL_GRAPH"
        and finding.details.get("import_reference") == "modelaudit_tp_opaque_newobj_ex_target.Gadget"
        and finding.details.get("sink") == "builtins.__import__"
        for finding in report.findings
    )
    assert _has_call_graph_source_unavailable_notice(
        report,
        "modelaudit_tp_opaque_newobj_ex_target",
        "Gadget",
        "invocation_metadata_incomplete",
    )
    assert not marker.exists()

    subprocess.run(
        [
            sys.executable,
            "-c",
            f"import pickle, sys; sys.path.insert(0, {str(tmp_path)!r}); pickle.loads({payload!r})",
        ],
        check=True,
    )
    assert marker.read_text(encoding="utf-8") == "owned"


def test_incomplete_newobj_ex_invocation_is_not_hidden_by_complete_duplicate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_tp_duplicate_newobj_ex_metadata"
    (tmp_path / f"{module_name}.py").write_text(
        "class Gadget:\n    def __new__(cls, **kwargs):\n        return super().__new__(cls)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()
    _clear_call_graph_caches()
    invocations = (
        {
            "opcode": "NEWOBJ_EX",
            "module": module_name,
            "name": "Gadget",
            "positional_arg_count": 0,
            "keyword_args_complete": True,
            "keyword_arg_names": (),
            "global_position": 1,
        },
        {
            "opcode": "NEWOBJ_EX",
            "module": module_name,
            "name": "Gadget",
            "positional_arg_count": 0,
            "keyword_args_complete": False,
            "global_position": 2,
        },
    )

    try:
        references = call_graph.find_unanalyzed_callable_call_graph_references(invocations)
    finally:
        _clear_call_graph_caches()

    assert references == (
        call_graph.UnanalyzedCallGraphReference(
            module=module_name,
            name="Gadget",
            import_reference=f"{module_name}.Gadget",
            reason="invocation_metadata_incomplete",
        ),
    )


def test_scan_bytes_analyzes_shadowed_torch_extension_callable_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    (module_dir / "torch.py").write_text(
        "import os\n\ndef device(command):\n    os.system(command)\n    return command\n",
        encoding="utf-8",
    )
    monkeypatch.delitem(sys.modules, "torch", raising=False)
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    _clear_call_graph_caches()

    try:
        report = scan_bytes(
            _global_call_payload("torch", "device", _unicode_operand("echo shadowed-torch-device")),
            source="shadowed-torch-device-rce.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, "torch", "device", "os.system")


def test_scan_bytes_fails_closed_when_shadowed_torch_extension_analysis_hits_alias_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    (module_dir / "torch.py").write_text(
        """\
import os


class Dangerous:
    def __call__(self, command):
        os.system(command)


class Safe:
    def __call__(self, command):
        return command


if cond:
    device = Dangerous()
else:
    device = Safe()
""",
        encoding="utf-8",
    )
    monkeypatch.delitem(sys.modules, "torch", raising=False)
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    _clear_call_graph_caches()

    try:
        report = scan_bytes(
            _global_call_payload("torch", "device", _unicode_operand("echo shadowed-torch-device")),
            source="shadowed-torch-device-alias-limit.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.metadata["analysis_incomplete"] is True
    assert not any(error.category == "rust_engine_error" for error in report.errors)
    assert any(
        error.category == "call_graph_analysis_error" and error.exception_type == "_CallGraphAnalysisLimitError"
        for error in report.errors
    )


def test_scan_bytes_fails_closed_on_installed_package_alias_read_before_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "site-packages"
    module_dir.mkdir()
    module_name = "installed_alias_read_before_overwrite"
    (module_dir / f"{module_name}.py").write_text(
        """\
import os


class Dangerous:
    def __call__(self, command):
        os.system(command)


class Safe:
    def __call__(self, command):
        return command


class Final:
    def __call__(self, command):
        return command


if cond:
    entry = Dangerous()
else:
    entry = Safe()
exposed = entry
entry = Final()
""",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    _clear_call_graph_caches()

    try:
        report = scan_bytes(
            _global_call_payload(module_name, "exposed", _unicode_operand("echo hidden-branch")),
            source="installed-alias-read-before-overwrite.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.metadata["analysis_incomplete"] is True
    assert any(
        error.category == "call_graph_analysis_error" and error.exception_type == "_CallGraphAnalysisLimitError"
        for error in report.errors
    )


def test_call_graph_analyzes_shadowed_torch_storage_persistent_id_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    (module_dir / "torch.py").write_text(
        "import os\n\ndef __getattr__(name):\n    os.system(name)\n    raise AttributeError(name)\n",
        encoding="utf-8",
    )
    monkeypatch.delitem(sys.modules, "torch", raising=False)
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    _clear_call_graph_caches()

    try:
        findings = call_graph.find_dangerous_call_graphs(
            [
                {
                    "module": "torch",
                    "name": "FloatStorage",
                    "import_reference": "torch.FloatStorage",
                    "pytorch_storage_persistent_id": True,
                }
            ]
        )
    finally:
        _clear_call_graph_caches()

    assert any(
        finding.module == "torch" and finding.name == "FloatStorage" and finding.sink == "os.system"
        for finding in findings
    )


def test_call_graph_keeps_setstate_entrypoint_for_unknown_newobj_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_probe_unknown_newobj_setstate"
    (module_dir / f"{module_name}.py").write_text(
        "import os\n\n"
        "class Stateful:\n"
        "    def __new__(cls):\n"
        "        return super().__new__(cls)\n\n"
        "    def __setstate__(self, state):\n"
        "        os.system(state)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    _clear_call_graph_caches()

    try:
        findings = call_graph.find_dangerous_call_graphs(
            [],
            [
                {
                    "module": module_name,
                    "name": "Stateful",
                    "import_reference": f"{module_name}.Stateful",
                    "opcode": "NEWOBJ",
                    "positional_arg_count": None,
                }
            ],
        )
    finally:
        _clear_call_graph_caches()

    assert any(
        finding.module == module_name and finding.name == "Stateful" and finding.sink == "os.system"
        for finding in findings
    )


def test_scan_bytes_fails_closed_for_late_loaded_torch_layout_module_dict_lookup() -> None:
    torch = pytest.importorskip("torch")
    if not hasattr(torch, "strided"):
        pytest.skip("usable PyTorch API is unavailable")
    payload = pickle.dumps(torch.strided, protocol=4)

    report = scan_bytes(payload, source="torch-layout-clean.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == "torch.serialization._get_layout"
        for finding in report.findings
    )
    assert not any(finding.rule_code == "DANGEROUS_CALL_GRAPH" for finding in report.findings)


def test_scan_bytes_uses_torch_module_lifecycle_entrypoints_for_newobj() -> None:
    torch = pytest.importorskip("torch")
    if not hasattr(torch, "save") or not hasattr(torch, "nn"):
        pytest.skip("usable PyTorch API is unavailable")
    buffer = io.BytesIO()
    torch.save(torch.nn.Linear(2, 2), buffer)
    with zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as archive:
        data_pickle = archive.read("archive/data.pkl")

    report = scan_bytes(data_pickle, source="torch-linear-data-clean.pkl")

    assert not any(
        finding.rule_code == "DANGEROUS_CALL_GRAPH"
        and finding.details.get("module") == "torch.nn.modules.linear"
        and finding.details.get("name") == "Linear"
        for finding in report.findings
    )


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

    assert call_graph.find_dangerous_call_graphs(import_references, direct_invocations) == ()

    findings = call_graph.find_dangerous_call_graphs(import_references, protocol_invocations)

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

    assert call_graph.find_dangerous_call_graphs(import_references, direct_invocations) == ()

    findings = call_graph.find_dangerous_call_graphs(import_references, protocol_invocations)

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
    call_graph_finding = next(finding for finding in report.findings if finding.rule_code == "DANGEROUS_CALL_GRAPH")
    assert call_graph_finding.details["invocation_import_reference"] == "builtins.help"
    assert call_graph_finding.details["opcode"] == "REDUCE"

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


def test_scan_bytes_keeps_callable_invocation_aliases_at_import_reference_budget() -> None:
    safe_import_names = [
        "abs",
        "all",
        "any",
        "ascii",
        "bin",
        "bool",
        "bytearray",
        "bytes",
        "callable",
        "chr",
        "complex",
        "divmod",
        "enumerate",
        "float",
        "format",
        "frozenset",
        "hash",
        "hex",
        "id",
        "int",
        "isinstance",
        "issubclass",
        "iter",
        "len",
        "list",
        "max",
        "min",
        "next",
        "object",
        "oct",
        "ord",
    ]
    payload = _builtins_help_payload_after_import_prefix(safe_import_names)

    report = scan_bytes(payload, source="builtins-help-at-call-graph-reference-budget.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "_sitebuiltins",
        "_Helper.__call__",
        "builtins.__import__",
    )


def test_scan_bytes_dedupes_callable_invocations_before_metadata_cap() -> None:
    payload = _duplicate_callable_invocation_budget_payload(repetitions=10_000)

    report = scan_bytes(
        payload,
        source="duplicate-callable-invocation-budget.pkl",
        options=ScanOptions(max_opcodes=200_000),
    )

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
        and invocation.get("positional_arg_count") == 1
        for invocation in report.metadata.get("callable_invocations", [])
    )


def test_scan_bytes_ignores_nested_function_body_sink_when_outer_function_is_imported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_nested_fp_{tmp_path.name.replace('-', '_')}"
    (tmp_path / f"{module_name}.py").write_text(
        "def harmless(value):\n    def inner():\n        import os\n        os.system(value)\n    return value\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = b"".join([b"\x80\x04", _global_operand(module_name, "harmless"), b"."])

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)
    assert not any(finding.rule_code == "DANGEROUS_CALL_GRAPH" for finding in report.findings)


def test_scan_bytes_blocks_called_inline_lambda_body_sink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_inline_lambda_{tmp_path.name.replace('-', '_')}"
    marker = tmp_path / "inline_lambda_marker"
    command = f"{sys.executable} -c \"from pathlib import Path; Path({str(marker)!r}).write_text('owned')\""
    (tmp_path / f"{module_name}.py").write_text(
        "import os\n\ndef invoke(value):\n    return (lambda: os.system(value))()\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = _global_call_payload(module_name, "invoke", _unicode_operand(command))

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, module_name, "invoke", "os.system")


def test_scan_bytes_ignores_nested_import_aliases_outside_outer_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_nested_import_alias_{tmp_path.name.replace('-', '_')}"
    (tmp_path / f"{module_name}.py").write_text(
        "def run(value):\n"
        "    return value\n\n"
        "def harmless(value):\n"
        "    def inner():\n"
        "        from os import system as run\n"
        "        return run(value)\n"
        "    return run(value)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = _global_call_payload(module_name, "harmless", _unicode_operand("echo nested-alias"))

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert not _has_critical_call_graph_finding(report, module_name, "harmless", "os.system")


def test_scan_bytes_tracks_imported_callable_assignment_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_module = f"modelaudit_alias_target_{tmp_path.name.replace('-', '_')}"
    module_name = f"modelaudit_alias_probe_{tmp_path.name.replace('-', '_')}"
    (tmp_path / f"{target_module}.py").write_text(
        "import os\n\ndef wrapper(value):\n    return os.system(value)\n",
        encoding="utf-8",
    )
    (tmp_path / f"{module_name}.py").write_text(
        f"from {target_module} import wrapper\n\nalias = wrapper\n\ndef invoke(value):\n    return alias(value)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = _global_call_payload(module_name, "invoke", _unicode_operand("echo imported-alias"))

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, module_name, "invoke", "os.system")


def test_scan_bytes_follows_imported_class_constructor_entrypoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_module = f"modelaudit_class_target_{tmp_path.name.replace('-', '_')}"
    module_name = f"modelaudit_class_probe_{tmp_path.name.replace('-', '_')}"
    (tmp_path / f"{target_module}.py").write_text(
        "import os\n\nclass Evil:\n    def __init__(self, value):\n        os.system(value)\n",
        encoding="utf-8",
    )
    (tmp_path / f"{module_name}.py").write_text(
        f"from {target_module} import Evil\n\ndef invoke(value):\n    return Evil(value)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = _global_call_payload(module_name, "invoke", _unicode_operand("echo imported-class"))

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, module_name, "invoke", "os.system")


def test_scan_bytes_flags_setstate_import_execution_with_required_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload_module = f"modelaudit_setstate_payload_{tmp_path.name.replace('-', '_')}"
    module_name = f"modelaudit_setstate_probe_{tmp_path.name.replace('-', '_')}"
    marker = tmp_path / "setstate_import_marker"
    (tmp_path / f"{payload_module}.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('owned')\n",
        encoding="utf-8",
    )
    (tmp_path / f"{module_name}.py").write_text(
        "class Stateful:\n"
        "    def __setstate__(self, state):\n"
        f"        import {payload_module}\n"
        "        self.state = state\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = b"".join([b"\x80\x04", _global_operand(module_name, "Stateful"), b")\x81}b."])

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, module_name, "Stateful", "builtins.__import__")
    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])

sys.path.insert(0, str(module_dir))
pickle.loads(payload)
if not marker.exists():
    raise SystemExit("setstate import did not execute")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(tmp_path), str(marker), payload.hex()],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


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
    if "empty" not in str(exc):
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
result_repr = repr(result)
expected_ordered_dict_repr = None
if expected_repr.startswith("OrderedDict(") and expected_repr.endswith(")"):
    expected_ordered_dict_repr = expected_repr[len("OrderedDict(") : -1]
if result_repr != expected_repr and not (
    type(result).__name__ == "OrderedDict" and repr(dict(result)) == expected_ordered_dict_repr
):
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
    ("payload", "values_literal", "expected_repr", "requires_python_3_11_plus"),
    [
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("array", "array", _unicode_operand("i"), b"h\x00"),
            "[7, 'stop']",
            "array('i', [7])",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("collections", "Counter", b"h\x00"),
            "['owned-value', 'stop']",
            "Counter({'owned-value': 1})",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("collections", "OrderedDict", b"h\x00"),
            "[('owned-key', 'owned-value'), 'stop']",
            "OrderedDict({'owned-key': 'owned-value'})",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("collections", "UserDict", b"h\x00"),
            "[('owned-key', 'owned-value'), 'stop']",
            "{'owned-key': 'owned-value'}",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("collections", "UserList", b"h\x00"),
            "['owned-value', 'stop']",
            "['owned-value']",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("math", "prod", b"h\x00"),
            "[7, 'stop']",
            "7",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("math", "fsum", b"h\x00"),
            "[7, 'stop']",
            "7.0",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("heapq", "nlargest", b"K\x01", b"h\x00"),
            "['owned-value', 'stop']",
            "['owned-value']",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("heapq", "nlargest", b"K\x01", b"h\x00", b"N"),
            "['owned-value', 'stop']",
            "['owned-value']",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("heapq", "nsmallest", b"K\x01", b"h\x00"),
            "['owned-value', 'stop']",
            "['owned-value']",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("heapq", "nsmallest", b"K\x01", b"h\x00", b"N"),
            "['owned-value', 'stop']",
            "['owned-value']",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "fmean", b"h\x00"),
            "[7, 'stop']",
            "7.0",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "fmean", b"h\x00", b"N"),
            "[7, 'stop']",
            "7.0",
            True,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "geometric_mean", b"h\x00"),
            "[7, 'stop']",
            "6.999999999999999",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "harmonic_mean", b"h\x00"),
            "[7, 'stop']",
            "7",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload(
                "statistics",
                "harmonic_mean",
                b"h\x00",
                b"N",
            ),
            "[7, 'stop']",
            "7",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "mean", b"h\x00"),
            "[7, 'stop']",
            "7",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "median", b"h\x00"),
            "[7, 'stop']",
            "7",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "median_grouped", b"h\x00"),
            "[7, 'stop']",
            "7.0",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload(
                "statistics",
                "median_grouped",
                b"h\x00",
                b"K\x01",
            ),
            "[7, 'stop']",
            "7.0",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "median_high", b"h\x00"),
            "[7, 'stop']",
            "7",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "median_low", b"h\x00"),
            "[7, 'stop']",
            "7",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "mode", b"h\x00"),
            "[7, 7, 'stop']",
            "7",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "multimode", b"h\x00"),
            "[7, 7, 'stop']",
            "[7]",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "quantiles", b"h\x00"),
            "[7, 8, 'stop']",
            "[6.75, 7.5, 8.25]",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "pstdev", b"h\x00"),
            "[7, 7, 'stop']",
            "0.0",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "pstdev", b"h\x00", b"N"),
            "[7, 7, 'stop']",
            "0.0",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "pvariance", b"h\x00"),
            "[7, 7, 'stop']",
            "0",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "pvariance", b"h\x00", b"N"),
            "[7, 7, 'stop']",
            "0",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "stdev", b"h\x00"),
            "[7, 7, 'stop']",
            "0.0",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "stdev", b"h\x00", b"N"),
            "[7, 7, 'stop']",
            "0.0",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "variance", b"h\x00"),
            "[7, 7, 'stop']",
            "0",
            False,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload("statistics", "variance", b"h\x00", b"N"),
            "[7, 7, 'stop']",
            "0",
            False,
        ),
    ],
)
def test_scan_bytes_blocks_stdlib_eager_call_iterator_consumption_rce(
    tmp_path: Path,
    payload: bytes,
    values_literal: str,
    expected_repr: str,
    requires_python_3_11_plus: bool,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "stdlib_eager_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        f"_values = {values_literal}\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )

    report = scan_bytes(payload, source="stdlib-eager-call-iterator-rce.pkl")

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
    if requires_python_3_11_plus and sys.version_info < (3, 11):
        return
    child_code = """
import ast
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
result_repr = repr(result)
try:
    expected_value = ast.literal_eval(expected_repr)
except (SyntaxError, ValueError):
    expected_value = None
expected_ordered_dict_repr = None
if expected_repr.startswith("OrderedDict(") and expected_repr.endswith(")"):
    expected_ordered_dict_repr = expected_repr[len("OrderedDict(") : -1]
if result_repr != expected_repr and not (
    isinstance(result, (int, float))
    and isinstance(expected_value, (int, float))
    and result == expected_value
) and not (
    type(result).__name__ == "OrderedDict" and repr(dict(result)) == expected_ordered_dict_repr
):
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
    ("payload", "values_literal", "expected_repr", "requires_python_3_11_plus"),
    [
        (
            _builtins_help_call_iterator_stdlib_materializer_payload(
                "statistics",
                "fmean",
                _singleton_small_int_tuple_operand(7),
                b"h\x00",
            ),
            "[1, 'stop']",
            "7.0",
            True,
        ),
        (
            _builtins_help_call_iterator_stdlib_materializer_payload(
                "statistics",
                "harmonic_mean",
                _singleton_small_int_tuple_operand(7),
                b"h\x00",
            ),
            "[1, 'stop']",
            "7.0",
            False,
        ),
    ],
)
def test_scan_bytes_blocks_weighted_statistics_call_iterator_consumption_rce(
    tmp_path: Path,
    payload: bytes,
    values_literal: str,
    expected_repr: str,
    requires_python_3_11_plus: bool,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "weighted_statistics_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        f"_values = {values_literal}\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )

    report = scan_bytes(payload, source="weighted-statistics-call-iterator-rce.pkl")

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
    if requires_python_3_11_plus and sys.version_info < (3, 11):
        return

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


@pytest.mark.parametrize(
    ("payload", "values_literal", "expected_repr"),
    [
        (
            _builtins_help_call_iterator_method_descriptor_payload("builtins", "set.union", b"\x8f", b"h\x00"),
            "['owned-value', 'stop']",
            "{'owned-value'}",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload("builtins", "set.update", b"\x8f", b"h\x00"),
            "['owned-value', 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload("builtins", "set.intersection", b"\x8f", b"h\x00"),
            "['owned-value', 'stop']",
            "set()",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload("builtins", "set.difference", b"\x8f", b"h\x00"),
            "['owned-value', 'stop']",
            "set()",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "builtins",
                "set.difference_update",
                b"\x8f",
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "builtins",
                "set.symmetric_difference",
                b"\x8f",
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "{'owned-value'}",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "builtins",
                "set.symmetric_difference_update",
                b"\x8f",
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "builtins",
                "set.intersection_update",
                b"\x8f",
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload("builtins", "set.isdisjoint", b"\x8f", b"h\x00"),
            "['owned-value', 'stop']",
            "True",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "builtins",
                "frozenset.union",
                _constructed_call_operand("builtins", "frozenset"),
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "frozenset({'owned-value'})",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "builtins",
                "frozenset.difference",
                _constructed_call_operand("builtins", "frozenset"),
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "frozenset()",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "builtins",
                "frozenset.isdisjoint",
                _constructed_call_operand("builtins", "frozenset"),
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "True",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload("builtins", "set.__init__", b"\x8f", b"h\x00"),
            "['owned-value', 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload("builtins", "dict.update", b"}", b"h\x00"),
            "[('owned-key', 'owned-value'), 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "builtins",
                "dict.fromkeys",
                b"h\x00",
                _unicode_operand("owned-value"),
            ),
            "['owned-key', 'stop']",
            "{'owned-key': 'owned-value'}",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload("builtins", "list.extend", b"]", b"h\x00"),
            "['owned-value', 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "builtins",
                "bytearray.extend",
                _constructed_call_operand("builtins", "bytearray", b"C\x00"),
                b"h\x00",
            ),
            "[65, 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "collections",
                "deque.extend",
                _constructed_call_operand("collections", "deque"),
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "array",
                "array.extend",
                _constructed_call_operand("array", "array", _unicode_operand("i")),
                b"h\x00",
            ),
            "[7, 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "collections",
                "Counter.update",
                _constructed_call_operand("collections", "Counter"),
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "collections",
                "Counter.subtract",
                _constructed_call_operand("collections", "Counter"),
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "collections",
                "OrderedDict.update",
                _constructed_call_operand("collections", "OrderedDict"),
                b"h\x00",
            ),
            "[('owned-key', 'owned-value'), 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "collections",
                "UserList.extend",
                _constructed_call_operand("collections", "UserList"),
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "collections",
                "UserDict.update",
                _constructed_call_operand("collections", "UserDict"),
                b"h\x00",
            ),
            "[('owned-key', 'owned-value'), 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "collections",
                "ChainMap.update",
                _constructed_call_operand("collections", "ChainMap"),
                b"h\x00",
            ),
            "[('owned-key', 'owned-value'), 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "collections",
                "defaultdict.update",
                _constructed_call_operand("collections", "defaultdict"),
                b"h\x00",
            ),
            "[('owned-key', 'owned-value'), 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "collections",
                "OrderedDict.__init__",
                _constructed_call_operand("collections", "OrderedDict"),
                b"h\x00",
            ),
            "[('owned-key', 'owned-value'), 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "collections",
                "defaultdict.__init__",
                _constructed_call_operand("collections", "defaultdict"),
                b"N",
                b"h\x00",
            ),
            "[('owned-key', 'owned-value'), 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "collections",
                "Counter.__init__",
                _constructed_call_operand("collections", "Counter"),
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "collections",
                "UserDict.__init__",
                _constructed_call_operand("collections", "UserDict"),
                b"h\x00",
            ),
            "[('owned-key', 'owned-value'), 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "collections",
                "UserList.__init__",
                _constructed_call_operand("collections", "UserList"),
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "None",
        ),
    ],
)
def test_scan_bytes_blocks_method_descriptor_call_iterator_consumption_rce(
    tmp_path: Path,
    payload: bytes,
    values_literal: str,
    expected_repr: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "method_descriptor_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        f"_values = {values_literal}\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )

    report = scan_bytes(payload, source="method-descriptor-call-iterator-rce.pkl")

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
result_repr = repr(result)
expected_ordered_dict_repr = None
if expected_repr.startswith("OrderedDict(") and expected_repr.endswith(")"):
    expected_ordered_dict_repr = expected_repr[len("OrderedDict(") : -1]
if result_repr != expected_repr and not (
    type(result).__name__ == "OrderedDict" and repr(dict(result)) == expected_ordered_dict_repr
):
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


def test_scan_bytes_keeps_defaultdict_init_factory_call_iterator_lazy(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "defaultdict_init_factory_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "_values = [('owned-key', 'owned-value'), 'stop']\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_call_iterator_method_descriptor_payload(
        "collections",
        "defaultdict.__init__",
        _constructed_call_operand("collections", "defaultdict"),
        b"h\x00",
    )

    report = scan_bytes(payload, source="defaultdict-init-factory-call-iterator.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
try:
    pickle.loads(payload)
except TypeError:
    pass
else:
    raise SystemExit("expected TypeError")
if marker.exists():
    raise SystemExit("marker was written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


@pytest.mark.parametrize(
    ("payload", "setup_code"),
    [
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "weakref",
                "WeakSet.update",
                _constructed_call_operand("weakref", "WeakSet"),
                b"h\x00",
            ),
            "class Box:\n    pass\n_box = Box()\n_values = [_box, 'stop']\n",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "weakref",
                "WeakKeyDictionary.update",
                _constructed_call_operand("weakref", "WeakKeyDictionary"),
                b"h\x00",
            ),
            "class Box:\n    pass\n_key = Box()\n_values = [(_key, 'owned-value'), 'stop']\n",
        ),
        (
            _builtins_help_call_iterator_method_descriptor_payload(
                "weakref",
                "WeakValueDictionary.update",
                _constructed_call_operand("weakref", "WeakValueDictionary"),
                b"h\x00",
            ),
            "class Box:\n    pass\n_value = Box()\n_values = [('owned-key', _value), 'stop']\n",
        ),
    ],
)
def test_scan_bytes_blocks_weakref_method_descriptor_call_iterator_consumption_rce(
    tmp_path: Path,
    payload: bytes,
    setup_code: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "weakref_method_descriptor_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        f"{setup_code}"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )

    report = scan_bytes(payload, source="weakref-method-descriptor-call-iterator-rce.pkl")

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
if result is not None:
    raise SystemExit(f"expected None, got {result!r}")
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


def test_scan_bytes_keeps_non_consuming_method_descriptor_call_iterator_lazy(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "method_descriptor_lazy_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "_values = ['owned-key', 'stop']\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_call_iterator_method_descriptor_payload("builtins", "dict.setdefault", b"}", b"h\x00")

    report = scan_bytes(payload, source="method-descriptor-lazy-call-iterator.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if result is not None:
    raise SystemExit(f"expected None, got {result!r}")
if marker.exists():
    raise SystemExit("marker was written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


@pytest.mark.parametrize(
    ("payload", "values_literal", "expected_repr"),
    [
        (
            _builtins_help_call_iterator_operator_payload("contains", b"h\x00", _unicode_operand("never")),
            "['owned-value', 'stop']",
            "False",
        ),
        (
            _builtins_help_call_iterator_operator_payload("countOf", b"h\x00", _unicode_operand("never")),
            "['owned-value', 'stop']",
            "0",
        ),
        (
            _builtins_help_call_iterator_operator_payload("indexOf", b"h\x00", _unicode_operand("owned-value")),
            "['owned-value', 'stop']",
            "0",
        ),
    ],
)
def test_scan_bytes_blocks_operator_sequence_search_call_iterator_consumption_rce(
    tmp_path: Path,
    payload: bytes,
    values_literal: str,
    expected_repr: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "operator_sequence_search_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        f"_values = {values_literal}\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )

    report = scan_bytes(payload, source="operator-sequence-search-call-iterator-rce.pkl")

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
result_repr = repr(result)
expected_ordered_dict_repr = None
if expected_repr.startswith("OrderedDict(") and expected_repr.endswith(")"):
    expected_ordered_dict_repr = expected_repr[len("OrderedDict(") : -1]
if result_repr != expected_repr and not (
    type(result).__name__ == "OrderedDict" and repr(dict(result)) == expected_ordered_dict_repr
):
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


def test_scan_bytes_keeps_operator_length_hint_call_iterator_lazy(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "operator_length_hint_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "_values = ['owned-value', 'stop']\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_call_iterator_operator_payload("length_hint", b"h\x00")

    report = scan_bytes(payload, source="operator-length-hint-call-iterator.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if result != 0:
    raise SystemExit(f"expected 0, got {result!r}")
if marker.exists():
    raise SystemExit("marker was written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


@pytest.mark.parametrize(
    ("payload", "values_literal", "expected_repr"),
    [
        (
            _builtins_help_call_iterator_operator_payload("iadd", b"]", b"h\x00"),
            "['owned-value', 'stop']",
            "['owned-value']",
        ),
        (
            _builtins_help_call_iterator_operator_payload("iconcat", b"]", b"h\x00"),
            "['owned-value', 'stop']",
            "['owned-value']",
        ),
        (
            _builtins_help_call_iterator_operator_payload(
                "iadd",
                _constructed_call_operand("collections", "deque"),
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "deque(['owned-value'])",
        ),
        (
            _builtins_help_call_iterator_operator_payload(
                "iconcat",
                _constructed_call_operand("collections", "deque"),
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "deque(['owned-value'])",
        ),
        (
            _builtins_help_call_iterator_operator_payload(
                "iadd",
                _constructed_call_operand("collections", "UserList"),
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "['owned-value']",
        ),
        (
            _builtins_help_call_iterator_operator_payload("ior", b"}", b"h\x00"),
            "[('owned-key', 'owned-value'), 'stop']",
            "{'owned-key': 'owned-value'}",
        ),
        (
            _builtins_help_call_iterator_operator_payload(
                "ior",
                _constructed_call_operand("collections", "ChainMap"),
                b"h\x00",
            ),
            "[('owned-key', 'owned-value'), 'stop']",
            "ChainMap({'owned-key': 'owned-value'})",
        ),
        (
            _builtins_help_call_iterator_operator_payload(
                "ior",
                _constructed_call_operand("collections", "defaultdict"),
                b"h\x00",
            ),
            "[('owned-key', 'owned-value'), 'stop']",
            "defaultdict(None, {'owned-key': 'owned-value'})",
        ),
        (
            _builtins_help_call_iterator_operator_payload(
                "ior",
                _constructed_call_operand("collections", "OrderedDict"),
                b"h\x00",
            ),
            "[('owned-key', 'owned-value'), 'stop']",
            "OrderedDict({'owned-key': 'owned-value'})",
        ),
        (
            _builtins_help_call_iterator_operator_payload(
                "ior",
                _constructed_call_operand("collections", "UserDict"),
                b"h\x00",
            ),
            "[('owned-key', 'owned-value'), 'stop']",
            "{'owned-key': 'owned-value'}",
        ),
        (
            _builtins_help_call_iterator_operator_payload(
                "setitem",
                b"]",
                _constructed_call_operand("builtins", "slice", b"N"),
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_operator_payload(
                "setitem",
                _constructed_call_operand("collections", "UserList"),
                _constructed_call_operand("builtins", "slice", b"N"),
                b"h\x00",
            ),
            "['owned-value', 'stop']",
            "None",
        ),
        (
            _builtins_help_call_iterator_operator_payload(
                "setitem",
                _constructed_call_operand("builtins", "bytearray", b"C\x00"),
                _constructed_call_operand("builtins", "slice", b"N"),
                b"h\x00",
            ),
            "[65, 'stop']",
            "None",
        ),
    ],
)
def test_scan_bytes_blocks_operator_protocol_call_iterator_consumption_rce(
    tmp_path: Path,
    payload: bytes,
    values_literal: str,
    expected_repr: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "operator_protocol_call_iterator_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        f"_values = {values_literal}\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )

    report = scan_bytes(payload, source="operator-protocol-call-iterator-rce.pkl")

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
result_repr = repr(result)
expected_ordered_dict_repr = None
if expected_repr.startswith("OrderedDict(") and expected_repr.endswith(")"):
    expected_ordered_dict_repr = expected_repr[len("OrderedDict(") : -1]
if result_repr != expected_repr and not (
    type(result).__name__ == "OrderedDict" and repr(dict(result)) == expected_ordered_dict_repr
):
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


def test_scan_bytes_keeps_operator_iadd_numeric_receiver_call_iterator_lazy(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "operator_iadd_numeric_receiver_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "_values = ['owned-value', 'stop']\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_call_iterator_operator_payload("iadd", b"K\x01", b"h\x00")

    report = scan_bytes(payload, source="operator-iadd-numeric-receiver-call-iterator.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
try:
    pickle.loads(payload)
except TypeError:
    pass
else:
    raise SystemExit("expected TypeError")
if marker.exists():
    raise SystemExit("marker was written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


def test_scan_bytes_keeps_operator_iadd_bytearray_receiver_call_iterator_lazy(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "operator_iadd_bytearray_receiver_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "_values = [65, 'stop']\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_call_iterator_operator_payload(
        "iadd",
        _constructed_call_operand("builtins", "bytearray", b"C\x00"),
        b"h\x00",
    )

    report = scan_bytes(payload, source="operator-iadd-bytearray-receiver-call-iterator.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
try:
    pickle.loads(payload)
except TypeError:
    pass
else:
    raise SystemExit("expected TypeError")
if marker.exists():
    raise SystemExit("marker was written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


def test_scan_bytes_keeps_operator_iconcat_userlist_receiver_call_iterator_lazy(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "operator_iconcat_userlist_receiver_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "_values = ['owned-value', 'stop']\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_call_iterator_operator_payload(
        "iconcat",
        _constructed_call_operand("collections", "UserList"),
        b"h\x00",
    )

    report = scan_bytes(payload, source="operator-iconcat-userlist-receiver-call-iterator.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
try:
    pickle.loads(payload)
except TypeError:
    pass
else:
    raise SystemExit("expected TypeError")
if marker.exists():
    raise SystemExit("marker was written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


def test_scan_bytes_keeps_operator_ior_counter_receiver_call_iterator_lazy(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "operator_ior_counter_receiver_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "_values = [('owned-key', 1), 'stop']\n"
        "def help(*args, **kwargs):\n"
        "    return _values.pop(0) if _values else 'stop'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_call_iterator_operator_payload(
        "ior",
        _constructed_call_operand("collections", "Counter"),
        b"h\x00",
    )

    report = scan_bytes(payload, source="operator-ior-counter-receiver-call-iterator.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
try:
    pickle.loads(payload)
except AttributeError:
    pass
else:
    raise SystemExit("expected AttributeError")
if marker.exists():
    raise SystemExit("marker was written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


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


@pytest.mark.parametrize("name", ["nlargest", "nsmallest"])
def test_scan_bytes_blocks_heapq_key_callback_rce(tmp_path: Path, name: str) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "heapq_key_callback_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 0\n",
        encoding="utf-8",
    )
    payload = _builtins_help_heapq_key_callback_payload(
        name,
        _args_tuple(_unicode_operand("owned-value")),
    )

    report = scan_bytes(payload, source=f"heapq-{name}-key-callback-rce.pkl")

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
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if result != ["owned-value"]:
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


@pytest.mark.parametrize("name", ["nlargest", "nsmallest"])
def test_scan_bytes_keeps_heapq_empty_iterable_key_callback_lazy(tmp_path: Path, name: str) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "heapq_empty_key_callback_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 0\n",
        encoding="utf-8",
    )
    payload = _builtins_help_heapq_key_callback_payload(name, _args_tuple())

    report = scan_bytes(payload, source=f"heapq-{name}-empty-key-callback.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 1
        for invocation in report.metadata.get("callable_invocations", [])
    )

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if result != []:
    raise SystemExit(f"unexpected result {result!r}")
if marker.exists():
    raise SystemExit("marker was written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


@pytest.mark.parametrize("name", ["sub", "subn"])
@pytest.mark.parametrize(
    ("pattern", "value", "extra_arg_operands"),
    [
        ("x", "x", ()),
        (".", "x", ()),
        (".", "\n", (b"K\x00", b"K\x10")),
    ],
)
def test_scan_bytes_blocks_re_sub_replacement_callback_rce(
    tmp_path: Path,
    name: str,
    pattern: str,
    value: str,
    extra_arg_operands: tuple[bytes, ...],
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "re_sub_replacement_callback_marker"
    marker_content = f"pydoc-owned-by-re-{name}"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'OWNED'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_re_sub_payload(name, pattern, value, *extra_arg_operands)

    report = scan_bytes(payload, source=f"re-{name}-replacement-callback-rce.pkl")

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
name = sys.argv[5]

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
expected = "OWNED" if name == "sub" else ("OWNED", 1)
if result != expected:
    raise SystemExit(f"unexpected result {result!r}")
if not marker.exists():
    raise SystemExit("marker was not written")
if marker.read_text() != marker_content:
    raise SystemExit("marker content mismatch")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex(), marker_content, name],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == marker_content


@pytest.mark.parametrize("name", ["sub", "subn"])
@pytest.mark.parametrize(
    ("pattern", "value", "expected_value"),
    [
        ("z", "x", "x"),
        (".", "", ""),
        (".", "\n", "\n"),
    ],
)
def test_scan_bytes_keeps_re_sub_no_match_callback_lazy(
    tmp_path: Path,
    name: str,
    pattern: str,
    value: str,
    expected_value: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "re_sub_no_match_callback_marker"
    marker_content = f"pydoc-owned-by-re-{name}"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'OWNED'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_re_sub_payload(name, pattern, value)

    report = scan_bytes(payload, source=f"re-{name}-no-match-callback.pkl")

    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 1
        for invocation in report.metadata.get("callable_invocations", [])
    )
    if report.verdict != SafetyVerdict.CLEAN:
        assert any(
            finding.rule_code == "DANGEROUS_CALL_GRAPH" and finding.details.get("analysis") == "python_call_graph"
            for finding in report.findings
        )

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])
name = sys.argv[4]
expected_value = sys.argv[5]

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
expected = expected_value if name == "sub" else (expected_value, 0)
if result != expected:
    raise SystemExit(f"unexpected result {result!r}")
if marker.exists():
    raise SystemExit("marker was written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex(), name, expected_value],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


@pytest.mark.parametrize("name", ["sub", "subn"])
@pytest.mark.parametrize(
    ("pattern", "value", "compile_flags_operand"),
    [
        ("x", "x", None),
        (".", "x", None),
        (".", "\n", b"K\x10"),
    ],
)
def test_scan_bytes_blocks_re_pattern_sub_replacement_callback_rce(
    tmp_path: Path,
    name: str,
    pattern: str,
    value: str,
    compile_flags_operand: bytes | None,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "re_pattern_sub_replacement_callback_marker"
    marker_content = f"pydoc-owned-by-re-pattern-{name}"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'OWNED'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_re_pattern_sub_payload(name, pattern, value, compile_flags_operand)

    report = scan_bytes(payload, source=f"re-pattern-{name}-replacement-callback-rce.pkl")

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
name = sys.argv[5]

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
expected = "OWNED" if name == "sub" else ("OWNED", 1)
if result != expected:
    raise SystemExit(f"unexpected result {result!r}")
if not marker.exists():
    raise SystemExit("marker was not written")
if marker.read_text() != marker_content:
    raise SystemExit("marker content mismatch")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex(), marker_content, name],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == marker_content


@pytest.mark.parametrize("name", ["sub", "subn"])
@pytest.mark.parametrize(
    ("pattern", "value", "expected_value"),
    [
        ("z", "x", "x"),
        (".", "", ""),
        (".", "\n", "\n"),
    ],
)
def test_scan_bytes_keeps_re_pattern_sub_no_match_callback_lazy(
    tmp_path: Path,
    name: str,
    pattern: str,
    value: str,
    expected_value: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "re_pattern_sub_no_match_callback_marker"
    marker_content = f"pydoc-owned-by-re-pattern-{name}"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'OWNED'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_re_pattern_sub_payload(name, pattern, value)

    report = scan_bytes(payload, source=f"re-pattern-{name}-no-match-callback.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 1
        for invocation in report.metadata.get("callable_invocations", [])
    )

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])
name = sys.argv[4]
expected_value = sys.argv[5]

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
expected = expected_value if name == "sub" else (expected_value, 0)
if result != expected:
    raise SystemExit(f"unexpected result {result!r}")
if marker.exists():
    raise SystemExit("marker was written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex(), name, expected_value],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


@pytest.mark.parametrize(
    ("pattern", "value", "flags_operand", "expected_result"),
    [
        ("x", "x", None, (["TOKEN:x"], "")),
        (".", "x", None, (["TOKEN:x"], "")),
        (".", "\n", b"K\x10", (["TOKEN:\n"], "")),
    ],
)
def test_scan_bytes_blocks_re_scanner_action_callback_rce(
    tmp_path: Path,
    pattern: str,
    value: str,
    flags_operand: bytes | None,
    expected_result: tuple[list[str], str],
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "re_scanner_action_callback_marker"
    marker_content = "pydoc-owned-by-re-scanner"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'TOKEN:' + args[-1]\n",
        encoding="utf-8",
    )
    payload = _builtins_help_re_scanner_payload(pattern, value, flags_operand)

    report = scan_bytes(payload, source="re-scanner-action-callback-rce.pkl")

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
        and invocation.get("positional_arg_count") == 2
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
expected_token = sys.argv[5]
expected_remainder = sys.argv[6]

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if result != ([expected_token], expected_remainder):
    raise SystemExit(f"unexpected result {result!r}")
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
            expected_result[0][0],
            expected_result[1],
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
    ("pattern", "value", "expected_result"),
    [
        ("z", "x", ([], "x")),
        (".", "", ([], "")),
        (".", "\n", ([], "\n")),
    ],
)
def test_scan_bytes_keeps_re_scanner_no_match_action_callback_lazy(
    tmp_path: Path,
    pattern: str,
    value: str,
    expected_result: tuple[list[str], str],
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "re_scanner_no_match_action_callback_marker"
    marker_content = "pydoc-owned-by-re-scanner"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'TOKEN:' + args[-1]\n",
        encoding="utf-8",
    )
    payload = _builtins_help_re_scanner_payload(pattern, value)

    report = scan_bytes(payload, source="re-scanner-no-match-callback.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 2
        for invocation in report.metadata.get("callable_invocations", [])
    )

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])
expected_remainder = sys.argv[4]

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if result != ([], expected_remainder):
    raise SystemExit(f"unexpected result {result!r}")
if marker.exists():
    raise SystemExit("marker was written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex(), expected_result[1]],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


def test_scan_bytes_blocks_future_done_callback_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "future_done_callback_marker"
    marker_content = "pydoc-owned-by-future"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'OWNED'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_future_callback_payload()

    report = scan_bytes(payload, source="future-done-callback-rce.pkl")

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
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if result is not None:
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


def test_scan_bytes_blocks_done_future_add_callback_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "done_future_add_callback_marker"
    marker_content = "pydoc-owned-by-done-future"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'OWNED'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_done_future_add_callback_payload()

    report = scan_bytes(payload, source="done-future-add-callback-rce.pkl")

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
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if result is not None:
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


def test_scan_bytes_keeps_future_pending_callback_lazy(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "future_pending_callback_marker"
    marker_content = "pydoc-owned-by-future"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'OWNED'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_future_callback_payload(complete=False)

    scan_child_code = """
import sys

# Load concurrent.futures before importing the scanner so the pending callback's
# trusted stdlib references (concurrent.futures.Future[.add_done_callback]) are
# captured in the call-graph identity snapshot. Otherwise an ambient late import
# of concurrent.futures (which happens under some CI runners) makes those
# allowlisted references correctly fail closed as SUSPICIOUS -- behavior that is
# orthogonal to the lazy-callback property this test exercises and is covered by
# test_scan_bytes_fails_closed_for_late_loaded_stdlib_source_modules_*.
import concurrent.futures  # noqa: F401

from modelaudit_picklescan import SafetyVerdict, scan_bytes

payload = bytes.fromhex(sys.argv[1])
report = scan_bytes(payload, source="future-pending-callback.pkl")
if report.verdict != SafetyVerdict.CLEAN:
    raise SystemExit(f"unexpected report: {report.to_dict()!r}")
if any(
    invocation.get("module") == "builtins"
    and invocation.get("name") == "help"
    and invocation.get("positional_arg_count") == 1
    for invocation in report.metadata.get("callable_invocations", [])
):
    raise SystemExit(f"pending callback was marked invoked: {report.to_dict()!r}")
"""
    scan_result = subprocess.run(
        [sys.executable, "-c", scan_child_code, payload.hex()],
        cwd=str(tmp_path.parent),
        env=dict(os.environ),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert scan_result.returncode == 0, scan_result.stderr

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if result is not None:
    raise SystemExit(f"unexpected result {result!r}")
if marker.exists():
    raise SystemExit("marker was written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


@pytest.mark.parametrize("name", ["ref", "proxy"])
def test_scan_bytes_blocks_weakref_lifetime_callback_rce(tmp_path: Path, name: str) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / f"weakref_{name}_callback_marker"
    marker_content = f"pydoc-owned-by-weakref-{name}"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'OWNED'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_weakref_callback_payload(name)

    report = scan_bytes(payload, source=f"weakref-{name}-callback-rce.pkl")

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
sys.modules.pop("pydoc", None)
pickle.loads(payload)
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


@pytest.mark.parametrize("name", ["ref", "proxy"])
def test_scan_bytes_keeps_weakref_without_callback_clean(name: str) -> None:
    payload = _builtins_help_weakref_callback_payload(name, with_callback=False)

    report = scan_bytes(payload, source=f"weakref-{name}-no-callback.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 1
        for invocation in report.metadata.get("callable_invocations", [])
    )


def test_scan_bytes_blocks_weakmethod_lifetime_callback_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "weakmethod_callback_marker"
    marker_content = "pydoc-owned-by-weakmethod"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'OWNED'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_weakmethod_callback_payload()

    report = scan_bytes(payload, source="weakmethod-callback-rce.pkl")

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
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if type(result).__name__ != "WeakMethod":
    raise SystemExit(f"unexpected result {result!r}")
if result() is not None:
    raise SystemExit("weak method unexpectedly stayed alive")
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


def test_scan_bytes_keeps_weakmethod_without_callback_clean() -> None:
    payload = _builtins_help_weakmethod_callback_payload(with_callback=False)

    report = scan_bytes(payload, source="weakmethod-no-callback.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 1
        for invocation in report.metadata.get("callable_invocations", [])
    )


@pytest.mark.parametrize(
    ("name", "line_values_literal", "fallback_literal", "expected_len"),
    [
        ("tokenize", "[b'x = 1\\n', b'']", "b''", 6),
        ("generate_tokens", "['x = 1\\n', '']", "''", 5),
    ],
)
def test_scan_bytes_blocks_tokenize_readline_callback_rce(
    tmp_path: Path,
    name: str,
    line_values_literal: str,
    fallback_literal: str,
    expected_len: int,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "tokenize_readline_callback_marker"
    marker_content = f"pydoc-owned-by-{name}"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        f"_lines = {line_values_literal}\n"
        "def help(*args, **kwargs):\n"
        f"    return _lines.pop(0) if _lines else {fallback_literal}\n",
        encoding="utf-8",
    )
    payload = _builtins_help_tokenize_readline_payload(name, consume=True)

    report = scan_bytes(payload, source=f"tokenize-{name}-readline-callback-rce.pkl")

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
expected_len = int(sys.argv[5])

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if not isinstance(result, list):
    raise SystemExit(f"unexpected result type {type(result)!r}")
if len(result) != expected_len:
    raise SystemExit(f"unexpected token count {len(result)!r}")
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


@pytest.mark.parametrize(
    ("name", "line_values_literal", "fallback_literal"),
    [
        ("generate_tokens", "['x = 1\\n', '']", "''"),
    ],
)
def test_scan_bytes_keeps_tokenize_readline_callback_lazy(
    tmp_path: Path,
    name: str,
    line_values_literal: str,
    fallback_literal: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "tokenize_readline_lazy_marker"
    marker_content = f"pydoc-owned-by-{name}"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        f"_lines = {line_values_literal}\n"
        "def help(*args, **kwargs):\n"
        f"    return _lines.pop(0) if _lines else {fallback_literal}\n",
        encoding="utf-8",
    )
    payload = _builtins_help_tokenize_readline_payload(name, consume=False)

    report = scan_bytes(payload, source=f"tokenize-{name}-readline-lazy.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if type(result).__name__ != "generator":
    raise SystemExit(f"unexpected result type {type(result)!r}")
if marker.exists():
    raise SystemExit("marker was written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


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


@pytest.mark.parametrize(
    ("wrapper_module", "wrapper_name"),
    [
        ("collections", "ChainMap"),
        ("types", "MappingProxyType"),
    ],
)
def test_scan_bytes_blocks_mapping_wrapper_defaultdict_factory_rce(
    tmp_path: Path,
    wrapper_module: str,
    wrapper_name: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / f"{wrapper_name.lower()}_defaultdict_factory_marker"
    marker_content = f"pydoc-owned-{wrapper_name}"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _mapping_wrapper_getitem_payload(
        wrapper_module,
        wrapper_name,
        lookup=True,
        default_factory=True,
    )

    report = scan_bytes(payload, source=f"{wrapper_module}-{wrapper_name}-defaultdict-wrapper-rce.pkl")

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


@pytest.mark.parametrize(
    ("wrapper_module", "wrapper_name"),
    [
        ("collections", "ChainMap"),
        ("types", "MappingProxyType"),
    ],
)
def test_scan_bytes_keeps_mapping_wrapper_defaultdict_constructor_clean(
    wrapper_module: str,
    wrapper_name: str,
) -> None:
    payload = _mapping_wrapper_getitem_payload(
        wrapper_module,
        wrapper_name,
        lookup=False,
        default_factory=True,
    )

    report = scan_bytes(payload, source=f"{wrapper_module}-{wrapper_name}-defaultdict-wrapper-constructor.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )


@pytest.mark.parametrize(
    ("wrapper_module", "wrapper_name"),
    [
        ("collections", "ChainMap"),
        ("types", "MappingProxyType"),
    ],
)
def test_scan_bytes_keeps_mapping_wrapper_plain_dict_lookup_clean(
    wrapper_module: str,
    wrapper_name: str,
) -> None:
    payload = _mapping_wrapper_getitem_payload(
        wrapper_module,
        wrapper_name,
        lookup=True,
        default_factory=False,
    )

    report = scan_bytes(payload, source=f"{wrapper_module}-{wrapper_name}-plain-dict-wrapper-lookup.pkl")

    assert report.verdict == SafetyVerdict.CLEAN


def test_scan_bytes_keeps_chainmap_shadowed_defaultdict_lookup_clean(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "chainmap_shadowed_defaultdict_marker"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('pydoc-owned')\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _chainmap_shadowed_defaultdict_getitem_payload()

    report = scan_bytes(payload, source="chainmap-shadowed-defaultdict-lookup.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])

sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if result != "safe":
    raise SystemExit(f"expected shadowed ChainMap value, got {result!r}")
if marker.exists():
    raise SystemExit("default factory unexpectedly imported pydoc")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


def test_scan_bytes_blocks_deep_mapping_proxy_defaultdict_factory_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "deep_mapping_proxy_defaultdict_marker"
    marker_content = "pydoc-owned-deep-wrapper"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _deep_mapping_proxy_defaultdict_getitem_payload(depth=5)

    report = scan_bytes(payload, source="deep-mapping-proxy-defaultdict-rce.pkl")

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


@pytest.mark.parametrize("format_string", ["", "plain text", "{{x}}"])
def test_scan_bytes_keeps_format_map_defaultdict_without_live_fields_clean(format_string: str) -> None:
    payload = _builtins_help_defaultdict_format_map_payload(lookup=True, format_string=format_string)

    report = scan_bytes(payload, source="format-map-defaultdict-no-live-field.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not _has_critical_call_graph_finding(
        report,
        "_sitebuiltins",
        "_Helper.__call__",
        "builtins.__import__",
    )


@pytest.mark.parametrize(
    ("format_string", "format_arguments"),
    [
        ("{0[x]}", (b"h\x00",)),
        ("{0[x].upper}", (b"h\x00",)),
        ("{[x]}", (b"h\x00",)),
        ("{0:{1[x]}}", (_unicode_operand("safe"), b"h\x00")),
        ("{0!r:{1[x]}}", (_unicode_operand("safe"), b"h\x00")),
        ("{[x]} {0}", (b"h\x00",)),
        ("{[x]} }", (b"h\x00",)),
    ],
)
def test_scan_bytes_blocks_str_format_defaultdict_factory_rce(
    format_string: str,
    format_arguments: tuple[bytes, ...],
) -> None:
    payload = _builtins_help_defaultdict_str_format_payload(format_string, *format_arguments)

    report = scan_bytes(payload, source="str-format-defaultdict-factory-rce.pkl")

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


@pytest.mark.parametrize(
    ("format_string", "format_arguments"),
    [
        ("{}", (b"h\x00",)),
        ("{0} {[x]}", (_unicode_operand("safe"), b"h\x00")),
    ],
)
def test_scan_bytes_keeps_non_lookup_str_format_defaultdict_cases_clean(
    format_string: str,
    format_arguments: tuple[bytes, ...],
) -> None:
    payload = _builtins_help_defaultdict_str_format_payload(format_string, *format_arguments)

    report = scan_bytes(payload, source="str-format-defaultdict-no-lookup.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )


def test_scan_bytes_keeps_str_format_chainmap_shadowed_defaultdict_lookup_clean(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "str_format_chainmap_shadowed_defaultdict_marker"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('pydoc-owned')\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _chainmap_defaultdict_str_format_payload(key="present", format_string="{0[present]}")

    report = scan_bytes(payload, source="str-format-chainmap-shadowed-defaultdict-lookup.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])

sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if result != "safe":
    raise SystemExit(f"expected shadowed ChainMap value, got {result!r}")
if marker.exists():
    raise SystemExit("default factory unexpectedly imported pydoc")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


def test_scan_bytes_blocks_nested_str_format_defaultdict_lookup_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "nested_str_format_defaultdict_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _nested_defaultdict_str_format_payload()

    report = scan_bytes(payload, source="nested-str-format-defaultdict-rce.pkl")

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


def test_scan_bytes_blocks_nested_setitems_str_format_defaultdict_lookup_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "nested_setitems_str_format_defaultdict_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _nested_setitems_defaultdict_str_format_payload()

    report = scan_bytes(payload, source="nested-setitems-str-format-defaultdict-rce.pkl")

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


def test_scan_bytes_blocks_nested_format_map_defaultdict_lookup_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "nested_format_map_defaultdict_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _nested_defaultdict_format_map_payload()

    report = scan_bytes(payload, source="nested-format-map-defaultdict-rce.pkl")

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


@pytest.mark.parametrize("method_name", ["vformat", "_vformat"])
def test_scan_bytes_blocks_nested_formatter_defaultdict_lookup_rce(tmp_path: Path, method_name: str) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / f"nested_formatter_{method_name}_defaultdict_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _nested_defaultdict_formatter_payload(method_name)

    report = scan_bytes(payload, source=f"nested-formatter-{method_name}-defaultdict-rce.pkl")

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
    expected_result = "('factory-value', 0)" if method_name == "_vformat" else "'factory-value'"
    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])
marker_content = sys.argv[4]
expected_result = sys.argv[5]

if marker.exists():
    raise SystemExit("marker already exists before pickle execution")
sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if repr(result) != expected_result:
    raise SystemExit(f"expected factory value result, got {result!r}")
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
            expected_result,
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
    ("wrapper_module", "wrapper_name"),
    [("collections", "ChainMap"), ("types", "MappingProxyType")],
)
def test_scan_bytes_blocks_nested_wrapped_str_format_defaultdict_lookup_rce(
    tmp_path: Path,
    wrapper_module: str,
    wrapper_name: str,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / f"nested_{wrapper_name.lower()}_str_format_defaultdict_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _nested_wrapped_defaultdict_str_format_payload(wrapper_module, wrapper_name)

    report = scan_bytes(payload, source=f"nested-{wrapper_name.lower()}-str-format-defaultdict-rce.pkl")

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


def test_scan_bytes_blocks_memoized_nested_str_format_defaultdict_lookup_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "memoized_nested_str_format_defaultdict_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _memoized_nested_defaultdict_str_format_payload()

    report = scan_bytes(payload, source="memoized-nested-str-format-defaultdict-rce.pkl")

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


def test_scan_bytes_blocks_str_format_unicode_decimal_chainmap_lookup_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "str_format_unicode_decimal_chainmap_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _chainmap_defaultdict_str_format_payload(key="١٢", format_string="{0[١٢]}")

    report = scan_bytes(payload, source="str-format-unicode-decimal-chainmap-rce.pkl")

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


def test_scan_bytes_keeps_str_format_oversized_decimal_chainmap_lookup_clean(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "str_format_oversized_decimal_chainmap_marker"
    oversized_decimal_key = str(2**64)
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('pydoc-owned')\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _chainmap_defaultdict_str_format_payload(
        key=oversized_decimal_key,
        format_string=f"{{0[{oversized_decimal_key}]}}",
    )

    report = scan_bytes(payload, source="str-format-oversized-decimal-chainmap-clean.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
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

sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
try:
    pickle.loads(payload)
except ValueError as exc:
    if str(exc) != "Too many decimal digits in format string":
        raise
else:
    raise SystemExit("expected oversized decimal field to raise ValueError")
if marker.exists():
    raise SystemExit("default factory unexpectedly imported pydoc")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


@pytest.mark.skipif(sys.version_info < (3, 12), reason="newer Unicode decimal digit is unsupported before Python 3.12")
def test_scan_bytes_blocks_str_format_newer_unicode_decimal_chainmap_lookup_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "str_format_newer_unicode_decimal_chainmap_marker"
    marker_content = "pydoc-owned"
    newer_decimal_key = "\U00011f50"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _chainmap_defaultdict_str_format_payload(
        key=newer_decimal_key,
        format_string=f"{{0[{newer_decimal_key}]}}",
    )

    report = scan_bytes(payload, source="str-format-newer-unicode-decimal-chainmap-rce.pkl")

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


@pytest.mark.skipif(sys.version_info >= (3, 12), reason="newer Unicode decimal digit is supported from Python 3.12")
def test_scan_bytes_keeps_str_format_newer_unicode_decimal_chainmap_lookup_clean(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "str_format_newer_unicode_decimal_chainmap_clean_marker"
    newer_decimal_key = "\U00011f50"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('pydoc-owned')\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _chainmap_defaultdict_str_format_payload(
        key=newer_decimal_key,
        format_string=f"{{0[{newer_decimal_key}]}}",
    )

    report = scan_bytes(payload, source="str-format-newer-unicode-decimal-chainmap-clean.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )

    child_code = """
import pickle
import sys
from pathlib import Path

module_dir = Path(sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])

sys.path.insert(0, str(module_dir))
sys.modules.pop("pydoc", None)
result = pickle.loads(payload)
if result != "safe":
    raise SystemExit(f"expected shadowed ChainMap value, got {result!r}")
if marker.exists():
    raise SystemExit("default factory unexpectedly imported pydoc")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(module_dir), str(marker), payload.hex()],
        cwd=str(tmp_path.parent),
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


@pytest.mark.skipif(sys.version_info < (3, 12), reason="newer Unicode decimal digit is unsupported before Python 3.12")
def test_scan_bytes_runtime_blocks_str_format_newer_unicode_decimal_chainmap_lookup_rce(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / "str_format_newer_unicode_decimal_chainmap_runtime_marker"
    marker_content = "pydoc-owned"
    newer_decimal_key = "\U00011f50"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _chainmap_defaultdict_str_format_payload(
        key=newer_decimal_key,
        format_string=f"{{0[{newer_decimal_key}]}}",
    )
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


def test_scan_bytes_keeps_format_map_defaultdict_bytes_receiver_clean() -> None:
    payload = _builtins_help_defaultdict_format_map_payload(
        lookup=True,
        format_operand=_bytes_operand(b"{x}"),
    )

    report = scan_bytes(payload, source="format-map-defaultdict-bytes-receiver.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )


@pytest.mark.parametrize("operator_name", ["mod", "imod"])
def test_scan_bytes_blocks_operator_percent_defaultdict_factory_rce(tmp_path: Path, operator_name: str) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / f"operator_{operator_name}_defaultdict_factory_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )

    factory_only_payload = _builtins_help_defaultdict_operator_mod_payload(lookup=False)
    report = scan_bytes(factory_only_payload, source=f"operator-{operator_name}-defaultdict-factory-only.pkl")

    assert report.verdict == SafetyVerdict.CLEAN

    payload = _builtins_help_defaultdict_operator_mod_payload(lookup=True, operator_name=operator_name)
    report = scan_bytes(payload, source=f"operator-{operator_name}-defaultdict-factory-rce.pkl")

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


@pytest.mark.parametrize("operator_name", ["mod", "imod"])
def test_scan_bytes_keeps_operator_percent_defaultdict_without_mapping_fields_clean(operator_name: str) -> None:
    payload = _builtins_help_defaultdict_operator_mod_payload(
        lookup=True,
        operator_name=operator_name,
        format_string="%%(x)s",
    )

    report = scan_bytes(payload, source=f"operator-{operator_name}-defaultdict-no-mapping-field.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )


@pytest.mark.parametrize("method_name", ["Template.substitute", "Template.safe_substitute"])
def test_scan_bytes_blocks_template_defaultdict_factory_rce(tmp_path: Path, method_name: str) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    marker = tmp_path / f"{method_name.replace('.', '_')}_defaultdict_factory_marker"
    marker_content = "pydoc-owned"
    (module_dir / "pydoc.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({marker_content!r})\n"
        "def help(*args, **kwargs):\n"
        "    return 'factory-value'\n",
        encoding="utf-8",
    )
    payload = _builtins_help_defaultdict_template_payload(method_name, "$missing")

    report = scan_bytes(payload, source=f"string-{method_name}-defaultdict-factory-rce.pkl")

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


@pytest.mark.parametrize("method_name", ["Template.substitute", "Template.safe_substitute"])
def test_scan_bytes_keeps_template_defaultdict_no_placeholder_clean(method_name: str) -> None:
    payload = _builtins_help_defaultdict_template_payload(method_name, "plain text")

    report = scan_bytes(payload, source=f"string-{method_name}-defaultdict-no-placeholder.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )


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


def test_scan_bytes_keeps_formatter_vformat_defaultdict_without_live_fields_clean() -> None:
    payload = _builtins_help_defaultdict_formatter_vformat_payload(lookup=True, format_string="{{x}}")

    report = scan_bytes(payload, source="formatter-vformat-defaultdict-no-live-field.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )


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


def test_scan_bytes_keeps_formatter_private_vformat_defaultdict_without_live_fields_clean() -> None:
    payload = _builtins_help_defaultdict_formatter_private_vformat_payload(lookup=True, format_string="{{x}}")

    report = scan_bytes(payload, source="formatter-private-vformat-defaultdict-no-live-field.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "builtins"
        and invocation.get("name") == "help"
        and invocation.get("positional_arg_count") == 0
        for invocation in report.metadata.get("callable_invocations", [])
    )


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


def test_scan_bytes_keeps_ipaddress_str_format_without_live_fields_clean() -> None:
    payload = _ipaddress_str_format_payload("plain text")

    report = scan_bytes(payload, source="ipaddress-str-format-no-live-field.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "ipaddress"
        and invocation.get("name") == "IPv4Address.__format__"
        and invocation.get("positional_arg_count") == 1
        for invocation in report.metadata.get("callable_invocations", [])
    )


def test_scan_bytes_keeps_ipaddress_str_format_bytes_receiver_clean() -> None:
    payload = _ipaddress_str_format_payload(format_operand=_bytes_operand(b"{:b}"))

    report = scan_bytes(payload, source="ipaddress-str-format-bytes-receiver.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(
        invocation.get("module") == "ipaddress"
        and invocation.get("name") == "IPv4Address.__format__"
        and invocation.get("positional_arg_count") == 1
        for invocation in report.metadata.get("callable_invocations", [])
    )


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


@pytest.mark.skipif(sys.platform == "win32", reason="platform.mac_ver proof depends on macOS/POSIX platform hooks")
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
    pytest.importorskip("typing_extensions")

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
try:
    result = pickle.loads(payload)
except TypeError as exc:
    if "Forward references" not in str(exc):
        raise
else:
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


def test_calls_in_function_reuses_getattr_assignment_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    module = ast.parse(
        """
def bridge(target, command, fallback):
    callback = getattr(target, command, fallback)
    callback(command)
"""
    )
    bridge = module.body[0]
    assert isinstance(bridge, ast.FunctionDef)

    calls = 0
    original_assignment_call_candidates = call_graph._function_assignment_call_candidates

    def counting_assignment_call_candidates(
        function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> tuple[tuple[set[str], ast.Call], ...]:
        nonlocal calls
        calls += 1
        return original_assignment_call_candidates(function_node)

    monkeypatch.setattr(call_graph, "_function_assignment_call_candidates", counting_assignment_call_candidates)

    resolved_calls = call_graph._calls_in_function(
        bridge,
        "benchmod",
        False,
        {},
        {"bridge"},
        set(),
        {},
    )

    assert "builtins.getattr.__call__" in resolved_calls
    assert calls == 1


def test_calls_in_function_reuses_instance_alias_parameter_analysis(monkeypatch: pytest.MonkeyPatch) -> None:
    module = ast.parse(
        """
class Runner:
    def execute(self, command):
        pass

def bridge(target, command):
    runner = Runner(command)
    runner.execute(command)
    getattr(target, command)(command)
"""
    )
    bridge = module.body[1]
    assert isinstance(bridge, ast.FunctionDef)

    calls = 0
    original_parameter_controlled_names = call_graph._parameter_controlled_names

    def counting_parameter_controlled_names(
        function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> set[str]:
        nonlocal calls
        calls += 1
        return original_parameter_controlled_names(function_node)

    monkeypatch.setattr(call_graph, "_parameter_controlled_names", counting_parameter_controlled_names)

    resolved_calls = call_graph._calls_in_function(
        bridge,
        "benchmod",
        False,
        {},
        {"Runner", "bridge"},
        {"benchmod.Runner"},
        {"benchmod.Runner": ("benchmod.Runner.execute",)},
    )

    assert "benchmod.Runner.execute" in resolved_calls
    assert calls == 1
