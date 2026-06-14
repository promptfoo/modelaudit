"""Regressions for import-hook-free call-graph module resolution."""

from __future__ import annotations

import _imp
import importlib
import os
import pickle
import posixpath
import subprocess
import sys
import sysconfig
import tarfile
import zipfile
import zipimport
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from importlib.machinery import (
    BYTECODE_SUFFIXES,
    EXTENSION_SUFFIXES,
    SOURCE_SUFFIXES,
    BuiltinImporter,
    ExtensionFileLoader,
    FileFinder,
    FrozenImporter,
    ModuleSpec,
    PathFinder,
    SourceFileLoader,
    SourcelessFileLoader,
)
from pathlib import Path
from types import BuiltinFunctionType, FunctionType, ModuleType
from typing import Any, cast
from zipimport import zipimporter

import pytest

import modelaudit_picklescan.api as package_api
import modelaudit_picklescan.call_graph as call_graph
from modelaudit_picklescan import PickleReport, SafetyVerdict, ScanStatus


def _clear_call_graph_caches() -> None:
    for function in call_graph._SOURCE_SENSITIVE_CACHED_FUNCTIONS:
        function.cache_clear()


def _posixpath_text_regex_cache_name() -> str:
    for name in ("_varsub", "_varprog"):
        if name in posixpath.expandvars.__code__.co_names:
            return name
    pytest.skip("posixpath.expandvars has no recognized text regex cache")
    raise AssertionError("pytest.skip returned unexpectedly")


def _standard_file_finder_loader_details() -> tuple[tuple[Any, list[str]], ...]:
    return (
        (ExtensionFileLoader, list(EXTENSION_SUFFIXES)),
        (SourceFileLoader, list(SOURCE_SUFFIXES)),
        (SourcelessFileLoader, list(BYTECODE_SUFFIXES)),
    )


def _zipimporter_directory_files(finder: zipimporter) -> dict[str, tuple[object, ...]]:
    finder_state = object.__getattribute__(finder, "__dict__")
    archive = dict.get(finder_state, "archive")
    assert type(archive) is str
    namespace = ModuleType.__getattribute__(zipimport, "__dict__")
    directory_cache = dict.get(namespace, "_zip_directory_cache")
    assert type(directory_cache) is dict
    files = dict.get(directory_cache, archive)
    assert type(files) is dict
    return cast(dict[str, tuple[object, ...]], files)


def _write_zipimporter_archive(archive_path: Path, module: str, *, include_module: bool) -> None:
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("payload.py", "value = 1\n")
        if include_module:
            archive.writestr(f"{module}.py", "class Fraction:\n    pass\n")


def _refresh_zipimporter_directory_files(
    archive_path: Path,
    files: dict[str, tuple[object, ...]],
) -> None:
    namespace = ModuleType.__getattribute__(zipimport, "__dict__")
    read_directory = dict.get(namespace, "_read_directory")
    assert isinstance(read_directory, FunctionType)
    refreshed = read_directory(str(archive_path))
    assert type(refreshed) is dict
    files.clear()
    files.update(cast(dict[str, tuple[object, ...]], refreshed))


@contextmanager
def _standard_import_runtime(
    monkeypatch: pytest.MonkeyPatch,
    *,
    module: str,
    importer_cache: dict[Any, Any],
    search_path: list[str] | None = None,
    trusted_site_package_root: Path | None = None,
) -> Iterator[None]:
    loader_details = _standard_file_finder_loader_details()
    with monkeypatch.context() as context:
        context.delitem(sys.modules, module, raising=False)
        context.setattr(sys, "meta_path", [BuiltinImporter, FrozenImporter, PathFinder])
        context.setattr(sys, "path_hooks", [zipimporter, FileFinder.path_hook(*loader_details)])
        context.setattr(sys, "path_importer_cache", importer_cache)
        if search_path is not None:
            context.setattr(sys, "path", search_path)
        if trusted_site_package_root is not None:
            context.setattr(call_graph, "_TRUSTED_SITE_PACKAGE_PATHS", (trusted_site_package_root.resolve(),))
            context.setattr(call_graph, "_TRUSTED_DELEGATED_SITE_PACKAGE_PATHS", ())
        _clear_call_graph_caches()
        try:
            yield
        finally:
            _clear_call_graph_caches()


class _FailIfExecutedFinder:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def find_spec(
        self,
        fullname: str,
        target: object | None = None,
    ) -> ModuleSpec | None:
        del target
        self.calls.append(f"find_spec:{fullname}")
        raise AssertionError("untrusted cached finder was executed")


def _assert_non_allowlisted_global(report: PickleReport, module: str, name: str) -> None:
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL" and finding.details.get("import_reference") == f"{module}.{name}"
        for finding in report.findings
    )


def _has_source_unavailable_notice(report: PickleReport, module: str, name: str) -> bool:
    return any(
        notice.code == "call_graph_source_unavailable"
        and notice.details.get("module") == module
        and notice.details.get("name") == name
        and notice.details.get("reason") == "source_unavailable"
        for notice in report.notices
    )


def _fail_builtin_find_spec(calls: list[str]) -> Any:
    def find_spec(
        cls: type[object],
        fullname: str,
        path: object | None = None,
        target: object | None = None,
    ) -> ModuleSpec | None:
        del cls, path, target
        calls.append(fullname)
        raise AssertionError(f"BuiltinImporter.find_spec called for {fullname!r}")

    return classmethod(find_spec)


def _fail_frozen_find_spec(calls: list[str]) -> Any:
    def find_spec(
        cls: type[object],
        fullname: str,
        path: object | None = None,
        target: object | None = None,
    ) -> ModuleSpec | None:
        del cls, path, target
        calls.append(fullname)
        raise AssertionError(f"FrozenImporter.find_spec called for {fullname!r}")

    return classmethod(find_spec)


def test_call_graph_enrichment_does_not_invoke_meta_path_finders_for_pickle_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "modelaudit_tp_pickle_controlled_meta_path_name"
    name = "invoke"
    marker = tmp_path / "meta_path_finder_called"
    builtin_calls: list[str] = []
    frozen_calls: list[str] = []
    original_builtin_find_spec = type.__getattribute__(BuiltinImporter, "__dict__")["find_spec"]
    original_frozen_find_spec = type.__getattribute__(FrozenImporter, "__dict__")["find_spec"]

    class RecordingFinder:
        @staticmethod
        def find_spec(
            fullname: str,
            path: object | None = None,
            target: object | None = None,
        ) -> ModuleSpec | None:
            del path, target
            marker.write_text(fullname, encoding="utf-8")
            return ModuleSpec(fullname, loader=None, origin="custom://module")

    monkeypatch.setattr(sys, "meta_path", [RecordingFinder(), *sys.meta_path])
    type.__setattr__(BuiltinImporter, "find_spec", _fail_builtin_find_spec(builtin_calls))
    type.__setattr__(FrozenImporter, "find_spec", _fail_frozen_find_spec(frozen_calls))
    _clear_call_graph_caches()

    try:
        report = PickleReport(
            source="pickle-controlled-meta-path.pkl",
            status=ScanStatus.COMPLETE,
            verdict=SafetyVerdict.CLEAN,
            metadata={
                "import_references": (
                    {
                        "module": module,
                        "name": name,
                        "import_reference": f"{module}.{name}",
                        "requires_origin_verification": True,
                    },
                ),
                "callable_invocations": (
                    {
                        "module": module,
                        "name": name,
                        "import_reference": f"{module}.{name}",
                        "opcode": "REDUCE",
                    },
                ),
            },
        )

        updated = package_api._with_call_graph_findings(report)
    finally:
        type.__setattr__(BuiltinImporter, "find_spec", original_builtin_find_spec)
        type.__setattr__(FrozenImporter, "find_spec", original_frozen_find_spec)
        _clear_call_graph_caches()

    assert updated.status == ScanStatus.INCONCLUSIVE
    assert updated.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_source_unavailable_notice(updated, module, name)
    assert not marker.exists()
    assert builtin_calls == []
    assert frozen_calls == []


def test_loaded_builtin_and_frozen_modules_avoid_hookable_find_spec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builtin_calls: list[str] = []
    frozen_calls: list[str] = []
    original_builtin_find_spec = type.__getattribute__(BuiltinImporter, "__dict__")["find_spec"]
    original_frozen_find_spec = type.__getattribute__(FrozenImporter, "__dict__")["find_spec"]
    type.__setattr__(BuiltinImporter, "find_spec", _fail_builtin_find_spec(builtin_calls))
    type.__setattr__(FrozenImporter, "find_spec", _fail_frozen_find_spec(frozen_calls))
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind("_io") == "stdlib"
        assert call_graph._call_graph_source_unavailable_reason("_io") is None

        if not _imp.is_frozen("ntpath"):
            pytest.skip("ntpath is not frozen on this interpreter")
        ntpath_was_trusted_loaded = "ntpath" in call_graph._TRUSTED_LOADED_INTERPRETER_MODULES
        expected_reason = None if ntpath_was_trusted_loaded else "source_unavailable"
        assert call_graph._call_graph_source_unavailable_reason("ntpath") == expected_reason
        assert call_graph._import_module_can_execute_user_code("ntpath") is not ntpath_was_trusted_loaded
    finally:
        type.__setattr__(BuiltinImporter, "find_spec", original_builtin_find_spec)
        type.__setattr__(FrozenImporter, "find_spec", original_frozen_find_spec)
        _clear_call_graph_caches()

    assert builtin_calls == []
    assert frozen_calls == []


def test_builtin_and_frozen_resolution_uses_import_time_snapshots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "modelaudit_tp_forged_interpreter_module"
    ntpath_is_frozen = call_graph._interpreter_module_origin_without_import_hooks("ntpath") == "frozen"
    ntpath_was_trusted_loaded = "ntpath" in call_graph._TRUSTED_LOADED_INTERPRETER_MODULES
    builtin_calls: list[str] = []
    frozen_calls: list[str] = []
    frozen_package_calls: list[str] = []
    module_spec_calls: list[str] = []
    original_builtin_find_spec = type.__getattribute__(BuiltinImporter, "__dict__")["find_spec"]
    original_frozen_find_spec = type.__getattribute__(FrozenImporter, "__dict__")["find_spec"]

    def forged_is_frozen(name: str) -> bool:
        frozen_calls.append(name)
        return True

    def forged_is_frozen_package(name: str) -> bool:
        frozen_package_calls.append(name)
        return False

    def forged_module_spec_init(
        self: ModuleSpec,
        name: str,
        loader: object,
        **kwargs: object,
    ) -> None:
        del self, loader, kwargs
        module_spec_calls.append(name)
        raise AssertionError(f"ModuleSpec.__init__ called for {name!r}")

    monkeypatch.setattr(sys, "builtin_module_names", (*sys.builtin_module_names, module))
    monkeypatch.setattr(_imp, "is_frozen", forged_is_frozen)
    monkeypatch.setattr(_imp, "is_frozen_package", forged_is_frozen_package)
    monkeypatch.setattr(ModuleSpec, "__init__", forged_module_spec_init)
    type.__setattr__(BuiltinImporter, "find_spec", _fail_builtin_find_spec(builtin_calls))
    type.__setattr__(FrozenImporter, "find_spec", _fail_frozen_find_spec(frozen_calls))
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) in {None, "unresolved"}
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
        assert call_graph._trusted_module_origin_kind("_io") == "stdlib"
        if ntpath_is_frozen:
            expected_reason = None if ntpath_was_trusted_loaded else "source_unavailable"
            assert call_graph._call_graph_source_unavailable_reason("ntpath") == expected_reason
            assert call_graph._import_module_can_execute_user_code("ntpath") is not ntpath_was_trusted_loaded
    finally:
        type.__setattr__(BuiltinImporter, "find_spec", original_builtin_find_spec)
        type.__setattr__(FrozenImporter, "find_spec", original_frozen_find_spec)
        _clear_call_graph_caches()

    assert builtin_calls == []
    assert frozen_calls == []
    assert frozen_package_calls == []
    assert module_spec_calls == []


@pytest.mark.parametrize(
    ("case", "origin", "loader"),
    [
        ("builtin-pair", "built-in", BuiltinImporter),
        ("frozen-pair", "frozen", FrozenImporter),
        ("builtin-origin-only", "built-in", None),
        ("frozen-origin-only", "frozen", None),
        ("builtin-loader-only", "custom://module", BuiltinImporter),
        ("frozen-loader-only", "custom://module", FrozenImporter),
    ],
)
def test_loaded_module_cannot_forge_builtin_or_frozen_origin(
    case: str,
    origin: str,
    loader: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = f"modelaudit_tp_forged_loaded_{case.replace('-', '_')}"
    loaded_module = ModuleType(module)
    loaded_module.__spec__ = ModuleSpec(module, loader, origin=origin)
    monkeypatch.setitem(sys.modules, module, loaded_module)
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph._find_module_spec_without_imports(module) is None
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
    finally:
        _clear_call_graph_caches()


def test_loaded_trusted_interpreter_module_replacement_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "_io"
    assert module in call_graph._TRUSTED_LOADED_INTERPRETER_MODULES
    replacement = ModuleType(module)
    replacement.__spec__ = ModuleSpec(module, cast(Any, BuiltinImporter), origin="built-in")
    monkeypatch.setitem(sys.modules, module, replacement)
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
        report = package_api.scan_bytes(b"c_io\nBytesIO\n.", source="poisoned-builtin.pkl")
        assert report.verdict == SafetyVerdict.SUSPICIOUS
        assert any(
            finding.rule_code == "NON_ALLOWLISTED_GLOBAL" and finding.details.get("import_reference") == "_io.BytesIO"
            for finding in report.findings
        )
    finally:
        _clear_call_graph_caches()


def test_cached_interpreter_origin_cannot_hide_module_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "_io"
    name = "BytesIO"
    replacement = ModuleType(module)
    replacement.__spec__ = ModuleSpec(module, cast(Any, BuiltinImporter), origin="built-in")
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) == "stdlib"
        assert call_graph.import_only_module_requires_origin_review(module, name) is False

        monkeypatch.setitem(sys.modules, module, replacement)

        assert call_graph._trusted_module_origin_kind(module) == "stdlib"
        assert call_graph.import_only_module_requires_origin_review(module, name) is True
    finally:
        _clear_call_graph_caches()


def test_shared_source_snapshot_detects_interpreter_module_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "_io"
    replacement = ModuleType(module)
    replacement.__spec__ = ModuleSpec(module, cast(Any, BuiltinImporter), origin="built-in")

    with call_graph.shared_source_sensitive_caches():
        report_generation = call_graph._begin_shared_source_report()
        assert call_graph._trusted_module_origin_kind(module) == "stdlib"
        metadata = call_graph.shared_source_fingerprint_metadata()
        assert metadata is not None
        assert metadata["reusable"] is False

        monkeypatch.setitem(sys.modules, module, replacement)
        with pytest.raises(call_graph._CallGraphAnalysisLimitError, match="source changed"):
            call_graph._ensure_shared_source_snapshot_stable(report_generation)


def test_loaded_interpreter_reference_mutation_cannot_remain_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "_frozen_importlib"
    name = "ModuleSpec"
    loaded_module = sys.modules[module]
    namespace = ModuleType.__getattribute__(loaded_module, "__dict__")
    original_reference = namespace[name]

    def replacement(*args: Any, **kwargs: Any) -> object:
        return cast(Any, original_reference)(*args, **kwargs)

    with call_graph.shared_source_sensitive_caches():
        report_generation = call_graph._begin_shared_source_report()
        assert call_graph.import_only_reference_is_proven_trusted(module, name) is True
        monkeypatch.setitem(namespace, name, replacement)
        with pytest.raises(call_graph._CallGraphAnalysisLimitError, match="source changed"):
            call_graph._ensure_shared_source_snapshot_stable(report_generation)

    _clear_call_graph_caches()
    try:
        assert call_graph._trusted_module_origin_kind(module) == "stdlib"
        assert call_graph.import_only_reference_is_proven_trusted(module, name) is False
        report = package_api.scan_bytes(
            b"c_frozen_importlib\nModuleSpec\n.",
            source="mutated-module-spec.pkl",
        )
        assert report.verdict == SafetyVerdict.SUSPICIOUS
        assert any(
            finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
            and finding.details.get("import_reference") == "_frozen_importlib.ModuleSpec"
            for finding in report.findings
        )
    finally:
        _clear_call_graph_caches()


def test_loaded_parent_package_namespace_hook_is_not_executed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class HostilePackage(ModuleType):
        def __getattribute__(self, name: str) -> Any:
            if name == "__dict__":
                calls.append(name)
                raise AttributeError("loaded package hook executed")
            return super().__getattribute__(name)

    package = HostilePackage("modelaudit_tp_hostile_parent")
    ModuleType.__getattribute__(package, "__dict__")["__path__"] = []
    monkeypatch.setitem(sys.modules, package.__name__, package)
    _clear_call_graph_caches()

    try:
        report = package_api.scan_bytes(
            b"cmodelaudit_tp_hostile_parent.child\nThing\n.",
            source="hostile-parent.pkl",
        )
        assert calls == []
        assert report.verdict == SafetyVerdict.SUSPICIOUS
        assert any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)
    finally:
        _clear_call_graph_caches()


def test_loaded_filesystem_reference_replacement_cannot_reuse_cached_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "argparse"
    name = "Namespace"
    baseline = call_graph._TRUSTED_LOADED_REFERENCE_BASELINES.get((module, name))
    if baseline is None:
        pytest.skip("argparse.Namespace was not loaded before the call-graph trust snapshot")
    assert baseline is not None
    original_module = baseline[0][1]
    assert sys.modules[module] is original_module
    original_spec = ModuleType.__getattribute__(original_module, "__spec__")
    assert type(original_spec) is ModuleSpec
    original_origin, original_loader = call_graph._module_spec_fields_without_hooks(original_spec)
    assert type(original_origin) is str

    _clear_call_graph_caches()
    clean_report = package_api.scan_bytes(b"cargparse\nNamespace\n)R.", source="original-argparse.pkl")
    assert clean_report.verdict == SafetyVerdict.CLEAN

    replacement = ModuleType(module)
    replacement.__spec__ = ModuleSpec(module, cast(Any, original_loader), origin=original_origin)
    ModuleType.__getattribute__(replacement, "__dict__")[name] = lambda: None
    monkeypatch.setitem(sys.modules, module, replacement)

    assert call_graph._trusted_module_origin_kind(module) == "stdlib"
    replaced_report = package_api.scan_bytes(b"cargparse\nNamespace\n)R.", source="replaced-argparse.pkl")

    assert replaced_report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == "argparse.Namespace"
        for finding in replaced_report.findings
    )


def test_loaded_trusted_reference_ignores_untrusted_cached_path_finder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "argparse"
    name = "Namespace"
    baseline = call_graph._TRUSTED_LOADED_REFERENCE_BASELINES.get((module, name))
    if baseline is None:
        pytest.skip("argparse.Namespace was not loaded before the call-graph trust snapshot")
    assert baseline is not None
    assert sys.modules[module] is baseline[0][1]
    calls: list[str] = []
    evil_entry = str(tmp_path / "loaded-module-evil-importer")
    importer_cache: dict[Any, Any] = dict(sys.path_importer_cache)
    importer_cache[evil_entry] = _FailIfExecutedFinder(calls)

    monkeypatch.setattr(sys, "path", [evil_entry, *sys.path])
    monkeypatch.setattr(sys, "path_importer_cache", importer_cache)
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) == "stdlib"
        report = package_api.scan_bytes(
            f"c{module}\n{name}\n.".encode(),
            source="loaded-module-untrusted-path.pkl",
        )
    finally:
        _clear_call_graph_caches()

    assert report.verdict == SafetyVerdict.CLEAN
    assert calls == []


def test_forged_loaded_filesystem_reference_is_not_trusted_on_first_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "statistics"
    name = "mean"
    if (module, name) in call_graph._TRUSTED_LOADED_REFERENCE_BASELINES:
        pytest.skip("statistics.mean was loaded before the call-graph trust snapshot")

    spec = call_graph._find_standard_filesystem_spec(module)
    assert type(spec) is ModuleSpec
    origin, loader = call_graph._module_spec_fields_without_hooks(spec)
    assert type(origin) is str

    replacement = ModuleType(module)
    replacement_spec = ModuleSpec(module, cast(Any, loader), origin=origin)
    replacement_namespace = ModuleType.__getattribute__(replacement, "__dict__")
    replacement_namespace.update(
        {
            "__package__": "",
            "__spec__": replacement_spec,
            "__loader__": loader,
            "__file__": origin,
            name: lambda values: values,
        }
    )
    monkeypatch.setitem(sys.modules, module, replacement)
    _clear_call_graph_caches()

    assert call_graph._trusted_module_origin_kind(module) == "stdlib"
    report = package_api.scan_bytes(b"cstatistics\nmean\n.", source="forged-statistics.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL" and finding.details.get("import_reference") == "statistics.mean"
        for finding in report.findings
    )


def test_loaded_site_package_reference_after_startup_uses_source_owner() -> None:
    script = """
import sys

import modelaudit_picklescan.call_graph as call_graph

if "numpy" in sys.modules:
    raise SystemExit(98)
try:
    import numpy  # noqa: F401
except ModuleNotFoundError:
    raise SystemExit(99)

for function in call_graph._SOURCE_SENSITIVE_CACHED_FUNCTIONS:
    function.cache_clear()

assert call_graph._TRUSTED_LOADED_REFERENCE_BASELINES.get(("numpy", "dtype")) is None
assert call_graph._trusted_module_origin_kind("numpy") == "site_packages"
assert call_graph.import_only_reference_is_proven_trusted("numpy", "dtype") is True

trusted_reconstruct_modules = []
for reconstruct_module in ("numpy._core.multiarray", "numpy.core.multiarray"):
    try:
        __import__(reconstruct_module, fromlist=["_reconstruct"])
    except ModuleNotFoundError:
        continue
    for function in call_graph._SOURCE_SENSITIVE_CACHED_FUNCTIONS:
        function.cache_clear()
    if call_graph.import_only_reference_is_proven_trusted(reconstruct_module, "_reconstruct"):
        trusted_reconstruct_modules.append(reconstruct_module)

assert trusted_reconstruct_modules
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 99:
        pytest.skip("NumPy is not installed")
    if result.returncode == 98:
        pytest.skip("NumPy was loaded before the call-graph trust snapshot")
    assert result.returncode == 0, result.stderr


def test_loaded_trusted_function_code_mutation_is_not_allowlisted() -> None:
    module = "tempfile"
    name = "gettempdir"
    baseline = call_graph._TRUSTED_LOADED_REFERENCE_BASELINES.get((module, name))
    if baseline is None:
        pytest.skip("tempfile.gettempdir was not loaded before the call-graph trust snapshot")
    assert baseline is not None
    function_value = baseline[1][1]
    if not isinstance(function_value, FunctionType):
        pytest.skip("tempfile.gettempdir was not loaded before the call-graph trust snapshot")
    assert isinstance(function_value, FunctionType)
    function = function_value
    original_code = function.__code__

    def hostile_gettempdir() -> str:
        raise AssertionError("mutated trusted function executed")

    function.__code__ = hostile_gettempdir.__code__
    _clear_call_graph_caches()
    try:
        report = package_api.scan_bytes(b"ctempfile\ngettempdir\n)R.", source="mutated-gettempdir.pkl")
        assert report.verdict == SafetyVerdict.SUSPICIOUS
        assert any(
            finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
            and finding.details.get("import_reference") == "tempfile.gettempdir"
            for finding in report.findings
        )
    finally:
        function.__code__ = original_code
        _clear_call_graph_caches()


def test_loaded_trusted_function_global_mutation_is_not_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "tempfile"
    name = "gettempdir"
    baseline = call_graph._TRUSTED_LOADED_REFERENCE_BASELINES.get((module, name))
    if baseline is None:
        pytest.skip("tempfile.gettempdir was not loaded before the call-graph trust snapshot")
    assert baseline is not None
    loaded_reference = baseline[1][1]
    if not isinstance(loaded_reference, FunctionType):
        pytest.skip("tempfile.gettempdir was not loaded before the call-graph trust snapshot")
    loaded_module = baseline[0][1]
    assert isinstance(loaded_module, ModuleType)
    namespace = ModuleType.__getattribute__(loaded_module, "__dict__")
    calls: list[str] = []

    def hostile_gettempdir() -> str:
        calls.append("_gettempdir")
        raise AssertionError("mutated trusted function global executed")

    monkeypatch.setitem(namespace, "_gettempdir", hostile_gettempdir)
    _clear_call_graph_caches()
    try:
        report = package_api.scan_bytes(b"ctempfile\ngettempdir\n)R.", source="mutated-gettempdir-global.pkl")
        assert report.verdict == SafetyVerdict.SUSPICIOUS
        assert any(
            finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
            and finding.details.get("import_reference") == "tempfile.gettempdir"
            for finding in report.findings
        )
    finally:
        _clear_call_graph_caches()

    assert calls == []


def test_loaded_trusted_function_transitive_global_mutation_is_not_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = call_graph._TRUSTED_LOADED_REFERENCE_BASELINES.get(("tempfile", "gettempdir"))
    if baseline is None:
        pytest.skip("tempfile.gettempdir was not loaded before the call-graph trust snapshot")
    assert baseline is not None
    loaded_module = baseline[0][1]
    assert type(loaded_module) is ModuleType
    namespace = ModuleType.__getattribute__(loaded_module, "__dict__")
    calls: list[str] = []

    def hostile_default_tempdir() -> str:
        calls.append("_get_default_tempdir")
        raise AssertionError("mutated transitive trusted function global executed")

    monkeypatch.setitem(namespace, "_get_default_tempdir", hostile_default_tempdir)
    _clear_call_graph_caches()
    report = package_api.scan_bytes(b"ctempfile\ngettempdir\n)R.", source="mutated-default-tempdir.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert calls == []


def test_loaded_trusted_function_module_attribute_mutation_is_not_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = call_graph._TRUSTED_LOADED_REFERENCE_BASELINES.get(("tempfile", "gettempdir"))
    if baseline is None:
        pytest.skip("tempfile.gettempdir was not loaded before the call-graph trust snapshot")
    assert baseline is not None
    loaded_module = baseline[0][1]
    assert type(loaded_module) is ModuleType
    namespace = ModuleType.__getattribute__(loaded_module, "__dict__")
    os_module = namespace["_os"]
    assert type(os_module) is ModuleType
    os_namespace = ModuleType.__getattribute__(os_module, "__dict__")
    calls: list[str] = []

    def hostile_fsdecode(value: object) -> str:
        del value
        calls.append("fsdecode")
        raise AssertionError("mutated trusted module attribute executed")

    monkeypatch.setitem(os_namespace, "fsdecode", hostile_fsdecode)
    _clear_call_graph_caches()
    report = package_api.scan_bytes(b"ctempfile\ngettempdir\n)R.", source="mutated-fsdecode.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert calls == []


def test_loaded_trusted_function_instance_attribute_shadow_is_not_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = call_graph._TRUSTED_LOADED_REFERENCE_BASELINES.get(("tempfile", "gettempdir"))
    if baseline is None:
        pytest.skip("tempfile.gettempdir was not loaded before the call-graph trust snapshot")
    assert baseline is not None
    loaded_module = baseline[0][1]
    assert type(loaded_module) is ModuleType
    namespace = ModuleType.__getattribute__(loaded_module, "__dict__")
    os_module = namespace["_os"]
    assert type(os_module) is ModuleType
    os_namespace = ModuleType.__getattribute__(os_module, "__dict__")
    environ = os_namespace["environ"]
    environ_namespace = object.__getattribute__(environ, "__dict__")
    assert type(environ_namespace) is dict
    calls: list[str] = []

    def hostile_get(key: str, default: object = None) -> object:
        del key, default
        calls.append("get")
        raise AssertionError("shadowed trusted instance method executed")

    monkeypatch.setitem(environ_namespace, "get", hostile_get)
    _clear_call_graph_caches()

    assert call_graph._loaded_trusted_reference_matches_baseline("tempfile", "gettempdir") is False
    assert calls == []


def test_loaded_trusted_function_attribute_dispatch_mutation_is_not_allowlisted() -> None:
    script = """
import tempfile

import modelaudit_picklescan.call_graph as call_graph

environ_class = type(tempfile._os.environ)
original_getattribute = type.__getattribute__(environ_class, "__getattribute__")
calls = []

def hostile_getattribute(self, name):
    if name == "get":
        calls.append(name)
        return lambda key, default=None: default
    return original_getattribute(self, name)

type.__setattr__(environ_class, "__getattribute__", hostile_getattribute)
for function in call_graph._SOURCE_SENSITIVE_CACHED_FUNCTIONS:
    function.cache_clear()
assert call_graph._loaded_trusted_reference_matches_baseline("tempfile", "gettempdir") is False
assert calls == []
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_loaded_trusted_tempdir_cache_transition_remains_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = call_graph._TRUSTED_LOADED_REFERENCE_BASELINES.get(("tempfile", "gettempdir"))
    if baseline is None:
        pytest.skip("tempfile.gettempdir was not loaded before the call-graph trust snapshot")
    assert baseline is not None
    loaded_module = baseline[0][1]
    assert type(loaded_module) is ModuleType
    namespace = ModuleType.__getattribute__(loaded_module, "__dict__")
    gettempdir = namespace["gettempdir"]
    assert isinstance(gettempdir, FunctionType)
    monkeypatch.setitem(namespace, "tempdir", None)
    _clear_call_graph_caches()

    assert call_graph._loaded_trusted_reference_matches_baseline("tempfile", "gettempdir") is True
    assert type(gettempdir()) is str
    _clear_call_graph_caches()
    assert call_graph._loaded_trusted_reference_matches_baseline("tempfile", "gettempdir") is True


def test_loaded_trusted_tempdir_posixpath_regex_cache_transition_remains_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.path is not posixpath:
        pytest.skip("tempfile does not use posixpath on this platform")
    baseline = call_graph._TRUSTED_LOADED_REFERENCE_BASELINES.get(("tempfile", "gettempdir"))
    if baseline is None:
        pytest.skip("tempfile.gettempdir was not loaded before the call-graph trust snapshot")
    assert baseline is not None
    assert baseline[2][0][2] is True
    namespace = ModuleType.__getattribute__(posixpath, "__dict__")
    cache_name = _posixpath_text_regex_cache_name()
    monkeypatch.setitem(namespace, cache_name, None)
    _clear_call_graph_caches()

    initial_report = package_api.scan_bytes(b"ctempfile\ngettempdir\n.", source="tempdir-before-regex.pkl")
    assert initial_report.verdict == SafetyVerdict.CLEAN

    assert posixpath.expandvars("$MODELAUDIT_MISSING_VARIABLE") == "$MODELAUDIT_MISSING_VARIABLE"
    cache_value = namespace[cache_name]
    assert cache_value is not None
    assert call_graph._trusted_posixpath_regex_cache_is_safe(cache_name, cache_value) is True
    _clear_call_graph_caches()
    populated_report = package_api.scan_bytes(b"ctempfile\ngettempdir\n.", source="tempdir-after-regex.pkl")

    assert populated_report.verdict == SafetyVerdict.CLEAN


def test_loaded_trusted_tempdir_rejects_hostile_posixpath_regex_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.path is not posixpath:
        pytest.skip("tempfile does not use posixpath on this platform")
    calls: list[str] = []

    class HostileRegex:
        def __call__(self, *_args: object, **_kwargs: object) -> object:
            calls.append("__call__")
            raise AssertionError("hostile regex cache executed")

        def search(self, value: object) -> object:
            del value
            calls.append("search")
            raise AssertionError("hostile regex cache executed")

    namespace = ModuleType.__getattribute__(posixpath, "__dict__")
    cache_name = _posixpath_text_regex_cache_name()
    monkeypatch.setitem(namespace, cache_name, HostileRegex())
    _clear_call_graph_caches()

    report = package_api.scan_bytes(b"ctempfile\ngettempdir\n.", source="hostile-posixpath-regex.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == "tempfile.gettempdir"
        for finding in report.findings
    )
    assert calls == []


def test_loaded_trusted_function_builtin_mutation_is_not_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = call_graph._TRUSTED_LOADED_REFERENCE_BASELINES.get(("tempfile", "gettempdir"))
    if baseline is None:
        pytest.skip("tempfile.gettempdir was not loaded before the call-graph trust snapshot")
    assert baseline is not None
    loaded_module = baseline[0][1]
    assert type(loaded_module) is ModuleType
    namespace = ModuleType.__getattribute__(loaded_module, "__dict__")
    helper = namespace["_get_default_tempdir"]
    assert isinstance(helper, FunctionType)
    builtins_namespace = object.__getattribute__(helper, "__builtins__")
    assert type(builtins_namespace) is dict
    original_next = builtins_namespace["next"]

    def hostile_next(iterator: object) -> object:
        return cast(Any, original_next)(iterator)

    monkeypatch.setitem(builtins_namespace, "next", hostile_next)
    _clear_call_graph_caches()
    report = package_api.scan_bytes(b"ctempfile\ngettempdir\n)R.", source="mutated-next.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS


def test_loaded_trusted_class_rejects_hostile_slotnames_cache_without_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = call_graph._TRUSTED_LOADED_REFERENCE_BASELINES.get(("tarfile", "TarInfo"))
    if baseline is None:
        pytest.skip("tarfile.TarInfo was not loaded before the call-graph trust snapshot")
    calls: list[str] = []

    class HostileSlotNames(list[str]):
        def __iter__(self) -> Iterator[str]:
            calls.append("__iter__")
            return super().__iter__()

    monkeypatch.setattr(tarfile.TarInfo, "__slotnames__", HostileSlotNames(), raising=False)
    _clear_call_graph_caches()

    report = package_api.scan_bytes(b"ctarfile\nTarInfo\n)R.", source="hostile-slotnames.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL" and finding.details.get("import_reference") == "tarfile.TarInfo"
        for finding in report.findings
    )
    assert calls == []


def test_loaded_trusted_class_namespace_mutation_is_not_allowlisted() -> None:
    script = """
import argparse

import modelaudit_picklescan.api as package_api
import modelaudit_picklescan.call_graph as call_graph
from modelaudit_picklescan import SafetyVerdict

baseline = call_graph._TRUSTED_LOADED_REFERENCE_BASELINES[("argparse", "Namespace")]
class_ = baseline[1][1]
calls = []

class HostileDescriptor:
    def __get__(self, instance, owner):
        calls.append("__new__")
        raise AssertionError("mutated trusted class descriptor executed")

type.__setattr__(class_, "__new__", HostileDescriptor())
for function in call_graph._SOURCE_SENSITIVE_CACHED_FUNCTIONS:
    function.cache_clear()
report = package_api.scan_bytes(b"cargparse\\nNamespace\\n)R.", source="mutated-namespace.pkl")
assert report.verdict == SafetyVerdict.SUSPICIOUS
assert any(
    finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
    and finding.details.get("import_reference") == "argparse.Namespace"
    for finding in report.findings
)
assert calls == []
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_trusted_reference_snapshot_matches_custom_metaclass_class() -> None:
    class CustomMeta(type):
        pass

    class EnumStyle(metaclass=CustomMeta):
        def __new__(cls) -> EnumStyle:
            return object.__new__(cls)

    snapshot = call_graph._trusted_reference_executable_snapshot(EnumStyle)

    assert call_graph._trusted_reference_executable_matches_snapshot(EnumStyle, snapshot) is True

    class HostileNewDescriptor:
        def __get__(self, instance: object, owner: object) -> object:
            raise AssertionError("mutated custom-metaclass class descriptor executed")

    type.__setattr__(EnumStyle, "__new__", HostileNewDescriptor())

    assert call_graph._trusted_reference_executable_matches_snapshot(EnumStyle, snapshot) is False


def test_loaded_module_metadata_comparison_does_not_execute_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "statistics"
    name = "mean"
    spec = call_graph._find_standard_filesystem_spec(module)
    assert type(spec) is ModuleSpec
    origin, loader = call_graph._module_spec_fields_without_hooks(spec)
    assert type(origin) is str
    calls: list[str] = []

    class HostileName:
        def __eq__(self, other: object) -> bool:
            del other
            calls.append("__eq__")
            raise AssertionError("loaded module metadata comparison executed attacker code")

    replacement = ModuleType(module)
    replacement_namespace = ModuleType.__getattribute__(replacement, "__dict__")
    replacement_namespace.update(
        {
            "__name__": HostileName(),
            "__package__": "",
            "__spec__": spec,
            "__loader__": loader,
            "__file__": origin,
            name: lambda values: values,
        }
    )
    monkeypatch.setitem(sys.modules, module, replacement)
    _clear_call_graph_caches()

    try:
        report = package_api.scan_bytes(b"cstatistics\nmean\n)R.", source="hostile-module-name.pkl")
        assert report.verdict == SafetyVerdict.SUSPICIOUS
    finally:
        _clear_call_graph_caches()

    assert calls == []


def test_loaded_module_origin_value_cannot_execute_during_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "modelaudit_tp_hostile_loaded_origin"
    calls: list[str] = []

    class HostileOrigin:
        __hash__: Any = None

        def __fspath__(self) -> str:
            calls.append("fspath")
            raise AssertionError("hostile origin was treated as a path")

        def __eq__(self, other: object) -> bool:
            del other
            calls.append("eq")
            raise AssertionError("hostile origin was compared")

    loaded_module = ModuleType(module)
    loaded_module.__spec__ = ModuleSpec(module, loader=None, origin=cast(Any, HostileOrigin()))
    monkeypatch.setitem(sys.modules, module, loaded_module)
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
    finally:
        _clear_call_graph_caches()

    assert calls == []


def test_unloaded_builtin_with_pristine_import_runtime_remains_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = next((name for name in sys.builtin_module_names if name not in sys.modules), None)
    if module is None:
        pytest.skip("all builtin modules are already loaded")
    assert module is not None
    monkeypatch.setattr(sys, "meta_path", [BuiltinImporter, FrozenImporter, PathFinder])
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) == "stdlib"
        assert call_graph._call_graph_source_unavailable_reason(module) is None
        assert call_graph._import_module_can_execute_user_code(module) is False
    finally:
        _clear_call_graph_caches()


def test_unrelated_import_runtime_attribute_does_not_block_unloaded_builtin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = next((name for name in sys.builtin_module_names if name not in sys.modules), None)
    if module is None:
        pytest.skip("all builtin modules are already loaded")
    assert module is not None
    monkeypatch.setattr(sys, "meta_path", [BuiltinImporter, FrozenImporter, PathFinder])
    marker = object()
    type.__setattr__(ModuleSpec, "_modelaudit_test_marker", marker)
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) == "stdlib"
        assert call_graph._call_graph_source_unavailable_reason(module) is None
        assert call_graph._import_module_can_execute_user_code(module) is False
    finally:
        type.__delattr__(ModuleSpec, "_modelaudit_test_marker")
        _clear_call_graph_caches()


def test_unrelated_importlib_global_does_not_block_unloaded_builtin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = next((name for name in sys.builtin_module_names if name not in sys.modules), None)
    if module is None:
        pytest.skip("all builtin modules are already loaded")
    assert module is not None
    frozen_importlib = call_graph._FROZEN_IMPORTLIB_MODULE
    assert type(frozen_importlib) is ModuleType
    namespace = ModuleType.__getattribute__(frozen_importlib, "__dict__")
    monkeypatch.setitem(namespace, "_modelaudit_test_marker", object())
    monkeypatch.setattr(sys, "meta_path", [BuiltinImporter, FrozenImporter, PathFinder])
    _clear_call_graph_caches()

    try:
        assert call_graph._interpreter_import_runtime_is_trusted() is True
        assert call_graph._trusted_module_origin_kind(module) == "stdlib"
    finally:
        _clear_call_graph_caches()


def test_added_importlib_shadow_global_blocks_resolution_without_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = next((name for name in sys.builtin_module_names if name not in sys.modules), None)
    if module is None:
        pytest.skip("all builtin modules are already loaded")
    assert module is not None
    frozen_importlib = call_graph._FROZEN_IMPORTLIB_MODULE
    assert type(frozen_importlib) is ModuleType
    namespace = ModuleType.__getattribute__(frozen_importlib, "__dict__")
    assert "getattr" in call_graph._IMPORT_RUNTIME_MISSING_GLOBAL_NAMES["_frozen_importlib"]
    calls: list[tuple[object, ...]] = []

    def hostile_getattr(*args: object) -> object:
        calls.append(args)
        raise AssertionError("added importlib global was executed")

    monkeypatch.setitem(namespace, "getattr", hostile_getattr)
    monkeypatch.setattr(sys, "meta_path", [BuiltinImporter, FrozenImporter, PathFinder])
    _clear_call_graph_caches()

    try:
        assert call_graph._interpreter_import_runtime_is_trusted() is False
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
    finally:
        _clear_call_graph_caches()

    assert calls == []


def test_hostile_meta_path_container_blocks_resolution_without_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = next((name for name in sys.builtin_module_names if name not in sys.modules), None)
    if module is None:
        pytest.skip("all builtin modules are already loaded")
    assert module is not None
    calls: list[str] = []

    class HostileMetaPath(list[object]):
        def __iter__(self) -> Any:
            calls.append("iter")
            raise AssertionError("hostile sys.meta_path was iterated")

    monkeypatch.setattr(sys, "meta_path", HostileMetaPath([BuiltinImporter, FrozenImporter, PathFinder]))
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
    finally:
        _clear_call_graph_caches()

    assert calls == []


@pytest.mark.parametrize("attribute", ["path", "path_hooks"])
def test_hostile_import_path_container_blocks_resolution_without_execution(
    monkeypatch: pytest.MonkeyPatch,
    attribute: str,
) -> None:
    calls: list[str] = []

    class HostilePathState(list[object]):
        def __iter__(self) -> Any:
            calls.append("iter")
            raise AssertionError(f"hostile sys.{attribute} was iterated")

    original = cast(list[object], getattr(sys, attribute))
    monkeypatch.setattr(sys, attribute, HostilePathState(original))
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind("statistics") is None
        assert call_graph._call_graph_source_unavailable_reason("statistics") == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code("statistics") is True
    finally:
        _clear_call_graph_caches()

    assert calls == []


def test_hostile_path_importer_cache_blocks_resolution_without_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class HostileImporterCache(dict[Any, Any]):
        def get(self, *args: Any, **kwargs: Any) -> Any:
            del kwargs
            calls.append(str(args[0]))
            raise AssertionError("hostile sys.path_importer_cache was accessed")

    monkeypatch.setattr(sys, "path_importer_cache", HostileImporterCache(sys.path_importer_cache))
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind("statistics") is None
        assert call_graph._call_graph_source_unavailable_reason("statistics") == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code("statistics") is True
    finally:
        _clear_call_graph_caches()

    assert calls == []


def test_later_untrusted_path_importer_does_not_block_prior_stdlib_source_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "statistics"
    stdlib_path = sysconfig.get_path("stdlib")
    assert stdlib_path is not None
    finder = FileFinder(stdlib_path, *_standard_file_finder_loader_details())
    untrusted_entry = str(Path(stdlib_path) / "later-untrusted-importer")
    importer_cache: dict[Any, Any] = {
        **sys.path_importer_cache,
        stdlib_path: finder,
        untrusted_entry: object(),
    }

    with _standard_import_runtime(
        monkeypatch,
        module=module,
        importer_cache=importer_cache,
        search_path=[stdlib_path, untrusted_entry],
    ):
        assert call_graph._trusted_module_origin_kind(module) == "stdlib"
        assert call_graph._resolve_module_source(module) is not None


def test_cached_and_fresh_stdlib_file_finder_resolution_are_equivalent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "statistics"
    stdlib_path = sysconfig.get_path("stdlib")
    assert stdlib_path is not None
    origins: list[str] = []
    for cached in (False, True):
        importer_cache: dict[Any, Any] = dict(sys.path_importer_cache)
        importer_cache.pop(stdlib_path, None)
        if cached:
            importer_cache[stdlib_path] = FileFinder(stdlib_path, *_standard_file_finder_loader_details())
        with _standard_import_runtime(
            monkeypatch,
            module=module,
            importer_cache=importer_cache,
            search_path=[stdlib_path],
        ):
            spec = call_graph._find_standard_filesystem_spec(module)
            assert type(spec) is ModuleSpec
            origin, _ = call_graph._module_spec_fields_without_hooks(spec)
            assert type(origin) is str
            origins.append(origin)
            assert call_graph._trusted_module_origin_kind(module) == "stdlib"
    assert origins[0] == origins[1]


@pytest.mark.parametrize("cached_stdlib_importer", ["none", "poisoned_file_finder"])
def test_cached_stdlib_importer_miss_with_later_untrusted_finder_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    cached_stdlib_importer: str,
) -> None:
    module, name = "statistics", "mean"
    stdlib_path = sysconfig.get_path("stdlib")
    assert stdlib_path is not None
    calls: list[str] = []
    evil_entry = str(Path(stdlib_path) / "later-evil-importer")
    importer_cache: dict[Any, Any] = dict(sys.path_importer_cache)
    if cached_stdlib_importer == "none":
        importer_cache[stdlib_path] = None
    else:
        finder = FileFinder(stdlib_path, *_standard_file_finder_loader_details())
        finder_state = object.__getattribute__(finder, "__dict__")
        finder_state.update(
            _path_mtime=os.stat(stdlib_path).st_mtime,
            _path_cache={"stale_deleted.py"},
            _relaxed_path_cache={"stale_deleted.py"},
        )
        assert finder.find_spec(module) is None
        importer_cache[stdlib_path] = finder
    importer_cache[evil_entry] = _FailIfExecutedFinder(calls)

    with _standard_import_runtime(
        monkeypatch,
        module=module,
        importer_cache=importer_cache,
        search_path=[stdlib_path, evil_entry],
    ):
        assert call_graph._trusted_module_origin_kind(module) is None
        report = package_api.scan_bytes(f"c{module}\n{name}\n.".encode(), source="cached-importer-miss.pkl")
    _assert_non_allowlisted_global(report, module, name)
    assert calls == []


@pytest.mark.parametrize("cache_transition", ["missing_to_none", "file_finder_to_poisoned"])
def test_shared_cache_refreshes_when_path_importer_semantics_change(
    monkeypatch: pytest.MonkeyPatch,
    cache_transition: str,
) -> None:
    module, name = "fractions", "Fraction"
    stdlib_path = sysconfig.get_path("stdlib")
    assert stdlib_path is not None
    calls: list[str] = []
    evil_entry = str(Path(stdlib_path) / "later-shared-cache-evil-importer")
    importer_cache: dict[Any, Any] = dict(sys.path_importer_cache)
    importer_cache.pop(stdlib_path, None)
    finder: FileFinder | None = None
    if cache_transition == "file_finder_to_poisoned":
        finder = FileFinder(stdlib_path, *_standard_file_finder_loader_details())
        assert finder.find_spec(module) is not None
        importer_cache[stdlib_path] = finder
    importer_cache[evil_entry] = _FailIfExecutedFinder(calls)

    with (
        _standard_import_runtime(
            monkeypatch,
            module=module,
            importer_cache=importer_cache,
            search_path=[stdlib_path, evil_entry],
        ),
        call_graph.shared_source_sensitive_caches(),
    ):
        trusted_report = package_api.scan_bytes(
            f"c{module}\n{name}\n.".encode(), source="shared-cache-trusted.pkl", enrich_call_graph=False
        )
        if finder is None:
            importer_cache[stdlib_path] = None
        else:
            finder_state = object.__getattribute__(finder, "__dict__")
            finder_state.update(
                _path_mtime=os.stat(stdlib_path).st_mtime,
                _path_cache=set(),
                _relaxed_path_cache=set(),
            )
        blocked_report = package_api.scan_bytes(
            f"c{module}\n{name}\n.".encode(), source="shared-cache-blocked.pkl", enrich_call_graph=False
        )
    assert trusted_report.verdict == SafetyVerdict.CLEAN
    _assert_non_allowlisted_global(blocked_report, module, name)
    assert calls == []


def test_shared_snapshot_accepts_equivalent_standard_importer_cache_population(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "benign_cache_population"
    (tmp_path / f"{module}.py").write_text("value = 1\n", encoding="utf-8")
    path_entry = str(tmp_path)
    importer_cache: dict[Any, Any] = {}

    with (
        _standard_import_runtime(
            monkeypatch,
            module=module,
            importer_cache=importer_cache,
            search_path=[path_entry],
        ),
        call_graph.shared_source_sensitive_caches(),
    ):
        generation = call_graph._begin_shared_source_report()
        importer_cache[path_entry] = FileFinder(path_entry, *_standard_file_finder_loader_details())
        call_graph._track_shared_source_candidates((module,))
        call_graph._ensure_shared_source_snapshot_stable(generation)
        metadata = call_graph.shared_source_fingerprint_metadata()

    assert metadata is not None
    assert metadata["reusable"] is True
    assert any(path_entry in identity for identity in metadata["resolution_context"]["path_importers"])


@pytest.mark.parametrize("initial_has_module", [True, False], ids=["hit-to-miss", "miss-to-hit"])
def test_shared_cache_refreshes_when_zipimporter_cache_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initial_has_module: bool,
) -> None:
    module, name = "fractions", "Fraction"
    archive_path = tmp_path / "trusted-modules.zip"
    _write_zipimporter_archive(archive_path, module, include_module=initial_has_module)
    path_entry = str(archive_path)
    finder = zipimporter(path_entry)
    files = _zipimporter_directory_files(finder)
    evil_entry = str(tmp_path / "later-zip-cache-evil-importer")
    calls: list[str] = []
    importer_cache: dict[Any, Any] = {
        **sys.path_importer_cache,
        path_entry: finder,
        evil_entry: _FailIfExecutedFinder(calls),
    }

    with (
        _standard_import_runtime(
            monkeypatch,
            module=module,
            importer_cache=importer_cache,
            search_path=[path_entry, evil_entry],
            trusted_site_package_root=tmp_path,
        ),
        call_graph.shared_source_sensitive_caches(),
    ):
        first_report = package_api.scan_bytes(
            f"c{module}\n{name}\n.".encode(), source="shared-zip-cache-first.pkl", enrich_call_graph=False
        )
        _write_zipimporter_archive(archive_path, module, include_module=not initial_has_module)
        _refresh_zipimporter_directory_files(archive_path, files)
        assert (type(zipimporter.find_spec(finder, module)) is ModuleSpec) is (not initial_has_module)
        second_report = package_api.scan_bytes(
            f"c{module}\n{name}\n.".encode(), source="shared-zip-cache-second.pkl", enrich_call_graph=False
        )
    trusted_report = first_report if initial_has_module else second_report
    blocked_report = second_report if initial_has_module else first_report
    assert trusted_report.verdict == SafetyVerdict.CLEAN
    _assert_non_allowlisted_global(blocked_report, module, name)
    assert calls == []


@pytest.mark.parametrize("forgery", ["name", "offset", "metadata"])
def test_forged_zipimporter_directory_entry_is_not_trusted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    forgery: str,
) -> None:
    module, name = "fractions", "Fraction"
    archive_path = tmp_path / "trusted-forged-modules.zip"
    _write_zipimporter_archive(archive_path, module, include_module=forgery != "name")
    path_entry = str(archive_path)
    finder = zipimporter(path_entry)
    files = _zipimporter_directory_files(finder)
    if forgery == "name":
        forged_metadata = files["payload.py"]
    else:
        forged_values = list(files[f"{module}.py"])
        forged_index = 4 if forgery == "offset" else 7
        forged_value = forged_values[forged_index]
        assert type(forged_value) is int
        forged_values[forged_index] = forged_value + 1
        forged_metadata = tuple(forged_values)
    monkeypatch.setitem(files, f"{module}.py", forged_metadata)
    assert type(zipimporter.find_spec(finder, module)) is ModuleSpec

    with _standard_import_runtime(
        monkeypatch,
        module=module,
        importer_cache={path_entry: finder},
        search_path=[path_entry],
        trusted_site_package_root=tmp_path,
    ):
        assert call_graph._trusted_module_origin_kind(module) is None
        report = package_api.scan_bytes(
            f"c{module}\n{name}\n.".encode(),
            source=f"forged-zip-directory-{forgery}.pkl",
            enrich_call_graph=False,
        )
    _assert_non_allowlisted_global(report, module, name)


def test_zipimporter_directory_shape_accepts_implicit_directory_sentinels() -> None:
    files = {
        "package/": None,
        "package/module.py": ("archive.zip/package/module.py", 0, 4, 4, 0, 0, 0, 0),
    }

    assert call_graph._zipimport_files_are_safe(files)


def test_zipimporter_directory_validation_does_not_execute_mutated_reader(tmp_path: Path) -> None:
    archive_path = tmp_path / "mutated-reader.zip"
    _write_zipimporter_archive(archive_path, "trusted_module", include_module=True)
    finder = zipimporter(str(archive_path))
    files = _zipimporter_directory_files(finder)
    assert call_graph._zipimport_archive_files_match(str(archive_path), files)

    read_directory = call_graph._ZIP_READ_DIRECTORY
    assert isinstance(read_directory, FunctionType)
    marker = tmp_path / "mutated-reader-executed"
    namespace: dict[str, Any] = {}
    exec(f"def poisoned(_archive):\n    open({str(marker)!r}, 'w').close()\n    return {{}}\n", namespace)
    poisoned = namespace["poisoned"]
    assert isinstance(poisoned, FunctionType)
    original_code = read_directory.__code__
    read_directory.__code__ = poisoned.__code__
    try:
        assert call_graph._zipimport_archive_files_match(str(archive_path), files) is False
    finally:
        read_directory.__code__ = original_code
    assert marker.exists() is False


def test_zipimporter_directory_validation_does_not_execute_mutated_reader_global(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "mutated-reader-global.zip"
    _write_zipimporter_archive(archive_path, "trusted_module", include_module=True)
    finder = zipimporter(str(archive_path))
    files = _zipimporter_directory_files(finder)
    assert call_graph._zipimport_archive_files_match(str(archive_path), files)

    zipimport_namespace = ModuleType.__getattribute__(zipimport, "__dict__")
    original_unpack = dict.get(zipimport_namespace, "_unpack_uint32")
    assert callable(original_unpack)
    calls: list[bytes] = []

    def poisoned_unpack(value: bytes) -> int:
        calls.append(value)
        return cast(Callable[[bytes], int], original_unpack)(value)

    monkeypatch.setitem(zipimport_namespace, "_unpack_uint32", poisoned_unpack)

    assert call_graph._zipimport_archive_files_match(str(archive_path), files) is False
    with _standard_import_runtime(
        monkeypatch,
        module="trusted_module",
        importer_cache={str(archive_path): finder},
        search_path=[str(archive_path)],
        trusted_site_package_root=tmp_path,
    ):
        assert call_graph._trusted_module_origin_kind("trusted_module") is None
    assert calls == []


def test_zipimporter_identity_does_not_rebuild_evicted_cache_with_mutated_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "evicted-mutated-reader.zip"
    _write_zipimporter_archive(archive_path, "trusted_module", include_module=True)
    path_entry = str(archive_path)
    finder = zipimporter(path_entry)
    assert call_graph._zipimporter_resolution_identity(finder, path_entry) is not None

    finder_state = object.__getattribute__(finder, "__dict__")
    archive = dict.get(finder_state, "archive")
    assert type(archive) is str
    zipimport_namespace = ModuleType.__getattribute__(zipimport, "__dict__")
    directory_cache = dict.get(zipimport_namespace, "_zip_directory_cache")
    original_reader = dict.get(zipimport_namespace, "_read_directory")
    assert type(directory_cache) is dict
    assert isinstance(original_reader, FunctionType)
    monkeypatch.delitem(directory_cache, archive)
    calls: list[str] = []

    def poisoned_reader(value: str) -> object:
        calls.append(value)
        return original_reader(value)

    monkeypatch.setitem(zipimport_namespace, "_read_directory", poisoned_reader)

    assert call_graph._zipimporter_resolution_identity(finder, path_entry) is None
    assert calls == []


def test_zipimporter_directory_validation_bounds_entries_before_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "oversized-directory.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for index in range(call_graph._MAX_SOURCE_FINGERPRINT_CANDIDATES + 1):
            archive.writestr(f"entry-{index}.py", "")
    assert archive_path.stat().st_size < call_graph._MAX_ZIPIMPORT_ARCHIVE_BYTES

    calls: list[str] = []
    original_reader = call_graph._ZIP_READ_DIRECTORY
    assert isinstance(original_reader, FunctionType)

    def counted_reader(archive: str) -> object:
        calls.append(archive)
        return original_reader(archive)

    zipimport_namespace = ModuleType.__getattribute__(zipimport, "__dict__")
    monkeypatch.setitem(zipimport_namespace, "_read_directory", counted_reader)
    monkeypatch.setattr(call_graph, "_ZIP_READ_DIRECTORY", counted_reader)
    monkeypatch.setattr(
        call_graph,
        "_ZIP_READ_DIRECTORY_SNAPSHOT",
        call_graph._trusted_executable_value_snapshot(counted_reader),
    )

    assert call_graph._zipimport_archive_files_match(str(archive_path), {}) is False
    assert calls == []


def test_file_finder_identity_does_not_execute_mutated_fill_cache(tmp_path: Path) -> None:
    finder = FileFinder(str(tmp_path), *_standard_file_finder_loader_details())
    fill_cache = FileFinder.__dict__["_fill_cache"]
    assert isinstance(fill_cache, FunctionType)
    marker = tmp_path / "mutated-fill-cache-executed"
    namespace: dict[str, Any] = {}
    exec(f"def poisoned(_finder):\n    open({str(marker)!r}, 'w').close()\n", namespace)
    poisoned = namespace["poisoned"]
    assert isinstance(poisoned, FunctionType)
    original_code = fill_cache.__code__
    fill_cache.__code__ = poisoned.__code__
    try:
        assert call_graph._file_finder_resolution_identity(finder, str(tmp_path)) is None
    finally:
        fill_cache.__code__ = original_code
    assert marker.exists() is False


def test_file_finder_miss_rejects_incomplete_current_cache(tmp_path: Path) -> None:
    module = "present_but_hidden"
    (tmp_path / f"{module}.py").write_text("value = 1\n", encoding="utf-8")
    path_entry = str(tmp_path)
    finder = FileFinder(path_entry, *_standard_file_finder_loader_details())
    assert finder.find_spec(module) is not None
    finder_state = object.__getattribute__(finder, "__dict__")
    finder_state["_path_mtime"] = os.stat(path_entry).st_mtime
    finder_state["_path_cache"] = {"stale_deleted.py"}
    finder_state["_relaxed_path_cache"] = {"stale_deleted.py"}
    assert finder.find_spec(module) is None

    call_graph._cached_file_finder_resolution_summary.cache_clear()
    try:
        assert call_graph._file_finder_resolution_identity(finder, path_entry) is not None
        assert call_graph._trusted_path_importer_spec(finder, "benign_missing", path_entry) is None
        assert isinstance(
            call_graph._trusted_path_importer_spec(finder, module, path_entry),
            call_graph._UnsafePathResolution,
        )
    finally:
        call_graph._cached_file_finder_resolution_summary.cache_clear()


def test_file_finder_resolution_identity_caches_bounded_state_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path_entry = str(tmp_path)
    for index in range(512):
        (tmp_path / f"module_{index}.py").touch()
    finder = FileFinder(path_entry, *_standard_file_finder_loader_details())
    assert finder.find_spec("module_0") is not None
    finder_state = object.__getattribute__(finder, "__dict__")
    original_identity = call_graph._string_sequence_identity
    original_type_validation = call_graph._file_finder_cache_names_are_strings
    work_count = 0
    type_validation_count = 0

    def counted_identity(values: Iterable[str]) -> str:
        nonlocal work_count
        materialized = tuple(values)
        work_count += len(materialized)
        return original_identity(materialized)

    def counted_type_validation(
        path_cache: Iterable[object],
        relaxed_path_cache: Iterable[object],
    ) -> bool:
        nonlocal type_validation_count
        type_validation_count += 1
        return original_type_validation(path_cache, relaxed_path_cache)

    call_graph._cached_file_finder_resolution_summary.cache_clear()
    monkeypatch.setattr(call_graph, "_string_sequence_identity", counted_identity)
    monkeypatch.setattr(call_graph, "_file_finder_cache_names_are_strings", counted_type_validation)
    try:
        first_identity = call_graph._file_finder_resolution_identity(finder, path_entry)
        assert first_identity is not None
        first_work_count = work_count
        first_type_validation_count = type_validation_count
        assert first_work_count <= len(finder_state["_path_cache"]) + 4
        assert first_type_validation_count == 1
        assert call_graph._file_finder_resolution_identity(finder, path_entry) == first_identity
        assert not work_count > first_work_count
        assert type_validation_count == first_type_validation_count

        replacement_work_count = work_count
        finder_state["_path_cache"] = set(finder_state["_path_cache"])
        assert call_graph._file_finder_resolution_identity(finder, path_entry) == first_identity
        assert replacement_work_count < work_count <= replacement_work_count + len(finder_state["_path_cache"]) + 4
        assert type_validation_count == first_type_validation_count + 1
        work_before_transition = work_count
        transitioned_cache = set(cast(frozenset[str], finder_state["_path_cache"]))
        finder_state["_path_cache"] = transitioned_cache
        transitioned_cache.remove("module_0.py")
        transitioned_cache.add("transitioned.py")
        transitioned_identity = call_graph._file_finder_resolution_identity(finder, path_entry)
        assert transitioned_identity is not None
        assert transitioned_identity != first_identity
        assert isinstance(
            call_graph._trusted_path_importer_spec(finder, "module_0", path_entry),
            call_graph._UnsafePathResolution,
        )
        assert work_before_transition < work_count <= work_before_transition + len(transitioned_cache) + 4

        work_before_oversized = work_count
        finder_state["_path_cache"] = {
            f"oversized_{index}.py" for index in range(call_graph._MAX_SOURCE_FINGERPRINT_CANDIDATES + 1)
        }
        assert call_graph._file_finder_resolution_identity(finder, path_entry) is None
        assert work_count == work_before_oversized
        cache_info = call_graph._cached_file_finder_resolution_summary.cache_info()
        assert cache_info.maxsize == call_graph._MAX_FILE_FINDER_IDENTITY_CACHE_SIZE
        assert cache_info.currsize <= cache_info.maxsize
    finally:
        call_graph._cached_file_finder_resolution_summary.cache_clear()


@pytest.mark.skipif(sys.platform == "win32", reason="requires POSIX symlink parent-traversal semantics")
def test_importer_context_preserves_symlink_sensitive_parent_components(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = tmp_path / "base"
    clean_parent = tmp_path / "other"
    clean_root = clean_parent / "pkgroot"
    poisoned_root = base / "pkgroot"
    clean_root.mkdir(parents=True)
    poisoned_root.mkdir(parents=True)
    symlink_target = clean_parent / "inner"
    symlink_target.mkdir()
    link = base / "link"
    try:
        link.symlink_to(symlink_target, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlinks unavailable: {error}")

    clean_entry = str(link / ".." / "pkgroot")
    poisoned_entry = str(poisoned_root)
    assert Path(clean_entry).resolve() == clean_root.resolve()
    assert os.path.abspath(clean_entry) == os.path.abspath(poisoned_entry)

    finder = FileFinder(clean_entry, *_standard_file_finder_loader_details())
    monkeypatch.setitem(sys.path_importer_cache, clean_entry, finder)
    monkeypatch.setitem(sys.path_importer_cache, poisoned_entry, finder)
    _clear_call_graph_caches()
    try:
        monkeypatch.setattr(sys, "path", [clean_entry])
        clean_search_context = call_graph._source_search_context()
        clean_importer_context = call_graph._path_importer_resolution_context(sys.path)
        assert call_graph._file_finder_resolution_identity(finder, clean_entry) is not None

        monkeypatch.setattr(sys, "path", [poisoned_entry])
        assert call_graph._source_search_context() != clean_search_context
        assert call_graph._path_importer_resolution_context(sys.path) != clean_importer_context
        assert call_graph._file_finder_resolution_identity(finder, poisoned_entry) is None
    finally:
        _clear_call_graph_caches()


def test_invalidated_file_finder_is_normalized_before_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "invalidated_cache_module"
    (tmp_path / f"{module}.py").write_text("value = 1\n", encoding="utf-8")
    path_entry = str(tmp_path)
    finder = FileFinder(path_entry, *_standard_file_finder_loader_details())
    assert finder.find_spec(module) is not None
    finder.invalidate_caches()
    assert object.__getattribute__(finder, "__dict__")["_path_mtime"] == -1

    with _standard_import_runtime(
        monkeypatch,
        module=module,
        importer_cache={path_entry: finder},
        search_path=[path_entry],
    ):
        first_context = call_graph._source_resolution_context()
        assert call_graph._source_resolution_context() == first_context
        assert object.__getattribute__(finder, "__dict__")["_path_mtime"] != -1


@pytest.mark.parametrize("transition", ["finder-to-none", "none-to-finder"])
def test_shared_cache_refreshes_when_loaded_package_importer_semantics_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    transition: str,
) -> None:
    parent_module = "loaded_cache_package"
    module = f"{parent_module}.child"
    package_path = tmp_path / "loaded-package-path"
    package_path.mkdir()
    (package_path / "child.py").write_text("class Entry:\n    pass\n", encoding="utf-8")
    path_entry = str(package_path)
    finder = FileFinder(path_entry, *_standard_file_finder_loader_details())
    assert finder.find_spec(module) is not None
    importer_cache: dict[Any, Any] = dict(sys.path_importer_cache)
    importer_cache[path_entry] = finder if transition == "finder-to-none" else None
    loaded_parent = ModuleType(parent_module)
    loaded_parent.__path__ = [path_entry]
    loaded_parent.__spec__ = ModuleSpec(parent_module, loader=None, is_package=True)
    monkeypatch.setitem(sys.modules, parent_module, loaded_parent)

    with (
        _standard_import_runtime(
            monkeypatch,
            module=module,
            importer_cache=importer_cache,
            trusted_site_package_root=tmp_path,
        ),
        call_graph.shared_source_sensitive_caches(),
    ):
        first_generation = call_graph._begin_shared_source_report()
        first_kind = call_graph._trusted_module_origin_kind(module)
        call_graph._ensure_shared_source_snapshot_stable(first_generation)
        importer_cache[path_entry] = None if transition == "finder-to-none" else finder
        second_generation = call_graph._begin_shared_source_report()
        second_kind = call_graph._trusted_module_origin_kind(module)
        call_graph._ensure_shared_source_snapshot_stable(second_generation)
    trusted_kind = first_kind if transition == "finder-to-none" else second_kind
    blocked_kind = second_kind if transition == "finder-to-none" else first_kind
    assert trusted_kind == "site_packages"
    assert blocked_kind == "unresolved"


def test_shared_cache_refreshes_when_unloaded_namespace_importer_semantics_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_module = "namespace_cache_package"
    module = f"{parent_module}.child"
    trusted_root = tmp_path / "trusted-root"
    later_root = tmp_path / "later-root"
    trusted_package = trusted_root / parent_module
    later_package = later_root / parent_module
    trusted_package.mkdir(parents=True)
    later_package.mkdir(parents=True)
    (trusted_package / "child.py").write_text("class Entry:\n    pass\n", encoding="utf-8")
    marker = tmp_path / "later-namespace-module-executed"
    (later_package / "child.py").write_text(
        f"open({str(marker)!r}, 'w').close()\nclass Entry:\n    pass\n",
        encoding="utf-8",
    )
    trusted_root_entry = str(trusted_root)
    later_root_entry = str(later_root)
    trusted_package_entry = str(trusted_package)
    importer_cache: dict[Any, Any] = {
        trusted_root_entry: FileFinder(trusted_root_entry, *_standard_file_finder_loader_details()),
        later_root_entry: FileFinder(later_root_entry, *_standard_file_finder_loader_details()),
    }

    with (
        _standard_import_runtime(
            monkeypatch,
            module=module,
            importer_cache=importer_cache,
            search_path=[trusted_root_entry, later_root_entry],
            trusted_site_package_root=trusted_root,
        ),
        call_graph.shared_source_sensitive_caches(),
    ):
        monkeypatch.delitem(sys.modules, parent_module, raising=False)
        first_generation = call_graph._begin_shared_source_report()
        first_kind = call_graph._trusted_module_origin_kind(module)
        call_graph._ensure_shared_source_snapshot_stable(first_generation)
        metadata = call_graph.shared_source_fingerprint_metadata()
        assert metadata is not None
        assert parent_module in metadata["namespace_package_resolution_contexts"]

        importer_cache[trusted_package_entry] = None
        second_generation = call_graph._begin_shared_source_report()
        second_kind = call_graph._trusted_module_origin_kind(module)
        call_graph._ensure_shared_source_snapshot_stable(second_generation)

        assert first_kind == "site_packages"
        assert second_kind is None
        assert second_generation != first_generation
        assert marker.exists() is False

        imported = importlib.import_module(module)
        assert imported.Entry is not None
    assert marker.exists() is True


@pytest.mark.parametrize("replacement", ["none", "custom"])
def test_shared_cache_tracks_unloaded_regular_package_importer_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: str,
) -> None:
    parent_module = "regular_cache_package"
    module = f"{parent_module}.child"
    trusted_root = tmp_path / "trusted-root"
    package_path = trusted_root / parent_module
    package_path.mkdir(parents=True)
    (package_path / "__init__.py").write_text("value = 1\n", encoding="utf-8")
    (package_path / "child.py").write_text("class Entry:\n    pass\n", encoding="utf-8")
    root_entry = str(trusted_root)
    package_entry = str(package_path)
    root_finder = FileFinder(root_entry, *_standard_file_finder_loader_details())
    package_finder = FileFinder(package_entry, *_standard_file_finder_loader_details())
    assert root_finder.find_spec(parent_module) is not None
    assert package_finder.find_spec(module) is not None
    calls: list[str] = []
    importer_cache: dict[Any, Any] = {
        root_entry: root_finder,
        package_entry: package_finder,
    }

    with (
        _standard_import_runtime(
            monkeypatch,
            module=module,
            importer_cache=importer_cache,
            search_path=[root_entry],
            trusted_site_package_root=trusted_root,
        ),
        call_graph.shared_source_sensitive_caches(),
    ):
        monkeypatch.delitem(sys.modules, parent_module, raising=False)
        first_generation = call_graph._begin_shared_source_report()
        assert call_graph._trusted_module_origin_kind(module) == "site_packages"
        call_graph._ensure_shared_source_snapshot_stable(first_generation)
        metadata = call_graph.shared_source_fingerprint_metadata()
        assert metadata is not None
        assert parent_module in metadata["namespace_package_resolution_contexts"]

        importer_cache[package_entry] = None if replacement == "none" else _FailIfExecutedFinder(calls)
        second_generation = call_graph._begin_shared_source_report()
        expected_kind = "unresolved" if replacement == "none" else None
        assert call_graph._trusted_module_origin_kind(module) == expected_kind
        call_graph._ensure_shared_source_snapshot_stable(second_generation)

    assert second_generation != first_generation
    assert calls == []


def test_loaded_package_cached_untrusted_importer_is_not_unresolved_trusted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, name = "pathlib._local", "PurePath"
    calls: list[str] = []
    pathlib_namespace = ModuleType.__getattribute__(sys.modules["pathlib"], "__dict__")
    package_entry = str(tmp_path.absolute())
    importer_cache: dict[Any, Any] = {
        **sys.path_importer_cache,
        package_entry: _FailIfExecutedFinder(calls),
    }
    monkeypatch.setitem(pathlib_namespace, "__path__", [package_entry])

    with _standard_import_runtime(monkeypatch, module=module, importer_cache=importer_cache):
        assert call_graph._trusted_module_origin_kind(module) is None
        report = package_api.scan_bytes(f"c{module}\n{name}\n.".encode(), source="cached-untrusted-parent.pkl")
    _assert_non_allowlisted_global(report, module, name)
    assert calls == []


def test_metadata_pathfinder_hook_removal_keeps_startup_distribution_roots_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if "find_distributions" not in type.__getattribute__(PathFinder, "__dict__"):
        pytest.skip("PathFinder has no stdlib distribution hook")
    trusted_root = call_graph._TRUSTED_SITE_PACKAGE_PATHS[0]
    metadata_path = trusted_root / "probe.dist-info"
    runtime_distribution_calls: list[str] = []

    def hostile_distribution(name: str) -> object:
        runtime_distribution_calls.append(name)
        raise AssertionError("runtime distribution discovery was executed")

    monkeypatch.setattr(
        call_graph,
        "_STARTUP_DISTRIBUTION_ROOTS",
        {"probe": ((metadata_path, tmp_path.resolve()),)},
    )
    monkeypatch.setattr(call_graph, "distribution", hostile_distribution)
    monkeypatch.delattr(PathFinder, "find_distributions")
    _clear_call_graph_caches()

    try:
        assert call_graph._interpreter_import_runtime_is_trusted() is True
        assert call_graph._installed_distribution_roots("probe") == (tmp_path.resolve(),)
        report = package_api.scan_bytes(b"cbuiltins\nprint\n.", source="metadata-finder-removed.pkl")
    finally:
        _clear_call_graph_caches()

    assert runtime_distribution_calls == []
    assert report.status == ScanStatus.COMPLETE
    assert not any(error.category == "call_graph_analysis_error" for error in report.errors)


def test_startup_distribution_root_capture_bounds_and_deduplicates_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_root = call_graph._TRUSTED_SITE_PACKAGE_PATHS[0]
    distribution_calls: list[str] = []

    class FakeDistribution:
        _path = trusted_root / "shared.dist-info"

        @staticmethod
        def locate_file(_name: str) -> Path:
            return tmp_path

    monkeypatch.setattr(
        call_graph,
        "packages_distributions",
        lambda: {"first": ["shared"], "second": ["shared"], "ignored": ["third"]},
    )

    def fake_distribution(name: str) -> FakeDistribution:
        distribution_calls.append(name)
        return FakeDistribution()

    monkeypatch.setattr(call_graph, "distribution", fake_distribution)
    monkeypatch.setattr(call_graph, "_MAX_STARTUP_DISTRIBUTION_NAMES", 2)

    captured = call_graph._capture_startup_distribution_roots()

    assert tuple(captured) == ("first", "second")
    assert captured["first"] == captured["second"] == ((FakeDistribution._path, tmp_path.resolve()),)
    assert distribution_calls == ["shared"]


def test_replaced_metadata_pathfinder_hook_blocks_without_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if "find_distributions" not in type.__getattribute__(PathFinder, "__dict__"):
        pytest.skip("PathFinder has no stdlib distribution hook")
    calls: list[object] = []

    def hostile_find_distributions(*args: object, **kwargs: object) -> tuple[()]:
        del kwargs
        calls.extend(args)
        raise AssertionError("mutated metadata finder was executed")

    monkeypatch.setattr(PathFinder, "find_distributions", hostile_find_distributions)
    _clear_call_graph_caches()

    try:
        assert call_graph._interpreter_import_runtime_is_trusted() is False
        assert call_graph._trusted_module_origin_kind("statistics") is None
    finally:
        _clear_call_graph_caches()

    assert calls == []


def test_added_import_runtime_type_hook_blocks_resolution_without_execution() -> None:
    calls: list[str] = []

    def hostile_getattribute(self: object, name: str) -> object:
        del self, name
        calls.append("FileFinder.__getattribute__")
        raise AssertionError("added import runtime type hook was executed")

    type.__setattr__(FileFinder, "__getattribute__", hostile_getattribute)
    _clear_call_graph_caches()

    try:
        assert call_graph._interpreter_import_runtime_is_trusted() is False
        assert call_graph._trusted_module_origin_kind("statistics") is None
    finally:
        type.__delattr__(FileFinder, "__getattribute__")
        _clear_call_graph_caches()

    assert calls == []


def test_added_import_runtime_data_descriptor_blocks_resolution_without_execution() -> None:
    calls: list[str] = []

    class HostilePath:
        def __get__(self, instance: object, owner: type[object] | None = None) -> object:
            del self, instance, owner
            calls.append("FileFinder.path.__get__")
            raise AssertionError("added import runtime descriptor was executed")

        def __set__(self, instance: object, value: object) -> None:
            del self, instance, value
            calls.append("FileFinder.path.__set__")
            raise AssertionError("added import runtime descriptor was executed")

    type.__setattr__(FileFinder, "path", HostilePath())
    _clear_call_graph_caches()

    try:
        assert call_graph._interpreter_import_runtime_is_trusted() is False
        assert call_graph._trusted_module_origin_kind("statistics") is None
    finally:
        type.__delattr__(FileFinder, "path")
        _clear_call_graph_caches()

    assert calls == []


def test_in_place_io_open_mutation_blocks_resolution_without_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen_importlib_external = sys.modules["_frozen_importlib_external"]
    frozen_namespace = ModuleType.__getattribute__(frozen_importlib_external, "__dict__")
    io_module = frozen_namespace["_io"]
    io_namespace = ModuleType.__getattribute__(io_module, "__dict__")
    calls: list[tuple[object, ...]] = []

    def hostile_open(*args: object, **kwargs: object) -> object:
        del kwargs
        calls.append(args)
        raise AssertionError("mutated _io.open was executed")

    monkeypatch.setitem(io_namespace, "open", hostile_open)
    _clear_call_graph_caches()

    try:
        assert call_graph._interpreter_import_runtime_is_trusted() is False
        assert call_graph._trusted_module_origin_kind("statistics") is None
    finally:
        _clear_call_graph_caches()

    assert calls == []


def test_import_runtime_dependency_prefers_frozen_namespace_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = ModuleType("canonical_dependency_name")
    monkeypatch.setitem(sys.modules, "frozen_dependency_name", module)

    assert (
        call_graph._import_runtime_dependency_module_name("frozen_dependency_name", module) == "frozen_dependency_name"
    )
    assert any(
        module_name == "_io" and dependency_module is sys.modules["_io"]
        for module_name, dependency_module, _ in call_graph._FROZEN_IMPORTLIB_EXTERNAL_DEPENDENCY_MODULES
    )


def test_replaced_sys_modules_mapping_blocks_resolution_without_execution() -> None:
    script = """
import sys

import modelaudit_picklescan.call_graph as call_graph

original_modules = sys.modules
calls = []

class HostileModules(dict):
    def get(self, key, default=None):
        calls.append(key)
        raise AssertionError("replacement sys.modules mapping was accessed")

sys.modules = HostileModules(original_modules)
try:
    runtime_is_trusted = call_graph._interpreter_import_runtime_is_trusted()
    origin_kind = call_graph._trusted_module_origin_kind("statistics")
finally:
    sys.modules = original_modules

assert runtime_is_trusted is False
assert origin_kind is None
assert calls == []
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_replaced_sys_modules_membership_blocks_unloaded_builtin_without_execution() -> None:
    script = """
import sys

import modelaudit_picklescan.call_graph as call_graph

module = next((name for name in sys.builtin_module_names if name not in sys.modules), None)
if module is None:
    raise SystemExit(0)
original_modules = sys.modules
calls = []

class HostileModules(dict):
    def __contains__(self, key):
        calls.append(key)
        raise AssertionError("replacement sys.modules membership was accessed")

sys.modules = HostileModules(original_modules)
try:
    call_graph._trusted_module_origin_kind.cache_clear()
    origin_kind = call_graph._trusted_module_origin_kind(module)
    source_reason = call_graph._call_graph_source_unavailable_reason(module)
    can_execute = call_graph._import_module_can_execute_user_code(module)
finally:
    sys.modules = original_modules
    call_graph._trusted_module_origin_kind.cache_clear()

assert origin_kind is None
assert source_reason == "source_unavailable"
assert can_execute is True
assert calls == []
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_cached_origin_is_rejected_after_import_runtime_mutation() -> None:
    module = "statistics"
    finder_function = type.__getattribute__(FileFinder, "__dict__")["find_spec"]
    original_code = finder_function.__code__

    def forged_find_spec(
        self: object,
        fullname: str,
        target: object | None = None,
    ) -> ModuleSpec | None:
        del self, fullname, target
        raise AssertionError("mutated filesystem import runtime was executed")

    _clear_call_graph_caches()
    assert call_graph._trusted_module_origin_kind(module) == "stdlib"
    finder_function.__code__ = forged_find_spec.__code__

    try:
        assert call_graph._interpreter_import_runtime_is_trusted() is False
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph.import_only_module_requires_origin_review(module, "mean") is True
    finally:
        finder_function.__code__ = original_code
        _clear_call_graph_caches()


def test_in_place_importer_code_mutation_blocks_unloaded_builtin() -> None:
    module = next((name for name in sys.builtin_module_names if name not in sys.modules), None)
    if module is None:
        pytest.skip("all builtin modules are already loaded")
    assert module is not None
    descriptor = type.__getattribute__(BuiltinImporter, "__dict__")["find_spec"]
    function = descriptor.__func__
    original_code = function.__code__

    def forged_find_spec(
        cls: type[object],
        fullname: str,
        path: object | None = None,
        target: object | None = None,
    ) -> ModuleSpec | None:
        del cls, fullname, path, target
        return None

    function.__code__ = forged_find_spec.__code__
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
    finally:
        function.__code__ = original_code
        _clear_call_graph_caches()


def test_in_place_import_runtime_dependency_mutation_blocks_unloaded_builtin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = next((name for name in sys.builtin_module_names if name not in sys.modules), None)
    if module is None:
        pytest.skip("all builtin modules are already loaded")
    assert module is not None
    frozen_importlib = sys.modules["_frozen_importlib"]
    frozen_namespace = ModuleType.__getattribute__(frozen_importlib, "__dict__")
    thread_module = frozen_namespace["_thread"]
    thread_namespace = ModuleType.__getattribute__(thread_module, "__dict__")
    calls: list[str] = []

    def hostile_rlock() -> object:
        calls.append("RLock")
        raise AssertionError("mutated import runtime dependency was executed")

    monkeypatch.setitem(thread_namespace, "RLock", hostile_rlock)
    _clear_call_graph_caches()

    try:
        assert call_graph._interpreter_import_runtime_is_trusted() is False
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
    finally:
        _clear_call_graph_caches()

    assert calls == []


def test_in_place_import_runtime_builtins_mutation_blocks_unloaded_builtin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = next((name for name in sys.builtin_module_names if name not in sys.modules), None)
    if module is None:
        pytest.skip("all builtin modules are already loaded")
    assert module is not None
    builtins_namespace = call_graph._IMPORT_RUNTIME_BUILTINS
    assert type(builtins_namespace) is dict
    calls: list[object] = []
    original_hasattr = builtins_namespace["hasattr"]

    def hostile_hasattr(value: object, name: str) -> bool:
        calls.append(value)
        return bool(cast(Any, original_hasattr)(value, name))

    monkeypatch.setitem(builtins_namespace, "hasattr", hostile_hasattr)
    _clear_call_graph_caches()

    try:
        assert call_graph._interpreter_import_runtime_is_trusted() is False
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
    finally:
        _clear_call_graph_caches()

    assert calls == []


def test_in_place_import_runtime_class_mutation_blocks_unloaded_builtin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = next((name for name in sys.builtin_module_names if name not in sys.modules), None)
    if module is None:
        pytest.skip("all builtin modules are already loaded")
    assert module is not None
    frozen_importlib = sys.modules["_frozen_importlib"]
    frozen_namespace = ModuleType.__getattribute__(frozen_importlib, "__dict__")
    module_lock = frozen_namespace["_ModuleLock"]
    original_init = type.__getattribute__(module_lock, "__dict__")["__init__"]
    calls: list[str] = []

    def hostile_init(self: object, name: str) -> None:
        del self, name
        calls.append("_ModuleLock.__init__")
        raise AssertionError("mutated import runtime class was executed")

    monkeypatch.setattr(module_lock, "__init__", hostile_init)
    _clear_call_graph_caches()

    try:
        assert call_graph._interpreter_import_runtime_is_trusted() is False
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
    finally:
        monkeypatch.setattr(module_lock, "__init__", original_init)
        _clear_call_graph_caches()

    assert calls == []


def test_in_place_file_finder_code_mutation_blocks_filesystem_resolution() -> None:
    finder_function = type.__getattribute__(FileFinder, "__dict__")["find_spec"]
    original_code = finder_function.__code__

    def forged_find_spec(
        cls: type[object],
        fullname: str,
        path: object | None = None,
        target: object | None = None,
    ) -> ModuleSpec | None:
        del cls, fullname, path, target
        raise AssertionError("mutated filesystem import runtime was executed")

    finder_function.__code__ = forged_find_spec.__code__
    _clear_call_graph_caches()

    try:
        assert call_graph._interpreter_import_runtime_is_trusted() is False
        assert call_graph._find_standard_filesystem_spec("modelaudit_tp_mutated_path_finder") is None
    finally:
        finder_function.__code__ = original_code
        _clear_call_graph_caches()


def test_hostile_importer_keyword_defaults_fail_closed_without_execution() -> None:
    module = next((name for name in sys.builtin_module_names if name not in sys.modules), None)
    if module is None:
        pytest.skip("all builtin modules are already loaded")
    assert module is not None
    descriptor = type.__getattribute__(BuiltinImporter, "__dict__")["find_spec"]
    function = descriptor.__func__
    original_keyword_defaults = function.__kwdefaults__
    calls: list[str] = []

    class HostileKeywordDefaults(dict[str, object]):
        def __bool__(self) -> bool:
            calls.append("bool")
            raise TypeError("keyword defaults truthiness was evaluated")

        def items(self) -> Any:
            calls.append("items")
            raise AssertionError("keyword defaults items hook was called")

    function.__kwdefaults__ = HostileKeywordDefaults()
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
    finally:
        function.__kwdefaults__ = original_keyword_defaults
        _clear_call_graph_caches()

    assert calls == []


def test_poisoned_import_lock_blocks_unloaded_builtin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = next((name for name in sys.builtin_module_names if name not in sys.modules), None)
    if module is None:
        pytest.skip("all builtin modules are already loaded")
    assert module is not None
    module_name = module
    bootstrap = call_graph._FROZEN_IMPORTLIB_MODULE
    assert type(bootstrap) is ModuleType
    namespace = ModuleType.__getattribute__(bootstrap, "__dict__")
    module_locks = namespace["_module_locks"]
    assert type(module_locks) is dict
    calls: list[str] = []

    class PoisonedKey:
        def __hash__(self) -> int:
            calls.append("hash")
            return hash(module_name)

        def __eq__(self, other: object) -> bool:
            del other
            calls.append("eq")
            raise AssertionError("poisoned import-lock key was compared")

    class PoisonedLock:
        def __call__(self) -> object:
            calls.append(module_name)
            return self

    monkeypatch.setattr(sys, "meta_path", [BuiltinImporter, FrozenImporter, PathFinder])
    monkeypatch.setitem(module_locks, PoisonedKey(), PoisonedLock())
    calls.clear()
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
    finally:
        _clear_call_graph_caches()

    assert calls == []


def test_unloaded_builtin_with_mutated_importer_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = next((name for name in sys.builtin_module_names if name not in sys.modules), None)
    if module is None:
        pytest.skip("all builtin modules are already loaded")
    assert module is not None
    builtin_calls: list[str] = []
    is_builtin_calls: list[str] = []
    original_builtin_find_spec = type.__getattribute__(BuiltinImporter, "__dict__")["find_spec"]

    def forged_is_builtin(name: str) -> int:
        is_builtin_calls.append(name)
        return 1

    type.__setattr__(BuiltinImporter, "find_spec", _fail_builtin_find_spec(builtin_calls))
    monkeypatch.setattr(_imp, "is_builtin", forged_is_builtin)
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
    finally:
        type.__setattr__(BuiltinImporter, "find_spec", original_builtin_find_spec)
        _clear_call_graph_caches()

    assert builtin_calls == []
    assert is_builtin_calls == []


def test_unloaded_frozen_module_with_pristine_import_runtime_remains_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen_names = getattr(_imp, "_frozen_module_names", lambda: ())()
    module = next(
        (
            name
            for name in frozen_names
            if name not in call_graph._TRUSTED_LOADED_INTERPRETER_MODULES
            and name not in sys.modules
            and call_graph._interpreter_module_origin_without_import_hooks(name) == "frozen"
        ),
        None,
    )
    if module is None:
        pytest.skip("all frozen modules were loaded when call_graph initialized")
    assert module is not None
    monkeypatch.setattr(sys, "meta_path", [BuiltinImporter, FrozenImporter, PathFinder])
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) == "stdlib"
        assert call_graph._call_graph_source_unavailable_reason(module) is None
        assert call_graph._import_module_can_execute_user_code(module) is False
    finally:
        _clear_call_graph_caches()


def test_unloaded_frozen_module_with_mutated_importer_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen_names = getattr(_imp, "_frozen_module_names", lambda: ())()
    module = next(
        (
            name
            for name in frozen_names
            if name not in call_graph._TRUSTED_LOADED_INTERPRETER_MODULES
            and name not in sys.modules
            and call_graph._interpreter_module_origin_without_import_hooks(name) == "frozen"
        ),
        None,
    )
    if module is None:
        pytest.skip("all frozen modules were loaded when call_graph initialized")
    assert module is not None
    frozen_calls: list[str] = []
    find_frozen_calls: list[str] = []
    original_frozen_find_spec = type.__getattribute__(FrozenImporter, "__dict__")["find_spec"]

    def forged_find_frozen(name: str, *args: object, **kwargs: object) -> object:
        del args, kwargs
        find_frozen_calls.append(name)
        return None

    type.__setattr__(FrozenImporter, "find_spec", _fail_frozen_find_spec(frozen_calls))
    monkeypatch.setattr(_imp, "find_frozen", forged_find_frozen)
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
    finally:
        type.__setattr__(FrozenImporter, "find_spec", original_frozen_find_spec)
        _clear_call_graph_caches()

    assert frozen_calls == []
    assert find_frozen_calls == []


def test_in_place_importer_closure_code_mutation_blocks_unloaded_frozen() -> None:
    frozen_names = getattr(_imp, "_frozen_module_names", lambda: ())()
    module = next(
        (
            name
            for name in frozen_names
            if name not in call_graph._TRUSTED_LOADED_INTERPRETER_MODULES
            and name not in sys.modules
            and call_graph._interpreter_module_origin_without_import_hooks(name) == "frozen"
        ),
        None,
    )
    if module is None:
        pytest.skip("all frozen modules were loaded when call_graph initialized")
    assert module is not None
    descriptor = type.__getattribute__(FrozenImporter, "__dict__")["get_code"]
    wrapper = descriptor.__func__
    inner = next(
        (cell.cell_contents for cell in wrapper.__closure__ or () if isinstance(cell.cell_contents, FunctionType)),
        None,
    )
    if inner is None:
        pytest.skip("FrozenImporter.get_code has no function closure")
    assert inner is not None
    original_code = inner.__code__

    def forged_get_code(cls: type[object], fullname: str) -> None:
        del cls, fullname

    inner.__code__ = forged_get_code.__code__
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
    finally:
        inner.__code__ = original_code
        _clear_call_graph_caches()


def test_late_loaded_builtin_with_canonical_spec_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = next((name for name in sys.builtin_module_names if name not in sys.modules), None)
    if module is None:
        pytest.skip("all builtin modules are already loaded")
    assert module is not None
    loaded_module = ModuleType(module)
    loaded_module.__spec__ = ModuleSpec(module, cast(Any, BuiltinImporter), origin="built-in")
    monkeypatch.setitem(sys.modules, module, loaded_module)
    _clear_call_graph_caches()

    try:
        assert call_graph._trusted_module_origin_kind(module) is None
        assert call_graph._call_graph_source_unavailable_reason(module) == "source_unavailable"
        assert call_graph._import_module_can_execute_user_code(module) is True
    finally:
        _clear_call_graph_caches()


def test_loaded_extension_export_does_not_fall_through_module_getattr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import _codecs
    from importlib.util import module_from_spec, spec_from_file_location

    module_name = "modelaudit_tp_extension_export"
    module_path = tmp_path / f"{module_name}.py"
    module_path.write_text(
        "import os\ndef __getattr__(name=None):\n    os.system('')\n    return None\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    spec = spec_from_file_location(module_name, module_path)
    assert spec is not None and spec.loader is not None
    loaded_module = module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, loaded_module)
    spec.loader.exec_module(loaded_module)
    namespace = ModuleType.__getattribute__(loaded_module, "__dict__")
    namespace["encode"] = _codecs.encode
    _clear_call_graph_caches()
    assert call_graph._loaded_extension_callable_bypasses_module_getattr(module_name, "encode") is False
    monkeypatch.setattr(
        call_graph,
        "_TRUSTED_LOADED_EXTENSION_EXPORT_OWNERS",
        {(module_name, "encode"): ("os",)},
    )
    assert call_graph._loaded_extension_callable_bypasses_module_getattr(module_name, "encode") is False
    monkeypatch.setattr(
        call_graph,
        "_TRUSTED_LOADED_EXTENSION_EXPORT_OWNERS",
        {(module_name, "encode"): ("_codecs",)},
    )
    reference = {
        "module": module_name,
        "name": "encode",
        "import_reference": f"{module_name}.encode",
        "opcode": "REDUCE",
        "positional_arg_count": 3,
    }
    _clear_call_graph_caches()

    try:
        bypasses_getattr = call_graph._loaded_extension_callable_bypasses_module_getattr(module_name, "encode")
        findings = call_graph.find_dangerous_call_graphs([reference], [reference])
    finally:
        _clear_call_graph_caches()

    assert bypasses_getattr is True
    assert findings == ()


def test_loaded_dangerous_builtin_cannot_impersonate_trusted_extension_export(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from importlib.util import module_from_spec, spec_from_file_location

    module_name = "modelaudit_tp_dangerous_extension_export"
    module_path = tmp_path / f"{module_name}.py"
    module_path.write_text(
        "import os\ndef __getattr__(name=None):\n    os.system('true')\n    return None\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    spec = spec_from_file_location(module_name, module_path)
    assert spec is not None and spec.loader is not None
    loaded_module = module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, loaded_module)
    spec.loader.exec_module(loaded_module)
    namespace = ModuleType.__getattribute__(loaded_module, "__dict__")
    namespace["_reconstruct"] = os.system
    owner = BuiltinFunctionType.__getattribute__(os.system, "__self__")
    assert type(owner) is ModuleType
    owner_name = ModuleType.__getattribute__(owner, "__name__")
    monkeypatch.setattr(
        call_graph,
        "_TRUSTED_LOADED_EXTENSION_EXPORT_OWNERS",
        {(module_name, "_reconstruct"): (owner_name,)},
    )
    reference = {
        "module": module_name,
        "name": "_reconstruct",
        "import_reference": f"{module_name}._reconstruct",
        "opcode": "REDUCE",
        "positional_arg_count": 1,
    }
    _clear_call_graph_caches()

    try:
        bypasses_getattr = call_graph._loaded_extension_callable_bypasses_module_getattr(module_name, "_reconstruct")
        findings = call_graph.find_dangerous_call_graphs([reference], [reference])
    finally:
        _clear_call_graph_caches()

    assert bypasses_getattr is False
    assert len(findings) == 1
    assert findings[0].sink == "os.system"


def test_loaded_extension_export_does_not_hide_legacy_dotted_module_getattr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import _codecs
    from importlib.util import module_from_spec, spec_from_file_location

    module_name = "modelaudit_tp_legacy_dotted_extension_export"
    module_path = tmp_path / f"{module_name}.py"
    module_path.write_text(
        "import os\ncalls = []\ndef __getattr__(name=None):\n"
        "    calls.append(name)\n    os.system('')\n    return None\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    spec = spec_from_file_location(module_name, module_path)
    assert spec is not None and spec.loader is not None
    loaded_module = module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, loaded_module)
    spec.loader.exec_module(loaded_module)
    namespace = ModuleType.__getattribute__(loaded_module, "__dict__")
    namespace["encode"] = _codecs.encode
    monkeypatch.setattr(
        call_graph,
        "_TRUSTED_LOADED_EXTENSION_EXPORT_OWNERS",
        {(module_name, "encode"): ("_codecs",)},
    )
    system_calls: list[str] = []

    def fake_system(command: str) -> int:
        system_calls.append(command)
        return 0

    monkeypatch.setattr(os, "system", fake_system)
    reference = {
        "module": module_name,
        "name": "encode.missing",
        "import_reference": f"{module_name}.encode.missing",
        "opcode": "GLOBAL",
    }
    _clear_call_graph_caches()

    try:
        bypasses_exact_export = call_graph._loaded_extension_callable_bypasses_module_getattr(module_name, "encode")
        findings = call_graph.find_dangerous_call_graphs([reference], [])
        payload = f"c{module_name}\nencode.missing\n.".encode()
        report = package_api.scan_bytes(payload, source="legacy-dotted-extension-export.pkl")
        runtime_calls = cast(list[str], namespace["calls"])
        assert runtime_calls == []
        loaded = pickle.loads(payload)
    finally:
        _clear_call_graph_caches()

    assert bypasses_exact_export is True
    assert loaded is None
    assert runtime_calls == ["encode.missing"]
    assert system_calls == [""]
    assert len(findings) == 1
    assert findings[0].sink == "os.system"
    public_findings = [finding for finding in report.findings if finding.rule_code == "DANGEROUS_CALL_GRAPH"]
    assert len(public_findings) == 1
    assert public_findings[0].details["sink"] == "os.system"
