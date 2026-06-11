import gzip
import os
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Literal

import pytest

from modelaudit import core
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.config import ModelAuditConfig, reset_config, set_config
from modelaudit.rules import Severity
from modelaudit.scanners import tar_scanner as tar_scanner_module
from modelaudit.scanners.archive_dispatch import NESTED_SCAN_CALLBACK_CONFIG_KEY
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.tar_scanner import (
    ARCHIVE_MEMBER_COPY_CHUNK_BYTES,
    DEFAULT_MAX_DECOMPRESSED_BYTES,
    DEFAULT_MAX_DECOMPRESSION_RATIO,
    DEFAULT_MAX_TAR_ENTRY_SIZE,
    TarScanner,
)


def _assert_inconclusive_aggregate_not_reused(
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

        stats = get_cache_manager(str(cache_dir), enabled=True).get_stats()
        assert stats["cache_hits"] == 0
        assert stats["total_entries"] == 0
    finally:
        reset_cache_manager()


class TestTarScanner:
    """Test the TAR scanner"""

    def setup_method(self):
        """Set up test fixtures"""
        self.scanner = TarScanner()

    def test_can_handle_tar_files(self):
        """Test that the scanner correctly identifies TAR files"""
        # Test uncompressed tar
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                info = tarfile.TarInfo("test.txt")
                content = b"Hello World"
                info.size = len(content)
                t.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]
            tmp_path = tmp.name

        try:
            assert TarScanner.can_handle(tmp_path) is True
            assert TarScanner.can_handle("/path/to/file.txt") is False
            assert TarScanner.can_handle("/path/to/file.pkl") is False
        finally:
            os.unlink(tmp_path)

    def test_can_handle_compressed_tar_files(self):
        """Test that the scanner correctly identifies compressed TAR files"""
        # Test tar.gz
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            with tarfile.open(tmp.name, "w:gz") as t:
                info = tarfile.TarInfo("test.txt")
                content = b"Hello World"
                info.size = len(content)
                t.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]
            tmp_path_gz = tmp.name

        # Test tar.bz2
        with tempfile.NamedTemporaryFile(suffix=".tar.bz2", delete=False) as tmp:
            with tarfile.open(tmp.name, "w:bz2") as t:
                info = tarfile.TarInfo("test.txt")
                content = b"Hello World"
                info.size = len(content)
                t.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]
            tmp_path_bz2 = tmp.name

        try:
            assert TarScanner.can_handle(tmp_path_gz) is True
            assert TarScanner.can_handle(tmp_path_bz2) is True
        finally:
            os.unlink(tmp_path_gz)
            os.unlink(tmp_path_bz2)

    def test_scan_simple_tar(self):
        """Test scanning a simple TAR file with text files"""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                # Add a file with content
                readme_info = tarfile.TarInfo("readme.txt")
                readme_content = b"This is a readme file"
                readme_info.size = len(readme_content)
                t.addfile(readme_info, tarfile.io.BytesIO(readme_content))  # type: ignore[attr-defined]

                # Add another file
                data_info = tarfile.TarInfo("data.json")
                data_content = b'{"key": "value"}'
                data_info.size = len(data_content)
                t.addfile(data_info, tarfile.io.BytesIO(data_content))  # type: ignore[attr-defined]
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            # Debug: print issues if any
            if result.issues:
                for issue in result.issues:
                    print(f"Issue: {issue.message}")
            assert result.success is True
            assert result.bytes_scanned > 0
            # Filter out DEBUG issues for unknown formats (txt, json files)
            non_debug_issues = [i for i in result.issues if i.severity != IssueSeverity.DEBUG]
            assert len(non_debug_issues) == 0
        finally:
            os.unlink(tmp_path)

    def test_scan_tar_flags_dangerous_python_member(self, tmp_path: Path) -> None:
        """Generic TAR files should scan Python source members for active payloads."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"import os\nos.system('echo hidden')\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].severity == IssueSeverity.WARNING
        assert python_checks[0].details["entry"] == "handler.py"
        assert result.success is True

    def test_scan_tar_flags_aliased_dangerous_python_member(self, tmp_path: Path) -> None:
        """Aliased high-risk calls should not bypass generic TAR Python member scanning."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"from os import system as run_command\nrun_command('echo hidden')\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].severity == IssueSeverity.WARNING
        assert python_checks[0].details["reason"] == "high-risk calls: os.system"

    def test_scan_tar_flags_wildcard_import_dangerous_python_member(self, tmp_path: Path) -> None:
        """Wildcard imports should resolve known high-risk call names."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"from subprocess import *\nrun(['echo', 'hidden'], check=False)\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].severity == IssueSeverity.WARNING
        assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"

    def test_scan_tar_flags_builtins_getattr_call_dangerous_python_member(self, tmp_path: Path) -> None:
        """getattr indirection should still resolve to the risky call name."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"import builtins as bi\nimport os\nbi.getattr(os, 'system').__call__('echo hidden')\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].severity == IssueSeverity.WARNING
        assert python_checks[0].rule_code == "S101"
        assert python_checks[0].details["reason"] == "high-risk calls: os.system"

    def test_scan_tar_flags_aliased_getattr_helper_dangerous_python_member(self, tmp_path: Path) -> None:
        """Aliased getattr helpers and module aliases should still resolve risky calls."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = (
            b"from builtins import getattr as resolve\n"
            b"import os as operating_system\n"
            b"resolve(operating_system, 'system')('echo hidden')\n"
        )

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].severity == IssueSeverity.WARNING
        assert python_checks[0].rule_code == "S101"
        assert python_checks[0].details["reason"] == "high-risk calls: os.system"

    def test_scan_tar_flags_concatenated_getattr_name_dangerous_python_member(self, tmp_path: Path) -> None:
        """Static string concatenation should not hide risky getattr targets."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"import os\ngetattr(os, 'sys' + 'tem')('echo hidden')\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].severity == IssueSeverity.WARNING
        assert python_checks[0].rule_code == "S101"
        assert python_checks[0].details["reason"] == "high-risk calls: os.system"

    def test_scan_tar_flags_namespace_mapping_dangerous_python_member(self, tmp_path: Path) -> None:
        """Module namespace dictionary lookup must not hide a risky call."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"import subprocess as sp\nvars(sp)['r' + 'un'](['echo', 'hidden'], check=False)\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].severity == IssueSeverity.WARNING
        assert python_checks[0].rule_code == "S103"
        assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"

    @pytest.mark.parametrize(
        "payload",
        [
            b"import os\nglobals()['os'].system('echo hidden')\n",
            b"import os\ngetattr(object, '__getattribute__')(os, 'sys' + 'tem')('echo hidden')\n",
            (
                b"import os\nnamespace = os.__dict__\nnamespace['runner'] = os.system\n"
                b"namespace['runner']('echo hidden')\n"
            ),
            (
                b"import os\nnamespace = globals()\nnamespace['runner'] = os.system\n"
                b"namespace['runner']('echo hidden')\n"
            ),
            b"import os\nglobals().setdefault('runner', os.system)\nrunner('echo hidden')\n",
            b"import os\nglobals().__setitem__('runner', os.system)\nrunner('echo hidden')\n",
            b"import os\nglobals()['runner'] = os.system\npopped = globals().pop('runner')\npopped('echo hidden')\n",
            b"import os\nos.__dict__['runner'] = os.system\nos.runner('echo hidden')\n",
            (
                b"import os\nos.__dict__['runner'] = os.system\n"
                b"popped = os.__dict__.pop('runner')\npopped('echo hidden')\n"
            ),
            b"import os\n[runner := os.system for _ in (1,)]\nrunner('echo hidden')\n",
            b"import os\nclass Install:\n    globals()['runner'] = os.system\nrunner('echo hidden')\n",
            b"import os\ndef run():\n    globals()['runner'] = os.system\n    runner('echo hidden')\nrun()\n",
            (
                b"import os\nrunner = os.system\nif bool():\n    globals()['runner'] = print\n"
                b"globals()['runner']('echo hidden')\n"
            ),
        ],
    )
    def test_scan_tar_flags_static_namespace_indirection_dangerous_python_member(
        self, tmp_path: Path, payload: bytes
    ) -> None:
        """Static namespace indirection should retain high-risk callable identity."""
        archive_path = tmp_path / "model_bundle.tar"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].rule_code == "S101"
        assert python_checks[0].details["reason"] == "high-risk calls: os.system"

    def test_scan_tar_flags_namespace_bound_os_process_launch(self, tmp_path: Path) -> None:
        """Namespace-write tracking must also preserve newly modeled OS launch APIs."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = (
            b"import os\n"
            b"namespace = os.__dict__\n"
            b"namespace['launch'] = os.posix_spawn\n"
            b"namespace['launch']('/bin/sh', ['sh'], {})\n"
        )

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].rule_code == "S101"
        assert python_checks[0].details["reason"] == "high-risk calls: os.posix_spawn"

    @pytest.mark.parametrize(
        ("payload", "dangerous_name"),
        [
            (
                b"import asyncio\nasyncio.create_subprocess_exec('/bin/sh', '-c', 'id')\n",
                "asyncio.create_subprocess_exec",
            ),
            (
                b"from asyncio import create_subprocess_shell as run\nrun('id')\n",
                "asyncio.create_subprocess_shell",
            ),
            (
                b"import asyncio.subprocess\nasyncio.subprocess.create_subprocess_shell('id')\n",
                "asyncio.subprocess.create_subprocess_shell",
            ),
            (
                b"import asyncio\nasyncio.create_subprocess_shell = len\nasyncio.create_subprocess_shell([])\n",
                "asyncio.create_subprocess_shell",
            ),
        ],
    )
    def test_scan_tar_flags_asyncio_subprocess_python_member(
        self, tmp_path: Path, payload: bytes, dangerous_name: str
    ) -> None:
        archive_path = tmp_path / "model_bundle.tar"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].rule_code == "S103"
        assert python_checks[0].details["reason"] == f"high-risk calls: {dangerous_name}"

    @pytest.mark.parametrize(
        ("payload", "dangerous_name"),
        [
            (b"import runpy\nrunpy._run_module_as_main('payload')\n", "runpy._run_module_as_main"),
            (b"import runpy\nrunpy.run_module('payload')\n", "runpy.run_module"),
            (b"from runpy import run_path as run\nrun('payload.py')\n", "runpy.run_path"),
        ],
    )
    def test_scan_tar_flags_runpy_execution_python_member(
        self, tmp_path: Path, payload: bytes, dangerous_name: str
    ) -> None:
        archive_path = tmp_path / "model_bundle.tar"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].rule_code == "S108"
        assert python_checks[0].details["reason"] == f"high-risk calls: {dangerous_name}"

    def test_scan_tar_flags_extensionless_runpy_python_member(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"import runpy\nrunpy.run_module('payload')\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].rule_code == "S108"
        assert python_checks[0].details["reason"] == "high-risk calls: runpy.run_module"

    def test_scan_tar_ignores_extensionless_runpy_near_match(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"documentation mentions runpy.run_module('payload')\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("notes")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert not any(check.name == "Python Archive Member Security" for check in result.checks)

    def test_scan_tar_allows_replaced_runpy_execution(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"import runpy\nrunpy.run_path = len\nrunpy.run_path([])\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert not any(check.name == "Python Archive Member Security" for check in result.checks)

    def test_scan_tar_ignores_runpy_member_after_module_alias_rebind(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"class Safe:\n    run_path = len\nimport runpy as rp\nrp = Safe()\nrp.run_path([])\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert not any(check.name == "Python Archive Member Security" for check in result.checks)

    def test_scan_tar_ignores_safe_namespace_slot_rebinding(self, tmp_path: Path) -> None:
        """A safe final callable bound through a module dictionary should remain clean."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = (
            b"import os\nnamespace = os.__dict__\nnamespace['runner'] = os.system\n"
            b"namespace['runner'] = print\nnamespace['runner']('safe')\n"
        )

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert not any(check.name == "Python Archive Member Security" for check in result.checks)

    def test_scan_tar_ignores_overwritten_module_namespace_import(self, tmp_path: Path) -> None:
        """A known module mapping overwrite should not retain a stale dangerous import."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = (
            b"import os\nclass Safe:\n    system = print\nnamespace = globals()\n"
            b"namespace['os'] = Safe\nnamespace['os'].system('safe')\n"
        )

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert not any(check.name == "Python Archive Member Security" for check in result.checks)

    def test_scan_tar_ignores_class_body_module_namespace_overwrite(self, tmp_path: Path) -> None:
        """A class-body globals write is an executed module namespace overwrite."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = (
            b"import os\nclass Safe:\n    system = print\nclass Replace:\n"
            b"    globals()['os'] = Safe\nos.system('safe')\n"
        )

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert not any(check.name == "Python Archive Member Security" for check in result.checks)

    def test_scan_tar_ignores_definite_safe_module_namespace_overwrite(self, tmp_path: Path) -> None:
        """A definitely executed safe mapping overwrite should suppress a stale alias."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = (
            b"import os\nrunner = os.system\nif True:\n    globals()['runner'] = print\nglobals()['runner']('safe')\n"
        )

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert not any(check.name == "Python Archive Member Security" for check in result.checks)

    @pytest.mark.parametrize(
        "payload",
        [
            b"import os\nos.__dict__['_safe'] = print\nos.__dict__.get('_safe', os.system)('safe')\n",
            b"import os\nos.__dict__['_safe'] = print\nos.__dict__.pop('_safe', os.system)('safe')\n",
            b"import os\nos.__dict__['_safe'] = print\nos.__dict__.setdefault('_safe', os.system)('safe')\n",
            b"import os\nrunner = print\nglobals().setdefault('runner', os.system)\nrunner('safe')\n",
            b"import os\nglobals()['runner'] = os.system\nglobals().pop('runner')\nrunner('safe')\n",
            b"import os\nos.__dict__['runner'] = os.system\nos.__dict__.pop('runner')\nos.runner('safe')\n",
            b"[locals()['__builtins__']['eval']('safe') for _ in (1,)]\n",
        ],
    )
    def test_scan_tar_ignores_benign_namespace_defaults_and_comprehension_locals(
        self, tmp_path: Path, payload: bytes
    ) -> None:
        """Definite safe namespace values and nested comprehension locals should stay clean."""
        archive_path = tmp_path / "model_bundle.tar"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert not any(check.name == "Python Archive Member Security" for check in result.checks)

    def test_scan_tar_flags_implicit_builtins_mapping_dangerous_python_member(self, tmp_path: Path) -> None:
        """Implicit builtins mapping lookup must not hide a risky call."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"__builtins__['ev' + 'al']('1 + 1')\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].rule_code == "S104"
        assert python_checks[0].details["reason"] == "high-risk calls: builtins.eval"

    def test_scan_tar_flags_rebound_dangerous_python_member(self, tmp_path: Path) -> None:
        """Callable rebindings should not bypass generic TAR Python member scanning."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"import subprocess\nrunner = subprocess.run\nrunner(['echo', 'hidden'], check=False)\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].severity == IssueSeverity.WARNING
        assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"

    def test_scan_tar_import_aliases_are_scoped_per_python_member(self, tmp_path: Path) -> None:
        """Local imports in one scope should not hide dangerous calls in another scope."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = (
            b"import subprocess\n"
            b"def helper() -> str:\n"
            b"    import os as subprocess\n"
            b"    return subprocess.getcwd()\n"
            b"def handler() -> None:\n"
            b"    subprocess.run(['echo', 'hidden'], check=False)\n"
        )

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"

    def test_scan_tar_method_does_not_capture_class_attribute_alias(self, tmp_path: Path) -> None:
        """Class attributes are not lexical aliases inside method bodies."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = (
            b"import subprocess\n"
            b"class Handler:\n"
            b"    subprocess = None\n"
            b"    def run(self) -> None:\n"
            b"        subprocess.run(['echo', 'hidden'], check=False)\n"
        )

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"

    def test_scan_tar_empty_loop_target_does_not_hide_later_dangerous_call(self, tmp_path: Path) -> None:
        """Loop targets should not unconditionally shadow imports after a maybe-empty loop."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = (
            b"import subprocess\nfor subprocess in ():\n    pass\nsubprocess.run(['echo', 'hidden'], check=False)\n"
        )

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"

    def test_scan_tar_nonempty_loop_target_shadows_dangerous_import(self, tmp_path: Path) -> None:
        """Definitely assigned loop targets should shadow imports after the loop."""
        archive_path = tmp_path / "source_bundle.tar"
        payload = b"import subprocess\nfor subprocess in (object(),):\n    pass\nsubprocess.run()\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("preprocess.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert not any(check.name == "Python Archive Member Security" for check in result.checks)
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    def test_scan_tar_conditional_target_does_not_hide_later_dangerous_call(self, tmp_path: Path) -> None:
        """Conditional assignments should not unconditionally shadow later imports."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = (
            b"import subprocess\nif False:\n    subprocess = None\nsubprocess.run(['echo', 'hidden'], check=False)\n"
        )

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"

    def test_scan_tar_conditional_aliases_preserve_dangerous_branch(self, tmp_path: Path) -> None:
        """Ambiguous conditional aliases should preserve any high-risk branch."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = (
            b"if __name__:\n"
            b"    import subprocess as sp\n"
            b"else:\n"
            b"    import os as sp\n"
            b"sp.run(['echo', 'hidden'], check=False)\n"
        )

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"

    def test_scan_tar_loop_body_alias_survives_to_later_dangerous_call(self, tmp_path: Path) -> None:
        """Aliases imported in possible loop bodies should remain visible afterward."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"for _ in (1,):\n    import subprocess as sp\nsp.run(['echo', 'hidden'], check=False)\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].details["reason"] == "high-risk calls: subprocess.run"

    def test_scan_tar_marks_malformed_python_member_incomplete(self, tmp_path: Path) -> None:
        """Malformed Python source should fail closed instead of passing as benign."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"def handler(:\n    pass\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert result.metadata["analysis_incomplete"] is True
        assert "tar_python_member_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].details["entry"] == "handler.py"
        assert python_checks[0].details["analysis_incomplete"] is True

    def test_scan_tar_ignores_benign_python_member(self, tmp_path: Path) -> None:
        """Benign Python source in generic TAR archives should not produce security findings."""
        archive_path = tmp_path / "model_bundle.tar"
        source = b"def preprocess(value: str) -> str:\n    return value.strip().lower()\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("preprocess.py")
            info.size = len(source)
            archive.addfile(info, tarfile.io.BytesIO(source))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert not any(check.name == "Python Archive Member Security" for check in result.checks)
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    def test_scan_tar_ignores_benign_python_file_operations(self, tmp_path: Path) -> None:
        """Ordinary source file I/O should not be reported as active payload code."""
        archive_path = tmp_path / "model_bundle.tar"
        source = (
            b"def load_config() -> tuple[str, str]:\n"
            b"    left = open('config-a.json', encoding='utf-8').read()\n"
            b"    right = open('config-b.json', encoding='utf-8').read()\n"
            b"    return left, right\n"
        )

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("preprocess.py")
            info.size = len(source)
            archive.addfile(info, tarfile.io.BytesIO(source))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert not any(check.name == "Python Archive Member Security" for check in result.checks)
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    def test_scan_tar_flags_executable_member(self, tmp_path: Path) -> None:
        """TAR archives must surface executable-suffix members for parity with ZIP."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"#!/bin/sh\necho hidden\n"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("bin/run.sh")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        executable_checks = [
            check
            for check in result.checks
            if check.name == "Executable Archive Member Detection" and check.status == CheckStatus.FAILED
        ]
        assert len(executable_checks) == 1
        assert executable_checks[0].severity == IssueSeverity.WARNING
        assert executable_checks[0].details["entry"] == "bin/run.sh"

    def test_scan_tar_flags_extensionless_executable_member(self, tmp_path: Path) -> None:
        """TAR archives should flag strong executable signatures without suffix help."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"\x7fELF" + b"\x00" * 64

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("bin/runme")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        executable_checks = [
            check
            for check in result.checks
            if check.name == "Executable Archive Member Detection" and check.status == CheckStatus.FAILED
        ]
        assert len(executable_checks) == 1
        assert executable_checks[0].severity == IssueSeverity.WARNING
        assert executable_checks[0].details["entry"] == "bin/runme"

    def test_scan_tar_marks_unconfirmed_pe_pointer_inconclusive(self, tmp_path: Path) -> None:
        """A bounded PE probe should report incomplete coverage without a PE signature."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = bytearray(64)
        payload[:2] = b"MZ"
        payload[0x3C:0x40] = ((1024 * 1024) + 1).to_bytes(4, "little")

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("bin/runme")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "tar_executable_member_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        assert not any(
            check.name == "Executable Archive Member Detection" and check.severity == IssueSeverity.WARNING
            for check in result.checks
        )

    @pytest.mark.parametrize(
        ("source", "expected_rule_code", "expected_call"),
        [
            (b"import os\nos.system('echo hidden')\n", "S101", "os.system"),
            (b"import subprocess\nsubprocess.run(['echo'], check=False)\n", "S103", "subprocess.run"),
            (b"import importlib\nimportlib.import_module('os')\n", "S107", "importlib.import_module"),
            (b"import runpy\nrunpy.run_path('payload.py')\n", "S108", "runpy.run_path"),
            (b"import ctypes\nctypes.CDLL(LIBRARY_PATH)\n", "S110", "ctypes.CDLL"),
            (b"from ctypes import CDLL as load\nload(LIBRARY_PATH)\n", "S110", "ctypes.CDLL"),
            (b"import webbrowser\nwebbrowser.open('https://example.invalid')\n", "S109", "webbrowser.open"),
            (
                b"from webbrowser import open_new_tab as launch\nlaunch('https://example.invalid')\n",
                "S109",
                "webbrowser.open_new_tab",
            ),
            (b"eval('1 + 1')\n", "S104", "eval"),
            (b"import pickle\npickle.loads(b'\\x80\\x04N.')\n", "S213", "pickle.loads"),
        ],
    )
    def test_scan_tar_python_member_emits_accurate_rule_code(
        self, tmp_path: Path, source: bytes, expected_rule_code: str, expected_call: str
    ) -> None:
        """Each risk category must surface its own rule code (os.system as S101, etc.)."""
        archive_path = tmp_path / "model_bundle.tar"
        source = source.replace(b"LIBRARY_PATH", repr(str(tmp_path / "libpayload.so")).encode())

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(source)
            archive.addfile(info, tarfile.io.BytesIO(source))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].rule_code == expected_rule_code
        assert expected_call in python_checks[0].details["reason"]

    @pytest.mark.parametrize(
        "source",
        [
            b"from ctypes import CDLL as load\nload = len\nload([])\n",
            b"import ctypes\nctypes.CDLL = len\nctypes.CDLL([])\n",
            b"from webbrowser import open as launch\nlaunch = len\nlaunch([])\n",
            b"import webbrowser\nwebbrowser.open = len\nwebbrowser.open([])\n",
        ],
    )
    def test_scan_tar_allows_shadowed_direct_python_member_primitives(self, tmp_path: Path, source: bytes) -> None:
        """Safe final bindings should not become ctypes or browser findings."""
        archive_path = tmp_path / "model_bundle.tar"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(source)
            archive.addfile(info, tarfile.io.BytesIO(source))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert not any(check.name == "Python Archive Member Security" for check in result.checks)

    def test_path_traversal_detection(self):
        """Test detection of path traversal attempts"""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                # Add file with path traversal
                info = tarfile.TarInfo("../../evil.txt")
                content = b"malicious content"
                info.size = len(content)
                t.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is False
            path_traversal_issues = [i for i in result.issues if "path traversal" in i.message.lower()]
            assert len(path_traversal_issues) > 0
            assert any(i.severity == IssueSeverity.CRITICAL for i in path_traversal_issues)
        finally:
            os.unlink(tmp_path)

    def test_symlink_outside_extraction_root(self):
        """Symlinks resolving outside the extraction root should be flagged"""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                # Create a symlink pointing outside
                info = tarfile.TarInfo("link.txt")
                info.type = tarfile.SYMTYPE
                info.linkname = "../../../etc/passwd"
                t.addfile(info)
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is False
            symlink_issues = [i for i in result.issues if "symlink" in i.message.lower()]
            assert len(symlink_issues) > 0
            assert any("outside" in i.message.lower() for i in symlink_issues)
        finally:
            os.unlink(tmp_path)

    def test_symlink_outside_extraction_root_uses_dedicated_rule(self, tmp_path: Path) -> None:
        """External TAR links must use the dedicated symlink escape rule."""
        archive_path = tmp_path / "external_link.tar"
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("link.txt")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../../etc/passwd"
            archive.addfile(info)

        result = self.scanner.scan(str(archive_path))

        symlink_checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
        assert result.success is False
        assert len(symlink_checks) == 1
        assert symlink_checks[0].rule_code == "S406"
        assert symlink_checks[0].severity == IssueSeverity.CRITICAL
        assert symlink_checks[0].details == {"target": "../../../etc/passwd", "entry": "link.txt"}

    def test_parent_relative_symlink_within_archive_is_safe(self, tmp_path: Path) -> None:
        """A symlink may traverse its parent while remaining inside the archive root."""
        archive_path = tmp_path / "parent_relative_link.tar"
        with tarfile.open(archive_path, "w") as archive:
            target = tarfile.TarInfo("weights.bin")
            target.size = 0
            archive.addfile(target, tarfile.io.BytesIO(b""))  # type: ignore[attr-defined]

            link = tarfile.TarInfo("nested/link.bin")
            link.type = tarfile.SYMTYPE
            link.linkname = "../weights.bin"
            archive.addfile(link)

        result = self.scanner.scan(str(archive_path))

        symlink_checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
        assert result.success is True
        assert symlink_checks == []

    def test_archive_root_relative_hardlink_within_archive_is_safe(self, tmp_path: Path) -> None:
        """TAR hardlink targets are resolved from the archive root, not the member parent."""
        archive_path = tmp_path / "root_relative_hardlink.tar"
        with tarfile.open(archive_path, "w") as archive:
            target = tarfile.TarInfo("weights.bin")
            target.size = 0
            archive.addfile(target, tarfile.io.BytesIO(b""))  # type: ignore[attr-defined]

            link = tarfile.TarInfo("nested/link.bin")
            link.type = tarfile.LNKTYPE
            link.linkname = "weights.bin"
            archive.addfile(link)

        result = self.scanner.scan(str(archive_path))

        symlink_checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
        assert result.success is True
        assert symlink_checks == []

    def test_many_safe_links_do_not_amplify_scan_results(self, tmp_path: Path) -> None:
        """Benign link floods must not create one passing check per TAR member."""
        archive_path = tmp_path / "many_safe_links.tar"
        with tarfile.open(archive_path, "w") as archive:
            for index in range(250):
                link = tarfile.TarInfo(f"links/link-{index}")
                link.type = tarfile.SYMTYPE
                link.linkname = "../targets/model.bin"
                archive.addfile(link)

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert not [check for check in result.checks if check.name == "Symlink Safety Validation"]

    def test_hardlink_outside_extraction_root_survives_s902_suppression(self, tmp_path: Path) -> None:
        """Suppressing generic structure noise must not suppress TAR hardlink escapes."""
        archive_path = tmp_path / "external_link_suppressed.tar"
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("nested/link.txt")
            info.type = tarfile.LNKTYPE
            info.linkname = "../outside"
            archive.addfile(info)

        reset_config()
        set_config(ModelAuditConfig(suppress={"S902"}))
        try:
            result = self.scanner.scan(str(archive_path))
        finally:
            reset_config()

        symlink_checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
        assert result.success is False
        assert len(symlink_checks) == 1
        assert symlink_checks[0].rule_code == "S406"
        assert symlink_checks[0].message == "Hard link nested/link.txt resolves outside extraction directory"
        assert symlink_checks[0].details["entry"] == "nested/link.txt"

    @pytest.mark.parametrize(
        ("link_type", "expected_kind"),
        [(tarfile.SYMTYPE, "Symlink"), (tarfile.LNKTYPE, "Hard link")],
    )
    def test_empty_link_target_fails_closed(
        self,
        tmp_path: Path,
        link_type: bytes,
        expected_kind: str,
    ) -> None:
        """Malformed archive links with empty targets must not be reported as safe."""
        archive_path = tmp_path / f"empty_{expected_kind.lower().replace(' ', '_')}.tar"
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("nested/link.txt")
            info.type = link_type
            info.linkname = ""
            archive.addfile(info)

        result = self.scanner.scan(str(archive_path))

        link_checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
        assert result.success is False
        assert len(link_checks) == 1
        assert link_checks[0].rule_code == "S406"
        assert link_checks[0].message == f"{expected_kind} nested/link.txt has an empty target"
        assert link_checks[0].details == {"target": "", "entry": "nested/link.txt"}

    def test_symlink_outside_extraction_root_respects_s406_suppression(self, tmp_path: Path) -> None:
        """The dedicated link escape rule remains directly suppressible."""
        archive_path = tmp_path / "external_link_s406_suppressed.tar"
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("link.txt")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../../etc/passwd"
            archive.addfile(info)

        reset_config()
        set_config(ModelAuditConfig(suppress={"S406"}))
        try:
            result = self.scanner.scan(str(archive_path))
        finally:
            reset_config()

        assert result.success is True
        assert not any(check.rule_code == "S406" for check in result.checks)

    def test_symlink_to_critical_path(self):
        """Symlinks targeting critical system paths should be flagged"""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                # Create a symlink to critical path
                info = tarfile.TarInfo("etc_passwd")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                t.addfile(info)
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is False
            symlink_issues = [i for i in result.issues if "symlink" in i.message.lower()]
            assert any("critical system" in i.message.lower() for i in symlink_issues)
        finally:
            os.unlink(tmp_path)

    def test_nested_tar_scanning(self):
        """Test scanning TAR files containing other TAR files"""
        # Create inner tar
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as inner_tmp:
            with tarfile.open(inner_tmp.name, "w") as inner_tar:
                info = tarfile.TarInfo("inner.txt")
                content = b"Inner content"
                info.size = len(content)
                inner_tar.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]
            inner_path = inner_tmp.name

        # Create outer tar containing inner tar
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as outer_tmp:
            with tarfile.open(outer_tmp.name, "w") as outer_tar:
                outer_tar.add(inner_path, "nested.tar")
            outer_path = outer_tmp.name

        try:
            result = self.scanner.scan(outer_path)
            assert result.success is True
            # Check that nested content was scanned
            assert "contents" in result.metadata
            assert len(result.metadata["contents"]) > 0
        finally:
            os.unlink(inner_path)
            os.unlink(outer_path)

    def test_max_depth_limit(self, tmp_path: Path) -> None:
        """Test that maximum nesting depth is enforced"""
        # Create deeply nested tars
        tar_paths: list[str] = []
        content = b"Deep content"

        for i in range(7):  # Create 7 levels of nesting (exceeds default max of 5)
            with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
                with tarfile.open(tmp.name, "w") as t:
                    if i == 0:
                        # Innermost tar
                        info = tarfile.TarInfo("deep.txt")
                        info.size = len(content)
                        t.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]
                    else:
                        # Add previous tar
                        t.add(tar_paths[-1], f"level{i}.tar")
                tar_paths.append(tmp.name)

        try:
            result = self.scanner.scan(tar_paths[-1])
            assert result.success is False
            depth_issues = [i for i in result.issues if "maximum" in i.message.lower() and "depth" in i.message.lower()]
            assert len(depth_issues) > 0
            assert depth_issues[0].severity == IssueSeverity.WARNING
            assert depth_issues[0].rule_code == "S902"
            assert "tar_depth_limit" in result.metadata["scan_outcome_reasons"]
            _assert_inconclusive_aggregate_not_reused(
                Path(tar_paths[-1]),
                "tar_depth_limit",
                tmp_path / "depth-limit-cache",
                expected_exit_code=1,
                expected_security_findings=True,
            )
        finally:
            for path in tar_paths:
                if os.path.exists(path):
                    os.unlink(path)

    def test_scan_tar_with_pickle_file(self):
        """Test scanning TAR containing pickle files"""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                # Add a safe pickle file
                import pickle

                data = pickle.dumps({"key": "value"})
                info = tarfile.TarInfo("data.pkl")
                info.size = len(data)
                t.addfile(info, tarfile.io.BytesIO(data))  # type: ignore[attr-defined]
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is True
            # Should have scanned the pickle file inside
            assert result.bytes_scanned > 0
        finally:
            os.unlink(tmp_path)

    def test_scan_tar_with_proto0_pickle_preserves_archive_context(self, tmp_path: Path) -> None:
        """Malicious TAR members should surface critical findings with archive-qualified locations."""
        archive_path = tmp_path / "proto0_payload.tar"
        payload = b'cos\nsystem\n(S"echo pwned"\ntR.'

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("payload.txt")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert result.has_errors is True
        critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
        assert any(
            "os.system" in issue.message.lower() or "posix.system" in issue.message.lower() for issue in critical_issues
        )
        assert any(issue.location == f"{archive_path}:payload.txt" for issue in critical_issues)

    def test_scan_extensionless_nested_gzip_recurses_by_header(self, tmp_path: Path) -> None:
        """Extensionless gzip members should route through CompressedScanner by header."""
        archive_path = tmp_path / "outer.tar"
        payload = b'cos\nsystem\n(S"echo tar gzip payload"\ntR.'
        compressed_payload = gzip.compress(payload)

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("compressed_payload")
            info.size = len(compressed_payload)
            archive.addfile(info, tarfile.io.BytesIO(compressed_payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert result.has_errors is True
        routing_checks = [check for check in result.checks if check.name == "Compressed Wrapper Inner Scanner Routing"]
        assert any(
            check.details.get("inner_scanner") == "pickle" and check.details.get("tar_entry") == "compressed_payload"
            for check in routing_checks
        ), f"Expected compressed nested routing check, got: {[(c.location, c.details) for c in routing_checks]}"
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and issue.details.get("tar_entry") == "compressed_payload"
            and ("os.system" in issue.message.lower() or "posix.system" in issue.message.lower())
            for issue in result.issues
        ), (
            "Expected critical nested compressed pickle finding, got: "
            f"{[(i.location, i.message, i.details) for i in result.issues]}"
        )

    def test_invalid_tar_file(self):
        """Test handling of invalid TAR files"""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            # Write invalid data
            tmp.write(b"This is not a valid tar file")
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is False
            assert any("not a valid tar file" in i.message.lower() for i in result.issues)
        finally:
            os.unlink(tmp_path)

    def test_nested_compressed_tar_scanning(self):
        """Test scanning TAR files containing compressed TAR files"""
        # Create inner tar.gz
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as inner_tmp:
            with tarfile.open(inner_tmp.name, "w:gz") as inner_tar:
                info = tarfile.TarInfo("inner.txt")
                content = b"Inner compressed content"
                info.size = len(content)
                inner_tar.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]
            inner_path = inner_tmp.name

        # Create outer tar containing inner tar.gz
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as outer_tmp:
            with tarfile.open(outer_tmp.name, "w") as outer_tar:
                outer_tar.add(inner_path, "nested.tar.gz")
            outer_path = outer_tmp.name

        try:
            result = self.scanner.scan(outer_path)
            assert result.success is True
            # Check that nested compressed tar was scanned
            assert "contents" in result.metadata
            assert len(result.metadata["contents"]) > 0
            # Should find the nested.tar.gz in contents
            nested_found = any("nested.tar.gz" in content.get("path", "") for content in result.metadata["contents"])
            assert nested_found
        finally:
            os.unlink(inner_path)
            os.unlink(outer_path)

    def test_tar_bytes_scanned(self):
        """Ensure bytes scanned equals the sum of embedded files"""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                import pickle

                data1 = pickle.dumps({"a": 1})
                data2 = pickle.dumps({"b": 2})

                info1 = tarfile.TarInfo("one.pkl")
                info1.size = len(data1)
                t.addfile(info1, tarfile.io.BytesIO(data1))  # type: ignore[attr-defined]

                info2 = tarfile.TarInfo("two.pkl")
                info2.size = len(data2)
                t.addfile(info2, tarfile.io.BytesIO(data2))  # type: ignore[attr-defined]
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is True
            expected = len(data1) + len(data2)
            assert result.bytes_scanned == expected
        finally:
            os.unlink(tmp_path)

    def test_scan_large_valid_tar_bypasses_generic_max_file_read_size(self, tmp_path: Path) -> None:
        """TAR-owned streaming should not inherit the generic whole-file read rejection."""
        archive_path = tmp_path / "large_by_padding.tar"
        payload = b"safe metadata"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("metadata.txt")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        assert archive_path.stat().st_size > 1024

        result = TarScanner(config={"max_file_read_size": 1024, "max_entry_size": 4096}).scan(str(archive_path))

        assert result.success is True
        assert result.scanner_name == "tar"
        assert "max_file_read_size_exceeded" not in result.metadata.get("scan_outcome_reasons", [])
        assert not any(
            check.name == "File Size Limit" and check.status == CheckStatus.FAILED for check in result.checks
        )
        entry_checks = [check for check in result.checks if check.name == "Entry Count Limit Check"]
        assert len(entry_checks) == 1
        assert entry_checks[0].status == CheckStatus.PASSED
        assert result.metadata["contents"][0]["path"] == f"{archive_path}:metadata.txt"

    def test_large_tar_path_traversal_still_fails_after_read_cap_bypass(self, tmp_path: Path) -> None:
        """Bypassing the generic read cap must not bypass TAR traversal protection."""
        archive_path = tmp_path / "large_traversal.tar"
        payload = b"evil"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("../evil.txt")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        assert archive_path.stat().st_size > 1024

        result = TarScanner(config={"max_file_read_size": 1024}).scan(str(archive_path))

        traversal_checks = [check for check in result.checks if check.name == "Path Traversal Protection"]
        assert result.success is False
        assert len(traversal_checks) == 1
        assert traversal_checks[0].rule_code == "S405"
        assert traversal_checks[0].severity == IssueSeverity.CRITICAL
        assert traversal_checks[0].details["entry"] == "../evil.txt"
        assert "max_file_read_size_exceeded" not in result.metadata.get("scan_outcome_reasons", [])

    def test_large_tar_oversized_member_records_inventory_after_read_cap_bypass(self, tmp_path: Path) -> None:
        """Large skipped members should produce TAR-specific incomplete coverage and inventory."""
        archive_path = tmp_path / "large_oversized_member.tar"
        payload = b"A" * 128

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = TarScanner(config={"max_file_read_size": 1024, "max_entry_size": 64}).scan(str(archive_path))

        entry_checks = [check for check in result.checks if check.name == "TAR Entry Scan"]
        assert result.success is False
        assert len(entry_checks) == 1
        assert "exceeds maximum size of 64 bytes" in entry_checks[0].message
        assert "tar_entry_extraction_incomplete" in result.metadata["scan_outcome_reasons"]
        assert "max_file_read_size_exceeded" not in result.metadata["scan_outcome_reasons"]
        assert result.metadata["contents"] == [
            {
                "path": f"{archive_path}:payload.bin",
                "type": "tar_file",
                "size": len(payload),
                "scan_status": "incomplete",
                "scan_outcome_reason": "tar_entry_extraction_incomplete",
            }
        ]

    def test_large_malformed_tar_reports_format_validation_not_generic_size_limit(self, tmp_path: Path) -> None:
        """Malformed TAR-looking files should reach TAR validation even over the generic read cap."""
        archive_path = tmp_path / "malformed.tar"
        archive_path.write_bytes(b"not a tar stream" * 256)

        result = TarScanner(config={"max_file_read_size": 1024}).scan(str(archive_path))

        format_checks = [check for check in result.checks if check.name == "TAR File Format Validation"]
        assert result.success is False
        assert len(format_checks) == 1
        assert format_checks[0].rule_code == "S902"
        assert "not a valid tar file" in format_checks[0].message.lower()
        assert "tar_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        assert "max_file_read_size_exceeded" not in result.metadata["scan_outcome_reasons"]

    def test_compressed_tar_bomb_over_read_cap_still_hits_wrapper_limit(self, tmp_path: Path) -> None:
        """Compressed TAR limits remain active after the scanner-level read cap is bypassed."""
        archive_path = tmp_path / "bombish.tar.gz"
        payload = b"B" * 10_000

        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = TarScanner(
            config={
                "max_file_read_size": 1,
                "compressed_max_decompressed_bytes": 1024,
            }
        ).scan(str(archive_path))

        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert result.success is False
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert "decompressed size exceeded" in limit_checks[0].message.lower()
        assert "max_file_read_size_exceeded" not in result.metadata["scan_outcome_reasons"]

    def test_core_max_file_size_still_rejects_oversized_tar_before_tar_scan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The operator hard stop remains a core-level limit, distinct from scanner read caps."""
        archive_path = tmp_path / "operator_limit.tar"
        payload = b"safe"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("metadata.txt")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        def fail_scan(_self: TarScanner, _path: str) -> ScanResult:
            raise AssertionError("core max_file_size should reject before TarScanner.scan")

        monkeypatch.setattr(TarScanner, "scan", fail_scan)

        result = core.scan_file(str(archive_path), config={"max_file_size": 1, "cache_enabled": False})

        assert result.scanner_name == "size_check"
        assert result.success is False
        assert any(
            check.name == "File Size Limit Check" and check.status == CheckStatus.FAILED for check in result.checks
        )

    @pytest.mark.slow
    @pytest.mark.integration
    def test_real_hf_bert_large_tar_gz_reaches_tar_terminal_outcome(self, tmp_path: Path) -> None:
        """Opt-in real-model reproduction for task 38's pinned Hugging Face artifact."""
        if os.environ.get("MODELAUDIT_RUN_HF_T38_REAL_MODEL") != "1":
            pytest.skip("set MODELAUDIT_RUN_HF_T38_REAL_MODEL=1 to download the pinned 1.25 GB HF artifact")

        from modelaudit.utils.sources.huggingface import download_file_from_hf

        url = (
            "https://huggingface.co/google-bert/bert-large-uncased/resolve/"
            "6da4b6a26a1877e173fca3225479512db81a5e5b/whole-word-masking.tar.gz"
        )
        model_path = download_file_from_hf(url, cache_dir=tmp_path / "hf-cache", max_size=2 * 1024 * 1024 * 1024)

        result = core.scan_model_directory_or_file(str(model_path), cache_enabled=False, max_file_size=2 * 1024**3)

        metadata = result.file_metadata[str(model_path)]
        assert "tar" in metadata["scanner_dependency_ids"]
        assert "max_file_read_size_exceeded" not in metadata.get("scan_outcome_reasons", [])
        assert "tar_entry_extraction_incomplete" in metadata.get("scan_outcome_reasons", [])
        assert any(asset.path == str(model_path) and asset.contents for asset in result.assets)

    def test_get_max_entry_size_uses_bounded_default(self) -> None:
        """Unconfigured TAR entry extraction should still have a bounded default."""
        assert TarScanner()._get_max_entry_size() == DEFAULT_MAX_TAR_ENTRY_SIZE

    def test_get_max_entry_size_prefers_explicit_entry_limit(self) -> None:
        """The TAR entry limit should not be raised by a larger top-level archive cap."""
        scanner = TarScanner(config={"max_file_size": 4096, "max_entry_size": 128})
        assert scanner._get_max_entry_size() == 128

    def test_get_max_entry_size_uses_entry_limit_when_file_size_is_unlimited(self) -> None:
        """An explicit TAR-entry limit should apply when the top-level file size is unlimited."""
        scanner = TarScanner(config={"max_file_size": 0, "max_entry_size": 128})
        assert scanner._get_max_entry_size() == 128

    def test_get_max_entry_size_uses_bounded_default_when_max_file_size_is_unlimited(self) -> None:
        """A top-level unlimited file-size config should not disable TAR member extraction limits."""
        scanner = TarScanner(config={"max_file_size": 0})
        assert scanner._get_max_entry_size() == DEFAULT_MAX_TAR_ENTRY_SIZE

    def test_invalid_limit_configs_fall_back_to_defaults(self) -> None:
        """Malformed TAR limit config values should not raise during scanner initialization."""
        scanner = TarScanner(
            config={
                "max_file_size": "bad",
                "max_entry_size": "bad",
                "compressed_max_decompressed_bytes": "bad",
                "compressed_max_decompression_ratio": "bad",
            }
        )

        assert scanner._get_max_entry_size() == DEFAULT_MAX_TAR_ENTRY_SIZE
        assert scanner.max_decompressed_bytes == DEFAULT_MAX_DECOMPRESSED_BYTES
        assert scanner.max_decompression_ratio == DEFAULT_MAX_DECOMPRESSION_RATIO

    def test_extract_member_to_tempfile_streams_in_chunks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Large TAR entries should be copied in bounded chunks instead of buffered in memory."""
        content = b"A" * 10_000
        archive_path = tmp_path / "payload.tar"
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(content)
            archive.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]

        read_sizes: list[int | None] = []
        original_read = tarfile.ExFileObject.read

        def tracked_read(self: tarfile.ExFileObject, size: int | None = None) -> bytes:
            read_sizes.append(size)
            return original_read(self, size)

        monkeypatch.setattr(tarfile.ExFileObject, "read", tracked_read)

        with tarfile.open(archive_path, "r") as archive:
            member = archive.getmember("payload.bin")
            extracted_path, total_size = self.scanner._extract_member_to_tempfile(
                archive,
                member,
                suffix="_payload.bin",
            )

        try:
            assert total_size == len(content)
            assert Path(extracted_path).read_bytes() == content
            assert len(read_sizes) > 1
            assert set(read_sizes) == {ARCHIVE_MEMBER_COPY_CHUNK_BYTES}
        finally:
            os.unlink(extracted_path)

    def test_scan_rejects_oversized_tar_member(self, tmp_path: Path) -> None:
        """Entries exceeding the configured limit should fail the scan before full extraction."""
        scanner = TarScanner(config={"max_entry_size": 64})
        archive_path = tmp_path / "oversized.tar"
        payload = b"B" * 128

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = scanner.scan(str(archive_path))

        assert result.success is False
        oversize_checks = [check for check in result.checks if check.name == "TAR Entry Scan"]
        assert len(oversize_checks) == 1
        assert oversize_checks[0].severity == IssueSeverity.INFO
        assert "tar entry payload.bin exceeds maximum size of 64 bytes" in oversize_checks[0].message.lower()
        assert "tar_entry_extraction_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_oversized_benign_tar_member_returns_inconclusive_exit_code(self, tmp_path: Path) -> None:
        """Skipped ordinary member content is incomplete coverage, not a security finding."""
        archive_path = tmp_path / "oversized_benign.tar"
        payload = b"ordinary metadata " * 10

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("notes.txt")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        _assert_inconclusive_aggregate_not_reused(
            archive_path,
            "tar_entry_extraction_incomplete",
            tmp_path / "oversized-benign-cache",
            max_entry_size=64,
        )

    def test_oversized_entry_name_cannot_inherit_symlink_severity_override(self, tmp_path: Path) -> None:
        """Attacker-controlled entry names must not recast incomplete coverage as symlink findings."""
        archive_path = tmp_path / "oversized_named_symlink.tar"
        payload = b"ordinary metadata " * 10

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("symlink.txt")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        reset_config()
        set_config(ModelAuditConfig(severity={"S406": Severity.CRITICAL}))
        try:
            direct = TarScanner(config={"max_entry_size": 64}).scan(str(archive_path))
            entry_checks = [check for check in direct.checks if check.name == "TAR Entry Scan"]
            assert len(entry_checks) == 1
            assert entry_checks[0].rule_code == "S902"
            assert entry_checks[0].severity == IssueSeverity.INFO

            aggregate = core.scan_model_directory_or_file(
                str(archive_path),
                cache_enabled=False,
                max_entry_size=64,
            )
            assert core.determine_exit_code(aggregate) == 2
        finally:
            reset_config()

    def test_incomplete_tar_does_not_cache_temporary_nested_members(self, tmp_path: Path) -> None:
        """A later coverage gap must not leave earlier extracted child scans cached."""
        archive_path = tmp_path / "mixed_nested_cache.tar"
        malicious_payload = b'cos\nsystem\n(S"echo pwned"\ntR.'

        with tarfile.open(archive_path, "w") as archive:
            nested = tarfile.TarInfo("payload.pkl")
            nested.size = len(malicious_payload)
            archive.addfile(nested, tarfile.io.BytesIO(malicious_payload))  # type: ignore[attr-defined]

            oversized = b"A" * 128
            info = tarfile.TarInfo("large.bin")
            info.size = len(oversized)
            archive.addfile(info, tarfile.io.BytesIO(oversized))  # type: ignore[attr-defined]

        cache_dir = tmp_path / "nested-member-cache"
        reset_cache_manager()
        try:
            for _ in range(2):
                aggregate = core.scan_model_directory_or_file(
                    str(archive_path),
                    cache_enabled=True,
                    cache_dir=str(cache_dir),
                    min_cache_file_size=0,
                    max_entry_size=64,
                )
                metadata = aggregate.file_metadata[str(archive_path)]
                assert "tar_entry_extraction_incomplete" in metadata["scan_outcome_reasons"]
                assert core.determine_exit_code(aggregate) == 1
                assert any(issue.location == f"{archive_path}:payload.pkl" for issue in aggregate.issues)

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_oversized_hidden_payload_returns_inconclusive_without_detected_finding(self, tmp_path: Path) -> None:
        """A payload hidden above the extraction bound must not be reported as observed."""
        archive_path = tmp_path / "oversized_hidden_payload.tar"
        payload = b'cos\nsystem\n(S"echo pwned"\ntR.' + (b"A" * 128)

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("payload.txt")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        _assert_inconclusive_aggregate_not_reused(
            archive_path,
            "tar_entry_extraction_incomplete",
            tmp_path / "oversized-hidden-cache",
            max_entry_size=64,
        )

    def test_scan_respects_max_file_size_over_entry_limit(self, tmp_path: Path) -> None:
        """A stricter top-level size limit should still fail TAR extraction before scan_file runs."""
        scanner = TarScanner(config={"max_file_size": 64, "max_entry_size": 1024})
        archive_path = tmp_path / "precedence.tar"
        payload = b"C" * 128

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = scanner.scan(str(archive_path))

        assert result.success is False
        oversize_checks = [check for check in result.checks if check.name == "TAR Entry Scan"]
        assert len(oversize_checks) == 1
        assert oversize_checks[0].severity == IssueSeverity.INFO
        assert "tar entry payload.bin exceeds maximum size of 64 bytes" in oversize_checks[0].message.lower()

    def test_scan_continues_after_oversized_member_and_detects_later_payload(self, tmp_path: Path) -> None:
        """A single oversized member should fail that entry without hiding later malicious members."""
        scanner = TarScanner(config={"max_entry_size": 64})
        archive_path = tmp_path / "mixed.tar"
        payload = b'cos\nsystem\n(S"echo pwned"\ntR.'

        with tarfile.open(archive_path, "w") as archive:
            large_member = tarfile.TarInfo("huge.bin")
            large_data = b"A" * 128
            large_member.size = len(large_data)
            archive.addfile(large_member, tarfile.io.BytesIO(large_data))  # type: ignore[attr-defined]

            evil_member = tarfile.TarInfo("payload.txt")
            evil_member.size = len(payload)
            archive.addfile(evil_member, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = scanner.scan(str(archive_path))

        assert result.success is False
        assert any(
            check.name == "TAR Entry Scan"
            and check.status == CheckStatus.FAILED
            and check.details.get("entry") == "huge.bin"
            for check in result.checks
        )
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and issue.location == f"{archive_path}:payload.txt"
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system"))
            for issue in result.issues
        )
        aggregate = core.scan_model_directory_or_file(
            str(archive_path),
            cache_enabled=False,
            max_entry_size=64,
        )
        assert core.determine_exit_code(aggregate) == 1

    def test_nested_member_scan_exception_returns_inconclusive_exit_code(self, tmp_path: Path) -> None:
        """A member scanner failure is unavailable coverage, not an observed finding."""
        archive_path = tmp_path / "nested_scan_failure.tar"
        payload = b"ordinary member"
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("member.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        def nested_scan(_path: str, _config: dict[str, Any]) -> ScanResult:
            raise RuntimeError("nested scanner unavailable")

        scan_kwargs: dict[str, Any] = {NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan}
        direct = TarScanner(config=scan_kwargs).scan(str(archive_path))
        assert "tar_entry_scan_incomplete" in direct.metadata["scan_outcome_reasons"]
        entry_checks = [check for check in direct.issues if check.message.startswith("Error scanning TAR entry")]
        assert len(entry_checks) == 1
        assert entry_checks[0].severity == IssueSeverity.INFO
        _assert_inconclusive_aggregate_not_reused(
            archive_path,
            "tar_entry_scan_incomplete",
            tmp_path / "nested-failure-cache",
            **scan_kwargs,
        )

    def test_unexpected_tar_scan_failure_returns_inconclusive_exit_code_without_cache_reuse(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A TAR scan abort is unavailable coverage unless a concrete hazard was observed."""
        archive_path = tmp_path / "outer_scan_failure.tar"
        with tarfile.open(archive_path, "w") as archive:
            payload = b"ordinary member"
            info = tarfile.TarInfo("member.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        def fail_tar_scan(_self: TarScanner, _path: str, depth: int = 0) -> ScanResult:
            raise RuntimeError(f"unexpected TAR stream failure at depth {depth}")

        monkeypatch.setattr(TarScanner, "_scan_tar_file", fail_tar_scan)

        direct = TarScanner().scan(str(archive_path))
        scan_checks = [check for check in direct.issues if check.message.startswith("Error scanning tar file")]
        assert len(scan_checks) == 1
        assert scan_checks[0].severity == IssueSeverity.INFO
        assert "tar_scan_incomplete" in direct.metadata["scan_outcome_reasons"]
        _assert_inconclusive_aggregate_not_reused(
            archive_path,
            "tar_scan_incomplete",
            tmp_path / "outer-failure-cache",
        )

    def test_late_tar_traversal_failure_preserves_detected_security_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unavailable later traversal must not erase a finding already observed."""
        archive_path = tmp_path / "partial_traversal_after_finding.tar"
        malicious_payload = b'cos\nsystem\n(S"echo pwned"\ntR.'
        with tarfile.open(archive_path, "w") as archive:
            for name, payload in (("payload.txt", malicious_payload), ("later.txt", b"unreadable later member")):
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        monkeypatch.setattr(
            TarScanner,
            "can_handle",
            classmethod(lambda _cls, path: path == str(archive_path)),
        )
        monkeypatch.setattr(TarScanner, "_preflight_tar_archive", lambda _self, _path, _result: True)
        original_member_risk_scan = tar_scanner_module.scan_archive_member_for_known_risks
        original_next = tarfile.TarFile.next
        malicious_member_scanned = False

        def observe_member_risk_scan(**kwargs: Any) -> None:
            nonlocal malicious_member_scanned
            original_member_risk_scan(**kwargs)
            if kwargs["member_name"] == "payload.txt":
                malicious_member_scanned = True

        def fail_after_detected_member(archive: tarfile.TarFile) -> tarfile.TarInfo | None:
            if (
                malicious_member_scanned
                and archive.name is not None
                and Path(os.fsdecode(archive.name)) == archive_path
            ):
                raise OSError("later TAR traversal unavailable")
            return original_next(archive)

        monkeypatch.setattr(tar_scanner_module, "scan_archive_member_for_known_risks", observe_member_risk_scan)
        monkeypatch.setattr(tarfile.TarFile, "next", fail_after_detected_member)

        aggregate = core.scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert "tar_scan_incomplete" in aggregate.file_metadata[str(archive_path)]["scan_outcome_reasons"]
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and issue.location == f"{archive_path}:payload.txt"
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system"))
            for issue in aggregate.issues
        )
        assert core.determine_exit_code(aggregate) == 1

    def test_scan_skips_non_regular_tar_members(self, tmp_path: Path) -> None:
        """Non-file TAR members should be explicit incomplete coverage without hiding later files."""
        archive_path = tmp_path / "fifo-first.tar"
        payload = b"payload"

        with tarfile.open(archive_path, "w") as archive:
            fifo = tarfile.TarInfo("named_pipe")
            fifo.type = tarfile.FIFOTYPE
            archive.addfile(fifo)

            info = tarfile.TarInfo("data.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert result.bytes_scanned == len(payload)
        assert "tar_special_member_unsupported" in result.metadata["scan_outcome_reasons"]
        coverage_checks = [check for check in result.checks if check.name == "TAR Member Coverage"]
        assert len(coverage_checks) == 1
        assert coverage_checks[0].details["entry"] == "named_pipe"
        assert coverage_checks[0].details["member_type"] == "tar_fifo"
        assert any(entry["path"] == f"{archive_path}:data.bin" for entry in result.metadata["contents"])

    @pytest.mark.parametrize(
        ("member_type", "expected_kind"),
        [(tarfile.CHRTYPE, "tar_device"), (tarfile.BLKTYPE, "tar_device")],
    )
    def test_scan_reports_device_tar_members_incomplete(
        self, tmp_path: Path, member_type: bytes, expected_kind: str
    ) -> None:
        """Device entries are not extracted and remain explicit incomplete coverage."""
        archive_path = tmp_path / "device.tar"
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("dev/null")
            info.type = member_type
            archive.addfile(info)

        result = self.scanner.scan(str(archive_path))

        coverage_checks = [check for check in result.checks if check.name == "TAR Member Coverage"]
        assert result.success is False
        assert len(coverage_checks) == 1
        assert coverage_checks[0].details["member_type"] == expected_kind
        assert "tar_special_member_unsupported" in result.metadata["scan_outcome_reasons"]

    def test_scan_reports_sparse_tar_members_incomplete(self, tmp_path: Path) -> None:
        """Sparse TAR members are skipped explicitly rather than expanded or trusted."""
        archive_path = tmp_path / "sparse.tar"
        sparse_size = 1024 * 1024 * 1024 * 2
        with tarfile.open(archive_path, "w", format=tarfile.PAX_FORMAT) as archive:
            info = tarfile.TarInfo("sparse.bin")
            info.size = 0
            info.pax_headers = {"GNU.sparse.size": str(sparse_size)}
            archive.addfile(info, tarfile.io.BytesIO(b""))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        coverage_checks = [check for check in result.checks if check.name == "TAR Member Coverage"]
        assert result.success is False
        assert len(coverage_checks) == 1
        assert coverage_checks[0].details["member_type"] == "tar_sparse"
        assert "tar_sparse_member_unsupported" in result.metadata["scan_outcome_reasons"]
        assert result.metadata["contents"] == [
            {
                "path": f"{archive_path}:sparse.bin",
                "type": "tar_sparse",
                "size": sparse_size,
                "scan_status": "incomplete",
                "scan_outcome_reason": "tar_sparse_member_unsupported",
            }
        ]

    def test_scan_empty_tar(self, tmp_path: Path) -> None:
        """An empty TAR archive should scan successfully with no critical issues."""
        archive_path = tmp_path / "empty.tar"
        with tarfile.open(archive_path, "w"):
            pass  # create empty archive

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert result.bytes_scanned == 0
        # No CRITICAL issues expected for an empty archive
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 0

    def test_scan_tar_with_multiple_model_formats(self, tmp_path: Path) -> None:
        """TAR containing multiple model-format files should scan all of them."""
        import pickle

        archive_path = tmp_path / "multi_format.tar"

        pkl_data = pickle.dumps({"weights": [1, 2, 3]})
        json_data = b'{"model_type": "linear", "version": "1.0"}'
        pt_data = pickle.dumps({"state_dict": {}})  # .pt files are pickle-based

        with tarfile.open(archive_path, "w") as t:
            for name, data in [
                ("model.pkl", pkl_data),
                ("config.json", json_data),
                ("weights.pt", pt_data),
            ]:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                t.addfile(info, tarfile.io.BytesIO(data))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        # All three files were scanned
        assert result.bytes_scanned == len(pkl_data) + len(json_data) + len(pt_data)
        # Each file should appear in the contents metadata
        contents_paths = {c.get("path", "") for c in result.metadata.get("contents", [])}
        assert any("model.pkl" in p for p in contents_paths)
        assert any("config.json" in p for p in contents_paths)
        assert any("weights.pt" in p for p in contents_paths)

    def test_scan_tar_with_very_long_filename(self, tmp_path: Path) -> None:
        """TAR members with very long filenames should be handled without crashing."""
        archive_path = tmp_path / "long_name.tar"
        long_name = "a" * 200 + ".pkl"  # 204-character filename
        import pickle

        payload = pickle.dumps({"key": "value"})

        with tarfile.open(archive_path, "w") as t:
            info = tarfile.TarInfo(long_name)
            info.size = len(payload)
            t.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        # Scan must not crash; success is expected for a benign payload
        assert result.success is True
        assert result.bytes_scanned == len(payload)

    def test_scan_truncated_tar(self, tmp_path: Path) -> None:
        """A truncated (corrupted) TAR file should fail gracefully."""
        # Build a real archive, then truncate it
        archive_path = tmp_path / "truncated.tar"
        content = b"some content"

        with tarfile.open(archive_path, "w") as t:
            info = tarfile.TarInfo("file.txt")
            info.size = len(content)
            t.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]

        full_data = archive_path.read_bytes()
        truncated_path = tmp_path / "truncated_cut.tar"
        truncated_path.write_bytes(full_data[:520])

        result = self.scanner.scan(str(truncated_path))

        assert result.success is False
        format_checks = [check for check in result.checks if check.name == "TAR File Format Validation"]
        assert len(format_checks) == 1
        assert "not a valid tar file" in format_checks[0].message.lower()
        assert any("not a valid tar file" in issue.message.lower() for issue in result.issues)

    @pytest.mark.parametrize(
        ("suffix", "mode"),
        [
            (".tar.gz", "w:gz"),
            (".tar.bz2", "w:bz2"),
            (".tar.xz", "w:xz"),
        ],
    )
    def test_scan_compressed_tar_enforces_decompression_ratio_limit(
        self, tmp_path: Path, suffix: str, mode: Literal["w:gz", "w:bz2", "w:xz"]
    ) -> None:
        """Compressed TAR wrappers should enforce decompression ratio limits across supported codecs."""
        archive_path = tmp_path / f"ratio_limit{suffix}"
        payload = b"A" * 1_000_000

        with tarfile.open(archive_path, mode) as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        scanner = TarScanner(config={"compressed_max_decompression_ratio": 2.0})
        result = scanner.scan(str(archive_path))

        assert result.success is False
        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert "decompression ratio exceeded" in limit_checks[0].message.lower()

    @pytest.mark.parametrize(
        ("suffix", "mode"),
        [
            (".tar.gz", "w:gz"),
            (".tar.bz2", "w:bz2"),
            (".tar.xz", "w:xz"),
        ],
    )
    def test_scan_compressed_tar_enforces_decompressed_size_limit(
        self, tmp_path: Path, suffix: str, mode: Literal["w:gz", "w:bz2", "w:xz"]
    ) -> None:
        """Compressed TAR wrappers should enforce size limits across supported codecs."""
        archive_path = tmp_path / f"size_limit{suffix}"
        payload = b"B" * 10_000

        with tarfile.open(archive_path, mode) as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        scanner = TarScanner(config={"compressed_max_decompressed_bytes": 1024})
        result = scanner.scan(str(archive_path))

        assert result.success is False
        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert "decompressed size exceeded" in limit_checks[0].message.lower()

    @pytest.mark.parametrize(
        ("suffix", "mode"),
        [
            (".tar.gz", "w:gz"),
            (".tar.bz2", "w:bz2"),
            (".tar.xz", "w:xz"),
        ],
    )
    def test_scan_compressed_tar_within_limits_passes_decompression_checks(
        self, tmp_path: Path, suffix: str, mode: Literal["w:gz", "w:bz2", "w:xz"]
    ) -> None:
        """Compressed TAR wrappers within safe bounds should produce a passing decompression check."""
        archive_path = tmp_path / f"within_limit{suffix}"
        payload = b"safe-payload"

        with tarfile.open(archive_path, mode) as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        scanner = TarScanner(
            config={
                "compressed_max_decompression_ratio": 1_000.0,
                "compressed_max_decompressed_bytes": 20_000,
            }
        )
        result = scanner.scan(str(archive_path))

        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.PASSED

    def test_scan_compressed_tar_accounts_for_tar_record_padding(self, tmp_path: Path) -> None:
        """Wrapper limits should account for TAR record padding, even on tiny archives."""
        archive_path = tmp_path / "tiny.tar.gz"

        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("payload.bin")
            payload = b"tiny"
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        scanner = TarScanner(config={"compressed_max_decompressed_bytes": 4_096})
        result = scanner.scan(str(archive_path))

        assert result.success is False
        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert "decompressed size exceeded" in limit_checks[0].message.lower()

    def test_scan_tar_preflight_streams_members_without_getmembers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Preflight should stream TAR members instead of materializing them with getmembers()."""
        archive_path = tmp_path / "streamed.tar.gz"

        with tarfile.open(archive_path, "w:gz") as archive:
            for index in range(3):
                info = tarfile.TarInfo(f"payload-{index}.bin")
                payload = f"payload-{index}".encode()
                info.size = len(payload)
                archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        def fail_getmembers(self: tarfile.TarFile) -> list[tarfile.TarInfo]:
            raise AssertionError("TarScanner should not call getmembers() during preflight")

        monkeypatch.setattr(tarfile.TarFile, "getmembers", fail_getmembers)

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        entry_checks = [check for check in result.checks if check.name == "Entry Count Limit Check"]
        assert len(entry_checks) == 1
        assert entry_checks[0].status == CheckStatus.PASSED

    def test_max_entries_limit_marks_inconclusive_metadata(self, tmp_path: Path) -> None:
        """Entry-count truncation should make TAR coverage explicit in metadata."""
        archive_path = tmp_path / "too_many_entries.tar"
        with tarfile.open(archive_path, "w") as archive:
            for index in range(2):
                payload = f"payload-{index}".encode()
                info = tarfile.TarInfo(f"payload-{index}.bin")
                info.size = len(payload)
                archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = TarScanner(config={"max_tar_entries": 1}).scan(str(archive_path))

        assert result.success is False
        entry_checks = [check for check in result.checks if check.name == "Entry Count Limit Check"]
        assert len(entry_checks) == 1
        assert entry_checks[0].status == CheckStatus.FAILED
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert result.metadata["analysis_incomplete"] is True
        assert "tar_analysis_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_core_tar_partial_nested_scan_without_findings_returns_exit_code_2(self, tmp_path: Path) -> None:
        """A failed nested TAR member scan with no finding should stay inconclusive in aggregate output."""
        archive_path = tmp_path / "nested_failure.tar"
        with tarfile.open(archive_path, "w") as archive:
            payload = b"payload"
            info = tarfile.TarInfo("member.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

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

    def test_tar_nested_critical_finding_does_not_mark_archive_incomplete(self, tmp_path: Path) -> None:
        """Real nested findings should fail the archive without claiming partial traversal."""
        archive_path = tmp_path / "nested_critical.tar"
        with tarfile.open(archive_path, "w") as archive:
            payload = b"payload"
            info = tarfile.TarInfo("model.pkl")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

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

        result = TarScanner(config={NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan}).scan(str(archive_path))

        assert result.success is False
        assert result.has_errors is True
        assert "scan_outcome" not in result.metadata
        assert result.metadata.get("analysis_incomplete") is not True
        assert any(check.name == "Nested Critical Finding" for check in result.checks)

    def test_scan_compressed_tar_detects_wrapper_by_content_not_suffix(self, tmp_path: Path) -> None:
        """Compressed TARs with plain .tar suffix should still enforce wrapper limits by magic bytes."""
        archive_path = tmp_path / "disguised_compressed.tar"
        payload = b"C" * 1_000_000

        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        scanner = TarScanner(config={"compressed_max_decompression_ratio": 2.0})
        result = scanner.scan(str(archive_path))

        assert result.success is False
        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert "decompression ratio exceeded" in limit_checks[0].message.lower()

    def test_core_routes_disguised_compressed_tar_without_tar_suffix(self, tmp_path: Path) -> None:
        """Compressed TAR wrappers renamed to generic suffixes should still route to TarScanner."""
        archive_path = tmp_path / "disguised_payload.bin"
        payload = b"D" * 1_000_000

        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = core.scan_file(
            str(archive_path),
            config={"compressed_max_decompression_ratio": 2.0},
        )

        assert result.success is False
        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert result.scanner_name == "tar"
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert "decompression ratio exceeded" in limit_checks[0].message.lower()
