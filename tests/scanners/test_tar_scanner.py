import gzip
import io
import lzma
import os
import pickle
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, BinaryIO, Literal, cast

import pytest

from modelaudit import core
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.config import ModelAuditConfig, reset_config, set_config
from modelaudit.rules import Severity
from modelaudit.scanners import tar_scanner as tar_scanner_module
from modelaudit.scanners.archive_dispatch import NESTED_SCAN_CALLBACK_CONFIG_KEY
from modelaudit.scanners.base import (
    DEFAULT_MAX_FILE_READ_SIZE,
    INCONCLUSIVE_SCAN_OUTCOME,
    CheckStatus,
    IssueSeverity,
    ScanResult,
)
from modelaudit.scanners.tar_scanner import (
    ARCHIVE_MEMBER_COPY_CHUNK_BYTES,
    DEFAULT_MAX_DECOMPRESSED_BYTES,
    DEFAULT_MAX_DECOMPRESSION_RATIO,
    DEFAULT_MAX_TAR_ENTRY_SIZE,
    TarScanner,
)
from modelaudit.utils.file import detection as file_detection


def _tar_octal_field(value: int, width: int) -> bytes:
    return f"{value:0{width - 1}o}\0".encode()


def _with_tar_checksum(header: bytearray) -> bytes:
    header[148:156] = b"        "
    header[148:156] = f"{sum(header):06o}\0 ".encode()
    return bytes(header)


def _old_gnu_sparse_tar_bytes(*, extension_blocks: int, physical_size: int = 0) -> bytes:
    info = tarfile.TarInfo("sparse.bin")
    info.type = tarfile.GNUTYPE_SPARSE
    info.size = physical_size
    header = bytearray(info.tobuf(format=tarfile.GNU_FORMAT))
    header[482] = int(extension_blocks > 0)
    header[483:495] = _tar_octal_field(max(physical_size, 1), 12)
    extensions: list[bytes] = []
    for index in range(extension_blocks):
        block = bytearray(tarfile.BLOCKSIZE)
        block[:12] = _tar_octal_field(index + 1, 12)
        block[12:24] = _tar_octal_field(1, 12)
        block[504] = int(index + 1 < extension_blocks)
        extensions.append(bytes(block))
    return _with_tar_checksum(header) + b"".join(extensions) + (b"\0" * physical_size) + (b"\0" * 1024)


def _write_sparse_raw_tar(
    path: Path,
    *,
    member_name: str,
    member_payload: bytes,
    late_invalid_header: bool,
) -> None:
    """Write a >512 MiB sparse raw TAR with an optional malformed late header."""

    def write_member(name: str, payload: bytes) -> None:
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        archive.write(info.tobuf())
        archive.write(payload)
        archive.write(b"\0" * (-len(payload) % tarfile.BLOCKSIZE))

    with path.open("wb") as archive:
        write_member(member_name, member_payload)
        if late_invalid_header:
            archive.write(b"A" * tarfile.BLOCKSIZE)
        archive.write(b"\0" * (2 * tarfile.BLOCKSIZE))
        archive.seek(DEFAULT_MAX_FILE_READ_SIZE)
        archive.write(b"\0")


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

    def test_can_handle_compressed_tar_files(self, tmp_path: Path) -> None:
        """Test that the scanner correctly identifies compressed TAR files."""
        tmp_path_gz = tmp_path / "fixture.tar.gz"
        with tarfile.open(tmp_path_gz, "w:gz") as t:
            info = tarfile.TarInfo("test.txt")
            content = b"Hello World"
            info.size = len(content)
            t.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]

        tmp_path_bz2 = tmp_path / "fixture.tar.bz2"
        with tarfile.open(tmp_path_bz2, "w:bz2") as t:
            info = tarfile.TarInfo("test.txt")
            content = b"Hello World"
            info.size = len(content)
            t.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]

        tmp_path_gzip_pickle = tmp_path / "pickle.tar.gz"
        tmp_path_gzip_pickle.write_bytes(gzip.compress(pickle.dumps({"weights": [1, 2, 3]})))

        assert TarScanner.can_handle(str(tmp_path_gz)) is True
        assert TarScanner.can_handle(str(tmp_path_bz2)) is True
        assert TarScanner.can_handle(str(tmp_path_gzip_pickle)) is False

    def test_can_handle_corrupt_gzip_returns_false(self, tmp_path: Path) -> None:
        path = tmp_path / "corrupt.tar.gz"
        path.write_bytes(b"\x1f\x8b\x08\x00corrupt-deflate")

        assert TarScanner.can_handle(str(path)) is False

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
        assert result.metadata["contents"] == [
            {
                "path": f"{archive_path}:link.txt",
                "type": "tar_symlink",
                "size": 0,
                "scan_status": "rejected",
            }
        ]

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
        assert any(
            entry["path"] == f"{archive_path}:nested/link.bin" and entry["scan_status"] == "link_validated"
            for entry in result.metadata["contents"]
        )

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
        assert result.metadata["contents"] == [
            {
                "path": f"{archive_path}:nested/link.txt",
                "type": "tar_symlink" if link_type == tarfile.SYMTYPE else "tar_hardlink",
                "size": 0,
                "scan_status": "rejected",
            }
        ]

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

    def test_scan_large_valid_tar_bypasses_generic_max_file_read_size(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """TAR-owned streaming should not inherit the generic whole-file read rejection."""
        archive_path = tmp_path / "large_by_padding.tar"
        payload = b"safe metadata"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("metadata.txt")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        assert archive_path.stat().st_size > 1024

        scanner = TarScanner(config={"max_file_read_size": 1024, "max_entry_size": 4096})

        def fail_hashes(_path: str) -> dict[str, str]:
            pytest.fail("streaming TAR scan should not hash archives above the read cap")

        monkeypatch.setattr(scanner, "calculate_file_hashes", fail_hashes)

        result = scanner.scan(str(archive_path))

        assert result.success is True
        assert result.scanner_name == "tar"
        assert "max_file_read_size_exceeded" not in result.metadata.get("scan_outcome_reasons", [])
        integrity_checks = [check for check in result.checks if check.name == "File Integrity Hash"]
        assert len(integrity_checks) == 1
        assert integrity_checks[0].status == CheckStatus.SKIPPED
        assert integrity_checks[0].details["skip_reason"] == "tar_file_integrity_hash_skipped"
        assert integrity_checks[0].details.get("analysis_incomplete") is not True
        assert result.metadata["file_hashes_skipped"] is True
        assert "file_hashes" not in result.metadata
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
        integrity_checks = [check for check in result.checks if check.name == "File Integrity Hash"]
        assert len(integrity_checks) == 1
        assert integrity_checks[0].status == CheckStatus.SKIPPED

    def test_rejected_regular_tar_member_counts_against_total_budget(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "rejected_budget.tar.gz"
        payload = b"A" * 128
        later_payload = b"later"

        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("../huge.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

            later_info = tarfile.TarInfo("later.txt")
            later_info.size = len(later_payload)
            archive.addfile(later_info, tarfile.io.BytesIO(later_payload))  # type: ignore[attr-defined]

        result = TarScanner(
            config={
                "max_tar_total_uncompressed_size": 64,
                "compressed_max_decompression_ratio": 10_000.0,
            }
        ).scan(str(archive_path))

        traversal_checks = [check for check in result.checks if check.name == "Path Traversal Protection"]
        aggregate_checks = [check for check in result.checks if check.name == "TAR Aggregate Size Limit Check"]
        assert result.success is False
        assert len(traversal_checks) == 1
        assert len(aggregate_checks) == 1
        assert aggregate_checks[0].status == CheckStatus.FAILED
        assert aggregate_checks[0].details["entry"] == "../huge.bin"
        assert "tar_total_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert any(
            entry["path"].endswith("../huge.bin") and entry["scan_status"] == "rejected"
            for entry in result.metadata["contents"]
        )
        assert not any(entry["path"].endswith("later.txt") for entry in result.metadata["contents"])

    def test_rejected_special_tar_member_counts_against_total_budget(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "rejected_special_budget.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("../unknown-special")
            info.type = b"Z"
            info.size = 128
            archive.addfile(info, tarfile.io.BytesIO(b"A" * info.size))  # type: ignore[attr-defined]
            later = tarfile.TarInfo("later.txt")
            later.size = 5
            archive.addfile(later, tarfile.io.BytesIO(b"later"))  # type: ignore[attr-defined]

        result = TarScanner(
            config={
                "max_tar_total_uncompressed_size": 64,
                "compressed_max_decompression_ratio": 10_000.0,
            }
        ).scan(str(archive_path))

        aggregate_checks = [check for check in result.checks if check.name == "TAR Aggregate Size Limit Check"]
        assert result.success is False
        assert any(check.status == CheckStatus.FAILED for check in aggregate_checks)
        assert not any(check.status == CheckStatus.PASSED for check in aggregate_checks)
        assert result.metadata["archive_uncompressed_size"] >= 128
        assert not any(entry["path"].endswith("later.txt") for entry in result.metadata["contents"])

    @pytest.mark.parametrize("member_type", [tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE])
    def test_body_carrying_metadata_member_fails_closed(
        self,
        tmp_path: Path,
        member_type: bytes,
    ) -> None:
        archive_path = tmp_path / f"body-metadata-{member_type.hex()}.tar"
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("metadata-entry")
            info.type = member_type
            info.linkname = "safe-target" if member_type in {tarfile.SYMTYPE, tarfile.LNKTYPE} else ""
            info.size = 128
            archive.addfile(info)

        result = TarScanner(config={"max_tar_total_uncompressed_size": 64}).scan(str(archive_path))

        assert result.success is False
        assert "tar_special_member_unsupported" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "TAR Member Coverage"
            and check.status == CheckStatus.FAILED
            and check.details["entry"] == "metadata-entry"
            for check in result.checks
        )
        assert not any(
            check.name == "TAR Aggregate Size Limit Check" and check.status == CheckStatus.PASSED
            for check in result.checks
        )

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

    def test_core_routes_compound_tar_gz_to_tar_scanner(self, tmp_path: Path) -> None:
        """Core routing should hand compound TAR wrappers to TAR scanner semantics."""
        archive_path = tmp_path / "compound.tar.gz"
        payload = b"safe"

        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("metadata.txt")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = core.scan_file(
            str(archive_path),
            config={
                "cache_enabled": False,
                "compressed_max_decompressed_bytes": 64 * 1024,
                "compressed_max_decompression_ratio": 10_000.0,
            },
        )

        assert result.scanner_name == "tar"
        assert result.success is True
        assert "max_file_read_size_exceeded" not in result.metadata.get("scan_outcome_reasons", [])

    def test_compressed_tar_truncated_nemo_route_scans_reachable_root_config(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_NEMO_ROUTE_MAX_BODY_SKIP_BYTES", 64)
        archive_path = tmp_path / "large-archive.tar.gz"

        with tarfile.open(archive_path, "w:gz") as archive:
            first_payload = b"x" * 128
            first_info = tarfile.TarInfo("large-weights.bin")
            first_info.size = len(first_payload)
            archive.addfile(first_info, tarfile.io.BytesIO(first_payload))  # type: ignore[attr-defined]

            config_payload = b"model:\n  _target_: os.system\n"
            config_info = tarfile.TarInfo("model_config.yaml")
            config_info.size = len(config_payload)
            archive.addfile(config_info, tarfile.io.BytesIO(config_payload))  # type: ignore[attr-defined]

        result = core.scan_file(str(archive_path), config={"cache_enabled": False})

        assert result.scanner_name == "tar"
        assert result.success is False
        assert any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)

    def test_compressed_tar_raw_suffix_truncated_nemo_route_scans_reachable_root_config(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_NEMO_ROUTE_MAX_BODY_SKIP_BYTES", 64)
        archive_path = tmp_path / "large-archive.tar"

        with tarfile.open(archive_path, "w:gz") as archive:
            first_payload = b"x" * 128
            first_info = tarfile.TarInfo("large-weights.bin")
            first_info.size = len(first_payload)
            archive.addfile(first_info, tarfile.io.BytesIO(first_payload))  # type: ignore[attr-defined]

            config_payload = b"model:\n  _target_: os.system\n"
            config_info = tarfile.TarInfo("model_config.yaml")
            config_info.size = len(config_payload)
            archive.addfile(config_info, tarfile.io.BytesIO(config_payload))  # type: ignore[attr-defined]

        result = core.scan_file(str(archive_path), config={"cache_enabled": False})

        assert result.scanner_name == "tar"
        assert result.success is False
        assert any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)

    def test_compressed_tar_truncated_nemo_route_allows_benign_root_config(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_NEMO_ROUTE_MAX_BODY_SKIP_BYTES", 64)
        archive_path = tmp_path / "safe-archive.tar.gz"

        with tarfile.open(archive_path, "w:gz") as archive:
            first_payload = b"x" * 128
            first_info = tarfile.TarInfo("large-weights.bin")
            first_info.size = len(first_payload)
            archive.addfile(first_info, tarfile.io.BytesIO(first_payload))  # type: ignore[attr-defined]

            config_payload = b"model:\n  _target_: torch.nn.Linear\n"
            config_info = tarfile.TarInfo("model_config.yaml")
            config_info.size = len(config_payload)
            archive.addfile(config_info, tarfile.io.BytesIO(config_payload))  # type: ignore[attr-defined]

        result = core.scan_file(str(archive_path), config={"cache_enabled": False})

        assert result.scanner_name == "tar"
        assert result.success is True
        assert any(
            check.name == "Hydra _target_ Safety Check" and check.status == CheckStatus.PASSED
            for check in result.checks
        )
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

    def test_compressed_tar_truncated_nemo_route_fails_closed_on_linked_root_config(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_NEMO_ROUTE_MAX_BODY_SKIP_BYTES", 64)
        archive_path = tmp_path / "linked-config.tar.gz"

        with tarfile.open(archive_path, "w:gz") as archive:
            first_payload = b"x" * 128
            first_info = tarfile.TarInfo("large-weights.bin")
            first_info.size = len(first_payload)
            archive.addfile(first_info, tarfile.io.BytesIO(first_payload))  # type: ignore[attr-defined]

            link_info = tarfile.TarInfo("model_config.yaml")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "payload.yaml"
            archive.addfile(link_info)

            config_payload = b"model:\n  _target_: os.system\n"
            payload_info = tarfile.TarInfo("payload.yaml")
            payload_info.size = len(config_payload)
            archive.addfile(payload_info, tarfile.io.BytesIO(config_payload))  # type: ignore[attr-defined]

        result = core.scan_file(str(archive_path), config={"cache_enabled": False})

        assert result.scanner_name == "tar"
        assert result.success is False
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "NeMo Link Semantics"
            and check.status == CheckStatus.FAILED
            and check.details["scan_outcome_reason"] == "nemo_link_semantics_incomplete"
            for check in result.checks
        )

    def test_compound_tar_gz_total_budget_stops_before_member_body_reads(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Aggregate TAR budget should stop extraction without decompressing oversized member bodies."""
        archive_path = tmp_path / "bounded-body.tar.gz"
        payload = b"\0" * (32 * 1024 * 1024)
        gzip_read_bytes = 0
        original_read = gzip.GzipFile.read

        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("huge.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        def tracked_read(self: gzip.GzipFile, size: int = -1) -> bytes:
            nonlocal gzip_read_bytes
            data = original_read(self, size)
            gzip_read_bytes += len(data)
            return data

        monkeypatch.setattr(gzip.GzipFile, "read", tracked_read)

        result = core.scan_file(
            str(archive_path),
            config={
                "cache_enabled": False,
                "max_total_size": 64 * 1024,
                "max_entry_size": 64 * 1024 * 1024,
                "compressed_max_decompressed_bytes": 64 * 1024,
                "compressed_max_decompression_ratio": 10_000.0,
            },
        )

        aggregate_checks = [check for check in result.checks if check.name == "TAR Aggregate Size Limit Check"]
        assert result.success is False
        assert gzip_read_bytes <= 64 * 1024
        assert any(check.status == CheckStatus.FAILED for check in aggregate_checks)
        assert "tar_total_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert "max_file_read_size_exceeded" not in result.metadata["scan_outcome_reasons"]

    def test_gzip_tar_oversized_pax_header_is_bounded_before_materialization(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Large extension headers should fail closed before tarfile allocates their content."""
        archive_path = tmp_path / "oversized-pax.tar.gz"
        long_name = "pax-" + ("a" * (8 * 1024 * 1024))
        gzip_read_bytes = 0
        original_read = gzip.GzipFile.read

        with tarfile.open(archive_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            info = tarfile.TarInfo(long_name)
            info.size = 0
            archive.addfile(info, tarfile.io.BytesIO(b""))  # type: ignore[attr-defined]

        def tracked_read(self: gzip.GzipFile, size: int = -1) -> bytes:
            nonlocal gzip_read_bytes
            data = original_read(self, size)
            gzip_read_bytes += len(data)
            return data

        monkeypatch.setattr(gzip.GzipFile, "read", tracked_read)

        result = TarScanner(
            config={
                "max_total_size": 64 * 1024,
                "max_tar_metadata_bytes": 64 * 1024,
                "compressed_max_decompressed_bytes": 64 * 1024,
                "compressed_max_decompression_ratio": 10_000.0,
            }
        ).scan(str(archive_path))

        stream_checks = [check for check in result.checks if check.name == "TAR Stream Budget"]
        assert result.success is False
        assert gzip_read_bytes <= 64 * 1024
        assert len(stream_checks) == 1
        assert stream_checks[0].status == CheckStatus.FAILED
        assert stream_checks[0].details["scan_outcome_reason"] == "tar_metadata_read_limit_exceeded"
        assert "tar_metadata_read_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_max_total_size_stops_before_extracting_later_members(self, tmp_path: Path) -> None:
        """The aggregate TAR budget should be enforced before dispatching the next member."""
        archive_path = tmp_path / "aggregate-budget.tar"
        payload = b"A" * (32 * 1024)
        malicious_payload = b'cos\nsystem\n(S"echo pwned"\ntR.' + (b"B" * (32 * 1024))
        dispatched_paths: list[Path] = []

        with tarfile.open(archive_path, "w") as archive:
            for index in range(2):
                info = tarfile.TarInfo(f"benign-{index}.bin")
                info.size = len(payload)
                archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

            info = tarfile.TarInfo("over-budget-payload.pkl")
            info.size = len(malicious_payload)
            archive.addfile(info, tarfile.io.BytesIO(malicious_payload))  # type: ignore[attr-defined]

        def nested_scan(path: str, _config: dict[str, Any]) -> ScanResult:
            dispatched_paths.append(Path(path))
            nested_result = ScanResult(scanner_name="unknown")
            nested_result.finish(success=True)
            return nested_result

        result = TarScanner(
            config={
                NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan,
                "max_total_size": len(payload) * 2,
                "max_entry_size": len(malicious_payload),
            }
        ).scan(str(archive_path))

        assert result.success is False
        assert len(dispatched_paths) == 2
        assert "tar_total_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "TAR Aggregate Size Limit Check"
            and check.status == CheckStatus.FAILED
            and check.details.get("entry") == "over-budget-payload.pkl"
            for check in result.checks
        )
        assert not any(
            issue.severity == IssueSeverity.CRITICAL and issue.location == f"{archive_path}:over-budget-payload.pkl"
            for issue in result.issues
        )
        assert any(
            entry["path"] == f"{archive_path}:over-budget-payload.pkl"
            and entry["scan_status"] == "incomplete"
            and entry["scan_outcome_reason"] == "tar_total_size_limit_exceeded"
            for entry in result.metadata["contents"]
        )

    def test_nested_tar_shares_total_budget_with_parent(self, tmp_path: Path) -> None:
        """Nested TAR dispatch must consume the same aggregate member budget as its parent."""
        inner_path = tmp_path / "inner.tar"
        outer_path = tmp_path / "outer.tar"
        payload = b"C" * (32 * 1024)

        with tarfile.open(inner_path, "w") as archive:
            for index in range(2):
                info = tarfile.TarInfo(f"inner-{index}.bin")
                info.size = len(payload)
                archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        inner_bytes = inner_path.read_bytes()
        with tarfile.open(outer_path, "w") as archive:
            info = tarfile.TarInfo("inner.tar")
            info.size = len(inner_bytes)
            archive.addfile(info, tarfile.io.BytesIO(inner_bytes))  # type: ignore[attr-defined]

        result = TarScanner(
            config={
                "max_total_size": len(inner_bytes) + len(payload),
                "max_entry_size": len(inner_bytes),
            }
        ).scan(str(outer_path))

        aggregate_checks = [
            check
            for check in result.checks
            if check.name == "TAR Aggregate Size Limit Check" and check.status == CheckStatus.FAILED
        ]
        assert result.success is False
        assert len(aggregate_checks) == 1
        assert aggregate_checks[0].location == f"{outer_path}:inner.tar:inner-1.bin"
        assert "tar_total_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]

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

        for nonfinite_ratio in (float("inf"), float("-inf"), float("nan")):
            assert (
                TarScanner(config={"compressed_max_decompression_ratio": nonfinite_ratio}).max_decompression_ratio
                == DEFAULT_MAX_DECOMPRESSION_RATIO
            )
            assert (
                file_detection._normalize_positive_float(nonfinite_ratio, DEFAULT_MAX_DECOMPRESSION_RATIO)
                == DEFAULT_MAX_DECOMPRESSION_RATIO
            )

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

    def test_scan_continues_after_oversized_uncompressed_tar_member_without_streaming_body(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scanner = TarScanner(config={"max_entry_size": 64})
        archive_path = tmp_path / "oversized_first.tar"
        payload = b"B" * 4096
        later_payload = b"later"

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

            later_info = tarfile.TarInfo("later.txt")
            later_info.size = len(later_payload)
            archive.addfile(later_info, tarfile.io.BytesIO(later_payload))  # type: ignore[attr-defined]

        with tarfile.open(archive_path, "r:") as archive:
            first_member = archive.getmember("payload.bin")
            payload_start = first_member.offset_data
            payload_end = payload_start + first_member.size

        payload_bytes_read = 0
        original_open = open

        class TrackingFile:
            def __init__(self, fileobj: Any) -> None:
                self._fileobj = fileobj

            def read(self, size: int = -1) -> bytes:
                nonlocal payload_bytes_read
                start = self._fileobj.tell()
                data = cast(bytes, self._fileobj.read(size))
                end = start + len(data)
                payload_bytes_read += max(0, min(end, payload_end) - max(start, payload_start))
                return data

            def __getattr__(self, name: str) -> Any:
                return getattr(self._fileobj, name)

            def __enter__(self) -> "TrackingFile":
                return self

            def __exit__(self, *args: Any) -> None:
                self._fileobj.close()

        def tracked_open(path: str, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            fileobj = original_open(path, mode, *args, **kwargs)
            return TrackingFile(fileobj) if os.fspath(path) == os.fspath(archive_path) and mode == "rb" else fileobj

        monkeypatch.setattr(tar_scanner_module, "open", tracked_open, raising=False)

        result = scanner._scan_tar_file(str(archive_path))

        assert result.success is False
        assert "tar_entry_extraction_incomplete" in result.metadata["scan_outcome_reasons"]
        contents = result.metadata["contents"]
        assert any(entry["path"].endswith("payload.bin") for entry in contents)
        assert any(entry["path"].endswith("later.txt") for entry in contents)
        assert payload_bytes_read < tarfile.BLOCKSIZE

    def test_scan_compressed_tar_stops_after_oversized_member_without_streaming_body(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scanner = TarScanner(config={"max_entry_size": 64})
        archive_path = tmp_path / "oversized_first.tar.gz"
        payload = b"B" * 4096
        malicious_payload = b'cos\nsystem\n(S"echo pwned"\ntR.'

        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

            later_info = tarfile.TarInfo("payload.txt")
            later_info.size = len(malicious_payload)
            archive.addfile(later_info, tarfile.io.BytesIO(malicious_payload))  # type: ignore[attr-defined]

        bytes_read = 0
        original_read = tar_scanner_module._TarBoundedStream.read

        def tracked_read(self: Any, size: int = -1) -> bytes:
            nonlocal bytes_read
            data = original_read(self, size)
            bytes_read += len(data)
            return data

        monkeypatch.setattr(tar_scanner_module._TarBoundedStream, "read", tracked_read)

        result = scanner._scan_tar_file(str(archive_path))

        assert result.success is False
        assert "tar_entry_extraction_incomplete" in result.metadata["scan_outcome_reasons"]
        contents = result.metadata["contents"]
        assert any(entry["path"].endswith("payload.bin") for entry in contents)
        assert not any(entry["path"].endswith("payload.txt") for entry in contents)
        assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert bytes_read < len(payload)
        aggregate_checks = [check for check in result.checks if check.name == "TAR Aggregate Size Limit Check"]
        assert not any(check.status == CheckStatus.PASSED for check in aggregate_checks)

    def test_tiny_total_budget_allows_tar_header_reads_for_empty_member(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "tiny_total_empty.tar"
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("empty.txt")
            info.size = 0
            archive.addfile(info, tarfile.io.BytesIO(b""))  # type: ignore[attr-defined]

        result = TarScanner(config={"max_tar_total_uncompressed_size": 1}).scan(str(archive_path))

        reasons = result.metadata.get("scan_outcome_reasons", [])
        assert "tar_metadata_read_limit_exceeded" not in reasons
        assert "tar_stream_budget_exceeded" not in reasons
        assert any(entry["path"].endswith("empty.txt") for entry in result.metadata["contents"])

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

    def test_scan_continues_after_oversized_seekable_member_and_detects_later_payload(
        self,
        tmp_path: Path,
    ) -> None:
        """Oversized seekable raw members are incomplete but do not hide later payloads."""
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
        assert "tar_entry_extraction_incomplete" in result.metadata["scan_outcome_reasons"]
        assert any(entry["path"].endswith("payload.txt") for entry in result.metadata["contents"])
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
        original_member_risk_scan = tar_scanner_module.scan_archive_member_for_known_risks
        original_next = tarfile.TarFile.next
        malicious_member_scanned = False

        def observe_member_risk_scan(**kwargs: Any) -> None:
            nonlocal malicious_member_scanned
            original_member_risk_scan(**kwargs)
            if kwargs["member_name"] == "payload.txt":
                malicious_member_scanned = True

        def fail_after_detected_member(archive: tarfile.TarFile) -> tarfile.TarInfo | None:
            if malicious_member_scanned:
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

    def test_sparse_large_raw_tar_late_invalid_header_is_inconclusive_without_cache(
        self,
        tmp_path: Path,
    ) -> None:
        archive_path = tmp_path / "late-invalid-benign.tar"
        _write_sparse_raw_tar(
            archive_path,
            member_name="safe.txt",
            member_payload=b"ordinary member",
            late_invalid_header=True,
        )

        direct = core.scan_file(str(archive_path), config={"cache_enabled": False})

        assert direct.scanner_name == "tar"
        assert direct.success is False
        assert "tar_scan_incomplete" in direct.metadata["scan_outcome_reasons"]
        assert any(entry["path"] == f"{archive_path}:safe.txt" for entry in direct.metadata["contents"])
        _assert_inconclusive_aggregate_not_reused(
            archive_path,
            "tar_scan_incomplete",
            tmp_path / "late-invalid-benign-cache",
        )

    def test_raw_tar_nonzero_tail_fails_closed(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "raw-nonzero-tail.tar"
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("safe.txt")
            payload = b"safe"
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]
        archive_path.write_bytes(archive_path.read_bytes() + b"hidden")

        result = TarScanner().scan(str(archive_path))

        assert result.success is False
        assert "tar_scan_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_sparse_large_raw_tar_complete_end_marker_remains_successful(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "complete-end-marker.tar"
        _write_sparse_raw_tar(
            archive_path,
            member_name="safe.txt",
            member_payload=b"ordinary member",
            late_invalid_header=False,
        )

        direct = core.scan_file(str(archive_path), config={"cache_enabled": False})
        aggregate = core.scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert direct.scanner_name == "tar"
        assert direct.success is True
        assert direct.metadata.get("scan_outcome_reasons", []) == []
        assert direct.metadata["contents"] == [
            {"path": f"{archive_path}:safe.txt", "type": "unknown", "size": len(b"ordinary member")}
        ]
        assert core.determine_exit_code(aggregate) == 0

    def test_sparse_large_raw_tar_late_invalid_header_preserves_malicious_finding_without_cache(
        self,
        tmp_path: Path,
    ) -> None:
        archive_path = tmp_path / "late-invalid-malicious.tar"
        malicious_payload = b'cos\nsystem\n(S"echo pwned"\ntR.'
        _write_sparse_raw_tar(
            archive_path,
            member_name="payload.pkl",
            member_payload=malicious_payload,
            late_invalid_header=True,
        )

        direct = core.scan_file(str(archive_path), config={"cache_enabled": False})

        assert direct.scanner_name == "tar"
        assert direct.success is False
        assert "tar_scan_incomplete" in direct.metadata["scan_outcome_reasons"]
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and issue.location == f"{archive_path}:payload.pkl"
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system"))
            for issue in direct.issues
        )
        _assert_inconclusive_aggregate_not_reused(
            archive_path,
            "tar_scan_incomplete",
            tmp_path / "late-invalid-malicious-cache",
            expected_exit_code=1,
            expected_security_findings=True,
        )

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

    def test_scan_continues_after_budgeted_body_carrying_special_member(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "special_body.tar"
        special_payload = b"A" * 128
        later_payload = b"later"

        with tarfile.open(archive_path, "w") as archive:
            special = tarfile.TarInfo("unknown_special")
            special.type = b"Z"
            special.size = len(special_payload)
            archive.addfile(special, tarfile.io.BytesIO(special_payload))  # type: ignore[attr-defined]

            later_info = tarfile.TarInfo("later.txt")
            later_info.size = len(later_payload)
            archive.addfile(later_info, tarfile.io.BytesIO(later_payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert result.success is False
        assert "tar_special_member_unsupported" in result.metadata["scan_outcome_reasons"]
        assert any(entry["path"].endswith("unknown_special") for entry in result.metadata["contents"])
        assert any(entry["path"].endswith("later.txt") for entry in result.metadata["contents"])

    def test_raw_tar_scan_uses_seekable_mode(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        archive_path = tmp_path / "seekable_preflight.tar"
        payload = b"A" * 1024
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        opened_modes: list[str] = []
        original_open = tarfile.open

        def tracked_open(*args: Any, **kwargs: Any) -> tarfile.TarFile:
            mode = kwargs.get("mode")
            if isinstance(mode, str):
                opened_modes.append(mode)
            return original_open(*args, **kwargs)

        monkeypatch.setattr(tarfile, "open", tracked_open)

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert "r:" in opened_modes
        assert "r|" not in opened_modes

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

    def test_scan_compressed_tar_ratio_limit_precedes_member_extraction(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "ratio_pre_extract.tar.gz"
        payload = b"A" * 1_000_000

        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        scanner = TarScanner(config={"compressed_max_decompression_ratio": 2.0})

        def fail_extract(
            tar: tarfile.TarFile,
            member: tarfile.TarInfo,
            *,
            suffix: str,
        ) -> tuple[str, int]:
            pytest.fail(f"ratio limit should be enforced before extracting {member.name} with {suffix}")

        monkeypatch.setattr(scanner, "_extract_member_to_tempfile", fail_extract)

        result = scanner.scan(str(archive_path))

        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert result.success is False
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert "decompression ratio exceeded" in limit_checks[0].message.lower()
        assert "tar_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        assert result.metadata["contents"][0]["scan_status"] == "incomplete"
        assert result.metadata["contents"][0]["scan_outcome_reason"] == "tar_analysis_incomplete"

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

    def test_scan_compressed_tar_counts_concatenated_wrapper_tail_toward_size_limit(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "concatenated_tail.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("payload.txt")
            payload = b"safe"
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]
        with archive_path.open("ab") as archive_file:
            archive_file.write(gzip.compress(b"\0" * (1024 * 1024)))

        result = TarScanner(
            config={
                "compressed_max_decompressed_bytes": 100 * 1024,
                "compressed_max_decompression_ratio": 100_000.0,
            }
        ).scan(str(archive_path))

        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert result.success is False
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert "decompressed size exceeded" in limit_checks[0].message.lower()
        assert "tar_decompressed_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_scan_compressed_tar_rejects_nonzero_concatenated_wrapper_tail(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "nonzero_tail.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("payload.txt")
            payload = b"safe"
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]
        with archive_path.open("ab") as archive_file:
            archive_file.write(gzip.compress(b"not-tar-data"))

        result = TarScanner(
            config={
                "compressed_max_decompressed_bytes": 1024 * 1024,
                "compressed_max_decompression_ratio": 100_000.0,
            }
        ).scan(str(archive_path))

        trailing_checks = [check for check in result.checks if check.name == "Compressed TAR Trailing Data"]
        assert result.success is False
        assert len(trailing_checks) == 1
        assert trailing_checks[0].status == CheckStatus.FAILED
        assert "tar_compressed_trailing_data" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize(
        ("suffix", "mode"),
        [
            (".tar.bz2", "w:bz2"),
            (".tar.xz", "w:xz"),
        ],
    )
    def test_scan_bzip2_xz_tar_rejects_physical_trailing_bytes(
        self,
        tmp_path: Path,
        suffix: str,
        mode: Literal["w:bz2", "w:xz"],
    ) -> None:
        archive_path = tmp_path / f"physical-tail{suffix}"
        with tarfile.open(archive_path, mode) as archive:
            info = tarfile.TarInfo("payload.txt")
            payload = b"safe"
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]
        with archive_path.open("ab") as archive_file:
            archive_file.write(b"physical trailing payload")

        result = TarScanner(
            config={
                "compressed_max_decompressed_bytes": 1024 * 1024,
                "compressed_max_decompression_ratio": 100_000.0,
            }
        ).scan(str(archive_path))

        trailing_checks = [check for check in result.checks if check.name == "Compressed TAR Trailing Data"]
        assert result.success is False
        assert len(trailing_checks) == 1
        assert trailing_checks[0].status == CheckStatus.FAILED
        assert "tar_compressed_trailing_data" in result.metadata["scan_outcome_reasons"]

    def test_scan_xz_tar_accepts_valid_stream_padding(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "stream-padding.tar.xz"
        with tarfile.open(archive_path, "w:xz") as archive:
            info = tarfile.TarInfo("payload.txt")
            payload = b"safe"
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]
        with archive_path.open("ab") as archive_file:
            archive_file.write(b"\0" * 4)

        result = TarScanner(
            config={
                "compressed_max_xz_padding_bytes": 4,
                "compressed_max_decompressed_bytes": 1024 * 1024,
                "compressed_max_decompression_ratio": 100_000.0,
            }
        ).scan(str(archive_path))

        trailing_checks = [check for check in result.checks if check.name == "Compressed TAR Trailing Data"]
        assert result.success is True
        assert trailing_checks == []

    def test_xz_stream_padding_budget_is_cumulative_across_streams(self) -> None:
        wrapped = io.BytesIO(lzma.compress(b"first") + (b"\0" * 4) + lzma.compress(b"second") + (b"\0" * 4))
        reader = tar_scanner_module._StrictConcatenatedDecompressionReader(
            wrapped,
            compression_codec="xz",
            max_xz_padding_bytes=4,
        )

        with pytest.raises(
            tar_scanner_module._TarStreamBudgetExceeded,
            match="XZ stream padding exceeded bounded read limit",
        ) as exc_info:
            reader.read()

        assert exc_info.value.reason == "tar_compressed_padding_limit_exceeded"
        assert exc_info.value.bytes_read == 8
        assert exc_info.value.max_bytes == 4

    def test_xz_stream_padding_followup_read_is_bounded_by_remaining_budget(self) -> None:
        class SplitReader:
            def __init__(self) -> None:
                self.first_read = True
                self.read_sizes: list[int] = []

            def read(self, size: int = -1) -> bytes:
                self.read_sizes.append(size)
                if self.first_read:
                    self.first_read = False
                    return lzma.compress(b"payload")
                return b"\0" * size

        wrapped = SplitReader()
        reader = tar_scanner_module._StrictConcatenatedDecompressionReader(
            cast(BinaryIO, wrapped),
            compression_codec="xz",
            max_xz_padding_bytes=64,
        )

        with pytest.raises(tar_scanner_module._TarStreamBudgetExceeded) as exc_info:
            reader.read()

        assert exc_info.value.reason == "tar_compressed_padding_limit_exceeded"
        assert wrapped.read_sizes == [reader._RAW_READ_SIZE, 65]

    def test_scan_xz_tar_bounds_zero_stream_padding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "bounded-stream-padding.tar.xz"
        with tarfile.open(archive_path, "w:xz") as archive:
            info = tarfile.TarInfo("payload.txt")
            payload = b"safe"
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]
        padding_size = 1024 * 1024
        with archive_path.open("r+b") as archive_file:
            archive_file.seek(0, os.SEEK_END)
            archive_file.seek(padding_size - 1, os.SEEK_CUR)
            archive_file.write(b"\0")

        class CountingReader:
            def __init__(self, fileobj: BinaryIO) -> None:
                self.fileobj = fileobj
                self.bytes_read = 0

            def read(self, size: int = -1) -> bytes:
                data = self.fileobj.read(size)
                self.bytes_read += len(data)
                return data

            def __getattr__(self, name: str) -> Any:
                return getattr(self.fileobj, name)

        readers: list[CountingReader] = []
        original_init = tar_scanner_module._StrictConcatenatedDecompressionReader.__init__

        def tracked_init(reader: Any, fileobj: BinaryIO, **kwargs: Any) -> None:
            counting_reader = CountingReader(fileobj)
            readers.append(counting_reader)
            original_init(reader, cast(BinaryIO, counting_reader), **kwargs)

        monkeypatch.setattr(tar_scanner_module._StrictConcatenatedDecompressionReader, "__init__", tracked_init)

        result = TarScanner(
            config={
                "compressed_max_xz_padding_bytes": 64,
                "compressed_max_decompressed_bytes": 1024 * 1024,
                "compressed_max_decompression_ratio": 100_000.0,
            }
        ).scan(str(archive_path))

        assert result.success is False
        assert "tar_compressed_padding_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert len(readers) == 1
        assert readers[0].bytes_read <= tar_scanner_module._StrictConcatenatedDecompressionReader._RAW_READ_SIZE
        _assert_inconclusive_aggregate_not_reused(
            archive_path,
            "tar_compressed_padding_limit_exceeded",
            tmp_path / "xz-padding-cache",
            compressed_max_xz_padding_bytes=64,
            compressed_max_decompressed_bytes=1024 * 1024,
            compressed_max_decompression_ratio=100_000.0,
        )

    def test_scan_compressed_tar_stops_tail_at_ratio_limit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "high-ratio-tail.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("payload.txt")
            payload = b"safe"
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]
        with archive_path.open("ab") as archive_file:
            archive_file.write(gzip.compress(b"X" * (8 * 1024 * 1024)))

        max_stream_bytes_read = 0
        original_read = tar_scanner_module._TarBoundedStream.read

        def track_stream_read(stream: tar_scanner_module._TarBoundedStream, size: int = -1) -> bytes:
            nonlocal max_stream_bytes_read
            try:
                return original_read(stream, size)
            finally:
                max_stream_bytes_read = max(max_stream_bytes_read, stream.bytes_read)

        monkeypatch.setattr(tar_scanner_module._TarBoundedStream, "read", track_stream_read)
        max_ratio = 2.0
        ratio_byte_limit = int(archive_path.stat().st_size * max_ratio)

        result = TarScanner(
            config={
                "compressed_max_decompressed_bytes": 16 * 1024 * 1024,
                "compressed_max_decompression_ratio": max_ratio,
            }
        ).scan(str(archive_path))

        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert result.success is False
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert "decompression ratio exceeded" in limit_checks[0].message.lower()
        assert max_stream_bytes_read <= ratio_byte_limit + 1

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

    def test_tar_scan_streams_members_without_getmembers(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """TAR scanning should stream members instead of materializing them with getmembers()."""
        archive_path = tmp_path / "streamed.tar.gz"

        with tarfile.open(archive_path, "w:gz") as archive:
            for index in range(3):
                info = tarfile.TarInfo(f"payload-{index}.bin")
                payload = f"payload-{index}".encode()
                info.size = len(payload)
                archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        def fail_getmembers(self: tarfile.TarFile) -> list[tarfile.TarInfo]:
            raise AssertionError("TarScanner should not call getmembers() during scanning")

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
        aggregate_checks = [check for check in result.checks if check.name == "TAR Aggregate Size Limit Check"]
        assert not any(check.status == CheckStatus.PASSED for check in aggregate_checks)

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
        payload = b"D" * 10_000

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

    def test_cumulative_pax_metadata_budget_fails_before_archive_scan(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "many-pax.tar.gz"
        with tarfile.open(archive_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            for index in range(3):
                info = tarfile.TarInfo(f"entry-{index}.txt")
                info.pax_headers = {"comment": "A" * (40 * 1024)}
                archive.addfile(info, tarfile.io.BytesIO(b""))  # type: ignore[attr-defined]

        assert file_detection._detect_tar_route(str(archive_path)) == "tar"

        result = TarScanner(config={"max_tar_metadata_bytes": 64 * 1024}).scan(str(archive_path))

        assert result.success is False
        assert "tar_metadata_read_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert any(check.name == "TAR Stream Budget" and check.status == CheckStatus.FAILED for check in result.checks)

    def test_cumulative_gnu_longname_metadata_budget_fails_closed(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "many-longnames.tar.gz"
        with tarfile.open(archive_path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
            for index in range(3):
                info = tarfile.TarInfo(("a" * (40 * 1024)) + f"-{index}.txt")
                archive.addfile(info, tarfile.io.BytesIO(b""))  # type: ignore[attr-defined]

        assert file_detection._detect_tar_route(str(archive_path)) == "tar"

        result = TarScanner(config={"max_tar_metadata_bytes": 64 * 1024}).scan(str(archive_path))

        assert result.success is False
        assert "tar_metadata_read_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_gnu_sparse_extension_chain_is_bounded_during_route_and_scan(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "sparse-metadata.tar"
        archive_path.write_bytes(_old_gnu_sparse_tar_bytes(extension_blocks=129))

        assert file_detection._detect_tar_route(str(archive_path)) == file_detection.NEMO_ROUTING_INCONCLUSIVE_FORMAT

        result = TarScanner(config={"max_tar_metadata_bytes": 64 * 1024}).scan(str(archive_path))

        assert result.success is False
        assert "tar_metadata_read_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_sparse_member_reserves_shared_work_before_compressed_body(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        archive_path = tmp_path / "sparse-body.tar.gz"
        physical_size = 32 * 1024
        archive_path.write_bytes(
            gzip.compress(_old_gnu_sparse_tar_bytes(extension_blocks=0, physical_size=physical_size))
        )
        bytes_read = 0
        original_read = tar_scanner_module._TarBoundedStream.read

        def tracked_read(self: Any, size: int = -1) -> bytes:
            nonlocal bytes_read
            data = original_read(self, size)
            bytes_read += len(data)
            return data

        monkeypatch.setattr(tar_scanner_module._TarBoundedStream, "read", tracked_read)

        result = TarScanner(
            config={
                "max_tar_total_uncompressed_size": 1,
                "compressed_max_decompressed_bytes": 100_000,
                "compressed_max_decompression_ratio": 10_000.0,
            }
        ).scan(str(archive_path))

        aggregate_checks = [check for check in result.checks if check.name == "TAR Aggregate Size Limit Check"]
        assert result.success is False
        assert any(check.status == CheckStatus.FAILED for check in aggregate_checks)
        assert not any(check.status == CheckStatus.PASSED for check in aggregate_checks)
        assert result.metadata["archive_uncompressed_size"] >= physical_size
        assert bytes_read < physical_size

    def test_truncated_route_scans_config_reached_through_ancestor_symlink(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_NEMO_ROUTE_MAX_BODY_SKIP_BYTES", 64)
        archive_path = tmp_path / "ancestor-link.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            payload = b"x" * 128
            info = tarfile.TarInfo("large.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

            link = tarfile.TarInfo("alias")
            link.type = tarfile.SYMTYPE
            link.linkname = "."
            archive.addfile(link)

            config = b"model:\n  _target_: os.system\n"
            info = tarfile.TarInfo("alias/model_config.yaml")
            info.size = len(config)
            archive.addfile(info, tarfile.io.BytesIO(config))  # type: ignore[attr-defined]

        result = core.scan_file(str(archive_path), config={"cache_enabled": False})

        assert result.scanner_name == "tar"
        assert result.success is False
        assert any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

    def test_truncated_route_scans_config_reached_through_hardlinked_symlink(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_NEMO_ROUTE_MAX_BODY_SKIP_BYTES", 64)
        archive_path = tmp_path / "hardlinked-symlink.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            payload = b"x" * 128
            info = tarfile.TarInfo("large.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

            directory_alias = tarfile.TarInfo("dir")
            directory_alias.type = tarfile.SYMTYPE
            directory_alias.linkname = "."
            archive.addfile(directory_alias)

            seed = tarfile.TarInfo("dir/seed")
            seed.type = tarfile.SYMTYPE
            seed.linkname = "."
            archive.addfile(seed)

            alias = tarfile.TarInfo("alias")
            alias.type = tarfile.LNKTYPE
            alias.linkname = "dir/seed"
            archive.addfile(alias)

            config = b"model:\n  _target_: os.system\n"
            info = tarfile.TarInfo("alias/model_config.yaml")
            info.size = len(config)
            archive.addfile(info, tarfile.io.BytesIO(config))  # type: ignore[attr-defined]

        result = core.scan_file(str(archive_path), config={"cache_enabled": False})

        assert result.scanner_name == "tar"
        assert result.success is False
        assert any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

    @pytest.mark.parametrize("member_type", [tarfile.SYMTYPE, tarfile.LNKTYPE])
    def test_truncated_route_fails_closed_for_link_created_at_symlinked_root_config(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        member_type: bytes,
    ) -> None:
        monkeypatch.setattr(file_detection, "_NEMO_ROUTE_MAX_BODY_SKIP_BYTES", 64)
        archive_path = tmp_path / f"linked-root-{member_type.hex()}.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            payload = b"x" * 128
            info = tarfile.TarInfo("large.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

            config = b"model:\n  _target_: os.system\n"
            info = tarfile.TarInfo("payload.yaml")
            info.size = len(config)
            archive.addfile(info, tarfile.io.BytesIO(config))  # type: ignore[attr-defined]

            alias = tarfile.TarInfo("alias")
            alias.type = tarfile.SYMTYPE
            alias.linkname = "."
            archive.addfile(alias)

            root_link = tarfile.TarInfo("alias/model_config.yaml")
            root_link.type = member_type
            root_link.linkname = "payload.yaml"
            archive.addfile(root_link)

        result = core.scan_file(str(archive_path), config={"cache_enabled": False})

        assert result.scanner_name == "tar"
        assert result.success is False
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_empty_tar_prefix_does_not_hide_malicious_zip(self, tmp_path: Path) -> None:
        class DangerousPayload:
            def __reduce__(self) -> tuple[Any, tuple[str]]:
                return (os.system, ("echo tar-prefix-zip",))

        zip_path = tmp_path / "payload.zip"
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr("data.pkl", pickle.dumps(DangerousPayload()))

        polyglot_path = tmp_path / "payload.tar"
        payload = (b"\0" * 1024) + zip_path.read_bytes()
        payload += b"\0" * (-len(payload) % tarfile.BLOCKSIZE)
        polyglot_path.write_bytes(payload)

        assert zipfile.is_zipfile(polyglot_path)
        assert file_detection.detect_file_format(str(polyglot_path)) == "zip"

        result = core.scan_file(str(polyglot_path), config={"cache_enabled": False})

        assert result.scanner_name == "zip"
        assert result.success is False
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)

    def test_outer_nemo_skip_flag_does_not_leak_into_nested_tar(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_NEMO_ROUTE_MAX_BODY_SKIP_BYTES", 64)
        inner_path = tmp_path / "inner.tar.gz"
        with tarfile.open(inner_path, "w:gz") as inner:
            payload = b"x" * 128
            info = tarfile.TarInfo("large.bin")
            info.size = len(payload)
            inner.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]
            config = b"model:\n  _target_: os.system\n"
            info = tarfile.TarInfo("model_config.yaml")
            info.size = len(config)
            inner.addfile(info, tarfile.io.BytesIO(config))  # type: ignore[attr-defined]

        outer_path = tmp_path / "outer.tar.gz"
        with tarfile.open(outer_path, "w:gz") as outer:
            root_config = b"model:\n  _target_: torch.nn.Linear\n"
            info = tarfile.TarInfo("model_config.yaml")
            info.size = len(root_config)
            outer.addfile(info, tarfile.io.BytesIO(root_config))  # type: ignore[attr-defined]
            nested = inner_path.read_bytes()
            info = tarfile.TarInfo("inner.tar.gz")
            info.size = len(nested)
            outer.addfile(info, tarfile.io.BytesIO(nested))  # type: ignore[attr-defined]

        result = core.scan_file(str(outer_path), config={"cache_enabled": False})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)
