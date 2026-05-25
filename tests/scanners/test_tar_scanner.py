import gzip
import os
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Literal

import pytest

from modelaudit import core
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.scanners.archive_dispatch import NESTED_SCAN_CALLBACK_CONFIG_KEY
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.tar_scanner import (
    ARCHIVE_MEMBER_COPY_CHUNK_BYTES,
    DEFAULT_MAX_DECOMPRESSED_BYTES,
    DEFAULT_MAX_DECOMPRESSION_RATIO,
    DEFAULT_MAX_TAR_ENTRY_SIZE,
    TarScanner,
)


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

    def test_scan_tar_flags_builtins_getattr_keyword_call_dangerous_python_member(self, tmp_path: Path) -> None:
        """Keyword-based getattr indirection should still resolve to the risky call name."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = b"import builtins as bi\nimport os\nbi.getattr(object=os, name='system').__call__('echo hidden')\n"

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

    @pytest.mark.parametrize(
        "payload",
        [
            b"__builtins__['ev' + 'al']('1 + 1')\n",
            b"getattr(__builtins__, 'eval')('1 + 1')\n",
            b"__builtins__.__dict__.get('eval')('1 + 1')\n",
            b"globals()['__builtins__']['ev' + 'al']('1 + 1')\n",
            b"globals().get('__builtins__').get('eval')('1 + 1')\n",
            b"getattr(globals()['__builtins__'], 'eval')('1 + 1')\n",
            b"namespace = globals()\nnamespace['__builtins__']['ev' + 'al']('1 + 1')\n",
            b"namespace = globals()\nnamespace.get('__builtins__').get('eval')('1 + 1')\n",
            b"namespace = globals()\ngetattr(namespace['__builtins__'], 'eval')('1 + 1')\n",
            b"lookup = globals().get\nlookup('__builtins__').get('ev' + 'al')('1 + 1')\n",
            (b"namespace = globals()\nlookup = namespace.get\nlookup('__builtins__')['ev' + 'al']('1 + 1')\n"),
            b"lookup = globals()['__builtins__'].get\nlookup('ev' + 'al')('1 + 1')\n",
            b"lookup = globals()['__builtins__'].__getitem__\nlookup('ev' + 'al')('1 + 1')\n",
        ],
    )
    def test_scan_tar_flags_implicit_builtins_dangerous_python_member(self, tmp_path: Path, payload: bytes) -> None:
        archive_path = tmp_path / "model_bundle.tar"
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].rule_code == "S104"
        assert python_checks[0].details["reason"] == "high-risk calls: __builtins__.eval"

    @pytest.mark.parametrize(
        "payload",
        [
            b"callbacks = {'eval': len}\ncallbacks['eval']([])\n",
            b"import builtins as bi\nbi.open('labels.json', 'r')\n",
            b"globals()['__builtins__']['len']([1])\n",
            b"globals = lambda: {'__builtins__': {'eval': len}}\nglobals()['__builtins__']['eval']([])\n",
            b"namespace = globals()\nnamespace['__builtins__']['len']([1])\n",
            (
                b"namespace = globals()\n"
                b"namespace = {'__builtins__': {'eval': len}}\n"
                b"namespace['__builtins__']['eval']([])\n"
            ),
            (
                b"namespace = globals()\n"
                b"namespace['__builtins__']['eval'] = len\n"
                b"namespace['__builtins__']['eval']([])\n"
            ),
            b"lookup = globals().get\nlookup('__builtins__').get('len')([1])\n",
            b"mapping = {'eval': len}\nlookup = mapping.get\nlookup('eval')([])\n",
        ],
    )
    def test_scan_tar_allows_benign_builtin_shaped_source(self, tmp_path: Path, payload: bytes) -> None:
        archive_path = tmp_path / "model_bundle.tar"
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert not any(check.name == "Python Archive Member Security" for check in result.checks)

    def test_scan_tar_reports_dangerous_builtin_reassignment(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "model_bundle.tar"
        payload = (
            b"namespace = globals()\n"
            b"namespace['__builtins__']['eval'] = __builtins__['exec']\n"
            b"namespace['__builtins__']['eval']('pass')\n"
        )
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("handler.py")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        python_checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(python_checks) == 1
        assert python_checks[0].status == CheckStatus.FAILED
        assert python_checks[0].rule_code == "S104"
        assert python_checks[0].details["reason"] == "high-risk calls: __builtins__.exec"

    def test_scan_tar_flags_aliased_getattr_helper_dangerous_python_member(self, tmp_path: Path) -> None:
        """Aliased getattr helpers and module aliases should still resolve risky calls."""
        archive_path = tmp_path / "model_bundle.tar"
        payload = (
            b"from builtins import getattr as resolve\n"
            b"import os as operating_system\n"
            b"resolve(object=operating_system, name='system')('echo hidden')\n"
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

    @pytest.mark.parametrize(
        "payload",
        [
            b"import os\nos.__dict__['sys' + 'tem']('echo hidden')\n",
            b"import os as operating_system\nvars(operating_system)['system']('echo hidden')\n",
            b"import os\nos.__dict__.get('sys' + 'tem')('echo hidden')\n",
            b"import os\nvars(os).get('system')('echo hidden')\n",
            b"import os\ngetattr(os, '__dict__')['system']('echo hidden')\n",
            b"import os\ngetattr(os, '__dict__').get('system')('echo hidden')\n",
            b"import os\nos.__dict__.pop('system')('echo hidden')\n",
            b"import os\nos.__dict__.setdefault('system', None)('echo hidden')\n",
            b"import os\nos.__getattribute__('system')('echo hidden')\n",
            b"import os\nobject.__getattribute__(os, 'system')('echo hidden')\n",
            b"import os\ncommands = os.__dict__\ncommands['system']('echo hidden')\n",
            b"import os\ncommands = vars(os)\ncommands.get('system')('echo hidden')\n",
            b"import os\ncommands = getattr(os, '__dict__')\ncommands['system']('echo hidden')\n",
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
    def test_scan_tar_flags_static_namespace_dangerous_python_member(self, tmp_path: Path, payload: bytes) -> None:
        """Static module namespace dispatch should still resolve risky calls."""
        archive_path = tmp_path / "model_bundle.tar"

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

    @pytest.mark.parametrize("dispatch", [b"handlers['system'](1.0)\n", b"handlers.get('system')(1.0)\n"])
    def test_scan_tar_ignores_benign_dictionary_dispatch_python_member(self, tmp_path: Path, dispatch: bytes) -> None:
        """Ordinary application dictionaries should not be treated as module namespaces."""
        archive_path = tmp_path / "model_bundle.tar"
        source = (
            b"def normalize(value: float) -> float:\n"
            b"    return value / 255.0\n"
            b"handlers = {'system': normalize}\n" + dispatch
        )

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

    @pytest.mark.parametrize(
        ("source", "expected_rule_code", "expected_call"),
        [
            (b"import os\nos.system('echo hidden')\n", "S101", "os.system"),
            (b"import subprocess\nsubprocess.run(['echo'], check=False)\n", "S103", "subprocess.run"),
            (b"import importlib\nimportlib.import_module('os')\n", "S107", "importlib.import_module"),
            (b"eval('1 + 1')\n", "S104", "eval"),
            (b"import pickle\npickle.loads(b'\\x80\\x04N.')\n", "S213", "pickle.loads"),
        ],
    )
    def test_scan_tar_python_member_emits_accurate_rule_code(
        self, tmp_path: Path, source: bytes, expected_rule_code: str, expected_call: str
    ) -> None:
        """Each risk category must surface its own rule code (os.system as S101, etc.)."""
        archive_path = tmp_path / "model_bundle.tar"

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

    def test_max_depth_limit(self):
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

    def test_get_max_entry_size_uses_bounded_default(self) -> None:
        """Unconfigured TAR entry extraction should still have a bounded default."""
        assert TarScanner()._get_max_entry_size() == DEFAULT_MAX_TAR_ENTRY_SIZE

    def test_get_max_entry_size_prefers_explicit_file_size_limit(self) -> None:
        """The top-level file-size limit should remain the hard extraction cap."""
        scanner = TarScanner(config={"max_file_size": 4096, "max_entry_size": 128})
        assert scanner._get_max_entry_size() == 4096

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
        assert "tar entry payload.bin exceeds maximum size of 64 bytes" in oversize_checks[0].message.lower()

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

    def test_scan_skips_non_regular_tar_members(self, tmp_path: Path) -> None:
        """Valid non-file TAR members should not abort scanning later regular files."""
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

        assert result.success is True
        assert result.bytes_scanned == len(payload)
        assert all("named_pipe" not in issue.message for issue in result.issues)

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

    def test_corrupt_magic_confirmed_tar_is_inconclusive_and_uncached(self, tmp_path: Path) -> None:
        """A parse failure after TAR routing is incomplete analysis, not a security finding."""
        archive_path = tmp_path / "corrupt_magic.tar"
        archive_path.write_bytes(b"entry" + b"\0" * 252 + b"ustar" + b"\0" * 20)
        cache_dir = tmp_path / "cache"

        direct_result = self.scanner.scan(str(archive_path))
        assert direct_result.success is False
        assert direct_result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "tar_analysis_incomplete" in direct_result.metadata["scan_outcome_reasons"]
        assert not any(
            issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in direct_result.issues
        )

        reset_cache_manager()
        try:
            first_result = core.scan_model_directory_or_file(
                str(archive_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            second_result = core.scan_model_directory_or_file(
                str(archive_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

            for audit_result in (first_result, second_result):
                metadata = audit_result.file_metadata[str(archive_path)]
                assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
                assert "tar_analysis_incomplete" in metadata["scan_outcome_reasons"]
                assert core.determine_exit_code(audit_result) == 2
                assert not any(
                    issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in audit_result.issues
                )

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

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
