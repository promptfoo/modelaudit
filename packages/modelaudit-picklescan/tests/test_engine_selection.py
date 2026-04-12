from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

from modelaudit_picklescan.engine.selection import RUST_EXTENSION_MODULE, rust_engine_available


def test_rust_engine_available_returns_bool() -> None:
    assert isinstance(rust_engine_available(), bool)


def test_default_scan_does_not_import_deleted_python_engine() -> None:
    if not rust_engine_available():
        pytest.skip("Rust extension is not available")

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            textwrap.dedent(
                """
                import pickle
                import sys

                from modelaudit_picklescan import ScanStatus, scan_bytes
                from modelaudit_picklescan.engine.selection import RUST_EXTENSION_MODULE

                report = scan_bytes(
                    pickle.dumps({"weights": [1, 2, 3]}, protocol=4),
                    source="rust-only-default.pkl",
                )
                if report.status != ScanStatus.COMPLETE:
                    raise SystemExit(f"unexpected status: {report.status!r}")
                if "modelaudit_picklescan.engine.scanner" in sys.modules:
                    raise SystemExit("deleted Python scanner was imported")
                if RUST_EXTENSION_MODULE not in sys.modules:
                    raise SystemExit("Rust extension was not imported")
                """
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_rust_extension_module_name_is_stable() -> None:
    assert RUST_EXTENSION_MODULE == "modelaudit_picklescan._rust"
