from __future__ import annotations

import subprocess
import sys
import textwrap
from importlib.util import find_spec

from modelaudit_picklescan.api import _RUST_EXTENSION_MODULE


def test_rust_extension_module_name_is_stable() -> None:
    assert _RUST_EXTENSION_MODULE == "modelaudit_picklescan._rust"


def test_default_scan_imports_native_module_without_engine_package() -> None:
    if find_spec(_RUST_EXTENSION_MODULE) is None:
        return

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            textwrap.dedent(
                """
                import pickle
                import sys

                from modelaudit_picklescan import ScanStatus, scan_bytes

                report = scan_bytes(
                    pickle.dumps({"weights": [1, 2, 3]}, protocol=4),
                    source="rust-only-default.pkl",
                )
                if report.status != ScanStatus.COMPLETE:
                    raise SystemExit(f"unexpected status: {report.status!r}")
                if any(name.startswith("modelaudit_picklescan.engine") for name in sys.modules):
                    raise SystemExit("deleted engine package was imported")
                if "modelaudit_picklescan._rust" not in sys.modules:
                    raise SystemExit("Rust extension was not imported")
                """
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
