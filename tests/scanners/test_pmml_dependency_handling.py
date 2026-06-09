"""Regression tests for PMML scanner dependency handling."""

import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "fake_package_source",
    [
        'raise RuntimeError("broken defusedxml installation")\n',
        "ElementTree = None\n",
    ],
    ids=["import-error", "missing-element-tree"],
)
def test_pmml_scanner_broken_defusedxml_fails_closed(
    tmp_path: Path,
    fake_package_source: str,
) -> None:
    fake_dependencies = tmp_path / "fake-dependencies"
    fake_package = fake_dependencies / "defusedxml"
    fake_package.mkdir(parents=True)
    (fake_package / "__init__.py").write_text(
        fake_package_source,
        encoding="utf-8",
    )
    pmml_path = tmp_path / "model.pmml"
    pmml_path.write_text(
        "<?xml version='1.0'?><PMML version='4.4'><Header/></PMML>",
        encoding="utf-8",
    )

    repository_root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    python_path = [str(fake_dependencies), str(repository_root)]
    if existing_python_path := env.get("PYTHONPATH"):
        python_path.append(existing_python_path)
    env["PYTHONPATH"] = os.pathsep.join(python_path)

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                "from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME; "
                "from modelaudit.scanners import pmml_scanner; "
                "result = pmml_scanner.PmmlScanner().scan(sys.argv[1]); "
                "assert pmml_scanner.HAS_DEFUSEDXML is False; "
                "assert pmml_scanner.DefusedET is None; "
                "assert result.success is False; "
                "assert result.metadata['scan_outcome'] == INCONCLUSIVE_SCAN_OUTCOME; "
                "assert result.metadata['scan_outcome_reasons'] == "
                "[pmml_scanner.PmmlScanner.XML_PARSER_UNAVAILABLE_INCOMPLETE_REASON]; "
                "assert any(check.name == 'XML Parser Security Check' for check in result.checks)"
            ),
            str(pmml_path),
        ],
        capture_output=True,
        check=False,
        env=env,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
