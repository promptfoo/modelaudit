import hashlib
import subprocess
from pathlib import Path

import pytest

from scripts.capture_process_provider_diagnostic import tracked_input_hashes


def test_tracked_input_hashes_preserve_git_paths_and_report_missing_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    subprocess.run(["git", "init", "--quiet"], check=True)
    package = Path("packages/modelaudit-picklescan")
    package.mkdir(parents=True)
    present = package / "tést file.py"
    missing = package / "removed.py"
    present.write_bytes(b"original")
    missing.write_bytes(b"removed")
    subprocess.run(["git", "add", "--", package.as_posix()], check=True)
    present.write_bytes(b"working tree")
    missing.unlink()

    hashes, missing_inputs = tracked_input_hashes()

    assert hashes == {present.as_posix(): hashlib.sha256(b"working tree").hexdigest()}
    assert missing_inputs == [missing.as_posix()]
