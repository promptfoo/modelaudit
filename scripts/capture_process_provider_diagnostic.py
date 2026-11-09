import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def tracked_input_hashes() -> tuple[dict[str, str], list[str]]:
    inputs = [
        "packages/modelaudit-picklescan",
        "pyproject.toml",
        "uv.lock",
        "tests/conftest.py",
        ".github/workflows/nightly.yml",
        "scripts/capture_process_provider_diagnostic.py",
    ]
    paths = subprocess.check_output(["git", "ls-files", "-z", "--", *inputs])
    hashes: dict[str, str] = {}
    missing: list[str] = []
    for name in os.fsdecode(paths).split("\0"):
        if not name:
            continue
        try:
            hashes[name] = hashlib.sha256(Path(name).read_bytes()).hexdigest()
        except FileNotFoundError:
            missing.append(name)
    return hashes, missing


def main() -> None:
    output = Path(os.environ["RUNNER_TEMP"]) / "picklescan-process-provider-diagnostic"
    output.mkdir()
    package = importlib.util.find_spec("modelaudit_picklescan")
    native = importlib.util.find_spec("modelaudit_picklescan._rust")
    assert package is not None and package.origin is not None
    assert native is not None and native.origin is not None
    binary = Path(native.origin).resolve(strict=True)
    assert binary.suffix == ".so"
    shutil.copy2(binary, output / binary.name)
    hashes, missing = tracked_input_hashes()
    manifest = {
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "tracked_status": subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], text=True),
        "runtime": sys.version,
        "executable": sys.executable,
        "platform": platform.platform(),
        "package_origin": package.origin,
        "native_origin": str(binary),
        "native_sha256": hashlib.sha256((output / binary.name).read_bytes()).hexdigest(),
        "tracked_input_sha256": hashes,
        "missing_tracked_inputs": missing,
        "installed_versions": sorted(
            (distribution.metadata["Name"], distribution.version) for distribution in importlib.metadata.distributions()
        ),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
