#!/usr/bin/env python3
"""
7-Zip Test Asset Generator

Generates 7z archive test assets for SevenZipScanner testing.
Creates both safe and malicious archives to test scanner behavior.
"""

import os
import pickle
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import py7zr as _py7zr
else:
    _py7zr = None

# Only try to import py7zr if available
try:
    import py7zr

    HAS_PY7ZR = True
except ImportError:
    HAS_PY7ZR = False
    py7zr = _py7zr


def generate_malicious_7z(assets_dir: Path) -> None:
    """Create 7z archive containing malicious pickle for testing"""
    if not HAS_PY7ZR:
        print("py7zr not available - skipping 7z asset generation")
        return

    archives_dir = assets_dir / "samples" / "archives"
    archives_dir.mkdir(parents=True, exist_ok=True)

    malicious_7z = archives_dir / "malicious.7z"
    if malicious_7z.exists():
        print(f"Skipping {malicious_7z} - already exists")
        return

    # Create temporary malicious pickle
    class MaliciousClass:
        def __reduce__(self):
            # This would execute 'echo 7z_test_attack' if unpickled
            return (eval, ("__import__('os').system('echo 7z_test_attack')",))

    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as temp_file:
        pickle.dump(MaliciousClass(), temp_file)
        temp_pickle_path = temp_file.name

    try:
        # Create 7z archive with malicious pickle
        with py7zr.SevenZipFile(malicious_7z, "w") as archive:
            archive.write(temp_pickle_path, "malicious_model.pkl")

        print(f"Created {malicious_7z}")

    finally:
        # Clean up temporary file
        os.unlink(temp_pickle_path)


def generate_safe_7z(assets_dir: Path) -> None:
    """Create 7z archive with safe content for testing"""
    if not HAS_PY7ZR:
        return

    archives_dir = assets_dir / "samples" / "archives"
    archives_dir.mkdir(parents=True, exist_ok=True)

    safe_7z = archives_dir / "safe.7z"
    if safe_7z.exists():
        print(f"Skipping {safe_7z} - already exists")
        return

    # Create safe test data
    safe_data = {
        "model_weights": [1.0, 2.0, 3.0, 4.0],
        "model_config": {"layers": 3, "activation": "relu"},
        "metadata": {"version": "1.0", "framework": "test"},
    }

    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as temp_file:
        pickle.dump(safe_data, temp_file)
        temp_pickle_path = temp_file.name

    try:
        # Create 7z archive with safe pickle
        with py7zr.SevenZipFile(safe_7z, "w") as archive:
            archive.write(temp_pickle_path, "safe_model.pkl")

        print(f"Created {safe_7z}")

    finally:
        # Clean up temporary file
        os.unlink(temp_pickle_path)


def generate_mixed_content_7z(assets_dir: Path) -> None:
    """Create 7z archive with mixed content (some scannable, some not)"""
    if not HAS_PY7ZR:
        return

    archives_dir = assets_dir / "samples" / "archives"
    archives_dir.mkdir(parents=True, exist_ok=True)

    mixed_7z = archives_dir / "mixed_content.7z"
    if mixed_7z.exists():
        print(f"Skipping {mixed_7z} - already exists")
        return

    # Create temporary files with different content types
    temp_files = []

    try:
        # Create a safe pickle file
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as temp_file:
            pickle.dump({"safe": True, "data": "test"}, temp_file)
            temp_files.append((temp_file.name, "model.pkl"))

        # Create a text file (not scannable by model scanners)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as temp_file:
            temp_file.write("This is just a text file with no security implications.")
            temp_files.append((temp_file.name, "readme.txt"))

        # Create a JSON config file (scannable)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_file:
            import json

            json.dump({"model_type": "test", "version": "1.0"}, temp_file)
            temp_files.append((temp_file.name, "config.json"))

        # Create 7z archive with mixed content
        with py7zr.SevenZipFile(mixed_7z, "w") as archive:
            for temp_path, archive_name in temp_files:
                archive.write(temp_path, archive_name)

        print(f"Created {mixed_7z}")

    finally:
        # Clean up temporary files
        for temp_path, _ in temp_files:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


def generate_path_traversal_7z(assets_dir: Path) -> None:
    """Create 7z archive with path traversal attempt for security testing"""
    if not HAS_PY7ZR:
        return

    archives_dir = assets_dir / "samples" / "archives"
    archives_dir.mkdir(parents=True, exist_ok=True)

    traversal_7z = archives_dir / "path_traversal.7z"
    if traversal_7z.exists():
        print(f"Skipping {traversal_7z} - already exists")
        return

    # Create safe content
    safe_data = {"safe": True, "test_data": [1, 2, 3]}

    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as temp_file:
        pickle.dump(safe_data, temp_file)
        temp_pickle_path = temp_file.name

    try:
        # Create 7z archive with path traversal attempt
        with py7zr.SevenZipFile(traversal_7z, "w") as archive:
            # This should be caught by the path traversal detection
            archive.write(temp_pickle_path, "../../../dangerous_file.pkl")

        print(f"Created {traversal_7z}")

    finally:
        # Clean up temporary file
        os.unlink(temp_pickle_path)


def generate_empty_7z(assets_dir: Path) -> None:
    """Create empty 7z archive for edge case testing"""
    if not HAS_PY7ZR:
        return

    archives_dir = assets_dir / "samples" / "archives"
    archives_dir.mkdir(parents=True, exist_ok=True)

    empty_7z = archives_dir / "empty.7z"
    if empty_7z.exists():
        print(f"Skipping {empty_7z} - already exists")
        return

    # Create empty 7z archive
    with py7zr.SevenZipFile(empty_7z, "w") as archive:
        pass  # Create empty archive

    print(f"Created {empty_7z}")


def generate_all_7z_assets(assets_dir: Path | None = None) -> None:
    """Generate all 7z test assets"""
    if assets_dir is None:
        # Default to tests/assets directory
        current_dir = Path(__file__).parent
        assets_dir = current_dir.parent

    if not HAS_PY7ZR:
        print("Warning: py7zr not available - 7z test assets will not be generated")
        print("Install with: pip install py7zr")
        return

    print(f"Generating 7z test assets in {assets_dir}")

    # Generate different types of test archives
    generate_safe_7z(assets_dir)
    generate_malicious_7z(assets_dir)
    generate_mixed_content_7z(assets_dir)
    generate_path_traversal_7z(assets_dir)
    generate_empty_7z(assets_dir)

    print("7z test asset generation complete!")


if __name__ == "__main__":
    generate_all_7z_assets()
