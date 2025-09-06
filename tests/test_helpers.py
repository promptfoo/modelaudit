"""
Robust test utilities that eliminate race conditions through proper synchronization.
"""

import os
import pickle
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Union


def create_pickle_file_atomically(target_path: Path, data: Any) -> None:
    """
    Create a pickle file atomically - it either exists completely or not at all.

    Uses atomic rename pattern to ensure the file is never in a partial state.
    """
    # Create temp file in same directory to ensure same filesystem
    temp_path = target_path.with_suffix(target_path.suffix + ".tmp")
    try:
        with open(temp_path, "wb") as f:
            pickle.dump(data, f)
            f.flush()
            os.fsync(f.fileno())  # Ensure OS writes to disk

        # Atomic rename - this is guaranteed atomic on POSIX systems
        temp_path.replace(target_path)
    except Exception:
        # Clean up temp file if anything goes wrong
        temp_path.unlink(missing_ok=True)
        raise


def create_zip_file_atomically(target_path: Path, content_builder: Callable[[zipfile.ZipFile], None]) -> None:
    """
    Create a zip file atomically using proper context management.

    Args:
        target_path: Final path for the zip file
        content_builder: Function that adds content to the zip file
    """
    temp_path = target_path.with_suffix(target_path.suffix + ".tmp")
    try:
        with zipfile.ZipFile(temp_path, "w") as zf:
            content_builder(zf)
            # Context manager ensures proper closing and flushing

        # Atomic rename
        temp_path.replace(target_path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


@contextmanager
def atomic_test_files(base_path: Path, file_specs: list[dict[str, Any]]):
    """
    Context manager that creates multiple test files atomically.

    Args:
        base_path: Directory to create files in
        file_specs: List of file specifications, e.g.:
            [
                {"name": "a.pkl", "data": {"test": "data"}},
                {"name": "b.pkl", "data": {"other": "data"}}
            ]

    Yields:
        Dict mapping file names to their paths
    """
    created_files = {}

    try:
        # Create all files atomically
        for spec in file_specs:
            file_path = base_path / spec["name"]

            if spec["name"].endswith(".pkl"):
                create_pickle_file_atomically(file_path, spec["data"])
            elif spec["name"].endswith(".zip"):
                create_zip_file_atomically(file_path, spec["builder"])
            else:
                # Generic file creation
                create_generic_file_atomically(file_path, spec.get("content", b""), spec.get("mode", "wb"))

            created_files[spec["name"]] = file_path

        yield created_files

    finally:
        # Clean up all created files
        for file_path in created_files.values():
            file_path.unlink(missing_ok=True)


def create_generic_file_atomically(target_path: Path, content: Union[str, bytes], mode: str = "wb") -> None:
    """Create any file atomically with given content."""
    temp_path = target_path.with_suffix(target_path.suffix + ".tmp")
    try:
        with open(temp_path, mode) as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())

        temp_path.replace(target_path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def prepare_test_scenario_max_total_size(base_path: Path) -> dict[str, Path]:
    """
    Prepare the test scenario for max_total_size test.
    Returns paths to all created files when they're guaranteed to be complete.
    """
    file_specs: list[dict[str, Any]] = [
        {"name": "a.pkl", "data": {"data": "x" * 100}},
        {"name": "b.pkl", "data": {"data": "y" * 100}},
        {"name": "c.pkl", "data": {"data": "z" * 100}},
    ]

    created_files: dict[str, Path] = {}
    for spec in file_specs:
        name: str = spec["name"]
        file_path = base_path / name
        create_pickle_file_atomically(file_path, spec["data"])
        created_files[name] = file_path

    return created_files


def prepare_test_scenario_nested_zip(base_path: Path) -> Path:
    """
    Prepare the test scenario for nested zip test.
    Returns path to zip file when it's guaranteed to be complete.
    """
    temp_st_path = base_path / "temp.safetensors"

    try:
        import numpy as np
        from safetensors.numpy import save_file

        # Create SafeTensors data
        safetensors_data = {"weight": np.array([1.0, 2.0, 3.0]).astype(np.float32)}

        # Create temporary SafeTensors file atomically
        save_file(safetensors_data, str(temp_st_path))
    except ImportError:
        # Fallback if safetensors not available
        create_generic_file_atomically(temp_st_path, b"fake safetensors content", "wb")

    try:
        # Create zip file atomically
        zip_path = base_path / "models.zip"

        def add_zip_content(zf: zipfile.ZipFile) -> None:
            zf.write(temp_st_path, "model.safetensors")
            zf.writestr("config.json", '{"model_type": "test", "hidden_size": 768}')

        create_zip_file_atomically(zip_path, add_zip_content)
        return zip_path

    finally:
        # Always clean up temp file, regardless of what happens
        temp_st_path.unlink(missing_ok=True)
