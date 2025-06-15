import re
from pathlib import Path


def is_zipfile(path: str) -> bool:
    """Check if file is a ZIP by reading the signature."""
    file_path = Path(path)
    if not file_path.is_file():
        return False
    try:
        with file_path.open("rb") as f:
            signature = f.read(4)
        return signature in [b"PK\x03\x04", b"PK\x05\x06"]
    except OSError:
        return False


def read_magic_bytes(path: str, num_bytes: int = 8) -> bytes:
    with Path(path).open("rb") as f:
        return f.read(num_bytes)


def detect_file_format(path: str) -> str:
    """
    Attempt to identify the format:
    - TensorFlow SavedModel (directory with saved_model.pb)
    - Keras HDF5 (.h5 file with HDF5 magic bytes)
    - PyTorch ZIP (.pt/.pth file that's a ZIP)
    - Pickle (.pkl/.pickle or other files with pickle magic)
    - If extension indicates pickle/pt/h5/pb, etc.
    """
    file_path = Path(path)
    if file_path.is_dir():
        # We'll let the caller handle directory logic.
        # But we do a quick guess if there's a 'saved_model.pb'.
        contents = list(file_path.iterdir())
        if any(f.name == "saved_model.pb" for f in contents):
            return "tensorflow_directory"
        return "directory"

    # Single file
    size = file_path.stat().st_size
    if size < 4:
        return "unknown"

    # Read first 4 bytes for most formats
    magic4 = read_magic_bytes(path, 4)

    # Check first 8 bytes for HDF5 magic
    magic8 = read_magic_bytes(path, 8)
    hdf5_magic = b"\x89HDF\r\n\x1a\n"
    if magic8 == hdf5_magic:
        return "hdf5"

    ext = file_path.suffix.lower()
    if ext in (".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle"):
        return "pickle"
    if ext == ".h5":
        return "hdf5"
    if ext == ".pb":
        return "protobuf"

    # Check ZIP magic
    if magic4[:2] == b"PK":
        return "zip"

    # Check pickle magic patterns
    if magic4 == b"\x80\x03]q" or magic4[:3] == b"\x80\x03]":
        return "pickle"

    return "unknown"


def find_sharded_files(directory: str) -> list:
    """
    Look for sharded model files like:
    pytorch_model-00001-of-00002.bin
    """
    dir_path = Path(directory)
    return sorted(
        [
            str(dir_path / fname)
            for fname in dir_path.iterdir()
            if fname.is_file()
            and re.match(r"pytorch_model-\d{5}-of-\d{5}\.bin", fname.name)
        ]
    )
