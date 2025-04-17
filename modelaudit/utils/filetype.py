import os
import struct
import re
import zipfile

def is_zipfile(path: str) -> bool:
    """Check if file is a ZIP by reading the signature."""
    try:
        with open(path, "rb") as f:
            signature = f.read(4)
        return signature in [b"PK\x03\x04", b"PK\x05\x06"]
    except Exception:
        return False

def read_magic_bytes(path: str, num_bytes: int = 8) -> bytes:
    with open(path, "rb") as f:
        return f.read(num_bytes)

def detect_file_format(path: str) -> str:
    """
    Attempt to identify the format:
     - If directory, return "tensorflow_directory" if saved_model.pb found, else "directory"
     - If is ZIP, return "zip_archive"
     - If is HDF5 from magic
     - If extension indicates pickle/pt/h5/pb, etc.
    """
    if os.path.isdir(path):
        # We'll let the caller handle directory logic.
        # But we do a quick guess if there's a 'saved_model.pb'.
        contents = os.listdir(path)
        if "saved_model.pb" in contents:
            return "tensorflow_directory"
        return "directory"

    # Single file
    size = os.path.getsize(path)
    if size < 4:
        return "unknown"

    if is_zipfile(path):
        return "zip_archive"

    # Check first 8 bytes for HDF5 magic
    # HDF5 = 0x894844460D0A1A0A
    magic8 = read_magic_bytes(path, 8)
    hdf5_magic = b"\x89HDF\r\n\x1a\n"
    if magic8 == hdf5_magic:
        return "hdf5"

    _, ext = os.path.splitext(path)
    ext = ext.lower()
    if ext in (".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle"):
        return "pickle"
    elif ext == ".h5":
        return "hdf5"
    elif ext == ".pb":
        return "tensorflow_pb"
    elif ext == ".onnx":
        return "onnx"

    return "unknown"

def gather_shards_if_any(directory: str):
    """
    Return a list of potential HF sharded model files, e.g.
    pytorch_model-00001-of-00005.bin
    """
    shards = []
    for fname in os.listdir(directory):
        # example pattern
        if re.match(r"pytorch_model-\d{5}-of-\d{5}\.bin", fname):
            shards.append(os.path.join(directory, fname))
    return sorted(shards)
