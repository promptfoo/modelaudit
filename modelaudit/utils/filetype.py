import re
import struct
from pathlib import Path

# Known GGML header variants (older formats like GGMF and GGJT)
GGML_MAGIC_VARIANTS = {
    b"GGML",
    b"GGMF",
    b"GGJT",
    b"GGLA",
    b"GGSA",
}


def is_zipfile(path: str) -> bool:
    """Check if file is a ZIP by reading the signature."""
    file_path = Path(path)
    if not file_path.is_file():
        return False
    try:
        signature = read_magic_bytes(path, 4)
        return signature.startswith(b"PK")
    except OSError:
        return False


def read_magic_bytes(path: str, num_bytes: int = 8) -> bytes:
    with Path(path).open("rb") as f:
        return f.read(num_bytes)


def detect_file_format_from_magic(path: str) -> str:
    """Detect file format solely from magic bytes."""
    file_path = Path(path)
    if file_path.is_dir():
        if (file_path / "saved_model.pb").exists():
            return "tensorflow_directory"
        return "directory"

    if not file_path.is_file():
        return "unknown"

    try:
        size = file_path.stat().st_size
        if size < 4:
            return "unknown"

        with file_path.open("rb") as f:
            header = f.read(16)

            # Check for TAR format by looking for the "ustar" signature
            if size >= 262:
                f.seek(257)
                if f.read(5).startswith(b"ustar"):
                    return "tar"
            # Reset to read from header for further checks
            f.seek(0)

            magic4 = header[:4]
            magic8 = header[:8]
            magic16 = header[:16]

            hdf5_magic = b"\x89HDF\r\n\x1a\n"
            if magic8 == hdf5_magic:
                return "hdf5"

            # NumPy magic check
            numpy_magic = b"\x93NUMPY"
            if magic8.startswith(numpy_magic):
                return "numpy"

            if magic4 == b"GGUF":
                return "gguf"
            if magic4 in GGML_MAGIC_VARIANTS:
                return "ggml"

            if magic4.startswith(b"PK"):
                return "zip"

            pickle_magics = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]
            if any(magic4.startswith(m) for m in pickle_magics):
                return "pickle"

            # SafeTensors format check: 8-byte length header + JSON metadata
            if size >= 12:  # Minimum: 8 bytes length + some JSON
                try:
                    json_length = struct.unpack("<Q", magic8)[0]
                    # Sanity check: JSON length should be reasonable
                    if 0 < json_length < size and json_length < 1024 * 1024:  # Max 1MB JSON
                        f.seek(8)
                        json_start = f.read(min(32, json_length))
                        if json_start.startswith(b"{") and b'"' in json_start:
                            return "safetensors"
                except (struct.error, OSError):
                    pass

    except OSError:
        return "unknown"

    # Fallback: check if it starts with JSON (for old safetensors or other JSON formats)
    magic4 = header[:4]
    magic8 = header[:8]
    magic16 = header[:16]

    if magic4[0:1] == b"{" or (size > 8 and b'"__metadata__"' in magic16):
        return "safetensors"

    if magic4 == b"\x08\x01\x12\x00" or b"onnx" in magic16:
        return "onnx"

    return "unknown"


def detect_file_format(path: str) -> str:
    """
    Attempt to identify the format:
    - TensorFlow SavedModel (directory with saved_model.pb)
    - Keras HDF5 (.h5 file with HDF5 magic bytes)
    - PyTorch ZIP (.pt/.pth file that's a ZIP)
    - Pickle (.pkl/.pickle or other files with pickle magic)
    - PyTorch binary (.bin files with various formats)
    - GGUF/GGML files with magic bytes
    - If extension indicates pickle/pt/h5/pb, etc.
    """
    file_path = Path(path)
    if file_path.is_dir():
        # We'll let the caller handle directory logic.
        # But we do a quick guess if there's a 'saved_model.pb'.
        if any(f.name == "saved_model.pb" for f in file_path.iterdir()):
            return "tensorflow_directory"
        return "directory"

    # Single file
    size = file_path.stat().st_size
    if size < 4:
        return "unknown"

    # Read first bytes for format detection using a single file handle
    with file_path.open("rb") as f:
        header = f.read(16)

    magic4 = header[:4]
    magic8 = header[:8]
    magic16 = header[:16]

    # Check first 8 bytes for HDF5 magic
    hdf5_magic = b"\x89HDF\r\n\x1a\n"
    if magic8 == hdf5_magic:
        return "hdf5"

    # Check for GGUF/GGML magic bytes
    if magic4 == b"GGUF":
        return "gguf"
    if magic4 in GGML_MAGIC_VARIANTS:
        return "ggml"

    ext = file_path.suffix.lower()

    # Check ZIP magic first (for .pt/.pth files that are actually zips)
    if magic4.startswith(b"PK"):
        return "zip"

    # Check pickle magic patterns
    pickle_magics = [
        b"\x80\x02",  # Protocol 2
        b"\x80\x03",  # Protocol 3
        b"\x80\x04",  # Protocol 4
        b"\x80\x05",  # Protocol 5
    ]
    if any(magic4.startswith(m) for m in pickle_magics):
        return "pickle"

    # For .bin files, do more sophisticated detection
    if ext == ".bin":
        # IMPORTANT: Check ZIP format first (PyTorch models saved with torch.save())
        if magic4.startswith(b"PK"):
            return "zip"
        # Check if it's a pickle file
        if any(magic4.startswith(m) for m in pickle_magics):
            return "pickle"
        # Check for safetensors format (starts with JSON header)
        if magic4[0:1] == b"{" or (size > 8 and b'"__metadata__"' in magic16):
            return "safetensors"

        # Check for ONNX format (protobuf)
        if magic4 == b"\x08\x01\x12\x00" or b"onnx" in magic16:
            return "onnx"

        # Otherwise, assume raw binary format (PyTorch weights)
        return "pytorch_binary"

    # Extension-based detection for non-.bin files
    # For .pt/.pth/.ckpt files, check if they're ZIP format first
    if ext in (".pt", ".pth", ".ckpt"):
        # These files can be either ZIP or pickle format
        if magic4.startswith(b"PK"):
            return "zip"
        # If not ZIP, assume pickle format
        return "pickle"
    if ext in (".ptl", ".pte"):
        if magic4.startswith(b"PK"):
            return "executorch"
        return "executorch"
    if ext in (".pkl", ".pickle", ".dill"):
        return "pickle"
    if ext == ".h5":
        return "hdf5"
    if ext == ".pb":
        return "protobuf"
    if ext == ".tflite":
        return "tflite"
    if ext == ".safetensors":
        return "safetensors"
    if ext in (".pdmodel", ".pdiparams"):
        return "paddle"
    if ext in (".msgpack", ".flax", ".orbax", ".jax"):
        return "flax_msgpack"
    if ext == ".onnx":
        return "onnx"
    ggml_exts = {".ggml", ".ggmf", ".ggjt", ".ggla", ".ggsa"}
    if ext in (".gguf", *ggml_exts):
        # Check magic bytes first for accuracy
        if magic4 == b"GGUF":
            return "gguf"
        if magic4 in GGML_MAGIC_VARIANTS:
            return "ggml"
        # Fall back to extension-based detection
        return "gguf" if ext == ".gguf" else "ggml"
    if ext == ".npy":
        return "numpy"
    if ext == ".npz":
        return "zip"
    if ext == ".joblib":
        if magic4.startswith(b"PK"):
            return "zip"
        return "pickle"
    if ext == ".mlmodel":
        return "coreml"
    if ext in (
        ".tar",
        ".tar.gz",
        ".tgz",
        ".tar.bz2",
        ".tbz2",
        ".tar.xz",
        ".txz",
    ):
        return "tar"

    return "unknown"


def find_sharded_files(directory: str) -> list[str]:
    """
    Look for sharded model files like:
    pytorch_model-00001-of-00002.bin
    """
    dir_path = Path(directory).resolve()
    return sorted(
        [
            str(fname.resolve())
            for fname in dir_path.iterdir()
            if fname.is_file() and re.match(r"pytorch_model-\d{5}-of-\d{5}\.bin", fname.name)
        ],
    )


EXTENSION_FORMAT_MAP = {
    ".pt": "pickle",
    ".pth": "pickle",
    ".ckpt": "pickle",
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".dill": "pickle",
    ".h5": "hdf5",
    ".hdf5": "hdf5",
    ".keras": "hdf5",
    ".pb": "protobuf",
    ".safetensors": "safetensors",
    ".onnx": "onnx",
    ".bin": "pytorch_binary",
    ".zip": "zip",
    ".gguf": "gguf",
    ".ggml": "ggml",
    ".ggmf": "ggml",
    ".ggjt": "ggml",
    ".ggla": "ggml",
    ".ggsa": "ggml",
    ".ptl": "executorch",
    ".pte": "executorch",
    ".tar": "tar",
    ".tar.gz": "tar",
    ".tgz": "tar",
    ".tar.bz2": "tar",
    ".tbz2": "tar",
    ".tar.xz": "tar",
    ".txz": "tar",
    ".npy": "numpy",
    ".npz": "zip",
    ".joblib": "pickle",  # joblib can be either zip or pickle format
    ".mlmodel": "coreml",
    ".pdmodel": "paddle",
    ".pdiparams": "paddle",
    ".engine": "tensorrt",
    ".plan": "tensorrt",
}


def detect_format_from_extension(path: str) -> str:
    """Return a format string based solely on the file extension."""
    file_path = Path(path)
    if file_path.is_dir():
        if (file_path / "saved_model.pb").exists():
            return "tensorflow_directory"
        return "directory"
    return EXTENSION_FORMAT_MAP.get(file_path.suffix.lower(), "unknown")


def validate_file_type(path: str) -> bool:
    """Validate that a file's magic bytes match its extension-based format."""
    try:
        header_format = detect_file_format_from_magic(path)
        ext_format = detect_format_from_extension(path)

        # If extension format is unknown, we can't validate - assume valid
        if ext_format == "unknown":
            return True

        # Small files (< 4 bytes) are always valid - can't determine magic bytes reliably
        file_path = Path(path)
        if file_path.is_file() and file_path.stat().st_size < 4:
            return True

        # Handle special cases where different formats are compatible first
        # before doing the unknown header check

        # Pickle files can be stored in various ways
        if ext_format == "pickle" and header_format in {"pickle", "zip"}:
            return True

        # PyTorch binary files are flexible in format
        if ext_format == "pytorch_binary" and header_format in {
            "pytorch_binary",
            "pickle",
            "zip",
            "unknown",  # .bin files can contain arbitrary binary data
        }:
            return True

        # TensorFlow protobuf files (.pb extension)
        if ext_format == "protobuf" and header_format in {"protobuf", "unknown"}:
            return True

        # ZIP files can have various extensions (.zip, .pt, .pth, .ckpt, .ptl, .pte)
        if header_format == "zip" and ext_format in {"zip", "pickle", "pytorch_binary", "executorch"}:
            return True

        # TAR files must match
        if ext_format == "tar" and header_format == "tar":
            return True

        # ExecuTorch files should be zip archives
        if ext_format == "executorch":
            return header_format == "zip"

        # HDF5 files should always match
        if ext_format == "hdf5":
            return header_format == "hdf5"

        # SafeTensors files should always match
        if ext_format == "safetensors":
            return header_format == "safetensors"

        # GGUF/GGML files should match their format
        if ext_format in {"gguf", "ggml"}:
            return header_format == ext_format

        # ONNX files (Protocol Buffer format - difficult to detect reliably)
        if ext_format == "onnx":
            return header_format in {"onnx", "unknown"}

        # NumPy files should match
        if ext_format == "numpy":
            return header_format == "numpy"

        # Flax msgpack files (less strict validation)
        if ext_format == "flax_msgpack":
            return True  # Hard to validate msgpack format reliably

        # TensorFlow directories are special case
        if ext_format == "tensorflow_directory":
            return header_format == "tensorflow_directory"

        # TensorFlow Lite files
        if ext_format == "tflite":
            return True  # TFLite format can be complex to validate

        if ext_format == "coreml":
            return True  # Core ML files are protobuf and lack clear magic bytes

        if ext_format == "tensorrt":
            return True  # TensorRT engine files have complex binary format

        # If header format is unknown but extension is known, this might be suspicious
        # unless the file is very small or empty (checked after format-specific rules)
        if header_format == "unknown":
            file_path = Path(path)
            return not (file_path.is_file() and file_path.stat().st_size >= 4)  # Small files are acceptable

        # Default: exact match required
        return header_format == ext_format

    except Exception:
        # If validation fails due to error, assume valid to avoid breaking scans
        return True
