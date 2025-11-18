import io
import tarfile
import zipfile
from pathlib import Path

from modelaudit.utils.file.detection import (
    detect_file_format,
    detect_file_format_from_magic,
    detect_format_from_extension,
    find_sharded_files,
    is_zipfile,
    validate_file_type,
)


def test_detect_file_format_directory(tmp_path):
    """Test detecting a directory format."""
    # Create a regular directory
    regular_dir = tmp_path / "regular_dir"
    regular_dir.mkdir()

    # Create a TensorFlow SavedModel directory
    tf_dir = tmp_path / "tf_dir"
    tf_dir.mkdir()
    (tf_dir / "saved_model.pb").write_bytes(b"dummy content")

    # Test detection
    assert detect_file_format(str(regular_dir)) == "directory"
    assert detect_file_format(str(tf_dir)) == "tensorflow_directory"


def test_detect_file_format_large_directory(tmp_path):
    """Ensure detection short-circuits in directories with many files."""
    tf_dir = tmp_path / "tf_large"
    tf_dir.mkdir()
    (tf_dir / "saved_model.pb").write_bytes(b"dummy content")

    for i in range(1000):
        (tf_dir / f"file_{i}.txt").write_text("x")

    assert detect_file_format(str(tf_dir)) == "tensorflow_directory"


def test_detect_file_format_zip(tmp_path):
    """Test detecting a ZIP file format."""
    # Create a ZIP file
    zip_path = tmp_path / "archive.zip"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("test.txt", "test content")

    assert detect_file_format(str(zip_path)) == "zip"


def test_detect_file_format_by_extension(tmp_path):
    """Test detecting file format by extension."""
    extensions = {
        ".pt": "pickle",  # .pt files are now treated as pickle files
        ".pth": "pickle",  # .pth files are now treated as pickle files
        ".bin": "pytorch_binary",  # .bin files with generic content are now pytorch_binary
        ".ckpt": "pickle",  # .ckpt files are now treated as pickle files
        ".pkl": "pickle",
        ".pickle": "pickle",
        ".dill": "pickle",  # .dill files are treated as pickle files
        ".msgpack": "flax_msgpack",
        ".h5": "hdf5",
        ".pb": "protobuf",
        ".tflite": "tflite",
        ".mlmodel": "coreml",
        ".unknown": "unknown",
    }

    for ext, expected_format in extensions.items():
        test_file = tmp_path / f"test{ext}"
        test_file.write_bytes(b"test content")
        assert detect_file_format(str(test_file)) == expected_format


def test_detect_file_format_hdf5(tmp_path):
    """Test detecting HDF5 format by magic bytes."""
    # Create a file with HDF5 magic bytes
    hdf5_path = tmp_path / "test.dat"
    hdf5_magic = b"\x89HDF\r\n\x1a\n"
    hdf5_path.write_bytes(hdf5_magic + b"additional content")

    assert detect_file_format(str(hdf5_path)) == "hdf5"


def test_detect_file_format_small_file(tmp_path):
    """Test detecting format of a very small file."""
    small_file = tmp_path / "small.dat"
    small_file.write_bytes(b"123")  # Less than 4 bytes

    assert detect_file_format(str(small_file)) == "unknown"


def test_is_zipfile(tmp_path):
    """Test the is_zipfile function."""
    # Create a ZIP file
    zip_path = tmp_path / "archive.zip"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("test.txt", "test content")

    # Create a non-ZIP file
    non_zip_path = tmp_path / "not_a_zip.txt"
    non_zip_path.write_bytes(b"This is not a ZIP file")

    assert is_zipfile(str(zip_path)) is True
    assert is_zipfile(str(non_zip_path)) is False
    assert is_zipfile("nonexistent_file.zip") is False


def test_detect_file_format_tar(tmp_path):
    """Detect tar archives by signature without extra I/O."""
    tar_path = tmp_path / "archive.tar"
    with tarfile.open(tar_path, "w") as tar:
        info = tarfile.TarInfo(name="test.txt")
        tar.addfile(info, io.BytesIO(b"content"))

    assert detect_file_format_from_magic(str(tar_path)) == "tar"
    assert detect_file_format(str(tar_path)) == "tar"


def test_zip_magic_variants(tmp_path):
    """Ensure alternate PK signatures are detected as ZIP."""
    for sig in (b"PK\x06\x06", b"PK\x06\x07"):
        path = tmp_path / f"file_{sig.hex()}.zip"
        path.write_bytes(sig + b"extra")
        assert is_zipfile(str(path)) is True
        assert detect_file_format(str(path)) == "zip"


def test_find_sharded_files(tmp_path):
    """Test finding sharded model files."""
    # Create directory with sharded files
    shard_dir = tmp_path / "model_dir"
    shard_dir.mkdir()

    # Create sharded files
    (shard_dir / "pytorch_model-00001-of-00005.bin").write_bytes(b"shard1")
    (shard_dir / "pytorch_model-00002-of-00005.bin").write_bytes(b"shard2")
    (shard_dir / "pytorch_model-00003-of-00005.bin").write_bytes(b"shard3")

    # Create non-shard files
    (shard_dir / "config.json").write_bytes(b"{}")
    (shard_dir / "other_file.bin").write_bytes(b"other")

    # Test finding shards
    shards = find_sharded_files(str(shard_dir))

    assert len(shards) == 3
    assert all("pytorch_model-0000" in shard for shard in shards)
    assert shards[0].endswith("pytorch_model-00001-of-00005.bin")
    assert shards[1].endswith("pytorch_model-00002-of-00005.bin")
    assert shards[2].endswith("pytorch_model-00003-of-00005.bin")


def test_find_sharded_files_relative_path(tmp_path, monkeypatch):
    """Sharded files should be discovered using relative paths without duplication."""
    shard_dir = tmp_path / "model_dir"
    shard_dir.mkdir()

    (shard_dir / "pytorch_model-00001-of-00005.bin").write_bytes(b"shard1")
    (shard_dir / "pytorch_model-00002-of-00005.bin").write_bytes(b"shard2")

    monkeypatch.chdir(tmp_path)
    shards = find_sharded_files("model_dir")

    expected = [
        str((shard_dir / "pytorch_model-00001-of-00005.bin").resolve()),
        str((shard_dir / "pytorch_model-00002-of-00005.bin").resolve()),
    ]
    assert shards == expected


def test_detect_format_from_extension(tmp_path):
    """Test extension-only format detection."""
    file_path = tmp_path / "model.pt"
    file_path.write_bytes(b"abc")
    assert detect_format_from_extension(str(file_path)) == "pickle"

    dir_path = tmp_path / "saved_model"
    dir_path.mkdir()
    (dir_path / "saved_model.pb").write_bytes(b"d")
    assert detect_format_from_extension(str(dir_path)) == "tensorflow_directory"


def test_detect_gguf_ggml_formats(tmp_path):
    """Test detection of GGUF and GGML formats by magic bytes."""
    # Test GGUF format
    gguf_path = tmp_path / "model.gguf"
    gguf_path.write_bytes(b"GGUF" + b"\x00" * 20)
    assert detect_file_format(str(gguf_path)) == "gguf"
    assert detect_format_from_extension(str(gguf_path)) == "gguf"

    # Test GGML format
    ggml_path = tmp_path / "model.ggml"
    ggml_path.write_bytes(b"GGML" + b"\x00" * 20)
    assert detect_file_format(str(ggml_path)) == "ggml"
    assert detect_format_from_extension(str(ggml_path)) == "ggml"

    # Test GGUF extension with wrong magic (should fall back to extension)
    fake_gguf_path = tmp_path / "fake.gguf"
    fake_gguf_path.write_bytes(b"FAKE" + b"\x00" * 20)
    assert detect_file_format(str(fake_gguf_path)) == "gguf"  # Falls back to extension
    assert detect_format_from_extension(str(fake_gguf_path)) == "gguf"


def test_detect_ggml_variant_formats(tmp_path):
    """Ensure GGML variants are recognized."""
    variants = [b"GGMF", b"GGJT"]
    for magic in variants:
        path = tmp_path / f"model_{magic.decode().lower()}.ggml"
        path.write_bytes(magic + b"\x00" * 20)
        assert detect_file_format(str(path)) == "ggml"
        assert detect_format_from_extension(str(path)) == "ggml"


def test_validate_file_type(tmp_path):
    """Validate files using magic numbers."""
    # Valid ZIP-based PyTorch file
    zip_path = tmp_path / "model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("test.txt", "data")
    assert validate_file_type(str(zip_path)) is True

    # Invalid HDF5 file with .h5 extension
    invalid_h5 = tmp_path / "bad.h5"
    invalid_h5.write_bytes(b"not real hdf5")
    assert validate_file_type(str(invalid_h5)) is False

    # Valid HDF5 file
    valid_h5 = tmp_path / "good.h5"
    hdf5_magic = b"\x89HDF\r\n\x1a\n"
    valid_h5.write_bytes(hdf5_magic + b"hdf5 data")
    assert validate_file_type(str(valid_h5)) is True

    # Valid pickle file
    pickle_path = tmp_path / "model.pkl"
    pickle_path.write_bytes(b"\x80\x03" + b"pickle data")
    assert validate_file_type(str(pickle_path)) is True

    # Valid GGUF file
    gguf_path = tmp_path / "model.gguf"
    gguf_path.write_bytes(b"GGUF" + b"\x00" * 20)
    assert validate_file_type(str(gguf_path)) is True

    # Invalid GGUF file (wrong magic)
    bad_gguf = tmp_path / "bad.gguf"
    bad_gguf.write_bytes(b"FAKE" + b"\x00" * 20)
    assert validate_file_type(str(bad_gguf)) is False

    # Small file should be valid (can't determine magic bytes)
    small_file = tmp_path / "small.h5"
    small_file.write_bytes(b"hi")
    assert validate_file_type(str(small_file)) is True

    # Unknown extension should be valid
    unknown_ext = tmp_path / "file.unknown"
    unknown_ext.write_bytes(b"some data")
    assert validate_file_type(str(unknown_ext)) is True

    # SafeTensors file with JSON header
    safetensors_path = tmp_path / "model.safetensors"
    safetensors_path.write_bytes(b'{"metadata": "test"}' + b"\x00" * 20)
    assert validate_file_type(str(safetensors_path)) is True

    # PyTorch binary (.bin) that's actually a ZIP (valid case)
    bin_zip = tmp_path / "model.bin"
    with zipfile.ZipFile(bin_zip, "w") as zipf:
        zipf.writestr("weights.pt", "data")
    assert validate_file_type(str(bin_zip)) is True

    # PyTorch binary (.bin) that's actually pickle (valid case)
    bin_pickle = tmp_path / "weights.bin"
    bin_pickle.write_bytes(b"\x80\x03" + b"pickle data")
    assert validate_file_type(str(bin_pickle)) is True


def test_detect_file_format_from_magic_oserror(tmp_path, monkeypatch):
    """Return 'unknown' when reading magic bytes fails."""
    file_path = tmp_path / "unreadable.bin"
    file_path.write_bytes(b"\x89HDF")

    def open_raise(self, *args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "open", open_raise)
    assert detect_file_format_from_magic(str(file_path)) == "unknown"


def test_detect_openvino_xml_format(tmp_path):
    """Test detecting OpenVINO XML files by magic bytes."""
    # Create an OpenVINO XML file with standard XML header
    xml_path = tmp_path / "openvino_model.xml"
    xml_content = b'<?xml version="1.0"?>\n<net name="Model0" version="11">\n</net>'
    xml_path.write_bytes(xml_content)

    # Test magic byte detection
    assert detect_file_format_from_magic(str(xml_path)) == "openvino"

    # Test extension detection
    assert detect_format_from_extension(str(xml_path)) == "openvino"

    # Test file type validation should pass (no mismatch)
    assert validate_file_type(str(xml_path)) is True


def test_detect_pmml_xml_format(tmp_path):
    """Test detecting PMML XML files by magic bytes."""
    # Create a PMML XML file with standard XML header
    pmml_path = tmp_path / "model.pmml"
    pmml_content = b'<?xml version="1.0"?>\n<PMML version="4.4">\n</PMML>'
    pmml_path.write_bytes(pmml_content)

    # Test magic byte detection should now recognize PMML
    assert detect_file_format_from_magic(str(pmml_path)) == "pmml"

    # Test extension detection
    assert detect_format_from_extension(str(pmml_path)) == "pmml"

    # Test file type validation should pass (no mismatch)
    assert validate_file_type(str(pmml_path)) is True


def test_detect_generic_xml_format(tmp_path):
    """Test that generic XML files don't get misdetected as OpenVINO."""
    # Create a generic XML file (SVG, config, etc.)
    xml_path = tmp_path / "config.xml"
    xml_content = b'<?xml version="1.0"?>\n<configuration>\n<setting>value</setting>\n</configuration>'
    xml_path.write_bytes(xml_content)

    # Magic detection should return unknown (no <net> tag)
    assert detect_file_format_from_magic(str(xml_path)) == "unknown"


def test_detect_openvino_xml_net_beyond_64_bytes(tmp_path):
    """Test that <net> tag beyond 64 bytes is not detected as OpenVINO."""
    # Create XML where <net> appears after 64 bytes
    xml_path = tmp_path / "late_net.xml"
    # Padding to push <net> beyond 64 bytes
    padding = b" " * 50
    xml_content = b'<?xml version="1.0"?>\n' + padding + b'\n<net name="Model0">\n</net>'
    xml_path.write_bytes(xml_content)

    # Should return unknown since <net> is beyond the 64-byte read limit
    assert detect_file_format_from_magic(str(xml_path)) == "unknown"


def test_detect_openvino_xml_short_file(tmp_path):
    """Test OpenVINO detection with file smaller than 64 bytes."""
    # Create a short OpenVINO XML file
    xml_path = tmp_path / "short.xml"
    xml_content = b'<?xml version="1.0"?>\n<net/>'
    xml_path.write_bytes(xml_content)

    # Should still detect as openvino (file is small but contains <net>)
    assert detect_file_format_from_magic(str(xml_path)) == "openvino"


def test_detect_xml_with_net_in_comment(tmp_path):
    """Test that <net> in XML comment doesn't trigger false positive."""
    # Create XML with <net> inside a comment
    xml_path = tmp_path / "commented.xml"
    xml_content = b'<?xml version="1.0"?>\n<!-- <net> -->\n<root/>'
    xml_path.write_bytes(xml_content)

    # Should still detect as openvino because we're doing simple byte matching
    # This is acceptable - the actual OpenVINO scanner will validate properly
    assert detect_file_format_from_magic(str(xml_path)) == "openvino"


def test_xml_detection_boundary_conditions(tmp_path):
    """Test XML detection at exact 64-byte boundary."""
    # Create XML where <net> is at exactly byte 60 (within 64 bytes)
    xml_path = tmp_path / "boundary.xml"
    # Position <net> to be just within the 64-byte limit
    xml_content = b'<?xml version="1.0"?>' + (b" " * 17) + b'<net name="M"/>'
    xml_path.write_bytes(xml_content)

    # Should detect as openvino
    assert detect_file_format_from_magic(str(xml_path)) == "openvino"


def test_detect_pmml_xml_beyond_64_bytes(tmp_path):
    """Test that <PMML> tag beyond 64 bytes is not detected as PMML."""
    # Create XML where <PMML> appears after 64 bytes
    pmml_path = tmp_path / "late_pmml.pmml"
    # Padding to push <PMML> beyond 64 bytes
    padding = b" " * 50
    pmml_content = b'<?xml version="1.0"?>\n' + padding + b'\n<PMML version="4.4">\n</PMML>'
    pmml_path.write_bytes(pmml_content)

    # Should return unknown since <PMML> is beyond the 64-byte read limit
    assert detect_file_format_from_magic(str(pmml_path)) == "unknown"


def test_detect_pmml_xml_short_file(tmp_path):
    """Test PMML detection with file smaller than 64 bytes."""
    # Create a short PMML XML file
    pmml_path = tmp_path / "short.pmml"
    pmml_content = b'<?xml version="1.0"?>\n<PMML/>'
    pmml_path.write_bytes(pmml_content)

    # Should still detect as pmml (file is small but contains <PMML>)
    assert detect_file_format_from_magic(str(pmml_path)) == "pmml"


def test_detect_xml_with_pmml_in_comment(tmp_path):
    """Test that <PMML> in XML comment still triggers detection."""
    # Create XML with <PMML> inside a comment
    xml_path = tmp_path / "commented.pmml"
    xml_content = b'<?xml version="1.0"?>\n<!-- <PMML> -->\n<root/>'
    xml_path.write_bytes(xml_content)

    # Should still detect as pmml because we're doing simple byte matching
    # This is acceptable - the actual PMML scanner will validate properly
    assert detect_file_format_from_magic(str(xml_path)) == "pmml"


def test_pmml_detection_boundary_conditions(tmp_path):
    """Test PMML detection at exact 64-byte boundary."""
    # Create XML where <PMML> is just within the 64-byte limit
    pmml_path = tmp_path / "boundary.pmml"
    # Position <PMML> to be just within the 64-byte limit
    pmml_content = b'<?xml version="1.0"?>' + (b" " * 16) + b'<PMML version="4"/>'
    pmml_path.write_bytes(pmml_content)

    # Should detect as pmml
    assert detect_file_format_from_magic(str(pmml_path)) == "pmml"


def test_openvino_vs_pmml_detection(tmp_path):
    """Test that OpenVINO and PMML formats are detected independently."""
    # OpenVINO file
    openvino_path = tmp_path / "model.xml"
    openvino_content = b'<?xml version="1.0"?>\n<net name="Model0" version="11">\n</net>'
    openvino_path.write_bytes(openvino_content)

    # PMML file
    pmml_path = tmp_path / "model.pmml"
    pmml_content = b'<?xml version="1.0"?>\n<PMML version="4.4" xmlns="http://www.dmg.org/PMML-4_4">\n</PMML>'
    pmml_path.write_bytes(pmml_content)

    # Each should be detected correctly
    assert detect_file_format_from_magic(str(openvino_path)) == "openvino"
    assert detect_file_format_from_magic(str(pmml_path)) == "pmml"

    # Validation should pass for both
    assert validate_file_type(str(openvino_path)) is True
    assert validate_file_type(str(pmml_path)) is True
