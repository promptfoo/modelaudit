import zipfile

from modelaudit.utils.filetype import detect_file_format, find_sharded_files, is_zipfile


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
