"""Tests for the metadata extractor functionality."""

import json
import os
import pickle
import pickletools
import struct
import tempfile
from pathlib import Path

import pytest

from modelaudit.metadata_extractor import ModelMetadataExtractor


class TestModelMetadataExtractor:
    """Test the ModelMetadataExtractor class."""

    def test_extract_metadata_unknown_format(self):
        """Test metadata extraction with unknown file format."""
        extractor = ModelMetadataExtractor()

        with tempfile.NamedTemporaryFile(suffix=".unknown") as tmp:
            tmp.write(b"some random data")
            tmp.flush()

            metadata = extractor.extract(tmp.name)

            assert metadata["format"] == "unknown"
            assert "error" in metadata
            assert metadata["file"] == Path(tmp.name).name

    def test_extract_metadata_basic(self, tmp_path):
        """Test basic metadata extraction functionality."""
        extractor = ModelMetadataExtractor()

        # Create a simple safetensors file
        header = {"tensor1": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}
        header_json = json.dumps(header).encode("utf-8")
        header_len = len(header_json)

        st_file = tmp_path / "model.safetensors"
        with open(st_file, "wb") as f:
            f.write(struct.pack("<Q", header_len))
            f.write(header_json)
            f.write(b"\x00" * 16)  # Dummy tensor data

        metadata = extractor.extract(str(st_file))

        assert metadata["format"] == "safetensors"
        assert metadata["file_size"] > 0
        assert metadata["tensor_count"] == 1
        assert metadata["total_parameters"] == 4
        assert "tensors" in metadata

    def test_extract_directory_metadata(self):
        """Test directory metadata extraction."""
        extractor = ModelMetadataExtractor()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple test files
            safetensors_file = os.path.join(tmpdir, "model.safetensors")
            pkl_file = os.path.join(tmpdir, "model.pkl")

            # Create safetensors file
            header = {"test": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}
            header_json = json.dumps(header).encode("utf-8")
            with open(safetensors_file, "wb") as f:
                f.write(struct.pack("<Q", len(header_json)))
                f.write(header_json)
                f.write(b"\x00\x00\x00\x00")

            # Create pickle file (empty for simplicity)
            with open(pkl_file, "wb") as f:
                import pickle

                pickle.dump({"test": "data"}, f)

            metadata = extractor.extract(tmpdir)

            assert "directory" in metadata
            assert metadata["directory"] == tmpdir
            assert metadata["summary"]["total_files"] >= 2
            assert "safetensors" in metadata["summary"]["formats"]
            assert "pickle" in metadata["summary"]["formats"]

    def test_security_only_filter(self, tmp_path):
        """Test security-only metadata filtering."""
        extractor = ModelMetadataExtractor()

        header = {
            "tensor1": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
            "__metadata__": {"framework": "test", "version": "1.0"},
        }
        header_json = json.dumps(header).encode("utf-8")

        st_file = tmp_path / "model.safetensors"
        with open(st_file, "wb") as f:
            f.write(struct.pack("<Q", len(header_json)))
            f.write(header_json)
            f.write(b"\x00\x00\x00\x00")

        # Test with security_only=True
        metadata = extractor.extract(str(st_file), security_only=True)

        # Should contain basic info
        assert "file" in metadata
        assert "format" in metadata
        assert "file_size" in metadata

        # Should contain custom metadata (potentially security relevant)
        if "custom_metadata" in metadata:
            assert metadata["custom_metadata"]["framework"] == "test"

    def test_format_table_single_file(self):
        """Test table formatting for single file."""
        from modelaudit.cli import _format_metadata_table

        metadata = {
            "file": "test.safetensors",
            "format": "safetensors",
            "file_size": 1024,
            "tensor_count": 2,
            "custom_metadata": {"framework": "pytorch"},
        }

        output = _format_metadata_table(metadata)

        assert "File: test.safetensors" in output
        assert "Format: safetensors" in output
        assert "Size: 1,024 bytes" in output
        assert "Tensor Count: 2" in output
        assert "framework: pytorch" in output

    def test_format_table_directory(self):
        """Test table formatting for directory."""
        from modelaudit.cli import _format_metadata_table

        metadata = {
            "directory": "/test/path",
            "summary": {"total_files": 3, "formats": {"safetensors": 2, "pickle": 1}},
            "files": [
                {"file": "model1.safetensors", "format": "safetensors"},
                {"file": "model2.pkl", "format": "pickle"},
            ],
        }

        output = _format_metadata_table(metadata)

        assert "Directory: /test/path" in output
        assert "Total Files: 3" in output
        assert "safetensors: 2" in output
        assert "pickle: 1" in output
        assert "model1.safetensors (safetensors)" in output
        assert "model2.pkl (pickle)" in output

    def test_pickle_metadata_no_deserialization(self, monkeypatch, tmp_path):
        """Ensure pickle metadata extraction does not deserialize by default."""
        extractor = ModelMetadataExtractor()

        import pickle

        pkl_file = tmp_path / "test.pkl"
        with open(pkl_file, "wb") as f:
            pickle.dump({"a": 1}, f)

        import pickle as std_pickle

        def fail_load(*_args, **_kwargs):
            raise AssertionError("pickle.load should not be called during metadata extraction")

        monkeypatch.setattr(std_pickle, "load", fail_load, raising=True)

        metadata = extractor.extract(str(pkl_file))

        assert metadata.get("deserialization_skipped") is True
        assert metadata.get("safe_loading") is False

    def test_joblib_metadata_no_deserialization(self, monkeypatch, tmp_path):
        """Ensure joblib metadata extraction does not deserialize by default."""
        joblib_mod = pytest.importorskip("joblib")
        extractor = ModelMetadataExtractor()

        joblib_file = tmp_path / "model.joblib"
        joblib_mod.dump({"x": 1}, joblib_file)

        def fail_load(*_args, **_kwargs):
            raise AssertionError("joblib.load should not be called during metadata extraction")

        monkeypatch.setattr(joblib_mod, "load", fail_load, raising=True)

        metadata = extractor.extract(str(joblib_file))

        assert metadata.get("deserialization_skipped") is True
        assert metadata.get("reason") == "Deserialization disabled for metadata extraction"

    def test_tf_savedmodel_metadata_no_deserialization(self, tmp_path):
        """Ensure TensorFlow SavedModel metadata extraction does not deserialize by default."""
        try:
            import tensorflow as tf

            # Verify that tf.saved_model.load is actually importable
            _ = tf.saved_model.load
        except (ImportError, AttributeError):
            pytest.skip("TensorFlow with saved_model.load not available")

        extractor = ModelMetadataExtractor()

        saved_model_dir = tmp_path / "saved_model"
        saved_model_dir.mkdir()
        (saved_model_dir / "saved_model.pb").write_bytes(b"")  # Minimal placeholder

        metadata = extractor.extract(str(saved_model_dir))

        assert metadata.get("deserialization_skipped") is True
        assert metadata.get("reason") == "Deserialization disabled for metadata extraction"

    def test_numpy_metadata_no_deserialization(self, tmp_path):
        """Ensure NumPy metadata extraction uses allow_pickle=False by default."""
        np = pytest.importorskip("numpy")
        extractor = ModelMetadataExtractor()

        # Create a simple numeric .npy file
        arr = np.array([1.0, 2.0, 3.0], dtype=np.float32)
        npy_file = tmp_path / "test.npy"
        np.save(str(npy_file), arr)

        metadata = extractor.extract(str(npy_file))

        # Numeric arrays should extract fine without pickle
        assert metadata["format"] == "numpy"
        assert metadata.get("array_shape") == [3]
        assert metadata.get("array_dtype") == "float32"
        assert metadata.get("deserialization_skipped") is not True

    def test_numpy_object_array_blocked_without_deserialization(self, tmp_path):
        """Ensure NumPy object arrays are blocked by default (require pickle)."""
        np = pytest.importorskip("numpy")
        extractor = ModelMetadataExtractor()

        # Create an object-dtype .npy file that requires pickle to load
        obj_arr = np.array([{"a": 1}, {"b": 2}], dtype=object)
        npy_file = tmp_path / "object_array.npy"
        np.save(str(npy_file), obj_arr, allow_pickle=True)

        metadata = extractor.extract(str(npy_file))

        # Should be blocked: object arrays require allow_pickle=True
        assert metadata.get("deserialization_skipped") is True
        assert "pickle" in metadata.get("reason", "").lower()

    def test_numpy_object_array_allowed_with_deserialization(self, tmp_path):
        """Ensure NumPy object arrays load when deserialization is explicitly allowed."""
        np = pytest.importorskip("numpy")
        extractor = ModelMetadataExtractor()

        obj_arr = np.array([{"a": 1}, {"b": 2}], dtype=object)
        npy_file = tmp_path / "object_array.npy"
        np.save(str(npy_file), obj_arr, allow_pickle=True)

        metadata = extractor.extract(str(npy_file), allow_deserialization=True)

        # With deserialization allowed, should extract metadata
        assert metadata.get("deserialization_skipped") is not True
        assert metadata.get("array_dtype") == "object"
        assert metadata.get("contains_objects") is True

    def test_xgboost_metadata_no_deserialization(self, tmp_path):
        """Ensure XGBoost metadata extraction is blocked without deserialization flag."""
        pytest.importorskip("xgboost")
        extractor = ModelMetadataExtractor()

        # Create a minimal XGBoost JSON model
        xgb_model = {
            "version": [2, 0, 3],
            "learner": {"learner_model_param": {"num_features": "10"}},
        }
        model_file = tmp_path / "model.json"
        model_file.write_text(json.dumps(xgb_model))

        metadata = extractor.extract(str(model_file))

        # XGBoost extract_metadata should skip deserialization by default
        assert metadata.get("deserialization_skipped") is True
        assert metadata.get("reason") == "Deserialization disabled for metadata extraction"

    def test_metadata_extractor_setdefault_preserves_scanner_values(self, tmp_path):
        """Ensure scanner metadata isn't overwritten by extractor's setdefault calls."""
        extractor = ModelMetadataExtractor()

        # Create a safetensors file - the scanner sets format to "safetensors"
        header = {"t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}
        header_json = json.dumps(header).encode("utf-8")

        st_file = tmp_path / "model.safetensors"
        with open(st_file, "wb") as f:
            f.write(struct.pack("<Q", len(header_json)))
            f.write(header_json)
            f.write(b"\x00\x00\x00\x00")

        metadata = extractor.extract(str(st_file))

        # Scanner-provided values must not be overwritten
        assert metadata["format"] == "safetensors"
        assert metadata["file"] == "model.safetensors"
        assert metadata["path"] == str(st_file)

    def test_security_only_includes_deserialization_keys(self):
        """Ensure security filter preserves deserialization-related keys."""
        extractor = ModelMetadataExtractor()

        metadata = {
            "file": "test.pkl",
            "format": "pickle",
            "file_size": 100,
            "deserialization_skipped": True,
            "reason": "Deserialization disabled for metadata extraction",
            "dangerous_opcodes": ["REDUCE"],
            "has_dangerous_opcodes": True,
            "training_epochs": 50,
            "learning_rate": 0.001,
        }

        filtered = extractor._filter_security_metadata(metadata)

        assert filtered["deserialization_skipped"] is True
        assert filtered["reason"] == "Deserialization disabled for metadata extraction"
        assert filtered["dangerous_opcodes"] == ["REDUCE"]
        assert filtered["has_dangerous_opcodes"] is True
        # Non-security keys should be filtered out
        assert "training_epochs" not in filtered
        assert "learning_rate" not in filtered

    def test_extract_metadata_handles_scanner_exception(self, tmp_path, monkeypatch):
        """Ensure metadata extraction gracefully handles scanner exceptions."""
        extractor = ModelMetadataExtractor()

        # Create a safetensors file
        header = {"t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}
        header_json = json.dumps(header).encode("utf-8")

        st_file = tmp_path / "broken.safetensors"
        with open(st_file, "wb") as f:
            f.write(struct.pack("<Q", len(header_json)))
            f.write(header_json)
            f.write(b"\x00\x00\x00\x00")

        # Monkey-patch the scanner's extract_metadata to raise
        from modelaudit.scanners.safetensors_scanner import SafeTensorsScanner

        original = SafeTensorsScanner.extract_metadata

        def broken_extract(self, file_path):
            raise RuntimeError("Simulated extraction failure")

        monkeypatch.setattr(SafeTensorsScanner, "extract_metadata", broken_extract)

        metadata = extractor.extract(str(st_file))

        # Should gracefully return error info, not crash
        assert "extraction_error" in metadata
        assert "Simulated extraction failure" in metadata["extraction_error"]
        assert metadata["file"] == "broken.safetensors"
        assert metadata["format"] == "safetensors"


class TestPickleDangerousOpcodes:
    """Test that pickle scanner detects NEWOBJ_EX and BUILD opcodes."""

    def test_pickle_detects_build_opcode(self, tmp_path):
        """Ensure BUILD opcode is detected as dangerous."""
        from modelaudit.scanners.pickle_scanner import PickleScanner

        # Manually construct a pickle stream that contains BUILD opcode.
        # This creates: GLOBAL 'collections' 'OrderedDict' -> EMPTY_DICT -> BUILD -> STOP
        # Protocol 2 with BUILD (opcode 'b')
        pkl_data = (
            b"\x80\x02"  # PROTO 2
            b"c"  # GLOBAL
            b"collections\nOrderedDict\n"
            b")"  # EMPTY_TUPLE
            b"\x81"  # NEWOBJ
            b"}"  # EMPTY_DICT
            b"b"  # BUILD
            b"."  # STOP
        )

        pkl_file = tmp_path / "with_build.pkl"
        pkl_file.write_bytes(pkl_data)

        # Verify BUILD is in the pickle stream
        opcodes = list(pickletools.genops(pkl_data))
        opcode_names = [op[0].name for op in opcodes]
        assert "BUILD" in opcode_names

        scanner = PickleScanner({})
        metadata = scanner.extract_metadata(str(pkl_file))

        assert "BUILD" in metadata.get("dangerous_opcodes", [])
        assert metadata.get("has_dangerous_opcodes") is True

    def test_pickle_metadata_reports_reduce(self, tmp_path):
        """Ensure REDUCE opcode is reported as dangerous in metadata."""
        from modelaudit.scanners.pickle_scanner import PickleScanner

        # __reduce__ triggers REDUCE opcode
        class ReduceClass:
            def __reduce__(self):
                return (list, ([1, 2, 3],))

        pkl_file = tmp_path / "with_reduce.pkl"
        with open(pkl_file, "wb") as f:
            pickle.dump(ReduceClass(), f)

        scanner = PickleScanner({})
        metadata = scanner.extract_metadata(str(pkl_file))

        assert "REDUCE" in metadata.get("dangerous_opcodes", [])
        assert metadata.get("has_dangerous_opcodes") is True

    def test_pickle_safe_data_no_dangerous_opcodes(self, tmp_path):
        """Ensure simple data structures don't trigger dangerous opcode detection."""
        from modelaudit.scanners.pickle_scanner import PickleScanner

        simple_data = {"key": "value", "numbers": [1, 2, 3]}
        pkl_file = tmp_path / "safe.pkl"
        with open(pkl_file, "wb") as f:
            pickle.dump(simple_data, f, protocol=0)  # Protocol 0 for simplest opcodes

        scanner = PickleScanner({})
        metadata = scanner.extract_metadata(str(pkl_file))

        # Simple dict shouldn't have dangerous opcodes
        dangerous = metadata.get("dangerous_opcodes", [])
        # Filter out BUILD/GLOBAL which may appear even for simple data in higher protocols
        truly_dangerous = [op for op in dangerous if op in ("REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX")]
        assert len(truly_dangerous) == 0


class TestCLIMetadataCommand:
    """Test the CLI metadata command integration."""

    def test_cli_metadata_json_output(self, tmp_path):
        """Test CLI metadata command with JSON output."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        # Create a safetensors file
        header = {"t": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}
        header_json = json.dumps(header).encode("utf-8")

        st_file = tmp_path / "test.safetensors"
        with open(st_file, "wb") as f:
            f.write(struct.pack("<Q", len(header_json)))
            f.write(header_json)
            f.write(b"\x00" * 8)

        runner = CliRunner()
        result = runner.invoke(cli, ["metadata", str(st_file), "--format", "json"])

        assert result.exit_code == 0
        output = json.loads(result.output)
        assert output["format"] == "safetensors"
        assert output["file_size"] > 0

    def test_cli_metadata_security_only(self, tmp_path):
        """Test CLI metadata command with security-only flag."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        header = {"t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}
        header_json = json.dumps(header).encode("utf-8")

        st_file = tmp_path / "model.safetensors"
        with open(st_file, "wb") as f:
            f.write(struct.pack("<Q", len(header_json)))
            f.write(header_json)
            f.write(b"\x00\x00\x00\x00")

        runner = CliRunner()
        result = runner.invoke(cli, ["metadata", str(st_file), "--format", "json", "--security-only"])

        assert result.exit_code == 0
        output = json.loads(result.output)
        assert "file" in output
        assert "format" in output

    def test_cli_metadata_table_output(self, tmp_path):
        """Test CLI metadata command with default table output."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        header = {"t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}
        header_json = json.dumps(header).encode("utf-8")

        st_file = tmp_path / "model.safetensors"
        with open(st_file, "wb") as f:
            f.write(struct.pack("<Q", len(header_json)))
            f.write(header_json)
            f.write(b"\x00\x00\x00\x00")

        runner = CliRunner()
        result = runner.invoke(cli, ["metadata", str(st_file)])

        assert result.exit_code == 0
        assert "Format: safetensors" in result.output
