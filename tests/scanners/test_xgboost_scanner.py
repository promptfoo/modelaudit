"""
Tests for XGBoost model scanner

Tests cover various XGBoost model formats and security vulnerabilities:
- JSON models with valid/invalid schemas
- UBJ (Universal Binary JSON) models
- Binary .bst models with integrity checks
- Malicious content detection in all formats
- Integration with pickle scanner for .pkl/.joblib files
"""

import copy
import gzip
import io
import json
import os
import pickle
import struct
import subprocess as real_subprocess
import tarfile
import tempfile
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, cast
from unittest.mock import ANY, Mock, patch

import pytest
from click.testing import CliRunner

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cli import cli
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file, scan_model_streaming
from modelaudit.models import ModelAuditResultModel
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.tar_scanner import TarScanner
from modelaudit.scanners.xgboost_scanner import XGBOOST_JSON_ROUTING_CHUNK_BYTES, XGBoostScanner
from modelaudit.scanners.zip_scanner import ZipScanner
from modelaudit.utils.file import detection as file_detection
from modelaudit.utils.file.detection import (
    detect_file_format,
    detect_file_format_for_skip_filter,
    detect_file_format_from_magic,
)
from modelaudit.utils.helpers.file_iterator import iterate_files_streaming
from tests.cli_output import parse_click_json_output


class FakeBooster:
    """A simple class that can be pickled for testing."""

    def __init__(self):
        self.__class__.__name__ = "Booster"


@pytest.fixture
def temp_dir() -> Iterator[Path]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def _headerless_legacy_binary_header() -> bytes:
    """Create the older pre-`binf` learner header used by legacy XGBoost binaries."""
    return struct.pack("<fIiiiII27i", 0.5, 4, 0, 1, 0, 0, 90, *([0] * 27))


def _proto_varint(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _proto_field(field_number: int, wire_type: int, payload: bytes) -> bytes:
    return _proto_varint((field_number << 3) | wire_type) + payload


def _unknown_sentencepiece_field(payload: bytes) -> bytes:
    return _proto_field(99, 2, _proto_varint(len(payload)) + payload)


def _small_zip_payload() -> bytes:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zip_archive:
        zip_archive.writestr("payload.py", "print('nested')")
    return archive.getvalue()


def _sentencepiece_piece(piece: str, piece_type: int) -> bytes:
    piece_payload = (
        _proto_field(1, 2, _proto_varint(len(piece.encode("utf-8"))) + piece.encode("utf-8"))
        + _proto_field(2, 5, struct.pack("<f", 0.0))
        + _proto_field(3, 0, _proto_varint(piece_type))
    )
    return _proto_field(1, 2, _proto_varint(len(piece_payload)) + piece_payload)


def _sentencepiece_trainer_spec(
    *,
    model_type: int = 1,
    vocab_size: int,
    unk_id: int | None = 0,
    unk_piece: str | None = "<unk>",
    byte_fallback: bool = False,
    extra_fields: bytes = b"",
) -> bytes:
    trainer_spec = _proto_field(3, 0, _proto_varint(model_type)) + _proto_field(4, 0, _proto_varint(vocab_size))
    if byte_fallback:
        trainer_spec += _proto_field(35, 0, _proto_varint(1))
    if unk_id is not None:
        trainer_spec += _proto_field(40, 0, _proto_varint(unk_id))
    if unk_piece is not None:
        encoded_unk_piece = unk_piece.encode("utf-8")
        trainer_spec += _proto_field(45, 2, _proto_varint(len(encoded_unk_piece)) + encoded_unk_piece)
    return _proto_field(2, 2, _proto_varint(len(trainer_spec + extra_fields)) + trainer_spec + extra_fields)


def _sentencepiece_trainer_spec_field(payload: bytes) -> bytes:
    return _proto_field(2, 2, _proto_varint(len(payload)) + payload)


def _sentencepiece_model_proto(*, include_trainer_spec: bool = False) -> bytes:
    pieces = [
        ("<unk>", 2),
        ("<s>", 3),
        ("</s>", 3),
        ("<pad>", 3),
        ("the", 1),
        ("of", 1),
        ("and", 1),
        ("to", 1),
    ]
    model = b"".join(_sentencepiece_piece(piece, piece_type) for piece, piece_type in pieces)
    if include_trainer_spec:
        model += _sentencepiece_trainer_spec(vocab_size=len(pieces))
    return model


def _sentencepiece_model_proto_with_default_unknown_metadata() -> bytes:
    pieces = [
        ("<unk>", 2),
        ("hello", 1),
        ("world", 1),
        ("token", 1),
    ]
    return b"".join(
        _sentencepiece_piece(piece, piece_type) for piece, piece_type in pieces
    ) + _sentencepiece_trainer_spec(
        vocab_size=len(pieces),
        unk_id=None,
        unk_piece=None,
    )


def _sentencepiece_model_proto_with_split_trainer_spec_metadata() -> bytes:
    pieces = [
        ("<unk>", 2),
        ("hello", 1),
        ("world", 1),
        ("token", 1),
    ]
    trainer_spec_head = _proto_field(3, 0, _proto_varint(1)) + _proto_field(4, 0, _proto_varint(len(pieces)))
    custom_unknown = b"<unk>"
    trainer_spec_tail = _proto_field(45, 2, _proto_varint(len(custom_unknown)) + custom_unknown)
    return (
        b"".join(_sentencepiece_piece(piece, piece_type) for piece, piece_type in pieces)
        + _sentencepiece_trainer_spec_field(trainer_spec_head)
        + _sentencepiece_trainer_spec_field(trainer_spec_tail)
    )


def _sentencepiece_model_proto_with_duplicate_unknown_pieces() -> bytes:
    pieces = [
        ("<unk>", 2),
        ("<bad_unk>", 2),
        ("<s>", 3),
        ("</s>", 3),
        ("<pad>", 3),
        ("the", 1),
        ("of", 1),
        ("and", 1),
    ]
    return b"".join(_sentencepiece_piece(piece, piece_type) for piece, piece_type in pieces)


def _sentencepiece_model_proto_with_byte_pieces_without_fallback() -> bytes:
    pieces = [
        ("<unk>", 2),
        ("<s>", 3),
        ("</s>", 3),
        ("<0x00>", 6),
        ("<0x01>", 6),
        ("<0x02>", 6),
        ("<0x03>", 6),
        ("<0x04>", 6),
    ]
    return b"".join(_sentencepiece_piece(piece, piece_type) for piece, piece_type in pieces)


def _sentencepiece_model_proto_with_trainer_varint_field_52() -> bytes:
    return _sentencepiece_model_proto() + _sentencepiece_trainer_spec(
        vocab_size=8,
        extra_fields=_proto_field(52, 0, _proto_varint(7)),
    )


def _sentencepiece_model_proto_with_trainer_string_field_54() -> bytes:
    seed_sentencepieces_file = b"seed_sentencepieces.tsv"
    return _sentencepiece_model_proto() + _sentencepiece_trainer_spec(
        vocab_size=8,
        extra_fields=_proto_field(54, 2, _proto_varint(len(seed_sentencepieces_file)) + seed_sentencepieces_file),
    )


def _large_real_sentencepiece_model_proto_shape() -> bytes:
    """Mirror large uMT5-style spiece.model prefixes without committing a large fixture."""
    pieces = [
        ("<pad>", 3),
        ("</s>", 3),
        ("<s>", 3),
        ("<unk>", 2),
        ("[eod]", 4),
        ("[web]", 4),
        ("[wiki]", 4),
        ("[translate]", 4),
    ]
    pieces.extend((f"<0x{byte:02X}>", 6) for byte in range(256))
    pieces.extend((f"t{index:05d}-{'x' * 470}", 1) for index in range(24000))
    return b"".join(
        _sentencepiece_piece(piece, piece_type) for piece, piece_type in pieces
    ) + _sentencepiece_trainer_spec(
        vocab_size=len(pieces),
        unk_id=3,
        byte_fallback=True,
    )


_SENTENCEPIECE_FIXTURE_DIR = Path(__file__).resolve().parents[1] / "assets" / "samples" / "sentencepiece"
_SENTENCEPIECE_OFFICIAL_FIXTURES = (
    "custom_unknown_disabled_specials.model",
    "custom_unknown_disabled_specials_byte_fallback.model",
)
_SENTENCEPIECE_SEMANTIC_MALFORMED_FACTORIES = (
    pytest.param(_sentencepiece_model_proto_with_duplicate_unknown_pieces, id="duplicate-unknown-pieces"),
    pytest.param(_sentencepiece_model_proto_with_byte_pieces_without_fallback, id="byte-pieces-without-fallback"),
)
_SENTENCEPIECE_MALFORMED_TAILS = (
    pytest.param(b"\x12\x80", id="truncated-length-varint"),
    pytest.param(b"\x80", id="truncated-tag-varint"),
    pytest.param(_proto_field(2, 2, _proto_varint(4) + b"x"), id="truncated-length-payload"),
    pytest.param(_proto_varint((2 << 3) | 6), id="invalid-wire-type-6"),
    pytest.param(_proto_varint((2 << 3) | 7), id="invalid-wire-type-7"),
    pytest.param(b"\x00not a protobuf tail", id="arbitrary-tail"),
    pytest.param(
        _unknown_sentencepiece_field(pickle.dumps({"payload": "pickle"}, protocol=4)), id="unknown-field-pickle"
    ),
    pytest.param(_unknown_sentencepiece_field(_small_zip_payload()), id="unknown-field-zip"),
)


def _write_official_sentencepiece_fixture(tmp_path: Path, fixture_name: str) -> Path:
    tokenizer_model = tmp_path / "tokenizer.model"
    tokenizer_model.write_bytes((_SENTENCEPIECE_FIXTURE_DIR / fixture_name).read_bytes())
    return tokenizer_model


def _write_sentencepiece_archive(tmp_path: Path, archive_kind: str, member_name: str, payload: bytes) -> Path:
    if archive_kind == "zip":
        archive_file = tmp_path / "tokenizer-bundle.zip"
        with zipfile.ZipFile(archive_file, "w") as archive:
            archive.writestr(member_name, payload)
        return archive_file
    if archive_kind == "tar":
        archive_file = tmp_path / "tokenizer-bundle.tar"
        with tarfile.open(archive_file, "w") as archive:
            info = tarfile.TarInfo(member_name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        return archive_file
    if archive_kind == "tar.gz":
        archive_file = tmp_path / "tokenizer-bundle.tar.gz"
        with tarfile.open(archive_file, "w:gz") as archive:
            info = tarfile.TarInfo(member_name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        return archive_file
    if archive_kind == "gz":
        archive_file = tmp_path / f"{Path(member_name).name}.gz"
        archive_file.write_bytes(gzip.compress(payload))
        return archive_file
    raise AssertionError(f"Unhandled archive kind: {archive_kind}")


@pytest.fixture
def xgboost_scanner() -> XGBoostScanner:
    """Create an XGBoost scanner instance."""
    return XGBoostScanner()


@pytest.fixture
def valid_xgboost_json() -> dict[str, Any]:
    """Valid XGBoost JSON model structure."""
    return {
        "version": [1, 7, 4],
        "learner": {
            "feature_names": ["feature_0", "feature_1", "feature_2"],
            "feature_types": ["float", "float", "float"],
            "learner_model_param": {
                "base_score": "0.5",
                "boost_from_average": "1",
                "num_class": "0",
                "num_features": "3",
                "num_parallel_tree": "1",
                "num_target": "1",
                "objective": "reg:squarederror",
                "predictor": "auto",
                "random_state": "0",
                "seed": "0",
                "seed_per_iteration": "0",
                "validate_parameters": "1",
            },
            "gradient_booster": {
                "name": "gbtree",
                "model": {
                    "gbtree_model_param": {"num_trees": "2", "num_parallel_tree": "1"},
                    "trees": [
                        {
                            "tree_param": {
                                "num_roots": "1",
                                "num_nodes": "3",
                                "num_deleted": "0",
                                "max_depth": "1",
                                "num_feature": "3",
                                "size_leaf_vector": "1",
                            },
                            "loss_changes": [0.5, 0.0, 0.0],
                            "sum_hessian": [2.0, 1.0, 1.0],
                            "base_weights": [0.25, -0.5, 0.5],
                            "left_children": [1, -1, -1],
                            "right_children": [2, -1, -1],
                            "parents": [2147483647, 0, 0],
                            "split_indices": [0, 0, 0],
                            "split_conditions": [0.5, 0.0, 0.0],
                            "split_type": [0, 0, 0],
                            "default_left": [0, 0, 0],
                            "categories": [],
                            "categories_nodes": [],
                            "categories_segments": [],
                            "categories_sizes": [],
                        },
                        {
                            "tree_param": {
                                "num_roots": "1",
                                "num_nodes": "1",
                                "num_deleted": "0",
                                "max_depth": "0",
                                "num_feature": "3",
                                "size_leaf_vector": "1",
                            },
                            "loss_changes": [0.0],
                            "sum_hessian": [2.0],
                            "base_weights": [0.125],
                            "left_children": [-1],
                            "right_children": [-1],
                            "parents": [2147483647],
                            "split_indices": [0],
                            "split_conditions": [0.0],
                            "split_type": [0],
                            "default_left": [0],
                            "categories": [],
                            "categories_nodes": [],
                            "categories_segments": [],
                            "categories_sizes": [],
                        },
                    ],
                    "tree_info": [0, 0],
                },
            },
        },
    }


def _scan_twice_with_cache(path: Path, cache_dir: Path) -> tuple[ModelAuditResultModel, ModelAuditResultModel]:
    first = scan_model_directory_or_file(
        str(path),
        cache_enabled=True,
        cache_dir=str(cache_dir),
        min_cache_file_size=0,
    )
    second = scan_model_directory_or_file(
        str(path),
        cache_enabled=True,
        cache_dir=str(cache_dir),
        min_cache_file_size=0,
    )
    return first, second


def _assert_inconclusive_metadata(result: ModelAuditResultModel, path: Path, reason: str) -> None:
    metadata = result.file_metadata[str(path)]
    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert metadata.get("analysis_incomplete") is True
    assert reason in metadata.get("scan_outcome_reasons", [])


def _assert_no_xgboost_s1004(result: ModelAuditResultModel) -> None:
    assert "xgboost" not in result.scanner_names
    assert determine_exit_code(result) == 0
    assert not any(issue.rule_code == "S1004" for issue in result.issues)


def _assert_xgboost_s1004(result: ModelAuditResultModel) -> None:
    assert "xgboost" in result.scanner_names
    assert determine_exit_code(result) == 2
    assert any(issue.rule_code == "S1004" for issue in result.issues)


def _ubjson_key(key: bytes) -> bytes:
    return b"U" + bytes([len(key)]) + key


def _ubjson_string(value: bytes) -> bytes:
    return b"SL" + len(value).to_bytes(8, byteorder="big", signed=True) + value


def _xgboost_ubjson_probe(
    *, root_padding: int = 0, learner_padding: int = 0, learner_noop: bool = False, malicious: bool = False
) -> bytes:
    root_body = b""
    if root_padding:
        root_body += _ubjson_key(b"metadata") + _ubjson_string(b"x" * root_padding)
    learner_body = b""
    if learner_padding:
        learner_body += _ubjson_key(b"metadata") + _ubjson_string(b"x" * learner_padding)
    learner_body += _ubjson_key(b"learner_model_param") + b"{}"
    if malicious:
        learner_body += _ubjson_key(b"malicious_code") + _ubjson_string(b"system(cpu)")
    learner_value = (b"N" if learner_noop else b"") + b"{" + learner_body + b"}"
    return b"{" + root_body + _ubjson_key(b"learner") + learner_value + _ubjson_key(b"version") + b"[]" + b"}"


def _xgboost_ubjson_counted_null_array_probe() -> bytes:
    max_count = ((1 << 63) - 1).to_bytes(8, byteorder="big", signed=True)
    learner = b"{" + _ubjson_key(b"learner_model_param") + b"{}" + _ubjson_key(b"payload") + b"[$Z#L" + max_count + b"}"
    return b"{" + _ubjson_key(b"learner") + learner + _ubjson_key(b"version") + b"[]" + b"}"


def _xgboost_ubjson_counted_null_array_before_learner_probe() -> bytes:
    max_count = ((1 << 63) - 1).to_bytes(8, byteorder="big", signed=True)
    return (
        b"{"
        + _ubjson_key(b"version")
        + b"[$Z#L"
        + max_count
        + _ubjson_key(b"learner")
        + b"{"
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + b"}"
        + b"}"
    )


def _xgboost_ubjson_noops_before_counted_null_array_probe() -> bytes:
    max_count = ((1 << 63) - 1).to_bytes(8, byteorder="big", signed=True)
    return (
        b"{"
        + (b"N" * XGBoostScanner._UBJSON_PROBE_READ_BYTES)
        + _ubjson_key(b"version")
        + b"[$Z#L"
        + max_count
        + _ubjson_key(b"learner")
        + b"{"
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + b"}"
        + b"}"
    )


def _xgboost_ubjson_uncounted_null_array_probe(item_count: int) -> bytes:
    learner = (
        b"{"
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + _ubjson_key(b"payload")
        + b"["
        + (b"Z" * item_count)
        + b"]}"
    )
    return b"{" + _ubjson_key(b"learner") + learner + b"}"


def _xgboost_ubjson_noop_before_counted_root_header_probe() -> bytes:
    return (
        b"{N#U\x02"
        + _ubjson_key(b"learner")
        + b"{"
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + b"}"
        + _ubjson_key(b"version")
        + b"[]"
    )


def _ubjson_root_counted_null_array_probe() -> bytes:
    max_count = ((1 << 63) - 1).to_bytes(8, byteorder="big", signed=True)
    return b"[$Z#L" + max_count


def _ubjson_noop_before_counted_null_array_probe() -> bytes:
    max_count = ((1 << 63) - 1).to_bytes(8, byteorder="big", signed=True)
    return b"{" + _ubjson_key(b"payload") + b"N[$Z#L" + max_count + b"}"


def _xgboost_ubjson_deep_before_counted_null_array_probe() -> bytes:
    max_count = ((1 << 63) - 1).to_bytes(8, byteorder="big", signed=True)
    nested = (
        b"[" * (XGBoostScanner._UBJSON_MAX_PROBE_DEPTH + 2) + b"Z" + b"]" * (XGBoostScanner._UBJSON_MAX_PROBE_DEPTH + 2)
    )
    learner = (
        b"{"
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + _ubjson_key(b"nested")
        + nested
        + _ubjson_key(b"payload")
        + b"[$Z#L"
        + max_count
        + b"}"
    )
    return b"{" + _ubjson_key(b"learner") + learner + b"}"


class TestXGBoostScannerBasic:
    """Test basic XGBoost scanner functionality."""

    def test_can_handle_supported_extensions(self, temp_dir: Path) -> None:
        """Test that scanner handles supported XGBoost file extensions."""
        # .bst, .ubj, and ambiguous .model files are accepted based on extension.
        for ext in [".bst", ".model", ".ubj"]:
            test_file = temp_dir / f"test{ext}"
            test_file.write_text("dummy content")
            assert XGBoostScanner.can_handle(str(test_file))

        # .json requires valid XGBoost structure
        json_file = temp_dir / "test.json"
        json_file.write_text(json.dumps({"version": [1, 5, 2], "learner": {"gradient_booster": {}}}))
        assert XGBoostScanner.can_handle(str(json_file))

    def test_can_handle_rejects_strong_sentencepiece_tokenizer_model(self, tmp_path: Path) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(_sentencepiece_model_proto())

        assert not XGBoostScanner.can_handle(str(tokenizer_model))

    @pytest.mark.parametrize("fixture_name", _SENTENCEPIECE_OFFICIAL_FIXTURES)
    def test_can_handle_rejects_dependency_sentencepiece_with_disabled_specials(
        self, tmp_path: Path, fixture_name: str
    ) -> None:
        tokenizer_model = _write_official_sentencepiece_fixture(tmp_path, fixture_name)

        assert not XGBoostScanner.can_handle(str(tokenizer_model))

    def test_can_handle_rejects_sentencepiece_with_proto2_default_unknown_metadata(self, tmp_path: Path) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(_sentencepiece_model_proto_with_default_unknown_metadata())

        assert not XGBoostScanner.can_handle(str(tokenizer_model))

    def test_can_handle_rejects_strong_sentencepiece_with_well_formed_tail(self, tmp_path: Path) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(_sentencepiece_model_proto() + _proto_field(2, 2, _proto_varint(0)))

        assert not XGBoostScanner.can_handle(str(tokenizer_model))

    def test_can_handle_rejects_sentencepiece_with_trainer_varint_field_52(self, tmp_path: Path) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(_sentencepiece_model_proto_with_trainer_varint_field_52())

        assert not XGBoostScanner.can_handle(str(tokenizer_model))

    def test_can_handle_rejects_sentencepiece_with_trainer_string_field_54(self, tmp_path: Path) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(_sentencepiece_model_proto_with_trainer_string_field_54())

        assert not XGBoostScanner.can_handle(str(tokenizer_model))

    def test_can_handle_keeps_malformed_sentencepiece_like_model_on_xgboost_route(self, tmp_path: Path) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(b"\x0a\x0e\x0a\x05<unk>\x15\x00" + (b"\0" * 64))

        assert XGBoostScanner.can_handle(str(tokenizer_model))

    @pytest.mark.parametrize("payload_factory", _SENTENCEPIECE_SEMANTIC_MALFORMED_FACTORIES)
    def test_can_handle_keeps_semantically_malformed_sentencepiece_on_xgboost_route(
        self, tmp_path: Path, payload_factory: Callable[[], bytes]
    ) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(payload_factory())

        assert XGBoostScanner.can_handle(str(tokenizer_model))

    def test_can_handle_keeps_capped_sentencepiece_prefix_on_xgboost_route(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        prefix = _sentencepiece_model_proto()
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(prefix + b"\x12\x80")
        monkeypatch.setattr(file_detection, "_SENTENCEPIECE_MODEL_PROTO_READ_BYTES", len(prefix))

        assert XGBoostScanner.can_handle(str(tokenizer_model))

    @pytest.mark.parametrize("tail", _SENTENCEPIECE_MALFORMED_TAILS)
    def test_can_handle_keeps_strong_sentencepiece_with_malformed_tail_on_xgboost_route(
        self, tmp_path: Path, tail: bytes
    ) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(_sentencepiece_model_proto() + tail)

        assert XGBoostScanner.can_handle(str(tokenizer_model))

    def test_can_handle_keeps_xgboost_model_extension_controls(self, tmp_path: Path) -> None:
        binary_model = tmp_path / "xgboost.model"
        binary_model.write_bytes(b"binf" + (b"\0" * 60))

        assert XGBoostScanner.can_handle(str(binary_model))

    def test_cannot_handle_unsupported_extensions(self, temp_dir):
        """Test that scanner rejects unsupported file extensions."""
        unsupported_extensions = [".txt", ".pkl", ".h5", ".onnx"]

        for ext in unsupported_extensions:
            test_file = temp_dir / f"test{ext}"
            test_file.write_text("dummy content")

            assert not XGBoostScanner.can_handle(str(test_file))

    def test_can_handle_extensionless_ubjson_with_xgboost_markers(self, temp_dir: Path) -> None:
        model_file = temp_dir / "model"
        model_file.write_bytes(_xgboost_ubjson_probe())

        assert XGBoostScanner.can_handle(str(model_file))

    def test_can_handle_extensionless_ubjson_with_noop_before_learner(self, temp_dir: Path) -> None:
        model_file = temp_dir / "model"
        model_file.write_bytes(_xgboost_ubjson_probe(learner_noop=True))

        assert XGBoostScanner.can_handle(str(model_file))

    def test_can_handle_extensionless_ubjson_with_noop_before_counted_root_header(self, temp_dir: Path) -> None:
        model_file = temp_dir / "model"
        model_file.write_bytes(_xgboost_ubjson_noop_before_counted_root_header_probe())

        assert XGBoostScanner.can_handle(str(model_file))

    def test_extensionless_counted_null_array_probe_is_bounded(self, temp_dir: Path) -> None:
        model_file = temp_dir / "model"
        model_file.write_bytes(_xgboost_ubjson_counted_null_array_probe())

        assert XGBoostScanner.can_handle(str(model_file))

    def test_rejects_extensionless_ubjson_like_header_without_xgboost_markers(self, temp_dir: Path) -> None:
        model_file = temp_dir / "model"
        model_file.write_bytes(b"{L" + (b"\0" * 64))

        assert not XGBoostScanner.can_handle(str(model_file))

    def test_rejects_extensionless_ubjson_with_only_learner_marker(self, temp_dir: Path) -> None:
        model_file = temp_dir / "model"
        model_file.write_bytes(b"{" + _ubjson_key(b"learner") + b"{}" + b"}")

        assert not XGBoostScanner.can_handle(str(model_file))

    def test_rejects_extensionless_ubjson_manifest_with_generic_version_key(self, temp_dir: Path) -> None:
        model_file = temp_dir / "model"
        model_file.write_bytes(
            b"{"
            + _ubjson_key(b"learner")
            + b"{}"
            + _ubjson_key(b"version")
            + b"[]"
            + _ubjson_key(b"note")
            + _ubjson_string(b"system(cpu)")
            + b"}"
        )

        assert not XGBoostScanner.can_handle(str(model_file))

    def test_rejects_extensionless_ubjson_with_marker_text_only_in_values(self, temp_dir: Path) -> None:
        model_file = temp_dir / "model"
        model_file.write_bytes(b"{" + _ubjson_key(b"note") + _ubjson_string(b"learner version system(cpu)") + b"}")

        assert not XGBoostScanner.can_handle(str(model_file))

    def test_rejects_extensionless_binary_signature_at_nonzero_offset(self, temp_dir: Path) -> None:
        model_file = temp_dir / "model"
        model_file.write_bytes(b"not-binf-in-prefix")

        assert not XGBoostScanner.can_handle(str(model_file))

    def test_bounded_can_handle_defers_extensionless_ubjson_with_late_model_key(self, temp_dir: Path) -> None:
        """Selection does not scan beyond the bounded extensionless probe."""
        probe_bytes = XGBoostScanner._UBJSON_PROBE_READ_BYTES
        payload = _xgboost_ubjson_probe(learner_padding=probe_bytes)
        encoded_strong_key = _ubjson_key(b"learner_model_param")
        assert encoded_strong_key not in payload[:probe_bytes]
        assert encoded_strong_key in payload

        model_file = temp_dir / "model"
        model_file.write_bytes(payload)

        assert not XGBoostScanner.can_handle(str(model_file))

    def test_scanner_name_and_description(self):
        """Test scanner metadata."""
        assert XGBoostScanner.name == "xgboost"
        assert "XGBoost" in XGBoostScanner.description
        assert "vulnerabilities" in XGBoostScanner.description

    def test_nonexistent_file_handling(self, xgboost_scanner):
        """Test handling of non-existent files."""
        result = xgboost_scanner.scan("/nonexistent/path/model.bst")
        assert not result.success
        assert any("does not exist" in str(issue.message) for issue in result.issues)


class TestXGBoostJSONScanning:
    """Test XGBoost JSON model scanning."""

    def test_valid_json_model_passes(
        self,
        temp_dir: Path,
        xgboost_scanner: XGBoostScanner,
        valid_xgboost_json: dict[str, Any],
    ) -> None:
        """Test that valid XGBoost JSON model passes all checks."""
        json_file = temp_dir / "valid_model.json"
        json_file.write_text(json.dumps(valid_xgboost_json, indent=2))

        result = xgboost_scanner.scan(str(json_file))

        assert result.success
        # Should have passing checks for JSON parsing and schema validation
        passing_checks = [c for c in result.checks if c.status.value == "passed"]
        assert len(passing_checks) > 0

        # Should not have critical issues
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 0

    def test_tree_depth_validation_uses_child_structure(
        self,
        temp_dir: Path,
        valid_xgboost_json: dict[str, Any],
    ) -> None:
        """Tree depth validation should use child arrays, not size_leaf_vector metadata."""
        tree = valid_xgboost_json["learner"]["gradient_booster"]["model"]["trees"][0]
        tree["tree_param"]["size_leaf_vector"] = "1"
        tree["left_children"] = [1, 2, 3, -1]
        tree["right_children"] = [-1, -1, -1, -1]
        tree["parents"] = [2147483647, 0, 1, 2]

        json_file = temp_dir / "deep_tree.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = XGBoostScanner({"max_tree_depth": 2}).scan(str(json_file))

        checks = {check.name: check for check in result.checks}
        assert checks["Tree Depth Validation"].status == CheckStatus.FAILED
        assert checks["Tree Depth Validation"].details["depth"] == 3

    def test_tree_depth_validation_checks_trees_after_first_ten(
        self,
        temp_dir: Path,
        valid_xgboost_json: dict[str, Any],
    ) -> None:
        """Late trees should not bypass structure validation."""
        trees = valid_xgboost_json["learner"]["gradient_booster"]["model"]["trees"]
        shallow_tree = copy.deepcopy(trees[1])
        deep_tree = copy.deepcopy(trees[0])
        deep_tree["left_children"] = [1, 2, 3, -1]
        deep_tree["right_children"] = [-1, -1, -1, -1]
        deep_tree["parents"] = [2147483647, 0, 1, 2]
        valid_xgboost_json["learner"]["gradient_booster"]["model"]["trees"] = [
            *[copy.deepcopy(shallow_tree) for _ in range(10)],
            deep_tree,
        ]

        json_file = temp_dir / "late_deep_tree.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = XGBoostScanner({"max_tree_depth": 2}).scan(str(json_file))

        checks = [check for check in result.checks if check.name == "Tree Depth Validation"]
        assert len(checks) == 1
        assert checks[0].status == CheckStatus.FAILED
        assert checks[0].details["tree_index"] == 10
        assert checks[0].details["depth"] == 3

    def test_tree_depth_validation_aggregates_many_late_failures(
        self,
        temp_dir: Path,
        valid_xgboost_json: dict[str, Any],
    ) -> None:
        """Repeated deep trees should not flood the scan result."""
        trees = valid_xgboost_json["learner"]["gradient_booster"]["model"]["trees"]
        deep_tree = copy.deepcopy(trees[0])
        deep_tree["left_children"] = [1, 2, 3, -1]
        deep_tree["right_children"] = [-1, -1, -1, -1]
        deep_tree["parents"] = [2147483647, 0, 1, 2]
        valid_xgboost_json["learner"]["gradient_booster"]["model"]["trees"] = [
            copy.deepcopy(deep_tree) for _ in range(25)
        ]

        json_file = temp_dir / "many_deep_trees.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = XGBoostScanner({"max_tree_depth": 2}).scan(str(json_file))

        checks = [check for check in result.checks if check.name == "Tree Depth Validation"]
        assert len(checks) == 1
        assert checks[0].status == CheckStatus.FAILED
        assert checks[0].details["tree_count"] == 25
        assert checks[0].details["tree_index"] == 0
        assert checks[0].details["max_observed_depth"] == 3
        assert checks[0].details["examples"] == [{"tree_index": tree_index, "depth": 3} for tree_index in range(10)]

    def test_invalid_json_fails(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Test that invalid JSON content is detected."""
        json_file = temp_dir / "invalid.json"
        json_file.write_text('{"invalid": json content}')  # Invalid JSON

        result = xgboost_scanner.scan(str(json_file))

        # Should detect JSON parsing error
        assert any("Invalid JSON format" in str(issue.message) for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_json_parse_failed" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize(
        ("field", "mutate_model"),
        [
            (
                "learner.gradient_booster",
                lambda payload: payload["learner"].update({"gradient_booster": "oops"}),
            ),
            (
                "learner.gradient_booster",
                lambda payload: payload["learner"].update({"gradient_booster": None}),
            ),
            (
                "learner.gradient_booster.model",
                lambda payload: payload["learner"]["gradient_booster"].update({"model": "oops"}),
            ),
            (
                "learner.gradient_booster.model",
                lambda payload: payload["learner"]["gradient_booster"].update({"model": None}),
            ),
            (
                "learner.gradient_booster.model.trees",
                lambda payload: payload["learner"]["gradient_booster"]["model"].update({"trees": "oops"}),
            ),
            (
                "learner.gradient_booster.model.trees[0].children",
                lambda payload: payload["learner"]["gradient_booster"]["model"]["trees"][0].update(
                    {"left_children": "oops"}
                ),
            ),
            (
                "learner.gradient_booster.model.trees[0].children",
                lambda payload: payload["learner"]["gradient_booster"]["model"]["trees"][0].update(
                    {"left_children": ["1", -1, -1]}
                ),
            ),
            (
                "learner.gradient_booster.model.trees[0].children",
                lambda payload: payload["learner"]["gradient_booster"]["model"]["trees"][0].update(
                    {"left_children": [1.9, -1, -1]}
                ),
            ),
            (
                "learner.gradient_booster.model.trees[0].children",
                lambda payload: payload["learner"]["gradient_booster"]["model"]["trees"][0].update(
                    {"left_children": [True, -1, -1]}
                ),
            ),
            (
                "learner.gradient_booster.model.trees[0].children",
                lambda payload: payload["learner"]["gradient_booster"]["model"]["trees"][0].update(
                    {"left_children": [99, -1, -1]}
                ),
            ),
        ],
    )
    def test_malformed_nested_json_is_inconclusive(
        self,
        temp_dir: Path,
        valid_xgboost_json: dict[str, Any],
        field: str,
        mutate_model: Callable[[dict[str, Any]], None],
    ) -> None:
        """Malformed nested fields should not disappear behind a clean JSON scan."""
        mutate_model(valid_xgboost_json)
        json_file = temp_dir / "malformed_nested.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = XGBoostScanner().scan(str(json_file))

        checks = [check for check in result.checks if check.name == "XGBoost JSON Structure Validation"]
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_json_structure_invalid" in result.metadata["scan_outcome_reasons"]
        assert any(check.details["field"] == field for check in checks)

    @pytest.mark.parametrize(
        "mutate_model",
        [
            lambda payload: payload.update({"version": "malformed"}),
            lambda payload: payload.update({"learner": "malformed"}),
        ],
    )
    def test_malformed_top_level_json_is_inconclusive(
        self,
        temp_dir: Path,
        valid_xgboost_json: dict[str, Any],
        mutate_model: Callable[[dict[str, Any]], None],
    ) -> None:
        mutate_model(valid_xgboost_json)
        json_file = temp_dir / "malformed_top_level.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = XGBoostScanner().scan(str(json_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_json_structure_invalid" in result.metadata["scan_outcome_reasons"]

    def test_json_structure_validation_aggregates_many_invalid_trees(
        self, temp_dir: Path, valid_xgboost_json: dict[str, Any]
    ) -> None:
        """Repeated malformed trees should collapse to one bounded finding."""
        valid_xgboost_json["learner"]["gradient_booster"]["model"]["trees"] = ["oops"] * 25
        json_file = temp_dir / "many_malformed_trees.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = XGBoostScanner().scan(str(json_file))

        checks = [check for check in result.checks if check.name == "XGBoost JSON Structure Validation"]
        assert len(checks) == 1
        assert checks[0].details["invalid_count"] == 25
        assert checks[0].details["aggregated"] is True
        assert len(checks[0].details["examples"]) == 10

    def test_malformed_xgboost_json_candidate_is_routed(self, temp_dir: Path) -> None:
        """Malformed XGBoost-shaped JSON should reach the fail-closed parser path."""
        json_file = temp_dir / "booster.json"
        json_file.write_text('{"version":[1,7,4],"learner":{"gradient_booster":')

        assert XGBoostScanner.can_handle(str(json_file))

    @pytest.mark.parametrize(
        ("filename", "payload"),
        [
            ("model.json", '{"version":"1","learner":'),
            ("settings.json", '{"version":"1","learner":{"objective":'),
        ],
    )
    def test_generic_malformed_json_candidate_is_not_routed(self, temp_dir: Path, filename: str, payload: str) -> None:
        """Generic malformed JSON should not be misclassified from weak key names alone."""
        json_file = temp_dir / filename
        json_file.write_text(payload)

        assert not XGBoostScanner.can_handle(str(json_file))

    def test_missing_required_keys_detected(self, temp_dir: Path) -> None:
        """Test that scanner rejects JSON files missing required XGBoost keys in can_handle()."""
        incomplete_json = {"version": [1, 0, 0]}  # Missing learner

        json_file = temp_dir / "incomplete.json"
        json_file.write_text(json.dumps(incomplete_json))

        # Should be rejected by can_handle() - scanner won't even try to scan it
        assert not XGBoostScanner.can_handle(str(json_file))

    def test_can_handle_json_uses_bounded_structural_sniff(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Routing should not fully parse arbitrary JSON before scanner limits apply."""
        json_file = tmp_path / "large_non_xgboost.json"
        json_file.write_text('{"padding": "' + ("A" * 200_000) + '"}', encoding="utf-8")

        def fail_json_load(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("can_handle() must not call json.load()")

        monkeypatch.setattr("modelaudit.scanners.xgboost_scanner.json.load", fail_json_load)

        read_sizes: list[int] = []
        real_open = open

        class TrackingBinaryReader:
            def __init__(self, raw: Any) -> None:
                self._raw = raw

            def __enter__(self) -> "TrackingBinaryReader":
                self._raw.__enter__()
                return self

            def __exit__(self, *args: Any) -> object:
                return self._raw.__exit__(*args)

            def read(self, size: int = -1) -> bytes:
                read_sizes.append(size)
                if size < 0:
                    raise AssertionError("can_handle() must not perform unbounded full-file read()")
                data = self._raw.read(size)
                assert isinstance(data, bytes)
                return data

            def seek(self, offset: int, whence: int = 0) -> int:
                return cast(int, self._raw.seek(offset, whence))

            def __getattr__(self, name: str) -> Any:
                return getattr(self._raw, name)

        def instrumented_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            stream = real_open(file, mode, *args, **kwargs)
            if isinstance(file, str) and Path(file) == json_file and "b" in mode:
                return TrackingBinaryReader(stream)
            return stream

        with patch("builtins.open", side_effect=instrumented_open):
            assert XGBoostScanner.can_handle(str(json_file)) is False

        assert XGBOOST_JSON_ROUTING_CHUNK_BYTES in read_sizes
        assert all(size <= XGBoostScanner._JSON_PROBE_READ_BYTES for size in read_sizes)

    def test_can_handle_json_detects_malicious_xgboost_after_large_prefix(self, tmp_path: Path) -> None:
        """Routing should find malicious XGBoost JSON markers beyond the first read chunk."""
        delayed_malicious_model = {
            "padding": "A" * (XGBOOST_JSON_ROUTING_CHUNK_BYTES + 1024),
            "version": [1, 7, 4],
            "learner": {
                "malicious_code": "os.system('touch pwned')",
            },
        }
        json_file = tmp_path / "delayed_malicious_xgboost.json"
        json_file.write_text(json.dumps(delayed_malicious_model), encoding="utf-8")

        assert XGBoostScanner.can_handle(str(json_file)) is True

        result = XGBoostScanner().scan(str(json_file))

        assert any("Suspicious pattern detected" in str(issue.message) for issue in result.issues)

    def test_can_handle_json_rejects_manifest_near_match(self, tmp_path: Path) -> None:
        """Manifest-like JSON should not be claimed by XGBoost on shallow marker names alone."""
        manifest_like_config = {
            "version": [1],
            "learner": {},
            "download_url": "s3://bucket/model.bin",
        }
        json_file = tmp_path / "config.json"
        json_file.write_text(json.dumps(manifest_like_config), encoding="utf-8")

        assert XGBoostScanner.can_handle(str(json_file)) is False

    def test_scan_default_read_limit_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        valid_xgboost_json: dict[str, Any],
    ) -> None:
        """JSON scans should fail closed before full parsing when the read cap is exceeded."""
        monkeypatch.setattr(XGBoostScanner, "default_max_file_read_size", 32)
        json_file = tmp_path / "oversized_model.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = XGBoostScanner().scan(str(json_file))

        checks = {check.name: check for check in result.checks}
        assert checks["File Size Limit"].status == CheckStatus.FAILED
        assert "File too large" in checks["File Size Limit"].message
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert result.metadata["analysis_incomplete"] is True
        assert "max_file_read_size_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_json_read_failure_is_inconclusive_not_security_finding(
        self,
        tmp_path: Path,
        xgboost_scanner: XGBoostScanner,
        valid_xgboost_json: dict[str, Any],
    ) -> None:
        json_file = tmp_path / "unreadable.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        with patch("modelaudit.scanners.xgboost_scanner.json.load", side_effect=OSError("forced JSON read failure")):
            result = xgboost_scanner.scan(str(json_file))

        read_checks = [check for check in result.checks if check.name == "XGBoost File Read"]
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_read_failed" in result.metadata["scan_outcome_reasons"]
        assert len(read_checks) == 1
        assert read_checks[0].severity == IssueSeverity.INFO
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    def test_malicious_json_content_detected(self, temp_dir, xgboost_scanner):
        """Test detection of malicious patterns in JSON."""
        malicious_json = {
            "version": [1, 0, 0],
            "learner": {
                "malicious_code": "os.system('rm -rf /')",
                "eval_call": "eval('__import__(\\'os\\').system(\\'ls\\')')",
                "subprocess_usage": "subprocess.run(['cat', '/etc/passwd'])",
            },
        }

        json_file = temp_dir / "malicious.json"
        json_file.write_text(json.dumps(malicious_json))

        result = xgboost_scanner.scan(str(json_file))

        # Should detect multiple suspicious patterns
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0
        assert any("Suspicious pattern detected" in str(issue.message) for issue in critical_issues)

    def test_feature_names_metadata_does_not_false_positive(
        self,
        tmp_path: Path,
        valid_xgboost_json: dict[str, Any],
    ) -> None:
        """Feature labels are inert metadata, not executable JSON content."""
        valid_xgboost_json["learner"]["feature_names"] = ["system(cpu)"]
        json_file = tmp_path / "feature_names.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = XGBoostScanner().scan(str(json_file))

        assert result.success is True
        assert not any(
            check.name == "JSON Content Analysis" and check.status == CheckStatus.FAILED for check in result.checks
        )

    def test_system_call_outside_feature_names_still_detected(
        self,
        tmp_path: Path,
        valid_xgboost_json: dict[str, Any],
    ) -> None:
        """The feature-name exemption must not suppress real payload fields."""
        valid_xgboost_json["learner"]["malicious_code"] = "system(cpu)"
        json_file = tmp_path / "malicious_field.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = XGBoostScanner().scan(str(json_file))

        assert any(
            check.name == "JSON Content Analysis"
            and check.status == CheckStatus.FAILED
            and "System call in JSON" in check.message
            for check in result.checks
        )

    def test_nested_feature_names_lookalike_still_detected(
        self,
        tmp_path: Path,
        valid_xgboost_json: dict[str, Any],
    ) -> None:
        """Only the canonical metadata path should receive the exemption."""
        valid_xgboost_json["learner"] = [{"feature_names": "system(cpu)"}]
        json_file = tmp_path / "nested_feature_names.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = XGBoostScanner().scan(str(json_file))

        assert any(
            check.name == "JSON Content Analysis"
            and check.status == CheckStatus.FAILED
            and "System call in JSON" in check.message
            for check in result.checks
        )

    @pytest.mark.parametrize(
        "feature_names",
        [
            "system(cpu)",
            {"payload": "system(cpu)"},
            [{"payload": "system(cpu)"}],
        ],
    )
    def test_malformed_feature_names_values_still_detected(
        self,
        tmp_path: Path,
        valid_xgboost_json: dict[str, Any],
        feature_names: Any,
    ) -> None:
        """Only valid inert feature-label arrays should receive the exemption."""
        valid_xgboost_json["learner"]["feature_names"] = feature_names
        json_file = tmp_path / "malformed_feature_names.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = XGBoostScanner().scan(str(json_file))

        assert any(
            check.name == "JSON Content Analysis"
            and check.status == CheckStatus.FAILED
            and "System call in JSON" in check.message
            for check in result.checks
        )


@pytest.mark.skipif(not hasattr(pytest, "importorskip"), reason="pytest.importorskip not available")
class TestXGBoostUBJScanning:
    """Test XGBoost UBJ model scanning."""

    def test_ubj_without_ubjson_library(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Test UBJ scanning without ubjson library (INFO level)."""
        ubj_file = temp_dir / "model.ubj"
        ubj_file.write_bytes(b"\x7b\x55")  # UBJ object start

        with patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=False):
            result = xgboost_scanner.scan(str(ubj_file))

        # Message changed to "Cannot scan UBJ file"
        assert any("cannot scan ubj file" in str(issue.message).lower() for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_ubj_dependency_missing" in result.metadata["scan_outcome_reasons"]

    def test_invalid_ubj_detected(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Malformed UBJ should fail closed before reaching the decoder."""
        pytest.importorskip("ubjson", reason="ubjson not installed")
        ubj_file = temp_dir / "invalid.ubj"
        ubj_file.write_bytes(b"\xff\xff\xff\xff")  # Invalid UBJ data

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch("ubjson.loadb") as mock_loadb,
        ):
            result = xgboost_scanner.scan(str(ubj_file))

        assert any("resource preflight could not complete" in str(issue.message) for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_ubj_preflight_incomplete" in result.metadata["scan_outcome_reasons"]
        mock_loadb.assert_not_called()
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


class TestXGBoostBinaryScanning:
    """Test XGBoost binary model scanning."""

    def test_legacy_header_pattern_search_reuses_lowered_header(self, xgboost_scanner: XGBoostScanner) -> None:
        class CountingHeader(str):
            lower_calls = 0

            def lower(self) -> str:
                self.lower_calls += 1
                return super().lower()

        header = CountingHeader("BINF GBTree REG:squarederror")

        assert xgboost_scanner._find_legacy_header_patterns(header) == ["gbtree", "reg:"]
        assert header.lower_calls == 1

    def test_empty_binary_file_detected(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Test detection of empty binary files."""
        binary_file = temp_dir / "empty.bst"
        binary_file.write_bytes(b"")

        result = xgboost_scanner.scan(str(binary_file))

        assert any("empty" in str(issue.message).lower() for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_empty" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize("suffix", [".bst", ".model"])
    def test_pickle_masquerading_as_binary_model_is_inconclusive(
        self, temp_dir: Path, xgboost_scanner: XGBoostScanner, suffix: str
    ) -> None:
        """Pickle files masquerading as XGBoost binaries should fail closed."""
        # Create a pickle file
        pickle_data = pickle.dumps({"fake": "model"})

        fake_bst = temp_dir / f"fake{suffix}"
        fake_bst.write_bytes(pickle_data)

        result = xgboost_scanner.scan(str(fake_bst))

        assert any("pickle file" in str(issue.message) for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_pickle_spoof" in result.metadata["scan_outcome_reasons"]

    def test_non_pickle_binary_starting_with_proto0_like_byte_is_not_spoof(
        self, temp_dir: Path, xgboost_scanner: XGBoostScanner
    ) -> None:
        """Custom XGBoost-like binaries starting with 'c' are not automatically pickle spoofs."""
        binary_file = temp_dir / "custom.bst"
        binary_file.write_bytes(b"custom xgboost binary gbtree reg:squarederror")

        result = xgboost_scanner.scan(str(binary_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_structure_unrecognized" in result.metadata["scan_outcome_reasons"]
        assert not any("pickle file" in str(issue.message) for issue in result.issues)

    def test_bst_with_ubjson_header_routes_to_ubj_scan(self, temp_dir: Path) -> None:
        """Modern UBJSON-backed .bst files should bypass binary structure validation."""
        binary_file = temp_dir / "modern.bst"
        binary_file.write_bytes(_xgboost_ubjson_probe())
        scanner = XGBoostScanner()

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch.object(scanner, "_scan_ubj_model") as mock_scan_ubj,
            patch.object(scanner, "_validate_binary_structure") as mock_validate_binary_structure,
        ):
            result = scanner.scan(str(binary_file))

        mock_scan_ubj.assert_called_once_with(str(binary_file), result)
        mock_validate_binary_structure.assert_not_called()

    def test_bst_with_late_ubjson_strong_marker_routes_to_ubj_scan(self, temp_dir: Path) -> None:
        """Large UBJSON .bst files should not require strong markers in the probe window."""
        binary_file = temp_dir / "modern_large.bst"
        binary_file.write_bytes(_xgboost_ubjson_probe(learner_padding=XGBoostScanner._UBJSON_PROBE_READ_BYTES))
        scanner = XGBoostScanner()

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch.object(scanner, "_scan_ubj_model") as mock_scan_ubj,
            patch.object(scanner, "_validate_binary_structure") as mock_validate_binary_structure,
        ):
            result = scanner.scan(str(binary_file))

        mock_scan_ubj.assert_called_once_with(str(binary_file), result)
        mock_validate_binary_structure.assert_not_called()

    def test_bst_with_ubjson_like_header_without_markers_uses_binary_validation(self, temp_dir: Path) -> None:
        """UBJSON-looking bytes without XGBoost markers should not bypass binary validation."""
        binary_file = temp_dir / "custom.bst"
        binary_file.write_bytes(b"{Llegacy gbtree reg:squarederror with enough bytes")
        scanner = XGBoostScanner()

        with (
            patch.object(scanner, "_scan_ubj_model") as mock_scan_ubj,
            patch.object(scanner, "_validate_binary_structure") as mock_validate_binary_structure,
        ):
            scanner.scan(str(binary_file))

        mock_scan_ubj.assert_not_called()
        mock_validate_binary_structure.assert_called_once_with(str(binary_file), ANY)

    def test_binary_structure_exception_is_inconclusive(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Binary analyzer exceptions should fail closed instead of returning success."""
        binary_file = temp_dir / "broken.bst"
        binary_file.write_bytes(b"gbtree reg:squarederror with enough bytes")

        with patch.object(xgboost_scanner, "_validate_binary_structure", side_effect=RuntimeError("boom")):
            result = xgboost_scanner.scan(str(binary_file))

        assert any("Error analyzing XGBoost binary model: boom" in str(issue.message) for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_analysis_failed" in result.metadata["scan_outcome_reasons"]

    def test_binary_structure_read_failure_is_inconclusive(
        self, temp_dir: Path, xgboost_scanner: XGBoostScanner
    ) -> None:
        """Read failures caught inside structure validation should still fail closed."""
        binary_file = temp_dir / "unreadable.bst"
        binary_file.write_bytes(b"gbtree reg:squarederror with enough bytes")
        result = xgboost_scanner._create_result()

        with patch("builtins.open", side_effect=OSError("forced read failure")):
            xgboost_scanner._validate_binary_structure(str(binary_file), result)
        xgboost_scanner._finish_scan_result(result)

        read_checks = [check for check in result.checks if check.name == "XGBoost File Read"]
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_read_failed" in result.metadata["scan_outcome_reasons"]
        assert len(read_checks) == 1
        assert read_checks[0].severity == IssueSeverity.INFO
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    def test_binary_read_failure_skips_optional_loading_and_safe_mode_check(self, temp_dir: Path) -> None:
        binary_file = temp_dir / "unreadable.bst"
        binary_file.write_bytes(b"binf" + (b"\0" * 64))
        scanner = XGBoostScanner({"enable_xgb_loading": True})
        result = scanner._create_result()

        def record_read_failure(path: str, nested_result: ScanResult) -> None:
            scanner._record_read_failure(path, nested_result, OSError("forced read failure"))

        with (
            patch.object(scanner, "_is_pickle_file", return_value=False),
            patch.object(scanner, "_is_ubjson_file", return_value=False),
            patch.object(scanner, "_validate_binary_structure", side_effect=record_read_failure),
            patch.object(scanner, "_safe_xgboost_load") as mock_safe_load,
        ):
            scanner._scan_binary_model(str(binary_file), result)

        mock_safe_load.assert_not_called()
        assert "xgboost_read_failed" in result.metadata["scan_outcome_reasons"]
        assert not any(check.name == "XGBoost Loading" for check in result.checks)

    def test_binary_structure_validation(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Test binary structure validation."""
        # Create a file with some XGBoost-like content
        binary_content = b"binf\x00\x00\x01\x02reg:squarederror\x00\x00extra xgboost bytes"

        binary_file = temp_dir / "valid.bst"
        binary_file.write_bytes(binary_content)

        result = xgboost_scanner.scan(str(binary_file))

        # Should find expected XGBoost patterns
        pattern_checks = [c for c in result.checks if "Pattern Check" in c.name and c.status.value == "passed"]
        assert len(pattern_checks) > 0

    def test_marker_only_binary_is_inconclusive(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Printable marker-shaped junk should not pass as a legacy binary model."""
        binary_file = temp_dir / "marker_only.bst"
        binary_file.write_bytes(b"custom xgboost binary gbtree reg:squarederror")

        result = xgboost_scanner.scan(str(binary_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_structure_unrecognized" in result.metadata["scan_outcome_reasons"]
        assert any("expected XGBoost binary signature" in str(issue.message) for issue in result.issues)

    def test_binf_binary_signature_passes_structure_validation(
        self, temp_dir: Path, xgboost_scanner: XGBoostScanner
    ) -> None:
        """The binary binf signature should not be treated as markerless."""
        binary_file = temp_dir / "signature.bst"
        binary_file.write_bytes(b"binf" + (b"\0" * 60) + b"gbtree appears outside first read window")

        result = xgboost_scanner.scan(str(binary_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert any(
            "binf" in check.details.get("patterns_found", [])
            for check in result.checks
            if "Pattern Check" in check.name
        )

    def test_headerless_legacy_binary_passes_structure_validation(
        self, temp_dir: Path, xgboost_scanner: XGBoostScanner
    ) -> None:
        """Older pre-`binf` binaries should remain accepted."""
        binary_file = temp_dir / "legacy.bst"
        binary_file.write_bytes(_headerless_legacy_binary_header())

        result = xgboost_scanner.scan(str(binary_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert any(
            check.details.get("binary_format") == "headerless_legacy"
            for check in result.checks
            if "Pattern Check" in check.name
        )

    def test_suspicious_binary_patterns_detected(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Test detection of suspicious binary patterns."""
        # Create binary data with no recognizable XGBoost patterns
        suspicious_binary = bytes(range(256))  # All byte values 0-255

        binary_file = temp_dir / "suspicious.bst"
        binary_file.write_bytes(suspicious_binary)

        result = xgboost_scanner.scan(str(binary_file))

        # Should detect unusual binary patterns
        assert any("unusual binary patterns" in str(issue.message) for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_structure_unrecognized" in result.metadata["scan_outcome_reasons"]

    def test_printable_binary_without_xgboost_markers_is_inconclusive(
        self, temp_dir: Path, xgboost_scanner: XGBoostScanner
    ) -> None:
        """Printable .bst content without XGBoost markers should not pass cleanly."""
        binary_file = temp_dir / "printable.bst"
        binary_file.write_bytes(b"abcdefghijklmnopqrstuvwxyzabcdef")

        result = xgboost_scanner.scan(str(binary_file))

        assert any("expected XGBoost binary signature" in str(issue.message) for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_structure_unrecognized" in result.metadata["scan_outcome_reasons"]

    @patch("modelaudit.scanners.xgboost_scanner._check_xgboost_available")
    def test_xgboost_loading_disabled_by_default(
        self, mock_check_xgb: Mock, temp_dir: Path, xgboost_scanner: XGBoostScanner
    ) -> None:
        """Test that XGBoost loading is disabled by default."""
        mock_check_xgb.return_value = True

        binary_file = temp_dir / "test.bst"
        binary_file.write_bytes(b"some_binary_data gbtree reg:squarederror")

        result = xgboost_scanner.scan(str(binary_file))

        # Should indicate safe mode (loading disabled)
        assert any("safe mode" in str(check.message) for check in result.checks)

    def test_ubjson_bst_without_decoder_uses_loading_fallback(self, temp_dir: Path) -> None:
        """Detected UBJSON .bst files should still exercise XGBoost loading when enabled."""
        ubjson_bst = temp_dir / "model.bst"
        ubjson_bst.write_bytes(_xgboost_ubjson_probe())
        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})

        def record_successful_load(path: str, result: ScanResult) -> None:
            result.add_check(
                name="XGBoost Model Loading",
                passed=True,
                message="XGBoost model loaded successfully in isolated process",
                location=path,
                details={"load_test": "passed"},
            )

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=False),
            patch.object(loading_scanner, "_safe_xgboost_load", side_effect=record_successful_load) as mock_safe_load,
        ):
            result = loading_scanner.scan(str(ubjson_bst))

        mock_safe_load.assert_called_once()
        assert mock_safe_load.call_args.args[0] == str(ubjson_bst)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_ubj_dependency_missing" in result.metadata["scan_outcome_reasons"]
        assert any(check.name == "UBJSON Library Check" for check in result.checks)
        assert any(
            check.name == "XGBoost Model Loading" and check.status == CheckStatus.PASSED for check in result.checks
        )
        assert not any(check.name == "Binary Structure Validation" for check in result.checks)

    def test_ubjson_bst_without_decoder_or_loading_fails_closed(self, temp_dir: Path) -> None:
        """Detected UBJSON .bst files should not be misreported as malformed legacy binaries."""
        ubjson_bst = temp_dir / "model.bst"
        ubjson_bst.write_bytes(_xgboost_ubjson_probe())

        with patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=False):
            result = XGBoostScanner({"enable_xgb_loading": False}).scan(str(ubjson_bst))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_ubj_dependency_missing" in result.metadata["scan_outcome_reasons"]
        assert any(check.name == "UBJSON Library Check" for check in result.checks)
        assert not any(check.name == "Binary Structure Validation" for check in result.checks)

    def test_ubjson_bst_oversized_count_skips_loading_fallback(self, temp_dir: Path) -> None:
        """The optional XGBoost loader must not receive unsafe counted UBJSON arrays."""
        ubjson_bst = temp_dir / "model.bst"
        ubjson_bst.write_bytes(_xgboost_ubjson_counted_null_array_probe())
        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=False),
            patch.object(loading_scanner, "_safe_xgboost_load") as mock_safe_load,
        ):
            result = loading_scanner.scan(str(ubjson_bst))

        mock_safe_load.assert_not_called()
        assert result.success is False
        assert "xgboost_ubj_dependency_missing" in result.metadata["scan_outcome_reasons"]
        assert "xgboost_ubj_array_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert any(check.name == "UBJ Decode Resource Limit" for check in result.checks)

    def test_ubjson_bst_oversized_count_before_learner_skips_loading_fallback(self, temp_dir: Path) -> None:
        """Unsafe UBJSON arrays must be blocked even before a claimed model's learner key."""
        ubjson_bst = temp_dir / "model.bst"
        ubjson_bst.write_bytes(_xgboost_ubjson_counted_null_array_before_learner_probe())
        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=False),
            patch.object(loading_scanner, "_safe_xgboost_load") as mock_safe_load,
        ):
            result = loading_scanner.scan(str(ubjson_bst))

        mock_safe_load.assert_not_called()
        assert result.success is False
        assert "xgboost_ubj_dependency_missing" in result.metadata["scan_outcome_reasons"]
        assert "xgboost_ubj_array_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert any(check.name == "UBJ Decode Resource Limit" for check in result.checks)

    def test_ubjson_bst_noops_before_oversized_count_skip_loading_fallback(self, temp_dir: Path) -> None:
        """A bounded no-op prefix must not allow unsafe UBJSON into native loading."""
        ubjson_bst = temp_dir / "model.bst"
        ubjson_bst.write_bytes(_xgboost_ubjson_noops_before_counted_null_array_probe())
        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=False),
            patch.object(loading_scanner, "_safe_xgboost_load") as mock_safe_load,
        ):
            result = loading_scanner.scan(str(ubjson_bst))

        mock_safe_load.assert_not_called()
        assert result.success is False
        assert "xgboost_ubj_dependency_missing" in result.metadata["scan_outcome_reasons"]
        assert "xgboost_ubj_array_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert any(check.name == "UBJ Decode Resource Limit" for check in result.checks)

    @patch("modelaudit.scanners.xgboost_scanner._check_xgboost_available")
    @patch("modelaudit.scanners.xgboost_scanner.subprocess")
    def test_xgboost_loading_success(self, mock_subprocess: Mock, mock_check_xgb: Mock, temp_dir: Path) -> None:
        """Test successful XGBoost model loading."""
        mock_check_xgb.return_value = True
        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.stdout = "SUCCESS: Model loaded successfully"
        mock_proc.stderr = ""
        mock_subprocess.run.return_value = mock_proc

        # Create scanner with loading enabled
        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})

        binary_file = temp_dir / "valid.bst"
        binary_file.write_bytes(b"dummy_xgboost_data gbtree reg:squarederror")

        result = loading_scanner.scan(str(binary_file))

        assert any("loaded successfully" in str(check.message) for check in result.checks)
        mock_subprocess.run.assert_called_once()
        _, run_kwargs = mock_subprocess.run.call_args
        assert "cwd" in run_kwargs
        assert run_kwargs["cwd"] is not None
        assert "env" in run_kwargs
        assert isinstance(run_kwargs["env"], dict)
        assert "PYTHONPATH" not in run_kwargs["env"]

    @patch("modelaudit.scanners.xgboost_scanner._check_xgboost_available")
    @patch("modelaudit.scanners.xgboost_scanner.subprocess")
    def test_xgboost_loading_failure(self, mock_subprocess: Mock, mock_check_xgb: Mock, temp_dir: Path) -> None:
        """Test XGBoost model loading failure detection."""
        mock_check_xgb.return_value = True
        mock_proc = Mock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "ERROR: Invalid model format"
        mock_subprocess.run.return_value = mock_proc

        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})

        binary_file = temp_dir / "invalid.bst"
        binary_file.write_bytes(b"invalid_data gbtree reg:squarederror")

        result = loading_scanner.scan(str(binary_file))

        assert any("Failed to load XGBoost model" in str(issue.message) for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_load_failed" in result.metadata["scan_outcome_reasons"]

    @patch("modelaudit.scanners.xgboost_scanner._check_xgboost_available")
    @patch("modelaudit.scanners.xgboost_scanner.subprocess")
    def test_xgboost_loading_windows_path_passed_via_argv(self, mock_subprocess: Mock, mock_check_xgb: Mock) -> None:
        """Test subprocess load command handles backslashes by passing paths via argv."""
        mock_check_xgb.return_value = True
        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.stdout = "SUCCESS: Model loaded successfully"
        mock_proc.stderr = ""
        mock_subprocess.run.return_value = mock_proc

        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})
        result = loading_scanner._create_result()
        windows_path = r"C:\temp\model\xgboost.bin"

        loading_scanner._safe_xgboost_load(windows_path, result)

        run_args, run_kwargs = mock_subprocess.run.call_args
        cmd = run_args[0]
        script = cmd[3]
        assert cmd[1] == "-I"
        assert "sys.argv[1]" in script
        assert windows_path not in script
        assert cmd[4] == windows_path
        assert run_kwargs["cwd"] != str(Path.cwd())
        assert "PYTHONPATH" not in run_kwargs["env"]
        assert any("loaded successfully" in str(check.message) for check in result.checks)

    @patch("modelaudit.scanners.xgboost_scanner._check_xgboost_available")
    @patch("modelaudit.scanners.xgboost_scanner.subprocess")
    def test_xgboost_loading_timeout(self, mock_subprocess: Mock, mock_check_xgb: Mock, temp_dir: Path) -> None:
        """Test XGBoost model loading timeout handling."""
        mock_check_xgb.return_value = True
        mock_subprocess.TimeoutExpired = real_subprocess.TimeoutExpired
        mock_subprocess.run.side_effect = real_subprocess.TimeoutExpired(["python"], 30)

        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})

        binary_file = temp_dir / "timeout.bst"
        binary_file.write_bytes(b"data_that_causes_timeout gbtree reg:squarederror")

        result = loading_scanner.scan(str(binary_file))

        assert any("timeout" in str(issue.message).lower() for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_load_timeout" in result.metadata["scan_outcome_reasons"]


class TestXGBoostFailClosedEndToEnd:
    """Test CLI/core-visible XGBoost fail-closed semantics."""

    def test_extensionless_ubjson_core_detects_malicious_content(
        self, tmp_path: Path, valid_xgboost_json: dict[str, Any]
    ) -> None:
        ubjson = pytest.importorskip("ubjson", reason="ubjson not installed")
        valid_xgboost_json["learner"]["malicious_code"] = "os.system('touch pwned')"
        model_file = tmp_path / "model"
        model_file.write_bytes(ubjson.dumpb(valid_xgboost_json))

        direct = scan_file(str(model_file), config={"cache_enabled": False})
        directory = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

        assert direct.scanner_name == "xgboost"
        assert direct.success is False
        assert any(
            check.name == "JSON Content Analysis" and check.status == CheckStatus.FAILED for check in direct.checks
        )
        assert directory.success is True
        assert determine_exit_code(directory) == 1
        assert "xgboost" in directory.scanner_names
        assert any("System call in JSON" in str(issue.message) for issue in directory.issues)

    def test_extensionless_ubjson_near_match_remains_unclaimed(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model"
        model_file.write_bytes(b"{" + _ubjson_key(b"learner") + b"{}" + b"}")

        result = scan_file(str(model_file), config={"cache_enabled": False})

        assert result.scanner_name == "unknown"
        assert result.success is True
        assert result.issues == []

    def test_extensionless_ubjson_generic_version_manifest_remains_unclaimed(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model"
        model_file.write_bytes(
            b"{"
            + _ubjson_key(b"learner")
            + b"{}"
            + _ubjson_key(b"version")
            + b"[]"
            + _ubjson_key(b"note")
            + _ubjson_string(b"system(cpu)")
            + b"}"
        )

        result = scan_file(str(model_file), config={"cache_enabled": False})

        assert result.scanner_name == "unknown"
        assert result.success is True
        assert result.issues == []

    def test_extensionless_ubjson_text_values_do_not_trigger_xgboost_findings(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model"
        model_file.write_bytes(b"{" + _ubjson_key(b"message") + _ubjson_string(b"learner version system(cpu)") + b"}")

        result = scan_file(str(model_file), config={"cache_enabled": False})

        assert result.scanner_name == "unknown"
        assert result.success is True
        assert result.issues == []

    def test_extensionless_plain_json_remains_unclaimed(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model"
        model_file.write_text('{"kind":"manifest","safe":true}', encoding="utf-8")

        result = scan_file(str(model_file), config={"cache_enabled": False})

        assert result.scanner_name == "unknown"
        assert result.success is True
        assert result.issues == []

    def test_extensionless_ubjson_oversized_count_fails_closed_before_decode(self, tmp_path: Path) -> None:
        pytest.importorskip("ubjson", reason="ubjson not installed")
        model_file = tmp_path / "model"
        model_file.write_bytes(_xgboost_ubjson_counted_null_array_probe())

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch("ubjson.loadb") as mock_loadb,
        ):
            result = scan_model_directory_or_file(str(model_file), cache_enabled=False)

        assert result.success is False
        assert determine_exit_code(result) == 2
        assert "xgboost" in result.scanner_names
        _assert_inconclusive_metadata(result, model_file, "xgboost_ubj_array_limit_exceeded")
        assert any("decoded arrays exceed" in str(issue.message) for issue in result.issues)
        mock_loadb.assert_not_called()

    def test_extensionless_ubjson_oversized_uncounted_array_fails_closed_before_decode(self, tmp_path: Path) -> None:
        pytest.importorskip("ubjson", reason="ubjson not installed")
        model_file = tmp_path / "model"
        model_file.write_bytes(_xgboost_ubjson_uncounted_null_array_probe(5))

        with (
            patch.object(XGBoostScanner, "_UBJSON_MAX_DECODED_ARRAY_ITEMS", 4),
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch("ubjson.loadb") as mock_loadb,
        ):
            result = scan_model_directory_or_file(str(model_file), cache_enabled=False)

        assert result.success is False
        assert determine_exit_code(result) == 2
        assert "xgboost" in result.scanner_names
        _assert_inconclusive_metadata(result, model_file, "xgboost_ubj_array_limit_exceeded")
        assert any("decoded arrays exceed" in str(issue.message) for issue in result.issues)
        mock_loadb.assert_not_called()

    def test_ubj_root_oversized_count_fails_closed_before_decode(self, tmp_path: Path) -> None:
        pytest.importorskip("ubjson", reason="ubjson not installed")
        model_file = tmp_path / "model.ubj"
        model_file.write_bytes(_ubjson_root_counted_null_array_probe())

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch("ubjson.loadb") as mock_loadb,
        ):
            result = scan_model_directory_or_file(str(model_file), cache_enabled=False)

        assert result.success is False
        assert determine_exit_code(result) == 2
        _assert_inconclusive_metadata(result, model_file, "xgboost_ubj_array_limit_exceeded")
        assert any("decoded arrays exceed" in str(issue.message) for issue in result.issues)
        mock_loadb.assert_not_called()

    def test_ubj_noop_before_oversized_count_fails_closed_before_decode(self, tmp_path: Path) -> None:
        pytest.importorskip("ubjson", reason="ubjson not installed")
        model_file = tmp_path / "model.ubj"
        model_file.write_bytes(_ubjson_noop_before_counted_null_array_probe())

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch("ubjson.loadb") as mock_loadb,
        ):
            result = scan_model_directory_or_file(str(model_file), cache_enabled=False)

        assert result.success is False
        assert determine_exit_code(result) == 2
        _assert_inconclusive_metadata(result, model_file, "xgboost_ubj_array_limit_exceeded")
        assert any("decoded arrays exceed" in str(issue.message) for issue in result.issues)
        mock_loadb.assert_not_called()

    def test_ubj_deep_container_fails_closed_before_decode(self, tmp_path: Path) -> None:
        pytest.importorskip("ubjson", reason="ubjson not installed")
        model_file = tmp_path / "model.ubj"
        model_file.write_bytes(_xgboost_ubjson_deep_before_counted_null_array_probe())

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch("ubjson.loadb") as mock_loadb,
        ):
            result = scan_model_directory_or_file(str(model_file), cache_enabled=False)

        assert result.success is False
        assert determine_exit_code(result) == 2
        _assert_inconclusive_metadata(result, model_file, "xgboost_ubj_preflight_incomplete")
        assert any("resource preflight could not complete" in str(issue.message) for issue in result.issues)
        mock_loadb.assert_not_called()

    def test_extensionless_ubjson_late_model_key_fails_closed_in_routing(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model"
        model_file.write_bytes(
            _xgboost_ubjson_probe(learner_padding=XGBoostScanner._UBJSON_PROBE_READ_BYTES, malicious=True)
        )

        result = scan_model_directory_or_file(str(model_file), cache_enabled=False)

        assert determine_exit_code(result) == 2
        assert "xgboost" not in result.scanner_names
        _assert_inconclusive_metadata(result, model_file, "xgboost_ubjson_routing_incomplete")
        assert any("routing was inconclusive" in str(issue.message) for issue in result.issues)

    def test_extensionless_ubjson_late_learner_fails_closed_in_routing(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model"
        model_file.write_bytes(
            _xgboost_ubjson_probe(root_padding=XGBoostScanner._UBJSON_PROBE_READ_BYTES, malicious=True)
        )

        result = scan_model_directory_or_file(str(model_file), cache_enabled=False)

        assert determine_exit_code(result) == 2
        assert "xgboost" not in result.scanner_names
        _assert_inconclusive_metadata(result, model_file, "xgboost_ubjson_routing_incomplete")
        assert any("routing was inconclusive" in str(issue.message) for issue in result.issues)

    def test_extensionless_ubjson_root_noops_before_late_learner_fail_closed_in_routing(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model"
        payload = (
            b"{"
            + (b"N" * XGBoostScanner._UBJSON_PROBE_READ_BYTES)
            + _ubjson_key(b"learner")
            + b"{"
            + _ubjson_key(b"learner_model_param")
            + b"{}"
            + b"}"
            + b"}"
        )
        model_file.write_bytes(payload)

        result = scan_model_directory_or_file(str(model_file), cache_enabled=False)

        assert determine_exit_code(result) == 2
        assert "xgboost" not in result.scanner_names
        _assert_inconclusive_metadata(result, model_file, "xgboost_ubjson_routing_incomplete")

    def test_extensionless_ubjson_noops_before_truncated_root_header_fail_closed_in_routing(
        self, tmp_path: Path
    ) -> None:
        model_file = tmp_path / "model"
        payload = (
            b"{"
            + (b"N" * (XGBoostScanner._UBJSON_PROBE_READ_BYTES - 2))
            + b"#U\x01"
            + _ubjson_key(b"learner")
            + b"{"
            + _ubjson_key(b"learner_model_param")
            + b"{}"
            + b"}"
        )
        model_file.write_bytes(payload)

        result = scan_model_directory_or_file(str(model_file), cache_enabled=False)

        assert determine_exit_code(result) == 2
        assert "xgboost" not in result.scanner_names
        _assert_inconclusive_metadata(result, model_file, "xgboost_ubjson_routing_incomplete")

    def test_extensionless_ubjson_noop_before_learner_fails_closed(self, tmp_path: Path) -> None:
        pytest.importorskip("ubjson", reason="ubjson not installed")
        model_file = tmp_path / "model"
        model_file.write_bytes(_xgboost_ubjson_probe(learner_noop=True, malicious=True))

        result = scan_model_directory_or_file(str(model_file), cache_enabled=False)

        assert determine_exit_code(result) == 2
        assert "xgboost" in result.scanner_names
        _assert_inconclusive_metadata(result, model_file, "xgboost_ubj_analysis_failed")
        assert any("Error analyzing XGBoost UBJ model" in str(issue.message) for issue in result.issues)

    def test_extensionless_ubjson_large_manifest_fails_closed_without_attribution(self, tmp_path: Path) -> None:
        ubjson = pytest.importorskip("ubjson", reason="ubjson not installed")
        model_file = tmp_path / "model"
        model_file.write_bytes(
            ubjson.dumpb(
                {
                    "learner": {
                        "metadata": "x" * XGBoostScanner._UBJSON_PROBE_READ_BYTES,
                        "note": "system(cpu)",
                    },
                    "version": [1],
                }
            )
        )

        result = scan_model_directory_or_file(str(model_file), cache_enabled=False)

        assert determine_exit_code(result) == 2
        assert "xgboost" not in result.scanner_names
        _assert_inconclusive_metadata(result, model_file, "xgboost_ubjson_routing_incomplete")
        assert not any("System call in JSON" in str(issue.message) for issue in result.issues)

    def test_binary_read_failure_core_is_operational_not_security_finding(self, tmp_path: Path) -> None:
        binary_file = tmp_path / "unreadable.bst"
        binary_file.write_bytes(b"binf" + (b"\0" * 64))

        with patch.object(XGBoostScanner, "_scan_binary_model", side_effect=OSError("forced binary read failure")):
            result = scan_model_directory_or_file(str(binary_file), cache_enabled=False)

        assert result.success is False
        assert determine_exit_code(result) == 2
        _assert_inconclusive_metadata(result, binary_file, "xgboost_read_failed")
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    def test_sentencepiece_tokenizer_model_core_is_not_xgboost_false_positive(self, tmp_path: Path) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(_sentencepiece_model_proto())

        direct = scan_file(str(tokenizer_model), config={"cache_enabled": False})
        aggregate = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

        assert direct.success is True
        assert direct.scanner_name == "unknown"
        assert "xgboost" not in aggregate.scanner_names
        assert determine_exit_code(aggregate) == 0
        assert not any(issue.rule_code == "S1004" for issue in aggregate.issues)

    @pytest.mark.parametrize("archive_kind", ["zip", "tar"])
    def test_sentencepiece_tokenizer_model_nested_archive_is_not_xgboost_false_positive(
        self, tmp_path: Path, archive_kind: str
    ) -> None:
        member_name = "models/tokenizer.model"
        archive_file = tmp_path / f"tokenizer-bundle.{archive_kind}"
        payload = _sentencepiece_model_proto()
        if archive_kind == "zip":
            with zipfile.ZipFile(archive_file, "w") as archive:
                archive.writestr(member_name, payload)
            direct_archive = ZipScanner({"cache_enabled": False}).scan(str(archive_file))
        else:
            with tarfile.open(archive_file, "w") as archive:
                info = tarfile.TarInfo(member_name)
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            direct_archive = TarScanner({"cache_enabled": False}).scan(str(archive_file))

        aggregate = scan_model_directory_or_file(str(archive_file), cache_enabled=False)

        assert direct_archive.success is True
        assert not any(issue.rule_code == "S1004" for issue in direct_archive.issues)
        _assert_no_xgboost_s1004(aggregate)

    def test_sentencepiece_tokenizer_model_cli_xgboost_selection_is_not_false_positive(self, tmp_path: Path) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(_sentencepiece_model_proto())

        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--no-cache", "--format", "json", "--scanners", "xgboost", str(tmp_path)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)

        assert cli_result.exit_code == 0
        assert "xgboost" not in cli_payload.get("scanner_names", [])
        assert not any(issue.get("rule_code") == "S1004" for issue in cli_payload.get("issues", []))

    def test_extensionless_sentencepiece_tokenizer_core_is_not_xgboost_false_positive(self, tmp_path: Path) -> None:
        tokenizer_model = tmp_path / "tokenizer"
        tokenizer_model.write_bytes(_sentencepiece_model_proto())

        direct = scan_file(str(tokenizer_model), config={"cache_enabled": False})
        aggregate = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

        assert detect_file_format(str(tokenizer_model)) == "unknown"
        assert detect_file_format_from_magic(str(tokenizer_model)) == "unknown"
        assert detect_file_format_for_skip_filter(str(tokenizer_model)) == "unknown"
        assert direct.success is True
        assert direct.scanner_name == "unknown"
        _assert_no_xgboost_s1004(aggregate)

    @pytest.mark.parametrize("payload_factory", _SENTENCEPIECE_SEMANTIC_MALFORMED_FACTORIES)
    def test_extensionless_malformed_sentencepiece_model_fails_closed_without_xgboost(
        self, tmp_path: Path, payload_factory: Callable[[], bytes]
    ) -> None:
        tokenizer_model = tmp_path / "tokenizer"
        tokenizer_model.write_bytes(payload_factory())
        expected_format = file_detection.SENTENCEPIECE_MODEL_PROTO_INCONCLUSIVE_FORMAT
        expected_reason = "sentencepiece_model_proto_routing_incomplete"

        direct = scan_file(str(tokenizer_model), config={"cache_enabled": False})
        aggregate = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
        streaming = scan_model_streaming(
            file_generator=iterate_files_streaming(tmp_path),
            scan_root=str(tmp_path),
            delete_after_scan=False,
            cache_enabled=False,
            skip_file_types=True,
        )
        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--stream", "--no-cache", "--format", "json", str(tmp_path)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)

        assert detect_file_format(str(tokenizer_model)) == expected_format
        assert detect_file_format_from_magic(str(tokenizer_model)) == expected_format
        assert detect_file_format_for_skip_filter(str(tokenizer_model)) == expected_format
        assert direct.success is False
        assert direct.scanner_name == "unknown"
        assert expected_reason in direct.metadata["scan_outcome_reasons"]
        assert not any(issue.rule_code == "S1004" for issue in direct.issues)
        assert "xgboost" not in aggregate.scanner_names
        assert "xgboost" not in streaming.scanner_names
        _assert_inconclusive_metadata(aggregate, tokenizer_model, expected_reason)
        _assert_inconclusive_metadata(streaming, tokenizer_model, expected_reason)
        assert determine_exit_code(aggregate) == 2
        assert determine_exit_code(streaming) == 2
        assert cli_result.exit_code == 2
        assert "xgboost" not in cli_payload.get("scanner_names", [])
        assert any(
            expected_reason in issue.get("details", {}).get("scan_outcome_reason", "")
            or "SentencePiece ModelProto routing was inconclusive" in issue.get("message", "")
            for issue in cli_payload.get("issues", [])
        )

    def test_model_card_text_mentions_do_not_trigger_xgboost_sentencepiece_routing(self, tmp_path: Path) -> None:
        model_card = tmp_path / "README.md"
        model_card.write_text(
            "This repository ships a SentencePiece tokenizer.model file. "
            "The words learner and version are documentation, not an XGBoost model.",
            encoding="utf-8",
        )

        result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

        assert determine_exit_code(result) == 0
        assert "xgboost" not in result.scanner_names
        assert not any(issue.rule_code == "S1004" for issue in result.issues)

    def test_sentencepiece_payload_with_xgboost_only_suffix_still_fails_closed(self, tmp_path: Path) -> None:
        deceptive_model = tmp_path / "tokenizer.bst"
        deceptive_model.write_bytes(_sentencepiece_model_proto())

        result = scan_file(str(deceptive_model), config={"cache_enabled": False})

        assert result.success is False
        assert result.scanner_name == "xgboost"
        assert "xgboost_binary_structure_unrecognized" in result.metadata["scan_outcome_reasons"]
        assert any(issue.rule_code == "S1004" for issue in result.issues)

    def test_sentencepiece_ownership_rechecks_same_path_replacement(self, tmp_path: Path) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        valid_tokenizer = _sentencepiece_model_proto()
        tokenizer_model.write_bytes(valid_tokenizer)
        original_stat = tokenizer_model.stat()

        valid_result = scan_file(str(tokenizer_model), config={"cache_enabled": False})

        assert valid_result.success is True
        assert valid_result.scanner_name == "unknown"

        replacement = b"custom xgboost binary gbtree reg:squarederror"
        tokenizer_model.write_bytes(replacement.ljust(len(valid_tokenizer), b"\0"))
        os.utime(tokenizer_model, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

        replaced_result = scan_file(str(tokenizer_model), config={"cache_enabled": False})

        assert replaced_result.success is False
        assert replaced_result.scanner_name == "xgboost"
        assert "xgboost_binary_structure_unrecognized" in replaced_result.metadata["scan_outcome_reasons"]
        assert any(issue.rule_code == "S1004" for issue in replaced_result.issues)

    def test_sentencepiece_model_with_proto2_default_unknown_metadata_is_not_xgboost_false_positive(
        self, tmp_path: Path
    ) -> None:
        # Synthetic regression for HuggingFaceH4/zephyr-7b-beta@892b3d7... tokenizer.model.
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(_sentencepiece_model_proto_with_default_unknown_metadata())

        direct = scan_file(str(tokenizer_model), config={"cache_enabled": False})
        aggregate = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
        streaming = scan_model_streaming(
            file_generator=iterate_files_streaming(tmp_path),
            scan_root=str(tmp_path),
            delete_after_scan=False,
            cache_enabled=False,
            skip_file_types=True,
        )
        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--stream", "--no-cache", "--format", "json", str(tmp_path)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)

        assert direct.success is True
        assert direct.scanner_name == "unknown"
        _assert_no_xgboost_s1004(aggregate)
        _assert_no_xgboost_s1004(streaming)
        assert cli_result.exit_code == 0
        assert "xgboost" not in cli_payload.get("scanner_names", [])
        assert not any(issue.get("rule_code") == "S1004" for issue in cli_payload.get("issues", []))

    def test_sentencepiece_model_with_repeated_trainer_spec_merge_is_not_xgboost_false_positive(
        self, tmp_path: Path
    ) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(_sentencepiece_model_proto_with_split_trainer_spec_metadata())

        direct = scan_file(str(tokenizer_model), config={"cache_enabled": False})
        aggregate = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
        streaming = scan_model_streaming(
            file_generator=iterate_files_streaming(tmp_path),
            scan_root=str(tmp_path),
            delete_after_scan=False,
            cache_enabled=False,
            skip_file_types=True,
        )
        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--stream", "--no-cache", "--format", "json", str(tmp_path)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)

        assert direct.success is True
        assert direct.scanner_name == "unknown"
        _assert_no_xgboost_s1004(aggregate)
        _assert_no_xgboost_s1004(streaming)
        assert cli_result.exit_code == 0
        assert "xgboost" not in cli_payload.get("scanner_names", [])
        assert not any(issue.get("rule_code") == "S1004" for issue in cli_payload.get("issues", []))

    @pytest.mark.parametrize("archive_kind", ["zip", "tar", "gz"])
    def test_archived_sentencepiece_repeated_trainer_spec_merge_is_not_xgboost_false_positive(
        self, tmp_path: Path, archive_kind: str
    ) -> None:
        member_name = "models/tokenizer.model"
        archive_file = _write_sentencepiece_archive(
            tmp_path,
            archive_kind,
            member_name,
            _sentencepiece_model_proto_with_split_trainer_spec_metadata(),
        )

        result = scan_model_directory_or_file(str(archive_file), cache_enabled=False)
        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--no-cache", "--format", "json", str(archive_file)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)

        assert determine_exit_code(result) == 0
        assert "xgboost" not in result.scanner_names
        assert not any(issue.rule_code == "S1004" for issue in result.issues)
        assert cli_result.exit_code == 0
        assert "xgboost" not in cli_payload.get("scanner_names", [])
        assert not any(issue.get("rule_code") == "S1004" for issue in cli_payload.get("issues", []))

    def test_sentencepiece_model_with_trainer_varint_field_52_is_not_xgboost_false_positive(
        self, tmp_path: Path
    ) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(_sentencepiece_model_proto_with_trainer_varint_field_52())

        direct = scan_file(str(tokenizer_model), config={"cache_enabled": False})
        aggregate = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
        streaming = scan_model_streaming(
            file_generator=iterate_files_streaming(tmp_path),
            scan_root=str(tmp_path),
            delete_after_scan=False,
            cache_enabled=False,
            skip_file_types=True,
        )
        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--stream", "--no-cache", "--format", "json", str(tmp_path)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)

        assert direct.success is True
        assert direct.scanner_name == "unknown"
        _assert_no_xgboost_s1004(aggregate)
        _assert_no_xgboost_s1004(streaming)
        assert cli_result.exit_code == 0
        assert "xgboost" not in cli_payload.get("scanner_names", [])
        assert not any(issue.get("rule_code") == "S1004" for issue in cli_payload.get("issues", []))

    def test_sentencepiece_model_with_trainer_string_field_54_is_not_xgboost_false_positive(
        self, tmp_path: Path
    ) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(_sentencepiece_model_proto_with_trainer_string_field_54())

        direct = scan_file(str(tokenizer_model), config={"cache_enabled": False})
        aggregate = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
        streaming = scan_model_streaming(
            file_generator=iterate_files_streaming(tmp_path),
            scan_root=str(tmp_path),
            delete_after_scan=False,
            cache_enabled=False,
            skip_file_types=True,
        )
        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--stream", "--no-cache", "--format", "json", str(tmp_path)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)

        assert direct.success is True
        assert direct.scanner_name == "unknown"
        _assert_no_xgboost_s1004(aggregate)
        _assert_no_xgboost_s1004(streaming)
        assert cli_result.exit_code == 0
        assert "xgboost" not in cli_payload.get("scanner_names", [])
        assert not any(issue.get("rule_code") == "S1004" for issue in cli_payload.get("issues", []))

    def test_large_real_sentencepiece_model_shape_is_not_tensorflow_or_xgboost_false_positive(
        self, tmp_path: Path
    ) -> None:
        # Mirrors baidu/NAVA@16c20287... Wan2.2-TI2V-5B/google/umt5-xxl/spiece.model:
        # a large SentencePiece ModelProto whose full payload exceeds the ownership read cap.
        tokenizer_model = tmp_path / "spiece.model"
        tokenizer_model.write_bytes(_large_real_sentencepiece_model_proto_shape())

        direct = scan_file(str(tokenizer_model), config={"cache_enabled": False})
        aggregate = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
        streaming = scan_model_streaming(
            file_generator=iterate_files_streaming(tmp_path),
            scan_root=str(tmp_path),
            delete_after_scan=False,
            cache_enabled=False,
            skip_file_types=True,
        )
        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--stream", "--no-cache", "--format", "json", str(tmp_path)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)

        assert tokenizer_model.stat().st_size > file_detection._SENTENCEPIECE_MODEL_PROTO_READ_BYTES
        assert detect_file_format(str(tokenizer_model)) == "unknown"
        assert detect_file_format_from_magic(str(tokenizer_model)) == "unknown"
        assert detect_file_format_for_skip_filter(str(tokenizer_model)) == "unknown"
        assert direct.success is True
        assert direct.scanner_name == "unknown"
        _assert_no_xgboost_s1004(aggregate)
        _assert_no_xgboost_s1004(streaming)
        assert cli_result.exit_code == 0
        assert "xgboost" not in cli_payload.get("scanner_names", [])
        assert not any(issue.get("rule_code") == "S1004" for issue in cli_payload.get("issues", []))

    def test_large_sentencepiece_ownership_probe_skips_unsampled_piece_text(self) -> None:
        class _CountingBytesIO(io.BytesIO):
            def __init__(self, payload: bytes) -> None:
                super().__init__(payload)
                self.bytes_read = 0

            def read(self, size: int | None = -1) -> bytes:
                payload = super().read(size)
                self.bytes_read += len(payload)
                return payload

        payload = _large_real_sentencepiece_model_proto_shape()
        stream = _CountingBytesIO(payload)

        route = file_detection._classify_sentencepiece_model_proto_stream(stream, len(payload))

        assert len(payload) > file_detection._SENTENCEPIECE_MODEL_PROTO_READ_BYTES
        assert route == "strong"
        assert stream.bytes_read < file_detection._SENTENCEPIECE_MODEL_PROTO_READ_BYTES

    def test_sentencepiece_ownership_probe_reuses_direct_scan_route(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(_large_real_sentencepiece_model_proto_shape())
        original_classifier = file_detection._classify_sentencepiece_model_proto_stream
        calls = 0

        def counting_classifier(
            stream: Any,
            file_size: int,
            *,
            max_decoded_piece_text_bytes: int = file_detection._SENTENCEPIECE_MODEL_PROTO_READ_BYTES,
        ) -> Any:
            nonlocal calls
            calls += 1
            return original_classifier(
                stream,
                file_size,
                max_decoded_piece_text_bytes=max_decoded_piece_text_bytes,
            )

        file_detection._classify_sentencepiece_model_proto_file_cached.cache_clear()
        monkeypatch.setattr(file_detection, "_classify_sentencepiece_model_proto_stream", counting_classifier)

        direct = scan_file(str(tokenizer_model), config={"cache_enabled": False})

        assert direct.success is True
        assert direct.scanner_name == "unknown"
        assert calls == 1

    @pytest.mark.parametrize("fixture_name", _SENTENCEPIECE_OFFICIAL_FIXTURES)
    def test_dependency_sentencepiece_model_with_disabled_specials_is_not_xgboost_false_positive(
        self, tmp_path: Path, fixture_name: str
    ) -> None:
        tokenizer_model = _write_official_sentencepiece_fixture(tmp_path, fixture_name)

        direct = scan_file(str(tokenizer_model), config={"cache_enabled": False})
        aggregate = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
        streaming = scan_model_streaming(
            file_generator=iterate_files_streaming(tmp_path),
            scan_root=str(tmp_path),
            delete_after_scan=False,
            cache_enabled=False,
            skip_file_types=True,
        )
        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--stream", "--no-cache", "--format", "json", str(tmp_path)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)

        assert direct.success is True
        assert direct.scanner_name == "unknown"
        _assert_no_xgboost_s1004(aggregate)
        _assert_no_xgboost_s1004(streaming)
        assert cli_result.exit_code == 0
        assert "xgboost" not in cli_payload.get("scanner_names", [])
        assert not any(issue.get("rule_code") == "S1004" for issue in cli_payload.get("issues", []))

    @pytest.mark.parametrize("archive_kind", ["zip", "tar", "tar.gz", "gz"])
    def test_archived_sentencepiece_model_is_not_xgboost_false_positive(
        self, tmp_path: Path, archive_kind: str
    ) -> None:
        archive_file = _write_sentencepiece_archive(
            tmp_path,
            archive_kind,
            "models/tokenizer.model",
            _sentencepiece_model_proto(),
        )

        result = scan_model_directory_or_file(str(archive_file), cache_enabled=False)
        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--no-cache", "--format", "json", str(archive_file)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)

        assert determine_exit_code(result) == 0
        assert "xgboost" not in result.scanner_names
        assert not any(issue.rule_code == "S1004" for issue in result.issues)
        assert cli_result.exit_code == 0
        assert "xgboost" not in cli_payload.get("scanner_names", [])
        assert not any(issue.get("rule_code") == "S1004" for issue in cli_payload.get("issues", []))

    @pytest.mark.parametrize("archive_kind", ["zip", "tar", "tar.gz", "gz"])
    @pytest.mark.parametrize("payload_factory", _SENTENCEPIECE_SEMANTIC_MALFORMED_FACTORIES)
    def test_extensionless_archived_malformed_sentencepiece_model_fails_closed_without_xgboost(
        self, tmp_path: Path, archive_kind: str, payload_factory: Callable[[], bytes]
    ) -> None:
        member_name = "models/tokenizer"
        archive_file = _write_sentencepiece_archive(tmp_path, archive_kind, member_name, payload_factory())
        expected_location = f"{archive_file} -> tokenizer" if archive_kind == "gz" else f"{archive_file}:{member_name}"
        expected_reason = "sentencepiece_model_proto_routing_incomplete"

        result = scan_model_directory_or_file(str(archive_file), cache_enabled=False)
        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--no-cache", "--format", "json", str(archive_file)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)
        metadata = result.file_metadata[str(archive_file)]

        assert determine_exit_code(result) == 2
        assert "xgboost" not in result.scanner_names
        assert expected_reason in metadata.get("scan_outcome_reasons", [])
        assert any(
            issue.location == expected_location
            and "SentencePiece ModelProto routing was inconclusive" in str(issue.message)
            for issue in result.issues
        )
        assert cli_result.exit_code == 2
        assert "xgboost" not in cli_payload.get("scanner_names", [])
        assert any(
            issue.get("location") == expected_location
            and "SentencePiece ModelProto routing was inconclusive" in issue.get("message", "")
            for issue in cli_payload.get("issues", [])
        )

    def test_malformed_sentencepiece_like_model_still_fails_closed_in_xgboost(self, tmp_path: Path) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(b"\x0a\x0e\x0a\x05<unk>\x15\x00" + (b"\0" * 64))

        result = scan_file(str(tokenizer_model), config={"cache_enabled": False})

        assert result.success is False
        assert result.scanner_name == "xgboost"
        assert "xgboost_binary_structure_unrecognized" in result.metadata["scan_outcome_reasons"]
        assert any(issue.rule_code == "S1004" for issue in result.issues)

    @pytest.mark.parametrize("payload_factory", _SENTENCEPIECE_SEMANTIC_MALFORMED_FACTORIES)
    def test_semantically_malformed_sentencepiece_model_still_fails_closed_in_xgboost(
        self, tmp_path: Path, payload_factory: Callable[[], bytes]
    ) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(payload_factory())

        direct = scan_file(str(tokenizer_model), config={"cache_enabled": False})
        aggregate = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
        streaming = scan_model_streaming(
            file_generator=iterate_files_streaming(tmp_path),
            scan_root=str(tmp_path),
            delete_after_scan=False,
            cache_enabled=False,
            skip_file_types=True,
        )
        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--stream", "--no-cache", "--format", "json", str(tmp_path)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)

        assert direct.success is False
        assert direct.scanner_name == "xgboost"
        assert "xgboost_binary_structure_unrecognized" in direct.metadata["scan_outcome_reasons"]
        assert any(issue.rule_code == "S1004" for issue in direct.issues)
        _assert_xgboost_s1004(aggregate)
        _assert_xgboost_s1004(streaming)
        assert cli_result.exit_code == 2
        assert "xgboost" in cli_payload.get("scanner_names", [])
        assert any(issue.get("rule_code") == "S1004" for issue in cli_payload.get("issues", []))

    @pytest.mark.parametrize("archive_kind", ["zip", "tar", "tar.gz", "gz"])
    @pytest.mark.parametrize("payload_factory", _SENTENCEPIECE_SEMANTIC_MALFORMED_FACTORIES)
    def test_archived_semantically_malformed_sentencepiece_model_still_fails_closed_in_xgboost(
        self, tmp_path: Path, archive_kind: str, payload_factory: Callable[[], bytes]
    ) -> None:
        member_name = "models/tokenizer.model"
        archive_file = _write_sentencepiece_archive(tmp_path, archive_kind, member_name, payload_factory())

        result = scan_model_directory_or_file(str(archive_file), cache_enabled=False)
        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--no-cache", "--format", "json", str(archive_file)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)
        expected_location = (
            f"{archive_file} -> tokenizer.model" if archive_kind == "gz" else f"{archive_file}:{member_name}"
        )

        assert determine_exit_code(result) == 2
        assert any(issue.rule_code == "S1004" and issue.location == expected_location for issue in result.issues)
        assert cli_result.exit_code == 2
        assert any(
            issue.get("rule_code") == "S1004" and issue.get("location") == expected_location
            for issue in cli_payload.get("issues", [])
        )

    @pytest.mark.parametrize("archive_kind", ["zip", "tar", "tar.gz", "gz"])
    @pytest.mark.parametrize(
        "tail",
        [
            pytest.param(_unknown_sentencepiece_field(pickle.dumps({"payload": "pickle"}, protocol=4)), id="pickle"),
            pytest.param(_unknown_sentencepiece_field(_small_zip_payload()), id="zip"),
        ],
    )
    def test_archived_sentencepiece_unknown_field_payload_still_fails_closed_in_xgboost(
        self, tmp_path: Path, archive_kind: str, tail: bytes
    ) -> None:
        member_name = "models/tokenizer.model"
        archive_file = _write_sentencepiece_archive(
            tmp_path,
            archive_kind,
            member_name,
            _sentencepiece_model_proto() + tail,
        )
        expected_location = (
            f"{archive_file} -> tokenizer.model" if archive_kind == "gz" else f"{archive_file}:{member_name}"
        )

        result = scan_model_directory_or_file(str(archive_file), cache_enabled=False)
        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--no-cache", "--format", "json", str(archive_file)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)

        assert determine_exit_code(result) == 2
        assert any(issue.rule_code == "S1004" and issue.location == expected_location for issue in result.issues)
        assert cli_result.exit_code == 2
        assert any(
            issue.get("rule_code") == "S1004" and issue.get("location") == expected_location
            for issue in cli_payload.get("issues", [])
        )

    @pytest.mark.parametrize("tail", _SENTENCEPIECE_MALFORMED_TAILS)
    def test_sentencepiece_model_with_malformed_tail_still_fails_closed_in_xgboost(
        self, tmp_path: Path, tail: bytes
    ) -> None:
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(_sentencepiece_model_proto() + tail)

        direct = scan_file(str(tokenizer_model), config={"cache_enabled": False})
        aggregate = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
        streaming = scan_model_streaming(
            file_generator=iterate_files_streaming(tmp_path),
            scan_root=str(tmp_path),
            delete_after_scan=False,
            cache_enabled=False,
            skip_file_types=True,
        )
        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--stream", "--no-cache", "--format", "json", str(tmp_path)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)

        assert direct.success is False
        assert direct.scanner_name == "xgboost"
        assert "xgboost_binary_structure_unrecognized" in direct.metadata["scan_outcome_reasons"]
        assert any(issue.rule_code == "S1004" for issue in direct.issues)
        _assert_xgboost_s1004(aggregate)
        _assert_xgboost_s1004(streaming)
        assert cli_result.exit_code == 2
        assert "xgboost" in cli_payload.get("scanner_names", [])
        assert any(issue.get("rule_code") == "S1004" for issue in cli_payload.get("issues", []))

    def test_capped_sentencepiece_prefix_with_unread_tail_still_fails_closed_in_xgboost(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        prefix = _sentencepiece_model_proto()
        tokenizer_model = tmp_path / "tokenizer.model"
        tokenizer_model.write_bytes(prefix + b"\x12\x80")
        monkeypatch.setattr(file_detection, "_SENTENCEPIECE_MODEL_PROTO_READ_BYTES", len(prefix))

        direct = scan_file(str(tokenizer_model), config={"cache_enabled": False})
        aggregate = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
        streaming = scan_model_streaming(
            file_generator=iterate_files_streaming(tmp_path),
            scan_root=str(tmp_path),
            delete_after_scan=False,
            cache_enabled=False,
            skip_file_types=True,
        )
        cli_result = CliRunner().invoke(
            cli,
            ["scan", "--stream", "--no-cache", "--format", "json", str(tmp_path)],
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
        )
        cli_payload = parse_click_json_output(cli_result.output)

        assert direct.success is False
        assert direct.scanner_name == "xgboost"
        assert "xgboost_binary_structure_unrecognized" in direct.metadata["scan_outcome_reasons"]
        assert any(issue.rule_code == "S1004" for issue in direct.issues)
        _assert_xgboost_s1004(aggregate)
        _assert_xgboost_s1004(streaming)
        assert cli_result.exit_code == 2
        assert "xgboost" in cli_payload.get("scanner_names", [])
        assert any(issue.get("rule_code") == "S1004" for issue in cli_payload.get("issues", []))

    def test_xgboost_binary_model_extension_still_scans_cleanly(self, tmp_path: Path) -> None:
        binary_model = tmp_path / "native.model"
        binary_model.write_bytes(b"binf" + (b"\0" * 60))

        result = scan_file(str(binary_model), config={"cache_enabled": False})

        assert result.success is True
        assert result.scanner_name == "xgboost"
        assert not result.issues

    def test_xgboost_shaped_model_extension_still_fails_closed(
        self, tmp_path: Path, valid_xgboost_json: dict[str, Any]
    ) -> None:
        valid_xgboost_json["learner"]["malicious_code"] = "os.system('touch pwned')"
        model_file = tmp_path / "tokenizer.model"
        model_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = scan_file(str(model_file), config={"cache_enabled": False})

        assert result.success is False
        assert result.scanner_name == "xgboost"
        assert "xgboost_binary_structure_unrecognized" in result.metadata["scan_outcome_reasons"]
        assert any(issue.rule_code == "S1004" for issue in result.issues)

    def test_extensionless_ubjson_nested_zip_detects_malicious_content(
        self, tmp_path: Path, valid_xgboost_json: dict[str, Any]
    ) -> None:
        ubjson = pytest.importorskip("ubjson", reason="ubjson not installed")
        valid_xgboost_json["learner"]["malicious_code"] = "os.system('touch pwned')"
        archive_file = tmp_path / "bundle.zip"
        with zipfile.ZipFile(archive_file, "w") as archive:
            archive.writestr("models/model", ubjson.dumpb(valid_xgboost_json))

        result = scan_model_directory_or_file(str(archive_file), cache_enabled=False)

        assert determine_exit_code(result) == 1
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and issue.location == f"{archive_file}:models/model"
            and "System call in JSON" in str(issue.message)
            for issue in result.issues
        )

    @pytest.mark.parametrize(
        ("archive_kind", "member_name"),
        [
            ("zip", "models/model.dat"),
            ("zip", "models/model.json"),
            ("zip", "models/model.onnx"),
            ("tar", "models/model.dat"),
            ("tar", "models/model.json"),
            ("tar", "models/model.safetensors"),
        ],
    )
    def test_misleading_suffix_nested_ubjson_detects_malicious_content(
        self,
        tmp_path: Path,
        valid_xgboost_json: dict[str, Any],
        archive_kind: str,
        member_name: str,
    ) -> None:
        ubjson = pytest.importorskip("ubjson", reason="ubjson not installed")
        valid_xgboost_json["learner"]["malicious_code"] = "os.system('touch pwned')"
        payload = ubjson.dumpb(valid_xgboost_json)
        archive_file = tmp_path / f"bundle.{archive_kind}"
        if archive_kind == "zip":
            with zipfile.ZipFile(archive_file, "w") as archive:
                archive.writestr(member_name, payload)
        else:
            with tarfile.open(archive_file, "w") as archive:
                info = tarfile.TarInfo(member_name)
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))

        result = scan_model_directory_or_file(str(archive_file), cache_enabled=False)

        assert determine_exit_code(result) == 1
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and issue.location == f"{archive_file}:{member_name}"
            and "System call in JSON" in str(issue.message)
            for issue in result.issues
        )

    @pytest.mark.parametrize(
        ("archive_kind", "member_name"), [("zip", "models/model.json"), ("tar", "models/model.dat")]
    )
    def test_direct_archive_dispatch_routes_misleading_suffix_ubjson(
        self,
        tmp_path: Path,
        valid_xgboost_json: dict[str, Any],
        archive_kind: str,
        member_name: str,
    ) -> None:
        ubjson = pytest.importorskip("ubjson", reason="ubjson not installed")
        valid_xgboost_json["learner"]["malicious_code"] = "os.system('touch pwned')"
        payload = ubjson.dumpb(valid_xgboost_json)
        archive_file = tmp_path / f"direct.{archive_kind}"
        if archive_kind == "zip":
            with zipfile.ZipFile(archive_file, "w") as archive:
                archive.writestr(member_name, payload)
            result = ZipScanner({"cache_enabled": False}).scan(str(archive_file))
        else:
            with tarfile.open(archive_file, "w") as archive:
                info = tarfile.TarInfo(member_name)
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            result = TarScanner({"cache_enabled": False}).scan(str(archive_file))

        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and issue.location == f"{archive_file}:{member_name}"
            and "System call in JSON" in str(issue.message)
            for issue in result.issues
        )

    def test_malformed_nested_xgboost_json_core_fails_closed_and_is_uncached(
        self, tmp_path: Path, valid_xgboost_json: dict[str, Any]
    ) -> None:
        valid_xgboost_json["learner"]["gradient_booster"] = None
        json_file = tmp_path / "nested.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")
        cache_dir = tmp_path / "cache"

        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(json_file, cache_dir)

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 2
                assert "xgboost" in result.scanner_names
                _assert_inconclusive_metadata(result, json_file, "xgboost_json_structure_invalid")
                assert any("Invalid XGBoost JSON structure" in str(issue.message) for issue in result.issues)

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_malformed_xgboost_json_core_fails_closed_and_is_uncached(self, tmp_path: Path) -> None:
        json_file = tmp_path / "booster.json"
        json_file.write_text('{"version":[1,7,4],"learner":{"gradient_booster":')
        cache_dir = tmp_path / "cache"

        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(json_file, cache_dir)

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 2
                assert "xgboost" in result.scanner_names
                _assert_inconclusive_metadata(result, json_file, "xgboost_json_parse_failed")
                assert any("Invalid JSON format" in str(issue.message) for issue in result.issues)

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_missing_ubjson_core_fails_closed_and_is_uncached(self, tmp_path: Path) -> None:
        ubj_file = tmp_path / "model.ubj"
        ubj_file.write_bytes(b"\x7b\x55")
        cache_dir = tmp_path / "cache"

        reset_cache_manager()
        try:
            with patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=False):
                first, second = _scan_twice_with_cache(ubj_file, cache_dir)

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 2
                _assert_inconclusive_metadata(result, ubj_file, "xgboost_ubj_dependency_missing")
                assert any("Cannot scan UBJ file" in str(issue.message) for issue in result.issues)

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_undecodable_ubjson_core_is_inconclusive_not_security_finding(self, tmp_path: Path) -> None:
        pytest.importorskip("ubjson", reason="ubjson not installed")
        ubj_file = tmp_path / "undecodable.ubj"
        ubj_file.write_bytes(_xgboost_ubjson_probe())

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch("ubjson.loadb", side_effect=ValueError("unsupported native UBJSON encoding")),
        ):
            result = scan_model_directory_or_file(str(ubj_file), cache_enabled=False)

        assert result.success is False
        assert determine_exit_code(result) == 2
        _assert_inconclusive_metadata(result, ubj_file, "xgboost_ubj_analysis_failed")
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    @pytest.mark.parametrize("filename", ["model.bst", "model"])
    def test_missing_ubjson_for_content_routed_header_core_fails_closed_and_is_uncached(
        self, tmp_path: Path, filename: str
    ) -> None:
        bst_file = tmp_path / filename
        bst_file.write_bytes(_xgboost_ubjson_probe())
        cache_dir = tmp_path / "cache"

        reset_cache_manager()
        try:
            with patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=False):
                first, second = _scan_twice_with_cache(bst_file, cache_dir)

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 2
                assert "xgboost" in result.scanner_names
                _assert_inconclusive_metadata(result, bst_file, "xgboost_ubj_dependency_missing")
                assert any("Cannot scan UBJ file" in str(issue.message) for issue in result.issues)

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_pickle_spoof_core_preserves_pickle_scan_and_is_uncached(self, tmp_path: Path) -> None:
        spoof_file = tmp_path / "spoof.bst"
        spoof_file.write_bytes(pickle.dumps({"safe": True}, protocol=4))
        cache_dir = tmp_path / "cache"

        direct = scan_file(str(spoof_file), config={"cache_enabled": False})
        assert direct.success is False
        assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_pickle_spoof" in direct.metadata["scan_outcome_reasons"]

        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(spoof_file, cache_dir)

            for result in (first, second):
                assert determine_exit_code(result) == 1
                assert "pickle" in result.scanner_names
                _assert_inconclusive_metadata(result, spoof_file, "xgboost_binary_pickle_spoof")
                assert any(
                    issue.severity == IssueSeverity.WARNING and "pickle file with .bst extension" in str(issue.message)
                    for issue in result.issues
                )

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_directory_dedup_preserves_filename_sensitive_spoof_detection(self, tmp_path: Path) -> None:
        payload = pickle.dumps({"safe": True}, protocol=4)
        pickle_file = tmp_path / "same.pkl"
        spoof_file = tmp_path / "same.bst"
        pickle_file.write_bytes(payload)
        spoof_file.write_bytes(payload)

        result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

        spoof_issues = [issue for issue in result.issues if "pickle file with .bst extension" in str(issue.message)]
        assert result.files_scanned == 2
        assert determine_exit_code(result) == 1
        assert len(spoof_issues) == 1
        assert spoof_issues[0].location == str(spoof_file)
        assert (
            "xgboost_binary_pickle_spoof" in result.file_metadata[str(spoof_file)].model_dump()["scan_outcome_reasons"]
        )
        assert "xgboost_binary_pickle_spoof" not in result.file_metadata[str(pickle_file)].model_dump().get(
            "scan_outcome_reasons",
            [],
        )

    def test_generic_model_pickle_core_does_not_false_positive(self, tmp_path: Path) -> None:
        model_file = tmp_path / "safe.model"
        model_file.write_bytes(pickle.dumps({"safe": True}, protocol=4))

        result = scan_model_directory_or_file(str(model_file), cache_enabled=False)

        assert result.success is True
        assert determine_exit_code(result) == 0
        assert "pickle" in result.scanner_names
        assert not result.issues

    def test_tiny_binary_core_fails_closed_and_is_uncached(self, tmp_path: Path) -> None:
        binary_file = tmp_path / "tiny.bst"
        binary_file.write_bytes(b"abcdefghijklmnopqrstuvwxyzabcde")
        cache_dir = tmp_path / "cache"

        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(binary_file, cache_dir)

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 2
                _assert_inconclusive_metadata(result, binary_file, "xgboost_binary_structure_too_small")
                assert any("too small" in str(issue.message).lower() for issue in result.issues)

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_marker_only_xgboost_binary_core_fails_closed(self, tmp_path: Path) -> None:
        binary_file = tmp_path / "custom.bst"
        binary_file.write_bytes(b"custom xgboost binary gbtree reg:squarederror")

        result = scan_model_directory_or_file(str(binary_file), cache_enabled=False)

        assert result.success is False
        assert determine_exit_code(result) == 2
        assert "xgboost" in result.scanner_names
        _assert_inconclusive_metadata(result, binary_file, "xgboost_binary_structure_unrecognized")

    def test_binf_signature_core_does_not_false_positive(self, tmp_path: Path) -> None:
        binary_file = tmp_path / "signature.bst"
        binary_file.write_bytes(b"binf" + (b"\0" * 60) + b"gbtree appears outside first read window")

        result = scan_model_directory_or_file(str(binary_file), cache_enabled=False)

        assert result.success is True
        assert determine_exit_code(result) == 0
        assert "xgboost" in result.scanner_names
        assert not result.issues

    def test_headerless_legacy_binary_core_does_not_false_positive(self, tmp_path: Path) -> None:
        binary_file = tmp_path / "legacy.bst"
        binary_file.write_bytes(_headerless_legacy_binary_header())

        result = scan_model_directory_or_file(str(binary_file), cache_enabled=False)

        assert result.success is True
        assert determine_exit_code(result) == 0
        assert "xgboost" in result.scanner_names
        assert not result.issues

    def test_markerless_binary_core_fails_closed_and_is_uncached(self, tmp_path: Path) -> None:
        binary_file = tmp_path / "markerless.bst"
        binary_file.write_bytes(b"abcdefghijklmnopqrstuvwxyzabcdef")
        cache_dir = tmp_path / "cache"

        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(binary_file, cache_dir)

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 2
                _assert_inconclusive_metadata(result, binary_file, "xgboost_binary_structure_unrecognized")
                assert any("expected XGBoost binary signature" in str(issue.message) for issue in result.issues)

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()


class TestXGBoostScannerConfiguration:
    """Test XGBoost scanner configuration options."""

    def test_xgboost_loading_enabled(self, temp_dir):
        """Test enabling XGBoost loading."""
        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})
        assert loading_scanner.enable_xgb_loading is True


class TestXGBoostSecurityPatterns:
    """Test specific security vulnerability patterns."""

    def test_hex_encoded_data_detection(self, temp_dir, xgboost_scanner):
        """Test detection of hex-encoded data that could be shellcode."""
        malicious_json = {
            "version": [1, 0, 0],
            "learner": {
                "suspicious_field": "\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48",  # Hex pattern
                "another_field": "\\x90\\x90\\x90\\x90",  # NOP sled pattern
            },
        }

        json_file = temp_dir / "hex_encoded.json"
        json_file.write_text(json.dumps(malicious_json))

        result = xgboost_scanner.scan(str(json_file))

        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0
        assert any("Hex-encoded data" in str(issue.message) for issue in critical_issues)


class TestXGBoostPickleIntegration:
    """Test integration with pickle scanner for XGBoost pickle files."""

    def test_pickle_file_with_xgboost_extension_detected(self, temp_dir, xgboost_scanner):
        """Test that pickle files masquerading as XGBoost files are detected."""
        # Create a pickle file with XGBoost-related content
        xgb_mock = FakeBooster()
        pickle_data = pickle.dumps(xgb_mock)

        fake_bst = temp_dir / "xgb_model.bst"
        fake_bst.write_bytes(pickle_data)

        result = xgboost_scanner.scan(str(fake_bst))

        # Should detect file format spoofing
        assert any("pickle file" in str(issue.message) for issue in result.issues)
        assert result.success is False


# Integration tests (require actual dependencies)
@pytest.mark.integration
@pytest.mark.xgboost
class TestXGBoostScannerIntegration:
    """Integration tests requiring actual XGBoost/ubjson libraries."""

    def test_real_xgboost_model_creation_and_scan(self, temp_dir: Path) -> None:
        """Test scanning of a real XGBoost model."""
        pytest.importorskip("xgboost", minversion="1.0")
        import numpy as np
        import xgboost as xgb

        # Create a simple dataset and train a model
        X = np.random.randn(100, 3)
        y = np.random.randn(100)

        dtrain = xgb.DMatrix(X, label=y)
        params = {"objective": "reg:squarederror", "max_depth": 3, "eta": 0.1}
        model = xgb.train(params, dtrain, num_boost_round=5)

        # Save in different formats
        json_path = temp_dir / "real_model.json"
        bst_path = temp_dir / "real_model.bst"

        model.save_model(str(json_path))
        model.save_model(str(bst_path))

        # Scan both files
        scanner = XGBoostScanner()

        json_result = scanner.scan(str(json_path))
        bst_result = scanner.scan(str(bst_path))

        # JSON must scan successfully; a native UBJSON BST may exceed the optional
        # UBJSON decoder, which is incomplete coverage rather than a security finding.
        assert json_result.success

        json_critical = [i for i in json_result.issues if i.severity == IssueSeverity.CRITICAL]
        bst_critical = [i for i in bst_result.issues if i.severity == IssueSeverity.CRITICAL]

        assert len(json_critical) == 0, f"JSON model had critical issues: {json_critical}"
        assert len(bst_critical) == 0, f"BST model had critical issues: {bst_critical}"
        if not bst_result.success:
            assert bst_result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert "xgboost_ubj_analysis_failed" in bst_result.metadata["scan_outcome_reasons"]

    def test_real_ubj_format_scan(self, temp_dir, valid_xgboost_json):
        """Test scanning of real UBJ format."""
        ubjson = pytest.importorskip("ubjson")

        # Create UBJ file
        ubj_path = temp_dir / "model.ubj"
        ubj_data = ubjson.dumpb(valid_xgboost_json)
        ubj_path.write_bytes(ubj_data)

        scanner = XGBoostScanner()
        result = scanner.scan(str(ubj_path))

        assert result.success

        # Should successfully decode UBJ
        assert any("decoded successfully" in str(check.message) for check in result.checks)

        # Should not have critical issues for valid content (except analysis errors which are acceptable)
        critical_issues = [
            i for i in result.issues if i.severity == IssueSeverity.CRITICAL and "Error analyzing" not in str(i.message)
        ]
        assert len(critical_issues) == 0
