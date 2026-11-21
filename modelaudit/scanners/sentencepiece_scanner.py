"""Static SentencePiece ModelProto validation without loading a tokenizer."""

import os
import zipfile
from io import BytesIO
from typing import BinaryIO, ClassVar

from ..scanner_results import mark_inconclusive_scan_result
from ..scanner_selection import add_scanner_selection_skip_check, allows_zip_content_analysis, policy_from_config
from ..utils._path_hardening import _file_stat_matches
from ..utils.file.detection import (
    _SENTENCEPIECE_MODEL_PROTO_READ_BYTES,
    _classify_sentencepiece_model_proto_stream,
    is_sentencepiece_model_proto_file,
)
from .archive_dispatch import merge_executable_zip_container_findings
from .base import BaseScanner, IssueSeverity, ScanResult


class SentencePieceScanner(BaseScanner):
    name = "sentencepiece"
    description = "Validates SentencePiece tokenizer structure and vocabulary"
    supported_extensions: ClassVar[list[str]] = []

    @classmethod
    def can_handle(cls, path: str) -> bool:
        return is_sentencepiece_model_proto_file(path)

    def scan(self, path: str) -> ScanResult:
        result = self._create_scan_result_after_preflight(path)
        if not result.success:
            return result

        try:
            with open(path, "rb") as handle:
                before = os.fstat(handle.fileno())
                size = before.st_size
                if self.max_file_read_size > 0 and size > self.max_file_read_size:
                    raise ValueError(f"file exceeds the {self.max_file_read_size}-byte read limit")
                stream: BinaryIO = handle
                if size <= _SENTENCEPIECE_MODEL_PROTO_READ_BYTES:
                    payload = handle.read(size)
                    if len(payload) != size:
                        raise ValueError("file ended before its declared size")
                    stream = BytesIO(payload)
                valid = (
                    _classify_sentencepiece_model_proto_stream(
                        stream, size, max_decoded_piece_text_bytes=size, inspect_values=True
                    )
                    == "strong"
                )
                if not _file_stat_matches(before, os.fstat(handle.fileno())) or not _file_stat_matches(
                    before, os.stat(path), cross_view=True
                ):
                    raise ValueError("file changed during inspection")
                result.bytes_scanned = stream.tell()
        except (OSError, ValueError) as exc:
            valid = False
            message = f"Could not read SentencePiece tokenizer: {exc}"
        else:
            message = (
                "Validated SentencePiece vocabulary, trainer metadata and normalization tables"
                if valid
                else "SentencePiece structure or vocabulary is invalid, unsupported, or exceeds inspection limits"
            )

        result.add_check(
            name="SentencePiece Vocabulary Validation",
            passed=valid,
            message=message,
            severity=None if valid else IssueSeverity.INFO,
            location=path,
            details={} if valid else {"scan_outcome_reason": "sentencepiece_validation_incomplete"},
        )
        if not valid:
            mark_inconclusive_scan_result(result, "sentencepiece_validation_incomplete")
        selection = policy_from_config(self.config)
        if allows_zip_content_analysis(selection):
            merge_executable_zip_container_findings(path, result, self.config, context="SentencePiece ZIP polyglot")
        elif zipfile.is_zipfile(path):
            add_scanner_selection_skip_check(result, path, "zip", selection, context="SentencePiece ZIP polyglot")
        result.finish(success=valid and not result.has_errors)
        return result
