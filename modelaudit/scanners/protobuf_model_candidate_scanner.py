"""Tentative analysis for bounded protobuf model-routing candidates."""

from __future__ import annotations

import os
from typing import ClassVar

from ..scanner_selection import ScannerSelectionPolicy, allows_protobuf_model_candidate_analyzer, policy_from_config
from ..utils.file.detection import PROTOBUF_MODEL_CANDIDATE_FORMAT
from .base import FORMAT_VALIDATION_CONFIG_KEY, BaseScanner, ScanResult
from .coreml_scanner import CoreMLScanner
from .onnx_scanner import OnnxScanner


class ProtobufModelCandidateScanner(BaseScanner):
    """Try concrete protobuf model analyzers after bounded routing is exhausted."""

    name = "protobuf_model_candidate"
    description = "Tentatively analyzes bounded protobuf model candidates"
    supported_extensions: ClassVar[list[str]] = []

    @classmethod
    def can_handle(cls, path: str) -> bool:
        return os.path.isfile(path)

    def _scan_filename_owned_fallback(self, path: str, policy: ScannerSelectionPolicy) -> ScanResult | None:
        """Let a rejected neutral candidate retain normal config/file coverage."""
        from . import _registry

        scanner_class = _registry.get_scanner_for_path(
            path,
            scanner_selection=policy if policy.active else None,
        )
        if scanner_class is None or scanner_class is type(self):
            return None
        return scanner_class(config=self.config).scan_with_cache(path)

    def scan(self, path: str) -> ScanResult:
        candidate_config = dict(self.config)
        existing_validation = candidate_config.get(FORMAT_VALIDATION_CONFIG_KEY)
        format_validation = dict(existing_validation) if isinstance(existing_validation, dict) else {}
        format_validation["routed_format"] = PROTOBUF_MODEL_CANDIDATE_FORMAT
        candidate_config[FORMAT_VALIDATION_CONFIG_KEY] = format_validation
        scanner_selection = policy_from_config(candidate_config)

        incomplete_result: ScanResult | None = None
        last_rejection: ScanResult | None = None
        for scanner_id, scanner_class in (("onnx", OnnxScanner), ("coreml", CoreMLScanner)):
            if not allows_protobuf_model_candidate_analyzer(scanner_selection, scanner_id):
                continue
            result = scanner_class(config=candidate_config).scan(path)
            if result.scanner_name != "unknown":
                return result
            if not result.success:
                incomplete_result = incomplete_result or result
                continue
            last_rejection = result

        fallback_result = self._scan_filename_owned_fallback(path, scanner_selection)
        if fallback_result is not None:
            return fallback_result
        if incomplete_result is not None:
            return incomplete_result
        if last_rejection is None:  # pragma: no cover - routing filters unusable selections
            result = self._create_result()
            result.scanner_name = "unknown"
            result.metadata["tentative_protobuf_candidate_unanalyzed"] = "scanner_selection_excluded_analyzers"
            result.finish(success=True)
            return result
        return last_rejection
