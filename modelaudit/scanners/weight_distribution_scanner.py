"""Scanner for detecting anomalous weight distributions in model files."""

import inspect
import math
import numbers
import os
import zipfile
from contextlib import suppress
from typing import Any, BinaryIO, ClassVar

from ..scanner_results import mark_inconclusive_scan_result
from .base import BaseScanner, IssueSeverity, ScanResult, logger
from .zip_scanner import ZipPreflightRejected

_ANALYSIS_INCONCLUSIVE_REASON = "weight_distribution_analysis_incomplete"
_FINAL_LAYER_NAME_PATTERNS = ("fc", "classifier", "head", "output", "final", "dense")
_ZIP_MEMBER_READ_CHUNK_SIZE = 64 * 1024
_MAX_PICKLE_METADATA_BYTES = 10 * 1024 * 1024
_DEFAULT_MAX_TENSOR_BYTES = 100 * 1024 * 1024
_DEFAULT_MAX_TOTAL_TENSOR_BYTES = 512 * 1024 * 1024
_ESTIMATED_PICKLE_OBJECT_BYTES = 64
_MAX_RESTRICTED_PICKLE_BYTES = 10 * 1024 * 1024
_MAX_RESTRICTED_PICKLE_NODES = 1_000_000
_MAX_RESTRICTED_PICKLE_OPCODES = 500_000
_MAX_RESTRICTED_PICKLE_MEMO_ENTRIES = 100_000
_MAX_NUMERIC_SCALAR_BYTES = 16
_MIN_NUMPY_ARRAY_BUDGET_BYTES = 256
_EXTREME_WEIGHT_MIN_EFFECT_RATIO = 2.0
_EXTREME_WEIGHT_MIN_PER_OUTPUT = 5
_EXTREME_WEIGHT_LOCALIZATION_MIN_PER_OUTPUT = 2
_EXTREME_WEIGHT_ROBUST_MAD_MULTIPLIER = 30.0
_EXTREME_WEIGHT_ROBUST_SUPPORT_MAD_MULTIPLIER = 10.0
_EXTREME_WEIGHT_MIN_ROBUST_TAIL_CONCENTRATION = 0.5
_EXTREME_WEIGHT_CLASSICAL_SUPPORT_STD_MULTIPLIER = 0.5
_EXTREME_WEIGHT_MIN_CLASSICAL_TAIL_CONCENTRATION = 0.5
_EXTREME_WEIGHT_ROBUST_FALLBACK_MIN_PER_OUTPUT = 5
_NORMAL_MAD_SCALE_FACTOR = 1.4826
_EXTREME_WEIGHT_ANALYSIS_CHUNK_BYTES = 8 * 1024 * 1024
_EXTREME_WEIGHT_ROBUST_SAMPLE_SIZE = 256 * 1024
_EXTREME_WEIGHT_OUTPUT_SCRATCH_ARRAYS = 20
_OUTPUT_NORM_ROBUST_Z_THRESHOLD = 10.0
_PICKLE_OBJECT_OPCODES = frozenset(
    {
        "BINBYTES",
        "BINBYTES8",
        "BINFLOAT",
        "BININT",
        "BININT1",
        "BININT2",
        "BINSTRING",
        "BINUNICODE",
        "BINUNICODE8",
        "BYTEARRAY8",
        "DICT",
        "EMPTY_DICT",
        "EMPTY_LIST",
        "EMPTY_SET",
        "EMPTY_TUPLE",
        "FLOAT",
        "FROZENSET",
        "INT",
        "LIST",
        "LONG",
        "LONG1",
        "LONG4",
        "NEWFALSE",
        "NEWTRUE",
        "NONE",
        "SHORT_BINBYTES",
        "SHORT_BINSTRING",
        "SHORT_BINUNICODE",
        "STRING",
        "TUPLE",
        "TUPLE1",
        "TUPLE2",
        "TUPLE3",
        "UNICODE",
    }
)
_ADDITIVE_EXTRACTION_DETAIL_KEYS = frozenset(
    {"external_reference_tensors", "oversized_tensors", "tensor_read_failures"}
)


class WeightDistributionScanner(BaseScanner):
    """Scanner that detects anomalous weight distributions potentially indicating trojaned models"""

    name = "weight_distribution"
    description = "Analyzes weight distributions to detect potential backdoors or trojans"
    supported_extensions: ClassVar[list[str]] = [
        ".pt",
        ".pth",
        ".h5",
        ".keras",
        ".hdf5",
        ".pb",
        ".onnx",
        # Note: .safetensors removed - handled exclusively by SafeTensorsScanner
    ]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        # Configuration parameters
        self.z_score_threshold = self.config.get("z_score_threshold", 3.0)
        self.cosine_similarity_threshold = self.config.get(
            "cosine_similarity_threshold",
            0.7,
        )
        self.weight_magnitude_threshold = self.config.get(
            "weight_magnitude_threshold",
            3.0,
        )
        self.llm_vocab_threshold = self.config.get("llm_vocab_threshold", 10000)
        self.enable_llm_checks = self.config.get("enable_llm_checks", False)
        # Use max_array_size for in-memory array size limits (default 100MB)
        self.max_array_size = self.config.get("max_array_size", _DEFAULT_MAX_TENSOR_BYTES)
        default_total_tensor_bytes = (
            0
            if self._configured_byte_limit(self.max_array_size, fallback=_DEFAULT_MAX_TENSOR_BYTES) is None
            else _DEFAULT_MAX_TOTAL_TENSOR_BYTES
        )
        self.max_total_tensor_bytes = self.config.get(
            "max_weight_distribution_total_bytes",
            default_total_tensor_bytes,
        )
        # Direct torch.load on untrusted files can trigger pickle RCE. Keep opt-in.
        self.enable_unsafe_torch_load = self.config.get("enable_unsafe_torch_load") is True
        # Flag set when weight extraction would be unsafe
        self.extraction_unsafe = False
        self.extraction_unsafe_reason: str | None = None
        self.extraction_incomplete = False
        self.extraction_incomplete_reasons: list[str] = []
        self.extraction_incomplete_details: dict[str, Any] = {}
        self.retained_tensor_bytes = 0

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if os.path.isdir(path):
            # Directory-based SavedModel weight extraction requires full TensorFlow
            # for checkpoint reading (tf.train.list_variables / tf.train.load_variable)
            try:
                import tensorflow  # noqa: F401
            except ImportError:
                return False
            return os.path.exists(os.path.join(path, "saved_model.pb"))

        if not os.path.isfile(path):
            return False

        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False

        # Skip weight distribution analysis for SafeTensors files
        # SafeTensors are inherently safe and can only contain tensor data
        # The SafeTensorsScanner already validates structure and metadata
        if ext == ".safetensors":
            return False

        # Check if we have the necessary libraries for the format
        if ext in [".pt", ".pth"]:
            try:
                import torch  # noqa: F401
            except ImportError:
                return False
        if ext in [".h5", ".keras", ".hdf5"]:
            try:
                import h5py  # noqa: F401
            except ImportError:
                return False
        if ext == ".pb":
            try:
                from modelaudit.utils.tensorflow_compat import get_protobuf_classes

                get_protobuf_classes()
            except ImportError:
                return False
        if ext == ".onnx":
            try:
                import onnx  # noqa: F401
            except ImportError:
                return False
        return True

    def scan(self, path: str) -> ScanResult:
        """Scan a model file for weight distribution anomalies"""
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        # Reset flag before extraction
        self.extraction_unsafe = False
        self.extraction_unsafe_reason = None
        self.extraction_incomplete = False
        self.extraction_incomplete_reasons = []
        self.extraction_incomplete_details = {}
        self.retained_tensor_bytes = 0
        onnx_plan: Any | None = None

        try:
            # Extract weights based on file format
            if os.path.isdir(path):
                weights_info = self._extract_tensorflow_weights(path)
            else:
                ext = os.path.splitext(path)[1].lower()

                if ext in [".pt", ".pth"]:
                    weights_info = self._extract_pytorch_weights(path)
                elif ext in [".h5", ".keras", ".hdf5"]:
                    weights_info = self._extract_keras_weights(path)
                elif ext == ".pb":
                    weights_info = self._extract_tensorflow_weights(path)
                elif ext == ".onnx":
                    onnx_plan = self._extract_semantic_onnx_weight_plan(path)
                    weights_info = {spec.analysis_id: spec.weights for spec in onnx_plan.specs}
                    result.metadata["onnx_weight_distribution_semantics"] = onnx_plan.metadata
                elif ext == ".safetensors":
                    weights_info = self._extract_safetensors_weights(path)
                else:
                    result.add_check(
                        name="Model Format Support Check",
                        passed=False,
                        message=f"Unsupported model format for weight distribution scanner: {ext}",
                        severity=IssueSeverity.DEBUG,
                        location=path,
                        details={"extension": ext},
                        rule_code="S801",
                    )
                    result.finish(success=False)
                    return result

            if onnx_plan is not None and any(spec.matrix_analysis for spec in onnx_plan.specs):
                try:
                    from scipy import stats as _stats  # noqa: F401
                except Exception as exc:
                    self._record_extraction_incomplete(
                        "missing_weight_distribution_dependency",
                        dependency="scipy",
                        exception_type=type(exc).__name__,
                    )
                    self._mark_analysis_incomplete(
                        result,
                        path,
                        message=f"Weight distribution analysis dependency unavailable: {exc!s}",
                    )
                    result.finish(success=False)
                    return result

            if not weights_info:
                if self.extraction_unsafe:
                    self._record_extraction_incomplete(
                        "unsafe_pytorch_weight_extraction",
                        unsafe_reason=self.extraction_unsafe_reason,
                    )
                if self.extraction_incomplete:
                    self._mark_analysis_incomplete(
                        result,
                        path,
                        message="Model tensor analysis incomplete; no readable matching tensors were available.",
                    )
                    result.finish(success=False)
                    return result

                message = "No numeric model tensors available for distribution analysis"
                severity = IssueSeverity.DEBUG
                rule_code = None
                if self.extraction_unsafe:
                    message = self.extraction_unsafe_reason or "Unsafe to extract weights from model"
                    severity = IssueSeverity.WARNING
                    rule_code = "S801"
                result.add_check(
                    name="Weight Extraction",
                    passed=False,
                    message=message,
                    severity=severity,
                    location=path,
                    rule_code=rule_code,
                )
                result.finish(success=True)
                return result

            # Analyze the weights
            analyzed_onnx: list[tuple[dict[str, Any], Any]] | None = None
            if onnx_plan is not None:
                analyzed_onnx = self._analyze_onnx_weight_specs(onnx_plan.specs)
                anomalies = [anomaly for anomaly, _spec in analyzed_onnx]
            else:
                anomalies = self._analyze_weight_distributions(weights_info)

            # Add issues for any anomalies found
            for anomaly_index, anomaly in enumerate(anomalies):
                details = dict(anomaly["details"])
                if analyzed_onnx is not None:
                    details.update(analyzed_onnx[anomaly_index][1].context)
                result.add_check(
                    name="Weight Distribution Anomaly Detection",
                    passed=False,
                    message=anomaly["description"],
                    severity=anomaly["severity"],
                    location=path,
                    details=details,
                    why=anomaly.get("why"),
                    rule_code="S801",
                )

            # Add metadata
            result.metadata["layers_analyzed"] = len(onnx_plan.specs) if onnx_plan is not None else len(weights_info)
            result.metadata["anomalies_found"] = len(anomalies)

            result.bytes_scanned = file_size

            if self.extraction_incomplete:
                self._mark_analysis_incomplete(
                    result,
                    path,
                    message="Model tensor analysis incomplete; one or more matching tensors could not be read.",
                )
                result.finish(success=False)
                return result

        except ZipPreflightRejected as exc:
            return exc.result
        except Exception as e:
            self._mark_analysis_incomplete(
                result,
                path,
                message="Model tensor analysis incomplete.",
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                },
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result

    def _record_extraction_incomplete(self, reason: str, **details: Any) -> None:
        """Record incomplete tensor extraction while preserving already-read tensors."""
        self.extraction_incomplete = True
        if reason not in self.extraction_incomplete_reasons:
            self.extraction_incomplete_reasons.append(reason)

        for key, value in details.items():
            if value is None:
                continue
            existing = self.extraction_incomplete_details.get(key)
            if key in _ADDITIVE_EXTRACTION_DETAIL_KEYS and isinstance(existing, int) and isinstance(value, int):
                self.extraction_incomplete_details[key] = existing + value
            elif existing == value:
                continue
            elif isinstance(existing, list):
                if isinstance(value, list):
                    existing.extend(value)
                else:
                    existing.append(value)
            elif key in self.extraction_incomplete_details:
                self.extraction_incomplete_details[key] = [existing, value]
            else:
                self.extraction_incomplete_details[key] = value

    def _mark_analysis_incomplete(
        self,
        result: ScanResult,
        path: str,
        *,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        mark_inconclusive_scan_result(result, _ANALYSIS_INCONCLUSIVE_REASON)
        result.add_check(
            name="Weight Distribution Analysis",
            passed=False,
            message=message,
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "analysis_incomplete": True,
                "scan_outcome_reason": _ANALYSIS_INCONCLUSIVE_REASON,
                "extraction_incomplete_reasons": self.extraction_incomplete_reasons,
                **self.extraction_incomplete_details,
                **(details or {}),
            },
        )

    @staticmethod
    def _configured_byte_limit(value: Any, *, fallback: int | None = None) -> int | None:
        if isinstance(value, bool) or not isinstance(value, numbers.Real):
            return fallback
        try:
            numeric_value = float(value)
        except (OverflowError, TypeError, ValueError):
            return fallback
        if not math.isfinite(numeric_value):
            return fallback
        if numeric_value == 0:
            return None
        if numeric_value < 0:
            return fallback
        return max(int(numeric_value), 1)

    def _max_tensor_bytes(self) -> int | None:
        return self._configured_byte_limit(self.max_array_size, fallback=_DEFAULT_MAX_TENSOR_BYTES)

    def _max_total_tensor_bytes(self) -> int | None:
        return self._configured_byte_limit(
            self.max_total_tensor_bytes,
            fallback=self._max_tensor_bytes(),
        )

    def _remaining_tensor_bytes(self) -> int | None:
        limits = [limit for limit in (self._max_tensor_bytes(),) if limit is not None]
        max_total_bytes = self._max_total_tensor_bytes()
        if max_total_bytes is not None:
            limits.append(max(max_total_bytes - self.retained_tensor_bytes, 0))
        if not limits:
            return None
        return min(limits)

    def _tensor_fits_budget(
        self,
        reason: str,
        name: str,
        *,
        tensor_nbytes: int | None,
        retain: bool = False,
    ) -> bool:
        max_tensor_bytes = self._max_tensor_bytes()
        if tensor_nbytes is None or tensor_nbytes < 0:
            self._record_oversized_tensor(reason, name, tensor_nbytes=tensor_nbytes)
            return False
        if max_tensor_bytes is not None and tensor_nbytes > max_tensor_bytes:
            self._record_oversized_tensor(reason, name, tensor_nbytes=tensor_nbytes)
            return False

        max_total_bytes = self._max_total_tensor_bytes()
        projected_total = self.retained_tensor_bytes + tensor_nbytes
        if max_total_bytes is not None and projected_total > max_total_bytes:
            self._record_extraction_incomplete(
                f"{reason}_total",
                failed_tensors=[name],
                oversized_tensors=1,
                tensor_nbytes=tensor_nbytes,
                retained_tensor_bytes=self.retained_tensor_bytes,
                max_total_tensor_bytes=max_total_bytes,
            )
            return False

        if retain:
            self.retained_tensor_bytes = projected_total
        return True

    @staticmethod
    def _logical_tensor_nbytes(shape: Any, dtype: Any) -> int | None:
        if dtype is None:
            return None
        try:
            dimensions = [int(dim) for dim in shape]
        except Exception:
            return None
        if any(dim < 0 for dim in dimensions):
            return None

        try:
            itemsize = int(dtype.itemsize)
        except Exception:
            try:
                import numpy as np

                itemsize = int(np.dtype(dtype).itemsize)
            except Exception:
                return None

        if itemsize <= 0:
            return None

        return math.prod(dimensions) * itemsize

    def _record_oversized_tensor(self, reason: str, name: str, *, tensor_nbytes: int | None) -> None:
        self._record_extraction_incomplete(
            reason,
            failed_tensors=[name],
            oversized_tensors=1,
            tensor_nbytes=tensor_nbytes,
            max_array_size=self._max_tensor_bytes(),
        )

    def _select_pytorch_data_pickle(
        self,
        archive: zipfile.ZipFile,
    ) -> tuple[str, zipfile.ZipInfo] | None:
        members = [member for member in archive.infolist() if not member.is_dir()]
        pickle_candidates: list[tuple[str, zipfile.ZipInfo]] = []
        for member in members:
            parts = member.filename.strip("/").split("/")
            if parts and parts[-1] == "data.pkl":
                pickle_candidates.append(("/".join(parts[:-1]), member))

        if not pickle_candidates:
            return None

        candidate_names = [member.filename for _root, member in pickle_candidates]
        if len(candidate_names) != len(set(candidate_names)):
            self._record_extraction_incomplete(
                "pytorch_pickle_member_ambiguous",
                pickle_member_count=len(candidate_names),
                pickle_members=candidate_names,
            )
            return None

        if len(pickle_candidates) == 1:
            return pickle_candidates[0]

        member_names = {member.filename.strip("/") for member in members}
        ranked: list[tuple[int, int, str, zipfile.ZipInfo]] = []
        for root, member in pickle_candidates:
            prefix = f"{root}/" if root else ""
            has_root_marker = any(f"{prefix}{marker}" in member_names for marker in ("version", "byteorder"))
            has_numeric_storage = any(
                name.startswith(f"{prefix}data/")
                and "/" not in name[len(f"{prefix}data/") :]
                and name[len(f"{prefix}data/") :].isdigit()
                for name in member_names
            )
            credibility = 2 if has_root_marker else int(has_numeric_storage)
            depth = len(root.split("/")) if root else 0
            ranked.append((credibility, depth, root, member))

        credible = [candidate for candidate in ranked if candidate[0] > 0]
        if len(credible) != 1:
            self._record_extraction_incomplete(
                "pytorch_pickle_member_ambiguous",
                pickle_member_count=len(candidate_names),
                pickle_members=candidate_names,
            )
            return None
        _credibility, _depth, root, member = credible[0]
        return root, member

    def _pytorch_load_within_budget(self, path: str) -> bool:
        from .zip_scanner import _open_preflighted_zip_handle

        with _open_preflighted_zip_handle(path, self.config, require_zip=False) as (archive_handle, is_zip):
            return self._pytorch_load_handle_within_budget(path, archive_handle, is_zip=is_zip)

    def _pytorch_load_handle_within_budget(self, path: str, archive_handle: BinaryIO, *, is_zip: bool) -> bool:
        max_total_bytes = self._max_total_tensor_bytes()
        max_tensor_bytes = self._max_tensor_bytes()

        try:
            archive_handle.seek(0)
            if is_zip:
                with zipfile.ZipFile(archive_handle) as archive:
                    selected = self._select_pytorch_data_pickle(archive)
                    if selected is None:
                        return not self.extraction_incomplete
                    root, data_pkl_info = selected
                    prefix_parts = root.split("/") if root else []
                    selected_members = [data_pkl_info]
                    selected_names = {data_pkl_info.filename}
                    for member_info in archive.infolist():
                        parts = member_info.filename.strip("/").split("/")
                        is_storage = (
                            len(parts) == len(prefix_parts) + 2
                            and parts[: len(prefix_parts)] == prefix_parts
                            and parts[-2] == "data"
                            and parts[-1].isdigit()
                        )
                        if member_info.is_dir() or not is_storage:
                            continue
                        if member_info.filename in selected_names:
                            self._record_extraction_incomplete(
                                "pytorch_archive_member_ambiguous",
                                failed_tensors=[member_info.filename],
                            )
                            return False
                        selected_names.add(member_info.filename)
                        selected_members.append(member_info)
                        if max_tensor_bytes is not None and member_info.file_size > max_tensor_bytes:
                            self._record_oversized_tensor(
                                "pytorch_tensor_storage_size_limit",
                                member_info.filename,
                                tensor_nbytes=member_info.file_size,
                            )
                            return False

                    load_bytes = sum(member.file_size for member in selected_members)

                    if max_total_bytes is not None and load_bytes > max_total_bytes:
                        self._record_extraction_incomplete(
                            "pytorch_load_size_limit",
                            failed_tensors=[path],
                            oversized_tensors=1,
                            tensor_nbytes=load_bytes,
                            max_total_tensor_bytes=max_total_bytes,
                        )
                        return False

                    data = self._read_zip_member_bounded(archive, data_pkl_info)
                    if data is None or not self._pickle_object_budget_allows(data, data_pkl_info.filename):
                        return False
                return True

            try:
                load_bytes = os.fstat(archive_handle.fileno()).st_size
            except (AttributeError, OSError):
                current_offset = archive_handle.tell()
                archive_handle.seek(0, os.SEEK_END)
                load_bytes = archive_handle.tell()
                archive_handle.seek(current_offset)
        except (OSError, zipfile.BadZipFile):
            return True

        if max_tensor_bytes is not None and load_bytes > max_tensor_bytes:
            self._record_oversized_tensor(
                "pytorch_legacy_load_size_limit",
                os.path.basename(path),
                tensor_nbytes=load_bytes,
            )
            return False
        if max_total_bytes is None or load_bytes <= max_total_bytes:
            return True

        self._record_extraction_incomplete(
            "pytorch_load_size_limit",
            failed_tensors=[path],
            oversized_tensors=1,
            tensor_nbytes=load_bytes,
            max_total_tensor_bytes=max_total_bytes,
        )
        return False

    def _pickle_object_budget_allows(self, data: bytes, name: str) -> bool:
        remaining_bytes = self._remaining_tensor_bytes()
        budget_bytes = min(limit for limit in (remaining_bytes, _MAX_PICKLE_METADATA_BYTES) if limit is not None)
        max_objects = max(budget_bytes // _ESTIMATED_PICKLE_OBJECT_BYTES, 1024)
        object_count = 0

        import pickletools

        for opcode, _arg, _pos in pickletools.genops(data):
            if opcode.name not in _PICKLE_OBJECT_OPCODES:
                continue
            object_count += 1
            if object_count > max_objects:
                self._record_extraction_incomplete(
                    "pytorch_pickle_object_budget",
                    failed_tensors=[name],
                    oversized_tensors=1,
                    pickle_objects=object_count,
                    max_pickle_objects=max_objects,
                )
                return False
        return True

    @staticmethod
    def _torch_tensor_nbytes(tensor: Any) -> int | None:
        try:
            numel = int(tensor.numel())
            element_size = int(tensor.element_size())
        except Exception:
            return None
        if numel < 0 or element_size <= 0:
            return None
        return numel * element_size

    def _convert_torch_tensor(
        self,
        tensor: Any,
        name: str,
        seen_storages: set[int] | None = None,
    ) -> Any | None:
        tensor_nbytes = self._torch_tensor_nbytes(tensor)
        if not self._tensor_fits_budget("pytorch_tensor_size_limit", name, tensor_nbytes=tensor_nbytes):
            return None

        storage_identity: int
        storage_nbytes: int | None
        try:
            storage = tensor.untyped_storage()
            storage_identity = int(getattr(storage, "_cdata", id(storage)))
            storage_nbytes = int(storage.nbytes())
        except Exception:
            storage_identity = id(tensor)
            storage_nbytes = tensor_nbytes
        retain_storage = seen_storages is None or storage_identity not in seen_storages
        if retain_storage and not self._tensor_fits_budget(
            "pytorch_tensor_storage_size_limit",
            name,
            tensor_nbytes=storage_nbytes,
        ):
            return None
        try:
            array = tensor.detach().cpu().numpy()
        except Exception as exc:
            self._record_extraction_incomplete(
                "pytorch_tensor_read_failed",
                failed_tensors=[name],
                tensor_read_failures=1,
                exception_type=type(exc).__name__,
            )
            return None
        if not self._tensor_fits_budget(
            "pytorch_tensor_size_limit",
            name,
            tensor_nbytes=int(array.nbytes),
        ):
            return None
        if retain_storage:
            if not self._tensor_fits_budget(
                "pytorch_tensor_storage_size_limit",
                name,
                tensor_nbytes=storage_nbytes,
                retain=True,
            ):
                return None
            if seen_storages is not None:
                seen_storages.add(storage_identity)
        return array.T

    def _python_tensor_nbytes(self, value: Any) -> int | None:
        max_bytes = self._remaining_tensor_bytes()
        stack: list[tuple[Any, bool]] = [(value, False)]
        active_containers: set[int] = set()
        scalar_count = 0
        max_itemsize = 1

        while stack:
            item, exiting = stack.pop()
            if isinstance(item, (list, tuple)):
                item_id = id(item)
                if exiting:
                    active_containers.remove(item_id)
                    continue
                if item_id in active_containers:
                    return None
                active_containers.add(item_id)
                stack.append((item, True))
                stack.extend((child, False) for child in reversed(item))
                continue
            if isinstance(item, bool):
                itemsize = 1
            elif isinstance(item, complex):
                itemsize = 16
            elif isinstance(item, float) or (isinstance(item, int) and -(2**63) <= item < 2**63):
                itemsize = 8
            else:
                return None
            scalar_count += 1
            max_itemsize = max(max_itemsize, itemsize)
            estimated_nbytes = scalar_count * max_itemsize
            if max_bytes is not None and estimated_nbytes > max_bytes:
                return estimated_nbytes

        return scalar_count * max_itemsize

    @staticmethod
    def _python_tensor_has_matrix_shape(value: Any) -> bool:
        if not isinstance(value, (list, tuple)) or not value:
            return False
        return isinstance(value[0], (list, tuple))

    def _restricted_pickle_array_limit(self) -> int:
        """Return a hard-bounded array budget for the primitive pickle fallback."""
        remaining_bytes = self._remaining_tensor_bytes()
        if remaining_bytes is None:
            return 100 * 1024 * 1024
        return min(remaining_bytes, 100 * 1024 * 1024)

    def _new_primitive_array_budget(self) -> dict[str, int]:
        byte_limit = self._restricted_pickle_array_limit()
        max_numeric_items = byte_limit // _MAX_NUMERIC_SCALAR_BYTES
        return {
            "remaining_bytes": byte_limit,
            "remaining_nodes": min(_MAX_RESTRICTED_PICKLE_NODES, max(1, max_numeric_items * 2 + 1)),
        }

    def _restricted_pickle_opcode_limit(self) -> int:
        return min(
            _MAX_RESTRICTED_PICKLE_OPCODES,
            max(1024, self._restricted_pickle_array_limit() // 8),
        )

    def _bounded_primitive_array(self, value: Any, np: Any, budget: dict[str, int]) -> Any | None:
        """Materialize a primitive numeric array only after bounded graph traversal."""
        active_container_ids: set[int] = set()
        stack: list[tuple[Any, bool]] = [(value, False)]
        numeric_items = 0
        max_numeric_item_bytes = 1
        metadata_items = 0

        while stack:
            node, leaving = stack.pop()
            if leaving:
                active_container_ids.remove(id(node))
                continue

            budget["remaining_nodes"] -= 1
            if budget["remaining_nodes"] < 0:
                raise ValueError("Primitive tensor structure exceeds aggregate node limit")

            if isinstance(node, (list, tuple)):
                node_id = id(node)
                if node_id in active_container_ids:
                    raise ValueError("Primitive tensor structure contains a cycle")
                active_container_ids.add(node_id)
                stack.append((node, True))
                stack.extend((item, False) for item in reversed(node))
                continue

            if isinstance(node, bool):
                metadata_items += 1
                continue
            if isinstance(node, numbers.Number):
                numeric_items += 1
                if isinstance(node, complex):
                    max_numeric_item_bytes = max(max_numeric_item_bytes, 16)
                elif isinstance(node, (int, float)):
                    max_numeric_item_bytes = max(max_numeric_item_bytes, 8)
                else:
                    max_numeric_item_bytes = max(max_numeric_item_bytes, _MAX_NUMERIC_SCALAR_BYTES)
                continue
            if isinstance(node, (str, bytes)) or node is None:
                metadata_items += 1
                continue
            raise ValueError(f"Primitive tensor contains unsupported value type: {type(node).__name__}")

        if numeric_items and metadata_items:
            raise ValueError("Primitive tensor mixes numeric values with non-numeric metadata")
        if metadata_items or numeric_items == 0:
            return None

        required_bytes = max(
            numeric_items * max_numeric_item_bytes,
            _MIN_NUMPY_ARRAY_BUDGET_BYTES,
        )
        if required_bytes > budget["remaining_bytes"]:
            raise ValueError(
                "Primitive tensor materialization exceeds aggregate byte limit "
                f"({required_bytes} > {budget['remaining_bytes']})"
            )
        budget["remaining_bytes"] -= required_bytes

        array = np.array(value)
        if not np.issubdtype(array.dtype, np.number):
            raise ValueError(f"Primitive tensor has non-numeric dtype: {array.dtype}")
        if array.nbytes > required_bytes:
            raise ValueError(
                f"Primitive tensor materialization exceeded reserved bytes ({array.nbytes} > {required_bytes})"
            )
        return array

    def _read_zip_member_bounded(self, archive: zipfile.ZipFile, member_info: zipfile.ZipInfo) -> bytes | None:
        max_tensor_bytes = self._max_tensor_bytes()
        remaining_tensor_bytes = self._remaining_tensor_bytes()
        max_bytes = min(
            limit
            for limit in (max_tensor_bytes, remaining_tensor_bytes, _MAX_PICKLE_METADATA_BYTES)
            if limit is not None
        )
        if member_info.file_size > max_bytes:
            self._record_extraction_incomplete(
                "pytorch_zip_data_pkl_size_limit",
                failed_tensors=[member_info.filename],
                oversized_tensors=1,
                tensor_nbytes=member_info.file_size,
                max_array_size=max_tensor_bytes,
                max_pickle_metadata_bytes=max_bytes,
            )
            return None

        data = bytearray()
        with archive.open(member_info, "r") as member:
            while True:
                chunk = member.read(_ZIP_MEMBER_READ_CHUNK_SIZE)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > max_bytes:
                    self._record_extraction_incomplete(
                        "pytorch_zip_data_pkl_size_limit",
                        failed_tensors=[member_info.filename],
                        oversized_tensors=1,
                        tensor_nbytes=len(data),
                        max_array_size=max_tensor_bytes,
                        max_pickle_metadata_bytes=max_bytes,
                    )
                    return None
        return bytes(data)

    @staticmethod
    def _is_weight_tensor_name(name: str) -> bool:
        lowered_name = name.lower()
        return "kernel" in lowered_name or "weight" in lowered_name

    @staticmethod
    def _weight_tensor_name_priority(name: str) -> int:
        lowered_name = name.lower()
        return int(any(pattern in lowered_name for pattern in _FINAL_LAYER_NAME_PATTERNS))

    @staticmethod
    def _tensorflow_dtype_itemsize(dtype: Any) -> int | None:
        try:
            import numpy as np

            as_numpy_dtype = getattr(dtype, "as_numpy_dtype", dtype)
            numpy_dtype = np.dtype(as_numpy_dtype)
            if numpy_dtype.hasobject or numpy_dtype.kind in "SU" or numpy_dtype.itemsize <= 0:
                return None
            return int(numpy_dtype.itemsize)
        except Exception:
            return None

    def _tensorflow_checkpoint_variable_nbytes(self, shape: Any, dtype: Any | None) -> int | None:
        try:
            dimensions = [int(dim) for dim in shape]
        except Exception:
            return None
        if any(dim < 0 for dim in dimensions):
            return None

        itemsize = self._tensorflow_dtype_itemsize(dtype) if dtype is not None else None
        if itemsize is None:
            return None
        return math.prod(dimensions) * itemsize

    def _extract_pytorch_weights(self, path: str) -> dict[str, Any]:
        """Extract weights from PyTorch model files"""
        try:
            import numpy as np
            import torch
        except ImportError:
            return {}

        # Reset safety flag for each extraction
        self.extraction_unsafe = False
        self.extraction_unsafe_reason = None

        weights_info: dict[str, Any] = {}
        seen_storages: set[int] = set()

        try:
            if not self.enable_unsafe_torch_load:
                self.extraction_unsafe = True
                self.extraction_unsafe_reason = (
                    "Blocked torch.load on untrusted model input. weights_only=True narrows the "
                    "deserialization attack surface but is not a trust boundary. Set "
                    "enable_unsafe_torch_load=true to opt in."
                )
                raise RuntimeError(self.extraction_unsafe_reason)

            # The explicit unsafe opt-in permits torch.load; retain weights_only when available
            # as defense in depth.
            load_kwargs: dict[str, Any] = {"map_location": torch.device("cpu")}
            supports_weights_only = False
            try:
                load_sig = inspect.signature(torch.load)
                supports_weights_only = "weights_only" in load_sig.parameters
            except (TypeError, ValueError):  # pragma: no cover - defensive
                supports_weights_only = False

            if supports_weights_only:
                load_kwargs["weights_only"] = True

            # Load model with map_location to CPU to avoid GPU requirements
            from .zip_scanner import _open_preflighted_zip_handle

            with _open_preflighted_zip_handle(path, self.config, require_zip=False) as (model_handle, is_zip):
                if not self._pytorch_load_handle_within_budget(path, model_handle, is_zip=is_zip):
                    return {}
                model_handle.seek(0)
                model_data = torch.load(model_handle, **load_kwargs)

            # Handle different PyTorch save formats
            if isinstance(model_data, dict):
                # State dict format
                state_dict = model_data.get("state_dict", model_data)

                # Find final layer weights (classification head)
                for key, value in state_dict.items():
                    key_text = str(key)
                    if isinstance(value, torch.Tensor) and (
                        (
                            any(
                                pattern in key_text.lower()
                                for pattern in [
                                    "fc",
                                    "classifier",
                                    "head",
                                    "output",
                                    "final",
                                ]
                            )
                            and "weight" in key_text.lower()
                        )
                        or "weight" in key_text.lower()
                    ):
                        if len(value.shape) < 2:
                            continue
                        array = self._convert_torch_tensor(value, key_text, seen_storages)
                        if array is not None:
                            weights_info[key_text] = array

            elif hasattr(model_data, "state_dict"):
                # Full model format
                state_dict = model_data.state_dict()
                for key, value in state_dict.items():
                    key_text = str(key)
                    if "weight" in key_text.lower() and isinstance(value, torch.Tensor):
                        if len(value.shape) < 2:
                            continue
                        array = self._convert_torch_tensor(value, key_text, seen_storages)
                        if array is not None:
                            weights_info[key_text] = array

        except ZipPreflightRejected:
            raise
        except Exception as e:
            logger.debug(f"Failed to extract weights from {path}: {e}")
            safe_fallback_processed = False
            try:
                from .zip_scanner import open_preflighted_zip

                with open_preflighted_zip(path, self.config) as z:
                    selected = self._select_pytorch_data_pickle(z)
                    if selected is not None:
                        import io
                        import pickle
                        import pickletools

                        _root, data_pkl_info = selected
                        data = self._read_zip_member_bounded(z, data_pkl_info)
                        if data is None:
                            self.extraction_unsafe = False
                            self.extraction_unsafe_reason = None
                            return weights_info
                        if not self._pickle_object_budget_allows(data, data_pkl_info.filename):
                            self.extraction_unsafe = False
                            self.extraction_unsafe_reason = None
                            return weights_info

                        # Look for disallowed opcodes that could trigger code execution
                        disallowed = {
                            "GLOBAL",
                            "STACK_GLOBAL",
                            "REDUCE",
                            "BUILD",
                            "INST",
                            "OBJ",
                            "NEWOBJ",
                            "NEWOBJ_EX",
                        }
                        unsafe = False
                        pickle_opcode_limit = self._restricted_pickle_opcode_limit()
                        pickle_graph_over_budget = False
                        pickle_memo_entries = 0
                        pickle_memo_limit = min(_MAX_RESTRICTED_PICKLE_MEMO_ENTRIES, pickle_opcode_limit)
                        for pickle_opcode_count, (opcode, arg, _pos) in enumerate(pickletools.genops(data), start=1):
                            if pickle_opcode_count > pickle_opcode_limit:
                                self._record_extraction_incomplete(
                                    "pytorch_pickle_graph_budget_exceeded",
                                    pickle_opcode_count=pickle_opcode_count,
                                    pickle_opcode_limit=pickle_opcode_limit,
                                )
                                pickle_graph_over_budget = True
                                break
                            if opcode.name in {"PUT", "BINPUT", "LONG_BINPUT"}:
                                if (
                                    not isinstance(arg, int)
                                    or arg < 0
                                    or arg > pickle_memo_entries
                                    or arg >= pickle_memo_limit
                                ):
                                    self._record_extraction_incomplete(
                                        "pytorch_pickle_graph_budget_exceeded",
                                        pickle_memo_index=arg,
                                        pickle_memo_entries=pickle_memo_entries,
                                        pickle_memo_limit=pickle_memo_limit,
                                        pickle_memo_opcode=opcode.name,
                                    )
                                    pickle_graph_over_budget = True
                                    break
                                if arg == pickle_memo_entries:
                                    pickle_memo_entries += 1
                            elif opcode.name == "MEMOIZE":
                                if pickle_memo_entries >= pickle_memo_limit:
                                    self._record_extraction_incomplete(
                                        "pytorch_pickle_graph_budget_exceeded",
                                        pickle_memo_entries=pickle_memo_entries,
                                        pickle_memo_limit=pickle_memo_limit,
                                        pickle_memo_opcode=opcode.name,
                                    )
                                    pickle_graph_over_budget = True
                                    break
                                pickle_memo_entries += 1
                            if opcode.name in disallowed:
                                unsafe = True
                                break

                        if pickle_graph_over_budget:
                            safe_fallback_processed = True
                        elif unsafe:
                            self.extraction_unsafe = True
                            self.extraction_unsafe_reason = "Unsafe to extract weights from data.pkl in PyTorch archive"
                        else:
                            try:

                                class RestrictedUnpickler(pickle.Unpickler):
                                    def find_class(self, module: str, name: str) -> Any:
                                        raise pickle.UnpicklingError("global lookup not allowed")

                                obj = RestrictedUnpickler(io.BytesIO(data)).load()
                                if isinstance(obj, dict):
                                    primitive_budget = self._new_primitive_array_budget()
                                    primitive_arrays: dict[int, Any | None] = {}
                                    retained_primitive_arrays: set[int] = set()
                                    primitive_array_names: dict[int, str] = {}
                                    for key, value in obj.items():
                                        if not isinstance(key, str) or not self._is_weight_tensor_name(key):
                                            continue
                                        if not self._python_tensor_has_matrix_shape(value):
                                            continue
                                        value_identity = id(value)
                                        if value_identity in primitive_arrays:
                                            array = primitive_arrays[value_identity]
                                        else:
                                            try:
                                                array = self._bounded_primitive_array(value, np, primitive_budget)
                                            except Exception as array_error:
                                                self._record_extraction_incomplete(
                                                    "pytorch_tensor_materialization_failed",
                                                    failed_tensors=[key],
                                                    tensor_read_failures=1,
                                                    exception_type=type(array_error).__name__,
                                                )
                                                primitive_arrays[value_identity] = None
                                                continue
                                            primitive_arrays[value_identity] = array
                                        if array is None or len(array.shape) < 2:
                                            continue
                                        if value_identity in retained_primitive_arrays:
                                            previous_name = primitive_array_names[value_identity]
                                            if self._weight_tensor_name_priority(
                                                key
                                            ) > self._weight_tensor_name_priority(previous_name):
                                                weights_info.pop(previous_name, None)
                                                weights_info[key] = array
                                                primitive_array_names[value_identity] = key
                                            continue
                                        if self._tensor_fits_budget(
                                            "pytorch_zip_tensor_size_limit",
                                            key,
                                            tensor_nbytes=int(array.nbytes),
                                            retain=True,
                                        ):
                                            weights_info[key] = array
                                            retained_primitive_arrays.add(value_identity)
                                            primitive_array_names[value_identity] = key
                                    safe_fallback_processed = True
                                else:
                                    self._record_extraction_incomplete(
                                        "pytorch_pickle_unsupported_root",
                                        pickle_root_type=type(obj).__name__,
                                    )
                                    safe_fallback_processed = True
                            except Exception as e2:  # pragma: no cover - defensive
                                logger.debug(f"Failed restricted unpickle for {path}: {e2}")
                                self._record_extraction_incomplete(
                                    "pytorch_pickle_parse_failed",
                                    exception_type=type(e2).__name__,
                                )
                                safe_fallback_processed = True
                    elif self.extraction_incomplete:
                        safe_fallback_processed = True
            except ZipPreflightRejected:
                raise
            except Exception as e2:  # pragma: no cover - defensive
                logger.debug(f"Failed to extract weights from {path}: {e2}")

            if safe_fallback_processed:
                self.extraction_unsafe = False
                self.extraction_unsafe_reason = None

        if weights_info and not self.extraction_incomplete:
            self.extraction_unsafe = False
            self.extraction_unsafe_reason = None

        return weights_info

    def _extract_keras_weights(self, path: str) -> dict[str, Any]:
        """Extract weights from Keras/TensorFlow H5 model files"""
        try:
            import h5py
            import numpy as np
        except ImportError:
            return {}

        weights_info: dict[str, Any] = {}

        try:
            with h5py.File(path, "r") as f:
                visited_group_states: set[tuple[Any, bool, bool]] = set()
                materialized_datasets: dict[Any, Any] = {}
                materialized_dataset_names: dict[Any, str] = {}
                skipped_dataset_ids: set[Any] = set()
                groups_to_visit: list[tuple[Any, str]] = [(f, "")]

                while groups_to_visit:
                    group, prefix = groups_to_visit.pop()
                    lowered_prefix = prefix.lower()
                    group_state = (
                        group.id,
                        self._is_weight_tensor_name(prefix),
                        any(pattern in lowered_prefix for pattern in _FINAL_LAYER_NAME_PATTERNS),
                    )
                    if group_state in visited_group_states:
                        continue
                    visited_group_states.add(group_state)

                    for child_name in group:
                        name = f"{prefix}/{child_name}" if prefix else str(child_name)
                        try:
                            link = group.get(child_name, getlink=True)
                        except Exception as exc:
                            if self._is_weight_tensor_name(name):
                                self._record_extraction_incomplete(
                                    "keras_hdf5_link_read_failed",
                                    failed_tensors=[name],
                                    tensor_read_failures=1,
                                    exception_type=type(exc).__name__,
                                )
                            continue

                        if isinstance(link, h5py.ExternalLink):
                            if not self._is_weight_tensor_name(name) and not self._is_weight_tensor_name(link.path):
                                continue
                            self._record_extraction_incomplete(
                                "keras_hdf5_external_link_skipped",
                                failed_tensors=[name],
                                external_reference_tensors=1,
                                link_type=type(link).__name__,
                            )
                            continue

                        try:
                            obj = group.get(child_name, getlink=False)
                        except Exception as exc:
                            if self._is_weight_tensor_name(name):
                                self._record_extraction_incomplete(
                                    "keras_hdf5_object_read_failed",
                                    failed_tensors=[name],
                                    tensor_read_failures=1,
                                    exception_type=type(exc).__name__,
                                )
                            continue

                        if isinstance(obj, h5py.Group):
                            groups_to_visit.append((obj, name))
                            continue

                        if obj is None:
                            if self._is_weight_tensor_name(name):
                                self._record_extraction_incomplete(
                                    "keras_hdf5_object_read_failed",
                                    failed_tensors=[name],
                                    tensor_read_failures=1,
                                    exception_type="DanglingLink",
                                )
                            continue

                        if not (
                            isinstance(obj, h5py.Dataset)
                            and self._is_weight_tensor_name(name)
                            and np.issubdtype(obj.dtype, np.number)
                        ):
                            continue

                        dataset_identity = obj.id
                        if dataset_identity in materialized_datasets:
                            previous_name = materialized_dataset_names[dataset_identity]
                            if self._weight_tensor_name_priority(name) > self._weight_tensor_name_priority(
                                previous_name
                            ):
                                weights_info.pop(previous_name, None)
                                weights_info[name] = materialized_datasets[dataset_identity]
                                materialized_dataset_names[dataset_identity] = name
                            continue
                        if dataset_identity in skipped_dataset_ids:
                            continue
                        skipped_dataset_ids.add(dataset_identity)

                        storage_properties = obj.id.get_create_plist()
                        if storage_properties.get_external_count() > 0:
                            self._record_extraction_incomplete(
                                "keras_hdf5_external_storage_skipped",
                                failed_tensors=[name],
                                external_reference_tensors=1,
                            )
                            continue

                        try:
                            virtual_source_count = storage_properties.get_virtual_count()
                        except ValueError:
                            virtual_source_count = 0
                        if virtual_source_count > 0:
                            self._record_extraction_incomplete(
                                "keras_hdf5_virtual_dataset_skipped",
                                failed_tensors=[name],
                                external_reference_tensors=1,
                            )
                            continue

                        tensor_nbytes = self._logical_tensor_nbytes(obj.shape, obj.dtype)
                        if not self._tensor_fits_budget(
                            "keras_tensor_size_limit",
                            name,
                            tensor_nbytes=tensor_nbytes,
                        ):
                            continue

                        try:
                            array = np.array(obj)
                        except Exception as exc:
                            logger.warning("Weight tensor '%s' could not be read from %s: %s", name, path, exc)
                            self._record_extraction_incomplete(
                                "keras_tensor_read_failed",
                                failed_tensors=[name],
                                tensor_read_failures=1,
                                exception_type=type(exc).__name__,
                            )
                            continue
                        if not self._tensor_fits_budget(
                            "keras_tensor_size_limit",
                            name,
                            tensor_nbytes=int(array.nbytes),
                            retain=True,
                        ):
                            continue
                        materialized_datasets[dataset_identity] = array
                        materialized_dataset_names[dataset_identity] = name
                        skipped_dataset_ids.discard(dataset_identity)
                        weights_info[name] = array

        except Exception as e:
            logger.debug(f"Failed to extract weights from {path}: {e}")
            if os.path.splitext(path)[1].lower() == ".keras" and zipfile.is_zipfile(path):
                return {}
            raise RuntimeError(f"Failed to extract Keras weights from {path}") from e

        return weights_info

    def _extract_tensorflow_weights(self, path: str) -> dict[str, Any]:
        """Extract weights from TensorFlow SavedModel files.

        Uses vendored protobuf stubs when available, falling back to full TensorFlow.
        Checkpoint reading (for SavedModel directories) requires full TensorFlow.
        """
        import numpy as np

        weights_info: dict[str, Any] = {}

        try:
            if os.path.isdir(path):
                # Checkpoint reading requires full TensorFlow - no lightweight alternative
                try:
                    import tensorflow as tf
                except ImportError:
                    logger.debug(f"Checkpoint reading requires TensorFlow: {path}")
                    return {}

                ckpt_prefix = os.path.join(path, "variables", "variables")
                if os.path.exists(ckpt_prefix + ".index"):
                    variable_dtype_map: dict[str, Any] = {}
                    with suppress(Exception):
                        checkpoint_reader = tf.train.load_checkpoint(ckpt_prefix)
                        if hasattr(checkpoint_reader, "get_variable_to_dtype_map"):
                            variable_dtype_map = dict(checkpoint_reader.get_variable_to_dtype_map())

                    for name, shape in tf.train.list_variables(ckpt_prefix):
                        if "weight" not in name.lower() and "kernel" not in name.lower():
                            continue
                        if len(shape) < 2:
                            continue
                        tensor_nbytes = self._tensorflow_checkpoint_variable_nbytes(
                            shape,
                            variable_dtype_map.get(name),
                        )
                        if not self._tensor_fits_budget(
                            "tensorflow_checkpoint_tensor_size_limit",
                            name,
                            tensor_nbytes=tensor_nbytes,
                        ):
                            continue
                        try:
                            tensor = tf.train.load_variable(ckpt_prefix, name)
                            array = np.asarray(tensor)
                        except Exception as exc:
                            logger.warning(
                                "TensorFlow weight variable '%s' could not be read from %s: %s", name, path, exc
                            )
                            self._record_extraction_incomplete(
                                "tensorflow_tensor_read_failed",
                                failed_tensors=[name],
                                tensor_read_failures=1,
                                exception_type=type(exc).__name__,
                            )
                            continue
                        if not self._tensor_fits_budget(
                            "tensorflow_checkpoint_tensor_size_limit",
                            name,
                            tensor_nbytes=int(array.nbytes),
                            retain=len(array.shape) >= 2,
                        ):
                            continue
                        # Only include 2D+ tensors for consistency with .pb file handling
                        if len(array.shape) >= 2:
                            weights_info[name] = array
            else:
                # For .pb files, use vendored protos
                data = self._read_file_safely(path)

                # Import vendored protos module (sets up sys.path for tensorflow.* imports)
                # Order matters: modelaudit.protos must be imported first to set up sys.path
                import modelaudit.protos  # noqa: F401, I001

                from tensorflow.core.framework import graph_pb2
                from tensorflow.core.protobuf import saved_model_pb2

                from modelaudit.utils.tensorflow_compat import DTYPE_MAP, tensor_proto_to_ndarray

                nodes: list[Any] = []
                saved_model = saved_model_pb2.SavedModel()
                with suppress(Exception):
                    saved_model.ParseFromString(data)
                    if saved_model.meta_graphs:
                        for meta_graph in saved_model.meta_graphs:
                            nodes.extend(meta_graph.graph_def.node)

                if not nodes:
                    graph_def = graph_pb2.GraphDef()
                    graph_def.ParseFromString(data)
                    nodes = list(graph_def.node)

                for node in nodes:
                    if node.op != "Const" or "value" not in node.attr:
                        continue

                    node_name = node.name.lower()
                    if "weight" not in node_name and "kernel" not in node_name:
                        continue

                    tensor_proto = node.attr["value"].tensor
                    tensor_dtype = DTYPE_MAP.get(int(tensor_proto.dtype))
                    if tensor_dtype is None or tensor_dtype.hasobject or tensor_dtype.kind in "SU":
                        self._record_extraction_incomplete(
                            "tensorflow_const_tensor_dtype_unsupported",
                            failed_tensors=[node.name],
                            tensor_read_failures=1,
                            tensor_dtype=int(tensor_proto.dtype),
                        )
                        continue
                    remaining_tensor_bytes = self._remaining_tensor_bytes()
                    if remaining_tensor_bytes == 0:
                        self._record_oversized_tensor(
                            "tensorflow_const_tensor_size_limit",
                            node.name,
                            tensor_nbytes=None,
                        )
                        continue
                    try:
                        array = tensor_proto_to_ndarray(
                            tensor_proto,
                            max_tensor_bytes=remaining_tensor_bytes,
                        )
                    except Exception as exc:
                        logger.warning(
                            "TensorFlow weight tensor '%s' could not be decoded from %s: %s", node.name, path, exc
                        )
                        self._record_extraction_incomplete(
                            "tensorflow_tensor_decode_failed",
                            failed_tensors=[node.name],
                            tensor_read_failures=1,
                            exception_type=type(exc).__name__,
                        )
                        continue

                    if not self._tensor_fits_budget(
                        "tensorflow_const_tensor_size_limit",
                        node.name,
                        tensor_nbytes=int(array.nbytes),
                        retain=len(array.shape) >= 2,
                    ):
                        continue
                    if len(array.shape) >= 2:
                        weights_info[node.name] = array
        except Exception as e:
            logger.warning(f"Weight analysis incomplete for {path}: {e}")
            raise RuntimeError(f"Failed to extract TensorFlow weights from {path}") from e

        return weights_info

    @staticmethod
    def _onnx_inline_storage_nbytes(onnx: Any, initializer: Any) -> int:
        raw_data = getattr(initializer, "raw_data", b"")
        raw_bytes = len(raw_data)
        data_type = getattr(initializer, "data_type", None)
        tensor_proto = getattr(onnx, "TensorProto", None)

        packed_multiplier = 1
        for dtype_name in ("FLOAT4E2M1", "INT4", "UINT4"):
            if tensor_proto is not None and data_type == getattr(tensor_proto, dtype_name, None):
                packed_multiplier = 2
                break
        for dtype_name in ("INT2", "UINT2"):
            if tensor_proto is not None and data_type == getattr(tensor_proto, dtype_name, None):
                packed_multiplier = 4
                break

        typed_bytes = 0
        for field_name, itemsize in (
            ("float_data", 4),
            ("int32_data", 4),
            ("int64_data", 8),
            ("double_data", 8),
            ("uint64_data", 8),
        ):
            typed_bytes += len(getattr(initializer, field_name, ())) * itemsize
        typed_bytes += sum(len(value) for value in getattr(initializer, "string_data", ()))
        return raw_bytes * packed_multiplier + typed_bytes

    def _extract_semantic_onnx_weight_plan(self, path: str) -> Any:
        """Build the same bounded semantic ONNX plan used by ``OnnxScanner``."""
        try:
            import numpy as np
            import onnx

            from modelaudit.scanners.onnx_scanner import (
                _build_onnx_weight_analysis_plan,
                _OnnxWeightAnalysisPlan,
            )
        except ImportError as exc:
            raise RuntimeError("ONNX semantic weight analysis dependencies are unavailable") from exc

        max_total_bytes = self._max_total_tensor_bytes()
        model_size = os.path.getsize(path)
        if max_total_bytes is not None and model_size > max_total_bytes:
            self._record_extraction_incomplete(
                "onnx_model_size_limit",
                failed_tensors=[path],
                oversized_tensors=1,
                tensor_nbytes=model_size,
                max_total_tensor_bytes=max_total_bytes,
            )
            plan = _OnnxWeightAnalysisPlan()
            plan.record_coverage_gap("onnx_model_size_limit")
            plan.metadata = {
                "eligible_initializer_count": 0,
                "analyzed_initializer_count": 0,
                "analyzed_layer_count": 0,
                "eligible": [],
                "eligible_metadata_truncated": False,
                "exclusion_counts": {},
                "exclusion_samples": [],
                "exclusion_metadata_truncated": False,
                "coverage_gaps": dict(plan.coverage_gaps),
            }
            return plan

        try:
            model = onnx.load(path, load_external_data=False)  # type: ignore[possibly-unresolved-reference]

            def pre_materialization_check(initializer: Any, name: str, estimated_bytes: int) -> bool:
                inline_storage_nbytes = self._onnx_inline_storage_nbytes(onnx, initializer)
                if not self._tensor_fits_budget(
                    "onnx_initializer_storage_size_limit",
                    name,
                    tensor_nbytes=inline_storage_nbytes,
                ):
                    return False
                return self._tensor_fits_budget(
                    "onnx_initializer_size_limit",
                    name,
                    tensor_nbytes=estimated_bytes,
                )

            plan = _build_onnx_weight_analysis_plan(
                model,
                onnx=onnx,
                np=np,
                max_array_size=None,
                pre_materialization_check=pre_materialization_check,
                retain_array_check=lambda name, nbytes: self._tensor_fits_budget(
                    "onnx_initializer_size_limit",
                    name,
                    tensor_nbytes=nbytes,
                    retain=True,
                ),
            )
        except Exception as exc:
            logger.warning("Failed to build semantic ONNX weight plan for %s (%s)", path, type(exc).__name__)
            raise RuntimeError(f"Failed to extract ONNX weights from {path}") from exc

        if plan.oversized_initializers_skipped:
            self._record_extraction_incomplete(
                "onnx_initializer_size_limit",
                oversized_initializers_skipped=plan.oversized_initializers_skipped,
            )
        if plan.external_initializers_skipped:
            self._record_extraction_incomplete(
                "onnx_external_initializer_skipped",
                external_reference_tensors=plan.external_initializers_skipped,
            )
        if plan.extraction_failures:
            self._record_extraction_incomplete(
                "onnx_initializer_read_failed",
                tensor_read_failures=plan.extraction_failures,
            )
        for reason, count in plan.coverage_gaps.items():
            self._record_extraction_incomplete(
                f"onnx_{reason}",
                coverage_gap_count=count,
                unresolved_lineage_samples=plan.unresolved_lineage_samples,
            )
        return plan

    def _extract_onnx_weights(self, path: str) -> dict[str, Any]:
        """Extract weights from ONNX model files.

        Uses load_external_data=False to avoid failures when external data files
        are missing (common with HuggingFace downloads or standalone .onnx files).
        External-data tensors are skipped since their data is not available inline.
        """
        try:
            import onnx
        except ImportError:
            return {}

        weights_info: dict[str, Any] = {}

        try:
            max_total_bytes = self._max_total_tensor_bytes()
            model_size = os.path.getsize(path)
            if max_total_bytes is not None and model_size > max_total_bytes:
                self._record_extraction_incomplete(
                    "onnx_model_size_limit",
                    failed_tensors=[path],
                    oversized_tensors=1,
                    tensor_nbytes=model_size,
                    max_total_tensor_bytes=max_total_bytes,
                )
                return {}

            # Use load_external_data=False to prevent ValidationError when
            # external data files (e.g. weights.pb) are missing. This is the
            # common case for models downloaded from HuggingFace or distributed
            # as standalone .onnx files without their companion data files.
            model = onnx.load(path, load_external_data=False)  # type: ignore[possibly-unresolved-reference]

            # Extract 2D+ initializers — these are weight matrices (conv kernels,
            # linear layers, embeddings). 1D tensors (biases, batch-norm params)
            # aren't relevant for weight distribution analysis. This approach is
            # framework-agnostic since ONNX naming conventions vary by exporter.
            import numpy as np

            for initializer in model.graph.initializer:
                if len(initializer.dims) < 2:
                    continue

                initializer_name = str(initializer.name)
                external_location = getattr(getattr(onnx, "TensorProto", None), "EXTERNAL", 1)
                if getattr(initializer, "data_location", None) == external_location or (
                    bool(getattr(initializer, "external_data", ()))
                    and self._onnx_inline_storage_nbytes(onnx, initializer) == 0
                ):
                    self._record_extraction_incomplete(
                        "onnx_external_initializer_skipped",
                        failed_tensors=[initializer_name],
                        external_reference_tensors=1,
                    )
                    continue

                # Pre-check estimated byte size before materializing the
                # full array — avoids memory exhaustion on huge tensors.
                tensor_dtype: Any | None = None
                with suppress(Exception):
                    tensor_dtype = onnx.helper.tensor_dtype_to_np_dtype(initializer.data_type)
                if tensor_dtype is None:
                    _onnx_mapping = getattr(onnx, "mapping", None)
                    with suppress(Exception):
                        if _onnx_mapping is not None and hasattr(_onnx_mapping, "TENSOR_TYPE_TO_NP_TYPE"):
                            tensor_dtype = _onnx_mapping.TENSOR_TYPE_TO_NP_TYPE[initializer.data_type]
                with suppress(Exception):
                    numpy_dtype = np.dtype(tensor_dtype)
                    if numpy_dtype.hasobject or numpy_dtype.kind in "SU" or numpy_dtype.itemsize <= 0:
                        tensor_dtype = None
                inline_storage_nbytes = self._onnx_inline_storage_nbytes(onnx, initializer)
                if not self._tensor_fits_budget(
                    "onnx_initializer_storage_size_limit",
                    initializer_name,
                    tensor_nbytes=inline_storage_nbytes,
                ):
                    continue
                estimated_size = self._logical_tensor_nbytes(initializer.dims, tensor_dtype)
                if not self._tensor_fits_budget(
                    "onnx_initializer_size_limit",
                    initializer_name,
                    tensor_nbytes=estimated_size,
                ):
                    continue

                try:
                    arr = onnx.numpy_helper.to_array(initializer)  # type: ignore[possibly-unresolved-reference]
                except Exception as exc:
                    logger.warning(
                        "ONNX weight initializer '%s' could not be read from %s: %s", initializer.name, path, exc
                    )
                    self._record_extraction_incomplete(
                        "onnx_initializer_read_failed",
                        failed_tensors=[initializer_name],
                        tensor_read_failures=1,
                        exception_type=type(exc).__name__,
                    )
                    continue
                if not self._tensor_fits_budget(
                    "onnx_initializer_size_limit",
                    initializer_name,
                    tensor_nbytes=int(arr.nbytes),
                    retain=True,
                ):
                    continue
                weights_info[initializer_name] = arr

        except Exception as e:
            logger.warning(f"Failed to extract ONNX weights from {path}: {e}")
            raise RuntimeError(f"Failed to extract ONNX weights from {path}") from e

        return weights_info

    def _extract_safetensors_weights(self, path: str) -> dict[str, Any]:
        """Extract weights from SafeTensors files"""
        try:
            from safetensors import safe_open
        except ImportError:
            return {}

        weights_info: dict[str, Any] = {}

        try:
            with safe_open(path, framework="numpy") as f:  # type: ignore[possibly-unresolved-reference]
                for key in f:
                    if "weight" in key.lower():
                        weights_info[key] = f.get_tensor(key)

        except Exception as e:
            logger.debug(f"Failed to extract weights from {path}: {e}")
            raise RuntimeError(f"Failed to extract SafeTensors weights from {path}") from e

        return weights_info

    def _analyze_weight_distributions(
        self,
        weights_info: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Analyze weight distributions for anomalies"""
        anomalies = []

        # SECURITY FIX: Perform architecture analysis once with complete model information
        # This provides accurate architectural classification instead of per-layer analysis
        architecture_analysis = self._analyze_architecture_properties(weights_info)

        # Focus on final layer weights (classification heads)
        final_layer_candidates = {}
        for name, weights in weights_info.items():
            if (
                any(pattern in name.lower() for pattern in _FINAL_LAYER_NAME_PATTERNS) and "weight" in name.lower()
            ) and len(weights.shape) == 2:  # Ensure it's a 2D weight matrix
                final_layer_candidates[name] = weights

        # If no clear final layer found, analyze all 2D weight matrices
        if not final_layer_candidates:
            final_layer_candidates = {
                name: weights for name, weights in weights_info.items() if len(weights.shape) == 2
            }

        # Analyze each candidate layer with complete architectural context
        for layer_name, weights in final_layer_candidates.items():
            layer_anomalies = self._analyze_layer_weights(layer_name, weights, architecture_analysis)
            anomalies.extend(layer_anomalies)

        return anomalies

    def _analyze_onnx_weight_specs(self, specs: list[Any]) -> list[tuple[dict[str, Any], Any]]:
        """Analyze collision-proof ONNX specs using their semantic output axes."""
        matrix_weights: dict[int, Any] = {}
        for spec in specs:
            if spec.matrix_analysis:
                matrix_weights.setdefault(spec.initializer_index, spec.weights)
        architecture_analysis = self._analyze_architecture_properties(matrix_weights)
        analyzed: list[tuple[dict[str, Any], Any]] = []
        for spec in specs:
            layer_name = str(spec.context["initializer"])
            if spec.matrix_analysis:
                anomalies = self._analyze_layer_weights(layer_name, spec.weights, architecture_analysis)
            else:
                anomalies = self._analyze_tensor_weight_extremes(
                    layer_name,
                    spec.weights,
                    output_axes=spec.output_axes,
                )
            analyzed.extend((anomaly, spec) for anomaly in anomalies)
        return analyzed

    def _analyze_architecture_properties(self, weights_info: dict[Any, Any]) -> dict[str, Any]:
        """
        Analyze the mathematical and architectural properties to determine model characteristics.
        Uses structural analysis rather than name-based detection to avoid security bypasses.
        """
        analysis: dict[str, Any] = {
            "is_likely_transformer": False,
            "is_likely_llm": False,
            "confidence": 0.0,
            "evidence": [],
            "architectural_features": {},
            "total_parameters": 0,
            "layer_count": 0,
        }

        if not weights_info:
            return analysis

        # Collect weight matrix information
        weight_matrices: list[dict[str, Any]] = []
        total_params = 0

        for layer_name, weights in weights_info.items():
            if len(weights.shape) == 2:  # 2D weight matrices
                weight_matrices.append(
                    {
                        "name": layer_name,
                        "shape": weights.shape,
                        "params": weights.size,
                        "input_dim": weights.shape[0],
                        "output_dim": weights.shape[1],
                    }
                )
                total_params += weights.size

        analysis["total_parameters"] = total_params
        analysis["layer_count"] = len(weight_matrices)

        if len(weight_matrices) == 0:
            analysis["evidence"].append("No 2D weight matrices found")
            return analysis

        # Analyze dimensional patterns typical of transformer architectures
        input_dims = [w["input_dim"] for w in weight_matrices]
        output_dims = [w["output_dim"] for w in weight_matrices]

        # Check for common transformer dimensions (powers of 2, multiples of 64)
        transformer_dims = [64, 128, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 8192]
        matching_dims = 0

        for dim in input_dims + output_dims:
            if dim in transformer_dims or any(dim % td == 0 and dim // td <= 16 for td in transformer_dims):
                matching_dims += 1

        if matching_dims > len(weight_matrices) * 0.6:  # 60% of dimensions match transformer patterns
            analysis["confidence"] += 0.3
            analysis["evidence"].append(f"Found {matching_dims} dimensions matching transformer patterns")
            analysis["is_likely_transformer"] = True

        # Check for large vocabulary/embedding patterns (characteristic of LLMs)
        large_vocab_evidence = 0
        common_vocab_sizes = [30522, 50257, 32000, 28996, 51200, 65536, 100000]  # Known vocab sizes

        for matrix in weight_matrices:
            # Check if either dimension could be a vocabulary size
            for vocab_size in common_vocab_sizes:
                if abs(matrix["output_dim"] - vocab_size) < vocab_size * 0.05:  # 5% tolerance
                    large_vocab_evidence += 1
                    analysis["evidence"].append(f"Found vocabulary-sized layer: {matrix['output_dim']} ≈ {vocab_size}")
                    break

        # Check for large hidden dimensions typical of modern LLMs
        large_hidden_dims = [dim for dim in input_dims + output_dims if dim >= 768]
        if large_hidden_dims:
            analysis["confidence"] += 0.2
            analysis["evidence"].append(f"Found large hidden dimensions: {set(large_hidden_dims)}")

        # Check for architectural consistency (repeated dimension patterns)
        dim_frequency: dict[int, int] = {}
        for dim in input_dims + output_dims:
            dim_frequency[dim] = dim_frequency.get(dim, 0) + 1

        # Look for repeated dimensions (characteristic of structured architectures)
        repeated_dims = [dim for dim, freq in dim_frequency.items() if freq >= 3]
        if repeated_dims:
            analysis["confidence"] += 0.2
            analysis["evidence"].append(f"Found repeated architectural dimensions: {repeated_dims}")

        # Check total parameter count (modern LLMs have millions/billions of parameters)
        if total_params > 100_000_000:  # > 100M parameters
            analysis["confidence"] += 0.3
            analysis["evidence"].append(f"Large parameter count: {total_params:,} parameters")
            analysis["is_likely_llm"] = True
        elif total_params > 10_000_000:  # > 10M parameters
            analysis["confidence"] += 0.2
            analysis["evidence"].append(f"Medium parameter count: {total_params:,} parameters")

        # Final classification based on structural evidence
        if analysis["confidence"] > 0.7 and (large_vocab_evidence > 0 or total_params > 50_000_000):
            analysis["is_likely_llm"] = True
            analysis["evidence"].append("High confidence: Large Language Model based on structural analysis")
        elif analysis["confidence"] > 0.5:
            analysis["is_likely_transformer"] = True
            analysis["evidence"].append("Moderate confidence: Transformer-based model")

        analysis["architectural_features"] = {
            "vocab_evidence": large_vocab_evidence,
            "transformer_dims": matching_dims,
            "repeated_dims": len(repeated_dims),
            "max_dimension": max(input_dims + output_dims) if input_dims + output_dims else 0,
            "dimension_diversity": len(set(input_dims + output_dims)),
        }

        return analysis

    def _analyze_layer_weights(
        self,
        layer_name: str,
        weights: Any,
        architecture_analysis: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Analyze a single layer's weights for anomalies using pre-computed architectural analysis"""
        try:
            import numpy as np
            from scipy import stats
        except ImportError:
            # Skip analysis if numpy/scipy not available
            return []

        anomalies: list[dict[str, Any]] = []

        # Weights shape is typically (input_features, output_features) for dense layers
        if len(weights.shape) != 2:
            return anomalies

        n_inputs, n_outputs = weights.shape

        # SECURITY FIX: Use pre-computed architecture analysis from complete model
        # instead of incorrectly analyzing only a single layer

        # Determine appropriate thresholds based on structural properties, not names
        if architecture_analysis["is_likely_llm"] and not self.enable_llm_checks:
            # For confirmed LLMs based on structural analysis, use relaxed thresholds
            # but don't completely skip checks (that would be a security vulnerability)
            z_score_threshold = max(8.0, self.z_score_threshold * 2.5)
            outlier_percentage_threshold = 0.0001  # 0.01% for LLMs
        elif (
            # Large output dimensions (vocabulary layers)
            n_outputs > self.llm_vocab_threshold
            # Large input dimensions (hidden layers in large models)
            or n_inputs > 2048
            # Large weight matrices (characteristic of large models)
            or weights.size > 10_000_000
        ):
            # Moderate relaxation for large models based on size analysis
            z_score_threshold = max(6.0, self.z_score_threshold * 1.8)
            outlier_percentage_threshold = 0.001  # 0.1% for large models
        else:
            # Standard thresholds for smaller models
            z_score_threshold = self.z_score_threshold
            outlier_percentage_threshold = 0.01  # 1% for classification models

        # Always perform security checks regardless of model type
        # (The original code had a security flaw where it would skip all checks for "LLMs")

        # 1. Check for outlier output neurons using Z-score
        output_norms = np.linalg.norm(weights, axis=0)  # L2 norm of each output neuron
        if len(output_norms) > 1:
            z_scores = np.abs(stats.zscore(output_norms))
            z_score_outliers = (z_scores > z_score_threshold) | np.isclose(
                z_scores, z_score_threshold, rtol=1e-5, atol=0.0
            )
            norm_median = float(np.median(output_norms))
            norm_mad_scale = _NORMAL_MAD_SCALE_FACTOR * float(np.median(np.abs(output_norms - norm_median)))
            if norm_mad_scale > 0:
                robust_norm_outliers = (
                    np.abs(output_norms - norm_median) / norm_mad_scale
                ) > _OUTPUT_NORM_ROBUST_Z_THRESHOLD
            else:
                robust_norm_outliers = output_norms > norm_median
            outlier_indices = np.flatnonzero(z_score_outliers | robust_norm_outliers)

            # Only flag if the number of outliers is reasonable
            outlier_percentage = len(outlier_indices) / n_outputs
            max_outlier_outputs = max(3, int(n_outputs * outlier_percentage_threshold))
            if 0 < len(outlier_indices) <= max_outlier_outputs:
                anomalies.append(
                    {
                        "description": f"Layer '{layer_name}' has {len(outlier_indices)} output neurons with "
                        f"abnormal weight magnitudes",
                        "severity": IssueSeverity.INFO,
                        "details": {
                            "layer": layer_name,
                            "outlier_neurons": outlier_indices.tolist()[:10],  # Limit to first 10
                            "total_outliers": len(outlier_indices),
                            "outlier_percentage": float(outlier_percentage * 100),
                            "z_scores": z_scores[outlier_indices].tolist()[:10],
                            "weight_norms": output_norms[outlier_indices].tolist()[:10],
                            "mean_norm": float(np.mean(output_norms)),
                            "std_norm": float(np.std(output_norms)),
                            "analysis_method": "structural_analysis",
                            "architecture_confidence": architecture_analysis["confidence"],
                        },
                        "why": (
                            "Neurons with weight magnitudes significantly different from others in the same layer may "
                            "indicate tampering, backdoors, or training anomalies. These outliers are flagged when "
                            "their statistical z-score exceeds the threshold. Thresholds are adjusted based on "
                            "structural analysis of the model architecture."
                        ),
                    },
                )

        # 2. Check for dissimilar weight vectors using cosine similarity
        # Only perform this check for smaller output layers to avoid false positives in large vocab models
        if 2 < n_outputs <= 1000:  # Skip for large vocabulary models based on size, not name
            # Compute pairwise cosine similarities
            normalized_weights = weights / (np.linalg.norm(weights, axis=0) + 1e-8)
            similarities = np.dot(normalized_weights.T, normalized_weights)

            dissimilar_neurons = []
            # Find neurons that are dissimilar to all others
            for i in range(n_outputs):
                # Get similarities to other neurons
                other_similarities = np.concatenate(
                    [similarities[i, :i], similarities[i, i + 1 :]],
                )
                max_similarity = np.max(np.abs(other_similarities)) if len(other_similarities) > 0 else 0

                if max_similarity < self.cosine_similarity_threshold:
                    dissimilar_neurons.append((i, max_similarity))

            # Only flag if we have a small number of dissimilar neurons (< 5% or max 3)
            if 0 < len(dissimilar_neurons) < n_outputs and len(dissimilar_neurons) <= max(
                3,
                int(0.05 * n_outputs),
            ):
                for neuron_idx, max_sim in dissimilar_neurons:
                    anomalies.append(
                        {
                            "description": f"Layer '{layer_name}' output neuron {neuron_idx} has unusually "
                            f"dissimilar weights",
                            "severity": IssueSeverity.INFO,
                            "details": {
                                "layer": layer_name,
                                "neuron_index": neuron_idx,
                                "max_similarity_to_others": float(max_sim),
                                "weight_norm": float(output_norms[neuron_idx]),
                                "total_outputs": n_outputs,
                                "analysis_method": "structural_analysis",
                            },
                            "why": (
                                "Neurons with weight patterns completely unlike others in the same layer are "
                                "uncommon in standard training. This dissimilarity (measured by cosine similarity "
                                "below threshold) may indicate injected functionality or training irregularities."
                            ),
                        },
                    )

        # 3. Check for extreme weight values. Keep the decision per output so
        # unrelated tails cannot supply or suppress another output's evidence.
        anomalies.extend(self._analyze_tensor_weight_extremes(layer_name, weights, output_axes=(1,)))

        return anomalies

    def _analyze_tensor_weight_extremes(
        self,
        layer_name: str,
        weights: Any,
        *,
        output_axes: tuple[int, ...],
    ) -> list[dict[str, Any]]:
        """Detect repeated extreme values without materializing a reordered tensor.

        ``output_axes`` identifies the dimensions that form distinct output
        neurons. Every other dimension is reduced as that output's weight vector.
        This supports grouped convolution layouts while keeping the original
        tensor storage order.
        """
        try:
            import numpy as np
        except ImportError:
            return []

        if len(weights.shape) < 2 or weights.size == 0:
            return []

        rank = len(weights.shape)
        normalized_output_axes = tuple(axis if axis >= 0 else rank + axis for axis in output_axes)
        if (
            not normalized_output_axes
            or len(set(normalized_output_axes)) != len(normalized_output_axes)
            or any(axis < 0 or axis >= rank for axis in normalized_output_axes)
        ):
            raise ValueError(f"Invalid output axes {output_axes!r} for weight rank {rank}")

        input_axes = tuple(axis for axis in range(rank) if axis not in normalized_output_axes)
        if not input_axes or any(int(weights.shape[axis]) == 0 for axis in input_axes):
            return []

        n_outputs = math.prod(int(weights.shape[axis]) for axis in normalized_output_axes)
        if n_outputs == 0:
            return []

        destination_axes = tuple(range(rank - len(normalized_output_axes), rank))
        output_last_view = np.moveaxis(weights, normalized_output_axes, destination_axes)
        input_shape = output_last_view.shape[: rank - len(normalized_output_axes)]
        output_shape = output_last_view.shape[rank - len(normalized_output_axes) :]
        # Magnitudes and squared magnitudes are accumulated in float64 so
        # narrow source dtypes cannot overflow before the reduction.
        analysis_itemsize = 8
        max_work_values = max(1, _EXTREME_WEIGHT_ANALYSIS_CHUNK_BYTES // analysis_itemsize)
        input_values_per_output = math.prod(int(dimension) for dimension in input_shape)
        max_scratch_outputs = max(1, max_work_values // _EXTREME_WEIGHT_OUTPUT_SCRATCH_ARRAYS)
        output_block_budget = max(
            1,
            min(
                n_outputs,
                max_work_values // max(1, input_values_per_output),
                max_scratch_outputs,
            ),
        )
        output_block_shape = [1] * len(output_shape)
        remaining_output_values = output_block_budget
        for axis in reversed(range(len(output_shape))):
            block_length = min(int(output_shape[axis]), remaining_output_values)
            output_block_shape[axis] = max(1, block_length)
            remaining_output_values = max(1, remaining_output_values // output_block_shape[axis])
        output_block_counts = tuple(
            math.ceil(int(dimension) / block_length)
            for dimension, block_length in zip(output_shape, output_block_shape, strict=True)
        )

        input_block_budget = max(1, max_work_values // output_block_budget)
        input_block_shape = [1] * len(input_shape)
        remaining_block_values = input_block_budget
        for axis in reversed(range(len(input_shape))):
            block_length = min(int(input_shape[axis]), remaining_block_values)
            input_block_shape[axis] = max(1, block_length)
            remaining_block_values = max(1, remaining_block_values // input_block_shape[axis])
        input_block_counts = tuple(
            math.ceil(int(dimension) / block_length)
            for dimension, block_length in zip(input_shape, input_block_shape, strict=True)
        )

        def magnitudes_as_float64(chunk: Any) -> Any:
            magnitudes = np.empty(chunk.shape, dtype=np.float64)
            if np.issubdtype(np.asarray(chunk).dtype, np.signedinteger):
                # Integer absolute-value ufuncs overflow on the signed minimum.
                np.copyto(magnitudes, chunk, casting="unsafe")
                np.absolute(magnitudes, out=magnitudes)
            else:
                np.absolute(chunk, out=magnitudes, casting="unsafe")
            return magnitudes

        def iter_output_groups() -> Any:
            for block_index in np.ndindex(*output_block_counts):
                output_starts = tuple(
                    index * block_length for index, block_length in zip(block_index, output_block_shape, strict=True)
                )
                output_ends = tuple(
                    min(int(output_shape[axis]), start + output_block_shape[axis])
                    for axis, start in enumerate(output_starts)
                )
                output_slices = tuple(slice(start, end) for start, end in zip(output_starts, output_ends, strict=True))
                output_count = math.prod(end - start for start, end in zip(output_starts, output_ends, strict=True))
                flat_output_start = 0
                for axis, start in enumerate(output_starts):
                    flat_output_start *= int(output_shape[axis])
                    flat_output_start += start
                yield flat_output_start, output_slices, output_count

        def iter_group_chunks(output_slices: tuple[slice, ...]) -> Any:
            for block_index in np.ndindex(*input_block_counts):
                input_slices = tuple(
                    slice(
                        index * block_length,
                        min(int(input_shape[axis]), (index + 1) * block_length),
                    )
                    for axis, (index, block_length) in enumerate(
                        zip(block_index, input_block_shape, strict=True),
                    )
                )
                yield output_last_view[input_slices + output_slices]

        reduction_axes = tuple(range(len(input_shape)))
        max_affected_outputs = max(1, int(0.001 * n_outputs))
        affected_neurons: list[int] = []
        evidence: list[dict[str, Any]] = []
        total_affected = 0
        tail_affected_outputs = 0
        num_extreme_weights = 0
        num_nonfinite_weights = 0
        max_extreme_weights_per_output = 0
        max_weight = 0.0
        max_effect_ratio = 0.0
        representative_threshold = 0.0
        representative_robust_median = 0.0
        representative_robust_scale = 0.0
        representative_robust_threshold = 0.0
        representative_set = False
        for flat_output_start, output_slices, output_count in iter_output_groups():
            sample_values_per_output = max(
                1,
                min(
                    input_values_per_output,
                    _EXTREME_WEIGHT_ROBUST_SAMPLE_SIZE // output_count,
                ),
            )
            sample_step = max(1, math.ceil(input_values_per_output / sample_values_per_output))
            sample_parts: list[Any] = []
            input_logical_offset = 0
            nonfinite_counts = np.zeros(output_count, dtype=np.int64)
            per_output_max = np.zeros(output_count, dtype=np.float64)
            normalized_sums = np.zeros(output_count, dtype=np.float64)
            normalized_square_sums = np.zeros(output_count, dtype=np.float64)

            for chunk in iter_group_chunks(output_slices):
                chunk_magnitudes = magnitudes_as_float64(chunk).reshape(
                    *chunk.shape[: len(input_shape)],
                    output_count,
                )
                flat_magnitudes = chunk_magnitudes.reshape(-1, output_count)
                first_sample = (-input_logical_offset) % sample_step
                if first_sample < flat_magnitudes.shape[0]:
                    sample_parts.append(np.array(flat_magnitudes[first_sample::sample_step], copy=True))
                input_logical_offset += int(flat_magnitudes.shape[0])

                finite_mask = np.isfinite(chunk_magnitudes)
                nonfinite_counts += chunk_magnitudes.size // output_count - np.asarray(
                    np.count_nonzero(finite_mask, axis=reduction_axes)
                ).reshape(-1)
                chunk_magnitudes[~finite_mask] = 0.0
                chunk_max = np.asarray(np.max(chunk_magnitudes, axis=reduction_axes)).reshape(-1)
                scale_increased = chunk_max > per_output_max
                if np.any(scale_increased):
                    scale_ratios = np.ones(output_count, dtype=np.float64)
                    np.divide(
                        per_output_max,
                        chunk_max,
                        out=scale_ratios,
                        where=scale_increased,
                    )
                    normalized_sums[scale_increased] *= scale_ratios[scale_increased]
                    normalized_square_sums[scale_increased] *= np.square(scale_ratios[scale_increased])
                    per_output_max[scale_increased] = chunk_max[scale_increased]

                scale_view = per_output_max.reshape((1,) * len(input_shape) + (output_count,))
                np.divide(
                    chunk_magnitudes,
                    scale_view,
                    out=chunk_magnitudes,
                    where=scale_view > 0,
                )
                normalized_sums += np.asarray(
                    np.sum(chunk_magnitudes, axis=reduction_axes, dtype=np.float64),
                ).reshape(-1)
                np.square(chunk_magnitudes, out=chunk_magnitudes)
                normalized_square_sums += np.asarray(
                    np.sum(chunk_magnitudes, axis=reduction_axes, dtype=np.float64),
                ).reshape(-1)

            finite_counts = input_values_per_output - nonfinite_counts
            normalized_means = np.zeros(output_count, dtype=np.float64)
            normalized_second_moments = np.zeros(output_count, dtype=np.float64)
            np.divide(normalized_sums, finite_counts, out=normalized_means, where=finite_counts > 0)
            np.divide(
                normalized_square_sums,
                finite_counts,
                out=normalized_second_moments,
                where=finite_counts > 0,
            )
            normalized_variances = normalized_second_moments - np.square(normalized_means)
            np.maximum(normalized_variances, 0.0, out=normalized_variances)
            normalized_stds = np.sqrt(normalized_variances)
            normalized_thresholds = normalized_means + self.weight_magnitude_threshold * normalized_stds
            normalized_classical_support_thresholds = (
                normalized_means + _EXTREME_WEIGHT_CLASSICAL_SUPPORT_STD_MULTIPLIER * normalized_stds
            )
            with np.errstate(over="ignore", invalid="ignore"):
                classical_thresholds = per_output_max * normalized_thresholds
                classical_support_thresholds = per_output_max * normalized_classical_support_thresholds

            robust_medians = np.zeros(output_count, dtype=np.float64)
            robust_scales = np.zeros(output_count, dtype=np.float64)
            if sample_parts:
                robust_sample = np.concatenate(sample_parts, axis=0)
                finite_sample_mask = np.isfinite(robust_sample)
                valid_sample_outputs = np.any(finite_sample_mask, axis=0)
                robust_sample[~finite_sample_mask] = np.nan
                if np.any(valid_sample_outputs):
                    valid_samples = robust_sample[:, valid_sample_outputs]
                    valid_medians = np.nanmedian(valid_samples, axis=0)
                    robust_medians[valid_sample_outputs] = valid_medians
                    valid_deviations = np.abs(valid_samples - valid_medians)
                    robust_scales[valid_sample_outputs] = _NORMAL_MAD_SCALE_FACTOR * np.nanmedian(
                        valid_deviations,
                        axis=0,
                    )

            with np.errstate(over="ignore", invalid="ignore"):
                robust_thresholds = robust_medians + _EXTREME_WEIGHT_ROBUST_MAD_MULTIPLIER * robust_scales
                robust_support_thresholds = (
                    robust_medians + _EXTREME_WEIGHT_ROBUST_SUPPORT_MAD_MULTIPLIER * robust_scales
                )

            classical_counts = np.zeros(output_count, dtype=np.int64)
            classical_support_counts = np.zeros(output_count, dtype=np.int64)
            classical_robust_counts = np.zeros(output_count, dtype=np.int64)
            robust_counts = np.zeros(output_count, dtype=np.int64)
            robust_support_counts = np.zeros(output_count, dtype=np.int64)
            inclusive_zero_mad = (robust_scales == 0) & (robust_medians > 0)
            inclusive_zero_mad_view = inclusive_zero_mad.reshape((1,) * len(input_shape) + (output_count,))
            robust_threshold_view = robust_thresholds.reshape((1,) * len(input_shape) + (output_count,))
            robust_support_threshold_view = robust_support_thresholds.reshape(
                (1,) * len(input_shape) + (output_count,),
            )
            classical_threshold_view = classical_thresholds.reshape(
                (1,) * len(input_shape) + (output_count,),
            )
            classical_support_threshold_view = classical_support_thresholds.reshape(
                (1,) * len(input_shape) + (output_count,),
            )
            for chunk in iter_group_chunks(output_slices):
                chunk_magnitudes = magnitudes_as_float64(chunk).reshape(
                    *chunk.shape[: len(input_shape)],
                    output_count,
                )
                chunk_magnitudes[~np.isfinite(chunk_magnitudes)] = 0.0
                robust_mask = chunk_magnitudes > robust_threshold_view
                robust_mask |= (
                    (chunk_magnitudes >= robust_threshold_view)
                    & inclusive_zero_mad_view
                    & (chunk_magnitudes > classical_threshold_view)
                )
                robust_counts += np.asarray(np.count_nonzero(robust_mask, axis=reduction_axes)).reshape(-1)
                robust_support_mask = chunk_magnitudes > robust_support_threshold_view
                robust_support_mask |= (
                    (chunk_magnitudes >= robust_support_threshold_view)
                    & inclusive_zero_mad_view
                    & (chunk_magnitudes > classical_support_threshold_view)
                )
                robust_support_counts += np.asarray(
                    np.count_nonzero(robust_support_mask, axis=reduction_axes),
                ).reshape(-1)
                classical_mask = chunk_magnitudes > classical_threshold_view
                classical_counts += np.asarray(
                    np.count_nonzero(classical_mask, axis=reduction_axes),
                ).reshape(-1)
                classical_support_mask = chunk_magnitudes > classical_support_threshold_view
                classical_support_counts += np.asarray(
                    np.count_nonzero(classical_support_mask, axis=reduction_axes),
                ).reshape(-1)
                classical_mask &= robust_mask
                classical_robust_counts += np.asarray(
                    np.count_nonzero(classical_mask, axis=reduction_axes),
                ).reshape(-1)

            tail_affected_outputs += int(
                np.count_nonzero(
                    (robust_counts >= _EXTREME_WEIGHT_LOCALIZATION_MIN_PER_OUTPUT)
                    | (classical_counts >= _EXTREME_WEIGHT_LOCALIZATION_MIN_PER_OUTPUT)
                    | (nonfinite_counts > 0),
                ),
            )

            per_output_effect_ratios = np.zeros(output_count, dtype=np.float64)
            np.divide(
                per_output_max,
                classical_thresholds,
                out=per_output_effect_ratios,
                where=classical_thresholds > 0,
            )
            per_output_effect_ratios[(classical_thresholds == 0) & (per_output_max > 0)] = np.inf

            robust_tail_concentrations = np.zeros(output_count, dtype=np.float64)
            np.divide(
                robust_counts,
                robust_support_counts,
                out=robust_tail_concentrations,
                where=robust_support_counts > 0,
            )
            concentrated_robust_tails = robust_tail_concentrations >= _EXTREME_WEIGHT_MIN_ROBUST_TAIL_CONCENTRATION
            classical_tail_concentrations = np.zeros(output_count, dtype=np.float64)
            np.divide(
                classical_counts,
                classical_support_counts,
                out=classical_tail_concentrations,
                where=classical_support_counts > 0,
            )
            concentrated_classical_tails = (
                classical_tail_concentrations >= _EXTREME_WEIGHT_MIN_CLASSICAL_TAIL_CONCENTRATION
            )

            classical_effect_qualified = (
                (classical_counts >= _EXTREME_WEIGHT_MIN_PER_OUTPUT)
                & (per_output_effect_ratios >= _EXTREME_WEIGHT_MIN_EFFECT_RATIO)
                & concentrated_classical_tails
            )
            robust_fallback_counts = np.where(inclusive_zero_mad, classical_robust_counts, robust_counts)
            robust_fallback_qualified = (
                robust_fallback_counts >= _EXTREME_WEIGHT_ROBUST_FALLBACK_MIN_PER_OUTPUT
            ) & concentrated_robust_tails
            classical_fallback_qualified = (
                classical_counts >= _EXTREME_WEIGHT_ROBUST_FALLBACK_MIN_PER_OUTPUT
            ) & concentrated_classical_tails
            nonfinite_qualified = nonfinite_counts > 0
            qualified_indices = np.flatnonzero(
                classical_effect_qualified
                | robust_fallback_qualified
                | classical_fallback_qualified
                | nonfinite_qualified,
            )
            if len(qualified_indices) == 0:
                continue

            finite_qualified_counts = np.maximum(
                classical_counts[qualified_indices],
                robust_fallback_counts[qualified_indices],
            )
            qualified_counts = finite_qualified_counts + nonfinite_counts[qualified_indices]
            total_affected += len(qualified_indices)
            num_extreme_weights += int(np.sum(qualified_counts))
            num_nonfinite_weights += int(np.sum(nonfinite_counts[qualified_indices]))
            max_extreme_weights_per_output = max(max_extreme_weights_per_output, int(np.max(qualified_counts)))
            max_weight = max(max_weight, float(np.max(per_output_max[qualified_indices])))

            for local_output_index in qualified_indices:
                output_index = flat_output_start + int(local_output_index)
                if len(affected_neurons) < 10:
                    affected_neurons.append(output_index)
                effect_ratio = float(per_output_effect_ratios[local_output_index])
                if not representative_set or effect_ratio > max_effect_ratio:
                    representative_set = True
                    max_effect_ratio = effect_ratio
                    representative_threshold = float(classical_thresholds[local_output_index])
                    representative_robust_median = float(robust_medians[local_output_index])
                    representative_robust_scale = float(robust_scales[local_output_index])
                    representative_robust_threshold = float(robust_thresholds[local_output_index])
                if len(evidence) >= 10:
                    continue
                robust_effect_ratio = (
                    float(
                        (per_output_max[local_output_index] - robust_medians[local_output_index])
                        / robust_scales[local_output_index]
                    )
                    if robust_scales[local_output_index] > 0
                    else None
                )
                if classical_effect_qualified[local_output_index] and robust_fallback_qualified[local_output_index]:
                    detection_path = "classical_and_robust"
                elif classical_effect_qualified[local_output_index]:
                    detection_path = "classical_effect"
                elif robust_fallback_qualified[local_output_index]:
                    detection_path = "robust_small_tensor_fallback"
                elif classical_fallback_qualified[local_output_index]:
                    detection_path = "concentrated_classical_fallback"
                else:
                    detection_path = "nonfinite_values"
                if nonfinite_qualified[local_output_index] and detection_path != "nonfinite_values":
                    detection_path = f"{detection_path}_and_nonfinite"
                evidence.append(
                    {
                        "output_index": output_index,
                        "classical_count": int(classical_counts[local_output_index]),
                        "classical_support_count": int(classical_support_counts[local_output_index]),
                        "classical_tail_concentration": float(classical_tail_concentrations[local_output_index]),
                        "classical_robust_count": int(classical_robust_counts[local_output_index]),
                        "robust_count": int(robust_counts[local_output_index]),
                        "robust_support_count": int(robust_support_counts[local_output_index]),
                        "robust_tail_concentration": float(robust_tail_concentrations[local_output_index]),
                        "nonfinite_count": int(nonfinite_counts[local_output_index]),
                        "threshold": float(classical_thresholds[local_output_index]),
                        "robust_median_magnitude": float(robust_medians[local_output_index]),
                        "robust_mad_scale": float(robust_scales[local_output_index]),
                        "robust_threshold": float(robust_thresholds[local_output_index]),
                        "max_to_threshold_ratio": effect_ratio if np.isfinite(effect_ratio) else None,
                        "robust_effect_ratio": robust_effect_ratio,
                        "detection_path": detection_path,
                    },
                )

        if total_affected == 0:
            return []

        description = f"Layer '{layer_name}' has neurons with extremely large weight values"
        if num_nonfinite_weights:
            description = f"Layer '{layer_name}' has neurons with non-finite or extremely large weight values"

        return [
            {
                "description": description,
                "severity": IssueSeverity.INFO,
                "details": {
                    "layer": layer_name,
                    "affected_neurons": affected_neurons,
                    "total_affected": total_affected,
                    "tail_affected_outputs": tail_affected_outputs,
                    "num_extreme_weights": num_extreme_weights,
                    "num_nonfinite_weights": num_nonfinite_weights,
                    "threshold": representative_threshold,
                    "threshold_scope": "per_output",
                    "max_weight": max_weight,
                    "max_to_threshold_ratio": max_effect_ratio if np.isfinite(max_effect_ratio) else None,
                    "max_extreme_weights_per_output": max_extreme_weights_per_output,
                    "affected_output_limit": max_affected_outputs,
                    "localized": total_affected <= max_affected_outputs,
                    "minimum_effect_ratio": _EXTREME_WEIGHT_MIN_EFFECT_RATIO,
                    "minimum_extreme_weights_per_output": _EXTREME_WEIGHT_MIN_PER_OUTPUT,
                    "localization_minimum_per_output": _EXTREME_WEIGHT_LOCALIZATION_MIN_PER_OUTPUT,
                    "robust_median_magnitude": representative_robust_median,
                    "robust_mad_scale": representative_robust_scale,
                    "robust_threshold": representative_robust_threshold,
                    "robust_mad_multiplier": _EXTREME_WEIGHT_ROBUST_MAD_MULTIPLIER,
                    "robust_support_mad_multiplier": _EXTREME_WEIGHT_ROBUST_SUPPORT_MAD_MULTIPLIER,
                    "minimum_robust_tail_concentration": _EXTREME_WEIGHT_MIN_ROBUST_TAIL_CONCENTRATION,
                    "classical_support_std_multiplier": _EXTREME_WEIGHT_CLASSICAL_SUPPORT_STD_MULTIPLIER,
                    "minimum_classical_tail_concentration": _EXTREME_WEIGHT_MIN_CLASSICAL_TAIL_CONCENTRATION,
                    "robust_fallback_minimum_per_output": _EXTREME_WEIGHT_ROBUST_FALLBACK_MIN_PER_OUTPUT,
                    "per_output_evidence": evidence,
                    "total_outputs": n_outputs,
                    "analysis_method": "per_output_robust_analysis",
                },
                "why": (
                    "Repeated weight values that are materially beyond both classical and robust distribution "
                    "baselines, and non-finite weights, can cause numerical instability, overflow attacks, or encode "
                    "hidden data. Evidence and thresholds are evaluated independently per output so unrelated "
                    "coefficients cannot create or suppress an alert."
                ),
            },
        ]
