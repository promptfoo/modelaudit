"""Scanner for ZIP-based Keras model files (.keras format)."""

import contextlib
import io
import json
import os
import re
import tempfile
import zipfile
from collections import deque
from collections.abc import Iterator
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, cast

from modelaudit.detectors.network_comm import redact_url_for_finding
from modelaudit.detectors.suspicious_symbols import (
    SUSPICIOUS_CONFIG_PROPERTIES,
    SUSPICIOUS_LAYER_TYPES,
)

from ..config.explanations import (
    get_cve_2024_3660_explanation,
    get_cve_2025_1550_explanation,
    get_cve_2025_8747_explanation,
    get_cve_2025_9906_explanation,
    get_cve_2025_12058_explanation,
    get_cve_2025_12060_explanation,
    get_cve_2025_49655_explanation,
    get_cve_2026_1669_explanation,
    get_pattern_explanation,
)
from ..scanner_results import (
    FILE_HASHES_BYTES_HASHED_METADATA_KEY,
    FILE_HASHES_COMPLETE_METADATA_KEY,
)
from ..utils.file.detection import _normalize_archive_member_name, _read_zip_member_bounded, _read_zip_member_prefix
from ..utils.file.hdf5 import (
    HDF5_SIGNATURE_SCAN_MAX_BYTES,
    HDF5_SUPERBLOCK_PROBE_BYTES,
    has_plausible_hdf5_superblock,
    hdf5_signature_offsets,
    is_hdf5_signature_probe_complete,
)
from ._archive_config import get_archive_depth
from ._evidence_redaction import (
    redact_evidence_mapping_key,
    redact_evidence_string,
    redact_evidence_value,
    redact_untrusted_error_message,
)
from .archive_dispatch import (
    KNOWN_UNREADABLE_ARCHIVE_ENTRY_OFFSETS_CONFIG_KEY,
    SKIP_COMPOSED_ARCHIVE_MEMBER_SCAN_CONFIG_KEY,
)
from .archive_member_security import is_executable_archive_member_name
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, Check, Issue, IssueSeverity, ScanResult
from .keras_utils import (
    check_custom_loss_config,
    check_custom_metric_config,
    check_lambda_dict_function,
    check_lambda_list_function,
    check_subclassed_model,
    is_known_safe_keras_layer_class,
    normalize_keras_layer_class,
)
from .zip_scanner import (
    ZIP_CONTENT_ONLY_MEMBER_ENTRIES_CONFIG_KEY,
    ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY,
    ZipScanner,
)

# CVE-2025-1550: Keras safe_mode bypass via arbitrary module references in config.json
# Allowlist of top-level module names that are safe in Keras model configs.
# Any module outside this list in a layer's "module" or "fn_module" key is suspicious.
# Uses exact root matching: "math" matches "math" and "math.ops" but NOT "mathutils".
_SAFE_KERAS_MODULE_ROOTS: frozenset[str] = frozenset({"keras", "tensorflow", "tf_keras", "tf", "numpy", "math"})
_SAFE_ALLOWLISTED_REGISTERED_OBJECTS: frozenset[str] = frozenset({"notequal"})

# Importable module roots that are explicitly dangerous when referenced in config.json.
_DANGEROUS_CONFIG_MODULE_ROOTS = frozenset(
    {
        "os",
        "sys",
        "subprocess",
        "builtins",
        "__builtin__",
        "importlib",
        "shutil",
        "socket",
        "http",
        "pickle",
        "marshal",
        "ctypes",
        "code",
        "codeop",
        "compileall",
        "runpy",
        "webbrowser",
        "tempfile",
        "signal",
        "multiprocessing",
        "threading",
        "pty",
        "commands",
        "pdb",
        "profile",
        "trace",
        "pip",
        "setuptools",
        "distutils",
    }
)
_DANGEROUS_LAMBDA_MODULE_TOKENS = frozenset(
    {
        "__builtin__",
        "__builtins__",
        "builtins",
        "ctypes",
        "importlib",
        "marshal",
        "nt",
        "os",
        "pickle",
        "posix",
        "runpy",
        "socket",
        "subprocess",
        "sys",
    }
)
_DANGEROUS_LAMBDA_FUNCTION_NAMES = frozenset(
    {"__import__", "attrgetter", "compile", "eval", "exec", "open", "popen", "spawn", "system"}
)
_DANGEROUS_LAMBDA_FUNCTION_MODULE_ROOTS = {
    "attrgetter": frozenset({"operator"}),
}

# Native extension modules are not packages. Only known executable symbols are
# critical; other exact-module references remain subject to callable warnings.
_DANGEROUS_EXACT_MODULE_SYMBOLS: dict[str, frozenset[str]] = {
    "_ctypes": frozenset({"dlopen"}),
    "_frozen_importlib": frozenset({"__import__", "_find_and_load", "_find_and_load_unlocked"}),
    "_imp": frozenset({"create_builtin", "create_dynamic", "exec_builtin", "exec_dynamic", "load_dynamic"}),
    "_interpreters": frozenset({"call", "exec"}),
    "_io": frozenset({"open"}),
    "_operator": frozenset({"attrgetter", "methodcaller"}),
    "_pickle": frozenset({"load", "loads"}),
    "_posixsubprocess": frozenset({"fork_exec"}),
    "_socket": frozenset({"socket"}),
    "_thread": frozenset({"start_new", "start_new_thread"}),
    "_winapi": frozenset({"CreateProcess", "ShellExecute"}),
    "_xxsubinterpreters": frozenset({"run_string"}),
    "io": frozenset({"open"}),
    "nt": frozenset({"popen", "startfile", "system"}),
    "operator": frozenset({"attrgetter", "methodcaller"}),
    "posix": frozenset({"popen", "system"}),
}
_DANGEROUS_EXACT_MODULE_SYMBOL_PREFIXES: dict[str, tuple[str, ...]] = {
    "nt": ("exec", "spawn"),
    "posix": ("exec", "spawn"),
}

_NESTED_SERIALIZED_OBJECT_KEYS = frozenset(
    {
        "activation",
        "activity_regularizer",
        "backward_layer",
        "beta_initializer",
        "bias_constraint",
        "bias_initializer",
        "bias_regularizer",
        "callable",
        "cell",
        "cells",
        "depthwise_constraint",
        "depthwise_initializer",
        "depthwise_regularizer",
        "embeddings_constraint",
        "embeddings_initializer",
        "embeddings_regularizer",
        "fn",
        "forward_layer",
        "function",
        "gamma_initializer",
        "kernel_constraint",
        "kernel_initializer",
        "kernel_regularizer",
        "layer",
        "layers",
        "learning_rate",
        "loss",
        "losses",
        "metric",
        "metrics",
        "moving_mean_initializer",
        "moving_variance_initializer",
        "optimizer",
        "output_activation",
        "pointwise_constraint",
        "pointwise_initializer",
        "pointwise_regularizer",
        "recurrent_activation",
        "recurrent_constraint",
        "recurrent_initializer",
        "recurrent_regularizer",
        "schedule",
        "weighted_metrics",
    }
)

# CVE-2025-8747: keras.utils.get_file used as gadget to download + execute files
_GET_FILE_PATTERN = re.compile(r"get_file", re.IGNORECASE)
_URL_PATTERN = re.compile(r"https?://", re.IGNORECASE)
_URL_SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_KERAS_CONFIG_ENTRY = "config.json"
_KERAS_CONFIG_MAX_BYTES = 10 * 1024 * 1024


def _has_get_file_reference(values: list[str]) -> bool:
    """Return whether config string values reference a get_file callable."""
    for value in values:
        stripped_value = value.strip()
        if _GET_FILE_PATTERN.fullmatch(stripped_value) is not None:
            return True

        stripped_value_lower = stripped_value.lower()
        if stripped_value_lower.endswith(".get_file") or "keras.utils.get_file" in stripped_value_lower:
            return True

    return False


def _archive_format_may_extract_tar(value: Any) -> bool:
    """Mirror Keras archive-format dispatch closely enough to identify tar extraction."""
    if value == "auto" or value == "tar":
        return True
    if isinstance(value, str):
        return False
    if isinstance(value, (list, tuple, dict)):
        for archive_type in value:
            if archive_type == "tar":
                return True
            if archive_type != "zip":
                return False
    return False


_KERAS_METADATA_ENTRY = "metadata.json"
_KERAS_METADATA_MAX_BYTES = 10 * 1024 * 1024
_KERAS_WEIGHTS_ENTRY = "model.weights.h5"
_HDF5_USERBLOCK_MAX_CONCATENATED_ZIP_SEGMENTS = 16
_ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x05\x06"
_ZIP_END_OF_CENTRAL_DIRECTORY_FIXED_BYTES = 22
_MAX_CONFIG_TRAVERSAL_PATH_CHARS = 512
_CONFIG_TRAVERSAL_DEPTH_EXCEEDED_REASON = "keras_zip_config_traversal_depth_exceeded"
_CONFIG_TRAVERSAL_ITEM_LIMIT_EXCEEDED_REASON = "keras_zip_config_traversal_item_limit_exceeded"
_CONFIG_STRING_LITERAL_LIMIT_EXCEEDED_REASON = "keras_zip_config_string_literal_limit_exceeded"
_CONFIG_STRING_CHAR_LIMIT_EXCEEDED_REASON = "keras_zip_config_string_char_limit_exceeded"
_KERAS_RELEASE_VERSION_PATTERN = re.compile(r"^\s*([0-9]+)\.([0-9]+)(?:\.([0-9]+))?([A-Za-z0-9.*+_-]*)\s*$")
_KERAS_TORCHMODULE_VERSION_PATTERN = re.compile(
    r"^\s*[vV]?(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)"
    r"([A-Za-z+_-][A-Za-z0-9.+_-]*|\.[A-Za-z][A-Za-z0-9.+_-]*)?\s*$"
)
_KERAS_PRERELEASE_SUFFIX_PATTERN = re.compile(
    r"(?i)^[._-]?(?:"
    r"(?:alpha|beta|preview|pre|rc|a|b|c)(?:[._-]?[0-9]+)?"
    r"(?:(?:[._-]?(?:post|rev|r)(?:[._-]?[0-9]+)?)|-[0-9]+)?"
    r"(?:[._-]?dev(?:[._-]?[0-9]+)?)?"
    r"|dev(?:[._-]?[0-9]+)?"
    r")(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?$"
)
_KERAS_LOCAL_VERSION_SUFFIX_PATTERN = re.compile(r"(?i)^\+[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_KERAS_POSTRELEASE_SUFFIX_PATTERN = re.compile(
    r"(?i)^(?:(?:[._-]?(?:post|rev|r)(?:[._-]?[0-9]+)?)|-[0-9]+)"
    r"(?:[._-]?dev(?:[._-]?[0-9]+)?)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?$"
)


def _zip_member_hdf5_signature_offset(archive: zipfile.ZipFile, member_info: zipfile.ZipInfo) -> int | None:
    offsets = hdf5_signature_offsets(member_info.file_size)
    if not offsets:
        return None

    read_size = min(member_info.file_size, offsets[-1] + HDF5_SUPERBLOCK_PROBE_BYTES)
    prefix = _read_zip_member_prefix(archive, member_info, read_size)
    for offset in offsets:
        superblock = prefix[offset : offset + HDF5_SUPERBLOCK_PROBE_BYTES]
        if has_plausible_hdf5_superblock(superblock, offset, member_info.file_size):
            return offset
    return None


def _split_concatenated_zip_payload(payload: bytes) -> tuple[bytes, ...]:
    """Split bounded concatenated ZIP payloads so earlier archives remain visible."""
    segments: list[bytes] = []
    remaining = payload

    while len(segments) < _HDF5_USERBLOCK_MAX_CONCATENATED_ZIP_SEGMENTS - 1:
        split_offset: int | None = None
        search_start = 0
        while True:
            eocd_offset = remaining.find(_ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE, search_start)
            if eocd_offset < 0:
                break
            search_start = eocd_offset + 1

            fixed_end = eocd_offset + _ZIP_END_OF_CENTRAL_DIRECTORY_FIXED_BYTES
            if fixed_end > len(remaining):
                continue
            comment_length = int.from_bytes(remaining[eocd_offset + 20 : fixed_end], "little")
            zip_end = fixed_end + comment_length
            if zip_end >= len(remaining):
                continue

            first_archive = remaining[:zip_end]
            later_archives = remaining[zip_end:]
            if zipfile.is_zipfile(io.BytesIO(first_archive)) and zipfile.is_zipfile(io.BytesIO(later_archives)):
                split_offset = zip_end
                break

        if split_offset is None:
            break
        segments.append(remaining[:split_offset])
        remaining = remaining[split_offset:]

    segments.append(remaining)
    return tuple(segments)


def _content_routable_hdf5_userblock_segments(prefix: bytes) -> tuple[bytes, ...]:
    """Split a user block into a valid ZIP prefix and later non-padding content."""
    search_end = len(prefix)
    while True:
        eocd_offset = prefix.rfind(_ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE, 0, search_end)
        if eocd_offset < 0:
            break

        fixed_end = eocd_offset + _ZIP_END_OF_CENTRAL_DIRECTORY_FIXED_BYTES
        if fixed_end <= len(prefix):
            comment_length = int.from_bytes(prefix[eocd_offset + 20 : fixed_end], "little")
            zip_end = fixed_end + comment_length
            if zip_end <= len(prefix):
                candidate = prefix[:zip_end]
                if zipfile.is_zipfile(io.BytesIO(candidate)):
                    zip_segments = _split_concatenated_zip_payload(candidate)
                    trailing_content = prefix[zip_end:].rstrip(b"\x00")
                    if trailing_content:
                        return *zip_segments, trailing_content
                    return zip_segments
        search_end = eocd_offset

    candidate = prefix.rstrip(b"\x00")
    return (candidate,) if candidate else ()


def _redact_url_for_display(url: str) -> str:
    return redact_url_for_finding(url)


try:
    import h5py

    HAS_H5PY = True
except Exception:  # pragma: no cover - optional dependency
    HAS_H5PY = False


class _EmbeddedWeightsLimitExceeded(Exception):
    """Raised when embedded weights exceed the configured extraction limit."""

    def __init__(self, message: str, extracted_bytes: int) -> None:
        super().__init__(message)
        self.extracted_bytes = extracted_bytes


class _AmbiguousKerasArchiveMemberError(Exception):
    """Raised when multiple non-canonical members normalize to the same Keras root path."""

    def __init__(self, member_name: str, candidate_filenames: list[str]) -> None:
        super().__init__(
            f"Ambiguous Keras ZIP member '{member_name}' matches multiple archive entries: "
            f"{', '.join(candidate_filenames)}"
        )
        self.member_name = member_name
        self.candidate_filenames = candidate_filenames


@dataclass
class _ConfigTraversalState:
    """Mutable accounting for one bounded config.json traversal."""

    max_depth: int
    max_items: int
    max_string_literals: int
    max_string_chars: int
    items_seen: int = 0
    items_pending: int = 0
    direct_items_seen: int = 0
    string_literals_seen: int = 0
    string_chars_seen: int = 0
    item_limit_reached: bool = False
    direct_item_limit_reached: bool = False
    halted: bool = False

    @property
    def exhausted(self) -> bool:
        return self.halted or self.item_limit_reached


class KerasZipScanner(BaseScanner):
    """Scanner for ZIP-based Keras .keras model files"""

    MAX_EMBEDDED_WEIGHTS_BYTES: ClassVar[int] = 100 * 1024 * 1024
    MAX_DUPLICATE_MEMBER_COMPARE_CANDIDATES: ClassVar[int] = 16
    MAX_HDF5_LINK_VISITS: ClassVar[int] = 4096
    MAX_HDF5_VIRTUAL_SOURCE_VISITS: ClassVar[int] = 4096
    MAX_HDF5_EXTERNAL_REFERENCE_REPORTS: ClassVar[int] = 20
    MAX_HDF5_EXTERNAL_STORAGE_SEGMENT_REPORTS: ClassVar[int] = 20
    MAX_HDF5_REFERENCE_TEXT_CHARS: ClassVar[int] = 4096
    MAX_ARCHIVE_MEMBER_TEXT_CHARS: ClassVar[int] = 4096
    MAX_NESTED_LAYER_DEPTH: ClassVar[int] = 64
    MAX_NESTED_LAYER_ITEMS: ClassVar[int] = 1_000
    MAX_CONFIG_TRAVERSAL_DEPTH: ClassVar[int] = 256
    MAX_CONFIG_TRAVERSAL_ITEMS: ClassVar[int] = 100_000
    MAX_CONFIG_STRING_LITERALS: ClassVar[int] = 100_000
    MAX_CONFIG_STRING_CHARS: ClassVar[int] = 2 * 1024 * 1024
    MAX_CONFIG_SECURITY_LITERAL_CHARS: ClassVar[int] = 256
    _CONFIG_PROJECTION_KEYS_AFTER_STRING_LIMIT: ClassVar[frozenset[str]] = frozenset(
        {
            "args",
            "backward_layer",
            "callable",
            "cell",
            "cells",
            "class_name",
            "compile_config",
            "config",
            "fn",
            "fn_module",
            "function",
            "function_name",
            "inbound_nodes",
            "kwargs",
            "layer",
            "layers",
            "loss",
            "metrics",
            "module",
            "name",
            "registered_name",
            "weighted_metrics",
        }
    )
    _CONFIG_SECURITY_STRING_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "callable",
            "class_name",
            "config",
            "fn",
            "fn_module",
            "function",
            "function_name",
            "loss",
            "metrics",
            "module",
            "name",
            "registered_name",
            "weighted_metrics",
        }
    )
    _MODEL_CONTAINER_CLASSES: ClassVar[frozenset[str]] = frozenset({"Model", "Functional", "Sequential"})
    _NESTED_LAYER_CONFIG_KEYS: ClassVar[tuple[str, ...]] = ("layer", "backward_layer", "cell", "cells")
    _NESTED_LAYER_LIST_CONFIG_KEYS: ClassVar[frozenset[str]] = frozenset({"cell", "cells"})
    _OPTIONAL_NESTED_LAYER_CONFIG_KEYS: ClassVar[frozenset[str]] = frozenset({"backward_layer"})
    _NESTED_LAYER_CONFIG_KEYS_BY_CLASS: ClassVar[dict[str, frozenset[str]]] = {
        "Bidirectional": frozenset({"layer", "backward_layer"}),
        "RNN": frozenset({"cell"}),
        "SpectralNormalization": frozenset({"layer"}),
        "StackedRNNCells": frozenset({"cells"}),
        "TimeDistributed": frozenset({"layer"}),
        "Wrapper": frozenset({"layer"}),
    }
    _WRAPPED_LAYER_SCAN_MODEL: ClassVar[dict[str, Any]] = {"class_name": "Sequential", "config": {"layers": []}}

    name = "keras_zip"
    description = "Scans ZIP-based Keras model files for suspicious configurations and Lambda layers"
    supported_extensions: ClassVar[list[str]] = [".keras"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        # Additional scanner-specific configuration
        self.suspicious_layer_types = dict(SUSPICIOUS_LAYER_TYPES)
        if config and "suspicious_layer_types" in config:
            self.suspicious_layer_types.update(config["suspicious_layer_types"])

        self.suspicious_config_props = list(SUSPICIOUS_CONFIG_PROPERTIES)
        if config and "suspicious_config_properties" in config:
            self.suspicious_config_props.extend(config["suspicious_config_properties"])

        configured_embedded_limit = self._normalize_positive_int_config(
            self.config.get("max_embedded_weights_bytes"),
            self.MAX_EMBEDDED_WEIGHTS_BYTES,
        )
        if self.max_file_read_size > 0:
            configured_embedded_limit = min(configured_embedded_limit, self.max_file_read_size)
        self.max_embedded_weights_bytes = configured_embedded_limit
        self.max_config_traversal_depth = min(
            self._normalize_positive_int_config(
                self.config.get("max_config_traversal_depth"),
                self.MAX_CONFIG_TRAVERSAL_DEPTH,
            ),
            self.MAX_CONFIG_TRAVERSAL_DEPTH,
        )
        self.max_config_traversal_items = self._normalize_positive_int_config(
            self.config.get("max_config_traversal_items"),
            self.MAX_CONFIG_TRAVERSAL_ITEMS,
        )
        self.max_config_string_literals = self._normalize_positive_int_config(
            self.config.get("max_config_string_literals"),
            self.MAX_CONFIG_STRING_LITERALS,
        )
        self.max_config_string_chars = self._normalize_positive_int_config(
            self.config.get("max_config_string_chars"),
            self.MAX_CONFIG_STRING_CHARS,
        )
        self._nested_layer_items_scanned = 0
        self._content_route_embedded_weights = False
        self._checked_config_module_references: set[tuple[int, str, str]] = set()
        self._current_keras_version: str | None = None
        self._torchmodule_version_status: bool | None = None

    @classmethod
    def _redact_archive_member_name(cls, member_name: str) -> str:
        """Return bounded, redacted archive-member evidence for serialized findings."""
        return redact_evidence_string(member_name, max_chars=cls.MAX_ARCHIVE_MEMBER_TEXT_CHARS)

    @classmethod
    def _redact_recursive_archive_scan_result(cls, nested_result: ScanResult) -> None:
        """Redact model-controlled ZIP member evidence before merging generic archive findings."""
        findings: list[Check | Issue] = [*nested_result.checks, *nested_result.issues]
        for finding in findings:
            finding.message = redact_evidence_string(
                finding.message,
                max_chars=cls.MAX_ARCHIVE_MEMBER_TEXT_CHARS,
            )
            if finding.location is not None:
                finding.location = redact_evidence_string(
                    finding.location,
                    max_chars=cls.MAX_ARCHIVE_MEMBER_TEXT_CHARS,
                )
            finding.details = cast(
                dict[str, Any],
                redact_evidence_value(
                    finding.details,
                    max_string_chars=cls.MAX_ARCHIVE_MEMBER_TEXT_CHARS,
                ),
            )

        if "contents" in nested_result.metadata:
            nested_result.metadata["contents"] = redact_evidence_value(
                nested_result.metadata["contents"],
                max_string_chars=cls.MAX_ARCHIVE_MEMBER_TEXT_CHARS,
            )

    @staticmethod
    def _is_allowlisted_keras_module(module_value: Any) -> bool:
        if not isinstance(module_value, str) or not module_value.strip():
            return False
        return module_value.strip().split(".")[0] in _SAFE_KERAS_MODULE_ROOTS

    def _iter_layer_module_references(self, layer: dict[str, Any]) -> list[str]:
        layer_config = layer.get("config", {})
        if not isinstance(layer_config, dict):
            layer_config = {}

        module_references: list[str] = []
        for key in ("module", "fn_module"):
            for value in (layer.get(key), layer_config.get(key)):
                if isinstance(value, str) and value.strip():
                    module_references.append(value.strip())
        return module_references

    def _layer_uses_allowlisted_module(self, layer: dict[str, Any]) -> bool:
        return any(
            self._is_allowlisted_keras_module(module_value)
            for module_value in self._iter_layer_module_references(layer)
        )

    def _layer_uses_non_allowlisted_module(self, layer: dict[str, Any]) -> bool:
        return any(
            not self._is_allowlisted_keras_module(module_value)
            for module_value in self._iter_layer_module_references(layer)
        )

    @staticmethod
    def _is_known_safe_allowlisted_registered_object(identifier: Any) -> bool:
        return isinstance(identifier, str) and identifier.strip().lower() in _SAFE_ALLOWLISTED_REGISTERED_OBJECTS

    def _is_known_safe_serialized_layer(self, layer: dict[str, Any]) -> bool:
        layer_class = layer.get("class_name")
        if is_known_safe_keras_layer_class(layer_class) or self._is_known_safe_allowlisted_registered_object(
            layer_class
        ):
            return not self._layer_uses_non_allowlisted_module(layer)

        return False

    def _should_flag_registered_object(self, layer: dict[str, Any]) -> bool:
        registered_name = layer.get("registered_name")
        if not isinstance(registered_name, str) or not registered_name.strip():
            return False

        normalized_registered_name = registered_name.strip()
        has_non_allowlisted_module = self._layer_uses_non_allowlisted_module(layer)
        layer_class = layer.get("class_name")
        if isinstance(layer_class, str) and normalized_registered_name == layer_class.strip():
            if self._is_known_safe_serialized_layer(layer) or self._is_known_safe_allowlisted_registered_object(
                layer_class
            ):
                return has_non_allowlisted_module
            return True

        if is_known_safe_keras_layer_class(normalized_registered_name):
            return has_non_allowlisted_module

        return True

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        # Check if it's a ZIP file
        try:
            from ..utils.file.detection import is_keras_zip_archive

            return is_keras_zip_archive(path, allow_config_only=Path(path).suffix.lower() == ".keras")
        except Exception:
            return False

    def _get_archive_member_info(
        self,
        archive: zipfile.ZipFile,
        member_name: str,
    ) -> zipfile.ZipInfo | None:
        """Return a canonical ZIP member deterministically by normalized archive-relative name."""
        exact_matches: list[zipfile.ZipInfo] = []
        normalized_matches: list[zipfile.ZipInfo] = []
        for info in archive.infolist():
            if not info.filename or info.is_dir():
                continue
            if info.filename == member_name:
                exact_matches.append(info)
            elif _normalize_archive_member_name(info.filename) == member_name:
                normalized_matches.append(info)

        if not exact_matches and not normalized_matches:
            return None

        if exact_matches:
            candidate_members = [*exact_matches, *normalized_matches]
            preferred_info = exact_matches[0]
        else:
            candidate_members = normalized_matches
            preferred_info = normalized_matches[0]

        if len(candidate_members) == 1:
            return preferred_info

        if len(candidate_members) > self.MAX_DUPLICATE_MEMBER_COMPARE_CANDIDATES:
            raise _AmbiguousKerasArchiveMemberError(
                member_name,
                [info.filename for info in candidate_members],
            )

        compare_limit = self._get_duplicate_member_compare_limit(member_name)
        try:
            preferred_data = _read_zip_member_bounded(archive, preferred_info, compare_limit)
            for candidate_info in candidate_members[1:]:
                candidate_data = _read_zip_member_bounded(archive, candidate_info, compare_limit)
                if candidate_data != preferred_data:
                    raise _AmbiguousKerasArchiveMemberError(
                        member_name,
                        [info.filename for info in candidate_members],
                    )
        except (ValueError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile, OSError) as exc:
            raise _AmbiguousKerasArchiveMemberError(
                member_name,
                [info.filename for info in candidate_members],
            ) from exc

        return preferred_info

    def _get_duplicate_member_compare_limit(self, member_name: str) -> int:
        """Return a bounded duplicate-content comparison limit for Keras root members."""
        if member_name == _KERAS_CONFIG_ENTRY:
            return _KERAS_CONFIG_MAX_BYTES
        if member_name == _KERAS_METADATA_ENTRY:
            return _KERAS_METADATA_MAX_BYTES
        if member_name == _KERAS_WEIGHTS_ENTRY:
            return self.max_embedded_weights_bytes
        return _KERAS_CONFIG_MAX_BYTES

    def _get_recursive_archive_scan_config(
        self,
        *,
        skip_weights_entry: bool = False,
        security_only_weights_entry: bool = False,
        content_only_weights_entry: bool = False,
    ) -> dict[str, Any]:
        """Return bounded ZIP-recursion config for entries not owned by this scanner."""
        recursive_config = dict(self.config)
        member_size_limits = [self.max_embedded_weights_bytes]
        for config_key in ("max_file_size", "max_entry_size"):
            configured_limit = self._normalize_positive_int_config(
                recursive_config.get(config_key),
                0,
            )
            if configured_limit > 0:
                member_size_limits.append(configured_limit)

        recursive_member_size_limit = min(member_size_limits)
        recursive_config["max_entry_size"] = recursive_member_size_limit
        if self.config.get("max_file_size") not in (None, 0):
            recursive_config["max_file_size"] = recursive_member_size_limit
        else:
            recursive_config.pop("max_file_size", None)
        skip_entries = recursive_config.get("skip_archive_entries", ())
        if isinstance(skip_entries, str):
            skip_entry_values: list[str] = [skip_entries]
        elif isinstance(skip_entries, (list, tuple, set, frozenset)):
            skip_entry_values = [entry for entry in skip_entries if isinstance(entry, str)]
        else:
            skip_entry_values = []
        raw_security_only_entries = recursive_config.get(ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY, ())
        if isinstance(raw_security_only_entries, str):
            security_only_entries: list[str] = [raw_security_only_entries]
        elif isinstance(raw_security_only_entries, (list, tuple, set, frozenset)):
            security_only_entries = [entry for entry in raw_security_only_entries if isinstance(entry, str)]
        else:
            security_only_entries = []
        raw_content_only_entries = recursive_config.get(ZIP_CONTENT_ONLY_MEMBER_ENTRIES_CONFIG_KEY, ())
        if isinstance(raw_content_only_entries, str):
            content_only_entries: list[str] = [raw_content_only_entries]
        elif isinstance(raw_content_only_entries, (list, tuple, set, frozenset)):
            content_only_entries = [entry for entry in raw_content_only_entries if isinstance(entry, str)]
        else:
            content_only_entries = []
        if skip_weights_entry and _KERAS_WEIGHTS_ENTRY not in skip_entry_values:
            skip_entry_values.append(_KERAS_WEIGHTS_ENTRY)
        owned_entries = [_KERAS_CONFIG_ENTRY]
        if security_only_weights_entry:
            owned_entries.append(_KERAS_WEIGHTS_ENTRY)
        for owned_entry in owned_entries:
            if owned_entry not in security_only_entries:
                security_only_entries.append(owned_entry)
        if content_only_weights_entry and _KERAS_WEIGHTS_ENTRY not in content_only_entries:
            content_only_entries.append(_KERAS_WEIGHTS_ENTRY)
        recursive_config["skip_archive_entries"] = skip_entry_values
        recursive_config[ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY] = security_only_entries
        recursive_config[ZIP_CONTENT_ONLY_MEMBER_ENTRIES_CONFIG_KEY] = content_only_entries
        return recursive_config

    def _merge_recursive_archive_scan(
        self,
        path: str,
        result: ScanResult,
        archive: zipfile.ZipFile | None = None,
    ) -> None:
        """Recursively scan every ZIP member through the generic archive scanner."""
        if self.config.get(SKIP_COMPOSED_ARCHIVE_MEMBER_SCAN_CONFIG_KEY):
            return

        has_embedded_weights_limit = self._has_embedded_weights_limit_reason(result)
        security_only_weights_entry = self._should_security_scan_owned_weights_entry(result)
        content_only_weights_entry = self._should_content_route_owned_weights_entry(result)
        zip_scanner = ZipScanner(
            self._get_recursive_archive_scan_config(
                skip_weights_entry=has_embedded_weights_limit,
                security_only_weights_entry=security_only_weights_entry,
                content_only_weights_entry=content_only_weights_entry,
            )
        )
        nested_result = zip_scanner.scan_archive_members(path, archive=archive)
        if has_embedded_weights_limit:
            self._suppress_expected_embedded_weights_limit_noise(nested_result)
        self._redact_recursive_archive_scan_result(nested_result)
        parent_integrity_metadata = {
            key: deepcopy(result.metadata[key])
            for key in (
                "file_hashes",
                "file_size",
                FILE_HASHES_COMPLETE_METADATA_KEY,
                FILE_HASHES_BYTES_HASHED_METADATA_KEY,
            )
            if key in result.metadata
        }
        nested_contents = nested_result.metadata.get("contents")
        result.merge(nested_result)
        for key in (
            "file_hashes",
            "file_size",
            FILE_HASHES_COMPLETE_METADATA_KEY,
            FILE_HASHES_BYTES_HASHED_METADATA_KEY,
        ):
            if key in parent_integrity_metadata:
                result.metadata[key] = deepcopy(parent_integrity_metadata[key])
            else:
                result.metadata.pop(key, None)
        if nested_contents is not None:
            result.metadata["contents"] = nested_contents
        result.success = result.success and nested_result.success

    def _merge_recursive_archive_scan_after_primary_failure(
        self,
        path: str,
        result: ScanResult,
        archive: zipfile.ZipFile | None = None,
    ) -> None:
        """Preserve independently detectable archive findings when Keras analysis is unavailable."""
        try:
            self._merge_recursive_archive_scan(path, result, archive=archive)
        except Exception:
            # The primary failure already makes this scan inconclusive; a
            # failing fallback must not replace that explicit outcome.
            return

    def scan(self, path: str) -> ScanResult:
        """Scan a ZIP-based Keras model file for suspicious configurations"""
        # Initialize context for this file
        self._initialize_context(path)
        self._nested_layer_items_scanned = 0
        self._content_route_embedded_weights = False
        self._checked_config_module_references.clear()
        self._current_keras_version = None
        self._torchmodule_version_status = None

        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        # Store the file path for use in issue locations
        self.current_file_path = path

        from .zip_scanner import ZipPreflightRejected, open_preflighted_zip

        archive_stack = contextlib.ExitStack()
        zf: zipfile.ZipFile | None = None
        try:
            zf = archive_stack.enter_context(open_preflighted_zip(path, self.config))
            with contextlib.nullcontext():
                result.bytes_scanned = file_size

                config_info = self._get_archive_member_info(zf, _KERAS_CONFIG_ENTRY)
                # Check for config.json
                if config_info is None:
                    self._mark_inconclusive_scan_result(result, "keras_zip_config_missing")
                    result.add_check(
                        name="Keras ZIP Format Check",
                        passed=False,
                        message="No config.json found in Keras ZIP file",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"files": [self._redact_archive_member_name(name) for name in zf.namelist()]},
                    )
                    self._load_keras_metadata(zf, result)
                    self._check_archive_security_members(zf, path, result)
                    self._merge_recursive_archive_scan(path, result, archive=zf)
                    self._finish_scan_result(result)
                    return result

                # Read and parse config.json
                raw_config_text = ""
                try:
                    config_data = _read_zip_member_bounded(
                        zf,
                        config_info,
                        _KERAS_CONFIG_MAX_BYTES,
                    )
                    raw_config_text = config_data.decode("utf-8", errors="ignore")
                    model_config = json.loads(config_data)
                except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
                    redacted_error = (
                        str(e)
                        if type(e) is ValueError and str(e) == "ZIP member exceeds bounded read size"
                        else redact_untrusted_error_message(e)
                    )
                    self._mark_inconclusive_scan_result(result, "keras_zip_config_parse_failed")
                    # Fall back to a structure-aware raw scan only when the archive
                    # config is malformed and cannot be parsed as JSON.
                    if raw_config_text:
                        self._check_unsafe_deserialization_bypass_raw(raw_config_text, result)
                    result.add_check(
                        name="Config JSON Parsing",
                        passed=False,
                        message=f"Failed to parse config.json: {redacted_error}",
                        severity=IssueSeverity.INFO,
                        location=f"{path}/{self._redact_archive_member_name(config_info.filename)}",
                        details={
                            "error": redacted_error,
                            "max_config_bytes": _KERAS_CONFIG_MAX_BYTES,
                        },
                    )
                    self._load_keras_metadata(zf, result)
                    self._check_archive_security_members(zf, path, result)
                    self._merge_recursive_archive_scan(path, result, archive=zf)
                    self._finish_scan_result(result)
                    return result

                # CVE-2025-9906 can be detected in any parsed JSON shape; the
                # rest of the structured model scan requires a top-level object.
                bounded_model_config = self._validate_config_traversal_budget(model_config, result)
                self._check_unsafe_deserialization_bypass(model_config, result)
                self._check_get_file_archive_extraction(model_config, result)
                self._check_get_file_gadget(model_config, result)
                self._load_keras_metadata(zf, result)

                if not isinstance(model_config, dict):
                    self._mark_inconclusive_scan_result(result, "keras_zip_config_invalid_type")
                    result.add_check(
                        name="Model Config Type Validation",
                        passed=False,
                        message=f"Invalid config.json type: expected dict, got {type(model_config).__name__}",
                        severity=IssueSeverity.INFO,
                        location=f"{path}/{self._redact_archive_member_name(config_info.filename)}",
                        details={"actual_type": type(model_config).__name__, "expected_type": "dict"},
                    )
                    self._check_archive_security_members(zf, path, result)
                    self._merge_recursive_archive_scan(path, result, archive=zf)
                    self._finish_scan_result(result)
                    return result

                # Scan model configuration
                self._scan_model_config(bounded_model_config, result)

                self._check_archive_security_members(zf, path, result)

                self._merge_recursive_archive_scan(path, result, archive=zf)

        except ZipPreflightRejected as exc:
            return exc.result
        except _AmbiguousKerasArchiveMemberError as e:
            redacted_member_name = self._redact_archive_member_name(e.member_name)
            redacted_candidate_filenames = [
                self._redact_archive_member_name(filename) for filename in e.candidate_filenames
            ]
            result.add_check(
                name="Keras ZIP Member Path Validation",
                passed=False,
                message=(
                    f"Ambiguous Keras ZIP member '{redacted_member_name}' matches multiple archive entries: "
                    f"{', '.join(redacted_candidate_filenames)}"
                ),
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "member_name": redacted_member_name,
                    "candidate_filenames": redacted_candidate_filenames,
                },
            )
            self._merge_recursive_archive_scan(path, result, archive=zf)
            result.finish(success=False)
            return result
        except OSError as e:
            redacted_error = redact_untrusted_error_message(e)
            self._mark_inconclusive_scan_result(result, "keras_zip_read_failed")
            result.add_check(
                name="Keras ZIP File Read",
                passed=False,
                message=f"Unable to read Keras ZIP content: {redacted_error}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": redacted_error,
                    "exception_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "keras_zip_read_failed",
                },
            )
            self._merge_recursive_archive_scan_after_primary_failure(path, result, archive=zf)
            self._finish_scan_result(result)
            return result
        except Exception as e:
            redacted_error = redact_untrusted_error_message(e)
            self._mark_inconclusive_scan_result(result, "keras_zip_scan_failed")
            result.add_check(
                name="Keras ZIP File Scan",
                passed=False,
                message=f"Error scanning Keras ZIP file: {redacted_error}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": redacted_error,
                    "exception_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "keras_zip_scan_failed",
                },
            )
            self._merge_recursive_archive_scan_after_primary_failure(path, result, archive=zf)
            self._finish_scan_result(result)
            return result
        finally:
            archive_stack.close()

        self._finish_scan_result(result)
        return result

    def _load_keras_metadata(self, archive: zipfile.ZipFile, result: ScanResult) -> None:
        metadata_info = self._get_archive_member_info(archive, _KERAS_METADATA_ENTRY)
        if metadata_info is None:
            return

        try:
            metadata_data = _read_zip_member_bounded(
                archive,
                metadata_info,
                _KERAS_METADATA_MAX_BYTES,
            )
            metadata = json.loads(metadata_data)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return

        if not isinstance(metadata, dict):
            return

        result.metadata["keras_metadata"] = redact_evidence_value(metadata)
        keras_version = metadata.get("keras_version")
        if isinstance(keras_version, str) and keras_version.strip():
            raw_keras_version = keras_version.strip()
            self._current_keras_version = raw_keras_version
            # Classify before evidence truncation can alter a valid long local-version label.
            self._torchmodule_version_status = self._is_vulnerable_keras_3_11_x(raw_keras_version)
            result.metadata["keras_version"] = redact_evidence_string(raw_keras_version)

    def _check_archive_security_members(
        self,
        archive: zipfile.ZipFile,
        archive_path: str,
        result: ScanResult,
    ) -> None:
        self._check_embedded_hdf5_weights_external_references(archive, result)

        for filename in archive.namelist():
            normalized_name = filename.lower()
            if normalized_name.endswith((".py", ".pyc", ".pyo")):
                redacted_filename = self._redact_archive_member_name(filename)
                result.add_check(
                    name="Python File Detection",
                    passed=False,
                    message=f"Python file found in Keras ZIP: {redacted_filename}",
                    severity=IssueSeverity.WARNING,
                    location=f"{archive_path}/{redacted_filename}",
                    details={"filename": redacted_filename},
                )
            elif is_executable_archive_member_name(normalized_name):
                redacted_filename = self._redact_archive_member_name(filename)
                result.add_check(
                    name="Executable File Detection",
                    passed=False,
                    message=f"Executable file found in Keras ZIP: {redacted_filename}",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{archive_path}/{redacted_filename}",
                    details={"filename": redacted_filename},
                )

    @staticmethod
    def _mark_inconclusive_scan_result(result: ScanResult, reason: str) -> None:
        """Mark the scan as incomplete without converting it into a security finding."""
        existing_reasons = result.metadata.get("scan_outcome_reasons")
        reasons = existing_reasons if isinstance(existing_reasons, list) else []
        if reason not in reasons:
            reasons.append(reason)

        result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
        result.metadata["scan_outcome_reasons"] = reasons
        result.metadata["analysis_incomplete"] = True

    def _new_config_traversal_state(self) -> _ConfigTraversalState:
        return _ConfigTraversalState(
            max_depth=self.max_config_traversal_depth,
            max_items=self.max_config_traversal_items,
            max_string_literals=self.max_config_string_literals,
            max_string_chars=self.max_config_string_chars,
        )

    @staticmethod
    def _bounded_config_path(path: str) -> str:
        if len(path) <= _MAX_CONFIG_TRAVERSAL_PATH_CHARS:
            return path
        return f"{path[: _MAX_CONFIG_TRAVERSAL_PATH_CHARS - 3]}..."

    @classmethod
    def _config_child_path(cls, path: str, child: str) -> str:
        return cls._bounded_config_path(f"{path}{child}")

    def _mark_config_traversal_limit_exceeded(
        self,
        result: ScanResult,
        reason: str,
        *,
        name: str,
        message: str,
        context: str,
        details: dict[str, Any],
    ) -> None:
        existing_reasons = result.metadata.get("scan_outcome_reasons")
        already_reported = isinstance(existing_reasons, list) and reason in existing_reasons
        self._mark_inconclusive_scan_result(result, reason)
        if already_reported:
            return

        result.add_check(
            name=name,
            passed=False,
            message=message,
            rule_code="S902",
            severity=IssueSeverity.INFO,
            location=f"{self.current_file_path}/config.json",
            details={
                "scan_outcome_reason": reason,
                "context": context,
                **details,
            },
        )

    def _config_traversal_depth_allowed(
        self,
        state: _ConfigTraversalState,
        result: ScanResult,
        *,
        context: str,
        depth: int,
    ) -> bool:
        if depth > state.max_depth:
            self._mark_config_traversal_limit_exceeded(
                result,
                _CONFIG_TRAVERSAL_DEPTH_EXCEEDED_REASON,
                name="Config Traversal Depth Limit",
                message=f"Keras config.json traversal exceeds maximum depth of {state.max_depth}",
                context=context,
                details={
                    "actual_depth": depth,
                    "max_config_traversal_depth": state.max_depth,
                    "items_seen": state.items_seen,
                },
            )
            return False

        return True

    def _mark_config_item_limit_exceeded(
        self,
        state: _ConfigTraversalState,
        result: ScanResult,
        *,
        context: str,
        actual_items: int,
    ) -> None:
        state.item_limit_reached = True
        self._mark_config_traversal_limit_exceeded(
            result,
            _CONFIG_TRAVERSAL_ITEM_LIMIT_EXCEEDED_REASON,
            name="Config Traversal Item Limit",
            message=f"Keras config.json traversal exceeds maximum of {state.max_items} items",
            context=context,
            details={
                "actual_items": actual_items,
                "max_config_traversal_items": state.max_items,
            },
        )

    def _reserve_config_traversal_item(
        self,
        state: _ConfigTraversalState,
        result: ScanResult,
        *,
        context: str,
        depth: int,
        allow_depth_exceeded: bool = False,
    ) -> bool:
        depth_allowed = self._config_traversal_depth_allowed(state, result, context=context, depth=depth)
        if not depth_allowed and not allow_depth_exceeded:
            return False

        if state.items_seen >= state.max_items:
            self._mark_config_item_limit_exceeded(
                state,
                result,
                context=context,
                actual_items=state.items_seen + 1,
            )
            return False

        state.items_seen += 1
        return True

    def _queue_config_traversal_item(
        self,
        pending: deque[Any],
        item: Any,
        state: _ConfigTraversalState,
        result: ScanResult,
        *,
        context: str,
        depth: int,
        allow_depth_exceeded: bool = False,
    ) -> bool:
        if not self._reserve_config_traversal_pending_item(
            state,
            result,
            context=context,
            depth=depth,
            allow_depth_exceeded=allow_depth_exceeded,
        ):
            return False

        pending.append(item)
        return True

    def _reserve_config_traversal_pending_item(
        self,
        state: _ConfigTraversalState,
        result: ScanResult,
        *,
        context: str,
        depth: int,
        allow_depth_exceeded: bool = False,
    ) -> bool:
        if state.exhausted:
            return False
        depth_allowed = self._config_traversal_depth_allowed(state, result, context=context, depth=depth)
        if not depth_allowed and not allow_depth_exceeded:
            return False
        if state.items_seen + state.items_pending >= state.max_items:
            self._mark_config_item_limit_exceeded(
                state,
                result,
                context=context,
                actual_items=state.items_seen + state.items_pending + 1,
            )
            return False

        state.items_pending += 1
        return True

    def _reserve_config_direct_item(
        self,
        state: _ConfigTraversalState,
        result: ScanResult,
        *,
        context: str,
        depth: int,
        allow_depth_exceeded: bool = False,
    ) -> bool:
        """Reserve bounded work for a direct mapping value not queued for traversal."""
        if state.halted or state.direct_item_limit_reached:
            return False
        depth_allowed = self._config_traversal_depth_allowed(state, result, context=context, depth=depth)
        if not depth_allowed and not allow_depth_exceeded:
            return False
        if state.direct_items_seen >= state.max_items:
            state.direct_item_limit_reached = True
            self._mark_config_item_limit_exceeded(
                state,
                result,
                context=context,
                actual_items=state.direct_items_seen + 1,
            )
            return False

        state.direct_items_seen += 1
        return True

    def _record_config_string_literal(
        self,
        value: str,
        state: _ConfigTraversalState,
        result: ScanResult,
        *,
        context: str,
    ) -> str | None:
        if state.string_literals_seen >= state.max_string_literals:
            state.halted = True
            self._mark_config_traversal_limit_exceeded(
                result,
                _CONFIG_STRING_LITERAL_LIMIT_EXCEEDED_REASON,
                name="Config String Literal Limit",
                message=f"Keras config.json traversal exceeds maximum of {state.max_string_literals} string literals",
                context=context,
                details={
                    "actual_string_literals": state.string_literals_seen + 1,
                    "max_config_string_literals": state.max_string_literals,
                },
            )
            return None

        state.string_literals_seen += 1
        next_string_chars_seen = state.string_chars_seen + len(value)
        if next_string_chars_seen > state.max_string_chars:
            state.halted = True
            state.string_chars_seen = state.max_string_chars
            self._mark_config_traversal_limit_exceeded(
                result,
                _CONFIG_STRING_CHAR_LIMIT_EXCEEDED_REASON,
                name="Config String Character Limit",
                message=f"Keras config.json traversal exceeds maximum of {state.max_string_chars} string characters",
                context=context,
                details={
                    "actual_string_chars": next_string_chars_seen,
                    "max_config_string_chars": state.max_string_chars,
                    "string_literals_seen": state.string_literals_seen,
                },
            )
            return None

        state.string_chars_seen = next_string_chars_seen
        return value

    def _validate_config_traversal_budget(self, model_config: Any, result: ScanResult) -> Any:
        """Return the admitted config.json projection and fail closed on omitted coverage."""
        traversal_state = self._new_config_traversal_state()
        literal_state = self._new_config_traversal_state()
        security_literal_state = self._new_config_traversal_state()
        root: dict[str, Any] = {}
        pending: deque[tuple[Any, int, str, dict[Any, Any] | list[Any], Any, bool]] = deque(
            [(model_config, 0, "root", root, "value", False)]
        )

        def attach(parent: dict[Any, Any] | list[Any], slot: Any, value: Any) -> None:
            if isinstance(parent, list):
                parent.append(value)
            else:
                parent[slot] = value

        traversal_state.items_pending = 1
        while pending:
            node, depth, context, parent, slot, preserve_security_string = pending.popleft()
            traversal_state.items_pending -= 1
            allow_depth_exceeded = not isinstance(node, (dict, list))
            if not self._reserve_config_traversal_item(
                traversal_state,
                result,
                context=context,
                depth=depth,
                allow_depth_exceeded=allow_depth_exceeded,
            ):
                continue

            if isinstance(node, str):
                bounded_value = None
                if not literal_state.halted:
                    bounded_value = self._record_config_string_literal(node, literal_state, result, context=context)
                if (
                    bounded_value is None
                    and preserve_security_string
                    and not security_literal_state.halted
                    and len(node) <= self.MAX_CONFIG_SECURITY_LITERAL_CHARS
                ):
                    bounded_value = self._record_config_string_literal(
                        node,
                        security_literal_state,
                        result,
                        context=context,
                    )
                if bounded_value is not None:
                    attach(parent, slot, bounded_value)
                continue

            if isinstance(node, dict):
                bounded_node: dict[Any, Any] = {}
                attach(parent, slot, bounded_node)
                if traversal_state.item_limit_reached:
                    for key, value in node.items():
                        redacted_key = redact_evidence_string(str(key), max_chars=64)
                        child_context = self._config_child_path(context, f".{redacted_key}")
                        if not self._reserve_config_direct_item(
                            traversal_state,
                            result,
                            context=child_context,
                            depth=depth + 1,
                            allow_depth_exceeded=True,
                        ):
                            break
                        key_context = self._config_child_path(context, f".<key:{redacted_key}>")
                        bounded_key = key
                        if isinstance(key, str):
                            bounded_key = None
                            if not literal_state.halted:
                                bounded_key = self._record_config_string_literal(
                                    key,
                                    literal_state,
                                    result,
                                    context=key_context,
                                )
                            if bounded_key is None and key in self._CONFIG_PROJECTION_KEYS_AFTER_STRING_LIMIT:
                                bounded_key = key
                            if bounded_key is None:
                                continue
                        if isinstance(value, (dict, list)):
                            continue
                        bounded_value = value
                        if isinstance(value, str):
                            bounded_value = None
                            if not literal_state.halted:
                                bounded_value = self._record_config_string_literal(
                                    value,
                                    literal_state,
                                    result,
                                    context=child_context,
                                )
                            if (
                                bounded_value is None
                                and isinstance(key, str)
                                and key in self._CONFIG_SECURITY_STRING_KEYS
                                and not security_literal_state.halted
                                and len(value) <= self.MAX_CONFIG_SECURITY_LITERAL_CHARS
                            ):
                                bounded_value = self._record_config_string_literal(
                                    value,
                                    security_literal_state,
                                    result,
                                    context=child_context,
                                )
                            if bounded_value is None:
                                continue
                        bounded_node[bounded_key] = bounded_value
                    continue
                for key, value in node.items():
                    redacted_key = redact_evidence_string(str(key), max_chars=64)
                    key_context = self._config_child_path(context, f".<key:{redacted_key}>")
                    bounded_key = key
                    if isinstance(key, str):
                        bounded_key = None
                        if not literal_state.halted:
                            bounded_key = self._record_config_string_literal(
                                key,
                                literal_state,
                                result,
                                context=key_context,
                            )
                        if bounded_key is None and key in self._CONFIG_PROJECTION_KEYS_AFTER_STRING_LIMIT:
                            bounded_key = key
                        if bounded_key is None:
                            if not self._reserve_config_direct_item(
                                traversal_state,
                                result,
                                context=key_context,
                                depth=depth + 1,
                                allow_depth_exceeded=True,
                            ):
                                break
                            continue

                    child_context = self._config_child_path(context, f".{redacted_key}")
                    child_is_scalar = not isinstance(value, (dict, list))
                    if not self._queue_config_traversal_item(
                        pending,
                        (
                            value,
                            depth + 1,
                            child_context,
                            bounded_node,
                            bounded_key,
                            isinstance(key, str) and key in self._CONFIG_SECURITY_STRING_KEYS,
                        ),
                        traversal_state,
                        result,
                        context=child_context,
                        depth=depth + 1,
                        allow_depth_exceeded=child_is_scalar,
                    ):
                        break
                continue

            if isinstance(node, list):
                bounded_node_list: list[Any] = []
                attach(parent, slot, bounded_node_list)
                if traversal_state.item_limit_reached:
                    continue
                for index, value in enumerate(node):
                    child_context = self._config_child_path(context, f"[{index}]")
                    child_is_scalar = not isinstance(value, (dict, list))
                    if not self._queue_config_traversal_item(
                        pending,
                        (
                            value,
                            depth + 1,
                            child_context,
                            bounded_node_list,
                            None,
                            preserve_security_string,
                        ),
                        traversal_state,
                        result,
                        context=child_context,
                        depth=depth + 1,
                        allow_depth_exceeded=child_is_scalar,
                    ):
                        break
                continue

            attach(parent, slot, node)

        return root.get("value")

    @staticmethod
    def _has_embedded_weights_limit_reason(result: ScanResult) -> bool:
        reasons = result.metadata.get("scan_outcome_reasons")
        return isinstance(reasons, list) and "keras_zip_embedded_weights_too_large" in reasons

    @staticmethod
    def _should_security_scan_owned_weights_entry(result: ScanResult) -> bool:
        reasons = result.metadata.get("scan_outcome_reasons")
        if not isinstance(reasons, list):
            return False
        return "keras_zip_embedded_weights_h5py_unavailable" in reasons

    def _should_content_route_owned_weights_entry(self, result: ScanResult) -> bool:
        reasons = result.metadata.get("scan_outcome_reasons")
        return self._content_route_embedded_weights or (
            isinstance(reasons, list) and "keras_zip_embedded_weights_hdf5_signature_probe_incomplete" in reasons
        )

    @staticmethod
    def _is_expected_recursive_weights_limit_noise(entry: Any) -> bool:
        details = getattr(entry, "details", None)
        message = getattr(entry, "message", "")
        return (
            isinstance(details, dict)
            and details.get("entry") == _KERAS_WEIGHTS_ENTRY
            and isinstance(message, str)
            and "exceeds maximum size" in message
        )

    @classmethod
    def _suppress_expected_embedded_weights_limit_noise(cls, result: ScanResult) -> None:
        result.issues = [issue for issue in result.issues if not cls._is_expected_recursive_weights_limit_noise(issue)]
        result.checks = [check for check in result.checks if not cls._is_expected_recursive_weights_limit_noise(check)]

    @staticmethod
    def _scan_result_has_security_findings(result: ScanResult) -> bool:
        """Return True when the scan found warning or critical security risk."""
        return any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

    @staticmethod
    def _scan_result_has_actionable_security_findings(result: ScanResult) -> bool:
        """Return True for actionable findings, excluding standalone pickle parse-noise warnings."""
        return any(
            issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL)
            and issue.rule_code not in {"S901", "S902"}
            for issue in result.issues
        )

    @classmethod
    def _finish_scan_result(cls, result: ScanResult) -> None:
        """Fail closed on incomplete/no-finding scans while preserving security precedence."""
        is_inconclusive = result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        has_security_findings = cls._scan_result_has_security_findings(result)
        if is_inconclusive and not has_security_findings:
            result.finish(success=False)
            return

        result.finish(success=result.success and not result.has_errors)

    def _scan_model_config(
        self,
        model_config: dict[str, Any],
        result: ScanResult,
        nested_layer_depth: int = 0,
    ) -> None:
        """Scan the model configuration for suspicious elements"""
        if nested_layer_depth > self.MAX_NESTED_LAYER_DEPTH:
            self._mark_inconclusive_scan_result(result, "keras_zip_nested_layer_depth_exceeded")
            result.add_check(
                name="Nested Layer Depth Validation",
                passed=False,
                message=f"Nested Keras layer depth exceeds maximum of {self.MAX_NESTED_LAYER_DEPTH}",
                rule_code="S902",
                severity=IssueSeverity.INFO,
                location=f"{self.current_file_path}/config.json",
                details={
                    "actual_depth": nested_layer_depth,
                    "max_nested_layer_depth": self.MAX_NESTED_LAYER_DEPTH,
                },
            )
            return

        # Check model class name
        model_class = model_config.get("class_name", "")
        model_class_is_string = isinstance(model_class, str)
        redacted_model_class = (
            redact_evidence_string(model_class) if model_class_is_string else f"<invalid:{type(model_class).__name__}>"
        )
        result.metadata["model_class"] = redacted_model_class

        # Check for subclassed models (custom class names)
        if model_class_is_string:
            check_subclassed_model(model_class, result, self.current_file_path)
        else:
            self._mark_inconclusive_scan_result(result, "keras_zip_model_class_invalid_type")
            result.add_check(
                name="Model Class Type Validation",
                passed=False,
                message=f"Invalid model class type: expected str, got {type(model_class).__name__}",
                rule_code="S902",
                severity=IssueSeverity.WARNING,
                location=f"{self.current_file_path}/config.json",
                details={"actual_type": type(model_class).__name__, "expected_type": "str"},
            )

        # Root configs can themselves be serialized callables rather than model containers.
        self._check_layer_module_references(
            model_config,
            result,
            "model_config",
            check_config_fields=False,
            check_nested=False,
        )

        # Check for suspicious model types (Lambda, etc.)
        if model_class_is_string and model_class in self.suspicious_layer_types:
            result.add_check(
                name="Model Type Security Check",
                passed=False,
                message=f"Suspicious model type: {redacted_model_class}",
                severity=IssueSeverity.WARNING,
                location=self.current_file_path,
                details={
                    "model_class": redacted_model_class,
                    "description": self.suspicious_layer_types.get(model_class, ""),
                },
            )

        if "compile_config" in model_config:
            self._scan_compile_config(model_config.get("compile_config"), result)

        # Get layers from config
        layers = []
        config_value = model_config.get("config")
        if "config" in model_config and not isinstance(config_value, dict):
            self._mark_inconclusive_scan_result(result, "keras_zip_model_config_structure_invalid")
            result.add_check(
                name="Model Config Structure Validation",
                passed=False,
                message=f"Invalid model config type: expected dict, got {type(config_value).__name__}",
                rule_code="S902",
                severity=IssueSeverity.INFO,
                location=f"{self.current_file_path}/config.json",
                details={"actual_type": type(config_value).__name__, "expected_type": "dict"},
            )
        elif isinstance(config_value, dict):
            if "layers" in config_value:
                layers_value = config_value["layers"]
                if isinstance(layers_value, list):
                    layers = layers_value
                else:
                    self._mark_inconclusive_scan_result(result, "keras_zip_model_layers_invalid_type")
                    result.add_check(
                        name="Layers Type Validation",
                        passed=False,
                        message=f"Invalid layers type: expected list, got {type(layers_value).__name__}",
                        rule_code="S902",
                        severity=IssueSeverity.INFO,
                        location=f"{self.current_file_path}/config.json",
                        details={"actual_type": type(layers_value).__name__, "expected_type": "list"},
                    )
            elif "layer" in config_value:
                # Single layer model
                layer_value = config_value["layer"]
                if isinstance(layer_value, dict):
                    layers = [layer_value]
                else:
                    self._mark_inconclusive_scan_result(result, "keras_zip_model_layer_invalid_type")
                    result.add_check(
                        name="Single Layer Type Validation",
                        passed=False,
                        message=f"Invalid layer type: expected dict, got {type(layer_value).__name__}",
                        rule_code="S902",
                        severity=IssueSeverity.INFO,
                        location=f"{self.current_file_path}/config.json",
                        details={"actual_type": type(layer_value).__name__, "expected_type": "dict"},
                    )

        # Count of each layer type
        layer_counts: dict[str, int] = {}
        layer_count_display_keys: dict[str, str] = {}
        layer_count_next_occurrences: dict[str, int] = {}

        # Check each layer
        for i, layer in enumerate(layers):
            if not isinstance(layer, dict):
                self._mark_inconclusive_scan_result(result, "keras_zip_model_layer_invalid_type")
                result.add_check(
                    name="Layer Type Validation",
                    passed=False,
                    message=f"Invalid layer type: expected dict, got {type(layer).__name__}",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=f"{self.current_file_path}/config.json",
                    details={"actual_type": type(layer).__name__, "expected_type": "dict", "index": i},
                )
                continue

            layer_class = layer.get("class_name", "")
            layer_name = layer.get("name", f"layer_{i}")
            redacted_layer_name = redact_evidence_string(str(layer_name))

            layer_config = layer.get("config")
            if "config" in layer and not isinstance(layer_config, dict):
                self._mark_inconclusive_scan_result(result, "keras_zip_layer_config_invalid_type")
                result.add_check(
                    name="Layer Config Type Validation",
                    passed=False,
                    message=f"Invalid layer config type: expected dict, got {type(layer_config).__name__}",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=f"{self.current_file_path} (layer: {redacted_layer_name})",
                    details={
                        "layer_name": redacted_layer_name,
                        "actual_type": type(layer_config).__name__,
                        "expected_type": "dict",
                    },
                )

            # Update layer count
            layer_count_identity = (
                f"str:{layer_class}" if isinstance(layer_class, str) else f"invalid:{type(layer_class).__name__}"
            )
            layer_count_key = layer_count_display_keys.get(layer_count_identity)
            if layer_count_key is None:
                display_key = layer_class if isinstance(layer_class, str) else f"<invalid:{type(layer_class).__name__}>"
                layer_count_key = redact_evidence_mapping_key(
                    display_key,
                    layer_counts,
                    next_occurrences=layer_count_next_occurrences,
                )
                layer_count_display_keys[layer_count_identity] = layer_count_key
            layer_counts[layer_count_key] = layer_counts.get(layer_count_key, 0) + 1

            # CVE-2025-49655: TorchModuleWrapper uses torch.load(weights_only=False)
            if layer_class == "TorchModuleWrapper":
                self._check_torch_module_wrapper(result, redacted_layer_name)
            # CVE-2025-1550: Check ALL layers for dangerous module references
            self._check_layer_module_references(layer, result, redacted_layer_name)
            # CVE-2025-12058: StringLookup can load external vocabulary paths even with safe_mode=True
            if layer_class == "StringLookup":
                self._check_stringlookup_vocabulary_path(layer, result, redacted_layer_name)

            is_lambda_layer = self._is_lambda_layer_class(layer_class)

            # Check for Lambda layers
            if is_lambda_layer:
                self._check_lambda_layer(layer, result, layer_name)
                keras_version = result.metadata.get("keras_version")
                classification_keras_version = self._current_keras_version
                cve_2024_3660_status = (
                    self._is_vulnerable_to_cve_2024_3660(classification_keras_version)
                    if isinstance(classification_keras_version, str)
                    else None
                )
                if cve_2024_3660_status is True:
                    # CVE-2024-3660: Lambda layers enable arbitrary code injection
                    result.add_check(
                        name="CVE-2024-3660: Lambda Layer Code Injection",
                        passed=False,
                        message=(
                            f"CVE-2024-3660: Lambda layer '{redacted_layer_name}' in Keras {keras_version} enables "
                            "arbitrary code injection during model loading"
                        ),
                        severity=IssueSeverity.CRITICAL,
                        location=f"{self.current_file_path} (layer: {redacted_layer_name})",
                        details={
                            "layer_name": redacted_layer_name,
                            "layer_class": "Lambda",
                            "keras_version": keras_version,
                            "cve_id": "CVE-2024-3660",
                            "cvss": 9.8,
                            "cwe": "CWE-94",
                            "description": "Lambda layer deserialization can enable arbitrary code injection.",
                            "remediation": "Remove Lambda layers or upgrade Keras to >= 2.13",
                        },
                        why=get_cve_2024_3660_explanation("lambda_code_injection"),
                    )
                elif cve_2024_3660_status is False:
                    result.add_check(
                        name="Lambda Version Risk Check",
                        passed=True,
                        message=(
                            f"Lambda layer '{redacted_layer_name}' detected with Keras {keras_version}; "
                            "outside known CVE-2024-3660 vulnerable range (<2.13.0)"
                        ),
                        location=f"{self.current_file_path} (layer: {redacted_layer_name})",
                        details={
                            "layer_name": redacted_layer_name,
                            "layer_class": "Lambda",
                            "keras_version": keras_version,
                        },
                    )
                else:
                    version_context = (
                        f"keras_version '{keras_version}' is non-canonical"
                        if isinstance(keras_version, str)
                        else "keras_version is unavailable"
                    )
                    result.add_check(
                        name="Lambda Risk (Version Unknown)",
                        passed=False,
                        message=(
                            f"Lambda layer '{redacted_layer_name}' detected but {version_context}; "
                            "cannot confidently attribute CVE-2024-3660 without reliable version context"
                        ),
                        severity=IssueSeverity.WARNING,
                        location=f"{self.current_file_path} (layer: {redacted_layer_name})",
                        details={
                            "layer_name": redacted_layer_name,
                            "layer_class": "Lambda",
                            "keras_version": keras_version,
                            "parse_status": "unknown",
                            "cve_id": "CVE-2024-3660",
                            "cvss": 9.8,
                            "cwe": "CWE-94",
                            "description": "Lambda layer deserialization can enable arbitrary code injection.",
                            "affected_versions": "Keras < 2.13.0",
                            "remediation": "Remove Lambda layers or upgrade Keras to >= 2.13",
                        },
                    )
            elif "class_name" in layer and not isinstance(layer_class, str):
                self._mark_inconclusive_scan_result(result, "keras_zip_layer_class_invalid_type")
                result.add_check(
                    name="Layer Class Type Validation",
                    passed=False,
                    message=f"Invalid layer class type: expected str, got {type(layer_class).__name__}",
                    rule_code="S902",
                    severity=IssueSeverity.WARNING,
                    location=f"{self.current_file_path} (layer: {redacted_layer_name})",
                    details={
                        "layer_name": redacted_layer_name,
                        "actual_type": type(layer_class).__name__,
                        "expected_type": "str",
                    },
                )
            elif layer_class in self.suspicious_layer_types:
                redacted_layer_class = redact_evidence_string(layer_class)
                result.add_check(
                    name="Suspicious Layer Type Detection",
                    passed=False,
                    message=f"Suspicious layer type found: {redacted_layer_class}",
                    severity=IssueSeverity.WARNING,
                    location=f"{self.current_file_path} (layer: {redacted_layer_name})",
                    details={
                        "layer_class": redacted_layer_class,
                        "layer_name": redacted_layer_name,
                        "description": self.suspicious_layer_types[layer_class],
                    },
                )
            elif isinstance(layer_class, str) and layer_class and not self._is_known_safe_serialized_layer(layer):
                redacted_layer_class = redact_evidence_string(layer_class)
                result.add_check(
                    name="Custom Layer Class Detection",
                    passed=False,
                    message=f"Unknown/custom layer class detected: {redacted_layer_class}",
                    severity=IssueSeverity.WARNING,
                    location=f"{self.current_file_path} (layer: {redacted_layer_name})",
                    details={
                        "layer_class": redacted_layer_class,
                        "layer_name": redacted_layer_name,
                        "layer_config": redact_evidence_value(layer.get("config", {}), max_string_chars=200),
                        "risk": "Custom layer classes require external code to load and may execute arbitrary logic",
                    },
                    rule_code="S810",
                )

            # Check for custom objects
            if self._should_flag_registered_object(layer):
                redacted_registered_name = redact_evidence_string(layer["registered_name"])
                result.add_check(
                    name="Custom Object Detection",
                    passed=False,
                    message=f"Custom registered object found: {redacted_registered_name}",
                    severity=IssueSeverity.WARNING,
                    location=f"{self.current_file_path} (layer: {redacted_layer_name})",
                    details={
                        "layer_name": redacted_layer_name,
                        "registered_name": redacted_registered_name,
                    },
                )

            # Recursively check nested models
            normalized_layer_class = (
                normalize_keras_layer_class(layer_class) if isinstance(layer_class, str) else layer_class
            )
            nested_model_class = (
                normalized_layer_class.rsplit(".", 1)[-1] if isinstance(normalized_layer_class, str) else None
            )
            if nested_model_class in self._MODEL_CONTAINER_CLASSES and "config" in layer:
                nested_config = layer["config"]
                if isinstance(nested_config, dict):
                    self._scan_model_config_preserving_metadata(layer, result, nested_layer_depth + 1)
                else:
                    self._mark_inconclusive_scan_result(result, "keras_zip_nested_model_config_invalid_type")
                    result.add_check(
                        name="Nested Model Config Type Validation",
                        passed=False,
                        message=f"Invalid nested model config type: expected dict, got {type(nested_config).__name__}",
                        rule_code="S902",
                        severity=IssueSeverity.INFO,
                        location=f"{self.current_file_path} (layer: {redacted_layer_name})",
                        details={"actual_type": type(nested_config).__name__, "expected_type": "dict"},
                    )

            self._scan_wrapped_layer_config(
                layer_class,
                layer_config,
                result,
                redacted_layer_name,
                nested_layer_depth,
            )

        # Add layer counts to metadata
        result.metadata["layer_counts"] = layer_counts

    def _scan_wrapped_layer_config(
        self,
        layer_class: Any,
        layer_config: Any,
        result: ScanResult,
        layer_name: str,
        nested_layer_depth: int,
    ) -> None:
        """Scan wrapper-owned nested layer payloads such as `TimeDistributed.config.layer`."""
        if not isinstance(layer_config, dict):
            return

        nested_config_keys, require_layer_shape = self._nested_layer_config_for_class(layer_class)
        if not nested_config_keys:
            return

        if require_layer_shape:
            missing_required_keys = nested_config_keys.difference(
                layer_config,
                self._OPTIONAL_NESTED_LAYER_CONFIG_KEYS,
            )
            for config_key in sorted(missing_required_keys):
                self._mark_inconclusive_scan_result(result, "keras_zip_wrapped_layer_required_config_missing")
                result.add_check(
                    name="Wrapped Layer Config Validation",
                    passed=False,
                    message=f"Wrapped Keras layer is missing required config key '{config_key}'",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=f"{self.current_file_path} (layer: {layer_name}, config: {config_key})",
                    details={"config_key": config_key, "required": True},
                )

        for config_key in self._NESTED_LAYER_CONFIG_KEYS:
            if config_key not in nested_config_keys or config_key not in layer_config:
                continue

            nested_layer = layer_config.get(config_key)
            if nested_layer is None and config_key == "backward_layer":
                continue
            if not require_layer_shape and not isinstance(nested_layer, (dict, list)):
                continue

            if isinstance(nested_layer, list) and config_key in self._NESTED_LAYER_LIST_CONFIG_KEYS:
                self._scan_wrapped_layer_list(
                    nested_layer,
                    result,
                    layer_name,
                    config_key,
                    nested_layer_depth,
                    require_layer_shape=require_layer_shape,
                )
                continue

            if self._reserve_nested_layer_items(result, layer_name, config_key, 1) == 0:
                continue
            self._scan_wrapped_layer_value(
                nested_layer,
                result,
                layer_name,
                config_key,
                nested_layer_depth,
                require_layer_shape=require_layer_shape,
            )

    @classmethod
    def _nested_layer_config_for_class(cls, layer_class: Any) -> tuple[frozenset[str], bool]:
        if not isinstance(layer_class, str):
            return frozenset(), False

        normalized_class = normalize_keras_layer_class(layer_class)
        require_layer_shape = "." not in normalized_class
        class_name = normalized_class if require_layer_shape else normalized_class.rsplit(".", 1)[-1]
        return cls._NESTED_LAYER_CONFIG_KEYS_BY_CLASS.get(class_name, frozenset()), require_layer_shape

    def _scan_wrapped_layer_list(
        self,
        nested_layers: list[Any],
        result: ScanResult,
        layer_name: str,
        config_key: str,
        nested_layer_depth: int,
        *,
        require_layer_shape: bool,
    ) -> None:
        candidate_layers = (
            nested_layers if require_layer_shape else [layer for layer in nested_layers if isinstance(layer, dict)]
        )
        items_to_scan = self._reserve_nested_layer_items(result, layer_name, config_key, len(candidate_layers))
        for index, nested_layer in enumerate(candidate_layers[:items_to_scan]):
            self._scan_wrapped_layer_value(
                nested_layer,
                result,
                layer_name,
                f"{config_key}[{index}]",
                nested_layer_depth,
                require_layer_shape=require_layer_shape,
            )

    def _reserve_nested_layer_items(
        self,
        result: ScanResult,
        layer_name: str,
        config_key: str,
        requested_items: int,
    ) -> int:
        if requested_items <= 0:
            return 0

        items_scanned_before = self._nested_layer_items_scanned
        remaining_items = max(self.MAX_NESTED_LAYER_ITEMS - items_scanned_before, 0)
        allowed_items = min(requested_items, remaining_items)
        self._nested_layer_items_scanned += allowed_items

        if allowed_items < requested_items:
            reason = "keras_zip_nested_layer_item_limit_exceeded"
            existing_reasons = result.metadata.get("scan_outcome_reasons")
            already_reported = isinstance(existing_reasons, list) and reason in existing_reasons
            self._mark_inconclusive_scan_result(result, "keras_zip_nested_layer_item_limit_exceeded")
            if not already_reported:
                result.add_check(
                    name="Nested Layer Item Limit",
                    passed=False,
                    message=(
                        f"Wrapped Keras nested-layer traversal exceeds maximum of {self.MAX_NESTED_LAYER_ITEMS} items"
                    ),
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=f"{self.current_file_path} (layer: {layer_name}, config: {config_key})",
                    details={
                        "config_key": config_key,
                        "actual_items": requested_items,
                        "allowed_items": allowed_items,
                        "items_scanned_before": items_scanned_before,
                        "max_nested_layer_items": self.MAX_NESTED_LAYER_ITEMS,
                    },
                )

        return allowed_items

    def _scan_wrapped_layer_value(
        self,
        nested_layer: Any,
        result: ScanResult,
        layer_name: str,
        config_key: str,
        nested_layer_depth: int,
        *,
        require_layer_shape: bool,
    ) -> None:
        if isinstance(nested_layer, dict):
            nested_layer_class = nested_layer.get("class_name")
            if require_layer_shape and (not isinstance(nested_layer_class, str) or not nested_layer_class.strip()):
                self._mark_inconclusive_scan_result(result, "keras_zip_wrapped_layer_structure_invalid")
                result.add_check(
                    name="Wrapped Layer Structure Validation",
                    passed=False,
                    message="Invalid wrapped layer structure: expected non-empty class_name",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=f"{self.current_file_path} (layer: {layer_name}, config: {config_key})",
                    details={"config_key": config_key, "expected_key": "class_name"},
                )
                return
            self._scan_wrapped_layer_dict(nested_layer, result, nested_layer_depth)
            return
        if not require_layer_shape:
            return

        self._mark_inconclusive_scan_result(result, "keras_zip_wrapped_layer_invalid_type")
        result.add_check(
            name="Wrapped Layer Type Validation",
            passed=False,
            message=f"Invalid wrapped layer type: expected dict, got {type(nested_layer).__name__}",
            rule_code="S902",
            severity=IssueSeverity.INFO,
            location=f"{self.current_file_path} (layer: {layer_name}, config: {config_key})",
            details={"config_key": config_key, "actual_type": type(nested_layer).__name__, "expected_type": "dict"},
        )

    def _scan_wrapped_layer_dict(
        self,
        nested_layer: dict[str, Any],
        result: ScanResult,
        nested_layer_depth: int,
    ) -> None:
        synthetic_model_config = {
            "class_name": self._WRAPPED_LAYER_SCAN_MODEL["class_name"],
            "config": {"layers": [nested_layer]},
        }
        self._scan_model_config_preserving_metadata(synthetic_model_config, result, nested_layer_depth + 1)

    def _scan_model_config_preserving_metadata(
        self,
        model_config: dict[str, Any],
        result: ScanResult,
        nested_layer_depth: int,
    ) -> None:
        metadata_snapshot = {
            key: result.metadata[key] for key in ("model_class", "layer_counts") if key in result.metadata
        }
        missing_metadata_keys = {key for key in ("model_class", "layer_counts") if key not in result.metadata}
        try:
            self._scan_model_config(model_config, result, nested_layer_depth)
        finally:
            for key in missing_metadata_keys:
                result.metadata.pop(key, None)
            result.metadata.update(metadata_snapshot)

    def _scan_compile_config(self, compile_config: Any, result: ScanResult) -> None:
        """Inspect compile_config for custom metrics and losses."""
        if compile_config is None:
            return
        if not isinstance(compile_config, dict):
            self._mark_inconclusive_scan_result(result, "keras_zip_compile_config_invalid_type")
            result.add_check(
                name="Compile Config Type Validation",
                passed=False,
                message=f"Invalid compile_config type: expected dict, got {type(compile_config).__name__}",
                rule_code="S902",
                severity=IssueSeverity.INFO,
                location=f"{self.current_file_path}/config.json",
                details={"actual_type": type(compile_config).__name__, "expected_type": "dict"},
            )
            return

        self._check_custom_metric_config(compile_config.get("metrics"), result, "compile_config.metrics")
        self._check_custom_metric_config(
            compile_config.get("weighted_metrics"),
            result,
            "compile_config.weighted_metrics",
        )
        self._check_custom_loss_config(compile_config.get("loss"), result, "compile_config.loss")
        for key in ("optimizer", "loss", "metrics", "weighted_metrics"):
            self._check_nested_serialized_module_references(
                compile_config.get(key),
                result,
                f"compile_config.{key}",
                trusted_container=True,
            )

    def _check_custom_metric_config(self, metrics_config: Any, result: ScanResult, context: str) -> None:
        """Flag custom metrics embedded anywhere in a serialized metric tree."""
        check_custom_metric_config(metrics_config, result, f"{self.current_file_path} ({context})")

    def _check_custom_loss_config(self, loss_config: Any, result: ScanResult, context: str) -> None:
        """Flag custom losses embedded anywhere in a serialized loss tree."""
        check_custom_loss_config(loss_config, result, f"{self.current_file_path} ({context})")

    def _check_torch_module_wrapper(self, result: ScanResult, layer_name: str) -> None:
        """Check for CVE-2025-49655: TorchModuleWrapper deserialization RCE.

        TorchModuleWrapper in Keras >= 3.11.0 and < 3.11.3 calls
        torch.load(weights_only=False) in from_config(),
        enabling arbitrary code execution via pickle deserialization.
        """
        keras_version = result.metadata.get("keras_version")
        vulnerability_status: bool | None = None
        if isinstance(keras_version, str):
            vulnerability_status = self._torchmodule_version_status

        if vulnerability_status is True:
            result.add_check(
                name="CVE-2025-49655: TorchModuleWrapper Deserialization RCE",
                passed=False,
                message=(
                    f"CVE-2025-49655: Layer '{layer_name}' is a TorchModuleWrapper in "
                    f"Keras {keras_version} (>= 3.11.0 and < 3.11.3) — "
                    "uses torch.load(weights_only=False) enabling arbitrary code execution"
                ),
                severity=IssueSeverity.CRITICAL,
                location=f"{self.current_file_path} (layer: {layer_name})",
                details={
                    "layer_name": layer_name,
                    "layer_class": "TorchModuleWrapper",
                    "keras_version": keras_version,
                    "cve_id": "CVE-2025-49655",
                    "cvss": 9.8,
                    "cwe": "CWE-502",
                    "description": (
                        "TorchModuleWrapper in vulnerable Keras versions can deserialize attacker-controlled "
                        "pickles via torch.load(weights_only=False), enabling RCE."
                    ),
                    "affected_versions": "Keras >= 3.11.0 and < 3.11.3",
                    "remediation": "Upgrade Keras to >= 3.11.3",
                },
                why=get_cve_2025_49655_explanation("torch_module_wrapper"),
            )
        elif vulnerability_status is False and isinstance(keras_version, str):
            result.add_check(
                name="TorchModuleWrapper Version Risk Check",
                passed=False,
                message=(
                    f"TorchModuleWrapper detected in Keras {keras_version}; "
                    "version metadata is outside known CVE-2025-49655 range "
                    "(>= 3.11.0 and < 3.11.3), "
                    "but metadata-only assessment is inconclusive without runtime verification"
                ),
                severity=IssueSeverity.WARNING,
                location=f"{self.current_file_path} (layer: {layer_name})",
                details={
                    "layer_name": layer_name,
                    "layer_class": "TorchModuleWrapper",
                    "keras_version": keras_version,
                    "metadata_only_assessment": True,
                    "parse_status": "metadata_non_vulnerable",
                },
            )
        else:
            version_context = (
                f"keras_version '{keras_version}' is non-canonical"
                if isinstance(keras_version, str)
                else "keras_version is unavailable"
            )
            result.add_check(
                name="TorchModuleWrapper Risk (Version Unknown)",
                passed=False,
                message=(
                    f"Layer '{layer_name}' is a TorchModuleWrapper but {version_context}; "
                    "cannot confidently attribute CVE-2025-49655 without reliable version context"
                ),
                severity=IssueSeverity.WARNING,
                location=f"{self.current_file_path} (layer: {layer_name})",
                details={
                    "layer_name": layer_name,
                    "layer_class": "TorchModuleWrapper",
                    "keras_version": keras_version,
                    "parse_status": "unknown",
                    "cve_id": "CVE-2025-49655",
                    "cvss": 9.8,
                    "cwe": "CWE-502",
                    "description": (
                        "TorchModuleWrapper may deserialize unsafe content, but version data was missing or "
                        "non-canonical so CVE attribution confidence is reduced."
                    ),
                    "affected_versions": "Keras >= 3.11.0 and < 3.11.3",
                    "remediation": "Ensure model metadata includes keras_version and upgrade to >= 3.11.3",
                },
                why=get_cve_2025_49655_explanation("torch_module_wrapper"),
            )

    @staticmethod
    def _is_vulnerable_keras_3_11_x(version: str) -> bool | None:
        """Return True for vulnerable Keras 3.11 TorchModuleWrapper versions."""
        version_match = _KERAS_TORCHMODULE_VERSION_PATTERN.match(version)
        if not version_match:
            return None

        try:
            epoch = int(version_match.group(1) or 0)
            release = tuple(int(part) for part in version_match.group(2).split("."))
            suffix = (version_match.group(3) or "").strip().lower()

            suffix_status = KerasZipScanner._classify_keras_release_suffix(suffix)
            if suffix_status is None:
                return None
            if epoch != 0:
                return False

            if release[:2] != (3, 11):
                return False

            while len(release) > 3 and release[-1] == 0:
                release = release[:-1]
            comparison_size = max(len(release), 3)
            normalized_release = release + (0,) * (comparison_size - len(release))
            vulnerable_release = (3, 11, 0) + (0,) * (comparison_size - 3)
            fixed_release = (3, 11, 3) + (0,) * (comparison_size - 3)
            if normalized_release < vulnerable_release or normalized_release > fixed_release:
                return False
            if normalized_release == vulnerable_release:
                return not suffix_status
            if normalized_release == fixed_release:
                return suffix_status
            return True
        except ValueError:
            return None

    @staticmethod
    def _config_reference_symbols(source: dict[str, Any], object_class: str) -> set[str]:
        symbols = {object_class}
        for key in ("config", "registered_name", "function_name"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                symbols.add(value.strip())
        return symbols

    @classmethod
    def _is_dangerous_exact_module_reference(
        cls,
        source: dict[str, Any],
        module_value: str,
        object_class: str,
    ) -> bool:
        symbols = cls._config_reference_symbols(source, object_class)
        dangerous_symbols = _DANGEROUS_EXACT_MODULE_SYMBOLS.get(module_value, frozenset())
        if symbols & dangerous_symbols:
            return True
        prefixes = _DANGEROUS_EXACT_MODULE_SYMBOL_PREFIXES.get(module_value, ())
        return any(symbol.startswith(prefixes) for symbol in symbols) if prefixes else False

    def _check_config_module_reference(
        self,
        source: dict[str, Any],
        key: str,
        module_value: str,
        object_class: str,
        result: ScanResult,
        layer_name: str,
    ) -> None:
        reference_key = (id(source), key, module_value)
        if reference_key in self._checked_config_module_references:
            return
        self._checked_config_module_references.add(reference_key)

        redacted_module_value = redact_evidence_string(module_value)
        redacted_object_class = redact_evidence_string(object_class)
        top_module = module_value.split(".")[0]
        is_dangerous = top_module in _DANGEROUS_CONFIG_MODULE_ROOTS or self._is_dangerous_exact_module_reference(
            source,
            module_value,
            object_class,
        )
        is_outside_allowlist = top_module not in _SAFE_KERAS_MODULE_ROOTS

        if is_dangerous:
            result.add_check(
                name="CVE-2025-1550: Dangerous Module in Config",
                passed=False,
                message=(
                    f"CVE-2025-1550: Layer '{layer_name}' references dangerous module "
                    f"'{redacted_module_value}' in {key} field — arbitrary code execution via safe_mode bypass"
                ),
                severity=IssueSeverity.CRITICAL,
                location=f"{self.current_file_path} (layer: {layer_name})",
                details={
                    "layer_name": layer_name,
                    "layer_class": redacted_object_class,
                    "key": key,
                    "module": redacted_module_value,
                    "cve_id": "CVE-2025-1550",
                    "cvss": 7.3,
                    "cwe": "CWE-94",
                    "description": (
                        "Arbitrary dangerous module references in .keras config can bypass safe_mode "
                        "and execute attacker-controlled code during model loading."
                    ),
                    "remediation": "Upgrade Keras to >= 3.9.0 or remove untrusted module references",
                },
                why=get_cve_2025_1550_explanation("dangerous_module"),
            )
        elif is_outside_allowlist and (
            key == "fn_module" or object_class == "function" or self._is_lambda_layer_class(object_class)
        ):
            result.add_check(
                name="CVE-2025-1550: Untrusted Module in Config",
                passed=False,
                message=(
                    f"CVE-2025-1550: Layer '{layer_name}' references non-allowlisted module "
                    f"'{redacted_module_value}' in {key} field — potential safe_mode bypass"
                ),
                severity=IssueSeverity.WARNING,
                location=f"{self.current_file_path} (layer: {layer_name})",
                details={
                    "layer_name": layer_name,
                    "layer_class": redacted_object_class,
                    "key": key,
                    "module": redacted_module_value,
                    "cve_id": "CVE-2025-1550",
                    "cvss": 7.3,
                    "cwe": "CWE-94",
                    "description": (
                        "Non-allowlisted callable module references may indicate safe_mode bypass "
                        "paths in untrusted .keras config content."
                    ),
                    "remediation": "Upgrade Keras to >= 3.9.0 or verify this module is safe",
                },
                why=get_cve_2025_1550_explanation("untrusted_module"),
            )

    def _check_nested_serialized_module_references(
        self,
        config_value: Any,
        result: ScanResult,
        layer_name: str,
        *,
        trusted_container: bool = False,
    ) -> None:
        """Inspect nested Keras object configs without recursing on attacker-controlled depth."""
        state = self._new_config_traversal_state()
        pending: deque[tuple[Any, str | None, bool, int, str]] = deque(
            [(config_value, None, trusted_container, 0, f"layer:{layer_name}")]
        )
        state.items_pending = 1
        while pending:
            node, parent_key, container_is_trusted, depth, context = pending.popleft()
            state.items_pending -= 1
            if not self._reserve_config_traversal_item(state, result, context=context, depth=depth):
                continue

            if isinstance(node, list):
                if state.item_limit_reached:
                    continue
                for index, item in enumerate(node):
                    child_context = self._config_child_path(context, f"[{index}]")
                    if not self._queue_config_traversal_item(
                        pending,
                        (
                            item,
                            parent_key,
                            container_is_trusted,
                            depth + 1,
                            child_context,
                        ),
                        state,
                        result,
                        context=child_context,
                        depth=depth + 1,
                    ):
                        break
                continue
            if not isinstance(node, dict):
                continue

            object_class = node.get("class_name")
            serialized_shape = isinstance(object_class, str) and "config" in node
            is_serialized_object = serialized_shape and (
                container_is_trusted
                or parent_key in _NESTED_SERIALIZED_OBJECT_KEYS
                or "registered_name" in node
                or object_class == "function"
                or self._is_lambda_layer_class(object_class)
            )
            if is_serialized_object:
                assert isinstance(object_class, str)
                for key in ("module", "fn_module"):
                    module_value = node.get(key)
                    if isinstance(module_value, str) and module_value.strip():
                        self._check_config_module_reference(
                            node,
                            key,
                            module_value.strip(),
                            object_class,
                            result,
                            layer_name,
                        )

            next_container_is_trusted = container_is_trusted and not is_serialized_object
            if state.item_limit_reached:
                continue
            for key, value in node.items():
                if key in {"module", "fn_module", "class_name", "registered_name"}:
                    continue
                child_context = self._config_child_path(context, f".{redact_evidence_string(str(key), max_chars=64)}")
                if not self._queue_config_traversal_item(
                    pending,
                    (
                        value,
                        str(key).lower(),
                        next_container_is_trusted,
                        depth + 1,
                        child_context,
                    ),
                    state,
                    result,
                    context=child_context,
                    depth=depth + 1,
                ):
                    break

    def _check_layer_module_references(
        self,
        layer: dict[str, Any],
        result: ScanResult,
        layer_name: str,
        *,
        check_config_fields: bool = True,
        check_nested: bool = True,
    ) -> None:
        """Check layer config for dangerous module references (CVE-2025-1550).

        CVE-2025-1550: Keras Model.load_model allows arbitrary code execution even
        with safe_mode=True by specifying arbitrary Python modules/functions in
        config.json's module/fn_module keys. This checks ALL layers, not just Lambda.
        """
        layer_class = layer.get("class_name")
        if not isinstance(layer_class, str) or "config" not in layer:
            return

        for key in ("module", "fn_module"):
            layer_value = layer.get(key)
            if isinstance(layer_value, str) and layer_value.strip():
                self._check_config_module_reference(
                    layer,
                    key,
                    layer_value.strip(),
                    layer_class,
                    result,
                    layer_name,
                )

        layer_config = layer.get("config")
        if not isinstance(layer_config, dict):
            return

        if check_config_fields:
            for key in ("module", "fn_module"):
                config_value = layer_config.get(key)
                if isinstance(config_value, str) and config_value.strip():
                    self._check_config_module_reference(
                        layer_config,
                        key,
                        config_value.strip(),
                        layer_class,
                        result,
                        layer_name,
                    )

        if layer_class == "FlaxLayer":
            self._check_nested_serialized_module_references(
                layer_config.get("module"),
                result,
                layer_name,
                trusted_container=True,
            )

        inbound_nodes = layer.get("inbound_nodes")
        if isinstance(inbound_nodes, list):
            for inbound_node in inbound_nodes:
                if not isinstance(inbound_node, dict):
                    continue
                for key in ("args", "kwargs"):
                    self._check_nested_serialized_module_references(
                        inbound_node.get(key),
                        result,
                        layer_name,
                        trusted_container=True,
                    )

        if check_nested:
            self._check_nested_serialized_module_references(layer_config, result, layer_name)

    def _check_get_file_gadget(self, model_config: Any, result: ScanResult) -> None:
        """Check for CVE-2025-8747: keras.utils.get_file gadget bypass.

        CVE-2025-8747: Bypass of CVE-2025-1550 fix. Uses keras.utils.get_file
        as a gadget to download and execute arbitrary files even with safe_mode=True.
        Detected when a single config object references get_file and includes URL arguments.
        """
        traversal_state = self._new_config_traversal_state()
        literal_state = self._new_config_traversal_state()
        url_literal_state = self._new_config_traversal_state()
        for context, node in self._iter_dict_nodes(model_config, result, state=traversal_state):
            if self._is_primarily_documentation(context, node):
                continue
            has_get_file = self._node_has_direct_get_file_reference(node)
            has_url = has_get_file and self._node_has_direct_get_file_url(node)
            if not literal_state.halted and not literal_state.direct_item_limit_reached:
                direct_string_values: list[str] = []
                url_candidate_values: list[str] = []
                nested_url_candidates: list[tuple[Any, str]] = []
                for key, value in node.items():
                    value_context = self._config_child_path(
                        context,
                        f".{redact_evidence_string(str(key), max_chars=64)}",
                    )
                    value_is_direct_string = isinstance(value, str)
                    if value_is_direct_string:
                        if not self._reserve_config_direct_item(
                            literal_state,
                            result,
                            context=value_context,
                            depth=1,
                        ):
                            break
                    elif literal_state.item_limit_reached:
                        if not self._reserve_config_direct_item(
                            literal_state,
                            result,
                            context=value_context,
                            depth=1,
                        ):
                            break
                        continue
                    key_lower = str(key).lower()
                    is_url_candidate_field = key_lower in {"url", "origin", "args", "kwargs"}
                    extracted_literals = self._extract_string_literals(
                        value,
                        result=result,
                        state=literal_state,
                        context=value_context,
                        root_reserved=value_is_direct_string,
                    )
                    if not isinstance(value, dict):
                        direct_string_values.extend(extracted_literals)
                    if is_url_candidate_field:
                        if isinstance(value, dict):
                            nested_url_candidates.append((value, value_context))
                        else:
                            url_candidate_values.extend(extracted_literals)
                bounded_has_get_file = _has_get_file_reference(direct_string_values)
                has_get_file = has_get_file or bounded_has_get_file
                if bounded_has_get_file:
                    for value, value_context in nested_url_candidates:
                        if url_literal_state.halted:
                            break
                        for key, candidate in value.items():
                            candidate_context = self._config_child_path(
                                value_context,
                                f".{redact_evidence_string(str(key), max_chars=64)}",
                            )
                            if not self._reserve_config_direct_item(
                                url_literal_state,
                                result,
                                context=candidate_context,
                                depth=1,
                            ):
                                break
                            if not isinstance(candidate, str):
                                continue
                            bounded_candidate = self._record_config_string_literal(
                                candidate,
                                url_literal_state,
                                result,
                                context=candidate_context,
                            )
                            if bounded_candidate is not None:
                                url_candidate_values.append(bounded_candidate)
                has_url = has_url or any(_URL_PATTERN.search(value) is not None for value in url_candidate_values)
            if not (has_get_file and has_url):
                continue
            result.add_check(
                name="CVE-2025-8747: get_file Gadget Bypass",
                passed=False,
                message=(
                    "CVE-2025-8747: config.json contains structured 'get_file' invocation with URL - "
                    "potential safe_mode bypass via file download gadget"
                ),
                severity=IssueSeverity.CRITICAL,
                location=f"{self.current_file_path}/config.json",
                details={
                    "cve_id": "CVE-2025-8747",
                    "context": redact_evidence_string(context),
                    "cvss": 8.8,
                    "cwe": "CWE-502",
                    "description": (
                        "Keras config references get_file with a remote URL in executable context, "
                        "which can bypass safe_mode protections and load attacker-controlled payloads."
                    ),
                    "affected_versions": "Keras 3.0.0-3.10.0",
                    "remediation": "Upgrade Keras to >= 3.11.0",
                },
                why=get_cve_2025_8747_explanation("get_file_gadget"),
            )
            return

    def _check_get_file_archive_extraction(self, model_config: Any, result: ScanResult) -> None:
        """Check for CVE-2025-12060: truthy get_file tar extraction arguments."""
        traversal_state = self._new_config_traversal_state()
        literal_state = self._new_config_traversal_state()
        for context, node in self._iter_dict_nodes(model_config, result, state=traversal_state):
            if self._is_primarily_documentation(context, node):
                continue
            has_get_file = self._node_has_direct_get_file_reference(node)
            if not literal_state.halted and not literal_state.direct_item_limit_reached:
                direct_string_values: list[str] = []
                for key, value in node.items():
                    value_context = self._config_child_path(
                        context,
                        f".{redact_evidence_string(str(key), max_chars=64)}",
                    )
                    value_is_direct_string = isinstance(value, str)
                    if value_is_direct_string:
                        if not self._reserve_config_direct_item(
                            literal_state,
                            result,
                            context=value_context,
                            depth=1,
                        ):
                            break
                    elif literal_state.item_limit_reached:
                        if not self._reserve_config_direct_item(
                            literal_state,
                            result,
                            context=value_context,
                            depth=1,
                        ):
                            break
                        continue
                    direct_string_values.extend(
                        self._extract_string_literals(
                            value,
                            result=result,
                            state=literal_state,
                            context=value_context,
                            root_reserved=value_is_direct_string,
                        )
                    )

                has_get_file = has_get_file or _has_get_file_reference(direct_string_values)
            origin = self._node_get_file_origin(node)
            if (
                not has_get_file
                or not self._node_has_get_file_tar_extraction_semantics(node)
                or origin is None
                or _URL_PATTERN.match(origin.strip()) is None
            ):
                continue

            result.add_check(
                name="CVE-2025-12060: get_file Archive Extraction Traversal",
                passed=False,
                message=(
                    "CVE-2025-12060: config.json contains keras.utils.get_file with remote tar extraction enabled"
                ),
                severity=IssueSeverity.CRITICAL,
                location=f"{self.current_file_path}/config.json",
                details={
                    "cve_id": "CVE-2025-12060",
                    "context": redact_evidence_string(context),
                    "urls": [_redact_url_for_display(origin)],
                    "cvss": 8.8,
                    "cwe": "CWE-22",
                    "description": (
                        "Truthy keras.utils.get_file untar arguments, or extract arguments with a "
                        "tar-capable archive format, can extract attacker-controlled archives with "
                        "traversal or symlink entries outside the intended destination."
                    ),
                    "affected_versions": "Keras < 3.12.0",
                    "remediation": (
                        "Upgrade Keras to >= 3.12.0 and reject configs that download and extract tar archives."
                    ),
                },
                why=get_cve_2025_12060_explanation("get_file_extract_tar"),
            )
            return

    @staticmethod
    def _node_has_direct_get_file_reference(node: dict[str, Any]) -> bool:
        """Check bounded callable fields without consuming the shared literal budget."""
        for key in ("fn", "function", "callable", "class_name", "registered_name", "config", "module"):
            value = node.get(key)
            if (
                isinstance(value, str)
                and len(value) <= KerasZipScanner.MAX_CONFIG_SECURITY_LITERAL_CHARS
                and _has_get_file_reference([value])
            ):
                return True
            if key not in {"fn", "function", "callable"} or not isinstance(value, dict):
                continue
            for nested_key in ("fn", "function", "callable", "class_name", "registered_name", "config", "module"):
                nested_value = value.get(nested_key)
                if (
                    isinstance(nested_value, str)
                    and len(nested_value) <= KerasZipScanner.MAX_CONFIG_SECURITY_LITERAL_CHARS
                    and _has_get_file_reference([nested_value])
                ):
                    return True
        return False

    @staticmethod
    def _node_has_direct_get_file_url(node: dict[str, Any]) -> bool:
        """Check bounded get_file argument positions for an HTTP(S) URL."""
        candidates: list[Any] = [node.get("origin"), node.get("url")]
        kwargs = node.get("kwargs")
        if isinstance(kwargs, dict):
            candidates.extend((kwargs.get("origin"), kwargs.get("url")))
        args = node.get("args")
        if isinstance(args, (list, tuple)):
            candidates.extend(args[:9])
        return any(
            isinstance(value, str)
            and _URL_PATTERN.search(value[: KerasZipScanner.MAX_CONFIG_SECURITY_LITERAL_CHARS]) is not None
            for value in candidates
        )

    @staticmethod
    def _node_get_file_argument(node: dict[str, Any], name: str, position: int, default: Any) -> Any:
        """Resolve one get_file argument from flattened, kwargs, or positional config forms."""
        if name in node:
            return node[name]

        kwargs = node.get("kwargs")
        if isinstance(kwargs, dict) and name in kwargs:
            return kwargs[name]

        args = node.get("args")
        if isinstance(args, (list, tuple)) and len(args) > position:
            return args[position]

        return default

    @staticmethod
    def _node_get_file_origin(node: dict[str, Any]) -> str | None:
        """Return only the actual get_file origin argument, excluding other URL-valued fields."""
        for container in (node, node.get("kwargs")):
            if not isinstance(container, dict):
                continue
            for key in ("origin", "url"):
                if key in container:
                    value = container[key]
                    return (
                        value[: KerasZipScanner.MAX_CONFIG_SECURITY_LITERAL_CHARS] if isinstance(value, str) else None
                    )

        args = node.get("args")
        if isinstance(args, (list, tuple)) and len(args) > 1:
            value = args[1]
            return value[: KerasZipScanner.MAX_CONFIG_SECURITY_LITERAL_CHARS] if isinstance(value, str) else None

        return None

    @staticmethod
    def _node_has_get_file_tar_extraction_semantics(node: dict[str, Any]) -> bool:
        """Return True when effective get_file arguments can extract a tar archive."""
        untar = KerasZipScanner._node_get_file_argument(node, "untar", 2, False)
        if bool(untar):
            return True

        extract = KerasZipScanner._node_get_file_argument(node, "extract", 7, False)
        if not bool(extract):
            return False

        archive_format = KerasZipScanner._node_get_file_argument(node, "archive_format", 8, "auto")
        return _archive_format_may_extract_tar(archive_format)

    def _check_unsafe_deserialization_bypass(self, model_config: Any, result: ScanResult) -> None:
        """Check for CVE-2025-9906: enable_unsafe_deserialization bypass in config.json.

        CVE-2025-9906: config.json in .keras archives can reference
        keras.config.enable_unsafe_deserialization to disable safe_mode
        from within the deserialization process itself, then load malicious layers.
        """
        if self._has_cve_2025_9906_issue(result):
            return

        if self._has_unsafe_deserialization_reference(model_config, result):
            result.add_check(
                name="CVE-2025-9906: Unsafe Deserialization Bypass",
                passed=False,
                message=(
                    "CVE-2025-9906: config.json contains structured reference to "
                    "keras.config.enable_unsafe_deserialization (safe_mode bypass attempt)"
                ),
                severity=IssueSeverity.CRITICAL,
                location=f"{self.current_file_path}/config.json",
                details={
                    "cve_id": "CVE-2025-9906",
                    "cvss": 8.6,
                    "cwe": "CWE-502",
                    "description": (
                        "config.json can invoke enable_unsafe_deserialization during model loading, "
                        "disabling safe_mode protections for subsequent deserialization."
                    ),
                    "remediation": "Upgrade Keras to >= 3.11.0 and remove untrusted model files",
                    "config_path": "config.json",
                    "matched_symbol": "enable_unsafe_deserialization",
                    "detection_method": "structured_config_scan",
                },
                why=get_cve_2025_9906_explanation("config_bypass"),
            )

    def _check_unsafe_deserialization_bypass_raw(self, raw_config_text: str, result: ScanResult) -> None:
        """Raw-text CVE fallback for malformed JSON configs."""
        if self._has_cve_2025_9906_issue(result):
            return

        lowered = raw_config_text.lower()
        full_symbol_match = re.search(
            r'"(?:loader|fn|function|callable)"\s*:\s*"(keras(?:\.src)?\.config\.enable_unsafe_deserialization)"',
            lowered,
        )
        executable_pair_patterns = (
            r'\{[^{}]{0,1024}"module"\s*:\s*"keras(?:\.src)?\.config"[^{}]{0,1024}'
            r'"(?:fn|function|callable)"\s*:\s*"enable_unsafe_deserialization"',
            r'\{[^{}]{0,1024}"(?:fn|function|callable)"\s*:\s*"enable_unsafe_deserialization"'
            r'[^{}]{0,1024}"module"\s*:\s*"keras(?:\.src)?\.config"',
        )
        has_scoped_executable_pair = any(re.search(pattern, lowered) for pattern in executable_pair_patterns)
        if not (has_scoped_executable_pair or full_symbol_match):
            return
        matched_symbol = full_symbol_match.group(1) if full_symbol_match else "enable_unsafe_deserialization"

        result.add_check(
            name="CVE-2025-9906: Unsafe Deserialization Bypass",
            passed=False,
            message=(
                "CVE-2025-9906: config.json contains raw executable reference to "
                "enable_unsafe_deserialization (safe_mode bypass attempt)"
            ),
            severity=IssueSeverity.CRITICAL,
            location=f"{self.current_file_path}/config.json",
            details={
                "cve_id": "CVE-2025-9906",
                "cvss": 8.6,
                "cwe": "CWE-502",
                "description": (
                    "config.json can invoke enable_unsafe_deserialization during model loading, "
                    "disabling safe_mode protections for subsequent deserialization."
                ),
                "remediation": "Upgrade Keras to >= 3.11.0 and remove untrusted model files",
                "config_path": "config.json",
                "matched_symbol": matched_symbol,
                "detection_method": "raw_config_scan",
            },
            why=get_cve_2025_9906_explanation("config_bypass"),
        )

    def _has_unsafe_deserialization_reference(self, obj: Any, result: ScanResult) -> bool:
        """Detect object-scoped unsafe-deserialization references with bounded traversal."""
        state = self._new_config_traversal_state()
        pending: deque[tuple[Any, int, str, bool]] = deque([(obj, 0, "root", False)])
        state.items_pending = 1
        while pending:
            node, depth, context, has_ancestor_keras_config_context = pending.popleft()
            state.items_pending -= 1
            if not self._reserve_config_traversal_item(state, result, context=context, depth=depth):
                continue

            if isinstance(node, str):
                if state.halted:
                    continue
                token = self._unsafe_deserialization_token(node, state, result, context)
                if token is None:
                    continue
                if token in {
                    "keras.config.enable_unsafe_deserialization",
                    "keras.src.config.enable_unsafe_deserialization",
                }:
                    return True
                if has_ancestor_keras_config_context and self._is_enable_unsafe_token(token):
                    return True
                continue

            if isinstance(node, dict):
                if self._node_has_direct_unsafe_deserialization_reference(
                    node,
                    has_ancestor_keras_config_context=has_ancestor_keras_config_context,
                ):
                    return True
                if state.halted:
                    continue
                if state.direct_item_limit_reached:
                    continue
                has_enable_unsafe = False
                has_keras_config_context = False
                deferred_children: list[tuple[Any, int, str]] = []
                for key, value in node.items():
                    child_context = self._config_child_path(
                        context,
                        f".{redact_evidence_string(str(key), max_chars=64)}",
                    )
                    if not isinstance(value, str):
                        if self._reserve_config_traversal_pending_item(
                            state,
                            result,
                            context=child_context,
                            depth=depth + 1,
                        ):
                            deferred_children.append((value, depth + 1, child_context))
                        elif not self._reserve_config_direct_item(
                            state,
                            result,
                            context=child_context,
                            depth=depth + 1,
                        ):
                            break
                        continue
                    if not self._reserve_config_direct_item(
                        state,
                        result,
                        context=child_context,
                        depth=depth + 1,
                    ):
                        break
                    token = self._unsafe_deserialization_token(
                        value,
                        state,
                        result,
                        child_context,
                    )
                    if token is None:
                        continue
                    if token in {
                        "keras.config.enable_unsafe_deserialization",
                        "keras.src.config.enable_unsafe_deserialization",
                    }:
                        return True
                    has_enable_unsafe = has_enable_unsafe or self._is_enable_unsafe_token(token)
                    has_keras_config_context = has_keras_config_context or self._is_keras_config_context_token(token)

                if has_enable_unsafe and (has_keras_config_context or has_ancestor_keras_config_context):
                    return True

                child_has_keras_config_context = has_ancestor_keras_config_context or has_keras_config_context
                pending.extend(
                    (value, child_depth, child_context, child_has_keras_config_context)
                    for value, child_depth, child_context in deferred_children
                )
                continue

            if isinstance(node, list):
                if state.item_limit_reached:
                    continue
                for index, value in enumerate(node):
                    child_context = self._config_child_path(context, f"[{index}]")
                    if not self._queue_config_traversal_item(
                        pending,
                        (value, depth + 1, child_context, has_ancestor_keras_config_context),
                        state,
                        result,
                        context=child_context,
                        depth=depth + 1,
                    ):
                        break

        return False

    @classmethod
    def _node_has_direct_unsafe_deserialization_reference(
        cls,
        node: dict[str, Any],
        *,
        has_ancestor_keras_config_context: bool,
    ) -> bool:
        """Check fixed executable fields after generic literal accounting stops."""
        has_enable_unsafe = False
        has_keras_config_context = False
        for key in ("loader", "fn", "function", "callable", "module", "fn_module"):
            value = node.get(key)
            if not isinstance(value, str) or len(value) > cls.MAX_CONFIG_SECURITY_LITERAL_CHARS:
                continue
            token = value.strip().lower()
            if token in {
                "keras.config.enable_unsafe_deserialization",
                "keras.src.config.enable_unsafe_deserialization",
            }:
                return True
            has_enable_unsafe = has_enable_unsafe or cls._is_enable_unsafe_token(token)
            has_keras_config_context = has_keras_config_context or cls._is_keras_config_context_token(token)

        return has_enable_unsafe and (has_keras_config_context or has_ancestor_keras_config_context)

    def _unsafe_deserialization_token(
        self,
        value: str,
        state: _ConfigTraversalState,
        result: ScanResult,
        context: str,
    ) -> str | None:
        bounded_value = self._record_config_string_literal(value, state, result, context=context)
        if bounded_value is None or self._is_primarily_documentation_text(bounded_value):
            return None
        return bounded_value.strip().lower()

    @staticmethod
    def _is_enable_unsafe_token(token: str) -> bool:
        return token == "enable_unsafe_deserialization" or token.endswith(".enable_unsafe_deserialization")

    @staticmethod
    def _is_keras_config_context_token(token: str) -> bool:
        return (
            token == "keras.config"
            or token.startswith("keras.config.")
            or token == "keras.src.config"
            or token.startswith("keras.src.config.")
        )

    @staticmethod
    def _has_cve_2025_9906_issue(result: ScanResult) -> bool:
        """Avoid duplicate CVE-2025-9906 checks from raw + structured paths."""
        return any(issue.details.get("cve_id") == "CVE-2025-9906" for issue in result.issues)

    def _check_stringlookup_vocabulary_path(self, layer: dict[str, Any], result: ScanResult, layer_name: str) -> None:
        """Check for CVE-2025-12058: external StringLookup vocabulary paths in .keras configs."""
        layer_config = layer.get("config")
        if not isinstance(layer_config, dict):
            return

        vocabulary = layer_config.get("vocabulary")
        if not isinstance(vocabulary, str) or not self._is_external_stringlookup_vocabulary(vocabulary):
            return

        keras_version = result.metadata.get("keras_version")
        classification_keras_version = self._current_keras_version
        redacted_vocabulary = (
            redact_url_for_finding(vocabulary)
            if _URL_SCHEME_PATTERN.match(vocabulary.strip())
            else redact_evidence_string(vocabulary)
        )
        location = f"{self.current_file_path} (layer: {layer_name})"
        details = {
            "layer_name": layer_name,
            "layer_class": "StringLookup",
            "vocabulary": redacted_vocabulary,
            "cve_id": "CVE-2025-12058",
            "cvss": 5.9,
            "cwe": "CWE-502, CWE-918",
            "description": (
                "StringLookup vocabulary paths can trigger arbitrary local file loading or SSRF when a crafted "
                ".keras archive is loaded."
            ),
            "remediation": "Upgrade Keras to >= 3.12.0 and avoid loading models with external vocabulary paths.",
            "affected_versions": "Keras < 3.12.0",
        }
        vulnerability_status = (
            self._is_vulnerable_to_cve_2025_12058(classification_keras_version)
            if isinstance(classification_keras_version, str)
            else None
        )

        if vulnerability_status is True:
            details["keras_version"] = keras_version
            result.add_check(
                name="CVE-2025-12058: StringLookup External Vocabulary Path",
                passed=False,
                message=(
                    f"CVE-2025-12058: StringLookup layer '{layer_name}' in Keras {keras_version} references "
                    f"external vocabulary path '{redacted_vocabulary}', which can expose local files or trigger SSRF "
                    "during model loading"
                ),
                severity=IssueSeverity.WARNING,
                location=location,
                details=details,
                why=get_cve_2025_12058_explanation("stringlookup_external_vocabulary"),
            )
            return

        if vulnerability_status is False:
            details["keras_version"] = keras_version
            details["metadata_only_assessment"] = True
            details["parse_status"] = "untrusted_artifact_version"
            details["version_source"] = "keras_archive_metadata"
            result.add_check(
                name="StringLookup External Vocabulary Risk (Untrusted Version Metadata)",
                passed=False,
                message=(
                    f"StringLookup layer '{layer_name}' references external vocabulary path '{redacted_vocabulary}', "
                    f"and archive metadata claims Keras {keras_version} outside the known CVE-2025-12058 "
                    "vulnerable range (<3.12.0), but artifact-controlled version metadata cannot prove the loader "
                    "runtime is fixed"
                ),
                severity=IssueSeverity.WARNING,
                location=location,
                details=details,
                why=get_cve_2025_12058_explanation("stringlookup_external_vocabulary"),
            )
            return

        if isinstance(keras_version, str):
            details["keras_version"] = keras_version
            version_context = f"keras_version '{keras_version}' is non-canonical"
        else:
            version_context = "keras_version is unavailable"
        result.add_check(
            name="StringLookup External Vocabulary Risk (Version Unknown)",
            passed=False,
            message=(
                f"StringLookup layer '{layer_name}' references external vocabulary path '{redacted_vocabulary}', but "
                f"{version_context}; cannot confidently attribute CVE-2025-12058 without version context"
            ),
            severity=IssueSeverity.WARNING,
            location=location,
            details=details,
            why=get_cve_2025_12058_explanation("stringlookup_external_vocabulary"),
        )

    @staticmethod
    def _is_external_stringlookup_vocabulary(vocabulary: Any) -> bool:
        """Return whether Keras interprets the vocabulary value as an external path."""
        return isinstance(vocabulary, str) and bool(vocabulary.strip())

    def _check_embedded_hdf5_weights_external_references(self, archive: zipfile.ZipFile, result: ScanResult) -> None:
        """Detect CVE-2026-1669 external HDF5 references inside embedded .keras weights."""
        weights_info = self._get_archive_member_info(archive, _KERAS_WEIGHTS_ENTRY)
        if weights_info is None:
            return

        if weights_info.file_size > self.max_embedded_weights_bytes:
            weights_entry = weights_info.filename
            display_weights_entry = self._redact_archive_member_name(weights_entry)
            self._mark_inconclusive_scan_result(result, "keras_zip_embedded_weights_too_large")
            result.add_check(
                name="Embedded Weights Size Limit",
                passed=False,
                message=(
                    "Skipping embedded model.weights.h5 inspection because the uncompressed weights entry "
                    f"exceeds the configured size limit ({weights_info.file_size} > {self.max_embedded_weights_bytes})"
                ),
                severity=IssueSeverity.INFO,
                location=f"{self.current_file_path}:{display_weights_entry}",
                details={
                    "entry": display_weights_entry,
                    "uncompressed_size": weights_info.file_size,
                    "compressed_size": weights_info.compress_size,
                    "max_embedded_weights_bytes": self.max_embedded_weights_bytes,
                },
                why=(
                    "Large embedded archive members can consume excessive disk space or processing time when "
                    "extracted for inspection."
                ),
            )
            return

        if not HAS_H5PY:
            hdf5_signature_offset = _zip_member_hdf5_signature_offset(archive, weights_info)
            if hdf5_signature_offset is None:
                self._content_route_embedded_weights = True
                if not is_hdf5_signature_probe_complete(weights_info.file_size):
                    self._mark_embedded_weights_hdf5_signature_probe_incomplete(weights_info, result)
                return

            weights_entry = weights_info.filename
            display_weights_entry = self._redact_archive_member_name(weights_entry)
            reason = "keras_zip_embedded_weights_h5py_unavailable"
            result.metadata["embedded_weights_hdf5_signature_offset"] = hdf5_signature_offset
            self._mark_inconclusive_scan_result(result, reason)
            self._scan_embedded_weights_security_prefix(
                archive,
                weights_info,
                hdf5_signature_offset,
                result,
                hdf5_signature_offset=hdf5_signature_offset,
            )
            result.add_check(
                name="Embedded Weights H5PY Library Check",
                passed=False,
                message=(
                    "Skipping embedded model.weights.h5 inspection because h5py is required for HDF5 weights "
                    "analysis. Install with 'pip install modelaudit[h5]'."
                ),
                severity=IssueSeverity.INFO,
                location=f"{self.current_file_path}:{display_weights_entry}",
                details={
                    "entry": display_weights_entry,
                    "required_package": "h5py",
                    "hdf5_signature_offset": hdf5_signature_offset,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": reason,
                },
                rule_code="S902",
            )
            return

        temp_path = None
        findings: list[dict[str, Any]] = []
        external_reference_analysis: dict[str, Any] = {}
        try:
            with tempfile.NamedTemporaryFile(suffix=".h5", delete=False) as temp_file:
                temp_path = temp_file.name
                extracted_bytes = 0
                with archive.open(weights_info, "r") as source:
                    while True:
                        chunk = source.read(64 * 1024)
                        if not chunk:
                            break
                        extracted_bytes += len(chunk)
                        if extracted_bytes > self.max_embedded_weights_bytes:
                            raise _EmbeddedWeightsLimitExceeded(
                                "Embedded model.weights.h5 exceeded the configured extraction limit "
                                f"({self.max_embedded_weights_bytes} bytes) after reading {extracted_bytes} bytes",
                                extracted_bytes,
                            )
                        temp_file.write(chunk)

            with h5py.File(temp_path, "r") as h5_file:
                findings = self._collect_hdf5_external_references(
                    h5_file,
                    analysis=external_reference_analysis,
                )
        except _EmbeddedWeightsLimitExceeded as exc:
            weights_entry = weights_info.filename
            display_weights_entry = self._redact_archive_member_name(weights_entry)
            self._mark_inconclusive_scan_result(result, "keras_zip_embedded_weights_too_large")
            result.add_check(
                name="Embedded Weights Size Limit",
                passed=False,
                message=str(exc),
                severity=IssueSeverity.INFO,
                location=f"{self.current_file_path}:{display_weights_entry}",
                details={
                    "entry": display_weights_entry,
                    "extracted_bytes": exc.extracted_bytes,
                    "uncompressed_size": weights_info.file_size,
                    "compressed_size": weights_info.compress_size,
                    "max_embedded_weights_bytes": self.max_embedded_weights_bytes,
                },
                why=(
                    "Large embedded archive members can consume excessive disk space or processing time when "
                    "extracted for inspection."
                ),
            )
            return
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)

        if external_reference_analysis.get("link_visits_truncated") or external_reference_analysis.get(
            "virtual_source_visits_truncated"
        ):
            reason = "keras_zip_external_reference_analysis_limit_exceeded"
            self._mark_inconclusive_scan_result(result, reason)
            result.add_check(
                name="Embedded HDF5 External Reference Analysis Limit",
                passed=False,
                message="Embedded Keras HDF5 external-reference analysis reached a configured safety limit",
                severity=IssueSeverity.INFO,
                location=f"{self.current_file_path}:{self._redact_archive_member_name(weights_info.filename)}",
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": reason,
                    **external_reference_analysis,
                },
                rule_code="S902",
            )

        if not findings:
            return

        keras_version = result.metadata.get("keras_version")
        classification_keras_version = self._current_keras_version
        location = f"{self.current_file_path}:{self._redact_archive_member_name(weights_info.filename)}"
        details = {
            "cve_id": "CVE-2026-1669",
            "cvss": 8.1,
            "cwe": "CWE-200, CWE-73",
            "description": (
                "HDF5 external storage, virtual datasets, or ExternalLink entries can cause Keras weight loading "
                "to read arbitrary host files into model tensors."
            ),
            "remediation": "Upgrade to Keras >= 3.12.1 or >= 3.13.2 and reject weights using HDF5 external references.",
            "external_references": findings,
            "affected_versions": "Keras >= 3.0.0, < 3.12.1 and >= 3.13.0, < 3.13.2",
        }
        if (
            external_reference_analysis.get("external_references_truncated")
            or external_reference_analysis.get("external_storage_segments_truncated")
            or external_reference_analysis.get("virtual_sources_truncated")
        ):
            details.update(
                {
                    "external_reference_count": external_reference_analysis["external_reference_count"],
                    "external_references_truncated": external_reference_analysis["external_references_truncated"],
                    "external_storage_segments_truncated": external_reference_analysis[
                        "external_storage_segments_truncated"
                    ],
                    "virtual_sources_truncated": external_reference_analysis["virtual_sources_truncated"],
                }
            )

        cve_2026_1669_status = (
            self._is_vulnerable_to_cve_2026_1669(classification_keras_version)
            if isinstance(classification_keras_version, str)
            else None
        )
        if cve_2026_1669_status is True:
            details["keras_version"] = keras_version
            result.add_check(
                name="CVE-2026-1669: HDF5 External Weight Reference",
                passed=False,
                message=(
                    f"CVE-2026-1669: embedded Keras {keras_version} weights use HDF5 external references that can "
                    "disclose arbitrary local file contents during model loading"
                ),
                severity=IssueSeverity.WARNING,
                location=location,
                details=details,
                why=get_cve_2026_1669_explanation("hdf5_external_reference"),
            )
            return

        if cve_2026_1669_status is False:
            details["keras_version"] = keras_version
            details["metadata_only_assessment"] = True
            details["parse_status"] = "untrusted_artifact_version"
            details["version_source"] = "keras_archive_metadata"
            result.add_check(
                name="HDF5 External Weight Reference Metadata Check",
                passed=False,
                message=(
                    "Embedded HDF5 external references detected in weights, and archive metadata claims "
                    f"Keras {keras_version} outside the known CVE-2026-1669 vulnerable ranges; "
                    "metadata-only assessment is inconclusive without runtime verification"
                ),
                severity=IssueSeverity.WARNING,
                location=location,
                details=details
                | {
                    "keras_version": keras_version,
                    "affected_versions": "Keras >= 3.0.0, < 3.12.1 and >= 3.13.0, < 3.13.2",
                    "metadata_only_assessment": True,
                    "parse_status": "metadata_non_vulnerable",
                },
                why=get_cve_2026_1669_explanation("hdf5_external_reference"),
            )
            return

        version_context = (
            f"keras_version '{keras_version}' is non-canonical"
            if isinstance(keras_version, str)
            else "keras_version is unavailable"
        )
        if isinstance(keras_version, str):
            details["keras_version"] = keras_version
        result.add_check(
            name="HDF5 External Weight Reference Risk (Version Unknown)",
            passed=False,
            message=(
                f"Embedded HDF5 external references detected in weights, but {version_context}; cannot confidently "
                "attribute CVE-2026-1669 without reliable version context"
            ),
            severity=IssueSeverity.WARNING,
            location=location,
            details=details
            | {
                "affected_versions": "Keras >= 3.0.0, < 3.12.1 and >= 3.13.0, < 3.13.2",
                "parse_status": "unknown",
            },
        )

    def _mark_embedded_weights_hdf5_signature_probe_incomplete(
        self,
        weights_info: zipfile.ZipInfo,
        result: ScanResult,
    ) -> None:
        weights_entry = weights_info.filename
        display_weights_entry = self._redact_archive_member_name(weights_entry)
        reason = "keras_zip_embedded_weights_hdf5_signature_probe_incomplete"
        self._mark_inconclusive_scan_result(result, reason)
        result.add_check(
            name="Embedded Weights HDF5 Signature Probe",
            passed=False,
            message=(
                "Skipping embedded model.weights.h5 inspection because h5py is unavailable and the weights entry "
                "is too large to rule out a valid HDF5 user-block signature within the bounded probe window. "
                "Install with 'pip install modelaudit[h5]'."
            ),
            severity=IssueSeverity.INFO,
            location=f"{self.current_file_path}:{display_weights_entry}",
            details={
                "entry": display_weights_entry,
                "required_package": "h5py",
                "file_size": weights_info.file_size,
                "hdf5_signature_probe_max_bytes": HDF5_SIGNATURE_SCAN_MAX_BYTES,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
            rule_code="S902",
        )

    def _scan_embedded_weights_security_prefix(
        self,
        archive: zipfile.ZipFile,
        weights_info: zipfile.ZipInfo,
        prefix_bytes: int,
        result: ScanResult,
        *,
        hdf5_signature_offset: int | None,
    ) -> None:
        """Content-route security findings hidden before the HDF5 user-block signature."""
        if prefix_bytes <= 0:
            return

        weights_entry = weights_info.filename
        display_weights_entry = self._redact_archive_member_name(weights_entry)
        from .pickle_scanner import PickleScanner
        from .picklescan_adapter import apply_pickle_member_context

        nested_config = dict(self.config)
        nested_config.pop("skip_archive_entries", None)
        nested_config.pop(ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY, None)
        nested_config.pop(ZIP_CONTENT_ONLY_MEMBER_ENTRIES_CONFIG_KEY, None)
        nested_config.pop(KNOWN_UNREADABLE_ARCHIVE_ENTRY_OFFSETS_CONFIG_KEY, None)
        nested_config["cache_enabled"] = False
        nested_config["_archive_depth"] = get_archive_depth(self.config) + 1

        zip_scanner = ZipScanner(config=self.config)
        if self._scan_embedded_weights_full_payload_security(
            archive,
            weights_info,
            result,
            zip_scanner=zip_scanner,
            nested_config=nested_config,
            hdf5_signature_offset=hdf5_signature_offset,
        ):
            return

        prefix_segments = _content_routable_hdf5_userblock_segments(
            _read_zip_member_prefix(archive, weights_info, prefix_bytes)
        )
        if not prefix_segments:
            return

        for segment_index, prefix in enumerate(prefix_segments):
            temp_path: str | None = None
            try:
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file.write(prefix)
                    temp_path = temp_file.name

                prefix_result = zip_scanner._scan_nested_archive_entry(temp_path, nested_config)
                if self._scan_result_has_actionable_security_findings(prefix_result):
                    zip_scanner._rewrite_nested_result_context(
                        prefix_result,
                        temp_path,
                        self.current_file_path,
                        display_weights_entry,
                    )
                    self._annotate_embedded_weights_security_prefix_result(
                        prefix_result,
                        weights_entry=display_weights_entry,
                        hdf5_signature_offset=hdf5_signature_offset,
                    )
                    result.merge_member_result(
                        prefix_result,
                        f"{display_weights_entry}:embedded-weights-prefix-{segment_index}.pkl",
                    )
                    continue
                pickle_scan_was_selection_skipped = (
                    prefix_result.scanner_name == "scanner_selection"
                    and prefix_result.metadata.get("skipped_scanner_id") == "pickle"
                )
                if prefix_result.scanner_name != "unknown" and not pickle_scan_was_selection_skipped:
                    continue
            finally:
                if temp_path is not None:
                    Path(temp_path).unlink(missing_ok=True)

            pickle_source = (
                f"{self.current_file_path}:{display_weights_entry}:embedded-weights-prefix-{segment_index}.pkl"
            )
            pickle_result = PickleScanner(config=self.config).scan_stream(
                io.BytesIO(prefix),
                len(prefix),
                source=pickle_source,
            )
            if self._scan_result_has_actionable_security_findings(pickle_result):
                apply_pickle_member_context(
                    pickle_result,
                    archive_path=self.current_file_path,
                    member_name=display_weights_entry,
                )
                self._annotate_embedded_weights_security_prefix_result(
                    pickle_result,
                    weights_entry=display_weights_entry,
                    hdf5_signature_offset=hdf5_signature_offset,
                )
                result.merge_member_result(
                    pickle_result,
                    f"{display_weights_entry}:embedded-weights-prefix-{segment_index}.pkl",
                )

    def _scan_embedded_weights_full_payload_security(
        self,
        archive: zipfile.ZipFile,
        weights_info: zipfile.ZipInfo,
        result: ScanResult,
        *,
        zip_scanner: ZipScanner,
        nested_config: dict[str, Any],
        hdf5_signature_offset: int | None,
    ) -> bool:
        """Preserve actionable findings from a polyglot's complete weights payload."""
        temp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_path = temp_file.name
                copied_bytes = 0
                with archive.open(weights_info, "r") as source:
                    while True:
                        chunk = source.read(64 * 1024)
                        if not chunk:
                            break
                        copied_bytes += len(chunk)
                        if copied_bytes > self.max_embedded_weights_bytes:
                            return False
                        temp_file.write(chunk)

            full_result = zip_scanner._scan_nested_archive_entry(temp_path, nested_config)
            if not self._scan_result_has_actionable_security_findings(full_result):
                return False

            zip_scanner._rewrite_nested_result_context(
                full_result,
                temp_path,
                self.current_file_path,
                self._redact_archive_member_name(weights_info.filename),
            )
            self._annotate_embedded_weights_security_prefix_result(
                full_result,
                weights_entry=self._redact_archive_member_name(weights_info.filename),
                hdf5_signature_offset=hdf5_signature_offset,
            )
            result.merge_member_result(full_result, self._redact_archive_member_name(weights_info.filename))
            return True
        finally:
            if temp_path is not None:
                Path(temp_path).unlink(missing_ok=True)

    @staticmethod
    def _annotate_embedded_weights_security_prefix_result(
        prefix_result: ScanResult,
        *,
        weights_entry: str,
        hdf5_signature_offset: int | None,
    ) -> None:
        display_weights_entry = redact_evidence_string(
            weights_entry,
            max_chars=KerasZipScanner.MAX_ARCHIVE_MEMBER_TEXT_CHARS,
        )
        for check in prefix_result.checks:
            check.details.setdefault("zip_entry", display_weights_entry)
            check.details["embedded_weights_hdf5_userblock"] = True
            if hdf5_signature_offset is None:
                check.details["hdf5_signature_probe_max_bytes"] = HDF5_SIGNATURE_SCAN_MAX_BYTES
            else:
                check.details["hdf5_signature_offset"] = hdf5_signature_offset
        for issue in prefix_result.issues:
            issue.details.setdefault("zip_entry", display_weights_entry)
            issue.details["embedded_weights_hdf5_userblock"] = True
            if hdf5_signature_offset is None:
                issue.details["hdf5_signature_probe_max_bytes"] = HDF5_SIGNATURE_SCAN_MAX_BYTES
            else:
                issue.details["hdf5_signature_offset"] = hdf5_signature_offset

    @classmethod
    def _collect_hdf5_external_references(
        cls,
        h5_file: Any,
        *,
        analysis: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Collect HDF5 links, external storage, and virtual datasets without following sources."""
        findings: list[dict[str, Any]] = []
        external_reference_count = 0
        external_storage_segments_truncated = False
        virtual_sources_truncated = False
        visited_virtual_source_count = 0
        virtual_source_visits_truncated = False

        def visit(name: str, link: Any, obj: Any, path_truncated: bool) -> None:
            nonlocal external_reference_count, external_storage_segments_truncated
            nonlocal visited_virtual_source_count, virtual_source_visits_truncated, virtual_sources_truncated
            if isinstance(link, h5py.ExternalLink):
                external_reference_count += 1
                if len(findings) < cls.MAX_HDF5_EXTERNAL_REFERENCE_REPORTS:
                    filename, filename_truncated = cls._bounded_hdf5_reference_text(link.filename)
                    target_path, target_path_truncated = cls._bounded_hdf5_reference_text(link.path)
                    link_finding: dict[str, Any] = {
                        "kind": "ExternalLink",
                        "hdf5_path": f"/{name}".replace("//", "/"),
                        "filename": filename,
                        "path": target_path,
                    }
                    if path_truncated:
                        link_finding["hdf5_path_truncated"] = True
                    if filename_truncated:
                        link_finding["filename_truncated"] = True
                    if target_path_truncated:
                        link_finding["path_truncated"] = True
                    findings.append(link_finding)
                return

            if not isinstance(obj, h5py.Dataset):
                return

            storage_properties = obj.id.get_create_plist()
            external_storage_segment_count = storage_properties.get_external_count()
            if external_storage_segment_count > 0:
                external_reference_count += 1
                if len(findings) < cls.MAX_HDF5_EXTERNAL_REFERENCE_REPORTS:
                    segments = [
                        {
                            **cls._hdf5_external_storage_filename_details(filename),
                            "offset": int(offset),
                            "size": int(size),
                        }
                        for filename, offset, size in (
                            storage_properties.get_external(index)
                            for index in range(
                                min(
                                    external_storage_segment_count,
                                    cls.MAX_HDF5_EXTERNAL_STORAGE_SEGMENT_REPORTS,
                                )
                            )
                        )
                    ]
                    storage_finding: dict[str, Any] = {
                        "kind": "external_storage",
                        "hdf5_path": f"/{name}".replace("//", "/"),
                        "segments": segments,
                    }
                    if path_truncated:
                        storage_finding["hdf5_path_truncated"] = True
                    if external_storage_segment_count > len(segments):
                        external_storage_segments_truncated = True
                        storage_finding["segment_count"] = external_storage_segment_count
                        storage_finding["segments_truncated"] = True
                    findings.append(storage_finding)

            try:
                virtual_source_count = storage_properties.get_virtual_count()
            except ValueError:
                virtual_source_count = 0
            if virtual_source_count <= 0:
                return

            remaining_virtual_source_visits = max(
                cls.MAX_HDF5_VIRTUAL_SOURCE_VISITS - visited_virtual_source_count,
                0,
            )
            mappings_to_visit = min(virtual_source_count, remaining_virtual_source_visits)
            external_virtual_source_count = 0
            sources: list[dict[str, Any]] = []
            for index in range(mappings_to_visit):
                visited_virtual_source_count += 1
                source_filename = storage_properties.get_virtual_filename(index)
                if os.fsdecode(source_filename) == ".":
                    continue
                external_virtual_source_count += 1
                if len(sources) < cls.MAX_HDF5_EXTERNAL_STORAGE_SEGMENT_REPORTS:
                    sources.append(
                        cls._hdf5_virtual_source_details(
                            source_filename,
                            storage_properties.get_virtual_dsetname(index),
                        )
                    )

            if mappings_to_visit < virtual_source_count:
                virtual_source_visits_truncated = True
            if external_virtual_source_count <= 0:
                return

            external_reference_count += 1
            if len(findings) >= cls.MAX_HDF5_EXTERNAL_REFERENCE_REPORTS:
                return

            virtual_finding: dict[str, Any] = {
                "kind": "virtual_dataset",
                "hdf5_path": f"/{name}".replace("//", "/"),
                "sources": sources,
            }
            if path_truncated:
                virtual_finding["hdf5_path_truncated"] = True
            if external_virtual_source_count > len(sources):
                virtual_sources_truncated = True
                virtual_finding["source_count"] = external_virtual_source_count
                virtual_finding["sources_truncated"] = True
            findings.append(virtual_finding)

        visited_link_count, link_visits_truncated = cls._visit_hdf5_links(
            h5_file,
            visit,
            max_links=cls.MAX_HDF5_LINK_VISITS,
        )
        if analysis is not None:
            analysis.update(
                {
                    "visited_link_count": visited_link_count,
                    "max_link_visits": cls.MAX_HDF5_LINK_VISITS,
                    "link_visits_truncated": link_visits_truncated,
                    "external_reference_count": external_reference_count,
                    "reported_external_reference_count": len(findings),
                    "external_references_truncated": external_reference_count > len(findings),
                    "external_storage_segments_truncated": external_storage_segments_truncated,
                    "visited_virtual_source_count": visited_virtual_source_count,
                    "max_virtual_source_visits": cls.MAX_HDF5_VIRTUAL_SOURCE_VISITS,
                    "virtual_source_visits_truncated": virtual_source_visits_truncated,
                    "virtual_sources_truncated": virtual_sources_truncated,
                }
            )

        return findings

    @classmethod
    def _visit_hdf5_links(cls, h5_file: Any, visit: Any, *, max_links: int) -> tuple[int, bool]:
        """Traverse HDF5 links without following ExternalLink or SoftLink targets."""
        visited_link_count = 0
        visited_group_ids: set[Any] = set()
        groups_to_visit: list[tuple[Any, str, bool]] = [(h5_file, "", False)]

        while groups_to_visit:
            group, prefix, prefix_truncated = groups_to_visit.pop()
            group_identity = cls._hdf5_object_identity(group)
            if group_identity in visited_group_ids:
                continue
            visited_group_ids.add(group_identity)

            for child_name in group:
                if visited_link_count >= max_links:
                    return visited_link_count, True
                visited_link_count += 1

                child_key = str(child_name)
                child_path, child_path_truncated = cls._bounded_hdf5_child_path(
                    prefix,
                    child_key,
                    prefix_truncated=prefix_truncated,
                )
                link = group.get(child_name, getlink=True)
                obj = group.get(child_name, getlink=False) if isinstance(link, h5py.HardLink) else None
                visit(child_path, link, obj, child_path_truncated)

                if isinstance(obj, h5py.Group):
                    groups_to_visit.append((obj, child_path, child_path_truncated))

        return visited_link_count, False

    @classmethod
    def _bounded_hdf5_child_path(
        cls,
        prefix: str,
        child_name: str,
        *,
        prefix_truncated: bool,
    ) -> tuple[str, bool]:
        """Join an HDF5 child path while bounding retained evidence."""
        child_path = f"{prefix}/{child_name}" if prefix else child_name
        bounded_path, path_truncated = cls._bounded_hdf5_reference_text(child_path)
        return bounded_path, prefix_truncated or path_truncated

    @classmethod
    def _bounded_hdf5_reference_text(cls, value: Any) -> tuple[str, bool]:
        """Return redacted, bounded HDF5 path evidence and whether it was truncated."""
        text = os.fsdecode(value)
        redacted_text = redact_evidence_string(text, max_chars=cls.MAX_HDF5_REFERENCE_TEXT_CHARS)
        was_truncated = max(len(text), len(redacted_text)) > cls.MAX_HDF5_REFERENCE_TEXT_CHARS
        return redacted_text[: cls.MAX_HDF5_REFERENCE_TEXT_CHARS], was_truncated

    @classmethod
    def _hdf5_external_storage_filename_details(cls, filename: Any) -> dict[str, Any]:
        """Return bounded external-storage filename evidence."""
        bounded_filename, filename_truncated = cls._bounded_hdf5_reference_text(filename)
        details: dict[str, Any] = {"filename": bounded_filename}
        if filename_truncated:
            details["filename_truncated"] = True
        return details

    @classmethod
    def _hdf5_virtual_source_details(cls, filename: Any, dataset_path: Any) -> dict[str, Any]:
        """Return bounded, redacted virtual-dataset source evidence."""
        bounded_filename, filename_truncated = cls._bounded_hdf5_reference_text(filename)
        bounded_dataset_path, dataset_path_truncated = cls._bounded_hdf5_reference_text(dataset_path)
        details: dict[str, Any] = {
            "filename": bounded_filename,
            "dataset_path": bounded_dataset_path,
        }
        if filename_truncated:
            details["filename_truncated"] = True
        if dataset_path_truncated:
            details["dataset_path_truncated"] = True
        return details

    @staticmethod
    def _hdf5_object_identity(obj: Any) -> Any:
        """Return a stable identity for cycle-safe HDF5 hard-link traversal."""
        try:
            return ("h5o_addr", int(h5py.h5o.get_info(obj.id).addr))
        except Exception:
            try:
                object_id = obj.id
                hash(object_id)
                return ("h5_object_id", object_id)
            except Exception:
                return ("python_id", id(obj))

    def _extract_string_literals(
        self,
        value: Any,
        *,
        include_dict_values: bool = False,
        include_dict_keys: bool = False,
        result: ScanResult,
        state: _ConfigTraversalState,
        context: str,
        root_reserved: bool = False,
    ) -> list[str]:
        """Extract string literals from simple container values."""
        literals: list[str] = []
        pending: deque[tuple[Any, int, str, bool]] = deque([(value, 0, context, not root_reserved)])
        if not root_reserved:
            state.items_pending = 1
        while pending and not state.halted:
            node, depth, node_context, pending_reservation = pending.popleft()
            if pending_reservation:
                state.items_pending -= 1
                if not self._reserve_config_traversal_item(state, result, context=node_context, depth=depth):
                    continue

            if isinstance(node, str):
                bounded_value = self._record_config_string_literal(node, state, result, context=node_context)
                if bounded_value is not None:
                    literals.append(bounded_value)
                continue

            if isinstance(node, list | tuple | set):
                if state.item_limit_reached:
                    continue
                for index, item in enumerate(node):
                    child_context = self._config_child_path(node_context, f"[{index}]")
                    if not self._queue_config_traversal_item(
                        pending,
                        (item, depth + 1, child_context, True),
                        state,
                        result,
                        context=child_context,
                        depth=depth + 1,
                    ):
                        break
                continue

            if isinstance(node, dict):
                if state.item_limit_reached:
                    continue
                if include_dict_keys:
                    for key in node:
                        child_context = self._config_child_path(
                            node_context,
                            f".<key:{redact_evidence_string(str(key), max_chars=64)}>",
                        )
                        if not self._queue_config_traversal_item(
                            pending,
                            (key, depth + 1, child_context, True),
                            state,
                            result,
                            context=child_context,
                            depth=depth + 1,
                        ):
                            break
                if include_dict_values and not state.item_limit_reached:
                    for key, item in node.items():
                        child_context = self._config_child_path(
                            node_context,
                            f".{redact_evidence_string(str(key), max_chars=64)}",
                        )
                        if not self._queue_config_traversal_item(
                            pending,
                            (item, depth + 1, child_context, True),
                            state,
                            result,
                            context=child_context,
                            depth=depth + 1,
                        ):
                            break
        return literals

    @staticmethod
    def _references_dangerous_module_literal(module_literal: str, dangerous_modules: set[str]) -> bool:
        """Match dangerous import roots without flagging benign nested path segments."""
        module_segments = [
            segment.lower() for segment in re.split(r"[^A-Za-z0-9_]+", module_literal.strip()) if segment
        ]
        return bool(module_segments) and module_segments[0] in dangerous_modules

    @staticmethod
    def _is_primarily_documentation(context: str, node: dict[str, Any]) -> bool:
        """Heuristically detect documentation-only nodes to reduce false positives."""
        context_lower = context.lower()
        doc_markers = (".description", ".doc", ".docs", ".comment", ".comments", ".notes", ".help", ".readme")
        lowered_keys = {str(key).lower() for key in node}
        doc_keys = {
            "description",
            "doc",
            "docs",
            "comment",
            "comments",
            "notes",
            "help",
            "readme",
            "citation",
            "url",
            "homepage",
            "link",
            "reference",
        }
        if any(marker in context_lower for marker in doc_markers):
            return not KerasZipScanner._has_serialized_callable_context(node, lowered_keys)

        return (
            bool(lowered_keys)
            and lowered_keys.issubset(doc_keys)
            and not KerasZipScanner._has_serialized_callable_context(node, lowered_keys)
        )

    @staticmethod
    def _has_serialized_callable_context(node: dict[str, Any], lowered_keys: set[str]) -> bool:
        """Return True when a doc-like node still resembles Keras callable config."""
        callable_keys = {"fn", "function", "callable"}
        callable_context_keys = {"module", "fn_module", "args", "kwargs", "config", "origin", "url"}
        if lowered_keys & callable_keys:
            return bool(lowered_keys & callable_context_keys)

        class_context_keys = {"module", "fn_module", "args", "kwargs", "config"}
        return bool(lowered_keys & {"class_name", "registered_name"}) and bool(lowered_keys & class_context_keys)

    @staticmethod
    def _is_lambda_layer_class(layer_class: Any) -> bool:
        """Return True for Keras/TensorFlow Lambda serialization names."""
        if not isinstance(layer_class, str):
            return False

        normalized = layer_class.strip()
        if normalized == "Lambda":
            return True

        module_path, _, class_name = normalized.rpartition(".")
        if class_name != "Lambda":
            return False

        framework_prefixes = (
            "keras.",
            "tensorflow.keras.",
            "tensorflow.python.keras.",
            "tf.keras.",
            "tf_keras.",
        )
        return any(f"{module_path.lower()}.".startswith(prefix) for prefix in framework_prefixes)

    @staticmethod
    def _is_primarily_documentation_text(text: str) -> bool:
        """Return True when content is mostly documentation-style text."""
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return False

        dangerous_tokens = (
            "enable_unsafe_deserialization",
            "keras.config",
            "__import__",
            "exec(",
            "eval(",
        )
        structured_markers = ('":', '{"', '"class_name"', '"module"', '"config"')
        doc_like_lines = 0
        for line in lines:
            lowered = line.lower()
            if any(token in lowered for token in dangerous_tokens):
                continue
            if any(marker in lowered for marker in structured_markers):
                continue
            if (
                line.startswith(("#", "//", "/*", "*", "- ", "* "))
                or "documentation" in lowered
                or "example" in lowered
                or "for awareness" in lowered
                or (len(line.split()) >= 7 and "." not in line)
            ):
                doc_like_lines += 1

        return (doc_like_lines / len(lines)) > 0.5

    def _iter_dict_nodes(
        self,
        obj: Any,
        result: ScanResult,
        *,
        state: _ConfigTraversalState,
        path: str = "root",
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        """Yield all dict nodes with their traversal path."""
        pending: deque[tuple[Any, str, int]] = deque([(obj, path, 0)])
        state.items_pending = 1
        while pending and not state.halted:
            node, node_path, depth = pending.popleft()
            state.items_pending -= 1
            if not self._reserve_config_traversal_item(state, result, context=node_path, depth=depth):
                continue

            if isinstance(node, dict):
                yield node_path, node
                if state.item_limit_reached:
                    continue
                for key, value in node.items():
                    child_path = self._config_child_path(
                        node_path,
                        f".{redact_evidence_string(str(key), max_chars=64)}",
                    )
                    if not self._queue_config_traversal_item(
                        pending,
                        (value, child_path, depth + 1),
                        state,
                        result,
                        context=child_path,
                        depth=depth + 1,
                    ):
                        break
                continue

            if isinstance(node, list):
                if state.item_limit_reached:
                    continue
                for index, value in enumerate(node):
                    child_path = self._config_child_path(node_path, f"[{index}]")
                    if not self._queue_config_traversal_item(
                        pending,
                        (value, child_path, depth + 1),
                        state,
                        result,
                        context=child_path,
                        depth=depth + 1,
                    ):
                        break

    def _check_lambda_layer(self, layer: dict[str, Any], result: ScanResult, layer_name: str) -> None:
        """Check Lambda layer for executable Python code"""
        redacted_layer_name = redact_evidence_string(str(layer_name))
        layer_config = layer.get("config", {})
        if not isinstance(layer_config, dict):
            return

        # Lambda layers in Keras ZIP format store the function as a list
        # where the first element is base64-encoded Python code
        function_data = layer_config.get("function")
        location = f"{self.current_file_path} (layer: {redacted_layer_name})"

        if isinstance(function_data, list):
            check_lambda_list_function(function_data, result, location, redacted_layer_name)
        elif isinstance(function_data, dict):
            # Keras 3.x dict-format Lambda: {"class_name": "__lambda__", "config": {"code": ...}}
            check_lambda_dict_function(function_data, result, location, redacted_layer_name)

        sibling_module_name = layer_config.get("module")
        sibling_function_name = layer_config.get("function_name")
        reference_candidates: list[tuple[Any, Any]] = [(sibling_module_name, sibling_function_name)]
        malformed_nested_reference_types: tuple[str, str] | None = None
        if isinstance(function_data, dict) and function_data.get("class_name") != "__lambda__":
            nested_module_name = function_data.get("module")
            nested_function_values = (function_data.get("config"), function_data.get("registered_name"))
            nested_function_names = [value for value in nested_function_values if value is not None] or [None]
            malformed_nested_function = next(
                (value for value in nested_function_values if value is not None and not isinstance(value, str)),
                None,
            )
            if (nested_module_name is not None and not isinstance(nested_module_name, str)) or (
                malformed_nested_function is not None
            ):
                malformed_nested_reference_types = (
                    type(nested_module_name).__name__,
                    type(malformed_nested_function).__name__,
                )
            reference_candidates.extend(
                (nested_module_name, nested_function_name) for nested_function_name in nested_function_names
            )

        dangerous_reference = None
        dangerous_module_name = None
        dangerous_function_name = None
        unattributed_dangerous_function = None
        for module_name, function_name in reference_candidates:
            module_literals = (
                [module_name]
                if isinstance(module_name, str)
                else self._extract_string_literals(
                    module_name,
                    include_dict_values=True,
                    include_dict_keys=True,
                    result=result,
                    state=self._new_config_traversal_state(),
                    context=f"{location}.module",
                )
            )
            dangerous_module = next(
                (
                    module_literal
                    for module_literal in module_literals
                    if self._references_dangerous_module_literal(
                        module_literal,
                        set(_DANGEROUS_LAMBDA_MODULE_TOKENS),
                    )
                ),
                None,
            )
            dangerous_function = (
                function_name if self._is_dangerous_lambda_function_reference(module_name, function_name) else None
            )
            if (
                dangerous_module is None
                and dangerous_function is None
                and module_name is None
                and isinstance(function_name, str)
                and function_name.strip().lower() in _DANGEROUS_LAMBDA_FUNCTION_NAMES
            ):
                unattributed_dangerous_function = function_name
            if dangerous_module is not None or dangerous_function is not None:
                dangerous_reference = dangerous_module or dangerous_function
                dangerous_module_name = module_name
                dangerous_function_name = function_name
                break

        if dangerous_reference is not None:
            result.add_check(
                name="Lambda Layer Module Reference Check",
                passed=False,
                message=(
                    f"Lambda layer '{redacted_layer_name}' references a potentially dangerous module or function: "
                    f"{redact_evidence_string(dangerous_reference)}"
                ),
                severity=IssueSeverity.CRITICAL,
                location=location,
                details={
                    "layer_name": redacted_layer_name,
                    "module": redact_evidence_value(dangerous_module_name),
                    "function": redact_evidence_value(dangerous_function_name),
                },
                why=get_pattern_explanation("lambda_layer"),
            )
        elif unattributed_dangerous_function is not None:
            result.add_check(
                name="Lambda Layer Module Reference Check",
                passed=False,
                message=(
                    f"Lambda layer '{redacted_layer_name}' references a security-sensitive function name "
                    "without module provenance"
                ),
                severity=IssueSeverity.WARNING,
                location=location,
                details={
                    "layer_name": redacted_layer_name,
                    "module": None,
                    "function": redact_evidence_string(unattributed_dangerous_function),
                    "parse_status": "module_unavailable",
                },
                why="Module metadata is required to distinguish standard-library gadgets from custom functions.",
            )
        elif malformed_nested_reference_types is not None:
            module_type, function_type = malformed_nested_reference_types
            result.add_check(
                name="Lambda Layer Module Reference Check",
                passed=False,
                message=f"Lambda layer '{redacted_layer_name}' uses malformed nested callable metadata",
                severity=IssueSeverity.WARNING,
                location=location,
                details={
                    "layer_name": redacted_layer_name,
                    "module_type": module_type,
                    "function_type": function_type,
                    "function_format": "nested_named_function",
                    "function_payload_omitted": "malformed_callable_metadata_may_contain_sensitive_payload",
                },
                why="Malformed nested callable metadata cannot be safely classified.",
            )
        elif any(
            value is not None and not isinstance(value, str) for value in (sibling_module_name, sibling_function_name)
        ) and not (
            isinstance(sibling_module_name, list)
            and all(isinstance(module_literal, str) for module_literal in sibling_module_name)
            and isinstance(sibling_function_name, str)
        ):
            result.add_check(
                name="Lambda Layer Module Reference Check",
                passed=False,
                message=f"Lambda layer '{redacted_layer_name}' uses malformed module/function reference metadata",
                severity=IssueSeverity.WARNING,
                location=location,
                details={
                    "layer_name": redacted_layer_name,
                    "module_type": type(sibling_module_name).__name__,
                    "function_type": type(sibling_function_name).__name__,
                },
                why="Malformed Lambda module references cannot be safely classified.",
            )

    @staticmethod
    def _is_lambda_module_reference_dangerous(module_name: Any, function_name: Any) -> bool:
        """Return True when Lambda sibling metadata names a risky symbol."""
        if KerasZipScanner._is_dangerous_lambda_function_reference(module_name, function_name):
            return True
        if not isinstance(module_name, str):
            return False

        return KerasZipScanner._references_dangerous_module_literal(
            module_name,
            set(_DANGEROUS_LAMBDA_MODULE_TOKENS),
        )

    @staticmethod
    def _is_dangerous_lambda_function_reference(module_name: Any, function_name: Any) -> bool:
        """Return whether a function name is dangerous for the referenced module root."""
        if not isinstance(module_name, str) or not isinstance(function_name, str):
            return False
        module_segments = [segment.lower() for segment in re.split(r"[^A-Za-z0-9_]+", module_name.strip()) if segment]
        if not module_segments:
            return False
        allowed_roots = _DANGEROUS_LAMBDA_FUNCTION_MODULE_ROOTS.get(function_name.strip().lower(), frozenset())
        return module_segments[0] in allowed_roots

    @staticmethod
    def _is_vulnerable_to_cve_2024_3660(version: str) -> bool | None:
        """Return True/False for parseable Keras versions, else None.

        Handles two-part versions (e.g. "2.10") by treating missing patch as 0.
        """
        version_match = _KERAS_RELEASE_VERSION_PATTERN.match(version)
        if not version_match:
            return None

        try:
            major = int(version_match.group(1))
            minor = int(version_match.group(2))
            patch = int(version_match.group(3) or 0)
        except ValueError:
            return None

        suffix = (version_match.group(4) or "").strip().lower()
        parsed = (major, minor, patch)
        if parsed < (2, 13, 0):
            return True

        suffix_status = KerasZipScanner._classify_keras_release_suffix(suffix)
        if suffix_status is None:
            return None
        if parsed > (2, 13, 0):
            return False
        return suffix_status

    @staticmethod
    def _classify_keras_release_suffix(suffix: str) -> bool | None:
        """Return True for prerelease, False for stable/post/local, or None for unknown."""
        if not suffix:
            return False
        if _KERAS_LOCAL_VERSION_SUFFIX_PATTERN.fullmatch(suffix):
            return False
        if _KERAS_POSTRELEASE_SUFFIX_PATTERN.fullmatch(suffix):
            return False

        if _KERAS_PRERELEASE_SUFFIX_PATTERN.fullmatch(suffix):
            return True
        return None

    @staticmethod
    def _is_vulnerable_to_cve_2025_12058(version: str) -> bool | None:
        """Classify Keras versions lower than 3.12.0, including fixed-boundary prereleases."""
        version_match = _KERAS_RELEASE_VERSION_PATTERN.match(version)
        if not version_match:
            return None

        try:
            major = int(version_match.group(1))
            minor = int(version_match.group(2))
            patch = int(version_match.group(3) or 0)
            suffix = (version_match.group(4) or "").strip().lower()
        except ValueError:
            return None

        parsed = (major, minor, patch)
        if parsed < (3, 12, 0):
            return True

        suffix_status = KerasZipScanner._classify_keras_release_suffix(suffix)
        if suffix_status is None:
            return None
        if parsed > (3, 12, 0):
            return False
        return suffix_status

    @staticmethod
    def _is_vulnerable_to_cve_2026_1669(version: str) -> bool | None:
        """Return vulnerability status for Keras versions in the known CVE-2026-1669 ranges."""
        version_match = _KERAS_RELEASE_VERSION_PATTERN.match(version)
        if not version_match:
            return None

        try:
            major = int(version_match.group(1))
            minor = int(version_match.group(2))
            patch = int(version_match.group(3) or 0)
        except ValueError:
            return None

        suffix = (version_match.group(4) or "").strip().lower()
        if version_match.group(3) is None and suffix in {"x", ".x", "-x", "_x", "*", ".*", "-*", "_*"}:
            if (3, 0) <= (major, minor) < (3, 12):
                return True
            if (major, minor) in {(3, 12), (3, 13)}:
                return None
            return False

        parsed = (major, minor, patch)
        if (3, 0, 0) <= parsed < (3, 12, 1) or (3, 13, 0) <= parsed < (3, 13, 2):
            return True

        suffix_status = KerasZipScanner._classify_keras_release_suffix(suffix)
        if suffix_status is None:
            return None
        if parsed in {(3, 12, 1), (3, 13, 2)}:
            return suffix_status
        return False
