"""Scanner for model manifest and configuration files."""

import configparser
import importlib
import json
import os
import re
import stat
from dataclasses import dataclass
from itertools import chain
from pathlib import Path
from types import ModuleType
from typing import Any, Final, TextIO

from modelaudit.config.name_blacklist import check_model_name_policies
from modelaudit.core_results import mark_operational_scan_error, scan_result_has_operational_error
from modelaudit.scanner_results import mark_inconclusive_scan_result

from ..detectors.network_comm import METADATA_NETWORK_CALL_PATTERN, iter_credential_urls
from ..scanner_selection import add_scanner_selection_skip_check, policy_from_config
from ..utils._path_hardening import _file_stat_matches
from ..utils.file.safetensors_index import INDEX_PROBE_BYTES, is_plain_safetensors_index
from . import base as scanner_base
from ._archive_config import get_archive_depth
from ._evidence_redaction import redact_evidence_string
from ._fairseq_config import check_fairseq_expressions
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult, logger

try:
    _tomllib: ModuleType | None = importlib.import_module("tomllib")
except ImportError:  # pragma: no cover - Python 3.10 compatibility
    try:
        _tomllib = importlib.import_module("tomli")
    except ImportError:
        _tomllib = None

HAS_NAME_POLICIES = True


# Try to import yaml, but handle the case where it's not installed
try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# Common manifest and config file formats
MANIFEST_EXTENSIONS = [
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".toml",
    ".ini",
    ".cfg",
    ".config",
    ".manifest",
    ".model",
    ".metadata",
]
MANIFEST_EXACT_FILENAMES = frozenset(
    {
        "manifest.json",
        "model.json",
        "params.json",
        "hyperparams.yaml",
        "training_args.json",
        "dataset_info.json",
        "environment.yml",
        "conda.yaml",
        "metadata.json",
        "index.json",
    }
)
MANIFEST_EXACT_EXTENSIONS = frozenset({".manifest"})

# Keys that might contain model names
MODEL_NAME_KEYS_LOWER = [
    "name",
    "model_name",
    "model",
    "model_id",
    "id",
    "title",
    "artifact_name",
    "artifact_id",
    "package_name",
]

HASH_INTEGRITY_KEYS = [
    "hash",
    "checksum",
    "digest",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "file_hash",
    "model_hash",
    "weight_hash",
    "integrity",
]

# Regex pattern for hexadecimal strings (used to detect hash values)
HEX_PATTERN = re.compile(r"^[a-fA-F0-9]+$")
JINJA_TEMPLATE_FIELD_NAMES = frozenset({"chat_template", "template", "jinja_template", "custom_chat_template"})
JINJA_TEMPLATE_INDICATORS = ("{{", "{%", "{#")
JINJA_TEMPLATE_COLLECTION_BUDGET_REASON: Final[str] = "manifest_jinja_template_collection_budget_exceeded"
MANIFEST_SCAN_TIMEOUT_REASON: Final[str] = "manifest_scan_timeout"
JINJA_TEMPLATE_COLLECTION_MAX_DEPTH_CONFIG_KEY: Final[str] = "jinja_template_collection_max_depth"
JINJA_TEMPLATE_COLLECTION_MAX_ITEMS_CONFIG_KEY: Final[str] = "jinja_template_collection_max_items"
DEFAULT_JINJA_TEMPLATE_COLLECTION_MAX_DEPTH: Final[int] = 64
DEFAULT_JINJA_TEMPLATE_COLLECTION_MAX_ITEMS: Final[int] = 50_000
JINJA_TEMPLATE_LOCATION_MAX_CHARS: Final[int] = 240
_JINJA_COLLECTION_MODE_FIELDS: Final[str] = "fields"
_JINJA_COLLECTION_MODE_CONTAINER: Final[str] = "container"


@dataclass
class _JinjaTemplateCollection:
    templates: dict[str, str]
    budget_exceeded: bool = False
    limit_type: str = ""
    path: str = ""
    items_visited: int = 0
    max_depth: int = DEFAULT_JINJA_TEMPLATE_COLLECTION_MAX_DEPTH
    max_items: int = DEFAULT_JINJA_TEMPLATE_COLLECTION_MAX_ITEMS


@dataclass
class _JinjaTraversalFrame:
    mode: str
    value: Any
    path: str
    depth: int
    allow_plain_field_scalar: bool = False
    iterator: Any | None = None
    visited: bool = False


# Configuration fields that designate an endpoint or an external model artifact.
_REMOTE_CONFIG_FIELD = re.compile(
    r"(?:callback|webhook|endpoint|(?:download|model|weights|checkpoint|adapter|mirror|inference|callback|webhook|"
    r"endpoint|upload)[_-]?(?:url|uri)s?)",
    re.IGNORECASE,
)
_REMOTE_CONFIG_VALUE = re.compile(r"(?:https?|s3a?|gs|az|abfss?|wasbs?|ftp)://[^\s<>\"']+", re.IGNORECASE)

_PARSE_FAILED: Final = object()
_HF_DOWNLOAD_RECORD: Final = object()
_INI_SECTION_HEADER_RE = re.compile(r"^\s*\[[A-Za-z0-9_. -]+\]\s*(?:[#;].*)?(?:\r?\n|$)")


def _matches_hf_download_metadata(path: Path, text: str, handle: TextIO) -> bool:
    """Recognize the download record format on the same regular file used for manifest checks."""
    # A protocol-0 GLOBAL can import a module even when the remaining stream is malformed.
    if handle.newlines not in ("\n", "\r\n") or not re.fullmatch(
        r"[0-9abdef][0-9a-f]{39}\n(?:[0-9a-f]{40}|[0-9a-f]{64})\n(?:0|[1-9][0-9]{0,15})\.[0-9]{1,16}\n",
        text,
    ):
        return False
    timestamp = text.splitlines()[-1]
    if (
        path.suffix != ".metadata"
        or path.stem in {".", ".."}
        or ".." in path.parts
        or str(float(timestamp)) != timestamp
    ):
        return False
    try:
        path = path.absolute()
        layout = (".cache", "huggingface", "download")
        roots = [parent for parent in path.parents if tuple(p.lower() for p in parent.parts[-3:]) == layout]
        if len(roots) != 1 or roots[0].parts[-3:] != layout or path.resolve(strict=True) != path:
            return False
        observed = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_nlink != 1
            or getattr(observed, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            or not _file_stat_matches(observed, path.lstat(), cross_view=True)
        ):
            return False
    except (OSError, ValueError, RuntimeError):
        return False
    return True


class ManifestScanner(BaseScanner):
    """
    Scanner for model manifest and configuration files.

    Checks for:
    - Blacklisted model names (user-configured)
    - Blacklisted terms in file content (user-configured)

    Extracts metadata for reporting:
    - Model architecture information (HuggingFace configs)
    - License information
    """

    name = "manifest"
    description = "Scans model manifest files for blacklisted names and terms"
    supported_extensions = MANIFEST_EXTENSIONS

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        # Get blacklist patterns from config
        self.blacklist_patterns = self.config.get("blacklist_patterns", [])

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        filename = os.path.basename(path).lower()

        # Whitelist: Only scan files that are unique to AI/ML models
        aiml_specific_patterns = [
            # HuggingFace/Transformers specific configuration files
            "config.json",
            "generation_config.json",
            "preprocessor_config.json",
            "feature_extractor_config.json",
            "image_processor_config.json",
            "scheduler_config.json",
            # Model metadata and manifest files specific to ML
            "model_index.json",
            "model_card.json",
            "pytorch_model.bin.index.json",
            "model.safetensors.index.json",
            "tf_model.h5.index.json",
            # ML-specific execution and deployment configs
            "inference_config.json",
            "deployment_config.json",
            "serving_config.json",
            # ONNX model specific
            "onnx_config.json",
            # Custom model configs
            "custom_config.json",
            "runtime_config.json",
        ]

        # Check if filename matches any AI/ML specific pattern (exact match or suffix match)
        # Exclude tokenizer configs - they don't contain security-relevant model info
        if "tokenizer" in filename:
            return False

        # Exclude common web/JS framework configs that are unrelated to ML
        web_configs = ["package.json", "tsconfig.json", "jsconfig.json", "webpack.config.json"]
        if filename in web_configs:
            return False

        if filename in MANIFEST_EXACT_FILENAMES:
            return True

        if os.path.splitext(filename)[1] in MANIFEST_EXACT_EXTENSIONS:
            return True

        if any(filename == pattern or filename.endswith(pattern) for pattern in aiml_specific_patterns):
            return True

        # Additional check: files with "config" in name that are in ML model context
        # Note: tokenizer files are already excluded above
        if "config" in filename and filename not in [
            "config.py",
            "config.yaml",
            "config.yml",
            "config.ini",
            "config.cfg",
        ]:
            # Only if it's likely an ML model config
            path_lower = path.lower()
            if any(
                ml_term in path_lower for ml_term in ["model", "checkpoint", "huggingface", "transformers"]
            ) or os.path.splitext(path)[1].lower() in [".json"]:
                return True

        return False

    def scan(self, path: str) -> ScanResult:
        """Scan a manifest or configuration file for blacklisted content"""
        preflight_result = self._run_preflight_checks(path, on_unreadable=self._finish_read_failure)
        if preflight_result:
            return preflight_result

        self._start_scan_timer()
        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        self._manifest_text_cache: dict[str, str] = {}
        self._hf_download_records: set[str] = set()

        try:
            # Store the file path for use in issue locations
            self.current_file_path = path

            self._check_timeout()

            # Check the raw file content for blacklisted terms
            self._check_file_for_blacklist(path, result)
            if scan_result_has_operational_error(result):
                self._finish_manifest_result(result)
                return result
            self._check_timeout()

            # Parse the file based on its extension
            ext = os.path.splitext(path)[1].lower()
            content = self._parse_file(path, ext, result)
            self._check_timeout()

            if content is _HF_DOWNLOAD_RECORD:
                result.bytes_scanned = file_size
                result.add_check(
                    name="Hugging Face Download Metadata Coverage",
                    passed=False,
                    message=(
                        "The scanned content matches the Hugging Face download metadata format. "
                        "The record alone cannot verify the associated artifact."
                    ),
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={
                        "reason": "hf_download_artifact_unverified",
                        "analysis_incomplete": True,
                    },
                    rule_code="S902",
                )
                self._mark_inconclusive_scan_result(result, "hf_download_artifact_unverified")
            elif content is _PARSE_FAILED:
                result.add_check(
                    name="Manifest Parse Coverage",
                    passed=False,
                    message=f"Unable to complete manifest analysis because the file could not be parsed: {path}",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={
                        "reason": "manifest_parse_failed",
                        "file_path": path,
                    },
                    why=(
                        "Model manifest parsing did not complete, so structured security checks for model names, "
                        "URLs, and integrity hashes could not be applied."
                    ),
                    rule_code="S902",
                )
                self._mark_inconclusive_scan_result(result, "manifest_parse_failed")
            elif isinstance(content, (dict, list)):
                result.bytes_scanned = file_size
                if isinstance(content, dict):
                    result.metadata["root_type"] = "dict"
                    result.metadata["keys"] = list(content.keys())

                    # Extract model metadata for HuggingFace config files
                    if os.path.basename(path) == "config.json":
                        model_info = self._extract_model_metadata(content)
                        if model_info:
                            result.metadata["model_info"] = model_info

                    # Extract license information if present
                    license_info = self._extract_license_info(content)
                    if license_info:
                        result.metadata["license"] = license_info

                else:
                    result.metadata["root_type"] = "list"
                    result.metadata["entry_count"] = len(content)

                # Check for blacklisted model names in config values
                self._check_model_name_policies(content, result)
                self._check_timeout()

                check_fairseq_expressions(content, result, self.current_file_path, self._check_timeout)
                self._check_timeout()

                self._check_remote_configuration(content, result)
                self._check_timeout()

                # Check for weak hash algorithms used for integrity verification
                self._check_weak_hashes(content, result)
                self._check_timeout()

                # Manifest-owned configs can still carry executable chat
                # templates, so preserve manifest checks while delegating those
                # embedded fields to the dedicated Jinja analyzer.
                self._scan_embedded_jinja_templates(path, content, result)
                self._check_timeout()

            else:
                result.add_check(
                    name="Manifest Structure",
                    passed=False,
                    message=f"Unsupported manifest root type: {type(content).__name__}",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={
                        "reason": "manifest_unsupported_root_type",
                        "root_type": type(content).__name__,
                    },
                    why=(
                        "The file parsed successfully, but the parsed value is not an object or list, so structured "
                        "manifest security checks could not be applied."
                    ),
                    rule_code="S902",
                )
                self._mark_inconclusive_scan_result(result, "manifest_unsupported_root_type")

        except TimeoutError as e:
            self._mark_inconclusive_scan_result(result, MANIFEST_SCAN_TIMEOUT_REASON)
            mark_operational_scan_error(result, MANIFEST_SCAN_TIMEOUT_REASON)
            result.add_check(
                name="Manifest Scan Timeout",
                passed=False,
                message=f"Scan timed out: {e!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "timeout_seconds": self.timeout,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": MANIFEST_SCAN_TIMEOUT_REASON,
                },
                why="Manifest scanning exceeded the configured timeout before all checks completed",
            )
            self._finish_manifest_result(result)
            return result
        except Exception as e:
            result.add_check(
                name="Manifest File Scan",
                passed=False,
                message=f"Error scanning manifest file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result
        finally:
            self._manifest_text_cache.clear()
            self._hf_download_records.clear()

        self._finish_manifest_result(result)
        return result

    def _mark_inconclusive_scan_result(self, result: ScanResult, reason: str) -> None:
        """Mark a manifest scan as inconclusive when structured analysis is incomplete."""
        mark_inconclusive_scan_result(result, reason)

    def _finish_manifest_result(self, result: ScanResult) -> None:
        """Fail closed for inconclusive manifests unless real security findings were recovered."""
        if scan_result_has_operational_error(result):
            result.finish(success=False)
            return

        # Return True when the manifest result includes WARNING/CRITICAL findings.
        if result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME and not any(
            issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues
        ):
            result.finish(success=False)
            return

        result.finish(success=True)

    @staticmethod
    def _record_read_failure(
        result: ScanResult,
        path: str,
        error: OSError | UnicodeError,
        *,
        reason: str,
        check_name: str,
        message: str,
    ) -> None:
        mark_inconclusive_scan_result(result, reason)
        mark_operational_scan_error(result, reason)
        result.add_check(
            name=check_name,
            passed=False,
            message=f"{message}: {error!s}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": str(error),
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
        )

    @classmethod
    def _finish_read_failure(
        cls,
        result: ScanResult,
        path: str,
        error: OSError | UnicodeError,
        *,
        reason: str = "manifest_read_failed",
    ) -> ScanResult:
        cls._record_read_failure(
            result,
            path,
            error,
            reason=reason,
            check_name="Manifest File Read",
            message="Unable to read manifest file",
        )
        result.finish(success=False)
        return result

    def _check_file_for_blacklist(self, path: str, result: ScanResult) -> None:
        """Check the entire file content for blacklisted terms"""
        if not self.blacklist_patterns:
            return

        try:
            content = self._read_manifest_text(path).lower()

            found_blacklisted = False
            for pattern in self.blacklist_patterns:
                self._check_timeout()
                pattern_lower = pattern.lower()
                if pattern_lower in content:
                    result.add_check(
                        name="Blacklist Pattern Check",
                        passed=False,
                        message=f"Blacklisted term '{pattern}' found in file",
                        severity=IssueSeverity.CRITICAL,
                        location=self.current_file_path,
                        details={"blacklisted_term": pattern, "file_path": path},
                        why=(
                            "This term matches a user-defined blacklist pattern. Organizations use blacklists to "
                            "identify models or configurations that violate security policies or contain known "
                            "malicious indicators."
                        ),
                        rule_code="S1001",
                    )
                    found_blacklisted = True

            if not found_blacklisted:
                result.add_check(
                    name="Blacklist Pattern Check",
                    passed=True,
                    message="No blacklisted patterns found in file",
                    location=self.current_file_path,
                    details={"patterns_checked": len(self.blacklist_patterns)},
                )
        except TimeoutError:
            raise
        except (OSError, UnicodeError) as e:
            self._record_read_failure(
                result,
                path,
                e,
                reason="manifest_blacklist_read_failed",
                check_name="Blacklist Pattern Check",
                message="Unable to load manifest text for configured policy analysis",
            )
        except Exception as e:
            result.add_check(
                name="Blacklist Pattern Check",
                passed=False,
                message=f"Error checking file for blacklist: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
                rule_code="S1001",
            )

    def _parse_file(
        self,
        path: str,
        ext: str,
        result: ScanResult | None = None,
    ) -> Any:
        """Parse the file based on its extension"""
        try:
            content = self._read_manifest_text(path)
            if path in getattr(self, "_hf_download_records", ()):
                return _HF_DOWNLOAD_RECORD

            stripped_content = content.strip()

            if ext == ".toml":
                if _tomllib is None:
                    raise ValueError("TOML parsing requires Python 3.11+ or the tomli package")
                return _tomllib.loads(content)

            if ext in [".ini", ".cfg"] or (ext == ".config" and self._looks_like_ini_file(stripped_content)):
                return self._parse_ini_file(content)

            # Try JSON format first
            if ext in [
                ".json",
                ".manifest",
                ".model",
                ".metadata",
            ] or stripped_content.startswith(("{", "[")):
                return json.loads(content)

            # Try YAML format if available
            if HAS_YAML and (ext in [".yaml", ".yml"] or stripped_content.startswith("---")):
                return yaml.safe_load(content)

            # For other formats, try JSON and then YAML if available
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                if HAS_YAML:
                    try:
                        return yaml.safe_load(content)
                    except TimeoutError:
                        raise
                    except Exception:
                        pass

        except TimeoutError:
            raise
        except (OSError, UnicodeError) as e:
            logger.warning(f"Error reading file {path}: {e!s}")
            if result is not None:
                self._record_read_failure(
                    result,
                    path,
                    e,
                    reason="manifest_read_failed",
                    check_name="Manifest File Read",
                    message="Unable to read manifest file for structured analysis",
                )
        except Exception as e:
            logger.warning(f"Error parsing file {path}: {e!s}")
            if result is not None:
                result.add_check(
                    name="File Parse Error",
                    passed=False,
                    message=f"Error parsing file: {path}",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                    details={"exception": str(e), "exception_type": type(e).__name__},
                    rule_code="S902",
                )

        return _PARSE_FAILED

    def _scan_embedded_jinja_templates(self, path: str, content: Any, result: ScanResult) -> None:
        scanner_selection = policy_from_config(self.config)
        if not scanner_selection.allows("jinja2_template"):
            if scanner_selection.active:
                add_scanner_selection_skip_check(
                    result,
                    path,
                    "jinja2_template",
                    scanner_selection,
                    context="embedded Jinja template analysis",
                )
            return

        collection = self._collect_jinja_template_fields_with_budget(content)
        templates = collection.templates
        if collection.budget_exceeded:
            if os.path.basename(path).lower() == "model.safetensors.index.json":
                raw = self._manifest_text_cache.get(path, "")
                if len(raw) <= INDEX_PROBE_BYTES and raw.isascii() and is_plain_safetensors_index(raw.encode("ascii")):
                    return
            self._record_jinja_collection_budget_exceeded(result, path, collection)
            self._check_timeout()

        if not templates:
            return

        from .jinja2_template_scanner import Jinja2TemplateScanner

        safe_templates = self._redact_jinja_template_locations(templates)
        result.merge(Jinja2TemplateScanner(config=self.config).scan_extracted_templates(path, safe_templates))

    def _collect_jinja_template_fields(self, value: Any, path: str = "") -> dict[str, str]:
        return self._collect_jinja_template_fields_with_budget(value, path).templates

    def _collect_jinja_template_fields_with_budget(self, value: Any, path: str = "") -> _JinjaTemplateCollection:
        return self._collect_jinja_templates_with_budget(value, path, _JINJA_COLLECTION_MODE_FIELDS)

    def _collect_jinja_templates_with_budget(
        self,
        value: Any,
        path: str,
        mode: str,
    ) -> _JinjaTemplateCollection:
        max_depth = self._get_positive_int_config(
            JINJA_TEMPLATE_COLLECTION_MAX_DEPTH_CONFIG_KEY,
            DEFAULT_JINJA_TEMPLATE_COLLECTION_MAX_DEPTH,
        )
        max_items = self._get_positive_int_config(
            JINJA_TEMPLATE_COLLECTION_MAX_ITEMS_CONFIG_KEY,
            DEFAULT_JINJA_TEMPLATE_COLLECTION_MAX_ITEMS,
        )
        collection = _JinjaTemplateCollection(
            templates={},
            max_depth=max_depth,
            max_items=max_items,
        )
        stack = [
            _JinjaTraversalFrame(
                mode=mode,
                value=value,
                path=path,
                depth=0,
                allow_plain_field_scalar=mode == _JINJA_COLLECTION_MODE_CONTAINER,
            )
        ]
        expanded_container_depths: dict[tuple[str, bool, int], int] = {}

        while stack:
            self._check_timeout()
            frame = stack[-1]

            if not frame.visited:
                frame.visited = True
                collection.items_visited += 1
                if collection.items_visited > max_items:
                    self._mark_jinja_collection_budget_exceeded(collection, "items", frame.path)
                    break

                if isinstance(frame.value, (dict, list)):
                    container_key = (
                        frame.mode,
                        "chat_template" in frame.path.lower(),
                        id(frame.value),
                    )
                    expanded_depth = expanded_container_depths.get(container_key)
                    if expanded_depth is not None and expanded_depth <= frame.depth:
                        stack.pop()
                        continue

                if frame.depth > max_depth:
                    self._mark_jinja_collection_budget_exceeded(collection, "depth", frame.path)
                    stack.pop()
                    continue

                if isinstance(frame.value, str):
                    self._record_jinja_scalar_if_template(
                        collection.templates,
                        frame.mode,
                        frame.path,
                        frame.value,
                        allow_plain_field_scalar=frame.allow_plain_field_scalar,
                    )
                    stack.pop()
                    continue

                if isinstance(frame.value, dict):
                    expanded_container_depths[(frame.mode, "chat_template" in frame.path.lower(), id(frame.value))] = (
                        frame.depth
                    )
                    if frame.mode == _JINJA_COLLECTION_MODE_FIELDS:
                        priority_items = (
                            (field_name, frame.value[field_name])
                            for field_name in sorted(JINJA_TEMPLATE_FIELD_NAMES)
                            if field_name in frame.value
                        )
                        remaining_items = (
                            (key, item) for key, item in frame.value.items() if key not in JINJA_TEMPLATE_FIELD_NAMES
                        )
                        frame.iterator = chain(priority_items, remaining_items)
                    else:
                        frame.iterator = iter(frame.value.items())
                    continue

                if isinstance(frame.value, list):
                    expanded_container_depths[(frame.mode, "chat_template" in frame.path.lower(), id(frame.value))] = (
                        frame.depth
                    )
                    frame.iterator = enumerate(frame.value)
                    continue

                stack.pop()
                continue

            if frame.iterator is None:
                stack.pop()
                continue

            try:
                key, item = next(frame.iterator)
            except StopIteration:
                stack.pop()
                continue

            self._check_timeout()
            child_path = self._jinja_collection_child_path(frame.path, key, isinstance(frame.value, list))
            child_mode = frame.mode
            allow_plain_field_scalar = False
            if frame.mode == _JINJA_COLLECTION_MODE_FIELDS:
                is_template_field = isinstance(key, str) and key in JINJA_TEMPLATE_FIELD_NAMES
                child_mode = _JINJA_COLLECTION_MODE_CONTAINER if is_template_field else _JINJA_COLLECTION_MODE_FIELDS
                allow_plain_field_scalar = is_template_field
            stack.append(
                _JinjaTraversalFrame(
                    mode=child_mode,
                    value=item,
                    path=child_path,
                    depth=frame.depth + 1,
                    allow_plain_field_scalar=allow_plain_field_scalar,
                )
            )

        return collection

    _get_positive_int_config = scanner_base._scanner_positive_int_config

    @staticmethod
    def _mark_jinja_collection_budget_exceeded(
        collection: _JinjaTemplateCollection,
        limit_type: str,
        path: str,
    ) -> None:
        if collection.budget_exceeded and limit_type != "items":
            return
        collection.budget_exceeded = True
        collection.limit_type = limit_type
        collection.path = path

    def _record_jinja_scalar_if_template(
        self,
        templates: dict[str, str],
        mode: str,
        path: str,
        value: str,
        *,
        allow_plain_field_scalar: bool,
    ) -> None:
        if mode != _JINJA_COLLECTION_MODE_CONTAINER or not value.strip():
            return
        if allow_plain_field_scalar or self._looks_like_jinja(value):
            self._record_jinja_template(templates, path, value)

    @staticmethod
    def _jinja_collection_child_path(path: str, key: Any, parent_is_list: bool) -> str:
        key_text = str(key)
        if parent_is_list:
            candidate = f"{path}[{key_text}]" if path else f"[{key_text}]"
        else:
            safe_key = redact_evidence_string(key_text, max_chars=JINJA_TEMPLATE_LOCATION_MAX_CHARS)
            candidate = f"{path}.{safe_key}" if path else safe_key

        preserve_chat_template_context = "chat_template" in path.casefold() or "chat_template" in key_text.casefold()
        context_suffix = ".chat_template" if preserve_chat_template_context else ""
        safe_path = redact_evidence_string(
            candidate,
            max_chars=JINJA_TEMPLATE_LOCATION_MAX_CHARS - len(context_suffix),
        )
        if context_suffix and "chat_template" not in safe_path.casefold():
            safe_path = f"{safe_path}{context_suffix}"
        return safe_path

    def _record_jinja_collection_budget_exceeded(
        self,
        result: ScanResult,
        path: str,
        collection: _JinjaTemplateCollection,
    ) -> None:
        self._mark_inconclusive_scan_result(result, JINJA_TEMPLATE_COLLECTION_BUDGET_REASON)
        result.add_check(
            name="Embedded Jinja Collection Budget",
            passed=False,
            message=(
                "Embedded Jinja template analysis incomplete because parsed manifest traversal exceeded "
                "the configured collection budget"
            ),
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "reason": JINJA_TEMPLATE_COLLECTION_BUDGET_REASON,
                "scan_outcome_reason": JINJA_TEMPLATE_COLLECTION_BUDGET_REASON,
                "analysis_incomplete": True,
                "limit_type": collection.limit_type,
                "path": redact_evidence_string(collection.path, max_chars=JINJA_TEMPLATE_LOCATION_MAX_CHARS),
                "items_visited": collection.items_visited,
                "max_depth": collection.max_depth,
                "max_items": collection.max_items,
                "templates_collected": len(collection.templates),
            },
            why=(
                "Manifest configs can contain attacker-controlled nested JSON, YAML, TOML, or INI structures. "
                "The embedded Jinja collector stops at a bounded traversal budget and marks analysis incomplete "
                "rather than recursively walking untrusted structures without limit."
            ),
        )

    @classmethod
    def _redact_jinja_template_locations(cls, templates: dict[str, str]) -> dict[str, str]:
        safe_templates: dict[str, str] = {}
        for path, value in templates.items():
            context_suffix = ".chat_template" if "chat_template" in path.casefold() else ""
            safe_path = redact_evidence_string(
                path,
                max_chars=JINJA_TEMPLATE_LOCATION_MAX_CHARS - len(context_suffix),
            )
            if context_suffix and "chat_template" not in safe_path.casefold():
                safe_path = f"{safe_path}{context_suffix}"
            cls._record_jinja_template(safe_templates, safe_path, value)
        return safe_templates

    @staticmethod
    def _record_jinja_template(templates: dict[str, str], path: str, value: str) -> None:
        if path not in templates:
            templates[path] = value
            return

        duplicate_index = len(templates) + 1
        unique_path = f"{path} [duplicate {duplicate_index}]"
        while unique_path in templates:
            duplicate_index += 1
            unique_path = f"{path} [duplicate {duplicate_index}]"
        templates[unique_path] = value

    @staticmethod
    def _looks_like_jinja(value: str) -> bool:
        return any(indicator in value for indicator in JINJA_TEMPLATE_INDICATORS)

    def _parse_ini_file(self, content: str) -> dict[str, Any]:
        """Parse INI-style manifests into nested dictionaries."""
        parser = configparser.ConfigParser()
        parser.read_string(content)

        parsed: dict[str, Any] = {}
        defaults = dict(parser.defaults())
        if defaults:
            parsed["DEFAULT"] = defaults

        for section in parser.sections():
            parsed[section] = dict(parser.items(section))

        return parsed

    @staticmethod
    def _looks_like_ini_file(stripped_content: str) -> bool:
        """Return True when stripped content starts with an INI section header."""
        return bool(_INI_SECTION_HEADER_RE.match(stripped_content))

    def _extract_model_metadata(self, content: dict[str, Any]) -> dict[str, Any]:
        """Extract model metadata from HuggingFace config files"""
        model_info = {}

        # Extract key model configuration
        metadata_keys = {
            "model_type": "model_type",
            "architectures": "architectures",
            "num_parameters": "num_parameters",
            "hidden_size": "hidden_size",
            "num_hidden_layers": "num_layers",
            "num_attention_heads": "num_heads",
            "vocab_size": "vocab_size",
            "task": "task",
            "transformers_version": "framework_version",
        }

        for source_key, dest_key in metadata_keys.items():
            if source_key in content:
                model_info[dest_key] = content[source_key]

        return model_info

    def _extract_license_info(self, content: dict[str, Any]) -> str | None:
        """Return license string if found in manifest content"""
        potential_keys = ["license", "licence", "licenses"]
        for key in potential_keys:
            if key in content:
                value = content[key]
                if isinstance(value, str):
                    return value
                if isinstance(value, list) and value:
                    first = value[0]
                    if isinstance(first, str):
                        return first

        return None

    def _check_model_name_policies(self, content: Any, result: ScanResult) -> None:
        """Check for blacklisted model names in config values"""
        visited_containers: set[int] = set()

        def check_value(value: Any, prefix: str = "") -> None:
            self._check_timeout()

            if isinstance(value, (dict, list)):
                container_id = id(value)
                if container_id in visited_containers:
                    return
                visited_containers.add(container_id)

            if isinstance(value, dict):
                for key, nested_value in value.items():
                    key_text = str(key)
                    key_lower = key_text.lower()
                    full_key = f"{prefix}.{key_text}" if prefix else key_text

                    # Check if this key might contain a model name
                    if key_lower in MODEL_NAME_KEYS_LOWER:
                        blocked, reason = check_model_name_policies(
                            str(nested_value),
                            self.blacklist_patterns,
                        )
                        if blocked:
                            result.add_check(
                                name="Model Name Policy Check",
                                passed=False,
                                message=f"Model name blocked by policy: {nested_value}",
                                severity=IssueSeverity.CRITICAL,
                                location=self.current_file_path,
                                details={
                                    "model_name": str(nested_value),
                                    "reason": reason,
                                    "key": full_key,
                                },
                                why=(
                                    "This model name matches a blacklist pattern. Organizations use model name "
                                    "blacklists to prevent use of banned, malicious, or policy-violating models."
                                ),
                            )
                        else:
                            result.add_check(
                                name="Model Name Policy Check",
                                passed=True,
                                message=f"Model name '{nested_value}' passed policy check",
                                location=self.current_file_path,
                                details={
                                    "model_name": str(nested_value),
                                    "key": full_key,
                                },
                            )

                    check_value(nested_value, full_key)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    check_value(item, f"{prefix}[{i}]")

        check_value(content)

    def _read_manifest_text(self, path: str) -> str:
        cached_content = getattr(self, "_manifest_text_cache", {}).get(path)
        if cached_content is not None:
            return cached_content

        with open(path, encoding="utf-8") as f:
            content = f.read()
            if (
                path.endswith(".metadata")
                and hasattr(self, "_hf_download_records")
                and self.config.get("_trusted_source_provenance") is None
                and get_archive_depth(self.config) == 0
                and _matches_hf_download_metadata(Path(path), content, f)
            ):
                self._hf_download_records.add(path)

        if hasattr(self, "_manifest_text_cache"):
            self._manifest_text_cache[path] = content
        return content

    def _check_remote_configuration(self, content: Any, result: ScanResult) -> None:
        """Check explicit destination fields and credentials in parsed config values."""
        pending = [(content, "", False)]
        visited: set[tuple[int, bool]] = set()
        while pending:
            self._check_timeout()
            value, key_path, remote_field = pending.pop()
            if isinstance(value, (dict, list)):
                identity = (id(value), remote_field)
                if identity in visited:
                    continue
                visited.add(identity)
            if isinstance(value, dict):
                pending.extend(
                    (
                        item,
                        f"{key_path}.{key}" if key_path else str(key),
                        remote_field or _REMOTE_CONFIG_FIELD.fullmatch(str(key)) is not None,
                    )
                    for key, item in value.items()
                )
            elif isinstance(value, list):
                pending.extend((item, f"{key_path}[{index}]", remote_field) for index, item in enumerate(value))
            elif isinstance(value, str):
                credential_url = next(iter_credential_urls(value), None)
                if credential_url is not None:
                    result.add_check(
                        name="Config URL Credential Check",
                        passed=False,
                        message="Credential material found in a configuration URL",
                        severity=IssueSeverity.WARNING,
                        location=self.current_file_path,
                        details={"url": credential_url, "key_path": key_path},
                    )
                elif remote_field and _REMOTE_CONFIG_VALUE.fullmatch(value.strip()) is not None:
                    result.add_check(
                        name="Remote Configuration Reference",
                        passed=False,
                        message="Configuration specifies a remote destination or model artifact",
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={"url": value.strip(), "key_path": key_path},
                    )
                elif METADATA_NETWORK_CALL_PATTERN.search(value):
                    result.add_check(
                        name="Config Network Invocation",
                        passed=False,
                        message="Network invocation found in a configuration value",
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={"key_path": key_path},
                    )

    def _check_weak_hashes(self, content: Any, result: ScanResult) -> None:
        """Check for weak hash algorithms (MD5, SHA1) used for integrity verification.

        MD5 and SHA1 are cryptographically broken and should not be used for
        integrity verification of model files. This check detects when these
        weak algorithms are used in config files.

        CWE-328: Use of Weak Hash
        """

        def _is_hex_string(value: str) -> bool:
            """Check if a string is a valid hexadecimal value."""
            return bool(HEX_PATTERN.match(value))

        def _detect_hash_algorithm(value: str) -> str | None:
            """Detect hash algorithm based on string length."""
            if not _is_hex_string(value):
                return None

            # Map hash length to algorithm name
            length_to_algorithm = {
                32: "MD5",
                40: "SHA1",
                64: "SHA256",
                128: "SHA512",
            }
            return length_to_algorithm.get(len(value))

        def check_hash_value(key: str, value: Any, path: str) -> None:
            """Check a single key-value pair for weak hash usage."""
            if not isinstance(value, str):
                return

            key_lower = key.lower()

            # Check if this key is likely a hash/checksum field
            is_hash_key = any(h in key_lower for h in HASH_INTEGRITY_KEYS)

            if not is_hash_key:
                return

            algorithm = _detect_hash_algorithm(value)

            if algorithm in ("MD5", "SHA1"):
                # Weak hash detected
                result.add_check(
                    name="Weak Hash Detection",
                    passed=False,
                    message=f"{algorithm} hash detected for integrity verification: {key}",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={
                        "key": path,
                        "algorithm": algorithm,
                        "hash_preview": value[:16] + "..." if len(value) > 16 else value,
                    },
                    why=(
                        f"{algorithm} is cryptographically broken and vulnerable to collision attacks. "
                        "Use SHA256 or stronger for model integrity verification. "
                        "See CWE-328: Use of Weak Hash."
                    ),
                )
            elif algorithm in ("SHA256", "SHA512"):
                # Strong hash - good!
                result.add_check(
                    name="Weak Hash Detection",
                    passed=True,
                    message=f"Strong hash algorithm ({algorithm}) used for: {key}",
                    severity=IssueSeverity.DEBUG,
                    location=self.current_file_path,
                    details={
                        "key": path,
                        "algorithm": algorithm,
                    },
                )

        visited_containers: set[int] = set()

        def traverse_for_hashes(value: Any, prefix: str = "", parent_key: str = "") -> None:
            """Recursively check parsed manifest content for weak hashes."""
            self._check_timeout()
            if isinstance(value, (dict, list)):
                container_id = id(value)
                if container_id in visited_containers:
                    return
                visited_containers.add(container_id)

            if isinstance(value, dict):
                for key, nested_value in value.items():
                    key_text = str(key)
                    full_key = f"{prefix}.{key_text}" if prefix else key_text
                    traverse_for_hashes(nested_value, full_key, key_text)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    item_path = f"{prefix}[{i}]"
                    traverse_for_hashes(item, item_path, parent_key)
            elif isinstance(value, str) and parent_key:
                check_hash_value(parent_key, value, prefix)

        traverse_for_hashes(content)
