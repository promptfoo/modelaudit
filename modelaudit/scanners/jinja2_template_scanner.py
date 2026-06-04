"""
Jinja2 Template Injection Scanner for ML Models

This scanner detects Server-Side Template Injection (SSTI) vulnerabilities in Jinja2 templates
found in ML model files, particularly targeting CVE-2024-34359 and similar attack vectors.

The scanner analyzes:
- GGUF model files with chat_template metadata
- HuggingFace tokenizer_config.json files with chat_template fields
- Standalone Jinja2 template files in ML contexts
- Configuration files containing template strings

Key Features:
- Comprehensive SSTI pattern detection with 6 risk categories
- Context-aware analysis to reduce false positives in ML environments
- Optional sandboxing test for template safety validation
- Support for obfuscated and WAF-bypass techniques
- Detailed risk assessment and explanation
"""

import json
import operator
import os
import re
import warnings
from typing import Any, ClassVar

from modelaudit.detectors.suspicious_symbols import JINJA2_SSTI_PATTERNS

from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult, logger

# Optional GGUF support with graceful fallback
try:
    from gguf.gguf_reader import GGUFReader  # type: ignore[import-untyped]

    HAS_GGUF = True
except ImportError:
    HAS_GGUF = False
    logger.debug("GGUF library not available - GGUF scanning disabled")

# Optional Jinja2 sandboxing support
try:
    import jinja2.exceptions
    import jinja2.sandbox

    HAS_JINJA2_SANDBOX = True
except ImportError:
    HAS_JINJA2_SANDBOX = False
    logger.debug("Jinja2 sandboxing not available - template safety tests disabled")

# Try to import yaml for configuration file parsing
try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False


_INCONCLUSIVE_METADATA_KEY = "scan_outcome"
_INCONCLUSIVE_REASONS_METADATA_KEY = "scan_outcome_reasons"
_JINJA_TEMPLATE_INDICATORS = ("{{", "{%", "{#")
_JINJA_TEMPLATE_INDICATOR_BYTES = tuple(indicator.encode("utf-8") for indicator in _JINJA_TEMPLATE_INDICATORS)
_TEMPLATE_FIELD_KEYS = frozenset({"chat_template", "template", "jinja_template", "custom_chat_template"})
_DETECTION_MESSAGE_LABELS = {
    "critical_injection": "critical injection",
    "object_traversal": "object hierarchy access",
    "global_access": "global namespace access",
    "obfuscation": "obfuscation",
    "control_flow": "control flow",
    "environment_access": "environment access",
    "sandbox_violation": "sandbox violation",
}
_MAX_REPORTED_TEMPLATE_LOCATIONS = 20
_RAW_PARSE_FALLBACK_CONTEXT_BYTES = 1024
_RAW_PARSE_FALLBACK_MAX_WINDOWS = 8
_RAW_PARSE_FALLBACK_READ_BYTES = 256 * 1024


def _compile_all_patterns() -> dict[str, list[tuple[re.Pattern[str], str]]]:
    """Compile the static SSTI regex set once for all scanner instances."""
    compiled: dict[str, list[tuple[re.Pattern[str], str]]] = {}

    for category, patterns in JINJA2_SSTI_PATTERNS.items():
        compiled[category] = []
        for pattern in patterns:
            try:
                compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                compiled[category].append((compiled_pattern, pattern))
            except re.error as e:
                logger.warning(f"Failed to compile regex pattern '{pattern}': {e}")

    return compiled


_COMPILED_JINJA2_SSTI_PATTERNS = _compile_all_patterns()


class MLContext:
    """Context information about the ML model/file being scanned"""

    def __init__(self):
        self.is_tokenizer = False
        self.is_chat_template = False
        self.framework = None  # 'huggingface', 'pytorch', 'tensorflow', etc.
        self.model_type = None  # 'text-generation', 'vision', etc.
        self.file_type = None  # 'gguf', 'json', 'yaml', 'template'
        self.confidence = 0  # Confidence level of ML context detection


class DetectionResult:
    """Result of template pattern detection"""

    def __init__(
        self,
        pattern_type: str,
        pattern: str,
        match_text: str,
        risk_level: str,
        location: str = "",
        explanation: str = "",
    ):
        self.pattern_type = pattern_type
        self.pattern = pattern
        self.match_text = match_text
        self.risk_level = risk_level
        self.location = location
        self.explanation = explanation


def _scan_result_has_security_findings(result: ScanResult) -> bool:
    return any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def _nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    return None


class Jinja2TemplateScanner(BaseScanner):
    """Scanner for Jinja2 template injection vulnerabilities in ML models"""

    name = "jinja2_template"
    description = "Scans for Jinja2 template injection vulnerabilities in ML model templates"
    supported_extensions: ClassVar[list[str]] = [".gguf", ".json", ".yaml", ".yml", ".jinja", ".j2", ".template"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)

        # Configuration options
        self.sensitivity_level = self.config.get("sensitivity_level", "medium")  # low/medium/high
        self.max_template_size = self.config.get("max_template_size", 50000)  # Skip huge templates
        self.enable_sandbox_test = self.config.get("enable_sandbox_test", True) and HAS_JINJA2_SANDBOX
        self.skip_common_patterns = self.config.get("skip_common_patterns", True)  # Ignore common ML patterns

        self._compiled_patterns = _COMPILED_JINJA2_SSTI_PATTERNS

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        filename = os.path.basename(path).lower()
        ext = os.path.splitext(path)[1].lower()

        # GGUF files
        if ext == ".gguf":
            return HAS_GGUF  # Only handle if GGUF library is available

        # Standalone template files
        if ext in [".jinja", ".j2", ".template"]:
            return True

        # JSON files containing templates
        if ext == ".json" and any(
            pattern in filename
            for pattern in [
                "tokenizer_config.json",
                "tokenizer.json",
                "chat_template.json",
                "generation_config.json",
            ]
        ):
            return True

        # YAML files in ML contexts
        if ext in [".yaml", ".yml"]:
            # Check if in ML model directory or contains ML-related patterns
            path_lower = path.lower()
            if any(
                ml_term in path_lower for ml_term in ["model", "checkpoint", "huggingface", "transformers", "config"]
            ):
                return True

        return False

    def scan(self, path: str) -> ScanResult:
        """Scan a file for Jinja2 template injection vulnerabilities"""
        # Standard path and size checks
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            # Determine file type and ML context
            context = self._determine_context(path)
            result.metadata["ml_context"] = {
                "framework": context.framework,
                "file_type": context.file_type,
                "is_tokenizer": context.is_tokenizer,
                "confidence": context.confidence,
            }

            # Extract templates based on file type
            templates, extraction_failures = self._extract_templates(path, context)
            for failure in extraction_failures:
                self._mark_inconclusive_scan_result(result, path, failure)

            if not templates:
                if extraction_failures:
                    size_limited = any(
                        failure["reason"] == "jinja2_template_size_limit_exceeded" for failure in extraction_failures
                    )
                    read_failed = any(
                        failure["reason"] == "jinja2_template_read_failed" for failure in extraction_failures
                    )
                    result.add_check(
                        name="Template Extraction",
                        passed=False,
                        message=(
                            "Template analysis incomplete because one or more extracted templates exceed the size limit"
                            if size_limited
                            else (
                                "Template analysis incomplete because standalone template could not be read"
                                if read_failed
                                else "Template extraction incomplete due to malformed structured config"
                            )
                        ),
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={
                            "file_type": context.file_type,
                            "failure_reasons": [failure["reason"] for failure in extraction_failures],
                        },
                    )
                    result.bytes_scanned = file_size
                    self._finish_scan_result(result)
                    return result

                result.add_check(
                    name="Template Extraction",
                    passed=True,
                    message="No Jinja2 templates found in file",
                    location=path,
                    details={"file_type": context.file_type},
                )
                result.finish(success=True)
                return result

            return self._scan_extracted_templates(path, templates, context, result=result, file_size=file_size)

        except Exception as e:
            import traceback

            logger.error(f"Error in Jinja2TemplateScanner.scan: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")

            result.add_check(
                name="Jinja2 Template Scan",
                passed=False,
                message=f"Error scanning file for template injection: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                    "file_size": file_size,
                    "traceback": traceback.format_exc(),
                },
            )
            result.finish(success=False)
            return result

    def scan_extracted_templates(self, path: str, templates: dict[str, str]) -> ScanResult:
        """Analyze templates that were already extracted by another structured scanner."""
        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        context = self._determine_context(path)
        if any("chat_template" in template_location.lower() for template_location in templates):
            context.is_chat_template = True
        result.metadata["ml_context"] = {
            "framework": context.framework,
            "file_type": context.file_type,
            "is_tokenizer": context.is_tokenizer,
            "confidence": context.confidence,
        }
        bounded_templates: dict[str, str] = {}
        oversized_failures: list[dict[str, Any]] = []
        for template_location, template_content in templates.items():
            if len(template_content) <= self.max_template_size:
                bounded_templates[template_location] = template_content
            else:
                self._add_template_size_failure(
                    oversized_failures,
                    "extracted",
                    template_location,
                    len(template_content),
                )

        if oversized_failures:
            result.metadata[_INCONCLUSIVE_METADATA_KEY] = INCONCLUSIVE_SCAN_OUTCOME
            result.metadata[_INCONCLUSIVE_REASONS_METADATA_KEY] = ["jinja2_template_size_limit_exceeded"]
            result.add_check(
                name="Template Size Limit",
                passed=False,
                message="Template analysis incomplete because one or more extracted templates exceed the size limit",
                severity=IssueSeverity.INFO,
                location=path,
                details=oversized_failures[0],
            )

        if not bounded_templates:
            result.bytes_scanned = file_size
            self._finish_scan_result(result)
            return result

        return self._scan_extracted_templates(path, bounded_templates, context, result=result, file_size=file_size)

    def _scan_extracted_templates(
        self,
        path: str,
        templates: dict[str, str],
        context: MLContext,
        *,
        result: ScanResult,
        file_size: int,
    ) -> ScanResult:
        total_detections = 0
        for template_location, template_content in templates.items():
            detections = self._analyze_template(template_content, context, f"{path}:{template_location}")
            total_detections += len(detections)

            for detection in detections:
                severity = self._get_severity_for_detection(detection, context)
                why_explanation = self._get_why_explanation(detection, context)

                result.add_check(
                    name="Jinja2 Template Injection Detection",
                    passed=False,
                    message=(
                        "Potential SSTI vulnerability detected: "
                        f"{_DETECTION_MESSAGE_LABELS.get(detection.pattern_type, detection.pattern_type)}"
                    ),
                    severity=severity,
                    location=detection.location or f"{path}:{template_location}",
                    details={
                        "pattern_type": detection.pattern_type,
                        "pattern": detection.pattern,
                        "match_text": detection.match_text[:200],
                        "risk_level": detection.risk_level,
                        "template_location": template_location,
                        "ml_context": context.framework,
                    },
                    why=why_explanation,
                )

        if total_detections == 0:
            result.add_check(
                name="Jinja2 SSTI Analysis",
                passed=True,
                message="No template injection patterns detected",
                location=path,
                details={"templates_analyzed": len(templates)},
            )
        else:
            result.add_check(
                name="Jinja2 SSTI Analysis Summary",
                passed=False,
                message=f"Found {total_detections} potential SSTI patterns across {len(templates)} templates",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "total_detections": total_detections,
                    "templates_analyzed": len(templates),
                    "sensitivity_level": self.sensitivity_level,
                },
            )

        result.bytes_scanned = file_size
        self._finish_scan_result(result)
        return result

    def _mark_inconclusive_scan_result(
        self,
        result: ScanResult,
        location: str,
        failure: dict[str, Any],
    ) -> None:
        reason = str(failure["reason"])
        reasons = result.metadata.get(_INCONCLUSIVE_REASONS_METADATA_KEY)
        if not isinstance(reasons, list):
            reasons = []
        if reason not in reasons:
            reasons.append(reason)

        result.metadata[_INCONCLUSIVE_METADATA_KEY] = INCONCLUSIVE_SCAN_OUTCOME
        result.metadata[_INCONCLUSIVE_REASONS_METADATA_KEY] = reasons
        if reason == "jinja2_template_size_limit_exceeded":
            result.add_check(
                name="Template Size Limit",
                passed=False,
                message="Template analysis incomplete because one or more extracted templates exceed the size limit",
                severity=IssueSeverity.INFO,
                location=location,
                details=failure,
            )
            return

        if reason == "jinja2_template_read_failed":
            result.add_check(
                name="Template Read",
                passed=False,
                message="Template analysis incomplete because the standalone template could not be read as UTF-8 text",
                severity=IssueSeverity.INFO,
                location=location,
                details=failure,
            )
            return

        result.add_check(
            name="Template Config Parsing",
            passed=False,
            message=f"Failed to parse {failure['format']} config for template extraction",
            severity=IssueSeverity.INFO,
            location=location,
            details=failure,
        )

    @staticmethod
    def _finish_scan_result(result: ScanResult) -> None:
        if result.metadata.get(
            _INCONCLUSIVE_METADATA_KEY
        ) == INCONCLUSIVE_SCAN_OUTCOME and not _scan_result_has_security_findings(result):
            result.finish(success=False)
            return

        result.finish(success=True)

    def _determine_context(self, path: str) -> MLContext:
        """Determine ML context and file type"""
        context = MLContext()
        filename = os.path.basename(path).lower()
        ext = os.path.splitext(path)[1].lower()

        # File type detection
        if ext == ".gguf":
            context.file_type = "gguf"
            context.confidence += 2
        elif "tokenizer" in filename:
            context.file_type = "tokenizer_config"
            context.is_tokenizer = True
            context.confidence += 2
        elif ext == ".json":
            context.file_type = "json"
            context.confidence += 1
        elif ext in [".yaml", ".yml"]:
            context.file_type = "yaml"
            context.confidence += 1
        elif ext in [".jinja", ".j2", ".template"]:
            context.file_type = "template"
            context.is_chat_template = True
            context.confidence += 1

        # Framework detection from path
        path_lower = path.lower()
        if "huggingface" in path_lower or "transformers" in path_lower:
            context.framework = "huggingface"
            context.confidence += 1
        elif "pytorch" in path_lower:
            context.framework = "pytorch"
            context.confidence += 1
        elif "tensorflow" in path_lower:
            context.framework = "tensorflow"
            context.confidence += 1

        return context

    def _extract_templates(self, path: str, context: MLContext) -> tuple[dict[str, str], list[dict[str, Any]]]:
        """Extract Jinja2 templates from various file formats"""
        templates: dict[str, str] = {}
        extraction_failures: list[dict[str, Any]] = []

        try:
            if context.file_type == "gguf" and HAS_GGUF:
                extracted, failures = self._extract_gguf_templates(path)
                templates.update(extracted)
                extraction_failures.extend(failures)
            elif context.file_type in ["json", "tokenizer_config"]:
                extracted, failures = self._extract_json_templates(path)
                templates.update(extracted)
                extraction_failures.extend(failures)
            elif context.file_type == "yaml":
                extracted, failures = self._extract_yaml_templates(path)
                templates.update(extracted)
                extraction_failures.extend(failures)
            elif context.file_type == "template":
                extracted, failures = self._extract_template_file(path)
                templates.update(extracted)
                extraction_failures.extend(failures)
        except Exception as e:
            logger.warning(f"Failed to extract templates from {path}: {e}")

        return templates, extraction_failures

    def _extract_gguf_templates(self, path: str) -> tuple[dict[str, str], list[dict[str, Any]]]:
        """Extract chat templates from GGUF metadata"""
        templates: dict[str, str] = {}
        extraction_failures: list[dict[str, Any]] = []

        try:
            reader = GGUFReader(path)
        except Exception as exc:
            logger.debug("Error opening GGUF for template extraction: %s", exc)
            extraction_failures.append(self._template_extraction_failure("gguf", "jinja2_gguf_parse_failed", exc))
            return templates, extraction_failures

        for key, field in reader.fields.items():
            if not self._is_gguf_chat_template_key(key):
                continue

            try:
                if not hasattr(field, "parts") or not hasattr(field, "data") or len(field.data) == 0:
                    raise ValueError("GGUF chat template field does not expose readable value data")

                value = field.parts[field.data[0]]
                template_str = self._gguf_template_value_to_string(value, extraction_failures, key)
                if template_str:
                    self._add_template_candidate(
                        template_str,
                        templates,
                        key,
                        extraction_failures,
                        "gguf",
                    )
            except Exception as exc:
                logger.debug("Error extracting GGUF chat template %s: %s", key, exc)
                self._add_gguf_template_decode_failure(extraction_failures, key, field, exc)

        return templates, extraction_failures

    @staticmethod
    def _is_gguf_chat_template_key(key: Any) -> bool:
        return isinstance(key, str) and (key == "tokenizer.chat_template" or key.startswith("tokenizer.chat_template."))

    @staticmethod
    def _add_gguf_template_decode_failure(
        extraction_failures: list[dict[str, Any]],
        template_location: str,
        value: Any,
        error: Exception | None = None,
    ) -> None:
        if any(
            failure.get("reason") == "jinja2_gguf_template_decode_failed"
            and failure.get("template_location") == template_location
            for failure in extraction_failures
        ):
            return

        failure = {
            "format": "gguf",
            "reason": "jinja2_gguf_template_decode_failed",
            "template_location": template_location,
            "value_type": type(value).__name__,
        }
        if error is not None:
            failure["exception"] = str(error)
            failure["exception_type"] = type(error).__name__
        extraction_failures.append(failure)

    def _gguf_template_value_to_string(
        self,
        value: Any,
        extraction_failures: list[dict[str, Any]],
        template_location: str,
    ) -> str | None:
        if isinstance(value, str):
            return value

        if isinstance(value, list | tuple):
            return self._gguf_integer_sequence_to_string(value, extraction_failures, template_location)

        if isinstance(value, bytes | bytearray | memoryview):
            return self._gguf_template_bytes_to_string(bytes(value), extraction_failures, template_location)

        declared_size = self._gguf_declared_template_size(value)
        if declared_size is not None and declared_size > self.max_template_size:
            self._add_template_size_failure(
                extraction_failures,
                "gguf",
                template_location,
                declared_size,
            )
            return None

        tobytes = getattr(value, "tobytes", None)
        if callable(tobytes):
            try:
                raw_value = tobytes()
            except Exception as exc:
                logger.debug("Error decoding GGUF chat template bytes: %s", exc)
            else:
                if isinstance(raw_value, bytes | bytearray | memoryview):
                    return self._gguf_template_bytes_to_string(
                        bytes(raw_value),
                        extraction_failures,
                        template_location,
                    )

        tolist = getattr(value, "tolist", None)
        if callable(tolist):
            try:
                list_value = tolist()
            except Exception as exc:
                logger.debug("Error decoding GGUF chat template list: %s", exc)
            else:
                if list_value is not value:
                    recursive_value = self._gguf_template_value_to_string(
                        list_value,
                        extraction_failures,
                        template_location,
                    )
                    if recursive_value is not None:
                        return recursive_value

        self._add_gguf_template_decode_failure(extraction_failures, template_location, value)
        return None

    def _gguf_integer_sequence_to_string(
        self,
        value: list[Any] | tuple[Any, ...],
        extraction_failures: list[dict[str, Any]],
        template_location: str,
    ) -> str | None:
        if len(value) > self.max_template_size:
            self._add_template_size_failure(
                extraction_failures,
                "gguf",
                template_location,
                len(value),
            )
            return None

        characters: list[str] = []
        for raw_code_point in value:
            if isinstance(raw_code_point, bool):
                self._add_gguf_template_decode_failure(extraction_failures, template_location, value)
                return None

            try:
                code_point = operator.index(raw_code_point)
            except TypeError:
                self._add_gguf_template_decode_failure(extraction_failures, template_location, value)
                return None

            if not 0 <= code_point <= 1114111:
                self._add_gguf_template_decode_failure(extraction_failures, template_location, value)
                return None
            characters.append(chr(code_point))

        return "".join(characters)

    def _gguf_template_bytes_to_string(
        self,
        value: bytes,
        extraction_failures: list[dict[str, Any]],
        template_location: str,
    ) -> str | None:
        if len(value) > self.max_template_size:
            self._add_template_size_failure(
                extraction_failures,
                "gguf",
                template_location,
                len(value),
            )
            return None

        return value.decode("utf-8", errors="replace")

    @staticmethod
    def _gguf_declared_template_size(value: Any) -> int | None:
        nbytes = _nonnegative_int(getattr(value, "nbytes", None))
        if nbytes is not None:
            return nbytes

        size = _nonnegative_int(getattr(value, "size", None))
        itemsize = _nonnegative_int(getattr(value, "itemsize", None))
        if size is not None and itemsize is not None:
            return size * itemsize

        return size

    def _extract_json_templates(self, path: str) -> tuple[dict[str, str], list[dict[str, Any]]]:
        """Extract templates from JSON configuration files"""
        templates: dict[str, str] = {}
        extraction_failures: list[dict[str, Any]] = []

        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)

            # Recursively search for template fields
            self._find_json_templates(data, templates, "", extraction_failures, "json")

        except Exception as e:
            logger.debug(f"Error extracting JSON templates: {e}")
            extraction_failures.append(self._template_extraction_failure("json", "jinja2_json_parse_failed", e))
            self._extract_raw_template_fallback(path, templates, "raw_json_parse_fallback")

        return templates, extraction_failures

    def _find_json_templates(
        self,
        data: Any,
        templates: dict[str, str],
        path: str,
        extraction_failures: list[dict[str, Any]],
        config_format: str,
    ) -> None:
        """Recursively find template strings in JSON data"""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key

                # Check for known template fields
                if key in _TEMPLATE_FIELD_KEYS and isinstance(value, str) and value.strip():
                    self._add_template_candidate(
                        value,
                        templates,
                        current_path,
                        extraction_failures,
                        config_format,
                    )

                # Recursively check nested structures
                elif isinstance(value, dict | list):
                    self._find_json_templates(value, templates, current_path, extraction_failures, config_format)

                # Check for template-like strings (contain Jinja2 syntax)
                elif isinstance(value, str) and self._looks_like_template(value):
                    self._add_template_candidate(
                        value,
                        templates,
                        current_path,
                        extraction_failures,
                        config_format,
                    )

        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]" if path else f"[{i}]"
                self._find_json_templates(item, templates, current_path, extraction_failures, config_format)

    def _extract_yaml_templates(self, path: str) -> tuple[dict[str, str], list[dict[str, Any]]]:
        """Extract templates from YAML configuration files"""
        templates: dict[str, str] = {}
        extraction_failures: list[dict[str, Any]] = []

        if not HAS_YAML:
            extraction_failures.append(
                {
                    "format": "yaml",
                    "reason": "jinja2_yaml_dependency_unavailable",
                    "required_package": "PyYAML",
                }
            )
            self._extract_raw_template_fallback(path, templates, "raw_yaml_dependency_fallback")
            return templates, extraction_failures

        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if data:
                self._find_json_templates(data, templates, "", extraction_failures, "yaml")  # Reuse JSON logic

        except Exception as e:
            logger.debug(f"Error extracting YAML templates: {e}")
            extraction_failures.append(self._template_extraction_failure("yaml", "jinja2_yaml_parse_failed", e))
            self._extract_raw_template_fallback(path, templates, "raw_yaml_parse_fallback")

        return templates, extraction_failures

    def _template_extraction_failure(self, config_format: str, reason: str, error: Exception) -> dict[str, Any]:
        return {
            "format": config_format,
            "reason": reason,
            "exception": str(error),
            "exception_type": type(error).__name__,
        }

    def _add_template_candidate(
        self,
        value: str,
        templates: dict[str, str],
        template_path: str,
        extraction_failures: list[dict[str, Any]],
        config_format: str,
    ) -> None:
        if len(value) <= self.max_template_size:
            self._record_template_candidate(templates, template_path, value)
            return

        self._add_template_size_failure(
            extraction_failures,
            config_format,
            template_path,
            len(value),
        )

    @staticmethod
    def _record_template_candidate(templates: dict[str, str], template_path: str, value: str) -> None:
        if template_path not in templates:
            templates[template_path] = value
            return

        duplicate_index = len(templates) + 1
        unique_path = f"{template_path} [duplicate {duplicate_index}]"
        while unique_path in templates:
            duplicate_index += 1
            unique_path = f"{template_path} [duplicate {duplicate_index}]"
        templates[unique_path] = value

    def _add_template_size_failure(
        self,
        extraction_failures: list[dict[str, Any]],
        config_format: str,
        template_path: str,
        template_size: int,
    ) -> None:
        for failure in extraction_failures:
            if (
                failure.get("format") == config_format
                and failure.get("reason") == "jinja2_template_size_limit_exceeded"
                and failure.get("max_template_size") == self.max_template_size
            ):
                break
        else:
            failure = {
                "format": config_format,
                "reason": "jinja2_template_size_limit_exceeded",
                "max_template_size": self.max_template_size,
                "skipped_template_locations": [],
                "skipped_template_location_count": 0,
                "skipped_template_locations_truncated": False,
                "template_size": 0,
            }
            extraction_failures.append(failure)

        failure["skipped_template_location_count"] = int(failure["skipped_template_location_count"]) + 1
        locations = failure["skipped_template_locations"]
        if isinstance(locations, list) and len(locations) < _MAX_REPORTED_TEMPLATE_LOCATIONS:
            locations.append(template_path)
        else:
            failure["skipped_template_locations_truncated"] = True
        failure["template_size"] = max(int(failure["template_size"]), template_size)

    def _legacy_template_size_failure(
        self,
        config_format: str,
        template_path: str,
        template_size: int,
    ) -> dict[str, Any]:
        extraction_failures: list[dict[str, Any]] = []
        self._add_template_size_failure(extraction_failures, config_format, template_path, template_size)
        return extraction_failures[0]

    def _extract_raw_template_fallback(self, path: str, templates: dict[str, str], template_key: str) -> None:
        for index, fallback_text in enumerate(self._raw_template_fallback_windows_from_file(path)):
            fallback_key = template_key if index == 0 else f"{template_key}_{index + 1}"
            templates[fallback_key] = fallback_text

    def _raw_template_fallback_windows_from_file(self, path: str) -> list[str]:
        try:
            file_size = os.path.getsize(path)
        except OSError as exc:
            logger.debug("Error sizing raw template fallback from %s: %s", path, exc)
            return []

        if file_size <= 0:
            return []

        window_size = self._raw_template_fallback_window_size(file_size)
        marker_offsets = self._template_marker_offsets_from_file(path, file_size, window_size)
        if not marker_offsets:
            return []

        windows: list[tuple[int, int]] = []
        for marker_offset in marker_offsets:
            if any(start <= marker_offset < end for start, end in windows):
                continue

            start = max(0, marker_offset - _RAW_PARSE_FALLBACK_CONTEXT_BYTES)
            end = min(file_size, start + window_size)
            start = max(0, end - window_size)
            windows.append((start, end))

            if len(windows) >= _RAW_PARSE_FALLBACK_MAX_WINDOWS:
                break

        fallback_windows: list[str] = []
        try:
            with open(path, "rb") as f:
                for start, end in windows:
                    f.seek(start)
                    raw = f.read(end - start)
                    fallback_windows.append(raw.decode("utf-8", errors="replace"))
        except OSError as exc:
            logger.debug("Error reading raw template fallback from %s: %s", path, exc)
            return []

        return fallback_windows

    def _raw_template_fallback_windows(self, text: str) -> list[str]:
        if not self._looks_like_template(text):
            return []

        window_size = self._raw_template_fallback_window_size(len(text))

        if len(text) <= window_size:
            return [text]

        windows: list[tuple[int, int]] = []
        for marker_offset in self._template_marker_offsets(text):
            if any(start <= marker_offset < end for start, end in windows):
                continue

            start = max(0, marker_offset - _RAW_PARSE_FALLBACK_CONTEXT_BYTES)
            end = min(len(text), start + window_size)
            start = max(0, end - window_size)
            windows.append((start, end))

            if len(windows) >= _RAW_PARSE_FALLBACK_MAX_WINDOWS:
                break

        return [text[start:end] for start, end in windows]

    def _raw_template_fallback_window_size(self, content_size: int) -> int:
        return self._raw_template_fallback_window_size_for_config(content_size, self.max_template_size)

    @staticmethod
    def _template_marker_offsets(text: str) -> list[int]:
        offsets: set[int] = set()
        for indicator in _JINJA_TEMPLATE_INDICATORS:
            marker_offset = text.find(indicator)
            while marker_offset != -1:
                offsets.add(marker_offset)
                marker_offset = text.find(indicator, marker_offset + len(indicator))

        return sorted(offsets)

    @staticmethod
    def _template_marker_offsets_from_file(path: str, file_size: int, window_size: int) -> list[int]:
        offsets: set[int] = set()
        windows: list[tuple[int, int]] = []
        max_indicator_size = max(len(indicator) for indicator in _JINJA_TEMPLATE_INDICATOR_BYTES)
        overlap_size = max_indicator_size - 1
        overlap = b""
        chunk_start = 0

        try:
            with open(path, "rb") as f:
                while len(windows) < _RAW_PARSE_FALLBACK_MAX_WINDOWS:
                    chunk = f.read(_RAW_PARSE_FALLBACK_READ_BYTES)
                    if not chunk:
                        break

                    data_start = max(0, chunk_start - len(overlap))
                    data = overlap + chunk
                    chunk_offsets: set[int] = set()
                    for indicator in _JINJA_TEMPLATE_INDICATOR_BYTES:
                        marker_offset = data.find(indicator)
                        while marker_offset != -1:
                            absolute_offset = data_start + marker_offset
                            if absolute_offset not in offsets:
                                chunk_offsets.add(absolute_offset)
                            marker_offset = data.find(indicator, marker_offset + len(indicator))

                    for absolute_offset in sorted(chunk_offsets):
                        if Jinja2TemplateScanner._add_fallback_window_for_marker(
                            windows,
                            absolute_offset,
                            file_size,
                            window_size,
                        ):
                            offsets.add(absolute_offset)
                            if len(windows) >= _RAW_PARSE_FALLBACK_MAX_WINDOWS:
                                break

                    overlap = data[-overlap_size:] if overlap_size else b""
                    chunk_start += len(chunk)
        except OSError as exc:
            logger.debug("Error searching raw template fallback markers in %s: %s", path, exc)
            return []

        return sorted(offsets)

    @staticmethod
    def _raw_template_fallback_window_size_for_config(content_size: int, configured_window_size: Any) -> int:
        if not isinstance(configured_window_size, int) or configured_window_size <= 0:
            configured_window_size = _RAW_PARSE_FALLBACK_READ_BYTES
        return min(configured_window_size, _RAW_PARSE_FALLBACK_READ_BYTES, content_size)

    @staticmethod
    def _fallback_window_for_marker(marker_offset: int, content_size: int, window_size: int) -> tuple[int, int]:
        start = max(0, marker_offset - _RAW_PARSE_FALLBACK_CONTEXT_BYTES)
        end = min(content_size, start + window_size)
        start = max(0, end - window_size)
        return start, end

    @staticmethod
    def _add_fallback_window_for_marker(
        windows: list[tuple[int, int]],
        marker_offset: int,
        content_size: int,
        window_size: int,
    ) -> bool:
        if any(start <= marker_offset < end for start, end in windows):
            return False
        windows.append(Jinja2TemplateScanner._fallback_window_for_marker(marker_offset, content_size, window_size))
        return True

    def _extract_template_file(self, path: str) -> tuple[dict[str, str], list[dict[str, Any]]]:
        """Extract bounded content from a standalone template file."""
        templates: dict[str, str] = {}
        extraction_failures: list[dict[str, Any]] = []

        try:
            with open(path, encoding="utf-8") as f:
                content = f.read(self.max_template_size + 1)

            if len(content) > self.max_template_size:
                extraction_failures.append(
                    self._legacy_template_size_failure(
                        "template",
                        "template_content",
                        len(content),
                    )
                )
            elif content:
                templates["template_content"] = content

        except Exception as e:
            logger.debug(f"Error reading template file: {e}")
            extraction_failures.append(self._template_extraction_failure("template", "jinja2_template_read_failed", e))

        return templates, extraction_failures

    def _looks_like_template(self, text: str) -> bool:
        """Check if text looks like a Jinja2 template"""
        if not isinstance(text, str) or len(text) < 5:
            return False

        return any(indicator in text for indicator in _JINJA_TEMPLATE_INDICATORS)

    def _analyze_template(self, template_content: str, context: MLContext, location: str) -> list[DetectionResult]:
        """Analyze template content for SSTI patterns"""
        detections: list[DetectionResult] = []

        # Skip empty or very short templates
        if not template_content or len(template_content.strip()) < 3:
            return detections

        # Check each pattern category
        for category, compiled_patterns in self._compiled_patterns.items():
            for compiled_pattern, original_pattern in compiled_patterns:
                matches = compiled_pattern.finditer(template_content)

                for match in matches:
                    # Skip if this is a common ML pattern and we're configured to ignore them
                    if self.skip_common_patterns and self._is_common_ml_pattern(match.group(), context):
                        continue

                    detection = DetectionResult(
                        pattern_type=category,
                        pattern=original_pattern,
                        match_text=match.group(),
                        risk_level=self._get_risk_level_for_category(category),
                        location=location,
                        explanation=self._get_pattern_explanation(category, match.group()),
                    )

                    detections.append(detection)

        # Optional: Test template safety with sandboxing
        if self.enable_sandbox_test and HAS_JINJA2_SANDBOX:
            sandbox_result = self._test_template_safety(template_content)
            if not sandbox_result:
                detections.append(
                    DetectionResult(
                        pattern_type="sandbox_violation",
                        pattern="jinja2_sandbox_test",
                        match_text="Template failed sandboxing safety test",
                        risk_level="CRITICAL",
                        location=location,
                        explanation="Template contains operations that are blocked by Jinja2 sandboxing",
                    )
                )

        return detections

    def _is_common_ml_pattern(self, match_text: str, context: MLContext) -> bool:
        """Check if match is a common, benign ML pattern"""
        match_lower = match_text.lower()
        if context.is_chat_template and match_lower.startswith("{% macro "):
            return True

        if not context.framework:
            return False

        # Common HuggingFace chat template patterns
        if context.framework == "huggingface":
            # Normalize quotes for matching (handle both single and double quotes)
            match_normalized = match_lower.replace('"', "'")

            benign_patterns = [
                "for message in messages",
                "message['role']",
                "message['content']",
                "messages[0]['role']",
                "if message['role'] == 'system'",
                "if message['role'] == 'user'",
                "if message['role'] == 'assistant'",
                "if message['role'] == 'tool'",
                # Bracket notation patterns (non-dunder attributes)
                "['role']",
                "['content']",
                "['tools']",
                "['name']",
                # Tool-related patterns
                "for tool in tools",
                "if tool is not string",
            ]

            return any(pattern in match_normalized for pattern in benign_patterns)

        return False

    def _get_risk_level_for_category(self, category: str) -> str:
        """Get risk level for a pattern category"""
        risk_mapping = {
            "critical_injection": "CRITICAL",
            "object_traversal": "HIGH",
            "global_access": "HIGH",
            "obfuscation": "HIGH",
            "control_flow": "MEDIUM",
            "environment_access": "MEDIUM",
        }

        return risk_mapping.get(category, "MEDIUM")

    def _get_severity_for_detection(self, detection: DetectionResult, context: MLContext) -> IssueSeverity:
        """Convert risk level to issue severity, considering context"""
        base_severity_map = {
            "CRITICAL": IssueSeverity.CRITICAL,
            "HIGH": IssueSeverity.WARNING,  # Changed from ERROR to WARNING
            "MEDIUM": IssueSeverity.WARNING,
            "LOW": IssueSeverity.INFO,
        }

        base_severity = base_severity_map.get(detection.risk_level, IssueSeverity.WARNING)

        # Context-based adjustments: Don't downgrade critical attack patterns
        # Only downgrade truly benign patterns in legitimate ML contexts
        if (
            context.confidence >= 3
            and context.framework == "huggingface"
            and detection.pattern_type in ["control_flow", "environment_access"]
            and base_severity == IssueSeverity.WARNING
        ):
            return IssueSeverity.INFO

        # Don't downgrade obfuscation patterns in HuggingFace context
        # The regex fix should prevent false positives, so any remaining matches are suspicious

        # Sensitivity level adjustments
        if self.sensitivity_level == "high":
            # Keep original severity
            pass
        elif self.sensitivity_level == "low" and base_severity == IssueSeverity.WARNING:
            # Downgrade non-critical issues
            return IssueSeverity.INFO

        return base_severity

    def _get_pattern_explanation(self, category: str, match_text: str) -> str:
        """Get explanation for a specific pattern match"""
        explanations = {
            "critical_injection": (
                f"Direct code execution pattern detected: '{match_text}'. "
                "This indicates an attempt to execute arbitrary Python code through template injection."
            ),
            "object_traversal": (
                f"Python object traversal detected: '{match_text}'. "
                "This pattern navigates Python's object hierarchy to access dangerous functions."
            ),
            "global_access": (
                f"Global namespace access detected: '{match_text}'. "
                "This pattern attempts to access Python's global namespace to reach restricted functions."
            ),
            "obfuscation": (
                f"Obfuscation technique detected: '{match_text}'. "
                "This pattern may be attempting to bypass security filters."
            ),
            "control_flow": (
                f"Suspicious template control flow: '{match_text}'. "
                "This pattern uses Jinja2 control structures in potentially malicious ways."
            ),
            "environment_access": (
                f"System environment access: '{match_text}'. "
                "This pattern attempts to access system information or configuration."
            ),
            "sandbox_violation": ("Template contains operations that violate Jinja2 sandboxing security restrictions."),
        }

        return explanations.get(category, f"Suspicious pattern detected: {match_text}")

    def _get_why_explanation(self, detection: DetectionResult, context: MLContext) -> str:
        """Get detailed 'why' explanation for the issue"""
        base_why = {
            "critical_injection": (
                "This pattern indicates a direct attempt to execute arbitrary code through Jinja2 template "
                "injection (SSTI). Such patterns are commonly used in CVE-2024-34359 and similar attacks to "
                "achieve remote code execution on systems processing untrusted templates."
            ),
            "object_traversal": (
                "This pattern exploits Python's object model to navigate from safe objects to dangerous functions. "
                "Attackers use object traversal to bypass template sandboxing and reach system functions like "
                "os.system() or subprocess.call()."
            ),
            "global_access": (
                "This pattern attempts to access Python's global namespace, which contains references to "
                "dangerous built-in functions. This is a common technique in template injection attacks to "
                "bypass restrictions and access system functions."
            ),
            "obfuscation": (
                "This pattern uses encoding or alternative syntax to evade basic security filters. "
                "Obfuscation techniques are often employed by attackers to bypass Web Application "
                "Firewalls (WAFs) and template sanitization."
            ),
            "control_flow": (
                "This pattern uses Jinja2's control structures (loops, conditionals) to implement complex "
                "attack logic. While these structures are legitimate in templates, they can be used to iterate "
                "through Python classes or conditionally execute payloads."
            ),
            "environment_access": (
                "This pattern attempts to access system environment variables or configuration data. "
                "While not directly dangerous, it can lead to information disclosure and aid in further "
                "exploitation."
            ),
        }

        why = base_why.get(detection.pattern_type, "This pattern matches known template injection techniques.")

        # Add context-specific information
        if context.file_type == "gguf":
            why += (
                " This is particularly concerning in GGUF models due to CVE-2024-34359, "
                "which affects llama-cpp-python when processing malicious chat templates."
            )
        elif context.is_tokenizer:
            why += (
                " Template injection in tokenizer configurations can execute when the tokenizer "
                "processes chat messages, potentially compromising applications using the model."
            )

        return why

    def _test_template_safety(self, template_content: str) -> bool:
        """Test if template is safe using Jinja2 sandboxing"""
        if not HAS_JINJA2_SANDBOX:
            return True  # Can't test, assume safe

        try:
            # Test with sandboxed environment
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # Suppress Jinja2 warnings

                env = jinja2.sandbox.SandboxedEnvironment()
                template = env.from_string(template_content)

                # Try to render with minimal context
                template.render(messages=[], config={})
                return True

        except jinja2.exceptions.SecurityError:
            # Template contains dangerous operations
            return False
        except Exception:
            # Other errors don't indicate security issues
            return True
