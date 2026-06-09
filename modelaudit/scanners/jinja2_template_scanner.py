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
import math
import multiprocessing as mp
import operator
import os
import platform
import queue
import re
import warnings
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, ClassVar, cast

try:
    import resource

    HAS_RESOURCE_LIMITS = True
except ImportError:
    resource = None  # type: ignore[assignment]
    HAS_RESOURCE_LIMITS = False

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
    import jinja2.nodes
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
_DEFAULT_SANDBOX_RENDER_TIMEOUT_SECONDS = 0.5
_DEFAULT_SANDBOX_RENDER_MAX_OUTPUT_CHARS = 64 * 1024
_DEFAULT_SANDBOX_RENDER_MAX_MEMORY_BYTES = 512 * 1024 * 1024
_SANDBOX_RENDER_SPAWN_STARTUP_GRACE_SECONDS = 2.0
_SANDBOX_RENDER_BUDGET_REASON = "jinja2_sandbox_render_budget_exceeded"
_STATIC_INT_EVAL_MAX_ABS = 10**100
_SANDBOX_MAX_RANGE_ITERATIONS = int(jinja2.sandbox.MAX_RANGE) if HAS_JINJA2_SANDBOX else 100_000
_EAGER_RANGE_ITERATION_FILTERS = frozenset({"groupby", "join", "list", "sort"})
_LAZY_RANGE_ITERATION_FILTERS = frozenset(
    {"batch", "d", "default", "map", "reject", "rejectattr", "reverse", "select", "selectattr", "slice", "unique"}
)

_StaticIntResult = tuple[int, bool]


@dataclass(frozen=True)
class _StaticIntCandidates:
    values: tuple[_StaticIntResult, ...]


_StaticIntBinding = _StaticIntResult | _StaticIntCandidates


class _SandboxRenderBudgetExceeded(Exception):
    pass


def _proc_statm_virtual_memory_bytes() -> int | None:
    try:
        with open("/proc/self/statm", encoding="ascii") as statm:
            total_pages = int(statm.read().split()[0])
        return total_pages * int(os.sysconf("SC_PAGE_SIZE"))
    except Exception:
        return None


def _resource_max_resident_set_bytes() -> int | None:
    if not HAS_RESOURCE_LIMITS or resource is None:
        return None
    try:
        max_rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except Exception:
        return None
    if max_rss <= 0:
        return None
    if platform.system() == "Darwin":
        return max_rss
    return max_rss * 1024


def _current_process_memory_baseline_bytes() -> int | None:
    return _proc_statm_virtual_memory_bytes() or _resource_max_resident_set_bytes()


def _sandbox_worker_start_method() -> str | None:
    start_methods = mp.get_all_start_methods()
    if "fork" in start_methods and _proc_statm_virtual_memory_bytes() is not None:
        return "fork"
    if "spawn" in start_methods:
        return "spawn"
    if "fork" in start_methods:
        return "fork"
    return None


def _limit_sandbox_worker_memory(max_memory_bytes: int) -> None:
    if not HAS_RESOURCE_LIMITS or resource is None:
        return

    baseline_memory_bytes = _current_process_memory_baseline_bytes()
    if baseline_memory_bytes is None:
        return

    for limit_name in ("RLIMIT_AS",):
        limit_id = getattr(resource, limit_name, None)
        if limit_id is None:
            continue
        try:
            _soft_limit, hard_limit = resource.getrlimit(limit_id)
            capped_limit = baseline_memory_bytes + max_memory_bytes
            if hard_limit != resource.RLIM_INFINITY:
                capped_limit = min(capped_limit, hard_limit)
            resource.setrlimit(limit_id, (capped_limit, hard_limit))
        except (OSError, ValueError):
            continue


def _project_repeated_value_size(left: Any, right: Any) -> int | None:
    if isinstance(left, int) and hasattr(right, "__len__"):
        return max(left, 0) * len(right)
    if isinstance(right, int) and hasattr(left, "__len__"):
        return max(right, 0) * len(left)
    return None


def _project_combined_value_size(left: Any, right: Any) -> int | None:
    if isinstance(left, str | bytes | list | tuple) and isinstance(right, type(left)):
        return len(left) + len(right)
    return None


_PERCENT_FORMAT_FIELD_PATTERN = re.compile(
    r"%(?:\([^)]+\))?[#0\- +]*(?P<width>\d+|\*)?(?:\.(?P<precision>\d+|\*))?[hlL]?(?P<conversion>[diouxXeEfFgGcrsa%])"
)


def _percent_format_exceeds_budget(left: Any, right: Any, max_output_chars: int) -> bool:
    if not isinstance(left, str | bytes):
        return False
    format_text = left.decode("latin-1") if isinstance(left, bytes) else left
    arguments = list(right) if isinstance(right, tuple) else [right]
    argument_index = 0
    for match in _PERCENT_FORMAT_FIELD_PATTERN.finditer(format_text):
        if match.group("conversion") == "%":
            continue
        for group_name in ("width", "precision"):
            value = match.group(group_name)
            if value == "*":
                if (
                    argument_index < len(arguments)
                    and isinstance(arguments[argument_index], int)
                    and abs(arguments[argument_index]) > max_output_chars
                ):
                    return True
                argument_index += 1
            elif value is not None and int(value) > max_output_chars:
                return True
        argument_index += 1
    return False


def _create_budgeted_sandbox_environment(max_output_chars: int) -> Any:
    class _BudgetedSandboxEnvironment(jinja2.sandbox.SandboxedEnvironment):
        intercepted_binops = frozenset({"*", "+", "%"})

        def call_binop(self, context: Any, operator: str, left: Any, right: Any) -> Any:
            projected_size = None
            if operator == "*":
                projected_size = _project_repeated_value_size(left, right)
            elif operator == "+":
                projected_size = _project_combined_value_size(left, right)
            elif operator == "%" and _percent_format_exceeds_budget(left, right, max_output_chars):
                raise _SandboxRenderBudgetExceeded

            if projected_size is not None and projected_size > max_output_chars:
                raise _SandboxRenderBudgetExceeded

            return super().call_binop(context, operator, left, right)

    return _BudgetedSandboxEnvironment()


def _run_budgeted_sandbox_render(template_content: str, max_output_chars: int) -> tuple[str, str | None]:
    try:
        env = _create_budgeted_sandbox_environment(max_output_chars)
        template = env.from_string(template_content)
        rendered_chars = 0
        for chunk in template.generate(messages=[], config={}):
            rendered_chars += len(str(chunk))
            if rendered_chars > max_output_chars:
                raise _SandboxRenderBudgetExceeded
        return "safe", None
    except jinja2.exceptions.SecurityError:
        return "security_error", None
    except _SandboxRenderBudgetExceeded:
        return "budget_exceeded", "output"
    except MemoryError:
        return "budget_exceeded", "memory"
    except OverflowError:
        return "budget_exceeded", "range"
    except Exception as exc:
        return "render_error", type(exc).__name__


def _sandbox_render_probe_worker(
    template_content: str,
    max_output_chars: int,
    max_memory_bytes: int,
    result_queue: Any,
    ready_queue: Any,
) -> None:
    try:
        _limit_sandbox_worker_memory(max_memory_bytes)
        ready_queue.put(("ready", None))
        result_queue.put(_run_budgeted_sandbox_render(template_content, max_output_chars))
    except Exception as exc:
        result_queue.put(("worker_error", type(exc).__name__))


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
        self.sandbox_render_timeout_seconds = self._positive_float_config(
            "sandbox_render_timeout_seconds",
            _DEFAULT_SANDBOX_RENDER_TIMEOUT_SECONDS,
        )
        self.sandbox_render_max_output_chars = self._positive_int_config(
            "sandbox_render_max_output_chars",
            _DEFAULT_SANDBOX_RENDER_MAX_OUTPUT_CHARS,
        )
        self.sandbox_render_max_memory_bytes = self._positive_int_config(
            "sandbox_render_max_memory_bytes",
            _DEFAULT_SANDBOX_RENDER_MAX_MEMORY_BYTES,
        )
        self.skip_common_patterns = self.config.get("skip_common_patterns", True)  # Ignore common ML patterns

        self._compiled_patterns = _COMPILED_JINJA2_SSTI_PATTERNS

    def _positive_float_config(self, key: str, default: float) -> float:
        try:
            value = float(self.config.get(key, default))
        except (TypeError, ValueError):
            return default
        return value if math.isfinite(value) and value > 0 else default

    def _positive_int_config(self, key: str, default: int) -> int:
        try:
            value = int(self.config.get(key, default))
        except (OverflowError, TypeError, ValueError):
            return default
        return value if value > 0 else default

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
            detections, analysis_failures = self._analyze_template(
                template_content,
                context,
                f"{path}:{template_location}",
            )
            for failure in analysis_failures:
                self._mark_inconclusive_scan_result(result, f"{path}:{template_location}", failure)

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

        if reason == _SANDBOX_RENDER_BUDGET_REASON:
            result.add_check(
                name="Template Sandbox Safety Probe",
                passed=False,
                message="Template sandbox safety probe incomplete because the render budget was exceeded",
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

    def _analyze_template(
        self,
        template_content: str,
        context: MLContext,
        location: str,
    ) -> tuple[list[DetectionResult], list[dict[str, Any]]]:
        """Analyze template content for SSTI patterns"""
        detections: list[DetectionResult] = []
        analysis_failures: list[dict[str, Any]] = []

        # Skip empty or very short templates
        if not template_content or len(template_content.strip()) < 3:
            return detections, analysis_failures

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
            sandbox_safe, sandbox_failure = self._test_template_safety(template_content, location)
            if sandbox_failure:
                analysis_failures.append(sandbox_failure)
            if not sandbox_safe:
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

        return detections, analysis_failures

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

    def _test_template_safety(self, template_content: str, location: str) -> tuple[bool, dict[str, Any] | None]:
        """Test if template is safe using Jinja2 sandboxing"""
        if not HAS_JINJA2_SANDBOX:
            return True, None  # Can't test, assume safe

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # Suppress Jinja2 warnings
                status, detail = self._test_template_safety_with_budget(template_content)

        except Exception as exc:
            failure = self._sandbox_render_budget_failure(location, "worker_error", type(exc).__name__)
            if self._template_has_static_sandbox_probe_risk(template_content):
                return False, failure
            return True, failure

        if status == "security_error":
            return False, None
        if self._sandbox_probe_unavailable(status, detail):
            if self._template_has_static_sandbox_probe_risk(template_content):
                return False, self._sandbox_render_budget_failure(location, "worker_unavailable", detail)
            if self._template_has_static_render_budget_risk(template_content):
                return True, self._sandbox_render_budget_failure(location, "worker_unavailable", detail)
            return True, None
        if status in {"budget_exceeded", "timeout", "worker_error"}:
            failure = self._sandbox_render_budget_failure(location, status, detail)
            if self._template_has_static_sandbox_probe_risk(template_content):
                return False, failure
            return True, failure
        return True, None

    def _sandbox_probe_unavailable(self, status: str, detail: str | None) -> bool:
        if status == "worker_unavailable":
            return True
        if status != "worker_error" or not detail:
            return False
        return detail == "empty_result" or detail.startswith("exitcode=")

    def _template_has_static_render_budget_risk(self, template_content: str) -> bool:
        return self._template_ast_has_static_render_budget_risk(template_content)

    def _template_has_static_preflight_render_budget_risk(self, template_content: str) -> bool:
        parsed = self._parse_template_ast(template_content)
        if parsed is None:
            return False
        return (
            self._template_ast_has_static_range_list_budget_risk(parsed)
            or self._template_ast_has_static_range_join_budget_risk(parsed)
            or self._template_ast_has_static_repeated_sequence_budget_risk(parsed)
        )

    def _template_has_static_sandbox_risk(self, template_content: str) -> bool:
        return bool(
            re.search(r"\.\s*__\w+__", template_content)
            or re.search(r"\|\s*attr\s*\(\s*['\"]__\w+__", template_content)
            or re.search(r"\[\s*['\"]__\w+__['\"]\s*\]", template_content)
        )

    def _template_has_static_sandbox_probe_risk(self, template_content: str) -> bool:
        if self._template_has_static_sandbox_risk(template_content):
            return True

        parsed = self._parse_template_ast(template_content)
        if parsed is None:
            return False

        risky_public_attrs = {"mro", "func_code", "func_globals", "gi_frame", "cr_frame"}
        for node in parsed.find_all(jinja2.nodes.Getattr):
            attr = node.attr
            if attr.startswith("_") or attr in risky_public_attrs:
                return True

        for node in parsed.find_all(jinja2.nodes.Getitem):
            arg = node.arg
            if isinstance(arg, jinja2.nodes.Const) and isinstance(arg.value, str) and arg.value.startswith("_"):
                return True

        for node in parsed.find_all(jinja2.nodes.Filter):
            if node.name != "attr" or not node.args:
                continue
            attr_arg = node.args[0]
            if (
                isinstance(attr_arg, jinja2.nodes.Const)
                and isinstance(attr_arg.value, str)
                and (attr_arg.value.startswith("_") or attr_arg.value in risky_public_attrs)
            ):
                return True

        return False

    def _template_ast_has_static_render_budget_risk(self, template_content: str) -> bool:
        parsed = self._parse_template_ast(template_content)
        if parsed is None:
            return False

        if self._template_ast_has_oversized_sandbox_range_call(parsed):
            return True

        if self._template_ast_has_static_range_list_budget_risk(parsed):
            return True

        if self._template_ast_has_static_iterated_range_budget_risk(parsed):
            return True

        return self._template_ast_has_static_repeated_sequence_budget_risk(parsed)

    def _template_ast_has_static_repeated_sequence_budget_risk(self, parsed: Any) -> bool:
        for node in parsed.find_all(jinja2.nodes.Mul):
            projected_size = self._constant_repeated_sequence_size(node.left, node.right)
            if projected_size is not None and projected_size > self.sandbox_render_max_output_chars:
                return True

        return False

    def _template_ast_has_static_iterated_range_budget_risk(self, parsed: Any) -> bool:
        range_threshold = max(1, self.sandbox_render_max_output_chars)
        for node in parsed.find_all(jinja2.nodes.For):
            if self._range_iterable_exceeds_static_budget(node.iter, range_threshold):
                return True

        for node in parsed.find_all(jinja2.nodes.Filter):
            if node.name in _EAGER_RANGE_ITERATION_FILTERS and self._range_iterable_exceeds_static_budget(
                node.node,
                range_threshold,
            ):
                return True

        return False

    def _template_ast_has_oversized_sandbox_range_call(self, parsed: Any) -> bool:
        range_aliases = {"range"}
        int_bindings: dict[str, _StaticIntBinding] = {}
        namespace_range_attrs: dict[str, set[str]] = {}
        macro_bindings: dict[str, tuple[Any, ...]] = {}
        return self._static_node_has_oversized_sandbox_range_call(
            parsed,
            range_aliases,
            int_bindings,
            namespace_range_attrs,
            macro_bindings,
            set(),
        )

    def _static_node_has_oversized_sandbox_range_call(
        self,
        node: Any,
        range_aliases: set[str],
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
        macro_bindings: dict[str, tuple[Any, ...]],
        active_macros: set[int],
    ) -> bool:
        if isinstance(node, jinja2.nodes.Block):
            block_aliases = set(range_aliases)
            block_int_bindings = dict(int_bindings)
            block_namespace_attrs = self._clone_static_namespace_bindings(namespace_range_attrs)
            inherited_namespace_attrs = dict(block_namespace_attrs)
            block_macro_bindings = dict(macro_bindings)
            has_risk = any(
                self._static_node_has_oversized_sandbox_range_call(
                    child,
                    block_aliases,
                    block_int_bindings,
                    block_namespace_attrs,
                    block_macro_bindings,
                    active_macros,
                )
                for child in node.body
            )
            if not has_risk:
                self._propagate_static_namespace_mutations(
                    namespace_range_attrs,
                    block_namespace_attrs,
                    inherited_namespace_attrs,
                )
            return has_risk

        if isinstance(node, jinja2.nodes.FilterBlock):
            if self._static_node_has_oversized_sandbox_range_call(
                node.filter,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
                macro_bindings,
                active_macros,
            ):
                return True
            block_aliases = set(range_aliases)
            block_int_bindings = dict(int_bindings)
            block_namespace_attrs = self._clone_static_namespace_bindings(namespace_range_attrs)
            inherited_namespace_attrs = dict(block_namespace_attrs)
            block_macro_bindings = dict(macro_bindings)
            has_risk = any(
                self._static_node_has_oversized_sandbox_range_call(
                    child,
                    block_aliases,
                    block_int_bindings,
                    block_namespace_attrs,
                    block_macro_bindings,
                    active_macros,
                )
                for child in node.body
            )
            if not has_risk:
                self._propagate_static_namespace_mutations(
                    namespace_range_attrs,
                    block_namespace_attrs,
                    inherited_namespace_attrs,
                )
            return has_risk

        if isinstance(node, jinja2.nodes.Assign):
            if self._static_node_has_oversized_sandbox_range_call(
                node.node,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
                macro_bindings,
                active_macros,
            ):
                return True
            self._collect_static_range_assignment(
                node.target,
                node.node,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
            )
            self._collect_static_macro_assignment(node.target, node.node, macro_bindings)
            return False

        if isinstance(node, jinja2.nodes.AssignBlock):
            block_aliases = set(range_aliases)
            block_int_bindings = dict(int_bindings)
            block_namespace_attrs = self._clone_static_namespace_bindings(namespace_range_attrs)
            inherited_namespace_attrs = dict(block_namespace_attrs)
            block_macro_bindings = dict(macro_bindings)
            if any(
                self._static_node_has_oversized_sandbox_range_call(
                    child,
                    block_aliases,
                    block_int_bindings,
                    block_namespace_attrs,
                    block_macro_bindings,
                    active_macros,
                )
                for child in node.body
            ):
                return True
            self._propagate_static_namespace_mutations(
                namespace_range_attrs,
                block_namespace_attrs,
                inherited_namespace_attrs,
            )
            self._clear_static_range_binding(
                node.target,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
            )
            self._clear_static_macro_binding(node.target, macro_bindings)
            return False

        if isinstance(node, jinja2.nodes.Macro):
            macro_target = jinja2.nodes.Name(node.name, "store")
            self._clear_static_range_binding(
                macro_target,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
            )
            self._clear_static_macro_binding(macro_target, macro_bindings)
            macro_bindings[node.name] = (node,)
            return False

        if isinstance(node, jinja2.nodes.If):
            if self._static_node_has_oversized_sandbox_range_call(
                node.test,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
                macro_bindings,
                active_macros,
            ):
                return True
            condition = self._constant_condition_value(node.test)
            if condition is True:
                return any(
                    self._static_node_has_oversized_sandbox_range_call(
                        child,
                        range_aliases,
                        int_bindings,
                        namespace_range_attrs,
                        macro_bindings,
                        active_macros,
                    )
                    for child in node.body
                )

            possible_branches = [node.body] if condition is None else []
            can_reach_later_branch = True
            for elif_node in node.elif_:
                if self._static_node_has_oversized_sandbox_range_call(
                    elif_node.test,
                    range_aliases,
                    int_bindings,
                    namespace_range_attrs,
                    macro_bindings,
                    active_macros,
                ):
                    return True
                elif_condition = self._constant_condition_value(elif_node.test)
                if can_reach_later_branch and elif_condition is not False:
                    possible_branches.append(elif_node.body)
                if elif_condition is True:
                    can_reach_later_branch = False
                    break
            if can_reach_later_branch:
                possible_branches.append(node.else_)

            branch_states: list[
                tuple[
                    set[str],
                    dict[str, _StaticIntBinding],
                    dict[str, set[str]],
                    dict[str, tuple[Any, ...]],
                ]
            ] = []
            for branch in possible_branches:
                branch_aliases = set(range_aliases)
                branch_int_bindings = dict(int_bindings)
                branch_namespace_attrs = self._clone_static_namespace_bindings(namespace_range_attrs)
                branch_macro_bindings = dict(macro_bindings)
                for child in branch:
                    if self._static_node_has_oversized_sandbox_range_call(
                        child,
                        branch_aliases,
                        branch_int_bindings,
                        branch_namespace_attrs,
                        branch_macro_bindings,
                        active_macros,
                    ):
                        return True
                branch_states.append(
                    (
                        branch_aliases,
                        branch_int_bindings,
                        branch_namespace_attrs,
                        branch_macro_bindings,
                    )
                )
            self._merge_static_branch_bindings(
                branch_states,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
                macro_bindings,
            )
            return False

        if isinstance(node, jinja2.nodes.CondExpr):
            if self._static_node_has_oversized_sandbox_range_call(
                node.test,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
                macro_bindings,
                active_macros,
            ):
                return True
            condition = self._constant_condition_value(node.test)
            if condition is not None:
                selected_expression = node.expr1 if condition else node.expr2
                return selected_expression is not None and self._static_node_has_oversized_sandbox_range_call(
                    selected_expression,
                    range_aliases,
                    int_bindings,
                    namespace_range_attrs,
                    macro_bindings,
                    active_macros,
                )
            return any(
                branch is not None
                and self._static_node_has_oversized_sandbox_range_call(
                    branch,
                    range_aliases,
                    int_bindings,
                    namespace_range_attrs,
                    macro_bindings,
                    active_macros,
                )
                for branch in (node.expr1, node.expr2)
            )

        if isinstance(node, jinja2.nodes.For):
            if self._static_range_iterable_exceeds_budget(
                node.iter,
                max(1, self.sandbox_render_max_output_chars),
                range_aliases,
                int_bindings,
                namespace_range_attrs,
            ):
                return True
            if self._static_node_has_oversized_sandbox_range_call(
                node.iter,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
                macro_bindings,
                active_macros,
            ):
                return True

            if node.test is not None and self._constant_condition_value(node.test) is False:
                return any(
                    self._static_node_has_oversized_sandbox_range_call(
                        child,
                        range_aliases,
                        int_bindings,
                        namespace_range_attrs,
                        macro_bindings,
                        active_macros,
                    )
                    for child in node.else_
                )

            literal_items = node.iter.items if isinstance(node.iter, jinja2.nodes.List | jinja2.nodes.Tuple) else None
            iteration_count: int | None = len(literal_items) if literal_items is not None else None
            range_call = self._static_iterable_range_call(node.iter, range_aliases, namespace_range_attrs)
            if range_call is not None:
                iteration_count = self._constant_range_iteration_count_with_bindings(
                    range_call.args,
                    _SANDBOX_MAX_RANGE_ITERATIONS,
                    int_bindings,
                )
            if iteration_count == 0:
                return any(
                    self._static_node_has_oversized_sandbox_range_call(
                        child,
                        range_aliases,
                        int_bindings,
                        namespace_range_attrs,
                        macro_bindings,
                        active_macros,
                    )
                    for child in node.else_
                )

            outer_namespace_names = set(namespace_range_attrs)
            if literal_items is not None:
                loop_namespace_attrs = self._clone_static_namespace_bindings(namespace_range_attrs)
                definitely_iterates = False
                for item in literal_items:
                    item_aliases = set(range_aliases)
                    item_int_bindings = dict(int_bindings)
                    item_namespace_attrs = self._clone_static_namespace_bindings(loop_namespace_attrs)
                    item_macro_bindings = dict(macro_bindings)
                    self._clear_static_range_binding(
                        node.target,
                        item_aliases,
                        item_int_bindings,
                        item_namespace_attrs,
                    )
                    self._clear_static_macro_binding(node.target, item_macro_bindings)
                    self._collect_static_range_assignment(
                        node.target,
                        item,
                        item_aliases,
                        item_int_bindings,
                        item_namespace_attrs,
                    )
                    self._collect_static_macro_assignment(node.target, item, item_macro_bindings)

                    test_condition: bool | None = True
                    if node.test is not None:
                        if self._static_node_has_oversized_sandbox_range_call(
                            node.test,
                            item_aliases,
                            item_int_bindings,
                            item_namespace_attrs,
                            item_macro_bindings,
                            active_macros,
                        ):
                            return True
                        test_condition = self._constant_condition_value(node.test)
                    if test_condition is False:
                        continue

                    executed_namespace_attrs = self._clone_static_namespace_bindings(item_namespace_attrs)
                    if any(
                        self._static_node_has_oversized_sandbox_range_call(
                            child,
                            item_aliases,
                            item_int_bindings,
                            executed_namespace_attrs,
                            item_macro_bindings,
                            active_macros,
                        )
                        for child in node.body
                    ):
                        return True

                    if test_condition is True:
                        definitely_iterates = True
                        loop_namespace_attrs = executed_namespace_attrs
                    else:
                        for name, attrs in executed_namespace_attrs.items():
                            loop_namespace_attrs.setdefault(name, set()).update(attrs)

                for name in outer_namespace_names:
                    namespace_range_attrs[name] = set(loop_namespace_attrs.get(name, set()))

                if definitely_iterates:
                    return False
                return any(
                    self._static_node_has_oversized_sandbox_range_call(
                        child,
                        range_aliases,
                        int_bindings,
                        namespace_range_attrs,
                        macro_bindings,
                        active_macros,
                    )
                    for child in node.else_
                )

            loop_aliases = set(range_aliases)
            loop_int_bindings = dict(int_bindings)
            loop_namespace_attrs = self._clone_static_namespace_bindings(namespace_range_attrs)
            loop_macro_bindings = dict(macro_bindings)
            self._clear_static_range_binding(
                node.target,
                loop_aliases,
                loop_int_bindings,
                loop_namespace_attrs,
            )
            self._clear_static_macro_binding(node.target, loop_macro_bindings)
            if node.test is not None and self._static_node_has_oversized_sandbox_range_call(
                node.test,
                loop_aliases,
                loop_int_bindings,
                loop_namespace_attrs,
                loop_macro_bindings,
                active_macros,
            ):
                return True
            if any(
                self._static_node_has_oversized_sandbox_range_call(
                    child,
                    loop_aliases,
                    loop_int_bindings,
                    loop_namespace_attrs,
                    loop_macro_bindings,
                    active_macros,
                )
                for child in node.body
            ):
                return True

            loop_definitely_executes = (
                iteration_count is not None
                and iteration_count > 0
                and (node.test is None or self._constant_condition_value(node.test) is True)
            )
            for name in outer_namespace_names:
                loop_attrs = loop_namespace_attrs.get(name, set())
                if loop_definitely_executes:
                    namespace_range_attrs[name] = set(loop_attrs)
                else:
                    namespace_range_attrs[name].update(loop_attrs)

            if loop_definitely_executes:
                return False
            return any(
                self._static_node_has_oversized_sandbox_range_call(
                    child,
                    range_aliases,
                    int_bindings,
                    namespace_range_attrs,
                    macro_bindings,
                    active_macros,
                )
                for child in node.else_
            )

        if isinstance(node, jinja2.nodes.With):
            for value in node.values:
                if self._static_node_has_oversized_sandbox_range_call(
                    value,
                    range_aliases,
                    int_bindings,
                    namespace_range_attrs,
                    macro_bindings,
                    active_macros,
                ):
                    return True
            with_aliases = set(range_aliases)
            with_int_bindings = dict(int_bindings)
            with_namespace_attrs = self._clone_static_namespace_bindings(namespace_range_attrs)
            inherited_namespace_attrs = dict(with_namespace_attrs)
            with_macro_bindings = dict(macro_bindings)
            for target, value in zip(node.targets, node.values, strict=False):
                self._collect_static_range_assignment(
                    target,
                    value,
                    with_aliases,
                    with_int_bindings,
                    with_namespace_attrs,
                )
                self._collect_static_macro_assignment(target, value, with_macro_bindings)
            has_risk = any(
                self._static_node_has_oversized_sandbox_range_call(
                    child,
                    with_aliases,
                    with_int_bindings,
                    with_namespace_attrs,
                    with_macro_bindings,
                    active_macros,
                )
                for child in node.body
            )
            if not has_risk:
                self._propagate_static_namespace_mutations(
                    namespace_range_attrs,
                    with_namespace_attrs,
                    inherited_namespace_attrs,
                )
            return has_risk

        if (
            isinstance(node, jinja2.nodes.Filter)
            and node.name in _EAGER_RANGE_ITERATION_FILTERS
            and self._static_range_filter_exceeds_budget(
                node,
                max(1, self.sandbox_render_max_output_chars),
                range_aliases,
                int_bindings,
                namespace_range_attrs,
            )
        ):
            return True

        if isinstance(node, jinja2.nodes.CallBlock):
            caller_macro = jinja2.nodes.Macro("caller", node.args, node.defaults, node.body)
            call_macro_bindings = dict(macro_bindings)
            call_macro_bindings["caller"] = (caller_macro,)
            macros = self._static_macro_binding_for_node(node.call.node, call_macro_bindings)
            if self._static_node_has_oversized_sandbox_range_call(
                node.call,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
                call_macro_bindings,
                active_macros,
            ):
                return True
            if macros:
                return False
            return any(
                self._static_node_has_oversized_sandbox_range_call(
                    child,
                    range_aliases,
                    int_bindings,
                    namespace_range_attrs,
                    macro_bindings,
                    active_macros,
                )
                for child in node.body
            )

        if isinstance(node, jinja2.nodes.Call) and self._static_macro_call_has_oversized_sandbox_range_call(
            node,
            range_aliases,
            int_bindings,
            namespace_range_attrs,
            macro_bindings,
            active_macros,
        ):
            return True

        normalized_range_call = self._range_call_with_literal_unpacking(node)
        if normalized_range_call is not None and self._is_static_range_callable(
            normalized_range_call.node,
            range_aliases,
            namespace_range_attrs,
        ):
            count = self._constant_range_iteration_count_with_bindings(
                normalized_range_call.args,
                _SANDBOX_MAX_RANGE_ITERATIONS,
                int_bindings,
            )
            if count is not None and count > _SANDBOX_MAX_RANGE_ITERATIONS:
                return True

        return any(
            self._static_node_has_oversized_sandbox_range_call(
                child,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
                macro_bindings,
                active_macros,
            )
            for child in node.iter_child_nodes()
        )

    def _static_macro_call_has_oversized_sandbox_range_call(
        self,
        node: Any,
        range_aliases: set[str],
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
        macro_bindings: dict[str, tuple[Any, ...]],
        active_macros: set[int],
    ) -> bool:
        macros = self._static_macro_binding_for_node(node.node, macro_bindings)
        return any(
            id(macro) not in active_macros
            and self._static_single_macro_call_has_oversized_sandbox_range_call(
                node,
                macro,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
                macro_bindings,
                active_macros,
            )
            for macro in macros
        )

    def _static_single_macro_call_has_oversized_sandbox_range_call(
        self,
        node: Any,
        macro: Any,
        range_aliases: set[str],
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
        macro_bindings: dict[str, tuple[Any, ...]],
        active_macros: set[int],
    ) -> bool:
        normalized_arguments = self._static_macro_call_arguments(node)
        if normalized_arguments is None:
            return False
        positional_arguments, keyword_arguments = normalized_arguments
        accepts_varargs = self._static_macro_uses_special_argument(macro, "varargs")
        accepts_kwargs = self._static_macro_uses_special_argument(macro, "kwargs")
        if len(positional_arguments) > len(macro.args) and not accepts_varargs:
            return False
        argument_names = {argument.name for argument in macro.args}
        positional_names = {argument.name for argument in macro.args[: len(positional_arguments)]}
        keyword_names: set[str] = set()
        for keyword_name, _ in keyword_arguments:
            if keyword_name in positional_names or keyword_name in keyword_names:
                return False
            if keyword_name not in argument_names and not accepts_kwargs:
                return False
            keyword_names.add(keyword_name)

        macro_aliases = set(range_aliases)
        macro_int_bindings = dict(int_bindings)
        macro_namespace_attrs = self._clone_static_namespace_bindings(namespace_range_attrs)
        nested_macro_bindings = dict(macro_bindings)
        for argument in macro.args:
            self._clear_static_range_binding(
                argument,
                macro_aliases,
                macro_int_bindings,
                macro_namespace_attrs,
            )
            self._clear_static_macro_binding(argument, nested_macro_bindings)

        supplied_arguments = {
            argument.name: value for argument, value in zip(macro.args, positional_arguments, strict=False)
        }
        supplied_arguments.update(dict(keyword_arguments))
        namespace_argument_sources: dict[str, str] = {}
        default_offset = len(macro.args) - len(macro.defaults)
        for index, argument in enumerate(macro.args):
            value = supplied_arguments.get(argument.name)
            uses_default = False
            if value is None and index >= default_offset:
                value = macro.defaults[index - default_offset]
                uses_default = True
            if value is None:
                continue
            if isinstance(value, jinja2.nodes.Name) and value.name in namespace_range_attrs:
                namespace_argument_sources[argument.name] = value.name
            if uses_default and self._static_node_has_oversized_sandbox_range_call(
                value,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
                macro_bindings,
                active_macros,
            ):
                return True
            self._bind_static_macro_argument(
                argument,
                value,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
                macro_bindings,
                macro_aliases,
                macro_int_bindings,
                macro_namespace_attrs,
                nested_macro_bindings,
            )

        if accepts_kwargs:
            kwargs_range_attrs = {
                keyword_name
                for keyword_name, keyword_value in keyword_arguments
                if keyword_name not in argument_names
                and self._is_static_range_callable(keyword_value, range_aliases, namespace_range_attrs)
            }
            if kwargs_range_attrs:
                macro_namespace_attrs["kwargs"] = kwargs_range_attrs
            else:
                macro_namespace_attrs.pop("kwargs", None)
            for keyword_name, keyword_value in keyword_arguments:
                if keyword_name in argument_names:
                    continue
                keyword_macros = self._static_macro_binding_for_node(keyword_value, macro_bindings)
                if keyword_macros:
                    nested_macro_bindings[f"kwargs.{keyword_name}"] = keyword_macros

        if accepts_varargs:
            extra_arguments = positional_arguments[len(macro.args) :]
            varargs_range_attrs = {
                str(index)
                for index, value in enumerate(extra_arguments)
                if self._is_static_range_callable(value, range_aliases, namespace_range_attrs)
            }
            if varargs_range_attrs:
                macro_namespace_attrs["varargs"] = varargs_range_attrs
            else:
                macro_namespace_attrs.pop("varargs", None)
            for index, value in enumerate(extra_arguments):
                vararg_macros = self._static_macro_binding_for_node(value, macro_bindings)
                if vararg_macros:
                    nested_macro_bindings[f"varargs.{index}"] = vararg_macros

        nested_active_macros = {*active_macros, id(macro)}
        has_risk = any(
            self._static_node_has_oversized_sandbox_range_call(
                child,
                macro_aliases,
                macro_int_bindings,
                macro_namespace_attrs,
                nested_macro_bindings,
                nested_active_macros,
            )
            for child in macro.body
        )
        if has_risk:
            return True
        for argument_name, source_name in namespace_argument_sources.items():
            argument_attrs = macro_namespace_attrs.get(argument_name)
            source_attrs = namespace_range_attrs.get(source_name)
            if argument_attrs is None or source_attrs is None:
                continue
            if argument_attrs is source_attrs:
                continue
            source_attrs.clear()
            source_attrs.update(argument_attrs)
        return False

    @staticmethod
    def _static_macro_call_arguments(node: Any) -> tuple[list[Any], list[tuple[str, Any]]] | None:
        positional_arguments = list(node.args)
        if node.dyn_args is not None:
            if not isinstance(node.dyn_args, jinja2.nodes.List | jinja2.nodes.Tuple):
                return None
            positional_arguments.extend(node.dyn_args.items)

        keyword_arguments = [(keyword.key, keyword.value) for keyword in node.kwargs]
        if node.dyn_kwargs is not None:
            if not isinstance(node.dyn_kwargs, jinja2.nodes.Dict):
                return None
            for pair in node.dyn_kwargs.items:
                if not isinstance(pair.key, jinja2.nodes.Const) or not isinstance(pair.key.value, str):
                    return None
                keyword_arguments.append((pair.key.value, pair.value))
        return positional_arguments, keyword_arguments

    def _bind_static_macro_argument(
        self,
        target: Any,
        value: Any,
        source_aliases: set[str],
        source_int_bindings: dict[str, _StaticIntBinding],
        source_namespace_attrs: dict[str, set[str]],
        source_macro_bindings: dict[str, tuple[Any, ...]],
        range_aliases: set[str],
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
        macro_bindings: dict[str, tuple[Any, ...]],
    ) -> None:
        if not isinstance(target, jinja2.nodes.Name):
            return
        if self._is_static_range_callable(value, source_aliases, source_namespace_attrs):
            range_aliases.add(target.name)
        int_results = self._constant_int_expression_results_with_bindings(
            value,
            _SANDBOX_MAX_RANGE_ITERATIONS,
            source_int_bindings,
        )
        int_binding = self._make_static_int_binding(int_results)
        if int_binding is not None:
            int_bindings[target.name] = int_binding
        if isinstance(value, jinja2.nodes.Name):
            if value.name in source_namespace_attrs:
                namespace_range_attrs[target.name] = source_namespace_attrs[value.name]
            source_prefix = f"{value.name}."
            target_prefix = f"{target.name}."
            for name, namespace_macro in source_macro_bindings.items():
                if name.startswith(source_prefix):
                    macro_bindings[f"{target_prefix}{name.removeprefix(source_prefix)}"] = namespace_macro
        source_macros = self._static_macro_binding_for_node(value, source_macro_bindings)
        if source_macros:
            macro_bindings[target.name] = source_macros

    @classmethod
    def _clear_static_macro_binding(cls, target: Any, macro_bindings: dict[str, tuple[Any, ...]]) -> None:
        if isinstance(target, jinja2.nodes.Tuple):
            for item in target.items:
                cls._clear_static_macro_binding(item, macro_bindings)
        elif isinstance(target, jinja2.nodes.NSRef):
            macro_bindings.pop(f"{target.name}.{target.attr}", None)
        elif isinstance(target, jinja2.nodes.Name):
            macro_bindings.pop(target.name, None)
            prefix = f"{target.name}."
            for name in [name for name in macro_bindings if name.startswith(prefix)]:
                macro_bindings.pop(name, None)

    @classmethod
    def _static_macro_binding_key(cls, node: Any) -> str | None:
        if isinstance(node, jinja2.nodes.Name):
            return node.name
        if isinstance(node, jinja2.nodes.Getattr) and isinstance(node.node, jinja2.nodes.Name):
            return f"{node.node.name}.{node.attr}"
        if (
            isinstance(node, jinja2.nodes.Getitem)
            and isinstance(node.node, jinja2.nodes.Name)
            and isinstance(node.arg, jinja2.nodes.Const)
            and isinstance(node.arg.value, str | int)
        ):
            return f"{node.node.name}.{node.arg.value}"
        return None

    @classmethod
    def _static_macro_binding_for_node(
        cls,
        node: Any,
        macro_bindings: dict[str, tuple[Any, ...]],
    ) -> tuple[Any, ...]:
        if isinstance(node, jinja2.nodes.CondExpr):
            condition = cls._constant_condition_value(node.test)
            if condition is not None:
                branch = node.expr1 if condition else node.expr2
                return cls._static_macro_binding_for_node(branch, macro_bindings) if branch is not None else ()
            candidates: list[Any] = []
            candidate_ids: set[int] = set()
            for branch in (node.expr1, node.expr2):
                if branch is None:
                    continue
                for macro in cls._static_macro_binding_for_node(branch, macro_bindings):
                    if id(macro) in candidate_ids:
                        continue
                    candidate_ids.add(id(macro))
                    candidates.append(macro)
            return tuple(candidates)
        key = cls._static_macro_binding_key(node)
        return macro_bindings.get(key, ()) if key is not None else ()

    @staticmethod
    def _static_macro_uses_special_argument(macro: Any, name: str) -> bool:
        return any(
            candidate.name == name and candidate.ctx == "load"
            for child in macro.body
            for candidate in child.find_all(jinja2.nodes.Name)
        )

    @classmethod
    def _collect_static_macro_assignment(
        cls,
        target: Any,
        value: Any,
        macro_bindings: dict[str, tuple[Any, ...]],
    ) -> None:
        if isinstance(target, jinja2.nodes.Tuple) and isinstance(value, jinja2.nodes.Tuple):
            if len(target.items) != len(value.items):
                cls._clear_static_macro_binding(target, macro_bindings)
                return
            original_bindings = dict(macro_bindings)
            cls._clear_static_macro_binding(target, macro_bindings)
            for item_target, item_value in zip(target.items, value.items, strict=False):
                if not isinstance(item_target, jinja2.nodes.Name):
                    continue
                source_macros = cls._static_macro_binding_for_node(item_value, original_bindings)
                if source_macros:
                    macro_bindings[item_target.name] = source_macros
            return
        original_bindings = dict(macro_bindings)
        source_macros = cls._static_macro_binding_for_node(value, original_bindings)
        cls._clear_static_macro_binding(target, macro_bindings)
        if isinstance(target, jinja2.nodes.NSRef):
            if source_macros:
                macro_bindings[f"{target.name}.{target.attr}"] = source_macros
            return
        if isinstance(target, jinja2.nodes.Name) and source_macros:
            macro_bindings[target.name] = source_macros
        if not isinstance(target, jinja2.nodes.Name):
            return
        if (
            isinstance(value, jinja2.nodes.Call)
            and isinstance(value.node, jinja2.nodes.Name)
            and value.node.name == "namespace"
        ):
            for keyword in value.kwargs:
                keyword_macros = cls._static_macro_binding_for_node(keyword.value, original_bindings)
                if keyword_macros:
                    macro_bindings[f"{target.name}.{keyword.key}"] = keyword_macros
        elif isinstance(value, jinja2.nodes.Name):
            source_prefix = f"{value.name}."
            target_prefix = f"{target.name}."
            for name, namespace_macro in original_bindings.items():
                if name.startswith(source_prefix):
                    macro_bindings[f"{target_prefix}{name.removeprefix(source_prefix)}"] = namespace_macro

    @staticmethod
    def _merge_static_branch_bindings(
        branch_states: list[
            tuple[
                set[str],
                dict[str, _StaticIntBinding],
                dict[str, set[str]],
                dict[str, tuple[Any, ...]],
            ]
        ],
        range_aliases: set[str],
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
        macro_bindings: dict[str, tuple[Any, ...]],
    ) -> None:
        range_aliases.clear()
        range_aliases.update(*(aliases for aliases, _, _, _ in branch_states))

        int_bindings.clear()
        int_names = {name for _, int_state_bindings, _, _ in branch_states for name in int_state_bindings}
        for name in int_names:
            candidates: list[_StaticIntResult] = []
            for _, int_state_bindings, _, _ in branch_states:
                binding = int_state_bindings.get(name)
                if isinstance(binding, _StaticIntCandidates):
                    candidates.extend(binding.values)
                elif binding is not None:
                    candidates.append(binding)
            merged_binding = Jinja2TemplateScanner._make_static_int_binding(candidates)
            if merged_binding is not None:
                int_bindings[name] = merged_binding

        namespace_range_attrs.clear()
        for _, _, attrs_by_name, _ in branch_states:
            for name, attrs in attrs_by_name.items():
                namespace_range_attrs.setdefault(name, set()).update(attrs)

        macro_bindings.clear()
        macro_names = {name for _, _, _, macro_state_bindings in branch_states for name in macro_state_bindings}
        for name in macro_names:
            macro_candidates: list[Any] = []
            candidate_ids: set[int] = set()
            for _, _, _, macro_state_bindings in branch_states:
                for macro in macro_state_bindings.get(name, ()):
                    if id(macro) in candidate_ids:
                        continue
                    candidate_ids.add(id(macro))
                    macro_candidates.append(macro)
            if macro_candidates:
                macro_bindings[name] = tuple(macro_candidates)

    def _static_range_iterable_exceeds_budget(
        self,
        node: Any,
        threshold: int,
        range_aliases: set[str],
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
    ) -> bool:
        range_call = self._static_iterable_range_call(node, range_aliases, namespace_range_attrs)
        if range_call is None:
            return False
        count = self._constant_range_iteration_count_with_bindings(range_call.args, threshold, int_bindings)
        return count is not None and count >= threshold

    def _static_range_filter_exceeds_budget(
        self,
        node: Any,
        threshold: int,
        range_aliases: set[str],
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
    ) -> bool:
        range_call = self._static_iterable_range_call(node.node, range_aliases, namespace_range_attrs)
        if range_call is None:
            return False
        if node.name == "list":
            projected_size = self._constant_range_rendered_list_size_with_bindings(
                range_call.args,
                threshold,
                int_bindings,
            )
            return projected_size is not None and projected_size > threshold
        if node.name == "join":
            projected_size = self._constant_range_joined_size_with_bindings(
                range_call.args,
                node.args,
                threshold,
                int_bindings,
            )
            return projected_size is not None and projected_size > threshold
        count = self._constant_range_iteration_count_with_bindings(range_call.args, threshold, int_bindings)
        return count is not None and count >= threshold

    def _static_iterable_range_call(
        self,
        node: Any,
        range_aliases: set[str],
        namespace_range_attrs: dict[str, set[str]],
    ) -> Any | None:
        while isinstance(node, jinja2.nodes.Filter) and node.name in _LAZY_RANGE_ITERATION_FILTERS:
            node = node.node
        normalized_range_call = self._range_call_with_literal_unpacking(node)
        if normalized_range_call is not None and self._is_static_range_callable(
            normalized_range_call.node,
            range_aliases,
            namespace_range_attrs,
        ):
            return normalized_range_call
        return None

    @staticmethod
    def _range_call_with_literal_unpacking(node: Any) -> Any | None:
        if not isinstance(node, jinja2.nodes.Call) or node.kwargs or node.dyn_kwargs is not None:
            return None
        arguments = list(node.args)
        if node.dyn_args is not None:
            if not isinstance(node.dyn_args, jinja2.nodes.List | jinja2.nodes.Tuple):
                return None
            arguments.extend(node.dyn_args.items)
        if not 1 <= len(arguments) <= 3:
            return None
        if node.dyn_args is None:
            return node
        return jinja2.nodes.Call(node.node, arguments, [], None, None)

    def _clear_static_range_binding(
        self,
        target: Any,
        range_aliases: set[str],
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
    ) -> None:
        if isinstance(target, jinja2.nodes.Tuple):
            for item in target.items:
                self._clear_static_range_binding(item, range_aliases, int_bindings, namespace_range_attrs)
            return
        if isinstance(target, jinja2.nodes.NSRef):
            attrs = namespace_range_attrs.get(target.name)
            if attrs is not None:
                attrs.discard(target.attr)
            return
        if not isinstance(target, jinja2.nodes.Name):
            return
        range_aliases.discard(target.name)
        int_bindings.pop(target.name, None)
        namespace_range_attrs.pop(target.name, None)

    @staticmethod
    def _clone_static_namespace_bindings(
        namespace_range_attrs: dict[str, set[str]],
    ) -> dict[str, set[str]]:
        cloned_sets: dict[int, set[str]] = {}
        cloned_bindings: dict[str, set[str]] = {}
        for name, attrs in namespace_range_attrs.items():
            cloned_bindings[name] = cloned_sets.setdefault(id(attrs), set(attrs))
        return cloned_bindings

    @staticmethod
    def _propagate_static_namespace_mutations(
        namespace_range_attrs: dict[str, set[str]],
        scoped_namespace_attrs: dict[str, set[str]],
        inherited_namespace_attrs: dict[str, set[str]],
    ) -> None:
        propagated_ids: set[int] = set()
        for name, outer_attrs in namespace_range_attrs.items():
            inherited_attrs = inherited_namespace_attrs.get(name)
            if inherited_attrs is None or scoped_namespace_attrs.get(name) is not inherited_attrs:
                continue
            if id(outer_attrs) in propagated_ids:
                continue
            propagated_ids.add(id(outer_attrs))
            outer_attrs.clear()
            outer_attrs.update(inherited_attrs)

    def _collect_static_range_assignment(
        self,
        target: Any,
        value: Any,
        range_aliases: set[str],
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
    ) -> bool:
        if isinstance(target, jinja2.nodes.Tuple) and isinstance(value, jinja2.nodes.Tuple):
            if len(target.items) != len(value.items):
                self._clear_static_range_binding(target, range_aliases, int_bindings, namespace_range_attrs)
                return False
            original_aliases = set(range_aliases)
            original_int_bindings = dict(int_bindings)
            original_namespace_attrs = self._clone_static_namespace_bindings(namespace_range_attrs)
            evaluated_bindings: list[
                tuple[
                    Any,
                    set[str],
                    dict[str, _StaticIntBinding],
                    dict[str, set[str]],
                ]
            ] = []
            for item_target, item_value in zip(target.items, value.items, strict=False):
                item_aliases = set(original_aliases)
                item_int_bindings = dict(original_int_bindings)
                item_namespace_attrs = self._clone_static_namespace_bindings(original_namespace_attrs)
                self._collect_static_range_assignment(
                    item_target,
                    item_value,
                    item_aliases,
                    item_int_bindings,
                    item_namespace_attrs,
                )
                evaluated_bindings.append((item_target, item_aliases, item_int_bindings, item_namespace_attrs))
            self._clear_static_range_binding(target, range_aliases, int_bindings, namespace_range_attrs)
            for item_target, item_aliases, item_int_bindings, item_namespace_attrs in evaluated_bindings:
                self._copy_static_target_binding(
                    item_target,
                    item_aliases,
                    item_int_bindings,
                    item_namespace_attrs,
                    range_aliases,
                    int_bindings,
                    namespace_range_attrs,
                )
            return True
        if isinstance(target, jinja2.nodes.NSRef):
            attrs = namespace_range_attrs.get(target.name)
            if attrs is None:
                return False
            if self._is_static_range_callable(value, range_aliases, namespace_range_attrs):
                previous_size = len(attrs)
                attrs.add(target.attr)
                return len(attrs) != previous_size
            attrs.discard(target.attr)
            return True
        if not isinstance(target, jinja2.nodes.Name):
            return False

        changed = False
        if self._is_static_range_callable(value, range_aliases, namespace_range_attrs):
            previous_size = len(range_aliases)
            range_aliases.add(target.name)
            changed |= len(range_aliases) != previous_size
        else:
            range_aliases.discard(target.name)

        int_results = self._constant_int_expression_results_with_bindings(
            value,
            _SANDBOX_MAX_RANGE_ITERATIONS,
            int_bindings,
        )
        int_binding = self._make_static_int_binding(int_results)
        if int_binding is not None and int_bindings.get(target.name) != int_binding:
            int_bindings[target.name] = int_binding
            changed = True
        elif int_binding is None:
            int_bindings.pop(target.name, None)

        if (
            isinstance(value, jinja2.nodes.Call)
            and isinstance(value.node, jinja2.nodes.Name)
            and value.node.name == "namespace"
        ):
            attrs = {
                keyword.key
                for keyword in value.kwargs
                if self._is_static_range_callable(keyword.value, range_aliases, namespace_range_attrs)
            }
            if namespace_range_attrs.get(target.name) != attrs:
                namespace_range_attrs[target.name] = attrs
                changed = True
        elif isinstance(value, jinja2.nodes.Name) and value.name in namespace_range_attrs:
            attrs = namespace_range_attrs[value.name]
            if namespace_range_attrs.get(target.name) is not attrs:
                namespace_range_attrs[target.name] = attrs
                changed = True
        else:
            namespace_range_attrs.pop(target.name, None)

        return changed

    def _copy_static_target_binding(
        self,
        target: Any,
        source_aliases: set[str],
        source_int_bindings: dict[str, _StaticIntBinding],
        source_namespace_attrs: dict[str, set[str]],
        range_aliases: set[str],
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
    ) -> None:
        if isinstance(target, jinja2.nodes.Tuple):
            for item in target.items:
                self._copy_static_target_binding(
                    item,
                    source_aliases,
                    source_int_bindings,
                    source_namespace_attrs,
                    range_aliases,
                    int_bindings,
                    namespace_range_attrs,
                )
            return
        if isinstance(target, jinja2.nodes.NSRef):
            if target.attr in source_namespace_attrs.get(target.name, set()):
                namespace_range_attrs.setdefault(target.name, set()).add(target.attr)
            return
        if not isinstance(target, jinja2.nodes.Name):
            return
        if target.name in source_aliases:
            range_aliases.add(target.name)
        if target.name in source_int_bindings:
            int_bindings[target.name] = source_int_bindings[target.name]
        if target.name in source_namespace_attrs:
            namespace_range_attrs[target.name] = set(source_namespace_attrs[target.name])

    @classmethod
    def _is_static_range_callable(
        cls,
        node: Any,
        range_aliases: set[str],
        namespace_range_attrs: dict[str, set[str]],
    ) -> bool:
        if isinstance(node, jinja2.nodes.Name):
            return node.name in range_aliases
        if isinstance(node, jinja2.nodes.CondExpr):
            condition = cls._constant_condition_value(node.test)
            branches = (node.expr1, node.expr2) if condition is None else (node.expr1 if condition else node.expr2,)
            return any(
                branch is not None and cls._is_static_range_callable(branch, range_aliases, namespace_range_attrs)
                for branch in branches
            )
        if (
            isinstance(node, jinja2.nodes.Getitem)
            and isinstance(node.node, jinja2.nodes.Name)
            and isinstance(node.arg, jinja2.nodes.Const)
            and isinstance(node.arg.value, str | int)
        ):
            return str(node.arg.value) in namespace_range_attrs.get(node.node.name, set())
        return bool(
            isinstance(node, jinja2.nodes.Getattr)
            and isinstance(node.node, jinja2.nodes.Name)
            and node.attr in namespace_range_attrs.get(node.node.name, set())
        )

    def _constant_int_expression_results_with_bindings(
        self,
        node: Any,
        cap: int,
        int_bindings: dict[str, _StaticIntBinding],
    ) -> list[_StaticIntResult]:
        variants, truncated = self._static_int_binding_variants(int_bindings, [node])
        if truncated:
            return [
                self._saturated_constant_int_result(cap),
                self._saturated_constant_int_result(cap, -1),
                self._constant_int_result(0, cap),
                self._constant_int_result(1, cap),
                self._constant_int_result(-1, cap),
            ]
        results: list[_StaticIntResult] = []
        for variant in variants:
            result = self._constant_int_expression_result(node, cap, variant)
            if result is not None and result not in results:
                results.append(result)
        return results

    @staticmethod
    def _make_static_int_binding(results: list[_StaticIntResult]) -> _StaticIntBinding | None:
        unique_results = list(dict.fromkeys(results))
        if not unique_results:
            return None
        if len(unique_results) == 1:
            return unique_results[0]
        if len(unique_results) > 8:
            selected: list[_StaticIntResult] = []
            for candidate in (
                min(unique_results, key=lambda result: result[0]),
                max(unique_results, key=lambda result: result[0]),
                min(unique_results, key=lambda result: abs(result[0])),
                max(unique_results, key=lambda result: abs(result[0])),
            ):
                if candidate not in selected:
                    selected.append(candidate)
            for sign in (-1, 1):
                signed = [result for result in unique_results if (result[0] < 0) == (sign < 0) and result[0] != 0]
                if signed:
                    candidate = min(signed, key=lambda result: abs(result[0]))
                    if candidate not in selected:
                        selected.append(candidate)
            unique_results = selected
        return _StaticIntCandidates(tuple(unique_results))

    @staticmethod
    def _static_int_binding_variants(
        int_bindings: dict[str, _StaticIntBinding],
        nodes: list[Any],
    ) -> tuple[list[dict[str, _StaticIntBinding]], bool]:
        referenced_names: set[str] = set()
        for node in nodes:
            if isinstance(node, jinja2.nodes.Name):
                referenced_names.add(node.name)
            referenced_names.update(candidate.name for candidate in node.find_all(jinja2.nodes.Name))

        variants: list[dict[str, _StaticIntBinding]] = [
            {name: binding for name, binding in int_bindings.items() if not isinstance(binding, _StaticIntCandidates)}
        ]
        for name, binding in int_bindings.items():
            if name not in referenced_names or not isinstance(binding, _StaticIntCandidates):
                continue
            if len(variants) * len(binding.values) > 4096:
                return variants, True
            variants = [{**variant, name: value} for variant in variants for value in binding.values]
        return variants, False

    def _constant_range_iteration_count_with_bindings(
        self,
        args: list[Any],
        cap: int,
        int_bindings: dict[str, _StaticIntBinding],
    ) -> int | None:
        range_values_candidates, truncated = self._constant_range_values_for_binding_variants(
            args,
            cap,
            int_bindings,
        )
        if truncated:
            return cap + 1
        counts = [self._range_iteration_count(*range_values, cap) for range_values in range_values_candidates]
        return max(counts) if counts else None

    def _constant_range_values_for_binding_variants(
        self,
        args: list[Any],
        cap: int,
        int_bindings: dict[str, _StaticIntBinding],
    ) -> tuple[list[tuple[int, int, int]], bool]:
        variants, truncated = self._static_int_binding_variants(int_bindings, args[:3])
        if truncated:
            return [], True
        range_values_candidates: list[tuple[int, int, int]] = []
        for variant in variants:
            results: list[_StaticIntResult] = []
            for arg in args[:3]:
                result = self._constant_int_expression_result(arg, cap, variant)
                if result is None:
                    break
                results.append(result)
            else:
                range_values = self._constant_range_values_from_results(args, results, cap, variant)
                if range_values is not None and range_values not in range_values_candidates:
                    range_values_candidates.append(range_values)
        return range_values_candidates, False

    def _template_ast_has_static_range_list_budget_risk(self, parsed: Any) -> bool:
        range_threshold = max(1, self.sandbox_render_max_output_chars)
        for node in parsed.find_all(jinja2.nodes.Filter):
            if node.name != "list":
                continue
            range_call = self._iterable_range_call(node.node)
            if range_call is None:
                continue
            projected_size = self._constant_range_rendered_list_size(range_call.args, range_threshold)
            if projected_size is not None and projected_size > self.sandbox_render_max_output_chars:
                return True

        return False

    def _template_ast_has_static_range_join_budget_risk(self, parsed: Any) -> bool:
        range_threshold = max(1, self.sandbox_render_max_output_chars)
        for node in parsed.find_all(jinja2.nodes.Filter):
            if node.name != "join":
                continue
            range_call = self._iterable_range_call(node.node)
            if range_call is None:
                continue
            projected_size = self._constant_range_joined_size(range_call.args, node.args, range_threshold)
            if projected_size is not None and projected_size > self.sandbox_render_max_output_chars:
                return True

        return False

    def _range_iterable_exceeds_static_budget(self, node: Any, threshold: int) -> bool:
        range_call = self._iterable_range_call(node)
        if range_call is None:
            return False

        range_count = self._constant_range_iteration_count(range_call.args, threshold)
        if range_count is not None:
            return range_count >= threshold

        stop_arg = range_call.args[1] if len(range_call.args) >= 2 else range_call.args[0]
        range_bound = self._constant_int_expression_value(stop_arg, threshold)
        return range_bound is not None and abs(range_bound) >= threshold

    def _iterable_range_call(self, node: Any) -> Any | None:
        while isinstance(node, jinja2.nodes.Filter) and node.name in _LAZY_RANGE_ITERATION_FILTERS:
            node = node.node
        normalized_range_call = self._range_call_with_literal_unpacking(node)
        return normalized_range_call if self._is_range_call(normalized_range_call) else None

    def _is_range_call(self, node: Any) -> bool:
        return (
            isinstance(node, jinja2.nodes.Call)
            and isinstance(node.node, jinja2.nodes.Name)
            and node.node.name == "range"
            and 1 <= len(node.args) <= 3
            and not node.kwargs
            and node.dyn_args is None
            and node.dyn_kwargs is None
        )

    def _parse_template_ast(self, template_content: str) -> Any | None:
        try:
            return jinja2.Environment().parse(template_content)
        except Exception:
            return None

    def _constant_repeated_sequence_size(self, left: Any, right: Any) -> int | None:
        left_size = self._constant_sequence_size(left)
        right_size = self._constant_sequence_size(right)
        left_count = self._constant_int_expression_value(left, self.sandbox_render_max_output_chars)
        right_count = self._constant_int_expression_value(right, self.sandbox_render_max_output_chars)
        if left_count is not None and right_size is not None:
            return max(left_count, 0) * right_size
        if right_count is not None and left_size is not None:
            return max(right_count, 0) * left_size
        return None

    def _constant_sequence_size(self, node: Any) -> int | None:
        if isinstance(node, jinja2.nodes.Const) and isinstance(node.value, str | bytes):
            return len(node.value)
        if isinstance(node, jinja2.nodes.List | jinja2.nodes.Tuple):
            item_sizes: list[int] = []
            is_tuple = isinstance(node, jinja2.nodes.Tuple)
            if is_tuple and not node.items:
                return 2
            total = 2
            for item in node.items:
                item_size = self._constant_rendered_item_size(item)
                if item_size is None:
                    return None
                item_sizes.append(item_size)
                total += item_size
            if len(node.items) > 1:
                total += (len(node.items) - 1) * 2
            if is_tuple and len(item_sizes) == 1:
                total += 1
            return total
        if isinstance(node, jinja2.nodes.Dict):
            total = 2
            for item in cast(list[Any], node.items):
                key_size = self._constant_rendered_item_size(item.key)
                value_size = self._constant_rendered_item_size(item.value)
                if key_size is None or value_size is None:
                    return None
                total += key_size + 2 + value_size
            if len(node.items) > 1:
                total += (len(node.items) - 1) * 2
            return total
        return None

    def _constant_rendered_item_size(self, node: Any) -> int | None:
        if isinstance(node, jinja2.nodes.Const):
            if isinstance(node.value, str | bytes):
                return len(repr(node.value))
            if isinstance(node.value, int | float | bool):
                return len(str(node.value))
            if node.value is None:
                return len("None")
            return None
        return self._constant_sequence_size(node)

    def _constant_range_rendered_list_size(self, args: list[Any], cap: int) -> int | None:
        range_values = self._constant_range_values(args, cap)
        if range_values is None:
            return None
        return self._constant_range_rendered_list_size_from_values(range_values, cap)

    def _constant_range_rendered_list_size_with_bindings(
        self,
        args: list[Any],
        cap: int,
        int_bindings: dict[str, _StaticIntBinding],
    ) -> int | None:
        range_values_candidates, truncated = self._constant_range_values_for_binding_variants(args, cap, int_bindings)
        if truncated:
            return cap + 1
        sizes = [
            self._constant_range_rendered_list_size_from_values(range_values, cap)
            for range_values in range_values_candidates
        ]
        return max(sizes) if sizes else None

    def _constant_range_rendered_list_size_from_values(
        self,
        range_values: tuple[int, int, int],
        cap: int,
    ) -> int:
        start, stop, step = range_values
        count = self._range_iteration_count(start, stop, step, cap)
        if count == 0:
            return 2

        min_rendered_size = 2 + count + ((count - 1) * 2)
        if min_rendered_size > cap:
            return cap + 1

        total = 1
        checked = 0
        for checked, value in enumerate(range(start, stop, step), start=1):
            if checked > 1:
                total += 2
            total += len(str(value))
            if total + 1 > cap:
                return cap + 1
            if checked >= min(count, 100_000):
                break
        total += self._remaining_range_rendered_size_lower_bound(start, step, checked, count, 2)
        if total + 1 > cap:
            return cap + 1
        return total + 1

    def _constant_range_joined_size(
        self,
        args: list[Any],
        join_args: list[Any],
        cap: int,
    ) -> int | None:
        range_values = self._constant_range_values(args, cap)
        if range_values is None:
            return None
        return self._constant_range_joined_size_from_values(range_values, join_args, cap)

    def _constant_range_joined_size_with_bindings(
        self,
        args: list[Any],
        join_args: list[Any],
        cap: int,
        int_bindings: dict[str, _StaticIntBinding],
    ) -> int | None:
        range_values_candidates, truncated = self._constant_range_values_for_binding_variants(args, cap, int_bindings)
        if truncated:
            return cap + 1
        sizes = [
            self._constant_range_joined_size_from_values(range_values, join_args, cap)
            for range_values in range_values_candidates
        ]
        known_sizes = [size for size in sizes if size is not None]
        return max(known_sizes) if known_sizes else None

    def _constant_range_joined_size_from_values(
        self,
        range_values: tuple[int, int, int],
        join_args: list[Any],
        cap: int,
    ) -> int | None:

        separator_size = 0
        if join_args:
            separator_arg = join_args[0]
            if not isinstance(separator_arg, jinja2.nodes.Const) or not isinstance(separator_arg.value, str | bytes):
                return None
            separator_size = len(separator_arg.value)

        start, stop, step = range_values
        count = self._range_iteration_count(start, stop, step, cap)
        total = 0
        checked = 0
        for checked, value in enumerate(range(start, stop, step), start=1):
            if checked > 1:
                total += separator_size
            total += len(str(value))
            if total > cap:
                return cap + 1
            if checked >= min(count, 100_000):
                break
        total += self._remaining_range_rendered_size_lower_bound(
            start,
            step,
            checked,
            count,
            separator_size,
        )
        if total > cap:
            return cap + 1
        return total

    @staticmethod
    def _remaining_range_rendered_size_lower_bound(
        start: int,
        step: int,
        checked: int,
        count: int,
        separator_size: int,
    ) -> int:
        remaining = count - checked
        if remaining <= 0:
            return 0
        next_value = start + checked * step
        last_value = start + (count - 1) * step
        if min(next_value, last_value) <= 0 <= max(next_value, last_value):
            minimum_value_size = 1
        else:
            minimum_value_size = min(len(str(next_value)), len(str(last_value)))
        return remaining * (minimum_value_size + separator_size)

    def _constant_int_expression_value(self, node: Any, cap: int) -> int | None:
        result = self._constant_int_expression_result(node, cap)
        return result[0] if result is not None else None

    def _constant_int_expression_result(
        self,
        node: Any,
        cap: int,
        int_bindings: dict[str, _StaticIntBinding] | None = None,
    ) -> tuple[int, bool] | None:
        if isinstance(node, jinja2.nodes.Name):
            binding = int_bindings.get(node.name) if int_bindings is not None else None
            return None if isinstance(binding, _StaticIntCandidates) else binding
        if isinstance(node, jinja2.nodes.Const):
            if isinstance(node.value, bool) or not isinstance(node.value, int):
                return None
            return self._constant_int_result(node.value, cap)
        if isinstance(node, jinja2.nodes.Neg | jinja2.nodes.Pos):
            result = self._constant_int_expression_result(node.node, cap, int_bindings)
            if result is None or isinstance(node, jinja2.nodes.Pos):
                return result
            value, saturated = result
            return self._constant_int_result(-value, cap, saturated=saturated)
        if isinstance(
            node,
            jinja2.nodes.Add | jinja2.nodes.Sub | jinja2.nodes.Mul | jinja2.nodes.FloorDiv | jinja2.nodes.Mod,
        ):
            left_result = self._constant_int_expression_result(node.left, cap, int_bindings)
            right_result = self._constant_int_expression_result(node.right, cap, int_bindings)
            if left_result is None or right_result is None:
                return None
            left, left_saturated = left_result
            right, right_saturated = right_result
            same_result = left_result is right_result
            if isinstance(node, jinja2.nodes.FloorDiv | jinja2.nodes.Mod) and right == 0 and not right_saturated:
                return None
            if isinstance(node, jinja2.nodes.Add):
                if left_saturated or right_saturated:
                    if left_saturated and right_saturated:
                        if (left < 0) != (right < 0):
                            magnitude_comparison = self._compare_static_power_magnitudes(
                                node.left,
                                node.right,
                                int_bindings,
                            )
                            if magnitude_comparison is None:
                                return None
                            if magnitude_comparison == 0:
                                return self._constant_int_result(0, cap)
                            dominant_value = left if magnitude_comparison > 0 else right
                            return self._saturated_constant_int_result(cap, -1 if dominant_value < 0 else 1)
                        return self._saturated_constant_int_result(cap, -1 if left < 0 else 1)
                    saturated_result = left_result if left_saturated else right_result
                    return self._saturated_constant_int_result(cap, -1 if saturated_result[0] < 0 else 1)
                return self._constant_int_result(left + right, cap)
            if isinstance(node, jinja2.nodes.Sub):
                if node.left == node.right or same_result:
                    return self._constant_int_result(0, cap)
                if left_saturated or right_saturated:
                    wrapped_difference = self._constant_wrapped_difference_result(
                        node.left,
                        node.right,
                        cap,
                        int_bindings,
                    )
                    if wrapped_difference is not None:
                        return wrapped_difference
                    if left_saturated and right_saturated:
                        if (left < 0) == (right < 0):
                            magnitude_comparison = self._compare_static_power_magnitudes(
                                node.left,
                                node.right,
                                int_bindings,
                            )
                            if magnitude_comparison is None:
                                return None
                            if magnitude_comparison == 0:
                                return self._constant_int_result(0, cap)
                            result_sign = (-1 if left < 0 else 1) * magnitude_comparison
                            return self._saturated_constant_int_result(cap, result_sign)
                        return self._saturated_constant_int_result(cap, -1 if left < 0 else 1)
                    if left_saturated:
                        return self._saturated_constant_int_result(cap, -1 if left < 0 else 1)
                    return self._saturated_constant_int_result(cap, -1 if right > 0 else 1)
                return self._constant_int_result(left - right, cap)
            if isinstance(node, jinja2.nodes.Mul):
                if (not left_saturated and left == 0) or (not right_saturated and right == 0):
                    return self._constant_int_result(0, cap)
                if left_saturated or right_saturated:
                    return self._saturated_constant_int_result(cap, -1 if left * right < 0 else 1)
                return self._constant_int_result(left * right, cap)
            if isinstance(node, jinja2.nodes.FloorDiv):
                if node.left == node.right or same_result:
                    return self._constant_int_result(1, cap)
                if not left_saturated and left == 0:
                    return self._constant_int_result(0, cap)
                if left_saturated or right_saturated:
                    if not left_saturated:
                        quotient = -1 if left * right < 0 else 0
                        return self._constant_int_result(quotient, cap)
                    if right_saturated:
                        return None
                    return self._saturated_constant_int_result(cap, -1 if left * right < 0 else 1)
                return self._constant_int_result(left // right, cap)
            if node.left == node.right or same_result or (not left_saturated and left == 0):
                return self._constant_int_result(0, cap)
            if left_saturated or right_saturated:
                if left_saturated:
                    if right_saturated:
                        return None
                    if abs(right) == 1:
                        return self._constant_int_result(0, cap)
                    return None
                if (left < 0) == (right < 0):
                    return self._constant_int_result(left, cap)
                return self._saturated_constant_int_result(cap, -1 if right < 0 else 1)
            return self._constant_int_result(left % right, cap)
        if isinstance(node, jinja2.nodes.Pow):
            left_result = self._constant_int_expression_result(node.left, cap, int_bindings)
            right_result = self._constant_int_expression_result(node.right, cap, int_bindings)
            if left_result is None or right_result is None:
                return None
            left, left_saturated = left_result
            right, right_saturated = right_result
            if right < 0:
                return None
            if not right_saturated and right == 0:
                return self._constant_int_result(1, cap)
            if not left_saturated and left in {-1, 0, 1}:
                if left == 0:
                    return self._constant_int_result(0, cap)
                if left == 1:
                    return self._constant_int_result(1, cap)
                if right_saturated:
                    return None
                return self._constant_int_result(-1 if right % 2 else 1, cap)
            if left_saturated or right_saturated:
                return self._saturated_constant_int_result(cap)
            magnitude_cap = self._constant_int_magnitude_cap(cap)
            if abs(left) > 1 and (abs(left).bit_length() - 1) * right >= magnitude_cap.bit_length():
                sign = -1 if left < 0 and right % 2 else 1
                return self._saturated_constant_int_result(cap, sign)
            return self._constant_int_result(left**right, cap)
        if isinstance(node, jinja2.nodes.CondExpr):
            condition = self._constant_condition_value(node.test)
            if condition is None:
                return None
            branch = node.expr1 if condition else node.expr2
            return self._constant_int_expression_result(branch, cap, int_bindings) if branch is not None else None
        if isinstance(node, jinja2.nodes.Filter):
            return self._constant_int_filter_result(node, cap, int_bindings)
        return None

    def _compare_static_power_magnitudes(
        self,
        left: Any,
        right: Any,
        int_bindings: dict[str, _StaticIntBinding] | None,
    ) -> int | None:
        while isinstance(left, jinja2.nodes.Neg | jinja2.nodes.Pos):
            left = left.node
        while isinstance(right, jinja2.nodes.Neg | jinja2.nodes.Pos):
            right = right.node
        left, left_factor = self._static_power_factor(left, int_bindings)
        right, right_factor = self._static_power_factor(right, int_bindings)
        if not isinstance(left, jinja2.nodes.Pow) or not isinstance(right, jinja2.nodes.Pow):
            return None
        left_base = self._constant_int_expression_result(left.left, _STATIC_INT_EVAL_MAX_ABS, int_bindings)
        right_base = self._constant_int_expression_result(right.left, _STATIC_INT_EVAL_MAX_ABS, int_bindings)
        left_exponent = self._constant_int_expression_result(left.right, _STATIC_INT_EVAL_MAX_ABS, int_bindings)
        right_exponent = self._constant_int_expression_result(right.right, _STATIC_INT_EVAL_MAX_ABS, int_bindings)
        if (
            left_base is None
            or right_base is None
            or left_exponent is None
            or right_exponent is None
            or left_base[1]
            or right_base[1]
            or left_exponent[1]
            or right_exponent[1]
            or left_exponent[0] < 0
            or right_exponent[0] < 0
            or abs(left_base[0]) <= 1
            or abs(right_base[0]) <= 1
        ):
            return None
        if left.left == right.left:
            exponent_comparison = (left_exponent[0] > right_exponent[0]) - (left_exponent[0] < right_exponent[0])
            if exponent_comparison != 0 and left_factor == right_factor == 1:
                return exponent_comparison
            if exponent_comparison == 0:
                return (left_factor > right_factor) - (left_factor < right_factor)

        left_log = left_exponent[0] * math.log(abs(left_base[0])) + math.log(left_factor)
        right_log = right_exponent[0] * math.log(abs(right_base[0])) + math.log(right_factor)
        difference = left_log - right_log
        tolerance = 1e-12 * max(1.0, abs(left_log), abs(right_log))
        if not math.isfinite(difference) or abs(difference) <= tolerance:
            return None
        return 1 if difference > 0 else -1

    def _static_power_factor(
        self,
        node: Any,
        int_bindings: dict[str, _StaticIntBinding] | None,
    ) -> tuple[Any, int]:
        if not isinstance(node, jinja2.nodes.Mul):
            return node, 1
        for factor_node, value_node in ((node.left, node.right), (node.right, node.left)):
            factor_result = self._constant_int_expression_result(
                factor_node,
                _STATIC_INT_EVAL_MAX_ABS,
                int_bindings,
            )
            if factor_result is not None and not factor_result[1] and factor_result[0] != 0:
                return value_node, abs(factor_result[0])
        return node, 1

    def _constant_wrapped_difference_result(
        self,
        left: Any,
        right: Any,
        cap: int,
        int_bindings: dict[str, _StaticIntBinding] | None,
    ) -> tuple[int, bool] | None:
        if not isinstance(left, jinja2.nodes.Add):
            return None
        right_result = self._constant_int_expression_result(right, cap, int_bindings)
        if right_result is None or not right_result[1]:
            return None
        for dominant, offset in ((left.left, left.right), (left.right, left.left)):
            dominant_result = self._constant_int_expression_result(dominant, cap, int_bindings)
            offset_result = self._constant_int_expression_result(offset, cap, int_bindings)
            if dominant_result is None or not dominant_result[1] or offset_result is None or offset_result[1]:
                continue
            if dominant == right:
                return offset_result
            magnitude_comparison = self._compare_static_power_magnitudes(dominant, right, int_bindings)
            if magnitude_comparison is None:
                continue
            dominant_sign = -1 if dominant_result[0] < 0 else 1
            right_sign = -1 if right_result[0] < 0 else 1
            if dominant_sign != right_sign or magnitude_comparison > 0:
                return self._saturated_constant_int_result(cap, dominant_sign)
            if magnitude_comparison < 0:
                return self._saturated_constant_int_result(cap, -right_sign)
            return offset_result
        return None

    def _constant_int_filter_result(
        self,
        node: Any,
        cap: int,
        int_bindings: dict[str, _StaticIntBinding] | None = None,
    ) -> tuple[int, bool] | None:
        if node.kwargs or node.dyn_args is not None or node.dyn_kwargs is not None:
            return None
        if node.name == "abs" and not node.args:
            result = self._constant_int_expression_result(node.node, cap, int_bindings)
            if result is None:
                return None
            value, saturated = result
            return self._constant_int_result(abs(value), cap, saturated=saturated)
        if node.name != "int" or len(node.args) > 2:
            return None

        if node.args:
            parsed_default_result = self._constant_int_expression_result(node.args[0], cap, int_bindings)
            if parsed_default_result is None:
                return None
            default_result = parsed_default_result
        else:
            default_result = self._constant_int_result(0, cap)

        base = 10
        if len(node.args) == 2:
            base_result = self._constant_int_expression_result(node.args[1], cap, int_bindings)
            if base_result is None or base_result[1]:
                return None
            base = base_result[0]

        source_result = self._constant_int_expression_result(node.node, cap, int_bindings)
        if source_result is not None:
            return source_result
        if not isinstance(node.node, jinja2.nodes.Const):
            return None

        value = node.node.value
        try:
            if isinstance(value, float):
                if not math.isfinite(value):
                    return default_result
                parsed = int(value)
            elif isinstance(value, str):
                text = value.strip()
                if len(text) > 4096:
                    return self._saturated_constant_int_result(cap, -1 if text.startswith("-") else 1)
                try:
                    parsed = int(text, base)
                except ValueError:
                    float_value = float(text)
                    if not math.isfinite(float_value):
                        return default_result
                    parsed = int(float_value)
            else:
                return default_result
        except (OverflowError, TypeError, ValueError):
            return default_result
        return self._constant_int_result(parsed, cap)

    @staticmethod
    def _constant_condition_value(node: Any) -> bool | None:
        known, value = Jinja2TemplateScanner._constant_condition_scalar(node)
        if not known:
            return None
        if value is None or isinstance(value, bool | int | float | str | bytes):
            return bool(value)
        return None

    @staticmethod
    def _constant_condition_scalar(node: Any, depth: int = 0) -> tuple[bool, Any]:
        if depth > 32:
            return False, None
        if isinstance(node, jinja2.nodes.Const):
            return True, node.value
        if isinstance(node, jinja2.nodes.Neg | jinja2.nodes.Pos):
            known, value = Jinja2TemplateScanner._constant_condition_scalar(node.node, depth + 1)
            if not known or not isinstance(value, int | float):
                return False, None
            return True, -value if isinstance(node, jinja2.nodes.Neg) else +value
        if not isinstance(
            node,
            jinja2.nodes.Add
            | jinja2.nodes.Sub
            | jinja2.nodes.Mul
            | jinja2.nodes.FloorDiv
            | jinja2.nodes.Mod
            | jinja2.nodes.Pow,
        ):
            return False, None
        left_known, left = Jinja2TemplateScanner._constant_condition_scalar(node.left, depth + 1)
        right_known, right = Jinja2TemplateScanner._constant_condition_scalar(node.right, depth + 1)
        if not left_known or not right_known or not isinstance(left, int | float) or not isinstance(right, int | float):
            return False, None
        try:
            if isinstance(node, jinja2.nodes.Add):
                result = left + right
            elif isinstance(node, jinja2.nodes.Sub):
                result = left - right
            elif isinstance(node, jinja2.nodes.Mul):
                result = left * right
            elif isinstance(node, jinja2.nodes.FloorDiv):
                result = left // right
            elif isinstance(node, jinja2.nodes.Mod):
                result = left % right
            else:
                if not isinstance(right, int) or right < 0 or right > 4096:
                    return False, None
                result = left**right
        except (OverflowError, TypeError, ValueError, ZeroDivisionError):
            return False, None
        if isinstance(result, int) and result.bit_length() > 4096:
            return False, None
        if isinstance(result, float) and not math.isfinite(result):
            return False, None
        return True, result

    def _constant_int_result(self, value: int, cap: int, *, saturated: bool = False) -> tuple[int, bool]:
        capped_value = self._cap_constant_int(value, cap)
        return capped_value, saturated or self._constant_int_is_saturated(capped_value, cap)

    def _saturated_constant_int_result(self, cap: int, sign: int = 1) -> tuple[int, bool]:
        magnitude = self._constant_int_magnitude_cap(cap) + 1
        return (magnitude if sign >= 0 else -magnitude), True

    def _constant_range_iteration_count(self, args: list[Any], cap: int) -> int | None:
        range_values = self._constant_range_values(args, cap)
        if range_values is None:
            return None
        return self._range_iteration_count(*range_values, cap)

    def _constant_range_values(self, args: list[Any], cap: int) -> tuple[int, int, int] | None:
        results: list[tuple[int, bool]] = []
        for arg in args[:3]:
            result = self._constant_int_expression_result(arg, cap)
            if result is None:
                return None
            results.append(result)

        return self._constant_range_values_from_results(args, results, cap)

    def _constant_range_values_from_results(
        self,
        args: list[Any],
        results: list[tuple[int, bool]],
        cap: int,
        int_bindings: dict[str, _StaticIntBinding] | None = None,
    ) -> tuple[int, int, int] | None:
        if not results:
            return None

        if len(results) == 1:
            start_result = (0, False)
            stop_result = results[0]
            step_result = (1, False)
        else:
            start_result = results[0]
            stop_result = results[1]
            step_result = results[2] if len(results) >= 3 else (1, False)

        start, start_saturated = start_result
        stop, stop_saturated = stop_result
        step, step_saturated = step_result

        if step == 0:
            return 0, 0, 1
        if len(args) >= 2 and args[0] == args[1]:
            return 0, 0, 1

        if len(args) >= 2 and (start_saturated or stop_saturated):
            delta_result = self._constant_range_bound_delta(args[0], args[1], cap, int_bindings)
            if delta_result is not None:
                delta, delta_saturated = delta_result
                if not delta_saturated:
                    return 0, delta, step

        comparison = self._compare_constant_int_results(start_result, stop_result)
        if comparison is not None and ((step > 0 and comparison >= 0) or (step < 0 and comparison <= 0)):
            return 0, 0, 1
        if step_saturated and self._static_zero_start_range_span_within_step(
            args,
            start_result,
            stop_result,
            step_result,
            int_bindings,
        ):
            return (0, 1, 1) if step > 0 else (1, 0, -1)
        if start_saturated or stop_saturated:
            synthetic_stop = max(1, abs(cap)) + 1
            return (0, synthetic_stop, 1) if step > 0 else (synthetic_stop, 0, -1)
        return start, stop, step

    def _static_zero_start_range_span_within_step(
        self,
        args: list[Any],
        start_result: tuple[int, bool],
        stop_result: tuple[int, bool],
        step_result: tuple[int, bool],
        int_bindings: dict[str, _StaticIntBinding] | None,
    ) -> bool:
        if len(args) < 3 or start_result != (0, False):
            return False
        stop, stop_saturated = stop_result
        step, step_saturated = step_result
        if not stop_saturated or not step_saturated or stop == 0 or step == 0 or (stop < 0) != (step < 0):
            return False
        if args[1] == args[2]:
            return True
        magnitude_comparison = self._compare_static_power_magnitudes(args[1], args[2], int_bindings)
        return magnitude_comparison is not None and magnitude_comparison <= 0

    def _constant_range_bound_delta(
        self,
        start: Any,
        stop: Any,
        cap: int,
        int_bindings: dict[str, _StaticIntBinding] | None = None,
    ) -> tuple[int, bool] | None:
        stop_offset = self._constant_offset_from_base(stop, start, cap, int_bindings)
        if stop_offset is not None:
            return stop_offset
        start_offset = self._constant_offset_from_base(start, stop, cap, int_bindings)
        if start_offset is not None:
            value, saturated = start_offset
            return self._constant_int_result(-value, cap, saturated=saturated)
        if isinstance(stop, jinja2.nodes.Add):
            if stop.left == start:
                return self._constant_int_expression_result(stop.right, cap, int_bindings)
            if stop.right == start:
                return self._constant_int_expression_result(stop.left, cap, int_bindings)
        if isinstance(stop, jinja2.nodes.Sub) and stop.left == start:
            result = self._constant_int_expression_result(stop.right, cap, int_bindings)
            if result is not None:
                value, saturated = result
                return self._constant_int_result(-value, cap, saturated=saturated)
        if isinstance(start, jinja2.nodes.Add):
            if start.left == stop:
                result = self._constant_int_expression_result(start.right, cap, int_bindings)
            elif start.right == stop:
                result = self._constant_int_expression_result(start.left, cap, int_bindings)
            else:
                result = None
            if result is not None:
                value, saturated = result
                return self._constant_int_result(-value, cap, saturated=saturated)
        if isinstance(start, jinja2.nodes.Sub) and start.left == stop:
            return self._constant_int_expression_result(start.right, cap, int_bindings)
        return None

    def _constant_offset_from_base(
        self,
        expression: Any,
        base: Any,
        cap: int,
        int_bindings: dict[str, _StaticIntBinding] | None,
    ) -> tuple[int, bool] | None:
        if expression == base:
            return self._constant_int_result(0, cap)
        if isinstance(expression, jinja2.nodes.Add):
            for nested, constant in ((expression.left, expression.right), (expression.right, expression.left)):
                nested_offset = self._constant_offset_from_base(nested, base, cap, int_bindings)
                constant_result = self._constant_int_expression_result(constant, cap, int_bindings)
                if nested_offset is None or constant_result is None:
                    continue
                value = nested_offset[0] + constant_result[0]
                return self._constant_int_result(value, cap, saturated=nested_offset[1] or constant_result[1])
        if isinstance(expression, jinja2.nodes.Sub):
            nested_offset = self._constant_offset_from_base(expression.left, base, cap, int_bindings)
            constant_result = self._constant_int_expression_result(expression.right, cap, int_bindings)
            if nested_offset is not None and constant_result is not None:
                value = nested_offset[0] - constant_result[0]
                return self._constant_int_result(value, cap, saturated=nested_offset[1] or constant_result[1])
        return None

    @staticmethod
    def _compare_constant_int_results(left: tuple[int, bool], right: tuple[int, bool]) -> int | None:
        left_value, left_saturated = left
        right_value, right_saturated = right
        if not left_saturated and not right_saturated:
            return (left_value > right_value) - (left_value < right_value)
        if left_saturated and right_saturated:
            if (left_value < 0) != (right_value < 0):
                return -1 if left_value < 0 else 1
            return None
        if left_saturated:
            return -1 if left_value < 0 else 1
        return 1 if right_value < 0 else -1

    def _range_iteration_count(self, start: int, stop: int, step: int, cap: int) -> int:
        if step > 0:
            if stop <= start:
                return 0
            return min(((stop - start - 1) // step) + 1, cap + 1)
        if stop >= start:
            return 0
        return min(((start - stop - 1) // abs(step)) + 1, cap + 1)

    @staticmethod
    def _constant_int_magnitude_cap(cap: int) -> int:
        return max(abs(cap), _STATIC_INT_EVAL_MAX_ABS)

    def _constant_int_is_saturated(self, value: int, cap: int) -> bool:
        return abs(value) > self._constant_int_magnitude_cap(cap)

    def _cap_constant_int(self, value: int, cap: int) -> int:
        magnitude_cap = self._constant_int_magnitude_cap(cap)
        if abs(value) <= magnitude_cap:
            return value
        return magnitude_cap + 1 if value > 0 else -(magnitude_cap + 1)

    def _sandbox_render_budget_failure(
        self,
        location: str,
        budget_type: str,
        detail: str | None = None,
    ) -> dict[str, Any]:
        failure: dict[str, Any] = {
            "format": "sandbox",
            "reason": _SANDBOX_RENDER_BUDGET_REASON,
            "budget_type": budget_type,
            "sandbox_render_timeout_seconds": self.sandbox_render_timeout_seconds,
            "sandbox_render_max_output_chars": self.sandbox_render_max_output_chars,
            "sandbox_render_max_memory_bytes": self.sandbox_render_max_memory_bytes,
            "template_location": location,
        }
        if detail:
            failure["detail"] = detail
        return failure

    def _test_template_safety_with_budget(self, template_content: str) -> tuple[str, str | None]:
        if self._template_has_static_preflight_render_budget_risk(template_content):
            return "budget_exceeded", "output"

        result_queue: Any | None = None
        ready_queue: Any | None = None
        process: Any | None = None
        try:
            start_method = _sandbox_worker_start_method()
            context = mp.get_context(start_method) if start_method else mp.get_context()
            result_queue = context.Queue(maxsize=1)
            ready_queue = context.Queue(maxsize=1)
            process = cast(Any, context).Process(
                target=_sandbox_render_probe_worker,
                args=(
                    template_content,
                    self.sandbox_render_max_output_chars,
                    self.sandbox_render_max_memory_bytes,
                    result_queue,
                    ready_queue,
                ),
            )
            process.daemon = True
            process.start()
        except Exception as exc:
            if result_queue is not None:
                result_queue.close()
            if ready_queue is not None:
                ready_queue.close()
            return "worker_unavailable", type(exc).__name__

        assert result_queue is not None
        assert ready_queue is not None
        assert process is not None
        try:
            if start_method == "spawn":
                try:
                    ready_queue.get(timeout=_SANDBOX_RENDER_SPAWN_STARTUP_GRACE_SECONDS)
                except queue.Empty:
                    if not process.is_alive():
                        try:
                            status, _detail = result_queue.get_nowait()
                            return str(status), str(_detail) if _detail else None
                        except queue.Empty:
                            return "worker_error", f"exitcode={process.exitcode}"
                    process.terminate()
                    process.join(1)
                    if process.is_alive() and hasattr(process, "kill"):
                        process.kill()
                        process.join(1)
                    return "worker_unavailable", "startup_timeout"

            process.join(self.sandbox_render_timeout_seconds)
            if process.is_alive():
                process.terminate()
                process.join(1)
                if process.is_alive() and hasattr(process, "kill"):
                    process.kill()
                    process.join(1)
                return "timeout", None

            try:
                status, _detail = result_queue.get_nowait()
            except queue.Empty:
                if process.exitcode not in (0, None):
                    return "worker_error", f"exitcode={process.exitcode}"
                return "worker_error", "empty_result"

            return str(status), str(_detail) if _detail else None
        finally:
            result_queue.close()
            result_queue.join_thread()
            ready_queue.close()
            ready_queue.join_thread()
            if hasattr(process, "close"):
                with suppress(ValueError):
                    process.close()
