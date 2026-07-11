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
from pathlib import Path
from typing import Any, ClassVar, cast

try:
    import resource

    HAS_RESOURCE_LIMITS = True
except ImportError:
    resource = None  # type: ignore[assignment]
    HAS_RESOURCE_LIMITS = False

from modelaudit.detectors.suspicious_symbols import (
    JINJA2_NAMED_GLOBAL_ACCESS_PATTERN,
    JINJA2_SSTI_PATTERNS,
    find_unquoted_jinja_named_global_access,
    mask_quoted_jinja_text,
)
from modelaudit.scanner_selection import add_scanner_selection_skip_check, policy_from_config
from modelaudit.utils.file.detection import (
    huggingface_tokenizer_json_has_jax_route_evidence,
    huggingface_tokenizer_json_has_template_route_evidence,
)

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
JINJA_SKIP_JAX_JSON_OVERLAP_CONFIG_KEY = "_jinja_skip_jax_json_overlap"
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
_QUOTE_SENSITIVE_GLOBAL_SUBSCRIPT_PATTERN = r"__globals__\s*\["
_RAW_PARSE_FALLBACK_CONTEXT_BYTES = 1024
_RAW_PARSE_FALLBACK_MAX_WINDOWS = 8
_RAW_PARSE_FALLBACK_READ_BYTES = 256 * 1024
_DEFAULT_SANDBOX_RENDER_TIMEOUT_SECONDS = 0.5
_DEFAULT_SANDBOX_RENDER_MAX_OUTPUT_CHARS = 64 * 1024
_DEFAULT_SANDBOX_RENDER_MAX_MEMORY_BYTES = 512 * 1024 * 1024
_SANDBOX_RENDER_SPAWN_STARTUP_GRACE_SECONDS = 2.0
_SANDBOX_RENDER_BUDGET_REASON = "jinja2_sandbox_render_budget_exceeded"
_STATIC_INT_EVAL_MAX_ABS = 10**100
_MAX_STATIC_RENDER_ANALYSIS_STEPS = 20_000
_MAX_STATIC_RANGE_PROJECTION_ITEMS = 200_000
_MAX_STATIC_CONTAINER_PATHS = 4_096
_SANDBOX_MAX_RANGE_ITERATIONS = int(jinja2.sandbox.MAX_RANGE) if HAS_JINJA2_SANDBOX else 100_000
_EAGER_RANGE_ITERATION_FILTERS = frozenset({"groupby", "join", "list", "sort"})
_LAZY_RANGE_ITERATION_FILTERS = frozenset(
    {"batch", "d", "default", "map", "reject", "rejectattr", "reverse", "select", "selectattr", "slice", "unique"}
)

_StaticIntResult = tuple[int, bool]


@dataclass(frozen=True)
class _StaticIntCandidates:
    values: tuple["_StaticBindingValue", ...]
    truncated: bool = False
    may_be_undefined: bool = False


@dataclass(frozen=True)
class _StaticScalarValue:
    value: str | float


_StaticBindingValue = _StaticIntResult | _StaticScalarValue
_StaticIntBinding = _StaticBindingValue | _StaticIntCandidates


class _StaticAnalysisBudgetExceeded(Exception):
    pass


class _StaticMacroAnalysisState(set[int]):
    def __init__(
        self,
        values: set[int] | None = None,
        remaining_steps: list[int] | None = None,
        remaining_range_items: list[int] | None = None,
        preflight_only: bool = False,
    ):
        super().__init__(values or ())
        self.remaining_steps = remaining_steps or [_MAX_STATIC_RENDER_ANALYSIS_STEPS]
        self.remaining_range_items = remaining_range_items or [_MAX_STATIC_RANGE_PROJECTION_ITEMS]
        self.preflight_only = preflight_only

    def consume(self, count: int = 1) -> bool:
        if count > self.remaining_steps[0]:
            self.remaining_steps[0] = 0
            return False
        self.remaining_steps[0] -= count
        return True

    def nested(self, macro_id: int) -> "_StaticMacroAnalysisState":
        return _StaticMacroAnalysisState(
            {*self, macro_id},
            self.remaining_steps,
            self.remaining_range_items,
            self.preflight_only,
        )

    def consume_range_items(self, count: int) -> bool:
        if count > self.remaining_range_items[0]:
            self.remaining_range_items[0] = 0
            return False
        self.remaining_range_items[0] -= count
        return True


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


@dataclass(frozen=True)
class _ExecutableTemplateSpan:
    text: str


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

        if huggingface_tokenizer_json_has_template_route_evidence(path):
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
            if filename == "tokenizer.json":
                return huggingface_tokenizer_json_has_template_route_evidence(path)
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
                self._scan_jax_json_overlap(path, result)
                result.finish(success=True)
                return result

            result = self._scan_extracted_templates(path, templates, context, result=result, file_size=file_size)
            self._scan_jax_json_overlap(path, result)
            return result

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

    def _merge_filename_owned_result(self, result: ScanResult, owner_result: ScanResult) -> None:
        """Merge an owner scan without dropping existing incomplete-coverage reasons."""
        existing_reasons = list(result.metadata.get(_INCONCLUSIVE_REASONS_METADATA_KEY, []))
        owner_reasons = list(owner_result.metadata.get(_INCONCLUSIVE_REASONS_METADATA_KEY, []))
        result.merge(owner_result)
        if existing_reasons or owner_reasons:
            result.metadata[_INCONCLUSIVE_REASONS_METADATA_KEY] = list(
                dict.fromkeys([*owner_reasons, *existing_reasons])
            )

    def _scan_jax_json_overlap(self, path: str, result: ScanResult) -> None:
        """Preserve JAX analysis for Jinja-owned tokenizer JSON files."""
        if self.config.get(JINJA_SKIP_JAX_JSON_OVERLAP_CONFIG_KEY) is True:
            return
        if Path(path).name.lower() not in {
            "tokenizer",
            "tokenizer.json",
            "tokenizer_config.json",
            "tokenizer.txt",
            "tokenizer.bin",
        } or not huggingface_tokenizer_json_has_jax_route_evidence(path):
            return

        from .jax_checkpoint_scanner import JAX_SKIP_JINJA_JSON_OVERLAP_CONFIG_KEY, JaxCheckpointScanner

        scanner_selection = policy_from_config(self.config)
        if scanner_selection.allows("jax_checkpoint"):
            jax_config = dict(self.config)
            jax_config[JAX_SKIP_JINJA_JSON_OVERLAP_CONFIG_KEY] = True
            self._merge_filename_owned_result(result, JaxCheckpointScanner(config=jax_config).scan(path))
        elif scanner_selection.active:
            add_scanner_selection_skip_check(
                result,
                path,
                "jax_checkpoint",
                scanner_selection,
                context="overlapping JAX JSON analysis",
            )

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

        executable_spans = self._executable_template_spans(template_content)
        named_detections, covered_global_receivers = self._detect_named_global_access(
            template_content,
            executable_spans,
            location,
        )
        detections.extend(named_detections)
        named_receiver_pattern = (
            re.compile(
                rf"\b(?:{'|'.join(re.escape(receiver) for receiver in sorted(covered_global_receivers))})"
                r"\s*\.\s*__globals__\b"
            )
            if covered_global_receivers
            else None
        )

        # Check each pattern category only inside executable Jinja spans. Literal
        # template data can contain model instructions or documentation prose.
        for category, compiled_patterns in self._compiled_patterns.items():
            for compiled_pattern, original_pattern in compiled_patterns:
                matches: list[re.Match[str]] = []
                for executable_span in executable_spans:
                    pattern_text = (
                        mask_quoted_jinja_text(executable_span.text)
                        if original_pattern == _QUOTE_SENSITIVE_GLOBAL_SUBSCRIPT_PATTERN
                        else executable_span.text
                    )
                    pattern_matches = list(compiled_pattern.finditer(pattern_text))
                    if (
                        original_pattern == _QUOTE_SENSITIVE_GLOBAL_SUBSCRIPT_PATTERN
                        and named_receiver_pattern is not None
                    ):
                        named_ranges = [
                            (named_match.start(), named_match.end())
                            for named_match in named_receiver_pattern.finditer(pattern_text)
                        ]
                        pattern_matches = [
                            match
                            for match in pattern_matches
                            if not any(
                                named_start <= match.start() < named_end for named_start, named_end in named_ranges
                            )
                        ]
                    matches.extend(pattern_matches)

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

    def _detect_named_global_access(
        self,
        template_content: str,
        executable_spans: list[_ExecutableTemplateSpan],
        location: str,
    ) -> tuple[list[DetectionResult], frozenset[str]]:
        matches = self._parsed_named_global_access(template_content)
        parsed_succeeded = matches is not None
        if matches is None:
            matches = self._fallback_named_global_access(executable_spans)

        covered_receivers = (
            {"lipsum", "get_flashed_messages"} if parsed_succeeded else set(matches)
        )

        return [
            DetectionResult(
                pattern_type="global_access",
                pattern=JINJA2_NAMED_GLOBAL_ACCESS_PATTERN.pattern,
                match_text=f"{root}.__globals__",
                risk_level=self._get_risk_level_for_category("global_access"),
                location=location,
                explanation=self._get_pattern_explanation("global_access", f"{root}.__globals__"),
            )
            for root in matches
        ], frozenset(covered_receivers)

    @staticmethod
    def _parsed_named_global_access(template_content: str) -> list[str] | None:
        if not HAS_JINJA2_SANDBOX:
            return None
        try:
            parsed = jinja2.Environment().parse(template_content)
        except Exception:
            return None

        matches: list[str] = []
        named_roots = {"lipsum", "get_flashed_messages"}
        with_node_type = getattr(jinja2.nodes, "With", None)
        isolated_scope_types = tuple(
            node_type
            for name in (
                "Block",
                "FilterBlock",
                "Scope",
                "OverlayScope",
            )
            if (node_type := getattr(jinja2.nodes, name, None)) is not None
        )

        def stored_names(node: Any) -> set[str]:
            return {
                name.name
                for name in node.find_all(jinja2.nodes.Name)
                if name.ctx in {"param", "store"}
            } | (
                {node.name}
                if isinstance(node, jinja2.nodes.Name) and node.ctx in {"param", "store"}
                else set()
            )

        def is_safe_literal(node: Any) -> bool:
            try:
                node.as_const()
            except Exception:
                return False
            return True

        def is_dangerous_name(
            node: Any,
            shadowed: set[str],
            dangerous_aliases: set[str],
        ) -> bool:
            return isinstance(node, jinja2.nodes.Name) and (
                node.name in dangerous_aliases
                or (node.name in named_roots and node.name not in shadowed)
            )

        def update_bindings(
            target_node: Any,
            value: Any,
            shadowed: set[str],
            dangerous_aliases: set[str],
            *,
            source_shadowed: set[str] | None = None,
            source_dangerous_aliases: set[str] | None = None,
        ) -> None:
            if source_shadowed is None:
                source_shadowed = shadowed.copy()
            if source_dangerous_aliases is None:
                source_dangerous_aliases = dangerous_aliases.copy()

            sequence_types = (jinja2.nodes.List, jinja2.nodes.Tuple)
            if (
                isinstance(target_node, sequence_types)
                and isinstance(value, sequence_types)
                and len(target_node.items) == len(value.items)
            ):
                for target_item, value_item in zip(
                    target_node.items,
                    value.items,
                    strict=True,
                ):
                    update_bindings(
                        target_item,
                        value_item,
                        shadowed,
                        dangerous_aliases,
                        source_shadowed=source_shadowed,
                        source_dangerous_aliases=source_dangerous_aliases,
                    )
                return

            safe_value = is_safe_literal(value) or (
                isinstance(value, jinja2.nodes.Name)
                and value.name in source_shadowed
            )
            dangerous_value = is_dangerous_name(
                value,
                source_shadowed,
                source_dangerous_aliases,
            )
            for target in stored_names(target_node):
                if safe_value:
                    shadowed.add(target)
                    dangerous_aliases.discard(target)
                elif dangerous_value:
                    shadowed.discard(target)
                    dangerous_aliases.add(target)
                else:
                    shadowed.discard(target)
                    dangerous_aliases.discard(target)

        def visit(
            node: Any,
            shadowed: set[str],
            dangerous_aliases: set[str],
            parent: Any = None,
        ) -> None:
            if isinstance(node, jinja2.nodes.Getattr):
                receiver = node.node
                if (
                    node.attr == "__globals__"
                    and isinstance(receiver, jinja2.nodes.Name)
                    and receiver.name in named_roots
                    and receiver.name not in shadowed
                ):
                    matches.append(receiver.name)

            if isinstance(node, jinja2.nodes.Assign):
                visit(node.node, shadowed, dangerous_aliases, node)
                update_bindings(
                    node.target,
                    node.node,
                    shadowed,
                    dangerous_aliases,
                )
                return

            if isinstance(node, jinja2.nodes.AssignBlock):
                for child in node.body:
                    visit(child, shadowed, dangerous_aliases, node)
                targets = stored_names(node.target)
                shadowed.update(targets)
                dangerous_aliases.difference_update(targets)
                return

            if isinstance(node, jinja2.nodes.Import):
                visit(node.template, shadowed, dangerous_aliases, node)
                shadowed.add(node.target)
                dangerous_aliases.discard(node.target)
                return

            if isinstance(node, jinja2.nodes.FromImport):
                visit(node.template, shadowed, dangerous_aliases, node)
                imported_names = {
                    imported[1] if isinstance(imported, tuple) else imported
                    for imported in node.names
                }
                shadowed.update(imported_names)
                dangerous_aliases.difference_update(imported_names)
                return

            if isinstance(node, jinja2.nodes.If):
                visit(node.test, shadowed, dangerous_aliases, node)
                branch_states: list[tuple[set[str], set[str]]] = []

                body_shadowed = shadowed.copy()
                body_dangerous = dangerous_aliases.copy()
                for child in node.body:
                    visit(child, body_shadowed, body_dangerous, node)
                branch_states.append((body_shadowed, body_dangerous))

                for elif_node in node.elif_:
                    visit(elif_node.test, shadowed, dangerous_aliases, elif_node)
                    elif_shadowed = shadowed.copy()
                    elif_dangerous = dangerous_aliases.copy()
                    for child in elif_node.body:
                        visit(child, elif_shadowed, elif_dangerous, elif_node)
                    branch_states.append((elif_shadowed, elif_dangerous))

                else_shadowed = shadowed.copy()
                else_dangerous = dangerous_aliases.copy()
                for child in node.else_:
                    visit(child, else_shadowed, else_dangerous, node)
                branch_states.append((else_shadowed, else_dangerous))

                shadowed.clear()
                shadowed.update(set.intersection(*(state[0] for state in branch_states)))
                dangerous_aliases.clear()
                dangerous_aliases.update(*(state[1] for state in branch_states))
                return

            if isinstance(node, jinja2.nodes.For):
                visit(node.iter, shadowed, dangerous_aliases, node)
                target_names = stored_names(node.target)
                sequence_types = (jinja2.nodes.List, jinja2.nodes.Tuple)
                if isinstance(node.iter, sequence_types) and node.iter.items:
                    iteration_states: list[tuple[set[str], set[str]]] = []
                    for item in node.iter.items:
                        item_shadowed = shadowed.copy()
                        item_dangerous = dangerous_aliases.copy()
                        update_bindings(
                            node.target,
                            item,
                            item_shadowed,
                            item_dangerous,
                            source_shadowed=shadowed,
                            source_dangerous_aliases=dangerous_aliases,
                        )
                        iteration_states.append((item_shadowed, item_dangerous))
                    body_shadowed = set.intersection(
                        *(state[0] for state in iteration_states)
                    )
                    body_dangerous = set().union(
                        *(state[1] for state in iteration_states)
                    )
                else:
                    body_shadowed = shadowed | target_names
                    body_dangerous = dangerous_aliases - target_names
                if node.test is not None:
                    visit(node.test, body_shadowed, body_dangerous, node)
                for child in node.body:
                    visit(child, body_shadowed, body_dangerous, node)
                else_shadowed = shadowed.copy()
                else_dangerous = dangerous_aliases.copy()
                for child in node.else_:
                    visit(child, else_shadowed, else_dangerous, node)
                return

            if isinstance(node, jinja2.nodes.Macro):
                for default in node.defaults:
                    visit(default, shadowed, dangerous_aliases, node)
                macro_shadowed = shadowed.copy()
                macro_dangerous = dangerous_aliases.copy()
                macro_shadowed.add(node.name)
                macro_dangerous.discard(node.name)
                required_count = len(node.args) - len(node.defaults)
                for argument in node.args[:required_count]:
                    names = stored_names(argument)
                    macro_shadowed.update(names)
                    macro_dangerous.difference_update(names)
                for argument, default in zip(
                    node.args[required_count:],
                    node.defaults,
                    strict=True,
                ):
                    update_bindings(
                        argument,
                        default,
                        macro_shadowed,
                        macro_dangerous,
                        source_shadowed=shadowed,
                        source_dangerous_aliases=dangerous_aliases,
                    )
                for child in node.body:
                    visit(child, macro_shadowed, macro_dangerous, node)
                shadowed.add(node.name)
                dangerous_aliases.discard(node.name)
                return

            if isinstance(node, jinja2.nodes.CallBlock):
                visit(node.call, shadowed, dangerous_aliases, node)
                for default in node.defaults:
                    visit(default, shadowed, dangerous_aliases, node)
                call_shadowed = shadowed.copy()
                call_dangerous = dangerous_aliases.copy()
                required_count = len(node.args) - len(node.defaults)
                for argument in node.args[:required_count]:
                    names = stored_names(argument)
                    call_shadowed.update(names)
                    call_dangerous.difference_update(names)
                for argument, default in zip(
                    node.args[required_count:],
                    node.defaults,
                    strict=True,
                ):
                    update_bindings(
                        argument,
                        default,
                        call_shadowed,
                        call_dangerous,
                        source_shadowed=shadowed,
                        source_dangerous_aliases=dangerous_aliases,
                    )
                for child in node.body:
                    visit(child, call_shadowed, call_dangerous, node)
                return

            if with_node_type is not None and isinstance(node, with_node_type):
                for value in node.values:
                    visit(value, shadowed, dangerous_aliases, node)
                with_shadowed = shadowed.copy()
                with_dangerous = dangerous_aliases.copy()
                for target, value in zip(node.targets, node.values, strict=True):
                    update_bindings(
                        target,
                        value,
                        with_shadowed,
                        with_dangerous,
                        source_shadowed=shadowed,
                        source_dangerous_aliases=dangerous_aliases,
                    )
                for child in node.body:
                    visit(child, with_shadowed, with_dangerous, node)
                return

            if isolated_scope_types and isinstance(node, isolated_scope_types):
                scope_shadowed = shadowed.copy()
                scope_dangerous = dangerous_aliases.copy()
                for child in node.iter_child_nodes():
                    visit(child, scope_shadowed, scope_dangerous, node)
                return

            for child in node.iter_child_nodes():
                visit(child, shadowed, dangerous_aliases, node)

        visit(parsed, set(), set())
        return matches

    @staticmethod
    def conservative_named_global_access(executable_spans: list[str]) -> list[str]:
        """Detect direct named gadgets only when fallback scope is unambiguous."""
        if any("{%" in mask_quoted_jinja_text(span) for span in executable_spans):
            return []
        return [root for span in executable_spans for root in find_unquoted_jinja_named_global_access(span)]

    @staticmethod
    def _fallback_named_global_access(
        executable_spans: list[_ExecutableTemplateSpan],
    ) -> list[str]:
        return Jinja2TemplateScanner.conservative_named_global_access([span.text for span in executable_spans])

    @staticmethod
    def _mask_quoted_template_text(text: str) -> str:
        return mask_quoted_jinja_text(text)

    @staticmethod
    def executable_template_spans(template_content: str) -> list[str]:
        """Return executable Jinja spans, excluding literals, comments, and raw blocks."""
        return [span.text for span in Jinja2TemplateScanner._executable_template_spans(template_content)]

    @staticmethod
    def _executable_template_spans(template_content: str) -> list[_ExecutableTemplateSpan]:
        if HAS_JINJA2_SANDBOX:
            lexer_spans = Jinja2TemplateScanner._jinja_lexer_executable_template_spans(template_content)
            if lexer_spans is not None:
                return lexer_spans
        return Jinja2TemplateScanner._delimiter_executable_template_spans(template_content)

    @staticmethod
    def _jinja_lexer_executable_template_spans(template_content: str) -> list[_ExecutableTemplateSpan] | None:
        spans: list[_ExecutableTemplateSpan] = []
        active_start: int | None = None
        cursor = 0

        try:
            tokens = jinja2.Environment().lex(template_content)
            for _lineno, token_type, token_value in tokens:
                token_start = cursor
                token_end = token_start + len(token_value)
                if template_content[token_start:token_end] != token_value:
                    return None

                if token_type in {"variable_begin", "block_begin"}:
                    active_start = token_start
                if active_start is not None and token_type in {"variable_end", "block_end"}:
                    spans.append(_ExecutableTemplateSpan(template_content[active_start:token_end]))
                    active_start = None

                cursor = token_end
        except Exception:
            return None

        if active_start is not None:
            spans.append(_ExecutableTemplateSpan(template_content[active_start:cursor]))
        return spans

    @staticmethod
    def _delimiter_executable_template_spans(template_content: str) -> list[_ExecutableTemplateSpan]:
        spans: list[_ExecutableTemplateSpan] = []
        cursor = 0
        while cursor < len(template_content):
            marker_start, marker = Jinja2TemplateScanner._next_jinja_marker(template_content, cursor)
            if marker_start is None or marker is None:
                break

            if marker == "{#":
                cursor = Jinja2TemplateScanner._find_jinja_tag_end(
                    template_content,
                    marker_start,
                    "#}",
                    quote_aware=False,
                )
                continue

            if marker == "{{":
                span_end = Jinja2TemplateScanner._find_jinja_tag_end(template_content, marker_start, "}}")
                spans.append(_ExecutableTemplateSpan(template_content[marker_start:span_end]))
                cursor = max(span_end, marker_start + len(marker))
                continue

            span_end = Jinja2TemplateScanner._find_jinja_tag_end(template_content, marker_start, "%}")
            span_text = template_content[marker_start:span_end]
            tag_name = Jinja2TemplateScanner._jinja_block_tag_name(span_text)
            if tag_name == "raw":
                cursor = Jinja2TemplateScanner._find_jinja_raw_end(template_content, span_end)
                continue

            spans.append(_ExecutableTemplateSpan(span_text))
            cursor = max(span_end, marker_start + len(marker))

        return spans

    @staticmethod
    def _next_jinja_marker(template_content: str, cursor: int) -> tuple[int | None, str | None]:
        next_marker_start: int | None = None
        next_marker: str | None = None
        for marker in ("{{", "{%", "{#"):
            marker_start = template_content.find(marker, cursor)
            if marker_start != -1 and (next_marker_start is None or marker_start < next_marker_start):
                next_marker_start = marker_start
                next_marker = marker
        return next_marker_start, next_marker

    @staticmethod
    def _find_jinja_tag_end(
        template_content: str,
        marker_start: int,
        end_token: str,
        *,
        quote_aware: bool = True,
    ) -> int:
        cursor = marker_start + 2
        quote: str | None = None
        escaped = False
        while cursor < len(template_content):
            character = template_content[cursor]
            if quote is not None:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = None
                cursor += 1
                continue

            if quote_aware and character in {"'", '"'}:
                quote = character
                cursor += 1
                continue

            if template_content.startswith(end_token, cursor):
                return cursor + len(end_token)
            cursor += 1

        return len(template_content)

    @staticmethod
    def _jinja_block_tag_name(span_text: str) -> str:
        if not span_text.startswith("{%"):
            return ""
        if span_text.endswith("%}"):
            span_text = span_text[:-2]
        inner = span_text[2:].strip(" \t\r\n-+")
        return inner.split(None, 1)[0].lower() if inner else ""

    @staticmethod
    def _find_jinja_raw_end(template_content: str, cursor: int) -> int:
        while cursor < len(template_content):
            block_start = template_content.find("{%", cursor)
            if block_start == -1:
                return len(template_content)
            block_end = Jinja2TemplateScanner._find_jinja_tag_end(
                template_content,
                block_start,
                "%}",
                quote_aware=False,
            )
            block_text = template_content[block_start:block_end]
            if Jinja2TemplateScanner._jinja_block_tag_name(block_text) == "endraw":
                return block_end
            cursor = block_start + 2
        return len(template_content)

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
        return self._template_ast_has_oversized_sandbox_range_call(
            parsed,
            preflight_only=True,
        ) or self._template_ast_has_static_repeated_sequence_budget_risk(parsed)

    def _template_has_static_sandbox_risk(self, template_content: str) -> bool:
        return any(
            re.search(r"\.\s*__\w+__", executable_span.text)
            or re.search(r"\|\s*attr\s*\(\s*['\"]__\w+__", executable_span.text)
            or re.search(r"\[\s*['\"]__\w+__['\"]\s*\]", executable_span.text)
            for executable_span in self._executable_template_spans(template_content)
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

    def _template_ast_has_oversized_sandbox_range_call(self, parsed: Any, *, preflight_only: bool = False) -> bool:
        range_aliases = {"range"}
        int_bindings: dict[str, _StaticIntBinding] = {}
        namespace_range_attrs: dict[str, set[str]] = {}
        macro_bindings: dict[str, tuple[Any, ...]] = {}
        try:
            return self._static_node_has_oversized_sandbox_range_call(
                parsed,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
                macro_bindings,
                _StaticMacroAnalysisState(preflight_only=preflight_only),
            )
        except _StaticAnalysisBudgetExceeded:
            return True

    def _static_node_has_oversized_sandbox_range_call(
        self,
        node: Any,
        range_aliases: set[str],
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
        macro_bindings: dict[str, tuple[Any, ...]],
        active_macros: set[int],
    ) -> bool:
        if isinstance(active_macros, _StaticMacroAnalysisState) and not active_macros.consume():
            return True
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
            if (
                isinstance(active_macros, _StaticMacroAnalysisState)
                and isinstance(node.target, jinja2.nodes.Tuple)
                and isinstance(node.node, jinja2.nodes.List | jinja2.nodes.Tuple)
            ):
                binding_width = (
                    len(range_aliases)
                    + len(int_bindings)
                    + len(macro_bindings)
                    + sum(len(attrs) for attrs in namespace_range_attrs.values())
                )
                if not active_macros.consume(len(node.target.items) * max(1, binding_width)):
                    return True
            self._collect_static_range_assignment(
                node.target,
                node.node,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
            )
            self._collect_static_macro_assignment(
                node.target,
                node.node,
                macro_bindings,
                namespace_range_attrs,
                range_aliases,
            )
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
            if isinstance(node.target, jinja2.nodes.Name):
                range_aliases.add(self._static_defined_binding_key(node.target.name))
                macro_bindings[self._static_defined_binding_key(node.target.name)] = ()
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
            range_aliases.add(self._static_defined_binding_key(node.name))
            macro_bindings[self._static_defined_binding_key(node.name)] = ()
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
            if not (
                isinstance(active_macros, _StaticMacroAnalysisState) and active_macros.preflight_only
            ) and self._static_range_iterable_exceeds_budget(
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

            literal_items = self._static_literal_iterable_items(node.iter)
            iteration_count: int | None = len(literal_items) if literal_items is not None else None
            range_call = self._static_iterable_range_call(
                node.iter,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
            )
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
                    self._collect_static_macro_assignment(
                        node.target,
                        item,
                        item_macro_bindings,
                        item_namespace_attrs,
                        item_aliases,
                    )

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
                        test_condition = self._constant_condition_value(node.test, item_int_bindings)
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
                self._collect_static_macro_assignment(
                    target,
                    value,
                    with_macro_bindings,
                    with_namespace_attrs,
                    with_aliases,
                )
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
            and (
                not isinstance(active_macros, _StaticMacroAnalysisState)
                or not active_macros.preflight_only
                or node.name in {"list", "join"}
            )
            and self._static_range_filter_exceeds_budget(
                node,
                max(1, self.sandbox_render_max_output_chars),
                range_aliases,
                int_bindings,
                namespace_range_attrs,
                active_macros if isinstance(active_macros, _StaticMacroAnalysisState) else None,
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

        normalized_range_call = self._range_call_with_static_unpacking(node, int_bindings)
        if (
            not (isinstance(active_macros, _StaticMacroAnalysisState) and active_macros.preflight_only)
            and normalized_range_call is not None
            and self._is_static_range_callable(
                normalized_range_call.node,
                range_aliases,
                namespace_range_attrs,
            )
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
        for macro in macros:
            if isinstance(active_macros, _StaticMacroAnalysisState) and not active_macros.consume():
                return True
            if id(macro) in active_macros:
                normalized_arguments = self._static_macro_call_arguments(
                    node,
                    int_bindings,
                    namespace_range_attrs,
                    macro_bindings,
                )
                if normalized_arguments is None:
                    continue
                positional_arguments, keyword_arguments = normalized_arguments
                if any(
                    self._is_static_range_callable(value, range_aliases, namespace_range_attrs)
                    for value in [*positional_arguments, *(value for _, value in keyword_arguments)]
                ):
                    return True
                continue
            if self._static_single_macro_call_has_oversized_sandbox_range_call(
                node,
                macro,
                range_aliases,
                int_bindings,
                namespace_range_attrs,
                macro_bindings,
                active_macros,
            ):
                return True
        return False

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
        normalized_arguments = self._static_macro_call_arguments(
            node,
            int_bindings,
            namespace_range_attrs,
            macro_bindings,
        )
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

        supplied_arguments = {
            argument.name: value for argument, value in zip(macro.args, positional_arguments, strict=False)
        }
        supplied_arguments.update(dict(keyword_arguments))
        default_offset = len(macro.args) - len(macro.defaults)
        projected_argument_count = len(macro.args)
        if accepts_varargs:
            projected_argument_count += max(0, len(positional_arguments) - len(macro.args))
        if accepts_kwargs:
            projected_argument_count += sum(name not in argument_names for name, _ in keyword_arguments)
        if (
            projected_argument_count
            and isinstance(active_macros, _StaticMacroAnalysisState)
            and not active_macros.consume(projected_argument_count * max(1, len(int_bindings)))
        ):
            return True

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

        namespace_argument_sources: dict[str, tuple[tuple[str, ...], set[str]]] = {}
        for index, argument in enumerate(macro.args):
            value = supplied_arguments.get(argument.name)
            uses_default = False
            if value is None and index >= default_offset:
                value = macro.defaults[index - default_offset]
                uses_default = True
            if value is None:
                continue
            namespace_source_names: tuple[str, ...] = ()
            if isinstance(value, jinja2.nodes.Name) and value.name in namespace_range_attrs:
                call_source_attrs = namespace_range_attrs[value.name]
                namespace_source_names = tuple(
                    name for name, attrs in namespace_range_attrs.items() if attrs is call_source_attrs
                )
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
            if namespace_source_names and argument.name in macro_namespace_attrs:
                namespace_argument_sources[argument.name] = (
                    namespace_source_names,
                    macro_namespace_attrs[argument.name],
                )

        if accepts_kwargs:
            macro_aliases.discard("kwargs")
            macro_aliases.add(self._static_defined_binding_key("kwargs"))
            macro_namespace_attrs.pop("kwargs", None)
            macro_int_bindings.pop("kwargs", None)
            nested_macro_bindings.pop("kwargs", None)
            nested_macro_bindings[self._static_defined_binding_key("kwargs")] = ()
            for binding_name in [
                binding_name
                for binding_name in macro_int_bindings
                if binding_name.startswith(self._static_container_binding_prefixes("kwargs"))
            ]:
                macro_int_bindings.pop(binding_name, None)
            for binding_name in [
                binding_name
                for binding_name in nested_macro_bindings
                if binding_name.startswith(self._static_container_binding_prefixes("kwargs"))
            ]:
                nested_macro_bindings.pop(binding_name, None)
            kwargs_range_attrs = {self._static_container_kind_attr_key("mapping")}
            macro_int_bindings[self._static_container_kind_binding_key("kwargs", "mapping")] = (
                self._constant_int_result(1, _SANDBOX_MAX_RANGE_ITERATIONS)
            )
            for keyword_name, keyword_value in keyword_arguments:
                if keyword_name in argument_names:
                    continue
                keyword_path = (keyword_name,)
                kwargs_range_attrs.add(self._static_container_member_attr_key(keyword_path))
                macro_int_bindings[self._static_container_member_binding_key("kwargs", keyword_path)] = (
                    self._constant_int_result(1, _SANDBOX_MAX_RANGE_ITERATIONS)
                )
                if self._is_static_range_callable(keyword_value, range_aliases, namespace_range_attrs):
                    kwargs_range_attrs.add(self._static_container_attr_key(keyword_path))
                int_results = self._constant_int_expression_results_with_bindings(
                    keyword_value,
                    _SANDBOX_MAX_RANGE_ITERATIONS,
                    int_bindings,
                )
                value_binding = self._make_static_int_binding(int_results)
                if value_binding is None:
                    scalar_value = self._constant_scalar_expression_value(keyword_value, int_bindings)
                    if scalar_value is not None:
                        value_binding = _StaticScalarValue(scalar_value)
                if value_binding is not None:
                    macro_int_bindings[self._static_container_binding_key("kwargs", keyword_path)] = value_binding
                keyword_macros = self._static_macro_binding_for_node(keyword_value, macro_bindings)
                if keyword_macros:
                    nested_macro_bindings[self._static_container_binding_key("kwargs", (keyword_name,))] = (
                        keyword_macros
                    )
            macro_namespace_attrs["kwargs"] = kwargs_range_attrs

        if accepts_varargs:
            extra_arguments = positional_arguments[len(macro.args) :]
            macro_aliases.discard("varargs")
            macro_aliases.add(self._static_defined_binding_key("varargs"))
            macro_namespace_attrs.pop("varargs", None)
            macro_int_bindings.pop("varargs", None)
            nested_macro_bindings.pop("varargs", None)
            nested_macro_bindings[self._static_defined_binding_key("varargs")] = ()
            for binding_name in [
                binding_name
                for binding_name in macro_int_bindings
                if binding_name.startswith(self._static_container_binding_prefixes("varargs"))
            ]:
                macro_int_bindings.pop(binding_name, None)
            for binding_name in [
                binding_name
                for binding_name in nested_macro_bindings
                if binding_name.startswith(self._static_container_binding_prefixes("varargs"))
            ]:
                nested_macro_bindings.pop(binding_name, None)
            varargs_range_attrs = {self._static_container_kind_attr_key("sequence")}
            macro_int_bindings[self._static_container_kind_binding_key("varargs", "sequence")] = (
                self._constant_int_result(1, _SANDBOX_MAX_RANGE_ITERATIONS)
            )
            macro_int_bindings[self._static_container_length_key("varargs")] = self._constant_int_result(
                len(extra_arguments),
                _SANDBOX_MAX_RANGE_ITERATIONS,
            )
            for index, value in enumerate(extra_arguments):
                vararg_path = (index,)
                varargs_range_attrs.add(self._static_container_member_attr_key(vararg_path))
                macro_int_bindings[self._static_container_member_binding_key("varargs", vararg_path)] = (
                    self._constant_int_result(1, _SANDBOX_MAX_RANGE_ITERATIONS)
                )
                if self._is_static_range_callable(value, range_aliases, namespace_range_attrs):
                    varargs_range_attrs.add(self._static_container_attr_key(vararg_path))
                int_results = self._constant_int_expression_results_with_bindings(
                    value,
                    _SANDBOX_MAX_RANGE_ITERATIONS,
                    int_bindings,
                )
                value_binding = self._make_static_int_binding(int_results)
                if value_binding is None:
                    scalar_value = self._constant_scalar_expression_value(value, int_bindings)
                    if scalar_value is not None:
                        value_binding = _StaticScalarValue(scalar_value)
                if value_binding is not None:
                    macro_int_bindings[self._static_container_binding_key("varargs", vararg_path)] = value_binding
                vararg_macros = self._static_macro_binding_for_node(value, macro_bindings)
                if vararg_macros:
                    nested_macro_bindings[self._static_container_binding_key("varargs", (index,))] = vararg_macros
            macro_namespace_attrs["varargs"] = varargs_range_attrs

        nested_active_macros = (
            active_macros.nested(id(macro))
            if isinstance(active_macros, _StaticMacroAnalysisState)
            else {*active_macros, id(macro)}
        )
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
        for argument_name, (source_names, bound_argument_attrs) in namespace_argument_sources.items():
            if macro_namespace_attrs.get(argument_name) is not bound_argument_attrs:
                continue
            argument_prefix = f"{argument_name}."
            argument_macro_attrs = {
                name.removeprefix(argument_prefix): macros
                for name, macros in nested_macro_bindings.items()
                if name.startswith(argument_prefix)
            }
            for source_name in source_names:
                outer_source_attrs = namespace_range_attrs.get(source_name)
                if outer_source_attrs is None:
                    continue
                if outer_source_attrs is not bound_argument_attrs:
                    outer_source_attrs.clear()
                    outer_source_attrs.update(bound_argument_attrs)
                source_prefix = f"{source_name}."
                for name in [name for name in macro_bindings if name.startswith(source_prefix)]:
                    macro_bindings.pop(name, None)
                for attribute, macros in argument_macro_attrs.items():
                    macro_bindings[f"{source_prefix}{attribute}"] = macros
        return False

    def _static_macro_call_arguments(
        self,
        node: Any,
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
        macro_bindings: dict[str, tuple[Any, ...]],
    ) -> tuple[list[Any], list[tuple[str, Any]]] | None:
        positional_arguments = list(node.args)
        if node.dyn_args is not None:
            if isinstance(node.dyn_args, jinja2.nodes.List | jinja2.nodes.Tuple):
                positional_arguments.extend(node.dyn_args.items)
            elif isinstance(node.dyn_args, jinja2.nodes.Name):
                bound_arguments = self._static_bound_sequence_arguments(
                    node.dyn_args.name,
                    int_bindings,
                    namespace_range_attrs,
                    macro_bindings,
                )
                if bound_arguments is None:
                    return None
                positional_arguments.extend(bound_arguments)
            else:
                return None

        keyword_arguments = [(keyword.key, keyword.value) for keyword in node.kwargs]
        if node.dyn_kwargs is not None:
            if isinstance(node.dyn_kwargs, jinja2.nodes.Dict):
                for pair in node.dyn_kwargs.items:
                    if not isinstance(pair.key, jinja2.nodes.Const) or not isinstance(pair.key.value, str):
                        return None
                    keyword_arguments.append((pair.key.value, pair.value))
            elif isinstance(node.dyn_kwargs, jinja2.nodes.Name):
                bound_keywords = self._static_bound_mapping_arguments(
                    node.dyn_kwargs.name,
                    int_bindings,
                    namespace_range_attrs,
                    macro_bindings,
                )
                if bound_keywords is None:
                    return None
                keyword_arguments.extend(bound_keywords)
            else:
                return None
        return positional_arguments, keyword_arguments

    def _static_bound_sequence_arguments(
        self,
        name: str,
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
        macro_bindings: dict[str, tuple[Any, ...]],
    ) -> list[Any] | None:
        length_binding = int_bindings.get(self._static_container_length_key(name))
        if not isinstance(length_binding, tuple) or length_binding[1]:
            return None
        return [
            self._static_bound_container_value_node(
                name,
                index,
                namespace_range_attrs,
                macro_bindings,
            )
            for index in range(length_binding[0])
        ]

    def _static_bound_mapping_arguments(
        self,
        name: str,
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
        macro_bindings: dict[str, tuple[Any, ...]],
    ) -> list[tuple[str, Any]] | None:
        keys = {
            path[0]
            for attr in namespace_range_attrs.get(name, set())
            if (path := self._static_container_path_from_attr_key(attr)) is not None
            and len(path) == 1
            and isinstance(path[0], str)
        }
        keys.update(
            path[0]
            for attr in namespace_range_attrs.get(name, set())
            if (path := self._static_container_member_path_from_attr_key(attr)) is not None
            and len(path) == 1
            and isinstance(path[0], str)
        )
        for binding in [*int_bindings, *macro_bindings]:
            path = self._static_container_path_from_binding_key(name, binding)
            if path is not None and len(path) == 1 and isinstance(path[0], str):
                keys.add(path[0])
        known_mapping = self._static_container_kind_binding_key(name, "mapping") in int_bindings
        if not keys and not known_mapping:
            return None
        return [
            (
                key,
                self._static_bound_container_value_node(
                    name,
                    key,
                    namespace_range_attrs,
                    macro_bindings,
                ),
            )
            for key in sorted(keys)
        ]

    @classmethod
    def _static_bound_container_value_node(
        cls,
        name: str,
        key: str | int | float,
        namespace_range_attrs: dict[str, set[str]],
        macro_bindings: dict[str, tuple[Any, ...]],
    ) -> Any:
        path = (key,)
        if cls._static_container_attr_key(path) in namespace_range_attrs.get(name, set()):
            return jinja2.nodes.Name("range", "load")
        binding_name = cls._static_container_binding_key(name, path)
        if binding_name in macro_bindings:
            return jinja2.nodes.Name(binding_name, "load")
        return jinja2.nodes.Name(binding_name, "load")

    @staticmethod
    def _static_container_length_key(name: str) -> str:
        return f"{name}\0length"

    @staticmethod
    def _static_defined_binding_key(name: str) -> str:
        return f"\0defined:{name}"

    @staticmethod
    def _static_int_binding_is_definitely_present(
        int_bindings: dict[str, _StaticIntBinding],
        name: str,
    ) -> bool:
        binding = int_bindings.get(name)
        return binding is not None and not (isinstance(binding, _StaticIntCandidates) and binding.may_be_undefined)

    def _static_value_is_definitely_defined(
        self,
        node: Any,
        range_aliases: set[str],
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
        depth: int = 0,
    ) -> bool:
        if depth > 32:
            return False
        if isinstance(node, jinja2.nodes.Const | jinja2.nodes.List | jinja2.nodes.Tuple | jinja2.nodes.Dict):
            return True
        if isinstance(node, jinja2.nodes.Name):
            return (
                self._static_defined_binding_key(node.name) in range_aliases
                or self._static_int_binding_is_definitely_present(int_bindings, node.name)
                or node.name in namespace_range_attrs
            )
        if self._is_static_range_callable(node, range_aliases, namespace_range_attrs):
            return True
        access = self._static_container_access_path(node)
        if access is not None:
            name, path = access
            binding_name = name if not path else self._static_container_binding_key(name, path)
            if self._static_int_binding_is_definitely_present(int_bindings, binding_name):
                return True
            if path and self._static_int_binding_is_definitely_present(
                int_bindings,
                self._static_container_member_binding_key(name, path),
            ):
                return True
        if self._constant_int_expression_results_with_bindings(
            node,
            _SANDBOX_MAX_RANGE_ITERATIONS,
            int_bindings,
        ):
            return True
        if self._constant_scalar_expression_value(node, int_bindings) is not None:
            return True
        if (
            isinstance(node, jinja2.nodes.Call)
            and isinstance(node.node, jinja2.nodes.Name)
            and node.node.name == "namespace"
        ):
            return True
        if (
            isinstance(node, jinja2.nodes.Filter)
            and node.name in {"d", "default"}
            and not node.kwargs
            and node.dyn_args is None
            and node.dyn_kwargs is None
            and len(node.args) <= 2
        ):
            if not node.args:
                return True
            return self._static_value_is_definitely_defined(
                node.args[0],
                range_aliases,
                int_bindings,
                namespace_range_attrs,
                depth + 1,
            )
        if isinstance(node, jinja2.nodes.CondExpr):
            condition = self._constant_condition_value(node.test, int_bindings)
            if condition is not None:
                selected = node.expr1 if condition else node.expr2
                return selected is not None and self._static_value_is_definitely_defined(
                    selected,
                    range_aliases,
                    int_bindings,
                    namespace_range_attrs,
                    depth + 1,
                )
            return node.expr2 is not None and all(
                self._static_value_is_definitely_defined(
                    branch,
                    range_aliases,
                    int_bindings,
                    namespace_range_attrs,
                    depth + 1,
                )
                for branch in (node.expr1, node.expr2)
            )
        return False

    @staticmethod
    def _static_container_path_token(path: tuple[str | int | float, ...]) -> str:
        return "\0path:" + json.dumps(path, separators=(",", ":"), ensure_ascii=True)

    @classmethod
    def _static_container_attr_key(cls, path: tuple[str | int | float, ...]) -> str:
        return cls._static_container_path_token(path)

    @staticmethod
    def _static_container_path_from_attr_key(key: str) -> tuple[str | int | float, ...] | None:
        if key.startswith("\0") and not key.startswith("\0path:"):
            return None
        if not key.startswith("\0path:"):
            return (key,)
        try:
            values = json.loads(key.removeprefix("\0path:"))
        except (TypeError, ValueError):
            return None
        if not isinstance(values, list) or not all(isinstance(value, str | int | float) for value in values):
            return None
        return tuple(values)

    @classmethod
    def _static_container_binding_key(cls, name: str, path: tuple[str | int | float, ...]) -> str:
        return f"{name}{cls._static_container_attr_key(path)}"

    @staticmethod
    def _static_container_member_attr_key(path: tuple[str | int | float, ...]) -> str:
        return "\0member:" + json.dumps(path, separators=(",", ":"), ensure_ascii=True)

    @staticmethod
    def _static_container_member_path_from_attr_key(key: str) -> tuple[str | int | float, ...] | None:
        if not key.startswith("\0member:"):
            return None
        try:
            values = json.loads(key.removeprefix("\0member:"))
        except (TypeError, ValueError):
            return None
        if not isinstance(values, list) or not all(isinstance(value, str | int | float) for value in values):
            return None
        return tuple(values)

    @classmethod
    def _static_container_member_binding_key(cls, name: str, path: tuple[str | int | float, ...]) -> str:
        return f"{name}{cls._static_container_member_attr_key(path)}"

    @staticmethod
    def _static_container_kind_attr_key(kind: str, path: tuple[str | int | float, ...] = ()) -> str:
        return f"\0kind:{kind}:" + json.dumps(path, separators=(",", ":"), ensure_ascii=True)

    @classmethod
    def _static_container_kind_binding_key(
        cls,
        name: str,
        kind: str,
        path: tuple[str | int | float, ...] = (),
    ) -> str:
        return f"{name}{cls._static_container_kind_attr_key(kind, path)}"

    @classmethod
    def _static_container_access_path(cls, node: Any) -> tuple[str, tuple[str | int | float, ...]] | None:
        if isinstance(node, jinja2.nodes.Name):
            return node.name, ()
        if isinstance(node, jinja2.nodes.Getitem):
            access = cls._static_container_access_path(node.node)
            key = cls._static_literal_container_key(node.arg)
        elif isinstance(node, jinja2.nodes.Getattr):
            access = cls._static_container_access_path(node.node)
            key = node.attr
        elif (
            isinstance(node, jinja2.nodes.Call)
            and isinstance(node.node, jinja2.nodes.Getattr)
            and node.node.attr == "get"
            and not node.kwargs
            and node.dyn_args is None
            and node.dyn_kwargs is None
            and 1 <= len(node.args) <= 2
        ):
            access = cls._static_container_access_path(node.node.node)
            key = cls._static_literal_container_key(node.args[0])
        else:
            return None
        if access is None or key is None:
            return None
        name, path = access
        return name, (*path, key)

    @classmethod
    def _static_container_binding_prefixes(cls, name: str) -> tuple[str, ...]:
        return f"{name}.", f"{name}\0path:", f"{name}\0member:", f"{name}\0kind:"

    @classmethod
    def _static_container_path_from_binding_key(
        cls,
        name: str,
        binding: str,
    ) -> tuple[str | int | float, ...] | None:
        if binding.startswith(f"{name}\0path:"):
            return cls._static_container_path_from_attr_key(binding[len(name) :])
        if binding.startswith(f"{name}."):
            return (binding.removeprefix(f"{name}."),)
        return None

    @classmethod
    def _static_rebased_container_binding_key(cls, binding: str, source: str, target: str) -> str | None:
        for prefix in cls._static_container_binding_prefixes(source):
            if binding.startswith(prefix):
                return target + binding[len(source) :]
        return None

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
        value_is_definitely_defined = self._static_value_is_definitely_defined(
            value,
            source_aliases,
            source_int_bindings,
            source_namespace_attrs,
        )
        defined_key = self._static_defined_binding_key(target.name)
        if value_is_definitely_defined:
            range_aliases.add(defined_key)
            macro_bindings[defined_key] = ()
        if self._is_static_range_callable(value, source_aliases, source_namespace_attrs):
            range_aliases.add(target.name)
        int_results = self._constant_int_expression_results_with_bindings(
            value,
            _SANDBOX_MAX_RANGE_ITERATIONS,
            source_int_bindings,
        )
        int_binding = self._make_static_int_binding(int_results)
        if int_binding is None:
            scalar_value = self._constant_scalar_expression_value(value, source_int_bindings)
            if scalar_value is not None:
                int_binding = _StaticScalarValue(scalar_value)
        if int_binding is not None:
            int_bindings[target.name] = int_binding
        if isinstance(value, jinja2.nodes.Name):
            if value.name in source_namespace_attrs:
                namespace_range_attrs[target.name] = source_namespace_attrs[value.name]
            for name, namespace_macro in source_macro_bindings.items():
                rebased = self._static_rebased_container_binding_key(name, value.name, target.name)
                if rebased is not None:
                    macro_bindings[rebased] = namespace_macro
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
            macro_bindings.pop(cls._static_defined_binding_key(target.name), None)
            prefixes = cls._static_container_binding_prefixes(target.name)
            for name in [name for name in macro_bindings if name.startswith(prefixes)]:
                macro_bindings.pop(name, None)

    @classmethod
    def _static_macro_binding_key(cls, node: Any) -> str | None:
        access = cls._static_container_access_path(node)
        if access is None:
            return None
        name, path = access
        return name if not path else cls._static_container_binding_key(name, path)

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
        if (
            isinstance(node, jinja2.nodes.Filter)
            and node.name in {"d", "default"}
            and not node.kwargs
            and node.dyn_args is None
            and node.dyn_kwargs is None
            and len(node.args) <= 2
        ):
            source_macros = cls._static_macro_binding_for_node(node.node, macro_bindings)
            source_is_defined = cls._static_macro_value_is_definitely_defined(
                node.node,
                macro_bindings,
            )
            if source_macros and source_is_defined:
                return source_macros
            fallback_possible = cls._static_default_filter_may_use_fallback(node)
            if fallback_possible and source_is_defined:
                boolean_mode = cls._constant_condition_value(node.args[1]) if len(node.args) == 2 else False
                fallback_possible = boolean_mode is not False
            candidates = list(source_macros)
            if node.args and fallback_possible:
                candidates.extend(cls._static_macro_binding_for_node(node.args[0], macro_bindings))
            return tuple(dict.fromkeys(candidates))
        literal_item = cls._static_literal_container_item(node)
        if literal_item is not None:
            return cls._static_macro_binding_for_node(literal_item, macro_bindings)
        if (
            isinstance(node, jinja2.nodes.Call)
            and isinstance(node.node, jinja2.nodes.Getattr)
            and node.node.attr == "get"
            and not node.kwargs
            and node.dyn_args is None
            and node.dyn_kwargs is None
            and 1 <= len(node.args) <= 2
        ):
            container_access = cls._static_container_access_path(node.node.node)
            key_value = cls._static_literal_container_key(node.args[0])
            if container_access is not None and key_value is not None:
                name, container_path = container_access
                path = (*container_path, key_value)
                binding_key = cls._static_container_binding_key(name, path)
                known_mapping = (
                    cls._static_container_kind_binding_key(name, "mapping", container_path) in macro_bindings
                )
                member_exists = cls._static_container_member_binding_key(name, path) in macro_bindings
                candidates = list(macro_bindings.get(binding_key, ()))
                if known_mapping and not member_exists and len(node.args) == 2:
                    candidates.extend(cls._static_macro_binding_for_node(node.args[1], macro_bindings))
                if candidates:
                    return tuple(dict.fromkeys(candidates))
                if known_mapping:
                    return ()
        if isinstance(node, jinja2.nodes.Getattr):
            access = cls._static_container_access_path(node)
            if access is not None:
                name, path = access
                if (
                    path
                    and cls._static_container_kind_binding_key(name, "mapping", path[:-1]) in macro_bindings
                    and isinstance(path[-1], str)
                    and hasattr({}, path[-1])
                ):
                    return ()
        key = cls._static_macro_binding_key(node)
        if key is not None and key in macro_bindings:
            return macro_bindings[key]
        if isinstance(node, jinja2.nodes.Getattr) and isinstance(node.node, jinja2.nodes.Name):
            return macro_bindings.get(f"{node.node.name}.{node.attr}", ())
        return ()

    @classmethod
    def _static_macro_value_is_definitely_defined(
        cls,
        node: Any,
        macro_bindings: dict[str, tuple[Any, ...]],
    ) -> bool:
        if isinstance(node, jinja2.nodes.Name):
            return cls._static_defined_binding_key(node.name) in macro_bindings
        access = cls._static_container_access_path(node)
        if access is None:
            return False
        name, path = access
        if not path:
            return cls._static_defined_binding_key(name) in macro_bindings
        if cls._static_container_member_binding_key(name, path) in macro_bindings:
            return True
        return bool(
            isinstance(node, jinja2.nodes.Getattr)
            and cls._static_container_kind_binding_key(name, "mapping", path[:-1]) in macro_bindings
            and isinstance(path[-1], str)
            and hasattr({}, path[-1])
        )

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
        namespace_range_attrs: dict[str, set[str]],
        range_aliases: set[str],
    ) -> None:
        if isinstance(target, jinja2.nodes.Tuple) and isinstance(value, jinja2.nodes.List | jinja2.nodes.Tuple):
            if len(target.items) != len(value.items):
                cls._clear_static_macro_binding(target, macro_bindings)
                return
            original_bindings = dict(macro_bindings)
            cls._clear_static_macro_binding(target, macro_bindings)
            for item_target, item_value in zip(target.items, value.items, strict=False):
                if not isinstance(item_target, jinja2.nodes.Name):
                    continue
                defined_key = cls._static_defined_binding_key(item_target.name)
                if defined_key in range_aliases:
                    macro_bindings[defined_key] = ()
                source_macros = cls._static_macro_binding_for_node(item_value, original_bindings)
                if source_macros:
                    macro_bindings[item_target.name] = source_macros
            return
        original_bindings = dict(macro_bindings)
        source_macros = cls._static_macro_binding_for_node(value, original_bindings)
        cls._clear_static_macro_binding(target, macro_bindings)
        if isinstance(target, jinja2.nodes.NSRef):
            if target.name in namespace_range_attrs:
                macro_bindings[cls._static_container_member_binding_key(target.name, (target.attr,))] = ()
                if source_macros:
                    macro_bindings[f"{target.name}.{target.attr}"] = source_macros
            return
        if isinstance(target, jinja2.nodes.Name) and source_macros:
            macro_bindings[target.name] = source_macros
        if not isinstance(target, jinja2.nodes.Name):
            return
        defined_key = cls._static_defined_binding_key(target.name)
        if defined_key in range_aliases:
            macro_bindings[defined_key] = ()
        container_entries = cls._static_literal_container_entries(value)
        if container_entries is not None:
            for kind_path, container_kind in cls._static_literal_container_kind_paths(value):
                macro_bindings[cls._static_container_kind_binding_key(target.name, container_kind, kind_path)] = ()
            for path, item in cls._static_literal_container_leaf_entries(value):
                for prefix_length in range(1, len(path) + 1):
                    macro_bindings[cls._static_container_member_binding_key(target.name, path[:prefix_length])] = ()
                item_macros = cls._static_macro_binding_for_node(item, original_bindings)
                if item_macros:
                    macro_bindings[cls._static_container_binding_key(target.name, path)] = item_macros
            return
        if (
            isinstance(value, jinja2.nodes.Call)
            and isinstance(value.node, jinja2.nodes.Name)
            and value.node.name == "namespace"
        ):
            for keyword in value.kwargs:
                macro_bindings[cls._static_container_member_binding_key(target.name, (keyword.key,))] = ()
                keyword_macros = cls._static_macro_binding_for_node(keyword.value, original_bindings)
                if keyword_macros:
                    macro_bindings[f"{target.name}.{keyword.key}"] = keyword_macros
        elif isinstance(value, jinja2.nodes.Name) and value.name in namespace_range_attrs:
            for name, namespace_macro in original_bindings.items():
                rebased = cls._static_rebased_container_binding_key(name, value.name, target.name)
                if rebased is not None:
                    macro_bindings[rebased] = namespace_macro

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
        range_aliases.update(
            alias for aliases, _, _, _ in branch_states for alias in aliases if not alias.startswith("\0defined:")
        )
        defined_aliases = {
            alias for aliases, _, _, _ in branch_states for alias in aliases if alias.startswith("\0defined:")
        }
        range_aliases.update(
            alias for alias in defined_aliases if all(alias in aliases for aliases, _, _, _ in branch_states)
        )

        int_bindings.clear()
        int_names = {name for _, int_state_bindings, _, _ in branch_states for name in int_state_bindings}
        for name in int_names:
            candidates: list[_StaticBindingValue] = []
            truncated = False
            may_be_undefined = False
            for _, int_state_bindings, _, _ in branch_states:
                binding = int_state_bindings.get(name)
                if isinstance(binding, _StaticIntCandidates):
                    candidates.extend(binding.values)
                    truncated |= binding.truncated
                    may_be_undefined |= binding.may_be_undefined
                elif binding is not None:
                    candidates.append(binding)
                else:
                    may_be_undefined = True
            unique_candidates = tuple(dict.fromkeys(candidates))
            if not unique_candidates:
                continue
            if len(unique_candidates) == 1 and not truncated and not may_be_undefined:
                int_bindings[name] = unique_candidates[0]
            else:
                int_bindings[name] = _StaticIntCandidates(
                    unique_candidates,
                    truncated=truncated,
                    may_be_undefined=may_be_undefined,
                )

        namespace_range_attrs.clear()
        namespace_names = {name for _, _, attrs_by_name, _ in branch_states for name in attrs_by_name}
        for name in namespace_names:
            merged_attrs: set[str] = set()
            metadata_attrs = {
                attr
                for _, _, attrs_by_name, _ in branch_states
                for attr in attrs_by_name.get(name, set())
                if attr.startswith("\0kind:") or attr.startswith("\0member:")
            }
            merged_attrs.update(
                attr
                for attr in metadata_attrs
                if all(attr in attrs_by_name.get(name, set()) for _, _, attrs_by_name, _ in branch_states)
            )
            merged_attrs.update(
                attr
                for _, _, attrs_by_name, _ in branch_states
                for attr in attrs_by_name.get(name, set())
                if not attr.startswith("\0kind:") and not attr.startswith("\0member:")
            )
            if merged_attrs:
                namespace_range_attrs[name] = merged_attrs

        macro_bindings.clear()
        macro_names = {name for _, _, _, macro_state_bindings in branch_states for name in macro_state_bindings}
        for name in macro_names:
            if "\0kind:" in name or "\0member:" in name or name.startswith("\0defined:"):
                if all(name in macro_state_bindings for _, _, _, macro_state_bindings in branch_states):
                    macro_bindings[name] = ()
                continue
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
        range_call = self._static_iterable_range_call(
            node,
            range_aliases,
            int_bindings,
            namespace_range_attrs,
        )
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
        analysis_state: _StaticMacroAnalysisState | None = None,
    ) -> bool:
        range_call = self._static_iterable_range_call(
            node.node,
            range_aliases,
            int_bindings,
            namespace_range_attrs,
        )
        if range_call is None:
            return False
        if node.name in {"list", "join"} and analysis_state is not None:
            count = self._constant_range_iteration_count_with_bindings(
                range_call.args,
                _SANDBOX_MAX_RANGE_ITERATIONS,
                int_bindings,
            )
            if count is not None and not analysis_state.consume_range_items(min(count, _SANDBOX_MAX_RANGE_ITERATIONS)):
                return True
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
        int_bindings: dict[str, _StaticIntBinding],
        namespace_range_attrs: dict[str, set[str]],
    ) -> Any | None:
        while isinstance(node, jinja2.nodes.Filter) and node.name in _LAZY_RANGE_ITERATION_FILTERS:
            node = node.node
        normalized_range_call = self._range_call_with_static_unpacking(node, int_bindings)
        if normalized_range_call is not None and self._is_static_range_callable(
            normalized_range_call.node,
            range_aliases,
            namespace_range_attrs,
        ):
            return normalized_range_call
        return None

    def _range_call_with_static_unpacking(
        self,
        node: Any,
        int_bindings: dict[str, _StaticIntBinding],
    ) -> Any | None:
        normalized = self._range_call_with_literal_unpacking(node)
        if normalized is not None or not isinstance(node, jinja2.nodes.Call) or node.dyn_args is None:
            return normalized
        if not isinstance(node.dyn_args, jinja2.nodes.Name) or node.kwargs or node.dyn_kwargs is not None:
            return None
        length_binding = int_bindings.get(self._static_container_length_key(node.dyn_args.name))
        if not isinstance(length_binding, tuple) or length_binding[1]:
            return None
        arguments = [*node.args]
        arguments.extend(
            jinja2.nodes.Name(self._static_container_binding_key(node.dyn_args.name, (index,)), "load")
            for index in range(length_binding[0])
        )
        if not 1 <= len(arguments) <= 3:
            return None
        return jinja2.nodes.Call(node.node, arguments, [], None, None)

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
        range_aliases.discard(self._static_defined_binding_key(target.name))
        int_bindings.pop(target.name, None)
        int_bindings.pop(self._static_container_length_key(target.name), None)
        prefixes = self._static_container_binding_prefixes(target.name)
        for name in [name for name in int_bindings if name.startswith(prefixes)]:
            int_bindings.pop(name, None)
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
        if isinstance(target, jinja2.nodes.Tuple) and isinstance(value, jinja2.nodes.List | jinja2.nodes.Tuple):
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
            attrs.add(self._static_container_member_attr_key((target.attr,)))
            if self._is_static_range_callable(value, range_aliases, namespace_range_attrs):
                previous_size = len(attrs)
                attrs.add(target.attr)
                return len(attrs) != previous_size
            attrs.discard(target.attr)
            return True
        if not isinstance(target, jinja2.nodes.Name):
            return False

        value_is_definitely_defined = self._static_value_is_definitely_defined(
            value,
            range_aliases,
            int_bindings,
            namespace_range_attrs,
        )
        original_int_bindings = dict(int_bindings)
        changed = False
        if self._is_static_range_callable(value, range_aliases, namespace_range_attrs):
            previous_size = len(range_aliases)
            range_aliases.add(target.name)
            changed |= len(range_aliases) != previous_size
        else:
            range_aliases.discard(target.name)
        defined_key = self._static_defined_binding_key(target.name)
        if value_is_definitely_defined:
            range_aliases.add(defined_key)
        else:
            range_aliases.discard(defined_key)

        int_results = self._constant_int_expression_results_with_bindings(
            value,
            _SANDBOX_MAX_RANGE_ITERATIONS,
            int_bindings,
        )
        int_binding = self._make_static_int_binding(int_results)
        if int_binding is None:
            scalar_value = self._constant_scalar_expression_value(value, original_int_bindings)
            if scalar_value is not None:
                int_binding = _StaticScalarValue(scalar_value)
        if int_binding is not None and int_bindings.get(target.name) != int_binding:
            int_bindings[target.name] = int_binding
            changed = True
        elif int_binding is None:
            int_bindings.pop(target.name, None)

        int_bindings.pop(self._static_container_length_key(target.name), None)
        target_prefixes = self._static_container_binding_prefixes(target.name)
        for name in [name for name in int_bindings if name.startswith(target_prefixes)]:
            int_bindings.pop(name, None)

        container_entries = self._static_literal_container_entries(value)
        if container_entries is not None:
            entries, is_sequence = container_entries
            leaf_entries = self._static_literal_container_leaf_entries(value)
            container_attrs: set[str] = set()
            for kind_path, container_kind in self._static_literal_container_kind_paths(value):
                container_attrs.add(self._static_container_kind_attr_key(container_kind, kind_path))
                int_bindings[self._static_container_kind_binding_key(target.name, container_kind, kind_path)] = (
                    self._constant_int_result(1, _SANDBOX_MAX_RANGE_ITERATIONS)
                )
            for path, item in leaf_entries:
                for prefix_length in range(1, len(path) + 1):
                    member_path = path[:prefix_length]
                    container_attrs.add(self._static_container_member_attr_key(member_path))
                    int_bindings[self._static_container_member_binding_key(target.name, member_path)] = (
                        self._constant_int_result(1, _SANDBOX_MAX_RANGE_ITERATIONS)
                    )
                if self._is_static_range_callable(item, range_aliases, namespace_range_attrs):
                    container_attrs.add(self._static_container_attr_key(path))
            namespace_range_attrs[target.name] = container_attrs
            if is_sequence:
                int_bindings[self._static_container_length_key(target.name)] = self._constant_int_result(
                    len(entries),
                    _SANDBOX_MAX_RANGE_ITERATIONS,
                )
            for path, item in leaf_entries:
                nested_results = self._constant_int_expression_results_with_bindings(
                    item,
                    _SANDBOX_MAX_RANGE_ITERATIONS,
                    original_int_bindings,
                )
                nested_binding = self._make_static_int_binding(nested_results)
                if nested_binding is None:
                    scalar_value = self._constant_scalar_expression_value(item, original_int_bindings)
                    if scalar_value is not None:
                        nested_binding = _StaticScalarValue(scalar_value)
                if nested_binding is not None:
                    int_bindings[self._static_container_binding_key(target.name, path)] = nested_binding
            return True

        if (
            isinstance(value, jinja2.nodes.Call)
            and isinstance(value.node, jinja2.nodes.Name)
            and value.node.name == "namespace"
        ):
            attrs = {self._static_container_member_attr_key((keyword.key,)) for keyword in value.kwargs}
            attrs.update(
                keyword.key
                for keyword in value.kwargs
                if self._is_static_range_callable(keyword.value, range_aliases, namespace_range_attrs)
            )
            previous_attrs = namespace_range_attrs.get(target.name)
            namespace_range_attrs[target.name] = attrs
            if previous_attrs is not attrs:
                changed = True
        elif isinstance(value, jinja2.nodes.Name) and value.name in namespace_range_attrs:
            attrs = namespace_range_attrs[value.name]
            if namespace_range_attrs.get(target.name) is not attrs:
                namespace_range_attrs[target.name] = attrs
                changed = True
            source_length_key = self._static_container_length_key(value.name)
            if source_length_key in original_int_bindings:
                int_bindings[self._static_container_length_key(target.name)] = original_int_bindings[source_length_key]
            for name, binding in original_int_bindings.items():
                rebased = self._static_rebased_container_binding_key(name, value.name, target.name)
                if rebased is not None:
                    int_bindings[rebased] = binding
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
        defined_key = self._static_defined_binding_key(target.name)
        if defined_key in source_aliases:
            range_aliases.add(defined_key)
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
            isinstance(node, jinja2.nodes.Filter)
            and node.name in {"d", "default"}
            and not node.kwargs
            and node.dyn_args is None
            and node.dyn_kwargs is None
            and len(node.args) <= 2
        ):
            if cls._is_static_range_callable(node.node, range_aliases, namespace_range_attrs):
                return True
            fallback_possible = cls._static_default_filter_may_use_fallback(node)
            if fallback_possible and cls._static_range_value_is_definitely_defined(
                node.node,
                range_aliases,
                namespace_range_attrs,
            ):
                boolean_mode = cls._constant_condition_value(node.args[1]) if len(node.args) == 2 else False
                fallback_possible = boolean_mode is not False
            return bool(
                node.args
                and fallback_possible
                and cls._is_static_range_callable(node.args[0], range_aliases, namespace_range_attrs)
            )
        if (
            isinstance(node, jinja2.nodes.Filter)
            and node.name == "attr"
            and len(node.args) == 1
            and not node.kwargs
            and node.dyn_args is None
            and node.dyn_kwargs is None
            and isinstance(node.args[0], jinja2.nodes.Const)
            and isinstance(node.args[0].value, str)
        ):
            attr = node.args[0].value
            if (
                isinstance(node.node, jinja2.nodes.Call)
                and isinstance(node.node.node, jinja2.nodes.Name)
                and node.node.node.name == "namespace"
            ):
                return any(
                    keyword.key == attr
                    and cls._is_static_range_callable(keyword.value, range_aliases, namespace_range_attrs)
                    for keyword in node.node.kwargs
                )
            if isinstance(node.node, jinja2.nodes.Name):
                return attr in namespace_range_attrs.get(node.node.name, set())
        literal_item = cls._static_literal_container_item(node)
        if literal_item is not None:
            return cls._is_static_range_callable(literal_item, range_aliases, namespace_range_attrs)
        if (
            isinstance(node, jinja2.nodes.Call)
            and isinstance(node.node, jinja2.nodes.Getattr)
            and node.node.attr == "get"
            and not node.kwargs
            and node.dyn_args is None
            and node.dyn_kwargs is None
            and 1 <= len(node.args) <= 2
        ):
            container_access = cls._static_container_access_path(node.node.node)
            key = cls._static_literal_container_key(node.args[0])
            if container_access is not None and key is not None:
                name, container_path = container_access
                path = (*container_path, key)
                attrs = namespace_range_attrs.get(name, set())
                if cls._static_container_attr_key(path) in attrs:
                    return True
                known_mapping = cls._static_container_kind_attr_key("mapping", container_path) in attrs
                member_exists = cls._static_container_member_attr_key(path) in attrs
                if known_mapping and not member_exists and len(node.args) == 2:
                    return cls._is_static_range_callable(node.args[1], range_aliases, namespace_range_attrs)
                if known_mapping:
                    return False
        access = cls._static_container_access_path(node)
        if access is None:
            return False
        name, path = access
        if not path:
            return False
        attrs = namespace_range_attrs.get(name, set())
        if (
            isinstance(node, jinja2.nodes.Getattr)
            and cls._static_container_kind_attr_key("mapping", path[:-1]) in attrs
            and isinstance(path[-1], str)
            and hasattr({}, path[-1])
        ):
            return False
        if cls._static_container_attr_key(path) in attrs:
            return True
        return bool(isinstance(node, jinja2.nodes.Getattr) and len(path) == 1 and path[0] in attrs)

    @classmethod
    def _static_range_value_is_definitely_defined(
        cls,
        node: Any,
        range_aliases: set[str],
        namespace_range_attrs: dict[str, set[str]],
    ) -> bool:
        if isinstance(node, jinja2.nodes.Name):
            return cls._static_defined_binding_key(node.name) in range_aliases
        access = cls._static_container_access_path(node)
        if access is None:
            return False
        name, path = access
        if not path:
            return cls._static_defined_binding_key(name) in range_aliases
        attrs = namespace_range_attrs.get(name, set())
        if cls._static_container_member_attr_key(path) in attrs:
            return True
        return bool(
            isinstance(node, jinja2.nodes.Getattr)
            and cls._static_container_kind_attr_key("mapping", path[:-1]) in attrs
            and isinstance(path[-1], str)
            and hasattr({}, path[-1])
        )

    @classmethod
    def _static_default_filter_may_use_fallback(cls, node: Any) -> bool:
        if not node.args:
            return False
        boolean_mode = False
        if len(node.args) == 2:
            boolean_value = cls._constant_condition_value(node.args[1])
            if boolean_value is None:
                return True
            boolean_mode = boolean_value
        known, value = cls._constant_condition_scalar(node.node)
        if not known:
            return True
        return boolean_mode and not bool(value)

    @classmethod
    def _static_literal_container_item(cls, node: Any) -> Any | None:
        if (
            isinstance(node, jinja2.nodes.Filter)
            and node.name in {"first", "last"}
            and not node.args
            and not node.kwargs
            and node.dyn_args is None
            and node.dyn_kwargs is None
        ):
            items = cls._static_literal_iterable_items(node.node)
            if items:
                return items[0] if node.name == "first" else items[-1]
            return None
        if (
            isinstance(node, jinja2.nodes.Call)
            and isinstance(node.node, jinja2.nodes.Getattr)
            and node.node.attr == "get"
            and isinstance(node.node.node, jinja2.nodes.Dict)
            and not node.kwargs
            and node.dyn_args is None
            and node.dyn_kwargs is None
            and 1 <= len(node.args) <= 2
        ):
            key = cls._static_literal_container_key(node.args[0])
            if key is None:
                return None
            for pair in reversed(node.node.node.items):
                if cls._static_literal_container_key(pair.key) == key:
                    return pair.value
            return node.args[1] if len(node.args) == 2 else None
        if not isinstance(node, jinja2.nodes.Getitem):
            return None
        key = cls._static_literal_container_key(node.arg)
        if key is None:
            return None
        sequence_items = cls._static_literal_sequence_items(node.node)
        if sequence_items is not None and isinstance(key, int):
            try:
                return sequence_items[key]
            except IndexError:
                return None
        if isinstance(node.node, jinja2.nodes.Dict):
            for pair in reversed(node.node.items):
                if cls._static_literal_container_key(pair.key) == key:
                    return pair.value
        return None

    @classmethod
    def _static_literal_sequence_items(cls, node: Any) -> list[Any] | None:
        if isinstance(node, jinja2.nodes.List | jinja2.nodes.Tuple):
            return list(node.items)
        if isinstance(node, jinja2.nodes.Add):
            left_items = cls._static_literal_sequence_items(node.left)
            right_items = cls._static_literal_sequence_items(node.right)
            if left_items is not None and right_items is not None:
                return [*left_items, *right_items]
        return None

    @classmethod
    def _static_literal_iterable_items(cls, node: Any) -> list[Any] | None:
        sequence_items = cls._static_literal_sequence_items(node)
        if sequence_items is not None:
            return sequence_items
        if (
            isinstance(node, jinja2.nodes.Filter)
            and node.name == "reverse"
            and not node.args
            and not node.kwargs
            and node.dyn_args is None
            and node.dyn_kwargs is None
        ):
            sequence_items = cls._static_literal_sequence_items(node.node)
            return list(reversed(sequence_items)) if sequence_items is not None else None
        if not (
            isinstance(node, jinja2.nodes.Call)
            and isinstance(node.node, jinja2.nodes.Getattr)
            and isinstance(node.node.node, jinja2.nodes.Dict)
            and node.node.attr in {"items", "keys", "values"}
            and not node.args
            and not node.kwargs
            and node.dyn_args is None
            and node.dyn_kwargs is None
        ):
            return None
        container_entries = cls._static_literal_container_entries(node.node.node)
        if container_entries is None:
            return None
        entries, _ = container_entries
        if node.node.attr == "keys":
            return [jinja2.nodes.Const(key) for key, _ in entries]
        if node.node.attr == "values":
            return [value for _, value in entries]
        return [jinja2.nodes.Tuple([jinja2.nodes.Const(key), value], "load") for key, value in entries]

    @classmethod
    def _static_literal_container_entries(cls, node: Any) -> tuple[list[tuple[str | int | float, Any]], bool] | None:
        sequence_items = cls._static_literal_sequence_items(node)
        if sequence_items is not None:
            return [(index, item) for index, item in enumerate(sequence_items)], True
        if isinstance(node, jinja2.nodes.Dict):
            entries_by_key: dict[str | int | float, Any] = {}
            for pair in node.items:
                key = cls._static_literal_container_key(pair.key)
                if key is None:
                    return None
                entries_by_key[key] = pair.value
            return list(entries_by_key.items()), False
        return None

    @classmethod
    def _static_literal_container_leaf_entries(
        cls,
        node: Any,
        prefix: tuple[str | int | float, ...] = (),
        remaining_paths: list[int] | None = None,
    ) -> list[tuple[tuple[str | int | float, ...], Any]]:
        if remaining_paths is None:
            remaining_paths = [_MAX_STATIC_CONTAINER_PATHS]
        container_entries = cls._static_literal_container_entries(node)
        if container_entries is None:
            if not prefix:
                return []
            if remaining_paths[0] <= 0:
                raise _StaticAnalysisBudgetExceeded
            remaining_paths[0] -= 1
            return [(prefix, node)]
        entries, is_sequence = container_entries
        if not entries:
            if not prefix:
                return []
            if remaining_paths[0] <= 0:
                raise _StaticAnalysisBudgetExceeded
            remaining_paths[0] -= 1
            return [(prefix, node)]
        leaves: list[tuple[tuple[str | int | float, ...], Any]] = []
        sequence_length = len(entries)
        for key, item in entries:
            aliases: tuple[str | int | float, ...] = (key,)
            if is_sequence and isinstance(key, int):
                aliases = (key, key - sequence_length)
            for alias in dict.fromkeys(aliases):
                nested = cls._static_literal_container_leaf_entries(item, (*prefix, alias), remaining_paths)
                leaves.extend(nested)
        return leaves

    @classmethod
    def _static_literal_container_kind_paths(
        cls,
        node: Any,
        prefix: tuple[str | int | float, ...] = (),
        remaining_paths: list[int] | None = None,
    ) -> list[tuple[tuple[str | int | float, ...], str]]:
        if remaining_paths is None:
            remaining_paths = [_MAX_STATIC_CONTAINER_PATHS]
        container_entries = cls._static_literal_container_entries(node)
        if container_entries is None:
            return []
        if remaining_paths[0] <= 0:
            raise _StaticAnalysisBudgetExceeded
        remaining_paths[0] -= 1
        entries, is_sequence = container_entries
        kind_paths = [(prefix, "sequence" if is_sequence else "mapping")]
        sequence_length = len(entries)
        for key, item in entries:
            aliases: tuple[str | int | float, ...] = (key,)
            if is_sequence and isinstance(key, int):
                aliases = (key, key - sequence_length)
            for alias in dict.fromkeys(aliases):
                kind_paths.extend(cls._static_literal_container_kind_paths(item, (*prefix, alias), remaining_paths))
        return kind_paths

    @staticmethod
    def _static_literal_container_key(node: Any) -> str | int | float | None:
        if isinstance(node, jinja2.nodes.Const) and node.value is None:
            return "\0key:none"
        if isinstance(node, jinja2.nodes.Const) and isinstance(node.value, str | int | float):
            value = node.value
            if isinstance(value, bool):
                return int(value)
            if isinstance(value, str) and value.startswith("\0key:"):
                return "\0key:str:" + json.dumps(value, ensure_ascii=True)
            if isinstance(value, float):
                if not math.isfinite(value):
                    return None
                return int(value) if value.is_integer() else value
            return value
        if isinstance(node, jinja2.nodes.Tuple):
            items = [Jinja2TemplateScanner._static_literal_container_key(item) for item in node.items]
            if any(item is None for item in items):
                return None
            return "\0key:tuple:" + json.dumps(items, separators=(",", ":"), ensure_ascii=True)
        if (
            isinstance(node, jinja2.nodes.Neg)
            and isinstance(node.node, jinja2.nodes.Const)
            and isinstance(node.node.value, int | float)
            and not isinstance(node.node.value, bool)
        ):
            value = -node.node.value
            if isinstance(value, float):
                if not math.isfinite(value):
                    return None
                return int(value) if value.is_integer() else value
            return value
        return None

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
        truncated = len(unique_results) > 8
        if truncated:
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
        return _StaticIntCandidates(tuple(unique_results), truncated=truncated)

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
            for candidate in [
                node,
                *node.find_all(jinja2.nodes.Getitem),
                *node.find_all(jinja2.nodes.Getattr),
                *node.find_all(jinja2.nodes.Call),
            ]:
                access = Jinja2TemplateScanner._static_container_access_path(candidate)
                if access is None:
                    continue
                name, path = access
                if path:
                    referenced_names.add(Jinja2TemplateScanner._static_container_binding_key(name, path))

        variants: list[dict[str, _StaticIntBinding]] = [
            {name: binding for name, binding in int_bindings.items() if not isinstance(binding, _StaticIntCandidates)}
        ]
        for name, binding in int_bindings.items():
            if name not in referenced_names or not isinstance(binding, _StaticIntCandidates):
                continue
            variant_count = len(binding.values) + int(binding.may_be_undefined)
            if binding.truncated or len(variants) * variant_count > 64:
                return variants, True
            variants = [{**variant, name: value} for variant in variants for value in binding.values] + (
                [dict(variant) for variant in variants] if binding.may_be_undefined else []
            )
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

    def _constant_scalar_expression_value(
        self,
        node: Any,
        int_bindings: dict[str, _StaticIntBinding] | None = None,
        depth: int = 0,
    ) -> str | float | None:
        if depth > 32:
            return None
        literal_item = self._static_literal_container_item(node)
        if literal_item is not None:
            return self._constant_scalar_expression_value(literal_item, int_bindings, depth + 1)
        access = self._static_container_access_path(node)
        if access is not None and int_bindings is not None:
            name, path = access
            binding_name = name if not path else self._static_container_binding_key(name, path)
            binding = int_bindings.get(binding_name)
            if isinstance(binding, _StaticScalarValue):
                return binding.value
            if isinstance(binding, tuple):
                return str(binding[0])
            if (
                isinstance(node, jinja2.nodes.Call)
                and isinstance(node.node, jinja2.nodes.Getattr)
                and node.node.attr == "get"
                and path
                and self._static_container_kind_binding_key(name, "mapping", path[:-1]) in int_bindings
                and self._static_container_member_binding_key(name, path) not in int_bindings
                and len(node.args) == 2
            ):
                default_value = self._constant_scalar_expression_value(node.args[1], int_bindings, depth + 1)
                if default_value is not None:
                    return default_value
                default_int = self._constant_int_expression_result(
                    node.args[1],
                    _SANDBOX_MAX_RANGE_ITERATIONS,
                    int_bindings,
                )
                return str(default_int[0]) if default_int is not None else None
        if isinstance(node, jinja2.nodes.Const):
            if isinstance(node.value, str):
                return node.value
            if isinstance(node.value, float) and not isinstance(node.value, bool):
                return node.value
            return None
        if (
            isinstance(node, jinja2.nodes.Filter)
            and node.name in {"d", "default"}
            and not node.kwargs
            and node.dyn_args is None
            and node.dyn_kwargs is None
            and len(node.args) <= 2
        ):
            source_value = self._constant_scalar_expression_value(node.node, int_bindings, depth + 1)
            boolean_mode = len(node.args) == 2 and self._constant_condition_value(node.args[1]) is True
            if source_value is not None and (not boolean_mode or bool(source_value)):
                return source_value
            if node.args and (source_value is None or boolean_mode):
                fallback_value = self._constant_scalar_expression_value(node.args[0], int_bindings, depth + 1)
                if fallback_value is not None:
                    return fallback_value
                fallback_int = self._constant_int_expression_result(
                    node.args[0],
                    _SANDBOX_MAX_RANGE_ITERATIONS,
                    int_bindings,
                )
                return str(fallback_int[0]) if fallback_int is not None else None
            return None
        if not isinstance(node, jinja2.nodes.Concat):
            return None
        parts: list[str] = []
        total_length = 0
        for item in node.nodes:
            value = self._constant_scalar_expression_value(item, int_bindings, depth + 1)
            if (
                value is None
                and isinstance(item, jinja2.nodes.Const)
                and isinstance(
                    item.value,
                    bool | int,
                )
            ):
                value = str(item.value)
            if value is None:
                return None
            text = str(value)
            total_length += len(text)
            if total_length > 4096:
                return None
            parts.append(text)
        return "".join(parts)

    def _constant_int_expression_result(
        self,
        node: Any,
        cap: int,
        int_bindings: dict[str, _StaticIntBinding] | None = None,
    ) -> tuple[int, bool] | None:
        literal_item = self._static_literal_container_item(node)
        if literal_item is not None:
            return self._constant_int_expression_result(literal_item, cap, int_bindings)
        access = self._static_container_access_path(node)
        if access is not None:
            name, path = access
            if (
                isinstance(node, jinja2.nodes.Getattr)
                and int_bindings is not None
                and path
                and self._static_container_kind_binding_key(name, "mapping", path[:-1]) in int_bindings
                and isinstance(path[-1], str)
                and hasattr({}, path[-1])
            ):
                return None
            binding_name = name if not path else self._static_container_binding_key(name, path)
            binding = int_bindings.get(binding_name) if int_bindings is not None else None
            if isinstance(binding, tuple):
                return binding
            if (
                isinstance(node, jinja2.nodes.Call)
                and isinstance(node.node, jinja2.nodes.Getattr)
                and node.node.attr == "get"
                and path
                and int_bindings is not None
                and self._static_container_kind_binding_key(name, "mapping", path[:-1]) in int_bindings
                and self._static_container_member_binding_key(name, path) not in int_bindings
                and len(node.args) == 2
            ):
                return self._constant_int_expression_result(node.args[1], cap, int_bindings)
            return None
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
                    quotient_signature = self._static_power_quotient_signature(node.left, int_bindings)
                    if quotient_signature is not None and quotient_signature == self._static_power_signature(
                        node.right,
                        int_bindings,
                    ):
                        return self._constant_int_result(0, cap)
                    wrapped_difference = self._constant_wrapped_difference_result(
                        node.left,
                        node.right,
                        cap,
                        int_bindings,
                    )
                    if wrapped_difference is not None:
                        return wrapped_difference
                    wrapped_right_difference = self._constant_wrapped_right_difference_result(
                        node.left,
                        node.right,
                        cap,
                        int_bindings,
                    )
                    if wrapped_right_difference is not None:
                        return wrapped_right_difference
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
                    quotient_signature = self._static_power_quotient_signature(node, int_bindings)
                    if quotient_signature is not None:
                        return self._constant_power_signature_result(quotient_signature, cap)
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
                wrapped_modulo = self._constant_wrapped_modulo_result(
                    node.left,
                    node.right,
                    cap,
                    int_bindings,
                )
                if wrapped_modulo is not None:
                    return wrapped_modulo
                if left_saturated:
                    if right_saturated:
                        return None
                    power_modulo = self._constant_power_modulo_result(
                        node.left,
                        right,
                        cap,
                        int_bindings,
                    )
                    if power_modulo is not None:
                        return power_modulo
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
            if right_saturated:
                if left < 0:
                    exponent_parity = self._constant_int_expression_parity(node.right, int_bindings)
                    if exponent_parity is None:
                        return None
                    return self._saturated_constant_int_result(cap, -1 if exponent_parity else 1)
                return self._saturated_constant_int_result(cap)
            if left_saturated:
                sign = -1 if left < 0 and right % 2 else 1
                return self._saturated_constant_int_result(cap, sign)
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

    def _static_power_signature(
        self,
        node: Any,
        int_bindings: dict[str, _StaticIntBinding] | None,
    ) -> tuple[int, int] | None:
        if not isinstance(node, jinja2.nodes.Pow):
            return None
        base_result = self._constant_int_expression_result(node.left, _STATIC_INT_EVAL_MAX_ABS, int_bindings)
        exponent_result = self._constant_int_expression_result(node.right, _STATIC_INT_EVAL_MAX_ABS, int_bindings)
        if (
            base_result is None
            or exponent_result is None
            or base_result[1]
            or exponent_result[1]
            or abs(base_result[0]) <= 1
            or exponent_result[0] < 0
        ):
            return None
        return base_result[0], exponent_result[0]

    def _static_power_quotient_signature(
        self,
        node: Any,
        int_bindings: dict[str, _StaticIntBinding] | None,
    ) -> tuple[int, int] | None:
        if not isinstance(node, jinja2.nodes.FloorDiv):
            return None
        numerator = self._static_power_signature(node.left, int_bindings)
        if numerator is None:
            return None
        denominator = self._static_power_signature(node.right, int_bindings)
        if denominator is None:
            denominator_result = self._constant_int_expression_result(
                node.right,
                _STATIC_INT_EVAL_MAX_ABS,
                int_bindings,
            )
            if denominator_result is None or denominator_result[1] or denominator_result[0] != numerator[0]:
                return None
            denominator = (numerator[0], 1)
        if numerator[0] != denominator[0] or numerator[1] < denominator[1]:
            return None
        return numerator[0], numerator[1] - denominator[1]

    def _constant_power_signature_result(self, signature: tuple[int, int], cap: int) -> tuple[int, bool]:
        base, exponent = signature
        if exponent == 0:
            return self._constant_int_result(1, cap)
        magnitude_cap = self._constant_int_magnitude_cap(cap)
        if (abs(base).bit_length() - 1) * exponent >= magnitude_cap.bit_length():
            return self._saturated_constant_int_result(cap, -1 if base < 0 and exponent % 2 else 1)
        return self._constant_int_result(base**exponent, cap)

    def _constant_int_expression_parity(
        self,
        node: Any,
        int_bindings: dict[str, _StaticIntBinding] | None,
    ) -> int | None:
        if isinstance(node, jinja2.nodes.Name):
            binding = int_bindings.get(node.name) if int_bindings is not None else None
            if not isinstance(binding, tuple) or binding[1]:
                return None
            return binding[0] % 2
        if isinstance(node, jinja2.nodes.Const):
            if isinstance(node.value, bool) or not isinstance(node.value, int):
                return None
            return node.value % 2
        if isinstance(node, jinja2.nodes.Neg | jinja2.nodes.Pos):
            return self._constant_int_expression_parity(node.node, int_bindings)
        if isinstance(node, jinja2.nodes.Add | jinja2.nodes.Sub):
            left = self._constant_int_expression_parity(node.left, int_bindings)
            right = self._constant_int_expression_parity(node.right, int_bindings)
            return None if left is None or right is None else (left + right) % 2
        if isinstance(node, jinja2.nodes.Mul):
            left = self._constant_int_expression_parity(node.left, int_bindings)
            right = self._constant_int_expression_parity(node.right, int_bindings)
            return None if left is None or right is None else left * right
        if isinstance(node, jinja2.nodes.Pow):
            exponent = self._constant_int_expression_result(node.right, _STATIC_INT_EVAL_MAX_ABS, int_bindings)
            if exponent is None or exponent[0] < 0:
                return None
            if not exponent[1] and exponent[0] == 0:
                return 1
            return self._constant_int_expression_parity(node.left, int_bindings)
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

    def _constant_wrapped_modulo_result(
        self,
        left: Any,
        right: Any,
        cap: int,
        int_bindings: dict[str, _StaticIntBinding] | None,
    ) -> tuple[int, bool] | None:
        if not isinstance(right, jinja2.nodes.Neg) or not isinstance(right.node, jinja2.nodes.Add):
            return None
        left_result = self._constant_int_expression_result(left, cap, int_bindings)
        if left_result is None or left_result[0] < 0:
            return None
        for dominant, offset in ((right.node.left, right.node.right), (right.node.right, right.node.left)):
            dominant_result = self._constant_int_expression_result(dominant, cap, int_bindings)
            offset_result = self._constant_int_expression_result(offset, cap, int_bindings)
            if (
                dominant_result is None
                or dominant_result[0] < 0
                or offset_result is None
                or offset_result[1]
                or offset_result[0] <= 0
            ):
                continue
            if dominant != left and self._compare_static_power_magnitudes(dominant, left, int_bindings) != 0:
                continue
            return self._constant_int_result(-offset_result[0], cap)
        return None

    def _constant_wrapped_right_difference_result(
        self,
        left: Any,
        right: Any,
        cap: int,
        int_bindings: dict[str, _StaticIntBinding] | None,
    ) -> tuple[int, bool] | None:
        if not isinstance(right, jinja2.nodes.Add):
            return None
        left_result = self._constant_int_expression_result(left, cap, int_bindings)
        if left_result is None or not left_result[1]:
            return None
        for dominant, offset in ((right.left, right.right), (right.right, right.left)):
            dominant_result = self._constant_int_expression_result(dominant, cap, int_bindings)
            offset_result = self._constant_int_expression_result(offset, cap, int_bindings)
            if dominant_result is None or not dominant_result[1] or offset_result is None or offset_result[1]:
                continue
            comparison = self._compare_static_power_magnitudes(left, dominant, int_bindings)
            if comparison is None:
                continue
            left_sign = -1 if left_result[0] < 0 else 1
            dominant_sign = -1 if dominant_result[0] < 0 else 1
            if left_sign != dominant_sign or comparison > 0:
                return self._saturated_constant_int_result(cap, left_sign)
            if comparison < 0:
                return self._saturated_constant_int_result(cap, -dominant_sign)
            return self._constant_int_result(-offset_result[0], cap)
        return None

    def _constant_power_modulo_result(
        self,
        left: Any,
        divisor: int,
        cap: int,
        int_bindings: dict[str, _StaticIntBinding] | None,
    ) -> tuple[int, bool] | None:
        signature = self._static_power_signature(left, int_bindings)
        if signature is None or divisor == 0:
            return None
        base, exponent = signature
        modulus = abs(divisor)
        remainder = pow(base, exponent, modulus)
        if divisor < 0 and remainder:
            remainder -= modulus
        return self._constant_int_result(remainder, cap)

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
        scalar_value = self._constant_scalar_expression_value(node.node, int_bindings)
        if scalar_value is None:
            return None
        try:
            if isinstance(scalar_value, float):
                if not math.isfinite(scalar_value):
                    return default_result
                parsed = int(scalar_value)
            elif isinstance(scalar_value, str):
                text = scalar_value.strip()
                if len(text) > 4096:
                    if base == 10:
                        sign = -1 if text.startswith("-") else 1
                        digits = text[1:] if text.startswith(("-", "+")) else text
                        if not digits or not digits.isdecimal():
                            return default_result
                        significant_digits = digits.lstrip("0")
                        if not significant_digits:
                            return self._constant_int_result(0, cap)
                        if len(significant_digits) <= 4096:
                            return self._constant_int_result(sign * int(significant_digits), cap)
                        return self._saturated_constant_int_result(cap, sign)
                    return self._saturated_constant_int_result(cap, -1 if text.startswith("-") else 1)
                try:
                    parsed = int(text, base)
                except ValueError:
                    float_value = float(text)
                    if not math.isfinite(float_value):
                        return default_result
                    parsed = int(float_value)
        except (OverflowError, TypeError, ValueError):
            return default_result
        return self._constant_int_result(parsed, cap)

    @classmethod
    def _constant_condition_value(
        cls,
        node: Any,
        int_bindings: dict[str, _StaticIntBinding] | None = None,
    ) -> bool | None:
        known, value = cls._constant_condition_scalar(node, int_bindings=int_bindings)
        if not known:
            return None
        if value is None or isinstance(value, bool | int | float | str | bytes):
            return bool(value)
        return None

    @classmethod
    def _constant_condition_scalar(
        cls,
        node: Any,
        depth: int = 0,
        int_bindings: dict[str, _StaticIntBinding] | None = None,
    ) -> tuple[bool, Any]:
        if depth > 32:
            return False, None
        access = cls._static_container_access_path(node)
        if access is not None and int_bindings is not None:
            name, path = access
            binding_name = name if not path else cls._static_container_binding_key(name, path)
            binding = int_bindings.get(binding_name)
            if isinstance(binding, tuple) and not binding[1]:
                return True, binding[0]
            if isinstance(binding, _StaticScalarValue):
                return True, binding.value
        if isinstance(node, jinja2.nodes.Const):
            return True, node.value
        if isinstance(node, jinja2.nodes.Not):
            known, value = cls._constant_condition_scalar(node.node, depth + 1, int_bindings)
            return (True, not bool(value)) if known else (False, None)
        if isinstance(node, jinja2.nodes.Neg | jinja2.nodes.Pos):
            known, value = cls._constant_condition_scalar(node.node, depth + 1, int_bindings)
            if not known or not isinstance(value, int | float):
                return False, None
            return True, -value if isinstance(node, jinja2.nodes.Neg) else +value
        if isinstance(node, jinja2.nodes.Compare):
            left_known, left = cls._constant_condition_scalar(node.expr, depth + 1, int_bindings)
            if not left_known:
                return False, None
            for operand in node.ops:
                right_known, right = cls._constant_condition_scalar(
                    operand.expr,
                    depth + 1,
                    int_bindings,
                )
                if not right_known:
                    return False, None
                try:
                    if operand.op == "eq":
                        matches = left == right
                    elif operand.op == "ne":
                        matches = left != right
                    elif operand.op == "lt":
                        matches = left < right
                    elif operand.op == "lteq":
                        matches = left <= right
                    elif operand.op == "gt":
                        matches = left > right
                    elif operand.op == "gteq":
                        matches = left >= right
                    else:
                        return False, None
                except TypeError:
                    return False, None
                if not matches:
                    return True, False
                left = right
            return True, True
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
        left_known, left = cls._constant_condition_scalar(node.left, depth + 1, int_bindings)
        right_known, right = cls._constant_condition_scalar(node.right, depth + 1, int_bindings)
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
