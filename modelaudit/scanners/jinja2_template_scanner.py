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
import multiprocessing as mp
import os
import platform
import queue
import re
import warnings
from contextlib import suppress
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
_RAW_PARSE_FALLBACK_CONTEXT_BYTES = 1024
_RAW_PARSE_FALLBACK_MAX_WINDOWS = 8
_RAW_PARSE_FALLBACK_READ_BYTES = 256 * 1024
_DEFAULT_SANDBOX_RENDER_TIMEOUT_SECONDS = 0.5
_DEFAULT_SANDBOX_RENDER_MAX_OUTPUT_CHARS = 64 * 1024
_DEFAULT_SANDBOX_RENDER_MAX_MEMORY_BYTES = 512 * 1024 * 1024
_SANDBOX_RENDER_SPAWN_STARTUP_GRACE_SECONDS = 2.0
_SANDBOX_RENDER_BUDGET_REASON = "jinja2_sandbox_render_budget_exceeded"


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


def _create_budgeted_sandbox_environment(max_output_chars: int) -> Any:
    class _BudgetedSandboxEnvironment(jinja2.sandbox.SandboxedEnvironment):
        intercepted_binops = frozenset({"*", "+"})

        def call_binop(self, context: Any, operator: str, left: Any, right: Any) -> Any:
            projected_size = None
            if operator == "*":
                projected_size = _project_repeated_value_size(left, right)
            elif operator == "+":
                projected_size = _project_combined_value_size(left, right)

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
        return value if value > 0 else default

    def _positive_int_config(self, key: str, default: int) -> int:
        try:
            value = int(self.config.get(key, default))
        except (TypeError, ValueError):
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
                            "Template analysis incomplete because standalone template exceeds the size limit"
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
        oversized_template_locations: list[str] = []
        for template_location, template_content in templates.items():
            if len(template_content) <= self.max_template_size:
                bounded_templates[template_location] = template_content
            else:
                oversized_template_locations.append(template_location)

        if oversized_template_locations:
            result.metadata[_INCONCLUSIVE_METADATA_KEY] = INCONCLUSIVE_SCAN_OUTCOME
            result.metadata[_INCONCLUSIVE_REASONS_METADATA_KEY] = ["jinja2_template_size_limit_exceeded"]
            result.add_check(
                name="Template Size Limit",
                passed=False,
                message="Template analysis incomplete because one or more extracted templates exceed the size limit",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "reason": "jinja2_template_size_limit_exceeded",
                    "max_template_size": self.max_template_size,
                    "skipped_template_locations": oversized_template_locations,
                },
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
                templates.update(self._extract_gguf_templates(path))
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

    def _extract_gguf_templates(self, path: str) -> dict[str, str]:
        """Extract chat templates from GGUF metadata"""
        templates = {}

        try:
            reader = GGUFReader(path)

            # Look for tokenizer.chat_template in metadata
            for key, field in reader.fields.items():
                if key == "tokenizer.chat_template" and hasattr(field, "parts") and hasattr(field, "data"):
                    value = field.parts[field.data[0]]
                    if isinstance(value, list | tuple):
                        # Convert list of integers to string
                        template_str = "".join(chr(i) for i in value if isinstance(i, int) and 0 <= i <= 1114111)
                    else:
                        template_str = str(value)

                    if template_str and len(template_str) <= self.max_template_size:
                        templates["tokenizer.chat_template"] = template_str

        except Exception as e:
            logger.debug(f"Error extracting GGUF templates: {e}")

        return templates

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
            templates[template_path] = value
            return

        extraction_failures.append(
            {
                "format": config_format,
                "reason": "jinja2_template_size_limit_exceeded",
                "max_template_size": self.max_template_size,
                "skipped_template_locations": [template_path],
                "template_size": len(value),
            }
        )

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
                    {
                        "format": "template",
                        "reason": "jinja2_template_size_limit_exceeded",
                        "max_template_size": self.max_template_size,
                        "skipped_template_locations": ["template_content"],
                    }
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
        if re.search(r"(['\"])(?:\\.|(?!\1).){1,256}\1\s*\*\s*\d{5,}", template_content) or re.search(
            r"\d{5,}\s*\*\s*(['\"])(?:\\.|(?!\1).){1,256}\1", template_content
        ):
            return True
        return self._template_ast_has_static_render_budget_risk(template_content)

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

        range_threshold = max(1, self.sandbox_render_max_output_chars)
        for node in parsed.find_all(jinja2.nodes.Filter):
            if node.name != "list" or not self._is_range_call(node.node):
                continue
            projected_size = self._constant_range_rendered_list_size(node.node.args, range_threshold)
            if projected_size is not None and projected_size > self.sandbox_render_max_output_chars:
                return True

        for node in parsed.find_all(jinja2.nodes.Call):
            if not self._is_range_call(node):
                continue
            range_count = self._constant_range_iteration_count(node.args, range_threshold)
            if range_count is not None:
                if range_count >= range_threshold:
                    return True
                continue

            stop_arg = node.args[1] if len(node.args) >= 2 else node.args[0]
            range_bound = self._constant_int_expression_value(stop_arg, range_threshold)
            if range_bound is not None and abs(range_bound) >= range_threshold:
                return True

        for node in parsed.find_all(jinja2.nodes.Mul):
            projected_size = self._constant_repeated_sequence_size(node.left, node.right)
            if projected_size is not None and projected_size > self.sandbox_render_max_output_chars:
                return True

        return False

    def _is_range_call(self, node: Any) -> bool:
        return (
            isinstance(node, jinja2.nodes.Call)
            and isinstance(node.node, jinja2.nodes.Name)
            and node.node.name == "range"
            and bool(node.args)
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
        if isinstance(node, jinja2.nodes.Const) and isinstance(node.value, int | float | bool):
            return len(str(node.value))
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
        start, stop, step = range_values
        count = self._range_iteration_count(start, stop, step, cap)
        if count == 0:
            return 2

        min_rendered_size = 2 + count + ((count - 1) * 2)
        if min_rendered_size > cap:
            return cap + 1

        total = 1
        for checked, value in enumerate(range(start, stop, step), start=1):
            if checked > 1:
                total += 2
            total += len(str(value))
            if total + 1 > cap:
                return cap + 1
            if checked >= min(count, 100_000):
                break
        return total + 1

    def _constant_int_expression_value(self, node: Any, cap: int) -> int | None:
        if isinstance(node, jinja2.nodes.Const):
            if isinstance(node.value, bool) or not isinstance(node.value, int):
                return None
            return node.value
        if isinstance(node, jinja2.nodes.Neg):
            value = self._constant_int_expression_value(node.node, cap)
            return -value if value is not None else None
        if isinstance(node, jinja2.nodes.Add | jinja2.nodes.Sub | jinja2.nodes.Mul):
            left = self._constant_int_expression_value(node.left, cap)
            right = self._constant_int_expression_value(node.right, cap)
            if left is None or right is None:
                return None
            if isinstance(node, jinja2.nodes.Add):
                return self._cap_constant_int(left + right, cap)
            if isinstance(node, jinja2.nodes.Sub):
                return self._cap_constant_int(left - right, cap)
            return self._cap_constant_int(left * right, cap)
        if isinstance(node, jinja2.nodes.Pow):
            left = self._constant_int_expression_value(node.left, cap)
            right = self._constant_int_expression_value(node.right, cap)
            if left is None or right is None or right < 0:
                return None
            if abs(left) > 1 and right > 32:
                return cap + 1
            return self._cap_constant_int(left**right, cap)
        return None

    def _constant_range_iteration_count(self, args: list[Any], cap: int) -> int | None:
        range_values = self._constant_range_values(args, cap)
        if range_values is None:
            return None
        return self._range_iteration_count(*range_values, cap)

    def _constant_range_values(self, args: list[Any], cap: int) -> tuple[int, int, int] | None:
        values: list[int] = []
        for arg in args[:3]:
            value = self._constant_int_expression_value(arg, cap)
            if value is None:
                return None
            values.append(value)

        if len(values) == 1:
            start = 0
            stop = values[0]
            step = 1
        else:
            start = values[0]
            stop = values[1]
            step = values[2] if len(values) >= 3 else 1

        if step == 0:
            return None
        return start, stop, step

    def _range_iteration_count(self, start: int, stop: int, step: int, cap: int) -> int:
        if step > 0:
            if stop <= start:
                return 0
            return min(((stop - start - 1) // step) + 1, cap + 1)
        if stop >= start:
            return 0
        return min(((start - stop - 1) // abs(step)) + 1, cap + 1)

    def _cap_constant_int(self, value: int, cap: int) -> int:
        if abs(value) <= cap:
            return value
        return cap + 1 if value > 0 else -(cap + 1)

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
