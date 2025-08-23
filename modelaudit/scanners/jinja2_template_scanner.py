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
import os
import re
import warnings
from typing import Any, ClassVar, Optional

from modelaudit.suspicious_symbols import JINJA2_SSTI_PATTERNS

from .base import BaseScanner, IssueSeverity, ScanResult, logger

# Optional GGUF support with graceful fallback
try:
    from gguf.gguf_reader import GGUFReader

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


class Jinja2TemplateScanner(BaseScanner):
    """Scanner for Jinja2 template injection vulnerabilities in ML models"""

    name = "jinja2_template"
    description = "Scans for Jinja2 template injection vulnerabilities in ML model templates"
    supported_extensions: ClassVar[list[str]] = [".gguf", ".json", ".yaml", ".yml", ".jinja", ".j2", ".template"]

    def __init__(self, config: Optional[dict[str, Any]] = None):
        super().__init__(config)

        # Configuration options
        self.sensitivity_level = self.config.get("sensitivity_level", "medium")  # low/medium/high
        self.max_template_size = self.config.get("max_template_size", 50000)  # Skip huge templates
        self.enable_sandbox_test = self.config.get("enable_sandbox_test", True) and HAS_JINJA2_SANDBOX
        self.skip_common_patterns = self.config.get("skip_common_patterns", True)  # Ignore common ML patterns

        # Compile regex patterns for efficiency
        self._compiled_patterns = self._compile_all_patterns()

    def _compile_all_patterns(self) -> dict[str, list[tuple[re.Pattern, str]]]:
        """Compile all regex patterns for efficient matching"""
        compiled: dict[str, list[tuple[re.Pattern, str]]] = {}

        for category, patterns in JINJA2_SSTI_PATTERNS.items():
            compiled[category] = []
            for pattern in patterns:
                try:
                    compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                    compiled[category].append((compiled_pattern, pattern))
                except re.error as e:
                    logger.warning(f"Failed to compile regex pattern '{pattern}': {e}")

        return compiled

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
            templates = self._extract_templates(path, context)

            if not templates:
                result.add_check(
                    name="Template Extraction",
                    passed=True,
                    message="No Jinja2 templates found in file",
                    location=path,
                    details={"file_type": context.file_type},
                )
                result.finish(success=True)
                return result

            # Analyze each extracted template
            total_detections = 0
            for template_location, template_content in templates.items():
                detections = self._analyze_template(template_content, context, f"{path}:{template_location}")
                total_detections += len(detections)

                # Convert detections to issues
                for detection in detections:
                    severity = self._get_severity_for_detection(detection, context)
                    why_explanation = self._get_why_explanation(detection, context)

                    result.add_check(
                        name="Jinja2 Template Injection Detection",
                        passed=False,
                        message=f"Potential SSTI vulnerability detected: {detection.pattern_type}",
                        severity=severity,
                        location=detection.location or f"{path}:{template_location}",
                        details={
                            "pattern_type": detection.pattern_type,
                            "pattern": detection.pattern,
                            "match_text": detection.match_text[:200],  # Limit output size
                            "risk_level": detection.risk_level,
                            "template_location": template_location,
                            "ml_context": context.framework,
                        },
                        why=why_explanation,
                    )

            # Overall assessment
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
            result.finish(success=True)
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

    def _extract_templates(self, path: str, context: MLContext) -> dict[str, str]:
        """Extract Jinja2 templates from various file formats"""
        templates = {}

        try:
            if context.file_type == "gguf" and HAS_GGUF:
                templates.update(self._extract_gguf_templates(path))
            elif context.file_type in ["json", "tokenizer_config"]:
                templates.update(self._extract_json_templates(path))
            elif context.file_type == "yaml":
                templates.update(self._extract_yaml_templates(path))
            elif context.file_type == "template":
                templates.update(self._extract_template_file(path))
        except Exception as e:
            logger.warning(f"Failed to extract templates from {path}: {e}")

        return templates

    def _extract_gguf_templates(self, path: str) -> dict[str, str]:
        """Extract chat templates from GGUF metadata"""
        templates = {}

        try:
            reader = GGUFReader(path)

            # Look for tokenizer.chat_template in metadata
            for key, field in reader.fields.items():
                if key == "tokenizer.chat_template" and hasattr(field, "parts") and hasattr(field, "data"):
                    value = field.parts[field.data[0]]
                    if isinstance(value, (list, tuple)):
                        # Convert list of integers to string
                        template_str = "".join(chr(i) for i in value if isinstance(i, int) and 0 <= i <= 1114111)
                    else:
                        template_str = str(value)

                    if template_str and len(template_str) <= self.max_template_size:
                        templates["tokenizer.chat_template"] = template_str

        except Exception as e:
            logger.debug(f"Error extracting GGUF templates: {e}")

        return templates

    def _extract_json_templates(self, path: str) -> dict[str, str]:
        """Extract templates from JSON configuration files"""
        templates: dict[str, str] = {}

        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)

            # Recursively search for template fields
            self._find_json_templates(data, templates, "")

        except Exception as e:
            logger.debug(f"Error extracting JSON templates: {e}")

        return templates

    def _find_json_templates(self, data: Any, templates: dict[str, str], path: str) -> None:
        """Recursively find template strings in JSON data"""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key

                # Check for known template fields
                if (
                    key in ["chat_template", "template", "jinja_template", "custom_chat_template"]
                    and isinstance(value, str)
                    and value.strip()
                    and len(value) <= self.max_template_size
                ):
                    templates[current_path] = value

                # Recursively check nested structures
                elif isinstance(value, (dict, list)):
                    self._find_json_templates(value, templates, current_path)

                # Check for template-like strings (contain Jinja2 syntax)
                elif (
                    isinstance(value, str) and self._looks_like_template(value) and len(value) <= self.max_template_size
                ):
                    templates[current_path] = value

        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]" if path else f"[{i}]"
                self._find_json_templates(item, templates, current_path)

    def _extract_yaml_templates(self, path: str) -> dict[str, str]:
        """Extract templates from YAML configuration files"""
        templates: dict[str, str] = {}

        if not HAS_YAML:
            return templates

        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if data:
                self._find_json_templates(data, templates, "")  # Reuse JSON logic

        except Exception as e:
            logger.debug(f"Error extracting YAML templates: {e}")

        return templates

    def _extract_template_file(self, path: str) -> dict[str, str]:
        """Extract content from standalone template files"""
        templates = {}

        try:
            with open(path, encoding="utf-8") as f:
                content = f.read()

            if content and len(content) <= self.max_template_size:
                templates["template_content"] = content

        except Exception as e:
            logger.debug(f"Error reading template file: {e}")

        return templates

    def _looks_like_template(self, text: str) -> bool:
        """Check if text looks like a Jinja2 template"""
        if not isinstance(text, str) or len(text) < 5:
            return False

        # Look for Jinja2 template syntax
        jinja_indicators = [
            "{{",  # Variable substitution
            "{%",  # Control structures
            "{#",  # Comments
        ]

        return any(indicator in text for indicator in jinja_indicators)

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
        if not context.framework:
            return False

        match_lower = match_text.lower()

        # Common HuggingFace chat template patterns
        if context.framework == "huggingface":
            benign_patterns = [
                "for message in messages",
                "message['role']",
                "message['content']",
                "messages[0]['role']",
                "if message['role'] == 'system'",
                "if message['role'] == 'user'",
                "if message['role'] == 'assistant'",
            ]

            return any(pattern in match_lower for pattern in benign_patterns)

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

        # Context-based adjustments
        if (
            context.confidence >= 3
            and context.framework == "huggingface"
            and detection.pattern_type in ["control_flow", "environment_access"]
            and base_severity == IssueSeverity.WARNING
        ):
            return IssueSeverity.INFO

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
