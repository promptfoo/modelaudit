"""Scanner for model metadata files (config.json, model cards, etc.)."""

import json
import logging
from pathlib import Path
from typing import Any

from .base import BaseScanner, Issue, IssueSeverity, ScanResult

logger = logging.getLogger(__name__)


class MetadataScanner(BaseScanner):
    """Scanner for model metadata files looking for security issues."""

    @staticmethod
    def can_handle(file_path: str) -> bool:
        """Check if this scanner can handle the file."""
        path = Path(file_path)

        # Handle specific metadata files (excluding config.json which is handled by ManifestScanner)
        if path.name.lower() in ["tokenizer_config.json", "generation_config.json"]:
            return True

        # Handle README/model card files (including extensionless README files)
        filename_lower = path.name.lower()
        return filename_lower in [
            "readme",
            "readme.md",
            "readme.txt",
            "model_card.md",
            "model_card.txt",
            "model-index.yml",
            "model-index.yaml",
        ] or filename_lower.startswith("readme.")

    def scan(self, file_path: str, timeout: int = 300) -> ScanResult:
        """Scan metadata file for security issues."""
        issues: list[Issue] = []
        path = Path(file_path)

        try:
            if path.suffix.lower() == ".json":
                issues.extend(self._scan_json_config(file_path))
            elif path.suffix.lower() in [".md", ".yml", ".yaml"]:
                issues.extend(self._scan_text_metadata(file_path))

        except Exception as e:
            logger.warning(f"Error scanning metadata file {file_path}: {e}")
            issues.append(
                Issue(
                    message=f"Failed to scan metadata file: {e}",
                    severity=IssueSeverity.WARNING,
                    location=file_path,
                    details={"error": str(e)},
                    why="Failed to process metadata file during scanning",
                    type="scan_error",
                )
            )

        result = ScanResult("metadata")
        result.issues = issues
        result.bytes_scanned = path.stat().st_size if path.exists() else 0
        return result

    def _scan_json_config(self, file_path: str) -> list[Issue]:
        """Scan JSON configuration files for security issues."""
        issues: list[Issue] = []

        try:
            with open(file_path, encoding="utf-8") as f:
                config = json.load(f)

            # Check for suspicious URLs or endpoints
            issues.extend(self._check_suspicious_urls(config, file_path))

            # Check for exposed tokens or keys
            issues.extend(self._check_exposed_secrets(config, file_path))

            # Check for suspicious custom code references
            issues.extend(self._check_custom_code_refs(config, file_path))

            # Check for unsafe auto_map entries
            issues.extend(self._check_auto_map_entries(config, file_path))

        except json.JSONDecodeError as e:
            issues.append(
                Issue(
                    message=f"Invalid JSON in metadata file: {e}",
                    severity=IssueSeverity.WARNING,
                    location=file_path,
                    details={"error": str(e)},
                    why="Malformed JSON could indicate tampering or corruption",
                    type="json_error",
                )
            )
        except Exception as e:
            issues.append(
                Issue(
                    message=f"Error reading metadata file: {e}",
                    severity=IssueSeverity.WARNING,
                    location=file_path,
                    details={"error": str(e)},
                    why="File access errors may indicate permission issues or tampering",
                    type="file_error",
                )
            )

        return issues

    def _scan_text_metadata(self, file_path: str) -> list[Issue]:
        """Scan text metadata files (README, model cards) for security issues."""
        issues: list[Issue] = []

        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            # Check for suspicious URLs
            issues.extend(self._check_suspicious_urls_in_text(content, file_path))

            # Check for exposed credentials in text
            issues.extend(self._check_exposed_secrets_in_text(content, file_path))

        except Exception as e:
            issues.append(
                Issue(
                    message=f"Error reading text metadata file: {e}",
                    severity=IssueSeverity.WARNING,
                    location=file_path,
                    details={"error": str(e)},
                    why="File access errors may indicate permission issues or tampering",
                    type="file_error",
                )
            )

        return issues

    def _check_suspicious_urls(self, config: dict[str, Any], file_path: str) -> list[Issue]:
        """Check for suspicious URLs in configuration."""
        issues: list[Issue] = []
        suspicious_domains = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "ow.ly",  # URL shorteners
            "github.io",
            "gitlab.io",  # Potentially compromised pages
            "ngrok.io",
            "localtunnel.me",  # Tunnel services
        ]

        def check_value(value: Any, key_path: str = "") -> None:
            if isinstance(value, str) and value.startswith(("http://", "https://")):
                for domain in suspicious_domains:
                    if domain in value.lower():
                        issues.append(
                            Issue(
                                message=f"Suspicious URL found in metadata: {value}",
                                severity=IssueSeverity.WARNING,
                                location=file_path,
                                details={"url": value, "key_path": key_path, "suspicious_domain": domain},
                                why="URL shorteners and tunnel services can hide malicious endpoints",
                                type="suspicious_url",
                            )
                        )

            elif isinstance(value, dict):
                for k, v in value.items():
                    check_value(v, f"{key_path}.{k}" if key_path else k)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    check_value(item, f"{key_path}[{i}]" if key_path else f"[{i}]")

        check_value(config)
        return issues

    def _check_exposed_secrets(self, config: dict[str, Any], file_path: str) -> list[Issue]:
        """Check for exposed secrets, tokens, or keys in configuration."""
        issues: list[Issue] = []
        secret_patterns = ["api_key", "access_token", "auth_token", "bearer", "jwt", "secret", "password", "credential"]

        # Common legitimate tokens/patterns to exclude
        legitimate_patterns = [
            "<|endoftext|>",
            "<|start|>",
            "<|end|>",
            "<pad>",
            "<unk>",
            "<s>",
            "</s>",
            "tokenizer",
            "config",
            "model",
            "gpt",
            "bert",
            "llama",
            "huggingface",
            "transformers",
            "pytorch",
        ]

        def check_value(value: Any, key_path: str = "") -> None:
            if isinstance(value, str) and len(value) > 10:
                # Check if key name suggests a secret (but exclude tokenizer-related keys)
                is_secret_key = any(pattern in key_path.lower() for pattern in secret_patterns)
                is_legitimate = any(pattern in value.lower() for pattern in legitimate_patterns)
                is_placeholder = any(
                    placeholder in value.lower()
                    for placeholder in ["placeholder", "example", "your_", "xxx", "****", "token_here"]
                )

                # Only flag if it looks like a secret key AND doesn't look legitimate
                if (
                    is_secret_key
                    and not is_legitimate
                    and not is_placeholder
                    and len(set(value)) > 8  # Simple entropy check
                ):
                    issues.append(
                        Issue(
                            message=f"Potential exposed secret in metadata: {key_path}",
                            severity=IssueSeverity.CRITICAL,
                            location=file_path,
                            details={
                                "key_path": key_path,
                                "value_preview": value[:10] + "..." if len(value) > 10 else value,
                            },
                            why="Exposed secrets in metadata files can lead to unauthorized access",
                            type="exposed_secret",
                        )
                    )

            elif isinstance(value, dict):
                for k, v in value.items():
                    check_value(v, f"{key_path}.{k}" if key_path else k)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    check_value(item, f"{key_path}[{i}]" if key_path else f"[{i}]")

        check_value(config)
        return issues

    def _check_custom_code_refs(self, config: dict[str, Any], file_path: str) -> list[Issue]:
        """Check for references to custom code that could be malicious."""
        issues: list[Issue] = []
        dangerous_keys = [
            "custom_object",
            "custom_objects",
            "lambda",
            "eval",
            "exec",
            "import",
            "torch.jit",
            "tf.py_func",
        ]

        def check_value(value: Any, key_path: str = "") -> None:
            if isinstance(value, str):
                for dangerous in dangerous_keys:
                    if dangerous in value.lower() or dangerous in key_path.lower():
                        issues.append(
                            Issue(
                                message=f"Custom code reference found in metadata: {key_path}",
                                severity=IssueSeverity.WARNING,
                                location=file_path,
                                details={"key_path": key_path, "value": value, "dangerous_pattern": dangerous},
                                why="Custom code references can execute arbitrary malicious code",
                                type="custom_code",
                            )
                        )

            elif isinstance(value, dict):
                for k, v in value.items():
                    check_value(v, f"{key_path}.{k}" if key_path else k)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    check_value(item, f"{key_path}[{i}]" if key_path else f"[{i}]")

        check_value(config)
        return issues

    def _check_auto_map_entries(self, config: dict[str, Any], file_path: str) -> list[Issue]:
        """Check for potentially unsafe auto_map entries."""
        issues: list[Issue] = []

        auto_map = config.get("auto_map", {})
        if isinstance(auto_map, dict):
            for key, value in auto_map.items():
                if isinstance(value, str):
                    # Check for directory traversal or absolute paths (suspicious)
                    if value.startswith(("./", "../", "/")) or ".." in value:
                        issues.append(
                            Issue(
                                message=f"Suspicious file path in auto_map: {value}",
                                severity=IssueSeverity.WARNING,
                                location=file_path,
                                details={"auto_map_key": key, "file_path": value},
                                why="Directory traversal paths can access unauthorized files",
                                type="path_traversal",
                            )
                        )

                    # Check for dangerous function calls or system commands
                    dangerous_patterns = [
                        "system(",
                        "exec(",
                        "eval(",
                        "subprocess.",
                        "os.system",
                        "import os",
                        "import sys",
                        "import subprocess",
                        "__import__(",
                        "pickle.loads",
                        "exec ",
                        "eval ",
                    ]
                    for pattern in dangerous_patterns:
                        if pattern in value:
                            issues.append(
                                Issue(
                                    message=f"Dangerous code pattern in auto_map: {value}",
                                    severity=IssueSeverity.CRITICAL,
                                    location=file_path,
                                    details={
                                        "auto_map_key": key,
                                        "code_reference": value,
                                        "dangerous_pattern": pattern,
                                    },
                                    why="Code execution patterns in auto_map can run arbitrary commands",
                                    type="code_execution",
                                )
                            )
                            break  # Only report the first match to avoid duplicates

        return issues

    def _check_suspicious_urls_in_text(self, content: str, file_path: str) -> list[Issue]:
        """Check for suspicious URLs in text content."""
        issues: list[Issue] = []
        import re

        # Find URLs in text
        url_pattern = r'https?://[^\s<>"\']+[^\s<>"\',.]'
        urls = re.findall(url_pattern, content)

        suspicious_domains = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "ow.ly",
            "github.io",
            "gitlab.io",
            "ngrok.io",
            "localtunnel.me",
        ]

        for url in urls:
            for domain in suspicious_domains:
                if domain in url.lower():
                    issues.append(
                        Issue(
                            message=f"Suspicious URL found in text metadata: {url}",
                            severity=IssueSeverity.WARNING,
                            location=file_path,
                            details={"url": url, "suspicious_domain": domain},
                            why="URL shorteners and tunnel services can hide malicious endpoints",
                            type="suspicious_url",
                        )
                    )

        return issues

    def _check_exposed_secrets_in_text(self, content: str, file_path: str) -> list[Issue]:
        """Check for exposed secrets in text content."""
        issues: list[Issue] = []
        import re

        # Common secret patterns
        secret_patterns = [
            (r"[A-Za-z0-9]{20,}", "Potential API key or token"),
            (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
            (r"sk-[A-Za-z0-9]{48}", "OpenAI API key"),
            (r"Bearer\s+[A-Za-z0-9._-]+", "Bearer token"),
            (r'[A-Za-z0-9._-]*[Tt]oken[A-Za-z0-9._-]*\s*[:=]\s*["\']?([A-Za-z0-9._-]{10,})', "Token assignment"),
        ]

        for pattern, description in secret_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Skip obvious examples or placeholders
                matched_text = match.group(0)
                if not any(
                    placeholder in matched_text.lower()
                    for placeholder in ["example", "placeholder", "your_", "xxx", "****", "token_here"]
                ):
                    issues.append(
                        Issue(
                            message=f"Potential exposed secret in text metadata: {description}",
                            severity=IssueSeverity.WARNING,
                            location=file_path,
                            details={
                                "pattern_description": description,
                                "match_preview": matched_text[:20] + "..." if len(matched_text) > 20 else matched_text,
                            },
                            why="Exposed secrets in documentation can lead to unauthorized access",
                            type="exposed_secret",
                        )
                    )

        return issues
