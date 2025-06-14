import json
import os
from typing import Any, Dict, Optional

from .base import BaseScanner, IssueSeverity, ScanResult

# Try to import the name policies module
try:
    from modelaudit.name_policies.blacklist import check_model_name_policies

    HAS_NAME_POLICIES = True
except ImportError:
    HAS_NAME_POLICIES = False

    # Create a placeholder function when the module is not available
    def check_model_name_policies(model_name, additional_patterns=None):
        return False, ""


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

# Keys that might contain model names
MODEL_NAME_KEYS = [
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

# Suspicious configuration patterns
SUSPICIOUS_CONFIG_PATTERNS = {
    "network_access": [
        "url",
        "endpoint",
        "server",
        "host",
        "callback",
        "webhook",
        "http",
        "https",
        "ftp",
        "socket",
    ],
    "file_access": [
        "file",
        "path",
        "directory",
        "folder",
        "output",
        "input",
        "save",
        "load",
        "write",
        "read",
    ],
    "execution": [
        "exec",
        "eval",
        "execute",
        "run",
        "command",
        "script",
        "shell",
        "subprocess",
        "system",
        "code",
    ],
    "credentials": [
        "password",
        "secret",
        "credential",
        "auth",
        "authentication",
        "api_key",
    ],
}


class ManifestScanner(BaseScanner):
    """Scanner for model manifest and configuration files"""

    name = "manifest"
    description = "Scans model manifest and configuration files for suspicious content and blacklisted names"
    supported_extensions = MANIFEST_EXTENSIONS

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        # Get blacklist patterns from config
        self.blacklist_patterns = self.config.get("blacklist_patterns", [])

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        # Check file extension
        ext = os.path.splitext(path)[1].lower()
        if ext in cls.supported_extensions:
            return True

        # For files without a recognized extension, try to peek at the content
        try:
            with open(path, "r", encoding="utf-8") as f:
                first_line = f.readline().strip()
                # Check for JSON format
                if first_line.startswith("{") or first_line.startswith("["):
                    return True
                # Check for YAML format if yaml is available
                if HAS_YAML and (first_line.startswith("---") or ":" in first_line):
                    return True
        except (UnicodeDecodeError, IOError):
            pass

        return False

    def scan(self, path: str) -> ScanResult:
        """Scan a manifest or configuration file"""
        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            # Store the file path for use in issue locations
            self.current_file_path = path

            # First, check the raw file content for blacklisted terms
            self._check_file_for_blacklist(path, result)

            # Parse the file based on its extension
            ext = os.path.splitext(path)[1].lower()
            content = self._parse_file(path, ext)

            if content:
                result.bytes_scanned = file_size

                # Check for suspicious configuration patterns
                self._check_suspicious_patterns(content, result)

            else:
                result.add_issue(
                    f"Unable to parse file as a manifest or configuration: {path}",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                )

        except Exception as e:
            result.add_issue(
                f"Error scanning manifest file: {str(e)}",
                severity=IssueSeverity.ERROR,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result

    def _check_file_for_blacklist(self, path: str, result: ScanResult) -> None:
        """Check the entire file content for blacklisted terms"""
        if not self.blacklist_patterns:
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = (
                    f.read().lower()
                )  # Convert to lowercase for case-insensitive matching

                for pattern in self.blacklist_patterns:
                    pattern_lower = pattern.lower()
                    if pattern_lower in content:
                        result.add_issue(
                            f"Blacklisted term '{pattern}' found in file",
                            severity=IssueSeverity.ERROR,
                            location=self.current_file_path,
                            details={"blacklisted_term": pattern, "file_path": path},
                        )
        except Exception as e:
            result.add_issue(
                f"Error checking file for blacklist: {str(e)}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )

    def _parse_file(self, path: str, ext: str) -> Optional[Dict[str, Any]]:
        """Parse the file based on its extension"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()

                # Try JSON format first
                if ext in [
                    ".json",
                    ".manifest",
                    ".model",
                    ".metadata",
                ] or content.strip().startswith(("{", "[")):
                    return json.loads(content)

                # Try YAML format if available
                if HAS_YAML and (
                    ext in [".yaml", ".yml"] or content.strip().startswith("---")
                ):
                    return yaml.safe_load(content)

                # For other formats, try JSON and then YAML if available
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    if HAS_YAML:
                        try:
                            return yaml.safe_load(content)
                        except Exception:
                            pass

        except Exception as e:
            # Log the error but don't raise, as we want to continue scanning
            print(f"Error parsing file {path}: {str(e)}")

        return None

    def _check_suspicious_patterns(
        self, content: Dict[str, Any], result: ScanResult
    ) -> None:
        """Check for suspicious patterns in the configuration"""
        suspicious_keys = []

        def check_dict(d, prefix=""):
            if not isinstance(d, dict):
                return

            for key, value in d.items():
                key_lower = key.lower()

                # Check each category of suspicious patterns
                for category, patterns in SUSPICIOUS_CONFIG_PATTERNS.items():
                    if any(pattern in key_lower for pattern in patterns):
                        suspicious_keys.append(
                            {
                                "key": f"{prefix}.{key}" if prefix else key,
                                "value": str(value)[:100]
                                + (
                                    "..."
                                    if isinstance(value, str) and len(value) > 100
                                    else ""
                                ),
                                "category": category,
                            }
                        )

                # Recursively check nested structures
                if isinstance(value, dict):
                    check_dict(value, f"{prefix}.{key}" if prefix else key)
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            check_dict(
                                item,
                                f"{prefix}.{key}[{i}]" if prefix else f"{key}[{i}]",
                            )

        check_dict(content)

        # Report suspicious keys
        for item in suspicious_keys:
            result.add_issue(
                f"Suspicious configuration key found: {item['key']} (category: {item['category']})",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={
                    "key": item["key"],
                    "value": item["value"],
                    "category": item["category"],
                },
            )
