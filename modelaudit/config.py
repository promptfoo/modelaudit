"""
Configuration management for ModelAudit rule system.
Simple TOML-based configuration for suppressing rules and adjusting severity.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # Python < 3.11

from .rules import Severity


@dataclass
class ModelAuditConfig:
    """Configuration for ModelAudit scanning."""
    
    # Rules to suppress (won't be reported)
    suppress: Set[str] = field(default_factory=set)
    
    # Severity overrides for specific rules
    severity: Dict[str, Severity] = field(default_factory=dict)
    
    # Per-file ignore patterns (gitignore-style patterns -> rules to ignore)
    ignore: Dict[str, List[str]] = field(default_factory=dict)
    
    # Scanner options
    options: Dict[str, any] = field(default_factory=dict)
    
    @classmethod
    def load(cls, path: Optional[Path] = None) -> "ModelAuditConfig":
        """
        Load configuration from file or use defaults.
        
        Search order:
        1. Specified path (if provided)
        2. .modelaudit.toml in current directory
        3. pyproject.toml [tool.modelaudit] section
        4. Default empty config
        """
        config = cls()
        
        # If specific path provided, use only that
        if path:
            if path.exists():
                config._load_from_file(path)
            return config
        
        # Try .modelaudit.toml first
        modelaudit_toml = Path(".modelaudit.toml")
        if modelaudit_toml.exists():
            config._load_from_file(modelaudit_toml)
            return config
        
        # Try pyproject.toml
        pyproject_toml = Path("pyproject.toml")
        if pyproject_toml.exists():
            config._load_from_pyproject(pyproject_toml)
            return config
        
        # Return default config
        return config
    
    def _load_from_file(self, path: Path):
        """Load configuration from a TOML file."""
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
                self._parse_config(data)
        except Exception as e:
            # Silently ignore config errors - use defaults
            # This makes the tool more robust
            pass
    
    def _load_from_pyproject(self, path: Path):
        """Load configuration from pyproject.toml [tool.modelaudit] section."""
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
                if "tool" in data and "modelaudit" in data["tool"]:
                    self._parse_config(data["tool"]["modelaudit"])
        except Exception:
            # Silently ignore config errors
            pass
    
    def _parse_config(self, data: dict):
        """Parse configuration dictionary into this object."""
        # Parse suppress list
        if "suppress" in data and isinstance(data["suppress"], list):
            self.suppress = set(data["suppress"])
        
        # Parse severity overrides
        if "severity" in data and isinstance(data["severity"], dict):
            for rule_code, severity_str in data["severity"].items():
                try:
                    # Convert string to Severity enum
                    self.severity[rule_code] = Severity(severity_str.upper())
                except (ValueError, AttributeError):
                    # Invalid severity, skip
                    pass
        
        # Parse ignore patterns
        if "ignore" in data and isinstance(data["ignore"], dict):
            self.ignore = data["ignore"]
        
        # Parse options
        if "options" in data and isinstance(data["options"], dict):
            self.options = data["options"]
    
    def is_suppressed(self, rule_code: str, file_path: Optional[str] = None) -> bool:
        """
        Check if a rule should be suppressed.
        
        Args:
            rule_code: The rule code (e.g., "S101")
            file_path: Optional file path to check against ignore patterns
        
        Returns:
            True if the rule should be suppressed
        """
        # Check global suppression
        if rule_code in self.suppress:
            return True
        
        # Check file-specific suppression
        if file_path and self.ignore:
            for pattern, rules in self.ignore.items():
                if self._matches_pattern(file_path, pattern):
                    if rule_code in rules or "ALL" in rules:
                        return True
        
        return False
    
    def get_severity(self, rule_code: str, default: Severity) -> Severity:
        """
        Get the configured severity for a rule.
        
        Args:
            rule_code: The rule code
            default: Default severity if not overridden
        
        Returns:
            The configured or default severity
        """
        return self.severity.get(rule_code, default)
    
    def _matches_pattern(self, file_path: str, pattern: str) -> bool:
        """
        Check if a file path matches a gitignore-style pattern.
        
        Simple implementation - can be enhanced with proper gitignore library.
        """
        from fnmatch import fnmatch
        
        # Simple glob matching for now
        # Could use gitignore library for full compatibility
        return fnmatch(file_path, pattern) or fnmatch(Path(file_path).name, pattern)
    
    @classmethod
    def from_cli_args(cls, suppress: Optional[List[str]] = None,
                      severity: Optional[Dict[str, str]] = None) -> "ModelAuditConfig":
        """
        Create config from CLI arguments.
        
        Args:
            suppress: List of rule codes to suppress
            severity: Dict of rule code -> severity overrides
        
        Returns:
            Configuration object
        """
        config = cls.load()  # Start with file config
        
        # Override with CLI args
        if suppress:
            config.suppress.update(suppress)
        
        if severity:
            for rule_code, severity_str in severity.items():
                try:
                    config.severity[rule_code] = Severity(severity_str.upper())
                except (ValueError, AttributeError):
                    pass
        
        return config


# Global config instance (lazy loaded)
_global_config: Optional[ModelAuditConfig] = None


def get_config() -> ModelAuditConfig:
    """Get the global configuration instance."""
    global _global_config
    if _global_config is None:
        _global_config = ModelAuditConfig.load()
    return _global_config


def set_config(config: ModelAuditConfig):
    """Set the global configuration instance."""
    global _global_config
    _global_config = config


def reset_config():
    """Reset the global configuration (useful for testing)."""
    global _global_config
    _global_config = None