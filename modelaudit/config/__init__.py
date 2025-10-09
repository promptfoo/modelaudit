"""Configuration and static data for ModelAudit.

This package contains configuration files and static data used throughout ModelAudit:
- constants.py - Global constants and configuration values
- name_blacklist.py - Blacklisted model names and patterns
- explanations.py - Human-readable explanations for security issues
"""

from modelaudit.config import constants, explanations, name_blacklist

__all__ = [
    "constants",
    "explanations",
    "name_blacklist",
]
