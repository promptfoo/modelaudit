"""Standalone pickle scanning API."""

from ._known_size_stream_security import install as _install_known_size_stream_security
from .api import PickleScanner, scan_bytes, scan_file, scan_stream
from .call_graph import shared_source_sensitive_caches
from .options import ScanOptions
from .report import CoverageSummary, Finding, Notice, PickleReport, SafetyVerdict, ScanError, ScanStatus, Severity

_install_known_size_stream_security()
del _install_known_size_stream_security

__all__ = [
    "CoverageSummary",
    "Finding",
    "Notice",
    "PickleReport",
    "PickleScanner",
    "SafetyVerdict",
    "ScanError",
    "ScanOptions",
    "ScanStatus",
    "Severity",
    "scan_bytes",
    "scan_file",
    "scan_stream",
    "shared_source_sensitive_caches",
]
