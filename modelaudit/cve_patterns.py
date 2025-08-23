"""
CVE Pattern Attribution System for ModelAudit

This module provides CVE-specific attribution and analysis for detected security patterns.
It integrates with the main scanning system to provide detailed CVE information when
specific vulnerability patterns are detected.

Key Features:
- CVE attribution for detected patterns
- Severity and risk scoring
- Remediation guidance
- CVSS scoring integration
- Integration with existing scanners

Usage:
    from modelaudit.cve_patterns import get_cve_attribution, analyze_cve_risk

    # Get CVE information for detected patterns
    cve_info = get_cve_attribution(detected_patterns)

    # Calculate CVE-specific risk score
    risk_score = analyze_cve_risk(patterns, context)
"""

from __future__ import annotations

import re
from typing import Any, Optional

from .suspicious_symbols import CVE_COMBINED_PATTERNS


class CVEAttribution:
    """CVE attribution information for detected patterns."""

    def __init__(
        self,
        cve_id: str,
        description: str,
        severity: str,
        cvss: float,
        cwe: str,
        affected_versions: str,
        remediation: str,
        confidence: float = 1.0,
        patterns_matched: Optional[list[str]] = None,
    ):
        self.cve_id = cve_id
        self.description = description
        self.severity = severity
        self.cvss = cvss
        self.cwe = cwe
        self.affected_versions = affected_versions
        self.remediation = remediation
        self.confidence = confidence
        self.patterns_matched = patterns_matched or []

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss": self.cvss,
            "cwe": self.cwe,
            "affected_versions": self.affected_versions,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "patterns_matched": self.patterns_matched,
        }


def analyze_cve_patterns(content: str, binary_content: bytes = b"") -> list[CVEAttribution]:
    """
    Analyze content for CVE-specific patterns using multi-line aware detection.

    Simple, effective approach that detects CVE patterns across multiple lines
    instead of requiring everything on a single line.

    Args:
        content: String content to analyze
        binary_content: Binary content to analyze

    Returns:
        List of CVE attributions for detected patterns
    """
    attributions = []

    # Check CVE-2020-13092 patterns
    cve_2020_matches = _check_cve_2020_13092_multiline(content, binary_content)
    if cve_2020_matches:
        attributions.append(_create_cve_2020_13092_attribution(cve_2020_matches))

    # Check CVE-2024-34997 patterns
    cve_2024_matches = _check_cve_2024_34997_multiline(content, binary_content)
    if cve_2024_matches:
        attributions.append(_create_cve_2024_34997_attribution(cve_2024_matches))

    return attributions


def _analyze_cve_patterns_basic(content: str, binary_content: bytes = b"") -> list[CVEAttribution]:
    """
    Basic CVE analysis fallback (original implementation).
    """
    # This function is kept for compatibility but uses the multiline versions
    return analyze_cve_patterns(content, binary_content)


def _check_cve_2020_13092_multiline(content: str, binary_content: bytes) -> list[str]:
    """
    Check for CVE-2020-13092 using multi-line aware detection.

    CVE-2020-13092: sklearn <= 0.23.0 joblib.load deserialization vulnerability
    Real malicious code spreads indicators across multiple lines.
    """
    matches = []
    content_lower = content.lower()

    # Skip documentation/comments that mention CVE patterns
    doc_indicators = ['"""', "'''", "#", "warning:", "note:", "documentation", "cve-2020", "vulnerability"]
    if any(indicator in content_lower for indicator in doc_indicators):
        # This looks like documentation, not executable code
        return []

    # Required indicators for CVE-2020-13092
    sklearn_indicators = ["sklearn", "joblib"]
    dangerous_operations = ["os.system", "subprocess", "__reduce__", "eval", "exec"]
    loading_operations = ["joblib.load", "joblib.dump", "pickle.load"]

    # Check if we have sklearn/joblib context
    has_sklearn = any(indicator in content_lower for indicator in sklearn_indicators)

    # Check if we have dangerous operations
    has_dangerous = any(op in content_lower for op in dangerous_operations)

    # Check if we have loading operations (vulnerability trigger)
    has_loading = any(op in content_lower for op in loading_operations)

    # Also check binary content for additional evidence
    binary_indicators = []
    for indicator in [b"sklearn", b"joblib", b"os.system", b"__reduce__", b"subprocess"]:
        if indicator in binary_content:
            binary_indicators.append(indicator.decode("utf-8", errors="ignore"))

    # CVE-2020-13092 detection logic:
    # Need sklearn/joblib context AND dangerous operations
    if has_sklearn and has_dangerous:
        matches.append("sklearn/joblib context with dangerous operations")

        # Higher confidence if loading operations present
        if has_loading:
            matches.append("loading operations present")

        # Higher confidence with binary evidence
        if binary_indicators:
            matches.extend(binary_indicators)

        # Check for specific dangerous combinations
        if "__reduce__" in content_lower and "os.system" in content_lower:
            matches.append("__reduce__ with os.system (high risk)")

    return matches


def _check_cve_2024_34997_multiline(content: str, binary_content: bytes) -> list[str]:
    """
    Check for CVE-2024-34997 using multi-line aware detection.

    CVE-2024-34997: joblib v1.4.2 NumpyArrayWrapper deserialization vulnerability
    Real malicious code spreads indicators across multiple lines.
    """
    matches = []
    content_lower = content.lower()

    # Skip documentation/comments that mention CVE patterns
    doc_indicators = ['"""', "'''", "#", "warning:", "note:", "documentation", "cve-2024", "vulnerability"]
    if any(indicator in content_lower for indicator in doc_indicators):
        # This looks like documentation, not executable code
        return []

    # Required indicators for CVE-2024-34997
    numpy_indicators = ["numpyarraywrapper", "read_array", "numpy_pickle"]
    dangerous_operations = ["pickle.load", "os.system", "subprocess", "__reduce__", "eval", "exec"]
    joblib_context = ["joblib", "joblib.cache"]

    # Check if we have numpy wrapper context
    has_numpy = any(indicator in content_lower for indicator in numpy_indicators)

    # Check if we have dangerous operations
    has_dangerous = any(op in content_lower for op in dangerous_operations)

    # Check if we have joblib context
    has_joblib = any(context in content_lower for context in joblib_context)

    # Also check binary content for additional evidence
    binary_indicators = []
    for indicator in [b"NumpyArrayWrapper", b"read_array", b"pickle.load", b"joblib", b"os.system"]:
        if indicator in binary_content:
            binary_indicators.append(indicator.decode("utf-8", errors="ignore"))

    # CVE-2024-34997 detection logic:
    # Need numpy wrapper context AND dangerous operations
    if has_numpy and has_dangerous:
        matches.append("NumpyArrayWrapper context with dangerous operations")

        # Higher confidence with joblib context
        if has_joblib:
            matches.append("joblib context present")

        # Higher confidence with binary evidence
        if binary_indicators:
            matches.extend(binary_indicators)

        # Check for specific dangerous combinations
        if "pickle.load" in content_lower and "numpyarraywrapper" in content_lower:
            matches.append("NumpyArrayWrapper with pickle.load (high risk)")

    return matches


def _create_cve_2020_13092_attribution(matches: list[str]) -> CVEAttribution:
    """Create CVE-2020-13092 attribution with matched patterns."""
    cve_info = CVE_COMBINED_PATTERNS["CVE-2020-13092"]

    # Calculate confidence based on pattern complexity and number of matches
    confidence = min(1.0, 0.7 + (len(matches) * 0.1))

    return CVEAttribution(
        cve_id="CVE-2020-13092",
        description=str(cve_info["description"]),
        severity=str(cve_info["severity"]),
        cvss=float(cve_info.get("cvss", 0.0)),  # type: ignore[arg-type]
        cwe=str(cve_info["cwe"]),
        affected_versions=str(cve_info["affected_versions"]),
        remediation=str(cve_info["remediation"]),
        confidence=confidence,
        patterns_matched=matches,
    )


def _create_cve_2024_34997_attribution(matches: list[str]) -> CVEAttribution:
    """Create CVE-2024-34997 attribution with matched patterns."""
    cve_info = CVE_COMBINED_PATTERNS["CVE-2024-34997"]

    # Calculate confidence based on pattern complexity and number of matches
    confidence = min(1.0, 0.7 + (len(matches) * 0.1))

    return CVEAttribution(
        cve_id="CVE-2024-34997",
        description=str(cve_info["description"]),
        severity=str(cve_info["severity"]),
        cvss=float(cve_info.get("cvss", 0.0)),  # type: ignore[arg-type]
        cwe=str(cve_info["cwe"]),
        affected_versions=str(cve_info["affected_versions"]),
        remediation=str(cve_info["remediation"]),
        confidence=confidence,
        patterns_matched=matches,
    )


def get_cve_attribution(patterns: list[str], binary_patterns: Optional[list[bytes]] = None) -> list[CVEAttribution]:
    """
    Get CVE attribution for a list of detected patterns.

    Args:
        patterns: List of detected string patterns
        binary_patterns: List of detected binary patterns

    Returns:
        List of CVE attributions
    """
    if binary_patterns is None:
        binary_patterns = []

    # Combine patterns for analysis
    content = " ".join(patterns)
    binary_content = b" ".join(binary_patterns)

    return analyze_cve_patterns(content, binary_content)


def calculate_cve_risk_score(attributions: list[CVEAttribution]) -> float:
    """
    Calculate overall risk score based on CVE attributions.

    Args:
        attributions: List of CVE attributions

    Returns:
        Risk score from 0.0 to 1.0
    """
    if not attributions:
        return 0.0

    # Use highest CVSS score, weighted by confidence
    max_risk = 0.0
    for attribution in attributions:
        # Normalize CVSS (0-10) to risk score (0-1)
        normalized_cvss = attribution.cvss / 10.0
        weighted_risk = normalized_cvss * attribution.confidence
        max_risk = max(max_risk, weighted_risk)

    return min(1.0, max_risk)


def get_cve_remediation_guidance(cve_id: str) -> str:
    """
    Get specific remediation guidance for a CVE.

    Args:
        cve_id: CVE identifier (e.g., 'CVE-2020-13092')

    Returns:
        Detailed remediation guidance
    """
    if cve_id in CVE_COMBINED_PATTERNS:
        return str(CVE_COMBINED_PATTERNS[cve_id]["remediation"])

    return "No specific remediation guidance available"


def is_cve_pattern_match(pattern: str, cve_id: str) -> bool:
    """
    Check if a pattern matches a specific CVE.

    Args:
        pattern: Pattern to check
        cve_id: CVE identifier

    Returns:
        True if pattern matches the CVE
    """
    if cve_id not in CVE_COMBINED_PATTERNS:
        return False

    cve_info = CVE_COMBINED_PATTERNS[cve_id]
    if "patterns" not in cve_info:
        return False

    cve_patterns = cve_info["patterns"]
    if not isinstance(cve_patterns, list):
        return False

    return any(re.search(cve_pattern, pattern, re.IGNORECASE) for cve_pattern in cve_patterns)


def get_all_cve_ids() -> list[str]:
    """Get all supported CVE identifiers."""
    return list(CVE_COMBINED_PATTERNS.keys())


def get_cve_info(cve_id: str) -> Optional[dict[str, Any]]:
    """
    Get complete information for a specific CVE.

    Args:
        cve_id: CVE identifier

    Returns:
        CVE information dictionary or None if not found
    """
    return CVE_COMBINED_PATTERNS.get(cve_id)


# Utility functions for scanner integration


def enhance_scan_result_with_cve(scan_result, detected_patterns: list[str], binary_content: bytes = b"") -> None:
    """
    Enhance a scan result with CVE attribution information.

    Args:
        scan_result: ScanResult object to enhance
        detected_patterns: List of detected pattern strings
        binary_content: Binary content that was scanned
    """
    # Analyze for CVE patterns
    cve_attributions = analyze_cve_patterns(" ".join(detected_patterns), binary_content)

    # Add CVE information to scan result metadata
    if cve_attributions:
        scan_result.metadata["cve_attributions"] = [attr.to_dict() for attr in cve_attributions]
        scan_result.metadata["cve_risk_score"] = calculate_cve_risk_score(cve_attributions)
        scan_result.metadata["cve_count"] = len(cve_attributions)

        # Add highest severity CVE to metadata
        highest_cvss = max(attr.cvss for attr in cve_attributions)
        highest_cve = next(attr for attr in cve_attributions if attr.cvss == highest_cvss)
        scan_result.metadata["primary_cve"] = highest_cve.cve_id


# Helper functions for enhanced CVE analysis integration


def _get_cve_description(cve_id: str) -> str:
    """Get CVE description."""
    info = CVE_COMBINED_PATTERNS.get(cve_id, {})
    return str(info.get("description", "Unknown CVE"))


def _get_cve_severity(cve_id: str) -> str:
    """Get CVE severity."""
    info = CVE_COMBINED_PATTERNS.get(cve_id, {})
    return str(info.get("severity", "UNKNOWN"))


def _get_cve_cvss(cve_id: str) -> float:
    """Get CVE CVSS score."""
    info = CVE_COMBINED_PATTERNS.get(cve_id, {})
    cvss_value = info.get("cvss", 0.0)
    if isinstance(cvss_value, (int, float)):
        return float(cvss_value)
    return 0.0


def _get_cve_cwe(cve_id: str) -> str:
    """Get CVE CWE classification."""
    info = CVE_COMBINED_PATTERNS.get(cve_id, {})
    return str(info.get("cwe", "CWE-UNKNOWN"))


def _get_cve_affected_versions(cve_id: str) -> str:
    """Get CVE affected versions."""
    info = CVE_COMBINED_PATTERNS.get(cve_id, {})
    return str(info.get("affected_versions", "Unknown versions"))


def _get_cve_remediation(cve_id: str) -> str:
    """Get CVE remediation guidance."""
    info = CVE_COMBINED_PATTERNS.get(cve_id, {})
    return str(info.get("remediation", "No remediation guidance available"))


def format_cve_report(attributions: list[CVEAttribution]) -> str:
    """
    Format CVE attributions into a human-readable report.

    Args:
        attributions: List of CVE attributions

    Returns:
        Formatted report string
    """
    if not attributions:
        return "No CVE-specific patterns detected."

    report = "CVE Detection Report:\n"
    report += "=" * 50 + "\n\n"

    for i, attr in enumerate(attributions, 1):
        report += f"{i}. {attr.cve_id}\n"
        report += f"   Description: {attr.description}\n"
        report += f"   Severity: {attr.severity} (CVSS: {attr.cvss})\n"
        report += f"   CWE: {attr.cwe}\n"
        report += f"   Affected Versions: {attr.affected_versions}\n"
        report += f"   Confidence: {attr.confidence:.2f}\n"
        report += f"   Patterns Matched: {len(attr.patterns_matched)}\n"
        report += f"   Remediation: {attr.remediation}\n\n"

    return report
