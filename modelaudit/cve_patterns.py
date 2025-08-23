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
from typing import Any, Dict, List, Optional, Tuple

from .suspicious_symbols import (
    CVE_2020_13092_PATTERNS,
    CVE_2024_34997_PATTERNS,
    CVE_COMBINED_PATTERNS,
    CVE_BINARY_PATTERNS,
)


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
        patterns_matched: Optional[List[str]] = None,
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

    def to_dict(self) -> Dict[str, Any]:
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


def analyze_cve_patterns(content: str, binary_content: bytes = b"") -> List[CVEAttribution]:
    """
    Analyze content for CVE-specific patterns and return attribution information.
    
    Args:
        content: String content to analyze
        binary_content: Binary content to analyze
        
    Returns:
        List of CVE attributions for detected patterns
    """
    attributions = []
    
    # Check CVE-2020-13092 patterns
    cve_2020_matches = _check_cve_2020_13092(content, binary_content)
    if cve_2020_matches:
        attributions.append(_create_cve_2020_13092_attribution(cve_2020_matches))
    
    # Check CVE-2024-34997 patterns  
    cve_2024_matches = _check_cve_2024_34997(content, binary_content)
    if cve_2024_matches:
        attributions.append(_create_cve_2024_34997_attribution(cve_2024_matches))
    
    return attributions


def _check_cve_2020_13092(content: str, binary_content: bytes) -> List[str]:
    """Check for CVE-2020-13092 specific patterns - requires multiple indicators."""
    matches = []
    
    # Check string patterns (these are already sophisticated combinations)
    for pattern in CVE_2020_13092_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
            matches.append(pattern)
    
    # For binary patterns, require multiple dangerous indicators
    cve_2020_binary_indicators = [
        b"joblib.load",
        b"sklearn",
        b"__reduce__", 
        b"os.system",
        b"subprocess",
        b"Pipeline",
    ]
    
    found_indicators = []
    for pattern in cve_2020_binary_indicators:
        if pattern in binary_content:
            found_indicators.append(pattern.decode("utf-8", errors="ignore"))
    
    # Only flag as CVE-2020-13092 if we have multiple indicators including dangerous ones
    dangerous_indicators = ["os.system", "subprocess", "__reduce__", "joblib.load"]
    has_sklearn = "sklearn" in found_indicators
    has_dangerous = any(indicator in found_indicators for indicator in dangerous_indicators)
    
    # Require both sklearn-related content AND dangerous operations
    if has_sklearn and has_dangerous and len(found_indicators) >= 3:
        matches.extend(found_indicators)
    
    return matches


def _check_cve_2024_34997(content: str, binary_content: bytes) -> List[str]:
    """Check for CVE-2024-34997 specific patterns - requires multiple indicators."""
    matches = []
    
    # Check string patterns (these are already sophisticated combinations)
    for pattern in CVE_2024_34997_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
            matches.append(pattern)
    
    # For binary patterns, require multiple dangerous indicators
    cve_2024_binary_indicators = [
        b"NumpyArrayWrapper",
        b"read_array",
        b"numpy_pickle",
        b"pickle.load",
        b"joblib.cache",
        b"__reduce__",
        b"os.system",
        b"subprocess",
    ]
    
    found_indicators = []
    for pattern in cve_2024_binary_indicators:
        if pattern in binary_content:
            found_indicators.append(pattern.decode("utf-8", errors="ignore"))
    
    # Only flag as CVE-2024-34997 if we have NumpyArrayWrapper AND dangerous operations
    numpy_indicators = ["NumpyArrayWrapper", "read_array", "numpy_pickle"]
    dangerous_indicators = ["pickle.load", "__reduce__", "os.system", "subprocess"]
    
    has_numpy = any(indicator in found_indicators for indicator in numpy_indicators)
    has_dangerous = any(indicator in found_indicators for indicator in dangerous_indicators)
    
    # Require both numpy-related content AND dangerous operations
    if has_numpy and has_dangerous and len(found_indicators) >= 2:
        matches.extend(found_indicators)
    
    return matches


def _create_cve_2020_13092_attribution(matches: List[str]) -> CVEAttribution:
    """Create CVE-2020-13092 attribution with matched patterns."""
    cve_info = CVE_COMBINED_PATTERNS["CVE-2020-13092"]
    
    # Calculate confidence based on pattern complexity and number of matches
    confidence = min(1.0, 0.7 + (len(matches) * 0.1))
    
    return CVEAttribution(
        cve_id="CVE-2020-13092",
        description=cve_info["description"],
        severity=cve_info["severity"],
        cvss=cve_info["cvss"],
        cwe=cve_info["cwe"],
        affected_versions=cve_info["affected_versions"],
        remediation=cve_info["remediation"],
        confidence=confidence,
        patterns_matched=matches,
    )


def _create_cve_2024_34997_attribution(matches: List[str]) -> CVEAttribution:
    """Create CVE-2024-34997 attribution with matched patterns."""
    cve_info = CVE_COMBINED_PATTERNS["CVE-2024-34997"]
    
    # Calculate confidence based on pattern complexity and number of matches
    confidence = min(1.0, 0.7 + (len(matches) * 0.1))
    
    return CVEAttribution(
        cve_id="CVE-2024-34997",
        description=cve_info["description"],
        severity=cve_info["severity"],
        cvss=cve_info["cvss"],
        cwe=cve_info["cwe"],
        affected_versions=cve_info["affected_versions"],
        remediation=cve_info["remediation"],
        confidence=confidence,
        patterns_matched=matches,
    )


def get_cve_attribution(patterns: List[str], binary_patterns: List[bytes] = None) -> List[CVEAttribution]:
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


def calculate_cve_risk_score(attributions: List[CVEAttribution]) -> float:
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
        return CVE_COMBINED_PATTERNS[cve_id]["remediation"]
    
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
    
    cve_patterns = CVE_COMBINED_PATTERNS[cve_id]["patterns"]
    
    for cve_pattern in cve_patterns:
        if re.search(cve_pattern, pattern, re.IGNORECASE):
            return True
    
    return False


def get_all_cve_ids() -> List[str]:
    """Get all supported CVE identifiers."""
    return list(CVE_COMBINED_PATTERNS.keys())


def get_cve_info(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Get complete information for a specific CVE.
    
    Args:
        cve_id: CVE identifier
        
    Returns:
        CVE information dictionary or None if not found
    """
    return CVE_COMBINED_PATTERNS.get(cve_id)


# Utility functions for scanner integration

def enhance_scan_result_with_cve(scan_result, detected_patterns: List[str], binary_content: bytes = b"") -> None:
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


def format_cve_report(attributions: List[CVEAttribution]) -> str:
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