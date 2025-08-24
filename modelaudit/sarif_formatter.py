"""SARIF (Static Analysis Results Interchange Format) formatter for ModelAudit.

This module converts ModelAudit scan results to SARIF 2.1.0 format for
integration with security tools and CI/CD pipelines.
"""

import contextlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from modelaudit import __version__
from modelaudit.models import ModelAuditResultModel
from modelaudit.scanners.base import IssueSeverity


def format_sarif_output(
    audit_result: ModelAuditResultModel,
    scan_paths: list[str],
    verbose: bool = False,
) -> str:
    """Format ModelAudit scan results as SARIF 2.1.0 JSON.

    Args:
        audit_result: The ModelAudit scan results
        scan_paths: List of paths that were scanned
        verbose: Whether to include debug-level findings

    Returns:
        JSON string in SARIF 2.1.0 format
    """
    sarif_output = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [_create_run(audit_result, scan_paths, verbose)],
    }

    return json.dumps(sarif_output, indent=2)


def _create_run(
    audit_result: ModelAuditResultModel,
    scan_paths: list[str],
    verbose: bool,
) -> dict[str, Any]:
    """Create a SARIF run object from ModelAudit results."""

    # Filter issues based on verbosity
    issues = audit_result.issues
    if not verbose:
        issues = [i for i in issues if i.severity != IssueSeverity.DEBUG]

    # Create rules from unique issue types
    rules = _create_rules(issues)

    # Create results from issues
    results = _create_results(issues)

    # Create artifacts from scanned files
    artifacts = _create_artifacts(audit_result)

    run = {
        "tool": {
            "driver": {
                "name": "ModelAudit",
                "version": __version__,
                "informationUri": "https://github.com/protectai/modelaudit",
                "rules": rules,
                "notifications": [],
                "taxa": [],
                "semanticVersion": __version__,
                "language": "en-US",
                "contents": ["localizedData", "nonLocalizedData"],
                "isComprehensive": False,
            }
        },
        "invocations": [
            {
                "executionSuccessful": audit_result.success,
                "commandLine": f"modelaudit {' '.join(scan_paths)}",
                "arguments": scan_paths,
                "workingDirectory": {"uri": Path.cwd().as_uri()},
                "exitCode": 0 if not audit_result.issues else 1,
                "exitCodeDescription": "No issues found" if not audit_result.issues else "Security issues detected",
                "exitSignalName": None,
                "exitSignalNumber": None,
                "processStartFailureMessage": None,
                "machine": None,
                "account": None,
                "processId": None,
                "executableLocation": None,
                "stdin": None,
                "stdout": None,
                "stderr": None,
                "stdoutStderr": None,
                "properties": {
                    "filesScanned": audit_result.files_scanned,
                    "bytesScanned": audit_result.bytes_scanned,
                    "duration": audit_result.duration,
                    "scanners": audit_result.scanner_names,
                },
            }
        ],
        "results": results,
        "artifacts": artifacts,
        "automationDetails": {
            "description": {"text": "ModelAudit security scan for ML model files"},
            "id": f"modelaudit-scan-{int(audit_result.start_time)}",
        },
        "threadFlowLocations": [],
        "taxonomies": [],
        "addresses": [],
        "translations": [],
        "policies": [],
        "webRequests": [],
        "webResponses": [],
        "properties": {
            "totalChecks": audit_result.total_checks,
            "passedChecks": audit_result.passed_checks,
            "failedChecks": audit_result.failed_checks,
        },
    }

    return run


def _create_rules(issues: list) -> list[dict[str, Any]]:
    """Create SARIF rules from unique issue types."""
    rules = []
    seen_rules = set()

    for issue in issues:
        # Create a rule ID from the issue type or message
        rule_id = _get_rule_id(issue)

        if rule_id not in seen_rules:
            seen_rules.add(rule_id)

            rule = {
                "id": rule_id,
                "name": _get_rule_name(issue),
                "shortDescription": {"text": _get_rule_short_description(issue)},
                "fullDescription": {"text": _get_rule_full_description(issue)},
                "defaultConfiguration": {
                    "enabled": True,
                    "level": _severity_to_sarif_level(issue.severity),
                    "rank": _severity_to_rank(issue.severity),
                },
                "properties": {
                    "tags": _get_tags_for_issue(issue),
                    "precision": "high",
                    "problem.severity": _severity_to_sarif_level(issue.severity).lower(),
                },
            }

            # Add help information if available
            if hasattr(issue, "why") and issue.why:
                rule["help"] = {"text": issue.why, "markdown": issue.why}

            rules.append(rule)

    return rules


def _create_results(issues: list) -> list[dict[str, Any]]:
    """Create SARIF results from issues."""
    results = []

    for idx, issue in enumerate(issues):
        result = {
            "ruleId": _get_rule_id(issue),
            "ruleIndex": idx,
            "level": _severity_to_sarif_level(issue.severity),
            "message": {"text": issue.message},
            "locations": [],
            "partialFingerprints": {},
            "relatedLocations": [],
            "suppressions": [],
            "baselineState": "new",
            "rank": _severity_to_rank(issue.severity),
            "kind": "fail" if issue.severity in [IssueSeverity.CRITICAL, IssueSeverity.WARNING] else "informational",
        }

        # Add location if available
        if issue.location:
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": _normalize_path_to_uri(issue.location), "uriBaseId": "%SRCROOT%"}
                }
            }

            # Add region information if available in details
            if issue.details and "line" in issue.details:
                location["physicalLocation"]["region"] = {
                    "startLine": issue.details.get("line", 1),
                    "startColumn": issue.details.get("column", 1),
                }

            result["locations"].append(location)  # type: ignore[attr-defined]

        # Add fingerprints for deduplication
        import hashlib

        fingerprint = hashlib.sha256(f"{issue.message}{issue.location or ''}{issue.severity}".encode()).hexdigest()[:16]
        result["partialFingerprints"]["primaryLocationLineHash"] = fingerprint  # type: ignore[index]

        # Add properties with additional details
        if issue.details:
            result["properties"] = issue.details

        # Add fix suggestions if available
        if hasattr(issue, "recommendation") and issue.recommendation:
            result["fixes"] = [{"description": {"text": issue.recommendation}}]

        results.append(result)

    return results


def _create_artifacts(audit_result: ModelAuditResultModel) -> list[dict[str, Any]]:
    """Create SARIF artifacts from scanned files."""
    artifacts = []

    for asset in audit_result.assets:
        artifact = {
            "location": {"uri": _normalize_path_to_uri(asset.path), "uriBaseId": "%SRCROOT%"},
            "mimeType": _get_mime_type(asset.type),
            "properties": {"type": asset.type},
        }

        # Add size if available
        if hasattr(asset, "size") and asset.size:
            artifact["length"] = asset.size  # type: ignore[assignment]

        # Add hashes if available from file metadata
        if asset.path in audit_result.file_metadata:
            metadata = audit_result.file_metadata[asset.path]
            if hasattr(metadata, "file_hashes") and metadata.file_hashes:
                hashes = {}
                if metadata.file_hashes.sha256:
                    hashes["sha-256"] = metadata.file_hashes.sha256
                if metadata.file_hashes.sha1:
                    hashes["sha-1"] = metadata.file_hashes.sha1
                if metadata.file_hashes.md5:
                    hashes["md5"] = metadata.file_hashes.md5

                if hashes:
                    artifact["hashes"] = hashes

        artifacts.append(artifact)

    return artifacts


def _get_rule_id(issue) -> str:
    """Generate a rule ID from an issue."""
    if hasattr(issue, "type") and issue.type:
        return f"MA{str(issue.type).replace(' ', '-').upper()}"

    # Generate from message if no type
    base = issue.message[:30].replace(" ", "-").replace(":", "").upper()
    # Remove special characters
    base = "".join(c if c.isalnum() or c == "-" else "" for c in base)
    return f"MA-{base}"


def _get_rule_name(issue) -> str:
    """Get a human-readable rule name from an issue."""
    if hasattr(issue, "type") and issue.type:
        return str(issue.type).replace("_", " ").title()

    # Extract from message
    return str(issue.message.split(":")[0] if ":" in issue.message else issue.message[:50])


def _get_rule_short_description(issue) -> str:
    """Get a short description for a rule."""
    if "pickle" in issue.message.lower():
        return "Potentially unsafe pickle operation detected"
    elif "import" in issue.message.lower():
        return "Dangerous import statement found"
    elif "exec" in issue.message.lower() or "eval" in issue.message.lower():
        return "Code execution vulnerability"
    elif "network" in issue.message.lower():
        return "Network communication detected"
    elif "secret" in issue.message.lower() or "key" in issue.message.lower():
        return "Potential secrets or keys exposed"
    elif "license" in issue.message.lower():
        return "License compliance issue"
    elif "blacklist" in issue.message.lower():
        return "Blacklisted model name detected"
    else:
        return str(issue.message[:100])


def _get_rule_full_description(issue) -> str:
    """Get a full description for a rule."""
    desc = _get_rule_short_description(issue)

    if hasattr(issue, "why") and issue.why:
        desc += f" {issue.why}"

    return desc


def _severity_to_sarif_level(severity: IssueSeverity) -> str:
    """Convert ModelAudit severity to SARIF level."""
    mapping = {
        IssueSeverity.CRITICAL: "error",
        IssueSeverity.WARNING: "warning",
        IssueSeverity.INFO: "note",
        IssueSeverity.DEBUG: "none",
    }
    return mapping.get(severity, "warning")


def _severity_to_rank(severity: IssueSeverity) -> float:
    """Convert severity to SARIF rank (0.0-100.0)."""
    mapping = {
        IssueSeverity.CRITICAL: 90.0,
        IssueSeverity.WARNING: 60.0,
        IssueSeverity.INFO: 30.0,
        IssueSeverity.DEBUG: 10.0,
    }
    return mapping.get(severity, 50.0)


def _get_tags_for_issue(issue) -> list[str]:
    """Get relevant tags for an issue."""
    tags = ["security", "ml-model"]

    message_lower = issue.message.lower()

    if "pickle" in message_lower:
        tags.append("pickle")
        tags.append("deserialization")
    if "import" in message_lower or "exec" in message_lower or "eval" in message_lower:
        tags.append("code-execution")
    if "network" in message_lower:
        tags.append("network")
    if "secret" in message_lower or "key" in message_lower:
        tags.append("secrets")
    if "license" in message_lower:
        tags.append("license")
    if "cve" in message_lower:
        tags.append("vulnerability")

    return tags


def _normalize_path_to_uri(path: str) -> str:
    """Normalize a file path to a URI format."""
    # Convert to Path object for normalization
    p = Path(path)

    # Make relative if possible
    with contextlib.suppress(ValueError):
        p = p.relative_to(Path.cwd())

    # Convert to POSIX-style path for URI
    uri_path = p.as_posix()

    # URL-encode special characters
    return quote(uri_path, safe="/")


def _get_mime_type(file_type: str) -> str:
    """Get MIME type for a file type."""
    mime_types = {
        "pickle": "application/octet-stream",
        "pytorch": "application/octet-stream",
        "tensorflow": "application/x-tensorflow",
        "onnx": "application/x-onnx",
        "keras": "application/x-keras",
        "safetensors": "application/x-safetensors",
        "joblib": "application/octet-stream",
        "numpy": "application/x-numpy",
        "zip": "application/zip",
        "tar": "application/x-tar",
        "json": "application/json",
        "yaml": "application/x-yaml",
        "text": "text/plain",
    }
    return mime_types.get(file_type.lower(), "application/octet-stream")
