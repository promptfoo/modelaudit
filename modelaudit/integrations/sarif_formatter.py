"""SARIF (Static Analysis Results Interchange Format) formatter for ModelAudit.

This module converts ModelAudit scan results to SARIF 2.1.0 format for
integration with security tools and CI/CD pipelines.
"""

import contextlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

from pydantic import BaseModel

from modelaudit import __version__
from modelaudit.core_results import (
    determine_exit_code,
    results_have_inconclusive_outcome,
    results_have_operational_error,
)
from modelaudit.models import ModelAuditResultModel
from modelaudit.scanner_results import IssueSeverity
from modelaudit.utils.sources.cloud_storage import is_stream_url
from modelaudit.utils.sources.cloud_storage import (
    normalize_escaped_url_delimiters_for_display as _normalize_escaped_url_delimiters_for_display,
)
from modelaudit.utils.sources.cloud_storage import redact_cloud_error_for_display as _redact_cloud_error_for_display
from modelaudit.utils.sources.cloud_storage import redact_stream_url_for_display as _redact_stream_url_for_display
from modelaudit.utils.sources.cloud_storage import redact_url_for_display as _redact_url_for_display

_URL_TEXT_CHARACTER = r'(?:[^\s"\'<>]|<redacted>|<credentials-redacted>)'
_URL_TOKEN_RE = re.compile(
    rf"(stream://[a-z][a-z0-9+.-]*://{_URL_TEXT_CHARACTER}+|[a-z][a-z0-9+.-]*://{_URL_TEXT_CHARACTER}+)",
    re.IGNORECASE,
)


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
    safe_scan_paths = [_redact_path_for_sarif(path) for path in scan_paths]

    # Filter issues based on verbosity
    issues = audit_result.issues
    if not verbose:
        issues = [i for i in issues if i.severity != IssueSeverity.DEBUG]
    issues = _primary_sarif_issues(issues)

    # Create rules from unique issue types
    rules = _create_rules(issues, prefiltered=True)
    rule_indices = {rule["id"]: idx for idx, rule in enumerate(rules)}

    # Create results from issues
    results = _create_results(issues, rule_indices, prefiltered=True)

    # Create artifacts from scanned files
    artifacts = _create_artifacts(audit_result)
    exit_code = determine_exit_code(audit_result)

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
                "executionSuccessful": exit_code != 2,
                "commandLine": f"modelaudit {' '.join(safe_scan_paths)}",
                "arguments": safe_scan_paths,
                "workingDirectory": {"uri": Path.cwd().as_uri()},
                "exitCode": exit_code,
                "exitCodeDescription": _exit_code_description(audit_result, exit_code),
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


def _exit_code_description(audit_result: ModelAuditResultModel, exit_code: int) -> str:
    """Return a user-facing description for ModelAudit CLI exit semantics."""
    if exit_code == 0:
        return "No security issues found"
    if exit_code == 1:
        return "Security issues detected"
    if results_have_operational_error(audit_result):
        return "Errors occurred during scanning"
    if results_have_inconclusive_outcome(audit_result):
        return "Scan outcome was inconclusive"
    if audit_result.files_scanned == 0:
        return "No files were scanned"
    return "Errors occurred during scanning"


def _create_rules(issues: list, *, prefiltered: bool = False) -> list[dict[str, Any]]:
    """Create SARIF rules from unique issue types."""
    if not prefiltered:
        issues = _primary_sarif_issues(issues)
    rules = []
    seen_rules = set()

    for issue in issues:
        # Create a rule ID from the issue type or message
        rule_id = _get_rule_id(issue)

        if rule_id not in seen_rules:
            seen_rules.add(rule_id)

            rule: dict[str, Any] = {
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

            rule_code = _get_issue_rule_code(issue)
            if rule_code:
                rule["properties"]["rule_code"] = rule_code

            # Add help information if available
            if hasattr(issue, "why") and issue.why:
                redacted_why = _redact_text_for_sarif(issue.why)
                rule["help"] = {"text": redacted_why, "markdown": redacted_why}

            rules.append(rule)

    return rules


def _create_results(
    issues: list,
    rule_indices: dict[str, int] | None = None,
    *,
    prefiltered: bool = False,
) -> list[dict[str, Any]]:
    """Create SARIF results from issues."""
    if not prefiltered:
        issues = _primary_sarif_issues(issues)
    results = []
    if rule_indices is None:
        rule_indices = {rule["id"]: idx for idx, rule in enumerate(_create_rules(issues, prefiltered=prefiltered))}

    for issue in issues:
        rule_id = _get_rule_id(issue)
        result = {
            "ruleId": rule_id,
            "ruleIndex": rule_indices[rule_id],
            "level": _severity_to_sarif_level(issue.severity),
            "message": {"text": _redact_text_for_sarif(issue.message)},
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

        fingerprint_message = _redact_text_for_sarif(issue.message)
        fingerprint_location = _redact_text_for_sarif(issue.location or "")
        fingerprint = hashlib.sha256(
            f"{fingerprint_message}{fingerprint_location}{issue.severity}".encode()
        ).hexdigest()[:16]
        result["partialFingerprints"]["primaryLocationLineHash"] = fingerprint  # type: ignore[index]

        # Add properties with additional details
        properties = _redact_value_for_sarif(dict(issue.details or {}))
        properties.pop("rule_code", None)
        properties.pop("issue_type", None)
        rule_code = _get_issue_rule_code(issue)
        if rule_code:
            properties["rule_code"] = rule_code
        if hasattr(issue, "type") and issue.type:
            properties["issue_type"] = _redact_text_for_sarif(issue.type)
        if properties:
            result["properties"] = properties

        # Add fix suggestions if available
        if hasattr(issue, "recommendation") and issue.recommendation:
            result["fixes"] = [{"description": {"text": _redact_text_for_sarif(issue.recommendation)}}]

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


def _primary_sarif_issues(issues: list) -> list:
    """Return issues that should be emitted as primary SARIF results."""
    return [issue for issue in issues if not _is_supporting_rule_code_issue(issue)]


def _is_supporting_rule_code_issue(issue: Any) -> bool:
    details = getattr(issue, "details", None)
    return isinstance(details, dict) and details.get("supporting_rule_code") is True


def _get_rule_id(issue: Any) -> str:
    """Generate a rule ID from an issue."""
    rule_code = _get_issue_rule_code(issue)
    if rule_code:
        return rule_code

    if hasattr(issue, "type") and issue.type:
        redacted_type = _redact_text_for_sarif(str(issue.type))
        return f"MA{redacted_type.replace(' ', '-').upper()}"

    # Generate from message if no type
    redacted_message = _redact_text_for_sarif(issue.message)
    base = redacted_message[:30].replace(" ", "-").replace(":", "").upper()
    # Remove special characters
    base = "".join(c if c.isalnum() or c == "-" else "" for c in base)
    return f"MA-{base}"


def _get_issue_rule_code(issue: Any) -> str | None:
    """Return the stable ModelAudit rule code for an issue when available."""
    rule_code = getattr(issue, "rule_code", None)
    if isinstance(rule_code, str) and rule_code:
        return _redact_text_for_sarif(rule_code)
    return None


def _get_rule_name(issue: Any) -> str:
    """Get a human-readable rule name from an issue."""
    if hasattr(issue, "type") and issue.type:
        return _redact_text_for_sarif(str(issue.type)).replace("_", " ").title()

    # Extract from message
    redacted_message = _redact_text_for_sarif(issue.message)
    return str(redacted_message.split(":")[0] if ":" in redacted_message else redacted_message[:50])


def _get_rule_short_description(issue: Any) -> str:
    """Get a short description for a rule."""
    lowered_message = issue.message.lower()
    if "pickle" in lowered_message:
        return "Potentially unsafe pickle operation detected"
    elif "import" in lowered_message:
        return "Dangerous import statement found"
    elif "exec" in lowered_message or "eval" in lowered_message:
        return "Code execution vulnerability"
    elif "network" in lowered_message:
        return "Network communication detected"
    elif "secret" in lowered_message or "key" in lowered_message:
        return "Potential secrets or keys exposed"
    elif "license" in lowered_message:
        return "License compliance issue"
    elif "blacklist" in lowered_message:
        return "Blacklisted model name detected"
    else:
        return str(_redact_text_for_sarif(issue.message)[:100])


def _get_rule_full_description(issue: Any) -> str:
    """Get a full description for a rule."""
    desc = _get_rule_short_description(issue)

    if hasattr(issue, "why") and issue.why:
        desc += f" {_redact_text_for_sarif(issue.why)}"

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


def _get_tags_for_issue(issue: Any) -> list[str]:
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
    path = _redact_path_for_sarif(path)
    # Convert to Path object for normalization
    p = Path(path)

    # Make relative if possible
    with contextlib.suppress(ValueError):
        p = p.relative_to(Path.cwd())

    # Convert to POSIX-style path for URI
    uri_path = p.as_posix()

    # URL-encode special characters
    return quote(uri_path, safe="/")


def _redact_path_for_sarif(path: str) -> str:
    """Return a SARIF-safe path without signed URL material."""
    if is_stream_url(path):
        return f"stream://{_redact_stream_url_for_display(path[9:])}"
    return _redact_url_for_display(path)


def _redact_text_for_sarif(text: str) -> str:
    """Redact signed URL tokens embedded in SARIF text fields."""
    normalized_text = _normalize_escaped_url_delimiters_for_display(text)
    redacted_text = _URL_TOKEN_RE.sub(lambda match: _redact_url_token_for_sarif(match.group(0)), normalized_text)
    return _redact_cloud_error_for_display(redacted_text)


def _redact_url_token_for_sarif(url: str) -> str:
    """Preserve benign query context while removing credentials from evidence URLs."""
    if is_stream_url(url):
        return _redact_path_for_sarif(url)
    preserve_redacted_params = "<redacted>" in url
    redacted_url = _redact_cloud_error_for_display(url)
    parts = urlsplit(url) if redacted_url == url else urlsplit(redacted_url)

    safe_query = _filter_sarif_url_params(parts.query, preserve_redacted_params=preserve_redacted_params)
    safe_fragment = _filter_sarif_url_params(parts.fragment, preserve_redacted_params=preserve_redacted_params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, safe_query, safe_fragment))


def _filter_sarif_url_params(value: str, *, preserve_redacted_params: bool) -> str:
    """Keep structured safe URL parameters and discard opaque credential material."""
    safe_parts: list[str] = []
    for part in re.split(r"[&;]", value):
        if "=" not in part:
            continue
        if part.endswith("=<redacted>") and not preserve_redacted_params:
            continue
        safe_parts.append(part)
    return "&".join(safe_parts)


def _redact_value_for_sarif(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _redact_value_for_sarif(value.model_dump(mode="python"))
    if isinstance(value, str):
        return _redact_text_for_sarif(value)
    if isinstance(value, (bytes, bytearray)):
        try:
            return _redact_text_for_sarif(bytes(value).decode("utf-8"))
        except UnicodeDecodeError:
            return "<binary data>"
    if isinstance(value, dict):
        return {_redact_mapping_key_for_sarif(key): _redact_value_for_sarif(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value_for_sarif(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value_for_sarif(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return sorted((_redact_value_for_sarif(item) for item in value), key=repr)
    return value


def _redact_mapping_key_for_sarif(value: Any) -> str | int | float | bool | None:
    redacted = _redact_value_for_sarif(value)
    if isinstance(redacted, (str, int, float, bool)) or redacted is None:
        return redacted
    return str(redacted)


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
