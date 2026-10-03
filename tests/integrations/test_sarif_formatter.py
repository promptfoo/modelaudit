"""Tests for SARIF formatter module."""

import hashlib
import io
import json
import os
import sys
import time
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

import modelaudit.integrations.sarif_formatter as sarif_formatter
from modelaudit.core import scan_model_directory_or_file
from modelaudit.integrations._sarif_identity import redact_source_identifier, redact_source_text
from modelaudit.models import (
    AssetModel,
    FileHashesModel,
    FileMetadataModel,
    ModelAuditResultModel,
    create_initial_audit_result,
)
from modelaudit.scanners.base import Check, CheckStatus, Issue, IssueSeverity, ScanResult

_create_artifacts = sarif_formatter._create_artifacts
_create_results = sarif_formatter._create_results
_create_rules = sarif_formatter._create_rules
_create_run = sarif_formatter._create_run
_get_mime_type = sarif_formatter._get_mime_type
_get_rule_full_description = sarif_formatter._get_rule_full_description
_get_rule_id = sarif_formatter._get_rule_id
_get_rule_name = sarif_formatter._get_rule_name
_get_rule_short_description = sarif_formatter._get_rule_short_description
_get_tags_for_issue = sarif_formatter._get_tags_for_issue
_normalize_path_to_uri = sarif_formatter._normalize_path_to_uri
_severity_to_rank = sarif_formatter._severity_to_rank
_severity_to_sarif_level = sarif_formatter._severity_to_sarif_level
format_sarif_output = sarif_formatter.format_sarif_output


class TestFormatSarifOutput:
    """Tests for main SARIF output formatting."""

    def test_basic_output_structure(self):
        """Test that output has correct SARIF structure."""
        result = create_initial_audit_result()
        result.finalize_statistics()

        output = format_sarif_output(result, ["/test/path"])
        parsed = json.loads(output)

        assert "$schema" in parsed
        assert parsed["version"] == "2.1.0"
        assert "runs" in parsed
        assert len(parsed["runs"]) == 1

    def test_with_issues(self):
        """Test SARIF output with issues."""
        result = create_initial_audit_result()
        issue = Issue(
            message="Test security issue",
            severity=IssueSeverity.WARNING,
            location="/test/file.pkl",
            timestamp=time.time(),
        )
        result.issues = [issue]
        result.finalize_statistics()

        output = format_sarif_output(result, ["/test/path"])
        parsed = json.loads(output)

        run = parsed["runs"][0]
        assert len(run["results"]) == 1
        assert len(run["tool"]["driver"]["rules"]) == 1

    def test_signed_stream_paths_and_values_are_preserved(self) -> None:
        """SARIF preserves raw source paths and nested evidence types."""
        raw_path = (
            "stream://https://bucket.s3.amazonaws.com/model.pkl?"
            "X-Amz-Credential=AKIASECRET&X-Amz-Signature=deadbeef&token=secret-token"
        )
        safe_path = raw_path
        result = create_initial_audit_result()
        result.assets = [AssetModel(path=raw_path, type="pickle")]
        result.issues = [
            Issue(
                message=f"Test security issue from {raw_path}",
                severity=IssueSeverity.WARNING,
                location=raw_path,
                details={
                    "source": raw_path,
                    raw_path.encode(): {"nested": [raw_path]},
                    "source_set": {raw_path},
                    "source_bytes": raw_path.encode(),
                    "parsed_query": {
                        "Authorization": "Bearer standalone-auth-secret",
                        "client_secret": "standalone-client-secret",
                        "tokenizer": "sentencepiece",
                    },
                    "nested_model": Issue(message=raw_path, details={"source_bytes": raw_path.encode()}),
                },
                why=f"Why contains {raw_path}",
                recommendation=f"Retry with {raw_path}",
                type=raw_path,
                rule_code=raw_path,
                timestamp=time.time(),
            )
        ]
        result.finalize_statistics()

        output = format_sarif_output(result, [raw_path])
        parsed = json.loads(output)
        invocation = parsed["runs"][0]["invocations"][0]

        for leaked in (
            "AKIASECRET",
            "deadbeef",
            "secret-token",
            "X-Amz-Signature",
            "standalone-auth-secret",
            "standalone-client-secret",
        ):
            assert leaked in output
        assert "sentencepiece" in output
        assert raw_path in output
        assert safe_path in output
        assert safe_path in invocation["commandLine"]
        assert invocation["arguments"] == [safe_path]

    def test_benign_raw_query_context_is_preserved(self) -> None:
        """SARIF text sanitization should retain non-credential query parameters."""
        documentation_url = "https://docs.example/help?section=models&lang=en"
        result = create_initial_audit_result()
        result.issues = [
            Issue(
                message=f"See {documentation_url}",
                severity=IssueSeverity.INFO,
                details={"documentation_url": documentation_url},
                timestamp=time.time(),
            )
        ]
        result.finalize_statistics()

        output = format_sarif_output(result, ["/test/path"])

        assert documentation_url in output

    def test_sarif_windows_path_uri(self) -> None:
        """Local Windows paths must not be rewritten as URL schemes."""
        windows_path = r"C:\models\model.pkl"

        result = create_initial_audit_result()
        parsed = json.loads(format_sarif_output(result, [windows_path]))
        assert parsed["runs"][0]["invocations"][0]["arguments"] == [windows_path]

    def test_verbose_includes_debug(self):
        """Test that verbose mode includes debug issues."""
        result = create_initial_audit_result()
        result.issues = [
            Issue(message="Debug issue", severity=IssueSeverity.DEBUG, timestamp=time.time()),
            Issue(message="Warning issue", severity=IssueSeverity.WARNING, timestamp=time.time()),
        ]
        result.finalize_statistics()

        # Non-verbose should filter debug
        output = format_sarif_output(result, ["/test"], verbose=False)
        parsed = json.loads(output)
        assert len(parsed["runs"][0]["results"]) == 1

        # Verbose should include debug
        output = format_sarif_output(result, ["/test"], verbose=True)
        parsed = json.loads(output)
        assert len(parsed["runs"][0]["results"]) == 2

    def test_supporting_rule_code_issues_are_not_emitted_as_primary_results(self) -> None:
        """Compatibility-only supporting rows should not duplicate SARIF findings."""
        result = create_initial_audit_result()
        result.issues = [
            Issue(
                message="Primary dangerous call",
                severity=IssueSeverity.CRITICAL,
                location="/test/file.pkl",
                details={"pickle_rule_code": "DANGEROUS_CALL"},
                rule_code="S104",
                timestamp=time.time(),
            ),
            Issue(
                message="Supporting REDUCE opcode row",
                severity=IssueSeverity.CRITICAL,
                location="/test/file.pkl",
                details={"supporting_rule_code": True, "primary_rule_code": "S104"},
                rule_code="S201",
                timestamp=time.time(),
            ),
        ]
        result.finalize_statistics()

        output = format_sarif_output(result, ["/test"], verbose=True)
        run = json.loads(output)["runs"][0]

        assert [item["ruleId"] for item in run["results"]] == ["S104"]
        assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["S104"]


class TestCreateRun:
    """Tests for _create_run function."""

    def test_run_structure(self):
        """Test run object structure."""
        result = create_initial_audit_result()
        result.finalize_statistics()

        run = _create_run(result, ["/test/path"], verbose=False)

        assert "tool" in run
        assert "invocations" in run
        assert "results" in run
        assert "artifacts" in run
        assert "automationDetails" in run

    def test_tool_driver_info(self):
        """Test tool driver information."""
        result = create_initial_audit_result()
        result.finalize_statistics()

        run = _create_run(result, ["/test"], verbose=False)

        driver = run["tool"]["driver"]
        assert driver["name"] == "ModelAudit"
        assert "version" in driver
        assert "rules" in driver

    def test_primary_issue_filter_runs_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Prefiltered issues should not be filtered again while building one run."""
        result = create_initial_audit_result()
        result.issues = [
            Issue(
                message="Primary dangerous call",
                severity=IssueSeverity.CRITICAL,
                location="/test/file.pkl",
                details={"pickle_rule_code": "DANGEROUS_CALL"},
                rule_code="S104",
                timestamp=time.time(),
            ),
            Issue(
                message="Supporting import module",
                severity=IssueSeverity.WARNING,
                location="/test/file.pkl",
                details={"supporting_rule_code": True, "primary_rule_code": "S104"},
                rule_code="S100",
                timestamp=time.time(),
            ),
        ]
        result.finalize_statistics()

        call_count = 0
        original_primary_sarif_issues = sarif_formatter._primary_sarif_issues

        def counting_primary_sarif_issues(issues: list[Issue]) -> list[Issue]:
            nonlocal call_count
            call_count += 1
            return original_primary_sarif_issues(issues)

        monkeypatch.setattr(sarif_formatter, "_primary_sarif_issues", counting_primary_sarif_issues)

        run = _create_run(result, ["/test"], verbose=False)

        assert call_count == 1
        assert len(run["results"]) == 1
        assert run["results"][0]["message"]["text"] == "Primary dangerous call"

    def test_invocation_properties(self):
        """Test invocation includes scan properties."""
        result = create_initial_audit_result()
        result.bytes_scanned = 1000
        result.files_scanned = 5
        result.scanner_names = ["PickleScanner"]
        result.finalize_statistics()

        run = _create_run(result, ["/test"], verbose=False)

        props = run["invocations"][0]["properties"]
        assert props["filesScanned"] == 5
        assert props["bytesScanned"] == 1000
        assert props["scanners"] == ["PickleScanner"]
        assert props["processCompleted"] is True
        assert props["securityCoverageComplete"] is True
        assert props["incompleteCoverage"] is False
        assert props["operationalErrors"] is False

    def test_invocation_properties_treat_dry_run_as_successful_invocation(self) -> None:
        """Dry-run previews should be successful invocations even without scanned files."""
        result = create_initial_audit_result().model_copy(update={"dry_run": True})
        result.files_scanned = 0
        result.finalize_statistics()

        run = _create_run(result, ["/test"], verbose=False)

        invocation = run["invocations"][0]
        assert invocation["exitCode"] == 0
        assert invocation["executionSuccessful"] is True
        assert invocation["properties"]["processCompleted"] is True
        assert invocation["properties"]["securityCoverageComplete"] is True
        assert invocation["properties"]["incompleteCoverage"] is False

    def test_invocation_properties_mark_incomplete_coverage_without_findings(self) -> None:
        """Incomplete coverage without findings should be an unsuccessful SARIF invocation."""
        result = create_initial_audit_result()
        result.files_scanned = 1
        result.success = False
        result.file_metadata["model.bin"] = FileMetadataModel(
            analysis_incomplete=True,
            scan_outcome_reasons=["bounded_probe_exhausted"],
        )
        result.finalize_statistics()

        run = _create_run(result, ["/test"], verbose=False)

        invocation = run["invocations"][0]
        assert invocation["exitCode"] == 2
        assert invocation["exitCodeDescription"] == "Scan outcome was inconclusive"
        assert invocation["executionSuccessful"] is False
        assert invocation["properties"]["processCompleted"] is True
        assert invocation["properties"]["securityCoverageComplete"] is False
        assert invocation["properties"]["incompleteCoverage"] is True
        assert invocation["properties"]["operationalErrors"] is False

    def test_invocation_properties_mark_issue_only_incomplete_coverage_without_findings(self) -> None:
        """Issue-only coverage gaps should be unsuccessful SARIF invocations."""
        result = create_initial_audit_result()
        result.files_scanned = 1
        result.issues = [
            Issue(
                message="DVC output limit exceeded - not all declared outputs were scanned",
                severity=IssueSeverity.INFO,
                location="model.dvc",
                details={
                    "analysis_incomplete": True,
                    "scan_outcome": "inconclusive",
                    "reason": "dvc_output_limit_exceeded",
                },
                type="dvc_output_limit_exceeded",
                timestamp=time.time(),
            ),
        ]
        result.finalize_statistics()

        run = _create_run(result, ["/test"], verbose=False)

        invocation = run["invocations"][0]
        assert invocation["exitCode"] == 2
        assert invocation["exitCodeDescription"] == "Scan outcome was inconclusive"
        assert invocation["executionSuccessful"] is False
        assert invocation["properties"]["securityCoverageComplete"] is False
        assert invocation["properties"]["incompleteCoverage"] is True

    def test_invocation_properties_mark_check_only_incomplete_coverage_without_findings(self) -> None:
        """Check-only coverage gaps should be unsuccessful SARIF invocations."""
        result = create_initial_audit_result()
        result.files_scanned = 1
        result.checks = [
            Check(
                name="DVC Output Resolution",
                status=CheckStatus.FAILED,
                message="DVC output resolution incomplete",
                severity=IssueSeverity.INFO,
                location="model.dvc",
                details={"analysis_incomplete": True, "scan_outcome_reason": "dvc_analysis_incomplete"},
                timestamp=time.time(),
            ),
        ]
        result.finalize_statistics()

        run = _create_run(result, ["/test"], verbose=False)

        invocation = run["invocations"][0]
        assert invocation["exitCode"] == 2
        assert invocation["exitCodeDescription"] == "Scan outcome was inconclusive"
        assert invocation["executionSuccessful"] is False
        assert invocation["properties"]["securityCoverageComplete"] is False
        assert invocation["properties"]["incompleteCoverage"] is True

    def test_invocation_properties_mark_incomplete_coverage_with_security_findings(self) -> None:
        """Security exit 1 should not hide incomplete coverage in SARIF."""
        result = create_initial_audit_result()
        result.files_scanned = 1
        result.success = False
        result.file_metadata["model.pkl"] = FileMetadataModel(scan_outcome="inconclusive")
        result.issues = [
            Issue(
                message="Dangerous pickle global",
                severity=IssueSeverity.WARNING,
                location="/test/model.pkl",
                timestamp=time.time(),
            ),
        ]
        result.finalize_statistics()

        run = _create_run(result, ["/test"], verbose=False)

        invocation = run["invocations"][0]
        assert invocation["exitCode"] == 1
        assert invocation["exitCodeDescription"] == "Security issues detected; scan coverage incomplete"
        assert invocation["executionSuccessful"] is False
        assert invocation["properties"]["processCompleted"] is True
        assert invocation["properties"]["securityCoverageComplete"] is False
        assert invocation["properties"]["incompleteCoverage"] is True
        assert invocation["properties"]["operationalErrors"] is False
        assert run["results"][0]["message"]["text"] == "Dangerous pickle global"

    def test_invocation_properties_mark_issue_only_incomplete_coverage_with_security_findings(self) -> None:
        """Security findings should keep exit 1 while issue-only coverage remains visible."""
        result = create_initial_audit_result()
        result.files_scanned = 2
        result.issues = [
            Issue(
                message="DVC output resolution incomplete",
                severity=IssueSeverity.INFO,
                location="model.dvc",
                details={"analysis_incomplete": True, "scan_outcome_reason": "dvc_analysis_incomplete"},
                timestamp=time.time(),
            ),
            Issue(
                message="Dangerous pickle global",
                severity=IssueSeverity.WARNING,
                location="/test/payload.pkl",
                timestamp=time.time(),
            ),
        ]
        result.finalize_statistics()

        run = _create_run(result, ["/test"], verbose=False)

        invocation = run["invocations"][0]
        assert invocation["exitCode"] == 1
        assert invocation["exitCodeDescription"] == "Security issues detected; scan coverage incomplete"
        assert invocation["executionSuccessful"] is False
        assert invocation["properties"]["securityCoverageComplete"] is False
        assert invocation["properties"]["incompleteCoverage"] is True
        assert [item["message"]["text"] for item in run["results"]] == [
            "DVC output resolution incomplete",
            "Dangerous pickle global",
        ]


class TestCreateRules:
    """Tests for _create_rules function."""

    def test_rules_from_issues(self):
        """Test rule creation from issues."""
        issues = [
            Issue(message="Pickle issue", severity=IssueSeverity.CRITICAL, timestamp=time.time()),
            Issue(message="Import issue", severity=IssueSeverity.WARNING, timestamp=time.time()),
        ]

        rules = _create_rules(issues)

        assert len(rules) == 2
        for rule in rules:
            assert "id" in rule
            assert "name" in rule
            assert "shortDescription" in rule
            assert "defaultConfiguration" in rule

    def test_deduplicate_rules(self):
        """Test that duplicate rules are not created."""
        issues = [
            Issue(message="Same issue", severity=IssueSeverity.WARNING, timestamp=time.time()),
            Issue(message="Same issue", severity=IssueSeverity.WARNING, timestamp=time.time()),
        ]

        rules = _create_rules(issues)

        assert len(rules) == 1

    def test_rule_with_why(self):
        """Test rule includes help from why field."""
        issue = Issue(
            message="Test issue",
            severity=IssueSeverity.WARNING,
            timestamp=time.time(),
            why="This is dangerous because...",
        )

        rules = _create_rules([issue])

        assert len(rules) == 1
        assert "help" in rules[0]
        assert rules[0]["help"]["text"] == "This is dangerous because..."


class TestCreateResults:
    """Tests for _create_results function."""

    def test_results_from_issues(self):
        """Test result creation from issues."""
        issues = [
            Issue(
                message="Test issue",
                severity=IssueSeverity.WARNING,
                location="/test/file.pkl",
                timestamp=time.time(),
            ),
        ]

        results = _create_results(issues)

        assert len(results) == 1
        result = results[0]
        assert result["ruleId"].startswith("MA")
        assert result["level"] == "warning"
        assert result["message"]["text"] == "Test issue"

    def test_result_with_location(self):
        """Test result includes physical location."""
        issue = Issue(
            message="Test",
            severity=IssueSeverity.WARNING,
            location="/test/file.pkl",
            timestamp=time.time(),
        )

        results = _create_results([issue])

        assert len(results[0]["locations"]) == 1
        location = results[0]["locations"][0]
        assert "physicalLocation" in location

    def test_result_with_line_info(self):
        """Test result includes line/column from details."""
        issue = Issue(
            message="Test",
            severity=IssueSeverity.WARNING,
            location="/test/file.pkl",
            details={"line": 42, "column": 10},
            timestamp=time.time(),
        )

        results = _create_results([issue])

        location = results[0]["locations"][0]
        region = location["physicalLocation"]["region"]
        assert region["startLine"] == 42
        assert region["startColumn"] == 10

    def test_result_properties_prefer_issue_identity_fields(self) -> None:
        """Canonical issue identity fields should override stale details."""
        issue = Issue(
            message="Test",
            severity=IssueSeverity.WARNING,
            details={"rule_code": "STALE", "issue_type": "stale"},
            timestamp=time.time(),
            type="pickle_check",
            rule_code="S201",
        )

        results = _create_results([issue])

        assert results[0]["properties"]["rule_code"] == "S201"
        assert results[0]["properties"]["issue_type"] == "pickle_check"

    def test_result_properties_strip_legacy_identity_details(self) -> None:
        """Legacy identity details should not imply canonical SARIF rule codes."""
        issue = Issue(
            message="Test",
            severity=IssueSeverity.WARNING,
            details={"rule_code": "S201", "issue_type": "pickle_check", "context": "kept"},
            timestamp=time.time(),
        )

        results = _create_results([issue])

        assert "rule_code" not in results[0]["properties"]
        assert "issue_type" not in results[0]["properties"]
        assert results[0]["properties"]["context"] == "kept"

    def test_result_fingerprints(self):
        """Test result has fingerprints for deduplication."""
        issue = Issue(
            message="Test",
            severity=IssueSeverity.WARNING,
            timestamp=time.time(),
        )

        results = _create_results([issue])

        assert "partialFingerprints" in results[0]
        assert "primaryLocationLineHash" in results[0]["partialFingerprints"]

    def test_result_uses_evidence_fingerprint_when_present(self) -> None:
        issue = Issue(
            message="Duplicate documentation indicators",
            severity=IssueSeverity.WARNING,
            location="/models/a/model_card.md",
            details={"evidence_fingerprint": "text-doc-network:stable"},
            timestamp=time.time(),
        )

        results = _create_results([issue])
        fingerprint = results[0]["partialFingerprints"]["primaryLocationLineHash"]

        assert isinstance(fingerprint, str)
        assert len(fingerprint) == 16
        assert fingerprint == _create_results([issue])[0]["partialFingerprints"]["primaryLocationLineHash"]
        assert results[0]["properties"]["evidence_fingerprint"] == "text-doc-network:stable"

    def test_result_scopes_evidence_fingerprint_by_artifact_location(self) -> None:
        first_issue = Issue(
            message="Duplicate documentation indicators",
            severity=IssueSeverity.WARNING,
            location="/models/a/model_card.md",
            details={"evidence_fingerprint": "text-doc-network:stable"},
            timestamp=time.time(),
        )
        second_issue = Issue(
            message="Duplicate documentation indicators",
            severity=IssueSeverity.WARNING,
            location="/models/b/model_card.md",
            details={"evidence_fingerprint": "text-doc-network:stable"},
            timestamp=time.time(),
        )

        first_result, second_result = _create_results([first_issue, second_issue])

        assert (
            first_result["partialFingerprints"]["primaryLocationLineHash"]
            != second_result["partialFingerprints"]["primaryLocationLineHash"]
        )

    def test_result_preserves_model_card_evidence_fingerprint_and_region(self, tmp_path: Path) -> None:
        text_path = tmp_path / "model_card.md"
        text_path.write_text("git clone https://evil.example/repo.git\n", encoding="utf-8")

        result = scan_model_directory_or_file(str(text_path), cache_enabled=False)
        output = format_sarif_output(result, [str(text_path)])
        sarif_result = json.loads(output)["runs"][0]["results"][0]

        assert sarif_result["message"]["text"] == "Git clone network command detected: https://evil.example/repo.git"
        assert len(sarif_result["partialFingerprints"]["primaryLocationLineHash"]) == 16
        assert (
            sarif_result["partialFingerprints"]["primaryLocationLineHash"]
            != sarif_result["properties"]["evidence_fingerprint"]
        )
        assert sarif_result["properties"]["evidence_fingerprint"].startswith("text-doc-network:")
        assert sarif_result["properties"]["normalized_evidence"] == {
            "kind": "url",
            "value": "https://evil.example/repo.git",
        }
        assert sarif_result["locations"][0]["physicalLocation"]["region"] == {
            "startLine": 1,
            "startColumn": len("git clone ") + 1,
        }

    def test_result_kind_by_severity(self):
        """Test result kind based on severity."""
        critical = Issue(message="Critical", severity=IssueSeverity.CRITICAL, timestamp=time.time())
        info = Issue(message="Info", severity=IssueSeverity.INFO, timestamp=time.time())

        critical_results = _create_results([critical])
        info_results = _create_results([info])

        assert critical_results[0]["kind"] == "fail"
        assert info_results[0]["kind"] == "informational"

    def test_supporting_rule_code_issue_is_filtered(self) -> None:
        issues = [
            Issue(message="Primary", severity=IssueSeverity.CRITICAL, rule_code="S104", timestamp=time.time()),
            Issue(
                message="Supporting",
                severity=IssueSeverity.CRITICAL,
                details={"supporting_rule_code": True, "primary_rule_code": "S104"},
                rule_code="S201",
                timestamp=time.time(),
            ),
        ]

        results = _create_results(issues)

        assert [result["ruleId"] for result in results] == ["S104"]

    def test_pickle_rule_codes_are_preserved_as_sarif_rule_ids(self) -> None:
        pickle_rule_codes = ["S209", "S213", "S214", "S601", "S602", "S604", "S902"]
        issues = [
            Issue(
                message=f"Pickle rule {rule_code}",
                severity=IssueSeverity.WARNING,
                rule_code=rule_code,
                timestamp=time.time(),
            )
            for rule_code in pickle_rule_codes
        ]

        results = _create_results(issues)
        rules = _create_rules(issues)

        assert [result["ruleId"] for result in results] == pickle_rule_codes
        assert [rule["id"] for rule in rules] == pickle_rule_codes
        assert [result["properties"]["rule_code"] for result in results] == pickle_rule_codes


class TestCreateArtifacts:
    """Tests for _create_artifacts function."""

    def test_artifacts_from_assets(self):
        """Test artifact creation from assets."""
        result = create_initial_audit_result()
        result.assets = [
            AssetModel(path="/test/model.pkl", type="pickle", size=1024),
        ]

        artifacts = _create_artifacts(result)

        assert len(artifacts) == 1
        assert artifacts[0]["mimeType"] == "application/octet-stream"
        assert artifacts[0]["length"] == 1024

    def test_artifact_with_hashes(self):
        """Test artifact includes hashes from metadata."""
        result = create_initial_audit_result()
        result.assets = [AssetModel(path="/test/model.pkl", type="pickle")]
        result.file_metadata["/test/model.pkl"] = FileMetadataModel(
            file_hashes=FileHashesModel(sha256="a" * 64, md5="b" * 32)
        )

        artifacts = _create_artifacts(result)

        assert "hashes" in artifacts[0]
        assert "sha-256" in artifacts[0]["hashes"]
        assert "md5" in artifacts[0]["hashes"]

    def test_artifact_omits_partial_sha256_prefix_hash(self) -> None:
        """Partial prefix hashes must not be emitted as complete SARIF hashes."""
        result = create_initial_audit_result()
        result.assets = [AssetModel(path="/test/model.pt", type="pickle")]
        result.file_metadata["/test/model.pt"] = FileMetadataModel(file_hashes=FileHashesModel(sha256_prefix="c" * 64))

        artifacts = _create_artifacts(result)

        assert "hashes" not in artifacts[0]


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_get_rule_id_with_type(self):
        """Test rule ID generation with type."""

        class MockIssue:
            type = "malicious_code"
            message = "Test"

        rule_id = _get_rule_id(MockIssue())
        assert rule_id == "MAMALICIOUS_CODE"

    def test_get_rule_id_from_message(self):
        """Test rule ID generation from message."""
        issue = Issue(message="Dangerous pickle operation", severity=IssueSeverity.WARNING, timestamp=time.time())

        rule_id = _get_rule_id(issue)
        assert rule_id.startswith("MA-")

    def test_get_rule_name_with_type(self):
        """Test rule name with type."""

        class MockIssue:
            type = "code_execution"
            message = "Test"

        name = _get_rule_name(MockIssue())
        assert name == "Code Execution"

    def test_get_rule_name_from_message(self):
        """Test rule name from message."""
        issue = Issue(message="Something: details here", severity=IssueSeverity.WARNING, timestamp=time.time())

        name = _get_rule_name(issue)
        assert name == "Something"

    def test_get_rule_short_description_pickle(self):
        """Test short description for pickle issues."""
        issue = Issue(message="Unsafe pickle deserialization", severity=IssueSeverity.WARNING, timestamp=time.time())

        desc = _get_rule_short_description(issue)
        assert "pickle" in desc.lower()

    def test_get_rule_short_description_reuses_lowered_message(self):
        """Short-description matching should normalize the issue message once."""

        class CountingMessage(str):
            lower_calls = 0

            def lower(self) -> str:
                self.lower_calls += 1
                return super().lower()

        message = CountingMessage("Potential exposed secret")
        issue = SimpleNamespace(message=message)

        assert _get_rule_short_description(issue) == "Potential secrets or keys exposed"
        assert message.lower_calls == 1

    def test_get_rule_short_description_import(self):
        """Test short description for import issues."""
        issue = Issue(message="Dangerous import os.system", severity=IssueSeverity.WARNING, timestamp=time.time())

        desc = _get_rule_short_description(issue)
        assert "import" in desc.lower()

    def test_get_rule_short_description_exec(self):
        """Test short description for exec/eval issues."""
        issue = Issue(message="eval() call detected", severity=IssueSeverity.WARNING, timestamp=time.time())

        desc = _get_rule_short_description(issue)
        assert "execution" in desc.lower()

    def test_get_rule_short_description_network(self):
        """Test short description for network issues."""
        issue = Issue(message="Network communication detected", severity=IssueSeverity.WARNING, timestamp=time.time())

        desc = _get_rule_short_description(issue)
        assert "network" in desc.lower()

    def test_get_rule_short_description_secret(self):
        """Test short description for secret issues."""
        issue = Issue(message="API key exposed", severity=IssueSeverity.WARNING, timestamp=time.time())

        desc = _get_rule_short_description(issue)
        assert "secret" in desc.lower() or "key" in desc.lower()

    def test_get_rule_short_description_license(self):
        """Test short description for license issues."""
        issue = Issue(message="License violation detected", severity=IssueSeverity.WARNING, timestamp=time.time())

        desc = _get_rule_short_description(issue)
        assert "license" in desc.lower()

    def test_get_rule_short_description_blacklist(self):
        """Test short description for blacklist issues."""
        issue = Issue(message="Blacklisted model name", severity=IssueSeverity.WARNING, timestamp=time.time())

        desc = _get_rule_short_description(issue)
        assert "blacklist" in desc.lower()

    def test_get_rule_short_description_generic(self):
        """Test short description for generic issues."""
        issue = Issue(message="Some other security issue", severity=IssueSeverity.WARNING, timestamp=time.time())

        desc = _get_rule_short_description(issue)
        assert desc == "Some other security issue"

    def test_get_rule_full_description_with_why(self):
        """Test full description includes why."""
        issue = Issue(
            message="Test issue",
            severity=IssueSeverity.WARNING,
            timestamp=time.time(),
            why="Because it's dangerous",
        )

        desc = _get_rule_full_description(issue)
        assert "dangerous" in desc

    def test_severity_to_sarif_level(self):
        """Test severity to SARIF level mapping."""
        assert _severity_to_sarif_level(IssueSeverity.CRITICAL) == "error"
        assert _severity_to_sarif_level(IssueSeverity.WARNING) == "warning"
        assert _severity_to_sarif_level(IssueSeverity.INFO) == "note"
        assert _severity_to_sarif_level(IssueSeverity.DEBUG) == "none"

    def test_severity_to_rank(self):
        """Test severity to rank mapping."""
        assert _severity_to_rank(IssueSeverity.CRITICAL) == 90.0
        assert _severity_to_rank(IssueSeverity.WARNING) == 60.0
        assert _severity_to_rank(IssueSeverity.INFO) == 30.0
        assert _severity_to_rank(IssueSeverity.DEBUG) == 10.0

    def test_get_tags_for_issue_pickle(self):
        """Test tags include pickle-related tags."""
        issue = Issue(message="Pickle deserialization issue", severity=IssueSeverity.WARNING, timestamp=time.time())

        tags = _get_tags_for_issue(issue)

        assert "security" in tags
        assert "ml-model" in tags
        assert "pickle" in tags
        assert "deserialization" in tags

    def test_get_tags_for_issue_code_execution(self) -> None:
        """Test tags for code execution issues."""
        issue = Issue(message="eval() call detected", severity=IssueSeverity.WARNING, timestamp=time.time())

        tags = _get_tags_for_issue(issue)
        assert "code-execution" in tags

    def test_get_tags_for_issue_network(self):
        """Test tags for network issues."""
        issue = Issue(message="Network URL detected", severity=IssueSeverity.WARNING, timestamp=time.time())

        tags = _get_tags_for_issue(issue)
        assert "network" in tags

    def test_get_tags_for_issue_secrets(self):
        """Test tags for secrets issues."""
        issue = Issue(message="API key exposed", severity=IssueSeverity.WARNING, timestamp=time.time())

        tags = _get_tags_for_issue(issue)
        assert "secrets" in tags

    def test_get_tags_for_issue_license(self):
        """Test tags for license issues."""
        issue = Issue(message="License compliance issue", severity=IssueSeverity.WARNING, timestamp=time.time())

        tags = _get_tags_for_issue(issue)
        assert "license" in tags

    def test_get_tags_for_issue_cve(self):
        """Test tags for CVE issues."""
        issue = Issue(message="CVE-2024-12345 vulnerability", severity=IssueSeverity.WARNING, timestamp=time.time())

        tags = _get_tags_for_issue(issue)
        assert "vulnerability" in tags

    def test_normalize_path_to_uri(self):
        """Test path normalization to URI."""
        result = _normalize_path_to_uri("/some/path/file.pkl")
        # Should return a valid URI path
        assert "/" in result

    def test_normalize_path_with_spaces(self):
        """Test path normalization with spaces."""
        result = _normalize_path_to_uri("/path with spaces/file.pkl")
        assert "%20" in result

    def test_get_mime_type(self):
        """Test MIME type mapping."""
        assert _get_mime_type("pickle") == "application/octet-stream"
        assert _get_mime_type("pytorch") == "application/octet-stream"
        assert _get_mime_type("tensorflow") == "application/x-tensorflow"
        assert _get_mime_type("onnx") == "application/x-onnx"
        assert _get_mime_type("keras") == "application/x-keras"
        assert _get_mime_type("safetensors") == "application/x-safetensors"
        assert _get_mime_type("json") == "application/json"
        assert _get_mime_type("unknown") == "application/octet-stream"

    def test_get_mime_type_case_insensitive(self):
        """Test MIME type is case insensitive."""
        assert _get_mime_type("PICKLE") == "application/octet-stream"
        assert _get_mime_type("PyTorch") == "application/octet-stream"


def test_report_value_serialization_preserves_shapes_and_bounds() -> None:
    from pydantic import AnyUrl, BaseModel

    from modelaudit.integrations.source_serialization import serialize_source_identifier, serialize_source_value

    class Details(BaseModel):
        url: AnyUrl

    value = {
        "tuple": (b"plain", bytearray(b"bytes")),
        "set": {"z", "a"},
        "frozen": frozenset({2, 1}),
        "model": Details(url=AnyUrl("https://user:secret@example.com/?token=raw")),
        "binary": b"\xff",
        "raw": "password=raw",
    }
    assert serialize_source_value(value) == {
        "tuple": ("plain", "bytes"),
        "set": ["a", "z"],
        "frozen": [1, 2],
        "model": {"url": "https://user:secret@example.com/?token=raw"},
        "binary": "<binary data>",
        "raw": "password=raw",
    }
    recursive: dict[str, object] = {}
    recursive["self"] = recursive
    assert serialize_source_value(recursive) == {"self": "<redacted recursive value>"}
    nested: object = "leaf"
    for _ in range(33):
        nested = [nested]
    converted = serialize_source_value(nested)
    for _ in range(33):
        converted = converted[0]
    assert converted == "<redacted>"
    assert serialize_source_value("x" * (256 * 1024)) == "x" * (256 * 1024)
    assert serialize_source_value("x" * (256 * 1024 + 1)) == "<redacted oversized value>"
    assert serialize_source_identifier("x" * (256 * 1024 + 1)) == "<source redacted>"
    assert serialize_source_value({(1, 2): "tuple", "(1, 2)": "text"}) == {
        "(1, 2)": "tuple",
        "(1, 2)#modelaudit-redacted-key-2": "text",
    }


@pytest.mark.parametrize("evidence", ["", "stable-evidence"])
@pytest.mark.parametrize(
    "source,normalized",
    [
        ("https://user:{secret}@bucket.example/model.pkl?token={secret}", "https://bucket.example/model.pkl"),
        ("//user:{secret}@bucket.example/model.pkl?token={secret}", "//bucket.example/model.pkl"),
        (
            "stream://https://user:{secret}@bucket.example/model.pkl?token={secret}",
            "stream://https://bucket.example/model.pkl",
        ),
    ],
)
def test_sarif_credential_rotation_preserves_baseline_identity(source: str, normalized: str, evidence: str) -> None:
    for secret in ["first-password", "rotated-password"]:
        raw = source.format(secret=secret)
        issue = Issue(
            message=f"Unsafe model from {raw}",
            severity=IssueSeverity.WARNING,
            location=raw,
            details={"evidence_fingerprint": evidence},
            timestamp=1,
        )
        result = _create_results([issue])[0]
        preimage = (
            "\x1f".join((evidence, normalized, str(issue.severity)))
            if evidence
            else f"Unsafe model from {normalized}{normalized}{issue.severity}"
        )
        assert (
            result["partialFingerprints"]["primaryLocationLineHash"]
            == hashlib.sha256(preimage.encode()).hexdigest()[:16]
        )


def test_sarif_rotating_assignments_preserve_derived_rule_grouping() -> None:
    issues = [
        Issue(
            message=f"password={secret} unsafe model", severity=IssueSeverity.WARNING, location="model.pkl", timestamp=1
        )
        for secret in ["first-token", "rotated-token"]
    ]
    assert [rule["id"] for rule in _create_rules(issues)] == ["MA-PASSWORDREDACTED"]
    assert [_get_rule_name(issue) for issue in issues] == ["password=<redacted>"] * 2
    assert [r["partialFingerprints"]["primaryLocationLineHash"] for r in _create_results(issues)] == [
        "dd9a19a60e1407fa"
    ] * 2


def test_sarif_existing_local_assignment_paths_keep_distinct_identity(tmp_path: Path) -> None:
    fingerprints = []
    for name in ["session=training", "session=evaluation"]:
        path = tmp_path / name / "model.pkl"
        path.parent.mkdir()
        path.write_bytes(b"model")
        issue = Issue(message="Unsafe local model", severity=IssueSeverity.WARNING, location=str(path), timestamp=1)
        fingerprints.append(_create_results([issue])[0]["partialFingerprints"]["primaryLocationLineHash"])
    assert fingerprints[0] != fingerprints[1]


@pytest.mark.parametrize(
    "source,normalized_message,normalized_location",
    [
        ("https://host/model.pkl?version=1", "Unsafe model from https://host/model.pkl", "https://host/model.pkl"),
        (
            "https://host/model.pkl?token=first-secret",
            "Unsafe model from https://host/model.pkl",
            "https://host/model.pkl",
        ),
        (
            "https://host/token%253Dpath-secret/model.pkl?visible=yes",
            "Unsafe model from https://host/token=<redacted>/model.pkl?visible=yes",
            "https://host/token=<redacted>/model.pkl",
        ),
        (
            "//user:first-password@bucket.example/model.pkl?token=secret",
            "Unsafe model from //bucket.example/model.pkl",
            "//bucket.example/model.pkl",
        ),
        (
            "https:/user:first-password@bucket.example/model.pkl?token=secret",
            "Unsafe model from https://bucket.example/model.pkl",
            "https://bucket.example/model.pkl",
        ),
        (
            "bucket.example/model.pkl?OPAQUE-SECRET",
            "Unsafe model from bucket.example/model.pkl",
            "bucket.example/model.pkl",
        ),
        (
            "bucket.example/model.pkl%3FOPAQUE-SECRET",
            "Unsafe model from bucket.example/model.pkl",
            "bucket.example/model.pkl",
        ),
        ("file:///tmp/model%3Fv1.pkl", "Unsafe model from file:///tmp/model%3Fv1.pkl", "file:///tmp/model%3Fv1.pkl"),
        ("file://host/tmp/model.pkl", "Unsafe model from file://host/tmp/model.pkl", "file://host/tmp/model.pkl"),
        (
            "./artifacts/user@example.com/model.pkl?version=1",
            "Unsafe model from ./artifacts/user@example.com/model.pkl?version=1",
            "./artifacts/user@example.com/model.pkl?version=1",
        ),
        ("Authorization Bearer first-secret", "Unsafe model from Authorization Bearer <redacted>", "<source redacted>"),
        ("Unsafe token_count=128", "Unsafe model from Unsafe token_count=128", "Unsafe token_count=128"),
    ],
)
@pytest.mark.parametrize("evidence", ["", "stable-evidence"])
def test_sarif_historical_normalization_preserves_fingerprint(
    source: str,
    normalized_message: str,
    normalized_location: str,
    evidence: str,
) -> None:
    # These expectations were captured from the parent implementation, including
    # encoded, malformed, schemeless, and local-looking source identifiers.
    issue = Issue(
        message=f"Unsafe model from {source}",
        severity=IssueSeverity.WARNING,
        location=source,
        details={"evidence_fingerprint": evidence},
        timestamp=1,
    )
    result = _create_results([issue])[0]
    preimage = (
        "\x1f".join((evidence, normalized_location, str(issue.severity)))
        if evidence
        else f"{normalized_message}{normalized_location}{issue.severity}"
    )
    assert (
        result["partialFingerprints"]["primaryLocationLineHash"] == hashlib.sha256(preimage.encode()).hexdigest()[:16]
    )


@pytest.mark.parametrize(
    "local_path",
    [
        r"C:\users\user:password@folder\model.pkl",
        r"\\server\share\user:password@folder\model.pkl",
    ],
)
def test_windows_and_unc_local_paths_are_preserved(local_path: str) -> None:
    assert redact_source_identifier(local_path) == local_path


@pytest.mark.parametrize(
    "local_path",
    [
        r"C:\models\sessionTokenCache=public\model.pkl",
        r"\\host\share\password_policy=public\model.pkl",
    ],
)
def test_nonexistent_windows_and_unc_near_matches_are_preserved(local_path: str) -> None:
    assert redact_source_identifier(local_path) == local_path


def test_existing_windows_assignment_filename_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    local_path = r"C:\models\token=literal-filename\model.pkl"
    monkeypatch.setattr(
        "modelaudit.integrations._sarif_identity._local_path_exists",
        lambda source: source == local_path,
    )

    assert redact_source_identifier(local_path) == local_path


@pytest.mark.parametrize(
    ("local_path", "safe_path"),
    [
        (r"C:\models\model.pkl?token=windows-secret", r"C:\models\model.pkl"),
        (r"\\server\share\model.pkl?token=unc-secret", r"\\server\share\model.pkl"),
    ],
)
def test_nonexistent_windows_and_unc_credential_suffixes_are_redacted(local_path: str, safe_path: str) -> None:
    assert redact_source_identifier(local_path) == safe_path


@pytest.mark.parametrize(
    "local_path",
    [
        "./api-key@bucket.example/model.pkl?token=secret",
        r"C:\models\user:password@bucket.example\model.pkl?token=secret",
    ],
)
def test_nonexistent_local_userinfo_with_credential_suffix_fails_closed(local_path: str) -> None:
    assert redact_source_identifier(local_path) == "<source redacted>"
    redacted_text = redact_source_text(local_path)
    assert "<source redacted>" in redacted_text
    assert "api-key" not in redacted_text
    assert "password" not in redacted_text
    assert "secret" not in redacted_text


@pytest.mark.parametrize(
    "source",
    [
        "file:///tmp/model%3Fv1.pkl",
        "file:///tmp/model.pkl%3Fversion%3D1",
        "user@example.com",
    ],
)
def test_encoded_file_names_and_email_near_matches_are_preserved(source: str) -> None:
    assert redact_source_identifier(source) == source


@pytest.mark.parametrize(
    "source",
    [
        "file://host/tmp/model.pkl",
        "model.pkl;version=v1",
        "bucket/model.pkl;version=v1",
    ],
)
def test_authority_and_semicolon_near_matches_are_preserved(source: str) -> None:
    assert redact_source_identifier(source) == source
    assert redact_source_text(f"source {source}") == f"source {source}"


def test_percent_encoded_at_in_file_path_is_not_treated_as_authority() -> None:
    source = "file:///tmp/api-key%40host/model.pkl"

    assert redact_source_identifier(source) == source


@pytest.mark.parametrize(
    "raw_path",
    [
        "token=scheme-less-secret?revision=v1",
        "sessionToken=scheme-less-secret?revision=v1",
        "session%54oken=scheme-less-secret?revision=v1",
        "bucket/token=path-secret/model.pkl?revision=v1",
        "bucket/token%3Dpath-secret/model.pkl?revision=v1",
        "Authorization: Bearer source-secret?revision=v1",
        "dbPassword: source-secret#tag=v1",
    ],
)
def test_safe_provenance_does_not_restore_sensitive_prefixes(raw_path: str) -> None:
    assert redact_source_identifier(raw_path) == "<source redacted>"


@pytest.mark.parametrize(
    "text",
    [
        'payload={"token":"EXPORT-SECRET-123"}',
        "token[]=EXPORT-SECRET-123",
        "headers[token]=EXPORT-SECRET-123",
        'headers["token"]=EXPORT-SECRET-123',
        'headers[ "token" ]=EXPORT-SECRET-123',
        "headers[ token]=EXPORT-SECRET-123",
        "headers[token ]=EXPORT-SECRET-123",
        r'payload={"\u0074oken":"EXPORT-SECRET-123"}',
        r'payload={"to\u006ben":"EXPORT-SECRET-123"}',
        '"token"=EXPORT-SECRET-123',
        r"payload={\"token\":\"EXPORT-SECRET-123\"}",
        "Authorization Bearer EXPORT-SECRET-123",
        "Authorization Digest EXPORT-SECRET-123",
        "Authorization ApiKey EXPORT-SECRET-123",
        "Authorization DPoP EXPORT-SECRET-123",
        "Authorization Hawk EXPORT-SECRET-123",
        "Proxy-Authorization NTLM EXPORT-SECRET-123",
        "Proxy-Authorization ApiKey EXPORT-SECRET-123",
        "--token EXPORT-SECRET-123 --verbose",
        "token <- EXPORT-SECRET-123; visible=yes",
    ],
)
def test_serialized_and_argument_credentials_are_redacted(text: str) -> None:
    redacted = redact_source_text(text)

    assert "EXPORT-SECRET-123" not in redacted


def test_redact_source_text_handles_dense_credential_assignments() -> None:
    text = "token=EXPORT-SECRET-123;" * 5_000

    redacted = redact_source_text(text)

    assert "EXPORT-SECRET-123" not in redacted
    assert redacted.count("<redacted>") == 5_000


@pytest.mark.parametrize("operator", ["!=", ">=", "<="])
def test_sensitive_key_ordering_comparisons_are_not_treated_as_assignments(operator: str) -> None:
    text = f'config={{"client_secret" {operator} "public": "os.system(15)"}}'

    assert redact_source_text(text) == text


def test_sensitive_key_equality_comparisons_redact_value_and_preserve_context() -> None:
    text = 'config={"client_secret" == "public": "os.system(15)"}'

    redacted = redact_source_text(text)

    assert redacted == 'config={"client_secret" == <redacted>: "os.system(15)"}'


def test_benign_comparisons_are_preserved_in_generic_exports() -> None:
    text = "status == 200 and count == 5"

    assert redact_source_text(text) == text


def test_comparison_marker_tail_is_redacted_in_generic_exports() -> None:
    text = 'client_secret == <redacted> + "RAW-MARKER-TAIL-SECRET-123456"'

    redacted = redact_source_text(text)

    assert "RAW-MARKER-TAIL-SECRET-123456" not in redacted
    assert redacted == "client_secret == <redacted>"


def test_exactly_redacted_comparison_value_is_preserved() -> None:
    text = "client_secret == <redacted>"

    assert redact_source_text(text) == text


def test_reversed_literal_key_comparison_redacts_value_in_generic_exports() -> None:
    text = '"OPAQUE-VALUE-CRED-123456" == "client_secret"; os.system("id")'

    redacted = redact_source_text(text)

    assert "OPAQUE-VALUE-CRED-123456" not in redacted
    assert '<redacted> == "client_secret"' in redacted
    assert 'os.system("id")' in redacted


@pytest.mark.parametrize(
    "text",
    [
        'label == "client_secret"; os.system("id")',
        '"OPAQUE-VALUE" == "tokenizer"',
    ],
)
def test_reversed_comparison_near_matches_are_preserved_in_generic_exports(text: str) -> None:
    assert redact_source_text(text) == text


@pytest.mark.parametrize(
    "text",
    [
        "https://host/model,Authorization: Bearer URL-ADJACENT-SECRET",
        "https://host/model;password: URL-ADJACENT-SECRET",
        "metadata token%3DENCODED-SECRET visible=yes",
        "metadata token%253DDOUBLE-ENCODED-SECRET",
        "Authorization%3A%20Bearer%20ENCODED-HEADER-SECRET",
        r"password\u003aESCAPED-SECRET",
        '{"token":"QUOTED-SECRET"}',
        '{"Authorization":"Bearer QUOTED-HEADER-SECRET"}',
        "token%3DCHAINED-SECRET%26visible%3Dyes",
        "token%253DDOUBLE-CHAINED-SECRET%2526visible%253Dyes",
        "Authorization%3A%20Bearer%20HEADER-SECRET%3Btoken%3DSECOND-SECRET",
    ],
)
def test_encoded_quoted_and_url_adjacent_assignments_are_redacted(text: str) -> None:
    redacted = redact_source_text(text)

    assert "SECRET" not in redacted
    assert "<redacted>" in redacted


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('--token "EXPORT SECRET 123" --verbose', "--token <redacted> --verbose"),
        ('Authorization Bearer "EXPORT SECRET 123" tail', "Authorization Bearer <redacted> tail"),
        ("payload=[token=EXPORT-SECRET-123] tail", "payload=[token=<redacted>] tail"),
        ("--token=EXPORT-SECRET-123 --verbose", "--token=<redacted> --verbose"),
        ("token: |\n  EXPORT-SECRET-123\nnext=safe", "token: <redacted>\nnext=safe"),
        ("token: >\n  EXPORT SECRET 123\nnext=safe", "token: <redacted>\nnext=safe"),
    ],
)
def test_credential_redaction_preserves_surrounding_context(text: str, expected: str) -> None:
    assert redact_source_text(text) == expected


def test_oversized_export_text_fails_closed() -> None:
    assert redact_source_text("a" * (256 * 1024 + 1)) == "<redacted oversized value>"


@pytest.mark.parametrize(
    "text",
    [
        "request_signature_algorithm=rsa",
        "authorization_method=oauth2",
        "Authorization method oauth2",
        "Authorization status disabled",
        "password_policy=strong",
        "my_secret_ingredient=salt",
        "token_count=42",
        "token_type_ids=[1, 2]",
        "signature_algorithm=rsa",
    ],
)
def test_export_credential_near_matches_are_preserved(text: str) -> None:
    assert redact_source_text(text) == text


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("bucket/user:EXPORT-SECRET-123@host/model.pkl", "bucket/host/model.pkl"),
        ("bucket/user%3AEXPORT-SECRET-123%40host/model.pkl", "bucket/host/model.pkl"),
        ("bucket/user%253AEXPORT-SECRET-123%2540host/model.pkl", "bucket/host/model.pkl"),
        ("///user:EXPORT-SECRET-123@host/model.pkl", "<source redacted>"),
        ("stream://jdbc:postgresql://user:EXPORT-SECRET-123@host/db", "stream://jdbc:postgresql://host/db"),
    ],
)
def test_nested_userinfo_is_redacted_from_direct_identifiers(source: str, expected: str) -> None:
    assert redact_source_identifier(source) == expected


@pytest.mark.parametrize(
    "text",
    [
        "token_count=128",
        "signature_algorithm=RSA",
        "auth_method=oauth",
        "session_duration=10",
        "password_length=12",
        "version%3D1",
        "tokenizer%3Dpublic",
    ],
)
def test_benign_metric_and_encoded_near_matches_are_preserved(text: str) -> None:
    assert redact_source_text(text) == text


def test_escaped_quote_does_not_end_credential_redaction_early() -> None:
    redacted = redact_source_text('refreshToken="abc\\"quoted-secret"; visible=yes')

    assert "quoted-secret" not in redacted
    assert "visible=yes" in redacted


def test_redacted_url_path_assignment_preserves_safe_path_and_query() -> None:
    raw_url = "https://example.com/token%253Dpath-secret/model.pkl?visible=yes"

    assert redact_source_text(raw_url) == "https://example.com/token=<redacted>/model.pkl?visible=yes"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "https://example.com/token:URL-SECRET/model.pkl",
            "https://example.com/token=<redacted>/model.pkl",
        ),
        (
            "https://example.com/sessionToken%253AURL-SECRET/model.pkl",
            "https://example.com/sessionToken=<redacted>/model.pkl",
        ),
        ("bucket/token:PATH-SECRET/model.pkl", "<source redacted>"),
        ("/tmp/token:PATH-SECRET/model.pkl", "<source redacted>"),
        (r"C:\models\token:PATH-SECRET\model.pkl", "<source redacted>"),
    ],
)
def test_colon_path_credentials_are_redacted(source: str, expected: str) -> None:
    assert redact_source_identifier(source) == expected


@pytest.mark.parametrize(
    "source",
    [
        "https://example.com/version:1/model.pkl",
        "bucket/version:1/model.pkl",
        "/tmp/version:1/model.pkl",
        r"C:\models\version:1\model.pkl",
    ],
)
def test_benign_colon_path_segments_are_preserved(source: str) -> None:
    assert redact_source_identifier(source) == source


def test_nonexistent_local_suffix_is_redacted_but_literal_filename_is_preserved(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.pkl?token=source-secret"

    assert redact_source_identifier(str(missing_path)) == str(tmp_path / "missing.pkl")
    if os.name != "nt":
        literal_path = tmp_path / "literal.pkl?token=filename-text"
        literal_path.write_bytes(b"model")
        assert redact_source_identifier(str(literal_path)) == str(literal_path)
    assert redact_source_identifier("./missing.pkl%3Ftoken%3Dsource-secret") == "./missing.pkl"


@pytest.mark.parametrize(
    "raw_path",
    [
        "./user:password@bucket.example/model.pkl",
        "./bucket/token=path-secret/model.pkl?revision=v1",
        "./bucket/token%3Dpath-secret/model.pkl?revision=v1",
    ],
)
def test_nonexistent_posix_local_credential_prefixes_fail_closed(raw_path: str) -> None:
    assert redact_source_identifier(raw_path) == "<source redacted>"


@pytest.mark.parametrize(
    "local_path",
    [
        "/tmp/build@2026/model.pkl",
        "./artifacts/user@example.com/model.pkl",
        "./artifacts/user@example.com/model.pkl?version=1",
    ],
)
def test_nonexistent_posix_at_paths_are_preserved(local_path: str) -> None:
    assert redact_source_identifier(local_path) == local_path
    assert redact_source_text(f"source {local_path}") == f"source {local_path}"


@pytest.mark.parametrize(
    ("raw_path", "safe_path"),
    [
        ("/bucket/model.pkl;token=source-secret", "/bucket/model.pkl"),
        ("./bucket/model.pkl%3Btoken%3Dsource-secret", "./bucket/model.pkl"),
    ],
)
def test_nonexistent_local_semicolon_credentials_are_redacted(raw_path: str, safe_path: str) -> None:
    assert redact_source_identifier(raw_path) == safe_path


def test_existing_local_credential_shaped_filename_is_preserved(tmp_path: Path) -> None:
    literal_path = tmp_path / "model.pkl;token=filename-text"
    literal_path.write_bytes(b"model")

    assert redact_source_identifier(str(literal_path)) == str(literal_path)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("model.pkl?OPAQUE-SECRET", "model.pkl"),
        ("model.pkl%3FOPAQUE-SECRET", "model.pkl"),
        ("model.pkl;OPAQUE-SECRET", "model.pkl"),
        ("bucket/model.pkl;OPAQUE-SECRET", "bucket/model.pkl"),
        (r"bucket/model.pkl\u003btoken\u003descaped-secret", "bucket/model.pkl"),
        ("source //bucket.example/model.pkl?OPAQUE-SECRET", "source //bucket.example/model.pkl"),
        ("model.pkl?version=1", "model.pkl?version=1"),
        ("model.pkl%3Fversion%3D1", "model.pkl%3Fversion%3D1"),
        ("./bucket/model.pkl;version=1", "./bucket/model.pkl;version=1"),
        ("release 1.2.3? maybe", "release 1.2.3? maybe"),
        ("email user@example.com?subject=safe", "email user@example.com?subject=safe"),
        ("email user@example.com?token=secret", "email user@example.com"),
    ],
)
def test_bare_and_protocol_relative_opaque_source_text_redaction(text: str, expected: str) -> None:
    assert redact_source_text(text) == expected


@pytest.mark.parametrize(
    "source, expected",
    [
        (
            "https://huggingface.co/synthetic/model?revision=v1&token=first-secret",
            ("4acb9afec8e4ca09", "c88940f6ed1f1e27"),
        ),
        (
            "https://huggingface.co/synthetic/model?revision=v2&token=rotated-secret",
            ("c41158d2c9a49cc2", "e1aaaf3843a01e19"),
        ),
        (
            "https://user:password@hf.co/synthetic/model?revision=refs%2Fpr%2F1#fragment",
            ("df9f6c632af59190", "c8f6914b602735fb"),
        ),
        ("hf://synthetic/model?revision=v1&token=first-secret", ("cb66d14a78b3ffa6", "296551dd1511bcb4")),
        pytest.param(
            "https://huggingface.co/synthetic/model?revision=v%3F1",
            ("da65abb18e99561b", "f8bd949293f4aad7"),
            marks=pytest.mark.skipif(os.name == "nt", reason="Windows revision paths cannot contain a question mark"),
        ),
        (
            "https://huggingface.co/synthetic/model/resolve/refs%2Fpr%2F1/model.pkl?token=first-secret",
            ("cbd09adff61aa463", "669223b82696b1ec"),
        ),
        ("https://huggingface.co/synthetic/model?token=first-secret", ("02bbb8268098d7b7", "09a5413822fb3085")),
    ],
)
@pytest.mark.parametrize("scanned_artifact_count", [0, 2])
def test_huggingface_acquisition_fingerprints_match_baseline(
    source: str, expected: tuple[str, str], scanned_artifact_count: int
) -> None:
    from modelaudit.cli import _record_huggingface_acquisition_error, _ScanPathState
    from modelaudit.models import ModelAuditResultModel, create_initial_audit_result

    # Captured from the parent before raw output changes, including punctuation.
    result = create_initial_audit_result()
    _record_huggingface_acquisition_error(
        result, _ScanPathState(), path=source, error_msg="HTTP 503", scanned_artifact_count=scanned_artifact_count
    )
    for converted in [result, ModelAuditResultModel.model_validate_json(result.model_dump_json())]:
        sarif_result = _create_results(converted.issues)[0]
        assert sarif_result["partialFingerprints"]["primaryLocationLineHash"] == expected[scanned_artifact_count // 2]
        assert sarif_result["message"]["text"] == converted.issues[0].message
        assert sarif_result["properties"]["source_url"] == converted.issues[0].location


@pytest.mark.parametrize("query", ["?token=synthetic", "?token=synthetic (pos 2)", "%253Ftoken%253Dsynthetic"])
@pytest.mark.parametrize(
    "suffix, mode, evidence, rule, fingerprint",
    [
        (" (pos 2)", "default", False, "MAUNSAFE_PICKLE", "fa5b7bc43ae2af24"),
        (" (pos 17)", "default", False, "MAUNSAFE_PICKLE", "d75b755d8cd36d92"),
        (":archive/data.pkl (pos 2)", "default", False, "MAUNSAFE_PICKLE", "19aa36e2e9eddac1"),
        ("#member (pos 2)", "default", True, "MAUNSAFE_PICKLE", "433b3f275ec02f61"),
        ("[member]:4", "type", False, "MAHTTPS://BUCKET.S3.AMAZONAWS.COM/MODEL.PKL[MEMBER]:4", "de3055da08d1ede8"),
        (" (pos 2)", "rule_code", False, "https://bucket.s3.amazonaws.com/model.pkl (pos 2)", "fa5b7bc43ae2af24"),
    ],
)
def test_stream_fingerprints_preserve_baseline_suffixes(
    monkeypatch: pytest.MonkeyPatch, query: str, suffix: str, mode: str, evidence: bool, rule: str, fingerprint: str
) -> None:
    # Frozen outputs from the parent, where core normalized the source before appending scanner positions.
    source = "https://bucket.s3.amazonaws.com/model.pkl" + query
    scanned = ScanResult(scanner_name="streaming")
    scanned.metadata["streaming_analysis"] = True
    issue = Issue(
        message=f"Unsafe pickle from {source}{suffix}; another URL https://user:password@other/model.pkl?token=second.",
        severity=IssueSeverity.WARNING,
        location=source + suffix,
        details={"evidence_fingerprint": "evidence at " + source + suffix if evidence else "", "custom": "retained"},
        type=source + suffix if mode == "type" else "unsafe_pickle",
        rule_code=source + suffix if mode == "rule_code" else None,
    )
    scanned.issues.append(issue)
    scanned.finish(success=False)
    monkeypatch.setattr("modelaudit.core.stream_analyze_file", lambda *args, **kwargs: (scanned, True))
    monkeypatch.setattr("modelaudit.scanners.get_scanner_for_file", lambda *args, **kwargs: object())
    result = scan_model_directory_or_file("stream://" + source)
    before = result.model_dump_json()
    for converted in [result, ModelAuditResultModel.model_validate_json(before)]:
        run = _create_run(converted, [], False)
        finding = run["results"][0]
        assert finding["ruleId"] == run["tool"]["driver"]["rules"][0]["id"] == rule
        assert finding["partialFingerprints"]["primaryLocationLineHash"] == fingerprint
        assert finding["message"]["text"] == issue.message
        assert converted.issues[0].location == source + suffix
        assert converted.issues[0].details == issue.details
        assert getattr(converted.issues[0], "finding_identity", {})["producer"] == "stream"
        assert finding["properties"]["custom"] == "retained"
    assert result.model_dump_json() == before


def test_overlapping_signed_stream_sources_preserve_baseline_identities(monkeypatch: pytest.MonkeyPatch) -> None:
    # Exercise the real stream scanner; signed query text can itself look like a scanner position.
    payload = b"\x80\x04N.\x7fELFsynthetic"
    merged = create_initial_audit_result()
    for source in [
        "https://bucket.s3.amazonaws.com/model.pkl?token=synthetic",
        "https://bucket.s3.amazonaws.com/model.pkl?token=synthetic (pos 4)",
    ]:
        filesystem = Mock()
        filesystem.info.return_value = {"size": len(payload)}
        filesystem.open.side_effect = lambda *args: io.BytesIO(payload)
        transport = Mock(return_value=filesystem)
        monkeypatch.setattr("fsspec.filesystem", transport)
        result = scan_model_directory_or_file("stream://" + source)
        transport.assert_called_once_with("https")
        filesystem.info.assert_called_once_with(source)
        filesystem.open.assert_called_once_with(source, "rb")
        assert all(getattr(issue, "finding_identity", {})["producer"] == "stream" for issue in result.issues)
        assert result.issues[0].location == source + " (pos 4)"
        merged.issues.extend(result.issues)
        merged.assets.extend(result.assets)
        merged.file_metadata.update(result.file_metadata)
    expected = [
        ("S902", "4a206c4a5abbf137"),
        ("S901", "44b7255a71502074"),
        ("MA-STREAMING-ANALYSIS-INCOMPLETE-", "81fb33e77d7f4ab9"),
    ] * 2
    for converted in [merged, ModelAuditResultModel.model_validate_json(merged.model_dump_json())]:
        findings = _create_run(converted, [], False)["results"]
        assert [
            (item["ruleId"], item["partialFingerprints"]["primaryLocationLineHash"]) for item in findings
        ] == expected


def test_stream_failure_fingerprint_survives_saved_results(monkeypatch: pytest.MonkeyPatch) -> None:
    source = "https://user:password@bucket.s3.amazonaws.com/model.pkl?token=synthetic (pos 2)"
    monkeypatch.setattr("modelaudit.core.stream_analyze_file", lambda *args, **kwargs: (None, False))
    monkeypatch.setattr("modelaudit.scanners.get_scanner_for_file", lambda *args, **kwargs: object())
    result = scan_model_directory_or_file("stream://" + source)
    for converted in [result, ModelAuditResultModel.model_validate_json(result.model_dump_json())]:
        finding = _create_run(converted, [], False)["results"][0]
        assert finding["partialFingerprints"]["primaryLocationLineHash"] == "5386d5566b6f8146"
        assert source in finding["message"]["text"]
        assert getattr(converted.issues[0], "finding_identity", {})["producer"] == "stream"


def test_stream_identity_context_excludes_local_and_huggingface_downloads() -> None:
    source = "https://bucket/model.pkl?token=synthetic"
    result = create_initial_audit_result()
    result.issues = [
        Issue(message=f"Local pickle references {source} (pos 2)", location="local.pkl (pos 2)", type="pickle_ref")
    ]
    expected = _create_run(result, [], False)["results"]
    result.file_metadata[source] = FileMetadataModel(streaming_analysis=True)
    assert _create_run(result, [], False)["results"] == expected
    result.file_metadata.clear()
    result.issues[0].location = source + " (pos 2)"
    expected = _create_run(result, [], False)["results"]
    result.assets = [AssetModel(path=source, type="pickle", is_streamed=True)]
    assert _create_run(result, [], False)["results"] == expected


@pytest.mark.parametrize(
    "mode, hashes",
    [
        ("budget", ("cd69d800710289bc", "cc721fc7dc9c02d5")),
        ("trust", ("db7cf136ad10ad54", "64b60a051d5364bd")),
        ("path", ("3f8bce7b2d2ed0bd", "e8d603c2a13f4ed9")),
    ],
)
@pytest.mark.parametrize(
    "query", ["?code=FIRSTSYNTHETIC", "?code=SECONDSYNTHETIC", "?code=" + "x" * 700 + "&version=actual"]
)
def test_mlflow_acquisition_identity_survives_bounded_raw_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str, hashes: tuple[str, str], query: str
) -> None:
    from modelaudit.integrations.mlflow import scan_mlflow_model

    # Parent-derived hashes include source normalization before the 512-character display limit.
    source = "models:/PublicModel/1" + query
    module = ModuleType("mlflow")
    repository = SimpleNamespace(artifact_uri="s3://trusted-bucket/models")
    lookup = Mock(side_effect=RuntimeError("unavailable")) if mode == "budget" else Mock(return_value=repository)
    module.__dict__["artifacts"] = SimpleNamespace(get_artifact_repository=lookup)
    monkeypatch.setitem(sys.modules, "mlflow", module)
    monkeypatch.setenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", "s3://trusted-bucket" if mode == "path" else "")
    monkeypatch.setattr("modelaudit.integrations.mlflow.tempfile.mkdtemp", lambda **kwargs: str(tmp_path / "missing"))
    result = scan_mlflow_model(source, max_file_size=1 if mode == "budget" else 0)
    expected_location = source if len(source) <= 512 else source[:509] + "..."
    assert result.issues[0].location == result.checks[0].location == expected_location
    assert len(getattr(result.issues[0], "finding_identity", {})["fields"]["location"]) <= 512
    aggregate = create_initial_audit_result()
    aggregate.aggregate_scan_result(result)
    direct = create_initial_audit_result()
    scanned = ScanResult(scanner_name="mlflow")
    scanned.issues, scanned.checks = result.issues, result.checks
    direct.aggregate_scan_result_direct(scanned)
    for converted in [
        result,
        aggregate,
        direct,
        ModelAuditResultModel.model_validate_json(aggregate.model_dump_json()),
    ]:
        finding = _create_run(converted, [], False)["results"][0]
        assert finding["partialFingerprints"]["primaryLocationLineHash"] == hashes[int(len(source) > 512)]
        assert finding["message"]["text"] == result.issues[0].message
        assert converted.issues[0].location == expected_location
        assert getattr(converted.checks[0], "finding_identity", {}) == getattr(result.checks[0], "finding_identity", {})


@pytest.mark.parametrize("query", ["", "?revision=main"])
@pytest.mark.skipif(os.name == "nt", reason="Literal question marks are not valid Windows directory names")
def test_directory_owner_preserves_parent_finding_and_check_identities(tmp_path: Path, query: str) -> None:
    from modelaudit.core_results import consolidate_checks

    root = tmp_path / ("owner" + query)
    root.mkdir()
    metadata = root / "metadata.json"
    metadata.write_text(
        json.dumps({"version": "0.1.0", "type": "orbax_checkpoint", "restore_fn": "lambda x: eval(x.decode())"})
    )
    result = scan_model_directory_or_file(str(root), cache_enabled=False)
    # Parent reports the same restore function through owner and child when normalization makes their keys differ.
    expected_locations = ([str(tmp_path / "owner") + "?revision=<redacted>"] if query else []) + [str(metadata)]
    expected_hashes = [
        hashlib.sha256(
            ("Dangerous restore function detected in Orbax metadata" + location + "IssueSeverity.CRITICAL").encode()
        ).hexdigest()[:16]
        for location in expected_locations
    ]
    expected_counts = (9, 7, 2) if query else (8, 7, 1)
    for converted in [result, ModelAuditResultModel.model_validate_json(result.model_dump_json())]:
        converted.deduplicate_issues()
        consolidate_checks(converted)
        findings = [item for item in _create_run(converted, [], False)["results"] if item["ruleId"] == "S302"]
        assert [item["partialFingerprints"]["primaryLocationLineHash"] for item in findings] == expected_hashes
        assert (converted.total_checks, converted.passed_checks, converted.failed_checks) == expected_counts
        assert all(issue.location == str(metadata) for issue in converted.issues if issue.rule_code == "S302")


@pytest.mark.parametrize("owner_path", ["/proc/self/fd/11", "/synthetic/staged-owner", "."])
def test_directory_owner_identity_keeps_message_rules_and_evidence(tmp_path: Path, owner_path: str) -> None:
    from modelaudit.core import _normalize_directory_owner_scan_result_for_reporting
    from modelaudit.utils.helpers.finding_identity import finding_identity

    report_path = str(tmp_path / "owner")
    scanned = ScanResult(scanner_name="jax_checkpoint")
    url = "https://example.com/a?revision=main"
    issue = Issue(
        message="Fetch " + url, location=owner_path, type=url, rule_code=url, details={"evidence_fingerprint": url}
    )
    scanned.issues.append(issue)
    _normalize_directory_owner_scan_result_for_reporting(scanned, owner_path, report_path)
    identity = finding_identity(issue)
    expected_url = url if owner_path == "." else "https://example.com/a?revision=<redacted>"
    assert identity.message == "Fetch " + expected_url
    assert identity.type == identity.rule_code == identity.details["evidence_fingerprint"] == expected_url
    assert issue.message == "Fetch " + url
    assert issue.type == issue.rule_code == issue.details["evidence_fingerprint"] == url
    assert identity.location == issue.location == report_path


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        [],
        {"producer": []},
        {"producer": {}},
        {"producer": "unknown"},
        {"producer": "directory_owner", "fields": []},
    ],
)
def test_malformed_or_evidence_owned_identity_metadata_is_ignored(metadata: object) -> None:
    from modelaudit.utils.helpers.finding_identity import finding_identity

    issue = Issue(
        message="original",
        location="model.pkl",
        finding_identity=metadata,
        details={"finding_identity": {"producer": "directory_owner", "fields": {"message": "spoofed"}}},
    )
    saved = Issue.model_validate_json(issue.model_dump_json())
    assert finding_identity(saved).message == "original"
    assert (
        _create_results([saved])[0]["partialFingerprints"]
        == _create_results([Issue(message="original", location="model.pkl")])[0]["partialFingerprints"]
    )


def test_real_stream_aggregation_retains_parent_deduplication(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b"cos\nsystem\n(S'printf sample'\ntR."
    aggregate = create_initial_audit_result()
    for token in ["alpha", "beta"]:
        source = "https://bucket.s3.amazonaws.com/model.pkl?token=" + token
        filesystem = Mock()
        filesystem.info.return_value = {"size": len(payload)}
        filesystem.open.side_effect = lambda *args: io.BytesIO(payload)
        monkeypatch.setattr("fsspec.filesystem", Mock(return_value=filesystem))
        result = scan_model_directory_or_file("stream://" + source, cache_scan_results=False)
        assert all(source in issue.location for issue in result.issues if issue.location)
        aggregate.aggregate_scan_result(result.model_dump())
    aggregate.finalize_statistics()
    for converted in [aggregate, ModelAuditResultModel.model_validate_json(aggregate.model_dump_json())]:
        converted.deduplicate_issues()
        assert len(converted.issues) == 2
        assert [
            item["partialFingerprints"]["primaryLocationLineHash"]
            for item in _create_run(converted, [], False)["results"]
        ] == [
            "fb2ab0e5be0479b9",
            "141c46e33bef25d8",
        ]


@pytest.mark.parametrize("output_format", ["json", "sarif"])
def test_huggingface_cli_preserves_parent_source_deduplication(
    monkeypatch: pytest.MonkeyPatch, output_format: str
) -> None:
    from click.testing import CliRunner

    from modelaudit.cli import cli

    paths = [
        "https://huggingface.co/synthetic/model?revision=v1&token=" + token
        for token in ["FIRSTSYNTHETIC", "SECONDSYNTHETIC"]
    ]
    downloader = Mock(side_effect=RuntimeError("403 Forbidden: gated model"))
    monkeypatch.setattr("modelaudit.cli.download_model", downloader)
    result = CliRunner().invoke(cli, ["scan", "--quiet", "--no-cache", "--format", output_format, *paths])
    assert result.exit_code == 2
    assert downloader.call_count == 2
    exported = json.loads(result.output[result.output.index("{") :])
    if output_format == "json":
        assert len(exported["issues"]) == 1
        assert paths[0] in exported["issues"][0]["location"]
        saved = ModelAuditResultModel.model_validate(exported)
        saved.deduplicate_issues()
        findings = _create_run(saved, [], False)["results"]
    else:
        findings = exported["runs"][0]["results"]
    assert len(findings) == 1
    assert findings[0]["partialFingerprints"]["primaryLocationLineHash"] == "e551792c82a8ce3b"


def test_direct_raw_sarif_models_do_not_infer_producer_normalization() -> None:
    source = "https://bucket.s3.amazonaws.com/model.pkl?token=alpha"
    result = create_initial_audit_result()
    result.issues = [
        Issue(
            message="Found dangerous pickle global",
            location=source + suffix,
            severity=IssueSeverity.CRITICAL,
            type="pickle_check",
            rule_code="S201",
        )
        for suffix in ["", " (pos 30)", ":42"]
    ]
    findings = _create_run(result, ["stream://" + source], False)["results"]
    assert [item["partialFingerprints"]["primaryLocationLineHash"] for item in findings] == ["69306204a0e4ca52"] * 3
    source = "https://huggingface.co/org/repo?token=alpha@main"
    result.issues = [
        Issue(
            message="Failed to download " + source + ": unavailable",
            location=source,
            severity=IssueSeverity.INFO,
            type="huggingface_acquisition_error",
            details={"requested_revision": "main"},
        )
    ]
    assert (
        _create_run(result, [source], False)["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
        == "015d415c5d3be61c"
    )


def test_stream_rule_classification_uses_identity_but_keeps_raw_description(monkeypatch: pytest.MonkeyPatch) -> None:
    source = "stream://https://bucket.s3.amazonaws.com/model.pkl?token=pickle-exec-secret-license-cve-network"
    filesystem = Mock()
    filesystem.info.side_effect = RuntimeError("transport unavailable")
    monkeypatch.setattr("fsspec.filesystem", Mock(return_value=filesystem))
    result = scan_model_directory_or_file(source, cache_scan_results=False)
    for converted in [result, ModelAuditResultModel.model_validate_json(result.model_dump_json())]:
        rule = _create_run(converted, [source], False)["tool"]["driver"]["rules"][0]
        assert rule["properties"]["tags"] == ["security", "ml-model"]
        assert rule["shortDescription"]["text"] == converted.issues[0].message[:100]
        assert "pickle-exec-secret-license-cve-network" in converted.issues[0].message
