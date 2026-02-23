"""Tests for SARIF formatter module."""

import json
import time

from modelaudit.integrations.sarif_formatter import (
    _create_artifacts,
    _create_results,
    _create_rules,
    _create_run,
    _get_mime_type,
    _get_rule_full_description,
    _get_rule_id,
    _get_rule_name,
    _get_rule_short_description,
    _get_tags_for_issue,
    _normalize_path_to_uri,
    _severity_to_rank,
    _severity_to_sarif_level,
    format_sarif_output,
)
from modelaudit.models import AssetModel, FileHashesModel, FileMetadataModel, create_initial_audit_result
from modelaudit.scanners.base import Issue, IssueSeverity


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

    def test_result_kind_by_severity(self):
        """Test result kind based on severity."""
        critical = Issue(message="Critical", severity=IssueSeverity.CRITICAL, timestamp=time.time())
        info = Issue(message="Info", severity=IssueSeverity.INFO, timestamp=time.time())

        critical_results = _create_results([critical])
        info_results = _create_results([info])

        assert critical_results[0]["kind"] == "fail"
        assert info_results[0]["kind"] == "informational"


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

    def test_get_tags_for_issue_code_execution(self):
        """Test tags for code execution issues."""
        issue = Issue(message="eval() import detected", severity=IssueSeverity.WARNING, timestamp=time.time())

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
