"""Tests for SARIF formatter module."""

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import modelaudit.integrations.sarif_formatter as sarif_formatter
from modelaudit.core import scan_model_directory_or_file
from modelaudit.models import AssetModel, FileHashesModel, FileMetadataModel, create_initial_audit_result
from modelaudit.scanners.base import Issue, IssueSeverity

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
_redact_path_for_sarif = sarif_formatter._redact_path_for_sarif
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

    def test_signed_stream_paths_are_redacted(self) -> None:
        """SARIF must not retain signed URL query material in paths."""
        raw_path = (
            "stream://https://bucket.s3.amazonaws.com/model.pkl?"
            "X-Amz-Credential=AKIASECRET&X-Amz-Signature=deadbeef&token=secret-token"
        )
        safe_path = "stream://https://bucket.s3.amazonaws.com/model.pkl"
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
            assert leaked not in output
        assert "sentencepiece" in output
        assert raw_path not in output
        assert safe_path in output
        assert safe_path in invocation["commandLine"]
        assert invocation["arguments"] == [safe_path]

    def test_mixed_case_signed_stream_paths_are_redacted(self) -> None:
        """URI scheme casing must not bypass SARIF stream redaction."""
        raw_path = "STREAM://HTTPS://BUCKET.S3.AMAZONAWS.COM/model.pkl?X-Amz-Signature=secret"
        result = create_initial_audit_result()
        result.assets = [AssetModel(path=raw_path, type="pickle")]
        result.finalize_statistics()

        output = format_sarif_output(result, [raw_path])

        assert "secret" not in output
        assert "X-Amz-Signature" not in output
        assert "stream://https://bucket.s3.amazonaws.com/model.pkl" in output

    def test_escaped_url_delimiters_cannot_bypass_sarif_redaction(self) -> None:
        escaped_url = r"https:\/\/collector.example\/callback\u003ftoken\u003dENCODED-SARIF-SECRET"
        result = create_initial_audit_result()
        result.issues = [
            Issue(
                message=f"Related endpoint: {escaped_url}",
                severity=IssueSeverity.WARNING,
                details={"related_url": escaped_url},
                timestamp=time.time(),
            )
        ]
        result.finalize_statistics()

        output = format_sarif_output(result, ["/test/path"])

        assert "ENCODED-SARIF-SECRET" not in output
        assert "https://collector.example/callback" in output
        assert "token=" not in output

    @pytest.mark.parametrize(
        "mixed_encoded_url",
        [
            "https%3A//user:password@collector.example/model.pkl?token=MIXED-TOKEN-LEAK",
            "https:%2F%2Fuser:password@collector.example/model.pkl?token=MIXED-TOKEN-LEAK",
            "https%253A/%252Fuser:password@collector.example/model.pkl?token=MIXED-TOKEN-LEAK",
        ],
    )
    def test_mixed_encoded_url_prefixes_cannot_bypass_sarif_redaction(self, mixed_encoded_url: str) -> None:
        result = create_initial_audit_result()
        result.issues = [
            Issue(
                message=f"Related endpoint: {mixed_encoded_url}",
                severity=IssueSeverity.WARNING,
                details={"related_url": mixed_encoded_url},
                timestamp=time.time(),
            )
        ]
        result.finalize_statistics()

        output = format_sarif_output(result, ["/test/path"])

        assert "user:password" not in output
        assert "MIXED-TOKEN-LEAK" not in output
        assert "https://collector.example/model.pkl" in output

    def test_malformed_stream_paths_fail_closed(self) -> None:
        """SARIF invocation and asset paths must not retain malformed stream queries."""
        raw_path = "stream://bucket/model.pkl?token=secret-token"
        result = create_initial_audit_result()
        result.assets = [AssetModel(path=raw_path, type="pickle")]
        result.finalize_statistics()

        output = format_sarif_output(result, [raw_path])

        assert "secret-token" not in output
        assert "token=" not in output
        assert "stream://<cloud URL redacted>" in output

    def test_already_redacted_url_preserves_benign_query_context(self) -> None:
        """Repeated SARIF sanitization must not corrupt safe query context."""
        safe_url = "https://collector.example/upload?visible=yes&token=<redacted>"
        partially_redacted_url = f"{safe_url}&Signature=remaining-secret"
        fully_redacted_url = f"{safe_url}&Signature=<redacted>"
        result = create_initial_audit_result()
        result.issues = [
            Issue(
                message=f"Related endpoint: {partially_redacted_url}",
                severity=IssueSeverity.WARNING,
                details={"related_url": partially_redacted_url},
                timestamp=time.time(),
            )
        ]
        result.finalize_statistics()

        output = format_sarif_output(result, ["/test/path"])

        assert fully_redacted_url in output
        assert "remaining-secret" not in output
        assert "https://collector.example/upload<redacted>" not in output

    def test_signed_url_rotation_preserves_finding_fingerprint(self) -> None:
        """Renewing a signed URL must not create a different SARIF finding identity."""

        def _fingerprint(signature: str) -> str:
            raw_url = f"https://bucket.s3.amazonaws.com/model.pkl?X-Amz-Signature={signature}"
            result = create_initial_audit_result()
            result.issues = [
                Issue(
                    message=f"Dangerous payload from {raw_url}",
                    severity=IssueSeverity.WARNING,
                    location=raw_url,
                    timestamp=time.time(),
                )
            ]
            result.finalize_statistics()
            parsed = json.loads(format_sarif_output(result, [raw_url]))
            return str(parsed["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"])

        assert _fingerprint("first-secret") == _fingerprint("renewed-secret")

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

    def test_raw_url_preserves_benign_query_context_while_redacting_credentials(self) -> None:
        """Finding evidence keeps useful query context without retaining credentials."""
        raw_url = "https://evil.example/c2?campaign=test&session=secret-session&token=secret-token"
        result = create_initial_audit_result()
        result.issues = [
            Issue(
                message=f"Detected callback {raw_url}",
                severity=IssueSeverity.WARNING,
                timestamp=time.time(),
            )
        ]
        result.finalize_statistics()

        output = format_sarif_output(result, ["/test/path"])

        assert "campaign=test" in output
        assert "session=" not in output
        assert "token=" not in output
        assert "secret-session" not in output
        assert "secret-token" not in output

    def test_raw_url_redacts_unknown_query_values(self) -> None:
        """Unknown evidence parameters must fail closed even without a credential-like key."""
        raw_url = "https://evil.example/c2?campaign=test&opaque=SUPERSECRET"
        result = create_initial_audit_result()
        result.issues = [
            Issue(
                message=f"Detected callback {raw_url}",
                severity=IssueSeverity.WARNING,
                timestamp=time.time(),
            )
        ]
        result.finalize_statistics()

        output = format_sarif_output(result, ["/test/path"])

        assert "campaign=test" in output
        assert "opaque=" not in output
        assert "SUPERSECRET" not in output

    def test_safe_query_key_cannot_hide_encoded_nested_credentials(self) -> None:
        """Allowlisted evidence keys must not preserve encoded nested credentials."""
        raw_url = "https://evil.example/c2?lang=en%26access_token%3DSUPERSECRET"
        result = create_initial_audit_result()
        result.issues = [
            Issue(
                message=f"Detected callback {raw_url}",
                severity=IssueSeverity.WARNING,
                details={"callback": raw_url},
                timestamp=time.time(),
            )
        ]
        result.finalize_statistics()

        output = format_sarif_output(result, ["/test/path"])

        assert "lang=" not in output
        assert "access_token" not in output
        assert "SUPERSECRET" not in output

    def test_percent_encoded_url_delimiters_cannot_hide_credentials(self) -> None:
        """Encoded URL structure must be exposed before SARIF evidence redaction."""
        raw_url = (
            "https://bucket.s3.amazonaws.com/model.pkl"
            "%3Fvisible%3Dyes%26X-Amz-Signature%3Ddeadbeef%26token%3Dprivate-token-value"
        )
        result = create_initial_audit_result()
        result.issues = [
            Issue(
                message=f"Provider failed while opening {raw_url}",
                severity=IssueSeverity.WARNING,
                details={"source": raw_url},
                timestamp=time.time(),
            )
        ]
        result.finalize_statistics()

        output = format_sarif_output(result, [raw_url])

        assert "visible=yes" in output
        assert "X-Amz-Signature" not in output
        assert "token=" not in output
        assert "deadbeef" not in output
        assert "private-token-value" not in output

    def test_percent_encoded_url_userinfo_cannot_hide_credentials(self) -> None:
        raw_url = (
            "https%3A%2F%2Fuser%3Aencoded-password%40bucket.s3.amazonaws.com%2Fmodel.pkl"
            "%3Fvisible%3Dyes%26token%3Dprivate-token-value"
        )
        result = create_initial_audit_result()
        result.issues = [
            Issue(
                message=f"Provider failed while opening {raw_url}",
                severity=IssueSeverity.WARNING,
                details={"source": raw_url},
                timestamp=time.time(),
            )
        ]
        result.finalize_statistics()

        output = format_sarif_output(result, [raw_url])

        assert "bucket.s3.amazonaws.com/model.pkl" in output
        assert "visible=yes" in output
        assert "encoded-password" not in output
        assert "private-token-value" not in output

    def test_sarif_path_redaction_does_not_treat_windows_drive_as_url(self) -> None:
        """Local Windows paths must not be rewritten as URL schemes."""
        windows_path = r"C:\models\model.pkl"

        assert _redact_path_for_sarif(windows_path) == windows_path

    def test_sarif_path_redaction_handles_encoded_url_prefix(self) -> None:
        """Encoded URL-like paths still need credential stripping."""
        raw_url = (
            "https%253A%252F%252Fbucket.s3.amazonaws.com%252Fmodel.pkl%253FX-Amz-Signature%253Dprivate-token-value"
        )

        assert _redact_path_for_sarif(raw_url) == "https://bucket.s3.amazonaws.com/model.pkl"

    def test_bare_query_and_fragment_credentials_are_removed(self) -> None:
        """Opaque URL components must not bypass key/value redaction."""
        raw_url = "https://evil.example/c2?campaign=test&BARE-QUERY-SECRET#section=overview&BARE-FRAGMENT-SECRET"
        result = create_initial_audit_result()
        result.issues = [
            Issue(
                message=f"Detected callback {raw_url}",
                severity=IssueSeverity.WARNING,
                timestamp=time.time(),
            )
        ]
        result.finalize_statistics()

        output = format_sarif_output(result, ["/test/path"])

        assert "campaign=test" in output
        assert "section=overview" in output
        assert "BARE-QUERY-SECRET" not in output
        assert "BARE-FRAGMENT-SECRET" not in output

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
