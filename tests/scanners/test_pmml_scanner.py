from pathlib import Path

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.pmml_scanner import PmmlScanner


def test_pmml_scanner_basic(tmp_path: Path) -> None:
    pmml = """<?xml version='1.0'?>
<PMML version='4.4'>
  <Header/>
  <DataDictionary numberOfFields='0'/>
</PMML>"""
    path = tmp_path / "model.pmml"
    path.write_text(pmml, encoding="utf-8")

    scanner = PmmlScanner()
    assert scanner.can_handle(str(path))

    result = scanner.scan(str(path))
    assert result.success
    assert result.bytes_scanned > 0
    assert not result.has_errors
    assert result.metadata["pmml_version"] == "4.4"


def test_pmml_scanner_xxe(tmp_path: Path) -> None:
    pmml = """<?xml version='1.0'?>
<!DOCTYPE pmml [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]>
<PMML version='4.4'>
  <Header>
    <Extension>&xxe;</Extension>
  </Header>
</PMML>"""
    path = tmp_path / "evil.pmml"
    path.write_text(pmml, encoding="utf-8")

    result = PmmlScanner().scan(str(path))
    messages = [i.message.lower() for i in result.issues]
    assert result.success is False
    assert any("doctype" in m or "entity" in m for m in messages)
    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)


def test_pmml_scanner_suspicious_extension_content(tmp_path: Path) -> None:
    """Test detection of suspicious content in Extension elements."""
    pmml = """<?xml version='1.0'?>
<PMML version='4.4'>
  <Header>
    <Extension>
      <script>alert('malicious')</script>
      eval('dangerous code')
    </Extension>
  </Header>
</PMML>"""
    path = tmp_path / "suspicious.pmml"
    path.write_text(pmml, encoding="utf-8")

    result = PmmlScanner().scan(str(path))
    assert result.success

    # Should detect suspicious patterns
    suspicious_issues = [i for i in result.issues if "suspicious content" in i.message.lower()]
    assert len(suspicious_issues) >= 1
    assert all(i.severity == IssueSeverity.WARNING for i in suspicious_issues)


def test_pmml_scanner_namespaced_extension_content(tmp_path: Path) -> None:
    """Test namespaced Extension and script tags are inspected."""
    pmml = """<?xml version='1.0'?>
<PMML xmlns='https://example.test/pmml' version='4.4'>
  <Header>
    <Extension>
      <script>exec ('dangerous code')</script>
    </Extension>
  </Header>
</PMML>"""
    path = tmp_path / "namespaced_suspicious.pmml"
    path.write_text(pmml, encoding="utf-8")

    result = PmmlScanner().scan(str(path))

    assert result.success is True
    assert any("Suspicious XML element found" in issue.message for issue in result.issues)
    assert any("Suspicious content in <Extension> element" in issue.message for issue in result.issues)


def test_pmml_scanner_external_references(tmp_path: Path) -> None:
    """Test detection of external resource references."""
    pmml = """<?xml version='1.0'?>
<PMML version='4.4'>
  <Header>
    <Extension extender="malicious" value="http://evil.com/steal-data"/>
  </Header>
  <DataDictionary>
    <DataField name="test" optype="continuous" dataType="double">
      <Value value="https://attacker.com/exfiltrate" property="external"/>
    </DataField>
  </DataDictionary>
</PMML>"""
    path = tmp_path / "external_refs.pmml"
    path.write_text(pmml, encoding="utf-8")

    result = PmmlScanner().scan(str(path))
    assert result.success

    # Should detect external references
    external_issues = [i for i in result.issues if "external resource" in i.message.lower()]
    assert len(external_issues) >= 2  # Should find both http and https references
    assert all(i.severity == IssueSeverity.WARNING for i in external_issues)


def test_pmml_scanner_malformed_xml(tmp_path: Path) -> None:
    """Test handling of malformed XML."""
    malformed_xml = """<?xml version='1.0'?>
<PMML version='4.4'>
  <Header>
    <Unclosed tag
  </Header>
</PMML>"""
    path = tmp_path / "malformed.pmml"
    path.write_text(malformed_xml, encoding="utf-8")

    result = PmmlScanner().scan(str(path))
    assert not result.success
    assert any("malformed xml" in i.message.lower() for i in result.issues)
    # Malformed XML is INFO severity (not a security threat, just parsing issue)
    assert any(i.severity == IssueSeverity.INFO for i in result.issues)


def test_pmml_scanner_invalid_root_element(tmp_path: Path) -> None:
    """Test handling of files with wrong root element."""
    wrong_root = """<?xml version='1.0'?>
<WrongRoot version='4.4'>
  <Header/>
</WrongRoot>"""
    path = tmp_path / "wrong_root.pmml"
    path.write_text(wrong_root, encoding="utf-8")

    result = PmmlScanner().scan(str(path))
    assert result.success
    assert any("root element is not" in i.message.lower() for i in result.issues)
    assert any(i.severity == IssueSeverity.WARNING for i in result.issues)


def test_pmml_scanner_missing_version(tmp_path: Path) -> None:
    """Test handling of PMML without version attribute."""
    no_version = """<?xml version='1.0'?>
<PMML>
  <Header/>
</PMML>"""
    path = tmp_path / "no_version.pmml"
    path.write_text(no_version, encoding="utf-8")

    result = PmmlScanner().scan(str(path))
    assert result.success
    assert any("missing version" in i.message.lower() for i in result.issues)
    assert result.metadata.get("pmml_version") == ""


def test_pmml_scanner_non_utf8_content(tmp_path: Path) -> None:
    """Test handling of non-UTF8 content."""
    # Create file with non-UTF8 bytes that breaks XML parsing
    path = tmp_path / "non_utf8.pmml"
    with open(path, "wb") as f:
        f.write(b'<?xml version="1.0"?>\n<PMML>\xff\xfe\x00Invalid</PMML>')

    result = PmmlScanner().scan(str(path))
    # XML with invalid bytes should fail parsing
    assert not result.success
    assert any("malformed xml" in i.message.lower() for i in result.issues)
    # Malformed XML is INFO severity (not a security threat, just parsing issue)
    assert any(i.severity == IssueSeverity.INFO for i in result.issues)


def test_pmml_scanner_utf8_with_replacement(tmp_path: Path) -> None:
    """Test handling of content that requires UTF-8 replacement characters."""
    # Create file with some invalid UTF-8 but valid XML structure
    path = tmp_path / "utf8_replacement.pmml"
    with open(path, "wb") as f:
        # Write valid XML with one invalid UTF-8 byte that can be replaced
        f.write(
            b'<?xml version="1.0"?>\n<PMML version="4.4">\n<Header>\xff</Header>\n</PMML>',
        )

    result = PmmlScanner().scan(str(path))
    # Should succeed with warning about UTF-8 issues
    assert result.success
    assert any("non utf-8" in i.message.lower() for i in result.issues)
    assert any(i.severity == IssueSeverity.WARNING for i in result.issues)


def test_pmml_scanner_enforces_size_limit(tmp_path: Path) -> None:
    pmml = """<?xml version='1.0'?>
<PMML version='4.4'>
  <Header/>
</PMML>"""
    path = tmp_path / "oversized.pmml"
    path.write_text(pmml, encoding="utf-8")

    result = PmmlScanner(config={"max_file_size": 16}).scan(str(path))

    assert result.success is False
    assert any("file too large" in issue.message.lower() for issue in result.issues)


def test_pmml_scanner_comment_doctype_is_not_xxe(tmp_path: Path) -> None:
    pmml = """<?xml version='1.0'?>
<!-- <!DOCTYPE pmml [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]> -->
<PMML version='4.4'>
  <Header/>
</PMML>"""
    path = tmp_path / "commented_doctype.pmml"
    path.write_text(pmml, encoding="utf-8")

    result = PmmlScanner().scan(str(path))

    assert result.success is True
    assert not any(
        issue.severity == IssueSeverity.CRITICAL and "PMML file contains" in issue.message for issue in result.issues
    )


def test_pmml_scanner_cdata_doctype_is_not_xxe(tmp_path: Path) -> None:
    pmml = """<?xml version='1.0'?>
<PMML version='4.4'>
  <Header>
    <Extension><![CDATA[<!DOCTYPE pmml [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]>]]></Extension>
  </Header>
</PMML>"""
    path = tmp_path / "cdata_doctype.pmml"
    path.write_text(pmml, encoding="utf-8")

    result = PmmlScanner().scan(str(path))

    assert result.success is True
    assert not any(
        issue.severity == IssueSeverity.CRITICAL and "PMML file contains" in issue.message for issue in result.issues
    )


def test_pmml_scanner_deep_extension_tree_does_not_recurse_forever(tmp_path: Path) -> None:
    nested_body = "<node>" * 1200 + "payload" + "</node>" * 1200
    pmml = f"""<?xml version='1.0'?>
<PMML version='4.4'>
  <Header>
    <Extension>{nested_body}</Extension>
  </Header>
</PMML>"""
    path = tmp_path / "deep_extension.pmml"
    path.write_text(pmml, encoding="utf-8")

    result = PmmlScanner().scan(str(path))

    assert result.success is True
    assert result.bytes_scanned > 0


def test_pmml_scanner_extension_text_truncation_fails_closed(tmp_path: Path) -> None:
    pmml = f"""<?xml version='1.0'?>
<PMML version='4.4'>
  <Header>
    <Extension>{"<node/>" * (PmmlScanner.MAX_EXTENSION_TEXT_NODES + 8)}<script>eval('x')</script></Extension>
  </Header>
</PMML>"""
    path = tmp_path / "truncated_extension.pmml"
    path.write_text(pmml, encoding="utf-8")

    result = PmmlScanner().scan(str(path))

    assert result.success is False
    assert any("exceeds the safe inspection node limit" in issue.message for issue in result.issues)
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_pmml_scanner_can_handle_detection(tmp_path: Path) -> None:
    """Test file format detection beyond just extensions."""
    # Test PMML content without .pmml extension
    pmml_content = """<?xml version='1.0'?>
<PMML version='4.4'>
  <Header/>
</PMML>"""

    # Test with different extension
    path = tmp_path / "model.xml"
    path.write_text(pmml_content, encoding="utf-8")

    scanner = PmmlScanner()
    assert scanner.can_handle(str(path))  # Should detect PMML content

    # Test non-PMML XML file
    non_pmml = """<?xml version='1.0'?>
<root>
  <data>not pmml</data>
</root>"""
    path2 = tmp_path / "other.xml"
    path2.write_text(non_pmml, encoding="utf-8")

    assert not scanner.can_handle(str(path2))  # Should not handle non-PMML


def test_pmml_scanner_comprehensive_dangerous_entities(tmp_path: Path) -> None:
    """Test detection of various dangerous XML constructs."""
    dangerous_xml = """<?xml version='1.0'?>
<!DOCTYPE pmml [
  <!ENTITY xxe SYSTEM 'file:///etc/passwd'>
  <!ELEMENT custom ANY>
  <!ATTLIST custom attr CDATA #IMPLIED>
]>
<PMML version='4.4'>
  <Header/>
</PMML>"""
    path = tmp_path / "dangerous.pmml"
    path.write_text(dangerous_xml, encoding="utf-8")

    result = PmmlScanner().scan(str(path))

    # Should detect multiple dangerous constructs
    dangerous_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
    construct_types = {i.details.get("construct") for i in dangerous_issues if i.details.get("construct")}

    # Should detect DOCTYPE, ENTITY, ELEMENT, and ATTLIST
    expected_constructs = {"<!DOCTYPE", "<!ENTITY", "<!ELEMENT", "<!ATTLIST"}
    assert expected_constructs.issubset(construct_types)


def test_pmml_scanner_metadata_tracking(tmp_path: Path) -> None:
    """Test that scanner properly tracks metadata."""
    pmml = """<?xml version='1.0'?>
<PMML version='4.4'>
  <Header/>
</PMML>"""
    path = tmp_path / "metadata_test.pmml"
    path.write_text(pmml, encoding="utf-8")

    result = PmmlScanner().scan(str(path))
    assert result.success

    # Check metadata is properly set
    assert "file_size" in result.metadata
    assert "pmml_version" in result.metadata
    assert "has_defusedxml" in result.metadata
    assert result.metadata["pmml_version"] == "4.4"
    assert isinstance(result.metadata["has_defusedxml"], bool)
    assert result.bytes_scanned > 0
