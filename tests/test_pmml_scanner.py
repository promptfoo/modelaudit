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
    assert any("doctype" in m or "entity" in m for m in messages)
    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)
