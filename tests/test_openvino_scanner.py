from pathlib import Path

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.openvino_scanner import OpenVinoScanner


def create_basic_model(dir_path: Path) -> Path:
    xml_path = dir_path / "model.xml"
    bin_path = dir_path / "model.bin"
    xml_content = """<net name='test' version='10'><layers><layer id='0' name='data' type='Input'/></layers></net>"""
    xml_path.write_text(xml_content, encoding="utf-8")
    bin_path.write_bytes(b"\x00" * 10)
    return xml_path


def test_openvino_scanner_basic(tmp_path: Path) -> None:
    xml_path = create_basic_model(tmp_path)

    scanner = OpenVinoScanner()
    assert scanner.can_handle(str(xml_path))

    result = scanner.scan(str(xml_path))
    assert result.success
    assert result.metadata["xml_size"] == xml_path.stat().st_size
    assert result.metadata.get("bin_size") == (tmp_path / "model.bin").stat().st_size
    assert not result.issues


def test_openvino_scanner_missing_bin(tmp_path: Path) -> None:
    xml_path = tmp_path / "model.xml"
    xml_path.write_text("<net version='10'></net>", encoding="utf-8")

    result = OpenVinoScanner().scan(str(xml_path))
    messages = [i.message.lower() for i in result.issues]
    assert any("weights file not found" in m for m in messages)
    assert any(i.severity == IssueSeverity.WARNING for i in result.issues)


def test_openvino_scanner_custom_layer(tmp_path: Path) -> None:
    xml_path = tmp_path / "model.xml"
    bin_path = tmp_path / "model.bin"
    xml_path.write_text(
        "<net version='10'><layers><layer id='1' name='evil' type='Python' library='evil.so'/></layers></net>",
        encoding="utf-8",
    )
    bin_path.write_bytes(b"\x00")

    result = OpenVinoScanner().scan(str(xml_path))
    assert any("python layer" in i.message.lower() for i in result.issues)
    assert any("external library" in i.message.lower() for i in result.issues)
    assert all(i.severity == IssueSeverity.CRITICAL for i in result.issues)
