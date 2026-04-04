from pathlib import Path

import pytest

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

    # Should have file type validation info for minimal XML
    file_type_issues = [i for i in result.issues if "File type validation failed" in i.message]
    assert len(file_type_issues) == 1
    assert file_type_issues[0].severity.value == "info"


def test_openvino_scanner_can_handle_long_xml_prolog(tmp_path: Path) -> None:
    """OpenVINO XML routing should not depend on finding the root tag in the first 256 bytes."""
    xml_path = tmp_path / "model.xml"
    xml_path.write_text(
        f"<?xml version='1.0'?><!--{'x' * 512}--><net name='test' version='10'></net>",
        encoding="utf-8",
    )

    assert OpenVinoScanner.can_handle(str(xml_path)) is True


def test_openvino_scanner_can_handle_uses_bounded_xml_prefix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Root tags beyond the bounded routing prefix should fail closed instead of forcing full-file parsing."""
    xml_path = tmp_path / "model.xml"
    xml_path.write_text(
        f"<?xml version='1.0'?><!--{'x' * 512}--><net name='test' version='10'></net>",
        encoding="utf-8",
    )
    monkeypatch.setattr(OpenVinoScanner, "CAN_HANDLE_MAX_PARSE_BYTES", 128)

    assert OpenVinoScanner.can_handle(str(xml_path)) is False


def test_openvino_scanner_can_handle_rejects_non_openvino_xml(tmp_path: Path) -> None:
    """Non-OpenVINO XML should not be routed to this scanner just because it has a .xml suffix."""
    xml_path = tmp_path / "document.xml"
    xml_path.write_text("<project><model name='not-openvino'/></project>", encoding="utf-8")

    assert OpenVinoScanner.can_handle(str(xml_path)) is False


def test_openvino_scanner_missing_bin(tmp_path: Path) -> None:
    xml_path = tmp_path / "model.xml"
    xml_path.write_text("<net version='10'></net>", encoding="utf-8")

    result = OpenVinoScanner().scan(str(xml_path))
    messages = [i.message.lower() for i in result.issues]
    assert any("weights file not found" in m for m in messages)
    # Missing weights file is INFO severity (not a security concern)
    assert any(i.severity == IssueSeverity.INFO for i in result.issues)


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

    # Check that the security issues are critical (ignoring file type validation warnings)
    security_issues = [
        i for i in result.issues if "python layer" in i.message.lower() or "external library" in i.message.lower()
    ]
    assert all(i.severity == IssueSeverity.CRITICAL for i in security_issues)


def test_openvino_scanner_respects_configured_file_size_limit(tmp_path: Path) -> None:
    """scan() should fail closed before parsing XML that exceeds max_file_read_size."""
    xml_path = create_basic_model(tmp_path)

    result = OpenVinoScanner(config={"max_file_read_size": 8}).scan(str(xml_path))

    assert result.success is False
    assert any(check.name == "File Size Limit" for check in result.checks)


def test_openvino_scanner_detects_nested_external_library_references(tmp_path: Path) -> None:
    """Nested layer config nodes should be checked for implementation/library references."""
    xml_path = tmp_path / "model.xml"
    xml_path.write_text(
        """
        <net version='10'>
          <layers>
            <layer id='1' name='conv' type='Convolution'>
              <data implementation='evil.so'/>
            </layer>
          </layers>
        </net>
        """,
        encoding="utf-8",
    )
    (tmp_path / "model.bin").write_bytes(b"\x00")

    result = OpenVinoScanner().scan(str(xml_path))

    assert result.success is False
    assert any("external library 'evil.so'" in issue.message for issue in result.issues)


def test_openvino_scanner_layer_attribute_importlib_false_positive_control(tmp_path: Path) -> None:
    """Benign names containing importlib as a substring should not be flagged."""
    xml_path = tmp_path / "model.xml"
    xml_path.write_text(
        """
        <net version='10'>
          <layers>
            <layer id='2' name='custom_importlib_feature' type='Input'/>
          </layers>
        </net>
        """,
        encoding="utf-8",
    )
    (tmp_path / "model.bin").write_bytes(b"\x00")

    result = OpenVinoScanner().scan(str(xml_path))

    assert result.success is True
    assert not any(check.name == "Layer Attribute Security Check" for check in result.checks)


def test_openvino_scanner_layer_attribute_detects_direct_importlib_reference(tmp_path: Path) -> None:
    """The importlib false-positive guard should still flag direct dangerous references."""
    xml_path = tmp_path / "model.xml"
    xml_path.write_text(
        """
        <net version='10'>
          <layers>
            <layer id='3' name='importlib.import_module' type='Input'/>
          </layers>
        </net>
        """,
        encoding="utf-8",
    )
    (tmp_path / "model.bin").write_bytes(b"\x00")

    result = OpenVinoScanner().scan(str(xml_path))

    assert result.success is False
    assert any(check.name == "Layer Attribute Security Check" for check in result.checks)
