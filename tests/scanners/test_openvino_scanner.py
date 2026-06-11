from pathlib import Path

import pytest

from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.openvino_scanner import OpenVinoScanner
from tests.helpers import create_malicious_pickle


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

    # Benign OpenVINO XML should not produce file-type validation noise.
    file_type_issues = [i for i in result.issues if "File type validation failed" in i.message]
    assert file_type_issues == []


def test_openvino_scanner_basic_model_has_zero_cli_exit(tmp_path: Path) -> None:
    """Benign OpenVINO XML should not produce a warning-level format-validation exit."""
    xml_path = create_basic_model(tmp_path)

    cli_result = scan_model_directory_or_file(str(xml_path))

    assert cli_result.scanner_names == ["openvino"]
    assert determine_exit_code(cli_result) == 0
    assert not any(
        check.name == "Format Validation" and check.severity == IssueSeverity.WARNING for check in cli_result.checks
    )


def test_openvino_scanner_matches_casefolded_unicode_weights_companion(tmp_path: Path) -> None:
    """Case and Unicode normalization variants should still resolve the adjacent weights."""
    xml_path = tmp_path / "Cafe\u0301-Model.XML"
    bin_path = tmp_path / "CAF\u00c9-model.BIN"
    xml_path.write_text("<net version='10'></net>", encoding="utf-8")
    bin_path.write_bytes(b"weights")

    result = OpenVinoScanner().scan(str(xml_path))

    assert OpenVinoScanner.can_handle(str(xml_path)) is True
    assert result.success is True
    assert result.metadata["bin_size"] == bin_path.stat().st_size
    assert not any("weights file not found" in check.message.lower() for check in result.checks)


def test_openvino_scanner_casefolded_companion_cache_rescans_changed_weights(tmp_path: Path) -> None:
    """Cache bypass must follow the actual normalized/casefolded OpenVINO companion."""
    xml_path = tmp_path / "Cafe\u0301-Model.XML"
    bin_path = tmp_path / "CAF\u00c9-model.BIN"
    xml_path.write_text("<net version='10'></net>", encoding="utf-8")
    bin_path.write_bytes(b"\x00" * 7)
    cache_config = {
        "cache_enabled": True,
        "cache_dir": str(tmp_path / "cache"),
        "min_cache_file_size": 0,
    }

    first_result = scan_file(str(xml_path), config=cache_config)
    bin_path.write_bytes(b"\x01" * 33)
    second_result = scan_file(str(xml_path), config=cache_config)

    assert first_result.metadata["bin_size"] == 7
    assert second_result.metadata["bin_size"] == 33


def test_openvino_scanner_detects_pickle_payload_in_weights_companion(tmp_path: Path) -> None:
    """A valid OpenVINO XML must not hide pickle-formatted same-stem weights."""
    xml_path = create_basic_model(tmp_path)
    bin_path = create_malicious_pickle(tmp_path / "model.bin")

    result = OpenVinoScanner().scan(str(xml_path))

    assert result.success is False
    assert result.metadata["openvino_weights_pickle_payload_scanned"] is True
    assert "pickle" in result.metadata["scanner_dependency_ids"]
    assert any(
        issue.location == str(bin_path)
        and issue.severity == IssueSeverity.CRITICAL
        and ("os.system" in issue.message.lower() or "posix.system" in issue.message.lower())
        for issue in result.issues
    )


def test_openvino_scanner_honors_pickle_exclusion_for_weights_companion(tmp_path: Path) -> None:
    """Embedded pickle scanning for OpenVINO weights must obey scanner selection."""
    xml_path = create_basic_model(tmp_path)
    bin_path = create_malicious_pickle(tmp_path / "model.bin")

    result = OpenVinoScanner({"exclude_scanners": ["pickle"]}).scan(str(xml_path))

    assert result.success is True
    assert result.metadata["openvino_weights_pickle_payload_skipped"] is True
    assert result.metadata["skipped_scanner_ids"] == ["pickle"]
    assert any(
        check.name == "Scanner Selection"
        and check.location == str(bin_path)
        and check.details.get("skipped_scanner_id") == "pickle"
        and check.details.get("context") == "OpenVINO weights sidecar"
        for check in result.checks
    )
    assert not any(issue.location == str(bin_path) for issue in result.issues)


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


def test_openvino_scanner_can_handle_forbidden_doctype_openvino_xml(tmp_path: Path) -> None:
    """OpenVINO XML with forbidden DOCTYPE declarations should still route to this scanner."""
    xml_path = tmp_path / "model.xml"
    xml_path.write_text(
        """<?xml version='1.0'?>
        <!DOCTYPE net [
          <!ENTITY payload SYSTEM 'file:///tmp/secret'>
        ]>
        <net version='10'><layers><layer id='0' name='data' type='Input'/></layers></net>
        """,
        encoding="utf-8",
    )

    assert OpenVinoScanner.can_handle(str(xml_path)) is True


def test_openvino_scanner_routes_unterminated_doctype_to_parse_failure(tmp_path: Path) -> None:
    """Malformed OpenVINO DOCTYPE prologs should fail closed as explicit parse errors."""
    xml_path = tmp_path / "model.xml"
    xml_path.write_text(
        """<?xml version='1.0'?>
        <!DOCTYPE net [
          <!ENTITY payload SYSTEM 'file:///tmp/secret'>
        <net version='10'><layers><layer id='0' name='data' type='Input'/></layers></net>
        """,
        encoding="utf-8",
    )
    (tmp_path / "model.bin").write_bytes(b"\x00")

    cli_result = scan_model_directory_or_file(str(xml_path))

    assert OpenVinoScanner.can_handle(str(xml_path)) is True
    assert cli_result.scanner_names == ["openvino"]
    assert determine_exit_code(cli_result) == 2
    parse_checks = [check for check in cli_result.checks if check.name == "OpenVINO XML Parse"]
    assert parse_checks
    assert all(check.status == CheckStatus.FAILED for check in parse_checks)
    assert any("Invalid OpenVINO XML" in check.message for check in parse_checks)


def test_openvino_scanner_can_handle_rejects_unterminated_non_openvino_doctype(tmp_path: Path) -> None:
    """Malformed non-OpenVINO DOCTYPE prologs should not route to OpenVINO."""
    xml_path = tmp_path / "document.xml"
    xml_path.write_text(
        """<?xml version='1.0'?>
        <!DOCTYPE html [
          <!ENTITY payload SYSTEM 'file:///tmp/secret'>
        <html><body>not an OpenVINO model</body></html>
        """,
        encoding="utf-8",
    )

    assert OpenVinoScanner.can_handle(str(xml_path)) is False


def test_openvino_scanner_missing_bin(tmp_path: Path) -> None:
    xml_path = tmp_path / "model.xml"
    xml_path.write_text("<net version='10'></net>", encoding="utf-8")

    result = OpenVinoScanner().scan(str(xml_path))
    messages = [i.message.lower() for i in result.issues]
    assert any("weights file not found" in m for m in messages)
    # Missing weights file is INFO severity (not a security concern)
    assert any(i.severity == IssueSeverity.INFO for i in result.issues)


def test_openvino_scanner_flags_bin_symlink_escape(tmp_path: Path, requires_symlinks: None) -> None:
    model_dir = tmp_path / "model"
    outside_dir = tmp_path / "outside"
    model_dir.mkdir()
    outside_dir.mkdir()

    xml_path = model_dir / "model.xml"
    escaped_weights = outside_dir / "secret.bin"
    xml_path.write_text("<net version='10'></net>", encoding="utf-8")
    escaped_weights.write_bytes(b"secret-weights")
    (model_dir / "model.bin").symlink_to(escaped_weights)

    result = OpenVinoScanner().scan(str(xml_path))

    symlink_checks = [check for check in result.checks if check.name == "OpenVINO Weights Symlink Boundary Check"]
    assert result.success is False
    assert symlink_checks
    assert symlink_checks[0].severity == IssueSeverity.CRITICAL
    assert symlink_checks[0].details["resolved_path"] == str(escaped_weights.resolve())
    assert symlink_checks[0].details["model_directory"] == str(model_dir.resolve())
    assert "bin_size" not in result.metadata


def test_openvino_scanner_allows_bin_symlink_inside_model_dir(tmp_path: Path, requires_symlinks: None) -> None:
    xml_path = tmp_path / "model.xml"
    weights_dir = tmp_path / "weights"
    weights_dir.mkdir()
    target_weights = weights_dir / "model.bin"
    xml_path.write_text("<net version='10'></net>", encoding="utf-8")
    target_weights.write_bytes(b"\x00" * 12)
    (tmp_path / "model.bin").symlink_to(target_weights)

    result = OpenVinoScanner().scan(str(xml_path))

    assert result.success is True
    assert result.metadata["bin_size"] == target_weights.stat().st_size
    assert not any(check.name == "OpenVINO Weights Symlink Boundary Check" for check in result.checks)


def test_directory_scan_preserves_path_sensitive_symlink_checks(tmp_path: Path, requires_symlinks: None) -> None:
    safe_dir = tmp_path / "safe"
    escaped_dir = tmp_path / "escaped"
    outside_dir = tmp_path / "outside"
    safe_dir.mkdir()
    escaped_dir.mkdir()
    outside_dir.mkdir()

    xml_content = "<net version='10'></net>"
    safe_xml = safe_dir / "model.xml"
    escaped_xml = escaped_dir / "model.xml"
    safe_xml.write_text(xml_content, encoding="utf-8")
    escaped_xml.write_text(xml_content, encoding="utf-8")
    (safe_dir / "model.bin").write_bytes(b"safe")
    escaped_weights = outside_dir / "secret.bin"
    escaped_weights.write_bytes(b"secret")
    (escaped_dir / "model.bin").symlink_to(escaped_weights)

    result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False, skip_file_types=False)

    symlink_checks = [check for check in result.checks if check.name == "OpenVINO Weights Symlink Boundary Check"]
    assert determine_exit_code(result) == 1
    assert {check.location for check in symlink_checks} == {str(escaped_dir / "model.bin")}
    assert result.file_metadata[str(safe_xml)]["bin_size"] == 4
    assert "bin_size" not in result.file_metadata[str(escaped_xml)]


def test_openvino_scanner_forbidden_doctype_fails_closed_with_exit_2(tmp_path: Path) -> None:
    """Forbidden DOCTYPE payloads should produce an explicit OpenVINO parse failure and exit 2."""
    xml_path = tmp_path / "model.xml"
    xml_path.write_text(
        """<?xml version='1.0'?>
        <!DOCTYPE net [
          <!ENTITY payload SYSTEM 'file:///tmp/secret'>
        ]>
        <net version='10'><layers><layer id='0' name='data' type='Input' value='&payload;'/></layers></net>
        """,
        encoding="utf-8",
    )
    (tmp_path / "model.bin").write_bytes(b"\x00")

    result = OpenVinoScanner().scan(str(xml_path))
    cli_result = scan_model_directory_or_file(str(xml_path))

    assert result.success is False
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "openvino_xml_parse_failed"
    assert any(check.name == "OpenVINO XML Parse" for check in result.checks)
    assert determine_exit_code(cli_result) == 2


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


def test_openvino_scanner_detects_namespaced_custom_layer(tmp_path: Path) -> None:
    xml_path = tmp_path / "namespaced.xml"
    xml_path.write_text(
        """
        <net xmlns='urn:openvino-test' version='10'>
          <layers>
            <layer id='1' name='evil' type='Python' library='evil.so'/>
          </layers>
        </net>
        """,
        encoding="utf-8",
    )
    (tmp_path / "namespaced.bin").write_bytes(b"\x00")

    direct = OpenVinoScanner().scan(str(xml_path))
    aggregate = scan_model_directory_or_file(str(xml_path), cache_scan_results=False)

    assert OpenVinoScanner.can_handle(str(xml_path)) is True
    assert any(check.name == "Suspicious Layer Type Detection" for check in direct.checks)
    assert any(check.name == "External Library Reference Check" for check in direct.checks)
    assert determine_exit_code(aggregate) == 1


def test_openvino_scanner_allows_benign_namespaced_layer(tmp_path: Path) -> None:
    xml_path = tmp_path / "benign-namespaced.xml"
    xml_path.write_text(
        """
        <net xmlns='urn:openvino-test' version='10'>
          <layers>
            <layer id='0' name='data' type='Input'/>
          </layers>
        </net>
        """,
        encoding="utf-8",
    )
    (tmp_path / "benign-namespaced.bin").write_bytes(b"\x00")

    result = OpenVinoScanner().scan(str(xml_path))

    assert result.success is True
    assert not any(check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for check in result.checks)


def test_openvino_scanner_detects_layer_in_namespace_distinct_from_root(tmp_path: Path) -> None:
    xml_path = tmp_path / "mixed-namespaces.xml"
    xml_path.write_text(
        """
        <net xmlns:custom='urn:untrusted-layer' version='10'>
          <layers>
            <custom:layer id='1' name='evil' type='Python' library='evil.so'/>
          </layers>
        </net>
        """,
        encoding="utf-8",
    )
    (tmp_path / "mixed-namespaces.bin").write_bytes(b"\x00")

    result = OpenVinoScanner().scan(str(xml_path))

    assert any(check.name == "Suspicious Layer Type Detection" for check in result.checks)
    assert any(check.name == "External Library Reference Check" for check in result.checks)


def test_openvino_scanner_detects_mixed_case_namespaced_layer(tmp_path: Path) -> None:
    xml_path = tmp_path / "mixed-case-layer.xml"
    xml_path.write_text(
        """
        <net xmlns:custom='urn:untrusted-layer' version='10'>
          <layers>
            <custom:Layer id='1' name='evil' type='Python' library='evil.so'/>
          </layers>
        </net>
        """,
        encoding="utf-8",
    )
    (tmp_path / "mixed-case-layer.bin").write_bytes(b"\x00")

    result = OpenVinoScanner().scan(str(xml_path))

    assert any(check.name == "Suspicious Layer Type Detection" for check in result.checks)
    assert any(check.name == "External Library Reference Check" for check in result.checks)


def test_openvino_scanner_respects_configured_file_size_limit(tmp_path: Path) -> None:
    """scan() should fail closed before parsing XML that exceeds max_file_read_size."""
    xml_path = create_basic_model(tmp_path)

    result = OpenVinoScanner(config={"max_file_read_size": 8}).scan(str(xml_path))

    assert result.success is False
    assert any(check.name == "File Size Limit" for check in result.checks)


def test_openvino_scanner_oversize_weights_fail_closed(tmp_path: Path) -> None:
    """Direct XML scans must fail closed when bounded OpenVINO weights are skipped."""
    xml_path = create_basic_model(tmp_path)
    bin_path = tmp_path / "model.bin"
    max_file_size = xml_path.stat().st_size + 1
    bin_path.write_bytes(b"\x00" * (max_file_size + 1))

    direct_result = scan_file(
        str(xml_path),
        config={"max_file_size": max_file_size, "cache_enabled": False},
    )
    cli_result = scan_model_directory_or_file(
        str(xml_path),
        max_file_size=max_file_size,
        cache_enabled=False,
    )

    assert direct_result.success is False
    assert direct_result.metadata["operational_error"] is True
    assert direct_result.metadata["operational_error_reason"] == "openvino_weights_file_size_exceeded"
    assert any(
        check.name == "OpenVINO Weights File Size Limit"
        and check.details.get("scan_outcome_reason") == "openvino_weights_file_size_exceeded"
        for check in direct_result.checks
    )
    assert cli_result.has_errors is True
    assert determine_exit_code(cli_result) == 2


def test_openvino_scanner_sidecar_cache_rescans_changed_weights(tmp_path: Path) -> None:
    """OpenVINO XML cache entries must not hide changed same-stem weights metadata."""
    xml_path = create_basic_model(tmp_path)
    bin_path = tmp_path / "model.bin"
    cache_config = {
        "cache_enabled": True,
        "cache_dir": str(tmp_path / "cache"),
        "min_cache_file_size": 0,
    }

    first_result = scan_file(str(xml_path), config=cache_config)
    bin_path.write_bytes(b"\x01" * 32)
    second_result = scan_file(str(xml_path), config=cache_config)

    assert first_result.metadata["bin_size"] == 10
    assert second_result.metadata["bin_size"] == 32


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


def test_openvino_scanner_symbolic_implementation_metadata_is_not_external_library(tmp_path: Path) -> None:
    """OpenVINO backend labels should not be treated as native library references."""
    xml_path = tmp_path / "model.xml"
    xml_path.write_text(
        """
        <net version='10'>
          <layers>
            <layer id='1' name='conv' type='Convolution'>
              <data implementation='fp16' library='CPU'/>
            </layer>
          </layers>
        </net>
        """,
        encoding="utf-8",
    )
    (tmp_path / "model.bin").write_bytes(b"\x00")

    result = OpenVinoScanner().scan(str(xml_path))

    assert result.success is True
    assert not any(check.name == "External Library Reference Check" for check in result.checks)


def test_openvino_scanner_detects_versioned_native_library_reference(tmp_path: Path) -> None:
    """Native library filenames should still be treated as external references."""
    xml_path = tmp_path / "model.xml"
    xml_path.write_text(
        """
        <net version='10'>
          <layers>
            <layer id='1' name='conv' type='Convolution'>
              <data implementation='libcustom_op.so.1'/>
            </layer>
          </layers>
        </net>
        """,
        encoding="utf-8",
    )
    (tmp_path / "model.bin").write_bytes(b"\x00")

    result = OpenVinoScanner().scan(str(xml_path))

    assert result.success is False
    assert any("external library 'libcustom_op.so.1'" in issue.message for issue in result.issues)


def test_openvino_scanner_detects_path_external_library_reference(tmp_path: Path) -> None:
    """Path-like plugin references should still be treated as external libraries."""
    xml_path = tmp_path / "model.xml"
    xml_path.write_text(
        """
        <net version='10'>
          <layers>
            <layer id='1' name='conv' type='Convolution'>
              <data library='../plugins/custom_op'/>
            </layer>
          </layers>
        </net>
        """,
        encoding="utf-8",
    )
    (tmp_path / "model.bin").write_bytes(b"\x00")

    result = OpenVinoScanner().scan(str(xml_path))

    assert result.success is False
    assert any("external library '../plugins/custom_op'" in issue.message for issue in result.issues)


def test_openvino_scanner_redacts_external_library_url_secrets(tmp_path: Path) -> None:
    """External library URL evidence should not preserve credentials or signed query strings."""
    xml_path = tmp_path / "model.xml"
    raw_library_url = "https://user:secret-token@evil.example/plugin.so?access_token=abcd#fragment"
    xml_path.write_text(
        f"""
        <net version='10'>
          <layers>
            <layer id='1' name='conv' type='Convolution'>
              <data implementation='{raw_library_url}'/>
            </layer>
          </layers>
        </net>
        """,
        encoding="utf-8",
    )
    (tmp_path / "model.bin").write_bytes(b"\x00")

    result = OpenVinoScanner().scan(str(xml_path))

    library_checks = [check for check in result.checks if check.name == "External Library Reference Check"]
    assert library_checks
    assert library_checks[0].details["library"] == "https://evil.example/plugin.so"
    rendered_result = f"{[check.message for check in result.checks]} {result.metadata} {library_checks[0].details}"
    assert "https://evil.example/plugin.so" in rendered_result
    assert "secret-token" not in rendered_result
    assert "access_token=" not in rendered_result
    assert "user:secret-token" not in rendered_result
    assert "#fragment" not in rendered_result


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
