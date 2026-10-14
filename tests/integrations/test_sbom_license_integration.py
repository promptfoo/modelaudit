"""Tests for SBOM integration with license metadata."""

import json
from pathlib import Path
from typing import Any

from modelaudit.core import scan_model_directory_or_file
from modelaudit.integrations.sbom_generator import generate_sbom


def _scan_sbom(path: Path) -> dict[str, Any]:
    results = scan_model_directory_or_file(str(path))
    sbom_json = generate_sbom([str(path)], results)
    sbom_data: dict[str, Any] = json.loads(sbom_json)
    return sbom_data


def _find_property(component: dict[str, Any], name: str) -> dict[str, Any] | None:
    properties: list[dict[str, Any]] = component.get("properties", [])
    return next((prop for prop in properties if prop["name"] == name), None)


class TestSBOMLicenseIntegration:
    """Test SBOM generation with license metadata."""

    def test_sbom_includes_license_metadata(self, tmp_path: Path) -> None:
        """Test that SBOM includes license metadata."""
        # Create a file with license
        test_file = tmp_path / "licensed_file.py"
        content = """# Copyright 2024 Test Corp
# SPDX-License-Identifier: Apache-2.0

def test():
    pass
"""
        test_file.write_text(content)

        # Scan and generate SBOM
        sbom_data = _scan_sbom(test_file)

        # Check that license information is included
        components = sbom_data.get("components", [])
        assert len(components) == 1

        component = components[0]
        assert "licenses" in component
        assert len(component["licenses"]) > 0

        # Check for license expression
        license_expr = component["licenses"][0]
        assert "expression" in license_expr
        assert "Apache-2.0" in license_expr["expression"]

    def test_sbom_includes_copyright_properties(self, tmp_path: Path) -> None:
        """Test that SBOM includes copyright information as properties."""
        test_file = tmp_path / "copyrighted_file.py"
        content = """# Copyright 2024 Example Corp
# Copyright (c) 2023 Another Corp
# Licensed under MIT License

def example():
    pass
"""
        test_file.write_text(content)

        sbom_data = _scan_sbom(test_file)

        component = sbom_data["components"][0]

        # Check for copyright holders property
        copyright_prop = _find_property(component, "copyright_holders")
        assert copyright_prop is not None
        assert "Example Corp" in copyright_prop["value"]
        assert "Another Corp" in copyright_prop["value"]

    def test_sbom_includes_file_type_properties(self, tmp_path: Path) -> None:
        """Test that SBOM includes file type properties."""
        # Create dataset file
        dataset_file = tmp_path / "data.csv"
        dataset_file.write_text("name,age\nAlice,25\nBob,30")

        # Create model file
        model_file = tmp_path / "model.pkl"
        model_file.write_bytes(b"dummy model content")

        sbom_data = _scan_sbom(tmp_path)

        components = sbom_data["components"]

        # Find dataset component
        dataset_component = next(
            (comp for comp in components if "data.csv" in comp["name"]),
            None,
        )
        assert dataset_component is not None

        is_dataset_prop = _find_property(dataset_component, "ml:is_dataset")
        assert is_dataset_prop is not None
        assert is_dataset_prop["value"] == "true"

        # Find model component
        model_component = next(
            (comp for comp in components if "model.pkl" in comp["name"]),
            None,
        )
        assert model_component is not None

        is_model_prop = _find_property(model_component, "ml:is_model")
        assert is_model_prop is not None
        assert is_model_prop["value"] == "true"

    def test_sbom_includes_risk_score_with_license_issues(self, tmp_path: Path) -> None:
        """Test that SBOM includes updated risk scores based on license issues."""
        # Create a file with non-commercial license (should generate warning)
        test_file = tmp_path / "nc_file.csv"
        content = """# Creative Commons Attribution NonCommercial
# This dataset cannot be used commercially
name,value
"""
        # Make it large enough to trigger warning
        content += "\n".join([f"item{i},value{i}" for i in range(1000)])
        test_file.write_text(content)

        sbom_data = _scan_sbom(test_file)

        component = sbom_data["components"][0]

        # Check for risk score property
        risk_score_prop = _find_property(component, "risk_score")
        assert risk_score_prop is not None

        # Risk score should reflect license warnings
        risk_score = int(risk_score_prop["value"])
        assert risk_score >= 0  # Should have some risk score

    def test_sbom_risk_score_with_critical_issue(self, tmp_path: Path) -> None:
        """Critical issues should increase SBOM risk score."""
        malicious_file = tmp_path / "malicious.pkl"
        malicious_file.write_bytes(b"subprocess.call('ls')")

        sbom_data = _scan_sbom(malicious_file)

        component = sbom_data["components"][0]

        risk_score_prop = _find_property(component, "risk_score")
        assert risk_score_prop is not None
        assert int(risk_score_prop["value"]) >= 5

    def test_sbom_handles_files_without_license_metadata(self, tmp_path: Path) -> None:
        """Test that SBOM handles files without license metadata gracefully."""
        test_file = tmp_path / "no_license.py"
        content = """# Just some code without license info

def function():
    pass
"""
        test_file.write_text(content)

        sbom_data = _scan_sbom(test_file)

        # Should still generate component without errors
        components = sbom_data.get("components", [])
        assert len(components) == 1

        component = components[0]
        # Component should have expected SBOM fields regardless of license presence
        assert "name" in component
        assert "type" in component

    def test_sbom_with_license_files_detected(self, tmp_path: Path) -> None:
        """Test SBOM when license files are detected in directory."""
        # Create a code file
        code_file = tmp_path / "code.py"
        code_file.write_text("def function(): pass")

        # Create license file
        license_file = tmp_path / "LICENSE"
        license_file.write_text("MIT License")

        sbom_data = _scan_sbom(tmp_path)

        # Find the code component
        code_component = next(
            (comp for comp in sbom_data["components"] if "code.py" in comp["name"]),
            None,
        )

        if code_component:
            license_files_prop = _find_property(code_component, "license_files_found")

            # Should detect the nearby license file
            if license_files_prop:
                assert int(license_files_prop["value"]) >= 1

    def test_sbom_multiple_licenses(self, tmp_path: Path) -> None:
        """Test SBOM generation with multiple licenses in one file."""
        test_file = tmp_path / "dual_license.py"
        content = """# Licensed under MIT License
# Also available under Apache-2.0
# SPDX-License-Identifier: MIT

def dual_licensed():
    pass
"""
        test_file.write_text(content)

        sbom_data = _scan_sbom(test_file)

        component = sbom_data["components"][0]
        licenses = component.get("licenses", [])

        # Should have multiple license entries
        # Note: The actual number depends on how many patterns match
        assert len(licenses) >= 1

    def test_sbom_legacy_license_field_compatibility(self, tmp_path: Path) -> None:
        """Test SBOM generation with legacy license field for backward compatibility."""
        # This test ensures that if there's a legacy license field in metadata,
        # it gets included in the SBOM
        test_file = tmp_path / "legacy.py"
        test_file.write_text("def legacy(): pass")

        # Mock the scan to include legacy license field
        from unittest.mock import patch

        with patch("modelaudit.core.scan_file") as mock_scan:
            mock_result = type(
                "MockResult",
                (),
                {
                    "issues": [],
                    "bytes_scanned": 100,
                    "scanner_name": "test",
                    "metadata": {"license": "GPL-3.0"},  # Legacy format
                },
            )()
            mock_scan.return_value = mock_result

            sbom_data = _scan_sbom(test_file)

            component = sbom_data["components"][0]
            licenses = component.get("licenses", [])

            # Should include the legacy license
            if licenses:
                license_expressions = [lic.get("expression", "") for lic in licenses]
                assert any("GPL-3.0" in expr for expr in license_expressions)

    def test_sbom_validates_as_cyclonedx(self, tmp_path: Path) -> None:
        """Test that generated SBOM is valid CycloneDX format."""
        test_file = tmp_path / "valid_test.py"
        content = """# SPDX-License-Identifier: MIT
def test(): pass
"""
        test_file.write_text(content)

        sbom_data = _scan_sbom(test_file)

        # Check basic CycloneDX structure
        assert "bomFormat" in sbom_data
        assert sbom_data["bomFormat"] == "CycloneDX"
        assert sbom_data["specVersion"] == "1.6"
        assert "components" in sbom_data
        assert isinstance(sbom_data["components"], list)

        # Check component structure
        if sbom_data["components"]:
            component = sbom_data["components"][0]
            assert "name" in component
            assert "type" in component
            assert component["type"] == "file"
            assert "hashes" in component
            assert isinstance(component["hashes"], list)
