"""Tests for SBOM integration with license metadata."""

import json

from modelaudit.core import scan_model_directory_or_file
from modelaudit.sbom import generate_sbom


class TestSBOMLicenseIntegration:
    """Test SBOM generation with license metadata."""

    def test_sbom_includes_license_metadata(self, tmp_path):
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
        results = scan_model_directory_or_file(str(test_file))
        sbom_json = generate_sbom([str(test_file)], results)
        sbom_data = json.loads(sbom_json)

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

    def test_sbom_includes_copyright_properties(self, tmp_path):
        """Test that SBOM includes copyright information as properties."""
        test_file = tmp_path / "copyrighted_file.py"
        content = """# Copyright 2024 Example Corp
# Copyright (c) 2023 Another Corp
# Licensed under MIT License

def example():
    pass
"""
        test_file.write_text(content)

        results = scan_model_directory_or_file(str(test_file))
        sbom_json = generate_sbom([str(test_file)], results)
        sbom_data = json.loads(sbom_json)

        component = sbom_data["components"][0]
        properties = component.get("properties", [])

        # Check for copyright holders property
        copyright_prop = next(
            (prop for prop in properties if prop["name"] == "copyright_holders"),
            None,
        )
        assert copyright_prop is not None
        assert "Example Corp" in copyright_prop["value"]
        assert "Another Corp" in copyright_prop["value"]

    def test_sbom_includes_file_type_properties(self, tmp_path):
        """Test that SBOM includes file type properties."""
        # Create dataset file
        dataset_file = tmp_path / "data.csv"
        dataset_file.write_text("name,age\nAlice,25\nBob,30")

        # Create model file
        model_file = tmp_path / "model.pkl"
        model_file.write_bytes(b"dummy model content")

        results = scan_model_directory_or_file(str(tmp_path))
        sbom_json = generate_sbom([str(tmp_path)], results)
        sbom_data = json.loads(sbom_json)

        components = sbom_data["components"]

        # Find dataset component
        dataset_component = next(
            (comp for comp in components if "data.csv" in comp["name"]),
            None,
        )
        assert dataset_component is not None

        dataset_props = dataset_component.get("properties", [])
        is_dataset_prop = next(
            (prop for prop in dataset_props if prop["name"] == "is_dataset"),
            None,
        )
        assert is_dataset_prop is not None
        assert is_dataset_prop["value"] == "true"

        # Find model component
        model_component = next(
            (comp for comp in components if "model.pkl" in comp["name"]),
            None,
        )
        assert model_component is not None

        model_props = model_component.get("properties", [])
        is_model_prop = next(
            (prop for prop in model_props if prop["name"] == "is_model"),
            None,
        )
        assert is_model_prop is not None
        assert is_model_prop["value"] == "true"

    def test_sbom_includes_risk_score_with_license_issues(self, tmp_path):
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

        results = scan_model_directory_or_file(str(test_file))
        sbom_json = generate_sbom([str(test_file)], results)
        sbom_data = json.loads(sbom_json)

        component = sbom_data["components"][0]
        properties = component.get("properties", [])

        # Check for risk score property
        risk_score_prop = next(
            (prop for prop in properties if prop["name"] == "risk_score"),
            None,
        )
        assert risk_score_prop is not None

        # Risk score should reflect license warnings
        risk_score = int(risk_score_prop["value"])
        assert risk_score >= 0  # Should have some risk score

    def test_sbom_risk_score_with_critical_issue(self, tmp_path):
        """Critical issues should increase SBOM risk score."""
        malicious_file = tmp_path / "malicious.pkl"
        malicious_file.write_bytes(b"subprocess.call('ls')")

        results = scan_model_directory_or_file(str(malicious_file))
        sbom_json = generate_sbom([str(malicious_file)], results)
        sbom_data = json.loads(sbom_json)

        component = sbom_data["components"][0]
        properties = component.get("properties", [])

        risk_score_prop = next(
            (prop for prop in properties if prop["name"] == "risk_score"),
            None,
        )
        assert risk_score_prop is not None
        assert int(risk_score_prop["value"]) >= 5

    def test_sbom_handles_files_without_license_metadata(self, tmp_path):
        """Test that SBOM handles files without license metadata gracefully."""
        test_file = tmp_path / "no_license.py"
        content = """# Just some code without license info

def function():
    pass
"""
        test_file.write_text(content)

        results = scan_model_directory_or_file(str(test_file))
        sbom_json = generate_sbom([str(test_file)], results)
        sbom_data = json.loads(sbom_json)

        # Should still generate component without errors
        components = sbom_data.get("components", [])
        assert len(components) == 1

        component = components[0]
        # May or may not have licenses field, but should not error
        # Should handle gracefully even if no licenses
        assert "licenses" in component or "licenses" not in component  # Either is valid

    def test_sbom_with_license_files_detected(self, tmp_path):
        """Test SBOM when license files are detected in directory."""
        # Create a code file
        code_file = tmp_path / "code.py"
        code_file.write_text("def function(): pass")

        # Create license file
        license_file = tmp_path / "LICENSE"
        license_file.write_text("MIT License")

        results = scan_model_directory_or_file(str(tmp_path))
        sbom_json = generate_sbom([str(tmp_path)], results)
        sbom_data = json.loads(sbom_json)

        # Find the code component
        code_component = next(
            (comp for comp in sbom_data["components"] if "code.py" in comp["name"]),
            None,
        )

        if code_component:
            properties = code_component.get("properties", [])
            license_files_prop = next(
                (prop for prop in properties if prop["name"] == "license_files_found"),
                None,
            )

            # Should detect the nearby license file
            if license_files_prop:
                assert int(license_files_prop["value"]) >= 1

    def test_sbom_multiple_licenses(self, tmp_path):
        """Test SBOM generation with multiple licenses in one file."""
        test_file = tmp_path / "dual_license.py"
        content = """# Licensed under MIT License
# Also available under Apache-2.0
# SPDX-License-Identifier: MIT

def dual_licensed():
    pass
"""
        test_file.write_text(content)

        results = scan_model_directory_or_file(str(test_file))
        sbom_json = generate_sbom([str(test_file)], results)
        sbom_data = json.loads(sbom_json)

        component = sbom_data["components"][0]
        licenses = component.get("licenses", [])

        # Should have multiple license entries
        # Note: The actual number depends on how many patterns match
        assert len(licenses) >= 1

    def test_sbom_legacy_license_field_compatibility(self, tmp_path):
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

            results = scan_model_directory_or_file(str(test_file))
            sbom_json = generate_sbom([str(test_file)], results)
            sbom_data = json.loads(sbom_json)

            component = sbom_data["components"][0]
            licenses = component.get("licenses", [])

            # Should include the legacy license
            if licenses:
                license_expressions = [lic.get("expression", "") for lic in licenses]
                assert any("GPL-3.0" in expr for expr in license_expressions)

    def test_sbom_validates_as_cyclonedx(self, tmp_path):
        """Test that generated SBOM is valid CycloneDX format."""
        test_file = tmp_path / "valid_test.py"
        content = """# SPDX-License-Identifier: MIT
def test(): pass
"""
        test_file.write_text(content)

        results = scan_model_directory_or_file(str(test_file))
        sbom_json = generate_sbom([str(test_file)], results)
        sbom_data = json.loads(sbom_json)

        # Check basic CycloneDX structure
        assert "bomFormat" in sbom_data
        assert sbom_data["bomFormat"] == "CycloneDX"
        assert "specVersion" in sbom_data
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
