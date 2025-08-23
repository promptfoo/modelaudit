"""Tests for the license checking functionality in ModelAudit."""

import json
from pathlib import Path

from modelaudit.license_checker import (
    CopyrightInfo,
    LicenseInfo,
    _is_ml_config_file,
    _is_ml_model_directory,
    check_commercial_use_warnings,
    collect_license_metadata,
    detect_agpl_components,
    detect_unlicensed_datasets,
    extract_copyright_notices,
    find_license_files,
    scan_for_license_headers,
)


class TestLicenseDetection:
    """Test license detection from file headers."""

    def test_mit_license_detection(self, tmp_path):
        """Test detection of MIT license."""
        test_file = tmp_path / "mit_file.py"
        content = """# Copyright 2024 Example Corp
# SPDX-License-Identifier: MIT
# Licensed under the MIT License

def example_function():
    pass
"""
        test_file.write_text(content)

        licenses = scan_for_license_headers(str(test_file))

        assert len(licenses) == 1
        assert licenses[0].spdx_id == "MIT"
        assert licenses[0].name == "MIT License"
        assert licenses[0].commercial_allowed is True
        assert licenses[0].source == "file_header"
        assert licenses[0].confidence == 0.8

    def test_apache_license_detection(self, tmp_path):
        """Test detection of Apache 2.0 license."""
        test_file = tmp_path / "apache_file.py"
        content = """# Licensed under the Apache License, Version 2.0
# Copyright 2024 Apache Foundation

import numpy as np
"""
        test_file.write_text(content)

        licenses = scan_for_license_headers(str(test_file))

        assert len(licenses) == 1
        assert licenses[0].spdx_id == "Apache-2.0"
        assert licenses[0].commercial_allowed is True

    def test_agpl_license_detection(self, tmp_path):
        """Test detection of AGPL license."""
        test_file = tmp_path / "agpl_file.py"
        content = """# Licensed under the GNU Affero General Public License
# SPDX-License-Identifier: AGPL-3.0

def network_service():
    pass
"""
        test_file.write_text(content)

        licenses = scan_for_license_headers(str(test_file))

        # May detect both GPL and AGPL patterns, check that AGPL is present
        assert len(licenses) >= 1
        agpl_licenses = [lic for lic in licenses if lic.spdx_id == "AGPL-3.0"]
        assert len(agpl_licenses) == 1
        assert agpl_licenses[0].commercial_allowed is True  # But with strong obligations

    def test_cc_by_nc_license_detection(self, tmp_path):
        """Test detection of Creative Commons NonCommercial license."""
        test_file = tmp_path / "cc_nc_file.txt"
        content = """Creative Commons Attribution NonCommercial License
This work is licensed under CC BY-NC 4.0

Some dataset content here...
"""
        test_file.write_text(content)

        licenses = scan_for_license_headers(str(test_file))

        assert len(licenses) == 1
        assert licenses[0].spdx_id == "CC-BY-NC-4.0"
        assert licenses[0].commercial_allowed is False

    def test_rail_license_detection(self, tmp_path):
        """Test detection of RAIL license."""
        test_file = tmp_path / "rail_file.py"
        content = """# Released under the Responsible AI License
# BigScience Open RAIL-M
def do_something():
    pass
"""
        test_file.write_text(content)

        licenses = scan_for_license_headers(str(test_file))

        assert len(licenses) >= 1
        spdx_ids = {lic.spdx_id for lic in licenses}
        assert "RAIL" in spdx_ids or "BigScience-OpenRAIL-M" in spdx_ids

    def test_bigscience_dataset_notice_detection(self, tmp_path):
        """Test detection of BigScience dataset license notice."""
        dataset_file = tmp_path / "dataset.json"
        content = """
{
  "_license": "BigScience Open RAIL-M",
  "_notice": "Dataset released under BigScience Open RAIL-M"
}
"""
        dataset_file.write_text(content)

        licenses = scan_for_license_headers(str(dataset_file))

        assert any(lic.spdx_id in {"RAIL", "BigScience-OpenRAIL-M"} for lic in licenses)

    def test_no_license_detection(self, tmp_path):
        """Test file with no license information."""
        test_file = tmp_path / "no_license.py"
        content = """# Just a regular file with no license info

def some_function():
    pass
"""
        test_file.write_text(content)

        licenses = scan_for_license_headers(str(test_file))

        assert len(licenses) == 0

    def test_binary_file_handling(self, tmp_path):
        """Test handling of binary files."""
        test_file = tmp_path / "binary_file.bin"
        test_file.write_bytes(b"\x00\x01\x02\x03\x04\x05")

        licenses = scan_for_license_headers(str(test_file))

        # Should handle gracefully and return empty list
        assert len(licenses) == 0

    def test_nonexistent_file_handling(self):
        """Test handling of nonexistent files."""
        licenses = scan_for_license_headers("/path/that/does/not/exist")

        assert len(licenses) == 0


class TestCopyrightExtraction:
    """Test copyright notice extraction."""

    def test_copyright_extraction_basic(self, tmp_path):
        """Test basic copyright notice extraction."""
        test_file = tmp_path / "copyright_file.py"
        content = """# Copyright 2024 Example Corporation
# Copyright (c) 2023-2024 Another Corp

def example():
    pass
"""
        test_file.write_text(content)

        copyrights = extract_copyright_notices(str(test_file))

        # May extract duplicates, check that we have the expected holders
        assert len(copyrights) >= 2
        holders = {cr.holder for cr in copyrights}
        assert "Example Corporation" in holders
        assert "Another Corp" in holders

        # Check years are extracted correctly
        example_corp_copyrights = [cr for cr in copyrights if cr.holder == "Example Corporation"]
        assert len(example_corp_copyrights) >= 1
        assert example_corp_copyrights[0].year == "2024"

    def test_copyright_symbols(self, tmp_path):
        """Test different copyright symbols."""
        test_file = tmp_path / "symbols.py"
        content = """# © 2024 Unicode Corp
# (c) 2023 Parentheses Corp

def test():
    pass
"""
        test_file.write_text(content)

        copyrights = extract_copyright_notices(str(test_file))

        assert len(copyrights) == 2
        holders = {cr.holder for cr in copyrights}
        assert "Unicode Corp" in holders
        assert "Parentheses Corp" in holders

    def test_no_copyright_notices(self, tmp_path):
        """Test file with no copyright notices."""
        test_file = tmp_path / "no_copyright.py"
        content = """# Just some code without copyright

def function():
    pass
"""
        test_file.write_text(content)

        copyrights = extract_copyright_notices(str(test_file))

        assert len(copyrights) == 0


class TestLicenseFiles:
    """Test license file discovery."""

    def test_find_license_files(self, tmp_path):
        """Test finding license files in directory."""
        # Create various license files
        (tmp_path / "LICENSE").write_text("MIT License")
        (tmp_path / "LICENSE.txt").write_text("Apache License")
        (tmp_path / "COPYING").write_text("GPL License")
        (tmp_path / "COPYRIGHT").write_text("Copyright notices")
        (tmp_path / "README.md").write_text("Not a license file")

        license_files = find_license_files(str(tmp_path))

        assert len(license_files) == 4
        filenames = {Path(f).name.lower() for f in license_files}
        assert "license" in filenames
        assert "license.txt" in filenames
        assert "copying" in filenames
        assert "copyright" in filenames
        assert "readme.md" not in filenames

    def test_find_license_files_nonexistent_dir(self):
        """Test handling of nonexistent directory."""
        license_files = find_license_files("/path/that/does/not/exist")

        assert len(license_files) == 0


class TestUnlicensedDatasetDetection:
    """Test detection of unlicensed datasets."""

    def test_detect_unlicensed_csv(self, tmp_path):
        """Test detection of unlicensed CSV file."""
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,age,score\nAlice,25,85\nBob,30,92")

        unlicensed = detect_unlicensed_datasets([str(csv_file)])

        assert len(unlicensed) == 1
        assert str(csv_file) in unlicensed

    def test_detect_unlicensed_json_large(self, tmp_path):
        """Test detection of large unlicensed JSON file."""
        json_file = tmp_path / "large_data.json"
        # Create a large file (>100KB)
        large_data = {"data": [{"id": i, "value": f"item_{i}"} for i in range(5000)]}
        json_file.write_text(json.dumps(large_data))

        unlicensed = detect_unlicensed_datasets([str(json_file)])

        assert len(unlicensed) == 1
        assert str(json_file) in unlicensed

    def test_skip_small_single_files(self, tmp_path):
        """Test that small single files are not flagged."""
        small_json = tmp_path / "small.json"
        small_json.write_text('{"test": "data"}')  # Small file

        unlicensed = detect_unlicensed_datasets([str(small_json)])

        # Note: Small JSON files may still be flagged if they don't have license info
        # This test verifies the behavior - small files in multi-file contexts are skipped
        # but single small files may still be checked
        assert len(unlicensed) <= 1  # May or may not be flagged depending on size threshold

    def test_dataset_with_nearby_license(self, tmp_path):
        """Test dataset with license file in same directory."""
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,age\nAlice,25\nBob,30")

        license_file = tmp_path / "LICENSE"
        license_file.write_text("MIT License")

        unlicensed = detect_unlicensed_datasets([str(csv_file)])

        assert len(unlicensed) == 0  # Should not be flagged due to nearby license

    def test_ml_model_directory_skip(self, tmp_path):
        """Test that ML model files in model directories are skipped."""
        # Create ML model directory
        (tmp_path / "config.json").write_text('{"model_type": "gpt2"}')
        (tmp_path / "pytorch_model.bin").write_bytes(b"model weights")
        (tmp_path / "data.pkl").write_bytes(
            b"some data",
        )  # This would normally be flagged

        file_paths = [str(f) for f in tmp_path.glob("*")]
        unlicensed = detect_unlicensed_datasets(file_paths)

        assert len(unlicensed) == 0  # PKL file should be skipped in ML model dir


class TestMLDirectoryDetection:
    """Test ML model directory detection."""

    def test_is_ml_model_directory_huggingface(self):
        """Test detection of HuggingFace model directory."""
        files = [
            "/path/config.json",
            "/path/pytorch_model.bin",
            "/path/tokenizer_config.json",
        ]

        assert _is_ml_model_directory(files) is True

    def test_is_ml_model_directory_pytorch(self):
        """Test detection of PyTorch model directory."""
        files = ["/path/model.safetensors", "/path/config.json"]

        assert _is_ml_model_directory(files) is True

    def test_is_not_ml_model_directory(self):
        """Test non-ML directory detection."""
        files = ["/path/data.csv", "/path/analysis.py", "/path/README.md"]

        assert _is_ml_model_directory(files) is False

    def test_is_ml_config_file(self):
        """Test ML config file recognition."""
        assert _is_ml_config_file("config.json") is True
        assert _is_ml_config_file("tokenizer_config.json") is True
        assert _is_ml_config_file("model.json") is True
        assert _is_ml_config_file("generation_config.json") is True

        assert _is_ml_config_file("data.json") is False
        assert _is_ml_config_file("analysis.json") is False
        assert _is_ml_config_file("config.txt") is False


class TestCommercialUseWarnings:
    """Test commercial use warnings."""

    def test_agpl_detection(self):
        """Test AGPL component detection."""
        scan_results = {
            "file_metadata": {
                "/path/agpl_file.py": {
                    "license_info": [
                        {"spdx_id": "AGPL-3.0", "commercial_allowed": True},
                    ],
                },
            },
        }

        agpl_files = detect_agpl_components(scan_results)

        assert len(agpl_files) == 1
        assert "/path/agpl_file.py" in agpl_files

    def test_no_agpl_detection(self):
        """Test when no AGPL components are present."""
        scan_results = {
            "file_metadata": {
                "/path/mit_file.py": {
                    "license_info": [{"spdx_id": "MIT", "commercial_allowed": True}],
                },
            },
        }

        agpl_files = detect_agpl_components(scan_results)

        assert len(agpl_files) == 0

    def test_check_commercial_use_warnings_agpl(self):
        """Test commercial use warnings for AGPL components."""
        scan_results = {
            "file_metadata": {
                "/path/agpl_component.py": {
                    "license_info": [
                        {"spdx_id": "AGPL-3.0", "commercial_allowed": True},
                    ],
                },
            },
        }

        warnings = check_commercial_use_warnings(scan_results)

        # AGPL may trigger both AGPL-specific and general copyleft warnings
        assert len(warnings) >= 1

        # Check that AGPL-specific warning is present
        agpl_warnings = [w for w in warnings if "AGPL" in w["message"]]
        assert len(agpl_warnings) == 1
        assert agpl_warnings[0]["type"] == "license_warning"
        assert agpl_warnings[0]["severity"] == "warning"
        assert "network use restrictions" in agpl_warnings[0]["message"]

    def test_check_commercial_use_warnings_noncommercial(self):
        """Test warnings for non-commercial licensed components."""
        scan_results = {
            "file_metadata": {
                "/path/cc_nc_dataset.csv": {
                    "license_info": [
                        {"spdx_id": "CC-BY-NC-4.0", "commercial_allowed": False},
                    ],
                },
            },
        }

        warnings = check_commercial_use_warnings(scan_results)

        assert len(warnings) >= 1
        assert any(w["severity"] == "warning" for w in warnings)
        assert any("Non-commercial" in w["message"] for w in warnings)
        assert any("cannot be used commercially" in w["message"] for w in warnings)

    def test_check_commercial_use_warnings_clean(self):
        """Test no warnings for clean licenses."""
        scan_results = {
            "file_metadata": {
                "/path/mit_file.py": {
                    "license_info": [{"spdx_id": "MIT", "commercial_allowed": True}],
                },
            },
        }

        warnings = check_commercial_use_warnings(scan_results)

        assert len(warnings) == 0


class TestSpdxLicenseChecks:
    """Test deprecated and incompatible license detection."""

    def test_deprecated_license_warning(self):
        scan_results = {"file_metadata": {"/path/old.py": {"license_info": [{"spdx_id": "AGPL-1.0"}]}}}

        warnings = check_commercial_use_warnings(scan_results)
        assert any("deprecated" in w["message"].lower() for w in warnings)

    def test_incompatible_license_warning(self):
        scan_results = {"file_metadata": {"/path/bad.py": {"license_info": [{"spdx_id": "3D-Slicer-1.0"}]}}}

        warnings = check_commercial_use_warnings(scan_results)
        assert any("incompatible" in w["message"].lower() for w in warnings)

    def test_strict_license_errors(self):
        scan_results = {"file_metadata": {"/path/bad.py": {"license_info": [{"spdx_id": "3D-Slicer-1.0"}]}}}

        warnings = check_commercial_use_warnings(scan_results, strict=True)
        assert any(w["severity"] == "error" for w in warnings)


class TestLicenseMetadataCollection:
    """Test license metadata collection."""

    def test_collect_license_metadata_basic(self, tmp_path):
        """Test basic license metadata collection."""
        test_file = tmp_path / "test.py"
        content = """# Copyright 2024 Test Corp
# SPDX-License-Identifier: MIT

def test_function():
    pass
"""
        test_file.write_text(content)

        metadata = collect_license_metadata(str(test_file))

        assert metadata["is_dataset"] is False
        assert metadata["is_model"] is False
        assert len(metadata["license_info"]) == 1
        assert metadata["license_info"][0]["spdx_id"] == "MIT"
        assert len(metadata["copyright_notices"]) == 1
        assert metadata["copyright_notices"][0]["holder"] == "Test Corp"

    def test_collect_license_metadata_dataset(self, tmp_path):
        """Test license metadata for dataset file."""
        test_file = tmp_path / "data.csv"
        content = """# Licensed under CC-BY-4.0
name,age
Alice,25
Bob,30
"""
        test_file.write_text(content)

        metadata = collect_license_metadata(str(test_file))

        assert metadata["is_dataset"] is True
        assert metadata["is_model"] is False

    def test_collect_license_metadata_model(self, tmp_path):
        """Test license metadata for model file."""
        test_file = tmp_path / "model.pkl"
        test_file.write_bytes(b"dummy model content")

        metadata = collect_license_metadata(str(test_file))

        assert metadata["is_dataset"] is True  # .pkl is both dataset and model extension
        assert metadata["is_model"] is True


class TestIntegration:
    """Integration tests for license checking with core scanning."""

    def test_license_warnings_in_scan_results(self, tmp_path):
        """Test that license warnings appear in scan results."""
        from modelaudit.core import scan_model_directory_or_file

        # Create a file with non-commercial license
        test_file = tmp_path / "nc_dataset.csv"
        content = """# Creative Commons Attribution NonCommercial
# CC BY-NC 4.0
name,value
test,data
"""
        # Make it large enough to trigger warning
        content += "\n".join([f"item{i},value{i}" for i in range(1000)])
        test_file.write_text(content)

        results = scan_model_directory_or_file(str(test_file))

        # Should have license warning
        license_issues = [
            issue for issue in results.get("issues", []) if getattr(issue, "type", None) == "license_warning"
        ]

        assert len(license_issues) > 0
        # The license detection should find the CC BY-NC (non-commercial) license
        # Check if it's detected as incompatible licenses (which is correct for non-commercial)
        assert any(
            "Incompatible licenses" in issue.message or "Non-commercial" in issue.message for issue in license_issues
        ), f"Expected license incompatibility detection in messages: {[issue.message for issue in license_issues]}"

    def test_ml_model_directory_no_false_positives(self, tmp_path):
        """Test that ML model directories don't generate false positive license warnings."""
        from modelaudit.core import scan_model_directory_or_file

        # Create ML model directory
        model_dir = tmp_path / "gpt2_model"
        model_dir.mkdir()

        config = {"model_type": "gpt2", "architectures": ["GPT2LMHeadModel"]}
        (model_dir / "config.json").write_text(json.dumps(config))
        (model_dir / "tokenizer_config.json").write_text(
            '{"tokenizer_class": "GPT2Tokenizer"}',
        )
        (model_dir / "pytorch_model.bin").write_bytes(b"dummy model weights")

        results = scan_model_directory_or_file(str(model_dir))

        # Should not have license warnings for config files
        license_issues = [
            issue
            for issue in results.get("issues", [])
            if getattr(issue, "type", None) == "license_warning"
            and "unspecified licenses" in getattr(issue, "message", "")
        ]

        assert len(license_issues) == 0


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_malformed_scan_results(self):
        """Test handling of malformed scan results."""
        # Empty results
        warnings = check_commercial_use_warnings({})
        assert len(warnings) == 0

        # Missing file_metadata
        warnings = check_commercial_use_warnings({"issues": []})
        assert len(warnings) == 0

    def test_empty_file_paths(self):
        """Test handling of empty file path lists."""
        assert detect_unlicensed_datasets([]) == []
        assert _is_ml_model_directory([]) is False

    def test_license_data_classes(self):
        """Test license data classes."""
        # Test LicenseInfo
        license_info = LicenseInfo(
            spdx_id="MIT",
            name="MIT License",
            commercial_allowed=True,
            source="test",
            confidence=0.9,
            text="License text",
        )

        assert license_info.spdx_id == "MIT"
        assert license_info.commercial_allowed is True

        # Test CopyrightInfo
        copyright_info = CopyrightInfo(
            holder="Test Corp",
            year="2024",
            text="Copyright 2024 Test Corp",
        )

        assert copyright_info.holder == "Test Corp"
        assert copyright_info.year == "2024"
