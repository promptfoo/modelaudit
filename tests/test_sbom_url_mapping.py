"""Tests for SBOM generation with URL-to-file path mapping."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from modelaudit.sbom import generate_sbom_with_path_mapping


def create_test_file(file_path: Path, content: bytes = b"test content") -> None:
    """Create a test file with specified content."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(content)


def create_test_results_dict(file_paths: list[str], issues: list[dict] = None) -> dict:
    """Create a mock results dictionary for testing."""
    if issues is None:
        issues = []
    
    file_metadata = {}
    for path in file_paths:
        if os.path.exists(path):
            file_metadata[path] = {
                "is_model": True,
                "file_size": os.path.getsize(path),
                "mime_type": "application/octet-stream"
            }
    
    return {
        "file_metadata": file_metadata,
        "issues": issues,
        "checks": []
    }


class TestSBOMURLMapping:
    """Test SBOM generation with URL-to-file path mapping."""
    
    def test_basic_path_mapping(self):
        """Test basic URL to file path mapping."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test file
            test_file = Path(temp_dir) / "model.bin" 
            create_test_file(test_file, b"fake model content")
            
            # Test data
            original_url = "hf://user/model/model.bin"
            actual_path = str(test_file)
            paths = [original_url]
            path_mappings = {original_url: actual_path}
            results_dict = create_test_results_dict([actual_path])
            
            # Generate SBOM
            sbom_json = generate_sbom_with_path_mapping(paths, results_dict, path_mappings)
            sbom = json.loads(sbom_json)
            
            # Verify SBOM structure
            assert "components" in sbom
            assert len(sbom["components"]) == 1
            
            component = sbom["components"][0]
            assert component["name"] == "model.bin"
            assert component["bom-ref"] == actual_path  # Should use actual path, not URL
            assert component["type"] == "machine-learning-model"
            assert "hashes" in component
            assert len(component["hashes"]) == 1
    
    def test_multiple_url_mappings(self):
        """Test SBOM generation with multiple URL mappings."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            model_file = Path(temp_dir) / "model.safetensors"
            config_file = Path(temp_dir) / "config.json"
            create_test_file(model_file, b"safetensors content")
            create_test_file(config_file, b'{"model_type": "llama"}')
            
            # Test data
            original_urls = [
                "hf://user/model/model.safetensors", 
                "hf://user/model/config.json"
            ]
            actual_paths = [str(model_file), str(config_file)]
            path_mappings = dict(zip(original_urls, actual_paths))
            results_dict = create_test_results_dict(actual_paths)
            
            # Generate SBOM
            sbom_json = generate_sbom_with_path_mapping(original_urls, results_dict, path_mappings)
            sbom = json.loads(sbom_json)
            
            # Verify SBOM structure
            assert len(sbom["components"]) == 2
            
            # Check both components use actual paths
            component_refs = {comp["bom-ref"] for comp in sbom["components"]}
            assert str(model_file) in component_refs
            assert str(config_file) in component_refs
            
            # Verify no URLs in bom-ref
            for comp in sbom["components"]:
                assert not comp["bom-ref"].startswith("hf://")
    
    def test_nonexistent_path_handling(self):
        """Test that nonexistent paths are skipped gracefully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create one real file
            real_file = Path(temp_dir) / "real.bin"
            create_test_file(real_file, b"real content")
            
            # Test data with one real and one fake path
            original_urls = [
                "hf://user/model/real.bin",
                "hf://user/model/nonexistent.bin"
            ]
            actual_paths = [str(real_file), "/fake/path/nonexistent.bin"]
            path_mappings = dict(zip(original_urls, actual_paths))
            results_dict = create_test_results_dict([str(real_file)])
            
            # Generate SBOM
            sbom_json = generate_sbom_with_path_mapping(original_urls, results_dict, path_mappings)
            sbom = json.loads(sbom_json)
            
            # Should only contain the real file
            assert len(sbom["components"]) == 1
            assert sbom["components"][0]["bom-ref"] == str(real_file)
    
    def test_no_path_mapping_fallback(self):
        """Test fallback to original path when no mapping exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test file
            test_file = Path(temp_dir) / "local.bin"
            create_test_file(test_file, b"local content")
            
            # Test with no path mappings (local file scenario)
            paths = [str(test_file)]
            path_mappings = {}  # Empty mappings
            results_dict = create_test_results_dict([str(test_file)])
            
            # Generate SBOM
            sbom_json = generate_sbom_with_path_mapping(paths, results_dict, path_mappings)
            sbom = json.loads(sbom_json)
            
            # Should work normally for local files
            assert len(sbom["components"]) == 1
            assert sbom["components"][0]["bom-ref"] == str(test_file)
    
    def test_issues_mapping_with_paths(self):
        """Test that issues are correctly mapped using both original and actual paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test file
            test_file = Path(temp_dir) / "risky.pkl"
            create_test_file(test_file, b"pickle content")
            
            # Test data with issues
            original_url = "hf://user/model/risky.pkl"
            actual_path = str(test_file)
            paths = [original_url]
            path_mappings = {original_url: actual_path}
            
            # Create issues that reference the actual path (as scanners would)
            issues = [
                {
                    "message": "Dangerous pickle detected",
                    "severity": "critical", 
                    "location": actual_path,
                    "type": "pickle_check"
                }
            ]
            results_dict = create_test_results_dict([actual_path], issues)
            
            # Generate SBOM
            sbom_json = generate_sbom_with_path_mapping(paths, results_dict, path_mappings)
            sbom = json.loads(sbom_json)
            
            # Verify issue is reflected in risk score
            component = sbom["components"][0]
            risk_score_prop = next(p for p in component["properties"] if p["name"] == "risk_score")
            assert int(risk_score_prop["value"]) > 0  # Should have risk due to critical issue
    
    def test_directory_mapping(self):
        """Test SBOM generation for directory mapping."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create directory structure
            model_dir = Path(temp_dir) / "downloaded_model"
            model_dir.mkdir()
            
            # Create files in directory
            model_file = model_dir / "pytorch_model.bin"
            config_file = model_dir / "config.json"
            create_test_file(model_file, b"pytorch model")
            create_test_file(config_file, b"config data")
            
            # Test directory mapping
            original_url = "hf://user/model"
            actual_path = str(model_dir)
            paths = [original_url]
            path_mappings = {original_url: actual_path}
            
            # Create metadata for files in directory
            file_paths = [str(model_file), str(config_file)]
            results_dict = create_test_results_dict(file_paths)
            
            # Generate SBOM
            sbom_json = generate_sbom_with_path_mapping(paths, results_dict, path_mappings)
            sbom = json.loads(sbom_json)
            
            # Should contain both files from directory
            assert len(sbom["components"]) == 2
            component_names = {comp["name"] for comp in sbom["components"]}
            assert "pytorch_model.bin" in component_names
            assert "config.json" in component_names
    
    def test_scanner_version_property(self):
        """Test that scanner version property is included."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test.bin"
            create_test_file(test_file, b"test")
            
            paths = [str(test_file)]
            path_mappings = {}
            results_dict = create_test_results_dict([str(test_file)])
            
            sbom_json = generate_sbom_with_path_mapping(paths, results_dict, path_mappings)
            sbom = json.loads(sbom_json)
            
            component = sbom["components"][0]
            scanner_version_prop = next(
                p for p in component["properties"] 
                if p["name"] == "security:scanner_version"
            )
            assert scanner_version_prop["value"].startswith("v")
            # Should be dynamic version from package
            assert "." in scanner_version_prop["value"]  # Contains version numbers
    
    def test_metadata_fallback_lookup(self):
        """Test that metadata lookup tries both original and actual paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "model.bin"
            create_test_file(test_file, b"model content")
            
            original_url = "hf://user/model/model.bin"
            actual_path = str(test_file)
            paths = [original_url]
            path_mappings = {original_url: actual_path}
            
            # Create results with metadata keyed by original URL
            results_dict = {
                "file_metadata": {
                    original_url: {  # Metadata keyed by original URL
                        "is_model": True,
                        "framework": "pytorch"
                    }
                },
                "issues": [],
                "checks": []
            }
            
            # Generate SBOM - should find metadata via fallback lookup
            sbom_json = generate_sbom_with_path_mapping(paths, results_dict, path_mappings)
            sbom = json.loads(sbom_json)
            
            # Should successfully generate component even with URL-keyed metadata
            assert len(sbom["components"]) == 1
            component = sbom["components"][0]
            assert component["name"] == "model.bin"
    
    def test_cyclone_dx_v16_format(self):
        """Test that generated SBOM uses CycloneDX v1.6 format."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "model.gguf"
            create_test_file(test_file, b"GGUF model")
            
            paths = [str(test_file)]
            path_mappings = {}
            results_dict = create_test_results_dict([str(test_file)])
            
            sbom_json = generate_sbom_with_path_mapping(paths, results_dict, path_mappings)
            sbom = json.loads(sbom_json)
            
            # Verify CycloneDX v1.6 format
            assert sbom["bomFormat"] == "CycloneDX"
            assert sbom["specVersion"] == "1.6" 
            assert sbom["$schema"] == "http://cyclonedx.org/schema/bom-1.6.schema.json"
            
            # Verify ML model component type (v1.6 feature)
            component = sbom["components"][0]
            assert component["type"] == "machine-learning-model"


@pytest.mark.integration
class TestSBOMURLMappingIntegration:
    """Integration tests for SBOM URL mapping with real scenarios."""
    
    def test_huggingface_like_scenario(self):
        """Test a scenario similar to real HuggingFace downloads."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Simulate HuggingFace cache structure
            cache_dir = Path(temp_dir) / ".modelaudit" / "cache" / "huggingface" / "user" / "model"
            cache_dir.mkdir(parents=True)
            
            # Create model files
            safetensors_file = cache_dir / "model.safetensors"
            config_file = cache_dir / "config.json"
            tokenizer_file = cache_dir / "tokenizer.json"
            
            create_test_file(safetensors_file, b"safetensors binary data")
            create_test_file(config_file, b'{"model_type": "llama", "hidden_size": 4096}')
            create_test_file(tokenizer_file, b'{"vocab_size": 32000}')
            
            # Simulate CLI path mappings 
            original_url = "hf://user/model"
            actual_path = str(cache_dir)
            paths = [original_url]
            path_mappings = {original_url: actual_path}
            
            # Create realistic metadata
            file_paths = [str(safetensors_file), str(config_file), str(tokenizer_file)]
            results_dict = {
                "file_metadata": {
                    str(safetensors_file): {
                        "is_model": True,
                        "ml_context": {"framework": "transformers", "model_type": "llama"},
                        "file_size": len(b"safetensors binary data")
                    },
                    str(config_file): {
                        "is_model": False,
                        "file_size": len(b'{"model_type": "llama", "hidden_size": 4096}')
                    },
                    str(tokenizer_file): {
                        "is_model": False, 
                        "file_size": len(b'{"vocab_size": 32000}')
                    }
                },
                "issues": [],
                "checks": []
            }
            
            # Generate SBOM
            sbom_json = generate_sbom_with_path_mapping(paths, results_dict, path_mappings)
            sbom = json.loads(sbom_json)
            
            # Verify realistic HF-like SBOM
            assert len(sbom["components"]) == 3
            
            # Check component types
            component_types = {comp["type"] for comp in sbom["components"]}
            assert "machine-learning-model" in component_types  # SafeTensors
            assert "data" in component_types  # Config files
            
            # Verify all paths are real file paths, not URLs
            for comp in sbom["components"]:
                assert comp["bom-ref"].startswith(str(cache_dir))
                assert not comp["bom-ref"].startswith("hf://")
                
            # Check ML-specific properties
            safetensors_comp = next(
                comp for comp in sbom["components"] 
                if comp["name"] == "model.safetensors"
            )
            ml_props = {p["name"]: p["value"] for p in safetensors_comp["properties"]}
            assert ml_props.get("ml:is_model") == "true"
            assert "ml:framework" in ml_props