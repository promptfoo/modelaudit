import os
import zipfile
import pickle
import pytest
from pathlib import Path

from modelaudit.scanners.pytorch_zip_scanner import PyTorchZipScanner
from modelaudit.scanners.base import IssueSeverity

def test_pytorch_zip_scanner_can_handle():
    """Test the can_handle method of PyTorchZipScanner."""
    assert PyTorchZipScanner.can_handle("model.pt") is True
    assert PyTorchZipScanner.can_handle("model.pth") is True
    assert PyTorchZipScanner.can_handle("model.pkl") is False
    assert PyTorchZipScanner.can_handle("model.h5") is False

def create_pytorch_zip(tmp_path, malicious=False):
    """Create a mock PyTorch ZIP file for testing."""
    # Create a ZIP file that mimics a PyTorch model
    zip_path = tmp_path / "model.pt"
    
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        # Add a version file
        zipf.writestr("version", "3")
        
        # Add a data.pkl file
        data = {"weights": [1, 2, 3], "bias": [0.1, 0.2]}
        
        if malicious:
            # Add a malicious class
            class MaliciousClass:
                def __reduce__(self):
                    return (eval, ("print('malicious code')",))
            
            data["malicious"] = MaliciousClass()
        
        # Pickle the data
        pickled_data = pickle.dumps(data)
        zipf.writestr("data.pkl", pickled_data)
        
        # Add some other files
        zipf.writestr("model.json", '{"name": "test_model"}')
    
    return zip_path

def test_pytorch_zip_scanner_safe_model(tmp_path):
    """Test scanning a safe PyTorch ZIP model."""
    model_path = create_pytorch_zip(tmp_path)
    
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))
    
    assert result.success is True
    assert result.bytes_scanned > 0
    
    # Check for issues - a safe model might still have some informational issues
    error_issues = [issue for issue in result.issues 
                   if issue.severity == IssueSeverity.ERROR]
    assert len(error_issues) == 0

def test_pytorch_zip_scanner_malicious_model(tmp_path):
    """Test scanning a malicious PyTorch ZIP model."""
    model_path = create_pytorch_zip(tmp_path, malicious=True)
    
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))
    
    # The scanner should detect the eval function in the pickle
    assert any(issue.severity == IssueSeverity.ERROR for issue in result.issues)
    assert any("eval" in issue.message.lower() for issue in result.issues)

def test_pytorch_zip_scanner_invalid_zip(tmp_path):
    """Test scanning an invalid ZIP file."""
    # Create an invalid ZIP file
    invalid_path = tmp_path / "invalid.pt"
    with open(invalid_path, "wb") as f:
        f.write(b"This is not a valid ZIP file")
    
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(invalid_path))
    
    # Should have an error about invalid ZIP
    assert any(issue.severity == IssueSeverity.ERROR for issue in result.issues)
    assert any("invalid" in issue.message.lower() or 
              "corrupt" in issue.message.lower() or
              "error" in issue.message.lower() 
              for issue in result.issues)

def test_pytorch_zip_scanner_missing_data_pkl(tmp_path):
    """Test scanning a PyTorch ZIP file without data.pkl."""
    # Create a ZIP file without data.pkl
    zip_path = tmp_path / "model.pt"
    
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("model.json", '{"name": "test_model"}')
    
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))
    
    # Should have a warning about missing data.pkl
    assert any("data.pkl" in issue.message for issue in result.issues)

def test_pytorch_zip_scanner_with_blacklist(tmp_path):
    """Test PyTorch ZIP scanner with custom blacklist patterns."""
    # Create a ZIP file with content that matches our blacklist
    zip_path = tmp_path / "model.pt"
    
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        zipf.writestr("version", "3")
        
        # Create data with a function name that will match our blacklist
        data = {"weights": [1, 2, 3], "custom_function": lambda x: x}
        pickled_data = pickle.dumps(data)
        zipf.writestr("data.pkl", pickled_data)
    
    # Create scanner with custom blacklist
    scanner = PyTorchZipScanner(config={"blacklist_patterns": ["custom_function"]})
    result = scanner.scan(str(zip_path))
    
    # Should detect our blacklisted function
    blacklist_issues = [issue for issue in result.issues 
                       if "custom_function" in issue.message.lower()]
    assert len(blacklist_issues) > 0 
