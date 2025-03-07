import os
import pytest
from pathlib import Path
import struct

from modelaudit.scanners.keras_h5_scanner import KerasH5Scanner
from modelaudit.scanners.base import IssueSeverity

def test_keras_h5_scanner_can_handle():
    """Test the can_handle method of KerasH5Scanner."""
    assert KerasH5Scanner.can_handle("model.h5") is True
    assert KerasH5Scanner.can_handle("model.hdf5") is True
    assert KerasH5Scanner.can_handle("model.keras") is True
    assert KerasH5Scanner.can_handle("model.pkl") is False
    assert KerasH5Scanner.can_handle("model.pt") is False

def create_mock_h5_file(tmp_path, malicious=False):
    """Create a mock HDF5 file for testing."""
    # This creates a very simplified mock of an HDF5 file
    # Real HDF5 files have a complex format, but we just need the magic bytes
    # and some content for testing
    h5_path = tmp_path / "model.h5"
    
    with open(h5_path, "wb") as f:
        # Write HDF5 magic bytes
        f.write(b"\x89HDF\r\n\x1a\n")
        
        # Write some dummy content
        f.write(b"DUMMY HDF5 CONTENT")
        
        # If malicious, add some suspicious content
        if malicious:
            f.write(b"import os; os.system('rm -rf /')")
            f.write(b"eval('malicious code')")
    
    return h5_path

def test_keras_h5_scanner_safe_model(tmp_path):
    """Test scanning a safe Keras H5 model."""
    model_path = create_mock_h5_file(tmp_path)
    
    scanner = KerasH5Scanner()
    result = scanner.scan(str(model_path))
    
    assert result.success is True
    assert result.bytes_scanned > 0
    
    # Check for issues - a safe model might still have some informational issues
    error_issues = [issue for issue in result.issues 
                   if issue.severity == IssueSeverity.ERROR]
    assert len(error_issues) == 0

def test_keras_h5_scanner_malicious_model(tmp_path):
    """Test scanning a malicious Keras H5 model."""
    model_path = create_mock_h5_file(tmp_path, malicious=True)
    
    scanner = KerasH5Scanner()
    result = scanner.scan(str(model_path))
    
    # The scanner should detect suspicious patterns
    assert any(issue.severity == IssueSeverity.ERROR or 
              issue.severity == IssueSeverity.WARNING 
              for issue in result.issues)
    assert any("eval" in issue.message.lower() or
              "system" in issue.message.lower() or
              "suspicious" in issue.message.lower()
              for issue in result.issues)

def test_keras_h5_scanner_invalid_h5(tmp_path):
    """Test scanning an invalid H5 file."""
    # Create an invalid H5 file (without magic bytes)
    invalid_path = tmp_path / "invalid.h5"
    with open(invalid_path, "wb") as f:
        f.write(b"This is not a valid HDF5 file")
    
    scanner = KerasH5Scanner()
    result = scanner.scan(str(invalid_path))
    
    # Should have an error about invalid H5
    assert any(issue.severity == IssueSeverity.ERROR for issue in result.issues)
    assert any("invalid" in issue.message.lower() or 
              "not an hdf5" in issue.message.lower() or
              "error" in issue.message.lower() 
              for issue in result.issues)

def test_keras_h5_scanner_with_blacklist(tmp_path):
    """Test Keras H5 scanner with custom blacklist patterns."""
    # Create a file with content that matches our blacklist
    h5_path = tmp_path / "model.h5"
    
    with open(h5_path, "wb") as f:
        # Write HDF5 magic bytes
        f.write(b"\x89HDF\r\n\x1a\n")
        
        # Write content with suspicious pattern
        f.write(b"This contains suspicious_function")
    
    # Create scanner with custom blacklist
    scanner = KerasH5Scanner(config={"blacklist_patterns": ["suspicious_function"]})
    result = scanner.scan(str(h5_path))
    
    # Should detect our blacklisted pattern
    blacklist_issues = [issue for issue in result.issues 
                       if "suspicious_function" in issue.message.lower()]
    assert len(blacklist_issues) > 0

def test_keras_h5_scanner_empty_file(tmp_path):
    """Test scanning an empty file."""
    empty_path = tmp_path / "empty.h5"
    with open(empty_path, "wb") as f:
        pass  # Create empty file
    
    scanner = KerasH5Scanner()
    result = scanner.scan(str(empty_path))
    
    # Should have an error about invalid H5
    assert any(issue.severity == IssueSeverity.ERROR for issue in result.issues)
    assert any("empty" in issue.message.lower() or
              "invalid" in issue.message.lower() or
              "too small" in issue.message.lower()
              for issue in result.issues) 
