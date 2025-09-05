#!/usr/bin/env python3

# Minimal test to debug the hanging issue
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from modelaudit.cli import cli

def create_mock_scan_result(bytes_scanned=100, issues=None, files_scanned=1, assets=None, has_errors=False, scanners=None):
    from modelaudit.models import ModelAuditResultModel
    return ModelAuditResultModel(
        success=True,
        bytes_scanned=bytes_scanned,
        files_scanned=files_scanned,
        issues=issues or [],
        assets=assets or [],
        has_errors=has_errors,
        scanners=scanners or [],
        duration=0.1
    )

# Test with minimal mocking
@patch("modelaudit.cli.is_jfrog_url")  
@patch("modelaudit.cli.scan_jfrog_artifact")
def test_minimal_jfrog(mock_scan_jfrog, mock_is_jfrog):
    print("Setting up mocks...")
    mock_is_jfrog.return_value = True
    mock_scan_jfrog.return_value = (
        create_mock_scan_result(),
        "/tmp/downloaded_file"
    )
    
    print("Creating CLI runner...")
    runner = CliRunner()
    
    print("Invoking CLI...")
    result = runner.invoke(cli, ["scan", "https://test.jfrog.io/model.bin"])
    
    print(f"Exit code: {result.exit_code}")
    print(f"Output: {result.output}")
    print(f"Exception: {result.exception}")
    
    return result

if __name__ == "__main__":
    import signal
    
    def timeout_handler(signum, frame):
        print("Test timed out!")
        exit(1)
        
    signal.signal(signal.SIGALRM, timeout_handler)  
    signal.alarm(10)  # 10 second timeout
    
    try:
        result = test_minimal_jfrog()
        print("Test completed successfully!")
    except Exception as e:
        print(f"Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
    finally:
        signal.alarm(0)  # Cancel timeout
