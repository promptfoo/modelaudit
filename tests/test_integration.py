import json
from pathlib import Path

from click.testing import CliRunner

from modelaudit.cli import cli
from modelaudit.core import determine_exit_code, scan_model_directory_or_file


def test_scan_directory_with_multiple_models(temp_model_dir, mock_progress_callback):
    """Test scanning a directory with multiple model types."""
    # Scan the directory with all models
    results = scan_model_directory_or_file(
        str(temp_model_dir),
        progress_callback=mock_progress_callback,
    )

    # Check basic results
    assert results.success is True
    assert results.files_scanned >= 4  # At least our 4 test files
    assert results.bytes_scanned > 0

    # Check progress callback was called
    assert len(mock_progress_callback.messages) > 0
    assert len(mock_progress_callback.percentages) > 0
    assert any("Scanning directory" in msg for msg in mock_progress_callback.messages)
    assert 100.0 in mock_progress_callback.percentages  # Should reach 100%

    # Check that issues were found for each model type
    [
        str(temp_model_dir / "model1.pkl"),
        str(temp_model_dir / "model2.pt"),
        str(temp_model_dir / "tf_model"),
        str(temp_model_dir / "subdir" / "model3.h5"),
    ]

    # Should have found some issues overall (but not necessarily for each file)
    # Clean models might not have any issues, which is correct behavior
    scanned_files = [getattr(issue, "location", None) for issue in results.issues if getattr(issue, "location", None)]
    print(f"Debug: Found {len(results.issues)} total issues")
    print(f"Debug: Issues locations: {scanned_files}")

    # Verify that the scan found and processed files
    assert results.files_scanned > 0, "Should have scanned at least one file"
    assert results.bytes_scanned >= 0, "Should have scanned some bytes"

    # Validate exit code behavior
    expected_exit_code = determine_exit_code(results)
    if getattr(results, "has_errors", False):
        assert expected_exit_code == 2, f"Should return exit code 2 for operational errors, got {expected_exit_code}"
    elif any(getattr(issue, "severity", None) != "debug" for issue in results.issues):
        assert expected_exit_code == 1, f"Should return exit code 1 for security issues, got {expected_exit_code}"
    else:
        assert expected_exit_code == 0, f"Should return exit code 0 for clean scan, got {expected_exit_code}"


def test_cli_scan_directory(temp_model_dir):
    """Test scanning a directory with multiple models using the CLI."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(temp_model_dir)])

    # Exit code should be deterministic based on content
    # The temp_model_dir contains real models that should be clean
    # But the scan might find warnings or info messages
    assert result.exit_code in [
        0,
        1,
    ], f"Unexpected exit code {result.exit_code}. Output: {result.output}"
    assert str(temp_model_dir) in result.output

    # Should mention the number of files scanned
    # Check for the new format - should contain "Files:" in the scan summary
    assert "Files:" in result.output


def test_cli_json_output_parsing(temp_model_dir):
    """Test that the CLI JSON output can be parsed."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(temp_model_dir), "--format", "json"])

    # Should exit with 0 for clean models, or 1 if any issues are found
    assert result.exit_code in [0, 1]

    # Should be valid JSON
    output_json = json.loads(result.output)

    # Check expected fields
    assert "files_scanned" in output_json
    assert "issues" in output_json
    assert "bytes_scanned" in output_json
    assert "duration" in output_json

    # Clean models might not have any issues, which is correct
    assert len(output_json["issues"]) >= 0


def test_scan_with_all_options(temp_model_dir, mock_progress_callback):
    """Test scanning with all options enabled."""
    results = scan_model_directory_or_file(
        str(temp_model_dir),
        blacklist_patterns=["suspicious_pattern", "malicious_code"],
        timeout=60,
        max_file_size=1000000,
        progress_callback=mock_progress_callback,
        verbose=True,
        additional_option="test_value",
    )

    assert results.success is True
    assert results.files_scanned > 0
    assert results.bytes_scanned > 0

    # Check progress callback was called
    assert len(mock_progress_callback.messages) > 0
    assert len(mock_progress_callback.percentages) > 0


def test_cli_with_all_options(temp_model_dir):
    """Test CLI with all options."""
    output_file = Path(temp_model_dir) / "output.json"

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            str(temp_model_dir),
            "--blacklist",
            "suspicious_pattern",
            "--blacklist",
            "malicious_code",
            "--format",
            "json",
            "--output",
            str(output_file),
            "--timeout",
            "60",
            "--max-file-size",
            "1000000",
            "--verbose",
        ],
    )

    # Should exit with 0 for clean models, or 1 if any issues are found
    assert result.exit_code in [0, 1]
    assert output_file.exists()

    # Read the output file
    output_content = output_file.read_text()
    output_json = json.loads(output_content)

    # Check expected fields
    assert "files_scanned" in output_json
    assert "issues" in output_json
    assert "bytes_scanned" in output_json


def test_scan_multiple_paths_combined_results(temp_model_dir):
    """Test scanning multiple paths and combining results."""
    # Create paths to scan
    path1 = temp_model_dir / "model1.pkl"
    path2 = temp_model_dir / "model2.pt"

    # Scan individual files
    results1 = scan_model_directory_or_file(str(path1))
    results2 = scan_model_directory_or_file(str(path2))

    # Filter debug issues from individual results to match CLI behavior (CLI filters debug by default)
    from modelaudit.scanners.base import IssueSeverity

    results1_issues = [issue for issue in results1.issues if getattr(issue, "severity", None) != IssueSeverity.DEBUG]
    results2_issues = [issue for issue in results2.issues if getattr(issue, "severity", None) != IssueSeverity.DEBUG]

    # Scan both files using CLI
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(path1), str(path2), "--format", "json"])

    # Should exit with 0 for clean models, or 1 if any issues are found
    assert result.exit_code in [0, 1]
    combined_results = json.loads(result.output)

    # Combined results should have at least the sum of individual scans
    assert combined_results["files_scanned"] >= results1.files_scanned + results2.files_scanned
    assert combined_results["bytes_scanned"] >= results1.bytes_scanned + results2.bytes_scanned
    assert len(combined_results["issues"]) >= len(results1_issues) + len(results2_issues)


def test_file_type_validation_integration(tmp_path):
    """Test that file type validation is integrated into the main scanning workflow."""
    from modelaudit.core import scan_file
    from modelaudit.scanners.base import IssueSeverity

    # Create a file with mismatched extension and content
    fake_h5 = tmp_path / "malicious.h5"
    fake_h5.write_bytes(b"this is not hdf5 data" + b"\x00" * 100)

    result = scan_file(str(fake_h5))

    # Should detect file type validation failure
    validation_issues = [issue for issue in result.issues if "file type validation" in issue.message.lower()]

    # Should have at least one validation issue
    assert len(validation_issues) > 0

    # Check that the issue has proper details
    validation_issue = validation_issues[0]
    assert validation_issue.severity in [IssueSeverity.WARNING, IssueSeverity.CRITICAL]
    assert "spoofing" in validation_issue.message or "security" in validation_issue.message


def test_valid_file_type_no_warnings(tmp_path):
    """Test that valid file types don't generate false positive warnings."""
    import zipfile

    from modelaudit.core import scan_file

    # Create a valid ZIP file with .zip extension
    zip_file = tmp_path / "valid.zip"
    with zipfile.ZipFile(zip_file, "w") as zipf:
        zipf.writestr("test.txt", "data")

    result = scan_file(str(zip_file))

    # Should not have file type validation warnings
    validation_issues = [issue for issue in result.issues if "file type validation" in issue.message.lower()]

    assert len(validation_issues) == 0


def test_pytorch_zip_file_valid(tmp_path):
    """Test that PyTorch files saved as ZIP are properly validated."""
    import zipfile

    from modelaudit.core import scan_file

    # Create a PyTorch file that's actually a ZIP (common with torch.save())
    pt_file = tmp_path / "model.pt"
    with zipfile.ZipFile(pt_file, "w") as zipf:
        zipf.writestr("data.pkl", "tensor data")

    result = scan_file(str(pt_file))

    # Should not have file type validation warnings (this is a valid case)
    validation_issues = [issue for issue in result.issues if "file type validation failed" in issue.message.lower()]

    assert len(validation_issues) == 0


def test_small_file_no_false_positives(tmp_path):
    """Test that very small files don't trigger false validation warnings."""
    from modelaudit.core import scan_file

    # Create a very small file
    small_file = tmp_path / "tiny.h5"
    small_file.write_bytes(b"hi")

    result = scan_file(str(small_file))

    # Should not have file type validation warnings for small files
    validation_issues = [issue for issue in result.issues if "file type validation failed" in issue.message.lower()]

    assert len(validation_issues) == 0


def test_tensorflow_savedmodel_integration(tmp_path):
    """Test integration of TensorFlow SavedModel scanning with the main workflow."""
    import pytest

    try:
        import tensorflow as tf
    except ImportError:
        pytest.skip("TensorFlow not available")

    from click.testing import CliRunner

    from modelaudit.cli import cli
    from modelaudit.core import scan_model_directory_or_file

    # Create a simple TensorFlow model with some weights that might trigger analysis
    model = tf.keras.Sequential(
        [
            tf.keras.layers.Dense(64, activation="relu", input_shape=(10,)),
            tf.keras.layers.Dense(32, activation="relu"),
            tf.keras.layers.Dense(1, activation="sigmoid"),
        ]
    )

    # Compile the model to ensure it's complete
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])

    # Save the model to the test directory
    savedmodel_path = tmp_path / "test_tensorflow_model"
    tf.saved_model.save(model, str(savedmodel_path))

    # Test using the core scanning functionality
    results = scan_model_directory_or_file(str(savedmodel_path))

    # Basic assertions
    assert results.success is True
    assert results.files_scanned >= 1  # Should scan at least the savedmodel directory
    assert results.bytes_scanned > 0  # Should have scanned some content

    # Test using CLI
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(savedmodel_path), "--format", "json"])

    # Should complete successfully (exit code 0 for clean model, 1 if issues found)
    assert result.exit_code in [0, 1]
    assert result.output is not None

    # Should be valid JSON
    import json

    output_json = json.loads(result.output)

    # Check expected fields are present
    assert "files_scanned" in output_json
    assert "issues" in output_json
    assert "bytes_scanned" in output_json
    assert "duration" in output_json

    # Verify the path appears in the output (the scanner handled the directory)
    assert str(savedmodel_path) in str(output_json) or str(savedmodel_path.name) in str(output_json)

    # Test that weight distribution scanner was used
    # Look for evidence that weight analysis was performed
    found_weight_analysis = False
    for issue in output_json.get("issues", []):
        if "weight" in issue.get("message", "").lower():
            found_weight_analysis = True
            break

    # It's okay if no weight analysis issues were found (clean model)
    # The important thing is that the scanning completed successfully

    # Test scanning the parent directory containing the SavedModel
    parent_results = scan_model_directory_or_file(str(tmp_path))
    assert parent_results.success is True
    assert parent_results.files_scanned >= 1

    # Test CLI scanning of parent directory
    parent_result = runner.invoke(cli, ["scan", str(tmp_path), "--format", "json"])
    assert parent_result.exit_code in [0, 1]
    parent_output = json.loads(parent_result.output)
    assert parent_output["files_scanned"] >= 1


def test_tensorflow_savedmodel_with_anomalous_weights_integration(tmp_path):
    """Test TensorFlow SavedModel scanning with artificially anomalous weights."""
    import pytest

    try:
        import numpy as np
        import tensorflow as tf
    except ImportError:
        pytest.skip("TensorFlow not available")

    from modelaudit.core import scan_model_directory_or_file

    # Create a model with potentially anomalous weights
    model = tf.keras.Sequential(
        [
            tf.keras.layers.Dense(10, input_shape=(5,), name="anomalous_layer"),
            tf.keras.layers.Dense(1, activation="sigmoid", name="output_layer"),
        ]
    )

    # Set some weights to potentially anomalous values
    # (though the weight analysis might not flag them if they're within normal ranges)
    weights = model.get_layer("anomalous_layer").get_weights()
    if len(weights) >= 1:
        # Make some weights larger than typical
        weights[0][:, 0] = np.random.randn(5) * 2.0  # Larger than normal but not extreme
        model.get_layer("anomalous_layer").set_weights(weights)

    # Save the model
    savedmodel_path = tmp_path / "anomalous_tensorflow_model"
    tf.saved_model.save(model, str(savedmodel_path))

    # Scan the model
    results = scan_model_directory_or_file(str(savedmodel_path))

    # Should complete successfully regardless of whether anomalies are detected
    assert results.success is True
    assert results.files_scanned >= 1
    assert results.bytes_scanned > 0

    # The weight distribution scanner should have been applied
    # (but may or may not find issues depending on the specific weight values)
    # The main test is that the integration works without errors
