#!/usr/bin/env python3
"""
Example demonstrating ModelAudit telemetry functionality.

This script shows how telemetry integrates with ModelAudit operations
and provides examples of telemetry configuration and usage.
"""

import os
import tempfile
from pathlib import Path

# Set development mode to see debug output
os.environ["MODELAUDIT_ENV"] = "development"

from modelaudit.telemetry import TelemetryConfig, get_telemetry_manager


def demonstrate_telemetry_config():
    """Demonstrate telemetry configuration options."""
    print("🔧 Telemetry Configuration Example")
    print("=" * 50)

    config = TelemetryConfig()

    print(f"Telemetry Enabled: {config.is_enabled}")
    print(f"Development Mode: {config.is_development_mode}")
    print(f"Distinct ID: {config.distinct_id[:8]}...")
    print(f"PostHog Host: {config.host}")

    print("\nTracking Settings:")
    print(f"  Usage Tracking: {config.usage_tracking_enabled}")
    print(f"  Error Tracking: {config.error_tracking_enabled}")
    print(f"  Performance Tracking: {config.performance_tracking_enabled}")

    print("\nEnvironment Variables:")
    for var in [
        "MODELAUDIT_TELEMETRY_ENABLED",
        "MODELAUDIT_POSTHOG_API_KEY",
        "MODELAUDIT_POSTHOG_HOST",
        "MODELAUDIT_DISTINCT_ID",
    ]:
        value = os.getenv(var, "Not set")
        print(f"  {var}: {value}")


def demonstrate_scan_tracking():
    """Demonstrate scan operation tracking."""
    print("\n📊 Scan Operation Tracking Example")
    print("=" * 50)

    telemetry = get_telemetry_manager()

    # Simulate a scan operation
    mock_paths = ["model1.pkl", "model2.h5", "model3.onnx"]

    with telemetry.track_scan_operation(
        paths=mock_paths,
        timeout_seconds=300,
        max_file_size=1024 * 1024 * 100,  # 100MB
        blacklist_patterns_count=2,
        output_format="json",
    ) as scan_data:
        print(f"Scanning {len(mock_paths)} files...")

        # Simulate processing
        scan_data.files_scanned = 3
        scan_data.bytes_scanned = 2048576  # ~2MB
        scan_data.issues_critical = 1
        scan_data.issues_warning = 2
        scan_data.issues_info = 0
        scan_data.issues_total = 3
        scan_data.scanners_used = "pickle,h5,onnx"

        print(f"Processed {scan_data.files_scanned} files")
        print(f"Scanned {scan_data.bytes_scanned} bytes")
        print(f"Found {scan_data.issues_total} issues")


def demonstrate_scanner_tracking():
    """Demonstrate individual scanner tracking."""
    print("\n🔍 Scanner Operation Tracking Example")
    print("=" * 50)

    telemetry = get_telemetry_manager()

    # Simulate scanning a suspicious pickle file
    mock_file_path = "/path/to/suspicious_model.pkl"

    with telemetry.track_scanner_operation(
        scanner_name="pickle", file_path=mock_file_path
    ) as scanner_data:
        print(f"Scanning file: {Path(mock_file_path).name}")

        # Simulate scanner results
        scanner_data.bytes_processed = 524288  # 512KB
        scanner_data.issues_found = 2
        scanner_data.highest_severity = "critical"

        print(f"Processed {scanner_data.bytes_processed} bytes")
        print(f"Found {scanner_data.issues_found} issues")
        print(f"Highest severity: {scanner_data.highest_severity}")

        # Simulate individual issue tracking
        telemetry.track_issue_found(
            severity="critical", scanner_name="pickle", file_path=mock_file_path
        )

        telemetry.track_issue_found(
            severity="warning", scanner_name="pickle", file_path=mock_file_path
        )


def demonstrate_error_tracking():
    """Demonstrate error tracking."""
    print("\n❌ Error Tracking Example")
    print("=" * 50)

    telemetry = get_telemetry_manager()

    # Simulate various types of errors
    errors = [
        (FileNotFoundError("Model file not found"), "core", "file_access"),
        (ValueError("Invalid pickle format"), "scanner", "pickle_scan"),
        (TimeoutError("Scan timeout exceeded"), "core", "scan_operation"),
        (MemoryError("Out of memory"), "scanner", "large_model_scan"),
    ]

    for error, component, operation in errors:
        print(f"Tracking error: {type(error).__name__}: {error}")
        telemetry.track_error(
            error=error,
            component=component,
            operation=operation,
            file_path_hash="abc123def456",  # Mock hash
        )


def demonstrate_performance_tracking():
    """Demonstrate performance metrics tracking."""
    print("\n⚡ Performance Tracking Example")
    print("=" * 50)

    telemetry = get_telemetry_manager()

    # Simulate performance metrics
    performance_metrics = {
        "cpu_usage_percent": 45.2,
        "memory_usage_mb": 256.8,
        "disk_io_mb": 12.4,
        "files_per_second": 3.2,
        "bytes_per_second": 1048576,  # 1MB/s
        "max_memory_mb": 512.0,
        "timeout_seconds": 300,
    }

    print("Performance metrics:")
    for metric, value in performance_metrics.items():
        print(f"  {metric}: {value}")

    telemetry.track_performance_metrics(**performance_metrics)


def demonstrate_file_processing_tracking():
    """Demonstrate file processing tracking."""
    print("\n📁 File Processing Tracking Example")
    print("=" * 50)

    telemetry = get_telemetry_manager()

    # Simulate different file types
    files = [
        ("/path/to/model.pkl", "pickle"),
        ("/path/to/model.h5", "hdf5"),
        ("/path/to/model.onnx", "onnx"),
        ("/path/to/model.pt", "pytorch"),
        ("/path/to/unknown.xyz", "unknown"),
    ]

    for file_path, detected_format in files:
        print(f"Processing: {Path(file_path).name} (format: {detected_format})")
        telemetry.track_file_processing(
            file_path=file_path,
            format_detected=detected_format,
            file_size_bytes=1024 * 512,  # 512KB
        )


def demonstrate_privacy_features():
    """Demonstrate privacy-preserving features."""
    print("\n🔒 Privacy Features Example")
    print("=" * 50)

    telemetry = get_telemetry_manager()

    # Show how sensitive data is hashed
    sensitive_paths = [
        "/home/user/secret_model.pkl",
        "/company/confidential/ai_model.h5",
        "C:\\Users\\Admin\\Desktop\\private_model.onnx",
    ]

    print("Path hashing for privacy:")
    for path in sensitive_paths:
        hashed = telemetry._hash_for_privacy(path)
        print(f"  Original: {path}")
        print(f"  Hashed:   {hashed}")
        print()


def demonstrate_configuration_management():
    """Demonstrate telemetry configuration management."""
    print("\n⚙️ Configuration Management Example")
    print("=" * 50)

    with tempfile.TemporaryDirectory() as temp_dir:
        # Mock config directory
        config_dir = Path(temp_dir) / ".modelaudit"

        # Test configuration persistence
        from unittest.mock import patch

        with patch.object(TelemetryConfig, "_config_dir", config_dir):
            config = TelemetryConfig()

            print(f"Initial state - Enabled: {config.is_enabled}")

            # Disable telemetry
            config.disable_telemetry()
            print(f"After disable - Enabled: {config.is_enabled}")
            print(
                f"Disable file exists: {(config_dir / 'telemetry_disabled').exists()}"
            )

            # Enable telemetry
            config.enable_telemetry()
            print(f"After enable - Enabled: {config.is_enabled}")
            print(f"Enable file exists: {(config_dir / 'telemetry_enabled').exists()}")
            print(
                f"Disable file exists: {(config_dir / 'telemetry_disabled').exists()}"
            )


def main():
    """Run all telemetry examples."""
    print("ModelAudit Telemetry Examples")
    print("=" * 60)
    print("This script demonstrates telemetry functionality in development mode.")
    print("In development mode, events are logged but not sent to PostHog.")
    print()

    try:
        demonstrate_telemetry_config()
        demonstrate_scan_tracking()
        demonstrate_scanner_tracking()
        demonstrate_error_tracking()
        demonstrate_performance_tracking()
        demonstrate_file_processing_tracking()
        demonstrate_privacy_features()
        demonstrate_configuration_management()

        print("\n✅ All telemetry examples completed successfully!")
        print("\nTo see telemetry in action:")
        print("1. Set MODELAUDIT_POSTHOG_API_KEY environment variable")
        print("2. Unset MODELAUDIT_ENV or set it to 'production'")
        print("3. Run ModelAudit commands normally")

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
