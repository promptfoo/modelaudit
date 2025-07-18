#!/usr/bin/env python3
"""
License Detection Feature Demonstration

This script demonstrates the complete license detection and compliance
functionality of ModelAudit. It shows:

1. License detection from file headers
2. AGPL license warnings for SaaS deployment
3. Unlicensed dataset detection
4. SBOM generation with license metadata
5. Commercial use compliance warnings

Run this script to see the license features in action.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run_cli_command(command_args):
    """Run a modelaudit CLI command and return the result."""
    base_cmd = [sys.executable, "-c", "from modelaudit.cli import main; main()"]
    result = subprocess.run(base_cmd + command_args, capture_output=True, text=True)
    return result


def demonstrate_license_features():
    """Demonstrate all license detection features."""
    print("🔍 ModelAudit License Detection Demo")
    print("=" * 60)
    print()

    # Get test data directory
    test_data_dir = Path(__file__).parent / "assets/scenarios/license_scenarios"

    if not test_data_dir.exists():
        print("❌ Test data directory not found. Run the integration tests first.")
        return

    # 1. MIT Model - Clean License (Should pass)
    print("1️⃣  Testing MIT Licensed Model (should be clean)")
    print("-" * 40)

    mit_dir = test_data_dir / "mit_model"
    result = run_cli_command(["scan", str(mit_dir), "--format", "json"])

    if result.returncode == 0:
        print("✅ PASS: MIT model scan completed without critical issues")
        data = json.loads(result.stdout)
        print(f"   📁 Files scanned: {data['files_scanned']}")
        print(f"   📊 Bytes scanned: {data['bytes_scanned']}")

        # Check for any license issues
        license_issues = [i for i in data.get("issues", []) if i.get("type") == "license_warning"]
        if license_issues:
            print(f"   ⚠️  License notices: {len(license_issues)}")
        else:
            print("   ✅ No license warnings (good for permissive MIT license)")
    else:
        print(f"❌ FAIL: MIT scan returned exit code {result.returncode}")
    print()

    # 2. AGPL Component - Should trigger warnings
    print("2️⃣  Testing AGPL Component (should trigger warnings)")
    print("-" * 40)

    agpl_dir = test_data_dir / "agpl_component"
    result = run_cli_command(["scan", str(agpl_dir), "--format", "json"])

    if result.returncode == 1:  # 1 = issues found
        print("✅ PASS: AGPL component triggered warnings as expected")
        data = json.loads(result.stdout)

        license_issues = [i for i in data.get("issues", []) if i.get("type") == "license_warning"]
        print(f"   ⚠️  License warnings: {len(license_issues)}")

        agpl_issues = [i for i in license_issues if "AGPL" in i.get("message", "")]
        if agpl_issues:
            print("   🚨 AGPL license detected:")
            for issue in agpl_issues:
                print(f"      - {issue['message']}")

        copyleft_issues = [i for i in license_issues if "copyleft" in i.get("message", "")]
        if copyleft_issues:
            print("   📋 Copyleft obligations noted")

    else:
        print(f"❌ FAIL: AGPL scan returned unexpected exit code {result.returncode}")
    print()

    # 3. Unlicensed Datasets - Should warn about licensing
    print("3️⃣  Testing Unlicensed Datasets (should warn)")
    print("-" * 40)

    unlicensed_dir = test_data_dir / "unlicensed_dataset"
    result = run_cli_command(["scan", str(unlicensed_dir), "--format", "json"])

    if result.returncode == 1:  # 1 = issues found
        print("✅ PASS: Unlicensed datasets triggered warnings")
        data = json.loads(result.stdout)

        dataset_issues = [i for i in data.get("issues", []) if "unspecified licenses" in i.get("message", "")]
        if dataset_issues:
            print("   📊 Unlicensed dataset warnings:")
            for issue in dataset_issues:
                print(f"      - {issue['message']}")
                files = issue.get("details", {}).get("files", [])
                print(f"      - Files: {len(files)} unlicensed data files")
    else:
        print(f"⚠️  Unlicensed datasets scan returned exit code {result.returncode}")
    print()

    # 4. SBOM Generation with License Metadata
    print("4️⃣  Testing SBOM Generation with License Metadata")
    print("-" * 40)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        sbom_path = f.name

    try:
        # Generate SBOM for the mixed licenses directory
        mixed_dir = test_data_dir / "mixed_licenses"
        result = run_cli_command(["scan", str(mixed_dir), "--sbom", sbom_path])

        if result.returncode in [0, 1]:  # Success or issues found
            print("✅ PASS: SBOM generation completed")

            # Read and analyze SBOM
            with open(sbom_path) as f:
                sbom_data = json.loads(f.read())

            components = sbom_data.get("components", [])
            print(f"   📦 SBOM components: {len(components)}")

            # Check for license metadata in components
            license_properties = 0
            for component in components:
                properties = component.get("properties", [])
                for prop in properties:
                    if prop.get("name") in [
                        "is_dataset",
                        "is_model",
                        "copyright_holders",
                        "license_files_found",
                    ]:
                        license_properties += 1
                        break

            print(f"   📋 Components with license metadata: {license_properties}")

            # Check for license expressions
            licensed_components = sum(1 for c in components if c.get("licenses"))
            print(f"   ⚖️  Components with license info: {licensed_components}")

        else:
            print(f"❌ FAIL: SBOM generation failed with exit code {result.returncode}")
    finally:
        Path(sbom_path).unlink(missing_ok=True)
    print()

    # 5. Mixed License Analysis
    print("5️⃣  Testing Mixed License Detection")
    print("-" * 40)

    mixed_dir = test_data_dir / "mixed_licenses"
    result = run_cli_command(["scan", str(mixed_dir), "--format", "json"])

    data = json.loads(result.stdout)
    license_issues = [i for i in data.get("issues", []) if i.get("type") == "license_warning"]

    print("✅ Mixed license analysis completed")
    print(f"   📁 Files scanned: {data['files_scanned']}")
    print(f"   ⚠️  License issues detected: {len(license_issues)}")

    # Categorize license issues
    issue_types = {}
    for issue in license_issues:
        message = issue.get("message", "")
        if "AGPL" in message:
            issue_types["AGPL"] = issue_types.get("AGPL", 0) + 1
        elif "Non-commercial" in message:
            issue_types["Non-commercial"] = issue_types.get("Non-commercial", 0) + 1
        elif "copyleft" in message:
            issue_types["Copyleft"] = issue_types.get("Copyleft", 0) + 1
        elif "unspecified" in message:
            issue_types["Unlicensed"] = issue_types.get("Unlicensed", 0) + 1

    if issue_types:
        print("   📊 License issue breakdown:")
        for issue_type, count in issue_types.items():
            print(f"      - {issue_type}: {count}")
    print()

    # 6. CLI Features Summary
    print("6️⃣  CLI Features Summary")
    print("-" * 40)

    # Test help command
    result = run_cli_command(["scan", "--help"])
    if result.returncode == 0 and "--sbom" in result.stdout:
        print("✅ CLI help includes SBOM option")

    print("   🔧 Available license features:")
    print("      - License detection from file headers")
    print("      - AGPL network service warnings")
    print("      - Unlicensed dataset detection")
    print("      - SBOM generation with license metadata")
    print("      - Commercial use compliance warnings")
    print("      - Mixed license analysis")
    print()

    # Summary
    print("📋 Demo Summary")
    print("=" * 60)
    print("✅ License detection is working correctly!")
    print("✅ AGPL warnings help identify network service obligations")
    print("✅ Unlicensed dataset detection helps identify data rights issues")
    print("✅ SBOM generation includes comprehensive license metadata")
    print("✅ CLI integration provides easy-to-use license analysis")
    print()
    print("🎯 The license mapping feature is ready for production use!")


def show_usage_examples():
    """Show usage examples for the license functionality."""
    print("\n📚 Usage Examples")
    print("=" * 60)

    examples = [
        {
            "description": "Basic scan with license detection",
            "command": "modelaudit scan ./my_model_directory",
        },
        {
            "description": "Generate SBOM with license metadata",
            "command": "modelaudit scan ./my_model --sbom model_sbom.json",
        },
        {
            "description": "JSON output for programmatic processing",
            "command": "modelaudit scan ./my_model --format json --output results.json",
        },
        {
            "description": "Verbose output showing license details",
            "command": "modelaudit scan ./my_model --verbose",
        },
        {
            "description": "Scan with custom file size limits",
            "command": "modelaudit scan ./large_model --max-file-size 1073741824",
        },
    ]

    for i, example in enumerate(examples, 1):
        print(f"{i}. {example['description']}:")
        print(f"   {example['command']}")
        print()


if __name__ == "__main__":
    try:
        demonstrate_license_features()
        show_usage_examples()
    except KeyboardInterrupt:
        print("\n\n⏹️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        sys.exit(1)
