#!/usr/bin/env python3
"""Test embedded secrets detection on real HuggingFace models."""

import json
import subprocess
import sys
from pathlib import Path

# Test models - variety of popular models
TEST_MODELS = [
    "hf://gpt2",  # Classic GPT-2 model
    "hf://bert-base-uncased",  # BERT model
    "hf://facebook/opt-125m",  # Small OPT model
    "hf://openai/whisper-tiny",  # Whisper ASR model
    "hf://sentence-transformers/all-MiniLM-L6-v2",  # Sentence transformer
]


def test_model(model_url):
    """Test a single model and return results."""
    print(f"\n{'='*60}")
    print(f"Testing: {model_url}")
    print('='*60)
    
    # Run modelaudit on the model
    result = subprocess.run(
        ["rye", "run", "modelaudit", "scan", "--format", "json", model_url],
        capture_output=True,
        text=True,
    )
    
    if result.returncode not in [0, 1]:  # 0 = no issues, 1 = issues found
        print(f"ERROR: Failed to scan {model_url}")
        print(f"STDERR: {result.stderr}")
        return None
    
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"ERROR: Invalid JSON output for {model_url}")
        print(f"STDOUT: {result.stdout[:500]}")
        return None
    
    # Analyze results
    files_scanned = data.get("files_scanned", 0)
    total_issues = data.get("total_issues", 0)
    
    # Look for embedded secrets checks
    secret_checks = []
    secret_issues = []
    
    for file_result in data.get("file_results", []):
        for check in file_result.get("checks", []):
            if "Embedded Secrets" in check.get("name", ""):
                secret_checks.append(check)
                if check.get("status") == "failed":
                    secret_issues.append(check)
        
        for issue in file_result.get("issues", []):
            if "secret" in issue.get("message", "").lower() or \
               "key" in issue.get("message", "").lower() or \
               "token" in issue.get("message", "").lower():
                secret_issues.append(issue)
    
    print(f"Files scanned: {files_scanned}")
    print(f"Total issues: {total_issues}")
    print(f"Secret checks performed: {len(secret_checks)}")
    print(f"Secret issues found: {len(secret_issues)}")
    
    if secret_issues:
        print("\nSecret issues detected:")
        for i, issue in enumerate(secret_issues, 1):
            msg = issue.get("message", "Unknown")
            details = issue.get("details", {})
            print(f"  {i}. {msg}")
            if details:
                if "secret_type" in details:
                    print(f"     Type: {details['secret_type']}")
                if "confidence" in details:
                    print(f"     Confidence: {details['confidence']}")
                if "redacted_value" in details:
                    print(f"     Value: {details['redacted_value']}")
    
    return {
        "model": model_url,
        "files_scanned": files_scanned,
        "total_issues": total_issues,
        "secret_checks": len(secret_checks),
        "secret_issues": len(secret_issues),
        "issues": secret_issues,
    }


def main():
    """Test all models and summarize results."""
    print("Testing embedded secrets detection on HuggingFace models")
    print("This will download and scan several popular models")
    
    results = []
    for model in TEST_MODELS:
        result = test_model(model)
        if result:
            results.append(result)
    
    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print('='*60)
    
    total_models = len(results)
    models_with_secrets = sum(1 for r in results if r["secret_issues"] > 0)
    total_secret_issues = sum(r["secret_issues"] for r in results)
    
    print(f"Models tested: {total_models}")
    print(f"Models with secret issues: {models_with_secrets}")
    print(f"Total secret issues: {total_secret_issues}")
    
    if total_secret_issues > 0:
        print("\nModels with potential false positives:")
        for r in results:
            if r["secret_issues"] > 0:
                print(f"  - {r['model']}: {r['secret_issues']} issues")
    
    # Analyze false positive rate
    print("\nFalse Positive Analysis:")
    if total_secret_issues == 0:
        print("✅ EXCELLENT: No false positives detected!")
        print("The detector correctly avoided flagging any model weights as secrets.")
    else:
        print(f"⚠️  WARNING: {total_secret_issues} potential false positives found")
        print("Review the detected issues above to determine if they are legitimate or false positives.")
        
        # Show unique secret types found
        secret_types = set()
        for r in results:
            for issue in r["issues"]:
                details = issue.get("details", {})
                if "secret_type" in details:
                    secret_types.add(details["secret_type"])
        
        if secret_types:
            print(f"\nSecret types detected: {', '.join(secret_types)}")
    
    return 0 if total_secret_issues == 0 else 1


if __name__ == "__main__":
    sys.exit(main())