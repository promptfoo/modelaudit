#!/usr/bin/env python3
"""
Comprehensive comparison script between main branch and fickling-integration hybrid.

Tests false positives and false negatives across legitimate and malicious models.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Any

# Test sets
LEGITIMATE_MODELS = [
    "legitimate_model.pkl",
    "tests/assets/pickles/innocent_model_v4.pkl",
    "tests/assets/samples/pickles/safe_model_with_binary.pkl",
    "tests/assets/samples/pickles/safe_data.pkl",
    "tests/assets/samples/pickles/safe_large_model.pkl",
]

MALICIOUS_MODELS = [
    "simple_malicious.pkl",
    "malicious_chained.pkl",
    "malicious_obfuscated.pkl",
    "tests/assets/pickles/simple_eval_attack.pkl",
    "tests/assets/pickles/steganographic_attack.pkl",
    "tests/assets/pickles/steganographic_attack_v2.pkl",
    "tests/assets/pickles/steganographic_attack_v3.pkl",
    "tests/assets/pickles/steganographic_attack_v4.pkl",
    "tests/assets/pickles/stack_global_attack.pkl",
    "tests/assets/pickles/multiple_stream_attack.pkl",
    "tests/assets/samples/pickles/malicious_system_call.pkl",
    "tests/assets/samples/pickles/malicious_model_realistic.pkl",
    "tests/assets/samples/pickles/nested_pickle_base64.pkl",
]


def run_scan(model_path: str, output_file: str) -> Dict[str, Any]:
    """Run modelaudit scan and return results."""
    try:
        cmd = ["rye", "run", "modelaudit", "scan", model_path, "--format", "json", "--output", output_file]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        # Load the JSON results
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                scan_results = json.load(f)
        else:
            scan_results = {"error": "No output file generated"}

        return {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "scan_results": scan_results,
            "scan_time": 0,  # We'll measure this separately
        }
    except subprocess.TimeoutExpired:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "Scan timed out after 60 seconds",
            "scan_results": {"error": "timeout"},
            "scan_time": 60,
        }
    except Exception as e:
        return {"exit_code": -1, "stdout": "", "stderr": str(e), "scan_results": {"error": str(e)}, "scan_time": 0}


def analyze_results(results: Dict[str, Any], is_legitimate: bool) -> Dict[str, Any]:
    """Analyze scan results for false positives/negatives."""
    scan_results = results.get("scan_results", {})

    if isinstance(scan_results, dict) and "error" in scan_results:
        return {
            "status": "error",
            "error": scan_results["error"],
            "false_positive": False,
            "false_negative": False,
            "issue_count": 0,
            "critical_issues": 0,
            "warning_issues": 0,
        }

    # Count issues by severity
    issues = []
    if isinstance(scan_results, dict) and "results" in scan_results:
        for file_result in scan_results["results"]:
            if "issues" in file_result:
                issues.extend(file_result["issues"])
    elif isinstance(scan_results, dict) and "issues" in scan_results:
        issues = scan_results["issues"]

    critical_issues = sum(1 for issue in issues if issue.get("severity") == "CRITICAL")
    warning_issues = sum(1 for issue in issues if issue.get("severity") == "WARNING")
    total_issues = len(issues)

    # Determine false positive/negative
    has_security_issues = results["exit_code"] == 1 or critical_issues > 0

    if is_legitimate:
        # For legitimate models, security issues indicate false positives
        false_positive = has_security_issues
        false_negative = False
    else:
        # For malicious models, no security issues indicate false negatives
        false_positive = False
        false_negative = not has_security_issues

    return {
        "status": "success" if results["exit_code"] in [0, 1] else "error",
        "false_positive": false_positive,
        "false_negative": false_negative,
        "issue_count": total_issues,
        "critical_issues": critical_issues,
        "warning_issues": warning_issues,
        "exit_code": results["exit_code"],
    }


def main():
    """Run comprehensive comparison tests."""
    print("🔬 ModelAudit Implementation Comparison")
    print("=" * 50)

    # Check which branch we're on
    try:
        branch_result = subprocess.run(["git", "branch", "--show-current"], capture_output=True, text=True)
        current_branch = branch_result.stdout.strip()
        print(f"Current branch: {current_branch}")
    except:
        current_branch = "unknown"

    results = {
        "branch": current_branch,
        "timestamp": time.time(),
        "legitimate_models": {},
        "malicious_models": {},
        "summary": {},
    }

    # Test legitimate models (should have few/no issues)
    print(f"\n📊 Testing {len(LEGITIMATE_MODELS)} legitimate models...")
    for i, model in enumerate(LEGITIMATE_MODELS):
        if not os.path.exists(model):
            print(f"  ⚠️  Skipping missing model: {model}")
            continue

        print(f"  [{i + 1}/{len(LEGITIMATE_MODELS)}] {model}")
        output_file = f"results_{current_branch}_{os.path.basename(model)}.json"

        start_time = time.time()
        scan_result = run_scan(model, output_file)
        scan_result["scan_time"] = time.time() - start_time

        analysis = analyze_results(scan_result, is_legitimate=True)
        results["legitimate_models"][model] = {**scan_result, **analysis}

        status_emoji = "✅" if analysis["status"] == "success" else "❌"
        fp_emoji = "🚨" if analysis["false_positive"] else "✅"
        print(f"    {status_emoji} Status: {analysis['status']}, Issues: {analysis['issue_count']}, FP: {fp_emoji}")

        # Cleanup
        if os.path.exists(output_file):
            os.remove(output_file)

    # Test malicious models (should have issues)
    print(f"\n🦠 Testing {len(MALICIOUS_MODELS)} malicious models...")
    for i, model in enumerate(MALICIOUS_MODELS):
        if not os.path.exists(model):
            print(f"  ⚠️  Skipping missing model: {model}")
            continue

        print(f"  [{i + 1}/{len(MALICIOUS_MODELS)}] {model}")
        output_file = f"results_{current_branch}_{os.path.basename(model)}.json"

        start_time = time.time()
        scan_result = run_scan(model, output_file)
        scan_result["scan_time"] = time.time() - start_time

        analysis = analyze_results(scan_result, is_legitimate=False)
        results["malicious_models"][model] = {**scan_result, **analysis}

        status_emoji = "✅" if analysis["status"] == "success" else "❌"
        fn_emoji = "🚨" if analysis["false_negative"] else "✅"
        print(f"    {status_emoji} Status: {analysis['status']}, Issues: {analysis['issue_count']}, FN: {fn_emoji}")

        # Cleanup
        if os.path.exists(output_file):
            os.remove(output_file)

    # Calculate summary statistics
    legitimate_results = list(results["legitimate_models"].values())
    malicious_results = list(results["malicious_models"].values())

    legitimate_fps = sum(1 for r in legitimate_results if r.get("false_positive", False))
    malicious_fns = sum(1 for r in malicious_results if r.get("false_negative", False))

    total_legitimate = len(legitimate_results)
    total_malicious = len(malicious_results)

    results["summary"] = {
        "legitimate_models_tested": total_legitimate,
        "malicious_models_tested": total_malicious,
        "false_positives": legitimate_fps,
        "false_negatives": malicious_fns,
        "false_positive_rate": legitimate_fps / total_legitimate if total_legitimate > 0 else 0,
        "false_negative_rate": malicious_fns / total_malicious if total_malicious > 0 else 0,
        "accuracy": ((total_legitimate - legitimate_fps) + (total_malicious - malicious_fns))
        / (total_legitimate + total_malicious)
        if (total_legitimate + total_malicious) > 0
        else 0,
    }

    # Print summary
    print(f"\n📈 Summary for {current_branch}:")
    print(f"  False Positives: {legitimate_fps}/{total_legitimate} ({results['summary']['false_positive_rate']:.1%})")
    print(f"  False Negatives: {malicious_fns}/{total_malicious} ({results['summary']['false_negative_rate']:.1%})")
    print(f"  Overall Accuracy: {results['summary']['accuracy']:.1%}")

    # Save detailed results (fix branch name for filename)
    safe_branch_name = current_branch.replace("/", "_")
    output_file = f"comparison_results_{safe_branch_name}_{int(time.time())}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n💾 Detailed results saved to: {output_file}")

    return results


if __name__ == "__main__":
    main()
