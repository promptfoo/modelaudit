#!/usr/bin/env python3
"""
Comprehensive testing script to compare ModelAudit vs modelscan across our model catalog.
This will help identify models where each tool has advantages/disadvantages.
"""

import os
import sys
import subprocess
import json
import time
import shutil
from pathlib import Path
from typing import Dict, List

# Model categories to test systematically
TEST_MODELS = {
    "ONNX_BLIND_SPOTS": [
        "Xenova/clip-vit-base-patch16",
        "Xenova/clip-vit-large-patch14", 
        "onnx-community/mobilenet_v2_1.0_224",
        "onnx-community/mobilenetv4_conv_small.e2400_r224_in1k",
        "Kalray/resnet50",
        "Kalray/deeplabv3plus-resnet50",
        "webnn/yolov8m",
    ],
    "GGUF_BLIND_SPOTS": [
        "microsoft/Phi-3-mini-4k-instruct-gguf",
        "gorilla-llm/gorilla-openfunctions-v0-gguf", 
        "TheBloke/Mistral-7B-Instruct-v0.2-GGUF",
        "QuantFactory/Meta-Llama-3-8B-Instruct-GGUF",
    ],
    "CONFIG_EXPLOITS": [
        "internlm/internlm2-chat-7b",
        "deepseek-ai/DeepSeek-V3", 
        "microsoft/Phi-3-mini-128k-instruct",
        "chandar-lab/NeoBERT",
        "microsoft/Dayhoff-170m-UR50-BRq",
    ],
    "KERAS_EXPLOITS": [
        "mkiani/unsafe-keras",
        "mkiani/keras-unsafe-models",
        "warmiros/unsafe_models", 
        "Anggads01/trashnet-classifier",
        "keras/siglip2_large_patch16_256",
        "yuto-urushima/my_gemma2_pt",
    ],
    "ADVANCED_PYTORCH": [
        "drhyrum/bert-tiny-torch-picklebomb",
        "kojino/bert-tiny-torch-picklebomb", 
        "hf-internal-testing/unsafe-model",
        "ykilcher/totally-harmless-model",
        "TencentAIGC/poisoned-model",
        "DSfsdasgaa/shell",
    ],
    "YOLO_EXPLOITS": [
        "echo840/MonkeyOCR",
        "Uminosachi/FastSAM",
        "guon/hand-eyes",
        "keremberke/yolov8m-hard-hat-detection",
        "deepghs/imgutils-models",
        "JCTN/adetailer",
    ],
    "ADVANCED_FRAMEWORKS": [
        "OpenVINO/bert-base-uncased-sst2-unstructured80-int8-ov",
        "helenai/distilbert-base-uncased-finetuned-sst-2-english-ov-int8",
        "PaddlePaddle/PP-OCRv5_server_det", 
        "PaddlePaddle/PP-OCRv3_mobile_det",
        "PaddlePaddle/PP-DocLayout-M",
        "HuggingWorm/PaddleNLP-ErnieTiny",
    ],
    "JOBLIB_PICKLE": [
        "Iredteam/joblib-payload-chatbot",
        "MasterShomya/Tweets_Sentiment_Analyzer",
        "Devishetty100/neoguardianai",
        "cis5190/transformer_model",
        "bertin-project/bertin-base-stepwise",
    ],
    "MIXED_ATTACKS": [
        "nono31/malicious-models-repo",
        "mcpotato/42-eicar-street",
        "liangjun1987/realtime-chat-llm",
    ]
}

def run_modelaudit(model_name: str, timeout: int = 300) -> Dict:
    """Run ModelAudit on a model and capture results."""
    print(f"🔍 Testing ModelAudit on {model_name}")
    
    try:
        cmd = [
            sys.executable, "-m", "modelaudit", 
            f"hf://{model_name}",
            "--format", "json",
            "--timeout", str(timeout),
            "--no-large-model-support"
        ]
        
        ma_cwd = os.getenv("MODELAUDIT_CWD", os.getcwd())
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=timeout,
            cwd=ma_cwd
        )
        
        if result.returncode == 0:
            # No issues found
            return {"status": "clean", "issues": 0, "details": "No security issues detected"}
        elif result.returncode == 1:
            # Issues found - try to parse JSON output
            try:
                if result.stdout:
                    data = json.loads(result.stdout)
                    return {
                        "status": "issues_found", 
                        "issues": len(data.get("results", [])),
                        "details": result.stderr.split('\n')[-20:] if result.stderr else []
                    }
            except json.JSONDecodeError:
                pass
            
            # Fallback to counting CRITICAL/WARNING messages in stderr
            critical_count = result.stderr.count("CRITICAL") if result.stderr else 0
            warning_count = result.stderr.count("WARNING") if result.stderr else 0
            
            return {
                "status": "issues_found",
                "issues": critical_count + warning_count,
                "critical": critical_count,
                "warning": warning_count,
                "details": result.stderr.split('\n')[-10:] if result.stderr else []
            }
        else:
            return {"status": "error", "details": result.stderr}
            
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "details": f"Timeout after {timeout}s"}
    except Exception as e:
        return {"status": "error", "details": str(e)}

def run_modelscan(cache_path: str) -> Dict:
    """Run modelscan on cached model directory."""
    print(f"🔎 Testing modelscan on {cache_path}")
    
    if not os.path.exists(cache_path):
        return {"status": "no_cache", "details": "Model not cached"}
    
    try:
        ms_bin = shutil.which("modelscan")
        if not ms_bin:
            return {"status": "error", "details": "modelscan binary not found in PATH"}
        result = subprocess.run(
            [ms_bin, "-p", cache_path],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        output = result.stdout
        
        # Parse modelscan output
        if "No issues found!" in output:
            return {"status": "clean", "issues": 0}
        
        # Count issues by severity
        critical = output.count("CRITICAL:")
        high = output.count("HIGH:")
        medium = output.count("MEDIUM:")
        low = output.count("LOW:")
        
        total_issues = critical + high + medium + low
        skipped = 0
        
        # Extract skipped count
        if "Total skipped:" in output:
            try:
                skipped_line = [line for line in output.split('\n') if 'Total skipped:' in line][0]
                skipped = int(skipped_line.split('Total skipped:')[1].split()[0])
            except:
                pass
        
        return {
            "status": "issues_found" if total_issues > 0 else "clean",
            "issues": total_issues,
            "critical": critical,
            "high": high, 
            "medium": medium,
            "low": low,
            "skipped": skipped
        }
        
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "details": "Timeout after 120s"}
    except Exception as e:
        return {"status": "error", "details": str(e)}

def test_category(category: str, models: List[str]) -> Dict:
    """Test a category of models."""
    print(f"\n{'='*60}")
    print(f"🧪 TESTING CATEGORY: {category}")
    print(f"{'='*60}")
    
    results = {}
    
    for model in models:
        print(f"\n--- Testing {model} ---")
        
        # Test with ModelAudit 
        ma_result = run_modelaudit(model, timeout=180)
        
        # Determine cache path for modelscan
        cache_root = os.getenv("MODELAUDIT_CACHE_ROOT", str(Path.home() / ".modelaudit" / "cache" / "huggingface"))
        cache_path = str(Path(cache_root) / model)
        
        # Test with modelscan (on cached files)
        ms_result = run_modelscan(cache_path)
        
        results[model] = {
            "modelaudit": ma_result,
            "modelscan": ms_result
        }
        
        # Print comparison
        ma_issues = ma_result.get('issues', 0)
        ms_issues = ms_result.get('issues', 0)
        
        print(f"  ModelAudit: {ma_issues} issues ({ma_result['status']})")
        print(f"  modelscan:  {ms_issues} issues ({ms_result['status']})")
        
        if ma_result['status'] in ['issues_found'] and ms_result['status'] == 'clean':
            print(f"  🚨 ModelAudit found issues that modelscan missed!")
        elif ms_result['status'] == 'issues_found' and ma_result['status'] == 'clean':
            print(f"  ⚠️  modelscan found issues that ModelAudit missed!")
        
        # Small delay between models
        time.sleep(2)
    
    return results

def generate_report(all_results: Dict) -> str:
    """Generate comprehensive comparison report."""
    report = []
    report.append("# Comprehensive ModelAudit vs modelscan Comparison Report\n")
    
    modelaudit_advantages = []
    modelscan_advantages = []
    both_detect = []
    both_clean = []
    
    for category, models in all_results.items():
        report.append(f"## Category: {category}\n")
        
        for model, results in models.items():
            ma = results['modelaudit']
            ms = results['modelscan']
            
            ma_issues = ma.get('issues', 0)
            ms_issues = ms.get('issues', 0)
            
            report.append(f"### {model}")
            report.append(f"- **ModelAudit**: {ma_issues} issues ({ma['status']})")
            report.append(f"- **modelscan**: {ms_issues} issues ({ms['status']})")
            
            if ma['status'] == 'issues_found' and ms['status'] in ['clean', 'no_cache']:
                modelaudit_advantages.append(f"{model} ({category})")
                report.append(f"- 🚨 **ModelAudit Advantage**: Found {ma_issues} issues, modelscan found none")
            elif ms['status'] == 'issues_found' and ma['status'] == 'clean':
                modelscan_advantages.append(f"{model} ({category})")
                report.append(f"- ⚠️ **modelscan Advantage**: Found {ms_issues} issues, ModelAudit found none")
            elif ma['status'] == 'issues_found' and ms['status'] == 'issues_found':
                both_detect.append(f"{model} ({category}) - MA:{ma_issues} vs MS:{ms_issues}")
                report.append(f"- ✅ **Both Detected**: ModelAudit {ma_issues}, modelscan {ms_issues}")
            else:
                both_clean.append(f"{model} ({category})")
                report.append(f"- ✅ **Both Clean**: No issues detected by either tool")
                
            report.append("")
        
        report.append("")
    
    # Summary section
    report.append("## Summary Analysis\n")
    report.append(f"### ModelAudit Exclusive Detections ({len(modelaudit_advantages)})")
    for item in modelaudit_advantages:
        report.append(f"- {item}")
    
    report.append(f"\n### modelscan Exclusive Detections ({len(modelscan_advantages)})")
    for item in modelscan_advantages:
        report.append(f"- {item}")
    
    report.append(f"\n### Both Tools Detected Issues ({len(both_detect)})")
    for item in both_detect:
        report.append(f"- {item}")
        
    report.append(f"\n### Both Tools Clean ({len(both_clean)})")
    for item in both_clean:
        report.append(f"- {item}")
    
    return "\n".join(report)

def main():
    if len(sys.argv) > 1:
        # Test specific category
        category = sys.argv[1].upper()
        if category in TEST_MODELS:
            results = {category: test_category(category, TEST_MODELS[category])}
        else:
            print(f"Unknown category: {category}")
            print(f"Available: {list(TEST_MODELS.keys())}")
            return
    else:
        # Test all categories (this will take a long time!)
        total_categories = len(TEST_MODELS)
        total_models = sum(len(models) for models in TEST_MODELS.values())
        est_time_per_model_min = 2  # Adjust as appropriate for your environment
        est_total_time_min = total_models * est_time_per_model_min
        est_total_time_hr = est_total_time_min / 60
        print(f"⚠️  This will test ALL models: {total_models} models in {total_categories} categories.")
        print(f"Estimated time: ~{est_total_time_min:.0f} minutes (~{est_total_time_hr:.1f} hours)")
        response = input("Continue? (y/N): ")
        if response.lower() != 'y':
            return
        
        results = {}
        partial_file = "comprehensive_comparison_report_partial.json"
        for idx, (category, models) in enumerate(TEST_MODELS.items(), 1):
            print(f"\n[{idx}/{total_categories}] Testing category: {category} ({len(models)} models)")
            results[category] = test_category(category, models)
            # Save intermediate results
            with open(partial_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Progress: {idx}/{total_categories} categories complete. Partial results saved to {partial_file}.")
    
    # Generate and save report
    report = generate_report(results)
    
    output_file = "comprehensive_comparison_report.md"
    with open(output_file, 'w') as f:
        f.write(report)
    
    # Clean up partial file if it exists
    partial_file = "comprehensive_comparison_report_partial.json"
    if os.path.exists(partial_file):
        os.remove(partial_file)
    
    print(f"\n🎉 Report saved to: {output_file}")

if __name__ == "__main__":
    main()