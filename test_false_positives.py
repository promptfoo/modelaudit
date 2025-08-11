#!/usr/bin/env python3
"""Test for false positives in embedded secrets detection."""

import pickle
import json
import numpy as np
import tempfile
from pathlib import Path
from modelaudit.secrets_detector import SecretsDetector

def create_test_models():
    """Create various test models that should NOT trigger secret detection."""
    test_cases = []
    
    # 1. Normal ML model with weights
    model1 = {
        "model_type": "transformer",
        "config": {
            "hidden_size": 768,
            "num_layers": 12,
            "num_attention_heads": 12,
            "vocab_size": 50257,
            "max_position_embeddings": 1024,
        },
        "weights": {
            "encoder.layer_0.weight": np.random.randn(768, 768).astype(np.float32),
            "encoder.layer_0.bias": np.random.randn(768).astype(np.float32),
            "encoder.layer_1.weight": np.random.randn(768, 768).astype(np.float32),
            "embedding.token_embedding": np.random.randn(50257, 768).astype(np.float32),
        },
        "training_info": {
            "optimizer": "adam",
            "learning_rate": 0.0001,
            "batch_size": 32,
            "epochs": 100,
            "checkpoint_5000": "saved",
            "model_v1.2.3": "loaded",
        }
    }
    test_cases.append(("Normal Transformer Model", model1))
    
    # 2. Model with hash values (should not be flagged)
    model2 = {
        "metadata": {
            "model_hash": "a1b2c3d4e5f6789012345678901234567890abcd",  # SHA1
            "checkpoint_md5": "098f6bcd4621d373cade4e832627b4f6",  # MD5
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        "layers": {
            "layer_0": np.random.randn(512, 512),
            "layer_1": np.random.randn(512, 512),
        }
    }
    test_cases.append(("Model with Hash Values", model2))
    
    # 3. Model with UUIDs (should not be flagged unless in secret context)
    model3 = {
        "model_id": "550e8400-e29b-41d4-a716-446655440000",  # Valid UUID
        "experiment_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "weights": {
            "conv1": np.random.randn(64, 3, 7, 7),
            "conv2": np.random.randn(128, 64, 3, 3),
        }
    }
    test_cases.append(("Model with UUIDs", model3))
    
    # 4. Model with base64-encoded weights (legitimate use)
    import base64
    model4 = {
        "architecture": "resnet50",
        "encoded_weights": {
            # These are legitimate encoded model weights, not secrets
            "layer1": base64.b64encode(np.random.randn(100).astype(np.float32).tobytes()).decode(),
            "layer2": base64.b64encode(np.random.randn(100).astype(np.float32).tobytes()).decode(),
        },
        "config": {
            "input_shape": [224, 224, 3],
            "num_classes": 1000,
        }
    }
    test_cases.append(("Model with Base64 Weights", model4))
    
    # 5. Model with version strings and identifiers
    model5 = {
        "model_name": "bert-base-uncased",
        "version": "1.0.0",
        "pytorch_version": "1.9.0+cu111",
        "transformers_version": "4.20.1",
        "model_card": {
            "model_id": "bert_base_uncased_finetuned",
            "training_data": "wikipedia_en",
            "performance": {
                "accuracy": 0.92,
                "f1_score": 0.89,
            }
        },
        "state_dict": {
            "bert.encoder.layer.0.attention.self.query.weight": np.random.randn(768, 768),
            "bert.encoder.layer.0.attention.self.key.weight": np.random.randn(768, 768),
        }
    }
    test_cases.append(("BERT Model with Metadata", model5))
    
    # 6. Edge case: Model with strings that might look suspicious but aren't
    model6 = {
        "description": "Model trained on AWS EC2 p3.2xlarge instance",
        "training_script": "python train.py --api-endpoint http://localhost:8080",
        "hyperparameters": {
            "optimizer_type": "adam",
            "scheduler_type": "cosine",
            "warmup_steps": 1000,
            "max_steps": 50000,
        },
        "weights": np.random.randn(1000, 1000),
        "vocab": {
            "token_0": 0,
            "token_1": 1,
            "special_tokens": ["[CLS]", "[SEP]", "[MASK]", "[PAD]"],
        }
    }
    test_cases.append(("Model with AWS/API mentions", model6))
    
    return test_cases


def test_false_positives():
    """Test each model for false positives."""
    detector = SecretsDetector()
    test_cases = create_test_models()
    
    print("Testing for false positives in ML models")
    print("=" * 60)
    
    total_tests = len(test_cases)
    false_positives = []
    
    for name, model_data in test_cases:
        print(f"\nTesting: {name}")
        print("-" * 40)
        
        # Test the model data
        findings = detector.scan_model_weights(model_data, context=name)
        
        if findings:
            print(f"  ⚠️  FOUND {len(findings)} potential secrets")
            false_positives.append((name, findings))
            
            # Show details
            for finding in findings[:3]:  # Show first 3
                print(f"    - Type: {finding.get('secret_type', 'Unknown')}")
                print(f"      Confidence: {finding.get('confidence', 0)}")
                print(f"      Message: {finding.get('message', '')}")
                if 'redacted_value' in finding:
                    print(f"      Value: {finding.get('redacted_value', '')}")
        else:
            print(f"  ✅ PASS - No false positives")
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    fp_count = len(false_positives)
    fp_rate = (fp_count / total_tests) * 100 if total_tests > 0 else 0
    
    print(f"Total test cases: {total_tests}")
    print(f"False positives: {fp_count}")
    print(f"False positive rate: {fp_rate:.1f}%")
    
    if fp_rate < 1:
        print("\n✅ SUCCESS: False positive rate is less than 1%")
    else:
        print(f"\n❌ FAILURE: False positive rate ({fp_rate:.1f}%) exceeds 1% threshold")
        print("\nModels with false positives:")
        for name, findings in false_positives:
            print(f"  - {name}: {len(findings)} false positives")
    
    # Also test with actual pickle files
    print("\n" + "=" * 60)
    print("Testing with pickle files")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        
        for name, model_data in test_cases[:3]:  # Test first 3 as pickle
            pkl_file = tmppath / f"{name.replace(' ', '_')}.pkl"
            with open(pkl_file, "wb") as f:
                pickle.dump(model_data, f)
            
            print(f"\nTesting pickle: {pkl_file.name}")
            
            # Use the pickle scanner
            from modelaudit.scanners.pickle_scanner import PickleScanner
            scanner = PickleScanner({"check_secrets": True})
            result = scanner.scan(str(pkl_file))
            
            # Check for secret-related failures
            secret_issues = [
                c for c in result.checks 
                if "Embedded Secrets" in c.name and c.status.value == "failed"
            ]
            
            if secret_issues:
                print(f"  ⚠️  FOUND {len(secret_issues)} secret issues in pickle")
                for issue in secret_issues[:2]:
                    print(f"    - {issue.message}")
            else:
                print(f"  ✅ PASS - No secrets detected in pickle")
    
    return fp_rate < 1


if __name__ == "__main__":
    import sys
    success = test_false_positives()
    sys.exit(0 if success else 1)