#!/usr/bin/env python3
"""Test that real secrets ARE detected (true positives)."""

import pickle
import tempfile
from pathlib import Path
from modelaudit.secrets_detector import SecretsDetector

def create_models_with_secrets():
    """Create test models that SHOULD trigger secret detection."""
    test_cases = []
    
    # 1. Model with real AWS credentials
    model1 = {
        "model_type": "classifier",
        "config": {
            "aws_access_key_id": "AKIAIOSFODNN7REALKEY",  # Not the example key
            "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREALSECRET",
            "region": "us-east-1",
        },
        "weights": [1.0, 2.0, 3.0],
    }
    test_cases.append(("Model with AWS Credentials", model1))
    
    # 2. Model with API keys
    model2 = {
        "training_config": {
            "openai_api_key": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ",
            "github_token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        },
        "model_weights": {"layer1": [0.1, 0.2, 0.3]},
    }
    test_cases.append(("Model with API Keys", model2))
    
    # 3. Model with database connection string
    model3 = {
        "database_config": {
            "connection": "mongodb+srv://admin:SuperSecretPassword123@cluster.mongodb.net/production",
            "backup_connection": "postgres://user:password123@prod-db.example.com:5432/maindb",
        },
        "model": {"weights": [1, 2, 3]},
    }
    test_cases.append(("Model with Database Credentials", model3))
    
    # 4. Model with JWT token
    model4 = {
        "auth": {
            "jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.cThIIoDvwdueQB468K5xDc5633seEFoqwxjF-xFnRyQ",
            "api_key": "my-super-secret-api-key-123456789",
        },
        "model_data": [1, 2, 3],
    }
    test_cases.append(("Model with JWT and API Key", model4))
    
    # 5. Model with private key
    model5 = {
        "deployment": {
            "ssh_key": """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx7kXfUcXdWZbJmpMqmvRfKEwKqNyL+kXBV0KxhE3xXaZpkQf
fake_private_key_content_here_for_testing_purposes_only
-----END RSA PRIVATE KEY-----""",
        },
        "weights": [0.5, 0.6, 0.7],
    }
    test_cases.append(("Model with Private Key", model5))
    
    return test_cases


def test_true_positives():
    """Test that real secrets are detected."""
    detector = SecretsDetector()
    test_cases = create_models_with_secrets()
    
    print("Testing detection of real embedded secrets")
    print("=" * 60)
    
    total_tests = len(test_cases)
    detected = []
    missed = []
    
    for name, model_data in test_cases:
        print(f"\nTesting: {name}")
        print("-" * 40)
        
        # Test the model data
        findings = detector.scan_model_weights(model_data, context=name)
        
        if findings:
            print(f"  ✅ DETECTED {len(findings)} secrets")
            detected.append((name, findings))
            
            # Show details
            for finding in findings[:3]:  # Show first 3
                print(f"    - Type: {finding.get('secret_type', 'Unknown')}")
                print(f"      Confidence: {finding.get('confidence', 0)}")
                print(f"      Severity: {finding.get('severity', 'Unknown')}")
                if 'redacted_value' in finding:
                    print(f"      Value: {finding.get('redacted_value', '')}")
        else:
            print(f"  ❌ MISSED - No secrets detected")
            missed.append(name)
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    detection_rate = (len(detected) / total_tests) * 100 if total_tests > 0 else 0
    
    print(f"Total test cases: {total_tests}")
    print(f"Detected: {len(detected)}")
    print(f"Missed: {len(missed)}")
    print(f"Detection rate: {detection_rate:.1f}%")
    
    if detection_rate >= 80:
        print("\n✅ SUCCESS: Detection rate is good (>= 80%)")
    else:
        print(f"\n⚠️  WARNING: Detection rate ({detection_rate:.1f}%) is below 80%")
        if missed:
            print("\nMissed detections:")
            for name in missed:
                print(f"  - {name}")
    
    # Test with pickle files
    print("\n" + "=" * 60)
    print("Testing with pickle files")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        
        # Test one model as pickle
        name, model_data = test_cases[0]  # AWS credentials
        pkl_file = tmppath / "model_with_secrets.pkl"
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
            print(f"  ✅ DETECTED {len(secret_issues)} secrets in pickle")
            for issue in secret_issues[:2]:
                print(f"    - {issue.message}")
                if issue.details:
                    if "secret_type" in issue.details:
                        print(f"      Type: {issue.details['secret_type']}")
        else:
            print(f"  ❌ MISSED - No secrets detected in pickle")
    
    return detection_rate >= 80


if __name__ == "__main__":
    import sys
    success = test_true_positives()
    sys.exit(0 if success else 1)