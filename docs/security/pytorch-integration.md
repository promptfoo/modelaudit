# ModelAudit PyTorch Integration

Comprehensive guide for integrating ModelAudit security scanning into PyTorch development workflows.

## Automated Security Scanning

### 1. Development Workflow

```bash
# Install ModelAudit with PyTorch support
pip install modelaudit[pytorch]

# Scan model before use
modelaudit my_model.pt --format json --output security_report.json

# Check exit code
if [ $? -eq 1 ]; then
    echo "Security issues found! Check security_report.json"
    exit 1
fi
```

### 2. Python Integration

```python
from modelaudit import scan_file
import json

def secure_model_loading(model_path):
    """Load model only after security validation"""

    # Scan with ModelAudit
    result = scan_file(model_path)

    # Check for critical issues
    critical_issues = [
        issue for issue in result.issues
        if issue.severity == 'CRITICAL'
    ]

    if critical_issues:
        raise ValueError(f"Critical security issues found: {critical_issues}")

    # Check for CVE-2025-32434 specifically
    cve_issues = [
        issue for issue in result.issues
        if 'CVE-2025-32434' in issue.message
    ]

    if cve_issues:
        raise ValueError("Model vulnerable to CVE-2025-32434")

    # Proceed with safe loading
    return torch.load(model_path, weights_only=True, map_location='cpu')
```

### 3. Advanced Integration Patterns

```python
import torch
from modelaudit import scan_file
from contextlib import contextmanager

class SecureModelLoader:
    def __init__(self, trusted_sources=None, max_file_size=None):
        self.trusted_sources = trusted_sources or []
        self.max_file_size = max_file_size

    def load_model(self, model_path, scan_timeout=300):
        """Load model with comprehensive security validation"""

        # 1. Basic file validation
        self._validate_file(model_path)

        # 2. Security scan with ModelAudit
        scan_result = scan_file(model_path, timeout=scan_timeout)
        self._process_scan_results(scan_result)

        # 3. Safe loading with PyTorch
        return self._safe_torch_load(model_path)

    def _validate_file(self, model_path):
        """Basic file validation"""
        import os

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")

        file_size = os.path.getsize(model_path)
        if self.max_file_size and file_size > self.max_file_size:
            raise ValueError(f"Model file too large: {file_size} bytes")

    def _process_scan_results(self, scan_result):
        """Process ModelAudit scan results"""
        if not scan_result.success:
            raise ValueError("Model scan failed")

        # Categorize issues
        critical_issues = []
        high_issues = []

        for issue in scan_result.issues:
            if issue.severity == 'CRITICAL':
                critical_issues.append(issue)
            elif issue.severity == 'HIGH':
                high_issues.append(issue)

        # Fail on critical issues
        if critical_issues:
            raise ValueError(f"Critical security issues: {[i.message for i in critical_issues]}")

        # Warn on high issues
        if high_issues:
            import warnings
            warnings.warn(f"High severity issues found: {[i.message for i in high_issues]}")

    def _safe_torch_load(self, model_path):
        """Safely load with PyTorch"""
        try:
            return torch.load(model_path, weights_only=True, map_location='cpu')
        except Exception as e:
            raise ValueError(f"PyTorch loading failed: {e}")

# Usage
loader = SecureModelLoader(max_file_size=1024*1024*1024)  # 1GB limit
model = loader.load_model('model.pt')
```

## CI/CD Integration

### GitHub Actions Example

```yaml
# .github/workflows/model-security.yml
name: Model Security Scan

on:
  pull_request:
    paths:
      - "**/*.pt"
      - "**/*.pth"
      - "**/*.pkl"

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install ModelAudit
        run: pip install modelaudit[all]

      - name: Scan PyTorch Models
        run: |
          find . -name "*.pt" -o -name "*.pth" -o -name "*.pkl" | while read model; do
            echo "Scanning $model..."
            modelaudit "$model" --format json --output "scan-$(basename $model).json"
            
            # Check for critical issues
            if jq -e '.issues[] | select(.severity == "CRITICAL")' "scan-$(basename $model).json" > /dev/null; then
              echo "❌ Critical security issues found in $model"
              cat "scan-$(basename $model).json" | jq '.issues[] | select(.severity == "CRITICAL")'
              exit 1
            fi
            
            echo "✅ $model passed security scan"
          done

      - name: Archive Security Reports
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: scan-*.json
```

### Pre-commit Hook Integration

```bash
#!/bin/sh
# .git/hooks/pre-commit

# Find all PyTorch model files
MODEL_FILES=$(find . -name "*.pt" -o -name "*.pth" -o -name "*.pkl" 2>/dev/null)

if [ -z "$MODEL_FILES" ]; then
    echo "No PyTorch model files found"
    exit 0
fi

echo "Scanning PyTorch models for security issues..."

# Scan each model file
for model in $MODEL_FILES; do
    echo "Scanning: $model"

    # Run ModelAudit scan
    if ! modelaudit "$model" --exit-code; then
        echo "❌ Security issues found in $model"
        echo "Please fix security issues before committing"
        exit 1
    fi

    echo "✅ $model passed security scan"
done

echo "All models passed security scanning"
```

### Docker Integration

```dockerfile
# Multi-stage build for secure model validation
FROM python:3.11-slim as scanner

# Install ModelAudit
RUN pip install modelaudit[all]

# Copy models for scanning
COPY models/ /models/

# Scan all models
RUN find /models -name "*.pt" -o -name "*.pth" -o -name "*.pkl" | \
    xargs -I {} modelaudit {} --exit-code

# Production stage - only include validated models
FROM python:3.11-slim as production

# Copy validated models
COPY --from=scanner /models/ /app/models/

# Install application dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Run application
CMD ["python", "app.py"]
```

## Integration Patterns

### Model Registry Integration

```python
class SecureModelRegistry:
    def __init__(self, registry_client, scan_on_upload=True):
        self.registry = registry_client
        self.scan_on_upload = scan_on_upload

    def upload_model(self, model_path, model_name, version):
        """Upload model with security validation"""

        if self.scan_on_upload:
            # Scan before upload
            scan_result = scan_file(model_path)

            if not scan_result.success or any(i.severity == 'CRITICAL' for i in scan_result.issues):
                raise ValueError("Model failed security scan - upload rejected")

        # Upload to registry
        return self.registry.upload(model_path, model_name, version)

    def download_model(self, model_name, version, scan_on_download=True):
        """Download and validate model"""

        # Download from registry
        model_path = self.registry.download(model_name, version)

        if scan_on_download:
            # Scan after download
            scan_result = scan_file(model_path)

            if not scan_result.success or any(i.severity == 'CRITICAL' for i in scan_result.issues):
                os.remove(model_path)  # Clean up
                raise ValueError("Downloaded model failed security scan")

        return model_path
```

### MLOps Pipeline Integration

```python
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class ModelValidationResult:
    model_path: str
    passed: bool
    issues: List[dict]
    scan_time: float

class MLOpsSecurityGate:
    def __init__(self, fail_on_critical=True, fail_on_high=False):
        self.fail_on_critical = fail_on_critical
        self.fail_on_high = fail_on_high

    def validate_model_for_deployment(self, model_path) -> ModelValidationResult:
        """Comprehensive model validation for deployment"""
        import time

        start_time = time.time()

        # Scan model
        scan_result = scan_file(model_path)

        # Process results
        issues = []
        critical_count = 0
        high_count = 0

        for issue in scan_result.issues:
            issue_dict = {
                'severity': issue.severity,
                'message': issue.message,
                'location': getattr(issue, 'location', 'unknown')
            }
            issues.append(issue_dict)

            if issue.severity == 'CRITICAL':
                critical_count += 1
            elif issue.severity == 'HIGH':
                high_count += 1

        # Determine if validation passed
        passed = True
        if self.fail_on_critical and critical_count > 0:
            passed = False
        if self.fail_on_high and high_count > 0:
            passed = False

        scan_time = time.time() - start_time

        return ModelValidationResult(
            model_path=model_path,
            passed=passed,
            issues=issues,
            scan_time=scan_time
        )
```

## Monitoring and Alerting

### Security Monitoring

```python
import logging
from datetime import datetime

class ModelSecurityMonitor:
    def __init__(self, log_file='model_security.log'):
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('ModelSecurity')

    def log_scan_results(self, model_path, scan_result):
        """Log model scan results"""

        critical_issues = [i for i in scan_result.issues if i.severity == 'CRITICAL']
        high_issues = [i for i in scan_result.issues if i.severity == 'HIGH']

        if critical_issues:
            self.logger.critical(f"CRITICAL issues in {model_path}: {len(critical_issues)} issues")
            for issue in critical_issues:
                self.logger.critical(f"  - {issue.message}")

        if high_issues:
            self.logger.warning(f"HIGH issues in {model_path}: {len(high_issues)} issues")

        if not critical_issues and not high_issues:
            self.logger.info(f"Model {model_path} passed security scan")

    def alert_on_critical_issues(self, model_path, issues):
        """Send alerts for critical security issues"""
        # Implementation depends on your alerting system
        # Could integrate with Slack, email, PagerDuty, etc.
        pass
```

### Metrics Collection

```python
from collections import defaultdict
import json

class SecurityMetricsCollector:
    def __init__(self):
        self.metrics = defaultdict(int)
        self.scan_history = []

    def record_scan(self, model_path, scan_result):
        """Record scan metrics"""

        self.metrics['total_scans'] += 1

        for issue in scan_result.issues:
            self.metrics[f'{issue.severity.lower()}_issues'] += 1

        # Record scan history
        self.scan_history.append({
            'timestamp': datetime.now().isoformat(),
            'model_path': model_path,
            'issues_count': len(scan_result.issues),
            'critical_count': len([i for i in scan_result.issues if i.severity == 'CRITICAL'])
        })

    def get_metrics_summary(self):
        """Get summary of security metrics"""
        return dict(self.metrics)

    def export_metrics(self, output_path):
        """Export metrics to JSON"""
        with open(output_path, 'w') as f:
            json.dump({
                'summary': self.get_metrics_summary(),
                'history': self.scan_history
            }, f, indent=2)
```

## Best Practices

### Development Integration

1. **Scan all models** before committing to version control
2. **Use pre-commit hooks** to enforce security scanning
3. **Integrate with IDE** for real-time feedback
4. **Set up automated scanning** in development pipelines

### Production Integration

1. **Scan models** before deployment to production
2. **Implement security gates** in MLOps pipelines
3. **Monitor model security** in production
4. **Log all security events** for audit trails

### Team Practices

1. **Train developers** on secure model handling
2. **Establish security policies** for model management
3. **Regular security reviews** of model pipelines
4. **Incident response procedures** for security issues

## Related Guides

- [PyTorch Security Overview](pytorch-overview.md) - Understanding threat vectors
- [Safe Loading Practices](pytorch-safe-loading.md) - Secure loading techniques
- [Supply Chain Security](pytorch-supply-chain.md) - Model source validation
- [Security Checklist](pytorch-checklist.md) - Complete security checklist
