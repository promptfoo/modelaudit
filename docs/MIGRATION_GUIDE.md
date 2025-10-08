# Directory Structure Migration Guide

This guide provides step-by-step instructions for executing the ModelAudit directory structure refactoring.

## Overview

**Goal**: Reorganize 38 files into clearer conceptual groups
**Phases**: 4 independent phases (can be executed separately)
**Total Time**: 4.5-5.5 hours
**Risk**: Medium (requires comprehensive import updates)

---

## Pre-Migration Checklist

Before starting any phase:

- [ ] Create feature branch: `git checkout -b refactor/directory-structure`
- [ ] Ensure clean working directory: `git status`
- [ ] Run full test suite: `rye run pytest -n auto`
- [ ] Verify all tests pass
- [ ] Have rollback plan ready (see below)

---

## Phase 1: Flatten Single-File Directories

**Time**: 30 minutes | **Risk**: Low | **Import Changes**: ~15

### What We're Doing

Moving 3 files from single-file directories to root:

```
context/unified_context.py      → unified_context.py
knowledge/framework_patterns.py → framework_patterns.py
name_policies/blacklist.py      → name_blacklist.py
```

### Step-by-Step Instructions

#### 1.1 Move Files

```bash
# Navigate to project root
cd /Users/mdangelo/projects/modelaudit

# Move files using git mv to preserve history
git mv modelaudit/context/unified_context.py modelaudit/unified_context.py
git mv modelaudit/knowledge/framework_patterns.py modelaudit/framework_patterns.py
git mv modelaudit/name_policies/blacklist.py modelaudit/name_blacklist.py

# Delete empty directories
rmdir modelaudit/context
rmdir modelaudit/knowledge
rmdir modelaudit/name_policies
```

#### 1.2 Update Imports (Automated)

```bash
# Update unified_context imports
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.context import unified_context/from modelaudit import unified_context/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.context\.unified_context/from modelaudit.unified_context/g' {} +

# Update framework_patterns imports
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.knowledge import framework_patterns/from modelaudit import framework_patterns/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.knowledge\.framework_patterns/from modelaudit.framework_patterns/g' {} +

# Update blacklist imports (renamed to name_blacklist)
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.name_policies import blacklist/from modelaudit import name_blacklist/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.name_policies\.blacklist/from modelaudit.name_blacklist/g' {} +

# Handle potential "import blacklist" statements (need manual review)
rg "import blacklist" modelaudit/ tests/ --type py
```

#### 1.3 Verification

```bash
# Check for any remaining old imports
rg "from modelaudit\.context" modelaudit/ tests/
rg "from modelaudit\.knowledge" modelaudit/ tests/
rg "from modelaudit\.name_policies" modelaudit/ tests/

# Syntax check
python -m py_compile modelaudit/*.py

# Run fast tests
rye run pytest -n auto -m "not slow and not integration" -v

# Type checking
rye run mypy modelaudit/

# Linting
rye run ruff check modelaudit/ tests/
```

#### 1.4 Commit

```bash
git add -A
git commit -m "refactor: flatten single-file directories (context, knowledge, name_policies)

- Move unified_context.py to root
- Move framework_patterns.py to root
- Rename blacklist.py to name_blacklist.py and move to root
- Update all imports accordingly
- Remove empty directories

This reduces unnecessary nesting and makes imports more straightforward."
```

---

## Phase 2: Create `detectors/` Module

**Time**: 1 hour | **Risk**: Medium | **Import Changes**: ~40

### What We're Doing

Creating `detectors/` directory and moving 5 security detection modules:

```
cve_patterns.py           → detectors/cve_patterns.py
jit_script_detector.py    → detectors/jit_script.py (renamed)
network_comm_detector.py  → detectors/network_comm.py (renamed)
secrets_detector.py       → detectors/secrets.py (renamed)
suspicious_symbols.py     → detectors/suspicious_symbols.py
```

### Step-by-Step Instructions

#### 2.1 Create Directory & Move Files

```bash
# Create detectors directory
mkdir modelaudit/detectors

# Move files (some renamed to remove redundant _detector suffix)
git mv modelaudit/cve_patterns.py modelaudit/detectors/cve_patterns.py
git mv modelaudit/jit_script_detector.py modelaudit/detectors/jit_script.py
git mv modelaudit/network_comm_detector.py modelaudit/detectors/network_comm.py
git mv modelaudit/secrets_detector.py modelaudit/detectors/secrets.py
git mv modelaudit/suspicious_symbols.py modelaudit/detectors/suspicious_symbols.py
```

#### 2.2 Create `__init__.py`

```bash
cat > modelaudit/detectors/__init__.py << 'EOF'
"""Security threat detection modules.

This package contains specialized detectors for identifying security threats in model files:
- CVE patterns (known vulnerabilities)
- Secrets (API keys, tokens, credentials)
- JIT/script code (TorchScript, executable code)
- Network communication (URLs, IPs, sockets)
- Suspicious symbols (dangerous function calls)
"""

from modelaudit.detectors import cve_patterns
from modelaudit.detectors import jit_script
from modelaudit.detectors import network_comm
from modelaudit.detectors import secrets
from modelaudit.detectors import suspicious_symbols

__all__ = [
    "cve_patterns",
    "jit_script",
    "network_comm",
    "secrets",
    "suspicious_symbols",
]
EOF
```

#### 2.3 Update Imports (Automated)

```bash
# CVE patterns
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit import cve_patterns/from modelaudit.detectors import cve_patterns/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.cve_patterns/from modelaudit.detectors.cve_patterns/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/import modelaudit\.cve_patterns/import modelaudit.detectors.cve_patterns/g' {} +

# JIT script (renamed from jit_script_detector)
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit import jit_script_detector/from modelaudit.detectors import jit_script/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.jit_script_detector/from modelaudit.detectors.jit_script/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/import modelaudit\.jit_script_detector/import modelaudit.detectors.jit_script/g' {} +

# Network comm (renamed from network_comm_detector)
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit import network_comm_detector/from modelaudit.detectors import network_comm/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.network_comm_detector/from modelaudit.detectors.network_comm/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/import modelaudit\.network_comm_detector/import modelaudit.detectors.network_comm/g' {} +

# Secrets (renamed from secrets_detector)
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit import secrets_detector/from modelaudit.detectors import secrets/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.secrets_detector/from modelaudit.detectors.secrets/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/import modelaudit\.secrets_detector/import modelaudit.detectors.secrets/g' {} +

# Suspicious symbols
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit import suspicious_symbols/from modelaudit.detectors import suspicious_symbols/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.suspicious_symbols/from modelaudit.detectors.suspicious_symbols/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/import modelaudit\.suspicious_symbols/import modelaudit.detectors.suspicious_symbols/g' {} +
```

#### 2.4 Verification

```bash
# Check for remaining old imports
rg "from modelaudit import (cve_patterns|jit_script_detector|network_comm_detector|secrets_detector|suspicious_symbols)" modelaudit/ tests/ --type py
rg "from modelaudit\.(cve_patterns|jit_script_detector|network_comm_detector|secrets_detector|suspicious_symbols)" modelaudit/ tests/ --type py

# Syntax check
python -m py_compile modelaudit/detectors/*.py

# Run tests
rye run pytest -n auto -m "not slow and not integration" -v

# Type checking
rye run mypy modelaudit/

# Linting
rye run ruff check modelaudit/ tests/
```

#### 2.5 Commit

```bash
git add -A
git commit -m "refactor: create detectors/ module for security detection

- Create detectors/ directory
- Move 5 detector modules: cve_patterns, jit_script, network_comm, secrets, suspicious_symbols
- Rename files to remove redundant _detector suffix
- Update all imports across codebase (~40 files)
- Add detectors/__init__.py with module documentation

This groups security detection modules conceptually for easier navigation."
```

---

## Phase 3: Create `integrations/` Module

**Time**: 1 hour | **Risk**: Medium | **Import Changes**: ~10

### What We're Doing

Creating `integrations/` directory and moving 5 external integration modules:

```
jfrog_integration.py → integrations/jfrog.py (renamed)
mlflow_integration.py → integrations/mlflow.py (renamed)
license_checker.py → integrations/license_checker.py
sbom.py → integrations/sbom_generator.py (renamed)
sarif_formatter.py → integrations/sarif_formatter.py
```

### Step-by-Step Instructions

#### 3.1 Create Directory & Move Files

```bash
# Create integrations directory
mkdir modelaudit/integrations

# Move files (some renamed to remove redundant _integration suffix)
git mv modelaudit/jfrog_integration.py modelaudit/integrations/jfrog.py
git mv modelaudit/mlflow_integration.py modelaudit/integrations/mlflow.py
git mv modelaudit/license_checker.py modelaudit/integrations/license_checker.py
git mv modelaudit/sbom.py modelaudit/integrations/sbom_generator.py
git mv modelaudit/sarif_formatter.py modelaudit/integrations/sarif_formatter.py
```

#### 3.2 Create `__init__.py`

```bash
cat > modelaudit/integrations/__init__.py << 'EOF'
"""External system integrations.

This package contains integrations with external systems and output formats:
- JFrog Artifactory (model repository)
- MLflow (model registry)
- License checker (SPDX license compliance)
- SBOM generator (CycloneDX format)
- SARIF formatter (security analysis output)
"""

from modelaudit.integrations import jfrog
from modelaudit.integrations import mlflow
from modelaudit.integrations import license_checker
from modelaudit.integrations import sbom_generator
from modelaudit.integrations import sarif_formatter

__all__ = [
    "jfrog",
    "mlflow",
    "license_checker",
    "sbom_generator",
    "sarif_formatter",
]
EOF
```

#### 3.3 Update Imports (Automated)

```bash
# JFrog (renamed from jfrog_integration)
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit import jfrog_integration/from modelaudit.integrations import jfrog/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.jfrog_integration/from modelaudit.integrations.jfrog/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/import modelaudit\.jfrog_integration/import modelaudit.integrations.jfrog/g' {} +

# MLflow (renamed from mlflow_integration)
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit import mlflow_integration/from modelaudit.integrations import mlflow/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.mlflow_integration/from modelaudit.integrations.mlflow/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/import modelaudit\.mlflow_integration/import modelaudit.integrations.mlflow/g' {} +

# License checker
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit import license_checker/from modelaudit.integrations import license_checker/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.license_checker/from modelaudit.integrations.license_checker/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/import modelaudit\.license_checker/import modelaudit.integrations.license_checker/g' {} +

# SBOM (renamed from sbom)
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit import sbom/from modelaudit.integrations import sbom_generator/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.sbom/from modelaudit.integrations.sbom_generator/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/import modelaudit\.sbom/import modelaudit.integrations.sbom_generator/g' {} +

# SARIF formatter
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit import sarif_formatter/from modelaudit.integrations import sarif_formatter/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/from modelaudit\.sarif_formatter/from modelaudit.integrations.sarif_formatter/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' \
  's/import modelaudit\.sarif_formatter/import modelaudit.integrations.sarif_formatter/g' {} +
```

#### 3.4 Verification

```bash
# Check for remaining old imports
rg "from modelaudit import (jfrog_integration|mlflow_integration|license_checker|sbom|sarif_formatter)" modelaudit/ tests/ --type py
rg "from modelaudit\.(jfrog_integration|mlflow_integration|license_checker|sbom|sarif_formatter)" modelaudit/ tests/ --type py

# Syntax check
python -m py_compile modelaudit/integrations/*.py

# Run tests
rye run pytest -n auto -m "not slow and not integration" -v

# Type checking
rye run mypy modelaudit/

# Linting
rye run ruff check modelaudit/ tests/
```

#### 3.5 Commit

```bash
git add -A
git commit -m "refactor: create integrations/ module for external systems

- Create integrations/ directory
- Move 5 integration modules: jfrog, mlflow, license_checker, sbom_generator, sarif_formatter
- Rename files to remove redundant _integration suffix
- Update all imports in cli.py and core.py (~10 files)
- Add integrations/__init__.py with module documentation

This groups external system integrations conceptually for easier navigation."
```

---

## Phase 4: Reorganize `utils/` into Subcategories

**Time**: 2-3 hours | **Risk**: High | **Import Changes**: ~155

### What We're Doing

Reorganizing 20 utility files into 3 subcategories:

- `utils/file/` - File handling (5 files)
- `utils/sources/` - Model sources (5 files)
- `utils/helpers/` - Generic utilities (10 files)

### Step-by-Step Instructions

#### 4.1 Create Subdirectories

```bash
mkdir modelaudit/utils/file
mkdir modelaudit/utils/sources
mkdir modelaudit/utils/helpers
```

#### 4.2 Move File Handling Utilities

```bash
# File handling
git mv modelaudit/utils/filetype.py modelaudit/utils/file/detection.py
git mv modelaudit/utils/file_filter.py modelaudit/utils/file/filtering.py
git mv modelaudit/utils/advanced_file_handler.py modelaudit/utils/file/handlers.py
git mv modelaudit/utils/large_file_handler.py modelaudit/utils/file/large_file_handler.py
git mv modelaudit/utils/streaming.py modelaudit/utils/file/streaming.py
```

#### 4.3 Create `utils/file/__init__.py`

```bash
cat > modelaudit/utils/file/__init__.py << 'EOF'
"""File handling utilities.

This package contains utilities for file operations:
- detection.py - File type detection and format identification
- filtering.py - File filtering and pattern matching
- handlers.py - Advanced file handling strategies
- large_file_handler.py - Large file optimization
- streaming.py - Streaming file processing
"""

from modelaudit.utils.file import detection
from modelaudit.utils.file import filtering
from modelaudit.utils.file import handlers
from modelaudit.utils.file import large_file_handler
from modelaudit.utils.file import streaming

__all__ = [
    "detection",
    "filtering",
    "handlers",
    "large_file_handler",
    "streaming",
]
EOF
```

#### 4.4 Move Model Source Integrations

```bash
# Model sources
git mv modelaudit/utils/cloud_storage.py modelaudit/utils/sources/cloud_storage.py
git mv modelaudit/utils/dvc_utils.py modelaudit/utils/sources/dvc.py
git mv modelaudit/utils/huggingface.py modelaudit/utils/sources/huggingface.py
git mv modelaudit/utils/jfrog.py modelaudit/utils/sources/jfrog.py
git mv modelaudit/utils/pytorch_hub.py modelaudit/utils/sources/pytorch_hub.py
```

#### 4.5 Create `utils/sources/__init__.py`

```bash
cat > modelaudit/utils/sources/__init__.py << 'EOF'
"""Model source integrations.

This package contains utilities for accessing models from various sources:
- cloud_storage.py - S3, GCS, Azure Blob storage
- dvc.py - DVC (Data Version Control)
- huggingface.py - Hugging Face Hub
- jfrog.py - JFrog Artifactory utilities
- pytorch_hub.py - PyTorch Hub
"""

from modelaudit.utils.sources import cloud_storage
from modelaudit.utils.sources import dvc
from modelaudit.utils.sources import huggingface
from modelaudit.utils.sources import jfrog
from modelaudit.utils.sources import pytorch_hub

__all__ = [
    "cloud_storage",
    "dvc",
    "huggingface",
    "jfrog",
    "pytorch_hub",
]
EOF
```

#### 4.6 Move Generic Helpers

```bash
# Generic helpers
git mv modelaudit/utils/assets.py modelaudit/utils/helpers/assets.py
git mv modelaudit/utils/cache_decorator.py modelaudit/utils/helpers/cache_decorator.py
git mv modelaudit/utils/code_validation.py modelaudit/utils/helpers/code_validation.py
git mv modelaudit/utils/disk_space.py modelaudit/utils/helpers/disk_space.py
git mv modelaudit/utils/ml_context.py modelaudit/utils/helpers/ml_context.py
git mv modelaudit/utils/result_conversion.py modelaudit/utils/helpers/result_conversion.py
git mv modelaudit/utils/retry.py modelaudit/utils/helpers/retry.py
git mv modelaudit/utils/secure_hasher.py modelaudit/utils/helpers/secure_hasher.py
git mv modelaudit/utils/smart_detection.py modelaudit/utils/helpers/smart_detection.py
git mv modelaudit/utils/types.py modelaudit/utils/helpers/types.py
```

#### 4.7 Create `utils/helpers/__init__.py`

```bash
cat > modelaudit/utils/helpers/__init__.py << 'EOF'
"""Generic utility helpers.

This package contains general-purpose utility functions:
- assets.py - Asset management
- cache_decorator.py - Caching decorators
- code_validation.py - Code validation utilities
- disk_space.py - Disk space checking
- ml_context.py - ML framework context detection
- result_conversion.py - Result format conversion
- retry.py - Retry logic for transient failures
- secure_hasher.py - Secure hashing utilities
- smart_detection.py - Smart configuration detection
- types.py - Type definitions and aliases
"""

from modelaudit.utils.helpers import assets
from modelaudit.utils.helpers import cache_decorator
from modelaudit.utils.helpers import code_validation
from modelaudit.utils.helpers import disk_space
from modelaudit.utils.helpers import ml_context
from modelaudit.utils.helpers import result_conversion
from modelaudit.utils.helpers import retry
from modelaudit.utils.helpers import secure_hasher
from modelaudit.utils.helpers import smart_detection
from modelaudit.utils.helpers import types

__all__ = [
    "assets",
    "cache_decorator",
    "code_validation",
    "disk_space",
    "ml_context",
    "result_conversion",
    "retry",
    "secure_hasher",
    "smart_detection",
    "types",
]
EOF
```

#### 4.8 Update Imports (See Appendix A for Complete Commands)

**Note**: Due to the large number of imports (~155), we'll use a migration script. See `scripts/migrate_utils_imports.sh` in Appendix A.

```bash
# Run migration script
bash scripts/migrate_utils_imports.sh

# Or execute commands manually (see Appendix A)
```

#### 4.9 Verification

```bash
# Check for remaining old imports (file utilities)
rg "from modelaudit\.utils import (filetype|file_filter|advanced_file_handler|large_file_handler|streaming)" modelaudit/ tests/ --type py

# Check for remaining old imports (sources)
rg "from modelaudit\.utils import (cloud_storage|dvc_utils|huggingface|jfrog|pytorch_hub)" modelaudit/ tests/ --type py

# Check for remaining old imports (helpers)
rg "from modelaudit\.utils import (assets|cache_decorator|code_validation|disk_space|ml_context|result_conversion|retry|secure_hasher|smart_detection|types)" modelaudit/ tests/ --type py

# Syntax check
python -m py_compile modelaudit/utils/file/*.py
python -m py_compile modelaudit/utils/sources/*.py
python -m py_compile modelaudit/utils/helpers/*.py

# Run full test suite
rye run pytest -n auto -v

# Type checking
rye run mypy modelaudit/

# Linting
rye run ruff check modelaudit/ tests/
```

#### 4.10 Commit

```bash
git add -A
git commit -m "refactor: reorganize utils/ into file/sources/helpers subcategories

- Create utils/file/ for file handling utilities
- Create utils/sources/ for model source integrations
- Create utils/helpers/ for generic utilities
- Move 20 files into appropriate subcategories
- Rename some files for clarity (filetype→detection, dvc_utils→dvc)
- Update ~155 imports across codebase
- Add __init__.py for each subcategory with documentation

This makes utils/ more discoverable and conceptually organized."
```

---

## Post-Migration Checklist

After completing all phases:

- [ ] All tests pass: `rye run pytest -n auto`
- [ ] Type checking passes: `rye run mypy modelaudit/`
- [ ] Linting passes: `rye run ruff check modelaudit/ tests/`
- [ ] Format code: `rye run ruff format modelaudit/ tests/`
- [ ] Documentation updated: README.md, CLAUDE.md
- [ ] No remaining old imports (verify with rg patterns)
- [ ] Create PR with structure comparison

---

## Rollback Procedures

### Rollback Single Phase

If a phase fails, rollback to previous commit:

```bash
# Check current status
git status

# See recent commits
git log --oneline -5

# Rollback last commit (keep changes)
git reset --soft HEAD~1

# Rollback last commit (discard changes)
git reset --hard HEAD~1

# Rollback to specific commit
git reset --hard <commit-hash>
```

### Rollback Entire Refactoring

```bash
# Reset to main branch
git checkout main

# Delete feature branch
git branch -D refactor/directory-structure

# Start over
git checkout -b refactor/directory-structure
```

---

## Troubleshooting

### Import Errors After Migration

**Symptom**: `ModuleNotFoundError: No module named 'modelaudit.context'`

**Solution**:
```bash
# Find remaining old imports
rg "from modelaudit\.context" modelaudit/ tests/

# Update manually or re-run sed commands
```

### Tests Fail After Migration

**Symptom**: Tests pass individually but fail in suite

**Solution**:
```bash
# Clear pytest cache
rm -rf .pytest_cache

# Clear Python cache
find . -type d -name __pycache__ -exec rm -rf {} +

# Re-run tests
rye run pytest -n auto
```

### Type Checking Fails

**Symptom**: `error: Cannot find implementation or library stub`

**Solution**:
```bash
# Clear mypy cache
rm -rf .mypy_cache

# Re-run type checking
rye run mypy modelaudit/
```

### Circular Import Errors

**Symptom**: `ImportError: cannot import name 'X' from partially initialized module`

**Solution**:
- Check __init__.py files for circular dependencies
- Move imports inside functions if needed
- Review import order in affected files

---

## Appendix A: Complete Phase 4 Import Update Commands

Create script file: `scripts/migrate_utils_imports.sh`

```bash
#!/bin/bash
set -e

echo "Migrating utils/ imports..."

# File utilities
echo "Updating file utilities..."
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils import filetype/from modelaudit.utils.file import detection/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils\.filetype/from modelaudit.utils.file.detection/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/import modelaudit\.utils\.filetype/import modelaudit.utils.file.detection/g' {} +

find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils import file_filter/from modelaudit.utils.file import filtering/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils\.file_filter/from modelaudit.utils.file.filtering/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/import modelaudit\.utils\.file_filter/import modelaudit.utils.file.filtering/g' {} +

find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils import advanced_file_handler/from modelaudit.utils.file import handlers/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils\.advanced_file_handler/from modelaudit.utils.file.handlers/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/import modelaudit\.utils\.advanced_file_handler/import modelaudit.utils.file.handlers/g' {} +

find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils import large_file_handler/from modelaudit.utils.file import large_file_handler/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils\.large_file_handler/from modelaudit.utils.file.large_file_handler/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/import modelaudit\.utils\.large_file_handler/import modelaudit.utils.file.large_file_handler/g' {} +

find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils import streaming/from modelaudit.utils.file import streaming/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils\.streaming/from modelaudit.utils.file.streaming/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/import modelaudit\.utils\.streaming/import modelaudit.utils.file.streaming/g' {} +

# Source integrations
echo "Updating source integrations..."
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils import cloud_storage/from modelaudit.utils.sources import cloud_storage/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils\.cloud_storage/from modelaudit.utils.sources.cloud_storage/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/import modelaudit\.utils\.cloud_storage/import modelaudit.utils.sources.cloud_storage/g' {} +

find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils import dvc_utils/from modelaudit.utils.sources import dvc/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils\.dvc_utils/from modelaudit.utils.sources.dvc/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/import modelaudit\.utils\.dvc_utils/import modelaudit.utils.sources.dvc/g' {} +

find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils import huggingface/from modelaudit.utils.sources import huggingface/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils\.huggingface/from modelaudit.utils.sources.huggingface/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/import modelaudit\.utils\.huggingface/import modelaudit.utils.sources.huggingface/g' {} +

find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils import jfrog/from modelaudit.utils.sources import jfrog/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils\.jfrog/from modelaudit.utils.sources.jfrog/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/import modelaudit\.utils\.jfrog/import modelaudit.utils.sources.jfrog/g' {} +

find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils import pytorch_hub/from modelaudit.utils.sources import pytorch_hub/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/from modelaudit\.utils\.pytorch_hub/from modelaudit.utils.sources.pytorch_hub/g' {} +
find modelaudit tests -name "*.py" -type f -exec sed -i '' 's/import modelaudit\.utils\.pytorch_hub/import modelaudit.utils.sources.pytorch_hub/g' {} +

# Generic helpers (10 files)
echo "Updating generic helpers..."
for util in assets cache_decorator code_validation disk_space ml_context result_conversion retry secure_hasher smart_detection types; do
    find modelaudit tests -name "*.py" -type f -exec sed -i '' "s/from modelaudit\.utils import ${util}/from modelaudit.utils.helpers import ${util}/g" {} +
    find modelaudit tests -name "*.py" -type f -exec sed -i '' "s/from modelaudit\.utils\.${util}/from modelaudit.utils.helpers.${util}/g" {} +
    find modelaudit tests -name "*.py" -type f -exec sed -i '' "s/import modelaudit\.utils\.${util}/import modelaudit.utils.helpers.${util}/g" {} +
done

echo "Migration complete!"
```

Make executable:
```bash
chmod +x scripts/migrate_utils_imports.sh
```

---

## Appendix B: Verification Checklist

Use this checklist to verify each phase:

### Phase 1 Verification
- [ ] `context/` directory deleted
- [ ] `knowledge/` directory deleted
- [ ] `name_policies/` directory deleted
- [ ] `unified_context.py` in root
- [ ] `framework_patterns.py` in root
- [ ] `name_blacklist.py` in root
- [ ] No imports from old paths
- [ ] All tests pass

### Phase 2 Verification
- [ ] `detectors/` directory exists
- [ ] 5 detector files in `detectors/`
- [ ] `detectors/__init__.py` exists
- [ ] Old detector files deleted from root
- [ ] No imports from old paths
- [ ] All tests pass

### Phase 3 Verification
- [ ] `integrations/` directory exists
- [ ] 5 integration files in `integrations/`
- [ ] `integrations/__init__.py` exists
- [ ] Old integration files deleted from root
- [ ] No imports from old paths
- [ ] All tests pass

### Phase 4 Verification
- [ ] `utils/file/` directory exists with 5 files
- [ ] `utils/sources/` directory exists with 5 files
- [ ] `utils/helpers/` directory exists with 10 files
- [ ] All `__init__.py` files created
- [ ] Old utils files deleted
- [ ] No imports from old paths
- [ ] All tests pass
- [ ] Full test suite passes

---

## Support

If you encounter issues during migration:

1. **Check the troubleshooting section** above
2. **Review git log** to see what changed
3. **Use rollback procedures** if needed
4. **Run verification commands** to identify issues
5. **Create an issue** with error details if stuck

**Remember**: Each phase is independent and can be executed/rolled back separately.
