# ModelAudit Directory Structure Refactoring Plan

**Goal**: Reorganize files and directories to make the codebase structure more clear and obvious through better conceptual grouping.

**Scope**: File and directory moves ONLY - no function refactoring or code changes.

**Risk Level**: Medium (requires import updates across codebase)

**Estimated Effort**: 4-6 hours

---

## Current Directory Structure

```
modelaudit/
├── __init__.py
├── __main__.py
├── cli.py                          # 1928 lines - CLI entry point
├── core.py                         # 1372 lines - scanning orchestration
├── constants.py                    # Constants and enums
├── models.py                       # Pydantic data models
├── explanations.py                 # Issue explanations
├── interrupt_handler.py            # Signal handling
│
├── cve_patterns.py                 # CVE detection patterns [DETECTOR]
├── jit_script_detector.py          # JIT script detection [DETECTOR]
├── network_comm_detector.py        # Network communication detection [DETECTOR]
├── secrets_detector.py             # Secrets detection [DETECTOR]
├── suspicious_symbols.py           # Suspicious symbol detection [DETECTOR]
│
├── jfrog_integration.py            # JFrog Artifactory integration [INTEGRATION]
├── mlflow_integration.py           # MLflow integration [INTEGRATION]
├── license_checker.py              # License compliance checking [INTEGRATION]
├── sbom.py                         # SBOM generation [INTEGRATION]
├── sarif_formatter.py              # SARIF output formatter [INTEGRATION]
│
├── analysis/                       # Advanced analysis algorithms
│   ├── __init__.py
│   ├── anomaly_detector.py
│   ├── enhanced_pattern_detector.py
│   ├── entropy_analyzer.py
│   ├── integrated_analyzer.py
│   ├── ml_context_analyzer.py
│   ├── opcode_sequence_analyzer.py
│   └── semantic_analyzer.py
│
├── auth/                           # Authentication management
│   ├── __init__.py
│   ├── client.py
│   └── config.py
│
├── cache/                          # Caching system
│   ├── __init__.py
│   ├── batch_operations.py
│   ├── cache_manager.py
│   ├── optimized_config.py
│   ├── scan_results_cache.py
│   └── smart_cache_keys.py
│
├── context/                        # [SINGLE FILE DIRECTORY]
│   ├── __init__.py
│   └── unified_context.py
│
├── knowledge/                      # [SINGLE FILE DIRECTORY]
│   ├── __init__.py
│   └── framework_patterns.py
│
├── name_policies/                  # [SINGLE FILE DIRECTORY]
│   ├── __init__.py
│   └── blacklist.py
│
├── progress/                       # Progress tracking
│   ├── __init__.py
│   ├── base.py
│   ├── console.py
│   ├── file.py
│   ├── hooks.py
│   └── multi_phase.py
│
├── scanners/                       # 29 file format scanners
│   ├── __init__.py                 # Scanner registry (400+ lines)
│   ├── base.py                     # BaseScanner class
│   ├── [29 individual scanner files]
│   └── weight_distribution_scanner.py  # Analysis scanner
│
└── utils/                          # 20+ utility modules [TOO GENERIC]
    ├── __init__.py
    ├── advanced_file_handler.py    # File handling strategy [FILE]
    ├── assets.py                   # Asset management
    ├── cache_decorator.py          # Caching utilities
    ├── cloud_storage.py            # Cloud storage access [SOURCE]
    ├── code_validation.py          # Code validation
    ├── disk_space.py               # Disk space checking
    ├── dvc_utils.py                # DVC integration [SOURCE]
    ├── file_filter.py              # File filtering [FILE]
    ├── filetype.py                 # File type detection [FILE]
    ├── huggingface.py              # HuggingFace integration [SOURCE]
    ├── jfrog.py                    # JFrog utilities [SOURCE]
    ├── large_file_handler.py       # Large file handling [FILE]
    ├── ml_context.py               # ML context detection
    ├── pytorch_hub.py              # PyTorch Hub integration [SOURCE]
    ├── result_conversion.py        # Result conversion
    ├── retry.py                    # Retry logic
    ├── secure_hasher.py            # Secure hashing
    ├── smart_detection.py          # Smart configuration detection
    ├── streaming.py                # Streaming utilities [FILE]
    └── types.py                    # Type definitions
```

**Statistics**:
- **Root level**: 18 Python files (too many, unclear grouping)
- **Single-file directories**: 3 (`context/`, `knowledge/`, `name_policies/`)
- **Utils directory**: 20+ files with unclear categorization
- **Detectors scattered**: 5 detector files in root
- **Integrations scattered**: 5 integration files in root

---

## Proposed Directory Structure

```
modelaudit/
├── __init__.py                     # Package entry point
├── __main__.py                     # CLI entry point
├── cli.py                          # CLI implementation (keep for now)
├── core.py                         # Core scanning logic (keep for now)
├── constants.py                    # Constants and enums
├── models.py                       # Pydantic data models
├── explanations.py                 # Issue explanations
├── interrupt_handler.py            # Signal handling
├── unified_context.py              # MOVED from context/
├── framework_patterns.py           # MOVED from knowledge/
├── name_blacklist.py               # MOVED from name_policies/blacklist.py
│
├── analysis/                       # ✓ Keep as-is (well organized)
│   ├── __init__.py
│   ├── anomaly_detector.py
│   ├── enhanced_pattern_detector.py
│   ├── entropy_analyzer.py
│   ├── integrated_analyzer.py
│   ├── ml_context_analyzer.py
│   ├── opcode_sequence_analyzer.py
│   └── semantic_analyzer.py
│
├── auth/                           # ✓ Keep as-is (well organized)
│   ├── __init__.py
│   ├── client.py
│   └── config.py
│
├── cache/                          # ✓ Keep as-is (well organized)
│   ├── __init__.py
│   ├── batch_operations.py
│   ├── cache_manager.py
│   ├── optimized_config.py
│   ├── scan_results_cache.py
│   └── smart_cache_keys.py
│
├── detectors/                      # ✨ NEW - Security threat detection
│   ├── __init__.py                 # Export all detectors
│   ├── cve_patterns.py             # MOVED from root
│   ├── jit_script.py               # MOVED from jit_script_detector.py
│   ├── network_comm.py             # MOVED from network_comm_detector.py
│   ├── secrets.py                  # MOVED from secrets_detector.py
│   └── suspicious_symbols.py       # MOVED from root
│
├── integrations/                   # ✨ NEW - External system integrations
│   ├── __init__.py                 # Export all integrations
│   ├── jfrog.py                    # MOVED from jfrog_integration.py
│   ├── mlflow.py                   # MOVED from mlflow_integration.py
│   ├── license_checker.py          # MOVED from root
│   ├── sbom_generator.py           # MOVED from sbom.py
│   └── sarif_formatter.py          # MOVED from root
│
├── progress/                       # ✓ Keep as-is (well organized)
│   ├── __init__.py
│   ├── base.py
│   ├── console.py
│   ├── file.py
│   ├── hooks.py
│   └── multi_phase.py
│
├── scanners/                       # ✓ Keep as-is (well organized)
│   ├── __init__.py                 # Scanner registry
│   ├── base.py                     # BaseScanner class
│   ├── [29 individual scanner files]
│   └── weight_distribution_scanner.py
│
└── utils/                          # ♻️ Reorganized into subcategories
    ├── __init__.py                 # Export common utilities
    │
    ├── file/                       # ✨ NEW - File handling
    │   ├── __init__.py
    │   ├── detection.py            # MOVED from filetype.py
    │   ├── filtering.py            # MOVED from file_filter.py
    │   ├── handlers.py             # MOVED from advanced_file_handler.py
    │   ├── large_file_handler.py   # MOVED from utils/
    │   └── streaming.py            # MOVED from utils/
    │
    ├── sources/                    # ✨ NEW - Model source integrations
    │   ├── __init__.py
    │   ├── cloud_storage.py        # MOVED from utils/
    │   ├── dvc.py                  # MOVED from dvc_utils.py
    │   ├── huggingface.py          # MOVED from utils/
    │   ├── jfrog.py                # MOVED from utils/jfrog.py
    │   └── pytorch_hub.py          # MOVED from utils/
    │
    └── helpers/                    # ✨ NEW - Generic utilities
        ├── __init__.py
        ├── assets.py               # MOVED from utils/
        ├── cache_decorator.py      # MOVED from utils/
        ├── code_validation.py      # MOVED from utils/
        ├── disk_space.py           # MOVED from utils/
        ├── ml_context.py           # MOVED from utils/
        ├── result_conversion.py    # MOVED from utils/
        ├── retry.py                # MOVED from utils/
        ├── secure_hasher.py        # MOVED from utils/
        ├── smart_detection.py      # MOVED from utils/
        └── types.py                # MOVED from utils/
```

**Improvements**:
- **Root level**: 11 Python files (down from 18, 39% reduction)
- **Clear conceptual grouping**: detectors/, integrations/, utils/file/, utils/sources/
- **No single-file directories**: Flattened to root
- **Discoverable utilities**: "Where's cloud storage?" → `utils/sources/`
- **Self-documenting structure**: Directory name = purpose

---

## File Move Mapping

### Phase 1: Flatten Single-File Directories (Low Risk)

| Current Path | New Path | Imports to Update |
|--------------|----------|-------------------|
| `context/unified_context.py` | `unified_context.py` | `from modelaudit.context import unified_context` → `from modelaudit import unified_context` |
| `knowledge/framework_patterns.py` | `framework_patterns.py` | `from modelaudit.knowledge import framework_patterns` → `from modelaudit import framework_patterns` |
| `name_policies/blacklist.py` | `name_blacklist.py` | `from modelaudit.name_policies import blacklist` → `from modelaudit import name_blacklist` |

**Files to update**: scanners/, core.py, cli.py (~15 import statements)

### Phase 2: Create `detectors/` Module (Medium Risk)

| Current Path | New Path | Imports to Update |
|--------------|----------|-------------------|
| `cve_patterns.py` | `detectors/cve_patterns.py` | `from modelaudit import cve_patterns` → `from modelaudit.detectors import cve_patterns` |
| `jit_script_detector.py` | `detectors/jit_script.py` | `from modelaudit import jit_script_detector` → `from modelaudit.detectors import jit_script` |
| `network_comm_detector.py` | `detectors/network_comm.py` | `from modelaudit import network_comm_detector` → `from modelaudit.detectors import network_comm` |
| `secrets_detector.py` | `detectors/secrets.py` | `from modelaudit import secrets_detector` → `from modelaudit.detectors import secrets` |
| `suspicious_symbols.py` | `detectors/suspicious_symbols.py` | `from modelaudit import suspicious_symbols` → `from modelaudit.detectors import suspicious_symbols` |

**Files to update**: scanners/* (~25 scanner files), core.py, cli.py (~40 import statements)

### Phase 3: Create `integrations/` Module (Medium Risk)

| Current Path | New Path | Imports to Update |
|--------------|----------|-------------------|
| `jfrog_integration.py` | `integrations/jfrog.py` | `from modelaudit import jfrog_integration` → `from modelaudit.integrations import jfrog` |
| `mlflow_integration.py` | `integrations/mlflow.py` | `from modelaudit import mlflow_integration` → `from modelaudit.integrations import mlflow` |
| `license_checker.py` | `integrations/license_checker.py` | `from modelaudit import license_checker` → `from modelaudit.integrations import license_checker` |
| `sbom.py` | `integrations/sbom_generator.py` | `from modelaudit import sbom` → `from modelaudit.integrations import sbom_generator` |
| `sarif_formatter.py` | `integrations/sarif_formatter.py` | `from modelaudit import sarif_formatter` → `from modelaudit.integrations import sarif_formatter` |

**Files to update**: cli.py, core.py (~10 import statements)

### Phase 4: Reorganize `utils/` into Subcategories (High Risk)

#### 4a: Create `utils/file/` (File Handling)

| Current Path | New Path | Imports to Update |
|--------------|----------|-------------------|
| `utils/filetype.py` | `utils/file/detection.py` | `from modelaudit.utils import filetype` → `from modelaudit.utils.file import detection` |
| `utils/file_filter.py` | `utils/file/filtering.py` | `from modelaudit.utils import file_filter` → `from modelaudit.utils.file import filtering` |
| `utils/advanced_file_handler.py` | `utils/file/handlers.py` | `from modelaudit.utils import advanced_file_handler` → `from modelaudit.utils.file import handlers` |
| `utils/large_file_handler.py` | `utils/file/large_file_handler.py` | `from modelaudit.utils import large_file_handler` → `from modelaudit.utils.file import large_file_handler` |
| `utils/streaming.py` | `utils/file/streaming.py` | `from modelaudit.utils import streaming` → `from modelaudit.utils.file import streaming` |

**Files to update**: core.py, cli.py, scanners/* (~60 import statements)

#### 4b: Create `utils/sources/` (Model Sources)

| Current Path | New Path | Imports to Update |
|--------------|----------|-------------------|
| `utils/cloud_storage.py` | `utils/sources/cloud_storage.py` | `from modelaudit.utils import cloud_storage` → `from modelaudit.utils.sources import cloud_storage` |
| `utils/dvc_utils.py` | `utils/sources/dvc.py` | `from modelaudit.utils import dvc_utils` → `from modelaudit.utils.sources import dvc` |
| `utils/huggingface.py` | `utils/sources/huggingface.py` | `from modelaudit.utils import huggingface` → `from modelaudit.utils.sources import huggingface` |
| `utils/jfrog.py` | `utils/sources/jfrog.py` | `from modelaudit.utils import jfrog` → `from modelaudit.utils.sources import jfrog` |
| `utils/pytorch_hub.py` | `utils/sources/pytorch_hub.py` | `from modelaudit.utils import pytorch_hub` → `from modelaudit.utils.sources import pytorch_hub` |

**Files to update**: core.py, cli.py (~15 import statements)

#### 4c: Create `utils/helpers/` (Generic Utilities)

| Current Path | New Path | Imports to Update |
|--------------|----------|-------------------|
| `utils/assets.py` | `utils/helpers/assets.py` | `from modelaudit.utils import assets` → `from modelaudit.utils.helpers import assets` |
| `utils/cache_decorator.py` | `utils/helpers/cache_decorator.py` | `from modelaudit.utils import cache_decorator` → `from modelaudit.utils.helpers import cache_decorator` |
| `utils/code_validation.py` | `utils/helpers/code_validation.py` | `from modelaudit.utils import code_validation` → `from modelaudit.utils.helpers import code_validation` |
| `utils/disk_space.py` | `utils/helpers/disk_space.py` | `from modelaudit.utils import disk_space` → `from modelaudit.utils.helpers import disk_space` |
| `utils/ml_context.py` | `utils/helpers/ml_context.py` | `from modelaudit.utils import ml_context` → `from modelaudit.utils.helpers import ml_context` |
| `utils/result_conversion.py` | `utils/helpers/result_conversion.py` | `from modelaudit.utils import result_conversion` → `from modelaudit.utils.helpers import result_conversion` |
| `utils/retry.py` | `utils/helpers/retry.py` | `from modelaudit.utils import retry` → `from modelaudit.utils.helpers import retry` |
| `utils/secure_hasher.py` | `utils/helpers/secure_hasher.py` | `from modelaudit.utils import secure_hasher` → `from modelaudit.utils.helpers import secure_hasher` |
| `utils/smart_detection.py` | `utils/helpers/smart_detection.py` | `from modelaudit.utils import smart_detection` → `from modelaudit.utils.helpers import smart_detection` |
| `utils/types.py` | `utils/helpers/types.py` | `from modelaudit.utils import types` → `from modelaudit.utils.helpers import types` |

**Files to update**: core.py, cli.py, scanners/*, cache/*, progress/* (~80 import statements)

---

## Implementation Phases

### Phase 1: Flatten Single-File Directories (30 minutes)
**Risk**: Low | **Estimated Imports**: ~15

**Steps**:
1. Move 3 files to root
2. Update imports in scanners, core.py, cli.py
3. Delete empty directories
4. Run tests

**Command sequence**:
```bash
# Move files
git mv modelaudit/context/unified_context.py modelaudit/unified_context.py
git mv modelaudit/knowledge/framework_patterns.py modelaudit/framework_patterns.py
git mv modelaudit/name_policies/blacklist.py modelaudit/name_blacklist.py

# Delete empty directories
rmdir modelaudit/context
rmdir modelaudit/knowledge
rmdir modelaudit/name_policies

# Update imports (automated with find/replace)
# Run tests
rye run pytest -n auto -m "not slow and not integration"
```

### Phase 2: Create `detectors/` Module (1 hour)
**Risk**: Medium | **Estimated Imports**: ~40

**Steps**:
1. Create `modelaudit/detectors/` directory
2. Move 5 detector files (rename 2 of them)
3. Create `detectors/__init__.py` with exports
4. Update imports in scanners/*, core.py, cli.py
5. Run tests

**Command sequence**:
```bash
# Create directory
mkdir modelaudit/detectors

# Move files
git mv modelaudit/cve_patterns.py modelaudit/detectors/cve_patterns.py
git mv modelaudit/jit_script_detector.py modelaudit/detectors/jit_script.py
git mv modelaudit/network_comm_detector.py modelaudit/detectors/network_comm.py
git mv modelaudit/secrets_detector.py modelaudit/detectors/secrets.py
git mv modelaudit/suspicious_symbols.py modelaudit/detectors/suspicious_symbols.py

# Create __init__.py
# Update imports (automated)
# Run tests
rye run pytest -n auto -m "not slow and not integration"
```

### Phase 3: Create `integrations/` Module (1 hour)
**Risk**: Medium | **Estimated Imports**: ~10

**Steps**:
1. Create `modelaudit/integrations/` directory
2. Move 5 integration files (rename 1 of them)
3. Create `integrations/__init__.py` with exports
4. Update imports in cli.py, core.py
5. Run tests

**Command sequence**:
```bash
# Create directory
mkdir modelaudit/integrations

# Move files
git mv modelaudit/jfrog_integration.py modelaudit/integrations/jfrog.py
git mv modelaudit/mlflow_integration.py modelaudit/integrations/mlflow.py
git mv modelaudit/license_checker.py modelaudit/integrations/license_checker.py
git mv modelaudit/sbom.py modelaudit/integrations/sbom_generator.py
git mv modelaudit/sarif_formatter.py modelaudit/integrations/sarif_formatter.py

# Create __init__.py
# Update imports (automated)
# Run tests
rye run pytest -n auto -m "not slow and not integration"
```

### Phase 4: Reorganize `utils/` (2-3 hours)
**Risk**: High | **Estimated Imports**: ~155

**Steps**:
1. Create subdirectories: `utils/file/`, `utils/sources/`, `utils/helpers/`
2. Move files to appropriate subdirectories
3. Create `__init__.py` files for each subdirectory with exports
4. Update imports across entire codebase
5. Run comprehensive tests

**Command sequence**:
```bash
# Create subdirectories
mkdir modelaudit/utils/file
mkdir modelaudit/utils/sources
mkdir modelaudit/utils/helpers

# Move file handling utilities
git mv modelaudit/utils/filetype.py modelaudit/utils/file/detection.py
git mv modelaudit/utils/file_filter.py modelaudit/utils/file/filtering.py
git mv modelaudit/utils/advanced_file_handler.py modelaudit/utils/file/handlers.py
git mv modelaudit/utils/large_file_handler.py modelaudit/utils/file/large_file_handler.py
git mv modelaudit/utils/streaming.py modelaudit/utils/file/streaming.py

# Move source integrations
git mv modelaudit/utils/cloud_storage.py modelaudit/utils/sources/cloud_storage.py
git mv modelaudit/utils/dvc_utils.py modelaudit/utils/sources/dvc.py
git mv modelaudit/utils/huggingface.py modelaudit/utils/sources/huggingface.py
git mv modelaudit/utils/jfrog.py modelaudit/utils/sources/jfrog.py
git mv modelaudit/utils/pytorch_hub.py modelaudit/utils/sources/pytorch_hub.py

# Move generic helpers
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

# Create __init__.py files
# Update imports (automated with comprehensive search/replace)
# Run full test suite
rye run pytest -n auto
```

---

## Import Update Strategy

### Automated Find & Replace Patterns

**Phase 1: Flatten single-file directories**
```bash
# unified_context
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.context import unified_context/from modelaudit import unified_context/g' {} +
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.context\.unified_context/from modelaudit.unified_context/g' {} +

# framework_patterns
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.knowledge import framework_patterns/from modelaudit import framework_patterns/g' {} +
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.knowledge\.framework_patterns/from modelaudit.framework_patterns/g' {} +

# blacklist → name_blacklist
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.name_policies import blacklist/from modelaudit import name_blacklist/g' {} +
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.name_policies\.blacklist/from modelaudit.name_blacklist/g' {} +
```

**Phase 2: Create detectors/ module**
```bash
# CVE patterns
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit import cve_patterns/from modelaudit.detectors import cve_patterns/g' {} +
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.cve_patterns/from modelaudit.detectors.cve_patterns/g' {} +

# JIT script detector
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit import jit_script_detector/from modelaudit.detectors import jit_script/g' {} +
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.jit_script_detector/from modelaudit.detectors.jit_script/g' {} +

# Network comm detector
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit import network_comm_detector/from modelaudit.detectors import network_comm/g' {} +
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.network_comm_detector/from modelaudit.detectors.network_comm/g' {} +

# Secrets detector
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit import secrets_detector/from modelaudit.detectors import secrets/g' {} +
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.secrets_detector/from modelaudit.detectors.secrets/g' {} +

# Suspicious symbols
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit import suspicious_symbols/from modelaudit.detectors import suspicious_symbols/g' {} +
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.suspicious_symbols/from modelaudit.detectors.suspicious_symbols/g' {} +
```

**Phase 3: Create integrations/ module**
```bash
# JFrog
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit import jfrog_integration/from modelaudit.integrations import jfrog/g' {} +
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.jfrog_integration/from modelaudit.integrations.jfrog/g' {} +

# MLflow
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit import mlflow_integration/from modelaudit.integrations import mlflow/g' {} +
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.mlflow_integration/from modelaudit.integrations.mlflow/g' {} +

# License checker
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit import license_checker/from modelaudit.integrations import license_checker/g' {} +
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.license_checker/from modelaudit.integrations.license_checker/g' {} +

# SBOM
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit import sbom/from modelaudit.integrations import sbom_generator/g' {} +
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.sbom/from modelaudit.integrations.sbom_generator/g' {} +

# SARIF formatter
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit import sarif_formatter/from modelaudit.integrations import sarif_formatter/g' {} +
find modelaudit tests -name "*.py" -exec sed -i '' 's/from modelaudit\.sarif_formatter/from modelaudit.integrations.sarif_formatter/g' {} +
```

**Phase 4: Reorganize utils/ - See detailed commands in implementation script**

---

## Testing Strategy

### After Each Phase

1. **Import verification**:
```bash
# Check for any remaining old imports
rg "from modelaudit\.context" modelaudit/ tests/
rg "from modelaudit\.knowledge" modelaudit/ tests/
rg "from modelaudit\.name_policies" modelaudit/ tests/
# (adjust patterns per phase)
```

2. **Syntax check**:
```bash
# Ensure all files parse correctly
python -m py_compile modelaudit/**/*.py
```

3. **Fast test suite**:
```bash
rye run pytest -n auto -m "not slow and not integration" --tb=short
```

4. **Full test suite** (after Phase 4):
```bash
rye run pytest -n auto --tb=short
```

5. **Type checking**:
```bash
rye run mypy modelaudit/
```

6. **Linting**:
```bash
rye run ruff check modelaudit/ tests/
```

---

## Rollback Plan

Each phase is independent and can be rolled back:

```bash
# Rollback Phase N
git reset --hard HEAD~1  # If committed
# OR
git checkout -- modelaudit/ tests/  # If not committed
```

**Recommendation**: Commit after each successful phase with clear commit messages:
- `refactor: flatten single-file directories`
- `refactor: create detectors/ module for security detection`
- `refactor: create integrations/ module for external systems`
- `refactor: reorganize utils/ into file/sources/helpers subcategories`

---

## Documentation Updates

### Update README.md

Add new "Project Structure" section after "Quick Start":

```markdown
## 📁 Project Structure

ModelAudit is organized by conceptual purpose for clarity:

```
modelaudit/
├── scanners/         # 29 file format scanners (pickle, pytorch, onnx, etc.)
├── detectors/        # Security threat detection (CVEs, secrets, network comm)
├── integrations/     # External systems (jfrog, mlflow, sbom, sarif)
├── analysis/         # Advanced analysis algorithms
├── utils/
│   ├── file/         # File handling (detection, filtering, streaming)
│   ├── sources/      # Model sources (HuggingFace, cloud, JFrog)
│   └── helpers/      # Generic utilities
├── cache/            # Caching system
├── auth/             # Authentication
└── progress/         # Progress tracking
```

**Key modules**:
- `scanners/` - What formats can we scan?
- `detectors/` - What threats do we find?
- `integrations/` - What systems do we connect to?
- `utils/sources/` - Where do models come from?
```

### Update CLAUDE.md

Update architecture section:

```markdown
## Architecture

### Directory Structure

- `scanners/` - File format scanners (29 specialized scanners)
- `detectors/` - Security detection modules (CVEs, secrets, JIT code)
- `integrations/` - External system integrations (JFrog, MLflow, SBOM)
- `analysis/` - Advanced analysis algorithms
- `utils/file/` - File handling utilities
- `utils/sources/` - Model source integrations (HuggingFace, cloud storage)
- `utils/helpers/` - Generic utilities

### Adding New Components

**New Scanner**: Add to `modelaudit/scanners/`, register in `scanners/__init__.py`
**New Detector**: Add to `modelaudit/detectors/`, import in scanner
**New Integration**: Add to `modelaudit/integrations/`, wire up in CLI
```

---

## Success Criteria

✅ **All tests pass** (no regressions)
✅ **No import errors** (all references updated)
✅ **Type checking passes** (mypy clean)
✅ **Linting passes** (ruff clean)
✅ **Documentation updated** (README.md, CLAUDE.md)
✅ **Clearer structure** (reduced cognitive load for navigation)

---

## Estimated Timeline

| Phase | Time | Risk | Dependencies |
|-------|------|------|--------------|
| Phase 1: Flatten directories | 30 min | Low | None |
| Phase 2: Create detectors/ | 1 hour | Medium | Phase 1 |
| Phase 3: Create integrations/ | 1 hour | Medium | Phase 1-2 |
| Phase 4: Reorganize utils/ | 2-3 hours | High | Phase 1-3 |
| **Total** | **4.5-5.5 hours** | **Medium-High** | Sequential |

**Recommendation**: Execute phases sequentially with full testing between each phase.

---

## Open Questions

1. **Should `utils/__init__.py` re-export common utilities?**
   - Pro: Backward compatibility (`from modelaudit.utils import filetype`)
   - Con: Hides new structure
   - **Recommendation**: No re-exports, force explicit imports for clarity

2. **Should we rename more files for consistency?**
   - Examples: `jit_script_detector.py` → `jit_script.py`
   - **Recommendation**: Yes, remove `_detector` suffix (redundant in `detectors/` dir)

3. **Should `license_checker.py` be in `integrations/` or `detectors/`?**
   - It checks licenses (detection-like) but also integrates with SPDX (integration-like)
   - **Recommendation**: `integrations/` - output focus (SBOM generation)

4. **Keep `cache_decorator.py` in root utils or move to `cache/`?**
   - **Recommendation**: `utils/helpers/` - it's a generic caching utility, not specific to scan cache

---

## Next Steps

1. **Review this plan** with team/maintainers
2. **Get approval** on directory structure
3. **Create feature branch**: `git checkout -b refactor/directory-structure`
4. **Execute Phase 1** (safest, quickest win)
5. **Validate & commit**
6. **Continue with remaining phases**
7. **Update documentation**
8. **Create PR** with before/after structure comparison
