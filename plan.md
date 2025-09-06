# Task: Drop Python 3.9 Support and Upgrade to Python 3.10+ Minimum

## Overview

This task involves upgrading ModelAudit to require Python 3.10 as the minimum version, removing Python 3.9 compatibility code, and leveraging new Python 3.10+ features for improved code quality and performance.

## Current State Analysis

### Python Version Configuration

- **pyproject.toml**: Currently specifies `requires-python = ">=3.9"`
- **classifiers**: Lists Python 3.9, 3.10, 3.11, 3.12
- **Ruff target**: Set to `py39`
- **MyPy**: Already configured for Python 3.10
- **CI/CD**: Tests Python 3.9, 3.10, 3.11, 3.12 in matrix
- **Docker**: Uses Python 3.11 (no changes needed)

### Code Quality Status

- **Modern typing**: Already uses `from __future__ import annotations` in 12 files
- **Union types**: Clean codebase - no `typing.Union` usage found
- **Walrus operator**: Already used in `modelaudit/utils/secure_hasher.py`
- **Match statements**: No current usage found
- **String formatting**: Some `.format()` usage in `suspicious_symbols.py` and % formatting in several files

## Implementation Plan

### Phase 1: Configuration Updates

#### 1.1 Update pyproject.toml

**File**: `/Users/mdangelo/projects/ma2/pyproject.toml`

**Changes**:

- Line 22: Remove `"Programming Language :: Python :: 3.9"`
- Line 27: Change `requires-python = ">=3.9"` to `requires-python = ">=3.10"`
- Line 151: Change `target-version = "py39"` to `target-version = "py310"`

**Rationale**: Update package metadata and tooling configuration to reflect new minimum version.

#### 1.2 Update GitHub Actions CI/CD

**File**: `/Users/mdangelo/projects/ma2/.github/workflows/test.yml`

**Changes**:

- Line 189: Change matrix from `["3.9", "3.12"]` to `["3.10", "3.12"]` for PRs
- Line 189: Change matrix from `["3.9", "3.10", "3.11", "3.12"]` to `["3.10", "3.11", "3.12"]` for main branch
- Line 255: Change matrix from `["3.9", "3.11", "3.12"]` to `["3.10", "3.11", "3.12"]` for NumPy compatibility tests

**Rationale**: Remove Python 3.9 from CI matrix to prevent testing against unsupported versions.

### Phase 2: Code Modernization Opportunities

#### 2.1 String Formatting Improvements

**Files to modernize**:

- `modelaudit/suspicious_symbols.py` - Replace `.format()` with f-strings
- `modelaudit/cli.py` - Replace % formatting with f-strings
- `modelaudit/utils/dvc_utils.py` - Replace % formatting with f-strings
- `modelaudit/sarif_formatter.py` - Replace % formatting with f-strings
- `modelaudit/progress/file.py` - Replace % formatting with f-strings
- `modelaudit/scanners/gguf_scanner.py` - Replace % formatting with f-strings
- `modelaudit/scanners/flax_msgpack_scanner.py` - Replace % formatting with f-strings

**Benefits**: Better performance and readability with f-strings.

#### 2.2 Pattern Matching Opportunities

**Potential candidates**:

- `modelaudit/explanations.py:271-275` - Multiple if-elif chains checking categories
- Complex conditional logic in scanners for file type detection
- Error handling patterns with multiple exception types

**Benefits**: More readable and potentially more performant pattern matching.

#### 2.3 Union Type Syntax

**Files already using modern typing** (no changes needed):

```python
from __future__ import annotations
```

Present in:

- `modelaudit/utils/assets.py`
- `modelaudit/scanners/safetensors_scanner.py`
- `modelaudit/jfrog_integration.py`
- `modelaudit/cve_patterns.py`
- And 8 other files

**Recommendation**: Continue using `from __future__ import annotations` pattern, which already enables modern syntax.

#### 2.4 Walrus Operator Usage

**Current usage**: Already optimized in `modelaudit/utils/secure_hasher.py:123,128`

```python
while chunk := f.read(self.chunk_size):
```

**Additional opportunities**:

- File processing loops where data is read and immediately checked
- Complex conditional assignments
- Iterator patterns with immediate validation

### Phase 3: Type System Improvements

#### 3.1 MyPy Strictness Improvements

**Current State Analysis**:

- ✅ **Good foundation**: Already has Phase 1 strict checks enabled
- ⚠️ **Phase 2 ready**: Can enable `check_untyped_defs = true` and `disallow_incomplete_defs = true`
- 🎯 **Phase 3 goal**: Eventually enable `disallow_untyped_defs = true`

**Immediate Improvements** (Python 3.10+):

- **Enable stricter checking**: Move Phase 2 options from comments to active
- **Clean up type: ignore comments**: 15 instances found, many can be removed with proper typing
- **Fix ONNX scanner typing issue**: Resolve `unused-ignore` and `no-redef` errors

#### 3.2 Reduce Any Usage

**High-impact Any usage to improve**:

- `modelaudit/models.py:67,441` - Generic dict access and aggregation methods
- `modelaudit/core.py:456,880` - Config creation and file handling
- `modelaudit/cli.py:1715` - Issue attribute access helper
- `modelaudit/secrets_detector.py:562` - Model weights scanning
- `modelaudit/utils/advanced_file_handler.py:109,308` - Scanner interface

**Strategy**: Replace with specific types, Protocols, or TypeVars where appropriate.

#### 3.3 Python 3.10+ Typing Features

**3.3.1 Union Type Syntax (X | Y)**
**Current**: Already clean - no `typing.Union` usage found
**Status**: ✅ Ready to use `X | Y` syntax directly

**3.3.2 TypeAlias (Python 3.10+)**
**High-value candidates**:

```python
# modelaudit/models.py
ScanResultDict: TypeAlias = dict[str, Any]
IssueDict: TypeAlias = dict[str, Any]
ConfigDict: TypeAlias = dict[str, Union[str, int, bool, list[str]]]

# modelaudit/scanners/base.py
ScannerConfig: TypeAlias = dict[str, Any] | None
PathLike: TypeAlias = str | Path
```

**3.3.3 ParamSpec and TypeVarTuple**
**Files that would benefit**:

- `modelaudit/utils/retry.py` - Decorator type hints
- `modelaudit/interrupt_handler.py:58` - Signal handler typing
- `modelaudit/core.py:880` - Generic file opening function

**3.3.4 Literal Types and TypedDict**
**Opportunities**:

```python
# For severity levels
from typing import Literal
SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# For scanner configurations
class ScannerConfigTypedDict(TypedDict, total=False):
    timeout: int
    verbose: bool
    max_size: int
```

**3.3.5 Protocol Classes for Better Duck Typing**
**Current**: No Protocol usage found
**Opportunities**:

- Scanner interface protocols
- File-like object protocols
- Progress tracker protocols

#### 3.4 Generic Improvements

**Self type (Python 3.11, but can use typing_extensions)**:

- Builder patterns in configuration classes
- Method chaining in scanner classes

**Concrete Benefits**:

1. **Better IDE support** - More precise autocompletion and error detection
2. **Runtime safety** - Catch more type errors before deployment
3. **Code documentation** - Types serve as living documentation
4. **Refactoring safety** - Type checker catches breaking changes

### Phase 4: Performance Optimizations

#### 4.1 Structural Pattern Matching

**High-value targets**:

- File type detection in `modelaudit/utils/filetype.py`
- Scanner routing logic in `modelaudit/scanners/__init__.py`
- Error categorization in exception handlers

**Benefits**: More efficient branching and cleaner code structure.

#### 4.2 Improved Error Messages (Python 3.10+)

**Files to review**:

- All scanner files for exception handling
- CLI error reporting in `modelaudit/cli.py`
- Validation errors in `modelaudit/models.py`

**Benefits**: More precise error location tracking and better debugging.

## Testing Strategy

### Compatibility Testing

1. **Remove Python 3.9 from test matrix** - Already covered in Phase 1
2. **Validate all existing tests pass** on Python 3.10, 3.11, 3.12
3. **Test optional dependencies** work correctly with new minimum version

### Regression Testing

1. **Core functionality tests** - Ensure all scanning capabilities work
2. **CLI integration tests** - Verify command-line interface compatibility
3. **Docker image tests** - Confirm containerized builds work (already Python 3.11)
4. **CI/CD pipeline validation** - Full pipeline test with new matrix

### Performance Testing

1. **Benchmark string formatting changes** - Measure f-string performance impact
2. **Pattern matching benchmarks** - Compare performance of match statements vs if-elif
3. **Type checking performance** - Ensure type system improvements don't slow MyPy

## Risk Assessment

### Low Risk Changes

- ✅ **Configuration updates** (pyproject.toml, CI matrix)
- ✅ **String formatting modernization** - Direct replacements
- ✅ **Docker files** - Already use Python 3.11

### Medium Risk Changes

- ⚠️ **Pattern matching adoption** - New syntax, potential logic errors
- ⚠️ **Type system upgrades** - Could introduce MyPy errors
- ⚠️ **Walrus operator expansion** - Side effects in conditionals

### High Risk Areas

- 🚨 **Scanner compatibility** - Core functionality must remain intact
- 🚨 **Dependency interactions** - ML frameworks may have Python version constraints
- 🚨 **User migration** - Breaking change for Python 3.9 users

## Migration Guide for Users

### Breaking Change Communication

1. **Version bump requirements** - Bump to v0.3.0 for semver compliance
2. **Changelog entry** - Clear documentation of Python version requirement change
3. **Migration timeline** - 30-day deprecation notice in v0.2.x releases

### User Impact

- **Direct impact**: Python 3.9 users must upgrade to Python 3.10+
- **Benefit**: Access to improved performance and modern language features
- **Mitigation**: Clear upgrade documentation and compatibility matrix

## Rollback Plan

### Quick Rollback Options

1. **Revert configuration changes** - Simple config file updates
2. **Restore CI matrix** - Add Python 3.9 back to testing
3. **Feature flags** - Use conditional imports for new features

### Validation Steps

1. **Test rollback on feature branch** before merging
2. **Validate CI passes** with reverted changes
3. **Confirm user-facing APIs unchanged** for existing functionality

## Timeline and Priorities

### High Priority (Week 1)

1. ✅ Configuration updates (pyproject.toml, CI/CD)
2. ✅ String formatting modernization
3. ✅ Basic testing validation
4. **NEW**: Enable MyPy Phase 2 strictness checks
5. **NEW**: Clean up unused `type: ignore` comments

### Medium Priority (Week 2)

1. Pattern matching implementation for high-value cases
2. Type system improvements (TypeAlias, Literal types)
3. Reduce high-impact Any usage (5 key locations)
4. **NEW**: Add TypedDict for configuration objects
5. Comprehensive testing across all Python versions

### Low Priority (Week 3)

1. **NEW**: Implement Protocol classes for better interfaces
2. **NEW**: Add ParamSpec for decorator typing
3. Performance optimizations
4. Advanced pattern matching adoption
5. Documentation updates

## Dependencies Analysis

### ML Framework Compatibility

- **TensorFlow >=2.13.0**: Supports Python 3.10+ ✅
- **PyTorch >=2.6.0**: Supports Python 3.10+ ✅
- **NumPy >=1.19.0**: Supports Python 3.10+ ✅
- **ONNX >=1.12.0**: Supports Python 3.10+ ✅
- **SciPy >=1.7.0**: Supports Python 3.10+ ✅

### Development Dependencies

- **pytest >=8.4.0**: Supports Python 3.10+ ✅
- **mypy >=1.16.0**: Supports Python 3.10+ ✅
- **ruff >=0.12.0**: Supports Python 3.10+ ✅

**Conclusion**: No dependency conflicts expected.

## Implementation Checklist

### Phase 1: Configuration

- [ ] Update `pyproject.toml` Python version requirements
- [ ] Update `pyproject.toml` classifiers
- [ ] Update `pyproject.toml` Ruff target version
- [ ] Update GitHub Actions CI matrix
- [ ] Update documentation references to Python version

### Phase 2: Code Modernization

- [ ] Replace `.format()` with f-strings in identified files
- [ ] Replace % formatting with f-strings
- [ ] Implement pattern matching for file type detection
- [ ] Add TypeAlias definitions for complex types
- [ ] Expand walrus operator usage where beneficial

### Phase 2b: Type System Improvements

- [ ] Enable MyPy `check_untyped_defs = true` and `disallow_incomplete_defs = true`
- [ ] Clean up 15 `type: ignore` comments where possible
- [ ] Fix ONNX scanner typing issues (unused-ignore, no-redef)
- [ ] Replace high-impact Any usage with specific types (5 key locations)
- [ ] Add Literal types for severity levels and configuration options
- [ ] Introduce TypedDict for scanner configurations
- [ ] Add TypeAlias for commonly used complex types

### Phase 3: Testing & Validation

- [ ] Run full test suite on Python 3.10, 3.11, 3.12
- [ ] Validate CI pipeline with new configuration
- [ ] Test Docker builds and functionality
- [ ] Performance benchmark key changes
- [ ] Update and test documentation

### Phase 4: Documentation & Release

- [ ] Update README.md Python version requirements
- [ ] Add CHANGELOG.md entry for breaking change
- [ ] Update installation documentation
- [ ] Prepare migration guide for users
- [ ] Plan deprecation notice strategy

## Success Criteria

1. **Functional**: All existing tests pass on Python 3.10+
2. **Performance**: No regression in scanning performance
3. **Compatibility**: All optional dependencies work correctly
4. **Quality**: MyPy and Ruff checks pass with new configuration
5. **Documentation**: Clear migration path for users
6. **CI/CD**: Pipeline runs successfully without Python 3.9

This comprehensive plan provides a structured approach to modernizing ModelAudit while minimizing risks and ensuring a smooth transition for users.
