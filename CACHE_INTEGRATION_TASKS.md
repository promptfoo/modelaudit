# Cache Integration Completion Tasks

## 🎯 **Overview**

Complete the remaining cache integration work in ModelAudit. **80% of cache integration is already done** - core scanning flows use caching through `scanner.scan_with_cache()`. This document outlines the remaining critical integration points.

## ✅ **Already Completed**

- ✅ Cache infrastructure (CacheManager, ScanResultsCache, SmartCacheKeyGenerator)
- ✅ Cache decorator system (`utils/cache_decorator.py`)
- ✅ BaseScanner integration (`scanners/base.py:scan_with_cache()`)
- ✅ Core scanning integration (`core.py:1288` calls `scanner.scan_with_cache()`)
- ✅ All 33 individual scanners inherit cache support automatically

---

## 🚧 **Phase 1: Critical Missing Pieces (Week 1)**

### **Task 1.1: Large File Handler Cache Integration**

**Priority**: 🔴 **CRITICAL** - These handlers bypass normal cache flow and are performance-critical for >1GB models

#### **Files to Edit:**

1. **`modelaudit/utils/large_file_handler.py`**
   - **Function**: `scan_large_file()` (around line 211)
   - **Change**: Wrap with cache manager integration
   - **Specific edits**:

     ```python
     def scan_large_file(file_path: str, scanner: Any, progress_callback: Optional[Callable] = None, timeout: int = 3600) -> ScanResult:
         from ..cache import get_cache_manager
         from ..models import ScanResult

         # Check if caching enabled in scanner config
         config = getattr(scanner, 'config', {}) or {}
         cache_enabled = config.get('cache_enabled', True)

         if not cache_enabled:
             return _scan_large_file_internal(file_path, scanner, progress_callback, timeout)

         # Use cache manager for large files
         cache_manager = get_cache_manager(
             cache_dir=config.get('cache_dir'),
             enabled=True
         )

         def cached_large_scan(path: str) -> dict:
             result = _scan_large_file_internal(path, scanner, progress_callback, timeout)
             return result.to_dict()

         result_dict = cache_manager.cached_scan(file_path, cached_large_scan)
         return ScanResult.from_dict(result_dict)

     def _scan_large_file_internal(file_path: str, scanner: Any, progress_callback: Optional[Callable] = None, timeout: int = 3600) -> ScanResult:
         """Move current scan_large_file implementation here."""
         # ... existing implementation moves here ...
     ```

2. **`modelaudit/utils/advanced_file_handler.py`**
   - **Function**: `scan_advanced_large_file()` (around line 489)
   - **Change**: Similar cache integration pattern
   - **Specific edits**:

     ```python
     def scan_advanced_large_file(file_path: str, scanner: Any, progress_callback: Optional[Callable] = None, timeout: int = 3600) -> ScanResult:
         from ..cache import get_cache_manager
         from ..models import ScanResult

         # Check if caching enabled in scanner config
         config = getattr(scanner, 'config', {}) or {}
         cache_enabled = config.get('cache_enabled', True)

         if not cache_enabled:
             return _scan_advanced_large_file_internal(file_path, scanner, progress_callback, timeout)

         # Use cache manager for advanced large files
         cache_manager = get_cache_manager(
             cache_dir=config.get('cache_dir'),
             enabled=True
         )

         def cached_advanced_scan(path: str) -> dict:
             result = _scan_advanced_large_file_internal(path, scanner, progress_callback, timeout)
             return result.to_dict()

         result_dict = cache_manager.cached_scan(file_path, cached_advanced_scan)
         return ScanResult.from_dict(result_dict)

     def _scan_advanced_large_file_internal(file_path: str, scanner: Any, progress_callback: Optional[Callable] = None, timeout: int = 3600) -> ScanResult:
         """Move current scan_advanced_large_file implementation here."""
         # ... existing implementation moves here ...
     ```

3. **`modelaudit/models.py`**
   - **Add method**: `ScanResult.from_dict()` if not exists
   - **Specific edits**:
     ```python
     @classmethod
     def from_dict(cls, data: dict) -> "ScanResult":
         """Create ScanResult from dictionary (for cache deserialization)."""
         # Implementation to reconstruct ScanResult from cached dict
         # This may already exist - verify first
     ```

### **Task 1.2: CLI Cache Configuration**

**Priority**: 🔴 **CRITICAL** - Users need control over caching behavior

#### **Files to Edit:**

1. **`modelaudit/cli.py`**
   - **Function**: `scan_command()` (around line 511)
   - **Change**: Add cache CLI options
   - **Specific edits**:

     ```python
     @cli.command("scan")
     @click.argument("paths", nargs=-1, required=True)
     # ... existing options ...
     @click.option("--cache/--no-cache", default=True, help="Enable scan result caching for faster repeated scans")
     @click.option("--cache-dir", type=click.Path(), help="Custom cache directory (default: system cache dir)")
     def scan_command(
         paths: tuple[str, ...],
         # ... existing parameters ...
         cache: bool,
         cache_dir: str | None,
     ):
         """Scan model files for security issues."""
         # ... existing code ...

         config = {
             # ... existing config ...
             'cache_enabled': cache,
             'cache_dir': cache_dir,
         }

         # ... rest of existing implementation ...
     ```

2. **`modelaudit/cli.py`**
   - **Add**: Cache status/stats command (optional)
   - **Specific edits**:

     ```python
     @cli.command("cache")
     @click.option("--clear", is_flag=True, help="Clear the scan cache")
     @click.option("--stats", is_flag=True, help="Show cache statistics")
     @click.option("--cache-dir", type=click.Path(), help="Cache directory to operate on")
     def cache_command(clear: bool, stats: bool, cache_dir: str | None):
         """Manage scan result cache."""
         from .cache import get_cache_manager

         cache_manager = get_cache_manager(cache_dir, enabled=True)

         if clear:
             cache_manager.clear()
             click.echo("Cache cleared.")

         if stats:
             stats_data = cache_manager.get_stats()
             click.echo(f"Cache enabled: {stats_data.get('enabled', False)}")
             click.echo(f"Total entries: {stats_data.get('total_entries', 0)}")
             click.echo(f"Hit rate: {stats_data.get('hit_rate', 0.0):.1%}")
     ```

### **Task 1.3: Verify Core Integration Works**

**Priority**: 🟡 **HIGH** - Validate existing cache integration

#### **Files to Check:**

1. **`modelaudit/core.py`**
   - **Line 1288**: Verify `scanner.scan_with_cache(path)` is called correctly
   - **Verify**: Config flows through properly

2. **`modelaudit/scanners/base.py`**
   - **Line 388**: Verify `scan_with_cache()` implementation
   - **Test**: Ensure cache decorator works

#### **Testing Steps:**

```bash
# Test existing cache integration
rye run modelaudit scan test_model.pkl --cache
rye run modelaudit scan test_model.pkl --cache  # Should be much faster

# Test cache disable
rye run modelaudit scan test_model.pkl --no-cache

# Test cache stats (after implementing Task 1.2)
rye run modelaudit cache --stats
```

---

## 🚀 **Phase 2: Validation & Testing (Week 1)**

### **Task 2.1: Performance Validation**

#### **Test Files Needed:**

- Small model (~10MB): `tests/assets/small_model.pkl`
- Medium model (~100MB): `tests/assets/medium_model.pt`
- Large model (~1GB): Download for testing

#### **Performance Tests:**

```bash
# Measure cache performance
time rye run modelaudit scan large_model.bin --no-cache
time rye run modelaudit scan large_model.bin --cache
time rye run modelaudit scan large_model.bin --cache  # Second run should be much faster

# Expected: 4-20x speedup on second run
```

### **Task 2.2: Integration Function Testing**

#### **Files to Test:**

1. **`modelaudit/jfrog_integration.py`** - Should benefit from cache automatically
2. **`modelaudit/mlflow_integration.py`** - Should benefit from cache automatically

#### **Test Process:**

- Test JFrog artifact scanning with cache enabled/disabled
- Test MLflow model scanning with cache enabled/disabled
- Verify download caching + scan caching work together

### **Task 2.3: Large File Handler Testing**

#### **Test Process:**

- Test >1GB model files with large file handlers
- Verify cache integration doesn't break memory-mapped scanning
- Test cache hit rates for sharded/memory-mapped files

---

## 🔧 **Phase 3: Polish & Optimization (Week 2)**

### **Task 3.1: Cache Statistics & Monitoring**

#### **Files to Edit:**

1. **`modelaudit/cli.py`**
   - **Enhancement**: Add cache hit rate to scan output
   - **Specific edits**:
     ```python
     # In scan_command, after scanning:
     if config.get('cache_enabled', True):
         from .cache import get_cache_manager
         cache_manager = get_cache_manager()
         stats = cache_manager.get_stats()
         if stats.get('total_entries', 0) > 0:
             click.echo(f"Cache hit rate: {stats.get('hit_rate', 0.0):.1%}")
     ```

### **Task 3.2: Advanced Cache Features**

#### **Files to Edit:**

1. **`modelaudit/cli.py`**
   - **Enhancement**: Add cache cleanup command
   - **Specific edits**:

     ```python
     @click.option("--cleanup", type=int, help="Clean cache entries older than N days")
     def cache_command(..., cleanup: int | None):
         # ... existing cache command ...

         if cleanup:
             removed = cache_manager.cleanup(max_age_days=cleanup)
             click.echo(f"Removed {removed} old cache entries.")
     ```

---

## 🧪 **Testing Plan**

### **Unit Tests to Add:**

1. **`tests/test_cache_integration.py`**

   ```python
   def test_large_file_handler_cache_integration():
       """Test large file handlers use cache correctly."""

   def test_cli_cache_options():
       """Test CLI cache options work correctly."""

   def test_cache_hit_performance():
       """Test cache provides expected speedup."""
   ```

### **Integration Tests:**

1. **`tests/test_cache_performance.py`**
   ```python
   def test_end_to_end_cache_performance():
       """Test full scanning pipeline with cache enabled."""
   ```

---

## 📊 **Success Criteria**

### **Phase 1 Success Metrics:**

- ✅ Large file handlers (>1GB models) benefit from caching
- ✅ CLI `--cache/--no-cache` options work correctly
- ✅ 4-10x speedup on cache hits with real models
- ✅ Cache can be disabled completely via `--no-cache`
- ✅ No breaking changes to existing functionality

### **Phase 2 Success Metrics:**

- ✅ Performance tests show expected speedup
- ✅ Large model caching works without memory issues
- ✅ Integration functions benefit from caching
- ✅ Cache invalidation works on model updates

### **Phase 3 Success Metrics:**

- ✅ Cache statistics provide useful insights
- ✅ Cache cleanup functionality works
- ✅ User documentation is complete

---

## ⚠️ **Risk Mitigation**

### **Potential Issues:**

1. **Memory Usage**: Large model caching could increase memory usage
   - **Mitigation**: Cache only results, not full model data
   - **Verification**: Monitor memory usage during testing

2. **Cache Invalidation**: Stale cache entries with model updates
   - **Mitigation**: Use file modification time in cache keys
   - **Verification**: Test cache invalidation on file changes

3. **Disk Space**: Cache could grow large over time
   - **Mitigation**: Implement cache cleanup functionality
   - **Verification**: Test cache size management

### **Rollback Plan:**

- All changes are additive and backwards-compatible
- Cache can be disabled with `--no-cache` flag
- Existing functionality continues to work without cache

---

## 🎯 **Implementation Order**

1. **Start with Task 1.1** (Large file handlers) - Biggest performance impact
2. **Then Task 1.2** (CLI options) - User-facing functionality
3. **Validate with Task 1.3** (Testing) - Ensure everything works
4. **Proceed to Phase 2** (Performance validation)
5. **Finish with Phase 3** (Polish features)

**Estimated Timeline**: 1-2 weeks for complete implementation and testing.
