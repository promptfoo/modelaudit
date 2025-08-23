# ModelAudit Performance Optimization Tasks

## Executive Summary

Two critical optimization areas can dramatically improve ModelAudit's performance:

1. **Disk Space Reduction**: Minimize temporary disk usage during scanning
2. **Intelligent Caching**: Speed up repeat scans through smart result caching

## Task 12: Implement Streaming and Memory-Efficient Scanning

**Priority**: P1 - Performance Critical
**Estimated Effort**: 5-7 days  
**Dependencies**: None

### Objective

Reduce disk space consumption by 80-90% through streaming analysis, in-memory processing, and smart temporary file management.

### Current Disk Usage Problems

```
Large Model Scan Analysis:
├── HuggingFace Llama-2 70B download: ~140GB temp storage
├── 7z/ZIP extraction: 2x model size (compressed + extracted)
├── Multiple temp files per scanner: 5-10GB additional
└── No cleanup on interruption: Orphaned temp files
```

### Files to Modify

- `modelaudit/utils/streaming.py` - New streaming utilities
- `modelaudit/utils/memory_manager.py` - Memory vs disk strategy
- `modelaudit/scanners/base.py` - Stream-aware base scanner
- All scanner implementations - Add streaming support

### Implementation Details

#### 1. Streaming File Analysis (`modelaudit/utils/streaming.py`)

```python
import mmap
import io
from typing import Iterator, Optional, Union
from contextlib import contextmanager

class StreamingFileAnalyzer:
    """Memory-efficient file analysis with configurable strategies"""

    def __init__(self, memory_limit_mb: int = 512):
        self.memory_limit = memory_limit_mb * 1024 * 1024
        self.chunk_size = 8192  # 8KB chunks

    @contextmanager
    def get_file_stream(self, file_path: str, size_hint: Optional[int] = None):
        """Get optimal file stream based on file size"""
        file_size = size_hint or os.path.getsize(file_path)

        if file_size < self.memory_limit:
            # Small files: load into memory
            with open(file_path, 'rb') as f:
                yield io.BytesIO(f.read())

        elif file_size < self.memory_limit * 4:
            # Medium files: use memory mapping
            with open(file_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    yield io.BytesIO(mm[:])

        else:
            # Large files: stream directly
            with open(file_path, 'rb') as f:
                yield f

    def streaming_pickle_analysis(self, stream: io.IOBase) -> Iterator[dict]:
        """Analyze pickle opcodes without loading entire file"""
        import pickletools

        # Process opcodes in chunks
        buffer = b''
        while True:
            chunk = stream.read(self.chunk_size)
            if not chunk:
                break

            buffer += chunk

            # Try to parse complete opcodes from buffer
            try:
                ops = list(pickletools.genops(io.BytesIO(buffer)))
                for op in ops:
                    if op[0].name in ('GLOBAL', 'INST', 'STACK_GLOBAL'):
                        yield {
                            'opcode': op[0].name,
                            'args': op[1],
                            'position': op[2]
                        }
                # Keep remainder for next iteration
                buffer = b''
            except Exception:
                # Incomplete opcode, continue reading
                continue
```

#### 2. Smart Archive Handling (`modelaudit/scanners/archive_scanner.py`)

```python
class InMemoryArchiveScanner(BaseScanner):
    """Memory-efficient archive scanning without disk extraction"""

    def scan_zip_streaming(self, zip_path: str) -> ScanResult:
        """Scan ZIP archives without extracting to disk"""
        result = self._create_result()

        with zipfile.ZipFile(zip_path, 'r') as archive:
            for file_info in archive.infolist():
                if not self._should_scan_archived_file(file_info.filename):
                    continue

                # Extract to memory only
                with archive.open(file_info.filename) as archived_file:
                    # Determine if we can handle this in memory
                    if file_info.file_size < self.memory_limit:
                        # Small files: full memory processing
                        file_content = archived_file.read()
                        memory_stream = io.BytesIO(file_content)

                        # Scan the in-memory stream
                        scanner = self._get_scanner_for_content(file_info.filename, memory_stream)
                        if scanner:
                            file_result = scanner.scan_stream(memory_stream, f"{zip_path}:{file_info.filename}")
                            result.merge(file_result)

                    else:
                        # Large files: streaming analysis
                        scanner = self._get_streaming_scanner(file_info.filename)
                        if scanner:
                            file_result = scanner.scan_stream(archived_file, f"{zip_path}:{file_info.filename}")
                            result.merge(file_result)

        return result

    def scan_7z_streaming(self, archive_path: str) -> ScanResult:
        """Stream-scan 7z archives with minimal disk usage"""
        import py7zr
        result = self._create_result()

        with py7zr.SevenZipFile(archive_path, mode='r') as archive:
            # Get list of scannable files without extracting
            scannable_files = [
                name for name in archive.getnames()
                if self._should_scan_archived_file(name)
            ]

            # Use temporary buffer strategy
            with tempfile.SpooledTemporaryFile(max_size=self.memory_limit) as temp_buffer:
                for filename in scannable_files:
                    # Extract single file to memory buffer
                    archive.extract(targets=[filename], path=temp_buffer)
                    temp_buffer.seek(0)

                    # Scan from buffer
                    scanner = self._get_scanner_for_content(filename, temp_buffer)
                    if scanner:
                        file_result = scanner.scan_stream(temp_buffer, f"{archive_path}:{filename}")
                        result.merge(file_result)

                    # Clear buffer for next file
                    temp_buffer.seek(0)
                    temp_buffer.truncate(0)

        return result
```

#### 3. Remote File Streaming (`modelaudit/utils/remote_streaming.py`)

```python
class StreamingRemoteScanner:
    """Download and scan files without full local storage"""

    def scan_remote_streaming(self, url: str, max_size: int = None) -> ScanResult:
        """Scan remote files with streaming download"""
        import requests

        # Get file info without downloading
        head_response = requests.head(url, timeout=10)
        content_length = int(head_response.headers.get('content-length', 0))

        if max_size and content_length > max_size:
            raise ValueError(f"File too large: {content_length} bytes > {max_size} bytes")

        # Stream download and analyze
        with requests.get(url, stream=True, timeout=30) as response:
            response.raise_for_status()

            # Determine strategy based on size
            if content_length < self.memory_limit:
                # Small files: load to memory buffer
                buffer = io.BytesIO()
                for chunk in response.iter_content(chunk_size=8192):
                    buffer.write(chunk)
                buffer.seek(0)

                return self._scan_buffer(buffer, url)

            else:
                # Large files: streaming analysis
                return self._scan_response_stream(response, url)

    def _scan_response_stream(self, response, url: str) -> ScanResult:
        """Scan HTTP response stream without storing locally"""
        # Create a file-like object from the response stream
        stream_wrapper = ResponseStreamWrapper(response)

        # Detect format from first few bytes
        header = stream_wrapper.peek(64)
        file_format = detect_format_from_bytes(header)

        # Get appropriate streaming scanner
        scanner = get_streaming_scanner(file_format)
        return scanner.scan_stream(stream_wrapper, url)

class ResponseStreamWrapper:
    """Wrap HTTP response to provide file-like interface"""

    def __init__(self, response):
        self.response = response
        self.iterator = response.iter_content(chunk_size=8192)
        self.buffer = b''
        self.position = 0

    def read(self, size: int = -1) -> bytes:
        """Read data from stream"""
        while len(self.buffer) < size or size == -1:
            try:
                chunk = next(self.iterator)
                self.buffer += chunk
            except StopIteration:
                break

        if size == -1:
            result = self.buffer
            self.buffer = b''
        else:
            result = self.buffer[:size]
            self.buffer = self.buffer[size:]

        self.position += len(result)
        return result

    def peek(self, size: int) -> bytes:
        """Peek at next bytes without consuming them"""
        while len(self.buffer) < size:
            try:
                chunk = next(self.iterator)
                self.buffer += chunk
            except StopIteration:
                break
        return self.buffer[:size]
```

### Validation Steps

```python
def test_streaming_vs_traditional_disk_usage():
    """Compare disk usage between streaming and traditional approaches"""
    import psutil
    import tempfile

    # Traditional approach
    with tempfile.TemporaryDirectory() as temp_dir:
        initial_disk = psutil.disk_usage(temp_dir).free

        traditional_scanner = TraditionalArchiveScanner()
        traditional_result = traditional_scanner.scan("tests/assets/large_model.zip")

        traditional_disk = psutil.disk_usage(temp_dir).free
        traditional_usage = initial_disk - traditional_disk

    # Streaming approach
    with tempfile.TemporaryDirectory() as temp_dir:
        initial_disk = psutil.disk_usage(temp_dir).free

        streaming_scanner = InMemoryArchiveScanner()
        streaming_result = streaming_scanner.scan("tests/assets/large_model.zip")

        streaming_disk = psutil.disk_usage(temp_dir).free
        streaming_usage = initial_disk - streaming_disk

    # Verify massive disk usage reduction
    disk_reduction_ratio = streaming_usage / traditional_usage
    assert disk_reduction_ratio < 0.2  # At least 80% reduction
    assert streaming_result.issues == traditional_result.issues  # Same detection

def test_large_file_memory_limit():
    """Test that large files don't exceed memory limits"""
    analyzer = StreamingFileAnalyzer(memory_limit_mb=100)

    # Create 500MB test file
    large_file_path = create_large_test_file(size_mb=500)

    # Memory usage should stay under limit
    import tracemalloc
    tracemalloc.start()

    with analyzer.get_file_stream(large_file_path) as stream:
        # Process file in chunks
        total_bytes = 0
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            total_bytes += len(chunk)

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Memory should stay under limit + overhead
    assert peak < 120 * 1024 * 1024  # 120MB max (100MB + 20MB overhead)
    assert total_bytes == 500 * 1024 * 1024  # All data processed
```

### Acceptance Criteria

- [ ] 80%+ reduction in temporary disk usage
- [ ] Memory usage stays within configured limits
- [ ] No degradation in detection accuracy
- [ ] Graceful handling of memory pressure
- [ ] Streaming support for all archive formats
- [ ] Remote file scanning without local storage

---

## Task 13: Implement Intelligent Result Caching System

**Priority**: P1 - Performance Critical  
**Estimated Effort**: 4-6 days
**Dependencies**: None

### Objective

Speed up repeat scans by 5-10x through intelligent caching of scan results, metadata, and expensive operations.

### Current Performance Issues

```
Repeat Scan Analysis:
├── Same file scanned multiple times: No caching
├── Archive re-extraction: Full extraction on each scan
├── Remote re-downloads: No HTTP caching
├── Pattern compilation: Regex recompiled each scan
└── Large model re-analysis: 10+ minutes for same file
```

### Files to Modify

- `modelaudit/cache/` - New caching subsystem
- `modelaudit/cache/file_cache.py` - File-level result caching
- `modelaudit/cache/content_cache.py` - Content-based caching
- `modelaudit/scanners/base.py` - Cache-aware scanning

### Implementation Details

#### 1. Content-Based File Caching (`modelaudit/cache/file_cache.py`)

```python
import hashlib
import sqlite3
import json
import time
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict

@dataclass
class CacheEntry:
    file_hash: str
    file_size: int
    file_mtime: float
    scan_version: str  # ModelAudit version
    scanner_versions: Dict[str, str]  # Individual scanner versions
    scan_results: Dict[str, Any]
    cached_at: float
    access_count: int
    last_access: float

class FileResultCache:
    """Intelligent file-level result caching with content awareness"""

    def __init__(self, cache_dir: str = None, max_size_gb: float = 2.0):
        self.cache_dir = Path(cache_dir or Path.home() / ".modelaudit" / "cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.max_cache_size = max_size_gb * 1024 * 1024 * 1024
        self.db_path = self.cache_dir / "scan_cache.db"

        self._init_database()
        self._cleanup_if_needed()

    def _init_database(self):
        """Initialize SQLite cache database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_cache (
                    file_hash TEXT PRIMARY KEY,
                    file_size INTEGER,
                    file_mtime REAL,
                    scan_version TEXT,
                    scanner_versions TEXT,  -- JSON
                    scan_results TEXT,      -- JSON
                    cached_at REAL,
                    access_count INTEGER DEFAULT 1,
                    last_access REAL
                )
            """)

            # Create index for cleanup queries
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_access
                ON scan_cache(last_access, cached_at)
            """)

    def _get_file_hash(self, file_path: str, quick_check: bool = True) -> tuple[str, int, float]:
        """Get content hash, size, and mtime for file"""
        file_stat = os.stat(file_path)
        file_size = file_stat.st_size
        file_mtime = file_stat.st_mtime

        if quick_check and file_size > 100 * 1024 * 1024:  # Large files (>100MB)
            # Quick hash: first 64KB + last 64KB + size + mtime
            with open(file_path, 'rb') as f:
                start_chunk = f.read(65536)  # First 64KB
                f.seek(-min(65536, file_size), 2)  # Last 64KB
                end_chunk = f.read(65536)

                hash_content = start_chunk + end_chunk + str(file_size).encode() + str(file_mtime).encode()
                file_hash = hashlib.sha256(hash_content).hexdigest()
        else:
            # Full hash for smaller files
            hash_obj = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_obj.update(chunk)
            file_hash = hash_obj.hexdigest()

        return file_hash, file_size, file_mtime

    def get_cached_result(self, file_path: str, scanner_versions: Dict[str, str]) -> Optional[dict]:
        """Get cached scan result if valid"""
        try:
            file_hash, file_size, file_mtime = self._get_file_hash(file_path)

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT scan_results, scanner_versions, file_mtime
                    FROM scan_cache
                    WHERE file_hash = ? AND file_size = ?
                """, (file_hash, file_size))

                row = cursor.fetchone()
                if not row:
                    return None

                cached_results, cached_scanner_versions, cached_mtime = row

                # Check if file has been modified
                if abs(cached_mtime - file_mtime) > 1.0:  # 1 second tolerance
                    return None

                # Check if scanner versions match
                cached_versions = json.loads(cached_scanner_versions)
                if cached_versions != scanner_versions:
                    return None

                # Update access statistics
                conn.execute("""
                    UPDATE scan_cache
                    SET access_count = access_count + 1, last_access = ?
                    WHERE file_hash = ?
                """, (time.time(), file_hash))

                return json.loads(cached_results)

        except Exception as e:
            logger.debug(f"Cache lookup failed for {file_path}: {e}")
            return None

    def store_result(self, file_path: str, scanner_versions: Dict[str, str],
                    scan_results: dict) -> None:
        """Store scan results in cache"""
        try:
            file_hash, file_size, file_mtime = self._get_file_hash(file_path)

            cache_entry = CacheEntry(
                file_hash=file_hash,
                file_size=file_size,
                file_mtime=file_mtime,
                scan_version=get_modelaudit_version(),
                scanner_versions=scanner_versions,
                scan_results=scan_results,
                cached_at=time.time(),
                access_count=1,
                last_access=time.time()
            )

            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO scan_cache
                    (file_hash, file_size, file_mtime, scan_version,
                     scanner_versions, scan_results, cached_at, access_count, last_access)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cache_entry.file_hash,
                    cache_entry.file_size,
                    cache_entry.file_mtime,
                    cache_entry.scan_version,
                    json.dumps(cache_entry.scanner_versions),
                    json.dumps(cache_entry.scan_results),
                    cache_entry.cached_at,
                    cache_entry.access_count,
                    cache_entry.last_access
                ))

        except Exception as e:
            logger.warning(f"Failed to cache result for {file_path}: {e}")

    def _cleanup_if_needed(self):
        """Clean up cache if it exceeds size limit"""
        cache_size = sum(f.stat().st_size for f in self.cache_dir.rglob('*') if f.is_file())

        if cache_size > self.max_cache_size:
            self._cleanup_old_entries()

    def _cleanup_old_entries(self):
        """Remove least recently used cache entries"""
        with sqlite3.connect(self.db_path) as conn:
            # Keep entries accessed in last 7 days or most frequently accessed
            cutoff_time = time.time() - (7 * 24 * 60 * 60)

            conn.execute("""
                DELETE FROM scan_cache
                WHERE last_access < ? AND access_count < 3
            """, (cutoff_time,))

            # If still too large, remove oldest entries
            total_entries = conn.execute("SELECT COUNT(*) FROM scan_cache").fetchone()[0]
            if total_entries > 10000:  # Max 10k cached entries
                conn.execute("""
                    DELETE FROM scan_cache
                    WHERE file_hash IN (
                        SELECT file_hash FROM scan_cache
                        ORDER BY last_access ASC
                        LIMIT ?
                    )
                """, (total_entries - 8000,))
```

#### 2. Remote Content Caching (`modelaudit/cache/remote_cache.py`)

```python
class RemoteContentCache:
    """HTTP-aware caching for remote model files"""

    def __init__(self, cache_dir: str = None):
        self.cache_dir = Path(cache_dir or Path.home() / ".modelaudit" / "remote_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.metadata_db = self.cache_dir / "remote_metadata.db"
        self._init_metadata_db()

    def _init_metadata_db(self):
        """Initialize metadata database for remote resources"""
        with sqlite3.connect(self.metadata_db) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS remote_metadata (
                    url_hash TEXT PRIMARY KEY,
                    original_url TEXT,
                    etag TEXT,
                    last_modified TEXT,
                    content_length INTEGER,
                    cached_path TEXT,
                    cached_at REAL,
                    last_access REAL,
                    access_count INTEGER DEFAULT 1
                )
            """)

    def get_cached_remote_file(self, url: str) -> Optional[str]:
        """Get cached remote file if still valid"""
        url_hash = hashlib.sha256(url.encode()).hexdigest()

        with sqlite3.connect(self.metadata_db) as conn:
            cursor = conn.execute("""
                SELECT cached_path, etag, last_modified
                FROM remote_metadata
                WHERE url_hash = ?
            """, (url_hash,))

            row = cursor.fetchone()
            if not row:
                return None

            cached_path, etag, last_modified = row
            cached_file = Path(cached_path)

            if not cached_file.exists():
                return None

            # Validate with HEAD request
            if self._is_remote_file_unchanged(url, etag, last_modified):
                # Update access stats
                conn.execute("""
                    UPDATE remote_metadata
                    SET access_count = access_count + 1, last_access = ?
                    WHERE url_hash = ?
                """, (time.time(), url_hash))

                return str(cached_file)

        return None

    def cache_remote_file(self, url: str, content: bytes,
                         etag: str = None, last_modified: str = None) -> str:
        """Cache remote file content"""
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        cached_path = self.cache_dir / f"{url_hash}.cache"

        # Store content
        with open(cached_path, 'wb') as f:
            f.write(content)

        # Store metadata
        with sqlite3.connect(self.metadata_db) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO remote_metadata
                (url_hash, original_url, etag, last_modified, content_length,
                 cached_path, cached_at, last_access, access_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                url_hash, url, etag, last_modified, len(content),
                str(cached_path), time.time(), time.time(), 1
            ))

        return str(cached_path)

    def _is_remote_file_unchanged(self, url: str, cached_etag: str = None,
                                 cached_last_modified: str = None) -> bool:
        """Check if remote file is unchanged using HTTP headers"""
        try:
            import requests

            headers = {}
            if cached_etag:
                headers['If-None-Match'] = cached_etag
            if cached_last_modified:
                headers['If-Modified-Since'] = cached_last_modified

            response = requests.head(url, headers=headers, timeout=10)

            # 304 Not Modified means file is unchanged
            return response.status_code == 304

        except Exception:
            # If we can't verify, assume it might have changed
            return False
```

#### 3. Cache-Aware Base Scanner (`modelaudit/scanners/base.py`)

```python
class CacheAwareScanner(BaseScanner):
    """Base scanner with intelligent caching support"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.file_cache = FileResultCache()
        self.remote_cache = RemoteContentCache()
        self._scanner_versions = self._get_scanner_versions()

    def scan(self, path: str, **kwargs) -> ScanResult:
        """Cache-aware scanning with fallback"""
        # Try to get cached result first
        cached_result = self.file_cache.get_cached_result(path, self._scanner_versions)
        if cached_result:
            logger.debug(f"Using cached result for {path}")
            return ScanResult.from_dict(cached_result)

        # Perform actual scan
        logger.debug(f"Scanning {path} (not in cache)")
        result = self._scan_implementation(path, **kwargs)

        # Cache the result
        self.file_cache.store_result(
            path,
            self._scanner_versions,
            result.to_dict()
        )

        return result

    def _get_scanner_versions(self) -> Dict[str, str]:
        """Get versions of all scanners for cache invalidation"""
        versions = {
            'modelaudit': get_modelaudit_version(),
            'scanner_class': f"{self.__class__.__module__}.{self.__class__.__name__}",
            'scanner_version': getattr(self, 'version', '1.0')
        }

        # Include pattern/rule versions
        if hasattr(self, 'pattern_version'):
            versions['patterns'] = self.pattern_version

        return versions

    def scan_remote_cached(self, url: str, **kwargs) -> ScanResult:
        """Scan remote URL with caching"""
        # Check if we have cached content
        cached_file = self.remote_cache.get_cached_remote_file(url)
        if cached_file:
            logger.debug(f"Using cached remote file for {url}")
            return self.scan(cached_file, **kwargs)

        # Download and cache
        logger.debug(f"Downloading and caching {url}")
        content, etag, last_modified = self._download_with_headers(url)

        cached_path = self.remote_cache.cache_remote_file(
            url, content, etag, last_modified
        )

        return self.scan(cached_path, **kwargs)
```

### Performance Benchmarks

```python
def test_cache_performance_improvement():
    """Measure cache performance improvement"""
    import time

    # Create test file
    test_file = "tests/assets/large_model.pkl"
    scanner = CacheAwarePickleScanner()

    # First scan (no cache)
    start_time = time.time()
    result1 = scanner.scan(test_file)
    first_scan_time = time.time() - start_time

    # Second scan (with cache)
    start_time = time.time()
    result2 = scanner.scan(test_file)
    cached_scan_time = time.time() - start_time

    # Verify results are identical
    assert result1.to_dict() == result2.to_dict()

    # Verify significant speedup (at least 5x)
    speedup_ratio = first_scan_time / cached_scan_time
    assert speedup_ratio >= 5.0

    print(f"Cache speedup: {speedup_ratio:.1f}x")
    print(f"First scan: {first_scan_time:.2f}s")
    print(f"Cached scan: {cached_scan_time:.2f}s")

def test_cache_invalidation():
    """Test that cache is invalidated when files change"""
    scanner = CacheAwarePickleScanner()
    test_file = "tests/assets/mutable_test.pkl"

    # First scan
    result1 = scanner.scan(test_file)

    # Modify file
    time.sleep(1.1)  # Ensure mtime difference
    with open(test_file, 'ab') as f:
        f.write(b'\n# modified')

    # Second scan should not use cache
    with patch('modelaudit.cache.file_cache.logger') as mock_logger:
        result2 = scanner.scan(test_file)

        # Should see "not in cache" message, not "using cached result"
        debug_calls = [call for call in mock_logger.debug.call_args_list]
        cache_miss_calls = [call for call in debug_calls if "not in cache" in str(call)]
        assert len(cache_miss_calls) > 0
```

### Acceptance Criteria

- [ ] 5-10x speedup for repeat scans of same files
- [ ] Proper cache invalidation when files change
- [ ] Memory usage under 100MB for cache operations
- [ ] Configurable cache size limits and cleanup
- [ ] HTTP caching for remote files with ETag support
- [ ] Cross-session cache persistence

---

## Task 14: Implement Probabilistic Pre-Filtering

**Priority**: P2 - Advanced Optimization
**Estimated Effort**: 3-4 days
**Dependencies**: Task 13 (Caching)

### Objective

Use probabilistic data structures (Bloom filters) and lightweight pre-checks to quickly eliminate obviously safe files before expensive scanning.

### Implementation Strategy

#### 1. Bloom Filter for Known-Safe Files

```python
class SafeFileBloomFilter:
    """Probabilistic filter for known-safe file signatures"""

    def __init__(self, capacity: int = 1000000, error_rate: float = 0.001):
        from pybloom_live import BloomFilter
        self.bloom_filter = BloomFilter(capacity=capacity, error_rate=error_rate)
        self._load_known_safe_signatures()

    def _load_known_safe_signatures(self):
        """Load signatures of known-safe files"""
        # Add common safe file patterns
        safe_patterns = [
            # Common PyTorch storage signatures
            "torch.FloatStorage",
            "torch.LongStorage",
            "collections.OrderedDict",

            # NumPy safe patterns
            "numpy.ndarray",
            "numpy.dtype",

            # Safe pickle patterns
            "__builtin__.list",
            "__builtin__.dict",
            "__builtin__.tuple"
        ]

        for pattern in safe_patterns:
            self.bloom_filter.add(pattern)

    def might_be_dangerous(self, file_signature: str) -> bool:
        """Check if file might contain dangerous content (false positives possible)"""
        # If signature is NOT in bloom filter, file might be dangerous
        return file_signature not in self.bloom_filter

    def quick_file_scan(self, file_path: str) -> tuple[bool, float]:
        """Quick scan to estimate danger probability"""
        try:
            # Read first 8KB for quick analysis
            with open(file_path, 'rb') as f:
                header = f.read(8192)

            # Look for obvious danger indicators
            danger_score = 0.0

            # Check for common malicious patterns
            if b'eval(' in header or b'exec(' in header:
                danger_score += 0.8

            if b'__import__' in header:
                danger_score += 0.6

            if b'subprocess' in header or b'os.system' in header:
                danger_score += 0.9

            # Check for common safe patterns
            safe_patterns = [b'torch.', b'numpy.', b'collections.OrderedDict']
            safe_matches = sum(1 for pattern in safe_patterns if pattern in header)
            danger_score -= safe_matches * 0.3

            # Normalize score
            danger_score = max(0.0, min(1.0, danger_score))

            return danger_score > 0.5, danger_score

        except Exception:
            # If we can't read file, assume it might be dangerous
            return True, 0.8
```

#### 2. Smart Scanning Pipeline

```python
class OptimizedScanningPipeline:
    """Multi-stage scanning pipeline with early exit"""

    def __init__(self):
        self.bloom_filter = SafeFileBloomFilter()
        self.file_cache = FileResultCache()
        self.quick_scanner = QuickPatternScanner()

    def scan_with_prefiltering(self, file_path: str) -> ScanResult:
        """Multi-stage scanning with early exits"""

        # Stage 1: Cache check (fastest)
        cached_result = self.file_cache.get_cached_result(file_path, {})
        if cached_result:
            return ScanResult.from_dict(cached_result)

        # Stage 2: Quick probabilistic check
        might_be_dangerous, danger_score = self.bloom_filter.quick_file_scan(file_path)

        if not might_be_dangerous and danger_score < 0.1:
            # Very likely safe - minimal scan
            return self._create_safe_result(file_path, danger_score)

        # Stage 3: Pattern-based pre-scan
        if danger_score < 0.7:
            quick_result = self.quick_scanner.scan(file_path)
            if not quick_result.has_issues():
                return quick_result

        # Stage 4: Full comprehensive scan
        return self._full_scan(file_path)

    def _create_safe_result(self, file_path: str, confidence: float) -> ScanResult:
        """Create result for files determined to be safe"""
        result = ScanResult(file_path)
        result.add_info(
            name="Probabilistic Safety Check",
            message=f"File determined to be safe with {(1-confidence)*100:.1f}% confidence",
            details={"safety_confidence": 1-confidence, "method": "bloom_filter"}
        )
        return result
```

### Acceptance Criteria

- [ ] 3-5x speedup for obviously safe files
- [ ] Less than 0.1% false negatives (missed dangerous files)
- [ ] Acceptable false positive rate (< 5% unnecessary full scans)
- [ ] Memory usage under 50MB for probabilistic structures

---

## Task 15: Advanced Memory and Resource Management

**Priority**: P2 - System Optimization  
**Estimated Effort**: 3-4 days
**Dependencies**: Task 12 (Streaming)

### Objective

Implement sophisticated memory management, connection pooling, and resource optimization for handling large-scale scanning operations.

### Implementation Details

#### 1. Memory Pool Management

```python
class ScannerMemoryPool:
    """Reusable memory buffers to reduce allocation overhead"""

    def __init__(self, buffer_size: int = 1024*1024, pool_size: int = 10):
        self.buffer_size = buffer_size
        self.pool_size = pool_size
        self.available_buffers = queue.Queue(maxsize=pool_size)

        # Pre-allocate buffers
        for _ in range(pool_size):
            self.available_buffers.put(bytearray(buffer_size))

    @contextmanager
    def get_buffer(self):
        """Get a reusable buffer from the pool"""
        try:
            buffer = self.available_buffers.get_nowait()
        except queue.Empty:
            # Create temporary buffer if pool is exhausted
            buffer = bytearray(self.buffer_size)

        try:
            yield buffer
        finally:
            # Return buffer to pool if there's space
            try:
                # Clear the buffer
                buffer[:] = b'\x00' * len(buffer)
                self.available_buffers.put_nowait(buffer)
            except queue.Full:
                # Pool is full, let buffer be garbage collected
                pass

class AdaptiveMemoryManager:
    """Dynamic memory management based on system resources"""

    def __init__(self):
        self.memory_pool = ScannerMemoryPool()
        self.current_memory_usage = 0
        self.memory_limit = self._calculate_memory_limit()

    def _calculate_memory_limit(self) -> int:
        """Calculate optimal memory limit based on available system memory"""
        import psutil

        # Use up to 25% of available memory, max 2GB
        available_memory = psutil.virtual_memory().available
        optimal_limit = min(available_memory // 4, 2 * 1024 * 1024 * 1024)

        return optimal_limit

    @contextmanager
    def memory_context(self, estimated_usage: int):
        """Context manager for tracking memory usage"""
        if self.current_memory_usage + estimated_usage > self.memory_limit:
            # Force garbage collection
            import gc
            gc.collect()

            # If still over limit, use disk fallback
            if self.current_memory_usage + estimated_usage > self.memory_limit:
                yield "disk"  # Signal to use disk-based processing
                return

        self.current_memory_usage += estimated_usage
        try:
            yield "memory"  # Signal to use memory-based processing
        finally:
            self.current_memory_usage -= estimated_usage
```

#### 2. Connection Pooling for Remote Resources

```python
class HTTPConnectionPool:
    """Reusable HTTP connections for remote scanning"""

    def __init__(self, max_connections: int = 10):
        import urllib3

        self.pool_manager = urllib3.PoolManager(
            num_pools=5,
            maxsize=max_connections,
            block=True,
            retries=urllib3.Retry(
                total=3,
                backoff_factor=0.3,
                status_forcelist=[500, 502, 503, 504]
            )
        )

    def download_with_caching(self, url: str, headers: dict = None) -> bytes:
        """Download with connection reuse and smart caching"""
        response = self.pool_manager.request(
            'GET', url,
            headers=headers or {},
            preload_content=False  # Stream the response
        )

        # Stream download with progress tracking
        content = b''
        for chunk in response.stream(8192, decode_content=True):
            content += chunk

            # Memory pressure check
            if len(content) > 100 * 1024 * 1024:  # 100MB chunks
                # For very large files, yield control periodically
                import asyncio
                if hasattr(asyncio, 'current_task'):
                    asyncio.sleep(0)  # Yield to event loop

        response.release_conn()
        return content
```

### Acceptance Criteria

- [ ] Memory usage stays within system limits
- [ ] 50%+ reduction in memory allocations through pooling
- [ ] Graceful degradation under memory pressure
- [ ] Connection reuse for remote resources
- [ ] Automatic resource cleanup on interruption

---

## Summary and Implementation Roadmap

### Performance Impact Summary

| Optimization                | Disk Space Reduction | Speed Improvement | Implementation Effort |
| --------------------------- | -------------------- | ----------------- | --------------------- |
| Streaming Scanning          | 80-90%               | 2-3x              | High                  |
| Intelligent Caching         | None                 | 5-10x             | Medium                |
| Probabilistic Pre-filtering | None                 | 3-5x              | Medium                |
| Memory Management           | Varies               | 1.5-2x            | Medium                |

### Implementation Priority

1. **Task 13 (Caching)** - Highest ROI, easiest to implement
2. **Task 12 (Streaming)** - Critical for large files, higher complexity
3. **Task 14 (Pre-filtering)** - Advanced optimization, good for scale
4. **Task 15 (Memory Management)** - System stability, lower priority

### Expected Overall Impact

- **10-50x faster** repeat scans through caching
- **80-90% less disk usage** through streaming
- **Handle 10x larger models** without running out of resources
- **Better user experience** with progress indicators and faster feedback

These optimizations will transform ModelAudit from a functional security scanner into a high-performance, enterprise-ready tool capable of handling the largest ML models efficiently.
