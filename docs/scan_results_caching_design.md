# ModelAudit Scan Results Caching System Design

## Core Concept: Content-Hash + Version-Based Caching

Cache scan results using a composite key of `file_content_hash + modelaudit_version + scanner_versions` to achieve:

- **Instant repeat scans** for same content
- **Automatic invalidation** when scanners improve
- **Cross-file deduplication** (same content, different paths)
- **Version-aware caching** (no false positives from outdated scans)

## Architecture Overview

```
~/.modelaudit/cache/
├── huggingface/              # Existing HF model downloads
├── f3/                       # Existing cloud storage cache
├── scan_results/             # NEW: Scan result cache
│   ├── results.db            # SQLite database
│   ├── metadata.json         # Cache metadata
│   └── blobs/                # Large result payloads (optional)
│       ├── ab/cd/abcd...     # Hash-based storage
└── user_config.json         # Existing user config
```

## Database Schema Design

```sql
-- Main scan results table
CREATE TABLE scan_results (
    -- Primary cache key
    cache_key TEXT PRIMARY KEY,

    -- File identification
    file_hash TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    file_name TEXT,  -- For debugging/display

    -- Version tracking
    modelaudit_version TEXT NOT NULL,
    scanner_versions TEXT NOT NULL,  -- JSON blob
    config_hash TEXT,                -- Hash of scan configuration

    -- Results
    scan_result TEXT NOT NULL,       -- JSON serialized ScanResult
    scan_status TEXT NOT NULL,       -- 'success', 'error', 'timeout'

    -- Metadata
    scanned_at REAL NOT NULL,
    access_count INTEGER DEFAULT 1,
    last_access REAL NOT NULL,
    scan_duration_ms INTEGER,

    -- Performance tracking
    file_format TEXT,                -- 'pickle', 'pytorch', etc.
    scanner_used TEXT               -- Which scanner was used
);

-- Index for fast lookups
CREATE INDEX idx_file_hash ON scan_results(file_hash);
CREATE INDEX idx_last_access ON scan_results(last_access);
CREATE INDEX idx_modelaudit_version ON scan_results(modelaudit_version);

-- Cache statistics table
CREATE TABLE cache_stats (
    date TEXT PRIMARY KEY,
    cache_hits INTEGER DEFAULT 0,
    cache_misses INTEGER DEFAULT 0,
    files_scanned INTEGER DEFAULT 0,
    avg_scan_time_ms REAL,
    cache_size_mb REAL
);
```

## Cache Key Generation Strategy

```python
class ScanResultsCache:
    def generate_cache_key(self, file_path: str) -> tuple[str, dict]:
        """Generate cache key and metadata for file"""

        # 1. Calculate file hash (optimized for large files)
        file_hash, file_size = self._calculate_file_hash(file_path)

        # 2. Get version fingerprint
        version_info = {
            'modelaudit': get_modelaudit_version(),
            'scanners': self._get_scanner_versions(),
            'config': self._get_config_hash(),
        }

        # 3. Create composite cache key
        version_string = self._serialize_versions(version_info)
        cache_key = f"{file_hash}:{hashlib.sha256(version_string.encode()).hexdigest()[:16]}"

        return cache_key, {
            'file_hash': file_hash,
            'file_size': file_size,
            'version_info': version_info
        }

    def _calculate_file_hash(self, file_path: str) -> tuple[str, int]:
        """Smart file hashing - full hash for small files, partial for large"""
        file_size = os.path.getsize(file_path)

        if file_size < 50 * 1024 * 1024:  # < 50MB: full hash
            return self._full_file_hash(file_path), file_size
        else:  # >= 50MB: smart partial hash
            return self._smart_partial_hash(file_path, file_size), file_size

    def _smart_partial_hash(self, file_path: str, file_size: int) -> str:
        """Partial hash: first 64KB + last 64KB + size + mtime + sample chunks"""
        hasher = hashlib.blake2b()  # Fast, cryptographically secure

        with open(file_path, 'rb') as f:
            # First 64KB
            hasher.update(f.read(65536))

            # Sample 8KB every 10MB through the middle
            if file_size > 2 * 65536:
                middle_samples = min(10, file_size // (10 * 1024 * 1024))
                for i in range(middle_samples):
                    offset = 65536 + (i * file_size // middle_samples)
                    f.seek(offset)
                    hasher.update(f.read(8192))

            # Last 64KB
            if file_size > 65536:
                f.seek(-65536, 2)
                hasher.update(f.read(65536))

        # Include file metadata
        stat = os.stat(file_path)
        hasher.update(str(file_size).encode())
        hasher.update(str(stat.st_mtime).encode())

        return hasher.hexdigest()

    def _get_scanner_versions(self) -> dict:
        """Get version fingerprint for all scanners and their rules"""
        from modelaudit.scanners import get_registry

        scanner_versions = {}
        registry = get_registry()

        for scanner_name, scanner_class in registry.items():
            version_info = {
                'class': f"{scanner_class.__module__}.{scanner_class.__name__}",
                'version': getattr(scanner_class, 'version', '1.0'),
            }

            # Include pattern/rule versions if available
            if hasattr(scanner_class, 'patterns_version'):
                version_info['patterns'] = scanner_class.patterns_version

            # Include suspicious symbols version for relevant scanners
            if hasattr(scanner_class, 'uses_suspicious_symbols'):
                from modelaudit.suspicious_symbols import get_symbols_version
                version_info['symbols'] = get_symbols_version()

            scanner_versions[scanner_name] = version_info

        return scanner_versions
```

## Cache Operations Implementation

```python
class ScanResultsCache:
    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = Path(cache_dir or Path.home() / ".modelaudit" / "cache")
        self.db_path = self.cache_dir / "scan_results" / "results.db"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        (self.cache_dir / "scan_results").mkdir(exist_ok=True)

        self._init_database()
        self._stats = CacheStats(self.db_path)

    def get_cached_result(self, file_path: str) -> Optional[ScanResult]:
        """Get cached scan result if available and valid"""
        try:
            cache_key, metadata = self.generate_cache_key(file_path)

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT scan_result, scan_status, scanned_at
                    FROM scan_results
                    WHERE cache_key = ?
                """, (cache_key,))

                row = cursor.fetchone()
                if not row:
                    self._stats.record_cache_miss()
                    return None

                scan_result_json, scan_status, scanned_at = row

                # Verify result is not too old (optional expiration)
                age_days = (time.time() - scanned_at) / (24 * 60 * 60)
                if age_days > 30:  # Results expire after 30 days
                    self._stats.record_cache_miss('expired')
                    return None

                # Update access statistics
                conn.execute("""
                    UPDATE scan_results
                    SET access_count = access_count + 1, last_access = ?
                    WHERE cache_key = ?
                """, (time.time(), cache_key))

                self._stats.record_cache_hit()

                # Deserialize and return result
                if scan_status == 'success':
                    return ScanResult.from_json(scan_result_json)
                else:
                    # Return cached error/timeout result
                    return ScanResult.from_error(scan_result_json)

        except Exception as e:
            logger.debug(f"Cache lookup failed for {file_path}: {e}")
            self._stats.record_cache_miss('error')
            return None

    def store_result(self, file_path: str, result: ScanResult,
                    scan_duration_ms: int = None) -> None:
        """Store scan result in cache"""
        try:
            cache_key, metadata = self.generate_cache_key(file_path)

            # Determine file format for analytics
            file_format = self._detect_file_format(file_path)

            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO scan_results
                    (cache_key, file_hash, file_size, file_name,
                     modelaudit_version, scanner_versions,
                     scan_result, scan_status, scanned_at, last_access,
                     scan_duration_ms, file_format, scanner_used)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cache_key,
                    metadata['file_hash'],
                    metadata['file_size'],
                    os.path.basename(file_path),
                    metadata['version_info']['modelaudit'],
                    json.dumps(metadata['version_info']['scanners']),
                    result.to_json(),
                    'success' if not result.has_errors else 'error',
                    time.time(),
                    time.time(),
                    scan_duration_ms,
                    file_format,
                    result.primary_scanner if hasattr(result, 'primary_scanner') else None
                ))

            self._cleanup_if_needed()

        except Exception as e:
            logger.warning(f"Failed to cache result for {file_path}: {e}")

    def cleanup_old_entries(self, max_age_days: int = 30, max_entries: int = 100000):
        """Clean up old cache entries"""
        cutoff_time = time.time() - (max_age_days * 24 * 60 * 60)

        with sqlite3.connect(self.db_path) as conn:
            # Remove old entries
            conn.execute("""
                DELETE FROM scan_results
                WHERE last_access < ? OR scanned_at < ?
            """, (cutoff_time, cutoff_time))

            # If still too many entries, remove least accessed
            total_entries = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
            if total_entries > max_entries:
                conn.execute("""
                    DELETE FROM scan_results
                    WHERE cache_key IN (
                        SELECT cache_key FROM scan_results
                        ORDER BY access_count ASC, last_access ASC
                        LIMIT ?
                    )
                """, (total_entries - max_entries * 0.8,))  # Remove 20% excess

            # Vacuum to reclaim space
            conn.execute("VACUUM")

    def get_cache_stats(self) -> dict:
        """Get cache performance statistics"""
        with sqlite3.connect(self.db_path) as conn:
            stats = conn.execute("""
                SELECT
                    COUNT(*) as total_entries,
                    COUNT(DISTINCT file_hash) as unique_files,
                    SUM(access_count) as total_accesses,
                    AVG(scan_duration_ms) as avg_scan_time,
                    MAX(scanned_at) - MIN(scanned_at) as cache_age_seconds,
                    SUM(file_size) / (1024*1024) as cached_data_mb
                FROM scan_results
            """).fetchone()

        return {
            'total_entries': stats[0],
            'unique_files': stats[1],
            'total_accesses': stats[2],
            'avg_scan_time_ms': stats[3] or 0,
            'cache_age_days': (stats[4] or 0) / (24 * 60 * 60),
            'cached_data_mb': stats[5] or 0,
            'hit_rate': self._stats.get_hit_rate()
        }
```

## Integration with Scanners

```python
# Enhanced base scanner with caching
class CacheAwareScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.cache = ScanResultsCache()

    def scan(self, file_path: str, **kwargs) -> ScanResult:
        """Cache-aware scanning with performance tracking"""

        # Try cache first
        start_time = time.time()
        cached_result = self.cache.get_cached_result(file_path)

        if cached_result:
            cached_result.metadata['cache_hit'] = True
            cached_result.metadata['cache_lookup_ms'] = (time.time() - start_time) * 1000
            logger.info(f"Cache HIT for {os.path.basename(file_path)}")
            return cached_result

        # Cache miss - perform actual scan
        logger.info(f"Cache MISS for {os.path.basename(file_path)} - scanning...")
        scan_start = time.time()

        result = self._actual_scan(file_path, **kwargs)

        scan_duration = (time.time() - scan_start) * 1000
        result.metadata['cache_hit'] = False
        result.metadata['scan_duration_ms'] = scan_duration

        # Store result in cache
        self.cache.store_result(file_path, result, int(scan_duration))

        return result
```

## CLI Integration

```python
# Add cache management commands
@cli.group()
def cache():
    """Manage scan result cache"""
    pass

@cache.command()
def stats():
    """Show cache statistics"""
    cache = ScanResultsCache()
    stats = cache.get_cache_stats()

    click.echo("📊 Cache Statistics:")
    click.echo(f"  Total entries: {stats['total_entries']:,}")
    click.echo(f"  Unique files: {stats['unique_files']:,}")
    click.echo(f"  Hit rate: {stats['hit_rate']:.1%}")
    click.echo(f"  Avg scan time: {stats['avg_scan_time_ms']:.0f}ms")
    click.echo(f"  Cache age: {stats['cache_age_days']:.1f} days")
    click.echo(f"  Cached data: {stats['cached_data_mb']:.1f} MB")

@cache.command()
@click.option('--max-age', default=30, help='Max age in days')
@click.option('--dry-run', is_flag=True, help='Show what would be deleted')
def clean(max_age: int, dry_run: bool):
    """Clean old cache entries"""
    cache = ScanResultsCache()

    if dry_run:
        # Show what would be cleaned
        pass
    else:
        cache.cleanup_old_entries(max_age_days=max_age)
        click.echo(f"✅ Cleaned cache entries older than {max_age} days")

@cache.command()
@click.confirmation_option(prompt='Are you sure you want to clear the entire cache?')
def clear():
    """Clear entire scan results cache"""
    cache_dir = Path.home() / ".modelaudit" / "cache" / "scan_results"
    if cache_dir.exists():
        import shutil
        shutil.rmtree(cache_dir)
        click.echo("✅ Cache cleared")
```

## Expected Performance Impact

### **Cache Hit Scenarios:**

- **Same file, same location**: ~1ms lookup (instant)
- **Same content, different location**: ~1ms lookup (content deduplication)
- **Repeated HuggingFace model scans**: ~1ms vs 30+ seconds

### **Cache Management:**

- **Database size**: ~1KB per cached result
- **10,000 cached results**: ~10MB database
- **Automatic cleanup**: Maintains reasonable size
- **Smart hashing**: Minimal I/O overhead for large files

### **Version Invalidation:**

- **ModelAudit update**: Automatic cache invalidation
- **Scanner improvements**: New results, old cache ignored
- **Configuration changes**: Separate cache keys

This system would transform ModelAudit from scanning the same files repeatedly to instant results for any content you've seen before, regardless of filename or location!
