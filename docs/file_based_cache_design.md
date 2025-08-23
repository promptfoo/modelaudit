# File-Based Scan Results Cache Design

## Simple, Powerful Cache Architecture

**Core Principle**: Use the file system as the database - hash-based directory structure with JSON files.

```
~/.modelaudit/cache/
├── huggingface/              # Existing HF downloads (80GB)
├── f3/                       # Existing cloud storage cache
├── scan_results/             # NEW: File-based scan cache
│   ├── cache_metadata.json   # Global cache stats and config
│   ├── ab/                   # First 2 chars of hash
│   │   ├── cd/               # Next 2 chars of hash
│   │   │   └── abcd...ef.json # Full hash filename
│   │   └── ef/
│   │       └── abef...gh.json
│   └── version_index.json    # Fast version-based cleanup
└── user_config.json          # Existing user config
```

## Cache File Format

### **Individual Cache Entry** (`<hash>.json`):

```json
{
  "cache_key": "secure:blake2b_hash_here",
  "file_info": {
    "hash": "blake2b_file_content_hash",
    "size": 1048576,
    "original_name": "model.pkl"
  },
  "version_info": {
    "modelaudit_version": "1.5.0",
    "scanner_versions": {
      "pickle": "2.1.0",
      "tensorflow": "1.8.0"
    },
    "config_hash": "config_settings_hash"
  },
  "scan_result": {
    "issues": [...],
    "metadata": {...},
    "summary": {...}
  },
  "cache_metadata": {
    "scanned_at": 1692025200.123,
    "last_access": 1692025200.123,
    "access_count": 5,
    "scan_duration_ms": 1250,
    "file_format": "pickle"
  }
}
```

### **Cache Metadata** (`cache_metadata.json`):

```json
{
  "version": "1.0",
  "created_at": 1692025200.123,
  "last_cleanup": 1692025200.123,
  "statistics": {
    "total_entries": 1247,
    "cache_hits": 8934,
    "cache_misses": 2156,
    "total_disk_usage_mb": 12.4,
    "avg_scan_time_ms": 850
  },
  "settings": {
    "max_entries": 100000,
    "max_age_days": 30,
    "cleanup_threshold": 0.9
  }
}
```

### **Version Index** (`version_index.json`):

```json
{
  "modelaudit_versions": {
    "1.4.0": ["ab/cd/hash1.json", "ef/gh/hash2.json"],
    "1.5.0": ["ab/cd/hash3.json", "xy/zw/hash4.json"]
  },
  "last_updated": 1692025200.123
}
```

## Implementation

```python
import json
import hashlib
import time
import os
from pathlib import Path
from typing import Optional, Dict, List
from dataclasses import dataclass, asdict

@dataclass
class CacheEntry:
    cache_key: str
    file_info: Dict
    version_info: Dict
    scan_result: Dict
    cache_metadata: Dict

class FileScanResultsCache:
    """Simple file-based scan results cache"""

    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = Path(cache_dir or Path.home() / ".modelaudit" / "cache" / "scan_results")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.metadata_file = self.cache_dir / "cache_metadata.json"
        self.version_index_file = self.cache_dir / "version_index.json"

        self.hasher = SecureModelAuditHasher()
        self._ensure_metadata_exists()

    def get_cached_result(self, file_path: str) -> Optional[Dict]:
        """Get cached scan result if available"""
        try:
            # Generate cache key
            file_hash = self.hasher.hash_file(file_path)
            version_info = self._get_version_info()
            cache_key = self._generate_cache_key(file_hash, version_info)

            # Find cache file
            cache_file_path = self._get_cache_file_path(cache_key)

            if not cache_file_path.exists():
                self._record_cache_miss()
                return None

            # Load and validate cache entry
            with open(cache_file_path, 'r') as f:
                cache_entry = json.load(f)

            # Validate entry is still valid
            if not self._is_cache_entry_valid(cache_entry, file_path):
                # Remove invalid entry
                cache_file_path.unlink()
                self._record_cache_miss('invalid')
                return None

            # Update access statistics
            cache_entry['cache_metadata']['access_count'] += 1
            cache_entry['cache_metadata']['last_access'] = time.time()

            # Write back updated entry
            with open(cache_file_path, 'w') as f:
                json.dump(cache_entry, f, indent=2)

            self._record_cache_hit()
            return cache_entry['scan_result']

        except Exception as e:
            logger.debug(f"Cache lookup failed for {file_path}: {e}")
            self._record_cache_miss('error')
            return None

    def store_result(self, file_path: str, scan_result: Dict,
                    scan_duration_ms: int = None) -> None:
        """Store scan result in cache"""
        try:
            # Generate cache entry
            file_hash = self.hasher.hash_file(file_path)
            version_info = self._get_version_info()
            cache_key = self._generate_cache_key(file_hash, version_info)

            file_stat = os.stat(file_path)
            cache_entry = CacheEntry(
                cache_key=cache_key,
                file_info={
                    'hash': file_hash,
                    'size': file_stat.st_size,
                    'original_name': os.path.basename(file_path),
                    'mtime': file_stat.st_mtime
                },
                version_info=version_info,
                scan_result=scan_result,
                cache_metadata={
                    'scanned_at': time.time(),
                    'last_access': time.time(),
                    'access_count': 1,
                    'scan_duration_ms': scan_duration_ms,
                    'file_format': self._detect_file_format(file_path)
                }
            )

            # Save cache entry
            cache_file_path = self._get_cache_file_path(cache_key)
            cache_file_path.parent.mkdir(parents=True, exist_ok=True)

            with open(cache_file_path, 'w') as f:
                json.dump(asdict(cache_entry), f, indent=2)

            # Update version index
            self._update_version_index(cache_key, version_info['modelaudit_version'])

            # Update global statistics
            self._update_cache_statistics()

        except Exception as e:
            logger.warning(f"Failed to cache result for {file_path}: {e}")

    def _get_cache_file_path(self, cache_key: str) -> Path:
        """Get file system path for cache key"""
        # Remove prefix if present (e.g., "secure:")
        clean_key = cache_key.split(':')[-1]

        # Create nested directory structure: ab/cd/abcd...ef.json
        return self.cache_dir / clean_key[:2] / clean_key[2:4] / f"{clean_key}.json"

    def _generate_cache_key(self, file_hash: str, version_info: Dict) -> str:
        """Generate cache key from file hash and version info"""
        version_str = json.dumps(version_info, sort_keys=True)
        version_hash = hashlib.blake2b(version_str.encode(), digest_size=16).hexdigest()

        # Combine file hash with version hash
        return f"{file_hash}:{version_hash}"

    def _get_version_info(self) -> Dict:
        """Get current version information"""
        from modelaudit import __version__ as modelaudit_version

        return {
            'modelaudit_version': modelaudit_version,
            'scanner_versions': self._get_scanner_versions(),
            'config_hash': self._get_config_hash()
        }

    def _get_scanner_versions(self) -> Dict:
        """Get version fingerprint for all scanners"""
        # Import scanner registry
        from modelaudit.scanners import get_registry

        versions = {}
        for name, scanner_class in get_registry().items():
            versions[name] = getattr(scanner_class, 'version', '1.0')

        return versions

    def _get_config_hash(self) -> str:
        """Hash of current scanning configuration"""
        # Hash relevant configuration that affects scan results
        config_data = {
            'max_file_size': getattr(self, 'max_file_size', None),
            'blacklist_patterns': getattr(self, 'blacklist_patterns', None),
            # Add other config that affects scanning
        }

        config_str = json.dumps(config_data, sort_keys=True)
        return hashlib.blake2b(config_str.encode(), digest_size=8).hexdigest()

    def _is_cache_entry_valid(self, cache_entry: Dict, file_path: str) -> bool:
        """Validate that cache entry is still valid"""
        try:
            # Check file hasn't changed
            current_stat = os.stat(file_path)
            cached_mtime = cache_entry['file_info']['mtime']
            cached_size = cache_entry['file_info']['size']

            if abs(current_stat.st_mtime - cached_mtime) > 1.0:
                return False

            if current_stat.st_size != cached_size:
                return False

            # Check entry isn't too old
            scanned_at = cache_entry['cache_metadata']['scanned_at']
            age_days = (time.time() - scanned_at) / (24 * 60 * 60)

            if age_days > 30:  # Expire after 30 days
                return False

            return True

        except Exception:
            return False

    def cleanup_old_entries(self, max_age_days: int = 30) -> int:
        """Clean up old cache entries"""
        removed_count = 0
        cutoff_time = time.time() - (max_age_days * 24 * 60 * 60)

        # Walk through all cache files
        for cache_file in self.cache_dir.rglob("*.json"):
            if cache_file.name in ['cache_metadata.json', 'version_index.json']:
                continue

            try:
                with open(cache_file, 'r') as f:
                    cache_entry = json.load(f)

                last_access = cache_entry['cache_metadata']['last_access']

                if last_access < cutoff_time:
                    cache_file.unlink()
                    removed_count += 1

            except Exception as e:
                logger.debug(f"Error processing cache file {cache_file}: {e}")
                # Remove corrupted cache files
                cache_file.unlink()
                removed_count += 1

        # Clean up empty directories
        self._cleanup_empty_directories()

        # Update metadata
        self._update_cache_statistics()

        return removed_count

    def _cleanup_empty_directories(self):
        """Remove empty cache subdirectories"""
        for root, dirs, files in os.walk(self.cache_dir, topdown=False):
            for dirname in dirs:
                dir_path = Path(root) / dirname
                try:
                    if not any(dir_path.iterdir()):
                        dir_path.rmdir()
                except OSError:
                    pass  # Directory not empty or other error

    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        metadata = self._load_cache_metadata()

        # Count current entries
        total_files = len(list(self.cache_dir.rglob("*.json"))) - 2  # Exclude metadata files

        # Calculate disk usage
        total_size = sum(f.stat().st_size for f in self.cache_dir.rglob("*") if f.is_file())

        return {
            'total_entries': total_files,
            'total_size_mb': total_size / (1024 * 1024),
            'cache_hits': metadata['statistics']['cache_hits'],
            'cache_misses': metadata['statistics']['cache_misses'],
            'hit_rate': self._calculate_hit_rate(metadata),
            'avg_scan_time_ms': metadata['statistics']['avg_scan_time_ms']
        }

    def clear_cache(self) -> None:
        """Clear entire cache"""
        import shutil

        # Remove all cache files except metadata
        for item in self.cache_dir.iterdir():
            if item.name not in ['cache_metadata.json']:
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()

        # Reset metadata
        self._reset_cache_metadata()

    def _ensure_metadata_exists(self):
        """Ensure cache metadata file exists"""
        if not self.metadata_file.exists():
            self._create_initial_metadata()

    def _create_initial_metadata(self):
        """Create initial cache metadata"""
        metadata = {
            'version': '1.0',
            'created_at': time.time(),
            'last_cleanup': time.time(),
            'statistics': {
                'total_entries': 0,
                'cache_hits': 0,
                'cache_misses': 0,
                'total_disk_usage_mb': 0.0,
                'avg_scan_time_ms': 0.0
            },
            'settings': {
                'max_entries': 100000,
                'max_age_days': 30,
                'cleanup_threshold': 0.9
            }
        }

        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
```

## CLI Integration

```python
# Add to modelaudit/cli.py

@cli.group()
def cache():
    """Manage scan result cache"""
    pass

@cache.command()
def stats():
    """Show cache statistics"""
    cache = FileScanResultsCache()
    stats = cache.get_cache_stats()

    click.echo("📊 Cache Statistics:")
    click.echo(f"  Entries: {stats['total_entries']:,}")
    click.echo(f"  Size: {stats['total_size_mb']:.1f} MB")
    click.echo(f"  Hit rate: {stats['hit_rate']:.1%}")
    click.echo(f"  Avg scan time: {stats['avg_scan_time_ms']:.0f}ms")

@cache.command()
@click.option('--max-age', default=30, help='Max age in days')
def clean(max_age: int):
    """Clean old cache entries"""
    cache = FileScanResultsCache()
    removed = cache.cleanup_old_entries(max_age_days=max_age)
    click.echo(f"✅ Removed {removed} old cache entries")

@cache.command()
@click.confirmation_option(prompt='Clear entire cache?')
def clear():
    """Clear entire cache"""
    cache = FileScanResultsCache()
    cache.clear_cache()
    click.echo("✅ Cache cleared")
```

<function_calls>
<invoke name="TodoWrite">
<parameter name="todos">[{"content": "Design robust file hashing strategy for cache system", "status": "completed", "activeForm": "Designing robust file hashing strategy for cache system"}, {"content": "Implement streaming hash calculation for large files", "status": "completed", "activeForm": "Implementing streaming hash calculation for large files"}, {"content": "Add hash verification and collision detection", "status": "completed", "activeForm": "Adding hash verification and collision detection"}, {"content": "Benchmark hashing performance on various file sizes", "status": "completed", "activeForm": "Benchmarking hashing performance on various file sizes"}, {"content": "Integrate smart hashing with cache key generation", "status": "completed", "activeForm": "Integrating smart hashing with cache key generation"}, {"content": "Design file-based cache system (no database)", "status": "completed", "activeForm": "Designing file-based cache system (no database)"}, {"content": "Implement JSON-based cache storage and retrieval", "status": "completed", "activeForm": "Implementing JSON-based cache storage and retrieval"}]
