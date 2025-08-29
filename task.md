# CLI Flag Consolidation Plan

## Goal

Reduce ModelAudit CLI complexity from 25 flags to 12 flags (-52%) through smart detection and consolidation.

## Smart Detection Handles Most Complexity

### Auto-detect based on input:

- `s3://`, `gs://` → Enable caching, reasonable size limits
- `hf://`, `huggingface.co` → Selective download
- `models://` → MLflow mode (registry detection)
- `.jfrog.io` URLs → JFrog auth from env vars only
- Local file > 1GB → Large model optimizations
- Directory → Skip non-model files automatically
- TTY detection → Colors on/off, spinner behavior

## New CLI Interface (12 flags)

### Core output control (4)

- `--format/-f [text|json|sarif]` - Output format
- `--output/-o FILE` - Output file
- `--verbose/-v` - Verbosity
- `--quiet/-q` - Silence detection messages

### Security behavior (2)

- `--blacklist/-b PATTERN` - Additional patterns
- `--strict` - Fail on any warnings

### Progress & reporting (2)

- `--progress` - Force enable progress (auto-detected by default)
- `--sbom FILE` - Generate SBOM file

### Override smart detection (2)

- `--timeout/-t SECONDS` - Override auto-detected timeout
- `--max-size SIZE` - Override auto-detected size limits

### Preview/debugging (2)

- `--dry-run` - Preview what would happen
- `--no-cache` - Force disable caching

## Flags to Remove (13 eliminated)

### Auto-detected instead:

- `--large-model-support/--no-large-model-support` → Auto-enabled for files >1GB
- `--selective/--all-files` → Auto-enabled for cloud directories
- `--cache/--cache-dir` → Smart defaults based on input type
- `--max-file-size/--max-total-size/--max-download-size` → Single `--max-size`
- `--no-skip-files/--skip-files` → Controlled by `--strict` mode
- `--stream` → Auto-enabled for very large cloud files

### Moved to env vars only:

- `--jfrog-api-token/--jfrog-access-token` → `JFROG_*` env vars
- `--registry-uri` → `MLFLOW_TRACKING_URI` env var

### Removed (rarely used/consolidated):

- `--progress-log/--progress-format/--progress-interval` → Smart defaults only
- `--preview` → Replaced by `--dry-run`
- `--strict-license` → Part of `--strict` mode

## Implementation Steps

### Phase 1: Add Smart Detection Logic

1. Create detection utilities in `modelaudit/utils/smart_detection.py`
2. Implement input type detection (cloud, local, registry)
3. Implement file size detection for large model optimizations
4. Implement TTY detection for UI behavior

### Phase 2: Update CLI Interface

1. Add new consolidated flags (`--quiet`, `--strict`, `--dry-run`, `--no-cache`)
2. Update existing flags to use smart detection as defaults
3. Remove deprecated flags from CLI definition
4. Update help text and documentation

### Phase 3: Update Core Logic

1. Modify `scan_command()` to use smart detection
2. Update default value logic throughout the scanning pipeline
3. Ensure all removed flag functionality is preserved through detection
4. Update tests to reflect new interface

### Phase 4: Documentation & Migration

1. Update all examples in README and docs
2. Update CLAUDE.md with new flag usage
3. Ensure backward compatibility where possible
4. Create migration guide for existing users

## Expected User Experience

```bash
# Simple case - just works
modelaudit scan model.pkl

# Cloud case - auto-detects and handles complexity
modelaudit scan s3://bucket/models/

# Force progress + generate SBOM
modelaudit scan models/ --progress --sbom audit.json

# Override only when needed
modelaudit scan huge-model.pt --max-size 20GB --timeout 7200 --strict
```

## Success Metrics

- CLI help output is significantly shorter and more focused
- Common use cases require fewer flags
- All existing functionality is preserved
- Tests continue to pass with updated interface
