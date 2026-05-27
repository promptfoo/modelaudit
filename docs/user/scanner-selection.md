# Scanner Selection

Use scanner selection when you need a focused scan for CI, incident response, or targeted remediation.

```bash
# List available scanner IDs and class names
modelaudit scan --list-scanners
modelaudit scan --list-scanners --format json

# Run only selected scanners
modelaudit scan ./models --scanners pickle,tf_savedmodel
modelaudit scan ./model.pkl --scanners PickleScanner

# Run the default scanner set except selected scanners
modelaudit scan ./models --exclude-scanner weight_distribution
```

`--scanners` accepts canonical scanner IDs and scanner class names. Values can be comma-separated or passed with repeated flags.

```bash
modelaudit scan ./models --scanners pickle --scanners tf_savedmodel
```

`--exclude-scanner` subtracts scanners from the active set. When used without `--scanners`, it subtracts from the default full scanner set. When combined with `--scanners`, it subtracts from that explicit allowlist.

```bash
modelaudit scan ./models --scanners zip,pickle --exclude-scanner pickle
```

Container scanners and nested scanners are selected independently. If you want to scan pickle files inside a ZIP archive, include both scanners:

```bash
modelaudit scan ./archive.zip --scanners zip,pickle
```

If a scanner is skipped because it is not enabled, ModelAudit records a `Scanner Selection` check. When the scanner that routing would have picked for a file is suppressed, the check is raised to WARNING severity, ModelAudit prints a stderr warning, and `scanner_selection.suppressed_preferred_scanner_ids` lists the affected scanner IDs. Embedded helper skips (for example, inner pickle analysis inside a PyTorch ZIP) remain informational because the primary scanner still runs. JSON output includes the effective policy under `scanner_selection`, so CI pipelines can verify both which scanners were enabled and which were suppressed.

Unknown scanner names in `--scanners`/`--exclude-scanner` exit with code 2 and include a `did you mean: …` suggestion built from all known IDs and class-name aliases.

Programmatic callers of `scan_file` or `scan_model_directory_or_file` can reuse `modelaudit.scanner_selection.collect_suppressed_preferred_scanners(result.checks)` to enumerate preferred-scanner skips without parsing check details by hand:

```python
from modelaudit.core import scan_file
from modelaudit.scanner_selection import collect_suppressed_preferred_scanners

result = scan_file("./model.pkl", config={"exclude_scanners": ["pickle"]})
for entry in collect_suppressed_preferred_scanners(result.checks):
    print(entry["scanner_id"], entry["location"])
```

For remote sources, selective downloads use the enabled scanners' known extensions when it is safe to do so. Content-based routing applies after acquisition, so direct file URLs are the reliable path when repository filenames may be intentionally misleading.
