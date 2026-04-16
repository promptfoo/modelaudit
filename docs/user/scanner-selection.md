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

If a scanner is skipped because it is not enabled, ModelAudit records an informational `Scanner Selection` check. JSON output includes the effective policy under `scanner_selection`, so CI pipelines can verify which scanners were enabled.

For remote sources, selective downloads use the enabled scanners' known extensions when it is safe to do so. ModelAudit keeps remote filtering conservative for container and header-routed scanners so extension-spoofed artifacts are not filtered out before download.
