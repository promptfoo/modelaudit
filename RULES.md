# ModelAudit Security Rules

ModelAudit uses `S###` rule codes as stable identifiers for scanner findings,
SARIF output, suppression, severity overrides, telemetry aggregation, and
dashboards. The authoritative catalog lives in `modelaudit/rule_catalog.py`;
this reference mirrors the catalog.

Rule codes can come from explicit scanner output or from the bounded message
fallback in `RuleRegistry.find_matching_rule()` when a check does not provide an
explicit code.

## Configuration

```toml
# .modelaudit.toml
suppress = ["S710", "S801"]

[severity]
S301 = "HIGH"

[ignore]
"tests/**" = ["S101"]
```

CLI usage:

```bash
modelaudit rules
modelaudit rules S101
modelaudit rules --category 200-299
modelaudit scan --suppress S101 --severity S301=HIGH model.pkl
```

## Rule Catalog

The catalog currently contains 114 rules.

### Module And Import Security

| Code   | Default severity | Name                           | Description                                                 |
| ------ | ---------------- | ------------------------------ | ----------------------------------------------------------- |
| `S101` | CRITICAL         | os module import               | Operating system command execution via os module            |
| `S102` | CRITICAL         | sys module import              | System manipulation via sys module                          |
| `S103` | CRITICAL         | subprocess module import       | Process spawning via subprocess module                      |
| `S104` | CRITICAL         | eval/exec usage                | Dynamic code execution via eval or exec                     |
| `S105` | CRITICAL         | compile usage                  | Code compilation at runtime                                 |
| `S106` | CRITICAL         | `__import__` usage             | Dynamic module importing                                    |
| `S107` | HIGH             | importlib usage                | Dynamic import machinery via importlib                      |
| `S108` | CRITICAL         | runpy module usage             | Running Python modules as scripts                           |
| `S109` | CRITICAL         | webbrowser module usage        | Opening web browsers programmatically                       |
| `S110` | HIGH             | ctypes module usage            | Foreign function interface via ctypes                       |
| `S115` | HIGH             | Builtins code-execution access | Access to dangerous builtins that can enable code execution |

### Pickle Execution And Structure

| Code   | Default severity | Name                               | Description                                                        |
| ------ | ---------------- | ---------------------------------- | ------------------------------------------------------------------ |
| `S201` | CRITICAL         | Pickle REDUCE opcode               | Arbitrary callable execution via pickle REDUCE                     |
| `S202` | CRITICAL         | Pickle INST opcode                 | Class instantiation via pickle INST                                |
| `S203` | CRITICAL         | Pickle OBJ opcode                  | Object construction via pickle OBJ                                 |
| `S204` | CRITICAL         | Pickle NEWOBJ opcode               | New-style class construction via pickle NEWOBJ                     |
| `S205` | HIGH             | Pickle STACK_GLOBAL opcode         | Stack-based global retrieval via pickle                            |
| `S206` | HIGH             | Pickle GLOBAL opcode               | Global name resolution via pickle                                  |
| `S207` | MEDIUM           | Pickle BUILD opcode                | Object building operations via pickle                              |
| `S208` | HIGH             | Pickle SETATTR opcode              | Attribute setting via pickle SETATTR                               |
| `S209` | MEDIUM           | Pickle SETITEM opcode              | Item assignment via pickle                                         |
| `S210` | MEDIUM           | Pickle SETITEMS opcode             | Multiple item assignment via pickle                                |
| `S211` | HIGH             | Pickle extension opcode            | Copyreg extension reference via pickle EXT opcode                  |
| `S212` | MEDIUM           | Pickle persistent ID opcode        | Persistent object resolution via pickle persistent_load callback   |
| `S213` | CRITICAL         | Nested/encoded pickle payload      | Nested or encoded pickle payload detected                          |
| `S214` | HIGH             | Pickle expansion denial-of-service | Pickle graph expansion pattern can consume excessive memory or CPU |

### Network And Communication

| Code   | Default severity | Name                       | Description                            |
| ------ | ---------------- | -------------------------- | -------------------------------------- |
| `S301` | HIGH             | socket module usage        | Low-level networking via socket module |
| `S302` | MEDIUM           | requests/urllib usage      | HTTP client operations                 |
| `S303` | MEDIUM           | http.client usage          | HTTP protocol handling                 |
| `S304` | HIGH             | ftplib usage               | FTP operations                         |
| `S305` | HIGH             | telnetlib usage            | Telnet protocol usage                  |
| `S306` | MEDIUM           | smtplib usage              | Email sending capabilities             |
| `S307` | MEDIUM           | DNS lookups                | Domain name resolution detected        |
| `S308` | LOW              | Hardcoded IP addresses     | Static IP addresses found              |
| `S309` | LOW              | Hardcoded URLs             | Static URLs found                      |
| `S310` | HIGH             | Data exfiltration patterns | Potential data theft patterns          |

### File System And Archive Security

| Code   | Default severity | Name                              | Description                                          |
| ------ | ---------------- | --------------------------------- | ---------------------------------------------------- |
| `S401` | MEDIUM           | open() for write/append           | File write operations detected                       |
| `S402` | MEDIUM           | pathlib write operations          | Path-based file writes                               |
| `S403` | MEDIUM           | shutil operations                 | File/directory operations via shutil                 |
| `S404` | LOW              | tempfile operations               | Temporary file creation                              |
| `S405` | CRITICAL         | Path traversal attempts           | Directory escape attempts detected                   |
| `S406` | HIGH             | Archive link to external location | Symbolic or hard archive link pointing outside scope |
| `S407` | LOW              | Hidden file access                | Dotfile operations detected                          |
| `S408` | HIGH             | /etc or system file access        | System configuration file access                     |
| `S409` | MEDIUM           | Home directory access             | User directory operations                            |
| `S410` | HIGH             | Archive bomb detected             | Excessive compression ratio                          |

### Embedded Executables And Scripts

| Code   | Default severity | Name                    | Description                   |
| ------ | ---------------- | ----------------------- | ----------------------------- |
| `S501` | CRITICAL         | Windows PE executable   | Windows binary embedded       |
| `S502` | CRITICAL         | Linux ELF executable    | Linux binary embedded         |
| `S503` | CRITICAL         | macOS Mach-O executable | macOS binary embedded         |
| `S504` | CRITICAL         | Shell script            | Shell script embedded         |
| `S505` | CRITICAL         | Batch script            | Windows batch script embedded |
| `S506` | CRITICAL         | PowerShell script       | PowerShell code embedded      |
| `S507` | HIGH             | Python script embedded  | Python code as string data    |
| `S508` | HIGH             | JavaScript code         | JavaScript code embedded      |
| `S509` | HIGH             | WebAssembly module      | WASM binary embedded          |
| `S510` | MEDIUM           | JIT/TorchScript code    | JIT compiled code detected    |

### Encoding And Obfuscation

| Code   | Default severity | Name                             | Description                                      |
| ------ | ---------------- | -------------------------------- | ------------------------------------------------ |
| `S601` | MEDIUM           | Base64 encoded payload           | Base64 encoded data detected                     |
| `S602` | MEDIUM           | Hex encoded payload              | Hexadecimal encoded data                         |
| `S603` | LOW              | zlib compressed data             | Compressed content detected                      |
| `S604` | HIGH             | Encrypted/obfuscated code        | Encrypted or obfuscated payloads                 |
| `S605` | MEDIUM           | Unicode encoding tricks          | Unicode obfuscation detected                     |
| `S606` | LOW              | ROT13/Caesar cipher              | Simple cipher detected                           |
| `S607` | MEDIUM           | XOR obfuscation                  | XOR encrypted data                               |
| `S609` | LOW              | URL/percent encoding obfuscation | URL-encoded content used to obfuscate payloads   |
| `S610` | MEDIUM           | Custom/unknown encoding          | Custom or unknown encoding used to hide payloads |

### Secrets And Credentials

| Code   | Default severity | Name                       | Description                        |
| ------ | ---------------- | -------------------------- | ---------------------------------- |
| `S701` | MEDIUM           | API key pattern            | API key detected                   |
| `S702` | HIGH             | Password/credential        | Password or credential detected    |
| `S703` | HIGH             | Private key                | Private cryptographic key detected |
| `S704` | HIGH             | AWS credentials            | AWS access keys detected           |
| `S705` | HIGH             | GCP/Azure credentials      | Cloud provider credentials         |
| `S706` | HIGH             | Database connection string | Database connection URL detected   |
| `S707` | MEDIUM           | JWT token                  | JSON Web Token detected            |
| `S708` | MEDIUM           | OAuth token                | OAuth token detected               |
| `S709` | LOW              | Webhook URL                | Webhook endpoint detected          |
| `S710` | LOW              | High entropy strings       | Random-looking string detected     |

### Model Integrity Signals

| Code   | Default severity | Name                           | Description                        |
| ------ | ---------------- | ------------------------------ | ---------------------------------- |
| `S801` | LOW              | Suspicious weight distribution | Statistical anomalies in weights   |
| `S802` | LOW              | Outlier neurons                | Extreme weight values detected     |
| `S803` | LOW              | Dissimilar weight vectors      | Inconsistent weight patterns       |
| `S804` | LOW              | Excessive model dimensions     | Unusually large layer dimensions   |
| `S805` | LOW              | Unusual layer configuration    | Non-standard architecture detected |
| `S806` | MEDIUM           | Hidden layers in manifest      | Undocumented layers found          |
| `S807` | HIGH             | Backdoor trigger patterns      | Potential backdoor detected        |
| `S808` | MEDIUM           | Weight manipulation signs      | Signs of tampered weights          |
| `S809` | LOW              | Non-standard activations       | Custom activation functions        |
| `S810` | MEDIUM           | Custom layers with code        | Layers containing executable code  |

### Structural And Format Issues

| Code   | Default severity | Name                        | Description                                            |
| ------ | ---------------- | --------------------------- | ------------------------------------------------------ |
| `S901` | MEDIUM           | File type mismatch          | Extension doesn't match content                        |
| `S902` | LOW              | Corrupted file structure    | Invalid file format detected                           |
| `S903` | LOW              | Invalid magic bytes         | Wrong file signature                                   |
| `S904` | LOW              | Excessive file size         | File exceeds size limits                               |
| `S905` | LOW              | Suspicious file metadata    | Unusual metadata detected                              |
| `S906` | LOW              | Non-standard file extension | Uncommon file extension                                |
| `S907` | MEDIUM           | Multiple format markers     | Multiple file format indicators                        |
| `S908` | HIGH             | Polyglot file detected      | File valid as multiple formats                         |
| `S999` | LOW              | Binary scan error           | Scanner encountered an unexpected binary parsing error |

### Provenance, Signatures, And Licensing

| Code    | Default severity | Name                    | Description                           |
| ------- | ---------------- | ----------------------- | ------------------------------------- |
| `S1001` | CRITICAL         | Blacklisted model name  | Known malicious model name            |
| `S1002` | CRITICAL         | Known malicious hash    | File matches malware signature        |
| `S1003` | HIGH             | Typosquatting detection | Name similar to popular model         |
| `S1004` | LOW              | Unsigned model          | Model lacks digital signature         |
| `S1005` | HIGH             | Invalid signature       | Digital signature verification failed |
| `S1006` | LOW              | Expired certificate     | Signing certificate has expired       |
| `S1007` | MEDIUM           | Untrusted repository    | Model from unknown source             |
| `S1008` | LOW              | License incompatibility | License conflicts detected            |
| `S1009` | LOW              | GPL in proprietary use  | GPL license in commercial context     |
| `S1010` | LOW              | Missing provenance      | No source tracking information        |

### Framework-Specific Risks

| Code    | Default severity | Name                         | Description                                                         |
| ------- | ---------------- | ---------------------------- | ------------------------------------------------------------------- |
| `S1101` | HIGH             | PyTorch unsafe load          | torch.load without weights_only=True                                |
| `S1102` | MEDIUM           | TensorFlow SavedModel risks  | TensorFlow SavedModel security issues                               |
| `S1103` | MEDIUM           | Keras Lambda layers          | Keras Lambda layers with code                                       |
| `S1104` | LOW              | ONNX opset version           | ONNX version compatibility issue                                    |
| `S1105` | MEDIUM           | JAX compilation risks        | JAX JIT compilation security                                        |
| `S1106` | MEDIUM           | MXNet custom operators       | MXNet custom operator risks                                         |
| `S1107` | MEDIUM           | PaddlePaddle dynamic graph   | PaddlePaddle dynamic mode risks                                     |
| `S1108` | MEDIUM           | CoreML custom layers         | CoreML custom layer risks                                           |
| `S1109` | MEDIUM           | TensorRT plugins             | TensorRT plugin security                                            |
| `S1110` | LOW              | GGUF/GGML format risks       | GGUF/GGML format security issues                                    |
| `S1111` | INFO             | ONNX custom operator domains | ONNX model may depend on an external custom operator implementation |

## Maintenance

When adding, removing, or renaming rules, update `modelaudit/rule_catalog.py`,
scanner tests that assert rule output, SARIF expectations when applicable, and
this file in the same PR.
