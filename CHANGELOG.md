# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.26](https://github.com/promptfoo/modelaudit/compare/v0.2.25...v0.2.26) (2026-02-24)

### Bug Fixes

- **ci:** pin protoc version for vendored proto reproducibility ([#548](https://github.com/promptfoo/modelaudit/issues/548)) ([03e9d35](https://github.com/promptfoo/modelaudit/commit/03e9d356dd87edbeff37658a81595abe07345b54))
- **cli:** add --cache-dir and simplify defaults wording ([#550](https://github.com/promptfoo/modelaudit/issues/550)) ([b8701dd](https://github.com/promptfoo/modelaudit/commit/b8701dda1fb9cd71385ff6bdbb1accae531b5ea3))
- **cli:** fail fast when glob patterns match nothing ([#519](https://github.com/promptfoo/modelaudit/issues/519)) ([404104b](https://github.com/promptfoo/modelaudit/commit/404104b8120e4e4cbcfdb8b456532221da6b3698))
- **deps:** update dependency xgboost to &gt;=3.2,&lt;3.3 ([#507](https://github.com/promptfoo/modelaudit/issues/507)) ([4489e97](https://github.com/promptfoo/modelaudit/commit/4489e97aa1eb1d4d9b2a56d925648d2f2f9403a4))
- enforce consistent scanner patterns across all scanners ([#564](https://github.com/promptfoo/modelaudit/issues/564)) ([dd6b8d2](https://github.com/promptfoo/modelaudit/commit/dd6b8d22b35ae85c5e6f3862ed026a47a4444d4b))
- improve test suite reliability and safety ([#565](https://github.com/promptfoo/modelaudit/issues/565)) ([4bd04a7](https://github.com/promptfoo/modelaudit/commit/4bd04a792a6fd6104b9aec3172bbf934699872e0))
- remove security anti-patterns from scanning infrastructure ([#562](https://github.com/promptfoo/modelaudit/issues/562)) ([d02cd0b](https://github.com/promptfoo/modelaudit/commit/d02cd0b345e68fb003a4d812058489a7657dc50f))
- **security:** close critical scanner and CI gating gaps ([#553](https://github.com/promptfoo/modelaudit/issues/553)) ([807a8aa](https://github.com/promptfoo/modelaudit/commit/807a8aa05a69761fc2fcce9267f68ded5e3f6efc))
- **security:** resolve CodeQL alerts for workflow permissions and sensitive logging ([#570](https://github.com/promptfoo/modelaudit/issues/570)) ([d2dfc79](https://github.com/promptfoo/modelaudit/commit/d2dfc799fe6267d65fb7646eca68d175449d8802))
- **security:** resolve remaining audit findings ([#4](https://github.com/promptfoo/modelaudit/issues/4)-[#8](https://github.com/promptfoo/modelaudit/issues/8)) ([#556](https://github.com/promptfoo/modelaudit/issues/556)) ([7430436](https://github.com/promptfoo/modelaudit/commit/74304368946e6bc9ea170a23630388e92f8014b0))
- **security:** use URL hostname parsing instead of substring matching ([#571](https://github.com/promptfoo/modelaudit/issues/571)) ([b4d3696](https://github.com/promptfoo/modelaudit/commit/b4d3696894c0bc3affe56ee77130056ee31c7926))
- **test:** relax benchmark timing assertions for Windows CI ([#569](https://github.com/promptfoo/modelaudit/issues/569)) ([b06faac](https://github.com/promptfoo/modelaudit/commit/b06faac20c75a8df5d208eb9cb0ed834cb8e22f3))

### Documentation

- clarify README exit codes ([#568](https://github.com/promptfoo/modelaudit/issues/568)) ([e57a0de](https://github.com/promptfoo/modelaudit/commit/e57a0dec6778fa8aab747bf8ef51c5043d9f6c2e))
- fix accuracy issues across AGENTS.md, README, and CONTRIBUTING ([#566](https://github.com/promptfoo/modelaudit/issues/566)) ([880e7a4](https://github.com/promptfoo/modelaudit/commit/880e7a4455ba7c40e581cc144b25d2bd0a8522dd))
- **open-source:** add user trust docs batch ([#534](https://github.com/promptfoo/modelaudit/issues/534)) ([dd5e676](https://github.com/promptfoo/modelaudit/commit/dd5e676eac59533212bcea8b5ab9d484eacfd4b8))
- **readme:** add cache management flag ([#521](https://github.com/promptfoo/modelaudit/issues/521)) ([33d74bd](https://github.com/promptfoo/modelaudit/commit/33d74bd9135f667ef3dd002889bae14031e4dd79))
- ship next-phase open-source readiness docs ([#532](https://github.com/promptfoo/modelaudit/issues/532)) ([c88035d](https://github.com/promptfoo/modelaudit/commit/c88035d705dda3b9d2cba8f9f03a1b70b4ed41f7))
- trim README to essentials, fix inaccuracies ([#517](https://github.com/promptfoo/modelaudit/issues/517)) ([59c056c](https://github.com/promptfoo/modelaudit/commit/59c056c5a0414b7700d0c3afc3bcc79f3679edcd))

## [Unreleased]

### Added

- **security**: detect CVE-2022-25882 ONNX external_data path traversal with CVE attribution, CVSS score, and CWE classification in scan results

### Fixed

- **security**: harden pickle scanner stack resolution to correctly track `STACK_GLOBAL` and memoized `REDUCE` call targets, preventing decoy-string and `BINGET` bypasses
- **security**: tighten manifest trusted-domain matching to validate URL hostnames instead of substring matches
- **security**: make `.keras` suspicious file extension checks case-insensitive to catch uppercase executable/script payloads
- **security**: block unsafe in-process `torch.load` in `WeightDistributionScanner` by default unless explicitly opted in

## [0.2.25] - 2026-02-12

### Features

- add binary patterns for native code loading ([#499](https://github.com/promptfoo/modelaudit/issues/499)) ([ef638f1](https://github.com/promptfoo/modelaudit/commit/ef638f1470b78f1f34ce7866c4a217f8093092f3))
- add comprehensive Windows compatibility support ([#474](https://github.com/promptfoo/modelaudit/issues/474)) ([d62574e](https://github.com/promptfoo/modelaudit/commit/d62574e264eb3511a2a48d8b6614ea9152aa2efa))
- add detection for dangerous TensorFlow operations ([#494](https://github.com/promptfoo/modelaudit/issues/494)) ([6c4c0c9](https://github.com/promptfoo/modelaudit/commit/6c4c0c90441706061e6c0e66f00da3c481962bb2))
- add detection for memo-based and extension registry pickle opcodes ([#493](https://github.com/promptfoo/modelaudit/issues/493)) ([72509f7](https://github.com/promptfoo/modelaudit/commit/72509f727e3105f0706ad80611a7e110096e1d62))
- add getattr-based evasion detection patterns ([#500](https://github.com/promptfoo/modelaudit/issues/500)) ([87ba295](https://github.com/promptfoo/modelaudit/commit/87ba2955c96e67b3110578f5e567ef76e7644690))
- add Git LFS pointer detection ([#488](https://github.com/promptfoo/modelaudit/issues/488)) ([6413ae3](https://github.com/promptfoo/modelaudit/commit/6413ae3a07ec2b2849db954d794038cffdf67e10))
- add Keras subclassed model detection ([#503](https://github.com/promptfoo/modelaudit/issues/503)) ([d9e5663](https://github.com/promptfoo/modelaudit/commit/d9e566346c46355f5b6bda413a0cb98af051dafb))
- add lambda variadic argument validation ([#501](https://github.com/promptfoo/modelaudit/issues/501)) ([52a6622](https://github.com/promptfoo/modelaudit/commit/52a6622961c7d63221bc44a74e569ba5a511a2af))
- add PyTorch ZIP archive security controls ([#502](https://github.com/promptfoo/modelaudit/issues/502)) ([09ab087](https://github.com/promptfoo/modelaudit/commit/09ab0871b7625899447a8b05b991ce9a77b9cc09))
- eliminate TensorFlow dependency with vendored protobuf stubs ([#485](https://github.com/promptfoo/modelaudit/issues/485)) ([56cec5e](https://github.com/promptfoo/modelaudit/commit/56cec5e1727aae973164ad6f8f0ef85004a0ba25))
- expand SUSPICIOUS_GLOBALS with process and memory modules ([#495](https://github.com/promptfoo/modelaudit/issues/495)) ([8637d2b](https://github.com/promptfoo/modelaudit/commit/8637d2beb00020a19b285a9c7d043fa88e9213b6))

### Bug Fixes

- add content-based CVE detection to SkopsScanner ([#498](https://github.com/promptfoo/modelaudit/issues/498)) ([89895cb](https://github.com/promptfoo/modelaudit/commit/89895cb611f95c6c3119cdd8adf513e1b0c5a818))
- add logging to critical exception handlers in pickle scanner ([#492](https://github.com/promptfoo/modelaudit/issues/492)) ([b6b06cb](https://github.com/promptfoo/modelaudit/commit/b6b06cb2b0f6adccfa15e43948e78efad005abb6))
- add logging to silent exception handlers in secrets detector ([#491](https://github.com/promptfoo/modelaudit/issues/491)) ([b59f8a4](https://github.com/promptfoo/modelaudit/commit/b59f8a4924e2285c72b3f40e2ff6bec5f5815727))
- add security keywords to QueueEnqueueV2 TF op explanation ([#511](https://github.com/promptfoo/modelaudit/issues/511)) ([1d93483](https://github.com/promptfoo/modelaudit/commit/1d93483b79c76a9fbbbd8bc7aa2239c8aca28ec2))
- **ci:** ensure numpy compatibility job runs ([#478](https://github.com/promptfoo/modelaudit/issues/478)) ([7266160](https://github.com/promptfoo/modelaudit/commit/72661605482c2883a9f7ae28c32416677d0fcd17))
- **deps:** bump pillow 12.1.0→12.1.1 and cryptography 46.0.4→46.0.5 ([#513](https://github.com/promptfoo/modelaudit/issues/513)) ([5b18d49](https://github.com/promptfoo/modelaudit/commit/5b18d49cd16bd611bb89b41b341475175bca6922))
- **deps:** update dependency fickling to v0.1.7 [security] ([#479](https://github.com/promptfoo/modelaudit/issues/479)) ([292eb23](https://github.com/promptfoo/modelaudit/commit/292eb234c5c3379706e51372973078b59b2516f9))
- improve Python version requirement UX ([#508](https://github.com/promptfoo/modelaudit/issues/508)) ([a44d8bb](https://github.com/promptfoo/modelaudit/commit/a44d8bb67f27f4e8b04d55c04fd28f9d257bfec8))
- reduce false positive scan warnings for HuggingFace models ([#514](https://github.com/promptfoo/modelaudit/issues/514)) ([b545c11](https://github.com/promptfoo/modelaudit/commit/b545c1102c538b7b907af6e4c949afd9b301c0a5))
- reduce pickle scanner false positives for BERT and standalone REDUCE opcodes ([#510](https://github.com/promptfoo/modelaudit/issues/510)) ([94c22d6](https://github.com/promptfoo/modelaudit/commit/94c22d6d5237e18aaa47f53cde93b4a1ff9e4b08))
- remove duplicate whitelist downgrading in add_check() ([#490](https://github.com/promptfoo/modelaudit/issues/490)) ([a8c52bc](https://github.com/promptfoo/modelaudit/commit/a8c52bcb85e160e1d80414aa4767ccebe1794707))
- remove variable shadowing for skip_file_types parameter ([#489](https://github.com/promptfoo/modelaudit/issues/489)) ([bcf99ea](https://github.com/promptfoo/modelaudit/commit/bcf99ea7d0e62b358c130754c38e7f5be3282e18))
- use deterministic data patterns in anomaly detector tests ([#477](https://github.com/promptfoo/modelaudit/issues/477)) ([df11759](https://github.com/promptfoo/modelaudit/commit/df11759ee22628aed6ed541f819fd5f26920a38b))

## [0.2.24] - 2025-12-23

### Bug Fixes

- **deps:** update dependency contourpy to &lt;1.3.4 ([#463](https://github.com/promptfoo/modelaudit/issues/463)) ([16fb916](https://github.com/promptfoo/modelaudit/commit/16fb916a88020a7d96455edcbd8bddc0a4c4a58b))
- **deps:** update dependency fickling to v0.1.6 [security] ([#462](https://github.com/promptfoo/modelaudit/issues/462)) ([9413ddc](https://github.com/promptfoo/modelaudit/commit/9413ddc95cb00fd068fd6ee39a3386a4f4db8016))
- **deps:** update dependency xgboost to v3 ([#469](https://github.com/promptfoo/modelaudit/issues/469)) ([97adbbc](https://github.com/promptfoo/modelaudit/commit/97adbbc0cfe3699264ade222b9949a98f5e6878d))
- resolve release-please CHANGELOG formatting race condition ([#457](https://github.com/promptfoo/modelaudit/issues/457)) ([4347b83](https://github.com/promptfoo/modelaudit/commit/4347b83e652fde580437964f22feffdbed7b8731))

## [0.2.23] - 2025-12-12

### Documentation

- consolidate agent guidance ([#453](https://github.com/promptfoo/modelaudit/issues/453)) ([a01ceff](https://github.com/promptfoo/modelaudit/commit/a01ceff5daa66750994008e1a9414ce3227115d6))
- restructure AGENTS.md and CLAUDE.md following 2025 best practices ([#451](https://github.com/promptfoo/modelaudit/issues/451)) ([e87de51](https://github.com/promptfoo/modelaudit/commit/e87de5153c574b9053b507d44f59d5fe85b7204d))

## [0.2.22] - 2025-12-10

### Added

- **feat**: add `modelaudit debug` command for troubleshooting - outputs comprehensive diagnostic information including version, platform, environment variables, authentication status, scanner availability, NumPy compatibility, cache status, and configuration in JSON or pretty-printed format; useful for bug reports and support interactions

## [0.2.21] - 2025-12-09

### Fixed

- **fix**: resolve UnicodeDecodeError when scanning PyTorch .pkl files saved with default ZIP serialization - torch.save() uses ZIP format by default since PyTorch 1.6 (`_use_new_zipfile_serialization=True`), but ModelAudit was incorrectly routing these files to PickleScanner which failed to parse the ZIP header. Now correctly routes ZIP-format .pkl files to PyTorchZipScanner.

## [0.2.20] - 2025-12-01

### Added

- **feat**: detect cloud storage URLs in model configs (AWS S3, GCS, Azure Blob, HuggingFace Hub) - identifies external resource references that could indicate supply chain risks or data exfiltration vectors
- **feat**: add URL allowlist security scanning to manifest scanner - uses 164 trusted domains to flag untrusted URLs in model configs as potential supply chain risks
- **feat**: detect weak hash algorithms (MD5, SHA1) in model config files - scans manifest files for hash/checksum fields using cryptographically broken algorithms and reports WARNING with CWE-328 reference; SHA256/SHA512 usage is confirmed as strong
- **feat**: add comprehensive analytics system with Promptfoo integration - opt-out telemetry for usage insights, respects `PROMPTFOO_DISABLE_TELEMETRY` and `NO_ANALYTICS` environment variables
- **feat**: auto-enable progress display when output goes to file - shows spinner/progress when stdout is redirected to a file

### Fixed

- **fix**: resolve false positives in pickle and TFLite scanners - improved detection accuracy
- **fix**: clean up tests for CI reliability - removed flaky tests and improved test isolation

## [0.2.19] - 2025-11-24

### Fixed

- **fix**: resolve Jinja2 SSTI false positives from bracket notation - refined obfuscation pattern to only match dunder attributes (`["__class__"]`) instead of legitimate dict access (`["role"]`), and fixed regex bug where `|format\(` matched any pipe character
- **fix**: remove overly broad secret detection pattern - replaced generic `[A-Za-z0-9]{20,}` pattern with specific well-known token formats (GitHub, OpenAI, AWS, Slack) to eliminate false positives on URLs and model IDs
- **fix**: resolve msgpack file type validation false positive - unified format name inconsistency where functions returned different values (`"msgpack"` vs `"flax_msgpack"`), causing validation failures on legitimate MessagePack files
- **fix**: add HuggingFace training utilities to pickle safe globals - added safe Transformers, Accelerate, and TRL classes (HubStrategy, SchedulerType, DistributedType, DeepSpeedPlugin, DPOConfig, etc.) to reduce false positives on training checkpoints

## [0.2.18] - 2025-11-20

### Fixed

- **fix**: exclude INFO/DEBUG checks from success rate calculation - success rate now only includes security-relevant checks (WARNING/CRITICAL), with informational checks (INFO/DEBUG) shown separately in "Failed Checks (non-critical)" section
- **fix**: missing whitelist logic in validation checks - whitelist downgrading now correctly applies to validation result instantiations
- **fix**: resolve PyTorch ZIP scanner hang on large models - improved memory-mapped file handling and timeout configuration
- **fix**: additional severity downgrades - further reduced false positives across multiple scanners

### Changed

- **chore**: standardize on `add_check()` API - migrated all internal code from legacy `add_issue()` method to modern `add_check()` method for structured check reporting with explicit pass/fail status

## [0.2.17] - 2025-11-19

### Fixed

- **fix**: eliminate false positive WARNINGs on sklearn/joblib models (removed overly broad pattern matching)
  - Removed `b"sklearn"`, `b"NumpyArrayWrapper"`, and `b"numpy_pickle"` from binary pattern detection
  - These patterns flagged ALL legitimate sklearn/joblib models (100% false positive rate)
  - Regex CVE patterns still detect actual exploits requiring dangerous combinations
  - Reduces false positive WARNING rate by 77% (10 out of 13 WARNINGs eliminated)
- **fix**: NEWOBJ/OBJ/INST opcodes now recognize safe ML classes (eliminates sklearn model false positives)
  - Applied same safety logic as REDUCE opcode: check if class is in ML_SAFE_GLOBALS allowlist
  - sklearn models like LogisticRegression now correctly identified as INFO instead of WARNING
  - Added support for nested sklearn modules (e.g., sklearn.linear_model.\_logistic)
  - Added joblib.numpy_pickle.NumpyArrayWrapper and dtype.dtype to safe class list
- **fix**: handle joblib protocol mismatches gracefully (protocol 4 files using protocol 5 opcodes)
  - joblib files may declare protocol 4 but use protocol 5 opcodes like READONLY_BUFFER (0x0f)
  - Scanner now parses as much as possible before unknown opcodes, logs INFO instead of failing
  - Eliminates false positive "Invalid pickle format - unrecognized opcode" WARNING on joblib files
- **fix**: accept ZIP magic bytes for .npz files (NumPy compressed format is ZIP by design)
  - .npz files ARE ZIP archives containing multiple .npy files (numpy.savez format)
  - Now accepts both "zip" and "numpy" header formats for .npz extension
  - Fixed case-sensitivity bug: MODEL.NPZ, model.Npz now handled correctly
- **fix**: handle XML namespaces in PMML root element validation
  - PMML 4.x files with namespaces like `{http://www.dmg.org/PMML-4_4}PMML` now recognized
  - Strips namespace prefix before comparing tag name
- **fix**: add validation to prevent TFLite scanner crashes on malformed files
  - Pre-validates magic bytes ("TFL3") before parsing
  - Prevents buffer overflow crashes: "unpack_from requires a buffer of at least X bytes"
  - Added security rationale ("why" field) to magic bytes check

## [0.2.16] - 2025-11-04

### Added

- **feat**: content hash generation for regular scan mode - all scans (not just streaming) now generate `content_hash` field for model deduplication and verification

### Changed

- **refactor**: rename `--scan-and-delete` flag to `--stream` for clarity - streaming mode is now invoked with the more intuitive `--stream` flag

## [0.2.15] - 2025-10-31

### Added

- **feat**: universal streaming scan-and-delete mode for all sources to minimize disk usage
  - New `--scan-and-delete` CLI flag works with ALL sources (not just HuggingFace):
    - HuggingFace models (`hf://` or `https://huggingface.co/`)
    - Cloud storage (S3, GCS: `s3://`, `gs://`)
    - PyTorch Hub (`https://pytorch.org/hub/`)
    - Local directories
  - Files are downloaded/scanned one-by-one, then deleted immediately
  - Computes SHA256 hash for each file and aggregate content hash for deduplication
  - Adds `content_hash` field to scan results for identifying identical models
  - Ideal for CI/CD or constrained disk environments where downloading entire models (100GB+) isn't feasible

### Changed

- **chore**: move cloud storage dependencies (fsspec, s3fs, gcsfs) to default install - S3, GCS, and cloud storage now work without [cloud] extra

### Fixed

- **fix**: centralize MODEL_EXTENSIONS to ensure all scannable formats are downloaded from HuggingFace
  - Created single source of truth for model extensions (62+ formats including GGUF)
  - Previously: GGUF files relied on fallback download (inefficient, downloads all files)
  - Now: GGUF, JAX, Flax, NumPy and other formats are properly detected and selectively downloaded
  - Dynamically extracts extensions from scanner registry to stay in sync
- **fix**: restore fallback behavior in streaming downloads to maintain parity with non-streaming mode

## [0.2.14] - 2025-10-23

### Fixed

- **fix**: eliminate false positives across URL detection, CVE checks, GGUF parsing, and secret detection (#412)
- **fix**: improve shebang detection, fix fsspec usage, and resolve UnboundLocalError (#411)

## [0.2.13] - 2025-10-23

### Added

- **feat**: huggingface model whitelist (#409)

### Fixed

- **fix**: eliminate CVE-2025-32434 false positives for legitimate PyTorch models (#408)

## [0.2.12] - 2025-10-22

### Fixed

- **fix**: remove non-security format validation checks across scanners (#406)
- **fix**: eliminate false positives in stack depth, GGUF limits, and builtins detection (#405)

## [0.2.11] - 2025-10-22

### Fixed

- **fix**: INFO and DEBUG severity checks no longer count as failures in success rate calculations

## [0.2.10] - 2025-10-22

### Fixed

- **fix**: eliminate false positive REDUCE warnings for safe ML framework operations (#398)
- **fix**: eliminate ONNX custom domain and PyTorch pickle false positives (#400)
- **fix**: eliminate false positive JIT/Script warnings on ONNX files (#399)

## [0.2.9] - 2025-10-21

### Added

- **feat**: add context-aware severity for PyTorch pickle models (#395)
  - Implement SafeTensors detection utility to identify safer format alternatives
  - Add import analysis to distinguish legitimate vs malicious pickle imports
  - Consolidate opcode warnings into single check with evidence counts
  - Add `import_reference` field to pickle scanner GLOBAL checks for analysis
  - Provide actionable recommendations (use SafeTensors format)

### Changed

- **feat**: rewrite PyTorch pickle severity logic with context-awareness (#395)
  - CRITICAL: malicious imports detected (os.system, subprocess, eval)
  - WARNING: legitimate imports + SafeTensors alternative available
  - INFO: legitimate imports + no SafeTensors alternative
  - Reduces false positives while maintaining security detection accuracy
  - Example: sentence-transformers/all-MiniLM-L6-v2 now shows WARNING (was CRITICAL)

## [0.2.8] - 2025-10-21

### Added

- **feat**: add skops scanner for CVE-2025-54412/54413/54886 detection (#392)
  - Implement dedicated skops scanner for .skops model files
  - Detect CVE-2025-54412 (OperatorFuncNode RCE vulnerability)
  - Detect CVE-2025-54413 (MethodNode dangerous attribute access)
  - Detect CVE-2025-54886 (Card.get_model silent joblib fallback)
  - Add ZIP format validation and archive bomb detection

### Changed

- **refactor**: remove non-security checks prone to false positives (#391)
  - Remove blacklist checks from manifest scanner
  - Remove model name policy checks from manifest scanner
  - Streamline XGBoost scanner by removing non-security validation checks
  - Reduce false positives in metadata scanner

### Fixed

- **fix**: resolve XGBoost UBJ crash and network scanner false positives (#392)
  - Fix UBJ format JSON serialization crash by sanitizing bytes objects to hex strings
  - Eliminate network scanner false positives for pickle/joblib ML models by adding ML context awareness
  - Add comprehensive XGBoost testing documentation with 25-model test corpus

## [0.2.7] - 2025-10-20

### Fixed

- **fix**: improve XGBoost scanner severity levels and reduce false positives (#389)
  - Handle string-encoded numeric values in XGBoost JSON models
  - Add deterministic JSON validation to prevent claiming non-XGBoost files
  - Implement tiered file size thresholds (INFO → WARNING) for large models
  - Downgrade metadata scanner generic secret patterns from WARNING to INFO
  - Reduce false positives for BibTeX citations and code examples in README files
- **fix**: prevent ML confidence bypass and hash collision security exploits (#388)
  - Enable --verbose flag and accurate HuggingFace file sizes
  - Remove CoreML scanner and coremltools dependency
- **fix**: enable advanced TorchScript vulnerability detection (#384)
  - Enable comprehensive detection for serialization injection, module manipulation, and bytecode injection patterns

### Changed

- **refactor**: reorganize codebase into logical module structure (#387)
  - Create detectors/ module for security detection logic
  - Improve maintainability and reduce import complexity
- **chore(deps)**: bump tj-actions/changed-files from v46 to v47 (#386)

## [0.2.6] - 2025-09-10

### Added

- **feat**: add comprehensive JFrog folder scanning support (#380)
- **feat**: add comprehensive XGBoost model scanner with security analysis (#378)
- **feat**: consolidate duplicate caching logic into unified decorator (#347)
- **test**: improve test architecture with dependency mocking (#374)

### Fixed

- **fix**: exclude Python 3.13 from NumPy 1.x compatibility tests (#375)

## [0.2.5] - 2025-09-05

### Added

- **feat**: upgrade to CycloneDX v1.6 (ECMA-424) with enhanced ML-BOM support (#364)
- **feat**: add 7-Zip archive scanning support (#344)
- **feat**: re-enable check consolidation system (#353)
- **feat**: integrate ty type checker and enhance type safety (#372)

### Changed

- **BREAKING**: drop Python 3.9 support, require Python 3.10+ minimum
- **feat**: add Python 3.13 support
- **feat**: consolidate CLI from 25 to 12 flags using smart detection (#359)
- **feat**: enhance pickle static analysis with ML context awareness (#358)
- **feat**: enhance check consolidation system with PII sanitization and performance improvements (#356)
- **docs**: update AGENTS.md with exact CI compliance instructions (#357)
- **docs**: rewrite README with professional technical content (#370)
- **feat**: improve logging standards and consistency (#355)
- **chore(deps)**: bump the github-actions group with 2 updates (#362)
- **chore**: update dependencies and modernize type annotations (#360)
- **chore**: remove unnecessary files from root directory (#369)

### Fixed

- **fix**: handle GGUF tensor dictionaries in SBOM asset creation (#363)
- **fix**: correct release dates in CHANGELOG.md (#354)
- **fix**: resolve SBOM generation FileNotFoundError with URLs (#373)

## [0.2.4] - 2025-08-28

### Added

- **feat**: improve CVE-2025-32434 detection with density-based analysis (#351)
- **feat**: implement graceful degradation and enhanced error handling (#343)
- **feat**: improve PyTorch ZIP scanner maintainability by splitting scan() into smaller functions (#346)
- **feat**: add SARIF output format support for integration with security tools and CI/CD pipelines (#349)
- **feat**: optimize cache performance by reducing file system calls (#338)
- **feat**: comprehensive task list update and critical CLI usability audit (#340)
- **feat**: add cache management CLI commands mirroring promptfoo's pattern (#331)
- **feat**: add comprehensive metadata security scanner and enhanced HuggingFace support (#335)
- **feat**: add comprehensive CVE detection for pickle/joblib vulnerabilities (#326)
- **feat**: add Jinja2 template injection scanner (#323)
- **feat**: comprehensive deep Pydantic integration with advanced type safety (#322)
- **feat**: optimize CI for faster feedback (#320)
- **feat**: skip SafeTensors in WeightDistributionScanner for performance (#317)
- **feat**: add Pydantic models for JSON export with type safety (#315)
- **feat**: add support for multi-part archive suffixes (#307)
- **docs**: add comprehensive CI optimization guide (#319)
- **docs**: add Non-Interactive Commands guidance to AGENTS.md (#318)
- **docs**: add comprehensive publishing instructions (#302)
- **test**: speed up tests and CI runtime (#316)
- **test**: cover Windows path extraction scenarios (#313)
- **feat**: detect dangerous TensorFlow operations (#329)
- **feat**: enhance pickle scanner with STACK_GLOBAL and memo tracking (#330)
- **feat**: detect Windows and Unix OS module aliases to prevent system command execution via `nt` and `posix`

### Changed

- **chore**: organize root directory structure (#341)
- **chore**: make ctrl+c immediately terminate if pressed twice (#314)

### Fixed

- **fix**: aggregate security checks per file instead of per chunk (#352)
- **fix**: eliminate circular import between base.py and core.py (#342)
- **fix**: default bytes_scanned in streaming operations (#312)
- **fix**: validate directory file list before filtering (#311)
- **fix**: tighten ONNX preview signature validation (#310)
- **fix**: recurse cloud object size calculations (#309)
- **fix**: handle missing author in HuggingFace model info (#308)
- **fix**: handle PyTorch Hub URLs with multi-part extensions (#306)
- **fix**: avoid duplicated sharded file paths (#305)
- **fix**: handle None values in Keras H5 scanner to prevent TypeError (#303)

## [0.2.3] - 2025-08-21

### Added

- **feat**: increase default max_entry_size from 10GB to 100GB for large language models (#298)
- **feat**: add support for 1TB+ model scanning (#293)
- **docs**: improve models.md formatting and organization (#297)

### Fixed

- **fix**: improve cache file skip reporting to not count as failed checks (#300)
- **fix**: eliminate ZIP entry read failures with robust null checking and streaming (#299)

## [0.2.2] - 2025-08-21

### Added

- **feat**: increase default scan timeout to 1 hour (#292)
- **feat**: improve CLI output user experience with verbose summary (#290)
- **feat**: add promptfoo authentication delegation system (#287)
- **feat**: expand malicious model test corpus with 42+ new models (#286)
- **feat**: streamline file format detection I/O (#285)
- **feat**: add comprehensive progress tracking for large model scans (#281)
- **feat**: raise large model thresholds to 10GB (#280)
- **feat**: enable scanner-driven streaming analysis (#278)
- **feat**: safely parse PyTorch ZIP weights (#268)
- **feat**: add comprehensive authentication system with semgrep-inspired UX (#50)
- **docs**: document security features and CLI options in README (#279)

### Changed

- **perf**: cache port regex patterns for network detector (#269)
- **refactor**: reduce file handle usage in format detection (#283)

### Fixed

- **fix**: eliminate SafeTensors recursion errors with high default recursion limit (#295)
- **fix**: add interrupt handling to ONNX scanner for graceful shutdown (#294)
- **fix**: eliminate duplicate checks through content deduplication (#289)
- **fix**: implement ML-context-aware stack depth limits to eliminate false positives (#284)
- **fix**: optimize directory detection (#282)
- **fix**: include license files in metadata scan (#277)
- **fix**: validate cloud metadata before download (#276)
- **fix**: handle async event loop in cloud download (#273)
- **fix**: add pdiparams extension to cloud storage filter (#272)
- **fix**: streamline magic byte detection (#271)
- **fix**: close cloud storage filesystems (#267)
- **fix**: flag critical scan errors (#266)
- **fix**: finalize early scan file exits (#265)
- **fix**: isolate network detector custom patterns (#264)
- **fix**: warn when JFrog auth missing (#263)
- **fix**: refine dangerous pattern detection check (#262)
- **fix**: handle deeply nested SafeTensors headers (#244)

### Removed

- **chore**: remove outdated markdown documentation files (#296)

## [0.2.1] - 2025-08-15

### Added

- **feat**: enhance timeout configuration for progressive scanning (#252)
- **feat**: add Keras ZIP scanner for new .keras format (#251)
- **feat**: add enhanced TensorFlow SavedModel scanner for Lambda layer detection (#250)
- **feat**: add compile() and eval() variants detection (#249)
- **feat**: improve os/subprocess detection for command execution patterns (#247)
- **feat**: add runpy module detection as critical security risk (#246)
- **feat**: add importlib and runpy module detection as CRITICAL security issues (#245)
- **feat**: add webbrowser module detection as CRITICAL security issue (#243)
- **feat**: add record path and size validation checks (#242)
- **feat**: enhance detection of dangerous builtin operators (#241)
- **feat**: add network communication detection (#238)
- **feat**: add JIT/Script code execution detection (#237)
- **feat**: add embedded secrets detection (#236)
- **feat**: add comprehensive security check tracking and reporting (#235)
- **feat**: add JFrog integration helper (#230)
- **feat**: add PyTorch Hub URL scanning (#228)
- **feat**: add tar archive scanning (#227)
- **feat**: add SPDX license checks (#223)
- **feat**: add RAIL and BigScience license patterns (#221)
- **feat**: expand DVC targets during directory scan (#215)
- **feat**: adjust SBOM risk scoring (#212)
- **feat**: add py_compile validation to reduce false positives (#206)
- **feat**: add disk space checking before model downloads (#201)
- **feat**: add interrupt handling for graceful scan termination (#196)
- **feat**: add CI-friendly output mode with automatic TTY detection (#195)

### Changed

- **perf**: use bytearray for chunked file reads (#217)
- **chore**: improve code professionalism and remove casual language (#258)
- **refactor**: remove unreachable branches (#222)
- **refactor**: remove type ignore comments (#211)

### Fixed

- **fix**: improve detection of evasive malicious models and optimize large file handling (#256)
- **fix**: eliminate false positives and false negatives in model scanning (#253)
- **fix**: improve PyTorch ZIP scanner detection for .bin files (#248)
- **fix**: add dangerous pattern detection to embedded pickles in PyTorch models (#240)
- **fix**: reduce false positives in multiple scanners (#229)
- **fix**: cast sbom output string (#220)
- **fix**: stream zip entries to temp file (#218)
- **fix**: handle broken symlinks safely (#214)
- **fix**: enforce UTF-8 file writes (#213)
- **fix**: update PyTorch minimum version to address CVE-2025-32434 (#205)
- **fix**: add **main**.py module and improve interrupt test reliability (#204)
- **fix**: resolve linting and formatting issues (#203)
- **fix**: return non-zero exit code when no files are scanned (#200)
- **fix**: improve directory scanning with multiple enhancements (#194)
- **fix**: add missing type annotations to scanner registry (#191)
- **fix**: resolve CI timeout by running only explicitly marked slow/integration tests (#190)
- **fix**: change false positive messages from INFO to DEBUG level (#189)

### Security

- **fix**: resolve PyTorch scanner pickle path context and version bump to 0.2.1 (#257)

## [0.2.0] - 2025-07-17

### Added

- **feat**: add scan command as default - improved UX with scan as the default command (#180)
- **feat**: add TensorRT engine scanner - support for NVIDIA TensorRT optimized models (#174)
- **feat**: add Core ML model scanner - support for Apple's Core ML .mlmodel format (#173)
- **feat**: add PaddlePaddle model scanner - support for Baidu's PaddlePaddle framework models (#172)
- **feat**: add ExecuTorch scanner - support for Meta's ExecuTorch mobile inference format (#171)
- **feat**: add TensorFlow SavedModel weight analysis - deep analysis of TensorFlow model weights (#138)
- **ci**: add GitHub Actions dependency caching - optimized CI pipeline performance (#183)

### Fixed

- **fix**: optimize CI test performance for large blob detection (#184)
- **fix**: properly handle HuggingFace cache symlinks to avoid path traversal warnings (#178)

## [0.1.5] - 2025-06-20

### Added

- **feat**: add cloud storage support - Direct scanning from S3, GCS, and other cloud storage (#168)
- **feat**: add JFrog Artifactory integration - Download and scan models from JFrog repositories (#167)
- **feat**: add JAX/Flax model scanner - Enhanced support for JAX/Flax model formats (#166)
- **feat**: add NumPy 2.x compatibility - Graceful fallback and compatibility layer (#163)
- **feat**: add MLflow model integration - Native support for MLflow model registry scanning (#160)
- **feat**: add DVC pointer support - Automatic resolution and scanning of DVC-tracked models (#159)
- **feat**: add nested pickle payload detection - Advanced analysis for deeply embedded malicious code (#153)
- **feat**: enhance SafeTensors scanner - Suspicious metadata and anomaly detection (#152)
- **feat**: add HuggingFace Hub integration - Direct model scanning from HuggingFace Hub URLs (#144, #158)
- **feat**: improve output formatting for better user experience (#143)
- **feat**: add PythonOp detection in ONNX - Critical security check for custom Python operations (#140)
- **feat**: add dangerous symlink detection - Identify malicious symbolic links in ZIP archives (#137)
- **feat**: add TFLite model scanner - Support for TensorFlow Lite mobile models (#103)
- **feat**: add asset inventory reporting - Comprehensive model asset discovery and cataloging (#102)
- **feat**: add Flax msgpack scanner - Support for Flax models using MessagePack serialization (#99)
- **feat**: add PMML model scanner - Support for Predictive Model Markup Language files (#98)
- **feat**: add header-based format detection - Improved accuracy for model format identification (#72)
- **feat**: add CycloneDX SBOM output - Generate Software Bill of Materials in standard format (#59)
- **feat**: add OCI layer scanning - Security analysis of containerized model layers (#53)
- **test**: add comprehensive test coverage for TFLite scanner (#165)
- **perf**: achieve 2074x faster startup - Lazy loading optimization for scanner dependencies (#129)

### Changed

- **perf**: stop scanning when size limit reached for better performance (#139)

### Fixed

- **fix**: reduce HuggingFace model false positives (#164)
- **fix**: reduce false positives for Windows executable detection in model files (#162)

## [0.1.4] - 2025-06-20

### Added

- **feat**: add binary pattern validation - Executable signature and pattern analysis (#134)
- **feat**: refine import pattern detection - Enhanced detection of malicious imports (#133)
- **feat**: centralize security patterns with validation system (#128)
- **feat**: add unified scanner logging - Consistent logging across all scanner modules (#125)
- **feat**: add magic byte-based file type validation - Improved format detection accuracy (#117)
- **feat**: add centralized dangerous pattern definitions - Unified security rule management (#112)
- **feat**: add scan configuration validation - Input validation and error handling (#107)
- **feat**: add total size limit enforcement - Configurable scanning limits across all scanners (#106, #119)
- **feat**: enhance dill and joblib serialization support - Advanced security scanning for scientific computing libraries (#55)
- **feat**: add GGML format variants support for better compatibility (4c3d842)
- **test**: organize comprehensive security test assets with CI optimization (#45)

## [0.1.3] - 2025-06-17

### Added

- **feat**: add security issue explanations - User-friendly 'why' explanations for detected threats (#92)
- **feat**: add modern single-source version management - Streamlined release process (#91)
- **feat**: add GGUF/GGML scanner - Support for llama.cpp and other quantized model formats (#66)
- **feat**: add ONNX model scanner - Security analysis for Open Neural Network Exchange format (#62)
- **feat**: add dill, joblib, and NumPy format support - Extended serialization format coverage (#60)
- **feat**: add comprehensive GGUF/GGML security checks - Advanced threat detection for quantized models (#56)

### Changed

- **chore**: modernize pyproject configuration (#87)
- **chore**: refine package build configuration (#82)

### Fixed

- **fix**: broaden ZIP signature detection (#95)
- **fix**: synchronize version between pyproject.toml and **init**.py to 0.1.3 (#90)
- **fix**: eliminate false positives in GPT-2 and HuggingFace models (#89)

## [0.1.2] - 2025-06-17

### Added

- **feat**: add Biome formatter integration - Code quality tooling for JSON and YAML files (#79)
- **feat**: enable full scan for .bin files (#76)
- **feat**: add zip-slip attack protection - Prevent directory traversal attacks in ZIP archives (#63)
- **feat**: add SafeTensors scanner - Security analysis for Hugging Face's SafeTensors format (#61)
- **feat**: add dill pickle support - Extended pickle format security scanning (#48)
- **feat**: add CLI version command - Easy version identification for users (#44)
- **feat**: add weight distribution anomaly detector - Advanced backdoor detection through statistical analysis (#32)
- **docs**: optimize README and documentation for PyPI package distribution (#83)

### Changed

- **chore**: update biome configuration to v2.0.0 schema (#85)
- **chore**: change errors → findings (#67)

### Fixed

- **fix**: reduce PyTorch pickle false positives (#78)
- **fix**: log weight extraction failures (#75)
- **fix**: log debug issues at debug level (#74)
- **fix**: clarify missing data.pkl warning (#73)
- **fix**: clarify missing dependency error messages (#71)
- **fix**: change weight distribution warnings to info level (#69)
- **fix**: correct duration calculation (#68)

## [0.1.1] - 2025-06-16

### Added

- **feat**: add multi-format .bin file support - Enhanced detection for various binary model formats (#57)
- **feat**: add PR title validation - Development workflow improvements (#35)
- **feat**: add manifest parser error handling - Better diagnostics for corrupted model metadata (#30)
- **feat**: change output label of ERROR severity to CRITICAL (#25)

### Changed

- **chore**: replace Black, isort, flake8 with Ruff for faster linting and formatting (#24)

### Fixed

- **fix**: treat raw .pt files as unsupported (#40)
- **fix**: avoid double counting bytes in zip scanner (#39)
- **fix**: mark scan result unsuccessful on pickle open failure and test (#29)
- **fix**: ignore debug issues in output status (#28)
- **fix**: use supported color for debug output (#27)
- **fix**: switch config keys to info and reduce false positives (#8)
- **fix**: reduce false positives for ML model configurations (#3)

## [0.1.0] - 2025-03-08

### Added

- **feat**: add ZIP archive security analysis - Comprehensive scanning of compressed model packages (#15)
- **feat**: add stack_global opcode detection - Critical security check for dangerous pickle operations (#7)
- **feat**: add configurable exit codes - Standardized return codes for CI/CD integration (#6)
- **feat**: add core pickle scanning engine - foundation for malicious code detection in Python pickles (f3b56a7)
- **docs**: add AI development guidance - CLAUDE.md for AI-assisted development (#16)
- **ci**: add GitHub Actions CI/CD - Automated testing and security validation (#4)

### Fixed

- **style**: improve code formatting and documentation standards (#12, #23)
- **fix**: improve core scanner functionality and comprehensive test coverage (#11)

[unreleased]: https://github.com/promptfoo/modelaudit/compare/v0.2.25...HEAD
[0.2.25]: https://github.com/promptfoo/modelaudit/compare/v0.2.24...v0.2.25
[0.2.24]: https://github.com/promptfoo/modelaudit/compare/v0.2.23...v0.2.24
[0.2.23]: https://github.com/promptfoo/modelaudit/compare/v0.2.22...v0.2.23
[0.2.22]: https://github.com/promptfoo/modelaudit/compare/v0.2.21...v0.2.22
[0.2.21]: https://github.com/promptfoo/modelaudit/compare/v0.2.20...v0.2.21
[0.2.20]: https://github.com/promptfoo/modelaudit/compare/v0.2.19...v0.2.20
[0.2.19]: https://github.com/promptfoo/modelaudit/compare/v0.2.18...v0.2.19
[0.2.18]: https://github.com/promptfoo/modelaudit/compare/v0.2.17...v0.2.18
[0.2.17]: https://github.com/promptfoo/modelaudit/compare/v0.2.16...v0.2.17
[0.2.16]: https://github.com/promptfoo/modelaudit/compare/v0.2.15...v0.2.16
[0.2.15]: https://github.com/promptfoo/modelaudit/compare/v0.2.14...v0.2.15
[0.2.14]: https://github.com/promptfoo/modelaudit/compare/v0.2.13...v0.2.14
[0.2.13]: https://github.com/promptfoo/modelaudit/compare/v0.2.12...v0.2.13
[0.2.12]: https://github.com/promptfoo/modelaudit/compare/v0.2.11...v0.2.12
[0.2.11]: https://github.com/promptfoo/modelaudit/compare/v0.2.10...v0.2.11
[0.2.10]: https://github.com/promptfoo/modelaudit/compare/v0.2.9...v0.2.10
[0.2.9]: https://github.com/promptfoo/modelaudit/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/promptfoo/modelaudit/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/promptfoo/modelaudit/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/promptfoo/modelaudit/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/promptfoo/modelaudit/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/promptfoo/modelaudit/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/promptfoo/modelaudit/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/promptfoo/modelaudit/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/promptfoo/modelaudit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/promptfoo/modelaudit/compare/v0.1.5...v0.2.0
[0.1.5]: https://github.com/promptfoo/modelaudit/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/promptfoo/modelaudit/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/promptfoo/modelaudit/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/promptfoo/modelaudit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/promptfoo/modelaudit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/promptfoo/modelaudit/releases/tag/v0.1.0
