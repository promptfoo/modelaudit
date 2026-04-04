# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.30](https://github.com/promptfoo/modelaudit/compare/v0.2.29...v0.2.30) (2026-03-30)

### Bug Fixes

- always run binary fallback for parse-failed .bin files ([#814](https://github.com/promptfoo/modelaudit/issues/814)) ([f5f3c90](https://github.com/promptfoo/modelaudit/commit/f5f3c904855bbd0c305690196826453d54502983))
- harden nested pickle detection against padded payloads ([#812](https://github.com/promptfoo/modelaudit/issues/812)) ([c15f53e](https://github.com/promptfoo/modelaudit/commit/c15f53eb8960e2328440b5c300c435d5a53d42d1))
- mark incomplete pickle scans as inconclusive ([#810](https://github.com/promptfoo/modelaudit/issues/810)) ([ade9296](https://github.com/promptfoo/modelaudit/commit/ade9296b6f1c41e8bae1ac6bdbd2fd83d6234c9a))
- normalize archive locations and route .skops ZIPs ([#805](https://github.com/promptfoo/modelaudit/issues/805)) ([f7c8277](https://github.com/promptfoo/modelaudit/commit/f7c8277adaf505655b5414aa1cda4d79a906c955))
- preserve fail-closed pickle fallback semantics ([#817](https://github.com/promptfoo/modelaudit/issues/817)) ([e8a6db7](https://github.com/promptfoo/modelaudit/commit/e8a6db7275aba944666bd668f6ae8e782618bb0f))
- restore post-budget pickle opcode parity ([#811](https://github.com/promptfoo/modelaudit/issues/811)) ([d321309](https://github.com/promptfoo/modelaudit/commit/d32130943ba931eef7b8f85804bde4762410bf39))
- use symbolic STACK_GLOBAL refs for pickle ML context ([#813](https://github.com/promptfoo/modelaudit/issues/813)) ([eb48c52](https://github.com/promptfoo/modelaudit/commit/eb48c52ee7522bccaf1da0d1f274ce3f33f1cb23))
- **utils:** recurse into cloud directories with size metadata ([#819](https://github.com/promptfoo/modelaudit/issues/819)) ([2d9852d](https://github.com/promptfoo/modelaudit/commit/2d9852deaaab4f6002404c197fd22231a9c9e69d))

## [0.2.29](https://github.com/promptfoo/modelaudit/compare/v0.2.28...v0.2.29) (2026-03-29)

### Features

- **cli:** add --no-whitelist and --strict flags for CI pipelines ([636b813](https://github.com/promptfoo/modelaudit/commit/636b813b607cec13af5bdb8fecc1ba2461828938))
- detect pickle expansion attack heuristics ([8e074fd](https://github.com/promptfoo/modelaudit/commit/8e074fda38280716bd6c09aba718b63486d357e2))
- **whitelist:** warn when HuggingFace whitelist snapshot is stale ([5a60871](https://github.com/promptfoo/modelaudit/commit/5a60871c21c9df18d26674c2c46222fbb98d318f))

### Bug Fixes

- add guarded CRC fallback for PyTorch ZIP scanning ([5db1e71](https://github.com/promptfoo/modelaudit/commit/5db1e71927d97c8c6c3b3ed41ec5d404fc41e2a3))
- **cache:** harden invalidation and skip operational failures ([6492598](https://github.com/promptfoo/modelaudit/commit/649259821adcbd30c9c1cf40722d0ac591223a2d))
- **cli:** propagate cache settings to registry downloads ([d6cf508](https://github.com/promptfoo/modelaudit/commit/d6cf508d7f5046757beb590273996dee70ea1365))
- **core:** count stream scans in files_scanned ([#749](https://github.com/promptfoo/modelaudit/issues/749)) ([50326bb](https://github.com/promptfoo/modelaudit/commit/50326bbada68a6dacbc82e0f0e8929156fcebfa1))
- **core:** route misnamed archives by trusted file structure ([cad90c3](https://github.com/promptfoo/modelaudit/commit/cad90c3fb2ebbfacee5c1113eefb71c89f8c04a6))
- **deps:** include py7zr in all extras ([#759](https://github.com/promptfoo/modelaudit/issues/759)) ([16cfae1](https://github.com/promptfoo/modelaudit/commit/16cfae1d805e7eaae082f743f5f69bfb2d32775b))
- **detection:** tighten safetensors magic detection to prevent misrouting ([109bca2](https://github.com/promptfoo/modelaudit/commit/109bca24440898bb954ae66eac5c054eca705afc))
- fail closed on pickle unknown opcode parse errors ([#747](https://github.com/promptfoo/modelaudit/issues/747)) ([a63979a](https://github.com/promptfoo/modelaudit/commit/a63979a70c63b22d8cd6993fd4e6f155d139a03c))
- **filtering:** preserve disguised model files during directory scans ([27058f5](https://github.com/promptfoo/modelaudit/commit/27058f5fd35ca2d1ec665385236ed27b06cc6b54))
- generate release sbom from uv lock ([#733](https://github.com/promptfoo/modelaudit/issues/733)) ([a1019a8](https://github.com/promptfoo/modelaudit/commit/a1019a8ac79652f9395e29c15e06d39cd9b18e07))
- harden pickle setitem target detection ([#756](https://github.com/promptfoo/modelaudit/issues/756)) ([877669c](https://github.com/promptfoo/modelaudit/commit/877669cf5a3c036abfc5f730200324ec3d0d9fdd))
- **huggingface:** fail closed on listing errors and timeouts ([f22ebbe](https://github.com/promptfoo/modelaudit/commit/f22ebbe894b80fb6f6d680d86a908b6509f48fad))
- **jfrog:** fail closed on partial folder downloads ([14e2ddd](https://github.com/promptfoo/modelaudit/commit/14e2ddd02fe19f74efc0ca5c3269da26c514e7d1))
- keep json stdout clean for skipped files ([#768](https://github.com/promptfoo/modelaudit/issues/768)) ([0857b98](https://github.com/promptfoo/modelaudit/commit/0857b98da7c331d45579777e2e0d1f45a7a9bec2))
- **keras-zip:** harden documentation padding bypass for CVE-2025-9906 ([6e73043](https://github.com/promptfoo/modelaudit/commit/6e73043cb5b0c5b346c14be92049010ca345f4dc))
- **keras:** anchor safe Lambda pattern regexes to prevent code injection bypass ([73fa571](https://github.com/promptfoo/modelaudit/commit/73fa571a172129602bf8637ef1ba601eb3de22d8))
- **keras:** prevent spoofed built-in registered_name from hiding non-allowlisted modules ([#736](https://github.com/promptfoo/modelaudit/issues/736)) ([6d8350e](https://github.com/promptfoo/modelaudit/commit/6d8350e1a9583c0d53931a6a465e6f8b9dea1d44))
- **large-files:** fail closed without bounded scanner coverage ([a2317eb](https://github.com/promptfoo/modelaudit/commit/a2317eb1ab98c16a29eb689282c32c61fbcafed0))
- make pickle operational errors explicit ([2d75778](https://github.com/promptfoo/modelaudit/commit/2d75778ba0f39601bae8adf18d7a8e3f5f79b345))
- **manifest:** trust regional S3 manifest URLs ([#763](https://github.com/promptfoo/modelaudit/issues/763)) ([f43af54](https://github.com/promptfoo/modelaudit/commit/f43af548a88c953a4c753b74bdad08d199a7fc5f))
- **mar:** analyze all Python files in TorchServe MAR archives ([dd2cf32](https://github.com/promptfoo/modelaudit/commit/dd2cf3220c42ecc1ea487c3e38c627d43633006a))
- **mar:** analyze requirements.txt for supply chain attacks ([5365583](https://github.com/promptfoo/modelaudit/commit/536558314b090fc9d7d58db027e6ef9361743ab7))
- **metadata:** harden metadata scanner userinfo URLs ([#767](https://github.com/promptfoo/modelaudit/issues/767)) ([07bf5a5](https://github.com/promptfoo/modelaudit/commit/07bf5a5d9906edd9d7bef9901e38a9812e2385e3))
- normalize streamed source path reporting ([#765](https://github.com/promptfoo/modelaudit/issues/765)) ([09431e0](https://github.com/promptfoo/modelaudit/commit/09431e0fb6aace491587b0fd221ee7e456b2f095))
- **onnx:** add ai.onnx.ml to standard domain allowlist ([c94f804](https://github.com/promptfoo/modelaudit/commit/c94f804c3d889fde1f20224d1e178dd580228f96))
- **pickle:** add budget-independent global/import byte scanner for large files ([512dd18](https://github.com/promptfoo/modelaudit/commit/512dd18ae43d0306c0f59b115af477ced262a74a))
- **pickle:** add catch-all for unhandled opcodes in stack simulator ([445b204](https://github.com/promptfoo/modelaudit/commit/445b204e98564267312ced85ea5f620d7f78dfd4))
- **pickle:** allow uppercase module segments in import checks ([#757](https://github.com/promptfoo/modelaudit/issues/757)) ([c1aeb55](https://github.com/promptfoo/modelaudit/commit/c1aeb55eec9adc67e29ac66973f78ab9b6eddc38))
- **pickle:** detect nested pickle BINBYTES8 and BYTEARRAY8 payloads ([#754](https://github.com/promptfoo/modelaudit/issues/754)) ([814c7f2](https://github.com/promptfoo/modelaudit/commit/814c7f2216556e687f256dbbddcd7ac77c11d011))
- **pickle:** harden blocklist — copyreg, \_pickle.Unpickler, functools.reduce ([fe04d9a](https://github.com/promptfoo/modelaudit/commit/fe04d9a077beb3b2659944e30e464103cb831701))
- **pickle:** surface large-file raw pattern coverage limits ([#769](https://github.com/promptfoo/modelaudit/issues/769)) ([d9904f2](https://github.com/promptfoo/modelaudit/commit/d9904f2551158b88ec80251d98553e64d82b627c))
- **pickle:** track BUILD opcode **setstate** exploitation ([7e8c370](https://github.com/promptfoo/modelaudit/commit/7e8c370df527c4b204f7357c375b2b1704fafa4a))
- **pickle:** treat scan timeouts as unsuccessful without regressing tail scans ([075adcd](https://github.com/promptfoo/modelaudit/commit/075adcd0d13058b66d784b3f6a55ebc8424bb014))
- preserve exit code 1 for zero-file findings ([#764](https://github.com/promptfoo/modelaudit/issues/764)) ([34d25e7](https://github.com/promptfoo/modelaudit/commit/34d25e7952c893b5aa688583511bcb8dd87a9f5a))
- preserve scanner execution for chunked large files ([#745](https://github.com/promptfoo/modelaudit/issues/745)) ([8d93f1d](https://github.com/promptfoo/modelaudit/commit/8d93f1d85c2c13fffc93a71629a5fc718468c1cc))
- preserve validated PE detections in pickle scans ([#746](https://github.com/promptfoo/modelaudit/issues/746)) ([017202c](https://github.com/promptfoo/modelaudit/commit/017202cc74839fc9007e7a11576a71fc63a06d98))
- prevent ExecuTorch polyglot ZIP bypass ([#743](https://github.com/promptfoo/modelaudit/issues/743)) ([e06d0e8](https://github.com/promptfoo/modelaudit/commit/e06d0e84ecd2ae878b2e78043f492ce3b2f40a67))
- route zip-backed pytorch containers in pickle scanner ([0390a00](https://github.com/promptfoo/modelaudit/commit/0390a00534867849d4b842a0c457c756a23e1289))
- **routing:** complete format_to_scanner primary routing map ([de69f71](https://github.com/promptfoo/modelaudit/commit/de69f71d891f9bddcc322e4c02e9b663559879cf))
- **safetensors:** add missing BF16/BOOL/FP8 dtypes for size validation ([f2f2574](https://github.com/promptfoo/modelaudit/commit/f2f257489cce06ad87277e3344200e1dd3f41150))
- **safetensors:** apply MAX_HEADER_BYTES limit in scan() to prevent DoS ([7a847a7](https://github.com/promptfoo/modelaudit/commit/7a847a7a309f41f1bf49feb7b6ce6fdb8ac2468c))
- **savedmodel:** scan assets/ directory for executable content ([04d2a0c](https://github.com/promptfoo/modelaudit/commit/04d2a0c358d297316664ce290fa612be0535d9ab))
- scan padded follow-on pickle streams ([#755](https://github.com/promptfoo/modelaudit/issues/755)) ([8727d03](https://github.com/promptfoo/modelaudit/commit/8727d03204bf903158164d2fa430c8c36e36015c))
- **security:** block streamed symlink traversal outside scan roots ([#751](https://github.com/promptfoo/modelaudit/issues/751)) ([aee6656](https://github.com/promptfoo/modelaudit/commit/aee66568021ca205372de27ef2ecfcae4929d070))
- **security:** bound embedded .keras weight extraction to prevent zip-bomb DoS ([#737](https://github.com/promptfoo/modelaudit/issues/737)) ([1cc0e46](https://github.com/promptfoo/modelaudit/commit/1cc0e4624b80766ec127c55f960405ab58a59cb6))
- **security:** bound MAR fallback python handler reads ([#735](https://github.com/promptfoo/modelaudit/issues/735)) ([88e42b9](https://github.com/promptfoo/modelaudit/commit/88e42b97b4ab30b07c87f3ac04978b5445aead9a))
- **security:** harden manifest URL trust checks and timeout handling ([#760](https://github.com/promptfoo/modelaudit/issues/760)) ([9ccc5f3](https://github.com/promptfoo/modelaudit/commit/9ccc5f36793b756b4a314c69adb33d939123232e))
- **security:** preserve scannable artifacts in directory filtering ([#758](https://github.com/promptfoo/modelaudit/issues/758)) ([7666930](https://github.com/promptfoo/modelaudit/commit/7666930fcdf357fcd9d8c905becd7985a1b4655f))
- **security:** preserve shared depth across nested archive types ([#753](https://github.com/promptfoo/modelaudit/issues/753)) ([607b506](https://github.com/promptfoo/modelaudit/commit/607b5060422a9848ebdea11c6e239a932c532a23))
- **security:** recurse into extensionless nested ZIP members ([#752](https://github.com/promptfoo/modelaudit/issues/752)) ([a2dfea9](https://github.com/promptfoo/modelaudit/commit/a2dfea9b5dd24994c8624c9db865db219f1587f4))
- **security:** recurse into nested sevenzip archives by content ([#761](https://github.com/promptfoo/modelaudit/issues/761)) ([3b0e3dc](https://github.com/promptfoo/modelaudit/commit/3b0e3dc0b6915ef2cd7ffaa4d41a6eb54ef475b3))
- **security:** require explicit HuggingFace provenance for whitelist downgrades ([#750](https://github.com/promptfoo/modelaudit/issues/750)) ([582e361](https://github.com/promptfoo/modelaudit/commit/582e36198bd30699bce2ebd1bbab73ad6e3504d9))
- **security:** route nested sevenzip members through core scanning ([#762](https://github.com/promptfoo/modelaudit/issues/762)) ([92ffdf7](https://github.com/promptfoo/modelaudit/commit/92ffdf7ca6bc30972e3b136470e92c2e8c8fbc63))
- **sevenzip:** recurse into misnamed nested archives ([2cc5423](https://github.com/promptfoo/modelaudit/commit/2cc5423764749344e6ce6108d6ac2943bc002dcd))
- **streaming:** avoid materializing file iterators ([7a9ae37](https://github.com/promptfoo/modelaudit/commit/7a9ae3741f3c8ab90fdd47c9101e8bf17179a086))
- **tflite:** stop after excessive subgraph counts ([64b08fa](https://github.com/promptfoo/modelaudit/commit/64b08fa3501ed7321c08887a6bee5c4914246e69))
- **whitelist:** preserve explicit HF download provenance ([#766](https://github.com/promptfoo/modelaudit/issues/766)) ([7e187cb](https://github.com/promptfoo/modelaudit/commit/7e187cb0bd96350c34b2e430a20be6a48ca7fd27))

### Documentation

- **agents:** tighten validation and routing guidance ([335b656](https://github.com/promptfoo/modelaudit/commit/335b65679de6c98d4040d3ea9e6a4fd025ac3f45))
- normalize unreleased changelog section ([#741](https://github.com/promptfoo/modelaudit/issues/741)) ([5e66490](https://github.com/promptfoo/modelaudit/commit/5e664901d4448871715685833a91cfb339d632d7))

## [Unreleased]

### Added

- **tests:** enable existing PaddlePaddle scanner tests in CI by adding `test_paddle_scanner.py` to the allowed test files list (Python 3.10/3.12/3.13)
- **security:** detect CVE-2026-1669 Keras HDF5 external weight references in standalone `.h5` and embedded `.keras` weights
- **security:** detect CVE-2026-24747 PyTorch weights_only=True bypass via SETITEM/SETITEMS abuse and tensor metadata mismatch detection
- **security:** detect CVE-2022-45907 PyTorch torch.jit.annotations.parse_type_line unsafe eval() injection (CVSS 9.8)
- **keras:** detect CVE-2025-12058 StringLookup external vocabulary path loading in `.keras` configs (local file read / SSRF)

### Changed

- **security:** temporarily bump the optional ONNX dependency to `1.21.0rc3`, which removes the vulnerable `onnx.hub` module flagged by CVE-2026-28500.

### Fixed

- **security:** detect protocol 0/1 pickle streams hidden behind long separator gaps after an initial safe pickle stream
- **security:** preserve failed status for malicious Skops CVE detections and avoid CVE-2025-54886 false positives on benign README/model-card text such as "download"
- **security:** enforce Flax msgpack scanner file-size limits before full reads, scan trailing msgpack stream objects with a bounded object-count cap, downgrade benign container-like trailing-object findings to INFO, and preserve failed status when CRITICAL findings are reported
- **security:** route `.joblib` files through the Joblib scanner, scan raw protocol-0/1 payloads directly, support gzip/bzip2/lzma/zlib wrappers with bounded output and trailing-data checks, preserve embedded Pickle finding locations, and fail closed on undecodable/trailing-wrapper errors
- **security:** detect direct `getattr(module, "dangerous")` handler calls in TorchServe MAR archives, parse conflicting duplicate manifests without silently downgrading hidden handlers, and suppress collision warnings for byte-identical duplicate manifests
- **security:** reduce NeMo Hydra `_target_` false positives by matching suspicious identifiers on token boundaries, preserve CVE-2025-23304 details on suspicious-target findings, and reject oversized YAML members before parsing
- **security:** detect protocol 0/1 pickle streams with trivial opcode prefixes even when `STOP` is followed by trailing junk, while preserving plain-text near-match rejection
- **security:** detect protocol 0/1 pickle streams whose dangerous opcode appears after large trivial padding or after a non-trivial probe-boundary prelude, reject all-trivial no-`STOP` probe prefixes, and preserve rule codes across cached scan-result round trips
- **license:** bound binary header scans and reuse compiled patterns to avoid full-file regex passes on large model archives
- **security:** stop iterating malformed TFLite models after excessive subgraph counts are detected
- **security:** scan every duplicate PyTorch ZIP member by physical archive entry and report conflicting duplicate names at INFO severity so benign trailing `data.pkl` entries cannot shadow malicious earlier payloads without making benign-but-conflicting duplicates warning-fail by themselves
- **security:** route misnamed Skops ZIPs by bounded schema sniffing, treat encrypted Skops-like schema members as non-matches instead of crashing routing, recurse into embedded members while preserving Skops-specific CVE checks, avoid tiny nested `.bin` false positives on clean archive members, preserve nested-member byte accounting, and preserve CLI `scanner_names` in aggregated JSON output
- **pickle:** bound post-budget global fallback state, retained findings, and deadline checks to prevent crafted pickle tails from exhausting scanner memory or flooding logs
- **pickle:** mark timeout-, budget-, recursion-, and resource-limited pickle scans as inconclusive so clean-looking partial analysis returns exit code 2 unless real security findings were reported
- route misnamed ZIP, HDF5, and 7z files through content-aware scanner selection
- **security:** recursively scan all members of content-routed `.keras` ZIP archives with bounded per-member extraction, prefer canonical root members over normalized aliases, and fail closed on ambiguous duplicate aliases so embedded payloads and `./config.json` entries are not skipped
- **security:** scan duplicate ZIP entries by physical archive member instead of resolving repeated names to the final entry, preventing shadowed payloads from being skipped during recursive archive analysis
- bound Keras `config.json` and `metadata.json` member reads before JSON parsing
- route oversized config-only Keras ZIP archives by bounded config-prefix sniffing instead of falling back to the generic ZIP scanner
- preserve disguised model files during directory prefiltering without promoting document ZIPs
- recurse into nested 7z members even when their filenames use misleading extensions
- fail closed on extreme-size files when a scanner lacks bounded large-file analysis
- harden scan-cache invalidation and skip caching operational scan failures
- propagate CLI cache settings into MLflow and JFrog downloads
- avoid materializing streaming directory iterators in memory
- fail closed when JFrog folder downloads return only partial results
- **keras:** anchor safe Lambda normalization regexes in H5 scanning so appended statements (for example `; __import__(...)`) cannot bypass dangerous-code analysis
- complete primary header-format routing in `core.py` so all registered model formats map to scanner IDs (including OpenVINO/PMML/CNTK/LightGBM/Torch7/CatBoost/RKNN/MXNet/NeMo/Llamafile/TFLite/CoreML/Paddle/TensorRT/Flax/R/ExecuTorch/7z/compressed/skops/joblib/xgboost/jax_checkpoint), add `.skops` extension detection coverage without spurious ZIP mismatch noise, and route ZIP-backed PyTorch `.ckpt`/`.pkl` containers through the PyTorch ZIP path
- **security:** track pickle `BUILD`-driven `__setstate__` mutation on non-safe globals and block tree-model opcode-threshold escalation when dangerous globals are present in-stream
- **safetensors:** include BOOL, BF16, F8_E4M3, and F8_E5M2 dtypes in tensor-size validation so malformed offsets are no longer skipped
- harden pickle symbolic stack simulation by ignoring stack-neutral opcodes and using unknown sentinels for unhandled stack pushes
- **security:** scan TensorFlow SavedModel `assets/` and `assets.extra/` directories for executable-like content (shebang scripts, ELF/Mach-O binaries, pickle magic, and embedded Python source patterns)
- **security:** enforce SafeTensors `MAX_HEADER_BYTES` during `scan()` and skip regex-heavy metadata-content analysis when headers exceed the configured limit to reduce header-based DoS risk
- emit a one-time warning when the HuggingFace whitelist snapshot is older than 90 days while preserving existing whitelist severity downgrades
- treat pickle scan timeouts as unsuccessful while preserving post-budget tail scans after opcode truncation
- harden pickle CVE-2026-24747 SETITEM detection against stack-neutral padding
- **keras:** harden CVE-2025-9906 detection against documentation-padding bypasses in `.keras` `config.json`
- count successful `stream://` scans in `files_scanned` so clean streaming scans return exit code 0 instead of 2
- harden 7z nested archive scanning and pre-extraction size checks
- scan follow-on pickle streams after large padding blocks
- **security:** add a budget-independent post-truncation GLOBAL/INST/STACK_GLOBAL byte scan (100 MB capped) so dangerous imports hidden past opcode limits are still detected
- **security:** detect nested pickle payloads in BINBYTES8 and BYTEARRAY8 opcodes
- **security:** scan bounded sliding windows for padded nested pickles hidden beyond the first 1 KB in raw, legacy `BINSTRING`, and base64/hex-encoded payloads
- **onnx:** treat official `ai.onnx.ml` and `ai.onnx.preview.training` domains as standard so only truly custom domains are flagged
- reject local streaming symlink traversal outside the scan root
- require explicit remote Hugging Face provenance for whitelist downgrades
- preserve scannable archives, hidden model files, hidden DVC pointers, and local `.metadata` files in directory scans
- tighten Hugging Face cache-root matching so only real `.cache/huggingface/hub` layouts get cache-specific filtering and provenance handling
- preserve validated PE detections in pickle binary ML-context filtering
- **security:** fail closed on pickle opcode parse errors for `.pkl` / `.pickle` / `.joblib` / `.dill` files instead of returning a successful INFO-only scan
- **security:** surface an explicit INFO limitation when large pickle raw byte-pattern heuristics cover only the first 10 MB of the file
- **security:** preserve full scanner execution for large files when scanners do not implement chunk analyzers
- harden manifest URL trust checks and enforce metadata/manifest scan limits
- harden metadata scanner URL handling so shorteners/tunnels hidden in userinfo are flagged without treating ordinary authenticated URLs as suspicious
- trust legitimate AWS S3 virtual-hosted regional and legacy manifest URLs without broadening other `amazonaws.com` hosts
- treat all-uppercase pickle module segments as plausible imports
- recurse into extensionless nested ZIP members by content
- preserve mixed ZIP/TAR/MAR archive depth limits
- **security:** keep Hugging Face model downloads fail-closed when repo listing errors/timeouts prevent exact file allowlists, and run disk-space preflight against the default HF cache even without an explicit `cache_dir`
- **security:** bound embedded `.keras` weight extraction before temporary-file inspection to reduce zip-bomb denial-of-service risk
- **security:** prevent ExecuTorch binary ZIP polyglots from bypassing archive scanning
- **security:** keep spoofed built-in Keras `registered_name` values from hiding non-allowlisted custom modules in `.keras` ZIP scans
- **keras:** suppress duplicate custom-object warnings for allowlisted registered objects when module metadata is absent
- **security:** analyze TorchServe MAR `requirements.txt` files for supply-chain attack indicators such as non-PyPI indexes, editable/git installs, direct remote URL installs, external requirement includes, insecure HTTP URLs, remote find-links, and typosquatting package names while ignoring inline comments
- **security:** stop auto-applying local `.modelaudit.toml` and `pyproject.toml` rule config during scans unless a human explicitly trusts that config in an interactive scan; remembered trust is stored securely under the local ModelAudit cache and invalidated when the config changes
- **telemetry:** preserve secret-scrubbed model references in telemetry payloads while omitting raw credentials, query strings, and local directory paths
- **cli:** preserve original local files during `--stream` directory scans instead of unlinking them after analysis
- **security:** reduce benign pickle scanner noise by suppressing placeholder `__reduce__` findings, narrowing generic base64-like string heuristics, and applying default suppression for the JWT.io example token
- **security:** recurse into object-dtype `.npy` payloads and `.npz` object members with the pickle scanner while preserving CVE-2019-6446 attribution and archive-member context
- eliminate false positives for valid ExecuTorch FlatBuffers binaries and file-type validation on public `.pte` models
- eliminate Keras ZIP false positives for safe built-in and allowlisted serialized objects such as `Add` and `NotEqual`
- **security:** remove `dill.load` / `dill.loads` from the pickle safe-global allowlist so recursive dill deserializers stay flagged as dangerous loader entry points
- **security:** add exact dangerous helper coverage for validated torch and NumPy refs such as `numpy.f2py.crackfortran.getlincoef`, `torch._dynamo.guards.GuardBuilder.get`, and `torch.utils.collect_env.run`
- **security:** add exact dangerous-global coverage for `numpy.load`, `site.main`, `_io.FileIO`, `test.support.script_helper.assert_python_ok`, `_osx_support._read_output`, `_aix_support._read_cmd_output`, `_pyrepl.pager.pipe_pager`, `torch.serialization.load`, and `torch._inductor.codecache.compile_file` (9 PickleScan-only loader and execution primitives)
- **security:** treat legacy `httplib` pickle globals the same as `http.client`, including import-only and `REDUCE` findings in standalone and archived payloads
- **security:** detect import-only pickle `GLOBAL`/`STACK_GLOBAL` references while preserving safe constructor imports and avoiding mislabeling executed call chains as import-only
- **security:** fail closed on malformed `STACK_GLOBAL` operands when memo lookups are missing or operand types are non-string, while keeping simple truncation-only context informational
- **security:** remove `builtins.hasattr` / `__builtin__.hasattr` from the pickle safe-global allowlist so attribute-access primitives stay flagged as dangerous builtins
- **security:** harden pickle blocklist enforcement by removing `_pickle.Unpickler`/`_pickle.Pickler` from safe globals, adding `copyreg.add_extension`/`copyreg.remove_extension` to suspicious globals, and limiting functools warning downgrades to `partial`/`partialmethod` so `functools.reduce` findings stay CRITICAL
- **security:** harden TensorFlow weight extraction limits to bound actual tensor payload materialization, including malformed `tensor_content` and string-backed tensors, and continue scanning past oversized `Const` nodes
- **security:** stream TAR members to temp files under size limits instead of buffering whole entries in memory during scan
- **security:** inspect TensorFlow SavedModel function definitions when scanning for dangerous ops and protobuf string abuse, with function-aware finding locations
- **cli:** include streamed artifacts as SBOM components when `scan --stream --sbom` is used
- **cli:** exclude HuggingFace download cache bookkeeping files from remote SBOMs and asset lists
- **cli:** add `--no-whitelist` and `--strict` whitelist/caching hardening so CI scans can disable HF severity downgrades and force uncached analysis
- **security:** require official or explicitly allowlisted JFrog hosts before treating `/artifactory/` URLs as authenticated JFrog endpoints
- **security:** detect CVE-2024-5480 PyTorch torch.distributed.rpc arbitrary function execution via PythonUDF (CVSS 10.0)
- **security:** detect CVE-2024-48063 PyTorch torch.distributed.rpc.RemoteModule deserialization RCE via pickle (CVSS 9.8)
- **security:** detect CVE-2019-6446 in NumPy scanner when object-dtype arrays are found, with informational attribution (CVSS 9.8) due to potential pickle deserialization via `allow_pickle=True`
- **security:** new NeMo scanner detecting CVE-2025-23304 Hydra `_target_` injection in `.nemo` model files (CVSS 7.6), with recursive config inspection and dangerous callable blocklist
- **security:** detect CVE-2025-51480 ONNX `save_external_data` arbitrary file overwrite via external_data path traversal (CVSS 8.8)
- **security:** detect CVE-2025-49655 TorchModuleWrapper deserialization RCE (CVSS 9.8).
- **security:** add CatBoost `.cbm` scanner with strict `CBM1` format validation, bounded parsing, and suspicious command/network/script indicator checks
- **security:** add dedicated scanner support for R serialized artifacts (`.rds`, `.rda`, `.rdata`) with bounded decompression and static detection of executable symbol/payload indicators
- **security:** add CNTK `.dnn`/`.cmf` scanner with strict signature validation, bounded reads, and multi-signal suspicious content correlation
- **feat:** add standalone compressed-wrapper scanner support for `.gz`, `.bz2`, `.xz`, `.lz4`, and `.zlib` with strict signature validation, decompression size/ratio safeguards, and inner-payload scanner routing
- **security:** add RKNN `.rknn` scanner with strict `RKNN` signature detection, bounded metadata parsing, and contextual command/network/obfuscation checks
- **security:** add Torch7 (`.t7`, `.th`, `.net`) scanner with strict signature heuristics plus Lua execution primitive and dynamic module-loading detection
- **security:** add native LightGBM scanner for `.lgb`/`.lightgbm` and signature-validated `.model` artifacts with strict XGBoost collision disambiguation and static command/network/path indicator checks
- **feat:** add Llamafile executable scanner with bounded runtime-string analysis and embedded GGUF payload carving/forwarding
- **feat:** add CoreML `.mlmodel` scanner with strict protobuf structure validation, custom layer/custom model detection, metadata abuse checks, and linked-model path safety checks
- **feat:** add MXNet scanner support for paired `*-symbol.json` and `*-NNNN.params` artifacts with strict contract validation, companion-file checks, and suspicious reference/payload detection
- **security:** add TensorFlow MetaGraph (`.meta`) scanner support with strict protobuf `can_handle()`, bounded MetaGraph parsing, unsafe op detection (`PyFunc`/`PyCall`/`LoadLibrary`), executable-context string checks, and payload-stuffing anomaly controls
- **security:** add dedicated TorchServe `.mar` scanner with strict archive validation, bounded manifest/member reads, manifest policy checks, and recursive embedded payload scanning
- **security:** detect CVE-2025-1716 pickle bypass via `pip.main()` as dangerous callable (CVSS 9.8)
- **keras:** detect CVE-2025-9906 `enable_unsafe_deserialization` config bypass in `.keras` archives (CVSS 8.6, safe_mode bypass)
- **security:** detect CVE-2025-8747 Keras get_file gadget safe_mode bypass
- **keras:** detect CVE-2025-9905 H5 safe_mode bypass for Lambda layers (CVSS 7.3)
- **keras:** add CVE-2024-3660 attribution to Lambda layer detection in .keras and .h5 scanners (CVSS 9.8)
- **keras:** recursively inspect H5 `training_config` and `.keras` `compile_config` for custom losses and metrics, while allowlisting standard aliases and built-in preprocessing layers to reduce false positives
- **security:** detect CVE-2025-10155 pickle protocol 0/1 payloads disguised as `.bin` files by extending `detect_file_format()` to recognize GLOBAL opcode patterns and adding `posix`/`nt` internal module names to binary code pattern blocklist
- **security:** detect CVE-2022-25882 ONNX external_data path traversal with CVE attribution, CVSS score, and CWE classification in scan results
- **security:** detect CVE-2024-27318 ONNX nested external_data path traversal bypass via path segment sanitization evasion
- **security:** restore ZIP scanner fallback for invalid `.mar` archives so malicious ZIP payloads renamed to `.mar` cannot bypass archive checks
- **security:** flag risky import-only pickle references for `torch.jit`, `torch._dynamo`, `torch._inductor`, `torch.compile`, `torch.storage._load_from_bytes`, `numpy.f2py`, and `numpy.distutils` while preserving safe state-dict reconstruction paths
- **security:** add low-severity pickle structural tamper findings for duplicate or misplaced `PROTO` opcodes while avoiding benign binary-tail false positives
- **security:** stop treating mixed-case valid pickle module names as implausible, so import and reduce checks no longer bypass on names like `PIL` or attacker-chosen `EvilPkg`
- **security:** scan OCI layer members based on registered file extensions so embedded ONNX, Keras H5, and other real-path scanners are no longer skipped inside tar layers
- **security:** resolve bare-module TorchServe handler references like `custom_handler` to concrete archive members so malicious handler source is no longer skipped by static analysis
- **security:** compare archive entry paths against the intended extraction root without following base-directory symlinks
- **security:** stop loading `.env` files implicitly during JFrog helper import so untrusted working directories cannot rewrite proxy or auth-related environment variables
- **rules:** preserve `rule_code` metadata through direct result aggregation and ensure dangerous advanced pickle globals emit explicit rule codes (with regression coverage)
- **rules:** ignore unknown rule IDs in config files with warning logs, normalize rule-code casing in config parsing, and prevent invalid severity entries from being applied
- **security:** harden shared auth config storage and archive path sanitization to avoid insecure temp fallbacks, symlink overwrite abuse, and temp-root symlink traversal bypasses
- **security:** stop archive path sanitization from resolving attacker-controlled extraction-root symlinks, preventing symlinked temp directories from weakening traversal checks
- **telemetry:** refresh the cached telemetry client when runtime context changes and lazily initialize PostHog when telemetry is re-enabled in-process
- **tests:** add scanner literal `rule_code` registry-consistency coverage to catch unknown rule identifiers early
- **cloud:** harden cache path handling to prevent sibling-prefix bypasses from escaping cache boundaries, avoid deleting out-of-cache metadata paths during cleanup, and clean temporary cloud download directories on failure
- **tests:** unskip and restore cloud disk-space failure coverage; add regressions for cache boundary enforcement and temp-directory cleanup on download errors
- **security**: harden pickle scanner stack resolution to correctly track `STACK_GLOBAL` and memoized `REDUCE` call targets, preventing decoy-string and `BINGET` bypasses
- **security**: flag pickle `EXT1`/`EXT2`/`EXT4` extension-registry call targets in `REDUCE` analysis to close EXT opcode bypasses
- **security**: detect protocol 0/1 ASCII pickle signatures in generic file-format detection to prevent ZIP entry extension bypasses (e.g., malicious `payload.txt`)
- **security**: harden protocol 0/1 pickle format detection with bounded opcode parsing to catch prefixed payloads (e.g., `MARK/LIST` before `GLOBAL`) while reducing plain-text false positives in ZIP entry scanning
- **security**: keep opcode-level pickle analysis active when malformed streams trigger unicode/text parse errors after partial opcode extraction
- **security**: tighten safetensors magic-byte detection to require valid framed headers, preventing JSON and protocol 0 pickle misrouting
- **security:** analyze all Python files in TorchServe `.mar` archives (including non-handler modules and `__init__.py`) for risky calls, import-time execution, and handler-to-utility import relationships

### Security

- **keras:** detect CVE-2025-1550 arbitrary module references in `.keras` config.json (CVSS 9.8, safe_mode bypass)
- **security**: treat `joblib.load` as always dangerous and remove it from pickle ML allowlist to block loader trampoline bypasses
- **security**: tighten manifest trusted-domain matching to validate URL hostnames instead of substring matches
- **security**: make `.keras` suspicious file extension checks case-insensitive to catch uppercase executable/script payloads
- **security**: block unsafe in-process `torch.load` in `WeightDistributionScanner` by default unless explicitly opted in
- **fix**: tighten metadata scanner suspicious URL matching to use exact hostname/subdomain checks and add focused regression coverage
- **fix**: treat `.nemo` files as tar-compatible during file-type validation to avoid false extension/magic mismatch alerts
- **fix**: pass XGBoost load-test file paths via subprocess argv instead of interpolating shell-quoted paths into `python -c`, preventing backslash escape corruption on Windows-style paths
- **security**: reject absolute OCI layer references so `.manifest` files cannot scan host tarballs outside the OCI layout

### Documentation

- update README and user docs for the `modelaudit metadata` command, metadata safety guidance (`--trust-loaders`), and new NeMo format coverage
- align maintainer/agent docs with current architecture and release workflow (metadata extractor component, dependency extras, and release-please + changelog guidance)

## [0.2.28](https://github.com/promptfoo/modelaudit/compare/v0.2.27...v0.2.28) (2026-03-20)

### Features

- add rule codes to all security checks ([#255](https://github.com/promptfoo/modelaudit/issues/255)) ([330e7df](https://github.com/promptfoo/modelaudit/commit/330e7df66407de9c8717d2c1d2ae33075c195d8b))
- **keras:** detect StringLookup external vocabulary paths ([#727](https://github.com/promptfoo/modelaudit/issues/727)) ([20e9852](https://github.com/promptfoo/modelaudit/commit/20e9852f581ff3822d01ba0cf14465e3b9ec96c5))
- **security:** detect Keras HDF5 external weight references ([#729](https://github.com/promptfoo/modelaudit/issues/729)) ([6db8e27](https://github.com/promptfoo/modelaudit/commit/6db8e27fc314c0d6873d6991dbb1015a36b921ea))

### Bug Fixes

- accept valid ExecuTorch FlatBuffers binaries ([93caa97](https://github.com/promptfoo/modelaudit/commit/93caa97d5fa8eaea0afcfdc6823cb37a799f8a6f))
- add torch and numpy helper primitive coverage ([#706](https://github.com/promptfoo/modelaudit/issues/706)) ([b0a6a11](https://github.com/promptfoo/modelaudit/commit/b0a6a11b4d392e17214673362d218f1a44ac1396))
- block dill recursive loader globals ([#695](https://github.com/promptfoo/modelaudit/issues/695)) ([0d88a4b](https://github.com/promptfoo/modelaudit/commit/0d88a4b8b2a7727297a5d742b27816b5599b7a28))
- block legacy httplib pickle aliases ([#703](https://github.com/promptfoo/modelaudit/issues/703)) ([24b789a](https://github.com/promptfoo/modelaudit/commit/24b789a5a4c6ead716933171730f26a6abd118eb))
- bound advanced pickle global extraction ([#700](https://github.com/promptfoo/modelaudit/issues/700)) ([d9fe283](https://github.com/promptfoo/modelaudit/commit/d9fe2834d3518ab412d05a52e5d191dcf6028df7))
- bound skops zip entry reads and enforce uncompressed size limit ([#702](https://github.com/promptfoo/modelaudit/issues/702)) ([a91577d](https://github.com/promptfoo/modelaudit/commit/a91577d49fbe943c2e2e108deec06e63938bb499))
- bound XZ decompression memory in r_serialized scanner ([26d5b44](https://github.com/promptfoo/modelaudit/commit/26d5b446e5de9a8726e21edb2d9e8f37898e0cf1))
- bound zlib wrapper decompression output ([#681](https://github.com/promptfoo/modelaudit/issues/681)) ([8bb9cc2](https://github.com/promptfoo/modelaudit/commit/8bb9cc2cc88faa34108d9d273237d40b53bf9e5f))
- **ci:** reorder provenance job steps to prevent SBOM generation failure ([#646](https://github.com/promptfoo/modelaudit/issues/646)) ([d4ab381](https://github.com/promptfoo/modelaudit/commit/d4ab38162ed82f1aa13b1c8cef6892c764b386a8))
- **deps:** move optional onnx extra to 1.21.0rc3 for CVE-2026-28500 mitigation ([#726](https://github.com/promptfoo/modelaudit/issues/726)) ([01b5f4f](https://github.com/promptfoo/modelaudit/commit/01b5f4fee5945755bc512185755cc159e5a2af42))
- **deps:** update dependency numpy to &gt;=2.4.3,&lt;2.5 ([#669](https://github.com/promptfoo/modelaudit/issues/669)) ([9d81218](https://github.com/promptfoo/modelaudit/commit/9d81218716d1f5414d11518bffe016aa6763b4ca))
- detect pickle proto structural tampering ([#697](https://github.com/promptfoo/modelaudit/issues/697)) ([0a8a737](https://github.com/promptfoo/modelaudit/commit/0a8a737af280d4e085e2945c190e5f4012ad17bc))
- detect risky import-only pickle ML surfaces ([#696](https://github.com/promptfoo/modelaudit/issues/696)) ([a272307](https://github.com/promptfoo/modelaudit/commit/a272307ad73b8a2e508d73dcab5eaaaed21a38af))
- enforce decompression limits for compressed tar wrappers ([841cc5e](https://github.com/promptfoo/modelaudit/commit/841cc5efaa95d762e02f8ec761e2d47bb813236c))
- expand dangerous pickle primitive coverage ([#705](https://github.com/promptfoo/modelaudit/issues/705)) ([40e45ac](https://github.com/promptfoo/modelaudit/commit/40e45acbdfabe4fb68ecb4a70b858635dd20aa73))
- fail closed on malformed STACK_GLOBAL operands ([#704](https://github.com/promptfoo/modelaudit/issues/704)) ([9a1b9a1](https://github.com/promptfoo/modelaudit/commit/9a1b9a1b2dd899d8d510e9ec6bcd45cc3144a7d3))
- handle Windows backslashes in XGBoost subprocess loader ([#656](https://github.com/promptfoo/modelaudit/issues/656)) ([ba30b81](https://github.com/promptfoo/modelaudit/commit/ba30b8111f0f31e4b235eb250120d9875cf522f5))
- harden archive path sanitization ([#666](https://github.com/promptfoo/modelaudit/issues/666)) ([9d77d50](https://github.com/promptfoo/modelaudit/commit/9d77d50f4bc3b1ddc3d9f686edfbe04994481a82))
- harden cloud download async/cache safety and cleanup ([#655](https://github.com/promptfoo/modelaudit/issues/655)) ([e14ea61](https://github.com/promptfoo/modelaudit/commit/e14ea61ce9a97dabe8992faa3b6f1b9a268ed757))
- harden import-only pickle global detection ([#691](https://github.com/promptfoo/modelaudit/issues/691)) ([d27d90d](https://github.com/promptfoo/modelaudit/commit/d27d90da844fe79ab8b2fa107440bf6f188fcd44))
- harden keras custom object detection ([#694](https://github.com/promptfoo/modelaudit/issues/694)) ([7651298](https://github.com/promptfoo/modelaudit/commit/765129807f51b8338e2d5cf8a23c94ae90a04dca))
- harden rule config parsing and debug path privacy ([#648](https://github.com/promptfoo/modelaudit/issues/648)) ([a073187](https://github.com/promptfoo/modelaudit/commit/a073187c9d84b57b6422f8ec0b00fc9ecf5e4080))
- harden shared config writes and archive path sanitization ([#660](https://github.com/promptfoo/modelaudit/issues/660)) ([60de400](https://github.com/promptfoo/modelaudit/commit/60de400f6eaefa7dfc5cced95def8a731a5a643e))
- harden xgboost subprocess import isolation ([#701](https://github.com/promptfoo/modelaudit/issues/701)) ([2df2d78](https://github.com/promptfoo/modelaudit/commit/2df2d78a6c61d79d39ce8a7148a63a0b9aa2b624))
- include streamed artifacts in SBOM output for --stream scans ([#672](https://github.com/promptfoo/modelaudit/issues/672)) ([48d8d54](https://github.com/promptfoo/modelaudit/commit/48d8d540bfacd4e67409cdc24083320c937be790))
- keras attack-vector fixes for coverage gaps in h5 and keras zip scanning ([#689](https://github.com/promptfoo/modelaudit/issues/689)) ([863c884](https://github.com/promptfoo/modelaudit/commit/863c8849f5c4baa654035a0f1df518d984d41624))
- **keras:** derive safe layer inventory from exports ([#718](https://github.com/promptfoo/modelaudit/issues/718)) ([9b8d143](https://github.com/promptfoo/modelaudit/commit/9b8d143aca68b92be800de01899c8f22351717d2))
- mark flaky timing test as performance to skip in CI ([#670](https://github.com/promptfoo/modelaudit/issues/670)) ([9c47f7e](https://github.com/promptfoo/modelaudit/commit/9c47f7eb3a84bb4bbe7d3bce94c0ba1c1330bace))
- **numpy:** downgrade benign object-dtype CVE attribution to info ([#723](https://github.com/promptfoo/modelaudit/issues/723)) ([b7cc190](https://github.com/promptfoo/modelaudit/commit/b7cc190f43097eacd0521241229dc8e2aaeb8cd3))
- preserve duplicate paths with spaces ([#690](https://github.com/promptfoo/modelaudit/issues/690)) ([ea7c6d9](https://github.com/promptfoo/modelaudit/commit/ea7c6d98c4edea8c2bb14216951c8a61d8f46619))
- preserve Hugging Face artifacts in SBOM output ([#673](https://github.com/promptfoo/modelaudit/issues/673)) ([49c7eca](https://github.com/promptfoo/modelaudit/commit/49c7ecadc83f125d04ac2c80151c6d04d4ed77db))
- preserve rule codes through scan aggregation ([#650](https://github.com/promptfoo/modelaudit/issues/650)) ([d71a219](https://github.com/promptfoo/modelaudit/commit/d71a219d02ec1e82302efa5bd5990707e7d10231))
- prevent jfrog folder download path traversal ([#679](https://github.com/promptfoo/modelaudit/issues/679)) ([6f226a4](https://github.com/promptfoo/modelaudit/commit/6f226a419e41a41a7d091d7c39cd07b0c8d21010))
- prevent unbounded tensor proto allocations in TF weight extraction ([#685](https://github.com/promptfoo/modelaudit/issues/685)) ([ae2b01c](https://github.com/promptfoo/modelaudit/commit/ae2b01cd6f761c907116099b8d3e2d75b9306c8e))
- recurse into NumPy object pickle payloads ([9893c0c](https://github.com/promptfoo/modelaudit/commit/9893c0c592e4305970544e38b3f7f02af3ab3edd))
- reduce Keras ZIP custom-object false positives ([#716](https://github.com/promptfoo/modelaudit/issues/716)) ([165b238](https://github.com/promptfoo/modelaudit/commit/165b238625c54432ba54f86fafc32743ea903a85))
- refresh telemetry client state ([#658](https://github.com/promptfoo/modelaudit/issues/658)) ([7b6ea2f](https://github.com/promptfoo/modelaudit/commit/7b6ea2f3a90749ec8e21b2d47b1d0b2e644502d4))
- reject absolute OCI layer references ([#659](https://github.com/promptfoo/modelaudit/issues/659)) ([722131a](https://github.com/promptfoo/modelaudit/commit/722131a554e1e149c1a996a43acdafbb0fce66f1))
- remove pickle hasattr allowlist entries ([#692](https://github.com/promptfoo/modelaudit/issues/692)) ([4d64cc8](https://github.com/promptfoo/modelaudit/commit/4d64cc80da940ccb9deb6f1d9f716010eba981e9))
- resolve bare torchserve handler modules ([#664](https://github.com/promptfoo/modelaudit/issues/664)) ([3ae3535](https://github.com/promptfoo/modelaudit/commit/3ae3535b0b69408b939b7e9e2586823949fba56b))
- restore raw telemetry fields and harden model_name extraction ([#649](https://github.com/promptfoo/modelaudit/issues/649)) ([275f087](https://github.com/promptfoo/modelaudit/commit/275f087eb28860b88b8494fa11fcea9472121d9e))
- restrict trusted jfrog hosts for auth ([#661](https://github.com/promptfoo/modelaudit/issues/661)) ([d959a0d](https://github.com/promptfoo/modelaudit/commit/d959a0d49f0a463ec4ea8165a8e434c89c4222b8))
- route compound tar wrappers to tar scanner ([#707](https://github.com/promptfoo/modelaudit/issues/707)) ([79c0772](https://github.com/promptfoo/modelaudit/commit/79c0772cd87ec92c867a0208db66c4d82650baf7))
- route oci layer members via extracted paths ([#663](https://github.com/promptfoo/modelaudit/issues/663)) ([1395af0](https://github.com/promptfoo/modelaudit/commit/1395af091d04b206f7253d540f176df5f5f210c0))
- scan TensorFlow SavedModel function definitions for dangerous ops ([#677](https://github.com/promptfoo/modelaudit/issues/677)) ([31f4715](https://github.com/promptfoo/modelaudit/commit/31f471514426196c4ca47cf4b2b82d73680b6b07))
- **security:** avoid torch import-hijack in PyTorch ZIP CVE checks ([#728](https://github.com/promptfoo/modelaudit/issues/728)) ([badd611](https://github.com/promptfoo/modelaudit/commit/badd61167833cd19fbc85a7688c958ec7d5d3e2f))
- **security:** bound pickle metadata reads in metadata extraction ([f1d0698](https://github.com/promptfoo/modelaudit/commit/f1d0698f582158f6bb8026e3e1fefb6699fb7f9a))
- **security:** detect nested kwargs URLs in CVE-2025-8747 check ([#682](https://github.com/promptfoo/modelaudit/issues/682)) ([9431fae](https://github.com/promptfoo/modelaudit/commit/9431fae04fa6341f7dade9a454f8dce8bbf640d2))
- **security:** reduce benign pickle scanner noise ([#724](https://github.com/promptfoo/modelaudit/issues/724)) ([237db31](https://github.com/promptfoo/modelaudit/commit/237db316787d672b30674be198160443ec3d8d9b))
- **security:** require explicit trust for local scan config ([#714](https://github.com/promptfoo/modelaudit/issues/714)) ([25c6936](https://github.com/promptfoo/modelaudit/commit/25c693617d906fbead1b7513618aa47c3b461f7e))
- **security:** restore ZIP fallback scanning for invalid .mar archives ([#711](https://github.com/promptfoo/modelaudit/issues/711)) ([55de730](https://github.com/promptfoo/modelaudit/commit/55de730c16c0acd09cf1faa788685f792c94d00a))
- **security:** use conservative PyTorch version selection for CVE checks ([#684](https://github.com/promptfoo/modelaudit/issues/684)) ([ef5c5e6](https://github.com/promptfoo/modelaudit/commit/ef5c5e639218c4d67de3898b710a4e041f3032ea))
- stop double-scanning PyTorch ZIP archives ([e4d36d4](https://github.com/promptfoo/modelaudit/commit/e4d36d49f5190e5a5096f9074fc362d1c363b8e3))
- stop importing dotenv in jfrog helper ([#662](https://github.com/promptfoo/modelaudit/issues/662)) ([d20fda3](https://github.com/promptfoo/modelaudit/commit/d20fda315a8e05106d25d212d026b2b602b4a586))
- stop suppressing mixed-case pickle modules ([18cdd31](https://github.com/promptfoo/modelaudit/commit/18cdd31d824383ea70121fa01e40fd8aa2fd2563))
- stream tar member extraction during scan ([#665](https://github.com/promptfoo/modelaudit/issues/665)) ([3de3048](https://github.com/promptfoo/modelaudit/commit/3de30487328738b2d8c62f203576d52b3c20409a))
- **telemetry:** preserve model refs while stripping secrets ([#717](https://github.com/promptfoo/modelaudit/issues/717)) ([d19d6fd](https://github.com/promptfoo/modelaudit/commit/d19d6fd0e95c8b62dbe53b75961987ad129a5b11))
- tighten dill MemoryError downgrade gating ([5eefa15](https://github.com/promptfoo/modelaudit/commit/5eefa15dad4e0b407c235da2eed3278c1f056bf1))
- tighten llamafile runtime allowlist matching ([#683](https://github.com/promptfoo/modelaudit/issues/683)) ([8592a80](https://github.com/promptfoo/modelaudit/commit/8592a8075d9633bbbf6e32da5f5f9a250fe0479a))
- use major GitHub Action refs ([#680](https://github.com/promptfoo/modelaudit/issues/680)) ([7965314](https://github.com/promptfoo/modelaudit/commit/7965314d2d0533795bd403fd32b591a2cb00a77a))

## [0.2.27](https://github.com/promptfoo/modelaudit/compare/v0.2.26...v0.2.27) (2026-03-05)

### Features

- add CatBoost .cbm scanner support ([#627](https://github.com/promptfoo/modelaudit/issues/627)) ([9138066](https://github.com/promptfoo/modelaudit/commit/9138066a94000d9d0ac4c23a733686c9794c3d42))
- add CNTK scanner support ([#629](https://github.com/promptfoo/modelaudit/issues/629)) ([74a60b9](https://github.com/promptfoo/modelaudit/commit/74a60b9a91cf536042f4564a2f22673bee45d410))
- add CoreML .mlmodel scanner support ([#635](https://github.com/promptfoo/modelaudit/issues/635)) ([4e24291](https://github.com/promptfoo/modelaudit/commit/4e24291bbe5b981b9af80de339de3e09a18b32d4))
- add llamafile executable scanner support ([#634](https://github.com/promptfoo/modelaudit/issues/634)) ([8d2c37d](https://github.com/promptfoo/modelaudit/commit/8d2c37d5c18673f21589cdbbe326594a6df0e02c))
- add Model Metadata Extractor feature ([#383](https://github.com/promptfoo/modelaudit/issues/383)) ([ff66f33](https://github.com/promptfoo/modelaudit/commit/ff66f339639aa72b1731879f9c2de94f74e4d6a7))
- add native LightGBM scanner support ([#633](https://github.com/promptfoo/modelaudit/issues/633)) ([d3aca64](https://github.com/promptfoo/modelaudit/commit/d3aca64f2203e5933a490f3be806c208e0e8c284))
- add R serialized scanner support ([#628](https://github.com/promptfoo/modelaudit/issues/628)) ([e27667c](https://github.com/promptfoo/modelaudit/commit/e27667c1a93c8d7fb91e8c02e8d4e0ead8ee2984))
- add RKNN scanner support ([#631](https://github.com/promptfoo/modelaudit/issues/631)) ([f1bbfb7](https://github.com/promptfoo/modelaudit/commit/f1bbfb76741b438834b93332315bf2b2d87e36a1))
- add standalone compressed wrapper scanner ([#630](https://github.com/promptfoo/modelaudit/issues/630)) ([c5f0dba](https://github.com/promptfoo/modelaudit/commit/c5f0dba48fe443974d708109969db17c7400d8e0))
- add TensorFlow MetaGraph scanner support ([#637](https://github.com/promptfoo/modelaudit/issues/637)) ([7c3c25d](https://github.com/promptfoo/modelaudit/commit/7c3c25d671d60147d05e58d1864db0deeab85461))
- add Torch7 scanner support ([#632](https://github.com/promptfoo/modelaudit/issues/632)) ([2e6f2c4](https://github.com/promptfoo/modelaudit/commit/2e6f2c4d5d25e83ce7887ff99a850d4152b2aacd))
- **security:** add CVE-2019-6446 attribution for NumPy object dtype RCE ([#610](https://github.com/promptfoo/modelaudit/issues/610)) ([5d707b5](https://github.com/promptfoo/modelaudit/commit/5d707b5968995eec50fb6ca9896cab6acae0500d))
- **security:** add CVE-2022-25882 attribution to ONNX external_data path traversal ([#606](https://github.com/promptfoo/modelaudit/issues/606)) ([4d69e83](https://github.com/promptfoo/modelaudit/commit/4d69e83623a1b057c9bf3b3ad2eb2cec49e55a87))
- **security:** add CVE-2024-3660 Lambda code injection attribution ([#604](https://github.com/promptfoo/modelaudit/issues/604)) ([60ca40f](https://github.com/promptfoo/modelaudit/commit/60ca40fd84cb92f9269d7835f80f4f5467f0c557))
- **security:** add NeMo scanner for CVE-2025-23304 Hydra _target_ injection ([#609](https://github.com/promptfoo/modelaudit/issues/609)) ([6d2dee3](https://github.com/promptfoo/modelaudit/commit/6d2dee3918dd64c7650052e9ff157e410969b519))
- **security:** detect 3 PyTorch CVEs (JIT eval, RPC injection, RemoteModule RCE) ([#611](https://github.com/promptfoo/modelaudit/issues/611)) ([98f2af6](https://github.com/promptfoo/modelaudit/commit/98f2af6d68ea50ca9b0c11591974e1fb43215bf6))
- **security:** detect 4 PyTorch CVEs via static scanning ([#595](https://github.com/promptfoo/modelaudit/issues/595)) ([024f583](https://github.com/promptfoo/modelaudit/commit/024f583dad37cdf054a3fa6c5846bc892346fea2))
- **security:** detect CVE-2024-27318 ONNX nested path traversal bypass ([#607](https://github.com/promptfoo/modelaudit/issues/607)) ([fe8837c](https://github.com/promptfoo/modelaudit/commit/fe8837c1e49a0fd8fb8d5c33b181b14900c2168e))
- **security:** detect CVE-2025-10155 pickle protocol 0/1 bypass via .bin extension ([#605](https://github.com/promptfoo/modelaudit/issues/605)) ([88a5901](https://github.com/promptfoo/modelaudit/commit/88a59017dc64c104c783bf897f8dffcc332ad1a8))
- **security:** detect CVE-2025-1550 Keras safe_mode bypass ([#599](https://github.com/promptfoo/modelaudit/issues/599)) ([432c383](https://github.com/promptfoo/modelaudit/commit/432c38314e40e6212d6f5d69413553fb827a11ee))
- **security:** detect CVE-2025-1716 pickle bypass via pip.main() ([#598](https://github.com/promptfoo/modelaudit/issues/598)) ([2f2ae20](https://github.com/promptfoo/modelaudit/commit/2f2ae2041657f6755af9e1ceea81892d68d87255))
- **security:** detect CVE-2025-49655 TorchModuleWrapper RCE ([#600](https://github.com/promptfoo/modelaudit/issues/600)) ([0c12d2d](https://github.com/promptfoo/modelaudit/commit/0c12d2dd47470104b4dcf43839ea2006d8b28d0a))
- **security:** detect CVE-2025-51480 ONNX save_external_data file overwrite ([#608](https://github.com/promptfoo/modelaudit/issues/608)) ([fe04271](https://github.com/promptfoo/modelaudit/commit/fe0427100aab3fb1377a660c7146e5a03a9dea35))
- **security:** detect CVE-2025-8747 get_file gadget bypass ([#602](https://github.com/promptfoo/modelaudit/issues/602)) ([16308d0](https://github.com/promptfoo/modelaudit/commit/16308d02745913ce15bd6d2347a56b996be3d0cf))
- **security:** detect CVE-2025-9905 H5 safe_mode bypass ([#603](https://github.com/promptfoo/modelaudit/issues/603)) ([1676693](https://github.com/promptfoo/modelaudit/commit/16766932ac7ef6dd4f1aa9bba31c14052650a5a4))
- **security:** detect CVE-2025-9906 Keras enable_unsafe_deserialization config bypass ([#601](https://github.com/promptfoo/modelaudit/issues/601)) ([b493806](https://github.com/promptfoo/modelaudit/commit/b493806550e39d5e90def4f59613ac2cf9030c3c))

### Bug Fixes

- block joblib.load pickle trampoline ([#626](https://github.com/promptfoo/modelaudit/issues/626)) ([966c223](https://github.com/promptfoo/modelaudit/commit/966c2233afb9c5b677640e2e301ff9902d48ad0b))
- **ci:** resolve 4 release pipeline failures ([#572](https://github.com/promptfoo/modelaudit/issues/572)) ([7e2e7ed](https://github.com/promptfoo/modelaudit/commit/7e2e7edf30ba8ad1959a98293241c8a79568bf18))
- **ci:** resolve Ruff failures on main ([#621](https://github.com/promptfoo/modelaudit/issues/621)) ([bd186f0](https://github.com/promptfoo/modelaudit/commit/bd186f0fbca43c12a3ecd38a9824908f3ff6da0c))
- **cli:** surface operational scan error status in text output ([#578](https://github.com/promptfoo/modelaudit/issues/578)) ([ddbbec6](https://github.com/promptfoo/modelaudit/commit/ddbbec600f832be348fd4b3d52afa3c8457e6b46))
- close pickle EXT opcode bypass ([#623](https://github.com/promptfoo/modelaudit/issues/623)) ([ffb5ec1](https://github.com/promptfoo/modelaudit/commit/ffb5ec1cbfe4eb70306e6bb3327f102ed1bc8bdc))
- **deps:** promote msgpack to core dependency for Flax scanner ([#583](https://github.com/promptfoo/modelaudit/issues/583)) ([ebba6b2](https://github.com/promptfoo/modelaudit/commit/ebba6b20eb9d59f4c7d2f9f8edd8874ee30d999f))
- detect proto0/1 pickles inside zip entries ([#624](https://github.com/promptfoo/modelaudit/issues/624)) ([2bce49d](https://github.com/promptfoo/modelaudit/commit/2bce49d4f1d506b34b41ef3f57933cc891c7868a))
- downgrade non-traversal ONNX external data refs to WARNING ([#642](https://github.com/promptfoo/modelaudit/issues/642)) ([44eb3ab](https://github.com/promptfoo/modelaudit/commit/44eb3ab25d839f42dc0ea65d585b22de9fd87777))
- eliminate false positive in skops Unsafe Joblib Fallback Detection ([#584](https://github.com/promptfoo/modelaudit/issues/584)) ([c1dd2a6](https://github.com/promptfoo/modelaudit/commit/c1dd2a69acf32d9d170c0bf805b5a08477e5cfac))
- handle MemoryError gracefully for joblib/sklearn pickle files ([#645](https://github.com/promptfoo/modelaudit/issues/645)) ([f8599fe](https://github.com/promptfoo/modelaudit/commit/f8599fea063f7977813eb413e8caba2c62fe0c09))
- **pickle-scanner:** three targeted false-positive reductions ([#591](https://github.com/promptfoo/modelaudit/issues/591)) ([7a5567e](https://github.com/promptfoo/modelaudit/commit/7a5567ebd7ece2e6b6969acda67e9b589b7c8659))
- preserve opcode analysis on malformed pickle tails ([#625](https://github.com/promptfoo/modelaudit/issues/625)) ([4fe4dee](https://github.com/promptfoo/modelaudit/commit/4fe4deec464dd93b622aea7f4552b90376ebdbcc))
- prevent false positives in TF SavedModel scanner ([#588](https://github.com/promptfoo/modelaudit/issues/588)) ([89282e2](https://github.com/promptfoo/modelaudit/commit/89282e22c4ac678c738670da9c32f3f9c865cf18))
- report actual file size in scan summary when scanner exits early ([#587](https://github.com/promptfoo/modelaudit/issues/587)) ([7d066fb](https://github.com/promptfoo/modelaudit/commit/7d066fb1c8439c4ff1a27a9cf137bcedd47b93c4))
- resolve false positive for .keras ZIP files (Keras 3.x) ([#582](https://github.com/promptfoo/modelaudit/issues/582)) ([f575769](https://github.com/promptfoo/modelaudit/commit/f575769e8e435971938d9d0d935692133d6fd950))
- resolve ONNX weight extraction failure ([#589](https://github.com/promptfoo/modelaudit/issues/589)) ([3f54602](https://github.com/promptfoo/modelaudit/commit/3f546025a69295f176a167730032e762336629a9))
- **security:** close scanner RCE bypasses and add regressions ([#518](https://github.com/promptfoo/modelaudit/issues/518)) ([e736ebb](https://github.com/promptfoo/modelaudit/commit/e736ebbeca111f30a34e07ae9100a10909711f01))
- **security:** harden pickle scanner blocklist and multi-stream analysis ([#581](https://github.com/promptfoo/modelaudit/issues/581)) ([f0c7246](https://github.com/promptfoo/modelaudit/commit/f0c7246c5c9402884d2a5fa522cef7dd52b69581))
- stabilize nightly performance CI and optimize pickle opcode analysis ([#619](https://github.com/promptfoo/modelaudit/issues/619)) ([e5dcec5](https://github.com/promptfoo/modelaudit/commit/e5dcec5a7d30a5e05e47f31007395b1ad4f87a75))
- suppress false positives in PaddlePaddle scanner ([#586](https://github.com/promptfoo/modelaudit/issues/586)) ([ec7fc48](https://github.com/promptfoo/modelaudit/commit/ec7fc48b22baa44bd5e7275a391ce98970a8b255))
- **tests:** prevent multiple_stream_attack fixture rewrites ([#580](https://github.com/promptfoo/modelaudit/issues/580)) ([0eb47c9](https://github.com/promptfoo/modelaudit/commit/0eb47c973408c055a44e61cec23682cdc26390c2))
- **tests:** resolve 3 nightly CI failures across Linux and Windows ([#576](https://github.com/promptfoo/modelaudit/issues/576)) ([dd115d1](https://github.com/promptfoo/modelaudit/commit/dd115d16e716041044f399c1d07b0d6bf64731eb))
- **tests:** resolve nightly CI failures on Linux and Windows ([#597](https://github.com/promptfoo/modelaudit/issues/597)) ([7f88c52](https://github.com/promptfoo/modelaudit/commit/7f88c524a5a2f794a4b269910f03326cea82dfce))
- **tflite:** recognize .tflite format without tflite package installed ([#585](https://github.com/promptfoo/modelaudit/issues/585)) ([8276184](https://github.com/promptfoo/modelaudit/commit/8276184b018f864acb8d9a1a2adc89108b7e07fd))
- tighten metadata URL hostname matching ([#617](https://github.com/promptfoo/modelaudit/issues/617)) ([c2af8c1](https://github.com/promptfoo/modelaudit/commit/c2af8c1d18641475457b443c3a28f975d34ed08b))

### Documentation

- add CVE detection checklist from 13 CVE implementation learnings ([#612](https://github.com/promptfoo/modelaudit/issues/612)) ([7ea1869](https://github.com/promptfoo/modelaudit/commit/7ea18695cd637cad76ff22fc973935ac4c35a3a7))
- audit and refresh README, user docs, and maintainer guides ([#643](https://github.com/promptfoo/modelaudit/issues/643)) ([015acdc](https://github.com/promptfoo/modelaudit/commit/015acdcbecd86db9e5baeef8db34df4bda5bb81b))
- rewrite SECURITY.md with comprehensive vulnerability policy ([#594](https://github.com/promptfoo/modelaudit/issues/594)) ([968a2c2](https://github.com/promptfoo/modelaudit/commit/968a2c2362a0e25862bece1ad5bb3fad4ad715fa))
- update scanner architecture example ([#579](https://github.com/promptfoo/modelaudit/issues/579)) ([20de35d](https://github.com/promptfoo/modelaudit/commit/20de35db738c828f5a29b8904834ecf5ea50e5ae))

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

[unreleased]: https://github.com/promptfoo/modelaudit/compare/v0.2.28...HEAD
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
