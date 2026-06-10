# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Bug Fixes

- assign ONNX custom operator domains to the dedicated S1111 framework rule instead of the HTTP-client S302 rule
- attribute core file-type validation failures directly to S901 instead of message-matching unrelated rules
- fail closed when manifest scanning exceeds its configured timeout
- stop cloud directory analysis as soon as download size or object-count budgets are exhausted
- preserve sanitized CatBoost command context in SARIF without exposing injected or neighboring credential values
- redact values compared against sensitive keys in generic exports and literal credential comparisons in CatBoost evidence
- preserve critical PyTorch malformed-ZIP symlink findings, valid Python 3.10 streamed ZIP64 descriptors, and selected subtype findings from complete nested and concatenated HDF5 user-block ZIPs while retaining bounded fail-closed preflight checks and avoiding structure-only ZIP route probes
- classify unsafe PyTorch ZIP symlink targets as critical archive-link findings while preserving safe relative links
- recognize canonical legacy PyTorch pickle-stream boundaries without treating raw tensor storage as incomplete pickle, binary-tail, or CVE coverage
- restore pickle CVE scan throughput, reprobe malformed stream separators, and route four-byte protocol-0 Joblib operands correctly
- bound manifest embedded-Jinja template collection while preserving findings across deep branches, cycles, and shared YAML aliases
- bound Jinja static render analysis and fail closed on CPU-heavy aliased, recursive, container-wrapped, and arithmetic range probes when sandbox workers are unavailable
- restrict auth bearer-token validation to trusted Promptfoo API hosts unless custom hosts are explicitly configured
- escape terminal and Unicode formatting controls in human-readable CLI output
- disable unsafe Joblib and NumPy object metadata deserialization
- keep concrete active execution, runtime-extension, and blacklist findings from being downgraded by Hugging Face whitelists
- keep same-fragment command/network correlations and relayed fail-closed findings active across Hugging Face whitelists
- validate Joblib NumPy wrapper state and scan resumed pickle opcodes around raw array payloads without flagging inert array bytes.
- bound CatBoost command-evidence redaction work and cover distant, shell-concatenated, wrapped, and netrc curl credentials
- use credential-free, cross-platform cloud routing filenames without changing native object-key suffix semantics
- encode native cloud object keys into collision-resistant, prefix-safe Windows paths and reject out-of-target listings
- fail closed on unsafe cloud object paths, parent-directory swaps, and download destination aliases
- discover extensionless pickle payloads inside ExecuTorch ZIP archives with bounded structural probing, including repeated protocol-0 comment-token evasions
- report TAR external link escapes with the dedicated symlink rule code, resolve link targets from their correct archive bases, and avoid retaining passing checks for benign link floods
- bind direct sharded-model cache entries to sibling shard and selected model configuration content fingerprints, and strengthen cache configuration hashes
- fail closed on PMML XML parsing when defusedxml is unavailable instead of using the stdlib parser
- reject ambiguous, lossy, SDK-invalid, or traversal-bearing Hugging Face direct file URLs, redact rejected URL secrets, and preserve platform-valid filenames
- scan safe OCI layer links with model-looking member names instead of treating link metadata as complete coverage
- preserve scanner read caps when core max_file_size is unlimited
- reject untrusted JFrog redirect hostnames unless explicitly allowed, block non-public IP targets, suppress ambient netrc credentials, and isolate redirect authentication and cookies
- restrict manual Docker publishes to validated immutable version tags and their matching Git release refs before registry login or push
- harden cloud acquisition size caps, HTTPS/R2 auto-default routing, and directory metadata failures
- detect operator attrgetter, itemgetter, and methodcaller archive-member Python paths to command execution while preserving benign accessor names
- redact Keras and TensorFlow scanner detail fields that echo model-controlled configs, code indicators, archive members, and external references.
- route security-relevant protocol-less binary pickle streams through pickle analysis even when file suffixes are misleading
- avoid routing complete benign cloud objects as protocol-less pickle prefixes when they exactly consume the content-sniff budget
- redact folded, placeholder-adjacent, proxy, and camel-case authorization evidence with scheme-bearing values without hiding benign counters
- bound Keras ZIP config traversal for CVE detectors and fail closed when config.json coverage budgets are exhausted
- redact MLflow registry, source, telemetry, and client exception credentials before logging, printing, or analytics export
- bound 7z member-name collection before archive entry-limit failures
- bound remote streaming-analysis reads and report actual received-byte coverage for truncated objects
- avoid sending raw model identifiers, source paths, object keys, issue locations, or free-form errors in telemetry
- cover Keras H5 callable metadata and module references, align CVE-2025-1550 attribution, and scope HDF5 external-reference checks to Keras weight trees
- require explicit boolean opt-in before weight-distribution scans call torch.load and bound primitive PyTorch ZIP fallback extraction
- fail closed when OCI layer TAR metadata, member counts, or cumulative extracted bytes exceed inspection budgets
- fail closed on JFrog folder downloads whose selected artifacts use unsafe, colliding, or overlapping local paths
- detect dangerous textual byte keys in Flax MessagePack checkpoints
- bound Joblib decompression output to the configured scanner read budget
- redact credential-bearing source identifiers in exported SARIF and SBOM reports
- reconcile validated streamed shard families across staging directories and add an explicit opt-in for local cross-directory shards
- stream Flax MessagePack containers with bounded traversal, object, and metadata-key handling instead of a whole-file size cutoff
- bound ExecuTorch ZIP metadata and member scans while preserving eligible pickle detections across archive limits and mutations
- close JIT replay alias, probe-budget, and compound-clause context gaps without suppressing dangerous browser or native-library calls
- detect `BINUNICODE8` literals and bounded concatenated-stream abuse in pickle CVE-2026-24747 SETITEM analysis without treating byte literals as `STACK_GLOBAL` names
- reject MLflow downloads that replace or escape private staging, hide behind directory links, expose special files, or retain external hardlinks, and report safety refusals without success telemetry
- scan raw payload indicators inside signature-valid ExecuTorch binaries and launcher-prefixed archives before reporting them clean
- detect Keras get_file tar extraction from effective call arguments without relying on URL suffixes
- reject cleartext HTTP cloud storage and PyTorch Hub model sources
- preserve dangerous JIT embedded-Python findings after benign member overwrites while bounding replay and suppression analysis
- treat Keras StringLookup external vocabularies with fixed-looking archive metadata as runtime risk instead of trusting artifact-supplied versions
- fail closed when capped DVC pointer outputs are not otherwise covered, change during verification, exceed bounded tail verification, or exhaust shared scan budgets
- preserve registrable network domains and redact delimiter-split credentials in bounded finding evidence
- preserve executable text-sidecar network findings for f-string calls, standard command wrappers, port-qualified Docker registries, and bounded xargs downloads while keeping prose references informational.
- require explicit public progress hook egress hosts and reject internal webhook and SMTP destinations before sending scan details.
- stabilize cache identity capture for compressed wrapper scans on Darwin `/private` path aliases and during unrelated temporary-file churn.
- fail closed on over-entry, oversized, inconsistent, hidden-entry, or trailing-record generic ZIP directories before `zipfile` materializes their entries, keep PyTorch ZIP budgets and loading on one descriptor, and validate generic ZIP symlinks against archive-root containment.
- detect interpolated Hydra helper configs, legacy Hydra global-state aliases, and unsafe local or remote NeMo model-loader paths.
- bound per-tensor and cumulative weight-distribution extraction before materializing PyTorch, HDF5, TensorFlow, and ONNX payloads
- keep bounded ExecuTorch ZIP snapshots seekable on Python 3.10 so benign and malicious pickle members remain analyzable

## [0.2.47](https://github.com/promptfoo/modelaudit/compare/v0.2.46...v0.2.47) (2026-06-05)

### Bug Fixes

- bind cache reads and writes to scanned file identity ([#1458](https://github.com/promptfoo/modelaudit/issues/1458)) ([860adab](https://github.com/promptfoo/modelaudit/commit/860adabe039437fcee6811a9cef561816ba25e74))
- redact MetaGraph evidence previews ([#1473](https://github.com/promptfoo/modelaudit/issues/1473)) ([58139d9](https://github.com/promptfoo/modelaudit/commit/58139d98cd6c20ddadc379ee476f2e51aa4b798e))
- redact Torch7 evidence examples ([#1467](https://github.com/promptfoo/modelaudit/issues/1467)) ([646857b](https://github.com/promptfoo/modelaudit/commit/646857bdd54f78334e79eb38896d3e0991810fca))

## [0.2.46](https://github.com/promptfoo/modelaudit/compare/v0.2.45...v0.2.46) (2026-06-05)

### Bug Fixes

- address runpy review edge cases ([#1401](https://github.com/promptfoo/modelaudit/issues/1401)) ([995f978](https://github.com/promptfoo/modelaudit/commit/995f9784529bda2f2e8e1154b38749ce3e316c56))
- analyze ambiguous protobuf routing candidates ([#1302](https://github.com/promptfoo/modelaudit/issues/1302)) ([411b6ee](https://github.com/promptfoo/modelaudit/commit/411b6eed16079f7fe74b3d9a1ecca2058e9bf407))
- avoid ambient TensorFlow proto imports ([#1406](https://github.com/promptfoo/modelaudit/issues/1406)) ([601003d](https://github.com/promptfoo/modelaudit/commit/601003def9254625f9a89ca50485dca4101757eb))
- avoid duplicate sharded scans and preserve metadata ([#1231](https://github.com/promptfoo/modelaudit/issues/1231)) ([83a0ce5](https://github.com/promptfoo/modelaudit/commit/83a0ce53a117ae1d65913bf3888a964680006d58))
- avoid framed process string false positives ([#1400](https://github.com/promptfoo/modelaudit/issues/1400)) ([9aae65a](https://github.com/promptfoo/modelaudit/commit/9aae65ae332f639b1654ce83ccb8a804a69f06f2))
- avoid pickle meta-path source probing ([#1493](https://github.com/promptfoo/modelaudit/issues/1493)) ([a31df76](https://github.com/promptfoo/modelaudit/commit/a31df7630614cf35d47031c92e4d735eb049c33e))
- block 7z symlinks before extraction ([#1462](https://github.com/promptfoo/modelaudit/issues/1462)) ([73152a0](https://github.com/promptfoo/modelaudit/commit/73152a010a8d61813522c9efa36f68fd0d88a6ff))
- block torch.load on vulnerable prereleases ([06125e5](https://github.com/promptfoo/modelaudit/commit/06125e5c1dd13c109d616ab206d13b2302aed9c4))
- bound directory metadata extraction ([#1470](https://github.com/promptfoo/modelaudit/issues/1470)) ([3dd9ceb](https://github.com/promptfoo/modelaudit/commit/3dd9ceb080f00c243a6061c05f286d0edae9cff6))
- bound GGUF declared collections ([#1316](https://github.com/promptfoo/modelaudit/issues/1316)) ([3ceb138](https://github.com/promptfoo/modelaudit/commit/3ceb13834ec89c1ddf668dcd20b2e9d179f5c520))
- bound jax and flax metadata scans ([#1500](https://github.com/promptfoo/modelaudit/issues/1500)) ([1f794df](https://github.com/promptfoo/modelaudit/commit/1f794dfe29f1a54e0bbc7a6f86ea16a415d3ce91))
- bound jinja sandbox render probes ([#1419](https://github.com/promptfoo/modelaudit/issues/1419)) ([6a6534b](https://github.com/promptfoo/modelaudit/commit/6a6534b1541fb892898edc777ed3143a5eea2520))
- bound native picklescan state simulation ([#1501](https://github.com/promptfoo/modelaudit/issues/1501)) ([f4c9cdf](https://github.com/promptfoo/modelaudit/commit/f4c9cdf0f13141e31f285d6d9fd249e6af90dd4b))
- bound OCI layer decompression ([#1443](https://github.com/promptfoo/modelaudit/issues/1443)) ([fd76fb1](https://github.com/promptfoo/modelaudit/commit/fd76fb1bddf0e08276f94dc3939b5bf7cdf660f1))
- bound Orbax directory checkpoint scanning ([#1414](https://github.com/promptfoo/modelaudit/issues/1414)) ([22a9ffa](https://github.com/promptfoo/modelaudit/commit/22a9ffaf3b4e697e21d11f139be739fb2261da7c))
- bound PyTorch ZIP version probes ([#1512](https://github.com/promptfoo/modelaudit/issues/1512)) ([196fb46](https://github.com/promptfoo/modelaudit/commit/196fb461f60d84916873189fb3b23a817a7f54ca))
- bound SavedModel graph traversal ([#1491](https://github.com/promptfoo/modelaudit/issues/1491)) ([b42fffb](https://github.com/promptfoo/modelaudit/commit/b42fffb6b06edc2ed92cc6b87295c3e5c13e5dea))
- bound SavedModel keras metadata parsing ([#1466](https://github.com/promptfoo/modelaudit/issues/1466)) ([b2eddc4](https://github.com/promptfoo/modelaudit/commit/b2eddc42affb16d6adeb7571b75cc9e9a57535a3))
- **cache:** key advanced shard allowlists ([#1248](https://github.com/promptfoo/modelaudit/issues/1248)) ([336148a](https://github.com/promptfoo/modelaudit/commit/336148a4736f3039b58b2d7ae525380ac4ad4c1c))
- cap PyTorch ZIP entry processing ([#1455](https://github.com/promptfoo/modelaudit/issues/1455)) ([e74da5b](https://github.com/promptfoo/modelaudit/commit/e74da5bccb6bca49fd12ae9107f17a552f7e0850))
- **ci:** avoid performance gating in Windows nightly ([#1264](https://github.com/promptfoo/modelaudit/issues/1264)) ([c01b42a](https://github.com/promptfoo/modelaudit/commit/c01b42a3551dd808be5afe4eaf1bd09d650a0630))
- classify incomplete CatBoost analysis correctly ([388565b](https://github.com/promptfoo/modelaudit/commit/388565b8e3fa28c7214f7a3e50cd68b885895aa2))
- classify incomplete OCI layer scans correctly ([#1291](https://github.com/promptfoo/modelaudit/issues/1291)) ([25aae73](https://github.com/promptfoo/modelaudit/commit/25aae7351247a6193941750890ada9b538b4edd3))
- classify incomplete pickle analysis and stream coverage ([#1310](https://github.com/promptfoo/modelaudit/issues/1310)) ([e20518f](https://github.com/promptfoo/modelaudit/commit/e20518f1dda61a1b1e4dcebdd90399978c9e3cff))
- classify incomplete PMML analysis correctly ([#1293](https://github.com/promptfoo/modelaudit/issues/1293)) ([a3b2cfe](https://github.com/promptfoo/modelaudit/commit/a3b2cfe6f866160f4e5bc67fe4057c311f8c817a))
- classify incomplete R serialized analysis correctly ([#1312](https://github.com/promptfoo/modelaudit/issues/1312)) ([9439adc](https://github.com/promptfoo/modelaudit/commit/9439adc87de190c319edc764720837c23a42e619))
- classify incomplete RKNN and Torch7 analysis correctly ([#1289](https://github.com/promptfoo/modelaudit/issues/1289)) ([6d0ad24](https://github.com/promptfoo/modelaudit/commit/6d0ad244b799a8681822ffab8ab7839e359e67aa))
- classify incomplete Skops coverage correctly ([#1298](https://github.com/promptfoo/modelaudit/issues/1298)) ([d618584](https://github.com/promptfoo/modelaudit/commit/d6185841a55ce00de004a79d4ee5c105f3afb23c))
- classify incomplete TAR member coverage correctly ([#1299](https://github.com/promptfoo/modelaudit/issues/1299)) ([0cb11b1](https://github.com/promptfoo/modelaudit/commit/0cb11b19e0b6cd80a14e42e4f99172938ab15e16))
- classify incomplete TorchServe analysis correctly ([#1297](https://github.com/promptfoo/modelaudit/issues/1297)) ([f443b02](https://github.com/promptfoo/modelaudit/commit/f443b02c024b188e08914b485a30c7ec197ac7ad))
- classify incomplete weight analysis correctly ([#1313](https://github.com/promptfoo/modelaudit/issues/1313)) ([e4138c1](https://github.com/promptfoo/modelaudit/commit/e4138c10402cc5e7f58c59b7a296c917d0d82978))
- classify incomplete ZIP and Keras coverage correctly ([#1300](https://github.com/promptfoo/modelaudit/issues/1300)) ([c350ab9](https://github.com/promptfoo/modelaudit/commit/c350ab93982a016815f1c5d91b5f5f15e5d47d66))
- classify PyTorch binary code patterns as findings ([#1497](https://github.com/promptfoo/modelaudit/issues/1497)) ([e9c6c0a](https://github.com/promptfoo/modelaudit/commit/e9c6c0afd456290f00a48e5796e0fb2b40043838))
- classify sevenzip probe limits as inconclusive ([#1296](https://github.com/promptfoo/modelaudit/issues/1296)) ([d7e1ad1](https://github.com/promptfoo/modelaudit/commit/d7e1ad1a03acaa97e7b0115c6e91a21736d54a16))
- classify unavailable binary artifact reads correctly ([#1305](https://github.com/promptfoo/modelaudit/issues/1305)) ([bc4e6b2](https://github.com/promptfoo/modelaudit/commit/bc4e6b27cdaf1a85610b94bdf8c69d3a34a6e370))
- classify unavailable CNTK and LightGBM reads correctly ([#1303](https://github.com/promptfoo/modelaudit/issues/1303)) ([26fcf41](https://github.com/promptfoo/modelaudit/commit/26fcf41c68d6062f9eaf2e29b72174ae656894de))
- classify unavailable Joblib reads correctly ([#1309](https://github.com/promptfoo/modelaudit/issues/1309)) ([5b56384](https://github.com/promptfoo/modelaudit/commit/5b56384ade28af193ab09e95e1d43992d4ad9f11))
- classify unavailable manifest and text reads correctly ([#1307](https://github.com/promptfoo/modelaudit/issues/1307)) ([5b50c71](https://github.com/promptfoo/modelaudit/commit/5b50c71e3c4bda4cbd99a0d4bc6c2ed97a1cc460))
- classify unavailable metadata reads correctly ([#1308](https://github.com/promptfoo/modelaudit/issues/1308)) ([fa4cdb0](https://github.com/promptfoo/modelaudit/commit/fa4cdb05c2d12f3a1c7ffb39abbdc981ef6ad72b))
- classify unavailable MetaGraph reads correctly ([#1304](https://github.com/promptfoo/modelaudit/issues/1304)) ([c00de0b](https://github.com/promptfoo/modelaudit/commit/c00de0ba3ddbe3acd18c6dd1c336fa09d14532f2))
- classify unavailable MXNet reads correctly ([#1301](https://github.com/promptfoo/modelaudit/issues/1301)) ([a7b8e27](https://github.com/promptfoo/modelaudit/commit/a7b8e272bada1164be86a7b2aea996e5f76268ad))
- classify unavailable serialized model reads correctly ([#1306](https://github.com/promptfoo/modelaudit/issues/1306)) ([113ba27](https://github.com/promptfoo/modelaudit/commit/113ba27b6365aec4eba5027ad580d2d1e2d0f0c8))
- classify unavailable TFLite analysis correctly ([#1311](https://github.com/promptfoo/modelaudit/issues/1311)) ([c3e1607](https://github.com/promptfoo/modelaudit/commit/c3e1607fc0b98fea60db8b112f9d63021870a0a5))
- **cloud:** enforce size caps on cached downloads ([#1507](https://github.com/promptfoo/modelaudit/issues/1507)) ([8f38004](https://github.com/promptfoo/modelaudit/commit/8f380044dc892351cdfbf6f765a22612c28cc976))
- confirm ONNX python_operator findings against the parsed graph ([#1254](https://github.com/promptfoo/modelaudit/issues/1254)) ([#1260](https://github.com/promptfoo/modelaudit/issues/1260)) ([beb71cd](https://github.com/promptfoo/modelaudit/commit/beb71cdf8e70961f8a949e854cc80ec164ac7d75))
- contain SBOM symlink hashing ([#1476](https://github.com/promptfoo/modelaudit/issues/1476)) ([f147ebc](https://github.com/promptfoo/modelaudit/commit/f147ebc275b92f328a97ab8002273213577efd9d))
- **core:** group HF cache shard symlinks ([#1252](https://github.com/promptfoo/modelaudit/issues/1252)) ([91f833d](https://github.com/promptfoo/modelaudit/commit/91f833d29d6f4714cad22646ce5947b19ebd2583))
- cover embedded browser and ctypes edges ([#1402](https://github.com/promptfoo/modelaudit/issues/1402)) ([ce31f2f](https://github.com/promptfoo/modelaudit/commit/ce31f2ff3316bfb66c89f3084eec58a1939f0379))
- cover patched PyTorch weight-load versions ([#1482](https://github.com/promptfoo/modelaudit/issues/1482)) ([4c0bdb3](https://github.com/promptfoo/modelaudit/commit/4c0bdb3ce7867e8b14779f873fbea205f5ce29e1))
- detect asyncio subprocess launches in embedded Python ([#1366](https://github.com/promptfoo/modelaudit/issues/1366)) ([f520c0d](https://github.com/promptfoo/modelaudit/commit/f520c0db8430e66e073445f68898d26741f5fec4))
- detect disguised PyTorch ZIP executables ([#1318](https://github.com/promptfoo/modelaudit/issues/1318)) ([00bc356](https://github.com/promptfoo/modelaudit/commit/00bc356079fe8ecc8f9c504bfa310c0a33958a8d))
- detect dynamic picklescan protocol hooks ([#1375](https://github.com/promptfoo/modelaudit/issues/1375)) ([400c132](https://github.com/promptfoo/modelaudit/commit/400c132628dd4cd31e243e4e9c46cdb5af1db46a))
- detect dynamic TorchServe handler primitives ([#1471](https://github.com/promptfoo/modelaudit/issues/1471)) ([5c28aee](https://github.com/promptfoo/modelaudit/commit/5c28aee887787a0f9be7d93fafec3a3ae38a9c4c))
- detect embedded runpy execution calls ([#1372](https://github.com/promptfoo/modelaudit/issues/1372)) ([1f9a8d5](https://github.com/promptfoo/modelaudit/commit/1f9a8d59d19d480b685ad5966f5b1be4969e085c))
- detect embedded webbrowser launch calls ([#1373](https://github.com/promptfoo/modelaudit/issues/1373)) ([f1b2df6](https://github.com/promptfoo/modelaudit/commit/f1b2df68a72273431fc9bead749980bc3f7d7edd))
- detect Keras weights-only external HDF5 refs ([69810c2](https://github.com/promptfoo/modelaudit/commit/69810c21cf07c3ce711c57d320bbf9955d83bba0))
- detect namespace-hidden archive Python calls ([#1317](https://github.com/promptfoo/modelaudit/issues/1317)) ([ae2deb3](https://github.com/promptfoo/modelaudit/commit/ae2deb3d3da5fe7323e71ea1f547c8add485927a))
- detect NeMo torch extension targets ([edb642c](https://github.com/promptfoo/modelaudit/commit/edb642c9aa3eb76f37ac7380bbc74087c6d462c6))
- detect newline-separated picklescan calls ([#1481](https://github.com/promptfoo/modelaudit/issues/1481)) ([8dcbbb1](https://github.com/promptfoo/modelaudit/commit/8dcbbb1776e68d1317b0f8c94807ebb20bac24cc))
- detect obscured GGUF chat templates ([#1315](https://github.com/promptfoo/modelaudit/issues/1315)) ([8d184c9](https://github.com/promptfoo/modelaudit/commit/8d184c915809415c959545ce2692ff5781a3ca16))
- detect os process launches in embedded Python ([#1363](https://github.com/promptfoo/modelaudit/issues/1363)) ([642fd4c](https://github.com/promptfoo/modelaudit/commit/642fd4cb9033d377ac6f8cd56bd8f054d13d2daf))
- disable sampled large-file scan caching ([#1459](https://github.com/promptfoo/modelaudit/issues/1459)) ([0ddbb93](https://github.com/promptfoo/modelaudit/commit/0ddbb93bd9dea19af83e8453d32b2c5e5b0425d7))
- enforce cloud download size caps ([#1407](https://github.com/promptfoo/modelaudit/issues/1407)) ([10e1342](https://github.com/promptfoo/modelaudit/commit/10e1342522d83366d840b55983d385d3e692239b))
- enforce Hugging Face download budgets ([#1413](https://github.com/promptfoo/modelaudit/issues/1413)) ([1587131](https://github.com/promptfoo/modelaudit/commit/1587131c5aa32eea32a8f8011c69e9056d97050d))
- enforce huggingface file size budget ([#1410](https://github.com/promptfoo/modelaudit/issues/1410)) ([7f55f52](https://github.com/promptfoo/modelaudit/commit/7f55f5230c8e750cbcaed51d0d9993968ea2fc47))
- enforce JFrog download size budgets ([#1416](https://github.com/promptfoo/modelaudit/issues/1416)) ([9cb392f](https://github.com/promptfoo/modelaudit/commit/9cb392f8e039c7bfd68bcddb00f9553d8488d747))
- enforce PyTorch Hub download budgets ([#1452](https://github.com/promptfoo/modelaudit/issues/1452)) ([d8e74fa](https://github.com/promptfoo/modelaudit/commit/d8e74fae9ff10fa794f04cfcb069ae5228ca23e5))
- fail closed on embedded Python JIT budget gaps ([#1502](https://github.com/promptfoo/modelaudit/issues/1502)) ([09a4844](https://github.com/promptfoo/modelaudit/commit/09a4844081e16afbba8c0bf5e84c4854ef90b52f))
- fail closed on embedded weights without h5py ([#1433](https://github.com/promptfoo/modelaudit/issues/1433)) ([463bc2c](https://github.com/promptfoo/modelaudit/commit/463bc2c34a938d3bfd8e997dc8b99441216b597f))
- fail closed on empty Hugging Face repo listings ([#1411](https://github.com/promptfoo/modelaudit/issues/1411)) ([1cbb8aa](https://github.com/promptfoo/modelaudit/commit/1cbb8aa5749ad5ec2223f8012bdb5595a4576770))
- fail closed on encoded nested probe cap ([6633dac](https://github.com/promptfoo/modelaudit/commit/6633dac9d284b4f3bcd994349cb2d16306e01842))
- fail closed on executable ZIP scanner gaps ([#1487](https://github.com/promptfoo/modelaudit/issues/1487)) ([889db72](https://github.com/promptfoo/modelaudit/commit/889db727469ce16caaebed66f650cc27b3b1e643))
- fail closed on hf streaming extensionless listings ([#1492](https://github.com/promptfoo/modelaudit/issues/1492)) ([d70dec4](https://github.com/promptfoo/modelaudit/commit/d70dec43130671a1821bcdd65b982e2c5db6968c))
- fail closed on incomplete Flax traversal ([#1295](https://github.com/promptfoo/modelaudit/issues/1295)) ([335d06c](https://github.com/promptfoo/modelaudit/commit/335d06cc06bbc1e4c2a43d9abf76760b97362849))
- fail closed on incomplete JAX analysis ([#1292](https://github.com/promptfoo/modelaudit/issues/1292)) ([a3558f1](https://github.com/promptfoo/modelaudit/commit/a3558f15aa89273cd21604dc38ac9e5e5155e5b5))
- fail closed on incomplete PyTorch ZIP scans ([65faa90](https://github.com/promptfoo/modelaudit/commit/65faa90034da9862bb8a89b4001e9bf180d03101))
- fail closed on malformed SavedModel metadata ([#1464](https://github.com/promptfoo/modelaudit/issues/1464)) ([60d5307](https://github.com/promptfoo/modelaudit/commit/60d530763b925edee382bef34800c94b3e5ece34))
- fail closed on NumPy object pickle skips ([#1460](https://github.com/promptfoo/modelaudit/issues/1460)) ([59c52b1](https://github.com/promptfoo/modelaudit/commit/59c52b17eb0f41e41a54c41f0db53061e67e7e29))
- fail closed on oversized standalone Jinja templates ([#1283](https://github.com/promptfoo/modelaudit/issues/1283)) ([76f221e](https://github.com/promptfoo/modelaudit/commit/76f221e431a32687a299482d230521750fa35bc3))
- fail closed on partial cloud metadata ([#1404](https://github.com/promptfoo/modelaudit/issues/1404)) ([70db661](https://github.com/promptfoo/modelaudit/commit/70db661626572c128600842a1f0a0172c790fa7c))
- fail closed on pickle import reference truncation ([#1449](https://github.com/promptfoo/modelaudit/issues/1449)) ([5ddac28](https://github.com/promptfoo/modelaudit/commit/5ddac28195813e8f5cb425a158b7c1f5d03caa79))
- fail closed on protocol 5 pickle buffers ([#1450](https://github.com/promptfoo/modelaudit/issues/1450)) ([e696a1f](https://github.com/promptfoo/modelaudit/commit/e696a1ff9452c9b9a7156325a1ff791f8ecd8ac6))
- fail closed on StringLookup external vocab metadata ([#1484](https://github.com/promptfoo/modelaudit/issues/1484)) ([b994dc3](https://github.com/promptfoo/modelaudit/commit/b994dc3f5f02b119c2359790dedbf7e9a345b087))
- fail closed on truncated CNTK string analysis ([#1290](https://github.com/promptfoo/modelaudit/issues/1290)) ([c6ee60f](https://github.com/promptfoo/modelaudit/commit/c6ee60f435bab3cd9df6f37267fab757eb3af866))
- fail closed on unavailable Keras ZIP scanner ([#1474](https://github.com/promptfoo/modelaudit/issues/1474)) ([0183a9e](https://github.com/promptfoo/modelaudit/commit/0183a9e71a8778c8050f4aac8cf84860e0a7c618))
- fail unsafe keras h5 lambda ambiguity ([#1434](https://github.com/promptfoo/modelaudit/issues/1434)) ([548d0f2](https://github.com/promptfoo/modelaudit/commit/548d0f20610820d9fc3189281b870e520ac227a4))
- flag import-only custom pickle globals ([#1499](https://github.com/promptfoo/modelaudit/issues/1499)) ([ca3a476](https://github.com/promptfoo/modelaudit/commit/ca3a4768b2dd691fb03f98da24d17a655a378162))
- flag keras fixed-boundary prereleases ([#1431](https://github.com/promptfoo/modelaudit/issues/1431)) ([0f6ea92](https://github.com/promptfoo/modelaudit/commit/0f6ea928115fae440065a4a12fc7dac2650a0f4f))
- flag native keras config modules ([#1430](https://github.com/promptfoo/modelaudit/issues/1430)) ([440fe18](https://github.com/promptfoo/modelaudit/commit/440fe18afd5bf99de3f1344cb76aa6600890c053))
- flag oversized pickle frames as tampered ([#1448](https://github.com/promptfoo/modelaudit/issues/1448)) ([c4758fd](https://github.com/promptfoo/modelaudit/commit/c4758fdc66dd831e346a5445c60a02c55fe6186a))
- harden asyncio subprocess review follow-up ([#1398](https://github.com/promptfoo/modelaudit/issues/1398)) ([31077f3](https://github.com/promptfoo/modelaudit/commit/31077f33ee1b4e31d1c82aca036a01b166b31fc0))
- harden embedded ctypes/browser analysis after [#1402](https://github.com/promptfoo/modelaudit/issues/1402) ([#1403](https://github.com/promptfoo/modelaudit/issues/1403)) ([0d37ebc](https://github.com/promptfoo/modelaudit/commit/0d37ebc6980e706d629c8de481fef12de032de56))
- harden embedded Python builtin alias detection ([#1420](https://github.com/promptfoo/modelaudit/issues/1420)) ([fadceb3](https://github.com/promptfoo/modelaudit/commit/fadceb38e1b4287301555534d73ef0215d9d2ba9))
- harden Keras ZIP external reference analysis ([#1423](https://github.com/promptfoo/modelaudit/issues/1423)) ([a0e00cf](https://github.com/promptfoo/modelaudit/commit/a0e00cf4dd633fca3320354310b68fb90bfe494d))
- harden Keras ZIP version attribution ([#1424](https://github.com/promptfoo/modelaudit/issues/1424)) ([57ca7f3](https://github.com/promptfoo/modelaudit/commit/57ca7f3fc27ecbd4980f10d6efc229038fcbc7a5))
- harden Keras ZIP wrapper traversal ([#1425](https://github.com/promptfoo/modelaudit/issues/1425)) ([713eb4d](https://github.com/promptfoo/modelaudit/commit/713eb4db979a355c6f08d04154f80dc2ee8a4322))
- harden late embedded Python replay analysis ([#1446](https://github.com/promptfoo/modelaudit/issues/1446)) ([6b625ff](https://github.com/promptfoo/modelaudit/commit/6b625ff994c50eb4aac006fcfd9a7e6607aa246c))
- harden legacy JAX checkpoint routing ([#1397](https://github.com/promptfoo/modelaudit/issues/1397)) ([4db8d50](https://github.com/promptfoo/modelaudit/commit/4db8d50254d99cb8eaed8afb0c3af8c5601b83cd))
- harden mixed Keras H5 Lambda analysis ([#1422](https://github.com/promptfoo/modelaudit/issues/1422)) ([6d1ba2e](https://github.com/promptfoo/modelaudit/commit/6d1ba2eacc949c16f79c4b9d6393feee46e7f095))
- harden MXNet overlap routing after merge audit ([#1378](https://github.com/promptfoo/modelaudit/issues/1378)) ([4e55dd0](https://github.com/promptfoo/modelaudit/commit/4e55dd07a2d7028e3e68178c5754d51f0ccbad14))
- harden NeMo Hydra interpolation analysis ([#1427](https://github.com/promptfoo/modelaudit/issues/1427)) ([099417a](https://github.com/promptfoo/modelaudit/commit/099417a03fb197535f2ba45214d836044d4b20ae))
- harden PyTorch Hub streaming cleanup ([#1454](https://github.com/promptfoo/modelaudit/issues/1454)) ([2f11b7c](https://github.com/promptfoo/modelaudit/commit/2f11b7cb43a68024e9d944ab3e5ce27957bd0c94))
- harden standalone Keras H5 external reference analysis ([#1421](https://github.com/promptfoo/modelaudit/issues/1421)) ([64e643f](https://github.com/promptfoo/modelaudit/commit/64e643ff954a7daa2664685b487bdcbf5a7b86cc))
- harden structured Jinja size handling ([#1418](https://github.com/promptfoo/modelaudit/issues/1418)) ([1165a0e](https://github.com/promptfoo/modelaudit/commit/1165a0e2a0bdf0f2babd985cb40f68c62a74a73e))
- honor compatible header alias routing ([#1272](https://github.com/promptfoo/modelaudit/issues/1272)) ([ee9611e](https://github.com/promptfoo/modelaudit/commit/ee9611e48113cd3c81ec405175bfcb090dd4e62d))
- include supported PyTorch Hub artifacts ([#1453](https://github.com/promptfoo/modelaudit/issues/1453)) ([a3e1616](https://github.com/promptfoo/modelaudit/commit/a3e16167f2f55445780daf5ad82ba4ba8820b05d))
- keep docker digest updates CI-compatible ([#1258](https://github.com/promptfoo/modelaudit/issues/1258)) ([406ed50](https://github.com/promptfoo/modelaudit/commit/406ed504be547961a2d4a95048eff32d37b64d05))
- keep shard siblings within scan root ([a1efccb](https://github.com/promptfoo/modelaudit/commit/a1efccbe5298d6de8725f88335228f8de3b39a2e))
- **keras:** redact authorization detail aliases ([#1511](https://github.com/promptfoo/modelaudit/issues/1511)) ([18de054](https://github.com/promptfoo/modelaudit/commit/18de0547a499b2779e823f7f379b9262d0fcec9f))
- **manifest:** fail closed on cloud URL read errors ([#1396](https://github.com/promptfoo/modelaudit/issues/1396)) ([cf1da88](https://github.com/promptfoo/modelaudit/commit/cf1da887a66c6fb21cc9ceacae89c2854f210793))
- mark compressed partial scans inconclusive ([#1286](https://github.com/promptfoo/modelaudit/issues/1286)) ([39b8f58](https://github.com/promptfoo/modelaudit/commit/39b8f586b29f77b248feff4948a76ab030f12207))
- mark oversized structured Jinja templates incomplete ([6662d3d](https://github.com/promptfoo/modelaudit/commit/6662d3d489a10764a24c5310965d4f9d9f3a9b74))
- mark truncated pickle binary tails incomplete ([#1445](https://github.com/promptfoo/modelaudit/issues/1445)) ([cae15c4](https://github.com/promptfoo/modelaudit/commit/cae15c4698cb0a641354778ebe4849fcaa9e0e1e))
- **nemo:** fail closed on linked load semantics ([#1377](https://github.com/promptfoo/modelaudit/issues/1377)) ([b952e4b](https://github.com/promptfoo/modelaudit/commit/b952e4b970acd9c4e315afb325adb7b0b7fbcee5))
- omit SafeTensors custom metadata from security view ([#1440](https://github.com/promptfoo/modelaudit/issues/1440)) ([23e7c44](https://github.com/promptfoo/modelaudit/commit/23e7c448e6c8706dca850848f0f8c6744f9e877c))
- **onnx:** scan function default graphs ([#1273](https://github.com/promptfoo/modelaudit/issues/1273)) ([10c57ed](https://github.com/promptfoo/modelaudit/commit/10c57ed00fd7b2fc1e5f9623b4b920e1f23b629f))
- **onnx:** scan nested Python operators ([#1265](https://github.com/promptfoo/modelaudit/issues/1265)) ([40850e3](https://github.com/promptfoo/modelaudit/commit/40850e3e1a5ea4396c45034a3766390f6e263e5a))
- preflight 7z extraction budgets ([bf7f3de](https://github.com/promptfoo/modelaudit/commit/bf7f3de9001a7dd6e4c8d5fc1706dd51a7732280))
- preserve Flax routing across ambiguous prefixes ([#1379](https://github.com/promptfoo/modelaudit/issues/1379)) ([b3438b8](https://github.com/promptfoo/modelaudit/commit/b3438b8d30070d7ec7b1ed8325429b28445ed706))
- preserve visible JAX findings in oversized JSON ([#1380](https://github.com/promptfoo/modelaudit/issues/1380)) ([39afcf0](https://github.com/promptfoo/modelaudit/commit/39afcf05e7149086bbbd8477b2e33ff52704ed3e))
- redact code evidence in scanner findings ([#1495](https://github.com/promptfoo/modelaudit/issues/1495)) ([1c2855e](https://github.com/promptfoo/modelaudit/commit/1c2855ebbe9a42a32919d3d054549a91c88afafe))
- redact compound credential evidence ([4a0a364](https://github.com/promptfoo/modelaudit/commit/4a0a364c03bc68a76fdfcdc6d4ab215909f864db))
- redact flax msgpack evidence ([#1409](https://github.com/promptfoo/modelaudit/issues/1409)) ([66c55cb](https://github.com/promptfoo/modelaudit/commit/66c55cb92b8299d3d04cb78d09ca84b1edbd4082))
- redact Keras evidence secrets ([#1475](https://github.com/promptfoo/modelaudit/issues/1475)) ([37eda4e](https://github.com/promptfoo/modelaudit/commit/37eda4e69404458d14aeba95f64a03de97761891))
- redact keras zip finding details ([#1436](https://github.com/promptfoo/modelaudit/issues/1436)) ([b90d08d](https://github.com/promptfoo/modelaudit/commit/b90d08dcb0532bc5ad2bcc7ab1818f3522aad8f0))
- redact LightGBM evidence excerpts ([#1437](https://github.com/promptfoo/modelaudit/issues/1437)) ([fed2313](https://github.com/promptfoo/modelaudit/commit/fed23134c5cffea10c98e644c6c3d61ef0fa1fb7))
- redact metadata secret previews ([#1439](https://github.com/promptfoo/modelaudit/issues/1439)) ([a96f83a](https://github.com/promptfoo/modelaudit/commit/a96f83af949114e6c1adebb9bf05a5e60c9ae368))
- redact network URL path tokens ([fa5fd17](https://github.com/promptfoo/modelaudit/commit/fa5fd1734651ada47d3329cd8b1abaf4f7954fee))
- redact R serialized executable samples ([#1456](https://github.com/promptfoo/modelaudit/issues/1456)) ([7c3e10c](https://github.com/promptfoo/modelaudit/commit/7c3e10c4e810042c9fea4de75d6e57a0e0365869))
- redact SavedModel decoded previews ([ba6eaa1](https://github.com/promptfoo/modelaudit/commit/ba6eaa18eea5c6d6b11c6b849a3f93a87acd1b7e))
- redact secret detector contexts ([923f6af](https://github.com/promptfoo/modelaudit/commit/923f6af40ee7e81da1c833d3012fd79ce787d39c))
- reject unsafe JFrog credential targets ([#1490](https://github.com/promptfoo/modelaudit/issues/1490)) ([11d8978](https://github.com/promptfoo/modelaudit/commit/11d8978d6a450740e0bad0e0f1a7ab7b70e478b4))
- repair nightly and docker ci ([#1255](https://github.com/promptfoo/modelaudit/issues/1255)) ([4c8fa7b](https://github.com/promptfoo/modelaudit/commit/4c8fa7b8e21e39b2b7bba120beaf1d9441ade48b))
- report Keras external refs despite metadata ([#1478](https://github.com/promptfoo/modelaudit/issues/1478)) ([0c63514](https://github.com/promptfoo/modelaudit/commit/0c63514d466c54877b3d9d7ee1ec1dc2e5b360f9))
- report Keras H5 external refs despite metadata ([#1483](https://github.com/promptfoo/modelaudit/issues/1483)) ([5997e06](https://github.com/promptfoo/modelaudit/commit/5997e06d9be1a4a2031aa245eaa2ca08332c2a91))
- require ETags for cloud cache hits ([1a8e39d](https://github.com/promptfoo/modelaudit/commit/1a8e39d169f008f2eb6ca494b07188d0e12c92ae))
- resolve follow-up quality findings ([#1222](https://github.com/promptfoo/modelaudit/issues/1222)) ([2968961](https://github.com/promptfoo/modelaudit/commit/2968961a40adf5c9e9333d1a2c601cc9aca7fa4e))
- restrict auth token API hosts ([#1486](https://github.com/promptfoo/modelaudit/issues/1486)) ([9ccddc5](https://github.com/promptfoo/modelaudit/commit/9ccddc58d59c7e702e52743d79a5c50f37195359))
- restrict JFrog credential forwarding ([8287edd](https://github.com/promptfoo/modelaudit/commit/8287edde56b084dc04bafa45bfe27f4e598f418b))
- retain oversized renamed SafeTensors candidates ([#1285](https://github.com/promptfoo/modelaudit/issues/1285)) ([64efefa](https://github.com/promptfoo/modelaudit/commit/64efefa93bbd5df6bdb27bfb33a367a0d0088172))
- route disguised llamafiles and classify preview read failures ([#1267](https://github.com/promptfoo/modelaudit/issues/1267)) ([ad55249](https://github.com/promptfoo/modelaudit/commit/ad55249069125ba83e045f49394cdb22823355ea))
- route disguised torch7 payloads by content ([#1268](https://github.com/promptfoo/modelaudit/issues/1268)) ([9ba9cd1](https://github.com/promptfoo/modelaudit/commit/9ba9cd1043f54c696c1bba47951cc231f0d320db))
- route extensionless XGBoost and classify incomplete analysis ([#1276](https://github.com/promptfoo/modelaudit/issues/1276)) ([46bffb4](https://github.com/promptfoo/modelaudit/commit/46bffb4d179125bb2fce8be5b1919369c9ac5151))
- route large and renamed Flax MessagePack checkpoints ([#1280](https://github.com/promptfoo/modelaudit/issues/1280)) ([40766c4](https://github.com/promptfoo/modelaudit/commit/40766c43df6ca843166ad5a9801a979552aa14c6))
- route padded and renamed JAX JSON checkpoints ([#1281](https://github.com/promptfoo/modelaudit/issues/1281)) ([62270b4](https://github.com/promptfoo/modelaudit/commit/62270b43f78caf40b4519d750ec48a821ea03e35))
- route prefixed renamed ONNX payloads by structure ([#1287](https://github.com/promptfoo/modelaudit/issues/1287)) ([b022bbb](https://github.com/promptfoo/modelaudit/commit/b022bbb900e6555e668ea7696663476ed5d52b2e))
- route renamed binary formats and classify ExecuTorch read failures ([#1271](https://github.com/promptfoo/modelaudit/issues/1271)) ([c86dd85](https://github.com/promptfoo/modelaudit/commit/c86dd85892f86a78952d078ed1c6bbd7e3d782b8))
- route renamed CNTK and LightGBM payloads ([#1269](https://github.com/promptfoo/modelaudit/issues/1269)) ([877aa10](https://github.com/promptfoo/modelaudit/commit/877aa10813ab39e6b5352bc68346f92687c09d80))
- route renamed MXNet symbol graphs by structure ([#1278](https://github.com/promptfoo/modelaudit/issues/1278)) ([1c0b3c5](https://github.com/promptfoo/modelaudit/commit/1c0b3c5c23ebfb99181bba28a8b873e004674f8b))
- route renamed NeMo archives by structure ([#1274](https://github.com/promptfoo/modelaudit/issues/1274)) ([bf96228](https://github.com/promptfoo/modelaudit/commit/bf96228c653c739b1afcc6eedc4d06721945c067))
- route renamed R workspace artifacts ([#1322](https://github.com/promptfoo/modelaudit/issues/1322)) ([e004deb](https://github.com/promptfoo/modelaudit/commit/e004deb1699626465e9c57917b8c089e1aab61bc))
- route renamed TensorFlow protobuf models by structure ([#1284](https://github.com/promptfoo/modelaudit/issues/1284)) ([3327c39](https://github.com/promptfoo/modelaudit/commit/3327c39fe327541f8b2fbf25134e27b4e3d914f5))
- **routing:** avoid false Flax overlap on complete pickles ([#1506](https://github.com/promptfoo/modelaudit/issues/1506)) ([6510430](https://github.com/promptfoo/modelaudit/commit/6510430a1c38e7fe8a6536fb0d844846ec1b0482))
- **routing:** preserve Torch7 findings in Llamafile polyglots ([#1376](https://github.com/promptfoo/modelaudit/issues/1376)) ([2e95c88](https://github.com/promptfoo/modelaudit/commit/2e95c88eb37043a72551a636e30e9df54e72f486))
- run text sidecar security detectors ([#1498](https://github.com/promptfoo/modelaudit/issues/1498)) ([9e3f581](https://github.com/promptfoo/modelaudit/commit/9e3f5811568755bcc13f666d633a02971742e7cd))
- scan duplicate executorch pickle members ([#1408](https://github.com/promptfoo/modelaudit/issues/1408)) ([5b4c616](https://github.com/promptfoo/modelaudit/commit/5b4c6161050018a65c58813eba2be7efa7d6a13e))
- scan hidden compressed payload risks ([#1320](https://github.com/promptfoo/modelaudit/issues/1320)) ([77ec76f](https://github.com/promptfoo/modelaudit/commit/77ec76fb145d4ea67f817b07635f655e53f145d8))
- scan late PyTorch binary executable signatures ([#1451](https://github.com/promptfoo/modelaudit/issues/1451)) ([bd2782c](https://github.com/promptfoo/modelaudit/commit/bd2782c76ab58b188bb35d47ee4a7f969399f98d))
- scan namespaced OpenVINO layers ([#1314](https://github.com/promptfoo/modelaudit/issues/1314)) ([59794d6](https://github.com/promptfoo/modelaudit/commit/59794d6fdb901ecd55878444b78ab7ea01a8c1c8))
- scan nested ONNX external initializers ([d3a9130](https://github.com/promptfoo/modelaudit/commit/d3a9130013c72b04c75bba424e783bea35c7242e))
- scan nested ONNX external tensor references ([#1399](https://github.com/promptfoo/modelaudit/issues/1399)) ([5071995](https://github.com/promptfoo/modelaudit/commit/5071995c630d804409b3e051e609a32d04b8a07e))
- scan padded SavedModel protobuf strings ([#1469](https://github.com/promptfoo/modelaudit/issues/1469)) ([b26c000](https://github.com/promptfoo/modelaudit/commit/b26c00095fc9a23ab45e2d7087644ab4221b95a3))
- scan protocol zero JAX checkpoint pickles ([aa580c6](https://github.com/promptfoo/modelaudit/commit/aa580c677172b611d93b65d5a18c110d37efc873))
- scan raw nested pickles in unicode strings ([#1461](https://github.com/promptfoo/modelaudit/issues/1461)) ([4278da9](https://github.com/promptfoo/modelaudit/commit/4278da93863ae5972de9e79eddc06bd5692974b5))
- scan RKNN safe metadata values ([cd833c2](https://github.com/promptfoo/modelaudit/commit/cd833c2050709acd15eac7d3c84016200f6330f2))
- skip hashing files over scan size limit ([#1441](https://github.com/promptfoo/modelaudit/issues/1441)) ([2b46042](https://github.com/promptfoo/modelaudit/commit/2b46042bf59de2aa628cde73b61e8990a2a20fcc))
- sniff cloud content before selective skip ([#1405](https://github.com/promptfoo/modelaudit/issues/1405)) ([90c5627](https://github.com/promptfoo/modelaudit/commit/90c5627ab40ec0f8fdd92be82ffa42e2c5999faf))
- sniff JFrog folder content before selective skip ([#1417](https://github.com/promptfoo/modelaudit/issues/1417)) ([372a72a](https://github.com/promptfoo/modelaudit/commit/372a72ab51868b4ed72a5462fffe6090b72494e9))
- strip jfrog credentials on redirects ([#1415](https://github.com/promptfoo/modelaudit/issues/1415)) ([6869361](https://github.com/promptfoo/modelaudit/commit/686936159f192b66201b2ec46ddee9019cd1ad72))
- terminate call-graph alias fixpoint on oscillating rebinds ([#1247](https://github.com/promptfoo/modelaudit/issues/1247)) ([#1259](https://github.com/promptfoo/modelaudit/issues/1259)) ([89895a4](https://github.com/promptfoo/modelaudit/commit/89895a4c646feabb98888fece9cf12ef283d351e))
- **torch7:** restore ASCII serialized routing ([#1263](https://github.com/promptfoo/modelaudit/issues/1263)) ([a0cf7f0](https://github.com/promptfoo/modelaudit/commit/a0cf7f09061c0d327a366e66838a516624dd4191))
- treat Keras fixed-version prereleases as vulnerable ([ae76cb9](https://github.com/promptfoo/modelaudit/commit/ae76cb9d453aea8a19625e41f75ecee7d109e691))

### Performance Improvements

- mmap TFLite files for zero-copy FlatBuffer scanning ([#1503](https://github.com/promptfoo/modelaudit/issues/1503)) ([ce3b4f4](https://github.com/promptfoo/modelaudit/commit/ce3b4f4e8f0ac5899e9cdfff93b8c5bb0c9efe42))
- restore realistic benchmark suite ([#1223](https://github.com/promptfoo/modelaudit/issues/1223)) ([9c36efb](https://github.com/promptfoo/modelaudit/commit/9c36efb472f91bcf8d9d0158a622621254cd81b0))
- reuse call graph analysis in directory scans ([#1266](https://github.com/promptfoo/modelaudit/issues/1266)) ([2f01ddf](https://github.com/promptfoo/modelaudit/commit/2f01ddfc88d1b625687867b6745237fe25aa3bb3))

### Documentation

- align picklescan version guidance ([#1279](https://github.com/promptfoo/modelaudit/issues/1279)) ([a53eb11](https://github.com/promptfoo/modelaudit/commit/a53eb112fcbdf4d6baca1ae0124aba8129cb95e1))

## [Unreleased]

### Bug Fixes

- prevent sharded-model scans from accepting changed family membership, stale shard identities, or unsafe aliases
- invalidate cached pickle call-graph results when analyzed Python sources, search paths, or loaded module origins change
- harden CLI scan, SBOM, metadata, and scanner-catalog output writes against links, reparse points, and special files; preserve Windows ownership and ACLs, and reject EFS-encrypted destinations that cannot be replaced without changing recipients
- distinguish valid R call/index argument tags from malformed credential assignments and fail closed on incomplete function bodies
- require every concrete non-local MLflow artifact target to match `MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS`, including artifact-path-specific entries, while safely composing local overlays and binding downloads to the validated repositories
- validate OCI layer member and link metadata without suppressing regular-file payload scans, while preserving valid container-root symlinks
- prevent cache identity checks from accepting temporary higher-ancestor path swaps
- preflight MLflow artifact sizes and copy supported local repositories under hard byte limits, rejecting unsafe paths, size drift, and backends that cannot enforce the configured download budget
- omit attacker-controlled Keras H5 Lambda names, module/function references, source, bytecode, code-analysis, malformed config, compiler-error, nested-key, and fake wrapped-layer evidence; clean up temporary Python compiler artifacts; fail closed on malformed scalar functions; and avoid substring-only malformed-source warnings
- fail closed on standalone and Keras ZIP HDF5 scans when `h5py` is unavailable, including content-routed and extensionless user-block files, while preserving overlapping format findings and invalidating stale cached results
- fail closed when raw secret, JIT, or network detector analysis errors occur, and when memory-mapped files change during scanning
- mark unresolved DVC outputs as incomplete scan coverage instead of scanning pointer text as clean
- redact secret-bearing TensorFlow MetaGraph executable previews and correlation examples
- redact credential-shaped Torch7 evidence and detect execution primitives across chunk boundaries and alternate Lua syntax
- bind cache reads and writes to complete file and pathname identities captured before scanning
- bind SBOM hashing to stable scan-root descriptors and omit hashes for outside, swapped, or missing local symlink targets
- detect native execution modules and nested serialized callables in Keras configs without promoting unimportable dotted native-module paths
- classify noncanonical Keras versions inside wholly vulnerable numeric ranges and avoid over-attributing wildcard fixed lines
- preserve selected content-routed and exact-name cloud/JFrog artifacts, structurally filter renamed JFrog ZIPs, share cloud probe and download budgets, isolate selective directory caches, and exclude confidently unselected shared-suffix formats
- detect TorchServe MAR handler execution primitives reached through dynamic imports, namespace lookups, literal selection, callbacks, and partial callables without flagging statically unreachable paths
- omit sensitive LightGBM model excerpts and network values from finding evidence
- fail closed when TensorFlow SavedModel graph traversal exceeds bounded node or function budgets
- restrict bearer-token authentication to validated HTTPS base API hosts before requests and preserve prior credential routing when config persistence fails
- redact credential-bearing and unrelated URL context from network and C&C finding snippets while preserving nested query and fragment endpoints
- enforce JFrog file and folder download size budgets before and during remote artifact transfer, and bound Storage API metadata responses
- validate and bound OCI gzip framing and raw TAR metadata before parsing layers, preventing decompression-budget dilution and malformed-trailer bypasses
- fail closed on embedded Keras HDF5 weights when `h5py` is unavailable while preserving full-payload, generic, and concatenated user-block security findings
- omit raw SafeTensors custom metadata values from security-only output while retaining precise redacted risk flags and rejecting malformed metadata maps
- block 7-Zip symlinks, junctions, and ambiguous duplicate member names before extraction
- add aggregate file, byte, and depth budgets to directory metadata extraction and reject non-regular entries and symlink targets
- redact and detect secrets in R serialized executable samples across native assignment syntax
- redact authorization aliases across structured, malformed, subscripted, and R scanner evidence
- scan padded TensorFlow SavedModel protobuf scalar and repeated string attributes past the legacy 10 KB injection-check window
- mark malformed SavedModel `keras_metadata.pb` analysis as inconclusive instead of a clean scan
- fail closed on pickle protocol 5 `NEXT_BUFFER` opcodes instead of reporting clean coverage
- bound `keras_metadata.pb` parsing in SavedModel scans, fail closed when the budget is exceeded, and continue analysis when a system hash policy disables MD5
- fail closed when structurally recognized Keras ZIP scanners are unavailable while retaining generic ZIP security findings
- redact sensitive decoded previews in TensorFlow SavedModel collection, PyFunc, and Keras metadata findings
- report proven oversized pickle `FRAME` length mismatches as structural tampering without misclassifying incomplete frame reads
- fail closed on novel standalone picklescan import/callable metadata truncation without masking operational read errors or repeated benign imports
- skip scan-result caching for sampled large-file fingerprints
- classify high-confidence active code patterns in PyTorch binary artifacts as security findings so scan exits reflect them
- run bounded secret and network-content checks for ML text sidecars and prefer strict LightGBM content over native Flax suffixes
- bound Flax MessagePack decoding/traversal and Orbax metadata JSON parsing so oversized JAX/Flax checkpoints fail closed
- avoid false inconclusive Flax overlap results for complete pickle payloads with no trailing data
- preserve dangerous embedded-Python builtin detection across aliases, builtin namespaces, and control flow
- bound Keras ZIP HDF5 external-reference inspection and evidence, preserve hard-link cycle traversal, and flag malformed Lambda metadata
- fail closed on noncanonical Keras ZIP Lambda and external-reference versions
- scan ONNX external data references in sparse initializers, tensor-valued attributes, and function defaults
- avoid false-positive process-launch findings for parsed framed Python string literals
- detect dangerous Python calls retrieved through module namespace dictionaries in ZIP and TAR members
- fail closed on malformed Keras version suffixes used for CVE boundary checks
- fail closed when executable ZIP subtype scanners are unavailable
- reject local, plaintext, and redirecting JFrog credential targets
- detect embedded Python `os.exec*`, `os.spawn*`, `os.posix_spawn*`, and `os.startfile` process-launch calls in archives and JIT-scanned content
- detect embedded Python `asyncio.create_subprocess_*` calls and resolved JIT `subprocess` launch aliases
- detect embedded Python `runpy.run_module`, `runpy.run_path`, and `runpy._run_module_as_main` dynamic-module execution calls
- preserve embedded Python runpy, webbrowser, and ctypes findings across continued imports, late aliases, and bounded tail-window extraction gaps
- preserve late `runpy` execution findings across bounded state updates, restoration, and builtin shadowing
- mark embedded Python/JIT byte and snippet budget exhaustion as incomplete coverage instead of clean scans
- detect embedded Python `webbrowser` launches and `ctypes` native-library loads in archives and JIT-scanned content
- resolve embedded `ctypes` loads through more CDLL-subclass construction forms (`__new__` returning inside `try`/`for`/`while`/`with`, `super()`/`*args` initializer forwarding) and indirect loader/controller bindings (conditional, boolean, walrus, and loop-bound expressions)
- honor benign loader/controller member overwrites spelled as `setattr(..., **{})` or starred `setattr(*(...))`
- fail closed on deeply nested embedded Python members and bound embedded-snippet alias probing so crafted archives cannot crash or stall the scan
- scan dangerous RKNN safe-key metadata values instead of suppressing the whole key-value string
- scan ONNX external data initializers in nested graphs, functions, and training graphs
- route protocol-0 JAX checkpoint pickles through pickle opcode security checks
- bound Orbax directory metadata parsing and checkpoint entry enumeration before scanning JAX checkpoints
- harden legacy JAX checkpoint pickle routing against bounded-prefix bypasses and benign sidecar false positives
- detect dangerous Python calls retrieved or installed through module namespace dictionaries in ZIP and TAR members, while avoiding comprehension-local false positives
- preflight and stream-enforce cumulative SevenZip extraction budgets before writing oversized archives
- mark oversized structured JSON/YAML Jinja template fields as incomplete coverage instead of clean
- bound Jinja sandbox safety probes so render amplification fails closed instead of exhausting scanner resources
- harden structured JSON/YAML/GGUF Jinja template extraction against oversized values, nested containers, and colliding template paths
- redact capability tokens embedded in network URL path segments
- redact Flax/JAX MessagePack scanner samples, contexts, key paths, structured fields, metadata, and errors
- redact secret previews and URL path credentials from metadata scanner findings
- redact secret-shaped dictionary keys from embedded-secret detector finding contexts
- redact compound credential names and malformed userinfo URLs in scanner evidence
- redact secret-bearing JAX/Orbax, JIT, PyTorch ZIP, and explicit model-network evidence before serializing findings
- restrict JFrog credential forwarding to explicitly trusted HTTPS hosts
- include content-routed renamed JFrog folder artifacts in selective downloads with fail-closed bounded probes
- strip JFrog credentials from untrusted redirect hops during artifact and Storage API requests
- enforce direct Hugging Face file `--max-size` budgets before downloading
- scan duplicate and case-varied ExecuTorch pickle ZIP members without shadowable-name or metadata-routing bypasses
- refresh cloud cache entries that cannot be proven within the configured download size limit
- enforce automatic cloud download size limits when remote size metadata is missing or late-bound
- avoid importing attacker-shadowed TensorFlow protobuf packages during static scanning
- inspect every parsed GGUF chat template when duplicate or trailing malformed metadata could otherwise hide SSTI payloads
- bound GGUF declared metadata and tensor collections, and cap reported tensor summaries, so oversized structures fail closed without exhausting scanner resources
- redact secret-shaped dictionary keys from embedded-secret detector finding contexts
- redact compound credential names and malformed userinfo URLs in scanner evidence
- restrict JFrog credential forwarding to explicitly trusted HTTPS hosts
- redact compound credential names and malformed userinfo URLs in scanner evidence
- restrict JFrog credential forwarding to explicitly trusted HTTPS hosts
- block weight distribution `torch.load` on PyTorch prerelease, dev, and unknown versions before deserialization while preserving final, local, and PEP 440 post-release patched builds
- fail closed on unverified Keras ZIP `StringLookup` vocabulary paths and redact remote URL evidence
- fail closed when cloud directory metadata cannot be read for every listed object
- treat normalized PEP 440 prereleases of the fixed Keras 3.11.3 CVE-2025-49655 boundary as vulnerable without allowing long local-version metadata to downgrade attribution
- treat prereleases of fixed Keras ZIP CVE-2026-1669 versions as vulnerable
- redact reversible secret evidence from CatBoost findings and validate IPv4/IPv6 network indicators
- detect and safely bound NeMo Hydra process-execution, native-loader, network, and file-access callable targets, including trusted-namespace import/cache helpers, repeated YAML aliases, and NumPy file writers
- fail closed on interpolation-bearing NeMo Hydra `_target_` selectors whose resolved callable cannot be verified
- scan and globally bound Keras ZIP wrapper-owned nested layers while preserving custom namespace warnings
- detect external references in weights-only Keras HDF5 layouts without Keras metadata
- bound standalone Keras HDF5 layout and external-reference analysis, and distrust artifact-controlled versions
- inspect mixed dict/list Keras HDF5 Lambda bytecode with bounded, marshal-aware analysis
- fail closed on malformed Keras HDF5 Lambda functions, code-loading callbacks, and non-allowlisted framework references
- restrict JFrog credential forwarding to explicitly trusted HTTPS hosts
- classify unavailable metadata document reads and timed-out metadata scans as operationally incomplete rather than security findings
- route renamed structured JAX/Orbax JSON checkpoints, conservatively report observable bounded-prefix threats, and fail closed for oversized identified metadata
- classify Flax MessagePack recursion-limit analysis gaps as inconclusive coverage
- classify incomplete JAX/Orbax metadata, pickle, and NumPy analysis as inconclusive coverage
- route renamed structured JAX/Orbax JSON checkpoints and fail closed for oversized identified metadata
- route renamed structurally valid Flax/JAX MessagePack checkpoints through bounded, fail-closed security analysis
- preserve Flax/JAX MessagePack routing under skipped text/configuration suffixes and pickle-shaped prefixes with bounded fail-closed ambiguity handling
- avoid emitting sensitive scanner finding or loader error payloads in logs
- fail closed when PyTorch ZIP analysis cannot complete configured blacklist inspection or a required scan phase
- stream Hugging Face files through case-insensitive suffix filtering with bounded extensionless coverage
- fail closed when standalone Jinja2 templates exceed the configured analysis size limit or cannot be decoded as UTF-8 text
- classify bounded, unreadable, or malformed PMML analysis gaps as inconclusive instead of security findings
- classify unavailable Joblib reads as inconclusive rather than security findings
- avoid repeatedly scanning sharded model families during directory scans
- keep shard sibling discovery within the requested scan root
- preserve per-shard metadata when aggregating sharded model families
- prevent picklescan call-graph alias cycles from hanging scans
- preserve HuggingFace snapshot shard paths while grouping cache-backed families
- enforce Hugging Face repository `--max-size` budgets before selected snapshot or streaming downloads begin
- fail closed when Hugging Face repository listings contain no recognized scannable files instead of downloading the full repository
- include bounded content-routed Hugging Face repository files in selective downloads, preserve local filename-based false-positive guards, pin probes and downloads to one immutable revision, redact signed transport errors, enforce acquisition deadlines across transfer process groups, and fail closed when repository coverage cannot be completed safely
- stop flagging a false-positive ONNX Python operator when tensor weight bytes coincidentally spell `PyOp`
- classify unavailable manifest and ML text reads as inconclusive rather than security findings, including routing, preflight, and stale cache transitions
- classify unavailable manifest cloud-reference inspection as inconclusive rather than reporting complete coverage
- detect Python operators declared in nested ONNX graphs, functions, and function-default graphs
- distinguish ASCII-serialized Torch7 artifacts from plain PyTorch source text
- route renamed R workspace artifacts only from complete workspace serialization headers without promoting text near-matches
- report incomplete R serialized coverage without treating extraction ceilings alone as suspicious payloads, and preserve detection across printable-chunk boundaries
- mark compressed-wrapper partial-analysis outcomes explicitly inconclusive
- scan decompressed Python and content-disguised executable payloads through bounded security checks without caching ephemeral inner files
- detect executable PyTorch ZIP sidecars hidden behind ordinary filenames while excluding raw tensor-storage bytes
- fail closed and cap downstream scanning, metadata listings, and version metadata probes for PyTorch ZIP archives, preserve parent structure attribution across nested entry limits, and retain deadline and prefixed-layout metadata handling
- scan 7-Zip Python members and content-disguised executable sidecars through shared archive security checks
- include supported non-PT artifacts linked from PyTorch Hub model pages while rejecting format-changing redirects and non-artifact responses
- enforce `--max-size` while streaming PyTorch Hub model weights
- enforce `--max-size` while downloading PyTorch Hub models in normal acquisition mode
- detect structurally valid executable payloads throughout PyTorch binary files while bounding context analysis and findings
- skip non-numeric weight metadata and report incomplete weight-distribution analysis accurately
- classify unavailable Paddle, NumPy, PyTorch binary, and SavedModel reads as inconclusive rather than security findings
- fail closed when scanner selection disables required NumPy object-dtype embedded pickle analysis
- classify unavailable CoreML, SafeTensors, and TensorRT reads as inconclusive rather than security findings
- classify unavailable TensorFlow MetaGraph reads as operational errors rather than security findings, including stale cache transitions
- classify unavailable CNTK and LightGBM reads as inconclusive rather than security findings
- route renamed and unknown-field-prefixed CoreML models, including valid unknown groups, reordered fields, and bounded routing candidates, through custom-code and metadata analysis
- avoid inconclusive protobuf-candidate noise for fully inspected scalar-only text and Keras-owned JSON members while preserving binary-tailed candidates for analysis
- preserve archive member incomplete-outcome reasons when nested tentative analysis also fails closed
- route renamed TensorFlow SavedModel and MetaGraph protobufs through unsafe-operation analysis
- route renamed ONNX protobuf models with prefixed unknown fields through content analysis and fail closed on unresolved or incomplete structure
- preserve ambiguous budget-exhausted protobuf candidates for tentative analysis without misclassifying non-ONNX payloads
- classify unavailable ZIP traversal, member, manifest-less TorchServe handler, and Keras artifact scan coverage as inconclusive while preserving archive-depth security findings
- classify unavailable TAR traversal and member scan coverage as inconclusive while preserving depth-limit security findings
- classify unavailable Skops member and schema coverage as inconclusive rather than security findings
- preserve Skops nested Python-member detection for high-risk calls reached through `__getattribute__`
- classify bounded, unreadable, or unparseable TorchServe MAR analysis gaps as inconclusive rather than security findings
- detect manifest-declared TorchServe extra files and PyTorch ZIP members disguised with executable content
- classify incomplete SevenZip coverage as inconclusive and avoid caching temporary extracted members
- classify uninspected OCI layers and members as inconclusive analysis instead of security findings, without caching extracted temporary members
- route renamed ONNX protobuf models with prefixed unknown fields through content analysis and fail closed on unresolved or incomplete structure
- mark compressed-wrapper partial-analysis outcomes explicitly inconclusive
- retain oversized renamed SafeTensors candidates for bounded fail-closed analysis
- route renamed TensorFlow SavedModel and MetaGraph protobufs through unsafe-operation analysis
- detect and scan signature-valid CNTK and LightGBM payloads even when renamed with misleading suffixes
- mark CNTK read failures and string-extraction limits as inconclusive analysis while retaining strict CNTK ownership and fail-closed ambiguous Flax overlap coverage
- detect and scan signature-valid RKNN, TFLite, and ExecuTorch payloads under non-conflicting renamed suffixes while preserving owned routes, and classify unavailable ExecuTorch reads as inconclusive
- mark CatBoost text-fragment extraction limits and unavailable reads as inconclusive analysis
- mark RKNN and Torch7 string-extraction limits and unavailable reads as inconclusive analysis
- classify unavailable TFLite parsing coverage as inconclusive rather than a security finding
- classify unavailable MXNet artifact reads as inconclusive rather than security findings
- detect dangerous OpenVINO layers inside namespace-qualified IR models
- classify unavailable pickle reads and stream coverage as inconclusive rather than security findings
- route renamed structurally valid MXNet symbol graphs through existing suspicious-reference analysis
- harden renamed MXNet symbol routing with fail-closed bounded ambiguity and XGBoost overlap handling
- restore content routing for extensionless XGBoost UBJSON models and classify unavailable or undecodable XGBoost reads as inconclusive
- detect NeMo Hydra targets that invoke PyTorch C++ extension loaders
- route renamed TAR-backed NeMo archives with relative archive-root model configs through Hydra `_target_` analysis while retaining generic embedded-member checks
- avoid reporting non-extractable forward-hardlinked NeMo config or checkpoint aliases as executable findings
- honor descriptor-owned header aliases during helper scanner selection for renamed HDF5, GGML, and compressed payloads
- detect signature-valid Torch7 payloads even when renamed with misleading suffixes
- detect acquired executable Llamafile payloads with misleading suffixes, retain archive-polyglot coverage, and classify unavailable runtime previews as inconclusive
- preserve Torch7 Lua findings in executable Llamafile/Torch7 polyglot payloads

### Performance Improvements

- reuse source-validated pickle call-graph analysis across multiple directory dispatches when supported by installed picklescan

## [0.2.45](https://github.com/promptfoo/modelaudit/compare/v0.2.44...v0.2.45) (2026-05-03)

### Bug Fixes

- remove checked-in benchmark files ([#1220](https://github.com/promptfoo/modelaudit/issues/1220)) ([1e258e4](https://github.com/promptfoo/modelaudit/commit/1e258e48f43522853ba167463a5fae8d5533612a))

## [0.2.44](https://github.com/promptfoo/modelaudit/compare/v0.2.43...v0.2.44) (2026-05-03)

### Bug Fixes

- address ai quality findings ([#1218](https://github.com/promptfoo/modelaudit/issues/1218)) ([30f4ef2](https://github.com/promptfoo/modelaudit/commit/30f4ef246f7e26a4c6f85e684bfb35ceaea7c43d))
- clear remaining security-quality findings ([#1219](https://github.com/promptfoo/modelaudit/issues/1219)) ([259f931](https://github.com/promptfoo/modelaudit/commit/259f931fa573e234734b7d72850e0ca09d775f45))

### Performance Improvements

- add opt-in core phase timings ([#1170](https://github.com/promptfoo/modelaudit/issues/1170)) ([75a7f0b](https://github.com/promptfoo/modelaudit/commit/75a7f0b4480f6e4305617a729fa9635b15432fe3))
- bound directory progress pre-counts ([#1174](https://github.com/promptfoo/modelaudit/issues/1174)) ([23dc5d0](https://github.com/promptfoo/modelaudit/commit/23dc5d009a9cf14060ee046fe74ef1af02de2e7d))
- bound ordinary license header reads ([#1197](https://github.com/promptfoo/modelaudit/issues/1197)) ([113ad34](https://github.com/promptfoo/modelaudit/commit/113ad3402d82aa1815239a4e3cbe93a862619cdc))
- cache call graph call nodes ([#1215](https://github.com/promptfoo/modelaudit/issues/1215)) ([aa52759](https://github.com/promptfoo/modelaudit/commit/aa52759aabaac335b87e30e2cbf042d141dc4e9f))
- cache function import aliases ([#1214](https://github.com/promptfoo/modelaudit/issues/1214)) ([d56eef2](https://github.com/promptfoo/modelaudit/commit/d56eef2de18652fee1a759642165e404b8202be9))
- cache manifest trusted-url lookups ([#1186](https://github.com/promptfoo/modelaudit/issues/1186)) ([09e76cf](https://github.com/promptfoo/modelaudit/commit/09e76cf9a793572e961aefbbc827aeaeab351e64))
- cache parameter controlled names ([#1213](https://github.com/promptfoo/modelaudit/issues/1213)) ([41b8f45](https://github.com/promptfoo/modelaudit/commit/41b8f4541c9b62204c74c04199931ef0484ba1a5))
- cache scanner selection policies ([#1177](https://github.com/promptfoo/modelaudit/issues/1177)) ([371f480](https://github.com/promptfoo/modelaudit/commit/371f48024153dcd93f5df327781348b4076ddfd4))
- cache split call graph names ([#1212](https://github.com/promptfoo/modelaudit/issues/1212)) ([77ab177](https://github.com/promptfoo/modelaudit/commit/77ab17782f23de46c57f6e2a7302a539fb0bfb98))
- dedupe repeated metadata urls ([#1166](https://github.com/promptfoo/modelaudit/issues/1166)) ([b3f1009](https://github.com/promptfoo/modelaudit/commit/b3f1009d8e75912117df1279da6230b80e6e61cc))
- reuse cache key content hash on store ([#1171](https://github.com/promptfoo/modelaudit/issues/1171)) ([e3981bd](https://github.com/promptfoo/modelaudit/commit/e3981bd21ddd912d893e306f354d49eb6b4e06e1))
- reuse call graph controlled names ([#1198](https://github.com/promptfoo/modelaudit/issues/1198)) ([84e6a9b](https://github.com/promptfoo/modelaudit/commit/84e6a9bd841095917e2199e9004759bcbe9c0eb3))
- reuse call graph module parses ([#1167](https://github.com/promptfoo/modelaudit/issues/1167)) ([0822b40](https://github.com/promptfoo/modelaudit/commit/0822b4043db270882b8fd14ff04de1cf3d3fb134))
- reuse compiled pmml extension patterns ([#1172](https://github.com/promptfoo/modelaudit/issues/1172)) ([51ddc85](https://github.com/promptfoo/modelaudit/commit/51ddc8510bf1fa696bf38f2f54b29885c267ca2a))
- reuse default secret regexes ([#1185](https://github.com/promptfoo/modelaudit/issues/1185)) ([b5ba149](https://github.com/promptfoo/modelaudit/commit/b5ba149f0667be7f7d86fe11f3647dac5ea3a620))
- reuse flax layer keyword text ([#1187](https://github.com/promptfoo/modelaudit/issues/1187)) ([b50947f](https://github.com/promptfoo/modelaudit/commit/b50947fefde1140693856011b221ff540d83b100))
- reuse flax structure analysis ([#1188](https://github.com/promptfoo/modelaudit/issues/1188)) ([c33c566](https://github.com/promptfoo/modelaudit/commit/c33c566cdb37ca480d593bbd474cb6f3dbd727b2))
- reuse flax suspicious patterns ([#1194](https://github.com/promptfoo/modelaudit/issues/1194)) ([0351de1](https://github.com/promptfoo/modelaudit/commit/0351de1b3419353a60bdc6510772ddb6b8b55d47))
- reuse hashes for hardlinked files ([#1175](https://github.com/promptfoo/modelaudit/issues/1175)) ([aac4367](https://github.com/promptfoo/modelaudit/commit/aac4367ef610e77c33bed9181821d83d4ccf1e4b))
- reuse jax probe file handle ([#1161](https://github.com/promptfoo/modelaudit/issues/1161)) ([3e95649](https://github.com/promptfoo/modelaudit/commit/3e956493a476156b71fd06142190d49eb95b8bac))
- reuse jinja scanner patterns ([#1184](https://github.com/promptfoo/modelaudit/issues/1184)) ([bb5a729](https://github.com/promptfoo/modelaudit/commit/bb5a729364aff328996d2868799b3ce394193df5))
- reuse jit import regexes ([#1190](https://github.com/promptfoo/modelaudit/issues/1190)) ([9f37f5d](https://github.com/promptfoo/modelaudit/commit/9f37f5d35317d9273388e24e72af4a6a2fd4c001))
- reuse lowered blacklist payload ([#1165](https://github.com/promptfoo/modelaudit/issues/1165)) ([624a17b](https://github.com/promptfoo/modelaudit/commit/624a17b2ede0e84062120987ed2b8919bedd822d))
- reuse lowered c2 payload scan ([#1163](https://github.com/promptfoo/modelaudit/issues/1163)) ([a63efaa](https://github.com/promptfoo/modelaudit/commit/a63efaaa44c257c6428ec64ac337657f8d948d9a))
- reuse lowered flax transform values ([#1169](https://github.com/promptfoo/modelaudit/issues/1169)) ([3d73ad7](https://github.com/promptfoo/modelaudit/commit/3d73ad719e540697d64636354f1ff23d4b2a8837))
- reuse lowered get_file values ([#1211](https://github.com/promptfoo/modelaudit/issues/1211)) ([3bc7890](https://github.com/promptfoo/modelaudit/commit/3bc7890339f9373e73e2979e48ef010c190c6028))
- reuse lowered hex token seed checks ([#1202](https://github.com/promptfoo/modelaudit/issues/1202)) ([8a34db9](https://github.com/promptfoo/modelaudit/commit/8a34db967e25d5b0a78479f71e53f85486f4c557))
- reuse lowered jax context text ([#1164](https://github.com/promptfoo/modelaudit/issues/1164)) ([d012c09](https://github.com/promptfoo/modelaudit/commit/d012c09ebb8a73b75360e8132d8a1434b37342ce))
- reuse lowered keras metadata text ([#1168](https://github.com/promptfoo/modelaudit/issues/1168)) ([abfe87b](https://github.com/promptfoo/modelaudit/commit/abfe87b3e4ac15aaf3d0721c9a9751a16fa10e6f))
- reuse lowered layer type names ([#1203](https://github.com/promptfoo/modelaudit/issues/1203)) ([4b94a67](https://github.com/promptfoo/modelaudit/commit/4b94a67f2b5142332b49da29fdb1e8ad2106cf03))
- reuse lowered license header text ([#1162](https://github.com/promptfoo/modelaudit/issues/1162)) ([447ea66](https://github.com/promptfoo/modelaudit/commit/447ea664889624da254d7de4c9c4219fe286e9e7))
- reuse lowered metadata filenames ([#1205](https://github.com/promptfoo/modelaudit/issues/1205)) ([4251df5](https://github.com/promptfoo/modelaudit/commit/4251df584cb5c3491492c643f211e07f3234fd68))
- reuse lowered metadata keys ([#1206](https://github.com/promptfoo/modelaudit/issues/1206)) ([3ea11f0](https://github.com/promptfoo/modelaudit/commit/3ea11f0d671902a95458cd143f3061b63db4f588))
- reuse lowered ml operation names ([#1201](https://github.com/promptfoo/modelaudit/issues/1201)) ([c5de398](https://github.com/promptfoo/modelaudit/commit/c5de398c1c1cb4809edd6bcab25740dc23eda1b8))
- reuse lowered sarif messages ([#1209](https://github.com/promptfoo/modelaudit/issues/1209)) ([fde43a4](https://github.com/promptfoo/modelaudit/commit/fde43a4a267de63530bd7716fcf6b851c6b74e78))
- reuse lowered secret descriptions ([#1208](https://github.com/promptfoo/modelaudit/issues/1208)) ([cb0324b](https://github.com/promptfoo/modelaudit/commit/cb0324b6ffd4444a974895a0dee7d209b0e4b571))
- reuse lowered skops member names ([#1207](https://github.com/promptfoo/modelaudit/issues/1207)) ([879c531](https://github.com/promptfoo/modelaudit/commit/879c5310f3f7f39b96bb280e9cc772647e1ea749))
- reuse lowered xgboost legacy headers ([#1204](https://github.com/promptfoo/modelaudit/issues/1204)) ([8bc1e7d](https://github.com/promptfoo/modelaudit/commit/8bc1e7d45ee89d62d51503c8e549114fa3df197e))
- reuse manifest text within scans ([#1160](https://github.com/promptfoo/modelaudit/issues/1160)) ([848bc1e](https://github.com/promptfoo/modelaudit/commit/848bc1ec65b428d0fe47adf117d848519e05f2be))
- reuse metagraph attr lowercase values ([#1200](https://github.com/promptfoo/modelaudit/issues/1200)) ([349751e](https://github.com/promptfoo/modelaudit/commit/349751e228f601c30bfbe61d386621db14aefb31))
- reuse nearby license discovery ([#1155](https://github.com/promptfoo/modelaudit/issues/1155)) ([301618d](https://github.com/promptfoo/modelaudit/commit/301618da66a41514e6e210d4ba8298cf816da81d))
- reuse network library patterns ([#1191](https://github.com/promptfoo/modelaudit/issues/1191)) ([630bd3d](https://github.com/promptfoo/modelaudit/commit/630bd3d35eff43c980a3bb9d0f75ad6cb548b42c))
- reuse normalized scanner selection policy ([#1153](https://github.com/promptfoo/modelaudit/issues/1153)) ([b8430a0](https://github.com/promptfoo/modelaudit/commit/b8430a04b141972febab6b03e744e1382c14aacb))
- reuse onnx model bytes for parsing ([#1193](https://github.com/promptfoo/modelaudit/issues/1193)) ([a5356a5](https://github.com/promptfoo/modelaudit/commit/a5356a5109a09f04db6efa764cb47088b7a5b1aa))
- reuse prefiltered sarif issues ([#1210](https://github.com/promptfoo/modelaudit/issues/1210)) ([d996043](https://github.com/promptfoo/modelaudit/commit/d9960432a37982595109d2c20ca34cbb7e2807cf))
- reuse savedmodel function patterns ([#1183](https://github.com/promptfoo/modelaudit/issues/1183)) ([c043bcd](https://github.com/promptfoo/modelaudit/commit/c043bcd0c9509f0704406e3cbf67a374f898d73e))
- reuse secrets detector heuristics ([#1189](https://github.com/promptfoo/modelaudit/issues/1189)) ([799e8bf](https://github.com/promptfoo/modelaudit/commit/799e8bf6c62c336cd64083309d2f615426041863))
- reuse sibling license directory listings ([#1157](https://github.com/promptfoo/modelaudit/issues/1157)) ([5ec7f21](https://github.com/promptfoo/modelaudit/commit/5ec7f21ab0b16eaf23c654688eab4219c091fc86))
- reuse suspicious port names ([#1192](https://github.com/promptfoo/modelaudit/issues/1192)) ([8ed7665](https://github.com/promptfoo/modelaudit/commit/8ed76651cc386ef4ad1ffbdd9f1b280ee951f1cc))
- share call graph caches within reports ([#1156](https://github.com/promptfoo/modelaudit/issues/1156)) ([b16d37c](https://github.com/promptfoo/modelaudit/commit/b16d37c3b4439b4e6d966b8b9624642307c2a322))
- share getattr assignment candidates ([#1199](https://github.com/promptfoo/modelaudit/issues/1199)) ([5d12903](https://github.com/promptfoo/modelaudit/commit/5d1290330328ad4fb6e6f88bddc34e7bfba9d310))
- short-circuit hf bookkeeping checks ([#1154](https://github.com/promptfoo/modelaudit/issues/1154)) ([ed0122d](https://github.com/promptfoo/modelaudit/commit/ed0122d57bb875beab88a92dbb670c7d06ec881b))
- skip call graph enrichment in pickle validation ([#1196](https://github.com/promptfoo/modelaudit/issues/1196)) ([2347d80](https://github.com/promptfoo/modelaudit/commit/2347d80a2d110f582c188679b4a0c04489779745))
- skip directory pre-count without progress ([#1173](https://github.com/promptfoo/modelaudit/issues/1173)) ([83c8bb4](https://github.com/promptfoo/modelaudit/commit/83c8bb42a53180d09d707bad6cd90d06d3ab55ee))
- skip redundant jax scans for plain pickles ([#1158](https://github.com/promptfoo/modelaudit/issues/1158)) ([04c6974](https://github.com/promptfoo/modelaudit/commit/04c6974283a02ddb5233a498ccfd0306261ab6ab))
- skip renormalizing scanner selection ([#1181](https://github.com/promptfoo/modelaudit/issues/1181)) ([74ac7a7](https://github.com/promptfoo/modelaudit/commit/74ac7a7fef31028582c201690610076214c2d544))
- summarize CLI progress tree once ([#1182](https://github.com/promptfoo/modelaudit/issues/1182)) ([0bc373f](https://github.com/promptfoo/modelaudit/commit/0bc373fc8a3d1694fa35a18f7789d195f2cacd79))

### Documentation

- add performance audit backlog ([#1159](https://github.com/promptfoo/modelaudit/issues/1159)) ([be6cc4a](https://github.com/promptfoo/modelaudit/commit/be6cc4a43facb6212c6f591779c5faddc111a280))

## [0.2.43](https://github.com/promptfoo/modelaudit/compare/v0.2.42...v0.2.43) (2026-05-01)

### Bug Fixes

- align manifest scanner routing ([#1111](https://github.com/promptfoo/modelaudit/issues/1111)) ([ad7f253](https://github.com/promptfoo/modelaudit/commit/ad7f2534ad3e9f5ec744aadbf2448e02bdaa092f))
- analyze jax-like pickle checkpoints ([#1114](https://github.com/promptfoo/modelaudit/issues/1114)) ([576ac54](https://github.com/promptfoo/modelaudit/commit/576ac540822e620204ea7d654848bcca9376b44f))
- avoid inert skops cve false positives ([7538e58](https://github.com/promptfoo/modelaudit/commit/7538e58fc6ba7c3f9f7721a6c686035f6502c1e6))
- avoid PMML system substring false positives ([#1125](https://github.com/promptfoo/modelaudit/issues/1125)) ([20fdd0c](https://github.com/promptfoo/modelaudit/commit/20fdd0c7ef498099e439306e323093920fd752c7))
- catch suspicious nemo target leaves ([#1116](https://github.com/promptfoo/modelaudit/issues/1116)) ([b8dccfa](https://github.com/promptfoo/modelaudit/commit/b8dccfa1b2aca25c277c35616ee1b01c87953e6f))
- close pytorch zip coverage gaps ([#1095](https://github.com/promptfoo/modelaudit/issues/1095)) ([a1ca298](https://github.com/promptfoo/modelaudit/commit/a1ca298b7d217989286b9bc0e3ef6545871f9b53))
- correct analysis suspiciousness ([#1101](https://github.com/promptfoo/modelaudit/issues/1101)) ([11b1d3e](https://github.com/promptfoo/modelaudit/commit/11b1d3e3ce7ace309f3864c599c7f70b6479c5cb))
- cover eager statistics consumers in picklescan ([#1148](https://github.com/promptfoo/modelaudit/issues/1148)) ([0d5ea8e](https://github.com/promptfoo/modelaudit/commit/0d5ea8e5a0be4f96d3ca97c55640cdb35b55215c))
- detect bare torch7 require loads ([#1117](https://github.com/promptfoo/modelaudit/issues/1117)) ([7c77be0](https://github.com/promptfoo/modelaudit/commit/7c77be01de8783e852815e58811f592455b3b6c4))
- detect extensionless archive executables ([#1110](https://github.com/promptfoo/modelaudit/issues/1110)) ([b64a2da](https://github.com/promptfoo/modelaudit/commit/b64a2da696f9a922e826c39d64c37894ce393582))
- detect nested brace-format mapping lookups ([#1151](https://github.com/promptfoo/modelaudit/issues/1151)) ([fc296ad](https://github.com/promptfoo/modelaudit/commit/fc296adaa97815b4067f0a764e653cdf777a5724))
- detect Paddle patterns across chunk boundaries ([#1120](https://github.com/promptfoo/modelaudit/issues/1120)) ([d4fedf9](https://github.com/promptfoo/modelaudit/commit/d4fedf9e9b1492cec291dedb1ff53fe420d13bb7))
- fail closed on bounded scanner analysis ([#1099](https://github.com/promptfoo/modelaudit/issues/1099)) ([60973e4](https://github.com/promptfoo/modelaudit/commit/60973e4eb48928c120d62ed651b1abb95c210134))
- fail closed on call graph errors ([#1143](https://github.com/promptfoo/modelaudit/issues/1143)) ([1a08449](https://github.com/promptfoo/modelaudit/commit/1a084493b16b5c62b0cd7022b79e60795e88b07b))
- fail closed on directory size limits ([#1093](https://github.com/promptfoo/modelaudit/issues/1093)) ([47054d7](https://github.com/promptfoo/modelaudit/commit/47054d7fe808cfb3ee676d1da533c244170946bf))
- fail closed on header-only streaming scans ([#1103](https://github.com/promptfoo/modelaudit/issues/1103)) ([7b934c0](https://github.com/promptfoo/modelaudit/commit/7b934c02004850b5ca2428fe2871acb3e413062a))
- fail closed on incomplete mar scans ([#1096](https://github.com/promptfoo/modelaudit/issues/1096)) ([af31235](https://github.com/promptfoo/modelaudit/commit/af312351a7b2069214d4938cb9c8e051e25ae8f3))
- fail closed on limited llamafile payload scans ([ceb3f22](https://github.com/promptfoo/modelaudit/commit/ceb3f22870f5555e809dbf19d7ce37e4d2488b5a))
- fail closed on malformed XGBoost JSON ([#1123](https://github.com/promptfoo/modelaudit/issues/1123)) ([4d4ba28](https://github.com/promptfoo/modelaudit/commit/4d4ba285e60a3abfb64f0259c792c52dcb66794d))
- fail closed on nemo archives without config ([#1115](https://github.com/promptfoo/modelaudit/issues/1115)) ([a09f763](https://github.com/promptfoo/modelaudit/commit/a09f76308e1e5e3db7d20298e1ed508806d9cbbd))
- fail closed on ONNX raw detector failures ([#1119](https://github.com/promptfoo/modelaudit/issues/1119)) ([2963764](https://github.com/promptfoo/modelaudit/commit/2963764e28c4fb94cdfdef6a975e630c4ab4dd2f))
- fail closed on truncated tensor metadata ([b267328](https://github.com/promptfoo/modelaudit/commit/b267328ca6952ade157a82de00ddc3ca541619f0))
- fail closed on unanalyzable call graphs ([#1108](https://github.com/promptfoo/modelaudit/issues/1108)) ([dcb8bbe](https://github.com/promptfoo/modelaudit/commit/dcb8bbe4683c284a1ea6c84231dee6808a93fc52))
- fail closed when recognized scanners are unavailable ([#1104](https://github.com/promptfoo/modelaudit/issues/1104)) ([f4866d4](https://github.com/promptfoo/modelaudit/commit/f4866d424c5fe2112c681f7984a2c59d9fe5b794))
- fail closed without yaml parser ([99ef15a](https://github.com/promptfoo/modelaudit/commit/99ef15a35cea50257ca31629da3e51f50d369f75))
- harden detector heuristics ([#1100](https://github.com/promptfoo/modelaudit/issues/1100)) ([bf57b3b](https://github.com/promptfoo/modelaudit/commit/bf57b3b20ab43d1fdf764a503a7bd9fe19c7cd11))
- ignore inert format placeholders ([#1142](https://github.com/promptfoo/modelaudit/issues/1142)) ([8f728e8](https://github.com/promptfoo/modelaudit/commit/8f728e8454578ba34ce5b28389258fa2eba29fe8))
- ignore inert XGBoost feature labels ([f637e1e](https://github.com/promptfoo/modelaudit/commit/f637e1ebc024913af14f4a3eff01ee4600459b5d))
- inspect savedmodel root siblings ([#1118](https://github.com/promptfoo/modelaudit/issues/1118)) ([cf6bf8f](https://github.com/promptfoo/modelaudit/commit/cf6bf8f83499910bf179361d1015c161ee8dafff))
- keep inert dotted global metadata clean ([#1150](https://github.com/promptfoo/modelaudit/issues/1150)) ([9a76915](https://github.com/promptfoo/modelaudit/commit/9a769151c0ffd29a1638f1dacc78d2eb77b0f268))
- **picklescan:** detect hidden-only pytorch zips ([#1098](https://github.com/promptfoo/modelaudit/issues/1098)) ([3e94f70](https://github.com/promptfoo/modelaudit/commit/3e94f7020d5a28fc150afed1520adcac8d58ce73))
- **picklescan:** detect statistics quantiles iterator consumption ([#1152](https://github.com/promptfoo/modelaudit/issues/1152)) ([b357fdb](https://github.com/promptfoo/modelaudit/commit/b357fdb7db320d3485cf0458a4cf0f16b86717c1))
- **picklescan:** fail closed on late encoded payload probes ([#1107](https://github.com/promptfoo/modelaudit/issues/1107)) ([55b43a5](https://github.com/promptfoo/modelaudit/commit/55b43a5229baadf1c3673b4d89838e55c5cf6ae3))
- **picklescan:** model str.format lookups ([#1097](https://github.com/promptfoo/modelaudit/issues/1097)) ([2c87acb](https://github.com/promptfoo/modelaudit/commit/2c87acbb01285289872203063074baf51d0cd28c))
- preserve exact entropy literals ([#1138](https://github.com/promptfoo/modelaudit/issues/1138)) ([95ba57c](https://github.com/promptfoo/modelaudit/commit/95ba57cad1d9bb346c2752942b8e054d8dfa66ff))
- preserve hidden model payloads ([#1091](https://github.com/promptfoo/modelaudit/issues/1091)) ([5b11f91](https://github.com/promptfoo/modelaudit/commit/5b11f91942c1e5943e74affa3fbf86244f63f9cc))
- preserve incomplete office zip scans ([#1094](https://github.com/promptfoo/modelaudit/issues/1094)) ([9ed81db](https://github.com/promptfoo/modelaudit/commit/9ed81db90ce60e4128f8e95a0ae50f5f5a75d214))
- preserve merged scan failures ([#1092](https://github.com/promptfoo/modelaudit/issues/1092)) ([e7fecc5](https://github.com/promptfoo/modelaudit/commit/e7fecc5e674a404164e352f07d5bca381e1862f0))
- preserve path-sensitive directory scans ([#1102](https://github.com/promptfoo/modelaudit/issues/1102)) ([ddebc52](https://github.com/promptfoo/modelaudit/commit/ddebc52095773f651b64944412180e2ee5e76762))
- preserve str.format lookup keys in picklescan ([#1149](https://github.com/promptfoo/modelaudit/issues/1149)) ([feb3e1c](https://github.com/promptfoo/modelaudit/commit/feb3e1ccb629344180e3a27e093e24b707c671e6))
- reject ajax as a JAX checkpoint hint ([#1124](https://github.com/promptfoo/modelaudit/issues/1124)) ([9f51b2c](https://github.com/promptfoo/modelaudit/commit/9f51b2c8e154d94b3361dfb0b07ba6bdd37aedd1))
- reject marker-only XGBoost binaries ([#1122](https://github.com/promptfoo/modelaudit/issues/1122)) ([30ec930](https://github.com/promptfoo/modelaudit/commit/30ec9308a50f445ddd2f55624fe0b294dc2e92cd))
- remove filename-based framework skips ([#1137](https://github.com/promptfoo/modelaudit/issues/1137)) ([7a18b49](https://github.com/promptfoo/modelaudit/commit/7a18b49f434ddc091cb26672323dad6dab42dab7))
- require startup hook invocations ([#1140](https://github.com/promptfoo/modelaudit/issues/1140)) ([7e0777d](https://github.com/promptfoo/modelaudit/commit/7e0777dcc71bfdbd8212358aa548ee45d3808642))
- require strict zip signatures ([93f60af](https://github.com/promptfoo/modelaudit/commit/93f60afe5765047752f2c97fc10f160939a66c62))
- resolve concatenated archive getattr names ([#1105](https://github.com/promptfoo/modelaudit/issues/1105)) ([59a7df6](https://github.com/promptfoo/modelaudit/commit/59a7df6464fda09f79bbd5fa44754402764e89b7))
- resync post-budget pickle replay ([#1141](https://github.com/promptfoo/modelaudit/issues/1141)) ([e275676](https://github.com/promptfoo/modelaudit/commit/e27567661295a96d94cd1ea29abd4f42c6c249e3))
- route extensionless scanners ([18accbd](https://github.com/promptfoo/modelaudit/commit/18accbdaf6808bd6316d742c84a1f92dce63984a))
- route flax suffixes without msgpack ([dca6056](https://github.com/promptfoo/modelaudit/commit/dca605662e2dbf3209b4d69e61fb9f1306599b7d))
- route middle-marker llamafiles ([f11792c](https://github.com/promptfoo/modelaudit/commit/f11792ca6c4e3237d731d54c47ce44b00a3c7d4b))
- route renamed XML models after long prologs ([#1109](https://github.com/promptfoo/modelaudit/issues/1109)) ([e2f9962](https://github.com/promptfoo/modelaudit/commit/e2f9962a887762ad49854ec1ee750c7df20b6a7c))
- scan concatenated compressed members ([#1135](https://github.com/promptfoo/modelaudit/issues/1135)) ([3f9a51a](https://github.com/promptfoo/modelaudit/commit/3f9a51a37b92bc6e48dedb5aa97e3aeb32d64a0d))
- scan embedded manifest chat templates ([#1112](https://github.com/promptfoo/modelaudit/issues/1112)) ([18433a8](https://github.com/promptfoo/modelaudit/commit/18433a83966229642555fa8886e3e55a8b3e15bb))
- scan gguf chat templates with jinja analysis ([#1113](https://github.com/promptfoo/modelaudit/issues/1113)) ([35b420a](https://github.com/promptfoo/modelaudit/commit/35b420ac908bd29cecc6e82b85e1af88056b9551))
- scan unmarked python jit blobs ([#1136](https://github.com/promptfoo/modelaudit/issues/1136)) ([681ce62](https://github.com/promptfoo/modelaudit/commit/681ce62487f0f41a9c2af7e8f7b50be65b16f901))
- scope huggingface bookkeeping skips ([#1090](https://github.com/promptfoo/modelaudit/issues/1090)) ([87f7204](https://github.com/promptfoo/modelaudit/commit/87f7204bedc8a6ff94472b5831abd52a25836dcd))
- stabilize non-pytorch zip status ([7449aae](https://github.com/promptfoo/modelaudit/commit/7449aae0e36a38de7681acfd0f5f77033afea059))
- validate all XGBoost trees ([#1121](https://github.com/promptfoo/modelaudit/issues/1121)) ([a38eab2](https://github.com/promptfoo/modelaudit/commit/a38eab225b3671e8df20621455fca775ff5ee96a))

### Documentation

- narrow scan coverage claims ([#1139](https://github.com/promptfoo/modelaudit/issues/1139)) ([47ec8cf](https://github.com/promptfoo/modelaudit/commit/47ec8cf3bc5a5ac3166757bbaae0c5a3c6adb73d))

## [Unreleased]

### Bug Fixes

- detect nested brace-format lookups that reach tracked `defaultdict` factories
- avoid `str.format` picklescan false positives when a `ChainMap` shadows a `defaultdict`
- block `statistics.quantiles` call-iterator consumption in picklescan call-graph analysis
- block additional eager `statistics` consumers in picklescan call-graph analysis
- avoid picklescan false positives for inert metadata under dangerous dotted globals
- preserve path-sensitive scan results while hashing duplicate directory contents
- correct analysis suspiciousness scoring and alias-aware semantic risk handling
- harden detector heuristics against comment padding, byte-backed credentials, unmarked Python blobs, and spoofed network context
- fail closed when bounded scanner windows leave relevant model content uninspected
- fail closed when TorchServe MAR limits leave manifest-referenced payloads unscanned
- recurse into nested ZIP members inside PyTorch archives and fail closed when compression-ratio guards leave members unscanned
- preserve large Office-like ZIPs when prefilter inspection is incomplete
- fail closed when directory scans stop at the total-size budget
- restrict Hugging Face bookkeeping filename skips to recognized cache layouts
- preserve unsuccessful child results after scan-result merges
- preserve supported payloads hidden behind default directory-skip names
- use bounded raw Jinja fallback windows and fail closed when PyYAML is
  unavailable for YAML template configs
- let extensionless file scanners participate in local file selection so
  supported extensionless Llamafiles do not fall through to clean unknown
  results
- fail closed when PyTorch ZIP tensor-metadata validation can only inspect a
  bounded pickle prefix or cannot complete member analysis
- preserve and scan concatenated compressed-wrapper member boundaries so a
  benign first member cannot hide later malicious payloads

## [0.2.42](https://github.com/promptfoo/modelaudit/compare/v0.2.41...v0.2.42) (2026-04-27)

### Bug Fixes

- require latest picklescan release ([a0237a7](https://github.com/promptfoo/modelaudit/commit/a0237a7658c0885848eea8d51b792ccfad45cc1c))

## [0.2.41](https://github.com/promptfoo/modelaudit/compare/v0.2.40...v0.2.41) (2026-04-27)

### Bug Fixes

- **ci:** skip POSIX proof cases on Windows ([#1072](https://github.com/promptfoo/modelaudit/issues/1072)) ([bfa17a3](https://github.com/promptfoo/modelaudit/commit/bfa17a3e152cd178c5d1fdbfec55dd3f124778ef))
- **docker:** add apt-get clean and pinned pip constraints to Dockerfile.tensorflow ([#1079](https://github.com/promptfoo/modelaudit/issues/1079)) ([8d9f9b7](https://github.com/promptfoo/modelaudit/commit/8d9f9b7c628ae05cdccf5d8eb480eea89f551e8d))
- harden picklescan call graph RCE detection ([#1061](https://github.com/promptfoo/modelaudit/issues/1061)) ([19c4fc4](https://github.com/promptfoo/modelaudit/commit/19c4fc487b4758462ac2107a3f3e59463e5d888b))
- harden picklescan stdlib callable detection ([f0f57b4](https://github.com/promptfoo/modelaudit/commit/f0f57b47f3355bea008a48779dbd856e6f550ec7))
- improve test isolation, reduce duplication, and fix command injection risk in test suite ([#1078](https://github.com/promptfoo/modelaudit/issues/1078)) ([3867c83](https://github.com/promptfoo/modelaudit/commit/3867c83b2dd0d5ab6a83b650c28d64122a675dea))
- **picklescan:** avoid call-graph false positives for PyTorch storage IDs ([#1069](https://github.com/promptfoo/modelaudit/issues/1069)) ([e75ed24](https://github.com/promptfoo/modelaudit/commit/e75ed249948558864d8f56882a02f1327323205d))
- silence stale CodeQL generated import alerts ([#1080](https://github.com/promptfoo/modelaudit/issues/1080)) ([9530740](https://github.com/promptfoo/modelaudit/commit/9530740312725d051a41f7f2a405280ee2be4c62))
- **telemetry:** stabilize modelaudit identity ([#1071](https://github.com/promptfoo/modelaudit/issues/1071)) ([592a656](https://github.com/promptfoo/modelaudit/commit/592a65672ac58e0b89eb50a54614e736b60c6741))

### Documentation

- improve PyPI READMEs ([#1057](https://github.com/promptfoo/modelaudit/issues/1057)) ([1cfb27d](https://github.com/promptfoo/modelaudit/commit/1cfb27de814125470d1e1a38eec03a83d79ff3d9))

## [0.2.40](https://github.com/promptfoo/modelaudit/compare/v0.2.39...v0.2.40) (2026-04-17)

### Bug Fixes

- add manual release recovery path ([aeea2da](https://github.com/promptfoo/modelaudit/commit/aeea2da68099f42a2fae68a50fff9e64e5e2f86f))
- avoid duplicate manylinux compatibility tag ([412677f](https://github.com/promptfoo/modelaudit/commit/412677f00e6a24b3471d9f14a36ef2b9405e5067))
- persist manylinux picklescan artifacts ([346bb3f](https://github.com/promptfoo/modelaudit/commit/346bb3f048b646c69573812a08ffd23342843658))

## [0.2.39](https://github.com/promptfoo/modelaudit/compare/v0.2.38...v0.2.39) (2026-04-17)

### Bug Fixes

- repair picklescan release wheel jobs ([#1051](https://github.com/promptfoo/modelaudit/issues/1051)) ([6c23190](https://github.com/promptfoo/modelaudit/commit/6c23190f9b23686d33d5da0a8b5522a59490084e))

## [0.2.38](https://github.com/promptfoo/modelaudit/compare/v0.2.37...v0.2.38) (2026-04-17)

### Features

- add scanner selection controls ([83334ca](https://github.com/promptfoo/modelaudit/commit/83334cacc53e5ab194bf46ced64cc775a7b9d18c)), closes [#7520](https://github.com/promptfoo/modelaudit/issues/7520)

### Bug Fixes

- address code quality findings ([#1038](https://github.com/promptfoo/modelaudit/issues/1038)) ([7af03cf](https://github.com/promptfoo/modelaudit/commit/7af03cf42f33f1b255eb9f9cbcaac6caccd48bc1))
- avoid per-call rule mapper closures ([fa0dc70](https://github.com/promptfoo/modelaudit/commit/fa0dc70ef2e1ca133a2eca9409c8b5ce86977caa))
- bound pytorch zip jit reads ([#1048](https://github.com/promptfoo/modelaudit/issues/1048)) ([f920d76](https://github.com/promptfoo/modelaudit/commit/f920d76563745d484895872b1724eb4b98856168))
- define analysis lazy exports ([8aeeadd](https://github.com/promptfoo/modelaudit/commit/8aeeadd8ffd4943b8c6007c58d9bef3f44eeba09))
- **deps:** update rust crate pyo3 to 0.28.0 ([#1006](https://github.com/promptfoo/modelaudit/issues/1006)) ([fe93b47](https://github.com/promptfoo/modelaudit/commit/fe93b47c839588b3f33cfd21f4380306ec418f2a))
- detect hidden pytorch zip pickles ([#1043](https://github.com/promptfoo/modelaudit/issues/1043)) ([19b6ebe](https://github.com/promptfoo/modelaudit/commit/19b6ebe505d2ba90f81d6284d07e111f77cbf0b5))
- detect proto0 pickles in 7z probes ([c1fb7d6](https://github.com/promptfoo/modelaudit/commit/c1fb7d6a8ba9e675780e78752e81bbc0f318a7b0))
- enforce ZIP aggregate size budget ([#1022](https://github.com/promptfoo/modelaudit/issues/1022)) ([94d576f](https://github.com/promptfoo/modelaudit/commit/94d576fc9c86ee1102677ccbf280284bdb2276ea))
- fail closed on incomplete ONNX weight analysis ([#1025](https://github.com/promptfoo/modelaudit/issues/1025)) ([03413c5](https://github.com/promptfoo/modelaudit/commit/03413c5f39b53aa9637bf914650812afb8eff9af))
- fail closed on incomplete XGBoost analysis ([#1019](https://github.com/promptfoo/modelaudit/issues/1019)) ([b8f334e](https://github.com/promptfoo/modelaudit/commit/b8f334ebad0b678c2e8ad1e14102323b30ce1096))
- fail closed on oversized Skops entries ([#1018](https://github.com/promptfoo/modelaudit/issues/1018)) ([3d74ab0](https://github.com/promptfoo/modelaudit/commit/3d74ab01d2eebfa5696afbab92cfaff62fc363a4))
- fail closed on pytorch zip timeouts ([bf72f62](https://github.com/promptfoo/modelaudit/commit/bf72f624aa5b1f6a306e9c545e36ec64160b876f))
- fail closed on RAR archives ([#1030](https://github.com/promptfoo/modelaudit/issues/1030)) ([14b6e8f](https://github.com/promptfoo/modelaudit/commit/14b6e8f3ae619081d656a8831dc78e0bbb328ea5))
- fail closed on template truncation ([#1026](https://github.com/promptfoo/modelaudit/issues/1026)) ([3d7967d](https://github.com/promptfoo/modelaudit/commit/3d7967dad5d34c49fe8e14c0690caddb5be33dd7))
- fail closed on unclassified scan failures ([#1014](https://github.com/promptfoo/modelaudit/issues/1014)) ([dfe0455](https://github.com/promptfoo/modelaudit/commit/dfe045561dacbc475395bc8f7b379c0b4a1b84b9))
- harden incomplete Keras scanner paths ([#1020](https://github.com/promptfoo/modelaudit/issues/1020)) ([86e017a](https://github.com/promptfoo/modelaudit/commit/86e017a7f12ba23bd995f69bf7a6a3b8179265cb))
- harden NeMo Hydra deserialization targets ([#1021](https://github.com/promptfoo/modelaudit/issues/1021)) ([0f899a6](https://github.com/promptfoo/modelaudit/commit/0f899a64afd84cc5f1651ff5b22b427f685bc314))
- harden pickle nested bypass detection ([#1027](https://github.com/promptfoo/modelaudit/issues/1027)) ([c3a3b9d](https://github.com/promptfoo/modelaudit/commit/c3a3b9d1e4ffbd854e6003afbf6ebef1e708a619))
- harden PyTorch pickle import classification ([#1015](https://github.com/promptfoo/modelaudit/issues/1015)) ([7b00e55](https://github.com/promptfoo/modelaudit/commit/7b00e55ce8c4377fc8e3d9c589e1a310f4b469e9))
- harden remote cache and scanner bounds ([#1031](https://github.com/promptfoo/modelaudit/issues/1031)) ([74c2b6d](https://github.com/promptfoo/modelaudit/commit/74c2b6d65867babde10a4fc3fc3d6ee3e73fd23a))
- preserve active payload severities ([#1046](https://github.com/promptfoo/modelaudit/issues/1046)) ([13752e9](https://github.com/promptfoo/modelaudit/commit/13752e9fc5764cdb45caa177f34a102be72990af))
- preserve scannable skipped ZIP containers ([#1028](https://github.com/promptfoo/modelaudit/issues/1028)) ([29747d5](https://github.com/promptfoo/modelaudit/commit/29747d508b28947216e1926e52cba1093dd63ced))
- redact telemetry issue fields ([#1023](https://github.com/promptfoo/modelaudit/issues/1023)) ([cd80d22](https://github.com/promptfoo/modelaudit/commit/cd80d22ac4c2fee113179d81d15685885713ac6b))
- restore nested pickle CI coverage ([b7a4846](https://github.com/promptfoo/modelaudit/commit/b7a4846a85d6d46685cd4d002f1ebcd605b6d917))
- route disguised nested archives in sevenzip scans ([#1017](https://github.com/promptfoo/modelaudit/issues/1017)) ([cb2572e](https://github.com/promptfoo/modelaudit/commit/cb2572ed65ffb2e8ba403d4a772b75c1998f6a40))
- route ONNX pb files by content ([#1029](https://github.com/promptfoo/modelaudit/issues/1029)) ([6e9aa45](https://github.com/promptfoo/modelaudit/commit/6e9aa459f36e8ab282dc7dbda6f6c027c6b34a11))
- route PyTorch ZIP archives without metadata ([#1016](https://github.com/promptfoo/modelaudit/issues/1016)) ([1f56bb8](https://github.com/promptfoo/modelaudit/commit/1f56bb82989c61004c2716f966ace3823e6fae5f))
- route UBJSON-format .bst files to UBJ scanner ([#1037](https://github.com/promptfoo/modelaudit/issues/1037)) ([52f869a](https://github.com/promptfoo/modelaudit/commit/52f869a7d7e95fc5168a55d9c21389f0e3860aca))
- **rule-mapper:** preserve unknown opcode fallback ([5153d68](https://github.com/promptfoo/modelaudit/commit/5153d68101e6e5c67d64419c6d391ec405b4daa1))
- run full Docker image as non-root ([#1024](https://github.com/promptfoo/modelaudit/issues/1024)) ([c1d2be6](https://github.com/promptfoo/modelaudit/commit/c1d2be64382718516432325a3ac8f005be64444c))
- scan generic archive python handlers ([#1047](https://github.com/promptfoo/modelaudit/issues/1047)) ([5b90a84](https://github.com/promptfoo/modelaudit/commit/5b90a84161cee233b0f6c8b69c36d21b182261f9))

### Performance Improvements

- optimize model scan hot paths ([#1012](https://github.com/promptfoo/modelaudit/issues/1012)) ([6a0c53a](https://github.com/promptfoo/modelaudit/commit/6a0c53a3172db274ba2ea4e192ce7dc244d92374))

### Documentation

- align markdown with current repo state ([#1035](https://github.com/promptfoo/modelaudit/issues/1035)) ([690bc52](https://github.com/promptfoo/modelaudit/commit/690bc5274198eb3428db9779ada0bdc2d40702ee))
- align README support and dependency guidance ([#1008](https://github.com/promptfoo/modelaudit/issues/1008)) ([5dcd62b](https://github.com/promptfoo/modelaudit/commit/5dcd62bad05ed9e661c2cafacc7ec1b4a4bad515))
- clarify security report closure policy ([#1049](https://github.com/promptfoo/modelaudit/issues/1049)) ([d53e445](https://github.com/promptfoo/modelaudit/commit/d53e445609708909eee6822a5215289ed64d6c48))
- prune stale planning artifacts ([#1010](https://github.com/promptfoo/modelaudit/issues/1010)) ([851cc10](https://github.com/promptfoo/modelaudit/commit/851cc102a8c1d40fce7433a1d221d6ff9acece5f))

## [Unreleased]

### Added

- **security:** inspect non-canonical SavedModel root siblings for suspicious
  executable-like content
- **security:** detect bare-string Lua `require "module"` loads in Torch7
  artifacts
- **security:** keep trusted NeMo namespaces from suppressing suspicious Hydra
  `_target_` leaf names
- **security:** fail closed when NeMo archives contain no analyzable config files
- **security:** analyze GGUF-embedded chat templates through the Jinja scanner
  while preserving GGUF scanner ownership
- **security:** run JAX checkpoint analysis for JAX-like pickle payloads that
  stay on the primary pickle scanner path
- **security:** detect `mailcap.findmatch` pickle call targets that can execute
  attacker-controlled mailcap `test` commands on Python versions that still
  provide `mailcap`
- **security:** detect `setuptools._distutils.spawn.spawn` pickle call targets
  that can execute attacker-controlled subprocess command lists when
  `setuptools` is installed
- **security:** detect `pipes.Template` pickle call targets that can execute
  attacker-controlled shell pipelines on Python versions that still provide
  `pipes`
- **security:** resolve module-level bound-method aliases and same-module
  constructor call paths in pickle call-graph analysis so process-dispatch
  wrappers are blocked
- **security:** resolve dangerous `six.moves` compatibility aliases, including
  vendored `six` copies, in pickle call-graph analysis so subprocess, pickle
  deserializer, and builtin execution wrappers are blocked
- **security:** resolve constructor-default sink aliases assigned to instance
  attributes in pickle call-graph analysis so wrappers like Botocore credential
  process providers are blocked
- **security:** resolve sink defaults forwarded through `super().__init__` in
  pickle call-graph analysis so async credential process wrappers are blocked
- **security:** resolve parameter-fed function-local class instance aliases in
  pickle call-graph analysis so wrapper functions like `click.edit` are blocked
- **security:** resolve function-local import aliases in pickle call-graph
  analysis so wrappers that import RCE sinks inside function bodies are blocked
- **security:** preserve callable invocation aliases when import-reference
  metadata is crowded, while ignoring uninvoked nested function and lambda
  bodies during pickle call-graph analysis
- **security:** detect `typing._eval_type` pickle call targets that can
  evaluate attacker-controlled `ForwardRef` expressions
- **security:** detect `dataclasses._create_fn` pickle call targets that can
  execute attacker-controlled generated Python source
- **security:** detect `typing.get_type_hints` pickle call targets that can
  evaluate attacker-controlled annotation strings
- **security:** detect public `operator.call` pickle call targets that can
  invoke attacker-controlled callables
- **security:** detect `builtins.map` pickle call targets that can lazily
  invoke attacker-controlled callables when iterated
- **security:** detect `itertools.starmap` pickle call targets that can lazily
  invoke attacker-controlled callables when iterated
- **security:** detect `builtins.filter` pickle call targets that can lazily
  invoke attacker-controlled callables when iterated
- **security:** detect `types.MethodType` pickle call targets that can
  synthesize attacker-controlled bound methods for later invocation
- **security:** detect `types.DynamicClassAttribute.__get__` pickle call
  targets that can invoke attacker-controlled descriptor getters
- **security:** detect `functools.cached_property.__get__` pickle call targets
  that can invoke attacker-controlled cached-property getters
- **security:** detect `functools.cmp_to_key` pickle call targets that can
  invoke attacker-controlled comparators during rich comparison
- **security:** detect `logging.Filterer.filter` pickle call targets that can
  invoke attacker-controlled logging filter callbacks
- **security:** detect `inspect.getmembers` pickle call targets that can
  invoke attacker-controlled descriptors during introspection
- **security:** detect `builtins.hasattr` pickle call targets that can invoke
  attacker-controlled descriptors during attribute-existence checks
- **security:** detect `__del__` finalizer string seeds that can execute
  attacker-controlled methods when pickle-built objects are dropped
- **security:** detect `__eq__` rich-comparison string seeds that can execute
  attacker-controlled methods during equality checks
- **security:** detect `__lt__`, `__le__`, `__gt__`, `__ge__`, and `__ne__`
  rich-comparison string seeds that can execute attacker-controlled methods
  during ordering checks
- **security:** detect `__contains__` membership string seeds that can execute
  attacker-controlled methods during containment checks
- **security:** detect `__setitem__` item-assignment string seeds that can
  execute attacker-controlled methods during item mutation
- **security:** detect `__getitem__` and `__delitem__` item-protocol string
  seeds that can execute attacker-controlled methods during item access
- **security:** detect binary arithmetic and bitwise dunder string seeds that
  can execute attacker-controlled methods during operator dispatch
- **security:** detect reflected and in-place binary operator dunder string
  seeds that can execute attacker-controlled methods during operator dispatch
- **security:** detect unary operator dunder string seeds that can execute
  attacker-controlled methods during operator dispatch
- **security:** detect context-manager entry dunder string seeds and
  `contextlib.ExitStack.enter_context` pickle call targets that can invoke
  attacker-controlled `__enter__` methods
- **security:** detect iteration protocol dunder string seeds that can execute
  attacker-controlled methods during builtin iteration dispatch
- **security:** detect numeric rounding protocol dunder string seeds that can
  execute attacker-controlled methods during rounding helper dispatch
- **security:** detect descriptor setup and numeric coercion dunder string
  seeds that can execute attacker-controlled methods during class creation
- **security:** detect presentation and size protocol dunder string seeds that
  can execute attacker-controlled methods during common builtin dispatch
- **security:** detect PathLike `__fspath__` dunder string seeds that can
  route attacker-controlled paths into file APIs during pickle loading
- **security:** detect direct pickle calls to stdlib file-write sinks such as
  `pathlib.Path.write_text`, `io.open`, and `_io.FileIO`
- **security:** detect pickle calls to logging file handlers and emit/handle
  dispatch methods that can write attacker-controlled startup hooks
- **security:** detect pickle calls to `argparse.FileType` and high-level
  logging stream dispatch methods that can write attacker-controlled startup
  hooks
- **security:** detect pickle calls to NumPy text writers that can write
  attacker-controlled startup hooks
- **security:** detect pickle calls to `python-dotenv` key writers that can
  write attacker-controlled startup hooks
- **security:** detect pickle globals whose Python call graph reaches known
  RCE-capable source primitives such as `os.execvpe`
- **security:** detect pickle globals whose Python call graph pairs file-open
  and file-write wrappers that can create executable startup hooks
- **security:** resolve pickle-imported Python class globals through bounded
  constructor and object-method call graph entrypoints
- **security:** detect public `io.FileIO` and `io.TextIOWrapper.write` aliases
  for blocked `_io` file-writing primitives
- **security:** detect builtin namespace dictionary access that can recover
  blocked primitives through mapping lookups
- **security:** detect dotted pickle global aliases that resolve to blocked
  source primitives such as `os.system`
- **security:** detect concrete `pathlib` path writer aliases and module
  namespace dictionary recovery for modules with blocked globals
- **security:** detect module namespace and `__builtins__` access used for
  dynamic builtin recovery
- **security:** detect `string.Formatter.get_field` pickle call targets that
  can traverse attacker-controlled field expressions into callable objects
- **security:** detect `unittest.mock._get_target` pickle call targets that
  can manufacture delayed `pkgutil.resolve_name` resolver partials
- **security:** detect descriptor getter pickle call targets that can bind
  recovered function descriptors and expose builtin namespaces
- **security:** detect wrapper and method descriptor getter pickle call targets
  that can bind recovered slot wrappers for dynamic attribute access
- **security:** detect global references to attribute-access and function
  namespace source methods used for dynamic builtin recovery
- **security:** detect object subclass enumeration globals that can recover
  loaded process capabilities without direct imports
- **security:** detect garbage collector object-graph globals that can recover
  hidden namespaces and loaded process capabilities
- **security:** detect frame-introspection globals and frame namespace
  descriptor getters used for dynamic builtin recovery
- **security:** detect callable `__call__` aliases of blocked pickle globals
  used to invoke hidden RCE source primitives
- **security:** detect wrapper `__get__` and `__self__` aliases of blocked
  pickle globals used to recover hidden RCE source primitives
- **security:** detect attribute aliases under blocked pickle global prefixes
  used to recover hidden RCE source primitives
- **security:** detect pickle calls to PyYAML unsafe loaders that can execute
  attacker-controlled Python constructors
- **security:** detect pickle calls to `codecs.open` and codec stream writes
  that can write attacker-controlled startup hooks
- **security:** detect pickle calls to durable tempfile creation and CSV
  `DictWriter` row dispatch that can write attacker-controlled startup hooks
- **security:** detect pickle calls to mailbox single-file `add` dispatch
  methods that can write attacker-controlled startup hooks
- **security:** detect pickle calls to `_tkinter` Tcl interpreter dispatch
  methods that can execute local commands
- **security:** detect high-level `tkinter.Misc` pickle call targets that can
  forward attacker-controlled commands into Tcl interpreter dispatch
- **security:** detect pickle calls to `_xxsubinterpreters.run_string` that
  can execute attacker-controlled Python source
- **security:** detect `builtins.staticmethod` pickle call targets that can
  synthesize callable descriptors for later invocation
- **security:** detect `builtins.property.__get__` pickle call targets that
  can invoke attacker-controlled property getters during descriptor access
- **security:** detect `builtins.classmethod.__get__` pickle call targets that
  can synthesize attacker-controlled bound methods during descriptor access
- **security:** detect `_functools.partial` pickle call targets that can
  synthesize private-alias partial callables for later invocation
- **security:** detect `_functools.reduce` pickle call targets that can invoke
  attacker-controlled reducer callables through the private CPython alias
- **security:** detect `functools.cache`, `functools.lru_cache`, and
  `functools.singledispatch` pickle call targets that can synthesize callable
  wrappers around attacker-controlled functions for later invocation
- **cli:** add scanner selection with `--scanners`, `--exclude-scanner`, and `--list-scanners` wired into core routing, nested dispatch, remote prefilters, and scan metadata; selection-suppressed preferred scanners emit a stderr warning and populate `scanner_selection.suppressed_preferred_scanner_ids`, and unknown scanner names suggest the closest match
- **pickle:** replace the standalone pickle scanner's package-engine selector with the Rust-only runtime and explicit native-extension errors
- **pickle:** scan PyTorch ZIP checkpoint pickle members directly in the standalone pickle scanner
- **pickle:** bundle the standalone `modelaudit_picklescan` API in the root `modelaudit` wheel and add source-tree coverage for the package boundary
- **tests:** enable existing PaddlePaddle scanner tests in CI by adding `test_paddle_scanner.py` to the allowed test files list (Python 3.10/3.12/3.13)
- **security:** detect CVE-2026-1669 Keras HDF5 external weight references in standalone `.h5` and embedded `.keras` weights
- **security:** detect CVE-2026-24747 PyTorch weights_only=True bypass via SETITEM/SETITEMS abuse and tensor metadata mismatch detection
- **security:** detect CVE-2022-45907 PyTorch torch.jit.annotations.parse_type_line unsafe eval() injection (CVSS 9.8)
- **keras:** detect CVE-2025-12058 StringLookup external vocabulary path loading in `.keras` configs (local file read / SSRF)

### Changed

- **telemetry:** persist ModelAudit distinct IDs in Promptfoo's global config
  format (creating `~/.promptfoo/promptfoo.yaml` if absent and migrating any
  legacy `~/.modelaudit/user_config.json` ID) and include `isRunningInCi` on
  analytics payloads, with presence-based detection for marker-style providers
  (TeamCity, CodeBuild, Bitbucket, Jenkins)
- **docs:** align public README and compatibility guidance with supported Python 3.10-3.13, TensorFlow extra requirements, supported formats, and telemetry sanitization behavior
- **security:** credit @mosebit for privately reporting a TensorRT native-code detection gap that helped harden native-code scanner coverage
- **security-policy:** clarify when low-impact scanner coverage gaps may be closed without publishing a public advisory while still crediting reporters
- **pickle:** increase Rust stream read chunks to reduce scan overhead on large file and archive-member inputs
- **pickle:** store Rust byte stack operands as source spans instead of copied previews to reduce large-pickle scan overhead
- **pickle:** skip no-seed raw-text and CVE fallback passes on clean Rust-complete pickle scans, tightening benign state-dict CLI performance while preserving targeted raw-detector positives
- **pickle:** document and pin parse-incomplete tail suppression to trusted pickle boundaries without dangerous import references; parse failures with security findings or dangerous imports still fail closed
- **security:** bump the optional ONNX dependency to `1.21.0rc3`, which removes the vulnerable `onnx.hub` module flagged by CVE-2026-28500.

### Rule Codes

- **pickle:** preserve and document Rust pickle scanner mappings for SETITEM abuse (`S209`), copyreg extensions (`S211`), persistent IDs (`S212`), nested or encoded pickle payloads (`S213`), base64/hex/obfuscated encoded payloads (`S601`/`S602`/`S604`), structural tamper and incomplete analysis (`S902`), and the new pickle expansion denial-of-service rule (`S214`).
- **pickle:** keep internal Rust finding codes such as `STRUCTURAL_TAMPER` and `PICKLE_EXPANSION` in `pickle_rule_code` details while exposing stable ModelAudit rule codes for dashboards, SARIF, suppression, and severity configuration.

### Fixed

- **llamafile:** stream marker detection across executable bodies so `.exe`
  wrappers with middle-only `llamafile` markers still route to the scanner
- **flax:** keep explicit Flax/JAX checkpoint suffixes routed to the scanner when
  `msgpack` is unavailable so missing parser coverage fails closed
- **llamafile:** fail closed when bounded embedded-payload scanning stops before
  covering the full executable
- **skops:** require exploit-shaped structured loader nodes for CVE-2025-54412
  and CVE-2025-54413 checks so inert prose, filenames, and valid loader nodes do
  not become critical findings
- **routing:** require recognized ZIP signatures before classifying files or
  streaming previews as archives, so benign `PK*` near-matches stay unclassified
- **xgboost:** avoid flagging inert `feature_names` metadata as executable JSON
  content.
- **pmml:** avoid flagging benign `ecosystem()` prose as a `system(...)` call.
- **jax:** avoid routing `ajax` near-matches as JAX checkpoint indicators.
- **security:** fail closed on malformed nested XGBoost JSON structures that
  would otherwise skip booster or tree validation.
- **security:** require the legacy XGBoost binary signature instead of
  accepting marker-shaped text payloads as valid `.bst` models.
- **security:** validate late XGBoost trees instead of sampling only the first
  ten tree structures.
- **security:** detect PaddlePaddle suspicious tokens that span the scanner's
  1 MiB read boundaries.
- **routing:** align manifest scanner routing with the manifest filenames and
  dedicated manifest-style suffixes declared by the registry.
- **security:** detect strong executable headers in generic archive members even
  when the payload has no executable-looking suffix.
- **routing:** preserve renamed OpenVINO and PMML XML models with long benign
  prologs during content-based directory filtering.
- **security:** resolve compile-time string concatenation in archive-member `getattr` calls so high-risk targets like `os.system` cannot hide behind split literals
- **security:** fail closed when routing recognizes a model format but no scanner is available to analyze it
- **security:** fail closed when streaming scans only fall back to heuristic header checks, even if the remote file bytes were fully read
- **docs:** narrow public scan-coverage wording so unsupported or merely discovered formats are not over-promised
- **analysis:** keep exact dangerous literals visible even when surrounding bytes look like ML weights
- **analysis:** stop attacker-controlled file and directory names from suppressing dangerous framework-pattern findings
- **security:** detect dangerous marker-free Python source blobs through the public JIT path so disguised archive members are still analyzed
- **security:** mark ONNX scans inconclusive when raw JIT/script or network
  detector analysis cannot complete instead of treating detector failures as
  clean passes.
- **security:** run Jinja template analysis for manifest-owned configs that carry
  embedded chat-template fields.
- **pickle:** detect stdlib filesystem probe and process-state callables such as `pathlib` metadata methods, `decimal.setcontext`, and `gc.disable` during pickle scans, while keeping local container mutations clean and covering public `operator.setitem` registry poisoning plus target-aware `operator.imul` warning-filter mutation.
- **pickle:** detect public `operator.setitem` pickle calls, keep callable
  invocation aliases ahead of import-reference budget exhaustion, dedupe repeated
  invocation metadata before the reporting cap, preserve literal mapping-key
  shadowing through `ChainMap`, block deeply wrapped `defaultdict` factories,
  and avoid outer-function call-graph false positives from nested function and
  lambda bodies.
- **security:** prevent HuggingFace whitelist provenance from downgrading active payload, CVE, traversal, executable, operational-error, or incomplete-coverage findings. Exemptions now cover S1xx code-execution primitives (`S101`–`S115`) and HIGH-severity S3xx network primitives (`S301`/`S304`/`S305`/`S310`), and the keyword fallback uses word-boundary matching so substrings like "executable" inside "ExecuTorch" no longer over-suppress legitimate downgrades.
- **security:** scan generic ZIP/TAR/NPZ Python members and ZIP/TAR/NPZ executable members, including wildcard imports and callable rebindings while failing closed on malformed Python source. Findings carry accurate rule codes per risk category (`S101` for `os.system`/`os.popen`, `S103` for `subprocess.*`, `S104` for `eval`/`exec`, `S106` for `__import__`, `S107` for `importlib.import_module`, `S213` for `pickle.load`/`pickle.loads`) instead of a single catch-all, the ZIP path now honors `max_mar_python_analysis_bytes` for non-MAR Python members, and source bytes are parsed directly so PEP 263 encoding declarations are respected.
- **security:** bound PyTorch ZIP JIT/network member reads (default 32 MiB per-member cap, configurable via `max_jit_scan_member_bytes`) and mark oversized or unreadable member coverage inconclusive. Oversize and read-failure events are aggregated into a single summary INFO check per kind (with per-member detail in `details["entries"]`) so adversarial archives cannot flood the checks list, duplicate-name entries are de-duplicated by `ZipInfo` identity rather than filename so the second of two same-name members is still analyzed, directory entries are skipped explicitly, and pickle members continue through the bounded JIT/network pass so padded payloads remain covered beyond the pickle scanner raw window.
- **security:** detect hidden PyTorch ZIP pickle members even when a benign `data.pkl` is already present. The bounded-prefix sniff now always runs across unselected members (including extensionless payloads and files under `data/<n>`), fails closed with one aggregated INFO check if probe reads raise (was one check per failed member), and is mirrored in the standalone `modelaudit-picklescan` package so both code paths discover the same hidden payloads.
- **security:** mark PyTorch ZIP scan timeouts inconclusive and unsuccessful instead of reporting complete coverage.
- **security:** detect extensionless protocol-0/1 pickle members during 7-Zip nested archive probes.
- **pickle:** restore ModelAudit nested-pickle findings from Rust standalone notices and keep network raw-detector coverage after native pickle findings
- **xgboost:** route UBJSON-backed `.bst` models when `version` or booster markers appear after a large `learner` object, and route extensionless XGBoost UBJSON models via content sniffing (requires both the `learner` marker and a booster/model-param strong marker within the probe window).
- **telemetry:** strip query strings, fragments, and URL userinfo from cloud model names and file-extension metadata
- preserve `S999` unknown-opcode mapping in generic rule fallback
- **docker:** run the full parser image as a non-root `appuser`
- **onnx:** mark weight-distribution analysis inconclusive when dependencies are missing or eligible tensors are external, oversized, or fail extraction
- **zip:** enforce an aggregate uncompressed-size budget before extracting ZIP entries so split archive bombs cannot bypass per-entry limits
- **security:** flag NeMo Hydra `_target_` values that invoke ML deserialization loaders such as `torch.load`, `joblib.load`, Keras load-model APIs, and related pickle-backed helpers.
- **telemetry:** replace free-form issue messages in telemetry issue fields with stable rule/CVE/type identifiers
- **security:** route renamed TFLite FlatBuffers by magic bytes, enforce scanner file-size limits before model reads, and fail closed instead of propagating malformed structure traversal exceptions
- **onnx:** fail closed on CRITICAL findings, detect `PyFunc` operators and Windows absolute external-data paths, validate external tensor slices with the current ONNX dtype API, and avoid Python-op substring false positives
- **tensorrt:** route `.trt` engines, detect case-variant and UTF-16 suspicious strings, and avoid substring false positives in benign engine metadata
- **coreml:** detect Python 3 command metadata, Windows and bundle-macro linked-model escapes, malformed custom-code protobuf blocks, and custom layers nested under pipeline wrappers while preserving safe-key metadata URL inspection
- **pmml:** enforce max-file-size limits, inspect namespaced Extension/script tags, ignore DOCTYPE/ENTITY text inside XML comments/CDATA, avoid recursive text-walk crashes on deeply nested Extension trees, and fail closed when CRITICAL PMML findings are present
- **gguf:** fall back to the GGUF spec default tensor-data alignment after rejecting invalid `general.alignment` metadata values
- **security:** detect protocol 0/1 pickle streams hidden behind long separator gaps after an initial safe pickle stream
- **security:** preserve failed status for malicious Skops CVE detections and avoid CVE-2025-54886 false positives on benign README/model-card text such as "download"
- **security:** validate HuggingFace repo path components before cache path construction, revalidate HuggingFace cache freshness through the provider SDK, bound XGBoost JSON routing sniffing, redact signed cloud URLs from cache metadata, and default full-file scanner reads to bounded fail-closed limits
- **security:** enforce Flax msgpack scanner file-size limits before full reads, scan trailing msgpack stream objects with a bounded object-count cap, downgrade benign container-like trailing-object findings to INFO, and preserve failed status when CRITICAL findings are reported
- **security:** route `.joblib` files through the Joblib scanner, scan raw protocol-0/1 payloads directly, support gzip/bzip2/lzma/zlib wrappers with bounded output and trailing-data checks, preserve embedded Pickle finding locations, and fail closed on undecodable/trailing-wrapper errors
- **security:** route ONNX protobuf payloads saved with a `.pb` suffix by content before TensorFlow protobuf extension fallback
- **security:** detect direct `getattr(module, "dangerous")` handler calls in TorchServe MAR archives, parse conflicting duplicate manifests without silently downgrading hidden handlers, and suppress collision warnings for byte-identical duplicate manifests
- **security:** recognize RAR archives and fail closed as unsupported coverage instead of skipping `.rar` files during directory scans
- **skops:** fail closed when Skops archive limits, malformed archives, or bounded metadata reads leave CVE coverage incomplete, while preserving benign numeric-array payload scans
- **xgboost:** fail closed on incomplete JSON, UBJ, binary-structure, pickle-spoof, and enabled-loader analyses while preserving core exit-code and cache semantics
- **security:** route disguised ZIP and TAR members inside 7-Zip archives by bounded header probes while stopping probe reads at the per-member budget
- **security:** reduce NeMo Hydra `_target_` false positives by matching suspicious identifiers on token boundaries, preserve CVE-2025-23304 details on suspicious-target findings, and reject oversized YAML members before parsing
- **security:** preserve skipped-suffix ZIP containers when Keras config-only structure or embedded model-like `.bin` members indicate scannable content
- **security:** fail closed when oversized NeMo YAML prevents Hydra target analysis and scan malformed Jinja2 config fallbacks beyond the initial prefix window
- **security:** detect protocol 0/1 pickle streams with trivial opcode prefixes even when `STOP` is followed by trailing junk, while preserving plain-text near-match rejection
- **security:** detect protocol 0/1 pickle streams whose dangerous opcode appears after large trivial padding or after a non-trivial probe-boundary prelude, reject all-trivial no-`STOP` probe prefixes, and preserve rule codes across cached scan-result round trips
- **pickle:** propagate standalone fallback parse and stream-read failures into merged scan success, preserve truncated `.bin` fail-closed behavior, reuse non-seekable stream spools for the legacy parity pass, clamp negative stream sizes, and reset post-budget scan state between reused scanner runs
- **pickle:** align Rust pickle suspicious-string matching, protocol-0 text decoding, EOF-before-`STOP` handling, malformed argument diagnostics, parse-incomplete reports, warning dangerous-call adaptation, negative stream sizes, and compatibility finding promotion with Python parity
- **pickle:** harden Rust opcode parity for protocol 5 buffers, copyreg extensions, follow-on streams, protocol-0 encoded nested payloads, and `__main__` call escalation while bounding Python raw-detector hot paths
- **pickle:** preserve root raw-detector coverage for Slack tokens, `mongodb+srv://` secrets, bare IPs, domains, and network-library/function indicators behind large-file compatibility prefilters
- **pickle:** detect modern `STACK_GLOBAL`, `INST`, and copyreg extension references in post-budget pickle tails, avoid a second Rust-boundary copy of Python byte payloads, and skip expensive raw detectors for realistic benign PyTorch state-dict key streams
- **pickle:** route crafted protocol-1 binary pickle headers and nested protocol-1 payload prefixes through the same scanner paths as newer binary protocols
- **pickle:** enforce PyTorch ZIP entry limits with a bounded EOCD preflight before opening over-cap archives
- **pickle:** resolve memoized `GET`/`BINGET`/`LONG_BINGET` operands in post-budget `STACK_GLOBAL` tails so pre-memoized dangerous globals cannot bypass the Rust scanner
- **pickle:** detect no-`PROTO` binary-opcode nested payloads in raw/base64/hex fields, fail closed when nested probe candidates exceed the bounded budget, and flag process-termination/resource primitives such as `builtins.exit`, `faulthandler._sigsegv`, and `resource.setrlimit`
- **numpy:** propagate incomplete embedded-pickle scan status from object-dtype `.npy` payloads so partial recursive pickle coverage fails closed
- **license:** bound binary header scans and reuse compiled patterns to avoid full-file regex passes on large model archives
- **security:** stop iterating malformed TFLite models after excessive subgraph counts are detected
- **openvino:** route forbidden-DOCTYPE IR XML into the OpenVINO scanner, fail closed on XML parse errors, and suppress warning-level format-validation noise for benign `.xml` models with no distinctive magic bytes
- **security:** fail closed on conflicting duplicate or alias Keras root members so benign trailing `config.json` entries cannot hide malicious earlier configs, while accepting byte-identical duplicates without warning noise
- **security:** detect PyTorch binary code and blacklist patterns that straddle chunk boundaries, avoid duplicate overlap reports, and return `success=False` when CRITICAL findings are present
- fail closed on bare scanner `success=False` results across object, dict, streaming, and cached scan paths instead of allowing clean aggregate success
- **security:** harden PyTorch ZIP pickle import classification without downgrading dangerous builtins or known benign rebuild aliases
- **security:** scan every duplicate PyTorch ZIP member by physical archive entry and report conflicting duplicate names at INFO severity so benign trailing `data.pkl` entries cannot shadow malicious earlier payloads without making benign-but-conflicting duplicates warning-fail by themselves
- **security:** route metadata-stripped PyTorch ZIP archives by numeric tensor storage members only, preserving generic ZIP routing for data-directory near-matches
- **security:** route misnamed Skops ZIPs by bounded schema sniffing, treat encrypted Skops-like schema members as non-matches instead of crashing routing, recurse into embedded members while preserving Skops-specific CVE checks, avoid tiny nested `.bin` false positives on clean archive members, preserve nested-member byte accounting, and preserve CLI `scanner_names` in aggregated JSON output
- **pickle:** bound post-budget global fallback state, retained findings, and deadline checks to prevent crafted pickle tails from exhausting scanner memory or flooding logs
- **pickle:** mark timeout-, budget-, recursion-, and resource-limited pickle scans as inconclusive so clean-looking partial analysis returns exit code 2 unless real security findings were reported
- route misnamed ZIP, HDF5, and 7z files through content-aware scanner selection
- **security:** recursively scan all members of content-routed `.keras` ZIP archives with bounded per-member extraction, prefer canonical root members over normalized aliases, and fail closed on ambiguous duplicate aliases so embedded payloads and `./config.json` entries are not skipped
- **keras:** fail closed when embedded `.keras` weights exceed inspection limits, constrain fully-qualified H5/ZIP Lambda CVE attribution to Keras/TensorFlow namespaces, and avoid CVE noise for documentation URLs that mention `get_file`.
- **security:** scan duplicate ZIP entries by physical archive member instead of resolving repeated names to the final entry, preventing shadowed payloads from being skipped during recursive archive analysis
- bound Keras `config.json` and `metadata.json` member reads before JSON parsing
- **openvino:** parse XML roots for long-prolog routing, enforce size limits before parsing, scan nested layer attributes for external library references, and avoid importlib substring false positives
- **zip:** propagate nested critical findings and incomplete archive traversal to `success=False`, and bound symlink-target reads before path validation
- **tar:** propagate nested critical findings and partial archive traversal to `success=False`, continue after per-entry extraction errors, and normalize malformed archive-limit configs to safe defaults
- route oversized config-only Keras ZIP archives by bounded config-prefix sniffing instead of falling back to the generic ZIP scanner
- preserve disguised model files during directory prefiltering without promoting document ZIPs
- fail closed on duplicate 7z entries, nested critical findings, probe-limit truncation, and malformed 7z safety-limit configs
- **oci:** fail closed on nested findings and partial layer traversal, content-sniff misnamed layer members, normalize cosmetic layer-ref suffix changes, and reject oversized members before temp extraction
- **oci:** ignore non-layer metadata strings ending in `.tar.gz` when collecting manifest layer refs so benign URLs do not become false missing-layer failures
- recurse into nested 7z members even when their filenames use misleading extensions
- fail closed on extreme-size files when a scanner lacks bounded large-file analysis
- harden scan-cache invalidation and skip caching operational scan failures
- propagate CLI cache settings into MLflow and JFrog downloads
- avoid materializing streaming directory iterators in memory
- fail closed when JFrog folder downloads return only partial results
- **keras:** anchor safe Lambda normalization regexes in H5 scanning so appended statements (for example `; __import__(...)`) cannot bypass dangerous-code analysis
- **keras:** harden Keras H5 scanning by propagating CRITICAL findings to `success=False`, scanning wrapper-owned nested layers, parsing prerelease fix-boundary versions correctly, and matching suspicious module/config tokens without benign substring false positives
- complete primary header-format routing in `core.py` so all registered model formats map to scanner IDs (including OpenVINO/PMML/CNTK/LightGBM/Torch7/CatBoost/RKNN/MXNet/NeMo/Llamafile/TFLite/CoreML/Paddle/TensorRT/Flax/R/ExecuTorch/7z/compressed/skops/joblib/xgboost/jax_checkpoint), add `.skops` extension detection coverage without spurious ZIP mismatch noise, and route ZIP-backed PyTorch `.ckpt`/`.pkl` containers through the PyTorch ZIP path
- **security:** track pickle `BUILD`-driven `__setstate__` mutation on non-safe globals and block tree-model opcode-threshold escalation when dangerous globals are present in-stream
- **safetensors:** include BOOL, BF16, F8_E4M3, and F8_E5M2 dtypes in tensor-size validation so malformed offsets are no longer skipped
- harden pickle symbolic stack simulation by ignoring stack-neutral opcodes and using unknown sentinels for unhandled stack pushes
- **security:** scan TensorFlow SavedModel `assets/` and `assets.extra/` directories for executable-like content (shebang scripts, ELF/Mach-O binaries, pickle magic, and embedded Python source patterns)
- **security:** make TensorFlow SavedModel scans fail closed on CRITICAL findings, avoid substring false positives in PyFunc function references, and treat `blacklist_patterns=None` as disabled instead of emitting DEBUG read errors
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
- **security:** detect import-only pickle `GLOBAL`/`STACK_GLOBAL` references while preserving safe constructors, legacy Python 2 aliases, keyword-only `NEWOBJ_EX` analysis, and large native extension scans
- **security:** fail closed on malformed `STACK_GLOBAL` operands when memo lookups are missing or operand types are non-string, while keeping simple truncation-only context informational
- **security:** remove `builtins.hasattr` / `__builtin__.hasattr` from the pickle safe-global allowlist so attribute-access primitives stay flagged as dangerous builtins
- **security:** harden pickle blocklist enforcement by removing `_pickle.Unpickler`/`_pickle.Pickler` from safe globals, adding `copyreg.add_extension`/`copyreg.remove_extension` to suspicious globals, and limiting functools warning downgrades to `partial`/`partialmethod` so `functools.reduce` findings stay CRITICAL
- **security:** harden TensorFlow weight extraction limits to bound actual tensor payload materialization, including malformed `tensor_content` and string-backed tensors, and continue scanning past oversized `Const` nodes
- **security:** stream TAR members to temp files under size limits instead of buffering whole entries in memory during scan
- **security:** inspect TensorFlow SavedModel function definitions when scanning for dangerous ops and protobuf string abuse, with function-aware finding locations
- **security:** route oversized TensorFlow MetaGraph files to fail-closed parse-budget scans, inspect `AttrValue.func.name` references in executable ops, and restore oversized-attribute anomaly detection after bounded string decoding
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
- align repository documentation around current scanner coverage, rule codes, package boundaries, and supported CI workflows

## [0.2.37](https://github.com/promptfoo/modelaudit/compare/v0.2.36...v0.2.37) (2026-04-12)

### Bug Fixes

- add CVE scanner coverage ([01dec02](https://github.com/promptfoo/modelaudit/commit/01dec0270516738295651ce07e7804de82eaabdb))
- add size floor for zip compression ratio ([#949](https://github.com/promptfoo/modelaudit/issues/949)) ([5e66eeb](https://github.com/promptfoo/modelaudit/commit/5e66eeb483048644da7c07bba6496a5c6c73a187))
- align SARIF scan metadata with CLI results ([#934](https://github.com/promptfoo/modelaudit/issues/934)) ([1a90415](https://github.com/promptfoo/modelaudit/commit/1a90415d53d9ddc4dba01ff7ad804125a1d76c20))
- allow generated TorchScript source files ([#948](https://github.com/promptfoo/modelaudit/issues/948)) ([53d0cdc](https://github.com/promptfoo/modelaudit/commit/53d0cdc48025628de0f56397d832dbac839721fd))
- **archives:** honor nested header routing ([fccdb91](https://github.com/promptfoo/modelaudit/commit/fccdb914ccd87d0f178729f6becdfdddcfe72024))
- avoid archive bin pickle routing ([#962](https://github.com/promptfoo/modelaudit/issues/962)) ([446df6b](https://github.com/promptfoo/modelaudit/commit/446df6b06a59cf6cc8e11485d6df8f5dc0d35ec8))
- avoid safetensors unicode metadata false positive ([#945](https://github.com/promptfoo/modelaudit/issues/945)) ([d595fde](https://github.com/promptfoo/modelaudit/commit/d595fdee57150ea22d9bb38b92ec61cdc865da60))
- bound standalone pickle stream reads ([4d0cb84](https://github.com/promptfoo/modelaudit/commit/4d0cb84af010b4ed332ebbf17fc8bd0769fa8b6e))
- **catboost:** redact finding urls ([c65334c](https://github.com/promptfoo/modelaudit/commit/c65334ceb456556835d80bf17010d952c7437985))
- **cli:** honor streaming file skips ([49291ac](https://github.com/promptfoo/modelaudit/commit/49291acbc9fb8c35f7944ee894fd81ac23fe3045))
- **cli:** redact cloud urls in output ([#964](https://github.com/promptfoo/modelaudit/issues/964)) ([0ee82ca](https://github.com/promptfoo/modelaudit/commit/0ee82ca1e84f2dc06daa8d05a4ad9c3abdc85987))
- default unknown severities to info ([#963](https://github.com/promptfoo/modelaudit/issues/963)) ([9b27b9a](https://github.com/promptfoo/modelaudit/commit/9b27b9ac672009a77a413aeea1fea350f6df145c))
- **deps:** update dependency tensorflow to &gt;=2.21,&lt;2.22 ([#985](https://github.com/promptfoo/modelaudit/issues/985)) ([2e3ac65](https://github.com/promptfoo/modelaudit/commit/2e3ac651e2bb0b83d87d070c00894eeddcf0091d))
- **detectors:** redact network urls in findings ([7e28a46](https://github.com/promptfoo/modelaudit/commit/7e28a46c6de3f5646d42b14fd76061fdfeaf114e))
- **dvc:** restrict target paths ([3bd9b68](https://github.com/promptfoo/modelaudit/commit/3bd9b685a3e3bb5de87d3775a9704deb7f4a253b))
- flag pickle persistent ids ([#938](https://github.com/promptfoo/modelaudit/issues/938)) ([2cfba40](https://github.com/promptfoo/modelaudit/commit/2cfba403e21d53f46ba7089b655cebc564dcddaf))
- **gguf:** detect tensor bounds overflow ([a4358ff](https://github.com/promptfoo/modelaudit/commit/a4358ffe0e3b8a8d8729b8bcf23a8f00f205a5e1))
- honor header-routed scanners ([#941](https://github.com/promptfoo/modelaudit/issues/941)) ([6740260](https://github.com/promptfoo/modelaudit/commit/6740260c36331156eb6f7fc491d58f5b570dbee4))
- **huggingface:** redact source urls ([73b538e](https://github.com/promptfoo/modelaudit/commit/73b538e21ccf23c5ef452b16153c1e6e2b8e6663))
- ignore pmml documentation urls ([506aa75](https://github.com/promptfoo/modelaudit/commit/506aa7510a820e4c01018231cb52be4f5964334f))
- **jfrog:** redact url secrets ([4546eee](https://github.com/promptfoo/modelaudit/commit/4546eeeadad7a8fadd31e21cf550a44688f0d076))
- **keras:** redact archive urls ([e532b0d](https://github.com/promptfoo/modelaudit/commit/e532b0dd67d2f7033c29644356efe8a220060441))
- **lightgbm:** redact finding urls ([d4f1fe2](https://github.com/promptfoo/modelaudit/commit/d4f1fe2a61e51166bf48c74861ff7cb31f55a69c))
- **manifest:** redact url secrets ([c831733](https://github.com/promptfoo/modelaudit/commit/c83173316cf98d9f19b0a8481a40b848077d0096))
- mark missing numpy format as operational ([#958](https://github.com/promptfoo/modelaudit/issues/958)) ([6d271d6](https://github.com/promptfoo/modelaudit/commit/6d271d6eb4e3faf38bf03ae3db76ce9d369ce4af))
- mark pickle parse failures inconclusive ([8a0e3fd](https://github.com/promptfoo/modelaudit/commit/8a0e3fd125ec6e4d49f72ab68d43d1c6544d3ae0))
- **metadata:** redact suspicious urls ([7af0d4d](https://github.com/promptfoo/modelaudit/commit/7af0d4d1dbe8a6c6d87870f3a0b5989c91bb35d1))
- **metadata:** reject symlink escapes ([3869cf0](https://github.com/promptfoo/modelaudit/commit/3869cf0492fa1db7418269c8263b42f65a130a07))
- narrow flax suspicious key criticals ([#957](https://github.com/promptfoo/modelaudit/issues/957)) ([9276d24](https://github.com/promptfoo/modelaudit/commit/9276d2472c18cda02a559c1f451fa65c91bdbcf1))
- narrow network c2 metadata patterns ([fd9cc41](https://github.com/promptfoo/modelaudit/commit/fd9cc410440568cbb1ef0c17fea03499c16441e9))
- narrow openvino external library checks ([#959](https://github.com/promptfoo/modelaudit/issues/959)) ([e895872](https://github.com/promptfoo/modelaudit/commit/e895872612c15bfd016f9a9e1fb58262ff4ee1eb))
- narrow safetensors path metadata checks ([#955](https://github.com/promptfoo/modelaudit/issues/955)) ([4241780](https://github.com/promptfoo/modelaudit/commit/42417800670c4fb49d8bf2ea9b46aec702550485))
- narrow suspicious dunder string detection ([#947](https://github.com/promptfoo/modelaudit/issues/947)) ([e866760](https://github.com/promptfoo/modelaudit/commit/e8667609d293d4391205ce4e8884fa3559030604))
- **nemo:** scan referenced non-checkpoint suffixes ([3ba4ff7](https://github.com/promptfoo/modelaudit/commit/3ba4ff76399987dbcaf7b56c1a23f0d0a3c0a205))
- **openvino:** flag sidecar symlink escapes ([772e796](https://github.com/promptfoo/modelaudit/commit/772e796c73b1b05172225af27a6dabf6c5254aae))
- **openvino:** redact library urls ([241a667](https://github.com/promptfoo/modelaudit/commit/241a667dd658f1e0a827a05d3ddef5d13717f357))
- preserve informational network findings ([b39d312](https://github.com/promptfoo/modelaudit/commit/b39d3124bf0b8578ae79919c726a28d7731261a4))
- reduce benign Keras Lambda bytecode noise ([8cb5c29](https://github.com/promptfoo/modelaudit/commit/8cb5c29308673f52e9a9f2b7186cdd37c9657214))
- require nested pickle execution evidence ([d2ad631](https://github.com/promptfoo/modelaudit/commit/d2ad6314f4df70ae03064f78ef37ddd6c8de8f53))
- route nested compressed archive members ([e217b29](https://github.com/promptfoo/modelaudit/commit/e217b2982609a1888450c3d4ae9bd29726e187d4))
- route nested compressed members ([#944](https://github.com/promptfoo/modelaudit/issues/944)) ([d839fe7](https://github.com/promptfoo/modelaudit/commit/d839fe734ccdabb62401970f4b652048156707ec))
- **r:** redact serialized urls ([013bcf0](https://github.com/promptfoo/modelaudit/commit/013bcf0056b63f850ff569062ca3f6c64cfdbd9a))
- **scanners:** redact evidence secrets ([3ae1383](https://github.com/promptfoo/modelaudit/commit/3ae13834844cd1cffc3975379e3ab8550309dc83))
- skip prose-only network references ([773eb88](https://github.com/promptfoo/modelaudit/commit/773eb881187ef3b6601c9650e5bd4c8c17ec939c))
- skip protocol-only streaming pickle warning ([#961](https://github.com/promptfoo/modelaudit/issues/961)) ([dba3ebe](https://github.com/promptfoo/modelaudit/commit/dba3ebec5c19ea86b1e40012ff0ffce8d81af451))
- tighten pytorch zip pickle discovery ([#953](https://github.com/promptfoo/modelaudit/issues/953)) ([bfd9663](https://github.com/promptfoo/modelaudit/commit/bfd9663f68e30213fa8bb76016815dfbfdbdd968))
- **torchserve:** redact manifest urls ([4626a02](https://github.com/promptfoo/modelaudit/commit/4626a02450b5436cc994329662b5e1623d2d6b00))

### Documentation

- add scanner CVE coverage notes ([73d6e8e](https://github.com/promptfoo/modelaudit/commit/73d6e8e512f0d86c7307df69a5663e3223724196))
- allow promptfoo telemetry approval ([1fbe64c](https://github.com/promptfoo/modelaudit/commit/1fbe64cbe071579ebbb8064980cd05cf27133f2c))

## [0.2.36](https://github.com/promptfoo/modelaudit/compare/v0.2.35...v0.2.36) (2026-04-11)

### Documentation

- disable telemetry during agent validation ([#928](https://github.com/promptfoo/modelaudit/issues/928)) ([69a1986](https://github.com/promptfoo/modelaudit/commit/69a1986aa2a63ab07e63871507e96bf857c1c882))

## [0.2.35](https://github.com/promptfoo/modelaudit/compare/v0.2.34...v0.2.35) (2026-04-11)

### Bug Fixes

- clean up oversized zip entry temps ([#911](https://github.com/promptfoo/modelaudit/issues/911)) ([66b4871](https://github.com/promptfoo/modelaudit/commit/66b4871f49e367dea545f36af85c9cc75303d615))
- flag Paddle code patterns as warnings ([#925](https://github.com/promptfoo/modelaudit/issues/925)) ([32fa0b7](https://github.com/promptfoo/modelaudit/commit/32fa0b7551c13059515c464b0118851fa1fbe671))
- harden manifest parse boundaries ([#922](https://github.com/promptfoo/modelaudit/issues/922)) ([6f5b516](https://github.com/promptfoo/modelaudit/commit/6f5b516bec8492b2f062ba5ea10498c705d972ca))
- harden standalone pickle scanner ([#901](https://github.com/promptfoo/modelaudit/issues/901)) ([31f7dd3](https://github.com/promptfoo/modelaudit/commit/31f7dd38c6bd77631ccdca90438312c4db2ac857))
- mark corrupt NumPy object payloads inconclusive ([#912](https://github.com/promptfoo/modelaudit/issues/912)) ([ecba19d](https://github.com/promptfoo/modelaudit/commit/ecba19dc585d5bfbfbfbd687e81cd734a7b0103b))
- mark incomplete MXNet scans inconclusive ([#923](https://github.com/promptfoo/modelaudit/issues/923)) ([a928ed7](https://github.com/promptfoo/modelaudit/commit/a928ed723a220185c3c0ea4b046b8885c74e8f62))
- mark incomplete sharded scans inconclusive ([#909](https://github.com/promptfoo/modelaudit/issues/909)) ([510d0fb](https://github.com/promptfoo/modelaudit/commit/510d0fbe45ae9f1b7e213227ebb1210b15a35991))
- mark malformed GGUF scans inconclusive ([#914](https://github.com/promptfoo/modelaudit/issues/914)) ([9b3e216](https://github.com/promptfoo/modelaudit/commit/9b3e21607309b846b15f809af6fd1bef31268b6a))
- mark malformed Keras H5 configs inconclusive ([#917](https://github.com/promptfoo/modelaudit/issues/917)) ([23671c3](https://github.com/promptfoo/modelaudit/commit/23671c38796293978b0538eb4c7ce30c8cfa5160))
- mark malformed Keras ZIP configs inconclusive ([#918](https://github.com/promptfoo/modelaudit/issues/918)) ([d4ad8d8](https://github.com/promptfoo/modelaudit/commit/d4ad8d8717c4f1ca647b292035f68bbf570d9904))
- mark malformed SafeTensors scans inconclusive ([#913](https://github.com/promptfoo/modelaudit/issues/913)) ([43913d6](https://github.com/promptfoo/modelaudit/commit/43913d65c5eb89014d1bb137768f89e93b8d0d41))
- mark malformed tflite scans inconclusive ([#916](https://github.com/promptfoo/modelaudit/issues/916)) ([07c871a](https://github.com/promptfoo/modelaudit/commit/07c871a8d19e9181bdcd568fffa9a165883585de))
- mark partial archive scans inconclusive ([#907](https://github.com/promptfoo/modelaudit/issues/907)) ([c8eb918](https://github.com/promptfoo/modelaudit/commit/c8eb918b8d0a717460be93097cfc1cf0a47e6689))
- mark partial streaming scans inconclusive ([#908](https://github.com/promptfoo/modelaudit/issues/908)) ([3d47a10](https://github.com/promptfoo/modelaudit/commit/3d47a1055d09c20995c21ebe75a50a2c3d1105f0))
- mark unknown ONNX tensor dtypes inconclusive ([#915](https://github.com/promptfoo/modelaudit/issues/915)) ([35661b6](https://github.com/promptfoo/modelaudit/commit/35661b6ac166f38f7642ac9a3ea89b6cea538928))
- preserve picklescan stack state ([#910](https://github.com/promptfoo/modelaudit/issues/910)) ([fabac5c](https://github.com/promptfoo/modelaudit/commit/fabac5c9ead49c2ed5f8357dfa53ccdcce946527))
- recover malformed Jinja template configs ([#920](https://github.com/promptfoo/modelaudit/issues/920)) ([d619c8f](https://github.com/promptfoo/modelaudit/commit/d619c8f185040c7b3c772a4b94631edddde9d8a8))
- route corrupt catboost scans fail closed ([#924](https://github.com/promptfoo/modelaudit/issues/924)) ([052bb5f](https://github.com/promptfoo/modelaudit/commit/052bb5f4e6dbc5e48a3fe5d134e0ec8d9605e292))
- traverse nemo yaml list configs ([#919](https://github.com/promptfoo/modelaudit/issues/919)) ([0d8d4fd](https://github.com/promptfoo/modelaudit/commit/0d8d4fd4dc2ef774db093fb9e7daf27c32b5a0a8))
- **zip:** fail closed on MAR handler parse errors ([#896](https://github.com/promptfoo/modelaudit/issues/896)) ([a06a620](https://github.com/promptfoo/modelaudit/commit/a06a620f011d120072b1e8619e543a7306d5a4fc))

### Documentation

- improve scanner correctness documentation ([#921](https://github.com/promptfoo/modelaudit/issues/921)) ([06be0b6](https://github.com/promptfoo/modelaudit/commit/06be0b6eaeb53f5f238612a386665c45f3c27dc2))

## [0.2.34](https://github.com/promptfoo/modelaudit/compare/v0.2.33...v0.2.34) (2026-04-10)

### Bug Fixes

- flag Paddle code patterns as warnings instead of failing benign scans
- route corrupt CatBoost scans to fail closed outcomes
- mark incomplete MXNet scans inconclusive instead of clean
- harden manifest parse boundaries around malformed metadata
- recover malformed Jinja template configs as inconclusive scan outcomes
- traverse NeMo YAML list configs when checking suspicious targets
- mark malformed Keras ZIP configs inconclusive instead of clean
- mark malformed Keras H5 scans inconclusive instead of clean
- mark malformed TFLite scans inconclusive instead of clean
- mark malformed GGUF scans inconclusive instead of clean
- mark malformed SafeTensors scans inconclusive instead of clean
- preserve picklescan stack state across reused scanner runs
- mark partial streaming scans inconclusive when large-file streaming coverage is incomplete
- harden native code detection in model scanners ([#897](https://github.com/promptfoo/modelaudit/issues/897)) ([f4f661a](https://github.com/promptfoo/modelaudit/commit/f4f661a09be0032e15aa8895864413e3878233f8))

## [0.2.33](https://github.com/promptfoo/modelaudit/compare/v0.2.32...v0.2.33) (2026-04-09)

### Features

- extract standalone pickle scanner package with parity harness ([#832](https://github.com/promptfoo/modelaudit/issues/832)) ([e2986cd](https://github.com/promptfoo/modelaudit/commit/e2986cddaa592306cc10541865f011b3dc99a0ba))

### Bug Fixes

- harden helper routing for zip-backed pickle checkpoints ([#870](https://github.com/promptfoo/modelaudit/issues/870)) ([3ebe0c0](https://github.com/promptfoo/modelaudit/commit/3ebe0c04f02f51274b9c9588200212ad2cffe70b))
- make return paths explicit ([#884](https://github.com/promptfoo/modelaudit/issues/884)) ([e31c254](https://github.com/promptfoo/modelaudit/commit/e31c254b820c78278289cf06acdf17f3f81d49b2))
- skip extraction for suspicious ZIP entries ([358aa44](https://github.com/promptfoo/modelaudit/commit/358aa4498ce9d6a091340c6f23289523f98f3a55))

### Documentation

- clarify detection bypass severity policy ([d8117a1](https://github.com/promptfoo/modelaudit/commit/d8117a14b4f8ef3e1a93cb1d48eeba8d8af92677))

## [0.2.32](https://github.com/promptfoo/modelaudit/compare/v0.2.31...v0.2.32) (2026-04-05)

### Bug Fixes

- detect punctuated TensorRT tmp paths ([#867](https://github.com/promptfoo/modelaudit/issues/867)) ([9607530](https://github.com/promptfoo/modelaudit/commit/96075302de2d71b228be97e49698d6a1ad6b35bf))
- fail closed on OpenVINO DOCTYPE parse errors ([#864](https://github.com/promptfoo/modelaudit/issues/864)) ([f5b19c4](https://github.com/promptfoo/modelaudit/commit/f5b19c48c7eab876e29f1f474c555b902fa9b6ce))
- ignore OCI metadata URLs during layer discovery ([#866](https://github.com/promptfoo/modelaudit/issues/866)) ([0b24e3f](https://github.com/promptfoo/modelaudit/commit/0b24e3f7a0e013541bce100b64f1d69558bd807d))
- reduce PMML subprocess extension false positives ([#869](https://github.com/promptfoo/modelaudit/issues/869)) ([5e6f79d](https://github.com/promptfoo/modelaudit/commit/5e6f79dc134267202b5a4b841a8946af865ebd15))
- tolerate bounded CoreML custom block truncation ([#868](https://github.com/promptfoo/modelaudit/issues/868)) ([34df06d](https://github.com/promptfoo/modelaudit/commit/34df06dd2c12b69815a2a15f1273085856bebf64))

## [0.2.31](https://github.com/promptfoo/modelaudit/compare/v0.2.30...v0.2.31) (2026-04-04)

### Bug Fixes

- clean up CodeQL quality findings ([#862](https://github.com/promptfoo/modelaudit/issues/862)) ([5fbcb10](https://github.com/promptfoo/modelaudit/commit/5fbcb101322791831fbf6159bab454231a7f01f0))
- detect long-gap protocol-0 pickle tails ([#844](https://github.com/promptfoo/modelaudit/issues/844)) ([cbc24b2](https://github.com/promptfoo/modelaudit/commit/cbc24b2af187055622b3776b3e49cca0c43ce9b7))
- detect protocol 0/1 pickles with trailing junk ([#827](https://github.com/promptfoo/modelaudit/issues/827)) ([d07869d](https://github.com/promptfoo/modelaudit/commit/d07869dadc80de567db894dd8ceda9de53038a71))
- fail closed on conflicting Keras ZIP config aliases ([#847](https://github.com/promptfoo/modelaudit/issues/847)) ([ab426b8](https://github.com/promptfoo/modelaudit/commit/ab426b8230b1766b4a7678803c90c45256bcdf54))
- harden content-routed .keras ZIP recursive scans ([#828](https://github.com/promptfoo/modelaudit/issues/828)) ([a607df7](https://github.com/promptfoo/modelaudit/commit/a607df7e8f94623c7802ef3af90896e1b4c564cc))
- harden CoreML scanner ([#859](https://github.com/promptfoo/modelaudit/issues/859)) ([50da953](https://github.com/promptfoo/modelaudit/commit/50da95393c6b0be318cb33535e12d16a361663ac))
- harden Flax msgpack stream scanning ([#842](https://github.com/promptfoo/modelaudit/issues/842)) ([34e4595](https://github.com/promptfoo/modelaudit/commit/34e4595b2017f272c951a45c6f89a0fa8997f8d5))
- harden JAX checkpoint scanner heuristics ([#837](https://github.com/promptfoo/modelaudit/issues/837)) ([1042c20](https://github.com/promptfoo/modelaudit/commit/1042c20c48ce09613125967623c715babc7b9da8))
- harden Joblib raw/compressed pickle analysis ([#841](https://github.com/promptfoo/modelaudit/issues/841)) ([9d16470](https://github.com/promptfoo/modelaudit/commit/9d164701345aebef8ad03421ac66cbcca6c61aed))
- harden Keras H5 scanner ([#848](https://github.com/promptfoo/modelaudit/issues/848)) ([aa0ef28](https://github.com/promptfoo/modelaudit/commit/aa0ef2878593e639a5b868a4be2d5de7a6c9c23b))
- harden MAR duplicate-member analysis ([#830](https://github.com/promptfoo/modelaudit/issues/830)) ([8d4e056](https://github.com/promptfoo/modelaudit/commit/8d4e0567f1df15405f429cefe3cd894aada3b712))
- harden NeMo target checks and YAML bounds ([#839](https://github.com/promptfoo/modelaudit/issues/839)) ([63ff67d](https://github.com/promptfoo/modelaudit/commit/63ff67d45aa7d454e63781c71039839c35e74892))
- harden OCI layer scanner ([#856](https://github.com/promptfoo/modelaudit/issues/856)) ([637a4da](https://github.com/promptfoo/modelaudit/commit/637a4daa72047c15598660320f2f12de6a43e627))
- harden ONNX scanner ([#857](https://github.com/promptfoo/modelaudit/issues/857)) ([de304a7](https://github.com/promptfoo/modelaudit/commit/de304a77513abf551e96a1828f57fdfdd11150c2))
- harden OpenVINO scanner ([#852](https://github.com/promptfoo/modelaudit/issues/852)) ([a97b76e](https://github.com/promptfoo/modelaudit/commit/a97b76efc44940d70b6cc0f485485d5c5ff7b550))
- harden PMML scanner ([#860](https://github.com/promptfoo/modelaudit/issues/860)) ([cbcd88a](https://github.com/promptfoo/modelaudit/commit/cbcd88a91cc8b3f9986554b255be366fcae672a8))
- harden post-budget pickle tail scan bounds ([16d6db3](https://github.com/promptfoo/modelaudit/commit/16d6db39a6263bc923415d34f7501765550e3564))
- harden PyTorch binary chunk scanning ([#846](https://github.com/promptfoo/modelaudit/issues/846)) ([930c0bf](https://github.com/promptfoo/modelaudit/commit/930c0bf32b53fbc32252c1b2d98aa1f30716eece))
- harden SevenZip scanner ([#855](https://github.com/promptfoo/modelaudit/issues/855)) ([8d0c362](https://github.com/promptfoo/modelaudit/commit/8d0c362770f4261eefd7461309e7de09b923587d))
- harden skops archive routing, recursion, and scanner reporting ([#829](https://github.com/promptfoo/modelaudit/issues/829)) ([fb13f68](https://github.com/promptfoo/modelaudit/commit/fb13f6880fdf80e2e78f5f3f30d9b31c2cff17a3))
- harden Skops CVE status and card fallback detection ([#843](https://github.com/promptfoo/modelaudit/issues/843)) ([9dd964f](https://github.com/promptfoo/modelaudit/commit/9dd964f0aff86092178578f5b952418a6ec52200))
- harden TAR scanner ([#854](https://github.com/promptfoo/modelaudit/issues/854)) ([219ce54](https://github.com/promptfoo/modelaudit/commit/219ce54446385e87739beacb2b9a8629cde31abb))
- harden TensorFlow MetaGraph scanner ([#850](https://github.com/promptfoo/modelaudit/issues/850)) ([2dacc9d](https://github.com/promptfoo/modelaudit/commit/2dacc9dcf844ff8ecd335ad1604519b07fc95432))
- harden TensorFlow SavedModel scanner ([#849](https://github.com/promptfoo/modelaudit/issues/849)) ([f42b7f2](https://github.com/promptfoo/modelaudit/commit/f42b7f2aa560ff72f495a330870478f9028d4fc3))
- harden TensorRT scanner ([#858](https://github.com/promptfoo/modelaudit/issues/858)) ([c923b55](https://github.com/promptfoo/modelaudit/commit/c923b55df6e8101f40728cbad254d708eea515c5))
- harden TFLite scanner ([#851](https://github.com/promptfoo/modelaudit/issues/851)) ([b1b1060](https://github.com/promptfoo/modelaudit/commit/b1b1060ae746047becec36356c6a3d3c8227c723))
- harden TorchServe MAR handler and manifest analysis ([#840](https://github.com/promptfoo/modelaudit/issues/840)) ([6fc0437](https://github.com/promptfoo/modelaudit/commit/6fc04375fd4709869766418e1873231623458e59))
- harden ZIP scanner ([#853](https://github.com/promptfoo/modelaudit/issues/853)) ([4ccec1a](https://github.com/promptfoo/modelaudit/commit/4ccec1afcd66b2bac3c75f6bd635f34b446090ea))
- reject raw trailers in zlib wrappers ([#838](https://github.com/promptfoo/modelaudit/issues/838)) ([3b15e2e](https://github.com/promptfoo/modelaudit/commit/3b15e2e1d148d1c700c6d5300655b5e4bb388d70))
- scan duplicate PyTorch ZIP members ([#845](https://github.com/promptfoo/modelaudit/issues/845)) ([4f63b22](https://github.com/promptfoo/modelaudit/commit/4f63b2277b8d843411d833d00bcf33615b8fb17b))

### Documentation

- remove Claude-specific commit trailer ([#834](https://github.com/promptfoo/modelaudit/issues/834)) ([d891025](https://github.com/promptfoo/modelaudit/commit/d891025791128245f293057f4849b481806292c7))
- simplify CLAUDE shim ([#835](https://github.com/promptfoo/modelaudit/issues/835)) ([616ee31](https://github.com/promptfoo/modelaudit/commit/616ee318019e188f90ee1d41b2a2aaaee9c9444e))

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

- **chore**: standardize on `add_check()` API - internal code now uses the modern `add_check()` method for structured check reporting with explicit pass/fail status

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

[unreleased]: https://github.com/promptfoo/modelaudit/compare/v0.2.37...HEAD
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
