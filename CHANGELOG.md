Total output lines: 2246

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Bug Fixes

- bound remote streaming-analysis reads and report actual received-byte coverage for truncated objects
- avoid sending raw model identifiers, source paths, object keys, issue locations, or free-form errors in telemetry
- cover Keras H5 callable metadata and module references, align CVE-2025-1550 attribution, and scope HDF5 external-reference checks to Keras weight trees
- require explicit boolean opt-in before weight-distribution scans call torch.load and bound primitive PyTorch ZIP fallback extraction
- fail closed when OCI layer TAR metadata, member counts, or cumulative extracted bytes exceed inspection budgets
- fail closed on JFrog folder downloads whose selected artifacts use unsafe, colliding, or overlapping local paths
- detect dangerous textual byte keys in Flax MessagePack checkpoints
- bound Joblib decompression output to the configured scanner read budget
- close JIT replay alias, probe-budget, and compound-clause context gaps without suppressing dangerous browser or native-library calls
- detect Keras get_file tar extraction from effective call arguments without relying on URL suffixes
- reject cleartext HTTP cloud storage and PyTorch Hub model sources
- preserve dangerous JIT embedded-Python findings after benign member overwrites while bounding replay and suppression analysis
- fail closed when capped DVC pointer outputs are not otherwise covered, change during verification, exceed bounded tail verification, or exhaust shared scan budgets
- preserve registrable network domains and redact delimiter-split credentials in bounded finding evidence
- preserve executable text-sidecar network findings for f-string calls, standard command wrappers, port-qualified Docker registries, and bounded xargs downloads while keeping prose references informational.
- stabilize cache identity capture for compressed wrapper scans on Darwin `/private` path aliases and during unrelated temporary-file churn.

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
- validate OCI layer member and link metadata without suppressing regular-file payload scans, while preserving valid container-root symlinks
- prevent cache identity checks from accepting temporary higher-ancestor path swaps
- preflight MLflow artifact sizes and copy supported local repositories under hard byte limits, rejecting unsafe paths, size drift, and backends that cannot enforce the configured download budget
- omit attacker-controlled Keras H5 Lambda names, module/function references, source, b…44210 tokens truncated…udit/issues/521)) ([33d74bd](https://github.com/promptfoo/modelaudit/commit/33d74bd9135f667ef3dd002889bae14031e4dd79))
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
