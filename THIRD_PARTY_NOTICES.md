# Third-Party Notices

ModelAudit includes or depends on the following third-party software. Each
component is listed with its license. Full license texts are available in each
package's distribution or at the URLs below.

## Bundled Components

### TensorFlow Protobuf Definitions

- **Path:** `modelaudit/protos/`
- **License:** Apache-2.0
- **Copyright:** The TensorFlow Authors
- **Source:** <https://github.com/tensorflow/tensorflow>
- **Notice:** See `modelaudit/protos/LICENSE` and `modelaudit/protos/NOTICE`

## Runtime Dependencies

| Package              | License      | URL                                                 |
| -------------------- | ------------ | --------------------------------------------------- |
| click                | BSD-3-Clause | <https://palletsprojects.com/p/click/>              |
| contourpy            | BSD-3-Clause | <https://github.com/contourpy/contourpy>            |
| cyclonedx-python-lib | Apache-2.0   | <https://github.com/CycloneDX/cyclonedx-python-lib> |
| defusedxml           | PSF-2.0      | <https://github.com/tiran/defusedxml>               |
| fsspec               | BSD-3-Clause | <https://github.com/fsspec/filesystem_spec>         |
| gcsfs                | BSD-3-Clause | <https://github.com/fsspec/gcsfs>                   |
| huggingface-hub      | Apache-2.0   | <https://github.com/huggingface/huggingface_hub>    |
| numpy                | BSD-3-Clause | <https://numpy.org>                                 |
| platformdirs         | MIT          | <https://github.com/tox-dev/platformdirs>           |
| posthog              | MIT          | <https://github.com/posthog/posthog-python>         |
| protobuf             | BSD-3-Clause | <https://developers.google.com/protocol-buffers/>   |
| pydantic             | MIT          | <https://github.com/pydantic/pydantic>              |
| python-dotenv        | BSD-3-Clause | <https://github.com/theskumar/python-dotenv>        |
| PyYAML               | MIT          | <https://pyyaml.org/>                               |
| requests             | Apache-2.0   | <https://requests.readthedocs.io>                   |
| s3fs                 | BSD-3-Clause | <https://github.com/fsspec/s3fs/>                   |
| scipy                | BSD-3-Clause | <https://scipy.org/>                                |
| yaspin               | MIT          | <https://github.com/pavdmyt/yaspin>                 |

## Optional Dependencies

These are installed only when the corresponding extra is requested.

| Package      | Extra         | License      | URL                                          |
| ------------ | ------------- | ------------ | -------------------------------------------- |
| dill         | `dill`        | BSD-3-Clause | <https://github.com/uqfoundation/dill>       |
| h5py         | `h5`          | BSD-3-Clause | <https://www.h5py.org/>                      |
| joblib       | `joblib`      | BSD-3-Clause | <https://joblib.readthedocs.io/>             |
| mlflow       | `mlflow`      | Apache-2.0   | <https://mlflow.org/>                        |
| msgpack      | `flax`        | Apache-2.0   | <https://github.com/msgpack/msgpack-python>  |
| onnx         | `onnx`        | Apache-2.0   | <https://onnx.ai/>                           |
| py7zr        | `sevenzip`    | LGPL-2.1+    | <https://github.com/miurahr/py7zr>           |
| py-ubjson    | `xgboost`     | Apache-2.0   | <https://github.com/Iber/py-ubjson>          |
| safetensors  | `safetensors` | Apache-2.0   | <https://github.com/huggingface/safetensors> |
| scikit-learn | `joblib`      | BSD-3-Clause | <https://scikit-learn.org/>                  |
| tensorflow   | `tensorflow`  | Apache-2.0   | <https://www.tensorflow.org/>                |
| tflite       | `tflite`      | Apache-2.0   | <https://www.tensorflow.org/lite>            |
| torch        | `pytorch`     | BSD-3-Clause | <https://pytorch.org/>                       |
| xgboost      | `xgboost`     | Apache-2.0   | <https://xgboost.readthedocs.io/>            |

## License Compatibility

All runtime dependencies use permissive licenses (MIT, BSD, Apache-2.0, PSF-2.0)
compatible with ModelAudit's MIT license. The one optional dependency using a
copyleft license (py7zr, LGPL-2.1+) is dynamically linked and only installed on
explicit user request via the `sevenzip` extra.

---

_This file was last reviewed on 2026-02-20. Run
`uv run python -c "import importlib.metadata as md; [print(f'{d.metadata[\"Name\"]} {d.metadata[\"Version\"]} {d.metadata.get(\"License\",\"\")}') for d in md.distributions()]"`
to regenerate the installed package list._
