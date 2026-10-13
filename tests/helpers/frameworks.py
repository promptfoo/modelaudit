"""Framework availability helpers for tests."""


def has_tensorflow_runtime() -> bool:
    try:
        import tensorflow as tf

        # Avoid treating vendored protobuf-only stubs as full TensorFlow runtime.
        # Those stubs are not sufficient for weight-distribution tests.
        return bool(getattr(tf, "__version__", None)) and hasattr(tf, "constant")
    except Exception:
        return False
