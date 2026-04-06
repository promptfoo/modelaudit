"""Package version resolution for runtime imports."""

try:
    from importlib.metadata import PackageNotFoundError, version

    __version__ = version("modelaudit")
except PackageNotFoundError:  # type: ignore[possibly-unresolved-reference]
    __version__ = "unknown"
