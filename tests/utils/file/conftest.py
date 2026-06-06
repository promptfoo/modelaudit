"""Platform-specific test routing for advanced file handlers."""

import os

import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip cache-only coverage where shard caching is intentionally disabled."""
    if os.name != "nt":
        return

    skip_unreliable_cache_identity = pytest.mark.skip(
        reason="sharded scan caching is intentionally disabled on Windows",
    )
    for item in items:
        if item.name == "test_cached_sharded_scan_rejects_family_change_during_scan":
            item.add_marker(skip_unreliable_cache_identity)
