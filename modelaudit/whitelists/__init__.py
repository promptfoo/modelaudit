"""
Model whitelists for reducing false positives.

This package contains whitelists of trusted models from various sources.
When a model is on a whitelist, security findings are downgraded to INFO severity
to reduce false positives for well-established, widely-used models.
"""

from modelaudit.whitelists.huggingface_popular import (
    POPULAR_MODELS,
    is_popular_model,
)

__all__ = [
    "POPULAR_MODELS",
    "is_popular_model",
]
