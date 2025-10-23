"""
Model whitelists for reducing false positives.

This package contains whitelists of trusted models from various sources.
When a model is on a whitelist, security findings are downgraded to INFO severity
to reduce false positives for well-established, widely-used models.

Whitelist sources:
1. Popular models - Top downloaded models from HuggingFace
2. Trusted organizations - Models from verified organizations (Meta, Google, Microsoft, etc.)
"""

from modelaudit.whitelists.huggingface_organizations import (
    ORGANIZATION_MODELS,
    is_from_trusted_organization,
)
from modelaudit.whitelists.huggingface_popular import (
    POPULAR_MODELS,
    is_popular_model,
)

# Combine both whitelists into a single set
ALL_WHITELISTED_MODELS = POPULAR_MODELS | ORGANIZATION_MODELS


def is_whitelisted_model(model_id: str | None) -> bool:
    """
    Check if a model ID is whitelisted (either popular or from trusted organization).

    Args:
        model_id: HuggingFace model ID (e.g., "bert-base-uncased")

    Returns:
        True if the model is whitelisted, False otherwise
    """
    # Check both lists
    return is_popular_model(model_id) or is_from_trusted_organization(model_id)


__all__ = [
    "ALL_WHITELISTED_MODELS",
    "ORGANIZATION_MODELS",
    "POPULAR_MODELS",
    "is_from_trusted_organization",
    "is_popular_model",
    "is_whitelisted_model",
]
