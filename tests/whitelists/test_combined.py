"""Tests for combined whitelist functionality."""

from modelaudit.whitelists import (
    ALL_WHITELISTED_MODELS,
    ORGANIZATION_MODELS,
    POPULAR_MODELS,
    is_whitelisted_model,
)


class TestCombinedWhitelist:
    """Tests for the combined whitelist."""

    def test_all_whitelisted_models_is_union(self):
        """Test that ALL_WHITELISTED_MODELS is the union of both whitelists."""
        assert ALL_WHITELISTED_MODELS == POPULAR_MODELS | ORGANIZATION_MODELS

    def test_all_whitelisted_models_count(self):
        """Test that the combined whitelist has a significant number of models."""
        # Should have at least 6000+ models (540 popular + 6900 org)
        assert len(ALL_WHITELISTED_MODELS) >= 6000

    def test_is_whitelisted_model_popular(self):
        """Test that popular models are whitelisted."""
        # Get a model from the popular whitelist
        if POPULAR_MODELS:
            popular_model = next(iter(POPULAR_MODELS))
            assert is_whitelisted_model(popular_model)

    def test_is_whitelisted_model_organization(self):
        """Test that organization models are whitelisted."""
        # Get a model from the organization whitelist
        if ORGANIZATION_MODELS:
            org_model = next(iter(ORGANIZATION_MODELS))
            assert is_whitelisted_model(org_model)

    def test_is_whitelisted_model_unknown(self):
        """Test that unknown models are not whitelisted."""
        assert not is_whitelisted_model("unknown-author/unknown-model-12345")

    def test_is_whitelisted_model_none(self):
        """Test that None returns False."""
        assert not is_whitelisted_model(None)

    def test_is_whitelisted_model_empty_string(self):
        """Test that empty string returns False."""
        assert not is_whitelisted_model("")

    def test_no_overlap_creates_larger_set(self):
        """Test that combining sets creates a properly sized whitelist."""
        # The combined set should be at least as large as the larger of the two
        assert len(ALL_WHITELISTED_MODELS) >= max(len(POPULAR_MODELS), len(ORGANIZATION_MODELS))
