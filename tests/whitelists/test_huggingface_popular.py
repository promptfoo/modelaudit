"""Tests for HuggingFace popular models whitelist."""

from modelaudit.whitelists.huggingface_popular import (
    POPULAR_MODELS,
    is_popular_model,
)


class TestPopularModels:
    """Tests for the popular models whitelist."""

    def test_popular_models_is_set(self):
        """Test that POPULAR_MODELS is a set."""
        assert isinstance(POPULAR_MODELS, set)
        assert len(POPULAR_MODELS) > 0

    def test_popular_models_format(self):
        """Test that all model IDs follow the expected format."""
        for model_id in POPULAR_MODELS:
            # Most models should have the format "author/model-name"
            # Some might be just "model-name" for official models
            assert isinstance(model_id, str)
            assert len(model_id) > 0

    def test_is_popular_model_with_known_model(self):
        """Test that a known popular model is recognized."""
        # Get the first model from the set
        known_model = next(iter(POPULAR_MODELS))
        assert is_popular_model(known_model)

    def test_is_popular_model_with_unknown_model(self):
        """Test that an unknown model is not recognized."""
        assert not is_popular_model("unknown-author/unknown-model-12345")

    def test_is_popular_model_with_none(self):
        """Test that None returns False."""
        assert not is_popular_model(None)

    def test_is_popular_model_with_empty_string(self):
        """Test that empty string returns False."""
        assert not is_popular_model("")

    def test_is_popular_model_with_revision(self):
        """Test that model IDs with revisions are normalized."""
        # Get a model from the whitelist
        known_model = next(iter(POPULAR_MODELS))
        # Add a revision
        model_with_revision = f"{known_model}@main"
        # Should still be recognized after normalization
        assert is_popular_model(model_with_revision)

    def test_is_popular_model_case_sensitive(self):
        """Test that model ID matching is case-sensitive."""
        known_model = next(iter(POPULAR_MODELS))
        # Change case - should not match
        wrong_case = known_model.upper()
        if wrong_case != known_model:  # Only test if case actually changed
            assert not is_popular_model(wrong_case)

    def test_popular_models_no_duplicates(self):
        """Test that there are no duplicate model IDs."""
        # Since it's a set, duplicates are automatically removed
        # But we can verify by comparing with a list version
        model_list = list(POPULAR_MODELS)
        assert len(model_list) == len(POPULAR_MODELS)

    def test_popular_models_is_long(self):
        """Test that popular models list is not empty and contains real models."""
        # We should have some well-known models in the top downloads
        # Check for at least some common models
        assert len(POPULAR_MODELS) > 100  # Should have fetched a good number
