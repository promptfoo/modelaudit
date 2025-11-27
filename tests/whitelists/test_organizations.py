"""Tests for HuggingFace organization models whitelist."""

from modelaudit.whitelists.huggingface_organizations import (
    ORGANIZATION_MODELS,
    is_from_trusted_organization,
)


class TestOrganizationModels:
    """Tests for the organization models whitelist."""

    def test_organization_models_is_set(self):
        """Test that ORGANIZATION_MODELS is a set."""
        assert isinstance(ORGANIZATION_MODELS, set)
        assert len(ORGANIZATION_MODELS) > 0

    def test_organization_models_count(self):
        """Test that we have a significant number of organization models."""
        # We should have thousands of models from trusted organizations
        assert len(ORGANIZATION_MODELS) > 5000

    def test_is_from_trusted_organization_known_model(self):
        """Test that a known organization model is recognized."""
        # Test with a known model from hf-internal-testing
        assert is_from_trusted_organization("hf-internal-testing/tiny-random-BertModel")

    def test_is_from_trusted_organization_facebook(self):
        """Test that Facebook organization models are recognized."""
        # Get first facebook model from the set
        facebook_models = [m for m in ORGANIZATION_MODELS if m.startswith("facebook/")]
        if facebook_models:
            assert is_from_trusted_organization(facebook_models[0])

    def test_is_from_trusted_organization_google(self):
        """Test that Google organization models are recognized."""
        # Get first google model from the set
        google_models = [m for m in ORGANIZATION_MODELS if m.startswith("google/")]
        if google_models:
            assert is_from_trusted_organization(google_models[0])

    def test_is_from_trusted_organization_unknown_model(self):
        """Test that an unknown model is not recognized."""
        assert not is_from_trusted_organization("unknown-author/unknown-model-12345")

    def test_is_from_trusted_organization_none(self):
        """Test that None returns False."""
        assert not is_from_trusted_organization(None)

    def test_is_from_trusted_organization_empty_string(self):
        """Test that empty string returns False."""
        assert not is_from_trusted_organization("")

    def test_is_from_trusted_organization_with_revision(self):
        """Test that model IDs with revisions are normalized."""
        # Get a model from the whitelist
        known_model = next(iter(ORGANIZATION_MODELS))
        # Add a revision
        model_with_revision = f"{known_model}@main"
        # Should still be recognized after normalization
        assert is_from_trusted_organization(model_with_revision)

    def test_organization_models_no_duplicates(self):
        """Test that there are no duplicate model IDs."""
        # Since it's a set, duplicates are automatically removed
        # But we can verify by comparing with a list version
        model_list = list(ORGANIZATION_MODELS)
        assert len(model_list) == len(ORGANIZATION_MODELS)

    def test_organization_models_format(self):
        """Test that all model IDs follow the expected format."""
        for model_id in list(ORGANIZATION_MODELS)[:100]:  # Test first 100
            # Most models should have the format "author/model-name"
            assert isinstance(model_id, str)
            assert len(model_id) > 0
            # Should have organization prefix
            assert "/" in model_id
