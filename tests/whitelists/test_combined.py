"""Tests for model whitelist contents and membership contracts."""

from collections.abc import Callable

import pytest

from modelaudit.whitelists import (
    ALL_WHITELISTED_MODELS,
    ORGANIZATION_MODELS,
    POPULAR_MODELS,
    is_from_trusted_organization,
    is_popular_model,
    is_whitelisted_model,
)


@pytest.mark.parametrize(
    ("models", "predicate", "minimum_count", "requires_author"),
    [
        pytest.param(POPULAR_MODELS, is_popular_model, 101, False, id="popular"),
        pytest.param(ORGANIZATION_MODELS, is_from_trusted_organization, 5001, True, id="organizations"),
        pytest.param(ALL_WHITELISTED_MODELS, is_whitelisted_model, 6000, False, id="combined"),
    ],
)
def test_whitelist_contents(
    models: set[str], predicate: Callable[[str | None], bool], minimum_count: int, requires_author: bool
) -> None:
    assert isinstance(models, set)
    assert len(models) >= minimum_count
    for model_id in sorted(models):
        assert isinstance(model_id, str)
        assert model_id
        if requires_author:
            assert "/" in model_id, model_id
        assert predicate(model_id), model_id
        assert predicate(f"{model_id}@main"), model_id


@pytest.mark.parametrize(
    "predicate",
    [is_popular_model, is_from_trusted_organization, is_whitelisted_model],
    ids=["popular", "organizations", "combined"],
)
@pytest.mark.parametrize("model_id", [None, "", "unknown-author/unknown-model-12345"], ids=["none", "empty", "unknown"])
def test_unknown_models(predicate: Callable[[str | None], bool], model_id: str | None) -> None:
    assert not predicate(model_id)


def test_combined_whitelist_is_union() -> None:
    assert ALL_WHITELISTED_MODELS == POPULAR_MODELS | ORGANIZATION_MODELS


@pytest.mark.parametrize("prefix", ["facebook/", "google/"], ids=["facebook", "google"])
def test_trusted_organization_is_represented(prefix: str) -> None:
    assert any(model_id.startswith(prefix) for model_id in ORGANIZATION_MODELS)


def test_known_organization_model() -> None:
    assert is_from_trusted_organization("hf-internal-testing/tiny-random-BertModel")


def test_popular_model_matching_is_case_sensitive() -> None:
    known_model = min(POPULAR_MODELS)
    wrong_case = known_model.upper()
    assert wrong_case != known_model
    assert wrong_case not in POPULAR_MODELS
    assert not is_popular_model(wrong_case)
