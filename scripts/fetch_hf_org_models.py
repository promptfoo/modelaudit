#!/usr/bin/env python3
"""
Script to fetch models from trusted HuggingFace organizations.

This script queries the HuggingFace API to get all models from trusted
organizations (like hf-internal-testing, facebook, google, etc.) and
generates a whitelist module.

Usage:
    python scripts/fetch_hf_org_models.py --output modelaudit/whitelists/huggingface_organizations.py
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# List of trusted organizations whose models should be whitelisted
TRUSTED_ORGANIZATIONS = [
    "hf-internal-testing",  # HuggingFace's internal testing models
    "facebook",  # Meta/Facebook AI
    "FacebookAI",  # Meta/Facebook AI (alternative name)
    "google",  # Google AI
    "openai",  # OpenAI
    "microsoft",  # Microsoft
    "huggingface",  # HuggingFace's own models
    "stabilityai",  # Stability AI
    "EleutherAI",  # EleutherAI
    "bigscience",  # BigScience
    "nvidia",  # NVIDIA
    "meta-llama",  # Meta's LLaMA models
    "mistralai",  # Mistral AI
    "anthropic",  # Anthropic (Claude)
    "sentence-transformers",  # Sentence Transformers
    "bert-base-uncased",  # BERT models
    "OpenAssistant",  # Open Assistant
    "bigcode",  # BigCode
    "tiiuae",  # Technology Innovation Institute (Falcon)
    "CompVis",  # Computer Vision models (Stable Diffusion)
]


def fetch_organization_models_page(org: str, page: int) -> dict[str, Any]:
    """Fetch a single page of models from a HuggingFace organization."""
    url = f"https://huggingface.co/api/organizations/{org}/models-json?p={page}&sort=modified&withCount=true"

    try:
        req = Request(url, headers={"User-Agent": "ModelAudit/1.0"})
        with urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as e:
        if e.code == 404:
            # Organization doesn't exist or has no models
            print(f"Organization '{org}' not found", file=sys.stderr)
            return {"models": [], "numTotalItems": 0}
        print(f"Error fetching page {page} for org '{org}': {e}", file=sys.stderr)
        raise
    except (URLError, Exception) as e:
        print(f"Error fetching page {page} for org '{org}': {e}", file=sys.stderr)
        raise


def fetch_organization_models(org: str, max_models: int | None = None) -> list[str]:
    """
    Fetch all models from a HuggingFace organization.

    Args:
        org: Organization name
        max_models: Maximum number of models to fetch (None = all)

    Returns:
        List of model IDs
    """
    models_per_page = 30
    model_ids = []

    print(f"\nFetching models from organization: {org}")

    try:
        # Get first page to determine total count
        first_page = fetch_organization_models_page(org, 0)
        total_count = first_page.get("numTotalItems", 0)

        if total_count == 0:
            print(f"  No models found for organization '{org}'")
            return []

        # Determine how many models to fetch
        target_count = min(total_count, max_models) if max_models else total_count
        pages_needed = (target_count + models_per_page - 1) // models_per_page

        print(f"  Total models: {total_count}, fetching: {target_count}")
        print(f"  Fetching {pages_needed} pages...")

        # Process first page
        for model in first_page.get("models", []):
            if max_models and len(model_ids) >= max_models:
                break
            model_id = model.get("id")
            if model_id:
                model_ids.append(model_id)

        # Fetch remaining pages
        for page in range(1, pages_needed):
            if max_models and len(model_ids) >= max_models:
                break

            print(f"  Fetching page {page + 1}/{pages_needed}...", end=" ")
            try:
                data = fetch_organization_models_page(org, page)
                models = data.get("models", [])

                for model in models:
                    if max_models and len(model_ids) >= max_models:
                        break
                    model_id = model.get("id")
                    if model_id:
                        model_ids.append(model_id)

                print(f"✓ ({len(model_ids)} total)")

            except Exception as e:
                print(f"✗ Error: {e}", file=sys.stderr)
                continue

        print(f"  Successfully fetched {len(model_ids)} model IDs from '{org}'")
        return model_ids

    except Exception as e:
        print(f"  Error fetching models from '{org}': {e}", file=sys.stderr)
        return []


def fetch_all_organizations(organizations: list[str], max_per_org: int | None = None) -> dict[str, list[str]]:
    """
    Fetch models from multiple organizations.

    Args:
        organizations: List of organization names
        max_per_org: Maximum models per organization (None = all)

    Returns:
        Dictionary mapping org name to list of model IDs
    """
    all_models: dict[str, list[str]] = {}

    print(f"Fetching models from {len(organizations)} organizations...")

    for org in organizations:
        models = fetch_organization_models(org, max_per_org)
        if models:
            all_models[org] = models

    return all_models


def generate_whitelist_module(org_models: dict[str, list[str]], output_path: Path) -> None:
    """
    Generate a Python module containing the organization whitelist.

    Args:
        org_models: Dictionary mapping org name to model IDs
        output_path: Path where the module should be written
    """
    # Ensure parent directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Flatten all model IDs into a single set (remove duplicates)
    all_model_ids = set()
    for models in org_models.values():
        all_model_ids.update(models)

    # Generate statistics
    total_orgs = len(org_models)
    total_models = len(all_model_ids)
    org_summary = "\n".join(f"  - {org}: {len(models)} models" for org, models in sorted(org_models.items()))

    # Generate the module content
    content = f'''"""
HuggingFace Trusted Organizations Whitelist

This module contains a whitelist of models from trusted HuggingFace organizations.
These organizations are well-established and their models are considered safe,
so security findings for these models are downgraded to INFO severity.

Generated: {datetime.utcnow().isoformat()}Z
Source: HuggingFace Organizations API
Total organizations: {total_orgs}
Total unique models: {total_models}

Organizations included:
{org_summary}

This whitelist is used by ModelAudit to reduce false positives when scanning
models from trusted organizations. Users can disable this behavior via the
'use_hf_whitelist' configuration option.
"""

# Set of model IDs from trusted organizations
ORGANIZATION_MODELS: set[str] = {{
'''

    # Add model IDs (sorted for readability and diff-friendliness)
    sorted_models = sorted(all_model_ids)
    for model_id in sorted_models:
        # Escape quotes in model IDs if any
        escaped_id = model_id.replace('"', '\\"')
        content += f'    "{escaped_id}",\n'

    content += '''}


def is_from_trusted_organization(model_id: str | None) -> bool:
    """
    Check if a model ID is from a trusted organization.

    Args:
        model_id: HuggingFace model ID (e.g., "hf-internal-testing/tiny-bert")

    Returns:
        True if the model is from a trusted organization, False otherwise
    """
    if not model_id:
        return False

    # Normalize the model ID (remove any revision/branch info)
    # e.g., "author/model@main" -> "author/model"
    normalized_id = model_id.split("@")[0].strip()

    return normalized_id in ORGANIZATION_MODELS
'''

    # Write the module
    with open(output_path, "w") as f:
        f.write(content)

    print(f"\nWhitelist module written to: {output_path}")
    print(f"Total organizations: {total_orgs}")
    print(f"Total unique models: {total_models}")


def main():
    parser = argparse.ArgumentParser(
        description="Fetch models from trusted HuggingFace organizations and generate whitelist module"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("modelaudit/whitelists/huggingface_organizations.py"),
        help="Output path for the whitelist module",
    )
    parser.add_argument(
        "--max-per-org",
        type=int,
        default=None,
        help="Maximum models to fetch per organization (default: all)",
    )
    parser.add_argument(
        "--orgs",
        nargs="+",
        default=TRUSTED_ORGANIZATIONS,
        help="List of organizations to fetch (default: predefined trusted list)",
    )

    args = parser.parse_args()

    try:
        # Fetch models from organizations
        org_models = fetch_all_organizations(args.orgs, args.max_per_org)

        if not org_models:
            print("Error: No models fetched from any organization!", file=sys.stderr)
            sys.exit(1)

        # Generate the module
        generate_whitelist_module(org_models, args.output)

        print("\n✓ Done!")

    except KeyboardInterrupt:
        print("\n\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
