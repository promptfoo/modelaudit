#!/usr/bin/env python3
"""
Script to fetch the top N models from HuggingFace by downloads.

This script queries the HuggingFace API to get the most popular models
and generates a whitelist module that can be used by ModelAudit to
downgrade security findings for well-established, widely-used models.

Usage:
    python scripts/fetch_hf_top_models.py --count 2000 --output modelaudit/whitelists/huggingface_popular.py
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def fetch_models_page(page: int, sort: str = "downloads") -> dict[str, Any]:
    """Fetch a single page of models from HuggingFace API."""
    url = f"https://huggingface.co/models-json?p={page}&sort={sort}&withCount=true"

    try:
        req = Request(url, headers={"User-Agent": "ModelAudit/1.0"})
        with urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except (URLError, HTTPError) as e:
        print(f"Error fetching page {page}: {e}", file=sys.stderr)
        raise


def fetch_top_models(count: int) -> list[str]:
    """
    Fetch the top N models from HuggingFace by downloads.

    Args:
        count: Number of top models to fetch

    Returns:
        List of model IDs (e.g., "author/model-name")
    """
    models_per_page = 30  # HuggingFace API returns 30 models per page
    pages_needed = (count + models_per_page - 1) // models_per_page

    model_ids = []

    print(f"Fetching top {count} models from HuggingFace...")
    print(f"Will fetch {pages_needed} pages ({models_per_page} models per page)")

    for page in range(pages_needed):
        print(f"Fetching page {page + 1}/{pages_needed}...", end=" ")
        try:
            data = fetch_models_page(page)
            models = data.get("models", [])

            for model in models:
                if len(model_ids) >= count:
                    break
                model_id = model.get("id")
                if model_id:
                    model_ids.append(model_id)

            print(f"✓ ({len(model_ids)} total)")

            if len(model_ids) >= count:
                break

        except Exception as e:
            print(f"✗ Error: {e}", file=sys.stderr)
            continue

    print(f"\nSuccessfully fetched {len(model_ids)} model IDs")
    return model_ids[:count]


def generate_whitelist_module(model_ids: list[str], output_path: Path) -> None:
    """
    Generate a Python module containing the whitelist.

    Args:
        model_ids: List of model IDs to whitelist
        output_path: Path where the module should be written
    """
    # Ensure parent directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate the module content
    content = f'''"""
HuggingFace Popular Models Whitelist

This module contains a whitelist of the top {len(model_ids)} most downloaded models
from HuggingFace. These models are widely used and trusted by the community,
so security findings for these models are downgraded to INFO severity.

Generated: {datetime.utcnow().isoformat()}Z
Source: https://huggingface.co/models-json?sort=downloads
Total models: {len(model_ids)}

This whitelist is used by ModelAudit to reduce false positives when scanning
popular, well-established models. Users can disable this behavior via the
'use_hf_whitelist' configuration option.
"""

# Set of model IDs (author/model-name format)
POPULAR_MODELS: set[str] = {{
'''

    # Add model IDs (sorted for readability and diff-friendliness)
    sorted_models = sorted(model_ids)
    for model_id in sorted_models:
        # Escape quotes in model IDs if any
        escaped_id = model_id.replace('"', '\\"')
        content += f'    "{escaped_id}",\n'

    content += '''}


def is_popular_model(model_id: str | None) -> bool:
    """
    Check if a model ID is in the popular models whitelist.

    Args:
        model_id: HuggingFace model ID (e.g., "bert-base-uncased" or "openai/whisper-large")

    Returns:
        True if the model is in the whitelist, False otherwise
    """
    if not model_id:
        return False

    # Normalize the model ID (remove any revision/branch info)
    # e.g., "author/model@main" -> "author/model"
    normalized_id = model_id.split('@')[0].strip()

    return normalized_id in POPULAR_MODELS
'''

    # Write the module
    with open(output_path, "w") as f:
        f.write(content)

    print(f"\nWhitelist module written to: {output_path}")
    print(f"Total models: {len(model_ids)}")


def main():
    parser = argparse.ArgumentParser(description="Fetch top HuggingFace models and generate whitelist module")
    parser.add_argument("--count", type=int, default=2000, help="Number of top models to fetch (default: 2000)")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("modelaudit/whitelists/huggingface_popular.py"),
        help="Output path for the whitelist module",
    )

    args = parser.parse_args()

    try:
        # Fetch the models
        model_ids = fetch_top_models(args.count)

        if not model_ids:
            print("Error: No models fetched!", file=sys.stderr)
            sys.exit(1)

        # Generate the module
        generate_whitelist_module(model_ids, args.output)

        print("\n✓ Done!")

    except KeyboardInterrupt:
        print("\n\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
