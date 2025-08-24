#!/usr/bin/env python3
"""
Script to verify that models listed in models.md still exist.
Updates the Status column to mark unavailable models.
"""

import re
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import requests
from urllib.parse import urlparse


def check_huggingface_repo(repo_name: str) -> bool:
    """Check if a Hugging Face repository exists."""
    if not repo_name:
        return False
    
    # Clean up repo name - remove any prefixes like 'hf://' 
    repo_name = repo_name.replace('hf://', '').strip()
    
    # Skip if it looks like a URL or local path
    if repo_name.startswith(('http', '/', '.', 'tfhub.dev')):
        return True  # Assume external URLs are valid for now
    
    url = f"https://huggingface.co/{repo_name}"
    try:
        response = requests.head(url, timeout=10)
        # 200 = exists, 302 = redirect (might still exist), 404 = not found
        return response.status_code in [200, 302]
    except requests.exceptions.RequestException:
        return False


def check_local_file(file_path: str) -> bool:
    """Check if a local file exists."""
    if not file_path or file_path.startswith(('http', 'hf://')):
        return True  # Not a local file
    
    # Handle conceptual scikit-learn models (these are examples, not real files)
    if file_path.startswith('scikit-learn/'):
        return True  # These are conceptual examples
    
    return Path(file_path).exists()


def parse_model_table_row(line: str) -> Optional[Tuple[str, str, str, str, str]]:
    """Parse a markdown table row to extract model info."""
    if not line.strip() or not line.strip().startswith('|'):
        return None
    
    # Split by | and clean up
    parts = [part.strip() for part in line.split('|')[1:-1]]  # Remove empty first/last
    
    if len(parts) < 5:
        return None
    
    # Extract: number, model_name, type, source, status
    try:
        number = parts[0].strip()
        model_name = parts[1].strip().strip('`')  # Remove backticks
        model_type = parts[2].strip()
        source = parts[3].strip()
        status = parts[4].strip()
        
        return number, model_name, model_type, source, status
    except (IndexError, ValueError):
        return None


def verify_model(model_name: str, source: str) -> Tuple[bool, str]:
    """Verify if a model exists based on its source."""
    if source == "Hugging Face":
        exists = check_huggingface_repo(model_name)
        return exists, "Repository not found" if not exists else ""
    elif source == "Local":
        exists = check_local_file(model_name)
        return exists, "File not found" if not exists else ""
    elif source in ["PyTorch Hub", "TF Hub", "External"]:
        # For now, assume these are valid - would need specific API calls
        return True, ""
    elif source == "HF Space":
        # Check if it's a space
        space_name = model_name.replace('hf://', '').strip()
        url = f"https://huggingface.co/spaces/{space_name}"
        try:
            response = requests.head(url, timeout=10)
            exists = response.status_code in [200, 302]
            return exists, "Space not found" if not exists else ""
        except requests.exceptions.RequestException:
            return False, "Space not found"
    else:
        return True, ""  # Unknown source, assume valid


def update_models_md(file_path: str, dry_run: bool = False) -> Dict[str, int]:
    """Update models.md with verification results."""
    stats = {"total": 0, "checked": 0, "failed": 0, "updated": 0}
    
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    new_lines = []
    in_table = False
    
    for line_num, line in enumerate(lines):
        # Detect if we're in a table
        if '| #' in line and '| Model Name' in line:
            in_table = True
            new_lines.append(line)
            continue
        elif line.strip().startswith('##') and in_table:
            in_table = False
        elif not in_table or not line.strip().startswith('|'):
            new_lines.append(line)
            continue
        
        # Skip header separator lines
        if '---' in line:
            new_lines.append(line)
            continue
            
        # Parse table row
        model_info = parse_model_table_row(line)
        if not model_info:
            new_lines.append(line)
            continue
        
        number, model_name, model_type, source, current_status = model_info
        stats["total"] += 1
        
        print(f"Checking {model_name} ({source})...")
        
        # Verify the model
        exists, error_msg = verify_model(model_name, source)
        stats["checked"] += 1
        
        if not exists:
            stats["failed"] += 1
            new_status = "No longer available"
            if error_msg:
                new_status += f" - {error_msg}"
            
            # Update the status column
            parts = line.split('|')
            if len(parts) >= 6:
                parts[5] = f" {new_status} "  # Status column
                new_line = '|'.join(parts)
                new_lines.append(new_line)
                stats["updated"] += 1
                print(f"  ❌ MARKED AS UNAVAILABLE: {model_name}")
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
            print(f"  ✅ Available: {model_name}")
        
        # Add a small delay to avoid rate limiting
        time.sleep(0.1)
    
    # Write the updated file
    if not dry_run and stats["updated"] > 0:
        with open(file_path, 'w') as f:
            f.writelines(new_lines)
        print(f"\nUpdated {file_path}")
    
    return stats


def main():
    # Get the project root (parent of scripts directory)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    models_md_path = project_root / "docs" / "models.md"
    
    if not os.path.exists(models_md_path):
        print(f"Error: {models_md_path} not found")
        sys.exit(1)
    
    print("Starting model verification...")
    print(f"Checking models in: {models_md_path}")
    print("-" * 50)
    
    # Run verification
    dry_run = '--dry-run' in sys.argv
    if dry_run:
        print("DRY RUN MODE - No changes will be made")
    
    stats = update_models_md(models_md_path, dry_run=dry_run)
    
    print("\n" + "=" * 50)
    print("VERIFICATION SUMMARY")
    print("=" * 50)
    print(f"Total models found: {stats['total']}")
    print(f"Models checked: {stats['checked']}")
    print(f"Failed/unavailable: {stats['failed']}")
    print(f"Status updates made: {stats['updated']}")
    
    if stats['failed'] > 0:
        print(f"\n⚠️  {stats['failed']} models are no longer available")
    else:
        print("\n✅ All models are available")


if __name__ == "__main__":
    main()