#!/usr/bin/env python3
"""
Script to generate llm-context.txt with README and all modelaudit source code.
Estimates token count to stay within Claude 4's context limits (~200k tokens).
"""

import fnmatch
import sys
from pathlib import Path


def estimate_tokens(text: str) -> int:
    """Rough estimation: ~4 characters per token for code/text."""
    return len(text) // 4


def should_include_file(file_path: Path, excluded_patterns: list[str]) -> bool:
    """Check if file should be included based on exclusion patterns."""
    file_str = str(file_path)
    return all(not fnmatch.fnmatch(file_str, pattern) for pattern in excluded_patterns)


def collect_python_files(directory: Path, excluded_patterns: list[str]) -> list[Path]:
    """Recursively collect all Python files in directory."""
    python_files = []
    for file_path in directory.rglob("*.py"):
        if should_include_file(file_path, excluded_patterns):
            python_files.append(file_path)
    return sorted(python_files)


def read_file_safe(file_path: Path) -> str:
    """Safely read file content with proper encoding handling."""
    try:
        with open(file_path, encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        try:
            with open(file_path, encoding="latin-1") as f:
                return f.read()
        except Exception as e:
            return f"# ERROR: Could not read {file_path}: {e}\n"
    except Exception as e:
        return f"# ERROR: Could not read {file_path}: {e}\n"


def generate_context_file(
    output_path: str = "llm-context.txt",
    max_tokens: int = 180000,
):
    """Generate the LLM context file with README and source code."""

    # Get project root (parent of scripts directory)
    project_root = Path(__file__).parent.parent

    # Files/patterns to exclude
    excluded_patterns = [
        "*/tests/*",  # Test files
        "*/__pycache__/*",  # Python cache
        "*/.*",  # Hidden files
        "*/htmlcov/*",  # Coverage reports
        "*/scratch/*",  # Scratch directory
        "*/examples/*",  # Example files (can include if needed)
        "*.pyc",  # Compiled Python
        "*.pyo",  # Optimized Python
        "*/.git/*",  # Git files
    ]

    content_parts = []
    total_tokens = 0

    # Add header
    header = """# ModelAudit - LLM Context File
# Generated automatically - contains README and all source code
# This file provides complete context for AI assistants working with the ModelAudit codebase

"""
    content_parts.append(header)
    total_tokens += estimate_tokens(header)

    # Add README
    readme_path = project_root / "README.md"
    if readme_path.exists():
        readme_content = read_file_safe(readme_path)
        readme_section = f"""
## README.md

{readme_content}

"""
        content_parts.append(readme_section)
        tokens = estimate_tokens(readme_section)
        total_tokens += tokens
        print(f"Added README.md: {tokens:,} tokens")

    # Add project structure overview
    structure_content = """
## Project Structure Overview

The ModelAudit project is organized as follows:

- `modelaudit/` - Main package directory
  - `__init__.py` - Package initialization and version info
  - `cli.py` - Command-line interface implementation
  - `core.py` - Core scanning logic and orchestration
  - `explanations.py` - Detailed explanations for findings
  - `license_checker.py` - License compliance checking
  - `sbom.py` - Software Bill of Materials generation
  - `suspicious_symbols.py` - Database of suspicious patterns
  - `auth/` - Authentication utilities
  - `name_policies/` - Model name policy enforcement
    - `blacklist.py` - Blacklist-based name filtering
  - `scanners/` - Individual format scanners
    - `base.py` - Base scanner interface and result classes
    - `*_scanner.py` - Format-specific scanners (pickle, pytorch, etc.)
  - `utils/` - Utility functions
    - `filetype.py` - File type detection and validation

## Source Code

"""
    content_parts.append(structure_content)
    total_tokens += estimate_tokens(structure_content)

    # Collect all Python files from modelaudit package
    modelaudit_dir = project_root / "modelaudit"
    if not modelaudit_dir.exists():
        print(f"ERROR: modelaudit directory not found at {modelaudit_dir}")
        return

    python_files = collect_python_files(modelaudit_dir, excluded_patterns)

    # Sort files by importance/dependency order
    file_priority = {
        "__init__.py": 0,
        "core.py": 1,
        "cli.py": 2,
        "base.py": 3,
        "filetype.py": 4,
    }

    def get_priority(file_path: Path) -> int:
        filename = file_path.name
        return file_priority.get(filename, 10)

    python_files.sort(key=get_priority)

    print(f"Found {len(python_files)} Python files to include")

    # Add each Python file
    for file_path in python_files:
        if total_tokens > max_tokens:
            print(
                f"WARNING: Approaching token limit ({total_tokens:,}/{max_tokens:,}), stopping",
            )
            break

        relative_path = file_path.relative_to(project_root)
        file_content = read_file_safe(file_path)

        file_section = f"""
### {relative_path}

```python
{file_content}
```

"""

        tokens = estimate_tokens(file_section)
        if total_tokens + tokens > max_tokens:
            print(f"WARNING: Adding {relative_path} would exceed token limit, skipping")
            continue

        content_parts.append(file_section)
        total_tokens += tokens
        print(f"Added {relative_path}: {tokens:,} tokens (total: {total_tokens:,})")

    # Add footer with summary
    footer = f"""
## Summary

This context file contains:
- Complete README documentation
- All {len(python_files)} Python source files from the modelaudit package
- Estimated total tokens: {total_tokens:,}

The ModelAudit tool is a security scanner for AI/ML models that detects:
- Malicious code execution in pickled models
- Suspicious TensorFlow operations
- Dangerous pickle opcodes
- License compliance issues
- And many other security risks across different model formats

For development, testing, and deployment information, refer to the README section above.
"""

    content_parts.append(footer)
    total_tokens += estimate_tokens(footer)

    # Write the complete file
    output_file = project_root / output_path
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("".join(content_parts))
        print(f"\n✓ Successfully generated {output_path}")
        print(f"✓ Total estimated tokens: {total_tokens:,}")
        print(f"✓ File size: {output_file.stat().st_size:,} bytes")

        if total_tokens > max_tokens:
            print(
                f"⚠️  WARNING: Estimated tokens ({total_tokens:,}) exceed target limit ({max_tokens:,})",
            )
        else:
            print(f"✓ Within token limit ({max_tokens:,})")

    except Exception as e:
        print(f"ERROR: Failed to write {output_path}: {e}")
        return False

    return True


if __name__ == "__main__":
    # Allow custom output filename and token limit from command line
    output_file = sys.argv[1] if len(sys.argv) > 1 else "llm-context.txt"
    token_limit = int(sys.argv[2]) if len(sys.argv) > 2 else 180000

    print(f"Generating LLM context file: {output_file}")
    print(f"Target token limit: {token_limit:,}")
    print("=" * 60)

    success = generate_context_file(output_file, token_limit)
    sys.exit(0 if success else 1)
