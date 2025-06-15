from typing import Optional

BLACKLIST_PATTERNS = [
    # Examples of patterns you might want to blacklist
    "malicious",
    "unsafe",
    # Add more patterns as needed
]


def check_model_name_policies(
    model_name: str,
    additional_patterns: Optional[list[str]] = None,
) -> tuple[bool, str]:
    """
    Return (blocked:boolean, reason:str) if model_name matches any pattern in
    the blacklist.

    Args:
        model_name: The name of the model to check
        additional_patterns: Optional list of additional patterns to check against
    """
    name_lower = model_name.lower()

    # Combine default patterns with any additional patterns
    patterns = list(BLACKLIST_PATTERNS)
    if additional_patterns:
        patterns.extend(additional_patterns)

    for pattern in patterns:
        if pattern.lower() in name_lower:
            return True, f"Model name matched blacklist pattern: {pattern}"
    return False, ""
