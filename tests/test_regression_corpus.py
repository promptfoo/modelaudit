"""Regression corpus validation.

Runs the scanner against committed malicious and benign test fixtures to ensure
detection accuracy does not regress. Every malicious fixture must produce at
least one issue. Every safe fixture must scan clean (success=True).

Marked as ``regression`` so CI can run this as a dedicated gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from modelaudit.core import scan_file

ASSETS = Path(__file__).parent / "assets"
EXPLOITS_DIR = ASSETS / "exploits"
SAFE_PICKLES_DIR = ASSETS / "samples" / "pickles"
MALICIOUS_PICKLES_DIR = ASSETS / "samples" / "pickles"
SAFE_SAFETENSORS_DIR = ASSETS / "samples" / "safetensors"
SAFE_PYTORCH_DIR = ASSETS / "samples" / "pytorch"
SAFE_ARCHIVES_DIR = ASSETS / "samples" / "archives"

# --- Malicious fixtures that MUST be detected ---

EXPLOIT_FILES = sorted(EXPLOITS_DIR.glob("*.pkl")) if EXPLOITS_DIR.exists() else []

MALICIOUS_PICKLE_NAMES = [
    "malicious_system_call.pkl",
    "malicious_model_realistic.pkl",
    "decode_exec_chain.pkl",
    "evil.pickle",
    "nested_pickle_raw.pkl",
    "nested_pickle_hex.pkl",
    "nested_pickle_base64.pkl",
    "nested_pickle_multistage.pkl",
]
MALICIOUS_PICKLE_FILES = [
    MALICIOUS_PICKLES_DIR / name for name in MALICIOUS_PICKLE_NAMES if (MALICIOUS_PICKLES_DIR / name).exists()
]

MALICIOUS_SAFETENSORS = [p for p in [SAFE_SAFETENSORS_DIR / "malicious_import.safetensors"] if p.exists()]

MALICIOUS_PYTORCH = [p for p in [SAFE_PYTORCH_DIR / "malicious_eval.pt"] if p.exists()]

MALICIOUS_ARCHIVES = [p for p in [SAFE_ARCHIVES_DIR / "path_traversal.zip"] if p.exists()]

ALL_MALICIOUS = EXPLOIT_FILES + MALICIOUS_PICKLE_FILES + MALICIOUS_SAFETENSORS + MALICIOUS_PYTORCH + MALICIOUS_ARCHIVES

# --- Safe fixtures that MUST scan clean ---

SAFE_PICKLE_NAMES = [
    "safe_data.pkl",
    "safe_large_model.pkl",
    "safe_model_with_binary.pkl",
    "safe_model_with_encoding.pkl",
    "safe_model_with_tokens.pkl",
    "safe_nested_structure.pkl",
]
SAFE_PICKLE_FILES = [SAFE_PICKLES_DIR / name for name in SAFE_PICKLE_NAMES if (SAFE_PICKLES_DIR / name).exists()]

SAFE_SAFETENSORS = [p for p in [SAFE_SAFETENSORS_DIR / "safe_model.safetensors"] if p.exists()]

SAFE_PYTORCH = [p for p in [SAFE_PYTORCH_DIR / "safe_model.pt"] if p.exists()]

SAFE_ARCHIVES = [p for p in [SAFE_ARCHIVES_DIR / "safe_model.zip"] if p.exists()]

ALL_SAFE = SAFE_PICKLE_FILES + SAFE_SAFETENSORS + SAFE_PYTORCH + SAFE_ARCHIVES


def _file_id(path: Path) -> str:
    """Generate a short test ID from a fixture path."""
    return f"{path.parent.name}/{path.name}"


# ---------------------------------------------------------------------------
# Malicious corpus: every file must produce at least one issue
# ---------------------------------------------------------------------------


@pytest.mark.regression
class TestMaliciousCorpus:
    """Every malicious fixture must be detected."""

    @pytest.mark.parametrize("path", ALL_MALICIOUS, ids=[_file_id(p) for p in ALL_MALICIOUS])
    def test_malicious_file_detected(self, path: Path) -> None:
        result = scan_file(str(path))
        assert result.issues, f"No issues detected for malicious file: {path.name}"


# ---------------------------------------------------------------------------
# Safe corpus: every file must scan clean
# ---------------------------------------------------------------------------


@pytest.mark.regression
class TestSafeCorpus:
    """Every safe fixture must scan clean."""

    @pytest.mark.parametrize("path", ALL_SAFE, ids=[_file_id(p) for p in ALL_SAFE])
    def test_safe_file_clean(self, path: Path) -> None:
        result = scan_file(str(path))
        assert result.success, f"Safe file failed scan: {path.name} — issues: {result.issues}"
