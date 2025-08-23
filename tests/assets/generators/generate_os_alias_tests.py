import os
import pickle
import sys
from types import ModuleType


def generate_nt_alias_attack() -> None:
    """Generate pickle using nt module (Windows os alias)."""

    fake_nt = ModuleType("nt")
    fake_nt.system = os.system  # type: ignore[attr-defined]
    sys.modules["nt"] = fake_nt
    try:
        with open("tests/assets/pickles/nt_alias_attack.pkl", "wb") as f:
            pickle.dump(fake_nt.system, f)
    finally:
        del sys.modules["nt"]


def generate_posix_alias_attack() -> None:
    """Generate pickle using posix module (Unix os alias)."""

    fake_posix = ModuleType("posix")
    fake_posix.system = os.system  # type: ignore[attr-defined]
    sys.modules["posix"] = fake_posix
    try:
        with open("tests/assets/pickles/posix_alias_attack.pkl", "wb") as f:
            pickle.dump(fake_posix.system, f)
    finally:
        del sys.modules["posix"]


if __name__ == "__main__":
    generate_nt_alias_attack()
    generate_posix_alias_attack()
