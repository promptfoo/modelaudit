import io
import pickle
from pathlib import Path

OUTPUT_DIR = Path("tests/assets/pickles")


def generate_stack_global_attack() -> None:
    """Generate pickle that uses STACK_GLOBAL to obfuscate os.system."""

    class StackGlobalAttack:
        def __reduce__(self):
            return (__import__("os").system, ("# STACK_GLOBAL_PAYLOAD",))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with (OUTPUT_DIR / "stack_global_attack.pkl").open("wb") as f:
        pickle.dump(StackGlobalAttack(), f, protocol=pickle.HIGHEST_PROTOCOL)


def generate_memo_based_attack() -> None:
    """Generate pickle that uses memo objects to hide malicious references."""

    class MemoAttack:
        def __reduce__(self):
            dangerous_module = __import__("subprocess")
            # Use inert command vector; still references subprocess.call for scanner coverage
            return (dangerous_module.call, (["#", "MEMO_ATTACK_PAYLOAD"],))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with (OUTPUT_DIR / "memo_attack.pkl").open("wb") as f:
        pickle.dump(MemoAttack(), f, protocol=pickle.HIGHEST_PROTOCOL)


def generate_multiple_pickle_attack() -> None:
    """Generate file with multiple pickle streams."""

    buffer = io.BytesIO()

    safe_data = {"model": "safe_weights"}
    pickle.dump(safe_data, buffer)

    class HiddenAttack:
        def __reduce__(self):
            return (eval, ("'HIDDEN_ATTACK_PAYLOAD'",))

    pickle.dump(HiddenAttack(), buffer)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with (OUTPUT_DIR / "multiple_stream_attack.pkl").open("wb") as f:
        f.write(buffer.getvalue())
