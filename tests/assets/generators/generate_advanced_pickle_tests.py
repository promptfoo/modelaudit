import io
import pickle


def generate_stack_global_attack() -> None:
    """Generate pickle that uses STACK_GLOBAL to obfuscate os.system."""

    class StackGlobalAttack:
        def __reduce__(self):
            return (__import__("os").system, ("echo pwned",))

    with open("tests/assets/pickles/stack_global_attack.pkl", "wb") as f:
        pickle.dump(StackGlobalAttack(), f)


def generate_memo_based_attack() -> None:
    """Generate pickle that uses memo objects to hide malicious references."""

    class MemoAttack:
        def __reduce__(self):
            dangerous_module = __import__("subprocess")
            return (dangerous_module.call, (["echo", "memo_attack"],))

    with open("tests/assets/pickles/memo_attack.pkl", "wb") as f:
        pickle.dump(MemoAttack(), f)


def generate_multiple_pickle_attack() -> None:
    """Generate file with multiple pickle streams."""

    buffer = io.BytesIO()

    safe_data = {"model": "safe_weights"}
    pickle.dump(safe_data, buffer)

    class HiddenAttack:
        def __reduce__(self):
            return (eval, ("__import__('os').system('hidden_attack')",))

    pickle.dump(HiddenAttack(), buffer)

    with open("tests/assets/pickles/multiple_stream_attack.pkl", "wb") as f:
        f.write(buffer.getvalue())
