import os
import pickle
from pathlib import Path

OUTPUT_DIR = Path("tests/assets/pickles")


class EvilClass:
    def __reduce__(self):
        # WARNING: For static scanning only. Do NOT unpickle this file.
        # If accidentally unpickled, the argument is a no-op shell comment to reduce risk,
        # but a shell is still spawned. Keep usage limited to bytes-level scanners.
        return (os.system, ("# MALICIOUS_PAYLOAD_PLACEHOLDER",))


def generate_evil_pickle() -> Path:
    """Generate an 'evil' pickle sample for scanner tests (do not unpickle)."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    evil_obj = EvilClass()
    serialized_data = pickle.dumps(evil_obj, protocol=pickle.HIGHEST_PROTOCOL)
    out_path = OUTPUT_DIR / "evil.pkl"
    out_path.write_bytes(serialized_data)
    return out_path


if __name__ == "__main__":
    print(generate_evil_pickle())
