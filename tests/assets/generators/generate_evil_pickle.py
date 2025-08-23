import os
import pickle
from pathlib import Path


class EvilClass:
    def __reduce__(self):
        # This is a malicious example for testing - uses safe placeholder command
        return (os.system, ('echo "MALICIOUS_PAYLOAD_PLACEHOLDER"',))


evil_obj = EvilClass()
serialized_data = pickle.dumps(evil_obj)

with Path("evil.pickle").open("wb") as file:
    file.write(serialized_data)
