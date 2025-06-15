import os
import pickle
from pathlib import Path


class EvilClass:
    def __reduce__(self):
        # This is a malicious example for testing
        return (os.system, ('echo "This is potentially malicious"',))


evil_obj = EvilClass()
serialized_data = pickle.dumps(evil_obj)

with Path("evil.pickle").open("wb") as file:
    file.write(serialized_data)
