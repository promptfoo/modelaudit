#!/usr/bin/env python3
import pickle


# Create a simple malicious pickle for testing
class MaliciousClass:
    def __reduce__(self):
        import os

        return (os.system, ('echo "Hello from malicious pickle"',))


# Create the pickle
with open("simple_malicious.pkl", "wb") as f:
    pickle.dump(MaliciousClass(), f)

print("Created simple_malicious.pkl")
