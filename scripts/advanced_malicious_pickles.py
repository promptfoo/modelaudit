#!/usr/bin/env python3
"""
Create advanced malicious pickle files that might evade basic detection
"""

import pickle
import types


def create_obfuscated_payload():
    """Create an obfuscated payload using bytecode manipulation"""

    class ObfuscatedPayload:
        def __reduce__(self):
            # Use compile to create bytecode that might be harder to detect
            code = compile('__import__("os").system("echo obfuscated")', "<string>", "exec")
            return (exec, (code,))

    with open("obfuscated_payload.pkl", "wb") as f:
        pickle.dump(ObfuscatedPayload(), f)
    print("Created obfuscated_payload.pkl")


def create_getattr_payload():
    """Create payload using getattr to be more indirect"""

    class GetattrPayload:
        def __reduce__(self):
            # Use getattr indirection
            return (getattr(__import__("builtins"), "exec"), ('__import__("os").system("echo getattr")',))

    with open("getattr_payload.pkl", "wb") as f:
        pickle.dump(GetattrPayload(), f)
    print("Created getattr_payload.pkl")


def create_lambda_payload():
    """Create payload using lambda function"""

    class LambdaPayload:
        def __reduce__(self):
            # Create lambda that calls dangerous function
            dangerous_lambda = lambda: __import__("os").system("echo lambda")
            return (dangerous_lambda, ())

    with open("lambda_payload.pkl", "wb") as f:
        pickle.dump(LambdaPayload(), f)
    print("Created lambda_payload.pkl")


def create_base64_payload():
    """Create payload with base64 encoded commands"""
    import base64

    class Base64Payload:
        def __reduce__(self):
            # Encode malicious command
            cmd = base64.b64encode(b'echo "base64 payload"').decode()
            return (exec, (f'__import__("os").system(__import__("base64").b64decode("{cmd}").decode())',))

    with open("base64_payload.pkl", "wb") as f:
        pickle.dump(Base64Payload(), f)
    print("Created base64_payload.pkl")


def create_unused_variable_payload():
    """Create payload that fickling might detect due to unused variables"""

    class UnusedVarPayload:
        def __reduce__(self):
            # This pattern might be detected by fickling's unused variable analysis
            return (exec, ('unused_var = "suspicious"; __import__("os").system("echo unused_var")',))

    with open("unused_var_payload.pkl", "wb") as f:
        pickle.dump(UnusedVarPayload(), f)
    print("Created unused_var_payload.pkl")


if __name__ == "__main__":
    print("Creating advanced malicious pickle files...")
    try:
        create_obfuscated_payload()
    except Exception as e:
        print(f"Error creating obfuscated: {e}")

    try:
        create_getattr_payload()
    except Exception as e:
        print(f"Error creating getattr: {e}")

    try:
        create_lambda_payload()
    except Exception as e:
        print(f"Error creating lambda: {e}")

    try:
        create_base64_payload()
    except Exception as e:
        print(f"Error creating base64: {e}")

    try:
        create_unused_variable_payload()
    except Exception as e:
        print(f"Error creating unused_var: {e}")

    print("Advanced pickle file creation complete!")
