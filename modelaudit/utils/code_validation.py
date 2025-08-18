"""Python code validation utilities using py_compile."""

import ast
import py_compile
import tempfile
from typing import Optional


def validate_python_syntax(code: str, filename: str = "<string>") -> tuple[bool, Optional[str]]:
    """
    Validate Python code syntax without executing it.

    Args:
        code: Python code string to validate
        filename: Optional filename for error messages

    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if syntax is valid, False otherwise
        - error_message: Error description if invalid, None if valid
    """
    if not code or not isinstance(code, str):
        return False, "Empty or invalid code string"

    try:
        # First try AST parsing for quick syntax check
        ast.parse(code)

        # Then use py_compile for more thorough validation
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp:
            tmp.write(code)
            tmp.flush()

            try:
                py_compile.compile(tmp.name, doraise=True)
                return True, None
            except py_compile.PyCompileError as e:
                return False, str(e)
            finally:
                import os

                os.unlink(tmp.name)

    except SyntaxError as e:
        error_msg = f"Syntax error at line {e.lineno}: {e.msg}"
        if e.offset:
            error_msg += f" (column {e.offset})"
        return False, error_msg
    except Exception as e:
        return False, f"Validation error: {e!s}"


def extract_dangerous_constructs(code: str) -> dict[str, list[str]]:
    """
    Extract potentially dangerous constructs from Python code.

    Args:
        code: Python code string to analyze

    Returns:
        Dictionary containing lists of dangerous constructs found
    """
    dangerous: dict[str, list[str]] = {
        "imports": [],
        "function_calls": [],
        "eval_exec": [],
        "file_operations": [],
        "network_operations": [],
        "subprocess_operations": [],
    }

    try:
        tree = ast.parse(code)

        for node in ast.walk(tree):
            # Check imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ["os", "sys", "subprocess", "socket", "urllib", "requests"]:
                        dangerous["imports"].append(alias.name)

            elif isinstance(node, ast.ImportFrom):
                if node.module in ["os", "sys", "subprocess", "socket", "urllib", "requests"]:
                    dangerous["imports"].append(f"from {node.module}")

            # Check function calls
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id

                    # Eval/exec calls
                    if func_name in ["eval", "exec", "compile", "__import__"]:
                        dangerous["eval_exec"].append(func_name)

                    # File operations
                    elif func_name in ["open", "file"]:
                        dangerous["file_operations"].append(func_name)

                    # Subprocess operations
                    elif func_name in ["system", "popen"]:
                        dangerous["subprocess_operations"].append(func_name)

                elif isinstance(node.func, ast.Attribute):
                    # Check for os.system, subprocess.run, etc.
                    if isinstance(node.func.value, ast.Name):
                        module = node.func.value.id
                        method = node.func.attr

                        if (module == "os" and method in ["system", "popen", "exec*"]) or (
                            module == "subprocess" and method in ["run", "call", "Popen"]
                        ):
                            dangerous["subprocess_operations"].append(f"{module}.{method}")
                        elif module == "socket" and method in ["socket", "connect"]:
                            dangerous["network_operations"].append(f"{module}.{method}")

    except Exception:
        # If parsing fails, we can't analyze the code
        pass

    return dangerous


def is_code_potentially_dangerous(code: str, threshold: str = "medium") -> tuple[bool, str]:
    """
    Check if Python code contains potentially dangerous operations.

    Args:
        code: Python code string to check
        threshold: Risk threshold - "low", "medium", or "high"

    Returns:
        Tuple of (is_dangerous, risk_description)
    """
    constructs = extract_dangerous_constructs(code)

    risk_score = 0
    risks = []

    # High risk items
    if constructs["eval_exec"]:
        risk_score += 10 * len(constructs["eval_exec"])
        risks.append(f"Dynamic code execution: {', '.join(constructs['eval_exec'])}")

    if constructs["subprocess_operations"]:
        risk_score += 8 * len(constructs["subprocess_operations"])
        risks.append(f"Subprocess operations: {', '.join(constructs['subprocess_operations'])}")

    # Medium risk items
    if constructs["file_operations"]:
        risk_score += 5 * len(constructs["file_operations"])
        risks.append(f"File operations: {', '.join(constructs['file_operations'])}")

    if constructs["network_operations"]:
        risk_score += 5 * len(constructs["network_operations"])
        risks.append(f"Network operations: {', '.join(constructs['network_operations'])}")

    # Low risk items
    if constructs["imports"]:
        risk_score += 2 * len(constructs["imports"])
        risks.append(f"Dangerous imports: {', '.join(constructs['imports'])}")

    # Determine if dangerous based on threshold
    thresholds = {"low": 5, "medium": 10, "high": 20}
    is_dangerous = risk_score >= thresholds.get(threshold, 10)

    risk_description = "; ".join(risks) if risks else "No dangerous constructs detected"

    return is_dangerous, risk_description
