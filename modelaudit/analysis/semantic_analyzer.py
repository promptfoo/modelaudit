"""Advanced semantic analysis beyond syntax checking."""

import ast
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class CodeRiskLevel(Enum):
    """Risk levels for code analysis."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CodeContext:
    """Context information for code analysis."""

    imports: set[str]
    function_calls: set[str]
    class_definitions: set[str]
    variable_assignments: dict[str, Any]
    control_flow: list[str]
    data_flow: dict[str, list[str]]
    external_calls: set[str]


class SemanticAnalyzer:
    """Performs semantic analysis of Python code."""

    def __init__(self):
        # Define safe operations by context
        self.safe_contexts = {
            # ML operations that look dangerous but are safe
            "ml_operations": {
                "torch.load",
                "torch.save",
                "pickle.load",
                "pickle.dump",
                "joblib.load",
                "joblib.dump",
                "np.load",
                "np.save",
                "tf.saved_model.load",
                "keras.models.load_model",
            },
            # Data processing operations
            "data_operations": {
                "eval",
                "exec",
                "compile",  # When used for mathematical expressions
            },
            # Safe magic methods
            "magic_methods": {
                "__init__",
                "__call__",
                "__getattr__",
                "__setattr__",
                "__getitem__",
                "__setitem__",
                "__len__",
                "__str__",
            },
        }

        # Define dangerous combinations
        self.dangerous_combinations = [
            ({"eval", "exec"}, {"requests", "urllib"}),  # Remote code execution
            ({"subprocess", "os.system"}, {"input", "request"}),  # Command injection
            ({"open", "write"}, {"os.environ", "sys.path"}),  # Path manipulation
        ]

        # Safe usage patterns
        self.safe_patterns = {
            # NumPy/math evaluations
            r"eval\s*\(\s*['\"][\d\s\+\-\*/\(\)\.]+['\"]\s*\)": "math_expression",
            # DataFrame operations
            r"eval\s*\(\s*['\"]df\[.+\]['\"]\s*\)": "dataframe_operation",
            # Safe pickle usage
            r"pickle\.load\s*\(\s*open\s*\(\s*['\"][\w/\-_\.]+\.pkl['\"]": "model_loading",
        }

    def extract_code_context(self, code: str) -> Optional[CodeContext]:
        """Extract comprehensive context from Python code."""
        try:
            tree = ast.parse(code)
        except (SyntaxError, ValueError):
            return None

        context = CodeContext(
            imports=set(),
            function_calls=set(),
            class_definitions=set(),
            variable_assignments={},
            control_flow=[],
            data_flow={},
            external_calls=set(),
        )

        # Custom visitor to extract context
        class ContextVisitor(ast.NodeVisitor):
            def __init__(self, ctx):
                self.context = ctx
                self.current_function = None
                self.call_graph = {}

            def visit_Import(self, node):
                for alias in node.names:
                    self.context.imports.add(alias.name)
                self.generic_visit(node)

            def visit_ImportFrom(self, node):
                if node.module:
                    self.context.imports.add(node.module)
                self.generic_visit(node)

            def visit_Call(self, node):
                # Extract function call information
                call_name = self._get_call_name(node)
                if call_name:
                    self.context.function_calls.add(call_name)

                    # Track data flow
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        var_name = node.func.value.id
                        if var_name not in self.context.data_flow:
                            self.context.data_flow[var_name] = []
                        self.context.data_flow[var_name].append(call_name)

                self.generic_visit(node)

            def visit_ClassDef(self, node):
                self.context.class_definitions.add(node.name)
                self.generic_visit(node)

            def visit_FunctionDef(self, node):
                old_function = self.current_function
                self.current_function = node.name
                self.generic_visit(node)
                self.current_function = old_function

            def visit_Assign(self, node):
                # Track variable assignments
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.context.variable_assignments[target.id] = node.value
                self.generic_visit(node)

            def visit_If(self, node):
                self.context.control_flow.append("if")
                self.generic_visit(node)

            def visit_For(self, node):
                self.context.control_flow.append("for")
                self.generic_visit(node)

            def visit_While(self, node):
                self.context.control_flow.append("while")
                self.generic_visit(node)

            def _get_call_name(self, node):
                if isinstance(node.func, ast.Name):
                    return node.func.id
                elif isinstance(node.func, ast.Attribute):
                    parts = []
                    current = node.func
                    while isinstance(current, ast.Attribute):
                        parts.append(current.attr)
                        current = current.value
                    if isinstance(current, ast.Name):
                        parts.append(current.id)
                    return ".".join(reversed(parts))
                return None

        visitor = ContextVisitor(context)
        visitor.visit(tree)

        return context

    def analyze_code_behavior(self, code: str, ml_context: dict[str, Any]) -> tuple[CodeRiskLevel, dict[str, Any]]:
        """Analyze code behavior with ML context awareness."""
        context = self.extract_code_context(code)
        if not context:
            return CodeRiskLevel.MEDIUM, {"error": "Failed to parse code"}

        risk_factors = []
        mitigating_factors = []

        # Check for dangerous operations
        dangerous_ops = {"eval", "exec", "compile", "__import__", "os.system", "subprocess.call"}
        found_dangerous = context.function_calls & dangerous_ops

        if found_dangerous:
            # Check if they're used in safe contexts
            for op in found_dangerous:
                if self._is_safe_usage(op, code, context, ml_context):
                    mitigating_factors.append(f"Safe usage of {op}")
                else:
                    risk_factors.append(f"Dangerous operation: {op}")

        # Check for dangerous combinations
        for combo in self.dangerous_combinations:
            if all(any(op in context.function_calls for op in ops) for ops in combo):
                risk_factors.append(f"Dangerous combination: {combo}")

        # Check imports
        dangerous_imports = {"os", "sys", "subprocess", "socket", "urllib", "requests"}
        risky_imports = context.imports & dangerous_imports

        # Analyze if imports are actually used dangerously
        for imp in risky_imports:
            if self._is_import_used_safely(imp, context, ml_context):
                mitigating_factors.append(f"Safe usage of {imp}")
            else:
                risk_factors.append(f"Potentially dangerous import: {imp}")

        # ML-specific analysis
        if (
            ml_context.get("framework") == "pytorch"
            and "torch.load" in context.function_calls
            and self._is_safe_torch_load(code)
        ):
            # PyTorch-specific safe patterns
            mitigating_factors.append("Safe torch.load usage")

        # Calculate risk level
        risk_score = len(risk_factors) - (len(mitigating_factors) * 0.5)

        if risk_score <= 0:
            risk_level = CodeRiskLevel.SAFE
        elif risk_score <= 1:
            risk_level = CodeRiskLevel.LOW
        elif risk_score <= 3:
            risk_level = CodeRiskLevel.MEDIUM
        elif risk_score <= 5:
            risk_level = CodeRiskLevel.HIGH
        else:
            risk_level = CodeRiskLevel.CRITICAL

        return risk_level, {
            "risk_factors": risk_factors,
            "mitigating_factors": mitigating_factors,
            "imports": list(context.imports),
            "function_calls": list(context.function_calls),
            "risk_score": risk_score,
        }

    def _is_safe_usage(self, operation: str, code: str, context: CodeContext, ml_context: dict[str, Any]) -> bool:
        """Check if a potentially dangerous operation is used safely."""
        # Check against safe patterns
        for pattern, _usage_type in self.safe_patterns.items():
            if re.search(pattern, code):
                return True

        # Check ML context
        if ml_context.get("framework") and operation in self.safe_contexts["ml_operations"]:
            return True

        # Check if eval/exec is used for math only
        if operation in ["eval", "exec"]:
            # Look for eval/exec usage in code
            eval_pattern = rf"{operation}\s*\(([^)]+)\)"
            matches = re.findall(eval_pattern, code)

            for match in matches:
                # Check if it's a literal string with only math
                if re.match(r"['\"][\d\s\+\-\*/\(\)\.]+['\"]", match.strip()):
                    return True

                # Check if it's a variable that we can trace
                if match.strip() in context.variable_assignments:
                    # Would need more complex analysis here
                    pass

        return False

    def _is_import_used_safely(self, import_name: str, context: CodeContext, ml_context: dict[str, Any]) -> bool:
        """Check if an import is used safely."""
        # Check if import is used at all
        import_calls = [call for call in context.function_calls if call.startswith(import_name)]

        if not import_calls:
            return True  # Import not used

        # Check specific safe usages
        safe_usages = {
            "os": ["os.path.join", "os.path.exists", "os.getenv"],
            "sys": ["sys.version", "sys.path", "sys.modules"],
            "subprocess": [],  # No safe subprocess usage by default
        }

        if import_name in safe_usages:
            dangerous_calls = [call for call in import_calls if call not in safe_usages[import_name]]
            return len(dangerous_calls) == 0

        return False

    def _is_safe_torch_load(self, code: str) -> bool:
        """Check if torch.load is used safely."""
        # Look for torch.load patterns
        load_pattern = r"torch\.load\s*\(([^,\)]+)"
        matches = re.findall(load_pattern, code)

        for match in matches:
            # Check if map_location is specified (safer)
            if "map_location" in code[code.find(match) : code.find(match) + 100]:
                return True

            # Check if it's loading from a literal path (safer than variable)
            if re.match(r"['\"][\w/\-_\.]+['\"]", match.strip()):
                return True

        return False

    def detect_obfuscation(self, code: str) -> tuple[bool, list[str]]:
        """Detect code obfuscation techniques."""
        obfuscation_indicators = []

        # Check for base64 encoded strings
        base64_pattern = r"base64\.b64decode\s*\(['\"][A-Za-z0-9+/=]{20,}['\"]\)"
        if re.search(base64_pattern, code):
            obfuscation_indicators.append("base64_encoded_strings")

        # Check for hex encoded strings
        hex_pattern = r"bytes\.fromhex\s*\(['\"][0-9a-fA-F]{20,}['\"]\)"
        if re.search(hex_pattern, code):
            obfuscation_indicators.append("hex_encoded_strings")

        # Check for chr() concatenation
        chr_pattern = r"chr\s*\(\d+\)\s*\+\s*chr\s*\(\d+\)"
        if re.search(chr_pattern, code):
            obfuscation_indicators.append("chr_concatenation")

        # Check for excessive use of getattr
        getattr_count = code.count("getattr")
        if getattr_count > 5:
            obfuscation_indicators.append("excessive_getattr")

        # Check for __import__ usage
        if "__import__" in code:
            obfuscation_indicators.append("dynamic_import")

        # Check for exec with complex expressions
        exec_pattern = r"exec\s*\([^'\"][^)]{20,}\)"
        if re.search(exec_pattern, code):
            obfuscation_indicators.append("complex_exec")

        return len(obfuscation_indicators) > 0, obfuscation_indicators
