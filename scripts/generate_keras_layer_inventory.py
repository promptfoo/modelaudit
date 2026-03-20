#!/usr/bin/env python3
"""Generate the Keras layer inventory used by ModelAudit scanners."""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

# Exclude public exports that are not ordinary safe built-in layers. Some are
# abstract/support classes, and some have dedicated security handling.
EXCLUDED_GENERATED_KERAS_LAYER_EXPORTS: frozenset[str] = frozenset(
    {
        "InputSpec",
        "Lambda",
        "Layer",
        "TorchModuleWrapper",
    }
)


def find_keras_source_root() -> Path:
    """Locate the installed Keras source tree without importing Keras."""
    spec = importlib.util.find_spec("keras")
    if spec is None or not spec.submodule_search_locations:
        raise RuntimeError("Could not locate an installed 'keras' package")

    package_root = Path(next(iter(spec.submodule_search_locations)))
    source_root = package_root / "src"
    if not source_root.is_dir():
        raise RuntimeError(f"Expected Keras source tree at {source_root}")
    return source_root


def exported_keras_layer_classes(source_root: Path) -> list[str]:
    """Return public `keras.layers.*` class exports from the Keras source tree."""
    exported_names: set[str] = {"Functional", "Model", "Sequential"}

    for path in source_root.rglob("*.py"):
        try:
            tree = ast.parse(path.read_text())
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue

                func = decorator.func
                if isinstance(func, ast.Name):
                    func_name = func.id
                elif isinstance(func, ast.Attribute):
                    func_name = func.attr
                else:
                    func_name = None
                if func_name != "keras_export":
                    continue

                for argument in decorator.args:
                    values: list[str] = []
                    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                        values = [argument.value]
                    elif isinstance(argument, (ast.List, ast.Tuple)):
                        values = [
                            item.value
                            for item in argument.elts
                            if isinstance(item, ast.Constant) and isinstance(item.value, str)
                        ]

                    for value in values:
                        if value.startswith("keras.layers."):
                            exported_names.add(value.split(".")[-1])

    return sorted(exported_names - EXCLUDED_GENERATED_KERAS_LAYER_EXPORTS)


def render_module(layer_names: list[str]) -> str:
    """Render the generated Python module."""
    lines = [
        '"""Generated Keras layer inventory.',
        "",
        "Regenerate this file with `scripts/generate_keras_layer_inventory.py` after",
        "updating the Keras reference version used for scanner maintenance.",
        '"""',
        "",
        "GENERATED_KNOWN_SAFE_KERAS_LAYER_CLASSES: frozenset[str] = frozenset(",
        "    {",
    ]
    lines.extend(f'        "{name}",' for name in layer_names)
    lines.extend(
        [
            "    }",
            ")",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    source_root = find_keras_source_root()
    layer_names = exported_keras_layer_classes(source_root)
    target = Path(__file__).resolve().parent.parent / "modelaudit" / "config" / "generated_keras_layers.py"
    target.write_text(render_module(layer_names))
    print(f"Wrote {len(layer_names)} layer names to {target}")


if __name__ == "__main__":
    main()
