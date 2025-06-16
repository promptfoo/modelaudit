"""Utilities for rewriting pickle files using Fickling."""

from __future__ import annotations

import difflib
import pickle
from pathlib import Path

from fickling.fickle import Memoize, Pickled, ShortBinUnicode, StackGlobal


def _contains_dangerous_chain(ops: list) -> bool:
    for i in range(4, len(ops)):
        op = ops[i]
        if (
            isinstance(op, StackGlobal)
            and isinstance(ops[i - 1], Memoize)
            and isinstance(ops[i - 2], ShortBinUnicode)
            and isinstance(ops[i - 3], Memoize)
            and isinstance(ops[i - 4], ShortBinUnicode)
        ):
            module = ops[i - 4].arg
            func = ops[i - 2].arg
            if (module in {"os", "posix"} and func == "system") or (
                module == "subprocess" and func in {"Popen", "call", "check_output"}
            ):
                return True
    return False


def safe_rewrite_pickle(path: str, output_path: str | None = None) -> tuple[str, str]:
    """Rewrite a pickle file removing obvious dangerous gadget chains."""

    in_path = Path(path)
    if output_path is None:
        output_path = str(in_path.with_suffix(in_path.suffix + ".safe"))
    out_path = Path(output_path)

    original_data = in_path.read_bytes()
    pickled = Pickled.load(original_data)

    if _contains_dangerous_chain(list(pickled)):
        sanitized_data = pickle.dumps("sanitized")
        out_path.write_bytes(sanitized_data)
        diff = "\n".join(
            difflib.unified_diff(
                original_data.decode("latin1").splitlines(),
                sanitized_data.decode("latin1").splitlines(),
                fromfile=str(in_path),
                tofile=str(out_path),
            )
        )
    else:
        out_path.write_bytes(original_data)
        diff = ""

    return str(out_path), diff
