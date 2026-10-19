"""Bound subprocess output and lifetime, including descendants retaining pipes."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class ProcessLimitError(RuntimeError):
    def __init__(self, message: str, stdout: bytes, stderr: bytes) -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr


def run_bounded(
    argv: list[str],
    *,
    cwd: Path,
    timeout: float,
    max_output: int = 4 * 1024 * 1024,
    stdin: bytes = b"",
    env: dict[str, str] | None = None,
) -> ProcessResult:
    if os.name != "posix":
        raise ValueError("The review worker requires a POSIX host")
    with subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    ) as process:
        assert process.stdin is not None and process.stdout is not None and process.stderr is not None
        outputs = {"stdout": bytearray(), "stderr": bytearray()}
        pending = memoryview(stdin)
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                if pending:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                else:
                    process.stdin.close()
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Reviewer exceeded its wall-clock limit")
                    for key, _events in selector.select(timeout=0.1):
                        if key.data == "stdin":
                            try:
                                pending = pending[os.write(key.fd, pending[:65536]) :]
                            except BrokenPipeError:
                                pending = pending[:0]
                            if not pending:
                                selector.unregister(key.fileobj)
                                process.stdin.close()
                        else:
                            chunk = os.read(key.fd, 65536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                            else:
                                outputs[key.data].extend(chunk)
                                if sum(map(len, outputs.values())) > max_output:
                                    raise ValueError("Reviewer exceeded its output limit")
                remaining = max(0.01, deadline - time.monotonic())
                returncode = process.wait(timeout=remaining)
            return ProcessResult(returncode, bytes(outputs["stdout"]), bytes(outputs["stderr"]))
        except (TimeoutError, ValueError, subprocess.TimeoutExpired) as exc:
            raise ProcessLimitError(str(exc), bytes(outputs["stdout"]), bytes(outputs["stderr"])) from exc
        finally:
            # The leader can exit while descendants are still running.
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
