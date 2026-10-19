"""Entrypoint inside the disposable, credential-free Linux worker image."""

from __future__ import annotations

import argparse
import os
import platform
import socket
import subprocess
import sys
from urllib.parse import urlsplit

from .codex import CODEX_VERSION, codex_command, codex_config


def preflight(proxy_url: str) -> None:
    if platform.system() != "Linux" or os.getuid() != 10001:
        raise ValueError("Reviewer must run as the unprivileged Linux worker user")
    if any(name in os.environ for name in ("OPENAI_API_KEY", "CODEX_API_KEY", "AWS_SECRET_ACCESS_KEY")):
        raise ValueError("Credentials must stay outside the reviewer worker")
    result = subprocess.run(["codex", "--version"], check=True, capture_output=True, text=True, timeout=15)
    if result.stdout.strip() != f"codex-cli {CODEX_VERSION}":
        raise ValueError("Unexpected Codex CLI version")
    proxy = urlsplit(proxy_url)
    with socket.create_connection((str(proxy.hostname), proxy.port or 80), timeout=5) as connection:
        gateway = connection.getpeername()
    # A listening parent socket proves a command cannot reach the harness network namespace.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        probe = (
            "import os,socket; from pathlib import Path; "
            "Path('/work/probe').write_text('scratch works'); "
            "assert Path('/request/schema.json').is_file(); "
            "assert 'OPENAI_API_KEY' not in os.environ\n"
            f"for endpoint in [('127.0.0.1',{port}), {gateway!r}]:\n"
            " try:\n  s=socket.create_connection(endpoint,timeout=1)\n"
            " except OSError:\n  continue\n"
            " s.close(); raise AssertionError('command network is reachable')\n"
            "for path in ('/artifacts/.probe', '/request/.probe', '/usr/local/.probe'):\n"
            " try:\n  Path(path).write_text('forbidden')\n"
            " except OSError:\n  continue\n"
            " raise AssertionError('protected mount is writable')\n"
        )
        subprocess.run(
            ["codex", "sandbox", *codex_config(proxy_url), "--", "python", "-c", probe],
            cwd="/work",
            check=True,
            stdout=sys.stderr,
            stderr=sys.stderr,
            timeout=30,
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--proxy-url", required=True)
    args = parser.parse_args()
    try:
        preflight(args.proxy_url)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"Reviewer sandbox preflight failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    command = codex_command(args.model, args.proxy_url)
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
