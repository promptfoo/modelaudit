import subprocess
import sys


def test_import_cli_does_not_configure_logging() -> None:
    """Importing modelaudit.cli should not modify root logging handlers."""
    subprocess.run(
        [
            sys.executable,
            "-c",
            """import logging
import modelaudit.cli
assert not logging.getLogger().handlers
""",
        ],
        check=True,
        timeout=30,
    )
