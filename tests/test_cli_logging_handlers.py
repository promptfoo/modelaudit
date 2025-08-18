import importlib
import logging
import sys


def test_import_cli_does_not_configure_logging():
    """Importing modelaudit.cli should not modify root logging handlers."""
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    try:
        assert len(root_logger.handlers) == 0
        sys.modules.pop("modelaudit.cli", None)
        importlib.import_module("modelaudit.cli")
        assert len(root_logger.handlers) == 0
    finally:
        for handler in original_handlers:
            root_logger.addHandler(handler)
