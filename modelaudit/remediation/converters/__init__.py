"""Model format converters."""

import logging
from pathlib import Path
from typing import Callable, Optional

from modelaudit.remediation.base import BaseConverter

logger = logging.getLogger(__name__)

# Registry of available converters
CONVERTER_REGISTRY: dict[str, type[BaseConverter]] = {}


def register_converter(name: str) -> Callable[[type[BaseConverter]], type[BaseConverter]]:
    """Decorator to register a converter class.

    Parameters
    ----------
    name : str
        Name to register the converter under.

    Returns
    -------
    callable
        Decorator function.
    """

    def decorator(cls: type[BaseConverter]) -> type[BaseConverter]:
        CONVERTER_REGISTRY[name] = cls
        logger.debug("Registered converter: %s", name)
        return cls

    return decorator


def get_converter(source_path: Path, target_format: str) -> Optional[BaseConverter]:
    """Get an appropriate converter for the given conversion.

    Parameters
    ----------
    source_path : Path
        Path to the source model file.
    target_format : str
        Target format name.

    Returns
    -------
    Optional[BaseConverter]
        Converter instance if one is available, None otherwise.
    """
    # Try each registered converter
    for name, converter_class in CONVERTER_REGISTRY.items():
        try:
            converter = converter_class()
            if converter.can_convert(source_path, target_format):
                logger.info("Using %s converter for %s -> %s", name, source_path.suffix, target_format)
                return converter
        except Exception as e:
            logger.warning("Error checking converter %s: %s", name, e)
            continue

    return None


# Import converters to register them
try:
    from .pickle_to_safetensors import PickleToSafeTensorsConverter
except ImportError:
    logger.debug("PickleToSafeTensorsConverter not available")

__all__ = ["CONVERTER_REGISTRY", "get_converter", "register_converter"]
