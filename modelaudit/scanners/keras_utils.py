"""Shared utilities for Keras scanners."""

from modelaudit.detectors.suspicious_symbols import KNOWN_SAFE_MODEL_CLASSES

from .base import IssueSeverity, ScanResult


def check_subclassed_model(
    model_class: str,
    result: ScanResult,
    location: str,
) -> None:
    """Check whether a Keras model class is subclassed (custom) or a known safe class.

    Subclassed models can contain arbitrary Python code in their call() method,
    unlike standard Keras models that use declarative layer configurations.

    Args:
        model_class: The class_name from the Keras model config.
        result: ScanResult to add the check to.
        location: File path for the check location.
    """
    if model_class and model_class not in KNOWN_SAFE_MODEL_CLASSES:
        result.add_check(
            name="Subclassed Model Detection",
            passed=False,
            message=f"Subclassed Keras model detected: {model_class}",
            severity=IssueSeverity.INFO,
            location=location,
            details={
                "model_class": model_class,
                "known_safe_classes": sorted(KNOWN_SAFE_MODEL_CLASSES),
                "risk": "Subclassed models require external Python code to load, which should be reviewed",
            },
            why=(
                "Subclassed Keras models (custom class names) require external Python class "
                "definitions to load. The model file itself does not contain executable code, "
                "but the loading code should be reviewed. Standard Keras models (Sequential, "
                "Functional, Model) use declarative layer configurations and load without custom code."
            ),
        )
    elif model_class in KNOWN_SAFE_MODEL_CLASSES:
        result.add_check(
            name="Subclassed Model Detection",
            passed=True,
            message=f"Standard Keras model class: {model_class}",
            location=location,
            details={"model_class": model_class},
        )
