# Legacy compatibility module
# This module provides backward compatibility for code importing PickleScanner
# from the old pickle_scanner module name

from .fickling_pickle_scanner import FicklingPickleScanner

# Legacy alias - maintains backward compatibility
PickleScanner = FicklingPickleScanner

# Export for backwards compatibility
__all__ = ["PickleScanner"]