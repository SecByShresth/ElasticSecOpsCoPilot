# ============================================================================
# src/correlation/__init__.py
# ============================================================================

"""Correlation layer - Event correlation and pattern matching."""

from src.correlation.engine import CorrelationEngine
from src.correlation.patterns import PatternLibrary

__all__ = [
    "CorrelationEngine",
    "PatternLibrary",
]