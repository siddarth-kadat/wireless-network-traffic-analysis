"""E4: Severity Classifier Module (Alias / Compatibility Wrapper).

Exposes SeverityManager to satisfy legacy or modular naming conventions.
"""

from .severity_manager import SEVERITY_MAP, SeverityManager

__all__ = ["SeverityManager", "SEVERITY_MAP"]
