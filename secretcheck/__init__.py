"""Public package interface for SecretCheck.

Importing the package exposes the main scanning helpers for end users and tests.
"""

from .scanner import scan_directory, scan_file, scan_line

__all__ = ["scan_line", "scan_file", "scan_directory"]
