# smart_autopsy/core/__init__.py
# Core package initializer for the Smart Autopsy forensics platform.
# Module 1: Data Acquisition & Raw Sector Reader

from .scanner import DriveScanner, list_physical_drives

__all__ = ["DriveScanner", "list_physical_drives"]
