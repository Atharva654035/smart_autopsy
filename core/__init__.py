# smart_autopsy/core/__init__.py
# Core package initializer for the Smart Autopsy forensics platform.

from .scanner import DriveScanner, list_physical_drives
from .carver  import FileCarver, CarvedFile, SafetyViolationError
from .parsers import (
    carve_png,
    carve_jpeg,
    carve_pdf,
    carve_mp3,
    CarveResult,
    FORMAT_MAX_BYTES,
    MIN_FILE_BYTES,
    MAX_FILE_BYTES,
)

__all__ = [
    "DriveScanner",
    "list_physical_drives",
    "FileCarver",
    "CarvedFile",
    "SafetyViolationError",
    "carve_png",
    "carve_jpeg",
    "carve_pdf",
    "carve_mp3",
    "CarveResult",
    "FORMAT_MAX_BYTES",
    "MIN_FILE_BYTES",
    "MAX_FILE_BYTES",
]
