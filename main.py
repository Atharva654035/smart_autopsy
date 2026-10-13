"""
smart_autopsy/main.py
══════════════════════════════════════════════════════════════════════════════
Application Entry Point
Smart Autopsy | Digital Forensics Platform

Usage
─────
    # Image files (no root needed):
    python3 main.py

    # Physical block devices (root required):
    sudo python3 main.py
    — or —
    sudo .venv/bin/python3 main.py   (when using a virtual environment)

Author : Smart Autopsy Engineering Team
Python : 3.9+
OS     : Linux
"""

from __future__ import annotations

import logging
import os
import sys


# ─────────────────────────────────────────────────────────────────────────────
# Enforce Python version
# ─────────────────────────────────────────────────────────────────────────────
if sys.version_info < (3, 9):
    sys.exit(
        "Smart Autopsy requires Python 3.9 or newer.\n"
        f"Current version: {sys.version}\n"
        "Upgrade with: sudo apt install python3.11"
    )

# ─────────────────────────────────────────────────────────────────────────────
# Enforce Linux
# ─────────────────────────────────────────────────────────────────────────────
if sys.platform != "linux":
    sys.exit(
        "Smart Autopsy is designed for Linux forensic workstations.\n"
        f"Detected platform: {sys.platform}\n\n"
        "Raw block-device I/O, lsblk device discovery, and the BLKGETSIZE64\n"
        "ioctl are Linux-specific.  The application cannot run on this OS."
    )

# ─────────────────────────────────────────────────────────────────────────────
# Logging — configure before any package imports so all loggers inherit this
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)-8s]  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            os.path.join(os.path.dirname(__file__), "smart_autopsy.log"),
            mode="a", encoding="utf-8",
        ),
    ],
)
log = logging.getLogger("smart_autopsy.main")


# ─────────────────────────────────────────────────────────────────────────────
# Root privilege advisory (non-blocking — GUI will re-check per operation)
# ─────────────────────────────────────────────────────────────────────────────
_IS_ROOT: bool = os.geteuid() == 0

if not _IS_ROOT:
    log.warning(
        "Process is NOT running as root (euid=%d).  "
        "Physical block-device access will be unavailable.  "
        "Disk image files (.dd/.img/.raw) can still be processed.",
        os.geteuid(),
    )
else:
    log.info("Running as root (euid=0) — full block-device access available.")


# ─────────────────────────────────────────────────────────────────────────────
# Ensure the venv or project root is on sys.path so relative imports work
# when the script is launched from any working directory.
# ─────────────────────────────────────────────────────────────────────────────
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


# ─────────────────────────────────────────────────────────────────────────────
# Import GUI (after path fixup)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from gui.dashboard import SmartAutopsyApp
except ImportError as exc:
    sys.exit(
        f"Failed to import GUI components: {exc}\n\n"
        "Ensure all dependencies are installed:\n"
        "    pip install -r requirements.txt\n\n"
        "If you are using a virtual environment:\n"
        "    source .venv/bin/activate\n"
        "    pip install -r requirements.txt"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Instantiate and run the Smart Autopsy GUI application."""
    log.info(
        "═" * 60 + "\n"
        "  Smart Autopsy v2.0 starting up\n"
        "  Platform : %s\n"
        "  Python   : %s\n"
        "  Root     : %s\n"
        "  PID      : %d\n"
        + "═" * 60,
        sys.platform,
        sys.version.split()[0],
        "yes" if _IS_ROOT else "no (image-only mode)",
        os.getpid(),
    )

    app = SmartAutopsyApp()

    # Centre the window on the primary monitor
    app.update_idletasks()
    screen_w = app.winfo_screenwidth()
    screen_h = app.winfo_screenheight()
    win_w    = app.winfo_width()
    win_h    = app.winfo_height()
    x = (screen_w - win_w) // 2
    y = (screen_h - win_h) // 2
    app.geometry(f"{win_w}x{win_h}+{x}+{y}")

    log.info("GUI window displayed — entering main loop.")
    app.mainloop()
    log.info("Application exited cleanly.")


if __name__ == "__main__":
    main()
