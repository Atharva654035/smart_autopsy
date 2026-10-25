"""
smart_autopsy/core/scanner.py
══════════════════════════════════════════════════════════════════════════════
Module 1 — Data Acquisition & Raw Sector Reader
Smart Autopsy | Digital Forensics Platform

Pipeline stage:  Input Storage  ──►  Raw Sector Reader  ──►  Carving Engine

Operational context
───────────────────
An investigator connects a suspect HDD/USB drive to a Linux workstation and
launches this application with root privileges.  This module is responsible
for two concerns:

  1. Device Discovery  — enumerate all attached block devices via ``lsblk``
                         and return structured metadata for each one.

  2. Raw Block I/O     — open the selected device (or a forensic disk image)
                         in read-only binary mode and stream raw byte chunks
                         to upstream carving/hashing stages without loading
                         the entire medium into memory.

Root access is mandatory for physical block devices (/dev/sdX, /dev/nvme0n1,
etc.).  Disk image files (.dd, .img, .raw, .E01-raw) can be read as a normal
user if file permissions allow.

Performance Notes (v2.2 — Zero-Skip Sliding Window)
────────────────────────────────────────────────────
Read-block size is CHUNK_SIZE = 2 MiB to amortise per-syscall overhead and
saturate modern SATA / NVMe bandwidth.  A full OVERLAP_SIZE = 4 KiB (one
complete 512-byte sector block × 8) window is maintained across chunk
boundaries so that any file-format signature — even one split arbitrarily
across the 2 MiB boundary — is captured in a single combined buffer pass.

Offset arithmetic guarantee
  For a match found at index ``i`` inside the combined buffer:
      absolute_disk_offset = global_disk_offset + i - len(overlap_bytes)
  where ``global_disk_offset`` is the byte position of the *first newly read
  byte* (i.e. it does NOT include the overlap prefix).  This is the only
  value advanced by ``len(incoming_chunk)`` after each read, ensuring
  neither double-counting nor sector skipping occurs.

Author : Smart Autopsy Engineering Team
Python : 3.9+
OS     : Linux (util-linux ≥ 2.36 required for lsblk --json)
"""

from __future__ import annotations

import json
import logging
import os
import struct
import subprocess
import sys
from typing import Dict, Generator, List, Optional, Tuple

# fcntl and ctypes are Linux-only; guard so the module can be imported on
# Windows (e.g. for unit testing on developer machines without a Linux VM).
if sys.platform != "win32":
    import ctypes
    import fcntl
else:
    ctypes = None  # type: ignore[assignment]
    fcntl  = None  # type: ignore[assignment]


# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  [%(levelname)-8s]  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("smart_autopsy.scanner")

# ─────────────────────────────────────────────────────────────────────────────
# Linux ioctl constant for querying block-device size in bytes
#   BLKGETSIZE64 = 0x80081272  (from <linux/fs.h>)
# ─────────────────────────────────────────────────────────────────────────────
BLKGETSIZE64: int = 0x80081272

# Accepted block-device types reported by lsblk
_ACCEPTED_TYPES: frozenset = frozenset({"disk", "part", "loop", "rom"})

# Human-readable size suffixes (IEC binary)
_SIZE_SUFFIXES: Tuple[str, ...] = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")

# ─────────────────────────────────────────────────────────────────────────────
# Performance constants (v2.2 — zero-skip sliding window)
# ─────────────────────────────────────────────────────────────────────────────

# 2 MiB read block — large enough to saturate SATA/NVMe, small enough to stay
# safely below OS per-read limits and comfortably in L3 cache.
CHUNK_SIZE: int = 2 * 1024 * 1024       # 2 MiB

# Backward-compat alias so any external code still importing READ_BLOCK_SIZE
# continues to work without modification.
READ_BLOCK_SIZE: int = CHUNK_SIZE

# Overlap window maintained at the tail of each 2 MiB read so that file-format
# signatures that are split across the chunk boundary are never missed.
# Set to exactly one full 4 KiB sector block so even the worst-case split
# (signature begins in the last byte of chunk N) is captured.
OVERLAP_SIZE: int = 4096                # 4 KiB — 1 sector block

# Backward-compat alias (previous value was 64 B; new value is 4 KiB).
MAX_HEADER_SIZE: int = OVERLAP_SIZE

# Permission-denied hint printed to the operator
_PERMISSION_HINT: str = (
    "\n"
    "╔══════════════════════════════════════════════════════════════════╗\n"
    "║  PERMISSION DENIED — root privileges are required               ║\n"
    "║                                                                  ║\n"
    "║  Raw block-device access on Linux demands elevated privileges.   ║\n"
    "║  Please restart Smart Autopsy with:                              ║\n"
    "║                                                                  ║\n"
    "║      sudo python3 core/scanner.py                                ║\n"
    "║  — or, for the full application —                                ║\n"
    "║      sudo python3 -m smart_autopsy                               ║\n"
    "╚══════════════════════════════════════════════════════════════════╝\n"
)


# ─────────────────────────────────────────────────────────────────────────────
# Internal utilities
# ─────────────────────────────────────────────────────────────────────────────

def _bytes_to_human(n: int) -> str:
    """Convert a raw byte count to a human-readable IEC string.

    Examples
    --------
    >>> _bytes_to_human(1073741824)
    '1.00 GiB'
    >>> _bytes_to_human(512)
    '512 B'
    """
    value = float(n)
    for suffix in _SIZE_SUFFIXES:
        if value < 1024.0:
            if suffix == "B":
                return f"{int(value)} {suffix}"
            return f"{value:.2f} {suffix}"
        value /= 1024.0
    return f"{value:.2f} PiB"


def _blkgetsize64(fd: int) -> int:
    """Return the size of an open block device in bytes using BLKGETSIZE64 ioctl.

    Parameters
    ----------
    fd : int
        An open file descriptor pointing at a block device.

    Returns
    -------
    int
        Total byte capacity of the block device.

    Raises
    ------
    OSError
        If the ioctl call fails (e.g. not a block device, insufficient perms).
    """
    buf = ctypes.create_string_buffer(8)  # uint64_t
    fcntl.ioctl(fd, BLKGETSIZE64, buf)
    return struct.unpack("Q", buf.raw)[0]  # unsigned long long, little-endian


# ══════════════════════════════════════════════════════════════════════════════
# Device Discovery
# ══════════════════════════════════════════════════════════════════════════════

def list_physical_drives() -> List[Dict[str, str]]:
    """Enumerate all connected block devices via ``lsblk``.

    Executes ``lsblk -J -b -o NAME,SIZE,TYPE,MODEL,PATH,MOUNTPOINT`` and
    parses the JSON response to produce a flat list of device records.  Both
    whole disks (``type == "disk"``) and individual partitions
    (``type == "part"``) are included; loop devices and optical drives are
    included when present.

    Returns
    -------
    list[dict[str, str]]
        Each dictionary contains:

        ``name``        – kernel device name, e.g. ``sdb``
        ``path``        – absolute device path, e.g. ``/dev/sdb``
        ``size_bytes``  – raw byte count as a string, e.g. ``"500107862016"``
        ``human_size``  – IEC human-readable size, e.g. ``"465.76 GiB"``
        ``model``       – drive model string (empty for partitions/virtuals)
        ``type``        – lsblk type field (``"disk"``, ``"part"``, …)
        ``mountpoint``  – current mount path or empty string if not mounted

    Raises
    ------
    RuntimeError
        If ``lsblk`` is not installed or returns a non-zero exit code.
    ValueError
        If the JSON output cannot be decoded (should never happen with a
        modern util-linux, but guarded defensively).
    """
    cmd: List[str] = [
        "lsblk",
        "--json",                           # machine-parseable JSON
        "--bytes",                          # report sizes in raw bytes
        "--output", "NAME,SIZE,TYPE,MODEL,PATH,MOUNTPOINT",
    ]

    log.debug("Running: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "lsblk not found.  Smart Autopsy requires a Linux system with "
            "util-linux installed (apt install util-linux)."
        ) from None
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"lsblk exited with code {exc.returncode}: {exc.stderr.strip()}"
        ) from exc

    # ── Parse JSON ────────────────────────────────────────────────────────
    try:
        payload: dict = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Could not parse lsblk JSON output: {exc}\n"
            f"Raw output was:\n{result.stdout[:500]}"
        ) from exc

    devices: List[Dict[str, str]] = []

    def _walk(nodes: List[dict]) -> None:
        """Recursively walk the lsblk device tree."""
        for node in nodes:
            dev_type: str = (node.get("type") or "").strip().lower()

            if dev_type in _ACCEPTED_TYPES:
                raw_size: int = int(node.get("size") or 0)
                record: Dict[str, str] = {
                    "name":       (node.get("name")       or "").strip(),
                    "path":       (node.get("path")       or "").strip(),
                    "size_bytes": str(raw_size),
                    "human_size": _bytes_to_human(raw_size),
                    "model":      (node.get("model")      or "").strip(),
                    "type":       dev_type,
                    "mountpoint": (node.get("mountpoint") or "").strip(),
                }
                devices.append(record)
                log.debug(
                    "Found %-6s  %-12s  %s  %s",
                    dev_type, record["path"], record["human_size"], record["model"],
                )

            # Recurse into children (partitions, LVM volumes, etc.)
            children: List[dict] = node.get("children") or []
            if children:
                _walk(children)

    _walk(payload.get("blockdevices") or [])

    log.info("Device discovery complete: %d device(s) found.", len(devices))
    return devices


# ══════════════════════════════════════════════════════════════════════════════
# DriveScanner
# ══════════════════════════════════════════════════════════════════════════════

class DriveScanner:
    """Low-level raw sector reader for a physical block device or disk image.

    ``DriveScanner`` is the data-acquisition kernel of Smart Autopsy.  It
    opens the target medium in read-only binary mode and exposes a streaming
    generator interface so that upstream stages (file carving, hash
    verification, entropy analysis) receive a continuous feed of raw byte
    chunks without ever loading the whole device into RAM.

    Attributes
    ----------
    target_path : str
        Absolute path to the block device or image file.
    chunk_size : int
        Number of bytes read per OS read call (default ``CHUNK_SIZE`` = 2 MiB).
    overlap_size : int
        Number of bytes retained from the tail of each chunk and prepended to
        the next (default ``OVERLAP_SIZE`` = 4 KiB).  This is the zero-skip
        guarantee: any signature split at the chunk boundary is captured.
    is_block_device : bool
        True if ``target_path`` refers to a ``/dev/`` block device.

    Sliding-Window Design (v2.2)
    ----------------------------
    For each OS read of ``chunk_size`` bytes the generator constructs::

        buffer = overlap_bytes + incoming_chunk

    and yields ``(window_start_offset, buffer)`` where::

        window_start_offset = global_disk_offset - len(overlap_bytes)

    ``global_disk_offset`` tracks the byte position of the *first byte of the
    incoming_chunk* (never includes the overlap prefix itself).  After yielding,
    ``overlap_bytes`` is updated to ``incoming_chunk[-overlap_size:]`` and
    ``global_disk_offset`` is advanced by ``len(incoming_chunk)`` — exactly once
    per chunk, preventing double-counting or sector skipping.

    Absolute offset formula for a signature found at index ``i`` in *buffer*::

        absolute_disk_offset = window_start_offset + i
                             = global_disk_offset - len(overlap_bytes) + i

    Both allocated (live) and unallocated (deleted) sectors are streamed;
    cluster allocation state is irrelevant at this layer.

    Parameters
    ----------
    target_path : str
        Path to a block device (``/dev/sdb``) or forensic disk image
        (``.dd``, ``.img``, ``.raw``).
    chunk_size : int, optional
        OS read granularity in bytes (default ``CHUNK_SIZE`` = 2 MiB).
    overlap_size : int, optional
        Overlap window in bytes (default ``OVERLAP_SIZE`` = 4 KiB).

    Raises
    ------
    FileNotFoundError
        If *target_path* does not exist on the filesystem.
    """

    def __init__(
        self,
        target_path: str,
        chunk_size: int = CHUNK_SIZE,
        overlap_size: int = OVERLAP_SIZE,
    ) -> None:
        if not os.path.exists(target_path):
            raise FileNotFoundError(
                f"Target not found: '{target_path}'\n"
                "Verify the device is connected and the path is correct."
            )

        self.target_path:  str  = os.path.realpath(target_path)
        self.chunk_size:   int  = chunk_size
        self.overlap_size: int  = overlap_size
        self.is_block_device: bool = self.target_path.startswith("/dev/")

        # Lazily opened file descriptor; None until first read_blocks() call
        self._fd: Optional[int]     = None   # low-level OS fd (block devices)
        self._fh: Optional[object]  = None   # Python file object (image files)

        log.info(
            "DriveScanner ready  target='%s'  chunk=%s  overlap=%s  block_device=%s",
            self.target_path,
            _bytes_to_human(self.chunk_size),
            _bytes_to_human(self.overlap_size),
            self.is_block_device,
        )

    # ──────────────────────────────────────────────────────────────────────
    # Permission check
    # ──────────────────────────────────────────────────────────────────────

    def check_permissions(self) -> bool:
        """Verify that the process has the privileges required to read the target.

        For physical block devices (paths under ``/dev/``), root access is
        mandatory on Linux.  For regular image files the check is relaxed to
        a simple POSIX read-access test on the file itself.

        Returns
        -------
        bool
            ``True`` if sufficient permissions exist; ``False`` otherwise.

        Side-effects
        ------------
        Logs a critical warning and prints the operator hint to stderr when
        permissions are insufficient, so the message is visible even if the
        caller swallows the return value.
        """
        if self.is_block_device:
            if os.geteuid() != 0:
                log.critical(
                    "Process is not running as root (euid=%d).  "
                    "Root is required to read block device '%s'.",
                    os.geteuid(), self.target_path,
                )
                print(_PERMISSION_HINT, file=sys.stderr)
                return False

            # Even as root, the device node must be readable
            if not os.access(self.target_path, os.R_OK):
                log.critical(
                    "Block device '%s' exists but is not readable by this process.",
                    self.target_path,
                )
                return False

            log.debug("Root access confirmed for block device '%s'.", self.target_path)
            return True

        # Regular file / disk image — check POSIX read permission
        if not os.access(self.target_path, os.R_OK):
            log.error(
                "Image file '%s' is not readable.  "
                "Check file ownership and permissions.",
                self.target_path,
            )
            return False

        log.debug("Read access confirmed for image file '%s'.", self.target_path)
        return True

    # ──────────────────────────────────────────────────────────────────────
    # Size determination
    # ──────────────────────────────────────────────────────────────────────

    def get_total_size(self) -> int:
        """Return the total byte capacity of the target medium.

        Strategy
        --------
        * **Disk image files** — ``os.path.getsize()`` (single syscall).
        * **Block devices**    — ``BLKGETSIZE64`` ioctl query so the kernel
          returns the exact byte count reported by the drive firmware,
          bypassing any filesystem layer.  Falls back to
          ``os.lseek(fd, 0, SEEK_END)`` when ioctl is unavailable (e.g. on
          non-Linux kernels or loop devices that do not respond to the ioctl).

        Returns
        -------
        int
            Total bytes, or ``-1`` if the size cannot be determined.
        """
        if not self.is_block_device:
            size = os.path.getsize(self.target_path)
            log.debug("Image file size: %s (%d B)", _bytes_to_human(size), size)
            return size

        # Block device path ─ try BLKGETSIZE64 ioctl first
        try:
            fd = os.open(self.target_path, os.O_RDONLY | os.O_NONBLOCK)
            try:
                size = _blkgetsize64(fd)
                log.debug(
                    "BLKGETSIZE64 reported: %s (%d B) for '%s'",
                    _bytes_to_human(size), size, self.target_path,
                )
                return size
            except OSError:
                # ioctl failed — fall back to lseek
                size = os.lseek(fd, 0, os.SEEK_END)
                os.lseek(fd, 0, os.SEEK_SET)
                log.debug(
                    "lseek fallback size: %s (%d B) for '%s'",
                    _bytes_to_human(size), size, self.target_path,
                )
                return size
            finally:
                os.close(fd)
        except PermissionError:
            log.critical(
                "Cannot open '%s' to query size — permission denied.",
                self.target_path,
            )
            print(_PERMISSION_HINT, file=sys.stderr)
            return -1
        except OSError as exc:
            log.error(
                "OS error while querying size of '%s': %s",
                self.target_path, exc,
            )
            return -1

    # ──────────────────────────────────────────────────────────────────────
    # Core streaming generator
    # ──────────────────────────────────────────────────────────────────────

    def read_blocks(
        self,
        start_offset: int = 0,
        num_blocks: Optional[int] = None,
    ) -> Generator[Tuple[int, bytes], None, None]:
        """Stream raw byte chunks from the target medium (v2.2 — zero-skip window).

        Opens the device/file in binary read-only mode (if not already open),
        seeks to *start_offset*, then yields ``(window_start_offset, buffer)``
        tuples continuously until *num_blocks* raw reads have been performed or
        EOF is reached.

        Sliding-Window Guarantee (v2.2)
        --------------------------------
        For each OS read of ``chunk_size`` bytes:

        1.  ``buffer = overlap_bytes + incoming_chunk``
            where ``len(overlap_bytes) <= overlap_size`` (= 4 KiB).

        2.  ``window_start_offset = global_disk_offset - len(overlap_bytes)``
            where ``global_disk_offset`` is the absolute position of
            ``incoming_chunk[0]`` on the medium.

        3.  After the yield, ``overlap_bytes`` is updated to
            ``incoming_chunk[-overlap_size:]`` and ``global_disk_offset`` is
            advanced by ``len(incoming_chunk)`` — exactly once, preventing
            double-counting or sector skipping.

        4.  The carver MUST scan the **full** buffer (to ``len(buffer)``).

        5.  Absolute offset of a match at index ``i``::

                absolute = window_start_offset + i

        Both allocated and unallocated sectors are streamed unconditionally.

        Parameters
        ----------
        start_offset : int
            Absolute byte offset at which to begin reading (default ``0``).
        num_blocks : int | None
            Maximum number of raw-read iterations to perform.
            ``None`` (default) means read until EOF.

        Yields
        ------
        (window_start_offset, buffer) : tuple[int, bytes]
            *window_start_offset* — disk byte position of ``buffer[0]``.
            *buffer*              — ``overlap_bytes + incoming_chunk``.

        Raises
        ------
        PermissionError
            If the process lacks the required privileges to open the device.
        OSError
            For any other I/O failure (bad sector, device removed mid-scan, …).
        """
        self._open()

        # global_disk_offset: absolute position of the first byte of the NEXT
        # OS read.  Advanced by len(incoming_chunk) only — never by len(buffer).
        global_disk_offset: int = start_offset
        blocks_yielded: int = 0

        # overlap_bytes: last overlap_size bytes of the previous incoming_chunk.
        # Prepended to each new read to bridge the chunk boundary.
        overlap_bytes: bytes = b""

        try:
            # Seek to the requested start position
            if self._fh is not None:
                self._fh.seek(start_offset)                         # type: ignore[union-attr]
            else:
                os.lseek(self._fd, start_offset, os.SEEK_SET)      # type: ignore[arg-type]

            log.info(
                "Block stream started  device='%s'  offset=%d  chunk=%s  "
                "overlap=%s  limit=%s",
                self.target_path,
                start_offset,
                _bytes_to_human(self.chunk_size),
                _bytes_to_human(self.overlap_size),
                str(num_blocks) if num_blocks is not None else "unlimited",
            )

            while True:
                # Honour the caller's block-count limit
                if num_blocks is not None and blocks_yielded >= num_blocks:
                    log.debug("Reached num_blocks limit (%d).", num_blocks)
                    break

                # ── Read one full chunk from the device / image ────────────
                if self._fh is not None:
                    incoming_chunk: bytes = self._fh.read(self.chunk_size)   # type: ignore[union-attr]
                else:
                    incoming_chunk = os.read(self._fd, self.chunk_size)      # type: ignore[arg-type]

                if not incoming_chunk:
                    log.debug(
                        "EOF reached at global_disk_offset=%d.", global_disk_offset
                    )
                    break

                # ── Assemble zero-skip combined buffer ─────────────────────
                # buffer[0] == disk byte at (global_disk_offset - len(overlap_bytes))
                buffer: bytes = overlap_bytes + incoming_chunk
                window_start_offset: int = global_disk_offset - len(overlap_bytes)

                yield window_start_offset, buffer

                # ── Advance sliding state ──────────────────────────────────
                # Overlap = last overlap_size bytes of the FRESH chunk only.
                # Offset counter advances by len(incoming_chunk), never by len(buffer).
                chunk_len: int = len(incoming_chunk)
                overlap_bytes = (
                    incoming_chunk[-self.overlap_size:]
                    if chunk_len >= self.overlap_size
                    else incoming_chunk
                )
                global_disk_offset += chunk_len
                blocks_yielded += 1

            log.info(
                "Block stream complete  blocks=%d  bytes_read=%s",
                blocks_yielded,
                _bytes_to_human(global_disk_offset - start_offset),
            )

        except PermissionError:
            log.critical(
                "Permission denied while reading '%s' at global_disk_offset=%d.",
                self.target_path, global_disk_offset,
            )
            print(_PERMISSION_HINT, file=sys.stderr)
            raise
        except OSError as exc:
            log.error(
                "I/O error at global_disk_offset=%d on '%s': %s",
                global_disk_offset, self.target_path, exc,
            )
            raise

    # ──────────────────────────────────────────────────────────────────────
    # Internal open / close helpers
    # ──────────────────────────────────────────────────────────────────────

    def _open(self) -> None:
        """Open the target in read-only binary mode (idempotent).

        Block devices are opened via the low-level ``os.open`` with
        ``O_RDONLY | O_NONBLOCK`` so the kernel does not attempt to mount
        the medium or block on a device with no media.

        Image files are opened via the standard Python ``open()`` call
        which is more portable and gives us the convenience of the
        ``io.BufferedReader`` interface.
        """
        if self._fh is not None or self._fd is not None:
            return  # already open

        try:
            if self.is_block_device:
                self._fd = os.open(
                    self.target_path,
                    os.O_RDONLY | os.O_NONBLOCK,
                )
                log.debug(
                    "Opened block device '%s' (fd=%d).",
                    self.target_path, self._fd,
                )
            else:
                self._fh = open(self.target_path, "rb")             # noqa: WPS515
                log.debug(
                    "Opened image file '%s'.",
                    self.target_path,
                )
        except PermissionError:
            log.critical(
                "Permission denied opening '%s'.", self.target_path
            )
            print(_PERMISSION_HINT, file=sys.stderr)
            raise
        except OSError as exc:
            log.error("Failed to open '%s': %s", self.target_path, exc)
            raise

    def close(self) -> None:
        """Close all open file descriptors associated with this scanner.

        Safe to call multiple times; subsequent calls are no-ops.
        Also called automatically when the instance is used as a context
        manager (``with DriveScanner(...) as s:``).
        """
        if self._fh is not None:
            try:
                self._fh.close()                                    # type: ignore[union-attr]
                log.debug("Closed file handle for '%s'.", self.target_path)
            except OSError as exc:
                log.warning("Error closing file handle: %s", exc)
            finally:
                self._fh = None

        if self._fd is not None:
            try:
                os.close(self._fd)
                log.debug("Closed fd=%d for '%s'.", self._fd, self.target_path)
            except OSError as exc:
                log.warning("Error closing fd=%d: %s", self._fd, exc)
            finally:
                self._fd = None

    # ── Context-manager protocol ──────────────────────────────────────────

    def __enter__(self) -> "DriveScanner":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"DriveScanner(target='{self.target_path}', "
            f"chunk_size={self.chunk_size}, "
            f"is_block_device={self.is_block_device})"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Hex dump utility
# ══════════════════════════════════════════════════════════════════════════════

def _hex_dump(data: bytes, base_offset: int = 0, width: int = 16) -> str:
    """Format *data* as a classic hex + ASCII dump string.

    Parameters
    ----------
    data : bytes
        Raw bytes to format.
    base_offset : int
        Starting address for the left-hand address column.
    width : int
        Bytes per row (default 16).

    Returns
    -------
    str
        Printable multi-line hex dump.
    """
    rows: List[str] = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_col   = " ".join(f"{b:02x}" for b in chunk)
        ascii_col = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        addr      = base_offset + i
        rows.append(f"  {addr:08x}  {hex_col:<{width * 3}}  |{ascii_col}|")
    return "\n".join(rows)


# ══════════════════════════════════════════════════════════════════════════════
# CLI self-test  (sudo python3 core/scanner.py)
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import tempfile

    SEPARATOR  = "═" * 72
    SEPARATOR2 = "─" * 72
    DEMO_BLOCKS = 3
    SAMPLE_PATH = "test_sample.raw"
    SAMPLE_SIZE = 4096 * DEMO_BLOCKS + 1024  # slightly over 3 full chunks

    # ────────────────────────────────────────────────────────────────────
    print(f"\n{SEPARATOR}")
    print("  Smart Autopsy — Module 1: Data Acquisition & Raw Sector Reader")
    print(f"{SEPARATOR}\n")

    # ── Step 1: enumerate physical drives ────────────────────────────────
    print("[ STEP 1 ]  Enumerating block devices via lsblk …\n")

    drives: List[Dict[str, str]] = []
    try:
        drives = list_physical_drives()
    except (RuntimeError, ValueError) as err:
        print(f"  WARNING: {err}")
        print("  (Continuing with synthetic image test.)\n")

    if drives:
        col_w = [16, 12, 8, 30, 6, 20]
        headers = ["PATH", "SIZE", "TYPE", "MODEL", "...MOUNTED", "MOUNTPOINT"]
        header_row = "  " + "  ".join(h.ljust(col_w[i]) for i, h in enumerate(headers))
        print(header_row)
        print("  " + SEPARATOR2)
        for d in drives:
            row = "  " + "  ".join([
                d["path"].ljust(col_w[0]),
                d["human_size"].ljust(col_w[1]),
                d["type"].ljust(col_w[2]),
                d["model"][:28].ljust(col_w[3]),
                ("YES" if d["mountpoint"] else "no").ljust(col_w[4]),
                d["mountpoint"].ljust(col_w[5]),
            ])
            print(row)
        print()
    else:
        print("  (No block devices discovered — likely not running on Linux.)\n")

    # ── Step 2: choose target ────────────────────────────────────────────
    print(SEPARATOR2)
    print("[ STEP 2 ]  Selecting scan target …\n")

    target: Optional[str] = None

    # Prefer the first non-system disk if available
    for d in drives:
        if d["type"] == "disk" and d["mountpoint"] == "" and d["path"] != "/dev/sda":
            target = d["path"]
            print(f"  Auto-selected physical device: {target}")
            break

    # Fall back to a synthetic binary test file
    if target is None:
        print(f"  No suitable physical device found.  "
              f"Creating synthetic test file: '{SAMPLE_PATH}'")

        with open(SAMPLE_PATH, "wb") as f:
            # Magic header that a carver would look for
            f.write(b"\x53\x4D\x41\x52\x54\x41\x55\x54\x4F\x50\x53\x59")  # SMARTAUTOPSY
            f.write(b"\xFF\xD8\xFF\xE0")                 # JPEG SOI marker
            # Fill remainder with a cycling byte pattern
            pattern = bytes(range(256))
            remaining = SAMPLE_SIZE - f.tell()
            f.write((pattern * ((remaining // 256) + 1))[:remaining])

        size_on_disk = os.path.getsize(SAMPLE_PATH)
        print(f"  Test file created: {SAMPLE_PATH}  ({_bytes_to_human(size_on_disk)})\n")
        target = SAMPLE_PATH

    # ── Step 3: permissions check ─────────────────────────────────────────
    print(SEPARATOR2)
    print("[ STEP 3 ]  Checking privileges …\n")

    scanner = DriveScanner(target_path=target)   # uses 2 MiB default
    perms_ok = scanner.check_permissions()

    if not perms_ok:
        print("  Aborting: insufficient permissions.")
        sys.exit(1)

    print(f"  {scanner}\n")

    # ── Step 4: query device size ──────────────────────────────────────────
    print(SEPARATOR2)
    print("[ STEP 4 ]  Querying total medium size …\n")

    total_bytes = scanner.get_total_size()
    if total_bytes >= 0:
        print(f"  Total size : {_bytes_to_human(total_bytes)}  ({total_bytes:,} bytes)\n")
    else:
        print("  Total size : UNKNOWN\n")

    # ── Step 5: read first N blocks and display hex dump ──────────────────
    print(SEPARATOR2)
    print(f"[ STEP 5 ]  Reading first {DEMO_BLOCKS} chunks "
          f"(chunk_size={_bytes_to_human(scanner.chunk_size)}) …\n")

    try:
        with scanner:
            for block_idx, (offset, data) in enumerate(
                scanner.read_blocks(start_offset=0, num_blocks=DEMO_BLOCKS),
                start=1,
            ):
                print(f"  ┌─ Chunk #{block_idx:02d}  "
                      f"offset=0x{offset:08x} ({offset:,} B)  "
                      f"length={len(data)} B")
                print(f"  │  hex() → {data[:32].hex()} …")
                print(_hex_dump(data[:64], base_offset=offset))
                print(f"  └{'─' * 65}\n")

    except PermissionError:
        sys.exit(1)
    except OSError as exc:
        print(f"\n  I/O ERROR: {exc}")
        sys.exit(1)

    # ── Cleanup ────────────────────────────────────────────────────────────
    if target == SAMPLE_PATH and os.path.exists(SAMPLE_PATH):
        os.remove(SAMPLE_PATH)
        print(f"  Temporary test file removed: {SAMPLE_PATH}")

    print(f"\n{SEPARATOR}")
    print("  Module 1 self-test complete.  All systems nominal.")
    print(f"{SEPARATOR}\n")
