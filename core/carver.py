"""
smart_autopsy/core/carver.py
══════════════════════════════════════════════════════════════════════════════
Module 2 — File Carver Engine
Smart Autopsy | Digital Forensics Platform

Pipeline stage:  Raw Sector Reader  ──►  File Carver  ──►  Evidence Export

Design principles
─────────────────
* Sliding-window buffer  — raw chunks from DriveScanner are appended to a
  continuous bytearray.  Signatures that straddle a 4096-byte chunk boundary
  are therefore never missed.

* Zero writes to source  — the output_dir is checked at startup to ensure it
  does not share a mount-point with the target device.  Any attempt to write
  back to the source drive raises SafetyViolationError immediately.

* Max-size guard         — any single carved file is capped at MAX_FILE_BYTES
  (50 MiB) to prevent runaway allocations from corrupted data regions.

* Progress callback      — `progress_callback(bytes_scanned, total_bytes,
  carved_count)` lets the GUI update its progress bar without polling.

* Stop flag              — callers set `carver.stop_flag = True` to cleanly
  interrupt a running carve_stream() from another thread.

Author : Smart Autopsy Engineering Team
Python : 3.9+
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .scanner import DriveScanner

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
log = logging.getLogger("smart_autopsy.carver")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
MAX_FILE_BYTES: int = 50 * 1024 * 1024      # 50 MiB hard cap per carved file
SLIDE_KEEP_BYTES: int = 16                  # bytes retained at buffer tail
                                            # to catch signatures split across chunks

# ─────────────────────────────────────────────────────────────────────────────
# Signature table
# Each entry: (file_extension, [(header, footer), ...])
# Multiple header variants share the same footer per type.
# ─────────────────────────────────────────────────────────────────────────────
_SIGNATURES: List[Tuple[str, List[Tuple[bytes, bytes]]]] = [
    ("jpg", [
        (b"\xFF\xD8\xFF\xE0", b"\xFF\xD9"),
        (b"\xFF\xD8\xFF\xE1", b"\xFF\xD9"),
        (b"\xFF\xD8\xFF\xE2", b"\xFF\xD9"),
        (b"\xFF\xD8\xFF\xDB", b"\xFF\xD9"),
    ]),
    ("pdf", [
        (b"%PDF",             b"%%EOF"),
    ]),
    ("png", [
        (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
    ]),
    ("zip", [
        (b"PK\x03\x04",      b"PK\x05\x06"),
    ]),
    ("mp3", [
        (b"\xFF\xFB",        b"\xFF\xFB"),   # approximate — footer = next frame header
        (b"ID3",             b"\xFF\xFB"),
    ]),
    ("gif", [
        (b"GIF87a",          b"\x00\x3B"),
        (b"GIF89a",          b"\x00\x3B"),
    ]),
    ("docx", [
        # DOCX is a ZIP variant; detected by PK + specific magic
        (b"PK\x03\x04\x14\x00\x06\x00", b"PK\x05\x06"),
    ]),
    ("bmp", [
        (b"BM",              b"\x00" * 2),   # BMP has no reliable footer; size-capped
    ]),
]

# Flat lookup: header_bytes -> (extension, footer_bytes)
_HEADER_MAP: Dict[bytes, Tuple[str, bytes]] = {}
for _ext, _variants in _SIGNATURES:
    for _hdr, _ftr in _variants:
        _HEADER_MAP[_hdr] = (_ext, _ftr)

# Sorted by descending header length so longer (more specific) signatures
# are checked before shorter ones (e.g. DOCX before plain ZIP)
_SORTED_HEADERS: List[bytes] = sorted(_HEADER_MAP.keys(), key=len, reverse=True)

# Maximum header length — used to size the backward-scan window
_MAX_HDR_LEN: int = max(len(h) for h in _SORTED_HEADERS)


# ─────────────────────────────────────────────────────────────────────────────
# Safety violation
# ─────────────────────────────────────────────────────────────────────────────

class SafetyViolationError(RuntimeError):
    """Raised when an output path resolves to the same device as the source.

    Writing recovered files back to the evidence drive would corrupt
    unallocated sectors that may contain additional recoverable data.
    """


# ─────────────────────────────────────────────────────────────────────────────
# Result record
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CarvedFile:
    """Metadata record for a single recovered file."""

    name:        str   = ""         # filename as written to disk
    file_type:   str   = ""         # extension / MIME type label
    offset_hex:  str   = ""         # start offset formatted as 0x…
    offset_int:  int   = 0          # start offset as integer
    size_bytes:  int   = 0          # recovered byte count
    human_size:  str   = ""         # human-readable size
    export_path: str   = ""         # absolute path of the written file
    md5:         str   = ""         # MD5 of recovered bytes
    sha256:      str   = ""         # SHA-256 of recovered bytes
    timestamp:   float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, str]:
        return {
            "name":        self.name,
            "type":        self.file_type,
            "offset":      self.offset_hex,
            "size":        self.human_size,
            "path":        self.export_path,
            "md5":         self.md5,
            "sha256":      self.sha256,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _bytes_to_human(n: int) -> str:
    """Convert byte count to IEC human-readable string."""
    value = float(n)
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024.0:
            return f"{int(value)} {suffix}" if suffix == "B" else f"{value:.2f} {suffix}"
        value /= 1024.0
    return f"{value:.2f} PiB"


def _get_device_id(path: str) -> Optional[int]:
    """Return the st_dev of *path*, or None if stat fails."""
    try:
        return os.stat(path).st_dev
    except OSError:
        return None


def _hash_bytes(data: bytes) -> Tuple[str, str]:
    """Return (MD5-hex, SHA256-hex) of *data*."""
    md5    = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256


# ══════════════════════════════════════════════════════════════════════════════
# FileCarver
# ══════════════════════════════════════════════════════════════════════════════

class FileCarver:
    """Signature-based file carver that operates on a DriveScanner stream.

    Usage
    -----
    ::

        carver = FileCarver()
        results = carver.carve_stream(
            scanner=DriveScanner("/dev/sdb"),
            output_dir="/mnt/evidence_export",
            progress_callback=my_callback,
        )

    Thread safety
    -------------
    Set ``carver.stop_flag = True`` from any thread to request a clean stop.
    The generator checks the flag between every chunk and will exit the loop
    on the next iteration, writing any in-progress file before returning.

    Parameters
    ----------
    signatures : list | None
        Override the built-in signature table for testing.  Pass ``None``
        (default) to use the production set.
    """

    def __init__(self, signatures: Optional[List[Tuple[str, List[Tuple[bytes, bytes]]]]] = None) -> None:
        self.stop_flag:  bool = False
        self._lock: threading.Lock = threading.Lock()

        # Build header lookup from the provided or default signature table
        if signatures is not None:
            self._header_map: Dict[bytes, Tuple[str, bytes]] = {}
            for ext, variants in signatures:
                for hdr, ftr in variants:
                    self._header_map[hdr] = (ext, ftr)
            self._sorted_headers: List[bytes] = sorted(
                self._header_map.keys(), key=len, reverse=True
            )
        else:
            self._header_map    = _HEADER_MAP
            self._sorted_headers = _SORTED_HEADERS

        log.info(
            "FileCarver initialised with %d header signatures.",
            len(self._header_map),
        )

    # ──────────────────────────────────────────────────────────────────────
    # Safety gate — enforce no-write-back rule
    # ──────────────────────────────────────────────────────────────────────

    def _assert_safe_output(self, scanner: DriveScanner, output_dir: str) -> None:
        """Raise SafetyViolationError if output_dir is on the source device.

        Compares st_dev values so symlinks and bind-mounts are also caught.
        """
        os.makedirs(output_dir, exist_ok=True)

        src_dev  = _get_device_id(scanner.target_path)
        dest_dev = _get_device_id(output_dir)

        if src_dev is not None and dest_dev is not None and src_dev == dest_dev:
            raise SafetyViolationError(
                f"CRITICAL FORENSIC SAFETY VIOLATION\n"
                f"  Source : {scanner.target_path}  (device id {src_dev})\n"
                f"  Output : {output_dir}  (device id {dest_dev})\n"
                f"\n"
                f"The destination directory resolves to the SAME storage device\n"
                f"as the evidence source.  Writing here would overwrite unallocated\n"
                f"sectors and destroy potential evidence.\n"
                f"\n"
                f"Choose an output path on a DIFFERENT drive or mount-point."
            )

        log.info(
            "Safety check passed — source dev=%s, output dev=%s",
            src_dev, dest_dev,
        )

    # ──────────────────────────────────────────────────────────────────────
    # Core carve loop
    # ──────────────────────────────────────────────────────────────────────

    def carve_stream(
        self,
        scanner:           DriveScanner,
        output_dir:        str,
        progress_callback: Optional[Callable[[int, int, int], None]] = None,
    ) -> List[CarvedFile]:
        """Carve recoverable files from the DriveScanner byte stream.

        Parameters
        ----------
        scanner : DriveScanner
            Configured, unopened scanner pointing at the evidence medium.
        output_dir : str
            Directory to write recovered files into.  Must be on a different
            physical device than the scan target (enforced).
        progress_callback : callable | None
            Called as ``progress_callback(bytes_scanned, total_bytes,
            carved_count)`` after processing each chunk.  Runs in the same
            thread as the carver — keep it non-blocking.

        Returns
        -------
        list[CarvedFile]
            Metadata for every successfully recovered file, in discovery order.

        Raises
        ------
        SafetyViolationError
            If *output_dir* is on the same device as the scan target.
        PermissionError
            If the process lacks privileges to open the block device.
        OSError
            For any lower-level I/O failure.
        """
        # ── Pre-flight checks ──────────────────────────────────────────────
        self._assert_safe_output(scanner, output_dir)
        os.makedirs(output_dir, exist_ok=True)

        total_bytes:  int = scanner.get_total_size()   # -1 if unknowable
        bytes_scanned: int = 0
        carved_files: List[CarvedFile] = []

        # ── Sliding window state ───────────────────────────────────────────
        # `buf`      — continuous byte buffer across chunk boundaries
        # `buf_base` — absolute device offset of buf[0]
        buf:      bytearray = bytearray()
        buf_base: int       = 0

        # Active carve state — set when a header has been matched
        carve_ext:    Optional[str]   = None   # file extension being carved
        carve_footer: Optional[bytes] = None   # footer to look for
        carve_start:  int             = 0      # absolute offset of header
        carve_buf:    bytearray       = bytearray()  # accumulating file bytes

        file_counter: int = 0   # monotonic counter for unique filenames

        log.info(
            "carve_stream started  target='%s'  output='%s'  total=%s",
            scanner.target_path, output_dir,
            _bytes_to_human(total_bytes) if total_bytes > 0 else "unknown",
        )
        t_start = time.monotonic()

        def _flush_carved_file() -> Optional[CarvedFile]:
            """Write the accumulated carve_buf to disk and return metadata."""
            nonlocal file_counter, carve_ext, carve_footer, carve_start, carve_buf

            if not carve_buf or carve_ext is None:
                return None

            file_counter += 1
            fname   = f"recovered_{file_counter:05d}.{carve_ext}"
            fpath   = os.path.join(output_dir, fname)
            data    = bytes(carve_buf)
            md5, sha256 = _hash_bytes(data)

            try:
                with open(fpath, "wb") as fout:
                    fout.write(data)
            except OSError as exc:
                log.error("Failed to write carved file '%s': %s", fpath, exc)
                return None

            cf = CarvedFile(
                name        = fname,
                file_type   = carve_ext.upper(),
                offset_hex  = f"0x{carve_start:08X}",
                offset_int  = carve_start,
                size_bytes  = len(data),
                human_size  = _bytes_to_human(len(data)),
                export_path = fpath,
                md5         = md5,
                sha256      = sha256,
            )
            log.info(
                "Carved: %s  %s  @ %s  md5=%s",
                fname, cf.human_size, cf.offset_hex, md5[:8] + "…",
            )

            # Reset active carve state
            carve_ext    = None
            carve_footer = None
            carve_start  = 0
            carve_buf    = bytearray()
            return cf

        # ── Main streaming loop ────────────────────────────────────────────
        try:
            for chunk_offset, chunk in scanner.read_blocks():
                if self.stop_flag:
                    log.info("Stop flag set — halting carver at offset %d.", chunk_offset)
                    break

                bytes_scanned += len(chunk)
                buf.extend(chunk)

                # Process every byte position in the newly grown buffer
                # We scan only the newly arrived portion, but we keep a
                # _MAX_HDR_LEN tail from the previous iteration so that
                # headers split across chunk boundaries are found.
                scan_start = max(0, len(buf) - len(chunk) - _MAX_HDR_LEN)

                i = scan_start
                while i < len(buf):

                    # ── If actively carving ───────────────────────────────
                    if carve_ext is not None:
                        remaining = bytes(buf[i:])

                        # Check for footer
                        footer_pos = remaining.find(carve_footer)  # type: ignore[arg-type]
                        if footer_pos != -1:
                            # Include the footer itself
                            end_pos = i + footer_pos + len(carve_footer)  # type: ignore[arg-type]
                            carve_buf.extend(buf[i:end_pos])

                            # Flush
                            cf = _flush_carved_file()
                            if cf:
                                carved_files.append(cf)
                                if progress_callback:
                                    progress_callback(bytes_scanned, total_bytes, len(carved_files))

                            i = end_pos
                            continue

                        # No footer yet — accumulate everything and guard max size
                        carve_buf.extend(buf[i:])
                        i = len(buf)

                        if len(carve_buf) > MAX_FILE_BYTES:
                            log.warning(
                                "Max size (%s) exceeded for %s at offset %s — discarding.",
                                _bytes_to_human(MAX_FILE_BYTES), carve_ext,
                                f"0x{carve_start:08X}",
                            )
                            carve_ext    = None
                            carve_footer = None
                            carve_buf    = bytearray()
                        continue

                    # ── Not carving — scan for headers ────────────────────
                    matched = False
                    for hdr in self._sorted_headers:
                        hlen = len(hdr)
                        if buf[i:i + hlen] == hdr:
                            carve_ext    = self._header_map[hdr][0]
                            carve_footer = self._header_map[hdr][1]
                            carve_start  = buf_base + i
                            carve_buf    = bytearray(hdr)
                            log.debug(
                                "Header match: %s @ 0x%08X",
                                carve_ext, carve_start,
                            )
                            i += hlen
                            matched = True
                            break

                    if not matched:
                        i += 1

                # Trim the buffer: keep only the tail we need for the next
                # iteration's backward-scan window (_MAX_HDR_LEN bytes).
                # If we are mid-carve we must not trim carve data — but
                # carve_buf is separate, so buf itself can still be trimmed.
                if not carve_ext:
                    trim_at = max(0, len(buf) - _MAX_HDR_LEN)
                    buf_base += trim_at
                    del buf[:trim_at]

                # Progress notification
                if progress_callback:
                    progress_callback(bytes_scanned, total_bytes, len(carved_files))

        finally:
            scanner.close()

        # Flush any in-progress carve that reached EOF without a footer
        if carve_ext and carve_buf:
            log.info(
                "EOF reached mid-carve for %s @ %s — flushing %s without footer.",
                carve_ext, f"0x{carve_start:08X}", _bytes_to_human(len(carve_buf)),
            )
            cf = _flush_carved_file()
            if cf:
                carved_files.append(cf)

        elapsed = time.monotonic() - t_start
        log.info(
            "carve_stream complete  duration=%.1fs  bytes=%s  files=%d",
            elapsed, _bytes_to_human(bytes_scanned), len(carved_files),
        )

        return carved_files
