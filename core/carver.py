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

from .scanner import DriveScanner, MAX_HEADER_SIZE
from .parsers import (
    carve_png,
    carve_jpeg,
    carve_pdf,
    carve_mp3,
    FORMAT_MAX_BYTES,
    MIN_FILE_BYTES as _PARSER_MIN_BYTES,
    MAX_FILE_BYTES as _PARSER_MAX_BYTES,
)

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
log = logging.getLogger("smart_autopsy.carver")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
MAX_FILE_BYTES: int = _PARSER_MAX_BYTES     # 250 MiB convenience ceiling (= max format cap)
MIN_FILE_BYTES: int = _PARSER_MIN_BYTES     # 4 KiB minimum — discard fragments

# Bytes retained at the buffer tail to catch signatures that straddle a chunk
# boundary.  Aligned with MAX_HEADER_SIZE exported by scanner (64 B).
SLIDE_KEEP_BYTES: int = MAX_HEADER_SIZE  # 64 bytes

# ─────────────────────────────────────────────────────────────────────────────
# UI thread throttling constants (v2.1)
# ─────────────────────────────────────────────────────────────────────────────

# Minimum wall-clock gap between two consecutive GUI progress dispatches.
# Prevents CustomTkinter's main-thread rendering from locking under the
# scan hot-path.  100 ms ≈ 10 FPS — imperceptible lag for a progress bar.
UI_UPDATE_INTERVAL_MS: float    = 0.100  # seconds (100 ms)

# Also cap by bytes: fire at most once per 10 MiB regardless of wall-clock
# time, so a very slow I/O device doesn't spam the GUI either.
UI_UPDATE_INTERVAL_BYTES: int   = 10 * 1024 * 1024  # 10 MiB

# Default cap for legacy formats (GIF, ZIP, BMP, DOCX) that have no structural
# parser.  100 MiB is a reasonable upper bound for compound-document formats.
_LEGACY_MAX_BYTES: int = 100 * 1024 * 1024

# File types handled by structural/chunk-level parsers (not naive footer scan)
_STRUCTURAL_EXTS: frozenset = frozenset({"png", "jpg", "pdf", "mp3"})

# Map extension to its structural parser function
_STRUCTURAL_PARSER_MAP = {
    "png": carve_png,
    "jpg": carve_jpeg,
    "pdf": carve_pdf,
    "mp3": carve_mp3,
}

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

# All unique header bytes as a flat list, ordered longest-first, for use
# with the C-native fast-path scanner in _find_next_header().
_ALL_HEADERS_SORTED: List[bytes] = _SORTED_HEADERS  # alias for clarity


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


def _find_next_header(
    buf: bytes,
    start: int,
    sorted_headers: List[bytes],
) -> Tuple[int, Optional[bytes]]:
    """C-accelerated scan for the nearest file-format header in *buf[start:].

    Uses ``bytes.find()`` — a C-native Boyer-Moore-Horspool implementation —
    to locate each known signature in one pass per signature.  The function
    returns the position and identity of the *earliest* match found.

    Parameters
    ----------
    buf : bytes
        The buffer to search (typically a 2 MiB chunk + MAX_HEADER_SIZE overlap).
    start : int
        Byte offset within *buf* at which to begin the search.
    sorted_headers : list[bytes]
        Header byte-strings ordered longest-first so more specific signatures
        win over ambiguous shorter ones that match at the same position.

    Returns
    -------
    (pos, header) : tuple[int, bytes | None]
        *pos*    — index into *buf* of the first byte of the matched header, or
                    ``len(buf)`` if nothing was found.
        *header* — the matched header bytes, or ``None`` if nothing was found.
    """
    best_pos:    int           = len(buf)
    best_header: Optional[bytes] = None

    for hdr in sorted_headers:
        pos = buf.find(hdr, start)
        if pos == -1:
            continue
        if pos < best_pos or (pos == best_pos and best_header is not None and len(hdr) > len(best_header)):
            best_pos    = pos
            best_header = hdr

    return best_pos, best_header


def _is_blank_chunk(data: bytes) -> bool:
    """Return True if *data* consists entirely of null bytes or 0xFF bytes.

    Such regions correspond to unallocated, zeroed-out, or factory-erased
    sectors and can be skipped without running any parser routines.  The check
    is implemented via C-native ``bytes`` operations and is O(n) with a very
    small constant.

    Parameters
    ----------
    data : bytes
        The raw chunk to inspect.

    Returns
    -------
    bool
        True when the chunk is provably empty / erased and safe to skip.
    """
    # Fast path: check the first and last byte before doing a full scan
    if not data:
        return True
    first = data[0]
    if first not in (0x00, 0xFF):
        return False
    # Leverage C-native count() to avoid a Python loop
    return data.count(first) == len(data)


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

        # UI throttle state — track last callback time and bytes milestone
        _last_ui_t:     float = t_start
        _last_ui_bytes: int   = 0

        def _maybe_notify(force: bool = False) -> None:
            """Dispatch progress_callback when the throttle window has elapsed.

            The callback is fired if *either* of the following is true:
              - ``force`` is set (e.g. at scan completion)
              - at least ``UI_UPDATE_INTERVAL_MS`` seconds have passed since
                the last dispatch, AND at least ``UI_UPDATE_INTERVAL_BYTES``
                have been scanned since the last dispatch.

            This decouples the GUI render rate from the I/O rate, preventing
            CustomTkinter's main thread from being starved by frequent redraws.
            """
            nonlocal _last_ui_t, _last_ui_bytes
            if progress_callback is None:
                return
            now = time.monotonic()
            bytes_since = bytes_scanned - _last_ui_bytes
            time_since  = now - _last_ui_t
            if force or (time_since >= UI_UPDATE_INTERVAL_MS and bytes_since >= UI_UPDATE_INTERVAL_BYTES):
                progress_callback(bytes_scanned, total_bytes, len(carved_files))
                _last_ui_t     = now
                _last_ui_bytes = bytes_scanned

        def _flush_carved_file(force_structural: bool = False) -> Optional[CarvedFile]:
            """Validate and write the accumulated carve_buf to disk.

            For formats in _STRUCTURAL_EXTS the raw buffer is passed through
            the dedicated structural parser.  The parser enforces CRC/segment
            validation and the global 4 KiB minimum-size filter.  If the parser
            rejects the candidate the carve state is reset and None is returned.

            For all other formats (GIF, ZIP, BMP, DOCX, …) the legacy
            footer-search approach is used, but the 4 KiB filter is still
            applied before writing.
            """
            nonlocal file_counter, carve_ext, carve_footer, carve_start, carve_buf

            if not carve_buf or carve_ext is None:
                return None

            raw: bytes = bytes(carve_buf)
            data: Optional[bytes] = None

            # ── Structural parser path ─────────────────────────────────────
            if carve_ext in _STRUCTURAL_EXTS:
                parser = _STRUCTURAL_PARSER_MAP[carve_ext]
                fmt_cap: int = FORMAT_MAX_BYTES.get(carve_ext, MAX_FILE_BYTES)
                data, status = parser(raw, offset=0, max_bytes=fmt_cap)
                if data is None:
                    log.debug(
                        "Structural parser rejected %s @ 0x%08X: %s",
                        carve_ext, carve_start, status,
                    )
                    # Reset state and return — do NOT write
                    carve_ext    = None
                    carve_footer = None
                    carve_start  = 0
                    carve_buf    = bytearray()
                    return None
                log.debug("Structural parser accepted %s: %s", carve_ext, status)

            else:
                # ── Legacy path (GIF, ZIP, BMP, DOCX …) ──────────────────
                # Enforce 4 KiB minimum and 100 MiB maximum for legacy formats
                if len(raw) < MIN_FILE_BYTES:
                    log.debug(
                        "Discarding %s @ 0x%08X — %d B < %d B minimum",
                        carve_ext, carve_start, len(raw), MIN_FILE_BYTES,
                    )
                    carve_ext    = None
                    carve_footer = None
                    carve_start  = 0
                    carve_buf    = bytearray()
                    return None
                if len(raw) > _LEGACY_MAX_BYTES:
                    log.warning(
                        "Discarding %s @ 0x%08X — %d B exceeds legacy cap %s",
                        carve_ext, carve_start, len(raw),
                        _bytes_to_human(_LEGACY_MAX_BYTES),
                    )
                    carve_ext    = None
                    carve_footer = None
                    carve_start  = 0
                    carve_buf    = bytearray()
                    return None
                data = raw

            # ── Write to disk ──────────────────────────────────────────────
            file_counter += 1
            # Use .jpg extension for JPEG (internal ext is 'jpg')
            file_ext = carve_ext
            fname   = f"recovered_{file_counter:05d}.{file_ext}"
            fpath   = os.path.join(output_dir, fname)
            md5, sha256 = _hash_bytes(data)

            try:
                with open(fpath, "wb") as fout:
                    fout.write(data)
            except OSError as exc:
                log.error("Failed to write carved file '%s': %s", fpath, exc)
                carve_ext    = None
                carve_footer = None
                carve_start  = 0
                carve_buf    = bytearray()
                return None

            cf = CarvedFile(
                name        = fname,
                file_type   = file_ext.upper(),
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

        # ── Main streaming loop (v2.1 — 2 MiB chunks, C-level find) ────────
        try:
            for chunk_offset, chunk in scanner.read_blocks():
                if self.stop_flag:
                    log.info("Stop flag set — halting carver at offset %d.", chunk_offset)
                    break

                chunk_len = len(chunk)
                bytes_scanned += chunk_len

                # ── Fast path: skip blank (null / 0xFF) chunks ─────────────
                # Unallocated or factory-erased sectors contain no file data.
                # Using _is_blank_chunk() avoids running any parser routine on
                # provably empty regions, saving significant CPU time on sparse
                # or freshly wiped drives.
                if not carve_ext and _is_blank_chunk(chunk):
                    log.debug(
                        "Skipping blank chunk at offset 0x%08X (%s)",
                        chunk_offset, _bytes_to_human(chunk_len),
                    )
                    _maybe_notify()
                    continue

                # Work on an immutable bytes view so bytes.find() can operate
                # at full C speed without copying the bytearray.
                buf_view: bytes = bytes(chunk)
                buf_len:  int   = len(buf_view)

                # scan_pos is our cursor into buf_view for header searches.
                scan_pos: int = 0

                while scan_pos < buf_len:

                    # ── Actively carving a file ───────────────────────────
                    if carve_ext is not None:

                        # ── Structural-parser branch (PNG/JPEG/PDF/MP3) ───
                        if carve_ext in _STRUCTURAL_EXTS:
                            carve_buf.extend(buf_view[scan_pos:])
                            scan_pos = buf_len

                            _fmt_cap: int = FORMAT_MAX_BYTES.get(carve_ext, MAX_FILE_BYTES)
                            if len(carve_buf) >= _fmt_cap:
                                log.info(
                                    "Structural parser: buffer reached %s cap for %s @ %s — flushing.",
                                    _bytes_to_human(_fmt_cap), carve_ext,
                                    f"0x{carve_start:08X}",
                                )
                                cf = _flush_carved_file()
                                if cf:
                                    carved_files.append(cf)
                                    _maybe_notify()
                            continue

                        # ── Legacy footer-scan branch (GIF, ZIP, BMP, DOCX)
                        # Use C-native bytes.find() instead of a Python loop.
                        footer_pos = buf_view.find(carve_footer, scan_pos)  # type: ignore[arg-type]
                        if footer_pos != -1:
                            end_pos = footer_pos + len(carve_footer)          # type: ignore[arg-type]
                            carve_buf.extend(buf_view[scan_pos:end_pos])

                            cf = _flush_carved_file()
                            if cf:
                                carved_files.append(cf)
                                _maybe_notify()

                            scan_pos = end_pos
                            continue

                        # No footer yet — accumulate remainder of this chunk
                        carve_buf.extend(buf_view[scan_pos:])
                        scan_pos = buf_len

                        if len(carve_buf) > _LEGACY_MAX_BYTES:
                            log.warning(
                                "Max size (%s) exceeded for %s at offset %s — discarding.",
                                _bytes_to_human(_LEGACY_MAX_BYTES), carve_ext,
                                f"0x{carve_start:08X}",
                            )
                            carve_ext    = None
                            carve_footer = None
                            carve_buf    = bytearray()
                        continue

                    # ── Not carving — fast C-level header search ──────────
                    # _find_next_header() calls bytes.find() for every known
                    # signature and returns the earliest match position.  This
                    # replaces the old byte-by-byte Python loop and is orders
                    # of magnitude faster on 2 MiB buffers.
                    match_pos, matched_hdr = _find_next_header(
                        buf_view, scan_pos, self._sorted_headers
                    )

                    if matched_hdr is None:
                        # No header in remainder of this chunk
                        break

                    carve_ext    = self._header_map[matched_hdr][0]
                    carve_footer = self._header_map[matched_hdr][1]
                    carve_start  = chunk_offset + match_pos
                    carve_buf    = bytearray(matched_hdr)
                    log.debug(
                        "Header match: %s @ 0x%08X",
                        carve_ext, carve_start,
                    )
                    scan_pos = match_pos + len(matched_hdr)

                # Throttled UI update — at most once per 100 ms / 10 MiB
                _maybe_notify()

        finally:
            scanner.close()

        # Flush any in-progress carve that reached EOF without a footer.
        # For structural formats the parser will decide validity/completeness.
        if carve_ext and carve_buf:
            log.info(
                "EOF reached mid-carve for %s @ %s — flushing %s.",
                carve_ext, f"0x{carve_start:08X}", _bytes_to_human(len(carve_buf)),
            )
            cf = _flush_carved_file()
            if cf:
                carved_files.append(cf)

        # Final forced UI update so the GUI reaches 100 %
        _maybe_notify(force=True)

        elapsed = time.monotonic() - t_start
        speed_mib = (bytes_scanned / (1024 * 1024)) / max(elapsed, 1e-9)
        log.info(
            "carve_stream complete  duration=%.1fs  speed=%.1f MiB/s  bytes=%s  files=%d",
            elapsed, speed_mib, _bytes_to_human(bytes_scanned), len(carved_files),
        )

        return carved_files
