"""
smart_autopsy/core/parsers.py
══════════════════════════════════════════════════════════════════════════════
Module 2a — Format-Aware Structural Parsers
Smart Autopsy | Digital Forensics Platform

Each public function in this module receives a raw byte buffer that begins
exactly at a valid file-type header and attempts to delimit the true end of
that file by walking its internal chunk/segment/frame structure rather than
searching naively for a footer byte-sequence.

Public API
──────────
    carve_png (buf, offset, max_bytes) -> (bytes | None, str)
    carve_jpeg(buf, offset, max_bytes) -> (bytes | None, str)
    carve_pdf (buf, offset, max_bytes) -> (bytes | None, str)
    carve_mp3 (buf, offset, max_bytes) -> (bytes | None, str)

    All four functions accept an optional ``max_bytes`` keyword argument
    that overrides the per-format default from ``FORMAT_MAX_BYTES``.  Pass
    a custom value to tighten or relax the upper-bound at call time without
    touching the global table.

Return contract
───────────────
    (carved_bytes, status_message)

    carved_bytes : bytes  — the complete carved file, ready to write to disk.
                   None   — the candidate was rejected (false positive or
                            structurally invalid); caller should discard it.
    status_message : human-readable one-liner explaining the outcome.

Global policy
─────────────
    MIN_FILE_BYTES = 4096 (4 KiB / 1 standard sector-cluster block).
    Any carved payload below this threshold is unconditionally rejected as a
    false-positive artifact regardless of structural validity.

    FORMAT_MAX_BYTES maps each supported extension to its upper-bound cap:
        png  — 100 MiB  (high-res screenshots / lossless graphics)
        jpg  —  50 MiB  (standard DSLR / phone camera photos)
        pdf  — 250 MiB  (large multi-page scanned documents)
        mp3  — 150 MiB  (long audio tracks / podcasts)

Author : Smart Autopsy Engineering Team
Python : 3.9+
"""

from __future__ import annotations

import logging
import re
import struct
import zlib
from typing import Optional, Tuple

log = logging.getLogger("smart_autopsy.parsers")

# ─────────────────────────────────────────────────────────────────────────────
# Global constants
# ─────────────────────────────────────────────────────────────────────────────

MIN_FILE_BYTES: int = 4096     # 4 KiB hard minimum — discard below this

# Per-format upper-bound caps (configurable via the max_bytes parameter).
# Keys match the extension strings used in carver.py's signature table.
FORMAT_MAX_BYTES: dict = {
    "png": 100 * 1024 * 1024,   # 100 MiB — high-res PNGs / screenshots
    "jpg":  50 * 1024 * 1024,   #  50 MiB — standard camera photos
    "pdf": 250 * 1024 * 1024,   # 250 MiB — large documents / multi-page scans
    "mp3": 150 * 1024 * 1024,   # 150 MiB — long audio tracks / podcasts
}

# Convenience scalar for legacy callers that referenced MAX_FILE_BYTES.
# Equals the largest single-format cap so it is always a safe upper bound.
MAX_FILE_BYTES: int = max(FORMAT_MAX_BYTES.values())  # 250 MiB

# ─────────────────────────────────────────────────────────────────────────────
# Type alias
# ─────────────────────────────────────────────────────────────────────────────

CarveResult = Tuple[Optional[bytes], str]

# ══════════════════════════════════════════════════════════════════════════════
# Internal helpers
# ══════════════════════════════════════════════════════════════════════════════

def _size_check(data: bytes, label: str) -> CarveResult:
    """Return an error result if *data* is below the minimum file size."""
    if len(data) < MIN_FILE_BYTES:
        msg = (
            f"{label}: discarded — {len(data)} B < {MIN_FILE_BYTES} B "
            f"minimum (false-positive fragment)"
        )
        log.debug(msg)
        return None, msg
    return data, f"{label}: OK ({len(data):,} B)"


def _read_be_uint32(buf: bytes, pos: int) -> int:
    """Read a 4-byte big-endian unsigned integer from *buf* at *pos*."""
    return struct.unpack_from(">I", buf, pos)[0]


# ══════════════════════════════════════════════════════════════════════════════
# PNG Parser
# ══════════════════════════════════════════════════════════════════════════════

_PNG_HEADER: bytes = b"\x89PNG\r\n\x1a\n"
_PNG_HEADER_LEN: int = 8
_PNG_IEND_TYPE: bytes = b"IEND"

# Minimum required chunk overhead: 4 (length) + 4 (type) + 0 (data) + 4 (CRC)
_PNG_CHUNK_MIN: int = 12


def carve_png(buf: bytes, offset: int = 0,
              max_bytes: Optional[int] = None) -> CarveResult:
    """Parse a PNG byte stream starting at *offset* in *buf*.

    Walks chunk-by-chunk (length -> type -> data -> CRC32), verifying the CRC
    of every chunk with ``zlib.crc32``.  Stops when the ``IEND`` chunk is
    reached and consumed.

    Parameters
    ----------
    buf       : bytes        - raw byte buffer containing the PNG (and more).
    offset    : int          - byte position where the PNG header starts.
    max_bytes : int | None   - upper-bound cap in bytes.  Defaults to
                               ``FORMAT_MAX_BYTES['png']`` (100 MiB).

    Returns
    -------
    (carved_bytes, status) - see module docstring for the return contract.
    """
    _max: int = max_bytes if max_bytes is not None else FORMAT_MAX_BYTES["png"]
    label = f"PNG@0x{offset:08X}"

    if buf[offset : offset + _PNG_HEADER_LEN] != _PNG_HEADER:
        return None, f"{label}: header mismatch"

    pos: int = offset + _PNG_HEADER_LEN   # points past the 8-byte signature
    chunks_parsed: int = 0

    while pos < len(buf):
        # Need at least 12 bytes for a minimal chunk
        if pos + _PNG_CHUNK_MIN > len(buf):
            return None, f"{label}: truncated — buffer ended inside chunk header"

        chunk_length: int = _read_be_uint32(buf, pos)
        pos += 4

        chunk_type: bytes = buf[pos : pos + 4]
        pos += 4

        # Sanity guard on chunk length
        if chunk_length > _max:
            return None, (
                f"{label}: rejected — chunk '{chunk_type}' declares "
                f"length {chunk_length:,} B (exceeds {_max:,} B cap)"
            )

        # Need chunk_length bytes of data + 4 bytes of CRC
        if pos + chunk_length + 4 > len(buf):
            return None, (
                f"{label}: truncated — buffer ended inside chunk "
                f"'{chunk_type}' data/CRC"
            )

        chunk_data: bytes = buf[pos : pos + chunk_length]
        pos += chunk_length

        stored_crc: int = _read_be_uint32(buf, pos)
        pos += 4

        # Verify CRC32 over (type || data)
        computed_crc: int = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        if computed_crc != stored_crc:
            log.debug(
                "%s: CRC mismatch on chunk '%s' (stored=0x%08X, computed=0x%08X) "
                "after %d valid chunks — stopping",
                label, chunk_type, stored_crc, computed_crc, chunks_parsed,
            )
            if chunks_parsed == 0:
                return None, f"{label}: first chunk CRC invalid — not a valid PNG"
            break

        chunks_parsed += 1
        log.debug("%s: chunk '%s' len=%d CRC OK", label, chunk_type, chunk_length)

        if chunk_type == _PNG_IEND_TYPE:
            carved: bytes = buf[offset:pos]
            log.info("%s: IEND reached — %d chunks, %d B", label, chunks_parsed, len(carved))
            return _size_check(carved, label)

    # Reached end of buffer without IEND — truncated PNG
    carved = buf[offset:pos]
    log.warning("%s: IEND not found — truncated PNG, flushing %d B", label, len(carved))
    return _size_check(carved, label)


# ══════════════════════════════════════════════════════════════════════════════
# JPEG Parser
# ══════════════════════════════════════════════════════════════════════════════

_JPEG_SOI: bytes = b"\xFF\xD8"
_JPEG_EOI: bytes = b"\xFF\xD9"
_JPEG_SOI_LEN: int = 2
_JPEG_EOI_LEN: int = 2

# Standalone markers (no length field follows)
_JPEG_STANDALONE_MARKERS: frozenset = frozenset({
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,  # RST0..RST7
    0xD8,  # SOI (Start Of Image)
    0xD9,  # EOI (End Of Image) — handled explicitly above
    0x01,  # TEM (Temporary Private Use)
})

# SOS marker value
_JPEG_SOS_MARKER: int = 0xDA


def carve_jpeg(buf: bytes, offset: int = 0,
               max_bytes: Optional[int] = None) -> CarveResult:
    """Parse a JPEG byte stream starting at *offset* in *buf*.

    Walks the JPEG APP/marker segment chain using the 2-byte marker + 2-byte
    length header to hop between segments.  When the SOS (Start Of Scan)
    marker is found the parser scans the subsequent entropy-coded data for a
    properly placed \\xFF\\xD9 EOI marker, ignoring stuffed \\xFF\\x00 bytes.

    Parameters
    ----------
    buf       : bytes        - raw byte buffer (may contain data after the JPEG).
    offset    : int          - byte position of the JPEG SOI (\\xFF\\xD8) header.
    max_bytes : int | None   - upper-bound cap in bytes.  Defaults to
                               ``FORMAT_MAX_BYTES['jpg']`` (50 MiB).  The JPEG
                               parser uses this only to guard the truncated-
                               stream fallback path.

    Returns
    -------
    (carved_bytes, status) - see module docstring for the return contract.
    """
    _max: int = max_bytes if max_bytes is not None else FORMAT_MAX_BYTES["jpg"]
    label = f"JPEG@0x{offset:08X}"

    if buf[offset : offset + _JPEG_SOI_LEN] != _JPEG_SOI:
        return None, f"{label}: SOI marker missing"

    pos: int = offset + _JPEG_SOI_LEN   # skip over SOI
    segments_parsed: int = 0

    while pos < len(buf):
        if buf[pos] != 0xFF:
            log.debug("%s: lost marker sync at 0x%X after %d segments", label, pos, segments_parsed)
            break

        # Skip padding 0xFF bytes (allowed by JFIF spec)
        while pos < len(buf) and buf[pos] == 0xFF:
            pos += 1

        if pos >= len(buf):
            break

        marker: int = buf[pos]
        pos += 1
        segments_parsed += 1

        # EOI — we're done
        if marker == 0xD9:
            carved: bytes = buf[offset : pos]
            log.info("%s: EOI found at 0x%X — %d B", label, pos, len(carved))
            return _size_check(carved, label)

        # Standalone markers have no length field
        if marker in _JPEG_STANDALONE_MARKERS:
            continue

        # All other markers have a 2-byte length field (big-endian, includes
        # the 2 length bytes themselves)
        if pos + 2 > len(buf):
            return None, f"{label}: truncated inside marker 0x{marker:02X} length field"

        seg_length: int = struct.unpack_from(">H", buf, pos)[0]
        if seg_length < 2:
            return None, f"{label}: invalid segment length {seg_length} for marker 0x{marker:02X}"

        data_length: int = seg_length - 2
        pos += 2   # advance past the 2 length bytes

        if marker == _JPEG_SOS_MARKER:
            pos += data_length  # skip SOS segment header
            eoi_pos = _find_jpeg_eoi(buf, pos)
            if eoi_pos == -1:
                carved = buf[offset : offset + _max]
                log.warning("%s: no EOI in scan data — truncated JPEG, %d B", label, len(carved))
                return _size_check(carved, label)
            carved = buf[offset : eoi_pos + _JPEG_EOI_LEN]
            log.info("%s: EOI after scan data at 0x%X — %d B", label, eoi_pos, len(carved))
            return _size_check(carved, label)

        pos += data_length

    carved = buf[offset:pos]
    log.warning("%s: buffer ended mid-parse — truncated JPEG, %d B", label, len(carved))
    return _size_check(carved, label)


def _find_jpeg_eoi(buf: bytes, scan_start: int) -> int:
    """Locate the real EOI (\\xFF\\xD9) in JPEG entropy-coded scan data.

    Inside entropy-coded data the byte 0xFF is always followed by 0x00
    (byte-stuffing) when it is part of image data; a genuine marker has a
    non-zero second byte.  We scan forward looking for 0xFF followed by a
    non-0x00 byte and treat the first 0xFF 0xD9 we find as the EOI.

    Returns the offset of 0xFF in *buf*, or -1 if not found.
    """
    i: int = scan_start
    limit: int = len(buf) - 1
    while i < limit:
        if buf[i] == 0xFF:
            next_byte: int = buf[i + 1]
            if next_byte == 0x00:
                i += 2
                continue
            if next_byte == 0xD9:
                return i
            if 0xD0 <= next_byte <= 0xD7:
                i += 2   # skip RST marker
                continue
            return -1
        i += 1
    return -1


# ══════════════════════════════════════════════════════════════════════════════
# PDF Parser
# ══════════════════════════════════════════════════════════════════════════════

_PDF_HEADER_RE: re.Pattern = re.compile(rb"%PDF-[0-9]\.[0-9]")
_PDF_EOF_MARKER: bytes = b"%%EOF"
_PDF_STRUCTURAL_KEYWORDS: tuple = (b"obj", b"endobj", b"xref", b"startxref", b"%%EOF")
_PDF_MIN_KEYWORDS: int = 4


def carve_pdf(buf: bytes, offset: int = 0,
              max_bytes: Optional[int] = None) -> CarveResult:
    """Parse a PDF byte stream starting at *offset* in *buf*.

    Strategy:
    1.  Verify the %PDF-X.Y header regex.
    2.  Scan forward for %%EOF (last occurrence within *max_bytes* window).
    3.  Verify the extracted slice contains the minimum structural keywords.
    4.  Apply the 4 KiB minimum-size filter.

    Parameters
    ----------
    buf       : bytes        - raw byte buffer.
    offset    : int          - byte position of the %PDF header.
    max_bytes : int | None   - upper-bound cap in bytes.  Defaults to
                               ``FORMAT_MAX_BYTES['pdf']`` (250 MiB).

    Returns
    -------
    (carved_bytes, status) - see module docstring.
    """
    _max: int = max_bytes if max_bytes is not None else FORMAT_MAX_BYTES["pdf"]
    label = f"PDF@0x{offset:08X}"

    if not _PDF_HEADER_RE.match(buf, offset):
        return None, f"{label}: header pattern mismatch"

    search_end: int = min(offset + _max, len(buf))
    window: bytes   = buf[offset:search_end]

    eof_pos = window.rfind(_PDF_EOF_MARKER)
    if eof_pos == -1:
        return None, f"{label}: %%EOF marker not found within {_max:,} B window"

    end_pos: int = offset + eof_pos + len(_PDF_EOF_MARKER) + 2
    end_pos = min(end_pos, len(buf))

    carved: bytes = buf[offset:end_pos]

    missing = [kw for kw in _PDF_STRUCTURAL_KEYWORDS if kw not in carved]
    if len(missing) > len(_PDF_STRUCTURAL_KEYWORDS) - _PDF_MIN_KEYWORDS:
        return None, (
            f"{label}: rejected — missing structural keywords: "
            + ", ".join(k.decode(errors="replace") for k in missing)
        )

    log.info("%s: %%EOF at +%d, %d B, structural keywords present", label, eof_pos, len(carved))
    return _size_check(carved, label)


# ══════════════════════════════════════════════════════════════════════════════
# MP3 Parser
# ══════════════════════════════════════════════════════════════════════════════

_ID3_HEADER: bytes = b"ID3"
_ID3_HEADER_LEN: int = 3

_MP3_MIN_FRAME_RUN: int = 3

# MPEG-1 Layer 3 bitrate table (kbps), indexed by bits 7-4 of the 3rd header byte
_MPEG1_L3_BITRATES: tuple = (
    0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, -1
)

# Sample rate table for MPEG-1, indexed by bits 3-2
_MPEG1_SAMPLE_RATES: tuple = (44100, 48000, 32000, -1)


def _parse_mp3_frame_header(buf: bytes, pos: int) -> Optional[int]:
    """Attempt to parse an MPEG-1/2 Layer 3 frame at *pos* in *buf*.

    Returns the frame length in bytes on success, or None if invalid.
    """
    if pos + 4 > len(buf):
        return None

    b0: int = buf[pos]
    b1: int = buf[pos + 1]
    b2: int = buf[pos + 2]

    # 11-bit sync word
    if b0 != 0xFF or (b1 & 0xE0) != 0xE0:
        return None

    mpeg_id: int = (b1 >> 3) & 0x03
    if mpeg_id not in (2, 3):
        return None

    layer: int = (b1 >> 1) & 0x03
    if layer != 1:   # 01 = Layer 3
        return None

    bitrate_idx: int = (b2 >> 4) & 0x0F
    bitrate: int = _MPEG1_L3_BITRATES[bitrate_idx]
    if bitrate <= 0:
        return None

    sr_idx: int = (b2 >> 2) & 0x03
    sample_rate: int = _MPEG1_SAMPLE_RATES[sr_idx]
    if sample_rate < 0:
        return None

    padding: int = (b2 >> 1) & 0x01
    frame_length: int = (144 * bitrate * 1000) // sample_rate + padding
    if frame_length < 24:
        return None

    return frame_length


def _find_mp3_sync(buf: bytes, start: int) -> int:
    """Find the next candidate MP3 frame sync at or after *start*.

    Returns the offset, or -1 if not found.
    """
    i: int = start
    limit: int = len(buf) - 4
    while i <= limit:
        if buf[i] == 0xFF and (buf[i + 1] & 0xE0) == 0xE0:
            if _parse_mp3_frame_header(buf, i) is not None:
                return i
        i += 1
    return -1


def carve_mp3(buf: bytes, offset: int = 0,
              max_bytes: Optional[int] = None) -> CarveResult:
    """Parse an MP3 byte stream starting at *offset* in *buf*.

    Accepts two forms:
    * ID3v2 tagged    — decodes the 4-byte syncsafe tag size, skips the tag
                        payload, then verifies a consecutive run of MPEG frames.
    * Raw MPEG frames — requires at least _MP3_MIN_FRAME_RUN (3) consecutive
                        structurally valid frames before accepting.

    Carves until lost sync or *max_bytes* from *offset*.

    Parameters
    ----------
    buf       : bytes        - raw byte buffer.
    offset    : int          - byte position of the ID3 tag or first sync word.
    max_bytes : int | None   - upper-bound cap in bytes.  Defaults to
                               ``FORMAT_MAX_BYTES['mp3']`` (150 MiB).

    Returns
    -------
    (carved_bytes, status) - see module docstring.
    """
    _max: int = max_bytes if max_bytes is not None else FORMAT_MAX_BYTES["mp3"]
    label = f"MP3@0x{offset:08X}"
    pos: int = offset

    # ── ID3v2 tag handling ────────────────────────────────────────────────────
    has_id3: bool = False
    if buf[pos : pos + _ID3_HEADER_LEN] == _ID3_HEADER:
        has_id3 = True
        if pos + 10 > len(buf):
            return None, f"{label}: ID3 header present but buffer too short"
        raw: bytes = buf[pos + 6 : pos + 10]
        if any(b & 0x80 for b in raw):
            return None, f"{label}: ID3 syncsafe size bytes have high bit set — malformed"
        tag_size: int = (raw[0] << 21) | (raw[1] << 14) | (raw[2] << 7) | raw[3]
        pos += 10 + tag_size
        log.debug("%s: ID3v2 tag size=%d, audio starts at 0x%X", label, tag_size, pos)

    # ── Find first valid frame sync ───────────────────────────────────────────
    first_frame: int = _find_mp3_sync(buf, pos)
    if first_frame == -1:
        return None, f"{label}: no valid MP3 frame sync found"

    # ── Walk consecutive frames ───────────────────────────────────────────────
    frame_pos: int    = first_frame
    frames_found: int = 0
    first_bitrate: int    = -1
    first_sample_rate: int = -1

    while frame_pos < len(buf) and (frame_pos - offset) < _max:
        frame_len = _parse_mp3_frame_header(buf, frame_pos)
        if frame_len is None:
            break

        b2: int          = buf[frame_pos + 2]
        bitrate_idx: int = (b2 >> 4) & 0x0F
        sr_idx: int      = (b2 >> 2) & 0x03
        bitrate: int     = _MPEG1_L3_BITRATES[bitrate_idx]
        sample_rate: int = _MPEG1_SAMPLE_RATES[sr_idx]

        if first_bitrate == -1:
            first_bitrate     = bitrate
            first_sample_rate = sample_rate
        elif bitrate != first_bitrate:
            log.debug(
                "%s: frame %d bitrate changed %d->%d kbps (VBR)",
                label, frames_found, first_bitrate, bitrate,
            )

        frames_found += 1
        frame_pos += frame_len

    if frames_found < _MP3_MIN_FRAME_RUN and not has_id3:
        return None, (
            f"{label}: rejected — only {frames_found} consecutive valid frames "
            f"(need {_MP3_MIN_FRAME_RUN}) and no ID3 tag"
        )

    if frames_found < 1:
        return None, f"{label}: no valid frames parsed after ID3 tag"

    carved: bytes = buf[offset:frame_pos]
    log.info(
        "%s: %d frames, %d B carved (id3=%s)",
        label, frames_found, len(carved), has_id3,
    )
    return _size_check(carved, label)
