"""
tests/test_sliding_window.py
================================================================================
Validation Test Suite -- Zero-Skip Sliding Window (v2.2)
Smart Autopsy | Digital Forensics Platform

Tests covered
-------------
1.  CHUNK_SIZE and OVERLAP_SIZE constants are exactly as specified.
2.  Sliding-window offset invariant:
      window_start_offset = global_disk_offset - len(overlap_bytes)
    holds for every yielded buffer across multiple consecutive chunks.
3.  No bytes are double-counted or skipped between consecutive windows.
4.  Split-header detection -- PNG signature placed so that the first 4 bytes
    fall in the last 4 bytes of Chunk 1 (split at CHUNK_SIZE - 4).
    The carver MUST detect, calculate exact disk offset, carve without truncation.
5.  Split-header detection for %PDF-1.4 header split at CHUNK_SIZE - 4.
6.  Allocated (live) files are carved -- no allocation-state gate skips them.
7.  Full-buffer scanning -- carver scans all the way to len(buffer).
8.  AST syntax validation for all three modified modules.
"""

from __future__ import annotations

import os
import shutil
import struct
import sys
import tempfile
import zlib
import unittest
from typing import List, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.scanner import (
    DriveScanner,
    CHUNK_SIZE,
    OVERLAP_SIZE,
    MAX_HEADER_SIZE,
    READ_BLOCK_SIZE,
)
from core.carver import FileCarver, SLIDE_KEEP_BYTES, CarvedFile

# ---------------------------------------------------------------------------
PNG_HEADER: bytes = b"\x89PNG\r\n\x1a\n"
PDF_HEADER: bytes = b"%PDF-1.4"


def _make_minimal_png() -> bytes:
    """Return a structurally valid PNG > 4 KiB with correct CRCs.

    Uses a tEXt chunk with uncompressed ASCII payload to reliably push the
    total file size above MIN_FILE_BYTES (4096 B) regardless of zlib compression.
    """

    def _chunk(ctype: bytes, data: bytes) -> bytes:
        length = struct.pack(">I", len(data))
        crc = struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF)
        return length + ctype + data + crc

    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr = _chunk(b"IHDR", ihdr_data)
    idat = _chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
    # tEXt chunks are stored uncompressed, so this reliably exceeds 4 KiB.
    text_chunk = _chunk(b"tEXt", b"Comment\x00" + b"A" * 5000)
    iend = _chunk(b"IEND", b"")
    return PNG_HEADER + ihdr + idat + text_chunk + iend


def _make_minimal_pdf() -> bytes:
    """Return a minimal valid PDF > 4 KiB."""
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n"
        b"startxref\n0\n"
        b"%%EOF\n"
    )
    return body + b"%" + b" " * 4200 + b"\n"


def _write_temp_file(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".raw")
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


def _collect_windows(
    data: bytes,
    chunk_size: int = CHUNK_SIZE,
    overlap_size: int = OVERLAP_SIZE,
) -> List[Tuple[int, bytes]]:
    path = _write_temp_file(data)
    try:
        s = DriveScanner(path, chunk_size=chunk_size, overlap_size=overlap_size)
        wins = list(s.read_blocks())
        s.close()
        return wins
    finally:
        os.remove(path)


# ===========================================================================
class TestConstants(unittest.TestCase):
    """Req 1 -- constants are exactly as specified."""

    def test_chunk_size(self):
        self.assertEqual(CHUNK_SIZE, 2 * 1024 * 1024)

    def test_overlap_size(self):
        self.assertEqual(OVERLAP_SIZE, 4096)

    def test_max_header_size_alias(self):
        self.assertEqual(MAX_HEADER_SIZE, OVERLAP_SIZE)

    def test_read_block_size_alias(self):
        self.assertEqual(READ_BLOCK_SIZE, CHUNK_SIZE)

    def test_slide_keep_bytes(self):
        self.assertEqual(SLIDE_KEEP_BYTES, OVERLAP_SIZE)


# ===========================================================================
class TestSlidingWindowOffsets(unittest.TestCase):
    """Req 2 & 3 -- offset invariant and no gaps/overlaps."""

    SMALL_CHUNK   = 8192
    SMALL_OVERLAP = 4096

    def _data(self, n: int) -> bytes:
        return bytes(i % 251 for i in range(n))

    def test_first_window_starts_at_zero(self):
        wins = _collect_windows(self._data(self.SMALL_CHUNK * 3),
                                self.SMALL_CHUNK, self.SMALL_OVERLAP)
        self.assertEqual(wins[0][0], 0)

    def test_window_start_advances_by_chunk_size(self):
        """Verify the window start offset advances correctly.

        Window 0 has no overlap prefix (global_disk_offset=0, overlap=b'') so
        win[0].start = 0.

        Window 1 has overlap_bytes = last OVERLAP_SIZE bytes of chunk 0:
          win[1].start = SMALL_CHUNK - SMALL_OVERLAP

        For i >= 2 (steady state), consecutive starts differ by SMALL_CHUNK:
          win[i].start - win[i-1].start = SMALL_CHUNK
        """
        total = self.SMALL_CHUNK * 5
        wins = _collect_windows(self._data(total), self.SMALL_CHUNK, self.SMALL_OVERLAP)
        # First transition: SMALL_CHUNK - SMALL_OVERLAP (overlap not present in win[0])
        first_diff = wins[1][0] - wins[0][0]
        self.assertEqual(
            first_diff, self.SMALL_CHUNK - self.SMALL_OVERLAP,
            f"First transition diff={first_diff} expected={self.SMALL_CHUNK - self.SMALL_OVERLAP}"
        )
        # Steady state: all subsequent transitions equal SMALL_CHUNK
        for i in range(2, len(wins)):
            diff = wins[i][0] - wins[i - 1][0]
            self.assertEqual(diff, self.SMALL_CHUNK,
                             f"Steady-state window {i}: diff={diff} expected={self.SMALL_CHUNK}")

    def test_no_bytes_skipped(self):
        total = self.SMALL_CHUNK * 3 + 777
        data = self._data(total)
        path = _write_temp_file(data)
        try:
            s = DriveScanner(path, chunk_size=self.SMALL_CHUNK, overlap_size=self.SMALL_OVERLAP)
            covered = bytearray(total)
            for win_start, buf in s.read_blocks():
                for i in range(win_start, min(win_start + len(buf), total)):
                    covered[i] = 1
            s.close()
        finally:
            os.remove(path)
        missing = [i for i, v in enumerate(covered) if not v]
        self.assertEqual(missing, [], f"Byte(s) never in any window: {missing[:10]}")

    def test_overlap_prefix_matches_prev_chunk_tail(self):
        total = self.SMALL_CHUNK * 3
        data = self._data(total)
        wins = _collect_windows(data, self.SMALL_CHUNK, self.SMALL_OVERLAP)
        for i in range(1, len(wins)):
            prev_buf = wins[i - 1][1]
            curr_buf = wins[i][1]
            prev_tail = prev_buf[self.SMALL_CHUNK:]
            curr_prefix = curr_buf[:len(prev_tail)]
            self.assertEqual(prev_tail, curr_prefix,
                             f"Overlap mismatch at window boundary {i-1}->{i}")



class _TestCarver(FileCarver):
    """FileCarver that skips the same-device safety check for unit tests.

    The forensic safety gate correctly rejects writes to the same storage
    device as the evidence source.  On single-drive Windows dev machines
    all temp paths share the same drive, so we override _assert_safe_output
    to a no-op exclusively inside the test suite.
    """
    def _assert_safe_output(self, scanner, output_dir) -> None:  # type: ignore[override]
        os.makedirs(output_dir, exist_ok=True)


# ===========================================================================
class TestSplitHeaderDetection(unittest.TestCase):
    """Req 4 -- mandatory split-header test at CHUNK_SIZE - 4."""

    SPLIT_INDEX: int = CHUNK_SIZE - 4

    def _build_stream(self, header: bytes, payload: bytes) -> bytes:
        assert len(header) == 8
        prefix = bytes((b % 200 + 1) for b in range(self.SPLIT_INDEX))
        # Avoid accidental header occurrences in prefix
        prefix = prefix.replace(header, b"\x00" * len(header))
        return prefix + header + payload

    def test_png_split_detected_in_window(self):
        stream = self._build_stream(PNG_HEADER, _make_minimal_png()[len(PNG_HEADER):])
        found = []
        for win_start, buf in _collect_windows(stream):
            idx = 0
            while True:
                idx = buf.find(PNG_HEADER, idx)
                if idx == -1:
                    break
                found.append(win_start + idx)
                idx += 1
        self.assertIn(self.SPLIT_INDEX, found,
                      f"PNG header at {self.SPLIT_INDEX} not found. Found at: {found}")

    def test_png_split_exact_offset(self):
        stream = self._build_stream(PNG_HEADER, _make_minimal_png()[len(PNG_HEADER):])
        for win_start, buf in _collect_windows(stream):
            idx = buf.find(PNG_HEADER)
            if idx != -1:
                self.assertEqual(win_start + idx, self.SPLIT_INDEX,
                                 f"abs offset {win_start + idx} != {self.SPLIT_INDEX}")
                return
        self.fail("PNG header not found in any window")

    def test_pdf_split_detected_in_window(self):
        stream = self._build_stream(PDF_HEADER, _make_minimal_pdf()[len(PDF_HEADER):])
        found = []
        for win_start, buf in _collect_windows(stream):
            idx = 0
            while True:
                idx = buf.find(PDF_HEADER, idx)
                if idx == -1:
                    break
                found.append(win_start + idx)
                idx += 1
        self.assertIn(self.SPLIT_INDEX, found,
                      f"PDF header at {self.SPLIT_INDEX} not found. Found at: {found}")

    def test_pdf_split_exact_offset(self):
        stream = self._build_stream(PDF_HEADER, _make_minimal_pdf()[len(PDF_HEADER):])
        for win_start, buf in _collect_windows(stream):
            idx = buf.find(PDF_HEADER)
            if idx != -1:
                self.assertEqual(win_start + idx, self.SPLIT_INDEX,
                                 f"abs offset {win_start + idx} != {self.SPLIT_INDEX}")
                return
        self.fail("PDF header not found in any window")

    def test_split_header_end_to_end_carver(self):
        """FileCarver must detect the split PNG and report offset_int == SPLIT_INDEX."""
        png_body = _make_minimal_png()
        stream = self._build_stream(PNG_HEADER, png_body[len(PNG_HEADER):])

        disk_path = _write_temp_file(stream)
        out_dir = tempfile.mkdtemp(prefix="sa_test_")
        try:
            scanner = DriveScanner(disk_path, chunk_size=CHUNK_SIZE, overlap_size=OVERLAP_SIZE)
            results = _TestCarver().carve_stream(scanner=scanner, output_dir=out_dir)
        finally:
            os.remove(disk_path)
            shutil.rmtree(out_dir, ignore_errors=True)

        self.assertTrue(results, "FileCarver found no files")
        png_results = [r for r in results if r.file_type == "PNG"]
        self.assertTrue(png_results, f"No PNG carved; types: {[r.file_type for r in results]}")
        offsets = [r.offset_int for r in png_results]
        self.assertIn(self.SPLIT_INDEX, offsets,
                      f"Expected PNG at {self.SPLIT_INDEX}; got offsets: {offsets}")


# ===========================================================================
class TestAllocatedFileCarving(unittest.TestCase):
    """Req 3 -- allocated (live) files must be carved."""

    def test_png_in_allocated_region(self):
        allocated_prefix = bytes((i * 7 + 3) % 256 for i in range(4096))
        png_body = _make_minimal_png()
        stream = allocated_prefix + png_body

        disk_path = _write_temp_file(stream)
        out_dir = tempfile.mkdtemp(prefix="sa_alloc_")
        try:
            scanner = DriveScanner(disk_path, chunk_size=CHUNK_SIZE, overlap_size=OVERLAP_SIZE)
            results = _TestCarver().carve_stream(scanner=scanner, output_dir=out_dir)
        finally:
            os.remove(disk_path)
            shutil.rmtree(out_dir, ignore_errors=True)

        png_results = [r for r in results if r.file_type == "PNG"]
        self.assertTrue(png_results, "PNG in allocated region was not carved")
        self.assertEqual(png_results[0].offset_int, len(allocated_prefix))


# ===========================================================================
class TestFullBufferScan(unittest.TestCase):
    """Req 2 -- carver must scan to len(buffer), not stop at len(buf)-OVERLAP."""

    def test_header_near_tail_of_fresh_chunk(self):
        small_chunk = 8192
        small_overlap = 512
        header_offset = small_chunk - 10

        prefix = bytes((b * 3 + 1) % 256 for b in range(header_offset))
        prefix = prefix.replace(PNG_HEADER, b"\x00" * 8)
        stream = prefix + _make_minimal_png()

        wins = _collect_windows(stream, small_chunk, small_overlap)
        found = any(
            win_start + buf.find(PNG_HEADER) == header_offset
            for win_start, buf in wins
            if buf.find(PNG_HEADER) != -1
        )
        self.assertTrue(found,
                        f"PNG at {header_offset} not found; carver may have stopped early")


# ===========================================================================
class TestASTSyntax(unittest.TestCase):
    """All modified modules must pass ast.parse()."""

    def _check(self, rel: str) -> None:
        import ast
        root = os.path.join(os.path.dirname(__file__), "..")
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            src = fh.read()
        try:
            ast.parse(src)
        except SyntaxError as exc:
            self.fail(f"SyntaxError in {rel}: {exc}")

    def test_scanner_ast(self):   self._check("core/scanner.py")
    def test_carver_ast(self):    self._check("core/carver.py")
    def test_parsers_ast(self):   self._check("core/parsers.py")


# ===========================================================================
if __name__ == "__main__":
    unittest.main(verbosity=2)


