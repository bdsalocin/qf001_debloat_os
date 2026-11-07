"""Empirical Stress Test Suite for Android Sparse, Unpacker, and Packer.

Author: teamwork_preview_challenger_m1_1
Purpose: Rigorous empirical stress-testing, boundary analysis, fuzzing, and performance
         verification for Milestone 1 components:
         - src/core/sparse.py
         - src/core/unpacker.py
         - src/core/packer.py
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import struct
import tempfile
import time
import tracemalloc
import unittest
import zipfile
import zlib
from pathlib import Path

from src.core.mcu_guard import MCUGuard, MCUSafetyViolationError
from src.core.packer import FirmwarePacker
from src.core.sparse import (
    BUFFER_STREAM_SIZE,
    CHUNK_TYPE_CRC32,
    CHUNK_TYPE_DONT_CARE,
    CHUNK_TYPE_FILL,
    CHUNK_TYPE_RAW,
    DEFAULT_BLOCK_SIZE,
    MAX_CHUNK_BLOCKS,
    SPARSE_HEADER_CHUNK_HDR_SZ,
    SPARSE_HEADER_FILE_HDR_SZ,
    SPARSE_HEADER_MAGIC,
    SPARSE_HEADER_MAJOR_VER,
    SparseChecksumError,
    SparseCorruptedError,
    SparseError,
    SparseFormatError,
    SparseImage,
)
from src.core.unpacker import FirmwareUnpacker, SecurityViolationError


class TestSparseArbitraryRoundtrip(unittest.TestCase):
    """Domain A: Arbitrary Raw Data Round-Trip & Oracle Verification."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def _assert_roundtrip(self, data: bytes, block_size: int = DEFAULT_BLOCK_SIZE) -> None:
        """Helper to assert exact byte-for-byte equality across raw -> sparse -> raw."""
        src_path = os.path.join(self.tmpdir.name, f"src_{len(data)}_{block_size}.raw")
        sparse_path = os.path.join(self.tmpdir.name, f"sparse_{len(data)}_{block_size}.img")
        dst_path = os.path.join(self.tmpdir.name, f"dst_{len(data)}_{block_size}.raw")

        with open(src_path, "wb") as f:
            f.write(data)

        self.assertTrue(SparseImage.sparse(src_path, sparse_path, block_size=block_size))
        self.assertTrue(SparseImage.is_sparse(sparse_path))

        self.assertTrue(SparseImage.unsparse(sparse_path, dst_path))
        with open(dst_path, "rb") as f:
            restored = f.read()

        src_sha = hashlib.sha256(data).hexdigest()
        dst_sha = hashlib.sha256(restored).hexdigest()
        self.assertEqual(src_sha, dst_sha, f"SHA256 mismatch for payload size {len(data)}")
        self.assertEqual(data, restored, f"Byte mismatch for payload size {len(data)}")

    def test_roundtrip_block_multiples(self):
        """Uniform random raw data of exact block multiples maintains byte-for-byte equality."""
        block_counts = [1, 2, 4, 16, 64, 256, 512]  # up to 2 MiB (exceeding BUFFER_STREAM_SIZE)
        for count in block_counts:
            with self.subTest(block_count=count):
                payload = os.urandom(count * DEFAULT_BLOCK_SIZE)
                self._assert_roundtrip(payload, DEFAULT_BLOCK_SIZE)

    def test_roundtrip_zero_data_dont_care(self):
        """100% zero payload generates DONT_CARE chunks with high compression and exact restoration."""
        payload = b"\x00" * (128 * DEFAULT_BLOCK_SIZE)  # 512 KiB of zeros
        src_path = os.path.join(self.tmpdir.name, "zeros.raw")
        sparse_path = os.path.join(self.tmpdir.name, "zeros.sparse")
        dst_path = os.path.join(self.tmpdir.name, "zeros.out")

        with open(src_path, "wb") as f:
            f.write(payload)

        self.assertTrue(SparseImage.sparse(src_path, sparse_path))
        # Header (28 bytes) + 1 DONT_CARE chunk header (12 bytes) = 40 bytes total
        sparse_size = os.path.getsize(sparse_path)
        self.assertEqual(sparse_size, 40)

        self.assertTrue(SparseImage.unsparse(sparse_path, dst_path))
        with open(dst_path, "rb") as f:
            restored = f.read()
        self.assertEqual(payload, restored)

    def test_roundtrip_fill_pattern(self):
        """Constant 4-byte repeating pattern generates FILL chunks with exact restoration."""
        pattern = b"\xca\xfe\xba\xbe"
        payload = pattern * (1024 * 64)  # 64 blocks = 256 KiB
        src_path = os.path.join(self.tmpdir.name, "fill.raw")
        sparse_path = os.path.join(self.tmpdir.name, "fill.sparse")
        dst_path = os.path.join(self.tmpdir.name, "fill.out")

        with open(src_path, "wb") as f:
            f.write(payload)

        self.assertTrue(SparseImage.sparse(src_path, sparse_path))
        # Header (28) + FILL chunk hdr (12) + 4-byte pattern = 44 bytes
        sparse_size = os.path.getsize(sparse_path)
        self.assertEqual(sparse_size, 44)

        self.assertTrue(SparseImage.unsparse(sparse_path, dst_path))
        with open(dst_path, "rb") as f:
            restored = f.read()
        self.assertEqual(payload, restored)

    def test_roundtrip_mixed_entropy_sequences(self):
        """Complex alternating sequence of DONT_CARE, FILL, RAW chunks roundtrips cleanly."""
        blocks: list[bytes] = []
        zero_blk = b"\x00" * DEFAULT_BLOCK_SIZE
        fill1_blk = b"\x11\x22\x33\x44" * 1024
        fill2_blk = b"\xaa\xbb\xcc\xdd" * 1024

        # Generate 120 blocks with alternating patterns
        for i in range(20):
            blocks.append(zero_blk * 2)          # DONT_CARE (2 blocks)
            blocks.append(fill1_blk * 1)         # FILL 1 (1 block)
            blocks.append(os.urandom(4096 * 2))  # RAW (2 blocks)
            blocks.append(fill2_blk * 1)         # FILL 2 (1 block)

        payload = b"".join(blocks)
        self._assert_roundtrip(payload)

    def test_roundtrip_variable_block_sizes(self):
        """Valid block sizes (1024, 2048, 4096, 8192) preserve round-trip byte-for-byte equality."""
        sizes = [1024, 2048, 4096, 8192]
        for bs in sizes:
            with self.subTest(block_size=bs):
                payload = os.urandom(bs * 8)
                self._assert_roundtrip(payload, block_size=bs)

    def test_sparse_invalid_block_sizes_rejected(self):
        """Invalid block sizes (negative, zero, non-multiple of 4) raise ValueError."""
        src_path = os.path.join(self.tmpdir.name, "dummy.raw")
        out_path = os.path.join(self.tmpdir.name, "dummy.sparse")
        with open(src_path, "wb") as f:
            f.write(b"A" * 4096)

        invalid_sizes = [-4096, 0, 1, 3, 5, 4097, 4098]
        for bs in invalid_sizes:
            with self.subTest(invalid_block_size=bs):
                with self.assertRaises(ValueError):
                    SparseImage.sparse(src_path, out_path, block_size=bs)


class TestSparseBoundaryAndNon4K(unittest.TestCase):
    """Domain B: Boundary cases, non-4K boundary files, and empty files."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_empty_file_roundtrip(self):
        """0-byte empty file converts to valid sparse header and unsparses back to 0 bytes."""
        empty_src = os.path.join(self.tmpdir.name, "empty.raw")
        empty_sparse = os.path.join(self.tmpdir.name, "empty.sparse")
        empty_dst = os.path.join(self.tmpdir.name, "empty.out")

        with open(empty_src, "wb") as f:
            pass
        self.assertEqual(os.path.getsize(empty_src), 0)

        # Convert to sparse
        self.assertTrue(SparseImage.sparse(empty_src, empty_sparse))
        self.assertTrue(SparseImage.is_sparse(empty_sparse))
        # Sparse file is exactly 28 bytes (header only, 0 chunks, 0 blocks)
        self.assertEqual(os.path.getsize(empty_sparse), 28)

        # Unsparse
        self.assertTrue(SparseImage.unsparse(empty_sparse, empty_dst))
        self.assertEqual(os.path.getsize(empty_dst), 0)

    def test_non_4k_boundary_padding_behavior(self):
        """Non-4K boundary files are zero-padded to the next block boundary per AOSP libsparse specification."""
        test_sizes = [
            1,           # 1 byte -> 1 block (4096 bytes)
            7,           # 7 bytes -> 1 block
            512,         # 512 bytes -> 1 block
            4095,        # 4096 - 1 byte -> 1 block
            4097,        # 4096 + 1 byte -> 2 blocks (8192 bytes)
            10000,       # 10000 bytes -> 3 blocks (12288 bytes)
            65535,       # 65535 bytes -> 16 blocks (65536 bytes)
            1048575,     # 1 MiB - 1 byte -> 256 blocks (1048576 bytes)
            1500001,     # Exceeding BUFFER_STREAM_SIZE -> 367 blocks (1503232 bytes)
        ]

        for sz in test_sizes:
            with self.subTest(file_size=sz):
                payload = os.urandom(sz)
                src_path = os.path.join(self.tmpdir.name, f"non4k_{sz}.raw")
                sparse_path = os.path.join(self.tmpdir.name, f"non4k_{sz}.sparse")
                dst_path = os.path.join(self.tmpdir.name, f"non4k_{sz}.out")

                with open(src_path, "wb") as f:
                    f.write(payload)

                self.assertTrue(SparseImage.sparse(src_path, sparse_path))
                self.assertTrue(SparseImage.is_sparse(sparse_path))

                self.assertTrue(SparseImage.unsparse(sparse_path, dst_path))
                with open(dst_path, "rb") as f:
                    restored = f.read()

                expected_blocks = (sz + DEFAULT_BLOCK_SIZE - 1) // DEFAULT_BLOCK_SIZE
                expected_len = expected_blocks * DEFAULT_BLOCK_SIZE

                self.assertEqual(len(restored), expected_len)
                # Prefix must match verbatim
                self.assertEqual(restored[:sz], payload)
                # Remainder must be zero-padded
                padding_len = expected_len - sz
                self.assertEqual(restored[sz:], b"\x00" * padding_len)

    def test_non_4k_file_with_fill_pattern_at_end(self):
        """Non-4K file ending with a repeated 4-byte pattern followed by fractional bytes."""
        pattern = b"\x33\x22\x11\x00"
        # 4096 bytes of pattern + 200 bytes of pattern + 3 bytes
        payload = (pattern * 1024) + (pattern * 50) + b"\x33\x22\x11"
        src_path = os.path.join(self.tmpdir.name, "fill_non4k.raw")
        sparse_path = os.path.join(self.tmpdir.name, "fill_non4k.sparse")
        dst_path = os.path.join(self.tmpdir.name, "fill_non4k.out")

        with open(src_path, "wb") as f:
            f.write(payload)

        self.assertTrue(SparseImage.sparse(src_path, sparse_path))
        self.assertTrue(SparseImage.unsparse(sparse_path, dst_path))

        with open(dst_path, "rb") as f:
            restored = f.read()

        expected_len = 8192
        self.assertEqual(len(restored), expected_len)
        self.assertEqual(restored[:len(payload)], payload)
        self.assertEqual(restored[len(payload):], b"\x00" * (expected_len - len(payload)))


class TestSparseHugeChunksAndLimits(unittest.TestCase):
    """Domain C: Huge chunk repetitions (FILL and DONT_CARE) exceeding MAX_CHUNK_BLOCKS."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_unsparse_huge_fill_chunk_70000_blocks(self):
        """Unsparse handles huge FILL chunk (70,000 blocks = ~286 MB) in bounded O(1) memory."""
        # Synthesize sparse image with 70,000 blocks in 2 chunks (65535 + 4465)
        sparse_path = os.path.join(self.tmpdir.name, "huge_fill.sparse")
        out_path = os.path.join(self.tmpdir.name, "huge_fill.raw")

        pattern = b"\xde\xad\xbe\xef"
        total_blks = 70000
        chunk1_blks = 65535
        chunk2_blks = 4465

        hdr = struct.pack(
            "<IHHHHIIII",
            SPARSE_HEADER_MAGIC,
            1,
            0,
            SPARSE_HEADER_FILE_HDR_SZ,
            SPARSE_HEADER_CHUNK_HDR_SZ,
            DEFAULT_BLOCK_SIZE,
            total_blks,
            2,  # 2 chunks
            0,
        )
        c1 = struct.pack("<HHII", CHUNK_TYPE_FILL, 0, chunk1_blks, 16) + pattern
        c2 = struct.pack("<HHII", CHUNK_TYPE_FILL, 0, chunk2_blks, 16) + pattern

        with open(sparse_path, "wb") as f:
            f.write(hdr + c1 + c2)

        self.assertTrue(SparseImage.is_sparse(sparse_path))

        t0 = time.perf_counter()
        self.assertTrue(SparseImage.unsparse(sparse_path, out_path))
        elapsed = time.perf_counter() - t0

        expected_size = total_blks * DEFAULT_BLOCK_SIZE
        actual_size = os.path.getsize(out_path)
        self.assertEqual(actual_size, expected_size)

        # Verify initial and final blocks match pattern
        with open(out_path, "rb") as f:
            first_block = f.read(DEFAULT_BLOCK_SIZE)
            self.assertEqual(first_block, pattern * 1024)
            f.seek(expected_size - DEFAULT_BLOCK_SIZE)
            last_block = f.read(DEFAULT_BLOCK_SIZE)
            self.assertEqual(last_block, pattern * 1024)

    def test_sparse_huge_fill_chunk_splitting(self):
        """sparse() automatically splits runs exceeding MAX_CHUNK_BLOCKS (65535) into multiple chunks."""
        # Test with block_size=1024 and 66,000 blocks (~67.5 MB raw) to keep execution fast
        block_sz = 1024
        total_blks = 66000
        pattern = b"\x11\x22\x33\x44"
        raw_path = os.path.join(self.tmpdir.name, "split_fill.raw")
        sparse_path = os.path.join(self.tmpdir.name, "split_fill.sparse")
        restored_path = os.path.join(self.tmpdir.name, "split_fill.out")

        # Stream write 66,000 blocks of pattern
        block_data = pattern * (block_sz // 4)
        with open(raw_path, "wb") as f:
            # Write in 1 MB chunks
            chunk_slice = block_data * 1024  # 1 MiB
            for _ in range(64):
                f.write(chunk_slice)
            f.write(block_data * (total_blks - 64 * 1024))

        self.assertEqual(os.path.getsize(raw_path), total_blks * block_sz)

        # Convert to sparse
        self.assertTrue(SparseImage.sparse(raw_path, sparse_path, block_size=block_sz))
        self.assertTrue(SparseImage.is_sparse(sparse_path))

        # Inspect sparse header: must contain exactly 2 chunks
        with open(sparse_path, "rb") as f:
            hdr_bytes = f.read(28)
            magic, maj, min_v, f_sz, c_sz, blk_s, t_blks, t_chunks, crc = struct.unpack(
                "<IHHHHIIII", hdr_bytes
            )
            self.assertEqual(t_blks, total_blks)
            self.assertEqual(t_chunks, 2)

            # Chunk 1: 65535 blocks
            c1_hdr = f.read(12)
            c1_type, _, c1_sz, c1_total = struct.unpack("<HHII", c1_hdr)
            self.assertEqual(c1_type, CHUNK_TYPE_FILL)
            self.assertEqual(c1_sz, MAX_CHUNK_BLOCKS)
            f.seek(4, os.SEEK_CUR)  # skip pattern

            # Chunk 2: 465 blocks
            c2_hdr = f.read(12)
            c2_type, _, c2_sz, c2_total = struct.unpack("<HHII", c2_hdr)
            self.assertEqual(c2_type, CHUNK_TYPE_FILL)
            self.assertEqual(c2_sz, total_blks - MAX_CHUNK_BLOCKS)

        # Unsparse and verify exact restoration
        self.assertTrue(SparseImage.unsparse(sparse_path, restored_path))
        self.assertEqual(os.path.getsize(restored_path), os.path.getsize(raw_path))

    def test_unsparse_huge_dont_care_chunk(self):
        """Unsparse handles large DONT_CARE runs across chunk splits."""
        sparse_path = os.path.join(self.tmpdir.name, "huge_dc.sparse")
        out_path = os.path.join(self.tmpdir.name, "huge_dc.raw")

        total_blks = 70000
        hdr = struct.pack(
            "<IHHHHIIII",
            SPARSE_HEADER_MAGIC,
            1,
            0,
            28,
            12,
            DEFAULT_BLOCK_SIZE,
            total_blks,
            2,
            0,
        )
        c1 = struct.pack("<HHII", CHUNK_TYPE_DONT_CARE, 0, 65535, 12)
        c2 = struct.pack("<HHII", CHUNK_TYPE_DONT_CARE, 0, 4465, 12)

        with open(sparse_path, "wb") as f:
            f.write(hdr + c1 + c2)

        self.assertTrue(SparseImage.unsparse(sparse_path, out_path))
        self.assertEqual(os.path.getsize(out_path), total_blks * DEFAULT_BLOCK_SIZE)


class TestSparseCorruptHeadersAndFuzzing(unittest.TestCase):
    """Domain D: Negative testing, corrupt headers, truncated chunks, and adversarial fuzzing."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def _create_minimal_sparse(self, **overrides) -> bytes:
        fields = {
            "magic": SPARSE_HEADER_MAGIC,
            "major": SPARSE_HEADER_MAJOR_VER,
            "minor": 0,
            "file_hdr_sz": SPARSE_HEADER_FILE_HDR_SZ,
            "chunk_hdr_sz": SPARSE_HEADER_CHUNK_HDR_SZ,
            "blk_sz": DEFAULT_BLOCK_SIZE,
            "total_blks": 1,
            "total_chunks": 1,
            "checksum": 0,
        }
        fields.update(overrides)
        hdr = struct.pack(
            "<IHHHHIIII",
            fields["magic"],
            fields["major"],
            fields["minor"],
            fields["file_hdr_sz"],
            fields["chunk_hdr_sz"],
            fields["blk_sz"],
            fields["total_blks"],
            fields["total_chunks"],
            fields["checksum"],
        )
        chunk = struct.pack("<HHII", CHUNK_TYPE_DONT_CARE, 0, 1, 12)
        return hdr + chunk

    def test_truncated_file_header(self):
        """Files shorter than 28 bytes return False for is_sparse and raise SparseFormatError."""
        for sz in [0, 1, 10, 27]:
            with self.subTest(truncated_size=sz):
                p = os.path.join(self.tmpdir.name, f"trunc_{sz}.sparse")
                with open(p, "wb") as f:
                    f.write(b"\x3a\xff\x26\xed"[:sz])
                self.assertFalse(SparseImage.is_sparse(p))
                out = os.path.join(self.tmpdir.name, f"trunc_{sz}.out")
                with self.assertRaises(SparseFormatError):
                    SparseImage.unsparse(p, out)

    def test_corrupted_magics(self):
        """Invalid magic numbers are rejected cleanly."""
        bad_magics = [0x00000000, 0xFFFFFFFF, 0x12345678, 0xED26FF3B, 0x41414141]
        for bm in bad_magics:
            with self.subTest(bad_magic=bm):
                p = os.path.join(self.tmpdir.name, f"magic_{bm}.sparse")
                with open(p, "wb") as f:
                    f.write(self._create_minimal_sparse(magic=bm))
                self.assertFalse(SparseImage.is_sparse(p))
                out = os.path.join(self.tmpdir.name, f"magic_{bm}.out")
                with self.assertRaises(SparseFormatError):
                    SparseImage.unsparse(p, out)

    def test_unsupported_major_version(self):
        """Major version other than 1 is rejected cleanly."""
        for ver in [0, 2, 5, 99]:
            with self.subTest(bad_ver=ver):
                p = os.path.join(self.tmpdir.name, f"ver_{ver}.sparse")
                with open(p, "wb") as f:
                    f.write(self._create_minimal_sparse(major=ver))
                self.assertFalse(SparseImage.is_sparse(p))
                out = os.path.join(self.tmpdir.name, f"ver_{ver}.out")
                with self.assertRaises(SparseFormatError):
                    SparseImage.unsparse(p, out)

    def test_corrupted_header_sizes(self):
        """Invalid file_hdr_sz or chunk_hdr_sz values are rejected."""
        # file_hdr_sz < 28
        p1 = os.path.join(self.tmpdir.name, "bad_fhdr.sparse")
        with open(p1, "wb") as f:
            f.write(self._create_minimal_sparse(file_hdr_sz=20))
        self.assertFalse(SparseImage.is_sparse(p1))

        # chunk_hdr_sz < 12
        p2 = os.path.join(self.tmpdir.name, "bad_chdr.sparse")
        with open(p2, "wb") as f:
            f.write(self._create_minimal_sparse(chunk_hdr_sz=8))
        self.assertFalse(SparseImage.is_sparse(p2))

    def test_corrupted_block_sizes(self):
        """block_size of 0 or non-multiple of 4 is rejected by is_sparse."""
        bad_bs = [0, 1, 2, 3, 4097, 4098]
        for bs in bad_bs:
            with self.subTest(bad_blk_sz=bs):
                p = os.path.join(self.tmpdir.name, f"bs_{bs}.sparse")
                with open(p, "wb") as f:
                    f.write(self._create_minimal_sparse(blk_sz=bs))
                self.assertFalse(SparseImage.is_sparse(p))

    def test_corrupted_chunk_total_sz(self):
        """Inconsistent total_sz in chunk headers raises SparseCorruptedError."""
        # RAW chunk with corrupted total_sz
        p_raw = os.path.join(self.tmpdir.name, "corrupt_raw_sz.sparse")
        hdr = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 1, 0, 28, 12, 4096, 1, 1, 0)
        c_raw = struct.pack("<HHII", CHUNK_TYPE_RAW, 0, 1, 12 + 4096 + 1) + (b"\x00" * 4096)
        with open(p_raw, "wb") as f:
            f.write(hdr + c_raw)
        with self.assertRaises(SparseCorruptedError):
            SparseImage.unsparse(p_raw, os.path.join(self.tmpdir.name, "out1"))

        # FILL chunk with total_sz != 16
        p_fill = os.path.join(self.tmpdir.name, "corrupt_fill_sz.sparse")
        c_fill = struct.pack("<HHII", CHUNK_TYPE_FILL, 0, 1, 12) + b"\x00\x00\x00\x00"
        with open(p_fill, "wb") as f:
            f.write(hdr + c_fill)
        with self.assertRaises(SparseCorruptedError):
            SparseImage.unsparse(p_fill, os.path.join(self.tmpdir.name, "out2"))

        # DONT_CARE chunk with total_sz != 12
        p_dc = os.path.join(self.tmpdir.name, "corrupt_dc_sz.sparse")
        c_dc = struct.pack("<HHII", CHUNK_TYPE_DONT_CARE, 0, 1, 16)
        with open(p_dc, "wb") as f:
            f.write(hdr + c_dc)
        with self.assertRaises(SparseCorruptedError):
            SparseImage.unsparse(p_dc, os.path.join(self.tmpdir.name, "out3"))

    def test_unknown_chunk_type(self):
        """Unrecognized chunk types (e.g. 0xCAC0, 0xCAC5, 0xFFFF) raise SparseCorruptedError."""
        unknown_types = [0x0000, 0xCAC0, 0xCAC5, 0xBEEF, 0xFFFF]
        for ut in unknown_types:
            with self.subTest(unknown_type=hex(ut)):
                p = os.path.join(self.tmpdir.name, f"unknown_{ut:#x}.sparse")
                hdr = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 1, 0, 28, 12, 4096, 1, 1, 0)
                chunk = struct.pack("<HHII", ut, 0, 1, 12)
                with open(p, "wb") as f:
                    f.write(hdr + chunk)
                with self.assertRaises(SparseCorruptedError):
                    SparseImage.unsparse(p, os.path.join(self.tmpdir.name, "out"))

    def test_truncated_chunk_payloads(self):
        """Truncated RAW payload raises SparseCorruptedError."""
        p = os.path.join(self.tmpdir.name, "trunc_payload.sparse")
        hdr = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 1, 0, 28, 12, 4096, 1, 1, 0)
        # RAW chunk specifies 4096 bytes data, but file contains only 100 bytes
        chunk = struct.pack("<HHII", CHUNK_TYPE_RAW, 0, 1, 12 + 4096) + (b"A" * 100)
        with open(p, "wb") as f:
            f.write(hdr + chunk)
        with self.assertRaises(SparseCorruptedError):
            SparseImage.unsparse(p, os.path.join(self.tmpdir.name, "out"))

    def test_total_blocks_mismatch(self):
        """Header total_blks mismatch against sum of chunk blocks raises SparseCorruptedError."""
        p = os.path.join(self.tmpdir.name, "blk_mismatch.sparse")
        # Header claims 10 blocks, but only 1 block is in chunk
        hdr = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 1, 0, 28, 12, 4096, 10, 1, 0)
        chunk = struct.pack("<HHII", CHUNK_TYPE_DONT_CARE, 0, 1, 12)
        with open(p, "wb") as f:
            f.write(hdr + chunk)
        with self.assertRaises(SparseCorruptedError):
            SparseImage.unsparse(p, os.path.join(self.tmpdir.name, "out"))

    def test_premature_eof_during_chunk_headers(self):
        """Header claims 5 chunks, but file ends after chunk 2 raises SparseCorruptedError."""
        p = os.path.join(self.tmpdir.name, "eof_chunks.sparse")
        hdr = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 1, 0, 28, 12, 4096, 5, 5, 0)
        c1 = struct.pack("<HHII", CHUNK_TYPE_DONT_CARE, 0, 1, 12)
        c2 = struct.pack("<HHII", CHUNK_TYPE_DONT_CARE, 0, 1, 12)
        with open(p, "wb") as f:
            f.write(hdr + c1 + c2)
        with self.assertRaises(SparseCorruptedError):
            SparseImage.unsparse(p, os.path.join(self.tmpdir.name, "out"))


class TestSparseStreamingMemoryFootprint(unittest.TestCase):
    """Domain E: Stream buffering and bounded O(1) RAM footprint verification."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_streaming_bounded_memory_footprint(self):
        """Verifies that sparse conversion and unsparse operate in bounded O(1) RAM for 12 MiB data."""
        raw_size = 12 * 1024 * 1024  # 12 MiB
        raw_path = os.path.join(self.tmpdir.name, "stream_12mb.raw")
        sparse_path = os.path.join(self.tmpdir.name, "stream_12mb.sparse")
        restored_path = os.path.join(self.tmpdir.name, "stream_12mb.out")

        # Stream write 12 MiB of mixed data in 1MB chunks
        with open(raw_path, "wb") as f:
            for _ in range(12):
                f.write(os.urandom(1024 * 1024))

        # Measure peak memory during sparse()
        tracemalloc.start()
        t0 = time.perf_counter()
        self.assertTrue(SparseImage.sparse(raw_path, sparse_path))
        sparse_elapsed = time.perf_counter() - t0
        _, peak_sparse = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Measure peak memory during unsparse()
        tracemalloc.start()
        t0 = time.perf_counter()
        self.assertTrue(SparseImage.unsparse(sparse_path, restored_path))
        unsparse_elapsed = time.perf_counter() - t0
        _, peak_unsparse = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Peak memory must remain well under 8 MiB despite 12 MiB file
        self.assertLess(
            peak_sparse,
            8 * 1024 * 1024,
            f"Sparse encoding memory spiked: {peak_sparse / (1024 * 1024):.2f} MB",
        )
        self.assertLess(
            peak_unsparse,
            8 * 1024 * 1024,
            f"Sparse decoding memory spiked: {peak_unsparse / (1024 * 1024):.2f} MB",
        )

        # Assert byte equality
        with open(raw_path, "rb") as f_src, open(restored_path, "rb") as f_dst:
            src_sha = hashlib.sha256(f_src.read()).hexdigest()
            dst_sha = hashlib.sha256(f_dst.read()).hexdigest()
        self.assertEqual(src_sha, dst_sha)


class TestUnpackerPackerSafetyAndPerformance(unittest.TestCase):
    """Domain F: FirmwareUnpacker and FirmwarePacker security isolation, traversal prevention, and stress."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.extract_dir = os.path.join(self.tmpdir.name, "extracted")
        self.pack_dir = os.path.join(self.tmpdir.name, "packed")
        os.makedirs(self.extract_dir, exist_ok=True)
        os.makedirs(self.pack_dir, exist_ok=True)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_unpacker_zip_slip_variations(self):
        """FirmwareUnpacker rejects diverse Zip Slip path traversal vectors."""
        traversal_vectors = [
            "../../evil.sh",
            "../../../etc/shadow",
            "system/../../../../tmp/pwned",
            "/absolute/evil.bin",
        ]

        for idx, vector in enumerate(traversal_vectors):
            with self.subTest(vector=vector):
                zip_path = os.path.join(self.tmpdir.name, f"slip_{idx}.zip")
                with zipfile.ZipFile(zip_path, "w") as zf:
                    zf.writestr(vector, b"ATTACK_PAYLOAD")

                unpacker = FirmwareUnpacker(zip_path, os.path.join(self.extract_dir, f"sub_{idx}"))
                self.assertFalse(unpacker.validate_archive())
                with self.assertRaises(SecurityViolationError):
                    unpacker.unpack()

    def test_unpacker_mcu_quarantine_preserves_safety(self):
        """FirmwareUnpacker quarantines MCU files and does not leak them into system root."""
        zip_path = os.path.join(self.tmpdir.name, "fw_mcu.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system/app/Radio/Radio.apk", b"RADIO_APP")
            zf.writestr("mcu.bin", b"MCU_CORE_IMAGE")
            zf.writestr("k706_mcu.bin", b"K706_MCU_DATA")
            zf.writestr("subfolder/STM32_MCU.hex", b":020000040800F2")

        unpacker = FirmwareUnpacker(zip_path, self.extract_dir)
        manifest = unpacker.unpack(quarantine_mcu=True)

        # Quarantined list must include all 3 MCU files
        self.assertEqual(len(manifest["quarantined_files"]), 3)
        self.assertTrue(os.path.isdir(unpacker.quarantine_dir))
        self.assertTrue(os.path.isfile(os.path.join(unpacker.quarantine_dir, "mcu.bin")))
        self.assertTrue(os.path.isfile(os.path.join(unpacker.quarantine_dir, "k706_mcu.bin")))

        # Ensure no MCU file is present in system root or normal extraction directory
        for root, _, files in os.walk(self.extract_dir):
            if "quarantine_mcu" in root:
                continue
            for fn in files:
                self.assertFalse(
                    MCUGuard.is_mcu_artifact(fn),
                    f"MCU artifact leaked into extracted tree: {os.path.join(root, fn)}",
                )

    def test_unpacker_quarantine_false_raises_immediately(self):
        """quarantine_mcu=False raises MCUSafetyViolationError on first encountered MCU binary."""
        zip_path = os.path.join(self.tmpdir.name, "fw_strict.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("mcu.bin", b"MCU_PAYLOAD")

        unpacker = FirmwareUnpacker(zip_path, self.extract_dir)
        with self.assertRaises(MCUSafetyViolationError):
            unpacker.unpack(quarantine_mcu=False)

    def test_unpacker_auto_unsparse_mixed_partitions(self):
        """FirmwareUnpacker automatically converts sparse partitions while preserving raw partitions."""
        zip_path = os.path.join(self.tmpdir.name, "mixed_fw.zip")

        # Create sparse partition
        sparse_file = os.path.join(self.tmpdir.name, "temp_sparse.img")
        raw_data = b"QF001_SYSTEM_IMAGE_TEST" * 200
        with open(sparse_file, "wb") as f:
            f.write(raw_data)
        SparseImage.sparse(sparse_file, sparse_file + ".sp")

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(sparse_file + ".sp", arcname="system.img")
            zf.writestr("vendor.img", b"RAW_VENDOR_PARTITION_NOT_SPARSE")

        unpacker = FirmwareUnpacker(zip_path, self.extract_dir)
        manifest = unpacker.unpack(auto_unsparse=True)

        expected_raw_sys = os.path.join(self.extract_dir, "system.raw.img")
        self.assertTrue(os.path.isfile(expected_raw_sys))
        self.assertIn(os.path.realpath(expected_raw_sys), manifest["unsparsed_images"])

        # vendor.raw.img must not exist
        self.assertFalse(os.path.exists(os.path.join(self.extract_dir, "vendor.raw.img")))

    def test_packer_zero_mcu_directory_audit(self):
        """FirmwarePacker refuses to pack directory containing any MCU artifacts."""
        sys_dir = os.path.join(self.tmpdir.name, "system_dirty")
        os.makedirs(os.path.join(sys_dir, "app"), exist_ok=True)
        with open(os.path.join(sys_dir, "app", "safe.apk"), "wb") as f:
            f.write(b"SAFE")
        with open(os.path.join(sys_dir, "mcu.bin"), "wb") as f:
            f.write(b"DANGEROUS_MCU")

        packer = FirmwarePacker(sys_dir, self.pack_dir)
        with self.assertRaises(MCUSafetyViolationError):
            packer.pack_partition("system")

        with self.assertRaises(MCUSafetyViolationError):
            packer.repack_update_archive(os.path.join(self.pack_dir, "update.zip"))

    def test_packer_deep_nested_tree_stress(self):
        """FirmwarePacker handles deep hierarchies of 100+ files and builds valid sparse partition."""
        sys_dir = os.path.join(self.tmpdir.name, "deep_system")
        os.makedirs(sys_dir, exist_ok=True)

        # Create 120 files across 6 directory levels
        file_count = 0
        for depth in range(6):
            dir_path = os.path.join(sys_dir, f"level_{depth}", "sub_module")
            os.makedirs(dir_path, exist_ok=True)
            for f_idx in range(20):
                file_p = os.path.join(dir_path, f"asset_{f_idx}.dat")
                with open(file_p, "wb") as f:
                    f.write(f"DEPTH_{depth}_ASSET_{f_idx}_CONTENT".encode("utf-8") * 10)
                file_count += 1

        self.assertEqual(file_count, 120)

        packer = FirmwarePacker(sys_dir, self.pack_dir)
        t0 = time.perf_counter()
        sparse_img = packer.pack_partition("system", make_sparse=True)
        elapsed = time.perf_counter() - t0

        self.assertTrue(os.path.isfile(sparse_img))
        self.assertTrue(SparseImage.is_sparse(sparse_img))
        self.assertLess(elapsed, 2.0, "Packing 120 files exceeded 2.0 seconds")

        # Repack into update.zip and verify
        zip_path = os.path.join(self.pack_dir, "update.zip")
        res_zip = packer.repack_update_archive(zip_path)
        verif = packer.verify_repacked_archive(res_zip)
        self.assertTrue(verif["is_valid"])
        self.assertTrue(verif["mcu_safe"])
        self.assertIn("system.img", verif["entries"])
        self.assertIn("system.img", verif["sparse_partitions"])


    def test_packer_empty_system_root(self):
        """FirmwarePacker cleanly handles an empty system_root, producing padded 16 KiB partition."""
        empty_root = os.path.join(self.tmpdir.name, "empty_system")
        os.makedirs(empty_root, exist_ok=True)

        packer = FirmwarePacker(empty_root, self.pack_dir)
        sparse_img = packer.pack_partition("system", make_sparse=True)
        self.assertTrue(os.path.isfile(sparse_img))
        self.assertTrue(SparseImage.is_sparse(sparse_img))

        # Raw partition padded to minimum 4 blocks (16 KiB)
        raw_img = os.path.join(self.pack_dir, "system.raw.img")
        self.assertTrue(os.path.isfile(raw_img))
        self.assertEqual(os.path.getsize(raw_img), 16384)

        # Repack into update.zip succeeds
        zip_path = os.path.join(self.pack_dir, "empty_update.zip")
        packer.repack_update_archive(zip_path)
        verif = packer.verify_repacked_archive(zip_path)
        self.assertTrue(verif["is_valid"])
        self.assertTrue(verif["mcu_safe"])

    def test_unpacker_valid_empty_zip_archive(self):
        """FirmwareUnpacker cleanly unpacks a valid ZIP archive containing 0 members."""
        zip_path = os.path.join(self.tmpdir.name, "empty_valid.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            pass  # 22-byte valid empty zip

        unpacker = FirmwareUnpacker(zip_path, self.extract_dir)
        self.assertTrue(unpacker.validate_archive())
        manifest = unpacker.unpack()
        self.assertEqual(len(manifest["extracted_files"]), 0)
        self.assertEqual(len(manifest["quarantined_files"]), 0)

    def test_unpacker_zero_byte_archive_inconsistency_finding(self):
        """0-byte archive returns validate_archive()=True but unpack() raises BadZipFile.
        
        This tests the worker discrepancy where validate_archive() was made to return True
        for 0-byte files (to pass a loose E2E check), but unpack() fails on BadZipFile.
        """
        zero_byte_path = os.path.join(self.tmpdir.name, "zero_byte.zip")
        with open(zero_byte_path, "wb") as f:
            pass

        unpacker = FirmwareUnpacker(zero_byte_path, self.extract_dir)
        # validate_archive returns True due to 'if size == 0: return True'
        self.assertTrue(unpacker.validate_archive())
        # But unpack raises BadZipFile because 0-byte file is not a valid zip
        with self.assertRaises(zipfile.BadZipFile):
            unpacker.unpack()

    def test_sparse_same_source_dest_destructive_overwrite(self):
        """Calling sparse with source_path == dest_path corrupts source because dst opens in 'wb' before reading.
        
        Empirically observes that sparse() fails to guard against source_path == dest_path,
        truncating source upon opening and turning the file into DONT_CARE zeros.
        """
        same_path = os.path.join(self.tmpdir.name, "same_file.raw")
        with open(same_path, "wb") as f:
            f.write(b"SAMPLE_CONTENT" * 500)

        # Calling with same path truncates source to 0 bytes
        SparseImage.sparse(same_path, same_path)
        # Because dest opened in 'wb' after getsize, the original data is destroyed
        # and replaced by DONT_CARE zeroes of 40 bytes (28 header + 12 chunk)
        self.assertEqual(os.path.getsize(same_path), 40)

    def test_unsparse_same_source_dest_destroys_input(self):
        """Calling unsparse with source_path == dest_path truncates the sparse image to 0 bytes and crashes.
        
        Empirically demonstrates absence of same-file collision guard in unsparse().
        """
        # Create valid sparse file
        sp_path = os.path.join(self.tmpdir.name, "same_unsparse.sparse")
        raw_temp = os.path.join(self.tmpdir.name, "temp.raw")
        with open(raw_temp, "wb") as f:
            f.write(b"DATA" * 1024)
        SparseImage.sparse(raw_temp, sp_path)

        # unsparse onto itself destroys the sparse file
        with self.assertRaises(SparseCorruptedError):
            SparseImage.unsparse(sp_path, sp_path)
        # Sparse file is now 0 bytes
        self.assertEqual(os.path.getsize(sp_path), 0)

    def test_sparse_performance_benchmark(self):
        """Benchmark: 16 MiB mixed workload must process at acceptable throughput."""
        raw_size = 16 * 1024 * 1024  # 16 MiB
        raw_path = os.path.join(self.tmpdir.name, "bench_16mb.raw")
        sparse_path = os.path.join(self.tmpdir.name, "bench_16mb.sparse")
        restored_path = os.path.join(self.tmpdir.name, "bench_16mb.out")

        # Mixed workload: 4MB zeros, 4MB fill, 8MB random
        zero_part = b"\x00" * (4 * 1024 * 1024)
        fill_part = b"\xaa\xbb\xcc\xdd" * (1024 * 1024)
        raw_part = os.urandom(8 * 1024 * 1024)

        with open(raw_path, "wb") as f:
            f.write(zero_part + fill_part + raw_part)

        t0 = time.perf_counter()
        self.assertTrue(SparseImage.sparse(raw_path, sparse_path))
        sparse_time = time.perf_counter() - t0
        sparse_speed = (raw_size / (1024 * 1024)) / sparse_time

        t1 = time.perf_counter()
        self.assertTrue(SparseImage.unsparse(sparse_path, restored_path))
        unsparse_time = time.perf_counter() - t1
        unsparse_speed = (raw_size / (1024 * 1024)) / unsparse_time

        # Validate throughput
        self.assertGreater(sparse_speed, 20.0, f"Sparse encoding too slow: {sparse_speed:.2f} MB/s")
        self.assertGreater(unsparse_speed, 30.0, f"Sparse decoding too slow: {unsparse_speed:.2f} MB/s")

        # Verify integrity
        with open(raw_path, "rb") as f1, open(restored_path, "rb") as f2:
            self.assertEqual(hashlib.sha256(f1.read()).hexdigest(), hashlib.sha256(f2.read()).hexdigest())


if __name__ == "__main__":
    unittest.main()

