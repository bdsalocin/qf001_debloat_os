"""Comprehensive unit tests for pure Python Android Sparse engine."""

import hashlib
import os
import struct
import tempfile
import unittest
import zlib

from src.core.sparse import (
    CHUNK_TYPE_CRC32,
    CHUNK_TYPE_DONT_CARE,
    CHUNK_TYPE_FILL,
    CHUNK_TYPE_RAW,
    DEFAULT_BLOCK_SIZE,
    SPARSE_HEADER_CHUNK_HDR_SZ,
    SPARSE_HEADER_FILE_HDR_SZ,
    SPARSE_HEADER_MAGIC,
    SparseChecksumError,
    SparseCorruptedError,
    SparseError,
    SparseFormatError,
    SparseImage,
)


class TestSparseImageDetection(unittest.TestCase):
    """Test suite for SparseImage.is_sparse detection logic."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_is_sparse_valid(self):
        """Valid sparse image must return True."""
        path = os.path.join(self.tmpdir.name, "valid.sparse")
        header = struct.pack(
            "<IHHHHIIII",
            SPARSE_HEADER_MAGIC,
            1,
            0,
            28,
            12,
            4096,
            1,
            1,
            0,
        )
        chunk = struct.pack("<HHII", CHUNK_TYPE_DONT_CARE, 0, 1, 12)
        with open(path, "wb") as f:
            f.write(header + chunk)

        self.assertTrue(SparseImage.is_sparse(path))

    def test_is_sparse_raw_file(self):
        """Arbitrary raw file without sparse magic must return False."""
        path = os.path.join(self.tmpdir.name, "raw.img")
        with open(path, "wb") as f:
            f.write(b"NOT_A_SPARSE_IMAGE_DATA" * 50)

        self.assertFalse(SparseImage.is_sparse(path))

    def test_is_sparse_truncated(self):
        """File smaller than 28 bytes must return False without crashing."""
        path = os.path.join(self.tmpdir.name, "short.img")
        with open(path, "wb") as f:
            f.write(b"\x3a\xff\x26\xed\x01\x00")

        self.assertFalse(SparseImage.is_sparse(path))

    def test_is_sparse_wrong_magic(self):
        """Header with invalid magic number must return False."""
        path = os.path.join(self.tmpdir.name, "wrong_magic.img")
        header = struct.pack(
            "<IHHHHIIII",
            0xDEADBEEF,
            1,
            0,
            28,
            12,
            4096,
            1,
            1,
            0,
        )
        with open(path, "wb") as f:
            f.write(header)

        self.assertFalse(SparseImage.is_sparse(path))

    def test_is_sparse_nonexistent_and_invalid_types(self):
        """Nonexistent paths or invalid arguments must return False."""
        self.assertFalse(SparseImage.is_sparse(os.path.join(self.tmpdir.name, "none.img")))
        self.assertFalse(SparseImage.is_sparse(""))
        self.assertFalse(SparseImage.is_sparse(None))  # type: ignore


class TestSparseImageDecompression(unittest.TestCase):
    """Test suite for SparseImage.unsparse decompressor."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_unsparse_raw_chunk(self):
        """Decompressing RAW chunk reproduces exact data payload."""
        sparse_path = os.path.join(self.tmpdir.name, "raw.sparse")
        out_path = os.path.join(self.tmpdir.name, "raw.out")
        blk_sz = 4096
        raw_payload = b"A" * 1024 + b"B" * 1024 + b"C" * 1024 + b"D" * 1024

        hdr = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 1, 0, 28, 12, blk_sz, 1, 1, 0)
        chunk = struct.pack("<HHII", CHUNK_TYPE_RAW, 0, 1, 12 + blk_sz) + raw_payload

        with open(sparse_path, "wb") as f:
            f.write(hdr + chunk)

        self.assertTrue(SparseImage.unsparse(sparse_path, out_path))
        with open(out_path, "rb") as f:
            self.assertEqual(f.read(), raw_payload)

    def test_unsparse_fill_chunk(self):
        """Decompressing FILL chunk repeats 4-byte pattern over all blocks."""
        sparse_path = os.path.join(self.tmpdir.name, "fill.sparse")
        out_path = os.path.join(self.tmpdir.name, "fill.out")
        blk_sz = 4096
        pattern = b"\xde\xad\xbe\xef"

        hdr = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 1, 0, 28, 12, blk_sz, 2, 1, 0)
        chunk = struct.pack("<HHII", CHUNK_TYPE_FILL, 0, 2, 16) + pattern

        with open(sparse_path, "wb") as f:
            f.write(hdr + chunk)

        self.assertTrue(SparseImage.unsparse(sparse_path, out_path))
        with open(out_path, "rb") as f:
            decomp = f.read()
        self.assertEqual(len(decomp), 8192)
        self.assertEqual(decomp, pattern * (8192 // 4))

    def test_unsparse_dont_care_chunk(self):
        """Decompressing DONT_CARE chunk outputs zero bytes."""
        sparse_path = os.path.join(self.tmpdir.name, "dont_care.sparse")
        out_path = os.path.join(self.tmpdir.name, "dont_care.out")
        blk_sz = 4096

        hdr = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 1, 0, 28, 12, blk_sz, 3, 1, 0)
        chunk = struct.pack("<HHII", CHUNK_TYPE_DONT_CARE, 0, 3, 12)

        with open(sparse_path, "wb") as f:
            f.write(hdr + chunk)

        self.assertTrue(SparseImage.unsparse(sparse_path, out_path))
        with open(out_path, "rb") as f:
            decomp = f.read()
        self.assertEqual(len(decomp), 12288)
        self.assertEqual(decomp, b"\x00" * 12288)

    def test_unsparse_crc32_validation(self):
        """CRC32 chunk validation succeeds when calculated checksum matches."""
        sparse_path = os.path.join(self.tmpdir.name, "crc_valid.sparse")
        out_path = os.path.join(self.tmpdir.name, "crc_valid.out")
        blk_sz = 4096
        raw_payload = b"SECURE_DATA_HASH" * 256

        calc_crc = zlib.crc32(raw_payload, 0)

        hdr = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 1, 0, 28, 12, blk_sz, 1, 2, 0)
        chunk1 = struct.pack("<HHII", CHUNK_TYPE_RAW, 0, 1, 12 + blk_sz) + raw_payload
        chunk2 = struct.pack("<HHII", CHUNK_TYPE_CRC32, 0, 0, 16) + struct.pack("<I", calc_crc)

        with open(sparse_path, "wb") as f:
            f.write(hdr + chunk1 + chunk2)

        self.assertTrue(SparseImage.unsparse(sparse_path, out_path))

    def test_unsparse_crc32_corrupted(self):
        """Corrupted CRC32 chunk raises SparseChecksumError."""
        sparse_path = os.path.join(self.tmpdir.name, "crc_bad.sparse")
        out_path = os.path.join(self.tmpdir.name, "crc_bad.out")
        blk_sz = 4096
        raw_payload = b"X" * blk_sz

        hdr = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 1, 0, 28, 12, blk_sz, 1, 2, 0)
        chunk1 = struct.pack("<HHII", CHUNK_TYPE_RAW, 0, 1, 12 + blk_sz) + raw_payload
        chunk2 = struct.pack("<HHII", CHUNK_TYPE_CRC32, 0, 0, 16) + struct.pack("<I", 0x12345678)

        with open(sparse_path, "wb") as f:
            f.write(hdr + chunk1 + chunk2)

        with self.assertRaises(SparseChecksumError):
            SparseImage.unsparse(sparse_path, out_path)

    def test_unsparse_corrupted_header_version(self):
        """Unsupported major version raises SparseFormatError."""
        sparse_path = os.path.join(self.tmpdir.name, "bad_ver.sparse")
        out_path = os.path.join(self.tmpdir.name, "bad_ver.out")
        hdr = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 2, 0, 28, 12, 4096, 1, 1, 0)
        with open(sparse_path, "wb") as f:
            f.write(hdr)

        with self.assertRaises(SparseFormatError):
            SparseImage.unsparse(sparse_path, out_path)

    def test_unsparse_corrupted_total_size(self):
        """Chunk with total_sz inconsistent with chunk_sz raises SparseCorruptedError."""
        sparse_path = os.path.join(self.tmpdir.name, "bad_total.sparse")
        out_path = os.path.join(self.tmpdir.name, "bad_total.out")
        hdr = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 1, 0, 28, 12, 4096, 1, 1, 0)
        # RAW chunk claiming 9999 total_sz instead of 12 + 4096
        chunk = struct.pack("<HHII", CHUNK_TYPE_RAW, 0, 1, 9999) + (b"\x00" * 4096)
        with open(sparse_path, "wb") as f:
            f.write(hdr + chunk)

        with self.assertRaises(SparseCorruptedError):
            SparseImage.unsparse(sparse_path, out_path)


class TestSparseImageRoundtripAndCompression(unittest.TestCase):
    """Test suite for SparseImage.sparse and round-trip conversion."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_roundtrip_raw_to_sparse_to_raw(self):
        """Complete round-trip: raw image -> sparse -> unsparse gives identical SHA256."""
        raw_path = os.path.join(self.tmpdir.name, "source.raw")
        sparse_path = os.path.join(self.tmpdir.name, "converted.sparse")
        restored_path = os.path.join(self.tmpdir.name, "restored.raw")

        # Create multi-block mixed content:
        # Block 0: DONT_CARE (zeros)
        # Block 1: FILL (0x12345678 repeated)
        # Block 2: RAW (random data)
        # Block 3: DONT_CARE (zeros)
        blk0 = b"\x00" * 4096
        blk1 = b"\x78\x56\x34\x12" * 1024
        blk2 = os.urandom(4096)
        blk3 = b"\x00" * 4096

        raw_data = blk0 + blk1 + blk2 + blk3
        with open(raw_path, "wb") as f:
            f.write(raw_data)
        src_sha256 = hashlib.sha256(raw_data).hexdigest()

        # Convert to sparse
        self.assertTrue(SparseImage.sparse(raw_path, sparse_path))
        self.assertTrue(SparseImage.is_sparse(sparse_path))

        # Restore from sparse
        self.assertTrue(SparseImage.unsparse(sparse_path, restored_path))
        with open(restored_path, "rb") as f:
            restored_data = f.read()
        restored_sha256 = hashlib.sha256(restored_data).hexdigest()

        self.assertEqual(src_sha256, restored_sha256)
        self.assertEqual(raw_data, restored_data)

    def test_sparse_compression_ratio(self):
        """1MB raw file with 90% zeros compresses significantly in sparse format."""
        raw_path = os.path.join(self.tmpdir.name, "mostly_empty.raw")
        sparse_path = os.path.join(self.tmpdir.name, "compressed.sparse")

        # 256 blocks of 4096 = 1,048,576 bytes
        # 10 blocks data, 246 blocks zeros
        data_block = (b"PAYLOAD_DATA" * 341 + b"P").ljust(4096, b"X")
        blocks = [data_block] * 10 + [b"\x00" * 4096] * 246
        with open(raw_path, "wb") as f:
            f.write(b"".join(blocks))

        raw_size = os.path.getsize(raw_path)
        self.assertEqual(raw_size, 1048576)

        self.assertTrue(SparseImage.sparse(raw_path, sparse_path))
        sparse_size = os.path.getsize(sparse_path)

        # 10 raw blocks (10 * (12+4096)) + 1 dont care chunk (12) + 28 header = ~41120 bytes
        self.assertLess(sparse_size, 150000, f"Sparse size {sparse_size} should be < 150KB")


if __name__ == "__main__":
    unittest.main()
