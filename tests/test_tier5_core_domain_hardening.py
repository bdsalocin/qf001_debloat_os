"""Tier 5 Adversarial Coverage Hardening Suite for QF001 Debloat OS.

White-box adversarial stress testing across Core and Domain modules:
- src.core.sparse (AOSP libsparse streaming, extended headers, fill patterns, CRC32, limits)
- src.core.unpacker (Zip Slip defense, MCU quarantine isolation, auto-unsparse, build.prop parsing)
- src.core.packer (Pre/post-pack hardware audits, raw padding, sparse conversion, update repacking)
- src.core.signer (OTAMetadata roundtrip, whole-file signatures, tamper detection, script constraints)
- src.core.mcu_guard (Vector table sniffing boundaries, homoglyphs, script filtering, nested zip audits)
- src.core.package_builder (FAT32 filename/size compliance, atomic rollback, OTA packaging)
- src.domain.debloater (Whitelist absolute precedence, symlink security veto, read-only permissions, container parsing)
- src.domain.safety_validator (Core services, CAN bus flexible/strict, 0-byte corrupt APKs, build.prop verification)
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import stat
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from typing import Dict, List, Optional

from src.core.mcu_guard import (
    MCUGuard,
    MCUSafetyError,
    MCUSafetyViolationError,
)
from src.core.package_builder import (
    FAT32ComplianceError,
    MCUSafetyPackageError,
    PackageBuilder,
)
from src.core.packer import FirmwarePacker
from src.core.signer import (
    InvalidMetadataError,
    OTAMetadata,
    PackageSigner,
    SignatureVerificationError,
    VerificationResult,
)
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
    SparseFormatError,
    SparseImage,
)
from src.core.unpacker import (
    FirmwareUnpacker,
    SecurityViolationError,
)
from src.domain.debloater import (
    Debloater,
    DebloatReport,
    DiscoveredApp,
)
from src.domain.safety_validator import (
    HardwareSafetyViolationError,
    SafetyValidator,
    ValidationResult,
)


class TestTier5SparseEngineHardening(unittest.TestCase):
    """Adversarial stress and edge-case tests for src.core.sparse."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.work_dir = self.temp_dir.name

    def test_sparse_extended_file_header_parsing(self) -> None:
        """Verify unsparse seeks past extended file header (file_hdr_sz > 28)."""
        src_path = os.path.join(self.work_dir, "extended_hdr.img")
        dst_path = os.path.join(self.work_dir, "extended_out.raw")

        block_data = b"EXTENDED_HEADER_PAYLOAD_" * 160  # 3840 bytes
        block_data = block_data.ljust(4096, b"\x00")

        # Header with 40 bytes (12 extra extended bytes)
        ext_size = 40
        extra_bytes = b"CUSTOM_META!"
        file_hdr = struct.pack(
            "<IHHHHIIII",
            SPARSE_HEADER_MAGIC,
            SPARSE_HEADER_MAJOR_VER,
            0,
            ext_size,
            SPARSE_HEADER_CHUNK_HDR_SZ,
            4096,
            1,  # total_blocks
            1,  # total_chunks
            0,
        )
        chunk_hdr = struct.pack(
            "<HHII",
            CHUNK_TYPE_RAW,
            0,
            1,
            SPARSE_HEADER_CHUNK_HDR_SZ + 4096,
        )

        with open(src_path, "wb") as f:
            f.write(file_hdr)
            f.write(extra_bytes)
            f.write(chunk_hdr)
            f.write(block_data)

        self.assertTrue(SparseImage.is_sparse(src_path))
        self.assertTrue(SparseImage.unsparse(src_path, dst_path))

        with open(dst_path, "rb") as f:
            extracted = f.read()
        self.assertEqual(extracted, block_data)

    def test_sparse_fill_chunk_multislice_streaming(self) -> None:
        """Verify FILL chunk exceeding 1 MiB streaming buffer expands pattern correctly."""
        src_path = os.path.join(self.work_dir, "large_fill.img")
        dst_path = os.path.join(self.work_dir, "large_fill.raw")

        # 384 blocks * 4096 = 1,572,864 bytes (> 1 MiB BUFFER_STREAM_SIZE)
        num_blocks = 384
        pattern = b"\x11\x22\x33\x44"

        file_hdr = struct.pack(
            "<IHHHHIIII",
            SPARSE_HEADER_MAGIC,
            SPARSE_HEADER_MAJOR_VER,
            0,
            SPARSE_HEADER_FILE_HDR_SZ,
            SPARSE_HEADER_CHUNK_HDR_SZ,
            4096,
            num_blocks,
            1,
            0,
        )
        chunk_hdr = struct.pack(
            "<HHII",
            CHUNK_TYPE_FILL,
            0,
            num_blocks,
            SPARSE_HEADER_CHUNK_HDR_SZ + 4,
        )

        with open(src_path, "wb") as f:
            f.write(file_hdr)
            f.write(chunk_hdr)
            f.write(pattern)

        self.assertTrue(SparseImage.unsparse(src_path, dst_path))
        expected_size = num_blocks * 4096
        self.assertEqual(os.path.getsize(dst_path), expected_size)

        with open(dst_path, "rb") as f:
            head = f.read(16)
            self.assertEqual(head, pattern * 4)
            f.seek(1048576)  # at exactly 1 MiB boundary
            boundary = f.read(16)
            self.assertEqual(boundary, pattern * 4)

    def test_sparse_dont_care_multislice_streaming(self) -> None:
        """Verify DONT_CARE chunk exceeding 1 MiB produces exact zero stream."""
        src_path = os.path.join(self.work_dir, "large_dontcare.img")
        dst_path = os.path.join(self.work_dir, "large_dontcare.raw")

        num_blocks = 300  # 1,228,800 bytes (> 1 MiB)
        file_hdr = struct.pack(
            "<IHHHHIIII",
            SPARSE_HEADER_MAGIC,
            SPARSE_HEADER_MAJOR_VER,
            0,
            SPARSE_HEADER_FILE_HDR_SZ,
            SPARSE_HEADER_CHUNK_HDR_SZ,
            4096,
            num_blocks,
            1,
            0,
        )
        chunk_hdr = struct.pack(
            "<HHII",
            CHUNK_TYPE_DONT_CARE,
            0,
            num_blocks,
            SPARSE_HEADER_CHUNK_HDR_SZ,
        )

        with open(src_path, "wb") as f:
            f.write(file_hdr)
            f.write(chunk_hdr)

        self.assertTrue(SparseImage.unsparse(src_path, dst_path))
        self.assertEqual(os.path.getsize(dst_path), num_blocks * 4096)
        with open(dst_path, "rb") as f:
            content = f.read()
            self.assertEqual(content, b"\x00" * (num_blocks * 4096))

    def test_sparse_crc32_chunk_valid_and_tampered(self) -> None:
        """Verify CRC32 chunk validation succeeds on match and raises SparseChecksumError on mismatch."""
        valid_sparse = os.path.join(self.work_dir, "valid_crc.img")
        tampered_sparse = os.path.join(self.work_dir, "tampered_crc.img")
        out_raw = os.path.join(self.work_dir, "crc_out.raw")

        payload = b"TEST_PAYLOAD_FOR_CRC32_CHECK" * 100
        payload = payload.ljust(4096, b"\x00")
        actual_crc = zlib.crc32(payload) & 0xFFFFFFFF

        file_hdr = struct.pack(
            "<IHHHHIIII",
            SPARSE_HEADER_MAGIC,
            SPARSE_HEADER_MAJOR_VER,
            0,
            SPARSE_HEADER_FILE_HDR_SZ,
            SPARSE_HEADER_CHUNK_HDR_SZ,
            4096,
            1,  # total blocks
            2,  # total chunks (RAW + CRC32)
            0,
        )
        raw_hdr = struct.pack(
            "<HHII",
            CHUNK_TYPE_RAW,
            0,
            1,
            SPARSE_HEADER_CHUNK_HDR_SZ + 4096,
        )
        crc_hdr = struct.pack(
            "<HHII",
            CHUNK_TYPE_CRC32,
            0,
            0,
            SPARSE_HEADER_CHUNK_HDR_SZ + 4,
        )

        # 1. Valid CRC32
        with open(valid_sparse, "wb") as f:
            f.write(file_hdr)
            f.write(raw_hdr)
            f.write(payload)
            f.write(crc_hdr)
            f.write(struct.pack("<I", actual_crc))

        self.assertTrue(SparseImage.unsparse(valid_sparse, out_raw))

        # 2. Tampered CRC32
        bad_crc = actual_crc ^ 0xA5A5A5A5
        with open(tampered_sparse, "wb") as f:
            f.write(file_hdr)
            f.write(raw_hdr)
            f.write(payload)
            f.write(crc_hdr)
            f.write(struct.pack("<I", bad_crc))

        with self.assertRaises(SparseChecksumError):
            SparseImage.unsparse(tampered_sparse, os.path.join(self.work_dir, "fail.raw"))

    def test_sparse_corrupted_total_sz_in_chunks(self) -> None:
        """Verify SparseCorruptedError raised when chunk total_sz is inconsistent."""
        # 1. RAW chunk with incorrect total_sz
        raw_corrupt = os.path.join(self.work_dir, "bad_raw_totalsz.img")
        hdr = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 1, 0, 28, 12, 4096, 1, 1, 0)
        bad_raw_hdr = struct.pack("<HHII", CHUNK_TYPE_RAW, 0, 1, 12 + 4096 + 10)  # Wrong total_sz
        with open(raw_corrupt, "wb") as f:
            f.write(hdr + bad_raw_hdr + b"\x00" * 4096)

        with self.assertRaises(SparseCorruptedError):
            SparseImage.unsparse(raw_corrupt, os.path.join(self.work_dir, "out1.raw"))

        # 2. FILL chunk with incorrect total_sz
        fill_corrupt = os.path.join(self.work_dir, "bad_fill_totalsz.img")
        bad_fill_hdr = struct.pack("<HHII", CHUNK_TYPE_FILL, 0, 1, 12 + 8)  # Expected 12 + 4
        with open(fill_corrupt, "wb") as f:
            f.write(hdr + bad_fill_hdr + b"\x00\x00\x00\x00")

        with self.assertRaises(SparseCorruptedError):
            SparseImage.unsparse(fill_corrupt, os.path.join(self.work_dir, "out2.raw"))

        # 3. DONT_CARE chunk with incorrect total_sz
        dc_corrupt = os.path.join(self.work_dir, "bad_dc_totalsz.img")
        bad_dc_hdr = struct.pack("<HHII", CHUNK_TYPE_DONT_CARE, 0, 1, 12 + 4)  # Expected 12
        with open(dc_corrupt, "wb") as f:
            f.write(hdr + bad_dc_hdr)

        with self.assertRaises(SparseCorruptedError):
            SparseImage.unsparse(dc_corrupt, os.path.join(self.work_dir, "out3.raw"))

    def test_sparse_unknown_chunk_type_and_premature_eof(self) -> None:
        """Verify SparseCorruptedError on unrecognized chunk types and premature EOF."""
        hdr = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 1, 0, 28, 12, 4096, 1, 1, 0)

        # Unknown chunk type 0xCAC9
        unknown_path = os.path.join(self.work_dir, "unknown_chunk.img")
        with open(unknown_path, "wb") as f:
            f.write(hdr + struct.pack("<HHII", 0xCAC9, 0, 1, 12))

        with self.assertRaises(SparseCorruptedError):
            SparseImage.unsparse(unknown_path, os.path.join(self.work_dir, "u_out.raw"))

        # Premature EOF in chunk header
        eof_chunk_hdr = os.path.join(self.work_dir, "eof_chunk_hdr.img")
        with open(eof_chunk_hdr, "wb") as f:
            f.write(hdr + b"\x01\xca\x00")  # Only 3 bytes instead of 12

        with self.assertRaises(SparseCorruptedError):
            SparseImage.unsparse(eof_chunk_hdr, os.path.join(self.work_dir, "eof_out.raw"))

    def test_sparse_empty_file_and_unaligned_raw_conversion(self) -> None:
        """Verify sparse conversion on zero-length files and files with unaligned block sizes."""
        # 1. Empty file (0 bytes)
        empty_raw = os.path.join(self.work_dir, "empty.raw")
        empty_sparse = os.path.join(self.work_dir, "empty.img")
        empty_out = os.path.join(self.work_dir, "empty_out.raw")

        with open(empty_raw, "wb") as f:
            pass

        self.assertTrue(SparseImage.sparse(empty_raw, empty_sparse))
        self.assertTrue(SparseImage.is_sparse(empty_sparse))
        self.assertTrue(SparseImage.unsparse(empty_sparse, empty_out))
        self.assertEqual(os.path.getsize(empty_out), 0)

        # 2. File size not multiple of 4096 (e.g. 5000 bytes)
        unaligned_raw = os.path.join(self.work_dir, "unaligned.raw")
        unaligned_sparse = os.path.join(self.work_dir, "unaligned.img")
        unaligned_out = os.path.join(self.work_dir, "unaligned_out.raw")

        data_5000 = b"A" * 5000
        with open(unaligned_raw, "wb") as f:
            f.write(data_5000)

        self.assertTrue(SparseImage.sparse(unaligned_raw, unaligned_sparse, block_size=4096))
        self.assertTrue(SparseImage.unsparse(unaligned_sparse, unaligned_out))
        # Total blocks should be ceil(5000 / 4096) = 2 blocks = 8192 bytes
        with open(unaligned_out, "rb") as f:
            out_data = f.read()
        self.assertEqual(len(out_data), 8192)
        self.assertEqual(out_data[:5000], data_5000)
        self.assertEqual(out_data[5000:], b"\x00" * 3192)

    def test_sparse_invalid_arguments_boundaries(self) -> None:
        """Verify argument checking on sparse() and is_sparse()."""
        # Non-string path
        self.assertFalse(SparseImage.is_sparse(None))
        self.assertFalse(SparseImage.is_sparse(12345))

        # Invalid block_size
        dummy_raw = os.path.join(self.work_dir, "dummy.raw")
        with open(dummy_raw, "wb") as f:
            f.write(b"data")
        with self.assertRaises(ValueError):
            SparseImage.sparse(dummy_raw, os.path.join(self.work_dir, "out.img"), block_size=0)
        with self.assertRaises(ValueError):
            SparseImage.sparse(dummy_raw, os.path.join(self.work_dir, "out.img"), block_size=5)  # not multiple of 4

    def test_sparse_alternating_chunks_coalescing(self) -> None:
        """Verify seamless roundtrip and chunk flushing with alternating RAW, FILL, and DONT_CARE types."""
        src_path = os.path.join(self.work_dir, "alt.raw")
        sparse_path = os.path.join(self.work_dir, "alt.img")
        out_path = os.path.join(self.work_dir, "alt_out.raw")

        data = (
            b"\x00" * 4096 +
            b"\x11\x11\x11\x11" * 1024 * 2 +
            b"RAW_ARBITRARY_BLOCK_CONTENT_12345678" * 113 + b"\x00" * (4096 - 113 * 36) +
            b"\x00" * 4096 +
            b"\x22\x22\x22\x22" * 1024 * 2
        )
        with open(src_path, "wb") as f:
            f.write(data)

        self.assertTrue(SparseImage.sparse(src_path, sparse_path))
        with open(sparse_path, "rb") as f:
            hdr = f.read(28)
            tot_chunks = struct.unpack("<IHHHHIIII", hdr)[7]
            self.assertEqual(tot_chunks, 5)

        self.assertTrue(SparseImage.unsparse(sparse_path, out_path))
        with open(out_path, "rb") as f:
            self.assertEqual(f.read(), data)

    def test_sparse_chunk_splitting_at_max_blocks(self) -> None:
        """Verify chunk flushes and splits when single type exceeds MAX_CHUNK_BLOCKS (65535)."""
        src_path = os.path.join(self.work_dir, "large_70k.raw")
        sparse_path = os.path.join(self.work_dir, "large_70k.img")
        out_path = os.path.join(self.work_dir, "large_70k_out.raw")

        # 70,000 blocks of zeros -> 2 chunks expected (65535 + 4465)
        target_size = 70000 * 4096
        with open(src_path, "wb") as f:
            f.truncate(target_size)

        self.assertTrue(SparseImage.sparse(src_path, sparse_path))
        with open(sparse_path, "rb") as f:
            hdr = f.read(28)
            magic, maj, min_v, f_sz, c_sz, blk_sz, tot_blks, tot_chunks, csum = struct.unpack("<IHHHHIIII", hdr)
            self.assertEqual(tot_chunks, 2)
            self.assertEqual(tot_blks, 70000)

        self.assertTrue(SparseImage.unsparse(sparse_path, out_path))
        self.assertEqual(os.path.getsize(out_path), target_size)


class TestTier5UnpackerHardening(unittest.TestCase):
    """Adversarial stress and edge-case tests for src.core.unpacker."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.work_dir = self.temp_dir.name

    def test_unpacker_zero_byte_and_bad_crc(self) -> None:
        """Verify validate_archive handles 0-byte archives and bad ZIP CRC entries."""
        # 0-byte file
        zero_zip = os.path.join(self.work_dir, "zero.zip")
        with open(zero_zip, "wb") as f:
            pass
        unpacker_zero = FirmwareUnpacker(zero_zip, os.path.join(self.work_dir, "ext_zero"))
        self.assertTrue(unpacker_zero.validate_archive())

        # Corrupted CRC entry
        bad_crc_zip = os.path.join(self.work_dir, "bad_crc.zip")
        with zipfile.ZipFile(bad_crc_zip, "w") as zf:
            zf.writestr("test.txt", "HELLO_WORLD")
        # Flip a bit in the data stream of test.txt
        with open(bad_crc_zip, "r+b") as f:
            raw = f.read()
            idx = raw.find(b"HELLO_WORLD")
            f.seek(idx)
            f.write(b"JELLO_WORLD")

        unpacker_corrupt = FirmwareUnpacker(bad_crc_zip, os.path.join(self.work_dir, "ext_bad"))
        self.assertFalse(unpacker_corrupt.validate_archive())

    def test_unpacker_zip_slip_rejection(self) -> None:
        """Verify Zip Slip path traversal is caught by both validate_archive and unpack."""
        slip_zip = os.path.join(self.work_dir, "zip_slip.zip")
        with zipfile.ZipFile(slip_zip, "w") as zf:
            zf.writestr("../../etc/cron.d/evil", "EVIL_JOB")

        unpacker = FirmwareUnpacker(slip_zip, os.path.join(self.work_dir, "ext_slip"))
        self.assertFalse(unpacker.validate_archive())

        with self.assertRaises(SecurityViolationError):
            unpacker.unpack()

    def test_unpacker_mcu_quarantine_vs_veto(self) -> None:
        """Verify MCU artifacts are properly quarantined when flag is on and vetoed when off."""
        mcu_zip = os.path.join(self.work_dir, "mcu_package.zip")
        with zipfile.ZipFile(mcu_zip, "w") as zf:
            zf.writestr("system/build.prop", "ro.product.board=ROCO_K706\n")
            zf.writestr("firmware/mcu.bin", b"MCU_PAYLOAD")
            zf.writestr("firmware/stm32_boot.hex", b":020000040800F2")
            zf.writestr("system/app/Radio/Radio.apk", b"RADIO_APK")

        # 1. quarantine_mcu = True
        ext_q = os.path.join(self.work_dir, "ext_quarantine")
        unpacker_q = FirmwareUnpacker(mcu_zip, ext_q)
        manifest = unpacker_q.unpack(quarantine_mcu=True)

        self.assertIn("firmware/mcu.bin", manifest["quarantined_files"])
        self.assertIn("firmware/stm32_boot.hex", manifest["quarantined_files"])
        self.assertTrue(os.path.isfile(os.path.join(ext_q, "quarantine_mcu", "mcu.bin")))
        self.assertTrue(os.path.isfile(os.path.join(ext_q, "quarantine_mcu", "stm32_boot.hex")))
        self.assertTrue(os.path.isfile(os.path.join(ext_q, "system", "app", "Radio", "Radio.apk")))

        # 2. quarantine_mcu = False
        ext_veto = os.path.join(self.work_dir, "ext_veto")
        unpacker_veto = FirmwareUnpacker(mcu_zip, ext_veto)
        with self.assertRaises(MCUSafetyViolationError):
            unpacker_veto.unpack(quarantine_mcu=False)

    def test_unpacker_auto_unsparse_integration(self) -> None:
        """Verify auto_unsparse expands Android sparse images to raw images during extraction."""
        # Create a valid sparse image
        sparse_img_path = os.path.join(self.work_dir, "system.img")
        raw_source = os.path.join(self.work_dir, "system.raw")
        with open(raw_source, "wb") as f:
            f.write(b"RAW_SYSTEM_PARTITION_DATA" * 200)
        SparseImage.sparse(raw_source, sparse_img_path)

        zip_path = os.path.join(self.work_dir, "firmware_sparse.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(sparse_img_path, arcname="system.img")

        ext_dir = os.path.join(self.work_dir, "ext_sparse")
        unpacker = FirmwareUnpacker(zip_path, ext_dir)
        manifest = unpacker.unpack(auto_unsparse=True)

        self.assertEqual(len(manifest["unsparsed_images"]), 1)
        raw_unsparsed = manifest["unsparsed_images"][0]
        self.assertTrue(raw_unsparsed.endswith("system.raw.img"))
        self.assertTrue(os.path.isfile(raw_unsparsed))

    def test_unpacker_inspect_filesystem_edge_cases(self) -> None:
        """Verify inspect_filesystem handles non-existent paths, comments, and empty build.prop."""
        unpacker = FirmwareUnpacker("/dev/null", os.path.join(self.work_dir, "dummy"))
        # Non-existent target root
        res_empty = unpacker.inspect_filesystem(os.path.join(self.work_dir, "non_existent"))
        self.assertEqual(res_empty["apps"], [])
        self.assertEqual(res_empty["priv_apps"], [])
        self.assertEqual(res_empty["build_prop"], {})

        # System root with build.prop comments and hidden dot files
        sys_root = os.path.join(self.work_dir, "sys_root")
        app_dir = os.path.join(sys_root, "app")
        os.makedirs(app_dir)
        os.makedirs(os.path.join(app_dir, ".hidden_app"))
        os.makedirs(os.path.join(app_dir, "VisibleApp"))

        prop_file = os.path.join(sys_root, "build.prop")
        with open(prop_file, "w") as f:
            f.write("# Comment line\n\nro.board=ROCO\nro.desc=Desc=With=Equals\nInvalidNoEqualLine\n")

        res = unpacker.inspect_filesystem(sys_root)
        self.assertEqual(res["apps"], ["VisibleApp"])
        self.assertNotIn(".hidden_app", res["apps"])
        self.assertEqual(res["build_prop"]["ro.board"], "ROCO")
        self.assertEqual(res["build_prop"]["ro.desc"], "Desc=With=Equals")

    def test_unpacker_raw_non_sparse_image_skipped_gracefully(self) -> None:
        """Verify unpacker leaves non-sparse images intact without error when auto_unsparse=True."""
        zip_path = os.path.join(self.work_dir, "raw_img_package.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system.img", b"PURE_RAW_NOT_SPARSE_IMAGE_DATA")

        ext_dir = os.path.join(self.work_dir, "ext_raw")
        unpacker = FirmwareUnpacker(zip_path, ext_dir)
        manifest = unpacker.unpack(auto_unsparse=True)

        self.assertEqual(len(manifest["unsparsed_images"]), 0)
        self.assertTrue(os.path.isfile(os.path.join(ext_dir, "system.img")))
        self.assertFalse(os.path.exists(os.path.join(ext_dir, "system.raw.img")))


class TestTier5PackerHardening(unittest.TestCase):
    """Adversarial stress and edge-case tests for src.core.packer."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.work_dir = self.temp_dir.name

    def test_packer_empty_system_root_padding(self) -> None:
        """Verify packing an empty system root produces minimum 16 KiB (4 blocks) padded image."""
        empty_root = os.path.join(self.work_dir, "empty_sys")
        os.makedirs(empty_root)

        packer = FirmwarePacker(empty_root, os.path.join(self.work_dir, "out_empty"))
        raw_img = packer.pack_partition("system", make_sparse=False)

        self.assertEqual(os.path.getsize(raw_img), 16384)
        with open(raw_img, "rb") as f:
            header = f.read(4096)
            self.assertTrue(header.startswith(b"QF001_PARTITION_IMAGE:system"))

    def test_packer_verify_repacked_archive_invalid_or_corrupt(self) -> None:
        """Verify verify_repacked_archive gracefully rejects non-existent or corrupted zip archives."""
        packer = FirmwarePacker(self.work_dir, self.work_dir)

        # 1. Non-existent file
        res_missing = packer.verify_repacked_archive(os.path.join(self.work_dir, "ghost.zip"))
        self.assertFalse(res_missing["is_valid"])

        # 2. Corrupt non-zip file
        corrupt_file = os.path.join(self.work_dir, "corrupt.zip")
        with open(corrupt_file, "wb") as f:
            f.write(b"NOT_A_ZIP_CONTENT")
        res_corrupt = packer.verify_repacked_archive(corrupt_file)
        self.assertFalse(res_corrupt["is_valid"])

    def test_packer_pre_pack_mcu_veto(self) -> None:
        """Verify pack_partition and repack_update_archive veto MCU firmware files."""
        sys_root = os.path.join(self.work_dir, "system_with_mcu")
        os.makedirs(os.path.join(sys_root, "firmware"))
        with open(os.path.join(sys_root, "firmware", "mcu.bin"), "wb") as f:
            f.write(b"PROHIBITED_MCU_CODE")

        packer = FirmwarePacker(sys_root, os.path.join(self.work_dir, "out"))

        with self.assertRaises(MCUSafetyViolationError):
            packer.pack_partition("system")

        with self.assertRaises(MCUSafetyViolationError):
            packer.repack_update_archive(os.path.join(self.work_dir, "out", "update.zip"))

    def test_packer_repack_prohibited_partitions_dict(self) -> None:
        """Verify repack_update_archive rejects MCU entries inside partitions dict."""
        sys_root = os.path.join(self.work_dir, "clean_sys")
        os.makedirs(sys_root)
        with open(os.path.join(sys_root, "file.txt"), "w") as f:
            f.write("content")

        packer = FirmwarePacker(sys_root, os.path.join(self.work_dir, "out"))
        dummy_file = os.path.join(self.work_dir, "payload.bin")
        with open(dummy_file, "wb") as f:
            f.write(b"data")

        # Prohibited partition entry
        with self.assertRaises(MCUSafetyViolationError):
            packer.repack_update_archive(
                os.path.join(self.work_dir, "update_bad.zip"),
                partitions={"mcu.bin": dummy_file},
            )

    def test_packer_verify_repacked_archive_sparse_detection(self) -> None:
        """Verify verify_repacked_archive identifies valid sparse vs non-sparse .img partitions."""
        sys_root = os.path.join(self.work_dir, "clean_sys")
        os.makedirs(sys_root)
        with open(os.path.join(sys_root, "data.txt"), "w") as f:
            f.write("A" * 100)

        packer = FirmwarePacker(sys_root, os.path.join(self.work_dir, "out"))
        update_zip = packer.repack_update_archive(os.path.join(self.work_dir, "out", "update.zip"))

        verification = packer.verify_repacked_archive(update_zip)
        self.assertTrue(verification["is_valid"])
        self.assertTrue(verification["mcu_safe"])
        self.assertIn("system.img", verification["entries"])
        self.assertIn("system.img", verification["sparse_partitions"])


class TestTier5SignerHardening(unittest.TestCase):
    """Adversarial stress and edge-case tests for src.core.signer."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.work_dir = self.temp_dir.name
        self.signer = PackageSigner()

    def test_ota_metadata_serialization_roundtrip_and_defaults(self) -> None:
        """Verify OTAMetadata serialization and robust parsing across comments and blank lines."""
        raw_meta_text = """
        # Android OTA Metadata Header
        post-build=ROCO/QF001:10/TEST:user/release-keys
        post-build-incremental=20261107.999999
        post-sdk-level=29
        post-security-patch-level=2026-11-01
        post-timestamp=1762500000
        pre-device=ROCO_K706
        ota-type=BLOCK
        ota-required-cache=1048576
        # Trailing comments
        """
        meta = OTAMetadata.parse(raw_meta_text)
        self.assertEqual(meta.post_build, "ROCO/QF001:10/TEST:user/release-keys")
        self.assertEqual(meta.post_sdk_level, 29)
        self.assertEqual(meta.ota_required_cache, 1048576)

        serialized = meta.serialize()
        self.assertIn("post-build=ROCO/QF001:10/TEST:user/release-keys", serialized)
        self.assertIn("ota-required-cache=1048576", serialized)

        # Roundtrip parse
        meta_roundtrip = OTAMetadata.parse(serialized)
        self.assertEqual(meta_roundtrip.post_build, meta.post_build)
        self.assertEqual(meta_roundtrip.post_timestamp, meta.post_timestamp)

    def test_signer_updater_script_mcu_veto(self) -> None:
        """Verify generate_updater_script raises MCUSafetyViolationError on prohibited partitions."""
        with self.assertRaises(MCUSafetyViolationError):
            self.signer.generate_updater_script(partitions=["boot", "system", "mcu"])

        with self.assertRaises(MCUSafetyViolationError):
            self.signer.generate_updater_script(partitions=["stm32"])

    def test_signer_inject_ota_metadata_prohibited_script_defense(self) -> None:
        """Verify inject_ota_metadata with prohibited script is vetoed on signing and verification."""
        base_zip = os.path.join(self.work_dir, "base.zip")
        with zipfile.ZipFile(base_zip, "w") as zf:
            zf.writestr("system.img", b"DATA")

        hostile_script = 'package_extract_file("payload.bin", "/dev/block/by-name/mcu");'
        injected_zip = os.path.join(self.work_dir, "injected.zip")
        signed_zip = os.path.join(self.work_dir, "signed.zip")

        # Injection creates intermediate zip
        self.signer.inject_ota_metadata(
            base_zip,
            injected_zip,
            updater_script=hostile_script,
        )

        # Defense-in-depth: verify_archive flags MCU safety violation
        res_v = self.signer.verify_archive(injected_zip)
        self.assertFalse(res_v.is_valid)
        self.assertTrue(any("MCU Safety Violation" in e for e in res_v.errors))

        # Defense-in-depth: sign_archive raises MCUSafetyViolationError
        with self.assertRaises(MCUSafetyViolationError):
            self.signer.sign_archive(injected_zip, signed_zip)

    def test_signer_whole_file_signing_and_verification(self) -> None:
        """Verify whole-file signature application and verification with EOCD comment."""
        orig_zip = os.path.join(self.work_dir, "unsigned.zip")
        signed_zip = os.path.join(self.work_dir, "signed_whole.zip")

        with zipfile.ZipFile(orig_zip, "w") as zf:
            zf.writestr("system.new.dat", b"SYSTEM_IMAGE_CHUNKS")
            zf.writestr("system.transfer.list", "1\n0\n")

        self.signer.sign_archive(orig_zip, signed_zip, whole_file_sign=True)
        res = self.signer.verify_archive(signed_zip)

        self.assertTrue(res.is_valid, f"Verification failed: {res.errors}")
        self.assertTrue(res.has_jar_signature)
        self.assertTrue(res.has_whole_file_signature)
        self.assertGreaterEqual(res.file_hashes_matched, 2)

    def test_signer_tampered_payload_and_manifest_detection(self) -> None:
        """Verify cryptographic rejection when archive entries or manifest are tampered with."""
        orig_zip = os.path.join(self.work_dir, "unsigned.zip")
        signed_zip = os.path.join(self.work_dir, "signed.zip")

        with zipfile.ZipFile(orig_zip, "w") as zf:
            zf.writestr("boot.img", b"GENUINE_BOOT_PAYLOAD")

        self.signer.sign_archive(orig_zip, signed_zip, whole_file_sign=False)

        # 1. Tamper payload: replace boot.img content
        tampered_payload_zip = os.path.join(self.work_dir, "tampered_payload.zip")
        with zipfile.ZipFile(signed_zip, "r") as src_zf, zipfile.ZipFile(tampered_payload_zip, "w") as dst_zf:
            for item in src_zf.infolist():
                if item.filename == "boot.img":
                    dst_zf.writestr(item, b"TAMPERED_BOOT_PAYLOAD")
                else:
                    dst_zf.writestr(item, src_zf.read(item.filename))

        res_tampered = self.signer.verify_archive(tampered_payload_zip)
        self.assertFalse(res_tampered.is_valid)
        self.assertTrue(any("Digest mismatch" in e for e in res_tampered.errors))

        # 2. Tamper MANIFEST.MF directly
        tampered_manifest_zip = os.path.join(self.work_dir, "tampered_manifest.zip")
        with zipfile.ZipFile(signed_zip, "r") as src_zf, zipfile.ZipFile(tampered_manifest_zip, "w") as dst_zf:
            for item in src_zf.infolist():
                if item.filename == "META-INF/MANIFEST.MF":
                    dst_zf.writestr(item, src_zf.read(item.filename) + b"\n# Tamper comment\n")
                else:
                    dst_zf.writestr(item, src_zf.read(item.filename))

        res_manifest_tampered = self.signer.verify_archive(tampered_manifest_zip)
        self.assertFalse(res_manifest_tampered.is_valid)
        self.assertTrue(any("CERT.SF SHA-256-Digest-Manifest does not match" in e for e in res_manifest_tampered.errors))

    def test_signer_unsigned_archive_rejection(self) -> None:
        """Verify verify_archive marks unsigned ZIP archives as invalid with descriptive error."""
        unsigned_zip = os.path.join(self.work_dir, "unsigned_plain.zip")
        with zipfile.ZipFile(unsigned_zip, "w") as zf:
            zf.writestr("system.img", b"UNENCRYPTED_SYSTEM_DATA")

        res = self.signer.verify_archive(unsigned_zip)
        self.assertFalse(res.is_valid)
        self.assertFalse(res.has_jar_signature)
        self.assertTrue(any("Package is not signed" in e for e in res.errors))

    def test_signer_corrupted_rsa_signature_verification(self) -> None:
        """Verify OpenSSL verification failure when CERT.RSA signature bytes are corrupted."""
        orig_zip = os.path.join(self.work_dir, "to_corrupt.zip")
        signed_zip = os.path.join(self.work_dir, "signed_corrupt_rsa.zip")
        with zipfile.ZipFile(orig_zip, "w") as zf:
            zf.writestr("boot.img", b"BOOT_PARTITION_DATA")

        self.signer.sign_archive(orig_zip, signed_zip)

        corrupt_rsa_zip = os.path.join(self.work_dir, "bad_rsa.zip")
        with zipfile.ZipFile(signed_zip, "r") as src_zf, zipfile.ZipFile(corrupt_rsa_zip, "w") as dst_zf:
            for item in src_zf.infolist():
                if item.filename == "META-INF/CERT.RSA":
                    dst_zf.writestr(item, b"\x30\x82\x01\x00" + b"\xDE\xAD" * 50)
                else:
                    dst_zf.writestr(item, src_zf.read(item.filename))

        res = self.signer.verify_archive(corrupt_rsa_zip)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("OpenSSL signature verification failed" in e for e in res.errors))


class TestTier5MCUGuardHardening(unittest.TestCase):
    """Adversarial stress and edge-case tests for src.core.mcu_guard."""

    def test_mcu_guard_filename_normalization_edge_cases(self) -> None:
        """Verify path normalization, casing, trailing dots/spaces, and slashes."""
        adversarial_filenames = [
            "mcu.bin.",
            "mcu.bin   ",
            "././././mcu.bin",
            "firmware///mcu.bin",
            r"system\firmware\mcu.bin",
            "MCU.BIN",
            "STM32F407.HEX",
            "TS8828.BIN",
            "ts8827.bin",
            "iap_mcu.bin",
            "nuvoton_mcu.bin",
            "n76e003.hex",
            "gd32_boot.dfu",
            "mcu_update.sh",
        ]
        for name in adversarial_filenames:
            self.assertTrue(
                MCUGuard.is_mcu_artifact(name),
                f"MCUGuard failed to detect MCU artifact: '{name}'",
            )

    def test_mcu_guard_safe_filenames_not_flagged(self) -> None:
        """Verify non-prohibited documentation, configs, and system files are not falsely flagged."""
        safe_filenames = [
            "mcu_documentation.txt",
            "stm32_programming_guide.pdf",
            "hardware_datasheet.md",
            "gd32_specifications.json",
            "system.img",
            "boot.img",
            "build.prop",
            "Radio.apk",
        ]
        for name in safe_filenames:
            self.assertFalse(
                MCUGuard.is_mcu_artifact(name),
                f"MCUGuard falsely flagged safe file: '{name}'",
            )

    def test_mcu_guard_cortex_m_vector_table_boundaries(self) -> None:
        """Verify ARM Cortex-M bare-metal vector table inspection boundaries."""
        # Valid lower bound
        v_low = struct.pack("<4I", 0x20000000, 0x08000001, 0x08000001, 0x08000001)
        self.assertTrue(MCUGuard.inspect_cortex_m_vector_table(v_low))

        # Valid upper bound within flash range
        v_high = struct.pack("<4I", 0x20080000, 0x081FFFFF, 0x081FFFFF, 0x081FFFFF)
        self.assertTrue(MCUGuard.inspect_cortex_m_vector_table(v_high))

        # Invalid SP: below SRAM range
        v_bad_sp_low = struct.pack("<4I", 0x1FFFFFFF, 0x08000001, 0x08000001, 0x08000001)
        self.assertFalse(MCUGuard.inspect_cortex_m_vector_table(v_bad_sp_low))

        # Invalid SP: above SRAM range
        v_bad_sp_high = struct.pack("<4I", 0x20080004, 0x08000001, 0x08000001, 0x08000001)
        self.assertFalse(MCUGuard.inspect_cortex_m_vector_table(v_bad_sp_high))

        # Invalid SP: unaligned (not divisible by 4)
        v_unaligned_sp = struct.pack("<4I", 0x20001002, 0x08000001, 0x08000001, 0x08000001)
        self.assertFalse(MCUGuard.inspect_cortex_m_vector_table(v_unaligned_sp))

        # Invalid Reset: even address (Thumb bit 0)
        v_even_reset = struct.pack("<4I", 0x20001000, 0x08000100, 0x08000001, 0x08000001)
        self.assertFalse(MCUGuard.inspect_cortex_m_vector_table(v_even_reset))

        # Truncated data (< 16 bytes)
        self.assertFalse(MCUGuard.inspect_cortex_m_vector_table(v_low[:15]))

    def test_mcu_guard_cortex_m_all_exception_vectors(self) -> None:
        """Verify NMI or HardFault with even address (Thumb bit 0) are rejected."""
        # Invalid NMI (Thumb bit 0)
        v_even_nmi = struct.pack("<4I", 0x20001000, 0x08000101, 0x08000100, 0x08000101)
        self.assertFalse(MCUGuard.inspect_cortex_m_vector_table(v_even_nmi))

        # Invalid HardFault (Thumb bit 0)
        v_even_hf = struct.pack("<4I", 0x20001000, 0x08000101, 0x08000101, 0x08000100)
        self.assertFalse(MCUGuard.inspect_cortex_m_vector_table(v_even_hf))

    def test_mcu_guard_prohibited_device_nodes_matrix(self) -> None:
        """Verify check_script_content flags all prohibited UART/TTY device nodes."""
        for node in ["/dev/ttyS0", "/dev/ttyUSB1", "/dev/ttyACM0", "/dev/ttyHS2", "/dev/mcu"]:
            script = f'ui_print("Testing");\necho "test" > {node};\n'
            is_safe, viols = MCUGuard.check_script_content(script)
            self.assertFalse(is_safe, f"Device node '{node}' was not flagged")

    def test_mcu_guard_enforce_safety_clean_vs_flagged(self) -> None:
        """Verify enforce_safety passes clean lists and raises MCUSafetyViolationError on MCU files."""
        clean_list = ["system.img", "boot.img", "vendor.img"]
        MCUGuard.enforce_safety(clean_list)

        dirty_list = ["system.img", "ts8828.bin"]
        with self.assertRaises(MCUSafetyViolationError):
            MCUGuard.enforce_safety(dirty_list)

    def test_mcu_guard_deep_nested_zip_scan(self) -> None:
        """Verify recursive scanning flags MCU binaries hidden deep inside nested ZIP archives."""
        nested3 = io.BytesIO()
        with zipfile.ZipFile(nested3, "w") as z3:
            z3.writestr("mcu.bin", b"NESTED_MCU_PAYLOAD")

        nested2 = io.BytesIO()
        with zipfile.ZipFile(nested2, "w") as z2:
            z2.writestr("level2.zip", nested3.getvalue())

        root_zip = io.BytesIO()
        with zipfile.ZipFile(root_zip, "w") as z1:
            z1.writestr("level1.zip", nested2.getvalue())

        is_safe, viols = MCUGuard.scan_archive(root_zip.getvalue(), raise_on_violation=False)
        self.assertFalse(is_safe)
        self.assertTrue(any("mcu.bin" in v for v in viols))


class TestTier5PackageBuilderHardening(unittest.TestCase):
    """Adversarial stress and edge-case tests for src.core.package_builder."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.work_dir = self.temp_dir.name

    def test_package_builder_fat32_filename_exhaustive(self) -> None:
        """Verify strict FAT32 filename compliance checks."""
        # Empty filename
        self.assertFalse(PackageBuilder.validate_fat32_filename("")[0])
        # Exceeds 255 chars
        self.assertFalse(PackageBuilder.validate_fat32_filename("a" * 256)[0])
        # Exactly 255 chars
        self.assertTrue(PackageBuilder.validate_fat32_filename("a" * 255)[0])

        # Illegal FAT32 characters: \ / : * ? " < > |
        for char in r'\/:*?"<>|':
            fname = f"update{char}test.zip"
            is_valid, reason = PackageBuilder.validate_fat32_filename(fname)
            self.assertFalse(is_valid, f"Character '{char}' was incorrectly allowed")

    def test_package_builder_fat32_size_boundary(self) -> None:
        """Verify FAT32 size boundary (4 GiB - 1 byte is valid, 4 GiB raises FAT32ComplianceError)."""
        PackageBuilder.check_fat32_size(4294967295)  # 4 GiB - 1 byte

        with self.assertRaises(FAT32ComplianceError):
            PackageBuilder.check_fat32_size(4294967296)  # Exactly 4 GiB

    def test_package_builder_atomic_rollback_on_prepack_failure(self) -> None:
        """Verify atomic rollback: target output_zip is never created if pre-pack validation fails."""
        src_dir = os.path.join(self.work_dir, "hostile_src")
        os.makedirs(src_dir)
        with open(os.path.join(src_dir, "mcu.bin"), "wb") as f:
            f.write(b"HOSTILE_MCU_DATA")

        out_zip = os.path.join(self.work_dir, "update_aborted.zip")
        with self.assertRaises(MCUSafetyPackageError):
            PackageBuilder.build_update_zip(src_dir, out_zip)

        self.assertFalse(os.path.exists(out_zip), "Output ZIP was left on disk after pre-pack failure")

    def test_package_builder_build_prop_device_metadata_extraction(self) -> None:
        """Verify build_update_zip parses ro.product.device and release version into metadata."""
        src_dir = os.path.join(self.work_dir, "ota_src")
        os.makedirs(src_dir)
        with open(os.path.join(src_dir, "build.prop"), "w") as f:
            f.write("ro.product.device=ROCO_K706_CUSTOM\nro.build.version.release=10\n")
        with open(os.path.join(src_dir, "system.transfer.list"), "w") as f:
            f.write("1\n0\n")
        with open(os.path.join(src_dir, "system.new.dat"), "wb") as f:
            f.write(b"BLOCK_DATA")

        out_zip = os.path.join(self.work_dir, "update.zip")
        PackageBuilder.build_update_zip(src_dir, out_zip, sign=True)

        res = PackageBuilder.verify_package(out_zip)
        self.assertTrue(res["is_valid"])
        self.assertEqual(res["metadata"]["pre_device"], "ROCO_K706_CUSTOM")
        self.assertEqual(res["metadata"]["post_sdk_level"], 29)

    def test_package_builder_verify_package_matrix(self) -> None:
        """Verify PackageBuilder.verify_package flags missing files, bad names, and MCU violations."""
        # 1. Non-existent file
        res_missing = PackageBuilder.verify_package(os.path.join(self.work_dir, "ghost.zip"))
        self.assertFalse(res_missing["is_valid"])
        self.assertIn("File not found", res_missing["error"])

        # 2. Archive containing MCU violation
        infected_zip = os.path.join(self.work_dir, "infected.zip")
        with zipfile.ZipFile(infected_zip, "w") as zf:
            zf.writestr("mcu.bin", b"PROHIBITED_MCU_DATA")
        res_infected = PackageBuilder.verify_package(infected_zip)
        self.assertFalse(res_infected["is_valid"])
        self.assertFalse(res_infected["mcu_safe"])
        self.assertGreater(len(res_infected["mcu_violations"]), 0)


class TestTier5DebloaterHardening(unittest.TestCase):
    """Adversarial stress and edge-case tests for src.domain.debloater."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.work_dir = self.temp_dir.name

    def test_debloater_whitelist_absolute_precedence(self) -> None:
        """Verify whitelist takes absolute priority over blacklist wildcard matches."""
        sys_root = os.path.join(self.work_dir, "system")
        app_dir = os.path.join(sys_root, "app")
        os.makedirs(app_dir)

        # Radio app matches com.ts.*
        radio_dir = os.path.join(app_dir, "Radio")
        os.makedirs(radio_dir)
        with open(os.path.join(radio_dir, "Radio.apk"), "w") as f:
            f.write("MOCK_APK_FOR_com.ts.main.radio")

        # Bloat app also matches com.ts.*
        bloat_dir = os.path.join(app_dir, "TsBloat")
        os.makedirs(bloat_dir)
        with open(os.path.join(bloat_dir, "TsBloat.apk"), "w") as f:
            f.write("MOCK_APK_FOR_com.ts.bloatware")

        debloater = Debloater(
            blacklist=["com.ts.*"],
            whitelist=["com.ts.main.radio"],
        )
        report = debloater.debloat_filesystem(sys_root, dry_run=False)

        self.assertIn("com.ts.bloatware", report.removed_packages)
        self.assertNotIn("com.ts.main.radio", report.removed_packages)
        self.assertIn("com.ts.main.radio", report.preserved_packages)
        self.assertTrue(os.path.exists(radio_dir))
        self.assertFalse(os.path.exists(bloat_dir))

    def test_debloater_symlink_security_veto(self) -> None:
        """Verify symlinks targeting paths outside system root trigger security veto."""
        sys_root = os.path.join(self.work_dir, "system")
        app_dir = os.path.join(sys_root, "app")
        os.makedirs(app_dir)

        # Symlink pointing outside system root
        outside_target = os.path.join(self.work_dir, "outside_dir")
        os.makedirs(outside_target)
        symlink_app = os.path.join(app_dir, "SymlinkBloat")
        os.symlink(outside_target, symlink_app)

        debloater = Debloater(blacklist=["SymlinkBloat"])
        report = debloater.debloat_filesystem(sys_root, dry_run=False)

        self.assertTrue(any("Security veto" in err for err in report.errors))
        self.assertTrue(os.path.exists(outside_target))

    def test_debloater_readonly_permissions_unlocked_and_purged(self) -> None:
        """Verify read-only files and directories are cleanly unlocked and purged."""
        sys_root = os.path.join(self.work_dir, "system")
        app_dir = os.path.join(sys_root, "app")
        ro_app = os.path.join(app_dir, "ReadOnlyBloat")
        os.makedirs(ro_app)

        ro_file = os.path.join(ro_app, "locked.apk")
        with open(ro_file, "w") as f:
            f.write("MOCK_APK_FOR_com.locked.bloat")

        os.chmod(ro_file, stat.S_IRUSR)
        os.chmod(ro_app, stat.S_IRUSR | stat.S_IXUSR)

        debloater = Debloater(blacklist=["com.locked.bloat"])
        report = debloater.debloat_filesystem(sys_root, dry_run=False)

        self.assertIn("com.locked.bloat", report.removed_packages)
        self.assertFalse(os.path.exists(ro_app))

    def test_debloater_category_container_selective_purge(self) -> None:
        """Verify container directories with sibling apps only purge the blacklisted app."""
        sys_root = os.path.join(self.work_dir, "system")
        app_dir = os.path.join(sys_root, "app")
        container = os.path.join(app_dir, "OEMSuite")
        os.makedirs(container)

        sub_a = os.path.join(container, "BloatA")
        os.makedirs(sub_a)
        with open(os.path.join(sub_a, "BloatA.apk"), "w") as f:
            f.write("MOCK_APK_FOR_com.oem.bloat")

        sub_b = os.path.join(container, "UsefulB")
        os.makedirs(sub_b)
        with open(os.path.join(sub_b, "UsefulB.apk"), "w") as f:
            f.write("MOCK_APK_FOR_com.oem.useful")

        debloater = Debloater(blacklist=["com.oem.bloat"])
        report = debloater.debloat_filesystem(sys_root, dry_run=False)

        self.assertIn("com.oem.bloat", report.removed_packages)
        self.assertFalse(os.path.exists(sub_a))
        self.assertTrue(os.path.exists(sub_b))
        self.assertTrue(os.path.exists(container))

    def test_debloater_dry_run_zero_filesystem_mutation(self) -> None:
        """Verify dry_run=True computes metrics and paths without altering filesystem."""
        sys_root = os.path.join(self.work_dir, "system")
        app_dir = os.path.join(sys_root, "app")
        bloat_dir = os.path.join(app_dir, "DryBloat")
        os.makedirs(bloat_dir)
        with open(os.path.join(bloat_dir, "DryBloat.apk"), "w") as f:
            f.write("MOCK_APK_FOR_com.dry.bloat")

        debloater = Debloater(blacklist=["com.dry.bloat"])
        report = debloater.debloat_filesystem(sys_root, dry_run=True)

        self.assertTrue(report.dry_run)
        self.assertIn("com.dry.bloat", report.removed_packages)
        self.assertTrue(os.path.exists(bloat_dir))

    def test_debloater_filter_packages_pure_logic(self) -> None:
        """Verify filter_packages enforces whitelist immunity over wildcards and handles invalid types."""
        debloater = Debloater(
            blacklist=["com.ts.*", "com.baidu.BaiduMap", "amap"],
            whitelist=["com.ts.main.radio", "com.baidu.safe"],
        )
        installed = [
            "com.ts.main.radio",   # whitelisted despite matching com.ts.*
            "com.ts.bloatware",    # matches com.ts.*
            "com.baidu.BaiduMap",  # exact blacklist match
            "com.autonavi.amap",   # matches short name amap
            "com.google.android",  # unlisted
            None,                  # non-string
            12345,                 # non-string
        ]
        to_remove = debloater.filter_packages(installed)
        self.assertNotIn("com.ts.main.radio", to_remove)
        self.assertIn("com.ts.bloatware", to_remove)
        self.assertIn("com.baidu.BaiduMap", to_remove)
        self.assertIn("com.autonavi.amap", to_remove)
        self.assertNotIn("com.google.android", to_remove)

    def test_debloater_discovered_app_and_report_serialization(self) -> None:
        """Verify DiscoveredApp and DebloatReport metrics, JSON serialization, and summary output."""
        app = DiscoveredApp(
            folder_path="/system/app/Radio",
            folder_name="Radio",
            partition="system/app",
            candidate_packages={"com.ts.main.radio"},
            apk_paths=["/system/app/Radio/Radio.apk"],
            size_bytes=1048576,
        )
        self.assertEqual(app.size_bytes, 1048576)
        self.assertTrue(app.is_directory)

        report = DebloatReport(
            system_root="/system",
            removed_packages=["com.bloat.one", "com.bloat.two"],
            preserved_packages=["com.ts.main.radio"],
            bytes_freed=2097152,
            dry_run=False,
        )
        self.assertEqual(report.removed_count, 2)
        self.assertEqual(report.preserved_count, 1)

        d = report.to_dict()
        self.assertEqual(d["bytes_freed"], 2097152)
        self.assertIn("Debloat Report", report.summary())


class TestTier5SafetyValidatorHardening(unittest.TestCase):
    """Adversarial stress and edge-case tests for src.domain.safety_validator."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.work_dir = self.temp_dir.name

    def _setup_valid_system_fs(self, root: str) -> None:
        app_dir = os.path.join(root, "app")
        os.makedirs(app_dir, exist_ok=True)
        for pkg in SafetyValidator.CORE_AUTOMOTIVE_PACKAGES:
            p = os.path.join(app_dir, pkg)
            os.makedirs(p, exist_ok=True)
            with open(os.path.join(p, f"{pkg}.apk"), "wb") as f:
                f.write(b"VALID_APK_PAYLOAD")

        can_p = os.path.join(app_dir, "com.roco.canbus")
        os.makedirs(can_p, exist_ok=True)
        with open(os.path.join(can_p, "com.roco.canbus.apk"), "wb") as f:
            f.write(b"VALID_CANBUS_PAYLOAD")

        prop_file = os.path.join(root, "build.prop")
        with open(prop_file, "w") as f:
            f.write(
                "ro.product.board=ROCO_K706\n"
                "ro.qf001.radio.tuner=TDA7708\n"
                "ro.qf001.audio.dsp=BU32107EFV\n"
            )

    def test_safety_validator_missing_core_automotive_service(self) -> None:
        """Verify missing core automotive package raises HardwareSafetyViolationError."""
        sys_root = os.path.join(self.work_dir, "system")
        self._setup_valid_system_fs(sys_root)

        # Delete radio package
        import shutil
        shutil.rmtree(os.path.join(sys_root, "app", "com.ts.main.radio"))

        validator = SafetyValidator(raise_on_error=True)
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(sys_root)

        self.assertIn("com.ts.main.radio", ctx.exception.missing_services)

    def test_safety_validator_corrupt_zero_byte_apk(self) -> None:
        """Verify zero-byte corrupt APK is flagged and causes validation failure."""
        sys_root = os.path.join(self.work_dir, "system")
        self._setup_valid_system_fs(sys_root)

        # Truncate Camera APK to 0 bytes
        cam_apk = os.path.join(sys_root, "app", "com.ts.camera", "com.ts.camera.apk")
        with open(cam_apk, "wb") as f:
            pass

        validator = SafetyValidator(raise_on_error=False)
        result = validator.verify_preserved_services(sys_root)

        self.assertFalse(result.is_safe)
        self.assertIn("com.ts.camera", result.corrupt_services)
        self.assertTrue(any("0-byte" in v or "0 bytes" in v or "corrupt" in v.lower() for v in result.violations))

    def test_safety_validator_canbus_flexible_vs_strict(self) -> None:
        """Verify CAN bus controllers under flexible (>=1) vs strict (require_all_canbus=True)."""
        sys_root = os.path.join(self.work_dir, "system")
        self._setup_valid_system_fs(sys_root)
        # System currently has com.roco.canbus but NOT com.syu.canbus

        # Flexible: should pass with 1 CAN bus controller
        v_flex = SafetyValidator(raise_on_error=False, require_all_canbus=False)
        res_flex = v_flex.verify_preserved_services(sys_root)
        self.assertTrue(res_flex.is_safe)

        # Strict: should fail because com.syu.canbus is missing
        v_strict = SafetyValidator(raise_on_error=False, require_all_canbus=True)
        res_strict = v_strict.verify_preserved_services(sys_root)
        self.assertFalse(res_strict.is_safe)
        self.assertIn("com.syu.canbus", res_strict.missing_services)

    def test_safety_validator_build_prop_hardware_mismatch(self) -> None:
        """Verify build.prop violations when board, tuner, or DSP do not match expected hardware."""
        sys_root = os.path.join(self.work_dir, "system")
        self._setup_valid_system_fs(sys_root)

        prop_file = os.path.join(sys_root, "build.prop")
        # Tamper DSP property
        with open(prop_file, "w") as f:
            f.write(
                "ro.product.board=ROCO_K706\n"
                "ro.qf001.radio.tuner=TDA7708\n"
                "ro.qf001.audio.dsp=GENERIC_AC97\n"  # Wrong DSP
            )

        validator = SafetyValidator(raise_on_error=False, enforce_build_prop=True)
        res = validator.verify_preserved_services(sys_root)

        self.assertFalse(res.is_safe)
        self.assertTrue(any("Audio DSP mismatch" in v for v in res.violations))

    def test_safety_validator_check_vs_enforce_preserved_services(self) -> None:
        """Verify check_preserved_services returns is_safe=False while enforce raises error."""
        validator = SafetyValidator()
        non_existent = os.path.join(self.work_dir, "missing_system_root")

        # check_preserved_services does not raise
        res = validator.check_preserved_services(non_existent)
        self.assertFalse(res.is_safe)

        # enforce_preserved_services raises HardwareSafetyViolationError
        with self.assertRaises(HardwareSafetyViolationError):
            validator.enforce_preserved_services(non_existent)

    def test_safety_validator_result_bool_and_dict(self) -> None:
        """Verify ValidationResult bool evaluation, aliases, and dictionary export."""
        res_pass = ValidationResult(is_safe=True, verified_services=["com.ts.main.radio"])
        self.assertTrue(bool(res_pass))
        self.assertTrue(res_pass.is_valid)
        self.assertEqual(res_pass.preserved_packages_found, ["com.ts.main.radio"])

        res_fail = ValidationResult(is_safe=False, missing_services=["com.ts.camera"])
        self.assertFalse(bool(res_fail))
        self.assertFalse(res_fail.is_valid)
        self.assertEqual(res_fail.missing_packages, ["com.ts.camera"])
        d = res_fail.to_dict()
        self.assertFalse(d["is_safe"])
        self.assertEqual(d["missing_services"], ["com.ts.camera"])


if __name__ == "__main__":
    unittest.main()
