"""Comprehensive unit tests for FirmwareUnpacker and FirmwarePacker."""

import io
import os
import shutil
import struct
import tempfile
import unittest
import zipfile

from src.core.mcu_guard import MCUGuard, MCUSafetyViolationError
from src.core.packer import FirmwarePacker
from src.core.sparse import CHUNK_TYPE_DONT_CARE, SPARSE_HEADER_MAGIC, SparseImage
from src.core.unpacker import FirmwareUnpacker, SecurityViolationError


class TestFirmwareUnpacker(unittest.TestCase):
    """Test suite for FirmwareUnpacker."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_unpacker_validate_valid_zip(self):
        """Valid ZIP archive is confirmed by validate_archive()."""
        zip_path = os.path.join(self.tmpdir.name, "valid.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system.img", b"TEST_SYSTEM_PAYLOAD")

        unpacker = FirmwareUnpacker(zip_path, os.path.join(self.tmpdir.name, "out"))
        self.assertTrue(unpacker.validate_archive())

    def test_unpacker_validate_missing_file(self):
        """Missing archive file returns False."""
        unpacker = FirmwareUnpacker(os.path.join(self.tmpdir.name, "none.zip"), self.tmpdir.name)
        self.assertFalse(unpacker.validate_archive())

    def test_unpacker_validate_corrupt_zip(self):
        """Corrupt non-ZIP file returns False."""
        bad_path = os.path.join(self.tmpdir.name, "corrupt.zip")
        with open(bad_path, "wb") as f:
            f.write(b"CORRUPTED_BYTES_NOT_ZIP")
        unpacker = FirmwareUnpacker(bad_path, self.tmpdir.name)
        self.assertFalse(unpacker.validate_archive())

    def test_unpacker_zip_slip_rejection(self):
        """Archive with path traversal member raises SecurityViolationError on unpack."""
        slip_zip = os.path.join(self.tmpdir.name, "slip.zip")
        with zipfile.ZipFile(slip_zip, "w") as zf:
            zf.writestr("../../evil.sh", b"#!/bin/sh\nrm -rf /")

        out_dir = os.path.join(self.tmpdir.name, "slip_out")
        unpacker = FirmwareUnpacker(slip_zip, out_dir)
        self.assertFalse(unpacker.validate_archive())
        with self.assertRaises(SecurityViolationError):
            unpacker.unpack()

    def test_unpacker_mcu_artifact_quarantine(self):
        """Firmware archive containing mcu.bin quarantines it without contaminating working tree."""
        zip_path = os.path.join(self.tmpdir.name, "fw_with_mcu.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system.img", b"SAFE_SYSTEM")
            zf.writestr("mcu.bin", b"MCU_FIRMWARE")

        out_dir = os.path.join(self.tmpdir.name, "quarantine_out")
        unpacker = FirmwareUnpacker(zip_path, out_dir)
        manifest = unpacker.unpack(quarantine_mcu=True)

        self.assertIn("mcu.bin", manifest["quarantined_files"])
        quarantine_file = os.path.join(out_dir, "quarantine_mcu", "mcu.bin")
        self.assertTrue(os.path.isfile(quarantine_file))
        # Ensure mcu.bin is NOT in standard extract path
        self.assertFalse(os.path.exists(os.path.join(out_dir, "mcu.bin")))

    def test_unpacker_auto_unsparse_partition(self):
        """Sparse system.img inside archive is automatically unsparsed to system.raw.img."""
        zip_path = os.path.join(self.tmpdir.name, "sparse_fw.zip")
        hdr = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 1, 0, 28, 12, 4096, 2, 1, 0)
        chunk = struct.pack("<HHII", CHUNK_TYPE_DONT_CARE, 0, 2, 12)
        sparse_bytes = hdr + chunk

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system.img", sparse_bytes)

        out_dir = os.path.join(self.tmpdir.name, "unsparse_out")
        unpacker = FirmwareUnpacker(zip_path, out_dir)
        manifest = unpacker.unpack(auto_unsparse=True)

        expected_raw = os.path.realpath(os.path.join(out_dir, "system.raw.img"))
        self.assertTrue(os.path.isfile(expected_raw))
        self.assertEqual(os.path.getsize(expected_raw), 8192)
        self.assertIn(expected_raw, manifest["unsparsed_images"])

    def test_unpacker_inspect_filesystem(self):
        """inspect_filesystem parses apps, priv-apps, and build.prop entries."""
        sys_dir = os.path.join(self.tmpdir.name, "system")
        os.makedirs(os.path.join(sys_dir, "app", "Radio"), exist_ok=True)
        os.makedirs(os.path.join(sys_dir, "app", "Canbus"), exist_ok=True)
        os.makedirs(os.path.join(sys_dir, "priv-app", "Settings"), exist_ok=True)

        with open(os.path.join(sys_dir, "build.prop"), "w", encoding="utf-8") as f:
            f.write("# Android configuration\n")
            f.write("ro.product.model=ROCO_K706\n")
            f.write("ro.build.version.release=10\n")
            f.write("ro.fyt.subvendor=ROCO\n")

        dummy_zip = os.path.join(self.tmpdir.name, "dummy.zip")
        with zipfile.ZipFile(dummy_zip, "w") as zf:
            zf.writestr("test.txt", b"test")

        unpacker = FirmwareUnpacker(dummy_zip, self.tmpdir.name)
        unpacker.system_root = sys_dir
        info = unpacker.inspect_filesystem()

        self.assertIn("Radio", info["apps"])
        self.assertIn("Canbus", info["apps"])
        self.assertIn("Settings", info["priv_apps"])
        self.assertEqual(info["build_prop"].get("ro.product.model"), "ROCO_K706")
        self.assertEqual(info["build_prop"].get("ro.build.version.release"), "10")


class TestFirmwarePacker(unittest.TestCase):
    """Test suite for FirmwarePacker."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_dir = os.path.join(self.tmpdir.name, "system")
        os.makedirs(os.path.join(self.sys_dir, "app", "Radio"), exist_ok=True)
        with open(os.path.join(self.sys_dir, "app", "Radio", "Radio.apk"), "wb") as f:
            f.write(b"APK_MOCK_DATA")
        self.out_dir = os.path.join(self.tmpdir.name, "out")
        os.makedirs(self.out_dir, exist_ok=True)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_packer_pack_partition_to_sparse(self):
        """pack_partition generates valid sparse image partition."""
        packer = FirmwarePacker(self.sys_dir, self.out_dir)
        sparse_img = packer.pack_partition("system", make_sparse=True)

        self.assertTrue(os.path.isfile(sparse_img))
        self.assertTrue(SparseImage.is_sparse(sparse_img))

    def test_packer_zero_mcu_enforcement(self):
        """Accidental MCU file in system tree causes pack_partition to abort with MCUSafetyViolationError."""
        # Inject mcu file
        mcu_trap = os.path.join(self.sys_dir, "etc", "mcu.bin")
        os.makedirs(os.path.dirname(mcu_trap), exist_ok=True)
        with open(mcu_trap, "wb") as f:
            f.write(b"DANGEROUS_MCU")

        packer = FirmwarePacker(self.sys_dir, self.out_dir)
        with self.assertRaises(MCUSafetyViolationError):
            packer.pack_partition("system")

    def test_packer_repack_update_archive(self):
        """repack_update_archive creates verified clean update ZIP."""
        packer = FirmwarePacker(self.sys_dir, self.out_dir)
        out_zip = os.path.join(self.out_dir, "update.zip")
        res = packer.repack_update_archive(out_zip)

        self.assertTrue(os.path.isfile(res))
        verif = packer.verify_repacked_archive(res)
        self.assertTrue(verif["is_valid"])
        self.assertTrue(verif["mcu_safe"])
        self.assertIn("system.img", verif["entries"])


if __name__ == "__main__":
    unittest.main()
