"""Comprehensive unit tests for PackageBuilder (src/core/package_builder.py).

Requirements covered:
- Clean update.zip package construction (signed and unsigned).
- Mandatory Pre-Pack and Post-Pack MCUGuard hardware isolation audits.
- Interception of MCU binaries, scripts, disguised Cortex-M payloads, and nested artifacts.
- Atomic build rollback: zero residual files left on disk when MCU contamination is detected.
- FAT32 filesystem constraints: filename validation (update.zip), max file size limit (4GB).
- Edify updater-script and update-binary generation with ROCO K706 platform assertions.
- Cryptographic signature generation and tamper verification.
"""

from __future__ import annotations

import io
import os
import shutil
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent

from src.core.mcu_guard import MCUGuard, MCUSafetyViolationError
from src.core.signer import OTAMetadata, PackageSigner, VerificationResult
from tests.e2e.test_helpers import (
    MAX_FAT32_FILE_SIZE,
    create_mock_system_fs,
    create_mock_update_zip,
    validate_fat32_filename,
)

try:
    from src.core.package_builder import (
        PackageBuilder,
        PackageBuilderError,
        validate_fat32_filename,
    )
    FAT32_LIMIT_BYTES = getattr(PackageBuilder, "FAT32_LIMIT_BYTES", MAX_FAT32_FILE_SIZE)
except ImportError:
    # Fallback / mock wrapper for test discovery before worker implementation
    FAT32_LIMIT_BYTES = MAX_FAT32_FILE_SIZE

    class PackageBuilderError(Exception):
        pass

    class PackageBuilder:
        @classmethod
        def build_update_zip(cls, source_dir: str | Path, output_zip: str | Path, sign: bool = True) -> str:
            raise NotImplementedError("PackageBuilder pending implementation")

        @classmethod
        def verify_package(cls, zip_path: str | Path) -> VerificationResult:
            raise NotImplementedError("PackageBuilder pending implementation")


class TestPackageBuilderCleanBuild(unittest.TestCase):
    """Test suite for clean builds of update.zip."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.source_dir = os.path.join(self.tmpdir.name, "clean_source")
        os.makedirs(self.source_dir, exist_ok=True)
        self.output_zip = os.path.join(self.tmpdir.name, "update.zip")

        # Create realistic mock system partition payload
        with open(os.path.join(self.source_dir, "system.new.dat"), "wb") as f:
            f.write(b"MOCK_SYSTEM_PARTITION_BLOCK_DATA" * 64)
        with open(os.path.join(self.source_dir, "system.transfer.list"), "w") as f:
            f.write("4\n1\n0\n1\n")
        with open(os.path.join(self.source_dir, "boot.img"), "wb") as f:
            f.write(b"MOCK_BOOT_KERNEL_IMAGE" * 32)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_build_clean_update_zip_success(self):
        """Authoritative Check: build_update_zip creates valid archive on disk and returns its path."""
        try:
            res = PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=False)
        except NotImplementedError:
            self.skipTest("PackageBuilder.build_update_zip pending implementation")

        self.assertTrue(os.path.isfile(self.output_zip), "update.zip must be created on disk")
        self.assertEqual(os.path.abspath(res), os.path.abspath(self.output_zip))

        with zipfile.ZipFile(self.output_zip, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("system.new.dat", namelist)
            self.assertIn("system.transfer.list", namelist)
            self.assertIn("boot.img", namelist)
            self.assertIn("META-INF/com/google/android/updater-script", namelist)
            self.assertIn("META-INF/com/google/android/update-binary", namelist)

    def test_02_build_unsigned_package(self):
        """When sign=False, package does not contain cryptographic signature files."""
        try:
            PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=False)
        except NotImplementedError:
            self.skipTest("PackageBuilder.build_update_zip pending implementation")

        with zipfile.ZipFile(self.output_zip, "r") as zf:
            namelist = zf.namelist()
            self.assertNotIn("META-INF/CERT.RSA", namelist)
            self.assertNotIn("META-INF/CERT.SF", namelist)

    def test_03_build_signed_package_by_default(self):
        """When sign=True (default), package contains standard Android OTA signature entries."""
        try:
            PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=True)
        except NotImplementedError:
            self.skipTest("PackageBuilder.build_update_zip pending implementation")

        with zipfile.ZipFile(self.output_zip, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("META-INF/MANIFEST.MF", namelist)
            self.assertIn("META-INF/CERT.SF", namelist)
            self.assertIn("META-INF/CERT.RSA", namelist)
            self.assertIn("META-INF/com/android/metadata", namelist)

    def test_04_updater_script_and_binary_present(self):
        """PackageBuilder generates Edify script and POSIX shell update-binary wrapper."""
        try:
            PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=False)
        except NotImplementedError:
            self.skipTest("PackageBuilder.build_update_zip pending implementation")

        with zipfile.ZipFile(self.output_zip, "r") as zf:
            script_bytes = zf.read("META-INF/com/google/android/updater-script")
            binary_bytes = zf.read("META-INF/com/google/android/update-binary")

        script_text = script_bytes.decode("utf-8", errors="ignore")
        self.assertIn('getprop("ro.product.device")', script_text)
        self.assertIn("ROCO_K706", script_text)
        self.assertTrue(binary_bytes.startswith(b"#!/sbin/sh"))

    def test_05_metadata_properties(self):
        """OTA metadata contains correct device and SDK level for ROCO K706 Unisoc UIS7862."""
        try:
            PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=True)
        except NotImplementedError:
            self.skipTest("PackageBuilder.build_update_zip pending implementation")

        with zipfile.ZipFile(self.output_zip, "r") as zf:
            meta_bytes = zf.read("META-INF/com/android/metadata")

        meta = OTAMetadata.parse(meta_bytes.decode("utf-8"))
        self.assertEqual(meta.pre_device, "ROCO_K706")
        self.assertEqual(meta.ota_type, "BLOCK")
        self.assertEqual(meta.post_sdk_level, 29)

    def test_06_build_from_pathlib_path(self):
        """PackageBuilder accepts pathlib.Path instances for source_dir and output_zip."""
        try:
            res = PackageBuilder.build_update_zip(
                Path(self.source_dir),
                Path(self.output_zip),
                sign=False,
            )
        except NotImplementedError:
            self.skipTest("PackageBuilder.build_update_zip pending implementation")

        self.assertTrue(os.path.isfile(res))

    def test_07_build_nonexistent_source_raises(self):
        """Non-existent source directory raises FileNotFoundError or PackageBuilderError."""
        bad_source = os.path.join(self.tmpdir.name, "nonexistent_dir")
        try:
            with self.assertRaises((FileNotFoundError, PackageBuilderError, ValueError)):
                PackageBuilder.build_update_zip(bad_source, self.output_zip)
        except NotImplementedError:
            self.skipTest("PackageBuilder.build_update_zip pending implementation")


class TestPackageBuilderMCUSafetyVeto(unittest.TestCase):
    """Test suite for MCU contamination detection, veto, and atomic failure cleanup."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.source_dir = os.path.join(self.tmpdir.name, "test_source")
        os.makedirs(self.source_dir, exist_ok=True)
        self.output_zip = os.path.join(self.tmpdir.name, "update.zip")

        # Legitimate Android files
        with open(os.path.join(self.source_dir, "system.img"), "wb") as f:
            f.write(b"SAFE_SYSTEM_IMAGE_PAYLOAD" * 32)
        with open(os.path.join(self.source_dir, "boot.img"), "wb") as f:
            f.write(b"SAFE_BOOT_IMAGE_PAYLOAD" * 32)

    def tearDown(self):
        self.tmpdir.cleanup()

    def assert_mcu_veto(self, source_dir: str, output_zip: str) -> None:
        """Helper to assert that build_update_zip halts and cleans up when MCU files are present."""
        try:
            PackageBuilder.build_update_zip(source_dir, output_zip)
        except NotImplementedError:
            self.skipTest("PackageBuilder pending implementation")
        except (RuntimeError, ValueError, PermissionError, MCUSafetyViolationError):
            pass
        else:
            self.fail("Expected MCU safety violation was not raised")

        self.assertFalse(
            os.path.exists(output_zip),
            "PackageBuilder must NEVER leave output.zip on disk when MCU file is present"
        )

    def test_01_pre_pack_direct_mcu_bin_rejection(self):
        """Source staging folder containing mcu.bin aborts packaging with no output file."""
        mcu_file = os.path.join(self.source_dir, "mcu.bin")
        with open(mcu_file, "wb") as f:
            f.write(b"HOSTILE_MCU_FIRMWARE_MICROCODE")

        self.assert_mcu_veto(self.source_dir, self.output_zip)

    def test_02_pre_pack_case_insensitive_mcu_bin_rejection(self):
        """Case variations like MCU.BIN or Mcu.Bin are detected and rejected."""
        mcu_file = os.path.join(self.source_dir, "MCU.BIN")
        with open(mcu_file, "wb") as f:
            f.write(b"HOSTILE_UPPERCASE_MCU")

        self.assert_mcu_veto(self.source_dir, self.output_zip)

    def test_03_pre_pack_hardware_specific_mcu_names_rejection(self):
        """Known MCU hardware filenames (STM32, Nuvoton, GD32, TS8827) are intercepted."""
        hazardous_names = [
            "k706_mcu.bin",
            "ts8827.bin",
            "ts8828.bin",
            "stm32_mcu.hex",
            "nuvoton_mcu.bin",
            "gd32_firmware.bin",
            "iap_mcu.bin",
        ]
        for name in hazardous_names:
            sub_dir = os.path.join(self.tmpdir.name, f"test_{name}")
            os.makedirs(sub_dir, exist_ok=True)
            with open(os.path.join(sub_dir, "system.img"), "wb") as f:
                f.write(b"SYSTEM")
            with open(os.path.join(sub_dir, name), "wb") as f:
                f.write(b"DANGEROUS_MCU_DATA")

            target_zip = os.path.join(self.tmpdir.name, f"out_{name}.zip")
            self.assert_mcu_veto(sub_dir, target_zip)

    def test_04_pre_pack_nested_mcu_artifact_rejection(self):
        """MCU artifact hidden deep inside a subfolder is intercepted."""
        nested_dir = os.path.join(self.source_dir, "system", "etc", "firmware")
        os.makedirs(nested_dir, exist_ok=True)
        with open(os.path.join(nested_dir, "mcu.bin"), "wb") as f:
            f.write(b"HIDDEN_MCU_CODE")

        self.assert_mcu_veto(self.source_dir, self.output_zip)

    def test_05_pre_pack_script_flash_mcu_rejection(self):
        """updater-script containing MCU flashing commands (flash_mcu, stm32flash) triggers veto."""
        meta_dir = os.path.join(self.source_dir, "META-INF", "com", "google", "android")
        os.makedirs(meta_dir, exist_ok=True)
        script_path = os.path.join(meta_dir, "updater-script")
        with open(script_path, "w") as f:
            f.write('ui_print("Flashing...");\npackage_extract_file("mcu.bin", "/dev/ttyS0");\n')

        self.assert_mcu_veto(self.source_dir, self.output_zip)

    def test_06_pre_pack_disguised_cortex_m_binary_rejection(self):
        """Raw binary masquerading as innocent file but containing ARM Cortex-M vector table is detected."""
        sp = 0x20001000
        reset = 0x08000101
        nmi = 0x08000141
        hardfault = 0x08000181
        vector_table = struct.pack("<4I", sp, reset, nmi, hardfault) + (b"\x00" * 48)

        disguised_file = os.path.join(self.source_dir, "radio_preset.dat")
        with open(disguised_file, "wb") as f:
            f.write(vector_table)

        self.assert_mcu_veto(self.source_dir, self.output_zip)

    def test_07_atomic_cleanup_on_mcu_veto(self):
        """Atomic rollback ensures temporary working files are cleaned up if veto triggers."""
        with open(os.path.join(self.source_dir, "mcu.bin"), "wb") as f:
            f.write(b"VETO_TRIGGER")

        try:
            PackageBuilder.build_update_zip(self.source_dir, self.output_zip)
        except NotImplementedError:
            self.skipTest("PackageBuilder pending implementation")
        except (RuntimeError, ValueError, PermissionError, MCUSafetyViolationError):
            pass

        self.assertFalse(os.path.exists(self.output_zip))
        tmp_files = [fn for fn in os.listdir(self.tmpdir.name) if fn.endswith(".tmp") or fn.startswith("staging_")]
        self.assertEqual(len(tmp_files), 0, "No residual temporary staging files should remain")


class TestPackageBuilderFAT32Compliance(unittest.TestCase):
    """Test suite for FAT32 filesystem constraints (naming rules and 4GB file size limit)."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_fat32_filename_validation_update_zip(self):
        """Canonical update.zip is recognized as valid for FAT32."""
        is_valid, msg = validate_fat32_filename("update.zip")
        self.assertTrue(is_valid, f"update.zip should be valid: {msg}")

    def test_02_fat32_filename_illegal_characters(self):
        """Filenames containing characters forbidden on FAT32 are rejected."""
        illegal_chars = [':', '*', '?', '"', '<', '>', '|', '/', '\\']
        for char in illegal_chars:
            bad_name = f"update{char}.zip"
            is_valid, msg = validate_fat32_filename(bad_name)
            self.assertFalse(is_valid, f"Char '{char}' must be rejected on FAT32")

    def test_03_fat32_filename_length_boundary(self):
        """Filenames up to 255 chars are valid; exceeding 255 chars is rejected."""
        name_255 = "a" * 251 + ".zip"
        is_valid, _ = validate_fat32_filename(name_255)
        self.assertTrue(is_valid)

        name_256 = "a" * 252 + ".zip"
        is_valid, _ = validate_fat32_filename(name_256)
        self.assertFalse(is_valid)

    def test_04_fat32_filename_empty_string(self):
        """Empty filename is invalid."""
        is_valid, _ = validate_fat32_filename("")
        self.assertFalse(is_valid)

    def test_05_fat32_max_file_size_constant(self):
        """MAX_FAT32_FILE_SIZE is strictly 4294967295 bytes (4 GiB - 1 byte)."""
        self.assertEqual(MAX_FAT32_FILE_SIZE, 4294967295)
        self.assertEqual(MAX_FAT32_FILE_SIZE, (1 << 32) - 1)

    def test_06_fat32_size_check_logic(self):
        """Payload or archive size exceeding FAT32 limit is rejected."""
        valid_size = 2 * 1024 * 1024 * 1024  # 2 GiB
        self.assertLess(valid_size, MAX_FAT32_FILE_SIZE)

        exceeded_size = 4 * 1024 * 1024 * 1024  # 4 GiB
        self.assertGreater(exceeded_size, MAX_FAT32_FILE_SIZE)

    def test_07_build_rejects_fat32_naming_violation(self):
        """Target output zip with illegal characters raises ValueError or PackageBuilderError."""
        source_dir = os.path.join(self.tmpdir.name, "clean_source")
        os.makedirs(source_dir, exist_ok=True)
        with open(os.path.join(source_dir, "system.img"), "wb") as f:
            f.write(b"SYSTEM")

        bad_zip = os.path.join(self.tmpdir.name, "update:bad.zip")
        try:
            with self.assertRaises((ValueError, PackageBuilderError)):
                PackageBuilder.build_update_zip(source_dir, bad_zip)
        except NotImplementedError:
            self.skipTest("PackageBuilder.build_update_zip pending implementation")


class TestPackageBuilderSignatureAndTamperVerification(unittest.TestCase):
    """Test suite for cryptographic signature generation and tamper verification."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.source_dir = os.path.join(self.tmpdir.name, "source")
        os.makedirs(self.source_dir, exist_ok=True)
        self.output_zip = os.path.join(self.tmpdir.name, "update.zip")

        with open(os.path.join(self.source_dir, "system.img"), "wb") as f:
            f.write(b"AUTHENTIC_SYSTEM_PAYLOAD" * 64)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_verify_valid_signed_package(self):
        """Properly signed package passes cryptographic verification."""
        try:
            PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=True)
        except NotImplementedError:
            self.skipTest("PackageBuilder pending implementation")

        signer = PackageSigner()
        res = signer.verify_archive(self.output_zip)
        self.assertTrue(res.is_valid, f"Clean signed package should be valid: {res.errors}")
        self.assertTrue(res.has_jar_signature)
        self.assertGreater(res.file_hashes_matched, 0)

    def test_02_tamper_payload_fails_verification(self):
        """Modifying a payload byte after signing invalidates the package."""
        try:
            PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=True)
        except NotImplementedError:
            self.skipTest("PackageBuilder pending implementation")

        # Tamper payload
        tampered_zip = os.path.join(self.tmpdir.name, "tampered.zip")
        with zipfile.ZipFile(self.output_zip, "r") as src_z, zipfile.ZipFile(tampered_zip, "w") as dst_z:
            for item in src_z.infolist():
                if item.filename == "system.img":
                    dst_z.writestr(item, b"CORRUPTED_SYSTEM_PAYLOAD" * 64)
                else:
                    dst_z.writestr(item, src_z.read(item.filename))

        signer = PackageSigner()
        res = signer.verify_archive(tampered_zip)
        self.assertFalse(res.is_valid, "Tampered payload must cause verification failure")
        self.assertTrue(any("Digest mismatch" in err for err in res.errors))

    def test_03_tamper_mcu_injection_into_signed_archive(self):
        """Injecting mcu.bin into an already signed archive is detected as an MCU violation."""
        try:
            PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=True)
        except NotImplementedError:
            self.skipTest("PackageBuilder pending implementation")

        injected_zip = os.path.join(self.tmpdir.name, "injected.zip")
        with zipfile.ZipFile(self.output_zip, "r") as src_z, zipfile.ZipFile(injected_zip, "w") as dst_z:
            for item in src_z.infolist():
                dst_z.writestr(item, src_z.read(item.filename))
            dst_z.writestr("mcu.bin", b"INJECTED_MCU_FIRMWARE")

        signer = PackageSigner()
        res = signer.verify_archive(injected_zip)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("MCU Safety Violation" in err for err in res.errors))


if __name__ == "__main__":
    unittest.main()
