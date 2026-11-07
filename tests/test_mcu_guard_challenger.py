"""Empirical challenger test suite for MCUGuard (src/core/mcu_guard.py).

This test suite rigorously evaluates:
1. Detection of microcontroller firmware filenames across standard MCU families
   (STM32, GD32, Nuvoton) and casing / naming variations.
2. Updater-script content inspection for hardware port and partition writing commands.
3. Archive safety auditing via scan_archive and directory safety auditing via
   scan_directory to verify MCUSafetyViolationError behavior on non-OS firmware.
4. Genuine Android files (system.img, vendor.img, boot.img, priv-app APKs) approval
   without false positives.
"""

from __future__ import annotations

import io
import os
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from src.core.mcu_guard import MCUGuard, MCUSafetyError, MCUSafetyViolationError


def make_cortex_m_payload(size: int = 128) -> bytes:
    """Generate synthetic ARM Cortex-M bare-metal vector table payload."""
    vector_table = struct.pack(
        "<4I",
        0x20010000,  # SP in SRAM range (0x20000000 - 0x20080000), 4-byte aligned
        0x08001001,  # Reset handler in Flash (0x08000000 - 0x08200000), Thumb bit 1
        0x08001021,  # NMI handler in Flash, Thumb bit 1
        0x08001041,  # HardFault handler in Flash, Thumb bit 1
    )
    padding = b"\x00" * max(0, size - len(vector_table))
    return vector_table + padding


class TestMCUFilenamesAndCasing(unittest.TestCase):
    """Test 1: Detection of microcontroller firmware filenames across families and casing."""

    def test_stm32_family_detection(self):
        """STM32 family firmware files must be detected."""
        self.assertTrue(MCUGuard.is_mcu_artifact("stm32f407.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("STM32F103.HEX"))
        self.assertTrue(MCUGuard.is_mcu_artifact("stm32_core.dfu"))
        self.assertTrue(MCUGuard.is_mcu_artifact("stm32_bootloader.elf"))

    def test_gd32_family_detection(self):
        """GD32 family firmware files must be detected."""
        self.assertTrue(MCUGuard.is_mcu_artifact("gd32f303.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("GD32F103.HEX"))
        self.assertTrue(MCUGuard.is_mcu_artifact("gd32_app.dfu"))
        self.assertTrue(MCUGuard.is_mcu_artifact("gd32_patch.elf"))

    def test_nuvoton_family_detection(self):
        """Nuvoton family firmware files must be detected."""
        self.assertTrue(MCUGuard.is_mcu_artifact("n76e003.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("N76E003.HEX"))

    def test_case_variations_on_standard_names(self):
        """Case variations must be caught under case-insensitive filesystem rules."""
        self.assertTrue(MCUGuard.is_mcu_artifact("MCU.BIN"))
        self.assertTrue(MCUGuard.is_mcu_artifact("Mcu.Bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("Stm32F407.Bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("Gd32F303.Bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("N76e003.Bin"))

    def test_qf001_and_k706_prefixed_mcu_bin(self):
        """Vendor-prefixed MCU bin files must be detected."""
        self.assertTrue(MCUGuard.is_mcu_artifact("k706_mcu.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("qf001_mcu.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("k706_mcu_v2.hex"))


class TestUpdaterScriptInspection(unittest.TestCase):
    """Test 2: Updater-script content inspection for ports and partition writing commands."""

    def test_genuine_edify_script_accepted(self):
        """Genuine Android updater-script must be approved."""
        script = (
            'ui_print("Flashing Android OS...");\n'
            'package_extract_file("boot.img", "/dev/block/by-name/boot");\n'
            'package_extract_file("system.img", "/dev/block/by-name/system");\n'
            'package_extract_file("vendor.img", "/dev/block/by-name/vendor");\n'
            'set_progress(1.000000);\n'
        )
        is_safe, viols = MCUGuard.check_script_content(script, "updater-script")
        self.assertTrue(is_safe)
        self.assertEqual(len(viols), 0)

    def test_prohibited_mcu_filename_in_script_rejected(self):
        """Referencing an MCU file inside updater-script must be rejected."""
        script = 'package_extract_file("mcu.bin", "/tmp/mcu.bin");\n'
        is_safe, viols = MCUGuard.check_script_content(script, "updater-script")
        self.assertFalse(is_safe)
        self.assertTrue(any("mcu.bin" in v for v in viols))

    def test_package_extract_to_mcu_partition_rejected(self):
        """package_extract_file targeting mcu partition must be rejected."""
        script = 'package_extract_file("payload.bin", "/dev/block/by-name/mcu");\n'
        is_safe, viols = MCUGuard.check_script_content(script, "updater-script")
        self.assertFalse(is_safe)

    def test_write_raw_image_to_mcu_partition_rejected(self):
        """write_raw_image targeting mcu partition must be rejected."""
        script = 'write_raw_image("/tmp/boot.img", "mcu");\n'
        is_safe, viols = MCUGuard.check_script_content(script, "updater-script")
        self.assertFalse(is_safe)

    def test_serial_dev_node_ttyS_rejected(self):
        """Flashing commands referencing /dev/ttyS0 must be rejected."""
        script = 'run_program("/sbin/sh", "-c", "cat fw > /dev/ttyS0");\n'
        is_safe, viols = MCUGuard.check_script_content(script, "updater-script")
        self.assertFalse(is_safe)


class TestArchiveAndDirectoryAuditing(unittest.TestCase):
    """Test 3: Archive safety auditing via scan_archive and directory safety auditing."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_scan_archive_clean_passes(self):
        """Clean Android archive returns is_safe=True without raising."""
        zip_path = os.path.join(self.tmpdir.name, "clean_update.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system.img", b"ANDROID_SYSTEM")
            zf.writestr("boot.img", b"ANDROID_BOOT")
            zf.writestr("META-INF/com/android/metadata", b"post-build=1\n")

        is_safe, viols = MCUGuard.scan_archive(zip_path, raise_on_violation=True)
        self.assertTrue(is_safe)
        self.assertEqual(len(viols), 0)

    def test_scan_archive_raises_mcu_safety_violation_error(self):
        """Contaminated archive must raise MCUSafetyViolationError."""
        zip_path = os.path.join(self.tmpdir.name, "bad_update.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system.img", b"ANDROID_SYSTEM")
            zf.writestr("mcu.bin", b"MCU_MICROCODE")

        with self.assertRaises(MCUSafetyViolationError) as ctx:
            MCUGuard.scan_archive(zip_path, raise_on_violation=True)
        self.assertTrue(any("mcu.bin" in v for v in ctx.exception.violations))

    def test_scan_directory_clean_passes(self):
        """Clean directory returns is_safe=True without raising."""
        clean_dir = os.path.join(self.tmpdir.name, "clean_firmware")
        os.makedirs(clean_dir, exist_ok=True)
        Path(clean_dir, "system.img").write_bytes(b"ANDROID_SYSTEM")
        Path(clean_dir, "vendor.img").write_bytes(b"ANDROID_VENDOR")

        is_safe, viols = MCUGuard.scan_directory(clean_dir, raise_on_violation=True)
        self.assertTrue(is_safe)
        self.assertEqual(len(viols), 0)

    def test_scan_directory_raises_mcu_safety_violation_error(self):
        """Contaminated directory must raise MCUSafetyViolationError."""
        bad_dir = os.path.join(self.tmpdir.name, "bad_firmware")
        os.makedirs(bad_dir, exist_ok=True)
        Path(bad_dir, "system.img").write_bytes(b"ANDROID_SYSTEM")
        Path(bad_dir, "stm32f407.bin").write_bytes(b"STM32_FIRMWARE")

        with self.assertRaises(MCUSafetyViolationError) as ctx:
            MCUGuard.scan_directory(bad_dir, raise_on_violation=True)
        self.assertTrue(any("stm32f407.bin" in v for v in ctx.exception.violations))

    def test_scan_directory_cortex_m_raw_bin_detection(self):
        """Raw binary with Cortex-M vector table must raise MCUSafetyViolationError."""
        bad_dir = os.path.join(self.tmpdir.name, "vector_firmware")
        os.makedirs(bad_dir, exist_ok=True)
        Path(bad_dir, "payload.bin").write_bytes(make_cortex_m_payload())

        with self.assertRaises(MCUSafetyViolationError):
            MCUGuard.scan_directory(bad_dir, raise_on_violation=True)


class TestGenuineAndroidApproval(unittest.TestCase):
    """Test 4: Genuine Android files are safely approved without false positives."""

    def test_all_standard_android_images_approved(self):
        """Every standard Android partition image must pass without false positive."""
        standard_images = [
            "system.img",
            "vendor.img",
            "boot.img",
            "super.img",
            "product.img",
            "system_ext.img",
            "odm.img",
            "recovery.img",
            "vbmeta.img",
            "dtbo.img",
            "userdata.img",
            "cache.img",
        ]
        is_safe, flagged = MCUGuard.check_archive_safety(standard_images)
        self.assertTrue(is_safe)
        self.assertEqual(flagged, [])

    def test_android_priv_app_apks_approved(self):
        """Automotive and system priv-app APKs must be approved."""
        apks = [
            "system/priv-app/Radio/Radio.apk",
            "system/priv-app/IOSLauncher/IOSLauncher.apk",
            "system/priv-app/CanbusService/CanbusService.apk",
            "system/priv-app/AudioControl/AudioControl.apk",
            "system/priv-app/Settings/Settings.apk",
            "system/priv-app/SystemUI/SystemUI.apk",
            "system/app/Bluetooth/Bluetooth.apk",
            "system/app/CarDSP/CarDSP.apk",
            "system/app/ReverseCamera/ReverseCamera.apk",
            "system/framework/framework.jar",
        ]
        is_safe, flagged = MCUGuard.check_archive_safety(apks)
        self.assertTrue(is_safe)
        self.assertEqual(flagged, [])

    def test_full_synthetic_update_zip_approved(self):
        """A complete realistic Android update.zip must pass scan_archive with zero violations."""
        with tempfile.TemporaryDirectory() as tmp:
            zip_p = os.path.join(tmp, "full_update.zip")
            with zipfile.ZipFile(zip_p, "w") as zf:
                zf.writestr("system.img", b"ANDROID_SYSTEM_SPARSE_IMAGE_DATA")
                zf.writestr("boot.img", b"ANDROID_BOOT_IMAGE_DATA")
                zf.writestr("vendor.img", b"ANDROID_VENDOR_IMAGE_DATA")
                zf.writestr("META-INF/com/android/metadata", b"ota-type=BLOCK\n")
                zf.writestr(
                    "META-INF/com/google/android/updater-script",
                    'ui_print("Flashing Android OS...");\n'
                    'package_extract_file("boot.img", "/dev/block/by-name/boot");\n'
                    'package_extract_file("system.img", "/dev/block/by-name/system");\n',
                )
                zf.writestr("system/priv-app/IOSLauncher.apk", b"APK_BYTES")
                zf.writestr("system/fonts/Roboto.ttf", b"FONT_BYTES")

            is_safe, viols = MCUGuard.scan_archive(zip_p, raise_on_violation=True)
            self.assertTrue(is_safe)
            self.assertEqual(len(viols), 0)


if __name__ == "__main__":
    unittest.main()
