"""Comprehensive unit tests for MCU Safety Guard (mcu_guard.py)."""

import io
import os
import struct
import tempfile
import unittest
import zipfile

from src.core.mcu_guard import MCUGuard, MCUSafetyError, MCUSafetyViolationError


class TestMCUGuardArtifactDetection(unittest.TestCase):
    """Test suite for filename and path artifact detection."""

    def test_exact_mcu_binaries(self):
        """Standard stock and custom MCU filenames must be flagged."""
        self.assertTrue(MCUGuard.is_mcu_artifact("mcu.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("mcu.hex"))
        self.assertTrue(MCUGuard.is_mcu_artifact("mcu.dfu"))
        self.assertTrue(MCUGuard.is_mcu_artifact("mcu.elf"))
        self.assertTrue(MCUGuard.is_mcu_artifact("mcu.img"))
        self.assertTrue(MCUGuard.is_mcu_artifact("k706_mcu.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("qf001_mcu_v2.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("flash_mcu.sh"))

    def test_case_insensitivity(self):
        """Case variations (FAT32 filesystem semantics) must be identified."""
        self.assertTrue(MCUGuard.is_mcu_artifact("MCU.BIN"))
        self.assertTrue(MCUGuard.is_mcu_artifact("Mcu.Bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("mCu.bIn"))
        self.assertTrue(MCUGuard.is_mcu_artifact("K706_MCU.BIN"))
        self.assertTrue(MCUGuard.is_mcu_artifact("MCU.HEX"))
        self.assertTrue(MCUGuard.is_mcu_artifact("STM32F4.BIN"))

    def test_chip_specific_patterns(self):
        """Microcontroller families (STM32, GD32, Nuvoton) must be flagged."""
        self.assertTrue(MCUGuard.is_mcu_artifact("stm32f407.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("stm32_fw.hex"))
        self.assertTrue(MCUGuard.is_mcu_artifact("gd32f303.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("gd32_patch.hex"))
        self.assertTrue(MCUGuard.is_mcu_artifact("n76e003.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("n76e_rom.hex"))

    def test_vendor_patterns(self):
        """Vendor-specific MCU update tools and conventions must be caught."""
        self.assertTrue(MCUGuard.is_mcu_artifact("ts8827.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("ts8828.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("mcu_update.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("mcu_updater.sh"))
        self.assertTrue(MCUGuard.is_mcu_artifact("iap_mcu_pack.bin"))

    def test_safe_android_files_pass(self):
        """Legitimate Android OS files must NEVER be flagged as MCU artifacts."""
        safe_list = [
            "system.img",
            "super.img",
            "boot.img",
            "vendor.img",
            "product.img",
            "build.prop",
            "updater-script",
            "update-binary",
            "IOSLauncher.apk",
            "priv-app/Radio/Radio.apk",
            "assets/fonts/Roboto.ttf",
            "META-INF/com/android/metadata",
        ]
        for name in safe_list:
            self.assertFalse(
                MCUGuard.is_mcu_artifact(name),
                f"Safe Android file '{name}' was falsely flagged as MCU artifact",
            )

    def test_path_normalization_and_traversal(self):
        """Deep paths, relative traversals and backslashes must be normalized."""
        self.assertTrue(MCUGuard.is_mcu_artifact("nested/dir/firmware/mcu.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("firmware\\mcu.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("./sub/../mcu.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("   system/etc/MCU.BIN   "))
        self.assertFalse(MCUGuard.is_mcu_artifact("   system/etc/safe.img   "))

    def test_extended_mcu_image_and_iap_patterns(self):
        """Extended microcontroller images (vendor-prefixed, stm32/gd32 .img, nuvoton, iap) must be caught."""
        self.assertTrue(MCUGuard.is_mcu_artifact("k706_mcu.img"))
        self.assertTrue(MCUGuard.is_mcu_artifact("qf001_mcu.img"))
        self.assertTrue(MCUGuard.is_mcu_artifact("stm32f407.img"))
        self.assertTrue(MCUGuard.is_mcu_artifact("gd32f303.img"))
        self.assertTrue(MCUGuard.is_mcu_artifact("nuvoton.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("nuvoton.hex"))
        self.assertTrue(MCUGuard.is_mcu_artifact("nuc131.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("iap.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("iap.img"))

    def test_unicode_and_fat32_normalization(self):
        """Full-width Unicode code points and trailing dot/spaces must be normalized and blocked."""
        self.assertTrue(MCUGuard.is_mcu_artifact("\uff4d\uff43\uff55.bin"))
        self.assertTrue(MCUGuard.is_mcu_artifact("mcu.bin."))
        self.assertTrue(MCUGuard.is_mcu_artifact("mcu.bin.  "))


class TestMCUGuardArchiveSafety(unittest.TestCase):
    """Test suite for check_archive_safety and enforce_safety interfaces."""

    def test_check_archive_safety_clean(self):
        """List of clean Android files returns is_safe=True with empty violations."""
        clean = ["system.img", "boot.img", "vendor.img", "META-INF/com/android/metadata"]
        is_safe, flagged = MCUGuard.check_archive_safety(clean)
        self.assertTrue(is_safe)
        self.assertEqual(len(flagged), 0)

    def test_check_archive_safety_with_violations(self):
        """List with MCU files returns is_safe=False and exact flagged names."""
        contaminated = ["system.img", "mcu.bin", "boot.img", "nested/k706_mcu.bin"]
        is_safe, flagged = MCUGuard.check_archive_safety(contaminated)
        self.assertFalse(is_safe)
        self.assertIn("mcu.bin", flagged)
        self.assertIn("nested/k706_mcu.bin", flagged)
        self.assertEqual(len(flagged), 2)

    def test_enforce_safety_clean_passes(self):
        """Clean list does not raise exception."""
        MCUGuard.enforce_safety(["system.img", "boot.img"])

    def test_enforce_safety_raises_mcu_violation_error(self):
        """Contaminated list raises MCUSafetyViolationError with violation details."""
        with self.assertRaises(MCUSafetyViolationError) as cm:
            MCUGuard.enforce_safety(["system.img", "mcu.bin"])
        self.assertIn("mcu.bin", cm.exception.violations)


class TestMCUGuardScriptInspection(unittest.TestCase):
    """Test suite for updater-script and shell script safety checks."""

    def test_clean_updater_script_passes(self):
        """Standard clean Edify updater-script passes inspection."""
        script = (
            'ui_print("Flashing QF001 system...");\n'
            'package_extract_file("boot.img", "/dev/block/by-name/boot");\n'
            'package_extract_file("system.img", "/dev/block/by-name/system");\n'
        )
        is_safe, viols = MCUGuard.check_script_content(script, "updater-script")
        self.assertTrue(is_safe)
        self.assertEqual(len(viols), 0)

    def test_updater_script_mcu_file_extract_rejected(self):
        """Extracting mcu.bin in updater-script is caught."""
        script = 'package_extract_file("mcu.bin", "/tmp/mcu.bin");\n'
        is_safe, viols = MCUGuard.check_script_content(script, "updater-script")
        self.assertFalse(is_safe)
        self.assertTrue(any("mcu.bin" in v for v in viols))

    def test_updater_script_mcu_partition_target_rejected(self):
        """Targeting MCU partition is caught."""
        script = 'write_raw_image("/tmp/fw.img", "mcu");\n'
        is_safe, viols = MCUGuard.check_script_content(script, "updater-script")
        self.assertFalse(is_safe)
        self.assertTrue(any("mcu" in v for v in viols))

    def test_updater_script_uart_dev_node_rejected(self):
        """Direct access to serial MCU device node /dev/ttyS0 is caught."""
        script = 'run_program("/sbin/sh", "-c", "cat fw > /dev/ttyS0");\n'
        is_safe, viols = MCUGuard.check_script_content(script, "updater-script")
        self.assertFalse(is_safe)
        self.assertTrue(any("/dev/ttyS0" in v for v in viols))

    def test_shell_script_mcu_flashing_tool_rejected(self):
        """Shell script invoking stm32flash or flash_mcu is caught."""
        script = (
            "#!/sbin/sh\n"
            "stm32flash -w /tmp/fw.bin /dev/ttyS1\n"
        )
        is_safe, viols = MCUGuard.check_script_content(script, "install.sh")
        self.assertFalse(is_safe)
        self.assertTrue(any("stm32flash" in v for v in viols))

    def test_case_insensitive_uart_and_dev_nodes(self):
        """Serial device nodes across case variations and USB UART bridges must be rejected."""
        nodes = [
            "/dev/ttys0",
            "/dev/TTYS0",
            "/dev/ttyacm0",
            "/dev/ttyUSB0",
            "/dev/ttyusb1",
            "/dev/ttyHS0",
            "/dev/MCU",
        ]
        for node in nodes:
            script = f'run_program("/sbin/sh", "-c", "echo data > {node}");\n'
            is_safe, viols = MCUGuard.check_script_content(script, "updater-script")
            self.assertFalse(is_safe, f"Device node {node} was not caught")

    def test_command_agnostic_mcu_partition_target(self):
        """Shell utilities (dd, nandwrite, flashcp) targeting MCU partitions must be rejected."""
        commands = [
            'run_program("/sbin/dd", "if=/tmp/fw", "of=/dev/mcu");\n',
            'run_program("/sbin/nandwrite", "-p", "mcu", "/tmp/fw");\n',
            'run_program("/sbin/flashcp", "/tmp/fw", "/dev/mtd/by-name/mcu");\n',
            'run_program("/sbin/dd", "if=/tmp/fw", "of=/dev/block/by-name/k706_mcu");\n',
            'run_program("/sbin/dd", "if=/tmp/fw", "of=/dev/block/by-name/iap");\n',
        ]
        for cmd in commands:
            is_safe, viols = MCUGuard.check_script_content(cmd, "updater-script")
            self.assertFalse(is_safe, f"Command {cmd.strip()} was not caught")


class TestMCUGuardCortexMVectorSniffing(unittest.TestCase):
    """Test suite for ARM Cortex-M bare-metal vector table sniffing."""

    def test_cortex_m_vector_valid_signature_detected(self):
        """Valid Cortex-M vector table signature is identified."""
        # Word 0: SP in SRAM (0x20010000, 4-byte aligned)
        # Word 1: Reset handler in Flash (0x08001001, Thumb bit 1)
        # Word 2: NMI handler in Flash (0x08001021, Thumb bit 1)
        # Word 3: HardFault handler in Flash (0x08001041, Thumb bit 1)
        vector_table = struct.pack(
            "<4I",
            0x20010000,
            0x08001001,
            0x08001021,
            0x08001041,
        )
        payload = vector_table + os.urandom(128)
        self.assertTrue(MCUGuard.inspect_cortex_m_vector_table(payload))

    def test_random_or_short_binary_not_flagged(self):
        """Random data or truncated bytes are not falsely flagged."""
        self.assertFalse(MCUGuard.inspect_cortex_m_vector_table(b"SHORT"))
        self.assertFalse(MCUGuard.inspect_cortex_m_vector_table(b"\x00" * 32))
        self.assertFalse(MCUGuard.inspect_cortex_m_vector_table(os.urandom(64)))

    def test_android_sparse_header_not_flagged(self):
        """Android sparse header bytes are not flagged as Cortex-M vector table."""
        sparse_header = struct.pack(
            "<IHHHHIIII",
            0xED26FF3A,
            1,
            0,
            28,
            12,
            4096,
            1,
            1,
            0,
        )
        self.assertFalse(MCUGuard.inspect_cortex_m_vector_table(sparse_header))


class TestMCUGuardDeepScan(unittest.TestCase):
    """Test suite for recursive scan_directory and scan_archive."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_scan_archive_clean_zip(self):
        """Clean ZIP archive returns is_safe=True."""
        zip_path = os.path.join(self.tmpdir.name, "clean.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system.img", b"CLEAN_SYSTEM_IMAGE")
            zf.writestr("boot.img", b"CLEAN_BOOT_IMAGE")

        is_safe, viols = MCUGuard.scan_archive(zip_path, raise_on_violation=False)
        self.assertTrue(is_safe)
        self.assertEqual(len(viols), 0)

    def test_scan_archive_with_mcu_bin_raises_violation(self):
        """ZIP containing mcu.bin raises MCUSafetyViolationError."""
        zip_path = os.path.join(self.tmpdir.name, "contaminated.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system.img", b"CLEAN_SYSTEM")
            zf.writestr("firmware/mcu.bin", b"MCU_MICROCODE")

        with self.assertRaises(MCUSafetyViolationError):
            MCUGuard.scan_archive(zip_path, raise_on_violation=True)

    def test_scan_archive_with_nested_zip_violation(self):
        """ZIP containing a nested ZIP with MCU firmware is detected."""
        nested_bytes = io.BytesIO()
        with zipfile.ZipFile(nested_bytes, "w") as nzf:
            nzf.writestr("stm32_fw.hex", b":10000000...")

        outer_path = os.path.join(self.tmpdir.name, "outer.zip")
        with zipfile.ZipFile(outer_path, "w") as ozf:
            ozf.writestr("system.img", b"SYSTEM")
            ozf.writestr("payload.zip", nested_bytes.getvalue())

        is_safe, viols = MCUGuard.scan_archive(outer_path, raise_on_violation=False)
        self.assertFalse(is_safe)
        self.assertTrue(any("payload.zip" in v for v in viols))

    def test_scan_directory_clean_and_dirty(self):
        """Directory scanning catches dirty files and passes clean ones."""
        clean_dir = os.path.join(self.tmpdir.name, "clean_dir")
        os.makedirs(clean_dir, exist_ok=True)
        with open(os.path.join(clean_dir, "system.img"), "wb") as f:
            f.write(b"SAFE")

        is_safe, viols = MCUGuard.scan_directory(clean_dir, raise_on_violation=True)
        self.assertTrue(is_safe)

        # Inject dirty file
        with open(os.path.join(clean_dir, "k706_mcu.bin"), "wb") as f:
            f.write(b"DANGER")

        with self.assertRaises(MCUSafetyViolationError):
            MCUGuard.scan_directory(clean_dir, raise_on_violation=True)

    def test_scan_archive_disguised_vector_table(self):
        """Disguised Cortex-M binary in non-bin file inside archive must be blocked."""
        vector_table = struct.pack(
            "<4I",
            0x20010000,
            0x08001001,
            0x08001021,
            0x08001041,
        )
        payload = vector_table + os.urandom(64)
        zip_path = os.path.join(self.tmpdir.name, "disguised.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system/fonts/Roboto-Regular.ttf", payload)

        is_safe, viols = MCUGuard.scan_archive(zip_path, raise_on_violation=False)
        self.assertFalse(is_safe)
        self.assertTrue(any("Roboto-Regular.ttf" in v for v in viols))

    def test_scan_archive_multi_level_nested_zip(self):
        """Multi-level nested archives hiding MCU binaries must be recursively caught."""
        inner2 = io.BytesIO()
        with zipfile.ZipFile(inner2, "w") as z2:
            z2.writestr("mcu.bin", b"MCU_FW")

        inner1 = io.BytesIO()
        with zipfile.ZipFile(inner1, "w") as z1:
            z1.writestr("level2.zip", inner2.getvalue())

        outer = os.path.join(self.tmpdir.name, "multi.zip")
        with zipfile.ZipFile(outer, "w") as z0:
            z0.writestr("level1.zip", inner1.getvalue())
            z0.writestr("system.img", b"ANDROID")

        is_safe, viols = MCUGuard.scan_archive(outer, raise_on_violation=False)
        self.assertFalse(is_safe)


if __name__ == "__main__":
    unittest.main()
