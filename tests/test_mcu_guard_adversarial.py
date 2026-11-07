"""Adversarial stress-testing suite for MCUGuard (src/core/mcu_guard.py).

This test suite empirically challenges MCUGuard against evasions, obfuscations,
nested archives, disguised vector tables, and fake updater-script commands.
"""

import io
import os
import struct
import tempfile
import unittest
import zipfile

from src.core.mcu_guard import MCUGuard, MCUSafetyViolationError


def make_cortex_m_payload(size: int = 256) -> bytes:
    """Generate synthetic ARM Cortex-M bare-metal vector table payload."""
    vector_table = struct.pack(
        "<4I",
        0x20010000,  # SP in SRAM range (0x20000000 - 0x20080000), 4-byte aligned
        0x08001001,  # Reset handler in Flash (0x08000000 - 0x08200000), Thumb bit 1
        0x08001021,  # NMI handler in Flash, Thumb bit 1
        0x08001041,  # HardFault handler in Flash, Thumb bit 1
    )
    padding = b"\xaa" * max(0, size - len(vector_table))
    return vector_table + padding


class TestDisguisedVectorTableBypass(unittest.TestCase):
    """Challenge MCUGuard with synthetic Cortex-M vector tables disguised with benign extensions."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_disguised_font_ttf_in_archive(self):
        """A Cortex-M binary payload disguised as 'font.ttf' in an update archive must be blocked."""
        zip_path = os.path.join(self.tmpdir.name, "disguised_font.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system/fonts/Roboto-Regular.ttf", make_cortex_m_payload())
            zf.writestr("system/build.prop", b"ro.build.version=10\n")

        is_safe, viols = MCUGuard.scan_archive(zip_path, raise_on_violation=False)
        self.assertFalse(
            is_safe,
            "VULNERABILITY: Disguised Cortex-M vector table in 'font.ttf' bypassed MCUGuard.scan_archive!",
        )

    def test_disguised_libaudio_so_in_archive(self):
        """A Cortex-M binary payload disguised as 'libaudio.so' in an update archive must be blocked."""
        zip_path = os.path.join(self.tmpdir.name, "disguised_libaudio.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("system/lib64/libaudio.so", make_cortex_m_payload())

        is_safe, viols = MCUGuard.scan_archive(zip_path, raise_on_violation=False)
        self.assertFalse(
            is_safe,
            "VULNERABILITY: Disguised Cortex-M vector table in 'libaudio.so' bypassed MCUGuard.scan_archive!",
        )

    def test_disguised_font_ttf_in_directory(self):
        """A Cortex-M binary payload disguised as 'font.ttf' in a directory must be blocked."""
        dir_path = os.path.join(self.tmpdir.name, "dir_font")
        fonts_dir = os.path.join(dir_path, "system", "fonts")
        os.makedirs(fonts_dir, exist_ok=True)
        with open(os.path.join(fonts_dir, "font.ttf"), "wb") as f:
            f.write(make_cortex_m_payload())

        is_safe, viols = MCUGuard.scan_directory(dir_path, raise_on_violation=False)
        self.assertFalse(
            is_safe,
            "VULNERABILITY: Disguised Cortex-M vector table in 'font.ttf' bypassed MCUGuard.scan_directory!",
        )

    def test_disguised_libaudio_so_in_directory(self):
        """A Cortex-M binary payload disguised as 'libaudio.so' in a directory must be blocked."""
        dir_path = os.path.join(self.tmpdir.name, "dir_libaudio")
        lib_dir = os.path.join(dir_path, "system", "lib")
        os.makedirs(lib_dir, exist_ok=True)
        with open(os.path.join(lib_dir, "libaudio.so"), "wb") as f:
            f.write(make_cortex_m_payload())

        is_safe, viols = MCUGuard.scan_directory(dir_path, raise_on_violation=False)
        self.assertFalse(
            is_safe,
            "VULNERABILITY: Disguised Cortex-M vector table in 'libaudio.so' bypassed MCUGuard.scan_directory!",
        )


class TestNestedArchiveBypass(unittest.TestCase):
    """Challenge MCUGuard with nested zip archives hiding MCU artifacts and scripts."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_multi_level_nested_zip_with_mcu_bin(self):
        """mcu.bin hidden two levels deep inside nested zip archives must be blocked."""
        inner_level2 = io.BytesIO()
        with zipfile.ZipFile(inner_level2, "w") as z2:
            z2.writestr("mcu.bin", b"MCU_MICROCODE_DATA")

        inner_level1 = io.BytesIO()
        with zipfile.ZipFile(inner_level1, "w") as z1:
            z1.writestr("subpackage.zip", inner_level2.getvalue())

        outer_path = os.path.join(self.tmpdir.name, "multi_nested.zip")
        with zipfile.ZipFile(outer_path, "w") as z0:
            z0.writestr("bundle.zip", inner_level1.getvalue())
            z0.writestr("system.img", b"ANDROID_SYSTEM")

        is_safe, viols = MCUGuard.scan_archive(outer_path, raise_on_violation=False)
        self.assertFalse(
            is_safe,
            "VULNERABILITY: Multi-level nested zip containing mcu.bin bypassed MCUGuard.scan_archive!",
        )

    def test_nested_zip_with_updater_script_mcu_flash(self):
        """An updater-script targeting MCU hidden inside a nested zip must be blocked."""
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w") as izf:
            izf.writestr(
                "META-INF/com/google/android/updater-script",
                'write_raw_image("/tmp/boot.img", "mcu");\n',
            )

        outer_path = os.path.join(self.tmpdir.name, "nested_script.zip")
        with zipfile.ZipFile(outer_path, "w") as ozf:
            ozf.writestr("firmware_package.zip", inner_buf.getvalue())
            ozf.writestr("system.img", b"ANDROID_SYSTEM")

        is_safe, viols = MCUGuard.scan_archive(outer_path, raise_on_violation=False)
        self.assertFalse(
            is_safe,
            "VULNERABILITY: updater-script inside nested zip targeting MCU bypassed MCUGuard.scan_archive!",
        )

    def test_nested_zip_with_cortex_m_binary(self):
        """A Cortex-M binary payload hidden inside a nested zip must be blocked."""
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w") as izf:
            izf.writestr("driver.bin", make_cortex_m_payload())

        outer_path = os.path.join(self.tmpdir.name, "nested_payload.zip")
        with zipfile.ZipFile(outer_path, "w") as ozf:
            ozf.writestr("drivers.zip", inner_buf.getvalue())

        is_safe, viols = MCUGuard.scan_archive(outer_path, raise_on_violation=False)
        self.assertFalse(
            is_safe,
            "VULNERABILITY: Cortex-M vector table inside nested zip bypassed MCUGuard.scan_archive!",
        )


class TestUpdaterScriptBypass(unittest.TestCase):
    """Challenge MCUGuard script parser with obfuscated commands, casing, and alternative UART paths."""

    def test_uart_case_variations_ttys0(self):
        """Lowercase /dev/ttys0 or uppercase /DEV/TTYS0 must be blocked."""
        script_lower = 'run_program("/sbin/sh", "-c", "cat payload > /dev/ttys0");\n'
        is_safe, viols = MCUGuard.check_script_content(script_lower, "updater-script")
        self.assertFalse(
            is_safe,
            "VULNERABILITY: /dev/ttys0 bypassed MCUGuard.check_script_content!",
        )

        script_upper = 'run_program("/sbin/sh", "-c", "cat payload > /dev/TTYS0");\n'
        is_safe2, viols2 = MCUGuard.check_script_content(script_upper, "updater-script")
        self.assertFalse(
            is_safe2,
            "VULNERABILITY: /dev/TTYS0 bypassed MCUGuard.check_script_content!",
        )

    def test_uart_ttyacm_case_variations(self):
        """Case variations of CDC ACM USB serial nodes must be blocked."""
        script = 'run_program("/sbin/sh", "-c", "echo fw > /dev/ttyacm0");\n'
        is_safe, viols = MCUGuard.check_script_content(script, "updater-script")
        self.assertFalse(
            is_safe,
            "VULNERABILITY: /dev/ttyacm0 bypassed MCUGuard.check_script_content!",
        )

    def test_uart_ttyusb_serial_nodes(self):
        """USB-to-UART bridge nodes /dev/ttyUSB0 must be blocked."""
        script = 'run_program("/sbin/sh", "-c", "cat fw > /dev/ttyUSB0");\n'
        is_safe, viols = MCUGuard.check_script_content(script, "updater-script")
        self.assertFalse(
            is_safe,
            "VULNERABILITY: /dev/ttyUSB0 bypassed MCUGuard.check_script_content!",
        )

    def test_partition_target_with_unwhitelisted_commands(self):
        """MCU partition write using commands not in the 5-item whitelist must be blocked."""
        # e.g., dd command without the word 'block'
        script_dd = 'run_program("/sbin/dd", "if=/tmp/fw", "of=/dev/mcu");\n'
        is_safe, viols = MCUGuard.check_script_content(script_dd, "updater-script")
        self.assertFalse(
            is_safe,
            "VULNERABILITY: dd targeting /dev/mcu bypassed MCUGuard.check_script_content!",
        )

        # flash_erase / nandwrite targeting mcu
        script_nand = 'run_program("/sbin/nandwrite", "-p", "mcu", "/tmp/fw");\n'
        is_safe2, viols2 = MCUGuard.check_script_content(script_nand, "updater-script")
        self.assertFalse(
            is_safe2,
            "VULNERABILITY: nandwrite targeting mcu partition bypassed MCUGuard.check_script_content!",
        )

    def test_mcu_dev_node_case_variation(self):
        """Uppercase /dev/MCU node must be blocked."""
        script = 'run_program("/sbin/sh", "-c", "echo data > /dev/MCU");\n'
        is_safe, viols = MCUGuard.check_script_content(script, "updater-script")
        self.assertFalse(
            is_safe,
            "VULNERABILITY: /dev/MCU bypassed MCUGuard.check_script_content!",
        )


class TestFilenameObfuscationAndUnicode(unittest.TestCase):
    """Challenge MCUGuard with Unicode normalization, homoglyphs, and traversal."""

    def test_unicode_fullwidth_mcu_bin(self):
        """Full-width Unicode characters ｍｃｕ.bin (NFKC normalizes to mcu.bin) must be blocked."""
        fullwidth_name = "\uff4d\uff43\uff55.bin"  # ｍｃｕ.bin
        self.assertTrue(
            MCUGuard.is_mcu_artifact(fullwidth_name),
            "VULNERABILITY: Unicode full-width 'ｍｃｕ.bin' bypassed MCUGuard.is_mcu_artifact!",
        )

    def test_trailing_dot_fat32_bypass(self):
        """Trailing dots stripped by FAT32 ('mcu.bin.') must be blocked."""
        self.assertTrue(
            MCUGuard.is_mcu_artifact("mcu.bin."),
            "VULNERABILITY: Trailing dot 'mcu.bin.' bypassed MCUGuard.is_mcu_artifact!",
        )

    def test_path_traversal_archive_entry(self):
        """Archive entry with path traversal escaping root must be blocked."""
        self.assertTrue(
            MCUGuard.is_mcu_artifact("../../../mcu.bin"),
            "VULNERABILITY: Path traversal '../../../mcu.bin' bypassed MCUGuard.is_mcu_artifact!",
        )


if __name__ == "__main__":
    unittest.main()
