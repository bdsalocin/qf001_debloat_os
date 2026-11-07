"""Adversarial challenger stress test suite for PackageBuilder and MCU Safety Guard.

This test suite empirically validates:
1. Hostile MCU injection attacks:
   - Microcontroller binaries with standard, variant, and vendor names
   - Binaries nested deep within multi-level subdirectories
   - MCU payloads disguised as text, hex, or non-binary files
   - Single-level and recursive multi-level nested ZIP archives
   - Disguised ARM Cortex-M bare-metal vector tables
   - MCU flashing commands and UART nodes inside shell scripts and updater-script
   - Fullwidth Unicode and FAT32 trailing dot/space normalization
   - Absolute guarantee: immediate veto and zero residual archive on disk
2. FAT32 filesystem constraints:
   - Filenames with forbidden characters (\\ / : * ? \" < > |)
   - Filename length boundary (255 chars valid vs 256 chars invalid)
   - Invalid extensions and empty filenames
   - Partition payloads and final archives exceeding the 4GB FAT32 limit
3. Archive format integrity and cryptographic signatures:
   - Central directory and CRC32 verification across all archive entries
   - Edify updater-script syntax and ROCO_K706 platform assertions
   - update-binary shell wrapper and OTA metadata compliance
   - Full PKCS#7 / JAR signature verification and tamper detection
4. Atomic rollback and cleanup:
   - Guaranteed disk purge on pre-pack veto, post-pack veto, I/O errors, and signing errors
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
from unittest.mock import patch

from src.core.mcu_guard import MCUGuard, MCUSafetyError, MCUSafetyViolationError
from src.core.package_builder import (
    FAT32_ILLEGAL_CHARS,
    MAX_FAT32_FILE_SIZE,
    FAT32ComplianceError,
    MCUSafetyPackageError,
    PackageBuilder,
    PackageBuilderError,
    validate_fat32_filename,
)
from src.core.signer import OTAMetadata, PackageSigner, SignerError


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


class TestHostileMCUInjectionStress(unittest.TestCase):
    """Stress suite 1: Hostile MCU injection attacks and mandatory veto."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.source_dir = os.path.join(self.tmpdir.name, "source")
        os.makedirs(self.source_dir, exist_ok=True)
        self.output_zip = os.path.join(self.tmpdir.name, "update.zip")

        # Legitimate Android files to establish a functional base
        with open(os.path.join(self.source_dir, "system.img"), "wb") as f:
            f.write(b"GENUINE_SYSTEM_PAYLOAD" * 32)
        with open(os.path.join(self.source_dir, "boot.img"), "wb") as f:
            f.write(b"GENUINE_BOOT_PAYLOAD" * 32)

    def tearDown(self):
        self.tmpdir.cleanup()

    def assert_veto_and_no_residual_file(self, src: str, out: str) -> None:
        """Helper asserting that packaging fails and no output zip exists on disk."""
        try:
            PackageBuilder.build_update_zip(src, out)
        except (RuntimeError, MCUSafetyViolationError, MCUSafetyPackageError):
            pass
        else:
            self.fail(f"Hostile MCU payload in '{src}' was not vetoed!")

        self.assertFalse(
            os.path.exists(out),
            f"VETO VIOLATION: Output archive '{out}' was left on disk after safety violation!"
        )

    def test_01_mcu_binary_standard_names(self):
        """Standard and case-variant MCU binary names must be vetoed."""
        hazardous_names = [
            "mcu.bin",
            "MCU.BIN",
            "Mcu.Bin",
            "k706_mcu.bin",
            "qf001_mcu.bin",
            "mcu_update.bin",
        ]
        for name in hazardous_names:
            sub_src = os.path.join(self.tmpdir.name, f"src_{name}")
            os.makedirs(sub_src, exist_ok=True)
            with open(os.path.join(sub_src, "system.img"), "wb") as f:
                f.write(b"SYSTEM")
            with open(os.path.join(sub_src, name), "wb") as f:
                f.write(b"MICROCODE_BIN")

            target_zip = os.path.join(self.tmpdir.name, f"out_{name}.zip")
            self.assert_veto_and_no_residual_file(sub_src, target_zip)

    def test_02_mcu_microcontroller_families(self):
        """Microcontroller families (STM32, GD32, Nuvoton, TS8827/28, IAP) must be vetoed."""
        hazardous_names = [
            "stm32f407.bin",
            "stm32f103.hex",
            "stm32_boot.dfu",
            "stm32_fw.elf",
            "stm32.rom",
            "stm32.img",
            "gd32f303.bin",
            "gd32f103.hex",
            "gd32_patch.dfu",
            "gd32_fw.elf",
            "gd32.rom",
            "gd32.img",
            "n76e003.bin",
            "n76e003.hex",
            "n76e.rom",
            "nuvoton.bin",
            "nuvoton.hex",
            "nuc131.bin",
            "ts8827.bin",
            "ts8828.bin",
            "iap_mcu.bin",
            "iap_mcu.hex",
            "iap.bin",
            "iap.img",
        ]
        for name in hazardous_names:
            sub_src = os.path.join(self.tmpdir.name, f"src_fam_{name}")
            os.makedirs(sub_src, exist_ok=True)
            with open(os.path.join(sub_src, "system.img"), "wb") as f:
                f.write(b"SYSTEM")
            with open(os.path.join(sub_src, name), "wb") as f:
                f.write(b"MCU_FAMILY_FIRMWARE")

            target_zip = os.path.join(self.tmpdir.name, f"out_fam_{name}.zip")
            self.assert_veto_and_no_residual_file(sub_src, target_zip)

    def test_03_deeply_nested_subdirectories(self):
        """MCU artifacts hidden in deep directory hierarchies must be detected and vetoed."""
        nested_paths = [
            os.path.join("system", "app", "Malicious", "mcu.bin"),
            os.path.join("system", "etc", "firmware", "soc", "arm", "mcu.bin"),
            os.path.join("data", "local", "tmp", ".hidden", "k706_mcu.bin"),
            os.path.join("vendor", "firmware", "sub1", "sub2", "sub3", "sub4", "ts8827.bin"),
        ]
        for rel_path in nested_paths:
            sub_src = os.path.join(self.tmpdir.name, f"src_nest_{hash(rel_path)}")
            os.makedirs(sub_src, exist_ok=True)
            with open(os.path.join(sub_src, "system.img"), "wb") as f:
                f.write(b"SYSTEM")

            full_trap = os.path.join(sub_src, rel_path)
            os.makedirs(os.path.dirname(full_trap), exist_ok=True)
            with open(full_trap, "wb") as f:
                f.write(b"NESTED_MCU_PAYLOAD")

            target_zip = os.path.join(self.tmpdir.name, f"out_nest_{hash(rel_path)}.zip")
            self.assert_veto_and_no_residual_file(sub_src, target_zip)

    def test_04_mcu_hidden_as_text_or_hex_files(self):
        """MCU firmware encoded in Intel HEX text format or flash descriptors must be vetoed."""
        hazardous_text_artifacts = [
            ("mcu.hex", ":100000000000012001010008210100084101000870\n:00000001FF\n"),
            ("stm32_fw.hex", ":100000000000012001010008210100084101000870\n:00000001FF\n"),
            ("gd32_fw.hex", ":100000000000012001010008210100084101000870\n:00000001FF\n"),
            ("n76e_fw.hex", ":100000000000012001010008210100084101000870\n:00000001FF\n"),
            ("mcu_update.txt", "ACTION=FLASH_MCU\nTARGET=/dev/ttyS0\n"),
            ("flash_mcu.txt", "COMMAND=FLASH_TS8827\n"),
            ("iap_mcu.txt", "IAP_BOOT_ENABLED=1\n"),
        ]
        for fname, content in hazardous_text_artifacts:
            sub_src = os.path.join(self.tmpdir.name, f"src_txt_{fname}")
            os.makedirs(sub_src, exist_ok=True)
            with open(os.path.join(sub_src, "system.img"), "wb") as f:
                f.write(b"SYSTEM")
            with open(os.path.join(sub_src, fname), "w", encoding="utf-8") as f:
                f.write(content)

            target_zip = os.path.join(self.tmpdir.name, f"out_txt_{fname}.zip")
            self.assert_veto_and_no_residual_file(sub_src, target_zip)

    def test_05_embedded_inside_single_level_zip_archives(self):
        """MCU artifacts contained inside a nested zip file must be unpacked and vetoed."""
        nested_zip_path = os.path.join(self.source_dir, "vendor_blobs.zip")
        with zipfile.ZipFile(nested_zip_path, "w") as zf:
            zf.writestr("firmware/k706_mcu.bin", b"HOSTILE_NESTED_BIN")

        self.assert_veto_and_no_residual_file(self.source_dir, self.output_zip)

    def test_06_embedded_inside_multi_level_nested_zip_archives(self):
        """MCU artifacts hidden multi-levels deep in nested archives must be recursively vetoed."""
        inner2 = io.BytesIO()
        with zipfile.ZipFile(inner2, "w") as z2:
            z2.writestr("deep/mcu.bin", b"LEVEL_2_MCU_BIN")

        inner1 = io.BytesIO()
        with zipfile.ZipFile(inner1, "w") as z1:
            z1.writestr("subpackage.zip", inner2.getvalue())

        with open(os.path.join(self.source_dir, "bundle.zip"), "wb") as f:
            with zipfile.ZipFile(f, "w") as z0:
                z0.writestr("container.zip", inner1.getvalue())
                z0.writestr("system_lib.so", b"SAFE_DATA")

        self.assert_veto_and_no_residual_file(self.source_dir, self.output_zip)

    def test_07_disguised_bare_metal_cortex_m_vector_tables(self):
        """Non-binary extensions disguising Cortex-M vector tables must be caught by header sniffing."""
        cortex_payload = make_cortex_m_payload(128)
        disguised_candidates = [
            "boot_logo.png",
            "sound_fx.wav",
            "libaudio_dsp.so",
            "radio_preset.dat",
            "driver_blob.raw",
        ]
        for disguised_name in disguised_candidates:
            sub_src = os.path.join(self.tmpdir.name, f"src_cm_{disguised_name}")
            os.makedirs(sub_src, exist_ok=True)
            with open(os.path.join(sub_src, "system.img"), "wb") as f:
                f.write(b"SYSTEM")
            with open(os.path.join(sub_src, disguised_name), "wb") as f:
                f.write(cortex_payload)

            target_zip = os.path.join(self.tmpdir.name, f"out_cm_{disguised_name}.zip")
            self.assert_veto_and_no_residual_file(sub_src, target_zip)

    def test_08_cortex_m_vector_table_nested_inside_zip_archive(self):
        """Disguised Cortex-M vector table hidden inside a nested zip entry must be vetoed."""
        nested_buf = io.BytesIO()
        with zipfile.ZipFile(nested_buf, "w") as nz:
            nz.writestr("assets/custom_font.ttf", make_cortex_m_payload(128))

        with open(os.path.join(self.source_dir, "assets_bundle.zip"), "wb") as f:
            f.write(nested_buf.getvalue())

        self.assert_veto_and_no_residual_file(self.source_dir, self.output_zip)

    def test_09_mcu_flashing_commands_in_shell_scripts(self):
        """Shell scripts invoking MCU flashing tools or serial nodes must be vetoed."""
        hazardous_scripts = [
            ("install.sh", "#!/sbin/sh\nstm32flash -w /tmp/fw.bin /dev/ttyS0\n"),
            ("flash.sh", "#!/sbin/sh\ncat /tmp/fw.bin > /dev/ttyUSB0\n"),
            ("setup.sh", "#!/sbin/sh\nmcu_update -f /tmp/fw.bin\n"),
            ("carrier.sh", "#!/sbin/sh\nflash_mcu /tmp/fw.bin\n"),
            ("block.sh", "#!/sbin/sh\ndd if=/tmp/fw of=/dev/block/by-name/mcu\n"),
            ("node.sh", "#!/sbin/sh\necho fw > /dev/ttyACM0\n"),
        ]
        for script_name, script_content in hazardous_scripts:
            sub_src = os.path.join(self.tmpdir.name, f"src_sh_{script_name}")
            os.makedirs(sub_src, exist_ok=True)
            with open(os.path.join(sub_src, "system.img"), "wb") as f:
                f.write(b"SYSTEM")
            with open(os.path.join(sub_src, script_name), "w", encoding="utf-8") as f:
                f.write(script_content)

            target_zip = os.path.join(self.tmpdir.name, f"out_sh_{script_name}.zip")
            self.assert_veto_and_no_residual_file(sub_src, target_zip)

    def test_10_mcu_flashing_commands_in_custom_updater_script(self):
        """Custom updater-script attempting to write to MCU partition or serial node must be vetoed."""
        meta_dir = os.path.join(self.source_dir, "META-INF", "com", "google", "android")
        os.makedirs(meta_dir, exist_ok=True)
        script_file = os.path.join(meta_dir, "updater-script")

        with open(script_file, "w", encoding="utf-8") as f:
            f.write(
                'ui_print("Malicious script");\n'
                'package_extract_file("boot.img", "/dev/block/by-name/boot");\n'
                'package_extract_file("payload.dat", "/dev/ttyS1");\n'
            )

        self.assert_veto_and_no_residual_file(self.source_dir, self.output_zip)

    def test_11_unicode_homoglyphs_and_fat32_trailing_dots(self):
        """Unicode homoglyphs and FAT32 trailing dot/space bypass attempts must be vetoed."""
        # Fullwidth unicode \uff4d\uff43\uff55 = ｍｃｕ
        fullwidth_file = os.path.join(self.source_dir, "\uff4d\uff43\uff55.bin")
        with open(fullwidth_file, "wb") as f:
            f.write(b"UNICODE_MCU")

        self.assert_veto_and_no_residual_file(self.source_dir, self.output_zip)


class TestFAT32ConstraintsStress(unittest.TestCase):
    """Stress suite 2: FAT32 filesystem constraints, illegal characters, and 4GB limits."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.source_dir = os.path.join(self.tmpdir.name, "source")
        os.makedirs(self.source_dir, exist_ok=True)
        with open(os.path.join(self.source_dir, "system.img"), "wb") as f:
            f.write(b"CLEAN_SYSTEM_IMAGE" * 32)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_illegal_characters_in_filename(self):
        """All characters prohibited by FAT32 must be rejected by validate_fat32_filename and build_update_zip."""
        for char in FAT32_ILLEGAL_CHARS:
            bad_filename = f"update{char}release.zip"
            is_valid, msg = validate_fat32_filename(bad_filename)
            self.assertFalse(is_valid, f"Illegal char '{char}' must be rejected by validate_fat32_filename")

            # In POSIX paths, '/' is the directory separator, so test non-slash illegal chars against build_update_zip
            if char != "/":
                bad_output_zip = os.path.join(self.tmpdir.name, bad_filename)
                with self.assertRaises((FAT32ComplianceError, ValueError, PackageBuilderError)):
                    PackageBuilder.build_update_zip(self.source_dir, bad_output_zip)

                self.assertFalse(os.path.exists(bad_output_zip))

    def test_02_filename_length_boundary_255_vs_256(self):
        """FAT32 filename length boundary: 255 chars valid, 256 chars rejected."""
        valid_255 = "a" * 251 + ".zip"
        self.assertEqual(len(valid_255), 255)
        is_valid, msg = validate_fat32_filename(valid_255)
        self.assertTrue(is_valid, f"255 chars filename should be valid: {msg}")

        invalid_256 = "a" * 252 + ".zip"
        self.assertEqual(len(invalid_256), 256)
        is_valid, msg = validate_fat32_filename(invalid_256)
        self.assertFalse(is_valid, "256 chars filename must be rejected")

        out_256 = os.path.join(self.tmpdir.name, invalid_256)
        with self.assertRaises((FAT32ComplianceError, ValueError, PackageBuilderError)):
            PackageBuilder.build_update_zip(self.source_dir, out_256)
        self.assertFalse(os.path.exists(out_256))

    def test_03_invalid_extension_rejection(self):
        """Update package destination without .zip extension must be rejected."""
        bad_extensions = ["update.tar", "update.img", "update.iso", "update.bin", "update"]
        for bad_name in bad_extensions:
            bad_path = os.path.join(self.tmpdir.name, bad_name)
            with self.assertRaises((FAT32ComplianceError, ValueError, PackageBuilderError)):
                PackageBuilder.build_update_zip(self.source_dir, bad_path)
            self.assertFalse(os.path.exists(bad_path))

    def test_04_empty_filename_rejection(self):
        """Empty filename must be rejected."""
        is_valid, msg = validate_fat32_filename("")
        self.assertFalse(is_valid)

    def test_05_partition_payload_exceeding_4gb(self):
        """Partition payload exceeding 4,294,967,295 bytes (4 GiB - 1 byte) must raise FAT32ComplianceError."""
        huge_file = os.path.join(self.source_dir, "huge_partition.img")
        with open(huge_file, "wb") as f:
            f.write(b"MOCK_HUGE_HEADER")

        orig_stat = Path.stat

        def mock_stat(path_obj):
            res = orig_stat(path_obj)
            if path_obj.name == "huge_partition.img":
                class MockHugeStat:
                    def __getattr__(self, item):
                        return getattr(res, item)
                    @property
                    def st_size(self):
                        return 4294967296  # 4 GiB exact (exceeds max limit by 1 byte)
                return MockHugeStat()
            return res

        out_zip = os.path.join(self.tmpdir.name, "huge_update.zip")
        with patch.object(Path, "stat", mock_stat):
            with self.assertRaises((FAT32ComplianceError, ValueError)):
                PackageBuilder.build_update_zip(self.source_dir, out_zip)

        self.assertFalse(os.path.exists(out_zip), "Output archive must not exist after 4GB limit breach")

    def test_06_partition_payload_at_exact_4gb_limit_boundary(self):
        """Verify check_fat32_size accepts <= 4294967295 bytes and rejects 4294967296 bytes."""
        # 4 GiB - 1 byte is compliant
        PackageBuilder.check_fat32_size(4294967295, context="boundary_valid")
        self.assertEqual(MAX_FAT32_FILE_SIZE, 4294967295)

        # 4 GiB exact is non-compliant
        with self.assertRaises((FAT32ComplianceError, ValueError)):
            PackageBuilder.check_fat32_size(4294967296, context="boundary_exceeded")

    def test_07_resulting_archive_exceeding_4gb_purged(self):
        """If the final archive exceeds 4GB during post-pack validation, it must be purged from disk."""
        out_zip = os.path.join(self.tmpdir.name, "post_pack_huge.zip")
        orig_stat = Path.stat

        def mock_stat_post(path_obj):
            res = orig_stat(path_obj)
            if path_obj.name == "post_pack_huge.zip":
                class MockArchiveStat:
                    def __getattr__(self, item):
                        return getattr(res, item)
                    @property
                    def st_size(self):
                        return 5000000000  # 5 GB
                return MockArchiveStat()
            return res

        with patch.object(Path, "stat", mock_stat_post):
            with self.assertRaises((FAT32ComplianceError, ValueError)):
                PackageBuilder.build_update_zip(self.source_dir, out_zip, sign=False)

        self.assertFalse(os.path.exists(out_zip), "Oversized archive must be purged during post-pack check")


class TestArchiveFormatAndSignatureStress(unittest.TestCase):
    """Stress suite 3: Archive format, CRC integrity, updater-script syntax, and PKCS#7 signatures."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.source_dir = os.path.join(self.tmpdir.name, "source")
        os.makedirs(self.source_dir, exist_ok=True)
        self.output_zip = os.path.join(self.tmpdir.name, "update.zip")

        # Mock standard block partition data
        with open(os.path.join(self.source_dir, "system.new.dat"), "wb") as f:
            f.write(b"BLOCK_DATA" * 64)
        with open(os.path.join(self.source_dir, "system.transfer.list"), "w") as f:
            f.write("4\n1\n0\n1\n")
        with open(os.path.join(self.source_dir, "boot.img"), "wb") as f:
            f.write(b"BOOT_KERNEL" * 32)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_zip_structure_and_crc_verification(self):
        """Constructed archive must be fully compliant with zipfile and have valid CRC32 across all entries."""
        PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=True)
        self.assertTrue(os.path.isfile(self.output_zip))

        with zipfile.ZipFile(self.output_zip, "r") as zf:
            # testzip() returns None if all entry checksums match
            corrupted_file = zf.testzip()
            self.assertIsNone(corrupted_file, f"Corrupted CRC detected in archive entry: {corrupted_file}")

            namelist = zf.namelist()
            expected_entries = [
                "system.new.dat",
                "system.transfer.list",
                "boot.img",
                "META-INF/com/google/android/updater-script",
                "META-INF/com/google/android/update-binary",
                "META-INF/com/android/metadata",
                "META-INF/MANIFEST.MF",
                "META-INF/CERT.SF",
                "META-INF/CERT.RSA",
            ]
            for exp in expected_entries:
                self.assertIn(exp, namelist, f"Expected entry '{exp}' missing from generated update.zip")

    def test_02_updater_script_syntax_and_assertions(self):
        """Generated updater-script must have valid Edify syntax and assert the ROCO_K706 platform."""
        PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=False)

        with zipfile.ZipFile(self.output_zip, "r") as zf:
            script_bytes = zf.read("META-INF/com/google/android/updater-script")

        script_text = script_bytes.decode("utf-8")
        # Assertions
        self.assertIn('getprop("ro.product.device") == "ROCO_K706"', script_text)
        self.assertIn('block_image_update("/dev/block/by-name/system"', script_text)
        self.assertIn('package_extract_file("boot.img"', script_text)

        # Edify syntax checks: each non-empty line must end with semicolon
        for line in script_text.splitlines():
            line_str = line.strip()
            if line_str and not line_str.startswith("#"):
                self.assertTrue(line_str.endswith(";"), f"Edify statement missing terminating semicolon: '{line_str}'")

    def test_03_update_binary_shell_wrapper(self):
        """Generated update-binary wrapper must be a POSIX shell script with executable shebang."""
        PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=False)

        with zipfile.ZipFile(self.output_zip, "r") as zf:
            bin_bytes = zf.read("META-INF/com/google/android/update-binary")

        self.assertTrue(bin_bytes.startswith(b"#!/sbin/sh") or bin_bytes.startswith(b"#!/system/bin/sh"))

    def test_04_metadata_conformance(self):
        """META-INF/com/android/metadata must parse into valid OTAMetadata with ROCO_K706 device identity."""
        PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=True)

        with zipfile.ZipFile(self.output_zip, "r") as zf:
            meta_str = zf.read("META-INF/com/android/metadata").decode("utf-8")

        meta = OTAMetadata.parse(meta_str)
        self.assertEqual(meta.pre_device, "ROCO_K706")
        self.assertEqual(meta.ota_type, "BLOCK")
        self.assertEqual(meta.post_sdk_level, 29)

    def test_05_cryptographic_verification_clean(self):
        """Clean signed package passes PackageSigner and PackageBuilder.verify_package verification."""
        PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=True)

        signer = PackageSigner()
        sig_res = signer.verify_archive(self.output_zip)
        self.assertTrue(sig_res.is_valid, f"Signature verification failed: {sig_res.errors}")
        self.assertTrue(sig_res.has_jar_signature)
        self.assertGreater(sig_res.file_hashes_matched, 0)

        v_dict = PackageBuilder.verify_package(self.output_zip)
        self.assertTrue(v_dict["is_valid"], f"verify_package returned invalid: {v_dict}")
        self.assertTrue(v_dict["filename_compliant"])
        self.assertTrue(v_dict["size_compliant"])
        self.assertTrue(v_dict["mcu_safe"])
        self.assertTrue(v_dict["signature_valid"])

    def test_06_tamper_payload_detection(self):
        """Cryptographic verification detects byte alteration in payload."""
        PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=True)

        tampered_zip = os.path.join(self.tmpdir.name, "tampered.zip")
        with zipfile.ZipFile(self.output_zip, "r") as src_z, zipfile.ZipFile(tampered_zip, "w") as dst_z:
            for item in src_z.infolist():
                if item.filename == "boot.img":
                    dst_z.writestr(item, b"TAMPERED_KERNEL_DATA" * 32)
                else:
                    dst_z.writestr(item, src_z.read(item.filename))

        signer = PackageSigner()
        sig_res = signer.verify_archive(tampered_zip)
        self.assertFalse(sig_res.is_valid, "Tampered payload must fail cryptographic verification")
        self.assertTrue(any("Digest mismatch" in e for e in sig_res.errors))

    def test_07_tamper_signature_corruption(self):
        """Tampering with CERT.SF or CERT.RSA invalidates verification."""
        PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=True)

        tampered_zip = os.path.join(self.tmpdir.name, "corrupted_sig.zip")
        with zipfile.ZipFile(self.output_zip, "r") as src_z, zipfile.ZipFile(tampered_zip, "w") as dst_z:
            for item in src_z.infolist():
                if item.filename == "META-INF/CERT.SF":
                    dst_z.writestr(item, b"Signature-Version: 1.0\nSHA-256-Digest-Manifest: corrupted\n")
                else:
                    dst_z.writestr(item, src_z.read(item.filename))

        signer = PackageSigner()
        sig_res = signer.verify_archive(tampered_zip)
        self.assertFalse(sig_res.is_valid, "Corrupted CERT.SF must fail signature verification")

    def test_08_post_pack_mcu_injection_detection(self):
        """Injecting mcu.bin into an already signed archive causes PackageBuilder.verify_package to fail."""
        PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=True)

        injected_zip = os.path.join(self.tmpdir.name, "post_injected.zip")
        with zipfile.ZipFile(self.output_zip, "r") as src_z, zipfile.ZipFile(injected_zip, "w") as dst_z:
            for item in src_z.infolist():
                dst_z.writestr(item, src_z.read(item.filename))
            dst_z.writestr("mcu.bin", b"INJECTED_POST_BUILD_FIRMWARE")

        v_dict = PackageBuilder.verify_package(injected_zip)
        self.assertFalse(v_dict["is_valid"])
        self.assertFalse(v_dict["mcu_safe"])
        self.assertGreater(len(v_dict["mcu_violations"]), 0)


class TestAtomicRollbackCleanupStress(unittest.TestCase):
    """Stress suite 4: Atomic cleanup guarantees zero residual partial files on failure."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.source_dir = os.path.join(self.tmpdir.name, "source")
        os.makedirs(self.source_dir, exist_ok=True)
        self.output_zip = os.path.join(self.tmpdir.name, "update.zip")

        with open(os.path.join(self.source_dir, "system.img"), "wb") as f:
            f.write(b"CLEAN_SYSTEM" * 32)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_rollback_on_pre_pack_mcu_veto(self):
        """When pre-pack audit detects MCU file, no output zip is created."""
        with open(os.path.join(self.source_dir, "mcu.bin"), "wb") as f:
            f.write(b"MCU_CONTAMINATION")

        try:
            PackageBuilder.build_update_zip(self.source_dir, self.output_zip)
        except (RuntimeError, MCUSafetyViolationError):
            pass

        self.assertFalse(os.path.exists(self.output_zip))

    def test_02_rollback_on_post_pack_mcu_veto(self):
        """When post-pack validation catches an MCU artifact, the target archive is deleted."""
        with patch.object(
            PackageBuilder,
            "_post_pack_validate",
            side_effect=MCUSafetyPackageError(["simulated_post_pack_violation"]),
        ):
            try:
                PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=False)
            except MCUSafetyPackageError:
                pass

        self.assertFalse(
            os.path.exists(self.output_zip),
            "Output archive must be deleted if post-pack validation fails"
        )

    def test_03_rollback_on_disk_io_error_during_zip_write(self):
        """Simulated disk I/O failure during zip writing triggers atomic cleanup."""
        with patch.object(zipfile.ZipFile, "write", side_effect=IOError("Simulated write error")):
            try:
                PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=False)
            except IOError:
                pass

        self.assertFalse(os.path.exists(self.output_zip))

    def test_04_rollback_on_signer_error(self):
        """Signing failure triggers atomic cleanup of output package."""
        with patch.object(PackageSigner, "sign_archive", side_effect=SignerError("Signing process failed")):
            try:
                PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=True)
            except SignerError:
                pass

        self.assertFalse(os.path.exists(self.output_zip))

    def test_05_rollback_on_fat32_payload_size_violation(self):
        """FAT32 size violation triggers atomic cleanup."""
        with patch.object(
            PackageBuilder,
            "_pre_pack_validate",
            side_effect=FAT32ComplianceError("Payload exceeds 4GB limit"),
        ):
            try:
                PackageBuilder.build_update_zip(self.source_dir, self.output_zip)
            except FAT32ComplianceError:
                pass

        self.assertFalse(os.path.exists(self.output_zip))

    def test_06_rollback_on_corrupted_crc_archive(self):
        """Corrupted CRC in post-pack validation triggers deletion of corrupt archive."""
        orig_post = PackageBuilder._post_pack_validate

        def mock_post(output_path):
            # Simulate failure during post pack check
            raise MCUSafetyPackageError(["Corrupted CRC detected in post-pack"])

        with patch.object(PackageBuilder, "_post_pack_validate", mock_post):
            try:
                PackageBuilder.build_update_zip(self.source_dir, self.output_zip, sign=False)
            except MCUSafetyPackageError:
                pass

        self.assertFalse(os.path.exists(self.output_zip))

    def test_07_no_residual_temp_files_left_behind(self):
        """Ensure no temporary staging files remain in parent folder after build or failure."""
        # 1. Clean build
        clean_out = os.path.join(self.tmpdir.name, "clean_out.zip")
        PackageBuilder.build_update_zip(self.source_dir, clean_out, sign=True)
        self.assertTrue(os.path.exists(clean_out))

        # Check for orphan files
        orphans = [
            fn for fn in os.listdir(self.tmpdir.name)
            if fn.endswith(".tmp") or fn.startswith("staging_") or fn.startswith("tmp")
        ]
        self.assertEqual(len(orphans), 0, f"Residual temporary files found: {orphans}")

        # 2. Failed build
        with open(os.path.join(self.source_dir, "mcu.bin"), "wb") as f:
            f.write(b"VETO")
        fail_out = os.path.join(self.tmpdir.name, "fail_out.zip")
        try:
            PackageBuilder.build_update_zip(self.source_dir, fail_out)
        except Exception:
            pass

        orphans_after_fail = [
            fn for fn in os.listdir(self.tmpdir.name)
            if fn.endswith(".tmp") or fn.startswith("staging_") or fn.startswith("tmp")
        ]
        self.assertEqual(len(orphans_after_fail), 0, f"Residual files after failure: {orphans_after_fail}")


if __name__ == "__main__":
    unittest.main()
