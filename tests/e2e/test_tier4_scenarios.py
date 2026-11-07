"""Tier 4: Real-World Scenarios E2E Tests for QF001 Debloat OS.

Simulates complete production automotive deployment workloads:
- Scenario 1: Standard Stock QF001 UIS7862 full lifecycle to signed FAT32 update.zip
- Scenario 2: Aggressive telemetry & background logger purge with TDA7708 integrity
- Scenario 3: Hostile MCU microcode tamper containment and rejection
- Scenario 4: FAT32 USB flash deployment readiness & constraints
- Scenario 5: First-boot automotive UX readiness & launcher integration
"""
import json
import os
import shutil
import tempfile
import unittest
import zipfile

from tests.e2e.test_helpers import (
    create_valid_sparse_file,
    create_mock_system_fs,
    create_mock_update_zip,
    validate_fat32_filename,
    MAX_FAT32_FILE_SIZE
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))


class TestTier4RealWorldScenarios(unittest.TestCase):
    """Tier 4 Real-World Automotive Production Scenarios."""

    def test_scenario_01_standard_qf001_full_lifecycle(self):
        """Scenario 1: Complete end-to-end pipeline run from mock ROM to signed FAT32 update.zip."""
        try:
            from src.core.sparse import SparseImage
            from src.domain.debloater import Debloater
            from src.domain.safety_validator import SafetyValidator
            from src.customization.launcher import IOSLauncherConfig
            from src.core.mcu_guard import MCUGuard
            from src.core.package_builder import PackageBuilder
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"Full pipeline components pending: {e}")

        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Setup mock incoming stock ROM
            rom_dir = os.path.join(tmpdir, "stock_rom")
            os.makedirs(rom_dir, exist_ok=True)
            sparse_sys = os.path.join(rom_dir, "system.img")
            create_valid_sparse_file(sparse_sys, num_blocks=4)

            # 2. Unpack & unsparse
            extracted_dir = os.path.join(tmpdir, "extracted")
            raw_sys = os.path.join(extracted_dir, "system.raw.img")
            os.makedirs(extracted_dir, exist_ok=True)
            self.assertTrue(SparseImage.unsparse(sparse_sys, raw_sys))

            # 3. Debloat system tree
            sys_fs = create_mock_system_fs(extracted_dir)
            with open(os.path.join(PROJECT_ROOT, "config", "bloatware_blacklist.json")) as f:
                bl = json.load(f)["packages"]
            with open(os.path.join(PROJECT_ROOT, "config", "preserved_services.json")) as f:
                wl = json.load(f)["preserved_packages"]

            debloater = Debloater(blacklist=bl, whitelist=wl)
            if hasattr(debloater, "debloat_filesystem"):
                debloater.debloat_filesystem(sys_fs)

            # 4. Validate hardware preservation
            validator = SafetyValidator()
            val_result = validator.verify_preserved_services(sys_fs)
            is_valid = val_result.is_valid if hasattr(val_result, "is_valid") else bool(val_result)
            self.assertTrue(is_valid, "Preserved hardware services must remain intact")

            # 5. Inject iOS-style launcher
            self.assertTrue(IOSLauncherConfig.inject_into_system(sys_fs))

            # 6. Pre-pack MCU safety audit
            files_to_pack = []
            for root, _, filenames in os.walk(extracted_dir):
                for fn in filenames:
                    files_to_pack.append(os.path.relpath(os.path.join(root, fn), extracted_dir))

            is_safe, flagged = MCUGuard.check_archive_safety(files_to_pack)
            self.assertTrue(is_safe, f"MCU guard flagged files in clean ROM: {flagged}")
            self.assertEqual(len(flagged), 0)

            # 7. Package update.zip for FAT32 USB
            output_zip = os.path.join(tmpdir, "update.zip")
            PackageBuilder.build_update_zip(extracted_dir, output_zip)

            self.assertTrue(os.path.exists(output_zip))
            # Verify zero MCU files inside update.zip
            with zipfile.ZipFile(output_zip, "r") as zf:
                archive_names = zf.namelist()
                for name in archive_names:
                    self.assertFalse(MCUGuard.is_mcu_artifact(name),
                                     f"Critical failure: {name} found inside output update.zip!")

    def test_scenario_02_aggressive_telemetry_purge(self):
        """Scenario 2: Purge aggressive telemetry while preserving TDA7708 radio and BU32107EFV DSP."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sys_fs = create_mock_system_fs(tmpdir)

            with open(os.path.join(PROJECT_ROOT, "config", "bloatware_blacklist.json")) as f:
                bl = json.load(f)["packages"]
            with open(os.path.join(PROJECT_ROOT, "config", "preserved_services.json")) as f:
                wl = json.load(f)["preserved_packages"]

            try:
                from src.domain.debloater import Debloater
                debloater = Debloater(blacklist=bl, whitelist=wl)
            except ImportError as e:
                raise unittest.SkipTest(f"Debloater pending: {e}")

            if hasattr(debloater, "debloat_filesystem"):
                debloater.debloat_filesystem(sys_fs)

                # Check removal of Chinese telemetry
                telemetry_path = os.path.join(sys_fs, "priv-app", "com.chinese.telemetry")
                self.assertFalse(os.path.exists(telemetry_path), "com.chinese.telemetry must be purged")

            # Check build.prop preservation
            build_prop = os.path.join(sys_fs, "build.prop")
            self.assertTrue(os.path.exists(build_prop))
            with open(build_prop, "r", encoding="utf-8") as f:
                prop_data = f.read()
            self.assertIn("TDA7708", prop_data, "TDA7708 tuner definition in build.prop must be preserved")
            self.assertIn("BU32107EFV", prop_data, "DSP definition in build.prop must be preserved")

    def test_scenario_03_hostile_mcu_tamper_containment(self):
        """Scenario 3: Hostile/contaminated MCU firmware injection is intercepted and quarantined."""
        try:
            from src.core.mcu_guard import MCUGuard
            from src.core.package_builder import PackageBuilder
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"MCUGuard or PackageBuilder pending: {e}")

        with tempfile.TemporaryDirectory() as tmpdir:
            tainted_root = os.path.join(tmpdir, "tainted_firmware")
            create_mock_system_fs(tainted_root)

            # Malicious/hazardous MCU file injected by untrusted source
            mcu_trap = os.path.join(tainted_root, "system", "etc", "mcu.bin")
            with open(mcu_trap, "wb") as f:
                f.write(b"HAZARDOUS_MCU_MICROCODE_THAT_WOULD_BRICK_SOUND")

            out_zip = os.path.join(tmpdir, "update.zip")

            with self.assertRaises((RuntimeError, ValueError, PermissionError)):
                PackageBuilder.build_update_zip(tainted_root, out_zip)

            self.assertFalse(os.path.exists(out_zip),
                             "Pipeline must abort immediately with NO output archive if MCU file is detected")

    def test_scenario_04_fat32_usb_deployment_readiness(self):
        """Scenario 4: Verify update package complies with FAT32 USB filesystem constraints."""
        target_filename = "update.zip"
        is_valid, msg = validate_fat32_filename(target_filename)
        self.assertTrue(is_valid, f"Target update filename must be FAT32 compliant: {msg}")

        # Check flash instructions exist
        doc_path = os.path.join(PROJECT_ROOT, "docs", "INSTRUCTIONS_FLASH_FAT32.md")
        if not os.path.exists(doc_path):
            raise unittest.SkipTest("Flash instruction guide docs/INSTRUCTIONS_FLASH_FAT32.md pending Milestone M4")

        with open(doc_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("FAT32", content)
        self.assertIn("USB", content)

    def test_scenario_05_launcher_first_boot_readiness(self):
        """Scenario 5: First-boot automotive UX layout validation."""
        try:
            from src.customization.launcher import IOSLauncherConfig
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"IOSLauncherConfig pending Milestone M3: {e}")

        layout = IOSLauncherConfig.generate_layout()
        self.assertIn("dock", layout)
        self.assertIn("tiles", layout)
        # Verify clean automotive essentials
        dock_items = layout.get("dock", [])
        self.assertGreaterEqual(len(dock_items), 2, "Dock must have at least 2 primary shortcuts")


if __name__ == "__main__":
    unittest.main()
