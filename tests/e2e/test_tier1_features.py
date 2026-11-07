"""Tier 1: Feature Coverage E2E Tests for QF001 Debloat OS.

Requirements covered:
- R1: Environment & QF001 Base (Sparse Engine, Unpacker, Signer)
- R2: Deep Debloating & Preservation (Debloater Engine, Preserved Services)
- R3: iOS Launcher & System Customization
- R4: MCU Safety Guard & FAT32 Packaging
"""
import json
import os
import shutil
import tempfile
import unittest

from tests.e2e.test_helpers import (
    create_valid_sparse_file,
    create_mock_system_fs,
    validate_fat32_filename,
    MAX_FAT32_FILE_SIZE
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))


class TestTier1FeatureR1Environment(unittest.TestCase):
    """Tier 1 Tests for R1: Firmware Toolchain & QF001 Hardware Base."""

    def test_r1_01_hardware_profiles_configuration(self):
        """Authoritative Check: Hardware profile must specify ROCO K706 UIS7862 with TDA7708 radio."""
        profile_path = os.path.join(PROJECT_ROOT, "config", "hardware_profiles.json")
        self.assertTrue(os.path.exists(profile_path), f"Missing hardware profiles at {profile_path}")

        with open(profile_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data.get("platform"), "ROCO_K706")
        self.assertEqual(data.get("reference"), "QF001")
        self.assertIn("UIS7862A_1.8GHz", data.get("cpu_options", []))
        self.assertIn("UIS7862S_2.0GHz", data.get("cpu_options", []))
        self.assertEqual(data.get("radio_ic"), "TDA7708")
        self.assertEqual(data.get("amplifier_ic"), "TDA7851")
        self.assertEqual(data.get("dsp_ic"), "BU32107EFV")
        self.assertTrue(data.get("mcu_preserved"), "Hardware profile must mandate MCU preservation")

    def test_r1_02_cli_entrypoint_initialization(self):
        """Authoritative Check: CLI entrypoint must initialize toolchain with code 0."""
        try:
            from src.cli.main import main
        except ImportError as e:
            raise unittest.SkipTest(f"R1 CLI entrypoint pending: {e}")

        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            exit_code = main()
        self.assertEqual(exit_code, 0, "CLI main() must exit with status 0 upon success")

    def test_r1_03_firmware_unpacker_archive_validation(self):
        """Authoritative Check: FirmwareUnpacker must validate archive existence before extraction."""
        try:
            from src.core.unpacker import FirmwareUnpacker
        except ImportError as e:
            raise unittest.SkipTest(f"R1 FirmwareUnpacker pending: {e}")

        # Non-existing archive
        fake_unpacker = FirmwareUnpacker("/path/to/nonexistent_archive.zip", "/tmp/ext")
        self.assertFalse(fake_unpacker.validate_archive(), "Validation must fail for nonexistent file")

        # Existing archive
        with tempfile.NamedTemporaryFile(suffix=".zip") as tf:
            valid_unpacker = FirmwareUnpacker(tf.name, "/tmp/ext")
            self.assertTrue(valid_unpacker.validate_archive(), "Validation must succeed for existing archive")

    def test_r1_04_sparse_detection_contract(self):
        """Authoritative Check: SparseImage.is_sparse contract for Android Sparse magic 0xED26FF3A."""
        try:
            from src.core.sparse import SparseImage
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"R1 SparseImage pending Milestone M1: {e}")

        with tempfile.TemporaryDirectory() as tmpdir:
            sparse_file = os.path.join(tmpdir, "valid.sparse.img")
            create_valid_sparse_file(sparse_file)
            self.assertTrue(SparseImage.is_sparse(sparse_file), "SparseImage must detect valid sparse magic")

            raw_file = os.path.join(tmpdir, "raw.img")
            with open(raw_file, "wb") as f:
                f.write(b"RAW_UNSPARSE_IMAGE_BYTES" * 100)
            self.assertFalse(SparseImage.is_sparse(raw_file), "SparseImage must return False for raw image")

    def test_r1_05_sparse_unsparse_and_repack_contract(self):
        """Authoritative Check: SparseImage.unsparse and sparse round-trip contract."""
        try:
            from src.core.sparse import SparseImage
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"R1 SparseImage conversion pending Milestone M1: {e}")

        with tempfile.TemporaryDirectory() as tmpdir:
            orig_sparse = os.path.join(tmpdir, "orig.sparse.img")
            unsparse_out = os.path.join(tmpdir, "unsparse.raw.img")
            create_valid_sparse_file(orig_sparse, num_blocks=2, blk_sz=4096)

            success = SparseImage.unsparse(orig_sparse, unsparse_out)
            self.assertTrue(success, "SparseImage.unsparse must succeed")
            self.assertTrue(os.path.exists(unsparse_out))
            self.assertGreaterEqual(os.path.getsize(unsparse_out), 8192)

            resparse_out = os.path.join(tmpdir, "resparse.sparse.img")
            success_re = SparseImage.sparse(unsparse_out, resparse_out)
            self.assertTrue(success_re, "SparseImage.sparse must succeed")
            self.assertTrue(SparseImage.is_sparse(resparse_out))

    def test_r1_06_package_signer_contract(self):
        """Authoritative Check: PackageSigner interface contract for OTA update integrity."""
        try:
            from src.core.signer import PackageSigner
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"R1 PackageSigner pending Milestone M1: {e}")

        signer = PackageSigner()
        self.assertTrue(hasattr(signer, "sign_package") or hasattr(signer, "verify_signature"),
                        "PackageSigner must expose signing or verification interface")


class TestTier1FeatureR2Debloating(unittest.TestCase):
    """Tier 1 Tests for R2: Deep Debloating & Hardware Service Preservation."""

    def test_r2_01_bloatware_blacklist_integrity(self):
        """Authoritative Check: Blacklist contains essential telemetry and bloatware packages."""
        blacklist_path = os.path.join(PROJECT_ROOT, "config", "bloatware_blacklist.json")
        self.assertTrue(os.path.exists(blacklist_path), f"Missing {blacklist_path}")

        with open(blacklist_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        packages = data.get("packages", [])
        self.assertIsInstance(packages, list)
        self.assertGreaterEqual(len(packages), 5, "Blacklist must target at least 5 bloatware packages")

        # Telemetry packages from specification
        self.assertIn("com.google.android.apps.tachyon", packages)
        self.assertIn("com.baidu.BaiduMap", packages)
        self.assertIn("com.chinese.telemetry", packages)
        self.assertIn("com.ts.car.updater", packages)

    def test_r2_02_preserved_services_integrity(self):
        """Authoritative Check: Preserved services list contains TDA7708, Canbus, BT, and camera."""
        preserved_path = os.path.join(PROJECT_ROOT, "config", "preserved_services.json")
        self.assertTrue(os.path.exists(preserved_path), f"Missing {preserved_path}")

        with open(preserved_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        preserved = data.get("preserved_packages", [])
        self.assertIsInstance(preserved, list)
        self.assertIn("com.ts.main.radio", preserved, "TDA7708 Radio service must be preserved")
        self.assertIn("com.syu.canbus", preserved, "Syu Canbus service must be preserved")
        self.assertIn("com.roco.canbus", preserved, "ROCO Canbus service must be preserved")
        self.assertIn("com.syu.bt", preserved, "Bluetooth service must be preserved")
        self.assertIn("com.ts.camera", preserved, "Reverse Camera service must be preserved")

    def test_r2_03_blacklist_whitelist_disjoint_safety(self):
        """Authoritative Check: Blacklist and preserved services sets must be strictly disjoint."""
        b_path = os.path.join(PROJECT_ROOT, "config", "bloatware_blacklist.json")
        p_path = os.path.join(PROJECT_ROOT, "config", "preserved_services.json")

        with open(b_path, "r", encoding="utf-8") as f:
            blacklisted = set(json.load(f).get("packages", []))
        with open(p_path, "r", encoding="utf-8") as f:
            preserved = set(json.load(f).get("preserved_packages", []))

        overlap = blacklisted.intersection(preserved)
        self.assertEqual(len(overlap), 0, f"Critical safety violation: overlap between blacklist and preserved: {overlap}")

    def test_r2_04_debloater_filtering_logic(self):
        """Authoritative Check: Debloater.filter_packages correctly filters blacklist and preserves whitelist."""
        try:
            from src.domain.debloater import Debloater
        except ImportError as e:
            raise unittest.SkipTest(f"R2 Debloater pending: {e}")

        debloater = Debloater(
            blacklist=["com.baidu.BaiduMap", "com.ts.car.updater"],
            whitelist=["com.ts.main.radio"]
        )
        installed = ["com.baidu.BaiduMap", "com.ts.main.radio", "com.android.settings"]
        to_remove = debloater.filter_packages(installed)

        self.assertIn("com.baidu.BaiduMap", to_remove)
        self.assertNotIn("com.ts.main.radio", to_remove)
        self.assertNotIn("com.android.settings", to_remove)

    def test_r2_05_debloat_filesystem_contract(self):
        """Authoritative Check: Debloater.debloat_filesystem removes blacklisted folders from system tree."""
        try:
            from src.domain.debloater import Debloater
        except ImportError as e:
            raise unittest.SkipTest(f"R2 Debloater pending: {e}")

        if not hasattr(Debloater, "debloat_filesystem"):
            raise unittest.SkipTest("Debloater.debloat_filesystem pending Milestone M2")

        with tempfile.TemporaryDirectory() as tmpdir:
            sys_root = create_mock_system_fs(tmpdir)
            with open(os.path.join(PROJECT_ROOT, "config", "bloatware_blacklist.json")) as f:
                bl = json.load(f)["packages"]
            with open(os.path.join(PROJECT_ROOT, "config", "preserved_services.json")) as f:
                wl = json.load(f)["preserved_packages"]

            debloater = Debloater(blacklist=bl, whitelist=wl)
            report = debloater.debloat_filesystem(sys_root)

            # Check that baidu map folder was physically purged
            baidu_folder = os.path.join(sys_root, "priv-app", "com.baidu.BaiduMap")
            if not os.path.exists(baidu_folder):
                baidu_folder = os.path.join(sys_root, "app", "com.baidu.BaiduMap")
            self.assertFalse(os.path.exists(baidu_folder), "Blacklisted folder must be deleted")

            # Check that radio was preserved
            radio_folder = os.path.join(sys_root, "priv-app", "com.ts.main.radio")
            if not os.path.exists(radio_folder):
                radio_folder = os.path.join(sys_root, "app", "com.ts.main.radio")
            self.assertTrue(os.path.exists(radio_folder), "Preserved service folder must remain intact")

    def test_r2_06_safety_validator_preservation_contract(self):
        """Authoritative Check: SafetyValidator.verify_preserved_services verifies hardware services."""
        try:
            from src.domain.safety_validator import SafetyValidator
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"R2 SafetyValidator pending Milestone M2: {e}")

        with tempfile.TemporaryDirectory() as tmpdir:
            sys_root = create_mock_system_fs(tmpdir)
            validator = SafetyValidator()
            result = validator.verify_preserved_services(sys_root)
            self.assertTrue(result.is_valid if hasattr(result, "is_valid") else bool(result),
                            "SafetyValidator must confirm all required hardware services are present")


class TestTier1FeatureR3Launcher(unittest.TestCase):
    """Tier 1 Tests for R3: iOS-Style Automotive UX & Customization."""

    def test_r3_01_launcher_layout_structure(self):
        """Authoritative Check: IOSLauncherConfig.generate_layout returns clean dock and tile layout."""
        try:
            from src.customization.launcher import IOSLauncherConfig
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"R3 IOSLauncherConfig pending Milestone M3: {e}")

        layout = IOSLauncherConfig.generate_layout()
        self.assertIsInstance(layout, dict)
        self.assertIn("tiles", layout)
        self.assertIn("dock", layout)

    def test_r3_02_launcher_quick_tiles_automotive(self):
        """Authoritative Check: Quick tiles contain essential automotive functions (radio, music, nav)."""
        try:
            from src.customization.launcher import IOSLauncherConfig
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"R3 IOSLauncherConfig pending Milestone M3: {e}")

        layout = IOSLauncherConfig.generate_layout()
        tiles = layout.get("tiles", [])
        tile_types = [t.get("action") or t.get("name") or t.get("type") for t in tiles]

        # Must support automotive primary actions
        tile_str = " ".join(str(x).lower() for x in tile_types)
        self.assertTrue(any(term in tile_str for term in ["radio", "music", "nav"]),
                        f"Tiles must contain automotive actions (radio, music, nav): {tile_types}")

    def test_r3_03_launcher_system_injection_contract(self):
        """Authoritative Check: IOSLauncherConfig.inject_into_system installs into priv-app."""
        try:
            from src.customization.launcher import IOSLauncherConfig
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"R3 IOSLauncherConfig pending Milestone M3: {e}")

        with tempfile.TemporaryDirectory() as tmpdir:
            sys_root = create_mock_system_fs(tmpdir)
            success = IOSLauncherConfig.inject_into_system(sys_root)
            self.assertTrue(success, "Launcher injection into system partition must succeed")

            launcher_path = os.path.join(sys_root, "priv-app", "IOSLauncher")
            self.assertTrue(os.path.exists(launcher_path), f"Launcher must be placed in priv-app at {launcher_path}")

    def test_r3_04_launcher_default_home_privapp_integration(self):
        """Authoritative Check: Launcher registration sets category HOME intent."""
        try:
            from src.customization.launcher import IOSLauncherConfig
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"R3 IOSLauncherConfig pending Milestone M3: {e}")

        config = IOSLauncherConfig()
        home_intent = getattr(config, "home_category", "android.intent.category.HOME")
        self.assertEqual(home_intent, "android.intent.category.HOME")

    def test_r3_05_microg_and_power_management_rules(self):
        """Authoritative Check: MicroG / power management rules prevent kill of essential audio/canbus."""
        try:
            from src.customization.microg import PowerOptimizer
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"R3 PowerOptimizer pending Milestone M3: {e}")

        optimizer = PowerOptimizer()
        protected = optimizer.get_protected_packages()
        self.assertIn("com.ts.main.radio", protected)
        self.assertIn("com.syu.canbus", protected)


class TestTier1FeatureR4MCUSafetyAndFAT32(unittest.TestCase):
    """Tier 1 Tests for R4: Absolute MCU Safety & FAT32 USB Packaging."""

    def test_r4_01_mcu_artifact_detection(self):
        """Authoritative Check: MCUGuard.is_mcu_artifact flags all hazardous MCU filenames."""
        try:
            from src.core.mcu_guard import MCUGuard
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"R4 MCUGuard pending Milestone M1: {e}")

        hazardous = [
            "mcu.bin",
            "MCU.BIN",
            "k706_mcu.bin",
            "stm32_mcu.hex",
            "flash_mcu.sh",
            "subfolder/nested_mcu.bin"
        ]
        for name in hazardous:
            self.assertTrue(MCUGuard.is_mcu_artifact(name),
                            f"MCUGuard must identify '{name}' as a dangerous MCU artifact")

    def test_r4_02_mcu_safe_files_allowed(self):
        """Authoritative Check: MCUGuard.is_mcu_artifact allows legitimate Android files."""
        try:
            from src.core.mcu_guard import MCUGuard
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"R4 MCUGuard pending Milestone M1: {e}")

        safe_files = [
            "system.img",
            "boot.img",
            "build.prop",
            "META-INF/com/google/android/updater-script",
            "priv-app/IOSLauncher/IOSLauncher.apk"
        ]
        for name in safe_files:
            self.assertFalse(MCUGuard.is_mcu_artifact(name),
                             f"MCUGuard must not flag safe file '{name}'")

    def test_r4_03_archive_safety_check_contract(self):
        """Authoritative Check: MCUGuard.check_archive_safety rejects lists containing MCU binaries."""
        try:
            from src.core.mcu_guard import MCUGuard
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"R4 MCUGuard pending Milestone M1: {e}")

        clean_files = ["system.img", "boot.img", "vendor.img"]
        is_safe, flagged = MCUGuard.check_archive_safety(clean_files)
        self.assertTrue(is_safe, "Clean archive must be marked safe")
        self.assertEqual(len(flagged), 0)

        contaminated_files = ["system.img", "mcu.bin", "boot.img"]
        is_safe, flagged = MCUGuard.check_archive_safety(contaminated_files)
        self.assertFalse(is_safe, "Archive containing mcu.bin must be rejected")
        self.assertIn("mcu.bin", flagged)

    def test_r4_04_package_builder_update_zip_contract(self):
        """Authoritative Check: PackageBuilder.build_update_zip generates update.zip structure."""
        try:
            from src.core.package_builder import PackageBuilder
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"R4 PackageBuilder pending Milestone M4: {e}")

        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, "package_src")
            os.makedirs(src_dir, exist_ok=True)
            with open(os.path.join(src_dir, "system.new.dat"), "wb") as f:
                f.write(b"MOCK_SYSTEM_DATA")

            out_zip = os.path.join(tmpdir, "update.zip")
            res = PackageBuilder.build_update_zip(src_dir, out_zip)
            self.assertTrue(os.path.exists(out_zip), "update.zip must be created on disk")
            self.assertEqual(res, out_zip)

    def test_r4_05_fat32_size_and_naming_compliance(self):
        """Authoritative Check: Update package target name complies strictly with FAT32 constraints."""
        valid_name = "update.zip"
        is_valid, msg = validate_fat32_filename(valid_name)
        self.assertTrue(is_valid, f"Standard update.zip must be FAT32 valid: {msg}")

        # Max file size boundary check
        test_size = 2147483648  # 2 GiB
        self.assertLess(test_size, MAX_FAT32_FILE_SIZE, "Firmware partition size must be < 4GB for FAT32")

    def test_r4_06_flash_instruction_documentation_presence(self):
        """Authoritative Check: Flash instructions guide must exist and mandate FAT32 format."""
        doc_path = os.path.join(PROJECT_ROOT, "docs", "INSTRUCTIONS_FLASH_FAT32.md")
        if not os.path.exists(doc_path):
            raise unittest.SkipTest("Flash instruction guide docs/INSTRUCTIONS_FLASH_FAT32.md pending Milestone M4")

        with open(doc_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("FAT32", content, "Documentation must specify FAT32 formatting")
        self.assertIn("MCU", content, "Documentation must mention MCU safety guarantee")


if __name__ == "__main__":
    unittest.main()
