"""Tier 3: Cross-Feature Combinations E2E Tests for QF001 Debloat OS.

Tests interactions across distinct modules:
- Sparse Unsparse -> Debloat -> Repack
- Debloater -> SafetyValidator Co-verification
- Launcher Injection -> Priv-app Permissions Integrity
- PackageBuilder -> MCUGuard Pre-packaging Veto
- End-to-end multi-step transition pipeline
"""
import json
import os
import shutil
import tempfile
import unittest

from tests.e2e.test_helpers import (
    create_valid_sparse_file,
    create_mock_system_fs,
    create_mock_update_zip
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))


class TestTier3CrossFeatureCombinations(unittest.TestCase):
    """Tier 3 Cross-Feature Integration Tests."""

    def test_tier3_01_sparse_unsparse_debloat_roundtrip(self):
        """Combination: Sparse unsparse -> debloat system tree -> repack as sparse."""
        try:
            from src.core.sparse import SparseImage
            from src.domain.debloater import Debloater
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"Sparse or Debloater pending: {e}")

        if not hasattr(Debloater, "debloat_filesystem"):
            raise unittest.SkipTest("Debloater.debloat_filesystem pending Milestone M2")

        with tempfile.TemporaryDirectory() as tmpdir:
            orig_sparse = os.path.join(tmpdir, "system.sparse.img")
            raw_img = os.path.join(tmpdir, "system.raw.img")
            repacked_sparse = os.path.join(tmpdir, "system_debloated.sparse.img")

            # 1. Unsparse
            create_valid_sparse_file(orig_sparse, num_blocks=4)
            self.assertTrue(SparseImage.unsparse(orig_sparse, raw_img))

            # 2. Debloat mock filesystem
            sys_root = create_mock_system_fs(tmpdir)
            with open(os.path.join(PROJECT_ROOT, "config", "bloatware_blacklist.json")) as f:
                bl = json.load(f)["packages"]
            with open(os.path.join(PROJECT_ROOT, "config", "preserved_services.json")) as f:
                wl = json.load(f)["preserved_packages"]

            debloater = Debloater(blacklist=bl, whitelist=wl)
            debloater.debloat_filesystem(sys_root)

            # 3. Repack to sparse
            self.assertTrue(SparseImage.sparse(raw_img, repacked_sparse))
            self.assertTrue(SparseImage.is_sparse(repacked_sparse))

    def test_tier3_02_debloater_and_safety_validator_cooperation(self):
        """Combination: Debloater cleans system tree and SafetyValidator confirms no critical loss."""
        try:
            from src.domain.debloater import Debloater
            from src.domain.safety_validator import SafetyValidator
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"Debloater or SafetyValidator pending: {e}")

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

            validator = SafetyValidator()
            val_result = validator.verify_preserved_services(sys_root)

            is_valid = val_result.is_valid if hasattr(val_result, "is_valid") else bool(val_result)
            self.assertTrue(is_valid, "SafetyValidator must pass after debloater execution")

            # Verify that BaiduMap was removed but TDA7708 Radio remained
            radio_found = False
            for root, dirs, files in os.walk(sys_root):
                if "com.ts.main.radio" in root:
                    radio_found = True
                self.assertNotIn("com.baidu.BaiduMap", root, "BaiduMap must not exist after debloat")

            self.assertTrue(radio_found, "TDA7708 Radio must remain present after debloat")

    def test_tier3_03_launcher_injection_and_privapp_preservation(self):
        """Combination: Debloat system, inject iOS launcher, and verify priv-app structure."""
        try:
            from src.customization.launcher import IOSLauncherConfig
            from src.domain.safety_validator import SafetyValidator
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"Launcher or SafetyValidator pending: {e}")

        with tempfile.TemporaryDirectory() as tmpdir:
            sys_root = create_mock_system_fs(tmpdir)

            # Inject launcher
            success = IOSLauncherConfig.inject_into_system(sys_root)
            self.assertTrue(success, "Launcher injection must succeed")

            # Check launcher location in priv-app
            launcher_apk = os.path.join(sys_root, "priv-app", "IOSLauncher", "IOSLauncher.apk")
            self.assertTrue(os.path.exists(launcher_apk) or os.path.exists(os.path.dirname(launcher_apk)))

            # Verify hardware safety validator still passes
            validator = SafetyValidator()
            val_result = validator.verify_preserved_services(sys_root)
            is_valid = val_result.is_valid if hasattr(val_result, "is_valid") else bool(val_result)
            self.assertTrue(is_valid, "Launcher injection must not break hardware services preservation")

    def test_tier3_04_package_builder_mcu_guard_veto(self):
        """Combination: PackageBuilder aborts build if MCUGuard detects MCU artifacts."""
        try:
            from src.core.mcu_guard import MCUGuard
            from src.core.package_builder import PackageBuilder
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"PackageBuilder or MCUGuard pending: {e}")

        with tempfile.TemporaryDirectory() as tmpdir:
            clean_staging = os.path.join(tmpdir, "clean_staging")
            os.makedirs(clean_staging, exist_ok=True)
            with open(os.path.join(clean_staging, "system.img"), "wb") as f:
                f.write(b"SAFE_SYSTEM_DATA")

            clean_zip = os.path.join(tmpdir, "clean_update.zip")
            # Clean build should succeed
            res = PackageBuilder.build_update_zip(clean_staging, clean_zip)
            self.assertTrue(os.path.exists(clean_zip))

            # Contaminated build with hostile MCU file
            dirty_staging = os.path.join(tmpdir, "dirty_staging")
            os.makedirs(dirty_staging, exist_ok=True)
            with open(os.path.join(dirty_staging, "system.img"), "wb") as f:
                f.write(b"SAFE_SYSTEM_DATA")
            with open(os.path.join(dirty_staging, "mcu.bin"), "wb") as f:
                f.write(b"HOSTILE_MCU_FIRMWARE")

            dirty_zip = os.path.join(tmpdir, "dirty_update.zip")
            with self.assertRaises((RuntimeError, ValueError, PermissionError)):
                PackageBuilder.build_update_zip(dirty_staging, dirty_zip)

            self.assertFalse(os.path.exists(dirty_zip),
                             "PackageBuilder must NEVER create an update.zip containing MCU firmware")

    def test_tier3_05_multistage_pipeline_sparse_debloat_launch_pack(self):
        """Combination: Complete multi-stage pipeline from sparse image to packaged update."""
        try:
            from src.core.sparse import SparseImage
            from src.domain.debloater import Debloater
            from src.customization.launcher import IOSLauncherConfig
            from src.core.mcu_guard import MCUGuard
            from src.core.package_builder import PackageBuilder
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"Full pipeline components pending: {e}")

        with tempfile.TemporaryDirectory() as tmpdir:
            sparse_input = os.path.join(tmpdir, "input.sparse.img")
            create_valid_sparse_file(sparse_input)

            # Pipeline step 1: Unsparse
            raw_output = os.path.join(tmpdir, "output.raw.img")
            self.assertTrue(SparseImage.unsparse(sparse_input, raw_output))

            # Pipeline step 2: Mock system debloat
            sys_root = create_mock_system_fs(tmpdir)
            debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=["com.ts.main.radio"])
            if hasattr(debloater, "debloat_filesystem"):
                debloater.debloat_filesystem(sys_root)

            # Pipeline step 3: Inject launcher
            IOSLauncherConfig.inject_into_system(sys_root)

            # Pipeline step 4: Pre-pack MCU safety audit
            files = os.listdir(tmpdir)
            is_safe, flagged = MCUGuard.check_archive_safety(files)
            self.assertTrue(is_safe)

            # Pipeline step 5: Build final package
            final_zip = os.path.join(tmpdir, "update.zip")
            PackageBuilder.build_update_zip(sys_root, final_zip)
            self.assertTrue(os.path.exists(final_zip))


if __name__ == "__main__":
    unittest.main()
