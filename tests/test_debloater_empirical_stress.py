"""Empirical stress test suite for Debloater engine (src/domain/debloater.py).

Verifies synthetic edge cases, permissions, whitelist collisions,
deeply nested folder structures, and DebloatReport metrics accuracy.
"""

import json
import os
import shutil
import stat
import tempfile
import unittest

from src.domain.debloater import Debloater, DebloatReport
from src.domain.safety_validator import SafetyValidator


class TestDebloaterEmpiricalStress(unittest.TestCase):
    """Adversarial stress-testing of Debloater filesystem engine."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = os.path.join(self.tmpdir.name, "system")
        os.makedirs(os.path.join(self.sys_root, "app"), exist_ok=True)
        os.makedirs(os.path.join(self.sys_root, "priv-app"), exist_ok=True)

    def tearDown(self):
        # Restore any modified permissions to allow clean teardown
        for root, dirs, files in os.walk(self.tmpdir.name):
            for d in dirs:
                try:
                    os.chmod(os.path.join(root, d), 0o777)
                except OSError:
                    pass
            for f in files:
                try:
                    os.chmod(os.path.join(root, f), 0o777)
                except OSError:
                    pass
        self.tmpdir.cleanup()

    def _create_mock_app(
        self,
        parent_dir: str,
        folder_name: str,
        apk_name: str,
        pkg_identifier: str,
        payload_size: int = 1024,
    ) -> str:
        app_dir = os.path.join(parent_dir, folder_name)
        os.makedirs(app_dir, exist_ok=True)
        apk_path = os.path.join(app_dir, f"{apk_name}.apk")
        with open(apk_path, "wb") as f:
            f.write(f"MOCK_APK_FOR_{pkg_identifier}\n".encode("utf-8") + b"P" * payload_size)
        return app_dir

    # =========================================================================
    # 1. Edge Case: Empty Trees & Missing Subfolders
    # =========================================================================

    def test_completely_empty_root(self):
        empty_root = os.path.join(self.tmpdir.name, "empty_root")
        os.makedirs(empty_root, exist_ok=True)
        debloater = Debloater()
        report = debloater.debloat_filesystem(empty_root)

        self.assertEqual(report.removed_count, 0)
        self.assertEqual(report.preserved_count, 0)
        self.assertEqual(report.bytes_freed, 0)
        self.assertEqual(len(report.errors), 0)
        self.assertEqual(report.total_scanned_apps, 0)

    def test_missing_priv_app_subfolder(self):
        only_app_root = os.path.join(self.tmpdir.name, "only_app")
        os.makedirs(os.path.join(only_app_root, "app"), exist_ok=True)
        self._create_mock_app(
            os.path.join(only_app_root, "app"),
            "com.baidu.BaiduMap",
            "com.baidu.BaiduMap",
            "com.baidu.BaiduMap",
            1024,
        )

        debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
        report = debloater.debloat_filesystem(only_app_root)

        self.assertEqual(report.removed_count, 1)
        self.assertIn("com.baidu.BaiduMap", report.removed_packages)
        self.assertEqual(len(report.errors), 0)

    def test_missing_app_subfolder(self):
        only_priv_root = os.path.join(self.tmpdir.name, "only_priv")
        os.makedirs(os.path.join(only_priv_root, "priv-app"), exist_ok=True)
        self._create_mock_app(
            os.path.join(only_priv_root, "priv-app"),
            "com.ts.car.updater",
            "com.ts.car.updater",
            "com.ts.car.updater",
            1024,
        )

        debloater = Debloater(blacklist=["com.ts.car.updater"], whitelist=[])
        report = debloater.debloat_filesystem(only_priv_root)

        self.assertEqual(report.removed_count, 1)
        self.assertIn("com.ts.car.updater", report.removed_packages)
        self.assertEqual(len(report.errors), 0)

    def test_empty_app_subdirectories(self):
        empty_sub = os.path.join(self.sys_root, "app", "EmptySubDir")
        os.makedirs(empty_sub, exist_ok=True)

        debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
        report = debloater.debloat_filesystem(self.sys_root)

        self.assertEqual(report.removed_count, 0)
        self.assertEqual(report.total_scanned_apps, 1)
        self.assertIn("EmptySubDir", report.preserved_packages)

    # =========================================================================
    # 2. Whitelist Collision Traps & Hardware Preservation
    # =========================================================================

    def test_whitelist_direct_collision_trap(self):
        """Attempting to blacklist com.roco.canbus and com.ts.main.radio."""
        canbus_dir = self._create_mock_app(
            os.path.join(self.sys_root, "priv-app"),
            "com.roco.canbus",
            "com.roco.canbus",
            "com.roco.canbus",
            2048,
        )
        radio_dir = self._create_mock_app(
            os.path.join(self.sys_root, "priv-app"),
            "com.ts.main.radio",
            "com.ts.main.radio",
            "com.ts.main.radio",
            4096,
        )

        # Both present in blacklist AND whitelist
        debloater = Debloater(
            blacklist=["com.roco.canbus", "com.ts.main.radio", "com.baidu.BaiduMap"],
            whitelist=["com.roco.canbus", "com.ts.main.radio"],
        )
        report = debloater.debloat_filesystem(self.sys_root)

        self.assertTrue(os.path.exists(canbus_dir), "com.roco.canbus must NOT be deleted")
        self.assertTrue(os.path.exists(radio_dir), "com.ts.main.radio must NOT be deleted")
        self.assertNotIn("com.roco.canbus", report.removed_packages)
        self.assertNotIn("com.ts.main.radio", report.removed_packages)
        self.assertIn("com.roco.canbus", report.preserved_packages)
        self.assertIn("com.ts.main.radio", report.preserved_packages)

    def test_whitelist_wildcard_catchall_collision(self):
        """Blacklist containing wildcard '*' or 'com.*' must not delete whitelisted apps."""
        radio_dir = self._create_mock_app(
            os.path.join(self.sys_root, "priv-app"),
            "com.ts.main.radio",
            "com.ts.main.radio",
            "com.ts.main.radio",
            2048,
        )
        canbus_dir = self._create_mock_app(
            os.path.join(self.sys_root, "priv-app"),
            "com.syu.canbus",
            "com.syu.canbus",
            "com.syu.canbus",
            2048,
        )
        bloat_dir = self._create_mock_app(
            os.path.join(self.sys_root, "app"),
            "com.baidu.BaiduMap",
            "com.baidu.BaiduMap",
            "com.baidu.BaiduMap",
            2048,
        )

        debloater = Debloater(
            blacklist=["*"],
            whitelist=["com.ts.main.radio", "com.syu.canbus"],
        )
        report = debloater.debloat_filesystem(self.sys_root)

        self.assertTrue(os.path.exists(radio_dir))
        self.assertTrue(os.path.exists(canbus_dir))
        self.assertFalse(os.path.exists(bloat_dir))
        self.assertIn("com.baidu.BaiduMap", report.removed_packages)
        self.assertIn("com.ts.main.radio", report.preserved_packages)
        self.assertIn("com.syu.canbus", report.preserved_packages)

    def test_whitelist_basename_and_prefix_collision(self):
        """Folder named 'Radio' with whitelist 'com.ts.main.radio'."""
        radio_dir = self._create_mock_app(
            os.path.join(self.sys_root, "priv-app"),
            "Radio",
            "Radio",
            "com.ts.main.radio",
            1024,
        )

        debloater = Debloater(
            blacklist=["*radio*"],
            whitelist=["com.ts.main.radio"],
        )
        report = debloater.debloat_filesystem(self.sys_root)

        self.assertTrue(os.path.exists(radio_dir))
        self.assertNotIn("Radio", report.removed_packages)
        self.assertIn("com.ts.main.radio", report.preserved_packages)

    def test_hardware_preservation_safety_validator_coupling(self):
        """Debloater followed by SafetyValidator verification."""
        with open(os.path.join(self.sys_root, "build.prop"), "w", encoding="utf-8") as f:
            f.write("ro.product.board=ROCO_K706\nro.qf001.radio.tuner=TDA7708\nro.qf001.audio.dsp=BU32107EFV\n")

        for pkg in ["com.ts.main.radio", "com.ts.camera", "com.syu.bt", "com.roco.canbus", "com.ts.car"]:
            self._create_mock_app(os.path.join(self.sys_root, "priv-app"), pkg, pkg, pkg, 1024)

        for bpkg in ["com.baidu.BaiduMap", "com.tencent.map", "com.txznet.music"]:
            self._create_mock_app(os.path.join(self.sys_root, "app"), bpkg, bpkg, bpkg, 1024)

        debloater = Debloater()
        report = debloater.debloat_filesystem(self.sys_root)
        self.assertEqual(report.removed_count, 3)

        validator = SafetyValidator()
        v_res = validator.verify_preserved_services(self.sys_root)
        self.assertTrue(v_res.is_safe)
        self.assertEqual(len(v_res.violations), 0)

    # =========================================================================
    # 3. Deeply Nested App Folder Structures
    # =========================================================================

    def test_deeply_nested_subfolders_inside_app(self):
        """25 levels of nested subdirectories inside blacklisted app folder."""
        deep_parts = [f"level_{i}" for i in range(25)]
        deep_dir = os.path.join(self.sys_root, "app", "com.baidu.BaiduMap", *deep_parts)
        os.makedirs(deep_dir, exist_ok=True)
        apk_path = os.path.join(deep_dir, "nested_map.apk")
        with open(apk_path, "wb") as f:
            f.write(b"MOCK_APK_FOR_com.baidu.BaiduMap\n" + b"N" * 2048)

        debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
        report = debloater.debloat_filesystem(self.sys_root)

        app_base = os.path.join(self.sys_root, "app", "com.baidu.BaiduMap")
        self.assertFalse(os.path.exists(app_base))
        self.assertEqual(report.removed_count, 1)
        self.assertGreaterEqual(report.bytes_freed, 2048)

    def test_deeply_nested_collateral_deletion_defect(self):
        """Intermediate category folder containing both blacklisted and innocent app."""
        category_dir = os.path.join(self.sys_root, "app", "OEM_Suite")
        innocent_app = self._create_mock_app(
            category_dir, "UsefulTool", "UsefulTool", "com.mycompany.usefultool", 1024
        )
        bloat_app = self._create_mock_app(
            category_dir, "BaiduMap", "BaiduMap", "com.baidu.BaiduMap", 1024
        )

        debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
        report = debloater.debloat_filesystem(self.sys_root)

        # Category folder recursion prevents collateral damage
        self.assertTrue(os.path.exists(innocent_app), "Innocent app in category folder must be preserved")
        self.assertFalse(os.path.exists(bloat_app), "Blacklisted app in category folder must be deleted")
        self.assertTrue(os.path.exists(category_dir), "Category folder must be kept while it contains innocent app")
        self.assertNotIn(category_dir, report.removed_paths)
        self.assertIn("com.baidu.BaiduMap", report.removed_packages)
        self.assertEqual(report.removed_count, 1)

    # =========================================================================
    # 4. Read-Only Directories & Permission Edge Cases (Bug Mining)
    # =========================================================================

    def test_readonly_directory_fails_and_produces_inaccurate_metrics(self):
        """Read-only app directory (mode 0o555).

        Verify that Debloater successfully unlocks read-only directories,
        purges the blacklisted app, and produces accurate report metrics.
        """
        app_dir = self._create_mock_app(
            os.path.join(self.sys_root, "app"),
            "com.baidu.BaiduMap",
            "com.baidu.BaiduMap",
            "com.baidu.BaiduMap",
            2048,
        )
        # Set app directory to read-only
        os.chmod(app_dir, 0o555)

        debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
        report = debloater.debloat_filesystem(self.sys_root)

        # Check reality on disk: directory and APK must be successfully deleted
        self.assertFalse(os.path.exists(app_dir), "App folder must be successfully deleted after unlocking")
        self.assertEqual(len(report.errors), 0, "No errors should occur when deleting unlocked directory")
        self.assertIn("com.baidu.BaiduMap", report.removed_packages)
        self.assertEqual(report.removed_count, 1)
        self.assertGreaterEqual(report.bytes_freed, 2048)

    def test_security_veto_inaccurate_metrics(self):
        """Symlink pointing outside system root.

        Security veto correctly prevents deleting outside target,
        and report metrics strictly exclude vetoed paths from removal count and bytes freed.
        """
        outside_dir = os.path.join(self.tmpdir.name, "outside_target")
        self._create_mock_app(
            outside_dir,
            "com.baidu.BaiduMap",
            "com.baidu.BaiduMap",
            "com.baidu.BaiduMap",
            3000,
        )

        # Create symlink inside system/app pointing to outside_target
        symlink_path = os.path.join(self.sys_root, "app", "com.baidu.BaiduMap")
        os.symlink(os.path.join(outside_dir, "com.baidu.BaiduMap"), symlink_path)

        debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
        report = debloater.debloat_filesystem(self.sys_root)

        # Veto triggered and outside target preserved
        self.assertTrue(any("Security veto" in err for err in report.errors))
        self.assertTrue(os.path.exists(os.path.join(outside_dir, "com.baidu.BaiduMap")))

        # Metrics must NOT include vetoed target
        self.assertNotIn("com.baidu.BaiduMap", report.removed_packages)
        self.assertEqual(report.removed_count, 0)
        self.assertEqual(report.bytes_freed, 0)

    # =========================================================================
    # 5. Metrics Reliability: Dry Run vs Execution Discrepancy
    # =========================================================================

    def test_readonly_modes_500_and_000_unlocking_and_deletion(self):
        """Verify proper unlocking and error-free deletion for modes 0o500 and 0o000."""
        for mode in (0o500, 0o000):
            app_dir = self._create_mock_app(
                os.path.join(self.sys_root, "app"),
                f"com.bloat.mode_{oct(mode)}",
                f"com.bloat.mode_{oct(mode)}",
                f"com.bloat.mode_{oct(mode)}",
                1024,
            )
            sub_dir = os.path.join(app_dir, "nested_sub")
            os.makedirs(sub_dir, exist_ok=True)
            with open(os.path.join(sub_dir, "libtest.so"), "wb") as f:
                f.write(b"ELF_SO" + b"X" * 512)
            os.chmod(os.path.join(sub_dir, "libtest.so"), 0o400)
            os.chmod(sub_dir, mode)
            os.chmod(app_dir, mode)

            debloater = Debloater(blacklist=[f"com.bloat.mode_{oct(mode)}"], whitelist=[])
            report = debloater.debloat_filesystem(self.sys_root)

            self.assertFalse(os.path.exists(app_dir), f"App folder with mode {oct(mode)} must be deleted")
            self.assertEqual(len(report.errors), 0, f"No errors expected for mode {oct(mode)}")
            self.assertIn(f"com.bloat.mode_{oct(mode)}", report.removed_packages)

    def test_category_directory_whitelisted_and_blacklisted_apps_zero_collateral_damage(self):
        """Verify zero collateral damage when category container has both whitelisted and blacklisted apps."""
        category_dir = os.path.join(self.sys_root, "app", "VendorOEMSuite")
        whitelisted_radio = self._create_mock_app(
            category_dir, "RadioApp", "RadioApp", "com.ts.main.radio", 2048
        )
        whitelisted_canbus = self._create_mock_app(
            category_dir, "CanbusApp", "CanbusApp", "com.roco.canbus", 2048
        )
        blacklisted_baidu = self._create_mock_app(
            category_dir, "BaiduMap", "BaiduMap", "com.baidu.BaiduMap", 1024
        )
        blacklisted_txz = self._create_mock_app(
            category_dir, "TxzVoice", "TxzVoice", "com.txznet.music", 1024
        )

        debloater = Debloater(
            blacklist=["com.baidu.BaiduMap", "com.txznet.music"],
            whitelist=["com.ts.main.radio", "com.roco.canbus"]
        )
        report = debloater.debloat_filesystem(self.sys_root)

        self.assertTrue(os.path.exists(category_dir), "Category container must be preserved")
        self.assertTrue(os.path.exists(whitelisted_radio), "Whitelisted radio app must be preserved")
        self.assertTrue(os.path.exists(whitelisted_canbus), "Whitelisted canbus app must be preserved")
        self.assertFalse(os.path.exists(blacklisted_baidu), "Blacklisted BaiduMap must be deleted")
        self.assertFalse(os.path.exists(blacklisted_txz), "Blacklisted TxzVoice must be deleted")
        self.assertIn("com.ts.main.radio", report.preserved_packages)
        self.assertIn("com.roco.canbus", report.preserved_packages)
        self.assertIn("com.baidu.BaiduMap", report.removed_packages)
        self.assertIn("com.txznet.music", report.removed_packages)
        self.assertEqual(len(report.errors), 0)

    def test_dry_run_parity_for_native_binaries_and_init_services(self):
        """Verify dry run parity across apps, native binaries, and init scripts without disk mutation."""
        app_dir = self._create_mock_app(
            os.path.join(self.sys_root, "app"),
            "com.baidu.BaiduMap",
            "com.baidu.BaiduMap",
            "com.baidu.BaiduMap",
            4096,
        )
        bin_dir = os.path.join(self.sys_root, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        ylog_bin = os.path.join(bin_dir, "ylog")
        with open(ylog_bin, "wb") as f:
            f.write(b"ELF_BINARY" + b"X" * 8192)

        init_dir = os.path.join(self.sys_root, "etc", "init")
        os.makedirs(init_dir, exist_ok=True)
        ylog_rc = os.path.join(init_dir, "ylog.rc")
        with open(ylog_rc, "wb") as f:
            f.write(b"service ylog /system/bin/ylog\n" + b"Y" * 2048)

        debloater = Debloater()
        report_dry = debloater.debloat_filesystem(self.sys_root, dry_run=True)

        self.assertTrue(os.path.exists(app_dir), "Dry run must preserve app directory on disk")
        self.assertTrue(os.path.exists(ylog_bin), "Dry run must preserve binary on disk")
        self.assertTrue(os.path.exists(ylog_rc), "Dry run must preserve init script on disk")
        self.assertIn("com.baidu.BaiduMap", report_dry.removed_packages)
        self.assertIn(ylog_bin, report_dry.removed_paths)
        self.assertIn(ylog_rc, report_dry.removed_paths)
        self.assertEqual(len(report_dry.errors), 0)

        report_exec = debloater.debloat_filesystem(self.sys_root, dry_run=False)
        self.assertFalse(os.path.exists(app_dir))
        self.assertFalse(os.path.exists(ylog_bin))
        self.assertFalse(os.path.exists(ylog_rc))
        self.assertEqual(report_dry.bytes_freed, report_exec.bytes_freed)
        self.assertEqual(report_dry.removed_count, report_exec.removed_count)


if __name__ == "__main__":
    unittest.main()
