"""Comprehensive unit tests for Debloater engine."""

import json
import os
import stat
import tempfile
import unittest

from src.domain.debloater import (
    Debloater,
    DebloatReport,
    DebloaterError,
    DebloaterFilesystemError,
    DebloaterSafetyViolationError,
    DebloaterConfigError,
)


class TestDebloaterFilteringLogic(unittest.TestCase):
    """Unit test suite for pure Debloater filtering logic."""

    def test_filter_packages_basic(self):
        debloater = Debloater(
            blacklist=["com.baidu.BaiduMap", "com.ts.car.updater"],
            whitelist=["com.ts.main.radio"]
        )
        installed = ["com.baidu.BaiduMap", "com.ts.main.radio", "com.android.settings"]
        to_remove = debloater.filter_packages(installed)
        self.assertIn("com.baidu.BaiduMap", to_remove)
        self.assertNotIn("com.ts.main.radio", to_remove)
        self.assertNotIn("com.android.settings", to_remove)

    def test_filter_packages_whitelist_override(self):
        debloater = Debloater(
            blacklist=["com.roco.canbus", "com.fyt.feedback"],
            whitelist=["com.roco.canbus"]
        )
        to_remove = debloater.filter_packages(["com.roco.canbus", "com.fyt.feedback"])
        self.assertIn("com.fyt.feedback", to_remove)
        self.assertNotIn("com.roco.canbus", to_remove, "Whitelist must strictly override blacklist")

    def test_filter_packages_empty_lists(self):
        d_empty = Debloater(blacklist=[], whitelist=[])
        self.assertEqual(len(d_empty.filter_packages(["com.baidu.BaiduMap"])), 0)

        d_empty_bl = Debloater(blacklist=[], whitelist=["com.ts.main.radio"])
        self.assertEqual(len(d_empty_bl.filter_packages(["com.ts.main.radio"])), 0)

        d_empty_wl = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
        self.assertEqual(d_empty_wl.filter_packages(["com.baidu.BaiduMap"]), {"com.baidu.BaiduMap"})

    def test_filter_packages_wildcard_patterns(self):
        debloater = Debloater(
            blacklist=["com.txznet.*"],
            whitelist=["com.ts.car"]
        )
        installed = ["com.txznet.music", "com.txznet.adapter", "com.ts.car"]
        to_remove = debloater.filter_packages(installed)
        self.assertIn("com.txznet.music", to_remove)
        self.assertIn("com.txznet.adapter", to_remove)
        self.assertNotIn("com.ts.car", to_remove)

    def test_filter_packages_updater_vs_core_abstraction(self):
        debloater = Debloater(
            blacklist=["com.ts.car.updater"],
            whitelist=["com.ts.car"]
        )
        installed = ["com.ts.car.updater", "com.ts.car"]
        to_remove = debloater.filter_packages(installed)
        self.assertIn("com.ts.car.updater", to_remove)
        self.assertNotIn("com.ts.car", to_remove)

    def test_filter_packages_non_string_entries_handled(self):
        debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
        to_remove = debloater.filter_packages(["com.baidu.BaiduMap", 123, None])  # type: ignore
        self.assertEqual(to_remove, {"com.baidu.BaiduMap"})


class TestDebloaterFilesystemEngine(unittest.TestCase):
    """Unit test suite for filesystem debloater operations on disk."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = os.path.join(self.tmpdir.name, "system")
        os.makedirs(os.path.join(self.sys_root, "app"), exist_ok=True)
        os.makedirs(os.path.join(self.sys_root, "priv-app"), exist_ok=True)
        os.makedirs(os.path.join(self.tmpdir.name, "product", "app"), exist_ok=True)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _create_app(self, parent_dir: str, pkg_name: str, payload_size: int = 1024) -> str:
        app_dir = os.path.join(parent_dir, pkg_name)
        os.makedirs(app_dir, exist_ok=True)
        apk_path = os.path.join(app_dir, f"{pkg_name}.apk")
        with open(apk_path, "wb") as f:
            f.write(b"MOCK_APK_FOR_" + pkg_name.encode("utf-8") + b"\n" + b"X" * payload_size)
        return app_dir

    def test_debloat_filesystem_standard_hierarchy(self):
        baidu_dir = self._create_app(os.path.join(self.sys_root, "app"), "com.baidu.BaiduMap", 2048)
        radio_dir = self._create_app(os.path.join(self.sys_root, "priv-app"), "com.ts.main.radio", 4096)

        debloater = Debloater(
            blacklist=["com.baidu.BaiduMap"],
            whitelist=["com.ts.main.radio"]
        )
        report = debloater.debloat_filesystem(self.sys_root)

        self.assertFalse(os.path.exists(baidu_dir), "Blacklisted folder must be deleted")
        self.assertTrue(os.path.exists(radio_dir), "Whitelisted folder must be preserved")
        self.assertIn("com.baidu.BaiduMap", report.removed_packages)
        self.assertEqual(report.removed_count, 1)
        self.assertGreater(report.bytes_freed, 2048)

    def test_debloat_filesystem_product_partition(self):
        prod_root = self.tmpdir.name
        prod_app = os.path.join(prod_root, "product", "app")
        amap_dir = self._create_app(prod_app, "com.autonavi.amapauto", 1024)

        debloater = Debloater(
            blacklist=["com.autonavi.amapauto"],
            whitelist=[]
        )
        report = debloater.debloat_filesystem(prod_root)

        self.assertFalse(os.path.exists(amap_dir))
        self.assertIn("com.autonavi.amapauto", report.removed_packages)

    def test_filesystem_strict_whitelist_override(self):
        canbus_dir = self._create_app(os.path.join(self.sys_root, "priv-app"), "com.syu.canbus")

        debloater = Debloater(
            blacklist=["com.syu.canbus"],
            whitelist=["com.syu.canbus"]
        )
        report = debloater.debloat_filesystem(self.sys_root)

        self.assertTrue(os.path.exists(canbus_dir), "Conflicting package must be protected by whitelist")
        self.assertNotIn("com.syu.canbus", report.removed_packages)
        self.assertIn("com.syu.canbus", report.preserved_packages)

    def test_partition_files_untouched(self):
        build_prop = os.path.join(self.sys_root, "build.prop")
        with open(build_prop, "w", encoding="utf-8") as f:
            f.write("ro.qf001.radio.tuner=TDA7708\nro.product.board=ROCO_K706\n")

        self._create_app(os.path.join(self.sys_root, "app"), "com.chinese.telemetry")
        debloater = Debloater(blacklist=["com.chinese.telemetry"], whitelist=[])
        debloater.debloat_filesystem(self.sys_root)

        self.assertTrue(os.path.exists(build_prop))
        with open(build_prop, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("TDA7708", content)
            self.assertIn("ROCO_K706", content)

    def test_dry_run_mode_zero_filesystem_changes(self):
        baidu_dir = self._create_app(os.path.join(self.sys_root, "app"), "com.baidu.BaiduMap", 1024)
        debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])

        report = debloater.debloat_filesystem(self.sys_root, dry_run=True)

        self.assertTrue(os.path.exists(baidu_dir), "In dry-run mode, folder must NOT be deleted")
        self.assertTrue(report.dry_run)
        self.assertEqual(report.removed_count, 1)
        self.assertIn("com.baidu.BaiduMap", report.removed_packages)
        self.assertGreater(report.bytes_freed, 1024)

    def test_empty_filesystem_resilience(self):
        empty_dir = os.path.join(self.tmpdir.name, "empty_root")
        os.makedirs(empty_dir, exist_ok=True)
        debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
        report = debloater.debloat_filesystem(empty_dir)

        self.assertEqual(report.removed_count, 0)
        self.assertEqual(report.bytes_freed, 0)
        self.assertEqual(len(report.errors), 0)

    def test_nonexistent_system_root_raises(self):
        debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
        with self.assertRaises(FileNotFoundError):
            debloater.debloat_filesystem("/nonexistent/path/for/sure/12345")

    def test_file_as_system_root_raises(self):
        dummy_file = os.path.join(self.tmpdir.name, "dummy.txt")
        with open(dummy_file, "w") as f:
            f.write("content")
        debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
        with self.assertRaises(NotADirectoryError):
            debloater.debloat_filesystem(dummy_file)

    def test_loose_apk_removal(self):
        app_dir = os.path.join(self.sys_root, "app")
        loose_apk = os.path.join(app_dir, "com.baidu.BaiduMap.apk")
        with open(loose_apk, "wb") as f:
            f.write(b"MOCK_APK_FOR_com.baidu.BaiduMap" + b"X" * 512)

        debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
        report = debloater.debloat_filesystem(self.sys_root)

        self.assertFalse(os.path.exists(loose_apk))
        self.assertEqual(report.removed_count, 1)

    def test_readonly_file_removal(self):
        baidu_dir = self._create_app(os.path.join(self.sys_root, "app"), "com.baidu.BaiduMap")
        apk_path = os.path.join(baidu_dir, "com.baidu.BaiduMap.apk")
        os.chmod(apk_path, stat.S_IREAD)

        debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
        report = debloater.debloat_filesystem(self.sys_root)

        self.assertFalse(os.path.exists(baidu_dir))
        self.assertEqual(report.removed_count, 1)

    def test_symlink_security_traversal_protection(self):
        outside_dir = os.path.join(self.tmpdir.name, "outside_dir")
        os.makedirs(outside_dir, exist_ok=True)
        victim_file = os.path.join(outside_dir, "important.txt")
        with open(victim_file, "w") as f:
            f.write("critical system file")

        # Create symlink inside app pointing outside
        app_dir = os.path.join(self.sys_root, "app", "com.baidu.BaiduMap")
        os.makedirs(app_dir, exist_ok=True)
        symlink_path = os.path.join(app_dir, "symlink_to_outside")
        os.symlink(victim_file, symlink_path)

        debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
        debloater.debloat_filesystem(self.sys_root)

        self.assertFalse(os.path.exists(app_dir))
        self.assertTrue(os.path.exists(victim_file), "Target outside system root must NOT be deleted")

    def test_ylog_native_binary_purged(self):
        bin_dir = os.path.join(self.sys_root, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        ylog_bin = os.path.join(bin_dir, "ylog")
        with open(ylog_bin, "wb") as f:
            f.write(b"\x7fELF" + b"YLOG_DAEMON")

        debloater = Debloater()
        report = debloater.debloat_filesystem(self.sys_root)

        self.assertFalse(os.path.exists(ylog_bin))
        self.assertIn(ylog_bin, report.removed_paths)


class TestDebloatReportDataStructures(unittest.TestCase):
    """Unit test suite for DebloatReport dataclass methods."""

    def test_report_properties_and_metrics(self):
        report = DebloatReport(
            system_root="/system",
            removed_packages=["pkg1", "pkg2"],
            preserved_packages=["pkg3"],
            removed_paths=["/system/app/pkg1", "/system/app/pkg2"],
            bytes_freed=5242880,
            dry_run=False,
            total_scanned_apps=3
        )
        self.assertEqual(report.removed_count, 2)
        self.assertEqual(report.preserved_count, 1)

        d = report.to_dict()
        self.assertEqual(d["system_root"], "/system")
        self.assertEqual(d["removed_count"], 2)
        self.assertEqual(d["preserved_count"], 1)
        self.assertEqual(d["bytes_freed"], 5242880)

        s = report.summary()
        self.assertIn("EXECUTED", s)
        self.assertIn("5.00 MB", s)
        self.assertIn("pkg1", s)


if __name__ == "__main__":
    unittest.main()
