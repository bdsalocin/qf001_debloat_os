"""Empirical stress test and adversarial evaluation suite for iOS Launcher Customization.

Challenger 1 Evaluation for Milestone M3 (QF001 Debloat OS).
Target: src/customization/launcher.py (IOSLauncherConfig)

Evaluates:
- Layout generation under unusual configurations (RHD/LHD, strange themes, missing ICs, empty options)
- AndroidManifest.xml and permissions XML generation with extreme priorities, custom packages, and XML parsing
- System injection robustness (read-only directories, deeply nested paths, spaces, unicode, symlinks, file collisions, idempotency)
- APK container binary integrity (zip CRC check, DEX header magic, ARSC header, internal manifest/layout verification)
- Hardware preservation and cross-customization coexistence (SafetyValidator verification, MicroG coexistence)
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.customization.launcher import IOSLauncherConfig
from src.customization.microg import MicroGConfig, PowerOptimizer
from src.domain.safety_validator import SafetyValidator
from tests.e2e.test_helpers import create_mock_system_fs


class TestLauncherLayoutStress(unittest.TestCase):
    """Adversarial boundary and stress tests on IOSLauncherConfig.generate_layout()."""

    def test_01_layout_driver_side_orientations(self):
        """Probing driver-side dock positions: LHD, RHD, left, right, custom, and edge inputs."""
        # Standard orientations
        layout_left = IOSLauncherConfig.generate_layout(driver_side="left")
        self.assertEqual(layout_left["dock_position"], "driver_side_left")

        layout_right = IOSLauncherConfig.generate_layout(driver_side="right")
        self.assertEqual(layout_right["dock_position"], "driver_side_right")

        # RHD / LHD explicit nomenclature
        layout_rhd = IOSLauncherConfig.generate_layout(driver_side="rhd")
        self.assertEqual(layout_rhd["dock_position"], "driver_side_rhd")

        layout_lhd = IOSLauncherConfig.generate_layout(driver_side="lhd")
        self.assertEqual(layout_lhd["dock_position"], "driver_side_lhd")

        # Empty string and None
        layout_empty = IOSLauncherConfig.generate_layout(driver_side="")
        self.assertEqual(layout_empty["dock_position"], "driver_side_")

        layout_none = IOSLauncherConfig.generate_layout(driver_side=None)
        self.assertEqual(layout_none["dock_position"], "driver_side_None")

        # Layout remains a valid dict and JSON-serializable in all cases
        for l in (layout_left, layout_right, layout_rhd, layout_lhd, layout_empty, layout_none):
            self.assertIsInstance(l, dict)
            dumped = json.dumps(l)
            self.assertTrue(len(dumped) > 0)

    def test_02_layout_hardware_tuner_dsp_fallbacks(self):
        """Probing tuner and DSP IC parameter permutations (custom ICs, blanks, None)."""
        # Alternate tuner and DSP chips (e.g. SI47920 tuner, AK7738 DSP)
        layout_alt = IOSLauncherConfig.generate_layout(tuner_ic="SI47920", dsp_ic="AK7738")
        dock = layout_alt["dock"]
        radio_dock = [d for d in dock if d.get("action") == "radio"][0]
        self.assertEqual(radio_dock["hardware_binding"], "SI47920")

        settings_dock = [d for d in dock if d.get("action") == "settings"][0]
        self.assertEqual(settings_dock["hardware_binding"], "AK7738")

        # Check widget source reflects tuner
        hub = layout_alt["widgets"]["media_hub"]
        radio_source = [s for s in hub["supported_sources"] if s.get("type") == "radio"][0]
        self.assertEqual(radio_source["chip"], "SI47920")

        # Status bar reflects DSP
        dsp_ind = [i for i in layout_alt["status_bar"]["indicators"] if i.get("type") == "dsp_status"][0]
        self.assertEqual(dsp_ind["chip"], "AK7738")

        # Empty / None fallbacks
        layout_none = IOSLauncherConfig.generate_layout(tuner_ic=None, dsp_ic=None)
        radio_dock_none = [d for d in layout_none["dock"] if d.get("action") == "radio"][0]
        self.assertIsNone(radio_dock_none["hardware_binding"])

    def test_03_layout_theme_permutations(self):
        """Probing theme variations (dark, high_contrast, oled, empty, unicode)."""
        themes = ["ios_automotive", "dark_mode", "oled_black", "high_contrast", "cyberpunk_2077", "Thème_Français_Élégant", "", None]
        for theme in themes:
            layout = IOSLauncherConfig.generate_layout(theme=theme)
            self.assertEqual(layout.get("style"), theme)
            serialized = json.dumps(layout, ensure_ascii=False)
            deserialized = json.loads(serialized)
            self.assertEqual(deserialized.get("style"), theme)

    def test_04_layout_dock_items_and_ordering(self):
        """Probing dock items structure: strictly 5 canonical shortcuts, sequential orders 1..5."""
        layout = IOSLauncherConfig.generate_layout()
        dock = layout["dock"]
        self.assertEqual(len(dock), 5)

        orders = [item["order"] for item in dock]
        self.assertEqual(orders, [1, 2, 3, 4, 5])

        ids = [item["id"] for item in dock]
        self.assertEqual(len(ids), len(set(ids)), "Dock IDs must be strictly unique")

        actions = [item["action"] for item in dock]
        self.assertEqual(actions, ["home", "nav", "music", "radio", "settings"])

        for item in dock:
            self.assertTrue(item.get("id"))
            self.assertTrue(item.get("name"))
            self.assertTrue(item.get("type"))
            self.assertTrue(item.get("icon"))
            self.assertTrue(item.get("package"))

    def test_05_layout_tiles_and_widget_referencing(self):
        """Probing automotive quick tiles and cross-widget references."""
        layout = IOSLauncherConfig.generate_layout()
        tiles = layout["tiles"]
        widgets = layout["widgets"]

        self.assertEqual(len(tiles), 6)
        tile_ids = [t["id"] for t in tiles]
        self.assertEqual(len(tile_ids), len(set(tile_ids)), "Tile IDs must be unique")

        # Verify navigation tile references primary_navigation widget
        nav_tile = [t for t in tiles if t["id"] == "tile_nav"][0]
        widget_ref = nav_tile.get("widget_ref")
        self.assertIsNotNone(widget_ref)
        self.assertIn(widget_ref, widgets, f"widget_ref '{widget_ref}' must exist in widgets dictionary")

        # Verify radio quick tile has essential capabilities
        radio_tile = [t for t in tiles if t["id"] == "tile_radio"][0]
        self.assertEqual(radio_tile.get("package"), "com.ts.main.radio")
        self.assertIn("direct_tune", radio_tile.get("capabilities", []))
        self.assertIn("rds_display", radio_tile.get("capabilities", []))

    def test_06_layout_status_bar_and_clock_integrity(self):
        """Probing status bar configuration: 24h clock, connectivity indicators."""
        layout = IOSLauncherConfig.generate_layout()
        sb = layout["status_bar"]
        self.assertTrue(sb.get("enabled"))
        self.assertEqual(sb.get("position"), "top")
        self.assertEqual(sb.get("height_dp"), 32)
        self.assertEqual(sb.get("clock", {}).get("format"), "24h")

        indicators = sb.get("indicators", [])
        ind_types = [ind["type"] for ind in indicators]
        self.assertEqual(len(ind_types), len(set(ind_types)), "Indicator types must be unique")
        self.assertIn("clock", ind_types)
        self.assertIn("wifi", ind_types)
        self.assertIn("bluetooth", ind_types)
        self.assertIn("cellular", ind_types)
        self.assertIn("gps", ind_types)
        self.assertIn("dsp_status", ind_types)

    def test_07_instance_vs_classmethod_execution(self):
        """Probing IOSLauncherConfig instantiation and invocation via instance."""
        cfg = IOSLauncherConfig(
            package_name="com.custom.launcher",
            app_name="CustomLauncher",
            driver_side="right",
            theme="high_contrast",
            tuner_ic="SI47920",
            dsp_ic="AK7738",
        )
        self.assertEqual(cfg.package_name, "com.custom.launcher")
        self.assertEqual(cfg.driver_side, "right")
        self.assertEqual(cfg.theme, "high_contrast")
        self.assertEqual(cfg.tuner_ic, "SI47920")
        self.assertEqual(cfg.dsp_ic, "AK7738")

        # Calling generate_layout on instance passing instance parameters
        layout = cfg.generate_layout(
            driver_side=cfg.driver_side,
            tuner_ic=cfg.tuner_ic,
            dsp_ic=cfg.dsp_ic,
            theme=cfg.theme,
        )
        self.assertEqual(layout["dock_position"], "driver_side_right")
        self.assertEqual(layout["style"], "high_contrast")


class TestLauncherManifestAndPermissionsStress(unittest.TestCase):
    """Adversarial stress tests on AndroidManifest.xml and privapp permissions generation."""

    def test_01_manifest_custom_package_names(self):
        """Probing custom, deep, and fallback package names."""
        # Deep package name
        deep_pkg = "org.automotive.android.system.priv.launcher.v3"
        manifest_deep = IOSLauncherConfig.generate_manifest(package_name=deep_pkg)
        root = ET.fromstring(manifest_deep)
        self.assertEqual(root.attrib.get("package"), deep_pkg)

        # Fallback on empty string -> defaults to com.qf001.ioslauncher
        manifest_empty = IOSLauncherConfig.generate_manifest(package_name="")
        root_empty = ET.fromstring(manifest_empty)
        self.assertEqual(root_empty.attrib.get("package"), IOSLauncherConfig.PACKAGE_NAME)

        # Fallback on None -> defaults to com.qf001.ioslauncher
        manifest_none = IOSLauncherConfig.generate_manifest(package_name=None)
        root_none = ET.fromstring(manifest_none)
        self.assertEqual(root_none.attrib.get("package"), IOSLauncherConfig.PACKAGE_NAME)

    def test_02_manifest_extreme_priorities(self):
        """Probing extreme intent priority values: negative, zero, extreme int32 boundaries."""
        boundary_priorities = [-2147483648, -1000, -1, 0, 1, 100, 9999, 2147483647]
        for prio in boundary_priorities:
            manifest_xml = IOSLauncherConfig.generate_manifest(priority=prio)
            root = ET.fromstring(manifest_xml)
            activity = root.find(".//activity")
            self.assertIsNotNone(activity)
            intent_filter = activity.find("intent-filter")
            self.assertIsNotNone(intent_filter)
            prio_attr = intent_filter.attrib.get("{http://schemas.android.com/apk/res/android}priority")
            self.assertEqual(int(prio_attr), prio)

    def test_03_manifest_xml_attributes_and_security(self):
        """Probing manifest XML attributes: singleTask, stateNotNeeded, landscape, exported=true."""
        manifest_xml = IOSLauncherConfig.generate_manifest()
        root = ET.fromstring(manifest_xml)

        self.assertEqual(root.tag, "manifest")
        self.assertEqual(root.attrib.get("{http://schemas.android.com/apk/res/android}versionCode"), "100")
        self.assertEqual(root.attrib.get("{http://schemas.android.com/apk/res/android}versionName"), "1.0.0-qf001")

        app = root.find("application")
        self.assertIsNotNone(app)
        self.assertEqual(app.attrib.get("{http://schemas.android.com/apk/res/android}launchMode"), "singleTask")
        self.assertEqual(app.attrib.get("{http://schemas.android.com/apk/res/android}stateNotNeeded"), "true")
        self.assertEqual(app.attrib.get("{http://schemas.android.com/apk/res/android}clearTaskOnLaunch"), "true")

        act = app.find("activity")
        self.assertIsNotNone(act)
        self.assertEqual(act.attrib.get("{http://schemas.android.com/apk/res/android}name"), ".MainActivity")
        self.assertEqual(act.attrib.get("{http://schemas.android.com/apk/res/android}exported"), "true")
        self.assertEqual(act.attrib.get("{http://schemas.android.com/apk/res/android}screenOrientation"), "sensorLandscape")

        # Intent categories
        categories = [c.attrib.get("{http://schemas.android.com/apk/res/android}name") for c in act.findall(".//category")]
        self.assertIn("android.intent.category.HOME", categories)
        self.assertIn("android.intent.category.DEFAULT", categories)

    def test_04_permissions_xml_structure_and_privileges(self):
        """Probing privapp permissions XML generation and privileged permission entries."""
        perm_xml = IOSLauncherConfig.generate_permissions_xml()
        root = ET.fromstring(perm_xml)
        self.assertEqual(root.tag, "permissions")

        priv = root.find("privapp-permissions")
        self.assertIsNotNone(priv)
        self.assertEqual(priv.attrib.get("package"), IOSLauncherConfig.PACKAGE_NAME)

        perms = [p.attrib.get("name") for p in priv.findall("permission")]
        expected_perms = [
            "android.permission.STATUS_BAR",
            "android.permission.EXPAND_STATUS_BAR",
            "android.permission.INTERNAL_SYSTEM_WINDOW",
            "android.permission.INTERACT_ACROSS_USERS",
            "android.permission.MANAGE_USERS",
            "android.permission.SET_ACTIVITY_WATCHER",
            "android.permission.STOP_APP_SWITCHES",
            "android.permission.REORDER_TASKS",
        ]
        for ep in expected_perms:
            self.assertIn(ep, perms, f"Missing privileged permission: {ep}")

    def test_05_permissions_xml_custom_package(self):
        """Probing privapp permissions XML with custom and fallback package names."""
        custom_pkg = "com.automotive.customlauncher"
        perm_xml = IOSLauncherConfig.generate_permissions_xml(package_name=custom_pkg)
        root = ET.fromstring(perm_xml)
        priv = root.find("privapp-permissions")
        self.assertEqual(priv.attrib.get("package"), custom_pkg)


class TestLauncherSystemInjectionStress(unittest.TestCase):
    """Adversarial stress tests on IOSLauncherConfig.inject_into_system()."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = os.path.join(self.tmpdir.name, "system")
        os.makedirs(self.sys_root, exist_ok=True)

    def tearDown(self):
        # Restore permissions before cleanup to prevent teardown failure
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

    def test_01_invalid_and_nonexistent_targets(self):
        """Probing invalid targets: None, empty string, non-existent paths, file as target."""
        self.assertFalse(IOSLauncherConfig.inject_into_system(None))
        self.assertFalse(IOSLauncherConfig.inject_into_system(""))
        self.assertFalse(IOSLauncherConfig.inject_into_system(os.path.join(self.tmpdir.name, "missing_dir")))

        # Target is a regular file, not a directory
        file_target = os.path.join(self.tmpdir.name, "regular_file.bin")
        with open(file_target, "wb") as f:
            f.write(b"not a directory")
        self.assertFalse(IOSLauncherConfig.inject_into_system(file_target))

    def test_02_readonly_targets_fail_gracefully(self):
        """Probing read-only system root and read-only subdirectories: must return False without crashing."""
        # Read-only root
        ro_root = os.path.join(self.tmpdir.name, "readonly_sys")
        os.makedirs(ro_root, exist_ok=True)
        os.chmod(ro_root, 0o555)
        try:
            res = IOSLauncherConfig.inject_into_system(ro_root)
            self.assertFalse(res, "Injection into read-only root directory must return False")
        finally:
            os.chmod(ro_root, 0o755)

        # Read-only priv-app directory
        ro_privapp_sys = os.path.join(self.tmpdir.name, "ro_privapp_sys")
        os.makedirs(os.path.join(ro_privapp_sys, "priv-app"), exist_ok=True)
        os.chmod(os.path.join(ro_privapp_sys, "priv-app"), 0o555)
        try:
            res = IOSLauncherConfig.inject_into_system(ro_privapp_sys)
            self.assertFalse(res, "Injection into read-only priv-app directory must return False")
        finally:
            os.chmod(os.path.join(ro_privapp_sys, "priv-app"), 0o755)

        # Read-only etc/permissions directory
        ro_perm_sys = os.path.join(self.tmpdir.name, "ro_perm_sys")
        os.makedirs(os.path.join(ro_perm_sys, "etc", "permissions"), exist_ok=True)
        os.chmod(os.path.join(ro_perm_sys, "etc", "permissions"), 0o555)
        try:
            res = IOSLauncherConfig.inject_into_system(ro_perm_sys)
            self.assertFalse(res, "Injection into read-only etc/permissions directory must return False")
        finally:
            os.chmod(os.path.join(ro_perm_sys, "etc", "permissions"), 0o755)

    def test_03_file_and_directory_type_collisions(self):
        """Probing path collisions where expected directories exist as regular files."""
        # 1. priv-app exists as a regular file
        col_sys1 = os.path.join(self.tmpdir.name, "col_sys1")
        os.makedirs(col_sys1, exist_ok=True)
        with open(os.path.join(col_sys1, "priv-app"), "w") as f:
            f.write("collision")
        self.assertFalse(IOSLauncherConfig.inject_into_system(col_sys1))

        # 2. etc/permissions exists as a regular file
        col_sys2 = os.path.join(self.tmpdir.name, "col_sys2")
        os.makedirs(os.path.join(col_sys2, "etc"), exist_ok=True)
        with open(os.path.join(col_sys2, "etc", "permissions"), "w") as f:
            f.write("collision")
        self.assertFalse(IOSLauncherConfig.inject_into_system(col_sys2))

        # 3. IOSLauncher.apk exists as a directory
        col_sys3 = os.path.join(self.tmpdir.name, "col_sys3")
        apk_dir = os.path.join(col_sys3, "priv-app", "IOSLauncher", "IOSLauncher.apk")
        os.makedirs(apk_dir, exist_ok=True)
        self.assertFalse(IOSLauncherConfig.inject_into_system(col_sys3))

    def test_04_deeply_nested_and_spaced_paths(self):
        """Probing deeply nested filesystem paths and paths with spaces and unicode."""
        # Deeply nested path (10 levels)
        deep_sys = os.path.join(self.tmpdir.name, "l1", "l2", "l3", "l4", "l5", "l6", "l7", "l8", "l9", "system")
        os.makedirs(deep_sys, exist_ok=True)
        self.assertTrue(IOSLauncherConfig.inject_into_system(deep_sys))
        apk_deep = os.path.join(deep_sys, "priv-app", "IOSLauncher", "IOSLauncher.apk")
        self.assertTrue(os.path.isfile(apk_deep))
        self.assertTrue(zipfile.is_zipfile(apk_deep))

        # Path with spaces and unicode characters
        spaced_sys = os.path.join(self.tmpdir.name, "Car OS 🚗 UIS7862 Système", "system")
        os.makedirs(spaced_sys, exist_ok=True)
        self.assertTrue(IOSLauncherConfig.inject_into_system(spaced_sys))
        apk_spaced = os.path.join(spaced_sys, "priv-app", "IOSLauncher", "IOSLauncher.apk")
        self.assertTrue(os.path.isfile(apk_spaced))
        self.assertTrue(zipfile.is_zipfile(apk_spaced))

    def test_05_symlink_redirection(self):
        """Probing injection when target or subdirectories are symlinks."""
        real_sys = os.path.join(self.tmpdir.name, "real_system_partition")
        os.makedirs(real_sys, exist_ok=True)

        symlink_sys = os.path.join(self.tmpdir.name, "symlink_system")
        os.symlink(real_sys, symlink_sys)

        self.assertTrue(IOSLauncherConfig.inject_into_system(symlink_sys))
        apk_real = os.path.join(real_sys, "priv-app", "IOSLauncher", "IOSLauncher.apk")
        self.assertTrue(os.path.isfile(apk_real))
        self.assertTrue(zipfile.is_zipfile(apk_real))

    def test_06_idempotency_and_hash_stability(self):
        """Probing repeated injections (5x) ensuring bit-for-bit file hash stability."""
        hashes = []
        apk_path = os.path.join(self.sys_root, "priv-app", "IOSLauncher", "IOSLauncher.apk")

        for _ in range(5):
            success = IOSLauncherConfig.inject_into_system(self.sys_root)
            self.assertTrue(success)
            self.assertTrue(zipfile.is_zipfile(apk_path))
            with open(apk_path, "rb") as f:
                hashes.append(hashlib.sha256(f.read()).hexdigest())

        # All SHA256 hashes must be strictly identical across repeated runs
        self.assertEqual(len(set(hashes)), 1, "Repeated injection must produce byte-stable APK")

    def test_07_recovery_from_corrupted_preexisting_apk(self):
        """Probing clean overwrite and recovery when pre-existing APK is corrupted garbage."""
        launcher_dir = os.path.join(self.sys_root, "priv-app", "IOSLauncher")
        os.makedirs(launcher_dir, exist_ok=True)
        corrupted_apk = os.path.join(launcher_dir, "IOSLauncher.apk")
        with open(corrupted_apk, "wb") as f:
            f.write(b"GARBAGE_BYTES_CORRUPTED_NOT_A_ZIP")

        self.assertFalse(zipfile.is_zipfile(corrupted_apk))

        # Re-inject launcher
        success = IOSLauncherConfig.inject_into_system(self.sys_root)
        self.assertTrue(success)
        self.assertTrue(zipfile.is_zipfile(corrupted_apk))
        with zipfile.ZipFile(corrupted_apk, "r") as zf:
            self.assertIsNone(zf.testzip())


class TestLauncherAPKContainerIntegrityStress(unittest.TestCase):
    """Rigorous binary and container format inspection of the generated IOSLauncher.apk."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = os.path.join(self.tmpdir.name, "system")
        os.makedirs(self.sys_root, exist_ok=True)
        IOSLauncherConfig.inject_into_system(self.sys_root)
        self.apk_path = os.path.join(self.sys_root, "priv-app", "IOSLauncher", "IOSLauncher.apk")
        self.manifest_path = os.path.join(self.sys_root, "priv-app", "IOSLauncher", "AndroidManifest.xml")
        self.layout_path = os.path.join(self.sys_root, "priv-app", "IOSLauncher", "layout.json")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_zip_archive_structure_and_crc(self):
        """Validating zip format, compression headers, and zero CRC checksum errors."""
        self.assertTrue(zipfile.is_zipfile(self.apk_path))
        with zipfile.ZipFile(self.apk_path, "r") as zf:
            self.assertIsNone(zf.testzip(), "testzip() must return None indicating valid CRCs")
            entries = zf.namelist()
            self.assertIn("AndroidManifest.xml", entries)
            self.assertIn("classes.dex", entries)
            self.assertIn("resources.arsc", entries)
            self.assertIn("res/raw/layout.json", entries)

    def test_02_dex_and_arsc_headers_magic(self):
        """Validating Android binary format headers (DEX 035 magic, ARSC table chunk type)."""
        with zipfile.ZipFile(self.apk_path, "r") as zf:
            dex_bytes = zf.read("classes.dex")
            # Standard DEX magic: 'dex\n035\0'
            self.assertEqual(dex_bytes[:8], b"dex\n035\x00", "DEX entry must begin with standard DEX 035 magic")
            self.assertGreaterEqual(len(dex_bytes), 40)

            arsc_bytes = zf.read("resources.arsc")
            # Standard ARSC RES_TABLE_TYPE header: 0x0002, header_size 12 bytes
            self.assertEqual(arsc_bytes[:4], b"\x02\x00\x0c\x00", "ARSC entry must begin with table chunk header")

    def test_03_embedded_manifest_and_layout_validity(self):
        """Validating that embedded AndroidManifest.xml and layout.json are valid and parseable."""
        with zipfile.ZipFile(self.apk_path, "r") as zf:
            manifest_bytes = zf.read("AndroidManifest.xml")
            manifest_xml = manifest_bytes.decode("utf-8")
            root = ET.fromstring(manifest_xml)
            self.assertEqual(root.tag, "manifest")
            self.assertEqual(root.attrib.get("package"), IOSLauncherConfig.PACKAGE_NAME)

            layout_bytes = zf.read("res/raw/layout.json")
            layout = json.loads(layout_bytes.decode("utf-8"))
            self.assertIn("dock", layout)
            self.assertIn("tiles", layout)
            self.assertEqual(len(layout["dock"]), 5)
            self.assertEqual(len(layout["tiles"]), 6)

    def test_04_embedded_vs_external_files_consistency(self):
        """Validating that companion manifest and layout files match internal archive contents."""
        with open(self.manifest_path, "rb") as f:
            ext_manifest = f.read()
        with open(self.layout_path, "rb") as f:
            ext_layout = f.read()

        with zipfile.ZipFile(self.apk_path, "r") as zf:
            in_manifest = zf.read("AndroidManifest.xml")
            in_layout = zf.read("res/raw/layout.json")
            self.assertEqual(ext_manifest, in_manifest, "External AndroidManifest.xml must match APK entry")
            self.assertEqual(ext_layout, in_layout, "External layout.json must match APK entry")


class TestLauncherPreservationSafetyAndCoexistence(unittest.TestCase):
    """Stress tests on hardware preservation and coexistence with MicroG / PowerOptimizer."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_launcher_injection_preserves_hardware_daemons(self):
        """Validating that launcher injection does not damage or remove essential automotive daemons."""
        val_pre = SafetyValidator().verify_preserved_services(self.sys_root)
        self.assertTrue(val_pre.is_valid)

        # Inject Launcher
        success = IOSLauncherConfig.inject_into_system(self.sys_root)
        self.assertTrue(success)

        # SafetyValidator must still pass cleanly
        val_post = SafetyValidator().verify_preserved_services(self.sys_root)
        self.assertTrue(val_post.is_valid)
        self.assertIn("com.ts.main.radio", val_post.verified_services)
        self.assertIn("com.syu.canbus", val_post.verified_services)
        self.assertIn("com.roco.canbus", val_post.verified_services)
        self.assertIn("com.ts.car", val_post.verified_services)
        self.assertIn("com.syu.bt", val_post.verified_services)
        self.assertIn("com.ts.camera", val_post.verified_services)

    def test_02_combined_launcher_and_microg_multistep_stress(self):
        """Stress testing alternating multi-step injections of Launcher and MicroG."""
        for step in range(3):
            self.assertTrue(IOSLauncherConfig.inject_into_system(self.sys_root))
            self.assertTrue(MicroGConfig.inject_into_system(self.sys_root))

            val = SafetyValidator().verify_preserved_services(self.sys_root)
            self.assertTrue(val.is_valid, f"SafetyValidator failed at iteration {step}")

        # Verify all expected artifacts exist and are non-empty
        launcher_apk = os.path.join(self.sys_root, "priv-app", "IOSLauncher", "IOSLauncher.apk")
        gmscore_apk = os.path.join(self.sys_root, "priv-app", "GmsCore", "GmsCore.apk")
        fakestore_apk = os.path.join(self.sys_root, "priv-app", "FakeStore", "FakeStore.apk")
        launcher_perm = os.path.join(self.sys_root, "etc", "permissions", "privapp-permissions-ioslauncher.xml")
        microg_perm = os.path.join(self.sys_root, "etc", "permissions", "privapp-permissions-microg.xml")
        skipappkill = os.path.join(self.sys_root, "etc", "skipappkill.prop")

        for fpath in (launcher_apk, gmscore_apk, fakestore_apk, launcher_perm, microg_perm, skipappkill):
            self.assertTrue(os.path.isfile(fpath), f"File {fpath} must exist")
            self.assertGreater(os.path.getsize(fpath), 0, f"File {fpath} must not be empty")

    def test_03_power_optimizer_preserves_launcher_and_hardware(self):
        """Validating that PowerOptimizer protects both launcher and automotive services."""
        optimizer = PowerOptimizer()
        protected = optimizer.get_protected_packages()

        # Essential hardware
        self.assertIn("com.ts.main.radio", protected)
        self.assertIn("com.syu.canbus", protected)
        self.assertIn("com.roco.canbus", protected)
        self.assertIn("com.ts.car", protected)
        self.assertIn("com.syu.bt", protected)
        self.assertIn("com.ts.camera", protected)

        # Launcher package
        self.assertIn("com.qf001.ioslauncher", protected)

        # MicroG packages
        self.assertIn("com.google.android.gms", protected)
        self.assertIn("com.android.vending", protected)

        # skipappkill.prop syntax
        prop = optimizer.generate_skipappkill_prop()
        self.assertIn("com.qf001.ioslauncher=true", prop)
        self.assertIn("com.ts.main.radio=true", prop)


if __name__ == "__main__":
    unittest.main()
