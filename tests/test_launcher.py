"""Comprehensive unit test suite for iOS Launcher & System Customization (Milestone M3).

Covers:
- Feature 10: iOS-Style Launcher Configuration (driver dock, tiles, weather, media, radio)
- Feature 11: Automotive Quick Tiles (radio TDA7708, music, navigation actions)
- Feature 12: Default Home Integration (HOME and DEFAULT intent categories, priority 100, priv-app injection)
- Feature 13: MicroG & Power Management (GmsCore/FakeStore priv-app, signature spoofing XML, skipappkill.prop)
"""

from __future__ import annotations

import io
import json
import os
import shutil
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
from tests.e2e.test_helpers import create_mock_system_fs
from src.domain.safety_validator import SafetyValidator


class TestIOSLauncherLayoutStructure(unittest.TestCase):
    """Unit tests for Feature 10 & 11: iOS-Style Automotive UX Layout & Quick Tiles."""

    def test_01_layout_root_structure(self):
        """Authoritative Check: generate_layout returns dict with dock, tiles, widgets, status_bar."""
        layout = IOSLauncherConfig.generate_layout()
        self.assertIsInstance(layout, dict, "Layout must be a dictionary")
        self.assertIn("dock", layout, "Layout must contain 'dock' key")
        self.assertIn("tiles", layout, "Layout must contain 'tiles' key")
        self.assertIn("widgets", layout, "Layout must contain 'widgets' key")
        self.assertIn("status_bar", layout, "Layout must contain 'status_bar' key")
        self.assertIn("orientation", layout, "Layout must specify screen orientation")
        self.assertEqual(layout.get("orientation"), "landscape")
        self.assertIn("screen_resolution", layout)

    def test_02_driver_dock_essentials(self):
        """Authoritative Check: Driver dock contains vertical shortcuts with >= 2 primary actions."""
        layout = IOSLauncherConfig.generate_layout()
        dock = layout.get("dock", [])
        self.assertIsInstance(dock, list, "Dock must be a list of shortcuts")
        self.assertGreaterEqual(len(dock), 2, "Dock must contain at least 2 primary shortcuts (Scenario 5 requirement)")
        self.assertGreaterEqual(len(dock), 5, "Dock should contain canonical 5 automotive shortcuts")

        dock_actions = [item.get("action") for item in dock]
        self.assertIn("home", dock_actions, "Dock must contain Home shortcut")
        self.assertIn("nav", dock_actions, "Dock must contain Navigation shortcut")
        self.assertIn("music", dock_actions, "Dock must contain Music shortcut")
        self.assertIn("radio", dock_actions, "Dock must contain Radio shortcut")
        self.assertIn("settings", dock_actions, "Dock must contain Vehicle Settings shortcut")

        # Validate mandatory metadata on each dock item
        for item in dock:
            self.assertIn("id", item, "Dock item must have an id")
            self.assertIn("name", item, "Dock item must have a name")
            self.assertIn("type", item, "Dock item must have a type")
            self.assertIn("icon", item, "Dock item must have an icon reference")
            self.assertIn("action", item, "Dock item must have an action")
            self.assertIn("package", item, "Dock item must have a target package")

    def test_03_driver_dock_position_and_hand_drive(self):
        """Authoritative Check: Dock position defaults to driver side and supports LHD/RHD configuration."""
        layout_lhd = IOSLauncherConfig.generate_layout(driver_side="left")
        self.assertIn("left", layout_lhd.get("dock_position", ""))

        layout_rhd = IOSLauncherConfig.generate_layout(driver_side="right")
        self.assertIn("right", layout_rhd.get("dock_position", ""))

    def test_04_quick_tiles_automotive_coverage(self):
        """Authoritative Check (Feature 11): Quick tiles contain essential radio, music, nav actions."""
        layout = IOSLauncherConfig.generate_layout()
        tiles = layout.get("tiles", [])
        self.assertIsInstance(tiles, list)
        self.assertGreaterEqual(len(tiles), 3, "Tiles must contain at least 3 automotive quick tiles")

        tile_types = [t.get("action") or t.get("name") or t.get("type") for t in tiles]
        tile_str = " ".join(str(x).lower() for x in tile_types)

        self.assertIn("radio", tile_str, "Tiles must support radio action")
        self.assertIn("music", tile_str, "Tiles must support music action")
        self.assertIn("nav", tile_str, "Tiles must support nav action")

    def test_05_radio_tile_hardware_binding(self):
        """Authoritative Check: Radio tile references TDA7708 tuner IC and com.ts.main.radio."""
        layout = IOSLauncherConfig.generate_layout()
        tiles = layout.get("tiles", [])
        radio_tiles = [t for t in tiles if t.get("action") == "radio" or t.get("type") == "radio"]
        self.assertGreaterEqual(len(radio_tiles), 1, "Must have at least one dedicated radio tile")

        rt = radio_tiles[0]
        self.assertEqual(rt.get("package"), "com.ts.main.radio")
        self.assertEqual(rt.get("hardware_binding"), "TDA7708")
        self.assertIn("capabilities", rt)
        self.assertIn("frequency_seek", rt.get("capabilities", []))

    def test_06_media_and_weather_tiles(self):
        """Authoritative Check: Media player and weather quick tiles have proper capabilities."""
        layout = IOSLauncherConfig.generate_layout()
        tiles = layout.get("tiles", [])

        music_tiles = [t for t in tiles if t.get("action") == "music" or t.get("type") == "music"]
        self.assertTrue(len(music_tiles) >= 1)
        self.assertIn("playback_controls", music_tiles[0].get("capabilities", []))

        weather_tiles = [t for t in tiles if t.get("action") == "weather" or t.get("type") == "weather"]
        self.assertTrue(len(weather_tiles) >= 1)
        self.assertIn("current_temp", weather_tiles[0].get("capabilities", []))

    def test_07_status_bar_indicators(self):
        """Authoritative Check: Status bar provides 24h clock, connectivity and DSP indicators."""
        layout = IOSLauncherConfig.generate_layout()
        status_bar = layout.get("status_bar", {})
        self.assertTrue(status_bar.get("enabled"))
        self.assertEqual(status_bar.get("clock", {}).get("format"), "24h")

        indicators = [ind.get("type") for ind in status_bar.get("indicators", [])]
        self.assertIn("clock", indicators)
        self.assertIn("wifi", indicators)
        self.assertIn("bluetooth", indicators)
        self.assertIn("cellular", indicators)
        self.assertIn("dsp_status", indicators)

    def test_08_widgets_specifications(self):
        """Authoritative Check: Split-screen widgets include live map navigation and unified media hub."""
        layout = IOSLauncherConfig.generate_layout()
        widgets = layout.get("widgets", {})
        self.assertIn("primary_navigation", widgets)
        self.assertIn("media_hub", widgets)

        nav_w = widgets["primary_navigation"]
        self.assertEqual(nav_w.get("aspect_ratio"), "16:9")
        self.assertTrue(nav_w.get("interactive"))
        self.assertTrue(nav_w.get("split_screen_compatible"))

        hub_w = widgets["media_hub"]
        sources = [s.get("type") for s in hub_w.get("supported_sources", [])]
        self.assertIn("radio", sources)
        self.assertIn("music", sources)


class TestIOSLauncherManifestAndHomeIntent(unittest.TestCase):
    """Unit tests for Feature 12: AndroidManifest.xml and Default HOME Integration."""

    def test_01_manifest_xml_validity(self):
        """Authoritative Check: generate_manifest returns syntactically valid AndroidManifest.xml."""
        manifest_xml = IOSLauncherConfig.generate_manifest()
        self.assertIsInstance(manifest_xml, str)
        root = ET.fromstring(manifest_xml)
        self.assertEqual(root.tag, "manifest")
        self.assertEqual(root.attrib.get("package"), "com.qf001.ioslauncher")

    def test_02_manifest_home_and_default_intent_categories(self):
        """Authoritative Check: Manifest declares HOME and DEFAULT intent categories with priority 100."""
        manifest_xml = IOSLauncherConfig.generate_manifest()
        root = ET.fromstring(manifest_xml)

        activities = root.findall(".//activity")
        self.assertGreaterEqual(len(activities), 1, "Must declare at least one activity")

        main_activity = activities[0]
        self.assertEqual(main_activity.attrib.get("{http://schemas.android.com/apk/res/android}launchMode"), "singleTask")
        self.assertEqual(main_activity.attrib.get("{http://schemas.android.com/apk/res/android}stateNotNeeded"), "true")

        intent_filters = main_activity.findall("intent-filter")
        self.assertGreaterEqual(len(intent_filters), 1)

        filter_elem = intent_filters[0]
        priority = filter_elem.attrib.get("{http://schemas.android.com/apk/res/android}priority")
        self.assertEqual(int(priority), 100, "Intent filter priority must be 100 to override AOSP default home")

        actions = [a.attrib.get("{http://schemas.android.com/apk/res/android}name") for a in filter_elem.findall("action")]
        self.assertIn("android.intent.action.MAIN", actions)

        categories = [c.attrib.get("{http://schemas.android.com/apk/res/android}name") for c in filter_elem.findall("category")]
        self.assertIn("android.intent.category.HOME", categories, "Must register category HOME")
        self.assertIn("android.intent.category.DEFAULT", categories, "Must register category DEFAULT")

    def test_03_launcher_config_attributes_match(self):
        """Authoritative Check: IOSLauncherConfig defines home_category attribute checked by E2E suite."""
        config = IOSLauncherConfig()
        home_intent = getattr(config, "home_category", None)
        self.assertEqual(home_intent, "android.intent.category.HOME")
        default_intent = getattr(config, "default_category", None)
        self.assertEqual(default_intent, "android.intent.category.DEFAULT")
        priority = getattr(config, "priority", None)
        self.assertEqual(priority, 100)

        # Check class level attributes as well
        self.assertEqual(IOSLauncherConfig.home_category, "android.intent.category.HOME")
        self.assertEqual(IOSLauncherConfig.default_category, "android.intent.category.DEFAULT")
        self.assertEqual(IOSLauncherConfig.priority, 100)

    def test_04_manifest_privileged_permissions(self):
        """Authoritative Check: Manifest requests required system and window management permissions."""
        manifest_xml = IOSLauncherConfig.generate_manifest()
        root = ET.fromstring(manifest_xml)
        permissions = [
            p.attrib.get("{http://schemas.android.com/apk/res/android}name")
            for p in root.findall("uses-permission")
        ]
        self.assertIn("android.permission.STATUS_BAR", permissions)
        self.assertIn("android.permission.SET_ACTIVITY_WATCHER", permissions)
        self.assertIn("android.permission.INTERNAL_SYSTEM_WINDOW", permissions)


class TestIOSLauncherSystemInjection(unittest.TestCase):
    """Unit tests for Feature 12: Priv-app injection and system partition integration."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_injection_creates_privapp_and_permissions(self):
        """Authoritative Check: inject_into_system installs APK and permissions XML into system tree."""
        success = IOSLauncherConfig.inject_into_system(self.sys_root)
        self.assertTrue(success, "Launcher injection must return True on success")

        # 1. Priv-app folder and APK
        launcher_dir = os.path.join(self.sys_root, "priv-app", "IOSLauncher")
        self.assertTrue(os.path.isdir(launcher_dir), f"Directory {launcher_dir} must exist")

        apk_path = os.path.join(launcher_dir, "IOSLauncher.apk")
        self.assertTrue(os.path.isfile(apk_path), f"APK {apk_path} must exist")

        # 2. Permissions XML in etc/permissions
        perm_path = os.path.join(self.sys_root, "etc", "permissions", "privapp-permissions-ioslauncher.xml")
        self.assertTrue(os.path.isfile(perm_path), f"Permissions XML {perm_path} must exist")

    def test_02_injected_apk_contents_and_format(self):
        """Authoritative Check: Injected IOSLauncher.apk contains valid ZIP structure, manifest, and dex."""
        success = IOSLauncherConfig.inject_into_system(self.sys_root)
        self.assertTrue(success)

        apk_path = os.path.join(self.sys_root, "priv-app", "IOSLauncher", "IOSLauncher.apk")
        with zipfile.ZipFile(apk_path, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("AndroidManifest.xml", namelist)
            self.assertIn("classes.dex", namelist)
            self.assertIn("resources.arsc", namelist)
            self.assertIn("res/raw/layout.json", namelist)

            manifest_content = zf.read("AndroidManifest.xml").decode("utf-8")
            self.assertIn("android.intent.category.HOME", manifest_content)

    def test_03_injected_permissions_xml_validity(self):
        """Authoritative Check: Injected privapp permissions XML is well-formed XML with package entry."""
        success = IOSLauncherConfig.inject_into_system(self.sys_root)
        self.assertTrue(success)

        perm_path = os.path.join(self.sys_root, "etc", "permissions", "privapp-permissions-ioslauncher.xml")
        root = ET.parse(perm_path).getroot()
        self.assertEqual(root.tag, "permissions")

        priv_elem = root.find("privapp-permissions")
        self.assertIsNotNone(priv_elem)
        self.assertEqual(priv_elem.attrib.get("package"), "com.qf001.ioslauncher")

        perm_names = [p.attrib.get("name") for p in priv_elem.findall("permission")]
        self.assertIn("android.permission.STATUS_BAR", perm_names)

    def test_04_injection_idempotency(self):
        """Authoritative Check: Calling inject_into_system multiple times is safe and idempotent."""
        success1 = IOSLauncherConfig.inject_into_system(self.sys_root)
        self.assertTrue(success1)

        success2 = IOSLauncherConfig.inject_into_system(self.sys_root)
        self.assertTrue(success2)

        apk_path = os.path.join(self.sys_root, "priv-app", "IOSLauncher", "IOSLauncher.apk")
        self.assertTrue(os.path.isfile(apk_path))

    def test_05_injection_preserves_hardware_services(self):
        """Authoritative Check: Launcher injection does NOT alter or corrupt preserved hardware packages."""
        success = IOSLauncherConfig.inject_into_system(self.sys_root)
        self.assertTrue(success)

        # Run SafetyValidator on system tree post-injection
        validator = SafetyValidator()
        result = validator.verify_preserved_services(self.sys_root)
        self.assertTrue(result.is_valid if hasattr(result, "is_valid") else bool(result),
                        "Preserved services must remain intact after launcher injection")

    def test_06_injection_handles_nested_system_directory(self):
        """Boundary: Handles path to parent directory containing 'system' subfolder gracefully."""
        parent_dir = self.tmpdir.name
        self.assertTrue(os.path.isdir(os.path.join(parent_dir, "system")))
        success = IOSLauncherConfig.inject_into_system(parent_dir)
        self.assertTrue(success)

        apk_path = os.path.join(parent_dir, "system", "priv-app", "IOSLauncher", "IOSLauncher.apk")
        self.assertTrue(os.path.isfile(apk_path))

    def test_07_injection_invalid_paths(self):
        """Boundary: Invalid, empty, or non-existent paths safely return False without crashing."""
        self.assertFalse(IOSLauncherConfig.inject_into_system(""))
        self.assertFalse(IOSLauncherConfig.inject_into_system(None))
        self.assertFalse(IOSLauncherConfig.inject_into_system("/path/does/not/exist/qf001_mock"))


class TestMicroGAndPowerManagement(unittest.TestCase):
    """Unit tests for Feature 13: MicroG Deployment & Power Management (skipappkill.prop)."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_power_optimizer_default_protected_packages(self):
        """Authoritative Check (Feature 13): PowerOptimizer protects essential automotive daemons."""
        optimizer = PowerOptimizer()
        protected = optimizer.get_protected_packages()
        self.assertIsInstance(protected, list)

        # Must protect radio and canbus (strictly verified by test_r3_05)
        self.assertIn("com.ts.main.radio", protected, "Must protect TDA7708 radio")
        self.assertIn("com.syu.canbus", protected, "Must protect Syu Canbus")

        # Must protect broader automotive hardware daemons
        self.assertIn("com.roco.canbus", protected, "Must protect ROCO Canbus")
        self.assertIn("com.ts.car", protected, "Must protect vehicle audio DSP HAL")
        self.assertIn("com.syu.bt", protected, "Must protect Bluetooth daemon")
        self.assertIn("com.ts.camera", protected, "Must protect reverse camera daemon")

        # Must protect MicroG background packages
        self.assertIn("com.google.android.gms", protected, "Must protect MicroG GmsCore")
        self.assertIn("com.android.vending", protected, "Must protect MicroG FakeStore")

    def test_02_power_optimizer_is_protected_query(self):
        """Authoritative Check: is_package_protected accurately identifies protected daemons."""
        optimizer = PowerOptimizer()
        self.assertTrue(optimizer.is_package_protected("com.ts.main.radio"))
        self.assertTrue(optimizer.is_package_protected("com.syu.canbus"))
        self.assertFalse(optimizer.is_package_protected("com.baidu.BaiduMap"))
        self.assertFalse(optimizer.is_package_protected("com.chinese.telemetry"))

    def test_03_skipappkill_prop_syntax_and_values(self):
        """Authoritative Check: generate_skipappkill_prop generates valid properties syntax with protected daemons."""
        optimizer = PowerOptimizer()
        prop_content = optimizer.generate_skipappkill_prop()
        self.assertIsInstance(prop_content, str)

        # Verify key Unisoc power management property keys
        self.assertIn("sys.skipappkill=", prop_content)
        self.assertIn("persist.sys.skipappkill=", prop_content)

        # Verify protected packages are listed
        self.assertIn("com.ts.main.radio", prop_content)
        self.assertIn("com.syu.canbus", prop_content)
        self.assertIn("com.roco.canbus", prop_content)
        self.assertIn("com.google.android.gms", prop_content)

        # Verify per-package flags
        self.assertIn("com.ts.main.radio=true", prop_content)
        self.assertIn("com.syu.canbus=true", prop_content)

    def test_04_microg_permissions_xml_signature_spoofing(self):
        """Authoritative Check: generate_permissions_xml includes FAKE_PACKAGE_SIGNATURE for MicroG."""
        xml_content = MicroGConfig.generate_permissions_xml()
        self.assertIsInstance(xml_content, str)

        root = ET.fromstring(xml_content)
        self.assertEqual(root.tag, "permissions")

        priv_blocks = root.findall("privapp-permissions")
        packages = [b.attrib.get("package") for b in priv_blocks]
        self.assertIn("com.google.android.gms", packages)
        self.assertIn("com.android.vending", packages)

        # Check FAKE_PACKAGE_SIGNATURE permission
        gms_block = [b for b in priv_blocks if b.attrib.get("package") == "com.google.android.gms"][0]
        gms_perms = [p.attrib.get("name") for p in gms_block.findall("permission")]
        self.assertIn("android.permission.FAKE_PACKAGE_SIGNATURE", gms_perms)
        self.assertIn("android.permission.ACCESS_FINE_LOCATION", gms_perms)

    def test_05_microg_inject_into_system(self):
        """Authoritative Check: MicroGConfig.inject_into_system installs suite, permissions, and skipappkill."""
        success = MicroGConfig.inject_into_system(self.sys_root)
        self.assertTrue(success, "MicroG injection must return True on success")

        # 1. MicroG suite APKs in priv-app
        gmscore_apk = os.path.join(self.sys_root, "priv-app", "GmsCore", "GmsCore.apk")
        fakestore_apk = os.path.join(self.sys_root, "priv-app", "FakeStore", "FakeStore.apk")
        gsfproxy_apk = os.path.join(self.sys_root, "priv-app", "GsfProxy", "GsfProxy.apk")
        self.assertTrue(os.path.isfile(gmscore_apk), f"GmsCore APK must exist at {gmscore_apk}")
        self.assertTrue(os.path.isfile(fakestore_apk), f"FakeStore APK must exist at {fakestore_apk}")
        self.assertTrue(os.path.isfile(gsfproxy_apk), f"GsfProxy APK must exist at {gsfproxy_apk}")

        # 2. Permissions XML
        perm_path = os.path.join(self.sys_root, "etc", "permissions", "privapp-permissions-microg.xml")
        self.assertTrue(os.path.isfile(perm_path), f"Permissions XML must exist at {perm_path}")

        # 3. skipappkill.prop
        prop_path = os.path.join(self.sys_root, "etc", "skipappkill.prop")
        self.assertTrue(os.path.isfile(prop_path), f"skipappkill.prop must exist at {prop_path}")

    def test_06_microg_injected_apk_validity(self):
        """Authoritative Check: MicroG APKs are valid ZIP archives containing manifest and dex."""
        success = MicroGConfig.inject_into_system(self.sys_root)
        self.assertTrue(success)

        gmscore_apk = os.path.join(self.sys_root, "priv-app", "GmsCore", "GmsCore.apk")
        with zipfile.ZipFile(gmscore_apk, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("AndroidManifest.xml", namelist)
            self.assertIn("classes.dex", namelist)
            self.assertIn("resources.arsc", namelist)

    def test_07_microg_injection_idempotency_and_preservation(self):
        """Authoritative Check: Repeated MicroG injection is idempotent and does not break hardware services."""
        self.assertTrue(MicroGConfig.inject_into_system(self.sys_root))
        self.assertTrue(MicroGConfig.inject_into_system(self.sys_root))

        validator = SafetyValidator()
        result = validator.verify_preserved_services(self.sys_root)
        self.assertTrue(result.is_valid if hasattr(result, "is_valid") else bool(result))

    def test_08_microg_injection_invalid_paths(self):
        """Boundary: Non-existent or empty system root paths return False safely."""
        self.assertFalse(MicroGConfig.inject_into_system(""))
        self.assertFalse(MicroGConfig.inject_into_system(None))
        self.assertFalse(MicroGConfig.inject_into_system("/non/existent/path/microg"))


class TestCustomizationIntegrationPipeline(unittest.TestCase):
    """Integration test suite for combined Launcher and MicroG injection into system partition."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_combined_customization_deployment(self):
        """Integration: Deploy launcher and MicroG into the same system tree without conflicts."""
        # 1. Deploy Launcher
        self.assertTrue(IOSLauncherConfig.inject_into_system(self.sys_root))

        # 2. Deploy MicroG suite
        self.assertTrue(MicroGConfig.inject_into_system(self.sys_root))

        # 3. Verify all artifacts coexist
        launcher_apk = os.path.join(self.sys_root, "priv-app", "IOSLauncher", "IOSLauncher.apk")
        gmscore_apk = os.path.join(self.sys_root, "priv-app", "GmsCore", "GmsCore.apk")
        launcher_perm = os.path.join(self.sys_root, "etc", "permissions", "privapp-permissions-ioslauncher.xml")
        microg_perm = os.path.join(self.sys_root, "etc", "permissions", "privapp-permissions-microg.xml")
        skipappkill = os.path.join(self.sys_root, "etc", "skipappkill.prop")

        self.assertTrue(os.path.isfile(launcher_apk))
        self.assertTrue(os.path.isfile(gmscore_apk))
        self.assertTrue(os.path.isfile(launcher_perm))
        self.assertTrue(os.path.isfile(microg_perm))
        self.assertTrue(os.path.isfile(skipappkill))

        # 4. Verify hardware preservation safety validator still passes
        validator = SafetyValidator()
        result = validator.verify_preserved_services(self.sys_root)
        self.assertTrue(result.is_valid if hasattr(result, "is_valid") else bool(result))


if __name__ == "__main__":
    unittest.main()
