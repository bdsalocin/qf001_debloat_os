"""Empirical challenger stress test suite for Milestone 3 Iteration 2.

Evaluates:
1. Multi-step adversarial stress testing of full customization pipeline:
   - Alternating injection of IOSLauncherConfig and MicroGConfig across 5 cycles.
   - Invariant preservation across every single injection step.
2. SafetyValidator().verify_preserved_services(sys_root) 100% preservation across:
   - Standard system partition layout
   - Nested system partition layout
   - Minimal system partition layout
3. Dynamic configuration shifts during alternating cycles:
   - Custom protected packages, empty lists, duplicate lists.
   - Driver side layout permutations.
   - APK and XML binary and structural integrity across repeated overwrites.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

# Project root setup
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.customization.launcher import IOSLauncherConfig
from src.customization.microg import MicroGConfig, PowerOptimizer
from src.domain.safety_validator import SafetyValidator, HardwareSafetyViolationError
from tests.e2e.test_helpers import create_mock_system_fs


def _file_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


class TestAlternatingPipeline5CyclesStress(unittest.TestCase):
    """Stress test: 5 cycles of alternating IOSLauncher and MicroG injection."""

    CORE_AUTOMOTIVE_SERVICES = [
        "com.ts.main.radio",
        "com.ts.camera",
        "com.syu.bt",
        "com.ts.car",
        "com.syu.canbus",
        "com.roco.canbus",
    ]

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _verify_artifacts_and_safety(self, sys_root: str, cycle: int, step_desc: str):
        # 1. SafetyValidator verification
        validator = SafetyValidator(raise_on_error=True)
        result = validator.verify_preserved_services(sys_root)
        self.assertTrue(
            result.is_valid,
            f"SafetyValidator failed at cycle {cycle} ({step_desc}): {result.violations}",
        )
        self.assertEqual(
            len(result.violations),
            0,
            f"Violations detected at cycle {cycle} ({step_desc}): {result.violations}",
        )

        for core_pkg in ["com.ts.main.radio", "com.ts.camera", "com.syu.bt", "com.ts.car"]:
            self.assertIn(
                core_pkg,
                result.verified_services,
                f"Core service '{core_pkg}' missing from verified services at cycle {cycle} ({step_desc})",
            )

        # 2. Launcher artifacts integrity
        launcher_dir = os.path.join(sys_root, "priv-app", "IOSLauncher")
        launcher_apk = os.path.join(launcher_dir, "IOSLauncher.apk")
        manifest_file = os.path.join(launcher_dir, "AndroidManifest.xml")
        layout_file = os.path.join(launcher_dir, "layout.json")
        launcher_perm = os.path.join(
            sys_root, "etc", "permissions", "privapp-permissions-ioslauncher.xml"
        )

        self.assertTrue(os.path.isfile(launcher_apk), f"Launcher APK missing at cycle {cycle}")
        self.assertTrue(os.path.isfile(manifest_file), f"Manifest file missing at cycle {cycle}")
        self.assertTrue(os.path.isfile(layout_file), f"Layout file missing at cycle {cycle}")
        self.assertTrue(os.path.isfile(launcher_perm), f"Launcher perms XML missing at cycle {cycle}")

        self.assertTrue(zipfile.is_zipfile(launcher_apk))
        with zipfile.ZipFile(launcher_apk, "r") as zf:
            self.assertIsNone(zf.testzip())
            names = zf.namelist()
            self.assertIn("AndroidManifest.xml", names)
            self.assertIn("classes.dex", names)
            self.assertIn("res/raw/layout.json", names)

        # 3. MicroG artifacts integrity
        is_complete, missing = MicroGConfig.verify_injection(sys_root)
        self.assertTrue(
            is_complete,
            f"MicroGConfig.verify_injection failed at cycle {cycle} ({step_desc}): {missing}",
        )

        prop_path = os.path.join(sys_root, "etc", "skipappkill.prop")
        self.assertTrue(os.path.isfile(prop_path))
        with open(prop_path, "r", encoding="utf-8") as f:
            prop_content = f.read()

        # Check skipappkill retains core automotive daemons
        for pkg in PowerOptimizer.CORE_AUTOMOTIVE_PACKAGES:
            self.assertIn(
                f"{pkg}=true",
                prop_content,
                f"Core automotive package '{pkg}=true' missing in skipappkill at cycle {cycle} ({step_desc})",
            )

    def test_01_five_alternating_cycles_launcher_then_microg(self):
        """Stress: 5 alternating cycles (Launcher -> MicroG) on standard partition."""
        # Initial pre-injection check
        val_initial = SafetyValidator().verify_preserved_services(self.sys_root)
        self.assertTrue(val_initial.is_valid)

        for cycle in range(1, 6):
            # Step A: Inject Launcher
            ok_launcher = IOSLauncherConfig.inject_into_system(self.sys_root)
            self.assertTrue(ok_launcher, f"IOSLauncher injection failed at cycle {cycle}")

            # Step B: Inject MicroG
            ok_microg = MicroGConfig.inject_into_system(self.sys_root)
            self.assertTrue(ok_microg, f"MicroG injection failed at cycle {cycle}")

            # Verify system integrity and safety invariants after both injections
            self._verify_artifacts_and_safety(self.sys_root, cycle, "Launcher -> MicroG")

    def test_02_five_alternating_cycles_microg_then_launcher(self):
        """Stress: 5 alternating cycles in reverse order (MicroG -> Launcher) on standard partition."""
        for cycle in range(1, 6):
            # Step A: Inject MicroG
            ok_microg = MicroGConfig.inject_into_system(self.sys_root)
            self.assertTrue(ok_microg, f"MicroG injection failed at cycle {cycle}")

            # Step B: Inject Launcher
            ok_launcher = IOSLauncherConfig.inject_into_system(self.sys_root)
            self.assertTrue(ok_launcher, f"IOSLauncher injection failed at cycle {cycle}")

            # Verify system integrity and safety invariants
            self._verify_artifacts_and_safety(self.sys_root, cycle, "MicroG -> Launcher")

    def test_03_alternating_cycles_with_dynamic_power_optimizer_configurations(self):
        """Adversarial Stress: Dynamic configuration parameters across 5 alternating cycles.

        Cycle 1: Default configuration
        Cycle 2: Custom packages ["com.waze", "com.spotify"]
        Cycle 3: Empty custom list [] (must still retain core packages)
        Cycle 4: Duplicate custom list ["com.ts.car", "com.waze", "com.ts.car"]
        Cycle 5: Extended automotive list
        """
        configs = [
            None,
            ["com.waze", "com.spotify"],
            [],
            ["com.ts.car", "com.waze", "com.ts.car"],
            ["com.google.android.apps.maps", "com.android.server.telecom"],
        ]

        for cycle, protected_pkgs in enumerate(configs, start=1):
            ok_l = IOSLauncherConfig.inject_into_system(self.sys_root)
            self.assertTrue(ok_l)

            ok_m = MicroGConfig.inject_into_system(self.sys_root, protected_packages=protected_pkgs)
            self.assertTrue(ok_m)

            self._verify_artifacts_and_safety(
                self.sys_root, cycle, f"Dynamic pkgs={protected_pkgs}"
            )

            # Check that skipappkill.prop accurately reflects any custom packages
            prop_file = os.path.join(self.sys_root, "etc", "skipappkill.prop")
            with open(prop_file, "r", encoding="utf-8") as f:
                content = f.read()

            if protected_pkgs:
                for p in protected_pkgs:
                    self.assertIn(f"{p}=true", content)

    def test_04_original_automotive_packages_byte_integrity_across_5_cycles(self):
        """Invariant: Automotive APK bytes remain strictly identical across 5 cycles."""
        original_apks = {}
        for r, _, files in os.walk(self.sys_root):
            for f in files:
                if f.endswith(".apk"):
                    fp = os.path.join(r, f)
                    original_apks[fp] = _file_sha256(fp)

        self.assertGreater(len(original_apks), 0, "Initial mock system must contain APKs")

        for cycle in range(1, 6):
            IOSLauncherConfig.inject_into_system(self.sys_root)
            MicroGConfig.inject_into_system(self.sys_root)

        for fp, original_hash in original_apks.items():
            self.assertTrue(os.path.isfile(fp), f"Original package disappeared: {fp}")
            self.assertEqual(
                original_hash,
                _file_sha256(fp),
                f"Original automotive package {fp} was mutated across 5 injection cycles",
            )


class TestSafetyValidatorPreservationAcrossLayouts(unittest.TestCase):
    """Stress test: SafetyValidator preservation across standard, nested, and minimal partition layouts."""

    MANDATORY_CORE_PACKAGES = [
        "com.ts.main.radio",
        "com.ts.camera",
        "com.syu.bt",
        "com.ts.car",
    ]

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_standard_system_partition_preservation(self):
        """Stress: Standard system partition layout (priv-app, app, build.prop directly in sys_root)."""
        sys_root = create_mock_system_fs(self.tmpdir.name)

        # 5 alternating cycles on standard layout
        for cycle in range(1, 6):
            self.assertTrue(IOSLauncherConfig.inject_into_system(sys_root))
            self.assertTrue(MicroGConfig.inject_into_system(sys_root))

            val = SafetyValidator(raise_on_error=True)
            res = val.verify_preserved_services(sys_root)
            self.assertTrue(res.is_valid, f"Failed standard layout at cycle {cycle}")
            self.assertEqual(len(res.violations), 0)

            # Ensure 100% of core packages verified
            for pkg in self.MANDATORY_CORE_PACKAGES:
                self.assertIn(pkg, res.verified_services)

    def test_02_nested_system_partition_preservation(self):
        """Stress: Nested system partition layout (parent_dir containing system/priv-app, etc.)."""
        # create_mock_system_fs creates <tmpdir>/system
        create_mock_system_fs(self.tmpdir.name)
        parent_root = self.tmpdir.name  # Nested root

        # 5 alternating cycles targeting parent_root
        for cycle in range(1, 6):
            ok_l = IOSLauncherConfig.inject_into_system(parent_root)
            self.assertTrue(ok_l, f"Launcher injection failed on nested root at cycle {cycle}")

            ok_m = MicroGConfig.inject_into_system(parent_root)
            self.assertTrue(ok_m, f"MicroG injection failed on nested root at cycle {cycle}")

            # Verify SafetyValidator handles nested root seamlessly
            val = SafetyValidator(raise_on_error=True)
            res = val.verify_preserved_services(parent_root)
            self.assertTrue(res.is_valid, f"SafetyValidator failed on nested root at cycle {cycle}")
            self.assertEqual(len(res.violations), 0)

            for pkg in self.MANDATORY_CORE_PACKAGES:
                self.assertIn(pkg, res.verified_services)

            # Also verify launcher and microg files landed in nested /system
            nested_launcher_apk = os.path.join(
                parent_root, "system", "priv-app", "IOSLauncher", "IOSLauncher.apk"
            )
            nested_gmscore_apk = os.path.join(
                parent_root, "system", "priv-app", "GmsCore", "GmsCore.apk"
            )
            nested_skipappkill = os.path.join(
                parent_root, "system", "etc", "skipappkill.prop"
            )

            self.assertTrue(os.path.isfile(nested_launcher_apk))
            self.assertTrue(os.path.isfile(nested_gmscore_apk))
            self.assertTrue(os.path.isfile(nested_skipappkill))

    def test_03_minimal_system_partition_preservation(self):
        """Stress: Minimal system partition containing ONLY essential automotive packages and minimal build.prop."""
        minimal_pkgs = [
            "com.ts.main.radio",
            "com.ts.camera",
            "com.syu.bt",
            "com.ts.car",
            "com.roco.canbus",  # exactly one CANbus controller
        ]
        sys_root = create_mock_system_fs(self.tmpdir.name, installed_packages=minimal_pkgs)

        # Run 5 alternating cycles on minimal partition
        for cycle in range(1, 6):
            self.assertTrue(IOSLauncherConfig.inject_into_system(sys_root))
            self.assertTrue(MicroGConfig.inject_into_system(sys_root))

            val = SafetyValidator(raise_on_error=True)
            res = val.verify_preserved_services(sys_root)
            self.assertTrue(res.is_valid, f"SafetyValidator failed on minimal system at cycle {cycle}")
            self.assertEqual(len(res.violations), 0)

            # Verify all 5 minimal packages are 100% verified
            for pkg in minimal_pkgs:
                self.assertIn(pkg, res.verified_services)

    def test_04_missing_essential_package_causes_rejection_even_after_injections(self):
        """Boundary: Removing an essential automotive package triggers HardwareSafetyViolationError."""
        sys_root = create_mock_system_fs(self.tmpdir.name)

        # Inject customizations
        self.assertTrue(IOSLauncherConfig.inject_into_system(sys_root))
        self.assertTrue(MicroGConfig.inject_into_system(sys_root))

        # Intentionally remove radio tuner service
        radio_dir = os.path.join(sys_root, "priv-app", "com.ts.main.radio")
        if os.path.isdir(radio_dir):
            shutil.rmtree(radio_dir)
        radio_app_dir = os.path.join(sys_root, "app", "com.ts.main.radio")
        if os.path.isdir(radio_app_dir):
            shutil.rmtree(radio_app_dir)

        val = SafetyValidator(raise_on_error=False)
        res = val.verify_preserved_services(sys_root)
        self.assertFalse(res.is_valid)
        self.assertIn("com.ts.main.radio", res.missing_services)

        val_strict = SafetyValidator(raise_on_error=True)
        with self.assertRaises(HardwareSafetyViolationError):
            val_strict.verify_preserved_services(sys_root)


class TestFullCustomizationPipelineAdversarialCornerCases(unittest.TestCase):
    """Stress test: Corner cases and adversarial scenarios in launcher & microg pipeline."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_permissions_xml_schema_and_privapp_tags(self):
        """Adversarial: Ensure XML files written across injections remain parseable by ElementTree."""
        for cycle in range(5):
            IOSLauncherConfig.inject_into_system(self.sys_root)
            MicroGConfig.inject_into_system(self.sys_root)

        launcher_xml = os.path.join(
            self.sys_root, "etc", "permissions", "privapp-permissions-ioslauncher.xml"
        )
        microg_xml = os.path.join(
            self.sys_root, "etc", "permissions", "privapp-permissions-microg.xml"
        )

        tree_l = ET.parse(launcher_xml)
        root_l = tree_l.getroot()
        self.assertEqual(root_l.tag, "permissions")
        priv_l = root_l.find("privapp-permissions")
        self.assertIsNotNone(priv_l)
        self.assertEqual(priv_l.attrib.get("package"), IOSLauncherConfig.PACKAGE_NAME)

        tree_m = ET.parse(microg_xml)
        root_m = tree_m.getroot()
        self.assertEqual(root_m.tag, "permissions")
        priv_pkgs = [p.attrib.get("package") for p in root_m.findall("privapp-permissions")]
        self.assertIn("com.google.android.gms", priv_pkgs)
        self.assertIn("com.android.vending", priv_pkgs)
        self.assertIn("com.google.android.gsf", priv_pkgs)

    def test_02_idempotent_hash_stability(self):
        """Stress: Injecting multiple times produces stable byte content for static templates."""
        IOSLauncherConfig.inject_into_system(self.sys_root)
        MicroGConfig.inject_into_system(self.sys_root)

        launcher_perm = os.path.join(
            self.sys_root, "etc", "permissions", "privapp-permissions-ioslauncher.xml"
        )
        microg_perm = os.path.join(
            self.sys_root, "etc", "permissions", "privapp-permissions-microg.xml"
        )
        skipappkill = os.path.join(self.sys_root, "etc", "skipappkill.prop")

        hash_l = _file_sha256(launcher_perm)
        hash_m = _file_sha256(microg_perm)
        hash_s = _file_sha256(skipappkill)

        # Inject 4 more times
        for _ in range(4):
            IOSLauncherConfig.inject_into_system(self.sys_root)
            MicroGConfig.inject_into_system(self.sys_root)

        self.assertEqual(hash_l, _file_sha256(launcher_perm))
        self.assertEqual(hash_m, _file_sha256(microg_perm))
        self.assertEqual(hash_s, _file_sha256(skipappkill))


if __name__ == "__main__":
    unittest.main()
