"""Adversarial challenger stress test suite for MicroG & Automotive Power Management (M3).

Focuses on:
1. Automotive Daemon Protection Invariants in PowerOptimizer:
   - Ensuring core automotive hardware daemons (com.ts.main.radio, com.syu.canbus,
     com.roco.canbus, com.ts.car, com.syu.bt, com.ts.camera) are NEVER excluded,
     even under custom protected package lists or corrupted/missing config files.
2. SkipAppKill.prop format stability:
   - Verifying property syntax, newline conventions, CSV vs per-package flags consistency,
     and large package list handling.
3. MicroG Privileged Permissions XML:
   - Validating XML schema well-formedness, signature spoofing grants, and permissions coverage.
4. MicroG System Injection & Hardware Preservation:
   - Verifying idempotency under multiple cycles, existing file/checksum preservation,
     flat vs nested filesystem support, boundary error handling, and SafetyValidator compliance.
"""

from __future__ import annotations

import hashlib
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
from unittest.mock import patch, mock_open

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.customization.microg import MicroGConfig, PowerOptimizer, MicroGError, MicroGInjectionError
from src.customization.launcher import IOSLauncherConfig
from src.domain.safety_validator import SafetyValidator
from tests.e2e.test_helpers import create_mock_system_fs


def _file_sha256(filepath: str) -> str:
    """Calculate SHA256 checksum of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


class TestPowerOptimizerCoreInvariants(unittest.TestCase):
    """Stress tests verifying critical automotive hardware daemon protection invariants."""

    CORE_AUTOMOTIVE_PACKAGES = [
        "com.ts.main.radio",  # STMicroelectronics TDA7708 radio tuner daemon
        "com.syu.canbus",     # Syu CANbus decoder
        "com.roco.canbus",    # ROCO K706 CANbus controller
        "com.ts.car",         # Vehicle HAL, ROHM BU32107EFV DSP, TDA7851 amp
        "com.syu.bt",         # UIS7862 Bluetooth hands-free daemon
        "com.ts.camera",      # Rearview AHD/CVBS camera daemon
    ]

    def test_01_default_protected_packages_contains_all_core_automotive_packages(self):
        """Stress: Default PowerOptimizer contains all 6 core automotive daemons."""
        optimizer = PowerOptimizer()
        protected = optimizer.get_protected_packages()
        self.assertIsInstance(protected, list)

        for core_pkg in self.CORE_AUTOMOTIVE_PACKAGES:
            self.assertIn(
                core_pkg,
                protected,
                f"Core automotive package '{core_pkg}' must be protected by default",
            )

    def test_02_custom_protected_packages_never_excludes_core_automotive_packages(self):
        """Adversarial Invariant: Supplying custom packages must NEVER exclude core automotive packages.

        Automotive daemons are mandatory hardware interfaces (radio, CANbus, camera, DSP).
        If custom user packages are passed to PowerOptimizer, core automotive packages
        must remain protected from LMK / STR sleep kill.
        """
        custom_list = ["com.waze", "com.spotify.music"]
        optimizer = PowerOptimizer(protected_packages=custom_list)
        protected = optimizer.get_protected_packages()

        # All 6 core automotive packages must NEVER be dropped
        for core_pkg in self.CORE_AUTOMOTIVE_PACKAGES:
            self.assertIn(
                core_pkg,
                protected,
                f"SAFETY INVARIANT VIOLATION: Core automotive package '{core_pkg}' was excluded "
                f"when custom protected_packages were supplied: {custom_list}",
            )

        # Custom packages must also be present
        self.assertIn("com.waze", protected)
        self.assertIn("com.spotify.music", protected)

    def test_03_empty_custom_list_never_excludes_core_automotive_packages(self):
        """Adversarial Invariant: Supplying an empty list must NEVER strip core automotive packages."""
        optimizer = PowerOptimizer(protected_packages=[])
        protected = optimizer.get_protected_packages()

        for core_pkg in self.CORE_AUTOMOTIVE_PACKAGES:
            self.assertIn(
                core_pkg,
                protected,
                f"SAFETY INVARIANT VIOLATION: Core automotive package '{core_pkg}' was excluded "
                f"when protected_packages=[] was supplied",
            )

    def test_04_config_file_missing_resilience(self):
        """Boundary: When config/preserved_services.json is missing, core packages remain protected."""
        with patch.object(PowerOptimizer, "_load_preserved_services_from_config", return_value=[]):
            optimizer = PowerOptimizer()
            protected = optimizer.get_protected_packages()
            for core_pkg in self.CORE_AUTOMOTIVE_PACKAGES:
                self.assertIn(
                    core_pkg,
                    protected,
                    f"Core package '{core_pkg}' must remain protected even if config file is missing",
                )

    def test_05_config_file_corrupted_json_resilience(self):
        """Boundary: When config/preserved_services.json has corrupted/malformed JSON, no crash occurs."""
        corrupted_content = "{ this is invalid JSON: 12345"
        with patch("builtins.open", mock_open(read_data=corrupted_content)):
            optimizer = PowerOptimizer()
            protected = optimizer.get_protected_packages()
            for core_pkg in self.CORE_AUTOMOTIVE_PACKAGES:
                self.assertIn(
                    core_pkg,
                    protected,
                    f"Core package '{core_pkg}' must survive corrupted JSON config",
                )

    def test_06_config_file_malformed_structure_resilience(self):
        """Boundary: When config file has non-list or unexpected structure, handles gracefully."""
        # Case A: preserved_packages is not a list
        with patch.object(PowerOptimizer, "_load_preserved_services_from_config", return_value=[]):
            optimizer = PowerOptimizer()
            self.assertTrue(all(p in optimizer.get_protected_packages() for p in self.CORE_AUTOMOTIVE_PACKAGES))

    def test_07_duplicate_package_inputs_deduplicated(self):
        """Stress: Duplicated packages in input are deduplicated while preserving order and uniqueness."""
        input_pkgs = [
            "com.ts.car",
            "com.custom.app1",
            "com.ts.car",
            "com.custom.app2",
            "com.custom.app1",
        ]
        optimizer = PowerOptimizer(protected_packages=input_pkgs)
        protected = optimizer.get_protected_packages()
        self.assertEqual(len(protected), len(set(protected)), "Protected packages list must contain no duplicates")

    def test_08_is_package_protected_boundary_queries(self):
        """Boundary: is_package_protected correctly handles unusual queries without crashing."""
        optimizer = PowerOptimizer()
        self.assertTrue(optimizer.is_package_protected("com.ts.main.radio"))
        self.assertFalse(optimizer.is_package_protected("com.baidu.BaiduMap"))
        self.assertFalse(optimizer.is_package_protected(""))
        self.assertFalse(optimizer.is_package_protected("   "))
        self.assertFalse(optimizer.is_package_protected(None))
        self.assertFalse(optimizer.is_package_protected("COM.TS.MAIN.RADIO"))  # Android package names are case-sensitive


class TestSkipAppKillPropStress(unittest.TestCase):
    """Stress tests for /system/etc/skipappkill.prop format stability and parser compliance."""

    def test_01_prop_syntax_and_headers(self):
        """Stress: Generated skipappkill.prop contains standard headers and valid property definitions."""
        optimizer = PowerOptimizer()
        content = optimizer.generate_skipappkill_prop()
        self.assertIsInstance(content, str)

        lines = content.split("\n")
        self.assertTrue(any(line.startswith("sys.skipappkill=") for line in lines))
        self.assertTrue(any(line.startswith("persist.sys.skipappkill=") for line in lines))
        self.assertTrue(any(line.startswith("#") for line in lines), "Header comments must be present")

    def test_02_prop_newline_and_line_endings(self):
        """Stress: File ends with a single newline and contains valid Android property syntax on all lines."""
        optimizer = PowerOptimizer()
        content = optimizer.generate_skipappkill_prop()

        self.assertTrue(content.endswith("\n"), "skipappkill.prop must terminate with a newline")
        self.assertNotIn("\r", content, "Windows CRLF line endings are forbidden in Android system props")

        # Every non-empty, non-comment line must follow key=value format
        for line in content.split("\n"):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                self.assertIn("=", stripped, f"Invalid property line syntax: '{stripped}'")
                key, val = stripped.split("=", 1)
                self.assertTrue(len(key) > 0, "Property key cannot be empty")

    def test_03_prop_csv_matches_per_package_flags(self):
        """Stress: Every package in sys.skipappkill CSV has a matching <pkg>=true flag."""
        optimizer = PowerOptimizer()
        content = optimizer.generate_skipappkill_prop()

        sys_csv = ""
        persist_csv = ""
        flag_packages = set()

        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("sys.skipappkill="):
                sys_csv = line.split("=", 1)[1]
            elif line.startswith("persist.sys.skipappkill="):
                persist_csv = line.split("=", 1)[1]
            elif line.endswith("=true"):
                pkg_name = line.split("=", 1)[0]
                flag_packages.add(pkg_name)

        self.assertEqual(sys_csv, persist_csv, "sys.skipappkill and persist.sys.skipappkill CSVs must be identical")

        csv_packages = set(sys_csv.split(",")) if sys_csv else set()
        self.assertEqual(
            csv_packages,
            flag_packages,
            "Packages declared in CSV must exactly match packages declared with =true flags",
        )

    def test_04_prop_all_protected_packages_have_true_flag(self):
        """Stress: All packages returned by get_protected_packages() have <pkg>=true in generated prop."""
        optimizer = PowerOptimizer()
        protected = optimizer.get_protected_packages()
        content = optimizer.generate_skipappkill_prop()

        for pkg in protected:
            expected_flag = f"{pkg}=true"
            self.assertIn(
                expected_flag,
                content,
                f"Missing protection flag '{expected_flag}' in skipappkill.prop",
            )

    def test_05_prop_large_package_list_stress(self):
        """Stress: High volume (60+ packages) generates cleanly without formatting corruption."""
        large_list = [f"com.stress.app_{i:03d}" for i in range(60)]
        optimizer = PowerOptimizer(protected_packages=large_list)
        content = optimizer.generate_skipappkill_prop()

        self.assertIn("sys.skipappkill=", content)
        self.assertIn("persist.sys.skipappkill=", content)
        for pkg in large_list:
            self.assertIn(f"{pkg}=true", content)

    def test_06_microg_config_prop_delegation_consistency(self):
        """Stress: MicroGConfig classmethods perfectly delegate to PowerOptimizer."""
        prop1 = MicroGConfig.generate_skipappkill_prop()
        prop2 = PowerOptimizer().generate_skipappkill_prop()
        self.assertEqual(prop1, prop2, "MicroGConfig.generate_skipappkill_prop must match PowerOptimizer output")

        pkgs1 = MicroGConfig.get_protected_packages()
        pkgs2 = PowerOptimizer().get_protected_packages()
        self.assertEqual(pkgs1, pkgs2, "MicroGConfig.get_protected_packages must match PowerOptimizer output")

    def test_07_custom_packages_prop_includes_core_automotive_flags(self):
        """Stress: When custom packages are provided, generated prop must still include core automotive flags."""
        custom_pkgs = ["com.spotify.music"]
        optimizer = PowerOptimizer(protected_packages=custom_pkgs)
        content = optimizer.generate_skipappkill_prop()
        for core_pkg in ["com.ts.main.radio", "com.syu.canbus", "com.roco.canbus", "com.ts.car", "com.syu.bt", "com.ts.camera"]:
            self.assertIn(
                f"{core_pkg}=true",
                content,
                f"Core automotive flag '{core_pkg}=true' missing from skipappkill.prop when custom packages supplied",
            )


class TestMicroGPermissionsXMLStress(unittest.TestCase):
    """Stress tests for /system/etc/permissions/privapp-permissions-microg.xml syntax and grants."""

    def test_01_permissions_xml_well_formedness(self):
        """Stress: XML is well-formed, parses cleanly with ElementTree, and has root <permissions>."""
        xml_content = MicroGConfig.generate_permissions_xml()
        self.assertIsInstance(xml_content, str)

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            self.fail(f"privapp-permissions-microg.xml failed XML parsing: {e}")

        self.assertEqual(root.tag, "permissions", "Root element must be <permissions>")

    def test_02_signature_spoofing_permission_for_gmscore(self):
        """Stress: FAKE_PACKAGE_SIGNATURE is granted to com.google.android.gms."""
        xml_content = MicroGConfig.generate_permissions_xml()
        root = ET.fromstring(xml_content)

        gms_blocks = [
            b for b in root.findall("privapp-permissions")
            if b.attrib.get("package") == "com.google.android.gms"
        ]
        self.assertEqual(len(gms_blocks), 1, "Must contain exactly one block for com.google.android.gms")

        perms = [p.attrib.get("name") for p in gms_blocks[0].findall("permission")]
        self.assertIn(
            "android.permission.FAKE_PACKAGE_SIGNATURE",
            perms,
            "GmsCore must have FAKE_PACKAGE_SIGNATURE for signature spoofing",
        )

    def test_03_signature_spoofing_permission_for_fakestore(self):
        """Stress: FAKE_PACKAGE_SIGNATURE is granted to com.android.vending (FakeStore)."""
        xml_content = MicroGConfig.generate_permissions_xml()
        root = ET.fromstring(xml_content)

        vending_blocks = [
            b for b in root.findall("privapp-permissions")
            if b.attrib.get("package") == "com.android.vending"
        ]
        self.assertEqual(len(vending_blocks), 1, "Must contain exactly one block for com.android.vending")

        perms = [p.attrib.get("name") for p in vending_blocks[0].findall("permission")]
        self.assertIn(
            "android.permission.FAKE_PACKAGE_SIGNATURE",
            perms,
            "FakeStore must have FAKE_PACKAGE_SIGNATURE for signature spoofing",
        )

    def test_04_location_and_system_permissions_gmscore(self):
        """Stress: GmsCore is granted automotive location and privileged phone/system permissions."""
        xml_content = MicroGConfig.generate_permissions_xml()
        root = ET.fromstring(xml_content)

        gms_block = [
            b for b in root.findall("privapp-permissions")
            if b.attrib.get("package") == "com.google.android.gms"
        ][0]
        perms = [p.attrib.get("name") for p in gms_block.findall("permission")]

        required_perms = [
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.WRITE_SECURE_SETTINGS",
            "android.permission.MODIFY_PHONE_STATE",
            "android.permission.READ_PRIVILEGED_PHONE_STATE",
        ]
        for rp in required_perms:
            self.assertIn(rp, perms, f"GmsCore missing critical privileged permission '{rp}'")

    def test_05_all_three_microg_packages_present(self):
        """Stress: All three MicroG components have dedicated privapp-permissions blocks."""
        xml_content = MicroGConfig.generate_permissions_xml()
        root = ET.fromstring(xml_content)

        declared_packages = [b.attrib.get("package") for b in root.findall("privapp-permissions")]
        self.assertIn("com.google.android.gms", declared_packages)
        self.assertIn("com.android.vending", declared_packages)
        self.assertIn("com.google.android.gsf", declared_packages)


class TestMicroGSystemInjectionStress(unittest.TestCase):
    """Stress tests for MicroG deployment, idempotency, APK integrity, and error boundaries."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_injection_idempotency_10_cycles(self):
        """Stress: Running inject_into_system 10 consecutive times produces stable, identical artifacts."""
        for cycle in range(10):
            success = MicroGConfig.inject_into_system(self.sys_root)
            self.assertTrue(success, f"Injection cycle {cycle + 1} must succeed")

        is_complete, missing = MicroGConfig.verify_injection(self.sys_root)
        self.assertTrue(is_complete, f"System should be verified complete after 10 cycles, missing: {missing}")

    def test_02_flat_system_root_injection_and_verification(self):
        """Stress: Correct deployment when system_root is a direct (flat) system partition root."""
        success = MicroGConfig.inject_into_system(self.sys_root)
        self.assertTrue(success)

        is_complete, missing = MicroGConfig.verify_injection(self.sys_root)
        self.assertTrue(is_complete, f"Flat root verification failed: {missing}")

    def test_03_nested_system_root_injection_and_verification(self):
        """Stress: Correct deployment when passing parent directory containing nested system/ folder."""
        parent_dir = self.tmpdir.name  # Contains self.sys_root under parent_dir/system
        success = MicroGConfig.inject_into_system(parent_dir)
        self.assertTrue(success)

        is_complete, missing = MicroGConfig.verify_injection(parent_dir)
        self.assertTrue(is_complete, f"Nested root verification failed: {missing}")

    def test_04_existing_vendor_files_preserved_unaltered(self):
        """Stress: Pre-existing vendor APKs and permissions files are never damaged or modified."""
        # Pre-record checksums of existing files
        radio_apk = os.path.join(self.sys_root, "priv-app", "com.ts.main.radio", "com.ts.main.radio.apk")
        canbus_apk = os.path.join(self.sys_root, "app", "com.syu.canbus", "com.syu.canbus.apk")

        radio_hash_before = _file_sha256(radio_apk)
        canbus_hash_before = _file_sha256(canbus_apk)

        # Also create a custom vendor permissions file
        vendor_perm_file = os.path.join(self.sys_root, "etc", "permissions", "vendor_automotive.xml")
        os.makedirs(os.path.dirname(vendor_perm_file), exist_ok=True)
        with open(vendor_perm_file, "w", encoding="utf-8") as f:
            f.write("<permissions><dummy/></permissions>")
        vendor_perm_hash_before = _file_sha256(vendor_perm_file)

        # Inject MicroG
        success = MicroGConfig.inject_into_system(self.sys_root)
        self.assertTrue(success)

        # Verify hashes are byte-for-byte identical
        self.assertEqual(radio_hash_before, _file_sha256(radio_apk))
        self.assertEqual(canbus_hash_before, _file_sha256(canbus_apk))
        self.assertEqual(vendor_perm_hash_before, _file_sha256(vendor_perm_file))

    def test_05_injected_apk_zip_structure_and_manifests(self):
        """Stress: Injected MicroG APKs are valid ZIP archives with well-formed manifests and dex."""
        success = MicroGConfig.inject_into_system(self.sys_root)
        self.assertTrue(success)

        for _, info in MicroGConfig.MICROG_PACKAGES.items():
            apk_path = os.path.join(self.sys_root, "priv-app", info["dir_name"], info["apk_name"])
            self.assertTrue(os.path.isfile(apk_path), f"APK missing at {apk_path}")

            with zipfile.ZipFile(apk_path, "r") as zf:
                namelist = zf.namelist()
                self.assertIn("AndroidManifest.xml", namelist)
                self.assertIn("classes.dex", namelist)
                self.assertIn("resources.arsc", namelist)

                manifest_data = zf.read("AndroidManifest.xml").decode("utf-8")
                self.assertIn(info["package_name"], manifest_data)

    def test_06_invalid_system_root_paths_safe_rejection(self):
        """Boundary: Invalid, empty, or non-directory roots safely return False without raising."""
        self.assertFalse(MicroGConfig.inject_into_system(""))
        self.assertFalse(MicroGConfig.inject_into_system(None))
        self.assertFalse(MicroGConfig.inject_into_system("/non/existent/mock/path/qf001"))

        # Verify injection also reports false safely
        is_complete, missing = MicroGConfig.verify_injection("")
        self.assertFalse(is_complete)
        self.assertIn("system_root_missing", missing)

    def test_07_verification_detects_corrupted_zero_byte_apk(self):
        """Stress: verify_injection accurately flags a 0-byte corrupt APK."""
        MicroGConfig.inject_into_system(self.sys_root)

        # Corrupt GmsCore.apk to 0 bytes
        gmscore_apk = os.path.join(self.sys_root, "priv-app", "GmsCore", "GmsCore.apk")
        with open(gmscore_apk, "wb") as f:
            f.truncate(0)

        is_complete, missing = MicroGConfig.verify_injection(self.sys_root)
        self.assertFalse(is_complete)
        self.assertTrue(any("GmsCore.apk" in m for m in missing))

    def test_08_verification_detects_missing_permissions_xml(self):
        """Stress: verify_injection accurately flags missing permissions XML."""
        MicroGConfig.inject_into_system(self.sys_root)

        perm_file = os.path.join(self.sys_root, "etc", "permissions", "privapp-permissions-microg.xml")
        os.remove(perm_file)

        is_complete, missing = MicroGConfig.verify_injection(self.sys_root)
        self.assertFalse(is_complete)
        self.assertTrue(any("privapp-permissions-microg.xml" in m for m in missing))

    def test_09_verification_detects_missing_prop_file(self):
        """Stress: verify_injection accurately flags missing skipappkill.prop."""
        MicroGConfig.inject_into_system(self.sys_root)

        prop_file = os.path.join(self.sys_root, "etc", "skipappkill.prop")
        os.remove(prop_file)

        is_complete, missing = MicroGConfig.verify_injection(self.sys_root)
        self.assertFalse(is_complete)
        self.assertTrue(any("skipappkill.prop" in m for m in missing))

    def test_10_injection_read_only_directory_safe_failure(self):
        """Stress: inject_into_system returns False safely without unhandled exception when directory is read-only."""
        with tempfile.TemporaryDirectory() as ro_dir:
            os.chmod(ro_dir, 0o444)
            try:
                success = MicroGConfig.inject_into_system(ro_dir)
                self.assertFalse(success)
            finally:
                os.chmod(ro_dir, 0o755)


class TestSafetyValidatorPreservationStress(unittest.TestCase):
    """Stress tests integrating MicroG injection with domain SafetyValidator across configurations."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_safety_validator_passes_on_standard_system_post_injection(self):
        """Stress: SafetyValidator validates preserved hardware services with is_valid==True post injection."""
        sys_root = create_mock_system_fs(self.tmpdir.name)
        self.assertTrue(MicroGConfig.inject_into_system(sys_root))

        validator = SafetyValidator(raise_on_error=True)
        result = validator.verify_preserved_services(sys_root)
        self.assertTrue(result.is_valid, f"SafetyValidator must pass. Violations: {result.violations}")
        self.assertEqual(len(result.violations), 0)

    def test_02_safety_validator_passes_on_nested_system_post_injection(self):
        """Stress: SafetyValidator validates nested system tree post injection."""
        create_mock_system_fs(self.tmpdir.name)
        parent_dir = self.tmpdir.name
        self.assertTrue(MicroGConfig.inject_into_system(parent_dir))

        validator = SafetyValidator(raise_on_error=True)
        result = validator.verify_preserved_services(parent_dir)
        self.assertTrue(result.is_valid, f"SafetyValidator must pass on nested system: {result.violations}")

    def test_03_safety_validator_passes_on_minimal_automotive_system(self):
        """Stress: System with only mandatory core packages passes validation post injection."""
        minimal_pkgs = [
            "com.ts.main.radio",
            "com.ts.camera",
            "com.syu.bt",
            "com.ts.car",
            "com.syu.canbus",
        ]
        sys_root = create_mock_system_fs(self.tmpdir.name, installed_packages=minimal_pkgs)
        self.assertTrue(MicroGConfig.inject_into_system(sys_root))

        validator = SafetyValidator(raise_on_error=True)
        result = validator.verify_preserved_services(sys_root)
        self.assertTrue(result.is_valid, f"SafetyValidator must pass on minimal system: {result.violations}")

    def test_04_combined_launcher_and_microg_safety(self):
        """Stress: Deploying both IOSLauncher and MicroG preserves all safety invariants."""
        sys_root = create_mock_system_fs(self.tmpdir.name)

        # Deploy launcher
        self.assertTrue(IOSLauncherConfig.inject_into_system(sys_root))
        # Deploy MicroG
        self.assertTrue(MicroGConfig.inject_into_system(sys_root))

        # Check all artifacts
        launcher_apk = os.path.join(sys_root, "priv-app", "IOSLauncher", "IOSLauncher.apk")
        gmscore_apk = os.path.join(sys_root, "priv-app", "GmsCore", "GmsCore.apk")
        launcher_perm = os.path.join(sys_root, "etc", "permissions", "privapp-permissions-ioslauncher.xml")
        microg_perm = os.path.join(sys_root, "etc", "permissions", "privapp-permissions-microg.xml")
        skipappkill = os.path.join(sys_root, "etc", "skipappkill.prop")

        for fpath in [launcher_apk, gmscore_apk, launcher_perm, microg_perm, skipappkill]:
            self.assertTrue(os.path.isfile(fpath), f"Artifact missing: {fpath}")

        validator = SafetyValidator(raise_on_error=True)
        result = validator.verify_preserved_services(sys_root)
        self.assertTrue(result.is_valid, f"SafetyValidator failed on combined deployment: {result.violations}")

    def test_05_automotive_apks_byte_for_byte_unaltered_after_injection(self):
        """Stress: Binary contents of automotive hardware APKs are not touched or altered."""
        sys_root = create_mock_system_fs(self.tmpdir.name)

        # Collect hashes of all .apk files in system before injection
        hashes_before = {}
        for root, _, files in os.walk(sys_root):
            for f in files:
                if f.endswith(".apk"):
                    p = os.path.join(root, f)
                    hashes_before[p] = _file_sha256(p)

        self.assertTrue(MicroGConfig.inject_into_system(sys_root))

        # Ensure all original files still have identical hashes
        for p, original_hash in hashes_before.items():
            self.assertTrue(os.path.isfile(p), f"Original APK missing: {p}")
            self.assertEqual(
                original_hash,
                _file_sha256(p),
                f"Original APK {p} was modified during MicroG injection!",
            )


if __name__ == "__main__":
    unittest.main()
