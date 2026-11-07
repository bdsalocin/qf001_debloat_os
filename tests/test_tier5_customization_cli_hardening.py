"""Tier 5 Adversarial Coverage Hardening Test Suite for Customization & CLI.

Target Source Modules:
- src/customization/launcher.py (IOSLauncherConfig)
- src/customization/microg.py (PowerOptimizer, MicroGConfig)
- src/cli/main.py (Unified CLI toolchain, CLIReporter, locate_system_root, all 6 subcommands)

Adversarial Testing Vectors:
1. Customization Layout, Manifest, and Permissions Boundary & Stress Testing
2. MicroG and Power Management Invariant Hardening & Corruption Resilience
3. CLI Reporter, Argument Parser, and System Root Discovery Heuristics
4. CLI Subcommand Error Branches, Edge Conditions, and Exit Codes
5. Cross-Stage Pipeline Abort and Intermediate Failure Propagation
"""

from __future__ import annotations

import contextlib
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
from unittest.mock import MagicMock, patch, mock_open

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.customization.launcher import IOSLauncherConfig
from src.customization.microg import MicroGConfig, PowerOptimizer, MicroGError, MicroGInjectionError
from src.domain.safety_validator import SafetyValidator
from tests.e2e.test_helpers import (
    create_mock_system_fs,
    create_mock_update_zip,
    create_valid_sparse_file,
)

import src.cli.main as cli_main
from src.cli.main import (
    CLIReporter,
    locate_system_root,
    cmd_unpack,
    cmd_debloat,
    cmd_customize,
    cmd_pack,
    cmd_verify,
    cmd_build_all,
    main,
    EXIT_SUCCESS,
    EXIT_ERROR,
    EXIT_USAGE_ERROR,
    EXIT_MCU_VIOLATION,
    EXIT_HARDWARE_VIOLATION,
    EXIT_VERIFICATION_FAILURE,
    MAX_FAT32_BYTES,
)


class TestLauncherEdgeConditionsHardening(unittest.TestCase):
    """Adversarial stress and edge condition hardening for IOSLauncherConfig."""

    def test_01_layout_unusual_parameters_and_types(self) -> None:
        """Adversarial: layout generation survives unusual types, empty values, and custom chips."""
        # Extreme driver side values
        for ds in ["left", "right", "center", "lhd", "rhd", "", "driver_custom_123"]:
            layout = IOSLauncherConfig.generate_layout(driver_side=ds)
            self.assertEqual(layout["dock_position"], f"driver_side_{ds}")
            self.assertEqual(len(layout["dock"]), 5)
            self.assertEqual(len(layout["tiles"]), 6)
            self.assertIn("primary_navigation", layout["widgets"])
            self.assertIn("media_hub", layout["widgets"])

        # Non-standard chips
        layout_custom_ic = IOSLauncherConfig.generate_layout(tuner_ic="SI47920", dsp_ic="AK7738")
        radio_dock = [d for d in layout_custom_ic["dock"] if d.get("action") == "radio"][0]
        self.assertEqual(radio_dock["hardware_binding"], "SI47920")
        settings_dock = [d for d in layout_custom_ic["dock"] if d.get("action") == "settings"][0]
        self.assertEqual(settings_dock["hardware_binding"], "AK7738")

        # Serializability
        dumped = json.dumps(layout_custom_ic, ensure_ascii=False)
        self.assertGreater(len(dumped), 100)
        reloaded = json.loads(dumped)
        self.assertEqual(reloaded["schema_version"], "1.0")
        self.assertEqual(reloaded["orientation"], "landscape")
        self.assertEqual(reloaded["screen_resolution"], "1280x720")

    def test_02_layout_tile_and_widget_referential_integrity(self) -> None:
        """Adversarial: all tile widget references resolve to valid widgets in layout."""
        layout = IOSLauncherConfig.generate_layout()
        widgets = layout["widgets"]
        for tile in layout["tiles"]:
            ref = tile.get("widget_ref")
            if ref:
                self.assertIn(ref, widgets, f"Widget ref '{ref}' missing from widgets dict")

        # Status bar indicators check
        indicators = layout["status_bar"]["indicators"]
        types = [ind["type"] for ind in indicators]
        self.assertIn("clock", types)
        self.assertIn("wifi", types)
        self.assertIn("bluetooth", types)
        self.assertIn("cellular", types)
        self.assertIn("gps", types)
        self.assertIn("dsp_status", types)

    def test_03_generate_manifest_boundary_values(self) -> None:
        """Adversarial: manifest generation handles custom packages, extreme priorities, and XML structure."""
        priorities = [-99999, -1, 0, 1, 100, 99999]
        for prio in priorities:
            manifest = IOSLauncherConfig.generate_manifest(package_name="org.custom.launcher", priority=prio)
            root = ET.fromstring(manifest)
            self.assertEqual(root.attrib.get("package"), "org.custom.launcher")
            act = root.find(".//activity")
            self.assertIsNotNone(act)
            filt = act.find("intent-filter")
            self.assertIsNotNone(filt)
            prio_attr = filt.attrib.get("{http://schemas.android.com/apk/res/android}priority")
            self.assertEqual(int(prio_attr), prio)

            # Check intent categories
            categories = [c.attrib.get("{http://schemas.android.com/apk/res/android}name") for c in filt.findall("category")]
            self.assertIn("android.intent.category.HOME", categories)
            self.assertIn("android.intent.category.DEFAULT", categories)

        # Fallback to default PACKAGE_NAME if None or empty
        manifest_none = IOSLauncherConfig.generate_manifest(package_name=None)
        root_none = ET.fromstring(manifest_none)
        self.assertEqual(root_none.attrib.get("package"), IOSLauncherConfig.PACKAGE_NAME)

        manifest_empty = IOSLauncherConfig.generate_manifest(package_name="")
        root_empty = ET.fromstring(manifest_empty)
        self.assertEqual(root_empty.attrib.get("package"), IOSLauncherConfig.PACKAGE_NAME)

    def test_04_generate_permissions_xml_boundary(self) -> None:
        """Adversarial: privapp permissions XML conforms to XML schema with custom and default packages."""
        xml_default = IOSLauncherConfig.generate_permissions_xml()
        root_default = ET.fromstring(xml_default)
        priv_default = root_default.find("privapp-permissions")
        self.assertIsNotNone(priv_default)
        self.assertEqual(priv_default.attrib.get("package"), IOSLauncherConfig.PACKAGE_NAME)

        xml_custom = IOSLauncherConfig.generate_permissions_xml(package_name="com.test.carlauncher")
        root_custom = ET.fromstring(xml_custom)
        priv_custom = root_custom.find("privapp-permissions")
        self.assertIsNotNone(priv_custom)
        self.assertEqual(priv_custom.attrib.get("package"), "com.test.carlauncher")

    def test_05_inject_into_system_path_objects_and_collisions(self) -> None:
        """Adversarial: inject_into_system handles Path objects, file collisions, and verify APK binary."""
        with tempfile.TemporaryDirectory() as td:
            sys_root_path = Path(td) / "system"
            sys_root_path.mkdir(parents=True, exist_ok=True)

            # Pass as pathlib.Path object
            self.assertTrue(IOSLauncherConfig.inject_into_system(sys_root_path))

            apk_path = sys_root_path / "priv-app" / "IOSLauncher" / "IOSLauncher.apk"
            self.assertTrue(apk_path.is_file())
            self.assertTrue(zipfile.is_zipfile(apk_path))

            with zipfile.ZipFile(apk_path, "r") as zf:
                dex_bytes = zf.read("classes.dex")
                self.assertTrue(dex_bytes.startswith(b"dex\n035\x00"))
                arsc_bytes = zf.read("resources.arsc")
                self.assertTrue(arsc_bytes.startswith(b"\x02\x00\x0c\x00"))
                layout_bytes = zf.read("res/raw/layout.json")
                layout_obj = json.loads(layout_bytes.decode("utf-8"))
                self.assertEqual(layout_obj["orientation"], "landscape")

            # Path collision: etc/permissions is a regular file
            col_dir = Path(td) / "collision_test"
            col_dir.mkdir(parents=True, exist_ok=True)
            etc_dir = col_dir / "etc"
            etc_dir.mkdir(parents=True, exist_ok=True)
            (etc_dir / "permissions").write_text("file_not_dir", encoding="utf-8")
            self.assertFalse(IOSLauncherConfig.inject_into_system(col_dir))

    def test_06_launcher_instance_vs_class_parity(self) -> None:
        """Authoritative: verify IOSLauncherConfig instance matches class attributes."""
        inst = IOSLauncherConfig(
            package_name="com.my.launcher",
            app_name="MyLauncher",
            driver_side="right",
            theme="ios_dark",
            tuner_ic="TDA7708_REV2",
            dsp_ic="BU32107_REV2",
        )
        self.assertEqual(inst.package_name, "com.my.launcher")
        self.assertEqual(inst.app_name, "MyLauncher")
        self.assertEqual(inst.driver_side, "right")
        self.assertEqual(inst.theme, "ios_dark")
        self.assertEqual(inst.tuner_ic, "TDA7708_REV2")
        self.assertEqual(inst.dsp_ic, "BU32107_REV2")
        self.assertEqual(inst.home_category, "android.intent.category.HOME")
        self.assertEqual(inst.default_category, "android.intent.category.DEFAULT")
        self.assertEqual(inst.priority, 100)


class TestMicroGPowerManagementHardening(unittest.TestCase):
    """Adversarial stress and edge condition hardening for MicroGConfig and PowerOptimizer."""

    def test_01_power_optimizer_malformed_json_config(self) -> None:
        """Adversarial: PowerOptimizer survives malformed JSON and corrupted structures in config file."""
        # Non-JSON content
        with patch("builtins.open", mock_open(read_data="INVALID_NOT_JSON")):
            opt = PowerOptimizer()
            pkgs = opt.get_protected_packages()
            self.assertIn("com.ts.main.radio", pkgs)
            self.assertIn("com.syu.canbus", pkgs)

        # JSON with preserved_packages as integer instead of list
        with patch("builtins.open", mock_open(read_data='{"preserved_packages": 12345}')):
            opt2 = PowerOptimizer()
            pkgs2 = opt2.get_protected_packages()
            self.assertIn("com.ts.main.radio", pkgs2)

        # JSON with preserved_packages as empty list
        with patch("builtins.open", mock_open(read_data='{"preserved_packages": []}')):
            opt3 = PowerOptimizer()
            pkgs3 = opt3.get_protected_packages()
            self.assertIn("com.ts.main.radio", pkgs3)

    def test_02_power_optimizer_custom_packages_floor_and_deduplication(self) -> None:
        """Adversarial: Custom lists never exclude core automotive packages and deduplicate inputs."""
        custom_input = ["com.app.one", "com.ts.car", "com.app.two", "com.app.one"]
        opt = PowerOptimizer(protected_packages=custom_input)
        pkgs = opt.get_protected_packages()

        # Duplicates stripped
        self.assertEqual(len(pkgs), len(set(pkgs)))
        self.assertIn("com.app.one", pkgs)
        self.assertIn("com.app.two", pkgs)

        # Mandatory hardware daemons invariant
        for core in PowerOptimizer.CORE_AUTOMOTIVE_PACKAGES:
            self.assertIn(core, pkgs, f"Core hardware package '{core}' must never be omitted")

    def test_03_skipappkill_prop_format_and_syntax(self) -> None:
        """Adversarial: verify skipappkill.prop conforms strictly to property syntax."""
        opt = PowerOptimizer()
        prop = opt.generate_skipappkill_prop()
        self.assertTrue(prop.endswith("\n"))
        self.assertNotIn("\r", prop)

        lines = [line.strip() for line in prop.split("\n") if line.strip() and not line.startswith("#")]
        sys_line = [l for l in lines if l.startswith("sys.skipappkill=")][0]
        persist_line = [l for l in lines if l.startswith("persist.sys.skipappkill=")][0]

        csv_sys = sys_line.split("=", 1)[1].split(",")
        csv_persist = persist_line.split("=", 1)[1].split(",")
        self.assertEqual(csv_sys, csv_persist)

        flag_lines = [l for l in lines if l.endswith("=true")]
        flag_pkgs = [l.split("=", 1)[0] for l in flag_lines]
        self.assertEqual(sorted(set(csv_sys)), sorted(set(flag_pkgs)))

    def test_04_microg_signature_spoofing_grants(self) -> None:
        """Adversarial: permissions XML grants FAKE_PACKAGE_SIGNATURE to GmsCore and FakeStore."""
        xml_content = MicroGConfig.generate_permissions_xml()
        root = ET.fromstring(xml_content)
        self.assertEqual(root.tag, "permissions")

        gms_blocks = [b for b in root.findall("privapp-permissions") if b.attrib.get("package") == "com.google.android.gms"]
        self.assertEqual(len(gms_blocks), 1)
        gms_perms = [p.attrib.get("name") for p in gms_blocks[0].findall("permission")]
        self.assertIn("android.permission.FAKE_PACKAGE_SIGNATURE", gms_perms)
        self.assertIn("android.permission.ACCESS_FINE_LOCATION", gms_perms)

        vending_blocks = [b for b in root.findall("privapp-permissions") if b.attrib.get("package") == "com.android.vending"]
        self.assertEqual(len(vending_blocks), 1)
        vending_perms = [p.attrib.get("name") for p in vending_blocks[0].findall("permission")]
        self.assertIn("android.permission.FAKE_PACKAGE_SIGNATURE", vending_perms)

        gsf_blocks = [b for b in root.findall("privapp-permissions") if b.attrib.get("package") == "com.google.android.gsf"]
        self.assertEqual(len(gsf_blocks), 1)

    def test_05_microg_verify_injection_comprehensive_matrix(self) -> None:
        """Adversarial: verify_injection accurately flags missing, empty, or incomplete components."""
        with tempfile.TemporaryDirectory() as td:
            sys_root = create_mock_system_fs(td)

            # Prior to injection: incomplete
            is_ok, missing = MicroGConfig.verify_injection(sys_root)
            self.assertFalse(is_ok)
            self.assertGreater(len(missing), 0)

            # Injected: complete
            self.assertTrue(MicroGConfig.inject_into_system(sys_root))
            is_ok2, missing2 = MicroGConfig.verify_injection(sys_root)
            self.assertTrue(is_ok2)
            self.assertEqual(missing2, [])

            # Corrupt FakeStore.apk to zero bytes
            fakestore_apk = os.path.join(sys_root, "priv-app", "FakeStore", "FakeStore.apk")
            with open(fakestore_apk, "wb") as f:
                f.truncate(0)

            is_ok3, missing3 = MicroGConfig.verify_injection(sys_root)
            self.assertFalse(is_ok3)
            self.assertTrue(any("FakeStore.apk" in m for m in missing3))

            # Non-existent system root returns system_root_missing
            is_ok4, missing4 = MicroGConfig.verify_injection(os.path.join(td, "missing_root"))
            self.assertFalse(is_ok4)
            self.assertIn("system_root_missing", missing4)

            # Empty string returns system_root_missing
            is_ok5, missing5 = MicroGConfig.verify_injection("")
            self.assertFalse(is_ok5)
            self.assertIn("system_root_missing", missing5)


class TestCLIReporterAndHelpersHardening(unittest.TestCase):
    """Adversarial stress on CLIReporter output channels and locate_system_root heuristics."""

    def test_01_cli_reporter_quiet_vs_verbose_channels(self) -> None:
        """Adversarial: quiet flag suppresses standard output but preserves critical error output."""
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()

        with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
            reporter = CLIReporter(verbose=False, quiet=True)
            reporter.info("Ignored info")
            reporter.success("Ignored success")
            reporter.warn("Ignored warn")
            reporter.debug("Ignored debug")
            reporter.header("Ignored header")
            reporter.banner()
            # Critical error MUST print to stderr even in quiet mode
            reporter.error("Critical error message")

        self.assertEqual(stdout_buf.getvalue(), "")
        self.assertIn("[ERREUR] Critical error message", stderr_buf.getvalue())

        # Verbose mode emits debug messages
        stdout_v = io.StringIO()
        with contextlib.redirect_stdout(stdout_v):
            rep_v = CLIReporter(verbose=True, quiet=False)
            rep_v.debug("Debug payload")
        self.assertIn("[DEBUG] Debug payload", stdout_v.getvalue())

    def test_02_locate_system_root_heuristics_matrix(self) -> None:
        """Adversarial: locate_system_root resolves varied layout patterns correctly."""
        with tempfile.TemporaryDirectory() as td:
            # Pattern A: Flat with priv-app
            flat_dir = os.path.join(td, "flat_dir")
            os.makedirs(os.path.join(flat_dir, "priv-app"), exist_ok=True)
            self.assertEqual(locate_system_root(flat_dir), os.path.abspath(flat_dir))

            # Pattern B: Nested system/priv-app
            nested_dir = os.path.join(td, "nested_dir")
            os.makedirs(os.path.join(nested_dir, "system", "priv-app"), exist_ok=True)
            self.assertEqual(locate_system_root(nested_dir), os.path.abspath(os.path.join(nested_dir, "system")))

            # Pattern C: Nested firmware/system/app
            fw_dir = os.path.join(td, "fw_dir")
            os.makedirs(os.path.join(fw_dir, "firmware", "system", "app"), exist_ok=True)
            self.assertEqual(locate_system_root(fw_dir), os.path.abspath(os.path.join(fw_dir, "firmware", "system")))

            # Pattern D: Fallback to base_dir
            empty_dir = os.path.join(td, "empty_dir")
            os.makedirs(empty_dir, exist_ok=True)
            self.assertEqual(locate_system_root(empty_dir), os.path.abspath(empty_dir))


class TestCLISubcommandsErrorBranchesHardening(unittest.TestCase):
    """Adversarial coverage for untested error branches and exit codes in src/cli/main.py."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.work_dir = self.tmpdir.name

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def run_cli(self, args: list[str] | None = None) -> tuple[int, str, str]:
        """Runs the CLI main() with captured stdout and stderr."""
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                exit_code = main(args)
        except SystemExit as e:
            exit_code = int(e.code)
        return exit_code, stdout_buf.getvalue(), stderr_buf.getvalue()

    def test_01_unpack_raw_img_copy_and_unsparse_failure(self) -> None:
        """Adversarial: unpack raw .img file copies directly; unsparse failure returns code 1."""
        raw_img = os.path.join(self.work_dir, "boot.raw.img")
        with open(raw_img, "wb") as f:
            f.write(b"RAW_BOOT_PAYLOAD" * 64)

        out_dir = os.path.join(self.work_dir, "extracted_raw")
        rc, out, _ = self.run_cli(["-q", "unpack", raw_img, "-o", out_dir])
        self.assertEqual(rc, EXIT_SUCCESS)
        dest_img = os.path.join(out_dir, "boot.raw.img")
        self.assertTrue(os.path.isfile(dest_img))

        # Test SparseImage.unsparse returning False
        sparse_img = os.path.join(self.work_dir, "system.sparse.img")
        create_valid_sparse_file(sparse_img)

        with patch("src.cli.main.SparseImage.unsparse", return_value=False):
            rc_fail, _, err = self.run_cli(["-q", "unpack", sparse_img, "-o", os.path.join(self.work_dir, "out_fail")])
            self.assertEqual(rc_fail, EXIT_ERROR)
            self.assertIn("Echec de la conversion", err)

    def test_02_unpack_directory_target_unsupported(self) -> None:
        """Adversarial: unpack fails cleanly with code 1 if input target is a directory."""
        dir_input = os.path.join(self.work_dir, "some_dir")
        os.makedirs(dir_input, exist_ok=True)
        rc, _, err = self.run_cli(["-q", "unpack", dir_input])
        self.assertEqual(rc, EXIT_ERROR)
        self.assertIn("non pris en charge", err)

    def test_03_debloat_custom_json_and_exception_handling(self) -> None:
        """Adversarial: debloat handles custom JSON formats, malformed JSON, and Debloater errors."""
        sys_dir = create_mock_system_fs(self.work_dir)

        # 1. Custom blacklist JSON with nested 'packages' key
        bl_file = os.path.join(self.work_dir, "custom_bl.json")
        with open(bl_file, "w", encoding="utf-8") as f:
            json.dump({"packages": ["com.baidu.BaiduMap"]}, f)

        rc, _, _ = self.run_cli(["-q", "debloat", sys_dir, "-b", bl_file, "--dry-run"])
        self.assertEqual(rc, EXIT_SUCCESS)

        # 2. Debloater core exception returns EXIT_ERROR
        with patch("src.cli.main.Debloater.debloat_filesystem", side_effect=RuntimeError("Disk failure")):
            rc_err, _, err = self.run_cli(["-q", "debloat", sys_dir])
            self.assertEqual(rc_err, EXIT_ERROR)
            self.assertIn("Erreur critique", err)

    def test_04_debloat_with_warnings_in_report_still_proceeds(self) -> None:
        """Adversarial: debloat with report.errors displays warnings and validates hardware."""
        sys_dir = create_mock_system_fs(self.work_dir)
        mock_report = MagicMock()
        mock_report.total_scanned_apps = 10
        mock_report.removed_count = 2
        mock_report.removed_packages = ["com.bloat.one", "com.bloat.two"]
        mock_report.preserved_count = 6
        mock_report.preserved_packages = ["com.ts.main.radio"]
        mock_report.bytes_freed = 2048576
        mock_report.errors = ["Non-fatal permission glitch on stub"]

        with patch("src.cli.main.Debloater.debloat_filesystem", return_value=mock_report):
            rc, out, err = self.run_cli(["debloat", sys_dir])
            self.assertEqual(rc, EXIT_SUCCESS)
            self.assertIn("Non-fatal permission glitch", err)

    def test_05_customize_subcommand_flags_and_failure_branches(self) -> None:
        """Adversarial: customize handles mutually exclusive flags, driver side, and injection failures."""
        sys_dir = create_mock_system_fs(self.work_dir)

        # 1. Both --launcher-only and --microg-only passed simultaneously
        rc1, _, _ = self.run_cli(["-q", "customize", sys_dir, "--launcher-only", "--microg-only"])
        self.assertEqual(rc1, EXIT_SUCCESS)

        # 2. Custom driver-side right and theme
        rc2, out2, _ = self.run_cli(["customize", sys_dir, "--launcher-only", "--driver-side", "right", "--theme", "dark_car"])
        self.assertEqual(rc2, EXIT_SUCCESS)
        self.assertIn("cote right", out2)

        # 3. Launcher injection returns False
        with patch("src.cli.main.IOSLauncherConfig.inject_into_system", return_value=False):
            rc3, _, err3 = self.run_cli(["-q", "customize", sys_dir, "--launcher-only"])
            self.assertEqual(rc3, EXIT_ERROR)
            self.assertIn("Echec de l injection du lanceur", err3)

        # 4. Launcher injection raises Exception
        with patch("src.cli.main.IOSLauncherConfig.inject_into_system", side_effect=OSError("Read-only")):
            rc4, _, err4 = self.run_cli(["-q", "customize", sys_dir, "--launcher-only"])
            self.assertEqual(rc4, EXIT_ERROR)
            self.assertIn("Erreur lors de l injection du lanceur", err4)

        # 5. MicroG injection returns False
        with patch("src.cli.main.MicroGConfig.inject_into_system", return_value=False):
            rc5, _, err5 = self.run_cli(["-q", "customize", sys_dir, "--microg-only"])
            self.assertEqual(rc5, EXIT_ERROR)
            self.assertIn("Echec de l injection de la suite MicroG", err5)

        # 6. MicroG injection raises Exception
        with patch("src.cli.main.MicroGConfig.inject_into_system", side_effect=OSError("Disk full")):
            rc6, _, err6 = self.run_cli(["-q", "customize", sys_dir, "--microg-only"])
            self.assertEqual(rc6, EXIT_ERROR)
            self.assertIn("Erreur lors de l injection de MicroG", err6)

        # 7. Target is a file instead of directory
        file_target = os.path.join(self.work_dir, "target_file.txt")
        with open(file_target, "w") as f:
            f.write("text")
        rc7, _, err7 = self.run_cli(["-q", "customize", file_target])
        self.assertEqual(rc7, EXIT_ERROR)
        self.assertIn("introuvable", err7)

    def test_06_pack_subcommand_fallback_and_multi_partition(self) -> None:
        """Adversarial: pack handles multiple .img files and PackageBuilder fallback."""
        pack_src = os.path.join(self.work_dir, "pack_src")
        os.makedirs(pack_src, exist_ok=True)
        with open(os.path.join(pack_src, "system.img"), "wb") as f:
            f.write(b"SYSTEM_IMG" * 32)
        with open(os.path.join(pack_src, "vendor.img"), "wb") as f:
            f.write(b"VENDOR_IMG" * 32)

        out_zip = os.path.join(self.work_dir, "multi_update.zip")

        # Test with PackageBuilder = None (fallback path using FirmwarePacker directly)
        with patch.object(cli_main, "PackageBuilder", None):
            rc, out, _ = self.run_cli(["-q", "pack", pack_src, "-o", out_zip, "--no-sign"])
            self.assertEqual(rc, EXIT_SUCCESS)
            self.assertTrue(os.path.isfile(out_zip))
            with zipfile.ZipFile(out_zip, "r") as zf:
                names = zf.namelist()
                self.assertIn("system.img", names)
                self.assertIn("vendor.img", names)

    def test_07_pack_post_packaging_mcu_violation_purges_zip(self) -> None:
        """Adversarial: pack purges output and returns code 3 if MCU artifact detected post-pack."""
        pack_src = os.path.join(self.work_dir, "clean_src")
        os.makedirs(pack_src, exist_ok=True)
        with open(os.path.join(pack_src, "system.img"), "wb") as f:
            f.write(b"CLEAN" * 32)

        out_zip = os.path.join(self.work_dir, "mcu_trap_update.zip")

        # Simulate MCUGuard.scan_archive detecting violation after packaging
        with patch("src.cli.main.MCUGuard.scan_archive", return_value=(False, ["mcu_trap_in_zip.bin"])):
            rc, _, err = self.run_cli(["-q", "pack", pack_src, "-o", out_zip, "--no-sign"])
            self.assertEqual(rc, EXIT_MCU_VIOLATION)
            self.assertTrue("MCU" in err or "mcu" in err.lower())
            self.assertFalse(os.path.exists(out_zip), "Contaminated zip must be purged")

    def test_08_verify_subcommand_flag_permutations(self) -> None:
        """Adversarial: verify options --mcu-only, --hardware-only, and --signature-only matrix."""
        # 1. Directory with MCU artifact but --hardware-only passed (MCU check skipped)
        sys_dir = create_mock_system_fs(self.work_dir)
        mcu_file = os.path.join(sys_dir, "etc", "mcu.bin")
        os.makedirs(os.path.dirname(mcu_file), exist_ok=True)
        with open(mcu_file, "wb") as f:
            f.write(b"MCU_BIN")

        rc1, _, _ = self.run_cli(["-q", "verify", sys_dir, "--hardware-only"])
        self.assertEqual(rc1, EXIT_SUCCESS, "--hardware-only must skip MCU audit")

        # 2. Directory missing automotive radio but --mcu-only passed (Hardware check skipped)
        empty_dir = os.path.join(self.work_dir, "empty_dir")
        os.makedirs(empty_dir, exist_ok=True)
        rc2, _, _ = self.run_cli(["-q", "verify", empty_dir, "--mcu-only"])
        self.assertEqual(rc2, EXIT_SUCCESS, "--mcu-only must skip hardware audit")

        # 3. Directory with --signature-only passed (both MCU and hardware checks skipped)
        rc3, _, _ = self.run_cli(["-q", "verify", empty_dir, "--signature-only"])
        self.assertEqual(rc3, EXIT_SUCCESS)

        # 4. ZIP archive with --hardware-only passed (skips MCU and signature checks)
        unsigned_zip = os.path.join(self.work_dir, "unsigned.zip")
        create_mock_update_zip(unsigned_zip, {"boot.img": b"BOOT"})
        rc4, _, _ = self.run_cli(["-q", "verify", unsigned_zip, "--hardware-only"])
        self.assertEqual(rc4, EXIT_SUCCESS)

        # 5. ZIP archive with --mcu-only passed (skips signature check)
        rc5, _, _ = self.run_cli(["-q", "verify", unsigned_zip, "--mcu-only"])
        self.assertEqual(rc5, EXIT_SUCCESS)

        # 6. Target is neither zip nor directory
        txt_target = os.path.join(self.work_dir, "readme.txt")
        with open(txt_target, "w") as f:
            f.write("text")
        rc6, _, err6 = self.run_cli(["-q", "verify", txt_target])
        self.assertEqual(rc6, EXIT_ERROR)
        self.assertIn("Cible non traitable", err6)

    def test_09_build_all_intermediate_stage_failure_propagation(self) -> None:
        """Adversarial: failure at each stage of build-all cleanly propagates code and cleans staging."""
        # Create a valid stock zip with all preserved automotive services
        sys_fs = create_mock_system_fs(self.work_dir)
        stock_zip = os.path.join(self.work_dir, "valid_stock.zip")
        files = {}
        for r, _, fs in os.walk(sys_fs):
            for f in fs:
                full = os.path.join(r, f)
                rel = os.path.relpath(full, self.work_dir)
                with open(full, "rb") as fp:
                    files[rel] = fp.read()
        create_mock_update_zip(stock_zip, files)

        out_zip = os.path.join(self.work_dir, "update.zip")

        # Stage 2 failure: debloat returns error
        with patch("src.cli.main.cmd_debloat", return_value=EXIT_ERROR):
            rc_d, _, err_d = self.run_cli(["-q", "build-all", stock_zip, "-o", out_zip])
            self.assertEqual(rc_d, EXIT_ERROR)
            self.assertIn("Interruption du pipeline a l etape de debloating", err_d)
            self.assertFalse(os.path.exists(out_zip))

        # Stage 3 failure: customize returns error
        with patch("src.cli.main.cmd_customize", return_value=EXIT_ERROR):
            rc_c, _, err_c = self.run_cli(["-q", "build-all", stock_zip, "-o", out_zip])
            self.assertEqual(rc_c, EXIT_ERROR)
            self.assertIn("Interruption du pipeline a l etape de personnalisation", err_c)
            self.assertFalse(os.path.exists(out_zip))

        # Stage 4 failure: verify returns hardware violation (code 4)
        with patch("src.cli.main.cmd_verify", return_value=EXIT_HARDWARE_VIOLATION):
            rc_v, _, err_v = self.run_cli(["-q", "build-all", stock_zip, "-o", out_zip])
            self.assertEqual(rc_v, EXIT_HARDWARE_VIOLATION)
            self.assertIn("Interruption du pipeline a l etape de verification", err_v)
            self.assertFalse(os.path.exists(out_zip))

        # Stage 5 failure: pack returns MCU violation (code 3)
        with patch("src.cli.main.cmd_pack", return_value=EXIT_MCU_VIOLATION):
            rc_p, _, err_p = self.run_cli(["-q", "build-all", stock_zip, "-o", out_zip])
            self.assertEqual(rc_p, EXIT_MCU_VIOLATION)
            self.assertIn("Interruption du pipeline a l etape d emballage", err_p)
            self.assertFalse(os.path.exists(out_zip))

    def test_10_main_keyboard_interrupt_and_traceback_hardening(self) -> None:
        """Adversarial: KeyboardInterrupt and unexpected exceptions in main() handled gracefully."""
        # 1. KeyboardInterrupt
        with patch("src.cli.main.cmd_unpack", side_effect=KeyboardInterrupt):
            rc_ki, _, err_ki = self.run_cli(["unpack", "some_file.zip"])
            self.assertEqual(rc_ki, EXIT_ERROR)
            self.assertIn("interrompue par l utilisateur", err_ki)

        # 2. Unexpected RuntimeError without --verbose
        with patch("src.cli.main.cmd_unpack", side_effect=RuntimeError("Unexpected fault")):
            rc_re, _, err_re = self.run_cli(["unpack", "some_file.zip"])
            self.assertEqual(rc_re, EXIT_ERROR)
            self.assertIn("Erreur inattendue", err_re)
            self.assertNotIn("Traceback", err_re)

        # 3. Unexpected RuntimeError WITH --verbose emits traceback
        with patch("src.cli.main.cmd_unpack", side_effect=RuntimeError("Verbose fault")):
            rc_v, _, err_v = self.run_cli(["-v", "unpack", "some_file.zip"])
            self.assertEqual(rc_v, EXIT_ERROR)
            self.assertIn("Erreur inattendue", err_v)
            self.assertIn("Traceback", err_v)


class TestCrossCustomizationAndSafetyValidatorHardening(unittest.TestCase):
    """Adversarial testing of cross-module customization coexistence with safety invariants."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_01_coexistence_and_hardware_preservation(self) -> None:
        """Adversarial: injecting both launcher and MicroG keeps all hardware daemons 100% intact."""
        self.assertTrue(IOSLauncherConfig.inject_into_system(self.sys_root))
        self.assertTrue(MicroGConfig.inject_into_system(self.sys_root))

        validator = SafetyValidator(raise_on_error=True)
        res = validator.verify_preserved_services(self.sys_root)
        self.assertTrue(res.is_valid)
        self.assertEqual(len(res.violations), 0)

        for core_pkg in PowerOptimizer.CORE_AUTOMOTIVE_PACKAGES:
            self.assertIn(core_pkg, res.verified_services)

    def test_02_xml_coexistence_and_parsing(self) -> None:
        """Adversarial: privapp permissions XMLs for both modules coexist and parse cleanly."""
        self.assertTrue(IOSLauncherConfig.inject_into_system(self.sys_root))
        self.assertTrue(MicroGConfig.inject_into_system(self.sys_root))

        perm_dir = os.path.join(self.sys_root, "etc", "permissions")
        launcher_perm = os.path.join(perm_dir, "privapp-permissions-ioslauncher.xml")
        microg_perm = os.path.join(perm_dir, "privapp-permissions-microg.xml")

        self.assertTrue(os.path.isfile(launcher_perm))
        self.assertTrue(os.path.isfile(microg_perm))

        root_launcher = ET.parse(launcher_perm).getroot()
        self.assertEqual(root_launcher.tag, "permissions")
        root_microg = ET.parse(microg_perm).getroot()
        self.assertEqual(root_microg.tag, "permissions")

    def test_03_skipappkill_coexistence(self) -> None:
        """Adversarial: skipappkill.prop protects both custom launcher and MicroG services."""
        self.assertTrue(IOSLauncherConfig.inject_into_system(self.sys_root))
        self.assertTrue(MicroGConfig.inject_into_system(self.sys_root))

        prop_file = os.path.join(self.sys_root, "etc", "skipappkill.prop")
        self.assertTrue(os.path.isfile(prop_file))

        with open(prop_file, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("com.qf001.ioslauncher=true", content)
        self.assertIn("com.google.android.gms=true", content)
        self.assertIn("com.ts.main.radio=true", content)
        self.assertIn("com.syu.canbus=true", content)


class TestParserAndPackagingLimitsHardening(unittest.TestCase):
    """Adversarial testing of CLI parser definitions, non-zip extensions, and cert validation."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.work_dir = self.tmpdir.name

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def run_cli(self, args: list[str] | None = None) -> tuple[int, str, str]:
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                exit_code = main(args)
        except SystemExit as e:
            exit_code = int(e.code)
        return exit_code, stdout_buf.getvalue(), stderr_buf.getvalue()

    def test_01_build_parser_options_and_defaults(self) -> None:
        """Authoritative: parser registers all 6 subcommands and canonical defaults."""
        parser = cli_main.build_parser()
        self.assertEqual(parser.prog, "qf001-toolchain")

        # Verify subcommands registered
        subparser_actions = [
            action for action in parser._actions
            if isinstance(action, cli_main.argparse._SubParsersAction)
        ]
        self.assertEqual(len(subparser_actions), 1)
        subcommands = list(subparser_actions[0].choices.keys())
        expected = ["unpack", "debloat", "customize", "pack", "verify", "build-all"]
        for exp in expected:
            self.assertIn(exp, subcommands)

    def test_02_pack_non_zip_extensions_rejected(self) -> None:
        """Adversarial: pack rejects files not ending in .zip."""
        src_dir = os.path.join(self.work_dir, "src")
        os.makedirs(src_dir, exist_ok=True)
        with open(os.path.join(src_dir, "system.img"), "wb") as f:
            f.write(b"DATA")

        for bad_ext in ["out.tar", "out.img", "out.bin", "out"]:
            out_file = os.path.join(self.work_dir, bad_ext)
            rc, _, err = self.run_cli(["-q", "pack", src_dir, "-o", out_file])
            self.assertEqual(rc, EXIT_ERROR)
            self.assertIn(".zip", err)

    def test_03_verify_invalid_cert_fails(self) -> None:
        """Adversarial: verify with non-existent or corrupted certificate returns failure."""
        valid_zip = os.path.join(self.work_dir, "signed.zip")
        create_mock_update_zip(valid_zip, {"boot.img": b"KERNEL"})

        # Pass non-existent certificate
        bad_cert = os.path.join(self.work_dir, "nonexistent.crt")
        rc, _, err = self.run_cli(["-q", "verify", valid_zip, "--cert", bad_cert])
        self.assertIn(rc, [EXIT_ERROR, EXIT_VERIFICATION_FAILURE])

    def test_04_build_all_dry_run_and_skip_customize(self) -> None:
        """Adversarial: build-all completes cleanly with combined dry-run and skip-customize."""
        sys_fs = create_mock_system_fs(self.work_dir)
        stock_zip = os.path.join(self.work_dir, "stock_combined.zip")
        files = {}
        for r, _, fs in os.walk(sys_fs):
            for f in fs:
                full = os.path.join(r, f)
                rel = os.path.relpath(full, self.work_dir)
                with open(full, "rb") as fp:
                    files[rel] = fp.read()
        create_mock_update_zip(stock_zip, files)

        out_zip = os.path.join(self.work_dir, "combined_update.zip")
        rc, out, _ = self.run_cli([
            "-q", "build-all", stock_zip,
            "-o", out_zip,
            "--dry-run",
            "--skip-customize",
            "--no-sign",
        ])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertTrue(os.path.isfile(out_zip))


if __name__ == "__main__":
    unittest.main()
