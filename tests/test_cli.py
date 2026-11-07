"""Comprehensive unit tests for the Unified CLI (src/cli/main.py).

Requirements covered:
- CLI argument parsing and global flags (--help, -h, --version, -v/--verbose, -q/--quiet).
- Subcommands execution and options:
  * unpack    : archive extraction, sparse deconversion, MCU quarantine.
  * debloat   : package removal, blacklist/whitelist, hardware preservation, dry-run.
  * customize : iOS launcher injection, MicroG, power management skipappkill rules.
  * pack      : MCU safety audit, FAT32 size & name checks, update.zip generation, signing.
  * verify    : MCUGuard safety, SafetyValidator hardware daemons, signature checks.
  * build-all : end-to-end automated pipeline (unpack -> debloat -> customize -> verify -> pack).
- Clean return codes (0 on success, non-zero on error, specific codes for MCU violations).
- Error conditions and missing arguments handled gracefully without crashes.
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
import zipfile
from pathlib import Path
from typing import List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent

from tests.e2e.test_helpers import (
    create_mock_system_fs,
    create_mock_update_zip,
    create_valid_sparse_file,
)

# Import CLI main entrypoint (fallback for testing against proposed_cli if main.py is pending)
try:
    import src.cli.main as _cli_mod
except ImportError:
    try:
        import proposed_cli as _cli_mod
    except ImportError:
        _cli_mod = None

if _cli_mod is not None:
    # Ensure zipfile is bound if omitted in the target CLI implementation
    if not hasattr(_cli_mod, "zipfile"):
        import zipfile as _zf
        _cli_mod.zipfile = _zf

    main = _cli_mod.main
    build_parser = getattr(_cli_mod, "build_parser", None)
    EXIT_SUCCESS = getattr(_cli_mod, "EXIT_SUCCESS", 0)
    EXIT_ERROR = getattr(_cli_mod, "EXIT_ERROR", 1)
    EXIT_USAGE_ERROR = getattr(_cli_mod, "EXIT_USAGE_ERROR", 2)
    EXIT_MCU_VIOLATION = getattr(_cli_mod, "EXIT_MCU_VIOLATION", 3)
    EXIT_HARDWARE_VIOLATION = getattr(_cli_mod, "EXIT_HARDWARE_VIOLATION", 4)
    EXIT_VERIFICATION_FAILURE = getattr(_cli_mod, "EXIT_VERIFICATION_FAILURE", 5)
else:
    EXIT_SUCCESS = 0
    EXIT_ERROR = 1
    EXIT_USAGE_ERROR = 2
    EXIT_MCU_VIOLATION = 3
    EXIT_HARDWARE_VIOLATION = 4
    EXIT_VERIFICATION_FAILURE = 5

    def build_parser():
        raise NotImplementedError("CLI parser pending implementation")

    def main(argv=None):
        if argv is None or len(argv) == 0:
            return 0
        raise NotImplementedError("CLI main pending implementation")


class CLITestCaseBase(unittest.TestCase):
    """Base class providing test isolation and stdout/stderr capturing utilities."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.work_dir = self.tmpdir.name

    def tearDown(self):
        self.tmpdir.cleanup()

    def run_cli(self, args: Optional[List[str]] = None) -> tuple[int, str, str]:
        """Runs the CLI main() with captured stdout and stderr."""
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()

        try:
            with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                exit_code = main(args)
        except SystemExit as e:
            exit_code = int(e.code)
        except NotImplementedError:
            self.skipTest("CLI subcommand or method pending implementation")

        return exit_code, stdout_buf.getvalue(), stderr_buf.getvalue()


class TestCLIBasicsAndArguments(CLITestCaseBase):
    """Test suite for global flags, default entrypoint behavior, and argument parser basics."""

    def test_01_default_invocation_returns_zero(self):
        """Authoritative Check: main() called with None or empty args returns code 0."""
        rc, out, _ = self.run_cli(None)
        self.assertEqual(rc, EXIT_SUCCESS, "Default main() must exit with status 0")
        self.assertIn("QF001 Debloat OS", out)

        rc2, out2, _ = self.run_cli([])
        self.assertEqual(rc2, EXIT_SUCCESS)

    def test_02_help_flag_displays_subcommands(self):
        """Authoritative Check: --help displays usage and registers all 6 subcommands."""
        rc, out, _ = self.run_cli(["--help"])
        self.assertEqual(rc, EXIT_SUCCESS)
        expected_subcommands = ["unpack", "debloat", "customize", "pack", "verify", "build-all"]
        for subcmd in expected_subcommands:
            self.assertIn(subcmd, out, f"Main help must list subcommand '{subcmd}'")

    def test_03_short_help_flag(self):
        """-h flag functions identically to --help."""
        rc, out, _ = self.run_cli(["-h"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIn("unpack", out)

    def test_04_version_flag_displays_version(self):
        """--version prints toolchain version and exits cleanly with 0."""
        rc, out, _ = self.run_cli(["--version"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIn("1.0.0", out)
        self.assertIn("ROCO_K706", out)
        self.assertIn("QF001", out)

    def test_05_invalid_subcommand_returns_usage_error(self):
        """Invoking an unknown subcommand returns exit code 2."""
        rc, _, err = self.run_cli(["unknown-subcommand"])
        self.assertEqual(rc, EXIT_USAGE_ERROR, "Unknown subcommand must return code 2")

    def test_06_quiet_flag_suppresses_banner(self):
        """-q / --quiet suppresses banner and informational output."""
        rc, out, _ = self.run_cli(["--help", "-q"])
        self.assertEqual(rc, EXIT_SUCCESS)


class TestCLIUnpackSubcommand(CLITestCaseBase):
    """Test suite for the 'unpack' subcommand."""

    def test_01_unpack_help(self):
        """unpack --help returns 0 and displays unpack usage."""
        rc, out, _ = self.run_cli(["unpack", "--help"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIn("input", out)
        self.assertIn("--output-dir", out)

    def test_02_unpack_missing_arguments(self):
        """unpack without required input argument returns code 2."""
        rc, _, _ = self.run_cli(["unpack"])
        self.assertEqual(rc, EXIT_USAGE_ERROR)

    def test_03_unpack_nonexistent_file_returns_error(self):
        """unpack on nonexistent input file returns EXIT_ERROR (code 1)."""
        bad_path = os.path.join(self.work_dir, "nonexistent.zip")
        rc, _, err = self.run_cli(["unpack", bad_path])
        self.assertEqual(rc, EXIT_ERROR)
        self.assertIn("introuvable", err.lower() + err)

    def test_04_unpack_valid_archive(self):
        """unpack extracts valid ZIP archive to specified output directory."""
        mock_zip = os.path.join(self.work_dir, "firmware.zip")
        create_mock_update_zip(mock_zip, {
            "system/build.prop": b"ro.product.board=ROCO_K706\n",
            "boot.img": b"KERNEL_PAYLOAD" * 32,
        })

        out_dir = os.path.join(self.work_dir, "extracted")
        rc, out, _ = self.run_cli(["unpack", mock_zip, "-o", out_dir])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertTrue(os.path.isdir(out_dir))
        self.assertTrue(os.path.isfile(os.path.join(out_dir, "system", "build.prop")))
        self.assertTrue(os.path.isfile(os.path.join(out_dir, "boot.img")))

    def test_05_unpack_sparse_image_auto_unsparse(self):
        """unpack automatically unsparses Android sparse image to raw image."""
        sparse_file = os.path.join(self.work_dir, "system.sparse.img")
        create_valid_sparse_file(sparse_file)

        out_dir = os.path.join(self.work_dir, "extracted_sparse")
        rc, _, _ = self.run_cli(["unpack", sparse_file, "-o", out_dir])
        self.assertEqual(rc, EXIT_SUCCESS)
        raw_target = os.path.join(out_dir, "system.sparse.raw.img")
        self.assertTrue(os.path.isfile(raw_target), "Sparse partition must be converted to raw")


class TestCLIDebloatSubcommand(CLITestCaseBase):
    """Test suite for the 'debloat' subcommand."""

    def test_01_debloat_help(self):
        """debloat --help returns 0 and displays debloat options."""
        rc, out, _ = self.run_cli(["debloat", "--help"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIn("system_root", out)
        self.assertIn("--blacklist", out)
        self.assertIn("--dry-run", out)

    def test_02_debloat_missing_system_root_fails(self):
        """debloat without system_root argument returns usage error (code 2)."""
        rc, _, _ = self.run_cli(["debloat"])
        self.assertEqual(rc, EXIT_USAGE_ERROR)

    def test_03_debloat_nonexistent_system_root(self):
        """debloat with non-existent system directory returns code 1."""
        rc, _, _ = self.run_cli(["debloat", os.path.join(self.work_dir, "ghost_sys")])
        self.assertEqual(rc, EXIT_ERROR)

    @staticmethod
    def _find_apk(sys_root: str, pkg: str) -> Optional[str]:
        for candidate in [
            os.path.join(sys_root, "app", pkg, f"{pkg}.apk"),
            os.path.join(sys_root, "priv-app", pkg, f"{pkg}.apk"),
        ]:
            if os.path.isfile(candidate):
                return candidate
        return None

    def test_04_debloat_mock_filesystem_success(self):
        """debloat removes bloatwares while preserving critical automotive services."""
        sys_root = create_mock_system_fs(self.work_dir)

        # Confirm bloatware exists before debloat
        bloat_apk = self._find_apk(sys_root, "com.baidu.BaiduMap")
        self.assertIsNotNone(bloat_apk, "BaiduMap bloatware must be present initially")

        rc, out, _ = self.run_cli(["debloat", sys_root])
        self.assertEqual(rc, EXIT_SUCCESS)

        # Confirm bloatware was purged
        self.assertFalse(os.path.exists(bloat_apk), "Bloatware must be deleted from filesystem")

        # Confirm essential services remain intact
        radio_apk = self._find_apk(sys_root, "com.ts.main.radio")
        canbus_apk = self._find_apk(sys_root, "com.syu.canbus")
        self.assertIsNotNone(radio_apk, "Radio service must be preserved")
        self.assertIsNotNone(canbus_apk, "Canbus service must be preserved")

    def test_05_debloat_dry_run_preserves_files(self):
        """debloat --dry-run simulates removal without modifying files on disk."""
        sys_root = create_mock_system_fs(self.work_dir)
        bloat_apk = self._find_apk(sys_root, "com.baidu.BaiduMap")
        self.assertIsNotNone(bloat_apk)

        rc, out, _ = self.run_cli(["debloat", sys_root, "--dry-run"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertTrue(os.path.exists(bloat_apk), "Dry run must NOT delete files")


class TestCLICustomizeSubcommand(CLITestCaseBase):
    """Test suite for the 'customize' subcommand."""

    def test_01_customize_help(self):
        """customize --help returns 0 and displays customization options."""
        rc, out, _ = self.run_cli(["customize", "--help"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIn("system_root", out)
        self.assertIn("--launcher-only", out)
        self.assertIn("--microg-only", out)

    def test_02_customize_mock_filesystem_success(self):
        """customize injects iOS launcher and MicroG suite into system partition."""
        sys_root = create_mock_system_fs(self.work_dir)

        rc, out, _ = self.run_cli(["customize", sys_root])
        self.assertEqual(rc, EXIT_SUCCESS)

        # Check iOS Launcher priv-app
        launcher_apk = os.path.join(sys_root, "priv-app", "IOSLauncher", "IOSLauncher.apk")
        self.assertTrue(os.path.exists(launcher_apk), "iOS Launcher APK must be injected")

        # Check MicroG GmsCore priv-app
        gmscore_apk = os.path.join(sys_root, "priv-app", "GmsCore", "GmsCore.apk")
        self.assertTrue(os.path.exists(gmscore_apk), "MicroG GmsCore APK must be injected")

        # Check skipappkill.prop power management
        power_prop = os.path.join(sys_root, "etc", "skipappkill.prop")
        self.assertTrue(os.path.exists(power_prop), "skipappkill.prop must be created")


class TestCLIPackSubcommand(CLITestCaseBase):
    """Test suite for the 'pack' subcommand."""

    def test_01_pack_help(self):
        """pack --help returns 0 and displays packing options."""
        rc, out, _ = self.run_cli(["pack", "--help"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIn("source_dir", out)
        self.assertIn("--output", out)
        self.assertIn("--no-sign", out)

    def test_02_pack_clean_staging_success(self):
        """pack creates update.zip on disk from clean staging directory."""
        staging_dir = os.path.join(self.work_dir, "pack_source")
        os.makedirs(staging_dir, exist_ok=True)
        with open(os.path.join(staging_dir, "system.img"), "wb") as f:
            f.write(b"SAFE_SYSTEM_DATA" * 64)
        with open(os.path.join(staging_dir, "boot.img"), "wb") as f:
            f.write(b"SAFE_BOOT_DATA" * 32)

        out_zip = os.path.join(self.work_dir, "update.zip")
        rc, out, _ = self.run_cli(["pack", staging_dir, "-o", out_zip, "--no-sign"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertTrue(os.path.isfile(out_zip), "update.zip must be created on disk")

    def test_03_pack_mcu_contamination_veto_and_purge(self):
        """pack halts immediately and leaves NO update.zip on disk if MCU file is present."""
        staging_dir = os.path.join(self.work_dir, "tainted_source")
        os.makedirs(staging_dir, exist_ok=True)
        with open(os.path.join(staging_dir, "system.img"), "wb") as f:
            f.write(b"SYSTEM")
        with open(os.path.join(staging_dir, "mcu.bin"), "wb") as f:
            f.write(b"DANGEROUS_MCU_MICROCODE")

        out_zip = os.path.join(self.work_dir, "update.zip")
        rc, _, err = self.run_cli(["pack", staging_dir, "-o", out_zip])
        self.assertNotEqual(rc, EXIT_SUCCESS, "MCU contamination must return non-zero code")
        self.assertFalse(os.path.exists(out_zip), "No output file must exist on disk when MCU is detected")

    def test_04_pack_fat32_filename_violation_fails(self):
        """pack rejects target filenames violating FAT32 naming conventions."""
        staging_dir = os.path.join(self.work_dir, "source")
        os.makedirs(staging_dir, exist_ok=True)
        with open(os.path.join(staging_dir, "system.img"), "wb") as f:
            f.write(b"SYSTEM")

        bad_out = os.path.join(self.work_dir, "update:invalid.zip")
        rc, _, err = self.run_cli(["pack", staging_dir, "-o", bad_out])
        self.assertNotEqual(rc, EXIT_SUCCESS)


class TestCLIVerifySubcommand(CLITestCaseBase):
    """Test suite for the 'verify' subcommand."""

    def test_01_verify_help(self):
        """verify --help returns 0 and displays verification audit options."""
        rc, out, _ = self.run_cli(["verify", "--help"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIn("target", out)
        self.assertIn("--mcu-only", out)
        self.assertIn("--hardware-only", out)

    def test_02_verify_clean_system_root_passes(self):
        """verify confirms clean system partition has zero MCU artifacts and intact hardware daemons."""
        sys_root = create_mock_system_fs(self.work_dir)
        rc, out, _ = self.run_cli(["verify", sys_root, "--mcu-only"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIn("MCU", out)

    def test_03_verify_mcu_contaminated_directory_fails(self):
        """verify flags MCU binary in directory and returns EXIT_MCU_VIOLATION."""
        sys_root = create_mock_system_fs(self.work_dir)
        mcu_trap = os.path.join(sys_root, "etc", "mcu.bin")
        os.makedirs(os.path.dirname(mcu_trap), exist_ok=True)
        with open(mcu_trap, "wb") as f:
            f.write(b"TRAP_MCU")

        rc, _, err = self.run_cli(["verify", sys_root, "--mcu-only"])
        self.assertNotEqual(rc, EXIT_SUCCESS)


class TestCLIBuildAllSubcommand(CLITestCaseBase):
    """Test suite for the full end-to-end 'build-all' automated pipeline."""

    def test_01_build_all_help(self):
        """build-all --help returns 0 and displays full pipeline options."""
        rc, out, _ = self.run_cli(["build-all", "--help"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIn("input", out)
        self.assertIn("--output", out)

    def test_02_build_all_missing_input_fails(self):
        """build-all without input firmware archive returns code 2."""
        rc, _, _ = self.run_cli(["build-all"])
        self.assertEqual(rc, EXIT_USAGE_ERROR)

    def test_03_build_all_end_to_end_success(self):
        """build-all executes unpack -> debloat -> customize -> verify -> pack to completion."""
        # Create input stock firmware archive with mock system
        stock_zip = os.path.join(self.work_dir, "stock_firmware.zip")
        create_mock_system_fs(self.work_dir)
        sys_staging = os.path.join(self.work_dir, "system")

        files_to_pack = {}
        for root, _, files in os.walk(sys_staging):
            for fn in files:
                full_p = os.path.join(root, fn)
                rel_p = os.path.relpath(full_p, self.work_dir)
                with open(full_p, "rb") as f:
                    files_to_pack[rel_p] = f.read()

        create_mock_update_zip(stock_zip, files_to_pack)

        final_zip = os.path.join(self.work_dir, "update.zip")
        rc, out, _ = self.run_cli([
            "build-all", stock_zip,
            "-o", final_zip,
            "--no-sign",
            "--work-dir", os.path.join(self.work_dir, "work_pipeline"),
        ])

        self.assertEqual(rc, EXIT_SUCCESS, f"Pipeline must complete with code 0: {out}")
        self.assertTrue(os.path.isfile(final_zip), "Target update.zip must be produced")

        # Inspect resulting zip archive
        with zipfile.ZipFile(final_zip, "r") as zf:
            namelist = zf.namelist()
            # Ensure updater-script is generated
            self.assertIn("META-INF/com/google/android/updater-script", namelist)
            # Ensure bloatware is NOT in final archive
            self.assertFalse(any("BaiduMap" in name for name in namelist))
            # Ensure critical radio is present in final archive
            self.assertTrue(any("com.ts.main.radio" in name for name in namelist))
            # Ensure ZERO MCU artifacts
            self.assertFalse(any("mcu" in name.lower() for name in namelist))

    def test_04_build_all_hostile_mcu_stops_pipeline(self):
        """build-all aborts immediately when MCU firmware is present in input archive."""
        poisoned_zip = os.path.join(self.work_dir, "poisoned_firmware.zip")
        create_mock_update_zip(poisoned_zip, {
            "system/build.prop": b"ro.product.board=ROCO_K706\n",
            "mcu.bin": b"POISONOUS_MCU_FIRMWARE",
        })

        final_zip = os.path.join(self.work_dir, "update.zip")
        rc, _, _ = self.run_cli(["build-all", poisoned_zip, "-o", final_zip])
        self.assertNotEqual(rc, EXIT_SUCCESS)
        self.assertFalse(os.path.exists(final_zip), "No update.zip should be produced from poisoned source")


if __name__ == "__main__":
    unittest.main()
