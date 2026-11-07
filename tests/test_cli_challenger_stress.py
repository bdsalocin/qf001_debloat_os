"""Adversarial stress test suite for Unified CLI (src/cli/main.py).

Authored by Challenger 2 for Milestone 4 (CLI Adversarial Robustness & Pipeline Stress).
Covers:
1. Malformed, missing, and invalid arguments across all 6 subcommands.
2. Non-existent, unreadable, and corrupted filesystem paths.
3. Hostile MCU firmware injection into pack, verify, unpack, and build-all (exit code 3).
4. Missing automotive hardware daemons in debloat, verify, and build-all (exit code 4).
5. Comprehensive end-to-end build-all pipeline execution (clean vs contaminated).
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

import src.cli.main as cli_main
from tests.e2e.test_helpers import (
    create_mock_system_fs,
    create_mock_update_zip,
    create_valid_sparse_file,
)

# Standardized exit codes
EXIT_SUCCESS = cli_main.EXIT_SUCCESS                      # 0
EXIT_ERROR = cli_main.EXIT_ERROR                          # 1
EXIT_USAGE_ERROR = cli_main.EXIT_USAGE_ERROR              # 2
EXIT_MCU_VIOLATION = cli_main.EXIT_MCU_VIOLATION          # 3
EXIT_SAFETY_VIOLATION = getattr(cli_main, "EXIT_HARDWARE_VIOLATION", 4)  # 4
EXIT_HARDWARE_VIOLATION = getattr(cli_main, "EXIT_HARDWARE_VIOLATION", 4)  # 4
EXIT_VERIFICATION_FAILURE = cli_main.EXIT_VERIFICATION_FAILURE  # 5


class CLIStressTestCaseBase(unittest.TestCase):
    """Base test fixture providing temporary workspace and stdout/stderr capture."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.work_dir = self.tmpdir.name

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def run_cli(self, args: Optional[List[str]] = None) -> tuple[int, str, str]:
        """Executes main() with captured stdout and stderr."""
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()

        try:
            with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                exit_code = cli_main.main(args)
        except SystemExit as exc:
            exit_code = int(exc.code)

        return exit_code, stdout_buf.getvalue(), stderr_buf.getvalue()


class TestCLIArgumentsAdversarial(CLIStressTestCaseBase):
    """Stress tests on CLI argument parsing, missing parameters, and invalid choices."""

    def test_01_empty_args_returns_zero(self) -> None:
        """Invoking with empty args or None displays help banner and exits cleanly with 0."""
        rc_none, out_none, _ = self.run_cli(None)
        self.assertEqual(rc_none, EXIT_SUCCESS)
        self.assertIn("QF001 Debloat OS", out_none)

        rc_empty, _, _ = self.run_cli([])
        self.assertEqual(rc_empty, EXIT_SUCCESS)

    def test_02_unknown_global_flag_returns_usage_error(self) -> None:
        """Unknown global flags return exit code 2."""
        rc, _, _ = self.run_cli(["--unrecognized-random-flag"])
        self.assertEqual(rc, EXIT_USAGE_ERROR)

    def test_03_unknown_subcommand_returns_usage_error(self) -> None:
        """Unrecognized subcommand names return exit code 2."""
        rc, _, _ = self.run_cli(["nonexistent-command"])
        self.assertEqual(rc, EXIT_USAGE_ERROR)

    def test_04_missing_positional_args_all_subcommands(self) -> None:
        """Each of the 6 subcommands returns code 2 when required positional args are omitted."""
        subcommands = ["unpack", "debloat", "customize", "pack", "verify", "build-all"]
        for subcmd in subcommands:
            rc, _, err = self.run_cli([subcmd])
            self.assertEqual(
                rc,
                EXIT_USAGE_ERROR,
                f"Subcommand '{subcmd}' without positional args must exit with code 2",
            )

    def test_05_invalid_choice_options_return_usage_error(self) -> None:
        """Passing an invalid choice (e.g. driver side other than left/right) returns code 2."""
        dummy_dir = os.path.join(self.work_dir, "dummy")
        os.makedirs(dummy_dir, exist_ok=True)

        rc1, _, _ = self.run_cli(["customize", dummy_dir, "--driver-side", "center"])
        self.assertEqual(rc1, EXIT_USAGE_ERROR)

        rc2, _, _ = self.run_cli(["build-all", dummy_dir, "--driver-side", "top"])
        self.assertEqual(rc2, EXIT_USAGE_ERROR)

    def test_06_invalid_type_options_return_usage_error(self) -> None:
        """Passing non-integer string to integer options returns code 2."""
        dummy_dir = os.path.join(self.work_dir, "dummy")
        os.makedirs(dummy_dir, exist_ok=True)

        rc, _, _ = self.run_cli(["pack", dummy_dir, "--max-size", "four_gigabytes"])
        self.assertEqual(rc, EXIT_USAGE_ERROR)

    def test_07_subcommands_reject_unknown_flags(self) -> None:
        """Subcommands reject arbitrary unrecognized options with exit code 2."""
        dummy_path = os.path.join(self.work_dir, "dummy")
        os.makedirs(dummy_path, exist_ok=True)

        for subcmd in ["unpack", "debloat", "customize", "pack", "verify", "build-all"]:
            rc, _, _ = self.run_cli([subcmd, dummy_path, "--invalid-flag-1234"])
            self.assertEqual(rc, EXIT_USAGE_ERROR, f"{subcmd} should reject invalid flags")

    def test_08_help_flags_across_subcommands_exit_zero(self) -> None:
        """--help on every subcommand succeeds with code 0."""
        for subcmd in ["unpack", "debloat", "customize", "pack", "verify", "build-all"]:
            rc, out, _ = self.run_cli([subcmd, "--help"])
            self.assertEqual(rc, EXIT_SUCCESS, f"{subcmd} --help must return 0")
            self.assertIn("usage:", out.lower())


class CLINonExistentAndUnreadablePaths(CLIStressTestCaseBase):
    """Stress tests on missing, unreadable, and malformed files or directories."""

    def test_01_nonexistent_paths_across_all_subcommands(self) -> None:
        """Every subcommand gracefully returns exit code 1 when target path does not exist."""
        ghost_path = os.path.join(self.work_dir, "nonexistent_target_path")

        for subcmd in ["unpack", "debloat", "customize", "pack", "verify", "build-all"]:
            rc, _, err = self.run_cli([subcmd, ghost_path])
            self.assertEqual(
                rc,
                EXIT_ERROR,
                f"Subcommand '{subcmd}' on missing path must exit with code 1, got {rc}",
            )
            self.assertIn("introuvable", err.lower() + err)

    def test_02_unreadable_file_handling(self) -> None:
        """Unreadable input files (0o000) are intercepted gracefully without uncaught tracebacks."""
        unreadable_file = os.path.join(self.work_dir, "unreadable.zip")
        with open(unreadable_file, "wb") as f:
            f.write(b"PK\x03\x04" + b"\x00" * 32)
        os.chmod(unreadable_file, 0o000)

        try:
            rc, _, err = self.run_cli(["-q", "unpack", unreadable_file])
            self.assertEqual(rc, EXIT_ERROR)
        finally:
            os.chmod(unreadable_file, 0o666)

    def test_03_unreadable_json_configs_in_debloat(self) -> None:
        """Malformed or unreadable blacklist and whitelist JSON files return code 1."""
        sys_dir = create_mock_system_fs(self.work_dir)

        # Corrupted JSON content
        bad_json = os.path.join(self.work_dir, "bad.json")
        with open(bad_json, "w") as f:
            f.write("{malformed json syntax")

        rc1, _, _ = self.run_cli(["-q", "debloat", sys_dir, "-b", bad_json])
        self.assertEqual(rc1, EXIT_ERROR)

        rc2, _, _ = self.run_cli(["-q", "debloat", sys_dir, "-w", bad_json])
        self.assertEqual(rc2, EXIT_ERROR)

    def test_04_corrupted_zip_archive_unpack(self) -> None:
        """Corrupted ZIP archive passed to unpack returns code 1."""
        corrupt_zip = os.path.join(self.work_dir, "corrupt.zip")
        with open(corrupt_zip, "wb") as f:
            f.write(b"PK\x03\x04\x00\x00_NOT_A_VALID_ZIP")

        rc, _, err = self.run_cli(["-q", "unpack", corrupt_zip])
        self.assertEqual(rc, EXIT_ERROR)

    def test_05_corrupted_sparse_image_unpack(self) -> None:
        """Truncated sparse image passed to unpack returns code 1 without uncaught crash."""
        corrupt_sparse = os.path.join(self.work_dir, "system.sparse.img")
        with open(corrupt_sparse, "wb") as f:
            # Valid sparse header (28 bytes) followed by truncated chunk
            f.write(
                b"\x3a\xff\x26\xed\x01\x00\x00\x00\x1c\x00\x0c\x00\x00\x10\x00\x00"
                b"\x0a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
                b"\xc1\xca\x01\x00"
            )

        rc, _, err = self.run_cli(["-q", "unpack", corrupt_sparse])
        self.assertEqual(rc, EXIT_ERROR)

    def test_06_zip_slip_traversal_unpack_rejection(self) -> None:
        """Malicious ZIP containing path traversal ('../') is vetoed with code 1."""
        slip_zip = os.path.join(self.work_dir, "slip.zip")
        with zipfile.ZipFile(slip_zip, "w") as zf:
            zf.writestr("../traversal_attack.txt", "attack_payload")

        out_dir = os.path.join(self.work_dir, "extract_slip")
        rc, _, err = self.run_cli(["-q", "unpack", slip_zip, "-o", out_dir])
        self.assertEqual(rc, EXIT_ERROR)
        self.assertFalse(os.path.exists(os.path.join(self.work_dir, "traversal_attack.txt")))

    def test_07_verify_on_non_zip_file_fails(self) -> None:
        """verify invoked on regular text or binary file returns code 1."""
        txt_target = os.path.join(self.work_dir, "info.txt")
        with open(txt_target, "w") as f:
            f.write("text content")

        rc, _, _ = self.run_cli(["-q", "verify", txt_target])
        self.assertEqual(rc, EXIT_ERROR)

    def test_08_build_all_corrupt_input_zip(self) -> None:
        """build-all on corrupt input zip returns code 1 and creates no output."""
        bad_zip = os.path.join(self.work_dir, "bad.zip")
        with open(bad_zip, "wb") as f:
            f.write(b"PK_CORRUPTED_BYTES")

        out_zip = os.path.join(self.work_dir, "update.zip")
        rc, _, _ = self.run_cli(["-q", "build-all", bad_zip, "-o", out_zip])
        self.assertEqual(rc, EXIT_ERROR)
        self.assertFalse(os.path.exists(out_zip))

    def test_09_build_all_zero_byte_input(self) -> None:
        """build-all on zero-byte input file exits with code 1 and leaves no output."""
        empty_input = os.path.join(self.work_dir, "empty.zip")
        with open(empty_input, "wb"):
            pass

        out_zip = os.path.join(self.work_dir, "update.zip")
        rc, _, _ = self.run_cli(["-q", "build-all", empty_input, "-o", out_zip])
        self.assertEqual(rc, EXIT_ERROR)
        self.assertFalse(os.path.exists(out_zip))


class TestCLIHostileMCUFirmwareEnforcement(CLIStressTestCaseBase):
    """Stress tests verifying strict MCU isolation (exit code 3) across CLI commands."""

    def test_01_pack_mcu_bin_root_veto_and_purge(self) -> None:
        """pack halts with code 3 and deletes output when mcu.bin is in root."""
        src_dir = os.path.join(self.work_dir, "src_mcu")
        os.makedirs(src_dir, exist_ok=True)
        with open(os.path.join(src_dir, "system.img"), "wb") as f:
            f.write(b"SAFE_DATA" * 64)
        with open(os.path.join(src_dir, "mcu.bin"), "wb") as f:
            f.write(b"HOSTILE_MCU_DATA")

        out_zip = os.path.join(self.work_dir, "update.zip")
        rc, _, err = self.run_cli(["-q", "pack", src_dir, "-o", out_zip])
        self.assertEqual(rc, EXIT_MCU_VIOLATION, "Must return EXIT_MCU_VIOLATION (code 3)")
        self.assertFalse(os.path.exists(out_zip), "No contaminated update.zip on disk")

    def test_02_pack_nested_mcu_artifacts_vetoed(self) -> None:
        """pack halts with code 3 for nested MCU binaries and vendor IC names."""
        nested_traps = [
            "system/etc/mcu.bin",
            "firmware/stm32_mcu.hex",
            "bin/ts8827.bin",
            "scripts/mcu_flash.sh",
        ]
        for trap in nested_traps:
            with tempfile.TemporaryDirectory() as td:
                src_dir = os.path.join(td, "src")
                os.makedirs(src_dir, exist_ok=True)
                with open(os.path.join(src_dir, "system.img"), "wb") as f:
                    f.write(b"SAFE_DATA" * 32)

                trap_path = os.path.join(src_dir, trap)
                os.makedirs(os.path.dirname(trap_path), exist_ok=True)
                with open(trap_path, "wb") as f:
                    f.write(b"TRAP_PAYLOAD")

                out_zip = os.path.join(td, "update.zip")
                rc, _, _ = self.run_cli(["-q", "pack", src_dir, "-o", out_zip])
                self.assertEqual(rc, EXIT_MCU_VIOLATION, f"Trap '{trap}' must return exit code 3")
                self.assertFalse(os.path.exists(out_zip), f"Output zip must not exist for '{trap}'")

    def test_03_verify_directory_with_mcu_artifact_returns_code_3(self) -> None:
        """verify halts with code 3 when target directory contains MCU files."""
        sys_dir = create_mock_system_fs(self.work_dir)
        mcu_trap = os.path.join(sys_dir, "etc", "mcu.bin")
        os.makedirs(os.path.dirname(mcu_trap), exist_ok=True)
        with open(mcu_trap, "wb") as f:
            f.write(b"TRAP")

        rc, _, err = self.run_cli(["-q", "verify", sys_dir])
        self.assertEqual(rc, EXIT_MCU_VIOLATION)

    def test_04_verify_archive_with_mcu_artifact_returns_code_3(self) -> None:
        """verify halts with code 3 when target ZIP archive contains MCU files."""
        poisoned_zip = os.path.join(self.work_dir, "poisoned.zip")
        create_mock_update_zip(poisoned_zip, {
            "system/build.prop": b"ro.product.board=ROCO_K706\n",
            "mcu.bin": b"MCU_PAYLOAD",
        })

        rc, _, err = self.run_cli(["-q", "verify", poisoned_zip])
        self.assertEqual(rc, EXIT_MCU_VIOLATION)

    def test_05_unpack_strict_mcu_returns_code_3(self) -> None:
        """unpack with --strict-mcu immediately halts with code 3 when MCU file is present."""
        poisoned_zip = os.path.join(self.work_dir, "poisoned.zip")
        create_mock_update_zip(poisoned_zip, {
            "system/build.prop": b"ro.product.board=ROCO_K706\n",
            "mcu.bin": b"HOSTILE_MCU",
        })

        out_dir = os.path.join(self.work_dir, "extracted")
        rc, _, _ = self.run_cli(["-q", "unpack", poisoned_zip, "-o", out_dir, "--strict-mcu"])
        self.assertEqual(rc, EXIT_MCU_VIOLATION)

    def test_06_unpack_default_quarantines_mcu_cleanly(self) -> None:
        """unpack in default mode quarantines MCU files into quarantine_mcu/ and returns code 0."""
        poisoned_zip = os.path.join(self.work_dir, "poisoned.zip")
        create_mock_update_zip(poisoned_zip, {
            "system/build.prop": b"ro.product.board=ROCO_K706\n",
            "mcu.bin": b"HOSTILE_MCU",
        })

        out_dir = os.path.join(self.work_dir, "extracted")
        rc, _, _ = self.run_cli(["-q", "unpack", poisoned_zip, "-o", out_dir])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertTrue(os.path.isfile(os.path.join(out_dir, "quarantine_mcu", "mcu.bin")))
        self.assertFalse(os.path.exists(os.path.join(out_dir, "mcu.bin")))

    def test_07_build_all_hostile_mcu_stops_pipeline_code_3(self) -> None:
        """build-all aborts at stage 1 with code 3 and leaves no output zip when input has MCU."""
        poisoned_zip = os.path.join(self.work_dir, "poisoned.zip")
        create_mock_update_zip(poisoned_zip, {
            "system/build.prop": b"ro.product.board=ROCO_K706\n",
            "mcu.bin": b"POISONOUS_MCU_FIRMWARE",
        })

        out_zip = os.path.join(self.work_dir, "update.zip")
        rc, _, _ = self.run_cli(["-q", "build-all", poisoned_zip, "-o", out_zip])
        self.assertEqual(rc, EXIT_MCU_VIOLATION)
        self.assertFalse(os.path.exists(out_zip), "No update.zip must exist when MCU detected")


class TestCLIMissingAutomotiveDaemonsSafety(CLIStressTestCaseBase):
    """Stress tests verifying hardware safety preservation (exit code 4)."""

    def test_01_verify_missing_all_automotive_daemons_returns_code_4(self) -> None:
        """verify returns code 4 when system partition lacks all automotive daemons."""
        empty_sys = os.path.join(self.work_dir, "empty_sys")
        os.makedirs(os.path.join(empty_sys, "app"), exist_ok=True)

        rc, _, err = self.run_cli(["-q", "verify", empty_sys])
        self.assertEqual(rc, EXIT_SAFETY_VIOLATION)

    def test_02_verify_missing_radio_service_returns_code_4(self) -> None:
        """verify returns code 4 when only com.ts.main.radio is missing."""
        pkgs_no_radio = [
            "com.syu.canbus",
            "com.roco.canbus",
            "com.syu.bt",
            "com.ts.camera",
            "com.ts.car",
        ]
        sys_dir = create_mock_system_fs(self.work_dir, installed_packages=pkgs_no_radio)
        rc, _, err = self.run_cli(["-q", "verify", sys_dir])
        self.assertEqual(rc, EXIT_SAFETY_VIOLATION)
        self.assertIn("com.ts.main.radio", err)

    def test_03_verify_missing_canbus_controller_returns_code_4(self) -> None:
        """verify returns code 4 when CAN bus services are missing."""
        pkgs_no_canbus = [
            "com.ts.main.radio",
            "com.syu.bt",
            "com.ts.camera",
            "com.ts.car",
        ]
        sys_dir = create_mock_system_fs(self.work_dir, installed_packages=pkgs_no_canbus)
        rc, _, err = self.run_cli(["-q", "verify", sys_dir])
        self.assertEqual(rc, EXIT_SAFETY_VIOLATION)
        self.assertIn("CAN bus", err)

    def test_04_verify_missing_camera_service_returns_code_4(self) -> None:
        """verify returns code 4 when com.ts.camera is missing."""
        pkgs_no_cam = [
            "com.ts.main.radio",
            "com.syu.canbus",
            "com.syu.bt",
            "com.ts.car",
        ]
        sys_dir = create_mock_system_fs(self.work_dir, installed_packages=pkgs_no_cam)
        rc, _, err = self.run_cli(["-q", "verify", sys_dir])
        self.assertEqual(rc, EXIT_SAFETY_VIOLATION)
        self.assertIn("com.ts.camera", err)

    def test_05_verify_missing_build_prop_returns_code_4(self) -> None:
        """verify returns code 4 when build.prop is absent."""
        sys_dir = create_mock_system_fs(self.work_dir, include_build_prop=False)
        rc, _, err = self.run_cli(["-q", "verify", sys_dir])
        self.assertEqual(rc, EXIT_SAFETY_VIOLATION)
        self.assertIn("build.prop", err)

    def test_06_debloat_missing_radio_service_returns_code_4(self) -> None:
        """debloat halts with code 4 when essential radio service is absent."""
        pkgs_no_radio = [
            "com.syu.canbus",
            "com.syu.bt",
            "com.ts.camera",
            "com.ts.car",
        ]
        sys_dir = create_mock_system_fs(self.work_dir, installed_packages=pkgs_no_radio)
        rc, _, err = self.run_cli(["-q", "debloat", sys_dir])
        self.assertEqual(rc, EXIT_SAFETY_VIOLATION)

    def test_07_debloat_bypass_strict_safety_flag_returns_code_0(self) -> None:
        """debloat with --no-strict-safety bypasses hardware validation and returns code 0."""
        pkgs_no_radio = [
            "com.syu.canbus",
            "com.syu.bt",
            "com.ts.camera",
            "com.ts.car",
        ]
        sys_dir = create_mock_system_fs(self.work_dir, installed_packages=pkgs_no_radio)
        rc, _, _ = self.run_cli(["-q", "debloat", sys_dir, "--no-strict-safety"])
        self.assertEqual(rc, EXIT_SUCCESS)

    def test_08_build_all_missing_hardware_daemons_returns_code_4(self) -> None:
        """build-all aborts at debloat stage with code 4 when input archive lacks radio."""
        pkgs_no_radio = [
            "com.syu.canbus",
            "com.roco.canbus",
            "com.syu.bt",
            "com.ts.camera",
            "com.ts.car",
            "com.baidu.BaiduMap",
        ]
        sys_tree = create_mock_system_fs(self.work_dir, installed_packages=pkgs_no_radio)
        stock_zip = os.path.join(self.work_dir, "stock_no_radio.zip")

        files = {}
        for r, _, fs in os.walk(sys_tree):
            for f in fs:
                full = os.path.join(r, f)
                rel = os.path.relpath(full, self.work_dir)
                with open(full, "rb") as fp:
                    files[rel] = fp.read()
        create_mock_update_zip(stock_zip, files)

        out_zip = os.path.join(self.work_dir, "update.zip")
        rc, _, _ = self.run_cli(["-q", "build-all", stock_zip, "-o", out_zip])
        self.assertEqual(rc, EXIT_SAFETY_VIOLATION)
        self.assertFalse(os.path.exists(out_zip), "No output file should be produced on safety violation")


class TestCLIPipelineEndToEndStress(CLIStressTestCaseBase):
    """Stress tests on end-to-end multi-step pipeline execution and packaging limits."""

    def _prepare_stock_archive(self, destination: str) -> str:
        """Creates a realistic stock firmware archive with bloatwares and hardware daemons."""
        sys_dir = create_mock_system_fs(self.work_dir)
        files = {}
        for r, _, fs in os.walk(sys_dir):
            for f in fs:
                full = os.path.join(r, f)
                rel = os.path.relpath(full, self.work_dir)
                with open(full, "rb") as fp:
                    files[rel] = fp.read()
        create_mock_update_zip(destination, files)
        return destination

    def test_01_build_all_clean_full_pipeline_success(self) -> None:
        """build-all executes complete cycle (unpack -> debloat -> customize -> verify -> pack)."""
        stock_zip = os.path.join(self.work_dir, "stock_firmware.zip")
        self._prepare_stock_archive(stock_zip)

        final_zip = os.path.join(self.work_dir, "clean_update.zip")
        rc, out, _ = self.run_cli([
            "-q", "build-all", stock_zip,
            "-o", final_zip,
            "--no-sign",
        ])
        self.assertEqual(rc, EXIT_SUCCESS, f"Pipeline must exit with 0: {out}")
        self.assertTrue(os.path.isfile(final_zip), "Final update.zip must exist on disk")

        # Inspect resulting zip structure
        with zipfile.ZipFile(final_zip, "r") as zf:
            namelist = zf.namelist()
            # 1. Standard AOSP/Unisoc OTA scripts
            self.assertIn("META-INF/com/google/android/updater-script", namelist)
            # 2. Bloatware purged
            self.assertFalse(any("BaiduMap" in n for n in namelist))
            self.assertFalse(any("tachyon" in n for n in namelist))
            # 3. Preserved automotive services intact
            self.assertTrue(any("com.ts.main.radio" in n for n in namelist))
            self.assertTrue(any("com.syu.canbus" in n for n in namelist))
            # 4. iOS Launcher and MicroG injected
            self.assertTrue(any("IOSLauncher" in n for n in namelist))
            self.assertTrue(any("GmsCore" in n for n in namelist))
            self.assertTrue(any("skipappkill.prop" in n for n in namelist))
            # 5. ZERO MCU artifacts
            self.assertFalse(any("mcu" in n.lower() for n in namelist))

    def test_02_build_all_with_signature_and_verify_signature(self) -> None:
        """build-all with default signing produces cryptographically verifiable package."""
        stock_zip = os.path.join(self.work_dir, "stock.zip")
        self._prepare_stock_archive(stock_zip)

        signed_zip = os.path.join(self.work_dir, "signed_update.zip")
        rc_build, _, _ = self.run_cli(["-q", "build-all", stock_zip, "-o", signed_zip])
        self.assertEqual(rc_build, EXIT_SUCCESS)
        self.assertTrue(os.path.isfile(signed_zip))

        # Run verify --signature-only
        rc_verify, out_verify, _ = self.run_cli(["-q", "verify", signed_zip, "--signature-only"])
        self.assertEqual(rc_verify, EXIT_SUCCESS)

    def test_03_build_all_skip_customize_option(self) -> None:
        """build-all --skip-customize omits iOS launcher and MicroG while completing pipeline."""
        stock_zip = os.path.join(self.work_dir, "stock.zip")
        self._prepare_stock_archive(stock_zip)

        out_zip = os.path.join(self.work_dir, "nocust_update.zip")
        rc, _, _ = self.run_cli([
            "-q", "build-all", stock_zip,
            "-o", out_zip,
            "--skip-customize",
            "--no-sign",
        ])
        self.assertEqual(rc, EXIT_SUCCESS)
        with zipfile.ZipFile(out_zip, "r") as zf:
            namelist = zf.namelist()
            self.assertFalse(any("IOSLauncher" in n for n in namelist))
            self.assertFalse(any("GmsCore" in n for n in namelist))
            self.assertTrue(any("com.ts.main.radio" in n for n in namelist))

    def test_04_build_all_dry_run_option(self) -> None:
        """build-all --dry-run completes pipeline without error."""
        stock_zip = os.path.join(self.work_dir, "stock.zip")
        self._prepare_stock_archive(stock_zip)

        out_zip = os.path.join(self.work_dir, "dry_update.zip")
        rc, _, _ = self.run_cli([
            "-q", "build-all", stock_zip,
            "-o", out_zip,
            "--dry-run",
            "--no-sign",
        ])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertTrue(os.path.isfile(out_zip))

    def test_05_build_all_custom_work_dir_and_keep_flag(self) -> None:
        """build-all --work-dir with --keep-work-dir preserves staging workspace."""
        stock_zip = os.path.join(self.work_dir, "stock.zip")
        self._prepare_stock_archive(stock_zip)

        custom_staging = os.path.join(self.work_dir, "my_custom_staging")
        out_zip = os.path.join(self.work_dir, "update.zip")

        rc, _, _ = self.run_cli([
            "-q", "build-all", stock_zip,
            "-o", out_zip,
            "--work-dir", custom_staging,
            "--keep-work-dir",
            "--no-sign",
        ])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertTrue(os.path.isdir(custom_staging))
        self.assertTrue(os.path.isdir(os.path.join(custom_staging, "extracted")))

    def test_06_pack_fat32_naming_violation_rejected(self) -> None:
        """pack rejects non-zip extensions and illegal FAT32 characters."""
        staging_dir = os.path.join(self.work_dir, "staging")
        os.makedirs(staging_dir, exist_ok=True)
        with open(os.path.join(staging_dir, "system.img"), "wb") as f:
            f.write(b"DATA")

        # Non-zip extension
        rc1, _, _ = self.run_cli(["-q", "pack", staging_dir, "-o", os.path.join(self.work_dir, "out.tar.gz")])
        self.assertEqual(rc1, EXIT_ERROR)

        # Illegal FAT32 characters
        rc2, _, _ = self.run_cli(["-q", "pack", staging_dir, "-o", os.path.join(self.work_dir, "bad*name.zip")])
        self.assertEqual(rc2, EXIT_ERROR)

    def test_07_pack_max_size_breach_purges_output(self) -> None:
        """pack enforces --max-size constraint and purges oversize file from disk."""
        staging_dir = os.path.join(self.work_dir, "staging")
        os.makedirs(staging_dir, exist_ok=True)
        with open(os.path.join(staging_dir, "system.img"), "wb") as f:
            f.write(b"EXTENDED_PAYLOAD_DATA" * 50)

        out_zip = os.path.join(self.work_dir, "overflow.zip")
        # Enforce strict 50-byte maximum size
        rc, _, _ = self.run_cli(["-q", "pack", staging_dir, "-o", out_zip, "--max-size", "50", "--no-sign"])
        self.assertEqual(rc, EXIT_ERROR)
        self.assertFalse(os.path.exists(out_zip), "Overflowed archive must be purged from disk")


if __name__ == "__main__":
    unittest.main()
