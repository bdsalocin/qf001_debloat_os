"""Empirical challenger test suite for SafetyValidator (src/domain/safety_validator.py).

This test suite empirically stresses:
1. Detection of missing automotive services (radio app, Canbus controllers).
2. Detection of damaged / 0-byte APK files across application directories.
3. Verification of build.prop hardware definitions (board name, radio tuner IC, audio DSP IC).
4. Rigorous verification that missing or altered automotive hardware definitions
   and services unconditionally trigger HardwareSafetyViolationError.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from src.domain.safety_validator import (
    SafetyValidator,
    SafetyValidatorError,
    HardwareSafetyViolationError,
    ValidationResult,
)
from tests.e2e.test_helpers import create_mock_system_fs


class TestChallengerMissingAutomotiveServices(unittest.TestCase):
    """Adversarial challenge on missing automotive service detection."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_missing_radio_app_detected_and_raises(self):
        """Missing com.ts.main.radio must fail validation and raise HardwareSafetyViolationError."""
        radio_dir = os.path.join(self.sys_root, "priv-app", "com.ts.main.radio")
        if not os.path.exists(radio_dir):
            radio_dir = os.path.join(self.sys_root, "app", "com.ts.main.radio")
        shutil.rmtree(radio_dir)

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        err = ctx.exception
        self.assertIn("com.ts.main.radio", err.missing_services)
        self.assertTrue(any("com.ts.main.radio" in v for v in err.violations))

    def test_missing_both_canbus_controllers_detected_and_raises(self):
        """Missing all CAN bus controllers must fail validation and raise HardwareSafetyViolationError."""
        for pkg in ["com.roco.canbus", "com.syu.canbus"]:
            d = os.path.join(self.sys_root, "priv-app", pkg)
            if not os.path.exists(d):
                d = os.path.join(self.sys_root, "app", pkg)
            if os.path.exists(d):
                shutil.rmtree(d)

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        err = ctx.exception
        self.assertTrue(any("CAN" in v for v in err.violations))
        self.assertTrue(
            "com.roco.canbus" in err.missing_services or "com.syu.canbus" in err.missing_services
        )

    def test_missing_one_canbus_in_strict_mode_raises(self):
        """When require_all_canbus=True, missing com.syu.canbus must raise HardwareSafetyViolationError."""
        d = os.path.join(self.sys_root, "priv-app", "com.syu.canbus")
        if not os.path.exists(d):
            d = os.path.join(self.sys_root, "app", "com.syu.canbus")
        if os.path.exists(d):
            shutil.rmtree(d)

        validator = SafetyValidator(require_all_canbus=True)
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        self.assertIn("com.syu.canbus", ctx.exception.missing_services)


class TestChallengerZeroByteApkFiles(unittest.TestCase):
    """Adversarial challenge on zero-byte and damaged APK detection."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_zero_byte_radio_apk_raises_hardware_safety_violation(self):
        """Zero-byte radio APK must be flagged as corrupt and raise HardwareSafetyViolationError."""
        radio_dir = os.path.join(self.sys_root, "priv-app", "com.ts.main.radio")
        if not os.path.exists(radio_dir):
            radio_dir = os.path.join(self.sys_root, "app", "com.ts.main.radio")
        apk_path = os.path.join(radio_dir, "com.ts.main.radio.apk")
        with open(apk_path, "wb") as f:
            f.truncate(0)

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        err = ctx.exception
        self.assertIn("com.ts.main.radio", err.corrupt_services)
        self.assertTrue(any("0 bytes" in v.lower() or "corrupt" in v.lower() for v in err.violations))

    def test_zero_byte_canbus_apk_raises_hardware_safety_violation(self):
        """Zero-byte CAN controller APK must raise HardwareSafetyViolationError."""
        # Keep only com.roco.canbus so it's the sole CAN controller
        syu_dir = os.path.join(self.sys_root, "priv-app", "com.syu.canbus")
        if not os.path.exists(syu_dir):
            syu_dir = os.path.join(self.sys_root, "app", "com.syu.canbus")
        if os.path.exists(syu_dir):
            shutil.rmtree(syu_dir)

        roco_dir = os.path.join(self.sys_root, "priv-app", "com.roco.canbus")
        if not os.path.exists(roco_dir):
            roco_dir = os.path.join(self.sys_root, "app", "com.roco.canbus")
        apk_path = os.path.join(roco_dir, "com.roco.canbus.apk")
        with open(apk_path, "wb") as f:
            f.truncate(0)

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        self.assertIn("com.roco.canbus", ctx.exception.corrupt_services)

    def test_empty_package_dir_without_apk_raises(self):
        """Package directory with no .apk file must raise HardwareSafetyViolationError."""
        radio_dir = os.path.join(self.sys_root, "priv-app", "com.ts.main.radio")
        if not os.path.exists(radio_dir):
            radio_dir = os.path.join(self.sys_root, "app", "com.ts.main.radio")
        for f in os.listdir(radio_dir):
            os.remove(os.path.join(radio_dir, f))

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        self.assertTrue(any("no .apk" in v.lower() for v in ctx.exception.violations))


class TestChallengerBuildPropIntegrity(unittest.TestCase):
    """Adversarial challenge on build.prop hardware properties."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_missing_build_prop_raises(self):
        """Missing build.prop must raise HardwareSafetyViolationError."""
        prop_path = os.path.join(self.sys_root, "build.prop")
        if os.path.exists(prop_path):
            os.remove(prop_path)

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        self.assertTrue(any("build.prop not found" in v for v in ctx.exception.violations))

    def test_altered_board_name_raises(self):
        """Altered ro.product.board must raise HardwareSafetyViolationError."""
        prop_path = os.path.join(self.sys_root, "build.prop")
        with open(prop_path, "w", encoding="utf-8") as f:
            f.write("ro.product.board=FOREIGN_BOARD_XYZ\n")
            f.write("ro.qf001.radio.tuner=TDA7708\n")
            f.write("ro.qf001.audio.dsp=BU32107EFV\n")

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        self.assertTrue(any("board mismatch" in v.lower() for v in ctx.exception.violations))

    def test_missing_board_name_raises(self):
        """Missing ro.product.board must raise HardwareSafetyViolationError."""
        prop_path = os.path.join(self.sys_root, "build.prop")
        with open(prop_path, "w", encoding="utf-8") as f:
            f.write("ro.qf001.radio.tuner=TDA7708\n")
            f.write("ro.qf001.audio.dsp=BU32107EFV\n")

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        self.assertTrue(any("missing required property 'ro.product.board'" in v for v in ctx.exception.violations))

    def test_mismatched_radio_tuner_raises(self):
        """Mismatched ro.qf001.radio.tuner must raise HardwareSafetyViolationError."""
        prop_path = os.path.join(self.sys_root, "build.prop")
        with open(prop_path, "w", encoding="utf-8") as f:
            f.write("ro.product.board=ROCO_K706\n")
            f.write("ro.qf001.radio.tuner=SI4754\n")
            f.write("ro.qf001.audio.dsp=BU32107EFV\n")

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        self.assertTrue(any("radio tuner mismatch" in v.lower() for v in ctx.exception.violations))

    def test_mismatched_audio_dsp_raises(self):
        """Mismatched ro.qf001.audio.dsp must raise HardwareSafetyViolationError."""
        prop_path = os.path.join(self.sys_root, "build.prop")
        with open(prop_path, "w", encoding="utf-8") as f:
            f.write("ro.product.board=ROCO_K706\n")
            f.write("ro.qf001.radio.tuner=TDA7708\n")
            f.write("ro.qf001.audio.dsp=AKM7738\n")

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        self.assertTrue(any("audio dsp mismatch" in v.lower() for v in ctx.exception.violations))

    def test_missing_audio_dsp_property_raises(self):
        """CRITICAL: build.prop missing ro.qf001.audio.dsp must raise HardwareSafetyViolationError."""
        prop_path = os.path.join(self.sys_root, "build.prop")
        with open(prop_path, "w", encoding="utf-8") as f:
            f.write("ro.product.board=ROCO_K706\n")
            f.write("ro.qf001.radio.tuner=TDA7708\n")
            # ro.qf001.audio.dsp is omitted

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        self.assertTrue(
            any("audio.dsp" in v.lower() or "dsp" in v.lower() for v in ctx.exception.violations),
            f"Expected violation for missing audio DSP property, got: {ctx.exception.violations}"
        )

    def test_missing_radio_tuner_property_raises(self):
        """CRITICAL: build.prop missing ro.qf001.radio.tuner must raise HardwareSafetyViolationError."""
        prop_path = os.path.join(self.sys_root, "build.prop")
        with open(prop_path, "w", encoding="utf-8") as f:
            f.write("ro.product.board=ROCO_K706\n")
            f.write("ro.qf001.audio.dsp=BU32107EFV\n")
            # ro.qf001.radio.tuner is omitted

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        self.assertTrue(
            any("radio.tuner" in v.lower() or "tuner" in v.lower() for v in ctx.exception.violations),
            f"Expected violation for missing radio tuner property, got: {ctx.exception.violations}"
        )

    def test_both_audio_properties_missing_raises(self):
        """CRITICAL: build.prop missing BOTH audio and radio tuner properties must raise HardwareSafetyViolationError."""
        prop_path = os.path.join(self.sys_root, "build.prop")
        with open(prop_path, "w", encoding="utf-8") as f:
            f.write("ro.product.board=ROCO_K706\n")
            # Neither tuner nor DSP property is present

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        self.assertTrue(
            any("dsp" in v.lower() or "audio" in v.lower() or "tuner" in v.lower() for v in ctx.exception.violations),
            f"Expected violation for missing audio properties, got: {ctx.exception.violations}"
        )

    def test_empty_audio_properties_raises(self):
        """Empty ro.qf001.audio.dsp or ro.qf001.radio.tuner must raise HardwareSafetyViolationError."""
        prop_path = os.path.join(self.sys_root, "build.prop")
        with open(prop_path, "w", encoding="utf-8") as f:
            f.write("ro.product.board=ROCO_K706\n")
            f.write("ro.qf001.radio.tuner=\n")
            f.write("ro.qf001.audio.dsp=\n")

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        self.assertTrue(len(ctx.exception.violations) > 0)


class TestChallengerPreservedServicesConfigIntegration(unittest.TestCase):
    """Adversarial challenge on config-driven preserved automotive packages."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_missing_com_ts_car_hal_fails_validation(self):
        """Preserved service com.ts.car (automotive DSP & AMP HAL) must not be silently ignored if missing."""
        car_dir = os.path.join(self.sys_root, "priv-app", "com.ts.car")
        if not os.path.exists(car_dir):
            car_dir = os.path.join(self.sys_root, "app", "com.ts.car")
        if os.path.exists(car_dir):
            shutil.rmtree(car_dir)

        # By default SafetyValidator loads config/preserved_services.json where com.ts.car is listed
        # A missing DSP/AMP HAL should be considered a critical automotive safety violation
        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.verify_preserved_services(self.sys_root)

        self.assertIn("com.ts.car", ctx.exception.missing_services)


if __name__ == "__main__":
    unittest.main()
