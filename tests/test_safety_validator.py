"""Comprehensive unit tests for SafetyValidator engine."""

import json
import os
import shutil
import tempfile
import unittest

from src.domain.safety_validator import (
    SafetyValidator,
    ValidationResult,
    SafetyValidatorError,
    HardwareSafetyViolationError,
)
from tests.e2e.test_helpers import create_mock_system_fs


class TestSafetyValidatorHappyPath(unittest.TestCase):
    """Unit test suite for successful validation of compliant automotive systems."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_default_mock_fs_passes(self):
        validator = SafetyValidator()
        result = validator.verify_preserved_services(self.sys_root)
        self.assertTrue(result.is_safe)
        self.assertTrue(result.is_valid)
        self.assertTrue(bool(result))
        self.assertEqual(len(result.missing_services), 0)
        self.assertEqual(len(result.violations), 0)

    def test_validation_result_attributes(self):
        validator = SafetyValidator()
        result = validator.verify_preserved_services(self.sys_root)
        self.assertIn("com.ts.main.radio", result.verified_services)
        self.assertIn("com.ts.camera", result.verified_services)
        self.assertIn("com.syu.bt", result.verified_services)
        self.assertTrue(result.build_prop_verified)
        self.assertEqual(result.build_prop_properties.get("ro.product.board"), "ROCO_K706")

    def test_to_dict_and_summary(self):
        validator = SafetyValidator()
        result = validator.verify_preserved_services(self.sys_root)
        d = result.to_dict()
        self.assertTrue(d["is_safe"])
        self.assertTrue(d["is_valid"])
        self.assertEqual(d["violations_count"], 0)

        s = result.summary()
        self.assertIn("PASSED", s)
        self.assertIn("services preserved", s)


class TestSafetyValidatorMissingServices(unittest.TestCase):
    """Unit test suite for detection of missing automotive hardware services."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_missing_radio_fails(self):
        radio_dir = os.path.join(self.sys_root, "priv-app", "com.ts.main.radio")
        if not os.path.exists(radio_dir):
            radio_dir = os.path.join(self.sys_root, "app", "com.ts.main.radio")
        shutil.rmtree(radio_dir)

        validator = SafetyValidator(raise_on_error=False)
        result = validator.verify_preserved_services(self.sys_root)

        self.assertFalse(result.is_safe)
        self.assertIn("com.ts.main.radio", result.missing_services)
        self.assertTrue(any("com.ts.main.radio" in v for v in result.violations))

    def test_missing_camera_fails(self):
        cam_dir = os.path.join(self.sys_root, "priv-app", "com.ts.camera")
        if not os.path.exists(cam_dir):
            cam_dir = os.path.join(self.sys_root, "app", "com.ts.camera")
        shutil.rmtree(cam_dir)

        validator = SafetyValidator(raise_on_error=False)
        result = validator.verify_preserved_services(self.sys_root)

        self.assertFalse(result.is_safe)
        self.assertIn("com.ts.camera", result.missing_services)

    def test_missing_bluetooth_fails(self):
        bt_dir = os.path.join(self.sys_root, "priv-app", "com.syu.bt")
        if not os.path.exists(bt_dir):
            bt_dir = os.path.join(self.sys_root, "app", "com.syu.bt")
        shutil.rmtree(bt_dir)

        validator = SafetyValidator(raise_on_error=False)
        result = validator.verify_preserved_services(self.sys_root)

        self.assertFalse(result.is_safe)
        self.assertIn("com.syu.bt", result.missing_services)

    def test_missing_all_canbus_fails(self):
        for pkg in ["com.roco.canbus", "com.syu.canbus"]:
            d = os.path.join(self.sys_root, "priv-app", pkg)
            if not os.path.exists(d):
                d = os.path.join(self.sys_root, "app", pkg)
            if os.path.exists(d):
                shutil.rmtree(d)

        validator = SafetyValidator(raise_on_error=False)
        result = validator.verify_preserved_services(self.sys_root)

        self.assertFalse(result.is_safe)
        self.assertTrue(any("CAN" in v for v in result.violations))

    def test_single_canbus_passes_default(self):
        # Remove only com.syu.canbus, keep com.roco.canbus
        d = os.path.join(self.sys_root, "priv-app", "com.syu.canbus")
        if not os.path.exists(d):
            d = os.path.join(self.sys_root, "app", "com.syu.canbus")
        if os.path.exists(d):
            shutil.rmtree(d)

        validator = SafetyValidator(raise_on_error=False, require_all_canbus=False)
        result = validator.verify_preserved_services(self.sys_root)
        self.assertTrue(result.is_safe)
        self.assertIn("com.roco.canbus", result.verified_services)

    def test_require_all_canbus_fails_when_one_missing(self):
        d = os.path.join(self.sys_root, "priv-app", "com.syu.canbus")
        if not os.path.exists(d):
            d = os.path.join(self.sys_root, "app", "com.syu.canbus")
        if os.path.exists(d):
            shutil.rmtree(d)

        validator = SafetyValidator(raise_on_error=False, require_all_canbus=True)
        result = validator.verify_preserved_services(self.sys_root)
        self.assertFalse(result.is_safe)
        self.assertIn("com.syu.canbus", result.missing_services)


class TestSafetyValidatorDamagedServices(unittest.TestCase):
    """Unit test suite for corrupted or damaged packages on disk."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_zero_byte_apk_detected(self):
        radio_dir = os.path.join(self.sys_root, "priv-app", "com.ts.main.radio")
        if not os.path.exists(radio_dir):
            radio_dir = os.path.join(self.sys_root, "app", "com.ts.main.radio")
        apk_path = os.path.join(radio_dir, "com.ts.main.radio.apk")
        with open(apk_path, "wb") as f:
            f.truncate(0)

        validator = SafetyValidator(raise_on_error=False)
        result = validator.verify_preserved_services(self.sys_root)

        self.assertFalse(result.is_safe)
        self.assertIn("com.ts.main.radio", result.corrupt_services)
        self.assertTrue(any("corrupt" in v.lower() or "0 bytes" in v.lower() for v in result.violations))

    def test_empty_package_directory_detected(self):
        radio_dir = os.path.join(self.sys_root, "priv-app", "com.ts.main.radio")
        if not os.path.exists(radio_dir):
            radio_dir = os.path.join(self.sys_root, "app", "com.ts.main.radio")
        for f in os.listdir(radio_dir):
            os.remove(os.path.join(radio_dir, f))

        validator = SafetyValidator(raise_on_error=False)
        result = validator.verify_preserved_services(self.sys_root)

        self.assertFalse(result.is_safe)
        self.assertTrue(any("no .apk binary file" in v for v in result.violations))


class TestSafetyValidatorBuildProp(unittest.TestCase):
    """Unit test suite for build.prop hardware property validations."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_missing_build_prop_fails(self):
        prop_path = os.path.join(self.sys_root, "build.prop")
        if os.path.exists(prop_path):
            os.remove(prop_path)

        validator = SafetyValidator(raise_on_error=False)
        result = validator.verify_preserved_services(self.sys_root)

        self.assertFalse(result.is_safe)
        self.assertFalse(result.build_prop_verified)
        self.assertTrue(any("build.prop not found" in v for v in result.violations))

    def test_tampered_board_property_fails(self):
        prop_path = os.path.join(self.sys_root, "build.prop")
        with open(prop_path, "w", encoding="utf-8") as f:
            f.write("ro.product.board=FOREIGN_BOARD_XYZ\nro.qf001.radio.tuner=TDA7708\n")

        validator = SafetyValidator(raise_on_error=False)
        result = validator.verify_preserved_services(self.sys_root)

        self.assertFalse(result.is_safe)
        self.assertTrue(any("board mismatch" in v.lower() for v in result.violations))

    def test_mismatched_tuner_property_fails(self):
        prop_path = os.path.join(self.sys_root, "build.prop")
        with open(prop_path, "w", encoding="utf-8") as f:
            f.write("ro.product.board=ROCO_K706\nro.qf001.radio.tuner=SI4754\n")

        validator = SafetyValidator(raise_on_error=False)
        result = validator.verify_preserved_services(self.sys_root)

        self.assertFalse(result.is_safe)
        self.assertTrue(any("radio tuner mismatch" in v.lower() for v in result.violations))

    def test_mismatched_dsp_property_fails(self):
        prop_path = os.path.join(self.sys_root, "build.prop")
        with open(prop_path, "w", encoding="utf-8") as f:
            f.write("ro.product.board=ROCO_K706\nro.qf001.audio.dsp=AKM7738\n")

        validator = SafetyValidator(raise_on_error=False)
        result = validator.verify_preserved_services(self.sys_root)

        self.assertFalse(result.is_safe)
        self.assertTrue(any("audio dsp mismatch" in v.lower() for v in result.violations))


class TestSafetyValidatorEnforcementAndExceptions(unittest.TestCase):
    """Unit test suite for exception handling and enforcement guarantees."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sys_root = create_mock_system_fs(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_enforce_preserved_services_raises_on_failure(self):
        radio_dir = os.path.join(self.sys_root, "priv-app", "com.ts.main.radio")
        if not os.path.exists(radio_dir):
            radio_dir = os.path.join(self.sys_root, "app", "com.ts.main.radio")
        shutil.rmtree(radio_dir)

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError) as ctx:
            validator.enforce_preserved_services(self.sys_root)

        err = ctx.exception
        self.assertIn("com.ts.main.radio", err.missing_services)
        self.assertGreater(len(err.violations), 0)

    def test_raise_on_error_parameter(self):
        radio_dir = os.path.join(self.sys_root, "priv-app", "com.ts.main.radio")
        if not os.path.exists(radio_dir):
            radio_dir = os.path.join(self.sys_root, "app", "com.ts.main.radio")
        shutil.rmtree(radio_dir)

        validator = SafetyValidator()
        with self.assertRaises(HardwareSafetyViolationError):
            validator.verify_preserved_services(self.sys_root, raise_on_error=True)

    def test_raise_if_invalid_method(self):
        validator = SafetyValidator(raise_on_error=False)
        # Happy path: no-op
        good_result = validator.verify_preserved_services(self.sys_root)
        good_result.raise_if_invalid()

        # Bad path
        radio_dir = os.path.join(self.sys_root, "priv-app", "com.ts.main.radio")
        if not os.path.exists(radio_dir):
            radio_dir = os.path.join(self.sys_root, "app", "com.ts.main.radio")
        shutil.rmtree(radio_dir)

        bad_result = validator.verify_preserved_services(self.sys_root)
        with self.assertRaises(HardwareSafetyViolationError):
            bad_result.raise_if_invalid()

    def test_nonexistent_root_path(self):
        validator = SafetyValidator(raise_on_error=False)
        result = validator.verify_preserved_services("/nonexistent/root/path/abc")
        self.assertFalse(result.is_safe)
        self.assertTrue(any("does not exist" in v for v in result.violations))


if __name__ == "__main__":
    unittest.main()
