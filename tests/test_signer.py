"""Comprehensive unit tests for Android OTA PackageSigner (signer.py)."""

import base64
import hashlib
import os
import tempfile
import unittest
import zipfile

from src.core.mcu_guard import MCUSafetyViolationError
from src.core.signer import (
    OTAMetadata,
    PackageSigner,
    SignatureVerificationError,
    SignerError,
    VerificationResult,
)


class TestOTAMetadata(unittest.TestCase):
    """Test suite for OTAMetadata serialization and parsing."""

    def test_ota_metadata_default_values(self):
        """Default values match ROCO K706 Unisoc UIS7862 platform specifications."""
        meta = OTAMetadata()
        self.assertEqual(meta.pre_device, "ROCO_K706")
        self.assertEqual(meta.ota_type, "BLOCK")
        self.assertEqual(meta.post_sdk_level, 29)
        self.assertIn("QF001", meta.post_build)

    def test_ota_metadata_roundtrip(self):
        """Serialization followed by parse produces identical fields."""
        original = OTAMetadata(
            post_timestamp=1762469999,
            post_build="ROCO/QF001/TEST:10/QP1A/CUSTOM:user/release-keys",
            post_build_incremental="20261106.999999",
            post_sdk_level=29,
            post_security_patch_level="2020-08-01",
            pre_device="QF001",
            ota_type="BLOCK",
            ota_required_cache=1024,
        )
        serialized = original.serialize()
        parsed = OTAMetadata.parse(serialized)

        self.assertEqual(parsed.post_timestamp, original.post_timestamp)
        self.assertEqual(parsed.post_build, original.post_build)
        self.assertEqual(parsed.post_build_incremental, original.post_build_incremental)
        self.assertEqual(parsed.post_sdk_level, original.post_sdk_level)
        self.assertEqual(parsed.post_security_patch_level, original.post_security_patch_level)
        self.assertEqual(parsed.pre_device, original.pre_device)
        self.assertEqual(parsed.ota_type, original.ota_type)
        self.assertEqual(parsed.ota_required_cache, original.ota_required_cache)


class TestScriptGeneration(unittest.TestCase):
    """Test suite for updater-script and update-binary generation."""

    def setUp(self):
        self.signer = PackageSigner()

    def test_updater_script_contains_safety_checks(self):
        """updater-script asserts ro.product.device compatibility."""
        script = self.signer.generate_updater_script("ROCO_K706")
        self.assertIn('getprop("ro.product.device") == "ROCO_K706"', script)
        self.assertIn("package_extract_file", script)
        self.assertIn("system.img", script)

    def test_updater_script_mcu_prohibition(self):
        """MCU partition injection attempt in script generator raises MCUSafetyViolationError."""
        with self.assertRaises(MCUSafetyViolationError):
            self.signer.generate_updater_script("ROCO_K706", partitions=["system", "mcu"])

    def test_update_binary_wrapper_executable(self):
        """update-binary wrapper is a valid POSIX shell script with shebang."""
        wrapper = self.signer.generate_update_binary_wrapper()
        self.assertTrue(wrapper.startswith(b"#!/sbin/sh"))


class TestPackageSigningAndVerification(unittest.TestCase):
    """Test suite for full cryptographic signing, manifest generation and verification."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.signer = PackageSigner()

        # Build dummy unsigned archive
        self.unsigned_zip = os.path.join(self.tmpdir.name, "unsigned.zip")
        with zipfile.ZipFile(self.unsigned_zip, "w") as zf:
            zf.writestr("boot.img", b"BOOT_KERNEL_PAYLOAD_BYTES" * 32)
            zf.writestr("system.img", b"SYSTEM_OS_PAYLOAD_BYTES" * 64)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_signer_interface_aliases(self):
        """PackageSigner exposes sign_package and verify_signature interface aliases."""
        self.assertTrue(hasattr(self.signer, "sign_package"))
        self.assertTrue(hasattr(self.signer, "verify_signature"))
        self.assertTrue(hasattr(self.signer, "sign_archive"))
        self.assertTrue(hasattr(self.signer, "verify_archive"))

    def test_sign_archive_produces_valid_structure(self):
        """Signing unsigned archive produces MANIFEST.MF, CERT.SF and CERT.RSA under META-INF."""
        signed_zip = os.path.join(self.tmpdir.name, "signed.zip")
        self.signer.sign_archive(self.unsigned_zip, signed_zip)

        self.assertTrue(os.path.isfile(signed_zip))
        with zipfile.ZipFile(signed_zip, "r") as zf:
            names = zf.namelist()
            self.assertIn("META-INF/MANIFEST.MF", names)
            self.assertIn("META-INF/CERT.SF", names)
            self.assertIn("META-INF/CERT.RSA", names)
            self.assertIn("META-INF/com/android/metadata", names)
            self.assertIn("META-INF/com/google/android/updater-script", names)

    def test_verify_valid_signed_package(self):
        """Verifying properly signed package succeeds with is_valid=True."""
        signed_zip = os.path.join(self.tmpdir.name, "signed_ok.zip")
        self.signer.sign_archive(self.unsigned_zip, signed_zip)

        result = self.signer.verify_archive(signed_zip)
        self.assertTrue(result.is_valid, f"Verification failed with errors: {result.errors}")
        self.assertTrue(result.has_jar_signature)
        self.assertGreaterEqual(result.file_hashes_matched, 2)
        self.assertIsNotNone(result.metadata)

    def test_verify_detects_tampered_file(self):
        """Modifying payload file in signed package is caught as digest mismatch."""
        signed_zip = os.path.join(self.tmpdir.name, "signed_tampered.zip")
        self.signer.sign_archive(self.unsigned_zip, signed_zip)

        tampered_zip = os.path.join(self.tmpdir.name, "tampered.zip")
        with zipfile.ZipFile(signed_zip, "r") as src_zf, zipfile.ZipFile(tampered_zip, "w") as dst_zf:
            for item in src_zf.infolist():
                if item.filename == "boot.img":
                    # Inject malicious modified payload
                    dst_zf.writestr("boot.img", b"TAMPERED_MALICIOUS_BYTES")
                else:
                    dst_zf.writestr(item, src_zf.read(item.filename))

        result = self.signer.verify_archive(tampered_zip)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("boot.img" in e for e in result.errors))

    def test_verify_detects_corrupted_signature(self):
        """Corrupted CERT.RSA bytes cause verification failure."""
        signed_zip = os.path.join(self.tmpdir.name, "signed_bad_sig.zip")
        self.signer.sign_archive(self.unsigned_zip, signed_zip)

        bad_sig_zip = os.path.join(self.tmpdir.name, "bad_sig.zip")
        with zipfile.ZipFile(signed_zip, "r") as src_zf, zipfile.ZipFile(bad_sig_zip, "w") as dst_zf:
            for item in src_zf.infolist():
                if item.filename == "META-INF/CERT.RSA":
                    dst_zf.writestr(item.filename, b"CORRUPTED_RSA_SIGNATURE")
                else:
                    dst_zf.writestr(item, src_zf.read(item.filename))

        result = self.signer.verify_archive(bad_sig_zip)
        self.assertFalse(result.is_valid)

    def test_verify_rejects_mcu_artifact(self):
        """Archive containing mcu.bin is rejected during signing and verification."""
        tainted_unsigned = os.path.join(self.tmpdir.name, "tainted.zip")
        with zipfile.ZipFile(tainted_unsigned, "w") as zf:
            zf.writestr("system.img", b"SYS")
            zf.writestr("mcu.bin", b"MCU_MICROCODE")

        signed_tainted = os.path.join(self.tmpdir.name, "signed_tainted.zip")
        with self.assertRaises(MCUSafetyViolationError):
            self.signer.sign_archive(tainted_unsigned, signed_tainted)

    def test_whole_file_eocd_signature(self):
        """Signing with whole_file_sign=True sets EOCD signature comment."""
        signed_whole = os.path.join(self.tmpdir.name, "signed_whole.zip")
        self.signer.sign_archive(self.unsigned_zip, signed_whole, whole_file_sign=True)

        result = self.signer.verify_archive(signed_whole)
        self.assertTrue(result.is_valid)
        self.assertTrue(result.has_whole_file_signature)


if __name__ == "__main__":
    unittest.main()
