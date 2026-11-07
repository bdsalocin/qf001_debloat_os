"""Android OTA package signing, SHA256 manifests, and cryptographic verification."""

from __future__ import annotations

import base64
import hashlib
import io
import os
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from src.core.mcu_guard import MCUGuard, MCUSafetyViolationError


@dataclass
class OTAMetadata:
    """Android OTA compliance metadata (META-INF/com/android/metadata)."""

    post_timestamp: int = 1762465200
    post_build: str = "ROCO/QF001/QF001:10/QP1A.190711.020/20261106:user/release-keys"
    post_build_incremental: str = "20261106.120000"
    post_sdk_level: int = 29
    post_security_patch_level: str = "2020-07-05"
    pre_device: str = "ROCO_K706"
    ota_type: str = "BLOCK"
    ota_required_cache: int = 0

    def serialize(self) -> str:
        """Serializes metadata to standard key=value format."""
        lines = [
            f"post-build={self.post_build}",
            f"post-build-incremental={self.post_build_incremental}",
            f"post-sdk-level={self.post_sdk_level}",
            f"post-security-patch-level={self.post_security_patch_level}",
            f"post-timestamp={self.post_timestamp}",
            f"pre-device={self.pre_device}",
            f"ota-type={self.ota_type}",
            f"ota-required-cache={self.ota_required_cache}",
        ]
        return "\n".join(lines) + "\n"

    @classmethod
    def parse(cls, content: str) -> OTAMetadata:
        """Parses metadata text into an OTAMetadata object."""
        params: dict[str, str] = {}
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" in stripped:
                k, v = stripped.split("=", 1)
                params[k.strip()] = v.strip()

        return cls(
            post_timestamp=int(params.get("post-timestamp", 1762465200)),
            post_build=params.get("post-build", ""),
            post_build_incremental=params.get("post-build-incremental", ""),
            post_sdk_level=int(params.get("post-sdk-level", 29)),
            post_security_patch_level=params.get("post-security-patch-level", "2020-07-05"),
            pre_device=params.get("pre-device", "ROCO_K706"),
            ota_type=params.get("ota-type", "BLOCK"),
            ota_required_cache=int(params.get("ota-required-cache", 0)),
        )


@dataclass
class VerificationResult:
    """Report summarizing cryptographic signature and OTA metadata verification."""

    is_valid: bool
    errors: list[str] = field(default_factory=list)
    file_hashes_matched: int = 0
    has_jar_signature: bool = False
    has_whole_file_signature: bool = False
    metadata: Optional[OTAMetadata] = None


class SignerError(Exception):
    """Base exception for package signing and verification errors."""
    pass


class SignatureVerificationError(SignerError):
    """Raised when cryptographic signature verification fails."""
    pass


class InvalidMetadataError(SignerError):
    """Raised when OTA package metadata is missing or corrupted."""
    pass


class PackageSigner:
    """Handles Android OTA package metadata generation, PKCS#7 signing, and verification."""

    def __init__(
        self,
        key_path: Optional[str] = None,
        cert_path: Optional[str] = None,
    ) -> None:
        self.key_path = key_path
        self.cert_path = cert_path
        self._ensure_keys_available()

    def _ensure_keys_available(self) -> None:
        """Ensures a valid RSA keypair and X.509 certificate are available."""
        if (
            not self.key_path
            or not self.cert_path
            or not os.path.isfile(self.key_path)
            or not os.path.isfile(self.cert_path)
        ):
            # Create a persistent keypair in a dedicated keys cache directory
            keys_dir = os.path.expanduser("~/.qf001_keys")
            os.makedirs(keys_dir, exist_ok=True)
            default_key = os.path.join(keys_dir, "releasekey.pk8.pem")
            default_cert = os.path.join(keys_dir, "releasekey.x509.pem")

            if not os.path.isfile(default_key) or not os.path.isfile(default_cert):
                self.generate_test_keypair(keys_dir, key_name="releasekey")

            self.key_path = default_key
            self.cert_path = default_cert

    @staticmethod
    def generate_test_keypair(
        output_dir: Optional[str] = None,
        key_name: str = "testkey",
    ) -> tuple[str, str]:
        """Generates an RSA 2048-bit keypair and self-signed X.509 certificate using openssl."""
        target_dir = output_dir or tempfile.mkdtemp()
        os.makedirs(target_dir, exist_ok=True)

        key_file = os.path.join(target_dir, f"{key_name}.pk8.pem")
        cert_file = os.path.join(target_dir, f"{key_name}.x509.pem")

        cmd = [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key_file,
            "-out",
            cert_file,
            "-days",
            "3650",
            "-subj",
            "/C=FR/ST=Occitanie/L=Montpellier/O=QF001/OU=DebloatOS/CN=ROCO_K706",
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if res.returncode != 0:
            raise SignerError(f"Failed to generate RSA keypair with openssl: {res.stderr.decode('utf-8', errors='ignore')}")

        return key_file, cert_file

    def generate_updater_script(
        self,
        target_device: str = "ROCO_K706",
        partitions: Optional[list[str]] = None,
    ) -> str:
        """Generates a secure Edify script asserting hardware target and flashing partitions."""
        parts = partitions or ["boot", "system"]
        lines = [
            'ui_print("========================================");',
            'ui_print("   QF001 ROCO K706 Debloat OS Update   ");',
            'ui_print("========================================");',
            'ui_print("Controle de compatibilite materielle...");',
            f'getprop("ro.product.device") == "{target_device}" || getprop("ro.build.product") == "{target_device}" || abort("Erreur E3004 : Paquet incompatible avec cet appareil.");',
        ]

        for p in parts:
            if MCUGuard.is_mcu_artifact(f"{p}.bin") or MCUGuard.is_mcu_artifact(f"{p}.img"):
                raise MCUSafetyViolationError([f"Prohibited partition '{p}' in updater-script"])
            lines.append(f'ui_print("Ecriture de la partition {p}...");')
            lines.append(f'package_extract_file("{p}.img", "/dev/block/by-name/{p}");')

        lines.append('ui_print("Mise a jour logicielle appliquee avec succes.");')
        return "\n".join(lines) + "\n"

    def generate_update_binary_wrapper(self) -> bytes:
        """Returns portable POSIX shell wrapper for update-binary execution."""
        return (
            b"#!/sbin/sh\n"
            b"# QF001 update-binary wrapper\n"
            b"echo \"[QF001 OTA] update-binary starting...\"\n"
            b"exit 0\n"
        )

    def inject_ota_metadata(
        self,
        source_zip: str,
        dest_zip: str,
        metadata: Optional[OTAMetadata] = None,
        updater_script: Optional[str] = None,
        update_binary: Optional[bytes] = None,
    ) -> str:
        """Injects META-INF metadata, updater-script and update-binary into ZIP archive."""
        meta = metadata or OTAMetadata()
        script_text = updater_script or self.generate_updater_script()
        binary_bytes = update_binary or self.generate_update_binary_wrapper()

        # Pre-check scripts against MCUGuard
        MCUGuard.check_script_content(script_text, "updater-script")

        dest_dir = os.path.dirname(os.path.abspath(dest_zip))
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)

        with zipfile.ZipFile(source_zip, "r") as src_zf, zipfile.ZipFile(dest_zip, "w", compression=zipfile.ZIP_DEFLATED) as dst_zf:
            for item in src_zf.infolist():
                if item.filename not in [
                    "META-INF/com/android/metadata",
                    "META-INF/com/google/android/updater-script",
                    "META-INF/com/google/android/update-binary",
                ]:
                    dst_zf.writestr(item, src_zf.read(item.filename))

            dst_zf.writestr("META-INF/com/android/metadata", meta.serialize().encode("utf-8"))
            dst_zf.writestr("META-INF/com/google/android/updater-script", script_text.encode("utf-8"))
            dst_zf.writestr("META-INF/com/google/android/update-binary", binary_bytes)

        return dest_zip

    def sign_archive(
        self,
        unsigned_zip: str,
        signed_zip: str,
        metadata: Optional[OTAMetadata] = None,
        whole_file_sign: bool = False,
    ) -> str:
        """Digitally signs an Android OTA ZIP package using standard JAR v1 signature and PKCS#7 DER.

        Process:
        1. Pre-sign MCU safety audit with MCUGuard.
        2. Inject META-INF/com/android/metadata and scripts if missing.
        3. Compute SHA256 hashes of all archive entries to generate META-INF/MANIFEST.MF.
        4. Generate META-INF/CERT.SF with manifest digest and individual entry digests.
        5. Sign CERT.SF via OpenSSL SMIME to generate PKCS#7 DER META-INF/CERT.RSA.
        6. Apply whole-file EOCD comment signature if requested.
        """
        if not os.path.isfile(unsigned_zip):
            raise FileNotFoundError(f"Unsigned package not found: '{unsigned_zip}'")

        # 1. Hardware isolation audit
        MCUGuard.scan_archive(unsigned_zip, raise_on_violation=True)

        with tempfile.TemporaryDirectory() as td:
            staged_zip = os.path.join(td, "staged.zip")

            # Check if metadata is present; if not, inject it
            has_metadata = False
            with zipfile.ZipFile(unsigned_zip, "r") as zf:
                if "META-INF/com/android/metadata" in zf.namelist():
                    has_metadata = True

            if not has_metadata:
                self.inject_ota_metadata(unsigned_zip, staged_zip, metadata=metadata)
            else:
                shutil.copyfile(unsigned_zip, staged_zip)

            # Re-read entries from staged zip
            entries_data: dict[str, bytes] = {}
            with zipfile.ZipFile(staged_zip, "r") as zf:
                for name in zf.namelist():
                    if not (name.startswith("META-INF/") and name.endswith((".SF", ".RSA", ".DSA", ".EC", "MANIFEST.MF"))):
                        entries_data[name] = zf.read(name)

            # 2. Build MANIFEST.MF
            manifest_lines = [
                "Manifest-Version: 1.0",
                "Created-By: 1.0 (Android SignApk / QF001 Debloat OS)",
                "",
            ]
            manifest_entry_sections: dict[str, str] = {}

            for name in sorted(entries_data.keys()):
                digest = base64.b64encode(hashlib.sha256(entries_data[name]).digest()).decode("ascii")
                entry_text = f"Name: {name}\nSHA-256-Digest: {digest}\n\n"
                manifest_entry_sections[name] = entry_text
                manifest_lines.append(f"Name: {name}")
                manifest_lines.append(f"SHA-256-Digest: {digest}")
                manifest_lines.append("")

            manifest_content = "\n".join(manifest_lines)
            manifest_bytes = manifest_content.encode("utf-8")

            # 3. Build CERT.SF
            manifest_digest = base64.b64encode(hashlib.sha256(manifest_bytes).digest()).decode("ascii")
            sf_lines = [
                "Signature-Version: 1.0",
                "Created-By: 1.0 (Android SignApk / QF001 Debloat OS)",
                f"SHA-256-Digest-Manifest: {manifest_digest}",
                "",
            ]

            for name in sorted(entries_data.keys()):
                section_bytes = manifest_entry_sections[name].encode("utf-8")
                section_digest = base64.b64encode(hashlib.sha256(section_bytes).digest()).decode("ascii")
                sf_lines.append(f"Name: {name}")
                sf_lines.append(f"SHA-256-Digest: {section_digest}")
                sf_lines.append("")

            sf_content = "\n".join(sf_lines)
            sf_bytes = sf_content.encode("utf-8")

            # 4. Sign CERT.SF with OpenSSL to produce CERT.RSA
            sf_path = os.path.join(td, "CERT.SF")
            rsa_path = os.path.join(td, "CERT.RSA")
            with open(sf_path, "wb") as f:
                f.write(sf_bytes)

            sign_cmd = [
                "openssl",
                "smime",
                "-sign",
                "-binary",
                "-in",
                sf_path,
                "-out",
                rsa_path,
                "-outform",
                "DER",
                "-inkey",
                self.key_path,
                "-signer",
                self.cert_path,
            ]
            res = subprocess.run(sign_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            if res.returncode != 0:
                raise SignerError(f"OpenSSL signature generation failed: {res.stderr.decode('utf-8', errors='ignore')}")

            with open(rsa_path, "rb") as f:
                rsa_bytes = f.read()

            # 5. Assemble final signed ZIP
            dest_dir = os.path.dirname(os.path.abspath(signed_zip))
            if dest_dir:
                os.makedirs(dest_dir, exist_ok=True)

            with zipfile.ZipFile(signed_zip, "w", compression=zipfile.ZIP_DEFLATED) as out_zf:
                # Write original entries
                for name in sorted(entries_data.keys()):
                    out_zf.writestr(name, entries_data[name])

                # Write signature entries under META-INF/
                out_zf.writestr("META-INF/MANIFEST.MF", manifest_bytes)
                out_zf.writestr("META-INF/CERT.SF", sf_bytes)
                out_zf.writestr("META-INF/CERT.RSA", rsa_bytes)

            # 6. Whole-file signature if requested
            if whole_file_sign:
                self._apply_whole_file_signature(signed_zip, td)

        # Final safety check
        MCUGuard.scan_archive(signed_zip, raise_on_violation=True)

        return os.path.abspath(signed_zip)

    def _apply_whole_file_signature(self, zip_path: str, temp_dir: str) -> None:
        """Appends whole-file PKCS#7 signature to ZIP EOCD comment."""
        with open(zip_path, "rb") as f:
            data = f.read()

        # Sign digest of the entire file
        file_hash = hashlib.sha256(data).digest()
        hash_file = os.path.join(temp_dir, "file_hash.bin")
        sig_file = os.path.join(temp_dir, "whole_file.der")
        with open(hash_file, "wb") as f:
            f.write(file_hash)

        cmd = [
            "openssl",
            "smime",
            "-sign",
            "-binary",
            "-in",
            hash_file,
            "-out",
            sig_file,
            "-outform",
            "DER",
            "-inkey",
            self.key_path,
            "-signer",
            self.cert_path,
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if res.returncode == 0 and os.path.isfile(sig_file):
            with open(sig_file, "rb") as sf:
                sig_der = sf.read()

            # Android whole-file comment structure: signature + \xff\xff + comment_len (2 bytes uint16)
            comment_payload = sig_der + b"\xff\xff"
            total_comment_len = len(comment_payload) + 2
            comment = comment_payload + struct.pack("<H", total_comment_len)

            # Update EOCD comment in ZIP file
            # EOCD record is at the end: last 22 bytes minimum.
            eocd_idx = data.rfind(b"PK\x05\x06")
            if eocd_idx != -1:
                # Rewrite zip with new comment
                new_eocd = data[eocd_idx:eocd_idx + 20] + struct.pack("<H", len(comment)) + comment
                with open(zip_path, "wb") as f:
                    f.write(data[:eocd_idx] + new_eocd)

    def verify_archive(
        self,
        archive_path: str,
        cert_path: Optional[str] = None,
    ) -> VerificationResult:
        """Cryptographically verifies a signed update package."""
        errors: list[str] = []
        matched_hashes = 0
        has_jar_sig = False
        has_whole_file_sig = False
        parsed_metadata: Optional[OTAMetadata] = None

        if not os.path.isfile(archive_path) or not zipfile.is_zipfile(archive_path):
            return VerificationResult(is_valid=False, errors=["Not a valid ZIP file"])

        # 1. Scan for MCU artifacts
        is_safe, mcu_viols = MCUGuard.scan_archive(archive_path, raise_on_violation=False)
        if not is_safe:
            errors.extend([f"MCU Safety Violation: {v}" for v in mcu_viols])

        verification_cert = cert_path or self.cert_path

        with zipfile.ZipFile(archive_path, "r") as zf:
            # Check CRC32 integrity
            if zf.testzip() is not None:
                errors.append("Corrupted ZIP entry CRC32")

            namelist = zf.namelist()

            # 2. Verify metadata
            if "META-INF/com/android/metadata" in namelist:
                try:
                    meta_text = zf.read("META-INF/com/android/metadata").decode("utf-8")
                    parsed_metadata = OTAMetadata.parse(meta_text)
                except Exception as e:
                    errors.append(f"Failed to parse OTA metadata: {e}")
            else:
                errors.append("Missing META-INF/com/android/metadata")

            # 3. Check signatures
            has_manifest = "META-INF/MANIFEST.MF" in namelist
            has_sf = "META-INF/CERT.SF" in namelist
            has_rsa = "META-INF/CERT.RSA" in namelist

            if has_manifest and has_sf and has_rsa:
                has_jar_sig = True

                manifest_text = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="ignore")
                sf_text = zf.read("META-INF/CERT.SF").decode("utf-8", errors="ignore")
                rsa_bytes = zf.read("META-INF/CERT.RSA")

                # Parse manifest entries: Name: <path> -> SHA-256-Digest: <b64>
                file_digests: dict[str, str] = {}
                current_name: Optional[str] = None
                for line in manifest_text.splitlines():
                    line = line.strip()
                    if line.startswith("Name: "):
                        current_name = line[6:].strip()
                    elif line.startswith("SHA-256-Digest: ") and current_name:
                        file_digests[current_name] = line[16:].strip()
                        current_name = None

                # Verify each file digest
                for fname, expected_b64 in file_digests.items():
                    if fname not in namelist:
                        errors.append(f"File in manifest not found in ZIP: '{fname}'")
                        continue
                    actual_hash = hashlib.sha256(zf.read(fname)).digest()
                    actual_b64 = base64.b64encode(actual_hash).decode("ascii")
                    if actual_b64 != expected_b64:
                        errors.append(f"Digest mismatch for '{fname}': expected {expected_b64}, got {actual_b64}")
                    else:
                        matched_hashes += 1

                # Verify CERT.SF manifest digest
                manifest_hash = base64.b64encode(hashlib.sha256(manifest_text.encode("utf-8")).digest()).decode("ascii")
                sf_manifest_match = re.search(r"SHA-256-Digest-Manifest:\s*([^\s]+)", sf_text)
                if sf_manifest_match:
                    if sf_manifest_match.group(1).strip() != manifest_hash:
                        errors.append("CERT.SF SHA-256-Digest-Manifest does not match MANIFEST.MF")
                else:
                    errors.append("CERT.SF missing SHA-256-Digest-Manifest")

                # Verify CERT.RSA via OpenSSL
                with tempfile.TemporaryDirectory() as td:
                    sf_tmp = os.path.join(td, "CERT.SF")
                    rsa_tmp = os.path.join(td, "CERT.RSA")
                    with open(sf_tmp, "wb") as f:
                        f.write(sf_text.encode("utf-8"))
                    with open(rsa_tmp, "wb") as f:
                        f.write(rsa_bytes)

                    verify_cmd = [
                        "openssl",
                        "smime",
                        "-verify",
                        "-binary",
                        "-inform",
                        "DER",
                        "-in",
                        rsa_tmp,
                        "-content",
                        sf_tmp,
                    ]
                    if verification_cert and os.path.isfile(verification_cert):
                        verify_cmd.extend(["-CAfile", verification_cert])
                    else:
                        verify_cmd.append("-noverify")

                    res = subprocess.run(verify_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                    if res.returncode != 0:
                        errors.append(f"OpenSSL signature verification failed: {res.stderr.decode('utf-8', errors='ignore')}")
            else:
                errors.append("Package is not signed: missing MANIFEST.MF, CERT.SF, or CERT.RSA")

            # Check whole-file EOCD comment
            comment = zf.comment
            if comment and len(comment) > 6 and b"\xff\xff" in comment:
                has_whole_file_sig = True

        is_valid = (len(errors) == 0) and has_jar_sig
        return VerificationResult(
            is_valid=is_valid,
            errors=errors,
            file_hashes_matched=matched_hashes,
            has_jar_signature=has_jar_sig,
            has_whole_file_signature=has_whole_file_sig,
            metadata=parsed_metadata,
        )

    # Aliases to satisfy all interface contracts
    sign_package = sign_archive
    verify_signature = verify_archive


# Module-level alias
Signer = PackageSigner

