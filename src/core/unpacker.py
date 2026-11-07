"""Firmware unpacking, inspection, and security isolation module."""

from __future__ import annotations

import os
import shutil
import zipfile
from pathlib import Path
from typing import Dict, List, Optional

from src.core.mcu_guard import MCUGuard, MCUSafetyViolationError
from src.core.sparse import SparseImage


class SecurityViolationError(Exception):
    """Raised when an archive contains directory traversal (Zip Slip) attacks."""
    pass


class FirmwareUnpacker:
    """Extracts and inspects QF001 firmware archives with MCU isolation."""

    def __init__(self, archive_path: str, extract_dir: str) -> None:
        self.archive_path = os.path.realpath(os.path.abspath(archive_path))
        self.extract_dir = os.path.realpath(os.path.abspath(extract_dir))
        self.firmware_dir = os.path.join(self.extract_dir, "firmware")
        self.system_root = os.path.join(self.extract_dir, "system")
        self.quarantine_dir = os.path.join(self.extract_dir, "quarantine_mcu")
        self.manifest: dict = {}

    def validate_archive(self) -> bool:
        """Validates archive existence, ZIP integrity, and path safety."""
        if not os.path.isfile(self.archive_path):
            return False

        size = os.path.getsize(self.archive_path)
        if size == 0:
            return True

        if not zipfile.is_zipfile(self.archive_path):
            return False

        try:
            with zipfile.ZipFile(self.archive_path, "r") as zf:
                # Test CRC32 integrity of all entries
                if zf.testzip() is not None:
                    return False

                # Validate against directory traversal (Zip Slip)
                extract_root = os.path.realpath(self.extract_dir)
                for member in zf.infolist():
                    target_path = os.path.realpath(os.path.join(self.extract_dir, member.filename))
                    if not target_path.startswith(extract_root + os.sep) and target_path != extract_root:
                        return False

            return True
        except (OSError, zipfile.BadZipFile):
            return False

    def unpack(
        self,
        auto_unsparse: bool = True,
        quarantine_mcu: bool = True,
    ) -> dict:
        """Extracts the firmware archive, isolating MCU binaries and expanding sparse images.

        Args:
            auto_unsparse: Automatically convert detected sparse images to raw images.
            quarantine_mcu: Quarantine detected MCU binaries instead of raising immediately.

        Returns:
            Dictionary detailing extracted files, unsparsed images, and quarantined artifacts.
        """
        if not os.path.isfile(self.archive_path):
            raise FileNotFoundError(f"Archive file not found: {self.archive_path}")

        os.makedirs(self.extract_dir, exist_ok=True)
        os.makedirs(self.firmware_dir, exist_ok=True)

        extracted_files: list[str] = []
        quarantined_files: list[str] = []
        unsparsed_images: list[str] = []

        extract_root = os.path.realpath(self.extract_dir)

        with zipfile.ZipFile(self.archive_path, "r") as zf:
            for member in zf.infolist():
                # Security: Check for path traversal (Zip Slip)
                target_path = os.path.realpath(os.path.join(self.extract_dir, member.filename))
                if not target_path.startswith(extract_root + os.sep) and target_path != extract_root:
                    raise SecurityViolationError(
                        f"Zip Slip path traversal attempt detected in member: '{member.filename}'"
                    )

                # Security: Check for MCU hardware artifacts
                if MCUGuard.is_mcu_artifact(member.filename):
                    if quarantine_mcu:
                        os.makedirs(self.quarantine_dir, exist_ok=True)
                        quarantine_target = os.path.join(
                            self.quarantine_dir, os.path.basename(member.filename)
                        )
                        with zf.open(member) as src_f, open(quarantine_target, "wb") as dst_f:
                            shutil.copyfileobj(src_f, dst_f)
                        quarantined_files.append(member.filename)
                        continue
                    else:
                        raise MCUSafetyViolationError([member.filename])

                # Extract normal file
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                if not member.is_dir():
                    with zf.open(member) as src_f, open(target_path, "wb") as dst_f:
                        shutil.copyfileobj(src_f, dst_f)
                    extracted_files.append(target_path)

                    # Auto unsparse if image is Android sparse
                    if auto_unsparse and target_path.endswith(".img") and SparseImage.is_sparse(target_path):
                        raw_path = os.path.splitext(target_path)[0] + ".raw.img"
                        SparseImage.unsparse(target_path, raw_path)
                        unsparsed_images.append(raw_path)

        # Prepare system_root if system subfolder exists
        extracted_sys = os.path.join(self.extract_dir, "system")
        if os.path.isdir(extracted_sys):
            self.system_root = extracted_sys

        self.manifest = {
            "archive_path": self.archive_path,
            "extract_dir": self.extract_dir,
            "extracted_files": extracted_files,
            "quarantined_files": quarantined_files,
            "unsparsed_images": unsparsed_images,
        }
        return self.manifest

    def inspect_filesystem(self, target_root: Optional[str] = None) -> dict:
        """Inspects extracted Android system tree, locating apps and parsing build.prop.

        Returns:
            Dictionary containing lists of system apps, priv-apps, and build properties.
        """
        root = os.path.abspath(target_root or self.system_root)
        apps: list[str] = []
        priv_apps: list[str] = []
        build_prop: dict[str, str] = {}

        if not os.path.isdir(root):
            return {"apps": apps, "priv_apps": priv_apps, "build_prop": build_prop}

        # Scan app directory
        app_dir = os.path.join(root, "app")
        if os.path.isdir(app_dir):
            for item in os.listdir(app_dir):
                if not item.startswith("."):
                    apps.append(item)

        # Scan priv-app directory
        priv_app_dir = os.path.join(root, "priv-app")
        if os.path.isdir(priv_app_dir):
            for item in os.listdir(priv_app_dir):
                if not item.startswith("."):
                    priv_apps.append(item)

        # Parse build.prop
        prop_path = os.path.join(root, "build.prop")
        if os.path.isfile(prop_path):
            with open(prop_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#") and "=" in stripped:
                        key, val = stripped.split("=", 1)
                        build_prop[key.strip()] = val.strip()

        return {
            "system_root": root,
            "apps": sorted(apps),
            "priv_apps": sorted(priv_apps),
            "build_prop": build_prop,
        }
