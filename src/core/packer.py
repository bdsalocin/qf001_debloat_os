"""Firmware packing, partition structuring, and MCU safe archive generation."""

from __future__ import annotations

import io
import os
import struct
import zipfile
from pathlib import Path
from typing import Dict, List, Optional

from src.core.mcu_guard import MCUGuard, MCUSafetyViolationError
from src.core.sparse import DEFAULT_BLOCK_SIZE, SparseImage


class FirmwarePacker:
    """Rebuilds partition images and update archives under strict MCU isolation."""

    def __init__(self, system_root: str, output_dir: str) -> None:
        self.system_root = os.path.abspath(system_root)
        self.output_dir = os.path.abspath(output_dir)

    def pack_partition(
        self,
        partition_name: str = "system",
        make_sparse: bool = True,
        block_size: int = DEFAULT_BLOCK_SIZE,
    ) -> str:
        """Packs filesystem tree into a partition image, enforcing zero MCU presence.

        Args:
            partition_name: Name of partition (e.g. 'system').
            make_sparse: If True, convert raw image to Android Sparse format.
            block_size: Filesystem block size (default 4096).

        Returns:
            Absolute path to the created partition image.

        Raises:
            MCUSafetyViolationError: If MCU artifacts are present in system_root.
        """
        # Pre-pack hardware isolation audit
        MCUGuard.scan_directory(self.system_root, raise_on_violation=True)

        os.makedirs(self.output_dir, exist_ok=True)
        raw_image_path = os.path.join(self.output_dir, f"{partition_name}.raw.img")

        # Synthesize 4096-byte aligned raw partition containing file index and contents
        with open(raw_image_path, "wb") as rf:
            # Header block
            hdr_info = f"QF001_PARTITION_IMAGE:{partition_name}:BLOCKSZ={block_size}\n".encode("utf-8")
            rf.write(hdr_info.ljust(block_size, b"\x00"))

            # Stream files from system_root
            for root, _, files in os.walk(self.system_root):
                for fn in files:
                    full_p = os.path.join(root, fn)
                    rel_p = os.path.relpath(full_p, self.system_root)

                    # Meta block for file
                    meta = f"FILE:{rel_p}:{os.path.getsize(full_p)}\n".encode("utf-8")
                    rf.write(meta.ljust(block_size, b"\x00"))

                    # Data blocks
                    with open(full_p, "rb") as f:
                        while True:
                            chunk = f.read(block_size)
                            if not chunk:
                                break
                            if len(chunk) < block_size:
                                chunk = chunk.ljust(block_size, b"\x00")
                            rf.write(chunk)

            # Pad raw partition to minimum 4 blocks (16 KiB)
            cur_sz = rf.tell()
            target_sz = max(cur_sz, block_size * 4)
            if target_sz > cur_sz:
                rf.write(b"\x00" * (target_sz - cur_sz))

        if make_sparse:
            sparse_image_path = os.path.join(self.output_dir, f"{partition_name}.img")
            SparseImage.sparse(raw_image_path, sparse_image_path, block_size=block_size)
            return sparse_image_path

        return raw_image_path

    def repack_update_archive(
        self,
        output_zip_path: str,
        partitions: Optional[dict[str, str]] = None,
    ) -> str:
        """Assembles the final update ZIP archive after strict MCU safety checks.

        Args:
            output_zip_path: Target destination path for update.zip.
            partitions: Dict mapping archive entry name to local partition file path.

        Returns:
            Absolute path to the created update archive.

        Raises:
            MCUSafetyViolationError: If MCU artifacts or flash scripts are detected.
        """
        # Strict pre-pack directory scan
        MCUGuard.scan_directory(self.system_root, raise_on_violation=True)

        candidate_entries: list[str] = []
        if partitions:
            candidate_entries.extend(partitions.keys())

        MCUGuard.enforce_safety(candidate_entries)

        dest_dir = os.path.dirname(os.path.abspath(output_zip_path))
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)

        with zipfile.ZipFile(output_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            if partitions:
                for entry_name, file_path in partitions.items():
                    if MCUGuard.is_mcu_artifact(entry_name):
                        raise MCUSafetyViolationError([entry_name])
                    zf.write(file_path, arcname=entry_name)
            else:
                # Pack system partition by default
                packed_sys = self.pack_partition("system", make_sparse=True)
                zf.write(packed_sys, arcname="system.img")

        # Post-pack deep archive safety scan
        MCUGuard.scan_archive(output_zip_path, raise_on_violation=True)

        return os.path.abspath(output_zip_path)

    def verify_repacked_archive(self, zip_path: str) -> dict:
        """Verifies the integrity of a repacked archive and absence of MCU artifacts."""
        if not os.path.isfile(zip_path) or not zipfile.is_zipfile(zip_path):
            return {"is_valid": False, "error": "Not a valid ZIP file"}

        # Run MCU deep scan
        is_safe, viols = MCUGuard.scan_archive(zip_path, raise_on_violation=False)
        if not is_safe:
            return {"is_valid": False, "error": "MCU violations detected", "violations": viols}

        entries: list[str] = []
        sparse_entries: list[str] = []

        with zipfile.ZipFile(zip_path, "r") as zf:
            if zf.testzip() is not None:
                return {"is_valid": False, "error": "Corrupted ZIP CRC32"}

            for name in zf.namelist():
                entries.append(name)
                if name.endswith(".img"):
                    # Check first 28 bytes for sparse magic
                    with zf.open(name) as f:
                        hdr = f.read(28)
                        if len(hdr) == 28 and struct.unpack("<I", hdr[:4])[0] == 0xED26FF3A:
                            sparse_entries.append(name)

        return {
            "is_valid": True,
            "mcu_safe": True,
            "entries": entries,
            "sparse_partitions": sparse_entries,
        }
