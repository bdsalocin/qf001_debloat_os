"""Helper utilities and fixtures for QF001 Debloat OS E2E Tests."""
import os
import struct
import zipfile
from typing import Dict, List, Optional, Tuple

SPARSE_HEADER_MAGIC = 0xED26FF3A
CHUNK_TYPE_RAW = 0xCAC1
CHUNK_TYPE_FILL = 0xCAC2
CHUNK_TYPE_DONT_CARE = 0xCAC3
CHUNK_TYPE_CRC32 = 0xCAC4

FAT32_ILLEGAL_CHARS = set(r'\/:*?"<>|')
MAX_FAT32_FILE_SIZE = 4294967295  # 4 GiB - 1 byte


def build_sparse_image_bytes(raw_blocks: List[bytes], blk_sz: int = 4096) -> bytes:
    """Build a standard AOSP Android sparse image in memory."""
    total_blocks = len(raw_blocks)
    chunks_bytes = bytearray()
    num_chunks = 0

    for block in raw_blocks:
        padded_block = block.ljust(blk_sz, b"\x00")[:blk_sz]
        chunk_header = struct.pack(
            "<HHII",
            CHUNK_TYPE_RAW,   # chunk_type
            0,                # reserved1
            1,                # chunk_sz in blocks
            12 + blk_sz       # total_sz in bytes (header + data)
        )
        chunks_bytes.extend(chunk_header)
        chunks_bytes.extend(padded_block)
        num_chunks += 1

    file_header = struct.pack(
        "<IHHHHIIII",
        SPARSE_HEADER_MAGIC,  # magic
        1,                    # major_version
        0,                    # minor_version
        28,                   # file_hdr_sz
        12,                   # chunk_hdr_sz
        blk_sz,               # blk_sz
        total_blocks,         # total_blks
        num_chunks,           # total_chunks
        0                     # image_checksum
    )

    return bytes(file_header + chunks_bytes)


def create_valid_sparse_file(filepath: str, num_blocks: int = 4, blk_sz: int = 4096) -> str:
    """Create a valid Android sparse file on disk."""
    raw_blocks = [f"BLOCK_PAYLOAD_{i}_QF001_DATA".encode("utf-8") for i in range(num_blocks)]
    data = build_sparse_image_bytes(raw_blocks, blk_sz=blk_sz)
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(data)
    return filepath


def create_corrupt_sparse_file(filepath: str, corruption: str = "bad_magic") -> str:
    """Create a corrupt Android sparse file for boundary/stress testing."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    if corruption == "bad_magic":
        data = struct.pack("<IHHHHIIII", 0xDEADBEEF, 1, 0, 28, 12, 4096, 2, 1, 0)
    elif corruption == "truncated_header":
        data = b"\x3a\xff\x26\xed\x01\x00"  # Only 6 bytes
    elif corruption == "truncated_chunk":
        # Valid header but truncated chunk payload
        header = struct.pack("<IHHHHIIII", SPARSE_HEADER_MAGIC, 1, 0, 28, 12, 4096, 1, 1, 0)
        chunk_hdr = struct.pack("<HHII", CHUNK_TYPE_RAW, 0, 1, 12 + 4096)
        data = header + chunk_hdr + b"SHORT_DATA"
    elif corruption == "zero_byte":
        data = b""
    else:
        data = b"RANDOM_CORRUPT_BYTES" * 16

    with open(filepath, "wb") as f:
        f.write(data)
    return filepath


def create_mock_system_fs(
    root_dir: str,
    installed_packages: Optional[List[str]] = None,
    include_build_prop: bool = True
) -> str:
    """Create a mock Android system filesystem tree under root_dir."""
    if installed_packages is None:
        installed_packages = [
            # Critical preserved automotive packages
            "com.ts.main.radio",
            "com.syu.canbus",
            "com.roco.canbus",
            "com.syu.bt",
            "com.ts.camera",
            "com.ts.car",
            # Bloatware packages to be removed
            "com.google.android.apps.tachyon",
            "com.android.carrierdefaultapp",
            "com.autonavi.amapauto",
            "com.baidu.BaiduMap",
            "com.fyt.feedback",
            "com.ts.car.updater",
            "com.chinese.telemetry",
            # Standard android app
            "com.android.settings"
        ]

    system_dir = os.path.join(root_dir, "system")
    app_dir = os.path.join(system_dir, "app")
    priv_app_dir = os.path.join(system_dir, "priv-app")
    os.makedirs(app_dir, exist_ok=True)
    os.makedirs(priv_app_dir, exist_ok=True)

    for i, pkg in enumerate(installed_packages):
        target_dir = priv_app_dir if i % 2 == 0 else app_dir
        pkg_folder = os.path.join(target_dir, pkg)
        os.makedirs(pkg_folder, exist_ok=True)
        apk_path = os.path.join(pkg_folder, f"{pkg}.apk")
        with open(apk_path, "wb") as f:
            f.write(f"MOCK_APK_FOR_{pkg}".encode("utf-8"))

    if include_build_prop:
        build_prop = os.path.join(system_dir, "build.prop")
        with open(build_prop, "w", encoding="utf-8") as f:
            f.write("ro.product.board=ROCO_K706\n")
            f.write("ro.build.version.release=10\n")
            f.write("ro.hardware.platform=uis7862\n")
            f.write("ro.qf001.radio.tuner=TDA7708\n")
            f.write("ro.qf001.audio.dsp=BU32107EFV\n")

    return system_dir


def create_mock_update_zip(zip_path: str, files_dict: Dict[str, bytes]) -> str:
    """Create a mock update.zip archive containing specified files."""
    os.makedirs(os.path.dirname(os.path.abspath(zip_path)), exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, content in files_dict.items():
            zf.writestr(arcname, content)
    return zip_path


def validate_fat32_filename(filename: str) -> Tuple[bool, str]:
    """Validate whether a filename is strictly FAT32 compliant."""
    if len(filename) == 0:
        return False, "Filename cannot be empty"
    if len(filename) > 255:
        return False, f"Filename exceeds 255 characters ({len(filename)})"
    for char in filename:
        if char in FAT32_ILLEGAL_CHARS:
            return False, f"Filename contains illegal FAT32 character: '{char}'"
    return True, "Valid"
