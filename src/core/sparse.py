"""Android Sparse file engine in pure Python for QF001 Debloat OS.

Provides full implementation of the AOSP libsparse format:
- Magic: 0xED26FF3A
- Chunk types: RAW (0xCAC1), FILL (0xCAC2), DONT_CARE (0xCAC3), CRC32 (0xCAC4)
- Streaming I/O with bounded memory footprint (O(1) RAM)
"""

from __future__ import annotations

import os
import struct
import zlib
from typing import Optional

SPARSE_HEADER_MAGIC = 0xED26FF3A
SPARSE_HEADER_MAJOR_VER = 1
SPARSE_HEADER_FILE_HDR_SZ = 28
SPARSE_HEADER_CHUNK_HDR_SZ = 12
DEFAULT_BLOCK_SIZE = 4096

CHUNK_TYPE_RAW = 0xCAC1
CHUNK_TYPE_FILL = 0xCAC2
CHUNK_TYPE_DONT_CARE = 0xCAC3
CHUNK_TYPE_CRC32 = 0xCAC4

BUFFER_STREAM_SIZE = 1048576  # 1 MiB per streaming slice
MAX_CHUNK_BLOCKS = 65535


class SparseError(ValueError):
    """Base exception for sparse image processing errors."""
    pass


class SparseFormatError(SparseError):
    """Raised when file format or header is invalid."""
    pass


class SparseCorruptedError(SparseError, IOError):
    """Raised when sparse chunks or payloads are truncated or corrupted."""
    pass


class SparseChecksumError(SparseError):
    """Raised when CRC32 checksum validation fails."""
    pass


class SparseImage:
    """AOSP Sparse Image format encoder, decoder, and inspector."""

    @classmethod
    def is_sparse(cls, path: str) -> bool:
        """Determines if the given file is a valid Android sparse image.

        Reads the 28-byte file header and validates magic, version and sizes.
        Does not raise exceptions on malformed files; returns False instead.
        """
        if not path or not isinstance(path, str):
            return False

        try:
            if not os.path.isfile(path):
                return False
            size = os.path.getsize(path)
            if size < SPARSE_HEADER_FILE_HDR_SZ:
                return False

            with open(path, "rb") as f:
                header_bytes = f.read(SPARSE_HEADER_FILE_HDR_SZ)

            if len(header_bytes) < SPARSE_HEADER_FILE_HDR_SZ:
                return False

            magic, major_ver, minor_ver, file_hdr_sz, chunk_hdr_sz, blk_sz, total_blks, total_chunks, checksum = (
                struct.unpack("<IHHHHIIII", header_bytes)
            )

            if magic != SPARSE_HEADER_MAGIC:
                return False
            if major_ver != SPARSE_HEADER_MAJOR_VER:
                return False
            if file_hdr_sz < SPARSE_HEADER_FILE_HDR_SZ:
                return False
            if chunk_hdr_sz < SPARSE_HEADER_CHUNK_HDR_SZ:
                return False
            if blk_sz == 0 or (blk_sz % 4 != 0):
                return False

            return True
        except (OSError, struct.error):
            return False

    @classmethod
    def unsparse(cls, source_path: str, dest_path: str) -> bool:
        """Decompresses an Android sparse image into a raw partition image.

        Processes chunks via bounded streaming buffers to support multi-gigabyte
        partitions with minimal RAM usage. Validates chunk sizes and CRC32.
        """
        if not cls.is_sparse(source_path):
            raise SparseFormatError(f"Not a valid Android sparse file: '{source_path}'")

        dest_dir = os.path.dirname(os.path.abspath(dest_path))
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)

        with open(source_path, "rb") as src, open(dest_path, "wb") as dst:
            header_bytes = src.read(SPARSE_HEADER_FILE_HDR_SZ)
            if len(header_bytes) < SPARSE_HEADER_FILE_HDR_SZ:
                raise SparseCorruptedError("Truncated sparse file header")

            magic, major_ver, minor_ver, file_hdr_sz, chunk_hdr_sz, blk_sz, total_blks, total_chunks, checksum = (
                struct.unpack("<IHHHHIIII", header_bytes)
            )

            # Skip extended file header bytes if any
            if file_hdr_sz > SPARSE_HEADER_FILE_HDR_SZ:
                src.seek(file_hdr_sz - SPARSE_HEADER_FILE_HDR_SZ, os.SEEK_CUR)

            running_blocks = 0
            running_crc = 0

            for chunk_idx in range(total_chunks):
                chunk_hdr_bytes = src.read(chunk_hdr_sz)
                if len(chunk_hdr_bytes) < chunk_hdr_sz:
                    raise SparseCorruptedError(
                        f"Premature EOF while reading chunk header {chunk_idx + 1}/{total_chunks}"
                    )

                chunk_type, reserved1, chunk_sz, total_sz = struct.unpack(
                    "<HHII", chunk_hdr_bytes[:SPARSE_HEADER_CHUNK_HDR_SZ]
                )

                if chunk_type == CHUNK_TYPE_RAW:
                    expected_total = chunk_hdr_sz + (chunk_sz * blk_sz)
                    if total_sz != expected_total:
                        raise SparseCorruptedError(
                            f"Corrupted total_sz in RAW chunk {chunk_idx}: expected {expected_total}, got {total_sz}"
                        )
                    bytes_remaining = chunk_sz * blk_sz
                    while bytes_remaining > 0:
                        slice_size = min(bytes_remaining, BUFFER_STREAM_SIZE)
                        data = src.read(slice_size)
                        if len(data) < slice_size:
                            raise SparseCorruptedError(
                                f"Truncated RAW chunk data: expected {slice_size} bytes, got {len(data)}"
                            )
                        dst.write(data)
                        running_crc = zlib.crc32(data, running_crc)
                        bytes_remaining -= slice_size
                    running_blocks += chunk_sz

                elif chunk_type == CHUNK_TYPE_FILL:
                    expected_total = chunk_hdr_sz + 4
                    if total_sz != expected_total:
                        raise SparseCorruptedError(
                            f"Corrupted total_sz in FILL chunk {chunk_idx}: expected {expected_total}, got {total_sz}"
                        )
                    pattern = src.read(4)
                    if len(pattern) < 4:
                        raise SparseCorruptedError(
                            f"Truncated FILL chunk pattern in chunk {chunk_idx}"
                        )
                    bytes_remaining = chunk_sz * blk_sz
                    # Build reusable block buffer
                    unit_len = min(bytes_remaining, BUFFER_STREAM_SIZE)
                    # Round down to multiple of 4
                    unit_len = max(4, unit_len - (unit_len % 4))
                    fill_buffer = pattern * (unit_len // 4)

                    while bytes_remaining > 0:
                        write_len = min(bytes_remaining, len(fill_buffer))
                        slice_data = fill_buffer[:write_len]
                        dst.write(slice_data)
                        running_crc = zlib.crc32(slice_data, running_crc)
                        bytes_remaining -= write_len
                    running_blocks += chunk_sz

                elif chunk_type == CHUNK_TYPE_DONT_CARE:
                    expected_total = chunk_hdr_sz
                    if total_sz != expected_total:
                        raise SparseCorruptedError(
                            f"Corrupted total_sz in DONT_CARE chunk {chunk_idx}: expected {expected_total}, got {total_sz}"
                        )
                    bytes_remaining = chunk_sz * blk_sz
                    zero_buffer = b"\x00" * min(bytes_remaining, BUFFER_STREAM_SIZE)
                    while bytes_remaining > 0:
                        write_len = min(bytes_remaining, len(zero_buffer))
                        slice_data = zero_buffer[:write_len]
                        dst.write(slice_data)
                        running_crc = zlib.crc32(slice_data, running_crc)
                        bytes_remaining -= write_len
                    running_blocks += chunk_sz

                elif chunk_type == CHUNK_TYPE_CRC32:
                    expected_total = chunk_hdr_sz + 4
                    if total_sz != expected_total or chunk_sz != 0:
                        raise SparseCorruptedError(
                            f"Corrupted CRC32 chunk header {chunk_idx}"
                        )
                    crc_bytes = src.read(4)
                    if len(crc_bytes) < 4:
                        raise SparseCorruptedError(
                            f"Truncated CRC32 checksum in chunk {chunk_idx}"
                        )
                    expected_crc = struct.unpack("<I", crc_bytes)[0]
                    if (running_crc & 0xFFFFFFFF) != (expected_crc & 0xFFFFFFFF):
                        raise SparseChecksumError(
                            f"CRC32 mismatch at chunk {chunk_idx}: expected {expected_crc:#010x}, got {running_crc:#010x}"
                        )

                else:
                    raise SparseCorruptedError(
                        f"Unrecognized chunk type {chunk_type:#x} at chunk index {chunk_idx}"
                    )

            if running_blocks != total_blks:
                raise SparseCorruptedError(
                    f"Decompressed block count mismatch: header specifies {total_blks}, extracted {running_blocks}"
                )

        return True

    @classmethod
    def sparse(
        cls,
        source_path: str,
        dest_path: str,
        block_size: int = DEFAULT_BLOCK_SIZE,
    ) -> bool:
        """Converts a raw partition image into an Android sparse image.

        Scans source in blocks of block_size, identifying runs of zeros (DONT_CARE),
        constant repeated 32-bit values (FILL), and arbitrary data (RAW).
        Coalesces consecutive blocks into chunks up to MAX_CHUNK_BLOCKS.
        """
        if not os.path.isfile(source_path):
            raise FileNotFoundError(f"Source file not found: '{source_path}'")

        if block_size <= 0 or (block_size % 4 != 0):
            raise ValueError(f"block_size must be a positive multiple of 4, got {block_size}")

        dest_dir = os.path.dirname(os.path.abspath(dest_path))
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)

        file_size = os.path.getsize(source_path)
        total_blocks = (file_size + block_size - 1) // block_size if file_size > 0 else 0

        zero_block = b"\x00" * block_size

        with open(source_path, "rb") as src, open(dest_path, "wb") as dst:
            # Reserve 28 bytes for sparse file header
            dst.write(b"\x00" * SPARSE_HEADER_FILE_HDR_SZ)

            current_type: Optional[int] = None
            current_blocks = 0
            current_fill_pattern: Optional[bytes] = None
            raw_block_start = 0
            total_chunks = 0

            def flush_chunk() -> None:
                nonlocal current_type, current_blocks, current_fill_pattern, raw_block_start, total_chunks
                if current_blocks == 0 or current_type is None:
                    return

                if current_type == CHUNK_TYPE_DONT_CARE:
                    chunk_hdr = struct.pack(
                        "<HHII",
                        CHUNK_TYPE_DONT_CARE,
                        0,
                        current_blocks,
                        SPARSE_HEADER_CHUNK_HDR_SZ,
                    )
                    dst.write(chunk_hdr)
                    total_chunks += 1

                elif current_type == CHUNK_TYPE_FILL:
                    chunk_hdr = struct.pack(
                        "<HHII",
                        CHUNK_TYPE_FILL,
                        0,
                        current_blocks,
                        SPARSE_HEADER_CHUNK_HDR_SZ + 4,
                    )
                    dst.write(chunk_hdr)
                    dst.write(current_fill_pattern or b"\x00\x00\x00\x00")
                    total_chunks += 1

                elif current_type == CHUNK_TYPE_RAW:
                    data_bytes = current_blocks * block_size
                    chunk_hdr = struct.pack(
                        "<HHII",
                        CHUNK_TYPE_RAW,
                        0,
                        current_blocks,
                        SPARSE_HEADER_CHUNK_HDR_SZ + data_bytes,
                    )
                    dst.write(chunk_hdr)

                    # Stream raw data from source
                    saved_pos = src.tell()
                    src.seek(raw_block_start * block_size)
                    remaining = data_bytes
                    while remaining > 0:
                        slice_len = min(remaining, BUFFER_STREAM_SIZE)
                        raw_data = src.read(slice_len)
                        if len(raw_data) < slice_len:
                            # Pad last block if file was not an exact multiple of block_size
                            raw_data = raw_data.ljust(slice_len, b"\x00")
                        dst.write(raw_data)
                        remaining -= slice_len
                    src.seek(saved_pos)
                    total_chunks += 1

                current_type = None
                current_blocks = 0
                current_fill_pattern = None

            for blk_idx in range(total_blocks):
                block = src.read(block_size)
                if len(block) < block_size:
                    block = block.ljust(block_size, b"\x00")

                # Classify block
                if block == zero_block:
                    b_type = CHUNK_TYPE_DONT_CARE
                    pattern = None
                else:
                    cand_pattern = block[:4]
                    if block == cand_pattern * (block_size // 4):
                        b_type = CHUNK_TYPE_FILL
                        pattern = cand_pattern
                    else:
                        b_type = CHUNK_TYPE_RAW
                        pattern = None

                # Determine if chunk must flush
                must_flush = (
                    current_type is not None
                    and (
                        current_type != b_type
                        or (b_type == CHUNK_TYPE_FILL and pattern != current_fill_pattern)
                        or current_blocks >= MAX_CHUNK_BLOCKS
                    )
                )

                if must_flush:
                    flush_chunk()

                if current_blocks == 0:
                    current_type = b_type
                    current_fill_pattern = pattern
                    if b_type == CHUNK_TYPE_RAW:
                        raw_block_start = blk_idx

                current_blocks += 1

            flush_chunk()

            # Write finalized sparse header
            dst.seek(0)
            file_hdr = struct.pack(
                "<IHHHHIIII",
                SPARSE_HEADER_MAGIC,
                SPARSE_HEADER_MAJOR_VER,
                0,                          # minor_version
                SPARSE_HEADER_FILE_HDR_SZ,
                SPARSE_HEADER_CHUNK_HDR_SZ,
                block_size,
                total_blocks,
                total_chunks,
                0,                          # checksum uncomputed
            )
            dst.write(file_hdr)

        return True
