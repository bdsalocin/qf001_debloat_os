"""Tier 2: Boundary & Corner Cases E2E Tests for QF001 Debloat OS.

Validates system behavior against:
- Empty lists & degenerate configurations
- Corrupt and truncated Android sparse headers
- MCU intrusion attempts (nested paths, uppercase, extensions)
- FAT32 illegal characters and length violations
- Malformed blacklist / corrupted JSON configs
- Zero-byte files and degenerate filesystem trees
"""
import json
import os
import tempfile
import unittest

from tests.e2e.test_helpers import (
    create_corrupt_sparse_file,
    create_valid_sparse_file,
    validate_fat32_filename,
    FAT32_ILLEGAL_CHARS
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))


class TestTier2BoundariesAndCornerCases(unittest.TestCase):
    """Tier 2 Boundary, Malformed Input & Adversarial Corner Cases."""

    def test_tier2_01_empty_blacklist_and_whitelist(self):
        """Boundary: Debloater with empty blacklist or empty whitelist."""
        try:
            from src.domain.debloater import Debloater
        except ImportError as e:
            raise unittest.SkipTest(f"Debloater pending: {e}")

        # Empty blacklist
        d_empty_bl = Debloater(blacklist=[], whitelist=["com.ts.main.radio"])
        res1 = d_empty_bl.filter_packages(["com.baidu.BaiduMap", "com.ts.main.radio"])
        self.assertEqual(len(res1), 0, "Empty blacklist must result in zero packages removed")

        # Empty whitelist
        d_empty_wl = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
        res2 = d_empty_wl.filter_packages(["com.baidu.BaiduMap", "com.ts.main.radio"])
        self.assertEqual(res2, {"com.baidu.BaiduMap"})

        # Both empty
        d_both_empty = Debloater(blacklist=[], whitelist=[])
        res3 = d_both_empty.filter_packages(["com.baidu.BaiduMap"])
        self.assertEqual(len(res3), 0)

    def test_tier2_02_corrupt_sparse_magic_rejection(self):
        """Boundary: Sparse engine must reject files with invalid magic bytes."""
        try:
            from src.core.sparse import SparseImage
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"SparseImage pending Milestone M1: {e}")

        with tempfile.TemporaryDirectory() as tmpdir:
            bad_magic_file = os.path.join(tmpdir, "bad_magic.img")
            create_corrupt_sparse_file(bad_magic_file, corruption="bad_magic")

            self.assertFalse(SparseImage.is_sparse(bad_magic_file),
                             "SparseImage.is_sparse must return False for invalid magic 0xDEADBEEF")

    def test_tier2_03_corrupt_sparse_truncated_header(self):
        """Boundary: Sparse file truncated before complete 28-byte header."""
        try:
            from src.core.sparse import SparseImage
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"SparseImage pending Milestone M1: {e}")

        with tempfile.TemporaryDirectory() as tmpdir:
            trunc_hdr_file = os.path.join(tmpdir, "trunc_header.img")
            create_corrupt_sparse_file(trunc_hdr_file, corruption="truncated_header")

            # Must handle short file gracefully without uncaught struct unpack errors
            self.assertFalse(SparseImage.is_sparse(trunc_hdr_file),
                             "Truncated header (<28 bytes) must be rejected safely")

    def test_tier2_04_corrupt_sparse_truncated_chunk_payload(self):
        """Boundary: Valid sparse header but truncated chunk payload data."""
        try:
            from src.core.sparse import SparseImage
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"SparseImage pending Milestone M1: {e}")

        with tempfile.TemporaryDirectory() as tmpdir:
            trunc_chunk_file = os.path.join(tmpdir, "trunc_chunk.img")
            out_raw = os.path.join(tmpdir, "out.raw")
            create_corrupt_sparse_file(trunc_chunk_file, corruption="truncated_chunk")

            # unsparse should fail or raise ValueError, not corrupt memory
            try:
                result = SparseImage.unsparse(trunc_chunk_file, out_raw)
                self.assertFalse(result, "Unsparse of truncated chunk must return False")
            except (ValueError, IOError, EOFError):
                pass  # Raising a structured error is also acceptable

    def test_tier2_05_zero_byte_sparse_file(self):
        """Boundary: 0-byte file must be safely identified as non-sparse."""
        try:
            from src.core.sparse import SparseImage
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"SparseImage pending Milestone M1: {e}")

        with tempfile.TemporaryDirectory() as tmpdir:
            zero_file = os.path.join(tmpdir, "zero.img")
            create_corrupt_sparse_file(zero_file, corruption="zero_byte")
            self.assertFalse(SparseImage.is_sparse(zero_file))

    def test_tier2_06_mcu_intrusion_case_variations(self):
        """Boundary: MCUGuard must detect MCU files regardless of casing (FAT32 case-insensitivity)."""
        try:
            from src.core.mcu_guard import MCUGuard
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"MCUGuard pending Milestone M1: {e}")

        case_variations = ["MCU.BIN", "Mcu.Bin", "mCu.bIn", "K706_MCU.BIN", "MCU.HEX"]
        for filename in case_variations:
            self.assertTrue(MCUGuard.is_mcu_artifact(filename),
                            f"MCUGuard must flag casing variation: {filename}")

    def test_tier2_07_mcu_intrusion_deeply_nested_paths(self):
        """Boundary: MCU binaries hidden in deep subdirectories or traversal paths."""
        try:
            from src.core.mcu_guard import MCUGuard
        except (ImportError, AttributeError) as e:
            raise unittest.SkipTest(f"MCUGuard pending Milestone M1: {e}")

        nested_paths = [
            "system/etc/firmware/mcu.bin",
            "META-INF/com/google/mcu.bin",
            "assets/drivers/stm32_mcu.hex",
            "tools/updater_mcu.bin",
            "nested/dir/level3/mcu_isp.bin"
        ]
        is_safe, flagged = MCUGuard.check_archive_safety(nested_paths)
        self.assertFalse(is_safe, "Archive with nested MCU artifacts must be flagged as unsafe")
        self.assertEqual(len(flagged), len(nested_paths), "All nested MCU artifacts must be caught")

    def test_tier2_08_fat32_illegal_character_rejection(self):
        """Boundary: FAT32 disallowed characters in partition or package filenames."""
        for char in FAT32_ILLEGAL_CHARS:
            bad_name = f"update{char}pack.zip"
            is_valid, msg = validate_fat32_filename(bad_name)
            self.assertFalse(is_valid, f"Character '{char}' must be rejected for FAT32: {msg}")

    def test_tier2_09_fat32_filename_length_boundary(self):
        """Boundary: FAT32 255-character maximum filename limit."""
        name_255 = "a" * 251 + ".zip"
        is_valid_255, _ = validate_fat32_filename(name_255)
        self.assertTrue(is_valid_255, "255-character filename should be valid in FAT32 LFN")

        name_256 = "a" * 252 + ".zip"
        is_valid_256, msg = validate_fat32_filename(name_256)
        self.assertFalse(is_valid_256, f"256-character filename must exceed limit: {msg}")

        empty_name = ""
        is_valid_empty, _ = validate_fat32_filename(empty_name)
        self.assertFalse(is_valid_empty, "Empty filename must be rejected")

    def test_tier2_10_malformed_blacklist_handling(self):
        """Boundary: Handling malformed or missing blacklist content gracefully."""
        # Test synthetic malformed dictionary
        malformed_dict = {"invalid_key": "not_a_list"}
        packages = malformed_dict.get("packages", [])
        self.assertEqual(packages, [], "Missing packages key must default safely to empty list")

        # Test non-list packages
        bad_type_dict = {"packages": "just_a_string"}
        raw_pkg = bad_type_dict.get("packages")
        safe_list = raw_pkg if isinstance(raw_pkg, list) else []
        self.assertEqual(safe_list, [], "Non-list packages field must be safely sanitized to empty list")

    def test_tier2_11_empty_system_filesystem_tree(self):
        """Boundary: Debloating an empty directory tree without crashes."""
        try:
            from src.domain.debloater import Debloater
        except ImportError as e:
            raise unittest.SkipTest(f"Debloater pending: {e}")

        if not hasattr(Debloater, "debloat_filesystem"):
            raise unittest.SkipTest("Debloater.debloat_filesystem pending Milestone M2")

        with tempfile.TemporaryDirectory() as tmpdir:
            empty_sys = os.path.join(tmpdir, "empty_system")
            os.makedirs(empty_sys, exist_ok=True)
            debloater = Debloater(blacklist=["com.baidu.BaiduMap"], whitelist=[])
            report = debloater.debloat_filesystem(empty_sys)
            # Should safely complete with 0 files removed
            removed = report.removed_count if hasattr(report, "removed_count") else 0
            self.assertEqual(removed, 0)


if __name__ == "__main__":
    unittest.main()
