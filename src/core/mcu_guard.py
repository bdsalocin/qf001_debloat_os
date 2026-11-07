"""Hardware isolation shield guaranteeing zero modification to MCU firmware."""

from __future__ import annotations

import io
import os
import posixpath
import re
import struct
import unicodedata
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple, Union


class MCUSafetyError(Exception):
    """Base exception for all MCU safety guard errors."""
    pass


class MCUSafetyViolationError(MCUSafetyError):
    """Raised when an MCU firmware artifact or flashing command is detected.

    Attributes:
        violations: Detailed descriptions of each safety violation.
        context: Additional inspection metadata.
    """

    def __init__(self, violations: list[str], context: Optional[dict] = None) -> None:
        self.violations = violations
        self.context = context or {}
        msg = (
            "[MCU SAFETY VIOLATION] Hardware invariant breached: zero modification "
            f"to MCU firmware permitted. Detected {len(violations)} violation(s):\n"
            + "\n".join(f"  - {v}" for v in violations)
            + "\nPackaging has been immediately halted to prevent hardware bricking."
        )
        super().__init__(msg)


class MCUGuard:
    """Hardware isolation shield enforcing zero MCU firmware modification."""

    # Prohibited filename regexes evaluated against normalized lowercase basename
    _FILENAME_PATTERNS = [
        # General MCU firmware binaries, images, and scripts
        re.compile(r"^.*mcu.*\.bin$"),
        re.compile(r"^.*mcu.*\.hex$"),
        re.compile(r"^.*mcu.*\.dfu$"),
        re.compile(r"^.*mcu.*\.elf$"),
        re.compile(r"^.*mcu.*\.rom$"),
        re.compile(r"^.*mcu.*\.img$"),
        re.compile(r"^.*mcu.*\.sh$"),
        # STM32 microcontroller family
        re.compile(r"^.*stm32.*\.bin$"),
        re.compile(r"^.*stm32.*\.hex$"),
        re.compile(r"^.*stm32.*\.dfu$"),
        re.compile(r"^.*stm32.*\.elf$"),
        re.compile(r"^.*stm32.*\.img$"),
        re.compile(r"^.*stm32.*\.rom$"),
        # GD32 microcontroller family
        re.compile(r"^.*gd32.*\.bin$"),
        re.compile(r"^.*gd32.*\.hex$"),
        re.compile(r"^.*gd32.*\.dfu$"),
        re.compile(r"^.*gd32.*\.elf$"),
        re.compile(r"^.*gd32.*\.img$"),
        re.compile(r"^.*gd32.*\.rom$"),
        # Nuvoton microcontroller family (N76E, NUC1xx, generic nuvoton)
        re.compile(r"^.*n76e.*\.bin$"),
        re.compile(r"^.*n76e.*\.hex$"),
        re.compile(r"^.*n76e.*\.img$"),
        re.compile(r"^.*n76e.*\.rom$"),
        re.compile(r"^.*nuvoton.*$"),
        re.compile(r"^.*nuc1[0-9]{2}.*$"),
        # Vendor MCU ICs and update tools
        re.compile(r"^mcu_update.*$"),
        re.compile(r"^ts8827\.bin$"),
        re.compile(r"^ts8828\.bin$"),
        re.compile(r"^.*ts882[78].*$"),
        re.compile(r"^iap_mcu.*$"),
        re.compile(r"^.*iap.*\.(bin|hex|dfu|elf|img|rom)$"),
        re.compile(r"^.*flash.*mcu.*$"),
    ]

    # Prohibited partition keywords
    _PROHIBITED_PARTITIONS = {
        "mcu",
        "mcu_fw",
        "mcu_app",
        "mcu_boot",
        "iap",
        "stm32",
        "gd32",
        "nuvoton",
    }

    # Prohibited device node regexes (case-insensitive)
    _DEV_NODE_PATTERNS = [
        re.compile(r"/dev/ttyS[0-9]+", re.IGNORECASE),
        re.compile(r"/dev/ttyUSB[0-9]+", re.IGNORECASE),
        re.compile(r"/dev/ttyACM[0-9]+", re.IGNORECASE),
        re.compile(r"/dev/ttyHS[0-9]+", re.IGNORECASE),
        re.compile(r"/dev/ttyMT[0-9]+", re.IGNORECASE),
        re.compile(r"/dev/ttyGS[0-9]+", re.IGNORECASE),
        re.compile(r"/dev/mcu.*", re.IGNORECASE),
        re.compile(r"/dev/mtd.*mcu.*", re.IGNORECASE),
        re.compile(r"/dev/block/(?:.*/)?by-name/.*mcu.*", re.IGNORECASE),
    ]

    # Prohibited script commands
    _PROHIBITED_SCRIPT_COMMANDS = [
        "stm32flash",
        "mcu_update",
        "flash_mcu",
    ]

    # Extensions recognized as textual or config files (excluded from vector table sniffing)
    _KNOWN_TEXT_EXTENSIONS = {
        ".txt", ".json", ".xml", ".prop", ".md", ".html", ".htm",
        ".csv", ".rc", ".cfg", ".ini", ".conf", ".yaml", ".yml",
        ".mf", ".sf", ".log",
    }

    # Extensions recognized as container archives (audited via dedicated archive inspection)
    _KNOWN_ARCHIVE_EXTENSIONS = {
        ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z",
        ".apk", ".jar",
    }

    @classmethod
    def _normalize_path(cls, path_str: str) -> tuple[str, str]:
        """Normalizes path and returns (clean_path, lowercase_basename).

        Applies Unicode NFKC decomposition to neutralize homoglyphs and
        strips trailing dots and spaces to emulate FAT32 filesystem resolution.
        """
        if not path_str or not isinstance(path_str, str):
            return "", ""
        clean = unicodedata.normalize("NFKC", path_str).strip().replace("\\", "/")
        norm = posixpath.normpath(clean)
        while norm.startswith("./"):
            norm = norm[2:]
        if norm.startswith("/"):
            norm = norm[1:]
        base = posixpath.basename(norm).lower().rstrip(". ")
        return norm, base

    @classmethod
    def is_mcu_artifact(cls, filename: str) -> bool:
        """Determines if a filename or path represents an MCU firmware artifact.

        Implements interface contract from PROJECT.md:
        MCUGuard.is_mcu_artifact(filename: str) -> bool
        """
        if not filename or not isinstance(filename, str):
            return False

        _, base = cls._normalize_path(filename)
        if not base:
            return False

        for pattern in cls._FILENAME_PATTERNS:
            if pattern.match(base):
                return True

        return False

    @classmethod
    def check_archive_safety(cls, file_list: list[str]) -> tuple[bool, list[str]]:
        """Validates a list of file paths against prohibited MCU patterns.

        Implements interface contract from PROJECT.md:
        MCUGuard.check_archive_safety(file_list: list[str]) -> tuple[bool, list[str]]

        Returns:
            Tuple of (is_safe: bool, flagged: list[str]) where flagged contains
            the exact matching entries from file_list.
        """
        flagged: list[str] = []

        for entry in file_list:
            if cls.is_mcu_artifact(entry):
                flagged.append(entry)

        is_safe = len(flagged) == 0
        return is_safe, flagged

    @classmethod
    def enforce_safety(cls, file_list: list[str]) -> None:
        """Enforces archive safety, raising MCUSafetyViolationError on any violation."""
        is_safe, flagged = cls.check_archive_safety(file_list)
        if not is_safe:
            raise MCUSafetyViolationError(flagged)

    @classmethod
    def check_script_content(
        cls, content: str, script_name: str = "updater-script"
    ) -> tuple[bool, list[str]]:
        """Parses script content line by line to detect MCU flashing commands or targets.

        Returns:
            Tuple of (is_safe: bool, violations: list[str]).
        """
        violations: list[str] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            lower_line = stripped.lower()

            # 1. Check for prohibited MCU filenames in script
            tokens = re.findall(r"[\w.\-]+", lower_line)
            for token in tokens:
                if cls.is_mcu_artifact(token):
                    violations.append(
                        f"[{script_name}:{idx}] Reference to prohibited MCU file '{token}': {stripped}"
                    )
                    break

            # 2. Check for prohibited target partitions (command-agnostic detection)
            for part in cls._PROHIBITED_PARTITIONS:
                part_regex = rf'(?:by-name/|[\"\']|\b)[a-z0-9_\-]*{re.escape(part)}[a-z0-9_\-]*(?:[\"\']|\b)'
                if re.search(part_regex, lower_line):
                    violations.append(
                        f"[{script_name}:{idx}] Prohibited target partition '{part}' in command: {stripped}"
                    )
                    break

            # 3. Check for prohibited device nodes (UART / serial flashing)
            for dev_pattern in cls._DEV_NODE_PATTERNS:
                if dev_pattern.search(stripped):
                    violations.append(
                        f"[{script_name}:{idx}] Prohibited MCU communication dev node detected: {stripped}"
                    )
                    break

            # 4. Check for prohibited script flashing commands
            for cmd in cls._PROHIBITED_SCRIPT_COMMANDS:
                if cmd in lower_line:
                    violations.append(
                        f"[{script_name}:{idx}] Prohibited MCU flashing command '{cmd}' detected: {stripped}"
                    )
                    break

        is_safe = len(violations) == 0
        return is_safe, violations

    @classmethod
    def inspect_cortex_m_vector_table(cls, data: bytes) -> bool:
        """Inspects raw binary header to detect ARM Cortex-M bare-metal vector tables.

        Validates:
        - Word 0: Initial SP in SRAM range (0x20000000 - 0x20080000), 4-byte aligned.
        - Word 1: Reset handler in Flash range (0x08000000 - 0x08200000), Thumb bit set.
        - Word 2 (NMI) and Word 3 (HardFault) in Flash range with Thumb bit set.
        """
        if len(data) < 16:
            return False

        try:
            sp, reset_vec, nmi_vec, hardfault_vec = struct.unpack("<4I", data[:16])
        except struct.error:
            return False

        sp_valid = (0x20000000 <= sp <= 0x20080000) and (sp & 0x3 == 0)
        reset_valid = (0x08000000 <= reset_vec <= 0x08200000) and (reset_vec & 0x1 == 1)
        nmi_valid = (0x08000000 <= nmi_vec <= 0x08200000) and (nmi_vec & 0x1 == 1)
        hardfault_valid = (0x08000000 <= hardfault_vec <= 0x08200000) and (hardfault_vec & 0x1 == 1)

        return sp_valid and reset_valid and nmi_valid and hardfault_valid

    @classmethod
    def scan_directory(
        cls, dir_path: str | Path, raise_on_violation: bool = True
    ) -> tuple[bool, list[str]]:
        """Recursively scans a directory for MCU artifacts and script violations."""
        root_path = Path(dir_path)
        violations: list[str] = []

        if not root_path.exists() or not root_path.is_dir():
            return True, []

        for current_root, _, files in os.walk(root_path):
            for file_name in files:
                full_path = Path(current_root) / file_name
                rel_path = full_path.relative_to(root_path).as_posix()
                lower_name = file_name.lower()
                ext = posixpath.splitext(lower_name)[1]

                # 1. Check filename
                if cls.is_mcu_artifact(file_name):
                    violations.append(
                        f"Prohibited MCU firmware file detected: '{rel_path}'"
                    )

                # 2. Check scripts
                if file_name in ["updater-script", "update-binary"] or ext == ".sh":
                    try:
                        content = full_path.read_text(encoding="utf-8", errors="ignore")
                        script_safe, script_viols = cls.check_script_content(
                            content, script_name=rel_path
                        )
                        if not script_safe:
                            violations.extend(script_viols)
                    except Exception as e:
                        violations.append(f"Error reading script '{rel_path}': {e}")

                # 3. Check nested zip in directory
                elif ext == ".zip":
                    try:
                        zip_safe, zip_viols = cls.scan_archive(full_path, raise_on_violation=False)
                        if not zip_safe:
                            for zv in zip_viols:
                                violations.append(f"Inside archive '{rel_path}': {zv}")
                    except Exception as e:
                        violations.append(f"Failed to scan archive '{rel_path}': {e}")

                # 4. Universal vector table sniffing for all files >= 16 bytes excluding known text & archives
                elif ext not in cls._KNOWN_TEXT_EXTENSIONS and ext not in cls._KNOWN_ARCHIVE_EXTENSIONS:
                    try:
                        if full_path.stat().st_size >= 16:
                            with open(full_path, "rb") as bf:
                                header = bf.read(64)
                                if len(header) >= 16 and cls.inspect_cortex_m_vector_table(header):
                                    violations.append(
                                        f"Disguised ARM Cortex-M MCU binary payload detected: '{rel_path}'"
                                    )
                    except Exception:
                        pass

        is_safe = len(violations) == 0
        if not is_safe and raise_on_violation:
            raise MCUSafetyViolationError(violations)
        return is_safe, violations

    @classmethod
    def scan_archive(
        cls,
        archive_path: str | Path | io.BytesIO | bytes,
        raise_on_violation: bool = True,
        max_depth: int = 5,
    ) -> tuple[bool, list[str]]:
        """Deep scans a ZIP archive for MCU files, script commands, and nested archives.

        Supports file paths, Path objects, byte buffers, or in-memory archives.
        Recursively audits nested ZIP archives up to max_depth levels.
        Universally inspects non-text, non-archive entries for ARM Cortex-M vector tables.
        """
        violations: list[str] = []

        if isinstance(archive_path, (str, Path)):
            arch_p = Path(archive_path)
            if not arch_p.exists() or not arch_p.is_file():
                raise FileNotFoundError(f"Archive not found: {archive_path}")
            target_source: str | Path | io.BytesIO = arch_p
        elif isinstance(archive_path, (bytes, bytearray)):
            target_source = io.BytesIO(archive_path)
        elif isinstance(archive_path, io.BytesIO):
            target_source = archive_path
        else:
            raise TypeError(f"Unsupported archive source type: {type(archive_path)}")

        try:
            with zipfile.ZipFile(target_source, "r") as zf:
                name_list = zf.namelist()

                # 1. Inspect archive entry names
                is_safe_names, name_viols = cls.check_archive_safety(name_list)
                if not is_safe_names:
                    violations.extend(name_viols)

                # 2. Inspect script files, nested archives, and sniff binary vectors inside archive
                for item in name_list:
                    if item.endswith("/"):
                        continue

                    lower_item = item.lower()
                    base_name = posixpath.basename(item)
                    lower_base = base_name.lower()
                    ext = posixpath.splitext(lower_base)[1]

                    # Script inspection
                    if (
                        "updater-script" in lower_item
                        or "update-binary" in lower_item
                        or lower_item.endswith(".sh")
                    ):
                        try:
                            script_content = zf.read(item).decode("utf-8", errors="ignore")
                            script_safe, script_viols = cls.check_script_content(
                                script_content, script_name=item
                            )
                            if not script_safe:
                                violations.extend(script_viols)
                        except Exception as e:
                            violations.append(f"Failed to read script '{item}': {e}")

                    # Recursive inspection of nested zip archives
                    elif lower_item.endswith(".zip") and max_depth > 0:
                        try:
                            nested_bytes = zf.read(item)
                            nested_safe, nested_viols = cls.scan_archive(
                                nested_bytes,
                                raise_on_violation=False,
                                max_depth=max_depth - 1,
                            )
                            if not nested_safe:
                                for nv in nested_viols:
                                    violations.append(f"Inside nested archive '{item}': {nv}")
                        except Exception as e:
                            violations.append(f"Failed to inspect nested zip '{item}': {e}")

                    # Universal binary sniffing on candidate entries
                    elif ext not in cls._KNOWN_TEXT_EXTENSIONS and ext not in cls._KNOWN_ARCHIVE_EXTENSIONS:
                        try:
                            with zf.open(item) as entry_file:
                                data_head = entry_file.read(64)
                                if (
                                    len(data_head) >= 16
                                    and cls.inspect_cortex_m_vector_table(data_head)
                                ):
                                    violations.append(
                                        f"Disguised ARM Cortex-M MCU binary payload in archive: '{item}'"
                                    )
                        except Exception:
                            pass

        except zipfile.BadZipFile as e:
            violations.append(f"Invalid or corrupted ZIP archive: {e}")

        is_safe = len(violations) == 0
        if not is_safe and raise_on_violation:
            raise MCUSafetyViolationError(violations)

        return is_safe, violations
