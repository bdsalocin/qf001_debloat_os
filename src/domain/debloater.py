"""Filesystem debloater engine enforcing hardware preservation safety rules."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union


class DebloaterError(Exception):
    """Base exception for all Debloater errors."""
    pass


class DebloaterFilesystemError(DebloaterError):
    """Raised when filesystem root is missing, invalid, or inaccessible."""
    pass


class DebloaterSafetyViolationError(DebloaterError):
    """Raised when an operation threatens hardware preserved services."""
    pass


class DebloaterConfigError(DebloaterError):
    """Raised when configuration files or lists are malformed."""
    pass


@dataclass
class DebloatReport:
    """Detailed audit report of filesystem debloating execution."""
    system_root: str
    removed_packages: List[str] = field(default_factory=list)
    preserved_packages: List[str] = field(default_factory=list)
    removed_paths: List[str] = field(default_factory=list)
    bytes_freed: int = 0
    dry_run: bool = False
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    scanned_directories: List[str] = field(default_factory=list)
    total_scanned_apps: int = 0

    @property
    def removed_count(self) -> int:
        """Total count of distinct removed packages."""
        return len(set(self.removed_packages))

    @property
    def preserved_count(self) -> int:
        """Total count of preserved packages."""
        return len(set(self.preserved_packages))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to a standard JSON-compatible dictionary."""
        return {
            "system_root": self.system_root,
            "removed_packages": list(self.removed_packages),
            "preserved_packages": list(self.preserved_packages),
            "removed_paths": list(self.removed_paths),
            "removed_count": self.removed_count,
            "preserved_count": self.preserved_count,
            "bytes_freed": self.bytes_freed,
            "dry_run": self.dry_run,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "total_scanned_apps": self.total_scanned_apps,
        }

    def summary(self) -> str:
        """Human-readable text summary of debloating results."""
        mode = "DRY RUN" if self.dry_run else "EXECUTED"
        mb_freed = self.bytes_freed / (1024 * 1024) if self.bytes_freed > 0 else 0.0
        return (
            f"Debloat Report [{mode}]\n"
            f"  System Root: {self.system_root}\n"
            f"  Scanned Apps: {self.total_scanned_apps}\n"
            f"  Removed Packages ({self.removed_count}): {', '.join(self.removed_packages) or 'None'}\n"
            f"  Preserved Packages ({self.preserved_count}): {', '.join(self.preserved_packages) or 'None'}\n"
            f"  Bytes Freed: {self.bytes_freed} bytes ({mb_freed:.2f} MB)\n"
            f"  Errors: {len(self.errors)}"
        )


@dataclass
class DiscoveredApp:
    """Represents an application found within the filesystem tree."""
    folder_path: str
    folder_name: str
    partition: str
    candidate_packages: Set[str]
    apk_paths: List[str]
    size_bytes: int
    is_directory: bool = True


class Debloater:
    """Filesystem debloater engine enforcing hardware preservation safety rules."""

    _PKG_REGEX = re.compile(rb'[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+')
    _MOCK_REGEX = re.compile(r'MOCK_APK_FOR_([a-zA-Z0-9_\.]*?)(?:[\r\n\x00\s]|$)')

    def __init__(
        self,
        blacklist: Optional[Union[List[str], Set[str]]] = None,
        whitelist: Optional[Union[List[str], Set[str]]] = None,
        config_dir: Optional[str] = None,
    ) -> None:
        self.config_dir = config_dir or self._discover_config_dir()
        self.patterns: List[str] = []
        self.system_binaries: List[str] = []
        self.init_services: List[str] = []
        self.spool_directories: List[str] = []

        if blacklist is None:
            self.blacklist = self._load_default_blacklist()
        else:
            self.blacklist = {pkg.strip() for pkg in blacklist if isinstance(pkg, str) and pkg.strip()}

        if whitelist is None:
            self.whitelist = self._load_default_whitelist()
        else:
            self.whitelist = {pkg.strip() for pkg in whitelist if isinstance(pkg, str) and pkg.strip()}

    def filter_packages(self, installed_packages: List[str]) -> Set[str]:
        """Pure logical filter returning packages scheduled for removal.

        Strictly enforces that any package in whitelist is never returned.
        """
        packages_to_remove = set()
        for pkg in installed_packages:
            if not isinstance(pkg, str):
                continue
            cleaned_pkg = pkg.strip()
            if self._matches_set(cleaned_pkg, self.blacklist) and not self._matches_set(cleaned_pkg, self.whitelist):
                packages_to_remove.add(cleaned_pkg)
        return packages_to_remove

    def debloat_filesystem(
        self,
        system_root: Union[str, Path],
        dry_run: bool = False
    ) -> DebloatReport:
        """Scan candidate system directories and purge blacklisted applications."""
        root_path = os.path.abspath(os.fspath(system_root))
        if not os.path.exists(root_path):
            raise FileNotFoundError(f"System root path does not exist: {root_path}")
        if not os.path.isdir(root_path):
            raise NotADirectoryError(f"System root path is not a directory: {root_path}")

        report = DebloatReport(system_root=root_path, dry_run=dry_run)
        scan_dirs = self._get_scan_directories(root_path)
        report.scanned_directories = scan_dirs

        discovered_apps = self.scan_applications(root_path)
        report.total_scanned_apps = len(discovered_apps)

        for app in discovered_apps:
            # Absolute Rule: Whitelist takes precedence
            if self._is_whitelisted_app(app):
                primary_name = self._determine_primary_name(app)
                report.preserved_packages.append(primary_name)
                continue

            if self._is_blacklisted_app(app):
                primary_name = self._determine_primary_name(app)

                # Check security veto before metrics update
                real_target = os.path.realpath(app.folder_path)
                real_root = os.path.realpath(root_path)
                root_prefix = real_root.rstrip(os.sep) + os.sep
                if real_target == real_root or not real_target.startswith(root_prefix):
                    report.errors.append(f"Security veto: {app.folder_path} resolves outside system root")
                    continue

                if dry_run:
                    if primary_name not in report.removed_packages:
                        report.removed_packages.append(primary_name)
                    report.removed_paths.append(app.folder_path)
                    report.bytes_freed += app.size_bytes
                else:
                    purged = self._purge_path(app.folder_path, root_path, report)
                    if purged:
                        if primary_name not in report.removed_packages:
                            report.removed_packages.append(primary_name)
                        report.removed_paths.append(app.folder_path)
                        report.bytes_freed += app.size_bytes
            else:
                primary_name = self._determine_primary_name(app)
                report.preserved_packages.append(primary_name)

        # Process native binaries, init scripts and spool directories in both dry-run and executed modes
        self._purge_extra_components(root_path, report, dry_run=dry_run)

        return report

    def scan_applications(self, system_root: Union[str, Path]) -> List[DiscoveredApp]:
        """Discover application folders in target partitions."""
        root_path = os.path.abspath(os.fspath(system_root))
        scan_dirs = self._get_scan_directories(root_path)
        discovered: List[DiscoveredApp] = []

        for s_dir in scan_dirs:
            if not os.path.isdir(s_dir):
                continue
            rel_partition = os.path.relpath(s_dir, root_path)
            self._scan_directory_recursive(s_dir, s_dir, rel_partition, discovered)

        return discovered

    def _is_category_container(self, dir_path: str, apks: List[str]) -> bool:
        """Determine whether dir_path is an intermediate category/container folder."""
        if not apks:
            return False

        pkg_names = set()
        for apk in apks:
            extracted = self._extract_package_names_from_apk(apk)
            if extracted:
                pkg_names.update(extracted)
            else:
                pkg_names.add(os.path.basename(apk).lower())

        if len(pkg_names) > 1:
            return True

        try:
            entries = sorted(os.listdir(dir_path))
        except OSError:
            return False

        child_dirs = [e for e in entries if os.path.isdir(os.path.join(dir_path, e)) and not e.startswith(".")]
        child_apks = [e for e in entries if os.path.isfile(os.path.join(dir_path, e)) and e.lower().endswith(".apk")]

        subdirs_with_apks = [
            d for d in child_dirs
            if self._inspect_directory(os.path.join(dir_path, d))[0]
        ]

        if len(subdirs_with_apks) > 1:
            return True
        if len(subdirs_with_apks) >= 1 and len(child_apks) >= 1:
            return True
        if len(child_apks) > 1 and len(pkg_names) > 1:
            return True

        return False

    def _scan_directory_recursive(
        self,
        current_dir: str,
        base_scan_dir: str,
        rel_partition: str,
        discovered: List[DiscoveredApp]
    ) -> None:
        """Scan directories, distinguishing app packages from intermediate category folders."""
        try:
            entries = sorted(os.listdir(current_dir))
        except OSError:
            return

        for entry in entries:
            if entry.startswith("."):
                continue
            full_path = os.path.join(current_dir, entry)

            if os.path.isfile(full_path) and entry.lower().endswith(".apk"):
                size = os.path.getsize(full_path)
                candidates = self._extract_candidates(entry[:-4], [full_path], full_path)
                discovered.append(
                    DiscoveredApp(
                        folder_path=full_path,
                        folder_name=entry,
                        partition=rel_partition,
                        candidate_packages=candidates,
                        apk_paths=[full_path],
                        size_bytes=size,
                        is_directory=False
                    )
                )
            elif os.path.isdir(full_path):
                apks, size = self._inspect_directory(full_path)
                if len(apks) == 0:
                    if current_dir == base_scan_dir:
                        candidates = {entry}
                        discovered.append(
                            DiscoveredApp(
                                folder_path=full_path,
                                folder_name=entry,
                                partition=rel_partition,
                                candidate_packages=candidates,
                                apk_paths=[],
                                size_bytes=0,
                                is_directory=True
                            )
                        )
                elif self._is_category_container(full_path, apks):
                    self._scan_directory_recursive(full_path, base_scan_dir, rel_partition, discovered)
                else:
                    candidates = self._extract_candidates(entry, apks, full_path)
                    discovered.append(
                        DiscoveredApp(
                            folder_path=full_path,
                            folder_name=entry,
                            partition=rel_partition,
                            candidate_packages=candidates,
                            apk_paths=apks,
                            size_bytes=size,
                            is_directory=True
                        )
                    )

    def is_blacklisted(self, candidates: Set[str]) -> bool:
        """Determine if any candidate package identifier matches blacklist."""
        for cand in candidates:
            if self._matches_set(cand, self.blacklist):
                return True
        return False

    def is_whitelisted(self, candidates: Set[str]) -> bool:
        """Determine if any candidate package identifier matches whitelist."""
        for cand in candidates:
            if self._matches_set(cand, self.whitelist):
                return True
        return False

    def _get_scan_directories(self, root_path: str) -> List[str]:
        """Return existing candidate application directories."""
        candidates = [
            os.path.join(root_path, "system", "app"),
            os.path.join(root_path, "system", "priv-app"),
            os.path.join(root_path, "app"),
            os.path.join(root_path, "priv-app"),
            os.path.join(root_path, "product", "app"),
            os.path.join(root_path, "product", "priv-app"),
            os.path.join(root_path, "system", "product", "app"),
            os.path.join(root_path, "system", "product", "priv-app"),
        ]
        seen_realpaths = set()
        existing = []
        for c in candidates:
            if os.path.isdir(c):
                rp = os.path.realpath(c)
                if rp not in seen_realpaths:
                    seen_realpaths.add(rp)
                    existing.append(c)
        return existing

    def _inspect_directory(self, dir_path: str) -> tuple[List[str], int]:
        """Collect APK files and total byte size within a directory."""
        apks = []
        total_size = 0
        for dirpath, _, filenames in os.walk(dir_path):
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                if not os.path.islink(fp):
                    try:
                        total_size += os.path.getsize(fp)
                    except OSError:
                        pass
                if fn.lower().endswith(".apk"):
                    apks.append(fp)
        return apks, total_size

    def _extract_candidates(self, folder_name: str, apks: List[str], target_path: str) -> Set[str]:
        """Extract all candidate package identifiers."""
        candidates = {folder_name}
        for apk in apks:
            apk_fn = os.path.basename(apk)
            if apk_fn.lower().endswith(".apk"):
                candidates.add(apk_fn[:-4])

            # Inspect APK contents
            if os.path.isfile(apk):
                extracted = self._extract_package_names_from_apk(apk)
                candidates.update(extracted)

        return candidates

    def _extract_package_names_from_apk(self, apk_path: str) -> Set[str]:
        """Pure Python extraction from APK archive or test fixture."""
        found = set()
        if not os.path.isfile(apk_path):
            return found

        if zipfile.is_zipfile(apk_path):
            try:
                with zipfile.ZipFile(apk_path, "r") as zf:
                    if "AndroidManifest.xml" in zf.namelist():
                        data = zf.read("AndroidManifest.xml")
                        matches = self._PKG_REGEX.findall(data)
                        for m in matches:
                            try:
                                found.add(m.decode("ascii"))
                            except UnicodeDecodeError:
                                pass
            except Exception:
                pass
        else:
            # Mock APK fixture handling
            try:
                with open(apk_path, "rb") as f:
                    content = f.read(4096)
                text = content.decode("utf-8", errors="ignore")
                mock_match = self._MOCK_REGEX.search(text)
                if mock_match:
                    found.add(mock_match.group(1))
            except Exception:
                pass

        return found

    def _matches_set(self, candidate: str, target_set: Set[str]) -> bool:
        """Check if candidate matches any entry in target_set."""
        c_low = candidate.lower()
        for item in target_set:
            i_low = item.lower()
            if c_low == i_low:
                return True
            # Glob pattern matching (e.g. com.txznet.*)
            if "*" in item or "?" in item:
                if fnmatch.fnmatch(c_low, i_low):
                    return True
            # Basename match: only if candidate does NOT contain dots (e.g. folder name 'BaiduMap')
            if "." not in candidate and "." in item:
                if i_low.split(".")[-1] == c_low:
                    return True
            # Item is short name without dots and candidate is full package
            if "." not in item and "." in candidate:
                if c_low.split(".")[-1] == i_low:
                    return True
        return False

    def _is_whitelisted_app(self, app: DiscoveredApp) -> bool:
        """Check if app matches whitelist."""
        for cand in app.candidate_packages:
            if self._matches_set(cand, self.whitelist):
                return True
        return False

    def _is_blacklisted_app(self, app: DiscoveredApp) -> bool:
        """Check if app matches blacklist."""
        for cand in app.candidate_packages:
            if self._matches_set(cand, self.blacklist):
                return True
        return False

    def _determine_primary_name(self, app: DiscoveredApp) -> str:
        """Select the most representative package identifier."""
        # Check if folder_name directly matches blacklist or whitelist
        if app.folder_name in self.blacklist or app.folder_name in self.whitelist:
            return app.folder_name
        for cand in app.candidate_packages:
            if cand in self.blacklist or cand in self.whitelist:
                return cand
        if "." in app.folder_name:
            return app.folder_name
        for cand in sorted(app.candidate_packages, key=len):
            if "." in cand:
                return cand
        return app.folder_name

    def _purge_path(self, target_path: str, system_root: str, report: DebloatReport) -> bool:
        """Safely remove directory or file with path traversal guard.

        Returns True if target was successfully removed, False otherwise.
        """
        real_target = os.path.realpath(target_path)
        real_root = os.path.realpath(system_root)
        root_prefix = real_root.rstrip(os.sep) + os.sep

        # Strictly reject root itself or any path outside root
        if real_target == real_root or not real_target.startswith(root_prefix):
            report.errors.append(f"Security veto: {target_path} resolves outside system root")
            return False

        if not os.path.lexists(target_path):
            return True

        errors_before = len(report.errors)

        def _unlock_path(path: str) -> None:
            try:
                parent = os.path.dirname(path)
                if parent and os.path.isdir(parent):
                    try:
                        os.chmod(parent, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
                    except OSError:
                        pass
                if os.path.islink(path):
                    return
                if os.path.exists(path):
                    try:
                        os.chmod(path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
                    except OSError:
                        pass
                    if os.path.isdir(path):
                        for root, dirs, files in os.walk(path):
                            for d in dirs:
                                dp = os.path.join(root, d)
                                try:
                                    os.chmod(dp, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
                                except OSError:
                                    pass
                            for f in files:
                                fp = os.path.join(root, f)
                                try:
                                    os.chmod(fp, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
                                except OSError:
                                    pass
            except Exception:
                pass

        def handle_remove_readonly(func: Any, path: str, exc_info: Any) -> None:
            try:
                parent_dir = os.path.dirname(path)
                if parent_dir and os.path.isdir(parent_dir):
                    try:
                        os.chmod(parent_dir, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
                    except OSError:
                        pass
                if os.path.exists(path) and not os.path.islink(path):
                    try:
                        os.chmod(path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
                    except OSError:
                        pass

                # Guard against os.open or variable function signatures
                if func is os.open or getattr(func, "__name__", "") == "open":
                    return

                if func in (os.unlink, os.remove):
                    os.unlink(path)
                elif func is os.rmdir:
                    os.rmdir(path)
                else:
                    try:
                        func(path)
                    except TypeError:
                        pass
            except Exception as e:
                report.errors.append(f"Failed to delete {path}: {e}")

        try:
            if os.path.islink(target_path):
                os.unlink(target_path)
            elif os.path.isdir(target_path):
                _unlock_path(target_path)
                shutil.rmtree(target_path, onerror=handle_remove_readonly)
            elif os.path.isfile(target_path):
                try:
                    os.remove(target_path)
                except PermissionError:
                    _unlock_path(target_path)
                    os.remove(target_path)
        except Exception as e:
            report.errors.append(f"Error purging {target_path}: {e}")
            return False

        if os.path.lexists(target_path) or len(report.errors) > errors_before:
            return False

        # Clean empty parent directories up to scan_dirs
        parent = os.path.dirname(target_path)
        scan_dirs = {os.path.realpath(sd) for sd in self._get_scan_directories(system_root)}
        while parent and parent != system_root:
            real_parent = os.path.realpath(parent)
            if not real_parent.startswith(root_prefix) or real_parent in scan_dirs:
                break
            try:
                if os.path.isdir(parent) and not os.listdir(parent):
                    os.rmdir(parent)
                    parent = os.path.dirname(parent)
                else:
                    break
            except OSError:
                break

        return True

    def _purge_extra_components(
        self,
        root_path: str,
        report: DebloatReport,
        dry_run: bool = False
    ) -> None:
        """Purges native binaries, init scripts and temporary log spools if configured."""
        targets = []
        for bin_path in self.system_binaries:
            stripped = bin_path.lstrip("/")
            targets.append(os.path.join(root_path, stripped))
            if stripped.startswith("system/"):
                targets.append(os.path.join(root_path, stripped[7:]))

        for init_path in self.init_services:
            stripped = init_path.lstrip("/")
            targets.append(os.path.join(root_path, stripped))
            if stripped.startswith("system/"):
                targets.append(os.path.join(root_path, stripped[7:]))

        for spool in self.spool_directories:
            stripped = spool.lstrip("/")
            targets.append(os.path.join(root_path, stripped))

        seen_targets = set()
        for target in targets:
            if target in seen_targets:
                continue
            seen_targets.add(target)

            if os.path.exists(target) or os.path.islink(target):
                real_target = os.path.realpath(target)
                real_root = os.path.realpath(root_path)
                root_prefix = real_root.rstrip(os.sep) + os.sep
                if real_target == real_root or not real_target.startswith(root_prefix):
                    report.errors.append(f"Security veto: {target} resolves outside system root")
                    continue

                size = 0
                if os.path.islink(target):
                    size = 0
                elif os.path.isfile(target):
                    try:
                        size = os.path.getsize(target)
                    except OSError:
                        size = 0
                elif os.path.isdir(target):
                    _, size = self._inspect_directory(target)

                if dry_run:
                    report.removed_paths.append(target)
                    report.bytes_freed += size
                else:
                    purged = self._purge_path(target, root_path, report)
                    if purged:
                        report.removed_paths.append(target)
                        report.bytes_freed += size

    def _discover_config_dir(self) -> str:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        cand = os.path.abspath(os.path.join(base_dir, "..", "..", "config"))
        if os.path.isdir(cand):
            return cand
        return os.path.abspath("config")

    def _load_default_blacklist(self) -> Set[str]:
        p = os.path.join(self.config_dir, "bloatware_blacklist.json")
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                pkgs = set(data.get("packages", []))
                self.patterns = data.get("patterns", [])
                for pat in self.patterns:
                    pkgs.add(pat)
                self.system_binaries = data.get("system_binaries", [])
                self.init_services = data.get("init_services", [])
                self.spool_directories = data.get("spool_directories", [])
                return pkgs
            except Exception:
                pass
        return set()

    def _load_default_whitelist(self) -> Set[str]:
        p = os.path.join(self.config_dir, "preserved_services.json")
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return set(data.get("preserved_packages", []))
            except Exception:
                pass
        return set()
