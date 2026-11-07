"""Hardware preservation safety engine for QF001 (ROCO K706 / UIS7862)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class SafetyValidatorError(Exception):
    """Base exception for all domain safety validator failures."""
    pass


class HardwareSafetyViolationError(SafetyValidatorError):
    """Raised when an essential automotive service or hardware definition is missing or damaged."""

    def __init__(
        self,
        violations: List[str],
        missing_services: Optional[List[str]] = None,
        corrupt_services: Optional[List[str]] = None,
        prop_violations: Optional[List[str]] = None,
        context: Optional[dict] = None,
        result: Optional[Any] = None,
    ) -> None:
        self.violations = violations
        self.missing_services = missing_services or []
        self.corrupt_services = corrupt_services or []
        self.prop_violations = prop_violations or []
        self.context = context or {}
        self.result = result

        msg = (
            f"[HARDWARE SAFETY VIOLATION] Critical automotive preservation check failed with "
            f"{len(violations)} violation(s):\n"
            + "\n".join(f"  - {v}" for v in violations)
            + "\nPackaging has been halted to prevent automotive hardware dysfunction."
        )
        super().__init__(msg)


@dataclass
class ValidationResult:
    """Detailed result returned by SafetyValidator inspections."""
    is_safe: bool = True
    verified_services: List[str] = field(default_factory=list)
    missing_services: List[str] = field(default_factory=list)
    violations: List[str] = field(default_factory=list)
    system_root: str = ""
    corrupt_services: List[str] = field(default_factory=list)
    build_prop_verified: bool = False
    build_prop_properties: Dict[str, str] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    prop_violations: List[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """Alias for is_safe to conform to testing contracts."""
        return self.is_safe

    @property
    def preserved_packages_found(self) -> List[str]:
        """Alias for verified_services."""
        return self.verified_services

    @property
    def missing_packages(self) -> List[str]:
        """Alias for missing_services."""
        return self.missing_services

    @property
    def corrupt_packages(self) -> List[str]:
        """Alias for corrupt_services."""
        return self.corrupt_services

    def __bool__(self) -> bool:
        """Direct boolean evaluation."""
        return self.is_safe

    def raise_if_invalid(self) -> None:
        """Raise HardwareSafetyViolationError if is_safe is False."""
        if not self.is_safe:
            raise HardwareSafetyViolationError(
                violations=self.violations,
                missing_services=self.missing_services,
                corrupt_services=self.corrupt_services,
                prop_violations=self.prop_violations,
                context={"system_root": self.system_root},
                result=self,
            )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize result to a dictionary."""
        return {
            "is_safe": self.is_safe,
            "is_valid": self.is_valid,
            "system_root": self.system_root,
            "verified_services": list(self.verified_services),
            "missing_services": list(self.missing_services),
            "corrupt_services": list(self.corrupt_services),
            "build_prop_verified": self.build_prop_verified,
            "violations_count": len(self.violations),
            "violations": list(self.violations),
            "warnings": list(self.warnings),
            "prop_violations": list(self.prop_violations),
        }

    def summary(self) -> str:
        """Generate formatted summary string."""
        status = "PASSED" if self.is_safe else "FAILED"
        return (
            f"Safety Validation {status}: {len(self.verified_services)} services preserved, "
            f"{len(self.violations)} violations."
        )


class SafetyValidator:
    """Hardware preservation safety engine for QF001 (ROCO K706 / UIS7862)."""

    CORE_AUTOMOTIVE_PACKAGES = [
        "com.ts.main.radio",
        "com.ts.camera",
        "com.syu.bt",
        "com.ts.car",
    ]

    CANBUS_CONTROLLERS = [
        "com.roco.canbus",
        "com.syu.canbus",
    ]

    EXTENDED_AUTOMOTIVE_PACKAGES = [
        "com.android.server.telecom",
    ]

    EXPECTED_BOARD = "ROCO_K706"
    EXPECTED_RADIO_IC = "TDA7708"
    EXPECTED_DSP_IC = "BU32107EFV"
    EXPECTED_AMP_IC = "TDA7851"

    def __init__(
        self,
        preserved_packages: Optional[List[str]] = None,
        hardware_profile: Optional[Dict[str, Any]] = None,
        config_dir: Optional[str] = None,
        raise_on_error: bool = True,
        require_all_canbus: bool = False,
        enforce_build_prop: bool = True,
    ) -> None:
        self.raise_on_error = raise_on_error
        self.require_all_canbus = require_all_canbus
        self.enforce_build_prop = enforce_build_prop
        self.explicit_preserved_packages = preserved_packages is not None
        self.config_dir = config_dir or self._discover_config_dir()

        if preserved_packages is not None:
            self.preserved_packages = list(preserved_packages)
        else:
            self.preserved_packages = self._load_preserved_packages_config()

        self.hardware_profile = hardware_profile or self._load_hardware_profile_config()

    def _discover_config_dir(self) -> str:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        cand = os.path.abspath(os.path.join(base_dir, "..", "..", "config"))
        if os.path.isdir(cand):
            return cand
        return os.path.abspath("config")

    def _load_preserved_packages_config(self) -> List[str]:
        cfg_file = os.path.join(self.config_dir, "preserved_services.json")
        if os.path.isfile(cfg_file):
            try:
                with open(cfg_file, "r", encoding="utf-8") as f:
                    return json.load(f).get("preserved_packages", [])
            except Exception:
                pass
        return list(self.CORE_AUTOMOTIVE_PACKAGES) + list(self.CANBUS_CONTROLLERS)

    def _load_hardware_profile_config(self) -> Dict[str, Any]:
        cfg_file = os.path.join(self.config_dir, "hardware_profiles.json")
        if os.path.isfile(cfg_file):
            try:
                with open(cfg_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "platform": self.EXPECTED_BOARD,
            "radio_ic": self.EXPECTED_RADIO_IC,
            "dsp_ic": self.EXPECTED_DSP_IC,
            "amplifier_ic": self.EXPECTED_AMP_IC,
        }

    def scan_installed_packages(self, system_root: str) -> Dict[str, str]:
        """Discovers packages across system and product application directories.

        Returns:
            Dictionary mapping package name -> path to folder or apk file.
        """
        root_path = os.path.abspath(system_root)
        installed: Dict[str, str] = {}
        search_dirs = [
            os.path.join(root_path, "priv-app"),
            os.path.join(root_path, "app"),
            os.path.join(root_path, "system", "priv-app"),
            os.path.join(root_path, "system", "app"),
            os.path.join(root_path, "product", "priv-app"),
            os.path.join(root_path, "product", "app"),
            os.path.join(root_path, "system", "product", "priv-app"),
            os.path.join(root_path, "system", "product", "app"),
        ]

        seen_realpaths = set()
        for s_dir in search_dirs:
            if not os.path.isdir(s_dir):
                continue
            rp = os.path.realpath(s_dir)
            if rp in seen_realpaths:
                continue
            seen_realpaths.add(rp)

            try:
                items = os.listdir(s_dir)
            except OSError:
                continue

            for item in items:
                if item.startswith("."):
                    continue
                item_path = os.path.join(s_dir, item)
                if os.path.isdir(item_path):
                    installed[item] = item_path
                    # Also map any APK basename found inside
                    try:
                        for sub_f in os.listdir(item_path):
                            if sub_f.lower().endswith(".apk"):
                                apk_base = sub_f[:-4]
                                installed[apk_base] = item_path
                    except OSError:
                        pass
                elif os.path.isfile(item_path) and item.lower().endswith(".apk"):
                    pkg_name = item[:-4]
                    installed[pkg_name] = item_path

        return installed

    def verify_package_integrity(self, pkg_path: str, pkg_name: str) -> Tuple[bool, List[str]]:
        """Verifies presence of at least one non-empty, valid APK in package folder."""
        violations: List[str] = []
        if os.path.isfile(pkg_path):
            try:
                if os.path.getsize(pkg_path) == 0:
                    violations.append(f"Package '{pkg_name}' APK at {pkg_path} is 0 bytes (corrupt/empty)")
                    return False, violations
            except OSError as e:
                violations.append(f"Package '{pkg_name}' APK at {pkg_path} is unreadable: {e}")
                return False, violations
            return True, []

        if not os.path.isdir(pkg_path):
            violations.append(f"Package '{pkg_name}' directory {pkg_path} does not exist")
            return False, violations

        try:
            apk_files = [f for f in os.listdir(pkg_path) if f.lower().endswith(".apk")]
        except OSError as e:
            violations.append(f"Cannot read directory {pkg_path} for '{pkg_name}': {e}")
            return False, violations

        if not apk_files:
            violations.append(f"Package '{pkg_name}' at {pkg_path} contains no .apk binary file")
            return False, violations

        for apk in apk_files:
            apk_full_path = os.path.join(pkg_path, apk)
            try:
                size = os.path.getsize(apk_full_path)
                if size == 0:
                    violations.append(f"Package '{pkg_name}' has 0-byte corrupt APK: {apk}")
            except OSError as e:
                violations.append(f"Package '{pkg_name}' APK {apk} is unreadable: {e}")

        return len(violations) == 0, violations

    def verify_build_prop(self, system_root: str) -> Tuple[bool, List[str], Dict[str, str]]:
        """Validates build.prop hardware platform and DSP/tuner entries."""
        violations: List[str] = []
        properties: Dict[str, str] = {}
        root = os.path.abspath(system_root)

        prop_candidates = [
            os.path.join(root, "build.prop"),
            os.path.join(root, "system", "build.prop"),
            os.path.join(os.path.dirname(root), "build.prop"),
        ]

        prop_path = None
        for cand in prop_candidates:
            if os.path.isfile(cand):
                prop_path = cand
                break

        if not prop_path:
            violations.append(f"build.prop not found in system root: {system_root}")
            return False, violations, properties

        try:
            with open(prop_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#") and "=" in stripped:
                        k, v = stripped.split("=", 1)
                        properties[k.strip()] = v.strip()
        except Exception as e:
            violations.append(f"Failed to read build.prop at {prop_path}: {e}")
            return False, violations, properties

        expected_board = self.hardware_profile.get("platform", self.EXPECTED_BOARD)
        actual_board = properties.get("ro.product.board")
        if not actual_board:
            violations.append("build.prop missing required property 'ro.product.board'")
        elif actual_board != expected_board:
            violations.append(
                f"Hardware board mismatch in build.prop: expected '{expected_board}', found '{actual_board}'"
            )

        # Check radio tuner definition (mandatory for QF001 automotive hardware)
        expected_tuner = self.hardware_profile.get("radio_ic", self.EXPECTED_RADIO_IC)
        allowed_tuners = self.hardware_profile.get("radio_options", [expected_tuner])
        if isinstance(allowed_tuners, str):
            allowed_tuners = [allowed_tuners]
        if expected_tuner and expected_tuner not in allowed_tuners:
            allowed_tuners.append(expected_tuner)

        tuner_prop = properties.get("ro.qf001.radio.tuner")
        if not tuner_prop:
            violations.append("build.prop missing required property 'ro.qf001.radio.tuner'")
        elif not any(cand in tuner_prop for cand in allowed_tuners):
            violations.append(
                f"Radio tuner mismatch in build.prop: expected one of {allowed_tuners}, found '{tuner_prop}'"
            )

        # Check DSP definition (mandatory for QF001 automotive hardware)
        expected_dsp = self.hardware_profile.get("dsp_ic", self.EXPECTED_DSP_IC)
        dsp_prop = properties.get("ro.qf001.audio.dsp")
        if not dsp_prop:
            violations.append("build.prop missing required property 'ro.qf001.audio.dsp'")
        elif expected_dsp not in dsp_prop:
            violations.append(
                f"Audio DSP mismatch in build.prop: expected '{expected_dsp}', found '{dsp_prop}'"
            )

        is_valid = len(violations) == 0
        return is_valid, violations, properties

    def verify_preserved_services(
        self,
        system_root: Union[str, Path],
        raise_on_error: Optional[bool] = None,
    ) -> ValidationResult:
        """Inspects filesystem tree for presence and integrity of all automotive services.

        Args:
            system_root: Path to the extracted system root or container directory.
            raise_on_error: If True, raises HardwareSafetyViolationError on any violation.
                Defaults to instance setting (True by default).

        Returns:
            ValidationResult containing status and lists of preserved/missing services.

        Raises:
            HardwareSafetyViolationError: If raise_on_error is True and any check fails.
        """
        should_raise = self.raise_on_error if raise_on_error is None else raise_on_error
        root_path = os.path.abspath(os.fspath(system_root))

        if not os.path.exists(root_path):
            err_msg = f"System root path does not exist: {root_path}"
            result = ValidationResult(
                is_safe=False,
                system_root=root_path,
                violations=[err_msg],
            )
            if should_raise:
                result.raise_if_invalid()
            return result

        installed = self.scan_installed_packages(root_path)

        verified_found: List[str] = []
        missing_pkgs: List[str] = []
        corrupt_pkgs: List[str] = []
        violations: List[str] = []
        warnings: List[str] = []

        if self.explicit_preserved_packages:
            # Mandate every package in explicit preserved_packages
            for pkg in self.preserved_packages:
                if pkg in installed:
                    is_intact, v_list = self.verify_package_integrity(installed[pkg], pkg)
                    if is_intact:
                        verified_found.append(pkg)
                    else:
                        corrupt_pkgs.append(pkg)
                        violations.extend(v_list)
                else:
                    missing_pkgs.append(pkg)
                    violations.append(f"Preserved automotive service missing: '{pkg}'")
        else:
            # 1. Verify Core Mandatory Automotive Packages
            for pkg in self.CORE_AUTOMOTIVE_PACKAGES:
                if pkg in installed:
                    is_intact, v_list = self.verify_package_integrity(installed[pkg], pkg)
                    if is_intact:
                        verified_found.append(pkg)
                    else:
                        corrupt_pkgs.append(pkg)
                        violations.extend(v_list)
                else:
                    missing_pkgs.append(pkg)
                    violations.append(f"Essential automotive service missing: '{pkg}'")

            # 2. Verify CAN Bus Controllers
            canbus_found = [pkg for pkg in self.CANBUS_CONTROLLERS if pkg in installed]
            if not canbus_found:
                missing_pkgs.extend(self.CANBUS_CONTROLLERS)
                violations.append(
                    f"No CAN bus controller found. At least one of {self.CANBUS_CONTROLLERS} must be present."
                )
            else:
                if self.require_all_canbus:
                    for c_pkg in self.CANBUS_CONTROLLERS:
                        if c_pkg not in installed:
                            missing_pkgs.append(c_pkg)
                            violations.append(f"CAN bus controller '{c_pkg}' missing (require_all_canbus=True)")
                        else:
                            is_intact, v_list = self.verify_package_integrity(installed[c_pkg], c_pkg)
                            if is_intact:
                                verified_found.append(c_pkg)
                            else:
                                corrupt_pkgs.append(c_pkg)
                                violations.extend(v_list)
                else:
                    for c_pkg in canbus_found:
                        is_intact, v_list = self.verify_package_integrity(installed[c_pkg], c_pkg)
                        if is_intact:
                            verified_found.append(c_pkg)
                        else:
                            corrupt_pkgs.append(c_pkg)
                            violations.extend(v_list)

            # 3. Verify Extended Automotive Services if present
            for ext_pkg in self.EXTENDED_AUTOMOTIVE_PACKAGES:
                if ext_pkg in installed:
                    is_intact, v_list = self.verify_package_integrity(installed[ext_pkg], ext_pkg)
                    if is_intact:
                        verified_found.append(ext_pkg)
                    else:
                        corrupt_pkgs.append(ext_pkg)
                        violations.extend(v_list)

        # 4. Verify build.prop
        prop_ok = True
        prop_violations: List[str] = []
        props: Dict[str, str] = {}
        if self.enforce_build_prop:
            prop_ok, prop_violations, props = self.verify_build_prop(root_path)
            if not prop_ok:
                violations.extend(prop_violations)

        is_safe = len(violations) == 0

        result = ValidationResult(
            is_safe=is_safe,
            verified_services=sorted(verified_found),
            missing_services=sorted(missing_pkgs),
            violations=violations,
            system_root=root_path,
            corrupt_services=sorted(corrupt_pkgs),
            build_prop_verified=prop_ok,
            build_prop_properties=props,
            warnings=warnings,
            prop_violations=list(prop_violations),
        )

        if not is_safe and should_raise:
            result.raise_if_invalid()

        return result

    def enforce_preserved_services(self, system_root: Union[str, Path]) -> ValidationResult:
        """Convenience method enforcing preservation and raising HardwareSafetyViolationError on failure."""
        return self.verify_preserved_services(system_root, raise_on_error=True)

    def check_preserved_services(self, system_root: Union[str, Path]) -> ValidationResult:
        """Inspects preserved services without raising exceptions."""
        return self.verify_preserved_services(system_root, raise_on_error=False)
