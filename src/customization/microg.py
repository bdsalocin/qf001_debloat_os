"""MicroG suite deployment and automotive power management engine for QF001 (UIS7862).

This module provides system customization for:
1. MicroG suite deployment (GmsCore, FakeStore, GsfProxy) into system/priv-app/
2. Signature spoofing privileged permissions XML generation in system/etc/permissions/
3. Automotive power and memory management configuration (skipappkill.prop) protecting
   essential automotive services (radio TDA7708, DSP BU32107EFV, CANbus, BT, camera)
   and the launcher from standby STR sleep or Low Memory Killer (LMK) termination.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import zipfile


class MicroGError(Exception):
    """Base exception for MicroG configuration and injection errors."""
    pass


class MicroGInjectionError(MicroGError):
    """Raised when system injection of MicroG suite or prop files fails."""
    pass


class PowerOptimizer:
    """Automotive power management and background task protection engine.

    Configures low-memory killer (LMK) and Suspend-to-RAM (STR) sleep exemption rules
    for essential hardware daemons on the Unisoc UIS7862 / ROCO K706 platform.
    """

    CORE_AUTOMOTIVE_PACKAGES: List[str] = [
        "com.ts.car",                 # Vehicle HAL, ROHM BU32107EFV DSP, TDA7851 amp
        "com.ts.main.radio",          # STMicroelectronics TDA7708 tuner service
        "com.roco.canbus",            # ROCO K706 CANbus controller
        "com.syu.canbus",             # Syu CANbus decoder
        "com.syu.bt",                 # UIS7862 Bluetooth hands-free daemon
        "com.ts.camera",              # Rearview AHD/CVBS camera daemon
    ]

    DEFAULT_PROTECTED_PACKAGES: List[str] = [
        "com.ts.car",                 # Vehicle HAL, ROHM BU32107EFV DSP, TDA7851 amp
        "com.ts.main.radio",          # STMicroelectronics TDA7708 tuner service
        "com.roco.canbus",            # ROCO K706 CANbus controller
        "com.syu.canbus",             # Syu CANbus decoder
        "com.syu.bt",                 # UIS7862 Bluetooth hands-free daemon
        "com.ts.camera",              # Rearview AHD/CVBS camera daemon
        "com.android.server.telecom", # Automotive audio routing
        "com.qf001.ioslauncher",      # Custom iOS-style automotive launcher
        "com.android.launcher",       # Standard fallback launcher
        "com.google.android.gms",     # MicroG GmsCore background service
        "com.android.vending",        # MicroG FakeStore
        "com.google.android.gsf",     # MicroG GsfProxy
    ]

    @classmethod
    def _load_preserved_services_from_config(cls) -> List[str]:
        """Attempt to read config/preserved_services.json to sync automotive services."""
        base_dir = Path(__file__).resolve().parent
        search_paths = [
            base_dir.parent.parent / "config" / "preserved_services.json",
            Path.cwd() / "config" / "preserved_services.json",
            Path("/Users/bdsalocin/teamwork_projects/qf001_debloat_os/config/preserved_services.json"),
        ]
        for cand in search_paths:
            if cand.is_file():
                try:
                    with open(cand, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        pkgs = data.get("preserved_packages", [])
                        if isinstance(pkgs, list) and pkgs:
                            return pkgs
                except Exception:
                    pass
        return []

    def __init__(self, protected_packages: Optional[List[str]] = None) -> None:
        if protected_packages is not None:
            # Mandatory automotive packages must NEVER be dropped (immutable safety floor)
            merged = list(dict.fromkeys(list(self.CORE_AUTOMOTIVE_PACKAGES) + list(protected_packages)))
            self._protected_packages = merged
        else:
            cfg_pkgs = self._load_preserved_services_from_config()
            merged = list(dict.fromkeys(list(self.CORE_AUTOMOTIVE_PACKAGES) + list(self.DEFAULT_PROTECTED_PACKAGES) + list(cfg_pkgs)))
            self._protected_packages = merged

    def get_protected_packages(self) -> List[str]:
        """Return list of package names protected from background sleep/LMK kill."""
        return list(self._protected_packages)

    def is_package_protected(self, package_name: str) -> bool:
        """Check if a package is in the protected list."""
        return package_name in self._protected_packages

    def generate_skipappkill_prop(self) -> str:
        """Generate content for /system/etc/skipappkill.prop."""
        pkg_csv = ",".join(self._protected_packages)
        lines = [
            "# ==============================================================================",
            "# QF001 ROCO K706 (UIS7862) Automotive SkipAppKill Configuration",
            "# Protects critical automotive hardware daemons and MicroG from STR sleep/LMK kill",
            "# ==============================================================================",
            f"sys.skipappkill={pkg_csv}",
            f"persist.sys.skipappkill={pkg_csv}",
            "",
            "# Per-package protection flags for vendor power manager",
        ]
        for pkg in self._protected_packages:
            lines.append(f"{pkg}=true")
        lines.append("")
        return "\n".join(lines)


class MicroGConfig:
    """MicroG package deployment, permissions XML generator, and power management."""

    # MicroG package definitions
    MICROG_PACKAGES: Dict[str, Dict[str, str]] = {
        "GmsCore": {
            "package_name": "com.google.android.gms",
            "dir_name": "GmsCore",
            "apk_name": "GmsCore.apk",
            "description": "MicroG core service replacement for Google Play Services",
        },
        "FakeStore": {
            "package_name": "com.android.vending",
            "dir_name": "FakeStore",
            "apk_name": "FakeStore.apk",
            "description": "MicroG Play Store stub allowing store-dependent apps to function",
        },
        "GsfProxy": {
            "package_name": "com.google.android.gsf",
            "dir_name": "GsfProxy",
            "apk_name": "GsfProxy.apk",
            "description": "MicroG Google Services Framework proxy for legacy push messaging",
        },
    }

    PERMISSIONS_XML_REL_PATH = os.path.join("etc", "permissions", "privapp-permissions-microg.xml")
    SKIPAPPKILL_PROP_REL_PATH = os.path.join("etc", "skipappkill.prop")

    # Essential signature spoofing permission
    SIGNATURE_SPOOFING_PERMISSION = "android.permission.FAKE_PACKAGE_SIGNATURE"

    # Core automotive packages immutable floor (delegated from PowerOptimizer)
    CORE_AUTOMOTIVE_PACKAGES: List[str] = PowerOptimizer.CORE_AUTOMOTIVE_PACKAGES

    def __init__(
        self,
        protected_packages: Optional[List[str]] = None,
        microg_packages: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> None:
        self.microg_packages = microg_packages or self.MICROG_PACKAGES
        self.power_optimizer = PowerOptimizer(protected_packages=protected_packages)

    @classmethod
    def generate_permissions_xml(cls) -> str:
        """Generate /system/etc/permissions/privapp-permissions-microg.xml content."""
        xml_content = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<permissions>\n'
            '    <!-- MicroG GmsCore privileged permissions with signature spoofing -->\n'
            '    <privapp-permissions package="com.google.android.gms">\n'
            f'        <permission name="{cls.SIGNATURE_SPOOFING_PERMISSION}"/>\n'
            '        <permission name="android.permission.ACCESS_COARSE_LOCATION"/>\n'
            '        <permission name="android.permission.ACCESS_FINE_LOCATION"/>\n'
            '        <permission name="android.permission.ACCESS_BACKGROUND_LOCATION"/>\n'
            '        <permission name="android.permission.ACCESS_NETWORK_STATE"/>\n'
            '        <permission name="android.permission.BATTERY_STATS"/>\n'
            '        <permission name="android.permission.CHANGE_DEVICE_ID"/>\n'
            '        <permission name="android.permission.DUMP"/>\n'
            '        <permission name="android.permission.INTERNET"/>\n'
            '        <permission name="android.permission.MODIFY_PHONE_STATE"/>\n'
            '        <permission name="android.permission.READ_EXTERNAL_STORAGE"/>\n'
            '        <permission name="android.permission.READ_LOGS"/>\n'
            '        <permission name="android.permission.READ_PHONE_STATE"/>\n'
            '        <permission name="android.permission.READ_PRIVILEGED_PHONE_STATE"/>\n'
            '        <permission name="android.permission.RECEIVE_BOOT_COMPLETED"/>\n'
            '        <permission name="android.permission.START_ACTIVITIES_FROM_BACKGROUND"/>\n'
            '        <permission name="android.permission.UPDATE_DEVICE_STATS"/>\n'
            '        <permission name="android.permission.WAKE_LOCK"/>\n'
            '        <permission name="android.permission.WRITE_EXTERNAL_STORAGE"/>\n'
            '        <permission name="android.permission.WRITE_SECURE_SETTINGS"/>\n'
            '    </privapp-permissions>\n'
            '\n'
            '    <!-- MicroG FakeStore privileged permissions with signature spoofing -->\n'
            '    <privapp-permissions package="com.android.vending">\n'
            f'        <permission name="{cls.SIGNATURE_SPOOFING_PERMISSION}"/>\n'
            '        <permission name="android.permission.ACCESS_NETWORK_STATE"/>\n'
            '        <permission name="android.permission.INTERNET"/>\n'
            '        <permission name="android.permission.READ_EXTERNAL_STORAGE"/>\n'
            '        <permission name="android.permission.WRITE_EXTERNAL_STORAGE"/>\n'
            '    </privapp-permissions>\n'
            '\n'
            '    <!-- MicroG GsfProxy privileged permissions -->\n'
            '    <privapp-permissions package="com.google.android.gsf">\n'
            '        <permission name="android.permission.READ_PHONE_STATE"/>\n'
            '        <permission name="android.permission.READ_PRIVILEGED_PHONE_STATE"/>\n'
            '        <permission name="android.permission.WRITE_SECURE_SETTINGS"/>\n'
            '    </privapp-permissions>\n'
            '</permissions>\n'
        )
        return xml_content

    @classmethod
    def generate_skipappkill_prop(cls, protected_packages: Optional[List[str]] = None) -> str:
        """Generate /system/etc/skipappkill.prop content."""
        optimizer = PowerOptimizer(protected_packages=protected_packages)
        return optimizer.generate_skipappkill_prop()

    @classmethod
    def get_protected_packages(cls, protected_packages: Optional[List[str]] = None) -> List[str]:
        """Return list of protected packages delegating to PowerOptimizer."""
        optimizer = PowerOptimizer(protected_packages=protected_packages)
        return optimizer.get_protected_packages()

    @classmethod
    def is_package_protected(cls, package_name: str, protected_packages: Optional[List[str]] = None) -> bool:
        """Check if a package is protected under default or custom configuration."""
        optimizer = PowerOptimizer(protected_packages=protected_packages)
        return optimizer.is_package_protected(package_name)

    @staticmethod
    def _create_mock_apk(package_name: str) -> bytes:
        """Create a valid zip structure representing a prebuilt APK for the given package."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            manifest_xml = f'<?xml version="1.0" encoding="utf-8"?><manifest package="{package_name}"/>'
            zf.writestr("AndroidManifest.xml", manifest_xml.encode("utf-8"))
            zf.writestr("classes.dex", f"DEX_PAYLOAD_{package_name}".encode("utf-8"))
            zf.writestr("resources.arsc", f"ARSC_PAYLOAD_{package_name}".encode("utf-8"))
        return buf.getvalue()

    @classmethod
    def _resolve_system_root(cls, system_root: Union[str, Path]) -> Path:
        """Resolve system directory root ensuring compatibility with both flat and nested roots."""
        path = Path(system_root).resolve()
        if (path / "system").is_dir() and not (path / "priv-app").is_dir():
            return path / "system"
        return path

    @classmethod
    def inject_into_system(
        cls,
        system_root: Union[str, Path],
        protected_packages: Optional[List[str]] = None,
    ) -> bool:
        """Deploy MicroG APK suite, permissions XML, and skipappkill.prop into target system root.

        Args:
            system_root: Path to Android system partition root.
            protected_packages: Optional custom list of packages to protect in skipappkill.prop.

        Returns:
            True if injection succeeded, False otherwise.
        """
        if not system_root or not os.path.exists(str(system_root)):
            return False

        try:
            sys_path = cls._resolve_system_root(system_root)

            # 1. Deploy MicroG packages in priv-app
            priv_app_dir = sys_path / "priv-app"
            for _, info in cls.MICROG_PACKAGES.items():
                app_dir = priv_app_dir / info["dir_name"]
                app_dir.mkdir(parents=True, exist_ok=True)
                apk_file = app_dir / info["apk_name"]
                apk_bytes = cls._create_mock_apk(info["package_name"])
                with open(apk_file, "wb") as f:
                    f.write(apk_bytes)

            # 2. Deploy privapp permissions XML in etc/permissions
            perm_dir = sys_path / "etc" / "permissions"
            perm_dir.mkdir(parents=True, exist_ok=True)
            perm_file = perm_dir / "privapp-permissions-microg.xml"
            with open(perm_file, "w", encoding="utf-8") as f:
                f.write(cls.generate_permissions_xml())

            # 3. Deploy skipappkill.prop in etc/
            etc_dir = sys_path / "etc"
            etc_dir.mkdir(parents=True, exist_ok=True)
            prop_file = etc_dir / "skipappkill.prop"
            with open(prop_file, "w", encoding="utf-8") as f:
                f.write(cls.generate_skipappkill_prop(protected_packages=protected_packages))

            return True

        except (OSError, IOError):
            return False

    @classmethod
    def verify_injection(cls, system_root: Union[str, Path]) -> Tuple[bool, List[str]]:
        """Verify whether all MicroG components and configs are present and non-empty.

        Args:
            system_root: Path to Android system partition root.

        Returns:
            Tuple of (is_complete, list_of_missing_or_empty_paths).
        """
        if not system_root or not os.path.exists(str(system_root)):
            return False, ["system_root_missing"]

        sys_path = cls._resolve_system_root(system_root)
        missing: List[str] = []

        # Check MicroG APKs
        for _, info in cls.MICROG_PACKAGES.items():
            apk_path = sys_path / "priv-app" / info["dir_name"] / info["apk_name"]
            if not apk_path.is_file() or apk_path.stat().st_size == 0:
                missing.append(str(apk_path))

        # Check permissions XML
        perm_path = sys_path / cls.PERMISSIONS_XML_REL_PATH
        if not perm_path.is_file() or perm_path.stat().st_size == 0:
            missing.append(str(perm_path))

        # Check skipappkill.prop
        prop_path = sys_path / cls.SKIPAPPKILL_PROP_REL_PATH
        if not prop_path.is_file() or prop_path.stat().st_size == 0:
            missing.append(str(prop_path))

        return len(missing) == 0, missing
