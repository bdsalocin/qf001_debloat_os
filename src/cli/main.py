#!/usr/bin/env python3
"""Point d entree principal et CLI unifiee de la toolchain QF001 Debloat OS.

Fournit une interface en ligne de commande unifiee pour piloter l ensemble du cycle
de debloating, personnalisation et packaging pour autoradios ROCO K706 (UIS 7862 / 7862S) :
  - unpack     : extraction et deconversion des images et archives de firmware
  - debloat    : assainissement en profondeur des bloatwares et telemetries
  - customize  : injection du lanceur style iOS et de la suite MicroG avec regles skipappkill
  - pack       : generation et signature du paquet update.zip destine a cle USB FAT32
  - verify     : audit de securite MCU, conformite materielle et validation de signature
  - build-all  : pipeline complet automatise de bout en bout
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

# Identification dynamique du repertoire racine du projet
def _find_project_root() -> str:
    cur = os.path.abspath(os.path.dirname(__file__))
    for _ in range(6):
        if os.path.isdir(os.path.join(cur, "src")) and os.path.isdir(os.path.join(cur, "config")):
            return cur
        cur = os.path.dirname(cur)
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

PROJECT_ROOT = _find_project_root()
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.core.sparse import SparseImage
from src.core.unpacker import FirmwareUnpacker, SecurityViolationError
from src.core.packer import FirmwarePacker
from src.core.signer import PackageSigner, OTAMetadata, VerificationResult, SignerError
from src.core.mcu_guard import MCUGuard, MCUSafetyViolationError, MCUSafetyError
from src.domain.debloater import Debloater, DebloatReport, DebloaterError
from src.domain.safety_validator import SafetyValidator, ValidationResult, HardwareSafetyViolationError
from src.customization.launcher import IOSLauncherConfig
from src.customization.microg import MicroGConfig, PowerOptimizer

# Import conditionnel de PackageBuilder (Milestone 4)
try:
    from src.core.package_builder import PackageBuilder
except ImportError:
    PackageBuilder = None  # type: ignore

TOOLCHAIN_VERSION = "1.0.0"
PLATFORM_TARGET = "ROCO_K706"
REFERENCE_DEVICE = "QF001"
MAX_FAT32_BYTES = 4294967295  # Limite de 4 Gio pour le systeme de fichiers FAT32

# Codes de retour normalises
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_USAGE_ERROR = 2
EXIT_MCU_VIOLATION = 3
EXIT_HARDWARE_VIOLATION = 4
EXIT_VERIFICATION_FAILURE = 5


class CLIReporter:
    """Gestionnaire d affichage et de journalisation pour la CLI.

    Respecte rigoureusement la directive de redaction : aucune utilisation
    de tirets dans les phrases ou messages destines a l utilisateur.
    """

    def __init__(self, verbose: bool = False, quiet: bool = False) -> None:
        self.verbose = verbose
        self.quiet = quiet

    def info(self, message: str) -> None:
        """Affiche un message d information standard."""
        if not self.quiet:
            print(f"[INFO] {message}")

    def success(self, message: str) -> None:
        """Affiche un message de reussite."""
        if not self.quiet:
            print(f"[SUCCES] {message}")

    def warn(self, message: str) -> None:
        """Affiche un message d avertissement."""
        if not self.quiet:
            print(f"[ATTENTION] {message}", file=sys.stderr)

    def error(self, message: str) -> None:
        """Affiche un message d erreur critique."""
        print(f"[ERREUR] {message}", file=sys.stderr)

    def debug(self, message: str) -> None:
        """Affiche un message de debogage si le mode verbeux est actif."""
        if self.verbose and not self.quiet:
            print(f"[DEBUG] {message}")

    def header(self, title: str) -> None:
        """Affiche un titre de section structure."""
        if not self.quiet:
            separator = "=" * 60
            print(f"\n{separator}")
            print(f"  {title}")
            print(f"{separator}")

    def banner(self) -> None:
        """Affiche la banniere officielle de la toolchain."""
        if not self.quiet:
            print("============================================================")
            print("  QF001 Debloat OS Toolchain (ROCO K706 / Unisoc UIS7862)")
            print(f"  Version {TOOLCHAIN_VERSION} — Mode Production Securise")
            print("============================================================")


def locate_system_root(base_dir: str) -> str:
    """Identifie le repertoire racine de la partition systeme."""
    abs_base = os.path.abspath(base_dir)

    # 1. Verification directe des emplacements standards
    for candidate in [
        os.path.join(abs_base, "system"),
        os.path.join(abs_base, "firmware", "system"),
        abs_base,
    ]:
        if os.path.isdir(candidate):
            has_apps = os.path.isdir(os.path.join(candidate, "priv-app")) or os.path.isdir(os.path.join(candidate, "app"))
            has_prop = os.path.isfile(os.path.join(candidate, "build.prop"))
            if has_apps or has_prop:
                return candidate

    # 2. Recherche recurrente dans l arborescence extraite
    for root, dirs, files in os.walk(abs_base):
        rel = os.path.relpath(root, abs_base)
        if rel != "." and rel.count(os.sep) > 3:
            continue
        if os.path.basename(root) == "system" or "priv-app" in dirs:
            if "priv-app" in dirs or "app" in dirs or "build.prop" in files:
                return root

    if os.path.isdir(os.path.join(abs_base, "system")):
        return os.path.join(abs_base, "system")

    return abs_base


def cmd_unpack(args: argparse.Namespace, reporter: CLIReporter) -> int:
    """Execute la sous-commande unpack : deballage et conversion sparse."""
    reporter.header("Extraction et analyse du firmware QF001")
    input_path = os.path.abspath(args.input)

    if not os.path.exists(input_path):
        reporter.error(f"Fichier source introuvable : {input_path}")
        return EXIT_ERROR

    output_dir = os.path.abspath(args.output_dir or "extracted")
    os.makedirs(output_dir, exist_ok=True)
    reporter.info(f"Fichier d entree : {input_path}")
    reporter.info(f"Repertoire de destination : {output_dir}")

    # Cas 1 : Archive ZIP de firmware
    if input_path.endswith(".zip") or zipfile.is_zipfile(input_path):
        reporter.info("Detection d une archive ZIP de mise a jour...")
        unpacker = FirmwareUnpacker(input_path, output_dir)

        if not unpacker.validate_archive():
            reporter.error("Archive invalide, corrompue ou tentative d intrusion Zip Slip detectee")
            return EXIT_ERROR

        try:
            auto_unsparse = not args.no_unsparse
            quarantine = not args.strict_mcu
            manifest = unpacker.unpack(auto_unsparse=auto_unsparse, quarantine_mcu=quarantine)

            reporter.success(f"Extraction terminee : {len(manifest.get('extracted_files', []))} fichiers extraits")

            unsparsed = manifest.get("unsparsed_images", [])
            if unsparsed:
                reporter.info(f"Images Sparse converties en RAW ({len(unsparsed)}) :")
                for img in unsparsed:
                    reporter.info(f"  * {os.path.basename(img)}")

            quarantined = manifest.get("quarantined_files", [])
            if quarantined:
                reporter.warn(f"Attention : {len(quarantined)} composant(s) MCU detectes et places en quarantaine :")
                for qf in quarantined:
                    reporter.warn(f"  * {qf}")
                reporter.info(f"Dossier de quarantaine securisee : {unpacker.quarantine_dir}")

            return EXIT_SUCCESS

        except MCUSafetyViolationError as e:
            reporter.error("Alerte de securite materielle : composants MCU detectes en mode strict")
            for viol in e.violations:
                reporter.error(f"  * Violation : {viol}")
            return EXIT_MCU_VIOLATION
        except Exception as e:
            reporter.error(f"Echec lors de l extraction du firmware : {e}")
            return EXIT_ERROR

    # Cas 2 : Fichier image partition unitaire (RAW ou Sparse)
    if input_path.endswith(".img") or os.path.isfile(input_path):
        reporter.info("Traitement d un fichier image de partition...")
        is_sparse = SparseImage.is_sparse(input_path)
        base_name = os.path.splitext(os.path.basename(input_path))[0]

        if is_sparse and not args.no_unsparse:
            raw_target = os.path.join(output_dir, f"{base_name}.raw.img")
            reporter.info(f"Image Sparse reconnue, conversion vers : {raw_target}")
            success = SparseImage.unsparse(input_path, raw_target)
            if success:
                reporter.success(f"Decompression de l image sparse achevee avec succes vers {raw_target}")
                return EXIT_SUCCESS
            else:
                reporter.error("Echec de la conversion de l image sparse")
                return EXIT_ERROR
        else:
            dest_target = os.path.join(output_dir, os.path.basename(input_path))
            shutil.copy2(input_path, dest_target)
            reporter.success(f"Copie de l image de partition vers {dest_target}")
            return EXIT_SUCCESS

    reporter.error("Format de fichier non pris en charge pour l extraction")
    return EXIT_ERROR


def cmd_debloat(args: argparse.Namespace, reporter: CLIReporter) -> int:
    """Execute la sous-commande debloat : purge des applications inutiles et telemetrie."""
    reporter.header("Assainissement et debloating de la partition systeme")
    system_root = locate_system_root(args.system_root)

    if not os.path.isdir(system_root):
        reporter.error(f"Repertoire systeme introuvable : {system_root}")
        return EXIT_ERROR

    reporter.info(f"Partition systeme cible : {system_root}")
    if args.dry_run:
        reporter.warn("Mode simulation actif (Dry Run) : aucune modification reelle ne sera appliquee")

    # Chargement des listes de configuration personnalisees ou par defaut
    blacklist = None
    if args.blacklist:
        bl_path = os.path.abspath(args.blacklist)
        reporter.info(f"Chargement de la liste de blocage personnalisee : {bl_path}")
        try:
            with open(bl_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                blacklist = data.get("packages", data)
        except Exception as e:
            reporter.error(f"Erreur de lecture de la liste noire : {e}")
            return EXIT_ERROR

    whitelist = None
    if args.whitelist:
        wl_path = os.path.abspath(args.whitelist)
        reporter.info(f"Chargement de la liste de preservation personnalisee : {wl_path}")
        try:
            with open(wl_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                whitelist = data.get("preserved_packages", data)
        except Exception as e:
            reporter.error(f"Erreur de lecture de la liste de preservation : {e}")
            return EXIT_ERROR

    try:
        debloater = Debloater(blacklist=blacklist, whitelist=whitelist)
        report: DebloatReport = debloater.debloat_filesystem(system_root, dry_run=args.dry_run)

        # Presentation detaillee du bilan
        reporter.info(f"Applications analysees au total : {report.total_scanned_apps}")
        reporter.info(f"Paquets supprimes ou purges ({report.removed_count}) :")
        for pkg in sorted(set(report.removed_packages)):
            reporter.info(f"  * {pkg}")

        reporter.info(f"Services automobiles rigoureusement preserves ({report.preserved_count}) :")
        for pkg in sorted(set(report.preserved_packages)):
            reporter.info(f"  * {pkg}")

        mb_freed = report.bytes_freed / (1024 * 1024)
        reporter.success(f"Espace libere sur la partition : {mb_freed:.2f} Mo ({report.bytes_freed} octets)")

        if report.errors:
            reporter.warn(f"Avertissements ou anomalies signalees ({len(report.errors)}) :")
            for err in report.errors:
                reporter.warn(f"  * {err}")

        # Verification stricte immediate de securite sauf si desactivee
        if not args.no_strict_safety:
            reporter.info("Controle de securite materielle apres debloating...")
            validator = SafetyValidator(raise_on_error=False)
            val_result = validator.verify_preserved_services(system_root)

            if not val_result.is_safe:
                reporter.error("Echec du controle de preservation des equipements automobiles :")
                for viol in val_result.violations:
                    reporter.error(f"  * {viol}")
                return EXIT_HARDWARE_VIOLATION
            else:
                reporter.success("Tous les services automobiles requis (TDA7708, Canbus, DSP, BT, Camera) sont intacts")

        return EXIT_SUCCESS

    except Exception as e:
        reporter.error(f"Erreur critique lors de l execution du debloater : {e}")
        return EXIT_ERROR


def cmd_customize(args: argparse.Namespace, reporter: CLIReporter) -> int:
    """Execute la sous-commande customize : injection du lanceur iOS et MicroG."""
    reporter.header("Personnalisation de l environnement et integration ergonomique")
    system_root = locate_system_root(args.system_root)

    if not os.path.isdir(system_root):
        reporter.error(f"Repertoire systeme introuvable : {system_root}")
        return EXIT_ERROR

    reporter.info(f"Partition systeme cible : {system_root}")
    overall_success = True

    # 1. Injection du lanceur ergonomique style iOS
    if not args.microg_only:
        reporter.info("Integration du lanceur automobile style iOS...")
        driver_side = args.driver_side or "left"
        theme = args.theme or "ios_automotive"
        reporter.info(f"Configuration du poste de conduite : dock cote {driver_side}, theme {theme}")

        try:
            launcher_success = IOSLauncherConfig.inject_into_system(system_root)
            if launcher_success:
                reporter.success("Lanceur automobile style iOS injecte avec succes dans priv-app/IOSLauncher")
                reporter.info("Permissions privilegiees et categorie HOME par defaut enregistrees")
            else:
                reporter.error("Echec de l injection du lanceur automobile")
                overall_success = False
        except Exception as e:
            reporter.error(f"Erreur lors de l injection du lanceur : {e}")
            overall_success = False

    # 2. Injection de la suite MicroG et regles skipappkill
    if not args.launcher_only:
        reporter.info("Integration de la suite MicroG et protection de l alimentation...")
        try:
            microg_success = MicroGConfig.inject_into_system(system_root)
            if microg_success:
                reporter.success("Suite MicroG (GmsCore, FakeStore, GsfProxy) injectee dans priv-app")
                reporter.info("Fichier de permissions signature spoofing ajoute dans etc/permissions")

                if not args.no_power_rules:
                    reporter.info("Regles de protection skipappkill.prop generees contre les coupures LMK/STR")
            else:
                reporter.error("Echec de l injection de la suite MicroG")
                overall_success = False

            # Verification de l integrite de l injection
            is_complete, missing = MicroGConfig.verify_injection(system_root)
            if not is_complete:
                reporter.warn(f"Certains composants MicroG semblent manquants ({len(missing)}) :")
                for m in missing:
                    reporter.warn(f"  * {m}")
        except Exception as e:
            reporter.error(f"Erreur lors de l injection de MicroG : {e}")
            overall_success = False

    return EXIT_SUCCESS if overall_success else EXIT_ERROR


def cmd_pack(args: argparse.Namespace, reporter: CLIReporter) -> int:
    """Execute la sous-commande pack : emballage securise et signature update.zip."""
    reporter.header("Creation du paquet de mise a jour update.zip pour cle USB FAT32")
    source_dir = os.path.abspath(args.source_dir)

    if not os.path.isdir(source_dir):
        reporter.error(f"Dossier source introuvable : {source_dir}")
        return EXIT_ERROR

    output_zip = os.path.abspath(args.output or "update.zip")
    reporter.info(f"Dossier source des fichiers : {source_dir}")
    reporter.info(f"Archive de sortie visee : {output_zip}")

    # 1. Audit prealable d isolation MCU absolue
    reporter.info("Audit de securite prealable : inspection complete contre les fichiers MCU...")
    try:
        MCUGuard.scan_directory(source_dir, raise_on_violation=True)
        reporter.success("Audit pre-emballage valide : aucun microcode MCU hostile detecte")
    except MCUSafetyViolationError as e:
        reporter.error("Violation critique d isolation materielle : presence de fichier MCU detectee")
        for viol in e.violations:
            reporter.error(f"  * {viol}")
        reporter.error("Operation interrompue immediatement pour proteger l autoradio")
        return EXIT_MCU_VIOLATION
    except Exception as e:
        reporter.error(f"Erreur lors de l analyse de conformite MCU : {e}")
        return EXIT_ERROR

    # 2. Verification de conformite de nom FAT32
    zip_basename = os.path.basename(output_zip)
    if not zip_basename.lower().endswith(".zip"):
        reporter.error(f"Le nom de l archive doit se terminer par .zip (recu : {zip_basename})")
        return EXIT_ERROR

    # 3. Construction de l archive
    try:
        sign = not args.no_sign
        temp_dest_dir = os.path.dirname(output_zip)
        if temp_dest_dir:
            os.makedirs(temp_dest_dir, exist_ok=True)

        if PackageBuilder is not None:
            reporter.info("Utilisation du module PackageBuilder pour structurer l archive...")
            PackageBuilder.build_update_zip(source_dir, output_zip, sign=sign)
        else:
            reporter.info("Assemblage de la partition et generation de l archive via la toolchain centrale...")
            with tempfile.TemporaryDirectory() as td:
                unsigned_zip = os.path.join(td, "unsigned_update.zip")
                packer = FirmwarePacker(source_dir, td)

                # Detection automatique de partitions existantes dans source_dir
                partitions: Dict[str, str] = {}
                for item in os.listdir(source_dir):
                    if item.endswith(".img"):
                        partitions[item] = os.path.join(source_dir, item)

                if partitions:
                    reporter.info(f"Partitions detectees pour emballage : {list(partitions.keys())}")
                    packer.repack_update_archive(unsigned_zip, partitions=partitions)
                else:
                    reporter.info("Generation de la partition systeme au format Android Sparse...")
                    packed_sys = packer.pack_partition("system", make_sparse=True)
                    packer.repack_update_archive(unsigned_zip, partitions={"system.img": packed_sys})

                if sign:
                    reporter.info("Application de la signature cryptographique PKCS#7 et metadonnees OTA...")
                    signer = PackageSigner(key_path=args.key, cert_path=args.cert)
                    signer.sign_archive(unsigned_zip, output_zip)
                else:
                    reporter.warn("Signature logicielle desactivee (option --no-sign specifiee)")
                    shutil.copyfile(unsigned_zip, output_zip)

        # 4. Audit de securite post-emballage
        reporter.info("Audit post-emballage de l archive generee...")
        is_safe, flagged = MCUGuard.scan_archive(output_zip, raise_on_violation=False)
        if not is_safe:
            reporter.error("Echec critique de l audit post-emballage : artefact MCU detecte dans le ZIP !")
            if os.path.exists(output_zip):
                os.remove(output_zip)
            return EXIT_MCU_VIOLATION

        # 5. Verification de la taille maximale compatible FAT32
        final_size = os.path.getsize(output_zip)
        max_size = args.max_size or MAX_FAT32_BYTES
        if final_size > max_size:
            reporter.error(
                f"Taille de l archive ({final_size} octets) superieure a la limite FAT32 ({max_size} octets)"
            )
            if os.path.exists(output_zip):
                os.remove(output_zip)
            return EXIT_ERROR

        size_mb = final_size / (1024 * 1024)
        reporter.success(f"Archive update.zip prete pour cle USB FAT32 : {output_zip} ({size_mb:.2f} Mo)")
        reporter.info("Consultez la notice docs/INSTRUCTIONS_FLASH_FAT32.md pour la procedure de flash")
        return EXIT_SUCCESS

    except MCUSafetyViolationError as e:
        reporter.error("Interruption de securite : tentative d injection MCU interceptee")
        if os.path.exists(output_zip):
            os.remove(output_zip)
        return EXIT_MCU_VIOLATION
    except Exception as e:
        reporter.error(f"Echec de construction de l archive update.zip : {e}")
        if os.path.exists(output_zip):
            try:
                os.remove(output_zip)
            except OSError:
                pass
        return EXIT_ERROR


def cmd_verify(args: argparse.Namespace, reporter: CLIReporter) -> int:
    """Execute la sous-commande verify : controles MCU, hardware et signature."""
    reporter.header("Audit d integrite et de securite complete")
    target_path = os.path.abspath(args.target)

    if not os.path.exists(target_path):
        reporter.error(f"Cible introuvable : {target_path}")
        return EXIT_ERROR

    reporter.info(f"Element a verifier : {target_path}")
    overall_ok = True

    # Cas A : Verification d une archive ZIP (update.zip)
    if os.path.isfile(target_path) and (target_path.endswith(".zip") or zipfile.is_zipfile(target_path)):
        reporter.info("Nature de la cible : Archive de mise a jour ZIP")

        # 1. Audit MCU
        if not args.hardware_only and not args.signature_only:
            reporter.info("1. Controle d absence de microcode MCU dans l archive...")
            is_safe, viols = MCUGuard.scan_archive(target_path, raise_on_violation=False)
            if is_safe:
                reporter.success("Bouclier MCU conforme : aucun binaire MCU present")
            else:
                reporter.error("Non conformite MCU : artefacts dangereux trouves dans l archive :")
                for v in viols:
                    reporter.error(f"  * {v}")
                return EXIT_MCU_VIOLATION

        # 2. Signature et metadonnees OTA
        if not args.mcu_only and not args.hardware_only:
            reporter.info("2. Verification de la signature cryptographique et metadonnees OTA...")
            signer = PackageSigner()
            res: VerificationResult = signer.verify_archive(target_path, cert_path=args.cert)
            if res.is_valid:
                reporter.success("Signature JAR v1 et empreintes SHA-256 validees avec succes")
                if res.metadata:
                    reporter.info(f"Metadonnees OTA verifiees : appareil {res.metadata.pre_device}, type {res.metadata.ota_type}")
            else:
                reporter.error("Echec de la verification de signature de l archive :")
                for err in res.errors:
                    reporter.error(f"  * {err}")
                return EXIT_VERIFICATION_FAILURE

        # 3. Conformite FAT32
        reporter.info("3. Verification de compatibilite avec support USB FAT32...")
        f_size = os.path.getsize(target_path)
        if f_size > MAX_FAT32_BYTES:
            reporter.error(f"Archive depassant la limite FAT32 de 4 Gio : {f_size} octets")
            overall_ok = False
        else:
            reporter.success(f"Taille conforme FAT32 : {f_size / (1024*1024):.2f} Mo")

        return EXIT_SUCCESS if overall_ok else EXIT_ERROR

    # Cas B : Verification d un dossier ou arborescence de partition
    if os.path.isdir(target_path):
        reporter.info("Nature de la cible : Repertoire de partition systeme")

        # 1. Audit MCU dans l arborescence
        if not args.hardware_only and not args.signature_only:
            reporter.info("1. Controle d absence de fichiers MCU dans l arborescence...")
            is_safe, viols = MCUGuard.scan_directory(target_path, raise_on_violation=False)
            if is_safe:
                reporter.success("Bouclier MCU conforme : aucun binaire MCU detecte dans le dossier")
            else:
                reporter.error("Non conformite MCU : composants interdits detectes :")
                for v in viols:
                    reporter.error(f"  * {v}")
                return EXIT_MCU_VIOLATION

        # 2. Audit de preservation des composants automobiles critiques
        if not args.mcu_only and not args.signature_only:
            reporter.info("2. Verification de la preservation des services automobiles indispensables...")
            validator = SafetyValidator(raise_on_error=False)
            val_res: ValidationResult = validator.verify_preserved_services(target_path)

            if val_res.is_safe:
                reporter.success(
                    f"Services automobiles valides ({len(val_res.verified_services)}) : "
                    "Radio TDA7708, DSP BU32107EFV, Canbus, BT et Camera intacts"
                )
            else:
                reporter.error("Echec critique de preservation des fonctions automobiles :")
                for v in val_res.violations:
                    reporter.error(f"  * {v}")
                return EXIT_HARDWARE_VIOLATION

        # 3. Verification des composants de personnalisation
        if not args.mcu_only and not args.signature_only:
            reporter.info("3. Inspection des modules de personnalisation (Lanceur iOS et suite MicroG)...")
            sys_root = locate_system_root(target_path)
            launcher_apk = os.path.join(sys_root, "priv-app", "IOSLauncher", "IOSLauncher.apk")
            if os.path.isfile(launcher_apk):
                reporter.success("Lanceur automobile style iOS present dans priv-app/IOSLauncher")
            else:
                reporter.warn("Lanceur automobile absent de priv-app/IOSLauncher")

            microg_ok, missing_microg = MicroGConfig.verify_injection(sys_root)
            if microg_ok:
                reporter.success("Suite MicroG et regles skipappkill.prop verifiees avec succes")
            else:
                reporter.warn(f"Composants MicroG manquants ou incomplets : {missing_microg}")

        return EXIT_SUCCESS

    reporter.error("Cible non traitable : doit etre une archive .zip ou un repertoire de partition")
    return EXIT_ERROR


def cmd_build_all(args: argparse.Namespace, reporter: CLIReporter) -> int:
    """Execute le pipeline complet automatise de bout en bout :
    unpack -> debloat -> customize -> verify -> pack.
    """
    reporter.header("Execution du pipeline automatise de bout en bout (Build-All)")
    start_time = time.time()
    input_file = os.path.abspath(args.input)

    if not os.path.exists(input_file):
        reporter.error(f"Fichier source introuvable : {input_file}")
        return EXIT_ERROR

    output_zip = os.path.abspath(args.output or "update.zip")
    keep_work_dir = getattr(args, "keep_work_dir", False)
    custom_work_dir = getattr(args, "work_dir", None)

    if custom_work_dir:
        staging_dir = os.path.abspath(custom_work_dir)
        os.makedirs(staging_dir, exist_ok=True)
        cleanup_staging = not keep_work_dir
    else:
        staging_dir = tempfile.mkdtemp(prefix="qf001_build_")
        cleanup_staging = not keep_work_dir

    reporter.info(f"Fichier d entree : {input_file}")
    reporter.info(f"Destination finale de l archive : {output_zip}")
    reporter.info(f"Repertoire de travail temporaire : {staging_dir}")

    try:
        # Phase 1 : Extraction du firmware
        reporter.header("Etape 1 sur 5 : Extraction et decompression")
        extracted_dir = os.path.join(staging_dir, "extracted")
        os.makedirs(extracted_dir, exist_ok=True)

        unpack_args = argparse.Namespace(
            input=input_file,
            output_dir=extracted_dir,
            no_unsparse=False,
            strict_mcu=True,
        )
        rc_unpack = cmd_unpack(unpack_args, reporter)
        if rc_unpack != EXIT_SUCCESS:
            reporter.error("Interruption du pipeline a l etape d extraction")
            return rc_unpack

        system_dir = locate_system_root(extracted_dir)
        reporter.info(f"Racine systeme identifiee : {system_dir}")

        # Phase 2 : Debloating profond
        reporter.header("Etape 2 sur 5 : Debloating et assainissement")
        debloat_args = argparse.Namespace(
            system_root=system_dir,
            blacklist=None,
            whitelist=None,
            dry_run=getattr(args, "dry_run", False),
            no_strict_safety=False,
        )
        rc_debloat = cmd_debloat(debloat_args, reporter)
        if rc_debloat != EXIT_SUCCESS:
            reporter.error("Interruption du pipeline a l etape de debloating")
            return rc_debloat

        # Phase 3 : Personnalisation (Lanceur iOS et MicroG)
        if not getattr(args, "skip_customize", False):
            reporter.header("Etape 3 sur 5 : Personnalisation ergonomique")
            cust_args = argparse.Namespace(
                system_root=system_dir,
                launcher_only=False,
                microg_only=False,
                driver_side=getattr(args, "driver_side", "left"),
                theme=getattr(args, "theme", "ios_automotive"),
                no_power_rules=False,
            )
            rc_cust = cmd_customize(cust_args, reporter)
            if rc_cust != EXIT_SUCCESS:
                reporter.error("Interruption du pipeline a l etape de personnalisation")
                return rc_cust
        else:
            reporter.info("Etape de personnalisation ignoree (--skip-customize specifie)")

        # Phase 4 : Verification complete pre-emballage
        reporter.header("Etape 4 sur 5 : Validation d integrite et de securite")
        verify_args = argparse.Namespace(
            target=system_dir,
            mcu_only=False,
            hardware_only=False,
            signature_only=False,
            cert=getattr(args, "cert", None),
        )
        rc_verify = cmd_verify(verify_args, reporter)
        if rc_verify != EXIT_SUCCESS:
            reporter.error("Interruption du pipeline a l etape de verification de securite")
            return rc_verify

        # Phase 5 : Emballage et signature
        reporter.header("Etape 5 sur 5 : Emballage et signature pour cle USB FAT32")
        pack_args = argparse.Namespace(
            source_dir=system_dir,
            output=output_zip,
            no_sign=getattr(args, "no_sign", False),
            key=getattr(args, "key", None),
            cert=getattr(args, "cert", None),
            max_size=MAX_FAT32_BYTES,
        )
        rc_pack = cmd_pack(pack_args, reporter)
        if rc_pack != EXIT_SUCCESS:
            reporter.error("Interruption du pipeline a l etape d emballage")
            return rc_pack

        elapsed = time.time() - start_time
        reporter.header("Bilan de production de la ROM QF001")
        reporter.success(f"Pipeline complet execute avec succes en {elapsed:.1f} secondes !")
        reporter.info(f"Archive finale generee : {output_zip}")
        reporter.info("Le paquet est certifie compatible avec le support amovible FAT32")
        reporter.info("La protection absolue du microcode MCU est confirmee")
        return EXIT_SUCCESS

    finally:
        if cleanup_staging and os.path.exists(staging_dir):
            try:
                shutil.rmtree(staging_dir)
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    """Construit l analyseur syntaxique unifie avec toutes ses sous-commandes."""
    parser = argparse.ArgumentParser(
        prog="qf001-toolchain",
        description="Toolchain unifiee de creation de ROM Debloat pour autoradios ROCO K706 (UIS 7862 / 7862S).",
        epilog="Exemple : %(prog)s build-all stock_firmware.zip -o update.zip",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Parametres globaux
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Affiche les details techniques et informations de debogage",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Supprime les affichages non essentiels a l exception des erreurs",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {TOOLCHAIN_VERSION} (Plateforme {PLATFORM_TARGET} {REFERENCE_DEVICE})",
        help="Affiche la version de la toolchain et quitte",
    )

    subparsers = parser.add_subparsers(
        title="Commandes disponibles",
        dest="subcommand",
        metavar="<commande>",
    )

    # 1. Sous-commande unpack
    p_unpack = subparsers.add_parser(
        "unpack",
        help="Extrait et deconventionne les images ou archives de firmware",
        description="Decompresse une archive ZIP ou convertit une partition Android Sparse en RAW.",
    )
    p_unpack.add_argument(
        "input",
        help="Chemin vers le fichier archive ZIP ou l image de partition (.img)",
    )
    p_unpack.add_argument(
        "-o", "--output-dir",
        default="extracted",
        help="Dossier de destination pour l extraction (par defaut : ./extracted)",
    )
    p_unpack.add_argument(
        "--no-unsparse",
        action="store_true",
        help="Desactive la conversion automatique des images sparse vers le format raw",
    )
    p_unpack.add_argument(
        "--strict-mcu",
        action="store_true",
        help="Interrompt immediatement l extraction en cas de detection de composant MCU au lieu de le mettre en quarantaine",
    )
    p_unpack.set_defaults(func=cmd_unpack)

    # 2. Sous-commande debloat
    p_debloat = subparsers.add_parser(
        "debloat",
        help="Execute le debloating profond sur la partition systeme",
        description="Purge les applications superflues, traceurs et telemetries selon la liste de blocage.",
    )
    p_debloat.add_argument(
        "system_root",
        help="Chemin vers la racine de la partition systeme extraite",
    )
    p_debloat.add_argument(
        "-b", "--blacklist",
        help="Chemin vers un fichier JSON personnalise de liste noire de paquets",
    )
    p_debloat.add_argument(
        "-w", "--whitelist",
        help="Chemin vers un fichier JSON personnalise de services automobiles a preserver",
    )
    p_debloat.add_argument(
        "--dry-run",
        action="store_true",
        help="Simule la suppression sans modifier les fichiers sur le disque",
    )
    p_debloat.add_argument(
        "--no-strict-safety",
        action="store_true",
        help="Desactive la validation automatique post-debloat des peripheriques automobiles",
    )
    p_debloat.set_defaults(func=cmd_debloat)

    # 3. Sous-commande customize
    p_cust = subparsers.add_parser(
        "customize",
        help="Installe le lanceur style iOS et la suite MicroG avec regles de veille",
        description="Configure l ergonomie conducteur, le dock tactile, les tuiles et les permissions MicroG.",
    )
    p_cust.add_argument(
        "system_root",
        help="Chemin vers la racine de la partition systeme extraite",
    )
    p_cust.add_argument(
        "--launcher-only",
        action="store_true",
        help="Injecte uniquement le lanceur automobile style iOS",
    )
    p_cust.add_argument(
        "--microg-only",
        action="store_true",
        help="Injecte uniquement la suite MicroG et les parametres d alimentation",
    )
    p_cust.add_argument(
        "--driver-side",
        choices=["left", "right"],
        default="left",
        help="Emplacement du dock ergonomique pour le conducteur (par defaut : left)",
    )
    p_cust.add_argument(
        "--theme",
        default="ios_automotive",
        help="Theme graphique du lanceur (par defaut : ios_automotive)",
    )
    p_cust.add_argument(
        "--no-power-rules",
        action="store_true",
        help="Ignore la creation du fichier skipappkill.prop de gestion de veille",
    )
    p_cust.set_defaults(func=cmd_customize)

    # 4. Sous-commande pack
    p_pack = subparsers.add_parser(
        "pack",
        help="Structure la partition et genere l archive signed update.zip pour cle FAT32",
        description="Verifie l absence absolue de composant MCU, assemble les partitions et signe l archive.",
    )
    p_pack.add_argument(
        "source_dir",
        help="Dossier contenant l arborescence de la partition systeme ou les images de partition",
    )
    p_pack.add_argument(
        "-o", "--output",
        default="update.zip",
        help="Nom et chemin du fichier archive en sortie (par defaut : update.zip)",
    )
    p_pack.add_argument(
        "--no-sign",
        action="store_true",
        help="Ne signe pas l archive avec les cles cryptographiques OTA",
    )
    p_pack.add_argument(
        "--key",
        help="Chemin vers la cle privee de signature RSA (facultatif)",
    )
    p_pack.add_argument(
        "--cert",
        help="Chemin vers le certificat X.509 de signature (facultatif)",
    )
    p_pack.add_argument(
        "--max-size",
        type=int,
        default=MAX_FAT32_BYTES,
        help="Limite de taille de fichier en octets (par defaut : limite FAT32 de 4294967295)",
    )
    p_pack.set_defaults(func=cmd_pack)

    # 5. Sous-commande verify
    p_verify = subparsers.add_parser(
        "verify",
        help="Verifie la securite MCU, les pilotes automobiles et la signature",
        description="Audite une archive update.zip ou un dossier de partition systeme.",
    )
    p_verify.add_argument(
        "target",
        help="Chemin vers l archive update.zip ou le repertoire de la partition",
    )
    p_verify.add_argument(
        "--mcu-only",
        action="store_true",
        help="Effectue uniquement le controle de conformite et d isolation MCU",
    )
    p_verify.add_argument(
        "--hardware-only",
        action="store_true",
        help="Effectue uniquement la verification des pilotes et services automobiles",
    )
    p_verify.add_argument(
        "--signature-only",
        action="store_true",
        help="Effectue uniquement la verification de signature cryptographique",
    )
    p_verify.add_argument(
        "--cert",
        help="Certificat X.509 a utiliser pour controler la signature",
    )
    p_verify.set_defaults(func=cmd_verify)

    # 6. Sous-commande build-all
    p_build = subparsers.add_parser(
        "build-all",
        help="Execute le cycle complet de production de bout en bout",
        description="Enchaine automatiquement : unpack -> debloat -> customize -> verify -> pack.",
    )
    p_build.add_argument(
        "input",
        help="Chemin vers l archive de firmware originale ou l image systeme",
    )
    p_build.add_argument(
        "-o", "--output",
        default="update.zip",
        help="Chemin de destination de l archive finale signee (par defaut : update.zip)",
    )
    p_build.add_argument(
        "-w", "--work-dir",
        help="Repertoire de travail temporaire personnalise",
    )
    p_build.add_argument(
        "--keep-work-dir",
        action="store_true",
        help="Conserve les dossiers de travail apres l execution",
    )
    p_build.add_argument(
        "--dry-run",
        action="store_true",
        help="Execute le debloating en mode simulation sans supprimer reellement les fichiers",
    )
    p_build.add_argument(
        "--driver-side",
        choices=["left", "right"],
        default="left",
        help="Position du dock conducteur pour le lanceur (par defaut : left)",
    )
    p_build.add_argument(
        "--theme",
        default="ios_automotive",
        help="Theme visuel du lanceur ergonomique",
    )
    p_build.add_argument(
        "--skip-customize",
        action="store_true",
        help="Ignore la personnalisation du lanceur et de MicroG",
    )
    p_build.add_argument(
        "--no-sign",
        action="store_true",
        help="Ne signe pas l archive finale",
    )
    p_build.add_argument(
        "--key",
        help="Cle privee RSA pour la signature",
    )
    p_build.add_argument(
        "--cert",
        help="Certificat X.509 pour la signature",
    )
    p_build.set_defaults(func=cmd_build_all)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Point d entree principal de l utilitaire en ligne de commande.

    Conforme au contrat d initialisation de l environnement :
    lorsqu aucun argument n est fourni, initialise la toolchain avec succes
    et retourne le code 0.
    """
    parser = build_parser()

    # Si argv n est pas fourni (appel direct sans arguments), traiter comme vide
    raw_args = [] if argv is None else list(argv)

    # Si aucun argument n est specifie, afficher la banniere et l aide, puis retourner 0
    if len(raw_args) == 0:
        reporter = CLIReporter(verbose=False, quiet=False)
        reporter.banner()
        print("QF001 Debloat OS Toolchain initialisee avec succes.\n")
        parser.print_help()
        return EXIT_SUCCESS

    try:
        args = parser.parse_args(raw_args)
    except SystemExit as e:
        return int(e.code)

    reporter = CLIReporter(verbose=args.verbose, quiet=args.quiet)

    if not hasattr(args, "func"):
        reporter.banner()
        parser.print_help()
        return EXIT_SUCCESS

    try:
        return args.func(args, reporter)
    except KeyboardInterrupt:
        reporter.warn("\nOperation interrompue par l utilisateur")
        return EXIT_ERROR
    except Exception as e:
        reporter.error(f"Erreur inattendue durant l execution : {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
