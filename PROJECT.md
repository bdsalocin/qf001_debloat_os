# Project: QF001 Debloat OS

## Architecture
Le projet structure la toolchain de debloating et de personnalisation de firmware pour autoradios ROCO K706 QF001 (Unisoc UIS 7862 / 7862S) selon une architecture modulaire a haute securite :
- `src/core` : Outils purs Python d extraction, de conversion Android Sparse, de reconstruction d image, de signature OTA et de securite materielle (MCU guard).
- `src/domain` : Moteur de debloating, regles d assainissement des telemetries et validation de la preservation absolue des services automobiles (TDA7708, DSP, Canbus, Camera, BT).
- `src/customization` : Module d integration du lanceur ergonomique style iOS (dock conducteur, tuiles musique/radio/navigation) et integration de MicroG.
- `src/cli` : Interface en ligne de commande unifiee pour piloter l ensemble du cycle de production.
- `config` : Profils materiels, listes de blocage des bloatwares et inventaire des services critiques preserves.
- `tests` : Suites de tests unitaires, d integration et tests E2E.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Python Sparse Engine | Module pur Python de conversion et analyse d images sparse Android | M1 | Survey Codebase |
| 2 | Firmware Unpacker | Extraction et inspection d archives et d images systeme | M1 | R1 |
| 3 | Firmware Packer | Reconstruction et structuration des partitions systeme | M1 | R1 |
| 4 | Package Signer | Generation des signatures OTA et metadonnees Android | M1 | R1 |
| 5 | MCU Safety Guard | Bouclier d isolation stricte interdisant tout composant MCU | M1 | R4 |
| 6 | Deep Debloater Engine | Suppression des bloatwares selon liste noire et arborescence | M2 | R2 |
| 7 | Telemetry & YLog Purge | Neutralisation des traceurs, logs intrusifs et assistants parasites | M2 | R2 |
| 8 | Preserved Services Validator | Validation stricte du maintien de la radio TDA7708, DSP, Canbus, camera | M2 | R2 |
| 9 | Configuration Profiles | Profils materiels et listes exhaustives securisees | M2 | R2 |
| 10 | iOS-Style Launcher Config | Configuration du lanceur epure pour environnement automobile | M3 | R3 |
| 11 | Automotive Quick Tiles | Ergonomie adaptee a la conduite (navigation, musique, radio, parametres) | M3 | R3 |
| 12 | Default Home Integration | Enregistrement de l intention HOME par defaut dans priv-app | M3 | R3 |
| 13 | MicroG & Power Management | Optimisation memoire MicroG et regles skipappkill | M3 | R3 |
| 14 | Update.zip Builder | Packaging automatise pour support amovible USB FAT32 | M4 | R4 |
| 15 | Zero-MCU Safety Check | Verification pre-emballage d absence totale de firmware MCU | M4 | R4 |
| 16 | CLI Toolchain Interface | Interface en ligne de commande unifiee avec commandes de build | M4 | R1, R4 |
| 17 | User Step-by-Step Guide | Documentation complete de flashage sur cle USB FAT32 | M4 | R4 |
| 18 | E2E Test Suite Validation | Validation integrale a 100% de la suite de tests E2E | M_final | R1, R2, R3, R4 |
| 19 | Adversarial Hardening | Durcissement adversarial et tests aux limites (Tier 5) | M_final | R1, R2, R3, R4 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Core Toolchain & MCU Guard | sparse.py, unpacker.py, packer.py, signer.py, mcu_guard.py | none | DONE |
| M2 | Debloater & Hardware Validator | debloater.py, safety_validator.py, config enrichie | M1 | IN_PROGRESS |
| M3 | iOS Launcher & Customization | launcher.py, microg.py, configuration HOME priv-app | M2 | PLANNED |
| M4 | FAT32 Packager, CLI & Guide | package_builder.py, cli/main.py, documentation flashage | M3 | PLANNED |
| M_final | Final Acceptance & Hardening | Validation complete des tests E2E (Tiers 1-4) puis durcissement Tier 5 | M4, E2E | PLANNED |

## Interface Contracts
### src.core.sparse ↔ src.core.unpacker / packer
- `SparseImage.is_sparse(path: str) -> bool`
- `SparseImage.unsparse(source_path: str, dest_path: str) -> bool`
- `SparseImage.sparse(source_path: str, dest_path: str) -> bool`

### src.core.mcu_guard ↔ src.core.package_builder
- `MCUGuard.check_archive_safety(file_list: list[str]) -> tuple[bool, list[str]]`
- `MCUGuard.is_mcu_artifact(filename: str) -> bool` : interdit `mcu.bin`, `*mcu*.bin`, scripts de flash MCU.

### src.domain.debloater ↔ src.domain.safety_validator
- `Debloater.debloat_filesystem(system_root: str) -> DebloatReport`
- `SafetyValidator.verify_preserved_services(system_root: str) -> ValidationResult` : verifie presence intacte des paquets TDA7708, Canbus, DSP, Camera, BT.

### src.customization.launcher ↔ src.cli.main
- `IOSLauncherConfig.generate_layout() -> dict`
- `IOSLauncherConfig.inject_into_system(system_root: str) -> bool`

### src.core.package_builder ↔ src.cli.main
- `PackageBuilder.build_update_zip(source_dir: str, output_zip: str) -> str`

## Code Layout
```
qf001_debloat_os/
├── config/
│   ├── bloatware_blacklist.json
│   ├── hardware_profiles.json
│   └── preserved_services.json
├── src/
│   ├── __init__.py
│   ├── cli/
│   │   ├── __init__.py
│   │   └── main.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── mcu_guard.py
│   │   ├── packer.py
│   │   ├── signer.py
│   │   ├── sparse.py
│   │   └── unpacker.py
│   ├── customization/
│   │   ├── __init__.py
│   │   ├── launcher.py
│   │   └── microg.py
│   └── domain/
│       ├── __init__.py
│       ├── debloater.py
│       └── safety_validator.py
├── tests/
│   ├── __init__.py
│   ├── test_debloater.py
│   ├── test_mcu_guard.py
│   ├── test_sparse.py
│   ├── test_unpacker_packer.py
│   ├── test_launcher.py
│   ├── test_safety_validator.py
│   ├── test_cli.py
│   └── e2e/
│       ├── __init__.py
│       ├── test_runner.py
│       ├── test_tier1_features.py
│       ├── test_tier2_boundaries.py
│       ├── test_tier3_combinations.py
│       └── test_tier4_scenarios.py
├── docs/
│   └── INSTRUCTIONS_FLASH_FAT32.md
├── PROJECT.md
└── README.md
```
