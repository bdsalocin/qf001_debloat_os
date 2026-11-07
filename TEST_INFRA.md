# Test Infrastructure & Methodology — QF001 Debloat OS

## 1. Overview and Scope

This document specifies the end-to-end (E2E) testing infrastructure for the QF001 Debloat OS project (ROCO K706 platform, Unisoc UIS 7862 / 7862S).
The testing suite is designed as an **opaque-box verification system** derived strictly from user requirements (R1, R2, R3, R4) and acceptance criteria documented in `ORIGINAL_REQUEST.md` and `PROJECT.md`.

The primary mandate is to guarantee:
1. **R1 (Firmware Toolchain)**: Robust unpacking, sparse image manipulation, repacking, and OTA signing without host dependencies.
2. **R2 (Deep Debloating & Preservation)**: Total eradication of bloatware and telemetry while preserving essential automotive daemons (Canbus, TDA7708 radio, audio DSP, reverse camera, Bluetooth).
3. **R3 (iOS-Style Automotive UX)**: Integration of a streamlined iOS-inspired launcher as the default priv-app home interface with quick automotive tiles.
4. **R4 (Absolute MCU Safety & FAT32 Packaging)**: Complete isolation of the MCU hardware, zero modification of MCU microcode, and valid FAT32 USB packaging.

---

## 2. 4-Tier Test Architecture

The test suite is organized into 4 distinct progressive tiers:

```
tests/e2e/
├── test_runner.py               # Central orchestrator and progressive signal reporter
├── test_tier1_features.py       # Tier 1: Direct requirement feature coverage (R1..R4)
├── test_tier2_boundaries.py     # Tier 2: Edge cases, corrupt data, boundary stress
├── test_tier3_combinations.py   # Tier 3: Cross-feature integrations & data pipelines
└── test_tier4_scenarios.py      # Tier 4: Real-world automotive deployment workflows
```

### Tier 1: Feature Coverage (Opaque-Box Verification)
- **Objective**: Verify that each core requirement (R1, R2, R3, R4) meets its functional specification.
- **Minimum Threshold**: At least 5 distinct test cases per requirement (>= 20 tests total).
- **Coverage Areas**:
  - `R1_Environment`: Toolchain availability, sparse image detection and conversion, archive extraction, OTA signing contract.
  - `R2_Debloating`: Blacklist enforcement, telemetry removal, preserved services whitelist integrity, filesystem cleaning report.
  - `R3_Launcher`: iOS launcher layout structure, quick tiles configuration, priv-app default home registration, microG optimization.
  - `R4_MCUSafety_FAT32`: Zero-MCU file exclusion, MCU artifact detection, update.zip structure, FAT32 path and size constraints.

### Tier 2: Boundary & Corner Cases
- **Objective**: Validate system behavior against pathological inputs, corrupt structures, and extreme conditions.
- **Coverage Areas**:
  - Malformed and corrupt Android Sparse headers (bad magic `0xED26FF3A`, invalid chunk headers, truncated payload).
  - MCU intrusion attempts (case variations, path traversal, nested binaries like `nested/mcu.bin`, `stm32_mcu.hex`).
  - Empty configurations (empty blacklist, empty whitelist, missing packages).
  - Malformed JSON configuration files (syntax errors, invalid types).
  - FAT32 filename and path length limits (255 chars, illegal characters `\ / : * ? " < > |`).
  - Extreme filesystem partitions (0-byte partitions, empty directories).

### Tier 3: Cross-Feature Combinations
- **Objective**: Validate the seamless interaction between independent modules across the pipeline.
- **Coverage Areas**:
  - **Sparse -> Unpack -> Debloat -> Repack -> Sparse**: Full round-trip data transformation maintaining filesystem validity.
  - **Debloat + Preserved Services Validation**: Debloater engine must never remove packages present in the preserved services registry.
  - **Launcher Injection + System Permissions**: Injected launcher configuration integrates into `/system/priv-app/` with default HOME category.
  - **Update Packaging + MCU Safety Audit**: Package builder automatically invokes MCU guard and aborts if any foreign binary is detected.

### Tier 4: Real-World Automotive Deployment Scenarios
- **Objective**: Execute complete lifecycle workflows that simulate actual deployment onto ROCO K706 UIS 7862 hardware.
- **Coverage Areas**:
  - **Scenario A**: Stock QF001 ROM ingestion -> complete debloat -> launcher install -> signed `update.zip` generation ready for FAT32 USB.
  - **Scenario B**: Hostile/bloated ROM cleanup verifying complete eradication of YLog and Chinese telemetry while confirming TDA7708 radio and Canbus services remain 100% operational.
  - **Scenario C**: USB Flash installation artifact validation: verifying `update.zip`, SHA256 checksums, flash instructions guide, and FAT32 compatibility.
  - **Scenario D**: MCU attack containment: deliberate insertion of hostile MCU files inside ROM payload; verification that pipeline aborts safely with zero output.

---

## 3. Progressive Testability & Signal Detection

Because implementation proceeds across milestones (M1 through M4), the test suite supports **progressive test signals**:

| Milestone | Expected Target Features | Progressive State |
|-----------|--------------------------|-------------------|
| **M1** | `sparse.py`, `unpacker.py`, `packer.py`, `signer.py`, `mcu_guard.py` | R1 & R4 (MCU Guard) active |
| **M2** | `debloater.py`, `safety_validator.py`, blacklist/whitelist configs | R2 active |
| **M3** | `launcher.py`, `microg.py`, priv-app HOME integration | R3 active |
| **M4** | `package_builder.py`, `cli/main.py`, USB FAT32 guide | R4 (Packager) & Scenarios active |
| **M_final** | All components integrated & hardened | 100% pass across all 4 tiers |

### Progressive Signal Mechanism
- The runner detects whether a module or interface is implemented.
- If a milestone is pending, tests indicate `PENDING [Milestone]` using standard `unittest.SkipTest`, providing non-crashing progressive diagnostics.
- If a feature is implemented, the test executes strict assertions. If an implementation defect is found, the test **FAILS** with a descriptive escalation report.
- The runner compiles an ASCII diagnostic board displaying progress across requirements and tiers.

---

## 4. Authoritative Expected Output Derivation

All expected values are derived from authoritative specifications:
1. **Android Sparse Format**: Official AOSP sparse format (`SPARSE_HEADER_MAGIC = 0xED26FF3A`, major version 1, minor version 0, 28-byte header, 12-byte chunk header).
2. **Hardware Constraints**: ROCO K706 QF001 hardware profile:
   - CPU: Unisoc UIS 7862 / 7862S
   - Radio Tuner IC: NXP TDA7708
   - Audio Amplifier: TDA7851
   - DSP: BU32107EFV
   - Critical Packages: `com.ts.main.radio`, `com.syu.canbus`, `com.roco.canbus`, `com.syu.bt`, `com.ts.camera`
3. **MCU Safety Guard**: Strict ban on any file matching `*mcu*.bin`, `mcu.bin`, `*mcu*.hex`, or MCU flash scripts.
4. **FAT32 Constraints**: Maximum single file size 4,294,967,295 bytes (4GB - 1 byte), ASCII/UTF-8 filename rules, 8.3 or LFN compatibility.

---

## 5. Execution Instructions

### Running the Entire Suite
```bash
python3 tests/e2e/test_runner.py
```

### Running Specific Tiers
```bash
# Tier 1 only (Feature Coverage)
python3 tests/e2e/test_runner.py --tier 1

# Tier 2 only (Boundaries & Edge Cases)
python3 tests/e2e/test_runner.py --tier 2

# Tier 3 only (Combinations)
python3 tests/e2e/test_runner.py --tier 3

# Tier 4 only (Real-World Scenarios)
python3 tests/e2e/test_runner.py --tier 4
```

### Running via Standard Python Unittest
```bash
python3 -m unittest discover -s tests/e2e
```

### Output Summary Format
The runner outputs:
```
======================================================================
  QF001 DEBLOAT OS — E2E TEST SUITE REPORT
======================================================================
Tier 1: Feature Coverage
  - R1 Toolchain & Base     : 5/5 PASSED
  - R2 Debloating & Safety   : 5/5 PASSED
  - R3 iOS Launcher          : 5/5 PASSED
  - R4 MCU Guard & FAT32     : 5/5 PASSED
Tier 2: Boundary & Corner Cases: 8/8 PASSED
Tier 3: Cross-Feature Combos   : 5/5 PASSED
Tier 4: Real-World Scenarios   : 4/4 PASSED
----------------------------------------------------------------------
Total Tests: 37 | Passed: 37 | Pending: 0 | Failed: 0
Overall Status: ALL TIERS GREEN
======================================================================
```
