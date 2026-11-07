#!/usr/bin/env python3
"""Central E2E Test Suite Runner for QF001 Debloat OS.

Executes all 4 testing tiers:
- Tier 1: Feature Coverage (R1 Environment, R2 Debloating, R3 Launcher, R4 MCU & FAT32)
- Tier 2: Boundary & Corner Cases
- Tier 3: Cross-Feature Combinations
- Tier 4: Real-World Automotive Scenarios

Provides detailed progressive signals across milestones (M1 to M4).
"""
import argparse
import io
import json
import os
import sys
import time
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class ProgressiveTestResult(unittest.TestResult):
    """Custom test result accumulator that tracks passed, skipped, and failed tests."""

    def __init__(self, stream=None, descriptions=None, verbosity=None):
        super().__init__(stream=stream, descriptions=descriptions, verbosity=verbosity)
        self.passed = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed.append(test)


def run_test_module(test_module_name: str, verbosity: int = 1):
    """Load and execute a specific test module, returning the result object."""
    suite = unittest.defaultTestLoader.loadTestsFromName(test_module_name)
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=verbosity, resultclass=ProgressiveTestResult)
    result = runner.run(suite)
    return result


def analyze_tier1_results(tier1_result):
    """Group Tier 1 results by Requirement (R1, R2, R3, R4)."""
    groups = {
        "R1 (Firmware Base & Toolchain)": {"total": 0, "pass": 0, "skip": 0, "fail": 0},
        "R2 (Debloating & Preservation)": {"total": 0, "pass": 0, "skip": 0, "fail": 0},
        "R3 (iOS-Style Launcher UX)": {"total": 0, "pass": 0, "skip": 0, "fail": 0},
        "R4 (MCU Safety & FAT32 Packaging)": {"total": 0, "pass": 0, "skip": 0, "fail": 0},
    }

    def categorize(test_name: str):
        tn = test_name.lower()
        if "test_r1" in tn or "featurer1" in tn:
            return "R1 (Firmware Base & Toolchain)"
        elif "test_r2" in tn or "featurer2" in tn or "debloat" in tn:
            return "R2 (Debloating & Preservation)"
        elif "test_r3" in tn or "featurer3" in tn or "launcher" in tn:
            return "R3 (iOS-Style Launcher UX)"
        elif "test_r4" in tn or "featurer4" in tn or "mcusafety" in tn:
            return "R4 (MCU Safety & FAT32 Packaging)"
        return "R1 (Firmware Base & Toolchain)"

    for test in tier1_result.passed:
        grp = categorize(str(test))
        groups[grp]["total"] += 1
        groups[grp]["pass"] += 1

    for test, reason in tier1_result.skipped:
        grp = categorize(str(test))
        groups[grp]["total"] += 1
        groups[grp]["skip"] += 1

    for test, err in tier1_result.failures + tier1_result.errors:
        grp = categorize(str(test))
        groups[grp]["total"] += 1
        groups[grp]["fail"] += 1

    return groups


def main():
    parser = argparse.ArgumentParser(description="QF001 Debloat OS E2E Test Suite Runner")
    parser.add_argument("--tier", type=int, choices=[1, 2, 3, 4], help="Run only a specific test tier (1-4)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose test execution output")
    args = parser.parse_args()

    verbosity = 2 if args.verbose else 1
    tiers_to_run = [args.tier] if args.tier else [1, 2, 3, 4]

    tier_modules = {
        1: ("Tier 1: Feature Coverage (R1-R4)", "tests.e2e.test_tier1_features"),
        2: ("Tier 2: Boundary & Corner Cases", "tests.e2e.test_tier2_boundaries"),
        3: ("Tier 3: Cross-Feature Combinations", "tests.e2e.test_tier3_combinations"),
        4: ("Tier 4: Real-World Scenarios", "tests.e2e.test_tier4_scenarios"),
    }

    start_time = time.time()
    tier_results = {}
    tier1_breakdown = None

    total_tests = 0
    total_passed = 0
    total_skipped = 0
    total_failed = 0

    for t in tiers_to_run:
        label, mod = tier_modules[t]
        res = run_test_module(mod, verbosity=verbosity)
        tier_results[t] = {
            "label": label,
            "total": res.testsRun,
            "passed": len(res.passed),
            "skipped": len(res.skipped),
            "failed": len(res.failures) + len(res.errors),
            "failure_details": [f"{str(t)}: {err}" for t, err in res.failures + res.errors],
            "skipped_details": [f"{str(t)}: {reason}" for t, reason in res.skipped]
        }
        if t == 1:
            tier1_breakdown = analyze_tier1_results(res)

        total_tests += res.testsRun
        total_passed += len(res.passed)
        total_skipped += len(res.skipped)
        total_failed += len(res.failures) + len(res.errors)

    elapsed_time = time.time() - start_time

    if args.json:
        report = {
            "elapsed_seconds": round(elapsed_time, 3),
            "summary": {
                "total": total_tests,
                "passed": total_passed,
                "pending": total_skipped,
                "failed": total_failed,
                "status": "GREEN" if total_failed == 0 else "RED"
            },
            "tiers": tier_results,
            "tier1_breakdown": tier1_breakdown
        }
        print(json.dumps(report, indent=2))
        return 1 if total_failed > 0 else 0

    # Formatted ASCII Dashboard
    print("\n" + "=" * 76)
    print("      QF001 DEBLOAT OS — COMPREHENSIVE E2E TEST SUITE REPORT")
    print("=" * 76)
    print(f" Timestamp : {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}")
    print(f" Scope     : ROCO K706 Platform (UIS 7862/7862S) — R1, R2, R3, R4")
    print(f" Execution : {total_tests} tests in {elapsed_time:.3f}s")
    print("-" * 76)

    for t in tiers_to_run:
        data = tier_results[t]
        label = data["label"]
        p, s, f, tot = data["passed"], data["skipped"], data["failed"], data["total"]
        status_tag = "[PASS]" if f == 0 and s == 0 else ("[PENDING]" if f == 0 else "[FAIL]")
        print(f" {status_tag:<9} {label:<44} : {p} passed, {s} pending, {f} failed (total {tot})")

    if tier1_breakdown and (args.tier is None or args.tier == 1):
        print("\n Tier 1 Requirement Breakdown:")
        for req, counts in tier1_breakdown.items():
            rp, rs, rf, rtot = counts["pass"], counts["skip"], counts["fail"], counts["total"]
            r_tag = "[READY]" if rf == 0 and rs == 0 else ("[IN_DEV]" if rf == 0 else "[FAIL]")
            print(f"   {r_tag:<9} {req:<36} : {rp}/{rtot} passed ({rs} pending milestone)")

    print("-" * 76)
    print(f" SUMMARY: Total: {total_tests} | Passed: {total_passed} | Pending: {total_skipped} | Failed: {total_failed}")

    if total_failed > 0:
        print("\n [!] TEST FAILURES DETECTED:")
        for t in tiers_to_run:
            for detail in tier_results[t]["failure_details"]:
                print(f"   - {detail}")
        print("=" * 76)
        print(" OVERALL VERDICT: RED (Implementation defect or regression detected)")
        print("=" * 76)
        return 1
    elif total_skipped > 0:
        print("=" * 76)
        print(" OVERALL VERDICT: PROGRESSIVE SIGNAL GREEN")
        print(" All active features pass cleanly. Pending tests reflect planned milestones.")
        print("=" * 76)
        return 0
    else:
        print("=" * 76)
        print(" OVERALL VERDICT: COMPLETE (100% TIERS GREEN)")
        print("=" * 76)
        return 0


if __name__ == "__main__":
    sys.exit(main())
