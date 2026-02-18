#!/usr/bin/env python3
"""
Targeted BAR0 MMIO Fuzzer for Qualcomm WCN785x (FastConnect 7800)

Discovers all active BAR0 registers at runtime, classifies them into
functional clusters, and fuzzes each with multiple test patterns while
monitoring device health between rounds.

Usage:
    sudo python3 bar0_fuzz.py [options]

Options:
    --recon-only        Discover active offsets and exit (no writes)
    --skip-recon        Skip discovery, use hardcoded known offsets only
    --cluster NAME      Fuzz only one cluster: hal, wfss, ce, or unknown
    --range START-END   Fuzz a custom hex range (e.g., 0x8000-0x8800)
    --no-health-check   Skip health checks between rounds (faster)
    --dry-run           Show what would be fuzzed without writing
"""

import argparse
import os
import sys
import time

import pci_lib

# Fuzz patterns -- each is (name, value)
FUZZ_PATTERNS = [
    ("all-zeros",      0x00000000),
    ("all-ones",       0xFFFFFFFF),
    ("alt-AA",         0xAAAAAAAA),
    ("alt-55",         0x55555555),
    ("deadbeef",       0xDEADBEEF),
    ("walking-1-b0",   0x00000001),
    ("walking-1-b8",   0x00000100),
    ("walking-1-b16",  0x00010000),
    ("walking-1-b24",  0x01000000),
    ("walking-1-b31",  0x80000000),
    ("high-half",      0xFFFF0000),
    ("low-half",       0x0000FFFF),
]


# ---------------------------------------------------------------------------
# Recon: discover all active BAR0 offsets
# ---------------------------------------------------------------------------
def discover_active_offsets(logger, scan_range=None):
    """Scan BAR0 and return sorted list of offsets with non-zero, non-FF values."""
    logger.log("=== BAR0 Recon Sweep ===")
    fd, mm = pci_lib.open_bar_raw(readonly=True)

    start = scan_range[0] if scan_range else 0
    end = scan_range[1] if scan_range else pci_lib.BAR_SIZE

    active = []
    for off in range(start, end, 4):
        val = pci_lib.read32(mm, off)
        if val != 0x00000000 and val != 0xFFFFFFFF:
            active.append((off, val))

    mm.close()
    os.close(fd)

    logger.log(f"Scanned 0x{start:06x}-0x{end:06x}: found {len(active)} active offsets")
    return active


def print_recon_summary(active, logger):
    """Print a summary of discovered active offsets grouped by cluster."""
    by_cluster = {}
    for off, val in active:
        c = pci_lib.classify_offset(off)
        by_cluster.setdefault(c, []).append((off, val))

    logger.log("")
    logger.log(f"Total active offsets: {len(active)}")
    logger.log("")
    for name in list(pci_lib.CLUSTERS.keys()) + ["unknown"]:
        if name not in by_cluster:
            continue
        offsets = by_cluster[name]
        desc = pci_lib.CLUSTERS[name][2] if name in pci_lib.CLUSTERS else "Unclassified region"
        logger.log(f"--- {name}: {desc} ({len(offsets)} offsets) ---")
        for off, val in offsets:
            logger.log(f"  0x{off:06x} = 0x{val:08x}")
        logger.log("")


# ---------------------------------------------------------------------------
# Health check wrapper (logs through Logger)
# ---------------------------------------------------------------------------
def health_check(logger, label=""):
    """Run a full health check with logging. Returns True if healthy."""
    logger.log(f"--- Health Check {label} ---")
    healthy = pci_lib.check_device_health(logger)
    logger.log("")
    return healthy


# ---------------------------------------------------------------------------
# Fuzz engine
# ---------------------------------------------------------------------------
def fuzz_offset(mm, offset, original, patterns, logger, dry_run=False):
    """
    Fuzz a single offset with all patterns.
    Saves original, writes each pattern, reads back, restores original.
    Returns list of (pattern_name, written, readback) for interesting results.
    """
    results = []
    for pname, pval in patterns:
        if dry_run:
            logger.log(f"  [DRY] 0x{offset:06x}: would write 0x{pval:08x} ({pname})")
            continue

        # Write pattern
        pci_lib.write32(mm, offset, pval)
        # Read back
        readback = pci_lib.read32(mm, offset)
        # Restore original
        pci_lib.write32(mm, offset, original)

        # Log if readback differs from what we wrote (interesting)
        if readback != pval:
            logger.log(
                f"  0x{offset:06x}: {pname} wrote=0x{pval:08x} "
                f"read=0x{readback:08x} (orig=0x{original:08x}) MASKED"
            )
        else:
            logger.log(
                f"  0x{offset:06x}: {pname} wrote=0x{pval:08x} "
                f"read=0x{readback:08x} (orig=0x{original:08x}) STICKY"
            )
        results.append((pname, pval, readback))

    # Verify restoration
    if not dry_run:
        verify = pci_lib.read32(mm, offset)
        if verify != original:
            logger.log(
                f"  *** RESTORE FAILED 0x{offset:06x}: expected 0x{original:08x} "
                f"got 0x{verify:08x} ***"
            )

    return results


def fuzz_round(mm, targets, patterns, logger, round_num, dry_run=False):
    """
    Run one fuzz round over all target offsets.
    targets: list of (offset, original_value)
    Returns dict of offset -> results.
    """
    logger.log(f"=== Fuzz Round {round_num}: {len(targets)} offsets x {len(patterns)} patterns ===")
    all_results = {}

    for i, (off, orig) in enumerate(targets):
        logger.log(f"  [{i+1:4d}/{len(targets)}] Offset 0x{off:06x} (orig=0x{orig:08x})")
        results = fuzz_offset(mm, off, orig, patterns, logger, dry_run=dry_run)
        all_results[off] = results

        # Brief pause between offsets to let firmware react
        if not dry_run:
            time.sleep(0.05)

    return all_results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Targeted BAR0 MMIO Fuzzer for Qualcomm WCN785x"
    )
    parser.add_argument("--recon-only", action="store_true",
                        help="Discover active offsets and exit (no writes)")
    parser.add_argument("--skip-recon", action="store_true",
                        help="Skip discovery, use hardcoded known offsets only")
    parser.add_argument("--cluster", type=str, default=None,
                        choices=list(pci_lib.CLUSTERS.keys()) + ["unknown"],
                        help="Fuzz only the named cluster")
    parser.add_argument("--range", type=str, default=None,
                        help="Fuzz a hex range: START-END (e.g., 0x8000-0x8800)")
    parser.add_argument("--no-health-check", action="store_true",
                        help="Skip health checks between rounds")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be fuzzed without writing")
    parser.add_argument("--device", type=str, default=None,
                        help="Override device BDF (e.g., 0000:03:00.0)")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.device:
        pci_lib.set_device(args.device)

    logger = pci_lib.Logger(prefix="bar0_fuzz")

    # Pre-flight check
    if not pci_lib.device_present():
        logger.log(f"ERROR: Device {pci_lib.DEVICE_BDF} not found in sysfs")
        logger.close()
        sys.exit(1)

    if not os.path.exists(pci_lib.BAR0_RESOURCE):
        logger.log(f"ERROR: {pci_lib.BAR0_RESOURCE} does not exist")
        logger.close()
        sys.exit(1)

    # Baseline health
    baseline_errors, _ = pci_lib.get_dmesg_errors()
    logger.log(f"Baseline dmesg errors: {baseline_errors}")
    logger.log("")

    # -----------------------------------------------------------------------
    # Phase 1: Recon
    # -----------------------------------------------------------------------
    if args.skip_recon:
        logger.log("Skipping recon, using hardcoded known offsets")
        fd, mm = pci_lib.open_bar_raw(readonly=True)
        active = []
        for off in pci_lib.KNOWN_OFFSETS:
            val = pci_lib.read32(mm, off)
            active.append((off, val))
        mm.close()
        os.close(fd)
    else:
        scan_range = pci_lib.parse_hex_range(args.range) if args.range else None
        active = discover_active_offsets(logger, scan_range=scan_range)

    print_recon_summary(active, logger)

    if args.recon_only:
        logger.log("Recon-only mode. Exiting.")
        logger.log(f"Log saved: {logger.path}")
        logger.close()
        sys.exit(0)

    # -----------------------------------------------------------------------
    # Phase 2: Filter targets
    # -----------------------------------------------------------------------
    if args.cluster:
        targets = [(off, val) for off, val in active
                   if pci_lib.classify_offset(off) == args.cluster]
        logger.log(f"Filtered to cluster '{args.cluster}': {len(targets)} offsets")
    elif args.range:
        lo, hi = pci_lib.parse_hex_range(args.range)
        targets = [(off, val) for off, val in active if lo <= off < hi]
        logger.log(f"Filtered to range 0x{lo:06x}-0x{hi:06x}: {len(targets)} offsets")
    else:
        targets = active

    if not targets:
        logger.log("No targets to fuzz. Exiting.")
        logger.close()
        sys.exit(0)

    # -----------------------------------------------------------------------
    # Phase 3: Fuzz
    # -----------------------------------------------------------------------
    logger.log(f"\nStarting fuzz: {len(targets)} offsets x {len(FUZZ_PATTERNS)} patterns")
    logger.log(f"Dry run: {args.dry_run}")
    logger.log("")

    if not args.no_health_check:
        health_check(logger, label="pre-fuzz")

    # Open BAR0 for read-write
    if not args.dry_run:
        fd, mm = pci_lib.open_bar_raw(readonly=False)
    else:
        fd, mm = pci_lib.open_bar_raw(readonly=True)

    # Group targets by cluster and fuzz each cluster as a round
    by_cluster = {}
    for off, val in targets:
        c = pci_lib.classify_offset(off)
        by_cluster.setdefault(c, []).append((off, val))

    round_num = 0
    total_findings = {}

    for cluster_name in list(pci_lib.CLUSTERS.keys()) + ["unknown"]:
        if cluster_name not in by_cluster:
            continue

        cluster_targets = by_cluster[cluster_name]
        round_num += 1
        desc = pci_lib.CLUSTERS[cluster_name][2] if cluster_name in pci_lib.CLUSTERS else "Unclassified"
        logger.log(f"\n{'='*60}")
        logger.log(f"CLUSTER: {cluster_name} -- {desc}")
        logger.log(f"{'='*60}")

        results = fuzz_round(
            mm, cluster_targets, FUZZ_PATTERNS, logger,
            round_num=round_num, dry_run=args.dry_run
        )
        total_findings.update(results)

        # Health check between clusters
        if not args.no_health_check and not args.dry_run:
            new_count, new_lines = pci_lib.get_dmesg_errors()
            if new_count > baseline_errors:
                logger.log(f"\n*** NEW ERRORS after {cluster_name} ({new_count - baseline_errors} new) ***")
                for line in new_lines[baseline_errors:]:
                    logger.log(f"  {line}")
                logger.log("")

            ok = health_check(logger, label=f"after {cluster_name}")
            if not ok:
                logger.log("*** DEVICE UNHEALTHY -- stopping fuzz ***")
                break

    mm.close()
    os.close(fd)

    # -----------------------------------------------------------------------
    # Phase 4: Summary
    # -----------------------------------------------------------------------
    logger.log(f"\n{'='*60}")
    logger.log("SUMMARY")
    logger.log(f"{'='*60}")
    logger.log(f"Offsets fuzzed: {len(total_findings)}")
    logger.log(f"Patterns per offset: {len(FUZZ_PATTERNS)}")

    sticky_offsets = []
    masked_offsets = []
    for off, results in sorted(total_findings.items()):
        sticky = [r for r in results if r[1] == r[2]]
        if sticky:
            sticky_offsets.append((off, sticky))
        masked = [r for r in results if r[1] != r[2]]
        if masked:
            masked_offsets.append((off, masked))

    logger.log(f"Offsets accepting writes (sticky): {len(sticky_offsets)}")
    logger.log(f"Offsets with hardware masking: {len(masked_offsets)}")

    if sticky_offsets:
        logger.log("\nSTICKY registers (writes accepted as-is):")
        for off, results in sticky_offsets:
            patterns_str = ", ".join(r[0] for r in results)
            logger.log(f"  0x{off:06x}: {patterns_str}")

    final_count, final_lines = pci_lib.get_dmesg_errors()
    new_errors = final_count - baseline_errors
    logger.log(f"\nNew dmesg errors during fuzz: {new_errors}")
    if new_errors > 0:
        logger.log("New error lines:")
        for line in final_lines[baseline_errors:]:
            logger.log(f"  {line}")

    logger.log(f"\nLog saved: {logger.path}")
    logger.close()


if __name__ == "__main__":
    main()
