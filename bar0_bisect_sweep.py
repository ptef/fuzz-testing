#!/usr/bin/env python3
"""
BAR0 Bisect Sweep — find exact MMIO offsets that crash the firmware.

Three-phase algorithm:
  Phase 1 (Coarse): Divide BAR0 into chunks, read every DWORD, detect crashes.
  Phase 2 (Bisect): Recursively split crashed chunks to isolate offsets.
  Phase 3 (Verify): Re-test each candidate in isolation to eliminate false positives.

Between crashes the script waits for MHI auto-recovery, falls back to a
modprobe cycle, and aborts after --max-retries consecutive failures.

State is persisted to JSON after each step so work can be resumed with --resume.

Usage:
    sudo python3 bar0_bisect_sweep.py
    sudo python3 bar0_bisect_sweep.py --range 0x0000-0x40000 --chunk-size 0x4000
    sudo python3 bar0_bisect_sweep.py --resume bisect_state_2026-02-18_14-30-00.json
"""

import argparse
import json
import os
import sys
import time

import pci_lib


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------
def new_state(start, end, chunk_size):
    """Create a fresh state dict."""
    return {
        "start": start,
        "end": end,
        "chunk_size": chunk_size,
        "phase": "coarse",
        "coarse_clean": [],
        "coarse_crashed": [],
        "bisect_queue": [],
        "bisect_crashed": [],
        "candidates": [],
        "verified": [],
        "false_positives": [],
        "recovery_failures": 0,
    }


def save_state(state, path):
    """Persist state to JSON."""
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def load_state(path):
    """Load state from JSON."""
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Scanning helpers
# ---------------------------------------------------------------------------
def scan_range(start, end, post_delay, verbose):
    """Read every DWORD in [start, end), then poll dmesg for crashes.

    Returns True if a crash was detected, False if clean.
    """
    baseline_count, _ = pci_lib.get_dmesg_errors()

    if verbose:
        print(f"  Scanning 0x{start:06x}-0x{end:06x} "
              f"({(end - start) // 4} DWORDs)...", flush=True)

    try:
        with pci_lib.open_bar(readonly=True) as mm:
            for off in range(start, end, 4):
                pci_lib.read32(mm, off)
    except Exception as e:
        print(f"  Exception during scan: {e}")
        return True

    # Poll dmesg for post_delay seconds
    elapsed = 0.0
    poll_interval = 0.5
    while elapsed < post_delay:
        time.sleep(poll_interval)
        elapsed += poll_interval
        count, lines = pci_lib.get_dmesg_errors()
        if count > baseline_count:
            if verbose:
                for line in lines[baseline_count:]:
                    print(f"    {line}")
            return True

    return False


def recover(timeout, verbose):
    """Attempt device recovery. Returns True on success."""
    if verbose:
        print("  Recovering device...", flush=True)
    ok = pci_lib.wait_for_recovery(timeout=timeout)
    if ok:
        # Clear dmesg so next baseline is clean
        import subprocess
        subprocess.run(["dmesg", "-C"], capture_output=True)
        if verbose:
            print("  Recovery successful, dmesg cleared.")
    else:
        if verbose:
            print("  *** Recovery FAILED ***")
    return ok


# ---------------------------------------------------------------------------
# Phase 1: Coarse scan
# ---------------------------------------------------------------------------
def phase_coarse(state, args):
    """Divide BAR into chunks and classify each as clean or crashed."""
    start = state["start"]
    end = state["end"]
    chunk_size = state["chunk_size"]

    # Build chunk list, skipping already-completed ones
    done_starts = set(c[0] for c in state["coarse_clean"]) | set(c[0] for c in state["coarse_crashed"])
    chunks = []
    off = start
    while off < end:
        chunk_end = min(off + chunk_size, end)
        if off not in done_starts:
            chunks.append((off, chunk_end))
        off = chunk_end

    total = len(chunks) + len(done_starts)
    done = len(done_starts)
    print(f"\n=== Phase 1: Coarse Scan ({total} chunks of 0x{chunk_size:x}) ===")
    print(f"  Already done: {done}, remaining: {len(chunks)}\n")

    for i, (cs, ce) in enumerate(chunks):
        print(f"  [{done + i + 1}/{total}] Chunk 0x{cs:06x}-0x{ce:06x}", flush=True)

        crashed = scan_range(cs, ce, args.post_delay, args.verbose)

        if crashed:
            print(f"    *** CRASH in 0x{cs:06x}-0x{ce:06x} ***")
            state["coarse_crashed"].append([cs, ce])
            save_state(state, args.state_file)

            if not recover(args.recovery_timeout, args.verbose):
                state["recovery_failures"] += 1
                if state["recovery_failures"] >= args.max_retries:
                    print(f"\n  Aborting: {args.max_retries} consecutive recovery failures.")
                    save_state(state, args.state_file)
                    return False
            else:
                state["recovery_failures"] = 0
        else:
            print(f"    Clean")
            state["coarse_clean"].append([cs, ce])
            save_state(state, args.state_file)

    state["phase"] = "bisect"
    # Seed bisect queue from coarse crashed chunks
    state["bisect_queue"] = list(state["coarse_crashed"])
    save_state(state, args.state_file)
    return True


# ---------------------------------------------------------------------------
# Phase 2: Bisect
# ---------------------------------------------------------------------------
def phase_bisect(state, args):
    """Recursively split crashed ranges until individual offsets are found."""
    print(f"\n=== Phase 2: Bisect ({len(state['bisect_queue'])} ranges) ===\n")

    while state["bisect_queue"]:
        cs, ce = state["bisect_queue"].pop(0)
        size = ce - cs

        # Base case: single DWORD
        if size <= 4:
            print(f"  Candidate: 0x{cs:06x}")
            state["candidates"].append(cs)
            save_state(state, args.state_file)
            continue

        # Split in half
        mid = cs + (size // 2)
        # Align to 4 bytes
        mid = mid & ~3

        halves = [(cs, mid), (mid, ce)]
        for hs, he in halves:
            if hs >= he:
                continue

            print(f"  Testing 0x{hs:06x}-0x{he:06x} ({(he - hs) // 4} DWORDs)...",
                  end="", flush=True)

            crashed = scan_range(hs, he, args.post_delay, args.verbose)

            if crashed:
                print(f" CRASH")
                state["bisect_crashed"].append([hs, he])
                state["bisect_queue"].append([hs, he])
                save_state(state, args.state_file)

                if not recover(args.recovery_timeout, args.verbose):
                    state["recovery_failures"] += 1
                    if state["recovery_failures"] >= args.max_retries:
                        print(f"\n  Aborting: {args.max_retries} consecutive recovery failures.")
                        save_state(state, args.state_file)
                        return False
                else:
                    state["recovery_failures"] = 0
            else:
                print(f" clean")

    state["phase"] = "verify"
    save_state(state, args.state_file)
    return True


# ---------------------------------------------------------------------------
# Phase 3: Verify
# ---------------------------------------------------------------------------
def phase_verify(state, args):
    """Re-test each candidate offset in isolation."""
    candidates = state["candidates"]
    if not candidates:
        print("\n=== Phase 3: Verify — no candidates to verify ===")
        state["phase"] = "done"
        save_state(state, args.state_file)
        return True

    # Skip already-verified offsets
    done = set(state["verified"]) | set(state["false_positives"])
    remaining = [c for c in candidates if c not in done]

    print(f"\n=== Phase 3: Verify ({len(remaining)} candidates) ===\n")

    if args.skip_verify:
        print("  --skip-verify: treating all candidates as verified")
        state["verified"] = list(candidates)
        state["phase"] = "done"
        save_state(state, args.state_file)
        return True

    for off in remaining:
        print(f"  Verifying 0x{off:06x}...", end="", flush=True)

        crashed = scan_range(off, off + 4, args.post_delay, args.verbose)

        if crashed:
            print(f" CONFIRMED")
            state["verified"].append(off)
            save_state(state, args.state_file)

            if not recover(args.recovery_timeout, args.verbose):
                state["recovery_failures"] += 1
                if state["recovery_failures"] >= args.max_retries:
                    print(f"\n  Aborting: {args.max_retries} consecutive recovery failures.")
                    save_state(state, args.state_file)
                    return False
            else:
                state["recovery_failures"] = 0
        else:
            print(f" false positive")
            state["false_positives"].append(off)
            save_state(state, args.state_file)

    state["phase"] = "done"
    save_state(state, args.state_file)
    return True


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def print_summary(state):
    """Print final results."""
    print(f"\n{'=' * 60}")
    print("BISECT SWEEP RESULTS")
    print(f"{'=' * 60}")
    print(f"  Range:            0x{state['start']:06x}-0x{state['end']:06x}")
    print(f"  Chunk size:       0x{state['chunk_size']:x}")
    print(f"  Coarse clean:     {len(state['coarse_clean'])} chunks")
    print(f"  Coarse crashed:   {len(state['coarse_crashed'])} chunks")
    print(f"  Candidates found: {len(state['candidates'])}")
    print(f"  Verified:         {len(state['verified'])}")
    print(f"  False positives:  {len(state['false_positives'])}")

    if state["verified"]:
        print(f"\nCRASH-TRIGGERING OFFSETS:")
        for off in sorted(state["verified"]):
            cluster = pci_lib.classify_offset(off)
            print(f"  0x{off:06x}  ({cluster})")

    if state["coarse_crashed"] and not state["verified"] and not state["candidates"]:
        print(f"\nCRASHED RANGES (not yet bisected):")
        for cs, ce in sorted(state["coarse_crashed"]):
            print(f"  0x{cs:06x}-0x{ce:06x}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="BAR0 bisect sweep — find crash-triggering MMIO offsets"
    )
    parser.add_argument("--range", type=str, default=None,
                        help="Hex range to scan (default: full BAR0)")
    parser.add_argument("--chunk-size", type=lambda x: int(x, 0), default=0x10000,
                        help="Coarse scan chunk size in bytes (default: 0x10000 = 64KB)")
    parser.add_argument("--post-delay", type=float, default=5.0,
                        help="Seconds to poll dmesg after each scan (default: 5.0)")
    parser.add_argument("--recovery-timeout", type=float, default=60.0,
                        help="Max seconds to wait for auto-recovery (default: 60)")
    parser.add_argument("--max-retries", type=int, default=5,
                        help="Abort after N consecutive recovery failures (default: 5)")
    parser.add_argument("--resume", type=str, default=None,
                        help="Resume from a saved state JSON file")
    parser.add_argument("--skip-verify", action="store_true",
                        help="Skip phase 3 verification")
    parser.add_argument("--device", type=str, default=None,
                        help="Override device BDF (e.g., 0000:03:00.0)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print detailed output")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.device:
        pci_lib.set_device(args.device)

    # State file name
    if args.resume:
        args.state_file = args.resume
    else:
        import datetime
        ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        args.state_file = f"bisect_state_{ts}.json"

    # Load or create state
    if args.resume:
        print(f"Resuming from {args.resume}")
        state = load_state(args.resume)
    else:
        if args.range:
            start, end = pci_lib.parse_hex_range(args.range)
        else:
            start, end = 0, pci_lib.BAR_SIZE
        state = new_state(start, end, args.chunk_size)

    # Pre-flight
    if not pci_lib.device_present():
        print(f"ERROR: Device {pci_lib.DEVICE_BDF} not found in sysfs")
        sys.exit(1)
    if not os.path.exists(pci_lib.BAR0_RESOURCE):
        print(f"ERROR: {pci_lib.BAR0_RESOURCE} does not exist")
        sys.exit(1)

    dev_id = pci_lib.read_device_id()
    if dev_id in ("ffffffff", "00000000", ""):
        print(f"ERROR: Device returns {dev_id!r} -- firmware is dead. Recover first.")
        sys.exit(1)

    print(f"Device: {pci_lib.DEVICE_BDF}  ID: {dev_id}")
    print(f"State file: {args.state_file}")

    # Run phases
    if state["phase"] == "coarse":
        if not phase_coarse(state, args):
            print_summary(state)
            sys.exit(1)

    if state["phase"] == "bisect":
        if not phase_bisect(state, args):
            print_summary(state)
            sys.exit(1)

    if state["phase"] == "verify":
        if not phase_verify(state, args):
            print_summary(state)
            sys.exit(1)

    print_summary(state)
    print(f"\nState saved: {args.state_file}")


if __name__ == "__main__":
    main()
