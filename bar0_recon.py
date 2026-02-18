#!/usr/bin/env python3
"""
Dump all active BAR0 regions with dmesg error detection.

Scans BAR0 MMIO space, reports active registers, and monitors dmesg for
errors (CmpltTO, UnsupReq, etc.) to identify which offset triggers faults.

Usage:
    sudo python3 bar0_recon.py
    sudo python3 bar0_recon.py --range 0x0000-0x2000
    sudo python3 bar0_recon.py --range 0x0000-0x1000 --check-every 1 --verbose
"""

import argparse
import os
import sys
import time

import pci_lib


def main():
    parser = argparse.ArgumentParser(
        description="Dump active BAR0 regions with error detection"
    )
    parser.add_argument("--range", type=str, default=None,
                        help="Hex range to scan (e.g., 0x0000-0x2000)")
    parser.add_argument("--step", type=int, default=4,
                        help="Read stride in bytes (default: 4)")
    parser.add_argument("--check-every", type=int, default=1024,
                        help="Check dmesg every N reads (default: 1024 ~4KB)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print every offset as it's read")
    parser.add_argument("--post-delay", type=float, default=5.0,
                        help="Seconds to wait after scan for delayed crashes "
                             "(default: 5.0)")
    parser.add_argument("--gap", type=lambda x: int(x, 0), default=0x100,
                        help="Gap threshold for region grouping (default: 0x100)")
    parser.add_argument("--device", type=str, default=None,
                        help="Override device BDF (e.g., 0000:03:00.0)")
    args = parser.parse_args()

    if args.device:
        pci_lib.set_device(args.device)

    if args.range:
        start, end = pci_lib.parse_hex_range(args.range)
    else:
        start, end = 0, pci_lib.BAR_SIZE

    step = args.step
    check_every = args.check_every

    # Pre-flight
    if not os.path.exists(pci_lib.BAR0_RESOURCE):
        print(f"ERROR: {pci_lib.BAR0_RESOURCE} not found")
        sys.exit(1)

    # Health check: read device ID to verify firmware is alive
    dev_id = pci_lib.read_device_id()
    if dev_id in ("ffffffff", "00000000", ""):
        print(f"ERROR: Device returns {dev_id!r} -- firmware is dead.")
        print("Recover first:")
        print("  sudo modprobe -r ath12k_pci && sudo modprobe ath12k_pci")
        print("  sudo dmesg -C")
        sys.exit(1)
    print(f"Device ID: {dev_id}  (OK)")

    # Check link status
    lnk = pci_lib.read_link_status()
    print(f"Link status: {lnk}", end="")
    if lnk in ("ffff", "0000", "UNREADABLE", ""):
        print("  *** LINK DOWN -- device may be crashed ***")
    else:
        print("  (OK)")

    # Baseline dmesg
    baseline_count, _ = pci_lib.get_dmesg_errors()
    print(f"Baseline dmesg errors: {baseline_count}")
    if baseline_count > 0:
        print("  TIP: Run 'sudo dmesg -C' to clear old errors for a clean baseline")
    print(f"Scanning 0x{start:06x}-0x{end:06x}  step={step}  "
          f"check_every={check_every}")
    print()

    fd, mm = pci_lib.open_bar_raw(readonly=True)

    regions = {}
    current_region = None
    last_active = None
    read_count = 0
    chunk_start_offset = start
    error_events = []
    total_reads = (end - start) // step
    last_off = start

    try:
        for off in range(start, end, step):
            last_off = off

            # Progress display
            if args.verbose:
                print(f"  0x{off:06x} ... ", end="", flush=True)
            elif read_count % 256 == 0:
                pct = (read_count / total_reads * 100) if total_reads else 0
                print(f"\r  Scanning 0x{off:06x} / 0x{end:06x}  "
                      f"({pct:5.1f}%)  ", end="", flush=True)

            val = pci_lib.read32(mm, off)

            if args.verbose:
                print(f"0x{val:08x}")

            if val != 0x00000000 and val != 0xFFFFFFFF:
                if (current_region is None
                        or (off - last_active) > args.gap):
                    current_region = off
                    regions[current_region] = []
                regions[current_region].append((off, val))
                last_active = off

            read_count += 1

            # Periodic dmesg check
            if read_count % check_every == 0:
                new_count, new_lines = pci_lib.get_dmesg_errors()
                if new_count > baseline_count:
                    n_new = new_count - baseline_count
                    print(f"\n\n*** NEW ERROR(S) after reading "
                          f"0x{chunk_start_offset:06x}-0x{off:06x} ***")
                    print(f"    {n_new} new error line(s):")
                    for line in new_lines[baseline_count:]:
                        print(f"    {line}")
                    error_events.append((chunk_start_offset, off))
                    baseline_count = new_count
                    print()
                chunk_start_offset = off + step

    except KeyboardInterrupt:
        print(f"\n\nInterrupted at 0x{last_off:06x}")
    except Exception as e:
        print(f"\n\nException at 0x{last_off:06x}: {e}")
    finally:
        mm.close()
        os.close(fd)

    # Immediate final dmesg check (catches synchronous errors)
    final_count, final_lines = pci_lib.get_dmesg_errors()
    if final_count > baseline_count:
        n_new = final_count - baseline_count
        print(f"\n*** LATE ERROR in final chunk "
              f"0x{chunk_start_offset:06x}-0x{last_off:06x} ***")
        print(f"    {n_new} new error line(s):")
        for line in final_lines[baseline_count:]:
            print(f"    {line}")
        error_events.append((chunk_start_offset, last_off))
        baseline_count = final_count

    # Delayed check for async firmware crashes / recoveries
    if args.post_delay > 0:
        print(f"\nWaiting {args.post_delay:.1f}s for delayed firmware "
              f"crashes...", end="", flush=True)
        poll_interval = 0.5
        elapsed = 0.0
        while elapsed < args.post_delay:
            time.sleep(poll_interval)
            elapsed += poll_interval
            delayed_count, delayed_lines = pci_lib.get_dmesg_errors()
            if delayed_count > baseline_count:
                n_new = delayed_count - baseline_count
                print(f"\n\n*** DELAYED CRASH detected {elapsed:.1f}s after "
                      f"scan completed ***")
                print(f"    Scan range was "
                      f"0x{start:06x}-0x{last_off + step:06x}")
                print(f"    {n_new} new dmesg line(s):")
                for line in delayed_lines[baseline_count:]:
                    print(f"    {line}")
                error_events.append((start, last_off))
                baseline_count = delayed_count
                # Keep polling for the full duration to catch recovery too
        print(" done.")

    # Results
    total_dwords = sum(len(r) for r in regions.values())
    print(f"\n\nFound {len(regions)} active regions "
          f"({total_dwords} total active DWORDs)\n")

    for region_start, regs in sorted(regions.items()):
        region_end = regs[-1][0]
        print(f"--- Region 0x{region_start:06x}-0x{region_end:06x} "
              f"({len(regs)} DWORDs) ---")
        for roff, rval in regs:
            print(f"  0x{roff:06x}: 0x{rval:08x}")
        print()

    # Error summary
    if error_events:
        print(f"{'=' * 60}")
        print(f"ERROR SUMMARY: {len(error_events)} error event(s) detected")
        print(f"{'=' * 60}")
        for i, (es, ee) in enumerate(error_events):
            print(f"  Event {i+1}: triggered in range "
                  f"0x{es:06x}-0x{ee:06x}")
        es, ee = error_events[0]
        print(f"\nTo bisect the exact offset, re-run with:")
        print(f"  sudo python3 bar0_recon.py "
              f"--range 0x{es:06x}-0x{ee + step:06x} "
              f"--check-every 1 --verbose")
    else:
        print("No new dmesg errors detected during scan.")


if __name__ == "__main__":
    main()
