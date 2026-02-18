#!/usr/bin/env python3
"""
Shared utilities for PCI fuzz testing tools.

Provides constants, MMIO helpers, device monitoring, health checks,
recovery logic, and common utilities used across all scripts.
"""

import datetime
import mmap
import os
import struct
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Device constants (defaults for Qualcomm WCN785x / FastConnect 7800)
# ---------------------------------------------------------------------------
DEVICE_BDF = "0004:01:00.0"
BAR_SIZE = 2 * 1024 * 1024  # 2 MB
INSTANCE_STRIDE = 0x80000   # 4 HW instances at 512 KB apart

# Derived paths (updated by set_device())
DEVICE_SYSFS = f"/sys/bus/pci/devices/{DEVICE_BDF}"
BAR0_RESOURCE = f"{DEVICE_SYSFS}/resource0"

# ---------------------------------------------------------------------------
# Known active offsets from initial recon (first 50 of 130)
# ---------------------------------------------------------------------------
KNOWN_OFFSETS = [
    0x000000, 0x000060, 0x000068, 0x000070, 0x000078, 0x00008c,
    0x0000a4, 0x0000b8, 0x000110, 0x000124, 0x000148, 0x0001c4,
    0x000280, 0x00028c, 0x000294, 0x0002a0, 0x000364, 0x00036c,
    0x000398, 0x0003a0, 0x0003a8, 0x0003b0, 0x000700, 0x000708,
    0x000710, 0x000a38, 0x000a40, 0x000b14, 0x000b38, 0x000b90,
    0x003008, 0x0030d8, 0x0030e8, 0x0030fc, 0x00310c, 0x00313c,
    0x00316c, 0x008000, 0x008010, 0x008020, 0x008100, 0x008110,
    0x008118, 0x008200, 0x008248, 0x008290, 0x008300, 0x008600,
    0x008690, 0x008700,
]

# Cluster boundaries (based on ath12k driver source)
CLUSTERS = {
    "hal":      (0x000000, 0x001000, "HAL / Core registers"),
    "ce":       (0x001000, 0x002000, "Copy Engine (low range)"),
    "wfss":     (0x003000, 0x004000, "Wi-Fi Subsystem"),
    "ce_high":  (0x008000, 0x00C000, "Copy Engine (high range)"),
    "umac":     (0x01E000, 0x020000, "Upper MAC"),
    "pcie_soc": (0x030000, 0x040000, "PCIe SOC interface"),
}


def set_device(bdf):
    """Override the default device BDF and update all derived paths."""
    global DEVICE_BDF, DEVICE_SYSFS, BAR0_RESOURCE
    DEVICE_BDF = bdf
    DEVICE_SYSFS = f"/sys/bus/pci/devices/{DEVICE_BDF}"
    BAR0_RESOURCE = f"{DEVICE_SYSFS}/resource0"


# ---------------------------------------------------------------------------
# MMIO helpers
# ---------------------------------------------------------------------------
class open_bar:
    """Context manager for BAR0 MMIO access.

    Usage:
        with open_bar() as mm:
            val = read32(mm, 0x0)
    """

    def __init__(self, readonly=True):
        self.readonly = readonly
        self.fd = None
        self.mm = None

    def __enter__(self):
        flags = os.O_RDONLY | os.O_SYNC if self.readonly else os.O_RDWR | os.O_SYNC
        prot = mmap.PROT_READ if self.readonly else mmap.PROT_READ | mmap.PROT_WRITE
        self.fd = os.open(BAR0_RESOURCE, flags)
        self.mm = mmap.mmap(self.fd, BAR_SIZE, mmap.MAP_SHARED, prot)
        return self.mm

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.mm:
            self.mm.close()
        if self.fd is not None:
            os.close(self.fd)
        return False


def open_bar_raw(readonly=True):
    """Open BAR0 and return (fd, mm) — caller must close both.

    Provided for scripts that need to manage the lifetime manually.
    Prefer the open_bar() context manager when possible.
    """
    flags = os.O_RDONLY | os.O_SYNC if readonly else os.O_RDWR | os.O_SYNC
    prot = mmap.PROT_READ if readonly else mmap.PROT_READ | mmap.PROT_WRITE
    fd = os.open(BAR0_RESOURCE, flags)
    mm = mmap.mmap(fd, BAR_SIZE, mmap.MAP_SHARED, prot)
    return fd, mm


def read32(mm, offset):
    """Read a 32-bit little-endian value from BAR0 at *offset*."""
    mm.seek(offset)
    return struct.unpack('<I', mm.read(4))[0]


def write32(mm, offset, value):
    """Write a 32-bit little-endian value to BAR0 at *offset*."""
    mm.seek(offset)
    mm.write(struct.pack('<I', value & 0xFFFFFFFF))


# ---------------------------------------------------------------------------
# Monitoring — unified dmesg error detection
# ---------------------------------------------------------------------------
def get_dmesg_errors():
    """Return (count, lines) of AER + ath12k + firmware recovery events in dmesg.

    Unifies the three separate implementations that existed previously:
    - AER / PCIe errors (CmpltTO, UnsupReq, etc.)
    - ath12k driver errors (failed, error, warn, fault, timeout, reset)
    - Firmware crash / recovery events (MHI power-on, hardware restart, recovered)
    """
    result = subprocess.run(["dmesg"], capture_output=True, text=True)
    lines = []
    for line in result.stdout.splitlines():
        low = line.lower()
        # AER / PCIe errors
        if ("ath12k" in line or "AER" in line or "pcieport" in line) and (
            "error" in low or "fail" in low or
            "CmpltTO" in line or "UnsupReq" in line or
            "timeout" in low or "warn" in low or
            "fault" in low or "reset" in low
        ):
            lines.append(line)
        # Firmware crash / recovery events
        elif ("Hardware restart was requested" in line or
              "successfully recovered" in line or
              "mhi mhi0: Requested to power ON" in line):
            lines.append(line)
    return len(lines), lines


# ---------------------------------------------------------------------------
# Health checks
# ---------------------------------------------------------------------------
def device_present():
    """Check if the PCI device is still visible in sysfs."""
    return os.path.exists(DEVICE_SYSFS)


def driver_bound():
    """Check if the ath12k driver is still bound to the device."""
    return os.path.exists(os.path.join(DEVICE_SYSFS, "driver"))


def read_link_status():
    """Read PCIe Link Status register (config offset 0x82)."""
    try:
        result = subprocess.run(
            ["setpci", "-s", DEVICE_BDF, "82.W"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip()
    except Exception:
        return "UNREADABLE"


def read_device_id():
    """Read PCI Device/Vendor ID (config offset 0x00)."""
    try:
        result = subprocess.run(
            ["setpci", "-s", DEVICE_BDF, "0.L"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip()
    except Exception:
        return ""


def check_device_health(logger=None):
    """Run a full health check. Returns True if device looks healthy.

    If *logger* is provided, detailed status is logged. Otherwise
    checks are silent (useful for automated scripts).
    """
    healthy = True

    present = device_present()
    if logger:
        logger.log(f"  Device: {'PRESENT' if present else '*** MISSING ***'}")
    if not present:
        healthy = False

    bound = driver_bound()
    if logger:
        logger.log(f"  Driver: {'BOUND' if bound else '*** UNBOUND ***'}")

    lnk = read_link_status()
    if logger:
        logger.log(f"  LnkSta: {lnk}")
    if lnk in ("UNREADABLE", "ffff", "0000", ""):
        if logger:
            logger.log("  Link:   *** DEGRADED OR DOWN ***")
        healthy = False

    count, _lines = get_dmesg_errors()
    if logger:
        logger.log(f"  dmesg errors: {count}")
        logger.log(f"  Healthy: {healthy}")

    return healthy


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------
def wait_for_recovery(timeout=60, poll_interval=2.0):
    """Wait for the device to recover after a crash.

    First watches dmesg for "successfully recovered" up to *timeout* seconds.
    If that doesn't appear, falls back to a modprobe -r / modprobe cycle.

    Returns True if device is healthy afterwards, False otherwise.
    """
    print(f"Waiting up to {timeout}s for auto-recovery...", flush=True)
    baseline_count, _ = get_dmesg_errors()
    elapsed = 0.0
    while elapsed < timeout:
        time.sleep(poll_interval)
        elapsed += poll_interval
        count, lines = get_dmesg_errors()
        for line in lines[baseline_count:]:
            if "successfully recovered" in line:
                print(f"  Auto-recovery detected after {elapsed:.1f}s")
                time.sleep(2)  # let driver settle
                if check_device_health():
                    return True

    # Fallback: modprobe cycle
    print("  Auto-recovery not seen, trying modprobe cycle...", flush=True)
    subprocess.run(["modprobe", "-r", "ath12k_pci"],
                   capture_output=True, timeout=30)
    time.sleep(2)
    subprocess.run(["modprobe", "ath12k_pci"],
                   capture_output=True, timeout=30)
    time.sleep(5)
    return check_device_health()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------
def parse_hex_range(range_str):
    """Parse 'START-END' hex range string into (start, end) tuple.

    Accepts formats like '0x8000-0x8800' or '8000-8800'.
    """
    parts = range_str.split("-", 1)
    if len(parts) != 2:
        print(f"Error: invalid range format '{range_str}', expected START-END")
        sys.exit(1)
    return int(parts[0], 16), int(parts[1], 16)


def classify_offset(offset):
    """Return cluster name for a given BAR0 offset."""
    for name, (lo, hi, _desc) in CLUSTERS.items():
        if lo <= offset < hi:
            return name
    return "unknown"


class Logger:
    """Simple file + stdout logger with timestamps."""

    def __init__(self, prefix="bar0_fuzz", logdir="."):
        ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.path = os.path.join(logdir, f"{prefix}_{ts}.log")
        self.fh = open(self.path, "w")
        self.log(f"{prefix} -- {ts}")
        self.log(f"Device: {DEVICE_BDF}")
        self.log("")

    def log(self, msg):
        line = f"{datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]}  {msg}"
        print(line)
        self.fh.write(line + "\n")
        self.fh.flush()

    def close(self):
        self.fh.close()
