# PCI Fuzz Testing Tools

A collection of Python tools for fuzz testing PCIe configuration space and BAR0 MMIO registers on the Qualcomm WCN785x Wi-Fi 7 chip (FastConnect 7800, driver `ath12k_pci`).

## Prerequisites

- Linux system with `setpci` installed (part of `pciutils`)
- `devmem2` or equivalent for MMIO access (scripts use direct mmap of sysfs `resource0`)
- `sudo` access (required for PCI config space and MMIO operations)
- Python 3.8+

## Project Structure

```
.
├── pci_lib.py                         # Shared library: constants, MMIO, health checks, recovery
├── bar0_recon.py                      # BAR0 recon scanner with dmesg error detection
├── bar0_fuzz.py                       # BAR0 MMIO write fuzzer (targeted, per-cluster)
├── bar0_bisect_sweep.py               # Automated bisect to find crash-triggering BAR0 offsets
├── config_read.py                     # Read PCI config space registers
├── config_fuzz.py                     # Exhaustive/random PCI config space write fuzzer
├── pattern_scripts/
│   ├── reg_write_pattern.py           # Replay a saved pattern file to config space
│   └── pattern_file                   # Example pattern file
├── BACKLOG.md                         # Prioritized future work items
├── FINDINGS.md                        # Full analysis writeup
├── PCI_FUZZ_GUIDE.md                  # Comprehensive fuzzing guide
├── pci_baseline_0x000_0x200.txt       # Config space baseline (0x000-0x200)
├── pci_baseline_0x200_0xFFF.txt       # Config space baseline (0x200-0xFFF)
└── sample-vm-snippet.xml              # Sample libvirt VM XML for PCI passthrough
```

## Shared Library — `pci_lib.py`

All scripts import from `pci_lib.py`, which provides:

- **Constants:** `DEVICE_BDF`, `BAR_SIZE`, `KNOWN_OFFSETS`, `CLUSTERS`, `INSTANCE_STRIDE`
- **Device override:** `set_device(bdf)` — change target device at runtime
- **MMIO:** `read32()`, `write32()`, `open_bar()` context manager, `open_bar_raw()`
- **Monitoring:** `get_dmesg_errors()` — unified AER + ath12k + firmware recovery detection
- **Health:** `device_present()`, `driver_bound()`, `read_link_status()`, `read_device_id()`, `check_device_health()`
- **Recovery:** `wait_for_recovery()` — auto-recovery polling + modprobe fallback
- **Utilities:** `parse_hex_range()`, `classify_offset()`, `Logger`

## BAR0 Tools

### `bar0_recon.py` — BAR0 Recon Scanner

Scans BAR0 MMIO space, reports active registers, and monitors dmesg for errors (CmpltTO, UnsupReq, etc.) to identify which offsets trigger faults.

```bash
sudo python3 bar0_recon.py
sudo python3 bar0_recon.py --range 0x0000-0x2000
sudo python3 bar0_recon.py --range 0x0000-0x1000 --check-every 1 --verbose
```

### `bar0_fuzz.py` — BAR0 MMIO Write Fuzzer

Discovers active BAR0 registers at runtime, classifies them into functional clusters (HAL, CE, WFSS, etc.), and fuzzes each with 12 test patterns while monitoring device health.

```bash
sudo python3 bar0_fuzz.py                          # Full recon + fuzz
sudo python3 bar0_fuzz.py --recon-only              # Discovery only
sudo python3 bar0_fuzz.py --cluster ce_high         # Fuzz only CE registers
sudo python3 bar0_fuzz.py --range 0x8000-0x8800     # Fuzz a specific range
sudo python3 bar0_fuzz.py --dry-run                 # Preview without writes
```

### `bar0_bisect_sweep.py` — Automated Crash Bisect

Finds the exact BAR0 offset(s) that trigger firmware crashes (CmpltTO). Three-phase algorithm: coarse scan → recursive bisect → single-offset verification. Supports resume from saved state.

```bash
sudo python3 bar0_bisect_sweep.py                                  # Full BAR0
sudo python3 bar0_bisect_sweep.py --range 0x0-0x40000 --chunk-size 0x4000
sudo python3 bar0_bisect_sweep.py --resume bisect_state_*.json     # Resume
sudo python3 bar0_bisect_sweep.py --verbose                        # Detailed output
```

## Config Space Tools

### `config_read.py` — Read PCI Configuration Space

Reads the first 64 DWORD registers from a device's PCI configuration space.

```bash
python3 config_read.py                    # Default device
python3 config_read.py -d=0000:03:00.0    # Specific device
```

### `config_fuzz.py` — Config Space Write Fuzzer

Exhaustive config space fuzzer. In serial mode, writes all 256 byte values to each register. In random mode, runs indefinitely tracking tested combinations.

```bash
sudo python3 config_fuzz.py -d=0004:01:00.0 -r=basic -n=new -o=serial
sudo python3 config_fuzz.py -d=0004:01:00.0 -r=full -n=new -o=random
sudo python3 config_fuzz.py -h    # Show all options
```

### `pattern_scripts/reg_write_pattern.py` — Pattern Replay

Replays register+value pairs from a pattern file back to the device.

```bash
sudo python3 pattern_scripts/reg_write_pattern.py 0004:01:00.0
```

## Quick Start

```bash
# 1. Verify the device is present
lspci -s 0004:01:00.0 -vv

# 2. Recon scan BAR0 (read-only, safe)
sudo python3 bar0_recon.py

# 3. Find crash-triggering offsets
sudo python3 bar0_bisect_sweep.py --verbose

# 4. Fuzz safe BAR0 registers
sudo python3 bar0_fuzz.py --skip-recon

# 5. Config space fuzz
sudo python3 config_fuzz.py -r=basic -n=new -o=serial
```

## Examples

### Example 1: First-time recon — what's alive on BAR0?

Start with a safe, read-only scan of the first 128 KB. Clear dmesg first so
error baselines are clean:

```bash
sudo dmesg -C
sudo python3 bar0_recon.py --range 0x0-0x20000
```

Expected output (healthy firmware):

```
Device ID: 1103a17c  (OK)
Link status: 5041  (OK)
Baseline dmesg errors: 0
Scanning 0x000000-0x020000  step=4  check_every=1024

  Scanning 0x01fc00 / 0x020000  (100.0%)
Found 5 active regions (87 total active DWORDs)

--- Region 0x000000-0x000b90 (30 DWORDs) ---
  0x000000: 0x00000008
  0x000060: 0x501c0107
  ...

No new dmesg errors detected during scan.
```

If errors are detected the tool prints the faulting range and suggests a
bisect command to narrow it down.

### Example 2: Find crash-triggering offsets with bisect sweep

Scan the full 2 MB BAR in 64 KB chunks. The script automatically recovers
the device after each crash and narrows down to individual 4-byte offsets:

```bash
sudo dmesg -C
sudo python3 bar0_bisect_sweep.py --verbose
```

If the process gets interrupted (Ctrl+C, reboot), resume from the saved state:

```bash
sudo python3 bar0_bisect_sweep.py --resume bisect_state_2026-02-18_14-30-00.json
```

For faster iteration on a known-bad region, restrict the range and shrink the
chunk size:

```bash
sudo python3 bar0_bisect_sweep.py --range 0x10000-0x20000 --chunk-size 0x1000 --verbose
```

### Example 3: Fuzz only the Copy Engine registers

Target the CE high cluster (0x8000–0xC000) where DMA ring pointers live.
The `--dry-run` flag lets you preview the plan before committing writes:

```bash
# Preview what would be fuzzed
sudo python3 bar0_fuzz.py --cluster ce_high --dry-run

# Run it for real
sudo python3 bar0_fuzz.py --cluster ce_high
```

Output shows each write/readback result flagged as STICKY (accepted) or
MASKED (hardware filtered the value):

```
  0x008000: all-ones wrote=0xFFFFFFFF read=0x0000001F (orig=0x0000001F) MASKED
  0x008000: alt-AA   wrote=0xAAAAAAAA read=0x0000000A (orig=0x0000001F) MASKED
```

### Example 4: Config space exhaustive write

Write all 256 byte values to every register in the first 64 bytes of config
space. Results are logged to a timestamped file:

```bash
sudo python3 config_fuzz.py -r=basic -n=new -o=serial
```

Skip sensitive registers (e.g., Command at 0x04, Status at 0x06):

```bash
sudo python3 config_fuzz.py -r=basic -n=new -o=serial -s=0x04,0x05,0x06,0x07
```

Run random writes across the full 256-byte space (runs until Ctrl+C):

```bash
sudo python3 config_fuzz.py -r=full -n=new -o=random
```

### Example 5: Using `pci_lib` in a custom script

Write a quick one-off test using the shared library:

```python
#!/usr/bin/env python3
import pci_lib

# Check device health before doing anything
if not pci_lib.check_device_health():
    print("Device unhealthy, aborting")
    exit(1)

# Read a single register
with pci_lib.open_bar(readonly=True) as mm:
    val = pci_lib.read32(mm, 0x000060)
    print(f"HAL version register: 0x{val:08x}")

# Read all 4 hardware instances of the same register
with pci_lib.open_bar(readonly=True) as mm:
    for i in range(4):
        off = 0x003008 + i * pci_lib.INSTANCE_STRIDE
        val = pci_lib.read32(mm, off)
        print(f"  Instance {i} @ 0x{off:06x}: 0x{val:08x}")
```

### Example 6: Targeting a different device

All tools accept `--device` (BAR0 tools) or `-d=` (config space tools) to
override the default BDF:

```bash
# BAR0 recon on a different device
sudo python3 bar0_recon.py --device 0000:03:00.0

# Config space read on a different device
python3 config_read.py -d=0000:03:00.0
```

Or set it once in a custom script:

```python
import pci_lib
pci_lib.set_device("0000:03:00.0")
# All subsequent calls use the new BDF
```

## VM Setup

A sample libvirt VM XML snippet (`sample-vm-snippet.xml`) is included to show how to configure PCI passthrough with PCIe expander buses for use with these tools inside a virtual machine.
