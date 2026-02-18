# PCI Express Extended Config Space Fuzzing Guide

Target device: **Qualcomm WCN785x Wi-Fi 7 (FastConnect 7800)**
BDF: `0004:01:00.0`
Driver: `ath12k_pci`

## Capability Map

```
0x00-0x3F   Standard PCI Header
0x40-0x4F   Power Management v3
0x50-0x6F   MSI (16/32 vectors, maskable, 32-bit)
0x70-0xFF   PCIe Endpoint v2 (DevCap/Ctl/Sta, LnkCap/Ctl/Sta)
0x100-0x147 AER v2 (Advanced Error Reporting)
0x148-0x157 Secondary PCIe (lane equalization)
0x158-0x1E3 TPH v1 (Transaction Processing Hints)
0x1E4-0x1EB LTR v1 (Latency Tolerance Reporting)
0x1EC-0x1FF L1 PM Substates
0x200-0xFFF Gaps / Vendor-specific (Qualcomm) -- primary fuzz target
```

---

## Step 1: Recon -- Dump Baseline

Save the entire extended config space before fuzzing.

```bash
# Dump 0x000-0x200 (standard + capabilities)
for off in $(seq 0 4 512); do
  printf '%03x: ' $off
  sudo setpci -s 0004:01:00.0 $(printf '%x' $off).L
done > pci_baseline_0x000_0x200.txt

# Dump 0x200-0xFFF (vendor-specific / undocumented)
for off in $(seq 512 4 4095); do
  printf '%03x: ' $off
  sudo setpci -s 0004:01:00.0 $(printf '%x' $off).L
done > pci_baseline_0x200_0xFFF.txt

# Find active (non-zero, non-all-ones) registers
awk '$2 != "00000000" && $2 != "ffffffff"' pci_baseline_0x200_0xFFF.txt
```

---

## Step 2: Writable Register Discovery

Identify which bytes in the undocumented region actually accept writes.
This is non-destructive -- original values are restored.

```bash
for off in $(seq 512 1 4095); do
  hex=$(printf '%x' $off)
  orig=$(sudo setpci -s 0004:01:00.0 ${hex}.B)
  sudo setpci -s 0004:01:00.0 ${hex}.B=ff
  after=$(sudo setpci -s 0004:01:00.0 ${hex}.B)
  sudo setpci -s 0004:01:00.0 ${hex}.B=${orig}  # restore
  if [ "$after" != "$orig" ]; then
    echo "WRITABLE 0x${hex}: orig=${orig} wrote=ff read=${after}"
  fi
done 2>&1 | tee pci_writable_discovery.log
```

---

## Step 3: Byte Walk with Restore

Probe each byte with 0xFF, log the response, then restore.

```bash
for off in $(seq 512 1 4095); do
  hex=$(printf '%x' $off)
  orig=$(sudo setpci -s 0004:01:00.0 ${hex}.B)
  sudo setpci -s 0004:01:00.0 ${hex}.B=ff
  readback=$(sudo setpci -s 0004:01:00.0 ${hex}.B)
  echo "0x${hex}: orig=${orig} wrote=ff read=${readback}"
  sudo setpci -s 0004:01:00.0 ${hex}.B=${orig}
done 2>&1 | tee pci_fuzz_bytewalk_ff.log
```

---

## Step 4: Destructive Pattern Sweeps

**WARNING: These do NOT restore original values.**

```bash
# All-ones DWORD sweep
for off in $(seq 512 4 4095); do
  sudo setpci -s 0004:01:00.0 $(printf '%x' $off).L=ffffffff
done 2>&1 | tee pci_fuzz_allones.log

# All-zeros DWORD sweep
for off in $(seq 512 4 4095); do
  sudo setpci -s 0004:01:00.0 $(printf '%x' $off).L=00000000
done 2>&1 | tee pci_fuzz_allzeros.log

# Alternating bit patterns (0xAA and 0x55)
for off in $(seq 512 4 4095); do
  sudo setpci -s 0004:01:00.0 $(printf '%x' $off).L=aaaaaaaa
done 2>&1 | tee pci_fuzz_0xaa.log

for off in $(seq 512 4 4095); do
  sudo setpci -s 0004:01:00.0 $(printf '%x' $off).L=55555555
done 2>&1 | tee pci_fuzz_0x55.log
```

---

## Step 5: Random DWORD Fuzz

```bash
for off in $(seq 512 4 4095); do
  rand=$(openssl rand -hex 4)
  hex=$(printf '%x' $off)
  result=$(sudo setpci -s 0004:01:00.0 ${hex}.L=${rand} 2>&1)
  echo "0x${hex} = ${rand}  ${result}"
done 2>&1 | tee pci_fuzz_random.log
```

---

## Step 6: Bit-Walking per DWORD

Single bit set, shifting through all 32 positions.

```bash
for off in $(seq 512 4 4095); do
  hex=$(printf '%x' $off)
  for bit in $(seq 0 31); do
    val=$(printf '%08x' $((1 << bit)))
    sudo setpci -s 0004:01:00.0 ${hex}.L=${val}
  done
done 2>&1 | tee pci_fuzz_bitwalk.log
```

---

## Step 7: Targeted Writable Register Fuzz

After running Step 2, extract writable offsets and test multiple patterns.

```bash
grep WRITABLE pci_writable_discovery.log | awk '{print $2}' | sed 's/://' | while read hex; do
  for val in 00 ff aa 55 0f f0 01 80 7f fe; do
    sudo setpci -s 0004:01:00.0 ${hex}.B=${val}
    readback=$(sudo setpci -s 0004:01:00.0 ${hex}.B)
    echo "${hex}: wrote=${val} read=${readback}"
  done
done 2>&1 | tee pci_fuzz_writable_targeted.log
```

---

## Health Check

Run between fuzzing rounds to verify the device is still alive.

```bash
health_check() {
  echo "=== Health Check $(date) ==="
  # Device still visible?
  sudo lspci -s 0004:01:00.0 || echo "DEVICE GONE"
  # Kernel errors?
  dmesg | tail -5
  # Driver still bound?
  ls /sys/bus/pci/devices/0004:01:00.0/driver 2>/dev/null \
    && echo "Driver: bound" || echo "Driver: UNBOUND"
  # Link status (offset 0x82 = LnkSta in PCIe capability)
  sudo setpci -s 0004:01:00.0 82.W
  echo "==========================="
}

health_check
```

---

## Device Recovery

If the device drops off the bus or becomes unresponsive:

```bash
# Re-scan PCI bus
echo 1 | sudo tee /sys/bus/pci/devices/0004:01:00.0/remove
echo 1 | sudo tee /sys/bus/pci/rescan

# Reset just the device
echo 1 | sudo tee /sys/bus/pci/devices/0004:01:00.0/reset

# Reload the driver
sudo modprobe -r ath12k_pci && sudo modprobe ath12k_pci
```

---

## Recommended Execution Order

| Step | Purpose                | Destructive? |
|------|------------------------|-------------|
| 1    | Save baseline dump     | No          |
| 2    | Writable discovery     | No (restores) |
| 3    | Byte walk with restore | No (restores) |
| 7    | Targeted writable fuzz | **Yes**     |
| 5    | Random DWORD fuzz      | **Yes**     |
| 4    | Pattern sweeps         | **Yes**     |
| 6    | Bit-walking            | **Yes**     |

Start with steps 1-3 to map the terrain, then use step 7 to focus on the
registers that actually accept writes before running broad destructive sweeps.

---

## Baseline Register Dump Analysis (0x000 - 0x200)

Raw dump command:

```bash
for off in $(seq 0 4 512); do
  printf '%03x: ' $off
  sudo setpci -s 0004:01:00.0 $(printf '%x' $off).L
done > pci_baseline_0x000_0x200.txt

awk '$2 != "00000000" && $2 != "ffffffff"' pci_baseline_0x000_0x200.txt
```

### Standard PCI Header (0x00 - 0x3F)

| Offset | Raw Value | Decoded |
|--------|-----------|---------|
| `0x000` | `110717cb` | **Vendor ID** = `17cb` (Qualcomm), **Device ID** = `1107` (WCN785x) |
| `0x004` | `00100406` | **Command** = `0406` (MemSpace+, BusMaster+, DisINTx+), **Status** = `0010` (Cap+ = capability list exists) |
| `0x008` | `02800001` | **Class** = `0280` (Network controller: other), **Rev** = `01` |
| `0x010` | `7c400004` | **BAR0** = `0x7c400000`, 64-bit, non-prefetchable (bit 2 = 64-bit flag) -- this is the 2MB MMIO window |
| `0x02c` | `e0e917aa` | **Subsystem Vendor** = `17aa` (Lenovo), **Subsystem ID** = `e0e9` |
| `0x034` | `00000040` | **Capabilities Pointer** = `0x40` -- the linked list starts here |

### Power Management (0x40)

| Offset | Raw Value | Decoded |
|--------|-----------|---------|
| `0x040` | `c8035001` | **Cap ID** = `01` (Power Mgmt), **Next** = `0x50`, PME from D0/D3hot/D3cold |
| `0x044` | `00000008` | **PM Status** = D0 (fully on), `NoSoftRst+` (bit 3 = device keeps state across D3->D0) |

### MSI (0x50)

| Offset | Raw Value | Decoded |
|--------|-----------|---------|
| `0x050` | `014b7005` | **Cap ID** = `05` (MSI), **Next** = `0x70`, **Control** = `014b` -> Enable+, 16 vectors allocated, Maskable+ |
| `0x054` | `17050040` | **MSI Address** = `0x17050040` -- GIC interrupt controller target on this ARM SoC |
| `0x05c` | `ffff8000` | **MSI Mask** = `0xffff8000` -- vectors 0-14 unmasked (active), 15-31 masked |

### PCIe Endpoint v2 (0x70)

| Offset | Raw Value | Decoded |
|--------|-----------|---------|
| `0x070` | `00020010` | **Cap ID** = `10` (PCIe), **Version** = 2, **Type** = Endpoint |
| `0x074` | `00008fc0` | **DevCap**: MaxPayload=128B, no phantom functions, L0s/L1 latency unlimited, RBE+ |
| `0x078` | `001a6008` | **DevCtl/DevSta**: All error reporting on, RlxdOrd+, NoSnoop+, MaxPayload=128B, MaxReadReq=512B. **DevSta**: CorrErr+, NonFatalErr+, UnsupReq+ (errors have been seen) |
| `0x07c` | `00434c23` | **LnkCap**: Gen3 (8GT/s), x2 width, ASPM L0s+L1 supported, Port #0 |
| `0x080` | `10230281` | **LnkCtl** = `0281` (ASPM disabled, CommClk+, RCB=64B), **LnkSta** = `1023` (Gen3 8GT/s, x2, SlotClk+) |
| `0x094` | `0000181f` | **DevCtl2**: Completion Timeout 50us-50ms, LTR enabled |
| `0x098` | `00000400` | **LnkCap2**: Supports 2.5/5.0/8.0 GT/s |
| `0x09c` | `0000000e` | **LnkCtl2**: Target speed = 8GT/s, normal transmit margin |
| `0x0a0` | `001e0003` | **LnkSta2**: Equalization complete for all phases, -6dB de-emphasis |

### AER -- Advanced Error Reporting (0x100)

| Offset | Raw Value | Decoded |
|--------|-----------|---------|
| `0x100` | `14820001` | **Extended Cap ID** = `0001` (AER), version 2, **Next** = `0x148` |
| `0x104` | `00100000` | **UE Status**: bit 20 = `UnsupReq+` -- an unsupported request was received |
| `0x108` | `00400000` | **UE Mask**: bit 22 = `UncorrIntErr` masked (internal errors suppressed) |
| `0x10c` | `00462030` | **UE Severity**: DLP, SDES, FCP, RxOF, MalfTLP, UncorrIntErr all **fatal** |
| `0x110` | `0000a000` | **CE Status**: `AdvNonFatalErr+`, `HeaderOF+` -- correctable errors logged |
| `0x114` | `0000e000` | **CE Mask**: AdvNonFatalErr, CorrIntErr, HeaderOF all masked |
| `0x118` | `000000b4` | **AER Cap**: First Error Pointer = `0x14` (points to UnsupReq), ECRC gen/check capable |
| `0x11c`-`0x128` | `40000001 0000000f 7c400980 6c000000` | **Header Log**: the TLP that caused the UnsupReq error -- a memory read to BAR0 + offset `0x980` |

### Secondary PCIe (0x148)

| Offset | Raw Value | Decoded |
|--------|-----------|---------|
| `0x148` | `15810019` | **Extended Cap ID** = `0x0019` (Secondary PCIe), **Next** = `0x158` |
| `0x154` | `55005500` | **Lane Equalization**: preset/coefficient values for Gen3 lane EQ |

### TPH -- Transaction Processing Hints (0x158)

| Offset | Raw Value | Decoded |
|--------|-----------|---------|
| `0x158` | `1e410017` | **Extended Cap ID** = `0x0017` (TPH), **Next** = `0x1E4` |
| `0x15c` | `00000001` | TPH Requester capable, no steering table |

### LTR -- Latency Tolerance Reporting (0x1E4)

| Offset | Raw Value | Decoded |
|--------|-----------|---------|
| `0x1e4` | `1ec10018` | **Extended Cap ID** = `0x0018` (LTR), **Next** = `0x1EC` |

### L1 PM Substates (0x1EC)

| Offset | Raw Value | Decoded |
|--------|-----------|---------|
| `0x1ec` | `0001001e` | **Extended Cap ID** = `0x001e` (L1 PM Substates), **Next** = `0x000` (end of list) |
| `0x1f0` | `0000461f` | **L1SubCtl1**: All L1 substates disabled, `LTR_L1.2_Threshold` = 76800ns, `T_CommonMode` = 70us |
| `0x1f4` | `00000005` | **L1SubCtl2**: `T_PwrOn` = ~10us |

### Key Observations

1. **Errors already present**: The device has logged an Unsupported Request error (AER `0x104` bit 20) from a TLP targeting BAR0+0x980 -- something tried to access an address the device didn't recognize.
2. **ASPM disabled**: Despite the hardware supporting L0s and L1, the link is running with ASPM off -- likely for Wi-Fi latency reasons.
3. **MSI active with 16 vectors**: The Wi-Fi driver is using 16 interrupt vectors for parallel Tx/Rx queue handling.
4. **Capability list ends at `0x1EC`**: Everything from `0x200` onward is outside any declared capability -- that's where the undocumented Qualcomm registers live.

---

## What Can Be Done -- Attack Surface and Test Scenarios

### A. Power State Manipulation

Force the device through power state transitions while the driver is active.
Can expose race conditions in the ath12k driver's power management handling.

```bash
# Slam into D3hot while driver is active
sudo setpci -s 0004:01:00.0 44.W=0003
sleep 1
# Wake back to D0
sudo setpci -s 0004:01:00.0 44.W=0000
# Rapid power cycling
for i in $(seq 1 100); do
  sudo setpci -s 0004:01:00.0 44.W=0003
  sudo setpci -s 0004:01:00.0 44.W=0000
done
```

### B. Interrupt Hijacking / Corruption

Corrupt MSI configuration to test how the system handles misrouted interrupts.

```bash
# Redirect MSI to a bogus address
sudo setpci -s 0004:01:00.0 54.L=deadbeef
# Corrupt MSI data payload
sudo setpci -s 0004:01:00.0 58.W=ffff
# Mask all interrupt vectors (starve the driver of interrupts)
sudo setpci -s 0004:01:00.0 5c.L=ffffffff
# Unmask all 32 vectors (driver only expects 16)
sudo setpci -s 0004:01:00.0 5c.L=00000000
```

### C. Link Destabilization

Manipulate PCIe link parameters to stress the physical layer.

```bash
# Force link retrain
sudo setpci -s 0004:01:00.0 80.W=0020
# Downgrade target speed to Gen1 (2.5GT/s)
sudo setpci -s 0004:01:00.0 9c.W=0001
# Force compliance mode
sudo setpci -s 0004:01:00.0 9c.W=0010
# Enable ASPM L0s+L1 (currently disabled by driver)
sudo setpci -s 0004:01:00.0 80.W=0283
# Disable the link entirely
sudo setpci -s 0004:01:00.0 80.W=0010
```

### D. BAR Corruption

Remap the device's memory window to cause the driver to read/write wrong addresses.

```bash
# Save original BAR0
orig_bar=$(sudo setpci -s 0004:01:00.0 10.L)
# Corrupt BAR0
sudo setpci -s 0004:01:00.0 10.L=deadbeef
# Restore
sudo setpci -s 0004:01:00.0 10.L=${orig_bar}
```

### E. Error Injection via AER

Unmask all errors and flip severity bits to see how the kernel's AER handler responds.

```bash
# Make ALL uncorrectable errors fatal
sudo setpci -s 0004:01:00.0 10c.L=ffffffff
# Unmask all uncorrectable errors
sudo setpci -s 0004:01:00.0 108.L=00000000
# Unmask all correctable errors
sudo setpci -s 0004:01:00.0 114.L=00000000
# Clear existing error status (write-1-to-clear)
sudo setpci -s 0004:01:00.0 104.L=ffffffff
sudo setpci -s 0004:01:00.0 110.L=ffffffff
```

### F. Command Register Abuse

Disable the device's ability to respond while the driver is loaded.

```bash
# Disable everything (device goes deaf)
sudo setpci -s 0004:01:00.0 04.W=0000
# Re-enable
sudo setpci -s 0004:01:00.0 04.W=0406
# Disable only bus mastering (device can't DMA)
sudo setpci -s 0004:01:00.0 04.W=0402
# Enable SERR (system error reporting)
sudo setpci -s 0004:01:00.0 04.W=0506
```

### G. L1 PM Substates -- Force Deep Sleep

Enable all L1 substates with corrupted timing thresholds.

```bash
# Enable all L1 substates with bogus timing
sudo setpci -s 0004:01:00.0 1f0.L=ffffffff
sudo setpci -s 0004:01:00.0 1f4.L=ffffffff
# Enable only ASPM L1.2 with zero recovery time (should cause link timeouts)
sudo setpci -s 0004:01:00.0 1f0.L=00000004
sudo setpci -s 0004:01:00.0 1f4.L=00000000
```

### H. Vendor-Specific Region (0x200 - 0xFFF)

See Steps 1-7 above. This is the primary fuzz target since behavior is
entirely implementation-dependent and undocumented.

### Monitoring During All Tests

Run these in a separate terminal to catch issues in real time:

```bash
# Watch kernel messages
sudo dmesg -w

# Monitor link status continuously
watch -n 1 'sudo setpci -s 0004:01:00.0 82.W'

# Monitor AER error counters
watch -n 1 'sudo setpci -s 0004:01:00.0 104.L; sudo setpci -s 0004:01:00.0 110.L'

# Check if Wi-Fi interface is still up
watch -n 1 'ip link show wlan0'
```

---

## Sending Complete PCIe Memory Transactions (TLPs)

`setpci` only generates **Config Read/Write TLPs**. To send actual **Memory
Read/Write TLPs** directly to the Qualcomm firmware, you need to access BAR0.

BAR0 for this device: `0x7c400000` (2MB, 64-bit, non-prefetchable)

### Method 1: sysfs resource file (easiest)

```bash
# The kernel exposes BAR0 as a mappable file
ls -la /sys/bus/pci/devices/0004:01:00.0/resource0

# Read first 4 bytes from BAR0
sudo xxd -l 4 /sys/bus/pci/devices/0004:01:00.0/resource0

# Dump first 256 bytes
sudo xxd -l 256 /sys/bus/pci/devices/0004:01:00.0/resource0
```

### Method 2: /dev/mem with devmem2

```bash
# Install
sudo apt install devmem2

# Read DWORD at BAR0 + 0x00
sudo devmem2 0x7c400000 w

# Write 0xdeadbeef to BAR0 + 0x100
sudo devmem2 0x7c400100 w 0xdeadbeef

# Read the address that caused the UnsupReq error in the AER log
sudo devmem2 0x7c400980 w
```

### Method 3: pcimem (purpose-built for BAR access)

```bash
# Clone and build
git clone https://github.com/billfarrow/pcimem.git
cd pcimem && make

# Read from BAR0 at offset 0x0
sudo ./pcimem /sys/bus/pci/devices/0004:01:00.0/resource0 0x0

# Write to BAR0 at offset 0x100
sudo ./pcimem /sys/bus/pci/devices/0004:01:00.0/resource0 0x100 w 0xdeadbeef

# Sweep-read the first 4KB (generates 1024 Memory Read TLPs)
for off in $(seq 0 4 4095); do
  sudo ./pcimem /sys/bus/pci/devices/0004:01:00.0/resource0 $(printf '0x%x' $off) w 2>/dev/null
done | tee bar0_dump.txt
```

### Method 4: Python MMIO fuzzer

```python
#!/usr/bin/env python3
"""Fuzz Qualcomm WCN785x BAR0 MMIO region with raw PCIe Memory TLPs."""

import mmap
import os
import struct
import random
import time

DEVICE = "/sys/bus/pci/devices/0004:01:00.0/resource0"
BAR_SIZE = 2 * 1024 * 1024  # 2MB

def open_bar():
    fd = os.open(DEVICE, os.O_RDWR | os.O_SYNC)
    mm = mmap.mmap(fd, BAR_SIZE, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    return fd, mm

def read32(mm, offset):
    mm.seek(offset)
    return struct.unpack('<I', mm.read(4))[0]

def write32(mm, offset, value):
    mm.seek(offset)
    mm.write(struct.pack('<I', value & 0xFFFFFFFF))

def dump_bar(mm, start, end, step=4):
    """Read and dump a range -- each read becomes a Memory Read TLP."""
    for off in range(start, end, step):
        val = read32(mm, off)
        if val != 0x00000000 and val != 0xFFFFFFFF:
            print(f"  0x{off:06x}: 0x{val:08x}")

def fuzz_random_writes(mm, start, end, count=1000):
    """Write random values to random offsets -- each write is a Memory Write TLP."""
    for i in range(count):
        off = random.randrange(start, end, 4)
        val = random.randint(0, 0xFFFFFFFF)
        print(f"  [{i}] 0x{off:06x} <= 0x{val:08x}")
        write32(mm, off, val)
        time.sleep(0.01)

def fuzz_sequential_writes(mm, start, end, pattern=0xDEADBEEF):
    """Walk a pattern through every DWORD -- sequential Memory Write TLPs."""
    for off in range(start, end, 4):
        write32(mm, off, pattern)
        readback = read32(mm, off)
        if readback != pattern:
            print(f"  0x{off:06x}: wrote 0x{pattern:08x} read 0x{readback:08x}")

if __name__ == "__main__":
    fd, mm = open_bar()
    try:
        print("=== BAR0 Recon (non-zero registers) ===")
        dump_bar(mm, 0x0000, 0x2000)

        print("\n=== Fuzz: Random writes to 0x1000-0x2000 ===")
        fuzz_random_writes(mm, 0x1000, 0x2000, count=100)

        print("\n=== Fuzz: Sequential pattern walk ===")
        fuzz_sequential_writes(mm, 0x1000, 0x2000, pattern=0xAAAAAAAA)
    finally:
        mm.close()
        os.close(fd)
```

### What each access method generates on the PCIe bus

| Userspace action | PCIe TLP generated | Target |
|---|---|---|
| `setpci ... XX.L` (read) | Configuration Read Type 0 | Config space |
| `setpci ... XX.L=YY` (write) | Configuration Write Type 0 | Config space |
| `read32(mm, offset)` | **Memory Read (MRd)** 32/64-bit | BAR0 MMIO |
| `write32(mm, offset, val)` | **Memory Write (MWr)** 32/64-bit | BAR0 MMIO |
| DMA by device | Memory Read/Write from device | System RAM |

Config TLPs go through the root complex's config mechanism. **Memory TLPs go
directly over the PCIe link** to the Qualcomm chip -- this exercises the
firmware's actual transaction handling logic.

### Interesting BAR0 regions to target

Based on ath12k driver source, common Qualcomm Wi-Fi register regions:

```
0x000000 - 0x001000   HAL (Host Access Layer)
0x001000 - 0x002000   CE (Copy Engine) registers
0x003000 - 0x004000   WFSS (Wi-Fi Subsystem)
0x01E000 - 0x020000   UMAC registers
0x030000 - 0x040000   PCIE_SOC registers
0x000980              Already known to trigger UnsupReq (from AER log)
```

### BAR0 Recon Results -- Active Register Map

A full 2MB BAR0 sweep (read every DWORD, flag non-zero/non-0xFFFFFFFF) found
**130 active offsets** that cluster into three functional groups:

**Cluster A -- HAL / Core (0x000000 - 0x000B90, ~30 offsets):**
```
0x000000  0x000060  0x000068  0x000070  0x000078  0x00008c
0x0000a4  0x0000b8  0x000110  0x000124  0x000148  0x0001c4
0x000280  0x00028c  0x000294  0x0002a0  0x000364  0x00036c
0x000398  0x0003a0  0x0003a8  0x0003b0  0x000700  0x000708
0x000710  0x000a38  0x000a40  0x000b14  0x000b38  0x000b90
```

**Cluster B -- WFSS / Wi-Fi Subsystem (0x003008 - 0x00316C, 7 offsets):**
```
0x003008  0x0030d8  0x0030e8  0x0030fc  0x00310c  0x00313c
0x00316c
```

**Cluster C -- Copy Engine / DMA (0x008000 - 0x008700+, 13+ offsets):**
```
0x008000  0x008010  0x008020  0x008100  0x008110  0x008118
0x008200  0x008248  0x008290  0x008300  0x008600  0x008690
0x008700
```

The remaining ~80 offsets are in higher BAR0 space (CE8+, UMAC, PCIE_SOC).
The targeted fuzzer (`bar0_targeted_fuzz.py`) performs runtime discovery to
find all active offsets before fuzzing.

### Priority targets for write fuzzing

| Region | Risk | Why |
|--------|------|-----|
| CE ring regs (0x008xxx) | **Critical** | DMA base/size pointers -- corrupting these can write to arbitrary host memory |
| Interrupt mask (0x00006x) | **High** | Can cause interrupt storms or starve the driver |
| WFSS control (0x003xxx) | **High** | Firmware subsystem control, may trigger watchdog |
| DMA ring config (0x000280+) | **Critical** | Ring descriptors, active DMA corruption risk |

### Unbind driver first (safer for pure hardware testing)

```bash
# Unbind ath12k so the driver doesn't interfere or crash the kernel
echo "0004:01:00.0" | sudo tee /sys/bus/pci/devices/0004:01:00.0/driver/unbind

# Now BAR0 MMIO access goes directly to hardware with no driver in the way
sudo devmem2 0x7c400000 w
sudo devmem2 0x7c400980 w

# Rebind when done
echo "0004:01:00.0" | sudo tee /sys/bus/pci/drivers/ath12k_pci/bind
```

The key difference: `setpci` can only poke config registers. MMIO access
through BAR0 sends real Memory Read/Write TLPs that exercise the Qualcomm
firmware's actual packet processing, DMA engine, and register decode logic --
a much larger and more interesting attack surface.

---

## Step 8: Targeted BAR0 MMIO Fuzzer

`bar0_targeted_fuzz.py` is the comprehensive fuzzer that combines runtime
discovery with targeted write fuzzing of all active BAR0 registers.

```bash
# Default: discover + fuzz all active offsets with health checks
sudo python3 bar0_targeted_fuzz.py

# Read-only recon (discover active offsets, no writes)
sudo python3 bar0_targeted_fuzz.py --recon-only

# Fuzz only a specific cluster
sudo python3 bar0_targeted_fuzz.py --cluster hal
sudo python3 bar0_targeted_fuzz.py --cluster wfss
sudo python3 bar0_targeted_fuzz.py --cluster ce

# Fuzz a custom offset range
sudo python3 bar0_targeted_fuzz.py --range 0x008000-0x008800

# Skip health checks (faster but riskier)
sudo python3 bar0_targeted_fuzz.py --no-health-check

# Write-only (skip recon, use hardcoded known offsets)
sudo python3 bar0_targeted_fuzz.py --skip-recon
```

The fuzzer:
1. Scans the full 2MB BAR0 to discover all active registers
2. Classifies them into HAL / WFSS / CE clusters
3. For each active offset: saves original value, writes test patterns, checks
   for firmware errors, restores original value
4. Runs health checks (device present, driver bound, link up, dmesg errors)
   between fuzz rounds
5. Logs everything to a timestamped file

See `FINDINGS.md` for the full analysis of results.

---

## Step 9: BAR0 Recon with Error Detection

`dump-regs-fw.py` scans BAR0 and monitors dmesg to identify which offsets
trigger CmpltTO (Completion Timeout) or other AER errors.

**WARNING:** A full 2MB scan triggers CmpltTO and crashes the firmware.
Use `--range` to scan smaller regions safely.

```bash
# Full scan with periodic dmesg checking (default: every 1024 reads = ~4KB)
sudo python3 dump-regs-fw.py

# Scan a specific range
sudo python3 dump-regs-fw.py --range 0x0000-0x2000

# Narrow bisect: check dmesg after every single read
sudo python3 dump-regs-fw.py --range 0x0000-0x1000 --check-every 1 --verbose

# Adjust region grouping gap (default: 0x100)
sudo python3 dump-regs-fw.py --gap 0x200
```

When an error is detected, the script reports the chunk range and prints
a bisect command to narrow it down further.

### Known Hazards

- **CmpltTO offsets exist** somewhere in the 2MB BAR0 space. Reading them
  causes the device to hang the PCIe transaction, triggering AER on the
  root port and crashing the firmware.
- **ath12k has no AER recovery callback**, so the kernel cannot recover
  the device automatically after CmpltTO.
- The root port's AER Header Log (`0x11c-0x128`) returns all zeros for
  CmpltTO -- it does not latch the faulting TLP address.
- After a CmpltTO crash, BAR0 exposes post-crash firmware state (raw SRAM,
  `0xDEADBEEF` fill patterns, debug sentinels).

### Multi-Instance Register Layout

The 2MB BAR0 contains 4 apparent hardware instances at 512KB stride:

| Instance | Base     | WFSS regs  | CE regs    |
|----------|----------|------------|------------|
| 0        | `0x000000` | `0x003xxx` | `0x008xxx` |
| 1        | `0x080000` | `0x083xxx` | `0x088xxx` |
| 2        | `0x100000` | `0x103xxx` | `0x108xxx` |
| 3        | `0x180000` | `0x183xxx` | `0x188xxx` |

This is consistent with Wi-Fi 7 Multi-Link Operation (separate radio
hardware per band). Not confirmed from vendor documentation.
