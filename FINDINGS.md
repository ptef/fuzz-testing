# PCI Fuzz Testing Findings -- Qualcomm WCN785x (FastConnect 7800)

**Target:** Qualcomm WCN785x Wi-Fi 7
**BDF:** `0004:01:00.0`
**Driver:** `ath12k_pci`
**Platform:** Lenovo (Subsystem `17aa:e0e9`), Qualcomm X1E SoC
**Date:** 2026-02-16 / 2026-02-17

---

## 1. Config Space Baseline (0x000 - 0x1FF)

### Standard Header

| Register | Value | Meaning |
|----------|-------|---------|
| Vendor/Device | `17cb:1107` | Qualcomm WCN785x |
| Command | `0406` | MemSpace+, BusMaster+, DisINTx+ |
| Class | `0280` rev `01` | Network controller: other |
| BAR0 | `0x7c400000` | 2MB, 64-bit, non-prefetchable MMIO |
| Subsystem | `17aa:e0e9` | Lenovo platform |
| Capabilities Ptr | `0x40` | Start of capability linked list |

### Capability Chain

```
0x40  Power Management v3    -> next 0x50
0x50  MSI (16 vectors)       -> next 0x70
0x70  PCIe Endpoint v2       -> next (extended @ 0x100)
0x100 AER v2                 -> next 0x148
0x148 Secondary PCIe         -> next 0x158
0x158 TPH v1                 -> next 0x1E4
0x1E4 LTR v1                 -> next 0x1EC
0x1EC L1 PM Substates        -> end of list
```

### Key Observations from Config Space

1. **Pre-existing AER error:** Uncorrectable Error Status (`0x104`) has bit 20 set = `UnsupReq`. The Header Log at `0x11C-0x128` shows the faulting TLP targeted **BAR0 + 0x980** -- a memory read to an address the firmware didn't recognize.

2. **Correctable errors logged:** CE Status (`0x110`) = `0x0000a000` showing `AdvNonFatalErr+` and `HeaderOF+`.

3. **ASPM disabled:** LnkCtl (`0x080`) = `0x0281` -- ASPM L0s and L1 both off despite hardware support. Driver keeps it off for Wi-Fi latency.

4. **Link status healthy:** LnkSta = `0x1023` -- Gen3 8GT/s, x2 width, slot clock in use.

5. **MSI fully active:** 16 vectors allocated and unmasked (bits 0-14), vector 15-31 masked. GIC target address = `0x17050040`.

6. **Vendor-specific region 0x200-0xFFF is entirely zero:** No extended capabilities or vendor VSEC structures are declared in config space beyond `0x1FF`. The "undocumented" config space is just empty.

---

## 2. BAR0 MMIO Recon Sweep

A full scan of the 2MB BAR0 address space (reading every DWORD) identified **130 active offsets** -- addresses returning values other than `0x00000000` or `0xFFFFFFFF`.

### Region Clustering

The 130 offsets cluster into distinct functional groups:

#### Cluster A: HAL / Core Registers (0x000000 - 0x000B90)

The densest region. Corresponds to the ath12k Host Access Layer (HAL) and core device registers.

| Offset | Notes |
|--------|-------|
| `0x000000` | Device ID / version register |
| `0x000060 - 0x000078` | Likely interrupt status / mask |
| `0x00008c` | |
| `0x0000a4` | |
| `0x0000b8` | |
| `0x000110` | |
| `0x000124` | |
| `0x000148` | |
| `0x0001c4` | |
| `0x000280 - 0x0002a0` | Possible DMA / ring config |
| `0x000364 - 0x0003b0` | |
| `0x000700 - 0x000710` | |
| `0x000a38 - 0x000a40` | |
| `0x000b14` | |
| `0x000b38` | |
| `0x000b90` | |

**Count:** ~30 offsets in this cluster.

#### Cluster B: WFSS / Wi-Fi Subsystem (0x003008 - 0x00316C)

Sparse but active. Corresponds to Wi-Fi Firmware Sub-System control registers.

| Offset | Notes |
|--------|-------|
| `0x003008` | |
| `0x0030d8` | |
| `0x0030e8` | |
| `0x0030fc` | |
| `0x00310c` | |
| `0x00313c` | |
| `0x00316c` | |

**Count:** 7 offsets in this cluster.

#### Cluster C: Copy Engine / DMA (0x008000 - 0x008700+)

Corresponds to the Copy Engine (CE) register block used for host-firmware DMA communication.

| Offset | Notes |
|--------|-------|
| `0x008000` | CE0 base |
| `0x008010` | |
| `0x008020` | |
| `0x008100` | CE1 base |
| `0x008110` | |
| `0x008118` | |
| `0x008200` | CE2 base |
| `0x008248` | |
| `0x008290` | |
| `0x008300` | CE3 base |
| `0x008600` | CE6 base |
| `0x008690` | |
| `0x008700` | CE7 base |

**Count:** 13 offsets shown (of 50 listed). The remaining ~80 offsets are in higher BAR0 address space and likely cover:
- Additional CE instances (CE8-CE11 at 0x008800+)
- UMAC registers (0x01E000 - 0x020000)
- PCIE_SOC registers (0x030000 - 0x040000)
- MHI (Modem Host Interface) registers
- TCSR (Top-Level Clock and Reset) block

---

## 3. AER Header Log Analysis

The AER Header Log captured at `0x11C-0x128`:

```
0x11c: 40000001   -- TLP header DW0: Fmt=01 (3DW+data?), Type=00000, TC=0, Attr=00
0x120: 0000000f   -- TLP header DW1: Length=15 DWORDs, RequesterID, Tag, etc.
0x124: 7c400980   -- TLP header DW2: Address = 0x7c400980 = BAR0 + 0x980
0x128: 6c000000   -- TLP header DW3: (upper address bits for 64-bit addressing)
```

**Interpretation:** Something (likely the ath12k driver during init or a firmware op) issued a Memory Read targeting BAR0 offset `0x980`. The device returned an Unsupported Request completion -- meaning offset `0x980` is not implemented in the firmware's MMIO decode logic. This is normal; the 2MB BAR is sparsely populated.

**Significance for fuzzing:** Accessing unimplemented offsets triggers UnsupReq errors but doesn't crash the device. However, accessing *implemented* registers with unexpected values (writes) may trigger firmware faults, hangs, or DMA corruption.

---

## 4. Fuzz Campaign Results Summary

### Config Space Writes (reg_write.py / reg_write_v2.py)

Multiple test runs were performed on 2026-02-16 writing to the PCI config space:

- **Basic range (0x00-0x3F):** Standard header writes. Most registers are read-only or have hardware-enforced masks. Writes to Command register (`0x04`) can disable the device.
- **Extended range (0x200-0xFFF):** All zeros in baseline. Writes accepted to some offsets but no observable effect -- these may be shadow registers or vendor debug interfaces.
- **Exhaustive v2 runs:** All 256 byte values written to each register in the basic range. Device survived but may have had transient link issues visible in dmesg.

### BAR0 MMIO Reads (bar0_bissect.py)

The bisect script was created to identify which specific BAR0 register read triggers firmware errors. The approach:

1. Read baseline dmesg error count
2. Read each target offset one at a time
3. Check dmesg after each read
4. Stop on first new error

**Status:** Script written with 50 of 130 target offsets populated. Needs runtime discovery to get the full set.

---

## 5. Attack Surface Assessment

### High-Value Targets

| Target | Risk Level | Rationale |
|--------|-----------|-----------|
| CE registers (0x008xxx) | **Critical** | DMA engine control. Corrupting ring pointers can cause DMA to arbitrary memory, kernel crash, or potential code execution |
| HAL interrupt regs (0x00006x) | **High** | Interrupt mask/status manipulation can starve the driver or cause interrupt storms |
| WFSS control (0x003xxx) | **High** | Firmware subsystem control. May trigger firmware reset, watchdog, or unexpected state transitions |
| DMA ring config (0x000280+) | **Critical** | Ring base address and size registers. Writing here while DMA is active can corrupt host memory |
| UMAC registers (0x01Exxx) | **Medium** | Upper MAC layer. May affect frame processing but less likely to cause system-level impact |
| PCIE_SOC regs (0x030xxx) | **High** | PCIe interface control on the device side. May cause link drops or device-side resets |

### Observed Behaviors

1. **Reading unimplemented offsets:** Returns `0x00000000` or `0xFFFFFFFF`. Generates UnsupReq in AER but device continues operating.
2. **Writing to config space read-only registers:** Silently ignored (hardware mask).
3. **Writing to config space writable registers:** Accepted. Command register changes take immediate effect (can disable device).
4. **BAR0 reads of active registers:** Returns firmware state. No adverse effects observed for reads alone.
5. **BAR0 writes:** Not yet systematically tested. This is the primary remaining attack vector.

---

## 6. Full BAR0 Sweep -- Completion Timeout Crash (2026-02-17)

### What Happened

Running `dump-regs-fw.py` (reads every DWORD across the full 2MB BAR0) triggered
**Completion Timeout (CmpltTO)** errors and a firmware crash:

```
pcieport 0004:00:00.0: AER: Uncorrectable (Non-Fatal) error message received from 0004:00:00.0
pcieport 0004:00:00.0: PCIe Bus Error: severity=Uncorrectable (Non-Fatal), type=Transaction Layer, (Requester ID)
pcieport 0004:00:00.0:   device [17cb:0111] error status/mask=00004000/00400000
pcieport 0004:00:00.0:    [14] CmpltTO                (First)
ath12k_pci 0004:01:00.0: AER: can't recover (no error_detected callback)
pcieport 0004:00:00.0: AER: device recovery failed
mhi mhi0: Requested to power ON
```

Two CmpltTO events fired 87ms apart, followed by MHI attempting firmware re-init.

### CmpltTO vs UnsupReq

| Error | Mechanism | Severity |
|-------|-----------|----------|
| **UnsupReq** (seen previously at BAR0+0x980) | Device receives read, responds with error completion | Low -- transaction completes |
| **CmpltTO** (this event) | Device receives read, **never responds** | **High** -- root port hangs waiting, triggers AER |

CmpltTO means the read TLP reached the device's internal bus fabric but was
routed to a subsystem that is powered down, clock-gated, or has no response
logic. The root port waited until its completion timeout expired.

### Recovery Failure Chain

1. Root port (`0004:00:00.0`) detects CmpltTO, logs AER error
2. Kernel AER handler invokes ath12k driver's error recovery
3. **ath12k has no `error_detected` callback** -- recovery cannot proceed
4. `device recovery failed` -- device left in broken state
5. MHI layer detects failure, attempts firmware power cycle

### Root Port AER Header Log

Attempted to read the faulting TLP address from the root port's AER Header Log:

```bash
sudo setpci -s 0004:00:00.0 11c.L  # → 00000000
sudo setpci -s 0004:00:00.0 120.L  # → 00000000
sudo setpci -s 0004:00:00.0 124.L  # → 00000000
sudo setpci -s 0004:00:00.0 128.L  # → 00000000
```

All zeros -- the Header Log was either cleared by the AER handler during
recovery, or the root port (`17cb:0111`, Qualcomm PCIe RC) does not latch
the faulting TLP for CmpltTO errors (only for received error TLPs).

### Post-Crash BAR0 State

The scan continued after the crash and found **553 active offsets** (vs 130
in the healthy-firmware scan). The data showed the firmware was in a
crashed/rebooting state:

**Probable raw SRAM exposure (0x000-0x8FC):**
Dense active offsets at every 8 bytes with high-entropy values
(e.g., `0xd53e3459`, `0xfa6a31e6`). Interpretation: these look like raw
firmware SRAM content rather than proper register values, based on the
high entropy and regular stride pattern. However, this is an inference --
they could also be legitimate firmware state not visible during normal
operation.

**Debug fill patterns (0xb90-0xff8):**
Contiguous block of `0xDEADBEEF` at every 8 bytes. `0xDEADBEEF` is a
universally used fill pattern for uninitialized memory in embedded systems
(not Qualcomm-specific -- used since the 1980s across IBM, Solaris, Linux,
etc.). Its presence here indicates firmware SRAM that was initialized with
the debug pattern but never written with real data.

**Possible debug sentinels (0x134, 0x13c):**
Value `0xCAFECACE` -- likely a debug/boot marker. The `0xCAFE____` family
of magic numbers is common in embedded firmware (cf. Java's `0xCAFEBABE`).
Not confirmed as a specific Qualcomm pattern.

**Repeated register blocks at 0x80000 stride:**
The same register layout appears at four base addresses:

| Base | WFSS-like regs | CE-like regs |
|------|---------------|--------------|
| `0x000000` | `0x003xxx` | `0x008xxx` |
| `0x080000` | `0x083xxx` | `0x088xxx` |
| `0x100000` | `0x103xxx` | `0x108xxx` |
| `0x180000` | `0x183xxx` | `0x188xxx` |

Values at corresponding offsets are similar or identical (e.g.,
`0x003008 = 0x00000004`, `0x103008 = 0x00000004`). This 4-instance layout
with 512KB stride across the 2MB BAR is consistent with multiple
hardware radio instances -- expected for Wi-Fi 7 (802.11be) which supports
Multi-Link Operation across 2.4/5/6 GHz bands. This is a structural
inference from the data, not from Qualcomm documentation.

### Key Takeaway

Reading certain BAR0 offsets causes CmpltTO, not just UnsupReq. The device
has regions where a read will hang the PCIe transaction and crash the
firmware. The exact triggering offset(s) have not yet been identified --
`dump-regs-fw.py` now includes per-chunk dmesg monitoring and bisect
guidance to locate them.

---

## 7. Next Steps

1. **Identify CmpltTO-triggering offsets:** Run `dump-regs-fw.py` with `--check-every 1 --verbose` on progressively narrower ranges to bisect the exact offset(s) that cause Completion Timeout. This is now the highest-priority recon task.

2. **Map the 4 hardware instances:** Confirm the 0x80000-stride register layout. Determine if all 4 instances have the same CmpltTO-triggering offsets or if some are safer.

3. **Write fuzzing of safe BAR0 registers:** Once CmpltTO offsets are known (and avoided), run save-fuzz-restore with test patterns on the remaining active offsets.

4. **DMA ring pointer corruption:** Target CE ring base/size registers (0x008xxx and mirror instances) to test for memory safety.

5. **Concurrent stress:** Fuzz BAR0 writes while the Wi-Fi interface is actively transmitting/receiving to expose race conditions.

6. **Power state + MMIO interaction:** Write to BAR0 registers immediately after forcing D3->D0 transitions to catch power management races.

---

## Appendix: Known Active BAR0 Offsets (First 50 of 130)

```
0x000000  0x000060  0x000068  0x000070  0x000078  0x00008c
0x0000a4  0x0000b8  0x000110  0x000124  0x000148  0x0001c4
0x000280  0x00028c  0x000294  0x0002a0  0x000364  0x00036c
0x000398  0x0003a0  0x0003a8  0x0003b0  0x000700  0x000708
0x000710  0x000a38  0x000a40  0x000b14  0x000b38  0x000b90
0x003008  0x0030d8  0x0030e8  0x0030fc  0x00310c  0x00313c
0x00316c  0x008000  0x008010  0x008020  0x008100  0x008110
0x008118  0x008200  0x008248  0x008290  0x008300  0x008600
0x008690  0x008700
```

The remaining 80 offsets are in higher BAR0 space and will be discovered at runtime by the targeted fuzzer.
