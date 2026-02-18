# Backlog

Prioritized work items for PCI fuzz testing of the Qualcomm WCN785x (FastConnect 7800).

## P0 — Critical Path

### 1. Bisect CmpltTO offset(s)
Run `bar0_bisect_sweep.py` to identify the exact BAR0 offset(s) that trigger Completion Timeout and crash the firmware. Start with the full 2 MB range, 64 KB chunks.

### 2. Map CmpltTO across 4 hardware instances
The 2 MB BAR contains 4 instances at 0x80000 stride. Once crash offsets are found in instance 0, verify whether the same relative offsets crash instances 1-3.

### 3. Write-fuzz safe BAR0 registers
With the crash-triggering offsets identified, run `bar0_fuzz.py` against the remaining safe registers to characterize write behavior (sticky vs masked, side effects).

## P1 — Attack Scenarios

### 4. CE ring pointer corruption
Target the Copy Engine ring base/head/tail pointer registers (cluster `ce_high`, 0x8000-0x8700) with crafted values to test for DMA-related vulnerabilities.

### 5. Concurrent Wi-Fi stress testing
Fuzz BAR0 registers while the Wi-Fi interface is active (associated, passing traffic) to test firmware robustness under real workload.

## P2 — Extended Testing

### 6. Power state + MMIO interaction
Test MMIO access patterns across PCIe power state transitions (D0 → D3hot → D0) and ASPM L0s/L1 states.

### 7. Firmware SRAM investigation
After a crash, the BAR0 exposes raw firmware SRAM contents. Map and analyze the post-crash memory layout for information leakage (keys, state, debug data).
