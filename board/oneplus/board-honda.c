//
// SPDX-FileCopyrightText: 2026 KAERU Labs, S.L.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Board file for OnePlus Nord CE5 (codename: honda)
// SoC: MediaTek Dimensity 8350 (MT6897)
//
// Status: AArch64 scaffold. The kaeru runtime now compiles for ARM64
// (CONFIG_KAERU_ARM64) and emits AArch64-encoded patches via the
// primitives in <arch/arm64.h>. The early/late init hooks below are
// intentionally minimal until the function offsets exported in
// configs/oneplus/honda_defconfig are confirmed on real hardware.
//
// What was reverse-engineered from lk.img with capstone:
//
//   * The flashed lk partition is a CHAIN of 5 GFH-wrapped sub-images
//     plus 4 cert pairs:
//
//       slot                file range          code size  type
//       --------------------------------------------------------------
//       lk-stage-0          0x00000000-0x0017D1D0   0x17CFD0  AArch64 LK
//       cert pair 0         0x0017D1D0-0x0017E083    -         certs
//       lk-stage-1          0x0017E090-0x002A0318   0x122088  AArch64 LK
//       cert pair 1         0x002A0320-0x002A11D3    -         certs
//       lk-stage-2          0x002A11E0-0x003F6818   0x155438  AArch64 LK
//       cert pair 2         0x003F6820-0x003F76D3    -         certs
//       lk-stage-3 (DTBs)   0x003F76E0-0x0045A046   0x062766  payload + DTBs
//       cert pair 3         0x0045A050-0x0045AF03    -         certs
//       lk-stage-4 (final)  0x0045AF10-0x00792A38   0x337928  AArch64 LK (fastboot)
//       cert pair 4         0x00792A40-0x007938F3    -         certs
//
//   * Stage 0 is the EL1 entry shim: the very first instruction at
//     file offset 0x200 is `mrs x28, currentel`, followed by SCTLR_EL1
//     setup. This is NOT where fastboot lives.
//
//   * Stage 4 ("final" LK, ~3.4 MiB) holds the strings that drive the
//     fastboot command table:
//       "MT6897", "OnePlus", "fastboot", "OKAY", "FAIL", "INFO",
//       "reboot", "reboot-bootloader", "continue", "boot",
//       "download:", "flash:", "erase:", "getvar:",
//       "flashing unlock", "flashing lock",
//       "reboot-recovery", "reboot-fastboot",
//       "version", "version-bootloader", "version-baseband",
//       "secure", "unlocked", "max-download-size", "slot-count",
//       "current-slot", "serialno", "off-mode-charge",
//       "is-userspace", "dm_verity", "5 seconds".
//     This is the image kaeru must ultimately patch.
//
//   * Direct adrp+add cross-references to the canonical fastboot command
//     strings did NOT appear in stage 0; the fastboot dispatch logic
//     lives in stage 4. utils/parse_aarch64.py iterates each sub-image
//     and exports per-stage offsets.
//
// Until honda_defconfig has the final-LK offsets validated and the
// patch.py tool routes patches into the correct sub-image slot, the
// hooks below are deliberately empty so they cannot brick a device.

#include <board_ops.h>

void board_early_init(void) {
    printf("kaeru: honda (OnePlus Nord CE5 / MT6897) early init\n");
}

void board_late_init(void) {
    printf("kaeru: honda (OnePlus Nord CE5 / MT6897) late init\n");
}
