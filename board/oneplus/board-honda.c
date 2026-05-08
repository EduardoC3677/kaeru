//
// SPDX-FileCopyrightText: 2026 KAERU Labs, S.L.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Board support stub for OnePlus Nord CE5 (codename: honda)
// SoC: MediaTek Dimensity 8350 (MT6897)
//
// !!! IMPORTANT - READ BEFORE FLASHING !!!
//
// This board entry is a SCAFFOLD only. It compiles, but the early/late
// init hooks below are deliberately empty: kaeru's payload is built for
// ARMv7 / Thumb-2 Little Kernel images and the OnePlus Nord CE5 ships
// an AArch64 LK. The patch primitives provided by kaeru (SEARCH_PATTERN,
// FORCE_RETURN, NOP, ...) emit Thumb-2 encodings that are not valid in
// AArch64 and will brick the device if applied blindly.
//
// Verified facts about this LK image (from utils/parse.py and capstone
// disassembly performed during initial port):
//   - Magic at file offset 0x00:    88 16 88 58 (MTK GFH FILE_INFO)
//   - First instruction at 0x200:   mrs x28, currentel  (AArch64 EL1 init)
//   - Code size from GFH header:    0x17CFD0 bytes
//   - SoC string in image:          "MT6897" @ file offset 0x0C5C85
//   - Vendor string in image:       "OnePlus" @ file offset 0x0D9086
//   - Warning strings present:      "orange", "yellow", "dm_verity",
//                                    "5 seconds", "verification",
//                                    "fastboot mode", "unlocked"
//
// To make this port real, the following work is required and is NOT
// done by this commit:
//   1. Port the kaeru payload (lib/, stage1/, arch/) to AArch64. The
//      relocation entry, hook trampoline and patch primitives must be
//      reimplemented in 64-bit instructions.
//   2. Locate AArch64 entry points for fastboot_publish, fastboot_okay,
//      fastboot_fail, fastboot_info, fastboot_register, mtk_detect_key,
//      platform_init, video_printf, etc. Existing parse.py signatures
//      are Thumb-2 byte patterns and will not match.
//   3. Verify SoC base addresses (SECURITY_AO_BASE, SEJ_BASE, UART_BASE,
//      WDT_BASE) for MT6897. The defaults inherited in soc/Kconfig were
//      copied from the legacy MTK common values and have NOT been
//      validated for the Dimensity 8350.
//
// Until step 1 is completed, this board file MUST NOT call any of the
// SEARCH_PATTERN / FORCE_RETURN / NOP macros against the OnePlus image.
// Doing so will produce a non-functional bootloader.
//

#include <board_ops.h>

void board_early_init(void) {
    // Intentionally empty. AArch64 LK port is required before any
    // patches can be applied. See file header for details.
    printf("kaeru: honda (OnePlus Nord CE5 / MT6897) early init stub\n");
}

void board_late_init(void) {
    // Intentionally empty. AArch64 LK port is required before any
    // patches can be applied. See file header for details.
    printf("kaeru: honda (OnePlus Nord CE5 / MT6897) late init stub\n");
}
