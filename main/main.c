//
// SPDX-FileCopyrightText: 2025-2026 Roger Ortiz <me@r0rt1z2.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <arch/arm.h>
#include <board_ops.h>
#include <main/main.h>

#ifdef CONFIG_KAERU_ARM64
typedef uint64_t lk_app_ptr_t;
#define LK_PTR_STEP   8
#define LK_APP_TARGET(fn)  ((lk_app_ptr_t)(uintptr_t)(fn))
#else
typedef uint32_t lk_app_ptr_t;
#define LK_PTR_STEP   4
#define LK_APP_TARGET(fn)  ((lk_app_ptr_t)(uintptr_t)(fn) | 1)
#endif

void kaeru_late_init(void) {
    OPTIONAL_INIT(sej_init);
    OPTIONAL_INIT(framebuffer_init);

    board_late_init();

#ifdef CONFIG_KAERU_ARM64
    ((void (*)(const struct app_descriptor*))(uintptr_t)CONFIG_APP_ADDRESS)(NULL);
#else
    ((void (*)(const struct app_descriptor*))(CONFIG_APP_ADDRESS | 1))(NULL);
#endif
}

void kaeru_early_init(void) {
    lk_app_ptr_t search_val = LK_APP_TARGET(CONFIG_APP_ADDRESS);
    uintptr_t start = CONFIG_BOOTLOADER_BASE;
    uintptr_t end = (uintptr_t)CONFIG_BOOTLOADER_BASE + CONFIG_BOOTLOADER_SIZE;
    uintptr_t ptr_addr = 0;

    print_kaeru_info(printf);
    common_early_init();
    board_early_init();

    for (uintptr_t addr = start; addr < end; addr += LK_PTR_STEP) {
        if (*(volatile lk_app_ptr_t*)addr == search_val) {
            ptr_addr = addr;
            break;
        }
    }

    if (ptr_addr != 0) {
        *(volatile lk_app_ptr_t*)ptr_addr = LK_APP_TARGET(kaeru_late_init);
        arch_clean_cache_range(ptr_addr, LK_PTR_STEP);
    } else {
        printf("Failed to patch mt_init_boot() pointer\n");
        printf("kaeru won't be able to run its late init!\n");
    }

#ifdef CONFIG_KAERU_ARM64
    ((void (*)(void))(uintptr_t)CONFIG_PLATFORM_INIT_ADDRESS)();
#else
    ((void (*)(void))(CONFIG_PLATFORM_INIT_ADDRESS | 1))();
#endif
}
