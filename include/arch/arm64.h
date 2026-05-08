#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#include <arch/cache.h>
#include <lib/string.h>

#define ARM_MODE(lr) "AArch64"

#define READ_SP(var)   asm volatile("mov %0, sp"           : "=r"(var))
#define READ_LR(var)   asm volatile("mov %0, x30"          : "=r"(var))
#define READ_CPSR(var) asm volatile("mrs %0, daif"         : "=r"(var))
#define READ_VBAR(var) asm volatile("mrs %0, vbar_el1"     : "=r"(var))

typedef enum { TARGET_AARCH64 } arm_mode_t;

#define AARCH64_NOP_INSN  0xD503201Fu
#define AARCH64_RET_INSN  0xD65F03C0u

static inline uint32_t aarch64_encode_b(uintptr_t pc, uintptr_t target) {
    int64_t off = (int64_t)target - (int64_t)pc;
    int32_t imm26 = (int32_t)(off >> 2);
    return 0x14000000u | ((uint32_t)imm26 & 0x03FFFFFFu);
}

static inline uint32_t aarch64_encode_bl(uintptr_t pc, uintptr_t target) {
    int64_t off = (int64_t)target - (int64_t)pc;
    int32_t imm26 = (int32_t)(off >> 2);
    return 0x94000000u | ((uint32_t)imm26 & 0x03FFFFFFu);
}

static inline uint32_t aarch64_encode_movz_w(uint32_t reg, uint16_t imm16) {
    return 0x52800000u | ((uint32_t)imm16 << 5) | (reg & 0x1F);
}

#define DECODE_BL_TARGET(addr)                                                   \
    ({                                                                           \
        uint32_t _w = *(volatile uint32_t *)(uintptr_t)(addr);                   \
        int32_t _imm26 = (int32_t)(_w & 0x03FFFFFFu);                            \
        if (_imm26 & (1 << 25)) _imm26 |= ~((1 << 26) - 1);                      \
        (uintptr_t)((uintptr_t)(addr) + ((int64_t)_imm26 << 2));                 \
    })

#define PATCH_CALL(addr, func, mode)                                             \
    do {                                                                         \
        (void)(mode);                                                            \
        volatile uint32_t *_p = (volatile uint32_t *)(uintptr_t)(addr);          \
        *_p = aarch64_encode_bl((uintptr_t)(addr), (uintptr_t)(func));           \
        arch_sync_cache_range((uintptr_t)(addr), 4);                             \
    } while (0)

#define PATCH_BRANCH(addr, func)                                                 \
    do {                                                                         \
        volatile uint32_t *_p = (volatile uint32_t *)(uintptr_t)(addr);          \
        *_p = aarch64_encode_b((uintptr_t)(addr), (uintptr_t)(func));            \
        arch_sync_cache_range((uintptr_t)(addr), 4);                             \
    } while (0)

#define PATCH_ALL_BL(func_addr, size, orig_func, hook)                           \
    ({                                                                           \
        int _count = 0;                                                          \
        uintptr_t _start = (uintptr_t)(func_addr);                               \
        uintptr_t _end = _start + (size);                                        \
        uintptr_t _orig = (uintptr_t)(orig_func);                                \
        for (uintptr_t _a = _start; _a < _end; _a += 4) {                        \
            uint32_t _w = *(volatile uint32_t *)_a;                              \
            if ((_w & 0xFC000000u) != 0x94000000u) continue;                     \
            if (DECODE_BL_TARGET(_a) == _orig) {                                 \
                PATCH_CALL(_a, (void *)(hook), TARGET_AARCH64);                  \
                _count++;                                                        \
            }                                                                    \
        }                                                                        \
        _count;                                                                  \
    })

#define PATCH_MEM(addr, ...)                                                     \
    do {                                                                         \
        const uint32_t _patch_data[] = {__VA_ARGS__};                            \
        volatile uint32_t *_p = (volatile uint32_t *)(uintptr_t)(addr);          \
        for (size_t _i = 0; _i < sizeof(_patch_data) / sizeof(_patch_data[0]);   \
             _i++) {                                                             \
            _p[_i] = _patch_data[_i];                                            \
        }                                                                        \
        arch_sync_cache_range((uintptr_t)(addr), sizeof(_patch_data));           \
    } while (0)

#define PATCH_MEM_ARM(addr, ...) PATCH_MEM(addr, __VA_ARGS__)

#define SEARCH_PATTERN(start_addr, end_addr, ...)                                \
    ({                                                                           \
        static uint32_t _pattern[] = {__VA_ARGS__};                              \
        const uintptr_t _pcount = sizeof(_pattern) / sizeof(_pattern[0]);        \
        uintptr_t _result = 0;                                                   \
        uintptr_t _max = (uintptr_t)(end_addr) - (_pcount * 4);                  \
        for (uintptr_t _o = (uintptr_t)(start_addr); _o < _max; _o += 4) {       \
            if (*(volatile uint32_t *)_o != _pattern[0]) continue;               \
            uintptr_t _i;                                                        \
            for (_i = 1; _i < _pcount; _i++) {                                   \
                if (*(volatile uint32_t *)(_o + _i * 4) != _pattern[_i]) break;  \
            }                                                                    \
            if (_i == _pcount) { _result = _o; break; }                          \
        }                                                                        \
        _result;                                                                 \
    })

#define SEARCH_PATTERN_ARM(start_addr, end_addr, ...)                            \
    SEARCH_PATTERN(start_addr, end_addr, __VA_ARGS__)

#define FORCE_RETURN(addr, value)                                                \
    do {                                                                         \
        PATCH_MEM((addr),                                                        \
                  aarch64_encode_movz_w(0, (uint16_t)((value) & 0xFFFF)),        \
                  AARCH64_RET_INSN);                                             \
    } while (0)

#define FORCE_RETURN_ARM(addr, value) FORCE_RETURN(addr, value)

#define NOP(addr, count)                                                         \
    do {                                                                         \
        volatile uint32_t *_p = (volatile uint32_t *)(uintptr_t)(addr);          \
        for (int _i = 0; _i < (count); _i++) _p[_i] = AARCH64_NOP_INSN;          \
        arch_sync_cache_range((uintptr_t)(addr), (count) * 4);                   \
    } while (0)

#define NOP_ARM(addr, count) NOP(addr, count)
