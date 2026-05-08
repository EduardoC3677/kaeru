.text

.global arch_clean_invalidate_cache_range
.type arch_clean_invalidate_cache_range, %function
arch_clean_invalidate_cache_range:
    add     x2, x0, x1
    mov     x3, #(CONFIG_CACHE_LINE - 1)
    bic     x0, x0, x3
1:
    dc      civac, x0
    add     x0, x0, #CONFIG_CACHE_LINE
    cmp     x0, x2
    blo     1b
    dsb     sy
    ret

.global arch_clean_cache_range
.type arch_clean_cache_range, %function
arch_clean_cache_range:
    add     x2, x0, x1
    mov     x3, #(CONFIG_CACHE_LINE - 1)
    bic     x0, x0, x3
1:
    dc      cvac, x0
    add     x0, x0, #CONFIG_CACHE_LINE
    cmp     x0, x2
    blo     1b
    dsb     sy
    ret

.global arch_sync_cache_range
.type arch_sync_cache_range, %function
arch_sync_cache_range:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    bl      arch_clean_invalidate_cache_range
    ic      iallu
    dsb     sy
    isb
    ldp     x29, x30, [sp], #16
    ret

.section .note.GNU-stack, "", %progbits
