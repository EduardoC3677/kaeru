#ifdef CONFIG_KAERU_ARM64

.section .text.start, "ax"
.global main
.type main, %function
main:
    stp     x29, x30, [sp, #-32]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]

    adr     x0, .Lreloc_anchor
    ldr     x1, =.Lreloc_anchor
    sub     x19, x0, x1

    ldr     x0, =__got_start
    ldr     x1, =__got_end
    add     x0, x0, x19
    add     x1, x1, x19

.Lreloc_loop:
    cmp     x0, x1
    b.ge    .Lreloc_done
    ldr     x2, [x0]
    cbz     x2, .Lreloc_skip
    add     x2, x2, x19
    str     x2, [x0]
.Lreloc_skip:
    add     x0, x0, #8
    b       .Lreloc_loop

.Lreloc_done:
    cbz     x19, .Lbss_clear
    ldr     x0, =__got_start
    ldr     x1, =__got_end
    add     x0, x0, x19
    sub     x1, x1, x0
    bl      arch_clean_invalidate_cache_range

.Lbss_clear:
    ldr     x0, =__bss_start
    ldr     x1, =__bss_end
    sub     x2, x1, x0
    mov     x1, #0
    bl      memset

    bl      kaeru_early_init

    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret

    .align 3
.Lreloc_anchor:
    .quad   0

.section .note.GNU-stack, "", %progbits

#else /* !CONFIG_KAERU_ARM64 */

.syntax unified
.thumb

.section .text.start, "ax"
.global main
.thumb_func
main:
    push    {r4, lr}

    adr     r0, 1f
    ldr     r1, =1f
    subs    r4, r0, r1
    beq     .Lno_reloc

    ldr     r0, =__got_start
    ldr     r1, =__got_end
    adds    r0, r0, r4
    adds    r1, r1, r4

.Lreloc_loop:
    cmp     r0, r1
    bge     .Lreloc_done
    ldr     r2, [r0]
    cbz     r2, .Lreloc_skip
    adds    r2, r2, r4
    str     r2, [r0]
.Lreloc_skip:
    adds    r0, #4
    b       .Lreloc_loop

.Lreloc_done:
    ldr     r0, =__got_start
    ldr     r1, =__got_end
    adds    r0, r0, r4
    subs    r1, r1, r0
    bl      arch_clean_invalidate_cache_range

.Lno_reloc:
    ldr     r0, =__bss_start
    ldr     r1, =__bss_end
    sub     r2, r1, r0
    mov     r1, #0
    bl     memset
.Lbss_done:
    bl      kaeru_early_init

    pop     {r4, pc}

    .align 2
1:  .word 0

.section .note.GNU-stack, "", %progbits

#endif /* CONFIG_KAERU_ARM64 */
