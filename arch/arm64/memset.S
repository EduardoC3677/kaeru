.text

.global memset
.type memset, %function
memset:
    cbz     x2, 2f
    and     w1, w1, #0xff
    mov     x3, x0
1:
    strb    w1, [x3], #1
    subs    x2, x2, #1
    bne     1b
2:
    ret

.section .note.GNU-stack, "", %progbits
