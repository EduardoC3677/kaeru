.text

.global memcpy
.type memcpy, %function
memcpy:
    cbz     x2, 2f
    mov     x3, x0
1:
    ldrb    w4, [x1], #1
    strb    w4, [x3], #1
    subs    x2, x2, #1
    bne     1b
2:
    ret

.section .note.GNU-stack, "", %progbits
