.text

.global memchr
.type memchr, %function
memchr:
    cbz     x2, 2f
    and     w1, w1, #0xff
1:
    ldrb    w3, [x0]
    cmp     w3, w1
    beq     3f
    add     x0, x0, #1
    subs    x2, x2, #1
    bne     1b
2:
    mov     x0, #0
3:
    ret

.section .note.GNU-stack, "", %progbits
