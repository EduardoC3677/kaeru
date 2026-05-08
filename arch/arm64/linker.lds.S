OUTPUT_FORMAT("elf64-littleaarch64", "elf64-bigaarch64", "elf64-littleaarch64")
OUTPUT_ARCH(aarch64)

ENTRY(main)

SECTIONS
{
    .text :
    {
        *(.text.start)
        *(.text.main)
        *(.text .text.* .gnu.linkonce.t.*)
    }

    .rodata :
    {
        *(.rodata .rodata.* .gnu.linkonce.r.*)
    }

    .got :
    {
        __got_start = .;
        *(.got .got.*)
        __got_end = .;
    }

    .data :
    {
        *(.data .data.* .gnu.linkonce.d.*)
    }

    .bss ALIGN(8) : {
        __bss_start = .;
        *(.bss)
        *(.bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /DISCARD/ :
    {
        *(.ARM.exidx*)
        *(.ARM.attributes*)
        *(.note.gnu.build-id)
        *(.note.GNU-stack)
        *(.eh_frame*)
        *(.interp)
        *(.dynsym)
        *(.dynstr)
        *(.hash)
        *(.gnu.hash)
        *(.dynamic)
        *(.comment)
    }
}
