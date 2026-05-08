# Reverse engineering notes — `lk.img` (OnePlus Nord CE5 / MT6897)

Author of these notes: KAERU Labs port for the OnePlus Nord CE5 (codename
`honda`).

This file documents what the AArch64 port of kaeru learned about the
factory bootloader image shipped on the Nord CE5 so that the next person
to touch this port does not have to start from zero (and does not brick a
device).

## TL;DR

`lk.img` is **not** a single Little Kernel binary. It is a chain of five
GFH-wrapped AArch64 LK stages with X.509 certificate pairs interleaved
between every stage. The kaeru runtime that lived in this repo was an
ARMv7/Thumb-2 payload; this port adds the AArch64 build target plus an
analysis tool (`utils/parse_aarch64.py`) that classifies every sub-image
and looks for the fastboot helpers, but it deliberately **does not ship
patches yet** because the offsets in the fastboot stage cannot be derived
purely statically.

## Layout of `lk.img`

`utils/parse_aarch64.py` walks every `8816 8858` ("GFH FILE_INFO") record
in the image and reports the layout below for the Nord CE5 dump used to
develop this port:

| slot | file range                | code size  | classified as  |
| ---- | ------------------------- | ---------- | -------------- |
| 0    | `0x00000000`–`0x0017D1D0` | `0x17CFD0` | aarch64-lk     |
| 1    | `0x0017D1D0`–`0x0017DA95` | `0x000006C5` | cert         |
| 2    | `0x0017DAA0`–`0x0017E083` | `0x000003E3` | cert         |
| 3    | `0x0017E090`–`0x002A0318` | `0x00122088` | aarch64-lk   |
| 4    | `0x002A0320`–`0x002A0BE5` | `0x000006C5` | cert         |
| 5    | `0x002A0BF0`–`0x002A11D3` | `0x000003E3` | cert         |
| 6    | `0x002A11E0`–`0x003F6818` | `0x00155438` | aarch64-lk   |
| 7    | `0x003F6820`–`0x003F70E5` | `0x000006C5` | cert         |
| 8    | `0x003F70F0`–`0x003F76D3` | `0x000003E3` | cert         |
| 9    | `0x003F76E0`–`0x0045A046` | `0x00062766` | dtb payload  |
| 10   | `0x0045A050`–`0x0045A915` | `0x000006C5` | cert         |
| 11   | `0x0045A920`–`0x0045AF03` | `0x000003E3` | cert         |
| 12   | `0x0045AF10`–`0x00792A38` | `0x00337928` | aarch64-lk   |
| 13   | `0x00792A40`–`0x00793305` | `0x000006C5` | cert         |
| 14   | `0x00793510`–`0x007938F3` | `0x000003E3` | cert         |

## What each AArch64 LK stage is

* **Stage 0** (`0x200`+`0x17CFD0`). The very first instruction at file
  offset `0x200` is `mrs x28, currentel`, immediately followed by
  `SCTLR_EL1` setup, `cpacr_el1` configuration and a 64-bit virtual
  address load via `adrp x21, ...`. This is the **EL1 entry shim**: it
  is the first thing the BootROM hands control to. It does not run
  fastboot, it does not implement the unlock policy, and patching it is
  almost certainly not what kaeru needs to do.

* **Stage 3** (`0x17E290`+`0x122088`). Smaller LK-style sub-image, very
  few fastboot strings; mostly `boot` and `off-mode-charge`. Likely a
  charger / battery-display intermediate stage.

* **Stage 6** (`0x2A13E0`+`0x155438`). **This is the fastboot stage.**
  It contains every canonical fastboot command string (`reboot`,
  `reboot-bootloader`, `continue`, `boot`, `download:`, `flash:`,
  `erase:`, `getvar:`, `flashing unlock`, `flashing lock`,
  `reboot-recovery`, `reboot-fastboot`) plus every getvar publishing
  variable (`version`, `version-bootloader`, `secure`, `unlocked`,
  `product`, `max-download-size`, `slot-count`, `current-slot`,
  `serialno`, `off-mode-charge`, `is-userspace`). When the kaeru port
  is finally wired up, this is the sub-image whose code section needs
  to be patched.

* **Stage 9**. DTB carrier — contains a string of `d00dfeed` magics,
  one DTB per board variant.

* **Stage 12** (`0x45AF10`+`0x337928`). Largest sub-image. Contains a
  duplicate copy of many of the rodata strings present in stage 6.
  Likely the second-stage / GUI / recovery slot. Not relevant to the
  fastboot port.

## Fastboot strings are not loaded by direct `adrp+add`

For each fastboot command string in stage 6 we ran capstone over every
4-byte slot, decoded `adrp xN, page` followed by `add xN, xN, #lo12`,
and counted how many of those resolved to one of the canonical command
strings. The result: exactly **1 hit in stage 6**, and it was a load
of `"version-bootloader"` into `x2` (the *helpline* argument), not into
`x0` (the *command* argument).

The conclusion: the LK build that ships on the Nord CE5 holds its
fastboot command table as a statically initialized array of
`{const char *cmd, const char *helpline, void (*fn)(args, data, sz)}`
records in `.data.rel.ro`. The pointers there are 64-bit absolute
addresses that the LK loader fixes up via its `.rela.dyn` relocations
at boot. They are not visible to a static disassembler that only walks
PC-relative instruction encodings.

This means recovering each handler's address requires either:

  * dumping `lk.img` *after the loader has applied relocations* (run
    on hardware, dump from RAM); or
  * locating the `.rela.dyn` section of stage 6 and applying the
    relocations off-line, which in turn requires recovering the
    section table, which the GFH wrapper has stripped.

Both approaches are out of scope for a static port. The pragmatic next
step is to take the unpatched stage-6 binary, load it into a real LK
emulator (or read RAM after `aboot_init` runs on hardware) and dump the
fully-relocated `.data.rel.ro` table.

## What this PR actually changes

* Adds a working AArch64 build target to kaeru:
  * `arch/arm64/{cache-ops.S, linker.lds.S, memset.S, memcpy.S, memchr.S, Makefile}`
  * `include/arch/arm64.h` — AArch64 patch primitives (`PATCH_CALL`,
    `PATCH_BRANCH`, `PATCH_MEM`, `PATCH_ALL_BL`, `SEARCH_PATTERN`,
    `FORCE_RETURN`, `NOP`).
  * `arch/Kconfig` — architecture choice (`KAERU_ARM` vs
    `KAERU_ARM64`). MT6897 selects the latter.
  * Top-level `Makefile` switches `CROSS_COMPILE` to
    `aarch64-linux-gnu-` and replaces `-mthumb -mcpu=cortex-a15` with
    `-mcpu=cortex-a55+nocrypto -mgeneral-regs-only -mcmodel=small`
    when building for AArch64.
  * `main/start.S` gains an AArch64 entry point that performs the
    same GOT relocation loop as the ARMv7 entry, in 64-bit
    instructions, before jumping to `kaeru_early_init`.
  * `main/main.c` uses `uintptr_t` and a 64-bit pointer step on
    AArch64 when scanning for the LK app pointer to patch.
  * `lib/common.c`, `include/lib/common.h` — printf format strings
    and cache-flush casts switched to `uintptr_t` so 64-bit pointers
    are not silently truncated.

* Adds `utils/parse_aarch64.py`, a chained-GFH-aware analyzer that:
  * iterates every `GFH FILE_INFO` record and classifies each one;
  * for every AArch64 LK sub-image, walks the prologues, builds an
    `adrp`+`add`/`ldr` resolver, scores fastboot/getvar string
    references, and emits per-stage findings as JSON;
  * picks the highest-scoring stage as the fastboot stage and writes
    `CONFIG_FASTBOOT_LK_STAGE_OFFSET` etc. into the defconfig **only
    when there is high-confidence signal**. For the Nord CE5 image
    the analyzer correctly identifies stage 6 as the fastboot stage
    but does not invent function offsets, because the static analysis
    cannot recover them.

* `board/oneplus/board-honda.c` is updated with the verified RE
  layout and the explicit constraint that the early/late init hooks
  must remain empty until the stage-6 offsets are confirmed on
  hardware. The risk being avoided is the previous PR's risk:
  shipping AArch64 patches at addresses derived from stage 0, which
  is not the fastboot stage.

* `configs/oneplus/honda_defconfig` selects `CONFIG_KAERU_ARM64=y`
  alongside the existing MT6897 / ONEPLUS_HONDA selections so that a
  build for `honda` produces an AArch64 ELF rather than a 32-bit
  Thumb-2 ELF.

## What still needs to be done

1. **Stage selector in the patcher.** `utils/patch.py` (not modified
   by this PR) currently treats `lk.img` as a single image and
   patches at `CONFIG_BOOTLOADER_BASE`. For the chained MTK image it
   needs to:
   * Iterate the GFH chain, find the sub-image whose `code_off`
     matches `CONFIG_FASTBOOT_LK_STAGE_OFFSET`, and apply the
     payload patches inside that sub-image only.
   * Re-sign / re-checksum the affected GFH FILE_INFO header (MTK
     GFH carries a CRC32 / signature that the bootrom verifies on
     all but engineering devices).

2. **Resolve the relocated fastboot table.** Boot the unmodified
   image on real hardware, dump the contents of stage 6's load
   region after `aboot_init`, and use the dumped `.data.rel.ro` to
   write `CONFIG_FASTBOOT_REGISTER_ADDRESS`,
   `CONFIG_FASTBOOT_PUBLISH_ADDRESS`, `CONFIG_FASTBOOT_OKAY_ADDRESS`,
   `CONFIG_FASTBOOT_FAIL_ADDRESS`, `CONFIG_FASTBOOT_INFO_ADDRESS`,
   `CONFIG_MTK_DETECT_KEY_ADDRESS`, `CONFIG_PLATFORM_INIT_ADDRESS`,
   `CONFIG_APP_ADDRESS`.

3. **MT6897 register map.** The `SECURITY_AO_BASE`, `SEJ_BASE`,
   `UART_BASE` and `WDT_BASE` defaults inherited from the legacy
   MTK common Kconfig entry are placeholders. They must be checked
   against the Dimensity 8350 reference manual / device tree before
   any driver in `drivers/` is enabled for `honda`.

4. **AArch64 SEJ port.** `lib/libsej/sej.c` uses 32-bit MMIO macros
   and 32-bit register values. The hardware block is unchanged, so
   the port is mostly a matter of switching `OUTREG32`/`INREG32` to
   `writel`/`readl` and updating the base address. Until then,
   `CONFIG_LIBSEJ_SUPPORT` should remain unset for `honda`.

5. **Stage1 loader.** Stage 1 (`stage1/`) is also written for
   ARMv7. For an AArch64 device that needs the stage-1 mechanism
   (very large board file, limited LK heap window), the stage-1
   relocator and `lkloader.c` payload also need an AArch64 port.
   For `honda` it is left disabled for now.
