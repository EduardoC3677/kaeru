# `lk.img` analysis report

This document is the result of running [`utils/extract_fastboot.py`](../utils/extract_fastboot.py) and a Capstone disassembly pass against the `lk.img` shipped at the root of this repository, plus a string-level inspection of the matching `pl.img` (preloader). The extractor handles both AArch64 and ARMv7-Thumb LK builds.

> **Reproduce:** `pip install -r utils/requirements.txt && python3 utils/extract_fastboot.py lk.img`

## 1. Image identification

| Field | Value |
| --- | --- |
| Container magic | `0x58881688` (`mkimage` / MTK BL header) |
| Partition name | `lk` |
| Code size | `0x17CFD0` (≈ 1.49 MiB) |
| Architecture | **AArch64** (`MRS x28, currentel` at entry, fixed 4-byte instructions) |
| Trailing partitions | `cert1` (1733 B), `cert2` (995 B) — signing certificates |
| SoC family (from `pl.img` strings) | **MT6897 / Dimensity 9300** (`mt6363`, `mt6375`, `mt6319`, `mt6685` PMIC family, `CHIP_SEGMENT_CODE`) |
| Product string | `k6897v1_64` (MTK reference platform identifier) |

The kaeru payload itself targets ARMv7-Thumb LK builds (see [README.md](../README.md)), so `lk.img` here is supplied **as a sample / regression input** for the analysis tooling rather than as a kaeru build target. `utils/parse.py` is the right tool for ARMv7 LK; this document plus `utils/extract_fastboot.py` cover the AArch64 case.

## 2. Detected fastboot ABI

The script seeds a list of well-known command/variable strings (`reboot`, `flash:`, `oem unlock`, `product`, `secure`, ...) and walks every ADRP+ADD load that resolves to a seed string forward to the next `BL`. The most-frequent target of those branches is the corresponding bootloader callback:

| Symbol | Inferred file offset (relative to base) | Confidence |
| --- | --- | --- |
| `fastboot_register(name, handler, sec_flag, ?)` | `0x000082C0` | High (3 distinct seed-string callers) |
| `fastboot_publish(name, value)` | `0x00008384` | High (10 distinct seed-string callers, builds linked list at `[adrp #0x180000, #0x150]`) |
| `fastboot_publish_attr(name, attr_value)` *(secondary publish path)* | `0x0000840C` | Medium |
| `fastboot_getvar(name)` lookup | `0x00008464` | High (read-only walk of the same linked list) |

Disassembling each helper confirms the prototype:

```
0x82C0  stp    x29, x30, [sp,#-0x40]!     ; classic 4-arg prologue
0x82D4  mov    x23, x0                    ; save name
0x82E0  mov    w20, w3                    ; save security flag
0x82E4  mov    w19, w2                    ; save extra flag
0x82E8  mov    x21, x1                    ; save handler
        ...                              ; bl malloc(0x28); fill struct
```

```
0x8384  stp    x29, x30, [sp,#-0x20]!     ; 2-arg publish prologue
0x8390  cbz    x1, ...                    ; null-check value
0x83C0  adrp   x8, #0x180000              ; load head pointer of var list
0x83CC  str    x0, [x8, #0x150]           ; insert at head
```

## 3. Static fastboot commands

Recovered from the call sites of `fastboot_register`. Every entry is the literal first argument passed at call time:

| Call site | Command string |
| --- | --- |
| `0x008DD4` | `getvar:` |
| `0x008DF0` | `reboot` |
| `0x008E0C` | `reboot-bootloader` |
| `0x008E28` | `reboot-fastboot` |
| `0x008E44` | `reboot-recovery` |
| `0x008E60` | `continue` |
| `0x008E7C` | `set_active:` |
| `0x00A730` | `download:` |
| `0x00A74C` | `flash:` |
| `0x00A768` | `erase:` |
| `0x00A788` | `oem ultraflash:` |
| `0x00A7A4` | `oem ultraflash_en` |

Notes:

- `oem ultraflash:` / `oem ultraflash_en` are **the only OEM commands registered through the standard `fastboot_register` path** — they appear to be MTK's bulk-flash extension. Other `oem ...` strings (see §6) are dispatched through a separate OEM-command table whose registrations live in code paths not reachable through the seed-and-cross-reference heuristic.
- `set_active:` and the absence of `oem unlock` / `oem lock` / `flashing unlock` strongly suggest unlocking is gated through `getvar` + `oem device-info` + signed unlock-token rather than a free `oem unlock` (typical Android-12+ MTK behaviour).

## 4. Static fastboot variables (`fastboot_publish`)

20 distinct names registered via `fastboot_publish`. `?` means the second argument is a runtime expression (e.g. `mov x1, x0` from a previous `bl`, an `add x1, sp, #N` snprintf buffer, or a `csel` ternary) and therefore not statically resolvable. Two are concrete literals:

| Variable | Value (or source) |
| --- | --- |
| `version` | `'0.5'` |
| `version-bootloader` | runtime |
| `max-download-size` | runtime |
| `product` | `'k6897v1_64'` |
| `serialno` | runtime (read from device) |
| `is-userspace` | runtime (probably `'no'` constant gated by build flag) |
| `protocol_version` | runtime |
| `version-baseband` | runtime |
| `current-slot` | runtime (`_a` / `_b`) |
| `slot-count` | runtime (`%d` formatted) |
| `slot-unbootable:a` | runtime |
| `slot-unbootable:b` | runtime |
| `slot-successful:a` | runtime |
| `slot-successful:b` | runtime |
| `slot-retry-count:a` | runtime |
| `slot-retry-count:b` | runtime |
| `off-mode-charge` | runtime |
| `secure` | runtime — at one site `'yes'` is the published value (callee `0x840C`, `+0x0B4B90`) |
| `unlocked` | runtime |
| `warranty` | runtime |

The presence of slot-* variables confirms this LK supports **A/B partitioning**.

## 5. Boot modes & key combinations

Heuristically extracted strings that anchor MTK boot-mode switching and key-detection paths. Each entry is a verbatim string in `lk.img` `.rodata`:

| File offset | String | Meaning |
| --- | --- | --- |
| `0x0C97D6` | `FASTBOOT MODE\n` | banner printed when entering fastboot |
| `0x0E8A17` | `FASTBOOT mode...\n` | secondary banner (bootmode handler) |
| `0x0CB354` | `home key is pressed\n` | home / camera-key combo log |
| `0x0D91EF` | `power key is pressed\n` | power-key debounce log |
| `0x0D06DB` | `boot_mode_check:allow enter kpoc` | KPOC = *Kernel Power-Off Charging* |
| `0x0D5EEF` | `boot_mode_check:kpoc` | runtime branch into KPOC |
| `0x0DE62D` | `boot_mode_check:not allow enter kpoc` | gating decision |
| `0x0E41B3` | `boot_mode_check:tvu batt status false` | TVU = battery-status guard |
| `0x0DFCCD` | `boot_mode_check:g_boot_mode is set %u\n` | global `g_boot_mode` writes |
| `0x0E71C6` | `boot_mode_check:g_boot_mode is modified here %u\n` | secondary bootmode override |
| `0x0EE55C` | `boot_mode_hook` (`platform_pl_boottags_boot_mode_hook`) | hook used by DTB writer |
| `0x0F0640` | `[FASTBOOT] Start reset dm-verity status.` | dm-verity reset path |

The combination `mtk_detect_key` / `home key`/`power key`/`volume up`/`volume down` follows the documented MTK convention:

| Held key combo at power-on | Resulting `g_boot_mode` (typical for this SoC line) |
| --- | --- |
| **Volume Up + Power** | `RECOVERY_BOOT` |
| **Volume Down + Power** | `FASTBOOT` (this LK explicitly handles fastboot entry) |
| **Volume Up + Volume Down + Power** | `FACTORY_BOOT` / `META_BOOT` (factory tooling) |
| AC charger inserted, no key | `KERNEL_POWER_OFF_CHARGING_BOOT` (KPOC, gated by `boot_mode_check:allow enter kpoc`) |
| RTC alarm wakeup | `ALARM_BOOT` |

The actual key-table address could not be resolved statically because `g_boot_mode` is at `[adrp #0x180000, #...]` (BSS) and is written through indirect stores; this is documented in the existing kaeru wiki under the *bootmode address* section, and the kaeru `Kconfig` option `CONFIG_BOOTMODE_ADDRESS` is exactly the manual override for it.

## 6. Hidden / OEM-style commands

Strings beginning with `oem ` found anywhere in the binary. Those *not* listed in §3 are **dispatched through a different mechanism** (typically a static `oem_cmd_table[]` populated by an `__attribute__((section))` array, or a switch on `strncmp` inside the `oem ` handler) — they are real, callable commands but the kaeru-style `fastboot_register` heuristic does not catch them:

| File offset | String | Notes |
| --- | --- | --- |
| `0x0C5093` | `oem get_key` | dump key fuse / FRP key |
| `0x0C745D` | `oem off-mode-charge` | toggle KPOC behaviour |
| `0x0C7E28` | `oem ultraflash_en` | also exposed via `fastboot_register` |
| `0x0C8CAC` | `oem mrdump_chkimg` | MRDump (kernel-crash) image check |
| `0x0CBBE8` | `oem printk-ratelimit` | toggle dprintf rate-limit |
| `0x0CBC36` | `oem cdms` | CDMS sub-command (Mediatek diagnostic) |
| `0x0CE51C` | `oem mrdump_out_set` | MRDump output partition |
| `0x0D3F9C` | `oem usb2jtag` | enable USB2JTAG bridge — **JTAG-over-USB on the bootloader** |
| `0x0D3FA9` | `oem mrdump_fallocate` | MRDump pre-allocate |
| `0x0D6CDB` | `oem p2u` | "preloader-to-userspace" log dump |
| `0x0D8483` | `oem get_socid` | print SoC unique HUID |
| `0x0DBAC5` | `oem set_enckey` | program data-encryption key |
| `0x0E1302` | `oem ultraflash:` | bulk-flash entry |
| `0x0E685A` | `oem dump_pllk_log` | dump preloader+LK ring buffer |
| `0x0E7F1E` | `oem test_seccfg_lockstate` | inspect seccfg lock state |

The `oem usb2jtag`, `oem set_enckey`, `oem mrdump_*`, `oem get_socid` and `oem test_seccfg_lockstate` commands are **the most security-relevant hidden commands** — they expose JTAG, key programming, and lock-state introspection. On a production-locked device most of them are gated by the `secure`/`unlocked` flag passed as the third argument to `fastboot_register`.

## 7. Preloader (`pl.img`) information

The shipped `pl.img` uses the Mediatek **MMM** container format (magic `0x4D4D4D01`, `FILE_INFO` block). String inspection confirms:

- **SoC PMIC stack:** `mt6363` (main PMIC), `mt6375` (charger), `mt6319` (sub-PMIC), `mt6685` (audio/clock) — consistent with MT6897/Dimensity 9300.
- **A/B preloader support:** strings `Current boot: Preloader_a` / `Preloader_b`.
- **BROM / DA download path:**
  - `usbdl_jump_da: %x`
  - `usbdl_send_da: clean invalid da`
  - `usbdl_verify_da: da_len (0x%x) is less than sig_len (0x%x)`
  - `emergency download mode(timeout: %ds).`
- **Power-up reasons (`bootreason` enumeration):**
  - `Power key boot!`
  - `RTC boot!`
  - `USB/charger boot!`
  - `WDT normal boot!`
  - `WDT reboot bypass power key!`
  - `Unknown boot!`
  - `Enumeration(Skip): powerkey pressed`
- **Force-shutdown combo:** `pmic: long press power & vol+ key shutdown!` — confirms the Power + Vol-Up long-press hard-reset combination handled in the PMIC.
- **Continuous-reboot guard:** `continue reboot, pl force full pmic reset!`
- **Per-slot AVB/`oplusreserve1`:** `get_oplusreserve1_add_for_noboot` — Oplus-customised partition layout ⇒ this image is from an **Oppo / OnePlus / Realme** device build.

## 8. Limitations

- **String-pointer tables in `.data` are not yet followed.** Hidden OEM commands registered through static tables (e.g. `static const oem_cmd_t cmds[] = {...}`) are detected via the string content (§6) but their handler addresses are not resolved.
- **Runtime values for `fastboot_publish` are reported as `?`.** Many of those values come from heap-allocated `snprintf` buffers (e.g. `add x1, sp, #0xc`); recovering them would require modelling the format strings and argument flow, which is out of scope for a static disassembler pass.
- **Base load address is not deduced** because every reference inside the image is PC-relative; the analyzer works in image-relative offsets and never needs the absolute base. Per-device boards in `board/` carry the right `CONFIG_BOOTLOADER_BASE` for downstream tooling.
- **Key-combination → bootmode mapping** is reported per the documented MTK convention. The exact `mtk_detect_key` table for this SoC was not statically located; if needed, place a hardware breakpoint on `g_boot_mode` (see kaeru wiki) and observe at runtime.

## 9. Files added / changed by this analysis

- [`utils/extract_fastboot.py`](../utils/extract_fastboot.py) — new Capstone-based extractor for AArch64 LK images.
- [`docs/lk-analysis.md`](./lk-analysis.md) — this report.
