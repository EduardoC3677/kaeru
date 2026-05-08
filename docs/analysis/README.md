# Firmware analysis - dumped device images

This directory documents the analysis of the device firmware images that were
checked into the repository root (`lk.img`, `pl.img`, `scp.img`,
`mmcblk0boot[01].bin`, `seccfg.img`, `vendor_boot.img`, `boot_para.img`,
`para.img`, `vb.img`, `oplus_custom.img`, `oplusreserve1.img`).

The analysis was requested in [issue #5][issue]. All findings are derived
purely from static inspection of the binaries with [Capstone][capstone] and
string extraction; no device was flashed and no runtime data was collected.

> **Note** - these images are device-specific dumps from one user's handset
> and are **not part of the kaeru source tree**. They were committed by an
> earlier contributor and remain in the tree only to keep the analysis
> reproducible. They are not redistributable in the general sense and you
> should treat anything derived from them as informational only.

## Reproducing the analysis

The helper script [`scripts/analysis/analyze_lk.py`](../../scripts/analysis/analyze_lk.py)
performs container detection, capstone disassembly (AArch64/ARMv7 auto-detect)
and string-classification in one pass.

```bash
pip install capstone

# Full Markdown report on lk.img
python3 scripts/analysis/analyze_lk.py lk.img

# Write the full disassembly to disk
python3 scripts/analysis/analyze_lk.py lk.img --disasm lk.S

# Strings-only summary of the SCP firmware
python3 scripts/analysis/analyze_lk.py scp.img --no-disasm
```

## Documents

| File | Contents |
| --- | --- |
| [`lk.md`](./lk.md) | Deep dive into `lk.img` - SoC, fastboot commands, OEM subcommands, getvar variables, boot modes, key combinations, hidden / debug features. |
| [`firmware-overview.md`](./firmware-overview.md) | Container summary for every dumped `.img` / `.bin`, including the SCP firmware, preloader, EMMC boot partitions, AVB / vbmeta, and OPLUS-reserved partitions. |

## Top-level findings

* The dumped `lk.img` is an **AArch64** Little Kernel for the
  **MediaTek MT6897 (Dimensity 9300)** platform, customised by **OPLUS /
  OnePlus**. kaeru's main payload targets **ARMv7** LK and therefore
  **cannot be applied to this image as-is** - support for AArch64 LK is a
  separate porting effort.
* The bootloader exposes the standard Android fastboot command surface
  (`flash:`, `erase:`, `getvar:`, `download:`, `boot`, `continue`,
  `set_active:`, `reboot{,-bootloader,-recovery,-fastboot}`) plus a set of
  vendor `oem ...` commands documented in [`lk.md`](./lk.md).
* Boot-mode entry uses the standard MediaTek key-press matrix described in
  the device-tree (`mediatek,hw-recovery-key`, `mediatek,hw-factory-key`,
  `mediatek,hw-pwrkey`, `mediatek,sw-rstkey`). The unlock confirmation UI
  is bound to the **Volume UP / Volume DOWN** keys.
* The preloader (`pl.img`) and EMMC boot partitions (`mmcblk0boot[01].bin`)
  are MediaTek BROM-format blobs that contain the standard
  `META_COM` / UART META download path, the
  `Disable_BROM_CMD` efuse fuse-blow logic, and `SP Flash Tool` /
  `Download Agent` boilerplate. Details in
  [`firmware-overview.md`](./firmware-overview.md).

[issue]: https://github.com/R0rt1z2/kaeru/issues/5
[capstone]: https://www.capstone-engine.org/
