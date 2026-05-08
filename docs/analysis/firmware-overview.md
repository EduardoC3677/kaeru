# Companion firmware overview

This document summarises the non-LK images that were dumped alongside
`lk.img`. For the deep dive on `lk.img` itself, see [`lk.md`](./lk.md).

The platform is **MediaTek MT6897 (Dimensity 9300)** customised by
**OPLUS / OnePlus**. All container detections below come from
[`scripts/analysis/analyze_lk.py`](../../scripts/analysis/analyze_lk.py).

## Per-image summary

| File | Size | Container | Notes |
| --- | ---: | --- | --- |
| `lk.img` | 16 MiB | MTK BFBF (`lk`) | AArch64 LK - see [`lk.md`](./lk.md). |
| `pl.img` | 4,190,208 B | MTK preloader (`MMM\x01` / `FILE_INFO`) | 32-bit ARM preloader; contains DRAM calibration, charging init, META-COM glue. |
| `mmcblk0boot0.bin` | 4 MiB | `UFS_BOOT` | EMMC boot partition 0; carries `preloader_a`. |
| `mmcblk0boot1.bin` | 4 MiB | `UFS_BOOT` | EMMC boot partition 1; carries `preloader_b`. Differs from `boot0` by ~508 bytes (slot signature). |
| `scp.img` | 16 MiB | MTK BFBF (`tinysys-scp-RV55_A`) | Sensor / audio co-processor firmware on a Cadence Tensilica RV55 core. **Not** AArch64; capstone ARM is not applicable. |
| `seccfg.img` | 8 MiB | MTK seccfg (`MMMM`) | Secure configuration partition (lock state, RPMB key, fastboot unlock policy). Mostly ciphertext / `0xFF` padding. |
| `vendor_boot.img` | 64 MiB | Android `VNDRBOOT` v4 | Standard Android vendor_boot containing the vendor ramdisk fragments. |
| `vb.img` | 4 MiB | Raw / all-zero | `vbmeta` slot - contents redacted in this dump. |
| `boot_para.img` | 1 MiB | Raw / all-zero | Boot-parameter scratch partition (provisioned at runtime). |
| `para.img` | 512 KiB | Raw | OPLUS "para" parameter blob. |
| `oplus_custom.img` | 1 MiB | Raw / all-zero | OPLUS customisation slot (per-region settings). |
| `oplusreserve1.img` | 8 MiB | OPLUS reserve (`5A 3A B7 9F`) | OPLUS reserved partition. Holds the **fastboot unlock-ability flag** (referenced as `unlock_allowed_flag_offset` in LK), the persisted `pl_lk` log, the UFS firmware blob, and other OPLUS bookkeeping. |

## `pl.img` - MediaTek preloader

* Container: `MMM\x01` / `FILE_INFO` MediaTek preloader format. Capstone
  decoding requires stripping the `FILE_INFO` block first; the meaningful
  payload is 32-bit ARM (`Cortex-A55` running at EL3 in secure-world).
* Strings expose the canonical preloader subsystems:
  * DRAM calibration: `platform/mt6897/src/drivers/dramc/...` paths,
    `PL_VERSION is updated, erase the DRAM shu_data`.
  * PMIC / charger init: `MT6363`, `MT6368`, `MT6375`, `MT6685`, `MT6319`.
  * META-mode link: *"UART META Connected, Switch log port to UART2..."*,
    *"use MTK meta usb preloader"*, `seclib_brom_meta_mode`.
  * Slot-aware boot: *"Current boot: Preloader_a"* / *"Preloader_b"*.
  * OPLUS DA hooks: `[oplus da]get da version error. ret=%d da_ver=%d`,
    `init_eng_version_newcdt: magic number:%d %d check fail`.
* No fastboot logic - that belongs to LK. The preloader's only "command"
  surface is the META download protocol over USB / UART.

## `mmcblk0boot0.bin` / `mmcblk0boot1.bin` - EMMC boot partitions

Both are MediaTek `UFS_BOOT` containers of 4 MiB each. Header layout:

```
0x00  "UFS_BOOT" + 0x00 0x00 0x00 0x00
0x08  flags = 0x00000000
0x0C  entry_count = 0x00000001
0x10  payload_offset = 0x00010000
```

(Some MediaTek SDK headers transpose the magic to `USF_BOOT` -
[`scripts/analysis/analyze_lk.py`](../../scripts/analysis/analyze_lk.py)
accepts both.)

The payload at offset `0x10000` is the same MediaTek preloader binary as
`pl.img`, signed for the corresponding A or B slot (the two files differ
in ~508 bytes - the signature / partition-id region, not the code). On a
real device this is what the BROM loads first; `pl.img` is just the same
preloader as a single-file partition image.

## `scp.img` - SCP / sensorhub firmware

* Container: MediaTek BFBF (`0x58881688`), name `tinysys-scp-RV55_A`,
  payload size `0x21CBDC`.
* Architecture: **Cadence Tensilica RV55** (extensa-LX based). This is
  *not* ARM, so neither the kaeru patcher nor `analyze_lk.py`'s capstone
  pass can disassemble it. The string table still tells us what runs on
  it:
  * FreeRTOS scheduler (`kernel/FreeRTOS_v10.1.0.1/FreeRTOS/Source/portable/LLVM/RV55/port.c`).
  * Sensor drivers: BMI3xy IMU, ICM456xy IMU, OIS controller (`dw9828c`),
    Maxim DS28E30 secure-element.
  * Voice-of-Wakeup (`vow_*`) Google Assistant detection pipeline.
  * Sensor-fusion / calibration (`oplus_fusion`,
    `middleware/sensorhub/algos/RV55NN_A/...`).
* Relevant to kaeru only because the LK image references
  `verify_load_scp_image` and re-validates `scp.img`'s signature on
  every boot.

## `seccfg.img` - Secure configuration

* Magic `MMMM` followed by a small TLV header. The body is the encrypted
  `seccfg` blob managed by the LK helper
  `oem test_seccfg_lockstate` (see [`lk.md`](./lk.md#oem-subcommands)).
* No printable strings - all ciphertext / padding.
* Cross-referenced from LK as the source-of-truth for **lock state**,
  with a fall-back to the **RPMB** copy (the `rpmb_lock_state` vs
  `seccfg_lock_state` reconciliation logic is present in `lk.img`).

## `vendor_boot.img` - Android vendor_boot v4

* Magic `VNDRBOOT` (`0x564E4452 'BOOT'`).
* Header version 4, page size `0x1000`.
* Contains the standard vendor ramdisk fragments referenced by the
  strings `first_stage_ramdisk/...` (`fsck.f2fs`, `linker64`, ...).
* Not relevant to LK patching but useful as the source of the
  `androidboot.*` cmdline expectations LK has to satisfy.

## `vb.img`, `boot_para.img`, `para.img`, `oplus_custom.img`

These four are mostly empty (all-zero or all-`0xFF`) in this dump:

* `vb.img` - vbmeta partition. On a real device this is populated by AVB
  with the chained hashtree descriptors. It's empty here either because
  the dump was taken before AVB provisioning or because the user
  scrubbed it before sharing.
* `boot_para.img` - 1 MiB scratch area used for `lk` <-> `kernel` boot
  parameter handoff.
* `para.img` - 512 KiB OPLUS "para" blob (typically holds bootmode,
  serial, last-reboot-reason).
* `oplus_custom.img` - regional / carrier customisation. Empty in this
  dump.

## `oplusreserve1.img` - OPLUS reserve partition

* 8 MiB container with magic `5A 3A B7 9F` (`OPLUS_PARTITION_RESERVE_1`
  per the LK string table) followed by the partition manufacturer tag -
  in this dump `SAMSUNG\0` is visible at offset 4, indicating a Samsung
  UFS chip.
* Hosts the **fastboot unlock-ability flag** that LK reads via
  `fastboot_unlock_read_flag_from_reserve`. This is what makes a generic
  seccfg reset (e.g. the classic SP-Flash trick) insufficient on this
  device: the OPLUS-side flag has to be set *separately*.
* Hosts the **persisted preloader / LK log** dumped by
  `oem dump_pllk_log`. The header is referenced as `pl_lk log header` in
  the LK strings (`failed to write oplusreserve1 pl_lk log header (%ld)`).
* Hosts a copy of the **UFS firmware** (LK string:
  *"Cannot read ufs firmware head from OPLUSreserve1 partition"*).

## Implication for kaeru

Even though many of these images are interesting, only `lk.img` is
something kaeru would patch. The rest are documented here so that future
porters of kaeru-on-AArch64 know:

1. Where the lock state actually lives (`seccfg.img` *and*
   `oplusreserve1.img`).
2. That the BROM's `Disable_BROM_CMD` efuse and the preloader signing
   sit upstream of LK and cannot be bypassed from inside `lk.img`.
3. That `scp.img` is a different ISA and is not an LK extension target.
4. That OPLUS's unlock policy depends on data in `oplusreserve1` which
   is not normally writable from fastboot.
