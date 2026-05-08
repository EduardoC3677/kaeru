# `lk.img` - Little Kernel deep dive

## Container

| Field | Value |
| --- | --- |
| Total file size | 16,777,216 B (16 MiB - matches typical MTK `lk_a` partition) |
| Outer header | MediaTek **GFH/BFBF** wrapper (magic `0x58881688`) |
| Image name | `lk` |
| Payload offset | `0x200` |
| Payload size | `0x17CFD0` (1,560,528 B / ~1.49 MiB) |
| Architecture | **AArch64 / ARMv8-A** (first instruction is `mrs x28, currentel`) |
| Assumed load base | `0x4C400000` (standard for MT689x-class LK) |

The remainder of the 16 MiB partition is `0xFF` padding plus an unused
secondary header at offset `0x40` (`0x58891688` BCBC); kaeru's existing
patch logic does not need to touch any of that.

## Platform identification

The strings `mediatek,mt6897-*`, file paths under
`platform/mediatek/mt6897/sboot/`, and the boot tag `MT6897Z/TZA` confirm:

* SoC family: **MediaTek MT6897 (Dimensity 9300 / 9300+)**.
* Vendor customisation: **OPLUS / OnePlus** (hundreds of `oplus_*` and
  `oplusboot.*` strings, `OplusRecordFastbootUnlock` helper, etc.).
* Code carries references to many sibling packages (`MT6363`, `MT6368`,
  `MT6375`, `MT6379`, `MT6685`) - these are the PMIC, charger and RTC
  companion chips and are not relevant to the boot logic itself.

## Compatibility note for kaeru

kaeru's main payload (under `arch/`) targets **ARMv7** Little Kernel binaries
shipped on 32-bit MediaTek SoCs (MT6580, MT6735, MT6739, MT8163, ...).
The image dumped here is **AArch64**, so the existing kaeru offsets,
trampolines and assembly stubs do **not** apply. Bringing kaeru to AArch64
is a larger porting exercise (new `arch/arm64/` tree, new linker script,
new hook ABI) and is out of scope for this issue.

## Fastboot command surface

The classic Android fastboot dispatch tokens registered in this image are:

| Command | Notes |
| --- | --- |
| `getvar:` | Standard variable accessor - see the table below |
| `download:` | Upload a payload from host into LK's RAM buffer |
| `flash:` | Flash the previously-downloaded payload to a partition |
| `erase:` | Erase a partition (gated by lock state) |
| `boot` | Boot the buffer at the download address (gated) |
| `continue` | Continue normal boot |
| `partition` | Used by host as token for `partition-type:` / `partition-size:` getvars |
| `set_active:` | Set the active A/B slot |
| `reboot` | Reboot to normal |
| `reboot-bootloader` | Reboot back to fastboot |
| `reboot-recovery` | Reboot into recovery |
| `reboot-fastboot` | Reboot into userspace fastboot (fastbootd) |
| `signature` | Verify a payload signature (legacy MTK) |

### `flashing` namespace

In addition to `oem ...`, the following modern `flashing` subcommands are
implemented (per AOSP fastboot convention):

* `flashing lock` - re-lock the bootloader.
* `flashing unlock` - request unlock; prompts the user with the unlock UI.
* `flashing get_unlock_ability` - read the carrier-provisioned unlock
  permission flag (publishes `unlock_ability`, value `0` or `1`).

The unlock flow is reinforced by OPLUS-specific helpers:

* `fastboot_unlock_read_flag_from_reserve` - the unlock-ability flag is
  stored inside `oplusreserve1` at a fixed `unlock_allowed_flag_offset`.
* `OplusRecordFastbootUnlock` - audit-record the unlock event.
* If unlock is allowed: *"Unlock the device successfully! Will return to
  fastboot in 3s"*.
* If denied: *"Failed to unlock the device! Will return to fastboot in 3s"*
  or *"Prohibit unlock operation"*.

### `getvar` variables

Confirmed names extracted from the .rodata of `lk.img`:

* Identity: `version`, `version-bootloader`, `version-baseband`,
  `product`, `serialno`, `platform`, `socid`, `hw-revision`.
* Lock / verified-boot state: `secure`, `unlocked`, `warranty`,
  `is-userspace`, `has-vbmeta`.
* Slots (A/B): `slot-count`, `current-slot`, `has-slot`, `slot-suffixes`,
  `slot-successful`, `slot-unbootable`, `slot-retry-count`.
* Power / charging: `off-mode-charge`, `battery-voltage`, `battery-soc-ok`.
* Partition probe: `partition-type:<name>`, `partition-size:<name>`.
* Transport: `max-download-size`.

### `oem` subcommands

The following `oem` commands are registered. Names come from string
literals tied to LK's standard `fastboot_register` registration pattern.

| Command | Purpose (inferred from surrounding strings) |
| --- | --- |
| `oem off-mode-charge` | Toggle off-mode-charge behaviour. |
| `oem usb2jtag` | Switch the USB lines into the JTAG mux. The strings *"Enable USB2JTAG"*, *"Disable USB2JTAG"*, *"Current USB2JAG setting: %s"* and *"USB2JTAG Done!"* confirm both `on` and `off` arguments are supported. |
| `oem p2u` | "Print to UART" - mirror LK's `dprintf` log to UART. Strings *"oem p2u on!"* / *"oem p2u off!"* confirm both directions. |
| `oem printk-ratelimit` | Toggle the LK `printk` rate-limiter. *"oem printk-ratelimit on!"* / *"oem printk-ratelimit off!"*. |
| `oem ultraflash_en` | Enable MediaTek's "ultraflash" fast-flash mode. |
| `oem ultraflash:<...>` | Ultraflash sub-protocol entry point. |
| `oem cdms` | CDMS (vendor-specific dump / diagnostics utility) hook. |
| `oem mrdump_chkimg` | Check an MRDUMP image - MRDUMP is MediaTek's mini-rdump RAM-dump-on-crash framework. |
| `oem mrdump_fallocate` | Pre-allocate the MRDUMP partition area. |
| `oem mrdump_out_set` | Set the MRDUMP output destination (UART / partition / etc.). |
| `oem dump_pllk_log` | Dump the buffered preloader / LK log over fastboot. The companion log code path uses `oplusreserve1` `pl_lk log` storage. |
| `oem get_socid` | Print the SoC ID (also exposed via `getvar:socid`). |
| `oem get_key` | Read a key entry from the secure store (gated). |
| `oem set_enckey` | Provision an encryption key (gated; OPLUS factory tooling). |
| `oem test_seccfg_lockstate` | Diagnostic that prints the current `seccfg` lock state and the RPMB lock state for cross-check. The relevant log lines are *"seccfg_lock_state is the same as rpmb_lock_state. It will do nothing and boot normal."* and the inverse. |

## Boot modes

The string table contains an exhaustive set of human-readable mode banners
that LK prints on the splash screen:

* `=> NORMAL MODE`
* `=> RECOVERY MODE`
* `=> FACTORY MODE`
* `=> META MODE`
* `=> FASTBOOT MODE`
* `=> POWER OFF CHARGING MODE`
* `=> UNKNOWN BOOT`

Internally LK consumes the kernel command-line tag `oplusboot.mode=...` to
route into a particular mode. Confirmed values:

* `oplusboot.mode=fastboot`
* `oplusboot.mode=factory`
* `oplus_ftm_mode=ftmaging` (factory-test-mode aging suite).

The corresponding kernel command-line plumbing is provided by the helpers
`add_oplusboot_avbKeySha256_cmdLine`, `add_oplusboot_serialno_cmdline`
and `add_oplusboot_prjname_cmdline`.

## Key combinations

LK reads the keypad state from device-tree-described GPIO indexes. The
relevant nodes are:

* `mediatek,hw-pwrkey` - hardware power key GPIO.
* `mediatek,hw-recovery-key` - hardware key whose press at boot enters
  recovery (typically Volume Down).
* `mediatek,hw-factory-key` - hardware key whose press at boot enters
  factory mode (typically Volume Up).
* `mediatek,sw-rstkey` / `mediatek,hw-rstkey` - software / hardware reset
  key indexes.
* `mediatek,kpd-hw-map-num`, `mediatek,gpio_key_index` - keymap helpers.
* `mediatek,kp` - PMIC keypad node.

The runtime probe logs these as:

* `kpd_hw_recovery_key = %d, kpd_hw_factory_key = %d`
* `kpd_sw_pwrkey = %d, kpd_hw_pwrkey = %d`
* `kpd_sw_rstkey = %d, kpd_hw_rstkey = %d`
* `vol_down_key_check gpio condition is %u success`

The unlock UI binds explicitly to volume keys:

> *"Press the Volume UP/Down buttons to select Yes or No."*
>
> *"Yes (Volume UP or Volume Down): Unlock(may void warranty)."*
>
> *"No (Auto exit after 5 seconds): Do not unlock bootloader."*

When a download stalls in fastboot the bootloader prints the recovery
hint:

> *"Download not completed! Please press volume+ and power key 10s to
> power off. Then download again. Otherwise will block here 60S until
> shutdown automatically."*

## Hidden / debug functionality

Strictly speaking nothing is "hidden" - everything is in plain text - but
the following features are vendor-specific and not documented in the
public Android fastboot reference:

* **USB-to-JTAG mux** (`oem usb2jtag on|off`). Switches the USB-C
  SuperSpeed lines to the JTAG controller for in-system debugging.
* **Printf-to-UART** (`oem p2u on|off`). Re-routes `dprintf` to UART so
  log capture works without USB enumeration.
* **MRDUMP** family (`oem mrdump_*`). MediaTek's RAM-dump-on-panic that
  preserves the kernel state across a warm reset; useful for post-mortem
  debugging.
* **Ultraflash** (`oem ultraflash_en`, `oem ultraflash:<...>`). MTK's
  proprietary high-throughput flashing protocol.
* **`oem dump_pllk_log`**. Dumps the preloader+LK ring buffer, which is
  persisted on `oplusreserve1` (the partition header `OPLUS_PARTITION_RESERVE_1`
  with a `pl_lk log header` is referenced in the code).
* **`oem test_seccfg_lockstate`**. Compares seccfg vs RPMB lock state -
  useful when troubleshooting why a `flashing unlock` was rejected.
* **`oem set_enckey` / `oem get_key`**. Factory provisioning hooks that
  interact with the secure key store; gated on the lock state.
* **OPLUS unlock-ability flag in `oplusreserve1`**. The carrier "may I be
  unlocked?" bit lives in the OPLUS reserve partition rather than in
  seccfg, so a generic SP-Flash seccfg reset is *not* sufficient on this
  device.

## Preloader / BROM interaction

The LK code references the standard MediaTek download path:

* `META_COM ID / TYPE / PORT` - meta-mode communication descriptor used
  during USB / UART META download (the legacy "FlashTool meta" link).
* `Disable_BROM_CMD` efuse - the runtime check for whether the SoC's BROM
  download command was disabled at the factory ("first time blow
  Disable_BROM_CMD: 0x%x").
* `preloader_a` / `preloader_b` partition names with locking helpers
  (`Lock preloader partition failed`).
* `process preloader fail.` warning path.

The actual preloader code is not in `lk.img` - it lives in `pl.img` and in
the EMMC boot partitions (`mmcblk0boot[01].bin`); see
[`firmware-overview.md`](./firmware-overview.md).

## Reproducibility

```bash
pip install capstone
python3 scripts/analysis/analyze_lk.py lk.img --bucket-limit 200
python3 scripts/analysis/analyze_lk.py lk.img --disasm /tmp/lk.S
```

The classifier in the helper script is the authoritative source for the
tables above; if you re-run it on a different `lk.img` the same buckets
will populate from that image's strings.
