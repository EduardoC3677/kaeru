# MediaTek BROM / Download-Agent on-the-wire protocol

This document is the synthesis used to drive [`tools/kaeru-mtk/`](../../tools/kaeru-mtk/).
It cross-references three sources:

1. The OPPO/MediaTek `FlashToolLib.dll` exports (vendor's own SDK, `BBChipType`,
   `Brom_*`, `DA_*`, `AUTH_*` symbol tables) — see [`mtk-da-brom.md`](./mtk-da-brom.md).
2. The public clean-room `bkerler/mtkclient` (GPLv3) reference, used as
   protocol cheat-sheet only — never copied verbatim.
3. The MediaTek "kamakiri" / `bypass_utility` writeups for handshake byte
   sequences and exploit payloads.

**Scope.** Only the protocol: framing, opcodes, layout. Vendor crypto keys
remain undisclosed; we re-implement the wire format and let the user supply
auth files at runtime.

---

## Layered model

```text
+----------------------+----------------------+----------------------+
|        DA v5 / v6    |       BROM           |   Auth / SLA         |
| read_data,write_data | read32, write32,     | challenge / response |
| format_data, hello   | jump_da, send_da     |                      |
+----------------------+----------------------+----------------------+
|                  Framing (BE16/BE32 + status)                      |
+--------------------------------------------------------------------+
|  USB bulk (libusb / WinUSB)  EP_IN=0x81 EP_OUT=0x01 (typical)      |
+--------------------------------------------------------------------+
```

Each layer in `kaeru-mtk` is a distinct module. The transport never knows
about commands. The protocol never knows about USB. The commands never know
about framing. This keeps the codebase from sliding into spaghetti.

---

## USB transport

| Mode             | VID    | PID    | Notes                                |
|------------------|--------|--------|--------------------------------------|
| BROM             | 0x0E8D | 0x0003 | First boot stage, immediately after `A0 0A 50 05` window |
| Preloader        | 0x0E8D | 0x2000 | Vendor preloader, after BROM hands off |
| Preloader (alt)  | 0x0E8D | 0x2001 | Some SoCs                            |

**Endpoints.** A single bulk-IN and bulk-OUT pair on interface 0.
Mtkclient-style discovery picks the first IN/OUT bulk EPs available — kaeru
does the same in [`transport/usb.py`](../../tools/kaeru-mtk/src/kaeru_mtk/transport/usb.py).

**Windows.** The default driver bound to `0E8D:0003` is a generic USB serial
driver and cannot be claimed by libusb. The user must replace it with
`WinUSB` via Zadig. `kaeru-mtk driver install` automates this.

**Linux.** `libusb-1.0` is enough; a 51-mediatek udev rule grants user
access without sudo.

---

## BROM layer

### Handshake

The BROM watches for the four magic bytes immediately after USB enumeration.
Send each byte; the device echoes the bitwise complement.

```text
host -> 0xA0  device -> 0x5F
host -> 0x0A  device -> 0xF5
host -> 0x50  device -> 0xAF
host -> 0x05  device -> 0xFA
```

Implementation: [`protocol/brom.py::BromClient.handshake`](../../tools/kaeru-mtk/src/kaeru_mtk/protocol/brom.py).

### Command opcodes

| Opcode | Constant            | Purpose                          | Status field |
|-------:|---------------------|----------------------------------|--------------|
| `0xA1` | `WRITE16`           | write N x uint16 to RAM          | BE16         |
| `0xA2` | `READ16`            | read  N x uint16 from RAM        | BE16         |
| `0xC4` | `POWER_INIT`        | PMIC init                        | BE16         |
| `0xC8` | `CMD_C8`            | undocumented vendor cmd          | BE16         |
| `0xD1` | `READ32`            | read  N x uint32 from RAM        | BE16         |
| `0xD4` | `WRITE32`           | write N x uint32 to RAM          | BE16         |
| `0xD5` | `JUMP_DA`           | jump to addr after SEND_DA       | BE16         |
| `0xD6` | `JUMP_BL`           | jump to next bootloader          | BE16         |
| `0xD7` | `SEND_DA`           | upload Download Agent blob       | BE16 (twice) |
| `0xD8` | `GET_TARGET_CONFIG` | secure_boot, sla_en, daa_en flags| BE16         |
| `0xDB` | `UART1_LOG_EN`      | enable preloader UART log        | BE16         |
| `0xE0` | `SEND_CERT`         | OEM root certificate             | BE16         |
| `0xE1` | `GET_ME_ID`         | per-device 16/32-byte ID         | BE16         |
| `0xE2` | `SEND_AUTH`         | send `auth_sv5.auth` blob        | BE16         |
| `0xE3` | `SLA_CHALLENGE`     | RX random nonce from BROM        | BE16         |
| `0xE4` | `SLA_RESPONSE`      | TX RSA-2048 signed nonce         | BE16         |
| `0xE7` | `GET_SOC_ID`        | SoC HW unique ID (when present)  | BE16         |
| `0xFC` | `GET_HW_SW_VER`     | hw_subcode/hw_ver/sw_ver         | BE16         |
| `0xFD` | `GET_HW_CODE`       | top-level hw_code (e.g. 0x0996)  | BE16         |
| `0xFE` | `GET_BL_VER`        | bootloader version byte          | none         |
| `0xFF` | `GET_VERSION`       | major/minor                      | none         |

Each command starts with the host writing the single opcode byte and the
device echoing it back. Any deviation aborts. After the echo the host
sends or reads structured payload, then a BE16 status word (`0x0000` = OK).

### Target discovery sequence

```text
1. handshake()
2. status = read32(0x40000000, 1)         # sanity ping
3. hw_code = GET_HW_CODE                   # e.g. 0x0996 = MT6853
4. hw_subcode, hw_ver, sw_ver = GET_HW_SW_VER
5. cfg = GET_TARGET_CONFIG                 # bit0 secure_boot, bit1 sla, bit2 daa
6. me_id = GET_ME_ID                       # 16 bytes
7. (optional) soc_id = GET_SOC_ID
8. if cfg & 0x6:
8a.    SEND_AUTH(auth_sv5_for_this_soc)
8b.    do_sla_challenge_response()
9. SEND_DA(da_blob, addr=0x200000, sig_len=0x100)
10. JUMP_DA(0x200000)
```

Implementation: [`protocol/brom.py::BromClient.probe_target`](../../tools/kaeru-mtk/src/kaeru_mtk/protocol/brom.py)
plus [`commands/_session.py`](../../tools/kaeru-mtk/src/kaeru_mtk/commands/_session.py)
for the orchestration.

---

## SLA (Serial-Link Authorization)

When `target_config.sla_en = 1`, the BROM will not load a DA without a
matching RSA-2048 signature. The flow:

```
host          BROM
SEND_AUTH ->                   (echo)
   raw auth_sv5.auth (5K, GFH MMM\x01)
                            <- BE16 status (0 = accepted)
SLA_CHALLENGE ->               (echo)
                            <- BE32 challenge_len
                            <- challenge bytes (typically 16 or 32)
                            <- BE16 status
SLA_RESPONSE ->                (echo)
   BE32 sig_len
   sig bytes (RSA-2048 = 256)
                            <- BE16 status
```

The signer is a **callable** the user provides. Kaeru does not ship private
keys. Test fixture: see `tests/test_protocol_brom.py` for the framing.

The `auth_sv5.auth` file format (verified against the 15 OPPO MTKResource
files):

| Offset   | Field              | Size  |
|---------:|--------------------|------:|
| `0x0000` | GFH magic `MMM\x01`| 4     |
| `0x0004` | FILE_INFO header   | 0x262 |
| `0x0262` | ANTI_CLONE block   | 0x262 |
| `0x04C4` | RSA-2048 modulus   | 0x100 |
|  end-256 | RSA signature      | 0x100 |

Implementation: [`formats/auth_sv5.py`](../../tools/kaeru-mtk/src/kaeru_mtk/formats/auth_sv5.py).

---

## Download Agent

Two protocol revisions coexist in the field. SoCs MT6757 and earlier use v5;
Dimensity-class SoCs (MT6877, MT6885, MT6889, MT6893+) use v6.

### v5 (single-byte opcodes, BE16 status)

| Opcode | Purpose          |
|-------:|------------------|
| `0x51` | `GET_BMT_INFO`   |
| `0x52` | `PROGRESS_QUERY` |
| `0x55` | `GET_PROJECT_ID` |
| `0x56` | `GET_FW_VERSION` |
| `0x57` | `BOOT_TO`        |
| `0x58` | `DOWNLOAD`       |
| `0x59` | `READBACK`       |
| `0x5A` | `FORMAT`         |
| `0x60` | `DA_HW_INIT`     |
| `0xFE` | `GET_DA_VERSION` |

### v6 (BE16 opcodes, prefix 0x68)

| Opcode    | Purpose             |
|----------:|---------------------|
| `0x6800`  | `HELLO`             |
| `0x6801`  | `SECURE_INIT`       |
| `0x6802`  | `SETUP_HW_INIT`     |
| `0x6803`  | `SETUP_ENV`         |
| `0x6810`  | `DEVICE_CTRL`       |
| `0x6811`  | `GET_HW_INFO`       |
| `0x6812`  | `GET_SYS_PROPERTY`  |
| `0x6830`  | `READ_DATA`         |
| `0x6831`  | `WRITE_DATA`        |
| `0x6832`  | `FORMAT_DATA`       |
| `0x6840`  | `SHUTDOWN`          |

`READ_DATA` takes `(name_len BE32, name bytes, offset_lo BE32, offset_hi BE32,
length BE32)` and streams bulk payload. `WRITE_DATA` is the inverse.

Implementation: [`protocol/da_v5.py`](../../tools/kaeru-mtk/src/kaeru_mtk/protocol/da_v5.py),
[`protocol/da_v6.py`](../../tools/kaeru-mtk/src/kaeru_mtk/protocol/da_v6.py).

---

## OnePlus / OPPO package formats

### scatter.txt (YAML-ish)

`SP Flash Tool` partition layout. One YAML stream, one `partitions:` array
of dictionaries with `partition_name`, `file_name`, `linear_start_addr`,
`partition_size`, `is_download`, `is_reserved`. See
[`formats/scatter.py`](../../tools/kaeru-mtk/src/kaeru_mtk/formats/scatter.py)
and [`tests/test_scatter.py`](../../tools/kaeru-mtk/tests/test_scatter.py).

### OFP (OPPO Firmware Package)

| Family    | Magic                       | Top-level wrapping             |
|-----------|-----------------------------|--------------------------------|
| Qualcomm  | `OPPOENCRYPT!`              | proprietary AES + obfuscated XML |
| MediaTek  | `MTK_PUMP_BIN`              | similar, MTK-specific keying  |
| Newer     | ZIP container               | per-image AES, Manifest.xml    |

Decryption requires per-product keys not bundled here. `kaeru-mtk flash ofp`
performs structural parsing and refuses to flash without `--extract-only`.

### OPS (OnePlus Package Stream)

512-byte footer at end of file:

| Offset  | Field           | Size |
|--------:|-----------------|-----:|
| `0x10`  | magic `0x7CEF`  |    2 |
| `0x14`  | version         |    4 |
| `0x18`  | xml_offset      |    8 |
| `0x20`  | xml_length      |    8 |

The XML region is encrypted with an AES key derived from the device model
prefix; payload regions follow per-entry AES with offsets recorded in the
XML. Implementation skeleton: [`formats/ops.py`](../../tools/kaeru-mtk/src/kaeru_mtk/formats/ops.py)
and tests/test_ops.py.

---

## Compatibility table (against OPPO MTKResource)

| SoC       | DA path            | Notes                                       |
|-----------|--------------------|---------------------------------------------|
| MT6763    | DA v5              | BROM exploit available                      |
| MT6765    | DA v5              | BROM exploit available                      |
| MT6769    | DA v5              | BROM exploit available                      |
| MT6771    | DA v5              | BROM exploit available                      |
| MT6779    | DA v5              | Auth required if `sla_en=1`                 |
| MT6833    | DA v6              | Auth required, well-tested                  |
| MT6853    | DA v6              | Auth required, well-tested                  |
| MT6873    | DA v6              | Auth required                               |
| MT6877    | DA v6              | Auth required, current Dimensity-class      |
| MT6885    | DA v6              | Auth required, no public BROM exploit       |
| MT6889    | DA v6              | Auth required, no public BROM exploit       |
| MT6893    | DA v6              | Auth required                               |
| MT6897    | DA v6              | Latest, AArch64 LK, **no public exploit**   |

`auth_sv5.auth` files for all of the above are in OPPO's official tool tree
under `MTKResource/<SoC>/auth_sv5.auth`. They are **OEM-signed**: kaeru
loads them but cannot generate them. If you do not have the OEM private key,
you cannot bypass `sla_en=1` without a BROM RCE on that specific SoC.

---

## Status of this implementation

- BROM framing, handshake, target probe: complete with mock-transport unit tests.
- SLA challenge/response: framing complete, signer pluggable, no key shipped.
- DA v5 / v6: hello + read_data + write_data + format frames implemented;
  device-side rollouts gated by explicit user confirmation flags.
- Scatter, auth_sv5, OFP (structural), OPS (footer): implemented and tested.
- USB transport: pyusb + libusb-package backend with WinUSB on Windows.
- CLI: 9 top-level subcommands, all wired to the layered modules.
