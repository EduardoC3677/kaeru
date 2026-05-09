# kaeru-mtk

MediaTek BROM/DA protocol tool for OPPO/OnePlus devices.

Implements the MediaTek BootROM and Download Agent protocol directly via USB
(pyusb/libusb), with bundled authentication files, SLA public keys, and BROM
exploits for both ARMv7 and AArch64 SoCs.

## Architecture

```
src/kaeru_mtk/
├── cli.py                argparse + subcommand dispatch
├── transport/
│   ├── interface.py      abstract transport interface
│   └── usb.py            USB transport via pyusb (WinUSB/libusb)
├── protocol/
│   ├── brom.py           BROM protocol: handshake, commands, DA loading
│   ├── da.py             DA protocol: partition enumeration, read/write/erase
│   ├── sla.py            SLA authentication (challenge-response)
│   └── exploits/
│       ├── kamakiri.py   ARMv7 USB control-transfer overflow
│       ├── kamakiri2.py  AArch64 USBDL overflow
│       ├── carbonara.py  Alternative AArch64 entry vector
│       ├── hashimoto.py  DMA-engine BROM dump primitive
│       └── heapbait.py   Heap-based exploit for newer Dimensity
├── commands/
│   ├── _session.py       device session management
│   ├── detect.py         USB endpoint enumeration
│   ├── info.py           BROM config probe + SoC match
│   ├── auth.py           bundled auth file inspection
│   ├── socs.py           SoC database listing
│   ├── exploit.py        BROM exploit runner
│   ├── flash.py          partition I/O via DA
│   ├── unlock.py         OPPO/OnePlus BL unlock
│   └── driver.py         Windows driver helper
├── data/
│   ├── auth/             15 auth_sv5.auth blobs (MMM\x01 GFH)
│   ├── auth_index.py     parses bundled auth + matches SLA key
│   ├── sla_keys.py       4 RSA-2048 keys from SLA_Challenge.dll
│   ├── soc_db.py         hwcode → SocSpec, verified vs mtkclient
│   └── usb_ids.py        MediaTek VID/PID list
├── driver/
│   └── windows.py        Zadig downloader + PnpDevice driver query
└── utils/
    ├── errors.py         typed error hierarchy
    ├── logging.py        rich console logging
    └── hexdump.py        hex dump formatter
```

## Install

```bash
pip install -e .
```

Requires pyusb + libusb (or WinUSB on Windows).

## Usage

```bash
kaeru-mtk --help                                    # top-level help
kaeru-mtk socs                                      # list known SoCs
kaeru-mtk auth list                                 # 15 bundled auth files
kaeru-mtk auth resolve 0x959                        # resolve auth for hwcode
kaeru-mtk exploit list                              # show available exploits

# Windows: bind WinUSB via Zadig
kaeru-mtk driver install
kaeru-mtk driver status

# Detect a connected device
kaeru-mtk detect

# Probe device + auto-select bundled auth
kaeru-mtk info

# Run BROM exploit (auto-detects kamakiri/kamakiri2 from arch)
kaeru-mtk exploit run
kaeru-mtk exploit run --exploit kamakiri2

# Partition I/O (requires DA after exploit)
kaeru-mtk flash read    --partition boot     --out boot.bin
kaeru-mtk flash readall --out-dir backup/    --exclude-sensitive
kaeru-mtk flash write   --partition recovery --image recovery.img --confirm-brick-risk
kaeru-mtk flash erase   --partition userdata --confirm-brick-risk

# OPPO/OnePlus BL unlock
kaeru-mtk unlock-bl --confirm-unlock --allow-dangerous
```

## BROM Protocol

The BROM (BootROM) is the first code executing on MediaTek SoCs. It appears as
USB device `0E8D:0003` and speaks a custom control-transfer protocol:

| Command | Code | Description |
|---------|------|-------------|
| GET_HW_CODE | 0xD1 | Read 16-bit hardware code |
| GET_HW_SW_VER | 0xD2 | Read hw/sw version quadlet |
| GET_TARGET_CONFIG | 0xD3 | Read full target config |
| WRITE16 | 0xD4 | Write 16-bit value to memory |
| WRITE32 | 0xD5 | Write 32-bit value to memory |
| READ16 | 0xD6 | Read 16-bit from memory |
| READ32 | 0xD7 | Read 32-bit from memory |
| JUMP_DA | 0xD8 | Jump to Download Agent |
| SEND_DA | 0xDA | Transfer DA blob to SRAM |
| GET_DA_LOAD_INFO | 0xDB | Get DA load address/size |
| SEND_CERT | 0xDC | Send certificate |
| SEND_AUTH_DATA | 0xDD | Send authentication data |
| GET_CHALLENGE | 0xDE | Get BROM challenge |
| WRITE_REG | 0xE0 | Write device register |
| READ_REG | 0xE1 | Read device register |
| JUMP_ADDR | 0xE2 | Jump to arbitrary address |

## Exploits

The BROM exploits work by sending malformed USB control transfers that overflow
stack buffers in the BROM's USB handler, bypassing authentication:

- **kamakiri** (ARMv7): `ctrl_transfer(0xA1, 0x00, 0xFFFF, 0x0000, payload)`
- **kamakiri2** (AArch64): `ctrl_transfer(0xA1, 0x21, 0xFFFF, 0x0000, payload)`
- **carbonara** (AArch64): Alternative vector using `bRequest=0x22`
- **hashimoto** (ARMv7): DMA engine primitive
- **heapbait** (AArch64): Heap-based for newer Dimensity

## Bundled Auth

15 `auth_sv5.auth` files are bundled under `src/kaeru_mtk/data/auth/`, covering
MT6763, MT6765, MT6769, MT6771, MT6779, MT6833, MT6853, MT6873, MT6877,
MT6885, MT6889, MT6893. Each file starts with the MTK GFH magic `MMM\x01` and
carries a 256-byte RSA-2048 modulus at offset `0x4C4`.

## SLA Keys

Four RSA-2048 public keys extracted from `SLA_Challenge.dll` (OPlus build
2021-11-23) are embedded in `src/kaeru_mtk/data/sla_keys.py`. Key #1 is shared
by seven SoCs (MT6763, MT6833, MT6853, MT6873, MT6877, MT6885, MT6889).

## Verification

```bash
ruff check src tests
pytest                    # 53 tests
```

## License

Apache-2.0. The bundled auth files are unmodified extracts from the public
`EduardoC3677/opencode` repository. The four RSA-2048 SLA public keys are
extracted from the publicly distributed `SLA_Challenge.dll`. No private keys
are or have ever been shipped.