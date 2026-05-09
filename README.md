# kaeru-mtk

Open-source MediaTek BROM/DA flasher for OnePlus / OPPO devices, Windows-first, Python.

This is a clean-room re-implementation of the on-the-wire protocol used by
OPPO's proprietary `OPlusFlashTool` / `ToolsHub` against MediaTek-based phones.
It is intended for **security research, recovery from soft-bricks, and
bootloader-unlock workflows** that the vendor refuses to support officially.

## Features

- BROM handshake + identification (`hwcode`, `target_config`, `ME-ID`, `SoC-ID`).
- Auto-selection of the correct `auth_sv5.auth` file based on the connected
  device's `hwcode`, using **15 auth files bundled with the package** under
  [`src/kaeru_mtk/data/auth/`](src/kaeru_mtk/data/auth/) covering
  MT6763/65/69/71/79, MT6833/53/73/77/85/89/93.
- The four RSA-2048 SLA public keys extracted from `SLA_Challenge.dll` are
  hardcoded under [`src/kaeru_mtk/data/sla_keys.py`](src/kaeru_mtk/data/sla_keys.py).
  At connection time the auth modulus is matched against this set and the
  resulting `SlaKey` is attached to the session so `kaeru-mtk info` can show
  which embedded OPlus key your device authenticates against. Key #1 is shared
  by **seven** SoCs (MT6763, MT6833, MT6853, MT6873, MT6877, MT6885, MT6889).
- BROM exploits for SLA/DAA bypass:
  - `kamakiri` — classic USB control-transfer overflow for armv7 SoCs
    (MT6763 .. MT6785).
  - `kamakiri2` — USBDL overflow targeting the AArch64 BROM
    (Dimensity 700–1300; MT6833/53/73/77/85/89/93).
  - `hashimoto` — DMA-engine BROM dump primitive (armv7 only).
  - `carbonara` — alternative entry vector for SLA-required AArch64 chips.
  - `iguana` — direct WRITE32 patch of the BROM AC dispatch table; targets
    Dimensity 8100 / 8200 / 9000 / 9200 / 9300 (MT6895 / MT6896 / MT6983 /
    MT6985 / MT6897), where the older overflow primitives have been patched.
- DA v5 + DA v6 framing, including BROM-side `JUMP_DA64` for AArch64.
- Windows-first transport: `pyusb` + `libusb-package` + WinUSB, with a
  `kaeru-mtk driver install` helper that downloads Zadig and walks you through
  binding WinUSB to the MTK BROM endpoint.
- Partition dump / readback-all / flash partition / flash scatter / flash OFP /
  bootloader unlock / `diag imei`, all with `--dry-run` and explicit
  destructive-action confirmation flags.

## Install

```bash
pip install -e .[dev]
```

## CLI

```bash
kaeru-mtk --help
kaeru-mtk driver install                # Windows: download Zadig + bind WinUSB
kaeru-mtk detect                        # enumerate BROM devices
kaeru-mtk info                          # bundled auth + SLA key match auto-loaded
kaeru-mtk exploit list                  # show known exploits & per-SoC recipe
kaeru-mtk exploit run --dry-run         # auto-select exploit by hwcode
kaeru-mtk exploit run --exploit iguana --soc MT6897
kaeru-mtk dump --partition oplusreserve1 --out reserve1.bin --da DA.bin
kaeru-mtk readback-all --out-dir backup/ --exclude-sensitive
kaeru-mtk unlock-bl --confirm-unlock
```

`info`, `dump`, `readback-all`, `flash *`, `unlock-bl`, `erase`, `diag imei`
all auto-pick the bundled auth file matching the connected SoC. Pass
`--auth-dir <path>` to override with a user-provided MTKResource directory
(takes precedence over the bundled set).

## Layout

```
src/kaeru_mtk/
├── data/
│   ├── auth/                  15 bundled auth_sv5.auth files
│   ├── sla_keys.py            4 RSA-2048 SLA public keys + SoC->key map
│   └── soc_db.py              23 SoC entries (hwcode, arch, da_version, exploits)
├── transport/                 USB (pyusb + WinUSB) + MockTransport for tests
├── protocol/
│   ├── brom.py                BROM handshake + opcodes (READ32, WRITE32, SEND_DA, JUMP_DA{,64}, SLA, …)
│   ├── da_v5.py               DA-Legacy framing
│   ├── da_v6.py               DA xflash framing
│   ├── sla.py                 SLA challenge-response
│   └── exploits/              kamakiri, kamakiri2, hashimoto, carbonara, iguana
├── formats/                   scatter / auth_sv5 / DA blob / OFP / OPS
├── oneplus/                   auth resolver, unlock flow, readback list
├── driver/                    Windows Zadig + PnpDevice helpers
├── commands/                  CLI subcommands
└── cli.py                     argparse front-end
```

## Safety

Destructive actions (`flash partition`, `flash scatter`, `unlock-bl`, `erase`)
require explicit confirmation flags (`--i-know-what-im-doing`,
`--confirm-brick-risk`, `--confirm-unlock`, `--allow-dangerous`). `--dry-run`
is available everywhere a write would happen.

## License

Apache-2.0. The bundled auth files are mirrored from the public
`EduardoC3677/opencode` repository for reproducibility of the analysis; the
RSA-2048 moduli are public keys recovered from `SLA_Challenge.dll` via static
analysis. No private key material is contained in this repository.
