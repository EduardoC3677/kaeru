# kaeru-mtk

Open-source MediaTek BROM/DA flasher for OnePlus / OPPO devices, Windows-first, Python.

This is a clean-room re-implementation of the on-the-wire protocol used by OPPO's
proprietary `OPlusFlashTool` / `ToolsHub` against MediaTek-based phones. The intent
is **security research, recovery from soft-bricks, and bootloader-unlock workflows**
that the vendor refuses to support officially.

The reverse-engineering notes that backed this work live under
[`docs/analysis/`](../../docs/analysis/) at the repo root:

- [`mtk-da-brom.md`](../../docs/analysis/mtk-da-brom.md) — DA / BROM keys, auth_sv5
- [`opseclib-dll.md`](../../docs/analysis/opseclib-dll.md) — host-side crypto facade
- [`oplus-toolshub-bins.md`](../../docs/analysis/oplus-toolshub-bins.md) — OPPO toolset
- [`servermanager-exe.md`](../../docs/analysis/servermanager-exe.md) — third-party MITM proxy

## Status

Alpha. The transport, BROM framing, format parsers (scatter, auth_sv5, OFP), CLI,
WinUSB-via-Zadig helper, and the test harness are functional. Destructive paths
(scatter flash, OFP flash, partition erase) are **gated behind explicit confirm
flags** until the DA-side write protocol is verified against more hardware.

## Install

Windows (recommended):

```pwsh
py -3 -m pip install -e .
kaeru-mtk driver install
```

Linux:

```bash
python -m pip install -e .
sudo apt install libusb-1.0-0
sudo cp scripts/51-mediatek.rules /etc/udev/rules.d/   # see below
sudo udevadm control --reload-rules
```

## Workflow

```
+----------------------+   1. handshake A0 0A 50 05 -> ~A0 ~0A ~50 ~05
|  phone in BROM mode  |   2. GET_HW_CODE / GET_TARGET_CONFIG / GET_ME_ID
|  (Vol-Down + USB-C)  |   3. SLA challenge (if locked)         <-- needs auth_sv5.auth
+----------+-----------+   4. SEND_DA + JUMP_DA
           |               5. DA hello -> READ_DATA / WRITE_DATA / FORMAT_DATA
           v
   +-------+--------+
   |   kaeru-mtk    |
   +----------------+
```

## Subcommands

```text
kaeru-mtk detect                           # enumerate connected MTK BROM/Preloader devices
kaeru-mtk info --da DA.bin --auth-dir MTKResource
kaeru-mtk dump --partition oplusreserve1 --out reserve1.bin --da DA.bin --auth-dir MTKResource
kaeru-mtk readback-all --out-dir backup/ --da DA.bin --auth-dir MTKResource --exclude-sensitive
kaeru-mtk flash partition --partition boot --image boot.img --da DA.bin --auth-dir MTKResource --i-know-what-im-doing
kaeru-mtk flash scatter --scatter MT6877_Android_scatter.txt --dry-run
kaeru-mtk flash ofp --ofp OnePlus_X.ofp --dry-run
kaeru-mtk unlock-bl --confirm-unlock --da DA.bin --auth-dir MTKResource
kaeru-mtk erase --partition oplusreserve2 --da DA.bin --auth-dir MTKResource
kaeru-mtk diag imei --da DA.bin --auth-dir MTKResource
kaeru-mtk driver status
kaeru-mtk driver install
```

Run `kaeru-mtk <subcommand> --help` for full flag listings.

## Architecture

Strict layering, no spaghetti:

```text
src/kaeru_mtk/
├── transport/        USB only (libusb / WinUSB / mock). Knows nothing about MTK.
├── protocol/         BROM frame, DA v5 frame, DA v6 frame, SLA. Pure protocol.
├── formats/          scatter, auth_sv5, DA blob header, OFP. Pure parsing.
├── oneplus/          OPlus-specific glue: auth-file selection, unlock flag, readback list.
├── driver/           Windows WinUSB / Zadig integration helper.
├── commands/         orchestration: maps user intent (dump/flash/unlock) onto the layers.
├── cli.py            argparse front-end.
└── utils/            logging, errors, hex.
```

Each layer is independently importable and unit-testable. `transport/mock.py`
provides a `MockTransport` that records writes and replays queued reads, so the
BROM/DA framing tests run with no hardware.

## Driver setup (Windows)

MediaTek BROM exposes USB ID `0E8D:0003`. Windows binds it to a generic serial
driver by default, which libusb cannot claim. Replace the driver with WinUSB
via Zadig:

```pwsh
kaeru-mtk driver install
```

This downloads the latest portable Zadig from the official GitHub releases,
launches it, and prints step-by-step instructions. Re-run `kaeru-mtk detect`
afterwards to confirm.

## Authentication

OPPO/OnePlus phones with `secure_boot=1` and `sla_en=1` require an `auth_sv5.auth`
file signed by the OEM RSA-2048 key. The file is per-SoC. The OPPO toolkit ships
the per-SoC tree under `MTKResource/<SoC>/auth_sv5.auth`. Point `--auth-dir`
at that directory; `kaeru-mtk` will pick the correct file based on the device's
reported hwcode.

If the device reports `sla_en=0` and `secure_boot=0`, pass `--skip-auth` to
bypass auth file selection.

## License

Apache-2.0. The OPPO/MediaTek binaries analysed under `docs/analysis/` are
**not** redistributed in this repo and remain copyright their respective owners.
This tool ships **no proprietary code, keys, certs, or DA images**. You provide
the DA blob and auth files on the command line.

## Non-goals

- Wrapping or bundling the closed `FlashToolLib.dll`. We re-implement the
  protocol; we do not load vendor DLLs.
- Replacing `mtkclient` for SoCs already covered by it; this tool focuses on
  the OPPO/OnePlus auth wrapper specifically.
- Bypassing SLA on locked devices. If your phone has `sla_en=1` and you do not
  hold the OEM private key, this tool will refuse to proceed.
