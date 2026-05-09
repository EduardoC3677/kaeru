# kaeru-mtk

Windows-first OnePlus / OPPO MediaTek flasher built on top of
[mtkclient](https://github.com/bkerler/mtkclient).

## What this is — and what it isn't

`kaeru-mtk` does **not** reimplement the MediaTek BROM/DA on-the-wire
protocol. The actual on-the-wire work — handshake, exploits
(`kamakiri`, `kamakiri2`, `carbonara`, `hashimoto`, `heapbait`), DA loading,
and partition I/O — is delegated to `mtkclient`, which is the mature,
hardware-tested reference implementation.

What kaeru-mtk adds on top:

* **15 bundled `auth_sv5.auth` files** under [`src/kaeru_mtk/data/auth/`](src/kaeru_mtk/data/auth/),
  covering MT6763, MT6765, MT6769, MT6771, MT6779, MT6833, MT6853, MT6873,
  MT6877, MT6885, MT6889, MT6893. Each file starts with the MTK GFH magic
  `MMM\x01` and carries a 256-byte RSA-2048 modulus at offset `0x4C4` plus a
  256-byte signature at the end.
* **The four RSA-2048 SLA public keys** extracted from `SLA_Challenge.dll`
  (OPlus build 2021-11-23), embedded in
  [`src/kaeru_mtk/data/sla_keys.py`](src/kaeru_mtk/data/sla_keys.py). Cross-
  referencing each auth file's modulus against this set shows that **Key #1
  is shared by seven SoCs** (MT6763, MT6833, MT6853, MT6873, MT6877, MT6885,
  MT6889).
* **A SoC database** ([`src/kaeru_mtk/data/soc_db.py`](src/kaeru_mtk/data/soc_db.py))
  whose hwcodes are cross-checked against `mtkclient`'s `brom_config.py`.
  Every entry is verified.
* **Automatic auth selection**: when you run a command that talks to a
  device, kaeru-mtk asks mtkclient for the device's hwcode, looks up the
  correct bundled auth file, and forwards it via `mtk --auth <path>`.
* **Windows driver helper**: `kaeru-mtk driver install` downloads Zadig and
  walks through binding WinUSB to the MediaTek BROM endpoint.

The `kaeru-mtk` CLI also provides safer defaults than raw `mtk` for the
OPPO/OnePlus flow: every destructive action requires an explicit
`--confirm-brick-risk` (or `--confirm-unlock --allow-dangerous` for BL
unlock), and every action supports `--dry-run` to preview the underlying
`mtk` invocation.

## Install

`mtkclient` is not on PyPI, so the recommended install is:

```bash
pip install -e .
pip install git+https://github.com/bkerler/mtkclient.git
```

Or, in one shot:

```bash
pip install -e .[mtkclient]
```

If `mtk` is available on `PATH` (or you set `KAERU_MTK_BIN` to a custom
command), kaeru-mtk will use it. Otherwise it falls back to invoking
`mtk.py` from the imported `mtkclient` package directly.

## Usage

```bash
kaeru-mtk --help                                    # top-level help
kaeru-mtk socs                                      # list known SoCs (hwcode, family, arch, bundled auth?)
kaeru-mtk auth list                                 # 15 bundled auth files + their matched SLA key index
kaeru-mtk auth resolve 0x959                        # resolve a specific hwcode
kaeru-mtk exploit list                              # show kamakiri / kamakiri2 / carbonara / hashimoto / heapbait

# Windows: bind WinUSB via Zadig
kaeru-mtk driver install
kaeru-mtk driver status

# Detect a connected device
kaeru-mtk detect

# Probe device + auto-select bundled auth
kaeru-mtk info

# Partition I/O (dry-run prints the mtk invocation; without --dry-run it actually runs it)
kaeru-mtk flash read    --partition boot     --out boot.bin
kaeru-mtk flash readall --out-dir backup/    --exclude-sensitive
kaeru-mtk flash write   --partition recovery --image recovery.img --confirm-brick-risk
kaeru-mtk flash erase   --partition userdata --confirm-brick-risk

# OPPO/OnePlus BL unlock (dry-run prints the steps; full automation is intentionally not bundled, see below)
kaeru-mtk unlock-bl --dry-run
```

### Authentication auto-resolution

Most commands accept an explicit `--auth-file <path>`. Without it,
kaeru-mtk will:

1. Run `mtk gettargetconfig` and parse the `hw_code` from its output.
2. Look up the hwcode in
   [`src/kaeru_mtk/data/soc_db.py`](src/kaeru_mtk/data/soc_db.py).
3. Pick the bundled auth file under
   [`src/kaeru_mtk/data/auth/`](src/kaeru_mtk/data/auth/) whose stem matches.
4. Forward it as `mtk --auth <path>`.

You can disable this behaviour with `--no-auto-auth`.

### BL unlock

`unlock-bl` only supports `--dry-run` in this release. The full unlock
procedure is device-specific (per-product offsets and structures inside
`oplusreserve1`), and shipping a one-size-fits-all flipper would brick
devices. The intended flow is:

1. `kaeru-mtk flash read --partition oplusreserve1 --out reserve1.bin`
2. Edit the unlock flag at the offset documented for **your** device.
3. `kaeru-mtk flash write --partition oplusreserve1 --image reserve1.bin --confirm-brick-risk`

## Architecture

```
src/kaeru_mtk/
├── cli.py                argparse, subcommand dispatch
├── auth/                 hwcode → bundled-auth resolver
├── commands/             one module per CLI subcommand
├── data/
│   ├── auth/             15 real auth_sv5.auth blobs (MMM\x01 GFH)
│   ├── auth_index.py     parses bundled auth + matches SLA key
│   ├── sla_keys.py       4 RSA-2048 keys from SLA_Challenge.dll
│   ├── soc_db.py         hwcode → SocSpec, verified vs mtkclient
│   └── usb_ids.py        MediaTek VID/PID list
├── driver/
│   └── windows.py        Zadig downloader + PnpDevice driver query
├── runner/
│   └── mtkclient.py      subprocess wrapper around `mtk`
└── utils/                logging, error types
```

## Verification

```bash
ruff check src tests
pytest                    # 41 tests covering SoC DB, auth bundles, SLA keys, runner, CLI
```

## License

Apache-2.0. The bundled auth files are unmodified extracts from the public
`EduardoC3677/opencode` repository (themselves originally extracted from
the publicly distributed OPlus Tools-Hub). The four RSA-2048 SLA public
keys are extracted from the publicly distributed `SLA_Challenge.dll`. No
private keys are or have ever been shipped.

`mtkclient` itself is GPL-3.0; running it as a subprocess from kaeru-mtk
does not affect kaeru-mtk's own licensing.
