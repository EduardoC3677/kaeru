#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
analyze_lk.py - Static analysis helper for MediaTek LK (Little Kernel)
                bootloader images and adjacent firmware blobs.

Given a MediaTek LK image (or any of the companion .img / .bin blobs dumped
from a device), this script will:

  * Detect the container format (MTK BFBF/BCBC, Android boot/vendor_boot,
    AVB, USF preloader, raw, ...).
  * Strip the MTK GFH/BFBF header and expose the raw payload.
  * Run capstone over the payload (auto-detecting AArch64 vs ARMv7) and
    optionally dump the disassembly.
  * Extract printable ASCII strings.
  * Classify the strings into useful buckets:
        - fastboot top-level commands       (flash:, erase:, getvar:, ...)
        - fastboot getvar variables         (version, unlocked, secure, ...)
        - oem subcommands                   (oem usb2jtag, oem p2u, ...)
        - boot modes                        (META, FACTORY, RECOVERY, ...)
        - keypad / GPIO references          (kpd_hw_factory_key, vol_down ...)
        - SoC / platform identifiers        (MT6897, mediatek,*, oplus,* ...)
        - preloader / BROM / DA references
  * Print a Markdown-friendly summary so the output can be pasted straight
    into docs/analysis/*.md.

This script is intentionally read-only and dependency-light: it only needs
``capstone`` (``pip install capstone``).  It does NOT modify the input file.

Examples
--------

    # Full report on lk.img to stdout
    python3 scripts/analysis/analyze_lk.py lk.img

    # Just dump disassembly to a file
    python3 scripts/analysis/analyze_lk.py lk.img --disasm out.S

    # Strings-only summary on a non-LK blob
    python3 scripts/analysis/analyze_lk.py mmcblk0boot0.bin --no-disasm
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from typing import Iterable

try:
    from capstone import Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:  # pragma: no cover
    Cs = None  # type: ignore[assignment]


MTK_BFBF_MAGIC = 0x58881688          # GFH "outer" header magic
MTK_BCBC_MAGIC = 0x58891688          # GFH per-image header magic

# Default LK load address for AArch64 MediaTek SoCs (MT6877+, MT6895, MT6897, ...).
# 32-bit LK images on older SoCs typically load at 0x41E00000 or 0x4C400000.
# This is a hint for capstone's pretty output, not a requirement.
DEFAULT_LOAD_BASE_AARCH64 = 0x4C400000
DEFAULT_LOAD_BASE_ARMV7   = 0x41E00000


@dataclass
class Container:
    kind: str                   # "mtk", "android_boot", "vendor_boot", "avb",
                                # "usf_preloader", "mtk_seccfg", "raw"
    payload_offset: int
    payload_size: int
    name: str = ""              # MTK image name, e.g. "lk", "tinysys-scp-RV55_A"
    extra: dict = field(default_factory=dict)


def detect_container(data: bytes) -> Container:
    """Identify the wrapper format of ``data``."""
    if len(data) < 0x40:
        return Container("raw", 0, len(data))

    magic = struct.unpack_from("<I", data, 0)[0]

    # MediaTek BFBF/GFH wrapper (lk.img, scp.img, tee.img, ...).
    if magic == MTK_BFBF_MAGIC:
        psize = struct.unpack_from("<I", data, 4)[0]
        name = data[8:40].split(b"\x00", 1)[0].decode("ascii", "replace")
        # The payload always starts at +0x200 in the MTK BFBF layout used by
        # MT6xxx 64-bit chips.  Older SoCs sometimes use +0x100, but +0x200
        # has been the norm since MT6779.
        return Container("mtk", 0x200, psize, name=name)

    if data[:8] == b"ANDROID!":
        # Standard Android boot.img - we don't peel further here, the strings
        # extractor copes fine with the kernel/ramdisk concatenation.
        return Container("android_boot", 0, len(data))

    if data[:4] == b"VNDR":
        return Container("vendor_boot", 0, len(data))

    if data[:4] == b"AVB0":
        return Container("avb", 0, len(data))

    if data[:8] in (b"UFS_BOOT", b"USF_BOOT"):
        # MediaTek "UFS_BOOT" wrapper used in mmcblk0boot[01].bin.  Real
        # preloader payload sits at +0x10000 (entry list at +0x10).  We leave
        # it raw so the user can carve further if needed.
        return Container("ufs_boot", 0, len(data))

    if data[:4] == b"MMMM":
        # MTK seccfg / sec_misc partition.
        return Container("mtk_seccfg", 0, len(data))

    if magic == 0x014D4D4D:          # "MMM\x01" - preloader.bin / pl.img
        return Container("mtk_preloader", 0, len(data))

    if magic == 0x9FB73A5A:           # OPLUS reserve partition signature
        return Container("oplus_reserve", 0, len(data))

    return Container("raw", 0, len(data))


def extract_strings(buf: bytes, min_len: int = 4) -> list[str]:
    """Pull printable ASCII runs out of ``buf``."""
    out: list[str] = []
    cur = bytearray()
    for byte in buf:
        if 32 <= byte < 127:
            cur.append(byte)
            continue
        if len(cur) >= min_len:
            out.append(cur.decode("ascii"))
        cur.clear()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii"))
    return out


KNOWN_FASTBOOT_CMDS = (
    "continue", "reboot", "reboot-bootloader", "reboot-recovery",
    "reboot-fastboot", "boot", "flash:", "erase:", "getvar:", "download:",
    "upload", "verify", "set_active:", "snapshot-update", "flashing",
    "stage", "format", "partition", "signature", "devices",
)

KNOWN_GETVAR_VARS = (
    "version", "version-bootloader", "version-baseband", "product",
    "serialno", "secure", "unlocked", "off-mode-charge", "battery-voltage",
    "battery-soc-ok", "variant", "partition-type:", "partition-size:",
    "is-userspace", "max-download-size", "slot-count", "current-slot",
    "has-slot", "slot-suffixes", "slot-successful", "slot-unbootable",
    "slot-retry-count", "hw-revision", "warranty", "platform", "has-vbmeta",
    "board", "socid",
)

BOOT_MODE_TOKENS = (
    "NORMAL", "RECOVERY", "FACTORY", "META", "FASTBOOT", "ATE",
    "ADVANCED META", "ADVANCED_META", "ALARM", "KERNEL_POWER", "SW_RESET",
    "HW_RESET", "BOOT_REASON", "WDT", "CHARGING", "POWER_OFF",
    "POWER OFF CHARGING",
)

KEY_TOKENS_RE = re.compile(
    r"(VOLUME|VOL_UP|VOL_DOWN|VOLUP|VOLDOWN|POWER_KEY|HOME_KEY|"
    r"KEY_PRESS|key_press|gpio_keypad|kpd_hw_recovery_key|"
    r"kpd_hw_factory_key|kpd_sw_pwrkey|kpd_hw_pwrkey|kpd_sw_rstkey|"
    r"kpd_hw_rstkey|vol_down_key_check|hw-recovery-key|hw-factory-key)",
    re.I,
)

PRELOADER_RE = re.compile(
    r"(BROM|preloader|brom|DA |download_agent|SP Flash|META_COM|"
    r"Disable_BROM_CMD|UART META|usbdl|usbdl_flag)",
    re.I,
)

OEM_PREFIX = re.compile(r"^oem[ _\-:]")


def classify(strings: Iterable[str]) -> dict[str, list[str]]:
    s = list(strings)
    sset = set(s)

    fastboot_cmds = sorted(c for c in KNOWN_FASTBOOT_CMDS if c in sset)
    getvar_vars = sorted(v for v in KNOWN_GETVAR_VARS if v in sset)
    oem_cmds = sorted({x for x in s if OEM_PREFIX.match(x) and len(x) < 64})
    boot_modes = sorted(
        {x for x in s if any(t in x for t in BOOT_MODE_TOKENS) and len(x) < 80}
    )
    key_refs = sorted({x for x in s if KEY_TOKENS_RE.search(x) and len(x) < 120})
    preloader = sorted({x for x in s if PRELOADER_RE.search(x) and len(x) < 120})

    soc = sorted({
        x for x in s
        if re.search(r"(MT[68]\d{3}|mediatek,|oplus[_,]|oneplus|prj[a-z_]*name)", x)
        and len(x) < 80
    })

    return {
        "fastboot_commands": fastboot_cmds,
        "getvar_variables": getvar_vars,
        "oem_subcommands": oem_cmds,
        "boot_modes": boot_modes,
        "key_gpio_refs": key_refs,
        "preloader_brom": preloader,
        "soc_platform": soc,
    }


def looks_like_aarch64(payload: bytes) -> bool:
    """Heuristic: the first instruction of an AArch64 LK is almost always
    ``mrs xN, currentel`` (encoding ``d538_42xx``) or a branch into the
    relocation stub.  A 32-bit ARM LK starts with ``b reset`` (``ea_xxxxxx``)
    or with the classic ARM exception vector table.
    """
    if len(payload) < 4:
        return False
    word = struct.unpack("<I", payload[:4])[0]
    # Very conservative: AArch64 MRS to currentel.
    if (word & 0xFFFF_FF00) == 0xD538_4200:
        return True
    # Heuristic: AArch64 instructions almost always have one of a small set
    # of high-byte values; ARMv7 ``b`` is 0xEA at byte 3.
    if (word >> 24) == 0xEA:
        return False
    return True


def disassemble(payload: bytes, base: int, is_aarch64: bool, limit: int) -> list[str]:
    if Cs is None:
        return ["; capstone not installed - install with: pip install capstone"]
    arch = CS_ARCH_ARM64 if is_aarch64 else CS_ARCH_ARM
    md = Cs(arch, CS_MODE_ARM)
    out: list[str] = []
    step = 4
    pos = 0
    end = len(payload) - (len(payload) % step)
    while pos < end and len(out) < limit:
        ins_iter = md.disasm(payload[pos:], base + pos)
        decoded_any = False
        for ins in ins_iter:
            out.append(f"{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")
            pos = (ins.address - base) + ins.size
            decoded_any = True
            if len(out) >= limit:
                break
        if not decoded_any:
            word = struct.unpack_from("<I", payload, pos)[0]
            out.append(f"{base + pos:08x}: .word    0x{word:08x}")
            pos += step
    return out


def report(path: str, args: argparse.Namespace) -> int:
    with open(path, "rb") as f:
        data = f.read()

    container = detect_container(data)
    print(f"# {os.path.basename(path)}")
    print()
    print(f"- size:      {len(data):,} bytes")
    print(f"- container: {container.kind}")
    if container.name:
        print(f"- name:      {container.name}")
    print(f"- payload:   offset 0x{container.payload_offset:x}, "
          f"size 0x{container.payload_size or len(data):x}")

    payload_end = (
        container.payload_offset + container.payload_size
        if container.payload_size else len(data)
    )
    payload = data[container.payload_offset:payload_end]

    if container.kind == "mtk" and payload:
        is_a64 = looks_like_aarch64(payload)
        base = DEFAULT_LOAD_BASE_AARCH64 if is_a64 else DEFAULT_LOAD_BASE_ARMV7
        print(f"- arch hint: {'AArch64' if is_a64 else 'ARMv7'} "
              f"(load base assumed 0x{base:08x})")

        do_disasm = args.disasm or not args.no_disasm
        if do_disasm:
            lines = disassemble(payload, base, is_a64, args.disasm_limit)
            if args.disasm:
                with open(args.disasm, "w") as g:
                    g.write("\n".join(lines))
                print(f"- disasm:    {len(lines):,} lines -> {args.disasm}")
            else:
                print(f"\n## first {min(args.preview, len(lines))} instructions\n")
                print("```")
                for ln in lines[:args.preview]:
                    print(ln)
                print("```")

    print("\n## strings\n")
    strings = extract_strings(payload, min_len=args.min_string_len)
    print(f"- total: {len(strings):,}")

    if args.strings_out:
        with open(args.strings_out, "w") as g:
            g.write("\n".join(strings))
        print(f"- saved: {args.strings_out}")

    buckets = classify(strings)
    for name, items in buckets.items():
        if not items:
            continue
        print(f"\n### {name} ({len(items)})\n")
        for it in items[:args.bucket_limit]:
            print(f"- `{it}`")
        if len(items) > args.bucket_limit:
            print(f"- ... ({len(items) - args.bucket_limit} more)")

    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("image", help="Path to .img or .bin file")
    p.add_argument("--disasm", metavar="FILE",
                   help="Write full disassembly to FILE instead of previewing")
    p.add_argument("--no-disasm", action="store_true",
                   help="Skip capstone disassembly (strings only)")
    p.add_argument("--disasm-limit", type=int, default=200_000,
                   help="Maximum number of instructions to decode (default 200k)")
    p.add_argument("--preview", type=int, default=64,
                   help="Instructions to preview when --disasm is not set")
    p.add_argument("--min-string-len", type=int, default=4)
    p.add_argument("--bucket-limit", type=int, default=80,
                   help="Max items printed per category")
    p.add_argument("--strings-out", metavar="FILE",
                   help="Write the full string table to FILE")
    args = p.parse_args()
    return report(args.image, args)


if __name__ == "__main__":
    sys.exit(main())
