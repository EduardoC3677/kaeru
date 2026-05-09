#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# extract_mtk_sla_keys.py
#
# Static extractor for the MediaTek SV5 Anti-Clone / SLA key material that
# ships with OPLUS / OPPO's "OPLUSFLASHTOOLNEXT" (a.k.a. ToolsHub) Windows
# flash-tool stack.
#
# Reads:
#   - <dir>/Plugins/FLASH_SRV/FlashTool_SDK_Full/SLA_Challenge.dll
#       (signed OPLUS build, 2021-11-23, OpenSSL/LIBEAY32-backed) - contains
#       up to 4 RSA-2048 hex-encoded SLA / Anti-Clone (AC) public keys
#       embedded in the .rdata section together with the public exponent
#       0x010001.
#   - <dir>/Plugins/FLASH_SRV/FlashTool_SDK_Full/Modules/ModMtkV5FlashWorker/
#         Resources/SLA_Challenge.dll
#       (the neutral 2006 MTK stub - no exports beyond SLA_Challenge / _END,
#       no LIBEAY32 import - included for diff comparison).
#   - <dir>/Plugins/resource/MTKResource/MTK/MT*/auth_sv5.auth
#       MediaTek GFH-wrapped per-SoC Anti-Clone authentication blobs
#       consumed by the BROM during USB-DL handshake. Each file:
#           0x000-0x037   GFH FILE_INFO          (constant)
#           0x038-0x047   GFH ANTI_CLONE header  (constant, type=0x0005)
#           0x048-0x1ab   padding
#           0x1ac-0x1bf   AC version/flags       (constant)
#           0x1c0-0x2b7   padding
#           0x2b8-0x33a   per-SoC info / pubkey-hash blob (131 bytes)
#           0x33b        '\0'
#           0x33c-0x3b7   per-SoC info area #2 (124 bytes)
#           0x3b8-0x4c3   padding
#           0x4c4-0x5c3   ** RSA-2048 raw modulus (256 bytes) - the AC key **
#           0x5c4-0x6cf   padding
#           0x6d0-0x752   per-SoC info / pubkey-hash blob #2 (131 bytes,
#                         identical to the one at 0x2b8)
#           0x753        '\0'
#           0x754-0x886   per-SoC info area #2 (307 bytes)
#           ...           remaining body up to 0x8ff
#           0x900-0x9ff   RSA-2048 signature over the GFH#2 body
#       (MT6769 has an extra 0x10-byte GFH type=0x0060 record between
#       offsets 0x7d0 and 0x7e0; the AC modulus offset shifts by +0x10.)
#
# Outputs:
#   - extracts the 4 RSA-2048 moduli from SLA_Challenge.dll
#   - extracts the 256-byte AC modulus from every auth_sv5.auth
#   - prints SHA-256 fingerprints
#   - cross-matches each per-SoC AC modulus against the 4 keys in the DLL
#
# Pure static. Reads files only. Does not run, decrypt, or sign anything.
#
# Reproduces the analysis in docs/analysis/mtk-da-brom.md.
#
# Usage:
#   python3 scripts/analysis/extract_mtk_sla_keys.py /path/to/opencode/O+
#
# (the path should point at the "O+" folder of EduardoC3677/opencode, the
# repository the original investigation analysed.)

from __future__ import annotations

import argparse
import hashlib
import os
import re
import struct
import sys
from typing import Dict, List, Optional, Tuple


PUB_EXP = 0x10001
RSA_HEX_LEN = 512  # RSA-2048 modulus = 256 bytes = 512 hex chars
AC_MOD_OFFSET = 0x4C4
AC_MOD_LEN = 0x100  # 256 bytes
EXTRA_GFH_FILESIZE = 2272  # MT6769 carries one extra 0x10-byte GFH type=0x0060 record; default file is 2256 bytes
EXTRA_SHIFT = 0x10  # AC modulus offset shifts by exactly the size of that extra GFH record


def extract_rsa_hex_strings(data: bytes) -> List[Tuple[int, str]]:
    """Return [(offset, hex_string), ...] for every NUL-terminated ASCII hex
    string of exactly 512 chars (i.e. RSA-2048 modulus) in `data`."""
    out: List[Tuple[int, str]] = []
    i = 0
    n = len(data)
    while i < n:
        if 0x20 <= data[i] < 0x7F:
            j = i
            while j < n and 0x20 <= data[j] < 0x7F:
                j += 1
            blob = data[i:j]
            if len(blob) == RSA_HEX_LEN and re.fullmatch(rb"[0-9A-Fa-f]+", blob):
                out.append((i, blob.decode("ascii")))
            i = j + 1
        else:
            i += 1
    return out


def parse_sla_dll(path: str) -> Dict[str, object]:
    """Pull the 4 RSA-2048 hex moduli from SLA_Challenge.dll's .rdata."""
    with open(path, "rb") as f:
        data = f.read()
    keys = extract_rsa_hex_strings(data)
    return {
        "path": path,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "keys": keys,  # list of (offset, hex)
    }


def parse_auth_sv5(path: str) -> Optional[Dict[str, object]]:
    """Extract the 256-byte AC RSA modulus from a MediaTek auth_sv5.auth."""
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(b"MMM\x01"):
        return None
    shift = EXTRA_SHIFT if len(data) == EXTRA_GFH_FILESIZE else 0
    off = AC_MOD_OFFSET + shift
    modulus = data[off : off + AC_MOD_LEN]
    if len(modulus) != AC_MOD_LEN:
        return None
    sig = data[-AC_MOD_LEN:]  # 256-byte tail = RSA-2048 signature
    return {
        "path": path,
        "size": len(data),
        "modulus_offset": off,
        "modulus_hex": modulus.hex(),
        "modulus_sha256": hashlib.sha256(modulus).hexdigest(),
        "signature_hex": sig.hex(),
        "signature_sha256": hashlib.sha256(sig).hexdigest(),
        "high_bit_set": bool(modulus[0] & 0x80),
        "is_odd": bool(modulus[-1] & 1),
    }


def gather_auth_files(root: str) -> List[str]:
    out: List[str] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            if fn == "auth_sv5.auth":
                out.append(os.path.join(dirpath, fn))
    out.sort()
    return out


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Extract MTK SLA / Anti-Clone keys from an OPLUSFLASHTOOLNEXT tree."
    )
    ap.add_argument(
        "root",
        help='Path to the "O+" directory of EduardoC3677/opencode (or any tree '
        "that contains the OPLUSFLASHTOOLNEXT layout).",
    )
    args = ap.parse_args(argv)

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"error: {root!r} is not a directory", file=sys.stderr)
        return 2

    # 1. SLA_Challenge.dll - the 4 OPLUS host-side public keys (signed 2021).
    sla_dll_oplus = os.path.join(
        root, "Plugins", "FLASH_SRV", "FlashTool_SDK_Full", "SLA_Challenge.dll"
    )
    sla_dll_stub = os.path.join(
        root,
        "Plugins",
        "FLASH_SRV",
        "FlashTool_SDK_Full",
        "Modules",
        "ModMtkV5FlashWorker",
        "Resources",
        "SLA_Challenge.dll",
    )

    sla_keys: List[Tuple[int, str]] = []
    print("\n## SLA_Challenge.dll (OPLUS, 2021-11-23, LIBEAY32-backed)")
    if os.path.isfile(sla_dll_oplus):
        info = parse_sla_dll(sla_dll_oplus)
        keys = info["keys"]  # type: ignore[assignment]
        sla_keys = keys  # type: ignore[assignment]
        print(f"  path:    {sla_dll_oplus}")
        print(f"  size:    {info['size']} bytes")
        print(f"  sha256:  {info['sha256']}")
        print(f"  RSA-2048 hex moduli embedded ({len(keys)}):")
        for off, hx in keys:
            n = bytes.fromhex(hx)
            print(f"    off={off:#06x} sha256={hashlib.sha256(n).hexdigest()}")
            print(f"      first 16B = {n[:16].hex()}")
            print(f"      last  16B = {n[-16:].hex()}")
            print(f"      high_bit={bool(n[0] & 0x80)} odd={bool(n[-1] & 1)}")
        print(f"  public exponent (e) = 0x{PUB_EXP:06X}  (= 65537)")
    else:
        print(f"  MISSING: {sla_dll_oplus}")

    if os.path.isfile(sla_dll_stub):
        info = parse_sla_dll(sla_dll_stub)
        print()
        print("## SLA_Challenge.dll (neutral MTK stub, 2006-08-13)")
        print(f"  path:    {sla_dll_stub}")
        print(f"  size:    {info['size']} bytes")
        print(f"  sha256:  {info['sha256']}")
        print(f"  embedded RSA-2048 hex moduli: {len(info['keys'])}")  # expect 0
        if not info["keys"]:
            print("  (no embedded RSA keys - this is the unmodified MTK fallback)")

    # 2. auth_sv5.auth files - per-SoC AC RSA-2048 moduli + signatures.
    mtk_root = os.path.join(root, "Plugins", "resource", "MTKResource", "MTK")
    print("\n## auth_sv5.auth Anti-Clone keys")
    if not os.path.isdir(mtk_root):
        print(f"  MISSING: {mtk_root}")
        return 1
    files = gather_auth_files(mtk_root)
    print(f"  found {len(files)} files under {mtk_root}")

    soc_to_mod_sha: Dict[str, str] = {}
    soc_to_record: Dict[str, dict] = {}
    for p in files:
        soc = os.path.basename(os.path.dirname(p))
        rec = parse_auth_sv5(p)
        if rec is None:
            print(f"  {soc}: ERROR (not a GFH MMM\\x01 file)")
            continue
        soc_to_mod_sha[soc] = rec["modulus_sha256"]  # type: ignore[index]
        soc_to_record[soc] = rec  # type: ignore[assignment]

    # Group SoCs by AC modulus
    by_mod: Dict[str, List[str]] = {}
    for soc, sh in soc_to_mod_sha.items():
        by_mod.setdefault(sh, []).append(soc)

    print(f"\n  {len(by_mod)} distinct AC RSA-2048 moduli among {len(soc_to_mod_sha)} SoCs:")
    sla_sha = {hx: hashlib.sha256(bytes.fromhex(hx)).hexdigest() for _, hx in sla_keys}
    sla_sha_to_label = {h: f"SLA_Challenge.dll #{i+1}" for i, (_, hx) in enumerate(sla_keys) for h in [hashlib.sha256(bytes.fromhex(hx)).hexdigest()]}

    for sh in sorted(by_mod):
        socs = sorted(by_mod[sh])
        match = sla_sha_to_label.get(sh, "(per-SoC unique - not embedded in SLA_Challenge.dll)")
        print(f"  - AC sha256 = {sh}")
        print(f"    used by  : {socs}")
        print(f"    matches  : {match}")

    # 3. Final summary table.
    print("\n## Per-SoC summary")
    print(f"  {'SoC':<14} {'auth-file size':<14} {'AC modulus SHA-256':<70}")
    for soc in sorted(soc_to_record):
        rec = soc_to_record[soc]
        print(f"  {soc:<14} {rec['size']:<14} {rec['modulus_sha256']}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
