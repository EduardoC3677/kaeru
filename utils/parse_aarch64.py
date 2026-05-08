#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 KAERU Labs, S.L.
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AArch64 / chained-GFH variant of utils/parse.py.
#
# Walks every GFH FILE_INFO record in the supplied lk image, classifies
# each sub-image (AArch64 LK / cert / DTB blob), and for every AArch64
# sub-image runs a capstone-driven analysis pass that recovers
# function prologues, adrp+add string xrefs, and well-known fastboot
# helper signatures.
#
# The output is a per-stage section in a defconfig-compatible file plus
# a JSON dump that the AArch64 build of kaeru can consume.

import json
import os
import re
import struct
import sys
from argparse import ArgumentParser
from collections import defaultdict
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    sys.stderr.write("capstone not installed: pip install capstone\n")
    sys.exit(1)


GFH_FILE_INFO_MAGIC = b"\x88\x16\x88\x58"
GFH_BL_INFO_MAGIC = b"\x89\x16\x89\x58"
GFH_FILE_INFO_HDR_LEN = 0x200
DTB_MAGIC = b"\xd0\x0d\xfe\xed"
CERT_NAMES = (b"cert1", b"cert2", b"BLCERT", b"CERT")


def find_subimages(blob):
    out = []
    for m in re.finditer(re.escape(GFH_FILE_INFO_MAGIC), blob):
        h = m.start()
        if h + 8 > len(blob):
            continue
        code_sz = struct.unpack_from("<I", blob, h + 4)[0]
        if code_sz == 0 or code_sz > 0x800000:
            continue
        out.append({
            "header_off": h,
            "code_off": h + GFH_FILE_INFO_HDR_LEN,
            "code_size": code_sz,
            "code_end": h + GFH_FILE_INFO_HDR_LEN + code_sz,
        })
    return out


def classify(blob, sub):
    co, sz = sub["code_off"], sub["code_size"]
    payload = blob[co:co + min(sz, 0x80)]
    name_field = blob[sub["header_off"] + 8:sub["header_off"] + 0x20]
    if any(n in name_field for n in CERT_NAMES):
        return "cert"
    if DTB_MAGIC in blob[co:co + sz]:
        if sz < 0x10000:
            return "dtb"
    if sz < 0x1000:
        return "small"
    if len(payload) >= 4:
        first = struct.unpack_from("<I", payload, 0)[0]
        if first == 0xD53800FC:
            return "aarch64-el1-shim"
        if (first & 0xFC000000) == 0x94000000:
            return "aarch64-lk"
        if (first & 0x9F000000) == 0x90000000:
            return "aarch64-lk"
        if first == 0x9100E29D or (first & 0xFFC07FFF) == 0xA9807BFD:
            return "aarch64-lk"
    return "aarch64-lk"


def adrp(w, pc):
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 0x3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm |= ~((1 << 21) - 1)
    return w & 0x1F, (pc & ~0xFFF) + (imm << 12)


def add_imm(w):
    if (w & 0xFF800000) != 0x91000000:
        return None
    sh = (w >> 22) & 1
    imm12 = (w >> 10) & 0xFFF
    if sh:
        imm12 <<= 12
    return w & 0x1F, (w >> 5) & 0x1F, imm12


def is_bl(w): return (w & 0xFC000000) == 0x94000000
def bl_target(w, pc):
    imm26 = w & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 |= ~((1 << 26) - 1)
    return pc + (imm26 << 2)


def is_stp_x29x30_pre(w):  return (w & 0xFFC07FFF) == 0xA9807BFD
def is_stp_x29x30_signed(w): return (w & 0xFFC07FFF) == 0xA9007BFD
def is_paciasp(w): return w == 0xD503233F
def is_pacibsp(w): return w == 0xD503237F
def is_sub_sp_imm12(w): return (w & 0xFF8003FF) == 0xD10003FF


def function_starts(blob, code_off, code_size):
    starts = []
    end = code_off + code_size
    for off in range(code_off, end, 4):
        w = struct.unpack_from('<I', blob, off)[0]
        nxt = struct.unpack_from('<I', blob, off + 4)[0] if off + 4 < end else 0
        if (is_stp_x29x30_pre(w) or is_paciasp(w) or is_pacibsp(w)
                or (is_sub_sp_imm12(w) and is_stp_x29x30_signed(nxt))):
            starts.append(off)
    return sorted(set(starts))


def all_string_offsets(blob, needle):
    out = []
    pos = 0
    nd = b"\0" + needle + b"\0"
    while True:
        i = blob.find(nd, pos)
        if i < 0:
            return out
        out.append(i + 1)
        pos = i + 1


def cstr_at(blob, off, maxlen=64):
    if off >= len(blob):
        return None
    end = blob.find(b"\0", off, off + maxlen + 1)
    if end < 0:
        return None
    try:
        return blob[off:end].decode("ascii")
    except UnicodeDecodeError:
        return None


def is_printable(s):
    return s and len(s) >= 2 and all(0x20 <= ord(c) < 0x7F for c in s)


def analyze_aarch64_lk(blob, sub, label):
    co, sz = sub["code_off"], sub["code_size"]
    starts = function_starts(blob, co, sz)
    end = co + sz

    cmd_strings = [b"reboot", b"reboot-bootloader", b"continue", b"boot",
                   b"download:", b"flash:", b"erase:", b"getvar:",
                   b"flashing unlock", b"flashing lock",
                   b"reboot-recovery", b"reboot-fastboot"]
    pub_strings = [b"version", b"version-bootloader", b"version-baseband",
                   b"secure", b"unlocked", b"product",
                   b"max-download-size", b"slot-count", b"current-slot",
                   b"serialno", b"off-mode-charge", b"is-userspace"]
    cmd_locs = {nd.decode(): all_string_offsets(blob, nd) for nd in cmd_strings}
    pub_locs = {nd.decode(): all_string_offsets(blob, nd) for nd in pub_strings}
    cmd_locs = {k: [o for o in v if co <= o < end] for k, v in cmd_locs.items()}
    pub_locs = {k: [o for o in v if co <= o < end] for k, v in pub_locs.items()}
    cmd_locs = {k: v for k, v in cmd_locs.items() if v}
    pub_locs = {k: v for k, v in pub_locs.items() if v}

    str_to_name = {}
    for k, v in cmd_locs.items():
        for o in v:
            str_to_name[o] = ("cmd", k)
    for k, v in pub_locs.items():
        for o in v:
            str_to_name[o] = ("pub", k)

    register_score = defaultdict(lambda: defaultdict(set))
    publish_score = defaultdict(lambda: defaultdict(set))

    state = {}
    cur_fn = None
    fn_iter = iter(starts)
    next_fn = next(fn_iter, None)
    for off in range(co, end, 4):
        if next_fn is not None and off == next_fn:
            cur_fn = next_fn
            next_fn = next(fn_iter, None)
            state.clear()
        w = struct.unpack_from('<I', blob, off)[0]
        a = adrp(w, off)
        if a:
            state[a[0]] = a[1]
            continue
        b = add_imm(w)
        if b:
            rd, rn, imm = b
            if rn in state:
                state[rd] = state[rn] + imm
            elif rd != rn:
                state.pop(rd, None)
            continue
        if is_bl(w):
            tgt = bl_target(w, off)
            x0 = state.get(0)
            if x0 in str_to_name:
                kind, name = str_to_name[x0]
                if kind == "cmd":
                    register_score[tgt][cur_fn].add(name)
                else:
                    publish_score[tgt][cur_fn].add(name)
            state.clear()
            continue
        rd_kill = w & 0x1F
        if rd_kill in state and rd_kill != 31:
            state.pop(rd_kill, None)

    def best(score):
        ranked = []
        for callee, callers in score.items():
            distinct = set().union(*callers.values())
            ranked.append((callee, distinct, callers))
        ranked.sort(key=lambda x: -len(x[1]))
        return ranked[:3]

    fmt_okay = blob.find(b"OKAY%s\0", co, end)
    fmt_fail = blob.find(b"FAIL%s\0", co, end)
    fmt_info = blob.find(b"INFO%s\0", co, end)

    def first_x0_string(fn):
        nxt = bisect_right_starts(starts, fn)
        e = starts[nxt] if nxt < len(starts) else end
        st = {}
        for o in range(fn, min(fn + 0x40, e), 4):
            w = struct.unpack_from('<I', blob, o)[0]
            a = adrp(w, o)
            if a:
                st[a[0]] = a[1]
                continue
            b = add_imm(w)
            if b:
                rd, rn, imm = b
                if rn in st and rd == 0:
                    return cstr_at(blob, st[rn] + imm)
            if is_bl(w):
                return None
        return None

    okay = [s for s in starts if first_x0_string(s) == "OKAY"]
    fail = [s for s in starts if first_x0_string(s) == "FAIL"]
    info = [s for s in starts if first_x0_string(s) == "INFO"]

    findings = {
        "label": label,
        "code_off": co,
        "code_size": sz,
        "function_count": len(starts),
        "cmd_strings_present": list(cmd_locs.keys()),
        "pub_strings_present": list(pub_locs.keys()),
        "fastboot_register_candidates": [
            {"callee": f"0x{c:X}",
             "distinct_cmds": sorted(d),
             "callers": [f"0x{k:X}" for k in callers],
             }
            for c, d, callers in best(register_score)
        ],
        "fastboot_publish_candidates": [
            {"callee": f"0x{c:X}",
             "distinct_vars": sorted(d),
             "callers": [f"0x{k:X}" for k in callers],
             }
            for c, d, callers in best(publish_score)
        ],
        "okay_format_at": f"0x{fmt_okay:X}" if fmt_okay >= 0 else None,
        "fail_format_at": f"0x{fmt_fail:X}" if fmt_fail >= 0 else None,
        "info_format_at": f"0x{fmt_info:X}" if fmt_info >= 0 else None,
        "fastboot_okay_candidates": [f"0x{x:X}" for x in okay],
        "fastboot_fail_candidates": [f"0x{x:X}" for x in fail],
        "fastboot_info_candidates": [f"0x{x:X}" for x in info],
    }
    return findings


def bisect_right_starts(arr, va):
    import bisect
    return bisect.bisect_right(arr, va)


def main():
    parser = ArgumentParser()
    parser.add_argument("lk", help="LK image (chained GFH)")
    parser.add_argument("defconfig", nargs="?", help="Optional defconfig to update")
    parser.add_argument("--json", help="Optional JSON output path")
    args = parser.parse_args()

    blob = Path(args.lk).read_bytes()
    subs = find_subimages(blob)
    print(f"[+] {len(subs)} GFH FILE_INFO sub-images found")

    findings = []
    for i, sub in enumerate(subs):
        kind = classify(blob, sub)
        label = f"stage{i}-{kind}"
        if kind != "aarch64-lk":
            print(f"  - {label}: {sub['code_off']:#x}+{sub['code_size']:#x} (skipped)")
            continue
        print(f"  + {label}: {sub['code_off']:#x}+{sub['code_size']:#x}")
        f = analyze_aarch64_lk(blob, sub, label)
        findings.append(f)
        for key in ("cmd_strings_present", "pub_strings_present"):
            if f[key]:
                print(f"      {key}: {f[key][:8]}{'...' if len(f[key]) > 8 else ''}")
        for cand in f["fastboot_register_candidates"][:1]:
            print(f"      fastboot_register? callee={cand['callee']}  distinct_cmds={cand['distinct_cmds']}")
        for cand in f["fastboot_publish_candidates"][:1]:
            print(f"      fastboot_publish?  callee={cand['callee']}  distinct_vars={cand['distinct_vars']}")
        if f["fastboot_okay_candidates"]:
            print(f"      fastboot_okay candidates: {f['fastboot_okay_candidates']}")
        if f["fastboot_fail_candidates"]:
            print(f"      fastboot_fail candidates: {f['fastboot_fail_candidates']}")
        if f["fastboot_info_candidates"]:
            print(f"      fastboot_info candidates: {f['fastboot_info_candidates']}")

    def primary_score(f):
        s = len(f["cmd_strings_present"]) + len(f["pub_strings_present"])
        for c in f["fastboot_register_candidates"]:
            s += 4 * len(c["distinct_cmds"])
        for c in f["fastboot_publish_candidates"]:
            s += 4 * len(c["distinct_vars"])
        s += 2 * len(f["fastboot_okay_candidates"])
        s += 2 * len(f["fastboot_fail_candidates"])
        s += 2 * len(f["fastboot_info_candidates"])
        return s

    primary = max(findings, key=primary_score, default=None)
    cfg = {}
    if args.defconfig and os.path.exists(args.defconfig):
        for line in Path(args.defconfig).read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    if primary and primary_score(primary) >= 16:
        cfg["CONFIG_BOOTLOADER_BASE"] = "0x0"
        cfg["CONFIG_BOOTLOADER_SIZE"] = f"0x{primary['code_size']:X}"
        cfg["CONFIG_FASTBOOT_LK_STAGE_OFFSET"] = f"0x{primary['code_off']:X}"
        regc = primary["fastboot_register_candidates"]
        if regc and len(regc[0]["distinct_cmds"]) >= 4:
            cfg["CONFIG_FASTBOOT_REGISTER_FILE_OFFSET"] = regc[0]["callee"]
        pubc = primary["fastboot_publish_candidates"]
        if pubc and len(pubc[0]["distinct_vars"]) >= 4:
            cfg["CONFIG_FASTBOOT_PUBLISH_FILE_OFFSET"] = pubc[0]["callee"]
        if primary["fastboot_okay_candidates"]:
            cfg["CONFIG_FASTBOOT_OKAY_FILE_OFFSET"] = primary["fastboot_okay_candidates"][0]
        if primary["fastboot_fail_candidates"]:
            cfg["CONFIG_FASTBOOT_FAIL_FILE_OFFSET"] = primary["fastboot_fail_candidates"][0]
        if primary["fastboot_info_candidates"]:
            cfg["CONFIG_FASTBOOT_INFO_FILE_OFFSET"] = primary["fastboot_info_candidates"][0]
    if args.defconfig:
        with open(args.defconfig, "w") as f:
            for k, v in sorted(cfg.items()):
                f.write(f"{k}={v}\n")
        print(f"[+] wrote {args.defconfig}")
    if args.json:
        Path(args.json).write_text(json.dumps(findings, indent=2))
        print(f"[+] wrote {args.json}")

    print()
    print("# WARNING: every CONFIG_*_FILE_OFFSET above is the FILE OFFSET")
    print("# inside the corresponding sub-image. The runtime virtual address")
    print("# depends on where the LK loader maps that sub-image; you MUST")
    print("# verify the load address on hardware before any patch is applied.")


if __name__ == "__main__":
    main()
