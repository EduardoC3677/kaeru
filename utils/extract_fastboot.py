#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 kaeru contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
#
"""Extract fastboot commands, variables, boot modes and key combinations from an
LK (Little Kernel) image.

Supports both ARMv7-Thumb and AArch64 LK builds. Detection strategy:

  1. Identify fastboot_register / fastboot_publish by locating known seed
     strings (e.g. "oem off-mode-charge") and walking back from their
     ADRP+ADD (or LDR-literal / MOV-MOVT) cross-references to the closest
     BL target. The most-frequent BL target preceded by a string-loading
     pair is fastboot_register / fastboot_publish.
  2. Once those callees are known, sweep every BL to them and recover the
     two preceding string operands from the surrounding instructions.
  3. Boot modes and key combinations are heuristically dumped via known
     MTK string tokens ("g_boot_mode", "KPD_*", "BOOT_NORMAL", ...).
"""
import argparse
import re
import struct
import sys
from collections import Counter

import capstone


def parse_lk_header(buf: bytes):
    if len(buf) < 8 or struct.unpack('<I', buf[0:4])[0] != 0x58881688:
        raise SystemExit('not an LK image (bad magic)')
    code_size = struct.unpack('<I', buf[4:8])[0]
    return 512, code_size


def detect_arch(code: bytes) -> str:
    md64 = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md32 = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    n64 = sum(1 for _ in md64.disasm(code[:4096], 0))
    n32 = sum(1 for _ in md32.disasm(code[:4096], 0))
    return 'arm64' if n64 >= n32 else 'thumb'


def collect_strings(code: bytes):
    out = {}
    for m in re.finditer(rb'[\x20-\x7e]{2,}\x00', code):
        s = m.group()[:-1].decode('latin1')
        out[m.start()] = s
    return out


def disasm_arm64(code: bytes):
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    adrp = {}
    add_imm = {}
    bl_at = {}
    for off in range(0, len(code) - 4, 4):
        word = code[off:off + 4]
        ins_list = list(md.disasm(word, off, 1))
        if not ins_list:
            continue
        ins = ins_list[0]
        m = ins.mnemonic
        if m == 'adrp' and len(ins.operands) == 2:
            rd = ins.operands[0].reg
            imm = ins.operands[1].imm
            delta = imm - (off & ~0xFFF)
            adrp[off] = (rd, delta)
        elif m == 'add' and len(ins.operands) == 3 \
                and ins.operands[2].type == capstone.arm64.ARM64_OP_IMM:
            rd = ins.operands[0].reg
            rn = ins.operands[1].reg
            imm = ins.operands[2].imm
            add_imm[off] = (rd, rn, imm)
        elif m == 'bl' and len(ins.operands) == 1:
            bl_at[off] = ins.operands[0].imm
    return adrp, add_imm, bl_at


def resolve_string_loads_arm64(adrp, add_imm, code):
    """Return dict file_off_of_load_seq_end -> (reg, str_offset_in_code)."""
    loads = {}
    for off, (rd, delta) in adrp.items():
        for k in range(1, 9):
            a_off = off + k * 4
            if a_off in add_imm:
                ard, arn, aimm = add_imm[a_off]
                if ard == rd and arn == rd:
                    str_off = (off & ~0xFFF) + delta + aimm
                    if 0 <= str_off < len(code):
                        loads[a_off] = (rd, str_off)
                    break
    return loads


SEED_FASTBOOT_CMDS = [
    'oem off-mode-charge',
    'oem p2u',
    'oem reboot-recovery',
    'oem reboot-fastboot',
    'oem unlock',
    'oem lock',
    'oem device-info',
    'getvar',
    'download',
    'flash',
    'erase',
    'reboot',
    'reboot-bootloader',
    'continue',
    'boot',
    'powerdown',
    'set_active',
]

SEED_FASTBOOT_VARS = [
    'product',
    'serialno',
    'version',
    'version-bootloader',
    'version-baseband',
    'secure',
    'unlocked',
    'off-mode-charge',
    'battery-voltage',
    'battery-soc-ok',
    'variant',
    'max-download-size',
    'partition-type',
    'partition-size',
    'has-slot',
    'current-slot',
    'slot-count',
    'hw-revision',
]


def find_string_offset(strings, value):
    for off, s in strings.items():
        if s == value:
            return off
    return None


def callees_for_string_seeds(loads_by_offset, bl_at, strings, seeds):
    """For each instruction-offset that loads a seed string, find the next BL.
    Tally BL targets to identify the most-likely register/publish callee."""
    seed_offsets = {find_string_offset(strings, s): s for s in seeds}
    seed_offsets.pop(None, None)
    target_counter = Counter()
    for ins_off, (_reg, str_off) in loads_by_offset.items():
        if str_off in seed_offsets:
            for k in range(1, 16):
                next_off = ins_off + k * 4
                if next_off in bl_at:
                    target_counter[bl_at[next_off]] += 1
                    break
    return target_counter


def extract_register_calls(code, bl_at, callee_addr, loads_by_offset,
                           strings, lookback=64):
    """For every BL to callee_addr, walk backward through instructions
    immediately preceding the BL and record the most recent string-load
    that lands in each register. Stop tracking a register once a write to
    that register from a non-string source (mov, ldr, csel, add-from-other-reg,
    BL return) is seen between the load and the BL."""
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    bl_to_callee = sorted(off for off, t in bl_at.items() if t == callee_addr)
    results = []
    for bl_off in bl_to_callee:
        per_reg = {}
        invalid = set()
        start = max(0, bl_off - lookback)
        seq = list(md.disasm(code[start:bl_off], start, lookback // 4))
        for ins in reversed(seq):
            if ins.address in loads_by_offset:
                reg, str_off = loads_by_offset[ins.address]
                if reg not in invalid and reg not in per_reg \
                        and str_off in strings:
                    per_reg[reg] = (strings[str_off], str_off)
                    invalid.add(reg)
                continue
            if not ins.operands:
                continue
            dst = ins.operands[0]
            if dst.type == capstone.arm64.ARM64_OP_REG:
                invalid.add(dst.reg)
        results.append((bl_off, per_reg))
    return results


def _bisect_right(arr, x):
    lo, hi = 0, len(arr)
    while lo < hi:
        mid = (lo + hi) // 2
        if arr[mid] <= x:
            lo = mid + 1
        else:
            hi = mid
    return lo


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('lk', help='LK image file')
    ap.add_argument('--limit', type=int, default=0,
                    help='Limit listed entries (0 = all)')
    args = ap.parse_args()

    with open(args.lk, 'rb') as f:
        buf = f.read()

    code_off, code_size = parse_lk_header(buf)
    code = buf[code_off:code_off + code_size]
    arch = detect_arch(code)
    strings = collect_strings(code)

    print(f'== LK Image Analysis ==')
    print(f'File:        {args.lk}')
    print(f'Code size:   0x{code_size:X}')
    print(f'Detected:    {arch}')
    print(f'Strings:     {len(strings)}')
    print()

    if arch != 'arm64':
        print('AArch32/Thumb mode not yet implemented in this extractor.',
              file=sys.stderr)
        print('Use utils/parse.py for ARMv7 LK images.', file=sys.stderr)
        sys.exit(2)

    adrp, add_imm, bl_at = disasm_arm64(code)
    loads = resolve_string_loads_arm64(adrp, add_imm, code)

    print(f'BL sites:    {len(bl_at)}')
    print(f'ADRP+ADD :   {len(loads)}')
    print()

    cmd_callees = callees_for_string_seeds(loads, bl_at, strings,
                                           SEED_FASTBOOT_CMDS)
    var_callees = callees_for_string_seeds(loads, bl_at, strings,
                                           SEED_FASTBOOT_VARS)

    print('== Top BL targets following fastboot-command-like strings ==')
    for tgt, cnt in cmd_callees.most_common(5):
        print(f'  0x{tgt:08X}: {cnt} matches')

    print()
    print('== Top BL targets following fastboot-variable-like strings ==')
    for tgt, cnt in var_callees.most_common(5):
        print(f'  0x{tgt:08X}: {cnt} matches')

    if not cmd_callees:
        print('Could not infer fastboot_register address.', file=sys.stderr)
        sys.exit(3)

    fb_register = cmd_callees.most_common(1)[0][0]
    fb_publishes = [t for t, _ in var_callees.most_common(3)
                    if t != fb_register]
    print()
    print(f'Inferred fastboot_register @ 0x{fb_register:08X}')
    for i, p in enumerate(fb_publishes):
        print(f'Inferred fastboot_publish#{i + 1} @ 0x{p:08X}')

    cmd_calls = extract_register_calls(code, bl_at, fb_register, loads,
                                       strings)
    cmd_strings = []
    seen = set()
    for bl_off, per_reg in cmd_calls:
        x0 = per_reg.get(capstone.arm64.ARM64_REG_X0)
        if x0 is None:
            continue
        s = x0[0]
        if s and s not in seen and s.isascii():
            seen.add(s)
            cmd_strings.append((bl_off, s))

    print()
    print(f'== fastboot commands (first arg of {len(cmd_calls)} calls)'
          f' ==')
    for bl_off, s in cmd_strings if not args.limit else cmd_strings[:args.limit]:
        print(f'  call@0x{bl_off:06X}  {s!r}')

    for fi, fb_publish in enumerate(fb_publishes):
        pub_calls = extract_register_calls(code, bl_at, fb_publish, loads,
                                           strings)
        pub_pairs = []
        for bl_off, per_reg in pub_calls:
            x0 = per_reg.get(capstone.arm64.ARM64_REG_X0)
            x1 = per_reg.get(capstone.arm64.ARM64_REG_X1)
            name = x0[0] if x0 else None
            value = x1[0] if x1 else None
            if name is not None:
                pub_pairs.append((bl_off, name, value))

        print()
        print(f'== fastboot variables via callee#{fi + 1} '
              f'@ 0x{fb_publish:08X} ({len(pub_calls)} calls) ==')
        for bl_off, name, value in (pub_pairs if not args.limit
                                    else pub_pairs[:args.limit]):
            v = '?' if value is None else repr(value)
            print(f'  call@0x{bl_off:06X}  {name!r:40s} = {v}')

    print()
    print('== Boot modes & key combinations (string heuristics) ==')
    BOOT_KEYWORDS = ('boot_mode', 'BOOT_MODE', 'BOOT_NORMAL', 'META_BOOT',
                     'RECOVERY_BOOT', 'FASTBOOT', 'KERNEL_POWER_OFF_CHARGING',
                     'ATE_FACTORY', 'ALARM_BOOT', 'g_boot_mode', 'KPD_',
                     'mtk_detect_key', 'detect_key', 'key_press', 'volume_up',
                     'volume_down', 'volume up', 'volume down', 'power key',
                     'POWER_KEY', 'VOLUMEUP', 'VOLUMEDOWN', 'press key')
    boot_hits = [(off, s) for off, s in strings.items()
                 if any(kw in s for kw in BOOT_KEYWORDS) and len(s) < 120]
    boot_hits.sort()
    for off, s in (boot_hits if not args.limit else boot_hits[:args.limit]):
        print(f'  +0x{off:06X}: {s!r}')

    print()
    print('== Hidden / OEM-style commands (raw strings starting with "oem ") ==')
    oem_hits = sorted([(o, s) for o, s in strings.items()
                       if s.startswith('oem ') and len(s) < 80])
    for off, s in (oem_hits if not args.limit else oem_hits[:args.limit]):
        print(f'  +0x{off:06X}: {s!r}')


if __name__ == '__main__':
    main()
