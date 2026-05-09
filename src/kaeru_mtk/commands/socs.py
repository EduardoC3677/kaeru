from __future__ import annotations

import argparse

from kaeru_mtk.data.soc_db import all_socs


def run(_args: argparse.Namespace) -> int:
    print(f"{'name':<10} {'hwcode':<8} {'arch':<8} {'auth':<6} family")
    print(f"{'-'*10} {'-'*8} {'-'*8} {'-'*6} {'-'*30}")
    for s in all_socs():
        auth = "yes" if s.auth_stem else "-"
        print(f"{s.name:<10} 0x{s.hw_code:04x}   {s.arch:<8} {auth:<6} {s.family}")
    print()
    print("Hwcodes are cross-checked against bkerler/mtkclient brom_config.py.")
    return 0


__all__ = ["run"]
