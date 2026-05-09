from __future__ import annotations

import argparse

from kaeru_mtk.auth.resolver import resolve_auth
from kaeru_mtk.data.auth_index import all_bundles
from kaeru_mtk.utils.errors import KaeruError


def list_bundles(_args: argparse.Namespace) -> int:
    bundles = all_bundles()
    if not bundles:
        print("No bundled auth files found.")
        return 0
    print(f"{'file':<22} {'soc':<8} {'hwcode':<8} {'sla key':<10} arch")
    print(f"{'-'*22} {'-'*8} {'-'*8} {'-'*10} {'-'*8}")
    for b in bundles:
        sla = f"#{b.sla_key.index}" if b.sla_key else "-"
        print(
            f"{b.path.name:<22} {b.soc.name:<8} 0x{b.soc.hw_code:04x}   "
            f"{sla:<10} {b.soc.arch}"
        )
    print(f"\n{len(bundles)} auth files bundled.")
    return 0


def _parse_hw_code(s: str) -> int:
    text = s.strip().lower()
    if text.startswith("0x"):
        return int(text, 16)
    if any(c in "abcdef" for c in text):
        return int(text, 16)
    return int(text, 10)


def resolve(args: argparse.Namespace) -> int:
    try:
        hw_code = _parse_hw_code(args.hw_code)
    except ValueError as e:
        raise KaeruError(f"invalid hw_code {args.hw_code!r}: {e}") from e

    res = resolve_auth(hw_code)
    print(f"hw_code: 0x{res.hw_code:04x}")
    if res.soc_candidates:
        print("matching SoCs:")
        for s in res.soc_candidates:
            extra = f"  (aliases: {', '.join(s.aliases)})" if s.aliases else ""
            print(f"  {s.name:<8} {s.arch:<8} {s.family}{extra}")
    else:
        print("no SoC matches this hw_code in our database")
    if res.bundle is not None:
        b = res.bundle
        sla = f"key #{b.sla_key.index}" if b.sla_key else "no embedded match"
        print(f"\nbundled auth: {b.path.name}  ({sla})")
        return 0
    print("\nno bundled auth available for this hwcode")
    return 1


__all__ = ["list_bundles", "resolve"]
