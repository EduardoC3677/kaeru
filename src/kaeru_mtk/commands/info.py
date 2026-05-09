from __future__ import annotations

import argparse
from pathlib import Path

from kaeru_mtk.commands._session import open_brom_session
from kaeru_mtk.data.auth_index import best_bundle_for_hwcode
from kaeru_mtk.data.soc_db import find_by_hwcode
from kaeru_mtk.utils.errors import DeviceNotFoundError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


def info(args: argparse.Namespace) -> int:
    try:
        session = open_brom_session()
    except DeviceNotFoundError as e:
        print(f"error: {e}")
        return 1

    config = session.config
    if config is None:
        print("error: could not get target config")
        session.close()
        return 1

    print("=== BROM Target Configuration ===")
    print(f"  HW Code:      0x{config.hw_code:04x}")
    print(f"  HW Subcode:   0x{config.hw_subcode:04x}")
    print(f"  HW Version:   0x{config.hw_version:04x}")
    print(f"  SW Version:   0x{config.sw_version:04x}")
    print(f"  Secure Boot:  {config.secure_boot}")
    print(f"  SLA Enabled:  {config.sla_enabled}")
    print(f"  DAA Enabled:  {config.daa_enabled}")
    if config.me_id:
        print(f"  ME ID:        {config.me_id.hex()}")

    socs = find_by_hwcode(config.hw_code)
    if socs:
        print(f"\n  Matched SoC:   {socs[0].name} ({socs[0].arch}, {socs[0].family})")
        if len(socs) > 1:
            print(f"  Also matches:  {', '.join(s.name for s in socs[1:])}")

    bundle = best_bundle_for_hwcode(config.hw_code)
    if bundle:
        sla = f"key #{bundle.sla_key.index}" if bundle.sla_key else "no embedded match"
        print(f"\n  Bundled auth:  {bundle.path.name}")
        print(f"  SLA key:       {sla}")
    else:
        print("\n  Bundled auth:  none")

    if args.auth_file:
        auth_path = Path(args.auth_file)
        if auth_path.exists():
            from kaeru_mtk.protocol.sla import SlaAuthenticator
            sla = SlaAuthenticator(session.brom)
            result = sla.authenticate(auth_path.read_bytes())
            print(f"\n  SLA Auth:      {'SUCCESS' if result else 'FAILED (expected without private key)'}")
        else:
            print(f"\n  Auth file not found: {args.auth_file}")

    session.close()
    return 0


__all__ = ["info"]
