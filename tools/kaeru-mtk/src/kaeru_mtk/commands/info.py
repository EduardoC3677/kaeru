from __future__ import annotations

from pathlib import Path
from typing import Any

from kaeru_mtk.commands._session import open_session
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


def cmd_info(args: Any) -> int:
    auth_dir = Path(args.auth_dir) if args.auth_dir else None
    da_path = Path(args.da) if args.da else None
    with open_session(auth_dir=auth_dir, da_path=da_path, skip_auth=args.skip_auth) as ctx:
        t = ctx.target
        print("=== MediaTek BROM Info ===")
        print(f"  HW code         : 0x{t.hw_code:04x}")
        print(f"  HW subcode      : 0x{t.hw_subcode:04x}")
        print(f"  HW version      : 0x{t.hw_version:04x}")
        print(f"  SW version      : 0x{t.sw_version:04x}")
        print(f"  Target config   : 0x{t.target_config_raw:08x}")
        print(f"   secure boot    : {t.secure_boot}")
        print(f"   SLA            : {t.serial_link_authorization}")
        print(f"   DAA            : {t.download_agent_authorization}")
        if t.me_id:
            print(f"  ME-ID           : {t.me_id.hex()}")
        if ctx.auth_bundle:
            ab = ctx.auth_bundle
            print(f"  Auth platform   : {ab.platform}")
            print(f"  Auth file       : {ab.auth_sv5_path}")
            print(f"  Auth modulus    : {ab.auth.rsa_modulus[:32].hex()}... (256 B)")
    return 0
