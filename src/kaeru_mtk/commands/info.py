from __future__ import annotations

from typing import Any

from kaeru_mtk.commands._session import open_session_from_args
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


def cmd_info(args: Any) -> int:
    with open_session_from_args(args) as ctx:
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
        if ctx.soc:
            s = ctx.soc
            print(f"  SoC             : {s.name} ({s.notes})")
            print(f"  Arch / DA       : {s.arch} / DA v{s.da_version}")
            print(f"  Exploit recipe  : {' -> '.join(s.exploits) or '(none)'}")
        if ctx.auth_bundle:
            ab = ctx.auth_bundle
            print(f"  Auth platform   : {ab.platform}")
            print(f"  Auth file       : {ab.auth_sv5_path}")
            print(f"  Auth modulus    : {ab.auth.rsa_modulus[:32].hex()}... (256 B)")
            if ab.sla_key:
                print(f"  SLA key match   : key #{ab.sla_key.index} (RSA-2048, OPlus embedded)")
        if ctx.sla_state:
            print(f"  SLA handshake   : {ctx.sla_state.state.value}")
    return 0
