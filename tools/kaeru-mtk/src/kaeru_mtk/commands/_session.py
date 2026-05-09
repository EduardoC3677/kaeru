from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from kaeru_mtk.oneplus.auth import (
    AuthBundle,
    default_auth_resolver,
    resolve_auth_for_hwcode,
)
from kaeru_mtk.protocol.brom import BromClient, BromTarget
from kaeru_mtk.protocol.da_v5 import DaV5Client
from kaeru_mtk.protocol.da_v6 import DaV6Client
from kaeru_mtk.transport.usb import UsbTransport
from kaeru_mtk.utils.errors import AuthError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class SessionContext:
    transport: UsbTransport
    brom: BromClient
    target: BromTarget
    auth_bundle: AuthBundle | None = None
    da_v5: DaV5Client | None = None
    da_v6: DaV6Client | None = None


@contextmanager
def open_session(
    *,
    auth_dir: Path | None,
    da_path: Path | None,
    skip_auth: bool = False,
) -> Iterator[SessionContext]:
    transport = UsbTransport()
    transport.open()
    try:
        brom = BromClient(transport)
        log.info("Performing BROM handshake...")
        brom.handshake()
        target = brom.probe_target()
        log.info(
            "Target: hwcode=0x%04x sw=0x%04x secure_boot=%s sla=%s daa=%s",
            target.hw_code,
            target.sw_version,
            target.secure_boot,
            target.serial_link_authorization,
            target.download_agent_authorization,
        )

        ctx = SessionContext(transport=transport, brom=brom, target=target)

        if auth_dir and not skip_auth:
            try:
                soc_map = default_auth_resolver(auth_dir)
                ctx.auth_bundle = resolve_auth_for_hwcode(target.hw_code, soc_map)
                log.info(
                    "Auth bundle: %s (%d bytes)",
                    ctx.auth_bundle.platform,
                    ctx.auth_bundle.auth.total_size,
                )
            except AuthError as e:
                if target.serial_link_authorization or target.download_agent_authorization:
                    raise
                log.warning("auth resolution failed (device does not require it): %s", e)

        yield ctx
    finally:
        transport.close()
