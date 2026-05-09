from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from kaeru_mtk.data.soc_db import SocSpec, get_primary_soc_by_hwcode
from kaeru_mtk.oneplus.auth import (
    AuthBundle,
    default_auth_resolver,
    resolve_auth_for_hwcode,
)
from kaeru_mtk.protocol.brom import BromClient, BromTarget
from kaeru_mtk.protocol.da_v5 import DaV5Client
from kaeru_mtk.protocol.da_v6 import DaV6Client
from kaeru_mtk.protocol.sla import SlaChallenge, SlaState, perform_sla
from kaeru_mtk.transport.usb import UsbTransport
from kaeru_mtk.utils.errors import AuthError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class SessionContext:
    transport: UsbTransport
    brom: BromClient
    target: BromTarget
    soc: SocSpec | None = None
    auth_bundle: AuthBundle | None = None
    sla_state: SlaChallenge | None = None
    da_v5: DaV5Client | None = None
    da_v6: DaV6Client | None = None


def open_session_from_args(args) -> Iterator[SessionContext]:  # type: ignore[name-defined]
    auth_dir = Path(args.auth_dir) if getattr(args, "auth_dir", None) else None
    da_path = Path(args.da) if getattr(args, "da", None) else None
    return open_session(
        auth_dir=auth_dir,
        da_path=da_path,
        skip_auth=getattr(args, "skip_auth", False),
        skip_sla=getattr(args, "skip_sla", False),
    )


@contextmanager
def open_session(
    *,
    auth_dir: Path | None,
    da_path: Path | None,
    skip_auth: bool = False,
    skip_sla: bool = False,
) -> Iterator[SessionContext]:
    transport = UsbTransport()
    transport.open()
    try:
        brom = BromClient(transport)
        log.info("Performing BROM handshake...")
        brom.handshake()
        target = brom.probe_target()
        soc = get_primary_soc_by_hwcode(target.hw_code)
        log.info(
            "Target: hwcode=0x%04x sw=0x%04x soc=%s arch=%s "
            "secure_boot=%s sla=%s daa=%s",
            target.hw_code,
            target.sw_version,
            soc.name if soc else "?",
            soc.arch if soc else "?",
            target.secure_boot,
            target.serial_link_authorization,
            target.download_agent_authorization,
        )

        ctx = SessionContext(transport=transport, brom=brom, target=target, soc=soc)

        if not skip_auth:
            try:
                soc_map = default_auth_resolver(auth_dir)
                ctx.auth_bundle = resolve_auth_for_hwcode(target.hw_code, soc_map)
                log.info(
                    "Auth bundle: %s (%d bytes, sla_key=%s)",
                    ctx.auth_bundle.platform,
                    ctx.auth_bundle.auth.total_size,
                    f"#{ctx.auth_bundle.sla_key.index}" if ctx.auth_bundle.sla_key else "none",
                )
            except AuthError as e:
                if target.serial_link_authorization or target.download_agent_authorization:
                    raise
                log.warning("auth resolution skipped (device does not require it): %s", e)

        if (
            target.serial_link_authorization
            and ctx.auth_bundle is not None
            and not skip_sla
        ):
            log.info("Device requires SLA - performing challenge-response")
            ctx.sla_state = perform_sla(brom, auth=ctx.auth_bundle.auth)
            if ctx.sla_state.state != SlaState.RESPONSE_OK:
                log.warning(
                    "SLA exchange did not return OK (%s); subsequent DA upload "
                    "may be rejected. Try kaeru-mtk exploit run --auto first.",
                    ctx.sla_state.state.value,
                )

        yield ctx
    finally:
        transport.close()
