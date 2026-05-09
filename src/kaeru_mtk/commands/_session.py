from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass
from pathlib import Path

from kaeru_mtk.data.auth_index import best_bundle_for_hwcode
from kaeru_mtk.data.soc_db import SocSpec, find_by_hwcode
from kaeru_mtk.protocol.brom import BromProtocol, BromTargetConfig
from kaeru_mtk.protocol.da import DaProtocol
from kaeru_mtk.protocol.exploits import EXPLOIT_REGISTRY
from kaeru_mtk.protocol.sla import SlaAuthenticator
from kaeru_mtk.transport.usb import UsbTransport
from kaeru_mtk.utils.errors import KaeruError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class DeviceSession:
    transport: UsbTransport | None = None
    brom: BromProtocol | None = None
    da: DaProtocol | None = None
    config: BromTargetConfig | None = None
    soc: SocSpec | None = None
    sla_authenticated: bool = False
    exploit_used: str | None = None
    da_loaded: bool = False

    def close(self) -> None:
        if self.brom is not None:
            with contextlib.suppress(Exception):
                self.brom.disconnect()
        if self.da is not None:
            with contextlib.suppress(Exception):
                self.da.disconnect()
        if self.transport is not None:
            with contextlib.suppress(Exception):
                self.transport.disconnect()


def open_brom_session(pid: int | None = None) -> DeviceSession:
    session = DeviceSession()
    transport = UsbTransport(pid=pid)
    brom = BromProtocol(transport)
    config = brom.detect_device()
    session.transport = transport
    session.brom = brom
    session.config = config

    socs = find_by_hwcode(config.hw_code)
    if socs:
        session.soc = socs[0]
        log.info("Matched SoC: %s (%s)", session.soc.name, session.soc.arch)

    return session


def authenticate_session(session: DeviceSession, auth_dir: Path | None = None) -> bool:
    if session.config is None or session.brom is None:
        raise KaeruError("No BROM session")

    hw_code = session.config.hw_code
    bundle = best_bundle_for_hwcode(hw_code)
    if bundle is None:
        log.warning("No bundled auth for hw_code=0x%04x", hw_code)
        return False

    auth_data = bundle.path.read_bytes()
    sla = SlaAuthenticator(session.brom)
    result = sla.authenticate(auth_data)
    session.sla_authenticated = result
    return result


def exploit_session(
    session: DeviceSession,
    exploit_name: str | None = None,
    **kwargs,
) -> bool:
    if session.brom is None or session.config is None:
        raise KaeruError("No BROM session")

    hw_code = session.config.hw_code
    socs = find_by_hwcode(hw_code)

    if exploit_name:
        exploit_cls = EXPLOIT_REGISTRY.get(exploit_name)
        if exploit_cls is None:
            raise KaeruError(f"Unknown exploit: {exploit_name}")
        exploit = exploit_cls(session.brom)
    elif socs:
        arch = socs[0].arch
        if arch == "armv7":
            exploit = EXPLOIT_REGISTRY["kamakiri"](session.brom)
            exploit_name = "kamakiri"
        else:
            exploit = EXPLOIT_REGISTRY["kamakiri2"](session.brom)
            exploit_name = "kamakiri2"
    else:
        exploit = EXPLOIT_REGISTRY["kamakiri2"](session.brom)
        exploit_name = "kamakiri2"

    log.info("Running exploit: %s", exploit_name)
    result = exploit.execute(**kwargs)
    session.exploit_used = exploit_name
    return result.success


def wait_for_da(timeout: float = 30.0) -> DaProtocol | None:
    import usb.core

    deadline = time.time() + timeout
    while time.time() < deadline:
        dev = usb.core.find(idVendor=0x0E8D, idProduct=0x6000)
        if dev is not None:
            log.info("DA device found (0x0E8D:0x6000)")
            da = DaProtocol(None)
            da.connect()
            return da
        dev = usb.core.find(idVendor=0x0E8D, idProduct=0x2000)
        if dev is not None:
            log.info("Preloader device found (0x0E8D:0x2000)")
            da = DaProtocol(None)
            da.connect()
            return da
        time.sleep(0.5)
    log.warning("DA device not found within %.0f seconds", timeout)
    return None
