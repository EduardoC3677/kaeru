from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.request import urlopen

from kaeru_mtk.data.usb_ids import all_known_ids
from kaeru_mtk.utils.errors import DriverError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)

ZADIG_DOWNLOAD_URL = "https://github.com/pbatard/libwdi/releases/latest/download/zadig.exe"


@dataclass
class DriverStatus:
    vid: int
    pid: int
    present: bool
    driver: str | None
    instance_id: str | None

    @property
    def is_winusb(self) -> bool:
        return bool(self.driver) and self.driver.lower() == "winusb"


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _powershell_query(vid: int, pid: int) -> list[DriverStatus]:
    if not _is_windows():
        return []
    instance_filter = f"USB\\VID_{vid:04X}&PID_{pid:04X}*"
    ps = (
        "Get-PnpDevice -PresentOnly | "
        f"Where-Object {{ $_.InstanceId -like '{instance_filter}' }} | "
        "Select-Object InstanceId, Service, FriendlyName | "
        "ConvertTo-Json -Compress"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except FileNotFoundError as e:
        raise DriverError("powershell.exe not found; cannot query driver state") from e

    if out.returncode != 0:
        log.debug("Get-PnpDevice non-zero: %s", out.stderr.strip())
        return []
    text = (out.stdout or "").strip()
    if not text:
        return []

    import json

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        log.debug("non-json from Get-PnpDevice: %s", text)
        return []
    if isinstance(parsed, dict):
        parsed = [parsed]

    out_list: list[DriverStatus] = []
    for entry in parsed:
        out_list.append(
            DriverStatus(
                vid=vid,
                pid=pid,
                present=True,
                driver=entry.get("Service"),
                instance_id=entry.get("InstanceId"),
            )
        )
    return out_list


def check_driver_status() -> list[DriverStatus]:
    results: list[DriverStatus] = []
    for entry in all_known_ids():
        if _is_windows():
            results.extend(_powershell_query(entry.vid, entry.pid))
        else:
            results.append(
                DriverStatus(vid=entry.vid, pid=entry.pid, present=False, driver=None, instance_id=None)
            )
    return results


def _download_zadig(target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    log.info("Downloading Zadig to %s", target)
    with urlopen(ZADIG_DOWNLOAD_URL, timeout=60) as resp, open(target, "wb") as fh:
        shutil.copyfileobj(resp, fh)
    return target


def install_winusb_driver(*, launch: bool = True) -> Path:
    if not _is_windows():
        raise DriverError(
            "Driver installation is Windows-only. On Linux/macOS, libusb is used directly; "
            "no Zadig step is needed."
        )

    cache = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "kaeru-mtk" / "tools"
    zadig = cache / "zadig.exe"
    if not zadig.exists():
        _download_zadig(zadig)

    if launch:
        log.info("Launching Zadig. Steps:")
        for line in _ZADIG_INSTRUCTIONS.strip().splitlines():
            log.info("  %s", line)
        subprocess.Popen([str(zadig)], close_fds=True)
    return zadig


_ZADIG_INSTRUCTIONS = """
1. With the phone OFF, hold Volume DOWN (or both volume keys) and plug USB-C cable.
2. Phone enters MediaTek BROM (USB ID 0E8D:0003) for ~5 seconds before timeout.
3. In Zadig: Options -> List All Devices.
4. Select 'MediaTek USB Port' (or 'MediaTek BROM').
5. Pick 'WinUSB (vX.Y.Z)' as the replacement driver.
6. Click 'Install Driver' or 'Replace Driver'.
7. Re-run `kaeru-mtk detect` to confirm.
"""


def print_driver_help() -> str:
    lines = ["MediaTek BROM/Preloader Windows driver setup", "=" * 50, _ZADIG_INSTRUCTIONS.strip()]
    if _is_windows():
        statuses = check_driver_status()
        if statuses:
            lines.append("")
            lines.append("Currently visible MTK USB endpoints:")
            for s in statuses:
                lines.append(
                    f"  {s.vid:04x}:{s.pid:04x}  service={s.driver!r}  instance={s.instance_id}"
                )
        else:
            lines.append("")
            lines.append("(No MTK USB endpoints currently enumerated.)")
    text = "\n".join(lines)
    print(text, file=sys.stderr)
    return text
