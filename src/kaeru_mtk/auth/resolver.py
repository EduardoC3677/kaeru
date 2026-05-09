from __future__ import annotations

import re
from dataclasses import dataclass

from kaeru_mtk.data.auth_index import AuthBundle, best_bundle_for_hwcode
from kaeru_mtk.data.soc_db import SocSpec, find_by_hwcode
from kaeru_mtk.runner.mtkclient import MtkClientRunner
from kaeru_mtk.utils.errors import KaeruError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


class HwcodeDetectionError(KaeruError):
    pass


@dataclass(frozen=True)
class AuthResolution:
    hw_code: int
    soc_candidates: tuple[SocSpec, ...]
    bundle: AuthBundle | None

    @property
    def has_bundle(self) -> bool:
        return self.bundle is not None

    @property
    def primary_soc(self) -> SocSpec | None:
        if self.bundle is not None:
            return self.bundle.soc
        return self.soc_candidates[0] if self.soc_candidates else None


_HWCODE_PATTERNS = (
    re.compile(r"hw[_\s]*code[^0-9a-fA-Fx]*0x([0-9a-fA-F]+)"),
    re.compile(r"HW[_\s]*code[^0-9a-fA-Fx]*0x([0-9a-fA-F]+)"),
    re.compile(r"Hardware\s+code\D+0x([0-9a-fA-F]+)"),
)


def _parse_hwcode(text: str) -> int | None:
    for pat in _HWCODE_PATTERNS:
        m = pat.search(text)
        if m:
            return int(m.group(1), 16)
    return None


def detect_hwcode_via_mtkclient(runner: MtkClientRunner, *, timeout: float = 30.0) -> int:
    proc = runner.run("gettargetconfig", check=False)
    code = _parse_hwcode(proc.stdout or "")
    if code is None:
        raise HwcodeDetectionError(
            "could not extract hw_code from mtkclient output. Raw output:\n"
            + (proc.stdout or "<empty>")
        )
    log.info("detected hw_code=0x%04x", code)
    return code


def resolve_auth(hw_code: int) -> AuthResolution:
    socs = tuple(find_by_hwcode(hw_code))
    bundle = best_bundle_for_hwcode(hw_code)
    return AuthResolution(hw_code=hw_code, soc_candidates=socs, bundle=bundle)


__all__ = [
    "AuthResolution",
    "HwcodeDetectionError",
    "detect_hwcode_via_mtkclient",
    "resolve_auth",
]
