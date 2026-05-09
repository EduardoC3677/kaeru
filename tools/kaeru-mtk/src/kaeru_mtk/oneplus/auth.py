from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from kaeru_mtk.formats.auth_sv5 import AuthSv5File, parse_auth_sv5
from kaeru_mtk.utils.errors import AuthError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)

HWCODE_TO_PLATFORM: dict[int, str] = {
    0x0707: "MT6763",
    0x0788: "MT6765",
    0x0816: "MT6779",
    0x0989: "MT6833",
    0x0996: "MT6853",
    0x1066: "MT6873",
    0x1067: "MT6885",
    0x1068: "MT6889",
    0x1166: "MT6893",
    0x1186: "MT6877",
    0x0321: "MT6771",
    0x0335: "MT6765",
}


@dataclass
class AuthBundle:
    platform: str
    auth_sv5_path: Path
    auth: AuthSv5File


@dataclass
class SocAuthMap:
    base_dir: Path
    mapping: dict[str, Path] = field(default_factory=dict)

    @classmethod
    def from_directory(cls, base_dir: Path) -> SocAuthMap:
        mapping: dict[str, Path] = {}
        if not base_dir.is_dir():
            return cls(base_dir=base_dir, mapping=mapping)
        for sub in sorted(base_dir.iterdir()):
            if not sub.is_dir():
                continue
            cand = sub / "auth_sv5.auth"
            if cand.is_file():
                mapping[sub.name.upper()] = cand
        return cls(base_dir=base_dir, mapping=mapping)

    def platforms(self) -> Iterable[str]:
        return sorted(self.mapping)

    def for_platform(self, platform: str) -> Path | None:
        return self.mapping.get(platform.upper())


def default_auth_resolver(base_dir: Path) -> SocAuthMap:
    return SocAuthMap.from_directory(base_dir)


def resolve_auth_for_hwcode(hwcode: int, soc_map: SocAuthMap) -> AuthBundle:
    platform = HWCODE_TO_PLATFORM.get(hwcode)
    if not platform:
        raise AuthError(
            f"unknown MTK hwcode 0x{hwcode:04x} - no platform mapping. "
            "Provide --auth-file <auth_sv5.auth> manually."
        )
    path = soc_map.for_platform(platform)
    if not path:
        raise AuthError(
            f"no auth_sv5.auth for {platform} under {soc_map.base_dir}. "
            f"Available: {list(soc_map.platforms())}"
        )
    auth = parse_auth_sv5(path)
    return AuthBundle(platform=platform, auth_sv5_path=path, auth=auth)
