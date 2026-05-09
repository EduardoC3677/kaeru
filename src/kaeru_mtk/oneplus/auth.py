from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from kaeru_mtk.data import AUTH_DIR
from kaeru_mtk.data.sla_keys import SlaKey, find_sla_key_by_modulus
from kaeru_mtk.data.soc_db import SocSpec, get_primary_soc_by_hwcode, get_soc_by_name
from kaeru_mtk.formats.auth_sv5 import AuthSv5File, parse_auth_sv5
from kaeru_mtk.utils.errors import AuthError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class AuthBundle:
    platform: str
    auth_sv5_path: Path
    auth: AuthSv5File
    soc: SocSpec | None = None
    sla_key: SlaKey | None = None


@dataclass
class SocAuthMap:
    base_dir: Path
    mapping: dict[str, Path] = field(default_factory=dict)

    @classmethod
    def from_directory(cls, base_dir: Path) -> SocAuthMap:
        mapping: dict[str, Path] = {}
        if not base_dir.is_dir():
            return cls(base_dir=base_dir, mapping=mapping)
        for entry in sorted(base_dir.iterdir()):
            if entry.is_dir():
                cand = entry / "auth_sv5.auth"
                if cand.is_file():
                    mapping[entry.name.upper()] = cand
            elif entry.is_file() and entry.suffix.lower() == ".auth":
                mapping[entry.stem.upper()] = entry
        return cls(base_dir=base_dir, mapping=mapping)

    @classmethod
    def bundled(cls) -> SocAuthMap:
        return cls.from_directory(AUTH_DIR)

    def platforms(self) -> Iterable[str]:
        return sorted(self.mapping)

    def for_platform(self, platform: str) -> Path | None:
        return self.mapping.get(platform.upper())


def default_auth_resolver(base_dir: Path | None = None) -> SocAuthMap:
    if base_dir is None:
        return SocAuthMap.bundled()
    user_map = SocAuthMap.from_directory(base_dir)
    if not user_map.mapping:
        log.warning("no auth files in %s, falling back to bundled", base_dir)
        return SocAuthMap.bundled()
    bundled = SocAuthMap.bundled()
    merged: dict[str, Path] = dict(bundled.mapping)
    merged.update(user_map.mapping)
    return SocAuthMap(base_dir=base_dir, mapping=merged)


def _build_bundle(platform: str, path: Path, soc: SocSpec | None) -> AuthBundle:
    auth = parse_auth_sv5(path)
    sla_key = find_sla_key_by_modulus(auth.rsa_modulus)
    if sla_key is None:
        log.debug(
            "auth modulus for %s not in known SLA key set; SLA may use device-specific key",
            platform,
        )
    return AuthBundle(
        platform=platform,
        auth_sv5_path=path,
        auth=auth,
        soc=soc,
        sla_key=sla_key,
    )


def resolve_auth_for_hwcode(hw_code: int, soc_map: SocAuthMap) -> AuthBundle:
    soc = get_primary_soc_by_hwcode(hw_code)
    candidates: list[str]
    if soc:
        candidates = [soc.name]
        candidates.extend(soc.aliases)
    else:
        candidates = []

    for cand in candidates:
        path = soc_map.for_platform(cand)
        if path:
            log.info(
                "selected auth for hwcode 0x%04x -> %s (%s)",
                hw_code, cand, path,
            )
            return _build_bundle(cand, path, soc)

    if not candidates:
        raise AuthError(
            f"unknown MTK hwcode 0x{hw_code:04x} - no SoC mapping. "
            "Provide --auth-file <auth_sv5.auth> manually."
        )

    raise AuthError(
        f"no auth_sv5.auth for {soc.name if soc else hex(hw_code)} under "
        f"{soc_map.base_dir}. Available: {list(soc_map.platforms())}. "
        "Bundled fallback also missing this SoC."
    )


def resolve_auth_for_soc_name(name: str, soc_map: SocAuthMap) -> AuthBundle:
    soc = get_soc_by_name(name)
    path = soc_map.for_platform(name)
    if not path:
        raise AuthError(
            f"no auth_sv5.auth for {name} under {soc_map.base_dir}. "
            f"Available: {list(soc_map.platforms())}."
        )
    return _build_bundle(name.upper(), path, soc)


__all__ = [
    "AuthBundle",
    "SocAuthMap",
    "default_auth_resolver",
    "resolve_auth_for_hwcode",
    "resolve_auth_for_soc_name",
]
