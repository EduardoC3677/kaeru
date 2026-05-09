from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from kaeru_mtk.data import AUTH_DIR
from kaeru_mtk.data.sla_keys import SlaKey, find_sla_key_by_modulus
from kaeru_mtk.data.soc_db import SocSpec, find_by_hwcode

_AUTH_GFH_MAGIC = b"MMM\x01"
_RSA_MODULUS_OFFSET = 0x4C4
_RSA_MODULUS_LEN = 256


@dataclass(frozen=True)
class AuthBundle:
    soc: SocSpec
    path: Path
    rsa_modulus: bytes
    sla_key: SlaKey | None

    @property
    def stem(self) -> str:
        return self.path.stem


def _read_auth_modulus(path: Path) -> bytes:
    blob = path.read_bytes()
    if not blob.startswith(_AUTH_GFH_MAGIC):
        raise ValueError(f"{path}: not a valid auth_sv5 (missing MMM\\x01 magic)")
    end = _RSA_MODULUS_OFFSET + _RSA_MODULUS_LEN
    if len(blob) < end:
        raise ValueError(f"{path}: truncated auth_sv5 (need >= {end} bytes, got {len(blob)})")
    return blob[_RSA_MODULUS_OFFSET:end]


def load_bundle(path: Path) -> AuthBundle:
    stem = path.stem
    soc_name = stem.split("_", 1)[0]
    from kaeru_mtk.data.soc_db import find_by_name
    soc = find_by_name(soc_name)
    if soc is None:
        raise ValueError(f"{path.name}: no SocSpec for stem {stem!r}")
    modulus = _read_auth_modulus(path)
    return AuthBundle(
        soc=soc,
        path=path,
        rsa_modulus=modulus,
        sla_key=find_sla_key_by_modulus(modulus),
    )


def all_bundles() -> list[AuthBundle]:
    return sorted(
        (load_bundle(p) for p in AUTH_DIR.glob("*.auth")),
        key=lambda b: b.path.name,
    )


def bundles_for_hwcode(hw_code: int) -> list[AuthBundle]:
    socs = {s.name for s in find_by_hwcode(hw_code)}
    if not socs:
        return []
    return [b for b in all_bundles() if b.soc.name in socs]


def best_bundle_for_hwcode(hw_code: int) -> AuthBundle | None:
    candidates = bundles_for_hwcode(hw_code)
    if not candidates:
        return None
    plain = [b for b in candidates if b.path.stem == b.soc.name]
    if plain:
        return plain[0]
    return candidates[0]


__all__ = [
    "AuthBundle",
    "all_bundles",
    "best_bundle_for_hwcode",
    "bundles_for_hwcode",
    "load_bundle",
]
