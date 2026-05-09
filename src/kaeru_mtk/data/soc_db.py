from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SocSpec:
    name: str
    hw_code: int
    arch: str
    da_version: int
    payload_addr: int = 0
    var_addr: int = 0
    watchdog_addr: int = 0x10007000
    blacklist_addr: int = 0
    sla_required: bool = False
    daa_required: bool = False
    aliases: tuple[str, ...] = ()
    notes: str = ""
    exploits: tuple[str, ...] = field(default_factory=tuple)


_SOC_TABLE: tuple[SocSpec, ...] = (
    SocSpec(
        name="MT6763", hw_code=0x0707, arch="armv7", da_version=5,
        payload_addr=0x100A00, var_addr=0x102868,
        notes="Helio P23 / P30",
        exploits=("kamakiri",),
    ),
    SocSpec(
        name="MT6765", hw_code=0x0766, arch="armv7", da_version=5,
        payload_addr=0x100A00, var_addr=0x100E70,
        notes="Helio P35 / G35",
        exploits=("kamakiri",),
    ),
    SocSpec(
        name="MT6768", hw_code=0x0707, arch="armv7", da_version=5,
        notes="Helio G80 / G85",
        exploits=("kamakiri",),
    ),
    SocSpec(
        name="MT6769", hw_code=0x0707, arch="armv7", da_version=5,
        notes="Helio G70 / G85",
        exploits=("kamakiri",),
    ),
    SocSpec(
        name="MT6771", hw_code=0x0788, arch="armv7", da_version=5,
        payload_addr=0x100A00, var_addr=0x100A1C,
        notes="Helio P60 / P70",
        exploits=("kamakiri",),
    ),
    SocSpec(
        name="MT6779", hw_code=0x0816, arch="armv7", da_version=5,
        payload_addr=0x100A00, var_addr=0x100A1C,
        notes="Helio P90 / P95",
        exploits=("kamakiri", "hashimoto"),
    ),
    SocSpec(
        name="MT6781", hw_code=0x0816, arch="armv7", da_version=5,
        notes="Helio G96",
        exploits=("kamakiri",),
    ),
    SocSpec(
        name="MT6785", hw_code=0x0816, arch="armv7", da_version=5,
        notes="Helio G90 / G95",
        exploits=("kamakiri",),
    ),
    SocSpec(
        name="MT6833", hw_code=0x0989, arch="aarch64", da_version=6,
        payload_addr=0x200B00, var_addr=0x200CB0,
        sla_required=True,
        notes="Dimensity 700 / 720 / 800U",
        exploits=("kamakiri2", "carbonara"),
    ),
    SocSpec(
        name="MT6853", hw_code=0x0996, arch="aarch64", da_version=6,
        payload_addr=0x200B00, var_addr=0x200CB0,
        sla_required=True,
        notes="Dimensity 720 / 800",
        exploits=("kamakiri2", "carbonara"),
    ),
    SocSpec(
        name="MT6873", hw_code=0x1066, arch="aarch64", da_version=6,
        payload_addr=0x200B00, var_addr=0x200CB0,
        sla_required=True,
        notes="Dimensity 800 / 820",
        exploits=("kamakiri2",),
    ),
    SocSpec(
        name="MT6877", hw_code=0x1186, arch="aarch64", da_version=6,
        payload_addr=0x200B00, var_addr=0x200CB0,
        sla_required=True,
        notes="Dimensity 900 / 920 / 1080",
        exploits=("kamakiri2", "iguana"),
    ),
    SocSpec(
        name="MT6885", hw_code=0x1067, arch="aarch64", da_version=6,
        payload_addr=0x200B00, var_addr=0x200CB0,
        sla_required=True,
        notes="Dimensity 1000 / 1000+",
        exploits=("kamakiri2",),
    ),
    SocSpec(
        name="MT6889", hw_code=0x1068, arch="aarch64", da_version=6,
        payload_addr=0x200B00, var_addr=0x200CB0,
        sla_required=True,
        notes="Dimensity 1000+ / 1000C",
        exploits=("kamakiri2",),
    ),
    SocSpec(
        name="MT6893", hw_code=0x1166, arch="aarch64", da_version=6,
        payload_addr=0x200B00, var_addr=0x200CB0,
        sla_required=True,
        notes="Dimensity 1200 / 1300",
        exploits=("kamakiri2", "iguana"),
    ),
    SocSpec(
        name="MT6895", hw_code=0x1366, arch="aarch64", da_version=6,
        payload_addr=0x200B00, var_addr=0x200CB0,
        sla_required=True, daa_required=True,
        notes="Dimensity 8100",
        exploits=("iguana",),
    ),
    SocSpec(
        name="MT6896", hw_code=0x1316, arch="aarch64", da_version=6,
        payload_addr=0x200B00, var_addr=0x200CB0,
        sla_required=True, daa_required=True,
        notes="Dimensity 8200",
        exploits=("iguana",),
    ),
    SocSpec(
        name="MT6897", hw_code=0x1607, arch="aarch64", da_version=6,
        payload_addr=0x200B00, var_addr=0x200CB0,
        sla_required=True, daa_required=True,
        notes="Dimensity 9300",
        exploits=("iguana",),
    ),
    SocSpec(
        name="MT6983", hw_code=0x1166, arch="aarch64", da_version=6,
        sla_required=True, daa_required=True,
        notes="Dimensity 9000 (shares hwcode 0x1166 with MT6893)",
        exploits=("iguana",),
    ),
    SocSpec(
        name="MT6985", hw_code=0x1576, arch="aarch64", da_version=6,
        sla_required=True, daa_required=True,
        notes="Dimensity 9200",
        exploits=("iguana",),
    ),
    SocSpec(
        name="MT6886", hw_code=0x1118, arch="aarch64", da_version=6,
        sla_required=True, daa_required=True,
        notes="Dimensity 7050 / 7200",
        exploits=("iguana",),
    ),
    SocSpec(
        name="MT6989", hw_code=0x8127, arch="aarch64", da_version=6,
        sla_required=True, daa_required=True,
        notes="Dimensity 9300+",
        exploits=("iguana",),
    ),
)


_BY_NAME: dict[str, SocSpec] = {s.name.upper(): s for s in _SOC_TABLE}
_BY_HWCODE: dict[int, list[SocSpec]] = {}
for _s in _SOC_TABLE:
    _BY_HWCODE.setdefault(_s.hw_code, []).append(_s)


def get_soc_by_name(name: str) -> SocSpec | None:
    return _BY_NAME.get(name.upper())


def get_socs_by_hwcode(hw_code: int) -> list[SocSpec]:
    return list(_BY_HWCODE.get(hw_code, ()))


def get_primary_soc_by_hwcode(hw_code: int) -> SocSpec | None:
    matches = _BY_HWCODE.get(hw_code, ())
    return matches[0] if matches else None


def all_socs() -> tuple[SocSpec, ...]:
    return _SOC_TABLE


__all__ = [
    "SocSpec",
    "all_socs",
    "get_primary_soc_by_hwcode",
    "get_soc_by_name",
    "get_socs_by_hwcode",
]
