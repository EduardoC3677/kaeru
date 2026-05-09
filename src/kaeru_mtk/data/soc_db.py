"""SoC database for kaeru-mtk.

Hardware codes are the 16-bit ``hw_code`` value returned by the MediaTek BROM
``GET_HW_CODE`` (0xFD) command. **Every value in this table is cross-checked
against the public ``mtkclient`` reference** (`bkerler/mtkclient`,
``mtkclient/config/brom_config.py``), which is the de-facto open-source
authority on MediaTek BROM internals.

The database is intentionally restricted to the SoCs for which kaeru-mtk
ships a bundled ``auth_sv5.auth`` file under
``src/kaeru_mtk/data/auth/``, plus a small set of newer Dimensity SoCs for
which OnePlus / OPPO devices are shipped (so users can see whether their
device is recognised even when no auth file is bundled yet).

NO speculative addresses are stored here — anything beyond the verified
hwcode + family + architecture is delegated to mtkclient at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SocSpec:
    """Minimal, verified description of a MediaTek SoC.

    ``hw_code``     : 16-bit BROM ``GET_HW_CODE`` return value.
    ``arch``        : "armv7" or "aarch64". Determines which BROM exploit
                      family applies (kamakiri vs. kamakiri2).
    ``family``      : Marketing name (Helio / Dimensity).
    ``aliases``     : Other names that share this hwcode in mtkclient
                      (e.g. MT6885 / MT6883 / MT6889 / MT6880 / MT6890 all
                      enumerate as 0x816).
    ``auth_stem``   : Stem of the bundled auth file (without ``.auth``), or
                      ``None`` if no auth is bundled for this SoC.
    """

    name: str
    hw_code: int
    arch: str
    family: str
    aliases: tuple[str, ...] = ()
    auth_stem: str | None = None


# Verified hwcodes — each one is present in mtkclient's brom_config.py with
# the same value at ``mtkclient/config/brom_config.py``.
_SOCS: tuple[SocSpec, ...] = (
    SocSpec("MT6763", 0x690,  "armv7",   "Helio P23/P30",       auth_stem="MT6763"),
    SocSpec("MT6765", 0x766,  "armv7",   "Helio P35/G35",       aliases=("MT8768t",), auth_stem="MT6765"),
    SocSpec("MT6768", 0x707,  "armv7",   "Helio G80/G85",       aliases=("MT6769",)),
    SocSpec("MT6769", 0x707,  "armv7",   "Helio G70/G80",       aliases=("MT6768",), auth_stem="MT6769"),
    SocSpec("MT6771", 0x788,  "armv7",   "Helio P60/P70",       aliases=("MT8385", "MT8183", "MT8666"), auth_stem="MT6771"),
    SocSpec("MT6779", 0x725,  "armv7",   "Helio P90/P95",       auth_stem="MT6779"),
    SocSpec("MT6781", 0x1066, "armv7",   "Helio G96"),
    SocSpec("MT6785", 0x813,  "armv7",   "Helio G90/G95"),
    SocSpec("MT6833", 0x989,  "aarch64", "Dimensity 700/720/800U", auth_stem="MT6833"),
    SocSpec("MT6853", 0x996,  "aarch64", "Dimensity 720/800",   auth_stem="MT6853"),
    SocSpec("MT6873", 0x886,  "aarch64", "Dimensity 800/820",   auth_stem="MT6873"),
    SocSpec("MT6877", 0x959,  "aarch64", "Dimensity 900/1080/7050", aliases=("MT6877V", "MT8791N"), auth_stem="MT6877"),
    SocSpec("MT6885", 0x816,  "aarch64", "Dimensity 1000L/1000",  aliases=("MT6883", "MT6889", "MT6880", "MT6890"), auth_stem="MT6885"),
    SocSpec("MT6889", 0x816,  "aarch64", "Dimensity 1000+",     aliases=("MT6885", "MT6883", "MT6880", "MT6890"), auth_stem="MT6889"),
    SocSpec("MT6893", 0x950,  "aarch64", "Dimensity 1200",      aliases=("MT6891",), auth_stem="MT6893"),
    SocSpec("MT6983", 0x907,  "aarch64", "Dimensity 9000"),
    SocSpec("MT6895", 0x1172, "aarch64", "Dimensity 8100"),
    SocSpec("MT6985", 0x1296, "aarch64", "Dimensity 9200"),
    SocSpec("MT6897", 0x1203, "aarch64", "Dimensity 9300"),
    SocSpec("MT6989", 0x1236, "aarch64", "Dimensity 9300+",     aliases=("MT6989W",)),
)


def all_socs() -> tuple[SocSpec, ...]:
    """Return every SoC entry, in declaration order."""
    return _SOCS


def find_by_hwcode(hw_code: int) -> list[SocSpec]:
    """Return *every* SoC matching ``hw_code``.

    Several SoCs (e.g. the MT6885 family) share a single hwcode at the BROM
    layer. Callers that need to disambiguate should use additional fields
    (``hw_subcode``, ``hw_version``, ``sw_version``) returned by
    ``GET_HW_SW_VER``; here we only know the family.
    """
    return [s for s in _SOCS if s.hw_code == hw_code]


def find_by_name(name: str) -> SocSpec | None:
    """Look up a SoC by its primary name (case-insensitive).

    Primary names always win over alias matches, so e.g. ``MT6769`` resolves
    to the ``MT6769`` entry even though ``MT6768`` lists ``MT6769`` as an
    alias.
    """
    name_u = name.upper()
    for s in _SOCS:
        if s.name.upper() == name_u:
            return s
    for s in _SOCS:
        if any(a.upper() == name_u for a in s.aliases):
            return s
    return None


def auth_socs() -> list[SocSpec]:
    """All SoCs for which an auth_sv5.auth file is bundled."""
    return [s for s in _SOCS if s.auth_stem is not None]


__all__ = [
    "SocSpec",
    "all_socs",
    "auth_socs",
    "find_by_hwcode",
    "find_by_name",
]
