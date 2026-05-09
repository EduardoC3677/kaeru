from __future__ import annotations

from kaeru_mtk.data import AUTH_DIR
from kaeru_mtk.data.sla_keys import ALL_SLA_KEYS
from kaeru_mtk.formats.auth_sv5 import parse_auth_sv5
from kaeru_mtk.oneplus.auth import (
    SocAuthMap,
    default_auth_resolver,
    resolve_auth_for_hwcode,
)


def test_bundled_auth_dir_exists_and_has_15_files():
    assert AUTH_DIR.is_dir()
    files = sorted(AUTH_DIR.glob("*.auth"))
    assert len(files) == 15


def test_every_bundled_auth_parses_and_starts_with_gfh_magic():
    for f in AUTH_DIR.glob("*.auth"):
        a = parse_auth_sv5(f)
        assert a.raw[:4] == b"MMM\x01"
        assert len(a.rsa_modulus) == 256
        assert len(a.signature) == 256


def test_bundled_socauthmap_lists_all_15():
    m = SocAuthMap.bundled()
    expected = {
        "MT6763", "MT6765", "MT6765_18540", "MT6765_20271",
        "MT6769", "MT6771", "MT6771_18531", "MT6779",
        "MT6833", "MT6853", "MT6873", "MT6877",
        "MT6885", "MT6889", "MT6893",
    }
    assert set(m.platforms()) == expected


def test_resolve_auth_for_hwcode_picks_correct_soc():
    m = SocAuthMap.bundled()
    bundle = resolve_auth_for_hwcode(0x1186, m)
    assert bundle.platform == "MT6877"
    assert bundle.sla_key is not None
    assert bundle.sla_key.index == 1


def test_default_resolver_falls_back_to_bundled():
    m = default_auth_resolver(None)
    assert len(list(m.platforms())) == 15


def test_seven_auth_files_share_sla_key_1():
    expected = {"MT6763", "MT6833", "MT6853", "MT6873", "MT6877", "MT6885", "MT6889"}
    matched = set()
    for f in AUTH_DIR.glob("*.auth"):
        a = parse_auth_sv5(f)
        if any(a.rsa_modulus == k.modulus for k in ALL_SLA_KEYS if k.index == 1):
            matched.add(f.stem)
    assert matched == expected
