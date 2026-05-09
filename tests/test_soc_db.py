from __future__ import annotations

from kaeru_mtk.data.soc_db import (
    all_socs,
    auth_socs,
    find_by_hwcode,
    find_by_name,
)


def test_db_contains_every_auth_bundled_soc():
    names = {s.name for s in auth_socs()}
    assert {
        "MT6763", "MT6765", "MT6769", "MT6771", "MT6779",
        "MT6833", "MT6853", "MT6873", "MT6877",
        "MT6885", "MT6889", "MT6893",
    }.issubset(names)


def test_find_by_name_case_insensitive():
    a = find_by_name("MT6877")
    b = find_by_name("mt6877")
    assert a is not None
    assert a is b
    assert find_by_name("MT9999") is None


def test_find_by_name_resolves_aliases():
    via_alias = find_by_name("MT8768t")
    assert via_alias is not None
    assert via_alias.name == "MT6765"


def test_hwcodes_match_mtkclient_for_known_socs():
    expected_hwcodes = {
        "MT6763": 0x690,
        "MT6765": 0x766,
        "MT6769": 0x707,
        "MT6771": 0x788,
        "MT6779": 0x725,
        "MT6833": 0x989,
        "MT6853": 0x996,
        "MT6873": 0x886,
        "MT6877": 0x959,
        "MT6885": 0x816,
        "MT6889": 0x816,
        "MT6893": 0x950,
        "MT6897": 0x1203,
        "MT6989": 0x1236,
    }
    for name, hw in expected_hwcodes.items():
        s = find_by_name(name)
        assert s is not None, f"missing {name}"
        assert s.hw_code == hw, f"{name} hwcode mismatch"


def test_hwcode_collision_returns_all_matches():
    matches = find_by_hwcode(0x816)
    names = {m.name for m in matches}
    assert {"MT6885", "MT6889"}.issubset(names)


def test_aarch64_arch_for_dimensity_socs():
    for name in ("MT6833", "MT6853", "MT6873", "MT6877", "MT6885", "MT6893", "MT6897"):
        s = find_by_name(name)
        assert s is not None
        assert s.arch == "aarch64"


def test_armv7_for_helio_socs():
    for name in ("MT6763", "MT6765", "MT6769", "MT6771", "MT6779"):
        s = find_by_name(name)
        assert s is not None
        assert s.arch == "armv7"


def test_all_socs_listed():
    assert len(all_socs()) >= 20
