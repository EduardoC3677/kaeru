from __future__ import annotations

from kaeru_mtk.data.soc_db import (
    all_socs,
    get_primary_soc_by_hwcode,
    get_soc_by_name,
    get_socs_by_hwcode,
)


def test_at_least_20_socs_in_db():
    assert len(all_socs()) >= 20


def test_lookup_by_name_case_insensitive():
    a = get_soc_by_name("MT6877")
    b = get_soc_by_name("mt6877")
    assert a is not None
    assert a is b
    assert get_soc_by_name("MT9999") is None


def test_lookup_by_hwcode():
    primary = get_primary_soc_by_hwcode(0x1186)
    assert primary is not None
    assert primary.name == "MT6877"

    unknown = get_primary_soc_by_hwcode(0xCAFE)
    assert unknown is None


def test_aarch64_socs_have_da_v6():
    for s in all_socs():
        if s.arch == "aarch64":
            assert s.da_version == 6, f"{s.name} aarch64 must use DA v6"


def test_all_socs_have_at_least_one_exploit():
    for s in all_socs():
        assert len(s.exploits) >= 1, f"{s.name} has no exploit recipe"


def test_dimensity_9300_is_aarch64_with_iguana():
    s = get_soc_by_name("MT6897")
    assert s is not None
    assert s.arch == "aarch64"
    assert "iguana" in s.exploits
    assert s.sla_required is True


def test_hwcode_collision_returns_all_matches():
    matches = get_socs_by_hwcode(0x0707)
    names = {m.name for m in matches}
    assert "MT6763" in names
