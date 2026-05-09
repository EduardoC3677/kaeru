from __future__ import annotations

import pytest

from kaeru_mtk.auth.resolver import _parse_hwcode, resolve_auth


def test_resolve_auth_for_known_hwcode():
    res = resolve_auth(0x959)
    assert res.hw_code == 0x959
    assert res.bundle is not None
    assert res.bundle.soc.name == "MT6877"
    assert res.primary_soc is not None
    assert res.primary_soc.name == "MT6877"


def test_resolve_auth_for_collision_hwcode_picks_one_with_plain_stem():
    res = resolve_auth(0x816)
    assert res.bundle is not None
    assert res.bundle.path.stem in {"MT6885", "MT6889"}


def test_resolve_auth_for_unknown_hwcode():
    res = resolve_auth(0xCAFE)
    assert res.bundle is None
    assert res.soc_candidates == ()
    assert res.primary_soc is None


@pytest.mark.parametrize("text,expected", [
    ("HW code: 0x959", 0x959),
    ("hw_code = 0x886\nstatus = ok", 0x886),
    ("Hardware code: 0x1203", 0x1203),
    ("garbage with no hwcode", None),
])
def test_parse_hwcode_from_mtkclient_output(text: str, expected: int | None) -> None:
    assert _parse_hwcode(text) == expected
