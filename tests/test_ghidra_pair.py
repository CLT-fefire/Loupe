"""Ghidra 워커 통합 테스트(실측 ipa 쌍, 분석이 끝난 캐시 필요).

실제 워커(JVM)를 띄우므로 느리다. LOUPE_GHIDRA_TESTS=1 일 때만 돈다.
    LOUPE_GHIDRA_TESTS=1 uv run pytest tests/test_ghidra_pair.py -q
"""

import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from loupe import config, ghidra_client, server

PLAIN, LIAPP = "85790996ee7f", "35c15f5085b2"


def _analyzed(ipa_id: str) -> bool:
    return (config.CACHE_DIR / ipa_id / "ghidra" / "Fork_Stars" / "analyzed.json").exists()


pytestmark = pytest.mark.skipif(
    os.environ.get("LOUPE_GHIDRA_TESTS") != "1" or not (_analyzed(PLAIN) and _analyzed(LIAPP)),
    reason="LOUPE_GHIDRA_TESTS=1 이고 두 ipa 의 메인 바이너리 분석이 끝나 있어야 한다",
)


def test_search_excludes_non_code_pseudo_functions():
    a = server.search_functions(id=PLAIN, pattern=".", limit=0)
    b = server.search_functions(id=LIAPP, pattern=".", limit=0)
    # 실제 코드 함수 수는 거의 같다(2026-11-09: 115,770 대 115,767)
    assert abs(a["matched"] - b["matched"]) <= 10
    # 재서명된 적용본은 import 자리 가상 항목이 훨씬 많다
    assert b["excluded_non_code"] > a["excluded_non_code"] * 10


def test_selector_xrefs_follow_objc_stub_callers():
    r = server.xrefs(id=PLAIN, target="billingErrorOnDismiss:", kind="string", limit=10)
    stubs = [ref for m in r["matches"] for ref in m["references"] if ref.get("callers")]
    assert stubs, "objc_stub 을 거쳐 실제 호출부까지 따라가야 한다"
    callers = {c["function"] for s in stubs for c in s["callers"]}
    assert "StoreManagerForObjC::purchaseProductID:completion:" in callers
    # 같은 위치가 참조 종류만 달리 중복되지 않는다
    froms = [(ref["from"], ref.get("function")) for m in r["matches"] for ref in m["references"]]
    assert len(froms) == len(set(froms))


def test_compare_function_names_only():
    r = server.compare_function(
        a=PLAIN, b=LIAPP, function="_TtC10Fork_Stars15IAPPopupManager::billingErrorOnDismiss:", max_chars=200
    )
    assert r["a"]["entry"] == r["b"]["entry"] == "1007148f0"
    assert r["names_only"] is True and r["identical"] is False
    assert any("zZZZZZZZvaaaaaa" in p["b"] for p in r["renamed"])


def test_hex_like_name_is_not_address():
    with pytest.raises(Exception, match="그 이름의 함수가 없다"):
        server.decompile(id=PLAIN, function="add")


def test_parallel_queries_do_not_fail():
    """대기열이 작으면 병렬 호출이 ECONNREFUSED 로 실패했다(2026-11-09)."""
    ghidra_client.ensure_worker()

    def q(i):
        return server.search_functions(id=[PLAIN, LIAPP][i % 2], pattern="didFinishLaunching", limit=1)["matched"]

    with ThreadPoolExecutor(16) as ex:
        res = list(ex.map(q, range(16)))
    assert all(n >= 1 for n in res)
    st = ghidra_client.call("status")
    assert len(st["open_programs"]) <= st["max_open"]


FN = "_TtC10Fork_Stars15IAPPopupManager::billingErrorOnDismiss:"


def _sig(ipa_id, target):
    return ghidra_client.call("function_signature", key=f"{ipa_id}/Fork_Stars", target=target)


def test_compare_function_reports_how_it_matched():
    r = server.compare_function(a=PLAIN, b=LIAPP, function=FN, max_chars=200)
    assert r["matched_by"] == "address" and not r["notes"]


def test_same_function_has_same_signature_in_both_builds():
    """적용본은 클래스 이름이 바뀌었지만(zZZ…) 코드 서명은 같다."""
    a, b = _sig(PLAIN, "0x1007148f0"), _sig(LIAPP, "0x1007148f0")
    assert a["signature"] == b["signature"]
    assert a["function"]["name"] != b["function"]["name"]


def test_signature_group_of_selector_thunks():
    """분기 대상만 다른 셀렉터 thunk 는 서명이 같은 묶음이 된다(2026-11-10: 4개)."""
    from loupe import matching

    sigs = [_sig(PLAIN, f"0x{e}")["signature"] for e in ("1007148f0", "100714970", "1007149f0", "100714a70")]
    assert len(set(sigs)) == 1
    assert matching.short_name(FN) == "billingErrorOnDismiss:"


def test_worker_rejects_bad_key():
    with pytest.raises(Exception, match="잘못된 key"):
        ghidra_client.call("search_functions", key=f"{PLAIN}/../x", pattern=".")


def test_deep_signature_splits_thunks_and_matches_across_builds():
    """thunk 4개는 서명이 같지만 호출 대상까지 넣은 서명으로는 3종으로 갈리고, 두 빌드에서 같다.
    가운데 둘(networkError·userCancelled)은 부르는 구현까지 쌍둥이라 묶음 순서로만 구분된다."""
    entries = ("1007148f0", "100714970", "1007149f0", "100714a70")
    plain = [_sig(PLAIN, f"0x{e}")["deep"] for e in entries]
    liapp = [_sig(LIAPP, f"0x{e}")["deep"] for e in entries]
    assert len({p.split("|")[0] for p in plain}) == 1
    assert len(set(plain)) == 3 and plain[1] == plain[2]
    assert plain == liapp
