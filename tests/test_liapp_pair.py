"""실측 ipa 쌍 회귀 테스트.

2026-11-09 Fork_Stars 1.5.0.1(261102) QA_QARelease, 같은 빌드의 미적용/LIAPP 적용본.
ipa 는 저장소에 넣지 않는다. LOUPE_TEST_IPA_DIR(기본 ~/Downloads/분석 mcp 개발)에
같은 sha 의 파일이 있을 때만 돈다.
"""

import os
from pathlib import Path

import pytest

from loupe import analysis, store

IPA_DIR = Path(os.environ.get("LOUPE_TEST_IPA_DIR", "~/Downloads/분석 mcp 개발")).expanduser()
PLAIN = IPA_DIR / "Stars_1.5.0.1.261102_QA.ipa"
LIAPP = IPA_DIR / "Stars_1.5.0.1.261102_QA_LIAPP_resigned.ipa"
PLAIN_ID, LIAPP_ID = "85790996ee7f", "35c15f5085b2"

pytestmark = pytest.mark.skipif(not (PLAIN.exists() and LIAPP.exists()), reason="실측 ipa 쌍이 없다")


@pytest.fixture(scope="module")
def pair():
    a, b = store.open_ipa(str(PLAIN)), store.open_ipa(str(LIAPP))
    assert (a.id, b.id) == (PLAIN_ID, LIAPP_ID), "ipa 파일이 실측 때와 다르다"
    return a, b


def test_verdicts(pair):
    a, b = pair
    ra, rb = analysis.protection_check(a), analysis.protection_check(b)
    assert ra["verdict"] == "not_applied"
    assert rb["verdict"] == "applied"
    # 미적용본에서 난독화 패턴 오탐이 없어야 한다
    assert all(v["obfuscated"] == 0 for v in ra["obfuscation"].values())
    # 적용본 하나만 보고도 쌍 비교의 정답(실제로 바뀐 이름 수)과 같아야 한다
    assert {k: v["obfuscated"] for k, v in rb["obfuscation"].items()} == {
        "__objc_classname": 1475,
        "__objc_methname": 8090,
        "__swift5_reflstr": 2241,
    }
    # SDK 흔적은 양쪽 모두에 있다 — 적용 근거로 쓰면 안 된다
    assert ra["sdk_markers_found"] and rb["sdk_markers_found"]


def test_diff(pair):
    a, b = pair
    d = analysis.diff(a, b)
    assert d["warnings"] == []
    assert {f["path"] for f in d["files"]["only_b"]} == {"LIAPP.ini", "LIAPPEgg.DCR", "LIAPPEgg.RST", "LIAPPEgg.re"}
    assert d["files"]["changed_count"] == 8 and d["files"]["changed"][0]["path"] == "Fork_Stars"
    main = d["binaries"]["Fork_Stars"]
    assert isinstance(main["sections"], dict), "섹션 배치가 같아 바이트 비교가 돼야 한다"
    assert "__TEXT,__text" not in main["sections"], "코드는 바뀌지 않는다"
    assert {k: v["renamed"] for k, v in main["names"].items()} == {
        "__objc_classname": 1475,
        "__objc_methname": 8090,
        "__swift5_reflstr": 2241,
    }
    assert "note" in d["binaries"]["Frameworks/RxSwift.framework/RxSwift"]
    ents = d["entitlements"]["."]
    assert ents["com.apple.developer.associated-domains"]["b"] == "*"
    assert "keychain-access-groups" in ents


def test_literals_not_hidden(pair):
    a, b = pair
    r = analysis.find_strings([a, b], query="https://", scope="main")
    per = r["results"][0]["per_ipa"]
    assert per[a.id]["total"] == per[b.id]["total"] == 52


def test_short_string_warning(pair):
    a, _ = pair
    r = analysis.find_strings([a], query="short", scope="main")
    assert any("15바이트" in w for w in r["warnings"])


def test_list_names_paired(pair):
    a, b = pair
    r = analysis.list_names(a, b, filter=r"^AESCrypt$")
    assert r["counts"] == {"matched": 1, "renamed": 0, "kept": 1}
    r = analysis.list_names(a, b, filter="IAPPopupManager", status="renamed")
    assert r["counts"]["renamed"] >= 1


# ── 2026-11-09 정밀 검증에서 찾은 문제의 회귀 테스트 ──


def test_korean_found_in_compiled_strings_utf16be(pair):
    """컴파일된 .strings(바이너리 plist)는 한글을 UTF-16BE 로 저장한다. 예전엔 0건이었다."""
    a, _ = pair
    r = analysis.find_strings([a], query="로그인", scope="all", max_hits=1)
    by_enc = {row["needle"]: row["per_ipa"][a.id] for row in r["results"]}
    be = by_enc["로그인 (UTF-16BE)"]
    assert be["total"] >= 1
    assert any(f["path"].endswith("ko.lproj/Localizable.strings") for f in be["files"])
    assert "로그인" in be["files"][0]["hits"][0]["match"]


def test_hit_in_code_signature_is_labeled(pair):
    a, _ = pair
    r = analysis.find_strings([a], regex=r"applinks:[a-z.-]+", scope="main", max_hits=5)
    hits = r["results"][0]["per_ipa"][a.id]["files"][0]["hits"]
    assert hits and all(h["section"].startswith("코드 서명") for h in hits)


def test_negative_counts_rejected(pair):
    a, b = pair
    with pytest.raises(store.LoupeError, match="limit"):
        analysis.list_names(a, limit=-1)
    with pytest.raises(store.LoupeError, match="max_hits"):
        analysis.find_strings([a], query="https://", max_hits=-1)
    with pytest.raises(store.LoupeError, match="samples"):
        analysis.diff(a, b, samples=-1)


def test_match_everything_regex_is_capped(pair):
    a, _ = pair
    r = analysis.find_strings([a], regex=".", scope="main", max_hits=1)
    entry = r["results"][0]["per_ipa"][a.id]
    assert entry["total"] == analysis.MAX_COUNT
    assert "count_capped" in entry


def test_uppercase_id_accepted(pair):
    a, _ = pair
    assert store.get(a.id.upper()).id == a.id


def test_linked_libraries_summary(pair):
    a, _ = pair
    libs = analysis.info(a)["main_binary"]["linked_libraries"]
    assert "@rpath/RxSwift.framework/RxSwift" in libs["embedded"] and len(libs["embedded"]) == 5
    assert "UIKit" in libs["system"]


def test_symbol_summary(pair):
    a, _ = pair
    s = analysis.info(a)["main_binary"]["symbols"]
    assert s == {"total": 3984, "imported": 3931, "exported": 52, "local": 1}
    assert s["local"] <= 5  # 릴리스(QA_QARelease) 빌드는 심볼이 제거돼 있다


def test_short_swift_string_found_inline(pair):
    """'Bearer' 는 문자열 섹션에 없고 명령어 즉값으로만 있다(2026-11-10, Ghidra 디컴파일로 확인)."""
    a, b = pair
    r = analysis.find_strings([a, b], query="Bearer", scope="main")
    plain, inline = r["results"]
    assert plain["per_ipa"][PLAIN_ID]["total"] == 0
    for i in (PLAIN_ID, LIAPP_ID):
        hit = inline["per_ipa"][i]["files"][0]["hits"][0]
        assert hit["address"] == "0x1006f9950" and hit["how"] == "instructions"


def test_secret_scan_and_pair_report(pair):
    a, b = pair
    s = analysis.secrets(b)
    rules = {f["rule"]: f["distinct"] for f in s["findings"]}
    # JWT = TranslateManager.h:13 하드코딩 값. plist_secret 1건은 GoogleService-Info.plist 의 API_KEY(구글 키와 같은 값)
    assert rules == {"jwt": 1, "google_api_key": 2, "plist_secret": 1}
    r = analysis.pair_report(a, b)
    assert (r["a"]["verdict"], r["b"]["verdict"]) == ("not_applied", "applied")
    assert any("__text" in c and "바뀌지 않았다" in c for c in r["conclusions"])
    assert r["code_binary"]["names"]["__objc_classname"]["renamed"] == 1475
    assert "__TEXT,__text" not in r["code_binary"]["sections"]
    still = r["secrets"]["still_visible_in_b"]
    assert len(still) == 3  # 같은 값은 지문으로 합친다
    merged = [x for x in still if x.get("also")]
    assert merged and all(x["public"] and x["rule"] == "google_api_key" for x in merged)
    assert "eyJh…" in r["markdown"]
    jwt = next(v for f in analysis.secrets(b, reveal=True)["findings"] if f["rule"] == "jwt" for v in f["values"])
    assert jwt["value"] not in r["markdown"] and jwt["value"] not in str(r)


def test_source_secrets_finds_known_hardcoded_values(pair):
    """2026-11-10 수동 비교에서 찾은 하드코딩 3건이 모두 ipa 에 있는 것으로 나온다(8자 값은 Swift 인라인)."""
    root = Path("/Users/Shared/Source/Company/Lysn_Epic/dontalk")
    if not root.is_dir():
        pytest.skip("Lysn 소스가 없다")
    a, _ = pair
    r = analysis.source_secrets(a, str(root))
    names = {s["name"] for e in r["found"] for s in e["sources"]}
    assert {"AES256DecryptWithKey", "TRANSLATE_FLITO_API_KEY", "certPassword"} <= names
    inline = [e for e in r["found"] if any(w["how"] == "swift_inline" for w in e["in_ipa"])]
    assert inline and inline[0]["length"] == 8
