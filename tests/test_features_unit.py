"""Swift 인라인 문자열 찾기, 시크릿 스캔(실제 바이너리 없이)."""

import os
import plistlib
import struct
import zipfile

import pytest

from loupe import analysis, config, secret_scan, store, swift_small
from loupe.macho import MachO, Section

# ── 명령어 인코딩(테스트용) ──────────────────────────────────────────────


def movz(rd, imm, hw=0, sf=1):
    return (sf << 31) | 0x52800000 | (hw << 21) | (imm << 5) | rd


def movk(rd, imm, hw, sf=1):
    return (sf << 31) | 0x72800000 | (hw << 21) | (imm << 5) | rd


def movn(rd, imm, hw=0, sf=1):
    return (sf << 31) | 0x12800000 | (hw << 21) | (imm << 5) | rd


NOP = 0xD503201F
ORR_X0_2020 = 0xB203C3E0  # mov x0, #0x2020202020202020 (swiftc -O 가 "        " 에 낸 실제 인코딩)
MOVZ_X1_E8 = 0xD2FD0001  # mov x1, #0xe800000000000000


def text_of(*insns):
    return b"".join(struct.pack("<I", i) for i in insns)


def fake_macho(text: bytes, data_tail: bytes = b"", addr=0x100004000):
    """__text 하나(와 선택적 데이터 섹션)로 된 가짜 Mach-O. find 는 섹션 정보만 쓴다."""
    blob = text + data_tail
    secs = [Section("__TEXT", "__text", 0, len(text), addr)]
    if data_tail:
        secs.append(Section("__TEXT", "__literal16", len(text), len(data_tail), addr + len(text)))
    return MachO(path=None, data=blob, slice_offset=0, slice_size=len(blob), binary=None, sections=secs)


def emit_words(w0, w1, r0=0, r1=1, gap=0):
    """컴파일러처럼 워드0·워드1 을 MOVZ/MOVK 로 만든다(0 인 16비트 조각은 건너뛴다)."""
    out = []
    for rd, w in ((r0, w0), (r1, w1)):
        parts = [(hw, (w >> (16 * hw)) & 0xFFFF) for hw in range(4) if (w >> (16 * hw)) & 0xFFFF]
        sf = 0 if w < (1 << 32) else 1
        first = True
        for hw, imm in parts:
            out.append(movz(rd, imm, hw, sf) if first else movk(rd, imm, hw, sf))
            first = False
        out += [NOP] * gap if rd == r0 else []
    return out


# ── swift_small ─────────────────────────────────────────────────────────


def test_words_layout():
    assert swift_small.words("abc") == (0x636261, 0xE3 << 56)
    w0, w1 = swift_small.words("secret_key_15ch")
    assert w1 >> 56 == 0xEF and w0 == int.from_bytes(b"secret_k", "little")
    assert swift_small.words("한글다섯자")[1] >> 56 == 0xAF  # 비ASCII 15바이트
    assert swift_small.words("") is None
    assert swift_small.words("x" * 16) is None


def test_decode_bitmask_matches_real_encoding():
    i = ORR_X0_2020
    v = swift_small.decode_bitmask((i >> 22) & 1, (i >> 10) & 0x3F, (i >> 16) & 0x3F, 64)
    assert v == 0x2020202020202020
    assert swift_small.decode_bitmask(0, 0x3F, 0, 32) is None  # 모든 비트 1 은 예약 인코딩


@pytest.mark.parametrize("s", ["abc", "hello", "12345678", "secret_key_15ch", "한글다섯자"])
def test_find_movz_movk_pair(s):
    w0, w1 = swift_small.words(s)
    m = fake_macho(text_of(NOP, *emit_words(w0, w1), NOP))
    hits = swift_small.find(m, s)
    assert len(hits) == 1 and hits[0].how == "instructions"
    assert hits[0].address >= 0x100004000 and hits[0].section == "__TEXT,__text"


def test_find_orr_bitmask():
    m = fake_macho(text_of(ORR_X0_2020, MOVZ_X1_E8))
    assert len(swift_small.find(m, "        ")) == 1


def test_movn_value():
    # movn x0, #0 = 0xffff_ffff_ffff_ffff
    ev = swift_small.mov_events(text_of(movn(0, 0)))
    assert ev == [(0, 0, (1 << 64) - 1)]


def test_needs_both_words_close_together():
    w0, w1 = swift_small.words("hello")
    far = text_of(*emit_words(w0, w1, gap=swift_small.PAIR_WINDOW + 5))
    assert swift_small.find(fake_macho(far), "hello") == []
    other_len = swift_small.words("hellp")[1]  # 길이는 같고 바이트가 다른 문자열의 워드1 은 같다
    assert swift_small.find(fake_macho(text_of(*emit_words(w0, other_len))), "hello")
    # 워드0 만 있고 판별자(길이)가 다르면 다른 문자열이다
    assert swift_small.find(fake_macho(text_of(*emit_words(w0, 0xE6 << 56))), "hello") == []


def test_movk_far_from_movz_is_not_chained():
    insns = [movz(0, 0x6568)] + [NOP] * (swift_small.MOVK_WINDOW + 1) + [movk(0, 0x6c6c, 1), movk(0, 0x6f, 2)]
    insns += [movz(1, 0xE500, 3)]
    assert swift_small.find(fake_macho(text_of(*insns)), "hello") == []


def test_find_16_byte_constant_in_data():
    w0, w1 = swift_small.words("token")
    m = fake_macho(text_of(NOP, NOP), struct.pack("<QQ", w0, w1))
    hits = swift_small.find(m, "token")
    assert [(h.how, h.section) for h in hits] == [("data", "__TEXT,__literal16")]


# ── find_strings 연동 ────────────────────────────────────────────────────


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(config, "ALLOWED_DIRS", [tmp_path.resolve()])
    return tmp_path


def _ipa(sandbox, name, files):
    p = sandbox / name
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("Payload/A.app/Info.plist", plistlib.dumps({"CFBundleExecutable": "A"}))
        zf.writestr("Payload/A.app/A", b"\xcf\xfa\xed\xfe" + b"\0" * 28)
        for k, v in files.items():
            zf.writestr(f"Payload/A.app/{k}", v)
    return store.open_ipa(str(p))


def test_find_strings_adds_inline_row_only_for_short_text(sandbox):
    ipa = _ipa(sandbox, "a.ipa", {"res.txt": b"a long string that is over fifteen bytes"})
    r = analysis.find_strings([ipa], query="hello", scope="all")
    assert [x["needle"] for x in r["results"]] == ["hello", "hello (Swift 인라인)"]
    r = analysis.find_strings([ipa], query="a long string that is", scope="all")
    assert [x["needle"] for x in r["results"]] == ["a long string that is"]


# ── secret_scan ─────────────────────────────────────────────────────────

# 소스에 키 모양 문자열을 그대로 두지 않는다(저장소 시크릿 검사 오탐 방지) — 실행 중에 조립한다
AWS = "AKIA" + "QWERTYUIOPASDFGH"
AWS_DOC = "AKIA" + "IOSFODNN7" + "EXAMPLE"
GOOGLE = "AIza" + "B" * 35
PEM_HEAD = "-----BEGIN RSA " + "PRIVATE KEY-----"


def test_secret_scan_finds_masks_and_allows(sandbox):
    body = "\n".join(["MIIE" + "A" * 60] * 3)
    files = {
        "config.json": f'{{"aws": "{AWS}", "doc": "{AWS_DOC}"}}'.encode(),
        "GoogleService-Info.plist": GOOGLE.encode(),
        "key.pem": f"{PEM_HEAD}\n{body}\n".encode(),
        "openssl_like": f"{PEM_HEAD}\n".encode(),  # 본문 없는 머리말(라이브러리 문자열)은 키가 아니다
    }
    ipa = _ipa(sandbox, "s.ipa", files)
    r = analysis.secrets(ipa)
    by = {f["rule"]: f for f in r["findings"]}
    assert set(by) == {"aws_access_key", "google_api_key", "private_key"}
    assert by["aws_access_key"]["distinct"] == 1  # 문서 예시 값(EXAMPLE)은 버린다
    v = by["aws_access_key"]["values"][0]
    assert v["value"] == f"{AWS[:4]}…{AWS[-2:]} ({len(AWS)}자)" and AWS not in str(r)
    assert v["fingerprint"] == secret_scan.fingerprint(AWS)
    assert by["google_api_key"].get("public_client_key") is True
    assert [f["rule"] for f in r["findings"]][-1] == "google_api_key"  # 공개 클라이언트 키는 뒤로
    assert analysis.secrets(ipa, reveal=True)["findings"][0]["values"][0]["value"] == AWS


def test_secret_scan_binaries_scope_skips_resources(sandbox):
    ipa = _ipa(sandbox, "r.ipa", {"config.json": AWS.encode()})
    assert analysis.secrets(ipa, scope="binaries")["findings"] == []
    with pytest.raises(store.LoupeError):
        analysis.secrets(ipa, scope="main")


def test_protection_check_rejects_non_protection_rules(sandbox):
    ipa = _ipa(sandbox, "p.ipa", {})
    with pytest.raises(store.LoupeError, match="보호 판정 규칙이 아니다"):
        analysis.protection_check(ipa, "secret_patterns")


# ── 리뷰 지적 회귀(2026-11-10) ──────────────────────────────────────────


def _rules():
    return secret_scan.rules(analysis.load_rules("secret_patterns"))


def _found(ipa, rule):
    return next((f for f in analysis.secrets(ipa)["findings"] if f["rule"] == rule), None)


def test_escaped_pem_in_json_is_found(sandbox):
    """서비스 계정 JSON 처럼 개행이 '\\n' 두 글자로 저장된 개인 키."""
    import json

    pem = PEM_HEAD.replace("RSA ", "") + "\n" + "\n".join(["MIIE" + "B" * 60] * 3) + "\n"
    ipa = _ipa(sandbox, "j.ipa", {"sa.json": json.dumps({"type": "service_account", "private_key": pem}).encode()})
    assert _found(ipa, "private_key")["distinct"] == 1


def test_url_credentials_do_not_cross_nul(sandbox):
    joined = b"https://\x00initWithFrame:\x00layoutSubviews\x00support@example.com\x00"
    real = b"ftp://" + b"user" + b":" + b"pa55word" + b"@files.example.com"
    ipa = _ipa(sandbox, "u.ipa", {"strings.bin": joined, "conf.txt": real})
    f = _found(ipa, "url_credentials")
    assert f["distinct"] == 1 and f["values"][0]["locations"][0]["path"] == "conf.txt"


def test_binary_plist_is_scanned_as_xml_and_ui_text_is_not_a_secret(sandbox):
    token = "Zx9" + "q" * 20
    bp = plistlib.dumps({"ApiSecretKey": token, "password_hint": "비밀번호를 입력하세요 please"}, fmt=plistlib.FMT_BINARY)
    ipa = _ipa(sandbox, "b.ipa", {"Config.plist": bp})
    f = _found(ipa, "plist_secret")
    assert f["distinct"] == 1
    loc = f["values"][0]["locations"][0]
    assert loc["offset"] is None and "binary plist" in loc["section"]


def test_media_files_are_skipped(sandbox):
    ipa = _ipa(sandbox, "m.ipa", {"logo.png": AWS.encode()})
    r = analysis.secrets(ipa)
    assert r["findings"] == [] and r["skipped_files"] == {"미디어·폰트": 1}


def test_short_values_show_length_only_and_fingerprint_is_keyed(sandbox):
    import hashlib
    import stat as st

    assert secret_scan.mask("short-secret") == "(12자)"
    fp = secret_scan.fingerprint("short-secret")
    assert fp != hashlib.sha256(b"short-secret").hexdigest()[:12]  # 솔트 없는 해시가 아니다
    assert fp == secret_scan.fingerprint("short-secret")
    key = config.CACHE_DIR / "fingerprint.key"
    assert st.S_IMODE(key.stat().st_mode) == 0o600


def test_secret_map_keeps_first_rule_and_public_flag():
    scan = {
        "findings": [
            {"rule": "google_api_key", "name": "Google API 키", "public_client_key": True, "values": [{"fingerprint": "f1", "value": "v"}]},
            {"rule": "assigned_secret", "name": "대입", "values": [{"fingerprint": "f1", "value": "v"}]},
        ]
    }
    m = analysis._secret_map(scan)
    assert m["f1"]["rule"] == "google_api_key" and m["f1"]["public"] is True and m["f1"]["also"] == ["assigned_secret"]


def test_pair_report_states_code_comparison_even_when_identical(sandbox):
    a = _ipa(sandbox, "a.ipa", {})
    b = _ipa(sandbox, "b.ipa", {"LIAPP.ini": b"x"})
    r = analysis.pair_report(a, b)
    assert any("바이트까지 같다" in c for c in r["conclusions"])
    assert r["code_binary"]["identical"] is True


def test_events_where_and_window_bisect():
    w0, w1 = swift_small.words("hi")
    insns = emit_words(w0, w1) + [NOP] * 40 + emit_words(w0, 0xE5 << 56)  # 두 번째는 워드1 이 다르다
    m = fake_macho(text_of(*insns))
    assert len(swift_small.find(m, "hi")) == 1
    assert len(swift_small._events(m).where(w0)) == 2


# ── 함수 서명(compare_function 짝짓기) ──────────────────────────────────

from loupe import arm64  # noqa: E402


def bl(off):
    return 0x94000000 | (off & 0x03FFFFFF)


def adrp(rd, imm):
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def add_imm(rd, rn, imm12):
    return 0x91000000 | (imm12 << 10) | (rn << 5) | rd


def test_signature_ignores_relocated_offsets():
    a = text_of(adrp(0, 0x123), add_imm(0, 0, 0x45), bl(0x1000), movz(1, 7), 0xD65F03C0)
    b = text_of(adrp(0, 0x999), add_imm(0, 0, 0x10), bl(0x2340), movz(1, 7), 0xD65F03C0)
    assert arm64.signature(a) == arm64.signature(b)


def test_signature_keeps_add_imm_not_paired_with_adrp():
    """스택 크기·필드 오프셋(ADRP 짝이 아닌 ADD 즉값)은 로직이라 지우지 않는다."""
    sp = 31
    a = text_of(add_imm(sp, sp, 0x20), bl(0x10))
    b = text_of(add_imm(sp, sp, 0x30), bl(0x10))
    assert arm64.signature(a) != arm64.signature(b)
    # ADRP 와 다른 레지스터를 밑으로 쓰는 ADD 도 그대로 둔다
    c = text_of(adrp(0, 0x1), add_imm(1, 2, 0x8))
    d = text_of(adrp(0, 0x1), add_imm(1, 2, 0x9))
    assert arm64.signature(c) != arm64.signature(d)


def test_signature_keeps_real_differences():
    a = text_of(bl(0x1000), movz(1, 7))
    assert arm64.signature(a) != arm64.signature(text_of(bl(0x1000), movz(1, 8)))  # 즉값 상수는 로직이다
    assert arm64.signature(a) != arm64.signature(text_of(bl(0x1000), movz(2, 7)))  # 레지스터
    assert arm64.signature(a) != arm64.signature(text_of(bl(0x1000)))  # 길이


# ── 짝짓기 규칙(matching.choose) ────────────────────────────────────────

from loupe import matching  # noqa: E402
from loupe.ghidra_worker import FuncEntry, FuncIndex  # noqa: E402


def side(rows, sigs):
    """rows: (전체 이름, 시작 주소, 크기), sigs: {주소: 서명}"""
    idx = FuncIndex([FuncEntry(n, matching.short_name(n), e, True, sz) for n, e, sz in rows])
    calls = []

    def sig(entry):
        calls.append(entry)
        return sigs.get(entry, "")

    s = matching.Side(idx, sig)
    s.calls = calls
    return s


def test_choose_same_address_and_signature():
    a = side([("A::f", "1000", 8)], {"1000": "s"})
    b = side([("zZZ::f", "1000", 8)], {"1000": "s"})
    r = matching.choose(a, b, "1000", "A::f", 8, True)
    assert r == {"method": "address", "entry": "1000", "notes": []}


def test_choose_name_when_address_moved():
    a = side([("A::f", "1000", 8)], {"1000": "s"})
    b = side([("A::f", "2000", 8), ("A::g", "1000", 8)], {"2000": "s", "1000": "t"})
    r = matching.choose(a, b, "1000", "A::f", 8, True)
    assert (r["method"], r["entry"], r["notes"]) == ("name", "2000", [])


def test_choose_name_requires_uniqueness_in_a_too():
    """a 에 같은 이름이 둘이면 b 의 유일한 같은 이름이 진짜 짝이라는 보장이 없다."""
    a = side([("A::f", "1000", 8), ("A::f", "1100", 8)], {"1000": "s1", "1100": "s2"})
    b = side([("A::f", "2000", 8), ("X::y", "3000", 8)], {"2000": "s1", "3000": "s2"})
    r = matching.choose(a, b, "1100", "A::f", 8, False)
    assert (r["method"], r["entry"]) == ("signature", "3000")


def test_choose_method_name_when_class_obfuscated():
    a = side([("Foo::billingError:", "1000", 8)], {"1000": "s"})
    b = side([("zZZaaa::billingError:", "2000", 8)], {"2000": "s"})
    r = matching.choose(a, b, "1000", "Foo::billingError:", 8, False)
    assert (r["method"], r["entry"]) == ("method_name", "2000")


def test_choose_skips_generated_names():
    """순번·주소로 붙는 이름은 빌드마다 다른 함수를 가리킬 수 있어 이름으로 짝짓지 않는다."""
    a = side([("_OUTLINED_FUNCTION_57", "1000", 8)], {"1000": "s"})
    b = side([("_OUTLINED_FUNCTION_57", "2000", 8), ("_OUTLINED_FUNCTION_58", "2100", 8)], {"2000": "other", "2100": "s"})
    r = matching.choose(a, b, "1000", "_OUTLINED_FUNCTION_57", 8, False)
    assert (r["method"], r["entry"]) == ("signature", "2100")
    assert matching.is_generated("thunk_FUN_100004000") and not matching.is_generated("Foo::bar")


def test_choose_signature_rank_within_group():
    names = ["zZ::a", "zZ::b", "zZ::c"]
    a = side([(f"A::{n[-1]}", e, 8) for n, e in zip(names, ["1000", "1010", "1020"])], {"1000": "s", "1010": "s", "1020": "s"})
    b = side([(n, e, 8) for n, e in zip(names, ["2000", "2010", "2020"])], {"2000": "s", "2010": "s", "2020": "s"})
    r = matching.choose(a, b, "1010", "NoSuch::x", 8, False)
    assert (r["method"], r["entry"]) == ("signature", "2010")
    assert "2번째" in r["notes"][0]


def test_choose_rejects_unique_b_hit_when_a_group_is_larger():
    """b 에서 하나뿐이어도 a 묶음이 둘이면 어느 쪽의 짝인지 모른다(리뷰 지적 2026-11-10)."""
    a = side([("FUN_1000", "1000", 8), ("FUN_1010", "1010", 8)], {"1000": "s", "1010": "s"})
    b = side([("FUN_2000", "2000", 8)], {"2000": "s"})
    r = matching.choose(a, b, "1010", "FUN_1010", 8, False)
    assert r["method"] is None and "a 2개, b 1개" in r["notes"][0]


def test_choose_falls_back_to_same_address_with_note():
    a = side([("FUN_1000", "1000", 8)], {"1000": "s"})
    b = side([("FUN_1000", "1000", 8)], {"1000": "changed"})
    r = matching.choose(a, b, "1000", "FUN_1000", 8, True)
    assert r["method"] == "address" and "코드 서명이 다르다" in r["notes"][-1]


def test_choose_does_not_hash_candidates_when_name_matches():
    """이름으로 정해지면 크기가 같은 후보 전체의 서명을 계산하지 않는다."""
    rows = [("A::f", "1000", 8)] + [(f"A::g{i}", f"{0x3000 + i:x}", 8) for i in range(50)]
    a = side(rows, {"1000": "s"})
    b = side([("A::f", "2000", 8)] + rows[1:], {"2000": "s"})
    matching.choose(a, b, "1000", "A::f", 8, False)
    assert len(a.calls) <= 1 and len(b.calls) <= 1


def test_choose_shifted_layout_does_not_trust_same_address_sibling():
    """서명이 같은 thunk 묶음에서 b 배치가 한 칸 밀리면, 같은 주소에는 형제 함수가 온다(재리뷰 지적 2026-11-10)."""
    ea = ["1000", "1080", "1100", "1180"]
    eb = ["1080", "1100", "1180", "1200"]  # 한 칸 밀림
    a = side([(f"FUN_{e}", e, 8) for e in ea], {e: "s" for e in ea})
    b = side([(f"FUN_{e}", e, 8) for e in eb], {e: "s" for e in eb})
    r = matching.choose(a, b, "1080", "FUN_1080", 8, True)  # a 의 두 번째 함수
    assert (r["method"], r["entry"]) == ("signature", "1100")
    assert any("배치가 밀린" in n for n in r["notes"])


def test_choose_names_win_over_same_address_sibling():
    a = side([("A::x", "1000", 8), ("A::y", "1080", 8)], {"1000": "s", "1080": "s"})
    b = side([("A::x", "1080", 8), ("A::y", "1100", 8)], {"1080": "s", "1100": "s"})
    r = matching.choose(a, b, "1080", "A::y", 8, True)
    assert (r["method"], r["entry"]) == ("name", "1100")


def test_choose_same_address_with_ambiguous_group_is_flagged():
    a = side([("FUN_1000", "1000", 8), ("FUN_1080", "1080", 8)], {"1000": "s", "1080": "s"})
    b = side([("FUN_1000", "1000", 8)], {"1000": "s"})
    r = matching.choose(a, b, "1000", "FUN_1000", 8, True)
    assert r["method"] == "address" and "다른 함수일 수 있다" in r["notes"][-1]


def test_choose_non_code_function_does_not_crash():
    idx_rows = [FuncEntry("FUN_1000", "FUN_1000", "1000", False, 8)]
    a = matching.Side(FuncIndex(idx_rows), lambda e: "s")
    b = side([("FUN_2000", "2000", 8)], {"2000": "s"})
    r = matching.choose(a, b, "1000", "FUN_1000", 8, False)
    assert r["method"] is None and "코드 블록 밖" in r["notes"][0]


# ── 호출 대상까지 넣은 서명(묶음 구분) ───────────────────────────────────


def test_call_targets_bl_and_tail_branch():
    b_insn = lambda off: 0x14000000 | (off & 0x03FFFFFF)  # noqa: E731
    code = text_of(bl(4), b_insn(1), bl(-2 & 0x03FFFFFF), b_insn(100))
    # BL +4 → 0x1010, B +1(함수 안) 제외, BL -2 → 0x1000, B +100 → 0x1000+12+400
    assert arm64.call_targets(code, 0x1000) == [0x1010, 0x1000, 0x1000 + 12 + 400]


def deep_side(rows, sigs, deeps):
    s = side(rows, sigs)
    s.deep = lambda e: deeps.get(e, "")
    return s


def test_choose_deep_signature_when_group_sizes_differ():
    """b 에서 thunk 하나가 빠져 묶음 개수가 달라도, 호출 대상이 다르면 짝을 찾는다."""
    ea = ["1000", "1080", "1100", "1180"]
    eb = ["2000", "2080", "2100"]  # a 의 1000 에 해당하는 것이 빠졌다
    a = deep_side([(f"FUN_{e}", e, 8) for e in ea], {e: "s" for e in ea}, {e: f"s|impl{k}" for k, e in enumerate(ea)})
    b = deep_side([(f"FUN_{e}", e, 8) for e in eb], {e: "s" for e in eb}, {e: f"s|impl{k + 1}" for k, e in enumerate(eb)})
    r = matching.choose(a, b, "1100", "FUN_1100", 8, False)  # impl2
    assert (r["method"], r["entry"]) == ("signature", "2080")
    assert "호출 대상" in r["notes"][0]


def test_choose_deep_signature_confirms_same_address():
    ea = ["1000", "1080"]
    a = deep_side([(f"FUN_{e}", e, 8) for e in ea], {e: "s" for e in ea}, {"1000": "s|x", "1080": "s|y"})
    b = deep_side([(f"FUN_{e}", e, 8) for e in ea], {e: "s" for e in ea}, {"1000": "s|x", "1080": "s|y"})
    r = matching.choose(a, b, "1080", "FUN_1080", 8, True)
    assert r == {"method": "address", "entry": "1080", "notes": []}


def test_choose_deep_tie_falls_back_to_rank():
    ea = ["1000", "1080"]
    a = deep_side([(f"FUN_{e}", e, 8) for e in ea], {e: "s" for e in ea}, {e: "s|same" for e in ea})
    b = deep_side([(f"FUN_{e}", e, 8) for e in ["2000", "2080"]], {"2000": "s", "2080": "s"}, {"2000": "s|same", "2080": "s|same"})
    r = matching.choose(a, b, "1080", "FUN_1080", 8, False)
    assert (r["method"], r["entry"]) == ("signature", "2080") and "순서" in r["notes"][0]


# ── source_secrets ──────────────────────────────────────────────────────

PW = "dQ7" + "#k&(" + "x^Lm" + "Z9pR" + "SG"  # 실제 값이 아닌 비밀번호 모양(실행 중 조립)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("Network error occurred", None),  # 문장
        ("/api/v1/signin", None),  # 경로
        ("0xff0000", None),  # 색상
        ("x-api-key", None),  # 문자로만 된 이름
        ("doNotShow24Hours", None),  # 단어 위주 이름
        ("1A2B3C4D-1111-2222-3333-444455556666", "low"),  # UUID
        (PW, "high"),
        ("abc12345", "medium"),
    ],
)
def test_source_confidence(value, expected):
    assert secret_scan.source_confidence(value) == expected


def test_source_literals_skip_key_name_apis_and_comments(tmp_path):
    (tmp_path / "A.m").write_text(
        "\n".join(
            [
                f'#define MY_API_KEY @"{PW}"',
                f'id x = [dict objectForKey:@"{PW}"];',  # 키 이름을 다루는 API
                f'userInfo:@{{NSLocalizedDescriptionKey: @"{PW}"}}',  # 오류 메시지 키
                f'// let password = "{PW}"',  # 주석
                f'return [data AES256DecryptWithKey:@"{PW}"];',
            ]
        )
    )
    (tmp_path / "B.swift").write_text('let c = load(certPassword: "abc12345")\n')
    (tmp_path / "skip.txt").write_text(f'apiKey = "{PW}"\n')
    got = {(os.path.basename(c["path"]), c["line"], c["name"]) for c in secret_scan.source_literals(tmp_path)}
    assert got == {("A.m", 1, "MY_API_KEY"), ("A.m", 5, "AES256DecryptWithKey"), ("B.swift", 1, "certPassword")}


def test_source_secrets_reports_only_values_in_ipa(sandbox, monkeypatch):
    src = sandbox / "src"
    src.mkdir()
    (src / "A.m").write_text(f'#define MY_API_KEY @"{PW}"\n#define OLD_KEY @"zz{PW}"\n')
    (src / "B.swift").write_text('let c = load(certPassword: "abc12345")\n')
    monkeypatch.setattr(config, "SOURCE_ROOTS", [sandbox.resolve()])
    w0, w1 = swift_small.words("abc12345")
    main = b"\xcf\xfa\xed\xfe" + b"\0" * 28 + b"\0" + PW.encode() + b"\0"
    ipa = _ipa(sandbox, "src.ipa", {})
    (ipa.app / "A").write_bytes(main)  # 메인 바이너리에 PW 만 넣는다
    r = analysis.source_secrets(ipa, str(src), include_absent=True)
    assert [(e["sources"][0]["name"], e["confidence"], e["in_ipa"][0]["how"]) for e in r["found"]] == [("MY_API_KEY", "high", "bytes")]
    assert r["absent_count"] == 2 and PW not in str(r)
    with pytest.raises(store.LoupeError, match="소스 루트 밖"):
        analysis.source_secrets(ipa, "/usr")


# ── 리뷰 지적 회귀(7차, 2026-11-10) ──────────────────────────────────────


@pytest.mark.parametrize(
    "line, name",
    [
        (f'let password = "{PW}"', "password"),
        (f'NSString *secret = @"{PW}";', "secret"),
        (f'static let token: String = "{PW}"', "token"),
        (f'let apiKey: String = "{PW}"', "apiKey"),
        (f'private let clientSecret: String? = "{PW}"', "clientSecret"),
        (f'let salt = "{PW}"', "salt"),
    ],
)
def test_source_literals_common_declarations(tmp_path, line, name):
    (tmp_path / "A.swift").write_text(line + "\n")
    assert [c["name"] for c in secret_scan.source_literals(tmp_path)] == [name]


def test_source_literals_unescape_like_find_strings(tmp_path):
    (tmp_path / "A.swift").write_text('let authToken = "Zx9\\tQw7#Lm\\u{AC00}"\n')
    [c] = secret_scan.source_literals(tmp_path)
    assert c["value"] == "Zx9\tQw7#Lm가"


def test_source_literals_skip_symlinked_files(tmp_path, tmp_path_factory):
    outside = tmp_path_factory.mktemp("out") / "Leak.swift"
    outside.write_text(f'let password = "{PW}"\n')
    (tmp_path / "Leak.swift").symlink_to(outside)
    assert secret_scan.source_literals(tmp_path) == []


def test_presence_finds_value_in_info_plist(sandbox):
    """xcconfig 값은 Info.plist 로 들어간다. XML plist 에서 '&' 는 '&amp;' 로 저장돼 바이트로는 안 맞으므로
    plist 를 읽어 값으로 비교한다. 바이너리 plist 는 바이트 그대로라 바이트 검색에 걸린다."""
    val = "Ab3&" + "Zq9#" + "Lm7!"
    files = {
        "Info2.plist": plistlib.dumps({"APIKey": val}, fmt=plistlib.FMT_XML),
        "Info3.plist": plistlib.dumps({"APIKey": val}, fmt=plistlib.FMT_BINARY),
    }
    ipa = _ipa(sandbox, "pl.ipa", files)
    where = secret_scan.presence(ipa, val)
    assert [(w["path"], w["how"]) for w in where] == [("Info2.plist", "plist"), ("Info3.plist", "bytes")]


def test_choose_deep_when_only_b_has_group():
    """a 에서는 서명이 유일하고 b 에만 같은 서명이 여럿이어도 호출 대상으로 구분한다."""
    a = deep_side([("FUN_1000", "1000", 8)], {"1000": "s"}, {"1000": "s|x"})
    b = deep_side([("FUN_2000", "2000", 8), ("FUN_2080", "2080", 8)], {"2000": "s", "2080": "s"}, {"2000": "s|y", "2080": "s|x"})
    r = matching.choose(a, b, "1000", "FUN_1000", 8, False)
    assert (r["method"], r["entry"]) == ("signature", "2080")


def test_choose_gives_up_when_signature_budget_exceeded(monkeypatch):
    monkeypatch.setattr(matching, "SIGNATURE_BUDGET_S", -1.0)
    a = side([("FUN_1000", "1000", 8)], {"1000": "s"})
    b = side([("FUN_2000", "2000", 8)], {"2000": "s"})
    r = matching.choose(a, b, "1000", "FUN_1000", 8, False)
    assert r["method"] is None and "초를 넘어" in r["notes"][0]


# ── 2차 재리뷰 회귀(7차) ────────────────────────────────────────────────


def test_source_literals_keep_sdk_setters(tmp_path):
    """setApiKey: 같은 세터에 넣은 키는 비밀값이다(키 이름 API 인 objectForKey: 와 다르다)."""
    (tmp_path / "A.m").write_text(f'[Foo setApiKey:@"{PW}"];\n[conn setConsumerKey:@"{PW}x"];\n[d objectForKey:@"{PW}"];\n')
    assert [c["name"] for c in secret_scan.source_literals(tmp_path)] == ["setApiKey", "setConsumerKey"]


def test_source_literals_xcconfig_unquoted(tmp_path):
    (tmp_path / "Release.xcconfig").write_text(
        f"API_KEY = {PW} // 운영\nCLIENT_SECRET[sdk=iphoneos*] = \"{PW}y\"\nBUNDLE_ID = com.example.app\nAPI_TOKEN = $(INHERITED_TOKEN)\n"
    )
    got = [(c["name"], c["value"]) for c in secret_scan.source_literals(tmp_path)]
    assert got == [("API_KEY", PW), ("CLIENT_SECRET", PW + "y")]


def test_presence_many_single_pass_and_nested_values(sandbox):
    short, long_ = "Zq9#Lm7!", "Ab3&Zq9#Lm7!Xy"  # 짧은 값이 긴 값 안에 들어 있다
    ipa = _ipa(sandbox, "pm.ipa", {"conf.txt": f"x{long_}x".encode(), "other.txt": short.encode()})
    r = secret_scan.presence_many(ipa, [short, long_, "absent-value-1"])
    assert sorted(w["path"] for w in r[short]) == ["conf.txt", "other.txt"]
    assert [w["path"] for w in r[long_]] == ["conf.txt"]
    assert r["absent-value-1"] == []


def test_source_literals_skip_build_products_and_frameworks(tmp_path):
    hdr = tmp_path / "Products" / "Debug" / "OpenSSL.framework" / "Headers"
    hdr.mkdir(parents=True)
    (hdr / "obj_mac.h").write_text('#define SN_pbe_WithSHA1And3_Key_TripleDES_CBC "PBE-SHA1-3DES"\n')
    vend = tmp_path / "Vendor" / "X.framework"
    vend.mkdir(parents=True)
    (vend / "X.h").write_text(f'#define X_API_KEY @"{PW}"\n')
    (tmp_path / "A.m").write_text(f'#define MY_API_KEY @"{PW}"\n')
    assert [c["name"] for c in secret_scan.source_literals(tmp_path)] == ["MY_API_KEY"]
