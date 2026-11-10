"""Swift 인라인 문자열 찾기, 시크릿 스캔(실제 바이너리 없이)."""

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
