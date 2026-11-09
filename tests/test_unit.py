import re
import stat
import zipfile

import pytest

from loupe import analysis, config, names, store


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(config, "ALLOWED_DIRS", [tmp_path.resolve()])
    monkeypatch.setattr(config, "SOURCE_ROOTS", [tmp_path.resolve()])
    return tmp_path


def _zip(path, entries):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries:
            zf.writestr(name, data)


def test_zip_slip_rejected(sandbox):
    p = sandbox / "evil.ipa"
    _zip(p, [("Payload/A.app/Info.plist", b"x"), ("../../escape.txt", b"x")])
    with pytest.raises(store.LoupeError, match="허용되지 않는 경로"):
        store.open_ipa(str(p))
    # 막지 못했다면 캐시 폴더 기준 ../../ 위치, 즉 sandbox/cache/.. 근처에 생긴다
    assert not list(sandbox.rglob("escape.txt"))
    assert not list((sandbox / "cache").glob("*.tmp")), "실패해도 임시 폴더를 남기지 않는다"


def test_absolute_path_rejected(sandbox):
    p = sandbox / "evil.ipa"
    _zip(p, [("/tmp/abs.txt", b"x")])
    with pytest.raises(store.LoupeError, match="허용되지 않는 경로"):
        store.open_ipa(str(p))


def test_symlink_entry_skipped(sandbox):
    p = sandbox / "link.ipa"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("Payload/A.app/Info.plist", b"<plist/>")
        info = zipfile.ZipInfo("Payload/A.app/link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "/etc/passwd")
    ipa = store.open_ipa(str(p))
    assert not (ipa.app / "link").exists()


def test_outside_allowed_dir_rejected(sandbox, tmp_path_factory):
    other = tmp_path_factory.mktemp("elsewhere") / "x.ipa"
    _zip(other, [("Payload/A.app/Info.plist", b"x")])
    with pytest.raises(store.LoupeError, match="허용된 폴더 밖"):
        store.open_ipa(str(other))


def test_bad_id_rejected(sandbox):
    with pytest.raises(store.LoupeError, match="잘못된 id"):
        store.get("../etc")


def test_swift_components():
    assert names.swift_components("_TtC10Fork_Stars28SignInForJapanRepositoryImpl") == [
        "Fork_Stars",
        "SignInForJapanRepositoryImpl",
    ]
    assert names.leaf("_TtC10Fork_Stars31zZAaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == "zZAaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert names.leaf("$__lazy_storage_$_badgeLabel") == "badgeLabel"
    assert names.leaf("purchaseProductID:completion:") == "purchaseProductID"


@pytest.mark.parametrize(
    "name,expected",
    [
        ("zZZZZZLaaaa", True),  # AppDelegate
        ("paaaaaaa", True),  # handlers
        ("zZZvaaaaaaaaaaaaaaaaaaaaaa", True),
        ("$__lazy_storage_$_zZEaaaaaaa", True),
        ("AppDelegate", False),
        ("Data", False),
        ("Baa", False),  # 너무 짧다
    ],
)
def test_obfuscation_pattern(name, expected):
    rules = analysis.load_rules("liapp")
    pat = names.Pattern(re.compile(rules["obfuscated_name"]["regex"]), rules["obfuscated_name"]["min_len"])
    assert pat.match(name) is expected


def test_literals_from_source(sandbox):
    src = sandbox / "A.m"
    src.write_text(
        "line1\n"
        'NSString *k = @"abc\\"def"; let s = "two";\n'
        'let n = user.name ?? ""\n'
        'let g = "Hello \\(name)!"\n'
        "if (c == '\"') { x = @\"k\"; }\n"
        'let u = "\\u{AC00}a"\n'
    )
    assert analysis.literals_from_source(f"{src}:2") == (['abc"def', "two"], [])
    with pytest.raises(store.LoupeError, match="리터럴이 없다"):
        analysis.literals_from_source(f"{src}:1")
    # 빈 문자열만 있으면 모든 위치에 맞아 버리므로 거부한다
    with pytest.raises(store.LoupeError, match="빈 문자열"):
        analysis.literals_from_source(f"{src}:3")
    lits, notes = analysis.literals_from_source(f"{src}:4")
    assert lits == ["Hello ", "!"] and notes
    assert analysis.literals_from_source(f"{src}:5")[0] == ["k"]  # 문자 리터럴 '"' 에 속지 않는다
    assert analysis.literals_from_source(f"{src}:6")[0] == ["가a"]


def test_source_outside_root_rejected(sandbox, tmp_path_factory):
    other = tmp_path_factory.mktemp("src") / "B.m"
    other.write_text('@"x"\n')
    with pytest.raises(store.LoupeError, match="소스 루트 밖"):
        analysis.literals_from_source(f"{other}:1")


def test_rules_name_validated():
    with pytest.raises(store.LoupeError):
        analysis.load_rules("../x")


def test_java_class_not_treated_as_fat_macho(sandbox):
    import plistlib

    p = sandbox / "j.ipa"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("Payload/A.app/Info.plist", plistlib.dumps({"CFBundleExecutable": "A"}))
        zf.writestr("Payload/A.app/A", b"\xcf\xfa\xed\xfe" + b"\0" * 28)
        zf.writestr("Payload/A.app/Foo.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\0" * 16)  # Java 8
    ipa = store.open_ipa(str(p))
    assert [ipa.rel(b) for b in ipa.binaries()] == ["A"]


def test_concurrent_open_same_ipa(sandbox):
    """같은 ipa 를 동시에 열어도 캐시가 깨지지 않는다(예전엔 같은 .tmp 를 같이 썼다)."""
    import plistlib
    from concurrent.futures import ThreadPoolExecutor

    p = sandbox / "c.ipa"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("Payload/A.app/Info.plist", plistlib.dumps({"CFBundleExecutable": "A"}))
        for i in range(300):
            zf.writestr(f"Payload/A.app/r/{i}.txt", b"x" * 1000)
    with ThreadPoolExecutor(8) as ex:
        ids = list(ex.map(lambda _: store.open_ipa(str(p)).id, range(8)))
    assert len(set(ids)) == 1
    ipa = store.get(ids[0])
    assert len(list((ipa.app / "r").iterdir())) == 300
    assert not list((sandbox / "cache").glob("*.tmp"))


def test_clamp():
    assert analysis.clamp("n", 5, 0, 3) == 3
    with pytest.raises(store.LoupeError):
        analysis.clamp("n", -1, 0, 3)
    with pytest.raises(store.LoupeError):
        analysis.clamp("n", True, 0, 3)


# ── 개선(2026-11-09 3차) ──


@pytest.mark.parametrize(
    "name,obfuscated",
    [
        ('T@"NSNumber",&,N,V_zZZZZeaaaa', True),  # 프로퍼티 속성 문자열의 이름
        ('T@"zZZqaaa",&,N', True),  # 속성 문자열 안의 타입 이름
        ('T@"_TtC10Fork_Stars10zZZZZZGaaa",N,R', True),  # 속성 문자열 안의 Swift 맹글링 이름
        ("_zZZZZeaaaa", True),  # 인스턴스 변수 밑줄
        ("_TtC10Fork_StarsP33_zZZPaaaaaaaaaaaaaaaaaaaaaaaaaaaa32JSONRequestManagerRawJSONFetcher", True),
        ('T@"NSNumber",&,N,V_isSendedAuthCode', False),
        ("_isInvalidAuthCode", False),
        ("_TtC10Fork_Stars28SignInForJapanRepositoryImpl", False),
    ],
)
def test_obfuscation_tokens(name, obfuscated):
    rules = analysis.load_rules("liapp")
    pat = names.Pattern(re.compile(rules["obfuscated_name"]["regex"]), rules["obfuscated_name"]["min_len"])
    assert pat.match(name) is obfuscated


def test_compare_code_names_only():
    a = "void IAPPopupManager::dismiss_(ID p1)\n{\n  FUN_1000(p1, 0x18);\n  return;\n}\n"
    b = "void zZZZZZZZvaaaaaa::dismiss_(ID p1)\n{\n  FUN_1000(p1, 0x18);\n  return;\n}\n"
    r = analysis.compare_code(a, b)
    assert r["identical"] is False and r["names_only"] is True
    assert r["renamed"] == [{"a": "IAPPopupManager::dismiss_", "b": "zZZZZZZZvaaaaaa::dismiss_"}]


def test_compare_code_logic_change():
    a = "int f(int x)\n{\n  return x + 1;\n}\n"
    b = "int f(int x)\n{\n  return x + 2;\n}\n"
    r = analysis.compare_code(a, b)
    assert r["names_only"] is False and r["diff_lines"] > 0
    assert analysis.compare_code(a, a)["identical"] is True


def test_compare_code_inconsistent_rename_is_logic_change():
    # 같은 이름 x 가 한 곳에선 y, 다른 곳에선 z 로 바뀌면 이름 바꾸기가 아니다
    a = "f(x); g(x);"
    b = "f(y); g(z);"
    assert analysis.compare_code(a, b)["names_only"] is False
