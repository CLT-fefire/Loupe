"""알려진 형식의 키·토큰이 ipa 에 들어 있는지 찾는다.

값은 기본으로 가린다(16자 이상이면 앞 4자·뒤 2자, 그보다 짧으면 길이만). 같은 값인지는 지문으로
비교한다. 지문은 이 Mac 의 캐시 폴더에만 있는 비밀 키로 만든 HMAC 이라, 가린 값과 지문이 밖으로
나가도 짧은 값을 사전 대입으로 되돌릴 수 없다. 감사 로그에는 값도 지문도 남기지 않는다.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import plistlib
import re
from dataclasses import dataclass

from . import config, literals, macho
from .store import Ipa, LoupeError

MAX_PER_FILE = 1000  # 파일 하나에서 규칙 하나당 이보다 많이 맞으면 세기를 멈춘다
MAX_FILE_BYTES = 64 * 1024**2  # 리소스 파일은 이보다 크면 건너뛴다(바이너리는 크기와 관계없이 본다)
# 키·토큰이 들어갈 일이 없는 미디어·폰트. 통째로 읽고 규칙 전부로 훑는 비용만 든다
SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".heic", ".webp", ".pdf", ".mp4", ".mov", ".m4v", ".m4a",
    ".mp3", ".wav", ".caf", ".aif", ".ttf", ".otf", ".woff", ".woff2", ".nib",
}


@dataclass
class Rule:
    id: str
    name: str
    regex: re.Pattern
    confidence: str
    allow: re.Pattern | None
    public: bool
    note: str | None


def rules(raw: dict) -> list[Rule]:
    out = []
    for p in raw.get("patterns", []):
        try:
            out.append(
                Rule(
                    id=p["id"],
                    name=p["name"],
                    regex=re.compile(p["regex"].encode()),
                    confidence=p.get("confidence", "medium"),
                    allow=re.compile(p["allow"]) if p.get("allow") else None,
                    public=bool(p.get("public")),
                    note=p.get("note"),
                )
            )
        except (KeyError, re.error) as e:
            raise LoupeError(f"시크릿 패턴 규칙 오류({p.get('id')}): {e}") from e
    return out


def mask(value: str) -> str:
    if len(value) < 16:
        return f"({len(value)}자)"
    return f"{value[:4]}…{value[-2:]} ({len(value)}자)"


def _fp_key() -> bytes:
    path = config.CACHE_DIR / "fingerprint.key"
    try:
        key = path.read_bytes()
        if len(key) == 32:
            return key
    except FileNotFoundError:
        pass
    config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    # 서버 여러 개가 동시에 처음 만들 수 있다 → 임시 파일에 다 쓴 뒤 link 로 한 번만 붙인다(먼저 붙인 쪽이 이긴다)
    tmp = path.with_name(f"fingerprint.key.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(os.urandom(32))
    try:
        os.link(tmp, path)
    except FileExistsError:
        pass
    finally:
        os.unlink(tmp)
    return path.read_bytes()


def fingerprint(value: str) -> str:
    """같은 값인지 비교하는 용도. 이 Mac 에서만 같은 결과가 나온다."""
    return hmac.new(_fp_key(), value.encode(), hashlib.sha256).hexdigest()[:12]


def _files(ipa: Ipa, scope: str):
    if scope == "binaries":
        return ipa.binaries()
    if scope == "all":
        return [p for p in sorted(ipa.app.rglob("*")) if p.is_file() and not p.is_symlink()]
    raise LoupeError("scope 는 binaries, all 중 하나다")


def _resource_bytes(p) -> tuple[bytes | None, str | None, bool]:
    """(읽을 바이트, 건너뛴 이유, 변환 여부). 바이너리 plist 는 XML 로 바꿔서 돌려준다(값이 문자열로 보이게)."""
    if p.suffix.lower() in SKIP_SUFFIXES:
        return None, "미디어·폰트", False
    if p.stat().st_size > MAX_FILE_BYTES:
        return None, f"{MAX_FILE_BYTES // 1024**2}MB 초과", False
    data = p.read_bytes()
    if data.startswith(b"bplist"):
        try:
            return plistlib.dumps(plistlib.loads(data), fmt=plistlib.FMT_XML), None, True
        except Exception:
            pass  # 깨진 plist 는 원래 바이트로 본다
    return data, None, False


def scan(ipa: Ipa, rule_list: list[Rule], scope: str = "all", reveal: bool = False) -> dict:
    """규칙별로 서로 다른 값마다 (가린 값, 지문, 위치)를 모은다."""
    bins = set(ipa.binaries())
    found: dict[str, dict[str, dict]] = {r.id: {} for r in rule_list}
    capped, skipped = [], {}
    for p in _files(ipa, scope):
        m = macho.load(p) if p in bins else None
        converted = False
        if m:
            data, lo, hi = m.data, m.slice_offset, m.slice_offset + m.slice_size
        else:
            data, why, converted = _resource_bytes(p)
            if data is None:
                skipped[why] = skipped.get(why, 0) + 1
                continue
            lo, hi = 0, len(data)
        for r in rule_list:
            n = 0
            for h in r.regex.finditer(data, lo, hi):
                raw = h.group(1) if r.regex.groups else h.group(0)
                value = raw.decode("utf-8", "replace")
                if r.allow and r.allow.search(value):
                    continue
                n += 1
                if n > MAX_PER_FILE:
                    capped.append(f"{ipa.rel(p)}: {r.id}")
                    break
                fp = fingerprint(value)
                e = found[r.id].setdefault(
                    fp, {"value": value if reveal else mask(value), "fingerprint": fp, "count": 0, "locations": []}
                )
                e["count"] += 1
                if len(e["locations"]) < 5:
                    e["locations"].append(
                        {
                            "path": ipa.rel(p),
                            # 바이너리 plist 는 XML 로 바꿔 찾았으므로 파일 오프셋이 없다
                            "offset": None if converted else h.start(),
                            "section": m.section_at(h.start()) if m else ("binary plist(XML 로 변환)" if converted else None),
                        }
                    )
    out = []
    for r in rule_list:
        values = list(found[r.id].values())
        if not values:
            continue
        item = {"rule": r.id, "name": r.name, "confidence": r.confidence, "distinct": len(values), "values": values}
        if r.public:
            item["public_client_key"] = True
        if r.note:
            item["note"] = r.note
        out.append(item)
    order = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda x: (order.get(x["confidence"], 3), x.get("public_client_key", False), x["rule"]))
    result: dict = {"id": ipa.id, "scope": scope, "revealed": reveal, "findings": out}
    if capped:
        result["count_capped"] = capped[:20]
    if skipped:
        result["skipped_files"] = skipped
    return result


# ── 소스 기준 점검(source_secrets) ──────────────────────────────────────
# 형식이 없는 임의 문자열 키(비밀번호 모양 등)는 바이너리만 봐서는 오탐 없이 찾을 수 없다
# (2026-11-10 실측: 엔트로피 규칙은 기준을 낮추면 수천 건, 높이면 실제 하드코딩 값을 놓쳤다).
# 대신 소스에서 비밀 키워드가 붙은 이름 바로 뒤의 리터럴을 모으고, 그 값이 ipa 에 실제로 들어갔는지 본다.

_SRC_KW = re.compile(r"(?i)key|secret|passw(?:or)?d|pwd|token|salt|credential|auth")
# 이름 바로 뒤의 리터럴. 사이에 올 수 있는 것: '=', ':'(라벨·딕셔너리), ': 타입 =' (Swift 타입 표기), 공백(#define)
_SRC_ASSIGN = re.compile(
    r'\b([A-Za-z_]\w*)\s*(?::\s*[A-Za-z_][\w.]*[?!]?\s*=|[:=]|\s)\s*@?"((?:[^"\\\n]|\\.){6,})"'
)
# 키 이름을 다루는 API·상수(값이 키 이름이나 메시지다)
_SRC_NOT_SECRET_NAME = re.compile(
    r"(?i)(?:for|by)key(?:path|edsubscript)?$|^key(?:path)?$"
    r"|(?:description|message|error|reason|title)key$|andkeys$"
)
_UUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
SOURCE_EXTS = {".m", ".h", ".mm", ".swift", ".c", ".cc", ".cpp", ".xcconfig"}
# xcconfig 는 따옴표 없이 'NAME[조건] = 값 // 주석' 이다
_XCCONFIG_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*=\s*(.*?)\s*(?://.*)?$")
# 서로 다른 후보 값이 이보다 많으면 앞의 것만 확인한다. 값마다 bytes.find 로 훑으므로 비용은 후보 수 x 바이트다
# (2026-11-10 실측: Lysn_Epic 전체 후보 33개. 정규식 하나로 묶는 방식은 후보 5,000개에 26MB 가 70초를 넘었다)
MAX_SOURCE_CANDIDATES = 500
# 빌드 산출물·외부 바이너리 프레임워크의 헤더는 우리 소스가 아니다
# (2026-11-10: Products/…/OpenSSL.framework/Headers 의 상수 이름 4건이 후보로 걸렸다)
SOURCE_SKIP_DIRS = {".git", "DerivedData", "build", ".build", "Build", "Products", "Intermediates.noindex", "node_modules", "Carthage"}
SOURCE_SKIP_SUFFIXES = (".framework", ".xcframework", ".xcarchive", ".app")


def _char_classes(v: str) -> int:
    return sum(
        [any(c.isupper() for c in v), any(c.islower() for c in v), any(c.isdigit() for c in v), any(not c.isalnum() for c in v)]
    )


def source_confidence(value: str) -> str | None:
    """소스 리터럴이 비밀값 모양이면 신뢰도, 아니면 None."""
    v = value
    if " " in v or "%" in v or "\\(" in v or v.startswith(("/", "http", "#", "com.", "kr.", "0x")):
        return None  # 문장·형식 문자열·보간·경로·URL·색상·번들 id·16진수 상수
    if re.fullmatch(r"[A-Za-z][A-Za-z._\-]*|[._\-][A-Za-z._\-]*", v):
        return None  # 문자로만 된 이름(키 이름·라벨)
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\-]*", v) and re.search(r"[a-z]{4,}|[A-Z]{4,}", v) and sum(c.isdigit() for c in v) <= 2:
        return None  # 단어 위주 이름(숫자 2개 이하)
    if _UUID.fullmatch(v):
        return "low"  # 키체인 계정 이름 같은 식별자일 때가 많다
    if _char_classes(v) >= 3 or len(v) >= 32:
        return "high"
    return "medium"


def source_literals(root) -> list[dict]:
    """root 아래 소스에서 비밀 키워드가 붙은 이름 바로 뒤의 리터럴. 주석 줄은 건너뛴다."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SOURCE_SKIP_DIRS and not d.endswith(SOURCE_SKIP_SUFFIXES))
        for fn in sorted(filenames):
            if os.path.splitext(fn)[1] not in SOURCE_EXTS:
                continue
            path = os.path.join(dirpath, fn)
            if os.path.islink(path):
                continue  # 소스 루트 밖을 가리킬 수 있는 링크는 열지 않는다
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    lines = f.read().split("\n")
            except OSError:
                continue
            is_xcconfig = fn.endswith(".xcconfig")
            for i, line in enumerate(lines, 1):
                if line.lstrip().startswith(("//", "*", "/*")):
                    continue
                if is_xcconfig:
                    m = _XCCONFIG_ASSIGN.match(line)
                    pairs = []
                    if m and m.group(2):
                        v = m.group(2)
                        if len(v) >= 2 and v[0] == v[-1] == '"':
                            v = v[1:-1]
                        if len(v) >= 6 and "$(" not in v:  # 다른 설정을 끌어오는 값은 비밀값이 아니다
                            pairs = [(m.group(1), v)]
                else:
                    pairs = [(m.group(1), m.group(2)) for m in _SRC_ASSIGN.finditer(line)]
                for name, raw in pairs:
                    if not _SRC_KW.search(name) or _SRC_NOT_SECRET_NAME.search(name):
                        continue
                    value = literals.unescape(raw)
                    conf = source_confidence(value)
                    if conf:
                        out.append({"path": path, "line": i, "name": name, "value": value, "confidence": conf})
    return out


def _plist_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _plist_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _plist_strings(v)


def presence_many(ipa: Ipa, values: list[str]) -> dict[str, list[dict]]:
    """값들이 ipa 에 들어 있는 곳. 모든 값을 하나의 정규식으로 묶어 파일마다 한 번만 훑는다(메모리에는 파일
    하나만 올린다). 바이너리는 바이트·UTF-16LE 와 Swift 인라인(15바이트 이하), 리소스는 바이트·UTF-16LE/BE 와
    plist(바이너리 plist 포함)의 문자열로 찾는다. xcconfig 값은 Info.plist 같은 리소스로 들어가므로 리소스도
    본다. 미디어·폰트와 64MB 넘는 파일은 건너뛴다."""
    from . import swift_small

    out: dict[str, list[dict]] = {v: [] for v in values}
    if not values:
        return out
    needles: list[tuple[bytes, str, str]] = []  # (바이트, 값, 인코딩)
    for v in values:
        needles.append((v.encode("utf-8"), v, "bytes"))
        if not v.isascii():
            needles.append((v.encode("utf-16-le"), v, "utf-16le"))
            needles.append((v.encode("utf-16-be"), v, "utf-16be"))

    def scan(data: bytes, lo: int, hi: int, encodings: tuple[str, ...]) -> dict[str, tuple[str, int]]:
        """값마다 bytes.find(C 구현) 한 번. 파일은 한 번만 읽고 메모리에는 그 파일 하나만 둔다."""
        seen: dict[str, tuple[str, int]] = {}
        for n, v, how in needles:
            if v in seen or how not in encodings:
                continue
            off = data.find(n, lo, hi)
            if off >= 0:
                seen[v] = (how, off)
        return seen

    bins = ipa.binaries()
    bin_set = set(bins)
    for p in bins:
        m = macho.load(p)
        found = scan(m.data, m.slice_offset, m.slice_offset + m.slice_size, ("bytes", "utf-16le"))
        for v, (how, off) in found.items():
            out[v].append({"path": ipa.rel(p), "how": how, "section": m.section_at(off)})
        for v in values:
            if v not in found and len(v.encode("utf-8")) <= swift_small.SMALL_MAX:
                hits = swift_small.find(m, v, 1)
                if hits:
                    out[v].append({"path": ipa.rel(p), "how": "swift_inline", "address": hex(hits[0].address)})
    for p in sorted(ipa.app.rglob("*")):
        if not p.is_file() or p.is_symlink() or p in bin_set:
            continue
        if p.suffix.lower() in SKIP_SUFFIXES or p.stat().st_size > MAX_FILE_BYTES:
            continue
        data = p.read_bytes()
        found = scan(data, 0, len(data), ("bytes", "utf-16le", "utf-16be"))
        if data.startswith((b"bplist", b"<?xml")) or p.suffix in (".plist", ".strings"):
            try:
                strings = list(_plist_strings(plistlib.loads(data)))
            except Exception:
                strings = []
            for v in values:
                if v not in found and any(v in x for x in strings):
                    found[v] = ("plist", -1)
        for v, (how, _) in found.items():
            out[v].append({"path": ipa.rel(p), "how": how})
    return out


def presence(ipa: Ipa, value: str) -> list[dict]:
    return presence_many(ipa, [value])[value]


def source_scan(ipa: Ipa, root, reveal: bool = False, include_absent: bool = False) -> dict:
    """소스의 비밀값 후보 중 ipa 에 실제로 들어간 것. 같은 값은 지문으로 합친다."""
    by_fp: dict[str, dict] = {}
    for c in source_literals(root):
        fp = fingerprint(c["value"])
        e = by_fp.get(fp)
        if e is None:
            e = by_fp[fp] = {
                "value": c["value"] if reveal else mask(c["value"]),
                "fingerprint": fp,
                "length": len(c["value"]),
                "confidence": c["confidence"],
                "sources": [],
                "_raw": c["value"],
            }
        if len(e["sources"]) < 5:
            e["sources"].append({"path": os.path.relpath(c["path"], root), "line": c["line"], "name": c["name"]})
    found, absent = [], []
    entries = list(by_fp.values())
    skipped = max(0, len(entries) - MAX_SOURCE_CANDIDATES)
    entries = entries[:MAX_SOURCE_CANDIDATES]
    where_all = presence_many(ipa, [e["_raw"] for e in entries])
    for e in entries:
        raw = e.pop("_raw")
        where = where_all[raw]
        if where:
            e["in_ipa"] = where
            found.append(e)
        else:
            absent.append(e)
    order = {"high": 0, "medium": 1, "low": 2}
    found.sort(key=lambda e: (order[e["confidence"]], e["sources"][0]["path"], e["sources"][0]["line"]))
    result = {"id": ipa.id, "root": str(root), "revealed": reveal, "found": found, "candidates": len(by_fp), "absent_count": len(absent)}
    if skipped:
        result["not_checked"] = f"후보가 {MAX_SOURCE_CANDIDATES:,}개를 넘어 {skipped:,}개는 확인하지 않았다. root 를 좁힌다"
    if include_absent:
        result["absent"] = absent
    return result
