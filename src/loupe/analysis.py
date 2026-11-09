"""1단계(정적 점검) 도구의 실제 로직. server.py 는 이 함수들을 MCP 도구로 감싸기만 한다."""

from __future__ import annotations

import hashlib
import re
from functools import lru_cache
from importlib import resources
from pathlib import Path

import yaml

from . import config, macho, names, signing
from .store import Ipa, LoupeError

SWIFT_INLINE_LIMIT = 15  # Swift 는 이 바이트 이하 문자열을 명령어에 인라인한다


def clamp(name: str, value: int, lo: int, hi: int) -> int:
    """개수 인자 검사. 음수는 파이썬 슬라이스에서 '뒤에서 n개 빼기'가 되므로 거부하고, 너무 크면 줄인다."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise LoupeError(f"{name} 는 정수다")
    if value < lo:
        raise LoupeError(f"{name} 는 {lo} 이상이다 (받은 값 {value})")
    return min(value, hi)


# ── 규칙 ────────────────────────────────────────────────────────────────


@lru_cache
def load_rules(name: str = "liapp") -> dict:
    if not re.fullmatch(r"[a-z0-9_-]+", name):
        raise LoupeError(f"잘못된 규칙 이름: {name!r}")
    try:
        text = resources.files("loupe.rules").joinpath(f"{name}.yaml").read_text()
    except FileNotFoundError as e:
        raise LoupeError(f"규칙 파일이 없다: {name}.yaml") from e
    return yaml.safe_load(text)


def _pattern(rules: dict) -> names.Pattern:
    o = rules["obfuscated_name"]
    return names.Pattern(re.compile(o["regex"]), int(o["min_len"]))


# ── ipa_info ────────────────────────────────────────────────────────────


def info(ipa: Ipa) -> dict:
    pl = ipa.info_plist
    main = macho.load(ipa.main_binary)
    bins = ipa.binaries()
    prof = signing.profile(ipa.app)
    debug_dylibs = [ipa.rel(p) for p in ipa.app.rglob("*.debug.dylib")]
    binaries = []
    for b in bins:
        try:
            m = macho.load(b)
            s = m.summary()
            binaries.append({"path": ipa.rel(b), "size": s["size"], "fairplay_encrypted": s["fairplay_encrypted"]})
        except Exception as e:  # 깨진 파일이 있어도 나머지는 보여 준다
            binaries.append({"path": ipa.rel(b), "error": str(e)})
    hints = []
    if prof and prof.get("get_task_allow"):
        hints.append("get-task-allow=true: 개발용 서명(Debug 계열일 가능성이 크다)")
    if debug_dylibs:
        hints.append("*.debug.dylib 있음: Xcode Debug 빌드. 실제 코드는 메인 실행 파일이 아니라 이 dylib 에 있다")
    if any(x.get("fairplay_encrypted") for x in binaries):
        hints.append("FairPlay 암호화된 바이너리가 있다: App Store 에서 받은 ipa 로 보인다. 정적 분석과 Ghidra 결과는 의미가 없다")
    return {
        "id": ipa.id,
        "source": ipa.source,
        "sha256": ipa.sha256,
        "bundle": {
            "identifier": pl.get("CFBundleIdentifier"),
            "name": pl.get("CFBundleDisplayName") or pl.get("CFBundleName"),
            "version": pl.get("CFBundleShortVersionString"),
            "build": pl.get("CFBundleVersion"),
            "minimum_os": pl.get("MinimumOSVersion"),
            "executable": pl.get("CFBundleExecutable"),
        },
        "profile": prof,
        "signature": signing.signature(ipa.app),
        "build_hints": hints,
        "main_binary": main.summary(),
        "binaries": binaries,
    }


# ── protection_check ───────────────────────────────────────────────────


def _obfuscation_stats(m: macho.MachO, pat: names.Pattern) -> dict:
    out = {}
    for sec, entries in names.all_names(m).items():
        total = len(entries)
        hit = [n for _, n in entries if pat.match(n)]
        out[sec] = {
            "total": total,
            "obfuscated": len(hit),
            "ratio": round(len(hit) / total, 4) if total else 0.0,
            "samples": hit[:8],
        }
    return out


def protection_check(ipa: Ipa, rules_name: str = "liapp") -> dict:
    rules = load_rules(rules_name)
    pat = _pattern(rules)
    code = ipa.code_binary
    main = macho.load(code)

    present = [f for f in rules.get("added_files", []) if (ipa.app / f).is_file()]
    missing = [f for f in rules.get("added_files", []) if f not in present]
    stats = _obfuscation_stats(main, pat)
    ratio = stats.get("__objc_classname", {}).get("ratio", 0.0)
    class_total = stats.get("__objc_classname", {}).get("total", 0)
    threshold = float(rules["obfuscated_name"]["classname_ratio_threshold"])

    sdk = rules.get("sdk_markers", {})
    classnames = {leaf for _, n in names.name_entries(main, "__objc_classname") for leaf in [names.leaf(n)]}
    sdk_found = [c for c in sdk.get("class_names", []) if c in classnames]
    sdk_found += [s for s in sdk.get("strings", []) if s.encode() in main.data]

    files_ok = not missing and bool(present)
    names_ok = ratio >= threshold
    if class_total == 0:
        # 이름 섹션이 비었다 = 판단할 재료가 없다. 0% 를 '난독화 없음'으로 읽으면 안 된다.
        verdict = "unknown"
    elif files_ok and names_ok:
        verdict = "applied"
    elif files_ok or names_ok or present:
        verdict = "partial"
    else:
        verdict = "not_applied"

    reasons = []
    reasons.append(f"추가 파일 {len(present)}/{len(present) + len(missing)}개 있음" + (f" (없음: {missing})" if missing else ""))
    if class_total == 0:
        reasons.append(
            f"{ipa.rel(code)} 에 ObjC 클래스 이름 섹션이 없다(순수 Swift·C 바이너리이거나 코드가 다른 파일에 있다). 이름 기준으로는 판정할 수 없다"
        )
    else:
        reasons.append(f"클래스 이름 난독화 비율 {ratio:.1%} (기준 {threshold:.0%}, 대상 {ipa.rel(code)})")
    if sdk_found:
        reasons.append(f"SDK 흔적 {sdk_found}: SDK 가 링크돼 있다는 뜻일 뿐, 적용 근거는 아니다")
    return {
        "id": ipa.id,
        "solution": rules.get("name", rules_name),
        "analyzed_binary": ipa.rel(code),
        "verdict": verdict,
        "reasons": reasons,
        "added_files": {"present": present, "missing": missing},
        "obfuscation": stats,
        "sdk_markers_found": sdk_found,
        "notes": [
            "이 판정은 정적 흔적만 본다. 안티디버그·무결성 검사 같은 실행 중 보호는 확인하지 못한다.",
            "재서명 때문에 바뀐 점(엔타이틀먼트 등)은 미적용본과 비교하는 ipa_diff 로 확인한다.",
        ],
    }


# ── ipa_diff ───────────────────────────────────────────────────────────


def _file_map(ipa: Ipa) -> dict[str, tuple[int, str]]:
    out = {}
    for p in ipa.app.rglob("*"):
        if p.is_file() and not p.is_symlink():
            data = p.read_bytes()
            out[ipa.rel(p)] = (len(data), hashlib.md5(data, usedforsecurity=False).hexdigest())
    return out


def _section_changes(a: macho.MachO, b: macho.MachO) -> dict | None:
    la = [(s.key, s.offset, s.size) for s in a.sections]
    lb = [(s.key, s.offset, s.size) for s in b.sections]
    if la != lb:
        return None
    out = {}
    for s in a.sections:
        x, y = a.section_bytes(s), b.section_bytes(s)
        n = sum(1 for i in range(len(x)) if x[i] != y[i]) if x != y else 0
        if n:
            out[s.key] = {"changed_bytes": n, "size": s.size, "ratio": round(n / s.size, 4)}
    return dict(sorted(out.items(), key=lambda kv: -kv[1]["changed_bytes"]))


def _name_changes(a: macho.MachO, b: macho.MachO, samples: int) -> dict:
    out = {}
    for sec in macho.NAME_SECTIONS:
        pairs = names.pair_names(a, b, sec)
        if pairs is None:
            sa = {n for _, n in names.name_entries(a, sec)}
            sb = {n for _, n in names.name_entries(b, sec)}
            out[sec] = {"paired": False, "only_a": len(sa - sb), "only_b": len(sb - sa)}
            continue
        changed = [(x, y) for x, y in pairs if x != y]
        out[sec] = {
            "paired": True,
            "total": len(pairs),
            "renamed": len(changed),
            "samples": [{"a": x, "b": y} for x, y in changed[:samples]],
        }
    return out


def _bundles(ipa: Ipa) -> list[Path]:
    """서명 단위(앱, appex, framework)."""
    out = [ipa.app]
    for ext in ("*.appex", "*.framework"):
        out += sorted(ipa.app.rglob(ext))
    return out


def diff(a: Ipa, b: Ipa, samples: int = 10) -> dict:
    samples = clamp("samples", samples, 0, 200)
    ia, ib = a.info_plist, b.info_plist
    warnings = []
    for key, label in [
        ("CFBundleIdentifier", "번들 id"),
        ("CFBundleShortVersionString", "버전"),
        ("CFBundleVersion", "빌드 번호"),
    ]:
        if ia.get(key) != ib.get(key):
            warnings.append(f"{label}가 다르다: {ia.get(key)} vs {ib.get(key)}")
    pa, pb = signing.profile(a.app) or {}, signing.profile(b.app) or {}
    if "error" in pa or "error" in pb:
        warnings.append("프로비저닝 프로파일을 읽지 못한 쪽이 있어 서명 종류를 비교하지 않았다")
    elif pa.get("kind") != pb.get("kind"):
        warnings.append(f"서명 종류가 다르다: {pa.get('kind')} vs {pb.get('kind')}. 빌드 설정 차이를 보호 효과로 착각할 수 있다")
    if bool(list(a.app.rglob("*.debug.dylib"))) != bool(list(b.app.rglob("*.debug.dylib"))):
        warnings.append("한쪽만 *.debug.dylib 가 있다: Debug 와 Release 빌드를 비교하고 있다")

    fa, fb = _file_map(a), _file_map(b)
    only_a = sorted(set(fa) - set(fb))
    only_b = sorted(set(fb) - set(fa))
    changed = sorted(k for k in set(fa) & set(fb) if fa[k][1] != fb[k][1])

    bin_rel = {a.rel(p) for p in a.binaries()}
    name_bins = {a.rel(a.main_binary), a.rel(a.code_binary)}
    binaries = {}
    for rel in changed:
        if rel not in bin_rel:
            continue
        try:
            ma, mb = macho.load(a.app / rel), macho.load(b.app / rel)
        except Exception as e:  # 한쪽이 깨졌거나 Mach-O 가 아니어도 나머지 비교는 계속한다
            binaries[rel] = {"size": [fa[rel][0], fb[rel][0]], "error": f"Mach-O 로 읽지 못했다: {e}"}
            continue
        sec = _section_changes(ma, mb)
        entry: dict = {"size": [fa[rel][0], fb[rel][0]]}
        if sec is None:
            entry["sections"] = "섹션 배치가 달라 바이트 비교를 하지 않았다"
        else:
            entry["sections"] = sec
            if not sec:
                entry["note"] = "모든 섹션 내용이 같다. 서명·링크 정보(__LINKEDIT, 헤더)만 다르다"
        if rel in name_bins or (sec and any(k.endswith(tuple(macho.NAME_SECTIONS)) for k in sec)):
            entry["names"] = _name_changes(ma, mb, samples)
        binaries[rel] = entry

    ents = {}
    for bundle in _bundles(a):
        rel = "." if bundle == a.app else a.rel(bundle)
        other = b.app if rel == "." else b.app / rel
        if not other.exists():
            continue
        d = signing.diff_dict(signing.entitlements(bundle), signing.entitlements(other))
        if d:
            ents[rel] = d

    sa, sb = signing.signature(a.app), signing.signature(b.app)
    return {
        "a": {"id": a.id, "source": a.source},
        "b": {"id": b.id, "source": b.source},
        "warnings": warnings,
        "files": {
            "only_a_count": len(only_a),
            "only_a": only_a[:FILE_LIST_LIMIT],
            "only_b_count": len(only_b),
            "only_b": [{"path": p, "size": fb[p][0]} for p in only_b[:FILE_LIST_LIMIT]],
            "changed_count": len(changed),
            # 바이너리를 먼저 보여 준다(리소스 수천 개에 묻히지 않게)
            "changed": [
                {"path": p, "size": [fa[p][0], fb[p][0]]}
                for p in sorted(changed, key=lambda x: (x not in bin_rel, x))[:FILE_LIST_LIMIT]
            ],
            "unchanged_count": len(set(fa) & set(fb)) - len(changed),
            "note": f"목록은 각각 최대 {FILE_LIST_LIMIT}개까지 보여 준다. 전체 개수는 *_count 를 본다.",
        },
        "binaries": binaries,
        "entitlements": ents or "차이 없음",
        "signature": signing.diff_dict(
            {k: v for k, v in sa.items() if k != "signed_time"}, {k: v for k, v in sb.items() if k != "signed_time"}
        )
        or "인증서·팀·식별자 같음",
    }


# ── find_strings ───────────────────────────────────────────────────────

_LITERAL = re.compile(r'@?"((?:[^"\\\n]|\\.)*)"')
_CHAR_LITERAL = re.compile(r"'(?:\\.|[^'\\\n])'")  # ObjC/C 문자 리터럴 '"' 같은 것
_INTERP = re.compile(r"\\\((?:[^()]|\([^()]*\))*\)")  # Swift 문자열 보간 \(...)
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "'": "'", "\\": "\\", "0": "\0"}


def _unescape(lit: str) -> str:
    lit = re.sub(r"\\u\{([0-9a-fA-F]{1,8})\}", lambda m: chr(int(m.group(1), 16)), lit)  # Swift \u{AC00}
    return re.sub(r"\\(.)", lambda m: _ESCAPES.get(m.group(1), m.group(0)), lit)


def literals_from_source(ref: str) -> tuple[list[str], list[str]]:
    """'경로:줄' 에서 문자열 리터럴을 꺼낸다. (리터럴 목록, 경고 목록)을 돌려준다.

    경로는 LOUPE_SOURCE_ROOTS 아래여야 한다. 빈 리터럴("")은 버린다(모든 위치에 맞아 버린다).
    Swift 보간("a\\(x)b")은 바이너리에 조각("a", "b")으로 들어가므로 조각으로 나눠 찾는다.
    """
    m = re.fullmatch(r"(.+):(\d+)", ref.strip())
    if not m:
        raise LoupeError("source_ref 는 '경로:줄' 형식이다. 예: /Users/Shared/Source/Company/Lysn_Epic/dontalk/A.m:13")
    path, line = Path(m.group(1)).expanduser(), int(m.group(2))
    if not path.is_absolute():
        cands = [r / path for r in config.SOURCE_ROOTS if (r / path).is_file()]
        if not cands:
            raise LoupeError(f"소스 파일을 찾지 못했다: {path} (루트: {[str(r) for r in config.SOURCE_ROOTS]})")
        path = cands[0]
    if not config.is_under(path, config.SOURCE_ROOTS):
        raise LoupeError(f"허용된 소스 루트 밖이다: {path} (LOUPE_SOURCE_ROOTS 로 바꿀 수 있다)")
    if not path.is_file():
        raise LoupeError(f"소스 파일이 없다: {path}")
    lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
    if not 1 <= line <= len(lines):
        raise LoupeError(f"줄 번호가 범위 밖이다: {line} (파일은 {len(lines)}줄)")
    text = _CHAR_LITERAL.sub("", lines[line - 1])
    out, notes = [], []
    for lit in _LITERAL.findall(text):
        if _INTERP.search(lit):
            pieces = [p for p in _INTERP.split(lit) if p]
            notes.append(f"Swift 보간이 있는 리터럴은 조각 {len(pieces)}개로 나눠 찾는다")
        else:
            pieces = [lit]
        for p in pieces:
            u = _unescape(p)
            if u and u not in out:
                out.append(u)
    if not out:
        raise LoupeError(f"{path.name}:{line} 에 찾을 만한 문자열 리터럴이 없다(빈 문자열은 제외)")
    return out, notes


def _targets(ipa: Ipa, scope: str) -> list[Path]:
    if scope == "main":
        # Debug 빌드면 실제 코드가 든 .debug.dylib 도 함께 본다
        return list(dict.fromkeys([ipa.main_binary, ipa.code_binary]))
    if scope == "binaries":
        return ipa.binaries()
    if scope == "all":
        return [p for p in sorted(ipa.app.rglob("*")) if p.is_file() and not p.is_symlink()]
    raise LoupeError("scope 는 main, binaries, all 중 하나다")


FILE_LIST_LIMIT = 200  # 응답이 너무 커지지 않게 파일 목록은 이만큼만 보여 준다
MAX_COUNT = 1_000_000  # 파일 하나에서 이보다 많이 맞으면 세기를 멈춘다(정규식 '.' 같은 경우)


def _decode(raw: bytes, encoding: str) -> str:
    if encoding.startswith("utf-16"):
        raw = raw[: len(raw) - len(raw) % 2]
    return raw.decode(encoding, "replace")


def _context(data: bytes, start: int, end: int, encoding: str, width: int = 24) -> str:
    """찾은 위치 앞뒤. UTF-16 은 2바이트 단위로 맞춰 디코딩한다."""
    if encoding.startswith("utf-16"):
        width -= width % 2
        seg = data[max(0, start - width) : end + width]
        text = _decode(seg, encoding)
        return "".join(c if c.isprintable() else "·" for c in text)
    seg = data[max(0, start - width) : end + width]
    text = seg.decode("utf-8", "replace")
    return "".join(c if c.isprintable() and c != "\ufffd" else "·" for c in text)


def find_strings(
    ipas: list[Ipa],
    query: str | None = None,
    regex: str | None = None,
    source_ref: str | None = None,
    scope: str = "binaries",
    max_hits: int = 5,
) -> dict:
    max_hits = clamp("max_hits", max_hits, 0, 100)
    # (표시 이름, 패턴, 인코딩)
    needles: list[tuple[str, re.Pattern, str]] = []
    warnings = []
    texts: list[str] = []
    if query:
        texts.append(query)
    if source_ref:
        lits, notes = literals_from_source(source_ref)
        texts += lits
        warnings += notes
    for t in texts:
        enc8 = t.encode("utf-8")
        needles.append((t, re.compile(re.escape(enc8)), "utf-8"))
        if any(ord(c) > 127 for c in t):
            # Mach-O __ustring 은 UTF-16LE, 컴파일된 .strings(바이너리 plist)는 UTF-16BE 로 저장한다
            needles.append((t + " (UTF-16LE)", re.compile(re.escape(t.encode("utf-16-le"))), "utf-16-le"))
            needles.append((t + " (UTF-16BE)", re.compile(re.escape(t.encode("utf-16-be"))), "utf-16-be"))
        if len(enc8) <= SWIFT_INLINE_LIMIT:
            warnings.append(
                f"'{t}' 는 {len(enc8)}바이트다. Swift 는 15바이트 이하 문자열을 명령어에 인라인하므로 "
                "Swift 코드에서 쓰였다면 0건이어도 바이너리에 없다는 뜻이 아니다(Ghidra decompile 로 확인)."
            )
    if regex:
        try:
            needles.append((f"regex:{regex}", re.compile(regex.encode("utf-8")), "utf-8"))
        except re.error as e:
            raise LoupeError(f"정규식 오류: {e}") from e
    if not needles:
        raise LoupeError("query, regex, source_ref 중 하나는 있어야 한다")

    bin_set: dict[str, set] = {}
    results = []
    for label, rx, enc in needles:
        row: dict = {"needle": label, "per_ipa": {}}
        for ipa in ipas:
            bin_set.setdefault(ipa.id, set(ipa.binaries()))
            total, files, capped, more_files = 0, [], False, 0
            for p in _targets(ipa, scope):
                m = macho.load(p) if p in bin_set[ipa.id] else None
                data = m.data if m else p.read_bytes()
                # fat 바이너리는 같은 문자열이 slice 마다 있으므로 arm64 slice 만 센다
                lo, hi = (m.slice_offset, m.slice_offset + m.slice_size) if m else (0, len(data))
                count, first = 0, []
                for h in rx.finditer(data, lo, hi):
                    if len(first) < max_hits:
                        first.append(h)
                    count += 1
                    if count >= MAX_COUNT:
                        capped = True
                        break
                if not count:
                    continue
                total += count
                if len(files) >= FILE_LIST_LIMIT:
                    more_files += 1
                    continue
                files.append(
                    {
                        "path": ipa.rel(p),
                        "count": count,
                        "hits": [
                            {
                                "offset": h.start(),
                                "section": m.section_at(h.start()) if m else None,
                                "match": _decode(h.group(0), enc)[:200],
                                "context": _context(data, h.start(), h.end(), enc),
                            }
                            for h in first
                        ],
                    }
                )
            entry = {"total": total, "files": files}
            if more_files:
                entry["more_files"] = f"맞은 파일이 {more_files}개 더 있다(목록은 {FILE_LIST_LIMIT}개까지)"
            if capped:
                entry["count_capped"] = f"파일당 {MAX_COUNT:,}건에서 세기를 멈췄다. 패턴을 좁힌다."
            row["per_ipa"][ipa.id] = entry
        results.append(row)
    return {
        "scope": scope,
        "ipas": {i.id: i.source for i in ipas},
        "warnings": warnings,
        "results": results,
    }


# ── list_names ─────────────────────────────────────────────────────────


def list_names(
    ipa: Ipa,
    other: Ipa | None = None,
    section: str = "__objc_classname",
    filter: str | None = None,
    status: str = "all",
    limit: int = 100,
    rules_name: str = "liapp",
) -> dict:
    limit = clamp("limit", limit, 0, 2000)
    if section not in macho.NAME_SECTIONS:
        raise LoupeError(f"section 은 {list(macho.NAME_SECTIONS)} 중 하나다")
    if status not in ("all", "kept", "renamed"):
        raise LoupeError("status 는 all, kept, renamed 중 하나다")
    try:
        rx = re.compile(filter, re.I) if filter else None
    except re.error as e:
        raise LoupeError(f"정규식 오류: {e}") from e
    pat = _pattern(load_rules(rules_name))
    m = macho.load(ipa.code_binary)

    if other is None:
        rows = [{"name": n, "looks_obfuscated": pat.match(n)} for _, n in names.name_entries(m, section)]
        if rx:
            rows = [r for r in rows if rx.search(r["name"])]
        if status == "renamed":
            rows = [r for r in rows if r["looks_obfuscated"]]
        elif status == "kept":
            rows = [r for r in rows if not r["looks_obfuscated"]]
        return {"id": ipa.id, "section": section, "mode": "single", "matched": len(rows), "names": rows[:limit]}

    mo = macho.load(other.code_binary)
    pairs = names.pair_names(m, mo, section)
    if pairs is None:
        raise LoupeError("두 바이너리의 이름 섹션 배치가 달라 짝지을 수 없다. 같은 빌드의 적용/미적용 쌍인지 확인한다.")
    rows = [{"name": x, "other": y, "renamed": x != y} for x, y in pairs]
    if rx:
        rows = [r for r in rows if rx.search(r["name"])]
    renamed = sum(1 for r in rows if r["renamed"])
    counts = {"matched": len(rows), "renamed": renamed, "kept": len(rows) - renamed}
    if status == "renamed":
        rows = [r for r in rows if r["renamed"]]
    elif status == "kept":
        rows = [r for r in rows if not r["renamed"]]
    return {
        "id": ipa.id,
        "other": other.id,
        "section": section,
        "mode": "paired",
        "counts": counts,
        "listed": min(len(rows), limit),
        "names": rows[:limit],
    }


# ── compare_function ───────────────────────────────────────────────────

_CODE_TOKEN = re.compile(r"[A-Za-z_$][A-Za-z0-9_$:.]*|0x[0-9a-fA-F]+|\d+|\S")


def compare_code(code_a: str, code_b: str, max_diff_lines: int = 200) -> dict:
    """두 디컴파일 결과를 비교한다.

    - identical: 글자 하나까지 같다
    - names_only: 토큰 수가 같고, 다른 토큰이 전부 식별자(이름)뿐이다 → 로직은 같고 이름만 바뀌었다
    """
    import difflib

    if code_a == code_b:
        return {"identical": True, "names_only": True, "renamed": [], "diff": []}
    ta, tb = _CODE_TOKEN.findall(code_a), _CODE_TOKEN.findall(code_b)
    renamed: dict[str, str] = {}
    names_only = len(ta) == len(tb)
    if names_only:
        for x, y in zip(ta, tb):
            if x == y:
                continue
            ident = re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$:.]*", x) and re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$:.]*", y)
            if not ident or renamed.get(x, y) != y:  # 이름이 아니거나, 같은 이름이 다른 이름으로 바뀌면 로직 차이
                names_only = False
                break
            renamed[x] = y
    diff = list(difflib.unified_diff(code_a.splitlines(), code_b.splitlines(), "a", "b", lineterm="", n=1))
    return {
        "identical": False,
        "names_only": names_only,
        "renamed": [{"a": k, "b": v} for k, v in list(renamed.items())[:50]] if names_only else [],
        "diff_lines": len(diff),
        "diff": diff[:max_diff_lines],
    }
