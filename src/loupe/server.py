"""Loupe MCP 서버 (stdio)."""

from __future__ import annotations

import json
import logging
import time
from functools import wraps
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import analysis, config, ghidra_client, store
from .store import LoupeError

INSTRUCTIONS = """\
Loupe — 우리가 직접 빌드한 ipa 를 정적으로 분석한다(보호 솔루션 적용 여부, 문자열·이름 노출, 디컴파일).

순서: ipa_open(경로) 로 id 를 받고, 그 id 로 다른 도구를 부른다. 같은 ipa 는 다시 풀지 않는다.
- 적용 여부: protection_check(id). 근거(추가 파일, 난독화 이름 비율)를 같이 준다.
- 쌍 비교: ipa_diff(a, b). 같은 빌드의 미적용(a)·적용(b) 쌍이어야 의미가 있다. 빌드 종류가 다르면 경고한다.
- 문자열: find_strings(ids, query|regex|source_ref). 15바이트 이하 Swift 문자열은 명령어에 인라인돼
  0건이어도 '없다'는 뜻이 아니다 — 그럴 땐 Ghidra(decompile)로 확인한다.
- 이름: list_names(id, other_id?) 로 난독화된/보존된 클래스·메서드 이름을 본다.
- Ghidra: ghidra_analyze 로 시작(26MB 바이너리는 약 10분, ghidra_status 가 예상 시간을 준다) → search_functions /
  decompile / xrefs. 같은 함수를 두 ipa 에서 비교하려면 compare_function(a, b, function).

찾은 값은 원문으로 돌려준다. 외부(Confluence·메일 등)로 옮길 때 키·토큰 같은 값은 사람이 가린다.
App Store 에서 받은 ipa(FairPlay 암호화)는 분석할 수 없다.
"""

mcp = MCPServer("loupe", instructions=INSTRUCTIONS)

config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
_log = logging.getLogger("loupe")
_handler = logging.FileHandler(config.LOG_FILE)
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
_log.addHandler(_handler)
_log.setLevel(logging.INFO)
_log.propagate = False  # 감사 로그는 파일에만 남긴다


def _audit(fn):
    """감사 로그: 도구 이름·ipa id·결과 크기·소요 시간만 남긴다(찾은 값은 남기지 않는다)."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        t = time.time()
        ids = {k: v for k, v in kwargs.items() if k in ("id", "a", "b", "ids", "other_id")}
        try:
            out = fn(*args, **kwargs)
            _log.info("%s ok ids=%s bytes=%d %.1fs", fn.__name__, ids, len(json.dumps(out, default=str)), time.time() - t)
            return out
        except LoupeError as e:
            _log.info("%s error ids=%s %s", fn.__name__, ids, type(e).__name__)
            raise
        except Exception:
            _log.exception("%s crash ids=%s", fn.__name__, ids)
            raise

    return wrapper


# 도구 성격 표시. 클라이언트가 권한 확인이나 병렬 실행을 판단할 때 쓴다.
READ = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False)
CACHE_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False)
DELETE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False)


def _key(ipa: store.Ipa, binary: str | None) -> tuple[str, str]:
    path = ipa.resolve_binary(binary)
    return f"{ipa.id}/{ipa.rel(path)}", str(path)


# ── 1단계: 정적 점검 ─────────────────────────────────────────────────


@mcp.tool(annotations=CACHE_WRITE)
@_audit
def ipa_open(path: str) -> dict[str, Any]:
    """ipa 파일을 열어 캐시에 풀고 id 를 돌려준다. 이후 도구는 이 id 로 부른다.

    path: ipa 절대 경로. 허용 폴더(~/Downloads, ~/Desktop, Xcode Archives, /Users/Shared/Source) 아래여야 한다.
    """
    ipa = store.open_ipa(path)
    pl = ipa.info_plist
    return {
        "id": ipa.id,
        "bundle_id": pl.get("CFBundleIdentifier"),
        "version": f"{pl.get('CFBundleShortVersionString')} ({pl.get('CFBundleVersion')})",
        "binaries": [ipa.rel(b) for b in ipa.binaries()],
    }


@mcp.tool(annotations=READ)
@_audit
def ipa_list() -> list[dict]:
    """지금까지 열어 둔(캐시에 있는) ipa 목록."""
    return store.list_opened()


@mcp.tool(annotations=READ)
@_audit
def ipa_info(id: str) -> dict[str, Any]:
    """번들 정보, 서명·프로파일 종류(ad-hoc/development/…), 빌드 종류 추정, 메인 바이너리 요약
    (암호화·연결 라이브러리·심볼 수), 앱 안의 바이너리 목록을 보여 준다."""
    return analysis.info(store.get(id))


@mcp.tool(annotations=READ)
@_audit
def protection_check(id: str, rules: str = "liapp") -> dict[str, Any]:
    """보호 솔루션 적용 여부를 판정한다(verdict: applied / partial / not_applied)와 근거.

    rules: 판정 규칙 이름(src/loupe/rules/<이름>.yaml). 기본 liapp.
    바이너리에 SDK 문자열이 있는 것만으로는 적용으로 보지 않는다.
    """
    return analysis.protection_check(store.get(id), rules)


@mcp.tool(annotations=READ)
@_audit
def ipa_diff(a: str, b: str, samples: int = 10) -> dict[str, Any]:
    """두 ipa 를 비교한다: 추가·삭제·변경 파일, 바이너리별 섹션 바이트 변화, 바뀐 이름 수와 샘플,
    엔타이틀먼트·서명 차이. a=미적용, b=적용으로 주면 읽기 쉽다. 빌드 종류가 다르면 warnings 에 적는다."""
    return analysis.diff(store.get(a), store.get(b), samples)


@mcp.tool(annotations=READ)
@_audit
def find_strings(
    ids: list[str],
    query: str | None = None,
    regex: str | None = None,
    source_ref: str | None = None,
    scope: str = "binaries",
    max_hits: int = 5,
) -> dict[str, Any]:
    """문자열이 각 ipa 에 몇 건, 어느 파일·섹션에 있는지 찾는다(값은 원문으로 보여 준다).

    query: 찾을 문자열. regex: 바이트 정규식. source_ref: '소스경로:줄' 을 주면 그 줄의 문자열
    리터럴을 꺼내 찾는다(상대 경로는 /Users/Shared/Source/Company 기준).
    scope: main(메인 실행 파일) | binaries(모든 Mach-O, 기본) | all(리소스 포함 모든 파일).
    """
    return analysis.find_strings([store.get(i) for i in ids], query, regex, source_ref, scope, max_hits)


@mcp.tool(annotations=READ)
@_audit
def list_names(
    id: str,
    other_id: str | None = None,
    section: str = "__objc_classname",
    filter: str | None = None,
    status: str = "all",
    limit: int = 100,
) -> dict[str, Any]:
    """메인 바이너리의 클래스·메서드·프로퍼티 이름을 보여 준다.

    other_id 를 주면 두 ipa 를 짝지어 이름이 바뀌었는지(renamed) 보존됐는지(kept) 알려 준다
    (같은 빌드의 미적용/적용 쌍이어야 한다). 없으면 난독화 패턴과 닮았는지(looks_obfuscated)만 본다.
    section: __objc_classname | __objc_methname | __swift5_reflstr
    filter: 이름 정규식(대소문자 무시). status: all | kept | renamed
    """
    other = store.get(other_id) if other_id else None
    return analysis.list_names(store.get(id), other, section, filter, status, limit)


@mcp.tool(annotations=DELETE)
@_audit
def ipa_clear(id: str) -> dict[str, Any]:
    """캐시에서 이 ipa 의 압축 해제본과 Ghidra 프로젝트를 지운다. 분석 중이면 거부한다."""
    ipa = store.get(id)
    # 워커가 이 ipa 의 프로젝트를 열어 두고 있으면 먼저 닫는다(안 그러면 지운 폴더를 계속 가리킨다)
    closed = ghidra_client.call_if_running("forget", ipa_id=ipa.id)
    store.clear(ipa.id)
    return {"cleared": ipa.id, "ghidra_closed": (closed or {}).get("closed", [])}


# ── 2단계: Ghidra ───────────────────────────────────────────────────


@mcp.tool(annotations=CACHE_WRITE)
@_audit
def ghidra_analyze(id: str, binary: str = "main") -> dict[str, Any]:
    """Ghidra 분석을 백그라운드로 시작한다. 이미 분석된 바이너리는 바로 done 이다.

    binary: main(기본) | 앱 기준 상대 경로(예: Frameworks/RxSwift.framework/RxSwift) | 파일 이름.
    큰 바이너리는 수십 분 걸린다. ghidra_status 로 확인한다.
    """
    key, path = _key(store.get(id), binary)
    return ghidra_client.call("analyze", key=key, path=path)


@mcp.tool(annotations=READ)
@_audit
def ghidra_status(id: str | None = None, binary: str = "main") -> dict[str, Any]:
    """Ghidra 분석 진행 상태. id 를 생략하면 이 워커가 맡은 모든 작업을 보여 준다."""
    if id is None:
        return ghidra_client.call("status")
    key, _ = _key(store.get(id), binary)
    return ghidra_client.call("status", key=key)


@mcp.tool(annotations=READ)
@_audit
def search_functions(
    id: str, pattern: str, binary: str = "main", limit: int = 50, include_non_code: bool = False
) -> dict[str, Any]:
    """분석된 바이너리에서 이름(또는 주소)이 정규식에 맞는 함수를 찾는다.
    ObjC 메서드는 보통 'Class::selector' 꼴이다.

    기본으로 실행 가능한 블록의 함수만 센다. import 심볼 자리에 Ghidra 가 만든 가상(EXTERNAL) 항목까지
    보려면 include_non_code=true. 걸러 낸 개수는 excluded_non_code 로 준다.
    """
    limit = analysis.clamp("limit", limit, 0, 1000)
    key, _ = _key(store.get(id), binary)
    return ghidra_client.call(
        "search_functions", key=key, pattern=pattern, limit=limit, include_non_code=bool(include_non_code)
    )


@mcp.tool(annotations=READ)
@_audit
def decompile(id: str, function: str, binary: str = "main", timeout: int = 60, max_chars: int = 20000) -> dict[str, Any]:
    """함수를 C 비슷한 코드로 디컴파일한다. function: 정확한 함수 이름 또는 주소(0x…)."""
    timeout = analysis.clamp("timeout", timeout, 1, 600)
    max_chars = analysis.clamp("max_chars", max_chars, 100, 200_000)
    key, _ = _key(store.get(id), binary)
    return ghidra_client.call(
        "decompile", wait=timeout + 30, key=key, target=function, timeout=timeout, max_chars=max_chars
    )


@mcp.tool(annotations=READ)
@_audit
def compare_function(a: str, b: str, function: str, binary: str = "main", max_chars: int = 6000) -> dict[str, Any]:
    """같은 함수를 두 ipa 에서 디컴파일해 비교한다(미적용 a, 적용 b 쌍용).

    function 은 a 에서의 이름이나 주소(0x…). b 에서는 같은 주소의 함수를 쓴다 — LIAPP 처럼 코드 배치를
    바꾸지 않는 보호라면 주소가 같다. 결과: identical(완전히 같음), names_only(로직은 같고 이름만 바뀜),
    renamed(바뀐 이름 짝), diff(그 밖의 차이).
    """
    max_chars = analysis.clamp("max_chars", max_chars, 100, 100_000)
    ia, ib = store.get(a), store.get(b)
    ka, _ = _key(ia, binary)
    kb, _ = _key(ib, binary)
    ra = ghidra_client.call("decompile", wait=120, key=ka, target=function, timeout=60, max_chars=10**7)
    entry = "0x" + ra["function"]["entry"]
    rb = ghidra_client.call("decompile", wait=120, key=kb, target=entry, timeout=60, max_chars=10**7)
    cmp = analysis.compare_code(ra["code"], rb["code"])
    notes = []
    if rb["function"]["entry"] != ra["function"]["entry"]:
        notes.append("b 에서 그 주소는 다른 함수의 중간이다. 코드 배치가 달라 주소로 짝지을 수 없다")
    if rb["function"]["size"] != ra["function"]["size"]:
        notes.append(f"함수 크기가 다르다: {ra['function']['size']} vs {rb['function']['size']} 바이트")
    return {
        "a": ra["function"],
        "b": rb["function"],
        **cmp,
        "notes": notes,
        "code_a": ra["code"][:max_chars],
        "code_b": rb["code"][:max_chars],
        "truncated": max(len(ra["code"]), len(rb["code"])) > max_chars,
    }


@mcp.tool(annotations=READ)
@_audit
def xrefs(id: str, target: str, binary: str = "main", kind: str = "auto", limit: int = 50) -> dict[str, Any]:
    """target 을 참조하는 함수를 찾는다.

    target: 문자열 값 / 심볼·함수 이름 / 주소(0x…). kind: auto | string | symbol | address.
    문자열은 CFString 같은 데이터 구조를 거쳐 참조되면 한 단계 더 따라간다(via_data).
    """
    limit = analysis.clamp("limit", limit, 0, 500)
    if kind not in ("auto", "string", "symbol", "address"):
        raise LoupeError("kind 는 auto, string, symbol, address 중 하나다")
    key, _ = _key(store.get(id), binary)
    return ghidra_client.call("xrefs", key=key, target=target, kind=kind, limit=limit)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
