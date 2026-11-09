"""Ghidra 워커 프로세스.

MCP 서버(stdio)와 같은 프로세스에서 JVM 을 띄우면 Ghidra 로그가 stdout 을 더럽혀
MCP 통신이 깨진다. 그래서 별도 프로세스로 띄우고 유닉스 소켓(JSON 한 줄씩)으로 통신한다.
stdout/stderr 는 띄운 쪽(ghidra_client)이 로그 파일로 돌린다.

실행: python -m loupe.ghidra_worker <socket 경로>
"""

from __future__ import annotations

import json
import os
import queue
import re
import socketserver
import sys
import threading
import time
import traceback
from pathlib import Path

from . import config

IDLE_SECONDS = int(os.environ.get("LOUPE_GHIDRA_IDLE", "1800"))
XMX = os.environ.get("LOUPE_GHIDRA_XMX", "8g")
MAX_OPEN = max(1, int(os.environ.get("LOUPE_GHIDRA_MAX_OPEN", "3")))  # 메모리에 열어 둘 프로그램 수
STUB_CALLERS_LIMIT = 30  # objc_stub 하나당 따라가 볼 호출부 수

_lock = threading.RLock()
_jobs: dict[str, dict] = {}  # key = "<ipa_id>/<rel>"
_main_q: "queue.Queue" = queue.Queue()  # 메인 스레드가 실행할 함수(지금은 분석뿐)
_pending: list[str] = []  # 분석 대기 중인 key (순서 = 대기 순서)
_projects: dict[str, object] = {}  # key -> GhidraProject
_programs: dict[str, object] = {}  # key -> Program
_key_locks: dict[str, threading.Lock] = {}  # 바이너리별 열기 잠금(큰 프로그램을 여는 동안 다른 바이너리를 막지 않게)
_inuse: dict[str, int] = {}  # key -> 지금 쓰고 있는 요청 수
_last_used: dict[str, float] = {}
_last_activity = time.time()


def _log(msg: str) -> None:
    print(f"[loupe-worker {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _project_dir(ipa_id: str, rel: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", rel)
    return config.CACHE_DIR / ipa_id / "ghidra" / safe


def _marker(ipa_id: str, rel: str) -> Path:
    return _project_dir(ipa_id, rel) / "analyzed.json"


# ── 분석 ───────────────────────────────────────────────────────────────


def _open_project(key: str, ipa_id: str, rel: str):
    from ghidra.base.project import GhidraProject

    with _lock:
        if key in _projects:
            return _projects[key]
    d = _project_dir(ipa_id, rel)
    d.mkdir(parents=True, exist_ok=True)
    if (d / "p.gpr").exists():
        proj = GhidraProject.openProject(str(d), "p", True)
    else:
        proj = GhidraProject.createProject(str(d), "p", False)
    with _lock:
        _projects[key] = proj
    return proj


def _key_lock(key: str) -> threading.Lock:
    with _lock:
        return _key_locks.setdefault(key, threading.Lock())


def _program(key: str):
    """분석이 끝난 프로그램을 연다(메모리에 유지).

    프로젝트 열기는 메인 스레드가 아니어도 된다(워밍업 뒤 실측 정상). 메인 스레드는 분석이
    수십 분 붙잡고 있을 수 있으므로 조회 스레드에서 바로 연다. 같은 바이너리를 두 번 열지 않도록
    바이너리별 잠금을 쓰고, 전역 잠금은 오래 붙잡지 않는다."""
    with _lock:
        if key in _programs:
            return _programs[key]
    ipa_id, rel = key.split("/", 1)
    if not _marker(ipa_id, rel).exists():
        job = _jobs.get(key)
        state = job["state"] if job else "없음"
        raise RuntimeError(f"아직 분석되지 않았다(상태: {state}). analyze 를 먼저 호출하고 끝날 때까지 기다린다.")
    with _key_lock(key):
        with _lock:
            if key in _programs:
                return _programs[key]
        proj = _open_project(key, ipa_id, rel)
        name = json.loads(_marker(ipa_id, rel).read_text())["program"]
        prog = proj.openProgram("/", name, False)
        with _lock:
            _programs[key] = prog
        return prog


def _close(key: str) -> None:
    """프로그램과 프로젝트를 닫는다. 호출하는 쪽이 _lock 을 잡고 있어야 한다."""
    proj = _projects.pop(key, None)
    _programs.pop(key, None)
    _last_used.pop(key, None)
    if proj is not None:
        try:
            proj.close()  # GhidraProject.close() 는 열린 프로그램도 닫는다
        except Exception as e:
            _log(f"프로젝트 닫기 실패: {type(e).__name__}")


def _evict(keep: str | None = None) -> list[str]:
    """열린 프로그램이 MAX_OPEN 을 넘으면 가장 오래 안 쓴 것부터 닫는다. 쓰는 중이거나 분석 중인 것은 두고."""
    closed = []
    with _lock:
        while len(_programs) > MAX_OPEN:
            busy = {k for k, j in _jobs.items() if j["state"] in ("queued", "running")}
            idle = [k for k in _programs if k != keep and _inuse.get(k, 0) == 0 and k not in busy]
            if not idle:
                break
            victim = min(idle, key=lambda k: _last_used.get(k, 0.0))
            _close(victim)
            closed.append(victim)
    for k in closed:
        _log(f"메모리 확보로 닫음: {k}")
    return closed


class _use:
    """with _use(key) as prog: 동안 그 프로그램이 닫히지 않게 표시한다."""

    def __init__(self, key: str):
        self.key = key

    def __enter__(self):
        prog = _program(self.key)
        with _lock:
            _inuse[self.key] = _inuse.get(self.key, 0) + 1
            _last_used[self.key] = time.time()
        _evict(keep=self.key)
        return prog

    def __exit__(self, *exc):
        with _lock:
            _inuse[self.key] = max(0, _inuse.get(self.key, 0) - 1)
            _last_used[self.key] = time.time()
        # 들어올 때는 다른 요청이 쓰고 있어 못 닫았을 수 있으므로 끝날 때도 정리한다
        _evict()
        return False


def _analyze(key: str) -> None:
    import pyghidra
    from java.io import File

    job = _jobs[key]
    ipa_id, rel = key.split("/", 1)
    path = Path(job["path"])
    with _lock:
        if key in _pending:
            _pending.remove(key)
    job.update(state="running", started=time.time())
    _log(f"분석 시작 {key}")
    try:
        proj = _open_project(key, ipa_id, rel)
        name = path.name
        prog = proj.getRootFolder().getFile(name)
        if prog is None:
            program = proj.importProgram(File(str(path)))
            if program is None:
                raise RuntimeError("Ghidra 가 이 파일을 불러오지 못했다")
            proj.saveAs(program, "/", name, True)
        else:
            program = proj.openProgram("/", name, False)
        job["phase"] = "auto-analysis"
        pyghidra.analyze(program)
        proj.save(program)
        finished = time.time()
        _marker(ipa_id, rel).write_text(
            json.dumps(
                {"program": name, "finished": finished, "seconds": round(finished - job["started"]), "size": path.stat().st_size}
            )
        )
        with _lock:
            _programs[key] = program
            _last_used[key] = finished
        job.update(state="done", finished=finished, phase=None)
        _log(f"분석 끝 {key} ({finished - job['started']:.0f}s)")
        _evict(keep=key)
    except Exception as e:
        job.update(state="error", finished=time.time(), error=f"{type(e).__name__}: {e}")
        _log(f"분석 실패 {key}\n{traceback.format_exc()}")


_stop = threading.Event()


def _main_loop() -> None:
    """메인 스레드에서 돈다. macOS 에서 Ghidra 의 프로젝트 생성·자동 분석은 메인 스레드가 아니면
    CPU 0% 로 멈춘다(2026-11-09 실측). 그래서 분석은 메인 스레드가 하고, 소켓과 조회(프로젝트 열기·
    디컴파일·참조 추적 — 워밍업 뒤에는 다른 스레드에서도 정상)는 별도 스레드가 맡는다."""
    while not _stop.is_set():
        try:
            fn = _main_q.get(timeout=1)
        except queue.Empty:
            continue
        try:
            fn()
        except Exception:
            _log(traceback.format_exc())


# ── 조회 ───────────────────────────────────────────────────────────────


def _func_info(f) -> dict:
    return {
        "name": str(f.getName(True)),
        "entry": str(f.getEntryPoint()),
        "size": int(f.getBody().getNumAddresses()),
    }


def _find_function(prog, target: str):
    """함수 이름 또는 주소로 찾는다. 주소는 0x 를 붙여야 확실하다.

    'add', 'fade' 처럼 16진수 글자로만 된 이름이 주소로 오해되지 않게, 0x 가 없으면 이름을 먼저 찾는다.
    """
    fm = prog.getFunctionManager()
    space = prog.getAddressFactory().getDefaultAddressSpace()

    def by_address(text: str):
        f = fm.getFunctionContaining(space.getAddress(int(text, 16)))
        if f is None:
            raise RuntimeError(f"주소 {text} 를 포함하는 함수가 없다")
        return f

    if re.fullmatch(r"0x[0-9a-fA-F]+", target):
        return by_address(target)
    exact = [f for f in fm.getFunctions(True) if str(f.getName(True)) == target or str(f.getName()) == target]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        raise RuntimeError(f"이름이 같은 함수가 {len(exact)}개다. 주소(0x…)로 지정한다: {[str(f.getEntryPoint()) for f in exact[:10]]}")
    if re.fullmatch(r"[0-9a-fA-F]{6,}", target):  # 이름이 없고 주소처럼 생겼으면 주소로 한 번 더
        return by_address(target)
    raise RuntimeError("그 이름의 함수가 없다. search_functions 로 정확한 이름을 찾는다.")


def op_search_functions(key: str, pattern: str, limit: int = 50, include_non_code: bool = False) -> dict:
    """이름(또는 주소)이 정규식에 맞는 함수.

    기본으로 실행 가능한 메모리 블록(__text 등)의 함수만 센다. Ghidra 는 import 심볼 자리에도
    가상 EXTERNAL 블록에 1바이트짜리 '함수'를 만든다 — 재서명으로 바인딩 정보 형식이 바뀐 LIAPP
    적용본에서는 같은 심볼이 바인딩 자리마다 하나씩(예: 303개) 생겨 개수 비교를 망친다(2026-11-09 실측).
    """
    rx = re.compile(pattern, re.I)
    with _use(key) as prog:
        return _search_functions(prog, rx, limit, include_non_code)


def _search_functions(prog, rx, limit: int, include_non_code: bool) -> dict:
    mem = prog.getMemory()
    out, total, non_code = [], 0, 0
    for f in prog.getFunctionManager().getFunctions(True):
        name = str(f.getName(True))
        if not (rx.search(name) or rx.search(str(f.getEntryPoint()))):
            continue
        block = mem.getBlock(f.getEntryPoint())
        is_code = block is not None and block.isExecute()
        if not is_code and not include_non_code:
            non_code += 1
            continue
        total += 1
        if len(out) < limit:
            info = _func_info(f)
            if not is_code:
                info["block"] = str(block.getName()) if block else None
            out.append(info)
    result = {"matched": total, "functions": out}
    if non_code:
        result["excluded_non_code"] = non_code
    return result


def op_decompile(key: str, target: str, timeout: int = 60, max_chars: int = 20000) -> dict:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    with _use(key) as prog:
        f = _find_function(prog, target)
        ifc = DecompInterface()
        try:
            ifc.openProgram(prog)
            res = ifc.decompileFunction(f, int(timeout), ConsoleTaskMonitor())
            if not res.decompileCompleted():
                raise RuntimeError(f"디컴파일 실패: {res.getErrorMessage()}")
            code = str(res.getDecompiledFunction().getC())
        finally:
            ifc.dispose()
    truncated = len(code) > max_chars
    return {"function": _func_info(f), "truncated": truncated, "code": code[:max_chars]}


def _is_objc_stub(f) -> bool:
    ns = f.getParentNamespace()
    return ns is not None and str(ns.getName()) == "objc_stub"


def _stub_callers(prog, stub, limit: int) -> tuple[list[dict], int]:
    """objc_stub 함수를 부르는 실제 함수들. (목록, 전체 호출부 수)"""
    fm = prog.getFunctionManager()
    out, total = [], 0
    for ref in prog.getReferenceManager().getReferencesTo(stub.getEntryPoint()):
        if not ref.getReferenceType().isCall():
            continue
        total += 1
        if len(out) >= limit:
            continue
        frm = ref.getFromAddress()
        f = fm.getFunctionContaining(frm)
        out.append({"from": str(frm), "function": str(f.getName(True)) if f else None})
    return out, total


def _refs_to(prog, addr, limit: int, hop: int = 0) -> list[dict]:
    """addr 를 참조하는 곳.

    - 데이터(예: CFString 구조체, 셀렉터 참조)에서 오는 참조는 한 단계 더 따라간다(via_data).
    - 참조하는 곳이 objc_stub 함수(ObjC 메시지 전송용 작은 함수)면, 그 stub 을 부르는 실제
      함수 목록(callers)을 붙인다. ObjC 셀렉터 문자열의 실제 사용처는 대부분 여기 있다.
    """
    rm = prog.getReferenceManager()
    fm = prog.getFunctionManager()
    listing = prog.getListing()
    out = []
    for ref in rm.getReferencesTo(addr):
        if len(out) >= limit:
            break
        frm = ref.getFromAddress()
        f = fm.getFunctionContaining(frm)
        if f is not None:
            entry = {"from": str(frm), "function": str(f.getName(True)), "type": str(ref.getReferenceType())}
            if _is_objc_stub(f):
                callers, total = _stub_callers(prog, f, STUB_CALLERS_LIMIT)
                entry["callers_total"] = total
                entry["callers"] = callers
            out.append(entry)
        elif hop == 0:
            data = listing.getDataContaining(frm)
            start = data.getMinAddress() if data is not None else frm
            for sub in _refs_to(prog, start, limit - len(out), hop + 1):
                sub["via_data"] = str(start)
                out.append(sub)
        else:
            out.append({"from": str(frm), "function": None, "type": str(ref.getReferenceType())})
    # 같은 위치가 참조 종류(READ·PARAM 등)만 달리 여러 번 나오면 하나로 합친다
    merged: dict[tuple, dict] = {}
    for e in out:
        k = (e["from"], e.get("function"))
        if k not in merged:
            merged[k] = e
            continue
        m = merged[k]
        types = set(m["type"].split(", ")) | {e["type"]}
        m["type"] = ", ".join(sorted(types))
        m.setdefault("via_data", e.get("via_data"))
        if m.get("via_data") is None:
            m.pop("via_data")
    return list(merged.values())


def op_xrefs(key: str, target: str, kind: str = "auto", limit: int = 50) -> dict:
    with _use(key) as prog:
        return _xrefs(prog, target, kind, limit)


def _xrefs(prog, target: str, kind: str, limit: int) -> dict:
    mem = prog.getMemory()
    space = prog.getAddressFactory().getDefaultAddressSpace()
    targets = []

    if kind in ("auto", "address") and re.fullmatch(r"0x[0-9a-fA-F]+", target):
        targets.append(("address", space.getAddress(int(target, 16))))
    if kind in ("auto", "symbol") and not targets:
        for s in prog.getSymbolTable().getSymbols(target):
            targets.append(("symbol", s.getAddress()))
        for f in prog.getFunctionManager().getFunctions(True):
            if str(f.getName(True)) == target and ("symbol", f.getEntryPoint()) not in targets:
                targets.append(("symbol", f.getEntryPoint()))
    if kind in ("auto", "string") and not targets:
        from jpype import JArray, JByte

        jb = JArray(JByte)(target.encode("utf-8"))
        start = mem.getMinAddress()
        while start is not None and len(targets) < 20:
            hit = mem.findBytes(start, jb, None, True, None)
            if hit is None:
                break
            targets.append(("string", hit))
            start = hit.add(1)
    if not targets:
        raise RuntimeError(f"'{target}' 를 주소·심볼·문자열 어느 것으로도 찾지 못했다")

    results = []
    for k, addr in targets[:20]:
        block = mem.getBlock(addr)
        results.append(
            {
                "kind": k,
                "address": str(addr),
                "block": str(block.getName()) if block else None,
                "references": _refs_to(prog, addr, limit),
            }
        )
    return {"target": target, "matches": results}


# ── 서버 ───────────────────────────────────────────────────────────────


def op_analyze(key: str, path: str) -> dict:
    ipa_id, rel = key.split("/", 1)
    with _lock:
        if _marker(ipa_id, rel).exists():
            return {"state": "done", "cached": True}
        job = _jobs.get(key)
        if job and job["state"] in ("queued", "running"):
            return _status_one(key)
        _jobs[key] = {"state": "queued", "path": path, "queued": time.time()}
        _pending.append(key)
        _main_q.put(lambda k=key: _analyze(k))
    return _status_one(key)


DEFAULT_SEC_PER_MB = 23.0  # 2026-11-09 실측: 26.5MB 메인 바이너리 608~629초


def _sec_per_mb() -> float:
    """지난 분석 기록(analyzed.json)으로 MB 당 분석 시간을 추정한다."""
    rates = []
    for m in config.CACHE_DIR.glob("*/ghidra/*/analyzed.json"):
        try:
            d = json.loads(m.read_text())
            if d.get("seconds") and d.get("size", 0) > 1_000_000:  # 작은 파일은 고정비가 커서 뺀다
                rates.append(d["seconds"] / (d["size"] / 1e6))
        except Exception:
            continue
    if not rates:
        return DEFAULT_SEC_PER_MB
    rates.sort()
    return rates[len(rates) // 2]


def _status_one(key: str) -> dict:
    ipa_id, rel = key.split("/", 1)
    job = _jobs.get(key)
    if job is None:
        return {"key": key, "state": "done" if _marker(ipa_id, rel).exists() else "not_started"}
    # 메인 스레드가 job 을 바꾸는 중일 수 있으므로 값은 한 번씩만 읽는다
    state, started, finished = job["state"], job.get("started"), job.get("finished")
    out = {"key": key, "state": state}
    elapsed = round((finished or time.time()) - started) if started else None
    if elapsed is not None:
        out["elapsed_s"] = elapsed
    for k in ("phase", "error"):
        v = job.get(k)
        if v:
            out[k] = v
    if state in ("queued", "running"):
        try:
            mb = Path(job["path"]).stat().st_size / 1e6
            est = round(mb * _sec_per_mb())
            out["estimated_total_s"] = est
            if elapsed is not None:
                out["estimated_remaining_s"] = max(0, est - elapsed)
            out["estimate_note"] = "지난 분석 속도로 낸 대략값"
        except OSError:
            pass
    if state == "queued":
        with _lock:
            if key in _pending:  # 없으면 메인 스레드가 막 꺼내 시작하는 중이다
                out["queue_position"] = _pending.index(key) + 1
    return out


def op_status(key: str | None = None) -> dict:
    if key:
        return _status_one(key)
    with _lock:
        keys = list(_jobs)
        open_programs = sorted(_programs, key=lambda k: -_last_used.get(k, 0.0))
    return {"jobs": [_status_one(k) for k in keys], "open_programs": open_programs, "max_open": MAX_OPEN}


def op_forget(ipa_id: str) -> dict:
    """ipa_clear 전에 부른다. 이 ipa 의 열린 프로그램·프로젝트를 닫고 작업 기록을 지운다."""
    prefix = f"{ipa_id}/"
    with _lock:
        busy = [k for k, j in _jobs.items() if k.startswith(prefix) and j["state"] in ("queued", "running")]
        if busy:
            raise RuntimeError(f"분석 중이라 지울 수 없다: {busy}. 끝난 뒤 다시 시도한다.")
        if any(_inuse.get(k, 0) for k in _programs if k.startswith(prefix)):
            raise RuntimeError("이 ipa 를 조회하는 요청이 진행 중이다. 끝난 뒤 다시 시도한다.")
        closed = sorted({k for k in list(_programs) + list(_projects) if k.startswith(prefix)})
        for k in closed:
            _close(k)
        for k in [k for k in _jobs if k.startswith(prefix)]:
            _jobs.pop(k)
    return {"closed": closed}


OPS = {
    "forget": op_forget,
    "ping": lambda: {"ok": True, "pid": os.getpid()},
    "analyze": op_analyze,
    "status": op_status,
    "search_functions": op_search_functions,
    "decompile": op_decompile,
    "xrefs": op_xrefs,
}


_EXPECTED = (RuntimeError, ValueError, KeyError, TypeError, FileNotFoundError, re.error)
_inflight = 0


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        global _last_activity, _inflight
        for line in self.rfile:
            _last_activity = time.time()
            with _lock:
                _inflight += 1
            op = "?"
            try:
                req = json.loads(line)
                op = str(req.pop("op", "?"))
                fn = OPS.get(op)
                if fn is None:
                    raise ValueError(f"모르는 op: {op}")
                resp = {"ok": True, "result": fn(**req)}
            except Exception as e:
                resp = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                # 로그에는 사용자가 넣은 값(검색어·키일 수 있다)이 든 예외 메시지를 남기지 않는다
                if isinstance(e, _EXPECTED):
                    _log(f"{op} 실패: {type(e).__name__}")
                else:
                    _log(f"{op} 예외: {type(e).__name__}\n" + "".join(traceback.format_tb(e.__traceback__)))
            finally:
                with _lock:
                    _inflight -= 1
                _last_activity = time.time()
            self.wfile.write((json.dumps(resp, ensure_ascii=False) + "\n").encode())
            self.wfile.flush()


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    # 기본 대기열(5)이면 병렬 도구 호출이 몰릴 때 연결이 거절된다(2026-11-09 실측: 12개 중 4개 ECONNREFUSED)
    request_queue_size = 128


def _idle_watch(server: Server) -> None:
    while True:
        time.sleep(30)
        try:
            with _lock:
                busy = _inflight > 0 or any(j["state"] in ("queued", "running") for j in list(_jobs.values()))
        except Exception:  # 감시 스레드가 죽으면 워커가 영영 안 내려가므로 삼킨다
            _log("유휴 감시 오류\n" + traceback.format_exc())
            continue
        if not busy and time.time() - _last_activity > IDLE_SECONDS:
            _log("유휴 시간 초과로 종료")
            server.shutdown()
            _stop.set()
            return


def _warm_up() -> None:
    """macOS 에서 첫 GhidraProject 생성이 메인 스레드가 아니면 영영 멈춘다(2026-11-09 실측:
    분석 스레드에서 createProject 가 CPU 0% 로 대기). 메인 스레드에서 한 번 만들어 두면
    이후 다른 스레드의 호출은 정상이다."""
    import shutil

    from ghidra.base.project import GhidraProject

    d = config.CACHE_DIR / f"_warmup-{os.getpid()}"  # 워커가 둘 떠도 서로 지우지 않게
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    GhidraProject.createProject(str(d), "w", True).close()  # temporary=True
    shutil.rmtree(d, ignore_errors=True)
    _log("메인 스레드 워밍업 완료")


def main() -> None:
    import faulthandler
    import signal

    faulthandler.register(signal.SIGUSR1, all_threads=True)  # kill -USR1 <pid> 로 스택을 로그에 남긴다
    sock = sys.argv[1]
    if os.path.exists(sock):
        # 이미 살아 있는 워커가 있으면 그 소켓을 빼앗지 않고 물러난다(빼앗으면 그 워커는 고아가 된다)
        import socket as _s

        alive = False
        for i in range(8):  # 살아 있지만 바쁜 워커는 잠깐 연결을 거절할 수 있다
            probe = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
            probe.settimeout(2)
            try:
                probe.connect(sock)
                alive = True
                break
            except OSError:
                time.sleep(0.1 * (i + 1))
            finally:
                probe.close()
        if alive:
            _log("다른 워커가 이미 소켓을 쓰고 있어 종료한다")
            return
        os.unlink(sock)  # 여러 번 시도해도 응답이 없다 = 죽은 워커가 남긴 소켓 파일
    import pyghidra
    from pyghidra.launcher import HeadlessPyGhidraLauncher

    launcher = HeadlessPyGhidraLauncher(install_dir=config.GHIDRA_INSTALL_DIR)
    launcher.add_vmargs(f"-Xmx{XMX}")
    launcher.start()
    assert pyghidra.started()
    _log(f"JVM 시작 완료 (Ghidra {config.GHIDRA_INSTALL_DIR})")
    _warm_up()

    old = os.umask(0o077)
    server = Server(sock, Handler)
    os.umask(old)
    my_inode = os.stat(sock).st_ino
    threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=_idle_watch, args=(server,), daemon=True).start()
    _log(f"소켓 대기 {sock}")
    try:
        _main_loop()
    finally:
        # 내가 만든 소켓일 때만 지운다(다른 워커가 이어받은 소켓을 지우지 않게)
        try:
            if os.stat(sock).st_ino == my_inode:
                os.unlink(sock)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
