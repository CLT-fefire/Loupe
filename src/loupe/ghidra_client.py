"""MCP 서버 쪽에서 Ghidra 워커를 띄우고 부르는 클라이언트."""

from __future__ import annotations

import fcntl
import json
import os
import socket
import subprocess
import sys
import time

from . import config
from .store import LoupeError

SOCK = str(config.CACHE_DIR / "ghidra.sock")
START_TIMEOUT = 180


def _connect(timeout: float) -> socket.socket:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(SOCK)
    return s


def _connect_retry(timeout: float, attempts: int = 20) -> socket.socket:
    """워커가 바쁠 때 대기열이 차 연결이 거절되면(ECONNREFUSED·EAGAIN) 잠깐 기다렸다 다시 붙는다."""
    for i in range(attempts):
        try:
            return _connect(timeout)
        except (ConnectionRefusedError, BlockingIOError):
            if i == attempts - 1 or not os.path.exists(SOCK):
                raise
            time.sleep(0.05 * (i + 1))
    raise ConnectionRefusedError(SOCK)


def _ping() -> dict | None:
    """워커의 ping 응답. 응답이 없으면 None. 연결 거절은 바빠서일 수도 있으므로 몇 번 다시 시도한 뒤에만
    죽었다고 본다(한 번에 판단하면 살아 있는 워커를 두고 새 워커를 띄워 소켓을 빼앗긴다)."""
    try:
        with _connect_retry(2, attempts=8) as s:
            s.sendall(b'{"op":"ping"}\n')
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        resp = json.loads(buf)
        return resp.get("result") if resp.get("ok") else None
    except (OSError, ValueError):
        return None


def _alive() -> bool:
    return _ping() is not None


def _protocol(pong: dict) -> int:
    v = pong.get("protocol")
    return v if isinstance(v, int) else 0  # protocol 을 싣기 전 워커


def _retire_old_worker(pong: dict) -> None:
    """이 MCP 서버보다 옛 프로토콜로 떠 있는 워커를 shutdown 으로 내린다. 워커가 바쁘면 내리지 않고 알린다.

    shutdown op 가 생기기 전 워커는 진행 중인 조회 수를 알려 주지 않는다. 그래서 강제로 내리지 않는다
    (다른 세션의 조회를 끊을 수 있다). 대신 내리는 방법을 알린다. 이런 워커는 한 번만 남는다."""
    try:
        _request("shutdown", 30)
    except _NotRunning:
        return
    except LoupeError as e:
        if "모르는 op" in str(e):
            raise LoupeError(
                f"옛 버전 Ghidra 워커(pid {pong.get('pid')})가 떠 있다. 이 버전은 스스로 내려가는 요청을 몰라 "
                "자동으로 바꾸지 못한다. 다른 세션이 Ghidra 도구를 쓰고 있지 않으면 `kill <pid>` 로 내리고, "
                "아니면 30분 동안 쓰이지 않아 스스로 종료된 뒤 다시 시도한다"
            ) from e
        raise LoupeError(
            f"옛 버전 Ghidra 워커(pid {pong.get('pid')})가 작업 중이라 새 버전으로 바꾸지 못했다: {e}. "
            "끝난 뒤 다시 시도한다"
        ) from e
    deadline = time.time() + 30
    while time.time() < deadline and os.path.exists(SOCK) and _alive():
        time.sleep(0.5)


def _check_protocol(pong: dict) -> bool:
    """True 면 이 워커를 그대로 쓴다. 옛 워커면 내리고 False. 더 새 워커면(이 MCP 서버가 옛 코드로 떠 있다)
    내리지 않고 알린다 — 내리면 디스크의 새 코드로 다시 떠도 이 서버는 끝내 받아들이지 못한다."""
    v = _protocol(pong)
    if v == config.WORKER_PROTOCOL:
        return True
    if v > config.WORKER_PROTOCOL:
        raise LoupeError(
            f"Ghidra 워커(protocol {v})가 이 MCP 서버(protocol {config.WORKER_PROTOCOL})보다 새 코드다. "
            "Loupe 를 업데이트한 뒤 이 세션의 MCP 서버가 옛 코드로 떠 있는 것이다. 세션(또는 MCP 서버)을 다시 시작한다"
        )
    _retire_old_worker(pong)
    return False


def ensure_worker() -> None:
    pong = _ping()
    if pong is not None and _check_protocol(pong):
        return
    # MCP 서버가 여럿(세션 여러 개)이면 동시에 워커를 띄우려 할 수 있다 → 파일 잠금으로 한 번만 띄운다
    config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with open(config.CACHE_DIR / "ghidra.spawn.lock", "w") as lockf:
        fcntl.flock(lockf, fcntl.LOCK_EX)
        try:
            pong = _ping()
            if pong is not None and _check_protocol(pong):
                return
            _spawn()
        finally:
            fcntl.flock(lockf, fcntl.LOCK_UN)


def _spawn() -> None:
    if not (config.GHIDRA_INSTALL_DIR / "support" / "analyzeHeadless").exists():
        raise LoupeError(
            f"Ghidra 설치를 찾지 못했다: {config.GHIDRA_INSTALL_DIR}. "
            "`brew install ghidra` 후 GHIDRA_INSTALL_DIR 를 <prefix>/libexec 로 지정한다."
        )
    _launch()
    relaunched = False
    deadline = time.time() + START_TIMEOUT
    while time.time() < deadline:
        pong = _ping()
        if pong is not None:
            if _protocol(pong) == config.WORKER_PROTOCOL:
                return
            # 더 새 워커면 세션 재시작 안내를 내고, 옛 워커면(바빠서 앞의 ping 을 놓쳤다) 내리거나 내리는 방법을
            # 알린다. 새로 띄운 워커는 옛 워커가 소켓을 쥐고 있어 곧바로 물러났으므로, 옛 워커를 내렸으면 한 번 더 띄운다
            if not _check_protocol(pong) and not relaunched:
                _launch()
                relaunched = True
        time.sleep(1)
    raise LoupeError(f"Ghidra 워커가 {START_TIMEOUT}초 안에 뜨지 않았다. 로그: {config.CACHE_DIR / 'ghidra-worker.log'}")


def _launch() -> None:
    config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    log = open(config.CACHE_DIR / "ghidra-worker.log", "ab")
    env = dict(os.environ, GHIDRA_INSTALL_DIR=str(config.GHIDRA_INSTALL_DIR))
    subprocess.Popen(
        [sys.executable, "-m", "loupe.ghidra_worker", SOCK],
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,  # MCP 서버가 끝나도 분석은 계속한다(유휴 30분 뒤 스스로 종료)
        env=env,
    )


class _NotRunning(Exception):
    """소켓에 붙지 못했다(소켓 파일이 없거나 여러 번 거절됨) = 워커가 없다."""


def call_if_running(op: str, wait: float = 60, **args) -> dict | None:
    """워커가 떠 있을 때만 부른다(워커를 새로 띄우지 않는다). 없으면 None.

    ping 응답(2초)으로 판단하지 않는다 — 바쁜 워커가 늦게 답하면 '없다'로 오판한다. 연결이 되면
    떠 있는 것이고, 응답이 늦으면 call 과 같이 오류로 알린다."""
    if not os.path.exists(SOCK):
        return None
    try:
        return _request(op, wait, **args)
    except _NotRunning:
        return None


def call(op: str, wait: float = 300, **args) -> dict:
    """op 를 부르고 결과를 기다린다. wait 는 응답을 기다리는 최대 초(소켓 타임아웃)."""
    ensure_worker()
    try:
        return _request(op, wait, **args)
    except _NotRunning as e:
        raise LoupeError(f"Ghidra 워커와 통신하지 못했다({op}): {e.__cause__}") from e


def _request(op: str, wait: float, **args) -> dict:
    try:
        s = _connect_retry(wait)
    except (FileNotFoundError, ConnectionRefusedError, BlockingIOError) as e:
        raise _NotRunning() from e
    try:
        with s:
            s.sendall((json.dumps({"op": op, **args}) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(1 << 16)
                if not chunk:
                    break
                buf += chunk
    except TimeoutError as e:
        raise LoupeError(f"Ghidra 워커가 {wait:.0f}초 안에 답하지 않았다({op}). ghidra_status 로 상태를 확인한다.") from e
    except OSError as e:
        raise LoupeError(f"Ghidra 워커와 통신하지 못했다({op}): {e}") from e
    if not buf:
        raise LoupeError(f"Ghidra 워커가 응답 없이 연결을 끊었다({op}). 로그: {config.CACHE_DIR / 'ghidra-worker.log'}")
    try:
        resp = json.loads(buf)
    except ValueError as e:
        raise LoupeError(f"Ghidra 워커 응답이 중간에 끊겼다({op}). 워커가 죽었을 수 있다. 다시 시도하면 새로 뜬다.") from e
    if not resp["ok"]:
        raise LoupeError(resp["error"])
    return resp["result"]
