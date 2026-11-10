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


def _alive() -> bool:
    """워커가 응답하는지. 연결 거절은 바빠서일 수도 있으므로 몇 번 다시 시도한 뒤에만 죽었다고 본다
    (한 번에 판단하면 살아 있는 워커를 두고 새 워커를 띄워 소켓을 빼앗긴다)."""
    try:
        with _connect_retry(2, attempts=8) as s:
            s.sendall(b'{"op":"ping"}\n')
            return b'"ok": true' in s.recv(4096)
    except OSError:
        return False


def ensure_worker() -> None:
    if _alive():
        return
    # MCP 서버가 여럿(세션 여러 개)이면 동시에 워커를 띄우려 할 수 있다 → 파일 잠금으로 한 번만 띄운다
    config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with open(config.CACHE_DIR / "ghidra.spawn.lock", "w") as lockf:
        fcntl.flock(lockf, fcntl.LOCK_EX)
        try:
            if _alive():
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
    deadline = time.time() + START_TIMEOUT
    while time.time() < deadline:
        if _alive():
            return
        time.sleep(1)
    raise LoupeError(f"Ghidra 워커가 {START_TIMEOUT}초 안에 뜨지 않았다. 로그: {config.CACHE_DIR / 'ghidra-worker.log'}")


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
