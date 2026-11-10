"""Ghidra 워커·서버의 JVM 없이 확인할 수 있는 부분."""

import os
import plistlib
import re
import zipfile

import pytest

from loupe import config, ghidra_client, ghidra_worker, server, store
from loupe.ghidra_worker import FuncEntry, FuncIndex


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(config, "ALLOWED_DIRS", [tmp_path.resolve()])
    return tmp_path


def _ipa(sandbox, name="a.ipa", extra=b"x" * 2_000_000):
    p = sandbox / name
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("Payload/A.app/Info.plist", plistlib.dumps({"CFBundleExecutable": "A"}))
        zf.writestr("Payload/A.app/A", b"\xcf\xfa\xed\xfe" + b"\0" * 28)
        zf.writestr("Payload/A.app/blob", extra)
    return store.open_ipa(str(p))


# ── 함수 색인 ───────────────────────────────────────────────────────────

ROWS = [
    FuncEntry("AppDelegate::application:didFinishLaunchingWithOptions:", "application:didFinishLaunchingWithOptions:", "100001000", True),
    FuncEntry("Foo::add", "add", "100002000", True),
    FuncEntry("Bar::add", "add", "100003000", True),
    FuncEntry("_objc_msgSend", "_objc_msgSend", "EXTERNAL:00000001", False),
    FuncEntry("_objc_msgSend", "_objc_msgSend", "EXTERNAL:00000002", False),
]


def test_index_search_excludes_non_code_by_default():
    idx = FuncIndex(ROWS)
    rows, total, non_code = idx.search(re.compile("objc|add", re.I), 50, False)
    assert total == 2 and non_code == 2
    assert [r.name for r in rows] == ["Foo::add", "Bar::add"]
    rows, total, non_code = idx.search(re.compile("objc", re.I), 50, True)
    assert total == 2 and non_code == 0


def test_index_search_limit_counts_all_matches():
    rows, total, _ = FuncIndex(ROWS).search(re.compile("."), 1, False)
    assert len(rows) == 1 and total == 3


def test_index_search_matches_entry_address():
    rows, total, _ = FuncIndex(ROWS).search(re.compile("100002"), 10, False)
    assert total == 1 and rows[0].name == "Foo::add"


def test_index_exact_by_full_or_short_name():
    idx = FuncIndex(ROWS)
    assert [r.entry for r in idx.exact("Foo::add")] == ["100002000"]
    assert {r.entry for r in idx.exact("add")} == {"100002000", "100003000"}
    assert len(idx.exact("_objc_msgSend")) == 2  # 이름과 짧은 이름이 같아도 두 번 세지 않는다
    assert idx.exact("nope") == []
    idx.exact("add").clear()  # 돌려준 목록을 고쳐도 색인은 그대로다
    assert len(idx.exact("add")) == 2


# ── 열린 프로그램 보호(_use) ─────────────────────────────────────────────


def test_use_marks_in_use_before_opening(monkeypatch):
    """프로그램을 받기 전에 쓰는 중 표시를 해야, 그 사이 다른 요청의 _evict 가 닫지 못한다."""
    seen = []

    def fake_program(key):
        seen.append(ghidra_worker._inuse.get(key, 0))
        return object()

    monkeypatch.setattr(ghidra_worker, "_program", fake_program)
    monkeypatch.setattr(ghidra_worker, "_evict", lambda keep=None: [])
    with ghidra_worker._use("k/x"):
        assert ghidra_worker._inuse["k/x"] == 1
    assert seen == [1]
    assert ghidra_worker._inuse["k/x"] == 0


def test_use_releases_mark_when_open_fails(monkeypatch):
    def boom(key):
        raise RuntimeError("아직 분석되지 않았다")

    monkeypatch.setattr(ghidra_worker, "_program", boom)
    with pytest.raises(RuntimeError):
        with ghidra_worker._use("k/y"):
            pass
    assert ghidra_worker._inuse["k/y"] == 0


# ── ghidra_status 는 워커를 띄우지 않는다 ─────────────────────────────────


@pytest.fixture
def no_worker(sandbox, monkeypatch):
    """워커 소켓을 임시 경로로 돌린다(실제로 떠 있는 워커에 붙지 않게).
    AF_UNIX 경로는 104바이트까지라 pytest tmp_path 는 너무 길다 → 짧은 임시 폴더를 쓴다."""
    import shutil
    import tempfile

    d = tempfile.mkdtemp(prefix="lp")
    sock = os.path.join(d, "w.sock")
    monkeypatch.setattr(ghidra_client, "SOCK", sock)
    monkeypatch.setattr(ghidra_client.time, "sleep", lambda s: None)

    def no_spawn():
        raise AssertionError("상태 조회가 워커를 띄웠다")

    monkeypatch.setattr(ghidra_client, "_spawn", no_spawn)
    yield sock
    shutil.rmtree(d, ignore_errors=True)


def test_status_without_worker_does_not_spawn(no_worker, sandbox):
    r = server.ghidra_status()
    assert r["worker"] == "not_running" and "max_open" in r  # 워커가 떠 있을 때와 같은 키

    ipa = _ipa(sandbox)
    r = server.ghidra_status(id=ipa.id)
    assert r == {"key": f"{ipa.id}/A", "state": "not_started", "worker": "not_running"}
    m = config.ghidra_marker(ipa.id, "A")
    m.parent.mkdir(parents=True)
    m.write_text("{}")
    assert server.ghidra_status(id=ipa.id)["state"] == "done"


def test_stale_socket_file_means_not_running(no_worker):
    import socket

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(no_worker))  # 파일만 남기고 듣지 않는다 = 죽은 워커가 남긴 소켓
    s.close()
    assert ghidra_client.call_if_running("status") is None


def test_busy_worker_is_not_reported_as_not_running(no_worker):
    """연결은 받지만 답이 늦는 워커를 '없다'로 보면 분석 중인 것을 not_started 로 보고한다."""
    import socket
    import threading

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(no_worker))
    srv.listen()
    conns = []
    t = threading.Thread(target=lambda: conns.append(srv.accept()), daemon=True)
    t.start()
    try:
        with pytest.raises(store.LoupeError, match="답하지 않았다"):
            ghidra_client.call_if_running("status", wait=0.3)
    finally:
        srv.close()
        for c, _ in conns:
            c.close()


def test_worker_status_has_worker_key():
    assert ghidra_worker.op_status()["worker"] == "running"


# ── 이름 조회는 필요할 때만 색인을 만든다 ────────────────────────────────


def test_address_lookup_does_not_build_index():
    class FM:
        def getFunctionContaining(self, addr):
            return f"fn@{addr:x}"

    class Space:
        def getAddress(self, n):
            return n

    class AF:
        def getDefaultAddressSpace(self):
            return Space()

    class Prog:
        def getFunctionManager(self):
            return FM()

        def getAddressFactory(self):
            return AF()

    def boom():
        raise AssertionError("주소 지정인데 색인을 만들었다")

    assert ghidra_worker._find_function(Prog(), "0x100004000", boom) == "fn@100004000"


# ── ipa_clear 는 여는 중인 프로그램도 지킨다 ─────────────────────────────


def test_forget_refuses_while_program_is_opening(monkeypatch):
    # _use 가 _inuse 를 올렸지만 아직 _programs 에는 없는(여는 중) 상태
    monkeypatch.setitem(ghidra_worker._inuse, "abc123/A", 1)
    with pytest.raises(RuntimeError, match="진행 중"):
        ghidra_worker.op_forget("abc123")


# ── ipa_list 크기 ──────────────────────────────────────────────────────


def test_ipa_list_reports_cache_size(sandbox):
    ipa = _ipa(sandbox)
    proj = config.ghidra_marker(ipa.id, "A").parent
    proj.mkdir(parents=True)
    (proj / "p.rep").write_bytes(b"\0" * 3_000_000)
    (proj / "analyzed.json").write_text("{}")
    r = store.list_opened()
    [item] = r["ipas"]
    assert item["id"] == ipa.id
    assert item["size_mb"] == 5  # 압축 해제본 2MB + Ghidra 3MB
    assert item["ghidra_mb"] == 3
    assert item["ghidra_analyzed"] == ["A"]
    assert r["total_mb"] == 5


def test_ipa_list_shows_binary_path_not_folder_name(sandbox):
    """분석된 바이너리는 binary 인자에 그대로 넣을 수 있는 상대 경로로 보여 준다(폴더 이름은 / 가 _)."""
    import json

    ipa = _ipa(sandbox)
    rel = "Frameworks/X.framework/X"
    m = config.ghidra_marker(ipa.id, rel)
    m.parent.mkdir(parents=True)
    m.write_text(json.dumps({"program": "X", "rel": rel}))
    assert m.parent.name == "Frameworks_X.framework_X"
    assert store.list_opened()["ipas"][0]["ghidra_analyzed"] == [rel]


def test_ipa_list_maps_old_marker_folder_to_binary_path(sandbox):
    """rel 을 적지 않던 예전 표시도 바이너리 목록과 맞춰 상대 경로로 보여 준다."""
    p = sandbox / "f.ipa"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("Payload/A.app/Info.plist", plistlib.dumps({"CFBundleExecutable": "A"}))
        zf.writestr("Payload/A.app/A", b"\xcf\xfa\xed\xfe" + b"\0" * 28)
        zf.writestr("Payload/A.app/Frameworks/X.framework/X", b"\xcf\xfa\xed\xfe" + b"\0" * 28)
    ipa = store.open_ipa(str(p))
    m = config.ghidra_marker(ipa.id, "Frameworks/X.framework/X")
    m.parent.mkdir(parents=True)
    m.write_text("{}")
    assert store.list_opened()["ipas"][0]["ghidra_analyzed"] == ["Frameworks/X.framework/X"]
