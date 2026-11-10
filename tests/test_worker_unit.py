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


# ── 워커 인자 재검사 ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "req",
    [
        {"key": "abc123/../../etc/passwd"},
        {"key": "abc123//x"},
        {"key": "abc123/./A"},
        {"key": "ABC/x"},  # id 는 소문자 16진수
        {"key": "abc123"},  # 경로가 없다
        {"key": 5},
        {"ipa_id": "../x"},
    ],
)
def test_check_args_rejects(req):
    with pytest.raises(ValueError):
        ghidra_worker.check_args(req)


def test_check_args_accepts_normal_keys():
    ghidra_worker.check_args({"key": "85790996ee7f/Fork_Stars"})
    ghidra_worker.check_args({"key": "85790996ee7f/Frameworks/X.framework/X", "ipa_id": "85790996ee7f"})


def test_analyze_rejects_path_outside_ipa_cache(sandbox, tmp_path_factory):
    ipa = _ipa(sandbox)
    outside = tmp_path_factory.mktemp("o") / "A"
    outside.write_bytes(b"x")
    with pytest.raises(ValueError, match="허용되지 않는 경로"):
        ghidra_worker.op_analyze(f"{ipa.id}/A", str(outside))
    # 캐시 안이어도 key 의 바이너리와 다른 파일이면 거부한다
    with pytest.raises(ValueError, match="허용되지 않는 경로"):
        ghidra_worker.op_analyze(f"{ipa.id}/A", str(ipa.app / "blob"))
    # 이름이 같은 다른 위치(appex 안 같은 이름 프레임워크 등)도 거부한다 — 앱 위치는 meta.json 기준
    other = ipa.root / "x" / "Payload" / "Other" / "A"
    other.parent.mkdir(parents=True)
    other.write_bytes(b"x")
    with pytest.raises(ValueError, match="허용되지 않는 경로"):
        ghidra_worker.op_analyze(f"{ipa.id}/A", str(other))
    with pytest.raises(ValueError, match="열린 ipa 가 아니다"):
        ghidra_worker.op_analyze("abcdef123456/A", str(outside))
    assert ghidra_worker._jobs.get(f"{ipa.id}/A") is None


def test_check_args_checks_other_key():
    with pytest.raises(ValueError, match="other_key"):
        ghidra_worker.check_args({"key": "abc123/A", "other_key": "abc123/../A"})


# ── 분석 프로필 ──────────────────────────────────────────────────────────


def test_analyze_rejects_unknown_profile(sandbox):
    ipa = _ipa(sandbox)
    with pytest.raises(ValueError, match="profile"):
        ghidra_worker.op_analyze(f"{ipa.id}/A", str(ipa.app / "A"), profile="turbo")


def test_cached_analysis_reports_its_profile(sandbox):
    import json

    ipa = _ipa(sandbox)
    m = config.ghidra_marker(ipa.id, "A")
    m.parent.mkdir(parents=True)
    m.write_text(json.dumps({"program": "A", "rel": "A", "profile": "fast"}))
    r = ghidra_worker.op_analyze(f"{ipa.id}/A", str(ipa.app / "A"), profile="full")
    assert (r["state"], r["cached"], r["profile"]) == ("done", True, "fast")
    assert "ipa_clear" in r["note"]  # 다른 프로필로 다시 분석하는 방법을 알려 준다
    assert "note" not in ghidra_worker.op_analyze(f"{ipa.id}/A", str(ipa.app / "A"), profile="fast")


def test_estimate_uses_same_profile_only(sandbox):
    import json

    for i, (prof, secs) in enumerate([("full", 2000), ("fast", 1000)]):
        d = config.CACHE_DIR / f"{i:012x}" / "ghidra" / "A"
        d.mkdir(parents=True)
        (d / "analyzed.json").write_text(json.dumps({"seconds": secs, "size": 100_000_000, "profile": prof}))
    assert ghidra_worker._sec_per_mb("full") == 20.0
    assert ghidra_worker._sec_per_mb("fast") == 10.0


def test_profiles_never_disable_switch_analysis():
    """Switch Analysis 를 끄면 case 블록 명령어가 해독되지 않아 xrefs 가 빠진다(2026-11-10 실측 -1.6%)."""
    assert all("Decompiler Switch Analysis" not in v for v in ghidra_worker.PROFILES.values())


# ── 옛 워커 교체(프로토콜) ───────────────────────────────────────────────


def test_shutdown_refuses_while_busy_and_stops_when_idle(monkeypatch):
    import threading

    stop = threading.Event()
    monkeypatch.setattr(ghidra_worker, "_stop", stop)
    monkeypatch.setattr(ghidra_worker, "_server_ref", [])
    monkeypatch.setitem(ghidra_worker._jobs, "abc123/A", {"state": "running"})
    with pytest.raises(RuntimeError, match="진행 중"):
        ghidra_worker.op_shutdown()
    assert not stop.is_set()
    ghidra_worker._jobs.pop("abc123/A")
    assert ghidra_worker.op_shutdown()["stopping"] is True and stop.is_set()


def test_ensure_worker_replaces_old_protocol(no_worker, monkeypatch):
    calls = []
    pongs = iter([{"pid": 1, "protocol": config.WORKER_PROTOCOL - 1}, None, {"pid": 2, "protocol": config.WORKER_PROTOCOL}])
    monkeypatch.setattr(ghidra_client, "_ping", lambda: next(pongs, {"pid": 2, "protocol": config.WORKER_PROTOCOL}))
    monkeypatch.setattr(ghidra_client, "_retire_old_worker", lambda pong: calls.append(("retire", pong["pid"])))
    monkeypatch.setattr(ghidra_client, "_spawn", lambda: calls.append(("spawn",)))
    ghidra_client.ensure_worker()
    assert calls == [("retire", 1), ("spawn",)]


def test_ensure_worker_keeps_current_protocol(no_worker, monkeypatch):
    monkeypatch.setattr(ghidra_client, "_ping", lambda: {"pid": 2, "protocol": config.WORKER_PROTOCOL})
    ghidra_client.ensure_worker()  # no_worker 의 _spawn 은 불리면 실패한다


def test_pre_protocol_worker_is_not_killed(no_worker, monkeypatch):
    """shutdown op 를 모르는 옛 워커는 진행 중인 조회를 알 수 없어 강제로 내리지 않고 방법을 알린다."""
    def fake_request(op, wait, **args):
        raise store.LoupeError("ValueError: 모르는 op: shutdown")

    monkeypatch.setattr(ghidra_client, "_request", fake_request)
    monkeypatch.setattr(ghidra_client.os, "kill", lambda pid, sig: pytest.fail("옛 워커를 죽였다"))
    with pytest.raises(store.LoupeError, match="kill <pid>"):
        ghidra_client._retire_old_worker({"pid": 4321})


def test_newer_worker_is_not_retired(no_worker, monkeypatch):
    """옛 코드로 떠 있는 MCP 서버가 더 새 워커를 내리지 않는다(내리면 새 코드로 다시 떠 영영 맞지 않는다)."""
    monkeypatch.setattr(ghidra_client, "_ping", lambda: {"pid": 9, "protocol": config.WORKER_PROTOCOL + 1})
    monkeypatch.setattr(ghidra_client, "_retire_old_worker", lambda pong: pytest.fail("더 새 워커를 내렸다"))
    with pytest.raises(store.LoupeError, match="다시 시작"):
        ghidra_client.ensure_worker()


_REAL_SPAWN = ghidra_client._spawn  # no_worker 픽스처가 _spawn 을 막기 전의 원래 함수


def test_spawn_wait_handles_old_worker_answering_late(no_worker, monkeypatch):
    """새 워커를 띄우고 기다리는데 옛 워커가 답하면(앞의 ping 을 놓친 경우) 180초를 기다리지 않는다:
    옛 워커를 내렸으면 한 번 더 띄우고, 내릴 수 없으면 바로 안내한다."""
    monkeypatch.setattr(ghidra_client.config, "GHIDRA_INSTALL_DIR", _fake_ghidra(no_worker))
    launches, retired = [], []
    monkeypatch.setattr(ghidra_client, "_launch", lambda: launches.append(1))
    pongs = iter([{"pid": 1, "protocol": 0}, None, {"pid": 2, "protocol": config.WORKER_PROTOCOL}])
    monkeypatch.setattr(ghidra_client, "_ping", lambda: next(pongs))
    monkeypatch.setattr(ghidra_client, "_retire_old_worker", lambda pong: retired.append(pong["pid"]))
    _REAL_SPAWN()
    assert launches == [1, 1] and retired == [1]

    pongs2 = iter([{"pid": 1, "protocol": 0}])
    monkeypatch.setattr(ghidra_client, "_ping", lambda: next(pongs2))

    def refuse(pong):
        raise store.LoupeError("옛 버전 Ghidra 워커(pid 1)가 떠 있다 ... kill <pid>")

    monkeypatch.setattr(ghidra_client, "_retire_old_worker", refuse)
    with pytest.raises(store.LoupeError, match="kill <pid>"):
        _REAL_SPAWN()


def _fake_ghidra(sock_path):
    import os

    d = os.path.join(os.path.dirname(sock_path), "ghidra")
    os.makedirs(os.path.join(d, "support"), exist_ok=True)
    open(os.path.join(d, "support", "analyzeHeadless"), "w").close()
    from pathlib import Path

    return Path(d)
