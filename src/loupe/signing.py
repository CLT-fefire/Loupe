"""서명·엔타이틀먼트·프로비저닝 프로파일 읽기 (macOS `codesign`, `security` 사용)."""

from __future__ import annotations

import plistlib
import subprocess
from pathlib import Path


def _run(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, returncode=-1, stdout=b"", stderr=f"{timeout}초 안에 끝나지 않았다".encode())


def entitlements(bundle_or_binary: Path) -> dict | None:
    r = _run(["codesign", "-d", "--entitlements", "-", "--xml", str(bundle_or_binary)])
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        return plistlib.loads(r.stdout)
    except Exception:
        return None


def signature(bundle: Path) -> dict:
    r = _run(["codesign", "-dvv", str(bundle)])
    text = r.stderr.decode("utf-8", "replace")
    out: dict = {"authorities": []}
    for line in text.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k == "Authority":
            out["authorities"].append(v)
        elif k in ("Identifier", "TeamIdentifier", "Signed Time", "Format"):
            out[k.lower().replace(" ", "_")] = v
    v = _run(["codesign", "--verify", "--deep", "--strict", str(bundle)])
    out["verify_ok"] = v.returncode == 0
    if v.returncode != 0:
        out["verify_error"] = v.stderr.decode("utf-8", "replace").strip()[-500:]
    return out


def profile(bundle: Path) -> dict | None:
    """embedded.mobileprovision 요약. 기기 UDID 목록은 개수만 돌려준다(기기 식별자)."""
    p = bundle / "embedded.mobileprovision"
    if not p.exists():
        return None
    r = _run(["security", "cms", "-D", "-i", str(p)])
    if r.returncode != 0:
        return {"error": r.stderr.decode("utf-8", "replace").strip()}
    d = plistlib.loads(r.stdout)
    ents = d.get("Entitlements", {})
    devices = d.get("ProvisionedDevices")
    if ents.get("get-task-allow"):
        kind = "development"
    elif d.get("ProvisionsAllDevices"):
        kind = "enterprise"
    elif devices:
        kind = "ad-hoc"
    else:
        kind = "app-store"
    return {
        "name": d.get("Name"),
        "kind": kind,
        "team_name": d.get("TeamName"),
        "expiration": str(d.get("ExpirationDate")),
        "provisioned_device_count": len(devices) if devices else 0,
        "get_task_allow": bool(ents.get("get-task-allow")),
    }


def diff_dict(a: dict | None, b: dict | None) -> dict:
    a, b = a or {}, b or {}
    out = {}
    for k in sorted(set(a) | set(b)):
        if a.get(k) != b.get(k):
            out[k] = {"a": a.get(k, "<없음>"), "b": b.get(k, "<없음>")}
    return out
