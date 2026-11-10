"""환경 설정. 모든 값은 환경 변수로 덮어쓸 수 있다."""

from __future__ import annotations

import os
import re
from pathlib import Path


def _paths(env: str, default: list[Path]) -> list[Path]:
    raw = os.environ.get(env)
    if not raw:
        return default
    return [Path(p).expanduser().resolve() for p in raw.split(os.pathsep) if p]


CACHE_DIR = Path(os.environ.get("LOUPE_CACHE_DIR", "~/Library/Caches/Loupe")).expanduser()

# ipa 는 이 폴더들 아래에 있는 것만 연다.
ALLOWED_DIRS = _paths(
    "LOUPE_ALLOWED_DIRS",
    [
        Path("~/Downloads").expanduser().resolve(),
        Path("~/Desktop").expanduser().resolve(),
        Path("~/Library/Developer/Xcode/Archives").expanduser().resolve(),
        Path("/Users/Shared/Source").resolve(),
    ],
)

# find_strings(source_ref=...) 가 읽을 소스 저장소 루트.
SOURCE_ROOTS = _paths("LOUPE_SOURCE_ROOTS", [Path("/Users/Shared/Source/Company").resolve()])

GHIDRA_INSTALL_DIR = Path(
    os.environ.get("GHIDRA_INSTALL_DIR", "/opt/homebrew/opt/ghidra/libexec")
).expanduser()

LOG_FILE = CACHE_DIR / "loupe.log"


# Ghidra 캐시 배치. 워커(분석)와 MCP 서버(상태·목록)가 같이 쓰므로 여기 한 곳에 둔다.
# 서버는 JVM 을 띄우는 워커 모듈을 import 하지 않는다.
def ghidra_project_dir(ipa_id: str, rel: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", rel)
    return CACHE_DIR / ipa_id / "ghidra" / safe


def ghidra_marker(ipa_id: str, rel: str) -> Path:
    """분석 완료 표시(analyzed.json). 내용: program, rel, finished, seconds, size."""
    return ghidra_project_dir(ipa_id, rel) / "analyzed.json"


def is_under(path: Path, roots: list[Path]) -> bool:
    path = path.resolve()
    return any(path == r or r in path.parents for r in roots)


# Ghidra 분석 프로필: 끌 분석기 목록. fast 는 xrefs·이름·함수 경계에 쓰지 않는 것만 끈다.
# 2026-11-10 실측(26.5MB): full 546초, fast 438초. Decompiler Switch Analysis 는 끄면 case 블록 명령어가
# 해독되지 않아(명령어 -1.6%) xrefs 가 빠지므로 어떤 프로필에서도 끄지 않는다.
GHIDRA_PROFILES: dict[str, list[str]] = {"full": [], "fast": ["Stack", "Call Convention ID"]}

# MCP 서버와 워커가 주고받는 요청 형식의 버전. 바꾸면 이미 떠 있는 옛 워커를 내리고 새로 띄운다.
WORKER_PROTOCOL = 3
