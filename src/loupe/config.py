"""환경 설정. 모든 값은 환경 변수로 덮어쓸 수 있다."""

from __future__ import annotations

import os
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


def is_under(path: Path, roots: list[Path]) -> bool:
    path = path.resolve()
    return any(path == r or r in path.parents for r in roots)
