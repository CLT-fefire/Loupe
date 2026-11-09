"""ipa 를 열어 캐시에 풀고, id 로 다시 찾는다.

id 는 ipa 파일 sha256 의 앞 12자다. 같은 ipa 는 다시 풀지 않는다.
"""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import shutil
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from mcp.server.mcpserver.exceptions import ToolError

from . import config

MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe",  # MH_MAGIC_64 (LE)
    b"\xce\xfa\xed\xfe",  # MH_MAGIC (LE)
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC
    b"\xca\xfe\xba\xbf",  # FAT_MAGIC_64
}

MAX_UNCOMPRESSED = 4 * 1024**3  # 압축 폭탄 방지: 풀었을 때 4GB 초과면 거부


class LoupeError(ToolError):
    """사용자에게 그대로 보여 줄 오류. ToolError 라서 MCP 클라이언트에 메시지가 전달된다
    (다른 예외는 SDK 가 'Error executing tool <name>' 으로만 감춘다)."""


@dataclass
class Ipa:
    id: str
    sha256: str
    source: str
    root: Path  # 캐시 폴더
    app: Path  # Payload/<name>.app

    @property
    def info_plist(self) -> dict:
        with open(self.app / "Info.plist", "rb") as f:
            return plistlib.load(f)

    @property
    def main_binary(self) -> Path:
        return self.app / self.info_plist["CFBundleExecutable"]

    @property
    def code_binary(self) -> Path:
        """클래스·메서드가 실제로 들어 있는 바이너리.

        Xcode Debug 빌드(ENABLE_DEBUG_DYLIB)는 메인 실행 파일이 껍데기이고 코드는
        `<실행 파일>.debug.dylib` 에 있다. 그런 파일이 있으면 그쪽을 쓴다.
        """
        dbg = self.app / f"{self.main_binary.name}.debug.dylib"
        return dbg if dbg.is_file() else self.main_binary

    def rel(self, p: Path) -> str:
        return str(p.relative_to(self.app))

    def binaries(self) -> list[Path]:
        """앱 안의 모든 Mach-O 파일. 메인 실행 파일이 맨 앞."""
        main = self.main_binary
        found = [main]
        for p in sorted(self.app.rglob("*")):
            if p == main or not p.is_file() or p.is_symlink():
                continue
            try:
                with open(p, "rb") as f:
                    head = f.read(8)
            except OSError:
                continue
            if head[:4] in MACHO_MAGICS:
                # CAFEBABE 는 Java .class 와 같다. fat 이면 다음 4바이트(slice 수)가 작다
                if head[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") and int.from_bytes(head[4:8], "big") > 30:
                    continue
                found.append(p)
        return found

    def resolve_binary(self, name: str | None) -> Path:
        """'main', 앱 기준 상대 경로, 파일 이름 중 하나로 바이너리를 찾는다."""
        if not name or name == "main":
            return self.main_binary
        bins = self.binaries()
        for b in bins:
            if self.rel(b) == name:
                return b
        matches = [b for b in bins if b.name == name]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise LoupeError(f"'{name}' 와 이름이 같은 바이너리가 여러 개다: {[self.rel(b) for b in matches]}")
        raise LoupeError(f"바이너리 '{name}' 를 찾지 못했다. 목록: {[self.rel(b) for b in bins]}")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_extract(zf: zipfile.ZipFile, dest: Path) -> None:
    """경로 이탈(zip slip)·심볼릭 링크·압축 폭탄을 막으며 푼다."""
    dest = dest.resolve()
    total = 0
    for info in zf.infolist():
        name = info.filename
        if name.startswith("/") or "\\" in name or any(part == ".." for part in name.split("/")):
            raise LoupeError(f"ipa 안에 허용되지 않는 경로가 있다: {name!r}")
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            continue  # 심볼릭 링크는 만들지 않는다
        total += info.file_size
        if total > MAX_UNCOMPRESSED:
            raise LoupeError("ipa 를 풀면 4GB 를 넘는다. 거부한다.")
        target = (dest / name).resolve()
        if dest not in target.parents and target != dest:
            raise LoupeError(f"ipa 안에 허용되지 않는 경로가 있다: {name!r}")
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as out:
            shutil.copyfileobj(src, out)


def _cache_root() -> Path:
    config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(config.CACHE_DIR, 0o700)
    return config.CACHE_DIR


def open_ipa(path: str) -> Ipa:
    p = Path(path).expanduser()
    if not p.is_file():
        raise LoupeError(f"파일이 없다: {path}")
    if not config.is_under(p, config.ALLOWED_DIRS):
        raise LoupeError(
            f"허용된 폴더 밖의 파일이다: {p}. 허용 폴더: {[str(d) for d in config.ALLOWED_DIRS]} "
            "(LOUPE_ALLOWED_DIRS 로 바꿀 수 있다)"
        )
    sha = _sha256(p)
    ipa_id = sha[:12]
    root = _cache_root() / ipa_id
    meta_path = root / "meta.json"
    if not meta_path.exists():
        # 같은 ipa 를 동시에 여는 경우(병렬 호출, 세션 여러 개)를 위해 임시 폴더는 매번 고유하게 만든다
        tmp = Path(tempfile.mkdtemp(prefix=f"{ipa_id}.", suffix=".tmp", dir=_cache_root()))
        try:
            try:
                with zipfile.ZipFile(p) as zf:
                    _safe_extract(zf, tmp / "x")
            except zipfile.BadZipFile as e:
                raise LoupeError(f"ipa(zip) 가 아니다: {e}") from e
            apps = list((tmp / "x" / "Payload").glob("*.app"))
            if len(apps) != 1:
                raise LoupeError(f"Payload 안의 .app 이 1개가 아니다: {[a.name for a in apps]}")
            if not (apps[0] / "Info.plist").is_file():
                raise LoupeError(f"{apps[0].name} 에 Info.plist 가 없다")
            (tmp / "meta.json").write_text(
                json.dumps({"sha256": sha, "source": str(p.resolve()), "app": str(apps[0].relative_to(tmp))})
            )
            try:
                tmp.rename(root)  # 원자적. root 가 이미 있으면(다른 쪽이 먼저 끝냄) 실패한다
            except OSError:
                if not meta_path.exists():
                    shutil.rmtree(root, ignore_errors=True)  # meta 없는 반쪽짜리 캐시
                    tmp.rename(root)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return get(ipa_id)


def get(ipa_id: str) -> Ipa:
    ipa_id = (ipa_id or "").strip().lower()
    if not ipa_id or not all(c in "0123456789abcdef" for c in ipa_id):
        raise LoupeError(f"잘못된 id: {ipa_id!r}")
    root = config.CACHE_DIR / ipa_id
    meta_path = root / "meta.json"
    if not meta_path.exists():
        raise LoupeError(f"열린 ipa 가 아니다: {ipa_id}. 먼저 ipa_open 을 호출한다.")
    meta = json.loads(meta_path.read_text())
    return Ipa(id=ipa_id, sha256=meta["sha256"], source=meta["source"], root=root, app=root / meta["app"])


def list_opened() -> list[dict]:
    out = []
    if not config.CACHE_DIR.exists():
        return out
    for meta_path in sorted(config.CACHE_DIR.glob("*/meta.json")):
        meta = json.loads(meta_path.read_text())
        out.append({"id": meta_path.parent.name, "source": meta["source"]})
    return out


def clear(ipa_id: str) -> None:
    ipa = get(ipa_id)
    shutil.rmtree(ipa.root)
