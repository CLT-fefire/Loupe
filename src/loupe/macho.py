"""Mach-O 읽기. 구조는 LIEF 로 읽고, 섹션 내용은 파일 바이트에서 직접 자른다."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import lief

lief.logging.disable()

FAT_MAGICS = {b"\xca\xfe\xba\xbe": False, b"\xca\xfe\xba\xbf": True}  # True = 64비트 fat
CPU_ARM64 = 0x0100000C

# 이름(식별자)이 들어 있는 섹션. 난독화 비교의 대상.
NAME_SECTIONS = ("__objc_classname", "__objc_methname", "__swift5_reflstr")


@dataclass
class Section:
    segment: str
    name: str
    offset: int  # 파일 기준 오프셋 (fat 이면 slice 오프셋을 더한 값)
    size: int

    @property
    def key(self) -> str:
        return f"{self.segment},{self.name}"


@dataclass
class MachO:
    path: Path
    data: bytes
    slice_offset: int
    slice_size: int
    binary: lief.MachO.Binary
    sections: list[Section] = field(default_factory=list)

    def section(self, name: str, segment: str | None = None) -> Section | None:
        for s in self.sections:
            if s.name == name and (segment is None or s.segment == segment):
                return s
        return None

    def section_bytes(self, s: Section) -> bytes:
        return self.data[s.offset : s.offset + s.size]

    def section_at(self, off: int) -> str:
        for s in self.sections:
            if s.offset <= off < s.offset + s.size:
                return s.key
        if self.binary.has_code_signature:
            cs = self.binary.code_signature
            start = self.slice_offset + cs.data_offset
            if start <= off < start + cs.data_size:
                return "코드 서명(엔타이틀먼트·서명 블롭)"
        for seg in self.binary.segments:
            start = self.slice_offset + seg.file_offset
            if start <= off < start + seg.file_size:
                return f"{seg.name} (섹션 밖)"
        return "헤더/기타"

    def c_strings(self, name: str) -> list[tuple[int, bytes]]:
        """NUL 로 끝나는 문자열 섹션을 (섹션 안 오프셋, 바이트) 목록으로."""
        s = self.section(name)
        if s is None:
            return []
        raw = self.section_bytes(s)
        out, pos = [], 0
        for chunk in raw.split(b"\0"):
            if chunk:
                out.append((pos, chunk))
            pos += len(chunk) + 1
        return out

    def summary(self) -> dict:
        b = self.binary
        enc = None
        if b.has_encryption_info:
            enc = {"cryptid": b.encryption_info.crypt_id, "size": b.encryption_info.crypt_size}
        cats: dict[str, int] = {}
        for s in b.symbols:
            k = str(s.category).split(".")[-1]
            cats[k] = cats.get(k, 0) + 1
        return {
            "arch": str(b.header.cpu_type).split(".")[-1],
            "file_type": str(b.header.file_type).split(".")[-1],
            "size": len(self.data),
            "fat": self.data[:4] in FAT_MAGICS,
            "encryption": enc,
            "fairplay_encrypted": bool(enc and enc["cryptid"] != 0),
            # 앱에 들어 있는 라이브러리(@rpath 등)는 그대로, 시스템 것은 이름만 짧게 보여 준다
            "linked_libraries": {
                "embedded": [lib.name for lib in b.libraries if lib.name.startswith("@")],
                "system": sorted(
                    {lib.name.rsplit("/", 1)[-1] for lib in b.libraries if not lib.name.startswith("@")}
                ),
            },
            "rpaths": [r.path for r in b.rpaths],
            "symbols": {
                "total": len(b.symbols),
                "imported": cats.get("UNDEFINED", 0),  # 다른 라이브러리에서 가져다 쓰는 심볼
                "exported": cats.get("EXTERNAL", 0),
                "local": cats.get("LOCAL", 0),  # 거의 0 이면 심볼이 제거된(strip) 빌드
            },
            "has_code_signature": b.has_code_signature,
            "min_os": _min_os(b),
        }


def _min_os(b: lief.MachO.Binary) -> str | None:
    if b.has_build_version:
        v = b.build_version.minos
        return ".".join(str(x) for x in v)
    if b.has_version_min:
        return ".".join(str(x) for x in b.version_min.version)
    return None


def _arm64_slice(data: bytes) -> tuple[int, int]:
    """fat 이면 arm64 slice 의 (오프셋, 크기), 아니면 (0, 전체 크기)."""
    magic = data[:4]
    if magic not in FAT_MAGICS:
        return 0, len(data)
    is64 = FAT_MAGICS[magic]
    (n,) = struct.unpack(">I", data[4:8])
    pos = 8
    first = None
    for _ in range(n):
        if is64:
            cpu, _sub, off, size, _align, _res = struct.unpack(">iiQQII", data[pos : pos + 32])
            pos += 32
        else:
            cpu, _sub, off, size, _align = struct.unpack(">iiIII", data[pos : pos + 20])
            pos += 20
        if first is None:
            first = (off, size)
        if cpu == CPU_ARM64:
            return off, size
    assert first is not None
    return first


@lru_cache(maxsize=16)
def _load(path_str: str, mtime: float) -> MachO:
    path = Path(path_str)
    data = path.read_bytes()
    off, size = _arm64_slice(data)
    parsed = lief.MachO.parse(path_str)
    if parsed is None:
        raise ValueError(f"Mach-O 로 읽을 수 없다: {path}")
    binary = None
    for i in range(parsed.size):
        b = parsed.at(i)
        if b.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
            binary = b
            break
    binary = binary or parsed.at(0)
    m = MachO(path=path, data=data, slice_offset=off, slice_size=size, binary=binary)
    for s in binary.sections:
        if s.offset == 0 and s.size and s.segment_name in ("__DATA", "__DATA_CONST", "__DATA_DIRTY"):
            # zerofill(__bss, __common) 은 파일에 없다
            continue
        m.sections.append(Section(s.segment_name, s.name, off + s.offset, s.size))
    return m


def load(path: Path) -> MachO:
    return _load(str(path), path.stat().st_mtime)
