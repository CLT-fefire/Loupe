"""15바이트 이하 Swift 문자열(small string) 찾기.

Swift 는 15바이트 이하 문자열 리터럴을 문자열 섹션에 두지 않고, String 값의 두 워드(16바이트)를
명령어 즉값으로 바로 만든다. arm64 에서는 레지스터 두 개에 MOVZ/MOVK(4바이트 이하는 w 레지스터)나
ORR 비트마스크(같은 바이트 반복)로 만든다. 그래서 바이트 검색(find_strings)에는 걸리지 않는다.

  워드0 = 문자열 바이트 0..7 (리틀 엔디언)
  워드1 = 바이트 8..14 + 맨 위 바이트 판별자(ASCII 면 0xE0|길이, 아니면 0xA0|길이)

2026-11-10 swiftc -O(arm64)로 확인했다: "abc" → mov w0,#0x6261; movk w0,#0x63,lsl 16; mov x1,#0xe300…
같은 16바이트가 상수 섹션(__literal16 등)에 놓이고 ldr 로 읽히는 경우도 있어, 데이터 섹션도 바이트로 찾는다.
"""

from __future__ import annotations

import re
import struct
from array import array
from bisect import bisect_left, bisect_right
from dataclasses import dataclass

from .macho import MachO

SMALL_MAX = 15
MASK64 = (1 << 64) - 1
# MOVN/MOVZ/MOVK(32·64비트), ORR 즉값(32·64비트)의 맨 위 바이트
_TOP_BYTES = re.compile(rb"[\x12\x92\x52\xd2\x72\xf2\x32\xb2]")
MOVK_WINDOW = 8  # MOVK 는 같은 레지스터의 직전 쓰기에서 이만큼(명령어 수) 안에 있어야 이어 붙인다
PAIR_WINDOW = 12  # 워드0 과 워드1 을 만드는 명령어 사이 최대 거리(명령어 수)


def words(text: str) -> tuple[int, int] | None:
    """문자열이 small string 이면 두 워드, 아니면 None."""
    b = text.encode("utf-8")
    if not 1 <= len(b) <= SMALL_MAX:
        return None
    disc = (0xE0 if b.isascii() else 0xA0) | len(b)
    raw = b.ljust(15, b"\0") + bytes([disc])
    w0, w1 = struct.unpack("<QQ", raw)
    return w0, w1


def _ror(x: int, r: int, width: int) -> int:
    r %= width
    return ((x >> r) | (x << (width - r))) & ((1 << width) - 1)


def decode_bitmask(n: int, imms: int, immr: int, width: int) -> int | None:
    """ARM 논리 즉값(DecodeBitMasks)의 wmask. 잘못된 인코딩이면 None."""
    combined = (n << 6) | (~imms & 0x3F)
    if combined == 0:
        return None
    length = combined.bit_length() - 1
    esize = 1 << length
    if esize > width:
        return None
    levels = esize - 1
    s, r = imms & levels, immr & levels
    if s == levels:
        return None
    elem = _ror((1 << (s + 1)) - 1, r, esize)
    out = 0
    for i in range(width // esize):
        out |= elem << (i * esize)
    return out


def mov_events(text: bytes) -> list[tuple[int, int, int]]:
    """__text 를 훑어 즉값으로 레지스터에 상수를 만드는 지점마다 (명령어 번호, 레지스터, 그때 값).

    전체 명령어를 해독하지 않고, 맨 위 바이트가 MOV 계열인 것만 골라 본다. MOVZ 와 MOVK 사이에
    다른 명령어가 같은 레지스터를 덮어쓰는 경우는 보지 않는다(컴파일러는 붙여서 낸다).
    """
    tops = text[3::4]
    regs: dict[int, tuple[int, int]] = {}
    out = []
    for m in _TOP_BYTES.finditer(tops):
        i = m.start()
        insn = int.from_bytes(text[4 * i : 4 * i + 4], "little")
        sf = insn >> 31
        width = 64 if sf else 32
        rd = insn & 31
        kind = insn & 0x7F800000
        if kind in (0x12800000, 0x52800000, 0x72800000):  # MOVN, MOVZ, MOVK
            hw = (insn >> 21) & 3
            if not sf and hw > 1:
                continue
            shift = 16 * hw
            imm = ((insn >> 5) & 0xFFFF) << shift
            if kind == 0x52800000:
                val = imm
            elif kind == 0x12800000:
                val = ~imm & ((1 << width) - 1)
            else:
                prev = regs.get(rd)
                if prev is None or i - prev[1] > MOVK_WINDOW:
                    regs.pop(rd, None)
                    continue
                val = (prev[0] & ~(0xFFFF << shift) & ((1 << width) - 1)) | imm
        elif kind == 0x32000000 and (insn >> 5) & 31 == 31:  # ORR Rd, ZR, #bitmask (= mov 즉값)
            val = decode_bitmask((insn >> 22) & 1, (insn >> 10) & 0x3F, (insn >> 16) & 0x3F, width)
            if val is None:
                continue
        else:
            continue
        if rd == 31:
            continue
        regs[rd] = (val, i)
        out.append((i, rd, val))
    return out


@dataclass
class Hit:
    offset: int  # 파일 오프셋(워드0 을 만드는 첫 명령어 또는 16바이트 상수의 시작)
    address: int  # 가상 주소. decompile(function=hex(address)) 로 그 함수를 볼 수 있다
    section: str
    how: str  # "instructions" | "data"


class Events:
    """mov_events 결과를 배열 세 개로 압축해 둔다(튜플 수십만 개를 상주시키지 않게)."""

    def __init__(self, events: list[tuple[int, int, int]]):
        self.idx = array("I", (e[0] for e in events))
        self.reg = array("B", (e[1] for e in events))
        self.val = array("Q", (e[2] for e in events))

    def where(self, value: int) -> list[tuple[int, int]]:
        """값이 value 가 되는 (명령어 번호, 레지스터). 명령어 번호 순."""
        return [(self.idx[k], self.reg[k]) for k, v in enumerate(self.val) if v == value]


def _events(m: MachO) -> Events:
    """바이너리마다 한 번만 훑는다(MachO 객체는 macho._load 가 캐시한다)."""
    ev = getattr(m, "_mov_events", None)
    if ev is None:
        s = m.section("__text", "__TEXT")
        ev = Events(mov_events(m.section_bytes(s)) if s else [])
        m._mov_events = ev  # type: ignore[attr-defined]
    return ev


def find(m: MachO, text: str, limit: int = 1000) -> list[Hit]:
    """small string 이 명령어 즉값이나 16바이트 상수로 있는 위치."""
    w = words(text)
    if w is None:
        return []
    w0, w1 = w
    hits: list[Hit] = []
    s = m.section("__text", "__TEXT")
    if s is not None:
        ev = _events(m)
        firsts = ev.where(w0)
        if firsts:
            seconds = ev.where(w1)
            pos = [i for i, _ in seconds]  # 명령어 번호 순이라 이분 탐색으로 창 안의 것만 본다
            for i0, r0 in firsts:
                lo_k, hi_k = bisect_left(pos, i0 - PAIR_WINDOW), bisect_right(pos, i0 + PAIR_WINDOW)
                if any(seconds[k][1] != r0 for k in range(lo_k, hi_k)):
                    hits.append(Hit(s.offset + 4 * i0, s.addr + 4 * i0, s.key, "instructions"))
                    if len(hits) >= limit:
                        return hits
    needle = struct.pack("<QQ", w0, w1)
    lo, hi = m.slice_offset, m.slice_offset + m.slice_size
    start = lo
    while len(hits) < limit:
        off = m.data.find(needle, start, hi)
        if off < 0:
            break
        start = off + 1
        sec = next((x for x in m.sections if x.offset <= off < x.offset + x.size), None)
        if sec is None or sec.key == "__TEXT,__text":
            continue
        hits.append(Hit(off, sec.addr + (off - sec.offset), sec.key, "data"))
    return hits
