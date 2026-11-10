"""arm64 함수 바이트 서명.

같은 소스에서 나온 함수라도 코드 배치가 바뀌면 PC 상대 오프셋(분기·ADRP·리터럴 로드)과
ADRP 짝의 페이지 안 오프셋(바로 뒤 ADD·LDR/STR 즉값)이 달라진다. 이 필드만 0 으로 지운 바이트의
해시를 서명으로 쓰면, 주소가 어긋난 두 바이너리에서도 같은 함수를 짝지을 수 있다.
ADRP 짝이 아닌 ADD·LDR/STR 즉값(스택 크기, 구조체 필드 오프셋)은 로직이므로 지우지 않는다.
"""

from __future__ import annotations

import hashlib
import struct

# (마스크, 값, 지울 비트) — insn & 마스크 == 값 이면 항상 지운다(PC 상대)
_PC_RELATIVE = [
    (0x7C000000, 0x14000000, 0x03FFFFFF),  # B, BL: imm26
    (0xFF000010, 0x54000000, 0x00FFFFE0),  # B.cond: imm19
    (0x7E000000, 0x34000000, 0x00FFFFE0),  # CBZ, CBNZ: imm19
    (0x7E000000, 0x36000000, 0x0007FFE0),  # TBZ, TBNZ: imm14
    (0x9F000000, 0x10000000, 0x60FFFFE0),  # ADR: immlo + immhi
    (0x3B000000, 0x18000000, 0x00FFFFE0),  # LDR(리터럴): imm19
]
_ADRP = (0x9F000000, 0x90000000, 0x60FFFFE0)
# ADRP 가 만든 레지스터를 밑으로 쓸 때만 지운다(페이지 안 오프셋)
_PAGE_OFFSET = [
    (0x7F800000, 0x11000000, 0x003FFC00),  # ADD 즉값(시프트 없음): imm12
    (0x3B000000, 0x39000000, 0x003FFC00),  # LDR/STR 부호 없는 오프셋: imm12
]
ADRP_PAIR_WINDOW = 4  # ADRP 뒤 이 명령어 수 안의 짝만 본다


def mask_relocations(code: bytes) -> bytes:
    """배치에 따라 바뀌는 즉값을 지운 코드 바이트. 길이가 4의 배수가 아니면 나머지는 그대로 둔다."""
    n = len(code) // 4
    words = list(struct.unpack(f"<{n}I", code[: 4 * n]))
    adrp_at: dict[int, int] = {}  # ADRP 의 대상 레지스터 -> 명령어 번호
    for k, w in enumerate(words):
        mask, val, clear = _ADRP
        if w & mask == val:
            words[k] = w & ~clear
            adrp_at[w & 31] = k
            continue
        for mask, val, clear in _PC_RELATIVE:
            if w & mask == val:
                words[k] = w & ~clear
                break
        else:
            for mask, val, clear in _PAGE_OFFSET:
                if w & mask == val:
                    rn = (w >> 5) & 31
                    if rn in adrp_at and k - adrp_at[rn] <= ADRP_PAIR_WINDOW:
                        words[k] = w & ~clear
                    break
    return struct.pack(f"<{n}I", *words) + code[4 * n :]


def signature(code: bytes) -> str:
    return hashlib.sha1(mask_relocations(code), usedforsecurity=False).hexdigest()[:16]


def call_targets(code: bytes, base: int) -> list[int]:
    """BL 과, 함수 밖으로 나가는 B(꼬리 호출)의 대상 주소(코드 순서)."""
    n = len(code) // 4
    out = []
    for k, w in enumerate(struct.unpack(f"<{n}I", code[: 4 * n])):
        if w & 0x7C000000 != 0x14000000:  # B / BL
            continue
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 1 << 26
        target = base + 4 * k + 4 * imm
        if w & 0x80000000 or not base <= target < base + len(code):
            out.append(target)
    return out
