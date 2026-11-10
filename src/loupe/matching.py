"""compare_function 의 짝짓기 규칙(Ghidra 와 분리한 순수 함수).

a 의 함수 하나에 대응하는 b 의 함수를 고른다. 두 쪽의 함수 색인과 '주소 -> 서명' 함수만 받으므로
Ghidra 없이 단위 테스트할 수 있다. 서명은 필요할 때만 계산한다(호출하는 쪽이 캐시한다).

순서(앞에서 정해지면 끝):
  ① name / method_name  전체 이름이, 안 되면 :: 뒤 메서드 이름이 a·b 양쪽에서 하나뿐이다
                        (고른 함수가 a 와 같은 주소이고 서명도 같으면 address 로 적는다)
  ② address     같은 주소에서 시작하는 함수의 서명이 a 와 같다. 단 a 에 서명이 같은 함수가 여럿이면
                (분기 대상만 다른 thunk 묶음) 배치가 밀려 형제 함수가 그 자리에 왔을 수 있으므로,
                묶음 개수와 순서까지 맞을 때만 확정하고 아니면 ③ 의 결과를 따른다
  ③ signature   크기·서명이 같은 함수 중 a 의 함수와 짝 — 묶음이 여럿이면 호출 대상까지 넣은 서명으로
                구분하고, 그래도 안 되면 묶음 개수가 a·b 같을 때 a 묶음 안 순서와 같은 것
  ④ address     같은 주소에서 시작하는 함수(코드는 다르다)
이름 단계는 주소·순번에서 나온 이름(FUN_…, _OUTLINED_FUNCTION_N)을 쓰지 않는다.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Callable, Protocol

MAX_CANDIDATES = 20_000  # 크기가 같은 후보가 이보다 많으면 서명 비교를 하지 않는다
SIGNATURE_BUDGET_S = 60.0  # 서명 계산이 이 시간을 넘으면 그만둔다(서명은 캐시되므로 다시 부르면 이어서 빨라진다)
DEEP_MAX = 200  # 서명 묶음이 이보다 크면 호출 대상 비교를 하지 않는다(묶음 순서로만 구분)
_GENERATED_NAME = re.compile(r"(?:thunk_)?(?:FUN|SUB|LAB)_[0-9a-fA-F]+|_?OUTLINED_FUNCTION_\d+")


class Row(Protocol):
    name: str
    short: str
    entry: str
    is_code: bool
    size: int


class Index(Protocol):
    rows: list

    def exact(self, name: str) -> list: ...


@dataclass
class Side:
    idx: Index
    sig: Callable[[str], str]  # 시작 주소 -> 서명
    # 시작 주소 -> 호출 대상까지 넣은 서명. 분기 대상만 다른 함수(thunk 묶음)를 구분한다. 없으면 순서로만 구분
    deep: Callable[[str], str] | None = None


def short_name(name: str) -> str:
    return name.rsplit("::", 1)[-1]


def is_generated(name: str) -> bool:
    return bool(_GENERATED_NAME.fullmatch(short_name(name)))


def _entry_key(entry: str) -> int:
    try:
        return int(entry, 16)
    except ValueError:
        return 0


def same_signature(side: Side, size: int, signature: str) -> list | None:
    """크기·서명이 같은 코드 함수(주소 순). 후보가 너무 많거나 시간 예산을 넘으면 None."""
    cands = [r for r in side.idx.rows if r.is_code and r.size == size]
    if len(cands) > MAX_CANDIDATES:
        return None
    deadline = time.monotonic() + SIGNATURE_BUDGET_S
    hits = []
    for r in cands:
        if side.sig(r.entry) == signature:
            hits.append(r)
        if time.monotonic() > deadline:
            return None
    return sorted(hits, key=lambda r: _entry_key(r.entry))


def _unique(idx: Index, name: str, field: str) -> list:
    return [r for r in idx.exact(name) if getattr(r, field) == name and r.is_code]


def choose(a: Side, b: Side, entry: str, name: str, size: int, b_has_entry: bool) -> dict:
    """{"method": …|None, "entry": b 쪽 시작 주소|None, "notes": [...]}"""
    sig = a.sig(entry)
    notes: list[str] = []
    same_at_entry = b_has_entry and b.sig(entry) == sig

    def by_name(method: str, b_entry: str, what: str) -> dict:
        if b_entry == entry and same_at_entry:
            return {"method": "address", "entry": entry, "notes": notes}
        if b.sig(b_entry) != sig:
            notes.append(f"{what}으로 짝지었지만 코드 서명이 다르다(로직이 바뀌었을 수 있다)")
        return {"method": method, "entry": b_entry, "notes": notes}

    if not is_generated(name):
        fa, fb = _unique(a.idx, name, "name"), _unique(b.idx, name, "name")
        if len(fa) == 1 and len(fb) == 1:
            return by_name("name", fb[0].entry, "이름")
        if len(fa) > 1 or len(fb) > 1:
            notes.append(f"이름이 같은 함수가 a {len(fa)}개, b {len(fb)}개라 이름으로 짝짓지 않았다")
        short = short_name(name)
        sa, sb = _unique(a.idx, short, "short"), _unique(b.idx, short, "short")
        if len(sa) == 1 and len(sb) == 1:
            if sb[0].entry != entry or not same_at_entry:
                notes.append("전체 이름이 달라 메서드 이름으로 짝지었다")
            return by_name("method_name", sb[0].entry, "메서드 이름")

    group_a = same_signature(a, size, sig)
    rank = next((k for k, r in enumerate(group_a) if r.entry == entry), None) if group_a is not None else None
    if same_at_entry and group_a is not None and len(group_a) <= 1:
        return {"method": "address", "entry": entry, "notes": notes}  # 서명이 유일하다 — 주소 짝이 확실하다

    hits = same_signature(b, size, sig) if group_a is not None else None
    if group_a is None or hits is None:
        notes.append(
            f"크기가 같은 함수가 {MAX_CANDIDATES:,}개를 넘었거나 서명 계산이 {SIGNATURE_BUDGET_S:.0f}초를 넘어 서명으로 찾지 않았다"
        )
    elif rank is None:
        notes.append("a 의 함수가 코드 블록 밖에 있어 서명 묶음으로 짝짓지 않았다")
    elif hits:
        # 묶음이 여럿이면 호출 대상까지 넣은 서명으로 먼저 구분한다(배치·개수가 달라도 된다)
        if (len(group_a) > 1 or len(hits) > 1) and a.deep and b.deep and max(len(group_a), len(hits)) <= DEEP_MAX:
            d = a.deep(entry)
            da = [r for r in group_a if a.deep(r.entry) == d]
            db = [r for r in hits if b.deep(r.entry) == d]
            if len(da) == 1 and len(db) == 1:
                if same_at_entry and db[0].entry == entry:
                    return {"method": "address", "entry": entry, "notes": notes}
                notes.append(f"크기·서명이 같은 함수가 a {len(group_a)}개, b {len(hits)}개라 호출 대상까지 비교해 구분했다")
                return {"method": "signature", "entry": db[0].entry, "notes": notes}
        if len(hits) == len(group_a):
            b_entry = hits[rank].entry
            if same_at_entry and b_entry == entry:
                return {"method": "address", "entry": entry, "notes": notes}
            if len(hits) > 1:
                notes.append(f"크기·서명이 같은 함수 {len(hits)}개 중 a 와 같은 순서({rank + 1}번째)의 것을 골랐다")
            if same_at_entry:
                notes.append("같은 주소에도 서명이 같은 함수가 있지만, 묶음 순서가 달라 배치가 밀린 것으로 보았다")
            return {"method": "signature", "entry": b_entry, "notes": notes}
        notes.append(f"크기·서명이 같은 함수가 a {len(group_a)}개, b {len(hits)}개라 서명으로 짝짓지 않았다")

    if same_at_entry:
        notes.append("같은 주소에서 시작하고 서명도 같지만, 서명이 같은 함수가 여럿이라 다른 함수일 수 있다")
        return {"method": "address", "entry": entry, "notes": notes}
    if b_has_entry:
        notes.append("같은 주소에서 시작하는 함수를 썼지만 코드 서명이 다르다")
        return {"method": "address", "entry": entry, "notes": notes}
    return {"method": None, "entry": None, "notes": notes}
