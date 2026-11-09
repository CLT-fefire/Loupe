"""이름(식별자) 추출과 난독화 패턴 판정."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .macho import NAME_SECTIONS, MachO

LAZY_PREFIX = "$__lazy_storage_$_"
_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


def swift_components(name: str) -> list[str]:
    """`_TtC10Fork_Stars28SomeClass` 같은 옛 Swift 맹글링에서 이름 조각을 꺼낸다."""
    if not name.startswith("_Tt"):
        return []
    out, i, s = [], 3, name
    while i < len(s) and not s[i].isdigit():
        i += 1
    while i < len(s):
        m = re.match(r"(\d+)", s[i:])
        if not m:
            # P33_<hash> 같은 private discriminator 는 건너뛴다
            i += 1
            continue
        n = int(m.group(1))
        i += len(m.group(1))
        out.append(s[i : i + n])
        i += n
    return out


def leaf(name: str) -> str:
    """비교에 쓸 대표 식별자. 클래스면 마지막 조각, 셀렉터면 첫 조각.

    - 프로퍼티 속성 문자열 `T@"NSNumber",&,N,V_isAuth` 은 마지막 `,V` 뒤의 이름을 쓴다.
    - 인스턴스 변수 `_isAuth` 처럼 앞에 붙은 밑줄은 뗀다(난독화는 밑줄 뒤 이름만 바꾼다).
    """
    comps = swift_components(name)
    if comps:
        return comps[-1]
    if name.startswith("T") and ",V" in name:
        name = name.rsplit(",V", 1)[1]
    if name.startswith(LAZY_PREFIX):
        name = name[len(LAZY_PREFIX) :]
    if ":" in name:
        name = name.split(":", 1)[0]
    name = name.lstrip("_")
    m = _IDENT.match(name)
    return m.group(0) if m else name


def tokens(name: str) -> list[str]:
    """이름 안의 식별자 조각 전부. 난독화된 부분이 맨 끝이 아니라 중간에 있을 수도 있다.

    예: 프로퍼티 속성 `T@"zZZqaaa",&,N` 의 타입 이름, Swift private 구분자 `P33_zZZP…`.
    """
    comps = swift_components(name)
    raw = comps if comps else _IDENT.findall(name)
    # 속성 문자열 안에 든 Swift 맹글링 이름(T@"_TtC10Fork_Stars10Foo")도 조각으로 편다
    raw = [c for t in raw for c in (swift_components(t) or [t])]
    out = [leaf(name)]
    for t in raw:
        t = t.lstrip("_")
        if t and t not in out:
            out.append(t)
    return out


@dataclass
class Pattern:
    regex: re.Pattern
    min_len: int

    def match(self, name: str) -> bool:
        return any(len(t) >= self.min_len and self.regex.fullmatch(t) for t in tokens(name))


def name_entries(m: MachO, section: str) -> list[tuple[int, str]]:
    return [(off, raw.decode("utf-8", "replace")) for off, raw in m.c_strings(section)]


def all_names(m: MachO) -> dict[str, list[tuple[int, str]]]:
    return {s: name_entries(m, s) for s in NAME_SECTIONS}


def pair_names(a: MachO, b: MachO, section: str) -> list[tuple[str, str]] | None:
    """두 바이너리의 같은 섹션을 오프셋 기준으로 짝짓는다.

    LIAPP 는 같은 길이로 이름을 바꾸므로 오프셋이 그대로다. 섹션 크기가 다르면
    짝지을 수 없으므로 None.
    """
    sa, sb = a.section(section), b.section(section)
    if sa is None or sb is None or sa.size != sb.size:
        return None
    # 원시 바이트로 짝짓고 비교한다(UTF-8 이 아닌 서로 다른 바이트가 둘 다 U+FFFD 로 같아 보이지 않게)
    ra, rb = dict(a.c_strings(section)), dict(b.c_strings(section))
    if ra.keys() != rb.keys():
        return None
    out = []
    for k in sorted(ra):
        x, y = ra[k], rb[k]
        dx, dy = x.decode("utf-8", "replace"), y.decode("utf-8", "replace")
        if x != y and dx == dy:
            dy += " (바이트 다름)"
        out.append((dx, dy))
    return out
