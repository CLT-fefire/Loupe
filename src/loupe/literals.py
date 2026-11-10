"""소스 문자열 리터럴 해석(find_strings·source_secrets 가 같이 쓴다)."""

from __future__ import annotations

import re

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "'": "'", "\\": "\\", "0": "\0"}


def unescape(lit: str) -> str:
    """C/ObjC/Swift 리터럴의 이스케이프를 푼다. Swift \\u{AC00} 도 처리한다."""
    lit = re.sub(r"\\u\{([0-9a-fA-F]{1,8})\}", lambda m: chr(int(m.group(1), 16)), lit)
    return re.sub(r"\\(.)", lambda m: _ESCAPES.get(m.group(1), m.group(0)), lit)
