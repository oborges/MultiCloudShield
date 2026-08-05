from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_PATTERNS = [
    re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(
        r"(?i)(?:authorization:\s*(?:bearer|basic)|\bbearer\s+|accountkey=|sig=|api[_-]?key\s*[:=])[^\s,;]+"
    ),
    re.compile(r"\bmcs_pat_[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"(?i)postgres(?:ql)?://[^:/\s]+:[^@\s]+@"),
]


def sanitize_text(value: str, *, max_length: int = 2048) -> str:
    return _CONTROL.sub("", value)[:max_length]


def redact_text(value: str) -> str:
    cleaned = sanitize_text(value, max_length=16_384)
    for pattern in _PATTERNS:
        cleaned = pattern.sub("[REDACTED]", cleaned)
    return cleaned


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            sanitize_text(str(key), max_length=128): (
                "[REDACTED]"
                if re.search(
                    r"(?i)(secret|password|token|authorization|private[_-]?key|api[_-]?key)",
                    str(key),
                )
                else redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value[:10_000]]
    return value


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())


def looks_secret(value: str) -> bool:
    return any(pattern.search(value) for pattern in _PATTERNS) or (
        len(value) >= 32 and shannon_entropy(value) > 4.2 and " " not in value
    )


def csv_safe(value: Any) -> str:
    text = sanitize_text(str(value), max_length=32_768)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text
