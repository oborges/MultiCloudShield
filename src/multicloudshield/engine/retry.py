from __future__ import annotations

import random


def backoff_delay(attempt: int, *, base: float = 0.25, cap: float = 8.0) -> float:
    upper = min(cap, base * (2**attempt))
    return random.SystemRandom().uniform(0, upper)
