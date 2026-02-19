"""Confidence decay — reduce score for repeated alerts from the same IP (Phase 9).

Prevents alert fatigue from persistent scanners by applying exponential
decay to the ensemble score based on recent alert count.
"""

import threading
import time
from collections import defaultdict

from ..config import CONFIDENCE_DECAY_FACTOR, CONFIDENCE_DECAY_WINDOW

_hits: dict = defaultdict(list)  # ip -> [timestamp, ...]
_lock = threading.Lock()


def apply_decay(ip: str, score: float) -> float:
    """Apply exponential decay based on recent alert count for this IP."""
    now = time.time()
    cutoff = now - CONFIDENCE_DECAY_WINDOW

    with _lock:
        _hits[ip] = [t for t in _hits[ip] if t > cutoff]
        repeat_count = len(_hits[ip])
        _hits[ip].append(now)

    if repeat_count == 0:
        return score
    return score * (CONFIDENCE_DECAY_FACTOR ** repeat_count)


def recent_alert_count(ip: str) -> int:
    """Return number of recent alerts for this IP within the decay window."""
    now = time.time()
    cutoff = now - CONFIDENCE_DECAY_WINDOW
    with _lock:
        return sum(1 for t in _hits.get(ip, []) if t > cutoff)
