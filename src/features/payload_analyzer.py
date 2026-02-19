"""Payload pattern matching for application-layer attack detection.

Adapted from cognitive-anomaly-detector. Uses regex with timeout protection
via threading to remain safe in worker threads.
"""

import re
import threading
from typing import List
from scapy.all import Raw


# Compiled patterns: (name, regex)
_PATTERNS: List[tuple] = [
    ("sql_injection",    re.compile(rb"(?:union\s+select|select\s+\*|drop\s+table|insert\s+into|delete\s+from|'.*?'|;--|xp_)", re.IGNORECASE)),
    ("xss",              re.compile(rb"(?:<script|javascript:|onerror=|onload=|<img\s|<svg\s|alert\()", re.IGNORECASE)),
    ("command_injection",re.compile(rb"(?:;\s*(?:ls|cat|wget|curl|bash|sh|python|perl)\b|&&\s*\w+|\|\s*\w+|`[^`]+`|\$\([^)]+\))", re.IGNORECASE)),
    ("path_traversal",   re.compile(rb"(?:\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e)", re.IGNORECASE)),
    ("log4j",            re.compile(rb"\$\{(?:jndi|env|sys|java):", re.IGNORECASE)),
    ("shellshock",       re.compile(rb"\(\s*\)\s*\{.*?;\s*\}", re.IGNORECASE)),
]

MATCH_TIMEOUT_SECS = 1


def _match_with_timeout(pattern: re.Pattern, data: bytes) -> bool:
    """Match with thread-based timeout to prevent ReDoS hangs."""
    result = [False]

    def _search():
        result[0] = bool(pattern.search(data))

    t = threading.Thread(target=_search, daemon=True)
    t.start()
    t.join(timeout=MATCH_TIMEOUT_SECS)
    return result[0]


def analyze_payload(packet) -> List[str]:
    """Return list of matched attack pattern names for this packet."""
    if Raw not in packet:
        return []
    payload = packet[Raw].load
    if not payload:
        return []
    # Limit to first 4KB to bound matching time
    sample = payload[:4096]
    matches = []
    for name, pattern in _PATTERNS:
        try:
            if _match_with_timeout(pattern, sample):
                matches.append(name)
        except Exception:
            pass
    return matches
