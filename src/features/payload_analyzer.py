"""Payload pattern matching for application-layer attack detection.

Adapted from cognitive-anomaly-detector. Uses regex with timeout protection
to guard against ReDoS.
"""

import re
import signal
from typing import List, Optional
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
    """Match with SIGALRM timeout to prevent ReDoS hangs (Unix only)."""
    try:
        def _handler(sig, frame):
            raise TimeoutError()
        old = signal.signal(signal.SIGALRM, _handler)
        signal.alarm(MATCH_TIMEOUT_SECS)
        try:
            result = bool(pattern.search(data))
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
        return result
    except (TimeoutError, AttributeError):
        # AttributeError on Windows (no SIGALRM)
        return False


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
