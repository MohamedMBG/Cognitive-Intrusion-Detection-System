"""IP allowlist and blocklist (Phase 9).

Allowlisted IPs bypass detection entirely.
Blocklisted IPs are auto-flagged with score=1.0.
"""

from ..config import IP_ALLOWLIST, IP_BLOCKLIST


def is_allowlisted(ip: str) -> bool:
    return ip in IP_ALLOWLIST


def is_blocklisted(ip: str) -> bool:
    return ip in IP_BLOCKLIST
