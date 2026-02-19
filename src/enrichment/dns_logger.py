"""DNS query logging from captured packets (Phase 8)."""

import logging
from typing import Optional, Dict

from scapy.all import IP, UDP, DNS, DNSQR

from ..config import DNS_LOGGING_ENABLED

logger = logging.getLogger(__name__)

# Recent DNS queries: {src_ip: [(timestamp, domain), ...]}
_dns_log: dict = {}
_MAX_PER_IP = 100


def extract_dns_query(packet) -> Optional[Dict]:
    """Extract DNS query info from a packet. Returns None if not a DNS query."""
    if not DNS_LOGGING_ENABLED:
        return None
    if not (IP in packet and UDP in packet and DNS in packet):
        return None
    dns = packet[DNS]
    if dns.qr != 0 or not dns.qd:  # qr=0 means query
        return None

    src_ip = packet[IP].src
    domain = dns[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
    qtype = dns[DNSQR].qtype

    entry = {
        "src_ip": src_ip,
        "domain": domain,
        "qtype": qtype,
    }

    # Store in memory log
    if src_ip not in _dns_log:
        _dns_log[src_ip] = []
    log = _dns_log[src_ip]
    log.append(domain)
    if len(log) > _MAX_PER_IP:
        _dns_log[src_ip] = log[-_MAX_PER_IP:]

    return entry


def get_dns_log(ip: str) -> list:
    """Return recent DNS queries for an IP."""
    return list(_dns_log.get(ip, []))


def get_all_logs() -> dict:
    """Return all DNS logs."""
    return {ip: list(domains) for ip, domains in _dns_log.items()}
