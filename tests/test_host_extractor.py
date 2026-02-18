"""Tests for the host-level feature extractor."""

import pytest
import numpy as np
from unittest.mock import MagicMock

from src.features.host_extractor import HostExtractor, HOST_FEATURE_NAMES


def _make_ip_packet(src="192.168.1.1", proto="TCP", dport=80, size=100):
    pkt = MagicMock()
    pkt.__len__ = lambda self: size

    from scapy.all import IP, TCP, UDP, ICMP, Raw
    ip = MagicMock()
    ip.src = src
    ip.proto = {"TCP": 6, "UDP": 17, "ICMP": 1}[proto]

    tcp = MagicMock()
    tcp.dport = dport
    tcp.payload = MagicMock()

    def contains(layer):
        if layer is IP:
            return True
        if layer is TCP:
            return proto == "TCP"
        if layer is UDP:
            return proto == "UDP"
        if layer is ICMP:
            return proto == "ICMP"
        return False

    pkt.__contains__ = lambda self, layer: contains(layer)
    pkt.__getitem__  = lambda self, layer: ip if layer is IP else tcp
    return pkt


def test_feature_name_count():
    assert len(HOST_FEATURE_NAMES) == 18


def test_no_features_before_min_packets():
    ext = HostExtractor()
    pkt = _make_ip_packet()
    ext.process_packet(pkt)
    ext.process_packet(pkt)
    features = ext.extract_features("192.168.1.1")
    assert features is None


def test_features_after_enough_packets():
    ext = HostExtractor()
    pkt = _make_ip_packet()
    for _ in range(5):
        ext.process_packet(pkt)
    features = ext.extract_features("192.168.1.1")
    assert features is not None
    assert features.shape == (18,)
    assert not np.any(np.isnan(features))


def test_unknown_ip_returns_none():
    ext = HostExtractor()
    assert ext.extract_features("99.99.99.99") is None


def test_multiple_ips_tracked():
    ext = HostExtractor()
    for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
        for _ in range(5):
            ext.process_packet(_make_ip_packet(src=ip))
    assert len(ext.tracked_ips()) == 3
