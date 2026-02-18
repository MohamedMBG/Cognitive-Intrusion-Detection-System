"""Tests for the CICFlowMeter-compatible flow extractor."""

import time
import pytest
import numpy as np
from unittest.mock import MagicMock, patch

from src.features.flow_extractor import FlowExtractor, FlowRecord, FLOW_FEATURE_NAMES


def _make_tcp_packet(src="192.168.1.1", dst="10.0.0.1", sport=12345, dport=80,
                     size=100, flags=0x02):
    """Create a minimal mock Scapy TCP packet."""
    pkt = MagicMock()
    pkt.__len__ = lambda self: size
    pkt.__contains__ = lambda self, layer: layer.__name__ in ("IP", "TCP")

    ip = MagicMock()
    ip.src = src
    ip.dst = dst
    ip.proto = 6
    ip.ihl = 5

    tcp = MagicMock()
    tcp.sport = sport
    tcp.dport = dport
    tcp.flags = flags
    tcp.window = 65535
    tcp.payload = MagicMock()

    from scapy.all import IP, TCP
    pkt.__getitem__ = lambda self, layer: ip if layer is IP else tcp
    return pkt


def test_feature_vector_length():
    """FlowRecord.to_feature_vector() must produce exactly 78 features."""
    rec = FlowRecord(key=("1.2.3.4", "5.6.7.8", 1234, 80, 6))
    rec.start_time = time.time() - 1
    rec.last_time  = time.time()
    rec.fwd_lengths = [100, 200, 150]
    rec.bwd_lengths = [80, 90]
    rec.fwd_times   = [rec.start_time, rec.start_time + 0.1, rec.start_time + 0.3]
    rec.bwd_times   = [rec.start_time + 0.05, rec.start_time + 0.2]
    rec._current_active_start = rec.start_time

    vec = rec.to_feature_vector()
    assert vec is not None
    assert len(vec) == 78
    assert len(FLOW_FEATURE_NAMES) == 78


def test_feature_names_count():
    assert len(FLOW_FEATURE_NAMES) == 78


def test_insufficient_packets():
    rec = FlowRecord(key=("1.2.3.4", "5.6.7.8", 1234, 80, 6))
    rec.start_time = time.time()
    rec.last_time  = time.time()
    rec.fwd_lengths = [100]
    assert rec.to_feature_vector() is None


def test_extractor_flow_count():
    extractor = FlowExtractor()
    assert extractor.active_flow_count == 0


def test_expired_flows_collected():
    """Flows older than FLOW_TIMEOUT should be returned by collect_expired."""
    import src.features.flow_extractor as fe_mod
    original_timeout = fe_mod.FLOW_TIMEOUT

    # Patch timeout to 0 so every flow is immediately expired
    fe_mod.FLOW_TIMEOUT = 0
    extractor = FlowExtractor()

    rec = FlowRecord(key=("1.1.1.1", "2.2.2.2", 100, 80, 6))
    rec.start_time = time.time() - 2
    rec.last_time  = time.time() - 2
    rec.fwd_lengths = [100, 200, 150]
    rec.bwd_lengths = [80]
    rec.fwd_times   = [rec.start_time]
    rec.bwd_times   = [rec.start_time + 0.05]
    rec._current_active_start = rec.start_time

    extractor._flows[rec.key] = rec
    expired = extractor.collect_expired()

    fe_mod.FLOW_TIMEOUT = original_timeout
    assert len(expired) == 1
    assert expired[0][1].shape == (78,)
