"""Tests for payload feature extraction."""

import numpy as np
import pytest

from src.features.payload_analyzer import (
    extract_payload_features,
    PAYLOAD_FEATURE_NAMES,
    PATTERN_NAMES,
)


def test_feature_names_count():
    assert len(PAYLOAD_FEATURE_NAMES) == 10


def test_empty_payloads():
    vec = extract_payload_features([])
    assert vec.shape == (10,)
    assert np.all(vec == 0.0)


def test_benign_payload():
    vec = extract_payload_features([b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"])
    assert vec.shape == (10,)
    # No patterns should match
    assert vec[6] == 0.0  # pattern_match_count
    # Should have some entropy and length
    assert vec[7] > 0.0   # max_payload_entropy
    assert vec[8] > 0.0   # mean_payload_length


def test_sqli_detected():
    vec = extract_payload_features([b"GET /search?q=1' UNION SELECT * FROM users-- HTTP/1.1"])
    assert vec[0] == 1.0   # has_sqli
    assert vec[6] >= 1.0   # pattern_match_count


def test_xss_detected():
    vec = extract_payload_features([b"POST /comment body=<script>alert(1)</script>"])
    assert vec[1] == 1.0   # has_xss
    assert vec[6] >= 1.0


def test_multiple_patterns():
    payload = b"<script>alert(1)</script>; cat /etc/passwd | grep root"
    vec = extract_payload_features([payload])
    assert vec[1] == 1.0   # has_xss
    assert vec[2] == 1.0   # has_cmdi
    assert vec[6] >= 2.0   # at least 2 patterns


def test_multiple_payloads_aggregated():
    payloads = [
        b"GET /index.html HTTP/1.1",
        b"GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1",
    ]
    vec = extract_payload_features(payloads)
    assert vec[0] == 1.0   # sqli found in second payload
    assert vec[8] > 0.0    # mean_payload_length across both


def test_suspicious_char_ratio():
    # Payload with many control characters
    payload = bytes(range(0, 16)) * 10  # 160 bytes of control chars
    vec = extract_payload_features([payload])
    # 0x09, 0x0A, 0x0D are excluded from suspicious count = 3 bytes * 10 = 30 non-suspicious
    # 13 suspicious chars * 10 = 130 suspicious out of 160
    assert vec[9] > 0.5


def test_path_traversal_detected():
    vec = extract_payload_features([b"GET /../../etc/passwd HTTP/1.1"])
    assert vec[3] == 1.0   # has_traversal


def test_pattern_names_match_patterns():
    assert len(PATTERN_NAMES) == 6
