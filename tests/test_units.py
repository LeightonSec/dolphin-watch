"""Unit tests for the rate/interval helpers and low-level packet extraction."""
import struct

import pytest


@pytest.mark.parametrize("ip", ["127.0.0.1", "127.9.9.9", "0.0.0.0", "::1", ""])
def test_is_localhost_true(dw, ip):
    assert dw._is_localhost(ip) is True


@pytest.mark.parametrize("ip", ["10.0.0.1", "8.8.8.8", "203.0.113.4", "192.168.1.5"])
def test_is_localhost_false(dw, ip):
    assert dw._is_localhost(ip) is False


def test_rate_window_below_two_is_zero(dw):
    w = dw._RateWindow()
    w.record(0.0)
    assert w.rate_per_min(0.0) == 0.0


def test_rate_window_basic_rate(dw):
    w = dw._RateWindow()
    w.record(0.0)
    w.record(1.0)
    assert w.rate_per_min(1.0) == pytest.approx(120.0)


def test_rate_window_evicts_old_samples(dw):
    w = dw._RateWindow(window_sec=10)
    w.record(0.0)
    w.record(100.0)
    w.record(101.0)
    # the 0.0 sample is outside the 10s window at now=101
    assert w.rate_per_min(101.0) == pytest.approx(120.0)


def test_interval_tracker(dw):
    t = dw._IntervalTracker()
    assert t.observe(0.0) is None       # first observation primes the tracker
    assert t.observe(2.0) == pytest.approx(2.0)
    assert t.observe(5.0) == pytest.approx(3.0)
    assert t.min_interval() == pytest.approx(2.0)
    assert t.median_interval() in (pytest.approx(2.0), pytest.approx(3.0))


def test_interval_tracker_empty(dw):
    t = dw._IntervalTracker()
    assert t.min_interval() is None
    assert t.median_interval() is None


def _null_ip_frame(proto, version=4, src=b"\x7f\x00\x00\x01", dst=b"\x7f\x00\x00\x01"):
    ihl_ver = (version << 4) | 5
    ip = struct.pack("!BBHHHBBH4s4s", ihl_ver, 0, 40, 0, 0, 64, proto, 0, src, dst)
    tcp_or_udp = b"\x00" * 20
    return struct.pack("<I", 2) + ip + tcp_or_udp


def test_extract_payload_non_tcp_returns_no_payload(dw):
    src, dst, payload = dw._extract_payload(_null_ip_frame(proto=17), 0)  # UDP
    assert src == "127.0.0.1" and dst == "127.0.0.1"
    assert payload is None


def test_extract_payload_ignores_ipv6(dw):
    assert dw._extract_payload(_null_ip_frame(proto=6, version=6), 0) == (None, None, None)


def test_extract_payload_unknown_linktype(dw):
    assert dw._extract_payload(b"\x00" * 64, 99) == (None, None, None)


def test_extract_payload_truncated_buffer(dw):
    assert dw._extract_payload(b"\x02\x00\x00\x00\x45", 0) == (None, None, None)


def test_extract_requests_parses_request_line(dw):
    payload = b"POST /createSignature HTTP/1.1\r\nHost: x\r\n\r\n"
    out = dw._extract_requests(payload)
    assert out == [("POST /createSignature", "POST", "/createSignature")]


def test_extract_requests_ignores_non_http(dw):
    assert dw._extract_requests(b"\x00\x01\x02 not http at all") == []
