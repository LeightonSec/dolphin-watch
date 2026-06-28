"""PCAP validation and parsing — the untrusted-input boundary."""
import pytest


def test_validate_accepts_well_formed_pcap(dw, build):
    p = build.pcap([(0.0, build.frame(build.LOCAL, build.LOCAL, build.get("/health")))])
    data = dw._validate_pcap(p)
    assert isinstance(data, bytes) and len(data) >= dw.PCAP_GLOBAL_HEADER_LEN


def test_validate_rejects_missing_file(dw, tmp_path):
    with pytest.raises(ValueError, match="not found"):
        dw._validate_pcap(tmp_path / "nope.pcap")


def test_validate_rejects_directory(dw, tmp_path):
    with pytest.raises(ValueError, match="not a regular file"):
        dw._validate_pcap(tmp_path)


def test_validate_rejects_too_small(dw, tmp_path):
    p = tmp_path / "tiny.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1")  # 4 bytes — below the 24-byte global header
    with pytest.raises(ValueError, match="too small"):
        dw._validate_pcap(p)


def test_validate_rejects_bad_magic(dw, tmp_path, build):
    good = build.raw([(0.0, build.frame(build.LOCAL, build.LOCAL, build.get("/health")))])
    corrupt = b"\x00\x00\x00\x00" + good[4:]
    p = tmp_path / "bad.pcap"
    p.write_bytes(corrupt)
    with pytest.raises(ValueError, match="magic"):
        dw._validate_pcap(p)


def test_validate_rejects_oversize(dw, tmp_path, build, monkeypatch):
    monkeypatch.setattr(dw, "MAX_PCAP_BYTES", 32)  # force the size guard to trip
    p = build.pcap([(0.0, build.frame(build.LOCAL, build.LOCAL, build.get("/health")))])
    with pytest.raises(ValueError, match="exceeds"):
        dw._validate_pcap(p)


def test_parse_returns_one_tcp_packet(dw, build):
    p = build.pcap([(1.5, build.frame(build.LOCAL, build.LOCAL, build.get("/health")))])
    data = dw._validate_pcap(p)
    packets = dw._parse_pcap(data)
    assert len(packets) == 1
    ts, src, dst, payload = packets[0]
    assert ts == pytest.approx(1.5)
    assert src == build.LOCAL and dst == build.LOCAL
    assert b"GET /health" in payload


def test_parse_big_endian_pcap(dw, build):
    p = build.pcap(
        [(2.0, build.frame(build.LOCAL, build.LOCAL, build.get("/status")))],
        endian=">",
    )
    data = dw._validate_pcap(p)
    packets = dw._parse_pcap(data)
    assert len(packets) == 1
    assert b"GET /status" in packets[0][3]


def test_parse_ethernet_linktype(dw, build):
    p = build.pcap(
        [(0.0, build.frame(build.LOCAL, build.LOCAL, build.get("/status"), linktype=1))],
        linktype=1,
    )
    data = dw._validate_pcap(p)
    packets = dw._parse_pcap(data)
    assert len(packets) == 1
    assert b"GET /status" in packets[0][3]


def test_parse_empty_pcap_has_no_packets(dw, build):
    p = build.pcap([])
    data = dw._validate_pcap(p)
    assert dw._parse_pcap(data) == []


def test_packet_cap_is_enforced(dw, build, monkeypatch):
    monkeypatch.setattr(dw, "MAX_PACKETS", 3)
    pkts = [(float(i), build.frame(build.LOCAL, build.LOCAL, build.get("/health"))) for i in range(10)]
    data = dw._validate_pcap(build.pcap(pkts))
    assert len(dw._parse_pcap(data)) == 3
