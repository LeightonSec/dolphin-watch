"""Shared fixtures for dolphin-watch tests.

The tool ships as a single hyphenated script (``dolphin-watch.py``), which is not
a valid module name, so it is loaded from its file path via importlib. Tests also
synthesise classic PCAP byte streams in-memory (the tool has zero dependencies,
so fixtures are just crafted bytes — no scapy/pyshark needed).
"""
from __future__ import annotations

import struct
import logging
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_MODULE_PATH = _REPO_ROOT / "dolphin-watch.py"


def _load_dw():
    spec = importlib.util.spec_from_file_location("dolphin_watch", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def dw():
    """The loaded dolphin-watch module."""
    return _load_dw()


@pytest.fixture
def logger():
    """A quiet logger that discards output (tests assert on the report, not logs)."""
    lg = logging.getLogger("dolphin-watch-test")
    lg.handlers[:] = [logging.NullHandler()]
    lg.setLevel(logging.CRITICAL)
    return lg


# ── PCAP synthesis ──────────────────────────────────────────────────────────────

def _ip_octets(ip: str) -> bytes:
    return bytes(int(o) for o in ip.split("."))


def _make_frame(
    src_ip: str,
    dst_ip: str,
    payload: bytes,
    *,
    linktype: int = 0,          # LINKTYPE_NULL (macOS loopback) by default
    src_port: int = 51000,
    dst_port: int = 8080,
) -> bytes:
    """Build one raw link-layer frame carrying an IPv4/TCP segment with ``payload``."""
    if linktype == 0:           # BSD loopback: 4-byte address family (AF_INET=2)
        link = struct.pack("<I", 2)
    elif linktype == 1:         # Ethernet: 14-byte header (dst mac, src mac, ethertype)
        link = b"\x00" * 12 + b"\x08\x00"
    else:
        raise ValueError(f"unsupported linktype {linktype}")

    total_len = 20 + 20 + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, total_len, 0x0000, 0x0000, 64, 6, 0x0000,
        _ip_octets(src_ip), _ip_octets(dst_ip),
    )
    tcp = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, 0, 0,
        0x50,        # data offset = 5 words (20 bytes), no options
        0x18,        # PSH+ACK
        65535, 0, 0,
    )
    return link + ip + tcp + payload


def _make_pcap(packets, *, linktype: int = 0, endian: str = "<") -> bytes:
    """Assemble a classic PCAP from ``[(timestamp_float, frame_bytes), ...]``.

    ``endian='<'`` -> little-endian file (magic a1b2c3d4 read as LE).
    ``endian='>'`` -> big-endian file (the tool detects both byte orders).
    """
    e = endian
    header = struct.pack(f"{e}IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    out = [header]
    for ts, frame in packets:
        ts_sec = int(ts)
        ts_usec = int(round((ts - ts_sec) * 1_000_000))
        out.append(struct.pack(f"{e}IIII", ts_sec, ts_usec, len(frame), len(frame)))
        out.append(frame)
    return b"".join(out)


def _http(method: str, path: str) -> bytes:
    return f"{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode("latin-1")


@pytest.fixture
def build(tmp_path):
    """Builders for synthesising PCAP fixtures.

    - ``build.frame(src, dst, payload, **kw)`` -> one raw frame
    - ``build.get(path)`` / ``build.post(path)`` -> an HTTP request-line payload
    - ``build.pcap(packets, **kw)`` -> writes a PCAP file, returns its ``Path``
    - ``build.raw(packets, **kw)`` -> the PCAP bytes without touching disk
    - ``build.LOCAL`` -> the loopback IP both detectors treat as known-good
    """
    counter = {"n": 0}

    def write(packets, *, linktype: int = 0, endian: str = "<") -> Path:
        counter["n"] += 1
        p = tmp_path / f"capture-{counter['n']}.pcap"
        p.write_bytes(_make_pcap(packets, linktype=linktype, endian=endian))
        return p

    return SimpleNamespace(
        frame=_make_frame,
        get=lambda path: _http("GET", path),
        post=lambda path: _http("POST", path),
        pcap=write,
        raw=_make_pcap,
        LOCAL="127.0.0.1",
    )
