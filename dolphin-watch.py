#!/usr/bin/env python3
"""
dolphin-watch: Defensive traffic monitor for dolphin-milk BSV AI agents.

Parses PCAP files, extracts HTTP endpoints, compares against a known baseline,
and generates structured JSON anomaly reports. Zero network calls. Zero payload logging.
"""

import os
import re
import sys
import json
import struct
import logging
import argparse
import datetime
from pathlib import Path
from collections import defaultdict, deque
from typing import Optional

# ── Security limits ────────────────────────────────────────────────────────────
MAX_PCAP_BYTES = 100 * 1024 * 1024          # 100 MB hard limit
MAX_ENDPOINT_LENGTH = 256                    # max sanitised endpoint string
MAX_PACKETS = 2_000_000                      # safety cap on loop iterations

# ── PCAP format constants ──────────────────────────────────────────────────────
PCAP_MAGIC_LE = 0xa1b2c3d4
PCAP_MAGIC_BE = 0xd4c3b2a1
PCAP_GLOBAL_HEADER_LEN = 24
PCAP_PKT_HEADER_LEN = 16
LINKTYPE_NULL = 0      # BSD loopback (what macOS tcpdump produces for localhost)
LINKTYPE_ETHERNET = 1

# ── Baseline configuration ─────────────────────────────────────────────────────
# Endpoints observed in the actual baseline PCAP (POST /listCertificates appears
# in captured traffic even though omitted from the spec — included here as known-good).
BASELINE_ENDPOINTS: frozenset[str] = frozenset({
    "POST /createSignature",
    "POST /verifySignature",
    "POST /verifyHmac",
    "GET /budget",
    "GET /health",
    "GET /task/{id}/events",   # normalised form; raw UUIDs are replaced at parse time
    "POST /chat",
    "GET /agent",
    "POST /listOutputs",
    "POST /getPublicKey",
    "POST /encrypt",
    "POST /createAction",
    "POST /listCertificates",  # present in baseline PCAP, treated as known-good
    # Action lifecycle
    "POST /signAction",
    "POST /abortAction",
    "POST /listActions",
    "POST /relinquishOutput",
    "POST /internalizeAction",
    # Crypto / key management
    "POST /createHmac",
    "POST /decrypt",
    "POST /proveCertificate",
    "POST /acquireCertificate",
    "POST /revealCounterpartyKeyLinkage",  # BRC-69 audit
    "POST /revealSpecificKeyLinkage",      # BRC-69 audit
    # Identity discovery (BRC-56)
    "POST /discoverByIdentityKey",
    "POST /discoverByAttributes",
    # Conversations
    "GET /conversations",
    "POST /listConversations",
    "GET /conversations/{id}",  # normalised form; raw UUIDs are replaced at parse time
    # MessageBox (BRC-33)
    "POST /sendMessage",
    "POST /listIncomingTransactions",
    "POST /acknowledgeMessage",
    # Status
    "GET /status",
    # OPTIONS CORS preflight — web UI sends these before every wallet API call
    "OPTIONS /chat",
    "OPTIONS /createSignature",
    "OPTIONS /verifySignature",
    "OPTIONS /verifyHmac",
    "OPTIONS /createHmac",
    "OPTIONS /getPublicKey",
    "OPTIONS /encrypt",
    "OPTIONS /decrypt",
    "OPTIONS /createAction",
    "OPTIONS /signAction",
    "OPTIONS /abortAction",
    "OPTIONS /listOutputs",
    "OPTIONS /listActions",
    "OPTIONS /listCertificates",
    "OPTIONS /proveCertificate",
    "OPTIONS /acquireCertificate",
    "OPTIONS /internalizeAction",
    "OPTIONS /relinquishOutput",
    "OPTIONS /discoverByIdentityKey",
    "OPTIONS /discoverByAttributes",
    "OPTIONS /sendMessage",
    "OPTIONS /listIncomingTransactions",
    "OPTIONS /acknowledgeMessage",
    "OPTIONS /revealCounterpartyKeyLinkage",
    "OPTIONS /revealSpecificKeyLinkage",
})

# Expected call rates (calls/minute) derived from baseline PCAP analysis
BASELINE_RATES: dict[str, float] = {
    "POST /createSignature": 50.0,
    "GET /budget": 12.0,   # ~5-second polling interval → 12/min
    "GET /health": 2.0,    # ~30-second polling interval → 2/min
}

# Polling interval baselines (seconds)
BASELINE_INTERVALS: dict[str, float] = {
    "GET /budget": 5.0,
    "GET /health": 30.0,
}

# Rate alert thresholds
SIGNATURE_MAX_PER_MIN = 150      # hard cap; baseline is ~50
BUDGET_MIN_INTERVAL_SEC = 3.0          # alert if polling faster than this (calibrated)
BUDGET_MIN_INTERVAL_SEC_STRICT = 10.0  # --strict: original pre-calibration value
BASELINE_INTERVAL_BUDGET_STRICT = 30.0 # --strict: budget polling baseline
BASELINE_RATE_BUDGET_STRICT = 2.0      # --strict: budget call rate
HEALTH_DEVIATION_MAX_SEC = 15.0        # alert if median interval deviates more than this
TOTAL_MAX_RPM = 500              # global request volume cap
RATE_SPIKE_MULTIPLIER = 3.0      # flag if any endpoint exceeds 3x baseline rate
RATE_WINDOW_SEC = 60             # sliding window for rate calculations

# Sequence constraints
AGENT_CHAT_MAX_GAP_SEC = 300    # GET /agent must precede POST /chat within this window
CHAT_TASK_MAX_GAP_SEC = 120     # POST /chat expected before new task ID within this window

# Agentic danger endpoints — any appearance is HIGH severity
DANGER_ENDPOINTS: frozenset[str] = frozenset({
    "POST /spawn_agent",
    "POST /delegate_task",
    "POST /execute_bash",
})

DANGER_DETAILS: dict[str, str] = {
    "POST /spawn_agent":    "Sub-agent creation detected — must be explicit and logged",
    "POST /delegate_task":  "Task delegation without verified auth context",
    "POST /execute_bash":   "Shell execution by agent — critical risk",
}

# ── Sanitisation ───────────────────────────────────────────────────────────────
_ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})

# Only these characters are permitted in a sanitised path
_SAFE_PATH_RE = re.compile(r"[^\w/\-\.{}\?=&%+]")

# Regex to detect and normalise task-event paths before comparison
_TASK_UUID_PATH_RE = re.compile(
    r"^/task/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/events",
    re.IGNORECASE,
)

# Regex to detect and normalise conversation paths before comparison
_CONVERSATIONS_UUID_PATH_RE = re.compile(
    r"^/conversations/(?:conv-)?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
    re.IGNORECASE,
)

# HTTP/1.x request line pattern applied to raw bytes
_HTTP_LINE_RE = re.compile(
    rb"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"
    rb" "
    rb"(/[^\x00-\x1f\r\n ]{0,512})"
    rb" HTTP/[\d.]+",
)


def _sanitize_endpoint(method: str, raw_path: str) -> Optional[str]:
    """
    Sanitise a method + path pair extracted from untrusted packet data.
    Returns None if the endpoint fails validation.
    Never raises — all errors become None.
    """
    try:
        if method not in _ALLOWED_METHODS:
            return None

        # Strip query string from the path used for comparison
        path = raw_path.split("?")[0]

        # Remove any character not on the safe allowlist
        path = _SAFE_PATH_RE.sub("", path)

        if not path.startswith("/"):
            return None
        if len(path) > MAX_ENDPOINT_LENGTH:
            path = path[:MAX_ENDPOINT_LENGTH]

        # Normalise task UUIDs so all task-event paths compare as one canonical form
        if _TASK_UUID_PATH_RE.match(path):
            path = "/task/{id}/events"

        # Normalise conversation UUIDs the same way
        if _CONVERSATIONS_UUID_PATH_RE.match(path):
            path = "/conversations/{id}"

        return f"{method} {path}"
    except Exception:
        return None


def _extract_task_uuid(raw_path: str) -> Optional[str]:
    """Return the raw UUID from a task-event path, or None."""
    m = _TASK_UUID_PATH_RE.match(raw_path)
    return m.group(1).lower() if m else None


# ── PCAP parsing (pure stdlib, no external deps) ───────────────────────────────

def _validate_pcap(path: Path) -> bytes:
    """Read and validate a PCAP file. Raises ValueError on any problem."""
    if not path.exists():
        raise ValueError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {path}")

    size = path.stat().st_size
    if size > MAX_PCAP_BYTES:
        raise ValueError(
            f"File size {size:,} bytes exceeds 100 MB limit — refusing to process"
        )
    if size < PCAP_GLOBAL_HEADER_LEN:
        raise ValueError("File too small to contain a valid PCAP global header")

    data = path.read_bytes()

    magic = struct.unpack("<I", data[:4])[0]
    if magic not in (PCAP_MAGIC_LE, PCAP_MAGIC_BE):
        raise ValueError(
            f"Invalid PCAP magic: {hex(magic)} — not a classic pcap file"
        )

    return data


def _extract_payload(pkt: bytes, linktype: int) -> tuple[Optional[str], Optional[str], Optional[bytes]]:
    """
    Extract (src_ip, dst_ip, tcp_payload) from one raw packet buffer.
    Only IPv4/TCP is handled. Returns (None, None, None) on any parse error.
    """
    try:
        # Strip link-layer header
        if linktype == LINKTYPE_NULL:
            if len(pkt) < 4:
                return None, None, None
            ip = pkt[4:]
        elif linktype == LINKTYPE_ETHERNET:
            if len(pkt) < 14:
                return None, None, None
            ip = pkt[14:]
        else:
            return None, None, None

        if len(ip) < 20:
            return None, None, None

        version = (ip[0] >> 4) & 0xF
        if version != 4:
            return None, None, None

        ihl = (ip[0] & 0xF) * 4
        if ihl < 20 or len(ip) < ihl:
            return None, None, None

        protocol = ip[9]
        src_ip = f"{ip[12]}.{ip[13]}.{ip[14]}.{ip[15]}"
        dst_ip = f"{ip[16]}.{ip[17]}.{ip[18]}.{ip[19]}"

        if protocol != 6:   # TCP only
            return src_ip, dst_ip, None

        tcp = ip[ihl:]
        if len(tcp) < 20:
            return src_ip, dst_ip, None

        data_offset = ((tcp[12] >> 4) & 0xF) * 4
        if data_offset < 20 or len(tcp) < data_offset:
            return src_ip, dst_ip, None

        payload = tcp[data_offset:]
        return src_ip, dst_ip, (payload if payload else None)

    except (IndexError, struct.error):
        return None, None, None


def _parse_pcap(data: bytes) -> list[tuple[float, str, str, bytes]]:
    """
    Iterate over a classic PCAP and return a list of
    (timestamp_float, src_ip, dst_ip, tcp_payload) for every TCP packet.
    Packet bodies are NOT decoded here — only raw bytes are returned.
    """
    magic = struct.unpack("<I", data[:4])[0]
    endian = "<" if magic == PCAP_MAGIC_LE else ">"
    linktype = struct.unpack(f"{endian}I", data[20:24])[0]

    results = []
    offset = PCAP_GLOBAL_HEADER_LEN
    count = 0

    while offset + PCAP_PKT_HEADER_LEN <= len(data) and count < MAX_PACKETS:
        ts_sec, ts_usec, incl_len, _ = struct.unpack(
            f"{endian}IIII", data[offset: offset + PCAP_PKT_HEADER_LEN]
        )
        offset += PCAP_PKT_HEADER_LEN

        if incl_len > len(data) - offset:
            break   # truncated file

        pkt = data[offset: offset + incl_len]
        offset += incl_len
        count += 1

        timestamp = ts_sec + ts_usec / 1_000_000
        src_ip, dst_ip, payload = _extract_payload(pkt, linktype)

        if payload and src_ip and dst_ip:
            results.append((timestamp, src_ip, dst_ip, payload))

    return results


def _extract_requests(payload: bytes) -> list[tuple[str, str, str]]:
    """
    Extract sanitised (endpoint, method, raw_path) tuples from one TCP payload.
    Payload content is NEVER stored or logged — only the request line is used.
    """
    results = []
    for m in _HTTP_LINE_RE.finditer(payload):
        try:
            method = m.group(1).decode("ascii")
            raw_path = m.group(2).decode("latin-1", errors="replace")
            endpoint = _sanitize_endpoint(method, raw_path)
            if endpoint:
                results.append((endpoint, method, raw_path))
        except Exception:
            continue
    return results


# ── Rate tracking helpers ──────────────────────────────────────────────────────

class _RateWindow:
    """Sliding-window request counter."""

    def __init__(self, window_sec: float = RATE_WINDOW_SEC):
        self._window = window_sec
        self._times: deque[float] = deque()

    def record(self, ts: float) -> None:
        self._times.append(ts)
        self._evict(ts)

    def _evict(self, now: float) -> None:
        cutoff = now - self._window
        while self._times and self._times[0] < cutoff:
            self._times.popleft()

    def rate_per_min(self, now: float) -> float:
        self._evict(now)
        if len(self._times) < 2:
            return 0.0
        span_sec = max(now - self._times[0], 1.0)
        return (len(self._times) / span_sec) * 60.0


class _IntervalTracker:
    """Tracks call intervals for polling endpoints."""

    def __init__(self):
        self._last: Optional[float] = None
        self._intervals: list[float] = []

    def observe(self, ts: float) -> Optional[float]:
        if self._last is None:
            self._last = ts
            return None
        gap = ts - self._last
        self._last = ts
        if gap > 0:
            self._intervals.append(gap)
        return gap

    def min_interval(self) -> Optional[float]:
        return min(self._intervals) if self._intervals else None

    def median_interval(self) -> Optional[float]:
        if not self._intervals:
            return None
        s = sorted(self._intervals)
        return s[len(s) // 2]


# ── Core analysis ──────────────────────────────────────────────────────────────

def _is_localhost(ip: str) -> bool:
    return ip.startswith("127.") or ip in ("0.0.0.0", "::1", "")


def analyse(pcap_path: Path, logger: logging.Logger, strict: bool = False) -> dict:
    """
    Parse the PCAP and return a structured report dict.
    All anomaly detection logic lives here.
    """
    budget_min_interval  = BUDGET_MIN_INTERVAL_SEC_STRICT  if strict else BUDGET_MIN_INTERVAL_SEC
    budget_interval_base = BASELINE_INTERVAL_BUDGET_STRICT if strict else BASELINE_INTERVALS["GET /budget"]
    budget_rate_base     = BASELINE_RATE_BUDGET_STRICT     if strict else BASELINE_RATES["GET /budget"]
    effective_rates      = {**BASELINE_RATES, "GET /budget": budget_rate_base}

    raw = _validate_pcap(pcap_path)
    packets = _parse_pcap(raw)
    logger.info("Parsed %d TCP packets from %s", len(packets), pcap_path.name)

    anomalies: list[dict] = []
    endpoint_counts: defaultdict[str, int] = defaultdict(int)
    rate_windows: defaultdict[str, _RateWindow] = defaultdict(_RateWindow)
    interval_trackers: defaultdict[str, _IntervalTracker] = defaultdict(_IntervalTracker)
    total_rate = _RateWindow()

    # Sequence tracking
    last_agent_ts: Optional[float] = None
    last_chat_ts: Optional[float] = None
    seen_task_ids: set[str] = set()
    external_ips: set[str] = set()

    # Deduplicate anomalies that fire per-packet (e.g. rate breaches)
    _rate_alerted: set[str] = set()

    for ts, src_ip, dst_ip, payload in packets:

        # External IP detection — any non-localhost address is immediately HIGH
        for ip in (src_ip, dst_ip):
            if ip and not _is_localhost(ip) and ip not in external_ips:
                external_ips.add(ip)
                anomalies.append({
                    "severity": "HIGH",
                    "type": "external_ip",
                    "endpoint": None,
                    "timestamp": ts,
                    "detail": f"Non-localhost IP in agent traffic: {ip}",
                })
                logger.warning("HIGH [external_ip] %s at %.3f", ip, ts)

        total_rate.record(ts)

        for endpoint, method, raw_path in _extract_requests(payload):
            endpoint_counts[endpoint] += 1
            rate_windows[endpoint].record(ts)

            # ── Interval tracking for known polling endpoints ──────────────
            if endpoint in ("GET /budget", "GET /health"):
                gap = interval_trackers[endpoint].observe(ts)

                if endpoint == "GET /budget" and gap is not None and gap < budget_min_interval:
                    anomalies.append({
                        "severity": "HIGH",
                        "type": "polling_interval",
                        "endpoint": endpoint,
                        "timestamp": ts,
                        "detail": (
                            f"/budget polling interval {gap:.2f}s dropped below "
                            f"{budget_min_interval}s minimum"
                        ),
                        "observed_interval_sec": round(gap, 3),
                        "baseline_interval_sec": budget_interval_base,
                    })
                    logger.warning(
                        "HIGH [polling_interval] %s gap=%.2fs at %.3f", endpoint, gap, ts
                    )

            # ── Sequence: GET /agent → POST /chat ────────────────────────
            if endpoint == "GET /agent":
                last_agent_ts = ts

            if endpoint == "POST /chat":
                last_chat_ts = ts
                if (
                    last_agent_ts is None
                    or (ts - last_agent_ts) > AGENT_CHAT_MAX_GAP_SEC
                ):
                    anomalies.append({
                        "severity": "HIGH",
                        "type": "sequence_violation",
                        "endpoint": endpoint,
                        "timestamp": ts,
                        "detail": "POST /chat fired without a preceding GET /agent within 5 minutes",
                    })
                    logger.warning("HIGH [sequence_violation] /chat without /agent at %.3f", ts)

            # ── New task ID without preceding POST /chat (MEDIUM) ─────────
            if endpoint == "GET /task/{id}/events":
                task_id = _extract_task_uuid(raw_path)
                if task_id and task_id not in seen_task_ids:
                    seen_task_ids.add(task_id)
                    if (
                        last_chat_ts is None
                        or (ts - last_chat_ts) > CHAT_TASK_MAX_GAP_SEC
                    ):
                        anomalies.append({
                            "severity": "MEDIUM",
                            "type": "task_without_chat",
                            "endpoint": endpoint,
                            "timestamp": ts,
                            "detail": (
                                "New task ID appeared without a preceding POST /chat "
                                "within 2 minutes"
                            ),
                        })
                        logger.warning(
                            "MEDIUM [task_without_chat] new task at %.3f", ts
                        )

            # ── Agentic danger endpoints ──────────────────────────────────
            if endpoint in DANGER_ENDPOINTS:
                anomalies.append({
                    "severity": "HIGH",
                    "type": "agentic_danger",
                    "endpoint": endpoint,
                    "timestamp": ts,
                    "detail": DANGER_DETAILS.get(endpoint, f"Danger endpoint: {endpoint}"),
                })
                logger.warning("HIGH [agentic_danger] %s at %.3f", endpoint, ts)

            # ── Unknown endpoint ──────────────────────────────────────────
            elif endpoint not in BASELINE_ENDPOINTS:
                anomalies.append({
                    "severity": "HIGH",
                    "type": "unknown_endpoint",
                    "endpoint": endpoint,
                    "timestamp": ts,
                    "detail": f"Unrecognised endpoint not in baseline: {endpoint}",
                })
                logger.warning("HIGH [unknown_endpoint] %s at %.3f", endpoint, ts)

    # ── Post-loop rate analysis (uses final timestamp as "now") ───────────────
    if not packets:
        final_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()
    else:
        final_ts = max(p[0] for p in packets)

    # Total volume check
    total_rpm = total_rate.rate_per_min(final_ts)
    if total_rpm > TOTAL_MAX_RPM:
        anomalies.append({
            "severity": "HIGH",
            "type": "rate_limit_total",
            "endpoint": "*",
            "timestamp": final_ts,
            "detail": f"Total request volume {total_rpm:.1f} RPM exceeds {TOTAL_MAX_RPM} RPM limit",
            "observed_rate_rpm": round(total_rpm, 2),
            "baseline_rate_rpm": TOTAL_MAX_RPM,
        })
        logger.warning("HIGH [rate_limit_total] %.1f RPM at %.3f", total_rpm, final_ts)

    # Per-endpoint rate checks
    for endpoint, window in rate_windows.items():
        rate = window.rate_per_min(final_ts)
        baseline = effective_rates.get(endpoint)

        if endpoint == "POST /createSignature":
            if rate > SIGNATURE_MAX_PER_MIN:
                anomalies.append({
                    "severity": "HIGH",
                    "type": "rate_limit",
                    "endpoint": endpoint,
                    "timestamp": final_ts,
                    "detail": (
                        f"createSignature {rate:.1f} RPM exceeds hard cap of "
                        f"{SIGNATURE_MAX_PER_MIN} RPM (baseline: {BASELINE_RATES[endpoint]} RPM)"
                    ),
                    "observed_rate_rpm": round(rate, 2),
                    "baseline_rate_rpm": BASELINE_RATES[endpoint],
                })
                logger.warning(
                    "HIGH [rate_limit] %s %.1f RPM at %.3f", endpoint, rate, final_ts
                )
            elif baseline and rate > RATE_SPIKE_MULTIPLIER * baseline:
                anomalies.append({
                    "severity": "HIGH",
                    "type": "rate_spike",
                    "endpoint": endpoint,
                    "timestamp": final_ts,
                    "detail": (
                        f"{endpoint} rate {rate:.1f} RPM is "
                        f"{rate/baseline:.1f}x baseline of {baseline} RPM"
                    ),
                    "observed_rate_rpm": round(rate, 2),
                    "baseline_rate_rpm": baseline,
                })
                logger.warning(
                    "HIGH [rate_spike] %s %.1f RPM (%.1fx) at %.3f",
                    endpoint, rate, rate / baseline, final_ts,
                )

        elif baseline and rate > RATE_SPIKE_MULTIPLIER * baseline:
            anomalies.append({
                "severity": "HIGH",
                "type": "rate_spike",
                "endpoint": endpoint,
                "timestamp": final_ts,
                "detail": (
                    f"{endpoint} rate {rate:.1f} RPM is "
                    f"{rate/baseline:.1f}x baseline of {baseline} RPM"
                ),
                "observed_rate_rpm": round(rate, 2),
                "baseline_rate_rpm": baseline,
            })
            logger.warning(
                "HIGH [rate_spike] %s %.1f RPM (%.1fx) at %.3f",
                endpoint, rate, rate / baseline, final_ts,
            )

    # Health interval deviation (MEDIUM — checked post-loop on median)
    health_tracker = interval_trackers.get("GET /health")
    if health_tracker:
        median = health_tracker.median_interval()
        if median is not None:
            deviation = abs(median - BASELINE_INTERVALS["GET /health"])
            if deviation > HEALTH_DEVIATION_MAX_SEC:
                anomalies.append({
                    "severity": "MEDIUM",
                    "type": "polling_interval",
                    "endpoint": "GET /health",
                    "timestamp": final_ts,
                    "detail": (
                        f"/health median interval {median:.1f}s deviates {deviation:.1f}s "
                        f"from {BASELINE_INTERVALS['GET /health']}s baseline "
                        f"(allowed deviation: ±{HEALTH_DEVIATION_MAX_SEC}s)"
                    ),
                    "observed_interval_sec": round(median, 3),
                    "baseline_interval_sec": BASELINE_INTERVALS["GET /health"],
                })
                logger.warning(
                    "MEDIUM [polling_interval] /health median=%.1fs deviation=%.1fs at %.3f",
                    median, deviation, final_ts,
                )

    # ── Build report ──────────────────────────────────────────────────────────
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in anomalies:
        sev = a.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    run_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    summary = (
        f"[{run_ts}] dolphin-watch | {pcap_path.name} | "
        f"{len(packets)} pkts | "
        f"{sum(endpoint_counts.values())} HTTP reqs | "
        f"{len(anomalies)} anomalies "
        f"(HIGH:{severity_counts['HIGH']} MED:{severity_counts['MEDIUM']} LOW:{severity_counts['LOW']})"
    )

    return {
        "schema_version": "1.0",
        "strict_mode": strict,
        "timestamp": run_ts,
        "pcap_file": pcap_path.name,
        "total_packets_analysed": len(packets),
        "total_http_requests": sum(endpoint_counts.values()),
        "unique_endpoints_observed": len(endpoint_counts),
        "endpoint_frequencies": dict(
            sorted(endpoint_counts.items(), key=lambda kv: -kv[1])
        ),
        "rate_analysis": {
            "window_seconds": RATE_WINDOW_SEC,
            "total_rpm_at_end": round(total_rpm, 2),
            "per_endpoint_rpm": {
                ep: round(rate_windows[ep].rate_per_min(final_ts), 2)
                for ep in sorted(rate_windows)
            },
        },
        "interval_analysis": {
            "GET /budget": {
                "min_interval_sec": (
                    round(interval_trackers["GET /budget"].min_interval(), 3)
                    if interval_trackers.get("GET /budget")
                    and interval_trackers["GET /budget"].min_interval() is not None
                    else None
                ),
                "median_interval_sec": (
                    round(interval_trackers["GET /budget"].median_interval(), 3)
                    if interval_trackers.get("GET /budget")
                    and interval_trackers["GET /budget"].median_interval() is not None
                    else None
                ),
            },
            "GET /health": {
                "min_interval_sec": (
                    round(interval_trackers["GET /health"].min_interval(), 3)
                    if interval_trackers.get("GET /health")
                    and interval_trackers["GET /health"].min_interval() is not None
                    else None
                ),
                "median_interval_sec": (
                    round(interval_trackers["GET /health"].median_interval(), 3)
                    if interval_trackers.get("GET /health")
                    and interval_trackers["GET /health"].median_interval() is not None
                    else None
                ),
            },
        },
        "anomalies": anomalies,
        "severity_breakdown": severity_counts,
        "incident_tracker_summary": summary,
    }


# ── Logging setup ──────────────────────────────────────────────────────────────

def _setup_logging(log_dir: Path) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("dolphin-watch")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler(log_dir / "dolphin-watch.log")
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(message)s"))
        logger.addHandler(fh)
    return logger


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="dolphin-watch — defensive traffic monitor for BSV AI agents"
    )
    parser.add_argument(
        "pcap",
        metavar="PCAP_FILE",
        help="Path to the .pcap file to analyse",
    )
    parser.add_argument(
        "--reports-dir",
        default="./reports",
        metavar="DIR",
        help="Directory for JSON reports (default: ./reports)",
    )
    parser.add_argument(
        "--log-dir",
        default="./logs",
        metavar="DIR",
        help="Directory for log files (default: ./logs)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Use original pre-calibration thresholds for /budget: "
            "10s min interval, 30s baseline, 2 RPM"
        ),
    )
    args = parser.parse_args()

    reports_dir = Path(args.reports_dir).resolve()
    log_dir = Path(args.log_dir).resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)

    logger = _setup_logging(log_dir)

    # Resolve and validate the path argument (no shell expansion of untrusted input)
    pcap_path = Path(args.pcap).resolve()

    try:
        report = analyse(pcap_path, logger, strict=args.strict)
    except ValueError as exc:
        logger.error("Input validation failed: %s", exc)
        sys.stderr.write(f"[dolphin-watch] ERROR: {exc}\n")
        sys.exit(1)

    # Write report — never overwrite a previous report
    ts_tag = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = reports_dir / f"dolphin-watch-{ts_tag}.json"
    counter = 1
    while report_path.exists():
        report_path = reports_dir / f"dolphin-watch-{ts_tag}-{counter}.json"
        counter += 1

    report_path.write_text(json.dumps(report, indent=2, default=str))
    logger.info("Report written: %s", report_path)

    # Only one line to stdout — suitable for piping into Incident Tracker
    print(report["incident_tracker_summary"])
    sys.stderr.write(f"Full report: {report_path}\n")


if __name__ == "__main__":
    main()
