"""End-to-end detector behaviour via analyse()."""
import json


def _types(report):
    return {a["type"] for a in report["anomalies"]}


def test_clean_baseline_has_no_anomalies(dw, build, logger):
    p = build.pcap([(0.0, build.frame(build.LOCAL, build.LOCAL, build.get("/health")))])
    report = dw.analyse(p, logger)
    assert report["anomalies"] == []
    assert report["total_packets_analysed"] == 1
    assert report["total_http_requests"] == 1
    assert report["endpoint_frequencies"] == {"GET /health": 1}


def test_external_ip_is_high(dw, build, logger):
    p = build.pcap([(0.0, build.frame("10.0.0.9", build.LOCAL, build.get("/health")))])
    report = dw.analyse(p, logger)
    hits = [a for a in report["anomalies"] if a["type"] == "external_ip"]
    assert len(hits) == 1
    assert hits[0]["severity"] == "HIGH"
    assert "10.0.0.9" in hits[0]["detail"]


def test_external_ip_deduplicated_per_address(dw, build, logger):
    pkts = [(float(i), build.frame("10.0.0.9", build.LOCAL, build.get("/health"))) for i in range(4)]
    report = dw.analyse(build.pcap(pkts), logger)
    assert sum(a["type"] == "external_ip" for a in report["anomalies"]) == 1


def test_agentic_danger_endpoint(dw, build, logger):
    p = build.pcap([(0.0, build.frame(build.LOCAL, build.LOCAL, build.post("/execute_bash")))])
    report = dw.analyse(p, logger)
    danger = [a for a in report["anomalies"] if a["type"] == "agentic_danger"]
    assert len(danger) == 1
    assert danger[0]["severity"] == "HIGH"
    assert danger[0]["endpoint"] == "POST /execute_bash"
    # danger endpoints take the danger branch, NOT the unknown_endpoint branch
    assert "unknown_endpoint" not in _types(report)


def test_unknown_endpoint(dw, build, logger):
    p = build.pcap([(0.0, build.frame(build.LOCAL, build.LOCAL, build.get("/admin")))])
    report = dw.analyse(p, logger)
    unknown = [a for a in report["anomalies"] if a["type"] == "unknown_endpoint"]
    assert len(unknown) == 1
    assert unknown[0]["endpoint"] == "GET /admin"


# ── Sanitiser regression anchor ─────────────────────────────────────────────────
# A crafted packet carries an XSS/markup payload in the HTTP request path. It must
# be neutralised by the endpoint allowlist before it ever reaches the JSON report
# (or the downstream Incident Tracker that consumes it). This is dolphin-watch's
# equivalent of the source-to-sink XSS regression tests in the pcap/HTML tools.

def test_markup_payload_in_path_is_neutralised(dw, build, logger):
    evil = "/<script>alert(1)</script>"
    p = build.pcap([(0.0, build.frame(build.LOCAL, build.LOCAL, build.get(evil)))])
    report = dw.analyse(p, logger)

    # It is still flagged (unknown endpoint), but in sanitised form only.
    unknown = [a for a in report["anomalies"] if a["type"] == "unknown_endpoint"]
    assert len(unknown) == 1
    assert unknown[0]["endpoint"] == "GET /scriptalert1/script"  # '/' of </script> survives; markup does not

    # No markup survives anywhere in the serialised report. (Bare parens are not
    # checked: the tool's own summary formatting uses them, e.g. "(HIGH:1 ...)".)
    serialised = json.dumps(report, default=str)
    for needle in ("<script", "</script", "alert(1)", "<", ">"):
        assert needle not in serialised, f"{needle!r} leaked into the report"


def test_report_is_json_serialisable(dw, build, logger):
    pkts = [
        (0.0, build.frame("203.0.113.7", build.LOCAL, build.get("/admin"))),
        (1.0, build.frame(build.LOCAL, build.LOCAL, build.post("/execute_bash"))),
    ]
    report = dw.analyse(build.pcap(pkts), logger)
    # default=str mirrors how main() writes the report; serialising must not raise.
    serialised = json.dumps(report, default=str)
    assert '"schema_version": "1.0"' in serialised


# ── Rate / volume detectors ─────────────────────────────────────────────────────

def test_signature_hard_cap(dw, build, logger):
    pkts = [(i * 0.1, build.frame(build.LOCAL, build.LOCAL, build.post("/createSignature"))) for i in range(10)]
    report = dw.analyse(build.pcap(pkts), logger)
    assert "rate_limit" in _types(report)


def test_total_volume_cap(dw, build, logger):
    pkts = [(i * 0.1, build.frame(build.LOCAL, build.LOCAL, build.get("/status"))) for i in range(10)]
    report = dw.analyse(build.pcap(pkts), logger)
    total = [a for a in report["anomalies"] if a["type"] == "rate_limit_total"]
    assert len(total) == 1
    assert total[0]["severity"] == "HIGH"


# ── Sequence detector ───────────────────────────────────────────────────────────

def test_chat_without_agent_is_violation(dw, build, logger):
    p = build.pcap([(0.0, build.frame(build.LOCAL, build.LOCAL, build.post("/chat")))])
    report = dw.analyse(p, logger)
    assert "sequence_violation" in _types(report)


def test_chat_after_agent_is_clean(dw, build, logger):
    pkts = [
        (0.0, build.frame(build.LOCAL, build.LOCAL, build.get("/agent"))),
        (1.0, build.frame(build.LOCAL, build.LOCAL, build.post("/chat"))),
    ]
    report = dw.analyse(build.pcap(pkts), logger)
    assert "sequence_violation" not in _types(report)


# ── Polling-interval detector + strict mode ─────────────────────────────────────

def test_budget_polling_too_fast(dw, build, logger):
    pkts = [
        (0.0, build.frame(build.LOCAL, build.LOCAL, build.get("/budget"))),
        (1.0, build.frame(build.LOCAL, build.LOCAL, build.get("/budget"))),  # 1s gap < 3s
    ]
    report = dw.analyse(build.pcap(pkts), logger)
    interval = [a for a in report["anomalies"]
                if a["type"] == "polling_interval" and a["endpoint"] == "GET /budget"]
    assert interval and interval[0]["severity"] == "HIGH"


def test_strict_mode_tightens_budget_interval(dw, build, logger):
    # 5s gap: clean under normal thresholds (3s), flagged under strict (10s).
    pkts = [
        (0.0, build.frame(build.LOCAL, build.LOCAL, build.get("/budget"))),
        (5.0, build.frame(build.LOCAL, build.LOCAL, build.get("/budget"))),
    ]
    pcap = build.pcap(pkts)
    normal = dw.analyse(pcap, logger, strict=False)
    strict = dw.analyse(pcap, logger, strict=True)
    assert not any(a["type"] == "polling_interval" for a in normal["anomalies"])
    assert any(a["type"] == "polling_interval" for a in strict["anomalies"])
    assert strict["strict_mode"] is True
