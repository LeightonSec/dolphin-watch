# dolphin-watch

PCAP-based defensive traffic monitor for BSV-native AI agents running on dolphin-milk.

## Why it exists

BSV agent infrastructure has no security observability layer. Agents make HTTP calls to sign transactions, poll budgets, stream task events, and chat — but nothing watches whether those calls are legitimate, rate-normal, or sequentially coherent. dolphin-watch fills that gap. It is the first defensive monitor purpose-built for this stack.

## Requirements

- Python 3.10+
- No external dependencies — stdlib only

## Usage

```
python3 dolphin-watch.py <PCAP_FILE> [--reports-dir DIR] [--log-dir DIR] [--strict]
```

**Arguments**

| Argument | Default | Description |
|---|---|---|
| `PCAP_FILE` | — | Path to the `.pcap` file to analyse |
| `--reports-dir` | `./reports` | Directory for JSON anomaly reports |
| `--log-dir` | `./logs` | Directory for structured log output |
| `--strict` | off | Use original pre-calibration thresholds for `/budget` (10s min interval, 30s baseline, 2 RPM). Default mode uses thresholds calibrated against baseline PCAP (3s min interval, 5s baseline, 12 RPM). |

**Examples**

```sh
# Normal mode — calibrated against observed baseline traffic
python3 dolphin-watch.py capture.pcap

# Strict mode — tighter /budget thresholds for production alerting
python3 dolphin-watch.py capture.pcap --strict --reports-dir ./reports --log-dir ./logs
```

Writes one timestamped JSON report per run to `--reports-dir` and prints a single summary line to stdout suitable for piping into an incident tracker:

```
[2026-05-01T14:22:01Z] dolphin-watch | capture.pcap | 4821 pkts | 312 HTTP reqs | 2 anomalies (HIGH:1 MED:1 LOW:0)
```

## Detection rules

| # | Rule | Severity | Trigger |
|---|---|---|---|
| 1 | **External IP** | HIGH | Any non-localhost IP appears in agent traffic |
| 2 | **Unknown endpoint** | HIGH | HTTP request to an endpoint not in the signed baseline |
| 3 | **Agentic danger endpoint** | HIGH | Any call to `POST /spawn_agent`, `POST /delegate_task`, or `POST /execute_bash` |
| 4 | **Budget polling too fast** | HIGH | `GET /budget` interval drops below minimum (3s normal / 10s strict) |
| 5 | **createSignature hard cap** | HIGH | `POST /createSignature` exceeds 150 RPM |
| 6 | **Rate spike** | HIGH | Any endpoint exceeds 3× its baseline call rate |
| 7 | **Total volume cap** | HIGH | Global request volume exceeds 500 RPM |
| 8 | **Sequence violation** | HIGH | `POST /chat` fires without a preceding `GET /agent` within 5 minutes |
| 9 | **Task without chat** | MEDIUM | A new task ID appears without a preceding `POST /chat` within 2 minutes |
| 10 | **Health interval deviation** | MEDIUM | `GET /health` median polling interval deviates more than 15s from the 30s baseline |

Baseline endpoints are defined as a signed frozenset in source. Any endpoint not in the set is flagged HIGH regardless of rate.

## OWASP Agentic Top 10 2026 coverage

| OWASP ID | Risk | dolphin-watch rules |
|---|---|---|
| ASI01 | Goal Hijacking | Unknown endpoint, sequence violation — detects agents deviating from their declared task graph |
| ASI02 | Tool Misuse | Agentic danger endpoints, rate spike — detects unexpected tool invocations and volume anomalies |
| ASI07 | Inter-Agent Communication | External IP, unknown endpoint — detects lateral calls outside the authorised localhost boundary |
| ASI08 | Cascading Failures | Total volume cap, rate spike — detects runaway call loops that propagate load across the stack |
| ASI10 | Rogue Agents | Agentic danger endpoints (`/spawn_agent`, `/delegate_task`) — direct detection of unsanctioned sub-agent creation |

## Output

Each run produces a JSON report in `--reports-dir`, never overwriting a previous report:

```
dolphin-watch-20260501T142201Z.json
```

Top-level report fields:

```json
{
  "schema_version": "1.0",
  "strict_mode": false,
  "timestamp": "2026-05-01T14:22:01Z",
  "pcap_file": "capture.pcap",
  "total_packets_analysed": 4821,
  "total_http_requests": 312,
  "unique_endpoints_observed": 9,
  "endpoint_frequencies": { "POST /createSignature": 180, "...": "..." },
  "rate_analysis": {
    "window_seconds": 60,
    "total_rpm_at_end": 94.2,
    "per_endpoint_rpm": { "...": 0.0 }
  },
  "interval_analysis": {
    "GET /budget": { "min_interval_sec": 4.9, "median_interval_sec": 5.1 },
    "GET /health": { "min_interval_sec": 29.8, "median_interval_sec": 30.2 }
  },
  "anomalies": [
    {
      "severity": "HIGH",
      "type": "unknown_endpoint",
      "endpoint": "POST /foo",
      "timestamp": 1746105721.4,
      "detail": "Unrecognised endpoint not in baseline: POST /foo"
    }
  ],
  "severity_breakdown": { "HIGH": 1, "MEDIUM": 0, "LOW": 0 },
  "incident_tracker_summary": "..."
}
```

## Security design

**Input validation** — PCAP files are rejected if they exceed 100 MB, lack a valid magic number, or are not regular files. Packet iteration is capped at 2,000,000 packets. Endpoint strings are capped at 256 characters and passed through a strict character allowlist before any comparison.

**Payload redaction** — Only the HTTP request line (method + path) is extracted from each packet. Request bodies are never read, stored, or logged.

**No network calls** — Fully offline. Reads one local file, writes one local file. No DNS, no telemetry, no external dependencies.

**UUID normalisation** — Raw UUIDs in `/task/<uuid>/events` and `/conversations/[conv-]<uuid>` paths are replaced with canonical `{id}` tokens before baseline comparison, preventing noise from legitimate dynamic paths.

**Log output** — Structured log lines record severity, type, endpoint, and timestamp only. No path parameters or packet content appear in logs.
