# CLAUDE.md — dolphin-watch

PCAP-based defensive traffic monitor for BSV-native AI agents running on dolphin-milk.
Parses PCAP files offline, extracts HTTP endpoints, detects anomalies against an immutable
baseline, and produces structured JSON reports.

Zero network calls. Zero external dependencies. Zero payload logging.

---

## SOC Toolkit Position

- **Layer:** Research (Layer 5) — Bastion Protocol R&D
- **Depends on:** Nothing — stdlib only
- **Feeds into:** Incident Tracker (via stdout summary line), future Bastion agent security layer
- **Gap it fills:** Security observability for BSV AI agent infrastructure — no equivalent exists

---

## Architecture

- `dolphin-watch.py` — Single-file tool: PCAP parsing, detection engine, report generation
- `capture-baseline.sh` — Shell script for capturing baseline traffic from live dolphin-milk
- `reports/` — JSON anomaly reports (gitignored)
- `logs/` — Structured log output (gitignored)

---

## Detection Rules

| # | Rule | Severity | Trigger |
|---|------|----------|---------|
| 1 | External IP | HIGH | Any non-localhost IP in agent traffic |
| 2 | Unknown endpoint | HIGH | HTTP request not in baseline frozenset |
| 3 | Agentic danger endpoint | HIGH | POST /spawn_agent, /delegate_task, /execute_bash |
| 4 | Budget polling too fast | HIGH | GET /budget interval < 3s (normal) / 10s (strict) |
| 5 | createSignature hard cap | HIGH | POST /createSignature exceeds 150 RPM |
| 6 | Rate spike | HIGH | Any endpoint exceeds 3× its baseline call rate |
| 7 | Total volume cap | HIGH | Global request volume exceeds 500 RPM |
| 8 | Sequence violation | HIGH | POST /chat fires without GET /agent within 5 minutes |
| 9 | Task without chat | MEDIUM | New task ID without preceding POST /chat within 2 minutes |
| 10 | Health interval deviation | MEDIUM | GET /health median interval deviates >15s from 30s baseline |

---

## OWASP Agentic Top 10 2026 Coverage

| OWASP ID | Risk | Rules |
|----------|------|-------|
| ASI01 | Goal Hijacking | Unknown endpoint, sequence violation |
| ASI02 | Tool Misuse | Agentic danger endpoints, rate spike |
| ASI07 | Inter-Agent Communication | External IP, unknown endpoint |
| ASI08 | Cascading Failures | Total volume cap, rate spike |
| ASI10 | Rogue Agents | Agentic danger endpoints |

---

## Security Design — Critical — Do Not Change Without Review

- **Immutable baseline** — `BASELINE_ENDPOINTS` is a `frozenset` — immutable at runtime (hardcoded in source, not cryptographically signed)
- **Input validation** — PCAP rejected if >100MB, invalid magic, not a regular file
- **Packet cap** — iteration hard-capped at 2,000,000 packets
- **Endpoint sanitisation** — method allowlist, safe path character allowlist (256 char max)
- **Payload redaction** — only HTTP request line (method + path) extracted — bodies never read, stored, or logged
- **UUID normalisation** — task and conversation UUIDs replaced with `{id}` tokens before comparison
- **No network calls** — fully offline, no DNS, no telemetry
- **Log safety** — severity, type, endpoint, timestamp only — no path parameters or packet content in logs
- **Report collision** — timestamped reports never overwrite previous reports

---

## Current Status

✅ Complete — LeightonSec/dolphin-watch
✅ Pure stdlib — zero external dependencies
✅ Custom PCAP parser — handles LINKTYPE_NULL (macOS) and LINKTYPE_ETHERNET
✅ Both LE and BE byte order supported
✅ 10 detection rules across HIGH/MEDIUM severity
✅ Sliding window rate tracking (_RateWindow)
✅ Polling interval tracking (_IntervalTracker)
✅ Sequence constraint enforcement (agent → chat → task)
✅ Agentic danger endpoint detection
✅ Immutable frozenset baseline — 58 known-good endpoints including OPTIONS CORS preflights
✅ Normal and strict modes for /budget thresholds
✅ Stdout summary line suitable for piping to Incident Tracker
✅ Calibrated against live dolphin-milk baseline PCAP traffic

---

## Modes

**Normal mode** (default) — calibrated against observed baseline:
- GET /budget: 3s min interval, 5s baseline, 12 RPM

**Strict mode** (`--strict`) — original pre-calibration thresholds:
- GET /budget: 10s min interval, 30s baseline, 2 RPM

Use strict mode for production alerting where false negatives are unacceptable.

---

## Known Issues

- Rate deduplication not implemented for per-packet rate breach alerts — can produce duplicate anomaly entries
- In-memory only — no state carried between runs
- IPv4/TCP only — IPv6 not parsed

---

## Next Steps

- Live capture mode (requires root)
- Rate anomaly deduplication
- Integration with Incident Tracker API
- Bastion Protocol agent monitoring integration
- IPv6 support

---

## Tech Stack

- Python 3.10+ (stdlib only)
- Shell (capture-baseline.sh)

---

## Development & CI

The **runtime tool stays stdlib-only** — `dolphin-watch.py` imports nothing
outside the standard library, and that is a deliberate security decision (see
Security Rules). The "no external dependencies" rule governs runtime, not the
development toolchain.

- **Dev tooling is dev-only and hash-pinned** in `requirements-dev.txt`
  (`ruff`, `pytest`, `pip-audit`), compiled from `requirements-dev.in` with
  `uv pip compile --python-version 3.10 --universal --generate-hashes`. None of
  it is imported by the tool; it never ships.
- **Tests** live in `tests/` and load the hyphenated `dolphin-watch.py` via
  `importlib` (the filename is not a valid module name). PCAP fixtures are
  synthesised as raw bytes in `tests/conftest.py` — no capture tooling needed.
  The sanitiser regression anchor
  (`test_detectors.py::test_markup_payload_in_path_is_neutralised`) proves a
  crafted markup payload in a packet path is stripped before it reaches the report.
- **CI** (`.github/workflows/ci.yml`): ruff + `pip-audit --strict` + pytest on
  Python 3.10/3.11/3.12, plus a SHA-pinned `security-gate` scan.
- **Accepted findings**: `accepted-findings.toml` waives the synthetic injection
  strings the gate flags inside test fixtures (SEC-TOOL-2). These are illustrative,
  locally authored, and not real IOCs.

---

## Security Rules

- Never add external dependencies — stdlib only is a deliberate security decision
- Never log packet payload content — only method + path
- Never modify BASELINE_ENDPOINTS without a documented baseline recapture
- Never reduce MAX_PCAP_BYTES, MAX_PACKETS, or MAX_ENDPOINT_LENGTH limits
- reports/ and logs/ gitignored — never commit either

---

## Conventions

- All detection logic in `analyse()` — do not split across modules
- Anomaly dict always contains: severity, type, endpoint, timestamp, detail
- Severity always strings: `"HIGH"`, `"MEDIUM"`, `"LOW"`
- Endpoint strings always `"METHOD /path"` format after sanitisation
- UUID paths always normalised to `{id}` token before any comparison or logging
- New detection rules must update OWASP coverage table in README
- Strict mode only changes /budget thresholds — never changes other rules
- Report filenames never overwrite — collision counter appended if needed
- stdout: one summary line only — full report goes to file

---

## capture-baseline.sh

Shell script for capturing baseline traffic from a live dolphin-milk server.

**Requires sudo** — tcpdump on macOS loopback needs root.

### What it does
Six phases against `localhost:8080`:
1. Monitoring endpoints — /health, /status, /agent, /budget polling simulation
2. OPTIONS CORS preflight sweep — all known endpoints
3. Wallet and crypto endpoints — createSignature, encrypt, decrypt, etc.
4. Identity and discovery — discoverByIdentityKey, discoverByAttributes
5. Chat and conversation endpoints — /chat, /conversations, MessageBox
6. Final polling sweep

Captures all traffic to PCAP then immediately runs dolphin-watch on it to find baseline gaps.

### Usage
```bash
sudo bash capture-baseline.sh
```

### Important notes
- curl bypasses the CLI wallet config (port 3322) — drives server at 8080 directly
- Auth failures still appear in PCAP — dolphin-watch reads request lines not responses
- Run dolphin-milk server first: `dolphin-milk serve`
- captures/ gitignored — PCAP files contain raw agent traffic, never commit