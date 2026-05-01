#!/usr/bin/env bash
# capture-baseline.sh — probe dolphin-milk's HTTP API to surface all reachable
# endpoints, capture traffic, then run dolphin-watch to find gaps in the baseline.
#
# Strategy: drive the running server at localhost:8080 directly with curl.
# The CLI subcommands use a separate wallet config (port 3322) that is not
# compatible with the embedded wallet the server uses. curl bypasses this
# entirely — auth failures still land in the PCAP and dolphin-watch reads
# request lines, not responses.
#
# Requires sudo for tcpdump on macOS loopback.
# Usage:  sudo bash capture-baseline.sh

set -euo pipefail

TIMESTAMP="$(date +%Y%m%dT%H%M%S)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPTURE_DIR="$SCRIPT_DIR/captures"
REPORTS_DIR="$SCRIPT_DIR/reports"
LOGS_DIR="$SCRIPT_DIR/logs"
PCAP_PATH="$CAPTURE_DIR/baseline-$TIMESTAMP.pcap"
DOLPHIN_WATCH="$SCRIPT_DIR/dolphin-watch.py"
BASE="http://localhost:8080"

# ── Preflight ──────────────────────────────────────────────────────────────────
if ! curl -sf --max-time 2 "$BASE/health" &>/dev/null; then
  echo "ERROR: dolphin-milk not responding on $BASE — run 'dolphin-milk serve' first" >&2
  exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "ERROR: tcpdump requires root — run as: sudo bash capture-baseline.sh" >&2
  exit 1
fi

mkdir -p "$CAPTURE_DIR" "$REPORTS_DIR" "$LOGS_DIR"

# ── Start capture ──────────────────────────────────────────────────────────────
echo "[capture] Starting tcpdump → $PCAP_PATH"
tcpdump -i lo0 -w "$PCAP_PATH" 'tcp port 8080' &>/dev/null &
TCPDUMP_PID=$!
sleep 1

cleanup() {
  kill -INT "$TCPDUMP_PID" 2>/dev/null || true
  wait "$TCPDUMP_PID" 2>/dev/null || true
}
trap cleanup EXIT

# ── Curl helpers ───────────────────────────────────────────────────────────────
get()  { curl -s --max-time 10 -X GET     "$BASE$1" &>/dev/null || true; }
post() { curl -s --max-time 10 -X POST    "$BASE$1" \
           -H "Content-Type: application/json" -d "${2:-{\}}" &>/dev/null || true; }
opts() { curl -s --max-time 5  -X OPTIONS "$BASE$1" \
           -H "Origin: http://localhost:8080" \
           -H "Access-Control-Request-Method: POST" &>/dev/null || true; }

# ── Phase 1: monitoring / status endpoints (no auth required) ──────────────────
echo ""
echo "══ 1/6  Monitoring endpoints ══"
get  /health
get  /status
get  /agent
# Simulate polling: hit budget and health several times with realistic gaps
for _ in $(seq 1 8); do
  get /budget
  get /health
  sleep 4
done

# ── Phase 2: CORS OPTIONS preflight sweep ─────────────────────────────────────
echo ""
echo "══ 2/6  OPTIONS preflight sweep ══"
for path in /chat /createSignature /verifySignature /verifyHmac /createHmac \
            /getPublicKey /encrypt /decrypt /createAction /signAction \
            /abortAction /listOutputs /listActions /listCertificates \
            /proveCertificate /acquireCertificate /internalizeAction \
            /relinquishOutput /discoverByIdentityKey /discoverByAttributes \
            /sendMessage /listIncomingTransactions /acknowledgeMessage \
            /createHmac /verifyHmac /revealCounterpartyKeyLinkage \
            /revealSpecificKeyLinkage; do
  opts "$path"
done

# ── Phase 3: wallet / crypto endpoints ────────────────────────────────────────
echo ""
echo "══ 3/6  Wallet and crypto endpoints ══"
post /getPublicKey      '{"protocolID":[2,"message signing"],"keyID":"1"}'
post /createSignature   '{"data":"dGVzdA==","protocolID":[2,"message signing"],"keyID":"1"}'
post /verifySignature   '{"data":"dGVzdA==","signature":"00","protocolID":[2,"message signing"],"keyID":"1"}'
post /createHmac        '{"data":"dGVzdA==","protocolID":[2,"message signing"],"keyID":"1"}'
post /verifyHmac        '{"data":"dGVzdA==","hmac":"00","protocolID":[2,"message signing"],"keyID":"1"}'
post /encrypt           '{"plaintext":"dGVzdA==","protocolID":[2,"message signing"],"keyID":"1"}'
post /decrypt           '{"ciphertext":"dGVzdA==","protocolID":[2,"message signing"],"keyID":"1"}'
post /listOutputs       '{"basket":"default","include":"locking scripts"}'
post /listActions       '{"labels":[]}'
post /listCertificates  '{"certifiers":[],"types":[]}'
post /proveCertificate  '{"certificate":{},"fieldsToReveal":[]}'
post /acquireCertificate '{"type":"","certifier":"","acquisitionProtocol":"direct","fields":{}}'
post /internalizeAction '{"tx":{"rawTx":""},"outputs":[]}'
post /relinquishOutput  '{"basket":"default","output":"0000000000000000000000000000000000000000000000000000000000000000.0"}'
post /createAction      '{"description":"baseline probe","outputs":[]}'
post /signAction        '{"reference":"00","spend":[]}'
post /abortAction       '{"reference":"00"}'
post /revealCounterpartyKeyLinkage '{"counterparty":"self","verifier":"self","protocolID":[2,"test"],"keyID":"1"}'
post /revealSpecificKeyLinkage     '{"counterparty":"self","verifier":"self","protocolID":[2,"test"],"keyID":"1","privileged":false}'

# ── Phase 4: identity / discovery ─────────────────────────────────────────────
echo ""
echo "══ 4/6  Identity and discovery endpoints ══"
post /discoverByIdentityKey '{"identityKey":"00","limit":5}'
post /discoverByAttributes  '{"attributes":{},"limit":5}'

# ── Phase 5: agent chat and conversation endpoints ────────────────────────────
echo ""
echo "══ 5/6  Chat and conversation endpoints ══"
# Initiate a chat turn to create at least one conversation
CONV_RESP=$(curl -s --max-time 30 -X POST "$BASE/chat" \
  -H "Content-Type: application/json" \
  -d '{"message":"What is x402?"}' 2>/dev/null || true)
echo "$CONV_RESP" | grep -o '"conversation_id":"[^"]*"' | head -1 || true

sleep 3

# Hit conversation list / read endpoints
get  /conversations
post /listConversations '{}'

# Try to hit a conversation UUID path (server will 404 but endpoint is captured)
get "/conversations/00000000-0000-0000-0000-000000000000"
get "/conversations/conv-00000000-0000-0000-0000-000000000000"

# MessageBox
post /sendMessage             '{"recipient":"self","messageBox":"default","body":"probe"}'
post /listIncomingTransactions '{}'
post /acknowledgeMessage      '{"messageIds":[]}'

# ── Phase 6: final polling sweep ───────────────────────────────────────────────
echo ""
echo "══ 6/6  Final monitoring sweep ══"
for _ in $(seq 1 5); do
  get /health
  get /budget
  sleep 4
done

# ── Stop capture ───────────────────────────────────────────────────────────────
sleep 2
cleanup
trap - EXIT
echo ""
echo "[capture] Done. PCAP → $PCAP_PATH"

# ── Run dolphin-watch ──────────────────────────────────────────────────────────
echo ""
echo "[dolphin-watch] Analysing capture…"
python3 "$DOLPHIN_WATCH" "$PCAP_PATH" \
  --reports-dir "$REPORTS_DIR" \
  --log-dir "$LOGS_DIR"
