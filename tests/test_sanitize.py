"""Endpoint sanitisation and UUID normalisation — the security boundary that
neutralises attacker-controlled packet data before it reaches any report sink."""
import pytest


def test_known_endpoint_passes_through(dw):
    assert dw._sanitize_endpoint("GET", "/health") == "GET /health"


def test_method_must_be_allowlisted(dw):
    assert dw._sanitize_endpoint("FETCH", "/health") is None
    assert dw._sanitize_endpoint("get", "/health") is None  # case-sensitive allowlist


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def test_all_allowed_methods(dw, method):
    assert dw._sanitize_endpoint(method, "/x") == f"{method} /x"


def test_query_string_is_stripped(dw):
    assert dw._sanitize_endpoint("GET", "/budget?token=abc&x=1") == "GET /budget"


def test_path_must_start_with_slash(dw):
    assert dw._sanitize_endpoint("GET", "health") is None


def test_length_capped_at_max(dw):
    long_path = "/" + "a" * 400
    out = dw._sanitize_endpoint("GET", long_path)
    path = out.split(" ", 1)[1]
    assert len(path) == dw.MAX_ENDPOINT_LENGTH


def test_task_uuid_normalised(dw):
    raw = "/task/12345678-1234-1234-1234-1234567890ab/events"
    assert dw._sanitize_endpoint("GET", raw) == "GET /task/{id}/events"


def test_conversation_uuid_normalised(dw):
    raw = "/conversations/12345678-1234-1234-1234-1234567890ab"
    assert dw._sanitize_endpoint("GET", raw) == "GET /conversations/{id}"


def test_conversation_conv_prefixed_uuid_normalised(dw):
    raw = "/conversations/conv-12345678-1234-1234-1234-1234567890ab"
    assert dw._sanitize_endpoint("GET", raw) == "GET /conversations/{id}"


def test_extract_task_uuid_roundtrip(dw):
    raw = "/task/ABCDEF12-1234-1234-1234-1234567890AB/events"
    assert dw._extract_task_uuid(raw) == "abcdef12-1234-1234-1234-1234567890ab"


def test_extract_task_uuid_rejects_non_match(dw):
    assert dw._extract_task_uuid("/task/not-a-uuid/events") is None


# ── Injection neutralisation: the allowlist strips dangerous characters ─────────

@pytest.mark.parametrize(
    "payload_path",
    [
        "/<script>alert(1)</script>",
        '/"><img src=x onerror=alert(1)>',
        "/'; DROP TABLE x;--",
        "/$(rm -rf /)",
        "/`whoami`",
        "/..%2f..%2fetc%2fpasswd",
    ],
)
def test_dangerous_characters_stripped(dw, payload_path):
    out = dw._sanitize_endpoint("GET", payload_path)
    assert out is not None
    # Inspect the path only (the "METHOD " prefix legitimately contains a space).
    path = out.split(" ", 1)[1]
    # No markup / shell / quoting metacharacter may survive into the sanitised path.
    forbidden = set("<>\"'`()$;\\ ")
    assert not (set(path) & forbidden), f"forbidden char survived in {path!r}"


def test_never_raises_on_garbage(dw):
    # Arbitrary bytes decoded latin-1 must not crash the sanitiser
    junk = "/" + "".join(chr(c) for c in range(0x20, 0x7F))
    assert dw._sanitize_endpoint("GET", junk) is not None
