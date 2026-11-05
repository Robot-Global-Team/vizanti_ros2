#!/usr/bin/env python3
"""vizanti_gateway.py - authenticating TLS gateway in front of vizanti.

Default auth mode (1.4.0+): nif-device-v1. Registrations and cryptographic
credentials belong exclusively to network-iface's local Unix-socket authority.
The gateway checks every protected request there and forwards NIF bearer tokens
to the protected REST/package backends. A missing authority fails closed (503).
Legacy clients.json/newcode behavior below is available only with --auth-mode legacy.

Code-only enrollment (1.5.0+): pyOpenSSL MemoryBIO TLS exposes the actual TLS 1.3
exporter. /gw/enroll/start -> confirm -> commit are the only keep-alive routes,
on one connection, at most three requests. NIF owns PAKE state and registration.
No TLS exporter or connection identity is accepted from HTTP JSON/headers.
The legacy access model described below is retained for explicit legacy mode.

The only externally exposed vizanti port. Everything behind it is loopback:
  flask (server.py)       127.0.0.1:5002
  rosbridge / rws         127.0.0.1:5001   (5001 is also a contract with the on-board
                                            GUI: rgt_ros2_gui/src/hooks/useRosbridge.ts)

Access model (device pairing, Ed25519, certificate-bound):
  - An operator PC is registered once with a one-time pairing token
    "<code>-<cert fingerprint prefix>" (printed by `newcode`). The PC refuses to
    pair unless the TLS certificate it observes matches the fingerprint in the
    token, and it never sends the code itself - only an HMAC proof bound to the
    fingerprint, its public key and its name. Only the PC's *public* key is
    stored on the robot (clients.json): no impersonation-capable secret exists
    on the robot or inside the editor binary.
  - Opening SLAM: POST /gw/challenge -> nonce, sign (fingerprint|client_id|nonce)
    with the PC's Ed25519 key -> POST /gw/session -> one-time token (OTT) ->
    browser opens /gw/sso?ott=... -> session cookie (2h).
  - Every other HTTP request and the rosbridge WebSocket upgrade require that
    cookie; authorized connections are spliced to the loopback backends.
    Revocation (clients.json), session expiry and /gw/logout sever live
    connections within JANITOR_PERIOD_S seconds.

The signature algorithm is fixed server-side by the registered key type
(Ed25519 only). A client-supplied "alg" field is deliberately ignored.

Permissions (clients.json "perms"): "ui" (vizanti cookie session), "read", "drive",
"package" (robot API). `newcode --perms` fixes them for the device that pairs with that
token; entries paired before 1.3.0 carry no "perms" and keep all four.

Robot API (protocol "rgt-robot-api-v1", replaces direct LAN access to network-iface):
  - POST /gw/challenge -> nonce, sign ("rgt-robot-api-v1"|fingerprint|client_id|nonce) ->
    POST /gw/api-token -> bearer token (15 min, bound to the source IP, <=4 per client).
    The signing context differs from the UI session's, so neither signature works for the other.
  - https://ROBOT:5000/api/nif/<path> -> 127.0.0.1:51231/<path> (network-iface REST)
    https://ROBOT:5000/api/pkg/<path> -> 127.0.0.1:51233/<path> (package HTTP)
    One request per connection, "Authorization: Bearer <token>", strict HTTP/1.1 parsing,
    exact (service, method, path) allowlist (API_ROUTES) with a permission, body cap and
    timeout per route, re-serialized to the backend (no client header passes except
    Content-Type / Accept). Revocation and permission changes apply to the next request.
    A request body is received completely before the backend is contacted: up to 1 MiB in
    memory, larger ones (start-position photos up to 64 MiB) in an unlinked spool file in the
    data dir (ApiBody), so memory stays bounded under MemoryMax.

Subcommands:
  serve            run the gateway (default)
  newcode          generate and print a fresh one-time pairing token (24h TTL)
                   [--perms ui,read,drive,package]
  list-clients     print registered clients and their permissions
  revoke <id|name> remove a client registration
  set-perms <id|name> <perms>   change a client's permissions (comma list)
  selfcheck        report Python / Ed25519 backend / TLS readiness (used by installers)

Portability: one file serves both the ROS 2 (3.4.0, Ubuntu 24.04, Python 3.12) and
the ROS 1 (2.9.x, Ubuntu 18.04, Python 3.6) robots. It therefore uses only asyncio
APIs that exist since Python 3.6 (own accept loop + connect_accepted_socket for TLS)
and verifies Ed25519 with the first available backend: python3-cryptography (>=2.6)
-> PyNaCl -> a built-in pure-Python RFC 8032 verifier. pyOpenSSL is required for
code-only enrollment; without it existing certificate-pinned logins remain usable
and new code-only registration is unavailable. No ROS dependency,
so it runs as an independent systemd unit (deploy/vizanti-gateway.service) and keeps
serving its guidance page even when the nav stack / vizanti itself is down.
"""

import argparse
import asyncio
import base64
import errno
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import tempfile
import time
import urllib.parse
import uuid
from http.client import responses as HTTP_REASONS

VERSION = "1.5.1"
ENROLLMENT_PROTOCOL = "spake2-tls-exporter-v2"
ENROLLMENT_TIMEOUT_S = 60.0
TLS_EXPORTER_LABEL = b"EXPORTER-Channel-Binding"

try:
    from OpenSSL import SSL as OPENSSL_SSL
except ImportError:
    OPENSSL_SSL = None


def openssl_exporter_available():
    return (OPENSSL_SSL is not None and
            hasattr(OPENSSL_SSL.Connection, "export_keying_material") and
            hasattr(OPENSSL_SSL.Context, "set_min_proto_version") and
            hasattr(OPENSSL_SSL, "TLS_SERVER_METHOD") and
            hasattr(OPENSSL_SSL, "TLS1_3_VERSION"))
SIGN_CONTEXT = b"vizanti-gw-v2"          # session signature: SIGN_CONTEXT|fp|client_id|nonce
API_SIGN_CONTEXT = b"rgt-robot-api-v1"   # API token signature: API_SIGN_CONTEXT|fp|client_id|nonce
PAIR_PROOF_CONTEXT = b"vizanti-gw-pair-v1"  # pairing proof: HMAC(code, CTX|fp|pubkey|name)

ALL_PERMS = ("ui", "read", "drive", "package")   # canonical order
API_PERMS = ("read", "drive", "package")         # what a bearer token can carry

# ---- limits (sync with deploy/README.ko.md) ----
MAX_HEAD_BYTES = 16 * 1024      # request head cap
HEAD_TIMEOUT_S = 2.0            # slowloris: full head must arrive this fast
MAX_BODY_BYTES = 8 * 1024       # /gw/* JSON bodies only
TLS_HANDSHAKE_TIMEOUT_S = 5.0
TLS_CLOSE_TIMEOUT_S = 1.0
TLS_CONCURRENT_HANDSHAKES = 16  # P-256 handshakes run on the event loop thread
LISTEN_BACKLOG = 64
LIVE_CONN_CAP = 256             # every accepted socket, counted BEFORE the TLS handshake
PER_IP_LIVE_CAP = 32
SPLICE_CAP = 64                 # authorized, spliced connections
PER_IP_SPLICE_CAP = 16
NONCE_TTL_S = 60
NONCE_PER_IP_CAP = 16
NONCE_GLOBAL_CAP = 1024
OTT_TTL_S = 180                 # browser cert-warning interstitial must fit in here
SESSION_TTL_S = 2 * 3600
CONN_IDLE_TIMEOUT_S = 30 * 60
CONN_HARD_LIFETIME_S = SESSION_TTL_S + 60   # backstop only; sessions sever connections first
PAIR_WINDOW_S = 600
PAIR_MAX_PER_WINDOW = 5
PAIR_ATTEMPTS_CAP = 4096        # distinct source IPs tracked (IPv6 rotation bound)
PAIR_CODE_TTL_S = 24 * 3600
JANITOR_PERIOD_S = 30           # also the max revocation-to-severance delay
WARN_PER_KEY_S = 60.0           # throttle for attacker-triggerable warnings
WARN_KEYS_CAP = 4096
# robot API (/api/<svc>/...)
API_TOKEN_TTL_S = 900
API_TOKENS_PER_CLIENT = 4       # oldest live token is evicted beyond this
API_CONN_CAP = 32               # API connections in progress (separate from SPLICE_CAP)
PER_IP_API_CAP = 8
API_MAX_HEADERS = 64
API_BODY_MIN_RATE = 32 * 1024   # request/response bodies: deadline >= length / rate ...
API_BODY_MIN_TIMEOUT_S = 10.0   # ... and at least this long (request bodies) ...
API_BODY_MAX_TIMEOUT_S = 256.0  # ... but never longer (request bodies, see api_body_time).
# 256 s = 8 MiB / 32 KiB/s: bodies up to 8 MiB (package uploads) keep exactly the allowance they
# had, and above 8 MiB the required average rate grows with the size instead of the deadline. A
# 64 MiB photo must arrive at >= 256 KiB/s (~2.1 Mbit/s); even a weak 2.4 GHz 802.11n link at MCS0
# (6.5 Mbit/s PHY) carries ~4 Mbit/s of TCP, i.e. 64 MiB in ~2.2 min and the 15-30 MB PNGs of old
# editors in under a minute. Uncapped, one 64 MiB body could hold one of the two pkg slots for
# 34 min; now a slot is held at most 256 s plus the route's backend timeout.
API_BODY_IDLE_TIMEOUT_S = 30.0  # request body: no byte for this long -> 408 as well. Frees the slot of
                                # a peer that vanished without FIN/RST (radio loss) long before the
                                # deadline; AP roaming stalls last seconds
API_BODY_MEM_MAX = 1024 * 1024  # request bodies up to this size stay in memory, larger ones are spooled
API_SPOOL_MIN_FREE = 32 * 1024 * 1024   # a spool must leave this much free space on the data dir's
                                        # filesystem (nav logs and maps live there too)
API_SPOOL_COPIES = 2            # copies of a spooled body on disk at once until the backend has stored
                                # it: the spool + network-iface's Werkzeug temp file of a photo (fed while
                                # the spool still exists), then that file + the new photo. /tmp is on the
                                # data dir's filesystem on a default install
API_IO_CHUNK = 64 * 1024        # body piece size: client reads, spool reads, backend writes
API_DRAIN_TIMEOUT_S = 3.0       # discard an announced body after an error reply, at most this long
API_DRAIN_DEFAULT = 64 * 1024   # ... and at most this many bytes (413: the route cap)
API_BACKEND_CONNECT_TIMEOUT_S = 3.0
API_BACKEND_HEAD_MAX = 16 * 1024
API_GET_LOG_PERIOD_S = 60.0     # GETs are audited as one aggregated line per key per period
API_GET_STATS_CAP = 1024

COOKIE_NAME = "vizanti_gw"
CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

log = logging.getLogger("vizanti_gateway")

# ---- robot API route table ----
API_SERVICES = ("nif", "pkg")
API_DEFAULT_PORTS = {"nif": 51231, "pkg": 51233}   # network-iface REST / package HTTP (loopback)
API_CONCURRENCY = {"nif": 4, "pkg": 2}             # backend requests in flight per service
MIB = 1024 * 1024
API_ROUTE_BODY_LIMIT = 64 * MIB                    # sanity bound for --api-routes entries
API_ROUTE_TIMEOUT_LIMIT = 600

# (service, method, path) -> (permission, max request body bytes, backend timeout s).
# Exact match only. Anything else - /iface/custom, Swagger ("/", "/swagger.json"), unknown
# paths or methods - is 404 without contacting the backend. One table, one place: robots with
# other endpoints extend it with --api-routes (load_api_routes).
API_ROUTES = {
    ("nif", "GET", "/uid"): ("read", 0, 10),
    ("nif", "GET", "/robot_ns"): ("read", 0, 10),
    ("nif", "GET", "/navi/info"): ("read", 0, 10),
    ("nif", "GET", "/navi/request"): ("read", 0, 10),
    ("nif", "GET", "/iface/recent"): ("read", 0, 10),
    ("nif", "GET", "/iface/position"): ("read", 0, 10),
    ("nif", "GET", "/iface/package"): ("read", 0, 10),
    ("nif", "GET", "/iface/vizanti/slam"): ("read", 0, 10),
    ("nif", "POST", "/navi/request"): ("drive", 65536, 30),
    ("nif", "POST", "/iface/task"): ("drive", 65536, 30),
    ("nif", "POST", "/iface/cruise"): ("drive", 65536, 30),
    ("nif", "POST", "/iface/pause"): ("drive", 65536, 30),
    ("nif", "POST", "/iface/resume"): ("drive", 65536, 30),
    ("nif", "POST", "/iface/stop"): ("drive", 65536, 30),
    ("pkg", "GET", "/package/download"): ("read", 0, 30),
    ("pkg", "GET", "/package/manifest"): ("read", 0, 30),
    ("pkg", "GET", "/package/floor"): ("read", 0, 30),
    ("pkg", "GET", "/package/position"): ("read", 0, 30),
    ("pkg", "GET", "/package/raw/image"): ("read", 0, 30),
    ("pkg", "POST", "/package/upload"): ("package", 8 * MIB, 60),
    # older editors send the camera PNG unscaled (15-30 MB seen); network-iface (51233) applies the
    # same 64 MiB cap to this route. The body is spooled (ApiBody); 60 s like /package/upload for the
    # backend to take 64 MiB over loopback, parse the multipart and store the image
    ("pkg", "POST", "/package/start-position/photo"): ("package", 64 * MIB, 60),
}

# strict request parsing (request smuggling / traversal defence)
_API_TARGET_RE = re.compile(r"/api/(" + "|".join(API_SERVICES) + r")(/[A-Za-z0-9_\-./]*)?(\?[A-Za-z0-9_\-.~=&%+]*)?\Z")
_API_REQUEST_LINE_RE = re.compile(r"([A-Z]{1,16}) (\S+) HTTP/1\.1\Z")
_API_HEADER_RE = re.compile(r"([!#$%&'*+\-.^_`|~0-9A-Za-z]+):[ \t]*(.*?)[ \t]*\Z")
_API_BAD_REQ_BYTES_RE = re.compile(rb"[^\t\r\n\x20-\x7e]")         # NUL, controls, non-ASCII
_API_BAD_RESP_BYTES_RE = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_API_BAD_PCT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_API_DIGITS_RE = re.compile(r"[0-9]{1,15}\Z")
_API_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]{16,128}\Z")
_API_ROUTE_PATH_RE = re.compile(r"(/[A-Za-z0-9_\-.]+)+\Z")
_API_STATUS_LINE_RE = re.compile(r"HTTP/1\.[01] ([0-9]{3})(?: (.*))?\Z")
# headers a request may carry once only (anything framing-, auth- or forwarding-relevant)
API_SINGLETON_HEADERS = frozenset(("host", "content-length", "transfer-encoding", "authorization",
                                   "content-type", "accept", "origin", "expect"))
# Repeatable HTTP list fields are combined for routing decisions. Credentials,
# framing and WebSocket nonces must have exactly one interpretation everywhere.
HTTP_LIST_HEADERS = frozenset(("accept", "accept-encoding", "accept-language", "cache-control",
    "connection", "upgrade", "sec-websocket-protocol", "sec-websocket-extensions", "pragma", "via"))
HTTP_SINGLETON_HEADERS = (API_SINGLETON_HEADERS - {"accept"}) | frozenset((
    "cookie", "proxy-authorization", "forwarded", "x-forwarded-for", "x-forwarded-host",
    "x-forwarded-proto", "x-real-ip", "sec-websocket-key", "sec-websocket-version"))
API_FORWARD_HEADERS = (("content-type", "Content-Type"), ("accept", "Accept"))   # all a client may pass
API_RESP_DROP_HEADERS = frozenset(("connection", "keep-alive", "transfer-encoding", "content-length",
                                   "set-cookie", "set-cookie2", "server", "cache-control",
                                   "proxy-connection", "upgrade", "te", "trailer"))


class ApiReject(Exception):
    """A request the API proxy refuses before any backend contact."""
    def __init__(self, status, error):
        Exception.__init__(self, error)
        self.status = status
        self.error = error


class AuthUnavailable(Exception):
    """The NIF authority cannot safely answer. Never fall back to local registrations."""
    def __init__(self, detail, error="auth_unavailable", retry_after=1):
        super().__init__(detail)
        self.error = error if error in ("auth_busy", "enrollment_capacity_exhausted") else "auth_unavailable"
        self.retry_after = retry_after if type(retry_after) is int and 1 <= retry_after <= 600 else 1


def client_perms(client):
    """Effective permissions of a clients.json entry. Entries paired before 1.3.0 have no
    "perms" key and keep full access; a present but malformed value grants nothing."""
    if not isinstance(client, dict):
        return set()
    if "perms" not in client:
        return set(ALL_PERMS)
    perms = client["perms"]
    if not isinstance(perms, list):
        return set()
    return set(p for p in perms if p in ALL_PERMS)


def parse_perms(text):
    """CLI comma list -> canonical permission list. Raises ValueError."""
    items = [p.strip() for p in str(text or "").split(",") if p.strip()]
    bad = [p for p in items if p not in ALL_PERMS]
    if bad or not items:
        raise ValueError("permissions must be a non-empty comma list of %s (got %r)"
                         % (",".join(ALL_PERMS), text))
    return [p for p in ALL_PERMS if p in items]


def _code_digest(code):
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def api_path_ok(path):
    """Path part after /api/<svc>: no empty, "." or ".." segments; no %, backslash or ";"."""
    if any(c in path for c in "%\\;"):
        return False
    return not ("//" in path or "/./" in path or "/../" in path
                or path.endswith("/.") or path.endswith("/.."))


def parse_api_head(head_bytes):
    """Strict HTTP/1.1 request head parser for /api (head_bytes ends with CRLFCRLF).
    Returns (method, svc, path, query, headers {lower name: value}, content_length or None);
    raises ApiReject. Everything ambiguous is refused instead of interpreted."""
    if not head_bytes.endswith(b"\r\n\r\n") or _API_BAD_REQ_BYTES_RE.search(head_bytes):
        raise ApiReject(400, "bad_request")
    lines = head_bytes[:-4].decode("ascii").split("\r\n")
    if any("\r" in line or "\n" in line for line in lines):      # bare CR / LF
        raise ApiReject(400, "bad_request")
    m = _API_REQUEST_LINE_RE.match(lines[0])
    if not m:
        raise ApiReject(400, "bad_request")
    method, target = m.group(1), m.group(2)
    t = _API_TARGET_RE.match(target)
    if not t or not api_path_ok(t.group(2) or "") or _API_BAD_PCT_RE.search(t.group(3) or ""):
        raise ApiReject(400, "bad_target")
    if len(lines) - 1 > API_MAX_HEADERS:
        raise ApiReject(400, "too_many_headers")
    headers = {}
    for line in lines[1:]:
        if line[:1] in (" ", "\t"):                                 # obs-fold
            raise ApiReject(400, "bad_header")
        h = _API_HEADER_RE.match(line)    # no colon / bad name / whitespace before the colon
        if not h:
            raise ApiReject(400, "bad_header")
        name, value = h.group(1).lower(), h.group(2)
        if name in headers:
            if name in HTTP_SINGLETON_HEADERS:
                raise ApiReject(400, "duplicate_header")
            if name in HTTP_LIST_HEADERS:
                headers[name] += ", " + value
            continue
        headers[name] = value
    if "host" not in headers:
        raise ApiReject(400, "bad_request")
    if "transfer-encoding" in headers:
        raise ApiReject(411, "length_required")
    length = None
    if "content-length" in headers:
        if not _API_DIGITS_RE.match(headers["content-length"]):
            raise ApiReject(400, "bad_content_length")
        length = int(headers["content-length"])
    if method == "POST" and length is None:
        raise ApiReject(411, "length_required")
    return method, t.group(1), t.group(2) or "", (t.group(3) or "")[1:], headers, length


def rewrite_api_response_head(head):
    """Backend response head (without the final CRLFCRLF) -> (status, client head bytes, mode, length).
    mode: "length" (Content-Length), "chunked" (passthrough), "eof" (until close), "none".
    Hop-by-hop, cookie, CORS and Server fields are dropped; Connection: close and
    Cache-Control: no-store are set. Raises ValueError on anything ambiguous."""
    if _API_BAD_RESP_BYTES_RE.search(head):
        raise ValueError("control characters in backend head")
    lines = head.decode("latin-1").split("\r\n")
    if any("\r" in line or "\n" in line for line in lines):
        raise ValueError("bare CR/LF in backend head")
    m = _API_STATUS_LINE_RE.match(lines[0])
    if not m:
        raise ValueError("bad status line")
    status = int(m.group(1))
    if status < 200 or status > 599:
        raise ValueError("unexpected status %d" % status)
    reason = (m.group(2) or "").strip() or HTTP_REASONS.get(status, "Status")
    fields = []
    for line in lines[1:]:
        h = _API_HEADER_RE.match(line)
        if not h or line[:1] in (" ", "\t"):
            raise ValueError("bad header line")
        fields.append((h.group(1), h.group(2)))
    hop = set()
    for name, value in fields:
        if name.lower() == "connection":
            hop.update(x.strip().lower() for x in value.split(",") if x.strip())
    lengths = [v for n, v in fields if n.lower() == "content-length"]
    codings = [v for n, v in fields if n.lower() == "transfer-encoding"]
    length = None
    if status in (204, 304):
        mode = "none"
    elif codings:
        if lengths or len(codings) != 1 or codings[0].lower() != "chunked":
            raise ValueError("ambiguous or unsupported transfer-encoding")
        mode = "chunked"
    elif lengths:
        if len(set(lengths)) != 1 or not _API_DIGITS_RE.match(lengths[0]):
            raise ValueError("bad content-length")
        mode, length = "length", int(lengths[0])
    else:
        mode = "eof"
    out = ["HTTP/1.1 %d %s" % (status, reason)]
    for name, value in fields:
        low = name.lower()
        if low in API_RESP_DROP_HEADERS or low in hop or low.startswith("access-control-"):
            continue
        out.append("%s: %s" % (name, value))
    if mode == "length":
        out.append("Content-Length: %d" % length)
    elif mode == "chunked":
        out.append("Transfer-Encoding: chunked")
    out += ["Connection: close", "Cache-Control: no-store"]
    return status, ("\r\n".join(out) + "\r\n\r\n").encode("latin-1"), mode, length


def load_api_routes(path):
    """--api-routes FILE extends or replaces API_ROUTES for robots with other endpoints:
      {"replace": false,
       "routes": [{"svc": "nif", "method": "GET", "path": "/x", "perm": "read",
                   "max_body": 0, "timeout": 10}, ...]}
    Entries override/add (svc, method, path) keys; "replace": true makes the file the whole
    table. Only GET/POST, existing services and API permissions. Raises ValueError/OSError."""
    with open(path, encoding="utf-8") as f:
        spec = json.load(f)
    if not isinstance(spec, dict) or not isinstance(spec.get("routes"), list):
        raise ValueError('expected an object with a "routes" list')
    table = {} if spec.get("replace") is True else dict(API_ROUTES)
    for i, r in enumerate(spec["routes"]):
        where = "routes[%d]" % i
        if not isinstance(r, dict):
            raise ValueError(where + ": not an object")
        svc, method, p, perm = r.get("svc"), r.get("method"), r.get("path"), r.get("perm")
        max_body, timeout = r.get("max_body", 0), r.get("timeout", 10)
        if svc not in API_SERVICES:
            raise ValueError("%s: svc must be one of %s" % (where, ",".join(API_SERVICES)))
        if method not in ("GET", "POST"):
            raise ValueError(where + ": method must be GET or POST")
        if not isinstance(p, str) or not _API_ROUTE_PATH_RE.match(p) or not api_path_ok(p):
            raise ValueError(where + ": bad path %r" % (p,))
        if perm not in API_PERMS:
            raise ValueError("%s: perm must be one of %s" % (where, ",".join(API_PERMS)))
        if (isinstance(max_body, bool) or not isinstance(max_body, int)
                or not 0 <= max_body <= API_ROUTE_BODY_LIMIT or (method == "GET" and max_body)):
            raise ValueError(where + ": max_body must be an integer 0..%d (0 for GET)" % API_ROUTE_BODY_LIMIT)
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0 < timeout <= API_ROUTE_TIMEOUT_LIMIT):
            raise ValueError(where + ": timeout must be a number in (0, %d]" % API_ROUTE_TIMEOUT_LIMIT)
        table[(svc, method, p)] = (perm, max_body, timeout)
    return table


# ---- robot API request bodies: bounded memory, complete before the backend sees a byte ----

def api_body_time(length):
    """Seconds a client gets to deliver a request body of `length` bytes: length / 32 KiB/s, at least
    API_BODY_MIN_TIMEOUT_S, at most API_BODY_MAX_TIMEOUT_S (globals, read at call time)."""
    return min(API_BODY_MAX_TIMEOUT_S, max(API_BODY_MIN_TIMEOUT_S, length / API_BODY_MIN_RATE))


_DISK_FULL_ERRNOS = frozenset(e for e in (errno.ENOSPC, getattr(errno, "EDQUOT", None), errno.EFBIG)
                              if e is not None)


class ApiSpoolError(Exception):
    """The gateway could not store a request body (disk full, quota, file size limit, I/O error, no
    free fd). Raised for the spool file only, never for a client or backend socket - both would be
    OSError - so the caller answers 507/500 instead of treating it as a dropped connection."""

    def __init__(self, err):
        Exception.__init__(self, str(err))
        self.disk_full = getattr(err, "errno", None) in _DISK_FULL_ERRNOS

    def reply(self):
        return (507, "insufficient_storage") if self.disk_full else (500, "spool_failed")


class ApiBody(object):
    """One request body of exactly `length` bytes, complete before the backend is contacted.

    Up to API_BODY_MEM_MAX it is kept as the received chunks (no join copy). A larger body goes from
    its first byte to an unlinked temporary file in the data dir (tempfile.TemporaryFile: O_TMPFILE,
    else mkstemp + immediate unlink), so a 64 MiB photo costs one 64 KiB piece of memory and cannot
    outlive the request on disk: the inode goes with the fd, even on SIGKILL. Not /tmp: that can be
    tmpfs (RAM) on some hosts. Spool pages are reclaimable page cache and are freed by close(). Disk
    use is bounded by the per-service semaphores, taken before a body is read (default routes: 2 pkg
    slots x 64 MiB), and a spool is refused unless API_SPOOL_COPIES x its length + API_SPOOL_MIN_FREE
    is free - what live spools and the backend's copies of their bodies will still take counts as
    used. Spool I/O runs on the event loop: 64 KiB writes into the page cache take microseconds and
    bodies arrive at network speed, far below the disk's, so a thread pool (threads count against
    TasksMax) would buy nothing.
    Every file error surfaces as ApiSpoolError; close() is idempotent."""

    _spooling = set()       # live spools (one per pkg/nif slot at most)

    def __init__(self, length, spool_dir):
        self.length = length
        self.size = 0           # bytes stored so far
        self._parts = []
        self._file = None
        if length > API_BODY_MEM_MAX:
            try:
                st = os.statvfs(spool_dir)
                announced = sum(API_SPOOL_COPIES * b.length - b.size for b in ApiBody._spooling)
                if st.f_bavail * st.f_frsize - announced < API_SPOOL_COPIES * length + API_SPOOL_MIN_FREE:
                    raise OSError(errno.ENOSPC, "a %d byte body (x%d with the backend's copy) would leave less "
                                  "than %d MiB free in %s"
                                  % (length, API_SPOOL_COPIES, API_SPOOL_MIN_FREE // MIB, spool_dir))
                self._file = tempfile.TemporaryFile(dir=spool_dir)
            except OSError as e:
                raise ApiSpoolError(e)
            ApiBody._spooling.add(self)

    @property
    def spooled(self):
        return self._file is not None

    def append(self, data):
        if self._file is None:
            self._parts.append(data)
        else:
            try:
                self._file.write(data)
            except OSError as e:
                raise ApiSpoolError(e)
        self.size += len(data)

    def finish(self):
        """All bytes are in: flush the userspace buffer so a full disk shows up now, before the
        backend is contacted, and not halfway through sending it the request."""
        if self._file is not None:
            try:
                self._file.flush()
            except OSError as e:
                raise ApiSpoolError(e)

    def chunks(self, release=False):
        """The stored body again: pieces of at most API_IO_CHUNK bytes, exactly `size` bytes in all.
        release=True closes the spool once its last piece is read, before that piece is passed on: its
        space is back before the receiver can hold the whole body (network-iface checks the free space
        for its own copy right then, and freeing 64 MiB takes milliseconds)."""
        if self._file is None:
            for part in self._parts:
                yield part
            return
        try:
            self._file.seek(0)
        except OSError as e:
            raise ApiSpoolError(e)
        left = self.size
        while left > 0:
            try:
                data = self._file.read(min(API_IO_CHUNK, left))
            except OSError as e:
                raise ApiSpoolError(e)
            if not data:
                raise ApiSpoolError(OSError(errno.EIO, "spool file shorter than the received body"))
            left -= len(data)
            if release and not left:
                self.close()
            yield data

    def close(self):
        self._parts = []
        ApiBody._spooling.discard(self)
        f, self._file = self._file, None
        if f is not None:
            try:
                f.close()
            except OSError:
                pass


# ====================================================================================
# Ed25519 verification (RFC 8032). The pure-Python verifier is the dependency-free
# fallback for old robots (Ubuntu 18.04 ships python3-cryptography 2.1.4, which has no
# Ed25519). Verification only handles public data, so constant time is not required.
# ====================================================================================

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _ed_add(p, q):
    """Point addition in extended twisted Edwards coordinates (X, Y, Z, T)."""
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _ed_mul(s, p):
    q = (0, 1, 1, 0)  # neutral element
    while s > 0:
        if s & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        s >>= 1
    return q


def _ed_equal(p, q):
    return ((p[0] * q[2] - q[0] * p[2]) % _P == 0) and ((p[1] * q[2] - q[1] * p[2]) % _P == 0)


def _ed_recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _ed_decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


_G_Y = 4 * pow(5, _P - 2, _P) % _P
_G_X = _ed_recover_x(_G_Y, 0)
_G = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def ed25519_pubkey_valid(pub):
    """32 bytes that decode to a curve point (uniform pairing-time check for every backend)."""
    return isinstance(pub, (bytes, bytearray)) and _ed_decompress(bytes(pub)) is not None


def _pure_verify(pub, sig, msg):
    if len(pub) != 32 or len(sig) != 64:
        return False
    a = _ed_decompress(pub)
    if a is None:
        return False
    r_bytes = sig[:32]
    r = _ed_decompress(r_bytes)
    if r is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:  # reject non-canonical S (malleability)
        return False
    h = int.from_bytes(hashlib.sha512(r_bytes + pub + msg).digest(), "little") % _L
    return _ed_equal(_ed_mul(s, _G), _ed_add(r, _ed_mul(h, a)))


def _load_ed25519_backend():
    """Returns (name, verify(pub_bytes, sig_bytes, msg_bytes) -> bool). Fail-closed: any error -> False."""
    forced = os.environ.get("VIZANTI_GW_ED25519", "").strip().lower()
    order = [forced] if forced else ["cryptography", "nacl", "pure"]
    for name in order:
        if name == "cryptography":
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            except ImportError:
                continue

            def verify(pub, sig, msg, _K=Ed25519PublicKey):
                try:
                    _K.from_public_bytes(pub).verify(sig, msg)
                    return True
                except Exception:
                    return False
            return "cryptography", verify
        if name == "nacl":
            try:
                from nacl.signing import VerifyKey
            except ImportError:
                continue

            def verify(pub, sig, msg, _K=VerifyKey):
                try:
                    _K(pub).verify(msg, sig)
                    return True
                except Exception:
                    return False
            return "nacl", verify
        if name == "pure":
            return "pure", _pure_verify
    raise SystemExit(f"vizanti_gateway: Ed25519 backend {forced!r} unavailable (VIZANTI_GW_ED25519)")


ED25519_BACKEND, ed25519_verify = _load_ed25519_backend()

# RFC 8032 section 7.1 TEST 1 - known-answer test for `selfcheck`
_KAT_PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
_KAT_SIG = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
                         "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")


# ====================================================================================
# asyncio portability helpers (Python 3.6 .. 3.12)
# ====================================================================================

def _run(coro):
    """asyncio.run() equivalent that also exists on Python 3.6."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()


def _make_listen_socket(port, backlog):
    """One dual-stack socket (IPv6 + v4-mapped IPv4); IPv4-only when IPv6 is unavailable."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        s = None
    if s is not None:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except (AttributeError, OSError):
                pass
            s.bind(("::", port))
        except OSError as e:
            s.close()
            if e.errno == errno.EADDRINUSE:
                raise
            s = None  # IPv6 disabled on this host -> fall back to IPv4
    if s is None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
    s.listen(backlog)
    s.setblocking(False)
    return s


def _abort_socket(sock):
    """Close with RST (SO_LINGER 0) - used for sockets refused before the TLS handshake."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _set_linger0(transport, on):
    """SO_LINGER (1, 0) on: every close of the socket is a RST, also the kernel's own when the process
    dies (SIGTERM, SIGKILL, OOM kill). Off again: a close is a normal FIN."""
    try:
        sock = transport.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1 if on else 0, 0))
    except Exception:
        pass


def _reset_transport(transport):
    """Abort an asyncio connection with RST (SO_LINGER 0) instead of FIN: for a backend request the
    gateway could not finish sending, so even a backend that reads up to EOF can never take the
    short body for a complete one."""
    _set_linger0(transport, True)
    transport.abort()


def _norm_ip(ip):
    # normalize v4-mapped v6 so IP binding matches across the dual-stack socket
    try:
        address = ipaddress.ip_address(ip)
        return str(getattr(address, "ipv4_mapped", None) or address)
    except ValueError:
        return ip


class _JournalFormatter(logging.Formatter):
    """sd-daemon priority prefix so journald keeps audit INFO lines in a separate pool
    from attacker-triggerable WARNING floods."""
    PRIO = {logging.CRITICAL: 2, logging.ERROR: 3, logging.WARNING: 4, logging.INFO: 6, logging.DEBUG: 7}

    def format(self, record):
        return f"<{self.PRIO.get(record.levelno, 6)}>{record.levelname} {record.getMessage()}" + (
            "\n" + self.formatException(record.exc_info) if record.exc_info else "")


def now() -> float:
    return time.monotonic()


class OpenSSLBIOTransport(asyncio.Transport, asyncio.Protocol):
    """TLS over a bounded asyncio TCP transport, using public pyOpenSSL APIs.

    The application sees a normal StreamReader/StreamWriter. TCP write pressure
    and StreamReader read pressure propagate through this layer; no second read
    task or unbounded plaintext queue is introduced. TLS objects never escape
    the owning event loop. The handshake future is separately deadline bounded.
    """
    MAX_PENDING = 1024 * 1024

    def __init__(self, context, application, loop):
        super().__init__()
        self.application = application
        self.loop = loop
        self.raw = None
        self.tls = OPENSSL_SSL.Connection(context, None)
        self.tls.set_accept_state()
        self.ready = loop.create_future()
        self.handshaken = False
        self.closed = False
        self.pending = bytearray()
        self.write_paused = False
        self.raw_write_paused = False
        self.failure = None

    def connection_made(self, transport):
        # Cancellation can win before connect_accepted_socket attaches TCP.
        # A late callback must close its new transport, never revive the TLS flow.
        if self.closed:
            transport.abort()
            return
        self.raw = transport
        self._pump()

    def _flush_ciphertext(self):
        while True:
            try:
                data = self.tls.bio_read(65536)
            except OPENSSL_SSL.WantReadError:
                return
            if not data:
                return
            self.raw.write(data)

    def _pump(self):
        if self.closed:
            return
        try:
            if not self.handshaken:
                try:
                    self.tls.do_handshake()
                except (OPENSSL_SSL.WantReadError, OPENSSL_SSL.WantWriteError):
                    self._flush_ciphertext()
                    return
                self.handshaken = True
                self.application.connection_made(self)
                self._update_pressure()
                if not self.ready.done():
                    self.ready.set_result(self)
            while self.pending:
                try:
                    sent = self.tls.send(bytes(self.pending[:65536]))
                    del self.pending[:sent]
                    self._flush_ciphertext()
                except (OPENSSL_SSL.WantReadError, OPENSSL_SSL.WantWriteError):
                    break
            self._flush_ciphertext()
            self._update_pressure()
            while True:
                try:
                    data = self.tls.recv(65536)
                except (OPENSSL_SSL.WantReadError, OPENSSL_SSL.WantWriteError):
                    break
                except OPENSSL_SSL.ZeroReturnError:
                    self.close()
                    break
                if not data:
                    break
                self.application.data_received(data)
                # StreamReader may have paused TCP at its high water mark.
                if not self.raw.is_reading():
                    break
            self._flush_ciphertext()
        except OPENSSL_SSL.Error:
            self._failed(ConnectionError("TLS connection failed"))
        except Exception as exc:
            self._failed(exc)

    def data_received(self, data):
        if self.closed:
            return
        try:
            self.tls.bio_write(data)
        except OPENSSL_SSL.Error:
            self._failed(ConnectionError("TLS input failed"))
            return
        self._pump()

    def eof_received(self):
        # A TCP EOF without close_notify is not authenticated TLS EOF.
        self._failed(ConnectionError("TLS peer disconnected"))
        return False

    def connection_lost(self, exc):
        self.closed = True
        if not self.ready.done():
            self.ready.set_exception(exc or ConnectionError("TLS handshake closed"))
        if self.handshaken:
            self.application.connection_lost(exc or self.failure)

    def _failed(self, exc):
        if not self.ready.done():
            self.ready.set_exception(exc)
        self.failure = exc
        self.abort()

    def pause_writing(self):
        self.raw_write_paused = True
        self._update_pressure()

    def resume_writing(self):
        self.raw_write_paused = False
        self._update_pressure()

    def _update_pressure(self):
        if not self.handshaken:
            return
        blocked = self.raw_write_paused or bool(self.pending)
        if blocked and not self.write_paused:
            self.write_paused = True
            self.application.pause_writing()
        elif not blocked and self.write_paused:
            self.write_paused = False
            self.application.resume_writing()

    def write(self, data):
        if self.closed:
            raise ConnectionError("TLS transport closed")
        if len(self.pending) + len(data) > self.MAX_PENDING:
            self.abort()
            raise ConnectionError("TLS output queue exceeded")
        self.pending.extend(data)
        self._update_pressure()
        self._pump()

    def writelines(self, lines):
        for line in lines:
            self.write(line)

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.tls.shutdown()
            self._flush_ciphertext()
        except OPENSSL_SSL.Error:
            pass
        if self.raw is not None:
            self.raw.close()

    def abort(self):
        self.closed = True
        self.pending.clear()
        if not self.ready.done():
            self.ready.cancel()
        if self.raw is not None:
            self.raw.abort()

    def is_closing(self):
        return self.closed or (self.raw is not None and self.raw.is_closing())

    def pause_reading(self):
        self.raw.pause_reading()

    def resume_reading(self):
        self.raw.resume_reading()
        # SSL may retain decrypted records after StreamReader paused TCP.
        self.loop.call_soon(self._pump)

    def is_reading(self):
        return not self.closed and self.raw.is_reading()

    def get_write_buffer_size(self):
        return len(self.pending) + self.raw.get_write_buffer_size()

    def get_write_buffer_limits(self):
        return self.raw.get_write_buffer_limits()

    def set_write_buffer_limits(self, high=None, low=None):
        return self.raw.set_write_buffer_limits(high=high, low=low)

    def can_write_eof(self):
        return False

    def get_extra_info(self, name, default=None):
        if name == "ssl_object":
            return self.tls
        return self.raw.get_extra_info(name, default)

    def enrollment_binding(self):
        if not self.handshaken or self.tls.get_protocol_version_name() != "TLSv1.3":
            raise ValueError("enrollment requires TLS 1.3")
        # b"" means a PRESENT empty context in pyOpenSSL's supported exporter API.
        return self.tls.export_keying_material(TLS_EXPORTER_LABEL, 32, b"")


class AcceptedSocketProtocol(asyncio.Protocol):
    """Own a transport even if its connection callback arrives after cancellation.

    The public asyncio attachment coroutine may be pending before a transport
    exists. Closing only the original socket misses that ownership transition.
    This guard also consumes the attachment task's eventual result/exception.
    """
    def __init__(self, application):
        self.application = application
        self.transport = None
        self.aborted_transport = None
        self.closed = False
        self.attached = False

    def connection_made(self, transport):
        self.transport = transport
        if self.closed:
            self._abort_transport(transport)
            return
        self.attached = True
        self.application.connection_made(transport)

    def attachment_done(self, task):
        if task.cancelled():
            return
        try:
            transport, _ = task.result()
        except Exception:
            return
        if self.closed:
            self._abort_transport(transport)

    def _abort_transport(self, transport):
        if transport is not self.aborted_transport:
            self.aborted_transport = transport
            transport.abort()

    def abort(self):
        self.closed = True
        if self.transport is not None:
            self._abort_transport(self.transport)

    def data_received(self, data):
        if not self.closed:
            self.application.data_received(data)

    def eof_received(self):
        return self.application.eof_received() if self.attached and not self.closed else False

    def connection_lost(self, exc):
        self.closed = True
        if self.attached:
            self.application.connection_lost(exc)

    def pause_writing(self):
        if self.attached and not self.closed:
            self.application.pause_writing()

    def resume_writing(self):
        if self.attached and not self.closed:
            self.application.resume_writing()


class Gateway:
    def __init__(self, args):
        self.args = args
        self.auth_mode = getattr(args, "auth_mode", "legacy")
        self.nif_auth_socket = getattr(args, "nif_auth_socket", "/run/rgt-network-iface/gateway.sock")
        self.nif_auth_uid = getattr(args, "nif_auth_uid", os.getuid())
        self.nif_instance = None
        self.data_dir = os.path.expanduser(args.data_dir)
        self.clients_path = os.path.join(self.data_dir, "clients.json")
        self.pairing_code_path = os.path.join(self.data_dir, "pairing_code")
        self.pairing_perms_path = os.path.join(self.data_dir, "pairing_perms")
        self.cert_path = os.path.join(self.data_dir, "tls_cert.pem")
        self.key_path = os.path.join(self.data_dir, "tls_key.pem")
        self.cert_fingerprint = None
        self.ssl_ctx = None
        self.openssl_enabled = False
        self.tls_sem = None     # created inside the running loop (3.6-3.9 bind primitives at creation)
        self._tasks = set()     # strong refs to connection tasks
        self.clients = {}
        self.clients_sig = None # (mtime_ns, inode, size) of the clients.json last loaded
        self.sessions = {}      # token -> {client_id, ip, expires}
        self.nonces = {}        # nonce -> {client_id, ip, expires}
        self.otts = {}          # ott -> {client_id, ip, expires}
        self.conns = {}         # id -> {client_id, token, ip, cwriter, bwriter, opened, last_active}
        self.conn_seq = 0
        self.live_total = 0     # accepted sockets incl. mid-handshake
        self.per_ip = {}        # ip -> live sockets
        self.per_ip_splice = {} # ip -> spliced connections
        self.pair_attempts = {} # ip -> [timestamps]  (bounded, see /gw/pair)
        self._warn_last = {}    # (event, ip) -> [last_ts, suppressed]
        self._warn_event_last = {}  # event -> last_ts
        # robot API
        self.api_routes = dict(API_ROUTES)      # --api-routes is applied in serve()
        self.api_ports = {"nif": args.nif_port, "pkg": args.pkg_port}
        self.api_tokens = {}    # token -> {client_id, ip, perms, expires}
        self.api_sems = {}      # svc -> asyncio.Semaphore (created inside the running loop)
        self.api_live = 0       # API connections in progress
        self.api_per_ip = {}    # ip -> API connections in progress
        self.api_conns = {}     # id -> {client_id, cwriter, bwriter, status, nin, nout, complete, severed}
        self.api_get_stats = {} # (name, id8, ip, svc, path, status) -> count, flushed by the janitor
        self.api_get_since = now()
        if self.auth_mode == "legacy":
            self.load_clients(initial=True)

    async def nif_auth(self, op, **fields):
        try:
            return await asyncio.wait_for(self._nif_auth(op, **fields), 2.0)
        except asyncio.TimeoutError:
            raise AuthUnavailable("authority deadline exceeded")

    async def _nif_auth(self, op, **fields):
        """One bounded JSON-line RPC to the local, UID-checked NIF authority."""
        reader, writer = None, None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.nif_auth_socket, limit=65536), 1.0)
            peer = writer.get_extra_info("socket")
            creds = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            if struct.unpack("3i", creds)[1] != self.nif_auth_uid:
                raise AuthUnavailable("unexpected authority UID")
            request = dict(fields, v=1, op=op, fp=self.cert_fingerprint or "")
            raw = json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n"
            if len(raw) > 65536:
                raise AuthUnavailable("authority request too large")
            writer.write(raw)
            await asyncio.wait_for(writer.drain(), 1.0)
            line = await asyncio.wait_for(reader.readline(), 1.5)
            if not line.endswith(b"\n") or len(line) > 65536:
                raise AuthUnavailable("incomplete authority response")
            reply = json.loads(line.decode("utf-8"))
            if not isinstance(reply, dict) or reply.get("v") != 1 or not isinstance(reply.get("ok"), bool):
                raise AuthUnavailable("invalid authority response")
            instance = reply.get("instance_id")
            if not isinstance(instance, str) or not instance:
                raise AuthUnavailable("authority instance missing")
            if self.nif_instance is not None and instance != self.nif_instance:
                self.sessions.clear()
                self.otts.clear()
                self.sever(lambda c: True, "authority_restart")
            self.nif_instance = instance
            if not reply["ok"] and reply.get("status") == 503:
                raise AuthUnavailable("authority rejected service state", reply.get("error"), reply.get("retry_after"))
            return reply
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
            raise AuthUnavailable(type(e).__name__)
        finally:
            if writer is not None:
                writer.close()

    @staticmethod
    def auth_status(reply):
        value = reply.get("status", 403)
        return value if isinstance(value, int) and value in (400, 401, 403, 404, 409, 429, 503) else 403

    def auth_reject(self, writer, reply, default="auth_failed"):
        """Forward only stable public error/rate information, never authority state."""
        status = self.auth_status(reply)
        value = {"error": reply.get("error", default)}
        extra = []
        retry = reply.get("retry_after")
        if status in (429, 503) and type(retry) is int and 1 <= retry <= 600:
            value["retry_after_seconds"] = retry
            extra.append("Retry-After: %d" % retry)
        self.json_resp(writer, status, value, extra=extra)

    async def nif_gateway(self, method, path, query, headers, reader, writer, ip, leftover):
        """NIF mode owns *all* registrations, challenges and bearer/UI sessions."""
        if method == "POST" and path == "/gw/enroll/result":
            if self.args.no_tls:
                return self.json_resp(writer, 403, {"error": "tls_required"})
            body = await self.read_json_body(reader, headers, leftover)
            fields = {key: body[key] for key in ("request_id", "pubkey", "client_name", "signature") if key in body}
            reply = await self.nif_auth("enrollment_result", peer_ip=ip, **fields)
            if not reply["ok"]:
                return self.auth_reject(writer, reply, "enrollment_rejected")
            return self.json_resp(writer, 200, dict(ok=True, **{key: reply[key] for key in ("client_id", "perms") if key in reply}))
        if method == "POST" and path in ("/gw/pair", "/gw/challenge", "/gw/api-token", "/gw/session"):
            body = await self.read_json_body(reader, headers, leftover)
            ops = {"/gw/pair": "pair", "/gw/challenge": "challenge",
                   "/gw/api-token": "api_token", "/gw/session": "session"}
            allowed = ("client_id", "pubkey", "proof", "request_id", "enroll_sig", "nonce", "sig", "purpose")
            fields = {k: body[k] for k in allowed if k in body}
            if path == "/gw/pair":
                fields["name"] = body.get("client_name", "")
            reply = await self.nif_auth(ops[path], peer_ip=ip, **fields)
            if not reply["ok"]:
                return self.auth_reject(writer, reply)
            if path == "/gw/session":
                if not isinstance(reply.get("token"), str) or "ui" not in reply.get("perms", []):
                    raise AuthUnavailable("invalid authority UI session")
                ott = secrets.token_urlsafe(32)
                self.otts[ott] = {"client_id": reply["client_id"], "ip": ip,
                    "expires": now() + OTT_TTL_S, "nif_token": reply["token"],
                    "nif_instance": reply["instance_id"], "ttl": reply["ttl"]}
                return self.json_resp(writer, 200, {"ott": ott, "ott_ttl": OTT_TTL_S,
                    "robot_uid": self.robot_uid(), "session_ttl": reply["ttl"]})
            # Do not expose internal authority state or any extra secret field to clients.
            keys = {"/gw/pair": ("client_id", "perms"),
                    "/gw/challenge": ("nonce", "ttl"),
                    "/gw/api-token": ("token", "ttl", "perms")}[path]
            result = {k: reply[k] for k in keys if k in reply}
            if path == "/gw/challenge":
                result["cert_fingerprint"] = self.cert_fingerprint
            if path == "/gw/api-token":
                result["robot_uid"] = self.robot_uid()
            return self.json_resp(writer, 200, result)
        if path == "/gw/sso" and method == "GET":
            ott = (query.get("ott") or [""])[0]
            entry = self.otts.pop(ott, None)
            if entry is None or entry["expires"] <= now() or entry["ip"] != ip:
                return self.respond(writer, 403, PAGE_SSO_EXPIRED, "text/html; charset=utf-8")
            reply = await self.nif_auth("validate", token=entry["nif_token"], purpose="ui", peer_ip=ip)
            if (not reply["ok"] or reply["instance_id"] != entry["nif_instance"]
                    or "ui" not in reply.get("perms", [])):
                return self.respond(writer, 403, PAGE_SSO_EXPIRED, "text/html; charset=utf-8")
            token = entry["nif_token"]
            ttl = max(1, min(SESSION_TTL_S, int(reply["ttl"])))
            self.sessions[token] = {"client_id": reply["client_id"], "ip": ip,
                "expires": now() + ttl, "nif_instance": reply["instance_id"]}
            cookie = f"{COOKIE_NAME}={token}; Path=/; Max-Age={ttl}; HttpOnly; SameSite=Strict"
            if not self.args.no_tls:
                cookie += "; Secure"
            return self.respond(writer, 302, b"", "text/plain", extra=["Set-Cookie: " + cookie, "Location: /"])
        if path == "/gw/logout" and method == "GET":
            token = self.cookie_token(headers)
            entry = self.sessions.get(token)
            if entry and entry["ip"] == ip:
                self.sessions.pop(token, None)
                self.sever(lambda c: c["token"] == token, "logout")
                await self.nif_auth("logout", token=token, purpose="ui", peer_ip=ip)
            return self.respond(writer, 302, b"", "text/plain", extra=["Location: /",
                f"Set-Cookie: {COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"])
        return self.json_resp(writer, 404, {"error": "not_found"})

    async def authorize_ui(self, headers, ip):
        if self.auth_mode == "legacy":
            return self.session_for(headers, ip)
        token = self.cookie_token(headers)
        entry = self.sessions.get(token)
        if not entry or entry["expires"] <= now() or entry["ip"] != ip:
            return None, None
        reply = await self.nif_auth("validate", token=token, purpose="ui", peer_ip=ip)
        if (not reply["ok"] or "ui" not in reply.get("perms", [])
                or reply["instance_id"] != entry["nif_instance"]):
            self.sessions.pop(token, None)
            self.sever(lambda c: c["token"] == token, "revoked")
            return None, None
        return entry, token

    async def authorize_api(self, value, ip):
        if self.auth_mode == "legacy":
            return self.api_auth(value, ip)
        scheme, _, token = (value or "").partition(" ")
        if scheme.lower() != "bearer" or not _API_TOKEN_RE.fullmatch(token):
            return None, None
        reply = await self.nif_auth("validate", token=token, purpose="api", peer_ip=ip)
        if not reply["ok"]:
            return None, None
        return reply["client_id"], set(reply.get("perms", []))

    def _spawn(self, coro):
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    # ---------- throttled logging for attacker-triggerable events ----------

    def _warn(self, event, ip, fmt, *args):
        t = now()
        if t - self._warn_event_last.get(event, 0.0) < 1.0:   # global per-event 1/s (IPv6 rotation)
            return
        key = (event, ip)
        last = self._warn_last.get(key)
        if last and t - last[0] < WARN_PER_KEY_S:
            last[1] += 1
            return
        if len(self._warn_last) >= WARN_KEYS_CAP:
            self._warn_last.pop(next(iter(self._warn_last)))
        suppressed = last[1] if last else 0
        self._warn_last[key] = [t, 0]
        self._warn_event_last[event] = t
        log.warning(fmt + (f" (+{suppressed} suppressed)" if suppressed else ""), *args)

    # ---------- registration store ----------

    @staticmethod
    def _file_sig(st):
        # mtime alone can miss two CLI writes inside one timestamp tick; every save is a new
        # inode (os.replace) and set-perms usually changes the size as well
        return (st.st_mtime_ns, st.st_ino, st.st_size)

    def load_clients(self, initial=False):
        try:
            st = os.stat(self.clients_path)
        except FileNotFoundError:
            self.clients, self.clients_sig = {}, None
            return
        if not initial and self._file_sig(st) == self.clients_sig:
            return
        try:
            with open(self.clients_path, encoding="utf-8") as f:
                clients = json.load(f)
            if not isinstance(clients, dict):
                raise ValueError("top level is not an object")
            self.clients = clients
            self.clients_sig = self._file_sig(st)
        except PermissionError as e:
            log.error("clients.json unreadable (%s) - check ownership, run the CLI as the gateway user; keeping previous set", e)
        except (OSError, ValueError) as e:
            log.error("clients.json unreadable, keeping previous set: %s", e)

    def save_clients(self):
        os.makedirs(self.data_dir, mode=0o700, exist_ok=True)
        tmp = f"{self.clients_path}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.clients, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.clients_path)
        self.clients_sig = self._file_sig(os.stat(self.clients_path))

    def robot_uid(self) -> str:
        try:
            with open(self.args.robot_uid_file, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return "unknown"

    def load_cert_fingerprint(self):
        """SHA-256 of the DER certificate, or None without a cert (no-tls)."""
        try:
            with open(self.cert_path, "rb") as f:
                der = ssl.PEM_cert_to_DER_cert(f.read().decode())
        except (OSError, ValueError):
            return None
        return hashlib.sha256(der).hexdigest()

    def read_pairing_code(self):
        """Current pairing code or '' when absent/expired (expired files are removed: fail-closed)."""
        try:
            st = os.stat(self.pairing_code_path)
            age = time.time() - st.st_mtime
            if age > PAIR_CODE_TTL_S or age < -60:   # clock went backwards -> treat as expired too
                self.remove_pairing_files()
                log.warning("pairing code expired (age=%.0fs) - issue a new one with `newcode`", age)
                return ""
            with open(self.pairing_code_path, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return ""

    def read_pairing_perms(self, code):
        """Permissions issued with the current pairing code (`newcode --perms`), canonical order.
        No perms file = a code from a pre-1.3.0 `newcode`: full access, as it always granted.
        A perms file that is unreadable or bound to a different code fails closed (None)."""
        try:
            with open(self.pairing_perms_path, encoding="utf-8") as f:
                obj = json.load(f)
        except FileNotFoundError:
            return list(ALL_PERMS)
        except (OSError, ValueError):
            return None
        if not isinstance(obj, dict) or not hmac.compare_digest(
                str(obj.get("code_sha256", "")).encode("utf-8"), _code_digest(code).encode("utf-8")):
            return None
        perms = obj.get("perms")
        if not isinstance(perms, list) or not perms or any(p not in ALL_PERMS for p in perms):
            return None
        return [p for p in ALL_PERMS if p in perms]

    def write_pairing(self, code, perms):
        """newcode: the perms file first (bound to the code by hash), then the code itself, so a
        pairing never sees the new code without its permissions."""
        os.makedirs(self.data_dir, mode=0o700, exist_ok=True)
        tmp = "%s.%d.tmp" % (self.pairing_perms_path, os.getpid())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"code_sha256": _code_digest(code), "perms": list(perms)}, f)
            f.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.pairing_perms_path)
        with open(self.pairing_code_path, "w", encoding="utf-8") as f:
            f.write(code + "\n")
        os.chmod(self.pairing_code_path, 0o600)

    def remove_pairing_files(self):
        for p in (self.pairing_code_path, self.pairing_perms_path):
            try:
                os.remove(p)
            except FileNotFoundError:
                pass

    # ---------- small HTTP plumbing ----------

    @staticmethod
    async def read_head(reader, timeout=HEAD_TIMEOUT_S):
        """Read the request head (<=16KB, <=2s). Returns (head_bytes, leftover)."""
        buf = b""
        deadline = now() + timeout
        while b"\r\n\r\n" not in buf:
            remain = deadline - now()
            if remain <= 0 or len(buf) >= MAX_HEAD_BYTES:
                raise ValueError("head too slow or too large")
            chunk = await asyncio.wait_for(reader.read(4096), timeout=remain)
            if not chunk:
                raise ValueError("closed before head")
            buf += chunk
        head, _, leftover = buf.partition(b"\r\n\r\n")
        head += b"\r\n\r\n"
        if len(head) > MAX_HEAD_BYTES:
            raise ValueError("head too large")
        return head, leftover

    @staticmethod
    def parse_head(head_bytes):
        """Common HTTP/1.1 syntax and framing gate, before any route/auth RPC."""
        if (len(head_bytes) > MAX_HEAD_BYTES or not head_bytes.endswith(b"\r\n\r\n")
                or _API_BAD_REQ_BYTES_RE.search(head_bytes)):
            raise ApiReject(400, "bad_request")
        lines = head_bytes[:-4].decode("ascii").split("\r\n")
        if any("\r" in line or "\n" in line for line in lines):
            raise ApiReject(400, "bad_request")
        request = _API_REQUEST_LINE_RE.fullmatch(lines[0])
        if not request:
            raise ApiReject(400, "bad_request")
        method, target = request.groups()
        if (not target.startswith("/") or target.startswith("//") or "#" in target
                or "\\" in target or _API_BAD_PCT_RE.search(target)):
            raise ApiReject(400, "bad_target")
        if len(lines) - 1 > API_MAX_HEADERS:
            raise ApiReject(400, "too_many_headers")
        headers = {}
        for line in lines[1:]:
            header = _API_HEADER_RE.fullmatch(line)
            if not header or line.startswith((" ", "\t")):
                raise ApiReject(400, "bad_header")
            name, value = header.group(1).lower(), header.group(2)
            if name in headers:
                if name in HTTP_SINGLETON_HEADERS:
                    raise ApiReject(400, "duplicate_header")
                if name in HTTP_LIST_HEADERS:
                    headers[name] += ", " + value
                continue
            headers[name] = value
        host = headers.get("host", "")
        if not re.fullmatch(r"(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._~-]+)(?::[0-9]{1,5})?", host):
            raise ApiReject(400, "bad_host")
        try:
            authority = urllib.parse.urlsplit("//" + host)
            authority.port  # also rejects out-of-range ports
            if host.startswith("["):
                ipaddress.IPv6Address(authority.hostname)
        except ValueError:
            raise ApiReject(400, "bad_host")
        if "transfer-encoding" in headers:
            raise ApiReject(411, "length_required")
        if "content-length" in headers and not _API_DIGITS_RE.fullmatch(headers["content-length"]):
            raise ApiReject(400, "bad_content_length")
        return method, target, headers

    @staticmethod
    def respond(writer, status, body=b"", ctype="application/json; charset=utf-8", extra=(), keep_alive=False):
        reasons = {200: "OK", 302: "Found", 400: "Bad Request", 401: "Unauthorized",
                   403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 409: "Conflict",
                   408: "Request Timeout", 411: "Length Required", 413: "Payload Too Large",
                   417: "Expectation Failed", 429: "Too Many Requests", 500: "Internal Server Error",
                   502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
                   507: "Insufficient Storage"}
        if isinstance(body, str):
            body = body.encode("utf-8")
        head = [f"HTTP/1.1 {status} {reasons.get(status, 'X')}",
                f"Content-Type: {ctype}",
                f"Content-Length: {len(body)}",
                "Connection: keep-alive" if keep_alive else "Connection: close",
                "Referrer-Policy: no-referrer",
                "X-Content-Type-Options: nosniff",
                "Cache-Control: no-store"]
        head.extend(extra)
        writer.write(("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body)

    def json_resp(self, writer, status, obj, keep_alive=False, extra=()):
        self.respond(writer, status, json.dumps(obj), keep_alive=keep_alive, extra=extra)

    async def read_json_body(self, reader, headers, leftover):
        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            raise ValueError("bad content-length")
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("body too large")
        body = leftover
        deadline = now() + HEAD_TIMEOUT_S
        while len(body) < length:
            remain = deadline - now()
            if remain <= 0:
                raise ValueError("body too slow")
            chunk = await asyncio.wait_for(reader.read(length - len(body)), timeout=remain)
            if not chunk:
                raise ValueError("closed before body")
            body += chunk
        obj = json.loads(body.decode("utf-8")) if length else {}
        if not isinstance(obj, dict):
            raise ValueError("body must be a JSON object")
        return obj

    @staticmethod
    async def flush_close(writer):
        try:
            await writer.drain()
        except OSError:
            pass

    # ---------- /gw/ endpoints ----------

    async def enrollment_protocols(self):
        if self.auth_mode != "nif-device-v1" or not self.openssl_enabled:
            return []
        reply = await self.nif_auth("enrollment_capabilities")
        return ([ENROLLMENT_PROTOCOL] if reply.get("ok") and
                ENROLLMENT_PROTOCOL in reply.get("enrollment_protocols", []) else [])

    async def read_enrollment_body(self, head, reader, leftover, expected_path):
        """Strict, bounded HTTP/1.1 framing for the only persistent HTTP flow."""
        method, target, headers = self.parse_head(head)
        if method != "POST" or target != expected_path:
            raise ValueError("unexpected enrollment step")
        length = headers.get("content-length", "")
        if (not re.fullmatch(r"[0-9]{1,5}", length) or "transfer-encoding" in headers
                or "expect" in headers or "upgrade" in headers or "host" not in headers):
            raise ValueError("invalid enrollment framing")
        length = int(length)
        if not 0 < length <= MAX_BODY_BYTES or len(leftover) > length:
            raise ValueError("invalid enrollment body size")
        # Read only this body. A later request can only be the next enrollment
        # step and can never enter a business route on this connection.
        body = leftover + await asyncio.wait_for(reader.readexactly(length - len(leftover)), HEAD_TIMEOUT_S)
        value = json.loads(body.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("enrollment body must be an object")
        return value

    async def handle_enrollment(self, head, leftover, reader, writer, ip):
        if self.auth_mode != "nif-device-v1" or not isinstance(writer.transport, OpenSSLBIOTransport):
            return self.json_resp(writer, 503, {"error": "enrollment_unavailable"})
        try:
            exporter = writer.transport.enrollment_binding()
        except ValueError:
            return self.json_resp(writer, 403, {"error": "tls13_required"})
        connection = {"connection_id": secrets.token_hex(16),
                      "tls_exporter": base64.b64encode(exporter).decode("ascii"),
                      "cert_fingerprint": self.cert_fingerprint, "peer_ip": ip}
        complete = False
        try:
            deadline = now() + ENROLLMENT_TIMEOUT_S
            steps = (("start", "pake_begin", ("request_id", "pubkey", "client_name"),
                      ("protocol", "session_id", "generation_id", "auth_instance_id", "perms", "server_message")),
                     ("confirm", "pake_confirm", ("session_id", "client_message", "proof"), ("proof",)),
                     ("commit", "pake_commit", ("session_id", "proof", "signature"), ("client_id", "perms")))
            session_id = None
            for index, (step, op, allowed, returned) in enumerate(steps):
                if index:
                    remaining = deadline - now()
                    if remaining <= 0:
                        raise ValueError("enrollment deadline")
                    head, leftover = await self.read_head(reader, min(remaining, 15.0))
                body = await self.read_enrollment_body(head, reader, leftover, "/gw/enroll/" + step)
                if index and body.get("session_id") != session_id:
                    raise ValueError("enrollment session changed")
                fields = {key: body[key] for key in allowed if key in body}
                reply = await self.nif_auth(op, **dict(connection, **fields))
                if not reply.get("ok"):
                    self.auth_reject(writer, reply, "enrollment_rejected")
                    await self.flush_close(writer)
                    return
                if not index:
                    session_id = reply.get("session_id")
                    if not isinstance(session_id, str) or not session_id:
                        raise AuthUnavailable("invalid enrollment session")
                result = {key: reply[key] for key in returned if key in reply}
                result["ok"] = True
                self.json_resp(writer, 200, result, keep_alive=index < 2)
                await writer.drain()
            complete = True
        finally:
            if not complete:
                try:
                    await self.nif_auth("pake_abort", **connection)
                except AuthUnavailable:
                    pass

    def purge_expired(self):
        t = now()
        for store in (self.sessions, self.nonces, self.otts, self.api_tokens):
            for k in [k for k, v in store.items() if v["expires"] <= t]:
                del store[k]

    def pair_proof(self, code, pub_b64, name):
        fp = (self.cert_fingerprint or "").encode()
        msg = PAIR_PROOF_CONTEXT + b"|" + fp + b"|" + pub_b64.encode() + b"|" + name.encode()
        return hmac.new(code.encode(), msg, hashlib.sha256).hexdigest()

    def take_nonce(self, nonce, client_id, ip):
        """Consume a /gw/challenge nonce FIRST (single use even on failure); True when it was
        live and issued to this client at this IP."""
        entry = self.nonces.pop(nonce, None)
        return not (entry is None or entry["expires"] <= now()
                    or entry["ip"] != ip or entry["client_id"] != client_id)

    def verify_client_sig(self, client, context, client_id, nonce, sig_b64):
        """Ed25519 over context|cert fingerprint|client_id|nonce. The context separates the
        UI session (SIGN_CONTEXT) from the API token (API_SIGN_CONTEXT)."""
        fp = (self.cert_fingerprint or "").encode()
        msg = context + b"|" + fp + b"|" + client_id.encode() + b"|" + nonce.encode()
        try:
            return ed25519_verify(base64.b64decode(client["ed25519_pub"]), base64.b64decode(sig_b64), msg)
        except (ValueError, KeyError, TypeError):
            return False

    async def handle_gw(self, method, path, query, headers, reader, writer, ip, leftover):
        self.purge_expired()

        if path == "/gw/info" and method in ("GET", "HEAD"):
            # deliberately minimal: no robot_uid before authentication
            return self.json_resp(writer, 200, {
                "service": "vizanti-gateway", "version": VERSION,
                "tls": not self.args.no_tls, "cert_fingerprint": self.cert_fingerprint,
                "api": 1, "api_services": list(API_SERVICES), "auth_mode": self.auth_mode,
                "enrollment_protocols": await self.enrollment_protocols()})

        if self.auth_mode == "nif-device-v1":
            return await self.nif_gateway(method, path, query, headers, reader, writer, ip, leftover)

        if path == "/gw/pair" and method == "POST":
            ts = self.pair_attempts.setdefault(ip, [])
            while len(self.pair_attempts) > PAIR_ATTEMPTS_CAP:          # bounded: evict oldest sources
                k = next(iter(self.pair_attempts))
                if k == ip:
                    break
                del self.pair_attempts[k]
            ts[:] = [x for x in ts if x > now() - PAIR_WINDOW_S]
            if len(ts) >= PAIR_MAX_PER_WINDOW:
                self._warn("pair-rate", ip, "pair rate-limited ip=%s", ip)
                return self.json_resp(writer, 429, {"error": "rate_limited"})
            ts.append(now())
            body = await self.read_json_body(reader, headers, leftover)
            name = str(body.get("client_name", ""))
            pub_b64 = str(body.get("pubkey", ""))
            proof = str(body.get("proof", ""))
            if not CLIENT_NAME_RE.match(name):
                return self.json_resp(writer, 400, {"error": "bad_client_name"})
            try:
                pub_ok = ed25519_pubkey_valid(base64.b64decode(pub_b64, validate=True))
            except Exception:
                pub_ok = False
            if not pub_ok:
                return self.json_resp(writer, 400, {"error": "bad_pubkey"})
            expected = self.read_pairing_code()
            # the code itself never travels: the proof binds it to THIS certificate, key and name
            if not expected or not hmac.compare_digest(proof.encode(), self.pair_proof(expected, pub_b64, name).encode()):
                self._warn("pair-fail", ip, "pair FAILED (bad/absent/expired code or wrong certificate) ip=%s", ip)
                return self.json_resp(writer, 403, {"error": "pairing_rejected"})
            perms = self.read_pairing_perms(expected)
            if perms is None:   # only a holder of the valid code gets here: not attacker-triggerable
                log.error("pair REFUSED: %s is unreadable or belongs to another code - issue a new "
                          "token with `newcode`", self.pairing_perms_path)
                return self.json_resp(writer, 403, {"error": "pairing_rejected"})
            client_id = uuid.uuid4().hex
            self.load_clients()
            self.clients[client_id] = {
                "name": name, "ed25519_pub": pub_b64, "perms": perms,
                "paired_at": int(time.time()), "paired_from": ip}
            self.save_clients()
            self.remove_pairing_files()  # single-use: a new token must be issued per device
            log.info("pair OK client=%s(%s) ip=%s perms=%s - pairing code consumed",
                     name, client_id[:8], ip, ",".join(perms))
            return self.json_resp(writer, 200, {"client_id": client_id, "perms": perms})

        if path == "/gw/challenge" and method == "POST":
            body = await self.read_json_body(reader, headers, leftover)
            client_id = str(body.get("client_id", ""))
            self.load_clients()
            if client_id not in self.clients:
                self._warn("challenge-unknown", ip, "challenge for unknown client ip=%s", ip)
                return self.json_resp(writer, 403, {"error": "unknown_client"})
            mine = [k for k, v in self.nonces.items() if v["ip"] == ip]
            if len(mine) >= NONCE_PER_IP_CAP:
                del self.nonces[mine[0]]
            while len(self.nonces) >= NONCE_GLOBAL_CAP:
                del self.nonces[next(iter(self.nonces))]
            nonce = secrets.token_urlsafe(32)
            self.nonces[nonce] = {"client_id": client_id, "ip": ip, "expires": now() + NONCE_TTL_S}
            return self.json_resp(writer, 200, {"nonce": nonce, "ttl": NONCE_TTL_S,
                                                "cert_fingerprint": self.cert_fingerprint})

        if path == "/gw/session" and method == "POST":
            body = await self.read_json_body(reader, headers, leftover)
            client_id = str(body.get("client_id", ""))
            nonce = str(body.get("nonce", ""))
            sig_b64 = str(body.get("sig", ""))
            if not self.take_nonce(nonce, client_id, ip):   # consume FIRST - single use even on failure
                self._warn("session-nonce", ip, "session FAILED (nonce) ip=%s", ip)
                return self.json_resp(writer, 403, {"error": "auth_failed"})
            self.load_clients()
            client = self.clients.get(client_id)
            if client is None:
                return self.json_resp(writer, 403, {"error": "auth_failed"})
            if not self.verify_client_sig(client, SIGN_CONTEXT, client_id, nonce, sig_b64):
                self._warn("session-sig", ip, "session FAILED (signature) client=%s ip=%s", client_id[:8], ip)
                return self.json_resp(writer, 403, {"error": "auth_failed"})
            if "ui" not in client_perms(client):
                self._warn("session-perm", ip, "session DENIED (no ui permission) client=%s ip=%s", client_id[:8], ip)
                return self.json_resp(writer, 403, {"error": "forbidden"})
            ott = secrets.token_urlsafe(32)
            self.otts[ott] = {"client_id": client_id, "ip": ip, "expires": now() + OTT_TTL_S}
            log.info("session OK client=%s(%s) ip=%s", client.get("name"), client_id[:8], ip)
            return self.json_resp(writer, 200, {
                "ott": ott, "ott_ttl": OTT_TTL_S,
                "robot_uid": self.robot_uid(), "session_ttl": SESSION_TTL_S})

        if path == "/gw/api-token" and method == "POST":
            body = await self.read_json_body(reader, headers, leftover)
            client_id = str(body.get("client_id", ""))
            nonce = str(body.get("nonce", ""))
            sig_b64 = str(body.get("sig", ""))
            if not self.take_nonce(nonce, client_id, ip):   # same store and rules as /gw/session
                self._warn("api-token-nonce", ip, "api-token FAILED (nonce) ip=%s", ip)
                return self.json_resp(writer, 403, {"error": "auth_failed"})
            self.load_clients()
            client = self.clients.get(client_id)
            if client is None:
                return self.json_resp(writer, 403, {"error": "auth_failed"})
            if not self.verify_client_sig(client, API_SIGN_CONTEXT, client_id, nonce, sig_b64):
                self._warn("api-token-sig", ip, "api-token FAILED (signature) client=%s ip=%s", client_id[:8], ip)
                return self.json_resp(writer, 403, {"error": "auth_failed"})
            granted = client_perms(client)
            perms = [p for p in API_PERMS if p in granted]
            if not perms:
                self._warn("api-token-perm", ip, "api-token DENIED (no API permission) client=%s ip=%s",
                           client_id[:8], ip)
                return self.json_resp(writer, 403, {"error": "forbidden"})
            mine = [k for k, v in self.api_tokens.items() if v["client_id"] == client_id]
            while len(mine) >= API_TOKENS_PER_CLIENT:      # insertion order = oldest first
                del self.api_tokens[mine.pop(0)]
            token = secrets.token_urlsafe(32)
            ttl = self.args.api_token_ttl
            self.api_tokens[token] = {"client_id": client_id, "ip": ip, "perms": perms,
                                      "expires": now() + ttl}
            log.info("api-token OK client=%s(%s) ip=%s perms=%s", client.get("name"), client_id[:8], ip,
                     ",".join(perms))
            return self.json_resp(writer, 200, {"token": token, "ttl": ttl, "perms": perms,
                                                "robot_uid": self.robot_uid()})

        if path == "/gw/sso" and method == "GET":
            ott = (query.get("ott") or [""])[0]
            entry = self.otts.pop(ott, None)  # single use
            if entry is None or entry["expires"] <= now() or entry["ip"] != ip:
                self._warn("sso-fail", ip, "sso FAILED ip=%s", ip)
                return self.respond(writer, 403, PAGE_SSO_EXPIRED, "text/html; charset=utf-8")
            token = secrets.token_urlsafe(32)
            self.sessions[token] = {"client_id": entry["client_id"], "ip": ip,
                                    "expires": now() + SESSION_TTL_S}
            cookie = (f"{COOKIE_NAME}={token}; Path=/; Max-Age={SESSION_TTL_S}; "
                      "HttpOnly; SameSite=Strict")
            if not self.args.no_tls:
                cookie += "; Secure"
            log.info("sso OK client=%s ip=%s", entry["client_id"][:8], ip)
            return self.respond(writer, 302, b"", "text/plain",
                                extra=[f"Set-Cookie: {cookie}", "Location: /"])

        if path == "/gw/logout" and method == "GET":
            token = self.cookie_token(headers)
            if token and self.sessions.pop(token, None):
                self.sever(lambda c: c["token"] == token, "logout")
            return self.respond(writer, 302, b"", "text/plain", extra=["Location: /"])

        return self.json_resp(writer, 404 if path.startswith("/gw/") else 405, {"error": "not_found"})

    # ---------- session / splice ----------

    def cookie_token(self, headers):
        for part in headers.get("cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE_NAME:
                return v
        return None

    def session_for(self, headers, ip):
        token = self.cookie_token(headers)
        if not token:
            return None, None
        s = self.sessions.get(token)
        if s is None or s["expires"] <= now():
            self.sessions.pop(token, None)
            return None, None
        self.load_clients()
        if "ui" not in client_perms(self.clients.get(s["client_id"])):  # revoked / "ui" withdrawn
            self.sessions.pop(token, None)
            return None, None
        if s["ip"] != ip:  # cookie replayed from another host
            self._warn("cookie-ip", ip, "cookie used from wrong ip: session=%s ip=%s", s["ip"], ip)
            return None, None
        return s, token

    @staticmethod
    def origin_ok(headers):
        """WS upgrades must come from a page we served: Origin host == Host."""
        origin = headers.get("origin")
        host = headers.get("host")
        if not origin or not host:
            return False
        try:
            return urllib.parse.urlsplit(origin).netloc == host
        except ValueError:
            return False

    def sever(self, pred, reason):
        for conn in list(self.conns.values()):
            if pred(conn):
                log.info("severing conn id=%s client=%s reason=%s", conn["id"], conn["client_id"][:8], reason)
                for w in (conn["cwriter"], conn["bwriter"]):
                    try:
                        w.close()
                    except Exception:
                        pass

    async def ui_once(self, session, token, head_bytes, reader, writer, ip):
        """NIF mode static UI: one authenticated GET/HEAD per connection, no opaque HTTP tunnel.

        Any pipelined bytes are discarded. Only WebSocket upgrades retain bidirectional splicing.
        This prevents a later HTTP request from sharing the first request's authorization check.
        """
        try:
            method, target, parsed = self.parse_head(head_bytes)
            if ("host" not in parsed or "transfer-encoding" in parsed
                    or ("content-length" in parsed and parsed["content-length"] != "0")):
                raise ValueError()
        except (ApiReject, ValueError, UnicodeError):
            return self.json_resp(writer, 400, {"error": "bad_request"})
        if method not in ("GET", "HEAD"):
            return self.respond(writer, 405, b"", "text/plain", extra=["Allow: GET, HEAD"])
        try:
            breader, bwriter = await asyncio.wait_for(asyncio.open_connection(
                self.args.flask_host, self.args.flask_port), 3.0)
        except (OSError, asyncio.TimeoutError):
            return self.respond(writer, 502, PAGE_BACKEND_DOWN, "text/html; charset=utf-8")
        self.conn_seq += 1
        conn = {"id": self.conn_seq, "client_id": session["client_id"], "token": token, "ip": ip,
                "cwriter": writer, "bwriter": bwriter, "opened": now(), "last_active": now(), "nout": 0}
        self.conns[conn["id"]] = conn
        self.per_ip_splice[ip] = self.per_ip_splice.get(ip, 0) + 1
        sent_head = False
        try:
            forward = ["%s %s HTTP/1.1" % (method, target),
                       "Host: %s:%d" % (self.args.flask_host, self.args.flask_port), "Connection: close"]
            for name in ("accept", "accept-encoding", "if-none-match", "if-modified-since", "range"):
                if name in parsed:
                    forward.append(name + ": " + parsed[name])
            bwriter.write(("\r\n".join(forward) + "\r\n\r\n").encode("ascii"))
            await asyncio.wait_for(bwriter.drain(), 3.0)
            deadline = now() + 60
            bhead, first = await self.api_backend_head(breader, deadline)
            status, response, mode, length = rewrite_api_response_head(bhead)
            writer.write(response)
            sent_head = True
            if method != "HEAD":
                await self.api_stream(conn, breader, first, writer, mode, length, deadline)
        except (OSError, ValueError, asyncio.TimeoutError):
            if not sent_head:
                self.json_resp(writer, 502, {"error": "backend_unavailable"})
            else:
                writer.transport.abort()
        finally:
            self.conns.pop(conn["id"], None)
            self.per_ip_splice[ip] -= 1
            if self.per_ip_splice[ip] <= 0:
                del self.per_ip_splice[ip]
            bwriter.close()

    async def splice(self, session, token, is_ws, head_bytes, leftover, reader, writer, ip):
        host, port = ((self.args.ws_host, self.args.ws_port) if is_ws
                      else (self.args.flask_host, self.args.flask_port))
        try:
            breader, bwriter = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3.0)
        except (OSError, asyncio.TimeoutError):
            self._warn("backend-down", host, "backend %s:%s unreachable", host, port)
            if is_ws:
                return self.respond(writer, 502, b"", "text/plain")
            return self.respond(writer, 502, PAGE_BACKEND_DOWN, "text/html; charset=utf-8")

        self.conn_seq += 1
        conn = {"id": self.conn_seq, "client_id": session["client_id"], "token": token, "ip": ip,
                "cwriter": writer, "bwriter": bwriter,
                "opened": now(), "last_active": now()}
        self.conns[conn["id"]] = conn
        self.per_ip_splice[ip] = self.per_ip_splice.get(ip, 0) + 1

        bwriter.write(head_bytes + leftover)

        async def pump(src, dst):
            while True:
                data = await src.read(65536)
                if not data:
                    break
                conn["last_active"] = now()
                dst.write(data)
                await dst.drain()

        tasks = []
        try:
            await bwriter.drain()
            tasks = [asyncio.ensure_future(pump(reader, bwriter)),
                     asyncio.ensure_future(pump(breader, writer))]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            for t in tasks:
                t.cancel()
            for r in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(r, Exception) and not isinstance(r, (ConnectionError, asyncio.CancelledError, OSError)):
                    log.warning("pump error conn=%s client=%s: %r", conn["id"], conn["client_id"][:8], r)
            del self.conns[conn["id"]]
            self.per_ip_splice[ip] -= 1
            if self.per_ip_splice[ip] <= 0:
                del self.per_ip_splice[ip]
            try:
                bwriter.close()
            except Exception:
                pass
            log.info("conn id=%s closed client=%s ws=%s age=%.0fs", conn["id"], conn["client_id"][:8],
                     is_ws, now() - conn["opened"])

    # ---------- robot API: /api/<svc>/<path>, one request per connection ----------

    @staticmethod
    def is_api_request(head_bytes):
        """Routing on the raw request target after common syntax checks, ahead of the cookie
        session: everything under /api belongs to the robot API (cookies never apply there)."""
        parts = head_bytes.split(b"\r\n", 1)[0].split(b" ")
        if len(parts) < 2:
            return False
        t = parts[1]
        return t == b"/api" or t.startswith(b"/api/") or t.startswith(b"/api?")

    def api_auth(self, value, ip):
        """Bearer token -> (client_id, effective perms) or (None, None). The registration and its
        permissions are re-read on every request, so revocation and set-perms apply to the next
        request; a token never gains permissions beyond those it was issued with."""
        scheme, _, token = (value or "").partition(" ")
        if scheme.lower() != "bearer" or not _API_TOKEN_RE.match(token):
            return None, None
        entry = self.api_tokens.get(token)
        if entry is None:
            return None, None
        if entry["expires"] <= now():
            self.api_tokens.pop(token, None)
            return None, None
        if entry["ip"] != ip:   # bearer replayed from another host
            self._warn("api-token-ip", ip, "api token used from wrong ip: token=%s ip=%s", entry["ip"], ip)
            return None, None
        self.load_clients()
        client = self.clients.get(entry["client_id"])
        if client is None:      # revoked
            self.api_tokens.pop(token, None)
            return None, None
        return entry["client_id"], set(entry["perms"]) & client_perms(client)

    def api_reply(self, writer, status, error, extra=()):
        self.respond(writer, status, json.dumps({"error": error}), extra=extra)

    async def api_reject(self, writer, reader, leftover, headers, length, status, error,
                         extra=(), drain=API_DRAIN_DEFAULT):
        """Error reply to a well-framed request, then discard (bounded in bytes and time) what the
        client still sends of its announced body, so it reads the status rather than a reset."""
        self.api_reply(writer, status, error, extra)
        await self.flush_close(writer)
        if "expect" in headers:     # client waits for 100-continue: no body follows
            return
        await self.api_discard(reader, min(length or 0, drain) - len(leftover))

    @staticmethod
    async def api_discard(reader, pending):
        """Read and drop up to `pending` bytes, for at most API_DRAIN_TIMEOUT_S."""
        deadline = now() + API_DRAIN_TIMEOUT_S
        while pending > 0:
            remain = deadline - now()
            if remain <= 0:
                return
            try:
                chunk = await asyncio.wait_for(reader.read(min(API_IO_CHUNK, pending)), remain)
            except (asyncio.TimeoutError, OSError):
                return
            if not chunk:
                return
            pending -= len(chunk)

    async def api_spool_failed(self, conn, err, svc, writer, reader, pending):
        """507 (disk full) / 500 for a body the gateway could not store; the backend was not
        contacted. Up to `pending` bytes the client still sends are discarded (bounded) so it reads
        the status rather than a reset."""
        status, error = err.reply()
        conn["status"], conn["complete"] = status, True
        self._warn("api-spool", svc, "api %s request body not stored in %s: %s", svc, self.data_dir, err)
        self.api_reply(writer, status, error)
        await self.flush_close(writer)
        await self.api_discard(reader, pending)

    async def handle_api(self, head_bytes, leftover, reader, writer, ip):
        t0 = now()
        try:
            method, svc, path, query, headers, length = parse_api_head(head_bytes)
        except ApiReject as e:  # framing unknown or ambiguous: reply and close, never read a body
            self._warn("api-bad", ip, "api request rejected ip=%s: %d %s", ip, e.status, e.error)
            return self.api_reply(writer, e.status, e.error)
        if "origin" in headers:     # browsers never belong here (CSRF, DNS rebinding)
            self._warn("api-origin", ip, "api request with Origin rejected ip=%s", ip)
            return await self.api_reject(writer, reader, leftover, headers, length, 403, "forbidden")
        try:
            client_id, perms = await self.authorize_api(headers.get("authorization"), ip)
        except AuthUnavailable as exc:
            return await self.api_reject(writer, reader, leftover, headers, length, 503, exc.error,
                                         extra=["Retry-After: %d" % exc.retry_after])
        if client_id is None:
            self._warn("api-unauth", ip, "api unauthenticated request ip=%s %s %s %s",
                       ip, method, svc, path[:80])
            return await self.api_reject(writer, reader, leftover, headers, length, 401, "unauthorized",
                                         extra=["WWW-Authenticate: Bearer"])
        # authenticated API work has its own caps (unauthenticated sockets stay bounded by the
        # pre-TLS live caps and can never use up the slots of paired clients)
        if self.api_live >= API_CONN_CAP or self.api_per_ip.get(ip, 0) >= PER_IP_API_CAP:
            self._warn("api-cap", ip, "api connection cap reached ip=%s live=%d per_ip=%d",
                       ip, self.api_live, self.api_per_ip.get(ip, 0))
            return await self.api_reject(writer, reader, leftover, headers, length, 503, "busy",
                                         extra=["Retry-After: 1"])
        self.api_live += 1
        self.api_per_ip[ip] = self.api_per_ip.get(ip, 0) + 1
        try:
            await self.api_request(method, svc, path, query, headers, length, client_id, perms,
                                   leftover, reader, writer, ip, t0)
        finally:
            self.api_live -= 1
            self.api_per_ip[ip] -= 1
            if self.api_per_ip[ip] <= 0:
                del self.api_per_ip[ip]

    async def api_request(self, method, svc, path, query, headers, length, client_id, perms,
                          leftover, reader, writer, ip, t0):
        self.conn_seq += 1
        conn = {"id": self.conn_seq, "client_id": client_id, "cwriter": writer, "bwriter": None,
                "status": None, "nin": 0, "nout": 0, "complete": False, "severed": None}
        if self.auth_mode == "nif-device-v1":
            conn["nif_token"] = headers.get("authorization", "").partition(" ")[2]
            conn["ip"] = ip
        self.api_conns[conn["id"]] = conn
        try:
            route = self.api_routes.get((svc, method, path))
            if route is None:
                conn["status"], conn["complete"] = 404, True
                return await self.api_reject(writer, reader, leftover, headers, length, 404, "not_found")
            perm, cap, timeout = route
            conn["required_perm"] = perm
            if perm not in perms:
                conn["status"], conn["complete"] = 403, True
                return await self.api_reject(writer, reader, leftover, headers, length, 403, "forbidden")
            if (length or 0) > cap:
                conn["status"], conn["complete"] = 413, True
                return await self.api_reject(writer, reader, leftover, headers, length, 413,
                                             "payload_too_large", drain=cap)
            expect = headers.get("expect")
            if expect is not None and expect.lower() != "100-continue":
                conn["status"], conn["complete"] = 417, True
                return self.api_reply(writer, 417, "expectation_failed")
            sem = self.api_sems[svc]
            if sem.locked():        # never queue behind a slow backend: the caller retries
                conn["status"], conn["complete"] = 503, True
                self._warn("api-busy", svc, "api %s busy (%d in flight) client=%s ip=%s",
                           svc, API_CONCURRENCY[svc], client_id[:8], ip)
                return await self.api_reject(writer, reader, leftover, headers, length, 503, "busy",
                                             extra=["Retry-After: 1"])
            await sem.acquire()     # BEFORE the body is read: slots bound buffered and spooled bodies too
            body = None
            try:
                try:    # spool + free-space check before 100 Continue: a full disk is answered first
                    body = ApiBody(length or 0, self.data_dir)
                except ApiSpoolError as e:
                    return await self.api_spool_failed(conn, e, svc, writer, reader, 0 if expect is not None
                                                       else (length or 0) - len(leftover))
                if expect is not None and length and len(leftover) < length:
                    writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                try:
                    await self.api_read_body(reader, leftover, body)
                except asyncio.TimeoutError:
                    conn["status"], conn["complete"] = 408, True
                    return self.api_reply(writer, 408, "body_timeout")
                except ApiSpoolError as e:
                    body.close()    # give the space back before discarding the rest of the upload
                    return await self.api_spool_failed(conn, e, svc, writer, reader, length - body.size)
                conn["nin"] = body.size
                await self.api_forward(conn, svc, method, path, query, headers, body, timeout, writer)
            finally:
                if body is not None:    # every path: success, 4xx/5xx, client abort, timeouts, backend errors
                    body.close()
                sem.release()
        finally:
            self.api_conns.pop(conn["id"], None)
            self.api_audit(conn, ip, method, svc, path, t0)

    @staticmethod
    async def api_read_body(reader, leftover, body):
        """Exactly body.length bytes into `body` (ApiBody) within api_body_time(). TimeoutError when
        that deadline passes or nothing arrives for API_BODY_IDLE_TIMEOUT_S, ConnectionError when the
        client closes first, ApiSpoolError when the body cannot be stored. Bytes past the announced
        length (pipelined or smuggled data) are never interpreted or forwarded."""
        length = body.length
        first = leftover[:length]
        if first:
            body.append(first)
        deadline = now() + api_body_time(length)
        while body.size < length:
            remain = deadline - now()
            if remain <= 0:
                raise asyncio.TimeoutError()
            chunk = await asyncio.wait_for(reader.read(min(API_IO_CHUNK, length - body.size)),
                                           min(remain, API_BODY_IDLE_TIMEOUT_S))
            if not chunk:
                raise ConnectionError("client closed before the body was complete")
            body.append(chunk)
        body.finish()

    async def api_forward(self, conn, svc, method, path, query, headers, body, timeout, writer):
        """One loopback connection per request, opened only once the whole body is stored: freshly
        serialized head + the body from memory or the spool in <= 64 KiB pieces with drain(), all
        under the route deadline, so the backend sees exactly one complete request or none. A
        request the gateway cannot finish sending (deadline, spool read error, backend gone, revoked
        client, gateway process killed) is reset, not half-closed: SO_LINGER 0 stays on until every
        byte is in the kernel. A spool is released as soon as its last piece is read, the body in
        memory once it is sent. The response head is rewritten (rewrite_api_response_head) and the
        body streamed under the route deadline."""
        if self.auth_mode == "nif-device-v1":
            # A slow upload must not carry an old authorization into a later backend mutation.
            granted = await self.nif_auth("validate", token=conn["nif_token"], purpose="api", peer_ip=conn["ip"])
            route_perm = self.api_routes[(svc, method, path)][0]
            if not granted["ok"] or route_perm not in granted.get("perms", []):
                conn["status"], conn["complete"] = 401, True
                return self.api_reply(writer, 401, "unauthorized")
        port = self.api_ports[svc]
        deadline = now() + timeout
        try:
            breader, bwriter = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port),
                                                      min(API_BACKEND_CONNECT_TIMEOUT_S, timeout))
        except (OSError, asyncio.TimeoutError):
            self._warn("api-backend-down", svc, "api backend %s (127.0.0.1:%d) unreachable", svc, port)
            conn["status"], conn["complete"] = 502, True
            return self.api_reply(writer, 502, "backend_unavailable")
        conn["bwriter"] = bwriter
        _set_linger0(bwriter.transport, True)   # from the first byte on: a dying gateway resets it too
        sent = False    # the whole request is in the kernel: a graceful close still delivers it
        try:
            if conn["severed"]:     # revoked meanwhile, client already cut off: the finally resets this unused
                return
            lines = ["%s %s HTTP/1.1" % (method, path + ("?" + query if query else "")),
                     "Host: 127.0.0.1:%d" % port, "Connection: close"]
            if self.auth_mode == "nif-device-v1":
                lines.append("Authorization: Bearer " + conn["nif_token"])
            for name, canonical in API_FORWARD_HEADERS:
                if name in headers:
                    lines.append("%s: %s" % (canonical, headers[name]))
            if method != "GET":
                lines.append("Content-Length: %d" % body.size)
            try:
                bwriter.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
                for piece in body.chunks(release=True):     # nothing is ever resent from the spool
                    bwriter.write(piece)
                    await asyncio.wait_for(bwriter.drain(), max(0.001, deadline - now()))
                # drain() returns at the low-water mark; with limits 0 only once no byte is left in user space
                bwriter.transport.set_write_buffer_limits(0)
                await asyncio.wait_for(bwriter.drain(), max(0.001, deadline - now()))
                sent = True
                _set_linger0(bwriter.transport, False)  # all in the kernel: even a killed gateway delivers it
                body.close()    # a body kept in memory: freed while the backend works
                bhead, first = await self.api_backend_head(breader, deadline)
                status, head, mode, blen = rewrite_api_response_head(bhead)
            except asyncio.TimeoutError:    # (an OSError on 3.11+: must come first)
                self._warn("api-backend-timeout", svc, "api backend %s timed out after %ss: %s %s",
                           svc, timeout, method, path)
                conn["status"], conn["complete"] = 504, True
                return self.api_reply(writer, 504, "backend_timeout")
            except ApiSpoolError as e:      # stored body unreadable: the backend got a partial request
                self._warn("api-spool", svc, "api %s request body unreadable from the spool: %s", svc, e)
                status, error = e.reply()
                conn["status"], conn["complete"] = status, True
                return self.api_reply(writer, status, error)
            except (ValueError, OSError) as e:
                if conn["severed"]:     # the janitor reset both connections: no backend failure, nobody to answer
                    return
                self._warn("api-backend-bad", svc, "api backend %s failed %s %s: %s", svc, method, path, e)
                conn["status"], conn["complete"] = 502, True
                return self.api_reply(writer, 502, "bad_backend_response")
            conn["status"] = status
            writer.write(head)
            if mode == "length":    # large downloads get a >= 32 KiB/s allowance (sizes are the backend's)
                deadline = max(deadline, now() + blen / API_BODY_MIN_RATE)
            await self.api_stream(conn, breader, first, writer, mode, blen, deadline)
            conn["complete"] = True
        finally:
            conn["bwriter"] = None
            try:
                if sent:
                    bwriter.close()
                else:   # cut off mid-request: RST, so the backend cannot take a short body for complete
                    _reset_transport(bwriter.transport)
            except Exception:
                pass

    @staticmethod
    async def api_backend_head(breader, deadline):
        buf = b""
        while b"\r\n\r\n" not in buf:
            if len(buf) > API_BACKEND_HEAD_MAX:
                raise ValueError("backend response head too large")
            remain = deadline - now()
            if remain <= 0:
                raise asyncio.TimeoutError()
            chunk = await asyncio.wait_for(breader.read(65536), remain)
            if not chunk:
                raise ValueError("backend closed before the response head")
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        if len(head) > API_BACKEND_HEAD_MAX:
            raise ValueError("backend response head too large")
        return head, rest

    @staticmethod
    async def api_stream(conn, breader, data, writer, mode, length, deadline):
        """Response body: exactly Content-Length bytes, or everything up to the backend's EOF
        (chunked passthrough / close-delimited). A truncated body raises, and the caller aborts
        the client connection (RST) so a close-delimited body is never mistaken for complete."""
        if mode == "none":
            return
        if mode == "length":
            data = data[:length]
        while True:
            if data:
                writer.write(data)
                conn["nout"] += len(data)
                await asyncio.wait_for(writer.drain(), max(0.001, deadline - now()))
            if mode == "length" and conn["nout"] >= length:
                return
            remain = deadline - now()
            if remain <= 0:
                raise asyncio.TimeoutError()
            want = min(65536, length - conn["nout"]) if mode == "length" else 65536
            data = await asyncio.wait_for(breader.read(want), remain)
            if not data:
                if mode == "length":
                    raise ConnectionError("backend closed before Content-Length bytes")
                return

    def api_audit(self, conn, ip, method, svc, path, t0):
        """Every non-GET is one INFO audit line. GETs (status polling) are aggregated per
        (client, ip, path, status) and flushed by the janitor every --api-log-period seconds."""
        cid = conn["client_id"]
        name = str((self.clients.get(cid) or {}).get("name", "?"))
        status = conn["status"]
        if conn["severed"]:     # at any stage: a relayed response cut off by it can still look complete
            status = "severed (%s)" % conn["severed"]
        elif not conn["complete"]:
            status = "aborted" if status is None else "%s truncated" % status
        if method == "GET":
            key = (name, cid[:8], ip, svc, path[:80], str(status))
            if key not in self.api_get_stats and len(self.api_get_stats) >= API_GET_STATS_CAP:
                self.api_flush_get_stats()
            self.api_get_stats[key] = self.api_get_stats.get(key, 0) + 1
            return
        log.info("api client=%s(%s) ip=%s %s %s %s -> %s req=%dB resp=%dB %.0fms", name, cid[:8], ip,
                 method, svc, path[:80], status, conn["nin"], conn["nout"], (now() - t0) * 1000)

    def api_flush_get_stats(self):
        stats, self.api_get_stats = self.api_get_stats, {}
        period, self.api_get_since = now() - self.api_get_since, now()
        for (name, id8, ip, svc, path, status), n in stats.items():
            log.info("api GET x%d in %.0fs client=%s(%s) ip=%s %s %s -> %s",
                     n, period, name, id8, ip, svc, path, status)

    # ---------- per-connection entry ----------

    async def accept_loop(self, lsock):
        loop = asyncio.get_event_loop()
        while True:
            try:
                sock, addr = await loop.sock_accept(lsock)
                accepted_at = now()
            except OSError as e:   # EMFILE/ENFILE etc.: back off instead of spinning
                self._warn("accept", "-", "accept failed: %s", e)
                await asyncio.sleep(0.5)
                continue
            ip = _norm_ip(addr[0] if addr else "?")
            # caps are enforced BEFORE the TLS handshake so unauthenticated sockets can't exhaust fds/CPU
            if self.live_total >= LIVE_CONN_CAP or self.per_ip.get(ip, 0) >= PER_IP_LIVE_CAP:
                self._warn("conn-cap", ip, "connection cap reached ip=%s live=%d per_ip=%d",
                           ip, self.live_total, self.per_ip.get(ip, 0))
                _abort_socket(sock)
                continue
            sock.setblocking(False)
            self.live_total += 1
            self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
            # The five-second TLS allowance starts at accept, before task/slot wait.
            accepted = {"started": False}
            task = self._spawn(self.handle_socket(sock, ip, accepted_at + TLS_HANDSHAKE_TIMEOUT_S, accepted))
            def before_start_done(_task, accepted=accepted, sock=sock, ip=ip):
                # A coroutine cancelled before its first instruction cannot run finally.
                if not accepted["started"]:
                    accepted["started"] = True
                    _abort_socket(sock)
                    self.release_live_socket(ip)
            task.add_done_callback(before_start_done)

    def release_live_socket(self, ip):
        self.live_total -= 1
        self.per_ip[ip] -= 1
        if self.per_ip[ip] <= 0:
            del self.per_ip[ip]

    async def handle_socket(self, sock, ip, tls_deadline=None, accepted=None):
        if accepted is not None:
            accepted["started"] = True
        loop = asyncio.get_event_loop()
        writer = None
        owner, attachment, tls = None, None, None
        path = "-"
        try:
            tls_deadline = tls_deadline if tls_deadline is not None else now() + TLS_HANDSHAKE_TIMEOUT_S
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)

            async def before_deadline(awaitable):
                remaining = tls_deadline - now()
                if remaining <= 0:
                    # Close an unstarted coroutine without producing a warning.
                    if hasattr(awaitable, "close"):
                        awaitable.close()
                    raise asyncio.TimeoutError()
                return await asyncio.wait_for(awaitable, remaining)

            slot = False
            try:
                if self.ssl_ctx is not None:
                    await before_deadline(self.tls_sem.acquire())
                    slot = True
                if now() >= tls_deadline:
                    raise asyncio.TimeoutError()
                # No TLS object is allocated while a connection is queued for a slot.
                application = protocol
                kw = {}
                if self.ssl_ctx is not None and self.openssl_enabled:
                    tls = OpenSSLBIOTransport(self.ssl_ctx, protocol, loop)
                    application = tls
                elif self.ssl_ctx is not None:
                    kw["ssl"] = self.ssl_ctx
                    if sys.version_info >= (3, 7):
                        kw["ssl_handshake_timeout"] = max(0.001, tls_deadline - now())
                owner = AcceptedSocketProtocol(application)
                attachment = asyncio.ensure_future(loop.connect_accepted_socket(lambda: owner, sock, **kw))
                attachment.add_done_callback(owner.attachment_done)
                # Shield separates the deadline from a late attachment callback.
                # On timeout the ownership guard aborts both current and later transports.
                transport, _ = await before_deadline(asyncio.shield(attachment))
                sock = None  # the transport owns it now
                if tls is not None:
                    transport = await before_deadline(tls.ready)
            except BaseException:
                if tls is not None:
                    tls.abort()
                if owner is not None:
                    owner.abort()
                if attachment is not None:
                    attachment.cancel()
                raise
            finally:
                if slot:
                    self.tls_sem.release()
            writer = asyncio.StreamWriter(transport, protocol, reader, loop)
            sock = None  # owned by the transport now

            head_bytes, leftover = await self.read_head(reader)
            method, target, headers = self.parse_head(head_bytes)
            if self.is_api_request(head_bytes):     # before any cookie/session logic
                path = "/api"
                await self.handle_api(head_bytes, leftover, reader, writer, ip)
                await self.flush_close(writer)
                return
            split = urllib.parse.urlsplit(target)
            path = split.path
            query = urllib.parse.parse_qs(split.query)

            if path == "/gw/enroll/start":
                await self.handle_enrollment(head_bytes, leftover, reader, writer, ip)
                await self.flush_close(writer)
                return

            if path == "/gw" or path.startswith("/gw/"):
                try:
                    await self.handle_gw(method, path, query, headers, reader, writer, ip, leftover)
                except ValueError:
                    self.json_resp(writer, 400, {"error": "bad_request"})
                await self.flush_close(writer)
                return

            session, token = await self.authorize_ui(headers, ip)
            is_ws = "websocket" in headers.get("upgrade", "").lower()

            if session is None:
                self._warn("unauth", ip, "unauthenticated request ip=%s path=%s ws=%s", ip, path, is_ws)
                if is_ws:
                    self.respond(writer, 401, b"", "text/plain")
                else:
                    self.respond(writer, 401, PAGE_DENIED, "text/html; charset=utf-8")
                await self.flush_close(writer)
                return

            if is_ws and not self.origin_ok(headers):
                self._warn("ws-origin", ip, "ws origin rejected ip=%s origin=%r", ip, headers.get("origin"))
                self.respond(writer, 403, b"", "text/plain")
                await self.flush_close(writer)
                return

            if len(self.conns) >= SPLICE_CAP or self.per_ip_splice.get(ip, 0) >= PER_IP_SPLICE_CAP:
                self._warn("splice-cap", ip, "splice cap reached ip=%s spliced=%d per_ip=%d",
                           ip, len(self.conns), self.per_ip_splice.get(ip, 0))
                self.respond(writer, 503, b"", "text/plain", extra=["Retry-After: 1"])
                await self.flush_close(writer)
                return

            if self.auth_mode == "nif-device-v1" and not is_ws:
                await self.ui_once(session, token, head_bytes, reader, writer, ip)
            else:
                await self.splice(session, token, is_ws, head_bytes, leftover, reader, writer, ip)
        except ApiReject as exc:
            if writer is not None:
                self.json_resp(writer, exc.status, {"error": exc.error})
                await self.flush_close(writer)
        except AuthUnavailable as exc:
            if writer is not None:
                self.json_resp(writer, 503, {"error": exc.error, "retry_after_seconds": exc.retry_after},
                               extra=["Retry-After: %d" % exc.retry_after])
                await self.flush_close(writer)
        except asyncio.CancelledError:
            raise   # (an Exception subclass before Python 3.8)
        except (ValueError, OSError, asyncio.TimeoutError, ssl.SSLError) as e:
            # plaintext probes, slow/oversized heads, TLS failures, resets: drop quietly (throttled log)
            self._warn("conn-drop", ip, "conn dropped ip=%s path=%s: %s", ip, path, type(e).__name__)
            if writer is not None:
                try:
                    writer.transport.abort()
                except Exception:
                    pass
        except Exception:
            log.exception("gw handler failed ip=%s path=%s", ip, path)
            if writer is not None:
                try:
                    self.json_resp(writer, 503, {"error": "internal"})
                    await self.flush_close(writer)
                except Exception:
                    pass
        finally:
            try:
                if sock is not None:        # no transport (handshake failed / timed out)
                    _abort_socket(sock)
                if writer is not None:
                    try:
                        writer.close()
                        if hasattr(writer, "wait_closed"):   # Python 3.7+
                            await asyncio.wait_for(writer.wait_closed(), TLS_CLOSE_TIMEOUT_S + 1.0)
                    except Exception:
                        pass
            finally:
                # A second cancellation during close must not bypass accounting.
                self.release_live_socket(ip)

    # ---------- janitor: expiry, revocation severance, lifetimes ----------

    async def nif_janitor(self):
        """One batch snapshot; a missing authority severs live work rather than retaining access."""
        ui = list(self.conns.values())
        api = list(self.api_conns.values())
        items = [{"token": c["token"], "purpose": "ui", "peer_ip": c["ip"]} for c in ui]
        items += [{"token": c["nif_token"], "purpose": "api", "peer_ip": c["ip"]} for c in api]
        if not items:
            return
        try:
            reply = await self.nif_auth("validate_many", items=items)
            results = reply.get("results")
            if not reply["ok"] or not isinstance(results, list) or len(results) != len(items):
                raise AuthUnavailable("invalid authority batch")
        except AuthUnavailable:
            results = [None] * len(items)
        t = now()
        for c, result in zip(ui, results[:len(ui)]):
            valid = isinstance(result, dict) and result.get("ok") and "ui" in result.get("perms", [])
            s = self.sessions.get(c["token"])
            if (not valid or not s or s["expires"] <= t
                    or t - c["opened"] > CONN_HARD_LIFETIME_S
                    or t - c["last_active"] > CONN_IDLE_TIMEOUT_S):
                self.sessions.pop(c["token"], None)
                self.sever(lambda v, cid=c["id"]: v["id"] == cid, "authority_or_session")
        for c, result in zip(api, results[len(ui):]):
            valid = isinstance(result, dict) and result.get("ok")
            # Any permission shrink severs in-flight requests; the next attempt checks its route.
            if valid and c.get("required_perm"):
                valid = c["required_perm"] in result.get("perms", [])
            if valid:
                continue
            c["severed"] = "authority_or_revoked"
            try:
                if c["bwriter"] is not None:
                    _reset_transport(c["bwriter"].transport)
            except Exception:
                pass
            try:
                c["cwriter"].transport.abort()
            except Exception:
                pass

    async def janitor(self):
        while True:
            await asyncio.sleep(min(self.args.janitor_period, 1.0) if self.auth_mode == "nif-device-v1"
                                else self.args.janitor_period)
            try:
                self.purge_expired()
                if self.auth_mode == "nif-device-v1":
                    await self.nif_janitor()
                    if self.api_get_stats and now() - self.api_get_since >= self.args.api_log_period:
                        self.api_flush_get_stats()
                    continue
                self.load_clients()
                t = now()
                for conn in list(self.conns.values()):
                    s = self.sessions.get(conn["token"])
                    if conn["client_id"] not in self.clients:
                        reason = "revoked"
                    elif "ui" not in client_perms(self.clients[conn["client_id"]]):
                        reason = "perms"
                    elif s is None or s["expires"] <= t:
                        reason = "session"
                    elif t - conn["opened"] > CONN_HARD_LIFETIME_S:
                        reason = "lifetime"
                    elif t - conn["last_active"] > CONN_IDLE_TIMEOUT_S:
                        reason = "idle"
                    else:
                        continue
                    self.sever(lambda c, cid=conn["id"]: c["id"] == cid, reason)
                for token in [k for k, v in self.sessions.items()
                              if "ui" not in client_perms(self.clients.get(v["client_id"]))]:
                    del self.sessions[token]
                for token in [k for k, v in self.api_tokens.items() if v["client_id"] not in self.clients]:
                    del self.api_tokens[token]
                for c in list(self.api_conns.values()):     # in-flight API requests of revoked clients
                    if c["client_id"] not in self.clients:
                        if c["severed"] is None:
                            log.info("severing api conn id=%s client=%s reason=revoked",
                                     c["id"], c["client_id"][:8])
                            c["severed"] = "revoked"    # api_forward / api_audit: not a backend failure
                        # abort (RST), never close(): a graceful close lets asyncio drop the socket once the
                        # write buffer drains, and api_forward's next write then fails inside asyncio
                        try:
                            if c["bwriter"] is not None:
                                _reset_transport(c["bwriter"].transport)
                        except Exception:
                            pass
                        try:
                            c["cwriter"].transport.abort()
                        except Exception:
                            pass
                if self.api_get_stats and t - self.api_get_since >= self.args.api_log_period:
                    self.api_flush_get_stats()
                cutoff = now() - PAIR_WINDOW_S
                for k in [k for k, ts in self.pair_attempts.items() if not ts or ts[-1] <= cutoff]:
                    del self.pair_attempts[k]
                self.read_pairing_code()  # removes an expired code proactively
            except Exception:
                log.exception("janitor iteration failed")

    # ---------- server ----------

    def make_ssl_context(self):
        self.openssl_enabled = False
        if self.args.no_tls:
            log.warning("TLS DISABLED (--no-tls): session cookies and pairing are sniffable on the LAN")
            return None
        if not (os.path.exists(self.cert_path) and os.path.exists(self.key_path)):
            raise SystemExit(f"TLS cert/key missing ({self.cert_path}). Run deploy/install_vizanti_gateway.sh "
                             f"or generate them, or pass --no-tls explicitly.")
        if openssl_exporter_available():
            ctx = OPENSSL_SSL.Context(OPENSSL_SSL.TLS_SERVER_METHOD)
            ctx.set_min_proto_version(OPENSSL_SSL.TLS1_2_VERSION)
            ctx.set_options(OPENSSL_SSL.OP_NO_COMPRESSION | OPENSSL_SSL.OP_NO_TICKET |
                            getattr(OPENSSL_SSL, "OP_NO_RENEGOTIATION", 0))
            ctx.set_session_cache_mode(OPENSSL_SSL.SESS_CACHE_OFF)
            ctx.use_certificate_chain_file(self.cert_path)
            ctx.use_privatekey_file(self.key_path)
            ctx.check_privatekey()
            self.openssl_enabled = True
            self.cert_fingerprint = self.load_cert_fingerprint()
            return ctx
        # Preserve already enrolled devices if an upgraded installation lacks
        # the optional bootstrap dependency. Code-only enrollment stays closed.
        log.warning("pyOpenSSL exporter unavailable: code-only enrollment disabled")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if hasattr(ssl, "TLSVersion"):          # Python 3.7+
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        ctx.load_cert_chain(self.cert_path, self.key_path)
        self.cert_fingerprint = self.load_cert_fingerprint()
        return ctx

    def load_api_config(self):
        """--api-routes (if any) -> self.api_routes. A broken file is a deploy-time error: refuse
        to start rather than run with a table nobody reviewed."""
        if self.args.api_routes:
            try:
                self.api_routes = load_api_routes(self.args.api_routes)
            except (OSError, ValueError) as e:
                raise SystemExit(f"--api-routes {self.args.api_routes}: {e}")

    async def serve(self):
        self.tls_sem = asyncio.Semaphore(TLS_CONCURRENT_HANDSHAKES)
        self.api_sems = {svc: asyncio.Semaphore(API_CONCURRENCY[svc]) for svc in API_SERVICES}
        self.load_api_config()
        self.ssl_ctx = self.make_ssl_context()
        try:
            lsock = _make_listen_socket(self.args.listen_port, LISTEN_BACKLOG)
        except OSError as e:
            raise SystemExit(f"listen on :{self.args.listen_port} failed: {e} - is an older vizanti launch "
                             f"(flask on 0.0.0.0:5000) still running? check: ss -ltnp | grep :{self.args.listen_port}")
        log.info("vizanti_gateway %s listening on %s (tls=%s fp=%s ed25519=%s py=%s) -> flask %s:%s, ws %s:%s, data_dir=%s",
                 VERSION, lsock.getsockname()[:2], not self.args.no_tls, (self.cert_fingerprint or "")[:12],
                 ED25519_BACKEND, "%d.%d" % sys.version_info[:2],
                 self.args.flask_host, self.args.flask_port,
                 self.args.ws_host, self.args.ws_port, self.data_dir)
        log.info("robot api %s: /api/nif -> 127.0.0.1:%d, /api/pkg -> 127.0.0.1:%d, %d routes%s, token ttl %ss",
                 API_SIGN_CONTEXT.decode(), self.api_ports["nif"], self.api_ports["pkg"], len(self.api_routes),
                 f" (from {self.args.api_routes})" if self.args.api_routes else "", self.args.api_token_ttl)
        self._spawn(self.janitor())
        try:
            await self.accept_loop(lsock)
        finally:
            lsock.close()


PAGE_DENIED = """<!doctype html><html lang="ko"><meta charset="utf-8">
<title>RGT vizanti</title>
<body style="font-family:sans-serif;max-width:34em;margin:4em auto;color:#333">
<h2>&#x1F512; 접근 권한이 필요합니다</h2>
<p>이 화면은 등록된 <b>RGT 패키지 편집기</b>에서만 열 수 있습니다.<br>
패키지 편집기의 <b>네트워크 &gt; SLAM 에디터 열기</b> 메뉴를 사용해 주세요.</p>
<p style="color:#888;font-size:smaller">vizanti gateway</p></body></html>"""

PAGE_SSO_EXPIRED = """<!doctype html><html lang="ko"><meta charset="utf-8">
<title>RGT vizanti</title>
<body style="font-family:sans-serif;max-width:34em;margin:4em auto;color:#333">
<h2>&#x23F3; 접속 링크가 만료되었거나 유효하지 않습니다</h2>
<p>패키지 편집기의 <b>네트워크 &gt; SLAM 에디터 열기</b>를 다시 눌러 주세요.<br>
(링크는 발급 후 3분 안에, 같은 PC에서 한 번만 사용할 수 있습니다)</p>
<p style="color:#888;font-size:smaller">vizanti gateway</p></body></html>"""

PAGE_BACKEND_DOWN = """<!doctype html><html lang="ko"><meta charset="utf-8">
<title>RGT vizanti</title>
<body style="font-family:sans-serif;max-width:34em;margin:4em auto;color:#333">
<h2>&#x23F3; vizanti가 아직 기동되지 않았습니다</h2>
<p>로봇의 내비게이션 스택이 시작되면 자동으로 접속됩니다. 잠시 후 새로고침해 주세요.</p>
<p style="color:#888;font-size:smaller">vizanti gateway</p></body></html>"""


# ---------- CLI ----------

def _cli_perms(text):
    try:
        return parse_perms(text)
    except ValueError as e:
        raise SystemExit(str(e))


def cmd_newcode(gw: Gateway, perms_text):
    perms = _cli_perms(perms_text if perms_text is not None else ",".join(ALL_PERMS))
    code = secrets.token_hex(16)
    gw.write_pairing(code, perms)
    fp = gw.load_cert_fingerprint()
    token = f"{code}-{fp[:12]}" if fp else code
    print(f"pairing token: {token}")
    print(f"permissions  : {','.join(perms)}  (granted to the device that pairs with this token)")
    print(f"valid for {PAIR_CODE_TTL_S // 3600}h or until the first successful pairing; issue a new one per device")
    if not fp:
        print("WARNING: no TLS certificate in data dir - token carries no certificate fingerprint (no-tls mode)")


def _perms_label(c):
    perms = ",".join(p for p in ALL_PERMS if p in client_perms(c)) or "-"
    return perms if "perms" in c else perms + " (paired before 1.3.0: full access)"


def cmd_list(gw: Gateway):
    gw.load_clients(initial=True)
    if not gw.clients:
        print(f"no clients registered (store: {gw.clients_path})")
        return
    for cid, c in gw.clients.items():
        print(f"{cid}  name={c.get('name')}  perms={_perms_label(c)}  paired_at={time.strftime('%Y-%m-%d %H:%M', time.localtime(c.get('paired_at', 0)))}  from={c.get('paired_from')}")


def cmd_set_perms(gw: Gateway, which: str, perms_text):
    perms = _cli_perms(perms_text)
    gw.load_clients(initial=True)
    hits = [cid for cid, c in gw.clients.items() if cid == which or c.get("name") == which]
    if not hits:
        raise SystemExit(f"no client matches {which!r} (store: {gw.clients_path})")
    for cid in hits:
        gw.clients[cid]["perms"] = perms
        print(f"set {cid} ({gw.clients[cid].get('name')}) perms={','.join(perms)}")
    gw.save_clients()
    print("robot API requests use the new permissions immediately (a token never gains permissions it "
          f"was not issued with); vizanti UI sessions without 'ui' are severed within {JANITOR_PERIOD_S}s")


def cmd_revoke(gw: Gateway, which: str):
    gw.load_clients(initial=True)
    hits = [cid for cid, c in gw.clients.items() if cid == which or c.get("name") == which]
    if not hits:
        raise SystemExit(f"no client matches {which!r} (store: {gw.clients_path})")
    for cid in hits:
        name = gw.clients[cid].get("name")
        del gw.clients[cid]
        print(f"revoked {cid} ({name})")
    gw.save_clients()
    print(f"live connections of revoked clients are severed within {JANITOR_PERIOD_S}s")


def cmd_selfcheck(gw: Gateway):
    """Exit 0 only when this host can run the gateway: Ed25519 backend passes the RFC 8032
    known-answer test (good signature accepted, tampered one rejected) and TLS loads."""
    ok = True
    print(f"python      : {sys.version.split()[0]} ({sys.executable})")
    print(f"openssl     : {ssl.OPENSSL_VERSION}")
    print("tls exporter: " + ("pyOpenSSL available" if openssl_exporter_available() else
          "UNAVAILABLE (code-only enrollment disabled)"))
    good = ed25519_verify(_KAT_PUB, _KAT_SIG, b"")
    bad = ed25519_verify(_KAT_PUB, _KAT_SIG[:-1] + bytes([_KAT_SIG[-1] ^ 1]), b"")
    kat = good and not bad
    ok &= kat
    print(f"ed25519     : backend={ED25519_BACKEND}  RFC8032 known-answer={'OK' if kat else 'FAIL'}")
    print(f"data dir    : {gw.data_dir} ({'exists' if os.path.isdir(gw.data_dir) else 'absent'})")
    if os.path.exists(gw.cert_path):
        try:
            gw.make_ssl_context()
            print(f"tls         : OK  fingerprint={gw.cert_fingerprint}")
        except Exception as e:  # noqa: BLE001 - report any TLS load failure
            ok = False
            print(f"tls         : FAIL {e}")
    else:
        print("tls         : no certificate yet (the installer creates it)")
    try:
        gw.load_api_config()
        print(f"robot api   : {len(gw.api_routes)} routes{' from ' + gw.args.api_routes if gw.args.api_routes else ''}"
              f", /api/nif -> 127.0.0.1:{gw.api_ports['nif']}, /api/pkg -> 127.0.0.1:{gw.api_ports['pkg']}")
    except SystemExit as e:
        ok = False
        print(f"robot api   : FAIL {e}")
    print("RESULT      :", "OK" if ok else "FAIL")
    if not ok:
        raise SystemExit(1)


def main():
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JournalFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", nargs="?", default="serve",
                    choices=["serve", "newcode", "list-clients", "revoke", "set-perms", "selfcheck"])
    ap.add_argument("target", nargs="?", help="client id or name (for revoke, set-perms)")
    ap.add_argument("perms_list", nargs="?", metavar="perms",
                    help="set-perms: comma list of " + ",".join(ALL_PERMS))
    ap.add_argument("--perms", default=None,
                    help="newcode: permissions of the device that pairs with the new token "
                         "(comma list, default " + ",".join(ALL_PERMS) + "; RCS: read,drive)")
    ap.add_argument("--listen-port", type=int, default=int(os.environ.get("VIZANTI_GW_PORT", 5000)))
    ap.add_argument("--flask-host", default="127.0.0.1")
    ap.add_argument("--flask-port", type=int, default=5002)
    ap.add_argument("--ws-host", default="127.0.0.1")
    ap.add_argument("--ws-port", type=int, default=5001)
    ap.add_argument("--nif-port", type=int, default=API_DEFAULT_PORTS["nif"],
                    help="network-iface REST backend for /api/nif (127.0.0.1)")
    ap.add_argument("--pkg-port", type=int, default=API_DEFAULT_PORTS["pkg"],
                    help="network-iface package HTTP backend for /api/pkg (127.0.0.1)")
    ap.add_argument("--api-routes", default=None,
                    help="JSON file extending/replacing the /api route table (see load_api_routes)")
    ap.add_argument("--api-token-ttl", type=int, default=API_TOKEN_TTL_S,
                    help="legacy-mode API bearer lifetime; NIF mode uses the authority's TTL")
    ap.add_argument("--api-log-period", type=float, default=API_GET_LOG_PERIOD_S,
                    help="seconds between aggregated audit lines for API GETs")
    ap.add_argument("--data-dir", default=os.environ.get("VIZANTI_GW_DATA", "~/.rgt_data/vizanti_gateway"))
    ap.add_argument("--auth-mode", choices=("nif-device-v1", "legacy"), default="nif-device-v1",
                    help="NIF is the default single authority; legacy requires explicit opt-in")
    ap.add_argument("--nif-auth-socket", default="/run/rgt-network-iface/gateway.sock")
    ap.add_argument("--nif-auth-uid", type=int, default=os.getuid(),
                    help="expected SO_PEERCRED UID of the NIF auth service")
    ap.add_argument("--robot-uid-file", default="/rgt/robot_uid")
    ap.add_argument("--janitor-period", type=float, default=JANITOR_PERIOD_S,
                    help="seconds between expiry/revocation sweeps (= max revoke-to-severance delay)")
    ap.add_argument("--no-tls", action="store_true",
                    help="serve plain HTTP (NOT recommended - documented risk)")
    args = ap.parse_args()
    if not 1 <= args.api_token_ttl <= 86400:
        ap.error("--api-token-ttl must be 1..86400 seconds")

    gw = Gateway(args)
    if args.command == "selfcheck":
        return cmd_selfcheck(gw)
    if args.auth_mode == "nif-device-v1" and args.command != "serve":
        raise SystemExit("NIF owns device registrations. Use rgt-nif-auth; legacy clients.json is inactive.")
    if args.command != "serve":
        # the daemon runs as user rgt: a root-run CLI would resolve "~" to /root and, worse, could
        # leave root-owned files the daemon cannot read. refuse instead of silently diverging.
        print(f"data dir: {gw.data_dir}")
        if os.path.isdir(gw.data_dir) and os.stat(gw.data_dir).st_uid != os.geteuid():
            raise SystemExit(f"{gw.data_dir} is owned by uid {os.stat(gw.data_dir).st_uid}; "
                             f"run this command as that user (e.g. sudo -u rgt python3 {sys.argv[0]} ...)")
    if args.command == "newcode":
        if args.target is not None or args.perms_list is not None:   # `newcode read,drive` would grant all
            raise SystemExit("usage: newcode [--perms " + ",".join(ALL_PERMS) + "]")
        return cmd_newcode(gw, args.perms)
    if args.command == "list-clients":
        return cmd_list(gw)
    if args.command == "revoke":
        if not args.target:
            raise SystemExit("revoke requires a client id or name")
        return cmd_revoke(gw, args.target)
    if args.command == "set-perms":
        perms_text = args.perms_list if args.perms_list is not None else args.perms
        if not args.target or perms_text is None:
            raise SystemExit("usage: set-perms <client id|name> <" + ",".join(ALL_PERMS) + ">")
        return cmd_set_perms(gw, args.target, perms_text)
    try:
        _run(gw.serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
