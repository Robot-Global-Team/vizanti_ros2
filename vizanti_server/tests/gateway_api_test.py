#!/usr/bin/env python3
"""vizanti_gateway 로봇 API(/api, 프로토콜 rgt-robot-api-v1) 테스트 (로봇 불필요, pytest 불필요).

가짜 network-iface 백엔드(nif/pkg)를 별도 스레드의 이벤트 루프에서 띄우고 게이트웨이 세 개를
서브프로세스로 기동한다.
  GW1: 기본 경로표, 기본 토큰 TTL(900s)
  GW2: 같은 clients.json, 토큰 TTL 1s, --api-routes 로 /iface/recent 타임아웃 1s, 본문을 안 읽는
       백엔드 경로 /package/slowread(64MiB, 1s), 느리지만 꾸준히 읽는 경로 /package/trickle(64MiB, 60s),
       본문을 읽고 응답 없이 끊는 경로 /package/badclose 추가 (만료·504·전송 중단 시 RST, janitor 폐기
       차단과 그 기록 검증용)
  GW3: 같은 clients.json, 래퍼로 기동: RLIMIT_FSIZE 4MiB (스풀 파일이 4MiB 를 넘으면 EFBIG = 디스크
       가득 참 모사), 본문 상한 256s -> 3s, 무응답 30s -> 1s 로 모듈 상수만 축소 (마감시간·507 검증용)
  GW4: GW2 와 같은 경로표, 테스트 도중 래퍼로 기동: 백엔드 소켓 SO_SNDBUF 128KiB 고정 (큰 tcp_wmem
       에서도 신호 전에 본문 전체가 커널로 넘어가지 않게). 백엔드로 본문을 보내는 중에 SIGTERM / SIGKILL
       로 죽인다 (신호는 이 테스트가 띄운 자식 프로세스에만, Popen 핸들로 보낸다). 그래도 본문 전체가
       신호 전에 커널에 들어갔으면 (아주 큰 tcp_rmem) RST 시나리오 미도달로 SKIP 한다
가짜 백엔드는 연결마다 받은 바이트를 그대로 기록한다. 그래서 "백엔드가 정확히 1건의 정상 요청을
받았거나 아무것도 받지 않았다"를 바이트 단위로 확인할 수 있다. 게이트웨이의 메모리(VmHWM)와
스풀 fd 는 /proc/<pid> 에서 읽는다 (Linux 전용).

검증 항목: 단위(파서, 경로표 로더, 권한 해석, 본문 마감 규칙, ApiBody 메모리/스풀), 페어링 권한
(newcode --perms), 토큰 발급(서명 도메인 분리, nonce 1회용·IP·client 바인딩, 클라이언트당 4개), 권한
(ui/read/drive/package, set-perms 즉시 반영), Bearer(누락/위조/만료/다른 IP/폐기), Origin 차단, 경로
허용목록(404), 트래버설·인코딩(400), 헤더 스머글링(중복 CL, CL+TE, TE, bare CR/LF, obs-fold, 헤더 65개,
파이프라이닝), 413/503/504/502, 업로드 바이트 정확성, 64MiB 사진(스풀, 메모리 상한, 도중 종료 시 정리,
64MiB+1 -> 413), 본문 마감시간(무응답/느린 전송 -> 408), 디스크 오류·여유 공간 하한(본문 2배 + 32MiB,
507), 세마포어 누수 없음, 백엔드로 전달 중 끊김(janitor 폐기, 게이트웨이 SIGTERM/SIGKILL -> 백엔드는
RST, 잘린 본문 + FIN 없음), janitor 차단 기록(감사 severed, 백엔드 장애 경고·502 아님, 연결 중 폐기는
백엔드 미전달), 스풀 해제 시점(마지막 조각을 백엔드에 쓰기 전), chunked/EOF/CL 응답 중계, 응답 헤더
재작성, 감사 로그(토큰 미노출).

실행: python3 tests/gateway_api_test.py          # 평문(--no-tls)
      python3 tests/gateway_api_test.py --tls    # 운영 기본값(TLS)
"""

import argparse
import asyncio
import base64
import errno
import hashlib
import hmac
import importlib.util
import json
import logging
import os
import re
import select
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GW = os.path.join(HERE, "..", "scripts", "vizanti_gateway.py")
P_GW1, P_GW2, P_GW3, P_GW4, P_NIF, P_PKG = 15900, 15901, 15902, 15903, 15931, 15933
USE_TLS = "--tls" in sys.argv
_TLS_CTX = ssl.create_default_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode = ssl.CERT_NONE  # self-signed robot cert; real clients pin it instead
MIB = 1024 * 1024

# deterministic payloads shared by the fake backends and the checks
BLOB_CHUNKED = hashlib.sha256(b"chunked").digest() * (MIB // 32)          # 1 MiB
BLOB_EOF = hashlib.sha256(b"eof").digest() * (300 * 1024 // 32)           # 300 KiB
BLOB_CL = hashlib.sha256(b"cl").digest() * (3 * MIB // 32)                # 3 MiB
SLAM_PARTS = [b'{"name": "slam_vizanti_1.json", ', b'"content": "', b"x" * 5000, b'"}']
PHOTO = "/api/pkg/package/start-position/photo"
PHOTO_CAP = 64 * MIB
# GW3 (see the module docstring): file size limit and the scaled-down body timers
GW3_FSIZE, GW3_BODY_MAX_S, GW3_IDLE_S = 4 * MIB, 3.0, 1.0
GW3_WRAPPER = """
import importlib.util, resource, sys
sys.dont_write_bytecode = True
resource.setrlimit(resource.RLIMIT_FSIZE, (%d, %d))     # Python ignores SIGXFSZ: writes past it -> EFBIG
spec = importlib.util.spec_from_file_location("vizanti_gateway", sys.argv[1])
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
g.API_BODY_MAX_TIMEOUT_S, g.API_BODY_IDLE_TIMEOUT_S = %r, %r
sys.argv = sys.argv[1:]
g.main()
""" % (GW3_FSIZE, GW3_FSIZE, GW3_BODY_MAX_S, GW3_IDLE_S)
# GW4 (see the module docstring): a fixed SO_SNDBUF also turns off the kernel's send buffer autotuning,
# which grows up to tcp_wmem[2] and could take the whole 16 MiB body before the signal
GW4_SNDBUF = 128 * 1024
GW4_WRAPPER = """
import importlib.util, socket, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("vizanti_gateway", sys.argv[1])
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
real = getattr(g, "_set_linger0", None)
if real is not None:    # set on every backend connection right after it is opened
    def pinned(transport, on):
        sock = transport.get_extra_info("socket")
        if on and sock is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, %d)
        real(transport, on)
    g._set_linger0 = pinned
sys.argv = sys.argv[1:]
g.main()
""" % GW4_SNDBUF


def multipart_of_size(total):
    """A multipart/form-data PNG upload (boundary XyZ) of exactly `total` bytes. Random fill: a
    repeating pattern would hide reordered or duplicated 64 KiB pieces from the sha256 check."""
    head = (b"--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"start.png\"\r\n"
            b"Content-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n")
    tail = b"\r\n--XyZ--\r\n"
    return head + os.urandom(total - len(head) - len(tail)) + tail

passed, failed, skipped = [], [], []


def tcp_buffer_sysctls():
    """tcp_wmem / tcp_rmem of this network namespace (min default max), for SKIP lines."""
    vals = []
    for key in ("tcp_wmem", "tcp_rmem"):
        try:
            with open("/proc/sys/net/ipv4/" + key) as f:
                vals.append("%s=%s" % (key, " ".join(f.read().split())))
        except OSError:
            vals.append(key + "=?")
    return " ".join(vals)


_SECRET_RE = re.compile(r"""(['"]?(?:token|ott|nonce|sig)['"]?\s*[:=]\s*['"]?)[A-Za-z0-9_\-+/=]{16,}""")


def check(name, cond, detail=""):
    (passed if cond else failed).append(name)
    shown = _SECRET_RE.sub(r"\1<redacted>", str(detail))    # failure details never echo credentials
    print(("  PASS  " if cond else "  FAIL  ") + name + (" - %s" % (shown,) if detail != "" and not cond else ""))


# ====================================================================================
# fake network-iface backends (own thread + own loop; the test client uses blocking sockets)
# ====================================================================================

class FakeBackend(object):
    """Records every connection's received bytes verbatim, answers by path."""

    def __init__(self, name, port):
        self.name, self.port = name, port
        self.conns = []         # {"raw": bytes, "done": bool}
        self.server = None
        self.release_ev = None  # asyncio.Event, created inside the loop (3.6 binds at creation)
        self.held = 0

    async def start(self):
        self.release_ev = asyncio.Event()
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", self.port)

    async def handle(self, reader, writer):
        rec = {"raw": b"", "done": False}
        self.conns.append(rec)
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            rec["raw"] += head
            if head.startswith(b"POST /package/slowread "):
                await asyncio.sleep(2.5)    # not reading the body: GW2's 1 s route deadline hits mid-body
            m = re.search(rb"\r\ncontent-length: *([0-9]+)\r\n", head, re.I)
            n = int(m.group(1)) if m else 0
            if head.startswith(b"POST /package/trickle "):
                body = await self.trickle(reader, n, rec)
            else:
                body = await asyncio.wait_for(reader.readexactly(n), 20) if n else b""
            rec["raw"] += body
            if head.startswith(b"POST /package/badclose "):
                return      # a broken backend: takes the body, closes without a response
            method, target = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ")[:2]
            path, _, query = target.partition("?")
            ctype = re.search(rb"\r\ncontent-type: *([^\r]*)\r\n", head, re.I)
            await self.reply(method, path, query, body, ctype.group(1).decode() if ctype else "", writer)
            # anything after the one request would be smuggled data: record it until the gateway closes
            rec["raw"] += await asyncio.wait_for(reader.read(), 10)
        except Exception as e:  # noqa: BLE001 - recorded, the checks look at it
            rec["error"] = repr(e)
        finally:
            rec["done"] = True
            writer.close()

    @staticmethod
    async def trickle(reader, n, rec):
        """The body, read slowly but steadily (32 KiB per 20 ms, ~1.6 MiB/s): the gateway's write buffer
        keeps filling and draining, and a 16 MiB forward stays in progress for ~8 s (the kernel buffers
        ~3.5 MiB of it). rec["got"]: body bytes so far. A FIN before the end -> IncompleteReadError."""
        parts = []
        rec["got"] = 0
        while rec["got"] < n:
            piece = await asyncio.wait_for(reader.read(min(32768, n - rec["got"])), 20)
            if not piece:
                raise asyncio.IncompleteReadError(b"".join(parts), n)
            parts.append(piece)
            rec["got"] += len(piece)
            await asyncio.sleep(0.02)
        return b"".join(parts)

    async def reply(self, method, path, query, body, ctype, writer):
        def send(status, payload, ctype="application/json", extra=b"", framing="length"):
            head = b"HTTP/1.1 %d X\r\nContent-Type: %s\r\n" % (status, ctype.encode()) + extra
            if framing == "length":
                writer.write(head + b"Content-Length: %d\r\n\r\n" % len(payload) + payload)
            elif framing == "chunked":
                writer.write(head + b"Transfer-Encoding: chunked\r\n\r\n")
                for part in payload:
                    writer.write(b"%x\r\n" % len(part) + part + b"\r\n")
                writer.write(b"0\r\n\r\n")
                writer.write_eof()
            else:   # close-delimited
                writer.write(head + b"\r\n" + payload)
                writer.write_eof()

        if "hold=1" in query:
            self.held += 1
            await asyncio.wait_for(self.release_ev.wait(), 20)
        if method == "POST":
            return send(200, json.dumps({"svc": self.name, "path": path, "len": len(body), "ctype": ctype,
                                         "sha256": hashlib.sha256(body).hexdigest()}).encode())
        if self.name == "nif":
            if path == "/uid":
                return send(200, b"test-uid-1234", "text/plain")
            if path == "/iface/position":
                return send(200, b'{"x": 1.5, "y": -2}', extra=(
                    b"Set-Cookie: sid=abc; Path=/\r\nServer: gevent/1.0\r\n"
                    b"Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\n"
                    b"Connection: keep-alive, X-Hop\r\nKeep-Alive: timeout=5\r\nX-Hop: 1\r\n"
                    b"Cache-Control: max-age=60\r\nX-Custom: kept\r\n"))
            if path == "/iface/recent":
                await asyncio.sleep(3)      # GW2 routes this with a 1 s timeout -> 504
                return send(200, b"late")
            if path == "/iface/vizanti/slam":
                return send(200, SLAM_PARTS, framing="chunked")
            return send(200, b"{}")
        if path == "/package/download":
            return send(200, [BLOB_CHUNKED[i:i + 65536] for i in range(0, len(BLOB_CHUNKED), 65536)],
                        "application/octet-stream", framing="chunked")
        if path == "/package/manifest":
            return send(200, BLOB_EOF, "application/octet-stream", framing="eof")
        if path == "/package/raw/image":
            return send(200, BLOB_CL, "image/png")
        return send(200, json.dumps({"path": path, "query": query}).encode())


class Backends(object):
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        self.nif = FakeBackend("nif", P_NIF)
        self.pkg = FakeBackend("pkg", P_PKG)

    def _run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(5)

    def start(self):
        self._run(self.nif.start())
        self._run(self.pkg.start())

    def release(self, be):
        self.loop.call_soon_threadsafe(be.release_ev.set)

    def rearm(self, be):
        self.loop.call_soon_threadsafe(be.release_ev.clear)

    def stop(self, be):
        async def go():
            be.server.close()
            await be.server.wait_closed()
        self._run(go())

    def count(self):
        return len(self.nif.conns) + len(self.pkg.conns)

    def since_nowait(self, mark):
        return self.nif.conns[mark[0]:] + self.pkg.conns[mark[1]:]

    def since(self, mark):
        """Backend connections opened after `mark` (=(n_nif, n_pkg)), once they are finished."""
        new = self.since_nowait(mark)
        for _ in range(100):
            if all(r["done"] for r in new):
                break
            time.sleep(0.05)
        return new

    def mark(self):
        return len(self.nif.conns), len(self.pkg.conns)


def well_formed(rec):
    """(True, info) iff the connection carried exactly ONE well-formed request built by the gateway."""
    raw = rec["raw"]
    if "error" in rec:
        return False, "backend error " + rec["error"]
    if b"\r\n\r\n" not in raw:
        return False, "no complete head"
    head, rest = raw.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    m = re.match(rb"(GET|POST) (/[!-~]*) HTTP/1\.1\Z", lines[0])
    if not m:
        return False, "bad request line %r" % lines[0][:80]
    hdrs = {}
    for line in lines[1:]:
        h = re.match(rb"([A-Za-z0-9-]+): ([ -~]*)\Z", line)
        if not h or h.group(1).lower() in hdrs:
            return False, "bad/duplicate header %r" % line[:80]
        hdrs[h.group(1).lower()] = h.group(2)
    unexpected = set(hdrs) - {b"host", b"connection", b"content-length", b"content-type", b"accept"}
    if unexpected:
        return False, "unexpected headers %r" % sorted(unexpected)
    if hdrs.get(b"connection") != b"close":
        return False, "Connection is not close"
    if hdrs.get(b"host") not in (b"127.0.0.1:%d" % P_NIF, b"127.0.0.1:%d" % P_PKG):
        return False, "Host %r" % hdrs.get(b"host")
    if m.group(1) == b"POST" and b"content-length" not in hdrs:
        return False, "POST without Content-Length"
    n = int(hdrs.get(b"content-length", b"0"))
    if len(rest) != n:
        return False, "%d bytes after the head, Content-Length %d (extra/smuggled data)" % (len(rest), n)
    return True, {"method": m.group(1).decode(), "target": m.group(2).decode(), "headers": hdrs, "body": rest}


# ====================================================================================
# blocking test client
# ====================================================================================

class Resp(object):
    def __init__(self, status, headers, body, head=b"", hlist=(), note=""):
        self.status, self.headers, self.body, self.head, self.hlist, self.note = \
            status, headers, body, head, list(hlist), note

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8"))
        except ValueError:
            return {}

    def __repr__(self):
        return "<%s %s %r>" % (self.status, self.note, self.body[:80])


def connect(src="127.0.0.1", port=P_GW1, timeout=8.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.bind((src, 0))
    s.connect(("127.0.0.1", port))
    if USE_TLS:
        s = _TLS_CTX.wrap_socket(s)
    return s


def _recv(s):
    try:
        return s.recv(65536)
    except socket.timeout:
        raise
    except (ConnectionError, ssl.SSLError, OSError):
        return None     # reset by the gateway


def decode_chunked(data):
    out, i = b"", 0
    while True:
        j = data.index(b"\r\n", i)
        size = int(data[i:j].split(b";")[0], 16)
        i = j + 2
        if size == 0:
            return out
        out += data[i:i + size]
        if data[i + size:i + size + 2] != b"\r\n":
            raise ValueError("bad chunk terminator")
        i += size + 2


def read_response(s, buf=b""):
    """Exactly one response: Content-Length bytes, chunked to the last chunk, or up to EOF.
    `buf`: bytes of it already received (poll_response)."""
    try:
        while b"\r\n\r\n" not in buf:
            chunk = _recv(s)
            if not chunk:
                return Resp(None, {}, buf, note="closed/reset before head")
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status = int(lines[0].split(b" ")[1])
        hlist = []
        for line in lines[1:]:
            k, _, v = line.partition(b":")
            hlist.append((k.strip().lower().decode("latin-1"), v.strip().decode("latin-1")))
        headers = dict(hlist)
        if "content-length" in headers:
            n = int(headers["content-length"])
            while len(rest) < n:
                chunk = _recv(s)
                if not chunk:
                    return Resp(status, headers, rest, head, hlist, "truncated")
                rest += chunk
            return Resp(status, headers, rest[:n], head, hlist)
        while True:     # chunked or close-delimited: the gateway closes after one response
            chunk = _recv(s)
            if chunk is None:
                return Resp(status, headers, rest, head, hlist, "reset")
            if not chunk:
                break
            rest += chunk
        if headers.get("transfer-encoding", "").lower() == "chunked":
            return Resp(status, headers, decode_chunked(rest), head, hlist, "chunked")
        return Resp(status, headers, rest, head, hlist, "eof")
    except socket.timeout:
        return Resp(None, {}, buf, note="timeout")


def poll_response(s, timeout):
    """What arrived of a response within `timeout`: None if nothing yet, else bytes (b"" = closed).
    On TLS the raw fd also turns readable for records without application data (TLS 1.3 session
    tickets after the handshake), so readability alone does not mean the gateway has answered."""
    if not (USE_TLS and s.pending()) and not select.select([s], [], [], max(0.0, timeout))[0]:
        return None
    s.setblocking(False)
    try:
        return s.recv(65536)
    except (ssl.SSLWantReadError, BlockingIOError):     # (OSError subclasses: must come first)
        return None
    except OSError:
        return b""
    finally:
        s.settimeout(10.0)


def send_raw(data, src="127.0.0.1", port=P_GW1, timeout=8.0, close_after_send=False):
    s = connect(src, port, timeout)
    try:
        try:
            s.sendall(data)
        except (ConnectionError, ssl.SSLError, OSError):
            pass    # the gateway may answer and close before the whole request is sent
        if close_after_send:
            s.close()
            return Resp(None, {}, b"", note="closed by client")
        return read_response(s)
    finally:
        s.close()


def api_req(method, path, token=None, body=None, ctype="application/json", extra=b"",
            src="127.0.0.1", port=P_GW1, scheme=b"Bearer", timeout=8.0):
    req = b"%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n" % (method.encode(), path.encode(), port)
    if token:
        req += b"Authorization: " + scheme + b" " + token.encode() + b"\r\n"
    if body is not None:
        req += b"Content-Type: " + ctype.encode() + b"\r\nContent-Length: %d\r\n" % len(body)
    return send_raw(req + extra + b"\r\n" + (body or b""), src=src, port=port, timeout=timeout)


def gw_post(path, obj, src="127.0.0.1", port=P_GW1):
    body = json.dumps(obj).encode()
    r = send_raw(b"POST %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\n"
                 b"Content-Length: %d\r\n\r\n%s" % (path.encode(), port, len(body), body), src=src, port=port)
    return r.status, r.json()


def gw_get(path, cookie=None, src="127.0.0.1", port=P_GW1):
    req = b"GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n" % (path.encode(), port)
    if cookie:
        req += b"Cookie: " + cookie + b"\r\n"
    return send_raw(req + b"\r\n", src=src, port=port)


def body_head(path, token, length, ctype="application/octet-stream"):
    return (b"POST %s HTTP/1.1\r\nHost: r\r\nAuthorization: Bearer %s\r\nContent-Type: %s\r\n"
            b"Content-Length: %d\r\n\r\n" % (path.encode(), token.encode(), ctype.encode(), length))


def send_body(path, token, body, ctype="application/octet-stream", port=P_GW1, timeout=120.0):
    """POST a large body in 1 MiB pieces (no head+body copy), then read exactly one response."""
    s = connect(port=port, timeout=timeout)
    try:
        s.sendall(body_head(path, token, len(body), ctype))
        view = memoryview(body)
        try:
            for i in range(0, len(body), MIB):
                s.sendall(view[i:i + MIB])
        except (ConnectionError, ssl.SSLError, OSError):
            pass    # the gateway may answer (507) and stop reading before the whole body is sent
        return read_response(s)
    finally:
        s.close()


def wait_until(fn, timeout=5.0):
    end = time.time() + timeout
    while True:
        if fn():
            return True
        if time.time() > end:
            return False
        time.sleep(0.02)


def proc_status(pid, key):
    """VmRSS / VmHWM of a process in bytes (None when unreadable)."""
    try:
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith(key + ":"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    return None


def reset_hwm(pid):
    """VmHWM := current RSS (clear_refs 5, Linux >= 4.0), so the next VmHWM is this window's peak."""
    try:
        with open("/proc/%d/clear_refs" % pid, "w") as f:
            f.write("5")
        return True
    except OSError:
        return False


def spool_fds(pid):
    """Open fds of a gateway that point into the data dir: the spool ('<dir>/#<ino> (deleted)' with
    O_TMPFILE, '<dir>/tmpXXXX (deleted)' after mkstemp + unlink). Nothing else stays open there."""
    base = os.path.realpath(DATA) + "/"
    n = 0
    try:
        names = os.listdir("/proc/%d/fd" % pid)
    except OSError:
        return -1
    for name in names:
        try:
            if os.readlink("/proc/%d/fd/%s" % (pid, name)).startswith(base):
                n += 1
        except OSError:
            pass    # closed meanwhile
    return n


class ProcWatch(threading.Thread):
    """Samples a gateway while a transfer runs: peak VmRSS and the most spool fds open at once."""

    def __init__(self, pid):
        threading.Thread.__init__(self)
        self.daemon = True
        self.pid, self.max_rss, self.max_spool = pid, 0, 0
        self._stop_ev = threading.Event()

    def run(self):
        while not self._stop_ev.is_set():
            self.max_rss = max(self.max_rss, proc_status(self.pid, "VmRSS") or 0)
            self.max_spool = max(self.max_spool, spool_fds(self.pid))
            time.sleep(0.005)

    def stop(self):
        self._stop_ev.set()
        self.join(5)


class FakeWriter(object):
    """StreamWriter (and transport) stand-in for in-process api_request tests: records the reply."""

    def __init__(self):
        self.data = b""
        self.transport = self

    def write(self, data):
        self.data += data

    async def drain(self):
        pass

    def close(self):
        pass

    def abort(self):
        pass

    def get_extra_info(self, name, default=None):
        return default


# ====================================================================================
# pairing / signing (same protocol as the editor / RCS clients)
# ====================================================================================

class _SigningKey(object):
    """Ed25519 signing for the TEST CLIENT only: python3-cryptography, else PyNaCl."""
    def __init__(self):
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            self._k = Ed25519PrivateKey.generate()
            self.pub = self._k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.sign = self._k.sign
        except ImportError:
            from nacl.signing import SigningKey
            self._k = SigningKey.generate()
            self.pub = bytes(self._k.verify_key)
            self.sign = lambda m: self._k.sign(m).signature


class Client(object):
    def __init__(self, name, cid, priv, perms):
        self.name, self.cid, self.priv, self.perms = name, cid, priv, perms


UI_CTX, API_CTX = b"vizanti-gw-v2", b"rgt-robot-api-v1"
DATA = tempfile.mkdtemp(prefix="vgw_api_")
UID_FILE = os.path.join(DATA, "robot_uid")
ROUTES_FILE = os.path.join(DATA, "routes_gw2.json")
ISSUED = []     # every token handed out: none may ever appear in the gateway log


def gw_cli(*args):
    return subprocess.run([sys.executable, GW] + list(args) + ["--data-dir", DATA],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)


def robot_fp():
    if not USE_TLS:
        return ""
    with open(os.path.join(DATA, "tls_cert.pem")) as f:
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).hexdigest()


def pair_body(code, name, pub_b64, fp):
    msg = b"vizanti-gw-pair-v1|" + fp.encode() + b"|" + pub_b64.encode() + b"|" + name.encode()
    return {"client_name": name, "pubkey": pub_b64, "proof": hmac.new(code.encode(), msg, hashlib.sha256).hexdigest()}


def read_code():
    with open(os.path.join(DATA, "pairing_code")) as f:
        return f.read().strip()


def pair(name, perms, src):
    r = gw_cli("newcode", *(["--perms", perms] if perms else []))
    assert r.returncode == 0, r.stderr
    priv = _SigningKey()
    pub_b64 = base64.b64encode(priv.pub).decode()
    st, j = gw_post("/gw/pair", pair_body(read_code(), name, pub_b64, robot_fp()), src=src)
    assert st == 200, (st, j)
    return Client(name, j["client_id"], priv, j.get("perms"))


def signed(cl, ctx, fp, nonce):
    return base64.b64encode(cl.priv.sign(ctx + b"|" + fp.encode() + b"|" + cl.cid.encode() + b"|"
                                         + nonce.encode())).decode()


def challenge(cl, src="127.0.0.1", port=P_GW1):
    _, j = gw_post("/gw/challenge", {"client_id": cl.cid}, src=src, port=port)
    return j.get("nonce", ""), j.get("cert_fingerprint") or ""


def api_token(cl, src="127.0.0.1", port=P_GW1, ctx=API_CTX, endpoint="/gw/api-token"):
    nonce, fp = challenge(cl, src, port)
    st, j = gw_post(endpoint, {"client_id": cl.cid, "nonce": nonce, "sig": signed(cl, ctx, fp, nonce)},
                    src=src, port=port)
    if j.get("token"):
        ISSUED.append(j["token"])
    return st, j


def token_of(cl, **kw):
    st, j = api_token(cl, **kw)
    assert st == 200, (cl.name, st, j)
    return j["token"]


def ui_cookie(cl, src="127.0.0.1"):
    st, j = api_token(cl, src=src, ctx=UI_CTX, endpoint="/gw/session")
    assert st == 200, (st, j)
    r = gw_get("/gw/sso?ott=" + j["ott"], src=src)
    sc = r.headers.get("set-cookie", "")
    return sc.split(";")[0].encode()


def wait_up(port, proc):
    for _ in range(100):
        time.sleep(0.1)
        try:
            if gw_get("/gw/info", port=port).status == 200:
                return
        except OSError:
            pass
        if proc.poll() is not None:
            raise SystemExit("gateway died on startup:\n" + proc.stdout.read())
    raise SystemExit("gateway did not come up")


# ====================================================================================
# in-process unit tests (module imported from the script path)
# ====================================================================================

def unit_tests():
    print("[0] 단위: 파서 / 경로표 로더 / 권한 해석")
    spec = importlib.util.spec_from_file_location("vizanti_gateway_ut", GW)
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)

    check("기본 경로표: 21개, /iface/custom·Swagger 없음",
          len(g.API_ROUTES) == 21 and not any(p in ("/iface/custom", "/", "/swagger.json")
                                              for (_s, _m, p) in g.API_ROUTES), len(g.API_ROUTES))
    check("기본 토큰 TTL 900s, 클라이언트당 4개", g.API_TOKEN_TTL_S == 900 and g.API_TOKENS_PER_CLIENT == 4)
    ok = g.parse_api_head(b"POST /api/pkg/package/upload?x=1 HTTP/1.1\r\nHost: r\r\nContent-Length: 5\r\n\r\n")
    check("parse_api_head 정상 요청", ok[:4] == ("POST", "pkg", "/package/upload", "x=1") and ok[5] == 5, ok)

    def rejects(head, status):
        try:
            g.parse_api_head(head)
            return False
        except g.ApiReject as e:
            return e.status == status
    check("parse_api_head: GET 에 Host 누락 -> 400", rejects(b"GET /api/nif/uid HTTP/1.1\r\n\r\n", 400))
    check("parse_api_head: 경로의 %2e -> 400", rejects(b"GET /api/nif/%2e%2e/x HTTP/1.1\r\nHost: r\r\n\r\n", 400))
    check("parse_api_head: 끝 세그먼트 '..' -> 400", rejects(b"GET /api/nif/iface/custom/.. HTTP/1.1\r\nHost: r\r\n\r\n", 400))
    check("is_api_request: /api, /api/.., /api? 만 API",
          g.Gateway.is_api_request(b"GET /api/nif/uid HTTP/1.1\r\n\r\n")
          and g.Gateway.is_api_request(b"GET /api HTTP/1.1\r\n\r\n")
          and g.Gateway.is_api_request(b"GET /api?x HTTP/1.1\r\n\r\n")
          and not g.Gateway.is_api_request(b"GET /apix HTTP/1.1\r\n\r\n")
          and not g.Gateway.is_api_request(b"GET / HTTP/1.1\r\n\r\n"))

    check("client_perms: perms 키 없는 기존 등록 -> 4개 전부", g.client_perms({"name": "x"}) == set(g.ALL_PERMS))
    check("client_perms: 형식 오류(문자열) -> 권한 없음 (fail-closed)", g.client_perms({"perms": "read"}) == set())
    check("client_perms: 알 수 없는 권한은 무시", g.client_perms({"perms": ["read", "root"]}) == {"read"})
    check("parse_perms: 정규화(순서/공백)", g.parse_perms(" drive ,read") == ["read", "drive"])
    for bad in ("", "admin", "read,,x"):
        try:
            g.parse_perms(bad)
            check("parse_perms 거부 %r" % bad, False)
        except ValueError:
            check("parse_perms 거부 %r" % bad, True)

    def load(obj):
        path = os.path.join(DATA, "ut_routes.json")
        with open(path, "w") as f:
            json.dump(obj, f)
        return g.load_api_routes(path)
    t = load({"routes": [{"svc": "nif", "method": "GET", "path": "/iface/extra", "perm": "read",
                          "max_body": 0, "timeout": 5}]})
    check("--api-routes 확장: 기본 21 + 1", len(t) == 22 and t[("nif", "GET", "/iface/extra")] == ("read", 0, 5))
    t = load({"replace": True, "routes": [{"svc": "pkg", "method": "POST", "path": "/a/b", "perm": "package",
                                            "max_body": 10, "timeout": 1}]})
    check("--api-routes replace: 파일이 전체 경로표", list(t) == [("pkg", "POST", "/a/b")])
    bads = [{"svc": "nif", "method": "GET", "path": "/x", "perm": "ui"},
            {"svc": "nif", "method": "GET", "path": "/x", "perm": "read", "max_body": 1},
            {"svc": "nif", "method": "PUT", "path": "/x", "perm": "read"},
            {"svc": "zzz", "method": "GET", "path": "/x", "perm": "read"},
            {"svc": "nif", "method": "GET", "path": "/a/../b", "perm": "read"},
            {"svc": "nif", "method": "GET", "path": "/a//b", "perm": "read"},
            {"svc": "nif", "method": "GET", "path": "/a%2fb", "perm": "read"},
            {"svc": "nif", "method": "POST", "path": "/x", "perm": "drive", "max_body": True},
            {"svc": "nif", "method": "GET", "path": "/x", "perm": "read", "timeout": 0}]
    rejected = 0
    for b in bads:
        try:
            load({"routes": [b]})
        except ValueError:
            rejected += 1
    check("--api-routes 잘못된 항목 9종 모두 거부", rejected == len(bads), rejected)

    def resp_rejects(head):
        try:
            g.rewrite_api_response_head(head)
            return False
        except ValueError:
            return True
    check("응답 헤더: CL+TE / 상이한 중복 CL / 1xx / obs-fold -> 거부 (502)",
          resp_rejects(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked")
          and resp_rejects(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2")
          and resp_rejects(b"HTTP/1.1 101 Switching")
          and resp_rejects(b"HTTP/1.1 200 OK\r\nX-A: 1\r\n folded"))
    st, head, mode, n = g.rewrite_api_response_head(b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\nServer: x")
    check("응답 헤더: HTTP/1.1 로 재작성, Server 제거, Connection: close",
          head.startswith(b"HTTP/1.1 200 OK\r\n") and b"Server" not in head and b"Connection: close" in head
          and mode == "length" and n == 3, head)

    print("[0b] 단위: 본문 마감 규칙 / 경로표 상한 / ApiBody(메모리·스풀) / 스풀 실패 응답")
    t = g.api_body_time
    check("본문 마감: <=320KiB 10s, 1MiB 32s, 8MiB 256s (1.3.0 규칙 그대로), 8MiB 초과는 256s 상한",
          t(0) == 10 and t(320 * 1024) == 10 and t(MIB) == 32 and t(8 * MIB) == 256
          and t(8 * MIB + 1) == 256 and t(PHOTO_CAP) == 256, [t(x) for x in (0, MIB, 8 * MIB, PHOTO_CAP)])
    check("64MiB 사진에 필요한 평균 속도 = 256 KiB/s (~2.1 Mbit/s), 상한 전 규칙이면 2048s(34분)",
          PHOTO_CAP / t(PHOTO_CAP) == 256 * 1024 and PHOTO_CAP / g.API_BODY_MIN_RATE == 2048)
    check("무응답 30s, 메모리 보관 상한 1MiB, 조각 64KiB",
          g.API_BODY_IDLE_TIMEOUT_S == 30 and g.API_BODY_MEM_MAX == MIB and g.API_IO_CHUNK == 65536)
    check("경로표: 사진 = (package, 64MiB, 60s), /package/upload = (package, 8MiB, 60s) 유지",
          g.API_ROUTES[("pkg", "POST", "/package/start-position/photo")] == ("package", PHOTO_CAP, 60)
          and g.API_ROUTES[("pkg", "POST", "/package/upload")] == ("package", 8 * MIB, 60))

    spool_dir = os.path.join(DATA, "ut_spool")
    os.mkdir(spool_dir)

    def my_spool_fds():
        base = os.path.realpath(spool_dir) + "/"
        n = 0
        for fd in os.listdir("/proc/self/fd"):
            try:
                n += os.readlink("/proc/self/fd/" + fd).startswith(base)
            except OSError:
                pass
        return n

    small = g.ApiBody(MIB, spool_dir)
    small.append(b"a" * MIB)
    small.finish()
    check("ApiBody: 1MiB 이하는 메모리 (파일 없음, 조각 그대로)",
          not small.spooled and my_spool_fds() == 0 and b"".join(small.chunks()) == b"a" * MIB)
    small.close()
    data = os.urandom(3 * MIB + 12345)
    big = g.ApiBody(len(data), spool_dir)
    for i in range(0, len(data), 50000):
        big.append(data[i:i + 50000])
    big.finish()
    pieces = list(big.chunks())
    check("ApiBody: 1MiB 초과는 데이터 디렉터리의 이름 없는 임시파일 (fd 1, 디렉터리 항목 0)",
          big.spooled and my_spool_fds() == 1 and os.listdir(spool_dir) == [], (my_spool_fds(), os.listdir(spool_dir)))
    check("ApiBody.chunks: 64KiB 이하 조각, 바이트 정확, 다시 읽어도 같음",
          b"".join(pieces) == data and max(len(p) for p in pieces) <= 65536 and b"".join(big.chunks()) == data)
    big.close()
    big.close()
    check("ApiBody.close: fd 해제, 두 번 호출해도 안전", my_spool_fds() == 0 and not big.spooled)

    def spool_error(fn):
        try:
            fn()
        except g.ApiSpoolError as e:
            return e
        return None
    saved = g.API_SPOOL_MIN_FREE
    g.API_SPOOL_MIN_FREE = 1 << 62      # more than any disk has
    e = spool_error(lambda: g.ApiBody(2 * MIB, spool_dir))
    g.API_SPOOL_MIN_FREE = saved
    check("ApiBody: 여유 공간 부족 -> 스풀 시작 전 거부, 507 insufficient_storage",
          e is not None and e.reply() == (507, "insufficient_storage") and my_spool_fds() == 0, e)
    # The free-space floor is arithmetic on statvfs (nothing is written), so a 1 GiB body and margins of
    # 256 MiB either way: other writes to this disk while the test runs cannot flip an outcome.
    gib, margin = 1024 * MIB, 256 * MIB
    st = os.statvfs(spool_dir)
    free = st.f_bavail * st.f_frsize
    g.API_SPOOL_MIN_FREE = free - 2 * gib + margin      # body + floor fits (by 768 MiB), twice the body does not
    e_twice = spool_error(lambda: g.ApiBody(gib, spool_dir).close())
    g.API_SPOOL_MIN_FREE = free - 2 * gib - margin      # twice the body + floor fits by 256 MiB
    e_fits = spool_error(lambda: g.ApiBody(gib, spool_dir).close())
    g.API_SPOOL_MIN_FREE = saved
    check("ApiBody: 여유 공간 < 본문 2배 + 32MiB -> 507 (백엔드 사본: werkzeug 임시 파일이 스풀과 함께 있고 이어서 사진 옆 "
          "임시 파일), 2배 + 32MiB 이상이면 수락",
          e_twice is not None and e_twice.reply() == (507, "insufficient_storage") and e_fits is None
          and my_spool_fds() == 0, (e_twice, e_fits))
    # live spools count with what they will still take, the rest of the spool and the backend's copy (two
    # uploads starting together must not both pass the check and then fill the disk)
    g.API_SPOOL_MIN_FREE = free - 2 * gib - margin      # the 1 GiB spool passes by 256 MiB
    first_spool = g.ApiBody(gib, spool_dir)             # announces 2 GiB, writes nothing yet
    g.API_SPOOL_MIN_FREE = free - 2 * 2 * MIB - gib - margin    # a 2 MiB spool: passes alone by 1.25 GiB,
    e_busy = spool_error(lambda: g.ApiBody(2 * MIB, spool_dir).close())     # fails by 768 MiB beside 2 GiB announced
    first_spool.close()
    e_alone = spool_error(lambda: g.ApiBody(2 * MIB, spool_dir).close())
    g.API_SPOOL_MIN_FREE = saved
    check("ApiBody: 진행 중 스풀이 앞으로 쓸 양(남은 스풀 + 백엔드 사본)도 사용분으로 계산 (동시 업로드로 디스크를 못 채움)",
          e_busy is not None and e_busy.reply() == (507, "insufficient_storage") and e_alone is None
          and not g.ApiBody._spooling and my_spool_fds() == 0, (e_busy, e_alone, len(g.ApiBody._spooling)))
    e = spool_error(lambda: g.ApiBody(2 * MIB, os.path.join(DATA, "no_such_dir")))
    check("ApiBody: 스풀 디렉터리 없음 -> ApiSpoolError 500 spool_failed (소켓 OSError 와 구분)",
          e is not None and e.reply() == (500, "spool_failed"), e)

    class FailingFile(object):
        def __init__(self, code):
            self.code = code

        def write(self, *_args):
            raise OSError(self.code, os.strerror(self.code))
        flush = seek = read = write

        def close(self):
            pass
    mapped = []
    for code in (errno.ENOSPC, errno.EDQUOT, errno.EFBIG, errno.EIO):
        b = g.ApiBody(2 * MIB, spool_dir)
        if b._file is not None:
            b._file.close()
        b._file = FailingFile(code)
        e1 = spool_error(lambda: b.append(b"x"))
        e2 = spool_error(lambda: b.finish())
        e3 = spool_error(lambda: list(b.chunks()))
        mapped.append((errno.errorcode[code], e1 and e1.reply(), e2 and e2.reply(), e3 and e3.reply()))
        b.close()
    check("ApiBody: 쓰기/flush/읽기 오류 -> ENOSPC·EDQUOT·EFBIG 는 507, EIO 는 500",
          [m[1:] for m in mapped] == [((507, "insufficient_storage"),) * 3] * 3 + [((500, "spool_failed"),) * 3],
          mapped)

    async def body_cases():     # readers are created inside the running loop (3.6 binds at creation)
        b = g.ApiBody(10, DATA)
        await g.Gateway.api_read_body(asyncio.StreamReader(), b"0123456789EXTRA", b)
        exact = b"".join(b.chunks())
        g.API_BODY_MIN_TIMEOUT_S = 0.3      # module global, read at call time
        t0 = time.time()
        try:
            await g.Gateway.api_read_body(asyncio.StreamReader(), b"ab", g.ApiBody(10, DATA))
            timed_out = False
        except asyncio.TimeoutError:
            timed_out = True
        took = time.time() - t0
        g.API_BODY_MIN_TIMEOUT_S, g.API_BODY_IDLE_TIMEOUT_S = 10.0, 0.3
        t0 = time.time()
        reader = asyncio.StreamReader()
        reader.feed_data(b"x" * 100)
        try:
            await g.Gateway.api_read_body(reader, b"", g.ApiBody(1000, DATA))
            idle = False
        except asyncio.TimeoutError:
            idle = True
        g.API_BODY_IDLE_TIMEOUT_S = 30.0
        return exact, timed_out, took, idle, time.time() - t0
    loop = asyncio.new_event_loop()
    try:
        exact, timed_out, took, idle, took_idle = loop.run_until_complete(body_cases())
    finally:
        loop.close()
    check("api_read_body: 선언 길이 이후 바이트(파이프라인/스머글링)는 버림", exact == b"0123456789", exact)
    check("api_read_body: 본문 전체 마감시간 초과 -> TimeoutError (408 경로)", timed_out and took < 1.5, took)
    check("api_read_body: 마감 전이라도 무응답(idle) 초과 -> TimeoutError", idle and took_idle < 1.5, took_idle)

    # api_request in process: spool failures answer before the backend (port 1: unreachable) and
    # free the slot; a client that vanishes or stalls mid-body leaves no spool fd and no held slot
    logging.getLogger("vizanti_gateway").setLevel(logging.CRITICAL)     # expected warnings: not test output

    async def request_case(data_dir, length, feed, eof, headers=None):
        args = argparse.Namespace(data_dir=data_dir, nif_port=1, pkg_port=1)
        gw = g.Gateway(args)
        gw.api_sems = {svc: asyncio.Semaphore(g.API_CONCURRENCY[svc]) for svc in g.API_SERVICES}
        reader = asyncio.StreamReader()
        reader.feed_data(feed)
        if eof:
            reader.feed_eof()
        w = FakeWriter()
        hdrs = {"host": "r", "content-length": str(length)}
        hdrs.update(headers or {})
        try:
            await gw.api_request("POST", "pkg", "/package/start-position/photo", "", hdrs, length, "c" * 32,
                                 {"package"}, b"", reader, w, "127.0.0.1", g.now())
            raised = None
        except Exception as ex:     # noqa: BLE001 - the case inspects it
            raised = ex
        sem = gw.api_sems["pkg"]
        free = 0
        for _ in range(g.API_CONCURRENCY["pkg"]):
            try:
                await asyncio.wait_for(sem.acquire(), 0.2)
                free += 1
            except asyncio.TimeoutError:
                pass
        return w.data, raised, free, my_spool_fds()

    def run_case(*a, **kw):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(request_case(*a, **kw))
        finally:
            loop.close()
    out, raised, free, fds = run_case(os.path.join(DATA, "no_such_dir"), 2 * MIB, b"x" * 1000, True)
    check("api_request: 스풀 생성 실패 -> 500 JSON spool_failed, 백엔드 미접촉, pkg 슬롯 2개 모두 반환",
          out.startswith(b"HTTP/1.1 500 ") and out.endswith(b'{"error": "spool_failed"}') and raised is None
          and free == 2, (out[:60], raised, free))
    g.API_SPOOL_MIN_FREE = 1 << 62
    out, raised, free, fds = run_case(spool_dir, 2 * MIB, b"", False, {"expect": "100-continue"})
    g.API_SPOOL_MIN_FREE = saved
    check("api_request: 디스크 부족 + Expect: 100-continue -> 100 없이 바로 507 insufficient_storage, 슬롯 반환",
          out.startswith(b"HTTP/1.1 507 Insufficient Storage\r\n") and b"100 Continue" not in out
          and out.endswith(b'{"error": "insufficient_storage"}') and free == 2, (out[:60], free))
    out, raised, free, fds = run_case(spool_dir, 2 * MIB, b"x" * (MIB + 5), True)
    check("api_request: 스풀 중 클라이언트 종료 -> ConnectionError 전파(연결 정리), 스풀 fd 0, 슬롯 반환",
          isinstance(raised, ConnectionError) and fds == 0 and free == 2 and out == b"", (raised, fds, free, out[:60]))
    g.API_BODY_MAX_TIMEOUT_S = 0.3
    out, raised, free, fds = run_case(spool_dir, 2 * MIB, b"x" * (MIB + 5), False)
    g.API_BODY_MAX_TIMEOUT_S = 256.0
    check("api_request: 스풀 중 본문 마감 초과 -> 408 body_timeout, 스풀 fd 0, 슬롯 반환",
          out.startswith(b"HTTP/1.1 408 ") and out.endswith(b'{"error": "body_timeout"}') and raised is None
          and fds == 0 and free == 2, (out[:60], raised, fds, free))

    # api_forward against a slow loopback backend: every SO_LINGER change is recorded together with the
    # transport's write buffer at that moment (a killed gateway loses what is still in user space), and
    # every write to the backend with the spool fds open at that moment
    payload = os.urandom(6 * MIB)       # more than the loopback kernel buffers take at once (~3.5 MiB)

    async def forward_case():
        seen, calls, writes = {}, [], []
        real = getattr(g, "_set_linger0", None)     # absent before this fix: nothing recorded, the check fails

        async def backend(reader, bw):
            try:
                head = await reader.readuntil(b"\r\n\r\n")
                n = int(re.search(rb"\r\nContent-Length: ([0-9]+)\r\n", head).group(1))
                parts, got = [], 0
                while got < n:
                    piece = await reader.read(min(32768, n - got))
                    if not piece:
                        break
                    parts.append(piece)
                    got += len(piece)
                    await asyncio.sleep(0.002)
                seen["body"] = b"".join(parts)
                await asyncio.sleep(0.1)            # a backend that takes its time to answer
                seen["fds"] = my_spool_fds()
                bw.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                await bw.drain()
                seen["tail"] = await reader.read()  # b"": FIN
            except Exception as ex:     # noqa: BLE001 - the case inspects it
                seen["error"] = repr(ex)
            finally:
                seen["done"] = True
                bw.close()

        def spy(transport, on):
            real(transport, on)
            try:
                linger = struct.unpack("ii", transport.get_extra_info("socket").getsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, 8))
            except (OSError, AttributeError):
                linger = None
            calls.append((on, transport.get_write_buffer_size(), transport.get_write_buffer_limits(), linger))
            if on and not writes:   # right after the connect: record each write (bytes, spool fds open)
                transport_write = transport.write

                def write(data):
                    writes.append((len(data), my_spool_fds()))
                    transport_write(data)
                transport.write = write
        server = await asyncio.start_server(backend, "127.0.0.1", 0)
        body = g.ApiBody(len(payload), spool_dir)
        if real is not None:
            g._set_linger0 = spy
        try:
            gw = g.Gateway(argparse.Namespace(data_dir=spool_dir, nif_port=1,
                                              pkg_port=server.sockets[0].getsockname()[1]))
            body.append(payload)
            body.finish()
            conn = {"id": 1, "client_id": "c" * 32, "cwriter": None, "bwriter": None, "status": None,
                    "nin": len(payload), "nout": 0, "complete": False, "severed": None}
            w = FakeWriter()
            await gw.api_forward(conn, "pkg", "POST", "/package/upload", "", {}, body, 30, w)
            for _ in range(250):
                if "done" in seen:
                    break
                await asyncio.sleep(0.02)
        finally:
            if real is not None:
                g._set_linger0 = real
            body.close()
            server.close()
        return calls, seen, w.data, conn, writes
    loop = asyncio.new_event_loop()
    try:
        calls, seen, out, conn, writes = loop.run_until_complete(forward_case())
    finally:
        loop.close()
    check("api_forward: 스풀은 마지막 조각을 읽은 뒤 그 조각을 백엔드에 쓰기 전에 해제 (백엔드가 본문을 다 받기 전에 디스크 공간"
          " 반환: network-iface 가 그 직후 자기 사본의 여유 공간을 확인)",
          len(writes) > 2 and all(fds == 1 for _n, fds in writes[:-1]) and writes[-1][1] == 0
          and sum(n for n, _fds in writes[1:]) == len(payload), writes[:2] + writes[-2:])
    check("api_forward: SO_LINGER(1,0) 은 연결 직후 설정(버퍼 0), 해제는 마지막 drain(쓰기 한계 0)으로 버퍼가 빈 뒤"
          " -> 어느 순간 죽어도 백엔드는 RST 또는 완전한 요청",
          len(calls) == 2 and calls[0][0] is True and calls[0][1] == 0 and calls[0][3] == (1, 0)
          and calls[1] == (False, 0, (0, 0), (0, 0)), calls)
    check("api_forward: 본문을 다 넘기면 백엔드 응답 전에 스풀 해제, 완료 후 200 + 백엔드 연결 정상 종료(FIN)",
          seen.get("fds") == 0 and seen.get("body") == payload and seen.get("tail") == b""
          and out.startswith(b"HTTP/1.1 200 ") and conn["status"] == 200 and conn["complete"],
          (seen.get("fds"), len(seen.get("body") or b""), seen.get("tail"), seen.get("error"), out[:40],
           conn["status"]))

    # The janitor severing a revoked client's request. "relay": its real loop (no clients.json in spool_dir:
    # every client counts as revoked) cuts in while a chunked response is relayed, where the reset backend's
    # early EOF looks like the end of the body. "connect": revoked while api_forward connected (the mark set
    # as the janitor sets it): the backend must not get a byte. Either way: audited as severed, no backend
    # failure warning, no reply.
    class Collect(logging.Handler):
        def __init__(self):
            logging.Handler.__init__(self)
            self.lines = []

        def emit(self, record):
            self.lines.append("%s %s" % (record.levelname, record.getMessage()))

    async def sever_case(stage):
        seen, tasks, collect = {}, [], Collect()

        async def backend(reader, bw):
            try:
                seen["got"] = await reader.read(65536)
                if seen["got"]:
                    bw.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\npart\r\n")
                    await bw.drain()
                seen["rest"] = await asyncio.wait_for(reader.read(), 5)
            except Exception as ex:     # noqa: BLE001 - the case inspects it
                seen["error"] = repr(ex)
            finally:
                seen["done"] = True
                bw.close()
        server = await asyncio.start_server(backend, "127.0.0.1", 0)
        gw = g.Gateway(argparse.Namespace(data_dir=spool_dir, nif_port=1, janitor_period=0.05, api_log_period=60.0,
                                          pkg_port=server.sockets[0].getsockname()[1]))
        gw.api_sems = {svc: asyncio.Semaphore(g.API_CONCURRENCY[svc]) for svc in g.API_SERVICES}
        w = FakeWriter()
        lg = logging.getLogger("vizanti_gateway")
        lg.addHandler(collect)
        lg.setLevel(logging.INFO)
        try:
            if stage == "connect":
                body = g.ApiBody(4, spool_dir)
                body.append(b"body")
                conn = {"id": 1, "client_id": "c" * 32, "cwriter": w, "bwriter": None, "status": None,
                        "nin": 4, "nout": 0, "complete": False, "severed": "revoked"}
                try:
                    await asyncio.wait_for(gw.api_forward(conn, "pkg", "POST", "/package/upload", "", {}, body,
                                                          30, w), 10)
                except Exception as ex:     # noqa: BLE001 - the case inspects it
                    seen["raised"] = repr(ex)
                body.close()
                gw.api_audit(conn, "127.0.0.1", "POST", "pkg", "/package/upload", g.now())
            else:
                async def janitor_once_relaying():
                    while b"part" not in w.data:
                        await asyncio.sleep(0.01)
                    tasks.append(asyncio.ensure_future(gw.janitor()))
                tasks.append(asyncio.ensure_future(janitor_once_relaying()))
                try:
                    await asyncio.wait_for(gw.api_request(
                        "POST", "pkg", "/package/upload", "", {"host": "r", "content-length": "4"}, 4, "c" * 32,
                        {"package"}, b"body", asyncio.StreamReader(), w, "127.0.0.1", g.now()), 10)
                except Exception as ex:     # noqa: BLE001 - the case inspects it
                    seen["raised"] = repr(ex)
            for _ in range(100):
                if "done" in seen:
                    break
                await asyncio.sleep(0.02)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            lg.removeHandler(collect)
            lg.setLevel(logging.CRITICAL)
            server.close()
        return seen, w.data, collect.lines
    loop = asyncio.new_event_loop()
    try:
        relay = loop.run_until_complete(sever_case("relay"))
        severed_early = loop.run_until_complete(sever_case("connect"))
    finally:
        loop.close()
    seen, out, lines = relay
    check("janitor(실제 루프)가 chunked 응답 중계 중 폐기 클라이언트를 끊음 -> 감사 'severed (revoked)' (200 아님), 백엔드 RST,"
          " 백엔드 장애 경고·502·처리 안 된 예외 없음",
          any("severing api conn" in l and "reason=revoked" in l for l in lines)
          and any("POST pkg /package/upload -> severed (revoked) req=4B" in l for l in lines)
          and not any(l.startswith(("WARNING", "ERROR")) for l in lines) and b"part" in out
          and b" 502 " not in out and seen.get("error", "").startswith("ConnectionResetError")
          and "raised" not in seen, (lines, out[-60:], seen))
    seen, out, lines = severed_early
    check("연결하는 사이 폐기된 요청 (janitor 표시) -> 백엔드는 한 바이트도 못 받음, 클라이언트 응답·경고 없음, 감사 "
          "'severed (revoked)'",
          not seen.get("got") and not seen.get("rest") and out == b"" and "raised" not in seen
          and any("POST pkg /package/upload -> severed (revoked) req=4B" in l for l in lines)
          and not any(l.startswith(("WARNING", "ERROR")) for l in lines), (seen, out[:60], lines))
    check("ApiBody/api_request 후 스풀 디렉터리 비어 있음", os.listdir(spool_dir) == [], os.listdir(spool_dir))


# ====================================================================================
# the end-to-end test
# ====================================================================================

def main():
    with open(UID_FILE, "w") as f:
        f.write("test-robot-uid-1234\n")
    with open(ROUTES_FILE, "w") as f:
        json.dump({"routes": [{"svc": "nif", "method": "GET", "path": "/iface/recent", "perm": "read",
                               "max_body": 0, "timeout": 1},
                              {"svc": "pkg", "method": "POST", "path": "/package/slowread", "perm": "package",
                               "max_body": PHOTO_CAP, "timeout": 1},
                              {"svc": "pkg", "method": "POST", "path": "/package/trickle", "perm": "package",
                               "max_body": PHOTO_CAP, "timeout": 60},
                              {"svc": "pkg", "method": "POST", "path": "/package/badclose", "perm": "package",
                               "max_body": 1024, "timeout": 10}]}, f)
    if USE_TLS:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-keyout", os.path.join(DATA, "tls_key.pem"), "-out", os.path.join(DATA, "tls_cert.pem"),
                        "-days", "1", "-nodes", "-subj", "/CN=vizanti-gw-api-test"],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("mode: %s | python %s | gateway ed25519 backend: %s" % (
        "TLS" if USE_TLS else "plain (--no-tls)", sys.version.split()[0],
        os.environ.get("VIZANTI_GW_ED25519") or "auto"))

    unit_tests()

    be = Backends()
    be.start()
    common = ([] if USE_TLS else ["--no-tls"]) + [
        "--data-dir", DATA, "--robot-uid-file", UID_FILE, "--nif-port", str(P_NIF), "--pkg-port", str(P_PKG),
        "--janitor-period", "1", "--flask-port", "15999", "--ws-port", "15998"]
    gw1 = subprocess.Popen([sys.executable, GW, "serve", "--listen-port", str(P_GW1), "--api-log-period", "1"] + common,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    gw2 = subprocess.Popen([sys.executable, GW, "serve", "--listen-port", str(P_GW2), "--api-token-ttl", "1",
                            "--api-routes", ROUTES_FILE] + common,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    gw3 = subprocess.Popen([sys.executable, "-c", GW3_WRAPPER, GW, "serve", "--listen-port", str(P_GW3)] + common,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    later = []      # GW4 instances started by run(): stopped (unless already killed) and logged here

    def spawn_gw4():
        p = subprocess.Popen([sys.executable, "-c", GW4_WRAPPER, GW, "serve", "--listen-port", str(P_GW4),
                              "--api-routes", ROUTES_FILE] + common,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        later.append(p)
        wait_up(P_GW4, p)
        return p
    out1 = out2 = out3 = ""
    outs4 = []
    try:
        wait_up(P_GW1, gw1)
        wait_up(P_GW2, gw2)
        wait_up(P_GW3, gw3)
        run(be, {"gw1": gw1, "gw2": gw2, "gw3": gw3, "spawn_gw4": spawn_gw4})
    finally:
        for p in [gw1, gw2, gw3] + later:
            if p.poll() is None:    # own children only, and never one that was already reaped
                p.terminate()
        try:
            out1 = gw1.communicate(timeout=5)[0]
            out2 = gw2.communicate(timeout=5)[0]
            out3 = gw3.communicate(timeout=5)[0]
            outs4 = [p.communicate(timeout=5)[0] for p in later]
        except subprocess.TimeoutExpired:
            for p in [gw1, gw2, gw3] + later:
                if p.poll() is None:
                    p.kill()

    print("[15] 감사 로그")
    lines = out1.splitlines()
    check("비-GET 은 요청마다 INFO 감사 (client/ip/메서드/경로/상태/바이트)",
          any(re.search(r"INFO api client=full\([0-9a-f]{8}\) ip=127\.0\.0\.1 POST nif /navi/request -> 200 "
                        r"req=\d+B resp=\d+B", l) for l in lines), "\n".join(lines[-15:]))
    check("권한 거부도 감사 (ro POST -> 403)",
          any("api client=ro(" in l and "POST nif /navi/request -> 403" in l for l in lines))
    check("GET 은 집계 줄로만 기록 (요청별 줄 없음)",
          any(re.search(r"api GET x\d+ in \d+s client=full\(", l) for l in lines)
          and not any(re.search(r"api client=\S+ ip=\S+ GET ", l) for l in lines))
    check("64MiB 사진 감사 줄 (req=67108864B -> 200)",
          any("POST pkg /package/start-position/photo -> 200 req=%dB" % PHOTO_CAP in l for l in lines))
    lines3 = out3.splitlines()
    check("GW3 감사: 507·408 기록 + 스풀 실패 경고(데이터 디렉터리·errno 포함)",
          any("POST pkg /package/start-position/photo -> 507" in l for l in lines3)
          and any("POST pkg /package/start-position/photo -> 408" in l for l in lines3)
          and any("request body not stored in %s: [Errno %d]" % (DATA, errno.EFBIG) in l for l in lines3),
          "\n".join(lines3[-15:]))
    lines2 = out2.splitlines()
    check("GW2: janitor 가 폐기된 클라이언트의 전달 중 요청을 끊음 (severing api conn reason=revoked), 처리 안 된 예외 없음",
          any("severing api conn" in l and "reason=revoked" in l for l in lines2)
          and not any("handler failed" in l or "Traceback" in l for l in lines2), "\n".join(lines2[-15:]))
    check("GW2: janitor 차단은 감사에 '-> severed (revoked)' 로 남고 백엔드 장애(경고 'api backend pkg failed', 502)로 "
          "기록되지 않음",
          any("POST pkg /package/trickle -> severed (revoked) req=%dB" % (16 * MIB) in l for l in lines2)
          and not any("/package/trickle" in l and ("api backend pkg failed" in l or "-> 502" in l) for l in lines2),
          [l for l in lines2 if "/package/trickle" in l])
    check("GW2: 차단 직후 실제 백엔드 장애의 경고는 그대로 남음 (차단이 pkg 의 60s 경고 슬롯을 쓰지 않음)",
          any("WARNING api backend pkg failed POST /package/badclose: backend closed before the response head" in l
              for l in lines2), [l for l in lines2 if "WARNING api backend" in l])
    crashes = [l for l in all_lines(out1, out2, out3, *outs4) if "Traceback" in l or "handler failed" in l]
    check("게이트웨이 로그 전부 (GW1-3, GW4 x%d) 에 처리 안 된 예외 없음 (Traceback / handler failed)" % len(outs4),
          not crashes, crashes[:5])
    check("발급된 토큰 값이 로그에 없음",
          ISSUED and not any(t in out for t in ISSUED for out in [out1, out2, out3] + outs4), len(ISSUED))

    shutil.rmtree(DATA, ignore_errors=True)
    print("\n==> %d passed, %d failed" % (len(passed), len(failed)))
    if skipped:
        print("skipped (scenario not reached on this host):", skipped)
    if failed:
        print("failed:", failed)
        print("--- GW1 log tail ---")
        print("\n".join(out1.splitlines()[-30:]))
        print("--- GW2 log tail ---")
        print("\n".join(out2.splitlines()[-10:]))
        print("--- GW3 log tail ---")
        print("\n".join(out3.splitlines()[-15:]))
        sys.exit(1)


def all_lines(*outs):
    return [l for out in outs for l in out.splitlines()]


def run(be, procs):
    fp = robot_fp()

    def pkg_slots_free(port, token):
        """(ok, detail): both pkg slots of that gateway are free - two held requests reach the
        backend and a third is 503 busy. Catches a semaphore leaked by any earlier error path."""
        results = {}
        held0 = be.pkg.held

        def hold(i):
            results[i] = api_req("GET", "/api/pkg/package/floor?hold=1", token, port=port, timeout=25)
        threads = [threading.Thread(target=hold, args=(i,)) for i in range(2)]
        for th in threads:
            th.start()
        wait_until(lambda: be.pkg.held - held0 >= 2)
        third = api_req("GET", "/api/pkg/package/floor", token, port=port)
        reached = be.pkg.held - held0
        be.release(be.pkg)
        for th in threads:
            th.join(30)
        be.rearm(be.pkg)
        ok = reached == 2 and third.status == 503 and all(
            results.get(i) is not None and results[i].status == 200 for i in range(2))
        return ok, (reached, third, results)

    def none_reach(label, fn, want):
        """fn() must answer `want` and the backends must not see a single connection."""
        mark = be.mark()
        r = fn()
        time.sleep(0.05)
        new = be.since(mark)
        check(label, r.status == want and not new, (r, len(new)))
        return r

    def one_request(label, fn, want=200, extra_check=None):
        """fn() must answer `want` and the backends must see exactly ONE well-formed request."""
        mark = be.mark()
        r = fn()
        new = be.since(mark)
        infos = [well_formed(rec) for rec in new]
        ok = r.status == want and len(new) == 1 and infos[0][0]
        detail = (r, [i[1] if not i[0] else "ok" for i in infos])
        if ok and extra_check is not None:
            ok = extra_check(r, infos[0][1])
        check(label, ok, detail)
        return r, (infos[0][1] if len(infos) == 1 and infos[0][0] else None)

    print("[1] /gw/info, 비인가 /api")
    r = gw_get("/gw/info")
    info = r.json()
    check("/gw/info: version 1.3.0, api=1, api_services=[nif,pkg]",
          info.get("version") == "1.3.0" and info.get("api") == 1 and info.get("api_services") == ["nif", "pkg"], info)
    r = none_reach("토큰 없는 /api -> 401 (백엔드 미접촉)", lambda: api_req("GET", "/api/nif/uid"), 401)
    check("401 에 WWW-Authenticate: Bearer + JSON", r.headers.get("www-authenticate") == "Bearer"
          and r.json() == {"error": "unauthorized"}, r.headers)

    print("[2] 페어링 권한 (newcode --perms)")
    full = pair("full", None, "127.0.0.11")
    check("기본 newcode -> perms 4개", full.perms == ["ui", "read", "drive", "package"], full.perms)
    ro = pair("ro", "read", "127.0.0.12")
    check("newcode --perms read -> perms [read]", ro.perms == ["read"], ro.perms)
    rcs = pair("rcs", "read,drive", "127.0.0.13")
    uionly = pair("uionly", "ui", "127.0.0.14")
    victim = pair("victim", None, "127.0.0.15")
    r = gw_cli("newcode", "read,drive")
    check("newcode 위치인자(--perms 누락) -> 거부 (전체 권한 오발급 방지)", r.returncode != 0, r.returncode)
    r = gw_cli("newcode", "--perms", "read,root")
    check("newcode --perms 알 수 없는 권한 -> 거부", r.returncode != 0, r.returncode)
    lc = gw_cli("list-clients").stdout
    check("list-clients 가 perms 출력", "name=ro  perms=read " in lc and "name=rcs  perms=read,drive " in lc, lc)
    # a code written by a pre-1.3.0 newcode (no pairing_perms file) keeps its old meaning: full access
    gw_cli("newcode")
    os.remove(os.path.join(DATA, "pairing_perms"))
    priv = _SigningKey()
    pub = base64.b64encode(priv.pub).decode()
    st, j = gw_post("/gw/pair", pair_body(read_code(), "legacycode", pub, fp), src="127.0.0.16")
    check("pairing_perms 없는 (구버전) 코드 -> 전체 권한", st == 200 and j.get("perms") == list(("ui", "read", "drive", "package")), (st, j))
    # a perms file that belongs to another code fails closed and keeps the code
    gw_cli("newcode", "--perms", "read")
    code = read_code()
    with open(os.path.join(DATA, "pairing_perms"), "w") as f:
        json.dump({"code_sha256": "0" * 64, "perms": ["read"]}, f)
    st, j = gw_post("/gw/pair", pair_body(code, "mismatch", pub, fp), src="127.0.0.17")
    check("다른 코드에 묶인 pairing_perms -> 페어링 거부 + 코드 보존",
          st == 403 and os.path.exists(os.path.join(DATA, "pairing_code")), (st, j))
    # an entry without "perms" (paired by gateway 1.2.0) keeps full access
    with open(os.path.join(DATA, "clients.json")) as f:
        clients = json.load(f)
    lpriv = _SigningKey()
    clients["0123456789abcdef0123456789abcdef"] = {"name": "legacy", "ed25519_pub": base64.b64encode(lpriv.pub).decode(),
                                                   "paired_at": 0, "paired_from": "127.0.0.18"}
    tmp = os.path.join(DATA, "clients.json.t")
    with open(tmp, "w") as f:
        json.dump(clients, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, os.path.join(DATA, "clients.json"))
    legacy = Client("legacy", "0123456789abcdef0123456789abcdef", lpriv, None)

    print("[3] 토큰 발급 / 서명 도메인 분리")
    st, j = api_token(full)
    check("정상 발급: ttl 900, perms [read,drive,package], robot_uid",
          st == 200 and j.get("ttl") == 900 and j.get("perms") == ["read", "drive", "package"]
          and j.get("robot_uid") == "test-robot-uid-1234" and len(j.get("token", "")) >= 40,
          (st, sorted(j)))
    tok_full = j.get("token", "")
    st, j = api_token(full, ctx=UI_CTX)
    check("UI 세션 서명(vizanti-gw-v2)으로 /gw/api-token -> 403", st == 403 and j.get("error") == "auth_failed", (st, j))
    st, j = api_token(full, ctx=API_CTX, endpoint="/gw/session")
    check("API 서명(rgt-robot-api-v1)으로 /gw/session -> 403", st == 403 and j.get("error") == "auth_failed", (st, j))
    nonce, _ = challenge(full)
    st, _ = gw_post("/gw/api-token", {"client_id": full.cid, "nonce": nonce, "sig": base64.b64encode(b"x" * 64).decode()})
    st2, _ = gw_post("/gw/api-token", {"client_id": full.cid, "nonce": nonce, "sig": signed(full, API_CTX, fp, nonce)})
    check("위조 서명 -> 403, 그 nonce 는 정상 서명으로도 재사용 불가", st == 403 and st2 == 403, (st, st2))
    nonce, _ = challenge(full)
    st, _ = gw_post("/gw/api-token", {"client_id": full.cid, "nonce": nonce, "sig": signed(full, API_CTX, fp, nonce)},
                    src="127.0.0.2")
    check("다른 IP 에서 받은 nonce -> 403", st == 403, st)
    nonce, _ = challenge(full)
    st, _ = gw_post("/gw/api-token", {"client_id": ro.cid, "nonce": nonce, "sig": signed(ro, API_CTX, fp, nonce)})
    check("다른 client 에 발급된 nonce -> 403", st == 403, st)
    st, j = api_token(uionly)
    check("ui 권한만 있는 client -> /gw/api-token 403 forbidden", st == 403 and j.get("error") == "forbidden", (st, j))
    st, j = api_token(rcs, ctx=UI_CTX, endpoint="/gw/session")
    check("ui 권한 없는 client(read,drive) -> /gw/session 403 forbidden", st == 403 and j.get("error") == "forbidden", (st, j))
    st, j = api_token(rcs)
    check("read,drive client -> 토큰 perms [read,drive]", st == 200 and j.get("perms") == ["read", "drive"], (st, j.get("perms")))
    tok_rcs = j.get("token", "")
    st, j = api_token(legacy)
    check("perms 없는 기존 등록 -> API 전체 권한", st == 200 and j.get("perms") == ["read", "drive", "package"], (st, j.get("perms")))
    st, _ = api_token(legacy, ctx=UI_CTX, endpoint="/gw/session")
    check("perms 없는 기존 등록 -> UI 세션 허용", st == 200, st)
    toks = [token_of(full) for _ in range(5)]
    check("클라이언트당 토큰 4개: 5번째 발급 시 가장 오래된 것 폐기",
          api_req("GET", "/api/nif/uid", toks[0]).status == 401
          and all(api_req("GET", "/api/nif/uid", t).status == 200 for t in toks[1:]))
    tok_full = toks[-1]

    print("[4] 프록시 기본 (요청 1건 = 연결 1개, 재직렬화)")
    r, req = one_request("GET /api/nif/uid -> 백엔드 GET /uid", lambda: api_req("GET", "/api/nif/uid", tok_full))
    check("응답 본문/헤더 (Connection: close, Cache-Control: no-store)",
          r.body == b"test-uid-1234" and r.headers.get("connection") == "close"
          and r.headers.get("cache-control") == "no-store", r)
    check("백엔드 요청: Host 127.0.0.1:nif, Connection: close, 다른 헤더 없음",
          req is not None and req["target"] == "/uid"
          and set(req["headers"]) == {b"host", b"connection"}, req and req["headers"])
    r, req = one_request("클라이언트 헤더 중 Content-Type/Accept 만 전달",
                         lambda: api_req("POST", "/api/nif/navi/request", tok_full, b'{"a":1}',
                                         extra=b"Cookie: vizanti_gw=zzz\r\nX-Evil: 1\r\nUser-Agent: t\r\n"
                                               b"Accept: application/json\r\nConnection: keep-alive, Upgrade\r\n"
                                               b"Upgrade: websocket\r\nX-Forwarded-For: 1.2.3.4\r\n"))
    check("백엔드 헤더 = host/connection/content-type/accept/content-length (Authorization·Cookie 미전달)",
          req is not None and set(req["headers"]) == {b"host", b"connection", b"content-type", b"accept", b"content-length"}
          and req["body"] == b'{"a":1}' and req["headers"][b"accept"] == b"application/json",
          req and sorted(req["headers"]))
    r, _ = one_request("응답 헤더 재작성 대상 경로", lambda: api_req("GET", "/api/nif/iface/position", tok_full))
    names = [k for k, _v in r.hlist]
    check("응답: Set-Cookie/Server/Access-Control-*/Keep-Alive/Connection 나열 헤더 제거",
          not any(n in ("set-cookie", "server", "keep-alive", "x-hop") or n.startswith("access-control-") for n in names)
          and r.headers.get("x-custom") == "kept" and names.count("cache-control") == 1
          and r.headers.get("cache-control") == "no-store" and names.count("connection") == 1
          and r.headers.get("connection") == "close" and r.body == b'{"x": 1.5, "y": -2}', r.hlist)
    r, req = one_request("쿼리 전달 (퍼센트 인코딩은 쿼리에서만 허용)",
                         lambda: api_req("GET", "/api/pkg/package/position?floor=B1%20F&x=1+2", tok_full))
    check("백엔드 대상 = /package/position?floor=B1%20F&x=1+2",
          req is not None and req["target"] == "/package/position?floor=B1%20F&x=1+2", req and req["target"])
    r, req = one_request("POST Content-Length: 0 -> 백엔드에도 Content-Length: 0",
                         lambda: api_req("POST", "/api/nif/iface/pause", tok_full, b""))
    check("빈 본문 POST 전달", req is not None and req["headers"].get(b"content-length") == b"0", req and req["headers"])
    # Expect: 100-continue (curl / .NET HttpWebRequest)
    mark = be.mark()
    s = connect()
    body = json.dumps({"goal": "B1-3"}).encode()
    s.sendall(b"POST /api/nif/navi/request HTTP/1.1\r\nHost: r\r\nAuthorization: Bearer %s\r\n"
              b"Content-Type: application/json\r\nContent-Length: %d\r\nExpect: 100-continue\r\n\r\n"
              % (tok_full.encode(), len(body)))
    interim = b""
    while b"\r\n\r\n" not in interim:
        chunk = s.recv(4096)
        if not chunk:
            break
        interim += chunk
    s.sendall(body)
    r = read_response(s)
    s.close()
    new = be.since(mark)
    check("Expect: 100-continue -> 100 후 본문 전달, 200",
          interim.startswith(b"HTTP/1.1 100 ") and r.status == 200 and r.json().get("len") == len(body)
          and len(new) == 1 and well_formed(new[0])[0], (interim[:40], r))

    print("[5] 권한")
    tok_ro = token_of(ro)
    one_request("read client: GET /api/nif/uid -> 200", lambda: api_req("GET", "/api/nif/uid", tok_ro))
    r = none_reach("read client: POST /navi/request -> 403 (백엔드 미접촉)",
                   lambda: api_req("POST", "/api/nif/navi/request", tok_ro, b'{"x":1}'), 403)
    check("403 본문 {error: forbidden}", r.json() == {"error": "forbidden"}, r)
    none_reach("read client: POST /package/upload -> 403",
               lambda: api_req("POST", "/api/pkg/package/upload", tok_ro, b"{}"), 403)
    one_request("read,drive client: POST /navi/request -> 200",
                lambda: api_req("POST", "/api/nif/navi/request", tok_rcs, b'{"x":1}'))
    none_reach("read,drive client: POST /package/upload -> 403",
               lambda: api_req("POST", "/api/pkg/package/upload", tok_rcs, b"{}"), 403)
    gw_cli("set-perms", "full", "read")
    none_reach("set-perms full read -> 같은 토큰의 POST 즉시 403",
               lambda: api_req("POST", "/api/nif/navi/request", tok_full, b"{}"), 403)
    one_request("set-perms 후에도 read 는 허용", lambda: api_req("GET", "/api/nif/uid", tok_full))
    gw_cli("set-perms", "full", "ui,read,drive,package")
    one_request("set-perms 복원 -> 같은 토큰의 POST 다시 200 (발급 시 권한 범위 내)",
                lambda: api_req("POST", "/api/nif/navi/request", tok_full, b"{}"))
    tok_up = token_of(rcs)
    gw_cli("set-perms", "rcs", "read,drive,package")
    none_reach("토큰은 발급 때 없던 권한을 얻지 않음 (package 추가 후에도 기존 토큰 upload 403)",
               lambda: api_req("POST", "/api/pkg/package/upload", tok_up, b"{}"), 403)
    gw_cli("set-perms", "rcs", "read,drive")
    cookie = ui_cookie(uionly)
    r = gw_get("/", cookie=cookie)
    check("ui client 쿠키 -> UI 경로 인가 (가짜 flask 없음 -> 502)", r.status == 502, r)
    none_reach("UI 쿠키는 /api 에 무효 (쿠키 무시) -> 401",
               lambda: send_raw(b"GET /api/nif/uid HTTP/1.1\r\nHost: r\r\nCookie: " + cookie + b"\r\n\r\n"), 401)
    gw_cli("set-perms", "uionly", "read")
    r = gw_get("/", cookie=cookie)
    check("set-perms 로 ui 회수 -> 기존 쿠키 즉시 401", r.status == 401, r)
    r = gw_cli("set-perms", "uionly", "admin")
    check("set-perms 알 수 없는 권한 -> 거부", r.returncode != 0, r.returncode)

    print("[6] Bearer / Origin")
    none_reach("Authorization 없음 -> 401", lambda: api_req("GET", "/api/nif/uid"), 401)
    none_reach("모르는 토큰 -> 401", lambda: api_req("GET", "/api/nif/uid", "A" * 43), 401)
    none_reach("Basic 스킴 -> 401", lambda: api_req("GET", "/api/nif/uid", tok_full, scheme=b"Basic"), 401)
    one_request("스킴 대소문자 무시 (bearer)", lambda: api_req("GET", "/api/nif/uid", tok_full, scheme=b"bearer"))
    none_reach("다른 IP 에서 같은 토큰 -> 401", lambda: api_req("GET", "/api/nif/uid", tok_full, src="127.0.0.2"), 401)
    t2 = token_of(full, port=P_GW2)
    one_request("GW2(TTL 1s): 발급 직후 200", lambda: api_req("GET", "/api/nif/uid", t2, port=P_GW2))
    time.sleep(1.3)
    none_reach("GW2: 만료된 토큰 -> 401", lambda: api_req("GET", "/api/nif/uid", t2, port=P_GW2), 401)
    none_reach("Origin 헤더 -> 403 (유효 토큰이라도)",
               lambda: api_req("POST", "/api/nif/navi/request", tok_full, b"{}",
                               extra=b"Origin: http://evil.example\r\n"), 403)
    none_reach("Origin: null -> 403",
               lambda: api_req("GET", "/api/nif/uid", tok_full, extra=b"Origin: null\r\n"), 403)

    print("[7] 경로 허용목록 (404, 백엔드 미접촉)")
    for method, path, body in [("POST", "/api/nif/iface/custom", b'{"type":1,"length":0,"data":""}'),
                               ("GET", "/api/nif/swagger.json", None), ("GET", "/api/nif/", None),
                               ("GET", "/api/nif", None), ("GET", "/api/nif/unknown", None),
                               ("GET", "/api/nif/iface/task", None), ("DELETE", "/api/nif/uid", None),
                               ("PUT", "/api/nif/navi/request", b"{}"), ("HEAD", "/api/nif/uid", None),
                               ("OPTIONS", "/api/nif/uid", None), ("GET", "/api/pkg/uid", None),
                               ("GET", "/api/nif/uid/", None), ("GET", "/api/nif/swaggerui/index.html", None)]:
        none_reach("%s %s -> 404" % (method, path), lambda: api_req(method, path, tok_full, body), 404)

    print("[8] 트래버설 / 인코딩 (400, 백엔드 미접촉)")
    for target in ["/api/nif/%2e%2e/iface/custom", "/api/nif/iface/%63ustom", "/api/nif/iface%2fcustom",
                   "/api/nif//uid", "/api/nif/./uid", "/api/nif/iface/../iface/custom", "/api/nif/iface/custom/..",
                   "/api/nif/iface/custom/.", "/api/nif/uid\\", "/api/nif/..\\iface\\custom", "/api/nif/uid;x=1",
                   "/api/nif/uid#x", "/api/NIF/uid", "/api/pkg/../nif/uid", "/api", "/api?x=1", "/api/",
                   "/api/nif/uid?x=%zz", "/api/nif/uid?x=<script>", "/api/nif/uid?a=b?c", "/api/nif/u%00id"]:
        none_reach("%s -> 400" % target, lambda: send_raw(
            b"GET %s HTTP/1.1\r\nHost: r\r\nAuthorization: Bearer %s\r\n\r\n" % (target.encode(), tok_full.encode())),
            400)

    print("[9] 헤더 스머글링 (백엔드는 정확히 1건의 정상 요청 또는 0건)")
    auth = b"Authorization: Bearer " + tok_full.encode() + b"\r\n"
    line = b"POST /api/nif/navi/request HTTP/1.1\r\n"
    cases = [
        ("중복 Content-Length (같은 값)", line + b"Host: r\r\n" + auth + b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}", 400),
        ("중복 Content-Length (다른 값)", line + b"Host: r\r\n" + auth + b"Content-Length: 2\r\nContent-Length: 40\r\n\r\n{}", 400),
        ("Content-Length 목록 '2, 2'", line + b"Host: r\r\n" + auth + b"Content-Length: 2, 2\r\n\r\n{}", 400),
        ("Content-Length '+2'", line + b"Host: r\r\n" + auth + b"Content-Length: +2\r\n\r\n{}", 400),
        ("CL + TE", line + b"Host: r\r\n" + auth + b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n", 411),
        ("TE: chunked", line + b"Host: r\r\n" + auth + b"Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n", 411),
        ("TE 대소문자 변형", line + b"Host: r\r\n" + auth + b"transfer-ENCODING: identity\r\nContent-Length: 2\r\n\r\n{}", 411),
        ("중복 TE", line + b"Host: r\r\n" + auth + b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\n", 400),
        ("콜론 앞 공백 'Content-Length :'", line + b"Host: r\r\n" + auth + b"Content-Length : 2\r\n\r\n{}", 400),
        ("bare CR", line + b"Host: r\r\n" + auth + b"X-A: a\rContent-Length: 40\r\nContent-Length: 2\r\n\r\n{}", 400),
        ("bare LF", line + b"Host: r\n" + auth + b"Content-Length: 2\r\n\r\n{}", 400),
        ("obs-fold", line + b"Host: r\r\n" + auth + b"Content-Length: 2\r\nX-A: a\r\n Transfer-Encoding: chunked\r\n\r\n{}", 400),
        ("헤더 65개", line + b"Host: r\r\n" + auth + b"Content-Length: 2\r\n"
         + b"".join(b"X-P%d: v\r\n" % i for i in range(62)) + b"\r\n{}", 400),
        ("중복 Host", line + b"Host: r\r\nHost: s\r\n" + auth + b"Content-Length: 2\r\n\r\n{}", 400),
        ("Host 없음", line + auth + b"Content-Length: 2\r\n\r\n{}", 400),
        ("중복 Authorization", line + b"Host: r\r\n" + auth + auth + b"Content-Length: 2\r\n\r\n{}", 400),
        ("콜론 없는 헤더 줄", line + b"Host: r\r\n" + auth + b"Content-Length: 2\r\nGarbage\r\n\r\n{}", 400),
        ("NUL 바이트", line + b"Host: r\r\n" + auth + b"X-A: a\x00b\r\nContent-Length: 2\r\n\r\n{}", 400),
        ("비 ASCII 헤더", line + b"Host: r\r\n" + auth + "X-A: 한글\r\n".encode() + b"Content-Length: 2\r\n\r\n{}", 400),
        ("HTTP/1.0", b"POST /api/nif/navi/request HTTP/1.0\r\nHost: r\r\n" + auth + b"Content-Length: 2\r\n\r\n{}", 400),
        ("소문자 메서드", b"post /api/nif/navi/request HTTP/1.1\r\nHost: r\r\n" + auth + b"Content-Length: 2\r\n\r\n{}", 400),
        ("요청줄 공백 2개", b"POST /api/nif/navi/request  HTTP/1.1\r\nHost: r\r\n" + auth + b"Content-Length: 2\r\n\r\n{}", 400),
        ("POST 에 Content-Length 없음", line + b"Host: r\r\n" + auth + b"\r\n{}", 411),
    ]
    for label, data, want in cases:
        none_reach("%s -> %d" % (label, want), lambda: send_raw(data), want)
    mark = be.mark()
    r = send_raw(b"POST http://127.0.0.1/api/nif/navi/request HTTP/1.1\r\nHost: r\r\n" + auth + b"Content-Length: 2\r\n\r\n{}")
    check("absolute-form 대상 -> API 로 라우팅 안 됨 (거부, 백엔드 미접촉)",
          r.status in (None, 401) and not be.since(mark), r)
    mark = be.mark()
    t0 = time.time()
    r = send_raw(b"POST /api/nif/navi/request HTTP/1.1\nHost: r\n" + auth.replace(b"\r\n", b"\n")
                 + b"Content-Length: 2\n\n{}", timeout=6)
    check("LF 전용 줄바꿈 -> 헤더 미완성으로 종료 (백엔드 미접촉)", r.status is None and not be.since(mark),
          (r, time.time() - t0))
    one_request("헤더 64개 정확히 -> 허용 (경계)", lambda: send_raw(
        line + b"Host: r\r\n" + auth + b"Content-Length: 2\r\n" + b"".join(b"X-P%d: v\r\n" % i for i in range(61)) + b"\r\n{}"))
    pipelined = (line + b"Host: r\r\n" + auth + b"Content-Length: 2\r\n\r\n{}"
                 + b"POST /api/nif/iface/custom HTTP/1.1\r\nHost: r\r\n" + auth + b"Content-Length: 2\r\n\r\n{}")
    r, req = one_request("파이프라인된 두 번째 요청 -> 무시, 백엔드는 1건만", lambda: send_raw(pipelined))
    check("백엔드가 받은 1건 = 첫 요청 그대로", req is not None and req["target"] == "/navi/request" and req["body"] == b"{}",
          req and (req["target"], req["body"][:40]))
    smuggle = b'{}POST /iface/custom HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}'
    r, req = one_request("본문 뒤에 숨긴 요청 (CL 이 짧음) -> 선언된 길이만 전달",
                         lambda: send_raw(line + b"Host: r\r\n" + auth + b"Content-Length: 2\r\n\r\n" + smuggle))
    check("백엔드 본문 = '{}' (숨긴 요청 미전달)", req is not None and req["body"] == b"{}", req and req["body"][:60])
    mark = be.mark()
    r = send_raw(line + b"Host: r\r\n" + auth + b"Content-Length: 10\r\n\r\n{}", close_after_send=True)
    time.sleep(0.3)
    check("본문 도중 연결 종료 -> 백엔드 미접촉", not be.since(mark))

    print("[10] 크기 / 동시성 / 시간 한도")
    none_reach("nif POST 64KiB+1 -> 413", lambda: send_raw(
        line + b"Host: r\r\n" + auth + b"Content-Length: 65537\r\n\r\n" + b"x" * 1000), 413)
    none_reach("pkg upload 8MiB+1 -> 413", lambda: send_raw(
        b"POST /api/pkg/package/upload HTTP/1.1\r\nHost: r\r\n" + auth + b"Content-Length: %d\r\n\r\n" % (8 * MIB + 1)
        + b"x" * 1000), 413)
    none_reach("GET 에 본문 -> 413 (GET 상한 0)", lambda: send_raw(
        b"GET /api/nif/uid HTTP/1.1\r\nHost: r\r\n" + auth + b"Content-Length: 1\r\n\r\nx"), 413)
    r = none_reach("413 후 본문 일부 전송 중에도 응답 수신 (drain)", lambda: send_raw(
        line + b"Host: r\r\n" + auth + b"Content-Length: 200000\r\n\r\n" + b"x" * 200000), 413)
    one_request("nif POST 정확히 64KiB -> 200 (경계)",
                lambda: api_req("POST", "/api/nif/navi/request", tok_full, b"x" * 65536))
    blob = os.urandom(2 * MIB)
    r, req = one_request("pkg upload 2MiB -> 200", lambda: api_req("POST", "/api/pkg/package/upload", tok_full, blob,
                                                                   timeout=30))
    check("업로드 바이트 정확성 (백엔드 sha256 = 원본, 응답 에코 일치)",
          req is not None and hashlib.sha256(req["body"]).digest() == hashlib.sha256(blob).digest()
          and r.json().get("sha256") == hashlib.sha256(blob).hexdigest() and r.json().get("len") == len(blob), r)
    blob8 = os.urandom(8 * MIB)
    r, req = one_request("pkg upload 정확히 8MiB -> 200 (경계)",
                         lambda: api_req("POST", "/api/pkg/package/upload", tok_full, blob8, timeout=60))
    check("8MiB 바이트 정확성", r.json().get("sha256") == hashlib.sha256(blob8).hexdigest(), r)
    mp = (b"--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"p.jpg\"\r\n"
          b"Content-Type: image/jpeg\r\n\r\n" + os.urandom(50000) + b"\r\n--XyZ--\r\n")
    r, req = one_request("multipart 사진 업로드 -> Content-Type(boundary) 그대로 전달",
                         lambda: api_req("POST", "/api/pkg/package/start-position/photo", tok_full, mp,
                                         ctype="multipart/form-data; boundary=XyZ"))
    check("multipart 본문/타입 정확", req is not None and req["body"] == mp
          and req["headers"].get(b"content-type") == b"multipart/form-data; boundary=XyZ", r)

    results = {}

    def held(i):
        results[i] = api_req("GET", "/api/pkg/package/floor?hold=1", tok_full, timeout=25)
    mark = be.mark()
    threads = [threading.Thread(target=held, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for _ in range(100):
        if be.pkg.held >= 2:
            break
        time.sleep(0.05)
    r = api_req("GET", "/api/pkg/package/floor", tok_full)
    check("pkg 동시 2건 점유 중 3번째 -> 503 + Retry-After: 1 (백엔드 미접촉)",
          r.status == 503 and r.headers.get("retry-after") == "1" and len(be.since_nowait(mark)) == 2,
          (r, len(be.pkg.conns) - mark[1]))
    one_request("pkg 포화 중에도 nif 는 별도 세마포어 -> 200", lambda: api_req("GET", "/api/nif/uid", tok_full))
    be.release(be.pkg)
    for t in threads:
        t.join(30)
    be.rearm(be.pkg)
    check("점유됐던 2건은 해제 후 200", all(results.get(i) is not None and results[i].status == 200 for i in range(2)),
          results)
    # API caps count AUTHENTICATED work only (per IP 8; a request parked in the post-reply drain
    # still counts). Unauthenticated sockets are bounded by the pre-TLS caps and never take a slot.
    tok_cap = token_of(legacy, src="127.0.0.3")
    socks = []
    for _ in range(10):
        s = connect(src="127.0.0.3")
        s.sendall(b"POST /api/nif/navi/request HTTP/1.1\r\nHost: r\r\nContent-Length: 1000\r\n\r\n")
        socks.append(s)
    time.sleep(0.3)
    one_request("비인증 연결 10개가 drain 중이어도 인증 요청은 API 상한에 안 걸림 -> 200",
                lambda: api_req("GET", "/api/nif/uid", tok_cap, src="127.0.0.3"))
    for _ in range(8):
        s = connect(src="127.0.0.3")
        s.sendall(b"POST /api/nif/iface/custom HTTP/1.1\r\nHost: r\r\nAuthorization: Bearer %s\r\n"
                  b"Content-Length: 1000\r\n\r\n" % tok_cap.encode())
        socks.append(s)
    time.sleep(0.3)
    r = none_reach("IP 당 인증 API 연결 상한 8 -> 9번째 503 (백엔드 미접촉)",
                   lambda: api_req("GET", "/api/nif/uid", tok_cap, src="127.0.0.3"), 503)
    check("상한 503 에 Retry-After: 1", r.headers.get("retry-after") == "1", r)
    for s in socks:
        s.close()
    t3 = token_of(full, port=P_GW2)
    took = {}

    def slow():
        t0 = time.time()
        resp = api_req("GET", "/api/nif/iface/recent", t3, port=P_GW2)
        took["s"] = time.time() - t0
        return resp
    r, _ = one_request("GW2: 백엔드 지연(3s) > 경로 타임아웃(1s, --api-routes) -> 504", slow, want=504)
    check("504 본문 backend_timeout, 약 1s 만에 응답", r.json() == {"error": "backend_timeout"}
          and 0.9 < took.get("s", 99) < 2.5, (r, took))

    print("[11] 응답 프레이밍 중계")
    r, _ = one_request("chunked 응답 (/iface/vizanti/slam)", lambda: api_req("GET", "/api/nif/iface/vizanti/slam", tok_full))
    check("chunked 통과 + 디코드 결과 일치", r.headers.get("transfer-encoding") == "chunked"
          and r.body == b"".join(SLAM_PARTS), r)
    r, _ = one_request("1MiB chunked (/package/download)", lambda: api_req("GET", "/api/pkg/package/download", tok_full))
    check("1MiB chunked 바이트 정확", r.body == BLOB_CHUNKED, (len(r.body), r.note))
    r, _ = one_request("EOF 구분 응답 (/package/manifest)", lambda: api_req("GET", "/api/pkg/package/manifest", tok_full))
    check("EOF 응답: CL/TE 없이 전체 전달", r.body == BLOB_EOF and "content-length" not in r.headers
          and "transfer-encoding" not in r.headers, (len(r.body), r.note))
    r, _ = one_request("3MiB Content-Length 응답 (/package/raw/image)",
                       lambda: api_req("GET", "/api/pkg/package/raw/image?type=raw", tok_full))
    check("3MiB CL 바이트 정확", r.body == BLOB_CL and r.headers.get("content-length") == str(len(BLOB_CL)),
          (len(r.body), r.note))

    print("[12] 대용량 본문: 64MiB 사진 상한, 스풀, 메모리 상한 (GW1)")
    pid1 = procs["gw1"].pid
    entries0 = sorted(os.listdir(DATA))
    big = multipart_of_size(PHOTO_CAP)
    sha_big = hashlib.sha256(big).hexdigest()
    mp_type = "multipart/form-data; boundary=XyZ"
    none_reach("사진 64MiB+1 -> 413 (백엔드 미접촉)",
               lambda: send_raw(body_head(PHOTO, tok_full, PHOTO_CAP + 1, mp_type) + big[:1000]), 413)
    mark = be.mark()
    s = connect(timeout=10)
    s.sendall(body_head(PHOTO, tok_full, PHOTO_CAP, mp_type) + big[:2 * MIB])
    spooling = wait_until(lambda: spool_fds(pid1) == 1)
    s.close()
    cleaned = wait_until(lambda: spool_fds(pid1) == 0)
    time.sleep(0.2)
    check("사진 업로드 도중 클라이언트 종료 (스풀 중) -> 백엔드 미접촉, 스풀 fd 해제, 데이터 디렉터리에 파일 없음",
          spooling and cleaned and not be.since(mark) and sorted(os.listdir(DATA)) == entries0,
          (spooling, cleaned, spool_fds(pid1), len(be.since_nowait(mark))))
    rss0 = proc_status(pid1, "VmRSS")
    reset = reset_hwm(pid1)
    hwm0 = proc_status(pid1, "VmHWM")   # == RSS at the reset
    watch = ProcWatch(pid1)
    watch.start()
    t0 = time.time()
    r, req = one_request("사진 정확히 64MiB (multipart PNG) -> 200 (경계), 백엔드는 완전한 요청 1건",
                         lambda: send_body(PHOTO, tok_full, big, mp_type))
    took = time.time() - t0
    watch.stop()
    hwm = proc_status(pid1, "VmHWM")
    if reset and hwm and hwm0:
        growth, how = hwm - hwm0, "VmHWM after clear_refs"
    else:
        growth, how = watch.max_rss - rss0, "sampled VmRSS, clear_refs unavailable"
    print("  info  64MiB 업로드 %.1fs, 게이트웨이 RSS %.1f MiB, 업로드 중 최대 증가 %.1f MiB (%s)"
          % (took, rss0 / MIB, growth / MIB, how))
    check("64MiB 바이트 정확성 (백엔드가 받은 본문 sha256 = 원본, 응답 에코 일치)",
          req is not None and hashlib.sha256(req["body"]).hexdigest() == sha_big
          and r.json().get("sha256") == sha_big and r.json().get("len") == PHOTO_CAP, r)
    check("64MiB 는 스풀 경유 (업로드 중 데이터 디렉터리 fd 정확히 1개 관찰)", watch.max_spool == 1, watch.max_spool)
    check("64MiB 업로드 중 게이트웨이 최대 RSS 증가 < 16MiB (메모리에 모으면 >= 128MiB)",
          growth < 16 * MIB, "%.1f MiB (%s)" % (growth / MIB, how))
    check("업로드 후 스풀 fd 0, 데이터 디렉터리 항목 그대로",
          wait_until(lambda: spool_fds(pid1) == 0) and sorted(os.listdir(DATA)) == entries0,
          (spool_fds(pid1), sorted(set(os.listdir(DATA)) ^ set(entries0))))
    mark = be.mark()
    holders = []
    for _ in range(2):
        s = connect(timeout=10)
        s.sendall(body_head(PHOTO, tok_full, 2 * MIB, mp_type) + big[:MIB + 1])
        holders.append(s)
    receiving = wait_until(lambda: spool_fds(pid1) == 2)
    r = api_req("GET", "/api/pkg/package/floor", tok_full)
    for s in holders:
        s.close()
    freed = wait_until(lambda: spool_fds(pid1) == 0)
    time.sleep(0.1)
    check("본문 수신 중인 업로드 2건이 pkg 슬롯 2개 점유 -> 3번째 503 (슬롯은 본문 읽기 전에 획득), 끊으면 해제",
          receiving and r.status == 503 and freed and not be.since(mark), (receiving, r, freed, len(be.since_nowait(mark))))
    check("GW1: 도중 종료·413·64MiB 뒤 pkg 슬롯 2개 모두 반환 (3번째 503)", *pkg_slots_free(P_GW1, tok_full))

    print("[13] 본문 마감시간 / 디스크 오류 / 백엔드 전송 중단 (GW3, GW2)")
    pid3 = procs["gw3"].pid
    t3 = token_of(full, port=P_GW3)
    mark = be.mark()
    s = connect(port=P_GW3, timeout=10)
    s.sendall(body_head(PHOTO, t3, 2 * MIB) + big[:MIB + MIB // 2])
    t0 = time.time()
    r = read_response(s)
    took = time.time() - t0
    s.close()
    time.sleep(0.05)
    check("GW3: 1.5MiB 보낸 뒤 멈춤 -> 무응답 1s 에 408 body_timeout (상한 3s 전), 백엔드 미접촉",
          r.status == 408 and r.json() == {"error": "body_timeout"} and 0.7 < took < 2.5 and not be.since(mark),
          (r, round(took, 2)))
    check("GW3: 408 후 스풀 fd 0", wait_until(lambda: spool_fds(pid3) == 0), spool_fds(pid3))
    mark = be.mark()
    s = connect(port=P_GW3, timeout=10)
    s.sendall(body_head(PHOTO, t3, 2 * MIB))
    t0 = time.time()
    sent, early = 0, None
    while early is None and time.time() - t0 < 8:   # ~128 KiB/s, never idle: only the deadline stops it
        step = time.time()
        try:
            s.sendall(b"y" * 32768)
            sent += 32768
        except (ConnectionError, ssl.SSLError, OSError):
            break
        while early is None and time.time() - step < 0.25:
            early = poll_response(s, 0.25 - (time.time() - step))
    r = read_response(s, early or b"")
    took = time.time() - t0
    s.close()
    time.sleep(0.05)
    check("GW3: 끊김 없이 느리게(~128KiB/s) 보내는 2MiB -> 본문 상한 3s 에 408, 백엔드 미접촉",
          r.status == 408 and r.json() == {"error": "body_timeout"} and 2.7 < took < 4.5 and sent < 2 * MIB
          and not be.since(mark), (r, round(took, 2), sent))
    check("GW3: 408 후 스풀 fd 0", wait_until(lambda: spool_fds(pid3) == 0), spool_fds(pid3))
    r = none_reach("GW3: 64MiB 사진, 스풀이 4MiB 에서 EFBIG(디스크 가득 참 모사) -> 507 (백엔드 미접촉)",
                   lambda: send_body(PHOTO, t3, big, mp_type, port=P_GW3), 507)
    check("507 본문 {error: insufficient_storage} (JSON)", r.json() == {"error": "insufficient_storage"}
          and r.headers.get("content-type", "").startswith("application/json"), r)
    check("GW3: 507 후 스풀 fd 0, 게이트웨이 계속 동작 (/gw/info 200)",
          wait_until(lambda: spool_fds(pid3) == 0) and gw_get("/gw/info", port=P_GW3).status == 200, spool_fds(pid3))
    # the last 100 bytes arrive on their own and sit in the file's userspace buffer: the limit is only
    # crossed by the final flush, which must happen before the backend is contacted (ApiBody.finish)
    mark = be.mark()
    s = connect(port=P_GW3, timeout=10)
    s.sendall(body_head("/api/pkg/package/upload", t3, GW3_FSIZE + 100) + big[:GW3_FSIZE])
    time.sleep(0.3)
    s.sendall(big[GW3_FSIZE:GW3_FSIZE + 100])
    r = read_response(s)
    s.close()
    time.sleep(0.05)
    check("GW3: 4MiB+100 (꼬리 100B 는 버퍼에서 마지막 flush 때 한도 초과) -> 백엔드 접촉 전에 507",
          r.status == 507 and r.json() == {"error": "insufficient_storage"} and not be.since(mark),
          (r, len(be.since_nowait(mark))))
    blob3 = os.urandom(3 * MIB)
    r, _ = one_request("GW3: 한도 아래 3MiB 스풀 업로드는 정상 -> 200",
                       lambda: send_body("/api/pkg/package/upload", t3, blob3, port=P_GW3))
    check("GW3: 3MiB 바이트 정확성", r.json().get("sha256") == hashlib.sha256(blob3).hexdigest(), r)
    check("GW3: 408·408·507·507 뒤 pkg 슬롯 2개 모두 반환 (3번째 503)", *pkg_slots_free(P_GW3, t3))
    check("GW3: 데이터 디렉터리 항목 그대로 (스풀 파일 이름 없음)", sorted(os.listdir(DATA)) == entries0,
          sorted(set(os.listdir(DATA)) ^ set(entries0)))
    # the backend stops reading mid-body: GW2's route deadline (1 s) fires while the spool is being
    # streamed -> 504, and the backend connection is reset, never half-closed: the backend's read fails
    # with ConnectionResetError, not IncompleteReadError (FIN), so a short body can't pass for complete
    mark = be.mark()
    t2 = token_of(full, port=P_GW2)
    r = send_body("/api/pkg/package/slowread", t2, big, port=P_GW2)
    new = be.since(mark)
    err = new[0].get("error", "") if len(new) == 1 else ""
    check("GW2: 백엔드가 본문을 안 읽음 -> 경로 타임아웃 1s 에 504, 백엔드 연결은 RST (불완전 요청이 완전으로 보일 수 없음)",
          r.status == 504 and r.json() == {"error": "backend_timeout"} and len(new) == 1
          and err.startswith("ConnectionResetError") and b"Content-Length: %d" % PHOTO_CAP in new[0]["raw"],
          (r, len(new), err[:80]))

    print("[13b] 백엔드로 전달 중 끊김 (janitor 폐기, 게이트웨이 SIGTERM/SIGKILL) / 본문 전달 직후 스풀 해제")

    def background(fn):
        res = {}
        th = threading.Thread(target=lambda: res.update(r=fn()))
        th.daemon = True
        th.start()
        return th, res

    def backend_rec(mark):
        """The one backend connection opened after `mark`, once it showed up ({"done": True} if none)."""
        wait_until(lambda: be.since_nowait(mark), 10)
        new = be.since_nowait(mark)
        return new[0] if len(new) == 1 else {"done": True, "none": len(new)}

    held0, body3 = be.pkg.held, os.urandom(3 * MIB)
    th, res = background(lambda: send_body("/api/pkg/package/upload?hold=1", tok_full, body3))
    holding = wait_until(lambda: be.pkg.held > held0, 10)
    freed = wait_until(lambda: spool_fds(pid1) == 0, 2)
    waiting = th.is_alive()
    be.release(be.pkg)
    th.join(30)
    be.rearm(be.pkg)
    r = res.get("r")
    check("백엔드가 본문을 다 받고 응답을 붙잡는 동안 게이트웨이 스풀 fd 는 이미 0 (응답 중계까지 안 기다림), 이후 200",
          holding and freed and waiting and r is not None and r.status == 200
          and r.json().get("sha256") == hashlib.sha256(body3).hexdigest(), (holding, freed, waiting, r))

    body16 = big[:16 * MIB]
    cut = pair("cutoff", "package", "127.0.0.19")
    pid2 = procs["gw2"].pid
    tc = token_of(cut, port=P_GW2)
    mark = be.mark()
    th, res = background(lambda: send_body("/api/pkg/package/trickle", tc, body16, port=P_GW2))
    rec = backend_rec(mark)
    midway = wait_until(lambda: rec.get("got", 0) > MIB, 10)
    gw_cli("revoke", "cutoff")      # GW2's janitor (1 s) finds the in-flight request
    ended = wait_until(lambda: rec["done"], 30)
    th.join(30)
    err, r = rec.get("error", ""), res.get("r")
    check("GW2: 백엔드로 본문 전달 중 클라이언트 폐기 -> janitor 가 끊음: 백엔드는 RST (ConnectionResetError, 잘린 본문 + FIN"
          " 아님), 클라이언트는 응답 없이 끊김",
          midway and ended and err.startswith("ConnectionResetError") and rec.get("got", 0) < len(body16)
          and r is not None and r.status is None, (midway, ended, err[:80], rec.get("got"), r))
    check("GW2: janitor 차단 후 스풀 fd 0", wait_until(lambda: spool_fds(pid2) == 0), spool_fds(pid2))
    # a genuinely broken pkg backend right after the severance: its warning must still be logged ([15]). The
    # global 1 s per-event throttle has passed by then; a severance logged as a backend failure would hold
    # pkg's 60 s per-key slot and suppress it
    time.sleep(1.1)
    r = api_req("POST", "/api/pkg/package/badclose", token_of(full, port=P_GW2), body=b"x" * 100, port=P_GW2)
    check("GW2: janitor 차단 직후 실제 백엔드 장애 (본문 받고 응답 없이 끊음) -> 502 bad_backend_response",
          r.status == 502 and r.json() == {"error": "bad_backend_response"}, r)

    # systemd stop (SIGTERM, no handler: default action) and OOM kill (SIGKILL) while GW4 streams a body:
    # the kernel closes the backend socket, and with SO_LINGER 0 that close is a RST as well
    for signame in ("SIGTERM", "SIGKILL"):
        sig = getattr(signal, signame)
        gw4 = procs["spawn_gw4"]()
        t4 = token_of(full, port=P_GW4)
        if sig == signal.SIGTERM:
            body5 = os.urandom(5 * MIB)
            r, _ = one_request("GW4: 같은 느린 경로로 5MiB 끝까지 전달 -> 200, 백엔드 연결은 정상 종료 (FIN, RST 아님)",
                               lambda: send_body("/api/pkg/package/trickle", t4, body5, port=P_GW4))
            check("GW4: 5MiB 바이트 정확성", r.json().get("sha256") == hashlib.sha256(body5).hexdigest(), r)
        mark = be.mark()
        th, res = background(lambda: send_body("/api/pkg/package/trickle", t4, body16, port=P_GW4))
        rec = backend_rec(mark)
        midway = wait_until(lambda: rec.get("got", 0) > MIB, 10)
        gw4.send_signal(sig)        # this test's own child, by its Popen handle
        try:
            rc = gw4.wait(5)
        except subprocess.TimeoutExpired:
            rc = None
        ended = wait_until(lambda: rec["done"], 30)
        th.join(30)
        err = rec.get("error", "")
        if midway and rc == -sig and ended and not err and rec.get("got") == len(body16):
            # the kernel had taken the whole body before the signal (linger off again by then): a FIN after the
            # complete request is correct, the RST case was just not reached on this host. A partial body + FIN
            # still fails below
            skipped.append("GW4 " + signame)
            print("  SKIP  GW4: %s 전에 본문 전체가 커널 버퍼에 들어가 RST 시나리오 미도달 (백엔드 %dB + FIN, %s)"
                  % (signame, rec["got"], tcp_buffer_sysctls()))
            continue
        check("GW4: 백엔드로 본문 전달 중 게이트웨이 %s -> 백엔드는 RST (ConnectionResetError, 잘린 본문 + FIN 아님)" % signame,
              midway and rc == -sig and ended and err.startswith("ConnectionResetError")
              and rec.get("got", 0) < len(body16), (midway, rc, ended, err[:80], rec.get("got")))

    print("[14] 폐기 / 백엔드 다운")
    tv = token_of(victim)
    one_request("victim 토큰 정상", lambda: api_req("GET", "/api/nif/uid", tv))
    gw_cli("revoke", "victim")
    none_reach("revoke 직후 (janitor 대기 없이) 토큰 거부 -> 401", lambda: api_req("GET", "/api/nif/uid", tv), 401)
    nonce, _ = challenge(victim)
    check("revoke 후 챌린지 불가", nonce == "")
    be.stop(be.pkg)
    r = api_req("GET", "/api/pkg/package/manifest", tok_full)
    check("pkg 백엔드 다운 -> 502 backend_unavailable", r.status == 502 and r.json() == {"error": "backend_unavailable"}, r)
    check("백엔드 다운 중에도 nif 정상", api_req("GET", "/api/nif/uid", tok_full).status == 200)


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA, ignore_errors=True)
