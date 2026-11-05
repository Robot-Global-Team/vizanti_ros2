#!/usr/bin/env python3
"""vizanti_gateway 로컬 셀프테스트 (로봇 불필요, pytest 불필요).

가짜 flask/ws 백엔드를 별도 스레드의 이벤트 루프에서 띄우고(클라이언트가 블로킹
소켓을 쓰므로 같은 루프에 두면 교착됨), 게이트웨이를 --no-tls 서브프로세스로 기동해
페어링 -> 챌린지 서명 -> 세션 -> SSO -> 스플라이스와 각종 거부 경로를 검증한다.

실행: python3 tests/gateway_selftest.py          # 평문(--no-tls)
      python3 tests/gateway_selftest.py --tls    # 운영 기본값(TLS)
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import ssl
import threading
import time


class _SigningKey:
    """Ed25519 signing for the TEST CLIENT only (the gateway itself only verifies).
    python3-cryptography >= 2.6 when available, else PyNaCl (2.9.x robots)."""
    def __init__(self):
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            self._k = Ed25519PrivateKey.generate()
            self.pub = self._k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self._sign = self._k.sign
        except ImportError:
            from nacl.signing import SigningKey
            self._k = SigningKey.generate()
            self.pub = bytes(self._k.verify_key)
            self._sign = lambda m: self._k.sign(m).signature

    def sign(self, msg):
        return self._sign(msg)


def Ed25519PrivateKey_generate():
    return _SigningKey()

HERE = os.path.dirname(os.path.abspath(__file__))
GW = os.path.join(HERE, "..", "scripts", "vizanti_gateway.py")
P_GW, P_FLASK, P_WS = 15800, 15802, 15803
JANITOR_S = 1.0
USE_TLS = "--tls" in sys.argv
_TLS_CTX = ssl.create_default_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode = ssl.CERT_NONE  # self-signed robot cert; the editor pins it instead

passed, failed = [], []


def check(name, cond, detail=""):
    (passed if cond else failed).append(name)
    print(("  PASS  " if cond else "  FAIL  ") + name + (f" - {detail}" if detail and not cond else ""))


# ---------- fake backends (own thread + own loop) ----------

class Backends:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.servers = {}
        threading.Thread(target=self.loop.run_forever, daemon=True).start()

    def _run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(5)

    def start(self):
        async def flask(reader, writer):
            await reader.read(4096)
            body = b"flask-echo"
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
            await writer.drain()
            writer.close()

        async def ws(reader, writer):
            # answers the upgrade, then HOLDS the connection open like a real rosbridge session
            await reader.read(4096)
            writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                         b"Connection: Upgrade\r\n\r\nWS-HELLO")
            await writer.drain()
            while await reader.read(4096):
                pass
            writer.close()

        async def go():
            self.servers["flask"] = await asyncio.start_server(flask, "127.0.0.1", P_FLASK)
            self.servers["ws"] = await asyncio.start_server(ws, "127.0.0.1", P_WS)
        self._run(go())

    def stop(self, name):
        async def go():
            srv = self.servers.pop(name)
            srv.close()
            await srv.wait_closed()
        self._run(go())


# ---------- raw HTTP client ----------

def raw(request, timeout=3.0, src="127.0.0.1", until=None, keep=False):
    """Send raw bytes; read until EOF / timeout / marker. keep=True returns the open socket too."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.bind((src, 0))
    s.connect(("127.0.0.1", P_GW))
    if USE_TLS:
        s = _TLS_CTX.wrap_socket(s)
    s.sendall(request)
    out = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
            if until and until in out:
                break
    except socket.timeout:
        out += b"<TIMEOUT>"
    except ConnectionError:
        pass  # gateway aborted the connection (RST) - treated as closed
    if keep:
        return out, s
    s.close()
    return out


def status(resp):
    try:
        return int(resp.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return None


def body_of(resp):
    return resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""


def get(path, cookie=None, extra=b"", src="127.0.0.1"):
    hdr = b"GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n" % (path.encode(), P_GW)
    if cookie:
        hdr += b"Cookie: " + cookie + b"\r\n"
    return raw(hdr + extra + b"\r\n", src=src)


def post(path, obj, src="127.0.0.1"):
    body = json.dumps(obj).encode()
    r = raw(b"POST %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\n"
            b"Content-Length: %d\r\nConnection: close\r\n\r\n%s" % (path.encode(), P_GW, len(body), body),
            src=src)
    try:
        return status(r), json.loads(body_of(r) or b"{}")
    except ValueError:
        return status(r), {}


def ws_upgrade(cookie=None, origin=b"http://127.0.0.1:%d" % P_GW):
    req = b"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" % P_GW
    if cookie:
        req += b"Cookie: " + cookie + b"\r\n"
    if origin:
        req += b"Origin: " + origin + b"\r\n"
    return req + b"\r\n"


def gw_cli(*args, data_dir):
    return subprocess.run([sys.executable, GW, *args, "--auth-mode", "legacy", "--data-dir", data_dir],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)


def robot_fp(data_dir):
    """게이트웨이가 쓰는 인증서 지문 (평문 모드는 '' - 게이트웨이의 cert_fingerprint None 과 동일)."""
    if not USE_TLS:
        return ""
    with open(os.path.join(data_dir, "tls_cert.pem")) as f:
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).hexdigest()


def pair_body(code, name, pub_b64, fp):
    """편집기와 동일한 페어링 증명: 코드는 전송하지 않고 HMAC(code, ctx|fp|pubkey|name) 만 보냄."""
    msg = b"vizanti-gw-pair-v1|" + fp.encode() + b"|" + pub_b64.encode() + b"|" + name.encode()
    return {"client_name": name, "pubkey": pub_b64,
            "proof": hmac.new(code.encode(), msg, hashlib.sha256).hexdigest()}


def sign_v2(priv, fp, client_id, nonce):
    return base64.b64encode(priv.sign(
        b"vizanti-gw-v2|" + fp.encode() + b"|" + client_id.encode() + b"|" + nonce.encode())).decode()


# ---------- the test ----------

def main():
    data_dir = tempfile.mkdtemp(prefix="vgw_test_")
    uid_file = os.path.join(data_dir, "robot_uid")
    with open(uid_file, "w") as f:
        f.write("test-robot-uid-1234\n")

    if USE_TLS:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-keyout", os.path.join(data_dir, "tls_key.pem"),
                        "-out", os.path.join(data_dir, "tls_cert.pem"),
                        "-days", "1", "-nodes", "-subj", "/CN=vizanti-gw-test"],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"mode: {'TLS' if USE_TLS else 'plain (--no-tls)'} | python {sys.version.split()[0]} | "
          f"gateway ed25519 backend: {os.environ.get('VIZANTI_GW_ED25519') or 'auto'}")

    backends = Backends()
    backends.start()

    gw = subprocess.Popen(
        [sys.executable, GW, "serve", "--auth-mode", "legacy", *([] if USE_TLS else ["--no-tls"]), "--listen-port", str(P_GW),
         "--flask-port", str(P_FLASK), "--ws-port", str(P_WS),
         "--data-dir", data_dir, "--robot-uid-file", uid_file,
         "--janitor-period", str(JANITOR_S)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    out = ""
    try:
        for _ in range(100):   # up to 10s: slow robots (Python 3.6) take ~0.4s to start listening
            time.sleep(0.1)
            try:
                if status(get("/gw/info")) == 200:
                    break
            except OSError:
                pass  # not listening yet
            if gw.poll() is not None:
                raise SystemExit("gateway died on startup:\n" + gw.stdout.read())
        else:
            raise SystemExit("gateway did not come up")

        print("[1] 비인가 접근 차단")
        r = get("/")
        check("무쿠키 HTTP -> 401 안내 페이지", status(r) == 401 and "접근 권한" in body_of(r).decode(), status(r))
        check("무쿠키 /ros_launch_params -> 401", status(get("/ros_launch_params")) == 401)
        check("무쿠키 WS 업그레이드 -> 401", status(raw(ws_upgrade())) == 401)
        r = get("/gw/info")
        info = json.loads(body_of(r))
        check("/gw/info 에 robot_uid 미노출", status(r) == 200 and "robot_uid" not in info, info)
        check("/gw/info 에 api=1, api_services=[nif,pkg] (클라이언트의 로봇 API 지원 판단)",
              info.get("api") == 1 and info.get("api_services") == ["nif", "pkg"], info)
        r = get("/api/nif/uid")
        check("무토큰 /api -> 401 JSON + WWW-Authenticate: Bearer (상세: tests/gateway_api_test.py)",
              status(r) == 401 and b"\r\nWWW-Authenticate: Bearer\r\n" in r
              and json.loads(body_of(r) or b"{}") == {"error": "unauthorized"}, r[:120])

        print("[2] 페어링")
        priv = Ed25519PrivateKey_generate()
        pub_b64 = base64.b64encode(priv.pub).decode()
        fp = robot_fp(data_dir)
        st, _ = post("/gw/pair", pair_body("wrong", "pc1", pub_b64, fp))
        check("발급 전/잘못된 페어링 코드 -> 403", st == 403, st)
        out_nc = gw_cli("newcode", data_dir=data_dir).stdout
        token = [l for l in out_nc.splitlines() if l.startswith("pairing token:")][0].split(":", 1)[1].strip()
        code = open(os.path.join(data_dir, "pairing_code")).read().strip()
        if USE_TLS:
            check("newcode 토큰 = <code>-<지문12> (편집기가 지문 대조)", token == f"{code}-{fp[:12]}", token)
            st, _ = post("/gw/pair", pair_body(code, "pc1", pub_b64, "f" * 64))
            check("다른 인증서 지문으로 만든 증명 -> 403 (중간자 차단)", st == 403, st)
        else:
            check("newcode 토큰 (평문 모드: 지문 없음)", token == code, token)
            st, _ = post("/gw/pair", pair_body(code, "pc1", pub_b64, "f" * 64))
            check("다른 지문으로 만든 증명 -> 403", st == 403, st)
        st, _ = post("/gw/pair", pair_body(code, "bad name!", pub_b64, fp))
        check("잘못된 client_name -> 400", st == 400, st)
        st, _ = post("/gw/pair", pair_body(code, "pc1", "bm90YWtleQ==", fp))
        check("잘못된 공개키 -> 400", st == 400, st)
        st, j = post("/gw/pair", pair_body(code, "pc1", pub_b64, fp))
        check("정상 페어링(증명) -> client_id", st == 200 and "client_id" in j, (st, j))
        check("기본 newcode 로 페어링 -> perms 4개 전부", j.get("perms") == ["ui", "read", "drive", "package"], j)
        client_id = j.get("client_id", "")
        check("페어링 코드 1회용 소모", not os.path.exists(os.path.join(data_dir, "pairing_code")))
        st, _ = post("/gw/pair", pair_body(code, "pc2", pub_b64, fp), src="127.0.0.2")
        check("소모된 코드 재사용(다른 IP) -> 403", st == 403, st)

        print("[3] 챌린지 / 서명 / 세션")
        st, _ = post("/gw/challenge", {"client_id": "nope"})
        check("미등록 client 챌린지 -> 403", st == 403, st)
        st, j = post("/gw/challenge", {"client_id": client_id})
        nonce = j.get("nonce", "")
        check("챌린지 발급", st == 200 and nonce)
        bad_sig = base64.b64encode(b"x" * 64).decode()
        st, _ = post("/gw/session", {"client_id": client_id, "nonce": nonce, "sig": bad_sig})
        check("위조 서명 -> 403", st == 403, st)
        good_sig_for_used_nonce = sign_v2(priv, fp, client_id, nonce)
        st, _ = post("/gw/session", {"client_id": client_id, "nonce": nonce, "sig": good_sig_for_used_nonce})
        check("실패로 소모된 nonce 는 정상 서명으로도 재사용 불가", st == 403, st)

        def login(cid=None, src="127.0.0.1"):
            cid = cid or client_id
            _, jj = post("/gw/challenge", {"client_id": cid}, src=src)
            n = jj["nonce"]
            check_fp = jj.get("cert_fingerprint") or ""
            sig = sign_v2(priv, check_fp, cid, n)
            return post("/gw/session", {"client_id": cid, "nonce": n, "sig": sig, "alg": "none"}, src=src)

        _, jj = post("/gw/challenge", {"client_id": client_id})
        check("챌린지 응답이 인증서 지문을 알림", (jj.get("cert_fingerprint") or "") == fp, jj)
        old_sig = base64.b64encode(priv.sign(b"vizanti-gw-v1|" + client_id.encode() + b"|" + jj["nonce"].encode())).decode()
        st, _ = post("/gw/session", {"client_id": client_id, "nonce": jj["nonce"], "sig": old_sig})
        check("구 v1 포맷 서명(지문 미포함) -> 403", st == 403, st)

        st, j = login()
        check("정상 서명 -> OTT + robot_uid (클라이언트 alg 필드 무시)",
              st == 200 and j.get("robot_uid") == "test-robot-uid-1234", (st, j))
        ott = j.get("ott", "")

        print("[4] SSO / 쿠키")
        r = get(f"/gw/sso?ott={ott}", src="127.0.0.2")
        check("다른 IP 에서 OTT 사용 -> 403", status(r) == 403, status(r))
        st, j = login()
        ott = j["ott"]
        r = get(f"/gw/sso?ott={ott}")
        set_cookie = [l for l in r.split(b"\r\n") if l.lower().startswith(b"set-cookie:")]
        cookie = set_cookie[0].split(b":", 1)[1].strip().split(b";")[0] if set_cookie else b""
        check("SSO -> 302 + HttpOnly/SameSite 쿠키",
              status(r) == 302 and cookie.startswith(b"vizanti_gw=")
              and b"HttpOnly" in set_cookie[0] and b"SameSite=Strict" in set_cookie[0], r[:200])
        check("OTT 재사용 -> 403", status(get(f"/gw/sso?ott={ott}")) == 403)
        if USE_TLS:
            check("TLS: 쿠키에 Secure 플래그", b"Secure" in set_cookie[0], set_cookie[0])
            import hashlib
            der = ssl.PEM_cert_to_DER_cert(open(os.path.join(data_dir, "tls_cert.pem")).read())
            check("TLS: /gw/info 인증서 지문 = 실제 인증서",
                  info.get("cert_fingerprint") == hashlib.sha256(der).hexdigest(), info)

        print("[5] 스플라이스")
        r = get("/", cookie=cookie)
        check("쿠키 HTTP -> flask 백엔드 도달", status(r) == 200 and body_of(r) == b"flask-echo", r[-60:])
        r = get("/", cookie=cookie, src="127.0.0.2")
        check("쿠키를 다른 IP 에서 재사용 -> 401", status(r) == 401, status(r))
        r = get("/api/nif/uid", cookie=cookie)
        check("UI 쿠키는 /api 에 무효 (쿠키 무시, Bearer 필요) -> 401", status(r) == 401, status(r))
        r = raw(ws_upgrade(cookie), until=b"WS-HELLO")
        check("쿠키+Origin 일치 WS -> rosbridge 백엔드 도달(101)", status(r) == 101 and b"WS-HELLO" in r, r[:80])
        check("Origin 불일치 WS -> 403", status(raw(ws_upgrade(cookie, b"http://evil.example"))) == 403)
        check("Origin 부재 WS -> 403", status(raw(ws_upgrade(cookie, None))) == 403)

        print("[6] 폐기 시 활성 WS 강제 절단")
        r, live = raw(ws_upgrade(cookie), until=b"WS-HELLO", keep=True)
        check("활성 WS 세션 수립", b"WS-HELLO" in r, r[:80])
        gw_cli("revoke", "pc1", data_dir=data_dir)
        live.settimeout(JANITOR_S * 4 + 2)
        try:
            tail = live.recv(4096)
            severed = tail == b""
        except socket.timeout:
            severed = False
        except ConnectionError:
            severed = True
        live.close()
        check(f"revoke 후 {JANITOR_S * 4 + 2:.0f}s 내 활성 WS 절단", severed)
        check("revoke 후 기존 쿠키 -> 401", status(get("/", cookie=cookie)) == 401)
        st, _ = post("/gw/challenge", {"client_id": client_id})
        check("revoke 후 챌린지 -> 403", st == 403, st)

        print("[6b] 로그아웃 시 활성 WS 절단")
        gw_cli("newcode", data_dir=data_dir)
        code = open(os.path.join(data_dir, "pairing_code")).read().strip()
        st, j = post("/gw/pair", pair_body(code, "pc2", pub_b64, fp), src="127.0.0.2")
        cid2 = j["client_id"]
        _, j = login(cid2, src="127.0.0.2")
        r = get(f"/gw/sso?ott={j['ott']}", src="127.0.0.2")
        cookie2 = [l for l in r.split(b"\r\n") if l.lower().startswith(b"set-cookie:")][0] \
            .split(b":", 1)[1].strip().split(b";")[0]
        r, live = raw(ws_upgrade(cookie2), until=b"WS-HELLO", keep=True, src="127.0.0.2")
        check("활성 WS 세션 수립 (pc2)", b"WS-HELLO" in r, r[:80])
        get("/gw/logout", cookie=cookie2, src="127.0.0.2")
        live.settimeout(JANITOR_S * 4 + 2)
        try:
            severed = live.recv(4096) == b""
        except socket.timeout:
            severed = False
        except ConnectionError:
            severed = True
        live.close()
        check("logout 후 활성 WS 즉시 절단", severed)
        check("logout 후 쿠키 -> 401", status(get("/", cookie=cookie2, src="127.0.0.2")) == 401)

        print("[7] 페어링 레이트리밋")
        gw_cli("newcode", data_dir=data_dir)
        code = open(os.path.join(data_dir, "pairing_code")).read().strip()
        st, _ = post("/gw/pair", pair_body(code, "pc3", pub_b64, fp))
        check("같은 IP 6번째 페어링 시도 -> 429 (5회/10분)", st == 429, st)
        check("레이트리밋으로 거부돼도 페어링 코드는 보존", os.path.exists(os.path.join(data_dir, "pairing_code")))

        print("[8] 백엔드 다운")
        other = "127.0.0.3"
        st, j = post("/gw/pair", pair_body(code, "pc3", pub_b64, fp), src=other)
        check("다른 IP 에서는 정상 페어링", st == 200 and "client_id" in j, (st, j))
        cid3 = j["client_id"]
        _, j = login(cid3, src=other)
        r = get(f"/gw/sso?ott={j['ott']}", src=other)
        cookie = [l for l in r.split(b"\r\n") if l.lower().startswith(b"set-cookie:")][0] \
            .split(b":", 1)[1].strip().split(b";")[0]
        backends.stop("flask")
        r = get("/", cookie=cookie, src=other)
        check("flask 다운 -> 502 안내 페이지 (게이트웨이 생존)",
              status(r) == 502 and "기동되지" in body_of(r).decode(), status(r))
        check("flask 다운 중에도 /gw/info 응답", status(get("/gw/info")) == 200)

        print("[9] 핸드셰이크 DoS 한도")
        s = socket.create_connection(("127.0.0.1", P_GW), timeout=5)
        if USE_TLS:
            s = _TLS_CTX.wrap_socket(s)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")  # never finish the head
        t0 = time.time()
        try:
            dropped = s.recv(1) == b""
        except ConnectionError:
            dropped = True   # transport.abort() -> RST: terminated, which is the point
        except socket.timeout:
            dropped = False
        s.close()
        check("미완성 헤더(slowloris) -> 2s 내 연결 종료", dropped and time.time() - t0 < 4, time.time() - t0)
        big = b"GET / HTTP/1.1\r\nHost: x\r\nX-Pad: " + b"a" * 20000 + b"\r\n\r\n"
        r = raw(big)
        check("16KB 초과 헤더 -> 즉시 종료", r == b"" or status(r) is None, r[:40])

    finally:
        gw.terminate()
        try:
            out = gw.communicate(timeout=3)[0]
        except subprocess.TimeoutExpired:
            gw.kill()
        shutil.rmtree(data_dir, ignore_errors=True)

    print(f"\n==> {len(passed)} passed, {len(failed)} failed")
    if failed:
        print("failed:", failed)
        print("--- gateway log tail ---")
        print("\n".join(out.splitlines()[-20:]))
        sys.exit(1)


if __name__ == "__main__":
    main()
