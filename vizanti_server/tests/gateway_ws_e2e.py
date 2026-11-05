#!/usr/bin/env python3
"""게이트웨이 경유 실제 WebSocket(RFC 6455) 종단 테스트 — TLS 모드.

gateway_selftest.py 의 가짜 백엔드와 달리, 독립 구현체(`websockets` 라이브러리)로
진짜 WS 서버(rosbridge 대역)와 진짜 wss:// 클라이언트를 써서 검증한다:
  - TLS 종단 + 업그레이드 스플라이스 후 101 핸드셰이크(Sec-WebSocket-Accept) 성립
  - 양방향 프레임 왕복 (rosbridge 식 JSON op 메시지, 대용량 프레임 포함)
  - 쿠키 없는 wss:// 접속 거부
  - 폐기(revoke) 시 진행 중인 WS 세션이 절단됨

의존: pip install websockets (로봇/운영에는 불필요 — 테스트 전용)
실행: python3 tests/gateway_ws_e2e.py
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import websockets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
GW = os.path.join(HERE, "..", "scripts", "vizanti_gateway.py")
P_GW, P_FLASK, P_WS = 15850, 15852, 15853
ORIGIN = f"https://127.0.0.1:{P_GW}"

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE  # self-signed robot cert; the editor pins it instead

passed, failed = [], []


def check(name, cond, detail=""):
    (passed if cond else failed).append(name)
    print(("  PASS  " if cond else "  FAIL  ") + name + (f" - {detail}" if detail and not cond else ""))


def http(method, path, obj=None, cookie=None):
    req = urllib.request.Request(f"https://127.0.0.1:{P_GW}{path}", method=method)
    data = None
    if obj is not None:
        data = json.dumps(obj).encode()
        req.add_header("Content-Type", "application/json")
    if cookie:
        req.add_header("Cookie", cookie)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX), NoRedirect)
    try:
        r = opener.open(req, data, timeout=5)
        return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


async def rosbridge_standin(ws):
    """rosbridge 대역: op 기반 JSON 을 받아 응답 (call_service -> service_response)."""
    try:
        async for raw in ws:
            msg = json.loads(raw)
            if msg.get("op") == "call_service":
                await ws.send(json.dumps({"op": "service_response", "id": msg.get("id"),
                                          "service": msg["service"], "result": True,
                                          "values": {"echo": msg.get("args")}}))
            elif msg.get("op") == "big":
                await ws.send("x" * msg["n"])
    except websockets.exceptions.ConnectionClosed:
        pass  # the gateway severed the spliced connection (revoke) - expected


async def main():
    data_dir = tempfile.mkdtemp(prefix="vgw_ws_")
    uid_file = os.path.join(data_dir, "robot_uid")
    with open(uid_file, "w") as f:
        f.write("e2e-robot\n")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-keyout", os.path.join(data_dir, "tls_key.pem"), "-out", os.path.join(data_dir, "tls_cert.pem"),
                    "-days", "1", "-nodes", "-subj", "/CN=e2e"], check=True, capture_output=True)

    ws_server = await websockets.serve(rosbridge_standin, "127.0.0.1", P_WS, max_size=None)
    gw = subprocess.Popen([sys.executable, GW, "serve", "--auth-mode", "legacy", "--listen-port", str(P_GW),
                           "--flask-port", str(P_FLASK), "--ws-port", str(P_WS),
                           "--data-dir", data_dir, "--robot-uid-file", uid_file, "--janitor-period", "1"],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = ""
    try:
        for _ in range(50):
            await asyncio.sleep(0.1)
            try:
                if http("GET", "/gw/info")[0] == 200:
                    break
            except OSError:
                pass

        # pair + login (same protocol the editor client implements)
        priv = Ed25519PrivateKey.generate()
        pub = base64.b64encode(priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        subprocess.run([sys.executable, GW, "newcode", "--auth-mode", "legacy", "--data-dir", data_dir], capture_output=True)
        with open(os.path.join(data_dir, "pairing_code")) as f:
            code = f.read().strip()
        with open(os.path.join(data_dir, "tls_cert.pem")) as f:
            fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).hexdigest()
        proof = hmac.new(code.encode(), b"vizanti-gw-pair-v1|" + fp.encode() + b"|" + pub.encode() + b"|e2e",
                         hashlib.sha256).hexdigest()
        _, _, b = http("POST", "/gw/pair", {"client_name": "e2e", "pubkey": pub, "proof": proof})
        cid = json.loads(b)["client_id"]
        _, _, b = http("POST", "/gw/challenge", {"client_id": cid})
        nonce = json.loads(b)["nonce"]
        assert json.loads(b)["cert_fingerprint"] == fp
        sig = base64.b64encode(priv.sign(b"vizanti-gw-v2|" + fp.encode() + b"|" + cid.encode() + b"|" + nonce.encode())).decode()
        _, _, b = http("POST", "/gw/session", {"client_id": cid, "nonce": nonce, "sig": sig})
        ott = json.loads(b)["ott"]
        st, hdrs, _ = http("GET", f"/gw/sso?ott={ott}")
        cookie = hdrs.get("Set-Cookie", "").split(";")[0]
        check("로그인 -> 쿠키", st == 302 and cookie.startswith("vizanti_gw="), (st, hdrs))

        url = f"wss://127.0.0.1:{P_GW}/"

        print("[1] 실제 WS 핸드셰이크 + 프레임 왕복 (wss -> gateway TLS 종단 -> ws 백엔드)")
        async with websockets.connect(url, ssl=CTX, origin=ORIGIN,
                                      additional_headers={"Cookie": cookie}, max_size=None) as ws:
            check("101 업그레이드 성립 (Sec-WebSocket-Accept 검증 통과)", ws.response.status_code == 101)
            await ws.send(json.dumps({"op": "call_service", "id": "c1",
                                      "service": "/vizanti/list_packages", "args": {"q": 1}}))
            resp = json.loads(await asyncio.wait_for(ws.recv(), 3))
            check("rosbridge 식 call_service 왕복", resp.get("op") == "service_response"
                  and resp.get("id") == "c1" and resp["values"]["echo"] == {"q": 1}, resp)
            await ws.send(json.dumps({"op": "big", "n": 3_000_000}))
            big = await asyncio.wait_for(ws.recv(), 10)
            check("3MB 단일 프레임(맵 데이터 규모) 무손실 중계", len(big) == 3_000_000, len(big))

        print("[2] 비인가 wss 차단")
        try:
            async with websockets.connect(url, ssl=CTX, origin=ORIGIN) as ws:
                check("쿠키 없는 wss -> 거부", False, "connected")
        except websockets.exceptions.InvalidStatus as e:
            check("쿠키 없는 wss -> 401 거부", e.response.status_code == 401, e.response.status_code)

        print("[3] 진행 중 WS 세션의 폐기 절단")
        ws = await websockets.connect(url, ssl=CTX, origin=ORIGIN,
                                      additional_headers={"Cookie": cookie})
        await ws.send(json.dumps({"op": "call_service", "id": "c2", "service": "/x", "args": {}}))
        await asyncio.wait_for(ws.recv(), 3)
        subprocess.run([sys.executable, GW, "revoke", "e2e", "--auth-mode", "legacy", "--data-dir", data_dir], capture_output=True)
        t0 = time.time()
        try:
            await asyncio.wait_for(ws.recv(), 6)
            severed = False
        except websockets.exceptions.ConnectionClosed:
            severed = True
        except asyncio.TimeoutError:
            severed = False
        check(f"revoke 후 진행 중 WS 절단 ({time.time() - t0:.1f}s)", severed)
        try:
            await ws.close()
        except websockets.exceptions.ConnectionClosed:
            pass  # already severed by the gateway - expected
    finally:
        gw.terminate()
        try:
            out = gw.communicate(timeout=3)[0]
        except subprocess.TimeoutExpired:
            gw.kill()
        ws_server.close()
        shutil.rmtree(data_dir, ignore_errors=True)

    print(f"\n==> {len(passed)} passed, {len(failed)} failed")
    if failed:
        print("\n".join(out.splitlines()[-20:]))
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
