#!/usr/bin/env python3
"""Bounded, local regressions for HTTP syntax and accepted-socket ownership."""
import argparse
import asyncio
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "admission_gateway", Path(__file__).parents[1] / "scripts/vizanti_gateway.py")
g = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(g)


class Socket:
    def __init__(self):
        self.closes = 0

    def setsockopt(self, *_args):
        pass

    def setblocking(self, _value):
        pass

    def close(self):
        self.closes += 1


class Transport:
    def __init__(self):
        self.aborts = 0

    def abort(self):
        self.aborts += 1


class Writer:
    def __init__(self):
        self.data = b""

    def write(self, data):
        self.data += data


class ChunkReader:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    async def read(self, _size):
        return self.chunks.pop(0) if self.chunks else b""


class HTTPAdmissionTests(unittest.IsolatedAsyncioTestCase):
    def test_common_syntax_rejected_on_public_and_protected_targets(self):
        for path in (b"/gw/info", b"/api/nif/uid", b"/", b"/gw/enroll/confirm"):
            good = b"GET " + path + b" HTTP/1.1\r\nHost: robot\r\n"
            cases = (
                b"GET " + path + b" HTTP/9.9\r\nHost: robot\r\n\r\n",
                b"GET " + path + b" HTTP/1.0\r\nHost: robot\r\n\r\n",
                b"get " + path + b" HTTP/1.1\r\nHost: robot\r\n\r\n",
                b"GET " + path + b" HTTP/1.1\r\n\r\n",
                good + b"Host: other\r\n\r\n",
                good + b"Garbage\r\n\r\n",
                good + b"X: a\nHost: other\r\n\r\n",
                good + b" X: folded\r\n\r\n",
                good + b"X: control\x00\r\n\r\n",
                good + b"X: \xff\r\n\r\n",
                good + b"Content-Length: 0\r\nContent-Length: 0\r\n\r\n",
                good + b"Authorization: a\r\nAuthorization: b\r\n\r\n",
                good + b"Cookie: a\r\nCookie: b\r\n\r\n",
                good + b"Origin: a\r\nOrigin: b\r\n\r\n",
                good + b"Sec-WebSocket-Key: a\r\nSec-WebSocket-Key: b\r\n\r\n",
                good + b"Content-Length: +0\r\n\r\n",
                good + b"Transfer-Encoding: chunked\r\n\r\n",
                b"GET http://robot/gw/info HTTP/1.1\r\nHost: robot\r\n\r\n",
                b"GET //other/gw/info HTTP/1.1\r\nHost: robot\r\n\r\n",
                b"GET /gw/info#fragment HTTP/1.1\r\nHost: robot\r\n\r\n",
            )
            for head in cases:
                with self.subTest(path=path, head=head):
                    with self.assertRaises(g.ApiReject):
                        g.Gateway.parse_head(head)

    def test_host_authority_validation(self):
        for value in ("", "robot,other", "robot@other", "robot:99999", "robot:",
                      "robot/path", "robot?query", "robot name", "[not-ipv6]", "::1"):
            with self.subTest(value=value), self.assertRaises(g.ApiReject):
                g.Gateway.parse_head(("GET /gw/info HTTP/1.1\r\nHost: %s\r\n\r\n" % value).encode())
        for value in ("robot", "robot.local:5000", "192.0.2.1:5000", "[::1]:5000"):
            g.Gateway.parse_head(("GET /gw/info HTTP/1.1\r\nHost: %s\r\n\r\n" % value).encode())

    def test_repeatable_lists_and_websocket_remain_compatible(self):
        head = (b"GET / HTTP/1.1\r\nHost: robot\r\nAccept: text/html\r\nAccept: */*\r\n"
                b"Connection: keep-alive\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
                b"Origin: https://robot\r\nSec-WebSocket-Key: abc\r\n"
                b"Sec-WebSocket-Version: 13\r\n\r\n")
        _, _, headers = g.Gateway.parse_head(head)
        self.assertEqual("text/html, */*", headers["accept"])
        self.assertEqual("keep-alive, Upgrade", headers["connection"])
        self.assertTrue(g.Gateway.origin_ok(headers))
        parsed = g.parse_api_head(head.replace(b"GET / HTTP", b"GET /api/nif/uid HTTP"))
        self.assertEqual("text/html, */*", parsed[4]["accept"])

    async def test_exact_16k_head_is_accepted_for_every_fragment_boundary(self):
        prefix = b"GET /gw/info HTTP/1.1\r\nHost: robot\r\nX-Padding: "
        head = prefix + b"x" * (g.MAX_HEAD_BYTES - len(prefix) - 4) + b"\r\n\r\n"
        for offset in (1, 4096, 16000, 16380):
            with self.subTest(offset=offset):
                actual, rest = await g.Gateway.read_head(ChunkReader([head[:offset], head[offset:]]))
                self.assertEqual(head, actual)
                self.assertEqual(b"", rest)
                g.Gateway.parse_head(actual)

    async def test_16385_head_is_rejected_even_when_terminator_arrives_in_last_chunk(self):
        prefix = b"GET /gw/info HTTP/1.1\r\nHost: robot\r\nX-Padding: "
        head = prefix + b"x" * (g.MAX_HEAD_BYTES + 1 - len(prefix) - 4) + b"\r\n\r\n"
        for offset in (1, 4096, 16000, 16380):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                await g.Gateway.read_head(ChunkReader([head[:offset], head[offset:]]))

    async def test_body_leftover_does_not_count_against_head_limit(self):
        head = b"POST /gw/challenge HTTP/1.1\r\nHost: robot\r\nContent-Length: 2\r\n\r\n"
        actual, rest = await g.Gateway.read_head(ChunkReader([head + b"{}" * 9000]))
        self.assertEqual(head, actual)
        self.assertEqual(18000, len(rest))

    async def test_enrollment_followup_uses_the_same_http_gate(self):
        gw = object.__new__(g.Gateway)
        for suffix in (b"Host: a\r\nHost: b\r\n", b"Garbage\r\n", b"Host: \r\n"):
            with self.subTest(suffix=suffix), self.assertRaises(g.ApiReject):
                await gw.read_enrollment_body(
                    b"POST /gw/enroll/confirm HTTP/1.1\r\n" + suffix + b"Content-Length: 2\r\n\r\n",
                    ChunkReader([]), b"{}", "/gw/enroll/confirm")

    def test_peer_ip_is_canonical_including_uppercase_mapped_ipv6(self):
        self.assertEqual("192.0.2.7", g._norm_ip("::FFFF:c000:207"))
        self.assertEqual("2001:db8::1", g._norm_ip("2001:DB8:0:0::1"))

    def test_authority_rate_metadata_is_bounded_and_mapped_to_public_contract(self):
        gw = object.__new__(g.Gateway)
        for retry in (1, 600):
            writer = Writer()
            gw.auth_reject(writer, {"status": 429, "error": "rate_limited", "retry_after": retry,
                                    "private_state": "must not be copied"})
            head, body = writer.data.split(b"\r\n\r\n", 1)
            self.assertIn(("Retry-After: %d" % retry).encode(), head)
            self.assertEqual({"error": "rate_limited", "retry_after_seconds": retry}, json.loads(body))
        for retry in (0, 601, True, "5", 1.5, "1\r\nInjected: yes"):
            writer = Writer()
            gw.auth_reject(writer, {"status": 429, "error": "rate_limited", "retry_after": retry})
            self.assertNotIn(b"Retry-After", writer.data)
            self.assertNotIn(b"retry_after_seconds", writer.data)


class TLSAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        args = argparse.Namespace(data_dir=self.temp.name, nif_port=1, pkg_port=1,
            auth_mode="nif-device-v1", no_tls=False, robot_uid_file="/nonexistent",
            api_log_period=60, janitor_period=1)
        self.gw = g.Gateway(args)
        self.gw.ssl_ctx = object()
        self.gw.openssl_enabled = False
        self.gw.tls_sem = asyncio.Semaphore(1)
        self.ip = "192.0.2.1"
        self.sock = Socket()
        self.loop = asyncio.get_running_loop()

    async def asyncTearDown(self):
        self.temp.cleanup()

    def counted(self):
        self.gw.live_total = 1
        self.gw.per_ip[self.ip] = 1

    def assert_released(self, slots=1):
        self.assertEqual(0, self.gw.live_total)
        self.assertEqual({}, self.gw.per_ip)
        self.assertEqual(slots, self.gw.tls_sem._value)

    async def test_queued_deadline_does_not_allocate_tls_or_attach_socket(self):
        self.gw.openssl_enabled = True
        self.gw.tls_sem = asyncio.Semaphore(0)
        self.counted()
        with mock.patch.object(g, "OpenSSLBIOTransport") as tls, \
                mock.patch.object(self.loop, "connect_accepted_socket") as attach:
            await self.gw.handle_socket(self.sock, self.ip, g.now() + 0.03)
        tls.assert_not_called()
        attach.assert_not_called()
        self.assertEqual(1, self.sock.closes)
        self.assert_released(slots=0)

    async def test_cancel_while_queued_does_not_release_someone_elses_slot(self):
        self.gw.tls_sem = asyncio.Semaphore(0)
        self.counted()
        task = asyncio.create_task(self.gw.handle_socket(self.sock, self.ip))
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(1, self.sock.closes)
        self.assert_released(slots=0)

    async def test_late_transport_attach_after_timeout_is_aborted_once(self):
        resume = asyncio.Event()
        attached = asyncio.Event()
        transport = Transport()
        tasks = []

        async def connect(factory, _sock, **_kwargs):
            tasks.append(asyncio.current_task())
            protocol = factory()
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                await resume.wait()  # force the ownership race after handler cleanup
            protocol.connection_made(transport)
            attached.set()
            return transport, protocol

        self.counted()
        with mock.patch.object(self.loop, "connect_accepted_socket", connect):
            await self.gw.handle_socket(self.sock, self.ip, g.now() + 0.03)
            self.assert_released()
            resume.set()
            await asyncio.wait_for(attached.wait(), 1)
            await asyncio.gather(*tasks)
            await asyncio.sleep(0)
        self.assertEqual(1, transport.aborts)

    async def test_late_transport_attach_after_cancellation_is_aborted_once(self):
        started = asyncio.Event()
        resume = asyncio.Event()
        transport = Transport()
        tasks = []

        async def connect(factory, _sock, **_kwargs):
            tasks.append(asyncio.current_task())
            protocol = factory()
            started.set()
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                await resume.wait()
            protocol.connection_made(transport)
            return transport, protocol

        self.counted()
        with mock.patch.object(self.loop, "connect_accepted_socket", connect):
            task = asyncio.create_task(self.gw.handle_socket(self.sock, self.ip))
            await started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assert_released()
            resume.set()
            await asyncio.gather(*tasks)
            await asyncio.sleep(0)
        self.assertEqual(1, transport.aborts)

    async def test_slot_wait_and_handshake_share_one_deadline(self):
        self.gw.openssl_enabled = True
        self.gw.tls_sem = asyncio.Semaphore(0)
        created = []
        transport = Transport()

        class TLS(asyncio.Protocol):
            def __init__(inner, _context, _application, loop):
                created.append(g.now())
                inner.ready = loop.create_future()
                inner.raw = None

            def connection_made(inner, raw):
                inner.raw = raw

            def abort(inner):
                inner.ready.cancel()

        async def connect(factory, _sock, **_kwargs):
            protocol = factory()
            protocol.connection_made(transport)
            return transport, protocol

        async def release():
            await asyncio.sleep(0.04)
            self.gw.tls_sem.release()

        self.counted()
        started = g.now()
        releaser = asyncio.create_task(release())
        with mock.patch.object(g, "OpenSSLBIOTransport", TLS), \
                mock.patch.object(self.loop, "connect_accepted_socket", connect):
            await self.gw.handle_socket(self.sock, self.ip, started + 0.08)
        await releaser
        self.assertEqual(1, len(created))
        self.assertGreaterEqual(created[0] - started, 0.035)
        self.assertLess(g.now() - started, 0.14)
        self.assertEqual(1, transport.aborts)
        self.assert_released()

    async def test_accepted_task_cancelled_before_start_releases_socket_and_counters(self):
        calls = 0
        delivered = asyncio.Event()

        async def accept(_listener):
            nonlocal calls
            calls += 1
            if calls == 1:
                return self.sock, (self.ip, 1234)
            delivered.set()
            await asyncio.sleep(60)

        def spawn(coro):
            task = asyncio.create_task(coro)
            task.cancel()
            return task

        with mock.patch.object(self.loop, "sock_accept", accept), mock.patch.object(self.gw, "_spawn", spawn):
            accept_task = asyncio.create_task(self.gw.accept_loop(object()))
            await delivered.wait()
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            accept_task.cancel()
            await asyncio.gather(accept_task, return_exceptions=True)
        self.assertEqual(1, self.sock.closes)
        self.assert_released()

    async def test_second_cancellation_during_writer_close_still_releases_counters(self):
        reading = asyncio.Event()
        closing = asyncio.Event()

        async def connect(factory, _sock, **_kwargs):
            return Transport(), factory()

        async def read_head(_reader):
            reading.set()
            await asyncio.sleep(60)

        class SlowCloseWriter:
            def __init__(inner, transport, *_args):
                inner.transport = transport

            def close(inner):
                closing.set()

            async def wait_closed(inner):
                await asyncio.sleep(60)

        self.counted()
        with mock.patch.object(self.loop, "connect_accepted_socket", connect), \
                mock.patch.object(self.gw, "read_head", read_head), \
                mock.patch.object(g.asyncio, "StreamWriter", SlowCloseWriter):
            task = asyncio.create_task(self.gw.handle_socket(self.sock, self.ip))
            await reading.wait()
            task.cancel()
            await closing.wait()
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assert_released()

    @unittest.skipIf(g.OPENSSL_SSL is None, "pyOpenSSL required")
    async def test_openssl_abort_before_attach_rejects_late_raw_transport(self):
        context = g.OPENSSL_SSL.Context(g.OPENSSL_SSL.TLS_SERVER_METHOD)
        application = mock.Mock()
        tls = g.OpenSSLBIOTransport(context, application, self.loop)
        tls.abort()
        transport = Transport()
        tls.connection_made(transport)
        self.assertEqual(1, transport.aborts)
        self.assertIsNone(tls.raw)
        self.assertTrue(tls.ready.cancelled())
        application.connection_made.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
