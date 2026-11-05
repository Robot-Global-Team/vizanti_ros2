#!/usr/bin/env python3
"""Real TLS exporter/connection boundary tests; PAKE is tested by NIF integration."""
import argparse
import asyncio
import base64
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('enrollment_gateway', Path(__file__).parents[1] / 'scripts/vizanti_gateway.py')
g = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(g)


class Client:
    def __init__(self, port, tls12=False):
        ssl = g.OPENSSL_SSL
        ctx = ssl.Context(ssl.TLS_CLIENT_METHOD)
        version = ssl.TLS1_2_VERSION if tls12 else ssl.TLS1_3_VERSION
        ctx.set_min_proto_version(version)
        ctx.set_max_proto_version(version)
        ctx.set_verify(ssl.VERIFY_NONE, lambda *_: True)  # Test-only untrusted bootstrap.
        self.sock = socket.create_connection(('127.0.0.1', port))
        self.sock.setblocking(True)
        self.tls = ssl.Connection(ctx, self.sock)
        self.tls.set_connect_state()
        self.tls.do_handshake()
        self.exporter = self.tls.export_keying_material(g.TLS_EXPORTER_LABEL, 32, b'')
        self.buffer = b''

    def request(self, path, body, extra=''):
        raw = json.dumps(body).encode()
        self.tls.sendall(('POST %s HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\n%s\r\n' %
                          (path, len(raw), extra)).encode() + raw)
        while b'\r\n\r\n' not in self.buffer:
            self.buffer += self.tls.recv(4096)
        head, self.buffer = self.buffer.split(b'\r\n\r\n', 1)
        lines = head.decode().split('\r\n')
        headers = dict(line.lower().split(': ', 1) for line in lines[1:])
        length = int(headers['content-length'])
        while len(self.buffer) < length:
            self.buffer += self.tls.recv(4096)
        value, self.buffer = self.buffer[:length], self.buffer[length:]
        return int(lines[0].split()[1]), headers, json.loads(value)

    def close(self):
        self.sock.close()


@unittest.skipIf(g.OPENSSL_SSL is None, 'pyOpenSSL required')
class EnrollmentTLSTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                        'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
                        '-subj', '/CN=fixture', '-keyout', str(self.root/'tls_key.pem'),
                        '-out', str(self.root/'tls_cert.pem')], check=True, capture_output=True)
        self.calls = []
        self.aborted = asyncio.Event()
        self.reject = False
        self.reject_reply = dict(status=403, error='enrollment_rejected')
        self.ready = True
        self.sock = str(self.root/'auth.sock')
        args = argparse.Namespace(data_dir=self.tmp.name, nif_port=1, pkg_port=1,
            auth_mode='nif-device-v1', nif_auth_socket=self.sock, nif_auth_uid=os.getuid(),
            no_tls=False, robot_uid_file='/nonexistent', api_log_period=60, janitor_period=1)
        self.gw = g.Gateway(args)
        self.gw.ssl_ctx = self.gw.make_ssl_context()
        self.gw.tls_sem = asyncio.Semaphore(16)
        self.authority = await asyncio.start_unix_server(self.rpc, path=self.sock)
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.listener.setblocking(False)
        self.port = self.listener.getsockname()[1]
        self.accept = asyncio.create_task(self.gw.accept_loop(self.listener))

    async def asyncTearDown(self):
        self.accept.cancel()
        self.listener.close()
        await asyncio.gather(self.accept, return_exceptions=True)
        for task in list(self.gw._tasks):
            task.cancel()
        await asyncio.gather(*self.gw._tasks, return_exceptions=True)
        self.authority.close()
        await self.authority.wait_closed()
        self.tmp.cleanup()

    async def rpc(self, reader, writer):
        try:
            value = json.loads(await reader.readline())
            self.calls.append(value)
            if value['op'] == 'pake_abort':
                self.aborted.set()
            result = dict(v=1, ok=not self.reject, instance_id='authority-fixture')
            if self.reject:
                result.update(self.reject_reply)
            elif value['op'] == 'enrollment_capabilities':
                result['enrollment_protocols'] = [g.ENROLLMENT_PROTOCOL] if self.ready else []
            elif value['op'] == 'pake_begin':
                result.update(protocol=g.ENROLLMENT_PROTOCOL, session_id='session', generation_id='generation',
                              auth_instance_id='authority-fixture', perms=['read'], server_message=base64.b64encode(b'b'*32).decode())
            elif value['op'] == 'pake_confirm':
                result['proof'] = 'c'*64
            elif value['op'] in ('pake_commit', 'enrollment_result'):
                result.update(client_id='a'*32, perms=['read'])
            elif value['op'] == 'challenge':
                result.update(nonce='n'*43, ttl=60)
            elif value['op'] in ('api_token', 'session'):
                result.update(token='t'*43, client_id='a'*32, perms=['ui', 'read'], ttl=900)
            elif value['op'] == 'pair':
                result.update(client_id='a'*32, perms=['read'])
            writer.write(json.dumps(result).encode() + b'\n')
            await writer.drain()
        finally:
            writer.close()

    async def run_client(self, function):
        return await asyncio.wait_for(asyncio.to_thread(function), 10)

    async def test_exporter_matches_real_client_and_server_ignores_assertions(self):
        def exchange():
            client = Client(self.port)
            try:
                values = [client.request('/gw/enroll/start', dict(request_id='1'*32, pubkey='key', client_name='pc',
                    tls_exporter='attacker', connection_id='attacker', cert_fingerprint='attacker', peer_ip='attacker'))]
                values.append(client.request('/gw/enroll/confirm', dict(session_id='session', client_message='message', proof='proof')))
                values.append(client.request('/gw/enroll/commit', dict(session_id='session', proof='proof', signature='signature')))
                return client.exporter, values
            finally:
                client.close()
        exporter, responses = await self.run_client(exchange)
        self.assertEqual([200,200,200], [v[0] for v in responses])
        self.assertEqual(['keep-alive','keep-alive','close'], [v[1]['connection'] for v in responses])
        calls = [v for v in self.calls if v['op'].startswith('pake_')]
        self.assertEqual(['pake_begin','pake_confirm','pake_commit'], [v['op'] for v in calls])
        self.assertEqual(1, len({v['connection_id'] for v in calls}))
        for value in calls:
            self.assertEqual(exporter, base64.b64decode(value['tls_exporter']))
            self.assertEqual(self.gw.cert_fingerprint, value['cert_fingerprint'])
            self.assertEqual('127.0.0.1', value['peer_ip'])

    async def test_same_certificate_different_tls_connections_have_different_exporters(self):
        def connect():
            client = Client(self.port)
            value = client.exporter
            client.close()
            return value
        first = await self.run_client(connect)
        second = await self.run_client(connect)
        self.assertEqual(32, len(first))
        self.assertNotEqual(first, second)

    async def test_business_request_cannot_follow_enrollment_start(self):
        def exchange():
            client = Client(self.port)
            try:
                client.request('/gw/enroll/start', dict(request_id='1'*32, pubkey='key', client_name='pc'))
                client.tls.sendall(b'GET /api/nif/nav/info HTTP/1.1\r\nHost: localhost\r\n\r\n')
                try:
                    return client.tls.recv(4096)
                except g.OPENSSL_SSL.Error:
                    return b''
            finally:
                client.close()
        response = await self.run_client(exchange)
        self.assertNotIn(b'200 OK', response)
        self.assertEqual(['pake_begin','pake_abort'], [v['op'] for v in self.calls])

    async def test_tls12_enrollment_rejected_before_authority(self):
        def exchange():
            client = Client(self.port, tls12=True)
            try:
                return client.request('/gw/enroll/start', {})
            finally:
                client.close()
        status, _, body = await self.run_client(exchange)
        self.assertEqual(403, status)
        self.assertEqual('tls13_required', body['error'])
        self.assertEqual([], self.calls)

    async def test_duplicate_content_length_rejected_before_authority(self):
        def exchange():
            client = Client(self.port)
            try:
                return client.request('/gw/enroll/start', {}, 'Content-Length: 2\r\n')
            except g.OPENSSL_SSL.Error:
                return None
            finally:
                client.close()
        await self.run_client(exchange)
        self.assertFalse(any(v['op'] == 'pake_begin' for v in self.calls))

    async def test_authority_rejection_closes_flow(self):
        self.reject = True
        def exchange():
            client = Client(self.port)
            try:
                return client.request('/gw/enroll/start', {})
            finally:
                client.close()
        status, headers, _ = await self.run_client(exchange)
        self.assertEqual(403, status)
        self.assertEqual('close', headers['connection'])
        await asyncio.wait_for(self.aborted.wait(), 1)
        self.assertTrue(any(v['op'] == 'pake_abort' for v in self.calls))

    async def test_capability_requires_native_readiness(self):
        self.assertEqual([g.ENROLLMENT_PROTOCOL], await self.gw.enrollment_protocols())
        self.ready = False
        self.assertEqual([], await self.gw.enrollment_protocols())
        self.gw.openssl_enabled = False
        self.assertEqual([], await self.gw.enrollment_protocols())

    async def test_common_http_validation_precedes_public_route_and_authority(self):
        def exchange(raw):
            client = Client(self.port)
            try:
                client.tls.sendall(raw)
                data = b''
                while b'\r\n\r\n' not in data:
                    data += client.tls.recv(4096)
                return int(data.split(b' ', 2)[1])
            finally:
                client.close()
        for raw in (b'GET /gw/info HTTP/9.9\r\nHost: localhost\r\n\r\n',
                    b'GET /gw/info HTTP/1.1\r\n\r\n',
                    b'GET /gw/info HTTP/1.1\r\nHost: localhost\r\nBroken\r\n\r\n',
                    b'POST /gw/challenge HTTP/1.1\r\nHost: localhost\r\nHost: other\r\nContent-Length: 2\r\n\r\n{}'):
            with self.subTest(raw=raw):
                self.assertEqual(400, await self.run_client(lambda: exchange(raw)))
        self.assertEqual([], self.calls)

    async def test_bad_followup_is_rejected_and_its_pake_session_aborted(self):
        def exchange():
            client = Client(self.port)
            try:
                client.request('/gw/enroll/start', {})
                client.tls.sendall(b'POST /gw/enroll/confirm HTTP/1.1\r\nHost: localhost\r\n'
                                   b'Host: other\r\nContent-Length: 2\r\n\r\n{}')
                return client.tls.recv(4096)
            finally:
                client.close()
        self.assertIn(b'400 Bad Request', await self.run_client(exchange))
        self.assertEqual(['pake_begin', 'pake_abort'], [v['op'] for v in self.calls])

    async def test_queued_tls_socket_times_out_then_normal_enrollment_recovers(self):
        self.gw.tls_sem = asyncio.Semaphore(0)
        def wait_for_close():
            sock = socket.create_connection(('127.0.0.1', self.port), timeout=1)
            try:
                try:
                    return sock.recv(1)
                except ConnectionResetError:
                    return b''
            finally:
                sock.close()
        with mock.patch.object(g, 'TLS_HANDSHAKE_TIMEOUT_S', 0.05):
            self.assertEqual(b'', await self.run_client(wait_for_close))
        self.assertEqual(0, self.gw.live_total)
        self.assertEqual({}, self.gw.per_ip)
        self.gw.tls_sem = asyncio.Semaphore(16)
        def enroll():
            client = Client(self.port)
            try:
                statuses = [client.request('/gw/enroll/start', {})[0]]
                statuses.append(client.request('/gw/enroll/confirm', dict(session_id='session'))[0])
                statuses.append(client.request('/gw/enroll/commit', dict(session_id='session'))[0])
                return statuses
            finally:
                client.close()
        self.assertEqual([200, 200, 200], await self.run_client(enroll))

    async def test_rate_and_busy_responses_expose_only_stable_retry_information(self):
        for status, error in ((429, 'rate_limited'), (503, 'auth_busy')):
            self.reject = True
            self.reject_reply = dict(status=status, error=error, retry_after=3, private_state='hidden')
            def exchange():
                client = Client(self.port)
                try:
                    return client.request('/gw/enroll/start', {})
                finally:
                    client.close()
            actual, headers, body = await self.run_client(exchange)
            self.assertEqual(status, actual)
            self.assertEqual('3', headers['retry-after'])
            self.assertEqual(dict(error=error, retry_after_seconds=3), body)

    async def test_login_and_signed_recovery_use_actual_socket_ip(self):
        for path, op in (('/gw/challenge', 'challenge'), ('/gw/api-token', 'api_token'),
                         ('/gw/session', 'session'), ('/gw/pair', 'pair'),
                         ('/gw/enroll/result', 'enrollment_result')):
            def exchange():
                client = Client(self.port)
                try:
                    return client.request(path, dict(peer_ip='192.0.2.99', source_ip='192.0.2.98',
                        client_id='a'*32, pubkey='key', signature='signature', request_id='1'*32),
                        'X-Forwarded-For: 192.0.2.97\r\n')
                finally:
                    client.close()
            with self.subTest(path=path):
                self.assertEqual(200, (await self.run_client(exchange))[0])
                self.assertEqual(op, self.calls[-1]['op'])
                self.assertEqual('127.0.0.1', self.calls[-1]['peer_ip'])
                self.assertNotIn('source_ip', self.calls[-1])


if __name__ == '__main__':
    unittest.main()
