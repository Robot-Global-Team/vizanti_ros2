#!/usr/bin/env python3
"""NIF authority boundary tests: real Unix RPC, proxy TCP, fail-closed and revocation."""
import argparse
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('gateway', Path(__file__).parents[1] / 'scripts/vizanti_gateway.py')
g = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(g)


class Writer:
    def __init__(self):
        self.data = b''
        self.closed = False
        self.transport = self
    def write(self, value): self.data += value
    async def drain(self): pass
    def abort(self): self.closed = True
    def close(self): self.closed = True
    def get_extra_info(self, key): return None


class NifAuthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sock = str(Path(self.tmp.name) / 'gateway.sock')
        self.instance = 'authority-1'
        self.calls = []
        self.valid = True
        self.drop = False
        self.token = 't' * 43
        self.cid = 'a' * 32
        self.perms = ['ui', 'read', 'package']
        # A legacy registration must never become a NIF-mode authorization source.
        Path(self.tmp.name, 'clients.json').write_text(json.dumps({self.cid: {'name': 'legacy', 'perms': ['ui','read']}}))
        args = argparse.Namespace(data_dir=self.tmp.name, nif_port=1, pkg_port=1,
            auth_mode='nif-device-v1', nif_auth_socket=self.sock, nif_auth_uid=os.getuid(),
            no_tls=True, robot_uid_file='/nonexistent', api_log_period=60, janitor_period=1)
        self.gw = g.Gateway(args)
        self.gw.cert_fingerprint = 'f' * 64
        self.server = await asyncio.start_unix_server(self.authority, path=self.sock)

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        self.tmp.cleanup()

    async def authority(self, reader, writer):
        try:
            line = await reader.readline()
            if not line: return
            req = json.loads(line)
            self.calls.append(req)
            if self.drop: return
            reply = {'v':1,'ok': True, 'instance_id': self.instance}
            if req['op'] == 'pair':
                reply.update(client_id=self.cid, perms=self.perms)
            elif req['op'] == 'challenge':
                reply.update(nonce='n' * 43, ttl=60)
            elif req['op'] in ('session', 'api_token'):
                reply.update(token=self.token, ttl=900, perms=self.perms, client_id=self.cid)
            elif req['op'] == 'validate':
                reply.update(ok=self.valid and req.get('token') == self.token,
                    client_id=self.cid, name='pc', perms=self.perms, ttl=800)
            elif req['op'] == 'validate_many':
                reply['results'] = [{'ok': self.valid, 'client_id': self.cid, 'perms': self.perms}
                                    for _ in req['items']]
            writer.write(json.dumps(reply).encode() + b'\n')
            await writer.drain()
        finally:
            writer.close()

    async def endpoint(self, path, payload=None, method='POST', query=None):
        raw = json.dumps(payload or {}).encode()
        writer = Writer()
        await self.gw.handle_gw(method, path, query or {}, {'content-length': str(len(raw))},
            asyncio.StreamReader(), writer, '192.0.2.1', raw)
        head, body = writer.data.split(b'\r\n\r\n', 1)
        return int(head.split()[1]), head, body

    async def test_info_advertises_single_authority(self):
        status, _, raw = await self.endpoint('/gw/info', method='GET')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)['auth_mode'], 'nif-device-v1')
        self.assertEqual(self.gw.clients, {})

    async def test_enrollment_forwards_key_proof_and_bound_identity(self):
        payload = dict(client_name='operator', pubkey='pubkey', proof='proof',
            request_id='b' * 32, enroll_sig='signature', op='validate', peer_ip='evil', fp='evil')
        status, _, raw = await self.endpoint('/gw/pair', payload)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)['client_id'], self.cid)
        req = self.calls[-1]
        self.assertEqual(req['op'], 'pair')
        self.assertEqual(req['peer_ip'], '192.0.2.1')
        self.assertEqual(req['fp'], 'f' * 64)
        self.assertEqual(req['enroll_sig'], 'signature')
        self.assertEqual(req['request_id'], 'b' * 32)
        self.assertNotIn('clients.json', str(req))

    async def test_api_requires_nif_even_if_legacy_token_exists(self):
        self.gw.api_tokens[self.token] = dict(client_id=self.cid, ip='192.0.2.1',
            perms=['read'], expires=g.now()+100)
        self.valid = False
        self.assertEqual(await self.gw.authorize_api('Bearer '+self.token, '192.0.2.1'), (None,None))
        self.assertEqual(self.calls[-1]['op'], 'validate')

    async def test_auth_unavailable_is_503_before_backend(self):
        self.drop = True
        writer = Writer()
        head = ('GET /api/nif/uid HTTP/1.1\r\nHost: robot\r\nAuthorization: Bearer '+self.token+'\r\n\r\n').encode()
        await self.gw.handle_api(head, b'', asyncio.StreamReader(), writer, '192.0.2.1')
        self.assertIn(b'503 Service Unavailable', writer.data)
        self.assertIn(b'auth_unavailable', writer.data)

    async def test_wrong_authority_uid_rejected(self):
        self.gw.nif_auth_uid = os.getuid()+1
        with self.assertRaises(g.AuthUnavailable):
            await self.gw.nif_auth('validate', token=self.token, purpose='api', peer_ip='192.0.2.1')

    async def test_sso_cookie_is_nif_session_and_revocation_applies(self):
        status, _, raw = await self.endpoint('/gw/session', {'client_id':self.cid,'nonce':'n','sig':'s'})
        self.assertEqual(status, 200)
        ott = json.loads(raw)['ott']
        status, head, _ = await self.endpoint('/gw/sso', method='GET', query={'ott':[ott]})
        self.assertEqual(status, 302)
        self.assertIn(('vizanti_gw='+self.token).encode(), head)
        headers = {'cookie':'vizanti_gw='+self.token}
        self.assertIsNotNone((await self.gw.authorize_ui(headers,'192.0.2.1'))[0])
        self.valid = False
        self.assertEqual(await self.gw.authorize_ui(headers,'192.0.2.1'), (None,None))
        status, _, _ = await self.endpoint('/gw/sso', method='GET', query={'ott':[ott]})
        self.assertEqual(status, 403)

    async def test_authority_restart_invalidates_ui_even_if_response_valid(self):
        await self._setup_session()
        self.instance = 'authority-2'
        self.assertEqual(await self.gw.authorize_ui({'cookie':'vizanti_gw='+self.token},'192.0.2.1'), (None,None))
        self.assertEqual(self.gw.sessions, {})

    async def _setup_session(self):
        self.gw.sessions[self.token] = dict(client_id=self.cid, ip='192.0.2.1',
            expires=g.now()+800, nif_instance=self.instance)
        await self.gw.nif_auth('validate',token=self.token,purpose='ui',peer_ip='192.0.2.1')

    async def test_batch_revoke_severs_live_websocket(self):
        await self._setup_session()
        cw,bw=Writer(),Writer()
        self.gw.conns[1] = dict(id=1,client_id=self.cid,token=self.token,ip='192.0.2.1',
            cwriter=cw,bwriter=bw,opened=g.now(),last_active=g.now())
        self.valid=False
        await self.gw.nif_janitor()
        self.assertTrue(cw.closed and bw.closed)
        self.assertEqual(self.gw.sessions,{})
        self.assertEqual(self.calls[-1]['op'],'validate_many')

    async def test_backend_receives_only_authorized_bearer(self):
        received=[]
        async def backend(reader,writer):
            received.append(await reader.readuntil(b'\r\n\r\n'))
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}')
            await writer.drain()
            writer.close()
        server=await asyncio.start_server(backend,'127.0.0.1',0)
        self.gw.api_ports['nif']=server.sockets[0].getsockname()[1]
        self.gw.api_sems={svc:asyncio.Semaphore(4) for svc in g.API_SERVICES}
        writer=Writer()
        try:
            head=('GET /api/nif/uid HTTP/1.1\r\nHost: robot\r\nAuthorization: Bearer '+self.token+
                  '\r\nX-Forwarded-For: attacker\r\nX-User: admin\r\n\r\n').encode()
            await self.gw.handle_api(head,b'',asyncio.StreamReader(),writer,'192.0.2.1')
            self.assertIn(b'200 OK',writer.data)
            self.assertIn(('Authorization: Bearer '+self.token+'\r\n').encode(),received[0])
            self.assertNotIn(b'X-Forwarded',received[0])
            self.assertNotIn(b'X-User',received[0])
            self.assertGreaterEqual(sum(c['op']=='validate' for c in self.calls),2)
        finally:
            server.close()
            await server.wait_closed()

    async def test_ui_http_is_one_request_and_discards_pipeline(self):
        received=[]
        async def backend(reader,writer):
            received.append(await reader.read(16384))
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
            await writer.drain()
            writer.close()
        server=await asyncio.start_server(backend,'127.0.0.1',0)
        self.gw.args.flask_host='127.0.0.1'
        self.gw.args.flask_port=server.sockets[0].getsockname()[1]
        reader=asyncio.StreamReader()
        reader.feed_data(b'GET /second HTTP/1.1\r\nHost: robot\r\n\r\n')
        reader.feed_eof()
        writer=Writer()
        try:
            await self.gw.ui_once({'client_id':self.cid},self.token,
                b'GET /first HTTP/1.1\r\nHost: robot\r\nCookie: secret\r\n\r\n',reader,writer,'192.0.2.1')
            self.assertIn(b'200 OK',writer.data)
            self.assertEqual(len(received),1)
            self.assertIn(b'GET /first HTTP/1.1',received[0])
            self.assertIn(b'Connection: close',received[0])
            self.assertNotIn(b'/second',received[0])
            self.assertNotIn(b'Cookie:',received[0])
            self.assertEqual(self.gw.conns,{})
        finally:
            server.close()
            await server.wait_closed()

    async def test_ui_http_refuses_request_body_and_transfer_encoding(self):
        for suffix in (b'Content-Length: 1',b'Transfer-Encoding: chunked',b'Cookie: a\r\nCookie: b'):
            writer=Writer()
            await self.gw.ui_once({'client_id':self.cid},self.token,
                b'GET / HTTP/1.1\r\nHost: robot\r\n'+suffix+b'\r\n\r\n',
                asyncio.StreamReader(),writer,'192.0.2.1')
            self.assertIn(b'400 Bad Request',writer.data)

if __name__ == '__main__': unittest.main(verbosity=2)
