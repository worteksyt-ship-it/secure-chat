'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const WebSocket = require('ws');
const { startServer, join, pow, room, sleep, msg, rid } = require('./helpers');

let srv;
test.before(async () => { srv = await startServer(18081); });
test.after(() => srv.stop());

test('security headers + compression + caching', async () => {
  const r = await fetch(srv.base + '/', { headers: { 'accept-encoding': 'gzip' } });
  assert.match(r.headers.get('content-security-policy'), /media-src 'self' blob:/);
  assert.equal(r.headers.get('cache-control'), 'no-cache');
  assert.equal(r.headers.get('content-encoding'), 'gzip');
  assert.equal(r.headers.get('x-powered-by'), null);
});

test('old (v2) client in URL gets a reload command', async () => {
  const ws = new WebSocket(srv.ws + '?v=2&room=' + room());
  const got = await new Promise((res) => { const out = {}; ws.on('message', (d) => { out.m = JSON.parse(d); }); ws.on('close', (c) => { out.code = c; res(out); }); });
  assert.equal(got.m.type, 'reload'); assert.equal(got.code, 4001);
});

test('join without / with bad / reused proof-of-work is rejected', async () => {
  const r = room();
  let c = await join(srv, r, { powOverride: { t: 'x.y.10.z', n: '0' } });
  assert.equal(c.closed?.code, 4004);
  const ch = await (await fetch(srv.base + '/api/pow')).json();
  c = await join(srv, r, { powOverride: { t: ch.t, n: 'zzzzzzzz' } });
  assert.equal(c.closed?.code, 4004);
  const good = await pow(srv.base);
  const a = await join(srv, r, { powOverride: good }); assert.ok(a.hello);
  const b = await join(srv, r, { powOverride: good }); assert.equal(b.closed?.code, 4004, 'token must be single use');
  a.ws.close();
});

test('messages flow between members, ts is minute-precise, history persists', async () => {
  const r = room();
  const a = await join(srv, r), b = await join(srv, r);
  msg(a.ws); await sleep(200);
  const m = b.inbox.find((x) => x.type === 'msg');
  assert.ok(m); assert.equal(m.ts % 60000, 0);
  const c = await join(srv, r);
  assert.equal(c.hello.history.length, 1);
  assert.equal(c.hello.count, 3);
  [a, b, c].forEach((x) => x.ws.close());
});

test('rooms are isolated', async () => {
  const a = await join(srv, room()), b = await join(srv, room());
  msg(a.ws); await sleep(200);
  assert.equal(b.inbox.filter((x) => x.type === 'msg').length, 0);
  a.ws.close(); b.ws.close();
});

test('message rate limit', async () => {
  const a = await join(srv, room());
  for (let i = 0; i < 10; i++) msg(a.ws);
  await sleep(300);
  assert.ok(a.inbox.some((x) => x.type === 'error' && x.code === 'rate'));
  a.ws.close();
});

test('media: auth, room isolation, size limit, wipe', async () => {
  const r = room();
  const a = await join(srv, r), other = await join(srv, room());
  const body = Buffer.alloc(5000, 7);
  const post = (up, b) => fetch(srv.base + '/api/blob', { method: 'POST', headers: { 'content-type': 'application/octet-stream', ...(up ? { 'x-up': up } : {}) }, body: b });
  assert.equal((await post(null, body)).status, 401);
  assert.equal((await post('deadbeef', body)).status, 401);
  assert.equal((await post(a.hello.up, Buffer.alloc(10))).status, 400);
  assert.equal((await post(a.hello.up, Buffer.alloc(700 * 1024))).status, 413);
  const up = await post(a.hello.up, body); assert.equal(up.status, 200);
  const { id } = await up.json();
  const get = (up2) => fetch(srv.base + '/api/blob/' + id, { headers: { 'x-up': up2 } });
  const ok = await get(a.hello.up); assert.equal(ok.status, 200);
  assert.equal(Buffer.from(await ok.arrayBuffer()).equals(body), true);
  assert.equal((await get(other.hello.up)).status, 404, 'other room must not read it');
  // wipe
  const b = await join(srv, r);
  msg(a.ws); await sleep(150);
  a.ws.send(JSON.stringify({ type: 'wipe' })); await sleep(300);
  assert.ok(b.inbox.some((x) => x.type === 'wiped'));
  assert.equal(b.closed?.code, 4002);
  const again = await join(srv, r);
  assert.equal(again.hello.history.length, 0);
  assert.equal((await fetch(srv.base + '/api/blob/' + id, { headers: { 'x-up': again.hello.up } })).status, 404);
  other.ws.close(); again.ws.close();
});

