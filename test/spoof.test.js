'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer, join, room } = require('./helpers');


test('forged X-Forwarded-For does not bypass the room-guess limit (xff mode, 1 hop)', async () => {
  const srv = await startServer(18082, { IP_MODE: 'xff', IP_HOPS: '1', ROOM_GUESS_MAX: '3' });
  try {
    const out = [];
    for (let i = 0; i < 5; i++) out.push(await join(srv, room(), { headers: { 'x-forwarded-for': `6.6.6.${i}, 9.9.9.9` } }));
    assert.equal(out.filter((c) => c.inbox.some((m) => m.type === 'blocked')).length, 2, 'proxy-appended entry is the identity; spoofed leftmost is ignored');
    out.forEach((c) => c.ws.close());
  } finally { srv.stop(); }
});

test('cf mode uses cf-connecting-ip, different clients do not share limits', async () => {
  const srv = await startServer(18083, { IP_MODE: 'cf', ROOM_GUESS_MAX: '2' });
  try {
    const a = [], b = [];
    for (let i = 0; i < 3; i++) a.push(await join(srv, room(), { headers: { 'cf-connecting-ip': '1.1.1.1' } }));
    for (let i = 0; i < 2; i++) b.push(await join(srv, room(), { headers: { 'cf-connecting-ip': '2.2.2.2' } }));
    assert.ok(a[2].inbox.some((m) => m.type === 'blocked'));
    assert.ok(b.every((c) => c.hello));
    [...a, ...b].forEach((c) => c.ws.close());
  } finally { srv.stop(); }
});

test('room creation per IP is capped', async () => {
  const srv = await startServer(18084, { ROOM_GUESS_MAX: '100' });
  try {
    const { msg, sleep } = require('./helpers');
    const errs = [];
    for (let i = 0; i < 8; i++) { const c = await join(srv, room()); msg(c.ws); await sleep(80); if (c.inbox.some((m) => m.type === 'error' && m.code === 'full')) errs.push(i); c.ws.close(); }
    assert.deepEqual(errs, [6, 7]);
  } finally { srv.stop(); }
});

test('key-guessing: too many different rooms from one IP => escalating ban', async () => {
  const srv = await startServer(18085);
  try {
  const hdr = {};
  const results = [];
  for (let i = 0; i < 14; i++) { const c = await join(srv, room(), { headers: hdr }); results.push(c); }
  const blocked = results.filter((c) => c.inbox.some((m) => m.type === 'blocked'));
  assert.ok(results.slice(0, 12).every((c) => c.hello), 'first 12 probes pass');
  assert.equal(blocked.length, 2);
  const b = blocked[0].inbox.find((m) => m.type === 'blocked');
  assert.ok(b.retry > 250 && b.retry <= 300);
  assert.equal(blocked[0].closed.code, 4029);
  results.forEach((c) => c.ws.close());
  } finally { srv.stop(); }
});
