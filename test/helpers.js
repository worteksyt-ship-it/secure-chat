'use strict';
const { spawn } = require('child_process');
const crypto = require('crypto');
const os = require('os'), fs = require('fs'), path = require('path');
const WebSocket = require('ws');

async function startServer(port, env = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vz-'));
  const p = spawn('node', ['server.js'], { cwd: path.join(__dirname, '..'), env: { ...process.env, PORT: String(port), DB_PATH: path.join(dir, 't.db'), POW_BITS: '10', ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise((res, rej) => { p.stdout.on('data', (d) => /listening/.test(d) && res()); p.on('exit', rej); setTimeout(() => rej(new Error('start timeout')), 8000); });
  return { base: `http://127.0.0.1:${port}`, ws: `ws://127.0.0.1:${port}/ws`, stop: () => { p.kill(); fs.rmSync(dir, { recursive: true, force: true }); } };
}
function solve(t, bits) {
  for (let i = 0; ; i++) {
    const n = i.toString(36);
    const h = crypto.createHash('sha256').update(t + ':' + n).digest();
    let z = 0; for (const b of h) { if (b === 0) { z += 8; continue; } z += Math.clz32(b) - 24; break; }
    if (z >= bits) return n;
  }
}
const rid = () => crypto.randomBytes(16).toString('hex');
const room = () => rid();
async function pow(base, headers = {}) { const r = await (await fetch(base + '/api/pow', { headers })).json(); return { t: r.t, n: solve(r.t, r.b) }; }

// Connects and joins. Resolves with a client {ws, hello, inbox, closed:{code}}.
async function join(srv, roomId, { cid = rid().slice(0, 16), headers = {}, powOverride } = {}) {
  const ws = new WebSocket(srv.ws, { headers });
  const c = { ws, inbox: [], cid, closed: null };
  ws.on('message', (d) => { const m = JSON.parse(d); if (m.type === 'hello') c.hello = m; c.inbox.push(m); });
  ws.on('close', (code) => { c.closed = { code }; });
  await new Promise((r, j) => { ws.on('open', r); ws.on('error', j); });
  const pw = powOverride || await pow(srv.base, headers);
  ws.send(JSON.stringify({ type: 'join', v: '3', room: roomId, cid, tid: rid().slice(0, 16), pow: pw }));
  await new Promise((r) => { const iv = setInterval(() => { if (c.hello || c.closed) { clearInterval(iv); r(); } }, 10); });
  return c;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const msg = (ws) => ws.send(JSON.stringify({ type: 'msg', iv: crypto.randomBytes(12).toString('base64'), ct: crypto.randomBytes(40).toString('base64') }));
module.exports = { startServer, join, pow, room, sleep, msg, solve, rid };
