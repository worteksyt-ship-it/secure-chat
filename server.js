'use strict';
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const { WebSocketServer } = require('ws');
const Database = require('better-sqlite3');

const PORT = Number(process.env.PORT) || 8080;
const MAX_CT = 12000;          // base64 ciphertext limit (~2000 chars of text)
const HISTORY = 200;
const MAX_CONN_PER_IP = 20;
const HEARTBEAT_MS = 25000;

// ---------- storage ----------
const db = new Database(process.env.DB_PATH || path.join(__dirname, 'chat.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    iv TEXT NOT NULL,
    ct TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
`);
// Rooms: every distinct passphrase is its own room. The client derives an opaque
// roomId from the passphrase (separate one-way derivation from the encryption key).
if (!db.prepare("SELECT 1 FROM pragma_table_info('messages') WHERE name = 'room'").get()) {
  db.exec("ALTER TABLE messages ADD COLUMN room TEXT NOT NULL DEFAULT ''");
}
db.exec('CREATE INDEX IF NOT EXISTS messages_room_id ON messages (room, id)');
// Room salt must be stable across restarts (Render's disk is ephemeral), so it is
// NOT stored in the DB. Override with ROOM_SALT (base64, >= 16 bytes) if desired.
const DEFAULT_SALT = 'bfq0F6x0n7Tq3Jm1v9cK2w==';
const BOOT = crypto.randomBytes(6).toString('hex'); // changes on every restart
const salt = (process.env.ROOM_SALT && /^[A-Za-z0-9+/]{22,}={0,2}$/.test(process.env.ROOM_SALT)) ? process.env.ROOM_SALT : DEFAULT_SALT;
const insertMsg = db.prepare('INSERT INTO messages (room, ts, iv, ct) VALUES (?, ?, ?, ?)');
const lastMsgs = db.prepare('SELECT id, ts, iv, ct FROM (SELECT * FROM messages WHERE room = ? ORDER BY id DESC LIMIT ?) ORDER BY id ASC');
const prune = db.prepare('DELETE FROM messages WHERE room = ? AND id <= (SELECT id FROM messages WHERE room = ? ORDER BY id DESC LIMIT 1 OFFSET 2000)');
const roomRe = /^[a-f0-9]{32}$/;

// ---------- http ----------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', true);
app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; worker-src 'self'; manifest-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
  });
  next();
});
app.get('/sw.js', (req, res, next) => { res.set({ 'Service-Worker-Allowed': '/', 'Cache-Control': 'no-cache' }); next(); });
app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0, index: 'index.html' }));
app.get('/health', (_req, res) => res.json({ ok: true }));

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 32 * 1024 });

const ipCount = new Map();
const byTab = new Map(); // "cid:tid" -> ws  (one socket per browser tab)
const idRe = /^[a-f0-9]{8,32}$/;

// Real client IP behind Render/Cloudflare proxy.
function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff) return xff.split(',')[0].trim();
  return req.headers['cf-connecting-ip'] || req.socket.remoteAddress;
}
// Unique people online = unique client ids (one per browser), not sockets.
function onlineCount(room) {
  const s = new Set();
  for (const c of wss.clients) if (c.readyState === 1 && c.room === room) s.add(c.cid);
  return s.size;
}
const isB64 = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max && /^[A-Za-z0-9+/]+={0,2}$/.test(s);

function broadcast(room, obj, except) {
  const data = JSON.stringify(obj);
  for (const c of wss.clients) if (c !== except && c.room === room && c.readyState === 1) c.send(data);
}
const onlineTimers = new Map();
function online(room) {
  if (onlineTimers.has(room)) return;
  onlineTimers.set(room, setTimeout(() => { onlineTimers.delete(room); broadcast(room, { type: 'online', count: onlineCount(room) }); }, 50));
}

wss.on('connection', (ws, req) => {
  const ip = clientIp(req);
  const q = new URL(req.url, 'http://x').searchParams;
  // Legacy clients (cached old app.js) send no ids: give them a random one.
  const cid = idRe.test(q.get('cid') || '') ? q.get('cid') : crypto.randomBytes(9).toString('hex');
  const tid = idRe.test(q.get('tid') || '') ? q.get('tid') : crypto.randomBytes(9).toString('hex');
  ws.cid = cid;
  const room = q.get('room');
  if (!roomRe.test(room || '')) { ws.close(4001, 'room required'); return; }
  ws.room = room;
  const tabKey = cid + ':' + tid;
  ipCount.set(ip, (ipCount.get(ip) || 0) + 1);

  ws.on('close', () => {
    if (byTab.get(tabKey) === ws) byTab.delete(tabKey);
    const c = (ipCount.get(ip) || 1) - 1;
    if (c <= 0) ipCount.delete(ip); else ipCount.set(ip, c);
    online(room);
  });

  // Same tab reconnecting (e.g. phone resumed from background): kill the stale socket.
  const prev = byTab.get(tabKey);
  if (prev && prev !== ws) prev.terminate();
  byTab.set(tabKey, ws);

  if (ipCount.get(ip) > MAX_CONN_PER_IP) { ws.close(1008, 'too many connections'); return; }

  // token bucket: 6 messages burst, refill 1 per 1.5s
  let tokens = 6, last = Date.now(), lastTyping = 0;
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.send(JSON.stringify({ type: 'hello', salt, boot: BOOT, history: lastMsgs.all(room, HISTORY), count: onlineCount(room) }));
  online(room);

  ws.on('message', (raw) => {
    let m;
    try { m = JSON.parse(raw); } catch { return; }
    if (!m || typeof m !== 'object') return;
    const now = Date.now();
    ws.isAlive = true;
    if (m.type === 'ping') { ws.send('{"type":"pong"}'); return; }
    if (m.type === 'msg') {
      tokens = Math.min(6, tokens + (now - last) / 1500); last = now;
      if (tokens < 1) { ws.send(JSON.stringify({ type: 'error', code: 'rate' })); return; }
      if (!isB64(m.iv, 24) || !isB64(m.ct, MAX_CT)) { ws.send(JSON.stringify({ type: 'error', code: 'invalid' })); return; }
      tokens -= 1;
      const info = insertMsg.run(room, now, m.iv, m.ct);
      if (info.lastInsertRowid % 200 === 0) prune.run(room, room);
      const out = { type: 'msg', id: Number(info.lastInsertRowid), ts: now, iv: m.iv, ct: m.ct };
      broadcast(room, out);
    } else if (m.type === 'typing') {
      if (now - lastTyping < 2000) return;
      if (!isB64(m.iv, 24) || !isB64(m.ct, 400)) return;
      lastTyping = now;
      broadcast(room, { type: 'typing', iv: m.iv, ct: m.ct }, ws);
    }
  });

});

setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) { ws.terminate(); continue; }
    ws.isAlive = false; ws.ping();
  }
}, HEARTBEAT_MS);

server.listen(PORT, () => console.log(`chat listening on :${PORT}`));
