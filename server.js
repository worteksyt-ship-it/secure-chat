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
const MAX_CONN_PER_IP = 8;

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
let salt = db.prepare('SELECT v FROM meta WHERE k = ?').get('salt')?.v;
if (!salt) {
  salt = crypto.randomBytes(16).toString('base64');
  db.prepare('INSERT INTO meta (k, v) VALUES (?, ?)').run('salt', salt);
}
const insertMsg = db.prepare('INSERT INTO messages (ts, iv, ct) VALUES (?, ?, ?)');
const lastMsgs = db.prepare('SELECT id, ts, iv, ct FROM (SELECT * FROM messages ORDER BY id DESC LIMIT ?) ORDER BY id ASC');
const prune = db.prepare('DELETE FROM messages WHERE id <= (SELECT id FROM messages ORDER BY id DESC LIMIT 1 OFFSET 5000)');

// ---------- http ----------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', true);
app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
  });
  next();
});
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h', index: 'index.html' }));
app.get('/health', (_req, res) => res.json({ ok: true }));

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 32 * 1024 });

const ipCount = new Map();
const isB64 = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max && /^[A-Za-z0-9+/]+={0,2}$/.test(s);

function broadcast(obj, except) {
  const data = JSON.stringify(obj);
  for (const c of wss.clients) if (c !== except && c.readyState === 1) c.send(data);
}
function online() { broadcast({ type: 'online', count: wss.clients.size }); }

wss.on('connection', (ws, req) => {
  const ip = req.headers['cf-connecting-ip'] || req.socket.remoteAddress;
  const n = (ipCount.get(ip) || 0) + 1;
  if (n > MAX_CONN_PER_IP) { ws.close(1008, 'too many connections'); return; }
  ipCount.set(ip, n);

  // token bucket: 6 messages burst, refill 1 per 1.5s
  let tokens = 6, last = Date.now(), lastTyping = 0;
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.send(JSON.stringify({ type: 'hello', salt, history: lastMsgs.all(HISTORY), count: wss.clients.size }));
  online();

  ws.on('message', (raw) => {
    let m;
    try { m = JSON.parse(raw); } catch { return; }
    if (!m || typeof m !== 'object') return;
    const now = Date.now();
    if (m.type === 'msg') {
      tokens = Math.min(6, tokens + (now - last) / 1500); last = now;
      if (tokens < 1) { ws.send(JSON.stringify({ type: 'error', code: 'rate' })); return; }
      if (!isB64(m.iv, 24) || !isB64(m.ct, MAX_CT)) { ws.send(JSON.stringify({ type: 'error', code: 'invalid' })); return; }
      tokens -= 1;
      const info = insertMsg.run(now, m.iv, m.ct);
      if (info.lastInsertRowid % 500 === 0) prune.run();
      const out = { type: 'msg', id: Number(info.lastInsertRowid), ts: now, iv: m.iv, ct: m.ct };
      broadcast(out);
    } else if (m.type === 'typing') {
      if (now - lastTyping < 2000) return;
      if (!isB64(m.iv, 24) || !isB64(m.ct, 400)) return;
      lastTyping = now;
      broadcast({ type: 'typing', iv: m.iv, ct: m.ct }, ws);
    }
  });

  ws.on('close', () => {
    const c = (ipCount.get(ip) || 1) - 1;
    if (c <= 0) ipCount.delete(ip); else ipCount.set(ip, c);
    online();
  });
});

setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) { ws.terminate(); continue; }
    ws.isAlive = false; ws.ping();
  }
}, 30000);

server.listen(PORT, () => console.log(`chat listening on :${PORT}`));
