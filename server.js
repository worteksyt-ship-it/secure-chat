'use strict';
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const compression = require('compression');
const { WebSocketServer } = require('ws');
const Database = require('better-sqlite3');
const sec = require('./lib/security');

// ---------- config (all overridable via env) ----------
const num = (k, d) => { const v = process.env[k]; const n = Number(v); return v != null && v !== '' && Number.isFinite(n) ? n : d; };
const MB = 1024 * 1024, DAY = 24 * 3600 * 1000;
const PORT = num('PORT', 8080);
const PROTO = '3';
const MAX_CT = 12000;                         // base64 ciphertext of a message (text is deflated before encryption)
const HISTORY = 200;
const MAX_PER_ROOM = num('MAX_MESSAGES_PER_ROOM', 1000);
const MAX_CONN_PER_IP = num('MAX_CONN_PER_IP', 30);
const HEARTBEAT_MS = 25000;
const MAX_BLOB = num('MAX_BLOB_KB', 600) * 1024;       // one encrypted photo / voice message
const ROOM_MEDIA_QUOTA = num('ROOM_MEDIA_MB', 40) * MB;
const GLOBAL_MEDIA_QUOTA = num('MEDIA_MB', 200) * MB;
const DB_MAX = num('DB_MAX_MB', 400) * MB;
const MSG_TTL = num('MESSAGE_TTL_DAYS', 30) * DAY;
const BLOB_TTL = num('MEDIA_TTL_DAYS', 7) * DAY;
const MAX_ROOMS = num('MAX_ROOMS', 500);
const POW_BITS = num('POW_BITS', 14);
const IP_MODE = process.env.IP_MODE || (process.env.RENDER ? 'cf' : 'socket');
const ipOf = sec.makeIpResolver(IP_MODE, num('IP_HOPS', 1));
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);

// ---------- limiters ----------
const powIssue = sec.makeLimiter(40, 60 * 1000);          // challenges per IP per minute
const powRecent = sec.makeLimiter(1e9, 60 * 1000);        // used to make difficulty adaptive
const roomCreate = sec.makeLimiter(6, 3600 * 1000);       // new rooms per IP per hour
const uploadIp = sec.makeLimiter(30, 60 * 1000);
const uploadTok = sec.makeLimiter(10, 60 * 1000);
const wipeIp = sec.makeLimiter(4, 3600 * 1000);
const roomGuard = sec.makeRoomGuard({ max: num('ROOM_GUESS_MAX', 12), windowMs: 10 * 60 * 1000, banBaseMs: 5 * 60 * 1000 });
const pow = sec.makePow(process.env.POW_SECRET ? { secret: Buffer.from(process.env.POW_SECRET) } : {});

// ---------- storage ----------
const db = new Database(process.env.DB_PATH || path.join(__dirname, 'chat.db'));
db.pragma('auto_vacuum = INCREMENTAL'); // only takes effect on a fresh DB file
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, iv TEXT NOT NULL, ct TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS blobs (id TEXT PRIMARY KEY, room TEXT NOT NULL, ts INTEGER NOT NULL, size INTEGER NOT NULL, data BLOB NOT NULL);
`);
if (!db.prepare("SELECT 1 FROM pragma_table_info('messages') WHERE name = 'room'").get()) {
  db.exec("ALTER TABLE messages ADD COLUMN room TEXT NOT NULL DEFAULT ''");
}
db.exec('CREATE INDEX IF NOT EXISTS messages_room_id ON messages (room, id)');
db.exec('CREATE INDEX IF NOT EXISTS blobs_room ON blobs (room)');
db.exec('CREATE INDEX IF NOT EXISTS blobs_ts ON blobs (ts)');

// Room salt must be stable across restarts (Render's disk is ephemeral). Override with ROOM_SALT.
const DEFAULT_SALT = 'bfq0F6x0n7Tq3Jm1v9cK2w==';
const BOOT = crypto.randomBytes(6).toString('hex');
const salt = (process.env.ROOM_SALT && /^[A-Za-z0-9+/]{22,}={0,2}$/.test(process.env.ROOM_SALT)) ? process.env.ROOM_SALT : DEFAULT_SALT;

const insertMsg = db.prepare('INSERT INTO messages (room, ts, iv, ct) VALUES (?, ?, ?, ?)');
const lastMsgs = db.prepare('SELECT id, ts, iv, ct FROM (SELECT * FROM messages WHERE room = ? ORDER BY id DESC LIMIT ?) ORDER BY id ASC');
const prune = db.prepare('DELETE FROM messages WHERE room = ? AND id <= (SELECT id FROM messages WHERE room = ? ORDER BY id DESC LIMIT 1 OFFSET ?)');
const delRoomMsgs = db.prepare('DELETE FROM messages WHERE room = ?');
const delRoomBlobs = db.prepare('DELETE FROM blobs WHERE room = ?');
const insBlob = db.prepare('INSERT INTO blobs (id, room, ts, size, data) VALUES (?, ?, ?, ?, ?)');
const getBlob = db.prepare('SELECT room, data FROM blobs WHERE id = ?');
const roomMedia = db.prepare('SELECT COALESCE(SUM(size), 0) AS s FROM blobs WHERE room = ?');
const allMedia = db.prepare('SELECT COALESCE(SUM(size), 0) AS s FROM blobs');
const knownRooms = new Set(db.prepare("SELECT DISTINCT room FROM messages WHERE room != ''").all().map((r) => r.room));
const dbBytes = () => db.pragma('page_count', { simple: true }) * db.pragma('page_size', { simple: true });
const dbFull = () => dbBytes() > DB_MAX;
// Metadata minimisation: the UI only shows HH:MM, so the server only ever stores minute precision.
const coarse = (t) => t - (t % 60000);

const roomRe = /^[a-f0-9]{32}$/;
const idRe = /^[a-f0-9]{8,32}$/;
const isB64 = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max && /^[A-Za-z0-9+/]+={0,2}$/.test(s);

// ---------- http ----------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', false); // we resolve client IPs ourselves (lib/security.js)
app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'self'; script-src 'self'; font-src 'self'; worker-src 'self'; manifest-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'microphone=(self), camera=(), geolocation=(), payment=()',
  });
  if (req.headers['x-forwarded-proto'] === 'https') res.set('Strict-Transport-Security', 'max-age=31536000');
  next();
});
app.use(compression());
app.get('/sw.js', (req, res, next) => { res.set({ 'Service-Worker-Allowed': '/', 'Cache-Control': 'no-cache' }); next(); });
app.use(express.static(path.join(__dirname, 'public'), {
  index: 'index.html',
  setHeaders(res, p) {
    // code revalidates (ETag -> cheap 304); icons/fonts are cached for a day
    res.setHeader('Cache-Control', /\.(png|svg|woff2?)$/.test(p) ? 'public, max-age=86400' : 'no-cache');
  },
}));
app.get('/health', (_req, res) => res.json({ ok: true }));

// Anti-bot challenge. Difficulty rises for IPs that ask for many challenges.
app.get('/api/pow', (req, res) => {
  const ip = ipOf(req);
  res.set('Cache-Control', 'no-store');
  if (!powIssue.hit(ip)) return res.status(429).json({ error: 'rate' });
  powRecent.hit(ip);
  const n = powRecent.count(ip);
  const bits = POW_BITS === 0 ? 0 : POW_BITS + (n > 24 ? 4 : n > 8 ? 2 : 0);
  res.json(pow.issue(bits));
});

// Encrypted media. The server only ever holds ciphertext; access needs the per-connection
// token (`up`) issued after a successful join, and a blob is only readable from its own room.
const tokens = new Map(); // up token -> ws
const wsFor = (req) => { const ws = tokens.get(String(req.get('x-up') || '')); return ws && ws.readyState === 1 && ws.room ? ws : null; };

app.post('/api/blob', express.raw({ type: 'application/octet-stream', limit: MAX_BLOB }), (req, res) => {
  res.set('Cache-Control', 'no-store');
  const ws = wsFor(req);
  if (!ws) return res.status(401).json({ error: 'auth' });
  if (!uploadIp.hit(ipOf(req)) || !uploadTok.hit(ws.up)) return res.status(429).json({ error: 'rate' });
  const buf = req.body;
  if (!Buffer.isBuffer(buf) || buf.length < 29) return res.status(400).json({ error: 'invalid' });
  if (dbFull() || roomMedia.get(ws.room).s + buf.length > ROOM_MEDIA_QUOTA || allMedia.get().s + buf.length > GLOBAL_MEDIA_QUOTA) {
    return res.status(507).json({ error: 'full' });
  }
  const id = crypto.randomBytes(16).toString('hex');
  insBlob.run(id, ws.room, coarse(Date.now()), buf.length, buf);
  res.json({ id });
});
app.get('/api/blob/:id', (req, res) => {
  res.set('Cache-Control', 'no-store');
  const ws = wsFor(req);
  if (!ws) return res.status(401).json({ error: 'auth' });
  if (!/^[a-f0-9]{32}$/.test(req.params.id)) return res.status(404).end();
  const row = getBlob.get(req.params.id);
  if (!row || row.room !== ws.room) return res.status(404).end();
  res.type('application/octet-stream').send(row.data);
});
app.use((err, _req, res, _next) => { // never leak stack traces
  const status = err && err.status >= 400 && err.status < 500 ? err.status : 500;
  res.status(status).json({ error: status === 413 ? 'too_large' : 'error' });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 32 * 1024 });

const ipCount = new Map();
const byTab = new Map(); // "cid:tid" -> ws  (one socket per browser tab)
const send = (ws, obj) => { try { ws.send(JSON.stringify(obj)); } catch {} };

function onlineCount(room) {
  const s = new Set();
  for (const c of wss.clients) if (c.readyState === 1 && c.room === room) s.add(c.cid);
  return s.size;
}
function broadcast(room, obj, except) {
  const data = JSON.stringify(obj);
  for (const c of wss.clients) if (c !== except && c.room === room && c.readyState === 1) c.send(data);
}
const onlineTimers = new Map();
function online(room) {
  if (onlineTimers.has(room)) return;
  onlineTimers.set(room, setTimeout(() => { onlineTimers.delete(room); broadcast(room, { type: 'online', count: onlineCount(room) }); }, 50));
}
function originOk(req) {
  const o = req.headers.origin;
  if (!o) return true; // non-browser clients: they still have to solve the proof of work
  try { const u = new URL(o); return u.host === req.headers.host || ALLOWED_ORIGINS.includes(u.origin); } catch { return false; }
}

function wipeRoom(room) {
  db.transaction(() => { delRoomMsgs.run(room); delRoomBlobs.run(room); })();
  knownRooms.delete(room);
  broadcast(room, { type: 'wiped' });
  for (const c of wss.clients) if (c.room === room) { try { c.close(4002, 'wiped'); } catch {} }
  try { db.pragma('incremental_vacuum(500)'); } catch {}
}

wss.on('connection', (ws, req) => {
  const q = new URL(req.url, 'http://x').searchParams;
  // Old cached clients put their params in the URL: tell them to reload.
  if (q.has('v') || q.has('room')) { send(ws, { type: 'reload', reason: 'protocol', proto: PROTO }); ws.close(4001, 'reload required'); return; }
  if (!originOk(req)) { ws.close(1008, 'origin'); return; }
  const ip = ipOf(req);
  ws.ip = ip;
  ipCount.set(ip, (ipCount.get(ip) || 0) + 1);
  ws.on('close', () => {
    clearTimeout(ws.joinTimer);
    if (ws.up) tokens.delete(ws.up);
    if (ws.tabKey && byTab.get(ws.tabKey) === ws) byTab.delete(ws.tabKey);
    const c = (ipCount.get(ip) || 1) - 1;
    if (c <= 0) ipCount.delete(ip); else ipCount.set(ip, c);
    if (ws.room) online(ws.room);
  });
  ws.on('error', () => {});
  if (ipCount.get(ip) > MAX_CONN_PER_IP) { ws.close(1008, 'too many connections'); return; }
  ws.joinTimer = setTimeout(() => { if (!ws.room) ws.close(4003, 'join timeout'); }, 8000);
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  ws.on('message', (raw) => onMessage(ws, raw));
});

function handleJoin(ws, m) {
  clearTimeout(ws.joinTimer);
  if (m.v !== PROTO) { send(ws, { type: 'reload', reason: 'protocol', proto: PROTO }); ws.close(4001, 'reload required'); return; }
  if (!roomRe.test(m.room || '') || !idRe.test(m.cid || '') || !idRe.test(m.tid || '')) { ws.close(1008, 'bad join'); return; }
  if (!m.pow || !pow.verify(m.pow.t, m.pow.n)) { send(ws, { type: 'error', code: 'pow' }); ws.close(4004, 'pow'); return; }
  const g = roomGuard.check(ws.ip, m.room);
  if (!g.ok) { send(ws, { type: 'blocked', retry: g.retry }); ws.close(4029, 'blocked'); return; }

  ws.cid = m.cid; ws.room = m.room;
  ws.tabKey = m.cid + ':' + m.tid;
  ws.tk = 6; ws.tl = Date.now(); ws.lastTyping = 0;
  // Same tab reconnecting (phone resumed from background): kill its stale socket.
  const prev = byTab.get(ws.tabKey);
  if (prev && prev !== ws) { prev.tabKey = null; prev.terminate(); }
  byTab.set(ws.tabKey, ws);
  ws.up = crypto.randomBytes(16).toString('hex');
  tokens.set(ws.up, ws);
  send(ws, { type: 'hello', salt, boot: BOOT, up: ws.up, lim: { blob: MAX_BLOB }, history: lastMsgs.all(ws.room, HISTORY), count: onlineCount(ws.room) });
  online(ws.room);
}

function onMessage(ws, raw) {
  let m;
  try { m = JSON.parse(raw); } catch { return; }
  if (!m || typeof m !== 'object') return;
  ws.isAlive = true;
  if (m.type === 'ping') { ws.send('{"type":"pong"}'); return; }
  if (!ws.room) { if (m.type === 'join') handleJoin(ws, m); return; }
  const now = Date.now();
  if (m.type === 'msg') {
    ws.tk = Math.min(6, ws.tk + (now - ws.tl) / 1500); ws.tl = now;
    if (ws.tk < 1) return send(ws, { type: 'error', code: 'rate' });
    if (!isB64(m.iv, 24) || !isB64(m.ct, MAX_CT)) return send(ws, { type: 'error', code: 'invalid' });
    if (!knownRooms.has(ws.room)) { // first message creates the room
      if (knownRooms.size >= MAX_ROOMS || dbFull() || !roomCreate.hit(ws.ip)) return send(ws, { type: 'error', code: 'full' });
      knownRooms.add(ws.room);
    }
    ws.tk -= 1;
    const ts = coarse(now);
    const info = insertMsg.run(ws.room, ts, m.iv, m.ct);
    if (Math.random() < 0.02) prune.run(ws.room, ws.room, MAX_PER_ROOM);
    broadcast(ws.room, { type: 'msg', id: Number(info.lastInsertRowid), ts, iv: m.iv, ct: m.ct });
  } else if (m.type === 'typing') {
    if (now - ws.lastTyping < 2000) return;
    if (!isB64(m.iv, 24) || !isB64(m.ct, 400)) return;
    ws.lastTyping = now;
    broadcast(ws.room, { type: 'typing', iv: m.iv, ct: m.ct }, ws);
  } else if (m.type === 'wipe') {
    if (!wipeIp.hit(ws.ip)) return send(ws, { type: 'error', code: 'rate' });
    wipeRoom(ws.room);
  } else {
    send(ws, { type: 'error', code: 'proto', proto: PROTO });
  }
}

// ---------- housekeeping ----------
function cleanup() {
  const now = Date.now();
  db.prepare('DELETE FROM messages WHERE ts < ?').run(now - MSG_TTL);
  db.prepare('DELETE FROM blobs WHERE ts < ?').run(now - BLOB_TTL);
  for (const r of [...knownRooms]) if (!db.prepare('SELECT 1 FROM messages WHERE room = ? LIMIT 1').get(r)) knownRooms.delete(r);
  try { db.pragma('incremental_vacuum(500)'); } catch {}
  for (const x of [powIssue, powRecent, roomCreate, uploadIp, uploadTok, wipeIp, roomGuard, pow]) x.sweep();
}
cleanup();
setInterval(cleanup, 60 * 60 * 1000).unref();
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) { ws.terminate(); continue; }
    ws.isAlive = false; ws.ping();
  }
}, HEARTBEAT_MS).unref();

server.listen(PORT, () => console.log(`chat listening on :${PORT} (proto ${PROTO}, ip-mode ${IP_MODE}, pow ${POW_BITS} bits)`));
