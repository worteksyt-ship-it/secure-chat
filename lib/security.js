'use strict';
const crypto = require('crypto');

// ---------- fixed-window rate limiter (in memory, keyed by anything) ----------
function makeLimiter(limit, windowMs) {
  const m = new Map();
  return {
    hit(key, now = Date.now()) {
      let e = m.get(key);
      if (!e || e.reset <= now) { e = { n: 0, reset: now + windowMs }; m.set(key, e); }
      e.n++;
      return e.n <= limit;
    },
    count(key, now = Date.now()) { const e = m.get(key); return e && e.reset > now ? e.n : 0; },
    sweep(now = Date.now()) { for (const [k, e] of m) if (e.reset <= now) m.delete(k); },
  };
}

// ---------- brute-force guard ----------
// The server never sees a passphrase, only the opaque room id derived from it, so a
// "wrong key" is simply "another room". What can be limited is how many DIFFERENT
// room ids one IP probes. Going over the limit gets an escalating ban (5 min, 10, 20 ... 24 h).
function makeRoomGuard({ max = 12, windowMs = 10 * 60 * 1000, banBaseMs = 5 * 60 * 1000 } = {}) {
  const m = new Map();
  const DAY = 24 * 3600 * 1000;
  return {
    check(ip, room, now = Date.now()) {
      let e = m.get(ip);
      if (!e) { e = { rooms: new Map(), strikes: 0, ban: 0, last: now }; m.set(ip, e); }
      if (now - e.last > DAY) { e.strikes = 0; }
      e.last = now;
      if (e.ban > now) return { ok: false, retry: Math.ceil((e.ban - now) / 1000) };
      for (const [r, exp] of e.rooms) if (exp <= now) e.rooms.delete(r);
      if (e.rooms.has(room)) return { ok: true };
      if (e.rooms.size >= max) {
        e.strikes++;
        e.ban = now + Math.min(DAY, banBaseMs * 2 ** (e.strikes - 1));
        e.rooms.clear();
        return { ok: false, retry: Math.ceil((e.ban - now) / 1000) };
      }
      e.rooms.set(room, now + windowMs);
      return { ok: true };
    },
    sweep(now = Date.now()) {
      for (const [ip, e] of m) if (e.ban <= now && now - e.last > 24 * 3600 * 1000) m.delete(ip);
    },
  };
}

// ---------- proof of work (anti-bot) ----------
// Server hands out an HMAC-signed challenge that carries its own difficulty; the client
// must find a nonce so that SHA-256(token + ':' + nonce) has `bits` leading zero bits.
// Tokens are single-use and expire after 2 minutes.
function leadingZeroBits(buf) {
  let n = 0;
  for (const byte of buf) {
    if (byte === 0) { n += 8; continue; }
    n += Math.clz32(byte) - 24;
    break;
  }
  return n;
}
function makePow({ secret = crypto.randomBytes(32), ttlMs = 120000 } = {}) {
  const used = new Map();
  const sign = (p) => crypto.createHmac('sha256', secret).update(p).digest('base64url').slice(0, 22);
  return {
    issue(bits, now = Date.now()) {
      const p = `${now}.${crypto.randomBytes(9).toString('hex')}.${bits}`;
      return { t: `${p}.${sign(p)}`, b: bits };
    },
    verify(t, n, now = Date.now()) {
      if (typeof t !== 'string' || typeof n !== 'string' || t.length > 100 || !/^[0-9a-z]{1,16}$/.test(n)) return false;
      const parts = t.split('.');
      if (parts.length !== 4) return false;
      const [ts, , b, sig] = parts;
      const want = sign(parts.slice(0, 3).join('.'));
      const a = Buffer.from(sig), w = Buffer.from(want);
      if (a.length !== w.length || !crypto.timingSafeEqual(a, w)) return false;
      const age = now - Number(ts), bits = Number(b);
      if (!(age >= -5000 && age <= ttlMs) || !(bits >= 0 && bits <= 28)) return false;
      if (used.has(t)) return false;
      if (bits > 0 && leadingZeroBits(crypto.createHash('sha256').update(t + ':' + n).digest()) < bits) return false;
      used.set(t, now + ttlMs);
      return true;
    },
    sweep(now = Date.now()) { for (const [k, exp] of used) if (exp <= now) used.delete(k); },
  };
}

// ---------- client IP ----------
// X-Forwarded-For can be forged by the client: only the entries added by OUR proxies are
// trustworthy. Modes:
//   cf      Render sits behind Cloudflare: cf-connecting-ip, else 2nd entry from the right of XFF
//   xff     take the entry `hops` places from the right of XFF
//   socket  direct connection (local dev, or hosts with no proxy)
function makeIpResolver(mode, hops) {
  const fromXff = (req, h) => {
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff !== 'string' || !xff) return null;
    const list = xff.split(',').map((s) => s.trim()).filter(Boolean);
    return list[Math.max(0, list.length - h)] || null;
  };
  return (req) => {
    if (mode === 'cf') {
      const cf = req.headers['cf-connecting-ip'] || req.headers['true-client-ip'];
      if (typeof cf === 'string' && cf) return cf.trim();
      return fromXff(req, 2) || req.socket.remoteAddress;
    }
    if (mode === 'xff') return fromXff(req, hops) || req.socket.remoteAddress;
    return req.socket.remoteAddress;
  };
}

module.exports = { makeLimiter, makeRoomGuard, makePow, makeIpResolver, leadingZeroBits };
