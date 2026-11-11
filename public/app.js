'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder(), dec = new TextDecoder();
  const MAX_LEN = 2000;
  const ITER = 310000;
  const PROTO = '3';
  const MEDIA_CACHE = 'vizard-media-v1';
  const IMG_MAX_SIDE = 1280, IMG_MAX_BYTES = 280 * 1024, VOICE_MAX_S = 120;
  const KEY_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  function forceReload() {
    // reload at most once per minute to avoid loops
    const last = +sessionStorage.getItem('chat.reloadAt') || 0;
    if (Date.now() - last < 60000) return false;
    sessionStorage.setItem('chat.reloadAt', String(Date.now()));
    location.reload(); return true;
  }

  const state = {
    nick: '', pass: '', key: null, keySalt: null, salt: null, boot: null, ws: null, retry: 0, paused: false,
    lastAuthor: null, lastTs: 0, lastDay: '', seen: new Set(),
    okCount: 0, failCount: 0, typers: new Map(), timer: null,
    up: null, lim: { blob: 600 * 1024 }, connecting: false, blockedUntil: 0,
  };

  // client id to recognize own messages
  let cid = localStorage.getItem('chat.cid');
  const rndId = () => Array.from(crypto.getRandomValues(new Uint8Array(9)), b => b.toString(16).padStart(2, '0')).join('');
  if (!/^[a-f0-9]{8,32}$/.test(cid || '')) { cid = rndId(); localStorage.setItem('chat.cid', cid); }
  // per-tab id (survives reloads of the same tab) so the server can replace this tab's stale socket
  let tid = sessionStorage.getItem('chat.tid');
  if (!/^[a-f0-9]{8,32}$/.test(tid || '')) { tid = rndId(); sessionStorage.setItem('chat.tid', tid); }

  // ---------- PWA ----------
  if ('serviceWorker' in navigator) {
    const hadController = !!navigator.serviceWorker.controller;
    let reloading = false;
    // when a new service worker takes over, reload once so page + server versions match
    navigator.serviceWorker.addEventListener('controllerchange', () => { if (hadController && !reloading) { reloading = true; location.reload(); } });
    window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js', { scope: '/', updateViaCache: 'none' })
      .then((reg) => { reg.update().catch(() => {}); document.addEventListener('visibilitychange', () => { if (!document.hidden) reg.update().catch(() => {}); }); })
      .catch(() => {}));
  }
  const standalone = matchMedia('(display-mode: standalone)').matches || matchMedia('(display-mode: window-controls-overlay)').matches || navigator.standalone === true;
  const isIOS = /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  let installEvt = null;
  function showInstall(on) {
    $('install').hidden = !on; $('installBtn').hidden = !installEvt; $('installBar').hidden = !installEvt;
    $('iosHint').hidden = !(on && isIOS && !installEvt);
  }
  if (!standalone && isIOS) showInstall(true);
  window.addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); installEvt = e; if (!standalone) showInstall(true); });
  window.addEventListener('appinstalled', () => { installEvt = null; showInstall(false); });
  async function doInstall() {
    if (!installEvt) return;
    installEvt.prompt();
    try { await installEvt.userChoice; } catch {}
    installEvt = null; showInstall(false);
  }
  document.addEventListener('click', (e) => { if (e.target.id === 'installBtn' || e.target.id === 'installBar') doInstall(); });

  // ---------- crypto ----------
  const b64 = (buf) => { let s = ''; const a = new Uint8Array(buf); for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); };
  const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));

  // Key is always derived fresh from (passphrase, salt sent by server in 'hello').
  async function deriveKey(pass, salt) {
    const base = await crypto.subtle.importKey('raw', enc.encode(pass.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: unb64(salt), iterations: ITER, hash: 'SHA-256' }, base, 288));
    const key = await crypto.subtle.importKey('raw', bits.slice(0, 32), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    const fp = Array.from(bits.slice(32, 34), b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return { key, fp };
  }
  // Room id: SEPARATE one-way derivation. It tells the server which room to use, nothing about the key.
  async function deriveRoomId(pass) {
    const base = await crypto.subtle.importKey('raw', enc.encode(pass.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode('VIZARD/room-id/v1'), iterations: 200000, hash: 'SHA-256' }, base, 128);
    return Array.from(new Uint8Array(bits), b => b.toString(16).padStart(2, '0')).join('');
  }

  // ----- generated keys: 25 chars x 5 bits = 125 bits, shown as XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
  const GEN_RE = /^[0-9A-HJKMNP-TV-Z]{25}$/;
  function genKey() {
    const a = crypto.getRandomValues(new Uint8Array(25));
    let s = ''; for (const x of a) s += KEY_ALPHABET[x & 31];
    return s.match(/.{5}/g).join('-');
  }
  // Only dashed/spaced input is canonicalised, so every pre-existing manual passphrase keeps its old room.
  function normKey(raw) {
    const t = raw.trim();
    if (/[-\s]/.test(t)) {
      const c = t.replace(/[-\s]/g, '').toUpperCase();
      if (GEN_RE.test(c)) return c.match(/.{5}/g).join('-');
    }
    return t;
  }
  const isGenKey = (k) => GEN_RE.test(k.replace(/-/g, '')) && /^([0-9A-Z]{5}-){4}[0-9A-Z]{5}$/.test(k);
  function weakKey(k) {
    if (isGenKey(k)) return false;
    const pool = (/[a-zа-яё]/.test(k) ? 26 : 0) + (/[A-ZА-ЯЁ]/.test(k) ? 26 : 0) + (/\d/.test(k) ? 10 : 0) + (/[^\w\s]/.test(k) ? 32 : 0) || 10;
    const uniq = new Set(k).size;
    return Math.min(k.length, uniq * 2) * Math.log2(pool) < 50;
  }

  // ----- text compression (deflate) BEFORE encryption; ciphertext cannot be compressed afterwards
  async function readAll(stream, cap) {
    const r = stream.getReader(); const chunks = []; let n = 0;
    for (;;) {
      const { done, value } = await r.read(); if (done) break;
      n += value.length; if (n > cap) { r.cancel().catch(() => {}); throw new Error('too big'); }
      chunks.push(value);
    }
    const out = new Uint8Array(n); let o = 0; for (const c of chunks) { out.set(c, o); o += c.length; } return out;
  }
  async function deflate(u8) { const cs = new CompressionStream('deflate-raw'); const w = cs.writable.getWriter(); w.write(u8).catch(() => {}); w.close().catch(() => {}); return readAll(cs.readable, 1 << 20); }
  async function inflate(u8, cap) { const ds = new DecompressionStream('deflate-raw'); const w = ds.writable.getWriter(); w.write(u8).catch(() => {}); w.close().catch(() => {}); return readAll(ds.readable, cap); }
  // plaintext layout: first byte 0x01 = deflate-raw follows; anything else = plain JSON (old messages start with '{')
  async function pack(obj) {
    const bytes = enc.encode(JSON.stringify(obj));
    if (bytes.length > 96 && typeof CompressionStream === 'function') {
      try { const z = await deflate(bytes); if (z.length + 1 < bytes.length) { const out = new Uint8Array(z.length + 1); out[0] = 1; out.set(z, 1); return out; } } catch {}
    }
    return bytes;
  }
  async function unpack(bytes) {
    if (bytes[0] === 1) bytes = await inflate(bytes.subarray(1), 64 * 1024); // capped: no decompression bombs
    return JSON.parse(dec.decode(bytes));
  }
  async function seal(obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.key, await pack(obj));
    return { iv: b64(iv), ct: b64(ct) };
  }
  async function open(iv, ct) {
    try {
      const o = await unpack(new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, state.key, unb64(ct))));
      return o && typeof o === 'object' ? o : null;
    } catch { return null; }
  }
  // binary (photo / voice): iv(12) || ciphertext
  async function sealBytes(u8) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.key, u8));
    const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12); return out;
  }
  async function openBytes(u8) {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u8.subarray(0, 12) }, state.key, u8.subarray(12)));
  }

  // ----- anti-bot proof of work: find a nonce whose SHA-256(token:nonce) has `b` leading zero bits
  const zeroBits = (h) => { let n = 0; for (const x of h) { if (x === 0) { n += 8; continue; } n += Math.clz32(x) - 24; break; } return n; };
  async function solvePow() {
    const r = await fetch('/api/pow', { cache: 'no-store' });
    if (!r.ok) throw new Error('pow ' + r.status);
    const { t, b } = await r.json();
    const prefix = enc.encode(t + ':');
    let n = Math.floor(Math.random() * 1e6);
    for (;;) {
      const batch = [];
      for (let i = 0; i < 96; i++) {
        const nonce = (n++).toString(36), nb = enc.encode(nonce);
        const buf = new Uint8Array(prefix.length + nb.length); buf.set(prefix); buf.set(nb, prefix.length);
        batch.push(crypto.subtle.digest('SHA-256', buf).then((h) => ({ nonce, h: new Uint8Array(h) })));
      }
      for (const { nonce, h } of await Promise.all(batch)) if (zeroBits(h) >= b) return { t, n: nonce };
    }
  }

  // ---------- viewport (mobile keyboard) ----------
  function fitViewport() {
    const vv = window.visualViewport;
    if (vv) {
      document.documentElement.style.setProperty('--app-h', vv.height + 'px');
      window.scrollTo(0, 0);
    }
  }
  if (window.visualViewport) {
    visualViewport.addEventListener('resize', () => { const nb = nearBottom(); fitViewport(); if (nb) toBottom(); });
    visualViewport.addEventListener('scroll', fitViewport);
    fitViewport();
  }

  // ---------- join ----------
  const savedNick = localStorage.getItem('chat.nick') || '';
  const savedPass = localStorage.getItem('chat.pass') || '';
  $('nick').value = savedNick;
  if (savedPass) { $('pass').value = savedPass; $('remember').checked = true; }

  // Invite link: https://site/#k=<key>. The fragment never reaches the server; remove it from the address bar at once.
  const hm = /^#k=([^&]+)/.exec(location.hash);
  if (hm) {
    let k = ''; try { k = decodeURIComponent(hm[1]); } catch {}
    history.replaceState(null, '', location.pathname + location.search);
    if (k) { $('pass').value = normKey(k); $('remember').checked = false; $('inviteNote').hidden = false; updateKeyHint(); setTimeout(() => $(savedNick ? 'joinBtn' : 'nick').focus(), 50); }
  }

  function updateKeyHint() {
    const v = normKey($('pass').value), h = $('keyHint');
    if (!v) { h.hidden = true; return; }
    h.hidden = false;
    if (isGenKey(v)) { h.textContent = 'Случайный ключ: подобрать его невозможно.'; h.classList.remove('weak'); }
    else if (weakKey(v)) { h.textContent = 'Слабый ключ: его можно подобрать. Лучше нажмите «создать новый».'; h.classList.add('weak'); }
    else h.hidden = true;
  }
  $('pass').addEventListener('input', updateKeyHint);
  $('showKey').addEventListener('click', () => {
    const show = $('pass').type === 'password';
    $('pass').type = show ? 'text' : 'password'; $('pass').classList.toggle('shown', show);
    $('showKey').textContent = show ? 'скрыть' : 'показать';
  });
  $('genKey').addEventListener('click', () => {
    $('pass').value = genKey(); $('pass').type = 'text'; $('pass').classList.add('shown'); $('showKey').textContent = 'скрыть';
    updateKeyHint();
    $('keyHint').textContent = 'Новый ключ создан. После входа откройте «#» вверху и отправьте ссылку-приглашение.';
    $('keyHint').hidden = false; $('keyHint').classList.remove('weak');
  });

  function backToJoin(msg) {
    closeSocket(); state.nick = ''; state.room = null; state.key = null; state.keySalt = null; state.up = null; state.boot = null;
    list.textContent = ''; state.seen.clear(); state.lastAuthor = null; state.lastTs = 0; state.lastDay = ''; state.okCount = 0; state.failCount = 0;
    $('chat').hidden = true; $('join').hidden = false;
    $('joinBtn').disabled = false; $('joinBtn').textContent = 'Войти';
    $('warn').hidden = true;
    const err = $('joinError'); err.textContent = msg || ''; err.hidden = !msg;
  }

  $('joinForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const nick = $('nick').value.trim().replace(/\s+/g, ' ');
    const pass = normKey($('pass').value); // trims: mobile keyboards often add a trailing space
    const err = $('joinError');
    err.hidden = true;
    if (!window.crypto || !crypto.subtle) { showErr('Браузер не поддерживает шифрование (нужен HTTPS).'); return; }
    if (nick.length < 2) { showErr('Никнейм — минимум 2 символа.'); return; }
    if (pass.length < 6) { showErr('Ключ комнаты — минимум 6 символов.'); return; }
    if (state.blockedUntil > Date.now()) { showErr(blockedText(Math.ceil((state.blockedUntil - Date.now()) / 1000))); return; }
    state.nick = nick; state.pass = pass;
    localStorage.setItem('chat.nick', nick);
    if ($('remember').checked) localStorage.setItem('chat.pass', pass); else localStorage.removeItem('chat.pass');
    $('joinBtn').disabled = true; $('joinBtn').textContent = 'Подключение…';
    $('join').hidden = true; $('chat').hidden = false;
    $('me').textContent = nick;
    setConn('connecting', '');
    deriveRoomId(pass).then((r) => { state.room = r; connect(); })
      .catch(() => { setConn('closed', 'ошибка шифрования — обновите страницу'); });
    setTimeout(() => { if (!matchMedia('(hover:none)').matches) $('input').focus(); }, 50);
    function showErr(t) { err.textContent = t; err.hidden = false; }
  });
  const blockedText = (s) => `Слишком много попыток войти с разными ключами. Повторите через ${s >= 90 ? Math.ceil(s / 60) + ' мин' : s + ' с'}.`;

  $('leave').addEventListener('click', () => {
    localStorage.removeItem('chat.pass');
    closeSocket();
    location.reload();
  });

  // ---------- socket ----------
  function setConn(s, text) { $('conn').dataset.state = s; $('chat').dataset.conn = s; $('connText').textContent = text; }

  let reconnectTimer = null, hbTimer = null, pongTimer = null, hideTimer = null;
  const touch = matchMedia('(hover:none)').matches;

  // Exactly one socket per tab: never open a new one while one is connecting/open.
  async function connect() {
    clearTimeout(reconnectTimer); reconnectTimer = null;
    if (!state.nick || !state.room || state.paused || state.connecting || state.blockedUntil > Date.now()) return;
    if (state.ws && state.ws.readyState <= 1) return;
    state.connecting = true;
    setConn('connecting', 'проверка');
    let pw;
    try { pw = await solvePow(); }
    catch { state.connecting = false; setConn('closed', 'нет связи, повтор…'); scheduleReconnect(); return; }
    state.connecting = false;
    if (!state.nick || state.paused || (state.ws && state.ws.readyState <= 1)) return;
    setConn('connecting', 'соединение');
    // Nothing identifying goes into the URL (it would end up in proxy logs): room/ids/proof travel in the first message.
    const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws');
    state.ws = ws;
    // connection timeout: no 'hello' within 10 s -> drop and retry (never spin forever)
    clearTimeout(state.connTimer);
    state.connTimer = setTimeout(() => {
      if (state.ws !== ws || state.gotHello) return;
      closeSocket(); state.fails = (state.fails || 0) + 1;
      setConn('closed', 'нет ответа, повтор…'); scheduleReconnect();
    }, 10000);
    state.gotHello = false;
    ws.onopen = () => {
      if (state.ws !== ws) return;
      state.retry = 0;
      ws.send(JSON.stringify({ type: 'join', v: PROTO, room: state.room, cid, tid, pow: pw }));
      startHeartbeat();
    };
    ws.onmessage = (ev) => {
      if (state.ws !== ws) return;
      clearTimeout(pongTimer); pongTimer = null;
      let m; try { m = JSON.parse(ev.data); } catch { return; }
      handle(m);
    };
    ws.onclose = (ev) => {
      clearTimeout(state.connTimer);
      if (state.ws !== ws) return;
      if (ev.code === 4001 && forceReload()) return;
      state.ws = null; state.up = null; stopHeartbeat();
      $('sendBtn').disabled = true; updateSend();
      if (ev.code === 4029 || ev.code === 4002) return; // blocked / chat wiped: handled by the message, no reconnect
      setConn('closed', 'нет связи, повтор…');
      scheduleReconnect();
    };
  }
  function scheduleReconnect() {
    if (reconnectTimer || state.paused) return;
    const delay = Math.min(15000, 600 * 2 ** state.retry++) + Math.random() * 400;
    reconnectTimer = setTimeout(connect, delay);
  }
  function closeSocket() {
    clearTimeout(reconnectTimer); reconnectTimer = null; stopHeartbeat();
    const ws = state.ws; state.ws = null;
    if (ws) { ws.onclose = ws.onmessage = ws.onopen = null; try { ws.close(1000, 'bye'); } catch {} }
  }
  // App-level heartbeat: detects sockets that died silently (phone sleep, network switch).
  function startHeartbeat() {
    stopHeartbeat();
    hbTimer = setInterval(probe, 20000);
  }
  function stopHeartbeat() { clearInterval(hbTimer); clearTimeout(pongTimer); hbTimer = pongTimer = null; }
  function probe() {
    const ws = state.ws;
    if (!ws || ws.readyState !== 1 || pongTimer) return;
    try { ws.send('{"type":"ping"}'); } catch {}
    pongTimer = setTimeout(() => { pongTimer = null; if (state.ws === ws) { closeSocket(); setConn('closed', 'нет связи'); connect(); } }, 6000);
  }
  function resume() {
    clearTimeout(hideTimer); hideTimer = null;
    state.paused = false;
    if (!state.nick) return;
    if (state.ws && state.ws.readyState === 1) probe();
    else if (!state.ws || state.ws.readyState > 1) { state.retry = 0; connect(); }
  }
  window.addEventListener('pagehide', () => { state.paused = true; closeSocket(); cancelRec(); });
  window.addEventListener('pageshow', resume);
  window.addEventListener('online', resume);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') resume();
    else if (touch && state.nick) {
      // Phones freeze background tabs; leave cleanly instead of becoming a ghost.
      clearTimeout(hideTimer);
      hideTimer = setTimeout(() => { if (document.visibilityState === 'hidden') { state.paused = true; closeSocket(); cancelRec(); } }, 3000);
    }
  });

  let queue = Promise.resolve();
  function handle(m) {
    // keep order: process sequentially since decrypt is async
    queue = queue.then(() => process(m)).catch(() => {});
  }

  async function process(m) {
    if (m.type === 'reload' || (m.type === 'error' && m.code === 'proto')) { forceReload(); return; }
    if (m.type === 'blocked') {
      state.blockedUntil = Date.now() + (+m.retry || 300) * 1000;
      backToJoin(blockedText(+m.retry || 300)); return;
    }
    if (m.type === 'wiped') { await wipeLocalData(); backToJoin('Чат удалён: все сообщения и файлы стёрты на сервере.'); return; }
    if (m.type === 'hello') {
      state.gotHello = true; state.fails = 0; clearTimeout(state.connTimer);
      state.up = m.up; if (m.lim && m.lim.blob) state.lim = m.lim;
      if (!state.key || state.keySalt !== m.salt) {
        state.key = null; state.keySalt = null; updateSend(); // never encrypt with a key for another salt
        setConn('connecting', 'ключ…');
        const { key, fp } = await deriveKey(state.pass, m.salt);
        state.key = key; state.keySalt = m.salt;
        $('fp').textContent = fp; $('fp').title = 'Отпечаток комнаты — у всех с тем же ключом он одинаковый';
      }
      state.salt = m.salt;
      if (state.boot !== m.boot) {
        // server restarted (ids start over, DB may be empty): rebuild the list from scratch
        state.boot = m.boot;
        list.textContent = ''; state.seen.clear();
        state.lastAuthor = null; state.lastTs = 0; state.lastDay = ''; state.okCount = 0; state.failCount = 0;
      }
      const nb = nearBottom();
      for (const h of m.history) await addMessage(h, false);
      updateEmpty();
      checkKey();
      setConn('open', m.count + ' в сети');
      updateSend();
      if (nb || m.history.length) toBottom();
    } else if (m.type === 'msg') {
      await addMessage(m, true);
      updateEmpty();
      checkKey();
    } else if (m.type === 'pong') {
      // heartbeat reply
    } else if (m.type === 'online') {
      if (state.key) setConn('open', m.count + ' в сети');
    } else if (m.type === 'typing') {
      const o = await open(m.iv, m.ct);
      if (o && typeof o.n === 'string' && o.c !== cid) { state.typers.set(o.n.slice(0, 24), Date.now()); renderTyping(); }
    } else if (m.type === 'error') {
      flash(m.code === 'rate' ? 'Слишком часто. Подождите пару секунд.' : m.code === 'full' ? 'Сервер заполнен, сообщение не сохранено.' : 'Сообщение отклонено сервером.');
    }
  }

  // ---------- rendering (no innerHTML for user content) ----------
  const list = $('list'), scroller = $('scroller');
  const fmtTime = new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit' });
  const fmtDay = new Intl.DateTimeFormat('ru-RU', { day: 'numeric', month: 'long' });
  const fmtDayY = new Intl.DateTimeFormat('ru-RU', { day: 'numeric', month: 'long', year: 'numeric' });

  function dayLabel(d) {
    const today = new Date(); const y = new Date(); y.setDate(today.getDate() - 1);
    if (d.toDateString() === today.toDateString()) return 'Сегодня';
    if (d.toDateString() === y.toDateString()) return 'Вчера';
    return d.getFullYear() === today.getFullYear() ? fmtDay.format(d) : fmtDayY.format(d);
  }

  function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }

  function linkify(parent, text) {
    const re = /\bhttps?:\/\/[^\s<>"']+[^\s<>"'.,;:!?)\]]/g;
    let i = 0, m;
    while ((m = re.exec(text))) {
      if (m.index > i) parent.appendChild(document.createTextNode(text.slice(i, m.index)));
      const a = el('a', null, m[0]);
      try { const u = new URL(m[0]); if (u.protocol === 'http:' || u.protocol === 'https:') { a.href = u.href; a.target = '_blank'; a.rel = 'noopener noreferrer nofollow'; } } catch {}
      parent.appendChild(a);
      i = m.index + m[0].length;
    }
    if (i < text.length) parent.appendChild(document.createTextNode(text.slice(i)));
  }

  // ---------- media (photos / voice) ----------
  const objectUrls = [];
  const blobUrl = (bytes, mime) => { const u = URL.createObjectURL(new Blob([bytes], { type: mime })); objectUrls.push(u); return u; };
  const IMG_TYPES = ['image/webp', 'image/jpeg'], AUD_TYPES = ['audio/webm', 'audio/ogg', 'audio/mp4'];
  const fail = (code) => Object.assign(new Error(code), { code });
  const fmtDur = (s) => { s = Math.max(0, Math.round(+s || 0)); return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); };

  // Ciphertext is kept in Cache Storage so a photo is downloaded once; wiped with the chat.
  async function fetchBlob(id) {
    const key = '/api/blob/' + id;
    let cache = null;
    try { cache = await caches.open(MEDIA_CACHE); const hit = await cache.match(key); if (hit) return new Uint8Array(await hit.arrayBuffer()); } catch {}
    if (!state.up) throw fail('auth');
    const r = await fetch(key, { headers: { 'x-up': state.up }, cache: 'no-store' });
    if (r.status === 404) throw fail('gone');
    if (!r.ok) throw fail('net');
    const buf = await r.arrayBuffer();
    try { if (cache) await cache.put(key, new Response(buf.slice(0))); } catch {}
    return new Uint8Array(buf);
  }

  const lazy = 'IntersectionObserver' in window
    ? new IntersectionObserver((es) => { for (const e of es) if (e.isIntersecting) { lazy.unobserve(e.target); if (e.target._load) e.target._load(); } }, { root: scroller_(), rootMargin: '300px' })
    : null;
  function scroller_() { return document.getElementById('scroller'); }

  function renderImage(o, live) {
    const box = el('div', 'media');
    const ph = el('div', 'ph', 'Фото…'); box.appendChild(ph);
    const w = Math.min(4000, Math.max(0, +o.w | 0)), h = Math.min(4000, Math.max(0, +o.h | 0));
    if (w && h) { box.style.width = Math.min(320, w) + 'px'; box.style.aspectRatio = w + ' / ' + h; }
    const mime = IMG_TYPES.includes(o.mt) ? o.mt : 'image/jpeg';
    const load = async () => {
      ph.textContent = 'Фото…'; ph.onclick = null;
      try {
        const url = blobUrl(await openBytes(await fetchBlob(o.b)), mime);
        const img = new Image(); img.alt = 'фото'; img.decoding = 'async';
        img.onload = () => { box.replaceChildren(img); box.style.aspectRatio = ''; if (live && nearBottom()) toBottom(); };
        img.onerror = () => { ph.textContent = 'не удалось показать'; };
        img.onclick = () => openViewer(url);
        img.src = url;
      } catch (e) { ph.textContent = e.code === 'gone' ? 'файл удалён с сервера' : 'не загрузилось, нажмите ещё раз'; if (e.code !== 'gone') ph.onclick = load; }
    };
    box._load = load;
    if (lazy) lazy.observe(box); else load();
    return box;
  }
  function openViewer(url) {
    const v = el('div', 'viewer'); const img = new Image(); img.src = url; v.appendChild(img);
    const close = () => { v.remove(); document.removeEventListener('keydown', onKey); };
    const onKey = (e) => { if (e.key === 'Escape') close(); };
    v.onclick = close; document.addEventListener('keydown', onKey); document.body.appendChild(v);
  }

  let playing = null;
  function renderVoice(o) {
    const wrap = el('div', 'voice');
    const btn = el('button', null, '▶'); btn.type = 'button'; btn.setAttribute('aria-label', 'Воспроизвести');
    const bar = el('div', 'bar'), fill = el('i'); bar.appendChild(fill);
    wrap.append(btn, bar, el('span', 'dur', fmtDur(o.d)));
    const mime = AUD_TYPES.includes(o.mt) ? o.mt : 'audio/webm';
    let audio = null, loading = false;
    btn.onclick = async () => {
      if (audio && !audio.paused) { audio.pause(); return; }
      if (!audio) {
        if (loading) return; loading = true; btn.textContent = '…';
        try {
          audio = new Audio(blobUrl(await openBytes(await fetchBlob(o.b)), mime));
          audio.onplay = () => { if (playing && playing !== audio) playing.pause(); playing = audio; btn.textContent = '❚❚'; };
          audio.onpause = () => { btn.textContent = '▶'; };
          audio.onended = () => { btn.textContent = '▶'; fill.style.width = '0'; };
          audio.ontimeupdate = () => { const t = +o.d || audio.duration; if (t && isFinite(t)) fill.style.width = Math.min(100, audio.currentTime / t * 100) + '%'; };
        } catch (e) { btn.textContent = '!'; btn.title = e.code === 'gone' ? 'файл удалён с сервера' : 'не загрузилось'; loading = false; return; }
        loading = false;
      }
      audio.play().catch(() => { btn.textContent = '▶'; });
    };
    return wrap;
  }

  async function addMessage(m, live) {
    if (state.seen.has(m.id)) return;
    state.seen.add(m.id);
    const o = await open(m.iv, m.ct);
    const media = o && (o.k === 'img' || o.k === 'vox') && typeof o.b === 'string' && /^[a-f0-9]{32}$/.test(o.b);
    const ok = o && typeof o.n === 'string' && (typeof o.t === 'string' || media);
    if (ok) state.okCount++; else state.failCount++;

    const nb = nearBottom();
    const d = new Date(m.ts);
    const dk = d.toDateString();
    if (dk !== state.lastDay) {
      list.appendChild(el('li', 'day', dayLabel(d)));
      state.lastDay = dk; state.lastAuthor = null;
    }
    const author = ok ? o.n.slice(0, 24) + '\u0000' + (o.c || '') : '\u0000locked';
    const first = author !== state.lastAuthor || m.ts - state.lastTs > 5 * 60 * 1000;
    state.lastAuthor = author; state.lastTs = m.ts;

    const mine = ok && o.c === cid;
    const li = el('li', 'msg' + (first ? ' first' : '') + (mine ? ' mine' : '') + (ok ? '' : ' locked'));
    const time = fmtTime.format(d);
    li.appendChild(el('span', 'time', time));
    const body = el('div', 'body');
    if (first) {
      const head = el('div', 'head');
      head.appendChild(el('span', 'nick', ok ? o.n.slice(0, 24) : 'зашифровано'));
      if (mine) head.appendChild(el('span', 'you', 'вы'));
      head.appendChild(el('span', 't', time));
      body.appendChild(head);
    }
    if (ok && media) body.appendChild(o.k === 'img' ? renderImage(o, live) : renderVoice(o));
    if (!ok || (typeof o.t === 'string' && o.t)) {
      const text = el('div', 'text');
      if (ok) linkify(text, o.t.slice(0, MAX_LEN)); else text.textContent = '[не удалось расшифровать — другой ключ]';
      body.appendChild(text);
    }
    li.appendChild(body);
    li.title = d.toLocaleString('ru-RU');
    list.appendChild(li);

    if (live) {
      if (mine || nb) toBottom(); else $('jump').hidden = false;
      if (ok && !mine && document.hidden) bumpTitle();
    }
  }

  function checkKey() {
    const w = $('warn');
    if (state.failCount > 0 && state.okCount === 0) {
      w.textContent = 'Похоже, ваш ключ не совпадает с ключом остальных участников: их сообщения не расшифровываются. Нажмите «выйти» и введите ключ заново.';
      w.hidden = false;
    } else w.hidden = true;
  }
  function updateEmpty() { $('empty').hidden = list.children.length > 0; }

  function nearBottom() { return scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 80; }
  function toBottom() { requestAnimationFrame(() => { scroller.scrollTop = scroller.scrollHeight; }); $('jump').hidden = true; }
  scroller.addEventListener('scroll', () => { if (nearBottom()) $('jump').hidden = true; }, { passive: true });
  $('jump').addEventListener('click', toBottom);

  let unread = 0; const baseTitle = document.title;
  function bumpTitle() { unread++; document.title = `(${unread}) ${baseTitle}`; }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) { unread = 0; document.title = baseTitle; } });

  function flash(t, info) {
    const ty = $('typing'); ty.textContent = t; ty.style.color = info ? 'var(--fg-2)' : 'var(--danger)';
    clearTimeout(flash.t); flash.t = setTimeout(() => { ty.style.color = ''; renderTyping(); }, info ? 8000 : 2500);
    if (info && !t) { ty.style.color = ''; renderTyping(); }
  }

  function renderTyping() {
    const now = Date.now();
    for (const [n, t] of state.typers) if (now - t > 4000) state.typers.delete(n);
    const names = [...state.typers.keys()];
    const ty = $('typing');
    if (ty.style.color) return;
    ty.textContent = names.length === 0 ? '' : names.length === 1 ? `${names[0]} печатает…` : names.length <= 3 ? `${names.join(', ')} печатают…` : 'несколько человек печатают…';
    clearTimeout(state.timer);
    if (names.length) state.timer = setTimeout(renderTyping, 1000);
  }

  // ---------- composer ----------
  const input = $('input');
  if (touch) input.setAttribute('enterkeyhint', 'enter');

  function autosize() { input.style.height = 'auto'; input.style.height = Math.min(input.scrollHeight, 180) + 'px'; }
  const wsReady = () => !!(state.key && state.ws && state.ws.readyState === 1);
  function updateSend() {
    const len = input.value.length;
    $('counter').textContent = `${len} / ${MAX_LEN}`; $('counter').hidden = len < MAX_LEN - 200;
    $('sendBtn').disabled = !input.value.trim() || !wsReady();
    $('attachBtn').disabled = $('micBtn').disabled = !wsReady() || !state.up || !!rec.mr;
  }
  let lastTypingSent = 0;
  input.addEventListener('input', async () => {
    autosize(); updateSend();
    const now = Date.now();
    if (input.value.trim() && now - lastTypingSent > 2500 && wsReady()) {
      lastTypingSent = now;
      const p = await seal({ n: state.nick, c: cid });
      if (state.ws?.readyState === 1) state.ws.send(JSON.stringify({ type: 'typing', ...p }));
    }
  });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !touch && !e.isComposing) { e.preventDefault(); $('sendForm').requestSubmit(); }
  });
  $('sendForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const t = input.value.replace(/\s+$/, '').replace(/^\n+/, '');
    if (!t.trim() || !state.key || state.keySalt !== state.salt || state.ws?.readyState !== 1) return;
    if (t.length > MAX_LEN) { flash('Слишком длинное сообщение.'); return; }
    const p = await seal({ n: state.nick, t, c: cid });
    if (state.ws?.readyState !== 1) return;
    state.ws.send(JSON.stringify({ type: 'msg', ...p }));
    input.value = ''; autosize(); updateSend(); lastTypingSent = 0;
    if (touch) input.focus();
  });

  // ----- sending a photo / voice: compress -> encrypt -> upload ciphertext -> send encrypted pointer
  async function sendMedia(kind, bytes, mime, extra) {
    if (!wsReady() || !state.up) { flash('Нет соединения.'); return; }
    const sealed = await sealBytes(bytes);
    if (sealed.length > state.lim.blob) { flash('Файл слишком большой.'); return; }
    flash('Отправка…', true);
    let r;
    try { r = await fetch('/api/blob', { method: 'POST', headers: { 'x-up': state.up, 'content-type': 'application/octet-stream' }, body: sealed }); }
    catch { flash('Не удалось отправить файл.'); return; }
    if (!r.ok) { flash(r.status === 507 ? 'Хранилище сервера заполнено.' : r.status === 429 ? 'Слишком часто. Подождите.' : r.status === 413 ? 'Файл слишком большой.' : 'Не удалось отправить файл.'); return; }
    const { id } = await r.json();
    try { const c = await caches.open(MEDIA_CACHE); await c.put('/api/blob/' + id, new Response(sealed.slice())); } catch {}
    const p = await seal({ n: state.nick, c: cid, k: kind, b: id, mt: mime, ...extra });
    if (state.ws?.readyState === 1) state.ws.send(JSON.stringify({ type: 'msg', ...p }));
    flash('', true);
  }

  const WEBP = (() => { const c = document.createElement('canvas'); c.width = c.height = 1; return c.toDataURL('image/webp').startsWith('data:image/webp'); })();
  async function prepareImage(file) {
    if (!/^image\//.test(file.type)) throw new Error('type');
    const bmp = await createImageBitmap(file, { imageOrientation: 'from-image' }).catch(() => createImageBitmap(file));
    let side = IMG_MAX_SIDE;
    // Re-encoding through a canvas also strips EXIF (GPS, camera model, timestamps).
    for (let attempt = 0; attempt < 5; attempt++) {
      const sc = Math.min(1, side / Math.max(bmp.width, bmp.height));
      const w = Math.max(1, Math.round(bmp.width * sc)), h = Math.max(1, Math.round(bmp.height * sc));
      const cv = document.createElement('canvas'); cv.width = w; cv.height = h;
      const ctx = cv.getContext('2d');
      if (!WEBP) { ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, w, h); }
      ctx.drawImage(bmp, 0, 0, w, h);
      for (const q of [0.78, 0.64, 0.5]) {
        const mime = WEBP ? 'image/webp' : 'image/jpeg';
        const blob = await new Promise((r) => cv.toBlob(r, mime, q));
        if (blob && blob.size <= IMG_MAX_BYTES) { if (bmp.close) bmp.close(); return { bytes: new Uint8Array(await blob.arrayBuffer()), mime: blob.type || mime, w, h }; }
      }
      side = Math.round(side * 0.75);
    }
    throw new Error('big');
  }
  $('attachBtn').addEventListener('click', () => $('file').click());
  $('file').addEventListener('change', async () => {
    const f = $('file').files[0]; $('file').value = '';
    if (!f) return;
    try { flash('Сжатие…', true); const im = await prepareImage(f); await sendMedia('img', im.bytes, im.mime, { w: im.w, h: im.h }); }
    catch { flash('Не удалось обработать картинку.'); }
  });

  // ----- voice: Opus ~20 kbit/s mono
  const rec = { mr: null, chunks: [], stream: null, t0: 0, timer: null, mime: '' };
  const pickMime = () => ['audio/webm;codecs=opus', 'audio/ogg;codecs=opus', 'audio/mp4'].find((m) => window.MediaRecorder && MediaRecorder.isTypeSupported(m)) || '';
  async function startRec() {
    if (rec.mr) return;
    if (!window.MediaRecorder || !navigator.mediaDevices?.getUserMedia) { flash('Запись голоса не поддерживается этим браузером.'); return; }
    try { rec.stream = await navigator.mediaDevices.getUserMedia({ audio: { channelCount: 1, echoCancellation: true, noiseSuppression: true } }); }
    catch { flash('Нет доступа к микрофону.'); return; }
    rec.mime = pickMime();
    const mr = new MediaRecorder(rec.stream, { ...(rec.mime ? { mimeType: rec.mime } : {}), audioBitsPerSecond: 20000 });
    rec.chunks = []; mr.ondataavailable = (e) => { if (e.data && e.data.size) rec.chunks.push(e.data); };
    rec.mr = mr; rec.t0 = Date.now(); mr.start(250);
    $('sendForm').hidden = true; $('recBar').hidden = false; $('recTime').textContent = '0:00';
    rec.timer = setInterval(() => {
      const s = (Date.now() - rec.t0) / 1000; $('recTime').textContent = fmtDur(s);
      if (s >= VOICE_MAX_S) finishRec(true);
    }, 250);
  }
  async function finishRec(send) {
    const mr = rec.mr; if (!mr) return;
    rec.mr = null; clearInterval(rec.timer);
    const stopped = new Promise((r) => { mr.onstop = r; });
    try { mr.stop(); } catch {}
    await stopped;
    if (rec.stream) rec.stream.getTracks().forEach((t) => t.stop()); rec.stream = null;
    $('recBar').hidden = true; $('sendForm').hidden = false; updateSend();
    const dur = Math.round((Date.now() - rec.t0) / 1000);
    if (!send || dur < 1 || !rec.chunks.length) return;
    const type = (mr.mimeType || rec.mime || 'audio/webm').split(';')[0];
    const bytes = new Uint8Array(await new Blob(rec.chunks, { type }).arrayBuffer());
    await sendMedia('vox', bytes, AUD_TYPES.includes(type) ? type : 'audio/webm', { d: Math.min(dur, VOICE_MAX_S) });
  }
  function cancelRec() { if (rec.mr) finishRec(false); }
  $('micBtn').addEventListener('click', startRec);
  $('recCancel').addEventListener('click', () => finishRec(false));
  $('recSend').addEventListener('click', () => finishRec(true));

  // ---------- room dialog: invite link, wipe ----------
  const dlg = $('roomDlg');
  const inviteUrl = () => location.origin + '/#k=' + encodeURIComponent(state.pass);
  $('roomBtn').addEventListener('click', () => {
    $('fp2').textContent = $('fp').textContent;
    $('inviteLink').value = inviteUrl();
    $('shareInvite').hidden = !navigator.share;
    $('copyInvite').textContent = 'Копировать ссылку';
    resetWipeBtn();
    dlg.showModal();
  });
  $('copyInvite').addEventListener('click', async () => {
    const url = inviteUrl();
    try { await navigator.clipboard.writeText(url); }
    catch { $('inviteLink').select(); try { document.execCommand('copy'); } catch {} }
    $('copyInvite').textContent = 'Скопировано';
  });
  $('shareInvite').addEventListener('click', () => { navigator.share({ title: 'VIZARD', url: inviteUrl() }).catch(() => {}); });
  $('inviteLink').addEventListener('focus', (e) => e.target.select());

  async function wipeLocalData() {
    for (const u of objectUrls.splice(0)) URL.revokeObjectURL(u);
    if (playing) { try { playing.pause(); } catch {} playing = null; }
    try { await caches.delete(MEDIA_CACHE); } catch {}
    localStorage.removeItem('chat.pass');
  }
  $('wipeLocal').addEventListener('click', async () => { await wipeLocalData(); closeSocket(); location.reload(); });

  let wipeArm = 0;
  function resetWipeBtn() { clearTimeout(wipeArm); $('wipeRoom').textContent = 'Удалить чат для всех'; $('wipeRoom').dataset.armed = ''; }
  $('wipeRoom').addEventListener('click', () => {
    if (!$('wipeRoom').dataset.armed) {
      $('wipeRoom').dataset.armed = '1'; $('wipeRoom').textContent = 'Точно удалить? Нажмите ещё раз';
      wipeArm = setTimeout(resetWipeBtn, 5000); return;
    }
    resetWipeBtn();
    if (state.ws?.readyState === 1) { state.ws.send(JSON.stringify({ type: 'wipe' })); dlg.close(); }
    else flash('Нет соединения.');
  });
})();
