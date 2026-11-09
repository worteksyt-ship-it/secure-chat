'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder(), dec = new TextDecoder();
  const MAX_LEN = 2000;
  const ITER = 310000;

  const state = {
    nick: '', pass: '', key: null, keySalt: null, salt: null, boot: null, ws: null, retry: 0, paused: false,
    lastAuthor: null, lastTs: 0, lastDay: '', seen: new Set(),
    okCount: 0, failCount: 0, typers: new Map(), timer: null,
  };

  // client id to recognize own messages
  let cid = localStorage.getItem('chat.cid');
  const rndId = () => Array.from(crypto.getRandomValues(new Uint8Array(9)), b => b.toString(16).padStart(2, '0')).join('');
  if (!/^[a-f0-9]{8,32}$/.test(cid || '')) { cid = rndId(); localStorage.setItem('chat.cid', cid); }
  // per-tab id (survives reloads of the same tab) so the server can replace this tab's stale socket
  let tid = sessionStorage.getItem('chat.tid');
  if (!/^[a-f0-9]{8,32}$/.test(tid || '')) { tid = rndId(); sessionStorage.setItem('chat.tid', tid); }

  // ---------- PWA ----------
  if ('serviceWorker' in navigator) window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {}));
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
  // Nothing derived is cached across page loads. Returns key + short fingerprint
  // (from extra PBKDF2 output bits, not from the key itself) so people can compare.
  async function deriveKey(pass, salt) {
    const base = await crypto.subtle.importKey('raw', enc.encode(pass.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: unb64(salt), iterations: ITER, hash: 'SHA-256' }, base, 288));
    const key = await crypto.subtle.importKey('raw', bits.slice(0, 32), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    const fp = Array.from(bits.slice(32, 34), b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return { key, fp };
  }
  async function seal(obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.key, enc.encode(JSON.stringify(obj)));
    return { iv: b64(iv), ct: b64(ct) };
  }
  async function open(iv, ct) {
    try {
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, state.key, unb64(ct));
      const o = JSON.parse(dec.decode(pt));
      if (typeof o !== 'object' || !o) return null;
      return o;
    } catch { return null; }
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

  $('joinForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const nick = $('nick').value.trim().replace(/\s+/g, ' ');
    const pass = $('pass').value.trim(); // mobile keyboards often add a trailing space
    const err = $('joinError');
    err.hidden = true;
    if (!window.crypto || !crypto.subtle) { showErr('Браузер не поддерживает шифрование (нужен HTTPS).'); return; }
    if (nick.length < 2) { showErr('Никнейм — минимум 2 символа.'); return; }
    if (pass.length < 6) { showErr('Ключ комнаты — минимум 6 символов.'); return; }
    state.nick = nick; state.pass = pass;
    localStorage.setItem('chat.nick', nick);
    if ($('remember').checked) localStorage.setItem('chat.pass', pass); else localStorage.removeItem('chat.pass');
    $('joinBtn').disabled = true; $('joinBtn').textContent = 'Подключение…';
    $('join').hidden = true; $('chat').hidden = false;
    $('me').textContent = nick;
    connect();
    setTimeout(() => { if (!matchMedia('(hover:none)').matches) $('input').focus(); }, 50);
    function showErr(t) { err.textContent = t; err.hidden = false; }
  });

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
  function connect() {
    clearTimeout(reconnectTimer); reconnectTimer = null;
    if (!state.nick || state.paused) return;
    if (state.ws && state.ws.readyState <= 1) return;
    setConn('connecting', 'соединение');
    const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws?cid=' + cid + '&tid=' + tid);
    state.ws = ws;
    ws.onopen = () => { if (state.ws !== ws) return; state.retry = 0; startHeartbeat(); };
    ws.onmessage = (ev) => {
      if (state.ws !== ws) return;
      clearTimeout(pongTimer); pongTimer = null;
      let m; try { m = JSON.parse(ev.data); } catch { return; }
      handle(m);
    };
    ws.onclose = () => {
      if (state.ws !== ws) return;
      state.ws = null; stopHeartbeat();
      setConn('closed', 'нет связи');
      $('sendBtn').disabled = true;
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
  window.addEventListener('pagehide', () => { state.paused = true; closeSocket(); });
  window.addEventListener('pageshow', resume);
  window.addEventListener('online', resume);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') resume();
    else if (touch && state.nick) {
      // Phones freeze background tabs; leave cleanly instead of becoming a ghost.
      clearTimeout(hideTimer);
      hideTimer = setTimeout(() => { if (document.visibilityState === 'hidden') { state.paused = true; closeSocket(); } }, 3000);
    }
  });

  let queue = Promise.resolve();
  function handle(m) {
    // keep order: process sequentially since decrypt is async
    queue = queue.then(() => process(m)).catch(() => {});
  }

  async function process(m) {
    if (m.type === 'hello') {
      if (!state.key || state.keySalt !== m.salt) {
        state.key = null; state.keySalt = null; updateSend(); // never encrypt with a key for another salt
        setConn('connecting', 'ключ…');
        const { key, fp } = await deriveKey(state.pass, m.salt);
        state.key = key; state.keySalt = m.salt;
        $('fp').textContent = fp; $('fp').title = 'Отпечаток ключа. У всех, кто ввёл ту же фразу, он одинаковый.';
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
      setConn('open', m.count + ' онлайн');
      updateSend();
      if (nb || m.history.length) toBottom();
    } else if (m.type === 'msg') {
      await addMessage(m, true);
      updateEmpty();
      checkKey();
    } else if (m.type === 'pong') {
      // heartbeat reply
    } else if (m.type === 'online') {
      if (state.key) setConn('open', m.count + ' онлайн');
    } else if (m.type === 'typing') {
      const o = await open(m.iv, m.ct);
      if (o && typeof o.n === 'string' && o.c !== cid) { state.typers.set(o.n.slice(0, 24), Date.now()); renderTyping(); }
    } else if (m.type === 'error') {
      flash(m.code === 'rate' ? 'Слишком часто. Подождите пару секунд.' : 'Сообщение отклонено сервером.');
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

  async function addMessage(m, live) {
    if (state.seen.has(m.id)) return;
    state.seen.add(m.id);
    const o = await open(m.iv, m.ct);
    const ok = o && typeof o.n === 'string' && typeof o.t === 'string';
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
    const text = el('div', 'text');
    if (ok) linkify(text, o.t.slice(0, MAX_LEN)); else text.textContent = '[не удалось расшифровать — другой ключ]';
    body.appendChild(text);
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
      w.textContent = 'Похоже, ваш ключ не совпадает с ключом остальных участников: их сообщения не расшифровываются. Сравните отпечаток ключа рядом с «e2e» с собеседником; если отличается — нажмите «выйти» и введите фразу заново.';
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

  function flash(t) {
    const ty = $('typing'); ty.textContent = t; ty.style.color = 'var(--danger)';
    clearTimeout(flash.t); flash.t = setTimeout(() => { ty.style.color = ''; renderTyping(); }, 2500);
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
  function updateSend() {
    const len = input.value.length;
    $('counter').textContent = `${len} / ${MAX_LEN}`;
    $('sendBtn').disabled = !input.value.trim() || !state.key || !state.ws || state.ws.readyState !== 1;
  }
  let lastTypingSent = 0;
  input.addEventListener('input', async () => {
    autosize(); updateSend();
    const now = Date.now();
    if (input.value.trim() && now - lastTypingSent > 2500 && state.key && state.ws?.readyState === 1) {
      lastTypingSent = now;
      const p = await seal({ n: state.nick, c: cid });
      state.ws.send(JSON.stringify({ type: 'typing', ...p }));
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
})();
