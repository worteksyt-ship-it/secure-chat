'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder(), dec = new TextDecoder();
  const MAX_LEN = 2000;
  const ITER = 310000;

  const state = {
    nick: '', pass: '', key: null, salt: null, ws: null, retry: 0,
    lastAuthor: null, lastTs: 0, lastDay: '', seen: new Set(),
    okCount: 0, failCount: 0, typers: new Map(), timer: null,
  };

  // client id to recognize own messages
  let cid = localStorage.getItem('chat.cid');
  if (!cid) { cid = Array.from(crypto.getRandomValues(new Uint8Array(9)), b => b.toString(16).padStart(2, '0')).join(''); localStorage.setItem('chat.cid', cid); }

  // ---------- crypto ----------
  const b64 = (buf) => { let s = ''; const a = new Uint8Array(buf); for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); };
  const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));

  async function deriveKey(pass, salt) {
    const base = await crypto.subtle.importKey('raw', enc.encode(pass.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: unb64(salt), iterations: ITER, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
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
    const pass = $('pass').value;
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
    location.reload();
  });

  // ---------- socket ----------
  function setConn(s, text) { $('conn').dataset.state = s; $('connText').textContent = text; }

  function connect() {
    setConn('connecting', 'соединение');
    const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws');
    state.ws = ws;
    ws.onopen = () => { state.retry = 0; };
    ws.onmessage = (ev) => { let m; try { m = JSON.parse(ev.data); } catch { return; } handle(m); };
    ws.onclose = () => {
      if (state.ws !== ws) return;
      setConn('closed', 'нет связи');
      $('sendBtn').disabled = true;
      const delay = Math.min(15000, 600 * 2 ** state.retry++) + Math.random() * 400;
      setTimeout(connect, delay);
    };
  }
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && state.ws && state.ws.readyState > 1 && state.nick) { state.retry = 0; connect(); }
  });

  let queue = Promise.resolve();
  function handle(m) {
    // keep order: process sequentially since decrypt is async
    queue = queue.then(() => process(m)).catch(() => {});
  }

  async function process(m) {
    if (m.type === 'hello') {
      if (!state.key || state.salt !== m.salt) {
        setConn('connecting', 'ключ…');
        state.salt = m.salt;
        state.key = await deriveKey(state.pass, m.salt);
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
      w.textContent = 'Похоже, ваш ключ не совпадает с ключом остальных участников: их сообщения не расшифровываются. Проверьте фразу — нажмите «выйти» и введите её заново.';
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
  const touch = matchMedia('(hover:none)').matches;
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
    if (!t.trim() || !state.key || state.ws?.readyState !== 1) return;
    if (t.length > MAX_LEN) { flash('Слишком длинное сообщение.'); return; }
    const p = await seal({ n: state.nick, t, c: cid });
    state.ws.send(JSON.stringify({ type: 'msg', ...p }));
    input.value = ''; autosize(); updateSend(); lastTypingSent = 0;
    if (touch) input.focus();
  });
})();
