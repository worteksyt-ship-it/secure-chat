// VIZARD service worker. Network-first for everything (bypassing HTTP cache), cache only as
// offline fallback. Never touches /ws, /health, /api. Bump VERSION on every protocol change.
const VERSION = 'v5';
const CACHE = 'vizard-shell-' + VERSION;
const SHELL = ['/', '/index.html', '/style.css', '/app.js', '/logo.svg', '/wordmark.svg', '/manifest.webmanifest',
  '/favicon-32.png', '/apple-touch-icon.png', '/icon-192.png', '/icon-512.png', '/icon-maskable-192.png', '/icon-maskable-512.png'];

self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL.map((u) => new Request(u, { cache: 'reload' })))).catch(() => {}));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;
  if (url.pathname.startsWith('/ws') || url.pathname.startsWith('/health') || url.pathname.startsWith('/api') || url.pathname === '/sw.js') return;
  e.respondWith(
    fetch(req, { cache: 'no-store' }).then((res) => {
      if (res.ok && res.type === 'basic') { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
      return res;
    }).catch(() => caches.match(req).then((r) => r || (req.mode === 'navigate' ? caches.match('/index.html') : Response.error())))
  );
});
