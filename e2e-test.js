const WebSocket = require('ws');
const { webcrypto: crypto } = require('crypto');
const URL_ = process.argv[2];
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (b) => Buffer.from(b).toString('base64'), unb64 = (s) => Buffer.from(s, 'base64');
async function key(pass, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: unb64(salt), iterations: 310000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
function client() {
  return new Promise((res) => {
    const ws = new WebSocket(URL_);
    const c = { ws, inbox: [] };
    ws.on('message', (d) => { const m = JSON.parse(d); if (m.type === 'hello') { c.salt = m.salt; res(c); } else c.inbox.push(m); });
  });
}
(async () => {
  const a = await client(), b = await client(), wrong = await client();
  const k = await key('секретная фраза', a.salt), kw = await key('другая', a.salt);
  const secret = 'Привет, это тест ' + Date.now();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, enc.encode(JSON.stringify({ n: 'Тест-А', t: secret, c: 'test' })));
  a.ws.send(JSON.stringify({ type: 'msg', iv: b64(iv), ct: b64(ct) }));
  await new Promise(r => setTimeout(r, 1500));
  const got = b.inbox.find(m => m.type === 'msg');
  const pt = JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(got.iv) }, k, unb64(got.ct))));
  console.log('B received & decrypted:', pt.t === secret, JSON.stringify(pt));
  let wrongOk = true; try { await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(got.iv) }, kw, unb64(got.ct)); } catch { wrongOk = false; }
  console.log('wrong passphrase can decrypt:', wrongOk);
  // rate limit
  for (let i = 0; i < 10; i++) a.ws.send(JSON.stringify({ type: 'msg', iv: b64(iv), ct: b64(ct) }));
  // oversize
  a.ws.send(JSON.stringify({ type: 'msg', iv: b64(iv), ct: 'A'.repeat(20000) }));
  await new Promise(r => setTimeout(r, 1500));
  console.log('errors returned to A:', a.inbox.filter(m => m.type === 'error').map(m => m.code).join(','));
  console.log('SECRET=' + secret);
  [a, b, wrong].forEach(c => c.ws.close());
})();
