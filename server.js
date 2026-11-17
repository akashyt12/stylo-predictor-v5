// Minimal .env loader (no dependency) — must run before modules read process.env.
(function loadEnv() {
  try {
    const fs = require('fs');
    const p = require('path').join(__dirname, '.env');
    if (!fs.existsSync(p)) return;
    fs.readFileSync(p, 'utf8').split(/\r?\n/).forEach(function (line) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/i);
      if (!m) return;
      let v = m[2].trim();
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
      if (process.env[m[1]] === undefined) process.env[m[1]] = v;
    });
  } catch (e) { /* ignore */ }
})();

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { load, save, backendName } = require('./lib/store');
const { sign, verify, sha256, genKey, safeEqual, rateLimit } = require('./lib/auth');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', true);
app.use(express.json({ limit: '32kb' }));

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const PREDICT_API = (process.env.PREDICT_API || 'https://wingo-api-two.vercel.app').replace(/\/+$/, '');
const ONLINE_MS = 45000;
const PUBLIC_DIR = path.join(__dirname, 'public');

const PLANS = {
  minute: { label: '1 Minute', ms: 60 * 1000 },
  hour: { label: '1 Hour', ms: 60 * 60 * 1000 },
  day: { label: '1 Day', ms: 24 * 60 * 60 * 1000 },
  week: { label: '7 Days', ms: 7 * 24 * 60 * 60 * 1000 },
  month: { label: '30 Days', ms: 30 * 24 * 60 * 60 * 1000 },
  year: { label: '1 Year', ms: 365 * 24 * 60 * 60 * 1000 }
};

function clientIp(req) {
  let ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  return ip || 'unknown';
}
function nowMs() { return Date.now(); }

// ---------------- FORTRESS SECURITY SHIELD (Anti-HTTP, Anti-cURL, Anti-Replay) ----------------
const BLOCKED_UA_REGEX = /(curl|wget|python|urllib|httpie|postman|insomnia|axios|node-fetch|go-http-client|libwww-perl|scrapy|headlesschrome|phantomjs|playwright|puppeteer|selenium|frida|xposed|burp|mitmproxy|charles|sqlmap|nikto|bot|spider|crawler)/i;
const usedNonces = new Map();

function computeClientSig(pathStr, ts, nonce, fp) {
  const raw = pathStr + '|' + ts + '|' + nonce + '|' + fp + '|STYLO-FORTRESS-V4';
  let h = 5381;
  for (let i = 0; i < raw.length; i++) h = ((h << 5) + h) ^ raw.charCodeAt(i);
  return ('00000000' + (h >>> 0).toString(16)).slice(-8).toUpperCase();
}

function fortressWall(req, res, next) {
  // 1. Strict HTTPS enforcement on Vercel / production
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host = (req.headers.host || '').split(':')[0];
  const isLocal = host === 'localhost' || host === '127.0.0.1';
  if (!isLocal && proto && proto !== 'https') {
    return res.status(403).json({ error: 'Plain HTTP is forbidden. HTTPS required.' });
  }

  // 2. Block cURL, Wget, Postman, Python, and non-browser User-Agents
  const ua = String(req.headers['user-agent'] || '');
  if (!ua || ua.length < 18 || BLOCKED_UA_REGEX.test(ua)) {
    return res.status(403).json({ error: 'Automated CLI / scraper blocked by Stylo Fortress.' });
  }

  // 3. Enforce Browser Fetch Metadata when present
  const secSite = req.headers['sec-fetch-site'];
  if (secSite && secSite !== 'same-origin' && secSite !== 'none') {
    return res.status(403).json({ error: 'Cross-origin request rejected.' });
  }

  // 4. Global IP Rate Limit (Anti-Flood)
  const rl = rateLimit(clientIp(req), 'global_fortress', 120, 60 * 1000);
  if (!rl.ok) {
    return res.status(429).json({ error: 'Rate limit exceeded. Try again in ' + rl.retry + 's.' });
  }

  // 5. Hardened Security Headers
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), usb=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  next();
}

function verifySignedApiPacket(req, res, next) {
  if (req.headers['x-frida'] || req.headers['x-forwarded-host'] !== undefined && String(req.headers['via'] || '').match(/mitm|burp|charles|proxy/i)) {
    return res.status(403).json({ error: 'Anti-Frida / MITM Shield triggered.' });
  }
  const integrity = String(req.headers['x-stylo-integrity'] || 'CLEAN-V5');
  if (integrity === 'TAMPERED') {
    return res.status(403).json({ error: 'Client runtime hook / Frida tamper detected.' });
  }
  const ts = String(req.headers['x-stylo-ts'] || '');
  const nonce = String(req.headers['x-stylo-nonce'] || '');
  const fp = String(req.headers['x-stylo-fp'] || '');
  const sig = String(req.headers['x-stylo-sig'] || '');
  const reqWall = req.headers['x-requested-with'];

  if (!ts || !nonce || !fp || !sig || reqWall !== 'StyloFortressXML') {
    return res.status(403).json({ error: 'Unsigned or raw HTTP request rejected.' });
  }
  const tsNum = parseInt(ts, 10);
  if (!tsNum || Math.abs(nowMs() - tsNum) > 45000) {
    return res.status(403).json({ error: 'Packet timestamp expired (replay protection).' });
  }
  // Cleanup old nonces & reject replays
  const now = nowMs();
  if (usedNonces.size > 5000) {
    for (const [k, exp] of usedNonces.entries()) { if (now > exp) usedNonces.delete(k); }
  }
  if (usedNonces.has(nonce)) {
    return res.status(403).json({ error: 'Replay detected: nonce already used.' });
  }
  usedNonces.set(nonce, now + 60000);

  const cleanPath = req.originalUrl.split('?')[0];
  const expected = computeClientSig(cleanPath, ts, nonce, fp);
  if (!safeEqual(sig, expected)) {
    return res.status(403).json({ error: 'Invalid packet signature.' });
  }
  req.clientFp = fp;
  req.uaHash = sha256(String(req.headers['user-agent'] || '')).slice(0, 16);
  next();
}

app.use(fortressWall);
app.use('/api', verifySignedApiPacket);

function pubKey(k) {
  const online = !k.revoked && k.expires > nowMs() && k.lastSeen && (nowMs() - k.lastSeen < ONLINE_MS);
  return {
    id: k.id,
    key: k.last4 ? 'WG-••••-••••-' + k.last4 : 'WG-••••',
    plan: k.plan,
    planLabel: (PLANS[k.plan] && PLANS[k.plan].label) || k.plan,
    note: k.note || '',
    created: k.created,
    expires: k.expires,
    expired: k.expires <= nowMs(),
    revoked: !!k.revoked,
    online: !!online,
    lastIp: k.lastIp || null,
    firstUsed: k.firstUsed || null,
    lastSeen: k.lastSeen || null,
    hits: k.hits || 0
  };
}

function bearer(req) {
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ')) return h.slice(7).trim();
  return req.headers['x-token'] || '';
}

async function requireAdmin(req, res, next) {
  const p = verify(bearer(req));
  if (!p || p.role !== 'admin') return res.status(401).json({ error: 'Admin auth required' });
  if (p.uah && p.uah !== req.uaHash) return res.status(401).json({ error: 'Session device mismatch' });
  req.admin = p;
  next();
}

async function requireUser(req, res, next) {
  const p = verify(bearer(req));
  if (!p || p.role !== 'user' || !p.kid) return res.status(401).json({ error: 'Login required' });
  if (p.fp && p.fp !== req.clientFp) return res.status(401).json({ error: 'Token bound to another device' });
  const db = await load();
  const key = db.keys.find((k) => k.id === p.kid);
  if (!key || key.revoked || key.expires <= nowMs()) {
    return res.status(401).json({ error: 'Key expired or revoked' });
  }
  key.lastSeen = nowMs();
  key.lastIp = clientIp(req);
  key.hits = (key.hits || 0) + 1;
  if (!key.firstUsed) key.firstUsed = nowMs();
  save();
  req.key = key;
  next();
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, time: Date.now(), storage: backendName(), shield: 'Fortress-V4' });
});

app.post('/api/login', async (req, res) => {
  const rl = rateLimit(clientIp(req), 'login', 15, 60 * 1000);
  if (!rl.ok) return res.status(429).json({ error: 'Too many attempts. Try in ' + rl.retry + 's.' });
  const key = String((req.body && req.body.key) || '').trim().toUpperCase();
  if (!/^WG-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key)) {
    return res.status(400).json({ error: 'Invalid key format' });
  }
  const db = await load();
  const hash = sha256(key);
  const found = db.keys.find((k) => k.hash === hash);
  if (!found) return res.status(401).json({ error: 'Key not found' });
  if (found.revoked) return res.status(403).json({ error: 'Key revoked' });
  if (found.expires <= nowMs()) return res.status(403).json({ error: 'Key expired' });

  // Optional single-device lock: bind key to first device fingerprint
  if (found.boundFp && found.boundFp !== req.clientFp) {
    return res.status(403).json({ error: 'Key is locked to another device.' });
  }
  found.boundFp = req.clientFp;
  found.lastSeen = nowMs();
  found.lastIp = clientIp(req);
  found.hits = (found.hits || 0) + 1;
  if (!found.firstUsed) found.firstUsed = nowMs();
  await save();

  const token = sign({ role: 'user', kid: found.id, plan: found.plan, fp: req.clientFp, uah: req.uaHash }, Math.min(found.expires - nowMs(), 24 * 60 * 60 * 1000));
  res.json({
    token,
    plan: found.plan,
    planLabel: (PLANS[found.plan] && PLANS[found.plan].label) || found.plan,
    expires: found.expires
  });
});

app.get('/api/me', requireUser, (req, res) => {
  res.json({
    plan: req.key.plan,
    planLabel: (PLANS[req.key.plan] && PLANS[req.key.plan].label) || req.key.plan,
    expires: req.key.expires,
    lastIp: req.key.lastIp,
    online: true
  });
});

let pCache = { ts: 0, data: null };
async function upstreamJson(pathname) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch(PREDICT_API + pathname, { signal: ctrl.signal, headers: { 'User-Agent': 'stylo-fortress-proxy' } });
    if (!r.ok) throw new Error('upstream ' + r.status);
    return await r.json();
  } finally {
    clearTimeout(t);
  }
}

app.get('/api/predict', requireUser, async (req, res) => {
  try {
    let data = pCache.data;
    if (!data || nowMs() - pCache.ts > 900) {
      data = await upstreamJson('/predict');
      pCache = { ts: nowMs(), data };
    }
    res.json(Object.assign({}, data, { _serverTime: nowMs() }));
  } catch (e) {
    if (pCache.data) return res.json(Object.assign({}, pCache.data, { _stale: true, _serverTime: nowMs() }));
    res.status(502).json({ error: 'Prediction service unavailable' });
  }
});

app.get('/api/history', requireUser, async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const data = await upstreamJson('/history?limit=' + limit);
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: 'History unavailable' });
  }
});

async function verifyAdminPass(candidate) {
  const db = await load();
  if (db.meta && db.meta.adminPassHash) {
    return safeEqual(sha256(String(candidate || '')), db.meta.adminPassHash);
  }
  return safeEqual(String(candidate || ''), ADMIN_PASSWORD);
}

app.post('/api/admin/login', async (req, res) => {
  const rl = rateLimit(clientIp(req), 'adminlogin', 8, 60 * 1000);
  if (!rl.ok) return res.status(429).json({ error: 'Too many attempts. Try in ' + rl.retry + 's.' });
  const pass = String((req.body && req.body.password) || '');
  if (!(await verifyAdminPass(pass))) return res.status(401).json({ error: 'Wrong password' });
  const token = sign({ role: 'admin', uah: req.uaHash }, 12 * 60 * 60 * 1000);
  res.json({ token });
});

app.post('/api/admin/password', requireAdmin, async (req, res) => {
  const rl = rateLimit(clientIp(req), 'adminpass', 6, 60 * 1000);
  if (!rl.ok) return res.status(429).json({ error: 'Too many attempts. Try in ' + rl.retry + 's.' });
  const cur = String((req.body && req.body.currentPassword) || '');
  const nw = String((req.body && req.body.newPassword) || '');
  if (!(await verifyAdminPass(cur))) return res.status(401).json({ error: 'Current password is incorrect' });
  if (nw.length < 6 || nw.length > 128) return res.status(400).json({ error: 'New password must be 6–128 characters' });
  const db = await load();
  if (!db.meta) db.meta = {};
  db.meta.adminPassHash = sha256(nw);
  db.meta.adminPassUpdated = nowMs();
  await save();
  res.json({ ok: true });
});

app.post('/api/admin/keys', requireAdmin, async (req, res) => {
  const b = req.body || {};
  const plan = String(b.plan || 'day');
  if (!PLANS[plan]) return res.status(400).json({ error: 'Unknown plan' });
  let count = Math.min(Math.max(parseInt(b.count, 10) || 1, 1), 50);
  const note = String(b.note || '').slice(0, 80);
  const durMs = PLANS[plan].ms;
  const db = await load();
  const created = [];
  for (let i = 0; i < count; i++) {
    let raw, hash;
    do { raw = genKey(); hash = sha256(raw); } while (db.keys.some((k) => k.hash === hash));
    const rec = {
      id: crypto.randomBytes(9).toString('hex'),
      hash,
      last4: raw.slice(-4),
      plan,
      note,
      created: nowMs(),
      expires: nowMs() + durMs,
      revoked: false,
      boundFp: null,
      lastIp: null,
      firstUsed: null,
      lastSeen: null,
      hits: 0
    };
    db.keys.push(rec);
    created.push({ id: rec.id, key: raw, plan, planLabel: PLANS[plan].label, expires: rec.expires });
  }
  await save();
  res.json({ created, count: created.length });
});

app.get('/api/admin/keys', requireAdmin, async (req, res) => {
  const db = await load();
  res.json({ keys: db.keys.slice().sort((a, b) => b.created - a.created).map(pubKey) });
});

app.post('/api/admin/keys/:id/revoke', requireAdmin, async (req, res) => {
  const db = await load();
  const k = db.keys.find((x) => x.id === req.params.id);
  if (!k) return res.status(404).json({ error: 'Not found' });
  k.revoked = !k.revoked;
  await save();
  res.json({ ok: true, revoked: k.revoked });
});

app.delete('/api/admin/keys/:id', requireAdmin, async (req, res) => {
  const db = await load();
  const before = db.keys.length;
  db.keys = db.keys.filter((x) => x.id !== req.params.id);
  if (db.keys.length === before) return res.status(404).json({ error: 'Not found' });
  await save();
  res.json({ ok: true });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const db = await load();
  const users = db.keys.filter((k) => k.firstUsed || k.lastSeen).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0)).map(pubKey);
  res.json({ users, onlineMs: ONLINE_MS, serverTime: nowMs() });
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const db = await load();
  const now = nowMs();
  res.json({
    total: db.keys.length,
    active: db.keys.filter((k) => !k.revoked && k.expires > now).length,
    online: db.keys.filter((k) => !k.revoked && k.expires > now && k.lastSeen && now - k.lastSeen < ONLINE_MS).length,
    expired: db.keys.filter((k) => k.expires <= now).length,
    revoked: db.keys.filter((k) => k.revoked).length
  });
});

app.use('/assets', express.static(path.join(PUBLIC_DIR, 'assets'), { maxAge: '1h' }));
const page = (f) => (req, res) => res.sendFile(path.join(PUBLIC_DIR, f));
app.get(['/', '/index.html'], page('index.html'));
app.get(['/login', '/login.html'], page('login.html'));
app.get(['/app', '/app.html'], page('app.html'));
app.get(['/admin', '/admin.html'], page('admin.html'));
app.use((req, res) => res.status(404).sendFile(path.join(PUBLIC_DIR, 'index.html')));

if (require.main === module) {
  load().then(() => {
    app.listen(PORT, () => {
      console.log(`\n  Stylo Predictor (Fortress V4) running: http://localhost:${PORT}\n`);
    });
  });
}

module.exports = app;
