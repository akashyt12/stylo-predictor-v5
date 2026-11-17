const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// ---------------- INLINED AUTH & CRYPTO HELPERS ----------------
const SECRET = process.env.SESSION_SECRET || 'stylo_fortress_v5_default_hmac_secret_2026_998877';
const PLAN_LIST = ['minute', 'hour', 'day', 'week', 'month', 'year'];
const EPOCH_2026 = 1767225600000; // 2026-01-01T00:00:00Z

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString('utf8');
}
function sign(payload, ttlMs) {
  const body = Object.assign({}, payload, { iat: Date.now(), exp: Date.now() + ttlMs });
  const data = b64url(JSON.stringify(body));
  const sig = crypto.createHmac('sha256', SECRET).update(data).digest('hex');
  return data + '.' + sig;
}
function verify(token) {
  if (!token || typeof token !== 'string' || token.indexOf('.') < 0) return null;
  const idx = token.lastIndexOf('.');
  const data = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  const expect = crypto.createHmac('sha256', SECRET).update(data).digest('hex');
  const a = Buffer.from(sig, 'utf8');
  const b = Buffer.from(expect, 'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let payload;
  try { payload = JSON.parse(fromB64url(data)); } catch (e) { return null; }
  if (!payload.exp || Date.now() > payload.exp) return null;
  return payload;
}
function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function toB32(num, len) {
  let s = '';
  for (let i = len - 1; i >= 0; i--) {
    s += ALPHABET[(num >>> (i * 5)) & 31];
  }
  return s;
}
function fromB32(str) {
  let n = 0;
  for (let i = 0; i < str.length; i++) {
    const idx = ALPHABET.indexOf(str[i]);
    if (idx < 0) return -1;
    n = (n << 5) | idx;
  }
  return n >>> 0;
}
function keyHmacChars(prefix6) {
  const digest = crypto.createHmac('sha256', SECRET).update('KEY:' + prefix6).digest();
  let out = '';
  for (let i = 0; i < 6; i++) out += ALPHABET[digest[i] & 31];
  return out;
}

// Generates a cryptographically signed Admin key: WG-AAAA-BBBB-CCCC
function genKey(planName) {
  const pIdx = Math.max(0, PLAN_LIST.indexOf(planName || 'day'));
  const slot10m = Math.max(0, Math.floor((Date.now() - EPOCH_2026) / 600000)) & 0x1FFFF;
  const packed20 = ((pIdx & 7) << 17) | slot10m;
  const g1 = toB32(packed20, 4);
  const s1 = ALPHABET[crypto.randomInt(0, 32)] + ALPHABET[crypto.randomInt(0, 32)];
  const mac6 = keyHmacChars(g1 + s1);
  const g2 = s1 + mac6.slice(0, 2);
  const g3 = mac6.slice(2, 6);
  return 'WG-' + g1 + '-' + g2 + '-' + g3;
}

function verifyStatelessKey(rawKey, plansObj) {
  if (!/^WG-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(rawKey)) return null;
  const parts = rawKey.slice(3).split('-');
  const g1 = parts[0], g2 = parts[1], g3 = parts[2];
  const s1 = g2.slice(0, 2);
  const macProvided = g2.slice(2, 4) + g3;
  const macExpected = keyHmacChars(g1 + s1);
  if (!safeEqual(macProvided, macExpected)) return null;
  const packed20 = fromB32(g1);
  const pIdx = (packed20 >>> 17) & 7;
  const slot10m = packed20 & 0x1FFFF;
  const plan = PLAN_LIST[pIdx] || 'day';
  const created = EPOCH_2026 + slot10m * 600000;
  const durMs = (plansObj[plan] && plansObj[plan].ms) || 86400000;
  const expires = created + durMs + 600000;
  return { plan, created, expires };
}

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
const buckets = new Map();
function rateLimit(ip, name, max, windowMs) {
  const key = name + ':' + ip;
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now > b.reset) { b = { count: 0, reset: now + windowMs }; buckets.set(key, b); }
  b.count++;
  const ok = b.count <= max;
  const retry = Math.ceil((b.reset - now) / 1000);
  return { ok, remaining: Math.max(0, max - b.count), retry };
}

// ---------------- INLINED STORAGE (ZERO DEMO KEYS) ----------------
const IS_VERCEL = !!process.env.VERCEL || !!process.env.AWS_LAMBDA_FUNCTION_NAME;
const DATA_DIR = process.env.DATA_DIR || (IS_VERCEL ? '/tmp/stylo_data' : path.join(__dirname, 'data'));
const FILE = path.join(DATA_DIR, 'db.json');
const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL || '';
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const USE_REDIS = !!(UPSTASH_URL && UPSTASH_TOKEN);
const REDIS_KEY = process.env.REDIS_KEY || 'wingo_db';
const FB_URL = (process.env.FIREBASE_DB_URL || '').replace(/\/+$/, '');
const FB_PATH = (process.env.FIREBASE_DB_PATH || 'wingo_oracle/db').replace(/^\/+|\/+$/g, '');
const USE_FB = !USE_REDIS && !!FB_URL;

let cache = null;
let writeChain = Promise.resolve();

function defaultDB() {
  return {
    keys: [],
    revokedHashes: [],
    meta: { created: Date.now() }
  };
}

async function redis(cmd) {
  const res = await fetch(UPSTASH_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + UPSTASH_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd)
  });
  if (!res.ok) throw new Error('Redis error ' + res.status);
  return res.json();
}
async function fbGet() {
  const r = await fetch(FB_URL + '/' + FB_PATH + '.json', { headers: { 'Cache-Control': 'no-cache' } });
  if (!r.ok) throw new Error('Firebase GET ' + r.status);
  const txt = await r.text();
  return txt && txt !== 'null' ? JSON.parse(txt) : null;
}
async function fbPut(obj) {
  const r = await fetch(FB_URL + '/' + FB_PATH + '.json', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(obj)
  });
  if (!r.ok) throw new Error('Firebase PUT ' + r.status);
  return r.json();
}
async function load() {
  if (cache) return cache;
  try {
    if (USE_REDIS) {
      const out = await redis(['GET', REDIS_KEY]);
      cache = out && out.result ? JSON.parse(out.result) : defaultDB();
    } else if (USE_FB) {
      const data = await fbGet();
      cache = data && typeof data === 'object' ? data : defaultDB();
    } else if (fs.existsSync(FILE)) {
      const raw = fs.readFileSync(FILE, 'utf8');
      cache = raw ? JSON.parse(raw) : defaultDB();
    } else {
      cache = defaultDB();
      await save();
    }
  } catch (e) {
    cache = defaultDB();
  }
  if (!Array.isArray(cache.keys)) cache.keys = [];
  if (!Array.isArray(cache.revokedHashes)) cache.revokedHashes = [];
  return cache;
}
function save() {
  const snapshot = JSON.parse(JSON.stringify(cache));
  writeChain = writeChain.then(async () => {
    try {
      if (USE_REDIS) await redis(['SET', REDIS_KEY, JSON.stringify(snapshot)]);
      else if (USE_FB) await fbPut(snapshot);
      else {
        if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
        fs.writeFileSync(FILE, JSON.stringify(snapshot));
      }
    } catch (e) {}
  });
  return writeChain;
}
function backendName() {
  return USE_REDIS ? 'upstash-redis' : USE_FB ? 'firebase-rtdb' : (IS_VERCEL ? 'vercel-tmp-memory' : 'local-file');
}

// ---------------- EXPRESS APP & FORTRESS SHIELD ----------------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', true);
app.use(express.json({ limit: '32kb' }));

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const PREDICT_API = (process.env.PREDICT_API || 'https://wingo-api-two.vercel.app').replace(/\/+$/, '');
const ONLINE_MS = 45000;
const PUBLIC_DIR = fs.existsSync(path.join(__dirname, 'index.html')) ? __dirname : path.join(__dirname, 'public');

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

const BLOCKED_UA_REGEX = /(curl|wget|python|urllib|httpie|postman|insomnia|axios|node-fetch|go-http-client|libwww-perl|scrapy|headlesschrome|phantomjs|playwright|puppeteer|selenium|frida|xposed|burp|mitmproxy|charles|sqlmap|nikto)/i;
const usedNonces = new Map();

function computeClientSig(pathStr, ts, nonce, fp, integrity) {
  const raw = pathStr + '|' + ts + '|' + nonce + '|' + fp + '|' + (integrity || 'CLEAN-V5') + '|STYLO-FORTRESS-V5';
  let h = 5381;
  for (let i = 0; i < raw.length; i++) h = ((h << 5) + h) ^ raw.charCodeAt(i);
  return ('00000000' + (h >>> 0).toString(16)).slice(-8).toUpperCase();
}

function fortressWall(req, res, next) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host = (req.headers.host || '').split(':')[0];
  const isLocal = host === 'localhost' || host === '127.0.0.1';
  if (!isLocal && proto && proto !== 'https') {
    return res.status(403).json({ error: 'Plain HTTP is forbidden. HTTPS required.' });
  }
  const ua = String(req.headers['user-agent'] || '');
  if (!ua || ua.length < 12 || BLOCKED_UA_REGEX.test(ua)) {
    return res.status(403).json({ error: 'Automated CLI / scraper blocked by Stylo Fortress.' });
  }
  const rl = rateLimit(clientIp(req), 'global_fortress', 180, 60 * 1000);
  if (!rl.ok) return res.status(429).json({ error: 'Rate limit exceeded. Try again in ' + rl.retry + 's.' });

  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), usb=()');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  next();
}

function verifySignedApiPacket(req, res, next) {
  if (req.headers['x-frida'] || String(req.headers['via'] || '').match(/mitm|burp|charles/i)) {
    return res.status(403).json({ error: 'Anti-Frida / MITM Shield triggered.' });
  }
  const secSite = req.headers['sec-fetch-site'];
  if (secSite && secSite !== 'same-origin' && secSite !== 'none') {
    return res.status(403).json({ error: 'Cross-origin API request rejected.' });
  }
  const integrity = String(req.headers['x-stylo-integrity'] || 'CLEAN-V5');
  if (integrity === 'TAMPERED') {
    return res.status(403).json({ error: 'Client runtime hook / Frida tamper detected.' });
  }
  const ts = String(req.headers['x-stylo-ts'] || '');
  const nonce = String(req.headers['x-stylo-nonce'] || '');
  const fp = String(req.headers['x-stylo-fp'] || '');
  const sig = String(req.headers['x-stylo-sig'] || '');

  if (!ts || !nonce || !fp || !sig) {
    return res.status(403).json({ error: 'Unsigned or raw HTTP request rejected.' });
  }
  const tsNum = parseInt(ts, 10);
  if (!tsNum || Math.abs(nowMs() - tsNum) > 60000) {
    return res.status(403).json({ error: 'Packet timestamp expired.' });
  }
  const now = nowMs();
  if (usedNonces.size > 5000) {
    for (const [k, exp] of usedNonces.entries()) { if (now > exp) usedNonces.delete(k); }
  }
  if (usedNonces.has(nonce)) {
    return res.status(403).json({ error: 'Replay detected.' });
  }
  usedNonces.set(nonce, now + 60000);

  const cleanPath = req.originalUrl.split('?')[0];
  const expected = computeClientSig(cleanPath, ts, nonce, fp, integrity);
  if (!safeEqual(sig, expected)) {
    return res.status(403).json({ error: 'Invalid packet signature.' });
  }
  req.clientFp = fp;
  req.uaHash = sha256(String(req.headers['user-agent'] || '')).slice(0, 16);
  next();
}

app.use(fortressWall);
app.get('/server.js', (req, res) => res.status(404).end());
app.use('/api', verifySignedApiPacket);

function pubKey(k) {
  const online = !k.revoked && k.expires > nowMs() && k.lastSeen && (nowMs() - k.lastSeen < ONLINE_MS);
  return {
    id: k.id,
    key: k.rawKey || (k.last4 ? 'WG-••••-••••-' + k.last4 : 'WG-••••'),
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
  req.admin = p;
  next();
}

async function requireUser(req, res, next) {
  const p = verify(bearer(req));
  if (!p || p.role !== 'user' || !p.kid) return res.status(401).json({ error: 'Login required' });
  const db = await load();
  if (p.khash && db.revokedHashes.includes(p.khash)) {
    return res.status(401).json({ error: 'Key revoked by admin' });
  }
  let key = db.keys.find((k) => k.id === p.kid);
  if (key && (key.revoked || key.expires <= nowMs())) {
    return res.status(401).json({ error: 'Key expired or revoked' });
  }
  if (!key) {
    key = { id: p.kid, plan: p.plan || 'day', expires: p.exp, lastIp: clientIp(req), lastSeen: nowMs(), hits: 1 };
  } else {
    key.lastSeen = nowMs();
    key.lastIp = clientIp(req);
    key.hits = (key.hits || 0) + 1;
    if (!key.firstUsed) key.firstUsed = nowMs();
    save();
  }
  req.key = key;
  next();
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, time: Date.now(), storage: backendName(), shield: 'Fortress-V5' });
});

app.post('/api/login', async (req, res) => {
  const rl = rateLimit(clientIp(req), 'login', 20, 60 * 1000);
  if (!rl.ok) return res.status(429).json({ error: 'Too many attempts. Try in ' + rl.retry + 's.' });
  const key = String((req.body && req.body.key) || '').trim().toUpperCase();
  if (!/^WG-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key)) {
    return res.status(400).json({ error: 'Invalid key format' });
  }
  const db = await load();
  const hash = sha256(key);
  if (db.revokedHashes.includes(hash)) {
    return res.status(403).json({ error: 'Key has been revoked by admin' });
  }
  let found = db.keys.find((k) => k.hash === hash);
  if (!found) {
    // Verify if this key was cryptographically generated by Admin Console
    const stateless = verifyStatelessKey(key, PLANS);
    if (!stateless) return res.status(401).json({ error: 'Access key not found. Contact Admin for a valid key.' });
    found = {
      id: 'k_' + hash.slice(0, 12),
      rawKey: key,
      hash,
      last4: key.slice(-4),
      plan: stateless.plan,
      note: 'Admin Key',
      created: stateless.created,
      expires: stateless.expires,
      revoked: false,
      lastIp: null,
      firstUsed: null,
      lastSeen: null,
      hits: 0
    };
    db.keys.push(found);
  }
  if (found.revoked) return res.status(403).json({ error: 'Key revoked by admin' });
  if (found.expires <= nowMs()) return res.status(403).json({ error: 'Key expired' });

  found.lastSeen = nowMs();
  found.lastIp = clientIp(req);
  found.hits = (found.hits || 0) + 1;
  if (!found.firstUsed) found.firstUsed = nowMs();
  await save();

  const token = sign({ role: 'user', kid: found.id, khash: hash, plan: found.plan, fp: req.clientFp }, Math.min(found.expires - nowMs(), 24 * 60 * 60 * 1000));
  res.json({
    token,
    key: key,
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
  const rl = rateLimit(clientIp(req), 'adminlogin', 10, 60 * 1000);
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
    do { raw = genKey(plan); hash = sha256(raw); } while (db.keys.some((k) => k.hash === hash));
    const rec = {
      id: 'k_' + hash.slice(0, 12),
      rawKey: raw,
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
  if (k.revoked && k.hash && !db.revokedHashes.includes(k.hash)) db.revokedHashes.push(k.hash);
  if (!k.revoked && k.hash) db.revokedHashes = db.revokedHashes.filter((h) => h !== k.hash);
  await save();
  res.json({ ok: true, revoked: k.revoked });
});

app.delete('/api/admin/keys/:id', requireAdmin, async (req, res) => {
  const db = await load();
  const target = db.keys.find((x) => x.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'Not found' });
  if (target.hash && !db.revokedHashes.includes(target.hash)) db.revokedHashes.push(target.hash);
  db.keys = db.keys.filter((x) => x.id !== req.params.id);
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
app.get(['/', '/index.html', '/login', '/login.html', '/app', '/app.html', '/admin', '/admin.html'], page('index.html'));
app.use((req, res) => res.status(404).sendFile(path.join(PUBLIC_DIR, 'index.html')));

if (require.main === module) {
  load().then(() => {
    app.listen(PORT, () => {
      console.log(`\n  Stylo Predictor (Fortress V5) running: http://localhost:${PORT}\n`);
    });
  });
}

module.exports = app;
