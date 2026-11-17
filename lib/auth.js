// Auth + crypto helpers (no external deps).
const crypto = require('crypto');

const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.warn('[auth] SESSION_SECRET not set — using random (tokens reset on restart). Set it in production!');
}

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
function genKey() {
  const pick = () => ALPHABET[crypto.randomInt(0, ALPHABET.length)];
  const groups = [];
  for (let g = 0; g < 3; g++) {
    let s = '';
    for (let i = 0; i < 4; i++) s += pick();
    groups.push(s);
  }
  return 'WG-' + groups.join('-');
}

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

// Simple in-memory rate limiter.
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

module.exports = { sign, verify, sha256, genKey, safeEqual, rateLimit };
