// Storage abstraction: Firebase RTDB (REST) / Upstash Redis / local JSON file.
// A single in-memory DB object is kept and writes are serialized.
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
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
  return { keys: [], meta: { created: Date.now() } };
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
    } else {
      if (fs.existsSync(FILE)) {
        const raw = fs.readFileSync(FILE, 'utf8');
        cache = raw ? JSON.parse(raw) : defaultDB();
      } else {
        cache = defaultDB();
        await save();
      }
    }
  } catch (e) {
    console.error('[store] load failed:', e.message);
    cache = defaultDB();
  }
  if (!Array.isArray(cache.keys)) cache.keys = [];
  return cache;
}

function save() {
  const snapshot = JSON.parse(JSON.stringify(cache));
  writeChain = writeChain.then(async () => {
    try {
      if (USE_REDIS) {
        await redis(['SET', REDIS_KEY, JSON.stringify(snapshot)]);
      } else if (USE_FB) {
        await fbPut(snapshot);
      } else {
        if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
        fs.writeFileSync(FILE, JSON.stringify(snapshot));
      }
    } catch (e) {
      console.error('[store] save failed:', e.message);
    }
  });
  return writeChain;
}

function backendName() {
  return USE_REDIS ? 'upstash-redis' : USE_FB ? 'firebase-rtdb' : 'local-file';
}

module.exports = { load, save, backendName, USE_REDIS, USE_FB, defaultDB };
