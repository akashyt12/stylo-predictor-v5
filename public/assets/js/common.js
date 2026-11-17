/* Shared helpers + Fortress Security Shield for Stylo Predictor */
(function () {
  'use strict';

  // Anti-Right-Click & Anti-F12 / DevTools Shortcuts
  document.addEventListener('contextmenu', function (e) { e.preventDefault(); return false; });
  document.addEventListener('keydown', function (e) {
    var k = (e.key || '').toUpperCase();
    if (e.keyCode === 123 || k === 'F12' ||
        (e.ctrlKey && e.shiftKey && (k === 'I' || k === 'J' || k === 'C' || k === 'K')) ||
        (e.metaKey && e.altKey && (k === 'I' || k === 'J' || k === 'C' || k === 'U')) ||
        (e.ctrlKey && (k === 'U' || k === 'S' || k === 'P'))) {
      e.preventDefault(); e.stopPropagation(); return false;
    }
  }, true);

  function computeFP() {
    var raw = [navigator.userAgent, navigator.language, screen.width + 'x' + screen.height, Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'].join('|');
    var h = 2166136261;
    for (var i = 0; i < raw.length; i++) { h ^= raw.charCodeAt(i); h = Math.imul(h, 16777619); }
    return ('00000000' + (h >>> 0).toString(16)).slice(-8).toUpperCase();
  }
  var FP = computeFP();

  function signHeaders(pathStr) {
    var clean = String(pathStr || '').split('?')[0];
    var ts = String(Date.now());
    var nonce = Math.random().toString(36).slice(2, 10).toUpperCase();
    var raw = clean + '|' + ts + '|' + nonce + '|' + FP + '|STYLO-FORTRESS-V4';
    var h = 5381;
    for (var i = 0; i < raw.length; i++) h = ((h << 5) + h) ^ raw.charCodeAt(i);
    var sig = ('00000000' + (h >>> 0).toString(16)).slice(-8).toUpperCase();
    return {
      'X-Stylo-Ts': ts,
      'X-Stylo-Nonce': nonce,
      'X-Stylo-FP': FP,
      'X-Stylo-Sig': sig,
      'X-Requested-With': 'StyloFortressXML'
    };
  }

  var TOKEN_KEY = 'wg_token';
  var PLAN_KEY = 'wg_plan';

  function getToken() { return localStorage.getItem(TOKEN_KEY) || ''; }
  function setSession(token, plan, planLabel, expires) {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(PLAN_KEY, JSON.stringify({ plan: plan, label: planLabel, expires: expires }));
  }
  function getPlan() {
    try { return JSON.parse(localStorage.getItem(PLAN_KEY) || 'null'); } catch (e) { return null; }
  }
  function clearSession() { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(PLAN_KEY); }

  async function api(path, opts) {
    opts = opts || {};
    var headers = Object.assign({ 'Content-Type': 'application/json' }, signHeaders(path), opts.headers || {});
    var tok = opts.token || getToken();
    if (tok && !opts.noAuth) headers['Authorization'] = 'Bearer ' + tok;
    var res;
    try {
      res = await fetch(path, {
        method: opts.method || 'GET',
        headers: headers,
        body: opts.body ? JSON.stringify(opts.body) : undefined
      });
    } catch (e) {
      throw { status: 0, error: 'Network error. Check connection.' };
    }
    var data = null;
    try { data = await res.json(); } catch (e) { data = {}; }
    if (!res.ok) {
      throw { status: res.status, error: (data && data.error) || ('Error ' + res.status), data: data };
    }
    return data;
  }

  function requireAuth() {
    if (!getToken()) { location.replace('/login'); return false; }
    return true;
  }
  function requireAdminGuard() {
    if (!localStorage.getItem('wg_admin')) { location.replace('/admin'); return false; }
    return true;
  }

  function toast(msg, type) {
    var host = document.getElementById('toasts');
    if (!host) { host = document.createElement('div'); host.id = 'toasts'; document.body.appendChild(host); }
    var el = document.createElement('div');
    el.className = 'toast ' + (type || '');
    el.innerHTML = '<span class="bar"></span><span></span>';
    el.lastChild.textContent = msg;
    host.appendChild(el);
    setTimeout(function () {
      el.style.transition = 'opacity .3s, transform .3s';
      el.style.opacity = '0';
      el.style.transform = 'translateY(8px)';
      setTimeout(function () { el.remove(); }, 320);
    }, 3400);
  }

  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function timeAgo(ts) {
    if (!ts) return '—';
    var d = Math.max(0, Math.floor((Date.now() - ts) / 1000));
    if (d < 5) return 'just now';
    if (d < 60) return d + 's ago';
    if (d < 3600) return Math.floor(d / 60) + 'm ago';
    if (d < 86400) return Math.floor(d / 3600) + 'h ago';
    return Math.floor(d / 86400) + 'd ago';
  }
  function fmtDate(ts) {
    if (!ts) return '—';
    var d = new Date(ts);
    return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  }
  function fmtLeft(ms) {
    if (ms <= 0) return 'Expired';
    var s = Math.floor(ms / 1000);
    var d = Math.floor(s / 86400); s -= d * 86400;
    var h = Math.floor(s / 3600); s -= h * 3600;
    var m = Math.floor(s / 60); s -= m * 60;
    if (d > 0) return d + 'd ' + h + 'h';
    if (h > 0) return h + 'h ' + m + 'm';
    return m + 'm ' + pad(s) + 's';
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
  }

  function initParticles() {
    var cv = document.getElementById('holoCanvas') || document.getElementById('particles');
    if (!cv) return;
    var ctx = cv.getContext('2d');
    var dots = [];
    var W, H;
    function resize() {
      W = cv.width = window.innerWidth;
      H = cv.height = window.innerHeight;
      var n = Math.min(70, Math.floor(W * H / 22000));
      dots = [];
      for (var i = 0; i < n; i++) {
        dots.push({ x: Math.random() * W, y: Math.random() * H, vx: (Math.random() - .5) * .3, vy: (Math.random() - .5) * .3, r: Math.random() * 1.6 + .4 });
      }
    }
    function frame() {
      ctx.clearRect(0, 0, W, H);
      for (var i = 0; i < dots.length; i++) {
        var d = dots[i];
        d.x += d.vx; d.y += d.vy;
        if (d.x < 0 || d.x > W) d.vx *= -1;
        if (d.y < 0 || d.y > H) d.vy *= -1;
        ctx.beginPath();
        ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(0,255,170,.45)';
        ctx.fill();
      }
      requestAnimationFrame(frame);
    }
    resize();
    window.addEventListener('resize', resize);
    frame();
  }

  window.WG = {
    getToken: getToken,
    setSession: setSession,
    getPlan: getPlan,
    clearSession: clearSession,
    api: api,
    requireAuth: requireAuth,
    requireAdminGuard: requireAdminGuard,
    toast: toast,
    timeAgo: timeAgo,
    fmtDate: fmtDate,
    fmtLeft: fmtLeft,
    pad: pad,
    esc: esc,
    initParticles: initParticles
  };
})();
