/* Predictor page logic */
(function () {
  'use strict';
  if (!WG.requireAuth()) return;
  WG.initParticles();

  var $ = function (id) { return document.getElementById(id); };
  var mode = 'size';
  var pollTimer = null;
  var lastData = null;
  var lastShown = '';
  var pending = {};
  var stats = { total: 0, win: 0, loss: 0 };
  var plan = WG.getPlan();
  var RING_C = 339.29;   // 2*pi*54
  var ACC_C = 207.35;    // 2*pi*33

  function setStatus(text, ok) {
    $('statusText').textContent = text;
    $('livePill').style.opacity = ok === false ? '.6' : '1';
  }
  function pct(v) { return (v == null) ? '—' : (v * 100).toFixed(1) + '%'; }

  function valueClass(v) {
    v = String(v || '').toUpperCase();
    if (v === 'SMALL' || v === 'RED') return 'small';
    if (v === 'VIOLET') return 'violet';
    if (v === 'BLUE') return 'blue';
    if (v === 'BIG' || v === 'GREEN') return '';
    return 'neutral';
  }

  function barRow(label, ico, probs, key, trackCls) {
    var v = probs ? probs[key] : null;
    var w = v ? Math.max(3, Math.min(100, v * 100)) : 0;
    return '<div class="bar-row"><span class="k"><i class="ico ' + ico + '"></i>' + label + '</span>' +
      '<div class="track ' + trackCls + '"><i style="width:' + w + '%"></i></div>' +
      '<span class="v">' + pct(v) + '</span></div>';
  }

  function confidence(d) {
    var pr = d.probabilities || {};
    var keys = mode === 'size' ? ['big', 'small'] : ['green', 'red', 'violet'];
    var best = 0;
    keys.forEach(function (k) { if (pr[k] != null && pr[k] > best) best = pr[k]; });
    return best ? (best * 100).toFixed(1) + '%' : '—';
  }

  function renderPrediction(d) {
    lastData = d;
    if (!d || !d.prediction) { setStatus('Waiting for data…', false); return; }
    var p = d.prediction;
    var valEl = $('resVal');
    var txt, sub;

    if (mode === 'size') {
      $('resLbl').textContent = 'Big / Small';
      txt = p.size || p.big_small || '—';
      sub = 'Colour hint: ' + (p.colour || (p.colours || []).join(' / ') || '—');
      $('bars').innerHTML =
        barRow('BIG', 'big', d.probabilities, 'big', 'red') +
        barRow('SMALL', 'small', d.probabilities, 'small', '');
    } else {
      $('resLbl').textContent = 'Colour';
      var cols = p.colours && p.colours.length ? p.colours : (p.colour ? [p.colour] : []);
      txt = cols.length ? cols.join(' + ') : '—';
      if (p.violet_alert) txt = txt + ' ⚠';
      sub = 'Size hint: ' + (p.size || '—');
      $('bars').innerHTML =
        barRow('GREEN', 'green', d.probabilities, 'green', '') +
        barRow('RED', 'red', d.probabilities, 'red', 'red') +
        barRow('VIOLET', 'violet', d.probabilities, 'violet', 'violet');
    }

    if (txt !== lastShown) {
      valEl.textContent = txt;
      valEl.className = 'val ' + valueClass(txt.split(' ')[0]);
      valEl.classList.remove('bump');
      void valEl.offsetWidth;
      valEl.classList.add('bump');
      setTimeout(function () { valEl.classList.remove('bump'); }, 260);
      lastShown = txt;
    }

    $('resSub').textContent = sub;
    $('conf').textContent = confidence(d);
    $('period').textContent = d.period || '—';

    // last pick result
    var lp = d.last_pick;
    if (lp && lp.period) {
      var hit = mode === 'size' ? lp.size_hit : lp.col_hit;
      var pick = mode === 'size' ? lp.size : (lp.colour || '—');
      $('lastPick').innerHTML = 'Last pick: <b>' + WG.esc(pick) + '</b> ' +
        (hit ? '<span class="tag win">WIN</span>' : '<span class="tag loss">LOSS</span>') +
        ' <span class="muted tiny">' + WG.esc(String(lp.period).slice(-4)) + '</span>';
      $('lastPick').classList.remove('hide');
    } else {
      $('lastPick').classList.add('hide');
    }

    // score pending predictions using latest result
    var latest = d.latest_result;
    if (latest && latest.period && pending[latest.period] && pending[latest.period] !== 'done') {
      var predicted = pending[latest.period];
      if (predicted && latest.size) {
        stats.total++;
        if (predicted === latest.size) stats.win++; else stats.loss++;
        renderStats();
      }
      pending[latest.period] = 'done';
    }
    if (d.period && p.size) pending[d.period] = p.size;

    setStatus(d._stale ? 'Live · cached' : 'Live · updating every second', !d._stale);
  }

  function renderStats() {
    $('stTotal').textContent = stats.total;
    $('stWin').textContent = stats.win;
    $('stLoss').textContent = stats.loss;
    var acc = stats.total ? stats.win / stats.total : 0;
    $('accPct').textContent = stats.total ? Math.round(acc * 100) + '%' : '—';
    var fg = $('accFg');
    if (fg) fg.style.strokeDashoffset = (ACC_C * (1 - acc)).toFixed(2);
  }

  // ---------- polling (1s) ----------
  async function poll() {
    try {
      var d = await WG.api('/api/predict');
      renderPrediction(d);
    } catch (e) {
      if (e.status === 401) { WG.clearSession(); location.replace('/login'); return; }
      setStatus('Reconnecting… (' + (e.error || 'error') + ')', false);
    }
  }
  function startPoll() {
    if (pollTimer) clearInterval(pollTimer);
    poll();
    pollTimer = setInterval(poll, 1000);
  }

  // ---------- history ----------
  function numTag(n, size) {
    var cls = String(size).toLowerCase() === 'big' ? ' big' : String(size).toLowerCase() === 'small' ? ' small' : '';
    return '<span class="num' + cls + '">' + (n == null ? '?' : n) + '</span>';
  }
  function sizeTag(s) { return '<span class="tag ' + String(s).toLowerCase() + '">' + WG.esc(s) + '</span>'; }
  function colorTag(c) {
    var parts = String(c || '').split(/[+,/]/).map(function (x) { return x.trim(); }).filter(Boolean);
    if (!parts.length) return '<span class="muted tiny">—</span>';
    return parts.map(function (x) { return '<span class="tag ' + x.toLowerCase() + '">' + WG.esc(x) + '</span>'; }).join(' ');
  }

  async function loadHistory() {
    try {
      var d = await WG.api('/api/history?limit=30');
      var items = Array.isArray(d) ? d : (d.draws || d.results || d.history || d.data || []);
      if (!items || !items.length) {
        $('histList').innerHTML = '<p class="small muted center-t" style="padding:16px">No history yet.</p>';
        return;
      }
      items = items.slice().sort(function (a, b) { return String(b.period || '').localeCompare(String(a.period || '')); });
      var html = '';
      for (var i = 0; i < items.length; i++) {
        var it = items[i];
        var colTxt = it.colour || it.color || (Array.isArray(it.colours) ? it.colours.join('+') : '');
        html += '<div class="hrow">' +
          numTag(it.number, it.size) +
          '<span class="period">' + WG.esc(String(it.period || '').slice(-8)) + '</span>' +
          '<span class="tags">' + sizeTag(it.size || '') + colorTag(colTxt) + '</span>' +
          '</div>';
      }
      $('histList').innerHTML = html;
    } catch (e) {
      if (e.status === 401) { WG.clearSession(); location.replace('/login'); return; }
      $('histList').innerHTML = '<p class="small muted center-t" style="padding:16px">History unavailable.</p>';
    }
  }

  // ---------- countdown ring ----------
  function tickCountdown() {
    var rem = 60 - (new Date().getSeconds());
    if (rem <= 0) rem = 60;
    $('countdown').textContent = WG.pad(rem);
    var ring = $('ringFg');
    if (ring) ring.style.strokeDashoffset = (RING_C * (1 - rem / 60)).toFixed(2);
    var fill = $('periodFill');
    if (fill) fill.style.width = (((60 - rem) / 60) * 100).toFixed(1) + '%';
    if (plan && plan.expires) $('keyLeft').textContent = WG.fmtLeft(plan.expires - Date.now());
  }

  // ---------- wiring ----------
  $('modeSeg').addEventListener('click', function (e) {
    var b = e.target.closest('button');
    if (!b) return;
    mode = b.getAttribute('data-mode');
    Array.prototype.forEach.call($('modeSeg').children, function (x) { x.classList.toggle('on', x === b); });
    lastShown = '';
    if (lastData) renderPrediction(lastData);
  });

  $('refreshBtn').addEventListener('click', function () { loadHistory(); WG.toast('History refreshed', 'ok'); });
  $('logoutBtn').addEventListener('click', function () { WG.clearSession(); location.replace('/login'); });

  if (plan && plan.label) $('planPill').textContent = plan.label;

  WG.api('/api/me').then(function (me) {
    if (me && me.planLabel) $('planPill').textContent = me.planLabel;
    if (me && me.expires) localStorage.setItem('wg_plan', JSON.stringify({ plan: me.plan, label: me.planLabel, expires: me.expires }));
  }).catch(function (e) { if (e.status === 401) { WG.clearSession(); location.replace('/login'); } });

  startPoll();
  loadHistory();
  setInterval(loadHistory, 12000);
  setInterval(tickCountdown, 1000);
  tickCountdown();
  renderStats();

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) { if (pollTimer) clearInterval(pollTimer); }
    else startPoll();
  });
})();
