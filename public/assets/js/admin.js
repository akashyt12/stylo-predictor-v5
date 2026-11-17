/* Admin console logic */
(function () {
  'use strict';
  WG.initParticles();
  var $ = function (id) { return document.getElementById(id); };
  var AKEY = 'wg_admin';
  var keyFilter = 'all';
  var tickTimer = null;

  function token() { return localStorage.getItem(AKEY) || ''; }
  function apiAdmin(path, opts) {
    opts = opts || {};
    opts.token = token();
    return WG.api(path, opts);
  }
  function logout() {
    localStorage.removeItem(AKEY);
    if (tickTimer) clearInterval(tickTimer);
    $('dashView').classList.add('hide');
    $('loginView').classList.remove('hide');
  }
  function fail(e) {
    if (e && e.status === 401) { logout(); WG.toast('Session expired. Login again.', 'err'); return true; }
    return false;
  }

  function showDash() {
    $('loginView').classList.add('hide');
    $('dashView').classList.remove('hide');
    refreshAll();
    if (tickTimer) clearInterval(tickTimer);
    tickTimer = setInterval(refreshLive, 3000);
  }

  // ----- login -----
  $('eye').addEventListener('click', function () {
    var p = $('pass');
    p.type = p.type === 'password' ? 'text' : 'password';
  });
  $('adminForm').addEventListener('submit', async function (e) {
    e.preventDefault();
    var errBox = $('errBox'), errMsg = $('errMsg'), btn = $('loginBtn');
    errBox.classList.add('hide');
    var pass = $('pass').value;
    if (!pass) { errMsg.textContent = 'Enter password'; errBox.classList.remove('hide'); return; }
    btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Signing in…';
    try {
      var r = await WG.api('/api/admin/login', { method: 'POST', body: { password: pass }, noAuth: true });
      localStorage.setItem(AKEY, r.token);
      WG.toast('Welcome, admin', 'ok');
      showDash();
    } catch (err) {
      errMsg.textContent = err.error || 'Login failed';
      errBox.classList.remove('hide');
      $('loginCard').classList.add('shake');
      setTimeout(function () { $('loginCard').classList.remove('shake'); }, 450);
    } finally {
      btn.disabled = false; btn.textContent = 'Sign in';
    }
  });

  // ----- stats / users -----
  async function loadStats() {
    try {
      var s = await apiAdmin('/api/admin/stats');
      $('kTotal').textContent = s.total;
      $('kActive').textContent = s.active;
      $('kOnline').textContent = s.online;
      $('kExpired').textContent = s.expired;
      $('admOnline').textContent = s.online;
    } catch (e) { fail(e); }
  }

  async function loadUsers() {
    try {
      var d = await apiAdmin('/api/admin/users');
      var users = d.users || [];
      if (!users.length) {
        $('usersBody').innerHTML = '<tr><td colspan="5" class="muted center-t" style="padding:20px">No users yet.</td></tr>';
        return;
      }
      var html = '';
      users.slice(0, 40).forEach(function (u) {
        var st = u.online ? '<span class="online"><span class="dotst on"></span>Online</span>'
                          : '<span class="offline"><span class="dotst off"></span>Offline</span>';
        html += '<tr><td><span class="keyval">' + WG.esc(u.key) + '</span></td>' +
          '<td>' + WG.esc(u.planLabel) + '</td>' +
          '<td class="mono">' + WG.esc(u.lastIp || '—') + '</td>' +
          '<td>' + WG.timeAgo(u.lastSeen) + '</td>' +
          '<td>' + st + '</td></tr>';
      });
      $('usersBody').innerHTML = html;
    } catch (e) { fail(e); }
  }

  // ----- keys -----
  var allKeys = [];
  async function loadKeys() {
    try {
      var d = await apiAdmin('/api/admin/keys');
      allKeys = d.keys || [];
      renderKeys();
    } catch (e) { fail(e); }
  }

  function statusOf(k) {
    if (k.revoked) return '<span class="tag red">Revoked</span>';
    if (k.expired) return '<span class="tag red">Expired</span>';
    if (k.online) return '<span class="online"><span class="dotst on"></span>Online</span>';
    return '<span class="tag green">Active</span>';
  }

  function renderKeys() {
    var list = allKeys.filter(function (k) {
      if (keyFilter === 'active') return !k.revoked && !k.expired;
      if (keyFilter === 'expired') return k.expired && !k.revoked;
      if (keyFilter === 'revoked') return k.revoked;
      return true;
    });
    if (!list.length) {
      $('keysBody').innerHTML = '<tr><td colspan="7" class="muted center-t" style="padding:20px">No keys here.</td></tr>';
      return;
    }
    var html = '';
    list.forEach(function (k) {
      html += '<tr>' +
        '<td><span class="keyval">' + WG.esc(k.key) + '</span></td>' +
        '<td>' + WG.esc(k.planLabel) + '</td>' +
        '<td class="muted">' + WG.esc(k.note || '—') + '</td>' +
        '<td class="small">' + WG.esc(WG.fmtDate(k.expires)) + '<br><span class="muted tiny">' + WG.fmtLeft(k.expires - Date.now()) + '</span></td>' +
        '<td class="mono">' + (k.hits || 0) + '</td>' +
        '<td>' + statusOf(k) + '</td>' +
        '<td style="white-space:nowrap">' +
          '<button class="btn ghost xs" data-act="revoke" data-id="' + WG.esc(k.id) + '">' + (k.revoked ? 'Unrevoke' : 'Revoke') + '</button> ' +
          '<button class="btn danger xs" data-act="del" data-id="' + WG.esc(k.id) + '">Del</button>' +
        '</td></tr>';
    });
    $('keysBody').innerHTML = html;
  }

  $('keysBody').addEventListener('click', async function (e) {
    var b = e.target.closest('button');
    if (!b) return;
    var id = b.getAttribute('data-id');
    var act = b.getAttribute('data-act');
    b.disabled = true;
    try {
      if (act === 'revoke') { await apiAdmin('/api/admin/keys/' + id + '/revoke', { method: 'POST' }); WG.toast('Updated', 'ok'); }
      else if (act === 'del') { if (!confirm('Delete this key permanently?')) { b.disabled = false; return; } await apiAdmin('/api/admin/keys/' + id, { method: 'DELETE' }); WG.toast('Key deleted', 'ok'); }
      await loadKeys(); await loadStats();
    } catch (err) { fail(err); b.disabled = false; }
  });

  $('keyTabs').addEventListener('click', function (e) {
    var b = e.target.closest('button');
    if (!b) return;
    keyFilter = b.getAttribute('data-f');
    Array.prototype.forEach.call($('keyTabs').children, function (x) { x.classList.toggle('on', x === b); });
    renderKeys();
  });

  // ----- generate -----
  $('genForm').addEventListener('submit', async function (e) {
    e.preventDefault();
    var btn = $('genBtn');
    btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Generating…';
    try {
      var r = await apiAdmin('/api/admin/keys', {
        method: 'POST',
        body: { plan: $('plan').value, count: parseInt($('count').value, 10) || 1, note: $('note').value }
      });
      var out = '';
      r.created.forEach(function (c) {
        out += '<div class="genrow"><span class="keyval">' + WG.esc(c.key) + '</span>' +
          '<button class="btn ghost xs" data-copy="' + WG.esc(c.key) + '">Copy</button></div>';
      });
      $('genOut').innerHTML = out;
      WG.toast(r.count + ' key(s) generated', 'ok');
      $('note').value = '';
      await loadKeys(); await loadStats();
    } catch (err) { fail(err); WG.toast(err.error || 'Failed', 'err'); }
    finally { btn.disabled = false; btn.textContent = 'Generate Keys'; }
  });

  $('genOut').addEventListener('click', function (e) {
    var b = e.target.closest('button[data-copy]');
    if (!b) return;
    var v = b.getAttribute('data-copy');
    navigator.clipboard.writeText(v).then(function () { WG.toast('Copied', 'ok'); }).catch(function () { WG.toast('Copy failed', 'err'); });
  });

  
  if ($('changePassForm')) {
    $('changePassForm').addEventListener('submit', async function (e) {
      e.preventDefault();
      var cur = $('curAdminPass').value;
      var nw = $('newAdminPass').value;
      var cfm = $('cfmAdminPass').value;
      if (!cur || !nw) { WG.toast('Enter current and new password', 'err'); return; }
      if (nw.length < 6) { WG.toast('New password must be at least 6 chars', 'err'); return; }
      if (nw !== cfm) { WG.toast('Passwords do not match', 'err'); return; }
      var btn = $('savePassBtn');
      btn.disabled = true; btn.textContent = 'Updating…';
      try {
        await apiAdmin('/api/admin/password', { method: 'POST', body: { currentPassword: cur, newPassword: nw } });
        $('curAdminPass').value = ''; $('newAdminPass').value = ''; $('cfmAdminPass').value = '';
        WG.toast('Admin password updated!', 'ok');
      } catch (err) {
        if (!fail(err)) WG.toast(err.error || 'Failed to update password', 'err');
      } finally {
        btn.disabled = false; btn.textContent = 'Update Password';
      }
    });
  }

  // ----- refresh -----
  async function refreshAll() { await loadStats(); await loadUsers(); await loadKeys(); }
  async function refreshLive() { await loadStats(); await loadUsers(); }

  $('usersRefresh').addEventListener('click', function () { loadUsers(); WG.toast('Users refreshed', 'ok'); });
  $('logoutBtn').addEventListener('click', logout);

  // ----- boot -----
  if (token()) {
    showDash();
  } else {
    $('loginView').classList.remove('hide');
  }
})();
