/* mini-SIEM shell behaviors: mobile nav drawer + light/dark theme toggle.
   Kept external (not inline) so the pages can run under a strict CSP. */
(function () {
  'use strict';

  // ---- theme ----------------------------------------------------------
  var root = document.documentElement;
  function stored() { try { return localStorage.getItem('mini-siem-theme'); } catch (e) { return null; } }
  function apply(mode) {
    if (mode === 'light' || mode === 'dark') root.setAttribute('data-theme', mode);
    else root.removeAttribute('data-theme');
  }
  function current() {
    var attr = root.getAttribute('data-theme');
    if (attr) return attr;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  apply(stored());

  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('themeToggle');
    if (btn) {
      var label = function () {
        var d = current() === 'dark';
        btn.textContent = d ? '☀ Light' : '☾ Dark';
        btn.setAttribute('aria-label', d ? 'Switch to light theme' : 'Switch to dark theme');
      };
      label();
      btn.addEventListener('click', function () {
        var next = current() === 'dark' ? 'light' : 'dark';
        apply(next);
        try { localStorage.setItem('mini-siem-theme', next); } catch (e) {}
        label();
      });
    }

    // ---- mobile nav drawer -------------------------------------------
    var app = document.getElementById('app');
    var ham = document.getElementById('hamburger');
    var scrim = document.getElementById('navScrim');
    function setOpen(open) {
      if (!app) return;
      app.classList.toggle('nav-open', open);
      if (ham) ham.setAttribute('aria-expanded', open ? 'true' : 'false');
    }
    if (ham) ham.addEventListener('click', function () { setOpen(!app.classList.contains('nav-open')); });
    if (scrim) scrim.addEventListener('click', function () { setOpen(false); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') setOpen(false); });
    // Close the drawer after following a nav link on mobile.
    var nav = document.getElementById('primaryNav');
    if (nav) nav.addEventListener('click', function (e) { if (e.target.closest('a')) setOpen(false); });
  });
}());

/* Shared UI helpers (window.MS): one time format, toasts, form dialog,
   live ingestion status and keyboard search focus. */
(function () {
  'use strict';
  var MS = window.MS = window.MS || {};

  // ---- time --------------------------------------------------------------
  function pad(n) { return String(n).padStart(2, '0'); }
  function parse(iso) {
    if (!iso) return null;
    var d = new Date(iso);
    return isNaN(d.getTime()) ? null : d;
  }
  MS.fmtTime = function (iso) {           // local, unambiguous, 24h
    var d = parse(iso);
    if (!d) return iso ? String(iso) : '—';
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' +
      pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  };
  MS.fmtAgo = function (iso) {
    var d = parse(iso);
    if (!d) return '';
    var s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.round(s / 60) + ' min ago';
    if (s < 86400) return Math.round(s / 3600) + ' h ago';
    return Math.round(s / 86400) + ' d ago';
  };
  MS.utcTitle = function (iso) { var d = parse(iso); return d ? 'UTC ' + d.toISOString().replace('T', ' ').replace('.000Z', 'Z') : ''; };
  MS.timeHTML = function (iso, withAgo) {  // escaped markup for innerHTML tables
    var d = parse(iso);
    if (!d) return '—';
    var ago = withAgo ? ' <span class="muted ago">' + MS.fmtAgo(iso) + '</span>' : '';
    return '<time datetime="' + d.toISOString() + '" title="' + MS.utcTitle(iso) + '">' + MS.fmtTime(iso) + '</time>' + ago;
  };

  // ---- toasts (replace alert()) -----------------------------------------
  MS.toast = function (message, kind) {
    var box = document.getElementById('toastBox');
    if (!box) {
      box = document.createElement('div'); box.id = 'toastBox';
      box.setAttribute('role', 'status'); box.setAttribute('aria-live', 'polite');
      document.body.appendChild(box);
    }
    var t = document.createElement('div');
    t.className = 'toast toast-' + (kind || 'info');
    t.textContent = String(message);
    var close = document.createElement('button');
    close.type = 'button'; close.className = 'toast-close'; close.textContent = '×';
    close.setAttribute('aria-label', 'Dismiss');
    close.onclick = function () { t.remove(); };
    t.appendChild(close);
    box.appendChild(t);
    setTimeout(function () { t.remove(); }, kind === 'error' ? 9000 : 4500);
  };

  // ---- form dialog (replace prompt()) -----------------------------------
  // MS.form({title, fields:[{name,label,value,type:'text'|'textarea'|'select',options:[...]}], submit})
  // resolves to {name: value} or null when cancelled.
  MS.form = function (opts) {
    return new Promise(function (resolve) {
      var dlg = document.createElement('dialog'); dlg.className = 'ms-dialog';
      var form = document.createElement('form'); form.method = 'dialog';
      var h = document.createElement('h2'); h.textContent = opts.title || ''; form.appendChild(h);
      (opts.fields || []).forEach(function (f, i) {
        var label = document.createElement('label'); label.textContent = f.label || f.name;
        var el;
        if (f.type === 'textarea') { el = document.createElement('textarea'); el.rows = 3; }
        else if (f.type === 'select') {
          el = document.createElement('select');
          (f.options || []).forEach(function (o) {
            var opt = document.createElement('option');
            opt.value = typeof o === 'string' ? o : o.value;
            opt.textContent = typeof o === 'string' ? o : o.label;
            el.appendChild(opt);
          });
        } else { el = document.createElement('input'); el.type = 'text'; }
        el.name = f.name; el.value = f.value == null ? '' : f.value;
        if (f.placeholder) el.placeholder = f.placeholder;
        if (i === 0) el.autofocus = true;
        label.appendChild(el); form.appendChild(label);
      });
      var row = document.createElement('div'); row.className = 'ms-dialog-actions';
      var cancel = document.createElement('button'); cancel.type = 'button'; cancel.textContent = 'Cancel';
      var ok = document.createElement('button'); ok.type = 'submit'; ok.className = 'btn-primary'; ok.textContent = opts.submit || 'Save';
      row.appendChild(cancel); row.appendChild(ok); form.appendChild(row); dlg.appendChild(form);
      document.body.appendChild(dlg);
      var done = false;
      function finish(value) { if (done) return; done = true; dlg.close(); dlg.remove(); resolve(value); }
      cancel.onclick = function () { finish(null); };
      dlg.addEventListener('cancel', function (e) { e.preventDefault(); finish(null); });
      form.onsubmit = function (e) {
        e.preventDefault();
        var out = {};
        (opts.fields || []).forEach(function (f) { out[f.name] = form.elements.namedItem(f.name).value; });
        finish(out);
      };
      dlg.showModal();
    });
  };

  // ---- live ingestion status in the header (every page) -------------------
  var LABELS = {
    receiving: function (d) { return 'Receiving · last event ' + MS.fmtAgo(d.last_event_at) + ' · ' + d.events_last_5m + ' in 5 min'; },
    quiet: function (d) { return 'Listener up · no events for ' + MS.fmtAgo(d.last_event_at).replace(' ago', ''); },
    listener_down: function (d) { return 'Listener not reporting · last event ' + MS.fmtAgo(d.last_event_at); },
    no_data: function () { return 'No events received yet'; }
  };
  MS.ingest = null;
  async function pollIngest() {
    var el = document.getElementById('ingestStatus');
    if (!el) return;
    try {
      var r = await fetch('/api/ingest-status', { headers: { 'X-Background-Poll': '1' } });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      var d = await r.json();
      MS.ingest = d;
      el.dataset.state = d.state;
      el.querySelector('.txt').textContent = (LABELS[d.state] || LABELS.no_data)(d);
      el.title = 'Listener: ' + d.listener + (d.last_event_at ? ' · last event ' + MS.fmtTime(d.last_event_at) + ' (' + MS.utcTitle(d.last_event_at) + ')' : '') + ' · open Health';
      document.dispatchEvent(new CustomEvent('ms:ingest', { detail: d }));
    } catch (e) {
      el.dataset.state = 'unknown';
      el.querySelector('.txt').textContent = 'Ingestion status unavailable';
    }
  }

  // ---- keyboard: "/" focuses the page's search box ------------------------
  function typing(t) { return t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)); }
  MS.isTyping = typing;
  document.addEventListener('keydown', function (e) {
    if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey && !typing(e.target)) {
      var box = document.querySelector('[data-hotkey="search"]');
      if (box) { e.preventDefault(); box.focus(); box.select && box.select(); }
    }
  });

  document.addEventListener('DOMContentLoaded', function () {
    pollIngest();
    setInterval(function () { if (!document.hidden) pollIngest(); }, 15000);
    document.addEventListener('visibilitychange', function () { if (!document.hidden) pollIngest(); });
  });
}());
