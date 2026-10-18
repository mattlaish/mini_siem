/* Alert queue: one place to triage every alert (filters, detail drawer,
   workflow, evidence, keyboard). Same hold-and-pill refresh as the dashboard. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const canTriage = $('alertQueue').dataset.canTriage === 'yes';
  // Mirrors alert_workflow.TRANSITIONS so the UI only offers moves the server accepts.
  const NEXT = {new: ['acknowledged', 'investigating', 'resolved'], acknowledged: ['investigating', 'resolved'],
                investigating: ['resolved'], resolved: ['closed', 'investigating'], closed: ['investigating']};
  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  const status = a => (a.workflow_status || 'new').toLowerCase();
  let rows = [], selected = -1, openId = null, maxId = 0;

  async function api(url, options) {
    const r = await fetch(url, options);
    let d = null;
    try { d = await r.json(); } catch (e) { /* non-JSON */ }
    if (!r.ok) throw new Error((d && d.error) || `Request failed (${r.status})`);
    return d;
  }

  // ---- filters <-> URL -----------------------------------------------------
  const FILTERS = [['status', 'fStatus'], ['severity', 'fSeverity'], ['rule', 'fRule'], ['assignee', 'fAssignee'], ['q', 'fQuery']];
  function params() {
    const p = new URLSearchParams({limit: '500'});
    FILTERS.forEach(([k, id]) => { if ($(id).value.trim()) p.set(k, $(id).value.trim()); });
    return p;
  }
  function syncUrl() {
    const u = new URLSearchParams();
    FILTERS.forEach(([k, id]) => { const v = $(id).value.trim(); if (k === 'status' ? v !== 'open' : v) u.set(k, k === 'status' && !v ? 'all' : v); });
    if (openId) u.set('id', openId);
    history.replaceState({}, '', location.pathname + (u.toString() ? '?' + u : ''));
  }
  function restore() {
    const u = new URLSearchParams(location.search);
    FILTERS.forEach(([k, id]) => {
      if (!u.has(k)) return;
      const v = u.get(k) === 'all' && k === 'status' ? '' : u.get(k);
      if (k === 'rule' && v && ![...$(id).options].some(o => o.value === v)) $(id).add(new Option(MS.label(v), v));
      $(id).value = v;
    });
    return u.get('id');
  }

  // ---- list ---------------------------------------------------------------
  // New alerts land at the top; don't shift rows under the pointer or a
  // scrolled list. The drawer is never redrawn by a refresh.
  let pointerInList = false;
  function held() {
    const sc = $('aqRows').closest('.table-scroll');
    return !!document.querySelector('dialog[open]') || pointerInList || (sc && sc.scrollTop > 8);
  }
  function occurrences(a) { return (a.detection_evidence && a.detection_evidence.occurrences) || 1; }
  function host(a) { return (a.detection_evidence && a.detection_evidence.fields && a.detection_evidence.fields['host.name']) || a.source_ip || '—'; }

  async function load(opts) {
    const background = !!(opts && opts.background);
    // Background polls must not keep an idle session alive.
    const data = await api('/api/alerts?' + params(), background ? {headers: {'X-Background-Poll': '1'}} : undefined);
    if (background && held()) {
      const fresh = data.filter(a => a.id > maxId).length;
      $('aqNewPill').textContent = fresh ? `${fresh} new ↑` : '';
      $('aqNewPill').classList.toggle('show', fresh > 0);
      return;
    }
    $('aqNewPill').classList.remove('show');
    const keep = rows[selected] && rows[selected].id;
    rows = data;
    maxId = Math.max(maxId, 0, ...rows.map(a => a.id));
    selected = keep ? rows.findIndex(a => a.id === keep) : (rows.length ? 0 : -1);
    render();
    if (!background) syncUrl();
  }
  function render() {
    const body = $('aqRows');
    $('aqCount').textContent = `${rows.length}${rows.length >= 500 ? '+' : ''} alert${rows.length === 1 ? '' : 's'}`;
    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="8" class="muted">No alerts match these filters.${$('fStatus').value === 'open' ? ' There are no open alerts in this view.' : ''}</td></tr>`;
      return;
    }
    body.innerHTML = rows.map((a, i) => `
      <tr data-i="${i}" class="${i === selected ? 'sel' : ''}" aria-selected="${i === selected}">
        <td class="msg-cell t">${MS.timeHTML(a.created_at, true)}</td>
        <td><span class="badge sev-${esc(a.severity)}">${esc(MS.label(a.severity))}</span></td>
        <td>${esc(MS.label(a.rule_name))}</td>
        <td class="msg-cell">${esc(host(a))}</td>
        <td class="desc c-desc"><div class="line">${esc(a.description)}</div></td>
        <td><span class="st st-${esc(status(a))}">${esc(MS.label(status(a)))}</span></td>
        <td>${esc(a.workflow_assignee) || '<span class="muted">—</span>'}</td>
        <td class="c-count">${occurrences(a)}</td>
      </tr>`).join('');
    body.querySelectorAll('tr[data-i]').forEach(tr => tr.addEventListener('click', () => { select(+tr.dataset.i); open(rows[+tr.dataset.i].id); }));
  }
  function select(i) {
    if (!rows.length) return;
    selected = Math.max(0, Math.min(rows.length - 1, i));
    $('aqRows').querySelectorAll('tr[data-i]').forEach(tr => {
      const on = +tr.dataset.i === selected;
      tr.classList.toggle('sel', on); tr.setAttribute('aria-selected', on);
      if (on) tr.scrollIntoView({block: 'nearest'});
    });
  }

  // ---- drawer -------------------------------------------------------------
  const PINNED = ['host.name', 'user.name', 'process.parent.name', 'process.name', 'process.command_line',
                  'process.path', 'process.parent.path', 'script.text', 'source.ip', 'message'];
  async function open(id) {
    openId = id; syncUrl();
    const drawer = $('aqDrawer');
    drawer.hidden = false; $('aqWrap').classList.add('drawer-open');
    drawer.innerHTML = '<p class="muted">Loading alert…</p>';
    try {
      const [wf, ev] = await Promise.all([api(`/api/alerts/${id}/workflow`), api(`/api/detection/alerts/${id}/evidence`)]);
      if (openId !== id) return;
      const a = {...wf.alert, ...(ev.alert || {})};
      const st = status(a);
      const fields = (a.detection_evidence && a.detection_evidence.fields) || {};
      const keyFields = PINNED.filter(k => fields[k]).map(k => `<dt title="${esc(k)}">${esc(MS.label(k))}</dt><dd>${esc(String(fields[k]).slice(0, 600))}</dd>`).join('');
      const history = (wf.events || []).map(e => `<div>${MS.timeHTML(e.at)} · <strong>${esc(e.actor)}</strong> ${esc(MS.label(e.from_status))} → ${esc(MS.label(e.to_status))}${e.assignee ? ' · assignee ' + esc(e.assignee) : ''}${e.note ? `<br><span class="muted">${esc(e.note)}</span>` : ''}</div>`).join('')
        || '<div class="muted">No status or assignment changes yet.</div>';
      const options = [st, ...(NEXT[st] || [])].map(s => `<option value="${s}"${s === st ? ' selected' : ''}>${s === st ? MS.label(s) + ' (current)' : MS.label(s)}</option>`).join('');
      const events = (ev.events || []).map(e => `#${e.id} · received ${MS.fmtTime(e.received_at)}\n${e.raw}`).join('\n\n');
      drawer.innerHTML = `
        <h2><span>Alert #${a.id}</span><button type="button" id="aqClose" aria-label="Close detail">Close</button></h2>
        <div><span class="badge sev-${esc(a.severity)}">${esc(MS.label(a.severity))}</span> <strong>${esc(MS.label(a.rule_name))}</strong></div>
        <p style="font-size:13px;line-height:1.5;">${esc(a.description)}</p>
        <dl><dt>Created</dt><dd>${MS.timeHTML(a.created_at, true)}</dd><dt>Source</dt><dd>${esc(a.source_ip || '—')}</dd>
            <dt>Occurrences</dt><dd>${occurrences(a)}</dd>${keyFields}</dl>
        ${canTriage ? `<form class="aq-form" id="aqForm">
          <label>Status<select name="status">${options}</select></label>
          <label>Assignee<input name="assignee" value="${esc(a.workflow_assignee || '')}" placeholder="unassigned"></label>
          <label>Note<textarea name="note" rows="2" placeholder="What you found / why"></textarea></label>
          <div><button type="submit" class="btn-primary">Save</button>
            <a href="/?ids=${esc(a.log_ids || '')}" style="margin-left:10px;font-size:12px;">Open related logs →</a></div>
        </form>` : `<p class="muted">Read-only: analyst or administrator role is needed to change alerts. <a href="/?ids=${esc(a.log_ids || '')}">Open related logs →</a></p>`}
        <h3 style="font-size:13px;margin:14px 0 4px;">History</h3><div class="aq-hist">${history}</div>
        <h3 style="font-size:13px;margin:14px 0 4px;">Original events</h3>
        ${events ? `<pre>${esc(events)}</pre>` : '<p class="muted">No linked events are currently available here. Check Log Search for archived evidence.</p>'}
        <p class="muted" style="font-size:11px;">${esc(ev.note || '')}</p>`;
      $('aqClose').onclick = close;
      if ($('aqForm')) $('aqForm').onsubmit = async e => {
        e.preventDefault();
        const f = e.target, body = {status: f.status.value, assignee: f.assignee.value.trim(), note: f.note.value.trim()};
        try {
          await save(id, body);
          MS.toast(`Alert #${id} saved (${MS.label(body.status)}).`, 'success');
          await load(); open(id);
        } catch (err) { MS.toast(err.message, 'error'); }
      };
    } catch (err) {
      drawer.innerHTML = `<p class="muted">${esc(err.message)}</p>`;
    }
  }
  function close() {
    openId = null; syncUrl();
    $('aqDrawer').hidden = true; $('aqWrap').classList.remove('drawer-open');
  }
  function save(id, body) {
    return api(`/api/alerts/${id}/workflow`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
  }
  async function acknowledge() {
    const a = rows[selected];
    if (!a || !canTriage) return;
    if (!(NEXT[status(a)] || []).includes('acknowledged')) { MS.toast(`Alert #${a.id} is ${status(a)}; it can't be acknowledged.`, 'error'); return; }
    try {
      await save(a.id, {status: 'acknowledged'});
      MS.toast(`Alert #${a.id} acknowledged.`, 'success');
      await load();
      if (openId === a.id) open(a.id);
    } catch (err) { MS.toast(err.message, 'error'); }
  }

  // ---- keyboard -------------------------------------------------------------
  document.addEventListener('keydown', e => {
    if (e.ctrlKey || e.metaKey || e.altKey || MS.isTyping(e.target) || document.querySelector('dialog[open]')) {
      if (e.key === 'Escape' && e.target.id === 'fQuery') e.target.blur();
      return;
    }
    if (e.key === 'j') { select(selected + 1); e.preventDefault(); }
    else if (e.key === 'k') { select(selected - 1); e.preventDefault(); }
    else if (e.key === 'Enter' && rows[selected]) { open(rows[selected].id); e.preventDefault(); }
    else if (e.key === 'a') { acknowledge(); e.preventDefault(); }
    else if (e.key === 'Escape' && openId) { close(); }
  });

  // ---- wiring ---------------------------------------------------------------
  ['fStatus', 'fSeverity', 'fRule', 'fAssignee'].forEach(id => $(id).addEventListener('change', () => load()));
  let t;
  $('fQuery').addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => load(), 250); });
  $('aqNewPill').addEventListener('click', () => { const sc = $('aqRows').closest('.table-scroll'); if (sc) sc.scrollTop = 0; pointerInList = false; load(); });
  const list = $('aqRows').closest('.table-scroll');
  list.addEventListener('mouseenter', () => { pointerInList = true; });
  list.addEventListener('mouseleave', () => { pointerInList = false; });

  (async () => {
    try {
      (await api('/api/alerts/rules')).forEach(r => $('fRule').add(new Option(MS.label(r), r)));
    } catch (e) { /* rule filter stays "All rules" */ }
    const initial = restore();
    await load();
    if (initial) open(+initial);
    let busy = false;
    const tick = () => {
      if (busy || document.hidden) return;   // no stacked polls, none in a background tab
      busy = true;
      load({background: true}).catch(() => {}).finally(() => { busy = false; });
    };
    setInterval(tick, 15000);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });
  })().catch(e => MS.toast(e.message, 'error'));
})();
