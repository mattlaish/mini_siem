(() => {
  'use strict';
  const el = id => document.getElementById(id);
  let rates = [];
  function row(parent, values) {
    const tr = document.createElement('tr');
    values.forEach(value => { const td = document.createElement('td'); td.textContent = value; tr.append(td); });
    parent.append(tr);
  }
  async function save(next) {
    const r = await fetch('/api/ai/usage/rates', {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({rates:next})});
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Could not save rates');
    await load();
  }
  async function load() {
    try {
      const r = await fetch('/api/ai/usage?limit=30');
      const d = await r.json();
      if (!r.ok) throw new Error(r.status === 403 ? 'Usage is available to administrators.' : (d.error || 'Usage unavailable'));
      const s = d.summary, c = d.cost;
      el('usageSummary').textContent = `${s.calls} AI requests · ${s.total_tokens} tokens used · ${s.errors} failed requests · ${s.retries} automatic retries · Estimated USD ${c.estimated_usd === null ? 'not estimated' : c.estimated_usd.toFixed(6)} · ${c.unpriced_calls} requests without a price set`;
      if(!s.calls)el('usageSummary').textContent='No AI requests recorded yet. Usage remains available when analysis is off.';
      el('usageModels').replaceChildren();
      d.by_model.forEach(g => row(el('usageModels'), [g.provider+' / '+g.model,g.calls,g.input_tokens,g.cached_tokens,g.output_tokens,g.estimated_usd === null ? 'Unpriced' : g.estimated_usd.toFixed(6)]));
      el('usageCalls').replaceChildren();
      d.rows.forEach(g => row(el('usageCalls'), [MS.fmtTime(g.at),g.model,MS.label(g.status),g.total_tokens,g.latency_ms+' ms',g.retry_count]));
      rates = d.rates;
      el('usageRates').replaceChildren();
      rates.forEach((rate, i) => {
        const p = document.createElement('p');
        p.textContent = `${rate.provider} / ${rate.model}: input ${rate.input}, cached ${rate.cached}, output ${rate.output} `;
        const button = document.createElement('button'); button.type='button'; button.textContent='Remove';
        button.onclick=()=>save(rates.filter((_,n)=>n!==i)).catch(e=>el('usageSummary').textContent=e.message);
        p.append(button); el('usageRates').append(p);
      });
    } catch(e) { el('usageSummary').textContent = e.message; }
  }
  el('usageRateForm').onsubmit = async e => {
    e.preventDefault();
    const value = {provider:el('rateProvider').value.trim(), model:el('rateModel').value.trim(), input:Number(el('rateInput').value), cached:Number(el('rateCached').value), output:Number(el('rateOutput').value)};
    const next = rates.filter(r=>r.provider!==value.provider || r.model!==value.model); next.push(value);
    try { await save(next); } catch(e) { el('usageSummary').textContent=e.message; }
  };
  el('refreshUsage').onclick=load;
  load();
})();
