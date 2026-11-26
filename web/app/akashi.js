/* Akashi: the screens. Reads the sample network (data.js) and draws it with the app shell (app.js) and the kit (taste/).
   Everything shown is sample data and is labelled so on every screen. No model runs and no proof is checked here. */
(function () {
  'use strict';
  const S = window.Sample, T = window.Taste;
  const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const N = (x) => Number(x).toLocaleString('en-GB');
  const hms = (t) => new Date(t).toISOString().slice(11, 19);
  const hm = (t) => new Date(t).toISOString().slice(11, 16);
  const iso = (t) => new Date(t).toISOString();
  const cut = (h, a = 8, b = 6) => h.slice(0, a) + '…' + h.slice(-b);
  const pct = (x, d = 1) => (x * 100).toFixed(d) + '%';
  const HOUR = 3600e3;

  /* ---------- words for states: the word always says it, the square repeats it ---------- */
  const REQ = {
    awaiting: ['pending', 'Awaiting beacon'], unselected: ['idle', 'Not selected'], proving: ['pending', 'Proving'],
    challenged: ['pending', 'Challenged'], conformant: ['verified', 'Conformant'], deviation: ['failed', 'Deviation'],
  };
  const ROLE = { holder: 'Holder', regulator: 'Regulator', auditor: 'Independent auditor', thirdparty: 'Third party' };
  const REASON = { model: 'the reply may come from another model', altered: 'the reply may have been altered', routine: 'routine supervision' };
  const STEP_WORD = { admitted: 'Admitting', released: 'Releasing', proving: 'Proving', signed: 'Signing', published: 'Publishing' };
  function chlState(c) {
    const g = S.stage(c);
    if (g.outcome === 'refused') return ['idle', 'Refused'];
    if (g.outcome && g.finished) return g.outcome === 'deviation' ? ['failed', 'Deviation proved'] : ['verified', 'Conformant'];
    if (g.outcome) return ['pending', 'Publishing'];
    return ['pending', STEP_WORD[g.current] || 'Filed'];
  }
  const reqState = (r) => REQ[S.stateOf(r)];
  const stateHTML = (k, w, attr = '') => `<span class="state" data-state="${k}"${attr}>${w}</span>`;
  const reqStateHTML = (r) => { const [k, w] = reqState(r); return stateHTML(k, w, ` data-req="${r.id}"`); };
  const chlStateHTML = (c) => { const [k, w] = chlState(c); return stateHTML(k, w, ` data-chl="${c.id}"`); };
  const modelName = (id) => S.model(id).name;
  const shortModel = (id) => S.model(id).name.replace(/ Instruct$/, '').replace(/ 17B 128E/, '');

  // a state word that changes goes through the cipher, then its square follows
  function settleState(el, kind, word) {
    if (el.textContent === word && el.dataset.state === kind) return;
    if (el._to === word) return;
    el._to = word;
    T.cipherText(el, word).then(() => { el.dataset.state = kind; el._to = null; });
  }
  function liveStates(scope = document) {
    $$('[data-req]', scope).forEach((el) => { const r = S.find(el.dataset.req); if (r) { const [k, w] = reqState(r); settleState(el, k, w); } });
    $$('[data-chl]', scope).forEach((el) => { const c = S.challenges.find((x) => x.id === el.dataset.chl); if (c) { const [k, w] = chlState(c); settleState(el, k, w); } });
  }

  /* ---------- counts over the last hour ---------- */
  function hourStats(t = S.now()) {
    const st = { logged: 0, decided: 0, selected: 0, proved: 0, deviations: 0, selProved: 0 };
    for (const r of S.requests) {
      if (r.at > t || r.at <= t - HOUR) continue;
      st.logged++;
      const s = S.stateOf(r, t);
      if (s !== 'awaiting') st.decided++;
      if (s !== 'awaiting' && r.sel) { st.selected++; if (s === 'conformant' || s === 'deviation') st.selProved++; }
      if (s === 'conformant') st.proved++;
      if (s === 'deviation') st.deviations++;
    }
    return st;
  }
  const visible = (t = S.now()) => S.requests.filter((r) => r.at <= t);
  const loaded = new Set();
  const setVal = (scope, k, v) => { const el = $(`[data-k="${k}"]`, scope); if (!el) return; if (el.hasAttribute('data-value')) { if (el.textContent !== String(v)) App.value(el, v); } else if (el.textContent !== String(v)) el.textContent = v; };

  /* ---------- 01 overview ---------- */
  const liveRow = (r) => `<li><a class="row" href="#request/${r.short}">${reqStateHTML(r)}<span class="row-t">${esc(shortModel(r.model))}</span><span class="mono"><b>${r.short}</b> · ${hms(r.at)}</span></a></li>`;
  function verdicts(t = S.now()) {
    const out = [];
    for (const r of S.requests) {
      if (r.at > t || r.at <= t - HOUR || !r.sel || r.chl) continue;
      if (t >= r.proofAt) out.push({ t: r.proofAt, r, how: 'Sampled' });
    }
    for (const c of S.challenges) {
      const g = S.stage(c, t);
      if (g.outcome && c.req) out.push({ t: g.at('signed'), r: c.req, c, how: 'Challenge · ' + ROLE[c.role] });
      else if (g.outcome === 'refused') out.push({ t: g.at('refused'), c, how: 'Challenge refused' });
    }
    return out.sort((a, b) => b.t - a.t);
  }
  const verdictRow = (v) => v.r
    ? `<li><a class="row" href="${v.c ? '#challenge/' + v.c.id : '#request/' + v.r.short}">${reqStateHTML(v.r)}<span class="row-t">${esc(v.how)} <span class="muted">· ${esc(shortModel(v.r.model))}</span></span><span class="mono"><b>${v.r.short}</b> · ${hms(v.t)}</span></a></li>`
    : `<li><a class="row" href="#challenge/${v.c.id}">${stateHTML('idle', 'Refused')}<span class="row-t">${esc(v.how)} <span class="muted">· invalid receipt</span></span><span class="mono"><b>${v.c.ref}</b> · ${hms(v.t)}</span></a></li>`;
  function overview(screen, fresh) {
    const t = S.now(), st = hourStats(t), chl = S.challenges.filter((c) => c.at <= t && c.at > t - HOUR).length;
    const vals = [N(st.logged), N(st.selProved), N(chl)];
    if (!loaded.has('overview')) {
      loaded.add('overview');
      const l = App.loading(screen); setTimeout(() => l.done(vals), 500);
    } else ['logged', 'proved', 'challenged'].forEach((k, i) => setVal(screen, k, vals[i]));
    $('#ov-live').innerHTML = visible(t).slice(-5).reverse().map(liveRow).join('');
    if (fresh) $$('#ov-live .row .mono b').slice(0, fresh).forEach((el) => T.cipherText(el, el.textContent, { out: false }));
    $('#ov-verdicts').innerHTML = verdicts(t).slice(0, 5).map(verdictRow).join('');
  }

  /* ---------- 02 models ---------- */
  function models() {
    $('#models-t tbody').innerHTML = S.MODELS.map((m) => `<tr data-href="#model/${m.id}">
      <th scope="row"><a href="#model/${m.id}">${esc(m.name)}</a></th>
      <td class="v wide-only" data-label="Commitment"><span class="hash">${cut(m.commitment, 8, 4)}</span></td>
      <td class="n" data-label="Window">${N(m.window)}</td>
      <td class="n" data-label="Price in / out">$${m.price[0].toFixed(2)} / $${m.price[1].toFixed(2)}</td>
      <td class="n wide-only" data-label="Operators">${m.ops.length}</td>
      <td class="s" data-label="State">${m.rebuilding ? stateHTML('pending', 'Rebuilding') : stateHTML('verified', 'Serving')}</td></tr>`).join('');
  }
  function curl(m, msg = 'What is 7 + 5? Answer with the number only.', max = 64) {
    return `<span class="k">curl</span> https://gateway.akashi.example/v1/chat/completions \\
  -H <span class="s">"Authorization: Bearer $AKASHI_KEY"</span> \\
  -d <span class="s">'{
    "model": "${m.id}",
    "messages": [{ "role": "user", "content": ${esc(JSON.stringify(msg))} }],
    "max_tokens": ${max},
    "temperature": 0
  }'</span>
<span class="c"># the reply carries its receipt in the x-akashi-receipt header</span>`;
  }
  function model(screen, id) {
    const m = S.model(id); if (!m) { location.replace('#models'); return; }
    const t = S.now(), rs = S.requests.filter((r) => r.model === m.id && r.at <= t && r.at > t - HOUR);
    $('#t-model').textContent = m.name;
    $('#model-sent').textContent = m.rebuilding
      ? 'Its commitment is being rebuilt from the published weights. Until the rebuild matches, no operator may serve it.'
      : `Served by ${m.ops.length} operators, each held to one commitment. Greedy decoding only, ${N(m.window)} tokens across prompt and reply.`;
    $('#model-actions').innerHTML = m.rebuilding ? '' : `<a class="btn small" href="#traffic/${m.id}">Its traffic</a><a class="btn small solid" href="#playground/${m.id}">Try it</a>`;
    const proved = rs.filter((r) => S.stateOf(r, t) === 'conformant').length, dev = rs.filter((r) => S.stateOf(r, t) === 'deviation').length;
    $('#model-facts').innerHTML = [['Window', N(m.window), m.real ? 'F7 · tokens' : 'Sample · tokens'], ['Replies', N(rs.length), 'Sample · last hour'], ['Proved', N(proved), 'Sample · conformant'], ['Deviations', N(dev), 'Sample · proved']]
      .map(([l, v, s], i) => `<div class="keyfact"><p class="mono"><b>0${i + 1}</b> · ${l}</p><p class="val" data-value>${v}</p><p class="mono">${s}</p></div>`).join('');
    $('#model-commit-src').textContent = m.real ? 'Facts register F3 and F4' : 'Sample · not a real commitment';
    $('#model-kv').innerHTML = [
      ['Commitment', copyHTML(m.commitment, 'commitment')],
      ['Weights', `<span class="mono"><b>${esc(m.format)}</b></span>`],
      ['Render profile', `<span class="hash">${m.profile}</span>`],
      ['Decoding', '<span class="mono"><b>Greedy only</b> · temperature 0</span>'],
      ['State', m.rebuilding ? stateHTML('pending', 'Commitment rebuilding') : stateHTML('verified', 'Published and serving')],
    ].map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join('');
    $('#model-ops tbody').innerHTML = m.ops.map((oid) => {
      const o = S.op(oid), ors = rs.filter((r) => r.op === oid), odev = S.requests.some((r) => r.op === oid && r.model === m.id && S.stateOf(r, t) === 'deviation');
      return `<tr><th scope="row">${o.name}</th><td class="v wide-only" data-label="Region">${o.region}</td><td class="n" data-label="Median reply">${m.rebuilding ? 'None' : o.p50.toFixed(1) + ' s'}</td>
        <td class="n" data-label="Replies">${N(ors.length)}</td><td class="n" data-label="Proved">${N(ors.filter((r) => S.stateOf(r, t) === 'conformant').length)}</td>
        <td class="s" data-label="Record">${m.rebuilding ? stateHTML('idle', 'Not serving') : odev ? stateHTML('failed', 'Deviation proved') : stateHTML('verified', 'All conformant')}</td></tr>`;
    }).join('');
    $('#model-code').innerHTML = curl(m);
    wireCopy(screen);
    if (!loaded.has('model/' + id)) { loaded.add('model/' + id); const l = App.loading('#model-facts', { stagger: 70 }); setTimeout(() => l.done(), 300); }
  }
  document.getElementById('model-copy').addEventListener('click', (e) => App.copy($('#model-code').textContent, e.currentTarget));

  /* ---------- 03 traffic ---------- */
  const tStep = matchMedia('(max-width: 700px)').matches ? 15 : 30;   // stacked rows on a phone: fewer at a time
  let tFilter = 'all', tQuery = '', tLimit = tStep;
  const tMatch = (r) => {
    const s = S.stateOf(r);
    const f = tFilter === 'all' || (tFilter === 'proved' ? s === 'conformant' || s === 'deviation' : tFilter === 'challenged' ? !!r.chl : s === tFilter);
    if (!f) return false;
    if (!tQuery) return true;
    const q = tQuery.toLowerCase(), m = S.model(r.model), o = S.op(r.op);
    return (r.id + ' ' + m.id + ' ' + m.name + ' ' + o.name + ' ' + o.region).toLowerCase().includes(q);
  };
  const trafficRow = (r, fresh) => `<tr data-href="#request/${r.short}"${fresh ? ' class="t-new"' : ''}>
    <th scope="row"><a href="#request/${r.short}">${r.short}</a></th>
    <td class="what" data-label="Model">${esc(shortModel(r.model))}</td>
    <td class="v wide-only" data-label="Operator">${S.op(r.op).name.replace('Operator ', 'OP ')}</td>
    <td class="n" data-label="Delivered, UTC">${hms(r.at)}</td>
    <td class="s">${reqStateHTML(r)}</td></tr>`;
  function traffic(screen, modelId) {
    if (modelId && S.model(modelId)) { tQuery = modelId; $('#t-q').value = modelId; }
    const all = visible().filter(tMatch).reverse(), list = all.slice(0, tLimit);
    $('#traffic-t tbody').innerHTML = list.length ? list.map((r) => trafficRow(r)).join('')
      : `<tr><td class="none" colspan="5">No reply matches. <button class="btn quiet small" type="button" id="t-clear">Show all traffic</button></td></tr>`;
    $('#t-count').textContent = `${N(list.length)} of ${N(all.length)} · sample`;
    $('#t-more').hidden = all.length <= tLimit;
    logLine();
    const clear = $('#t-clear'); if (clear) clear.onclick = () => { tQuery = ''; $('#t-q').value = ''; setTFilter('all'); };
  }
  function logLine() {
    const size = $('#log-size'), head = $('#log-head'); if (!size) return;
    size.textContent = N(S.treeSize()); head.textContent = hms(Math.floor(S.now() / 60e3) * 60e3);
  }
  function trafficTick(added) {
    logLine();
    const rows = added.filter(tMatch).reverse();
    if (!rows.length) return;
    const tb = $('#traffic-t tbody'); if ($('td.none', tb)) { traffic(); return; }
    tb.insertAdjacentHTML('afterbegin', rows.map((r) => trafficRow(r, true)).join(''));
    while (tb.rows.length > tLimit) tb.deleteRow(-1);
    setTimeout(() => rows.forEach((r) => { const tr = $(`tr[data-href="#request/${r.short}"]`, tb); if (tr) tr.classList.remove('t-new'); }), 4000);
    const all = visible().filter(tMatch).length;
    $('#t-count').textContent = `${N(Math.min(all, tLimit))} of ${N(all)} · sample`;
  }
  function setTFilter(f) { tFilter = f; $$('#t-filter button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.f === f))); traffic(); }
  $$('#t-filter button').forEach((b) => b.addEventListener('click', () => setTFilter(b.dataset.f)));
  $('#t-q').addEventListener('input', (e) => { tQuery = e.target.value.trim(); traffic(); });
  $('#t-more').addEventListener('click', () => { tLimit += tStep; traffic(); });
  $('#t-more').textContent = `Show ${tStep} more`;

  /* ---------- 03 one request ---------- */
  let shownReq = null, shownReqState = '';
  function copyHTML(v, what) { return `<div class="copy"><span class="hash">${v}</span><button class="btn small" type="button" data-copy="${v}" aria-label="Copy the ${what}">Copy</button></div>`; }
  function wireCopy(scope) {
    $$('[data-copy]', scope).forEach((b) => { if (b._w) return; b._w = true; b.addEventListener('click', async () => { const ok = await App.copy(b.dataset.copy, b); if (!ok) App.toast('Your browser did not allow the copy. Select the text instead.', { state: 'failed', returnTo: b }); }); });
  }
  const digest = (r, k) => S.hex(64, k + ' ' + r.leaf);
  function request(screen, id) {
    const r = S.find(id); if (!r || r.at > S.now()) { location.replace('#traffic'); return; }
    shownReq = r; shownReqState = S.stateOf(r);
    const m = S.model(r.model), o = S.op(r.op), s = shownReqState, t = S.now(), rt = S.roundTime(r.round), decided = t >= rt;
    $('#t-request').textContent = 'Request ' + r.short;
    $('#req-sent').textContent = `${m.name}, served by ${o.name} in ${o.region.split(' ').map((w) => (w.length <= 2 ? w : w[0] + w.slice(1).toLowerCase())).join(' ')}. Delivered ${hms(r.at)} UTC, ${N(r.rt)} reply tokens.`;
    const [k, w] = reqState(r);
    $('#req-state').outerHTML = stateHTML(k, w, ` id="req-state" data-req="${r.id}"`);
    const proofDone = s === 'conformant' || s === 'deviation';
    const acts = [];
    if (r.chl) acts.push(`<a class="btn small" href="#challenge/${r.chl.id}">Its challenge</a>`);
    else if (!proofDone) acts.push(`<a class="btn small${s === 'unselected' ? ' solid' : ''}" href="#file/${r.short}">Challenge this reply</a>`);
    acts.push(`<a class="btn small${proofDone ? ' solid' : ''}" href="#verify/${r.short}">Verify offline</a>`);
    $('#req-actions').innerHTML = acts.join('');
    const score = r.score.toFixed(4), thr = (1 / S.RATE).toFixed(4);
    const proof = {
      awaiting: ['No proof yet. It depends on the beacon.', 'idle', 'Not yet'],
      unselected: ['Not selected, so not proved. The holder can still challenge it.', 'idle', 'Not proved'],
      proving: [`FlashProve is proving each of the ${N(r.rt)} reply tokens against the committed model.`, 'pending', 'Proving'],
      challenged: ['Challenged: the auditor is proving it now.', 'pending', 'Proving'],
      conformant: [`Proved: each of the ${N(r.rt)} reply tokens is the committed model's greedy choice.`, 'verified', 'Conformant'],
      deviation: [`Proved: token ${r.devTok ? r.devTok.pos : 0} is not the committed model's greedy choice.`, 'failed', 'Deviation'],
    }[s];
    const items = [
      ['Model', 'Bound to the commitment of the model the operator named.', cut(m.commitment), 'done', 'Bound'],
      ['Log', 'Logged before delivery. The leaf is in a signed tree head.', 'LEAF ' + N(r.leaf), 'done', 'Logged'],
      ['Beacon', decided ? `Fixed at delivery, published at ${hms(rt)} UTC. It did not exist when the reply was sent.` : `Fixed at delivery. Published at ${hms(rt)} UTC, in ${Math.ceil((rt - t) / 1000)} s.`,
        'ROUND ' + N(r.round), decided ? 'done' : 'pending', decided ? 'Published' : 'Waiting'],
      ['Selection', decided ? (r.sel ? 'Selected: its score is under the threshold of 1 in 20.' : 'Over the threshold of 1 in 20, so not selected.') : 'Decided by anyone once the round is published.',
        decided ? `SCORE ${score} ${r.sel ? '&lt;' : '≥'} ${thr}` : 'NOT YET', decided ? (r.sel ? 'verified' : 'idle') : 'pending', decided ? (r.sel ? 'Selected' : 'Not selected') : 'Waiting'],
      ['Proof', proof[0], proofDone ? cut(digest(r, 'proof')) : s === 'proving' || s === 'challenged' ? 'IN PROGRESS' : 'NONE', proof[1], proof[2]],
    ];
    $('#req-receipt').innerHTML = items.map(([l, wh, v, st, word], i) => `<li><h3 class="mono l"><b>0${i + 1}</b> · ${l}</h3><p class="w">${wh}</p><p class="v"><span>${v}</span></p><span class="s state" data-state="${st}">${word}</span></li>`).join('');
    const dev = s === 'deviation' && r.devTok;
    $('#req-dev-block').hidden = !dev;
    if (dev) $('#req-dev').innerHTML = [
      ['Position', `<span class="mono"><b>Token ${N(r.devTok.pos)}</b> of ${N(r.rt)}</span>`],
      ['Served', `<span class="mono"><b>${r.devTok.served}</b> · what the operator returned</span>`],
      ['Committed model', `<span class="mono"><b>${r.devTok.committed}</b> · its greedy choice</span>`],
      ['Proof', copyHTML(digest(r, 'proof'), 'proof digest')],
    ].map(([a, b]) => `<div><dt>${a}</dt><dd>${b}</dd></div>`).join('');
    if (r.mine) {
      $('#req-tr-note').textContent = 'Held in this browser · yours';
      $('#req-transcript').innerHTML = `<dl class="kv"><div><dt>You</dt><dd>${esc(r.mine.prompt)}</dd></div><div><dt>${esc(shortModel(r.model))}</dt><dd>${esc(r.mine.reply).replace(/\n/g, '<br>')}</dd></div></dl>`;
    } else {
      $('#req-tr-note').textContent = 'Never public';
      $('#req-transcript').innerHTML = `<div class="ak-sealed"><p class="sent">${s === 'unselected'
        ? 'Deleted from escrow once its round was decided. The holder keeps their own copy and can present it with a challenge.'
        : r.sel || r.chl ? 'Released from escrow to the auditor alone, for the proof. It is never published.' : 'Held in escrow until the beacon decides. Only the auditor can receive it, and only for a proof.'}</p>
        <p class="mono">Prompt <b>${N(r.pt)}</b> tokens · Reply <b>${N(r.rt)}</b> tokens · Only their commitment is public</p></div>`;
    }
    $('#req-kv').innerHTML = [
      ['Request ID', `<span class="hash">${r.id}</span>`],
      ['Leaf hash', copyHTML(r.lh, 'leaf hash')],
      ['Transcript commitment', copyHTML(digest(r, 'transcript'), 'transcript commitment')],
      ['Log signature', copyHTML(S.hex(128, 'sig ' + r.leaf), 'log signature')],
    ].map(([a, b]) => `<div><dt>${a}</dt><dd>${b}</dd></div>`).join('');
    wireCopy(screen);
  }

  /* ---------- 04 sampling ---------- */
  let lattice = null, oddsN = 20;
  const LEGEND = [['awaiting', 'Awaiting beacon'], ['unselected', 'Not selected'], ['proving', 'Proving'], ['challenged', 'Challenged'], ['conformant', 'Conformant'], ['deviation', 'Deviation']];
  function latestDecided(t = S.now()) { for (let i = S.requests.length - 1; i >= 0; i--) { const r = S.requests[i]; if (r.at <= t && r.sel && t >= S.roundTime(r.round)) return r; } return null; }
  let rcShown = null;
  function recompute() {
    const r = latestDecided(); if (!r || r === rcShown) return; rcShown = r;
    const score = r.score.toFixed(4), thr = (1 / S.RATE).toFixed(4);
    $('#rc-open').href = '#request/' + r.short;
    $('#recompute').innerHTML = [
      ['Round fixed', `Written into the receipt of ${r.short} at ${hms(r.at)} UTC, before the round existed.`, 'ROUND ' + N(r.round), 'done', 'Fixed'],
      ['Randomness', `Published by the drand quicknet beacon at ${hms(S.roundTime(r.round))} UTC. Anyone can fetch it.`, cut(S.randomness(r.round), 10, 6), 'done', 'Published'],
      ['Score', 'The randomness and the leaf hash, hashed together, read as a number between 0 and 1.', 'SCORE ' + score, 'done', 'Computed'],
      ['Decision', r.sel ? 'Under the threshold: this reply must be proved.' : 'Over the threshold: not selected this time.', `${score} ${r.sel ? '&lt;' : '≥'} ${thr}`, r.sel ? 'verified' : 'idle', r.sel ? 'Selected' : 'Not selected'],
    ].map(([l, w, v, st, word], i) => `<li><h3 class="mono l"><b>0${i + 1}</b> · ${l}</h3><p class="w">${w}</p><p class="v"><span>${v}</span></p><span class="s state" data-state="${st}">${word}</span></li>`).join('');
  }
  function odds() {
    const p = Math.pow(1 - 1 / S.RATE, oddsN);
    $('#odds-n-v').textContent = oddsN;
    $('#odds-sent').textContent = `If an operator changes ${oddsN} ${oddsN === 1 ? 'reply' : 'replies'}, the chance that the beacon selects none of them is:`;
    $('#odds-val').textContent = pct(p, p < 0.001 ? 3 : 1);
  }
  function sampling(screen) {
    const t = S.now(), st = hourStats(t);
    setVal(screen, 'selected', N(st.selected));
    setVal(screen, 'share', `Sample · of ${N(st.decided)} decided`);
    setVal(screen, 'provedOf', `${N(st.selProved)}/${N(st.selected)}`);
    if (!lattice) {
      lattice = AkashiFigure.selection('#lattice', { cells: (n) => { const now = S.now(), v = []; for (let i = S.requests.length - 1; i >= 0 && v.length < n; i--) { const r = S.requests[i]; if (r.at <= now) v.push({ leaf: r.leaf, s: S.stateOf(r, now) }); } return v.reverse(); } });
      $('#legend').innerHTML = LEGEND.map(([s, w]) => `<span class="ak-key"><i class="ak-glyph" data-s="${s}" aria-hidden="true"></i>${w}</span>`).join('');
      $$('#legend .ak-glyph').forEach((g) => AkashiFigure.glyph(g, g.dataset.s));
    }
    const recent = visible(t).slice(-400), sel = recent.filter((r) => r.sel && t >= S.roundTime(r.round)).length, aw = recent.filter((r) => t < S.roundTime(r.round)).length;
    $('#lattice').setAttribute('aria-label', `A lattice of the latest logged replies, one cell each. Of the last 400, ${aw} await their beacon round and ${sel} were selected for proof. Sample data.`);
    $('#lat-caption').textContent = `Round ${N(S.roundAt(t))} · ${hms(t)} UTC`;
    recompute();
    odds();
  }
  $('#odds-n').addEventListener('input', (e) => { oddsN = +e.target.value; odds(); });

  /* ---------- 05 challenges ---------- */
  function challenges(screen) {
    const t = S.now(), cs = S.challenges.filter((c) => c.at <= t);
    const c4 = { open: 0, conformant: 0, deviation: 0, refused: 0 };
    cs.forEach((c) => { const g = S.stage(c, t); if (!g.outcome || (g.outcome !== 'refused' && !g.finished)) c4.open++; else c4[g.outcome]++; });
    Object.entries(c4).forEach(([k, v]) => setVal(screen, k, N(v)));
    $('#chl-t tbody').innerHTML = cs.map((c) => `<tr data-href="#challenge/${c.id}"${c.fresh ? ' class="t-new"' : ''}>
      <th scope="row"><a href="#challenge/${c.id}">${c.id}</a></th>
      <td class="v" data-label="Request">${c.req ? `<span class="hash">${c.req.short}</span>` : `<span class="hash">${c.ref}</span>`}</td>
      <td class="what" data-label="Filed by">${ROLE[c.role]}${c.mine ? ' · <span class="muted">you</span>' : ''}</td>
      <td class="n wide-only" data-label="Filed, UTC">${hms(c.at)}</td>
      <td class="s">${chlStateHTML(c)}</td></tr>`).join('');
    navCounts();
  }
  function navCounts() {
    const t = S.now(), open = S.challenges.filter((c) => { const g = S.stage(c, t); return c.at <= t && (!g.outcome || (g.outcome !== 'refused' && !g.finished)); }).length;
    $('#nav-open').textContent = open ? open + ' open' : '';
    $('#nav-models').textContent = S.MODELS.length;
  }

  /* ---------- 05 file a challenge ---------- */
  const form = $('#file-form');
  function file(screen, ref) {
    if (ref) { $('#f-req').value = ref; $('#f-req').removeAttribute('aria-invalid'); $('#f-req-m').textContent = ''; }
  }
  $('#f-pick').addEventListener('click', () => {
    const t = S.now(), r = [...S.requests].reverse().find((x) => x.at <= t && !x.chl && S.stateOf(x, t) === 'unselected');
    if (r) { $('#f-req').value = r.short; $('#f-req').removeAttribute('aria-invalid'); $('#f-req-m').textContent = ''; $('#f-req').focus(); }
  });
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!App.validate(form)) return;
    const d = new FormData(form), ref = String(d.get('req')).trim().toLowerCase(), r = S.find(ref.slice(0, 8)), inp = $('#f-req');
    if (!r || r.at > S.now()) {
      inp.setAttribute('aria-invalid', 'true'); $('#f-req-m').textContent = 'No reply in the log has this request ID. Check it against the receipt.'; inp.focus(); return;
    }
    if (r.chl) { App.toast(`Request ${r.short} is already challenged. Here is its challenge.`, { state: 'idle' }); location.hash = 'challenge/' + r.chl.id; return; }
    const m = S.model(r.model), o = S.op(r.op);
    const ok = await App.confirm({ label: '<b>New challenge</b> · Sample', title: 'File this challenge?', text: 'The auditor proves the reply against its model and signs the verdict. The verdict is public; the transcript is not.',
      rows: [['Request', r.short], ['Model', m.name], ['Operator', o.name], ['Challenger', ROLE[d.get('role')] + ' · ' + (d.get('key') || 'no key')], ['Reason', REASON[d.get('reason')]]], ok: 'File challenge', cancel: 'Go back' });
    if (!ok) return;
    const c = S.file({ req: r, role: d.get('role'), key: String(d.get('key') || '').toUpperCase(), reason: d.get('reason'), note: d.get('note'), at: S.now(), mine: true });
    c.fresh = true; form.reset(); mineChl.add(c.id);
    location.hash = 'challenge/' + c.id;
    App.toast(`Challenge ${c.id} filed. It is being admitted.`, { state: 'pending' });
  });
  const mineChl = new Set(), told = new Set();

  /* ---------- 05 one challenge ---------- */
  let shownChl = null, chlKey = '';
  const STEP_TEXT = {
    filed: ['Filed', 'The challenger presented the signed receipt.'],
    admitted: ['Admitted', 'Checked: the receipt signature, its leaf in the log, and the challenge window.'],
    released: ['Transcript released', 'Escrow handed the transcript to the auditor alone. It is never published.'],
    proving: ['Proving', 'FlashProve runs the committed model over the whole reply.'],
    signed: ['Verdict signed', 'The auditor signed the outcome and the proof digest.'],
    published: ['Published', 'The verdict is in the log. Anyone can check the proof offline.'],
  };
  function challenge(screen, id) {
    const c = S.challenges.find((x) => x.id === id); if (!c) { location.replace('#challenges'); return; }
    shownChl = c;
    const t = S.now(), g = S.stage(c, t), r = c.req;
    chlKey = g.done.join() + (g.outcome || '');
    $('#t-challenge').textContent = 'Challenge ' + c.id;
    $('#chl-sent').textContent = r
      ? `${ROLE[c.role]} ${c.key} challenged request ${r.short}, served by ${S.op(r.op).name} for ${S.model(r.model).name}. Reason: ${REASON[c.reason]}.${c.note ? ' Note: ' + c.note : ''}`
      : `${ROLE[c.role]} ${c.key} presented a receipt for request ${c.ref}. Reason: ${REASON[c.reason]}.`;
    const [k, w] = chlState(c);
    $('#chl-state').outerHTML = stateHTML(k, w, ` id="chl-state" data-chl="${c.id}"`);
    const acts = [];
    if (r) acts.push(`<a class="btn small" href="#request/${r.short}">Open the request</a>`);
    if (g.finished && r) acts.push(`<a class="btn small solid" href="#verify/${r.short}">Verify the proof offline</a>`);
    $('#chl-actions').innerHTML = acts.join('');
    let steps;
    if (c.refused) {
      steps = [
        ['filed', 'done', 'Filed', hms(c.at) + ' · ' + c.key],
        ['admitted', g.outcome ? 'failed' : 'pending', g.outcome ? 'Refused' : 'Checking', g.outcome ? 'NOT ADMITTED' : 'CHECKING'],
      ];
    } else {
      steps = S.STEPS.map((s) => {
        const done = g.done.includes(s.k), cur = g.current === s.k, at = hms(g.at(s.k));
        let v = done ? at : cur ? 'IN PROGRESS' : 'NOT YET';
        if (s.k === 'filed') v = at + ' · ' + c.key;
        if (s.k === 'admitted' && done) v = `${at} · LEAF ${N(r.leaf)}`;
        if (s.k === 'released' && done) v = `${at} · TO AUD 1`;
        if (s.k === 'proving') v = done ? `${(S.PROOF_MS / 1000).toFixed(1)} S · ${N(r.rt)} TOKENS` : cur ? `<span data-progress>${progress(c, t)}</span>` : 'NOT YET';
        if (s.k === 'signed' && done) v = `${at} · ${r.dev ? 'DEVIATION' : 'CONFORMANT'}`;
        const kind = done ? (s.k === 'signed' && r.dev ? 'failed' : 'done') : cur ? 'pending' : 'idle';
        const word = done ? (s.k === 'signed' ? (r.dev ? 'Deviation' : 'Conformant') : 'Done') : cur ? 'Now' : 'Waiting';
        return [s.k, kind, word, v];
      });
    }
    $('#chl-steps').innerHTML = steps.map(([key, kind, word, v], i) => {
      const [l, wh] = key === 'admitted' && c.refused && g.outcome ? ['Refused', c.refused] : STEP_TEXT[key];
      return `<li><h3 class="mono l"><b>0${i + 1}</b> · ${l}</h3><p class="w">${esc(wh)}</p><p class="v"><span>${v}</span></p><span class="s state" data-state="${kind}">${word}</span></li>`;
    }).join('');
    const signed = g.outcome && g.outcome !== 'refused';
    $('#chl-kv').innerHTML = c.refused
      ? [['Outcome', g.outcome ? stateHTML('idle', 'Refused') : stateHTML('pending', 'Checking')], ['Why', `<span>${esc(c.refused)}</span>`], ['What it costs the operator', '<span class="muted">Nothing. A receipt the log did not sign binds no one.</span>']].map(([a, b]) => `<div><dt>${a}</dt><dd>${b}</dd></div>`).join('')
      : signed ? [
        ['Outcome', r.dev ? stateHTML('failed', 'Deviation proved') : stateHTML('verified', 'Conformant')],
        ['Statement', `<span>${r.dev ? `Token ${N(r.devTok.pos)} of the reply is ${r.devTok.served}. The committed model's greedy choice is ${r.devTok.committed}.` : `Each of the ${N(r.rt)} reply tokens is the committed model's greedy choice for the verified input.`}</span>`],
        ['Proof digest', copyHTML(digest(r, 'proof'), 'proof digest')],
        ['Proof size', '<span class="mono"><b>18.7 MB</b> · sample</span>'],
        ['Signed by', '<span class="mono"><b>AUD 1</b> · the auditor, not the operator</span>'],
        ['Signature', copyHTML(S.hex(128, 'verdict ' + c.id), 'verdict signature')],
      ].map(([a, b]) => `<div><dt>${a}</dt><dd>${b}</dd></div>`).join('')
        : `<div><dt>Outcome</dt><dd><span class="muted">Not signed yet. The auditor signs once the proof is done.</span></dd></div>`;
    wireCopy(screen);
  }
  function progress(c, t) {
    const s = Math.max(0, (t - c.at - S.STEPS[3].at) / 1000);
    return `${s.toFixed(0)} S OF ABOUT ${(S.PROOF_MS / 1000).toFixed(0)} S`;
  }

  /* ---------- 07 playground ---------- */
  const PRESETS = [
    ['What is 7 + 5? Answer with the number only.', '12'],
    ['Translate the word "proof" into Japanese. One word.', '証'],
    ['Name the planet closest to the Sun.', 'Mercury.'],
    ['Write a haiku about a public log.', 'Each leaf signed, then shown.\nThe branch keeps every one of them.\nNo page is torn out.'],
  ];
  let preset = 0, mine = null;
  const sel = $('#p-model');
  sel.innerHTML = S.MODELS.filter((m) => !m.rebuilding).map((m) => `<option value="${m.id}">${esc(m.name)}</option>`).join('');
  function playCode(view) {
    const m = S.model(sel.value), msg = $('#p-msg').value.trim() || PRESETS[0][0], max = +$('#p-max').value || 64;
    if (view === 'res') {
      const r = mine;
      $('#p-code').innerHTML = r
        ? `<span class="c"># HTTP/1.1 200 · sample response</span>
<span class="k">x-akashi-receipt</span>: ${btoa(r.id + '.' + r.lh.slice(0, 24))}
<span class="k">x-akashi-leaf</span>: ${r.leaf}
<span class="k">x-akashi-beacon-round</span>: ${r.round}

{
  "id": "${r.id}",
  "model": "${r.model}",
  "choices": [{ "message": { "role": "assistant", "content": ${esc(JSON.stringify(r.mine.reply))} }, "finish_reason": "stop" }],
  "usage": { "prompt_tokens": ${r.pt}, "completion_tokens": ${r.rt} }
}`
        : '<span class="c"># send a message first: the response and its receipt headers appear here</span>';
    } else $('#p-code').innerHTML = curl(m, msg, max);
  }
  function playground(screen, modelId) {
    if (modelId && S.model(modelId) && !S.model(modelId).rebuilding) sel.value = modelId;
    playCode($('#p-tabs [aria-pressed="true"]').dataset.v);
  }
  $$('#p-tabs button').forEach((b) => b.addEventListener('click', () => { $$('#p-tabs button').forEach((x) => x.setAttribute('aria-pressed', String(x === b))); playCode(b.dataset.v); }));
  ['#p-model', '#p-msg', '#p-max'].forEach((s) => $(s).addEventListener('input', () => playCode($('#p-tabs [aria-pressed="true"]').dataset.v)));
  $('#p-another').addEventListener('click', () => { preset = (preset + 1) % PRESETS.length; $('#p-msg').value = PRESETS[preset][0]; playCode($('#p-tabs [aria-pressed="true"]').dataset.v); });
  $('#play-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!App.validate(e.currentTarget)) return;
    const msg = $('#p-msg').value.trim(), m = S.model(sel.value), max = +$('#p-max').value;
    const hit = PRESETS.find((p) => p[0].toLowerCase() === msg.toLowerCase());
    const reply = hit ? hit[1] : 'This preview runs no model, so this is sample text. On the network, the reply would be the greedy output of the committed model, bound to the receipt you now hold.';
    const st = $('#p-state'), btn = $('#p-send');
    btn.disabled = true; $('#p-kv').hidden = true; $('#p-after').hidden = true;
    T.cipherText(st, 'Waiting for the reply').then(() => { st.dataset.state = 'pending'; });
    T.cipherText($('#p-reply'), '');
    await new Promise((res) => setTimeout(res, 900));
    const words = reply.split(/\s+/).length;
    const r = S.make(S.now(), { model: m.id, pt: 18 + Math.round(msg.length / 4), rt: Math.min(max, Math.max(2, Math.round(words * 1.4) + 1)), mine: { prompt: msg, reply } });
    mine = r;
    await T.cipherText($('#p-reply'), reply);
    T.cipherText(st, 'Logged · receipt held').then(() => { st.dataset.state = 'done'; });
    $('#p-kv').innerHTML = [
      ['Request ID', `<span class="hash">${r.id}</span>`],
      ['Leaf', `<span class="mono"><b>${N(r.leaf)}</b> · logged before delivery</span>`],
      ['Beacon round', `<span class="mono"><b>${N(r.round)}</b> · published in about ${Math.round((S.roundTime(r.round) - S.now()) / 1000)} s</span>`],
      ['Selection', `<span class="state" data-state="pending" data-req="${r.id}">Awaiting beacon</span>`],
    ].map(([a, b]) => `<div><dt>${a}</dt><dd>${b}</dd></div>`).join('');
    $('#p-kv').hidden = false; $('#p-after').hidden = false; $('#p-open').href = '#request/' + r.short;
    btn.disabled = false;
    playCode($('#p-tabs [aria-pressed="true"]').dataset.v);
  });
  $('#p-dl').addEventListener('click', () => {
    if (!mine) return;
    App.download(`receipt-${mine.short}-sample.json`, JSON.stringify(bundle(mine, false), null, 2));
    App.toast('Receipt saved as a file. Sample data.');
  });

  /* ---------- 08 verify ---------- */
  let vReq = null, flipped = false, running = false, vRun = 0;
  function bundle(r, withProof = true) {
    const m = S.model(r.model), s = S.stateOf(r), proved = s === 'conformant' || s === 'deviation';
    const b = { sample: true, note: 'Sample bundle from the Akashi preview. Not a real receipt or proof.', version: 'akashi/1',
      receipt: { request_id: r.id, served_at: iso(r.at), model: m.id, commitment_id: m.commitment, leaf_hash: r.lh, beacon_round: r.round, sampling_mode: 'live', log_key_id: 'LOG KEY 1', promise_sig: S.hex(128, 'sig ' + r.leaf) },
      history: { leaf_index: r.leaf, tree_size: S.treeSize(), checkpoint: S.heads(1)[0].root } };
    if (withProof && proved) b.proof = { system: 'FlashProve', outcome: s, digest: digest(r, 'proof'), bytes: 18734112 };
    return b;
  }
  function loadBundle(r) {
    vRun++; running = false;
    vReq = r; flipped = false;
    $('#v-in').value = JSON.stringify(bundle(r), null, 2);
    $('#v-in').removeAttribute('aria-invalid'); $('#v-in-m').textContent = '';
    $('#v-flip').disabled = !bundle(r).proof;
    $('#v-src').textContent = `Request ${r.short} · sample`;
    resetChecks();
  }
  const VSTEPS = [
    ['Receipt signature', 'Ed25519 over the log ID and the leaf hash, with the log key you trust.'],
    ['Log inclusion', 'The leaf is in the signed tree head, by its inclusion path.'],
    ['History', 'That head extends the checkpoint you already trust. Nothing was rewritten.'],
    ['Statement', 'The proof states the same commitment, tokens and window as the receipt.'],
    ['Proof', 'The FlashProve proof checked on this CPU. About 21 s on one thread (F26); simulated here.'],
  ];
  function resetChecks() {
    $('#v-steps').innerHTML = VSTEPS.map(([l, w], i) => `<li><h3 class="mono l"><b>0${i + 1}</b> · ${l}</h3><p class="w">${w}</p><p class="v"><span>NOT RUN</span></p><span class="s state" data-state="idle">Waiting</span></li>`).join('');
    $('#v-outcome').hidden = true;
    const st = $('#v-state'); st.dataset.state = 'idle'; st.textContent = 'Not run';
  }
  function verify(screen, id) {
    const r = id && S.find(id);
    if (r && r !== vReq) loadBundle(r);
    else if (!vReq) $('#v-sample').click();
    else if (!$('#v-steps').children.length) resetChecks();
  }
  $('#v-sample').addEventListener('click', () => {
    const t = S.now(), r = [...S.requests].reverse().find((x) => x.at <= t && S.stateOf(x, t) === 'conformant');
    if (r) loadBundle(r);
  });
  $('#v-flip').addEventListener('click', () => {
    let b; try { b = JSON.parse($('#v-in').value); } catch (e) { return; }
    if (!b.proof) return;
    const d = b.proof.digest, last = parseInt(d.slice(-1), 16) ^ 1;
    b.proof.digest = d.slice(0, -1) + last.toString(16);
    $('#v-in').value = JSON.stringify(b, null, 2); flipped = true; vRun++; running = false;
    App.toast('One bit of the proof changed. Run the checks again.', { state: 'idle' });
    resetChecks();
  });
  $('#v-in').addEventListener('input', () => { flipped = true; });
  $('#v-run').addEventListener('click', async () => {
    if (running) return;
    const inp = $('#v-in');
    if (!App.validate(inp.closest('.block'))) return;
    let b; try { b = JSON.parse(inp.value); } catch (e) { inp.setAttribute('aria-invalid', 'true'); $('#v-in-m').textContent = 'This is not a bundle: it does not read as JSON.'; inp.focus(); return; }
    const r = b.receipt && S.find(String(b.receipt.request_id || '').slice(0, 8));
    if (!r) { inp.setAttribute('aria-invalid', 'true'); $('#v-in-m').textContent = 'This bundle names no request in the sample log.'; inp.focus(); return; }
    const intact = b.proof ? b.proof.digest === digest(r, 'proof') : true, sigOk = b.receipt.leaf_hash === r.lh && b.receipt.promise_sig === S.hex(128, 'sig ' + r.leaf);
    running = true; resetChecks();
    const me = ++vRun, stale = () => me !== vRun;   // a new bundle or a changed bit ends this run
    const st = $('#v-state'); T.cipherText(st, 'Checking').then(() => { st.dataset.state = 'pending'; });
    const lis = $$('#v-steps > li');
    const outcomes = [
      [sigOk, sigOk ? 'LOG KEY 1 · VALID' : 'DOES NOT VERIFY'],
      [sigOk, `LEAF ${N(r.leaf)} · PATH OF ${Math.ceil(Math.log2(S.treeSize()))}`],
      [sigOk, `SIZE ${N(b.history ? b.history.tree_size : 0)} EXTENDS CHECKPOINT`],
      [!!b.proof && intact, b.proof ? 'COMMITMENT AND TOKENS MATCH' : 'NO PROOF IN THIS BUNDLE'],
      [!!b.proof && intact, b.proof ? (intact ? (b.proof.outcome === 'deviation' ? 'DEVIATION PROVED' : 'ACCEPTED') : 'REJECTED') : 'SKIPPED'],
    ];
    let failedAt = -1;
    for (let i = 0; i < lis.length; i++) {
      const li = lis[i], s = $('.state', li), v = $('.v span', li);
      if (failedAt >= 0 || (!b.proof && i >= 3)) { T.cipherText(s, 'Skipped'); T.cipherText(v, b.proof ? 'NOT RUN' : outcomes[i][1]); continue; }
      T.cipherText(s, 'Checking').then(() => { s.dataset.state = 'pending'; });
      await new Promise((res) => setTimeout(res, T.motion() ? (i === 4 ? 2200 : 650) : 0));
      if (stale()) return;
      const [ok, word] = outcomes[i];
      // a changed proof still matches its statement; it fails at the proof check itself
      const pass = i === 3 && b.proof ? true : ok;
      if (!pass) failedAt = i;
      await Promise.all([T.cipherText(v, i === 3 && b.proof ? 'COMMITMENT AND TOKENS MATCH' : word), T.cipherText(s, pass ? (i === 4 && b.proof.outcome === 'deviation' ? 'Deviation' : 'Passed') : 'Failed')]);
      s.dataset.state = pass ? (i === 4 && b.proof.outcome === 'deviation' ? 'failed' : 'verified') : 'failed';
    }
    if (stale()) return;
    const res = !sigOk ? ['REJECTED · RECEIPT', 'The receipt signature does not verify. Nothing in this bundle can be trusted.', 'failed', 'Rejected']
      : !b.proof ? ['RECEIPT VERIFIED · EXIT 30', 'The receipt and its place in the log check out. There is no proof yet: the reply was not selected or challenged.', 'done', 'Receipt verified']
      : !intact ? ['REJECTED · EXIT 20', 'One bit of the proof is different, and the proof no longer checks. The original is accepted; this copy is not.', 'failed', 'Rejected']
      : b.proof.outcome === 'deviation' ? ['DEVIATION PROVED', `The proof checks, and it shows token ${r.devTok.pos} is not the committed model's choice. The operator served something else.`, 'failed', 'Deviation proved']
      : ['ACCEPTED · EXIT 0', `Each of the ${N(r.rt)} reply tokens is the greedy choice of the committed model. Checked here, without the weights.`, 'verified', 'Accepted'];
    $('#v-val').textContent = res[0]; $('#v-what').textContent = res[1]; $('#v-outcome').hidden = false;
    T.cipherText(st, res[3]).then(() => { st.dataset.state = res[2]; });
    T.figures.decode($('#v-val'), { drive: 'manual', start: 0 }).play(1, 1100, 0);
    running = false;
  });

  /* ---------- rows that open something on click (the row's link is there for the keyboard) ---------- */
  document.addEventListener('click', (e) => {
    const tr = e.target.closest('tr[data-href]');
    if (!tr || e.target.closest('a, button') || String(getSelection())) return;
    location.hash = tr.dataset.href.slice(1);
  });

  /* ---------- the live control: the sample network and all motion, paused or running ---------- */
  const liveBtn = $('#live');
  liveBtn.addEventListener('click', () => {
    const on = !S.live(); S.live(on); T.pause(!on);
    liveBtn.setAttribute('aria-pressed', String(on));
    App.toast(on ? 'The sample network is running again.' : 'Paused: no new traffic and no motion until you resume.', { state: on ? 'done' : 'idle', returnTo: liveBtn });
  });

  /* ---------- start ---------- */
  const router = App.routes({
    overview: (s) => overview(s), models, model, traffic: (s, m) => traffic(s, m), request, sampling,
    challenges, file, challenge, playground, verify,
  }, {
    home: 'overview',
    parent: { model: 'models', request: 'traffic', file: 'challenges', challenge: 'challenges' },
    title: (name, args) => ({ overview: 'Network', models: 'Models', model: S.model(args[0]) ? S.model(args[0]).name : 'Model', traffic: 'Traffic', request: 'Request ' + (args[0] || ''),
      sampling: 'Sampling', challenges: 'Challenges', file: 'File a challenge', challenge: 'Challenge ' + (args[0] || ''), playground: 'Playground', verify: 'Verify' }[name]) + ' · Akashi · Sample',
  });
  navCounts();

  S.on(({ added }) => {
    const cur = router.current(), scr = $(`[data-screen="${cur}"]`);
    if (cur === 'overview') overview(scr, added.length);
    else if (cur === 'traffic') trafficTick(added);
    else if (cur === 'sampling') sampling(scr);
    else if (cur === 'challenges') challenges(scr);
    else if (cur === 'request' && shownReq && S.stateOf(shownReq) !== shownReqState) request(scr, shownReq.short);
    else if (cur === 'challenge' && shownChl) {
      const g = S.stage(shownChl);
      if (g.done.join() + (g.outcome || '') !== chlKey) challenge(scr, shownChl.id);
      else { const p = $('[data-progress]', scr); if (p) p.textContent = progress(shownChl, S.now()); }
    }
    liveStates(scr);
    navCounts();
    // tell the reader when a challenge they filed has its verdict, wherever they are
    mineChl.forEach((id) => {
      const c = S.challenges.find((x) => x.id === id), g = c && S.stage(c);
      if (g && g.finished && !told.has(id)) { told.add(id); App.toast(`Challenge ${id}: ${c.req.dev ? 'deviation proved' : 'proved conformant'}. The verdict is signed.`, { state: c.req.dev ? 'failed' : 'done', action: { label: 'View', run: () => { location.hash = 'challenge/' + id; } } }); }
    });
  });
})();
