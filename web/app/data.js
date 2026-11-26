/* Akashi sample network. Everything here is invented and labelled as sample on screen, except where a line says otherwise:
   no real traffic, operators, prices, keys, signatures or proofs. It simulates a network so the screens have something to show.

   What follows the real design (README.md and specs/ at the root of the repository):
   - a reply is logged before it is delivered, and its receipt fixes a future beacon round (drand quicknet, one round every 3 s);
   - when that round is published, anyone can recompute whether the reply was selected; the descriptor's live rate is 1 in 20;
   - a proof takes about 58.8 s on one request (facts register F23); the Maverick commitment and its 1,024-token window are F4 and F7;
   - transcripts stay in escrow and are never shown publicly; a challenge releases one to the auditor alone.

   window.Sample: { MODELS, OPS, RATE, now(), requests, challenges, find(id), stateOf(r), stage(c), heads(), on(fn), live(on), file(...) } */
(function (root) {
  'use strict';

  /* ---------- deterministic sample values ---------- */
  function mulberry(a) { return () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
  function seedOf(s) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
  const hex = (n, seed) => { const r = mulberry(seedOf(String(seed))); let s = ''; for (let i = 0; i < n; i++) s += '0123456789abcdef'[Math.floor(r() * 16)]; return s; };
  const uuid = (seed) => { const h = hex(32, seed); return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${'89ab'[parseInt(h[16], 16) % 4]}${h.slice(17, 20)}-${h.slice(20, 32)}`; };
  const rnd = mulberry(20261126);

  /* ---------- the catalogue ---------- */
  const OPS = [
    { id: '3f1c', name: 'Operator 3F1C', region: 'EU WEST', p50: 3.9 },
    { id: '9d2e', name: 'Operator 9D2E', region: 'US EAST', p50: 3.4 },
    { id: 'a7b4', name: 'Operator A7B4', region: 'EU NORTH', p50: 4.2 },
    { id: '5e80', name: 'Operator 5E80', region: 'AP NORTHEAST', p50: 4.6 },
    { id: 'c21d', name: 'Operator C21D', region: 'US WEST', p50: 3.7 },
  ];
  const MODELS = [
    { id: 'llama-4-maverick', name: 'Llama 4 Maverick 17B 128E Instruct', window: 1024, price: [0.18, 0.60], share: 0.34, ops: ['3f1c', '9d2e', 'a7b4'],
      commitment: 'c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46', format: 'Integer conversion · UD-Q4_K_XL', real: true },
    { id: 'qwen3-32b', name: 'Qwen3 32B', window: 2048, price: [0.10, 0.30], share: 0.22, ops: ['3f1c', '5e80'] },
    { id: 'gemma-3-27b', name: 'Gemma 3 27B Instruct', window: 2048, price: [0.09, 0.17], share: 0.17, ops: ['a7b4', 'c21d'] },
    { id: 'mistral-small-3.2', name: 'Mistral Small 3.2 24B Instruct', window: 2048, price: [0.06, 0.18], share: 0.15, ops: ['5e80', 'c21d', '9d2e'] },
    { id: 'llama-3.3-70b', name: 'Llama 3.3 70B Instruct', window: 1024, price: [0.13, 0.39], share: 0.12, ops: ['3f1c', 'c21d'] },
    { id: 'phi-4', name: 'Phi 4 14B', window: 1024, price: [0.07, 0.14], share: 0, ops: ['a7b4'], rebuilding: true },
  ];
  MODELS.forEach((m) => {
    m.commitment = m.commitment || hex(64, 'commit ' + m.id);
    m.format = m.format || 'Integer conversion · sample';
    m.profile = hex(64, 'profile ' + m.id);
  });
  const model = (id) => MODELS.find((m) => m.id === id);
  const op = (id) => OPS.find((o) => o.id === id);

  /* ---------- time: a sample clock that runs only while the network is live ---------- */
  const T0 = Date.UTC(2026, 10, 26, 14, 20, 0);
  const R0 = 34127000, PERIOD = 3000, DELAY_ROUNDS = 10, PROOF_MS = 58800, RATE = 20;
  let simNow = T0, last = performance.now(), running = true;
  const now = () => simNow;
  const roundAt = (t) => R0 + Math.floor((t - T0) / PERIOD);
  const roundTime = (r) => T0 + (r - R0) * PERIOD;
  const randomness = (r) => hex(64, 'drand ' + r);

  /* ---------- requests ---------- */
  const requests = [], byId = new Map();
  let leaf = 1204311;
  function pickModel() { let x = rnd(), acc = 0; for (const m of MODELS) { acc += m.share; if (x < acc) return m; } return MODELS[0]; }
  function make(at, o = {}) {
    const m = o.model ? model(o.model) : pickModel();
    const opId = o.op || m.ops[Math.floor(rnd() * m.ops.length)];
    const id = uuid('req ' + leaf), lh = hex(64, 'leaf ' + leaf);
    const pt = o.pt || 40 + Math.floor(rnd() * Math.min(520, m.window * 0.45)), rt = o.rt || 6 + Math.floor(rnd() * Math.min(380, m.window - pt - 8));
    const round = roundAt(at) + DELAY_ROUNDS;
    const score = parseInt(hex(8, 'score ' + round + lh), 16) / 4294967296;
    const r = { id, short: id.slice(0, 8), model: m.id, op: opId, at, pt, rt, lat: Math.round((op(opId).p50 * 0.7 + rnd() * 2.2) * 1000) / 1000,
      leaf: leaf++, lh, round, score: o.score != null ? o.score : score, proofAt: 0, dev: !!o.dev, mine: o.mine || null };
    r.sel = r.score < 1 / RATE;
    r.proofAt = roundTime(r.round) + PROOF_MS + Math.floor(rnd() * 9000);
    requests.push(r); byId.set(r.id, r); byId.set(r.short, r);
    return r;
  }
  // an hour of history, then the network keeps going while it is live
  for (let t = T0 - 3600 * 1000; t < T0; t += 400 + rnd() * 2400) make(t);
  // the one reply in the sample that did not match its model: Operator 9D2E, not selected by the beacon, found by a challenge
  const devReq = requests.find((r) => r.at > T0 - 47.5 * 60e3 && r.model === 'llama-4-maverick' && !r.sel);
  devReq.op = '9d2e'; devReq.dev = true; devReq.devTok = { pos: 214, served: 51813, committed: 1274 };
  if (devReq.rt < 260) devReq.rt = 389;
  const stateOf = (r, t = simNow) => {
    if (r.chl) { const s = stage(r.chl, t); if (s.outcome) return s.outcome === 'deviation' ? 'deviation' : s.outcome === 'refused' ? baseState(r, t) : 'conformant'; return 'challenged'; }
    return baseState(r, t);
  };
  function baseState(r, t) {
    if (t < roundTime(r.round)) return 'awaiting';
    if (!r.sel) return 'unselected';
    if (t < r.proofAt) return 'proving';
    return r.dev ? 'deviation' : 'conformant';
  }

  /* ---------- challenges ---------- */
  // the steps of a challenge, as offsets in milliseconds from the moment it was filed
  const STEPS = [
    { k: 'filed', at: 0 }, { k: 'admitted', at: 4000 }, { k: 'released', at: 9000 },
    { k: 'proving', at: 12000 }, { k: 'signed', at: 12000 + PROOF_MS }, { k: 'published', at: 15000 + PROOF_MS },
  ];
  const challenges = [];
  let chlN = 0;
  function file(o) {
    const c = { id: 'chl_' + hex(6, 'chl ' + chlN++), req: o.req || null, ref: o.ref || (o.req ? o.req.short : ''), role: o.role, key: o.key || ('KEY ' + hex(4, 'key ' + o.role + chlN).toUpperCase()),
      reason: o.reason, note: o.note || '', at: o.at, refused: o.refused || null, mine: !!o.mine };
    if (c.req && !c.refused) c.req.chl = c;
    challenges.unshift(c);
    challenges.sort((a, b) => b.at - a.at);
    return c;
  }
  // stage(c): where the challenge is now: { done: [step keys reached], current, outcome }
  function stage(c, t = simNow) {
    const dt = t - c.at;
    if (c.refused) {
      const done = dt >= 4000 ? ['filed', 'refused'] : ['filed'];
      return { done, current: dt >= 4000 ? null : 'admitted', outcome: dt >= 4000 ? 'refused' : null, at: (k) => c.at + (k === 'refused' ? 4000 : 0) };
    }
    const done = STEPS.filter((s) => dt >= s.at).map((s) => s.k);
    const next = STEPS.find((s) => dt < s.at);
    const finished = !next;
    return { done, current: next ? next.k : null, outcome: dt >= STEPS[4].at ? (c.req.dev ? 'deviation' : 'conformant') : null, finished, at: (k) => c.at + (STEPS.find((s) => s.k === k) || { at: 0 }).at };
  }
  const pickReq = (fn) => requests.find((r) => fn(r) && !r.chl && !r.dev) || requests.find((r) => !r.sel && !r.chl && !r.dev && r.at > T0 - 20 * 60e3);
  file({ req: devReq, role: 'regulator', reason: 'model', at: devReq.at + 9.5 * 60e3, key: 'REG 04A1' });
  file({ req: pickReq((r) => r.at > T0 - 33 * 60e3 && !r.sel), role: 'holder', reason: 'altered', at: T0 - 31 * 60e3, key: 'HOLDER 7C20' });
  file({ req: pickReq((r) => r.at > T0 - 25 * 60e3 && !r.sel && r.model === 'qwen3-32b'), role: 'auditor', reason: 'routine', at: T0 - 22 * 60e3, key: 'AUD 19F3' });
  file({ ref: 'e01b77c2', role: 'thirdparty', reason: 'model', at: T0 - 14 * 60e3, refused: 'The receipt signature does not verify against log key LOG KEY 1. It was not issued by this log.', key: 'KEY 88D0' });
  file({ req: pickReq((r) => r.at > T0 - 9 * 60e3 && !r.sel && r.model === 'mistral-small-3.2'), role: 'regulator', reason: 'routine', at: T0 - 40e3, key: 'REG 04A1' });
  file({ req: pickReq((r) => r.at > T0 - 3 * 60e3 && !r.sel && r.model === 'gemma-3-27b'), role: 'thirdparty', reason: 'altered', at: T0 - 7e3, key: 'KEY 3B9E' });

  /* ---------- the log: a signed tree head every 60 s and after every write (F29); here, one a minute ---------- */
  const LOG0 = leaf - requests.length;
  function heads(n = 12) {
    const out = [], minute = Math.floor(simNow / 60e3) * 60e3;
    for (let k = 0; k < n; k++) {
      const t = minute - k * 60e3, size = LOG0 + requests.filter((r) => r.at <= t).length;
      out.push({ t, size, root: hex(64, 'root ' + size), sig: hex(128, 'sth ' + size) });
    }
    return out;
  }
  const treeSize = () => LOG0 + requests.filter((r) => r.at <= simNow).length;

  /* ---------- the loop ---------- */
  const subs = new Set();
  let nextAt = T0 + 400;
  function tick() {
    const p = performance.now(), dt = p - last; last = p;
    const added = [];
    if (running) {
      simNow += Math.min(dt, 5000);
      while (nextAt <= simNow) { added.push(make(nextAt)); nextAt += 500 + rnd() * 2300; }
    }
    subs.forEach((fn) => fn({ added }));
  }
  setInterval(tick, 1000);

  root.Sample = {
    MODELS, OPS, RATE, PERIOD, PROOF_MS, STEPS, DELAY_ROUNDS,
    now, roundAt, roundTime, randomness, model, op, hex,
    requests, challenges, find: (id) => byId.get(String(id).toLowerCase()), stateOf, stage, heads, treeSize,
    make, file,
    on(fn) { subs.add(fn); return () => subs.delete(fn); },
    live(on) { if (on != null) { running = !!on; last = performance.now(); } return running; },
  };
})(window);
