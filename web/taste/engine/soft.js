/* Soft: outlines of shapes given as distance fields. A shape is one continuous field
   instead of straight lines and arcs, so every corner is soft and every part can move.
   Everything lives in a 100 x 100 box. Part of the taste foundation; the code is unchanged from its source.

   Soft.field(o)        -> f(x, y): signed distance to the ink, negative inside
   Soft.trace(o, N, to) -> walks the outline into `to` (a canvas context or Soft.pen())
   Soft.svg(o)          -> a complete <svg> string
   Soft.draw(ctx, o, x, y, size, N)

   o.mode   'frame'  : soft square with four windows, the star joins the frame
            'pieces' : the four windows themselves, the star is the gap between them
            'inlay'  : the four windows and the star as five pieces with a hairline (o.gap) between them
            'star'   : the star piece of the inlay alone
            'sil'    : the plain silhouette the windows live in
   o.sil    'square' | 'circle'   silhouette
   o.t      frame thickness (inset of the windows)
   o.neck   gap between two windows where they meet an edge
   o.tips   [top, right, bottom, left] 0..1, where the star touches each side
   o.wins   explicit windows [{cx, cy, ax, ay}] instead of tips
   o.k      corner radius where a window's arc meets an edge
   o.kin    radius of the windows' own corner, o.kout radius of the outer corner
   o.p      2 = corners are true arcs, 3 to 4 = squarer "continuous" corners
   o.fit    small windows shrink their corners to this share of their size, so they end as dots
   o.n      2 = round windows, lower = flatter, higher = squarer
   o.goo    lets windows melt into each other when they get close
   o.dent   { d, hw } soft notch in the outer edge at each tip                                  */
(function (root) {
  const smax = (a, b, k) => { if (k <= 0) return a > b ? a : b; const h = k - Math.abs(a - b); return (a > b ? a : b) + (h > 0 ? h * h / (4 * k) : 0); };
  const smin = (a, b, k) => -smax(-a, -b, k);

  const BASE = { mode: 'frame', sil: 'square', t: 12, neck: 5, a: 27, k: 7, kin: 7, kout: 14, p: 2, fit: 0.38, n: 2, gap: 3, ks: 3, goo: 0, dent: null, scale: null };

  // where the star touches the four sides, for the classic leaning star with small disc radius a
  function lean(a, t = BASE.t, neck = BASE.neck) { const w = 100 - 2 * t, p = (a + neck / 2) / w; return [p, 1 - p, 1 - p, p]; }

  function windows(o) {
    if (o.wins) return o.wins;
    const t = o.t, w = 100 - 2 * t, h = o.neck / 2, [T, R, B, L] = (o.tips || lean(o.a, t, o.neck)).map((v) => v * w), s = o.scale || [1, 1, 1, 1];
    return [
      { cx: t, cy: t, ax: (T - h) * s[0], ay: (L - h) * s[0] },
      { cx: 100 - t, cy: t, ax: (w - T - h) * s[1], ay: (R - h) * s[1] },
      { cx: 100 - t, cy: 100 - t, ax: (w - B - h) * s[2], ay: (w - R - h) * s[2] },
      { cx: t, cy: 100 - t, ax: (B - h) * s[3], ay: (w - L - h) * s[3] },
    ];
  }

  // intersection of two shapes with a soft corner of radius r. p = 2 gives a true arc, higher p a squarer, "continuous" corner
  function meet(a, b, r, p) {
    const A = a + r, B = b + r, m = A > B ? A : B;
    if (m <= 0) return m - r;
    if (A <= 0) return B - r;
    if (B <= 0) return A - r;
    return (p === 2 ? Math.sqrt(A * A + B * B) : Math.pow(Math.pow(A, p) + Math.pow(B, p), 1 / p)) - r;
  }

  function field(opts) {
    const o = { ...BASE, ...opts }, t = o.t, n = o.n, p = o.p, wins = windows(o).filter((w) => w.ax > 2.5 && w.ay > 2.5);
    const circle = o.sil === 'circle', lo = t, hi = 100 - t;
    for (const w of wins) w.r = Math.min(o.k, o.fit * Math.min(w.ax, w.ay));
    const dents = [];
    if (o.dent && o.mode === 'frame') {
      const { d, hw } = o.dent, R = (hw * hw + d * d) / (2 * d), w = 100 - 2 * t, tp = (o.tips || lean(o.a, t, o.neck)).map((v) => t + v * w);
      dents.push([tp[0], d - R, R], [100 - d + R, tp[1], R], [tp[2], 100 - d + R, R], [d - R, tp[3], R]);
    }
    const ell = (x, y, w) => {
      const u = (x - w.cx) / w.ax, v = (y - w.cy) / w.ay;
      if (n === 2) {
        const g = Math.sqrt(u * u + v * v);
        if (w.ax === w.ay) return (g - 1) * w.ax;
        if (g < 1e-5) return -Math.min(w.ax, w.ay);
        const gu = u / (g * w.ax), gv = v / (g * w.ay);
        return (g - 1) / Math.sqrt(gu * gu + gv * gv);
      }
      const au = Math.abs(u), av = Math.abs(v), g = Math.pow(Math.pow(au, n) + Math.pow(av, n), 1 / n);
      if (g < 1e-5) return -Math.min(w.ax, w.ay);
      const c = Math.pow(g, 1 - n), gu = c * Math.pow(au, n - 1) / w.ax, gv = c * Math.pow(av, n - 1) / w.ay;
      return (g - 1) / Math.sqrt(gu * gu + gv * gv);
    };
    return (x, y) => {
      const X = Math.max(lo - x, x - hi), Y = Math.max(lo - y, y - hi), disc = circle ? Math.hypot(x - 50, y - 50) - (50 - t) : 0;
      let H = 1e9;
      for (let i = 0; i < wins.length; i++) {
        const w = wins[i], room = circle ? disc : meet(X, Y, o.k > 0 ? Math.min(o.kin, w.r * o.kin / o.k) : o.kin, p), d = meet(room, ell(x, y, w), w.r, p);
        H = o.goo ? smin(H, d, o.goo) : Math.min(H, d);
      }
      if (o.mode === 'sil') return circle ? disc : meet(X, Y, o.kin, p);
      if (o.goo) H = Math.max(H, circle ? disc : meet(X, Y, o.kin, p)); // melted windows stay inside the room
      if (o.mode === 'pieces') return H;
      if (o.mode === 'star' || o.mode === 'inlay') { // the star as a piece of its own: the room minus the windows grown by the gap
        let S = circle ? disc : meet(X, Y, o.kin, p);
        for (let i = 0; i < wins.length; i++) S = meet(S, o.gap - ell(x, y, wins[i]), o.ks, 2);
        return o.mode === 'star' ? S : Math.min(H, S);
      }
      let ink = circle ? Math.hypot(x - 50, y - 50) - 50 : meet(Math.max(-x, x - 100), Math.max(-y, y - 100), o.kout, p);
      ink = Math.max(ink, -H);
      for (let i = 0; i < dents.length; i++) ink = smax(ink, dents[i][2] - Math.hypot(x - dents[i][0], y - dents[i][1]), o.dent.k ?? 4);
      return ink;
    };
  }

  /* ---------- outline: marching squares, joined into loops, drawn through midpoints ---------- */
  const PAD = 2;
  const cache = {};
  function buffers(N) {
    if (cache[N]) return cache[N];
    const M = N + 1, E = 2 * M * M;
    return (cache[N] = { F: new Float32Array(M * M), px: new Float32Array(E), py: new Float32Array(E), adj: new Int32Array(2 * E), seen: new Uint8Array(E), used: [] });
  }
  function trace(o, N, to) {
    const f = typeof o === 'function' ? o : field(o), M = N + 1, { F, px, py, adj, seen, used } = buffers(N), step = (100 + 2 * PAD) / N;
    // sample in blocks of 4 x 4: a block whose middle is far from any edge takes that one value
    const far = 5.8 * step;
    for (let bj = 0; bj < M; bj += 4) for (let bi = 0; bi < M; bi += 4) {
      const c = f(-PAD + (bi + 1.5) * step, -PAD + (bj + 1.5) * step), jm = Math.min(M, bj + 4), im = Math.min(M, bi + 4);
      if (c > far || c < -far) { for (let j = bj; j < jm; j++) for (let i = bi; i < im; i++) F[j * M + i] = c; }
      else for (let j = bj; j < jm; j++) for (let i = bi; i < im; i++) F[j * M + i] = f(-PAD + i * step, -PAD + j * step);
    }
    used.length = 0;
    const link = (a, b) => { adj[2 * a + (adj[2 * a] < 0 ? 0 : 1)] = b; adj[2 * b + (adj[2 * b] < 0 ? 0 : 1)] = a; };
    const edge = (i, j, vert, va, vb) => { // crossing point on the edge starting at grid point (i, j)
      const id = 2 * (j * M + i) + vert;
      if (!seen[id]) {
        seen[id] = 1; used.push(id); adj[2 * id] = adj[2 * id + 1] = -1;
        const u = va / (va - vb);
        px[id] = -PAD + (i + (vert ? 0 : u)) * step; py[id] = -PAD + (j + (vert ? u : 0)) * step;
      }
      return id;
    };
    for (let j = 0; j < N; j++) for (let i = 0; i < N; i++) {
      const a = F[j * M + i], b = F[j * M + i + 1], c = F[(j + 1) * M + i + 1], d = F[(j + 1) * M + i];
      const code = (a < 0 ? 1 : 0) | (b < 0 ? 2 : 0) | (c < 0 ? 4 : 0) | (d < 0 ? 8 : 0);
      if (code === 0 || code === 15) continue;
      const T = () => edge(i, j, 0, a, b), R = () => edge(i + 1, j, 1, b, c), B = () => edge(i, j + 1, 0, d, c), L = () => edge(i, j, 1, a, d);
      switch (code) {
        case 1: case 14: link(L(), T()); break;
        case 2: case 13: link(T(), R()); break;
        case 4: case 11: link(R(), B()); break;
        case 8: case 7: link(L(), B()); break;
        case 3: case 12: link(L(), R()); break;
        case 6: case 9: link(T(), B()); break;
        default: {
          const mid = (a + b + c + d) / 4 < 0, joinAC = code === 5 ? mid : !mid;
          if (joinAC) { link(T(), R()); link(L(), B()); } else { link(L(), T()); link(R(), B()); }
        }
      }
    }
    // walk every loop once
    for (let s = 0; s < used.length; s++) {
      const start = used[s];
      if (seen[start] !== 1) continue;
      const loop = [];
      let prev = -1, cur = start;
      while (cur >= 0 && seen[cur] === 1) { seen[cur] = 2; loop.push(cur); const nx = adj[2 * cur] !== prev ? adj[2 * cur] : adj[2 * cur + 1]; prev = cur; cur = nx; }
      const L = loop.length;
      if (L < 4) continue;
      const mx = (q) => (px[loop[q % L]] + px[loop[(q + 1) % L]]) / 2, my = (q) => (py[loop[q % L]] + py[loop[(q + 1) % L]]) / 2;
      to.moveTo(mx(0), my(0));
      for (let q = 1; q <= L; q++) to.quadraticCurveTo(px[loop[q % L]], py[loop[q % L]], mx(q), my(q));
      to.closePath();
    }
    for (let s = 0; s < used.length; s++) seen[used[s]] = 0;
    return to;
  }

  function pen() {
    const r = (v) => +v.toFixed(2); let d = '';
    return { moveTo: (x, y) => { d += `M${r(x)} ${r(y)}`; }, quadraticCurveTo: (a, b, x, y) => { d += `Q${r(a)} ${r(b)} ${r(x)} ${r(y)}`; }, closePath: () => { d += 'Z'; }, get d() { return d; } };
  }
  const path = (o, N = 200) => trace(o, N, pen()).d;
  const svg = (o, { fg = '#07080c', bg = null, N = 240, size = 512 } = {}) =>
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="${size}" height="${size}">${bg ? `<rect width="100" height="100" fill="${bg}"/>` : ''}<path fill="${fg}" fill-rule="evenodd" d="${path(o, N)}"/></svg>`;

  // draw into a canvas context; the glyph box maps to (x, y, size, size)
  function draw(ctx, o, x, y, size, N = 96, fill) {
    ctx.save(); ctx.translate(x, y); ctx.scale(size / 100, size / 100);
    ctx.beginPath(); trace(o, N, ctx);
    if (fill !== false) { if (fill) ctx.fillStyle = fill; ctx.fill('evenodd'); }
    ctx.restore();
  }

  root.Soft = { BASE, smax, smin, meet, lean, windows, field, trace, pen, path, svg, draw };
})(typeof window !== 'undefined' ? window : globalThis);
