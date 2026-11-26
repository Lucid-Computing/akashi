/* Taste: the drawing engine of the foundation. One classic script, one global: window.Taste.
   It works from file:// with no build step. It draws figures on a square lattice with a small fixed
   vocabulary (cipher characters and small tiles), carries changes with waves of light, and changes
   text through the cipher. Colours always come from the custom properties of the element a figure
   is mounted on (tokens.css and a theme), never from constants here.

   Load order: taste/engine/soft.js (optional for Taste, needed by brand files), then this file.
   The contract, with every function and option, is taste/README.md.

   Levels of reading, from clear to dark: a plain word (4), a cipher character (3), a shape (2),
   a dot (1), nothing (0). Decoding climbs the levels; ciphering goes down them.
   Motion: the reader's scroll drives the important changes, and they are reversible. Ambient motion
   is slow and sparse. Under prefers-reduced-motion nothing moves on its own. "#t=6" in the address
   freezes time at 6 seconds, for screenshots. */
(function (root) {
  'use strict';
  const DOM = typeof window !== 'undefined' && typeof document !== 'undefined';
  const TAU = Math.PI * 2;
  const FONT = { sans: '"Geist", system-ui, sans-serif', mono: '"Geist Mono", ui-monospace, Menlo, monospace' };

  /* ---------- maths ---------- */
  const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));
  // 0 below a, 1 above b, a smooth step between
  const smooth = (a, b, x) => { const u = clamp((x - a) / (b - a)); return u * u * (3 - 2 * u); };
  const mix = (a, b, t) => a + (b - a) * t;
  // a stable number in [0, 1) for a cell (i, j) and a seed s. The same inputs always give the same number
  const hash = (i, j, s = 0) => { let h = (Math.imul(i, 374761393) + Math.imul(j, 668265263) + Math.imul(s, 1442695041)) | 0; h = Math.imul(h ^ (h >>> 13), 1274126177); return ((h ^ (h >>> 16)) >>> 0) / 4294967296; };
  // smooth value noise in [0, 1]: neighbouring points get neighbouring values. Use it for clusters and density
  const noise = (x, y) => { const xi = Math.floor(x), yi = Math.floor(y), s = (t) => t * t * (3 - 2 * t), fx = s(x - xi), fy = s(y - yi), a = hash(xi, yi, 7), b = hash(xi + 1, yi, 7), c = hash(xi, yi + 1, 7), d = hash(xi + 1, yi + 1, 7); return a + (b - a) * fx + (c - a) * fy + (a - b - c + d) * fx * fy; };

  /* ---------- shapes as distance fields (negative inside) ---------- */
  const sdf = {
    // a box with soft corners of radius r: (x0, y0) top left, w by h
    box: (x, y, x0, y0, w, h, r = 0) => { const hx = w / 2, hy = h / 2, qx = Math.abs(x - x0 - hx) - (hx - r), qy = Math.abs(y - y0 - hy) - (hy - r); return Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) - r; },
    circle: (x, y, cx, cy, r) => Math.hypot(x - cx, y - cy) - r,
    // a shape and the inside of another: max; either: min
    and: (a, b) => Math.max(a, b),
    or: (a, b) => Math.min(a, b),
    not: (a) => -a,
  };

  /* ---------- the cipher ---------- */
  const HEX = '0123456789ABCDEF';
  const CIPHER = '0123456789ABCDEF0123456789ABCDEF#%&$@+=*/<>?!;:';
  const CIPHER_LOWER = '0123456789abcdef0123456789abcdef#%&$@+=*/<>?!;:';
  // the tiles, in order of weight: dot, character, coded square, ring, quarter, diamond, disc, star, square
  const SHAPES = ['dot', 'char', 'boxchar', 'ring', 'q', 'diamond', 'disc', 'star', 'box'];
  const NAMES = { dot: 'Dot', char: 'Character', boxchar: 'Coded square', ring: 'Ring', q: 'Quarter', diamond: 'Diamond', disc: 'Disc', star: 'Star', box: 'Square' };
  const SYMBOLS = ['dot', 'boxchar', 'ring', 'q', 'diamond', 'disc', 'star', 'box'];   // the shapes a cell can take (no plain character)
  const SCAN = ['char', 'char', 'ring', 'box', 'boxchar', 'q'];                        // what a cell shows while a wave is on it
  const LEVEL = { WORD: 4, CIPHER: 3, SHAPE: 2, DOT: 1, NONE: 0 };
  const cipherChar = (i, j, s = 0, set = CIPHER) => set[Math.floor(hash(i, j, s) * set.length)];

  /* ---------- tiles: the alphabet between code and light ----------
     tile(ctx, x, y, s, kind, col, r, o, bg): one tile of size s centred on (x, y).
     r in [0, 1) picks the character of 'char' and 'boxchar'; o (0 to 3) turns 'ring' and 'q'; bg is the colour cut out of 'boxchar' */
  const SG = [[1, 1], [-1, 1], [-1, -1], [1, -1]];
  function tile(ctx, x, y, s, kind, col, r = 0, o = 0, bg) {
    const h = s / 2; col = css(col); ctx.fillStyle = col; ctx.strokeStyle = col;
    if (kind === 'dot') { const d = Math.max(1.5, s * 0.15); ctx.fillRect(x - d / 2, y - d / 2, d, d); }
    else if (kind === 'char' || kind === 'boxchar') {
      if (kind === 'boxchar') { ctx.fillRect(x - h, y - h, s, s); ctx.fillStyle = css(bg || '#ffffff'); }
      ctx.font = `400 ${s * 0.74}px ${FONT.mono}`; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.fillText(HEX[Math.floor(r * 4099) % 16], x, y + s * 0.04);
    } else if (kind === 'ring') {
      const [sx, sy] = SG[o & 3], cx = x - sx * h, cy = y - sy * h, a0 = Math.atan2(0, sx), a1 = Math.atan2(sy, 0);
      ctx.lineWidth = Math.max(1, s * 0.095); for (const q of [0.4, 0.86]) { ctx.beginPath(); ctx.arc(cx, cy, s * q, a0, a1, sx * sy < 0); ctx.stroke(); }
    } else if (kind === 'q') {
      const [sx, sy] = SG[o & 3], cx = x - sx * h, cy = y - sy * h;
      ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + sx * s, cy); ctx.arc(cx, cy, s, Math.atan2(0, sx), Math.atan2(sy, 0), sx * sy < 0); ctx.closePath(); ctx.fill();
    } else if (kind === 'star') {
      ctx.beginPath(); ctx.moveTo(x, y - h); ctx.arc(x + h, y - h, h, Math.PI, Math.PI / 2, true); ctx.arc(x + h, y + h, h, -Math.PI / 2, Math.PI, true); ctx.arc(x - h, y + h, h, 0, -Math.PI / 2, true); ctx.arc(x - h, y - h, h, Math.PI / 2, 0, true); ctx.closePath(); ctx.fill();
    } else if (kind === 'diamond') { ctx.beginPath(); ctx.moveTo(x, y - h * 0.86); ctx.lineTo(x + h * 0.86, y); ctx.lineTo(x, y + h * 0.86); ctx.lineTo(x - h * 0.86, y); ctx.closePath(); ctx.fill(); }
    else if (kind === 'disc') { ctx.beginPath(); ctx.arc(x, y, h * 0.94, 0, TAU); ctx.fill(); }
    else if (kind === 'box') ctx.fillRect(x - h, y - h, s, s);
  }

  /* ---------- colour ----------
     colour(any) -> { r, g, b, a, css, rgb }: any CSS colour as numbers. rgb is "r,g,b" for building rgba() strings */
  const CC = new Map();
  let probeCtx = null;
  function colour(c) {
    if (c && typeof c === 'object') return c;
    c = String(c == null ? '' : c).trim();
    if (CC.has(c)) return CC.get(c);
    let v = null, m;
    if ((m = /^rgba?\(([^)]+)\)$/i.exec(c))) {
      const p = m[1].split(/[\s,/]+/).filter(Boolean).map((t) => (t.endsWith('%') ? parseFloat(t) * 2.55 : parseFloat(t)));
      v = [p[0], p[1], p[2], p[3] == null ? 1 : /%/.test(m[1].split(/[\s,/]+/).filter(Boolean)[3]) ? p[3] / 255 : p[3]];
    } else if ((m = /^color\(srgb\s+([^)]+)\)$/i.exec(c))) {
      const p = m[1].split(/[\s/]+/).filter(Boolean).map(parseFloat);
      v = [p[0] * 255, p[1] * 255, p[2] * 255, p[3] == null ? 1 : p[3]];
    } else if ((m = /^#([0-9a-f]{3,8})$/i.exec(c))) {
      let x = m[1]; if (x.length <= 4) x = [...x].map((d) => d + d).join('');
      v = [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2, 4), 16), parseInt(x.slice(4, 6), 16), x.length === 8 ? parseInt(x.slice(6, 8), 16) / 255 : 1];
    } else if (DOM) {
      if (!probeCtx) { const cv = document.createElement('canvas'); cv.width = cv.height = 1; probeCtx = cv.getContext('2d', { willReadFrequently: true }); }
      probeCtx.clearRect(0, 0, 1, 1); probeCtx.fillStyle = '#000'; probeCtx.fillStyle = c; probeCtx.fillRect(0, 0, 1, 1);
      const d = probeCtx.getImageData(0, 0, 1, 1).data; v = [d[0], d[1], d[2], d[3] / 255];
    } else v = [0, 0, 0, 1];
    const [r, g, b] = v.slice(0, 3).map((n) => Math.round(clamp(n || 0, 0, 255))), a = clamp(v[3]);
    const out = { r, g, b, a, rgb: `${r},${g},${b}`, css: a < 1 ? `rgba(${r},${g},${b},${+a.toFixed(3)})` : `rgb(${r},${g},${b})` };
    CC.set(c, out); return out;
  }
  const css = (c) => (c && typeof c === 'object' ? c.css : c);
  // the same colour at another opacity
  const alpha = (c, a) => { const k = colour(c); return `rgba(${k.rgb},${a})`; };
  // a colour between two others
  const blend = (c1, c2, t) => { const a = colour(c1), b = colour(c2); return colour(`rgb(${Math.round(mix(a.r, b.r, t))},${Math.round(mix(a.g, b.g, t))},${Math.round(mix(a.b, b.b, t))})`); };

  // the roles a figure reads from its element, with the neutral fallback used when tokens.css is missing
  const ROLES = {
    bg: ['--bg', '#f3f4f0'], fg: ['--fg', '#07080c'], mist: ['--fg-mist', '#686e88'], rule: ['--rule', '#07080c26'], strong: ['--rule-strong', '#07080c'],
    signal: ['--signal', '#07080c'], fill: ['--fill', '#07080c'], onFill: ['--on-fill', '#ffffff'], cipher: ['--cipher', '#6b718b'], dim: ['--cipher-dim', '#a3a7b8'],
    accent: ['--accent', '#07080c'], onAccent: ['--on-accent', '#ffffff'], light: ['--accent-light', '#ffffff'],
    paper: ['--ground-paper', '#f3f4f0'], night: ['--ground-night', '#07080c'], white: ['--ground-white', '#ffffff'], ink: ['--ink', '#07080c'], inkNight: ['--ink-night', '#ffffff'],
    mistPaper: ['--mist', '#686e88'], mistNight: ['--mist-night', '#8a8d97'],
  };
  const PAL = new WeakMap();
  /* palette(el): the roles of el's ground, read from its custom properties. Read once, then again only after a theme change
     (a class or style change on <html> or <body>, a stylesheet added, removed or loaded, or Taste.refresh()) */
  function palette(el) {
    if (!DOM) { const out = {}; for (const k in ROLES) out[k] = colour(ROLES[k][1]); return out; }
    el = el || document.documentElement;
    const hit = PAL.get(el); if (hit && hit.v === S.theme) return hit.c;
    const host = el === document.documentElement || el.tagName === 'CANVAS' || el.tagName === 'IMG' ? (el.tagName === 'CANVAS' || el.tagName === 'IMG' ? el.parentElement : document.body || el) : el;
    const p = document.createElement('i'); p.setAttribute('aria-hidden', 'true'); p.style.cssText = 'position:absolute;width:0;height:0;overflow:hidden;visibility:hidden;pointer-events:none;transition:none;animation:none';
    host.appendChild(p);
    const cs = getComputedStyle(p), out = {};
    for (const k in ROLES) { p.style.color = `var(${ROLES[k][0]}, ${ROLES[k][1]})`; out[k] = colour(cs.color); }
    p.remove();
    PAL.set(el, { v: S.theme, c: out }); return out;
  }

  /* ---------- light and grain ---------- */
  const rgbOf = (c) => (typeof c === 'string' && /^\d+\s*,\s*\d+\s*,\s*\d+$/.test(c) ? c : colour(c).rgb);
  /* pass(ctx, x, y, rho, bw, max, col): a pass of light, a wave. It leaves (x, y) and has reached radius rho. A faint band of width bw,
     a crisp leading edge, three thin rings behind it. Nothing is drawn beyond radius max. col: any colour (the accent as it reads on this ground) */
  function pass(ctx, x, y, rho, bw, max, col = '#93a5ff') {
    const rgb = rgbOf(col), ro = rho + bw / 2, ri = Math.max(0, rho - bw / 2);
    if (ri < max) { const band = new Path2D(); band.arc(x, y, ro, 0, TAU); band.arc(x, y, ri, 0, TAU); const g = ctx.createRadialGradient(x, y, ri, x, y, ro); g.addColorStop(0, `rgba(${rgb},0)`); g.addColorStop(1, `rgba(${rgb},0.15)`); ctx.fillStyle = g; ctx.fill(band, 'evenodd'); }
    if (ro < max) { ctx.strokeStyle = `rgba(${rgb},0.85)`; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(x, y, ro, 0, TAU); ctx.stroke(); }
    ctx.lineWidth = 1; for (const [d, a] of [[bw * 0.08, 0.55], [bw * 0.25, 0.32], [bw * 0.55, 0.15]]) { const rr = ri - d; if (rr > 0 && rr < max) { ctx.strokeStyle = `rgba(${rgb},${a})`; ctx.beginPath(); ctx.arc(x, y, rr, 0, TAU); ctx.stroke(); } }
  }
  /* passLine(ctx, x0, x1, y, bw, col, dir): the same pass, straightened: a crisp edge at y and three lines behind it (dir 1: it travels down, -1: up) */
  function passLine(ctx, x0, x1, y, bw, col = '#93a5ff', dir = 1) {
    const rgb = rgbOf(col);
    ctx.fillStyle = `rgba(${rgb},0.85)`; ctx.fillRect(x0, y - 1, x1 - x0, 2);
    for (const [d, a] of [[bw * 1.08, 0.55], [bw * 1.25, 0.32], [bw * 1.55, 0.15]]) { ctx.fillStyle = `rgba(${rgb},${a})`; ctx.fillRect(x0, Math.round(y - dir * d), x1 - x0, 1); }
  }
  let noiseCv = null;
  function noiseCanvas() {
    if (noiseCv || !DOM) return noiseCv;
    const c = document.createElement('canvas'); c.width = c.height = 256; const x = c.getContext('2d'), im = x.createImageData(256, 256); let s = 7;
    const rnd = () => ((s = (s * 1664525 + 1013904223) >>> 0) / 4294967296);
    for (let i = 0; i < im.data.length; i += 4) { const v = 128 + (rnd() + rnd() + rnd() - 1.5) * 150; im.data[i] = im.data[i + 1] = im.data[i + 2] = v; im.data[i + 3] = 255; }
    x.putImageData(im, 0, 0); return (noiseCv = c);
  }
  /* grain(ctx, x, y, w, h, a): film grain over a rectangle, on dark and accent grounds only. a: strength, 0.16 for a whole ground, 0.4 on a solid shape */
  function grain(ctx, x, y, w, h, a = 0.4) { const n = noiseCanvas(); if (!n) return; ctx.save(); ctx.globalCompositeOperation = 'overlay'; ctx.globalAlpha = a; ctx.fillStyle = ctx.createPattern(n, 'repeat'); ctx.fillRect(x, y, w, h); ctx.restore(); }
  /* grainTile(bg, a): a ground colour with the grain on it, baked into a 256 x 256 tile, as a data URL for CSS backgrounds */
  const GT = new Map();
  function grainTile(bg, a = 0.2) {
    const k = colour(bg), key = k.css + '|' + a; if (GT.has(key)) return GT.get(key);
    if (!noiseCanvas()) return '';
    const c = document.createElement('canvas'); c.width = c.height = 256; const x = c.getContext('2d');
    x.fillStyle = k.css; x.fillRect(0, 0, 256, 256); grain(x, 0, 0, 256, 256, a);
    let url = ''; try { url = c.toDataURL('image/png'); } catch (e) { url = ''; }
    GT.set(key, url); return url;
  }
  /* grainGround(el, a): lay the grain on an element's own ground (what the class "grain" does by itself). a: strength, from data-grain or 0.2 */
  function grainGround(el, a) {
    if (!DOM || !el) return;
    const bg = colour(getComputedStyle(el).backgroundColor); if (!bg.a) return;
    if (a == null) a = el.dataset.grain ? +el.dataset.grain : 0.2;
    const url = grainTile(bg, a); if (url) el.style.setProperty('--grain-tile', `url(${url})`);
  }

  /* ---------- the lattice ----------
     lattice(o): whole cells of a square lattice inside an area, and inside a shape if one is given.
     o.x o.y o.w o.h: the area. o.cell: the size of a cell. o.origin: [x, y] the lattice is anchored to (default: whole cells centred in the area).
     o.inside(x, y): a signed distance, negative inside (optional). o.margin: how far inside a cell's centre must lie, as a share of the cell
     (default 0.62: the whole cell is inside). o.seed.
     Returns an array of cells { i, j, x, y, d, r }: i and j count from the origin, so a cell keeps its identity (and its hash r)
     as the area moves or grows. The array also carries cols, rows, ox, oy and cell. */
  function lattice(o) {
    const c = o.cell, x = o.x || 0, y = o.y || 0, w = o.w, h = o.h, seed = o.seed || 0, margin = o.margin == null ? 0.62 : o.margin;
    const ox = o.origin ? o.origin[0] : x + (w - Math.floor(w / c) * c) / 2, oy = o.origin ? o.origin[1] : y + (h - Math.floor(h / c) * c) / 2;
    const i0 = Math.ceil((x - ox) / c - 1e-6), i1 = Math.floor((x + w - ox) / c + 1e-6), j0 = Math.ceil((y - oy) / c - 1e-6), j1 = Math.floor((y + h - oy) / c + 1e-6);
    const out = [];
    for (let j = j0; j < j1; j++) for (let i = i0; i < i1; i++) {
      const cx = ox + (i + 0.5) * c, cy = oy + (j + 0.5) * c, d = o.inside ? o.inside(cx, cy) : -Infinity;
      if (d < -margin * c) out.push({ i, j, x: cx, y: cy, d, r: hash(i, j, seed) });
    }
    Object.assign(out, { cols: Math.max(0, i1 - i0), rows: Math.max(0, j1 - j0), i0, j0, ox, oy, cell: c });
    return out;
  }
  /* rows(cols, rows, layers): characters on the lattice, kept a row at a time and drawn with one fillText per row and colour.
     put(i, j, ch, layer) sets a cell (i and j from 0), draw(ctx, ox, oy, cell, size, colours) paints layer k in colours[k], clear() empties it */
  function rows(cols, nrows, layers = 2) {
    const buf = [], has = [];
    for (let k = 0; k < layers; k++) { buf.push(new Uint16Array(cols * nrows).fill(32)); has.push(new Uint8Array(nrows)); }
    return {
      cols, rows: nrows,
      clear() { for (let k = 0; k < layers; k++) { buf[k].fill(32); has[k].fill(0); } },
      put(i, j, ch, layer = 0) { if (i < 0 || j < 0 || i >= cols || j >= nrows || !ch) return; buf[layer][j * cols + i] = ch.charCodeAt(0); has[layer][j] = 1; },
      draw(ctx, ox, oy, cell, size, colours) {
        ctx.font = `400 ${(size * 0.74).toFixed(2)}px ${FONT.mono}`; ctx.textBaseline = 'middle'; ctx.textAlign = 'left';
        const spaced = 'letterSpacing' in ctx; if (spaced) ctx.letterSpacing = '0px';
        const gw = ctx.measureText('0').width, x0 = ox + (cell - gw) / 2;
        if (spaced) ctx.letterSpacing = (cell - gw).toFixed(3) + 'px';
        for (let k = 0; k < layers; k++) {
          if (!colours[k]) continue; ctx.fillStyle = css(colours[k]); const b = buf[k];
          for (let j = 0; j < nrows; j++) {
            if (!has[k][j]) continue; const y = oy + (j + 0.5) * cell + size * 0.04;
            if (spaced) ctx.fillText(String.fromCharCode.apply(null, b.subarray(j * cols, (j + 1) * cols)), x0, y);
            else for (let i = 0; i < cols; i++) { const v = b[j * cols + i]; if (v !== 32) ctx.fillText(String.fromCharCode(v), x0 + i * cell, y); }
          }
        }
        if (spaced) ctx.letterSpacing = '0px';
      },
    };
  }

  /* ---------- scenes: one canvas per element, drawn by one shared loop ---------- */
  const S = { list: [], io: null, ro: null, started: false, looping: false, paused: false, pausedAt: 0, theme: 0, layout: 0, scrollers: new Set(), onScroll: new Set() };
  const ARGS = DOM ? Object.fromEntries(location.hash.slice(1).split('&').filter(Boolean).map((s) => s.split('='))) : {};
  // FIXED: the frozen time from "#t=" in the address, or null
  let FIXED = ARGS.t != null && isFinite(+ARGS.t) ? Math.max(0, +ARGS.t) : null;
  const RM = DOM && window.matchMedia ? matchMedia('(prefers-reduced-motion: reduce)') : null;
  let still = RM ? RM.matches : false;
  // motion(): may anything move on its own now? False under reduced motion, a frozen time, or a pause
  const motion = () => !still && FIXED == null && !S.paused;

  function dirtyAll() { for (const s of S.list) s.dirty = true; }
  /* scene(el, draw, options): give el a canvas that fills it and draw it in the shared loop.
     draw(ctx, w, h, time, now): ctx is scaled to CSS pixels; time in seconds (frozen by "#t=", held under reduced motion and pause).
     options.live: true redraws every frame while motion is allowed; a number redraws at most every that many milliseconds; false only when dirty.
     options.scroll: true redraws on every scroll (for scroll-driven figures). options.still: the time drawn under reduced motion (default 6.4).
     Returns the scene { el, cv, ctx, dirty }: set scene.dirty = true to have it drawn on the next frame. */
  function scene(el, draw, o = {}) {
    if (typeof o === 'boolean') o = { live: o };
    let cv = el.querySelector(':scope > canvas[data-taste]');
    if (!cv) { cv = document.createElement('canvas'); cv.setAttribute('data-taste', ''); cv.setAttribute('aria-hidden', 'true'); el.prepend(cv); }
    const st = getComputedStyle(el);
    if (st.position === 'static') el.style.position = 'relative';
    el.style.isolation = 'isolate';
    cv.style.cssText = 'position:absolute;left:0;top:0;width:100%;height:100%;display:block;pointer-events:none;z-index:-1';
    const s = { el, cv, ctx: cv.getContext('2d'), draw, live: o.live == null ? true : o.live, scroll: !!o.scroll, still: o.still == null ? 6.4 : o.still, seen: true, drawn: false, dirty: true, last: 0, dead: false };
    s.destroy = () => drop(s);
    S.list.push(s); if (s.scroll) S.scrollers.add(s);
    if (S.io) S.io.observe(el); if (S.ro) S.ro.observe(el);
    start(); return s;
  }
  // drop(scene): take a scene out of the loop and remove its canvas (scene.destroy() does the same)
  function drop(s) { if (!s || s.dead) return; s.dead = true; S.list = S.list.filter((x) => x !== s); S.scrollers.delete(s); if (S.io) S.io.unobserve(s.el); if (S.ro) S.ro.unobserve(s.el); s.cv.remove(); }
  function frame(now) {
    const dpr = Math.min(2, (DOM && devicePixelRatio) || 1), t = FIXED != null ? FIXED : S.paused ? S.pausedAt : now / 1000, moving = motion();
    for (const s of S.list) {
      const w = s.el.clientWidth, h = s.el.clientHeight;
      // a scene away from the screen is skipped, once it has been drawn: every canvas has a picture before any print
      if (!w || !h || (!s.seen && s.drawn)) continue;
      const W = Math.round(w * dpr), H = Math.round(h * dpr);
      if (s.cv.width !== W || s.cv.height !== H) { s.cv.width = W; s.cv.height = H; s.dirty = true; }
      const due = moving && (s.live === true || (typeof s.live === 'number' && now - s.last >= s.live));
      if (!due && !s.dirty) continue;
      s.last = now; s.dirty = false; s.drawn = true;
      const ctx = s.ctx; ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, w, h); ctx.save();
      if ('letterSpacing' in ctx) ctx.letterSpacing = '0px';
      try { s.draw(ctx, w, h, still && FIXED == null ? s.still : t, now); } catch (e) { console.error(e); s.draw = () => {}; }
      ctx.restore();
    }
  }
  const loop = (now) => { frame(now); requestAnimationFrame(loop); };
  /* start(): begin the loop once the two faces are loaded, so text drawn into canvases is in the right font from the first frame.
     scene() calls it; calling it again does nothing */
  function start() {
    if (!DOM || S.started) return; S.started = true;
    const fonts = document.fonts ? Promise.all([document.fonts.load(`400 20px ${FONT.mono}`), document.fonts.load(`600 40px ${FONT.sans}`), document.fonts.load(`400 20px ${FONT.sans}`)]).catch(() => {}) : Promise.resolve();
    const go = () => { if (!S.looping) { S.looping = true; S.layout++; dirtyAll(); requestAnimationFrame(loop); } };
    fonts.then(go); setTimeout(go, 1500);
  }
  // pause(on): stop or restart everything that moves on its own (for a page's own pause control). Returns the new state
  function pause(on = !S.paused) { if (on !== S.paused) { S.paused = on; S.pausedAt = performance.now() / 1000; dirtyAll(); } return S.paused; }
  const togglePause = () => pause(!S.paused);
  // refresh(): read the colours of every figure again and redraw (after changing a theme in a way Taste cannot see)
  function refresh() { S.theme++; S.layout++; dirtyAll(); }
  /* drawAll(): draw every scene now, including the ones away from the screen. Call it before printing or exporting a PDF
     (not from inside a "beforeprint" handler: Chrome prints the clear pixels of a canvas drawn during the print as white) */
  function drawAll() { if (!DOM) return; S.list.forEach((s) => { s.seen = true; s.dirty = true; }); frame(performance.now()); }
  /* freeze(t): hold time at t seconds, as "#t=" in the address does (for screenshots and PDFs); freeze(null) lets it run again */
  function freeze(t) { FIXED = t == null || !isFinite(+t) ? null : Math.max(0, +t); S.layout++; dirtyAll(); return FIXED; }

  /* ---------- scroll ---------- */
  const vh = () => (DOM ? innerHeight : 800);
  // scrub(el): how far a tall block with a pinned child has been scrolled through: 0 as its top reaches the top of the screen, 1 as its bottom reaches the bottom
  const scrub = (el) => clamp(-el.getBoundingClientRect().top / Math.max(1, el.offsetHeight - vh()));
  // cross(el): how far a block has crossed the screen: 0 as its top enters at the bottom, 1 as its bottom leaves at the top
  const cross = (el) => { const q = el.getBoundingClientRect(); return clamp((vh() - q.top) / (vh() + q.height)); };
  // onScroll(fn): call fn once per frame while the page scrolls (and once now). Returns a function that stops it
  function onScroll(fn) { S.onScroll.add(fn); if (DOM) requestAnimationFrame(() => fn()); return () => S.onScroll.delete(fn); }

  /* ---------- text through the cipher ----------
     cipherText(el, text, options) -> Promise: change el's text through the cipher, one character at a time. The old text goes down
     (two cipher steps, then gone); the new one climbs (three cipher steps, then the letter). Words never break while it runs.
     options: { step (ms per cipher step, default 46), out (false: skip the old text leaving), order ('ltr' or 'random'), instant }.
     Under reduced motion, a frozen time, or a pause, the text changes at once. Replaces any child elements with plain text */
  const RUN = new WeakMap();
  /* the shown letters are aria-hidden (their cipher glyphs are drawn by CSS, which a screen reader would read out);
     a visually hidden copy carries the text the element is going to, so it is read out once, as words */
  function spans(el, text, says) {
    const out = [], frag = document.createDocumentFragment();
    for (const part of String(text).split(/(\s+)/)) {
      if (!part) continue;
      if (/^\s+$/.test(part)) { frag.append(' '); continue; }
      const w = document.createElement('span'); w.className = 't-w';
      for (const ch of part) { const s = document.createElement('span'); s.className = 't-ch'; s.textContent = ch; w.append(s); out.push(s); }
      frag.append(w);
    }
    const box = document.createElement('span'); box.setAttribute('aria-hidden', 'true'); box.append(frag);
    if (says) { const hid = document.createElement('span'); hid.className = 'vh'; hid.textContent = says; el.replaceChildren(hid, box); }
    else el.replaceChildren(box);
    return out;
  }
  function cipherText(el, text, o = {}) {
    if (typeof el === 'string') el = document.querySelector(el);
    if (!el) return Promise.resolve();
    const prev = RUN.get(el); if (prev) prev.stop();
    text = String(text);
    if (o.instant || !motion() || !DOM) { el.textContent = text; return Promise.resolve(); }
    const mono = /mono/i.test(getComputedStyle(el).fontFamily.split(',')[0]); el.classList.toggle('t-mono', mono);
    const step = o.step || 46, seed = Math.floor(Math.random() * 1e6);
    let raf = 0, done = null;
    const order = (n, k) => (o.order === 'random' ? hash(k, n, seed) : k / Math.max(1, n));
    const job = { stop() { cancelAnimationFrame(raf); el.classList.remove('t-mono'); el.textContent = text; RUN.delete(el); if (done) done(); } };
    RUN.set(el, job);
    return new Promise((resolve) => {
      done = resolve;
      const old = el.textContent, outSpread = Math.min(260, old.length * 18), inSpread = clamp(text.length * 24, 120, 520);
      let phase = old.trim() && o.out !== false ? 0 : 1, chs = phase === 0 ? spans(el, old, text) : null, t0 = performance.now();
      const glyph = (s, a, b) => { s.classList.remove('t-off'); s.classList.add('t-x'); s.dataset.g = CIPHER[Math.floor(hash(a, b, seed) * CIPHER.length)]; };
      const begin = () => { phase = 1; t0 = performance.now(); chs = spans(el, text, text); chs.forEach((s) => s.classList.add('t-off')); };
      if (phase === 1) begin();
      const tick = (now) => {
        const e = now - t0, n = chs.length; let busy = false;
        if (phase === 0) {
          chs.forEach((s, j) => { const u = e - (outSpread * order(n, j) + 60 * hash(j, 1, seed)); if (u < 0) { busy = true; return; }
            const ph = Math.floor(u / (step * 1.1)); if (ph < 2) { busy = true; glyph(s, j, ph + 11); } else { s.classList.add('t-off'); s.classList.remove('t-x'); } });
          if (!busy) begin();
          raf = requestAnimationFrame(tick); return;
        }
        chs.forEach((s, j) => { const u = e - (20 + inSpread * order(n, j) + 90 * hash(j, 2, seed)); if (u < 0) { busy = true; return; }
          const ph = Math.floor(u / (step * 1.2)); if (ph < 3) { busy = true; glyph(s, j, ph + 21); } else s.classList.remove('t-off', 't-x'); });
        if (busy) raf = requestAnimationFrame(tick); else job.stop();
      };
      raf = requestAnimationFrame(tick);
    });
  }

  /* ---------- headings and reading ---------- */
  /* reveal(targets): each heading is crossed by a pass of light the first time it is seen (base.css .rv). Taste runs it on every .rv when the page loads */
  function reveal(targets = '.rv') {
    if (!DOM) return;
    const els = all(targets), ok = window.CSS && (CSS.supports('background-clip', 'text') || CSS.supports('-webkit-background-clip', 'text'));
    if (!ok || !motion() || !('IntersectionObserver' in window)) return;
    const ob = new IntersectionObserver((es) => es.forEach((e) => {
      if (!e.isIntersecting) return; ob.unobserve(e.target);
      if (!motion()) { e.target.classList.add('rv-done'); return; }
      e.target.classList.add('rv-in'); setTimeout(() => e.target.classList.add('rv-done'), 1500);
    }), { threshold: 0.3 });
    els.forEach((e) => { if (e.classList.contains('rv-on')) return; e.classList.add('rv-on'); ob.observe(e); });
  }
  /* readProgress(targets): set --p (0 to 1) on each element as the reader goes through it, so the .sq inside fills like a ticked list */
  function readProgress(targets = '[data-read]') {
    if (!DOM) return;
    const els = all(targets); let last = [];
    const tick = () => {
      const end = scrollY + innerHeight >= document.documentElement.scrollHeight - 4, y = innerHeight * 0.55;
      els.forEach((s, i) => { const q = s.getBoundingClientRect(), p = end ? 1 : Math.round(clamp((y - q.top) / Math.max(1, q.height)) * 40) / 40; if (p !== last[i]) { last[i] = p; s.style.setProperty('--p', p); } });
    };
    return onScroll(tick);
  }

  /* ---------- helpers for figures ---------- */
  function all(t) { if (!DOM || t == null) return []; if (typeof t === 'string') return [...document.querySelectorAll(t)]; if (t instanceof Element) return [t]; return [...t]; }
  /* rectsOf(sel, el): the boxes of the elements sel names, relative to el, as [left, top, right, bottom]. Text is measured line by line.
     A selector is looked for inside el first; if nothing inside matches, in the whole document (the hero's words sit beside its stage).
     Pass elements (an element or an array) to be exact, as a deck does */
  function rectsOf(sel, el) {
    if (!sel) return [];
    const base = el.getBoundingClientRect(), list = typeof sel === 'string' ? (el.querySelector(sel) ? el.querySelectorAll(sel) : document.querySelectorAll(sel)) : sel instanceof Element ? [sel] : sel;
    const out = []; const range = document.createRange();
    for (const n of list) {
      // text is kept clear line by line, so a short last line does not clear the whole block; controls by their whole box
      const dsp = getComputedStyle(n).display, block = !/^(A|BUTTON|INPUT|SELECT|TEXTAREA|IMG|SVG|CANVAS)$/i.test(n.tagName) && !/flex|grid/.test(dsp) && n.childElementCount === 0 && n.textContent.trim();
      if (block) { range.selectNodeContents(n); for (const q of range.getClientRects()) if (q.width > 1) out.push([q.left - base.left, q.top - base.top, q.right - base.left, q.bottom - base.top]); }
      else { const q = n.getBoundingClientRect(); if (q.width && q.height) out.push([q.left - base.left, q.top - base.top, q.right - base.left, q.bottom - base.top]); }
    }
    return out;
  }
  /* the drive of a figure: what sets its progress p (0 to 1).
     'cross' (default): the block crossing the screen, mapped through range. 'pin': the scroll through the nearest .pin block.
     'time': on its own, slowly there and back (held at options.still under reduced motion). 'manual': only set() and play().
     options.of: another element whose crossing (or pinned scroll) drives it, such as the tall block a figure sits in */
  function driver(el, o, onChange) {
    const d = { manual: null, anim: 0 };
    const range = o.range;
    const map = (v) => clamp((v - range[0]) / (range[1] - range[0]));
    d.value = (time) => {
      if (d.manual != null) return d.manual;
      if (o.drive === 'manual') return o.start;
      if (o.drive === 'time') { if (!motion()) return o.still; const u = ((time % o.period) + o.period) % o.period / o.period; return smooth(0, 1, u < 0.5 ? u * 2 : 2 - u * 2); }
      if (o.drive === 'pin') return map(scrub(o.pin || o.of || el.closest('.pin') || el));
      return map(cross(o.of || el));
    };
    d.set = (p) => { cancelAnimationFrame(d.anim); d.manual = p == null ? null : clamp(p); onChange(); };
    d.play = (to = 1, ms = 2400, from) => new Promise((resolve) => {
      cancelAnimationFrame(d.anim);
      const a = from != null ? from : d.manual != null ? d.manual : d.value(performance.now() / 1000);
      if (!motion() || ms <= 0) { d.manual = clamp(to); onChange(); resolve(); return; }
      const t0 = performance.now();
      const step = (now) => { const u = clamp((now - t0) / ms); d.manual = mix(a, to, u * u * (3 - 2 * u)); onChange(); if (u < 1) d.anim = requestAnimationFrame(step); else resolve(); };
      d.anim = requestAnimationFrame(step);
    });
    return d;
  }
  const CORNERS = [[0, 0], [1, 1], [1, 0], [0, 1]];

  /* ---------- figure: field ----------
     A lattice field of cipher cells. As the block is scrolled it gathers (a dot first, then a character or a shape, in clusters),
     then waves of light cross it from the corners: behind each wave most cells go down the cipher and vanish, and the few that
     survive climb a level with every wave until they are solid. Scrolling back runs it backwards.
     Taste.figures.field(el, { drive, of, range, cell, density, waves, keep, clear, fade, still, period, start, seed }) -> handle.
     cell: px, or a function (w, h) -> px (a share of the figure's size, for a frame that scales) */
  function field(target, opts = {}) {
    const el = all(target)[0]; if (!el) return null;
    const o = { drive: 'cross', cell: 0, density: 0.5, waves: 2, keep: 0.2, clear: null, fade: '', still: 0.4, start: 0, period: 22, seed: 0, ...opts };
    if (!o.range) o.range = o.drive === 'pin' ? [0.02, 0.92] : [0.06, 0.6];
    let L = null, sc = null;
    const WL = 0.2, drive = driver(el, o, () => { if (sc) sc.dirty = true; });
    const layout = (w, h) => {
      const c = (typeof o.cell === 'function' ? o.cell(w, h) : o.cell) || (w > 900 ? clamp(w * 0.0105, 15, 18) : 12.5), S2 = c * 0.9, cols = Math.max(1, Math.floor(w / c)), nrows = Math.max(1, Math.floor(h / c)), ox = (w - cols * c) / 2, oy = (h - nrows * c) / 2;
      const clear = rectsOf(o.clear, el), fade = String(o.fade), dens = clamp(o.density * 2, 0.05, 2), seed = o.seed * 101;
      const cells = [], corners = CORNERS.slice(0, 3).map(([u, v]) => [u * w, v * h]);
      for (let j = 0; j < nrows; j++) for (let i = 0; i < cols; i++) {
        const x = ox + (i + 0.5) * c, y = oy + (j + 0.5) * c;
        let keep = 1;
        for (const q of clear) { const dx = Math.max(q[0] - x, 0, x - q[2]), dy = Math.max(q[1] - y, 0, y - q[3]); keep = Math.min(keep, smooth(c * 1.5, c * 5, Math.hypot(dx, dy))); }
        if (/bottom|edges/.test(fade)) keep *= 1 - smooth(h - 6 * c, h - c, y);
        if (/top|edges/.test(fade)) keep *= smooth(c, 6 * c, y);
        if (/edges/.test(fade)) keep *= smooth(c, 6 * c, x) * (1 - smooth(w - 6 * c, w - c, x));
        if (keep <= 0) continue;
        const dn = 0.68 * noise(i / 6.2 + 3.1 + seed, j / 6.2 + 7.7) + 0.32 * noise(i / 2.4 + 11.3 + seed, j / 2.4 + 5.9);
        if (hash(i, j, 1 + seed) > Math.min(1, smooth(0.4, 0.72, dn) * 0.94 * dens) * keep) continue;
        const lv = dn + (hash(i, j, 4 + seed) - 0.5) * 0.24, z = hash(i, j, 6 + seed);
        const kind = lv > 0.63 ? SYMBOLS[1 + Math.floor(z * 7)] : lv > 0.47 ? 'char' : 'dot';
        cells.push({ i, j, x, y, kind, z, col: kind === 'char' || kind === 'dot' ? 'cipher' : hash(i, j, 7 + seed) < 0.05 ? 'signal' : 'fg', o: Math.floor(hash(i, j, 8 + seed) * 4),
          a: 0.36 * (0.6 * (1 - smooth(0.42, 0.78, dn)) + 0.4 * hash(i, j, 9 + seed)), d: corners.map((p) => Math.hypot(x - p[0], y - p[1])),
          surv: hash(i, j, 77 + seed) < o.keep, kill: Math.floor(hash(i, j, 78 + seed) * Math.max(1, o.waves)), nc: 3 + Math.floor(hash(i, j, 32 + seed) * 3), h1: hash(i, j, 31 + seed),
          up: kind === 'char' || kind === 'dot' ? SYMBOLS[2 + Math.floor(z * 6)] : kind });
      }
      const free = 1 - 0.44 - WL, ws = Array.from({ length: o.waves }, (_, k) => 0.44 + (o.waves === 1 ? free / 2 : free * k / (o.waves - 1)));
      L = { w, h, c, S: S2, cols, nrows, ox, oy, cells, corners, ws, diag: Math.hypot(w, h), grid: rows(cols, nrows, 2), v: S.layout, th: S.theme };
    };
    sc = scene(el, (ctx, w, h, time) => {
      if (!L || L.w !== w || L.h !== h || L.v !== S.layout) layout(w, h);
      const C = palette(el), p = drive.value(time), moving = motion(), tick = moving ? Math.floor(time * 8) : 0, slow = moving ? time * 0.22 : 0;
      const { c, S: sz, grid } = L, bw = Math.max(60, L.diag * 0.07), stepLen = c * 2.7, tiles = [];
      grid.clear();
      const rho = L.ws.map((s) => { const u = (p - s) / WL; return u <= 0 ? -1e9 : -bw / 2 + Math.min(1, u) * (L.diag + bw + 9.5 * stepLen); });
      const rest = (q) => { if (q.kind === 'char') grid.put(q.i, q.j, CIPHER[Math.floor(hash(q.i, q.j, 2 + Math.floor(slow + q.z * 9)) * CIPHER.length)], 0); else tiles.push([q.x, q.y, q.kind, C[q.col], q.z, q.o]); };
      const scan = (q) => { const z = hash(q.i, q.j, tick); tiles.push([q.x, q.y, SCAN[Math.floor(z * 6)], C.signal, z, Math.floor(z * 4)]); };
      for (const q of L.cells) {
        if (p < q.a) continue;
        if (p < q.a + 0.025) { tiles.push([q.x, q.y, 'dot', C.cipher, 0, 0]); continue; }
        let band = false, lev = 0;
        for (let k = 0; k < rho.length; k++) { const r = rho[k]; if (r < -1e8) continue; const dd = q.d[k % 3]; if (Math.abs(dd - r) < bw / 2) band = true; else if (dd < r - bw / 2) lev++; }
        if (q.surv) {
          if (band) scan(q);
          else if (lev >= o.waves && o.waves > 0) tiles.push([q.x, q.y, 'box', C.fg, 0, 0]);
          else if (lev === o.waves - 1 && lev > 0) tiles.push([q.x, q.y, 'boxchar', C.fg, q.z, 0]);
          else if (lev >= 1) tiles.push([q.x, q.y, q.up, C.fg, q.z, q.o]);
          else rest(q);
          continue;
        }
        const r = rho[q.kill], dS = r == null ? -1e9 : r - q.d[q.kill % 3], st = dS > bw / 2 ? Math.max(0, Math.floor((dS - bw / 2) / stepLen - q.h1 * 1.6)) : -1;
        if (st < 0) { if (band) scan(q); else rest(q); }
        else if (st < q.nc) grid.put(q.i, q.j, CIPHER[Math.floor(hash(q.i, q.j, 50 + st) * CIPHER.length)], st === 0 ? 1 : 0);
        else if (st === q.nc) tiles.push([q.x, q.y, SYMBOLS[1 + Math.floor(q.z * 7)], C.cipher, q.z, q.o]);
        else if (st === q.nc + 1) tiles.push([q.x, q.y, 'dot', C.dim, 0, 0]);
      }
      grid.draw(ctx, L.ox, L.oy, c, sz, [C.cipher, C.signal]);
      for (const t of tiles) tile(ctx, t[0], t[1], sz, t[2], t[3], t[4], t[5], C.bg);
      ctx.textAlign = 'left'; ctx.textBaseline = 'alphabetic';
      rho.forEach((r, k) => { if (r > -bw && r - bw < L.diag * 1.2) pass(ctx, L.corners[k % 3][0], L.corners[k % 3][1], r, bw, L.diag * 1.3, C.signal); });
    }, { live: 66, scroll: o.drive === 'cross' || o.drive === 'pin', still: 6.4 });
    return { el, scene: sc, set: drive.set, play: drive.play, progress: () => drive.value(performance.now() / 1000), refresh() { L = null; sc.dirty = true; }, destroy() { drop(sc); } };
  }

  /* ---------- figure: wave ----------
     A headline (or any line of text) that stays real type, crossed by waves of light. Under a wave each letter steps aside and
     the lattice stands in for it, knocked down the cipher cell by cell; behind the wave every letter comes back, exactly.
     The first wave is moved by the scroll as the text comes up the screen; after it a wave comes every few seconds.
     Taste.figures.wave(el, { scroll, repeat, every, bleed, cell, still }) -> handle with pass() to send a wave now.
     still (0 to 1, or null): when nothing may move (reduced motion, "#t=", a pause, a print), a wave held this far across the text */
  function wave(target, opts = {}) {
    const el = all(target)[0]; if (!el) return null;
    const o = { scroll: true, repeat: true, every: 8.5, bleed: 1, cell: 0, still: null, ...opts };
    const text = el.textContent.replace(/\s+/g, ' ').trim();
    // the visible copy, a letter per span; the hidden copy is read out
    const vis = document.createElement('span'); vis.setAttribute('aria-hidden', 'true'); vis.className = 't-wave-text';
    while (el.firstChild) vis.appendChild(el.firstChild);
    const glyphs = [];
    const walk = (n) => { for (const k of [...n.childNodes]) {
      if (k.nodeType !== 3) { walk(k); continue; }
      const frag = document.createDocumentFragment();
      for (const part of k.textContent.split(/(\s+)/)) {
        if (!part) continue; if (/^\s+$/.test(part)) { frag.append(' '); continue; }
        const w = document.createElement('span'); w.className = 't-w';
        for (const ch of part) { const g = document.createElement('span'); g.className = 't-g'; g.textContent = ch; w.appendChild(g); glyphs.push({ el: g, ch, off: false, cells: [] }); }
        frag.append(w);
      }
      k.replaceWith(frag);
    } };
    walk(vis);
    const hid = document.createElement('span'); hid.className = 'vh'; hid.textContent = text;
    el.append(hid, vis);
    if (getComputedStyle(el).position === 'static') el.style.position = 'relative';
    el.style.isolation = 'isolate';
    const stage = document.createElement('div'); stage.className = 't-wave-stage'; stage.setAttribute('aria-hidden', 'true'); el.appendChild(stage);
    // the light reaches past the text by the bleed above and below, and sideways only as far as the page allows, so the page never scrolls sideways
    const bleed = (fs) => { const B = Math.round(fs * o.bleed), er = el.getBoundingClientRect(), W = document.documentElement.clientWidth;
      const L = Math.max(0, Math.min(B, Math.floor(er.left))), R = Math.max(0, Math.min(B, Math.floor(W - er.right)));
      stage.style.inset = `${-B}px ${-R}px ${-B}px ${-L}px`; return { B, L, R }; };
    bleed(parseFloat(getComputedStyle(el).fontSize) || 16);
    const mk = document.createElement('canvas'), mx = mk.getContext('2d', { willReadFrequently: true });
    const M = { ok: false, fs: 0, c: 10, bw: 100, B: 0, v: -1, w: 0 };
    let trig = -1e9, trigN = 0;
    const layout = () => {
      const cs = getComputedStyle(el), fs = parseFloat(cs.fontSize); if (!fs) return;
      const { B, L, R } = bleed(fs);
      const er = el.getBoundingClientRect(), sx = er.left - L, sy = er.top - B, upper = cs.textTransform === 'uppercase';
      const font = `${cs.fontStyle} ${cs.fontWeight} ${fs}px ${cs.fontFamily}`, c = o.cell || clamp(fs * 0.07, 6, 13.5), u = 4;
      mx.font = font; const asc = mx.measureText('H').fontBoundingBoxAscent, cap = mx.measureText('H').actualBoundingBoxAscent;
      let x0 = 1e9;
      for (const g of glyphs) { const q = g.el.getBoundingClientRect(); g.x = q.left - sx; g.base = q.top - sy + asc; g.w = q.width; x0 = Math.min(x0, g.x); }
      for (const g of glyphs) {
        const ch = upper ? g.ch.toUpperCase() : g.ch; mx.font = font; const m = mx.measureText(ch), y0 = g.base - cap, line = Math.round(y0 / fs);
        const i0 = Math.floor((g.x - m.actualBoundingBoxLeft - x0) / c), i1 = Math.ceil((g.x + m.actualBoundingBoxRight - x0) / c), j0 = Math.floor((g.base - m.actualBoundingBoxAscent - y0) / c), j1 = Math.ceil((g.base + m.actualBoundingBoxDescent - y0) / c);
        const cw = Math.max(1, i1 - i0), chh = Math.max(1, j1 - j0); g.cells = [];
        mk.width = Math.ceil(cw * u); mk.height = Math.ceil(chh * u);
        mx.setTransform(u / c, 0, 0, u / c, 0, 0); mx.clearRect(0, 0, cw * c, chh * c); mx.font = font; mx.fillStyle = '#000'; mx.textBaseline = 'alphabetic';
        mx.fillText(ch, g.x - (x0 + i0 * c), g.base - (y0 + j0 * c)); mx.setTransform(1, 0, 0, 1, 0, 0);
        const d = mx.getImageData(0, 0, mk.width, mk.height).data;
        for (let j = 0; j < chh; j++) for (let i = 0; i < cw; i++) {
          let n = 0; for (let b = 0; b < u; b++) for (let a = 0; a < u; a++) if (d[((j * u + b) * mk.width + i * u + a) * 4 + 3] > 110) n++;
          g.cells.push([x0 + (i0 + i + 0.5) * c, y0 + (j0 + j + 0.5) * c, i0 + i, j0 + j + line * 97, n / (u * u) >= 0.3]);
        }
        g.cx = g.x + g.w / 2; g.cy = g.base - cap / 2; g.rad = Math.hypot(cw, chh) * c * 0.36;
      }
      Object.assign(M, { ok: true, fs, c, bw: Math.max(90, fs * 1.05), B, L, R, v: S.layout, w: er.width, h: er.height });
    };
    const far = (x, y) => { let f = 0; for (const g of glyphs) f = Math.max(f, Math.hypot(g.cx - x, g.cy - y) + g.rad); return f; };
    const sc = scene(stage, (ctx, w, h, time, now) => {
      const er = el.getBoundingClientRect();
      if (!M.ok || M.v !== S.layout || Math.abs(M.w - er.width) > 0.5 || Math.abs(M.h - er.height) > 0.5) layout();
      if (!M.ok) return;
      const C = palette(el), bw = M.bw, B = M.B, BL = M.L, BR = M.R;
      let wx = 0, wy = 0, rho = -1, flick = 0;
      const p = o.scroll ? clamp((vh() * 0.95 - (er.bottom - M.fs * 0.2)) / (vh() * 0.5)) : 1;
      const tN = now / 1000;
      if (o.still != null && !motion() && (p <= 0 || p >= 1)) { wx = BL * 0.5; wy = B * 0.5; rho = clamp(o.still) * (far(wx, wy) + bw); flick = 0; }
      else if (p > 0 && p < 1) { wx = BL * 0.5; wy = B * 0.5; rho = p * (far(wx, wy) + bw); flick = Math.floor(rho / (M.c * 1.7)); }
      else if (motion() && tN - trig < 4) {
        const cr = CORNERS[trigN % 4], fx = cr[0] * w, fy = cr[1] * h, reach = far(fx, fy) + bw, dur = clamp(reach / Math.max(560, w * 0.5), 1.6, 3.2), t = tN - trig;
        if (t < dur) { wx = fx; wy = fy; rho = (t / dur) * reach; flick = Math.floor(tN * 9); }
      } else if (p >= 1 && o.repeat && motion()) {
        const WP = o.every, k = Math.floor(time / WP), t = time - k * WP, cr = CORNERS[k % 4], fx = cr[0] * w, fy = cr[1] * h, reach = far(fx, fy) + bw, dur = clamp(reach / Math.max(560, w * 0.5), 1.6, 3.2);
        if (t < dur) { wx = fx; wy = fy; rho = (t / dur) * reach; flick = Math.floor(time * 9); }
      }
      if (rho > 0) {
        pass(ctx, wx, wy, rho, bw, Math.hypot(w, h) * 1.5, C.signal);
        // the light thins out towards the edges of the stage, so it has no edge of its own
        ctx.save(); ctx.globalCompositeOperation = 'destination-out';
        const edge = (x0, y0, x1, y1, rx, ry, rw, rh) => { const g = ctx.createLinearGradient(x0, y0, x1, y1); g.addColorStop(0, 'rgba(0,0,0,1)'); g.addColorStop(1, 'rgba(0,0,0,0)'); ctx.fillStyle = g; ctx.fillRect(rx, ry, rw, rh); };
        edge(0, 0, 0, B, 0, 0, w, B); edge(0, h, 0, h - B, 0, h - B, w, B);
        if (BL > 0) edge(0, 0, BL, 0, 0, 0, BL, h); if (BR > 0) edge(w, 0, w - BR, 0, w - BR, 0, BR, h);
        ctx.restore();
      }
      const S2 = M.c * 0.9, tiles = [], cols = [[], [], []], light = blend(C.fg, C.bg, 0.12);
      for (const g of glyphs) {
        const on = rho > 0 && Math.abs(Math.hypot(g.cx - wx, g.cy - wy) - rho) < bw / 2 + g.rad;
        if (on !== g.off) { g.off = on; g.el.classList.toggle('t-x', on); }
        if (!on) continue;
        for (const [x, y, i, j, ink] of g.cells) {
          const e = Math.abs(Math.hypot(x - wx, y - wy) - rho), lv = (1 - e / (bw / 2)) * 3.8 + (hash(i, j, 7) - 0.5) * 1.2;
          if (!ink) { if (lv > 0.6 && lv < 2.6 && hash(i, j, 3) < 0.09) cols[2].push(x, y, CIPHER[Math.floor(hash(i, j, 41 + flick) * CIPHER.length)]); continue; }
          if (lv < 1) cols[0].push(x, y, CIPHER[Math.floor(hash(i, j, 40 + Math.floor(Math.max(0, lv) * 3) + (e < bw * 0.6 ? flick : 0)) * CIPHER.length)]);
          else if (lv < 1.9) cols[1].push(x, y, CIPHER[Math.floor(hash(i, j, 44 + Math.floor(lv * 3) + flick) * CIPHER.length)]);
          else if (lv < 2.8) { const z = hash(i, j, 60); tiles.push([x, y, SYMBOLS[1 + Math.floor(z * 7)], z < 0.16 ? C.signal : light, z]); }
          else if (lv < 3.35) tiles.push([x, y, 'dot', C.mist, 0]);
        }
      }
      if (tiles.length || cols[0].length || cols[1].length || cols[2].length) {
        ctx.font = `500 ${(S2 * 0.8).toFixed(2)}px ${FONT.mono}`; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
        [light, C.signal, C.dim].forEach((col, k) => { const a = cols[k]; ctx.fillStyle = css(col); for (let n = 0; n < a.length; n += 3) ctx.fillText(a[n + 2], a[n], a[n + 1] + S2 * 0.04); });
        for (const q of tiles) tile(ctx, q[0], q[1], S2, q[2], q[3], q[4], Math.floor(q[4] * 4), C.bg);
      }
    }, { live: true, scroll: true });
    if (DOM && 'ResizeObserver' in window) new ResizeObserver(() => { M.ok = false; sc.dirty = true; }).observe(el);
    return { el, scene: sc, pass() { trig = performance.now() / 1000; trigN++; sc.dirty = true; }, refresh() { M.ok = false; sc.dirty = true; }, destroy() { drop(sc); } };
  }

  /* ---------- figure: decode ----------
     A value (best in mono) that climbs the cipher levels as it crosses the screen: each character starts as a shape, goes through
     three to five cipher characters, and becomes itself, from left to right. Scrolling back ciphers it again. The real text stays in the
     page for reading out and copying. Words never break inside while it runs.
     Taste.figures.decode(el or selector, { drive, of, range, start, still, seed, onProgress }) -> handle (or an array of handles for
     several elements). handle.text(value) changes the value (it starts again from the shapes); handle.destroy() puts plain text back.
     Mounting again on the same element replaces the earlier handle. */
  const KINDS = ['boxchar', 'ring', 'q', 'diamond', 'disc', 'star', 'box'];
  const DECODED = DOM ? new WeakMap() : null;
  // a stable number for a whole string, so two values of the same length wait as different shapes
  const strSeed = (t, k = 0) => { let h = 2166136261 ^ k; for (let i = 0; i < t.length; i++) h = Math.imul(h ^ t.charCodeAt(i), 16777619); return (h >>> 0) % 997; };
  function decode(target, opts = {}) {
    const els = all(target); if (els.length !== 1) return els.map((e) => decode(e, opts));
    const el = els[0];
    const was = DECODED.get(el); if (was) was.destroy();
    const o = { drive: 'cross', range: [0.1, 0.5], start: 0, still: 1, seed: 0, onProgress: null, ...opts };
    let text = el.textContent, cells = [], total = 1, box = null, n0 = 0, set = CIPHER, shown = -1, dead = false;
    const build = () => {
      const low = /[a-z]/.test(text) && getComputedStyle(el).textTransform !== 'uppercase';
      set = low ? CIPHER_LOWER : CIPHER; n0 = strSeed(text, o.seed);
      const hid = document.createElement('span'); hid.className = 'vh'; hid.textContent = text;
      box = document.createElement('span'); box.setAttribute('aria-hidden', 'true'); box.className = 't-cells';
      cells = [];
      let word = null;
      [...text].forEach((ch, i) => {
        const s = document.createElement('span'); s.className = 't-c'; s.textContent = ch;
        if (/\s/.test(ch)) { word = null; box.appendChild(s); return; }
        if (!word) { word = document.createElement('span'); word.className = 't-w'; box.appendChild(word); }
        word.appendChild(s);
        const z = hash(i, n0, 61);
        cells.push({ s, i, kind: KINDS[Math.floor(z * KINDS.length)], o: Math.floor(hash(i, n0, 62) * 4), a: hash(i, n0, 63) < 0.08, nc: 3 + Math.floor(hash(i, n0, 32) * 3), off: i * 0.2 + hash(i, n0, 31) * 1.2, st: null });
      });
      el.replaceChildren(hid, box);
      total = Math.max(1, ...cells.map((c) => c.off)) + 6.2; shown = -1;
    };
    const setCell = (c, u) => {
      const st = u < 0 ? 's' : u < c.nc ? 'c' + Math.floor(u) : '';
      if (st === c.st) return st === '';
      c.st = st; const s = c.s;
      if (st === '') { s.removeAttribute('data-l'); s.removeAttribute('data-k'); s.removeAttribute('data-c'); s.removeAttribute('data-a'); return true; }
      if (st === 's') { s.dataset.l = 's'; s.dataset.k = c.kind; s.style.setProperty('--t-o', c.o); if (c.a) s.dataset.a = ''; else s.removeAttribute('data-a'); s.dataset.c = HEX[Math.floor(hash(c.i, n0, 64) * 16)]; return false; }
      const k = Math.floor(u); s.dataset.l = k === 0 ? 'h' : 'c'; s.removeAttribute('data-k'); s.removeAttribute('data-a');
      s.dataset.c = set[Math.floor(hash(c.i, n0, 50 + k) * set.length)]; return false;
    };
    const update = () => {
      if (dead) return;
      const p = drive.value(performance.now() / 1000), key = Math.round(p * 400);
      if (key === shown) return; shown = key;
      let done = 0; for (const c of cells) if (setCell(c, p * total - c.off)) done++;
      if (o.onProgress) o.onProgress(cells.length ? done / cells.length : 1, p);
    };
    const printed = () => { for (const c of cells) setCell(c, 1e9); shown = -1; };
    build();
    const drive = driver(el, o, update);
    const stop = o.drive === 'cross' || o.drive === 'pin' ? onScroll(update) : (update(), () => {});
    if (DOM) { addEventListener('resize', update); addEventListener('beforeprint', printed); }
    const h = {
      el, set: drive.set, play: drive.play, progress: () => drive.value(performance.now() / 1000), refresh() { shown = -1; update(); },
      text(v) { if (dead) return h; text = String(v == null ? '' : v); build(); update(); return h; },
      destroy() {
        if (dead) return; dead = true; stop(); cancelAnimationFrame(drive.anim);
        if (DOM) { removeEventListener('resize', update); removeEventListener('beforeprint', printed); }
        // the plain text comes back only if the cells are still there (a caller may have written new text over them)
        if (box && box.parentNode === el) el.textContent = text;
        if (DECODED.get(el) === h) DECODED.delete(el);
      },
    };
    DECODED.set(el, h);
    return h;
  }

  /* token(name, el, as): what a custom property resolves to on el (default: <body>). as: nothing for the text of its value,
     'colour' for a colour { r, g, b, a, css, rgb }, 'px' for a length in pixels */
  function token(name, el, as) {
    if (!DOM) return as === 'px' ? 0 : as === 'colour' ? colour('#000') : '';
    el = el || document.body || document.documentElement;
    if (!as) return getComputedStyle(el).getPropertyValue(name).trim();
    const p = document.createElement('i'); p.setAttribute('aria-hidden', 'true');
    p.style.cssText = 'position:absolute;left:0;top:0;height:0;overflow:hidden;visibility:hidden;pointer-events:none;transition:none';
    if (as === 'colour') p.style.color = `var(${name})`; else p.style.width = `var(${name})`;
    el.appendChild(p); const cs = getComputedStyle(p), v = as === 'colour' ? colour(cs.color) : parseFloat(cs.width) || 0; p.remove();
    return v;
  }

  /* ---------- wiring ---------- */
  if (DOM) {
    S.io = 'IntersectionObserver' in window ? new IntersectionObserver((es) => es.forEach((e) => { const s = S.list.find((x) => x.el === e.target); if (s) { s.seen = e.isIntersecting; if (s.seen) s.dirty = true; } }), { rootMargin: '120px' }) : null;
    S.ro = 'ResizeObserver' in window ? new ResizeObserver((es) => es.forEach((e) => { const s = S.list.find((x) => x.el === e.target); if (s) s.dirty = true; })) : null;
    let queued = false;
    addEventListener('scroll', () => {
      for (const s of S.scrollers) s.dirty = true;
      if (!queued && S.onScroll.size) { queued = true; requestAnimationFrame(() => { queued = false; S.onScroll.forEach((f) => f()); }); }
    }, { passive: true });
    addEventListener('resize', () => { S.layout++; dirtyAll(); S.onScroll.forEach((f) => f()); });
    if (RM && RM.addEventListener) RM.addEventListener('change', (e) => { still = e.matches; dirtyAll(); });
    // a theme change: a class, style or data-theme change on <html> or <body>, or a stylesheet added, removed, switched or loaded
    const grains = () => document.querySelectorAll('.grain').forEach((n) => grainGround(n));
    const bump = () => { S.theme++; dirtyAll(); if (document.body) grains(); };
    const watchLinks = (nodes) => nodes.forEach((n) => { if (n.tagName === 'LINK') n.addEventListener('load', bump); });
    const mo = new MutationObserver((rs) => { for (const r of rs) if (r.type === 'childList') watchLinks([...r.addedNodes]); bump(); });
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'style', 'data-theme'] });
    if (document.head) mo.observe(document.head, { childList: true, subtree: true, attributes: true, attributeFilter: ['disabled', 'href', 'media'] });
    const ready = () => {
      if (document.body) mo.observe(document.body, { attributes: true, attributeFilter: ['class', 'style', 'data-theme'] });
      grains();
      reveal('.rv');
    };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ready); else ready();
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => { S.layout++; dirtyAll(); });
    // a print or a PDF takes every canvas as it is. Nothing is drawn during the print itself (Chrome would print a canvas drawn then
    // with white where it is clear); every scene has been drawn once already, even away from the screen. Before an export, call drawAll()
  }

  root.Taste = {
    version: '0.1.0',
    // maths
    TAU, clamp, smooth, mix, hash, noise, sdf,
    // the cipher
    HEX, CIPHER, CIPHER_LOWER, SHAPES, SYMBOLS, SCAN, NAMES, LEVEL, cipherChar,
    // drawing
    FONT, tile, pass, passLine, grain, grainTile, grainGround, lattice, rows,
    // colour
    colour, palette, alpha, blend, token,
    // the loop
    scene, drop, drawAll, start, pause, togglePause, refresh, freeze, motion, get FIXED() { return FIXED; }, get still() { return still; }, get paused() { return S.paused; },
    // scroll
    scrub, cross, onScroll,
    // text and reading
    cipherText, reveal, readProgress,
    // ready-made figures
    figures: { field, wave, decode },
    // helpers for figures built elsewhere (a project's own figure, LucidMark)
    rectsOf, all,
    // internal: may change
    _driver: driver, _all: all, _rectsOf: rectsOf, _drop: drop,
  };
})(typeof window !== 'undefined' ? window : globalThis);
