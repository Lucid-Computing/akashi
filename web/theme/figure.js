/* Akashi's own figure: the selection lattice. One classic script, one global (AkashiFigure). Load after taste/engine/taste.js.

   Each cell is one logged reply, placed by its leaf index, so a cell keeps its place while the log grows and the newest
   replies write over the oldest. A reply waits as a cipher character until its beacon round is published. Then it goes
   down the cipher to a dot (not selected) or climbs: a ring while it is proved, a solid square once proved conformant,
   a diamond in ink if a deviation was proved. Every change is carried by a short pass of light on that cell.

   AkashiFigure.selection(el, { cells, cell }) -> { el, scene, refresh(), destroy() }
     cells  (n) => the latest n replies as [{ leaf, s }], oldest first (n: the cells the lattice holds), s one of awaiting, unselected, proving, challenged, conformant, deviation
     cell   the lattice cell in px (default 15 on wide screens, 12 on narrow ones)
   AkashiFigure.glyph(el, s): one cell drawn alone, for a legend.

   Colours only from Taste.palette(el); the accent only on selected and proved cells and on the light of a change.
   Under reduced motion it is a still picture of the current state. */
(function (root) {
  'use strict';
  const T = root.Taste;
  if (!T) throw new Error('figure.js needs taste/engine/taste.js loaded before it');
  const { hash, tile, palette, SCAN, CIPHER } = T;

  // one cell: its shape and colour for a state
  function draw(ctx, C, x, y, S, s, i, j, time) {
    const still = T.still || !T.motion();
    switch (s) {
      case 'awaiting': {
        const step = still ? 0 : Math.floor(time / 1.6 + hash(i, j, 7) * 3);
        ctx.fillStyle = C.cipher.css;
        ctx.fillText(CIPHER[Math.floor(hash(i, j, step) * CIPHER.length)], x, y + S * 0.04);
        break;
      }
      case 'unselected': tile(ctx, x, y, S, 'dot', C.dim); break;
      case 'proving': tile(ctx, x, y, S, 'ring', C.signal, 0, still ? 0 : Math.floor(time * 2 + hash(i, j, 3) * 4) % 4); break;
      case 'challenged': tile(ctx, x, y, S, 'q', C.signal, 0, still ? 1 : Math.floor(time + hash(i, j, 5) * 4) % 4); break;
      case 'conformant': tile(ctx, x, y, S * 0.86, 'box', C.signal); break;
      case 'deviation': tile(ctx, x, y, S, 'diamond', C.fg); break;
      default: break;
    }
  }

  function selection(target, opts = {}) {
    const el = typeof target === 'string' ? document.querySelector(target) : target; if (!el) return null;
    const o = { cells: () => [], cell: 0, ...opts };
    const seen = new Map();   // leaf -> { s, t }: when each cell last changed, for its pass of light
    let primed = false;       // the first picture is drawn settled; only later changes get the light
    const sc = T.scene(el, (ctx, w, h, time, now) => {
      const C = palette(el), c = o.cell || (w > 900 ? 15 : 12), S = c * 0.86;
      const cols = Math.max(1, Math.floor(w / c)), rows = Math.max(1, Math.floor(h / c)), cap = cols * rows;
      const ox = (w - cols * c) / 2 + c / 2, oy = (h - rows * c) / 2 + c / 2;
      const items = o.cells(cap), top = items.length ? items[items.length - 1].leaf : 0;
      ctx.font = `400 ${(S * 0.78).toFixed(2)}px ${T.FONT.mono}`; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      for (const it of items) {
        if (it.leaf <= top - cap) continue;
        const pos = it.leaf % cap, i = pos % cols, j = Math.floor(pos / cols), x = ox + i * c, y = oy + j * c;
        const was = seen.get(it.leaf);
        if (!was) seen.set(it.leaf, { s: it.s, t: primed ? now : -1e9 });
        else if (was.s !== it.s) { was.s = it.s; was.t = now; }
        const age = now - (seen.get(it.leaf).t);
        if (!T.still && T.motion() && age < 700) {
          // the pass of light: the cell scans through the light tiles, then settles at its new level
          tile(ctx, x, y, S, SCAN[Math.floor(hash(i, j, Math.floor(age / 90)) * SCAN.length)], C.signal, hash(i, j, 2), 0, C.bg);
          continue;
        }
        draw(ctx, C, x, y, S, it.s, i, j, time);
      }
      ctx.textAlign = 'left'; ctx.textBaseline = 'alphabetic';
      primed = true;
      if (seen.size > cap * 3) { for (const k of seen.keys()) { if (k <= top - cap) seen.delete(k); } }
    }, { live: 66, still: 6 });
    return { el, scene: sc, refresh() { sc.dirty = true; }, destroy() { sc.destroy(); } };
  }

  function glyph(target, s) {
    const el = typeof target === 'string' ? document.querySelector(target) : target; if (!el) return null;
    return T.scene(el, (ctx, w, h) => {
      const C = palette(el), S = Math.min(w, h) * 0.86;
      ctx.font = `400 ${(S * 0.78).toFixed(2)}px ${T.FONT.mono}`; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      draw(ctx, C, w / 2, h / 2, S, s, 3, 4, 0);
    }, { live: false });
  }

  root.AkashiFigure = { selection, glyph };
})(window);
