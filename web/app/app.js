/* App: what a product screen needs that the foundation does not have yet. One classic script, one global: window.App.
   Load after taste/engine/taste.js. It works from file:// with no build step and no server.

   It holds only behaviour, never sample content: the screens of a demo, their data and their wording live in the page.
     App.routes(handlers)        screens switched by the address (#jobs, #job/7F3A), focus moved to the new headline
     App.loading(scope)          values wait at the deepest level of the cipher, then climb to themselves: the one motion a tool has
     App.toast(text, options)    one line that says what just happened; its words come through the cipher
     App.confirm(options)        a confirmation dialog; resolves true or false
     App.copy(text, button)      copy to the clipboard; the button says so through the cipher
     App.sortable(table, onSort) column heads that sort, with aria-sort
     App.validate(form)          the browser's own checks, shown as a message under each control
     App.night(on)               night mode: the class "night" on <html>, remembered in this browser
     App.download(name, text)    hand the reader a file (a receipt as JSON)
   The contract, with every option and the class names, is templates/app/README.md. */
(function (root) {
  'use strict';
  const T = root.Taste;
  if (!T) throw new Error('app.js needs taste/engine/taste.js loaded before it');
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* storage may be blocked: the page still works */ } },
  };
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  /* ---------- night mode: one attribute, the class "night" on <html> ----------
     night(on): on true, false, or nothing to switch. Returns the new state. Buttons carrying data-night-toggle are wired by themselves
     and get aria-pressed. Put the stored choice on <html> in the head (see index.html) so the first paint is right. */
  const GROUND_KEY = 'app-ground';
  function night(on) {
    const h = document.documentElement;
    if (on == null) on = !h.classList.contains('night');
    h.classList.toggle('night', !!on);
    store.set(GROUND_KEY, on ? 'night' : 'paper');
    $$('[data-night-toggle]').forEach((b) => b.setAttribute('aria-pressed', String(!!on)));
    $$('.toast').forEach(groundOf);
    return !!on;
  }
  const isNight = () => document.documentElement.classList.contains('night');

  /* ---------- screens by address ----------
     routes(handlers, options): every element carrying data-screen="name" is a screen; the address #name/arg shows it and hides the others.
     handlers[name](screen, ...args) runs each time a screen is shown. Links carrying data-route="name" get aria-current.
     After the first screen, the new screen's <h1> takes the focus, so a keyboard or a screen reader lands on it.
     options.home: the screen for an empty or unknown address (the first screen by default). options.title(name, args): the document title.
     options.parent: { screen: 'nav screen' }, for a screen with no link of its own (a job's detail): its parent's link stays current. */
  function routes(handlers = {}, o = {}) {
    const screens = $$('[data-screen]');
    const home = o.home || (screens[0] && screens[0].dataset.screen);
    const base = document.title;
    let first = true, current = null;
    const go = () => {
      const raw = decodeURIComponent(location.hash.slice(1));
      const [name, ...args] = raw.split('/');
      // an anchor to an element (a skip link) moves the focus there and leaves the screen as it is
      if (name && !screens.some((s) => s.dataset.screen === name)) {
        const el = document.getElementById(name);
        if (el && current) { el.focus(); return; }
      }
      const target = screens.find((s) => s.dataset.screen === name) || screens.find((s) => s.dataset.screen === home);
      if (!target) return;
      const key = target.dataset.screen;
      screens.forEach((s) => { s.hidden = s !== target; });
      const nav = (o.parent && o.parent[key]) || key;
      $$('[data-route]').forEach((a) => { if (a.dataset.route === key) a.setAttribute('aria-current', 'page'); else if (a.dataset.route === nav) a.setAttribute('aria-current', 'true'); else a.removeAttribute('aria-current'); });
      current = key;
      menu(false);
      if (handlers[key]) handlers[key](target, ...args);
      document.title = o.title ? o.title(key, args) : base;
      if (!first) {
        window.scrollTo({ top: 0, behavior: 'instant' });
        const h = $('h1', target);
        if (h) { h.tabIndex = -1; h.focus({ preventScroll: true }); }
      }
      first = false;
    };
    addEventListener('hashchange', go);
    go();
    return { go, current: () => current, to(hash) { if (location.hash === '#' + hash) go(); else location.hash = hash; } };
  }

  /* ---------- the phone menu: a button with aria-controls naming the nav, and data-menu ---------- */
  function menu(open) {
    $$('[data-menu]').forEach((b) => {
      const nav = document.getElementById(b.getAttribute('aria-controls'));
      const on = open == null ? b.getAttribute('aria-expanded') !== 'true' : open;
      b.setAttribute('aria-expanded', String(on));
      if (nav) nav.classList.toggle('open', on);
    });
  }

  /* ---------- loading: values climb the cipher and settle ----------
     A value is any element carrying data-value. While its data is on the way it waits at the deepest level of the cipher (a small
     shape per character); when the data arrives each character climbs through three to five cipher characters to itself, left to
     right. Under reduced motion the values simply appear. The real text stays in the page for screen readers and copying.
     loading(scope, options) -> { done(values) }: scope is an element or selector; every [data-value] inside it waits, scope gets
     aria-busy, and elements carrying data-loading inside it are shown. done(values) gives the values (an array in the order of the
     elements, or nothing to keep the text already there) and returns a Promise that settles when every value has arrived.
     options.ms: how long one value takes to climb (default 900). options.stagger: the delay from one value to the next (default 90). */
  const TEXT = new WeakMap();
  function hold(el, text) {
    if (text == null) text = TEXT.has(el) ? TEXT.get(el) : el.textContent;
    text = String(text);
    TEXT.set(el, text);
    el.textContent = text;
    return T.figures.decode(el, { drive: 'manual', start: 0 });
  }
  function settle(el, text) { const h = hold(el, text); h.set(1); return h; }
  function loading(scope, o = {}) {
    scope = typeof scope === 'string' ? $(scope) : scope;
    if (!scope) return { done: () => Promise.resolve() };
    const els = $$('[data-value]', scope);
    const ms = o.ms || 900, stagger = o.stagger == null ? 90 : o.stagger;
    scope.setAttribute('aria-busy', 'true');
    $$('[data-loading]', scope).forEach((n) => { n.hidden = false; });
    let hs = els.map((el) => hold(el));
    return {
      done(values) {
        scope.removeAttribute('aria-busy');
        $$('[data-loading]', scope).forEach((n) => { n.hidden = true; });
        return Promise.all(els.map((el, k) => {
          const v = values && values[k];
          if (v != null && String(v) !== TEXT.get(el)) hs[k] = hold(el, v);
          return new Promise((res) => setTimeout(() => hs[k].play(1, ms, 0).then(res), T.motion() ? k * stagger : 0));
        }));
      },
    };
  }
  // value(el, text): set a value without loading it (it shows at once, spaced like the values that loaded)
  const value = (el, text) => settle(typeof el === 'string' ? $(el) : el, text);

  /* ---------- toast ----------
     toast(text, options) -> { close() }: one line at the foot of the screen, read out politely. The box appears at once (never a fade)
     and its words climb through the cipher; when it leaves, they go down the cipher and the box is gone.
     options.state: 'done' (default), 'pending', 'failed' or 'idle': the square before the words. options.action: { label, run }.
     options.ms: how long it stays (default 5200; 0 keeps it until closed). Its ground is the opposite of the screen's. */
  function region() {
    let box = $('#app-toasts');
    if (!box) {
      box = document.createElement('div'); box.id = 'app-toasts'; box.className = 'toasts';
      box.innerHTML = '<p class="vh" role="status" aria-live="polite"></p>';
      document.body.append(box);
    }
    return box;
  }
  function groundOf(t) { t.classList.toggle('night', !isNight()); t.classList.toggle('paper', isNight()); }
  function toast(text, o = {}) {
    const box = region(), live = $('[role="status"]', box);
    const t = document.createElement('div'); t.className = 'toast'; groundOf(t);
    t.innerHTML = `<i class="state" data-state="${esc(o.state || 'done')}" aria-hidden="true"></i><p aria-hidden="true"></p>` +
      `<div class="cluster">${o.action ? `<button class="btn small" type="button">${esc(o.action.label)}</button>` : ''}<button class="btn small" type="button" aria-label="Dismiss">Close</button></div>`;
    const words = $('p', t), [act, x] = o.action ? $$('button', t) : [null, $('button', t)];
    const old = $$('.toast', box); if (old.length >= 3) old[0].remove();
    box.append(t);
    live.textContent = ''; setTimeout(() => { live.textContent = text; }, 30);
    T.cipherText(words, text, { out: false });
    let timer = 0, gone = false;
    const close = () => {
      if (gone) return; gone = true; clearTimeout(timer);
      const back = t.contains(document.activeElement);
      T.cipherText(words, '').then(() => { t.remove(); if (back && o.returnTo) o.returnTo.focus(); });
    };
    x.addEventListener('click', close);
    if (act) act.addEventListener('click', () => { o.action.run(); close(); });
    const ms = o.ms == null ? 5200 : o.ms;
    // it stays while the pointer or the focus is on it
    const arm = () => { clearTimeout(timer); if (ms) timer = setTimeout(close, ms); };
    t.addEventListener('pointerenter', () => clearTimeout(timer)); t.addEventListener('pointerleave', arm);
    t.addEventListener('focusin', () => clearTimeout(timer)); t.addEventListener('focusout', arm);
    arm();
    return { el: t, close };
  }

  /* ---------- confirmation dialog ----------
     confirm(options) -> Promise<boolean>. A native modal <dialog>: the focus stays inside it, Escape and a click on the dimmed screen
     cancel, and the focus goes back where it was. options: label (a mono line above), title (the question, a few words), text (one
     sentence on what will happen), rows ([[key, value], ...] shown as a record), ok (the action's words), cancel ('Cancel'),
     danger (true: the focus starts on the safe choice). */
  function dialog() {
    let d = $('#app-confirm');
    if (d) return d;
    d = document.createElement('dialog'); d.id = 'app-confirm'; d.className = 'dialog';
    d.setAttribute('aria-labelledby', 'app-confirm-t'); d.setAttribute('aria-describedby', 'app-confirm-d');
    d.innerHTML = '<form method="dialog" class="dialog-in"><p class="mono" id="app-confirm-l"></p><h2 class="tt" id="app-confirm-t"></h2>' +
      '<p id="app-confirm-d"></p><dl class="kv" id="app-confirm-kv"></dl>' +
      '<div class="dialog-actions"><button class="btn" value="no" id="app-confirm-no"></button><button class="btn solid" value="yes" id="app-confirm-ok"></button></div></form>';
    d.addEventListener('click', (e) => { if (e.target === d) d.close('no'); });
    document.body.append(d);
    return d;
  }
  function confirm(o = {}) {
    const d = dialog(), back = document.activeElement;
    $('#app-confirm-l', d).innerHTML = o.label ? o.label : '';
    $('#app-confirm-l', d).hidden = !o.label;
    $('#app-confirm-t', d).textContent = o.title || 'Are you sure?';
    $('#app-confirm-d', d).textContent = o.text || '';
    const kv = $('#app-confirm-kv', d);
    kv.innerHTML = (o.rows || []).map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('');
    kv.hidden = !(o.rows && o.rows.length);
    $('#app-confirm-ok', d).textContent = o.ok || 'Confirm';
    $('#app-confirm-no', d).textContent = o.cancel || 'Cancel';
    d.returnValue = '';
    d.showModal();
    (o.danger ? $('#app-confirm-no', d) : $('#app-confirm-ok', d)).focus();
    return new Promise((res) => d.addEventListener('close', () => { if (back && back.focus) back.focus(); res(d.returnValue === 'yes'); }, { once: true }));
  }

  /* ---------- copy ----------
     copy(text, button) -> Promise<boolean>: copies text. The button's words go through the cipher to "Copied" and back.
     From file:// the clipboard is usually allowed; if not, the older copy command is used. */
  async function copy(text, btn) {
    let ok = false;
    try { await navigator.clipboard.writeText(text); ok = true; } catch (e) {
      const ta = document.createElement('textarea'); ta.value = text; ta.setAttribute('readonly', ''); ta.style.cssText = 'position:fixed;left:-9999px;top:0';
      document.body.append(ta); ta.select();
      try { ok = document.execCommand('copy'); } catch (e2) { ok = false; }
      ta.remove(); if (btn) btn.focus();
    }
    if (btn) {
      const was = btn.dataset.label || btn.textContent.trim(); btn.dataset.label = was;
      clearTimeout(btn._copy);
      T.cipherText(btn, ok ? 'Copied' : 'Not copied');
      btn._copy = setTimeout(() => T.cipherText(btn, was), 2200);
    }
    return ok;
  }

  /* ---------- sortable column heads ----------
     sortable(table, onSort): every <th data-sort="key"> in the table head becomes a button. A click sorts by that column, then
     the other way; aria-sort says the order. With onSort(key, dir) the page sorts its own data and draws the rows again (dir is
     'ascending' or 'descending'); without it the rows of the first tbody are sorted in place, by each cell's data-sort or its text.
     Returns { sort(key, dir), key(), dir() }. */
  function sortable(table, onSort) {
    table = typeof table === 'string' ? $(table) : table;
    const ths = $$('thead th[data-sort]', table);
    let k = null, dir = 'ascending';
    ths.forEach((th) => {
      const label = th.textContent.trim();
      th.innerHTML = `<button class="sort" type="button"><span>${esc(label)}</span><i aria-hidden="true"></i></button>`;
      $('button', th).addEventListener('click', () => sort(th.dataset.sort, k === th.dataset.sort && dir === 'ascending' ? 'descending' : 'ascending'));
    });
    function sort(key, d = 'ascending') {
      k = key; dir = d;
      ths.forEach((th) => { if (th.dataset.sort === key) th.setAttribute('aria-sort', d); else th.removeAttribute('aria-sort'); });
      if (onSort) { onSort(key, d); return; }
      const th = ths.find((t) => t.dataset.sort === key); if (!th) return;
      const col = [...th.parentNode.children].indexOf(th), tb = table.tBodies[0];
      const val = (tr) => { const c = tr.children[col]; return c ? (c.dataset.sort != null ? c.dataset.sort : c.textContent.trim()) : ''; };
      const rows = [...tb.rows], num = rows.every((r) => val(r) !== '' && !isNaN(+val(r)));
      rows.sort((a, b) => { const x = val(a), y = val(b), v = num ? x - y : x.localeCompare(y, undefined, { numeric: true }); return d === 'ascending' ? v : -v; });
      tb.append(...rows);
    }
    return { sort, key: () => k, dir: () => dir };
  }

  /* ---------- validation ----------
     validate(form) -> boolean: runs the browser's own checks (required, pattern, type, min, max) on every .input and .select in the
     form. A control that fails gets aria-invalid (its edge turns dashed) and its field's .msg says why, in the words of the control's
     data-missing (when empty) or data-invalid (when wrong), else the browser's message. The focus goes to the first that fails.
     Give the form novalidate, and point each control's aria-describedby at its .help and .msg. Messages clear as the reader types. */
  function check(inp) {
    const f = inp.closest('.field'), msg = f && $('.msg', f), ok = inp.checkValidity();
    if (ok) inp.removeAttribute('aria-invalid'); else inp.setAttribute('aria-invalid', 'true');
    if (msg) msg.textContent = ok ? '' : (inp.validity.valueMissing ? inp.dataset.missing : inp.dataset.invalid) || inp.validationMessage;
    return ok;
  }
  function validate(form) {
    form = typeof form === 'string' ? $(form) : form;
    let first = null;
    $$('.input, .select', form).forEach((inp) => { if (!check(inp) && !first) first = inp; });
    if (first) first.focus();
    if (!form._live) { form._live = true; form.addEventListener('input', (e) => { if (e.target.getAttribute('aria-invalid') === 'true') check(e.target); }); }
    return !first;
  }

  /* ---------- a file for the reader ---------- */
  function download(name, text, type = 'application/json') {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = document.createElement('a'); a.href = url; a.download = name; document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  /* ---------- wiring ---------- */
  function wire() {
    $$('[data-night-toggle]').forEach((b) => { b.setAttribute('aria-pressed', String(isNight())); b.addEventListener('click', () => night()); });
    $$('[data-menu]').forEach((b) => { b.setAttribute('aria-expanded', 'false'); b.addEventListener('click', () => menu()); });
    addEventListener('keydown', (e) => { if (e.key === 'Escape') { const b = $('[data-menu][aria-expanded="true"]'); if (b) { menu(false); b.focus(); } } });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire); else wire();

  root.App = { version: '0.1.0', night, routes, menu, loading, value, toast, confirm, copy, sortable, validate, download, store };
})(window);
