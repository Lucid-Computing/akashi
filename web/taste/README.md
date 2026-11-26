# Taste: the contract

Taste is the foundation every project uses, branded or not: the type roles, the page grid, hairline rules, mono for facts, soft corners, grain, the motion rules, and a drawing engine for lattices of characters and small shapes crossed by waves of light. It has one slot for an accent colour and neutral names for everything else. It never mentions or draws any brand mark. With no theme loaded, a page is already correct, and merely colourless (ink on paper, white on night).

A brand or project adds a theme on top: one small stylesheet that fills the accent slot (Lucid's is `brand/lucid.css`; a project led by Lucid writes its own from `themes/_template/`).

This file lists every token, every class and every function, with what it is for. Anything not written here is internal and may change. The taste in words (layout, type, colour, figures, motion, writing, and what is rejected) is in `taste/RULES.md`; read it before designing anything.

Contents: [Files and load order](#files-and-load-order) · [Smallest pages](#the-smallest-complete-pages) · [Tokens](#tokens) · [Grounds and roles](#grounds-and-roles) · [Classes](#classes) · [Taste (JavaScript)](#taste-the-engine) · [Figures](#ready-made-figures) · [LucidMark](#lucidmark-brand-only) · [Themes](#writing-a-theme) · [Checks](#checks-before-you-ship)

---

## Files and load order

| File | What it is |
| --- | --- |
| `taste/tokens.css` | The custom properties, and the two `@font-face` rules. |
| `taste/base.css` | The classes. Needs `tokens.css`. |
| `taste/engine/soft.js` | `window.Soft`: traces outlines of shapes given as distance fields. Needed by `brand/lucid-mark.js`; optional for Taste. |
| `taste/engine/taste.js` | `window.Taste`: the drawing engine, scroll helpers, text through the cipher, three ready-made figures. |
| `taste/fonts/` | `geist.woff2`, `geistmono.woff2` (Geist and Geist Mono, by Vercel) and `OFL.txt`, their licence (SIL Open Font License 1.1). |
| `taste/tokens.json` | The same tokens as data, for other stacks. |
| `brand/lucid.css` | The Lucid theme. Lucid's own work only. |
| `brand/lucid-mark.js` | `window.LucidMark`: the Lucid mark. Lucid's own work only. Needs `soft.js` and `taste.js` before it. |

Order, always:

```html
<link rel="stylesheet" href="taste/tokens.css">
<link rel="stylesheet" href="taste/base.css">
<link rel="stylesheet" href="brand/lucid.css">          <!-- or your project's theme.css; or nothing -->
...
<script src="taste/engine/soft.js"></script>
<script src="taste/engine/taste.js"></script>
<script src="brand/lucid-mark.js"></script>             <!-- Lucid only -->
<script> /* your page: mount figures here */ </script>
```

Rules that hold everywhere:

- Everything works opened straight from the file system (`file://`): classic `<script src>`, relative paths, no modules, no fetch of local files, no build step, nothing loaded from the network.
- Paths are relative to the page. From `templates/deck/index.html` they start with `../../taste/`.
- Put the scripts at the end of `<body>`. Taste and LucidMark wait for the document and the fonts by themselves.
- Font files resolve relative to `tokens.css`, so keep `taste/fonts/` beside it.
- Taking the kit out of this repository: a project led by Lucid starts with `sh themes/_template/new-project.sh <folder> site app deck`, which copies `taste/` and lays the pages one folder below it (`themes/_template/README.md`). A deck is shipped on its own as `templates/deck/README.md` ("Ship a deck") shows.

---

## The smallest complete pages

Without a theme (correct, colourless; the start of any project):

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Project</title>
  <link rel="stylesheet" href="taste/tokens.css">
  <link rel="stylesheet" href="taste/base.css">
</head>
<body>
  <header class="night"><div class="wrap bar"><b class="mono">Project</b><nav class="nav"><a href="#">Notes</a></nav></div></header>
  <section class="night grain part">
    <div class="wrap"><div class="r head">
      <div class="m"><b>01</b><b>Overview</b></div>
      <div class="x"><h1 class="xl">One claim.</h1><p class="sent">One sentence that explains it.</p></div>
    </div></div>
  </section>
  <section class="paper sheet part">
    <div class="wrap ruled"><div class="r">
      <div class="m"><b>Record</b><span>Sample data</span></div>
      <div class="x"><div class="figure wide" id="f" role="img" aria-label="A field of cipher cells"></div></div>
    </div></div>
  </section>
  <script src="taste/engine/taste.js"></script>
  <script>Taste.figures.field('#f');</script>
</body>
</html>
```

With the Lucid theme (Lucid's own work only): the same page, plus the theme, the mark script and a lockup.

```html
  <link rel="stylesheet" href="taste/tokens.css">
  <link rel="stylesheet" href="taste/base.css">
  <link rel="stylesheet" href="brand/lucid.css">
  <link rel="icon" href="brand/assets/favicon.svg" type="image/svg+xml">
  ...
  <header class="night"><div class="wrap bar"><a href="#" data-lucid-lockup aria-label="Lucid Computing, home"></a><nav class="nav"><a href="#">Notes</a></nav></div></header>
  ...
  <script src="taste/engine/soft.js"></script>
  <script src="taste/engine/taste.js"></script>
  <script src="brand/lucid-mark.js"></script>
```

---

## Tokens

All tokens are custom properties on `:root`, defined in `taste/tokens.css`. Fluid values use `clamp()`. Where three values are given, they apply below 701px, from 701px, and from 1181px.

### Grounds and ink

| Token | Value | Role |
| --- | --- | --- |
| `--ground-night` | `#07080c` | The dark ground. |
| `--ground-paper` | `#f3f4f0` | The light ground, the default. |
| `--ground-white` | `#ffffff` | Panels laid on paper. |
| `--ground-night-panel` | `#111218` | Panels laid on night. |
| `--ink` | `#07080c` | Text and solid marks on paper. |
| `--ink-night` | `#ffffff` | Text and solid marks on night. |

### The accent slot (a theme sets these five)

| Token | Neutral default | Lucid (`brand/lucid.css`) | Role |
| --- | --- | --- | --- |
| `--accent` | `#07080c` | `#1b3bff` cobalt | The one colour: fills, and marks on paper. |
| `--on-accent` | `#ffffff` | `#ffffff` | Text and marks on an accent fill. |
| `--accent-light` | `#ffffff` | `#93a5ff` periwinkle | The accent as light on night: waves, live marks, a checked box. |
| `--accent-night` | `#ffffff` | `#1b3bff` | The accent as a fill on night (a hovered button). |
| `--on-accent-night` | `#07080c` | `#ffffff` | Text on that fill. |

Derived from the slot (a theme may set them exactly; Lucid does). They are worked out again on every element that carries `data-theme`, so a theme scoped to part of a page gets its own:

| Token | Default | Role |
| --- | --- | --- |
| `--mist-accent` | `color-mix(in srgb, var(--on-accent) 82%, var(--accent))` | Labels on an accent ground. |
| `--line-accent` | `color-mix(in srgb, var(--on-accent) 32%, transparent)` | Hairlines on an accent ground. |
| `--cipher-accent` | `color-mix(in srgb, var(--on-accent) 78%, var(--accent))` | Cipher characters on an accent ground. |
| `--cipher-dim-accent` | `color-mix(in srgb, var(--on-accent) 45%, var(--accent))` | Faint cipher on an accent ground. |

### Mist, lines and cipher greys

| Token | Value | Role |
| --- | --- | --- |
| `--mist` | `#686e88` | Labels and quiet text on paper and white. |
| `--mist-night` | `#8a8d97` | Labels and quiet text on night. |
| `--line` | `#07080c26` | Hairline on paper. |
| `--line-night` | `#ffffff26` | Hairline on night. |
| `--line-tag` | `#07080c45` | The edge of a tag on paper. |
| `--line-tag-night` | `#ffffff4d` | The edge of a tag on night. |
| `--cipher-paper` | `#6b718b` | Cipher characters in figures on paper. |
| `--cipher-dim-paper` | `#a3a7b8` | Faint cipher on paper. |
| `--cipher-night` | `#98a0c4` | Cipher characters on night. |
| `--cipher-dim-night` | `#4d536b` | Faint cipher on night. |

`data-theme="none"` on `<html>` or on any element puts the neutral slot back, whatever theme is loaded (a colourless preview, a part kept free of the accent).

No other colours exist. No gradients as backgrounds, no shadows, no borders-and-cards.

### Type

| Token | Value | Role |
| --- | --- | --- |
| `--font-sans` | `"Geist", system-ui, ...` | Claims and sentences. |
| `--font-mono` | `"Geist Mono", ui-monospace, ...` | Labels and anything that is a fact. |
| `--size-claim` / `--leading-claim` / `--track-claim` | `clamp(40px, 6.5vw, 104px)` / `0.9` / `-0.042em` | The one claim of a screen (class `.xl`). |
| `--size-headline` / `--leading-headline` / `--track-headline` | `clamp(28px, 3.1vw, 46px)` / `0.95` / `-0.035em` | A smaller headline (class `.tt`). |
| `--size-lead` / `--leading-lead` / `--track-lead` | `clamp(22px, 2.3vw, 38px)` / `1.15` / `-0.025em` | A large sentence (class `.lead`). |
| `--size-sentence` / `--leading-sentence` / `--track-sentence` | `clamp(18px, 1.5vw, 23px)` / `1.3` / `-0.015em` | A sentence that carries meaning (class `.sent`). |
| `--size-body` / `--leading-body` / `--track-body` | `16px` / `1.45` / `-0.01em` | Running text and controls. |
| `--size-value` | `clamp(22px, 3.15vw, 56px)` | A fact shown large in mono (class `.val`). |
| `--size-label` / `--leading-label` / `--track-label` | `11px` / `16px` / `0.07em` | Labels and facts: mono, capitals, wide (class `.mono`). |
| `--size-button` | `12px` | Button labels. |
| `--size-code` | `13px` | Code blocks. |
| `--weight-regular` / `--weight-claim` | `400` / `600` | Regular for sentences; Semibold for claims. |

### Spacing

| Token | Value | Role |
| --- | --- | --- |
| `--space-1` ... `--space-7` | `4px 8px 12px 16px 24px 32px 48px` | Steps inside components. |
| `--space-8` | `clamp(56px, 6vw, 96px)` | Between blocks of a part; under a part's headline. |
| `--space-9` | `clamp(72px, 8vw, 136px)` | Between large blocks. |
| `--space-top` | `clamp(48px, 6.5vw, 100px)` | From a part's top edge to its label line. |
| `--space-end` | `clamp(96px, 11vw, 168px)` | Clear ground under a part's last line, before the next sheet. |

### Radii

| Token | Value | Role |
| --- | --- | --- |
| `--radius-sheet` | `clamp(26px, 4vw, 56px)` | The soft corner of a sheet laid over another ground. |
| `--radius-box` | `14%` | A square figure: 14 on 100, the softness of a box. |
| `--radius-panel` | `14px` | A panel in an app. |
| `--radius-control` | `7px` | Buttons and inputs. |
| `--radius-tag` | `4px` | Tags. |

### Grid

| Token | Value | Role |
| --- | --- | --- |
| `--grid-max` | `1560px` | The widest the page grid gets. |
| `--grid-gutter` | `clamp(16px, 2.4vw, 36px)` | Page edge to content. |
| `--grid-margin` | `0px` / `132px` / `188px` | The margin column for numbers and labels. Folds away on phones. |
| `--grid-gap` | `20px` / `28px` / `40px` | Between the margin column and the main column. |
| `--grid-label` | `168px` / `168px` / `216px` | A label track inside the main column (`.split`, `.kv`). |
| `--grid-value` | `200px` / `200px` / `248px` | A value track inside the main column. |
| `--grid-rail` | `52px` | The running head inside the margin column (wide only). |

### Motion and grain

| Token | Value | Role |
| --- | --- | --- |
| `--ease` | `cubic-bezier(.3, .6, .2, 1)` | The one easing. |
| `--dur-quick` | `.2s` | Colour changes on hover and focus. |
| `--dur-reveal` | `1.3s` | A heading crossed by a pass of light. |
| `--cipher-step` | `46ms` | One step of text through the cipher. |
| `--grain-tile` | `none` | Set by Taste on each `.grain` element: its own ground baked with grain. |

---

## Grounds and roles

A ground class sets the **roles** its contents read. Components and figures use roles, never fixed colours, so they are right on every ground.

| Role | `:root` and `.paper` | `.white` | `.night` | `.accent` |
| --- | --- | --- | --- | --- |
| `--bg` | `--ground-paper` | `--ground-white` | `--ground-night` | `--accent` |
| `--fg` | `--ink` | `--ink` | `--ink-night` | `--on-accent` |
| `--fg-mist` | `--mist` | `--mist` | `--mist-night` | `--mist-accent` |
| `--rule` | `--line` | `--line` | `--line-night` | `--line-accent` |
| `--rule-strong` | `--ink` | `--ink` | `--ink-night` | `--on-accent` |
| `--tag-line` | `--line-tag` | `--line-tag` | `--line-tag-night` | `--line-accent` |
| `--signal` (the accent as it reads here) | `--accent` | `--accent` | `--accent-light` | `--on-accent` |
| `--fill` / `--on-fill` (hover fill) | `--accent` / `--on-accent` | same | `--accent-night` / `--on-accent-night` | `--on-accent` / `--accent` |
| `--focus` | `--accent` | `--accent` | `--ink-night` | `--on-accent` |
| `--cipher` / `--cipher-dim` | paper greys | paper greys | night greys | accent greys |
| `--field-bg` (inside an input) | transparent | `--ground-white` | transparent | transparent |

Use roles in your own CSS: `color: var(--fg-mist)`, `border-top: 1px solid var(--rule)`, `background: var(--signal)`. Never write `var(--accent)` for text on night: write `var(--signal)`.

A whole page on night: put `.night` on `<html>` (the app template's night mode does this). An element with `data-theme` starts again from the paper roles, so give it its ground class too (`<div data-theme="sorrel" class="night">`).

---

## Classes

Every class is in `taste/base.css`. Snippets are minimal.

### Grounds

| Class | Use |
| --- | --- |
| `.paper` | The light ground (the page default). |
| `.white` | A white panel ground on paper. |
| `.night` | The dark ground. |
| `.accent` | The accent as a ground: one band per page at most. |
| `.grain` | Grain on the element's own ground. Night and accent grounds only. `data-grain="0.3"` for more (default `0.2`). |

```html
<section class="night grain part">...</section>
<section class="accent grain">...</section>
```

### The page grid: the page as a record

| Class | Use |
| --- | --- |
| `.wrap` | Centred container, `--grid-max` wide, `--grid-gutter` at the sides. |
| `.r` | A row: the margin column (`.m`), then the main column (`.x`), on one hard left axis. On phones it stacks. |
| `.m` | The margin cell: mono labels. `<b>` is in ink, `<span>` is a quiet note under it, a `.tag` hangs right. On phones it folds into one line above the block. |
| `.x` | The main cell. |
| `.ruled` | On a `.wrap`: a hairline down the page between the two columns (from 701px). |
| `.head` | A part's head row: label in the margin, headline in the main column, `--space-8` under it. |
| `.part` | A part of a page: `--space-top` above, `--space-end` below. Rows directly inside get `--space-8` between them. |
| `.split` | Two tracks inside the main column: a label track (`--grid-label`) and the rest. Stacks on phones. |
| `.rail` / `.run` | The running head (wide only): the part's number and a square that fills as it is read. Put `.rail` first inside `.wrap`; call `Taste.readProgress()`. |
| `.pin` / `.pin-stage` | A tall block (`--pin-length`, default `300svh`) with one pinned stage the scroll drives. |

```html
<section class="paper sheet part" data-read>
  <div class="wrap ruled">
    <div class="rail" aria-hidden="true"><span class="run mono"><b>01</b><i class="sq"></i></span></div>
    <div class="r head">
      <div class="m"><b>How it is made</b><span>One note</span></div>
      <div class="x"><h2 class="xl rv">Built by us.<br>Checked by others.</h2></div>
    </div>
    <div class="r">
      <div class="m"><b>Receipt</b><span class="tag">Sample</span></div>
      <div class="x"><div class="split"><span class="mono">What you get</span><p class="sent">One sentence.</p></div></div>
    </div>
  </div>
</section>
```

### Type

| Class | Use |
| --- | --- |
| `.xl` | The one claim of a screen: Geist Semibold, capitals, set tight. One per screen. |
| `.tt` | A smaller headline, same voice. |
| `.lead` | A large sentence in sentence case. |
| `.sent` | A sentence that carries meaning (max 44 characters wide). |
| `.mono` | Labels and facts: Geist Mono 11px, capitals, wide tracking, in mist. `<b>` inside is in ink; `<code>` inside keeps its case (`--accent`, not `--ACCENT`), as in `.m` and `figcaption`. |
| `.val` | A fact shown large: mono, at `--size-value`. |
| `.muted` | Text in the ground's mist. |
| `.num` | Tabular figures. |
| `.prose` | Running text (articles, documents): spaced paragraphs, square bullets, underlined links. |

```html
<h1 class="xl">Compute you can see into</h1>
<p class="sent">Attested: the machine your workload runs on.</p>
<p class="mono"><b>01</b> · Where it runs</p>
<p class="val">RACK 14 · ZONE B</p>
```

### Rules and lists

| Class | Use |
| --- | --- |
| `hr`, `.rule` | A hairline (`--rule`). |
| `.rule-strong` | A 1px rule in the ground's ink. |
| `.rule-heavy` | A 2px rule in the ground's ink: the top and bottom of a record. |
| `.list` | Rows with a strong rule above and below, hairlines between. |

```html
<ul class="list"><li class="split"><span class="mono"><b>01</b> · Notes</span><p class="sent">One line.</p></li></ul>
```

### Buttons and tags

| Class | Use |
| --- | --- |
| `.btn` | Outline button: mono capitals, soft corners. Fills with `--fill` on hover. |
| `.btn.solid` | Filled with the ground's ink (ink on paper, white on night). The one main action. |
| `.btn.quiet` | Text only; takes `--signal` on hover. |
| `.btn.small` | 32px tall, for dense screens. |
| `.tag` | A fact in a thin soft box: `Sample`, `Placeholder`, `To clear`. |
| `.seg` | A segmented control: one choice of a few (a filter, a view). Buttons with `aria-pressed` inside, or, in a `fieldset.seg` with a `legend`, radios each in a `<label>` followed by a `<span>`. The chosen one is filled with the ground's ink. `.n` inside for a count. |

```html
<a class="btn solid" href="#">Get compute</a> <button class="btn">Read the work</button> <span class="tag">Sample</span>
<div class="seg" role="group" aria-label="Show jobs by state">
  <button type="button" aria-pressed="true">All <span class="n">14</span></button><button type="button" aria-pressed="false">Failed <span class="n">2</span></button>
</div>
<fieldset class="seg"><legend>View</legend>
  <label><input type="radio" name="v" value="list" checked><span>List</span></label><label><input type="radio" name="v" value="grid"><span>Grid</span></label>
</fieldset>
```

### Sheets and panels

| Class | Use |
| --- | --- |
| `.sheet` | A part whose ground differs from the one before: laid over it with soft top corners (`--radius-sheet`), the earlier ground showing behind them. |
| `.sheet.whole` | All four corners soft, no overlap (a band inside a page). |
| `.panel` | A flat surface in an app: white on paper, `--ground-night-panel` on night. No border, no shadow. Add a ground class to give it that ground. |

```html
<section class="night sheet part">...</section>
<div class="panel"><p class="mono">Workload</p>...</div>
```

### Figures

| Class | Use |
| --- | --- |
| `.figure` | A box that holds a drawing; a canvas inside fills it. Give it a height, or a ratio: |
| `.figure.square` / `.figure.wide` / `.figure.band` | 1:1, 16:9, or a band `clamp(360px, 70svh, 900px)` tall. Or set `--figure-ratio`. |
| `.figure.box` | Corners of `--radius-box`, contents clipped. |
| `figcaption` | Mono caption under a figure; `<b>` in ink. |

```html
<figure><div class="figure wide" id="f" role="img" aria-label="What the figure shows"></div><figcaption><b>01</b> Field</figcaption></figure>
```

Always give the figure element `role="img"` and an `aria-label` that says what it shows. Canvases Taste adds are `aria-hidden`.

### Records: rows of label, sentence, value, state

| Class | Use |
| --- | --- |
| `table.record` | Heavy rules top and bottom, hairlines between rows, mono labels. Row headers (`th scope="row"`) are mono. |
| `.what` | The sentence cell. |
| `.v` | A value cell in mono. |
| `.n` | A number cell: mono, right aligned, tabular. |
| `.s` | The state cell (holds a `.state`). |
| `tr.on`, `tr[aria-selected="true"]` | A selected row. |
| `table.record.keep` | Keep columns on phones (wrap it in `.scroll-x`). Without it, rows stack on phones and each cell shows its `data-label`. |
| `.scroll-x` | A box that scrolls sideways inside itself, never the page. |
| `dl.kv` | Key and value: each pair in a `<div>`; mono key, then value. |

```html
<table class="record">
  <thead><tr><th scope="col">Check</th><th scope="col">What it means</th><th scope="col">Value</th><th scope="col">State</th></tr></thead>
  <tbody><tr><th scope="row">01 Where it runs</th><td class="what" data-label="What it means">Attested: the machine and where it is.</td>
    <td class="v" data-label="Value">RACK 14 · ZONE B</td><td class="s"><span class="state" data-state="attested">Attested</span></td></tr></tbody>
</table>
<dl class="kv"><div><dt>Receipt</dt><dd class="hash">sha256:7f3a…e9d1</dd></div></dl>
```

### States: the small square that fills

| Class | Use |
| --- | --- |
| `.sq` | A 9px square, outlined in the ground's ink, that fills from below with `--signal` by `--p` (0 to 1). |
| `.state` | A state in mono with its square. `data-state` is one of: `verified` or `attested` or `done` (filled), `pending` (half full, the fill breathing slowly; still under reduced motion), `failed` (struck through, in ink), `idle` (empty, in mist). |

```html
<span class="state" data-state="verified">Verified</span>
<span class="state" data-state="pending">Pending</span>
<span class="state" data-state="failed">Failed</span>
<i class="sq" style="--p: .5"></i>
```

States are never coloured pills. The word always says the state; the square only repeats it.

### Code and hashes

| Class | Use |
| --- | --- |
| `code`, `kbd`, `samp`, `.code` | Inline mono. |
| `pre.code` | A code block on night (raised night on a night ground). `.c` inside for comments, `.k` for keywords (accent light). |
| `.hash` | A hash or identifier: mono, normal case, breaks anywhere. |

```html
<pre class="code"><span class="c"># fetch a receipt</span>
<span class="k">curl</span> https://example.invalid/receipt/7f3a</pre>
<span class="hash">sha256:7f3a9c04e1b2</span>
```

### Forms

| Class | Use |
| --- | --- |
| `.field` | A label (mono) above a control, with an optional `.help` line under it. |
| `.input` | Text input or `textarea`: 44px tall, hairline edge, soft corners, the ground's `--field-bg` inside. `.input.code` for values and keys typed in mono. `aria-invalid="true"` dashes the edge. |
| `.select` | A native select in the same language; `aria-invalid="true"` dashes its edge too. |
| `label.check` | A checkbox: the small square, filled with `--signal` when checked. |
| `label.radio` | A radio: a ring with a disc. |
| `label.switch` | A switch: a soft track with a square that slides and fills. Add `role="switch"` to the input. |
| `.help` | A quiet line under a control. |

```html
<div class="field"><label for="w">Workload</label><input id="w" class="input"><p class="help">Sample values.</p></div>
<label class="check"><input type="checkbox" checked> Bind to policy</label>
<label class="switch"><input type="checkbox" role="switch"> Live checks</label>
```

### Bars and helpers

| Class | Use |
| --- | --- |
| `.bar` | The top bar of a page or app: name left, nav right, a hairline under it. Use on a `.wrap`. |
| `.nav` | Mono links; `aria-current` marks the current one. |
| `.led-by` | The one line that names who leads a project: mono, in the ground's mist, the name in `<b>` in ink. In the colophon or footer only: `<p class="led-by">Led by <b>Lucid Computing</b></p>`. |
| `.stack` | Vertical gap `--gap` (default `--space-4`). |
| `.cluster` | Wrapping row with gap `--gap` (default `--space-3`). |
| `.rv` | A heading crossed by a pass of light the first time it is seen (Taste runs it; nothing happens without JavaScript or under reduced motion). |
| `.vh` | Visually hidden, still read out. |

```html
<header class="night"><div class="wrap bar"><b class="mono">Project</b><nav class="nav"><a href="#" aria-current="page">Notes</a></nav></div></header>
```

Also built in: `:focus-visible` rings in `--focus`; under `prefers-reduced-motion` all CSS animation and transition is off and scrolling is instant; print keeps grounds and colours; a `canvas` never inherits the page's letter-spacing (Chrome would apply it to canvas text and push lattice characters off their cells).

`[hidden]` always hides (`display: none !important`), even over a library's inline `display`. A library that keeps hidden elements visible on purpose needs an exception: the deck has one for reveal.js's overview.

---

## Taste: the engine

`taste/engine/taste.js` exposes `window.Taste`. It also loads in Node (for build scripts); everything that needs a page is skipped there.

### Maths

| Function | Use |
| --- | --- |
| `Taste.clamp(x, a = 0, b = 1)` | Keep x between a and b. |
| `Taste.smooth(a, b, x)` | 0 below a, 1 above b, a smooth step between. |
| `Taste.mix(a, b, t)` | Linear mix. |
| `Taste.hash(i, j, s = 0)` | A stable number in [0, 1) for a cell and a seed: the identity of a cell. |
| `Taste.noise(x, y)` | Smooth value noise in [0, 1]: clusters and density. |
| `Taste.sdf.box(x, y, x0, y0, w, h, r)`, `.circle(x, y, cx, cy, r)`, `.and(a, b)`, `.or(a, b)`, `.not(a)` | Signed distances (negative inside) for shapes to fill with a lattice. |
| `Taste.TAU` | 2π. |

```js
const r = Taste.hash(i, j, 3);                       // the same cell always gets the same r
const dense = Taste.smooth(0.4, 0.72, Taste.noise(i / 6, j / 6));
const inside = Taste.sdf.box(x, y, 0, 0, w, h, 24) < 0;
```

### The cipher

| Name | Value |
| --- | --- |
| `Taste.HEX` | `0123456789ABCDEF` |
| `Taste.CIPHER` / `Taste.CIPHER_LOWER` | Hexadecimal twice, then signs `#%&$@+=*/<>?!;:` (capitals or lower case). |
| `Taste.SHAPES` | `dot, char, boxchar, ring, q, diamond, disc, star, box`: the whole vocabulary, light to heavy. |
| `Taste.SYMBOLS` | The shapes a cell can take without a character: `dot, boxchar, ring, q, diamond, disc, star, box`. |
| `Taste.SCAN` | What a cell shows while a wave is on it. |
| `Taste.NAMES` | Plain names: `{ dot: 'Dot', boxchar: 'Coded square', q: 'Quarter', ... }`. |
| `Taste.LEVEL` | `{ WORD: 4, CIPHER: 3, SHAPE: 2, DOT: 1, NONE: 0 }`: levels of reading, clear to dark. Decoding climbs; ciphering goes down. |
| `Taste.cipherChar(i, j, s, set = CIPHER)` | The cipher character of a cell at step s. |

### Drawing

`Taste.tile(ctx, x, y, s, kind, col, r = 0, o = 0, bg)`: one tile of size s centred on (x, y). `kind` from `SHAPES`; `col` any colour or a palette entry; `r` in [0, 1) picks the character of `char` and `boxchar`; `o` (0 to 3) turns `ring` and `q`; `bg` is cut out of `boxchar`.

| Tile | What it looks like |
| --- | --- |
| `dot` | A small square dot at the centre (a sixth of the cell). |
| `char` | One hexadecimal character, picked by `r`. |
| `boxchar` | A solid square with a character cut out of it in `bg` (the coded square). |
| `ring` | Two concentric quarter arcs centred on one corner of the cell (which corner: `o`). Not a full circle: at small sizes it reads as a pair of curved strokes. |
| `q` | A quarter disc filling the cell from one corner (`o`). |
| `diamond` | A square turned 45 degrees. |
| `disc` | A full disc. |
| `star` | A four-pointed star with concave sides. |
| `box` | A solid square filling the cell. |

The reference page (`index.html`, part 05) draws them all.

```js
const C = Taste.palette(el);
Taste.tile(ctx, 40, 40, 14, 'ring', C.fg, 0, 2);
Taste.tile(ctx, 60, 40, 14, 'boxchar', C.signal, Taste.hash(3, 4), 0, C.bg);
```

`Taste.pass(ctx, x, y, rho, bw, max, col)`: a pass of light (a wave) leaving (x, y), now at radius `rho`: a faint band `bw` wide, a crisp leading edge, three thin rings behind it, nothing beyond `max`. `col`: the ground's `--signal`.

```js
const rho = (time % 6) / 1.9 * w;                      // a wave every six seconds
if (rho < Math.hypot(w, h) + 100) Taste.pass(ctx, 0, 0, rho, 80, Math.hypot(w, h), Taste.palette(el).signal);
```

`Taste.passLine(ctx, x0, x1, y, bw, col, dir = 1)`: the same pass straightened: an edge at y and three lines behind it (`dir` 1 travels down).

`Taste.grain(ctx, x, y, w, h, a = 0.4)`: film grain over a rectangle (overlay). `0.16` over a whole night ground, `0.4` on a solid shape. Never on paper.

`Taste.grainTile(bg, a = 0.2)` returns a data URL of a 256px tile of ground `bg` with grain. `Taste.grainGround(el, a)` lays it on an element (the `.grain` class does this by itself, and again on theme changes).

`Taste.lattice({ x, y, w, h, cell, origin, inside, margin = 0.62, seed })`: whole cells of a square lattice inside an area, and inside a shape if `inside(x, y)` (a signed distance) is given. Returns cells `{ i, j, x, y, d, r }`; i and j count from `origin`, so a cell keeps its identity as the area moves. The array carries `cols`, `rows`, `i0`, `j0` (the first column and row inside the area, counted from the origin), `ox`, `oy`, `cell`.

```js
const cells = Taste.lattice({ w, h, cell: 16, inside: (x, y) => Taste.sdf.circle(x, y, w / 2, h / 2, h * 0.4) });
for (const c of cells) Taste.tile(ctx, c.x, c.y, 14, c.r < 0.6 ? 'char' : 'disc', C.fg, c.r);
```

`Taste.rows(cols, rows, layers = 2)`: characters on the lattice, kept a row at a time and drawn with one `fillText` per row and colour (fast, and every character sits whole in its cell). `put(i, j, ch, layer)` (i and j from 0), `draw(ctx, ox, oy, cell, size, colours)` (layer k in `colours[k]`), `clear()`.

```js
const g = Taste.rows(cells.cols, cells.rows, 2);
for (const c of cells) g.put(c.i - cells.i0, c.j - cells.j0, Taste.cipherChar(c.i, c.j, 1), c.r < 0.05 ? 1 : 0);
g.draw(ctx, cells.ox + cells.i0 * 16, cells.oy + cells.j0 * 16, 16, 14.4, [C.cipher, C.signal]);
```

`Taste.FONT`: `{ sans, mono }` font strings for canvas text.

### Colour

| Function | Use |
| --- | --- |
| `Taste.palette(el)` | The roles of el's ground, read from its custom properties: `{ bg, fg, mist, rule, strong, signal, fill, onFill, cipher, dim, accent, onAccent, light, paper, night, white, ink, inkNight, mistPaper, mistNight }`. Each is `{ r, g, b, a, css, rgb }`. Read once; read again after a theme change (a class, style or `data-theme` change on `<html>` or `<body>`, a stylesheet added, removed or loaded) or `Taste.refresh()`. |
| `Taste.colour(any)` | Any CSS colour as `{ r, g, b, a, css, rgb }`. |
| `Taste.alpha(c, a)` | The colour at another opacity, as an `rgba()` string. |
| `Taste.blend(c1, c2, t)` | A colour between two. |
| `Taste.token(name, el, as)` | What a custom property resolves to on `el` (default `<body>`): its text, or with `as` `'colour'` a colour `{ r, g, b, a, css, rgb }`, or `'px'` a length in pixels. For showing token values and measuring contrast. |

```js
const C = Taste.palette(document.querySelector('#f'));
ctx.fillStyle = C.fg.css;
ctx.strokeStyle = Taste.alpha(C.signal, 0.5);
```

Never write a colour constant into a figure. Read the palette, so the figure follows the theme and the ground.

### The loop

`Taste.scene(el, draw, options)`: gives `el` a canvas that fills it (behind its content) and draws it in one shared loop. Returns `{ el, cv, ctx, dirty, destroy() }`; set `scene.dirty = true` to have it drawn on the next frame; `scene.destroy()` takes it out of the loop and removes its canvas (the same as `Taste.drop(scene)`).

- `draw(ctx, w, h, time, now)`: `ctx` is in CSS pixels; `time` in seconds (frozen by `#t=`, held under reduced motion and pause); `now` in milliseconds.
- `options.live`: `true` redraws every frame while motion is allowed; a number redraws at most every that many milliseconds (ambient motion: use 66 or more); `false` draws only when dirty.
- `options.scroll`: `true` redraws on every scroll (scroll-driven figures).
- `options.still`: the time drawn under reduced motion (default `6.4`).

A scene is drawn once when the fonts arrive (even away from the screen, so a print or PDF has every picture), then only while near the screen, and again on resize and on theme change.

```js
Taste.scene(document.querySelector('#f'), (ctx, w, h, time) => {
  const C = Taste.palette(ctx.canvas.parentElement);
  Taste.tile(ctx, w / 2, h / 2, 40, Taste.SYMBOLS[Math.floor(time) % 8], C.fg);
}, { live: 250 });
```

| Function or value | Use |
| --- | --- |
| `Taste.start()` | Start the loop once the fonts are loaded. `scene()` calls it; calling again does nothing. |
| `Taste.pause(on)` / `Taste.togglePause()` | Stop or restart all motion of its own; returns the new state. Give every page with ambient motion a pause control. |
| `Taste.paused` | Whether paused. |
| `Taste.motion()` | May anything move on its own now? False under reduced motion, `#t=`, or pause. |
| `Taste.still` | True under `prefers-reduced-motion: reduce`. |
| `Taste.FIXED` | The frozen time from `#t=6` in the address or from `freeze()`, or `null`. |
| `Taste.freeze(t)` | Hold time at `t` seconds, as `#t=` does (for screenshots and PDFs); `freeze(null)` lets it run again. |
| `Taste.refresh()` | Read colours and layouts again and redraw everything. |
| `Taste.drawAll()` | Draw every scene now, including those away from the screen. Call it before printing or exporting a PDF. Never call it from inside a `beforeprint` handler: Chrome prints a canvas drawn during the print with white where it should be clear. |

```js
document.querySelector('#pause').onclick = (e) => {
  const on = Taste.togglePause(); e.target.textContent = on ? 'Play motion' : 'Pause motion';
};
```

### Scroll

| Function | Use |
| --- | --- |
| `Taste.scrub(el)` | How far a tall block with a pinned child has been scrolled through: 0 as its top reaches the top of the screen, 1 as its bottom reaches the bottom. |
| `Taste.cross(el)` | How far a block has crossed the screen: 0 as its top enters at the bottom, 1 as its bottom leaves at the top. |
| `Taste.onScroll(fn)` | Call `fn` once per frame while the page scrolls (and once now). Returns a function that stops it. |

```js
const pin = document.querySelector('.pin');
Taste.onScroll(() => pin.style.setProperty('--p', Taste.scrub(pin)));
```

### Text and reading

`Taste.cipherText(el, text, options) -> Promise`: change an element's text through the cipher, one character at a time. The old text goes down (two cipher steps, then gone); the new text climbs (three cipher steps, then the letter). Words never break while it runs, and the real letters stay in the page. Options: `step` (ms per step, default 46), `out: false` (skip the old text leaving), `order: 'random'`, `instant`. Under reduced motion, `#t=` or pause it changes at once. Replaces any child elements with plain text. Use it for every text change: never fade a whole block.

```js
const status = document.querySelector('#status');
await Taste.cipherText(status, 'Verified');
status.closest('.state').dataset.state = 'verified';
```

Changed text is read out once, as words: while it runs, the letters on screen are hidden from screen readers and a visually hidden copy carries the new text, so `cipherText` is safe inside an `aria-live` region.

`Taste.reveal(targets = '.rv')`: headings crossed by a pass of light the first time they are seen. Runs by itself on every `.rv` when the page loads; call it for headings added later.

`Taste.readProgress(targets = '[data-read]')`: sets `--p` (0 to 1) on each element as the reader goes through it, so the `.sq` inside (the running head) fills like a ticked list. Returns a stop function.

```js
Taste.readProgress('section[data-read]');
```

### Helpers for a figure of your own

| Function | Use |
| --- | --- |
| `Taste.rectsOf(sel, el)` | The boxes of what `sel` names, relative to `el`, as `[left, top, right, bottom]`: the words a figure keeps clear of. Text is measured line by line. A selector is looked for inside `el` first, then in the whole document (a hero's words sit beside its stage); pass elements to be exact. |
| `Taste.all(target)` | A selector, an element or a list, as an array of elements. |
| `Taste.drop(scene)` | Take a scene out of the loop and remove its canvas. |

Names that start with `_` (`Taste._driver` and others) are internal and may change.

---

## Ready-made figures

Each figure mounts with one call on an element, takes every colour from that element's ground (so it works with any accent, on paper, night or accent grounds), and has a static form: under reduced motion nothing moves on its own; scroll-driven changes still follow the reader's scroll, both ways; without JavaScript the element's own content (its text) is what shows.

Each returns a handle. Figures that follow a progress `p` (0 to 1) take a **drive**:

| `drive` | What sets p |
| --- | --- |
| `'cross'` (default) | The element crossing the screen, mapped through `range: [a, b]`. |
| `'pin'` | The scroll through the nearest `.pin` block (or `options.pin`), mapped through `range`. |
| `'time'` | On its own, slowly there and back over `period` seconds (held at `still` under reduced motion). |
| `'manual'` | Only `handle.set(p)` and `handle.play(to, ms)`. For decks: play on the slide's arrival. |

Handles have `set(p)` (null returns to the drive), `play(to = 1, ms = 2400, from) -> Promise` (jumps under reduced motion), `progress()`, `refresh()` and `destroy()`; canvas figures also have `scene`.

`options.of` (an element) makes another element's crossing drive the figure (with `'cross'`), or names the pinned block (with `'pin'`): a field in a pinned stage that starts to gather as the block comes up the screen uses `{ drive: 'cross', of: pinBlock }`.

### `Taste.figures.field(el, options)`

A lattice field of cipher cells. As the block is scrolled it gathers (a dot first, then a character or a shape, in clusters), then waves of light cross it from the corners: behind each wave most cells go down the cipher and vanish, and the few that survive climb a level with every wave until they are solid squares. Scrolling back runs it backwards.

Options: `drive` (`'cross'`), `of`, `range` (`[0.06, 0.6]` for cross, `[0.02, 0.92]` for pin), `cell` (px, or a function `(w, h) => px` for a frame that scales; default 12.5 below 900px wide, else about 1% of the width), `density` (0 to 1, default 0.5), `waves` (0 to 3, default 2), `keep` (share of cells that survive, default 0.2), `clear` (a selector or elements whose text and boxes stay clear of cells, line by line), `fade` (`'bottom'`, `'top'`, `'edges'`: thin the field towards those edges), `still` (p under reduced motion with the time drive, default 0.4: fully gathered), `period` (seconds, time drive, default 22), `start` (p before any set, manual drive), `seed`.

```html
<div class="figure band" id="field" role="img" aria-label="A field of cipher cells that gathers, crossed by waves"></div>
<script>Taste.figures.field('#field', { fade: 'bottom', clear: '#field-words' });</script>
```

In a deck slide (`templates/deck/` does this for you from `data-figure`):

```js
const f = Taste.figures.field('#slide-3 .figure', { drive: 'manual' });
Reveal.on('slidechanged', (e) => { if (e.currentSlide.id === 'slide-3') f.play(1, 4000, 0); });
```

### `Taste.figures.wave(el, options)`

A headline (or any line of text) that stays real type, crossed by waves of light. Under a wave each letter steps aside and the lattice stands in for it, knocked down the cipher cell by cell (characters, a shape, a dot, nothing); behind the wave every letter comes back, exactly. The first wave follows the scroll as the text comes up the screen; after it a wave comes every few seconds from alternating corners (not under reduced motion). The text stays selectable and is read out once.

Options: `scroll` (true: the first wave follows the scroll), `repeat` (true), `every` (seconds between waves, 8.5), `bleed` (how far the light reaches past the text, in em, 1), `cell` (px; default 7% of the font size), `still` (0 to 1, or null: when nothing may move, as under reduced motion, `#t=` or in a PDF, a wave held that far across the text; by default the text is plain). Handle: `pass()` sends a wave now (for decks), `refresh()`, `destroy()`.

```html
<h2 class="xl" id="claim">Attacked, not asserted.</h2>
<script>const w = Taste.figures.wave('#claim');</script>
```

### `Taste.figures.decode(el, options)`

A value that climbs the cipher levels as it crosses the screen: each character starts as a shape, passes through three to five cipher characters, and becomes itself, from left to right. Scrolling back ciphers it again. Best on mono values (each character takes one lattice cell, `.72em` wide). The real text stays in the page for reading out and copying; a print shows it decoded. Pass a selector to mount on several elements at once (returns an array).

Words never break inside while it runs. Options: `drive` (`'cross'`), `of`, `range` (`[0.1, 0.5]`), `start` (manual drive), `seed` (another set of waiting shapes; by default they follow the whole text, so two values never wait alike), `onProgress(done, p)` (`done`: share of characters decoded; use it to fill a state square). The handle also has `text(value)`, which changes the value and starts it again from the shapes, and `destroy()`, which puts plain text back. Mounting again on the same element replaces the earlier handle.

```html
<tr><th scope="row"><i class="sq" id="sq1"></i> 01 Where it runs</th><td class="v"><span id="v1">RACK 14 · ZONE B</span></td></tr>
<script>
  const sq = document.getElementById('sq1');
  Taste.figures.decode('#v1', { onProgress: (done) => sq.style.setProperty('--p', done) });
</script>
```

---

## LucidMark (brand only)

`brand/lucid-mark.js` exposes `window.LucidMark`. Lucid's own site, decks and demos only; a project led by Lucid never loads it. The mark's meaning, and what never to do with it, are in `brand/README.md`. In short: the mark is a black box with a star cut through it; the box is always one solid colour distinct from its ground; the star is always the ground showing through (never a gradient or a picture behind dark petals); it appears rarely (as the logo, and at most once as a figure that earns it); under 40px it uses the wider cut. The wordmark is **provisional**: an earlier drawing, not yet redrawn for this mark.

| Name | What it is |
| --- | --- |
| `LucidMark.POSITIONS` | `through` (A, the primary), `open` (B), `pinwheel` (C), `off` (D, off centre), each `{ key, name, note, l, w, sx, sy, stop }`. |
| `LucidMark.ORDER` | `['through', 'open', 'pinwheel', 'off']`. |
| `LucidMark.CORNERS` | The four petals' meanings, top left clockwise: where it runs, what is running, how it is used, who checks it. |
| `LucidMark.COLOURS` | `{ night, paper, white, ink, cobalt, periwinkle, peach, mist, mistNight }`, for files and canvases. In pages prefer the tokens. |
| `LucidMark.DAWN` | The dawn stops `[[0, '#0a1fa8'], [0.3, '#1b3bff'], [0.56, '#3f6ef5'], [0.78, '#a9c4ff'], [0.92, '#f1e6e0'], [1, '#ffd3a8']]`. |
| `LucidMark.SHAPE`, `LucidMark.SMALL` | The geometry constants (do not change), and 40: the size in px below which the wider cut is used. |

`LucidMark.field(position = 'through', options) -> f(x, y)`: the mark as a signed distance field in its 100 x 100 box (negative inside the ink). Options: `sx`, `sy` (shift the star), `w` (another twist), `neck` (a wider cut), `size` (px it will be shown at; under 40 gives the wider cut), `only` (0 to 3: one petal, top left clockwise). `LucidMark.petal(i, position, options)` is `field` with `only: i`. `LucidMark.boxField(x, y)`: the box the mark sits in.

```js
const f = LucidMark.field('pinwheel');
const inStar = f(50, 50) > 0 && LucidMark.boxField(50, 50) < 0;
const small = LucidMark.field('through', { size: 16 });
```

`LucidMark.path(position, options, N = 320)`: the outline as an SVG path `d` in the 100 box.

`LucidMark.svg(options) -> string`: the mark as a complete `<svg>`. Options: `position`, `fill` (`'currentColor'`), `size` (px: sets width and height; under 40 the wider cut), `small` (true or a px size: the wider cut, 24 by default), `only`, `bg`, `N`, `title`, `decorative`.

```js
el.innerHTML = LucidMark.svg({ fill: 'var(--accent)', title: 'Lucid' });
const icon = LucidMark.svg({ size: 24, fill: '#07080c', decorative: true });
const petal = LucidMark.svg({ only: 1, fill: '#f3f4f0', decorative: true });
```

`LucidMark.lockupSVG(options) -> string`: the mark and the provisional wordmark. Options: `fill`, `height` (px), `title`, `decorative`. `LucidMark.wordmarkSVG(options)`: the wordmark alone.

```js
header.querySelector('.logo').innerHTML = LucidMark.lockupSVG({ fill: '#f3f4f0', height: 26, title: 'Lucid Computing' });
```

`LucidMark.draw(ctx, x, y, size, options)`: the mark on a canvas, its box at (x, y), `size` px. Options: `position`, `fill` (or `false` to build the path only), `sx`, `sy`, `only`, `N`, `field`. `LucidMark.drawLockup(ctx, x, y, size, col, right)` and `LucidMark.drawWord(ctx, x, y, h, col)` draw the lockup and the wordmark.

```js
Taste.scene(el, (ctx, w, h) => {
  const s = Math.min(w, h) * 0.6; LucidMark.draw(ctx, (w - s) / 2, (h - s) / 2, s, { fill: Taste.palette(el).fg.css });
}, false);
```

`LucidMark.lit(ctx, f, box, N = 112)`: the solid mark (a field, or a position name) filled with the dawn light from top to bottom, with grain. `box: { x, y, size }`. On night only. `LucidMark.dawn(x)` gives the dawn's colour at x (0 deep blue, 1 peach).

```js
Taste.scene(el, (ctx, w, h) => {
  const s = Math.min(w, h) * 0.62; LucidMark.lit(ctx, 'through', { x: (w - s) / 2, y: (h - s) / 2, size: s }, 150);
}, false);
```

`LucidMark.mount(root = document)`: fills every element carrying `data-lucid-mark` or `data-lucid-lockup` (it runs once by itself when the page loads; call it for elements added later). The attribute's value is the fill (empty: `currentColor`, so the ground's text colour). `data-position` picks a position; `data-size` (or the element's width) picks the wider cut under 40px. `aria-label` on the element names it; `aria-hidden="true"` makes it decorative. Size a mark with `width` or `--mark-size`; a lockup with `--lockup-size` (its height, 26px by default).

```html
<a href="/" data-lucid-lockup aria-label="Lucid Computing, home" style="--lockup-size: 26px"></a>
<span data-lucid-mark="#1b3bff" data-position="pinwheel" style="width: 120px" aria-hidden="true"></span>
<span data-lucid-mark data-size="20" aria-hidden="true"></span>
```

`LucidMark.favicon(fill = cobalt)`: puts the small mark in the browser tab (or link `brand/assets/favicon.svg`).

### `LucidMark.figures.hero(el, options)`

The mark holding a cipher, as at the top of the landing page, without the scroll zoom. On a night ground, four petals in paper, each filled with cipher characters and small tiles; between them the star, the night showing through, and inside it the same lattice decoded into plain words. Every few seconds a wave of light leaves one corner of the box, scrambles what it crosses and leaves a new cipher. Under reduced motion it is a still picture.

Options: `position` (`'through'`), `words` (lines for the star; default the four corners), `place` (`'auto'`: right of the words on wide screens, above them on upright ones; `'right'`, `'centre'`, or `(w, h) => ({ x, y, size })`), `clear` (a selector or elements kept clear of cells, and, upright, kept below the mark), `every` (seconds between waves, 6), `cell` (px), `top` (px kept free above the mark when upright, 24), `lean` (false: the star leans a little toward the pointer when true).

```html
<section class="night hero" style="position: relative; min-height: 100svh">
  <div class="stage" id="stage" style="position: absolute; inset: 0" role="img" aria-label="The Lucid mark holding a cipher; waves of light cross it"></div>
  <div class="wrap hero-text" id="words">...</div>
</section>
<script>LucidMark.figures.hero('#stage', { clear: '#words > *' });</script>
```

### `LucidMark.figures.petals(el, options)`

Two petals of the mark, in the paper's colour and far larger than the band that holds them, reaching into it from its edges, so the accent between them reads as the star. On a wide screen they come in from the right; on an upright screen (narrower than 11 by 10) both come up from below, into room `lucid.css` keeps under the band's words, so put the words at the top of the band. They drift a little against the scroll (not under reduced motion).

Options: `avoid` (a selector or element, usually the headline, that the petals keep clear of), `fill` (`'var(--ground-paper)'`: the ground of the part that follows), `drift` (true).

```html
<section class="accent grain sheet" id="band">
  <div class="wrap"><div class="r"><div class="m"><b>02</b></div><div class="x"><h2 class="xl" id="band-h">We prove it rather than assert it.</h2></div></div></div>
</section>
<script>LucidMark.figures.petals('#band', { avoid: '#band-h' });</script>
```

### Brand files

`brand/assets/` holds files built from the engine by `node brand/assets/build.mjs` (Node only, no packages): `mark-{through,open,pinwheel,off}-{ink,paper,cobalt}.svg`, `mark-small-{ink,paper,cobalt}.svg` (the wider cut, for under 40px), `lockup-{ink,paper,cobalt}.svg`, `favicon.svg`, `favicon-16.png`, `favicon-32.png` (cobalt, transparent), `favicon-180.png`, `favicon-512.png` (paper mark on a cobalt square, for home screens), `social-preview.png` (1200 x 630, night). Ink is `#07080c`, paper `#f3f4f0`, cobalt `#1b3bff`. Rebuild after any change to the engine; never edit them by hand.

```html
<link rel="icon" href="brand/assets/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="brand/assets/favicon-180.png">
<meta property="og:image" content="brand/assets/social-preview.png">
```

---

## Writing a theme

A theme is one small stylesheet loaded after `base.css`. It sets the five values of the accent slot and nothing else is required:

```css
:root {
  --accent: #c8320f;           /* the one colour: 4.5:1 or more against paper #f3f4f0 (it is used as text) */
  --on-accent: #ffffff;        /* text on it: 4.5:1 or more */
  --accent-light: #ff8a66;     /* the same colour as light on night: 4.5:1 or more against #07080c */
  --accent-night: #c8320f;     /* the fill of a pressed button on night */
  --on-accent-night: #ffffff;  /* text on that fill: 4.5:1 or more */
}
```

These are Sorrel's values (`themes/example/theme.css`). If your colour is light (it does not read on paper), use it as `--accent-light` and `--accent-night`, and choose a darker `--accent`. `themes/_template/check.html` measures the four contrasts. A theme may also set the derived `--mist-accent`, `--line-accent`, `--cipher-accent` and `--cipher-dim-accent` exactly. A theme never adds colours, gradients or shadows, and never renames a token.

To scope a theme to part of a page, write its selector as `:root, [data-theme="name"]` and add `data-theme="name"` to that element (or to `<html>`). The four derived tokens follow it there by themselves. A theme that sets them exactly declares them on the same selector, as `brand/lucid.css` does.

---

## Checks before you ship

- Open the page from the file system at 390px and 1500px wide (the kit's two check widths): no console errors, no sideways scroll.
- Turn on reduced motion: nothing moves on its own; every figure is a finished still picture.
- Open it with `#t=6` for screenshots: time is frozen, waves stand where they are.
- Every figure element has `role="img"` and an `aria-label`; every number shown has a source; sample data is labelled `Sample`.
- Read `taste/RULES.md` once more against the page.
