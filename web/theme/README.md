# Starting a project led by Lucid

Lucid launches websites and projects that are led by Lucid but do not carry the Lucid brand: no Lucid mark, no Lucid colours, their own name. They must still feel like the same hand. They get that by sharing everything in `taste/` and changing very little on top of it.

This folder is the starting point for such a project. `themes/example/` is one worked through, for an invented project called Sorrel.

## What a project has of its own

| Its own | How |
| --- | --- |
| A name | Written in type: Geist Mono capitals in the top bar and the colophon (`.bar-name` in the page template), the claim in Geist Semibold capitals like any claim. No drawn logo is needed; if one is drawn later, it is drawn in the same hand (soft corners, square lattice), and never resembles the Lucid mark. |
| An accent, and its light | `theme.css`: five values in the accent slot. One colour, not blue. |
| One figure | `figure.js`: one drawing of its own, built from the lattice vocabulary and the engine, used once (usually in the hero). |
| A favicon | `favicon.svg`: one square in the accent. Change its colour to the theme's `--accent`. |
| One line | "Led by Lucid Computing", in the colophon or footer only (below). |

## What stays the same

Everything in `taste/`, untouched: the grounds (night, paper, white for panels), the type roles and the one type scale, the page grid with its margin column and hard left axis, hairline rules, mono for facts, soft corners and sheets, grain on dark grounds, the motion rules, the writing rules, the cipher, the tiles, the waves, and the ready-made figures (`field`, `wave`, `decode`). The page, deck and app templates work for a project as they are, with its theme in place of `brand/lucid.css`.

## What a project never uses

Anything in `brand/`: the Lucid mark in any position, its petals, the lockup and the wordmark, cobalt (`#1b3bff`), periwinkle (`#93a5ff`), the dawn light, `brand/lucid.css`, `brand/lucid-mark.js`, the Lucid favicon and social preview. Not even small, not even in the "Led by" line.

## The layout of a project

One layout, so every path is the same in every project:

```text
my-project/
  taste/     the foundation, copied from the kit unchanged
  theme/     theme.css, figure.js, favicon.svg, check.html, README.md (this folder)
  site/      the landing or project page (from templates/page)
  app/       the demo, if there is one (from templates/app)
  deck/      a deck, if there is one (from templates/deck)
```

Every page sits one folder below the project, so it links `../taste/` and `../theme/`. Make it with one command from the kit's root (it needs only `sh`, `cp` and `perl`, and writes nothing inside the kit):

```sh
sh themes/_template/new-project.sh ../my-project site app      # add deck for a deck
```

It copies `taste/` and this folder, copies the templates you name, rewrites their `../../taste/` to `../taste/`, links `../theme/theme.css` and `../theme/favicon.svg` in place of the Lucid theme and favicon, and removes `brand/lucid-mark.js`. Without the mark script the templates show the project's name in type, the "Led by" line, and a field where the mark would be.

The page and app templates still hold a few lines written for Lucid that do nothing in a project: `Page.hero` has a branch for `LucidMark`, the CSS hides an empty `[data-lucid-lockup]`, and the bar keeps an empty lockup element. They are inert; delete them if you like. A check for brand leaks is therefore "no file from `brand/` is loaded", not a search for the word Lucid.

## Steps

1. Make the project: `sh themes/_template/new-project.sh ../my-project site` (add `app` or `deck` as needed). Rename `PROJECT` in `theme/theme.css` and `ProjectFigure` in `theme/figure.js`.
2. Choose the accent. Fill the five values in `theme/theme.css`, following the notes at its top, then open `theme/check.html`: the four contrasts must each read "Passes" (4.5 to 1 or more), and the accent must look right on paper, on night and as a band. Set the same colour in `theme/favicon.svg`.
3. Make the figure. Start from `theme/figure.js` (it runs as it is, with a placeholder silhouette) and replace `shape` with the project's own idea; `place` already puts any shape beside or above the words. Load it in the page after `taste.js` and pass it to `Page.hero(stage, { figure: (el, o) => ProjectFigure.figure(el, o) })`.
4. Write the words: the name in the bar (`.bar-word`) and the colophon, the page's `<title>`, the copyright line, the claims. In the app, the product's name in the bar.
5. Keep the "Led by Lucid Computing" line in the colophon (the templates have it; see below).
6. A link preview: if the site is shared by link, make a 1200 x 630 PNG of the hero (a screenshot of `site/index.html#t=6` at 1200 x 630 works) and link it with `<meta property="og:image">`. Never use Lucid's.
7. Run the checklist.

## The "Led by" line

A project led by Lucid says so once, in one mono line, in its colophon or footer. Nowhere else: not in the top bar, not in the hero, not in a figure, not beside the project's name. It takes the ground's own colours (mist, the name in the ground's ink) and never any Lucid colour or mark. The class `.led-by` is in `taste/base.css`.

```html
<p class="led-by">Led by <b>Lucid Computing</b></p>
```

If the project's site links to Lucid's, make the name the link, nothing more: `<p class="led-by">Led by <a href="..."><b>Lucid Computing</b></a></p>`.

## Choosing the accent

- `--accent` must read on paper (4.5 to 1 or more against `#f3f4f0`): a mid-dark, saturated colour. It is used as text and links, so 4.5 to 1 is the rule, the same everywhere in the kit. `--on-accent` (usually white) must read on it at 4.5 to 1 too.
- `--accent-light` is the same hue made light enough for night (4.5 to 1 or more against `#07080c`; aim for about 8): it carries waves, live marks and checked boxes on night.
- A light colour (yellow, lime, cyan) cannot be `--accent`: put it in `--accent-light` and use a darker shade of the same hue as `--accent`.
- Not blue: cobalt and periwinkle are Lucid's. Keep clear of the blues from about 215 to 250 degrees of hue.
- One accent only. No second colour, no gradient, no shadow.
- Look at it as a band. `check.html` shows the accent as a grained ground; a colour that passes every contrast can still look dull there (dark ochres and browns read as cardboard). If it does, move it towards a cleaner, more saturated hue of the same family.

Accents already in use, so a new project picks another:

| Project | `--accent` | `--accent-light` | Note |
| --- | --- | --- | --- |
| Lucid Computing | `#1b3bff` cobalt | `#93a5ff` periwinkle | Lucid's own; never for a project. |
| Sorrel (`themes/example/`, invented) | `#c8320f` vermilion | `#ff8a66` | The kit's worked example and the "Other accent" on the reference page. |

| Inference Proofs | `#5b7bff` | `#5b7bff` | Predates the kit and kept its own blue by its owner's decision; night words on it. An existing product keeps the accent it has (`skills/lucid-design/reference/existing-products.md`). |

Add a row here when a real project settles its accent.

## Making the figure

The figure is where a project shows its own idea, in the shared vocabulary. Sorrel's is a sheet of paper on the night with a register drawn on it in the lattice, rewritten row by row by a straight pass of light: the project's subject (a register of runs), the taste's devices (a sheet, a record, the cipher, a wave).

- Cells of a square lattice, holding cipher characters, the small tiles (dot, coded square, ring, quarter, diamond, disc, star, square; `taste/README.md` says what each looks like) and plain words. Levels from clear to dark: word, cipher, shape, dot, nothing. Changes travel with a wave of light (`Taste.pass`, or `Taste.passLine` for a straight one); decoding climbs the levels, ciphering goes down.
- Its own silhouette. Never the Lucid mark (a soft box with a four-pointed star cut through it), never its petals, never a pictogram or portrait made of tiles, never a wall of one repeated word.
- Colours only from `Taste.palette(el)`. The accent on very few cells and on the light of a wave; the rest in the ground's ink, cipher greys and mist.
- Quiet when it moves on its own: a wave every several seconds, slow ambient change, redrawn no more often than every 66 ms (`live: 66`); nothing under reduced motion (draw from `time` in `Taste.scene` and test `Taste.still`). Keep the light of a wave on the figure, not across the page.
- No glow or halo, no blend-mode effect, no blobs, no spotlight following the pointer, nothing cute.
- The element has `role="img"` and an `aria-label` that says what it shows.
- Use only what `taste/README.md` documents (`Taste.rectsOf` for the words to keep clear of, `scene.destroy()` to remove it). Names starting with `_` in `Taste` are internal.

## Checklist

- [ ] `theme.css` sets only the accent slot (and, rarely, the grounds); `check.html` shows four passes; `favicon.svg` has the accent.
- [ ] The accent is not blue and is not in the table above; it appears sparingly: one band per page at most, a few cells in a figure.
- [ ] No file from `brand/` is loaded (`grep -rnE '(src|href)="[^"]*brand/' site app deck` finds nothing); no cobalt, periwinkle or dawn anywhere; the Lucid mark appears nowhere.
- [ ] The project's name is set in the kit's type; the "Led by Lucid Computing" line is in the colophon or footer and nowhere else.
- [ ] One figure of its own, used once, built from the lattice vocabulary, with `role="img"` and an `aria-label`.
- [ ] Pages open from the file system at 390px and 1500px wide with no console errors and no sideways scroll.
- [ ] Under reduced motion nothing moves on its own; every page with motion has a pause control.
- [ ] Put a page beside the same part of a Lucid page: it should look like the same hand, and not like Lucid.
- [ ] Writing: say what the mechanism does; no "provably safe", "unhackable" or "trustless"; no em dashes or en dashes; every number has a source and approval; no customer or partner names without their agreement; sample data labelled `Sample`.
