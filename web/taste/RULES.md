# Taste: the rules

These are the settled decisions behind every page, deck and demo made with this kit, branded or not. Each rule has a one-line reason, so that a case the rules do not cover can be judged the same way.

The rules hold for any accent colour and any name. Nothing here belongs to one brand: the Lucid mark, cobalt and the dawn light are in `brand/README.md`. Every token, class and function named below is listed in the contract, `taste/README.md`.

The measure for all of it is the approved landing page: a record of a few strong screens, each with one idea, separated by quiet typographic ones.

Contents: [The idea](#the-idea) · [Layout](#layout) · [Type](#type) · [Colour](#colour) · [Figures and the cipher](#figures-and-the-cipher) · [Motion](#motion) · [Components](#components) · [Writing](#writing) · [Rejected](#rejected) · [Cases the rules do not cover](#cases-the-rules-do-not-cover)

---

## The idea

The work is about things that can be checked. So the page behaves like a record: labels and numbers in a margin, facts in mono, one hard left edge to read down. Its figures show the same idea in drawing: a field of characters that is unreadable at first and becomes clear, level by level, as a wave of light passes. Everything else is restraint: one colour, two typefaces, hairlines, space.

---

## Layout

- **The page is a record: a margin column, then a main column.** Numbers and labels go in the margin (`.m`), content in the main column (`.x`), so the main column carries only what matters.
- **One hard left axis.** Everything in the main column starts on the same vertical line; a record is read down one edge, and the eye never has to look for where a block begins.
- **Nothing is centred.** A centred block has no edge to read from and breaks the axis.
- **One idea per screen.** A screen with two ideas has none that the reader keeps.
- **A part has a number, a label and one claim.** `01`, `02`, in two digits, in the margin: the page becomes an index that can be cited ("see 03").
- **Hairlines separate; boxes do not.** A rule orders things without closing them in; a card makes every item compete for attention.
- **Generous vertical space.** `--space-top` above a part, `--space-end` below it, `--space-8` between its rows: space is what lets few words read as considered rather than sparse.
- **Few words.** A claim of a few words, one sentence that explains it, labels for the rest. Every word on a screen is read; spend them.
- **Quiet screens between strong ones.** A typographic list after a large figure gives the eye a rest and is where the reading happens.
- **Where the ground changes, lay a sheet.** `.sheet` puts the new ground over the last one with soft top corners: the change is a page turned, not a stripe.
- **Large radii on large things, small radii on small things.** Sheets `--radius-sheet`, square figures `--radius-box` (14 on 100, the softness of a box), panels `--radius-panel`, controls `--radius-control`, tags `--radius-tag`. One family of curves, scaled to the object.
- **The grid stacks on a phone and nothing scrolls sideways.** The margin folds into one line above its block; a wide table scrolls inside `.scroll-x`, never the page.

## Type

- **Two typefaces: Geist and Geist Mono. No serif, no third face.** One voice for what we say, one for what we can show.
- **The claim: Geist Semibold, capitals, set tight (`.xl`), one per screen.** A claim must be seen at once; two on a screen and neither is the claim.
- **A smaller headline in the same voice (`.tt`).** For parts that need a title but not a claim, such as a list or a team.
- **Sentences: Geist Regular, sentence case (`.sent`, `.lead`).** Capitals are for claims; explanation is read, so it is set as speech.
- **Labels and facts: Geist Mono, 11px, capitals, wide tracking (`.mono`).** Mono says "this is a value you could check", and the reader learns it after one screen.
- **Anything that is a fact is in mono:** values, hashes, numbers, identifiers, tags, table values, states. The distinction only works if it is never broken.
- **A fact shown large stays mono (`.val`).** A large value is still a value, not a headline.
- **Hashes keep their case and break anywhere (`.hash`).** An identifier must be copied exactly.
- **Document titles: Semibold, sentence case.** The title of a report is a name, not a claim.
- **Two weights: Regular (400) and Semibold (600).** Emphasis is ink against mist, not weight: inside a label, `<b>` is in ink and the rest is in mist.
- **One type scale.** Use the sizes in `tokens.css`; never invent one. One scale holds every screen, deck and app together.
- **Sentences at most 44 characters wide (`.sent`), prose at most 62.** Short lines are read whole.

## Colour

- **Grounds: night `#07080c`, paper `#f3f4f0`, and white for panels on paper.** Two grounds give two moods (looking into the box, reading the record) and nothing more is needed.
- **One accent colour.** Because there is only one, it always means something: the one action, a live state, the light of a wave.
- **A lighter tint of the accent for light on night (`--accent-light`).** The accent itself is too dark to read on night; its tint is the same colour as light.
- **Mist for labels: `#686e88` on paper, `#8a8d97` on night.** Labels step back so the content leads.
- **No other colours.** No red for failure, no green for success: a state is said in a word and shown by a square, which works for every reader and keeps a record from turning into a dashboard.
- **No gradients as backgrounds.** A gradient ground is decoration; the grounds here are flat so the drawing on them reads.
- **No shadows, no borders-and-cards.** Depth comes from a sheet laid over a ground, not from a shadow under a box.
- **Grain on night and accent grounds, never on paper.** Grain gives a dark ground a material; on paper it reads as dirt.
- **The accent as a ground (`.accent`) at most once per page.** A band of colour is a strong event; twice, and it is a theme.
- **Read colours from roles, never write a colour constant.** `var(--signal)`, `var(--fg-mist)` and `Taste.palette(el)` keep one component right on every ground and with any accent.
- **Contrast is checked, not assumed.** Text and labels reach 4.5:1 against their ground. The accent is used as text and links, so it reaches 4.5:1 against paper too, and so do the three other pairs of a theme (`themes/_template/check.html` measures them). A theme with a light colour puts it in `--accent-light` and picks a darker `--accent`.

## Figures and the cipher

- **Figures are drawn on a square lattice.** A fixed grid makes every figure belong to the same record, and every cell sits whole in its place.
- **A small fixed vocabulary.** Cipher characters (hexadecimal and the signs `#%&$@+=*/<>?!;:`) and eight tiles: dot, coded square, ring, quarter, diamond, disc, star, square (`Taste.SHAPES`). A small alphabet keeps the work in one hand and can be learnt by the reader.
- **Levels of reading, from clear to dark:** a plain word (4), a cipher character (3), a shape (2), a dot (1), nothing (0) (`Taste.LEVEL`). These levels are the story the figures tell: something unreadable becoming checked.
- **Decoding climbs the levels; ciphering goes down them.** The direction always means the same thing, so a change can be read without a caption.
- **Waves of light carry changes.** A pass with a crisp leading edge and three thin rings behind it (`Taste.pass`): a change has a cause and a direction, and the wave shows both.
- **A figure shows an idea, never a picture of a thing.** A field of cells that gathers, a value that decodes, a headline crossed by light. No icons, faces or objects built from tiles.
- **The accent is rare inside a figure.** A few cells in a hundred: the accent marks what is live, and loses meaning when it is everywhere.
- **Grain on figures on dark grounds.** The same material as the ground.
- **Figures keep clear of text.** Cells never sit under type (the `clear` option); type is never drawn over.
- **One figure per screen.** Two figures compete, and the screen has two ideas.
- **Every figure has a still form.** Under reduced motion, in print and in screenshots (`#t=6`) it is a finished picture; without JavaScript its own text shows.
- **Colours come from the ground.** A figure mounted on paper, night or an accent ground reads its palette there, so it needs no variant.

## Motion

- **The reader's scroll drives the important changes, and they are reversible.** The reader is in control; scrolling back undoes the change, so nothing is missed and nothing is waited for.
- **Ambient motion is slow and sparse.** A wave every six to nine seconds, redraws no faster than needed (`live: 66` or more): motion that never rests becomes noise, and a page must be readable while it moves.
- **Text changes through the cipher, never by fading a whole block.** `Taste.cipherText` takes the old text down the levels and the new text up them; a fade hides the change, the cipher shows it.
- **Nothing moves on its own under `prefers-reduced-motion`.** Scroll-driven changes still follow the scroll, because the reader is moving them.
- **Every page with ambient motion has a pause control.** `Taste.togglePause()`; motion that cannot be stopped is a barrier for some readers.
- **One easing (`--ease`) and a few durations (`--dur-quick`, `--dur-reveal`, `--cipher-step`).** One rhythm across every piece.
- **The pointer is never the main idea.** At most a figure leans a little toward it; nothing follows it, and everything works by touch and by keyboard.

## Components

- **Buttons are mono capitals with soft corners, outlined by default (`.btn`).** One solid button per screen (`.btn.solid`) for the one main action; more than one and the reader has to choose.
- **Tags state a fact about the content: `Sample`, `Placeholder`, `To clear`, `Draft` (`.tag`).** They keep unfinished or illustrative material honest in every screenshot.
- **States are a word and a small square that fills (`.state`, `.sq`).** Never a coloured pill: the word says the state, the square repeats it.
- **Tables are records (`table.record`).** A heavy rule above and below, hairlines between, labels and values in mono: a table is read like the page.
- **Key and value pairs are `dl.kv`.** The record again, at the scale of one object.
- **Panels are flat (`.panel`).** White on paper, raised night on night; no border, no shadow.
- **Forms speak the same language (`.field`, `.input`, `label.check`, `label.switch`).** A form is a record the reader fills in.
- **Code sits on night (`pre.code`), hashes in mono (`.hash`).** Code is a fact; it looks like one.
- **No icon set.** Use a word in mono, or a tile from the vocabulary where a state needs a mark. Pictograms bring a second visual language.
- **Charts, when needed, are records too.** Hairline axes, mono labels, ink and the one accent, values labelled with their source. There is no chart component yet; keep to these rules.
- **Photographs: no rules yet.** None of the approved work uses them. Ask before adding any; never use stock or generated imagery.

## Writing

These hold for all public text: pages, decks, demos, captions, labels, alt text.

- **Say what the mechanism does.** "Attested", "verified", "bound to", "checked by": a reader can ask how, and there is an answer.
- **Never "provably safe", "unhackable" or "trustless".** Each claims more than any mechanism gives, and one counterexample undoes the whole page.
- **No em dashes or en dashes.** Use a full stop, a colon or a comma. Short sentences carry the register.
- **Every number shown in public has a source and the chief executive's approval.** A number is a claim that can be checked; it must survive the check.
- **No customer or partner names unless they have agreed.** Their name is theirs to give.
- **Sample data is labelled as sample.** A `Sample` tag or a caption, on the screen itself, so a screenshot cannot mislead.
- **Placeholders are labelled as placeholders.** The same reason.
- **British spelling: colour, centre, licence (noun).** One spelling across everything.
- **Plain and exact.** No marketing voice, no exclamation marks, no superlatives. A research lab states what it did and what it found.
- **Claims are short; sentences explain them.** A claim of two to six words in `.xl`; one sentence under it in `.sent`.

## Rejected

Each of these has been turned down. Do not let them back in.

| Rejected | Why |
| --- | --- |
| Glows or halos round shapes | They blur the edge. Here edges are crisp, and light is a pass that moves, not a haze that sits. |
| Blend-mode tricks | They make colours that are not in the palette, and look different on every screen and ground. |
| Blobs, or ovals popping up | Shapes without construction. Every shape here comes from the lattice or the box. |
| A spotlight following the pointer as the main idea | It puts the visitor's hand at the centre instead of the work, and it is dead on touch screens and under reduced motion. |
| A brand mark repeated small as decoration | A mark that is wallpaper means nothing. It appears rarely. |
| Pictograms or portraits made of tiles | The lattice shows levels of reading, not pictures. A face made of tiles is a gimmick. |
| Walls of repeated words used as texture | Noise that pretends to be a pattern, and is read out by screen readers as noise. |
| Complexity for its own sake | Every element on a screen must carry its one idea; the rest is taken away. |
| Anything cute or jokey | The work is about trust. The register is a research lab's. |
| Stock or generated AI imagery | Generic, unearned, and says nothing about the mechanism. |
| Glowing chips, circuit boards, neural-network illustrations | The clichés of the field. They say "AI" and nothing else. |
| Gradients as backgrounds, shadows, bordered cards | Decoration in place of structure. |
| Colour coding (red, amber, green) | A second colour system, unreadable for some readers. States are words with a square. |

## Cases the rules do not cover

**A product that already has a design is one of them, and the largest.** These rules describe new work. Laid in full over an existing tool they replace its character and read as a regression. For that case the measure is the product as it was, not the landing page: `skills/lucid-design/reference/existing-products.md` has the order of work, what stays, and the rules for a dense tool.

For everything else, ask, in this order:

1. **What would the landing page do?** It is the measure. If a part of it already solves the problem, reuse that part.
2. **Is it a fact?** Then it is in mono, it has a source, and it may be labelled.
3. **Does it carry the one idea of the screen?** If not, remove it.
4. **Does it still work on a phone, under reduced motion, without colour and in print?**
5. **Would it look finished with another accent?** If it only works in one colour, it belongs to a brand, not to the taste.

When two answers disagree, choose the quieter one.
