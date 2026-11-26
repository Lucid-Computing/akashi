# Akashi web preview

A clickable preview of the Akashi platform: a network of models whose replies are signed, logged, sampled for proof and open to challenge. **Everything in it is sample data.** No model runs, no proof is checked and nothing is sent anywhere. It exists to settle the interface before real features are wired in.

Open `app/index.html` in a browser. No build step, no server, no network access.

| Screen | Address | What it shows |
| --- | --- | --- |
| Overview | `#overview` | How it works in three live steps (logged, sampled and proved, challenged), then live traffic and verdicts |
| Models | `#models`, `#model/<id>` | Each model's commitment, operators, record and an OpenAI-compatible call |
| Traffic | `#traffic`, `#request/<id>` | Every logged reply with the log's live size, and one reply's receipt: model, log, beacon, selection, proof |
| Sampling | `#sampling` | One in 20 selected by a public beacon, the selection lattice, a selection recomputed |
| Challenges | `#challenges`, `#file`, `#challenge/<id>` | Holders, regulators and third parties asking for a proof, and each challenge's lifecycle |
| Playground | `#playground` | Send a chat, get a sample reply and a receipt you hold |
| Verify | `#verify` | Offline checks of a bundle, including one with a changed bit |

**Live network** in the bar pauses the simulated traffic and all motion.

## Files

| Path | What it is |
| --- | --- |
| `app/index.html` | The shell and the screens |
| `app/data.js` | The sample network: models, operators, traffic, beacon rounds, challenges, log heads |
| `app/akashi.js` | The screens' behaviour |
| `app/akashi.css` | What the screens need beyond the design kit |
| `app/app.css`, `app/app.js` | The app shell from the design kit, unchanged |
| `theme/` | Akashi's accent (`theme.css`), its figure (`figure.js`, the selection lattice) and favicon |
| `taste/` | The design foundation, copied unchanged from Lucid's design kit |

## What follows the real design

The sample is invented, but its shape follows the specification in this repository: replies are logged before delivery, a receipt fixes a future drand beacon round, the live sampling rate is 1 in 20, a proof takes about 58.8 s (facts register F23), and transcripts never appear on public screens. Llama 4 Maverick keeps its real commitment (F4) and 1,024-token window (F7). Other models, operators, prices, keys, hashes and signatures are sample values.

## Wiring real features in

Replace `app/data.js` with calls to the gateway, log, auditor and verifier. The screens read only what `window.Sample` exposes (`requests`, `challenges`, `stateOf`, `stage`, `heads`, `treeSize`, `on`), so that object is the seam.
