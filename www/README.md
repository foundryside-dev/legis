# Legis — landing site

Static landing page for **Legis**, the Weft Federation's governance surface
(git/CI governance & attestations · violet thread). Modeled faithfully on the
federation hub site at `~/weft/www/` — terminal-grade, warm-espresso "Loom"
palette, JetBrains Mono as the product face with Space Grotesk reserved for brand
moments (the wordmark, the hero, the cell names). Hand-rolled HTML/CSS/JS, no
build step, no runtime dependencies, no CDN. GitHub-Pages-deployable as-is.

This is the **landing page for one product**, not a second documentation build.
The hub already documents Legis in MkDocs; this site presents what Legis is, its
role in the federation, and how it engages each sibling, and links out to the
authoritative repo / hub docs rather than duplicating them.

## Files

| File | Purpose |
|---|---|
| `index.html` | The page: header (violet Legis mark + `~/legis` path-hint, sticky nav), hero (the question Legis answers + the operating axiom + a dated stat strip), **what Legis is** (the four artifacts it owns + "what Legis is not"), the **governance 2×2** centerpiece (four static cells + an additive filter), **federation engagement** (per-sibling bindings + the combination matrix), and **security & honesty** (tamper-*evident* definition, the residual tiers, both published reviews). Content-complete server-side. |
| `colors_and_type.css` | **Token source of truth, copied verbatim from the hub** (`~/weft/www/`). The warm-espresso "Loom" palette — surfaces, text, the amber `--accent`, the per-member thread palette (`--thread-legis: #B79BF2`), the `.thread-*` helpers, radii, type roles, the documented `[data-theme="light"]` theme. Not edited; re-copy on a design-system update rather than editing tokens here. |
| `styles.css` | Layout + components, layered on the tokens. Reuses the hub's component grammar (header, hero, `.axiom`, the stat strip, `.tag` chips, `.bindings`, footer) verbatim and adds the single-product sections (the 2×2 cell grid, the federation bindings, the security list). |
| `main.js` | Progressive enhancement only: the 2×2 cell filter (additive dimming + ARIA-tablist keyboard nav). No content depends on it. |
| `fonts/` | JetBrains Mono (upright + italic) and Space Grotesk variable TTFs + their OFL licenses. Bundled locally — fully offline, no CDN. Preloaded before first paint. |
| `assets/marks/` | The federation glyphs Legis references — `legis` (primary, violet), the four siblings it engages (`loomweave` · `filigree` · `wardline` · `charter`), plus `weft` and `foundryside` for the footer. Marks are also inlined in `index.html` so they inherit their thread colour via `currentColor`. |
| `.nojekyll` | Serve files verbatim on GitHub Pages (no Jekyll processing). |

## Preview locally

```
python3 -m http.server 8000
```

Then open `http://localhost:8000/`. Use `localhost` (not `file://`) so the
preloaded fonts resolve under a normal origin.

## Design fidelity & deliberate decisions

- **Tokens + fonts copied verbatim.** `colors_and_type.css`, the `fonts/`, and
  the mark SVGs are byte-for-byte copies of the hub's; nothing was regenerated.
  Re-copy them on a design-system update rather than editing here.
- **Dark only.** Warm espresso is the canonical theme and the hub ships no theme
  toggle, so none is added here (the tokens *do* define a full light theme under
  `[data-theme="light"]` if one is wanted later).
- **Violet brand, amber interaction.** Legis paints violet (`--thread-legis`) on
  its glyph, left-rules, cell names, and member identity — but per the token
  system's rule (colour means status / severity / member, never decoration), the
  interactive accent stays amber (`--accent`): links, focus rings, the active
  filter pill, and the graded-enforcement primitive callout.
- **The 2×2 is content-complete with JS off.** All four cells render in a real
  static grid with their full README descriptions; `main.js` only adds an
  *additive* filter that dims the non-matching cells. Disable JavaScript and all
  four cells are simply always shown — nothing is hidden behind the toggle.
- **Version string — dated snapshot, not a bare version.** The page is shown at
  the **`1.0.0`** release line, which is Legis's own authoritative
  self-description (`README.md`: "Legis is at 1.0.0 — the gold release") and
  matches the hub's member card. It is stamped **"snapshot 2026-06-11 — see
  repo/CHANGELOG for the live state."** That qualifier is load-bearing: the gold
  `1.0.0` was cut after a P0 honesty false-green (G1) re-opened the release on
  2026-06-10, so the date-stamp points at the build state the CHANGELOG records
  rather than asserting a frozen claim. Mirrors how every federation doc dates
  its snapshots and how the hub README documented its own 1.0.0-vs-rc choice. The
  page never asserts a bare, unqualified version.
- **Honesty guardrails kept intact.** "Tamper-*evident*," never "tamper-proof" —
  with the README's exact framing that the HMAC layer is intra-suite
  tamper-evidence (self-asserted actor, same-process Python verification), not
  third-party-verifiable proof. The residual tiers (coached-cell
  model-robustness wall, raw-DB-file-write, durability, response-integrity-rests-
  on-TLS) are named, and **both** pre-1.0 adversarial reviews are linked.
- **Defers to the hub for federation-level claims.** The page presents Legis's
  *role* and bindings but cites the hub (`federation-map.md`,
  `contracts-index.md`, `sei-standard.md`, `doctrine.md`) as the authority rather
  than re-deriving the federation rules — mirroring how the Legis `README.md`
  cites `~/weft/doctrine.md` instead of restating the roster/axiom.
- **No theme-flash / font-flash.** Both brand faces are `<link rel="preload">`-ed
  before first paint.

## Links

- **Nav + footer** link to the Legis repo (`github.com/foundryside-dev/legis`)
  and out to the hub's authoritative federation docs.
- **The two security reviews** link to repo-relative blobs under
  `foundryside-dev/legis/blob/main/docs/`.
- **Federation citations** (federation-map, contracts-index, SEI standard,
  doctrine) link to blobs under `foundryside-dev/weft/blob/main/`.
- External links carry an `↗` affordance and open in a new tab.

## Notes

- Content-complete with JavaScript disabled: every section, all four 2×2 cells,
  and every link work with JS off. JS only adds the cell filter and its keyboard
  navigation.
