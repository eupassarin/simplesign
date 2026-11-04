# ADR 0017: Managed HTML Layout and OpenType Shaping

**Status:** Accepted

**Context:**
`SimpleSign.HtmlToPdf` produces the documents that applications later sign: contracts,
reports, invoices and editor (CKEditor) content, often in Portuguese and sometimes in
Arabic, Hebrew or Indic scripts. The first version handled a narrow CSS subset with the
14 standard PDF fonts, so real documents lost tables, styling and non-Latin text.

Requirements:
- Run anywhere the signing library runs: no browser, no native libraries, Native AOT.
- Deterministic output with no network access; resources only from explicit sources.
- Archival output (PDF/A-2b) suitable for long-term signatures.
- Correct text for complex scripts and right-to-left languages.
- Safe on untrusted HTML, CSS, SVG and fonts.

**Decision:**
Implement the whole pipeline in managed code inside the package:

1. **CSS engine** — a selector parser/matcher, a full cascade (specificity, `!important`,
   custom properties) and computed styles. Percentages and `calc()` expressions are kept
   unresolved until layout knows the containing block (`CssLength`, `CssCalc`).
2. **Layout** — a block/inline formatting engine with floats, positioning, flexbox, grid,
   multi-column and paginated tables. Content that must be measured first (cells, flex
   items, inline-blocks, columns) is laid out by isolated sub-engines on an unbounded page
   and then fragmented across pages between leaf boxes.
3. **Rendering** — layout boxes become PDF content streams. Paint effects use native PDF
   features: shadings for gradients, ExtGState alpha and luminosity soft masks for
   transparency, `cm` for transforms, clipping paths for overflow. SVG is drawn as vectors
   by the same renderer.
4. **Fonts and shaping** — fonts are embedded as Type0/CIDFontType2 subsets with ToUnicode
   maps. A built-in OpenType engine (`TextShaper`, `LookupApplier`) applies GSUB and GPOS
   (single, multiple, ligature, contextual and chained substitutions; pair, mark and
   contextual positioning) with script rules for Arabic joining and Devanagari syllables.
   Its output is regression-tested against HarfBuzz reference results.
5. **Bidi and hyphenation** — word-level UAX #9 reordering per line, bracket mirroring,
   and rule-based syllable hyphenation for Portuguese and Spanish.
6. **Safety limits** — every recursive or repeating structure is bounded (nesting depth of
   at-rules, `:not()`, `calc()` and SVG; `use` expansions; tile, gradient-repeat and
   GSUB operation counts), and resource loading is sandboxed to a base directory or a
   caller-supplied loader.

**Consequences:**
- The package keeps zero dependencies and works under Native AOT on every supported OS.
- Rendering quality is close to browsers for document-style content, but not identical:
  no JavaScript, vertical writing modes, filters or CSS animations.
- Complex-script support covers Arabic and Devanagari; other Indic scripts, Nastaliq
  cursive attachment and explicit bidi embeddings are not modelled.
- The engine is a large surface to maintain; it is guarded by per-feature unit tests,
  golden layout snapshots, HarfBuzz comparison tests and the `html`/`css` fuzz targets.

**Alternatives considered:**
- **Headless Chromium (PuppeteerSharp/Playwright)** — best fidelity, but a ~150 MB
  native browser per platform, process management, no AOT, and network-capable by default.
- **wkhtmltopdf / native libraries** — unmaintained or native, breaking the pure-.NET goal.
- **HarfBuzz through P/Invoke for shaping** — reference-quality shaping, but adds native
  binaries for every runtime identifier and conflicts with the AOT and no-native-code goals.
- **Third-party .NET HTML renderers** — limited CSS support and licensing constraints for
  an MIT library.
