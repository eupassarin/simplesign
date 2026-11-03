# HTML to PDF

`SimpleSign.HtmlToPdf` converts HTML + CSS into PDF with a managed layout engine. It has no
dependencies, needs no browser or native runtime, and is AOT-friendly. It targets **documents**
(contracts, reports, invoices, letters, CKEditor/TinyMCE content), not arbitrary web pages.

```bash
dotnet add package SimpleSign.HtmlToPdf
```

## Quickstart

```csharp
using SimpleSign.HtmlToPdf;

byte[] pdf = await HtmlToPdfConverter
    .Html("<h1>Contrato</h1><p>Texto do contrato.</p>")
    .WithFooter("Página {page} de {pages}")
    .ConvertAsync();
```

`<style>` blocks, `<link rel="stylesheet">`, `<title>` and `<html lang>` in the document are honored.
A stylesheet passed with `WithStylesheet` is applied **after** the document's own styles.

## Pages

Page size and margins come from CSS `@page`, unless the builder sets them explicitly:

```css
@page { size: A4 landscape; margin: 2cm 1.5cm; }
```

`size` accepts `A3`, `A4`, `A5`, `A6`, `B4`, `B5`, `letter`, `legal`, `ledger`, `tabloid`, explicit
lengths (`210mm 297mm`) and `portrait`/`landscape`. `WithPageSize`, `WithPageOrientation` and
`WithMargins` override `@page`.

Pagination follows the CSS fragmentation rules you would expect in print:

- `page-break-before/after/inside` and `break-before/after/inside` (`always`, `page`, `avoid`)
- `orphans` / `widows` (default 2) for paragraphs
- headings are kept with the content that follows them
- table rows (and rowspan groups) are never split; long tables continue on the next page and
  **repeat the `<thead>`**; `<tfoot>` is placed after the last row
- boxes that span pages repeat their background and side borders on every page
- `position: fixed` content is repeated on every page (watermarks, running labels)

## Fonts

The 14 standard PDF fonts (Helvetica, Times, Courier) are used by default; they cover Latin-1
(WinAnsi) only. For any other text, register TrueType/OpenType fonts:

```csharp
var pdf = HtmlToPdfConverter.Html(html)
    .WithFontFile("Noto Sans", "fonts/NotoSans-Regular.ttf")
    .WithFontFile("Noto Sans", "fonts/NotoSans-Bold.ttf", FontVariant.Bold)
    .WithFontFile("Noto Sans", "fonts/NotoSans-Italic.ttf", FontVariant.Italic)
    .WithStylesheet("body { font-family: 'Noto Sans', sans-serif; }")
    .Convert();
```

Or from CSS (data URIs, or files under the base directory):

```css
@font-face { font-family: "Noto Sans"; src: url(fonts/NotoSans-Regular.ttf); }
@font-face { font-family: "Noto Sans"; font-weight: bold; src: url(fonts/NotoSans-Bold.ttf); }
```

- Fonts are **subset**: only the glyphs used are embedded, and each font is written once per document.
- `font-family` lists are honored in order; unregistered names are skipped.
- Missing faces are synthesized: bold (stroke) and italic (slant) when only the regular face exists.
- **Per-glyph fallback**: characters missing from the chosen font are drawn with another registered
  font that has them (e.g. a symbols or CJK font), then with the standard fonts.
- Supported: TrueType outlines (`.ttf`) and non-CID OpenType/CFF (`.otf`). Not supported: `.ttc`,
  WOFF/WOFF2, CID-keyed CFF (use the `.ttf` builds of CJK fonts). No complex shaping or ligatures
  (Arabic, Indic scripts render unshaped).

## Images and other resources

`data:` URIs always work. For files and remote resources, opt in explicitly:

```csharp
HtmlToPdfConverter.Html(html)
    .WithBaseDirectory("templates/invoice")          // relative src/href/url() resolve here
    .WithResourceLoader(uri => uri.StartsWith("https://", StringComparison.Ordinal)
        ? httpClient.GetByteArrayAsync(uri).GetAwaiter().GetResult()
        : null)                                        // null = fall back to the base directory
    .Convert();
```

Files outside the base directory are never read, and the library itself never accesses the network.
PNG (all color types and bit depths, palette, interlaced, alpha via soft masks) and JPEG
(baseline/progressive, gray/RGB/CMYK) are supported. SVG, GIF and WebP fall back to the `alt` text.

## PDF/A

```csharp
byte[] archival = HtmlToPdfConverter.Html(html)
    .WithFontFile("Noto Sans", "NotoSans-Regular.ttf")
    .WithTitle("Contrato 42")
    .WithPdfA()          // PDF/A-2b
    .Convert();
```

`WithPdfA()` embeds an sRGB output intent and XMP metadata, writes a file identifier, and only uses
embedded fonts (conversion fails if no font is registered). This is the recommended input for
long-term PAdES signatures (`SimpleSign.PAdES`).

## CLI

```bash
simplesign html-to-pdf contrato.html -o contrato.pdf \
    --font "Noto Sans=fonts/NotoSans-Regular.ttf" --font "Noto Sans:bold=fonts/NotoSans-Bold.ttf" \
    --footer "Página {page} de {pages}" --pdfa
```

Relative images and stylesheets resolve against the input file's folder (`--base-dir` to change).

## CSS support

| Area | Supported |
|------|-----------|
| Selectors | type, `*`, `.class`, `#id`, `[attr]`, `[attr=v]`, `~=`, `\|=`, `^=`, `$=`, `*=` (with `i`), descendant, `>`, `+`, `~`, `:first-child`, `:last-child`, `:only-child`, `:nth-child()`, `:nth-last-child()`, `:first/last/only-of-type`, `:nth-of-type()`, `:not()`, `:root`, `:empty`, `:link`, `::before`, `::after` |
| Cascade | specificity, source order, `!important`, inline styles, inheritance, `inherit`, custom properties `var(--x, fallback)`, `currentColor`, `@media print`/`all` (screen ignored), `@supports` |
| At-rules | `@page` (size, margin, `:first`/`:left`/`:right`, margin boxes `@top-left`…`@bottom-right-corner` with `counter(page)`/`counter(pages)`), `@font-face`, `@media` |
| Box model | margin (incl. `auto` centering, collapsing), padding (incl. %), border (width/style/color per side; `solid`, `dashed`, `dotted`, `double`), `border-radius` (uniform), `box-sizing`, `width`/`min-width`/`max-width`, `height`/`min-height`/`max-height` |
| Display | `block`, `inline`, `inline-block`, `flex`, `grid`, `table` (and parts), `list-item`, `flow-root`, `none`; `visibility: hidden` |
| Positioning | `float` + `clear` (text wraps around floats), `position: relative/absolute/fixed` with offsets |
| Flexbox | `flex-direction`, `flex-wrap`, `flex-flow`, `flex-grow/shrink/basis`, `flex`, `gap`/`row-gap`/`column-gap`, `justify-content` (start, center, end, space-between/around/evenly), `align-items` |
| Grid | `grid-template-columns` (px, %, `fr`, `auto`, `repeat()`, `repeat(auto-fill, minmax())`), `gap`, `grid-column: span N` / `a / b`; automatic row placement |
| Tables | auto and fixed column sizing from content, `colspan`/`rowspan`, `<col>`/`<colgroup>` widths, `border-collapse`, `border-spacing`, `vertical-align`, `<caption>`, row/cell backgrounds, presentational attributes (`border`, `cellpadding`, `cellspacing`, `bgcolor`, `align`, `valign`, `width`) |
| Text | `font` shorthand, `font-family` lists, `font-size` (keywords, %, em, rem), `font-weight` (numeric), `font-style`, `color` (named, hex incl. alpha, `rgb()`, `hsl()`), `text-align` (incl. `justify`), `text-indent`, `line-height`, `letter-spacing`, `word-spacing`, `text-transform`, `text-decoration`, `white-space`, `word-break`, `overflow-wrap`, `vertical-align` (sub/super/middle), baseline alignment of mixed sizes, inline backgrounds |
| Lists | `list-style-type` (disc, circle, square, decimal, decimal-leading-zero, lower/upper-alpha, lower/upper-roman, lower-greek, strings, none), `list-style-position`, `<ol start reversed>`, `<li value>` |
| Units | `px`, `pt`, `pc`, `in`, `cm`, `mm`, `Q`, `em`, `rem`, `ex`, `ch`, `%`, `calc()`, `min()`, `max()`, `clamp()` (with percentages resolved at layout), negative lengths |
| Backgrounds | `background` shorthand and longhands, multiple layers, `url()` images (PNG, JPEG, SVG), `linear-gradient`, `radial-gradient`, `repeating-*`, translucent stops, `background-size` (`cover`, `contain`, lengths), `-position`, `-repeat`, `-origin`, `-clip`; root/body background fills the page |
| Effects | `opacity`, colors with alpha (real PDF transparency), `box-shadow` (outer, inset, blur, spread), `text-shadow`, `transform` (`translate`, `scale`, `rotate`, `skew`, `matrix`) with `transform-origin`, `mix-blend-mode`, `overflow: hidden` clipping |
| Generated content | `counter-reset`, `counter-increment`, `counter-set`, `counter()`, `counters()`, implicit `list-item` counter |
| Multi-column | `column-count`, `column-width`, `columns`, `column-gap`, `column-rule`, `column-span: all`; balanced columns that continue across pages |
| SVG | inline `<svg>`, `<img src="*.svg">` and SVG backgrounds as vector graphics: shapes, paths (incl. arcs), `g`, `use`/`symbol`, nested `svg`, `viewBox`/`preserveAspectRatio`, transforms, fill/stroke/opacity/dashes, linear and radial gradients, `clipPath`, text/`tspan`, embedded images, CSS classes from `<style>` |
| International text | OpenType shaping (GSUB/GPOS) for embedded fonts: kerning, ligatures, mark positioning, Arabic joining, basic Devanagari conjuncts (reph, half forms, pre-base matras); bidirectional text (`dir`, `direction`, `text-align: start/end`, number/punctuation ordering, bracket mirroring); hyphenation with `&shy;` and `hyphens: auto` for Portuguese and Spanish (`lang`); all HTML 4 named entities |


Not supported (by design or not yet): JavaScript, `writing-mode` (vertical text), conic gradients,
CSS filters, SVG masks/patterns/filters/markers, explicit bidi embeddings (`unicode-bidi`), cursive
attachment (Nastaliq) and Indic scripts other than Devanagari, `hyphens: auto` for other languages.
Complex scripts need a registered font that covers them (the standard PDF fonts are Latin only).

## Quality

The engine is covered by unit tests per feature, golden-layout snapshot tests (any geometry change
shows up as a diff; regenerate with `HTMLTOPDF_UPDATE_SNAPSHOTS=1`), randomized robustness tests,
and the `html`/`css` targets of the `SimpleSign.Fuzz` harness.
