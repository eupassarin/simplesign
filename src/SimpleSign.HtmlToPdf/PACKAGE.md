# SimpleSign.HtmlToPdf

Dependency-free HTML → PDF for .NET. A managed layout engine for documents — contracts, reports,
invoices, editor content — with no browser or native runtime, AOT-friendly.

- CSS cascade with complex selectors, `!important`, `var()`, `@media print`, `@page`, `@font-face`
- Block/inline flow, floats, positioning, inline-block, flexbox, grid, lists, justification
- Tables with content-based column sizing, colspan/rowspan, collapsed borders, and pagination that
  repeats `<thead>` on every page
- Embedded, subset TrueType/OpenType fonts with Unicode text extraction, per-glyph fallback, and
  synthesized bold/italic
- Backgrounds, gradients, opacity, shadows, transforms, `calc()`, CSS counters, `@page` margin
  boxes (page numbers), and multi-column layout
- SVG (inline, `<img>`, backgrounds) drawn as vector graphics
- OpenType shaping (kerning, ligatures, Arabic, Devanagari), right-to-left text, and hyphenation
- PNG (incl. alpha), JPEG and SVG images from data URIs, a base directory, or your own loader
- PDF/A-2b output for archiving and long-term signatures

## Quickstart

```csharp
using SimpleSign.HtmlToPdf;

byte[] pdf = await HtmlToPdfConverter
    .Html("<h1>Hello, SimpleSign</h1><p>A paragraph of text.</p>")
    .WithFooter("Page {page} of {pages}")
    .ConvertAsync();
File.WriteAllBytes("output.pdf", pdf);

// Unicode text: register fonts (regular + bold) and use them from CSS.
byte[] unicodePdf = HtmlToPdfConverter
    .Html("<p class='u'>Olá — Καλημέρα — <b>Привет</b></p>")
    .WithFontFile("Noto Sans", "fonts/NotoSans-Regular.ttf")
    .WithFontFile("Noto Sans", "fonts/NotoSans-Bold.ttf", FontVariant.Bold)
    .WithStylesheet(".u { font-family: 'Noto Sans', sans-serif; }")
    .WithPdfA()
    .Convert();
```

Relative images/stylesheets are only read when you opt in with `WithBaseDirectory(...)` or
`WithResourceLoader(...)`; the library never accesses the network on its own.

More (CSS support matrix, fonts, PDF/A, CLI) at
[github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign) and the
[docs](https://github.com/eupassarin/SimpleSign/tree/main/docs/articles). MIT licensed.
