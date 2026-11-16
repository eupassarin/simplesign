# Interop source documents

Two one-revision PDFs with three empty pages, made by qpdf so that `qpdf --check` finds nothing in them before
SimpleSign signs them:

| File | Cross-reference | Made with |
|---|---|---|
| `xref-table.pdf` | classic table (ISO 32000 §7.5.4) | `qpdf --deterministic-id --object-streams=disable in.pdf xref-table.pdf` |
| `xref-stream.pdf` | stream, pages in an object stream (§7.5.7, §7.5.8) | `qpdf --deterministic-id --object-streams=generate in.pdf xref-stream.pdf` |

`in.pdf` is `TestPdfFactory.CreateThreePagePdf()` written to a file. qpdf repairs it on the way (its `startxref` is
off and its pages have no `/Resources`).
