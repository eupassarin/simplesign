# veraPDF corpus files

PDF/A documents that veraPDF reports as compliant ("pass" files). The tests sign them with SimpleSign and check that
veraPDF still reports them compliant.

| File | Flavour |
|---|---|
| `PDF_A-1b-6-4-t01-pass-a.pdf`, `PDF_A-1b-6-5-3-t01-pass-a.pdf` | PDF/A-1b |
| `PDF_A-2b-6-1-2-t02-pass-a.pdf`, `PDF_A-2b-6-1-3-t01-pass-a.pdf`, `PDF_A-2b-6-1-5-t01-pass-a.pdf`, `PDF_A-2b-6-2-3-t01-pass-a.pdf`, `PDF_A-2b-6-2-10-t01-pass-a.pdf`, `PDF_A-2b-6-3-2-t01-pass-a.pdf`, `PDF_A-2b-6-3-3-t01-pass-a.pdf` | PDF/A-2b |
| `PDF_A-3b-6-8-t02-pass-a.pdf`, `PDF_A-3b-6-8-t02-pass-b.pdf` | PDF/A-3b |

The flavour comes from the file name (`PDF_A-<part><level>-…`), so a new file needs no code change.

Source: [veraPDF-corpus](https://github.com/veraPDF/veraPDF-corpus) (branch `staging`), by the veraPDF Consortium,
licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The files are unchanged.
