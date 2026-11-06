# ADR 0005: Custom PDF Parser (No Third-Party PDF Library)

**Status:** Accepted (permanent)

**Context:**
PDF digital signatures require precise byte-level control over the PDF structure — reading cross-reference tables, parsing objects, computing byte ranges, and performing incremental saves. Established .NET PDF libraries include:

- **iText** (AGPL/commercial) — full PDF manipulation, market leader, but AGPL license requires open-sourcing or a commercial license
- **PdfPig** (MIT) — read-only parser, no incremental save support needed for signing
- **Docotic.Pdf** (commercial) — full feature set, paid license
- **Aspose.PDF** (commercial) — heavy dependency, paid license

No existing MIT-licensed library provided both reading and incremental save capabilities with the byte-fidelity required for PAdES signing.

**Decision:**
Build `SimpleSign.Pdf` — a custom, minimal PDF parser written entirely in C# with zero third-party dependencies. It handles exactly what PAdES signing needs:

- Cross-reference tables (classic and streams)
- Object parsing (dictionaries, arrays, strings, names, streams)
- Byte-range tracking
- Incremental updates (append-only, preserving original bytes)
- XRef stream reconstruction
- Object streams (ObjStm) decompression

It does **not** attempt to be a general-purpose PDF library — no rendering, no content stream parsing, no form filling.

**Consequences:**

- Full control over byte-level operations (critical for `ByteRange` integrity)
- MIT-licensed, no license restrictions for any use case
- Native AOT compatible (no reflection, no risky dependencies)
- Smaller deployment footprint (minimal dependency, no third-party PDF library inclusion)
- No CVE surface from third-party PDF libraries
- Significant development investment (a dedicated parser project)
- Must maintain parser correctness across PDF versions (1.0 through 2.0)
- Edge cases from real-world PDFs require ongoing fixes (legacy Adobe, iText, Word, LibreOffice)
- New PDF features require manual implementation

**Alternatives considered:**

| Library | Cost | Read | Incremental Save | AOT Safe | Verdict |
|---------|------|------|-------------------|----------|---------|
| iText 7/9 | AGPL/$$$ | Yes | Yes | No (reflection) | License incompatible with MIT |
| PdfPig 2.x | MIT | Yes | No (read-only) | No (reflection) | Cannot sign |
| Docotic.Pdf | $$$ | Yes | Yes | Unknown | Commercial license required |
| Aspose.PDF | $$$ | Yes | Yes | No | Commercial + heavy |
| **SimpleSign.Pdf** | **MIT** | **Yes** | **Yes** | **Yes** | **Chosen** |

**Status:** This decision is permanent. No third-party PDF library dependency will be added.

**Update (v0.11):** the parser is no longer a separate package. It lives in `SimpleSign.PAdES` under `Pdf/`, namespace `SimpleSign.PAdES.Pdf`. See ADR 0018.
