# ADR 0014: PDF/A Conformance Strategy

**Status:** Accepted

**Context:**
PDF/A (ISO 19005) is the ISO standard for long-term electronic document archiving. Conformance requires that:
- All fonts are embedded (ISO 19005-1 §6.3.4)
- The document is self-contained (no external dependencies)
- XMP metadata declares the PDF/A level and conformance
- Incremental updates preserve the original data and metadata
- Widget annotations have specific flags set (`/F` Print + Locked per ISO 19005-3 §6.3.2)
- Digital signatures use the correct SubFilter for the PDF/A version (PDF/A-1 forbids `ETSI.CAdES.detached`)

SimpleSign signs incrementally (appending objects, never modifying original bytes), which inherently preserves PDF/A metadata. However, the new objects it adds (signature dictionary, widget annotation, appearance stream, cross-reference table) must also conform.

**Decision:**
A four-layer conformance strategy covering detection, pre-signing validation, incremental update guarantees, and font embedding.

### 1. PDF/A level detection

`PdfStructureReader.DetectPdfALevel()` scans the raw PDF bytes for XMP metadata:

- Searches for `pdfaid:part` → extracts the part number (1, 2, 3, 4)
- Searches for `pdfaid:conformance` → extracts the conformance letter (A, B, U, E; B when absent)
- Reads both XMP forms of a property (ISO 16684-1 §7.9.2.2): the element `<pdfaid:part>3</pdfaid:part>` and the
  `rdf:Description` attribute `pdfaid:part="3"`. Only the element form was read until the veraPDF tests (§5) signed a
  corpus file written with attributes: it was taken for a document that is not PDF/A, so `WithPdfAPreservation()`
  checked nothing and the stamp got no `/DefaultRGB`.
- Maps `(part, conformance)` to the `PdfALevel` enum:

| Enum value | ISO 19005 part | Conformance |
|---|---|---|
| `None` | — | Not a PDF/A document |
| `A1a`, `A1b` | Part 1 | Level A (accessible) / Level B (basic visual) |
| `A2a`, `A2b`, `A2u` | Part 2 | A / B / U (Unicode text mapping) |
| `A3a`, `A3b`, `A3u` | Part 3 | A / B / U |
| `A4a`, `A4b`, `A4u`, `A4e` | Part 4 | A / B / U / E (embedded files) |
| `Unknown` | — | Detected but unrecognised level |

Detection is purely byte-level (text search for XMP properties in the raw bytes) — no XML parser is involved. This is sufficient for the conformance validation checks SimpleSign performs and avoids a parser dependency.

### 2. Pre-signing validation (`PdfAPreservationValidator`)

Before any PDF modification, `PdfAPreservationValidator` checks whether the requested signing options are compatible with the detected PDF/A level. Activated by `PadesSignerBuilder.WithPdfAPreservation()`.

**Check 1 — SubFilter (PDF/A-1 only):**

| Document level | `ETSI.CAdES.detached` | `adbe.pkcs7.detached` |
|---|---|---|
| PDF/A-1 (A1a, A1b) | ❌ Error (PDF/A-1 predates PAdES) | ✅ Allowed |
| PDF/A-2+ | ✅ Allowed | ✅ Allowed |

**Check 2 — PNG background transparency (PDF/A-1 only):**
PDF/A-1 forbids transparency. A visible signature with a PNG background image (which may contain transparency) is rejected with an error. JPEG is recommended for PDF/A-1.

**Check 3 — CMYK JPEG background (all levels, warning):**
A CMYK JPEG is embedded in DeviceCMYK, which ISO 19005-1 §6.2.3.3 and ISO 19005-2/3 §6.2.4.3 allow only with a CMYK
PDF/A OutputIntent or a `/DefaultCMYK`. The stamp maps DeviceRGB and DeviceGray to sRGB (§5) but has no CMYK profile to
embed. The check does not read the document's OutputIntents, and print-oriented PDF/A documents often have a CMYK one,
so it is a `Warning`, not an `Error`: `WithPdfAPreservation()` still signs, and logs the warning (event 1006,
`LogLevel.Warning`). Callers of `PdfAPreservationValidator.Validate` see it in the returned issues.

With `WithPdfAPreservation()`, errors refuse the signature and warnings are logged.

**Check 4 — Font (all levels):**
Base14 fonts (Helvetica, Times-Roman, Courier, etc.) are always allowed per ISO 19005. Non-standard font names are caught by the `GetBaseFontName()` normalisation guard.

### 3. Incremental update guarantees

Three mechanisms ensure the appended objects satisfy PDF/A requirements:

**3a. EOL before first new object (`EnsureTrailingEol`):**

```csharp
if (ms.Length > 0 && ms.GetBuffer()[ms.Length - 1] is not (byte)'\n' and not (byte)'\r')
    ms.WriteByte((byte)'\n');
```

Called by all three incremental writers (`PdfSignatureWriter`, `LtvEmbedder`, `DocTimeStampWriter`) before writing the first new object.

Satisfies ISO 32000 §7.3.10 (VeraPDF rule `spacingCompliesPDFA`).

**3b. Widget annotation `/F 132` (Print + Locked):**

Both `PdfSignatureWriter` and `DocTimeStampWriter` hardcode `/F 132` on every widget annotation:

| Flag | Value | Meaning |
|---|---|---|
| Print | 4 (bit 3) | Required by ISO 19005-3 §6.3.2 Test 2 for PDF/A-2/3 |
| Locked | 128 (bit 7) | Prevents user deletion of the widget |

This applies to both invisible (`/Rect [0 0 0 0]`) and visible widgets. Invisibility is conveyed by the missing `/AP` dictionary, not by clearing the Print flag.

**3c. Incremental save preserves XMP metadata:**
Because the original PDF bytes are never modified, the XMP metadata containing `pdfaid:part` and `pdfaid:conformance` remains intact and referenced by the existing cross-reference table. No XMP rewrite is needed.

### 4. Font embedding (PDF/A-1 §6.3.4)

PDF/A-1 requires all fonts to be embedded, including the standard 14. When a visible signature appearance is rendered using Helvetica (the typical case), SimpleSign embeds LiberationSans — a metric-compatible, OFL-licensed substitute.

**Font file:** `LiberationSans-subset.ttf` (embedded as assembly resource, WinAnsi subset)

**Font embedding workflow in `PdfSignatureWriter.PrepareAsync`:**

1. `FontResources` lazy-loads the TTF bytes, computes Widths array (1000 UPM per ISO 32000-1 §9.2.2, scaled from LiberationSans' native 2048 UPM), and provides font metrics
2. `PdfFontWriter.BuildFontFileObject()` — creates a `/FontFile2` object containing the TTF compressed with `ZLibStream` (RFC 1950 zlib wrapper, not raw `DeflateStream`)
3. `PdfFontWriter.BuildFontDescriptorObject()` — creates a `/FontDescriptor` referencing the FontFile2, with Ascent, Descent, CapHeight, FontBBox, Flags, StemV, ItalicAngle
4. `SignatureAppearanceRenderer.WrapInFormXObject*()` — references the embedded LiberationSans as `/Type /Font /Subtype /TrueType /BaseFont /LiberationSans`

Font embedding only activates when:
- A visible signature appearance is requested (`.WithAppearance(...)`)
- The appearance uses Helvetica (the default Base14 font)

For invisible signatures or non-Helvetica fonts, Type1 Base14 references are used — these do not require embedding per the PDF/A-1 spec (Base14 fonts are assumed available in conforming readers, but embedding is recommended).

### 5. Cross-platform verification

`tests/integration/SimpleSign.VeraPdf.Tests` signs the PDF/A-1b, 2b and 3b files of the veraPDF corpus and has
veraPDF (the `verapdf/cli` Docker image, pinned by digest in `VeraPdf.cs`, or a local CLI named by
`SIMPLESIGN_VERAPDF`) validate the result. The CI job `PDF/A (veraPDF)` runs it on every push, with
`SIMPLESIGN_REQUIRE_VERAPDF=true` so that a missing veraPDF fails instead of skipping; documents veraPDF rejects are
kept as a build artifact with its report.

| Test (`PadesSignerPdfAConformanceTests`) | Files | Must PASS veraPDF |
|---|---|---|
| `SignAsync_InvisibleSignature_PreservesConformance` | 2b, 3b | one invisible signature |
| `SignAsync_VisibleSignature_PreservesConformance` | all | one visible signature (appearance, embedded LiberationSans; adbe.pkcs7.detached on 1b) |
| `SignAsync_SecondSignature_PreservesConformance` | all | two visible signatures |
| `SignAsync_ArchiveLevel_PreservesConformance` | 2b, 3b | B-LTA: signature timestamp, DSS, document timestamp (TSA and CRLs answered in memory) |
| `SignAsync_WidgetWithoutPrintFlag_FailsConformance` | 3b | the control: with `/F 132` turned into `/F 128`, veraPDF must report §6.3.2 |

**Device colours in the appearance (gap found by these tests, fixed).** The appearance stream paints with `rg`/`RG`
(DeviceRGB). ISO 19005-2/3 §6.2.4.3 allows DeviceRGB only with an RGB PDF/A OutputIntent or a `/DefaultRGB` colour
space in the current resources (ISO 19005-1 §6.2.3.3 says the same for PDF/A-1), and DeviceGray only with an
OutputIntent or a `/DefaultGray`. A visible signature on a document with neither — the corpus file
`PDF_A-3b-6-8-t02-pass-b.pdf` — broke conformance (4 checks of §6.2.4.3).

When the document is PDF/A (any detected level, with or without `WithPdfAPreservation()`), the appearance form XObject
now carries `/ColorSpace << /DefaultRGB [/ICCBased n 0 R] >>`, backed by an sRGB ICC profile stream written in the same
incremental update; a grayscale background image adds `/DefaultGray` with a gray profile on the sRGB tone curve. The
content stream is unchanged, and a document that is not PDF/A gets the same bytes as before. Why this option:

- **It conforms whatever the OutputIntent.** A DefaultRGB is valid with an RGB OutputIntent, a CMYK one or none, so the
  signer does not need to parse `/OutputIntents` and their profile headers (often inside object streams). Adding it
  when an RGB OutputIntent already exists costs under 1 KB per signature and changes nothing visible: sRGB is what
  those intents almost always are.
- **The profiles are built in code** (`SrgbIccProfile`, ICC version 2.1, matrix/TRC: the IEC 61966-2-1 primaries
  adapted to D50 and the sRGB transfer function sampled at its 256 8-bit code values). No third-party `.icc` file is shipped, so there
  is no licence to carry; version 2.1 is readable by every PDF/A part (PDF/A-1 accepts profiles before version 4).
- **Rejected:** painting in DeviceGray when there is a Gray OutputIntent (needs OutputIntent parsing, and loses colour);
  explicit `[/ICCBased]` colour spaces with `cs`/`sc` (rewrites the content stream for every document, for the same
  result); refusing visible signatures on such documents (no reason to, since a conforming option exists).

Still open: a CMYK JPEG background image paints in DeviceCMYK, which §6.2.4.3 allows only with a CMYK OutputIntent or
a `/DefaultCMYK`. SimpleSign has no CMYK profile to embed (a usable one is large and licensed), so use an RGB or
grayscale image on PDF/A documents. `PdfAPreservationValidator` warns about it (§2, check 3).

`KnownVisibleFailures` in the tests stays, empty, for the next gap: an entry requires exactly the failure it names, so
the test fails once that gap is fixed and the entry can go.

To update veraPDF: pull `verapdf/cli:latest`, take its digest, change it in `VeraPdf.cs` and `.github/workflows/ci.yml`,
and run the tests.

### 6. API surface

Five layers: automatic PDF/A level detection (during validation), pre-signing validation (`.WithPdfAPreservation()`), widget flags (`/F 132` — always set), EOL guard (always applied), and automatic font embedding (for visible signatures).

CLI: `--preserve-pdf-a` flag
HostSigner: `preservePdfA` JSON config option

**Consequences:**
- PDF/A conformance is preserved through all signing operations — B-B, B-T, B-LT, and B-LTA
- No OutputIntent or ICCProfile management — existing color profiles are preserved via incremental save
- LiberationSans is subset to WinAnsi (smaller than the full TTF)
- ZLibStream (RFC 1950) is used for compression, not raw DeflateStream — matches PDF expectations for `/FlateDecode`
- Widths array in 1000 UPM (ISO 32000-1 §9.2.2), scaled from LiberationSans' native 2048 UPM
- PDF/A-1 documents require a visible signature appearance (to provide `/AP` dictionary) and `adbe.pkcs7.detached` SubFilter
- PDF/A-1 documents with PNG background are rejected — JPEG must be used instead
- The EOL guard is idempotent — already-terminated streams are unchanged
- Append-only mode means the first revision is never modified, so XMP metadata is always preserved

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **Fully embedded TrueType (LiberationSans, chosen)** | PDF/A-1 compliant, OFL-licensed | Binary size increase (subset TTF embedded) | **Chosen** |
| **Base14 Type1 references only** | No binary size increase | Non-compliant for PDF/A-1 (must embed) | Rejected |
| **Custom subtype font** | Full control | Reader compatibility risk | Rejected |
| **PNG-forced for PDF/A-1** | Simpler code path | Transparent PNG rejected by VeraPDF | Rejected |
| **Post-signing validation only** | No false positives | Signs document then fails — too late | Rejected |

**Status:** Accepted. The four-layer strategy (detect → validate → enforce → embed) is the canonical PDF/A conformance approach. All three writers (`PdfSignatureWriter`, `LtvEmbedder`, `DocTimeStampWriter`) are responsible for maintaining conformance for their respective incremental updates.
