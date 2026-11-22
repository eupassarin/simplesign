# ADR 0032: A PDF Object Model for Reading and Incremental Writing

**Status:** Proposed. Becomes Accepted when the last step of the migration below removes the scanning code.

**Context:**
ADR 0005 chose to write our own PDF code, and that stays. How that code works is what this ADR changes. `SimpleSign.PAdES`
has no object model: it reads a PDF by scanning raw bytes for literal tokens and writes one by splicing text.

- **Three ways to find an object.** They do not agree with each other:
  - `PdfStructureParser.FindObjectBytes` takes the last `N 0 obj` text match and ignores the cross-reference table;
  - `PdfObjectIndex` scans every `obj` keyword in a Latin-1 copy of the file;
  - the cross-reference reader in `PdfStructureReader.CrossReference` is a third.

  An object that no cross-reference section points to, appended at the end of the file, wins over the real one.
- **Assumptions written as text searches:**
  - the generation number is always 0;
  - page *n* is looked up only in the root's `/Kids`;
  - the DocMDP level is the first `/P ` within 2 KB after `/TransformMethod /DocMDP`, which a widget's `/P n 0 R` can
    shadow;
  - an empty signature field must contain the literal `/FT /Sig` with its space, and the oldest copy of the field is
    the one found;
  - trailer values come from `LastIndexOf` over the whole file;
  - patching a dictionary turns every CRLF of the object into LF, inside literal strings too.
- **Duplicated code.** The cross-reference writers exist in two copies, and the `/Prev` and next-object-number lookups
  in three.
- **Memory.** Several readers turn the whole file into a string, which takes twice the file's size.
- **The signature envelope needs what splicing cannot do safely.** The envelope (ADR 0033) is empty signature fields
  with seed values and locks, plus an associated file in `/AF` and `/Names /EmbeddedFiles`, all prepared before the
  first signature. It needs field trees with `/Kids`, name trees, catalog entries and per-revision reads.

**Decision:**

1. **An internal object model** in `src/Formats/SimpleSign.PAdES/Pdf/Model` (namespace `SimpleSign.PAdES.Pdf.Model`),
   with its writer in `Pdf/Writing`.
   - Parsed objects are immutable: `PdfNull`, `PdfBoolean`, `PdfInteger`, `PdfReal` (which keeps its source text),
     `PdfString` (literal or hexadecimal, as bytes), `PdfName`, `PdfArray`, `PdfDictionary` (ordered), `PdfStream`
     (its data a slice of the input, decoded on demand), `PdfReference` and `PdfIndirectObject`.
   - Each parsed object keeps the byte range it was read from, so a later edit can keep the original bytes.
   - The model is not public. ADR 0005 still holds that this is not a general-purpose PDF library. The public API
     (`PdfStructureReader`, `PdfSignatureWriter`, `DocTimeStampWriter`, `PdfEmbeddedFiles`, `IPdfStructureReader`)
     keeps its shape and calls into the model.
2. **Reading is tolerant, and records what it repaired.** These are repaired and recorded in a diagnostics list:
   - cross-reference offsets that miss their object (the object list is rebuilt from `N G obj` headers);
   - a missing `endobj`;
   - a wrong `/Length`;
   - stray tokens;
   - a hybrid file's `/XRefStm`;
   - `/Prev` loops;
   - linearized files.

   The public reader keeps the errors it raises today (`PdfStructureException`, `EncryptedPdfException`).
3. **Limits, and no recursion on input.**
   - The parser and every tree walk (pages, fields, name trees) use an explicit stack, a visited set and a depth limit.
   - `PdfReadLimits` holds today's constants: file size, cross-reference sections, nesting depth, reference hops,
     decoded stream size, object-stream budget and page count.
   - No regular expressions.
4. **Revisions come from the cross-reference sections.** A revision is a section of the `/Prev` chain; a linearized
   file's first-page section is merged into the main one. A view of a revision gives:
   - the catalog;
   - the full page tree, with inherited attributes;
   - the AcroForm and its field tree, with `/Lock` and `/SV`;
   - name trees, the DSS and the signature dictionaries.
5. **Writing keeps today's output.**
   - A serializer writes new objects in exactly the current layout.
   - A dictionary patch splices only the entries that change and keeps the rest of the bytes, CRLF included.
   - One incremental-update writer replaces the copies:
     - it numbers objects as each writer numbers them today;
     - it keeps the AcroForm's object number, since changing it made EU DSS reject earlier signatures;
     - it rewrites the catalog only where that happens today;
     - it chooses between a table and a stream as today;
     - it tracks the offsets of the `/ByteRange` and `/Contents` placeholders.

   The format of a deferred signing session does not change.
6. **The migration proves parity before anything old is removed.**
   - A harness in `tests/unit/Formats/SimpleSign.PAdES.Tests/Pdf/Parity` computes the same facts with the old code and
     with the model, over the committed fixtures and over generated documents, and fails on any difference that is not
     listed with a reason.
   - The writers are compared byte for byte, with a fixed clock and fixed signatures.
   - The steps, each its own pull request with CI green:
     1. objects, lexer, parser;
     2. filters;
     3. cross-reference, document, revisions, harness;
     4. revision views;
     5. readers: embedded files and the text locator;
     6. readers: DSS, DocMDP, encryption, PDF/A;
     7. readers: signature fields and inspection;
     8. readers: the revision comparer;
     9. the serializer and the incremental update;
     10. writers: document time-stamp;
     11. writers: LTV;
     12. writers: signing an existing field;
     13. writers: signing a new field;
     14. removing the old code.
7. **When the old code is removed.** All of these must hold:
   - no unexplained difference over the corpus;
   - the weekly external corpus and the interop and EU DSS jobs green twice in a row;
   - one preview release with the new writers;
   - the Interop, VeraPdf and EtsiChecker categories run green on the last writer step.

**Consequences:**

- **More correct reading:**
  - an object is found through the cross-reference;
  - generation numbers are honoured;
  - nested page and field trees are walked;
  - hybrid files are read in full;
  - a DSS that is inline or inside an object stream is found.
- **Less code and memory.** One implementation of each operation; no whole-file strings.
- **Some changes of behaviour are intended.** Each is listed in the harness and in the changelog of the release that
  removes the old code.
- **Two implementations live side by side during the migration.** Tests that assert internal heuristics of the
  scanning code are ported or removed in the last step.

**Alternatives considered:**

- *Keep scanning and build the envelope by splicing.* Editing field trees and name trees safely is not possible that
  way.
- *A third-party PDF library.* Rejected by ADR 0005.
- *A public object model.* Too large an API to document and keep stable; it can be considered later through narrow,
  read-only views.
- *Rewriting everything at once.* Nothing could be shown to behave the same.
- *A runtime switch for every step.* Only the writers get one (an `AppContext` switch), for one preview release.

**Follow-ups:**

- DocMDP `/P` absent means 2 (the standard's default), not 1.
- Fully qualified field names in `PdfSignatureField`.
- Whether signature dictionaries no field points to are still reported.
- Dense object-number allocation.
- ADR 0033, the signature envelope.
