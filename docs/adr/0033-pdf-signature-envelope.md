# ADR 0033: A Signature Envelope Inside the PDF

**Status:** Proposed (2026-11-23). Built in steps B1–B10; it becomes Accepted when the last of them, with the checks of
point 9, is merged.

**Context:**
The SimpleSign Desktop gets a company mode with no server: several people sign the same PDF, in order, and the file goes
from one to the next through a shared folder or by email. Nothing outside the file says who signs, in which order,
where on the page, or how strongly. The PDF has to carry that itself, from before the first signature to after the last,
in a form other tools leave alone and the people who receive it can check:

- each signer's place is a signature field that is there before anyone signs (ISO 32000-1 §12.7.4.5), because a field
  added after a signature is a change no certification allows and that validators report (`PdfRevisionComparer` counts
  it as undefined);
- the list of signers, their identities, their order and the level each must reach does not fit the PDF's own
  dictionaries, so it travels as a file associated with the document (ISO 32000-2 §14.13; PDF/A-3);
- anything a reader such as Acrobat can enforce goes into the field's seed values (`/SV`) and lock (`/Lock`), the rest is
  checked by SimpleSign.

ADR 0032 made this possible: the object model reads field trees, name trees and every revision, and writes incremental
updates that keep the bytes they do not change.

**Decision:**

1. **Prepared once, before any signature.** `PdfEnvelope.Prepare(pdf)…PrepareAsync()` writes one incremental update with
   every field and the manifest. A document that is signed, certified (DocMDP), encrypted, PDF/A-1, or already holds an
   envelope is refused (`DocumentNotSignable`, `DocumentEncrypted`). A PDF/A-2 or PDF/A-3 document is declared PDF/A-3
   in its XMP (`pdfaid:part` 3), as an associated file needs; nothing else of the XMP changes.
2. **One signature field per signer**, `SimpleSign_1`, `SimpleSign_2`…: a flat name, the field merged with its widget,
   no `/V`; `/F 4` (132, print and locked, outside PDF/A), the page and rectangle chosen when preparing, and an empty
   appearance stream (nothing drawn: no font, no colour space, safe for PDF/A; a reader marks the empty field itself).
   - `/SV` holds only what any reader understands:
     - `/TimeStamp << /URL … /Ff 1 >>` when the signer's level needs a signature time-stamp;
     - `/MDP << /P n >>`, on the first field only, when the first signature certifies;
     - `/Cert` with `/KeyUsage`, and `/OID` and `/Subject` when given;
     - `/DigestMethod`;
     - `/Reasons`, when given.
   - Never `/Filter` nor `/SubFilter`: ICP-Brasil signs with `/Filter /PBAD_PAdES /SubFilter /PBAD.PAdES`, and a reader
     that enforces the seed value would refuse it.
   - `/Lock << /Action /Exclude /Fields [the other SimpleSign_ fields] >>`, so a signature locks everything but the
     fields still to sign; `/P` (lock the document) only when asked for.
3. **The manifest, `simplesign-envelope.json`**, an associated file:
   - its file specification has `/F` and `/UF`, `/Desc`, and `/AFRelationship /Data`; it is in the catalog's `/AF` and in
     `/Names /EmbeddedFiles`;
   - the embedded file stream has `/Subtype /application#2Fjson`, `/Params << /Size /CreationDate /ModDate >>`, and
     `/FlateDecode`;
   - no `/CheckSum`: it is optional (ISO 32000-1 Table 46, PDF/A-3), it is an MD5, and it protects nothing before the
     first signature, which is what protects the manifest.
4. **Manifest version 1**, keys in English, written with System.Text.Json source generation (AOT):

   ```json
   {
     "version": 1,
     "id": "5b0c…",
     "order": "sequential",
     "preparedAt": "2026-11-23T12:00:00Z",
     "signers": [{
       "field": "SimpleSign_1",
       "name": "Maria Silva",
       "role": "Diretora",
       "email": "maria@empresa.com",
       "external": false,
       "identifiers": [
         { "type": "CPF", "value": "12345678909", "alsoAccept": ["RESPONSIBLE-CPF"] },
         { "type": "CNPJ", "value": "11222333000181" }
       ],
       "level": { "id": "icp-ad-rt", "baseline": "B-T", "timestamp": true,
                  "subFilters": ["PBAD.PAdES"], "policyOids": ["2.16.76.1.7.1.12.1.3"] }
     }]
   }
   ```

   - `order` is `sequential` or `parallel`.
   - An identifier's `type` is one of `SignerIdentifierTypes` (CPF, CNPJ, RESPONSIBLE-CPF, NATURAL-PERSON-ID,
     LEGAL-PERSON-ID, EMAIL, SERIALNUMBER, ORGANIZATIONIDENTIFIER, CERT-SHA256). No country prefix: a framework brings
     the readers of its own types (`ICountryExtension.SignerIdentityReaders`).
   - `email` is a contact. It is checked only when it is also among the `identifiers`.
   - The level describes itself: `baseline` (B-B, B-T, B-LT, B-LTA), whether a signature time-stamp is needed, and the
     SubFilters and signature policies accepted. Checking it needs no package of the framework that defined it. The ids
     are `any`, `pades-b`, `pades-t`, `pades-lt`, `pades-lta`, and those of a framework (`icp-ad-rb`, `icp-ad-rt` from
     `IcpBrasilEnvelopeLevels`).
5. **Who may sign a field.** Every identifier of the signer must be read from the certificate, by the readers of the
   profile and `DefaultSignerIdentityReader`: an identifier is matched by its own type or one of its `alsoAccept`. When no
   reader reads a type, the identifier is *not verifiable* and the signature is refused (`UnexpectedSigner`).
   `PdfEnvelope.CheckSignerAsync` answers this before the PIN is asked, identifier by identifier.
6. **Signing a field.** `WithEnvelopeField(name)` on `PadesSignerBuilder` and `DeferredSignerBuilder` signs that field and
   checks, before anything is signed:
   - the field (`EnvelopeFieldNotFound`, `EnvelopeFieldAlreadySigned`) and the turn (`NotYourTurn`, sequential order
     only);
   - the signer (`UnexpectedSigner`), the seed values (`TimestampRequired`, `SeedValueViolated`) and the level
     (`LevelNotMet`);
   - the manifest and the fields against each other (`EnvelopeTampered`).

   The level is not applied for the caller: the signature is configured as always (policy, time-stamp server…) and what
   falls short of the level is refused. The signer's role from the manifest is written in signer-attributes-v2 (ETSI
   EN 319 122-1 §5.2.6.1) unless the caller gives roles of their own. A field with a `/Lock` gets the matching FieldMDP
   reference (`/Reference [<< /TransformMethod /FieldMDP /TransformParams <</Action /Fields>> >>]`, §12.8.2.4), with the
   DocMDP one when the signature certifies.
7. **Reading and validating.** `PdfEnvelopeReader` gives the manifest, each field (page, rectangle, seed values, lock,
   whether signed, by whom, in which revision, the claimed roles), the next field to sign, and a status: `Prepared`,
   `InProgress`, `Completed` or `Inconsistent`. `PdfEnvelopeValidator` validates every signature as today and adds, per
   field, whether the signer matched, the seed values held, the level was met and the order was kept, and for the
   envelope whether a field is missing and the manifest is unchanged; its report serializes to JSON.
8. **Tampering.**
   - Before the first signature nothing protects the manifest or the fields: the reader reports a field missing or added,
     or seed values or a lock that differ from the manifest, as `Inconsistent`, and signing refuses with
     `EnvelopeTampered`.
   - From the first signature on, the manifest of the revision it signed is compared with the current one, and the
     revision comparer reports a field removed.
9. **Checked outside the library before this ADR is accepted:**
   - Adobe Reader shows the fields, its enforcement of `/SV` does not refuse an ICP-Brasil (PBAD) signature, and a
     certification with DocMDP P2 shows the later signatures as allowed;
   - ITI's VALIDAR accepts an ICP-Brasil signature with signer-attributes-v2. If it does not, ICP-Brasil levels leave
     the role out;
   - qpdf, pyHanko and veraPDF (the Interop and VeraPdf categories) accept prepared and signed envelopes.

**Consequences:**

- `SimpleSign.PAdES` gains a public namespace, `SimpleSign.PAdES.Envelope`. Only the frameworks' levels live outside it
  (`IcpBrasilEnvelopeLevels`).
- `PdfEmbeddedFiles.Read` reports what the envelope reader needs: whether a file is associated (`/AF`), its relationship,
  description, media type, size and dates.
- The writer of an existing field writes a FieldMDP reference when the field has a `/Lock`. A field without one is
  signed as before, byte for byte.
- `SigningErrorReason` 29–36 (already public) are raised.
- The CLI gets `simplesign envelope prepare|status`, `sign --envelope-field` and `validate --envelope` (with the trust
  options of `validate`). A framework's levels reach it through its extension (`ICliExtension.EnvelopeLevels`), so the
  CLI still references no framework (ADR 0030). The TestBench gets an Envelope tab.

**Alternatives considered:**

- *Splicing text, before the object model.* Rejected: see ADR 0032.
- *The manifest in the XMP, or in a dictionary of our own in the catalog.* Other tools drop or rewrite the XMP, and a
  private dictionary is a change validators do not know. An associated file is the place PDF 2.0 and PDF/A-3 give data
  that belongs to the document.
- *Signing the manifest separately (a CMS of its own).* That needs a key for whoever prepares it, and the first signature
  already covers it.
- *Fixed `cpf` and `cnpj` keys.* They tie the format to Brazil; identifiers by type let any framework take part.
- *Applying the level automatically.* It hides which time-stamp server and policy were used; refusing what falls short
  keeps the caller in charge.
- *Seed values for everything (`/SubFilter`, `/Filter`).* They would make Acrobat refuse ICP-Brasil signatures.

**Follow-ups:**

- A reserved page for a completion report.
- A TestBench playbook for the envelope (its steps and the evidence of each refusal).
- Identity readers for Peru (DNI, RUC).
- DocMDP `/P` absent read as 2 (ADR 0032).
