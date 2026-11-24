# Signature envelope

A signature envelope lets several people sign the same PDF in turn, with no server: the file goes from one to the
next (a shared folder, email), and **the PDF itself** says who signs, in which order, where on the page, and at which
level. The design is [ADR 0033](../adr/0033-pdf-signature-envelope.md).

It is written once, before the first signature, in one incremental update:

- **one signature field per signer**, `SimpleSign_1`, `SimpleSign_2`…, empty, with seed values (`/SV`: the time-stamp
  server, the certification asked of the first signer, the digests and reasons offered) and a lock (`/Lock`: once
  signed, every other field but the ones still to sign is locked);
- **the manifest**, `simplesign-envelope.json`, a file associated with the document (`/AF`, `/AFRelationship /Data`,
  `application/json`): the signers, their identifiers, roles, levels and order.

Any reader shows the fields; SimpleSign checks the rest: the signer's identity against the certificate, the turn, the
level, and that nothing was changed.

## The flow

```csharp
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Envelope;
using SimpleSign.PAdES.Signing;

// 1. Prepare: before any signature.
byte[] prepared = await PdfEnvelope.Prepare(pdf)
    .WithOrder(EnvelopeOrder.Sequential)
    .WithCertification(CertificationLevel.FormFilling)      // the first signer certifies (DocMDP P2)
    .WithTimestampUrl(new Uri("https://act.example/tsa"))  // in the seed values of the fields that need one
    .AddSigner(new EnvelopeSigner
    {
        Name = "Maria Silva",
        Identifiers = [new EnvelopeIdentifier(SignerIdentifierTypes.Cpf, "529.982.247-25")],
        Role = "Diretora",
        Level = IcpBrasilEnvelopeLevels.AdRt,
        Placement = new EnvelopePlacement(Page: 1, X: 72, Y: 72, Width: 200, Height: 50),
    })
    .AddSigner(new EnvelopeSigner
    {
        Name = "João Souza",
        Email = "joao@example.com",
        Identifiers = [new EnvelopeIdentifier(SignerIdentifierTypes.Email, "joao@example.com")],
        External = true,
        Level = EnvelopeLevel.PadesB,
        Placement = new EnvelopePlacement(1, 72, 140, 200, 50),
    })
    .PrepareAsync();

// 2. Where it stands, and who is next.
PdfEnvelopeInfo envelope = PdfEnvelopeReader.Read(prepared)!;   // Status, Fields, Next, Problems, Manifest

// 3. Before asking for the PIN: may this certificate sign this field now?
EnvelopeCheck check = PdfEnvelope.CheckSigner(prepared, "SimpleSign_1", certificate, IcpBrasilProfile.Create());
if (!check.Allowed) { /* check.Reason, check.Message, check.Identifiers[i].Match */ }

// 4. Sign the field: the same checks again, then the field's seed values and level.
byte[] signed = await PadesSigner.Document(prepared)
    .WithCertificate(certificate, chain)
    .WithProfile(IcpBrasilProfile.Create())                       // its readers read the CPF
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRt, new TimestampOptions(new Uri("https://act.example/tsa")))
    .AsCertification(CertificationLevel.FormFilling)              // the first field asks for it
    .WithEnvelopeField("SimpleSign_1")
    .SignAsync();

// 5. Validate the whole envelope.
PdfEnvelopeReport report = await new PdfEnvelopeValidator(new ValidationOptions { Profile = IcpBrasilProfile.Create() })
    .ValidateAsync(signed);
bool done = report.IsComplete;     // every field signed, valid, by its signer, at its level, in order
string json = report.ToJson();
```

`DeferredSignerBuilder.WithEnvelopeField` does the same for a two-phase signature: the checks run in `PrepareAsync`,
before the data to sign is given out.

## Who may sign a field

Each signer has identifiers: a type of `SignerIdentifierTypes` and a value. **Every** identifier must be read from the
certificate, by the identity readers of the profile (`TrustProfile.SignerIdentityReaders`: ICP-Brasil and Gov.br read
`CPF`, `CNPJ` and `RESPONSIBLE-CPF`) or by `DefaultSignerIdentityReader` (`EMAIL`, `SERIALNUMBER`,
`NATURAL-PERSON-ID`, `LEGAL-PERSON-ID`, `ORGANIZATIONIDENTIFIER`, `CERT-SHA256`).

| Match | Meaning |
|---|---|
| `Matched` | The certificate carries the value. |
| `Mismatch` | A reader knows the type and read another value, or none. |
| `NotVerifiable` | No reader of the profile knows the type (a CPF checked without the ICP-Brasil profile): **refused**. |

An identifier may accept other types: `new EnvelopeIdentifier("CPF", "…") { AlsoAccept = ["RESPONSIBLE-CPF"] }` lets
the person sign with the e-CNPJ they hold for a company. A signer for a company lists both: the person's CPF and the
company's CNPJ. Values are compared without case, and, but for an email, without dots, hyphens, slashes and spaces.

### Signers who sign outside their field

Some signers sign with a tool that makes its own signature field, such as the gov.br signer: it cannot sign
`SimpleSign_N`. Mark them with `SignsOutsideField = true` (no `Placement` needed; at least one identifier is):

```csharp
.AddSigner(new EnvelopeSigner
{
    Name = "Maria Silva",
    SignsOutsideField = true,
    Identifiers = [new EnvelopeIdentifier(SignerIdentifierTypes.Cpf, "52998224725")],
})
```

- Their field is still written, hidden and without size, so the names, the order and the other fields' locks stay the
  same; the manifest says `"signsOutsideField": true`.
- The reader counts as theirs the first signature, in the order they were made, outside the envelope's fields (not a
  document time-stamp, not already another signer's) whose certificate carries **every** identifier of theirs. Read
  with the profile's readers — `PdfEnvelopeReader.Read(pdf, profile.SignerIdentityReaders)` — to match a CPF;
  `Read(pdf)` uses `DefaultSignerIdentityReader` only. `EnvelopeFieldInfo.SignatureField` names the field that holds the
  signature.
- `CheckSigner` and `WithEnvelopeField` refuse their field with `EnvelopeFieldSignedOutside`; in a sequential envelope
  the next signer waits for the signature outside.
- The validator validates the signature found, with the same checks of identity, level and order.
- Certification and the document lock are refused when anyone signs outside their field: both forbid the new field.

## Levels

A level describes itself in the manifest, so checking it needs no package of the framework that defined it. It is
**checked, never applied**: the signature is configured as usual, and what falls short is refused.

| Id | Where | Asks for |
|---|---|---|
| `any` | `EnvelopeLevel.Any` | nothing |
| `pades-b` / `pades-t` / `pades-lt` / `pades-lta` | `EnvelopeLevel.PadesB`… | that baseline level |
| `icp-ad-rb` | `IcpBrasilEnvelopeLevels.AdRb` | `PBAD.PAdES`, the PAdES AD-RB policy |
| `icp-ad-rt` | `IcpBrasilEnvelopeLevels.AdRt` | `PBAD.PAdES`, the PAdES AD-RT policy, a signature time-stamp |

## Errors

`SigningException.Reason` says why a field may not be signed:

| Reason | When |
|---|---|
| `EnvelopeFieldNotFound` (29) | No envelope, or no such field in it. |
| `EnvelopeFieldAlreadySigned` (30) | The field is signed. |
| `UnexpectedSigner` (31) | An identifier does not match, or cannot be verified. |
| `NotYourTurn` (32) | Sequential order: a field before this one is not signed. |
| `TimestampRequired` (33) | The level or the field's seed values need a signature time-stamp. |
| `SeedValueViolated` (34) | The field asks for a certification the signature does not make, or a digest it does not use. |
| `LevelNotMet` (35) | Below the baseline level, another SubFilter, or another signature policy. |
| `EnvelopeTampered` (36) | The fields and the manifest disagree, or the manifest changed after the first signature. |

Preparing refuses a signed, certified, encrypted, PDF/A-1 or PDF/A-4 (but A-4e) document, or one that already holds an
envelope (`DocumentNotSignable`, `DocumentEncrypted`). A PDF/A-2 document is declared PDF/A-3 in its XMP.

## The manifest (version 1)

```json
{
  "version": 1,
  "id": "5b0c2d1e-…",
  "title": "Contrato de locação",
  "order": "sequential",
  "preparedAt": "2026-11-23T12:00:00Z",
  "signers": [
    {
      "field": "SimpleSign_1",
      "name": "Maria Silva",
      "role": "Diretora",
      "external": false,
      "identifiers": [{ "type": "CPF", "value": "529.982.247-25" }],
      "level": { "id": "icp-ad-rt", "baseline": "B-T", "timestamp": true,
                 "subFilters": ["PBAD.PAdES"], "policyOids": ["2.16.76.1.7.1.12.1", "…"] }
    }
  ]
}
```

`EnvelopeManifest.ToJson()` and `EnvelopeManifest.Parse(json)` write and read it. `title` is optional
(`PdfEnvelopeBuilder.WithTitle`): the name shown to people, covered by the first signature like the rest of the
manifest.

## The validation report

`PdfEnvelopeReport.ToJson()`, for a log or another program (the desktop app's sidecar reads it):

```json
{
  "id": "5b0c2d1e-…",
  "status": "Completed",
  "isComplete": true,
  "orderRespected": true,
  "manifestUnchanged": true,
  "missingFields": [],
  "problems": [],
  "signatures": [
    {
      "field": "SimpleSign_1",
      "signer": "Maria Silva",
      "isSigned": true,
      "indication": "Valid",
      "signerCertificate": "CN=MARIA SILVA:52998224725, …",
      "signingTime": "2026-11-23T12:05:00+00:00",
      "signerMatches": true,
      "identifiers": [{ "type": "CPF", "value": "529.982.247-25", "match": "Matched" }],
      "level": "icp-ad-rt",
      "reachedLevel": "B-T",
      "levelMet": true,
      "levelProblems": [],
      "inOrder": true,
      "isComplete": true
    }
  ]
}
```

## Tampering

Nothing protects the manifest or the fields before the first signature: the reader reports a field missing, added or
renamed, or a lock that is not the envelope's, as `Inconsistent`, and signing refuses with `EnvelopeTampered`. From the
first signature on, the manifest of the revision it signed is compared with the current one, and validation reports a
field removed or changed as a modification after the signature.

## CLI and TestBench

```bash
simplesign envelope prepare contract.pdf -o prepared.pdf --certify form-filling \
  --signer "name=Maria Silva;id=CPF:52998224725;role=Diretora;level=icp-ad-rt;page=1;rect=72,72,200,50" \
  --signer "name=João Souza;id=EMAIL:joao@example.com;level=pades-b;page=1;rect=72,140,200,50;external"
simplesign envelope status prepared.pdf
simplesign sign prepared.pdf --cert maria.pfx --profile icp-brasil --envelope-field SimpleSign_1 --certify form-filling -o signed1.pdf
simplesign validate signed2.pdf --envelope --profile icp-brasil --json
```

The levels of a framework (`icp-ad-rb`, `icp-ad-rt`) come with its CLI extension (`ICliExtension.EnvelopeLevels`). The
TestBench has an Envelope tab: prepare, sign each field with the Sandbox's certificates, download every stage, validate.
