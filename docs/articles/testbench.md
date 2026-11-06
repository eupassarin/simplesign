# SimpleSign TestBench

The TestBench is a local web app for trying **every PDF signing option** of the library, with
an explanation next to each one. It never shows options that cannot be combined: the rules live
in one place (`Signing/Compatibility.cs`), and the UI, the runner and the run matrix all use them.

```bash
dotnet run --project src/Apps/SimpleSign.TestBench          # http://127.0.0.1:5199, opens the browser
dotnet run --project src/Apps/SimpleSign.TestBench -- --port 5200 --no-browser
```

The UI is in **English (en-US), Portuguese (pt-BR) and Spanish (es)**: it follows the browser's
language, and the selector in the top bar overrides it (saved in the browser). The server's
explanations, compatibility messages and sample descriptions follow the same choice
(`Accept-Language`). Library names, OIDs, standard terms and the generated code stay as they are.

The first run builds the UI (Node.js 20+ needed; `npm ci && npm run build` in
`src/Apps/SimpleSign.TestBench/web`). To work on the UI with hot reload, run the app and, in another
terminal, `npm run dev` in `web/` (Vite on :5173, proxying `/api` to :5199). The app listens on
127.0.0.1 only. Uploads, keys and token sessions stay in memory and are gone when it stops.

## Sandbox and Real

| | Sandbox | Real |
|---|---|---|
| Certificates | Test PKI (*AC Raiz Sandbox SimpleSign*): RSA 2048/3072/4096, ECDSA P-256/384/521, e-CNPJ, expired, not yet valid, revoked, no nonRepudiation | Your PFX, the OS store, A3 tokens (PKCS#11), real PSC/CSC accounts |
| Timestamp | Offline RFC 3161 TSA, plus one that requires HTTP Basic | DigiCert, Sectigo, FreeTSA or any URL (http, https, tcp), with Basic/Bearer and mTLS |
| Revocation | CRLs of both sandbox CAs | The certificates' real CRL/OCSP |
| Cloud | Simulated ICP-Brasil PSC (OAuth + PKCE, CPF + OTP) and CSC v2 service (PIN/OTP, SCAL 1/2, OAuth); login pages are approved automatically | Your provider; OAuth opens the system browser |
| Validation | Trusts the sandbox root | Trusts the OS roots and the ICP-Brasil roots |

Sandbox services answer on `*.sandbox.simplesign.test` through an in-process
`IHttpClientProvider`, so the library runs its normal code paths without the network. The
*Sandbox* page lists the certificates, the services and every request they answered.

## Signing, step by step

1. **Document**: samples (plain, empty signature field, already signed, certified P=1/2/3, PDF/A-2b,
   PDF/A-1b) or your upload. Its facts (DocMDP, existing signatures, empty fields, PDF/A) decide
   what the next steps offer.
2. **Signer**: sandbox A1, PFX, OS store, A3 token, PSC or CSC v2. The card shows what the key can
   produce (digests, RSA schemes).
3. **Signature type**: PAdES baseline (B-B…B-LTA), an ICP-Brasil policy (AD-RB, AD-RT, AD-RC,
   AD-RA, any version, with its signing period and accepted roots), or a custom policy. The TSA,
   archive TSA and failure behavior appear only when needed.
4. **Cryptography**: digest, RSA PKCS#1 v1.5 or PSS, sub-filter, PDF/A preservation, `/Contents` size.
5. **Field & appearance**: new or existing field; a visible stamp with a live preview (a real B-B
   signature of a throwaway copy, rendered with pdf.js; click the page to place it), text, date,
   colors, Base14 font, QR code and background image.
6. **Details**: reason, location, contact, claimed signing time, signer metadata or AEA (Lei
   14.063), certification (DocMDP), health documents, document information, operation id.
7. **Mode**: sign now, deferred (prepare → sign the signed attributes → complete) or batch.

The result shows the requested and achieved level, the validation report (`PdfSignatureValidator`
+ `BrasilExtension`), what the output contains (DSS, document timestamp, DocMDP), and a **Code**
tab with the exact C# builder calls and the equivalent `simplesign sign` command. Secrets are
never printed. **Validate in Validation** opens the signed file on the Validation page.

## Validation

The *Validation* page has three tabs, all using the settings on the left: trust anchors (sandbox
root, OS roots, ICP-Brasil, uploaded roots), revocation checking,
network timeout and the ICP-Brasil extension.

- **Validate**: `PdfSignatureValidator` (+ `BrasilExtension`). Per signature: the checks, PAdES
  level, Lei 14.063 level, policy, signer certificate and the certificates in the CMS, the
  signature timestamp, which part of the file the ByteRange covers, and the signed attributes;
  plus the DSS and the C#/CLI code.
- **Bulk**: `BulkValidator` over many PDFs with a chosen concurrency; one row per file.
- **Inspect**: `PdfStructureDumper` (signature dictionaries, DSS, VRI, each entry explained) and
  the CMS of each signature for download (`PadesExtractor`).

Samples built at startup in the sandbox show each kind of result:

| Sample | Expected |
|---|---|
| Valid B-LT (control) | Valid |
| Content changed after signing | Invalid (integrity) |
| Signature value changed | Invalid (signature) |
| Bytes appended after signing | Valid, with "ByteRange does not cover entire PDF" |
| Revoked signer (B-B) | Invalid (revocation) |
| Expired signer | Indeterminate (chain) |
| Root outside the trust anchors | Indeterminate (chain) |
| Untrusted TSA | Valid, with a TSA chain warning |

## CAdES

The *CAdES* page signs any file with `CadesSigner` and validates with `CadesSignatureValidator`.

- **Operation**: sign, co-sign (`CoSign`: another signer of the same content) or countersign
  (`CounterSign`: a signature over one signer's signature value). The result offers *Co-sign this*
  and *Countersign this* to build multi-signer files step by step.
- **Content**: detached (.p7s) or enveloped (.p7m). A co-signature keeps the existing content type;
  co-signing a detached signature needs the same data (the message digest is checked first).
- **Type**: CAdES baseline B-B…B-LTA, ICP-Brasil CAdES policies AD-RB, AD-RT, AD-RV, AD-RC and AD-RA
  (`WithIcpBrasilPolicy`), or a policy OID. RFC 5126 extended forms (CAdES-X, X Long, A) need a
  signature timestamp (B-T, B-LT or B-LTA).
- **Result**: the validation tree (signers, with their countersignatures nested), the CMS structure
  (signed and unsigned attributes of every signer) and the C# / `simplesign cades` code.
- **Validate**: samples built at startup (valid, two signers plus a countersignature, data changed,
  signature value changed, unknown root) or your own .p7s / .p7m and data, with the same trust
  settings as the Validation page.

The run matrix has a CAdES set as well (operation × content × type × extended form × hash ×
padding × signer).

## XML (XAdES and fiscal XML-DSig)

The *XML* page has two modes.

- **XAdES** (`XadesSigner`): enveloped, detached (with the data URI) or enveloping; XAdES baseline
  B-B…B-LTA, ICP-Brasil XML policies AD-RB…AD-RA (`WithIcpBrasilPolicy`, which also sets the
  SigningCertificate V1) or a policy OID; extended forms XAdES-X, X-L and A (on B-T: they replace the
  B-LT / B-LTA data); signer roles, DataObjectFormat, commitment, signing time, hash and RSASSA-PSS.
  Validation with `XadesSignatureValidator.ValidateAll`, plus the ICP-Brasil policy check.
- **Fiscal XML-DSig** (`FiscalXmlSigner`): NF-e/NFC-e, events, voiding, CT-e, MDF-e, NFS-e DPS,
  eSocial and EFD-Reinf, with synthetic samples. The layout fixes the algorithms (RSA-SHA1 or
  RSA-SHA256), so only RSA certificates can sign; batches can be signed by Id or all at once.
  Validation checks each reference digest, signature value and chain, and reads the CNPJ/CPF.

The result shows the verdict of every `ds:Signature`, the Signature element (indented, base64
shortened), the start of the document, and the C# / `simplesign xades` / `simplesign fiscal` code.
The run matrix has an XML set (XAdES pairwise plus every fiscal layout).

## Run matrix

The *Run matrix* page (and `SimpleSign.TestBench.Tests` in CI) generates cases from the same
rules: every value of every dimension on its own, plus pairwise combinations, so every pair of
compatible values is signed together at least once. Each case signs in the sandbox, validates,
and checks the output has what was asked: level, sub-filter, field, timestamps, DSS, document
timestamp, DocMDP and mode.

## Limitations

- Sandbox certificates do not chain to a real ICP-Brasil root: the policy version is not picked
  by root, and AD-RA embeds simulated policy artifacts.
- Empty signature fields inside compressed object streams are not listed.
- PKCS#11 needs a driver; with no token, try SoftHSM2.
