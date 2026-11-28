# Fiscal XML (NF-e, CT-e, MDF-e, NFS-e, eSocial, EFD-Reinf)

`SimpleSign.Brazil.Fiscal` signs and validates the XML-DSig signatures of Brazilian fiscal XML with ICP-Brasil
certificates. These layouts take a plain enveloped XML-DSig signature, not XAdES: one `Reference` to an element by its
Id (or to the whole document), the `enveloped-signature` and C14N transforms, RSA, and only the signer certificate in
`KeyInfo`. The signature itself is `XmlDsigSigner` of SimpleSign.XAdES
([ADR 0034](../../../../docs/adr/0034-plain-xmldsig-and-fiscal-layouts.md)); this package adds the layouts, their
signing policy and the checks of the layout.

```bash
dotnet add package SimpleSign.Brazil.Fiscal
```

## Sign

```csharp
using SimpleSign.Brazil.Fiscal;

// One NF-e: signs infNFe (by its Id) and inserts <Signature> after it
byte[] signed = await FiscalXmlSigner.Document(nfeXml, FiscalDocumentProfile.NFe).WithCertificate(eCnpj).SignAsync();

// A batch (enviNFe, envEvento): every element not signed yet
byte[] batch = await FiscalXmlSigner.Document(enviNFe, FiscalDocumentProfile.NFe).WithCertificate(eCnpj).SignAllAsync();

// One NF-e of a batch, by its Id
byte[] one = await FiscalXmlSigner.Document(enviNFe, FiscalDocumentProfile.NFe).WithElementId("NFe3526…").WithCertificate(eCnpj).SignAsync();

// A3 token / HSM / cloud certificate (Pkcs11Signer, CscSigner, PscSigner)
byte[] withToken = await FiscalXmlSigner.Document(nfeXml, FiscalDocumentProfile.NFe)
    .WithExternalSigner(certificate, pkcs11Signer).SignAsync();
```

`FiscalXmlSigner.Document` returns an `XmlDsigSignerBuilder` already set for the layout (element, hash, placement,
C14N), with the ICP-Brasil anchors and the layout's signing policy. The certificate is checked before anything is
signed, as in PAdES: an ICP-Brasil chain, not revoked (LCR/OCSP), key usage, RSA 2048 bits or more. A refusal is a
`SigningException` with its `Reason` (`UntrustedRoot`, `CertificateRevoked`, `AlgorithmNotPermitted`…), and
`WithAuditSink` records every signature made or refused.

The XML is not reformatted. Send exactly the bytes you get back: any change after signing, even whitespace, breaks
the signature (SEFAZ rejection 297/298).

### SHA-1

The SEFAZ layouts (NF-e, NFC-e, CT-e, MDF-e and their events) mandate RSA-SHA1. SimpleSign refuses SHA-1 everywhere
else, and the default signing policies do too. The layouts with SHA-1 are signed under `FiscalPolicies.Sefaz`: the
ICP-Brasil signing policy with SHA-1 accepted as the signature digest, and nothing else relaxed. The CA certificates
of the chain must still be signed with SHA-2. The external signers (PKCS#11, CSC, PSC) and the SimpleSign Agent hash
with SHA-1 only for an XML-DSig `SignedInfo`; CMS signed attributes are never signed with SHA-1.

### Two phases (a local agent, a token in the browser)

```csharp
var prepared = await FiscalXmlSigner.Deferred(nfeXml, FiscalDocumentProfile.NFe)
    .WithCertificate(publicCertificate).WithSessionIntegrityKey(key).PrepareAsync();
// prepared.DataToSign is the canonical SignedInfo (prepared.DigestAlgorithm "SHA1"): hand it to the SimpleSign Agent
// (/api/sign, hashAlgorithm SHA1) or to any IExternalSigner (prepared.ToSigningRequest())
byte[] signed = await XmlDsigDeferredSigner.Resume(prepared.SessionData, key).CompleteAsync(signature);
```

## Layouts

| Profile | Signed element | Hash | Signature placement |
|---|---|---|---|
| `NFe` (NF-e, NFC-e 4.00) | `infNFe@Id` | SHA-1 | after `infNFe` |
| `Evento` (NF-e/CT-e/MDF-e events) | `infEvento@Id` | SHA-1 | after `infEvento` |
| `Inutilizacao` | `infInut@Id` | SHA-1 | after `infInut` |
| `CTe` | `infCte@Id` | SHA-1 | after `infCte` |
| `MDFe` | `infMDFe@Id` | SHA-1 | after `infMDFe` |
| `NFSeDps` (NFS-e Nacional) | `infDPS@Id` | SHA-256 | after `infDPS` |
| `ESocial` | whole document (`URI=""`) | SHA-256 | last child of `eSocial` |
| `Reinf` | the event, by `id` | SHA-256 | last child of `Reinf` |

> The NFS-e Nacional profile is not settled: integrators report both SHA-1 and SHA-256. Check the current
> ADN/Sefin Nacional manual. Profiles are records, so you can adjust one:
> `FiscalDocumentProfile.NFSeDps with { HashAlgorithm = HashAlgorithmName.SHA1 }`.

eSocial and EFD-Reinf sign each event on its own, as a document, before it goes in the batch (`envioLoteEventos`):
the batch itself is not signed. Sign each event, then build the batch from the signed bytes. A batch given to
`FiscalXmlSigner` (or to `brasil fiscal sign`) is refused with an `ArgumentException`.

Another XML-DSig signature that is not a fiscal layout is `XmlDsigSigner` directly:

```csharp
await XmlDsigSigner.Document(xml).WithSignedElement("pedido").WithCertificate(cert).SignAsync();   // or WithWholeDocument()
```

## Validate

```csharp
// Digest and signature value only (offline), and the layout
var quick = FiscalXmlValidator.VerifySignatures(signedXml, FiscalDocumentProfile.NFe);

// Plus the ICP-Brasil chain of each signer (e-CNPJ/e-CPF), with LCR/OCSP
var full = await new FiscalXmlValidator().ValidateAsync(signedXml, FiscalDocumentProfile.NFe);
foreach (var s in full.Signatures)
    Console.WriteLine($"{s.Signature.SignedElement} {s.Signature.ReferenceUri} CNPJ {s.Cnpj}: {s.IsValid}");
```

References must resolve to exactly one element: a duplicate Id is refused, against XML signature wrapping. Given the
layout, each signature must sign the layout's element with the layout's hash (`LayoutErrors`).

An eSocial or EFD-Reinf batch (`envioLoteEventos`) is validated event by event, each as the document it was when
signed: in eSocial `URI=""` means the event, not the batch. `BatchEventId` says which `evento` holds each signature;
an event not signed, or a signature of the batch itself, is in `Errors`.

## CLI

```bash
simplesign extension install SimpleSign.Brazil.Cli
simplesign brasil fiscal sign nfe.xml --layout nfe --cert empresa.pfx
simplesign brasil fiscal sign lote.xml --layout nfe --cert empresa.pfx --all
simplesign brasil fiscal sign nfe.xml --layout nfe --pkcs11-lib /usr/lib/libaetpkss.so      # A3 token
simplesign brasil fiscal sign nfe.xml --layout nfe --cert empresa.cer --prepare --session-key …  # two phases
simplesign brasil fiscal validate nfe.xml.signed.xml --layout nfe
```

`brasil fiscal sign` is `simplesign xmldsig sign` (every option of it: the certificate from a PFX, the Windows store,
a PKCS#11 token or a cloud certificate; `--prepare` and `deferred complete`; `--all`) with the layout, the ICP-Brasil
anchors and the layout's policy. `--element`, `--hash`, `--placement` and `--canonicalization` are set by `--layout`.
`--signing-policy` replaces the layout's policy; the preset `fiscal-sefaz` is `FiscalPolicies.Sefaz`.

## TestBench

The XML page has a **Fiscal XML** signature type: choose the layout, a sample (NF-e, event, CT-e, eSocial) or your own
XML, and sign through the library or the CLI, in one call or in two phases. The playbook `fiscal-xmldsig` runs every
family, the refusal of SHA-1 outside `fiscal-sefaz` and the two phases, with the Sandbox's trust added to the
icp-brasil profile.

## Checking against the authorities

The tests check each layout with .NET's own `SignedXml`, independently of this implementation. Before production,
send a document to the SEFAZ (or eSocial/Reinf) **homologation** environment with a homologation e-CNPJ.
