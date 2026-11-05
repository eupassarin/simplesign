# Fiscal XML (NF-e, CT-e, MDF-e, NFS-e, eSocial, EFD-Reinf)

`SimpleSign.Brasil.Fiscal` signs and validates the XMLDSig signatures of Brazilian fiscal XML.

```bash
dotnet add package SimpleSign.Brasil.Fiscal
```

## Sign

```csharp
using SimpleSign.Brasil.Fiscal;

// One NF-e: signs infNFe (by its Id) and inserts <Signature> after it
byte[] signed = FiscalXmlSigner.Sign(nfeXml, FiscalDocumentProfile.NFe, eCnpj);

// A batch (enviNFe, envEvento): every element not signed yet
byte[] batch = FiscalXmlSigner.SignAll(enviNFe, FiscalDocumentProfile.NFe, eCnpj);

// A3 token / HSM / cloud certificate
byte[] withToken = await FiscalXmlSigner.SignAsync(nfeXml, FiscalDocumentProfile.NFe, certificate, pkcs11Signer);
```

The XML is not reformatted. Send exactly the bytes you get back: any change after signing, even
whitespace, breaks the signature (SEFAZ rejection 297/298).

## Profiles

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

Every profile uses an enveloped signature with the `enveloped-signature` and C14N 1.0 transforms,
RSA, and only the signer certificate in `KeyInfo/X509Data`.

> The NFS-e Nacional profile is not settled: integrators report both SHA-1 and SHA-256. Check the
> current ADN/Sefin Nacional manual. Profiles are records, so you can adjust one:
> `FiscalDocumentProfile.NFSeDps with { HashAlgorithm = HashAlgorithmName.SHA1 }`.

## Validate

```csharp
// Digest and signature value only (offline)
var quick = FiscalXmlValidator.VerifySignatures(signedXml);

// Plus the ICP-Brasil chain of each signer (e-CNPJ/e-CPF), with LCR/OCSP
var full = await new FiscalXmlValidator(httpClient).ValidateAsync(signedXml);
foreach (var s in full.Signatures)
    Console.WriteLine($"{s.SignedElement} {s.ReferenceUri} CNPJ {s.Cnpj}: {s.IsValid}");
```

References must resolve to exactly one element: duplicate Ids are rejected, against XML
signature-wrapping attacks.

## CLI

```bash
simplesign fiscal sign nfe.xml --profile nfe --cert empresa.pfx
simplesign fiscal sign lote.xml --profile nfe --cert empresa.pfx --all
simplesign fiscal validate nfe-signed.xml
```

## Checking against the authorities

The tests check each profile with .NET's own `SignedXml`, independently of this implementation.
Before production, send a document to the SEFAZ (or eSocial/Reinf) **homologation** environment
with a homologation e-CNPJ.
