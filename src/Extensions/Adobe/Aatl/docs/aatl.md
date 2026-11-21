# Adobe Approved Trust List (AATL)

The Adobe Approved Trust List is the list of certification authorities whose signatures Acrobat and Acrobat Reader show
as trusted without any configuration. `SimpleSign.Adobe.Aatl` reads it, so a validation can answer the question most
people outside a national framework ask: *will Acrobat trust this signature?*

SimpleSign is not affiliated with or endorsed by Adobe.

```bash
dotnet add package SimpleSign.Adobe.Aatl
```

```csharp
using SimpleSign.Adobe.Aatl;

var aatl = await AatlProfile.LoadAsync();   // Adobe's list, checked against the bundled Adobe root
var results = await new PdfSignatureValidator(new ValidationOptions { Profile = aatl }).ValidateAsync(signed);

// Sign only with a certificate the list trusts
await PadesSigner.Document(pdf).WithCertificate(cert, chain).WithProfile(aatl).SignAsync();

// Another framework's policies, trusting the AATL too
var both = IcpBrasilProfile.Create().WithTrustFrom(aatl);
```

```bash
simplesign extension install SimpleSign.Adobe.Aatl.Cli
simplesign validate contract.pdf --profile aatl
simplesign validate contract.pdf --profile icp-brasil --trust-profile aatl
```

## What the profile says, and what it does not

- **Trust, not a legal level.** A signature trusted under `aatl` chains to a certification authority Adobe admitted to
  its program. Nothing says what the signature is in a country's law: no qualification is given (for the EU, see the
  eIDAS package).
- **The operating system's roots are not trusted**, as with every framework's profile.
- **No history.** The list is a picture of today: an authority taken out of it stops being trusted for the signatures
  it vouched for before, too. A trusted list with a service history (ETSI TS 119 612) does not have this limit.
- **No expiry date.** `AatlList.SignedAt` says when Adobe signed the copy; Adobe publishes a new one every few weeks.

## How the list is read

The list is a PDF (`.acrobatsecuritysettings`) signed by Adobe that embeds `SecuritySettings.xml`. `AatlList.LoadAsync`:

1. checks the PDF's signature: it must verify, **cover the whole file**, and chain to `AatlExtension.ListSigners`
   (Adobe Root CA G2, bundled) — never to the system's roots. With `AatlOptions.CheckRevocation` (the default) the
   signer's revocation is checked too. The one place a signature does not cover, its own `/Contents`, must hold the
   signature's hexadecimal and nothing else: an object hidden there would otherwise be read as part of the list;
2. reads the embedded `SecuritySettings.xml` (`PdfEmbeddedFiles`), with DTDs prohibited;
3. reads each `Identity`: its certificate, its trust flags, its policy restrictions.

`AatlSource` keeps the list current: `RefreshAsync` or `StartAutoRefresh` read it again, a copy that does not verify or
that was signed before the one served is refused, and the last good copy is kept (in `AatlOptions.CacheFile` across
restarts).

Adobe does not document the format. It was read from the list of 2026-11-12 (313 identities); a format change shows as
a list that cannot be read, which gives no anchors.

## Which identities are trust anchors

| In the list | Meaning here |
|---|---|
| `Trust/Root` = 1 | A trusted root for signatures: an anchor |
| `Trust/Root` = 0 | Listed, not an anchor (Acrobat uses the other flags for certified documents and scripts) |
| `ImportAction` = 3 | Removed: not an anchor, whatever its flags. Adobe does not document the values; in the list read, 3 marks the authorities taken out of the program (Camerfirma, GLOBALTRUST 2020…), so it is read as a removal |
| `PolicyRestrictions/CertificatePolicies` | The anchor is trusted only for those certificate policies (below) |

An anchor that is not self-signed helps build a chain and decides for it, but a chain is trusted only when it ends at
a self-signed anchor, as for every trust anchor provider.

## Certificate policy restrictions

Half of the anchors are trusted only for certain certificate policies — usually the ones of certificates whose key is
on a hardware device. ICP-Brasil's root, for one, is in the list for its A3 and A4 certificates only: a signature made
with an A1 certificate is not trusted by Acrobat, and not by this profile.

`AatlList` is an `IConstrainedTrustAnchorProvider`: once the signer's chain reaches one of its anchors, it refuses the
chain when **the signer's certificate asserts none of the anchor's policies** (certificatePolicies, RFC 5280 §4.2.1.4).
The refusal is an error of the signature, which is then not trusted. The same check is made before signing under the
profile (`SigningException`, reason `UntrustedRoot`).

- The anchor asked about is the one nearest to the signer's certificate.
- When another profile added with `WithTrustFrom` gives the same anchor without conditions, the chain is accepted:
  `IcpBrasilProfile.Create().WithTrustFrom(aatl)` trusts an A1 certificate, because ICP-Brasil's own profile does.
- `PolicyRestrictions/NonExplicitProcessing` is reported (`AatlIdentity.NonExplicitPolicyProcessing`) and not
  interpreted: Adobe does not document it.
- The chain of a time-stamp's TSA is not asked about: a TSA under a restricted anchor is trusted whatever its policies.

## The policies

- `AatlPolicies.Validation`: the default policy with the reference to the signing certificate at WARN. Acrobat signs
  in `adbe.pkcs7.detached` without the signing-certificate attribute and accepts such signatures; under the default
  policy they are INDETERMINATE (NO_SIGNING_CERTIFICATE_FOUND).
- `AatlPolicies.Signing`: the default checks, and the certificate must chain to an anchor of the list that accepts it.

## Using Adobe's list

The list is not part of the package: the application downloads it from Adobe at run time, as Acrobat does. Adobe
publishes no terms for its use by other software that we could find; whoever uses this package is responsible for that
use being acceptable to Adobe. The bundled Adobe root is the one Adobe publishes on its
[Trust Services page](https://helpx.adobe.com/acrobat/kb/trust-services.html).
