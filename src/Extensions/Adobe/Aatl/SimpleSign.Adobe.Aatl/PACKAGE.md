# SimpleSign.Adobe.Aatl

The Adobe Approved Trust List (AATL) for SimpleSign: the certification authorities Acrobat trusts for signatures, read
from Adobe's signed list at run time, with the list's certificate policy restrictions. Not affiliated with or endorsed
by Adobe.

```csharp
using SimpleSign.Adobe.Aatl;

var aatl = await AatlProfile.LoadAsync();   // Adobe's list, checked against the bundled Adobe root
var results = await new PdfSignatureValidator(new ValidationOptions { Profile = aatl }).ValidateAsync(signed);
```

- `AatlList`: one copy of the list — a PDF signed by Adobe that embeds the trusted identities. Its signature must cover
  the whole file and chain to `AatlExtension.ListSigners` (Adobe Root CA G2, bundled), never to the system's roots.
- `AatlSource` (`AatlExtension.LoadAsync`, `services.AddSimpleSignAatl()`): the list downloaded from Adobe and read
  again on demand or on a schedule; the last good copy is kept when a refresh fails. The list is not part of the package.
- Policy restrictions: an anchor trusted only for certain certificate policies refuses a chain whose signer certificate
  asserts none of them (`IConstrainedTrustAnchorProvider`), as Acrobat does.
- `AatlPolicies` and `AatlProfile` (`aatl`): `WithProfile(aatl)` for signers, `ValidationOptions.Profile = aatl` for
  validators; `simplesign … --profile aatl` in the CLI (extension `SimpleSign.Adobe.Aatl.Cli`).

The profile gives trust, not a legal level, and the list has no history: an authority taken out of it stops being
trusted for earlier signatures too.

Documentation: [src/Extensions/Adobe/Aatl/docs/aatl.md](https://github.com/eupassarin/SimpleSign/blob/main/src/Extensions/Adobe/Aatl/docs/aatl.md).

## The bundled Adobe root

`Certs/adobe-root-ca-g2.pem`: Adobe Root CA G2, SHA-256
`458E0E219698B18D2D4093D6336A12547953A54C05DD967C3A5A268B772D1B22`, valid to 2046-11-28 — the fingerprint Adobe
publishes on its [Trust Services page](https://helpx.adobe.com/acrobat/kb/trust-services.html).

MIT licensed. "Adobe" and "Acrobat" are trademarks of Adobe.
