# Adobe Approved Trust List (AATL)

Everything SimpleSign has for the trust list Acrobat uses for signatures, in one folder. SimpleSign is not affiliated
with or endorsed by Adobe; "Adobe" and "Acrobat" are trademarks of Adobe.

| | |
|---|---|
| [`SimpleSign.Adobe.Aatl/`](SimpleSign.Adobe.Aatl) | The library: the list read and checked, its anchors with their certificate policy restrictions, the `aatl` profile and policies. One `ICountryExtension`, built on the public API of Core and PAdES |
| [`SimpleSign.Adobe.Aatl.Cli/`](SimpleSign.Adobe.Aatl.Cli) | The extension of the `simplesign` command line: `--profile aatl` and the `aatl` policies |
| [`docs/aatl.md`](docs/aatl.md) | The article: what the list is, how it is read, what the profile says and does not say |

The tests are in `tests/unit/Extensions/Adobe/Aatl`.

- `AatlList`: one copy of the list. The file is a PDF signed by Adobe that embeds `SecuritySettings.xml`; its signature
  must cover the whole file and chain to `AatlExtension.ListSigners` (bundled, below), never to the system's roots,
  and nothing but the signature may be where the signature is kept.
- `AatlSource` (`AatlExtension.LoadAsync`, `services.AddSimpleSignAatl()`): the list downloaded from Adobe at run time
  and read again on demand or on a schedule, the last good copy kept when a refresh fails. **The list is not part of the
  package.**
- `AatlIdentity`: each identity of the list and what Acrobat trusts it for. The anchors are the trusted roots that are
  not removed; an anchor with policy restrictions refuses a chain whose signer certificate asserts none of its
  certificate policies (`IConstrainedTrustAnchorProvider`).
- `AatlPolicies.Signing` / `Validation` and `AatlProfile` (`aatl`): `WithProfile(aatl)` for signers,
  `ValidationOptions.Profile = aatl` for validators; `simplesign … --profile aatl` in the CLI (the extension).

## The bundled Adobe root

`SimpleSign.Adobe.Aatl/Certs/adobe-root-ca-g2.pem`: Adobe Root CA G2, the root the list's signature chains to
(Adobe Certified Document Service Program ← Adobe CDS CA ← Adobe Root CA G2). Adobe publishes its fingerprint on its
[Trust Services page](https://helpx.adobe.com/acrobat/kb/trust-services.html); it was compared with that page on
2026-11-17. **Before a release, compare it again.**

| Subject | Valid to | SHA-256 |
|---|---|---|
| Adobe Root CA G2 | 2046-11-28 | `458E0E219698B18D2D4093D6336A12547953A54C05DD967C3A5A268B772D1B22` |

## Using Adobe's list

The list is downloaded from Adobe's server (`https://trustlist.adobe.com/tl12.acrobatsecuritysettings`) by the
application that uses this package, as Acrobat does. Adobe publishes no terms for the use of the list by other software
that we could find; whoever uses this package is responsible for that use being acceptable to Adobe.
