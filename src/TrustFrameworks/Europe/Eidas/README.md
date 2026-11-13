# eIDAS (EU)

`SimpleSign.Europe.Eidas` — the EU trust framework (Regulation (EU) No 910/2014). It follows the layout of `../../Peru/`:
a project implementing `ICountryExtension`, built on the public API of Core and XAdES.

- `EidasExtension`: trust anchors from the EU list of trusted lists (LOTL) and the national lists it points to
  (`TrustedListSet`), with the status history of each service. The LOTL is checked against
  `EidasExtension.LotlSigners` (bundled, below), and the pivot LOTLs carry those keys forward when the Commission changes
  them.
- `EidasTrustedListSource` (`EidasExtension.LoadRefreshableAsync`, `services.AddSimpleSignEidas(options)`): the lists read
  again on demand or on a schedule, swapped in one step, the last good set kept when a refresh fails.
- `EidasQualifier`: the qualification of each validated signature — ETSI TS 119 615 (the CA/QC service at the
  certificate's issuance and at signing time, its Qualifications over the QC statements) and TS 119 172-4 (QESig,
  QESeal, AdESig-QC, AdESeal-QC, AdESig, AdESeal) — and of its time-stamps (QTSA when a granted TSA/QTST issued them).
- `EidasPolicies.Signing` / `Validation` and `EidasProfile` (`eidas`): `WithProfile(eidas)` for signers,
  `ValidationOptions.Profile = eidas` for validators; `simplesign … --profile eidas` in the CLI.

Documentation: [docs/articles/eidas.md](../../../docs/articles/eidas.md); what each item shows in
[docs/playbooks/eidas-checklist.md](../../../docs/playbooks/eidas-checklist.md).

## The bundled LOTL signers

`SimpleSign.Europe.Eidas/Certs/eu-lotl-signers.pem`: the keys the EU LOTL #398 (2026-11) names for itself (its pointer of
TSLType `EUlistofthelists`), which the Commission announces in the Official Journal (C/2026/1944, next to C 276 of
2019). **Before a release, compare these SHA-256 fingerprints with the Official Journal notice**; the LOTL #398 is signed
by the second one.

| Subject | Valid to | SHA-256 |
|---|---|---|
| Patrick Kremer (Signature) | 2028-05-30 | `D2064FDD70F6982DCC516B86D9D5C56AEA939417C624B2E478C0B29DE54F8474` |
| EUROPEAN COMMISSION | 2027-11-17 | `E0A620FBB6747362BB933AC44169D676A553444716CF5F31605F12A22B8396B1` |
| IOANNA KALOGEROPOULOU | 2029-11-23 | `C0641C4F7D56C431B1C924742DB7FCE9C1EEF7D7FD212113A2768486B3ABCDC5` |
| VICENTE ANDREU NAVARRO | 2027-05-06 | `DF7E29360C34B2B8D6D5F40325C1D4D12C9922CECD33B7407674A74B2B3CA1E5` |
| APOSTOLOS APLADAS | 2027-04-26 | `B63D416744E7098BF9EC2CAA596A93BC2468E37F8284BA65ECC061711BCBAA18` |
| EUROPEAN COMMISSION | 2029-12-17 | `236103F03A8031AE8F47F9059BF8DE38564CDBFEBEDDE4A597D50F8980AA653B` |

When the Commission moves to keys not in this list, a newer LOTL names pivot LOTLs signed by these: `TrustedListSet`
walks them (oldest first, skipping those older than the known keys) to the new keys, with no new package. Pass
`EidasExtensionOptions.LotlSigners` to use other keys.

```csharp
var eidas = await EidasProfile.LoadAsync(new EidasExtensionOptions { CacheDirectory = "/var/lib/simplesign/eu-lotl" });

byte[] signed = await PadesSigner.Document(pdf).WithCertificate(certificate, chain).WithProfile(eidas).SignAsync();

var results = await new PdfSignatureValidator(new ValidationOptions { Profile = eidas }).ValidateAsync(signed);
Console.WriteLine(results[0].Qualification?.Level); // QESig, AdESig-QC…
```
