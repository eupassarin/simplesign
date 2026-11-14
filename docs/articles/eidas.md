# eIDAS (EU): trusted lists and qualification

`SimpleSign.Europe.Eidas` brings the EU trust framework (Regulation (EU) No 910/2014): the trust anchors of the EU
trusted lists, the qualification of each signature (QESig, QESeal, AdESig-QC…), and eIDAS policies, as one profile
(`eidas`) the library, the CLI and the TestBench use the same way.

## Installation

```bash
dotnet add package SimpleSign.Europe.Eidas
```

It depends on SimpleSign.Core and SimpleSign.XAdES (the trusted-list reader).

## The profile

```csharp
using SimpleSign.Europe.Eidas;

var eidas = await EidasProfile.LoadAsync(new EidasExtensionOptions
{
    CacheDirectory = "/var/lib/simplesign/eu-lotl",   // the last good copy of each list, used when a download fails
});

byte[] signed = await PadesSigner.Document(pdf).WithCertificate(certificate, chain).WithProfile(eidas).SignAsync();

var results = await new PdfSignatureValidator(new ValidationOptions { Profile = eidas }).ValidateAsync(signed);
var qualification = results[0].Qualification;   // Level: QESig, AdESig-QC…; Notes: why; Timestamps: QTSA…
```

`WithProfile` sets the signing policy (`EidasPolicies.Signing`: the signer and each TSA chain to the EU lists, the
revocation of the whole chain, a warning on a non-qualified certificate) and the trust anchors. `ValidationOptions.Profile`
sets the validation policy (`EidasPolicies.Validation`: a list that is expired or badly signed fails), the anchors, the
lists' service history and the qualifier. An explicit `WithSigningPolicy` / `Policy` wins.

To sign only with a qualified certificate whose key is on a QSCD:

```csharp
var fail = new PolicyConstraint(ConstraintLevel.Fail);
var qualifiedOnly = EidasPolicies.Signing
    .With("SigningCertificate/QcCompliance", fail)
    .With("SigningCertificate/QcSSCD", fail);   // otherwise SigningException, Reason CertificateNotQualified
```

## The EU list of trusted lists

`EidasExtensionOptions.LotlUrl` is `https://ec.europa.eu/tools/lotl/eu-lotl.xml` by default. The LOTL is checked against
`EidasExtension.LotlSigners`, the keys bundled with the package (their SHA-256 fingerprints are in the package README;
compare them with the Official Journal notice C/2026/1944). When the Commission signs the LOTL with a newer key, the
LOTL names *pivot LOTLs* in its SchemeInformationURI: `TrustedListSet` checks each, oldest first, with the keys known
so far, and each gives the keys accepted after it (`TrustedListSetOptions.FollowPivots`, on by default). The keys
reached are `TrustedListSet.LotlSigners`; `EidasTrustedListSource` starts the next refresh from them.

Each national list is checked against the certificates the LOTL gives for it. A list that cannot be read or checked is
a `TrustedListSet.Problems` entry, not a failure of the set. An expired LOTL is refused; an expired national list is
refused for signing and kept for validation, where `TrustedLists/TLNotExpired` (FAIL in the eidas policy) judges it.

`EidasExtension.LoadRefreshableAsync` (or `services.AddSimpleSignEidas(options, refreshInterval)`) keeps the lists
current: `RefreshAsync`, `StartAutoRefresh`, `Changed`, `RefreshFailed`. `Territories` limits the member states read.

## Qualification

`EidasQualifier` runs after each signature is validated (it is the profile's `SignatureQualifiers`):

1. **The trust service** — the CA/QC or CA/PKC service the signer's chain reaches (by issuer, through the certificates
   of the signature). None: `N/A`.
2. **At issuance** (the certificate's notBefore, ETSI TS 119 615 §4.3) — the service then in force (from its history)
   must be a granted CA/QC. Its Qualifications extension, applied through its criteria to the certificate, corrects the
   QC statements: `QCStatement` / `NotQualified`, `QCForESig` / `QCForESeal` / `QCForWSA`. Otherwise the certificate's
   QcCompliance and QcType (esign, eseal; absent: signatures) say. A certificate under another legislation
   (QcCClegislation) is not EU qualified.
3. **At the signing time** (the best signature time, else the claimed one) — the service must still be granted; its
   Qualifications say whether the key is on a QSCD (`QCWithQSCD`, `QCNoQSCD`, `QCQSCDStatusAsInCert`,
   `QCQSCDManagedOnBehalf`…), else the certificate's QcSSCD does.
4. **ETSI TS 119 172-4** — QESig / QESeal (qualified, QSCD), AdESig-QC / AdESeal-QC (qualified, no QSCD), AdESig /
   AdESeal; an indeterminate validation gives `Indeterminate …`, a failed one `Not AdES`.

Each time-stamp is `QTSA` when a TSA/QTST service of the lists, granted at its genTime, issued it; `TSA` for another TSA
service; `N/A` otherwise.

The qualification does not change the indication. It is in `SignatureValidationResult.Qualification` (and the CAdES and
XAdES results), the ETSI TS 119 102-2 report (`SignatureQuality`, with DSS's URIs
`urn:cef:dss:signatureQualification:QESig`…), the simple JSON report and the HTML report. A qualifier of another
framework implements `ISignatureQualifier`; a country extension returns it in `SignatureQualifiers`.

## CLI

```bash
simplesign sign contract.pdf --cert signer.pfx --profile eidas --tsa https://tsa.example.eu/
simplesign validate contract-signed.pdf --profile eidas
simplesign validate contract-signed.pdf --profile eidas --sandbox http://localhost:5300   # the Sandbox's LOTL, to test
```

`validate` prints the qualification of each signature and its time-stamps (`--json`: `qualification`,
`timestampQualifications`). `simplesign policy export validation --preset eidas` writes the policy out.

## Sandbox and TestBench

The Sandbox's LOTL (`/tl/lotl.xml`) points to its TL (`/tl/tl.xml`), whose root is a CA/QC service with
AdditionalServiceInformation (ForeSignatures, ForeSeals) and a Qualifications extension (`QCWithQSCD` for the
QCP-n-qscd policy), a CA/PKC service (`intermediate-pkc`), a TSA/QTST and a non-qualified TSA (`/tsa/non-qualified`).
Its signers `qc-esign-qscd`, `qc-esign`, `qc-eseal-qscd`, `qc-esign-policy` and `pkc-esign` carry QC statements; the
LOTL fails on demand (`lotl`: Expired, WrongSigner, Tampered), as the TL does.

In the TestBench, the Profile menu has **EU (eIDAS) · EU LOTL (real)** and **· Sandbox's LOTL (test)**; each result shows
the qualification. The `eidas-baseline` playbook runs the list faults, the qualification cases and the time-stamps on
both engines; [eidas-checklist.md](../playbooks/eidas-checklist.md) maps each item to its steps.
