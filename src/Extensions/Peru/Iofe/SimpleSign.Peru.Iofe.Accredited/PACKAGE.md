# SimpleSign.Peru.Iofe.Accredited

The configuration of SimpleSign that INDECOPI's *Guía de Acreditación de Aplicaciones de Software* (v4.0) asks for in
sections **4.2** (signing by automated agents), **4.3** (verification by automated agents) and **4.4** (time-stamp
requests), as a narrow API with nothing to relax:

- the private key signs only inside a cryptographic module: the organization's, through PKCS#11 (a key the driver
  does not report as sensitive and not extractable is refused), or that of a remote signing service the operator
  declares (Cloud Signature Consortium API v2: only the hash is sent). A PKCS#12 (PFX) file is not accepted;
- the checks of the certificate (trust, revocation by CRL or OCSP, validity, nonRepudiation, algorithms) are fixed —
  no policy is taken from the caller; the one exception is a declared contingency, written to the audit trail;
- every signature made or refused, and every verification, is recorded in a hash-chained audit trail;
- an agent signs only for the kinds of transaction it was set up for;
- a rejected document produces a notice to its sender;
- each time-stamp is checked: it comes from the authority asked, its signature verifies, and the authority's
  certificate is trusted, not expired and not revoked.

```csharp
using SimpleSign.Peru.Iofe.Accredited;

await using var agent = await IofeSigningAgent.OpenAsync(new IofeSigningAgentOptions
{
    Module = new Pkcs11SignerOptions { LibraryPath = hsmDriver, TokenLabel = "firma", KeyLabel = "sello-2026", Pin = pin },
    ModuleDeclaration = new IofeModuleDeclaration("Thales", "Luna K7", "FIPS 140-2 Level 3", "4090"),
    Audit = new JsonLinesAuditSink("/var/log/firma/auditoria.jsonl"),
    Transactions = ["factura", "constancia"],
    Timestamp = new IofeTimestampAuthority(new Uri(tsaUrl), tsaCertificate),
});
IofeSignedDocument signed = await agent.SignPdfAsync(pdf, new IofeTransaction("factura", "F001-123"));

await using var verifier = await IofeVerificationAgent.CreateAsync(new IofeVerificationAgentOptions
{
    Audit = new JsonLinesVerificationAuditSink("/var/log/firma/verificacion.jsonl"),
    Notifier = notifier,                                   // IIofeSenderNotifier: how the notice reaches the sender
});
IofeVerification result = await verifier.VerifyAsync(received, new IofeSender("20123456789", "mesa@entidad.pe"));
```

By default both trust INDECOPI's trusted list (`IofeTrust.IndecopiList()`), kept current. The manuals the guide asks
for (administration, user, programmer, security configuration, scope) are under
[src/Extensions/Peru/Iofe/docs/accreditation](https://github.com/eupassarin/SimpleSign/tree/main/src/Extensions/Peru/Iofe/docs/accreditation),
and in Spanish under
[docs/es/acreditacion](https://github.com/eupassarin/SimpleSign/tree/main/src/Extensions/Peru/Iofe/docs/es/acreditacion). MIT licensed.

Being accredited is a decision of INDECOPI about a product and its operation: this package gives the software part,
and the manuals say what remains with the operator (the module's certification, key custody, access control).
