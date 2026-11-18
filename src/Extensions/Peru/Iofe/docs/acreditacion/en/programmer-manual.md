# Programmer's manual

How the library `SimpleSign.Peru.Iofe.Accredited` works and how to configure it (Req. 20: "manual de programador").
Namespace: `SimpleSign.Peru.Iofe.Accredited`. Frameworks: .NET 8 and .NET 10; compatible with Native AOT. All the
cryptography uses `System.Security.Cryptography`; the private-key operation happens in the PKCS#11 module or in the
remote signing service. (English translation of [`manual-del-programador.md`](../manual-del-programador.md); the
Spanish text is the one handed to INDECOPI.)

```bash
dotnet add package SimpleSign.Peru.Iofe.Accredited
```

## Design principle

The types of this package **take no policy**. The signing policy (`IofePolicies.AgentSigning`) and the validation
policy (`IofePolicies.AgentValidation`) are fixed, and no overload accepts a certificate with its key, a PKCS#12 (PFX)
file or an external signer of any kind: the key is in a PKCS#11 module or in a declared remote signing service, and
nowhere else. What the guide requires is met by construction; what the integrator decides is where the key is, where
the audit trail is written, which transactions are signed and how the sender is notified.

For operations outside the scope of the accreditation there are SimpleSign's general signers (`PadesSigner`,
`CadesSigner`, `XadesSigner`); they must not be used for the accredited operations.

## Signing by an automated agent (section 4.2)

```csharp
using SimpleSign.Core.Signing;
using SimpleSign.Peru.Iofe.Accredited;
using SimpleSign.Signers.Pkcs11;

await using var agent = await IofeSigningAgent.OpenAsync(new IofeSigningAgentOptions
{
    Module = new Pkcs11SignerOptions
    {
        LibraryPath = "/usr/lib/libCryptoki2_64.so",
        TokenLabel = "firma",
        KeyLabel = "sello-2026",
        Pin = pin,                                   // null: PIN pad or protected authentication path
    },
    ModuleDeclaration = new IofeModuleDeclaration("Thales", "Luna K7", "FIPS 140-2 Level 3", "4090"),
    Audit = new JsonLinesAuditSink("/var/log/firma/auditoria.jsonl"),
    Transactions = ["factura", "constancia"],
    Timestamp = new IofeTimestampAuthority(new Uri("https://tsa.example.pe/tsa"), tsaCertificate),   // optional
});

IofeSignedDocument pdf = await agent.SignPdfAsync(pdfBytes, new IofeTransaction("factura", "F001-123"));
IofeSignedDocument cms = await agent.SignCmsAsync(data, new IofeTransaction("constancia", "C-77"), detached: false);
IofeSignedDocument xml = await agent.SignXmlAsync(xmlBytes, new IofeTransaction("factura", "F001-124"));
```

- `OpenAsync` loads the trust, opens the session in the module and checks the key and the declared module. The agent
  keeps one session open and may be shared between threads; release it with `await using`.
- `IofeSignedDocument` carries the signed document, the format, the level reached, whether it is time-stamped, the
  identifier of the operation (`type/id`), the certificate's subject and fingerprint, the policy applied, whether it
  was signed under a contingency and where the key that signed is (`KeySource`: module or remote service).
- Level of the signature: B-B without a time-stamp authority (signing time and certificate chain, protected by the
  signature); B-LT with one (also the time-stamp and the revocation data of the whole chain).
- The certificate's chain is completed up to the root with the certificates of the module, those of
  `ChainCertificates` (the issuing CAs' certificates, for a module or service that holds the signing certificate
  alone), those of the trust and, when an issuer is missing, the one downloaded from the address the certificate names
  (AIA). The root must be a trusted one.

### With the key in a remote signing service

Instead of `Module` and `ModuleDeclaration` (one key source or the other, never both):

```csharp
using SimpleSign.Signers.Cloud.Csc;

await using var agent = await IofeSigningAgent.OpenAsync(new IofeSigningAgentOptions
{
    RemoteService = new IofeRemoteService
    {
        Service = new CscClientOptions
        {
            BaseUri = new Uri("https://provider.example.pe/csc/v2/"),
            ClientId = clientId,                     // or AccessToken, a service token obtained elsewhere
            ClientSecret = clientSecret,
        },
        CredentialId = "sello-2026",
        Pin = pin,                                   // null when the credential asks for none
    },
    RemoteServiceDeclaration = new IofeRemoteServiceDeclaration(
        "Proveedor S.A.", "Firma Remota", "PSVA de firma remota acreditado ante el INDECOPI", "Res. 000-2025/DGI-INDECOPI"),
    Audit = new JsonLinesAuditSink("/var/log/firma/auditoria.jsonl"),
    Transactions = ["factura", "constancia"],
});
```

- The service speaks the *Cloud Signature Consortium API v2*. The library sends it the hash and receives the
  signature; the key does not leave the service.
- `OpenAsync` first asks the service what it is (`info`): when it is not the declared one, it refuses it
  (`RemoteServiceMismatch`) without sending it the client secret or the PIN. It also refuses a credential a person
  must authorize (`RemoteAuthorizationNotUnattended`).
- With client credentials, the agent renews the service token when it expires.
- `agent.RemoteService` reports the service, the credential, its authorization mode and what was declared;
  `agent.Module` is null. Everything else — policy, transactions, audit, time-stamp, contingency — is identical.
- A PKCS#12 (PFX) file is not a key source of this package: see the administration manual, section 3.3.

### Errors

| Exception | When |
|---|---|
| `IofeAccreditationException` (`Refusal`) | A refusal of the accredited configuration itself: `KeyNotInModule`, `ModuleMismatch`, `RemoteServiceMismatch`, `RemoteAuthorizationNotUnattended`, `TransactionNotAllowed`, `AuditMissing`, `OptionsIncomplete`, `ContingencyExpired`, `NoticeNotDelivered` |
| `SigningException` (`Reason`) | A check of the policy refused the certificate, the key, the algorithm or the time-stamp: `CertificateRevoked`, `RevocationStatusUnknown`, `CertificateExpired`, `ChainCertificateNotValid`, `KeyUsageNotPermitted`, `KeyTooWeak`, `AlgorithmNotPermitted`, `UntrustedRoot`, `TimestampUntrusted`, `TimestampInvalid`, `TimestampCertificateRevoked`… |
| `Pkcs11Exception` | The module could not be opened or refused to sign (driver, PIN, key selection) |
| `CloudSigningException` | The remote signing service refused the agent or the credential (token, client secret, disabled key). A PIN refused when signing comes inside a `SigningException` |

Every refusal is in the audit trail before the exception reaches the caller: that of a signature asked for, that of
a key, a module or a service that is not the right one, and that of an agent that does not get to open
(`AgentNotOpened`: the trusted list could not be read, the module refused the PIN, the service refused the agent, the
options are incomplete). The exception is the same in each case.

The verification agent is created before any document arrives: when it cannot read the trusted list, `CreateAsync`
throws and there is no record, because there is no document to record.

## Verification by an automated agent (section 4.3)

```csharp
await using var verifier = await IofeVerificationAgent.CreateAsync(new IofeVerificationAgentOptions
{
    Audit = new JsonLinesVerificationAuditSink("/var/log/firma/verificacion.jsonl"),
    Notifier = new MyNotifier(),
});

IofeVerification result = await verifier.VerifyAsync(
    received,
    new IofeSender("20123456789", "mesa@entidad.pe"),
    new IofeVerificationRequest { Reference = "MP-2026-001" });

if (!result.Accepted)
{
    // result.Notice has been handed to the sender; result.Reasons says why.
}
```

- The format (PDF, CMS, XML) is detected. For a detached signature, pass the content in
  `IofeVerificationRequest.DetachedContent`.
- **Every** signature is validated. `Accepted` is true only when there is at least one and all are valid
  (TOTAL-PASSED of ETSI EN 319 102-1). An indeterminate signature — one without a revocation status, for instance —
  is not accepted.
- A document that cannot be read or has no signatures is rejected with its notice; it does not throw.
- `IofeVerification` carries each signature (`SignatureReportEntry`), the reasons, the notice, the report in Spanish
  (`ReportHtml`) and the ETSI TS 119 102-2 report (`EtsiReportXml`).

### The notice to the sender

```csharp
sealed class MyNotifier : IIofeSenderNotifier
{
    public async ValueTask NotifyAsync(IofeRejectionNotice notice, CancellationToken cancellationToken) =>
        await mail.SendAsync(notice.Sender.Contact, "Documento rechazado", notice.Text, cancellationToken);
}
```

When `NotifyAsync` throws, `VerifyAsync` records the notice as not delivered and throws `IofeAccreditationException`
with `NoticeNotDelivered`.

This agent does not sign the documents it receives. A product that must do so uses an `IofeSigningAgent`.

## Time-stamps (section 4.4)

`IofeTimestampAuthority(Uri endpoint, X509Certificate2 certificate)`; with `Authorization` or `ClientCertificate` when
the authority asks for them. The certificate is mandatory: a token signed by any other is refused. The checks are in
the administration manual, section 8.

## Trust

| | |
|---|---|
| `IofeTrust.IndecopiList()` (the default) | INDECOPI's list, verified and kept current. Takes `IofeExtensionOptions` (`CacheFile`, `TrustedListSigners`, `HttpClientProvider`) |
| `IofeTrust.List(extension)` | A list the application has loaded (`IofeExtension.Load`, `LoadRefreshableAsync`) and keeps current itself |
| `IofeTrust.ListFile(path, signers)` | A copy of the list kept as a file (`--tsl FILE` on the command line). It is read and checked when the agent is created, as the downloaded one is: a signing agent that does not open because the list was refused leaves that in the audit trail (`AgentNotOpened`). It is read once |
| `IofeTrust.InstalledRoots(roots)` | Root certificates installed by the operator |

## Viewer (Req. 18, 28)

```csharp
string page = await agent.Viewer.RenderAsync(signed.Document);             // or verifier.Viewer
await using var viewer = await IofeViewer.CreateAsync();                    // for a relying party
```

It returns a self-contained HTML page, in Spanish.

## Audit

`ISignatureAuditSink` (signatures) and `IVerificationAuditSink` (verifications) are interfaces: you may write to
another store. The implementations included, `JsonLinesAuditSink` and `JsonLinesVerificationAuditSink`, write one
JSON object per line, chained by digest; `Verify(path)` returns 0 or the number of the first line that breaks the
chain. A sink that fails makes the operation fail.

## Contingency

```csharp
Contingency = new IofeContingency("PROC-AAC-07", from, until)
```

See the administration manual, section 5. `TimeProvider` lets a test set the clock.

## Network

`HttpClientProvider` (`IHttpClientProvider`) gives the HTTP client of the CRL, OCSP and time-stamp requests, and its
outbound policy (`OutboundPolicy`): proxy, allowed hosts and `AllowLdap = true` for CRLs published over LDAP.

## Testing

To test without an HSM: SoftHSM2 as the PKCS#11 module and the SimpleSign Sandbox as the test PKI (CRL, OCSP, TSA,
trusted list and a remote signing service, with failures to switch on). The package's tests are in
`tests/unit/Extensions/Peru/Iofe/SimpleSign.Peru.Iofe.Accredited.Tests`: those of the key in a remote service run on
any machine; the token ones, with `scripts/tests/pkcs11.sh`. Each test that shows an item of annex B carries the
trait `AnnexB` (`dotnet test --filter "AnnexB=F-8"`).

The script `src/Extensions/Peru/Iofe/tools/auditoria/auditoria.py` runs `simplesign iofe` for each item of annex B
against the Sandbox and keeps the evidence: see the [audit walk-through](../../audit-walkthrough.md).
