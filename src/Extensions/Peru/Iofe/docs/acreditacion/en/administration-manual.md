# Administration manual

For whoever installs, configures and operates a solution built on `SimpleSign.Peru.Iofe.Accredited`.
(English translation of [`manual-de-administracion.md`](../manual-de-administracion.md); the Spanish text is the one
handed to INDECOPI.)

## 1. Requirements

- .NET 8 or .NET 10 on Windows, Linux or macOS.
- To sign: a cryptographic module (HSM) with a PKCS#11 driver, certified FIPS 140-2 or Common Criteria EAL 4+,
  holding the signing key and its certificate issued by a Certification Authority accredited by INDECOPI.
- Outbound network access to: the CRL distribution points and OCSP services of the certificate's chain, the
  time-stamp authority (if used) and `https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml`.

## 2. Installation

```bash
dotnet add package SimpleSign.Peru.Iofe.Accredited
```

For the command line, install the tool and, in it, the IOFE extension:

```bash
dotnet tool install --global SimpleSign.Cli
simplesign extension install SimpleSign.Peru.Iofe.Cli
simplesign extension list
```

The extension is kept in `~/.simplesign/extensions/iofe` (or in the folder `SIMPLESIGN_EXTENSIONS_DIR` names).
`extension install` shows where the package came from and its SHA-512 digest: keep them as the installation record.
To install without Internet access, download the package and use `--source <folder>`.

### Checking the authenticity of the software (Req. 17, 27)

Before deploying, check the signature of each package downloaded:

```bash
dotnet nuget verify SimpleSign.Peru.Iofe.Accredited.<version>.nupkg --all
```

The result shows the signature and the certificate used; keep it as the installation record. nuget.org signs every
package it distributes (repository signature).

> **Pending on the vendor's side.** The guide also asks that the application be signed with a code-signing certificate
> issued by a CA the operating systems recognize. The author signature of the packages and the Authenticode signature
> of the assemblies depend on that certificate and are not part of the release yet. Until then the package alone does
> not meet this requirement: whoever accredits a product must sign its own installer or executable with its own
> code-signing certificate.

## 3. The private key: a cryptographic module or a remote signing service (Req. 15)

The library signs in two ways **only**, and in both the private key stays inside a cryptographic module and the
library never reads, exports or copies it:

- in the **operator's cryptographic module**, through PKCS#11 (`Module`);
- in a **remote signing service** that keeps the key in its own module (`RemoteService`): the library sends the hash
  of what it signs and receives the signature.

One of the two is given, never both. It does not accept certificate files with a key (PKCS#12 / PFX) nor keys in
memory: see [3.3](#33-pkcs12--pfx-files-outside-the-scope).

### 3.1 Cryptographic module (PKCS#11)

On opening the module it checks the following and, when a check fails, refuses the operation and records it in the
audit trail:

| Check | Refusal |
|---|---|
| The driver reports the key as sensitive (`CKA_SENSITIVE`) and not extractable (`CKA_EXTRACTABLE` false) | `KeyNotInModule` |
| The token's manufacturer and model are those declared in `ModuleDeclaration` | `ModuleMismatch` |

To see the manufacturer and the model as the driver reports them:

```bash
simplesign pkcs11 list --lib /path/to/driver.so
```

The module's FIPS 140-2 or Common Criteria certification **cannot be checked by software**: it is a declaration of
the operator (`Certification`, `CertificateNumber`) which the auditor compares with the manufacturer's certificate.

**The certificate's chain.** The agent builds it, in this order, from the certificates in the module, those the
operator gives (`ChainCertificates`, `--chain file`), those of the trusted list and, when an issuer is still missing,
the one downloaded from the address the certificate itself names (AIA). No certificate given or downloaded widens the
trust: the chain must end in a root of the trusted list. When an issuer is missing, the signature is refused with
`UntrustedRoot` and the message says which.

### 3.2 Remote signing service

The service must speak the *Cloud Signature Consortium API v2* (the protocol of ETSI TS 119 432). The agent signs
unattended, so it authenticates with the service's own means: a service token or client credentials (`ClientId`,
`ClientSecret`), which it renews when the token expires, and the credential's PIN. It takes no one-time password and
no login a person has to complete.

On opening the service it checks the following and, when a check fails, refuses the operation and records it in the
audit trail:

| Check | Refusal |
|---|---|
| The name the service reports about itself (`info`) is the one declared in `RemoteServiceDeclaration`. It is checked **before** the client secret or the PIN is sent to it | `RemoteServiceMismatch` |
| The credential is authorized without a person (mode `explicit` or `implicit`, not `oauth2code`) | `RemoteAuthorizationNotUnattended` |
| The service's address is `https` | configuration error |

To see the name the service reports and its credentials:

```bash
simplesign csc list --csc-url https://provider.example.pe/csc/v2/ --csc-token env:CSC_TOKEN
```

Every audit record of a signature made — or refused — with the remote key carries the provider in the name of the
policy, which ends in `(firma remota: <provider>)`.

What **cannot be checked by software** and stays a declaration of the operator (`Accreditation`,
`AccreditationReference`), which the auditor compares with the resolution or the certificate:

- that the provider is accredited by INDECOPI as a remote signature service (Resolución 175-2024/DGI-INDECOPI) or
  that its signing device is certified (EN 419 241-2, EN 419 221-5);
- that the key is not extractable: the protocol does not report it, unlike PKCS#11. The service's certification is
  what guarantees it.

With the key in a remote service, the cryptographic module is not part of the solution: the custody controls of the
next section are the service provider's.

### 3.3 PKCS#12 / PFX files: outside the scope

A PKCS#12 (PFX) file is a copy of the private key, and signing with it is a key operation in the application's
memory. That contradicts Req. 15 (operations only inside the certified module, no copies of the key), so
`IofeSigningAgent` and `simplesign iofe sign` **do not accept one**, and no option enables it.

Whoever needs to sign with a PFX — tests, or uses that do not need the accreditation — can do so with SimpleSign's
general signers under the IOFE profile, which apply the same checks of the certificate:

```bash
simplesign sign document.pdf --cert certificate.pfx --password <password> --profile iofe -o signed.pdf
```

```csharp
var iofe = await IofeProfile.LoadAsync();
byte[] signed = await PadesSigner.Document(pdf).WithCertificate(certificate).WithProfile(iofe).SignAsync();
```

Those signatures **are outside the scope of the accreditation**: they do not meet Req. 15 nor what depends on it (key
in a certified module, no copies), and they do not go through the agent (defined transactions, mandatory audit).

### What is the operator's

The following controls of the guide concern the operation of the module and cannot be exercised by a library. They
must be in the operator's procedures:

- access to the private key and its copies under the control of at least two people, from its generation;
- keys imported and exported encrypted, under a key controlled by two people;
- audit records of the key's generation, export, transport, revocation, expiry and deletion (the cryptographic module
  produces them);
- physical protection of the module under two-person control, with its movements and those of its backups recorded,
  and its administration assigned to roles under contractual responsibility;
- the certificate requested in PKCS#10;
- revocation requested at once when the key is compromised.

## 4. Trust: the trusted list (TSL)

By default INDECOPI's list is trusted. On each load the library:

1. checks the list's signature against the certificate INDECOPI signs it with (included in the package
   `SimpleSign.Peru.Iofe`; another can be given with `TrustedListSigners` or `--tsl-signer`);
2. refuses the list when its next update has passed;
3. refuses a list with a sequence number lower than the current one's;
4. downloads it again every 6 hours and when its next update comes, without interrupting the operations under way.

With `CacheFile` the last valid copy is kept, and used when the download fails while the list is still current.

> Confirm with INDECOPI, through an independent channel, the fingerprint of the certificate that signs the list before
> putting the solution into production. The fingerprint of the bundled copy is in
> `src/Extensions/Peru/Iofe/docs/iofe.md`.

As an alternative (the guide's "manual query"), `IofeTrust.InstalledRoots` or `--trust-root` limit trust to the root
certificates the operator installs.

## 5. The checks of the certificate: always on (Req. 11–14, 21–24)

Before each signature, and for each signature of a received document, the following is checked:

| Check | Reason of refusal |
|---|---|
| The certificate chains to a trusted root | `UntrustedRoot` |
| Neither the certificate nor any of its chain is revoked (OCSP or CRL) | `CertificateRevoked` |
| The revocation status could be obtained; the CRL is signed by its CA, current and has a next update | `RevocationStatusUnknown` |
| The certificate and its chain have not expired | `CertificateExpired`, `ChainCertificateNotValid` |
| The certificate has the nonRepudiation bit | `KeyUsageNotPermitted` |
| RSA of 2048 bits or more, or ECDSA of 256 or more; SHA-2 or SHA-3; no SHA-1 nor MD5 in the chain | `KeyTooWeak`, `AlgorithmNotPermitted` |

There is no parameter, file or environment variable that switches these checks off. The command line refuses an
option it does not have.

### Contingency

The one exception is the one the guide foresees: a contingency operated under a procedure INDECOPI approved. It is
declared with the reference of the procedure and its validity:

```csharp
Contingency = new IofeContingency("PROC-AAC-07", from, until)
```

While it is in force, a document is signed or accepted even though the revocation status **cannot be obtained**. A
certificate known to be revoked or expired is still refused. Every audit record made under a contingency carries the
reference of the procedure. Once its validity is over, every operation is refused (`ContingencyExpired`) until the
declaration is removed.

## 6. Kinds of transaction (Req. 14)

The signing agent is configured with the closed list of the kinds of transaction it signs for (`Transactions`). A
signature asked for another kind is refused (`TransactionNotAllowed`) and recorded. Administrator rights over the
system give no other way: the only way to sign is `Sign…Async(document, transaction)`.

## 7. Audit records (Req. 14, 24)

| Record | Content |
|---|---|
| Signatures (`JsonLinesAuditSink`) | Each signature made or refused: time, format, transaction (`type/id`), level, result and reason, certificate (subject, issuer, serial, SHA-256), policy and its digest, SHA-256 of the input and of the output |
| Verifications (`JsonLinesVerificationAuditSink`) | Each document verified: time, format, SHA-256, sender, reference, accepted or rejected, the indication of each signature, reasons, whether the notice was delivered, policy, contingency |

An agent is not created without its audit sink (`AuditMissing`), and an operation is not returned before its record
is written. A signing agent that does not get to open is recorded too (`AgentNotOpened`, with the reason): the
trusted list could not be read, the module refused the PIN, the remote service refused the agent or the
configuration is incomplete.

Each line carries the digest of the one before, so a line changed, removed or inserted breaks the chain:

```bash
simplesign audit verify /var/log/firma/auditoria.jsonl
simplesign audit verify /var/log/firma/verificacion.jsonl
```

The chain shows tampering, it does not prevent it: keep the files where the application's account cannot rewrite
them, and send a copy to an external system.

## 8. Time-stamps (section 4.4)

The authority is configured with its address and **its certificate**. Of each token received, before the signature is
returned, the following is checked:

| Check | Reason of refusal |
|---|---|
| The token carries the identifier of the certificate of the authority asked | `TimestampUntrusted` |
| The token's signature is valid and the token is over what was sent | `TimestampInvalid` |
| The authority's certificate chains to a trusted root | `TimestampUntrusted` |
| The authority's certificate is not revoked | `TimestampCertificateRevoked`, `TimestampRevocationStatusUnknown` |
| The authority's certificate has not expired | `TimestampCertificateNotValid` |

INDECOPI's list says which authorities are accredited, not their address: ask your provider for it.

## 9. Access control (Req. 14, 24)

The library opens no port and exposes no service. Protection against unauthorized access belongs to the system that
hosts it: authentication of whoever asks for signatures, a service account without privileges, restriction of the
network and of access to the cryptographic module.

## 10. Notice to the sender (section 4.3)

When a received document is rejected, the agent writes the notice and hands it to the configured means (`Notifier`), with the reasons in Spanish.
If the delivery fails, the verification fails (`NoticeNotDelivered`) and the record says so: a document is never
rejected in silence.
