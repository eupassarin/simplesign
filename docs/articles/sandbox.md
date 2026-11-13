# SimpleSign Sandbox

The Sandbox is a test PKI with its services on real network endpoints: certificate authorities,
CRLs over HTTP, HTTPS and LDAP, an OCSP responder, RFC 3161 timestamping authorities and a CSC v2
cloud-signing service, with failures you can switch on. It runs on its own, apart from the
application under test, so any client reaches it the way it reaches a real PKI: the TestBench,
the CLI, the Agent, your own application, or another validator such as DSS.

It is a service with an API and no page of its own: its UI is the TestBench's **Sandbox** control
(connect, then the PKI, failures and request log), and every other client drives it through the same
[admin API](#admin-api), so a Sandbox set up by a playbook, a test suite or `curl` serves any validator
without the TestBench.

It simulates what a real PKI does, including what goes wrong: a certificate revoked by CRL or
OCSP, a revoked or expired CA, a CRL that expired, is signed by the wrong key or is stale, a
responder that is down or not authorized, an expired certificate. Each case is a certificate or
a failure the Sandbox has ready.

```bash
dotnet run --project src/Apps/SimpleSign.Sandbox                 # http://localhost:5300 (API only)
dotnet run --project src/Apps/SimpleSign.Sandbox -- --name lab2 --port 5310
```

It also runs in Docker (`src/Apps/SimpleSign.Sandbox/Dockerfile`). [`tools/stack`](../../tools/stack/README.md)
starts it with DSS and fills a local SoftHSM token with its certificates, ready for the TestBench:
`tools/stack/up.sh`, then `tools/stack/testbench.sh` (on Windows: `pwsh -File tools/stack/up.ps1`, then
`pwsh -File tools/stack/testbench.ps1`).

The test certificates and keys are for tests only. Never trust the Sandbox root in a validator
used for real signatures.

## Endpoints

| Service | Address (default environment) |
|---|---|
| Admin API | `http://localhost:5300/api/…` (admin answers loopback only); `/` says where the API and the UI are |
| Root and chain | `/root.pem`, `/chain.pem`, AIA `/aia/{ca}.cer` |
| CRLs over HTTP | `/crl/{ca}.crl` |
| CRLs over HTTPS | `https://localhost:5301/crl/{ca}.crl` (TLS certificate issued by the Sandbox root) |
| CRLs over LDAP | `ldap://localhost:5302/cn={ca},o=SimpleSign Sandbox?certificateRevocationList;binary` |
| OCSP (RFC 6960) | `POST /ocsp/{ca}` and `GET /ocsp/{ca}/{request}` |
| TSA (RFC 3161) | `/tsa/tsr`, `/tsa/authenticated` (HTTP Basic), `/tsa/untrusted`, `/tsa/revoked`, `/tsa/expired`, `/tsa/wrong-name`, `/tsa/shifted?seconds=N` (its clock is N seconds off, -86400 to 86400), `/tsa/no-accuracy` (no accuracy in the TSTInfo; the others give one second, as EN 319 422 asks), `/tsa/short-lived?seconds=N` (a TSA certificate issued for the request, valid N more seconds, 1 to 3600: its tokens outlive it), `/tsa/iofe` (a TSA under its own self-signed CA, trusted only through `/tl/tl.xml` read with the IOFE profile) |
| CSC v2 | `/csc/v2/…` (PIN, OTP, SCAL 1/2, OAuth with a login page that approves at once) |
| Trusted lists (ETSI TS 119 612 v5) | `/tl/lotl.xml` (list of trusted lists), `/tl/tl.xml` (the trusted list), `/tl/lotl-signer.pem`, `/tl/tl-signer.pem` (the operators' certificates) |

The HTTPS endpoint listens on the port after the HTTP one and LDAP on the one after that
(`--https-port`, `--ldap-port` change them).

## Environments

An environment is a named set of keys, certificates, revocations and failures, kept in
`%LocalAppData%/SimpleSign/Sandbox/<name>/` (`--name`, `--data-dir`). Its root stays the same
between runs, so a validator that trusts it keeps trusting it.

The address written into the certificates (CRL distribution points, AIA, OCSP) is fixed when the
environment is created: `http://localhost:<port>` unless `--public-base-url` says otherwise.
Create another environment to use another address, for instance one a Docker container reaches
(see `tools/dss/README.md`).

| Option | Meaning |
|---|---|
| `--name NAME` | The environment (default `default`) |
| `--port N` | HTTP port (default 5300); HTTPS and LDAP use the next two |
| `--public-base-url URL` | The address written into new certificates |
| `--ephemeral` | A new environment in a temporary folder, deleted on exit (CI) |
| `--listen-any` | Listen on every interface (a lab network); the admin API still answers loopback only |
| `--allow-remote-admin` | Let the admin API answer other machines too |
| `--signing-country XX` | The country (C) of the seeded signers' subject when the environment is created (default `BR`; `none` for no C) |

## The PKI

A root, an intermediate CA that issues the signers, a second intermediate that the root has
revoked, a third that has expired, and a fourth whose certificate the root signed with SHA-1; and, apart from the root,
a self-signed Timestamping CA (`tsa-ca`) that issues the TSA of `/tsa/iofe` only.
An environment created before a CA was added gets it the next time it opens (its root stays). Each certificate has a purpose:

| Certificate | What a correct client does |
|---|---|
| `rsa-2048`, `rsa-3072`, `rsa-4096`, `ecdsa-p256/384/521` | Signs; validation is TOTAL-PASSED |
| `revoked` | Refuses to sign (revoked in the CRL over HTTP and by OCSP) |
| `revoked-ocsp`, `good-ocsp` | OCSP only, no CRL distribution point |
| `revoked-crl-https`, `good-crl-https` | Only CRL over HTTPS |
| `revoked-crl-ldap`, `good-crl-ldap` | Only CRL over LDAP |
| `under-revoked-ca` | Refuses: its issuing CA is revoked in the root's CRL |
| `expired`, `not-yet-valid` | Refuses: outside its validity |
| `under-expired-ca` | Refuses: its issuing CA expired |
| `under-sha1-ca` | Refuses under a policy that rejects SHA-1: the root signed its issuing CA with SHA-1 |
| `rsa-1024` | Refuses: key too weak |
| `no-signing-key-usage` | Refuses: no digitalSignature or nonRepudiation (keyEncipherment only) |
| `no-key-usage-extension` | No KeyUsage extension at all: refused by a policy that requires a signing key usage |
| `no-nonrepudiation` | Signs; some validation policies flag it |
| `tsa`, `tsa-revoked`, `tsa-expired` | The TSAs' certificates (`/tsa/tsr`, `/tsa/revoked`, `/tsa/expired`) |
| `tsa-iofe` | The TSA of `/tsa/iofe`, under `tsa-ca`: trusted only through a list reader that keeps the `unspecified` service naming that CA (`/tl/tl.xml` with the IOFE profile) |
| `code-signing` | A code-signing certificate (EKU codeSigning), listed in `/tl/tl.xml` as signature software (`unspecified`): never a trust anchor |

Signers with a chosen subject (`POST /api/certificates/custom`) are issued by the intermediate CA
and listed with the others (id `custom-…`), so they can be revoked and downloaded the same way;
**Back to normal** removes them. For instance, a Peruvian DNI signer:

```bash
curl -X POST http://localhost:5300/api/certificates/custom -H "Content-Type: application/json" \
  -d '{"subject":"CN=Juan Pérez, serialNumber=PNOPE-12345678, C=PE","keyType":"EcdsaP256"}'
```

Every signer can be downloaded as a PKCS#12 (password in `GET /api/info`). **Revoke now** adds a
certificate to its CA's CRL and OCSP answers at once (or to one of them only); **Back to normal**
puts every revocation and failure back.

## Failures

| Service | Failures |
|---|---|
| CRL (HTTP, HTTPS, LDAP) | down, slow, expired (nextUpdate passed), signed by the wrong key, stale (the CRL published before the last revocation: a copy cached before it), no nextUpdate |
| OCSP | down, slow, tryLater, expired response, signed by an unauthorized responder, unknown for every certificate; delegated responder (OCSPSigning, `id-pkix-ocsp-nocheck`) |
| TSA | down, slow, invalid token |
| Trusted list | expired (NextUpdate passed), signed by a certificate the LOTL does not name, changed after signing |

Every request is in the request log (`GET /api/log`; the **Requests** tab of the TestBench's Sandbox control):
service, URL, status, the failure applied. The Sandbox keeps the last 500; the tab shows them 50 at a time.

The TestBench signs with each of these certificates and failures under the Strict signing policy
in `SandboxScenarioTests`.

## Admin API

Everything the TestBench's Sandbox control does goes through this API (passed through by the TestBench at
`/api/sandbox/admin/…`, so the page talks to one origin), so another client (a test suite, `curl`, DSS)
drives the Sandbox the same way, with or without a TestBench, and what one client changes the others see. JSON is camelCase with enums as names. Every route except
`GET /api/info` answers loopback only (HTTP 403 otherwise), unless the Sandbox starts with
`--allow-remote-admin`.

| Route | Does | Body / query | Answers |
|---|---|---|---|
| `GET /api/info` | Addresses and test credentials of this Sandbox | | `SandboxInfo` |
| `GET /api/pki` | The CAs, the TSA outside the chain and every certificate | | `PkiView` |
| `GET /api/certificates/{id}` | One certificate | | `CertificateView`, 404 if unknown |
| `GET /api/certificates/{id}/pfx` | Its PKCS#12 (password in `pfxPassword`) | | `application/x-pkcs12` |
| `GET /api/certificates/{id}/cer` | Its certificate (DER) | | `application/pkix-cert` |
| `POST /api/certificates/{id}/revoke` | Revokes it now | `{"reason": "KeyCompromise", "publication": "Both" \| "CrlOnly" \| "OcspOnly"}` (both optional) | `CertificateView`, 400 for an unknown reason |
| `POST /api/certificates/{id}/unrevoke` | Takes the revocation back | | `CertificateView` |
| `POST /api/certificates/custom` | Issues a signer with a chosen subject under the intermediate CA (revocable, downloadable, removed by reset; at most 200) | `{"subject": "CN=…, serialNumber=…, C=PE"}` or `{"rdns": [{"type": "CN", "value": "…"}, …]}` (most specific first); optional `keyType` (`Rsa2048` default, `Rsa3072`, `Rsa4096`, `EcdsaP256/384/521`), `keyUsage` (`DigitalSignature`, `NonRepudiation`, `KeyEncipherment`, `DataEncipherment`, `KeyAgreement`; default the first two; `[]` for no extension), `title`, `validityDays` (1–825, default 365). Accepted attributes: `CN` (required), `serialNumber`, `C`, `O`, `OU`, `L`, `ST`, `T`, `G`/`GN`, `SN`, `organizationIdentifier`; 1–64 characters, 16 at most | 201 `CertificateView`, 400 for an invalid subject |
| `POST /api/certificates/short-lived?seconds=3` | Issues a signer that expires in 1–3600 s (valid from two hours back, before the CRLs and OCSP responses it is checked against) | | `application/x-pkcs12` |
| `GET /api/faults` | The failures | | `SandboxFaults` |
| `PUT /api/faults` | Replaces every failure | `SandboxFaults` (fields left out take their default) | `SandboxFaults` |
| `PATCH /api/faults` | Changes only the fields sent | any subset of `SandboxFaults` | `SandboxFaults` |
| `DELETE /api/faults` | Every failure off (the delays and `ocspSigner` stay) | | `SandboxFaults` |
| `GET /api/log` | Requests answered, oldest first | `after` (id), `limit` (1–500: the newest N), `service` (`AIA`, `CRL`, `CRL (LDAP)`, `OCSP`, `TSA`, `CSC`, `TL`) | `SandboxRequest[]` |
| `DELETE /api/log` | Clears the request log | | 204 |
| `POST /api/reset` | Back to the initial state: revocations, failures off, log cleared, signers issued on request removed | | 204 |

`SandboxFaults` fields: `tsa` (`None`, `Down`, `Slow`, `InvalidToken`, `Untrusted`), `crl` (`None`,
`Down`, `Slow`, `Expired`, `WrongKey`, `Stale`, `NoNextUpdate`), `ocsp` (`None`, `Down`, `Slow`, `TryLater`, `Expired`,
`Unauthorized`, `Unknown`), `ocspSigner` (`Issuer`, `Delegated`), `trustedList` (`None`, `Expired`,
`WrongSigner`, `Tampered`, `WithdrawnAfterUse`: the root CA's service withdrawn now and granted before, in its
service history), and `tsaDelayMs`, `crlDelayMs`, `ocspDelayMs` (0–60000, used when `Slow`).

```bash
# CRL server down, the other failures as they are
curl -X PATCH http://localhost:5300/api/faults -H 'Content-Type: application/json' -d '{"crl":"Down"}'
# OCSP slow, 5 s
curl -X PATCH http://localhost:5300/api/faults -H 'Content-Type: application/json' -d '{"ocsp":"Slow","ocspDelayMs":5000}'
# Every failure off
curl -X DELETE http://localhost:5300/api/faults
# Revoke a signer in the CRL only
curl -X POST http://localhost:5300/api/certificates/rsa-2048/revoke -H 'Content-Type: application/json' -d '{"reason":"KeyCompromise","publication":"CrlOnly"}'
# The last 20 CRL requests
curl 'http://localhost:5300/api/log?service=CRL&limit=20'
```

## The trust scheme

The Sandbox is also a trust scheme, as an EU member state is. `/tl/tl.xml` is a trusted list (territory `ZZ`) with:
- the root CA (`Svctype/CA/QC`, granted);
- the TSA (`Svctype/TSA/QTST`, granted);
- the revoked TSA (withdrawn);
- the Timestamping CA (`Svctype/unspecified`, granted): the CA of the `/tsa/iofe` TSA;
- a signature software, listed with its code-signing certificate (`Svctype/unspecified`, granted).

The last two are typed as INDECOPI types them in Peru's list: see [below](#reading-it-as-indecopis-list).

`/tl/lotl.xml` is a list of trusted lists that points to it. Each list is signed by its own scheme operator, as
TS 119 612 §5.7.1 asks: an enveloped XAdES signature whose only transforms are the enveloped one and exclusive
canonicalization. The operators' certificates are kept with the environment.

A validator given the LOTL and `/tl/lotl-signer.pem` trusts the Sandbox's chains through the trusted list, and judges the
service type and status and the `TrustedLists` constraints (TLWellSigned, TLNotExpired…), instead of trusting a bare root:

```bash
simplesign validate signed.pdf --lotl http://localhost:5300/tl/lotl.xml --lotl-signer lotl-signer.pem
```

The TestBench does this by default (trust "Sandbox trusted list"), and so does the DSS container in `tools/dss`.

### Reading it as INDECOPI's list

INDECOPI's list (`https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml`) types its TSAs and the accredited signature software
`Svctype/unspecified`, and for a TSA it names the **CA** (the Llama.pe Timestamping CA), not the TSA.
`IofeExtension.DefaultListOptions` keeps the active `unspecified` services as anchors, except a certificate whose EKU is
code signing. Reading `/tl/tl.xml` with those options shows both rules on the Sandbox:
- the `/tsa/iofe` TSA chains to the Timestamping CA, an anchor only with the IOFE options: with the default options
  (and with the root as a bare anchor) its time-stamps are untrusted;
- the code-signing certificate is never an anchor.

The rest of the list (version, vocabulary, territory) is read the same way in both layouts, and the library's tests
read INDECOPI's real list (`tests/unit/TrustFrameworks/Peru/Iofe`), so the Sandbox does not copy its layout.

```csharp
var list = await TrustedList.DownloadAsync(new Uri("http://localhost:5300/tl/tl.xml"),
    IofeExtension.DefaultListOptions with { SignerCertificates = [tlSigner] });
var iofe = new IofeExtension(list);
```

The iofe profile reads the same list when it is pointed at the Sandbox: `--sandbox URL` fetches the list's signer from
the Sandbox (a test PKI); `--tsl … --tsl-signer … --tsl-profile iofe` does the same by hand.

```bash
simplesign validate signed.pdf --profile iofe --sandbox http://localhost:5300
simplesign validate signed.pdf --tsl http://localhost:5300/tl/tl.xml --tsl-signer tl-signer.pem --tsl-profile iofe --policy iofe
```

In the TestBench it is the Profile menu's "Peru (IOFE) · Sandbox's list (test)" (`"profile": "Iofe", "profileSource":
"Sandbox"`), and the TSA "Sandbox TSA under its own CA (IOFE)" (`SandboxIofe`); the `indecopi-guia-v4` playbook uses
both. DSS reads the list
through the LOTL and trusts every granted service in it, whatever its type.

## Using it from a client

A client must trust the Sandbox root (`/root.pem`) and must be allowed to reach it: SimpleSign's
outbound policy refuses `localhost` by default (SSRF guard). List the Sandbox's origins, which
`GET /api/info` gives as `loopbackOrigins`:

```csharp
var http = new SingleClientProvider(new HttpClient(handlerThatTrustsTheSandboxRootForTls))
{
    OutboundPolicy = new OutboundHttpPolicy
    {
        AllowLdap = true,
        LoopbackOrigins = [new Uri("http://localhost:5300"), new Uri("https://localhost:5301"), new Uri("ldap://localhost:5302")],
    },
};

byte[] signed = await PadesSigner.Document(pdf)
    .WithCertificate(certificate, chain)
    .WithHttpClientProvider(http)
    .WithSigningPolicy(SigningPolicy.Load("strict-signing-policy.json")) // NotRevoked: FAIL
    .SignAsync();
```

The [TestBench](testbench.md) does all of this when you connect a Sandbox to it.
