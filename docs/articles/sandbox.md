# SimpleSign Sandbox

The Sandbox is a test PKI with its services on real network endpoints: certificate authorities,
CRLs over HTTP, HTTPS and LDAP, an OCSP responder, RFC 3161 timestamping authorities and a CSC v2
cloud-signing service, with failures you can switch on. It runs on its own, apart from the
application under test, so any client reaches it the way it reaches a real PKI: the TestBench,
the CLI, the Agent, your own application, or another validator such as DSS.

It simulates what a real PKI does, including what goes wrong: a certificate revoked by CRL or
OCSP, a revoked or expired CA, a CRL that expired, is signed by the wrong key or is stale, a
responder that is down or not authorized, an expired certificate. Each case is a certificate or
a failure the Sandbox has ready.

```bash
dotnet run --project src/Apps/SimpleSign.Sandbox                 # http://localhost:5300, opens the browser
dotnet run --project src/Apps/SimpleSign.Sandbox -- --name lab2 --port 5310 --no-browser
```

The test certificates and keys are for tests only. Never trust the Sandbox root in a validator
used for real signatures.

## Endpoints

| Service | Address (default environment) |
|---|---|
| UI and admin API | `http://localhost:5300/`, `/api/…` (admin answers loopback only) |
| Root and chain | `/root.pem`, `/chain.pem`, AIA `/aia/{ca}.cer` |
| CRLs over HTTP | `/crl/{ca}.crl` |
| CRLs over HTTPS | `https://localhost:5301/crl/{ca}.crl` (TLS certificate issued by the Sandbox root) |
| CRLs over LDAP | `ldap://localhost:5302/cn={ca},o=SimpleSign Sandbox?certificateRevocationList;binary` |
| OCSP (RFC 6960) | `POST /ocsp/{ca}` and `GET /ocsp/{ca}/{request}` |
| TSA (RFC 3161) | `/tsa/tsr`, `/tsa/authenticated` (HTTP Basic), `/tsa/untrusted`, `/tsa/revoked`, `/tsa/wrong-name` |
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
| `--no-browser` | Do not open the UI |

## The PKI

A root, an intermediate CA that issues the signers, a second intermediate that the root has
revoked, and a third that has expired. Each certificate has a purpose:

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
| `rsa-1024` | Refuses: key too weak |
| `no-signing-key-usage` | Refuses: no digitalSignature or nonRepudiation |
| `no-nonrepudiation` | Signs; some validation policies flag it |
| `tsa`, `tsa-revoked` | The TSAs' certificates |

Every signer can be downloaded as a PKCS#12 (password in `GET /api/info`). **Revoke now** adds a
certificate to its CA's CRL and OCSP answers at once (or to one of them only); **Back to normal**
puts every revocation and failure back.

## Failures

| Service | Failures |
|---|---|
| CRL (HTTP, HTTPS, LDAP) | down, slow, expired (nextUpdate passed), signed by the wrong key, stale (the CRL published before the last revocation: a copy cached before it) |
| OCSP | down, slow, tryLater, expired response, signed by an unauthorized responder, unknown for every certificate; delegated responder (OCSPSigning, `id-pkix-ocsp-nocheck`) |
| TSA | down, slow, invalid token |
| Trusted list | expired (NextUpdate passed), signed by a certificate the LOTL does not name, changed after signing |

Every request is in the **Requests** tab (service, URL, status, the failure applied). The Sandbox keeps
the last 500; the tab shows them 50 at a time.

The TestBench signs with each of these certificates and failures under the Strict signing policy
in `SandboxScenarioTests`.

## Admin API

Everything the UI does goes through this API, so another app (the TestBench, the Playbook, a test
suite) can drive the Sandbox the same way. JSON is camelCase with enums as names. Every route except
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
| `POST /api/certificates/short-lived?seconds=3` | Issues a signer that expires in 1–3600 s | | `application/x-pkcs12` |
| `GET /api/faults` | The failures | | `SandboxFaults` |
| `PUT /api/faults` | Replaces every failure | `SandboxFaults` (fields left out take their default) | `SandboxFaults` |
| `PATCH /api/faults` | Changes only the fields sent | any subset of `SandboxFaults` | `SandboxFaults` |
| `DELETE /api/faults` | Every failure off (the delays and `ocspSigner` stay) | | `SandboxFaults` |
| `GET /api/log` | Requests answered, oldest first | `after` (id), `limit` (1–500: the newest N), `service` (`AIA`, `CRL`, `CRL (LDAP)`, `OCSP`, `TSA`, `CSC`, `TL`) | `SandboxRequest[]` |
| `DELETE /api/log` | Clears the request log | | 204 |
| `POST /api/reset` | Back to the initial state: revocations, failures off, log cleared | | 204 |

`SandboxFaults` fields: `tsa` (`None`, `Down`, `Slow`, `InvalidToken`, `Untrusted`), `crl` (`None`,
`Down`, `Slow`, `Expired`, `WrongKey`, `Stale`), `ocsp` (`None`, `Down`, `Slow`, `TryLater`, `Expired`,
`Unauthorized`, `Unknown`), `ocspSigner` (`Issuer`, `Delegated`), `trustedList` (`None`, `Expired`,
`WrongSigner`, `Tampered`), and `tsaDelayMs`, `crlDelayMs`, `ocspDelayMs` (0–60000, used when `Slow`).

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
- the revoked TSA (withdrawn).

`/tl/lotl.xml` is a list of trusted lists that points to it. Each list is signed by its own scheme operator, as
TS 119 612 §5.7.1 asks: an enveloped XAdES signature whose only transforms are the enveloped one and exclusive
canonicalization. The operators' certificates are kept with the environment.

A validator given the LOTL and `/tl/lotl-signer.pem` trusts the Sandbox's chains through the trusted list, and judges the
service type and status and the `TrustedLists` constraints (TLWellSigned, TLNotExpired…), instead of trusting a bare root:

```bash
simplesign validate signed.pdf --lotl http://localhost:5300/tl/lotl.xml --lotl-signer lotl-signer.pem
```

The TestBench does this by default (trust "Sandbox trusted list"), and so does the DSS container in `tools/dss`.

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
