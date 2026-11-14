# SimpleSign.Sandbox

A **test PKI whose services answer on real network endpoints** — so signing and validation take the
same code paths they take in production, without touching a production PKI.

```bash
dotnet run --project src/Apps/SimpleSign.Sandbox -- --ephemeral
```

| | |
|---|---|
| HTTP | `http://localhost:5300` — AIA, CRLs, OCSP, TSA, CSC v2, trusted lists, the admin API |
| HTTPS | `https://localhost:5301` — the same CRLs over TLS, under the Sandbox's own root |
| LDAP | `ldap://localhost:5302` — the same CRLs over LDAP |

**API only.** It has no page of its own: its user interface is the TestBench's **Sandbox** drawer.
The CLI, the playbooks, EU DSS and `curl` use it without a TestBench.

## What it serves

- **A PKI**: a root CA, intermediates (including one signed with SHA-1), and signers for every key
  type — RSA 2048/3072/4096, ECDSA P-256/384/521 — plus the awkward ones: expired, not yet valid,
  revoked, without KeyUsage, with a weak key.
- **Revocation**: CRLs over HTTP, HTTPS and LDAP, and an OCSP responder.
- **Time-stamping**: a plain TSA, one needing Basic auth, and TSAs that are expired, revoked,
  short-lived, clock-shifted, wrongly named, non-qualified or without accuracy.
- **Trusted lists**: `/tl/lotl.xml` and `/tl/tl.xml` (ETSI TS 119 612) and `/tl/iofe.xml`
  (INDECOPI's TS 102 231 v3 layout), each signed by its own scheme operator.
- **Cloud signing**: a CSC v2 service.
- **eIDAS cases**: signers with QC statements, a CA/PKC service, Qualifications and
  AdditionalServiceInformation on the CA/QC service.

## Failures you can switch on

The point of the Sandbox. Through the admin API or the TestBench's drawer you can make the CRL
server go down, serve an expired CRL, a wrongly signed one or one without `nextUpdate`; make a TSA
refuse, stall or return an invalid token; revoke a signer or a whole CA at run time; and break a
trusted list (expired, tampered with, signed by the wrong key), including the LOTL.

That is what the [playbooks](../../../docs/playbooks/) drive to show that validation reaches the
right verdict for the right reason.

## Options

| | |
|---|---|
| `--ephemeral` | A new environment in a temp folder, deleted on exit (what CI uses) |
| `--name NAME` | Keep several environments side by side |
| `--port N` | HTTP port; HTTPS is `N+1` and LDAP `N+2` |
| `--data-dir DIR` | Where kept environments live |
| `--public-base-url URL` | The address written into the certificates, for reaching it from a container |
| `--signing-country XX` | The country of the seeded signers' subject (or `none`) |
| `--listen-any`, `--allow-remote-admin` | Leave loopback — only on a machine you trust |

Without `--ephemeral` the environment is kept by name, so the root and the URLs inside the
certificates stay stable between runs.

A Dockerfile is in this folder, and `tools/stack/up.sh` starts the Sandbox, a SoftHSM token and
EU DSS together.

Full guide: [docs/articles/sandbox.md](../../../docs/articles/sandbox.md). How it fits with the
other apps: [docs/articles/apps.md](../../../docs/articles/apps.md).
