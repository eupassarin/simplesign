# DSS validation service for the TestBench

The TestBench can send every signature it makes to the
[EU DSS](https://github.com/esig/dss) and show its verdict next to SimpleSign's. DSS is an
independent implementation of the validation algorithm of ETSI EN 319 102-1, so a difference
between the two is worth looking at.

This folder runs the DSS demo web application in Docker and exposes its REST validation service.

## Start

Start the Sandbox first (any port), then DSS:

```bash
dotnet run --project src/Apps/SimpleSign.Sandbox -- --ephemeral
docker compose -f tools/dss/docker-compose.yml up -d
```

Or start both in Docker, with a SoftHSM token holding the Sandbox's certificates, through
[`tools/stack`](../stack/README.md): `tools/stack/up.sh`.

Nothing else is needed: DSS trusts the Sandbox's root, reaches its CRLs, OCSP responders and LDAP
server, and fetches revocation data on every request, like SimpleSign. Compose rebuilds the image
on every `up` (`pull_policy: build`; seconds, from the build cache), so a changed entrypoint is
never left out.

The first build downloads the DSS bundle published by the European Commission (353 MB). That
server is slow (about 0.5 MB/s), so allow **around 15 minutes**. The download is kept in the
build cache and resumes if the build is interrupted; later builds reuse it.
When Tomcat is up:

- `http://localhost:8080/` — the DSS demo pages
- `http://localhost:8080/services/rest/validation/validateSignature` — what the TestBench calls

Then, in the TestBench, open **DSS** in the top bar, turn it on and check the address. Every
run is then validated twice, and the **Validation** tab shows both verdicts.

## The validation policy

The TestBench sends SimpleSign's validation policy with every request, written as the DSS `constraint.xml`
(`DssPolicyConverter`, following [the compatibility table](../../docs/policies/compatibility.md)): both validators
judge under the same constraints and levels. Constraints SimpleSign's format does not have are absent, so DSS does not
check them either. What stays apart is the server's own configuration:
its trust store (below) and how it fetches revocation data.

## Trusting the Sandbox certificates

DSS only knows the trust anchors it is given. The test certificates come from the SimpleSign
Sandbox (`src/Apps/SimpleSign.Sandbox`, see [docs/articles/sandbox.md](../../docs/articles/sandbox.md)). There are
two ways to trust them, chosen with `DSS_SANDBOX_TRUST`:

- **`list` (default): through the Sandbox's trusted list.**
  - The Sandbox publishes a list of trusted lists (`/tl/lotl.xml`, signed by `/tl/lotl-signer.pem`), and a trusted list
    with its root CA and TSA as services (`/tl/tl.xml`).
  - The container puts the LOTL operator's certificate in `sandbox-lotl.p12`, and points DSS's LOTL loader at the
    Sandbox's LOTL.
  - DSS then trusts the Sandbox as it trusts the EU: it reports the trusted list, the service type and status, and the
    TL checks (well signed, not expired, version, structure). It no longer says "Unable to build a certificate chain up
    to a trusted list!".
  - With the EU lists off (`DSS_LOAD_EU_TRUSTED_LISTS=false`), the Sandbox's LOTL takes the EU slot (`current.lotl.url`,
    `oj.content.keystore.*`).
  - With the EU lists on, it takes the second slot (`tl.loader.ades.*`), and both are loaded.
  - The loader downloads the lists again every `DSS_TL_REFRESH_SECONDS`: 10 s with the Sandbox's list alone (so a
    trusted-list failure switched on in the Sandbox shows within seconds), one hour with the EU lists.
  - A Sandbox that publishes no trusted list (an older one) falls back to `anchor`.
  - A trusted list or LOTL whose signature fails is not used, as ETSI TS 119 615 asks and as SimpleSign does. The demo
    keeps such a list (its default `AcceptAllStrategy`) and only reports it in the qualification checks, so the image
    adds a small Spring component (`SimpleSignTlSynchronization.java`, compiled into the WAR) that sets the job's
    `ExpirationAndSignatureCheckStrategy`. Expired lists are kept: the policy's `TLNotExpired` judges them.
    `DSS_ACCEPT_INVALID_TRUSTED_LISTS=true` restores the demo's behaviour.
- **`anchor`: the Sandbox root alone, as a bare trust anchor** (`trusted.source.keystore`). DSS validates the chain but
  reports no trusted list.

Either way the container fetches the Sandbox's files when it starts, so start the Sandbox first:

- **Docker Desktop (macOS, Windows):** the root and the LOTL come from `SANDBOX_URL` (default
  `http://host.docker.internal:5300`). The container waits up to `SANDBOX_WAIT_SECONDS` (20 by default) for it. The
  root is also added to the JVM's TLS trust store, so DSS can download the CRLs the Sandbox publishes over HTTPS.
- **Linux, or when the Sandbox was not running:** save the root to this folder and restart the container. This gives
  the `anchor` mode:

  ```bash
  curl http://127.0.0.1:5300/root.pem > tools/dss/trust/sandbox-root.pem
  ```

A new `--ephemeral` Sandbox has a new root and new operators, so start DSS again after it (`docker compose up -d`
recreates the container).

### What the TestBench shows: `/simplesign/config.json`

When it starts, the entrypoint writes what it set up to `http://localhost:8080/simplesign/config.json`
(Tomcat serves the folder `webapps/simplesign` next to the DSS application): the DSS version, how the
Sandbox is trusted (`list`, `anchor`, `testbench` or `none`, its LOTL, whether its root is trusted for TLS),
the EU lists (`false`, `true`, `cached`) and the loader's refresh, `DSS_ACCEPT_INVALID_TRUSTED_LISTS`, the
revocation cache, the ICP-Brasil, Gov.br, public TSA and Peruvian roots (with the Peruvian list's sequence
and next update), and every certificate in the trust store (group, name, subject). The TestBench's **DSS**
popup reads it each time it is opened; a DSS without it (another image, an older build) shows "setup
unknown".

### Letting DSS reach the Sandbox's CRLs, OCSP and LDAP

The Sandbox writes its own address into the certificates: `http://localhost:5300` (CRLs, OCSP,
AIA), `https://localhost:5301` and `ldap://localhost:5302`. Inside the container `localhost` is
the container itself, so the entrypoint forwards those ports from the container's localhost to
the host (`forward.pl`, one per port in `SANDBOX_FORWARD_PORTS`, to `SANDBOX_FORWARD_HOST`).
The certificates keep naming `localhost`, which is what SimpleSign accepts: its outbound policy
only lets a request to a private address through when it is loopback.

A Sandbox on another port needs the same ports here:

```bash
dotnet run --project src/Apps/SimpleSign.Sandbox -- --ephemeral --port 5310
SANDBOX_URL=http://host.docker.internal:5310 SANDBOX_FORWARD_PORTS="5310 5311 5312" \
  docker compose -f tools/dss/docker-compose.yml up -d
```

### Revocation data: no cache

The DSS demo keeps the CRLs and OCSP responses it downloads (up to 3 hours) and answers from them
when the server is down. SimpleSign fetches every time, so under a Sandbox failure (CRL server
down, expired CRL) the two would see different data. `DSS_REVOCATION_CACHE=false` (the default
here) turns the cache off; `true` restores the demo's.

Any other certificate (PEM or DER, as `.pem`, `.cer`, `.crt` or `.der`) placed in
`tools/dss/trust/` is trusted too. The container log lists what it trusts (`[dss] trusting …`).

The Sandbox root is a test root. Do not add it to a validator that is used for real signatures.

## ICP-Brasil and Gov.br roots

The container also trusts the ICP-Brasil roots (Autoridade Certificadora Raiz Brasileira) and
the Gov.br root (Autoridade Certificadora Raiz do Governo Federal do Brasil v1), so DSS can
validate real Brazilian signatures. It reads them from the library's own copies
(`src/TrustFrameworks/Brazil/IcpBrasil/SimpleSign.Brazil.IcpBrasil/Certs` and
`src/TrustFrameworks/Brazil/GovBr/SimpleSign.Brazil.GovBr/Certs`), so DSS and SimpleSign trust
the same roots. Only the roots are trust anchors; DSS fetches the intermediates from each
certificate's AIA. Set `DSS_TRUST_ICP_BRASIL=false` or `DSS_TRUST_GOVBR=false` to turn them off.

Three ICP-Brasil roots cannot be loaded, and the log says so:

| Root | Key | Why |
|---|---|---|
| v4, v13 | brainpoolP512r1, curve parameters written out | A Java trust store cannot hold such a certificate. |
| v7 | Ed521 (1.3.6.1.4.1.44588.2.1) | DSS does not know the algorithm, and one such certificate in its trust store stops it from starting. |

DSS returns NO_CERTIFICATE_CHAIN_FOUND for signatures that chain to these roots.

The entrypoint checks every certificate this way, including those in `trust/`, so one
unsupported certificate is skipped instead of keeping DSS from starting.

Neither ICP-Brasil nor Gov.br publishes an ETSI trusted list, so DSS treats these roots as plain
trust anchors: it validates the chain but does not report a qualification (QES/QSCD).

## Public TSA roots

The container also trusts the roots of the public TSAs the TestBench offers: DigiCert Trusted Root G4,
Sectigo Public Time Stamping Root R46 and the FreeTSA Root CA. Without them, DSS reports for any signature
timestamped by these TSAs "The certificate chain for time-stamp is not trusted, it does not contain a trust
anchor". It reads them from the TestBench's own copies (`src/Apps/SimpleSign.TestBench/TsaRoots`), which its
**Public TSA roots** trust choice (on by default) reads too, so DSS and SimpleSign trust the same roots. Set
`DSS_TRUST_TSA_ROOTS=false` to turn them off.

## Peru trusted list

The container also trusts the certification authorities of the Peruvian trusted list, published
by INDECOPI (the IOFE's supervisory authority) at `https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml`.
It is downloaded at every start. A copy is kept in the `tl-cache` volume and used when the
download fails. Set `DSS_TRUST_PERU=false` to turn this off.

DSS cannot load this list as a trusted list. It only loads lists through a LOTL, and the
Peruvian list is an ETSI TSL version 3, while DSS reads versions 5 and 6. So the entrypoint takes
out the certificates and adds them to the trust store, like the ICP-Brasil roots:

- **In:** every service of type CA/QC whose status is "undersupervision" (66 certificates in
  sequence 25).
- **Out:** registration authorities, time-stamping authorities, signing software, and anything
  "No acredited".

Two things to know:

- The XML signature of the list is not checked. The list comes over HTTPS from indecopi.gob.pe.
- The list includes global roots that some Peruvian providers chain to: GlobalSign Root CA and R6,
  COMODO, WISeKey, emSign, Certisign, Entrust. DSS then trusts anything issued under them, not
  only Peruvian certificates.

DSS reports no qualification for these certificates: a Peruvian "qualified" status has no
meaning under eIDAS.

## EU trusted lists

DSS can also load the EU trusted lists (the EU LOTL and the national lists it points to), to
validate real EU signatures and say whether they are qualified:

```bash
DSS_LOAD_EU_TRUSTED_LISTS=true docker compose -f tools/dss/docker-compose.yml up -d
```

| Value | What DSS does |
|---|---|
| `false` (default) | No EU trusted lists. |
| `true` | Loads the copy kept from earlier runs, then downloads the lists at start and every hour (internet). |
| `cached` | Only loads the copy kept from an earlier `true` run, and never downloads. Works offline. |

DSS keeps what it downloads in the `tl-cache` volume (`eu-tl/`, about 30 MB), so it survives
restarts and rebuilds. Run once with `true` to fill it; after that `cached` starts with the lists, without
the internet. The download took under two minutes here, and loading the copy adds about 20
seconds to the start. With `false` the copy is kept but not used. To delete it:
`docker compose -f tools/dss/docker-compose.yml down -v`.

The trusted lists stay as trusted lists: DSS keeps each service's type and status, so it can
report a qualification. Copying their certificates into `trust/` would lose that. The cached copy
goes stale, so run with `true` from time to time. The **Trusted Lists Summary** page
(`http://localhost:8080/tl-info`) shows what is loaded and each list's next update.

## Other trusted lists

The DSS demo application only loads trusted lists through a LOTL, and it has two slots: the EU
one and the AdES MRA one. When the Sandbox's LOTL is loaded (`DSS_SANDBOX_TRUST=list`), it takes one of them (see
"Trusting the Sandbox certificates"). The demo cannot load a single ETSI trusted list (a TSL XML) on its own. To trust
the services of another list, put their certificates in `trust/`; DSS then validates the chain but cannot say whether
the signature is qualified.

## What to expect

| Signature | DSS says | Why |
|---|---|---|
| Any Sandbox scenario, any level | the same indication and sub-indication as SimpleSign | DSS fetches the CRLs and OCSP responses itself (forwarded ports, no cache). `DssScenarioCrossValidationTests` checks it, scenario by scenario. |
| Any level, Sandbox not trusted (no LOTL loaded, no root) | INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND | See "Trusting the Sandbox certificates". The **Trusted Lists Summary** page (`http://localhost:8080/tl-info`) shows whether the Sandbox's list loaded. |
| Real ICP-Brasil or Gov.br certificates | validated against their roots | See "ICP-Brasil and Gov.br roots". |
| Timestamps of DigiCert, Sectigo or FreeTSA | the TSA chain reaches a trust anchor | See "Public TSA roots". |
| Real Peruvian certificates | validated against the CAs of the Peruvian trusted list | See "Peru trusted list". |
| Other real certificates | depends on the roots DSS trusts | Add your roots to `trust/`, or load the EU trusted lists (above). |

## Options

| Variable | Default | Meaning |
|---|---|---|
| `DSS_PORT` | `8080` | The host port. |
| `SANDBOX_URL` | `http://host.docker.internal:5300` | The SimpleSign Sandbox whose root is trusted (`/root.pem`). |
| `SANDBOX_WAIT_SECONDS` | `20` | How long to wait for the Sandbox's root at start. |
| `SANDBOX_FORWARD_PORTS` | `5300 5301 5302` | The Sandbox ports forwarded from the container's localhost (HTTP, HTTPS, LDAP); empty turns it off. |
| `SANDBOX_FORWARD_HOST` | `host.docker.internal` | Where they are forwarded to. |
| `DSS_REVOCATION_CACHE` | `false` | `true` keeps the DSS demo's revocation cache (CRLs up to 3 h). |
| `DSS_SANDBOX_TRUST` | `list` | `list` trusts the Sandbox through its trusted list (LOTL); `anchor` trusts its root alone. |
| `DSS_ACCEPT_INVALID_TRUSTED_LISTS` | `false` | `true` keeps the trust anchors of a list whose signature fails (the DSS demo's default). |
| `DSS_TL_REFRESH_SECONDS` | `10` (Sandbox list alone), `3600` (with the EU lists) | How often the trusted lists are downloaded again. |
| `TESTBENCH_URL` | (none) | A TestBench whose connected Sandbox's root is used when `SANDBOX_URL` does not answer. |
| `DSS_LOAD_EU_TRUSTED_LISTS` | `false` | `true` downloads the EU trusted lists; `cached` only uses the copy kept from an earlier run. See "EU trusted lists". |
| `DSS_TRUST_ICP_BRASIL` | `true` | `true` trusts the ICP-Brasil roots (all but v4, v7 and v13; see above). |
| `DSS_TRUST_GOVBR` | `true` | `true` trusts the Gov.br root. |
| `DSS_TRUST_TSA_ROOTS` | `true` | `true` trusts the roots of the public TSAs (DigiCert, Sectigo, FreeTSA; see above). |
| `DSS_TRUST_PERU` | `true` | `true` trusts the CAs of the Peruvian trusted list (downloaded at start; see above). |
| `DSS_PERU_TSL_URL` | INDECOPI's address | Where to download the Peruvian trusted list from. |

To use another DSS version, change `DSS_VERSION` in `docker-compose.yml`.

You can also point the TestBench at a DSS you already run: set its address in the **DSS** panel
or in the `SIMPLESIGN_DSS_URL` environment variable.

## Automated check

With the container up, the test suite also uses it:

```bash
dotnet test tests/unit/Apps/SimpleSign.TestBench.Tests --filter "FullyQualifiedName~DssCrossValidationTests|FullyQualifiedName~DssScenarioCrossValidationTests"
```

`DssScenarioCrossValidationTests` signs every Sandbox scenario (each signer, TSA and failure, in
PAdES, CAdES and XAdES, at each level that can be made) and requires the same indication and
sub-indication from both validators, under the same policy. The few known differences are listed
in the test, each with its reason. A Sandbox on another port: set `SIMPLESIGN_SANDBOX_URL` too.

The tests sign with the connected Sandbox's certificates and assert what DSS reads from each file (signatures and timestamps
intact, references found, structure valid, baseline level). They do not depend on the roots DSS
trusts, and they are skipped when nothing answers at `SIMPLESIGN_DSS_URL` (or no Sandbox answers
at `SIMPLESIGN_SANDBOX_URL`).
