# DSS validation service for the TestBench

The TestBench can send every signature it makes to the
[EU DSS](https://github.com/esig/dss) and show its verdict next to SimpleSign's. DSS is an
independent implementation of the validation algorithm of ETSI EN 319 102-1, so a difference
between the two is worth looking at.

This folder runs the DSS demo web application in Docker and exposes its REST validation service.

## Start

```bash
docker compose -f tools/dss/docker-compose.yml up --build
```

The first build downloads the DSS bundle published by the European Commission (353 MB). That
server is slow (about 0.5 MB/s), so allow **around 15 minutes**. The download is kept in the
build cache and resumes if the build is interrupted; later builds reuse it.
When Tomcat is up:

- `http://localhost:8080/` — the DSS demo pages
- `http://localhost:8080/services/rest/validation/validateSignature` — what the TestBench calls

Then, in the TestBench, open **DSS** in the top bar, turn it on and check the address. Every
run is then validated twice, and the **Validation** tab shows both verdicts.

## Trusting the Sandbox certificates

DSS only knows the roots it is given. The test certificates come from the SimpleSign Sandbox
(`src/Apps/SimpleSign.Sandbox`, see [docs/articles/sandbox.md](../../docs/articles/sandbox.md)): they
chain to the root of its environment, served at `/root.pem`. The root is kept with the
environment, so DSS keeps trusting it until the environment is deleted.

- **Docker Desktop (macOS, Windows):** start the Sandbox first. The container fetches the root
  from `http://host.docker.internal:5300/root.pem` when it starts (`SANDBOX_URL`).
- **Linux, or when the Sandbox was not running:** save the root to this folder and restart the
  container:

  ```bash
  curl http://127.0.0.1:5300/root.pem > tools/dss/trust/sandbox-root.pem
  ```

### Letting DSS reach the Sandbox's CRLs, OCSP and TSA

The Sandbox writes its own address into the certificates (CRL distribution points, AIA, OCSP).
With the default `http://localhost:5300`, DSS, inside the container, cannot reach them, so a
B-B or B-T signature (no revocation data embedded) is INDETERMINATE there. For DSS to fetch them,
create a Sandbox environment whose certificates name an address both sides reach:

```bash
dotnet run --project src/Apps/SimpleSign.Sandbox -- --name dss --public-base-url http://host.docker.internal:5300
```

The TestBench on the host must then resolve `host.docker.internal` (Docker Desktop adds it on
Windows; on macOS and Linux add `127.0.0.1 host.docker.internal` to `/etc/hosts`).

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

## Peru trusted list

The container also trusts the certification authorities of the Peruvian trusted list, published
by INDECOPI (the IOFE's accreditation authority) at `https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml`.
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

The DSS demo application only loads trusted lists through a LOTL: the EU one (above) and the
AdES MRA one. It cannot load a single ETSI trusted
list (a TSL XML) on its own. To trust the services of such a list, put their certificates in
`trust/`; DSS then validates the chain but cannot say whether the signature is qualified.

## What to expect

| Signature | DSS says | Why |
|---|---|---|
| B-B, B-T with Sandbox certificates (default environment) | INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE ("No revocation data found") | The certificates name `localhost`, which DSS cannot reach from the container. |
| B-B, B-T with Sandbox certificates (`--public-base-url http://host.docker.internal:5300`) | the same verdict as SimpleSign | DSS fetches the CRLs and OCSP responses itself. |
| B-LT, B-LTA with Sandbox certificates | the same verdict as SimpleSign | The certificates and revocation data are embedded in the signature. |
| Any level, Sandbox root not trusted | INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND | See "Trusting the Sandbox certificates". |
| Real ICP-Brasil or Gov.br certificates | validated against their roots | See "ICP-Brasil and Gov.br roots". |
| Real Peruvian certificates | validated against the CAs of the Peruvian trusted list | See "Peru trusted list". |
| Other real certificates | depends on the roots DSS trusts | Add your roots to `trust/`, or load the EU trusted lists (above). |

## Options

| Variable | Default | Meaning |
|---|---|---|
| `DSS_PORT` | `8080` | The host port. |
| `SANDBOX_URL` | `http://host.docker.internal:5300` | The SimpleSign Sandbox whose root is trusted (`/root.pem`). |
| `TESTBENCH_URL` | (none) | A TestBench whose connected Sandbox's root is used when `SANDBOX_URL` does not answer. |
| `DSS_LOAD_EU_TRUSTED_LISTS` | `false` | `true` downloads the EU trusted lists; `cached` only uses the copy kept from an earlier run. See "EU trusted lists". |
| `DSS_TRUST_ICP_BRASIL` | `true` | `true` trusts the ICP-Brasil roots (all but v4, v7 and v13; see above). |
| `DSS_TRUST_GOVBR` | `true` | `true` trusts the Gov.br root. |
| `DSS_TRUST_PERU` | `true` | `true` trusts the CAs of the Peruvian trusted list (downloaded at start; see above). |
| `DSS_PERU_TSL_URL` | INDECOPI's address | Where to download the Peruvian trusted list from. |

To use another DSS version, change `DSS_VERSION` in `docker-compose.yml`.

You can also point the TestBench at a DSS you already run: set its address in the **DSS** panel
or in the `SIMPLESIGN_DSS_URL` environment variable.

## Automated check

With the container up, the test suite also uses it:

```bash
dotnet test tests/unit/Apps/SimpleSign.TestBench.Tests --filter "FullyQualifiedName~DssCrossValidationTests"
```

The tests sign with the connected Sandbox's certificates and assert what DSS reads from each file (signatures and timestamps
intact, references found, structure valid, baseline level). They do not depend on the roots DSS
trusts, and they are skipped when nothing answers at `SIMPLESIGN_DSS_URL` (or no Sandbox answers
at `SIMPLESIGN_SANDBOX_URL`).
