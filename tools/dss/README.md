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

## Trusting the sandbox certificates

DSS only knows the roots it is given. The sandbox certificates of the TestBench chain to a test
root (AC Raiz Sandbox SimpleSign), which the TestBench keeps between runs and serves at
`/api/sandbox/root.pem`.

- **Docker Desktop (macOS, Windows):** start the TestBench first. The container fetches the root
  from `http://host.docker.internal:5199` when it starts.
- **Linux, or when the TestBench was not running:** save the root to this folder and restart the
  container:

  ```bash
  curl http://127.0.0.1:5199/api/sandbox/root.pem > tools/dss/trust/sandbox-root.pem
  ```

Any other certificate (PEM or DER) placed in `tools/dss/trust/` is trusted too. The container
log lists what it trusts (`[dss] trusting …`).

The sandbox root is a test root. Do not add it to a validator that is used for real signatures.

## What to expect

| Signature | DSS says | Why |
|---|---|---|
| B-B, B-T with sandbox certificates | INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE ("No revocation data found") | The sandbox CRL and TSA addresses only exist inside the TestBench, so DSS cannot fetch revocation data. |
| B-LT, B-LTA with sandbox certificates | the same verdict as SimpleSign | The certificates and CRLs are embedded in the signature. |
| Any level, sandbox root not trusted | INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND | See "Trusting the sandbox certificates". |
| Real certificates | depends on the roots DSS trusts | Add your roots to `trust/`, or load the EU trusted lists (below). |

## Options

| Variable | Default | Meaning |
|---|---|---|
| `DSS_PORT` | `8080` | The host port. |
| `TESTBENCH_URL` | `http://host.docker.internal:5199` | Where to fetch the sandbox root from. |
| `DSS_LOAD_EU_TRUSTED_LISTS` | `false` | `true` loads the EU trusted lists at start (needs the internet and takes a few minutes). |

To use another DSS version, change `DSS_VERSION` in `docker-compose.yml`.

You can also point the TestBench at a DSS you already run: set its address in the **DSS** panel
or in the `SIMPLESIGN_DSS_URL` environment variable.
