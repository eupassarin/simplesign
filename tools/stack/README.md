# Test stack for the TestBench

One command brings up what the TestBench needs to test with a real PKI, a token and an
independent validator:

1. the **SimpleSign Sandbox** (Docker): the test PKI, CRLs over HTTP/HTTPS/LDAP, OCSP, TSA, CSC;
2. a **SoftHSM token** on this machine, holding a key pair for each of the Sandbox's signing
   certificates;
3. the **EU DSS** validation service (Docker, [`tools/dss`](../dss/README.md)), trusting the Sandbox's
   PKI through its trusted list.

```bash
tools/stack/up.sh             # Sandbox → SoftHSM token → DSS, each waiting for the one before
tools/stack/testbench.sh      # the TestBench, connected to the Sandbox, with the token
```

In the TestBench:

- the Sandbox is connected at start (`--sandbox http://localhost:5300`);
- **Credential → PKCS#11**: SoftHSM 2, token `SimpleSign Sandbox`, PIN `1234`; each certificate is labelled
  with its Sandbox id (`signer`, `revoked`, `expired`, `no-nonrepudiation`…);
- **DSS** in the top bar: turn it on, address `http://localhost:8080`.

Requirements: Docker, the .NET SDK, and on the host `softhsm2-util`, `pkcs11-tool`, OpenSSL 3+, `curl`, `jq`
(macOS: `brew install softhsm opensc openssl@3 jq`).

## Why the token is not in a container

A PKCS#11 module is a native library loaded *inside* the process that signs. The TestBench runs
on the host, so it must load the host's SoftHSM (`/opt/homebrew/lib/softhsm/libsofthsm2.so` on
macOS); a Linux SoftHSM in a container cannot be loaded by it. `softhsm-provision.sh` therefore runs
on the host, between the Sandbox and DSS, which is why the order lives in `up.sh` rather than in
Compose alone.

## The token

`softhsm-provision.sh` (run by `up.sh`, or on its own once the Sandbox answers):

- keeps the token in `.softhsm/` at the repository root (ignored by git), with its own
  `softhsm2.conf`, apart from Homebrew's tokens. SoftHSM reads `SOFTHSM2_CONF` when the process
  starts, which `testbench.sh` sets; for the CLI or another program:

  ```bash
  export SOFTHSM2_CONF="$PWD/.softhsm/softhsm2.conf"
  ```

- downloads each signing certificate with its key from the Sandbox (`/api/certificates/{id}/pfx`),
  and writes the key and the certificate to the token under the same id and label. The certificates
  of the Sandbox's own services (TSA, OCSP responder, HTTPS) are left out; so are the CAs (the chain
  comes from the AIA).
- does nothing when the token already holds the certificates of the current Sandbox root, and
  rebuilds it when the root changed (a new PKI). `--force` rebuilds it anyway.

The certificates are the Sandbox's own: revoking `signer` in the Sandbox's UI makes the token's
`signer` revoked too.

Environment: `SANDBOX_URL`, `SOFTHSM_TOKEN_LABEL`, `SOFTHSM_PIN`, `SOFTHSM_SO_PIN`, `SOFTHSM2_MODULE`.

## The Sandbox container

`src/Apps/SimpleSign.Sandbox/Dockerfile`, built from the repository root. It runs with
`--listen-any` (HTTP, HTTPS and LDAP answer outside the container's loopback) and
`--allow-remote-admin` (requests published from the host arrive from the Docker bridge, not from
loopback). The ports are published on `127.0.0.1` only, so the admin API, which hands out private
keys, stays on this machine.

The certificates name `http://localhost:5300`, `https://localhost:5301` and `ldap://localhost:5302`:
the host reaches them through the published ports, and DSS through its port forwarding to the
`sandbox` service.

The PKI is kept in a volume between runs:

```bash
tools/stack/up.sh --fresh    # a new PKI: new root and certificates; the token and DSS follow
```

DSS reads the Sandbox's root and trusted-list operator when it starts, so `up.sh` recreates the
DSS container whenever the root changed.

## Options

| Variable / flag                              | Default            | What                                                    |
|----------------------------------------------|--------------------|---------------------------------------------------------|
| `--fresh`                                    |                    | a new Sandbox PKI (the DSS download cache is kept)      |
| `--no-dss`                                   |                    | the Sandbox and the token only                          |
| `SANDBOX_PORT`                               | `5300`             | the Sandbox's HTTP port, inside and outside             |
| `SANDBOX_HTTPS_PORT` / `SANDBOX_LDAP_PORT`   | port + 1 / + 2     | CRLs over HTTPS / LDAP                                  |
| `DSS_PORT`                                   | `8080`             | DSS on the host                                         |
| `COMPOSE_PROJECT_NAME`                       | `simplesign-stack` | to run a second stack next to the first                 |

The DSS variables of [`tools/dss/docker-compose.yml`](../dss/docker-compose.yml) (`DSS_LOAD_EU_TRUSTED_LISTS`,
`DSS_SANDBOX_TRUST`…) apply here too: the `dss` service extends it.

On other ports, start the TestBench with the same Sandbox:

```bash
SANDBOX_PORT=5390 DSS_PORT=8094 tools/stack/up.sh
SANDBOX_URL=http://localhost:5390 tools/stack/testbench.sh
```

## Stop

```bash
tools/stack/down.sh               # keeps the PKI and the DSS download cache
tools/stack/down.sh --drop-pki    # drops the PKI (the next up.sh makes a new one), keeps the DSS cache
tools/stack/down.sh --volumes     # drops every volume: the PKI and the DSS download cache
```

With `COMPOSE_PROJECT_NAME` set for `up.sh`, set it for `down.sh` too.

`tools/dss/docker-compose.yml` on its own still works with a Sandbox started with `dotnet run`.
