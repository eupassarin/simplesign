# SimpleSign Playbook

The Playbook app runs a **playbook**: a list of SimpleSign CLI commands, each with what it must give.
Before a step it can change a [SimpleSign Sandbox](sandbox.md) (switch failures on, revoke a
certificate, hand out a certificate); after the command it checks the exit code, the JSON the CLI
printed, the files written and the requests the Sandbox answered; and it records everything.
It is generic: what to check, and why, is up to the playbook.

```bash
dotnet run --project src/Apps/SimpleSign.Playbook              # http://127.0.0.1:5400, opens the browser
dotnet run --project src/Apps/SimpleSign.Playbook -- --workspace ~/playbooks/mine --no-browser
```

The UI is in English and Portuguese, like the other apps. It listens on 127.0.0.1 only.

## Workspaces

A workspace is a folder:

| Path | What |
|---|---|
| `playbook.json` | The playbook (below) |
| `assets/` | The files the steps use: documents, certificates (PKCS#12, PEM, DER), policies |
| `secrets.json` | The passwords of the assets, by key; kept out of the playbook so it can be shared |
| `runs/ID/` | Each run: `run.json`, `report.md`, `report.html`, and per step its command, stdout, stderr, the Sandbox's requests and the files it wrote |

It can be versioned; `secrets.json` and `runs/` are in the `.gitignore` the app writes. **New
workspace** starts with a small playbook or a copy of a sample (`Sandbox basics` signs and
validates with a Sandbox's certificates, good and bad).

## The playbook

```json
{
  "schema": 1,
  "name": "Revocation checks",
  "sandbox": { "url": "http://localhost:5300/", "resetBeforeRun": true },
  "variables": { "doc": "${run}/contract.pdf" },
  "assets": [ { "id": "my-a1", "file": "assets/a1.pfx", "secret": "my-a1" } ],
  "sections": [
    { "id": "revocation", "title": "Revocation", "steps": [
      {
        "id": "ocsp-revoked",
        "title": "Revoked by OCSP",
        "description": "Signing is refused: the responder answers revoked.",
        "setup": [ { "sandbox": "certificate", "id": "revoked-ocsp", "as": "cert" } ],
        "run": { "args": ["sign", "${var.doc}", "--cert", "${cert.path}", "--password", "${cert.password}",
                          "--signing-policy", "strict", "--json", "-o", "${out}/signed.pdf"] },
        "expect": { "json": { "error.reason": "CertificateRevoked" }, "sandboxRequests": [ { "service": "OCSP" } ] },
        "teardown": [ { "sandbox": "reset" } ]
      },
      { "id": "reader", "title": "Check in a PDF reader", "manual": true }
    ] }
  ]
}
```

- **`run.args`**: the arguments after `simplesign`, one per entry (no shell). With a Sandbox, the
  app adds `--allow-origin` for each of its origins, `--allow-ldap` and `--tls-trust` with its
  chain (see [CLI › Network](cli.md#network)); `"network": "none"` leaves the arguments as written.
  `timeoutSeconds` defaults to 120.
- **`expect`** (every check that is set must pass; with no `expect`, the exit code must be 0):
  `exitCode`; `json` (dotted paths into the JSON on stdout, such as `error.reason` or
  `signatures.0.indication`, and the JSON value each must have); `stdoutContains`,
  `stderrContains`, `stdoutMatches` (regular expressions); `files` that must exist;
  `sandboxRequests` (`service` CRL, OCSP, TSA, AIA or CSC, `pathContains`, `min`, `max`).
- **Sandbox actions** (`setup`, `teardown`): `faults` (`crl`, `ocsp`, `tsa`, `ocspSigner`; the
  others keep their value), `revoke` (`certificate`, `reason`, `publication` Both, CrlOnly or
  OcspOnly), `unrevoke`, `reset`, `certificate` (`id`; the PKCS#12 is saved in the step's folder as
  `${NAME.path}` with `${NAME.password}`, NAME being `as`, `cert` by default) and `shortLived`
  (`seconds`).
- **A manual step** has no command: the run waits; the operator does it, writes a note, attaches
  files (screenshots…) and marks it passed, failed or skipped.

Variables: `${out}` (the step's folder), `${run}` (the run's folder), `${workspace}`,
`${asset.ID}` and `${asset.ID.password}`, `${var.NAME}`, `${env.NAME}`, and with a Sandbox
`${sandbox.url}`, `${sandbox.tsa}` (also `tsaAuthenticated`, `tsaUntrusted`, `tsaRevoked`,
`tsaWrongName`, `tsaUser`, `tsaPassword`), `${sandbox.root}`, `${sandbox.chain}` and
`${sandbox.pfxPassword}`. `$${` writes a literal `${`.

The **Playbook** tab edits it as a form or as JSON; the server checks it as you type and lists each
problem with its path. Errors stop a run; warnings (an asset not in the folder yet, a step without
a title) do not.

## Running

**Run** runs every step, or the ones ticked. Each step shows its status live, its actions, the
command line (it can be pasted in a shell), its output as it comes, each check with what was
expected and what was found, the Sandbox's requests during the step, and its files. A run can be
stopped; the command running is killed.

Each run records the date, the machine and user, the CLI and its version (`simplesign version`),
the Sandbox (name, version, root) and the SHA-256 of the playbook, so a result can be traced to
what produced it. **History** lists the runs, compares two step by step, and downloads the report
(HTML, Markdown) or the whole run folder (zip).

**Settings** says how this machine starts the CLI: by default a CLI built in this repository
(`src/Apps/SimpleSign.Cli/bin`), else `simplesign` on the PATH; it can be a path, or `dotnet` with
`run --project src/Apps/SimpleSign.Cli --` before each command.

## Tests

`tests/unit/Apps/SimpleSign.Playbook.Tests` checks the playbook format, variables, expectations,
workspaces and the runner (with a fake CLI and a fake Sandbox), and runs the sample playbook with
the real CLI against a running Sandbox (`SIMPLESIGN_SANDBOX_URL`; skipped without one, required in
CI).
