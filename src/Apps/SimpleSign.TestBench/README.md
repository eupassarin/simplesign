# SimpleSign.TestBench

A local web app for **PAdES, CAdES and XAdES** on one screen: set any option, sign, validate, and
read the result, the verdicts, the log of every step and the matching C# and CLI code.

```bash
dotnet run --project src/Apps/SimpleSign.TestBench
# → http://127.0.0.1:5199, loopback only
```

Connect it to a [Sandbox](../SimpleSign.Sandbox/README.md) to get test certificates, revocation,
TSAs and the failures to switch on:

```bash
dotnet run --project src/Apps/SimpleSign.Sandbox -- --ephemeral          # :5300
dotnet run --project src/Apps/SimpleSign.TestBench -- --sandbox http://localhost:5300
```

The connection is remembered between runs; you can also connect from the Sandbox popup in the UI.

## What it is for

**Every option names the clause that defines it** — ETSI EN 319 142-1, 122-1, 132-1, 102-1,
RFC 5652/3161/6960/5280, ISO 32000-1, XMLDSig — and the library call it becomes. Options the
standards define and SimpleSign does not implement are listed too, disabled. So it answers "what
does this flag actually mean, and what does a validator make of it?" without writing a program.

The **Library / CLI** switch runs the same operation through either engine, which is how
"Lib ≠ CLI" differences get found.

| | |
|---|---|
| **Sign** | The three formats, every option, baseline presets B-B…B-LTA, *Vary* and *Combinations* to sweep an option, the Stamp drawer with a live preview |
| **Validate** | One screen for the three formats, with samples each broken in one specific way and the verdict each should get |
| **Playbook** | Runs a playbook of scripted steps against the Sandbox and exports the evidence |
| Panels | Policies, the standards Reference, Environment, Sandbox, EU DSS |

The **Profile** menu applies a whole trust framework at once (Sandbox, Peru/IOFE, ICP-Brasil,
Gov.br, EU/eIDAS), setting the policies with it.

## The Playbook tab

A playbook is a JSON file of tagged steps (schema 2). The TestBench checks it against the connected
Sandbox, runs one step, a section or all of them — through the library, the CLI or both — shows
everything a step will do *before* it runs, and exports the evidence as an HTML page and a zip.
That is how an accreditation is demonstrated.

Bundled in [`docs/playbooks/`](../../../docs/playbooks/): `sandbox-basics`, `etsi-baseline`,
`eidas-baseline`, `indecopi-guia-v4`, `icp-brasil-pades` and `govbr-pades`.

## Options

`--port N` (default 5199) · `--no-browser` · `--sandbox URL` (or `SIMPLESIGN_SANDBOX_URL`).

## Building

The UI is React + Vite + Tailwind + shadcn/ui in [`web/`](web/). **`dotnet build` runs `npm ci` and
`npm run build` for you** (Node 20+); skip it with `-p:SkipWeb=true`. Running from `bin/` serves
`web/dist` directly, so there is no second port. `npm run dev` in `web/` gives hot reload on 5173,
proxying `/api` to 5199.

The build also puts the CLI next to the TestBench, because the engine switch runs it.

`tools/stack/testbench.sh` starts it against the stack's Sandbox with a SoftHSM token; plain
`dotnet run` needs neither Docker nor SoftHSM.

Full guide: [docs/articles/testbench.md](../../../docs/articles/testbench.md) ·
[playbooks](../../../docs/articles/playbook.md) · how it fits with the other apps:
[docs/articles/apps.md](../../../docs/articles/apps.md).
