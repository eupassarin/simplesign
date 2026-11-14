# SimpleSign Agent (local signing agent)

SimpleSign Agent is a small macOS, Windows and Linux app (Avalonia) that web pages call to sign
with the user's certificate: the OS certificate store or an **A3 token / smartcard** (PKCS#11).
The private key never leaves the computer. It replaces the former Windows-only
`SimpleSign.HostSigner`.

It lives in the tray (the menu bar on macOS) and has one window, in **English (en-US), Portuguese
(pt-BR) and Spanish (es-ES)**, with the same look as the [TestBench](testbench.md): one bar at the
top, no side menu, light and dark themes. There is one neutral Spanish: any `es*` system language
gets it.

## The tray

The icon is drawn by the app from the product mark. On macOS it is a monochrome *template* image
that the system tints for light, dark and highlighted menu bars; on Windows and Linux it is the
dark rounded square, with a dot when the agent is paused (amber) or could not start (red).

| Item | |
|------|---|
| Status | *Listening on 127.0.0.1:21590*, *Agent paused* or the start error (e.g. port in use). |
| **Open SimpleSign Agent** | Shows the window. On Windows and Linux a click on the icon does the same. |
| **Pause / Resume the agent** | Stops / starts the HTTP listener (saved). |
| **Quit** | Stops the agent and closes open token sessions. |

Closing the window does not stop the agent. Starting the app again while it runs shows the window
of the running one (one agent per user). The window opens by itself on the first run.

## The window

| Section | |
|---------|---|
| **Overview** | Running / paused / could not start (with *Try again*), the on/off switch, and the certificates found: holder, masked CPF/CNPJ, store or token and driver, a badge for each enabled trust framework that recognizes the certificate, validity. |
| **Sites** | Sites allowed always or for this session, and blocked sites: *Remove*, *Block*, *Unblock*. |
| **Activity** | What the agent did since it started (memory only), with an errors filter. |
| **Test** | An end-to-end test: the window calls the agent over HTTP as a page does (health → certificates → sign), with the real consent dialog and PIN prompt, then verifies the signature with the certificate's public key. Each step shows the request, the response and the `fetch` code. |
| **Documentation** | Built-in pages in both languages: how it works, getting started, integration, security, troubleshooting. |
| **Settings** (panel) | Agent on/off, start at login, port, how long a token PIN is remembered, the trust frameworks that are enabled, the state of the signed-request mode and of the administrator policy, language, theme, the settings folder. |
| **About** (panel) | Version, what the agent guarantees, the facts of the installation (system, runtime, drivers found) and *Copy diagnostics*. |

*Start at login* is a LaunchAgent (`~/Library/LaunchAgents/io.github.eupassarin.simplesign.agent.plist`)
on macOS, the per-user `Run` key on Windows and an XDG autostart entry on Linux.

Settings live in `settings.json` under the user's application-data folder (`SimpleSign/`):
`agentEnabled`, `agentPort`, `allowedOrigins`, `blockedOrigins`, `pinCacheMinutes`,
`enabledTrustFrameworks`, `signedRequestsRequired`, `signedRequestKeys`, `language`
(`en-US`, `pt-BR`, `es-ES` or null to follow the system), `theme` (`system`, `light`, `dark`),
`firstRunDone`.

### Trust frameworks

Every trust framework of the library is built into the agent — **ICP-Brasil** (`icp-brasil`, BR),
**Gov.br** (`govbr`, BR), **IOFE** (`iofe`, PE) and **eIDAS** (`eidas`, EU) — and the user enables
the ones they want in *Settings → Trust frameworks* (`enabledTrustFrameworks`). Only an enabled
framework answers `?country=`, `?trust=` and `filterIcpBrasil`, and only an enabled framework puts
a badge on a certificate in the Overview.

A **new installation enables none**: the agent asks for no trust until someone chooses it. An
installation that already had a `settings.json` without the key keeps what an older agent filtered
by, `icp-brasil` and `govbr`, so existing integrations are unaffected. A listing with no filter
returns every certificate either way.

IOFE and eIDAS take their anchors from a trusted list (INDECOPI's, the EU LOTL). It is downloaded in
the background, cached next to `settings.json` (`iofe-tsl-pe.xml`, `eu-lotl/`) and refreshed every
six hours, so it never blocks the window or a certificate listing; while it cannot be read, those
filters answer **503** and the panel says *not available offline*, retried a minute later. The
Brazilian frameworks carry their roots inside the agent and need no network.

## API

The agent listens on **`http://127.0.0.1:21590`** only (`agentPort` in the settings). The API
keeps the former HostSigner contract, so existing integrations work:

| Endpoint | |
|----------|---|
| `GET /api/health` | `{ "status": "ok", "version": "…", "app": "SimpleSign Agent" }` — no permission needed. |
| `GET /api/certificates?source=all\|store\|pkcs11&country=XX&trust=ID&signingOnly=true&filterIcpBrasil=true` | Store and token certificates (`source`, `tokenLabel` are new fields). Optional filters: `country` (a region code: certificates that chain to the trust anchors of that country's **enabled** frameworks — `BR`, `PE`, `EU`), `trust` (one framework by id: `icp-brasil`, `govbr`, `iofe`, `eidas`), `signingOnly=true` (valid now, with digitalSignature or nonRepudiation). An unknown country or id answers 400 with the known ones; one the agent knows but the user has not enabled answers 400 listing what is enabled; a framework whose trusted list cannot be read answers 503. `filterIcpBrasil=true` keeps its former meaning (issuer name or ICP-Brasil policy OID), while ICP-Brasil is enabled; `trust=icp-brasil` checks the chain. |
| `POST /api/sign` | `{ thumbprint, hashAlgorithm, documentName?, signedRequest?, signRequests: [{ id, authenticatedAttributeBase64 }] }` → `[{ id, signedHashBase64 }]`. The bytes — CMS signed attributes or an XML-DSig `SignedInfo`, nothing else — are hashed with `hashAlgorithm` and signed (RSA PKCS#1 v1.5; ECDSA as IEEE P1363, as before). `signedRequest` is required only in the mode below. |

```js
await fetch("http://127.0.0.1:21590/api/health");
const certs = await (await fetch("http://127.0.0.1:21590/api/certificates")).json();
const [result] = await (await fetch("http://127.0.0.1:21590/api/sign", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ thumbprint: certs[0].thumbprint, hashAlgorithm: "SHA256", documentName: "contrato.pdf",
    signRequests: [{ id: "1", authenticatedAttributeBase64 }] })
})).json();
```

Use it with [deferred signing](deferred-signing.md): the server prepares the signed attributes,
the browser asks the agent to sign them, the server completes the PDF.

Error messages (`{ "error": "…" }`) are in the agent's language; rely on the HTTP status.

### Security model

- **Loopback only**, request bodies limited to 1 MB, at most 100 items per request, 20 requests a minute per site.
- **A token warns before it locks.** The PIN dialog shows the token's own flags before a wrong PIN
  can cost the card: *last attempt* (`CKF_USER_PIN_FINAL_TRY`, shown as an error), a wrong PIN since
  the last good one (`CKF_USER_PIN_COUNT_LOW`), and a PIN that must still be changed
  (`CKF_USER_PIN_TO_BE_CHANGED`).
- **Sites must be authorized.** The first time a site (exact `scheme://host[:port]`) lists
  certificates or asks for a signature, the app asks *“Allow access to your certificates?”* —
  allow once, always (saved, removable in **Sites**) or refuse. A blocked site is refused without
  asking. `null`, `file://` and other non-http(s) origins are refused. CORS echoes only the
  requesting site; Chrome's Private Network Access preflight is answered.
- **Only signature data is signed.** Each item must be DER CMS signed attributes (with `contentType` and
  `messageDigest`; a `signingCertificateV2` must name the chosen certificate) or a canonical XML-DSig `SignedInfo`
  (`DataToSignInspector` in SimpleSign.Core). A raw hash or any other bytes are refused with 400 before the user is
  asked.
- **Every signature is confirmed** in a dialog, showing the site, the document name, the certificate and the digest
  being signed (such as `SHA256 1A2B3C4D…5E6F7A8B`).
- **The PIN never crosses the API.** Token PINs are typed in the agent's dialog (or on the reader's
  PIN pad) and kept in memory only for `pinCacheMinutes` (default 0: ask every time).
- **The window has no HTTP API.** Settings, sites and the log are changed only in the app itself.
  The Test page calls the same public endpoints a site calls, and goes through the same dialogs.
- The former `/api/sign-file`, `/api/inspect` and `/api/validate` endpoints, which took local
  file paths, were removed: they let any page that the user allowed act on arbitrary local files.
  Use the library or the CLI instead.

### Server-signed sign requests (opt-in)

`DataToSignInspector` already stops the agent signing arbitrary bytes, but an allowed page can still
ask for a signature over signed attributes it built itself. Where a server prepares every signature,
the agent can be told to accept nothing else: with `signedRequestsRequired: true` and at least one
key in `signedRequestKeys`, `POST /api/sign` is answered only when the body carries a
`signedRequest` the server signed. Off by default; nothing changes for an agent that does not set it,
and an agent that does not require a token ignores one that is sent.

The token is a **JWS in compact serialization** (RFC 7515), `header.payload.signature`, each part
base64url. Verification happens before the bytes are parsed and before the user is asked; any
failure is a 400 naming the reason.

Header:

| | |
|---|---|
| `alg` | `ES256`, `ES384`, `ES512`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384` or `PS512`. Anything else, `none` included, is refused. |
| `typ` | exactly `simplesign-sign-request+jws`. |
| `kid` | optional; when present, the base64url SHA-256 of the key's SubjectPublicKeyInfo, as the agent computes it. Without it every configured key is tried. |

Claims (all required unless marked):

| | |
|---|---|
| `aud` | `simplesign-agent`. |
| `origin` | the exact site the token is for, normalized `scheme://host[:port]`; must equal the requesting origin. |
| `thumbprint` | the certificate's SHA-1 thumbprint in hex, case-insensitive; must equal the body's. |
| `items` | `[{ "id", "digest" }]`, one per entry of `signRequests`, same order and same count; `digest` is the base64url SHA-256 of the **decoded** `authenticatedAttributeBase64`. |
| `iat`, `exp` | seconds since the Unix epoch. `exp` must be in the future and at most 300 s after `iat` (60 s of clock leeway). |
| `jti` | 1 to 64 characters, accepted once: a replay is refused. |
| `documentName` *(optional)* | shown in the consent dialog **instead of** the body's. |
| `documentNames` *(optional)* | one per item. |
| `hashAlgorithm` *(optional)* | must equal the body's when given. |

```jsonc
// the payload a server signs, then sends to the page as `signedRequest`
{
  "aud": "simplesign-agent",
  "origin": "https://portal.example.com",
  "thumbprint": "9F2A…C1",
  "documentName": "contract.pdf",
  "hashAlgorithm": "SHA256",
  "items": [{ "id": "1", "digest": "Zm9vYmFy…" }],
  "iat": 1763600000, "exp": 1763600180,
  "jti": "b0f1c2d3e4f5"
}
```

Both keys and the mode come from the settings (or from the administrator policy below). The agent
holds only the public key, so a page cannot mint a token even with everything it can see.

### Locked-down installations

An administrator can ship a `policy.json` that fixes settings for every user of a machine:
`$SIMPLESIGN_AGENT_POLICY` when set, else `/Library/Application Support/SimpleSign/policy.json`
(macOS), `%ProgramData%\SimpleSign\policy.json` (Windows) or `/etc/simplesign/policy.json` (Linux).

```json
{
  "lockedSettings": ["allowedOrigins", "signedRequests", "trustFrameworks", "agentPort", "pinCacheMinutes"],
  "allowedOrigins": ["https://portal.example.com"],
  "blockedOrigins": [],
  "signedRequestsRequired": true,
  "signedRequestKeys": ["-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----"],
  "enabledTrustFrameworks": ["iofe"],
  "agentPort": 21590,
  "pinCacheMinutes": 0
}
```

A value the file carries is applied to the settings; a value also named in `lockedSettings` is shown
read-only in the window and written back over any change, so it cannot be saved away. With
`allowedOrigins` locked, **Sites** becomes a read-only list and an unknown site is refused with 403
without asking the user — the *allow this site?* dialog never appears. Without the file nothing
changes, and the interactive behaviour stays the default.

A `policy.json` that exists but cannot be parsed makes the agent **refuse every request** with 403,
and the window says the file is invalid: failing open would silently undo the lock the administrator
relies on.

## Install and run

Download `SimpleSignAgent-<version>-<rid>` from the GitHub release (macOS `.app` zip for Apple
silicon and Intel, Windows zip, Linux tarball). The builds are not code-signed yet: on macOS,
right-click → *Open* the first time; on Windows, *More info* → *Run anyway*. On Linux the tray icon
needs a desktop with StatusNotifier / AppIndicator support (KDE, or GNOME with the AppIndicator
extension); without it, start the app again to show the window.

The release is one native executable (Native AOT) plus the Skia and HarfBuzz libraries: no .NET
runtime to install. On macOS arm64 the app is about 41 MB (18 MB zipped) and answers
`/api/health` about 0.25 s after starting.

From source:

```bash
dotnet run --project src/Apps/SimpleSign.Agent
scripts/package-agent.sh osx-arm64 0.11.0      # "SimpleSign Agent.app" in artifacts/agent (Native AOT)
```

Developer commands of the executable:

| | |
|---|---|
| `SimpleSign.Agent --self-check` | Checks a published binary without opening a window (texts, embedded documentation, an HTTP round trip); exit code 0 when it works. CI runs it after the AOT publish on the three systems. |
| `SimpleSign.Agent --export-icons <dir>` | Writes the application icons drawn by the app (`Assets/icon-1024.png`, `icon-256.png`, `icon.ico` come from it). |

The window's texts are in `Localization/Strings.cs` (en-US is the source of the keys) and the
built-in documentation in `Docs/<language>/<topic>.md`; tests check that both languages have the
same keys, placeholders and document structure.

## Migrating from SimpleSign.HostSigner

Same port and the same `/api/health`, `/api/certificates` and `/api/sign` contract. What changes
for users: each site is authorized once, and each signature is confirmed in a dialog. Token
certificates now appear in `/api/certificates` (`source: "pkcs11"`).
