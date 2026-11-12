# SimpleSign Agent (local signing agent)

SimpleSign Agent is a small macOS, Windows and Linux app (Avalonia) that web pages call to sign
with the user's certificate: the OS certificate store or an **A3 token / smartcard** (PKCS#11).
The private key never leaves the computer. It replaces the former Windows-only
`SimpleSign.HostSigner`.

It lives in the tray (the menu bar on macOS) and has one window, in **English (en-US) and
Portuguese (pt-BR)**, with the same look as the [TestBench](testbench.md): one bar at the top, no
side menu, light and dark themes.

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
| **Overview** | Running / paused / could not start (with *Try again*), the on/off switch, and the certificates found: holder, masked CPF/CNPJ, store or token and driver, ICP-Brasil, validity. |
| **Sites** | Sites allowed always or for this session, and blocked sites: *Remove*, *Block*, *Unblock*. |
| **Activity** | What the agent did since it started (memory only), with an errors filter. |
| **Test** | An end-to-end test: the window calls the agent over HTTP as a page does (health → certificates → sign), with the real consent dialog and PIN prompt, then verifies the signature with the certificate's public key. Each step shows the request, the response and the `fetch` code. |
| **Documentation** | Built-in pages in both languages: how it works, getting started, integration, security, troubleshooting. |
| **Settings** (panel) | Agent on/off, start at login, port, how long a token PIN is remembered, language, theme, the settings folder. |
| **About** (panel) | Version, what the agent guarantees, the facts of the installation (system, runtime, drivers found) and *Copy diagnostics*. |

*Start at login* is a LaunchAgent (`~/Library/LaunchAgents/io.github.eupassarin.simplesign.agent.plist`)
on macOS, the per-user `Run` key on Windows and an XDG autostart entry on Linux.

Settings live in `settings.json` under the user's application-data folder (`SimpleSign/`):
`agentEnabled`, `agentPort`, `allowedOrigins`, `blockedOrigins`, `pinCacheMinutes`, `language`
(`en-US`, `pt-BR` or null to follow the system), `theme` (`system`, `light`, `dark`), `firstRunDone`.

## API

The agent listens on **`http://127.0.0.1:21590`** only (`agentPort` in the settings). The API
keeps the former HostSigner contract, so existing integrations work:

| Endpoint | |
|----------|---|
| `GET /api/health` | `{ "status": "ok", "version": "…", "app": "SimpleSign Agent" }` — no permission needed. |
| `GET /api/certificates?source=all\|store\|pkcs11&filterIcpBrasil=true` | Store and token certificates (`source`, `tokenLabel` are new fields). |
| `POST /api/sign` | `{ thumbprint, hashAlgorithm, documentName?, signRequests: [{ id, authenticatedAttributeBase64 }] }` → `[{ id, signedHashBase64 }]`. The bytes — CMS signed attributes or an XML-DSig `SignedInfo`, nothing else — are hashed with `hashAlgorithm` and signed (RSA PKCS#1 v1.5; ECDSA as IEEE P1363, as before). |

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
