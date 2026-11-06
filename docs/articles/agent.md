# SimpleSign Agent (local signing agent)

SimpleSign Agent is a small macOS, Windows and Linux **tray / menu-bar app** (Avalonia) that web
pages call to sign with the user's certificate: the OS certificate store or an **A3 token /
smartcard** (PKCS#11). The private key never leaves the computer. It replaces the former
Windows-only `SimpleSign.HostSigner`.

It has no main window. The tray menu shows:

| Item | |
|------|---|
| Status | *Ouvindo em 127.0.0.1:21590*, *Agente pausado* or the start error (e.g. port in use). |
| **Agente ativo** | Pauses / resumes the HTTP listener (saved). |
| **Sites autorizados…** | Sites allowed permanently; *Remover* revokes one. |
| **Iniciar com o sistema** | Starts the agent at login: a LaunchAgent (`~/Library/LaunchAgents/io.github.eupassarin.simplesign.agent.plist`) on macOS, the per-user `Run` key on Windows, an XDG autostart entry on Linux. |
| **Sair** | Stops the agent and closes open token sessions. |

Settings live in `settings.json` under the user's application-data folder (`SimpleSign/`):
`agentEnabled`, `agentPort`, `allowedOrigins`, `blockedOrigins`, `pinCacheMinutes`.

## API

The agent listens on **`http://127.0.0.1:21590`** only (`agentPort` in the settings file). The API
keeps the former HostSigner contract, so existing integrations work:

| Endpoint | |
|----------|---|
| `GET /api/health` | `{ "status": "ok", "version": "…", "app": "SimpleSign Agent" }` — no permission needed. |
| `GET /api/certificates?source=all\|store\|pkcs11&filterIcpBrasil=true` | Store and token certificates (`source`, `tokenLabel` are new fields). |
| `POST /api/sign` | `{ thumbprint, hashAlgorithm, documentName?, signRequests: [{ id, authenticatedAttributeBase64 }] }` → `[{ id, signedHashBase64 }]`. The bytes are hashed with `hashAlgorithm` and signed (RSA PKCS#1 v1.5; ECDSA as IEEE P1363, as before). |

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

### Security model

- **Loopback only**, request bodies limited to 1 MB, at most 100 items per request, 20 requests a minute per site.
- **Sites must be authorized.** The first time a site (exact `scheme://host[:port]`) lists
  certificates or asks for a signature, the app asks *“Permitir acesso aos certificados?”* —
  allow once, always (saved, removable in *Sites autorizados…*) or deny. `null`, `file://` and other
  non-http(s) origins are refused. CORS echoes only the requesting site; Chrome's Private Network
  Access preflight is answered.
- **Every signature is confirmed** in a dialog, showing the site, the document name and the certificate.
- **The PIN never crosses the API.** Token PINs are typed in the agent's dialog (or on the reader's
  PIN pad) and kept in memory only for `pinCacheMinutes` (default 0: ask every time).
- The former `/api/sign-file`, `/api/inspect` and `/api/validate` endpoints, which took local
  file paths, were removed: they let any page that the user allowed act on arbitrary local files.
  Use the library or the CLI instead.

## Install and run

Download `SimpleSignAgent-<version>-<rid>` from the GitHub release (macOS `.app` zip for Apple
silicon and Intel, Windows zip, Linux tarball). The builds are not code-signed yet: on macOS,
right-click → *Abrir* the first time; on Windows, *Mais informações* → *Executar assim mesmo*.

From source:

```bash
dotnet run --project src/Apps/SimpleSign.Agent
scripts/package-agent.sh osx-arm64 0.11.0      # "SimpleSign Agent.app" in artifacts/agent
```

## Migrating from SimpleSign.HostSigner

Same port and the same `/api/health`, `/api/certificates` and `/api/sign` contract. What changes
for users: each site is authorized once, and each signature is confirmed in a dialog. Token
certificates now appear in `/api/certificates` (`source: "pkcs11"`).
