# SimpleSign.Agent

The **local signing agent**: a tray / menu-bar app that web pages call to sign with a key the
browser cannot reach on its own — a certificate in the operating system's store, or an A3 token or
smartcard over PKCS#11.

Cross-platform (Avalonia; macOS, Windows, Linux), published with Native AOT, no Dock icon on macOS.
It replaces the Windows-only `SimpleSign.HostSigner`.

```bash
dotnet run --project src/Apps/SimpleSign.Agent
```

The API listens on **`http://127.0.0.1:21590`**, loopback only. Only one instance runs per user;
launching it again asks the running one to show its window.

## The API

| Endpoint | What it does |
|---|---|
| `GET /api/health` | `{ "status": "ok", "version": "…", "app": "SimpleSign Agent" }` |
| `GET /api/certificates` | The usable certificates, with any policy problem; `?country=XX`, `?trust=icp-brasil\|govbr`, `?signingOnly=true` |
| `POST /api/sign` | Signs one payload, after the user confirms it in a dialog |

`POST /api/sign` accepts **only what a signature is made of** — DER CMS signed attributes, or a
canonical XML-DSig `SignedInfo`. A raw hash, a whole document or bytes of another protocol are
refused with 400 *before* the user is asked, and the consent dialog shows the digest being signed
(`DataToSignInspector`). Each origin has to be authorized once, and the PIN is asked by the app,
never by the page.

This pairs with [two-phase signing](../../../docs/articles/deferred-signing.md): your server
prepares, the agent signs, your server completes — the document and the policy never leave the
server.

## The window

Opened from the tray menu, or automatically on first run.

| Page | |
|---|---|
| Overview | The agent's state, the certificates it sees and any problem with them |
| Sites | The authorized origins, and a way to revoke one |
| Activity | What has been signed |
| Test | A real health → certificates → sign round trip, through the consent dialog |
| Documentation | The built-in guide (en-US and pt-BR) |

Plus Settings and About panels. The tray menu shows the listening address and pauses, opens or
quits the agent.

## Developer flags

```bash
dotnet run --project src/Apps/SimpleSign.Agent -- --self-check     # checks a published binary, no window
dotnet run --project src/Apps/SimpleSign.Agent -- --export-icons <dir>
```

## Packaging

```bash
scripts/package-agent.sh osx-arm64 0.11.0    # also osx-x64, linux-x64, linux-arm64, win-x64
```

Native AOT, so it must be built on the target OS (on macOS both architectures build from either
one). The builds are **not code-signed or notarized**: on macOS the first launch needs
right-click → Open.

Full guide: [docs/articles/agent.md](../../../docs/articles/agent.md). How it fits with the other
apps: [docs/articles/apps.md](../../../docs/articles/apps.md).
