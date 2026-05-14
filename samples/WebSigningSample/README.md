# WebSigningSample — Deferred PDF Signing

A sample ASP.NET web app that signs one or more PDFs using SimpleSign's **DeferredSigner** and **SimpleSign.HostSigner** running on the user's machine.

## Architecture

```
Browser (JavaScript)                    Server (ASP.NET)              HostSigner (localhost:21590)
────────────────────                    ────────────────              ───────────────────────────
1. GET /api/certificates  ─────────────────────────────────────────→  Returns certs
2. Select cert + upload PDFs
3. POST /api/prepare (PDF + cert)  ──→  DeferredSigner.PrepareAsync() → hash
4. POST /api/sign (hashes)  ───────────────────────────────────────→  Signs with key
5. POST /api/complete (session + sig) → DeferredSigner.CompleteAsync() → signed PDF
6. Download signed PDFs ✓
```

The **private key never leaves the user's machine**. The server only receives the public certificate and hash digests — HostSigner signs locally.

If HostSigner is not running, the browser offers a "Launch HostSigner" button that opens `simplesign://` to start it automatically.

## Prerequisites

Install HostSigner on the user's machine:

```powershell
# Quick install (no .NET SDK required)
irm https://raw.githubusercontent.com/eupassarin/SimpleSign/main/scripts/install/install-hostsigner.ps1 | iex

# Or from source
.\scripts\install\install-hostsigner-local.ps1
```

See [HostSigner README](../../src/SimpleSign.HostSigner/README.md) for full setup instructions.

## Running

1. Start HostSigner:

```bash
cd src/SimpleSign.HostSigner
dotnet run
```

2. Start the web sample:

```bash
cd samples/WebSigningSample
dotnet run
```

Open http://localhost:5133 (or https://localhost:7180) in your browser.

## Server Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/prepare` | Receives a PDF + base64 certificate, returns `hashToSign` and `sessionData` |
| `POST` | `/api/complete` | Receives `sessionData` + raw signature, returns the signed PDF |

## HostSigner Endpoints (called from browser JS)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/certificates` | Lists available signing certificates from the OS certificate store |
| `POST` | `/api/sign` | Signs hash digests with the selected certificate's private key |
| `GET` | `/api/health` | Health check — used to detect if HostSigner is running |

See [HostSigner API Reference](../../src/SimpleSign.HostSigner/README.md#api-reference) for request/response formats.

## Requirements

- .NET 8+
- SimpleSign.HostSigner running locally (port 21590)
