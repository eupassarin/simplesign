# WebSigningSample — Deferred PDF Signing

A sample ASP.NET web app that signs one or more PDFs using SimpleSign's **DeferredSigner** and a local signing agent (SimpleSign.Agent).

## Architecture

```
Browser (JavaScript)                    Server (ASP.NET)              Local Agent (:8070)
────────────────────                    ────────────────              ──────────────────
1. GET /ReadCertificates  ─────────────────────────────────────────→  Returns certs
2. Select cert + upload PDFs
3. POST /api/prepare (PDF + cert)  ──→  DeferredSigner.PrepareAsync() → hash
4. POST /SignHashsPOST (hashes)  ──────────────────────────────────→  Signs with key
5. POST /api/complete (session + sig) → DeferredSigner.CompleteAsync() → signed PDF
6. Download signed PDFs ✓
```

The **private key never leaves the user's machine**. The server only receives the public certificate and hash digests — the agent signs locally.

## Running

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

## Agent Endpoints (called from browser JS)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/Client/ReadCertificates` | Lists available certificates |
| `POST` | `/api/Client/SignHashsPOST` | Signs hash digests with the selected certificate's private key |

## Requirements

- .NET 8+
- SimpleSign.Agent running locally at `https://localhost:8070`
