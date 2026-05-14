# WebSigningSample

Sample ASP.NET web app that signs PDFs using SimpleSign's **DeferredSigner** + a local signing agent.

## Architecture

```
Browser (JavaScript)                    Server (ASP.NET)              Local Agent (:8070)
────────────────────                    ────────────────              ──────────────────
1. GET /ReadCertificates  ─────────────────────────────────────────→  Returns certs
2. Select cert ✓
3. Upload PDF + cert  ────────────────→  PrepareAsync() → hashes
4. POST /SignHashs + hashes  ──────────────────────────────────────→  Signs with key
5. Send signatures  ──────────────────→  CompleteAsync() → signed PDF
6. Download ✓
```

The **private key never leaves the user's machine**. Only hashes travel to the agent.

## Run

```bash
cd samples/WebSigningSample
dotnet run
```

## Requirements

- .NET 8+
- Local signing agent running at `https://localhost:8070` with:
  - `GET /api/Client/ReadCertificates?filtroCertificadosICPBrasil=true`
  - `POST /api/Client/SignHashs`
