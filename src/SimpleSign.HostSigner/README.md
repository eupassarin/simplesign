# SimpleSign.HostSigner

A lightweight Windows tray application that exposes local certificate operations over HTTP, enabling browser-based PDF signing workflows.

## How it works

```
Browser (JavaScript)          HostSigner (localhost:21590)          OS Certificate Store
────────────────────          ─────────────────────────────          ──────────────────
1. GET /api/certificates  ──→  Lists signing certificates  ────────→  CurrentUser\My
2. POST /api/sign         ──→  Signs hash digests          ────────→  Private key operation
```

The **private key never leaves the machine**. The browser sends only hash digests — HostSigner signs them using the OS certificate store.

## Installation

### Quick Install (download from GitHub Releases)

No .NET SDK required — the download is self-contained:

```powershell
irm https://raw.githubusercontent.com/eupassarin/SimpleSign/main/scripts/install/install-hostsigner.ps1 | iex
```

Or install a specific version:

```powershell
.\install-hostsigner.ps1 -Version 0.1.0
```

### Install from Source

Requires .NET 8 SDK:

```powershell
.\scripts\install\install-hostsigner-local.ps1
```

Both scripts:
- Install to `%LOCALAPPDATA%\SimpleSign\HostSigner`
- Register the `simplesign://` protocol handler (HKCU, no admin needed)
- Unblock files to prevent Windows SmartScreen issues

> **Note:** Windows Defender may block unsigned executables. You may need to add an exclusion for `%LOCALAPPDATA%\SimpleSign`.

## API Reference

Base URL: `http://localhost:21590`

All endpoints return JSON and include CORS headers (`Access-Control-Allow-Origin: *`).

### GET /api/health

Health check — used to detect if HostSigner is running.

**Response:**

```json
{ "status": "ok", "version": "0.1.0" }
```

### GET /api/certificates

Lists signing certificates with private keys from the current user's certificate store.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filterIcpBrasil` | `bool` | `false` | Filter to ICP-Brasil certificates only |

**Response:**

```json
[
  {
    "name": "CN=John Doe",
    "thumbprint": "A1B2C3D4...",
    "issuerName": "CN=My CA",
    "notBefore": "2024-01-01T00:00:00",
    "expireDate": "2026-01-01T00:00:00",
    "signatureAlgorithm": "RSA",
    "hashAlgorithm": "SHA256",
    "userCertificateBase64": "MIID..."
  }
]
```

### POST /api/sign

Signs one or more hash digests using a certificate identified by thumbprint.

**Request:**

```json
{
  "hashAlgorithm": "SHA256",
  "signatureAlgorithm": "RSA",
  "thumbprint": "A1B2C3D4...",
  "signRequests": [
    {
      "id": "0",
      "authenticatedAttributeBase64": "base64-encoded-data-to-sign"
    }
  ]
}
```

**Response:**

```json
[
  {
    "id": "0",
    "signedHashBase64": "base64-encoded-signature"
  }
]
```

**Error response (per item):**

```json
[
  {
    "id": "0",
    "error": "Certificate not found: A1B2C3D4..."
  }
]
```

### GET /api/version

Checks for updates against GitHub Releases.

**Response:**

```json
{
  "current": "0.1.0",
  "latest": "0.2.0",
  "updateAvailable": true,
  "downloadUrl": "https://github.com/eupassarin/SimpleSign/releases/tag/v0.2.0"
}
```

## Features

- **System tray** — runs minimized in the notification area
- **Auto-update check** — checks GitHub Releases on startup, shows balloon notification
- **Certificates tab** — view all signing certificates with expiry status (🟢/🔴)
- **Logs tab** — real-time HTTP request logging with clear button
- **About tab** — version, endpoint, PID, .NET version, GitHub link
- **Status bar** — connection status, update link when available
- **CORS enabled** — accessible from any web origin
- **Single instance** — mutex prevents duplicate processes
- **Protocol handler** — supports `simplesign://` deep links for auto-launch from browsers

## Running from Source

```bash
cd src/SimpleSign.HostSigner
dotnet run
```

## Protocol Registration

The install scripts register the protocol automatically. To register manually:

```reg
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Classes\simplesign]
@="SimpleSign HostSigner"
"URL Protocol"=""

[HKEY_CURRENT_USER\Software\Classes\simplesign\shell\open\command]
@="\"C:\\path\\to\\simplesign-hostsigner.exe\" \"%1\""
```

## Requirements

- Windows (WinForms-based tray app)
- .NET 8+ (or use the self-contained installer which includes the runtime)
