# Signing with A3 tokens, smartcards and HSMs (PKCS#11)

`SimpleSign.Signers.Pkcs11` signs with a private key that never leaves the device. It talks to the
device through the vendor's **PKCS#11 driver**, so it works the same on Windows, Linux and macOS.
SimpleSign computes the hash itself; the token only performs the key operation.

```bash
dotnet add package SimpleSign.Signers.Pkcs11
```

The package uses its own minimal interop over the driver (no third-party dependencies, no `unsafe`
code) and works in Native AOT applications.

## Sign a PDF

```csharp
using SimpleSign.PAdES;
using SimpleSign.Signers.Pkcs11;

using var token = Pkcs11Signer.Open(new Pkcs11SignerOptions
{
    LibraryPath = "/usr/lib/libeToken.so",   // the token vendor's PKCS#11 driver
    Pin = pin,
});

byte[] signed = await PadesSigner.Document(pdfBytes)
    .WithExternalSigner(token.Certificate, token, token.Chain)
    .SignAsync();
```

`Pkcs11Signer` is an `IExternalSigner`, so the same instance works with `CadesSigner`,
`XadesSigner`, `BatchSigner` and the deferred signer. Timestamps and LTV levels work as usual.

`token.Certificate` is read from the token, and `token.Chain` holds the CA certificates stored on
it. An instance keeps one logged-in session until it is disposed; disposing it logs out and also
disposes `Certificate` and `Chain`. Calls are serialized, so one instance can serve concurrent
signing operations.

## Choosing the token and the key

With no selectors, the only token connected and its only key that has a certificate are used.
Otherwise set one or more of:

| Option | Selects |
|---|---|
| `TokenLabel`, `TokenSerial`, `SlotId` | the token |
| `KeyLabel` | the key, by the label of the key **or** of its certificate |
| `KeyId` | the key, by `CKA_ID` (shared by the key and its certificate) |
| `CertificateThumbprint` | the key, by its certificate's SHA-1 thumbprint |

When the selection matches nothing or more than one key, `Pkcs11Exception` lists what the token
has. To discover labels and thumbprints without a PIN:

```csharp
foreach (var t in Pkcs11Signer.ListTokens(libraryPath))
{
    Console.WriteLine($"{t.Label} ({t.Manufacturer} {t.Model}, serial {t.SerialNumber})");
    foreach (var c in t.Certificates)
    {
        Console.WriteLine($"  {c.Label}: {c.Certificate.Subject} {c.Certificate.Thumbprint}");
        c.Certificate.Dispose();
    }
}
```

## PIN

Set `Pin` to the user PIN. It is copied to a native buffer that is zeroed right after login and is
never logged. For readers with a PIN pad, leave `Pin` null and the PIN is typed on the reader.

`Pkcs11Exception` carries the driver's return value: `IsPinIncorrect` and `IsPinLocked` cover the
common cases, and `ReturnValueName` gives the `CKR_*` name for the rest. Tokens lock the PIN after a
few wrong attempts, so do not retry a wrong PIN automatically.

## Supported algorithms

| Key | Signature | PKCS#11 mechanism |
|---|---|---|
| RSA | PKCS#1 v1.5 (SHA-1, SHA-2, SHA-3) | `CKM_RSA_PKCS` |
| RSA | RSASSA-PSS (SHA-1, SHA-2) — `WithSignatureAlgorithm(Oids.RsaPss)` | `CKM_RSA_PKCS_PSS` |
| EC | ECDSA (SHA-2, SHA-3) | `CKM_ECDSA` |

## Finding the driver

The driver ships with the token's middleware. SimpleSign knows where the middlewares used in
Brazil install it (SafeNet/Thales, SafeSign/G+D, Watchdata, Gemalto IDPrime/GemSafe,
Oberthur/Certisign, Pronova, Feitian ePass2003, Safeweb, NeoID, Dexon, birdID, desktopID, OpenSC and
SoftHSM), so the path is usually not needed:

```csharp
// The library of the connected token (or of the one labelled "ICP-Brasil" when several are)
string library = await Pkcs11Drivers.FindLibraryAsync();
using var token = Pkcs11Signer.Open(new Pkcs11SignerOptions { LibraryPath = library, Pin = pin });

// Every installed driver and its tokens
foreach (var found in await Pkcs11Drivers.FindTokensAsync())
{
    Console.WriteLine($"{found.Driver.Driver.Product} ({found.Driver.LibraryPath}): {found.Tokens.Count} token(s) {found.Error}");
}
```

`Pkcs11Drivers.DetectInstalled()` only checks which files exist; `FindTokensAsync` loads each
driver and skips, with the reason, those that fail. Other drivers can be added with the
`SIMPLESIGN_PKCS11_LIBRARY` environment variable (paths separated by `:`, or `;` on Windows).
`Pkcs11Drivers.Known` is the catalog. Typical locations:

| Middleware | Windows | Linux | macOS |
|---|---|---|---|
| SafeNet Authentication Client (eToken) | `C:\Windows\System32\eTPKCS11.dll` | `/usr/lib/libeToken.so` | `/usr/local/lib/libeTPkcs11.dylib` |
| SafeSign Identity Client (A.E.T.) | `C:\Windows\System32\aetpkss1.dll` | `/usr/lib/libaetpkss.so` | `/usr/local/lib/libaetpkss.dylib` |
| OpenSC (smartcards) | `C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll` | `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` | `/Library/OpenSC/lib/opensc-pkcs11.so` |
| SoftHSM2 (testing) | — | `/usr/lib/softhsm/libsofthsm2.so` | `/opt/homebrew/lib/softhsm/libsofthsm2.so` |

Paths vary with the middleware version; check its installation folder. The process must have the
same architecture as the driver (64-bit drivers for 64-bit processes).

> Drivers read their own configuration through the native environment. On Linux and macOS,
> `Environment.SetEnvironmentVariable` does not reach native code, so variables such as
> `SOFTHSM2_CONF` must be set before the process starts.

## CLI

```bash
simplesign pkcs11 drivers                     # the catalog and what is installed
simplesign pkcs11 list                        # tokens of every installed driver
simplesign pkcs11 list --lib /usr/lib/libeToken.so
simplesign sign contract.pdf --pkcs11-lib auto --pkcs11-key "My signing key"
simplesign sign contract.pdf --pkcs11-lib /usr/lib/libeToken.so --pkcs11-key "My signing key"
simplesign cades sign data.bin --pkcs11-lib /usr/lib/libeToken.so --tsa http://timestamp.digicert.com --level timestamped
```

Without `--pin` the CLI asks for the PIN; leave it blank to use the reader's PIN pad.

## Testing without a token

The package is tested against [SoftHSM2](https://github.com/softhsm/SoftHSMv2), a software token.
`scripts/tests/pkcs11.sh` runs the token tests and a Native AOT smoke test in Docker; on Linux with
`softhsm2` and `opensc` installed, `scripts/tests/pkcs11-run.sh` runs them directly.

The package has been tested with SoftHSM2 only. Reports of drivers that work (or do not) are welcome
in the issue tracker.
