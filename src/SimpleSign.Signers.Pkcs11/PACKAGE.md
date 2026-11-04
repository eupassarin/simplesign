# SimpleSign.Signers.Pkcs11

Sign PAdES, CAdES and XAdES documents with a private key that stays on an **A3 token, smartcard
or HSM**, through the device's PKCS#11 driver — on Windows, Linux and macOS. Own minimal interop:
no third-party dependencies, no `unsafe` code. Native AOT compatible.

## Quickstart

```csharp
using SimpleSign.PAdES;
using SimpleSign.Signers.Pkcs11;

using var token = Pkcs11Signer.Open(new Pkcs11SignerOptions
{
    LibraryPath = "/usr/lib/libeToken.so",   // the token vendor's PKCS#11 driver
    KeyLabel = "My signing key",             // optional when the token has one key
    Pin = pin,                               // null for readers with a PIN pad
});

byte[] signed = await PadesSigner.Document(pdfBytes)
    .WithExternalSigner(token.Certificate, token, token.Chain)
    .SignAsync();
```

`Pkcs11Signer.ListTokens(libraryPath)` lists the connected tokens and their certificates without a PIN.

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [PKCS#11 guide](https://eupassarin.github.io/SimpleSign/articles/pkcs11.html). MIT licensed.
