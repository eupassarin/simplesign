# Cloud signing (ICP-Brasil PSCs and CSC v2)

`SimpleSign.Signers.Cloud` signs with certificates whose keys live in a provider's HSM:

- **ICP-Brasil cloud certificates** from PSCs (*Prestadores de Serviço de Confiança*) such as
  BirdID, VIDaaS, NeoID, SafeID and RemoteID, through the ITI's PSC API ("API v0", DOC-ICP-17.01);
- **remote signing services** that implement the **Cloud Signature Consortium API v2** (common
  among European QTSPs).

```bash
dotnet add package SimpleSign.Signers.Cloud
```

Both signers are `IExternalSigner`s, so they work with `PadesSigner`, `CadesSigner`,
`XadesSigner`, `BatchSigner` and the deferred signer. SimpleSign hashes the data locally; only
the hash goes to the provider. The package has no third-party dependencies and works in Native
AOT applications.

> **Note:** the PSC API defaults were checked against SimpleSign's PSC simulator only. Run
> the steps in [Homologation](#homologation) against each provider before going to production.

## ICP-Brasil PSC

### 1. Register your application

Ask the provider for a `client_id`/`client_secret` and register the redirect URI. Desktop and CLI
apps usually use a loopback URI such as `http://127.0.0.1:43821/callback`.

### 2. Authorize

The holder approves the signature in the provider's page or app (OAuth 2.0 authorization code
with PKCE S256):

```csharp
using SimpleSign.Signers.Cloud;
using SimpleSign.Signers.Cloud.Psc;

var client = new PscClient(new PscClientOptions
{
    BaseUri = new Uri("https://<provider>/v0/"),   // from the provider
    ClientId = clientId,
    ClientSecret = clientSecret,
});

OAuthToken token = await client.AuthorizeAsync(
    new LoopbackAuthorizationHandler(),   // opens the browser and waits for the redirect
    PscScope.SignatureSession,            // sign several documents...
    TimeSpan.FromMinutes(10),             // ...for 10 minutes
    loginHint: cpf);
```

Providers that accept a one-time password from their app (the `pwd_authorize` flow) need no browser:

```csharp
OAuthToken token = await client.PasswordAuthorizeAsync(cpf, otpFromApp, PscScope.SignatureSession, TimeSpan.FromMinutes(10));
```

Web applications redirect the user themselves: build the URL with `BuildAuthorizationUri(pkce, ...)`
(keep the `OAuthPkce` in the user's session) and call `ExchangeCodeAsync(redirect, pkce)` in the
callback. The `state` is always checked.

| Scope | Signs |
|---|---|
| `SingleSignature` | one hash; the token is then invalidated |
| `MultiSignature` | one batch of hashes |
| `SignatureSession` | any number of hashes until the lifetime ends |

### 3. Sign

```csharp
using var signer = await PscSigner.CreateAsync(client, token);   // reads the certificate
byte[] signed = await PadesSigner.Document(pdf)
    .WithExternalSigner(signer.Certificate, signer, signer.Chain)
    .SignAsync();
```

When the account has more than one certificate, pass its alias (`client.GetCertificatesAsync(token)`
lists them). PSCs issue **RSA keys only** and return PKCS#1 v1.5 signatures; ECDSA and RSASSA-PSS
requests are refused with `NotSupportedException`.

### Provider differences

Field names, paths and the encoding of hashes are in `PscWireFormat`. Override what differs
without changing code:

```csharp
var options = new PscClientOptions
{
    BaseUri = baseUri,
    ClientId = clientId,
    WireFormat = PscWireFormat.Default with { HashEncoding = PscBinaryEncoding.Hex },
};
```

## CSC API v2

```csharp
using SimpleSign.Signers.Cloud.Csc;

var client = new CscClient(new CscClientOptions
{
    BaseUri = new Uri("https://<qtsp>/csc/v2/"),
    ClientId = clientId,
    ClientSecret = clientSecret,
});
await client.AuthorizeServiceWithClientCredentialsAsync();   // or AuthorizeServiceAsync(handler), or AccessToken

foreach (var credential in await client.ListCredentialsAsync())
{
    Console.WriteLine($"{credential.Id}: {credential.Certificate.Subject} ({credential.AuthMode}, SCAL {credential.Scal})");
}

using var signer = await CscSigner.CreateAsync(client, credentialId, new ExplicitCscAuthorizer(pin));
byte[] signed = await PadesSigner.Document(pdf)
    .WithExternalSigner(signer.Certificate, signer, signer.Chain)
    .SignAsync();
```

- **Authorization:** `ExplicitCscAuthorizer(pin, otp)` calls `credentials/authorize`. For SCAL 1
  credentials one SAD may cover several signatures (`signaturesPerAuthorization`, capped by the
  credential's `multisign`); for SCAL 2 every signature is authorized for its own hash.
  `OAuthCscAuthorizer(handler)` uses the OAuth `credential` scope, where the user approves the exact hashes.
- **Algorithms:** RSA PKCS#1 v1.5, RSASSA-PSS (`WithSignatureAlgorithm(Oids.RsaPss)`) and ECDSA, as
  allowed by the credential's `key/algo`. ECDSA signatures are accepted as DER or raw `r||s`.

## Errors and secrets

Every provider refusal is a `CloudSigningException` with `StatusCode`, `Error` and
`ErrorDescription`. Tokens, SADs, PINs, OTPs and client secrets are never written to messages or
logs (`OAuthToken.ToString()` hides the token), and nothing is persisted by the package.

## CLI

```bash
# PSC with a one-time password from the provider's app
simplesign sign contract.pdf --psc-url https://<provider>/v0/ --psc-client-id <id> \
  --psc-client-secret env:PSC_SECRET --psc-cpf 12345678909 --psc-otp 123456

# PSC with the browser login (omit --psc-otp)
simplesign psc certificates --psc-url https://<provider>/v0/ --psc-client-id <id> --psc-cpf 12345678909

# CSC
simplesign csc list --csc-url https://<qtsp>/csc/v2/ --csc-token env:CSC_TOKEN
simplesign cades sign data.bin --csc-url https://<qtsp>/csc/v2/ --csc-token env:CSC_TOKEN \
  --csc-credential <id> --pin env:CSC_PIN
```

Secret options accept `env:NAME` to keep values out of the shell history.

## Homologation

1. Get sandbox credentials from the provider (client ID/secret and a test holder).
2. Run the integration tests, which are skipped until these variables are set:

   ```bash
   PSC_BASE_URL=https://<provider-sandbox>/v0/ PSC_CLIENT_ID=... PSC_CLIENT_SECRET=... \
   PSC_CPF=... PSC_OTP=... dotnet test tests/unit/Signers/SimpleSign.Signers.Cloud.Tests --filter Category=Integration
   ```

   For CSC: `CSC_BASE_URL`, `CSC_TOKEN`, `CSC_CREDENTIAL` and `CSC_PIN`.
3. If a call fails because of a field name or encoding, adjust `PscWireFormat` and report the
   difference in the issue tracker so the defaults can be improved.
4. Check the signed PDF on [validar.iti.gov.br](https://validar.iti.gov.br).

## Signing policy

Cloud certificates go through the same checks as local ones: the builder's `SigningPolicy` (chain validity, key
usage, key size, hash algorithm) runs before the provider is asked to sign. With a signing policy whose `NotRevoked` is FAIL the revocation
of the chain is checked too, so the provider's chain (`signer.Chain`) must reach the root. The provider interface is
the generic `IExternalSigner` described in [remote signing](remote-signing.md).
