# SimpleSign.Signers.Cloud

Sign PAdES, CAdES and XAdES documents with **cloud certificates**: ICP-Brasil PSCs (BirdID,
VIDaaS, NeoID, SafeID, RemoteID — the ITI's PSC API, DOC-ICP-17.01) and **Cloud Signature
Consortium API v2** services. OAuth 2.0 with PKCE, no third-party dependencies, Native AOT compatible.

## Quickstart (ICP-Brasil PSC)

```csharp
using SimpleSign.PAdES;
using SimpleSign.Signers.Cloud;
using SimpleSign.Signers.Cloud.Psc;

var client = new PscClient(new PscClientOptions
{
    BaseUri = new Uri("https://<provider>/v0/"),
    ClientId = clientId,
    ClientSecret = clientSecret,
});
var token = await client.AuthorizeAsync(new LoopbackAuthorizationHandler(),
    PscScope.SignatureSession, TimeSpan.FromMinutes(10), loginHint: cpf);
using var signer = await PscSigner.CreateAsync(client, token);

byte[] signed = await PadesSigner.Document(pdfBytes)
    .WithExternalSigner(signer.Certificate, signer, signer.Chain)
    .SignAsync();
```

## Quickstart (CSC v2)

```csharp
using SimpleSign.Signers.Cloud.Csc;

var client = new CscClient(new CscClientOptions { BaseUri = new Uri("https://<qtsp>/csc/v2/"), AccessToken = serviceToken });
using var signer = await CscSigner.CreateAsync(client, credentialId, new ExplicitCscAuthorizer(pin));
```

The PSC defaults were validated against SimpleSign's simulator; confirm them in each provider's
homologation environment. More in the
[cloud signing guide](https://eupassarin.github.io/SimpleSign/articles/cloud-signing.html). MIT licensed.
