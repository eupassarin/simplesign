using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Signers.Cloud;
using SimpleSign.Signers.Cloud.Csc;
using SimpleSign.Signers.Pkcs11;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Credentials;

public sealed record SandboxCredentialRequest(string SignerId);

public sealed record PfxCredentialRequest(string UploadId, string? Password);

public sealed record StoreCredentialRequest(string Thumbprint);

public sealed record Pkcs11CredentialRequest(string LibraryPath, string? TokenSerial, string? CertificateThumbprint, string? Pin, bool UsePinPad);

public enum CscServiceAuth
{
    /// <summary>A service access token obtained elsewhere.</summary>
    Token,

    /// <summary>OAuth client credentials (client id + secret).</summary>
    ClientCredentials,

    /// <summary>OAuth authorization code: the user logs in to the service.</summary>
    OAuth,
}

public enum CscAuthorizerKind
{
    /// <summary>credentials/authorize with the PIN (and OTP for SCAL 2).</summary>
    Explicit,

    /// <summary>OAuth "credential" scope: the user authorizes the hashes on the provider's page.</summary>
    OAuth,
}

public sealed record CscCredentialRequest(
    string? BaseUrl, CscServiceAuth ServiceAuth, string? AccessToken, string? ClientId, string? ClientSecret,
    string CredentialId, CscAuthorizerKind Authorizer, string? Pin, string? Otp, int SignaturesPerAuthorization = 1);

public sealed record CscCredentialListRequest(string? BaseUrl, CscServiceAuth ServiceAuth, string? AccessToken, string? ClientId, string? ClientSecret);

public sealed record CscCredentialSummary(string Id, string Holder, string AuthMode, string Scal, int MultiSign, IReadOnlyList<string> Algorithms, bool Enabled);

public sealed record StoreCertificate(string Thumbprint, string Holder, string Issuer, string NotAfter, bool HasPrivateKey);

public sealed record Pkcs11TokenView(string LibraryPath, string Driver, string TokenLabel, string TokenSerial, bool HasPinPad, bool PinLocked,
    IReadOnlyList<StoreCertificate> Certificates);

public sealed record Pkcs11DriverView(string Driver, string LibraryPath, string? Error, IReadOnlyList<Pkcs11TokenView> Tokens);

/// <summary>Opens each kind of credential, in the sandbox (simulated) or for real.</summary>
internal sealed class CredentialFactory(SandboxEnvironment sandbox, DocumentStore documents)
{
    private const string RsaPssOid = "1.2.840.113549.1.1.10";
    private static readonly IReadOnlyList<HashChoice> Sha2 = [HashChoice.Sha256, HashChoice.Sha384, HashChoice.Sha512];

    public CredentialHandle OpenSandbox(SandboxCredentialRequest request)
    {
        var signer = sandbox.Pki.Signer(request.SignerId);
        var notes = new List<Note> { "Issued by the sandbox PKI (AC Raiz Sandbox SimpleSign). Validation in the TestBench trusts this root; real validators will not." };
        if (signer.Problem is not null)
        {
            notes.Add(new Note(signer.Description));
        }

        return new CredentialHandle(CredentialKind.SandboxA1, "Sandbox A1 · " + signer.Title, signer.Certificate, sandbox.Pki.Chain, null, null, notes: notes);
    }

    public CredentialHandle OpenPfx(PfxCredentialRequest request)
    {
        var file = documents.Get(request.UploadId);
        var collection = X509CertificateLoader.LoadPkcs12Collection(file.Content, request.Password, KeyStorage);
        var leaf = collection.FirstOrDefault(c => c.HasPrivateKey)
            ?? throw new CryptographicException(L.T("The PFX has no certificate with a private key."));
        var chain = collection.Where(c => !ReferenceEquals(c, leaf)).ToList();
        return new CredentialHandle(CredentialKind.Pfx, "PFX · " + file.FileName, leaf, chain, null, new Owned(collection),
            notes: ["The password is used once to open the file and is not stored."]);
    }

    public static IReadOnlyList<StoreCertificate> ListStore()
    {
        var result = new List<StoreCertificate>();
        try
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            foreach (var certificate in store.Certificates)
            {
                result.Add(View(certificate, certificate.HasPrivateKey));
                certificate.Dispose();
            }
        }
        catch (CryptographicException)
        {
            // No user store on this platform.
        }

        return result;
    }

    public static CredentialHandle OpenStore(StoreCredentialRequest request)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var found = store.Certificates.Find(X509FindType.FindByThumbprint, request.Thumbprint, validOnly: false);
        var certificate = found.FirstOrDefault(c => c.HasPrivateKey)
            ?? throw new CryptographicException(L.T("Certificate not found in the user store, or it has no private key."));
        return new CredentialHandle(CredentialKind.OsStore, OperatingSystem.IsMacOS() ? "macOS keychain" : "OS certificate store", certificate, [], null, certificate,
            notes: ["The OS may show its own prompt (keychain password, smartcard PIN) when signing."]);
    }

    public static async Task<IReadOnlyList<Pkcs11DriverView>> ListTokensAsync(CancellationToken cancellationToken)
    {
        var drivers = await Pkcs11Drivers.FindTokensAsync(cancellationToken);
        return [.. drivers.Select(d => new Pkcs11DriverView(
            d.Driver.Driver.Product, d.Driver.LibraryPath, d.Error,
            [.. d.Tokens.Select(t => new Pkcs11TokenView(d.Driver.LibraryPath, d.Driver.Driver.Product, t.Label.Trim(), t.SerialNumber.Trim(),
                t.HasProtectedAuthenticationPath, t.IsPinLocked,
                [.. t.Certificates.Select(c => View(c.Certificate, true))]))]))];
    }

    public static CredentialHandle OpenPkcs11(Pkcs11CredentialRequest request)
    {
        var signer = Pkcs11Signer.Open(new Pkcs11SignerOptions
        {
            LibraryPath = request.LibraryPath,
            TokenSerial = string.IsNullOrWhiteSpace(request.TokenSerial) ? null : request.TokenSerial,
            CertificateThumbprint = string.IsNullOrWhiteSpace(request.CertificateThumbprint) ? null : request.CertificateThumbprint,
            Pin = request.UsePinPad ? null : request.Pin,
            Logger = Runs.AmbientRunLogger.Instance,
        });
        return new CredentialHandle(CredentialKind.Pkcs11, $"PKCS#11 · {Path.GetFileName(request.LibraryPath)}", signer.Certificate, signer.Chain, signer, signer,
            hashes: Sha2,
            notes: ["The token session stays open (logged in) until you close this credential or the TestBench stops.",
                "RSASSA-PSS needs the token to support CKM_RSA_PKCS_PSS; many tokens only do PKCS#1 v1.5."]);
    }

    public async Task<IReadOnlyList<CscCredentialSummary>> ListCscAsync(CscCredentialListRequest request, EnvironmentMode mode, CancellationToken cancellationToken)
    {
        var client = await CscClientAsync(request.BaseUrl, request.ServiceAuth, request.AccessToken, request.ClientId, request.ClientSecret, mode, cancellationToken);
        var credentials = await client.ListCredentialsAsync(cancellationToken);
        var result = credentials.Select(c => new CscCredentialSummary(c.Id, c.Certificate.GetNameInfo(X509NameType.SimpleName, false),
            c.AuthMode, c.Scal, c.MultiSign, c.KeyAlgorithms, c.IsKeyEnabled)).ToList();
        foreach (var credential in credentials)
        {
            credential.Certificate.Dispose();
        }

        return result;
    }

    public async Task<CredentialHandle> OpenCscAsync(CscCredentialRequest request, EnvironmentMode mode, CancellationToken cancellationToken)
    {
        bool isSandbox = mode == EnvironmentMode.Sandbox;
        var client = await CscClientAsync(request.BaseUrl, request.ServiceAuth, request.AccessToken, request.ClientId, request.ClientSecret, mode, cancellationToken);
        ICscCredentialAuthorizer authorizer = request.Authorizer == CscAuthorizerKind.OAuth
            ? new OAuthCscAuthorizer(isSandbox ? sandbox.Csc : new LoopbackAuthorizationHandler())
            : new ExplicitCscAuthorizer(request.Pin, string.IsNullOrWhiteSpace(request.Otp) ? null : request.Otp, Math.Max(1, request.SignaturesPerAuthorization));
        var signer = await CscSigner.CreateAsync(client, request.CredentialId, authorizer, cancellationToken: cancellationToken);
        var algorithms = signer.Credential.KeyAlgorithms;
        bool isRsa = signer.Certificate.GetRSAPublicKey() is not null;
        var paddings = new List<RsaPadding>();
        if (isRsa && algorithms.Any(a => a != RsaPssOid))
        {
            paddings.Add(RsaPadding.Pkcs1);
        }

        if (isRsa && algorithms.Contains(RsaPssOid))
        {
            paddings.Add(RsaPadding.Pss);
        }

        var notes = new List<Note>
        {
            new("Credential '{0}': SCAL {1}, auth mode {2}, {3} signature(s) per authorization.", signer.Credential.Id, signer.Credential.Scal, signer.Credential.AuthMode, signer.Credential.MultiSign),
            new("Key algorithms: {0}", string.Join(", ", algorithms)),
        };
        if (isSandbox)
        {
            notes.Insert(0, "Simulated CSC v2 service (PIN 1234, OTP 123456; the OAuth page is approved automatically).");
        }

        return new CredentialHandle(CredentialKind.Csc, $"CSC · {client.Options.BaseUri.Host} · {signer.Credential.Id}", signer.Certificate, signer.Chain,
            signer, signer, hashes: Sha2, paddings: paddings, notes: notes);
    }

    private async Task<CscClient> CscClientAsync(string? baseUrl, CscServiceAuth auth, string? accessToken, string? clientId, string? clientSecret,
        EnvironmentMode mode, CancellationToken cancellationToken)
    {
        bool isSandbox = mode == EnvironmentMode.Sandbox;
        var options = new CscClientOptions
        {
            BaseUri = isSandbox ? SandboxCsc.BaseUri : HttpsUrl(baseUrl, "CSC base URL"),
            AccessToken = auth == CscServiceAuth.Token ? (isSandbox ? SandboxCsc.ServiceToken : Required(accessToken, "access token")) : null,
            ClientId = isSandbox ? SandboxCsc.ClientId : clientId,
            ClientSecret = isSandbox ? SandboxCsc.ClientSecret : clientSecret,
            Logger = Runs.AmbientRunLogger.Instance,
        };
        var client = new CscClient(options, isSandbox ? sandbox.Network.GetClient() : null);
        switch (auth)
        {
            case CscServiceAuth.ClientCredentials:
                await client.AuthorizeServiceWithClientCredentialsAsync(cancellationToken);
                break;
            case CscServiceAuth.OAuth:
                await client.AuthorizeServiceAsync(isSandbox ? sandbox.Csc : new LoopbackAuthorizationHandler(), cancellationToken);
                break;
            default:
                break;
        }

        return client;
    }

    private static StoreCertificate View(X509Certificate2 certificate, bool hasKey) => new(
        certificate.Thumbprint,
        certificate.GetNameInfo(X509NameType.SimpleName, false),
        certificate.GetNameInfo(X509NameType.SimpleName, true),
        certificate.NotAfter.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
        hasKey);

    private static X509KeyStorageFlags KeyStorage =>
        OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet;

    /// <summary>A provider URL typed by the user: absolute https only.</summary>
    private static Uri HttpsUrl(string? value, string name) =>
        Uri.TryCreate(Required(value, name), UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps
            ? uri
            : throw new ArgumentException(L.T("{0} must be an absolute https:// URL.", name));

    private static string Required(string? value, string name) =>
        string.IsNullOrWhiteSpace(value) ? throw new ArgumentException(L.T("{0} is required.", name)) : value.Trim();

    private sealed class Owned(X509Certificate2Collection collection) : IDisposable
    {
        public void Dispose()
        {
            foreach (var certificate in collection)
            {
                certificate.Dispose();
            }
        }
    }
}
