using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Signing;
using SimpleSign.Signers.Cloud;
using SimpleSign.Signers.Cloud.Csc;
using SimpleSign.Signers.Cloud.Psc;
using SimpleSign.Signers.Pkcs11;
using Spectre.Console;

namespace SimpleSign.Cli.Commands;

/// <summary>A signer whose private key is outside this process, with its certificate and chain.</summary>
/// <param name="Signer">The external signer.</param>
/// <param name="Certificate">The signer certificate.</param>
/// <param name="Chain">Intermediate certificates.</param>
/// <param name="Owner">Releases the token session or cloud signer.</param>
internal sealed record ExternalCredential(
    IExternalSigner Signer, X509Certificate2 Certificate, IReadOnlyList<X509Certificate2> Chain, IDisposable Owner) : IDisposable
{
    public void Dispose() => Owner.Dispose();
}

/// <summary>Validates and opens the PKCS#11, PSC and CSC credentials of <see cref="ExternalCredentialSettings"/>.</summary>
internal static class ExternalCredentialSupport
{
    /// <summary>Whether the settings ask for an external credential.</summary>
    internal static bool IsRequested(ExternalCredentialSettings s) =>
        !string.IsNullOrWhiteSpace(s.Pkcs11Library) || !string.IsNullOrWhiteSpace(s.PscUrl) || !string.IsNullOrWhiteSpace(s.CscUrl);

    /// <summary>Validates the options against each other and against a local credential.</summary>
    /// <returns>An error message, or <see langword="null"/> when the options are valid.</returns>
    internal static string? Validate(ExternalCredentialSettings s, bool hasLocalCredential)
    {
        bool pkcs11 = !string.IsNullOrWhiteSpace(s.Pkcs11Library);
        bool psc = !string.IsNullOrWhiteSpace(s.PscUrl);
        bool csc = !string.IsNullOrWhiteSpace(s.CscUrl);

        if (pkcs11 && hasLocalCredential)
        {
            return "--pkcs11-lib cannot be combined with --cert or --thumbprint.";
        }

        if ((psc || csc) && hasLocalCredential)
        {
            return "--psc-url and --csc-url cannot be combined with --cert or --thumbprint.";
        }

        if ((pkcs11 ? 1 : 0) + (psc ? 1 : 0) + (csc ? 1 : 0) > 1)
        {
            return "Use only one of --pkcs11-lib, --psc-url and --csc-url.";
        }

        if (!pkcs11 && (s.Pkcs11Token is not null || s.Pkcs11Key is not null))
        {
            return "--pkcs11-token and --pkcs11-key require --pkcs11-lib.";
        }

        if (s.Pin is not null && !pkcs11 && !csc)
        {
            return "--pin requires --pkcs11-lib or --csc-url.";
        }

        if (!psc && (s.PscClientId ?? s.PscClientSecret ?? s.PscCpf ?? s.PscOtp ?? s.PscAlias) is not null)
        {
            return "--psc-client-id, --psc-client-secret, --psc-cpf, --psc-otp and --psc-alias require --psc-url.";
        }

        if (psc && string.IsNullOrWhiteSpace(s.PscClientId))
        {
            return "--psc-url requires --psc-client-id.";
        }

        if (psc && s.PscOtp is not null && string.IsNullOrWhiteSpace(s.PscCpf))
        {
            return "--psc-otp requires --psc-cpf.";
        }

        if (!csc && (s.CscToken ?? s.CscCredential ?? s.Otp) is not null)
        {
            return "--csc-token, --csc-credential and --otp require --csc-url.";
        }

        if (csc && (string.IsNullOrWhiteSpace(s.CscToken) || string.IsNullOrWhiteSpace(s.CscCredential)))
        {
            return "--csc-url requires --csc-token and --csc-credential.";
        }

        foreach (string? url in new[] { s.PscUrl, s.CscUrl })
        {
            if (!string.IsNullOrWhiteSpace(url) && !Uri.TryCreate(url, UriKind.Absolute, out _))
            {
                return $"Invalid URL: {url}";
            }
        }

        return null;
    }

    /// <summary>Opens the requested external credential, or returns <see langword="null"/> when none is requested.</summary>
    internal static async Task<ExternalCredential?> OpenAsync(ExternalCredentialSettings s, CancellationToken cancellationToken)
    {
        ExternalCredential? credential;
        if (!string.IsNullOrWhiteSpace(s.Pkcs11Library))
        {
            credential = await OpenPkcs11Async(s);
        }
        else if (!string.IsNullOrWhiteSpace(s.PscUrl))
        {
            credential = await OpenPscAsync(s, cancellationToken);
        }
        else if (!string.IsNullOrWhiteSpace(s.CscUrl))
        {
            var client = new CscClient(new CscClientOptions { BaseUri = new Uri(s.CscUrl), AccessToken = Secret(s.CscToken) });
            var signer = await CscSigner.CreateAsync(
                client, s.CscCredential!, new ExplicitCscAuthorizer(Secret(s.Pin), Secret(s.Otp)), cancellationToken: cancellationToken);
            credential = new ExternalCredential(signer, signer.Certificate, signer.Chain, signer);
            Announce($"CSC credential {signer.Credential.Id}", signer.Certificate);
        }
        else
        {
            credential = null;
        }

        return credential;
    }

    /// <summary>Resolves <c>env:NAME</c> to the environment variable's value.</summary>
    /// <exception cref="InvalidOperationException">The variable is not set.</exception>
    internal static string? Secret(string? value)
    {
        if (value is null || !value.StartsWith("env:", StringComparison.Ordinal))
        {
            return value;
        }

        string name = value[4..];
        return Environment.GetEnvironmentVariable(name) is { Length: > 0 } resolved
            ? resolved
            : throw new InvalidOperationException($"Environment variable '{name}' is not set.");
    }

    /// <summary>Creates the PSC client described by the options.</summary>
    internal static PscClient CreatePscClient(string url, string clientId, string? clientSecret) =>
        new(new PscClientOptions { BaseUri = new Uri(url), ClientId = clientId, ClientSecret = Secret(clientSecret) });

    /// <summary>Authorizes with the PSC: with --psc-otp directly, otherwise in the browser.</summary>
    internal static async Task<OAuthToken> AuthorizePscAsync(
        PscClient client, string? cpf, string? otp, CancellationToken cancellationToken)
    {
        if (Secret(otp) is { } resolvedOtp)
        {
            return await client.PasswordAuthorizeAsync(cpf!, resolvedOtp, PscScope.SignatureSession, TimeSpan.FromMinutes(10), cancellationToken);
        }

        var handler = new LoopbackAuthorizationHandler(uri =>
        {
            AnsiConsole.MarkupLine("[blue]Approve the signature in your browser.[/] If it does not open, visit:");
            AnsiConsole.WriteLine(uri.AbsoluteUri);
            LoopbackAuthorizationHandler.OpenInSystemBrowser(uri);
        });
        return await client.AuthorizeAsync(handler, PscScope.SignatureSession, TimeSpan.FromMinutes(10), cpf, cancellationToken);
    }

    private static async Task<ExternalCredential> OpenPkcs11Async(ExternalCredentialSettings s)
    {
        string library = string.Equals(s.Pkcs11Library, "auto", StringComparison.OrdinalIgnoreCase)
            ? await Pkcs11Drivers.FindLibraryAsync(s.Pkcs11Token)
            : s.Pkcs11Library!;
        string? pin = await PasswordResolver.ResolvePinAsync(Secret(s.Pin));
#pragma warning disable CA2000 // Ownership transferred to the returned ExternalCredential
        var token = Pkcs11Signer.Open(new Pkcs11SignerOptions
        {
            LibraryPath = library,
            TokenLabel = s.Pkcs11Token,
            KeyLabel = s.Pkcs11Key,
            Pin = pin,
        });
#pragma warning restore CA2000
        Announce($"Token {token.TokenLabel}", token.Certificate);
        return new ExternalCredential(token, token.Certificate, token.Chain, token);
    }

    private static async Task<ExternalCredential> OpenPscAsync(ExternalCredentialSettings s, CancellationToken cancellationToken)
    {
        var client = CreatePscClient(s.PscUrl!, s.PscClientId!, s.PscClientSecret);
        var token = await AuthorizePscAsync(client, s.PscCpf, s.PscOtp, cancellationToken);
        var signer = await PscSigner.CreateAsync(client, token, s.PscAlias, cancellationToken: cancellationToken);
        Announce($"PSC certificate {signer.CertificateAlias}", signer.Certificate);
        return new ExternalCredential(signer, signer.Certificate, signer.Chain, signer);
    }

    private static void Announce(string source, X509Certificate2 certificate) =>
        AnsiConsole.MarkupLine($"[dim]{source.EscapeMarkup()} ·[/] {certificate.Subject.EscapeMarkup()}");
}
