using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Signing;
using SimpleSign.Signers.Cloud.Csc;
using SimpleSign.Signers.Pkcs11;

namespace SimpleSign.Peru.Iofe.Accredited.Internal;

/// <summary>
/// The signing key of an agent, wherever it is kept: in the organization's module (PKCS#11) or in a remote signing
/// service. Either way the key is never here: this holds the certificate and what signs a hash with the key.
/// </summary>
internal sealed class IofeKey : IDisposable
{
    private readonly IDisposable _owner;

    private IofeKey(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        IExternalSigner signer,
        IDisposable owner,
        IofeModuleInfo? module,
        IofeRemoteServiceInfo? remoteService)
    {
        Certificate = certificate;
        Chain = chain;
        Signer = signer;
        _owner = owner;
        Module = module;
        RemoteService = remoteService;
    }

    internal X509Certificate2 Certificate { get; }

    /// <summary>The other certificates the module or the service gave (usually the issuers).</summary>
    internal IReadOnlyList<X509Certificate2> Chain { get; }

    internal IExternalSigner Signer { get; }

    /// <summary>The module, when the key is in one.</summary>
    internal IofeModuleInfo? Module { get; }

    /// <summary>The remote service, when the key is in one.</summary>
    internal IofeRemoteServiceInfo? RemoteService { get; }

    internal IofeKeySourceKind Kind => RemoteService is null ? IofeKeySourceKind.Module : IofeKeySourceKind.RemoteService;

    /// <summary>Opens the token of a PKCS#11 module.</summary>
    internal static IofeKey OpenModule(Pkcs11SignerOptions module, IofeModuleDeclaration declaration)
    {
        var token = Pkcs11Signer.Open(module);
        var info = new IofeModuleInfo(
            token.TokenLabel, token.TokenManufacturer, token.TokenModel, token.TokenSerialNumber, token.KeyProtection, declaration);
        return new IofeKey(token.Certificate, token.Chain, token, token, info, null);
    }

    /// <summary>
    /// Reads the credential of a remote service the caller has already checked to be the declared one
    /// (<paramref name="reported"/> is what it said of itself).
    /// </summary>
    internal static async Task<IofeKey> OpenRemoteAsync(
        CscClient client,
        CscInfo reported,
        IofeRemoteService service,
        IofeRemoteServiceDeclaration declaration,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        await RemoteSigner.EnsureServiceTokenAsync(client, clock, cancellationToken).ConfigureAwait(false);
        var signer = await CscSigner.CreateAsync(
            client, service.CredentialId, new ExplicitCscAuthorizer(service.Pin), clock, cancellationToken).ConfigureAwait(false);
        var credential = signer.Credential;
        var info = new IofeRemoteServiceInfo(
            client.Options.BaseUri, reported.Name ?? string.Empty, reported.Specs, credential.Id, credential.AuthMode, credential.Scal, declaration);
        return new IofeKey(signer.Certificate, signer.Chain, new RemoteSigner(client, signer, clock), signer, null, info);
    }

    public void Dispose() => _owner.Dispose();

    /// <summary>
    /// Signs through the service, renewing the service token first when it came from client credentials and is about
    /// to expire: an agent runs for longer than a token lasts.
    /// </summary>
    private sealed class RemoteSigner(CscClient client, CscSigner signer, TimeProvider clock) : IExternalSigner
    {
        private static readonly TimeSpan Margin = TimeSpan.FromSeconds(30);

        public async ValueTask<ReadOnlyMemory<byte>> SignAsync(ExternalSigningRequest request, CancellationToken cancellationToken)
        {
            await EnsureServiceTokenAsync(client, clock, cancellationToken).ConfigureAwait(false);
            return await signer.SignAsync(request, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Gets a service token with the client credentials when there is none or it is about to expire. A token the
        /// options gave carries no expiry and is used as it is.
        /// </summary>
        internal static async Task EnsureServiceTokenAsync(CscClient client, TimeProvider clock, CancellationToken cancellationToken)
        {
            bool canRenew = !string.IsNullOrEmpty(client.Options.ClientId) && !string.IsNullOrEmpty(client.Options.ClientSecret);
            bool stale = client.ServiceToken is not { } token || (token.ExpiresAt is { } expiry && expiry - clock.GetUtcNow() < Margin);
            if (canRenew && stale)
            {
                await client.AuthorizeServiceWithClientCredentialsAsync(cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
