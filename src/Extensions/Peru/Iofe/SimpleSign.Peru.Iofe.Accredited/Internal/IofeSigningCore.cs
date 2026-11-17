using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.CAdES;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.Signers.Cloud.Csc;
using SimpleSign.Signers.Pkcs11;
using SimpleSign.XAdES;

namespace SimpleSign.Peru.Iofe.Accredited.Internal;

/// <summary>
/// What signing under the accredited configuration is made of: the key (in a module or in a remote service), the
/// profile with its fixed policy, the level, the audit sink and the contingency. Nothing here takes a policy from the
/// caller.
/// </summary>
internal sealed class IofeSigningCore : IAsyncDisposable
{
    private const string AuditFormat = "IOFE";

    private static readonly PolicyConstraint Warn = new(ConstraintLevel.Warn);

    private readonly IofeKey _key;
    private readonly TrustProfile _profile;
    private readonly IAsyncDisposable? _ownedTrust;
    private readonly ISignatureAuditSink _audit;
    private readonly TimestampOptions? _timestamp;
    private readonly IofeContingency? _contingency;
    private readonly IHttpClientProvider? _http;
    private readonly TimeProvider _clock;

    private IofeSigningCore(
        IofeKey key,
        TrustProfile profile,
        IAsyncDisposable? ownedTrust,
        ISignatureAuditSink audit,
        TimestampOptions? timestamp,
        IofeContingency? contingency,
        IHttpClientProvider? http,
        TimeProvider clock)
    {
        _key = key;
        _profile = profile;
        _ownedTrust = ownedTrust;
        _audit = audit;
        _timestamp = timestamp;
        _contingency = contingency;
        _http = http;
        _clock = clock;
        Viewer = new IofeViewer(profile, http);
    }

    internal IofeModuleInfo? Module => _key.Module;

    internal IofeRemoteServiceInfo? RemoteService => _key.RemoteService;

    internal IofeViewer Viewer { get; }

    internal string SignerSubject => _key.Certificate.Subject;

    /// <summary>
    /// Opens the token and refuses it unless its driver states the key cannot leave it (Req. 15, 25) and it is the
    /// module the operator declared. A refusal is written to the audit sink.
    /// </summary>
    internal static async Task<IofeSigningCore> OpenModuleAsync(
        Pkcs11SignerOptions module,
        IofeModuleDeclaration declaration,
        IofeTrust trust,
        SigningPolicy signing,
        ValidationPolicy validation,
        ISignatureAuditSink audit,
        TimestampOptions? timestamp,
        IofeContingency? contingency,
        IHttpClientProvider? http,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var (profile, owned) = await trust.ResolveAsync(signing, validation, cancellationToken).ConfigureAwait(false);
        IofeKey? key = null;
        try
        {
            key = IofeKey.OpenModule(module, declaration);
            var token = key.Module!;
            var core = new IofeSigningCore(key, profile, owned, audit, timestamp, contingency, http, clock);

            if (!token.KeyProtection.IsConfinedToToken)
            {
                await core.RefuseAsync(
                    IofeRefusal.KeyNotInModule,
                    $"La clave privada del token '{token.TokenLabel}' no está confinada al módulo criptográfico "
                    + $"(CKA_SENSITIVE={Show(token.KeyProtection.Sensitive)}, CKA_EXTRACTABLE={Show(token.KeyProtection.Extractable)}).",
                    operationId: null,
                    cancellationToken).ConfigureAwait(false);
            }

            if (!declaration.Matches(token.Manufacturer, token.Model))
            {
                await core.RefuseAsync(
                    IofeRefusal.ModuleMismatch,
                    $"El token en uso ('{token.Manufacturer}' / '{token.Model}') no es el módulo criptográfico declarado "
                    + $"('{declaration.Manufacturer}' / '{declaration.Model}').",
                    operationId: null,
                    cancellationToken).ConfigureAwait(false);
            }

            return core;
        }
        catch
        {
            key?.Dispose();
            if (owned is not null)
            {
                await owned.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
    }

    /// <summary>
    /// Opens the credential of a remote signing service. The service is asked what it is before anything is sent to
    /// it: one that is not the declared service gets neither the service token nor the PIN. A credential a person has
    /// to authorize is refused, since the agent signs unattended. A refusal is written to the audit sink.
    /// </summary>
    internal static async Task<IofeSigningCore> OpenRemoteAsync(
        IofeRemoteService service,
        IofeRemoteServiceDeclaration declaration,
        IofeTrust trust,
        SigningPolicy signing,
        ValidationPolicy validation,
        ISignatureAuditSink audit,
        TimestampOptions? timestamp,
        IofeContingency? contingency,
        IHttpClientProvider? http,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        // The audit trail names the provider in the policy of every signature made with its key.
        signing = signing.WithName($"{signing.Name} (firma remota: {declaration.Provider})");
        var (profile, owned) = await trust.ResolveAsync(signing, validation, cancellationToken).ConfigureAwait(false);
        IofeKey? key = null;
        try
        {
            var client = new CscClient(service.Service, http?.GetClient(), clock);
            var reported = await client.GetInfoAsync(cancellationToken).ConfigureAwait(false);
            if (!declaration.Matches(reported))
            {
                await RefuseAsync(
                    audit,
                    clock,
                    profile.SigningPolicy!,
                    certificate: null,
                    AdesBaselineLevel.Basic,
                    IofeRefusal.RemoteServiceMismatch,
                    $"El servicio en {client.Options.BaseUri} ('{reported.Name}') no es el servicio de firma remota declarado "
                    + $"('{declaration.ServiceName}', {declaration.Provider}).",
                    operationId: null,
                    cancellationToken).ConfigureAwait(false);
            }

            key = await IofeKey.OpenRemoteAsync(client, reported, service, declaration, clock, cancellationToken).ConfigureAwait(false);
            var core = new IofeSigningCore(key, profile, owned, audit, timestamp, contingency, http, clock);

            if (!string.Equals(key.RemoteService!.AuthMode, "explicit", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(key.RemoteService.AuthMode, "implicit", StringComparison.OrdinalIgnoreCase))
            {
                await core.RefuseAsync(
                    IofeRefusal.RemoteAuthorizationNotUnattended,
                    $"La credencial '{key.RemoteService.CredentialId}' se autoriza en modo '{key.RemoteService.AuthMode}', que requiere "
                    + "la intervención de una persona: un agente automatizado firma de manera desatendida.",
                    operationId: null,
                    cancellationToken).ConfigureAwait(false);
            }

            return core;
        }
        catch
        {
            key?.Dispose();
            if (owned is not null)
            {
                await owned.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
    }

    /// <summary>Records a refusal of this package (not of the signing policy) and throws it.</summary>
    internal Task RefuseAsync(IofeRefusal refusal, string message, string? operationId, CancellationToken cancellationToken) =>
        RefuseAsync(_audit, _clock, _profile.SigningPolicy!, _key.Certificate, Level.Level, refusal, message, operationId, cancellationToken);

    /// <summary>Records a refusal and throws it; <paramref name="certificate"/> is null when it came before the key was read.</summary>
    private static async Task RefuseAsync(
        ISignatureAuditSink audit,
        TimeProvider clock,
        SigningPolicy policy,
        X509Certificate2? certificate,
        AdesBaselineLevel level,
        IofeRefusal refusal,
        string message,
        string? operationId,
        CancellationToken cancellationToken)
    {
        await audit.RecordAsync(
            new SignatureAuditEvent
            {
                Time = clock.GetUtcNow(),
                Format = AuditFormat,
                OperationId = operationId,
                RequestedLevel = level,
                Signed = false,
                Message = $"{refusal}: {message}",
                CertificateSubject = certificate?.Subject,
                CertificateIssuer = certificate?.Issuer,
                CertificateSerialNumber = certificate?.SerialNumber,
                CertificateSha256 = certificate is null ? null : Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)),
                PolicyName = policy.Name,
                PolicyDigest = policy.Digest,
            },
            cancellationToken).ConfigureAwait(false);

        throw new IofeAccreditationException(message, refusal);
    }

    internal Task<IofeSignedDocument> SignPdfAsync(byte[] pdf, string operationId, CancellationToken cancellationToken) =>
        SignAsync(IofeDocumentFormat.Pdf, operationId, async (policy, token) =>
        {
            var builder = PadesSigner.Document(pdf)
                .WithExternalSigner(_key.Certificate, _key.Signer, Chain)
                .WithProfile(_profile)
                .WithSigningPolicy(policy)
                .WithLevel(Level)
                .WithAuditSink(_audit)
                .WithOperationId(operationId);
            builder = _http is null ? builder : builder.WithHttpClientProvider(_http);
            var result = await builder.SignWithDetailsAsync(token).ConfigureAwait(false);
            return (result.SignedArtifact, result.AchievedLevel, result.HasSignatureTimestamp);
        }, cancellationToken);

    internal Task<IofeSignedDocument> SignCmsAsync(byte[] data, bool detached, string operationId, CancellationToken cancellationToken) =>
        SignAsync(IofeDocumentFormat.Cms, operationId, async (policy, token) =>
        {
            var builder = CadesSigner.Document(data)
                .WithExternalSigner(_key.Certificate, _key.Signer, Chain)
                .WithContentType(detached ? CadesContentType.Detached : CadesContentType.Enveloped)
                .WithProfile(_profile)
                .WithSigningPolicy(policy)
                .WithLevel(Level)
                .WithAuditSink(_audit)
                .WithOperationId(operationId);
            builder = _http is null ? builder : builder.WithHttpClientProvider(_http);
            var result = await builder.SignWithDetailsAsync(token).ConfigureAwait(false);
            return (result.SignedArtifact, result.AchievedLevel, result.HasSignatureTimestamp);
        }, cancellationToken);

    internal Task<IofeSignedDocument> SignXmlAsync(byte[] xml, string operationId, CancellationToken cancellationToken) =>
        SignAsync(IofeDocumentFormat.Xml, operationId, async (policy, token) =>
        {
            var builder = XadesSigner.Document(xml)
                .WithExternalSigner(_key.Certificate, _key.Signer, Chain)
                .WithProfile(_profile)
                .WithSigningPolicy(policy)
                .WithLevel(Level)
                .WithAuditSink(_audit)
                .WithOperationId(operationId);
            builder = _http is null ? builder : builder.WithHttpClientProvider(_http);
            var result = await builder.SignWithDetailsAsync(token).ConfigureAwait(false);
            return (result.SignedArtifact, result.AchievedLevel, result.HasSignatureTimestamp);
        }, cancellationToken);

    public async ValueTask DisposeAsync()
    {
        _key.Dispose();
        if (_ownedTrust is not null)
        {
            await _ownedTrust.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The level every signature is made at: B-LT with a time-stamp authority (signing time proven, chain and
    /// revocation data embedded: Req. 19, 29), B-B without one (signing time and chain).
    /// </summary>
    private AdesBaselineProfile Level =>
        _timestamp is null
            ? AdesBaselineProfile.Basic()
            : AdesBaselineProfile.LongTerm(_timestamp, new LongTermValidationOptions(_http));

    /// <summary>The issuers of the signing certificate up to its root, read again at each signature: the trusted list may have changed.</summary>
    private IReadOnlyList<X509Certificate2> Chain => IofeChains.Complete(_key.Certificate, _key.Chain, _profile.TrustAnchorProviders);

    private async Task<IofeSignedDocument> SignAsync(
        IofeDocumentFormat format,
        string operationId,
        Func<SigningPolicy, CancellationToken, Task<(byte[] Artifact, AdesBaselineLevel Achieved, bool Timestamped)>> sign,
        CancellationToken cancellationToken)
    {
        var (policy, underContingency) = await EffectivePolicyAsync(operationId, cancellationToken).ConfigureAwait(false);
        var (artifact, achieved, timestamped) = await sign(policy, cancellationToken).ConfigureAwait(false);
        return new IofeSignedDocument(
            artifact,
            format,
            achieved,
            timestamped,
            operationId,
            _key.Certificate.Subject,
            Convert.ToHexString(_key.Certificate.GetCertHash(HashAlgorithmName.SHA256)),
            policy.Name ?? string.Empty,
            underContingency,
            _key.Kind);
    }

    /// <summary>
    /// The profile's signing policy; under a contingency in force, the same policy with the availability of the
    /// revocation data lowered to a warning (a certificate known to be revoked is still refused) and the procedure in
    /// its name, so the audit record of each signature says so.
    /// </summary>
    private async Task<(SigningPolicy Policy, bool UnderContingency)> EffectivePolicyAsync(string operationId, CancellationToken cancellationToken)
    {
        var policy = _profile.SigningPolicy!;
        if (_contingency is null)
        {
            return (policy, false);
        }

        if (!_contingency.IsInForce(_clock.GetUtcNow()))
        {
            await RefuseAsync(
                IofeRefusal.ContingencyExpired,
                $"La contingencia '{_contingency.ProcedureReference}' no está vigente ({_contingency.From:u} a {_contingency.Until:u}).",
                operationId,
                cancellationToken).ConfigureAwait(false);
        }

        return (policy
            .WithName($"{policy.Name} (contingencia: {_contingency.ProcedureReference})")
            .With("SigningCertificate/RevocationDataAvailable", Warn)
            .With("CACertificate/RevocationDataAvailable", Warn)
            .With("Timestamp/RevocationDataAvailable", Warn), true);
    }

    private static string Show(bool? value) => value switch { true => "true", false => "false", _ => "no informado" };
}
