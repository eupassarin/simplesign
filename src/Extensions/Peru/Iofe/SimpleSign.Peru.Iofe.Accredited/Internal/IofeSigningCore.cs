using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.CAdES;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.Signers.Pkcs11;
using SimpleSign.XAdES;

namespace SimpleSign.Peru.Iofe.Accredited.Internal;

/// <summary>
/// What signing under the accredited configuration is made of: the token, the profile with its fixed policy, the
/// level, the audit sink and the contingency. Nothing here takes a policy from the caller.
/// </summary>
internal sealed class IofeSigningCore : IAsyncDisposable
{
    private const string AuditFormat = "IOFE";

    private static readonly PolicyConstraint Warn = new(ConstraintLevel.Warn);

    private readonly Pkcs11Signer _token;
    private readonly TrustProfile _profile;
    private readonly IAsyncDisposable? _ownedTrust;
    private readonly ISignatureAuditSink _audit;
    private readonly TimestampOptions? _timestamp;
    private readonly IofeContingency? _contingency;
    private readonly IHttpClientProvider? _http;
    private readonly TimeProvider _clock;

    private IofeSigningCore(
        Pkcs11Signer token,
        TrustProfile profile,
        IAsyncDisposable? ownedTrust,
        IofeModuleInfo module,
        ISignatureAuditSink audit,
        TimestampOptions? timestamp,
        IofeContingency? contingency,
        IHttpClientProvider? http,
        TimeProvider clock)
    {
        _token = token;
        _profile = profile;
        _ownedTrust = ownedTrust;
        Module = module;
        _audit = audit;
        _timestamp = timestamp;
        _contingency = contingency;
        _http = http;
        _clock = clock;
        Viewer = new IofeViewer(profile, http);
    }

    internal IofeModuleInfo Module { get; }

    internal IofeViewer Viewer { get; }

    internal string SignerSubject => _token.Certificate.Subject;

    /// <summary>
    /// Opens the token and refuses it unless its driver states the key cannot leave it (Req. 15, 25) and it is the
    /// module the operator declared. A refusal is written to the audit sink.
    /// </summary>
    internal static async Task<IofeSigningCore> OpenAsync(
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
        Pkcs11Signer? token = null;
        try
        {
            token = Pkcs11Signer.Open(module);
            var info = new IofeModuleInfo(
                token.TokenLabel, token.TokenManufacturer, token.TokenModel, token.TokenSerialNumber, token.KeyProtection, declaration);
            var core = new IofeSigningCore(token, profile, owned, info, audit, timestamp, contingency, http, clock);

            if (!token.KeyProtection.IsConfinedToToken)
            {
                await core.RefuseAsync(
                    IofeRefusal.KeyNotInModule,
                    $"La clave privada del token '{token.TokenLabel}' no está confinada al módulo criptográfico "
                    + $"(CKA_SENSITIVE={Show(token.KeyProtection.Sensitive)}, CKA_EXTRACTABLE={Show(token.KeyProtection.Extractable)}).",
                    operationId: null,
                    cancellationToken).ConfigureAwait(false);
            }

            if (!declaration.Matches(token))
            {
                await core.RefuseAsync(
                    IofeRefusal.ModuleMismatch,
                    $"El token en uso ('{token.TokenManufacturer}' / '{token.TokenModel}') no es el módulo criptográfico declarado "
                    + $"('{declaration.Manufacturer}' / '{declaration.Model}').",
                    operationId: null,
                    cancellationToken).ConfigureAwait(false);
            }

            return core;
        }
        catch
        {
            token?.Dispose();
            if (owned is not null)
            {
                await owned.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
    }

    /// <summary>Records a refusal of this package (not of the signing policy) and throws it.</summary>
    internal async Task RefuseAsync(IofeRefusal refusal, string message, string? operationId, CancellationToken cancellationToken)
    {
        var certificate = _token.Certificate;
        await _audit.RecordAsync(
            new SignatureAuditEvent
            {
                Time = _clock.GetUtcNow(),
                Format = AuditFormat,
                OperationId = operationId,
                RequestedLevel = Level.Level,
                Signed = false,
                Message = $"{refusal}: {message}",
                CertificateSubject = certificate.Subject,
                CertificateIssuer = certificate.Issuer,
                CertificateSerialNumber = certificate.SerialNumber,
                CertificateSha256 = Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)),
                PolicyName = _profile.SigningPolicy!.Name,
                PolicyDigest = _profile.SigningPolicy.Digest,
            },
            cancellationToken).ConfigureAwait(false);

        throw new IofeAccreditationException(message, refusal);
    }

    internal Task<IofeSignedDocument> SignPdfAsync(byte[] pdf, string operationId, CancellationToken cancellationToken) =>
        SignAsync(IofeDocumentFormat.Pdf, operationId, async (policy, token) =>
        {
            var builder = PadesSigner.Document(pdf)
                .WithExternalSigner(_token.Certificate, _token, Chain)
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
                .WithExternalSigner(_token.Certificate, _token, Chain)
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
                .WithExternalSigner(_token.Certificate, _token, Chain)
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
        _token.Dispose();
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
    private IReadOnlyList<X509Certificate2> Chain => IofeChains.Complete(_token.Certificate, _token.Chain, _profile.TrustAnchorProviders);

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
            _token.Certificate.Subject,
            Convert.ToHexString(_token.Certificate.GetCertHash(HashAlgorithmName.SHA256)),
            policy.Name ?? string.Empty,
            underContingency);
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
